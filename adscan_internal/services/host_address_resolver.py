"""Centralized pre-transport host → IP resolver (single source of truth).

Every transport that needs to turn a host identifier (IP, short name, or FQDN)
into a reachable address goes through :func:`resolve_host_address`. It layers,
in order:

  (a) already an IP → use it verbatim.
  (b) operator-override store (``domains_data[domain]["host_ip_overrides"]``) —
      silent reuse, never re-ask.
  (c) environment overrides — ``ADSCAN_HOST_IP_<HOST>``, ``ADSCAN_HOST_IP_MAP``,
      and the back-compat ``ADSCAN_ADCS_CA_FQDN_<DOMAIN>`` (FQDN → re-resolve).
  (d) workspace inventory reverse map (massdns + reachability).
  (e) DC / unbound DNS (A-record lookup, optionally via a resolver IP).
  (f) on-demand foreign-realm DC discovery (best-effort) + DNS retry.
  (g) premium operator prompt / ``skip`` (interactive only — gated by
      :func:`is_non_interactive`).
  (h) give up: ``resolved_ip=None, source="skipped"``.

The result carries ``force_ntlm_to_ip`` — True only when the address came from
an operator/env IP (layers b, c-IP, g). In that case the caller may connect
directly over an authenticated NTLM session to the IP, bypassing DNS and the
Kerberos SPN, *unless* the realm's posture says NTLM is disabled. Inventory and
DNS-derived IPs never set the flag (the name resolved cleanly, so Kerberos works
and is preferred).

This module never opens a socket itself for the transport — it only resolves an
address. It is import-light: heavy / shell-coupled helpers are imported lazily.
"""

from __future__ import annotations

import ipaddress
import os
import time
from dataclasses import dataclass
from typing import Any, Optional

from rich.text import Text

from adscan_core.interaction import is_non_interactive
from adscan_core.theme import ADSCAN_PRIMARY
from adscan_internal.rich_output import mark_sensitive
from adscan_core.rich_output import (
    print_exception,
    print_info,
    print_info_debug,
    print_panel,
    print_success,
    print_warning,
    prompt_ask,
)

__all__ = [
    "HostAddress",
    "resolve_connect_and_spn",
    "resolve_host_address",
]


@dataclass(frozen=True)
class HostAddress:
    """Outcome of host → IP resolution.

    Attributes:
        host: The host identifier the caller asked to resolve (unchanged).
        resolved_ip: The reachable IP, or ``None`` when it could not be
            resolved and the operator skipped / the run was unattended.
        source: Which layer produced the answer — one of ``already_ip``,
            ``operator``, ``env_override``, ``inventory``, ``dns``,
            ``foreign_dc``, ``skipped``.
        realm: The host's DNS realm when known (used to detect the
            cross-forest case and for the posture NTLM gate).
        force_ntlm_to_ip: True only for an operator/env-supplied IP — the
            caller may connect direct over an authenticated session to the IP
            (no DNS, no Kerberos SPN). Posture-gated by the caller.
    """

    host: str
    resolved_ip: Optional[str]
    source: str
    realm: Optional[str] = None
    force_ntlm_to_ip: bool = False

    @property
    def resolved(self) -> bool:
        """True when an address is available to connect to."""
        return bool(self.resolved_ip)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value or "").strip())
        return True
    except ValueError:
        return False


def _env_host_key(host: str) -> str:
    """Derive the ``ADSCAN_HOST_IP_<KEY>`` suffix for a host.

    Uppercase the host and replace every run of non-alphanumeric characters
    with a single underscore so an FQDN or short name maps to a stable,
    shell-safe env-var name (e.g. ``ca.essos.local`` → ``CA_ESSOS_LOCAL``).
    """
    raw = str(host or "").strip().rstrip(".")
    out_chars: list[str] = []
    for ch in raw.upper():
        out_chars.append(ch if ch.isalnum() else "_")
    return "".join(out_chars).strip("_")


def _host_keys(host: str) -> list[str]:
    """Alias-aware comparison keys for a host (lowercased FQDN + short label)."""
    try:
        from adscan_internal.services.credential_store_service import host_match_keys

        return sorted(host_match_keys(host))
    except Exception:  # noqa: BLE001 — best-effort fallback
        raw = str(host or "").strip().strip(".").rstrip("$").lower()
        if not raw:
            return []
        keys = {raw}
        if not _is_ip(raw):
            short = raw.split(".", 1)[0]
            if short:
                keys.add(short)
        return sorted(keys)


# ---------------------------------------------------------------------------
# Layer (b): operator-override store
# ---------------------------------------------------------------------------


def _lookup_operator_override(
    shell: Any, *, domain: str, host: str
) -> Optional[str]:
    """Return a persisted operator IP for ``host`` (alias-aware), if any."""
    try:
        domains_data = getattr(shell, "domains_data", {}) or {}
        entry = domains_data.get(domain) or {}
        overrides = entry.get("host_ip_overrides") or {}
        if not isinstance(overrides, dict):
            return None
        wanted = set(_host_keys(host))
        for stored_host, record in overrides.items():
            if not isinstance(record, dict):
                continue
            if wanted & set(_host_keys(stored_host)):
                ip = str(record.get("ip") or "").strip()
                if _is_ip(ip):
                    return ip
    except Exception:  # noqa: BLE001 — best-effort
        return None
    return None


def _persist_operator_override(
    shell: Any,
    *,
    domain: str,
    host: str,
    ip: str,
    realm: Optional[str],
    source: str,
) -> None:
    """Persist an operator/env IP under ``host_ip_overrides`` (alias-aware).

    Writes one record per alias key (short + FQDN) so a later lookup by either
    the short name or the FQDN hits. JSON-safe so it survives
    ``save_workspace_data``. Best-effort: never raises.
    """
    try:
        domains_data = getattr(shell, "domains_data", None)
        if not isinstance(domains_data, dict):
            return
        entry = domains_data.setdefault(domain, {})
        if not isinstance(entry, dict):
            return
        overrides = entry.setdefault("host_ip_overrides", {})
        if not isinstance(overrides, dict):
            overrides = {}
            entry["host_ip_overrides"] = overrides
        record = {
            "ip": ip,
            "realm": realm or "",
            "source": source,
            "at": int(time.time()),
        }
        for key in _host_keys(host) or [str(host or "").strip().lower()]:
            if key and not _is_ip(key):
                overrides[key] = dict(record)
        try:
            save = getattr(shell, "save_workspace_data", None)
            if callable(save):
                save()
        except Exception:  # noqa: BLE001 — persistence is best-effort
            pass
    except Exception:  # noqa: BLE001
        return


# ---------------------------------------------------------------------------
# Layer (c): environment overrides
# ---------------------------------------------------------------------------


def _lookup_env_override(host: str, domain: str) -> Optional[str]:
    """Return an env-supplied value (IP or FQDN) for ``host``, if any.

    Checks, in order:
      * ``ADSCAN_HOST_IP_<HOST>`` (host-keyed)
      * ``ADSCAN_HOST_IP_MAP`` (``host=ip,host2=ip2`` comma list, alias-aware)
      * ``ADSCAN_ADCS_CA_FQDN_<DOMAIN>`` / ``ADSCAN_ADCS_CA_FQDN`` (back-compat,
        typically an FQDN to re-resolve)
    """
    host_key = _env_host_key(host)
    if host_key:
        v = os.environ.get(f"ADSCAN_HOST_IP_{host_key}", "").strip()
        if v:
            return v

    raw_map = os.environ.get("ADSCAN_HOST_IP_MAP", "").strip()
    if raw_map:
        wanted = set(_host_keys(host))
        for pair in raw_map.split(","):
            if "=" not in pair:
                continue
            name, _, value = pair.partition("=")
            value = value.strip()
            if value and (wanted & set(_host_keys(name))):
                return value

    domain_key = str(domain or "").upper().replace(".", "_")
    for env_var in (f"ADSCAN_ADCS_CA_FQDN_{domain_key}", "ADSCAN_ADCS_CA_FQDN"):
        v = os.environ.get(env_var, "").strip()
        if v:
            return v
    return None


# ---------------------------------------------------------------------------
# Layer (d): workspace inventory reverse map
# ---------------------------------------------------------------------------


def _lookup_inventory(shell: Any, *, domain: str, host: str) -> Optional[str]:
    """Reverse-resolve ``host`` to an IP from the workspace inventory."""
    try:
        from adscan_internal.services.kerberos_hostname_inventory import (
            load_workspace_hostname_ip_inventory,
        )

        workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "")
        domains_dir = str(getattr(shell, "domains_dir", "domains") or "domains")
        if not workspace_dir or not domain:
            return None
        inventory = load_workspace_hostname_ip_inventory(
            workspace_dir=workspace_dir,
            domains_dir=domains_dir,
            domain=domain,
        )
        if not inventory:
            return None
        for key in _host_keys(host):
            ip = inventory.get(key)
            if ip and _is_ip(ip):
                return ip
    except Exception:  # noqa: BLE001 — best-effort
        return None
    return None


# ---------------------------------------------------------------------------
# Layer (d)+(e): known-address union (multi-homed aware)
# ---------------------------------------------------------------------------
#
# A single source collapses a multi-homed host to ONE address BEFORE the
# reachable-NIC selection can run: the reverse inventory map is first-wins
# single-valued, and post-pivot the DC's own DNS returns only the internal NIC.
# So gather every KNOWN IP for the host across ALL sources into ONE candidate
# set and let ``_select_reachable_ip`` pick the reachable interface. The three
# helpers below are the individual sources; ``_gather_candidate_ips`` unions
# them (de-duplicated, order-stable). Each is best-effort — a missing/failing
# source contributes nothing, never raises.


def _inventory_candidate_ips(shell: Any, *, domain: str, host: str) -> list[str]:
    """ALL inventory IPs whose hostname matches ``host`` (alias-aware, multi).

    Unlike :func:`_lookup_inventory` (which returns a single first-wins IP from
    the collapsed hostname→IP reverse map), this inverts the MULTI-valued
    IP→hostname inventory (``load_workspace_ip_hostname_inventory``) and collects
    every IP whose hostname candidates alias-match ``host`` — so a multi-homed
    host contributes both of its NICs, not one.
    """
    out: list[str] = []
    try:
        from adscan_internal.services.kerberos_hostname_inventory import (
            load_workspace_ip_hostname_inventory,
        )

        workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "")
        domains_dir = str(getattr(shell, "domains_dir", "domains") or "domains")
        if not workspace_dir or not domain:
            return out
        ip_to_hosts = load_workspace_ip_hostname_inventory(
            workspace_dir=workspace_dir,
            domains_dir=domains_dir,
            domain=domain,
        )
        wanted = set(_host_keys(host))
        for ip_value, hostnames in ip_to_hosts.items():
            if not _is_ip(ip_value):
                continue
            keys_for_ip: set[str] = set()
            for hostname in hostnames or []:
                keys_for_ip |= set(_host_keys(hostname))
            if wanted & keys_for_ip:
                out.append(ip_value)
    except Exception:  # noqa: BLE001 — best-effort
        return out
    return out


def _reachability_candidate_ips(shell: Any, *, domain: str, host: str) -> list[str]:
    """ALL current-vantage reachability-report IPs for ``host`` (alias-aware).

    Reads the exact SET the target-viability gate trusts
    (``network_reachability_report.json`` via
    ``current_vantage_reachability_service._build_hostname_to_ips_map``), so the
    resolver no longer discards the reachable set the viability gate already saw.
    """
    out: list[str] = []
    try:
        from adscan_internal.services.current_vantage_reachability_service import (
            _build_hostname_to_ips_map,
            load_current_vantage_reachability_report,
        )

        workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "")
        domains_dir = str(getattr(shell, "domains_dir", "domains") or "domains")
        if not workspace_dir or not domain:
            return out
        payload, _path = load_current_vantage_reachability_report(
            workspace_dir, domains_dir, domain
        )
        if not isinstance(payload, dict):
            return out
        mapping = _build_hostname_to_ips_map(payload)
        for key in _host_keys(host):
            for ip_value in mapping.get(key, set()):
                if _is_ip(ip_value):
                    out.append(ip_value)
    except Exception:  # noqa: BLE001 — best-effort
        return out
    return out


def _dns_candidate_ips(host: str, resolver_ip: Optional[str]) -> list[str]:
    """ALL A records for ``host`` (ordered, de-duplicated) via the DC/system DNS."""
    try:
        from adscan_internal.services.kerberos_tcp_target import _query_a_records

        return [ip for ip in _query_a_records(host, resolver_ip, 2.0) if _is_ip(ip)]
    except Exception:  # noqa: BLE001 — best-effort
        return []


def _gather_candidate_ips(
    shell: Any,
    *,
    domain: str,
    host: str,
    resolver_ip: Optional[str] = None,
    candidates: Optional[list[str]] = None,
) -> list[str]:
    """Union (de-duplicated, order-stable) of every KNOWN IP for ``host``.

    The SSOT that defeats the multi-homed collapse: instead of trusting one
    source's single answer, it merges — in trust order — a caller-supplied seed
    (e.g. the verifier's already-resolved ``matched_ips``), the multi-valued
    workspace inventory, the current-vantage reachability report, and the DNS A
    records. Every consumer of :func:`resolve_host_address` inherits the full set
    for free, so ``_select_reachable_ip`` can pick the routable NIC.

    Best-effort: each source is isolated so an absence/failure contributes
    nothing. Returns ``[]`` when nothing is known about the host.
    """
    ordered: list[str] = []
    seen: set[str] = set()

    def _add(ip: object) -> None:
        value = str(ip or "").strip()
        if _is_ip(value) and value not in seen:
            seen.add(value)
            ordered.append(value)

    for ip in candidates or []:
        _add(ip)
    for ip in _inventory_candidate_ips(shell, domain=domain, host=host):
        _add(ip)
    for ip in _reachability_candidate_ips(shell, domain=domain, host=host):
        _add(ip)
    for ip in _dns_candidate_ips(host, resolver_ip):
        _add(ip)
    return ordered


# ---------------------------------------------------------------------------
# Layer (e): DC / unbound DNS
# ---------------------------------------------------------------------------


# Compact liveness port set used ONLY to disambiguate a multi-homed host (a
# name resolving to several A records) into the address reachable from the
# current vantage. Covers the ports a domain host almost always exposes — SMB
# (445), RPC endpoint mapper (135), Kerberos/LDAP on a DC (88/389), RDP (3389).
# A hit on ANY of them means "this NIC answers from here".
_LIVENESS_PROBE_PORTS: tuple[int, ...] = (445, 135, 88, 389, 3389)

# Two-pass probe budget for a SERVICE-port selection. A genuinely-reachable NIC
# can transiently miss a single 3s probe (event-loop contention under load, or a
# mid-scan wall-clock step for DC sync) even on the correct routable interface —
# and a blind first-record fallback would then dead-end on the WRONG (unreachable)
# NIC, a ~1-in-3 false host-offline seen in the lab. So a service-port caller gets
# ONE slower retry pass before giving up. Only reached on a genuine multi-homed
# total miss (rare), so the extra cost is bounded and almost never paid.
_LIVE_PROBE_TIMEOUT: float = 3.0
_LIVE_PROBE_RETRY_TIMEOUT: float = 6.0

# Session-scoped memo: (sorted-candidate-signature, resolver_ip, service,
# probe_port) -> reachable IP. Keying on ``resolver_ip`` makes a vantage/pivot
# change (a different DC/KDC or proxy resolver) a cache MISS, so a reachable IP
# learned from one vantage is never reused after the frontier moves. Keying on
# ``service`` + ``probe_port`` keeps a port-specific selection (e.g. MSSQL 1433)
# from being reused for a different service/port — a NIC that answers on 445 but
# not 1433 must not serve a later 1433 lookup. In-process only — never persisted
# to disk, so it cannot go stale across scans nor corrupt the ``force_ntlm_to_ip``
# semantics of the operator-override store.
_REACHABLE_IP_MEMO: dict[tuple[str, str, str, str], str] = {}


def _select_via_live_probe(
    ip_candidates: list[str], *, probe_port: Optional[int]
) -> Optional[str]:
    """Live TCP-probe — the PRIMARY, authoritative multi-homed selector.

    A live probe reflects the CURRENT moment, unlike cached SYN-scan data that
    can go stale — so this always runs first and wins, exactly as the privilege
    sweeps live-test the port (``ips.txt`` is only a candidate list). When
    ``probe_port`` is given it is the ONLY port probed — it is the exact port the
    caller is about to connect on, so it is the authoritative signal for which
    NIC to pick. A NIC that answers on a generic liveness port (445/135/…) but
    has the SERVICE port filtered is the WRONG NIC for that connect, so probing
    the generic set would wrongly select it. Without ``probe_port`` the generic
    ``_LIVENESS_PROBE_PORTS`` set is probed (the "is this NIC alive at all"
    signal, for portless / generic resolution — unchanged from before). Reuses
    the probe SSOT (``network_probe_service``); ``None`` on no answer.

    A service-port caller (``probe_port`` set) gets TWO passes: a fast first pass,
    then — only when NO candidate answered it — ONE slower retry pass over the
    same candidates (a reachable NIC can transiently miss the fast probe; see
    ``_LIVE_PROBE_RETRY_TIMEOUT``). Portless callers keep the single fast pass, so
    the generic liveness selection is byte-for-byte unchanged.
    """
    probe_ports: tuple[int, ...] = (
        (int(probe_port),) if probe_port else _LIVENESS_PROBE_PORTS
    )
    timeouts: tuple[float, ...] = (
        (_LIVE_PROBE_TIMEOUT, _LIVE_PROBE_RETRY_TIMEOUT)
        if probe_port
        else (_LIVE_PROBE_TIMEOUT,)
    )
    try:
        from adscan_internal.services.async_bridge import run_async_sync
        from adscan_internal.services.network_probe_service import tcp_probe_batch

        for attempt, timeout in enumerate(timeouts, start=1):
            for candidate in ip_candidates:
                batch = run_async_sync(
                    tcp_probe_batch(candidate, list(probe_ports), timeout=timeout)
                )
                open_ports = sorted(
                    p for p, r in batch.items() if r.status == "open"
                )
                print_info_debug(
                    "reachable-ip-probe: "
                    f"candidate={mark_sensitive(candidate, 'ip')} "
                    f"probed_ports={list(probe_ports)} open={open_ports} "
                    f"attempt={attempt}/{len(timeouts)} timeout={timeout}s "
                    f"verdict={'SELECTED' if open_ports else 'no-answer'}"
                )
                if open_ports:
                    return candidate
    except Exception:  # noqa: BLE001 — best-effort; fall through to legacy pick
        return None
    return None


def _select_via_pivot_reachability(
    ip_candidates: list[str],
    *,
    shell: Any,
    domain: Optional[str],
    service: Optional[str],
    probe_port: Optional[int],
) -> Optional[str]:
    """Pivot-reachable fallback — rescues a candidate reachable ONLY via a pivot.

    A host reachable only through a pivot fails a DIRECT live probe from our
    vantage even though it is reachable through the pivot, so this runs ONLY when
    the direct probe found nothing. Reuses the POSITIVE pivot evidence the scan
    already recorded (``collect_pivot_reachable_targets`` for THIS service/port)
    — never ``infer_target_reachability`` as a rejecter, since the live probe is
    the authority. Best-effort: ``None`` when there is no ``shell``/``service``
    to key on (the portless ADCS path) or on any failure, so a working path is
    never made worse.
    """
    if shell is None or not service:
        return None
    try:
        from adscan_internal.services.target_reachability_inference_service import (
            collect_pivot_reachable_targets,
        )

        ports = [int(probe_port)] if probe_port else None
        reachable = collect_pivot_reachable_targets(
            shell, domain=domain or "", service=service, ports=ports
        )
        if not reachable:
            return None
        reachable_keys = set(reachable.keys())
        for candidate in ip_candidates:
            if candidate.strip().lower() in reachable_keys:
                return candidate
    except Exception:  # noqa: BLE001 — best-effort; defer to the legacy fallback
        return None
    return None


def _select_via_recorded_reachability(
    ip_candidates: list[str],
    *,
    shell: Any,
    domain: Optional[str],
    service: Optional[str],
) -> Optional[str]:
    """Positive-evidence pick from the scan's recorded reachability (last resort).

    Consulted ONLY when the live probe (both passes) AND the pivot-reachable
    fallback were inconclusive, and BEFORE the blind first-record pick. Prefers a
    candidate the scan already recorded as reachable — direct SYN scan OR any
    pivot — via ``infer_target_reachability`` (positive evidence only; a
    ``globally_unreachable`` or evidence-less candidate is never chosen). Cheap:
    reads the workspace reachability reports, no network. Best-effort: ``None``
    when there is no ``shell``/``service`` to key on (the portless ADCS/scan/
    exploits callers stay byte-identical) or on any failure, so the blind
    first-record fallback still applies unchanged.
    """
    if shell is None or not service:
        return None
    try:
        from adscan_internal.services.target_reachability_inference_service import (
            infer_target_reachability,
        )

        for candidate in ip_candidates:
            verdict = infer_target_reachability(
                shell, domain=domain or "", target_ip=candidate
            )
            if verdict.direct_reachable is True or any(
                v.reachable is True for v in verdict.pivot_verdicts
            ):
                return candidate
    except Exception:  # noqa: BLE001 — best-effort; defer to the legacy fallback
        return None
    return None


def _select_reachable_ip(
    candidates: list[str],
    *,
    resolver_ip: Optional[str],
    probe_port: Optional[int] = None,
    shell: Any = None,
    domain: Optional[str] = None,
    service: Optional[str] = None,
) -> Optional[str]:
    """Pick the reachable IP among MULTIPLE candidates for a multi-homed host.

    Selection order (each layer only runs when the previous did not decide):

      1. **Live port-probe — PRIMARY.** A live probe of the exact service port
         is authoritative and current (cached SYN data can be stale), so it runs
         first and wins (:func:`_select_via_live_probe`).
      2. **Pivot-reachable fallback** — only when NO candidate answers the direct
         probe; a pivot-only host is unreachable directly yet reachable through
         the pivot, so we consult the POSITIVE pivot evidence the scan recorded
         for THIS service/port (:func:`_select_via_pivot_reachability`).
      3. Caller fallback — returns ``None`` so :func:`_lookup_dns` keeps the
         legacy ``resolver_ip``-then-first-record pick (never worse).

    Only runs when there is a genuine choice (``len > 1``); a single-homed host
    pays nothing. Memoized per ``(candidates, resolver_ip, service, probe_port)``
    so a multi-homed host is resolved at most once per vantage/service. When
    ``probe_port``/``service`` are absent (the ADCS / portless callers) it is
    byte-for-byte today's behavior: generic-set live probe, no reachability-SSOT
    calls.
    """
    ip_candidates = [ip for ip in candidates if _is_ip(ip)]
    if not ip_candidates:
        return None
    if len(ip_candidates) == 1:
        return ip_candidates[0]

    memo_key = (
        ",".join(sorted(ip_candidates)),
        str(resolver_ip or ""),
        str(service or ""),
        str(probe_port or ""),
    )
    cached = _REACHABLE_IP_MEMO.get(memo_key)
    if cached:
        print_info_debug(
            "reachable-ip-select: "
            f"candidates={[mark_sensitive(c, 'ip') for c in ip_candidates]} "
            f"service={service or '—'} probe_port={probe_port or '—'} "
            f"picked={mark_sensitive(cached, 'ip')} via=memo"
        )
        return cached

    # (1) Live probe of the actual service port — primary and authoritative.
    probe_pick = _select_via_live_probe(ip_candidates, probe_port=probe_port)
    # (2) Pivot-reachable fallback — rescues a pivot-only host the direct probe
    #     cannot see. No-op for the portless / shell-less callers.
    pivot_pick = (
        None
        if probe_pick
        else _select_via_pivot_reachability(
            ip_candidates,
            shell=shell,
            domain=domain,
            service=service,
            probe_port=probe_port,
        )
    )
    pick = probe_pick or pivot_pick
    layer = "live-probe" if probe_pick else ("pivot-reachable" if pivot_pick else "none")
    print_info_debug(
        "reachable-ip-select: "
        f"candidates={[mark_sensitive(c, 'ip') for c in ip_candidates]} "
        f"service={service or '—'} probe_port={probe_port or '—'} "
        f"picked={mark_sensitive(pick, 'ip') if pick else 'NONE (caller falls back to resolver_ip/first-record)'} "
        f"via={layer}"
    )
    if pick:
        _REACHABLE_IP_MEMO[memo_key] = pick
    return pick


def _log_dns_fallback(
    ips: list[str],
    picked: str,
    service: Optional[str],
    probe_port: Optional[int],
    via: str,
) -> None:
    """Emit the ``reachable-ip-select`` decision line for a blind DNS fallback.

    Mirrors the format :func:`_select_reachable_ip` prints, so a run where the
    live probe was inconclusive is still diagnosable — the ``via=`` marker names
    exactly which fallback layer picked the address (resolver-ip vs recorded
    reachability vs first-record), not just ``via=none``.
    """
    print_info_debug(
        "reachable-ip-select: "
        f"candidates={[mark_sensitive(c, 'ip') for c in ips]} "
        f"service={service or '—'} probe_port={probe_port or '—'} "
        f"picked={mark_sensitive(picked, 'ip')} via={via}"
    )


def _lookup_dns(
    host: str,
    resolver_ip: Optional[str],
    probe_port: Optional[int] = None,
    *,
    shell: Any = None,
    domain: Optional[str] = None,
    service: Optional[str] = None,
) -> Optional[str]:
    """Resolve ``host`` to a reachable A record via the system / DC resolver.

    When the name resolves to a SINGLE address, return it. When it resolves to
    MULTIPLE (a multi-homed host advertising, say, both an internal-only and a
    routable NIC), the reachability selection runs FIRST and WINS — reusing the
    scan's already-collected reachability, then a live service-port probe (see
    :func:`_select_reachable_ip`) — rather than blindly taking the first record
    or the resolver's own IP, so a caller cannot dead-end on an unreachable
    secondary interface. Only when that selection is fully inconclusive do the
    safe fallbacks apply, in order: the ``resolver_ip`` if it is among the
    records (we are already talking to it, so it is reachable), then a candidate
    the scan recorded as reachable (positive evidence), and only then the first
    record — so behavior is never worse than before.

    ``probe_port`` / ``service`` (when given) let the selection reuse the
    per-service reachability data and probe the exact port the caller will
    connect on; ``shell`` + ``domain`` key that data lookup.
    """
    if _is_ip(host):
        return host
    try:
        from adscan_internal.services.kerberos_tcp_target import _query_a_records

        ips = _query_a_records(host, resolver_ip, 2.0)
        if not ips:
            return None
        if len(ips) == 1:
            return ips[0]
        # Multiple candidates: select FIRST (data-first, then port-aware probe)
        # so a real reachability signal beats the blind short-circuits below.
        reachable = _select_reachable_ip(
            ips,
            resolver_ip=resolver_ip,
            probe_port=probe_port,
            shell=shell,
            domain=domain,
            service=service,
        )
        if reachable:
            return reachable
        # Selection fully inconclusive (both probe passes AND the pivot fallback
        # found nothing) → a SAFE fallback order, never a blind first-record pick
        # while a better signal exists:
        #   (a) the resolver we are already talking to, if it is among the records
        #       (we reached it, so it is reachable),
        #   (b) a candidate the scan recorded as reachable (positive evidence),
        #   (c) only then the first record — behavior never worse than before.
        if resolver_ip and resolver_ip in ips:
            _log_dns_fallback(ips, resolver_ip, service, probe_port, "fallback-resolver-ip")
            return resolver_ip
        recorded = _select_via_recorded_reachability(
            ips, shell=shell, domain=domain, service=service
        )
        if recorded:
            _log_dns_fallback(ips, recorded, service, probe_port, "fallback-recorded-reachability")
            return recorded
        _log_dns_fallback(ips, ips[0], service, probe_port, "fallback-first-record")
        return ips[0]
    except Exception:  # noqa: BLE001 — best-effort
        return None


# ---------------------------------------------------------------------------
# Layer (f): on-demand foreign-realm DC discovery
# ---------------------------------------------------------------------------


def _realm_is_mapped(shell: Any, realm: str) -> bool:
    """True when ``realm`` is a known domain or a discovered trust partner.

    Used to choose the cross-realm vs same-realm reason copy and to decide
    whether foreign-DC discovery is worth attempting.
    """
    realm_clean = str(realm or "").strip().rstrip(".").lower()
    if not realm_clean:
        return True  # no realm hint → treat as same-realm (no special copy)
    try:
        domains_data = getattr(shell, "domains_data", {}) or {}
        for domain_name, entry in domains_data.items():
            if str(domain_name or "").strip().rstrip(".").lower() == realm_clean:
                return True
            if not isinstance(entry, dict):
                continue
            for trust in entry.get("trusts") or []:
                if not isinstance(trust, dict):
                    continue
                partner = str(
                    trust.get("name")
                    or trust.get("target")
                    or trust.get("partner")
                    or ""
                ).strip().rstrip(".").lower()
                if partner == realm_clean:
                    return True
    except Exception:  # noqa: BLE001
        return True
    return False


def _try_foreign_dc_discovery(
    shell: Any,
    *,
    host: str,
    realm: str,
    probe_port: Optional[int] = None,
    domain: Optional[str] = None,
    service: Optional[str] = None,
) -> Optional[str]:
    """Best-effort: discover the foreign realm's DC, re-point DNS, retry (e).

    Foreign hosts ARE routable even when their name doesn't resolve from the
    current vantage; if we can find a reachable DC IP for ``realm`` we point the
    resolver at it and retry the A-record lookup. Best-effort — any failure
    falls through to the operator prompt. Never raises.
    """
    realm_clean = str(realm or "").strip().rstrip(".")
    if not realm_clean:
        return None
    try:
        domains_data = getattr(shell, "domains_data", {}) or {}
        from adscan_internal.models.domain import resolve_dc_ip

        dc_ip: Optional[str] = None
        for domain_name, entry in domains_data.items():
            if (
                str(domain_name or "").strip().rstrip(".").lower()
                == realm_clean.lower()
                and isinstance(entry, dict)
            ):
                dc_ip = resolve_dc_ip(entry)
                break
        if not dc_ip or not _is_ip(dc_ip):
            return None
        try:
            from adscan_internal.cli.dns import update_resolver_for_domain

            update_resolver_for_domain(shell, realm_clean, dc_ip)
        except Exception:  # noqa: BLE001 — re-point is best-effort
            pass
        return _lookup_dns(
            host, dc_ip, probe_port, shell=shell, domain=domain, service=service
        )
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# Layer (g): premium operator prompt
# ---------------------------------------------------------------------------


def _build_reason(*, cross_realm: bool, host: str, realm: str) -> str:
    """Operator-readable reason text for the unresolvable panel (two variants)."""
    if cross_realm:
        return (
            "This host lives in a forest ADscan hasn't mapped from your current "
            "position. There's no trust path and no DNS route to it from the "
            "domain you're scanning, so its name can't be resolved to an address "
            "here."
        )
    return (
        "DNS returned no address for this host, and nothing collected so far "
        "maps the name to one. It may be offline, renamed, or served by a "
        "resolver this host can't see."
    )


def _render_unresolvable_panel(
    *, host: str, realm: str, cross_realm: bool
) -> None:
    """Render the premium 'host could not be resolved' panel."""
    from rich.console import Group
    from rich.table import Table

    host_masked = mark_sensitive(host, "domain")
    realm_masked = mark_sensitive(realm, "domain") if realm else "—"
    reason = _build_reason(cross_realm=cross_realm, host=host, realm=realm)

    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="right", style="dim", no_wrap=True)
    grid.add_column(justify="left", style="white")
    grid.add_row("Host", Text(str(host_masked), style=ADSCAN_PRIMARY))
    grid.add_row("Realm", Text(str(realm_masked), style="white"))
    grid.add_row("Reason", Text(reason, style="white"))

    action = Text()
    action.append("→ ", style=f"bold {ADSCAN_PRIMARY}")
    action.append(
        "If you know this host's IP, ADscan can reach it directly over a "
        "direct authenticated connection, no DNS or domain lookup needed.",
        style=ADSCAN_PRIMARY,
    )

    body = Group(grid, Text(""), action)
    print_panel(
        body,
        title="⚠  Host could not be resolved",
        title_align="left",
        border_style="yellow",
        spacing="none",
    )


def _prompt_operator_for_ip(*, host: str) -> Optional[str]:
    """Loop the operator-IP prompt until a valid IP or an explicit skip.

    Returns the IP string on success, or ``None`` on skip/empty.
    """
    host_masked = mark_sensitive(host, "domain")
    while True:
        answer = prompt_ask(
            f'IP address for {host_masked} (or "skip")',
            default="skip",
        )
        candidate = str(answer or "").strip()
        if not candidate or candidate.lower() == "skip":
            print_info(
                Text(
                    "○  Skipped. This host won't be reached in this run.",
                    style="dim",
                )
            )
            return None
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            print_warning(
                "⚠  That's not a valid IPv4 or IPv6 address. Enter an address "
                'like 10.20.4.11, or type "skip".'
            )
            continue
        print_success(
            f"✓  Will connect to {mark_sensitive(candidate, 'ip')} directly."
        )
        return candidate


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def resolve_host_address(
    shell: Any,
    *,
    host: str,
    domain: str,
    realm: Optional[str] = None,
    resolver_ip: Optional[str] = None,
    probe_port: Optional[int] = None,
    service: Optional[str] = None,
    candidates: Optional[list[str]] = None,
    allow_operator_prompt: bool = True,
    allow_foreign_dc_discovery: bool = True,
) -> HostAddress:
    """Resolve ``host`` to a reachable IP through the layered SSOT.

    Args:
        shell: The pentest shell (carries ``domains_data`` + workspace dirs).
        host: Host identifier to resolve (IP, short name, or FQDN).
        domain: The domain being scanned (override store + inventory key).
        realm: The host's DNS realm when known (cross-forest detection +
            posture gate). Defaults to ``domain``.
        resolver_ip: DC/KDC IP to query for DNS (layer e).
        probe_port: The exact service port the caller will connect on. When a
            name resolves to MULTIPLE addresses (a multi-homed host), the NIC
            that accepts THIS port is live-probed and selected — the
            authoritative signal for a service like MSSQL whose routable NIC may
            have the generic liveness ports filtered. ``None`` (default) keeps
            the generic liveness probe and is byte-for-byte the legacy behavior.
        service: The service label (e.g. ``"mssql"``) used ONLY as the fallback
            key into the scan's recorded pivot-reachability when no candidate
            answers a direct probe. ``None`` (default) skips that fallback — the
            portless/ADCS callers stay identical to today.
        candidates: Optional caller-supplied IPs to seed the known-address union
            (e.g. a verifier's already-resolved ``matched_ips``). Merged ahead of
            the workspace/DNS sources so a caller that already knows the reachable
            set need not re-read it. ``None`` (default) relies purely on the
            workspace + DNS sources.
        allow_operator_prompt: When False, never prompt (used by non-blocking
            call sites); resolution stops at layer (f).
        allow_foreign_dc_discovery: When False, skip the on-demand foreign-DC
            discovery layer (f).

    Returns:
        A :class:`HostAddress`. ``resolved_ip`` is ``None`` only when every
        layer missed and the operator skipped (or the run is unattended).
    """
    host_clean = str(host or "").strip().rstrip(".")
    realm_clean = str(realm or domain or "").strip().rstrip(".")

    # (a) already an IP.
    if _is_ip(host_clean):
        return HostAddress(
            host=host_clean,
            resolved_ip=host_clean,
            source="already_ip",
            realm=realm_clean or None,
            force_ntlm_to_ip=False,
        )

    # (b) operator-override store — silent reuse.
    stored = _lookup_operator_override(shell, domain=domain, host=host_clean)
    if stored:
        return HostAddress(
            host=host_clean,
            resolved_ip=stored,
            source="operator",
            realm=realm_clean or None,
            force_ntlm_to_ip=True,
        )

    # (c) environment override — IP wins direct; FQDN re-resolves via DNS.
    env_value = _lookup_env_override(host_clean, domain)
    if env_value:
        if _is_ip(env_value):
            return HostAddress(
                host=host_clean,
                resolved_ip=env_value,
                source="env_override",
                realm=realm_clean or None,
                force_ntlm_to_ip=True,
            )
        env_dns = _lookup_dns(
            env_value,
            resolver_ip,
            probe_port,
            shell=shell,
            domain=domain,
            service=service,
        )
        if env_dns:
            return HostAddress(
                host=host_clean,
                resolved_ip=env_dns,
                source="dns",
                realm=realm_clean or None,
                force_ntlm_to_ip=False,
            )

    # (d) known-address UNION — inventory + reachability report + DNS + seed.
    #     A multi-homed host contributes ALL its NICs here, so the reachable-NIC
    #     selection actually engages instead of the resolver collapsing to one
    #     source's single answer (the post-pivot dead-end on the unreachable NIC).
    #     A single-homed host yields one candidate → returned verbatim (no probe);
    #     an empty union falls through to the single-source layers below, so a
    #     working path is never made worse.
    union = _gather_candidate_ips(
        shell,
        domain=domain,
        host=host_clean,
        resolver_ip=resolver_ip,
        candidates=candidates,
    )
    if len(union) > 1:
        picked = _select_reachable_ip(
            union,
            resolver_ip=resolver_ip,
            probe_port=probe_port,
            shell=shell,
            domain=domain,
            service=service,
        )
        chosen = picked or (resolver_ip if resolver_ip in union else union[0])
        if not picked:
            _log_dns_fallback(
                union,
                chosen,
                service,
                probe_port,
                "fallback-resolver-ip" if chosen == resolver_ip else "fallback-first-record",
            )
        return HostAddress(
            host=host_clean,
            resolved_ip=chosen,
            source="dns",
            realm=realm_clean or None,
            force_ntlm_to_ip=False,
        )
    if len(union) == 1:
        return HostAddress(
            host=host_clean,
            resolved_ip=union[0],
            source="dns",
            realm=realm_clean or None,
            force_ntlm_to_ip=False,
        )

    # (d-fallback) workspace inventory reverse map (single-source).
    inv = _lookup_inventory(shell, domain=domain, host=host_clean)
    if inv:
        return HostAddress(
            host=host_clean,
            resolved_ip=inv,
            source="inventory",
            realm=realm_clean or None,
            force_ntlm_to_ip=False,
        )

    # (e-fallback) DC / unbound DNS (single-source).
    dns_ip = _lookup_dns(
        host_clean,
        resolver_ip,
        probe_port,
        shell=shell,
        domain=domain,
        service=service,
    )
    if dns_ip:
        return HostAddress(
            host=host_clean,
            resolved_ip=dns_ip,
            source="dns",
            realm=realm_clean or None,
            force_ntlm_to_ip=False,
        )

    cross_realm = bool(realm_clean) and not _realm_is_mapped(shell, realm_clean)

    # (f) on-demand foreign-realm DC discovery (best-effort).
    if allow_foreign_dc_discovery and realm_clean:
        foreign_ip = _try_foreign_dc_discovery(
            shell,
            host=host_clean,
            realm=realm_clean,
            probe_port=probe_port,
            domain=domain,
            service=service,
        )
        if foreign_ip:
            return HostAddress(
                host=host_clean,
                resolved_ip=foreign_ip,
                source="foreign_dc",
                realm=realm_clean or None,
                force_ntlm_to_ip=False,
            )

    # (g) premium operator prompt — interactive only.
    if not allow_operator_prompt or is_non_interactive(shell):
        # Render the panel (so the operator sees WHY in the recording), then
        # auto-skip with an env hint. No prompt → no CI hang.
        _render_unresolvable_panel(
            host=host_clean, realm=realm_clean, cross_realm=cross_realm
        )
        env_key = _env_host_key(host_clean)
        print_info(
            Text(
                "○  Unattended run: skipped. To reach it next time, set "
                f"ADSCAN_HOST_IP_{env_key}=<ip> before the run.",
                style="dim",
            )
        )
        return HostAddress(
            host=host_clean,
            resolved_ip=None,
            source="skipped",
            realm=realm_clean or None,
            force_ntlm_to_ip=False,
        )

    _render_unresolvable_panel(
        host=host_clean, realm=realm_clean, cross_realm=cross_realm
    )
    operator_ip = _prompt_operator_for_ip(host=host_clean)
    if operator_ip:
        _persist_operator_override(
            shell,
            domain=domain,
            host=host_clean,
            ip=operator_ip,
            realm=realm_clean or None,
            source="operator",
        )
        return HostAddress(
            host=host_clean,
            resolved_ip=operator_ip,
            source="operator",
            realm=realm_clean or None,
            force_ntlm_to_ip=True,
        )

    # (h) give up.
    return HostAddress(
        host=host_clean,
        resolved_ip=None,
        source="skipped",
        realm=realm_clean or None,
        force_ntlm_to_ip=False,
    )


def resolve_connect_and_spn(
    shell: Any,
    *,
    host: str,
    domain: str,
    resolver_ip: Optional[str] = None,
    spn_hostname: Optional[str] = None,
    probe_port: Optional[int] = None,
    service: Optional[str] = None,
    candidates: Optional[list[str]] = None,
) -> tuple[str, str]:
    """Split a possibly-multi-homed host into ``(connect_ip, spn_fqdn)`` (SSOT).

    The service-agnostic seam every attack-path / execution backend uses to talk
    to a host that may resolve to multiple IPs. DCs and servers are frequently
    multi-homed (a routable NIC alongside an internal-only one), and a transport
    that resolves the name itself and takes only ``getaddrinfo()[0]`` — impacket's
    TDS is the canonical hazard — dead-ends on the unreachable interface. This
    resolves the **CONNECT target** to its reachable IP through
    :func:`resolve_host_address` while keeping the **FQDN as the Kerberos SPN /
    ``remoteName``**: IP for the connect, FQDN for the ticket (the same split as
    the Kerberos-SPN rule). An IP handed to Kerberos as the SPN would fail auth,
    so the two must stay separate.

    Best-effort by contract: on a missing ``shell``, an empty ``host``, or any
    resolution failure it returns ``(host, spn_fqdn)`` unchanged, so the caller's
    own resolution and the async native stack's addrinfo iteration still apply —
    the split never makes a working path worse.

    Args:
        shell: The pentest shell (carries ``domains_data`` + workspace dirs). May
            be ``None`` in a context without one — then no resolution is attempted.
        host: The connect host identifier (IP, short name, or FQDN).
        domain: The domain being scanned (override store + inventory key).
        resolver_ip: DC/KDC IP to query for DNS.
        spn_hostname: The FQDN to keep as the Kerberos SPN when it differs from
            ``host`` (e.g. the verifier's ``target_hostname``). Defaults to
            ``host``.
        probe_port: The exact port the backend will connect on (e.g. the MSSQL
            instance port, 1433 by default). Threaded into the multi-homed NIC
            selection so the reachable IP chosen is the one that accepts THAT
            service — not merely one that answers a generic liveness port.
        service: The service label (e.g. ``"mssql"``) used only as the fallback
            key into the scan's recorded pivot-reachability when no candidate
            answers a direct probe.
        candidates: Optional caller-supplied IPs (e.g. the verifier's resolved
            ``matched_ips``) seeded into the known-address union, so a caller that
            already knows the reachable set can skip a redundant workspace re-read.

    Returns:
        ``(connect_ip, spn_fqdn)``. ``connect_ip`` is the reachable IP when one
        was resolved, else ``host`` verbatim; ``spn_fqdn`` is ``spn_hostname``
        when given, else ``host``.
    """
    spn_fqdn = spn_hostname or host
    if shell is None or not host:
        return host, spn_fqdn
    try:
        resolved = resolve_host_address(
            shell,
            host=host,
            domain=domain,
            resolver_ip=resolver_ip,
            probe_port=probe_port,
            service=service,
            candidates=candidates,
            allow_operator_prompt=False,
        )
        if resolved.resolved_ip:
            return str(resolved.resolved_ip), spn_fqdn
    except Exception as exc:  # noqa: BLE001 — best-effort; keep the name on failure
        print_exception(exception=exc)
    return host, spn_fqdn
