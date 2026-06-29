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
    print_info,
    print_panel,
    print_success,
    print_warning,
    prompt_ask,
)

__all__ = [
    "HostAddress",
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
# Layer (e): DC / unbound DNS
# ---------------------------------------------------------------------------


def _lookup_dns(host: str, resolver_ip: Optional[str]) -> Optional[str]:
    """Resolve ``host`` to an A record via the system / DC resolver."""
    if _is_ip(host):
        return host
    try:
        from adscan_internal.services.kerberos_tcp_target import _query_a_records

        ips = _query_a_records(host, resolver_ip, 2.0)
        if resolver_ip and resolver_ip in ips:
            return resolver_ip
        return ips[0] if ips else None
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
    shell: Any, *, host: str, realm: str
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
        return _lookup_dns(host, dc_ip)
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
        env_dns = _lookup_dns(env_value, resolver_ip)
        if env_dns:
            return HostAddress(
                host=host_clean,
                resolved_ip=env_dns,
                source="dns",
                realm=realm_clean or None,
                force_ntlm_to_ip=False,
            )

    # (d) workspace inventory reverse map.
    inv = _lookup_inventory(shell, domain=domain, host=host_clean)
    if inv:
        return HostAddress(
            host=host_clean,
            resolved_ip=inv,
            source="inventory",
            realm=realm_clean or None,
            force_ntlm_to_ip=False,
        )

    # (e) DC / unbound DNS.
    dns_ip = _lookup_dns(host_clean, resolver_ip)
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
            shell, host=host_clean, realm=realm_clean
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
