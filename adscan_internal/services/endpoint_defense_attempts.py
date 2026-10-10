"""Per-attempt record of what a credential-extraction technique met.

One row per credential-extraction technique ADscan ran: which host, what
endpoint posture was observed there at the time, and how the technique ended.
It is the only source for the efficacy half of the client's endpoint-defense
section, and it exists because the attack-graph edge cannot cover the cases
that matter most.

Why not read it off the attack-graph edge
-----------------------------------------
The dump seams already stamp a posture context onto the active attack-step
edge, which is the right home for the per-step NARRATIVE. But
``update_active_step_status`` returns immediately when no attack step is
active, so a dump run from the workbench (``dump_lsa``, ``dump_sam``,
``dump_registries``, ``dump_lsass``, ``dump_dpapi``) or from
``adscan execute dump_*`` writes no edge at all and leaves no trace of the
outcome. Those are exactly the runs where an operator is testing a specific
host against a specific product, so an efficacy section built on edges alone
would be empty on the engagements where it is most wanted. This record covers
both paths with one mechanism.

Why the caller passes the outcome
---------------------------------
Persistence is normally a property of the observing seam, not of each call
site (``endpoint_posture.probe_endpoint_posture``, and the clock-sync doctrine
in CLAUDE.md § 1a). That cannot apply here: the probe runs BEFORE the
technique, so the outcome does not exist yet when the seam fires. So the
record is written at the one point where the posture and the outcome coexist,
which is the same place each dump path already derives its posture notes. One
call, beside code that is already there, and the shape lives in exactly one
function rather than being rebuilt per site.

An ABSENT file means attempt recording never ran in this workspace; an EMPTY
``attempts`` list means it ran and nothing was attempted. The report tells
those apart (``attempts_recorded``), because "we did not measure" and "we
measured nothing" are different claims. Same reasoning as the environment
change ledger materializing itself empty.
"""

from __future__ import annotations

import os
import time
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from adscan_core.reporting.endpoint_defense import (
    OUTCOME_COMPLETED,
    OUTCOME_INCOMPLETE,
    OUTCOME_INTERRUPTED,
    OUTCOME_TOKENS,
    build_endpoint_defense,
    classify_host_posture,
)
from adscan_core.rich_output import print_exception, print_info_debug
from adscan_internal import telemetry
from adscan_internal.workspaces.io import read_json_file, write_json_file

_FILENAME = "endpoint_defense_attempts.json"
_SCHEMA_VERSION = "1.1"

#: Identifies the process that stamped an attempt. A monotonic reading is only
#: comparable against another from the SAME process, so ordering by it across
#: two sessions of the same engagement would be meaningless. Pairing the two
#: keeps the comparison honest.
_SESSION_ID = str(uuid.uuid4())


def _utc_now_iso() -> str:
    """The wall-clock stamp the CLIENT correlates against.

    It stays on the wall clock deliberately, against the repo's usual rule,
    because this one is an absolute time a human reads: the client's SOC looks
    for these events in their own console, and a monotonic counter has no
    calendar meaning to search for.
    """
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _monotonic_now() -> float:
    """The ORDERING and DURATION stamp, immune to the clock being stepped.

    ADscan physically steps the host wall clock mid-scan to sync with the DC
    for PKINIT, so two attempts stamped either side of that step come from
    different clock bases and sorting them by wall clock can invert them. The
    report would then show a window running backwards, which is a time the
    client cannot find. Monotonic never moves backwards, so it decides the
    order while the wall clock supplies the value shown.
    """
    return time.monotonic()


def _clock_synced_to_dc(shell: Any) -> bool:
    """Whether the host clock had already been stepped to the DC's time.

    An attempt stamped BEFORE the first sync carries whatever offset the host
    had; one stamped after agrees with the DC, and therefore with the client's
    own DC-synced hosts, which is exactly what makes correlation work. Saying
    which of the two a stamp is lets the report qualify it instead of implying
    a precision it does not have.
    """
    return bool(getattr(shell, "_clock_synced_at", None))


def _workspace_dir(shell: Any) -> str | None:
    path = getattr(shell, "current_workspace_dir", None)
    return str(path) if path else None


def _path_for(workspace_dir: str) -> str:
    return os.path.join(workspace_dir, _FILENAME)


def _load(path: str) -> dict[str, Any]:
    if os.path.exists(path):
        try:
            data = read_json_file(path)
            if isinstance(data, dict) and isinstance(data.get("attempts"), list):
                return data
        except Exception as exc:  # noqa: BLE001 — a corrupt record is not fatal
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
    return {
        "schema_version": _SCHEMA_VERSION,
        "started_at": _utc_now_iso(),
        "attempts": [],
    }


def outcome_for(*, success: bool, interrupted_every_retry: bool = False) -> str:
    """Map a dump result to an outcome token.

    The order matters: a technique that produced its result is
    :data:`OUTCOME_COMPLETED` even when the read was interrupted along the way,
    because the credentials came out. Reporting that as interference would
    credit the product with a success it did not have.
    """
    if success:
        return OUTCOME_COMPLETED
    if interrupted_every_retry:
        return OUTCOME_INTERRUPTED
    return OUTCOME_INCOMPLETE


def record_attempt(
    shell: Any,
    *,
    technique: str,
    domain: str,
    host: str,
    fp: Any,
    outcome: str,
    source_method: str | None = None,
) -> None:
    """Append one technique attempt to the workspace record.

    Args:
        shell: The ``PentestShell``, for the workspace path. A shell with no
            active workspace is a no-op.
        technique: The attack-step name for this technique ("DumpLSA",
            "DumpSAM", "DumpLSASS", "DumpDPAPI", "BackupOperatorDump"), so the
            report groups by the same name the attack graph uses.
        domain: The domain the host belongs to.
        host: The host the technique ran against, as resolved.
        fp: The ``HostFingerprint`` observed before the technique ran, or
            ``None``. Its posture is classified through the shared SSOT, so the
            undetermined state is never confused with a clean host.
        outcome: One of :data:`OUTCOME_TOKENS`. Use :func:`outcome_for` rather
            than deciding at the call site.
        source_method: Which read actually produced the result, when the
            technique has more than one ("inline" / "savekey").

    Best-effort: never raises into the dump flow. A dump must not fail because
    a record could not be written.
    """
    try:
        workspace_dir = _workspace_dir(shell)
        if not workspace_dir:
            return
        if outcome not in OUTCOME_TOKENS:
            outcome = OUTCOME_INCOMPLETE

        products = [
            {
                "name": str(getattr(product, "name", "") or ""),
                "category": str(getattr(product, "category", "") or ""),
                "active": bool(getattr(product, "active", False)),
            }
            for product in (getattr(fp, "products", None) or ())
        ]
        posture_assessed = _posture_assessed(fp)

        path = _path_for(workspace_dir)
        state = _load(path)
        state["attempts"].append(
            {
                "attempt_id": str(uuid.uuid4()),
                "technique": str(technique),
                "domain": str(domain or ""),
                "host": str(host or ""),
                "observed_at": _utc_now_iso(),
                "observed_monotonic": _monotonic_now(),
                "session_id": _SESSION_ID,
                "clock_synced_to_dc": _clock_synced_to_dc(shell),
                "outcome": outcome,
                "source_method": str(source_method or "") or None,
                "host_posture": classify_host_posture(products, posture_assessed),
                "posture_assessed": posture_assessed,
                "products": products,
            }
        )
        write_json_file(path, state)
    except Exception as exc:  # noqa: BLE001 — recording must never break a dump
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"endpoint-defense attempt not recorded: {exc}")


def _posture_assessed(fp: Any) -> bool:
    """Whether the fingerprint determined the host's posture.

    Mirrors ``inventory_writer.posture_was_assessed``: an observed product is
    a fact whatever partial error came back, and no products with an error
    means the probe did not complete rather than that the host is clean.
    """
    if fp is None:
        return False
    if list(getattr(fp, "products", None) or []):
        return True
    return not getattr(fp, "error", None)


def read_attempts(workspace_dir: str | None) -> tuple[list[dict[str, Any]], bool]:
    """Return ``(attempts, recorded)`` for a workspace.

    ``recorded`` is ``False`` only when the file is absent, which means this
    workspace predates attempt recording. An empty list with ``recorded=True``
    is an observation: nothing was attempted.
    """
    if not workspace_dir:
        return [], False
    path = _path_for(str(workspace_dir))
    if not os.path.exists(path):
        return [], False
    try:
        data = read_json_file(path)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return [], False
    if not isinstance(data, dict):
        return [], False
    attempts = [a for a in (data.get("attempts") or ()) if isinstance(a, dict)]
    return attempts, True


def record_endpoint_defense_for_domain(shell: Any, domain: str) -> None:
    """Build and persist the endpoint-defense block for one domain.

    Joins the two halves: the per-host posture the probe seam already persists
    into ``inventory/defensive_posture.json``, and the per-attempt records
    above. Stamps the result into ``technical_report.json`` so the PDF report,
    the LITE report and the platform all read one block.

    Best-effort: a workspace with neither half simply records nothing, and the
    report renders exactly as it did before rather than growing an empty
    section.
    """
    try:
        workspace_dir = _workspace_dir(shell)
        if not workspace_dir or not domain:
            return

        posture_hosts = _read_posture_hosts(workspace_dir, domain)
        attempts, recorded = read_attempts(workspace_dir)
        domain_key = str(domain).strip().rstrip(".").lower()
        scoped = [
            a
            for a in attempts
            if str(a.get("domain") or "").strip().rstrip(".").lower() == domain_key
        ]

        _install_tier_label_provider()
        block = build_endpoint_defense(
            posture_hosts=posture_hosts,
            attempts=scoped,
            computers_in_estate=_count_computers(workspace_dir, domain_key),
            attempts_recorded=recorded,
            host_tiers=_resolve_host_tiers(
                shell, workspace_dir, domain, posture_hosts, scoped
            ),
            host_names=_resolve_host_names(shell, workspace_dir, domain, scoped),
        )
        if not block.get("present"):
            return

        from adscan_core.reporting.technical_report import record_endpoint_defense

        record_endpoint_defense(shell, domain, block=block)
    except Exception as exc:  # noqa: BLE001 — never break the scan over a record
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"endpoint-defense block not recorded for {domain}: {exc}")


def _install_tier_label_provider() -> None:
    """Point the report SSOT at the ONE tier-label owner.

    ``adscan_core.reporting.endpoint_defense`` is dependency-light because the
    web backend imports it, so it cannot reach the tier classifier itself. This
    layer can, so it installs the resolver here and the tier badge on an
    endpoint-defense row is worded by the same function that words the badge on
    a finding's affected assets. A local copy of the labels was written first
    and had already drifted before it was deleted.

    The install itself belongs to the label owner
    (``compromise_class.install_privilege_tier_label_provider``), because more
    than one reporting surface needs it; this stays as the endpoint-defense
    block's own entry point onto it.
    """
    try:
        from adscan_internal.services.compromise_class import (
            install_privilege_tier_label_provider,
        )

        install_privilege_tier_label_provider()
    except Exception as exc:  # noqa: BLE001 - a missing badge beats no report
        print_info_debug(f"tier label provider not installed: {exc}")


def _resolve_host_tiers(
    shell: Any,
    workspace_dir: str,
    domain: str,
    posture_hosts: Any,
    attempts: Any,
) -> dict[str, str]:
    """Map each host named in this block to its STAMPED privilege tier.

    Reuses the asset index the affected-assets surface already builds from the
    attack graph (``load_asset_index``), so the tier here is resolved by the
    same alias-aware lookup and read off the same stamped ``privilege_tier``
    property, never raw ``isTierZero`` (which is the pre-graph collector flag
    and legitimately reads False on a stamp-graded Tier 0).

    Why it matters to the client: credential material recovered from a Tier 0
    host, the ones that control the domain's identity, is a materially worse
    finding than the same read on a workstation. Without the tier both rows
    read the same.

    Best-effort. A workspace with no graph, or an older graph carrying no
    stamp, yields an empty map and the section renders with no tier badge,
    which is the honest outcome rather than a guessed one.
    """
    tiers: dict[str, str] = {}
    try:
        from adscan_internal.services.affected_assets_struct import load_asset_index

        index = load_asset_index(workspace_dir, domain)
    except Exception as exc:  # noqa: BLE001 - no graph is not an error here
        print_info_debug(f"host tiers not resolved for {domain}: {exc}")
        return tiers

    candidates: set[str] = set()
    for record in posture_hosts or ():
        if isinstance(record, Mapping):
            for key in ("dns_name", "host_object_id", "name"):
                value = str(record.get(key) or "").strip()
                if value:
                    candidates.add(value)
    for record in attempts or ():
        if isinstance(record, Mapping):
            value = str(record.get("host") or "").strip()
            if value:
                candidates.add(value)

    # A dump is run against whatever the operator targeted, which is usually an
    # IP, while the graph indexes computers by name and FQDN. Measured on a real
    # engagement: every row that mattered came back ungraded because its host
    # was recorded as an address. So an address is translated through the
    # workspace's own IP-to-hostname inventory, the same SSOT the Kerberos and
    # host-address resolvers use, before the tier is looked up.
    aliases = _ip_hostname_aliases(shell, workspace_dir, domain, candidates)

    for candidate in candidates:
        tier = ""
        for probe in _tier_lookup_probes(candidate, aliases):
            try:
                node = index.lookup(probe)
            except Exception:  # noqa: BLE001 - one unresolvable host is not fatal
                continue
            tier = str(getattr(node, "tier", "") or "").strip()
            if tier:
                break
        if tier:
            tiers[candidate.lower()] = tier
    return tiers


def _looks_like_address(value: str) -> bool:
    """Whether a host string is an IP literal rather than a name.

    An address has dots but no short form: splitting ``192.168.1.251`` on its
    first dot yields ``192``, which is not an abbreviation of anything. It is a
    plausible sAMAccountName, so in a directory that happens to hold a computer
    named ``192$`` the probe matches a completely unrelated object and inherits
    its tier. That is how two file and print servers graded Tier 1 on the graph
    came out as "Tier 2: Standard" in a rendered report, which is worse than
    leaving them ungraded: a wrong tier reads as measured.
    """
    text = str(value or "").strip()
    if not text:
        return False
    if ":" in text:  # IPv6, bracketed or bare
        return True
    parts = text.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def _tier_lookup_probes(
    candidate: str, aliases: Mapping[str, tuple[str, ...]]
) -> tuple[str, ...]:
    """Every name worth trying for one host, in order, without duplicates.

    The candidate itself, then the hostnames the workspace resolved for it when
    it is an address, and the SHORT form of each NAME: a collected computer node
    frequently carries only its sAMAccountName, with no ``dnsHostName``, so the
    index answers to ``DC-CORP-01`` and not to ``DC-CORP-01.corp.example``.
    Measured on a real engagement, where probing only the fully-qualified name
    left every host ungraded.

    An ADDRESS is never short-split, for the reason in
    :func:`_looks_like_address`. Resolved hostnames are therefore the only
    source of a short form when the recorded host is an IP, which is also the
    order that gets the right answer: the real name before any abbreviation.
    """
    probes: list[str] = []

    def _add(value: str) -> None:
        text = str(value or "").strip()
        if text and text not in probes:
            probes.append(text)

    _add(candidate)
    names = [candidate, *aliases.get(str(candidate).strip().lower(), ())]
    for name in names:
        _add(name)
    for name in names:
        if _looks_like_address(name):
            continue
        head = str(name or "").strip().split(".", 1)[0]
        if head and head != name:
            _add(head)
    return tuple(probes)


def _resolve_host_names(
    shell: Any, workspace_dir: str, domain: str, attempts: Any
) -> dict[str, str]:
    """The searchable NAME for each host an attempt recorded as an address.

    The section asks the client to find the same event in their own console,
    and a console is indexed by hostname. A dump records whatever the operator
    targeted, which is usually an address, so without this the one action the
    section asks for starts with the client translating an IP by hand. Reuses
    the workspace's own IP-to-hostname inventory, the same source the Kerberos
    and host-address resolvers read, so the name shown is the name the rest of
    the engine settled on.

    Best-effort and name-only: a host already recorded by name maps to itself
    and is filtered out downstream, and an address the inventory cannot resolve
    simply keeps showing as the address.
    """
    recorded = {
        str(r.get("host") or "").strip()
        for r in (attempts or ())
        if isinstance(r, Mapping) and str(r.get("host") or "").strip()
    }
    if not recorded:
        return {}
    aliases = _ip_hostname_aliases(shell, workspace_dir, domain, recorded)
    out: dict[str, str] = {}
    for host in recorded:
        for name in aliases.get(host.lower(), ()):
            if name and name.strip().lower() != host.lower():
                out[host.lower()] = name
                break
    return out


def _ip_hostname_aliases(
    shell: Any, workspace_dir: str, domain: str, candidates: set[str]
) -> dict[str, tuple[str, ...]]:
    """Hostname candidates for each address among ``candidates``.

    Reuses the persisted IP-to-hostname inventory rather than re-resolving
    anything, so the name a tier is looked up under is the same name the rest
    of the engine already settled on for that address. An empty result is
    normal (a run with no resolution report) and simply leaves those hosts
    ungraded, which the surfaces render as "Not graded".
    """
    try:
        from adscan_internal.services.kerberos_hostname_inventory import (
            load_workspace_ip_hostname_inventory,
        )

        inventory = load_workspace_ip_hostname_inventory(
            workspace_dir=workspace_dir,
            domains_dir=str(getattr(shell, "domains_dir", "domains") or "domains"),
            domain=domain,
        )
    except Exception as exc:  # noqa: BLE001 - no inventory is not an error
        print_info_debug(f"ip-hostname inventory unavailable for {domain}: {exc}")
        return {}

    wanted = {c.lower() for c in candidates}
    return {
        str(ip).strip().lower(): tuple(
            str(name).strip() for name in (names or ()) if str(name).strip()
        )
        for ip, names in (inventory or {}).items()
        if str(ip).strip().lower() in wanted
    }


def _read_posture_hosts(workspace_dir: str, domain: str) -> list[dict[str, Any]]:
    """The per-host posture rows the probe seam persisted for this domain."""
    domain_key = str(domain).strip().rstrip(".").lower()
    path = os.path.join(
        workspace_dir, "domains", domain_key, "inventory", "defensive_posture.json"
    )
    if not os.path.exists(path):
        return []
    try:
        data = read_json_file(path)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return []
    if not isinstance(data, dict):
        return []
    return [h for h in (data.get("hosts") or ()) if isinstance(h, dict)]


def _count_computers(workspace_dir: str, domain_key: str) -> int:
    """Total computers in the directory, the only honest context for the count.

    Never a coverage denominator (see
    :mod:`adscan_core.reporting.endpoint_defense`); it is there so the client
    can see how much of the estate the examined hosts represent.
    """
    path = os.path.join(
        workspace_dir, "domains", domain_key, "inventory", "computers.json"
    )
    if not os.path.exists(path):
        return 0
    try:
        data = read_json_file(path)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return 0
    if not isinstance(data, dict):
        return 0
    records = data.get("records")
    return len(records) if isinstance(records, list) else 0


__all__ = [
    "outcome_for",
    "read_attempts",
    "record_attempt",
    "record_endpoint_defense_for_domain",
]
