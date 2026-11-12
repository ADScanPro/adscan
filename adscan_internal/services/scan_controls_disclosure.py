"""Stamp the scan-policy and assessment-pace disclosure blocks for a run.

Engine-side half of the disclosure (the pure builders live in
``adscan_core.scan_policy.coverage`` and
``adscan_core.reporting.scan_pacing_disclosure``). Reads the run's state off the
shell (the resolved policy, where it came from, a pending ``policy clear``, the
engine's refusal records, the published pace and the strain safeguard's report)
and records both blocks for every domain of the run in ``technical_report.json``.

Called from the scan-finalization seam
(``attack_path_execution.rematerialize_attack_path_snapshots_at_scan_end``)
twice: first, before findings are reconciled, so a stub-shell writer already
sees the excluded detections (S7) and the scan-end compliance stamp sees the
block; then with the canonical listing, to fill ``routes_not_executed``.
Idempotent; best-effort; never raises into the scan.

``policy clear`` contract (scan-policy spec D-1): the first run after the clear
discloses it, then the workspace record is marked ``disclosed_at`` and later
runs no longer repeat it. A new policy replaces the record entirely.
"""

from __future__ import annotations

import os
from typing import Any, Iterable, Mapping

from adscan_core import telemetry
from adscan_core.rich_output import print_exception

#: Shell attribute: the clear record this session has already disclosed.
_CLEAR_DISCLOSED_ATTR = "_scan_policy_clear_disclosed"


def _run_domains(shell: Any) -> list[str]:
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return []
    return [d for d in domains_data if isinstance(d, str) and d.strip()]


def _pending_clear(shell: Any) -> Mapping[str, Any] | None:
    disclosed = getattr(shell, _CLEAR_DISCLOSED_ATTR, None)
    if isinstance(disclosed, Mapping):
        return disclosed
    cleared = getattr(shell, "scan_policy_cleared", None)
    if not isinstance(cleared, Mapping) or not cleared:
        return None
    if cleared.get("disclosed_at"):
        return None
    if getattr(shell, "scan_policy", None) is not None:
        # A new policy applies to this run; the clear is superseded.
        return None
    return cleared


def _read_lines(path: str) -> list[str]:
    try:
        with open(path, encoding="utf-8") as handle:
            return [ln.strip() for ln in handle if ln.strip()]
    except OSError:
        return []


def _hosts_by_domain(shell: Any, domains: Iterable[str]) -> dict[str, set[str]]:
    """Known hosts (IPs and names) of each run domain, from the recorded inventory."""
    domains_data = getattr(shell, "domains_data", None) or {}
    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "")
    result: dict[str, set[str]] = {}
    for domain in domains:
        hosts: set[str] = set()
        data = domains_data.get(domain) if isinstance(domains_data, dict) else None
        if isinstance(data, dict):
            for key in ("pdc", "dc_ip", "pdc_hostname_fqdn", "dc_fqdn"):
                value = data.get(key)
                if isinstance(value, str) and value.strip():
                    hosts.add(value.strip())
            for value in data.get("dcs") or ():
                if isinstance(value, str) and value.strip():
                    hosts.add(value.strip())
        if workspace_dir:
            base = os.path.join(workspace_dir, "domains", domain)
            for name in ("dcs.txt", "enabled_computers_ips.txt", "enabled_computers.txt"):
                hosts.update(_read_lines(os.path.join(base, name)))
        result[domain] = hosts
    return result


def _pacing_block(shell: Any, domain: str | None = None) -> dict[str, Any]:
    """The ``scan_pacing`` block, its strain narrowed to ``domain``'s hosts when given."""
    from adscan_core.reporting.scan_pacing_disclosure import (
        build_scan_pacing_disclosure,
        strain_for_domain,
    )
    from adscan_core.scan_pacing import active_pacing
    from adscan_core.scan_pacing.pacing_runtime import active_runtime

    resolved_pacing = getattr(shell, "scan_pacing", None) or active_pacing()
    strain: Mapping[str, Any] | None = None
    try:
        strain = active_runtime().strain_report()
    except Exception as exc:  # noqa: BLE001 - disclosure states what it has
        telemetry.capture_exception(exc)
    if domain and strain is not None:
        strain = strain_for_domain(
            strain,
            domain=domain,
            hosts_by_domain=_hosts_by_domain(shell, _run_domains(shell)),
        )
    return build_scan_pacing_disclosure(
        resolved_pacing,
        strain=strain,
        fast_downgraded=bool(getattr(shell, "scan_pacing_fast_downgraded", False)),
    )


def _reversal_capability_block(shell: Any) -> dict[str, Any] | None:
    """The cleanup-account capability block this run established, or ``None``.

    The run records it once the directory is collected (``cleanup_capability``);
    the disclosure reads that FINAL record. One taken before collection, or none
    at all, is established now, read-only (``capability_block_for_report``).
    """
    from adscan_internal.services.cleanup_capability import (  # noqa: PLC0415
        capability_block_for_report,
    )

    return capability_block_for_report(shell)


def build_blocks(
    shell: Any, *, listings: Mapping[str, Iterable[Any]] | None = None
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return ``(scan_policy_coverage, scan_pacing)`` for the run on ``shell``."""
    from adscan_core.reporting.scan_pacing_disclosure import scan_pacing_disclosure_view
    from adscan_core.scan_policy import gate
    from adscan_core.scan_policy.annotate import (
        annotate_policy_exclusions,
        count_routes_not_executed,
        excluded_relations_from_block,
    )
    from adscan_core.scan_policy.execution import execution_decision
    from adscan_core.scan_policy.coverage import build_scan_policy_coverage
    from adscan_core.version import get_version
    from adscan_internal.services.revert_permission import (
        in_scope_run_domains,
        record_domain_verdicts,
        verdicts_for_report,
    )
    from adscan_internal.services.scan_policy_enforcement import refusals
    from adscan_internal.services.spray_policy_service import (
        resolve_password_attempt_rules,
    )

    pacing_block = _pacing_block(shell)
    # The verdict per in-scope domain is stated even when no gated write was reached.
    # A domain outside the engagement scope is never assessed, so it gets none.
    record_domain_verdicts(shell, in_scope_run_domains(shell, _run_domains(shell)))

    try:
        version = get_version()
    except Exception:  # noqa: BLE001
        version = ""
    policy_block = build_scan_policy_coverage(
        gate.active_policy(shell),
        source=str(getattr(shell, "scan_policy_source", "") or ""),
        refusals=refusals(shell),
        cleared=_pending_clear(shell),
        posture_probe_disabled=bool(os.environ.get("ADSCAN_NO_POSTURE_PROBE")),
        engine_version=version,
        pacing_applied=scan_pacing_disclosure_view(pacing_block),
        execution_decision=execution_decision(shell),
        password_attempts=resolve_password_attempt_rules(shell).to_dict(),
        revert_verdicts=[v.to_dict() for v in verdicts_for_report(shell)],
        reversal_capability=_reversal_capability_block(shell),
        agreed_policy=getattr(getattr(shell, "scan_config", None), "agreed_policy", None),
    )
    if listings:
        # Display metadata only (never the path set or a status), the same
        # annotation the report seam applies, so the count matches what renders.
        relations = excluded_relations_from_block(policy_block)
        total = 0
        for records in listings.values():
            batch = [r for r in (records or ()) if isinstance(r, dict)]
            annotate_policy_exclusions(batch, relations)
            total += count_routes_not_executed(batch)
        policy_block["routes_not_executed"] = total
    return policy_block, pacing_block


def _in_engagement_scope(shell: Any, domain: str) -> bool:
    try:
        from adscan_internal.services.engagement_scope import (  # noqa: PLC0415
            domain_in_engagement_scope,
        )

        return bool(domain_in_engagement_scope(shell, domain))
    except Exception as exc:  # noqa: BLE001 - unknown scope: state nothing for it
        telemetry.capture_exception(exc)
        return False


def stamp_scan_controls_disclosure(
    shell: Any, *, listings: Mapping[str, Iterable[Any]] | None = None
) -> None:
    """Record both blocks for every domain of the run. Never raises."""
    try:
        domains = _run_domains(shell)
        if not domains or not getattr(shell, "current_workspace_dir", None):
            return
        from adscan_core.reporting.technical_report import (
            record_scan_pacing,
            record_scan_policy_coverage,
        )

        policy_block, pacing_block = build_blocks(shell, listings=listings)
        from adscan_core.reporting.scan_pacing_disclosure import (
            scan_pacing_disclosure_view,
        )

        for domain in domains:
            # The pace is a property of the run, but the servers the safeguard
            # slowed belong to a domain: each statement names only its own.
            domain_pacing = _pacing_block(shell, domain)
            domain_policy = dict(policy_block)
            domain_policy["pacing_applied"] = scan_pacing_disclosure_view(domain_pacing)
            if not _in_engagement_scope(shell, domain):
                # What the cleanup account can undo is a statement about the
                # in-scope forests; a domain the engagement does not cover
                # (a trust partner only mapped) carries none.
                domain_policy.pop("reversal_capability", None)
            record_scan_policy_coverage(shell, domain, block=domain_policy)
            record_scan_pacing(shell, domain, block=domain_pacing)

        cleared = policy_block.get("cleared")
        if isinstance(cleared, Mapping) and cleared and not isinstance(
            getattr(shell, _CLEAR_DISCLOSED_ATTR, None), Mapping
        ):
            from adscan_internal.services.scan_controls import (
                mark_policy_clear_disclosed,
            )

            setattr(shell, _CLEAR_DISCLOSED_ATTR, dict(cleared))
            mark_policy_clear_disclosed(getattr(shell, "current_workspace_dir", None))
    except Exception as exc:  # noqa: BLE001 - disclosure never breaks the scan
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


__all__ = ["build_blocks", "stamp_scan_controls_disclosure"]
