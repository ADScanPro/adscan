"""Detector families that report every outcome into the run's observation record.

Each function here is called by the code that ran the check, with the results
it just produced, and records one observation per (check, domain): clear,
finding, not assessed or failed. Families whose every outcome is recorded here
are the ``instrumented`` ones in ``adscan_core.engagement.detectors``; their
observation is then required before an absent item can close.

Best-effort: the seam (``coverage_recorder.note_observation``) never raises and
does nothing outside a recorded run.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable, Mapping, Optional

from adscan_core.engagement.detectors import CVE_CHECK_IDS
from adscan_core.engagement.observations import Outcome
from adscan_internal.services.engagement.coverage_recorder import note_observation

#: Verdict categories of one CVE probe result.
_RAN_CLEAR = "clear"
_RAN_FINDING = "finding"
_NOT_RUN = "not_run"


def _verdict(status: Any) -> Optional[str]:
    from adscan_internal.services.cve_scanner.result import CVEStatus  # noqa: PLC0415

    if status is CVEStatus.VULNERABLE:
        return _RAN_FINDING
    # Not applicable is a reading: the host offers no surface for the probe.
    if status in (CVEStatus.NOT_VULNERABLE, CVEStatus.NOT_APPLICABLE):
        return _RAN_CLEAR
    if status in (CVEStatus.ERROR, CVEStatus.SKIPPED):
        return _NOT_RUN
    return None  # still running: not an outcome


def observe_cve_results(
    shell: Any,
    results: Iterable[Any],
    *,
    host_to_domain: Optional[Mapping[str, str]] = None,
    default_domain: Optional[str] = None,
    replace: bool = False,
) -> None:
    """Record one observation per CVE probe and domain from a scan's results.

    ``replace`` (see ``CoverageRecorder.observe``) is for a caller passing the
    run's FULL per-host verdict set for each probe it names, so the record is
    rebuilt rather than merged.

    Complete only when every targeted host returned a verdict; a host that
    errored or was skipped makes the observation incomplete (it names how many
    of the targeted hosts answered), so the family can never vouch for hosts
    it did not reach. Host object ids are not known here, so an incomplete
    observation carries counts only and closes nothing object by object.
    """
    host_map = dict(host_to_domain or {})
    default = str(default_domain or "").strip()
    tally: dict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {"clear": 0, "finding": 0, "not_run": 0, "statuses": set()}
    )
    for result in results or ():
        check_id = CVE_CHECK_IDS.get(str(getattr(result, "cve_id", "") or ""))
        if check_id is None:
            continue
        verdict = _verdict(getattr(result, "status", None))
        if verdict is None:
            continue
        host = str(getattr(result, "host", "") or "").strip()
        domain = str(host_map.get(host) or default or "").strip()
        if not domain:
            continue
        counts = tally[(check_id, domain)]
        counts[verdict] += 1
        if verdict == _NOT_RUN:
            counts["statuses"].add(str(getattr(getattr(result, "status", None), "value", "")))

    for (check_id, domain), counts in sorted(tally.items()):
        answered = counts["clear"] + counts["finding"]
        total = answered + counts["not_run"]
        if answered == 0:
            outcome = Outcome.NOT_ASSESSED
        elif counts["finding"]:
            outcome = Outcome.FINDING
        else:
            outcome = Outcome.CLEAR
        reason = ",".join(f"probe_{s}" for s in sorted(counts["statuses"]) if s)
        note_observation(
            shell,
            check_id,
            outcome,
            domain=domain,
            scope_kind="host",
            complete=counts["not_run"] == 0 and answered > 0,
            examined=answered,
            total=total,
            reason=reason,
            replace=replace,
        )


__all__ = ("observe_cve_results",)
