"""Outcome mapping for the checks fed by the CA registry probe.

ESC6 (``EDITF_ATTRIBUTESUBJECTALTNAME2``), ESC11 (``IF_ENFORCEENCRYPTICERTREQUEST``)
and Certighost (chase flag plus the CA host's patch level) are decided from
values read on the CA host. A probe that could not run, or a value that could
not be read, is a DATA GAP: the check is recorded ``not_assessed`` with a
reason, never ``clear`` and never a finding. Pure logic plus one recorder.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from adscan_core import telemetry
from adscan_core.rich_output import print_exception

CHECK_ESC6 = "adcs.esc6"
CHECK_ESC11 = "adcs.esc11"
CHECK_CERTIGHOST = "cve.certighost"
REGISTRY_CHECK_IDS: tuple[str, ...] = (CHECK_ESC6, CHECK_ESC11, CHECK_CERTIGHOST)

#: Finding keys the scan policy gates the three checks on.
REGISTRY_FINDING_KEYS: tuple[str, ...] = ("adcs_esc6", "adcs_esc11", "certighost")

REASON_PATCH_LEVEL_UNKNOWN = "ca_patch_level_unknown"


@dataclass(frozen=True)
class CheckAssessment:
    """Whether one check could be decided, and why not when it could not."""

    assessed: bool
    reason: str = ""


def assess_registry_checks(
    registry: Any, *, skip_reason: str
) -> dict[str, CheckAssessment]:
    """Return the assessment of each registry-fed check for one CA.

    Args:
        registry: The CA's ``CARegistryProbeResult`` or ``None`` when no probe ran.
        skip_reason: Why no probe ran (no administrator credential, scan policy,
            unknown CA host). Used only when ``registry`` is ``None``.
    """
    from adscan_internal.services.adcs.esc12_detection import (  # noqa: PLC0415
        REASON_READ_FAILED,
    )
    from adscan_internal.services.collector.adcs_detectors.certighost_detector import (  # noqa: PLC0415
        certighost_patch_status,
    )

    if registry is None:
        gap = CheckAssessment(False, skip_reason)
        return {cid: gap for cid in REGISTRY_CHECK_IDS}

    reason = getattr(registry, "error_reason", "") or REASON_READ_FAILED
    gap = CheckAssessment(False, reason)
    esc6 = CheckAssessment(True) if registry.edit_flags_readable else gap
    esc11 = (
        CheckAssessment(True)
        if getattr(registry, "interface_flags_readable", False)
        else gap
    )
    if not registry.edit_flags_readable:
        certighost = gap
    elif certighost_patch_status(registry.os_build_number, registry.os_ubr) == "unknown":
        certighost = CheckAssessment(False, REASON_PATCH_LEVEL_UNKNOWN)
    else:
        certighost = CheckAssessment(True)
    return {CHECK_ESC6: esc6, CHECK_ESC11: esc11, CHECK_CERTIGHOST: certighost}


def observe_registry_check(
    shell: Any,
    *,
    domain: str,
    check_id: str,
    assessment: CheckAssessment,
    found: bool,
) -> None:
    """Record one check's observation for one CA. Never raises.

    ``found`` is meaningful only for an assessed check: a finding when the
    detector emitted an edge for this CA, a clear reading otherwise. An
    unassessed check is ``not_assessed`` with its reason.
    """
    if shell is None:
        return
    try:
        from adscan_core.engagement.observations import Outcome  # noqa: PLC0415
        from adscan_internal.services.engagement.coverage_recorder import (  # noqa: PLC0415
            note_observation,
        )

        if not assessment.assessed:
            outcome = Outcome.NOT_ASSESSED
        elif found:
            outcome = Outcome.FINDING
        else:
            outcome = Outcome.CLEAR
        ran = assessment.assessed
        note_observation(
            shell,
            check_id,
            outcome,
            domain=domain,
            scope_kind="host",
            complete=ran,
            examined=1 if ran else 0,
            total=1,
            reason="" if outcome is Outcome.FINDING else assessment.reason,
        )
    except Exception as exc:  # noqa: BLE001 - coverage never breaks collection
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


__all__ = [
    "CHECK_CERTIGHOST",
    "CHECK_ESC11",
    "CHECK_ESC6",
    "CheckAssessment",
    "REASON_PATCH_LEVEL_UNKNOWN",
    "REGISTRY_CHECK_IDS",
    "REGISTRY_FINDING_KEYS",
    "assess_registry_checks",
    "observe_registry_check",
]
