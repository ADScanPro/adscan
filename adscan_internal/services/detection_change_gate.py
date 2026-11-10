"""The one seam through which detection code may change the client's environment.

Detection and collection code reads. A few detections can be CONFIRMED by an
action that changes the environment: the ESC15 and ESC9/ESC10 confirmations
enroll a certificate on the client's CA, revoked at the final revert pass when
the run holds a certificate-manager credential and disclosed otherwise. That action is its own check in the scan-policy registry (a
``module:...`` declaration in ``scan_phases.MODULE_CHECK_DECLARATIONS`` whose
``environment_change_kinds`` say what it leaves behind), so the built-ins place
it by what it declares: on in Lab / CTF, off in Audit and Production-sensitive.

Every such action passes :func:`authorize_detection_change`, which applies the
same two rules an attack step's own write passes:

1. **The policy subtracts.** A check the active policy excludes is refused
   through :func:`scan_policy_enforcement.refuse` (one operator line, one
   disclosure record), never asked about.
2. **Consent.** :func:`directory_change_consent.confirm_directory_change`
   decides the rest: by the policy in an unattended run, by asking the operator
   (preset to the policy's answer) in an attended one, refused in a map-only run,
   and, with no policy at all, by the built-in the workspace type implies.

The function returns a :class:`DetectionChangeAuthorization` or ``None``. The
function that calls the environment-changing primitive takes that token as a
parameter, and nothing else constructs it, so the primitive is unreachable from
detection code without passing the gate. The structural test
``tests/unit/scan_policy/test_detection_writes_are_policy_gated.py`` holds both
halves: no detection-code function calls a primitive in
:data:`ENVIRONMENT_CHANGE_PRIMITIVES` unless it takes the token, and every
check id passed here is a registry check that declares a write.

When the gate refuses, the detection keeps the confidence it already has: the
finding is reported confirmation-pending
(``adscan_core.reporting.finding_confidence``), never confirmed by a silent
enrollment and never dropped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from adscan_core.rich_output import print_exception, print_info_verbose
from adscan_internal import telemetry
from adscan_internal.rich_output import mark_sensitive

#: Check ids of the confirmation actions (declared in
#: ``scan_phases.MODULE_CHECK_DECLARATIONS``).
ESC15_CONFIRMATION_CHECK_ID = "module:adcs_esc15_confirmation"
ESC9_CONFIRMATION_CHECK_ID = "module:adcs_esc9_confirmation"

#: ``surface`` recorded on a refusal made by this seam.
REFUSAL_SURFACE = "detection_confirmation"

#: Call names that change the client's environment: certificate enrollment
#: (the single enrollment seam and the runners built on it) and the ledger and
#: directory-write seams. Detection code may call one only from a function that
#: takes a :class:`DetectionChangeAuthorization`.
ENVIRONMENT_CHANGE_PRIMITIVES: frozenset[str] = frozenset(
    {
        # Certificate enrollment.
        "request_certificate_native",
        "confirm_esc15_vulnerable",
        "confirm_esc9_vulnerable",
        "run_esc15_confirm",
        "run_esc15_confirm_sync",
        "run_esc",
        "run_esc_sync",
        "register_issued_certificate",
        # Environment-change ledger recorders (a recorded change is a change).
        "register_change",
        "register_ldap_change",
        "record_directory_write",
        "record_password_reset",
        "record_account_enabled",
        "record_object_restored",
        # Directory writes.
        "acquire_controlled_machine_account",
        "add_computer_native",
        "add_computer_to_domain",
        "set_rbcd_delegation",
        "add_shadow_credentials",
        "add_shadow_credentials_native",
        "add_group_member",
        "set_object_attribute",
        "set_object_attribute_values",
        "set_service_principal_name",
        "set_user_logon_script",
        "set_object_owner_detailed",
        "grant_generic_all_on_ou",
        "change_password_with_samr",
        "enable_user",
        "enable_computer",
        "restore_deleted_object",
        "plant_bait_targets",
    }
)

#: Per-ESC runners (``run_esc1`` ... ``run_esc16`` and their variants such as
#: ``run_esc15_schannel_sync``), matched by pattern. The collection-stage phase
#: drivers (``run_esc15_confirmation_phase``) are not runners: they hold the gate.
ENVIRONMENT_CHANGE_PRIMITIVE_PATTERN = re.compile(r"^run_esc\d+(?!.*_phase$)(_[a-z_]+)?$")


def is_environment_change_primitive(name: str) -> bool:
    """True when ``name`` is a call that changes the client's environment."""
    return name in ENVIRONMENT_CHANGE_PRIMITIVES or bool(
        ENVIRONMENT_CHANGE_PRIMITIVE_PATTERN.match(name)
    )


@dataclass(frozen=True)
class DetectionChangeAuthorization:
    """Proof that the gate approved one environment change for a detection.

    Only :func:`authorize_detection_change` builds one (structural test).
    """

    check_id: str
    domain: str


def authorize_detection_change(
    shell: Any, check_id: str, *, domain: str, prompt: str
) -> DetectionChangeAuthorization | None:
    """Decide whether a detection may make the environment change ``check_id`` owns.

    Args:
        shell: The active shell.
        check_id: The registry check that owns the change.
        domain: The domain the change is made in.
        prompt: The question shown when an operator decides.

    Returns:
        The authorization, or ``None`` when the policy or the operator declines.
        Never raises: any failure declines.
    """
    try:
        from adscan_internal.services.directory_change_consent import (  # noqa: PLC0415
            confirm_directory_change,
        )
        from adscan_internal.services.scan_policy_enforcement import (  # noqa: PLC0415
            check_excluded,
            refuse,
        )

        if check_excluded(shell, check_id):
            refuse(shell, check_id, surface=REFUSAL_SURFACE, domain=domain)
            return None
        if not confirm_directory_change(shell, prompt, check_id=check_id):
            print_info_verbose(
                f"{mark_sensitive(check_id, 'detail')} not run on "
                f"{mark_sensitive(domain, 'domain')}: no consent for the change it makes."
            )
            return None
        return DetectionChangeAuthorization(check_id=str(check_id), domain=str(domain))
    except Exception as exc:  # noqa: BLE001 - a failing gate declines
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


__all__ = (
    "DetectionChangeAuthorization",
    "ENVIRONMENT_CHANGE_PRIMITIVES",
    "ENVIRONMENT_CHANGE_PRIMITIVE_PATTERN",
    "ESC15_CONFIRMATION_CHECK_ID",
    "ESC9_CONFIRMATION_CHECK_ID",
    "REFUSAL_SURFACE",
    "authorize_detection_change",
    "is_environment_change_primitive",
)
