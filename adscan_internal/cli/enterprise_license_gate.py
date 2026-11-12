"""Enterprise license gate for the commands that START a new assessment.

Two seams:

* :func:`ensure_license_allows_new_scan` — at launch, in ``adscan ci`` (what the
  appliance worker runs), ``adscan execute`` and the interactive ``start``: the
  license itself (signature, dates, clock).
* :func:`ensure_environment_admitted` — where assessment activity in a DOMAIN
  begins (the unauthenticated scan and the authenticated enumeration of a
  domain): when a format 2 licence declares an entitlement mode, the domain's
  forest is identified pre-authentication and checked against it
  (``adscan_core.environment_ledger``). ``scoped``: a domain outside the signed
  scope is refused (a trusted one stays mapped as context). ``organizations``:
  the first forest of a workspace anchors an organization, a forest with an
  observed trust path to it is free, an unrelated one is refused unless an
  administrator declared it. An ATTENDED run (``start``, the REPL, a web scan
  whose policy leaves decisions to the operator at the console) asks at that
  moment whether the refused forest is the same organization; "same
  organization" writes the very declaration Settings > License writes (same
  record, same cap) and the forest is assessed with no new count. An
  unattended run refuses and records, as before: nobody is there to ask. The
  seam runs for a trusted forest only when ADscan collects in it; enumerating a
  trust never admits anything.
* :func:`record_scan_identity_usage` — at the end of a scan, ``scoped`` only:
  enabled identities per assessed domain, warned over the priced figure and
  never blocked.

Everything that only reads existing results (``deliver``, ``report``, the web
panel) never passes through here, so an expired license never hides a client's
own evidence.

LITE and PRO without the Enterprise marker get ``not_required`` from the SSOT
and these gates print nothing and change nothing; so does a license without the
environment entitlement.
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Coroutine
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from adscan_core.enterprise_license import (
    ERROR_LICENSE_UNREADABLE,
    LICENSE_BLOCKED_EXIT_CODE,
    LicenseStatus,
    record_engine_info,
    scan_launch_status,
)
from adscan_core.environment_ledger import (
    DECLARE_DIFFERENT_ORGANIZATION,
    DECLARE_SAME_ORGANIZATION,
    DECLARED_VIA_ASSESSMENT,
    MODE_SCOPED,
    OUTCOME_ADMITTED,
    OUTCOME_JOINED,
    REASON_ENVIRONMENT_QUOTA,
    REASON_OUTSIDE_SCOPE,
    REASON_WORKSPACE_ORGANIZATION,
    SOURCE_NAME_ONLY,
    EntitlementError,
    EnvironmentAdmission,
    ForestIdentity,
    admit_environment,
    confirmed_trust_edges,
    declaration_question,
    declare_same_organization,
    entitlement_policy,
    record_identity_count,
)
from adscan_core.interaction import is_non_interactive
from adscan_core.license_storage import (
    LICENSE_STORAGE_UNAVAILABLE_MESSAGE,
    REASON_LICENSE_STORAGE_UNAVAILABLE,
    LicenseStorageError,
)
from adscan_core.output import prompt_ask, questionary_select_index
from adscan_core.pal.process import current_user_name
from adscan_internal import (
    print_error,
    print_exception,
    print_info,
    print_info_debug,
    print_warning,
    telemetry,
)
from adscan_internal.rich_output import mark_sensitive

#: Written into the run's workspace when an environment is refused, so the
#: appliance worker can store the right reason beside exit 78.
LICENSE_REFUSAL_FILENAME = "license_refusal.json"

PHASE_UNAUTH = "unauth"
PHASE_AUTH = "auth"

_MEMO_ATTR = "_environment_admissions"
_REFUSED_ATTR = "_environment_refusals"

#: Operator-decision category of the inline "same organization" question. The
#: web console docks it over the scan pages and lets only an administrator pick
#: "same organization" (``admin_only_options``), as Settings > License does.
LICENSE_DECLARATION_CATEGORY = "license_declaration"
#: Who declares from the command line, when set (forwarded into the container
#: by the launcher's ``ADSCAN_*`` wildcard).
OPERATOR_NAME_ENV = "ADSCAN_OPERATOR_NAME"
#: Suffix that tells a command-line declaration from a console user's in the
#: usage report: the name there is the operator's statement, not a sign-in.
_COMMAND_LINE_SUFFIX = " (command line)"
_OPERATOR_NAME_MAX_LENGTH = 80


def ensure_lab_policy_allowed(shell: Any) -> bool:
    """Return True unless this run is a Lab / CTF one the appliance has turned off.

    On the Enterprise edition a lab policy (the Lab / CTF built-in, one based on
    it, or any policy for a lab environment, ``adscan_core.scan_policy.lab_policy``)
    runs only when the client's administrator turned lab policies on. The web
    platform and the host worker refuse such a scan first; this is the engine's
    own check, so a direct ``adscan ci`` on the appliance cannot bypass them.
    The refusal is written beside the run (exit 78), so the worker stores the
    same sentence. Off the Enterprise edition it is always True.
    """
    from adscan_core.scan_policy.lab_policy import (
        LAB_POLICY_DISABLED_MESSAGE,
        REASON_LAB_POLICY_NOT_ENABLED,
        gate_applies,
        is_lab_policy,
        lab_policies_available,
    )

    try:
        if not gate_applies():
            return True
        from adscan_internal.services.scan_controls import workspace_environment

        policy = getattr(shell, "scan_policy", None)
        definition = getattr(policy, "definition", None)
        lab_run = is_lab_policy(
            base=getattr(definition, "base", ""), environment=workspace_environment(shell)
        )
        if not lab_run or lab_policies_available(gated=True):
            return True
    except Exception as exc:  # noqa: BLE001 — a check that cannot run must not pass
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    telemetry.capture("lab_policy_refused", properties={"command": "ci"})
    print_error(LAB_POLICY_DISABLED_MESSAGE)
    _write_refusal_marker(shell, REASON_LAB_POLICY_NOT_ENABLED, LAB_POLICY_DISABLED_MESSAGE)
    return False


def ensure_license_allows_new_scan(command_name: str, *, workspace_dir: str | None = None) -> bool:
    """Return True when a new assessment may start; print why when it may not.

    Records the engine image's own expiry beside the license first, so the web
    platform can warn when the image would stop before the license does.
    Never raises: an unexpected failure blocks the launch with a clear message
    (Enterprise only), because "could not verify" must not read as "licensed".

    Args:
        command_name: The launching command, for telemetry.
        workspace_dir: The run's workspace when it already exists (``adscan
            ci`` from the appliance worker, which pre-creates it). A refusal
            caused by the license STORAGE (not the license) is recorded there,
            so the worker shows that cause instead of "missing, expired".
    """
    status: LicenseStatus
    try:
        status = scan_launch_status(record=False)
        if not status.required:
            # Not Enterprise: the PRO licence decides (dormant until required).
            from adscan_internal.cli.pro_license_gate import ensure_pro_license_allows_new_scan

            return ensure_pro_license_allows_new_scan(command_name, workspace_dir=workspace_dir)
        record_engine_info()
        status = scan_launch_status(record=True)
    except Exception as exc:  # noqa: BLE001 — a verifier crash must not pass silently
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        if isinstance(exc, LicenseStorageError):
            print_error(LICENSE_STORAGE_UNAVAILABLE_MESSAGE)
            _write_refusal_marker_in(
                workspace_dir, REASON_LICENSE_STORAGE_UNAVAILABLE, LICENSE_STORAGE_UNAVAILABLE_MESSAGE
            )
            return False
        print_error(
            "The ADscan license could not be checked, so new assessments cannot "
            "start. Existing reports, history and exports remain available."
        )
        return False

    telemetry.capture(
        "enterprise_license_checked",
        properties={
            "command": command_name,
            "state": status.state,
            "scans_allowed": status.scans_allowed,
        },
    )
    if not status.scans_allowed:
        print_error(status.display_message)
        if status.error_code == ERROR_LICENSE_UNREADABLE:
            _write_refusal_marker_in(workspace_dir, REASON_LICENSE_STORAGE_UNAVAILABLE, status.message)
        return False
    if status.warning:
        print_warning(status.display_message)
    if status.environments is not None and not status.environment_warning:
        print_info(f"License: {status.environments.summary}.")
    return True


# ── Environment admission ────────────────────────────────────────────────────


def _run_blocking(coro: Coroutine[Any, Any, Any]) -> Any:
    """Run a coroutine from sync code, also when a loop is already running."""
    from adscan_internal.services.async_bridge import run_async_sync  # noqa: PLC0415

    return run_async_sync(coro)


def _logical_workspace_name(shell: Any) -> str:
    """Logical workspace name (a live scan runs in ``.run_<logical>_<id>``)."""
    name = str(getattr(shell, "current_workspace", "") or "").strip()
    if name.startswith(".run_"):
        stem = name[len(".run_") :]
        head, sep, tail = stem.rpartition("_")
        if sep and head and tail and all(c in "0123456789abcdef" for c in tail.lower()):
            return head
    return name


def _domain_dc_ip(shell: Any, domain: str) -> str | None:
    from adscan_internal.models.domain import resolve_dc_ip

    data = (getattr(shell, "domains_data", None) or {}).get(domain) or {}
    try:
        return resolve_dc_ip(data)
    except Exception:  # noqa: BLE001 - a malformed record means "unknown"
        return None


def _root_dc_locator(shell: Any):
    """``(forest, resolver_ip) -> PDC ip`` through the shell's DNS service."""
    service_factory = getattr(shell, "_get_dns_discovery_service", None)
    if not callable(service_factory):
        return None

    async def _locate(forest: str, resolver_ip: str) -> str | None:
        service = service_factory()
        return await asyncio.to_thread(
            service.find_pdc_via_resolver, domain=forest, resolver_ip=resolver_ip
        )

    return _locate


def resolve_identity_for_admission(
    shell: Any, domain_norm: str, *, dc_ip: str | None = None, known: Any = None
) -> ForestIdentity:
    """The forest identity of ``domain_norm`` for a licence admission.

    Shared by the Enterprise environment ledger and the PRO domain registration
    (``pro_license_gate``), so both identify a forest the same way: reuses a
    confirmed identity from the session, otherwise asks the forest root
    pre-authentication (CLDAP), and adds the root SID once an authenticated
    phase has read it. Never raises (a name-only identity at worst).
    """
    if isinstance(known, ForestIdentity) and not known.provisional:
        identity = known
    else:
        target_dc = dc_ip or _domain_dc_ip(shell, domain_norm)
        from adscan_internal.services.forest_identity import resolve_forest_identity

        identity = _run_blocking(
            resolve_forest_identity(domain_norm, target_dc, locate_root_dc=_root_dc_locator(shell))
        )
    if identity.source != SOURCE_NAME_ONLY and identity.domain_dns_name == identity.forest_dns_name:
        sid = str(
            ((getattr(shell, "domains_data", None) or {}).get(domain_norm) or {}).get("domain_sid") or ""
        ).strip()
        if sid:
            identity = replace(identity, root_sid=sid)
    return identity


def _write_refusal_marker(shell: Any, reason_code: str, message: str) -> None:
    _write_refusal_marker_in(getattr(shell, "current_workspace_dir", ""), reason_code, message)


def _write_refusal_marker_in(workspace_dir: Any, reason_code: str, message: str) -> None:
    """Record why this run was refused, for the appliance worker (best-effort)."""
    workspace_dir = str(workspace_dir or "").strip()
    if not workspace_dir or not os.path.isdir(workspace_dir):
        return
    try:
        Path(workspace_dir, LICENSE_REFUSAL_FILENAME).write_text(
            json.dumps({"reason_code": reason_code, "message": message}),
            encoding="utf-8",
        )
    except OSError:
        return


def _memo(shell: Any) -> dict[str, dict[str, Any]]:
    memo = getattr(shell, _MEMO_ATTR, None)
    if not isinstance(memo, dict):
        memo = {}
        try:
            setattr(shell, _MEMO_ATTR, memo)
        except Exception:  # noqa: BLE001
            pass
    return memo


def environment_refused_for_run(shell: Any) -> bool:
    """True when this run was refused every environment it tried to assess.

    ``adscan ci`` returns exit 78 then. A run that assessed its primary forest
    and was refused only a trusted one finished its licensed work normally.
    """
    from adscan_internal.cli.pro_license_gate import pro_admission_memo

    entries = list(_memo(shell).values()) + list(pro_admission_memo(shell).values())
    refused = [entry for entry in entries if not entry.get("allowed")]
    admitted = [entry for entry in entries if entry.get("allowed")]
    return bool(refused) and not admitted


# ── Inline "same organization" declaration ───────────────────────────────────


@dataclass(frozen=True)
class DeclarationAnswer:
    """The operator's answer to the inline question.

    ``declared_by`` is who the declaration is recorded under; empty when the
    answer is "different organization", or when nobody could be named.
    """

    same_organization: bool
    declared_by: str = ""


def operator_can_declare(shell: Any) -> bool:
    """Whether a person is there to answer the inline declaration question.

    Interactive (``start``, the REPL): yes, unless the session has no terminal.
    Unattended entries (``ci``, ``execute``, the web worker): only when the
    scan policy leaves decisions to an operator AND the remote bridge connects
    one (``DECISION_ATTENDED``). Any other run refuses and records the forest,
    exactly as before the question existed: nobody is there to ask.
    """
    from adscan_core.scan_policy import execution as run_execution  # noqa: PLC0415

    try:
        if run_execution.run_entry(shell) == run_execution.ENTRY_INTERACTIVE:
            return not is_non_interactive(shell)
        return run_execution.execution_decision(shell) == run_execution.DECISION_ATTENDED
    except Exception as exc:  # noqa: BLE001 - unknown means nobody to ask
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False


def _clean_name(value: Any) -> str:
    return " ".join(str(value or "").split())[:_OPERATOR_NAME_MAX_LENGTH]


def _command_line_declarer(shell: Any) -> str:
    """Who a command-line declaration is recorded under.

    The command line has no sign-in, so the name is the operator's own
    statement: ``ADSCAN_OPERATOR_NAME`` when configured; natively, the OS
    account running ADscan; inside the container (where the OS account is the
    image's service user, never a person) the operator is asked. Empty when
    nobody gives a name, and then nothing is declared.
    """
    from adscan_internal.services.operator_identity import (  # noqa: PLC0415
        command_line_operator_name,
    )

    # The shared resolution (also used for a declined attack step). This
    # module's own ``prompt_ask`` / ``current_user_name`` are passed in so the
    # call keeps its patch points.
    return command_line_operator_name(
        shell,
        prompt_text="Your name, recorded with the declaration in the usage report",
        prompt=prompt_ask,
        user_name=current_user_name,
    )


def _ask_declaration(shell: Any, admission: EnvironmentAdmission, *, remaining: int) -> DeclarationAnswer:
    """Ask whether a refused forest is the same organization, and who says so.

    One question for both surfaces: the shell's select prompt relays it to the
    web console when the remote bridge is connected (the answer then carries
    the signed-in user who gave it) and asks on the terminal otherwise. The
    default, and a timeout, is "different organization": nothing is declared.
    """
    from adscan_internal import interactive_requests  # noqa: PLC0415

    remote = interactive_requests.is_remote_interaction_enabled()
    show = str if remote else (lambda label: mark_sensitive(label, "domain"))
    title, options = declaration_question(
        forest=show(admission.forest_label),
        anchor=show(admission.anchor_label),
        remaining=remaining,
    )
    context = {
        "remote_interaction": True,
        "category": LICENSE_DECLARATION_CATEGORY,
        "forest": admission.forest_label,
        "anchor": admission.anchor_label,
        "admin_only_options": [DECLARE_SAME_ORGANIZATION],
    }
    selector = getattr(shell, "_questionary_select", None)
    if callable(selector):
        index = selector(title, options, default_idx=DECLARE_DIFFERENT_ORGANIZATION, context=context)
    else:
        index = questionary_select_index(
            title=title, options=options, default_idx=DECLARE_DIFFERENT_ORGANIZATION, shell=shell
        )
    if index != DECLARE_SAME_ORGANIZATION:
        return DeclarationAnswer(same_organization=False)
    if remote:
        who = _clean_name(interactive_requests.last_responder())
    else:
        who = _command_line_declarer(shell)
    return DeclarationAnswer(same_organization=True, declared_by=who)


def _declare_inline(
    shell: Any,
    admission: EnvironmentAdmission,
    *,
    license_payload: Any,
    readmit: Any,
) -> EnvironmentAdmission:
    """Offer the inline declaration for a refused forest; the resulting admission.

    Returns the original refusal when the operator answers "different
    organization", when no name can be recorded, or when the declaration cannot
    be made (the cap filled meanwhile). Otherwise the declaration is written by
    the same function Settings > License uses, and the forest is admitted again.
    """
    remaining = admission.usage.remaining if admission.usage is not None else 0
    answer = _ask_declaration(shell, admission, remaining=remaining)
    if not answer.same_organization:
        return admission
    if not answer.declared_by:
        print_warning(
            "The answer did not say who gave it, so nothing was declared. An "
            "administrator can declare the forest under Settings > License."
        )
        return admission
    try:
        declare_same_organization(
            admission.refusal_id,
            declared_by=answer.declared_by,
            declared_via=DECLARED_VIA_ASSESSMENT,
            license_payload=license_payload,
        )
    except EntitlementError as exc:
        print_warning(str(exc))
        return admission
    telemetry.capture("enterprise_environment_declared_inline", properties={})
    return readmit()


def ensure_environment_admitted(
    shell: Any,
    domain: str,
    *,
    dc_ip: str | None = None,
    phase: str = PHASE_UNAUTH,
) -> bool:
    """Return True when ADscan may start assessing ``domain`` under the license.

    Cheap after the first call for a domain (session memo). A provisional
    admission (the forest root did not answer) is resolved again once at the
    authenticated phase and upgraded in place. Never raises: an unexpected
    failure on an Enterprise license that limits environments refuses, because
    "could not count" must not read as "free".
    """
    domain_norm = str(domain or "").strip().rstrip(".").lower()
    if not domain_norm:
        return True
    try:
        status = scan_launch_status(record=False)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False
    if not status.required:
        # Not Enterprise: the PRO licence registers the domain (dormant until required).
        from adscan_internal.cli.pro_license_gate import ensure_pro_domain_admitted

        return ensure_pro_domain_admitted(shell, domain_norm, dc_ip=dc_ip, phase=phase)
    if not status.scans_allowed:
        print_error(status.display_message)
        return False
    policy = entitlement_policy(status.license)
    if policy is None:
        return True

    memo = _memo(shell)
    previous = memo.get(domain_norm)
    if previous is not None:
        if not previous.get("allowed"):
            return False
        # Re-admit once at the authenticated phase: a provisional identity may
        # resolve now, and the trust records enumerated since the first
        # admission may show this forest belongs to an environment already
        # counted (same organisation, so the two are joined).
        if phase != PHASE_AUTH or previous.get("auth_retried"):
            return True

    try:
        identity = resolve_identity_for_admission(
            shell, domain_norm, dc_ip=dc_ip, known=(previous or {}).get("identity")
        )
        other_forests = {
            entry.get("forest")
            for key, entry in memo.items()
            if key != domain_norm and entry.get("allowed")
        }
        def _admit() -> EnvironmentAdmission:
            return admit_environment(
                identity,
                license_payload=status.license,
                now=datetime.now(timezone.utc),
                workspace=_logical_workspace_name(shell),
                trusted=bool(other_forests - {identity.forest_dns_name}),
                supersedes=(previous or {}).get("admitted_as") or None,
                trust_edges=confirmed_trust_edges(getattr(shell, "domains_data", None) or {}),
                format_label=lambda label: mark_sensitive(label, "domain"),
                format_person=lambda name: mark_sensitive(name, "user"),
            )

        admission = _admit()
        if (
            not admission.allowed
            and admission.reason_code == REASON_WORKSPACE_ORGANIZATION
            and admission.declarable
            and admission.refusal_id
            and operator_can_declare(shell)
        ):
            admission = _declare_inline(
                shell, admission, license_payload=status.license, readmit=_admit
            )
    except Exception as exc:  # noqa: BLE001 — counting must not fail open
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        if isinstance(exc, LicenseStorageError):
            # The license records could not be opened (a permission or storage
            # fault), so nothing was decided about the license: say so, and
            # record it for the worker rather than let it read as a refusal.
            print_error(LICENSE_STORAGE_UNAVAILABLE_MESSAGE)
            _write_refusal_marker(
                shell, REASON_LICENSE_STORAGE_UNAVAILABLE, LICENSE_STORAGE_UNAVAILABLE_MESSAGE
            )
        else:
            print_error(
                "The ADscan license could not check this domain against its "
                "entitlement, so its assessment cannot start. Existing reports, "
                "history and exports remain available."
            )
        memo[domain_norm] = {"allowed": False, "forest": domain_norm}
        return False

    memo[domain_norm] = {
        "allowed": admission.allowed,
        "admitted_as": admission.admitted_as,
        "source": identity.source,
        "forest": identity.forest_dns_name,
        "identity": identity,
        "auth_retried": phase == PHASE_AUTH,
    }
    telemetry.capture(
        "enterprise_environment_admission",
        properties={
            "phase": phase,
            "outcome": admission.outcome,
            "identity_source": identity.source,
            "used": admission.usage.used if admission.usage else None,
            "quota": admission.usage.quota if admission.usage else None,
        },
    )
    print_info_debug(
        f"environment admission domain_source={identity.source} outcome={admission.outcome}"
    )
    if not admission.allowed:
        assessed_elsewhere = any(
            entry.get("allowed") for key, entry in memo.items() if key != domain_norm
        )
        if admission.reason_code == REASON_OUTSIDE_SCOPE and assessed_elsewhere:
            # A trusted domain discovered beyond the licensed scope: it stays in
            # the map as context and the assessment of the in-scope ones goes on.
            print_info(
                f"{mark_sensitive(domain_norm, 'domain')} is outside this license's scope: "
                "it stays mapped as context and is not assessed."
            )
            return False
        print_error(admission.message)
        _write_refusal_marker(shell, admission.reason_code or REASON_ENVIRONMENT_QUOTA, admission.message)
        return False
    if admission.outcome in (OUTCOME_ADMITTED, OUTCOME_JOINED):
        print_info(admission.message)
    if admission.usage is not None and admission.usage.warning_message:
        print_warning(admission.usage.warning_message)
    return True


def record_scan_identity_usage(shell: Any) -> None:
    """Record the enabled identities of every domain this session assessed.

    ``scoped`` licences only: the count is read from the workspace (the enabled
    user list the enumeration wrote) and kept as the latest figure and a
    high-water mark per domain. Over the priced figure this WARNS; it never
    blocks, and it never raises.
    """
    try:
        status = scan_launch_status(record=False)
        if not status.required:
            from adscan_internal.cli.pro_license_gate import record_pro_scan_bands

            record_pro_scan_bands(shell)
            return
        if status.license is None:
            return
        policy = entitlement_policy(status.license)
        if policy is None or policy.mode != MODE_SCOPED:
            return
        from adscan_internal.services.estate_size_telemetry import build_estate_size_properties

        usage = None
        for domain, entry in _memo(shell).items():
            if not entry.get("allowed"):
                continue
            count = build_estate_size_properties(shell, domain).get("user_count")
            if count is None:
                continue
            identity = entry.get("identity")
            usage = record_identity_count(
                domain,
                int(count),
                license_payload=status.license,
                workspace=_logical_workspace_name(shell),
                identity_confirmed=isinstance(identity, ForestIdentity) and not identity.provisional,
            )
        if usage is not None:
            if usage.warning_message:
                print_warning(usage.warning_message)
            else:
                print_info(f"License: {usage.summary}.")
    except Exception as exc:  # noqa: BLE001 — usage recording never breaks a scan
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        if isinstance(exc, LicenseStorageError):
            # Not silent: the identity peak was NOT recorded for this run.
            print_warning(
                "ADscan could not write its license records on this appliance, so "
                "this assessment's identity count was not recorded. Contact ADscan "
                "support."
            )


__all__ = [
    "LICENSE_BLOCKED_EXIT_CODE",
    "LICENSE_REFUSAL_FILENAME",
    "ensure_lab_policy_allowed",
    "PHASE_AUTH",
    "PHASE_UNAUTH",
    "ensure_environment_admitted",
    "ensure_license_allows_new_scan",
    "environment_refused_for_run",
    "record_scan_identity_usage",
    "resolve_identity_for_admission",
]
