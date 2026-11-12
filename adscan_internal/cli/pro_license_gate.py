"""PRO licence gate at the engine's licence seams (spec § 9).

Called from :mod:`adscan_internal.cli.enterprise_license_gate` when the
deployment is not Enterprise, at the same three seams:

* :func:`ensure_pro_license_allows_new_scan` — at launch (``ci``,
  ``execute``, ``start``, ``recheck``).
* :func:`ensure_pro_domain_admitted` — where assessment of a domain begins:
  computes the per-partner domain code, shows it, and registers the forest
  under the licence's policy (trial: queued, never blocks; partner and paid:
  registered, 14 days of grace for a new code; offline engagement: the
  environment ledger).
* :func:`record_pro_scan_bands` — at scan end: the identity band of each
  admitted forest, queued as a band report when it changed, and written on
  this run's usage line.
* :func:`record_pro_recheck_usage` — after ``adscan recheck``: a usage line
  ``run_kind=recheck`` with its parent scan for each code that scan assessed.
  Nothing is queued for the server: a recheck is never billable.

Every admission also records the run's usage line (run kind, run id, date,
licence retest window) and, when a full scan opens a new billable engagement
of an already-known code, an engagement report. The run kind is
:func:`assessment_run_kind`: a recheck session never registers a domain nor
starts its grace (:func:`adscan_core.pro_license.evaluation.admit_domain`).

DORMANT until required (:func:`adscan_core.pro_license.evaluation.enforcement_required`):
LITE never consults it, and PRO without the licensed-build marker and without
an installed licence behaves exactly as before. Never raises: an unexpected
failure on a REQUIRED licence refuses ("could not verify" never reads as
"licensed"); on a dormant one it changes nothing.

Network: only a direct registration attempt (short timeout) when a new domain
is admitted, and never under ``ADSCAN_OFFLINE`` / ``ADSCAN_NO_EXTERNAL``
(relay mode then). Telemetry carries the state and outcome only, never a
licence id, an activation key or a domain code.
"""

from __future__ import annotations

from typing import Any

from adscan_core.offline import offline_mode_enabled
from adscan_core.pro_license import client as pro_client
from adscan_core.pro_license import evaluation as pro_eval
from adscan_core.pro_license.billable_engagements import RUN_KIND_FULL_SCAN, RUN_KIND_RECHECK
from adscan_core.pro_license.model import POLICY_OFFLINE, ProLicense
from adscan_core.pro_license.state import ProLicenseStore
from adscan_internal import print_error, print_exception, print_info, print_warning, telemetry
from adscan_internal.rich_output import mark_sensitive

#: Same file the Enterprise check reads, monkeypatched by tests.
PRO_LICENSE_MARKER = pro_eval.PRO_LICENSE_MARKER

_MEMO_ATTR = "_pro_domain_admissions"
_DIRECT_TIMEOUT_SECONDS = 5.0


def _is_pro() -> bool:
    from adscan_core.tier import is_pro

    return is_pro()


def _store() -> ProLicenseStore:
    return ProLicenseStore()


def _required(store: ProLicenseStore) -> bool:
    return _is_pro() and pro_eval.enforcement_required(store, marker=PRO_LICENSE_MARKER)


def assessment_run_kind(shell: Any) -> str:
    """The billing run kind of this session: ``recheck`` for ``adscan recheck``, else a full scan."""
    command = str(getattr(shell, "session_command_type", "") or "").strip().lower()
    return RUN_KIND_RECHECK if command == RUN_KIND_RECHECK else RUN_KIND_FULL_SCAN


def _run_id() -> str:
    from adscan_core.engagement.run_identity import current_run_id

    return current_run_id()


def pro_admission_memo(shell: Any) -> dict[str, dict[str, Any]]:
    """Per-session record of PRO domain admissions (read by ``environment_refused_for_run``)."""
    memo = getattr(shell, _MEMO_ATTR, None)
    if not isinstance(memo, dict):
        memo = {}
        try:
            setattr(shell, _MEMO_ATTR, memo)
        except Exception:  # noqa: BLE001 - a shell without attributes still works
            pass
    return memo


def _write_refusal(shell: Any, reason_code: str, message: str) -> None:
    from adscan_internal.cli.enterprise_license_gate import _write_refusal_marker

    _write_refusal_marker(shell, reason_code, message)


def ensure_pro_license_allows_new_scan(command_name: str, *, workspace_dir: str | None = None) -> bool:
    """True when a new assessment may start under the PRO licence."""
    try:
        store = _store()
        if not _required(store):
            return True
        status = pro_eval.check_pro_license(store, record=True)
    except Exception as exc:  # noqa: BLE001 - a verifier crash must not pass silently
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(
            "The ADscan PRO licence could not be checked, so new assessments cannot start. "
            "Existing reports and workspaces remain available."
        )
        return False
    telemetry.capture(
        "pro_license_checked",
        properties={"command": command_name, "state": status.state, "scans_allowed": status.scans_allowed},
    )
    if not status.scans_allowed:
        print_error(status.message)
        if workspace_dir:
            from adscan_internal.cli.enterprise_license_gate import _write_refusal_marker_in

            _write_refusal_marker_in(workspace_dir, f"pro_license_{status.state}", status.message)
        return False
    if status.warning:
        print_warning(status.message)
    return True


def _send_callable():
    if offline_mode_enabled():
        return None
    try:
        return pro_client.HttpTransport(timeout=_DIRECT_TIMEOUT_SECONDS).send
    except ValueError:
        return None


def _admit_offline(shell: Any, store: ProLicenseStore, licence: ProLicense, identity: Any) -> tuple[bool, str, str]:
    from datetime import datetime, timezone

    from adscan_core.environment_ledger import admit_environment, confirmed_trust_edges
    from adscan_internal.cli.enterprise_license_gate import _logical_workspace_name

    admission = admit_environment(
        identity,
        license_payload=licence.as_ledger_payload(),
        now=datetime.now(timezone.utc),
        workspace=_logical_workspace_name(shell),
        trust_edges=confirmed_trust_edges(getattr(shell, "domains_data", None) or {}),
        directory=store.directory,
        format_label=lambda label: mark_sensitive(label, "domain"),
        format_person=lambda name: mark_sensitive(name, "user"),
    )
    return admission.allowed, admission.message, admission.reason_code or ""


def ensure_pro_domain_admitted(shell: Any, domain_norm: str, *, dc_ip: str | None = None, phase: str = "unauth") -> bool:
    """True when assessment of ``domain_norm`` may start under the PRO licence."""
    from adscan_internal.cli.enterprise_license_gate import PHASE_AUTH, resolve_identity_for_admission

    try:
        store = _store()
        if not _required(store):
            return True
        memo = pro_admission_memo(shell)
        previous = memo.get(domain_norm)
        if previous is not None and (
            not previous.get("allowed") or phase != PHASE_AUTH or previous.get("auth_retried")
        ):
            return bool(previous.get("allowed"))
        status = pro_eval.check_pro_license(store)
        if not status.scans_allowed or status.licence is None:
            print_error(status.message)
            memo[domain_norm] = {"allowed": False}
            return False
        licence = status.licence
        run_kind = assessment_run_kind(shell)
        run_id = _run_id()
        identity = resolve_identity_for_admission(
            shell, domain_norm, dc_ip=dc_ip, known=(previous or {}).get("identity")
        )
        supersedes = None
        if previous and previous.get("code_basis") != "root_guid" and previous.get("domain_code"):
            supersedes = previous["domain_code"]
        if licence.registration_policy == POLICY_OFFLINE and run_kind != RUN_KIND_RECHECK:
            allowed, message, reason = _admit_offline(shell, store, licence, identity)
            from adscan_core.pro_license.domain_code import code_for_identity

            code, basis = code_for_identity(licence.domain_code_key, identity)
            outcome = "offline_admitted" if allowed else "offline_refused"
        else:
            result = pro_eval.admit_domain(
                store,
                licence,
                identity,
                engine_version=pro_client.engine_version(),
                send=_send_callable(),
                supersedes=supersedes,
                run_kind=run_kind,
                run_id=run_id,
            )
            allowed, message, reason = result.allowed, result.message, result.reason_code
            code, basis, outcome = result.domain_code, result.code_basis, result.outcome
        if allowed and run_kind == RUN_KIND_FULL_SCAN:
            pro_eval.record_assessment(
                store,
                licence,
                domain_code=code,
                run_kind=run_kind,
                run_id=run_id,
                engine_version=pro_client.engine_version(),
                supersedes=supersedes,
            )
    except Exception as exc:  # noqa: BLE001 - registration must not fail open
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(
            "The ADscan PRO licence could not register this domain, so its assessment cannot start. "
            "Existing reports and workspaces remain available."
        )
        pro_admission_memo(shell)[domain_norm] = {"allowed": False}
        return False

    memo[domain_norm] = {
        "allowed": allowed,
        "identity": identity,
        "domain_code": code,
        "code_basis": basis,
        "auth_retried": phase == PHASE_AUTH,
    }
    telemetry.capture("pro_domain_admission", properties={"phase": phase, "outcome": outcome, "basis": basis})
    print_info(
        f"Domain code for {mark_sensitive(identity.label, 'domain')}: {mark_sensitive(code, 'domain')}"
    )
    if not allowed:
        print_error(message)
        _write_refusal(shell, reason or pro_eval.REASON_REGISTRATION_REQUIRED, message)
        return False
    if outcome == pro_eval.OUTCOME_GRACE:
        print_warning(message)
    elif message and outcome != pro_eval.OUTCOME_REGISTERED:
        print_info(message)
    return True


def _identity_count(shell: Any, domain: str) -> int | None:
    from adscan_internal.services.estate_size_telemetry import build_estate_size_properties

    count = build_estate_size_properties(shell, domain).get("user_count")
    return int(count) if count is not None else None


def record_pro_scan_bands(shell: Any) -> None:
    """Queue a band report for each admitted forest whose band changed. Never raises."""
    try:
        store = _store()
        if not _required(store):
            return
        licence, _error = store.load_licence()
        if licence is None:
            return
        if licence.registration_policy == POLICY_OFFLINE:
            for domain, entry in pro_admission_memo(shell).items():
                count = _identity_count(shell, domain) if entry.get("allowed") and entry.get("domain_code") else None
                if count is not None:
                    store.set_assessment_band(_run_id(), entry["domain_code"], licence.band_for(int(count)))
            return
        queued = 0
        for domain, entry in pro_admission_memo(shell).items():
            if not entry.get("allowed") or not entry.get("domain_code"):
                continue
            count = _identity_count(shell, domain)
            if count is None:
                continue
            store.set_assessment_band(_run_id(), entry["domain_code"], licence.band_for(int(count)))
            if pro_client.queue_band_report(store, licence, entry["domain_code"], count):
                queued += 1
        send = _send_callable() if queued else None
        if send is not None:
            entries = store.register_entries()
            for item in store.pending():
                code = item.get("document", {}).get("payload", {}).get("domain_code")
                # A band follows its registration; an unregistered code keeps its band queued.
                if item.get("kind") == "band_report" and (entries.get(code) or {}).get("status") == "registered":
                    answer = send(item["document"])
                    if answer is None:
                        break
                    store.apply_answer(answer)
    except Exception as exc:  # noqa: BLE001 - a band report never breaks a scan
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def record_pro_recheck_usage(shell: Any, *, run_id: str, parent_run_id: str) -> int:
    """Record a ``recheck`` usage line for each code the parent scan assessed. Never raises.

    The recheck re-reads what its parent scan found, so its codes are the
    parent's usage lines; nothing is admitted, registered or queued. Returns
    the number of lines written (0 when dormant or when the parent scan left
    no line, e.g. it ran before the licence was activated).
    """
    try:
        store = _store()
        if not _required(store):
            return 0
        licence, _error = store.load_licence()
        if licence is None or not parent_run_id:
            return 0
        codes = sorted(
            {
                r.domain_code
                for r in store.assessment_records()
                if r.run_id == parent_run_id and r.run_kind == RUN_KIND_FULL_SCAN
            }
        )
        for code in codes:
            pro_eval.record_assessment(
                store,
                licence,
                domain_code=code,
                run_kind=RUN_KIND_RECHECK,
                run_id=run_id,
                parent_run_id=parent_run_id,
            )
        return len(codes)
    except Exception as exc:  # noqa: BLE001 - usage recording never breaks a recheck
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return 0


__all__ = [
    "PRO_LICENSE_MARKER",
    "assessment_run_kind",
    "ensure_pro_domain_admitted",
    "ensure_pro_license_allows_new_scan",
    "pro_admission_memo",
    "record_pro_recheck_usage",
    "record_pro_scan_bands",
]
