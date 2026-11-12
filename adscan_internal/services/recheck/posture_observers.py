"""Read-only re-observation of the domain controller's posture (recheck ``observe``).

One observer per posture detector family that raises a finding
(``posture.ldap_signing``, ``posture.smb_signing``, ``posture.ntlm_authentication``,
``posture.ldaps_available``, ``posture.kerberos_rc4``, ``posture.kerberos_aes_only``).

The observation is the scan's own posture probe, forced once per domain per
recheck run through the freshness guard (``posture_orchestration.ensure_posture_fresh``
with ``force=True``, ``record_evidence=False``): the same probes, the same
transports, the same auth-attempt guard, and nothing written to the scan's
report. Which finding an observation raises is the scan's own rule table
(``posture_findings_emitter.POSTURE_TO_FINDING_RULES``), read, not copied.

**Cache observations, never absences.** Only a result the DC answered
definitively in THIS run counts: ``succeeded``, not skipped, HIGH confidence,
a state other than UNKNOWN. A timeout, a probe the scan policy switched off, or
a stale value cached by an earlier scan decides nothing, so its finding reads
"not re-checked". A finding closes only when every rule behind it was answered
and none fires (``ldap_security_posture`` needs both LDAP signing and channel
binding observed as required).

``smb_signing_disabled`` is a per-host finding of the host collection; the probe
reads the domain controller only. A DC that still does not require signing
re-observes it; a DC that does cannot close it (the member hosts were not
read), so it stays not re-checked. ``smb_relay_targets`` likewise.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, Mapping, Optional

from adscan_core.engagement.model import CheckStatus
from adscan_core.engagement.recheck import ReadOutcome
from adscan_internal.services.recheck.recorded import (
    STATE_ABSENT,
    STATE_PRESENT,
    STATE_UNKNOWN,
    shell_domain,
)

POSTURE_CHECKS = (
    "posture.ldap_signing",
    "posture.smb_signing",
    "posture.ntlm_authentication",
    "posture.ldaps_available",
    "posture.kerberos_rc4",
    "posture.kerberos_aes_only",
)

REASON_NO_SHELL = "no_workspace_session"
REASON_NO_CREDENTIAL = "no_credential"
REASON_RULES_UNAVAILABLE = "posture_rules_unavailable"
REASON_NOT_ANSWERED = "dc_did_not_answer_definitively"

_SMB_HOST_FINDING = "smb_signing_disabled"


def definitive_observations(results: Iterable[Any]) -> dict[Any, Any]:
    """``category -> state`` for every result the DC answered definitively.

    Mirrors the posture caching policy: a skipped probe, a failed one, a
    low-confidence one or an UNKNOWN state is an absence and is dropped.
    """
    from adscan_internal.services.domain_posture import SignalConfidence, TriState  # noqa: PLC0415

    observed: dict[Any, Any] = {}
    for result in results:
        if not getattr(result, "succeeded", False) or getattr(result, "skipped", False):
            continue
        if getattr(result, "confidence", None) != SignalConfidence.HIGH:
            continue
        state = getattr(result, "state", None)
        if state is None or state == TriState.UNKNOWN:
            continue
        observed[result.category] = state
    return observed


def _fires(rule: Any, state: Any) -> bool:
    predicate = getattr(rule, "predicate", None)
    return bool(predicate(state)) if predicate is not None else state == rule.trigger_state


def decide_posture_findings(
    finding_keys: Iterable[str], observed: Mapping[Any, Any], rules: Iterable[Any]
) -> dict[str, str]:
    """Decide each finding key from definitive observations and the scan's rules."""
    from adscan_internal.services.domain_posture import ConstraintCategory, TriState  # noqa: PLC0415

    rules = list(rules)
    decided: dict[str, str] = {}
    for key in finding_keys:
        key_rules = [r for r in rules if r.finding_key == key]
        if key_rules:
            if any(r.category in observed and _fires(r, observed[r.category]) for r in key_rules):
                decided[key] = STATE_PRESENT
            elif all(r.category in observed for r in key_rules):
                decided[key] = STATE_ABSENT
            else:
                decided[key] = STATE_UNKNOWN
        elif key == _SMB_HOST_FINDING:
            state = observed.get(ConstraintCategory.SMB_SIGNING)
            decided[key] = STATE_PRESENT if state is not None and state != TriState.REQUIRED else STATE_UNKNOWN
        else:
            decided[key] = STATE_UNKNOWN
    return decided


def grade_posture_check(check_id: str, domain_id: str, decided: Mapping[str, str]) -> ReadOutcome:
    """The read outcome of one posture family from its per-finding decisions."""
    present = {k: frozenset({domain_id}) for k, s in decided.items() if s == STATE_PRESENT}
    if all(s != STATE_UNKNOWN for s in decided.values()):
        return ReadOutcome(check_id, domain_id, CheckStatus.RAN, None, present)
    return ReadOutcome(check_id, domain_id, CheckStatus.PARTIAL, frozenset(), present, REASON_NOT_ANSWERED)


def _posture_rules() -> Optional[list[Any]]:
    from adscan_core.rich_output import print_info_debug  # noqa: PLC0415
    from adscan_internal.reporting_compat import load_optional_pro_attr  # noqa: PLC0415

    rules = load_optional_pro_attr(
        "adscan_internal.pro.services.posture_findings_emitter",
        "POSTURE_TO_FINDING_RULES",
        action="Posture recheck rules",
        debug_printer=print_info_debug,
        prefix="[recheck]",
    )
    return list(rules) if rules is not None else None


def fresh_posture_results(ctx: Any) -> tuple[Optional[list[Any]], str]:
    """Run the scan's posture probe once for this domain, forced. Never raises."""
    if "posture_results" in ctx.cache:
        return ctx.cache["posture_results"]
    value: tuple[Optional[list[Any]], str]
    shell = getattr(ctx, "shell", None)
    if shell is None:
        value = (None, REASON_NO_SHELL)
    else:
        value = _probe(shell, ctx.domain_id)
    ctx.cache["posture_results"] = value
    return value


def _probe(shell: Any, domain_id: str) -> tuple[Optional[list[Any]], str]:
    from adscan_core import telemetry  # noqa: PLC0415
    from adscan_core.async_bridge import run_on_new_loop  # noqa: PLC0415
    from adscan_core.rich_output import print_exception  # noqa: PLC0415
    from adscan_internal.models.domain import resolve_dc_ip  # noqa: PLC0415
    from adscan_internal.services.posture_orchestration import (  # noqa: PLC0415
        FreshnessOutcome,
        ensure_posture_fresh,
    )
    from adscan_internal.services.posture_probe import ProbeCredentials, ProbePhase  # noqa: PLC0415

    domain = shell_domain(shell, domain_id)
    data = (getattr(shell, "domains_data", None) or {}).get(domain) or {}
    user = str(data.get("username") or "").strip()
    secret = str(data.get("password") or "")
    dc_ip = str(resolve_dc_ip(data) or "").strip()
    if not user or not secret or not dc_ip:
        return None, REASON_NO_CREDENTIAL
    try:
        freshness = run_on_new_loop(
            ensure_posture_fresh(
                shell,
                domain=domain,
                dc_ip=dc_ip,
                creds=ProbeCredentials(username=user, password=secret),
                phase=ProbePhase.AUTH,
                render_ui=False,
                force=True,
                record_evidence=False,
            )
        )
    except Exception as exc:  # noqa: BLE001 - a probe failure closes nothing
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None, "posture_probe_failed"
    if freshness.outcome is not FreshnessOutcome.PROBED:
        return None, f"posture_probe_{freshness.outcome.value}"
    return list(freshness.results), ""


def observe_posture_check(check_id: str, ctx: Any) -> ReadOutcome:
    """Re-observe one posture family for ``ctx``'s domain (the scan's probe, forced)."""
    from adscan_core.engagement.detectors import DETECTORS  # noqa: PLC0415

    detector = next(d for d in DETECTORS if d.check_id == check_id)
    rules = _posture_rules()
    if rules is None:
        return ReadOutcome(check_id, ctx.domain_id, CheckStatus.FAILED, None, {}, REASON_RULES_UNAVAILABLE)
    results, reason = fresh_posture_results(ctx)
    if results is None:
        return ReadOutcome(check_id, ctx.domain_id, CheckStatus.FAILED, None, {}, reason)
    decided = decide_posture_findings(detector.finding_keys, definitive_observations(results), rules)
    return grade_posture_check(check_id, ctx.domain_id, decided)


def _observer_for(check_id: str) -> Callable[[Any, Optional[frozenset[str]]], ReadOutcome]:
    def observe(ctx: Any, _objects: Optional[frozenset[str]]) -> ReadOutcome:
        return observe_posture_check(check_id, ctx)

    observe.__name__ = f"observe_{check_id.replace('.', '_')}"
    observe.__doc__ = f"``{check_id}``: the domain controller's answer, re-probed."
    return observe


POSTURE_OBSERVERS: Mapping[str, Callable[[Any, Optional[frozenset[str]]], ReadOutcome]] = {
    check_id: _observer_for(check_id) for check_id in POSTURE_CHECKS
}

#: The scan's own probe and posture-to-finding rules each posture observer
#: reuses (``module:attribute``), checked by ``test_recheck_coverage_declared.py``.
POSTURE_SCAN_GRADERS: Mapping[str, tuple[str, ...]] = {
    check_id: (
        "adscan_internal.services.posture_orchestration:ensure_posture_fresh",
        "adscan_internal.pro.services.posture_findings_emitter:POSTURE_TO_FINDING_RULES",
    )
    for check_id in POSTURE_CHECKS
}


__all__ = (
    "POSTURE_CHECKS",
    "POSTURE_OBSERVERS",
    "POSTURE_SCAN_GRADERS",
    "decide_posture_findings",
    "definitive_observations",
    "fresh_posture_results",
    "grade_posture_check",
    "observe_posture_check",
)
