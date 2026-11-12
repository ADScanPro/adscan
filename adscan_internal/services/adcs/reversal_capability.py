"""The AD CS issuance gate: establish the revoke right on THIS CA before issuing.

Reversible-by-construction § 5.1, the ordering rule::

    establish the reversal capability  →  issue  →  use  →  revoke and confirm

never ``issue → discover we cannot revoke → disclose a manual item``.

Under a policy that allows no manual cleanup (Audit, Production-sensitive), a
certificate is requested only once an account in the revert cascade
(``revert_credentials.revert_candidates``: the client's cleanup account first,
then the highest-privilege credential the run verified) is established, by the
CA itself, to hold the right to revoke it there (``revert_rights`` token
``revoke_certificate``, probed by ``revert_right_probes.ca_probe``: the four
facts of § 6). Anything short of that is not undoable and the step declines,
before any write and before any coercion: ``reversal_not_proven``. A policy that
accepts manual cleanup (Lab / CTF, Full validation) passes straight through,
exactly as before, and a certificate nobody revokes is disclosed for manual
revocation.

Two seams call it, so no ESC can forget it: the single native enrollment seam
``cert_request.request_certificate_native`` (every template-based ESC) and the
relay entries in ``esc_relay`` (ESC8 / ESC11, before coercion). The ESC runner
asks it once more up front so a flow that writes something before it enrolls
(ESC4's template, ESC9's UPN) declines before that write too. The answer is
memoized per CA and account (``revert_right_probes``), so asking at several
seams costs one read.
"""

from __future__ import annotations

from typing import Any, Optional

from adscan_core import telemetry
from adscan_core.reporting.attack_path_execution_events import (
    NOT_EXECUTED_REVERSAL_NOT_PROVEN,
)
from adscan_core.rich_output import print_exception, print_info, print_info_debug
from adscan_core.scan_policy.model import REVERT_RIGHT_REVOKE_CERTIFICATE
from adscan_core.scan_policy.revert_rights import (
    SCOPE_CA,
    RightVerdict,
    ca_key,
    revert_right,
)
from adscan_internal.rich_output import mark_sensitive

#: Edge note / result token of a certificate step declined because no account
#: could be established to revoke the certificate on that CA. Distinct from a
#: policy exclusion: the client's action is to supply the right, not to change
#: the policy. Never "blocked" (the safety policy), never "attempted".
NOT_EXECUTED_REASON = NOT_EXECUTED_REVERSAL_NOT_PROVEN
#: ``domains_data[<domain>]`` key holding the per-CA issuance verdicts.
ISSUANCE_VERDICT_KEY = "reversal_capability_issuance"
_SHELL_REFUSALS_ATTR = "_reversal_not_proven_refusals"


def _policy_requires_proof(shell: Any) -> bool:
    """True only under a policy that accepts no manual cleanup."""
    from adscan_internal.services.revert_permission import (  # noqa: PLC0415
        policy_accepts_manual_cleanup,
    )

    accepts = policy_accepts_manual_cleanup(shell)
    return accepts is False


def _record_verdict(shell: Any, domain: str, verdict: RightVerdict) -> None:
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return
    for key, bucket in domains_data.items():
        if isinstance(key, str) and key.strip().lower() == domain.strip().lower() and isinstance(bucket, dict):
            store = bucket.setdefault(ISSUANCE_VERDICT_KEY, {})
            if isinstance(store, dict):
                store[verdict.target] = verdict.to_dict()
            return


def refusal_line(*, ca_name: str, verdicts: list[RightVerdict]) -> str:
    """The operator line for a declined certificate step (§ 10.3). Worded once."""
    from adscan_core.reporting.reversal_capability import reason_text  # noqa: PLC0415

    right = revert_right(REVERT_RIGHT_REVOKE_CERTIFICATE)
    permission = right.console_name if right is not None else "Issue and Manage Certificates"
    tried = [v for v in verdicts if v.principal]
    if not tried:
        why = "no account that could revoke it was available"
    else:
        parts = [
            f"{v.principal}, {reason_text(v.reason) or 'it could not be confirmed'}"
            for v in tried[:3]
        ]
        why = "; ".join(parts)
    return (
        f"ADscan did not request a certificate from {ca_name}, because it could not "
        f"confirm that an account can revoke it there ({why}). The weakness is still "
        f'reported. An account holding "{permission}" on {ca_name} closes this gap.'
    )


def issuance_permitted(
    shell: Any,
    *,
    domain: str,
    ca_name: str,
    ca_host: str,
    surface: str,
    technique: str = "",
) -> bool:
    """Whether a certificate may be requested from this CA now. Never raises.

    Returns True without probing when no policy is active or the policy accepts
    manual cleanup. Otherwise True only once an account in the revert cascade is
    established to hold the revoke right on THIS CA; an error declines.
    """
    if shell is None:
        return True
    try:
        if not _policy_requires_proof(shell):
            return True
    except Exception as exc:  # noqa: BLE001 - an unreadable policy fails closed
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    host = str(ca_host or "").strip()
    name = str(ca_name or "").strip()
    target_key = ca_key(host, name)
    verdicts: list[RightVerdict] = []
    ca_domain = str(domain or "").strip().lower()
    try:
        from adscan_internal.services.engagement_scope import (  # noqa: PLC0415
            domain_in_engagement_scope,
            host_owner_domain,
        )
        from adscan_internal.services.revert_credentials import (  # noqa: PLC0415
            revert_candidates,
        )
        from adscan_internal.services.revert_right_probes import (  # noqa: PLC0415
            ProbeAccount,
            ProbeTarget,
            probe_revert_right,
        )

        ca_domain = host_owner_domain(shell, host, collecting_domain=ca_domain) or ca_domain
        if host and name and domain_in_engagement_scope(shell, ca_domain):
            target = ProbeTarget(SCOPE_CA, target_key, ca_domain, ca_name=name, ca_host=host)
            for candidate in revert_candidates(shell, domain=ca_domain, purpose="issued_certificate"):
                verdict = probe_revert_right(
                    shell,
                    REVERT_RIGHT_REVOKE_CERTIFICATE,
                    target,
                    ProbeAccount(candidate.username, candidate.domain, candidate),
                )
                verdicts.append(verdict)
                if verdict.permitted:
                    _record_verdict(shell, ca_domain, verdict)
                    print_info_debug(
                        "reversal-capability proven "
                        f"ca={mark_sensitive(target_key, 'hostname')} "
                        f"principal={mark_sensitive(candidate.username, 'user')} "
                        f"role={candidate.role} surface={surface}"
                    )
                    return True
    except Exception as exc:  # noqa: BLE001 - unestablished means not undoable
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    if verdicts:
        _record_verdict(shell, ca_domain, verdicts[0])
    _record_refusal(shell, ca_name=name or target_key, verdicts=verdicts, surface=surface, technique=technique)
    return False


def _record_refusal(
    shell: Any, *, ca_name: str, verdicts: list[RightVerdict], surface: str, technique: str
) -> None:
    refusals = getattr(shell, _SHELL_REFUSALS_ATTR, None)
    if not isinstance(refusals, list):
        refusals = []
        try:
            setattr(shell, _SHELL_REFUSALS_ATTR, refusals)
        except Exception:  # noqa: BLE001
            pass
    first = not any(r.get("ca") == ca_name for r in refusals)
    refusals.append(
        {
            "ca": ca_name,
            "surface": surface,
            "technique": technique,
            "reasons": [v.reason for v in verdicts],
        }
    )
    if first:
        print_info(mark_sensitive(refusal_line(ca_name=ca_name, verdicts=verdicts), "detail"))
    else:
        # Every declined step is visible; the full reason was printed once per CA.
        what = technique or "This certificate step"
        print_info(
            f"{what} did not run on {mark_sensitive(ca_name, 'hostname')}, for the reason "
            "given above for this CA."
        )


def reversal_refusals(shell: Any) -> list[dict[str, Any]]:
    """Certificate steps declined this session for want of a proven revoke right."""
    refusals = getattr(shell, _SHELL_REFUSALS_ATTR, None)
    return list(refusals) if isinstance(refusals, list) else []


async def require_reversal_capability(
    shell: Any,
    *,
    domain: str,
    ca_name: str,
    ca_host: str,
    surface: str,
    technique: str = "",
) -> Optional[str]:
    """Async form for the issuance seams: ``None`` to proceed, else the refusal token.

    The probe itself drives its own short-lived connection through the async
    bridge (``run_async_sync`` offloads it to a worker thread under a running
    loop), so nothing bound to this loop is created or kept.
    """
    if issuance_permitted(
        shell, domain=domain, ca_name=ca_name, ca_host=ca_host, surface=surface, technique=technique
    ):
        return None
    return NOT_EXECUTED_REASON


async def esc_reversal_refusal(config: Any, *, technique: str, surface: str) -> Any:
    """``None`` to proceed, else the declined ``EscResult`` for an ESC flow.

    Shared by the ESC runner and the relay entries (ESC8, ESC11), which ask
    before any write and before any coercion.
    """
    from adscan_internal.services.adcs.esc_types import EscResult  # noqa: PLC0415

    refusal = await require_reversal_capability(
        getattr(config, "shell", None),
        domain=str(getattr(config, "domain", "") or ""),
        ca_name=str(getattr(config, "ca_name", "") or ""),
        ca_host=str(getattr(config, "ca_fqdn", "") or getattr(config, "ca_host", "") or ""),
        surface=surface,
        technique=technique,
    )
    if refusal is None:
        return None
    return EscResult(
        success=False,
        esc=int(getattr(config, "esc", 0) or 0),
        error=refusal,
        evidence={"not_executed_reason": refusal, "certificate_issued": False},
    )


__all__ = [
    "esc_reversal_refusal",
    "ISSUANCE_VERDICT_KEY",
    "NOT_EXECUTED_REASON",
    "issuance_permitted",
    "refusal_line",
    "require_reversal_capability",
    "reversal_refusals",
]
