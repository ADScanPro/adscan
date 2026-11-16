"""A domain controller that stopped answering makes the phase that needed it incomplete.

The SSOT for one verdict: "this phase ran, but the domain controller it works
against did not answer, so its checks were not evaluated". It exists because the
per-check record already said so (``probe_skipped``) while everything a client
reads said the opposite. On 2026-11-14 a release-gate run lost its domain
controller five seconds after collection finished: every CVE probe against it
was skipped, the console printed "Lab/host appears clean for the scanned CVEs",
``coverage.json`` read ``complete`` and ``adscan ci`` exited 0. Four findings an
earlier run of the same domain had reported were silently absent.

A phase that detects the loss calls :func:`declare_target_unreachable`, which
writes ONE incomplete mark through the phase SSOT
(``scan_progress.mark_phase_incomplete``). From there the end-of-scan panel,
``adscan ci``'s exit status 3, ``coverage.json`` (``incomplete_phases`` and
``run_status``) and the ``technical_report.json`` assessment block all read the
same record (``scan_progress.authenticated_assessment_gap`` counts a phase
carrying this reason even when it is not a core phase). A phase that runs again
clears its own mark first (:func:`begin_target_watch`), so a resume that reaches
the controller closes the gap.

Only a DOMAIN CONTROLLER counts. A member server that does not answer is a
per-check gap the coverage record already carries; it does not decide whether
the domain was assessed.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

#: Reason token prefix (``target_unreachable:<role>``) in the incomplete mark.
REASON_TARGET_UNREACHABLE = "target_unreachable"
#: The role of the host that stopped answering.
ROLE_DOMAIN_CONTROLLER = "domain_controller"
TARGET_LOSS_TOKEN = f"{REASON_TARGET_UNREACHABLE}:{ROLE_DOMAIN_CONTROLLER}"
#: Start of the operator sentence this module writes into the mark's detail.
_DETAIL_PREFIX = "the domain controller stopped answering"


def is_target_loss_reason(token: Any) -> bool:
    """True when an incomplete-mark reason records a domain controller that stopped answering."""
    return str(token or "").split(":", 1)[0] == REASON_TARGET_UNREACHABLE


def mark_has_target_loss(mark: Mapping[str, Any] | None) -> bool:
    """True when an incomplete mark (``{"reasons": [...]}``) carries a target-loss reason."""
    if not isinstance(mark, Mapping):
        return False
    return any(is_target_loss_reason(r) for r in mark.get("reasons") or ())


def begin_target_watch(shell: Any, domain: str, phase_id: str) -> None:
    """A phase is about to run again: forget its earlier target-loss mark.

    Only the target-loss reason is dropped; another stage's reason on the same
    phase (an operator stop, a memory stop) stays. Never raises.
    """
    try:
        from adscan_internal.services import scan_progress  # noqa: PLC0415

        if not scan_progress.drop_phase_incomplete_reason(shell, domain, phase_id, TARGET_LOSS_TOKEN):
            return
        remaining = scan_progress.incomplete_phases(shell, domain).get(phase_id)
        if not remaining:
            return
        detail = str(remaining.get("detail") or "")
        kept = "; ".join(
            part for part in detail.split("; ") if not part.startswith(_DETAIL_PREFIX)
        )
        if kept != detail:
            scan_progress.mark_phase_incomplete(
                shell, domain, phase_id, reasons=tuple(remaining.get("reasons") or ()), detail=kept
            )
    except Exception:  # noqa: BLE001 - bookkeeping must never break a phase
        pass


def hosts_scope_let_be_checked(
    shell: Any, domain: str, hosts: Iterable[str], *, contact: Any = None
) -> list[str]:
    """The hosts of ``hosts`` the engagement scope let the phase's checks contact.

    A domain outside the engagement scope, a host the asset scope excludes, a
    controller kept to directory reads when the checks are host work, and a
    host the scope cannot place are all left out: nothing was sent to them on
    purpose, so "it did not answer" is not a fact about them. Without an asset
    scope every host of an in-scope domain is returned. When the scope cannot
    be asked, no host is returned: a loss is never declared on a guess.
    """
    named = [str(h).strip() for h in hosts if str(h or "").strip()]
    if not named:
        return []
    try:
        from adscan_internal.services.engagement_scope import (  # noqa: PLC0415
            Contact,
            asset_scope_recorded,
            domain_scope_verdict,
            host_scope_verdict,
        )
        from adscan_internal.services.engagement_scope_targets import (  # noqa: PLC0415
            prepare_targets_for_scope,
        )

        if domain and not domain_scope_verdict(shell, domain).in_scope:
            return []
        if not asset_scope_recorded(shell):
            return named
        opened = contact if isinstance(contact, Contact) else Contact()
        prepare_targets_for_scope(shell, named, domain=domain or None)
        return [
            host
            for host in named
            if host_scope_verdict(shell, host=host, domain=domain or None, contact=opened).allowed
        ]
    except Exception as exc:  # noqa: BLE001 - an unknown verdict never declares a loss
        from adscan_core import telemetry  # noqa: PLC0415
        from adscan_core.rich_output import print_exception  # noqa: PLC0415

        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return []


def declare_target_unreachable(
    shell: Any,
    domain: str,
    phase_id: str,
    *,
    hosts: Iterable[str],
    what: str,
    contact: Any = None,
) -> bool:
    """Mark ``phase_id`` incomplete for ``domain``: its domain controller stopped answering.

    Asks WHY the checks did not run before it calls a controller lost: one the
    engagement scope keeps the phase's checks off was never asked, by the
    client's own decision, so its silence is no loss (:func:`hosts_scope_let_be_checked`).

    Args:
        shell: The session shell.
        domain: The domain whose controller did not answer.
        phase_id: The phase whose checks were not evaluated.
        hosts: The controller addresses that did not answer (operator line only).
        what: Plural noun phrase for the checks not evaluated ("its CVE checks").
        contact: What the phase's checks open on the controller (an
            ``engagement_scope.Contact``). ``None`` is ordinary host work, the
            reading under which a controller kept to directory reads is out.

    Returns:
        True when the mark was written. Never raises.
    """
    marked = sorted({str(h).strip() for h in hosts if str(h or "").strip()})
    marked = hosts_scope_let_be_checked(shell, domain, marked, contact=contact)
    if not domain or not phase_id or not marked:
        return False
    try:
        from adscan_core.rich_output import mark_sensitive, print_warning  # noqa: PLC0415
        from adscan_internal.services import scan_progress  # noqa: PLC0415

        detail = f"{_DETAIL_PREFIX} during this phase, so {what} were not evaluated"
        # mark_phase_incomplete replaces the phase's mark: keep what another
        # stage already recorded on it (an operator stop, a memory stop).
        existing = scan_progress.incomplete_phases(shell, domain).get(phase_id) or {}
        reasons = [str(r) for r in existing.get("reasons") or () if not is_target_loss_reason(r)]
        prior_detail = str(existing.get("detail") or "").strip()
        if prior_detail and _DETAIL_PREFIX not in prior_detail:
            detail = f"{prior_detail}; {detail}"
        scan_progress.mark_phase_incomplete(
            shell, domain, phase_id, reasons=(*reasons, TARGET_LOSS_TOKEN), detail=detail
        )
        names = ", ".join(mark_sensitive(h, "ip") for h in marked)
        title = scan_progress.phase_titles((phase_id,))[0]
        print_warning(
            f"{title}: the domain controller of {mark_sensitive(domain, 'domain')} ({names}) "
            f"stopped answering, so {what} were not evaluated. The run will not report "
            "this domain as fully assessed."
        )
        return True
    except Exception as exc:  # noqa: BLE001 - declaring a gap must never break the scan
        from adscan_core import telemetry  # noqa: PLC0415
        from adscan_core.rich_output import print_exception  # noqa: PLC0415

        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False


__all__ = [
    "REASON_TARGET_UNREACHABLE",
    "ROLE_DOMAIN_CONTROLLER",
    "TARGET_LOSS_TOKEN",
    "begin_target_watch",
    "declare_target_unreachable",
    "hosts_scope_let_be_checked",
    "is_target_loss_reason",
    "mark_has_target_loss",
]
