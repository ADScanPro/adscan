"""Exit statuses ``adscan ci`` uses for outcomes other than success or a crash.

Importable on the host and in the container. The appliance Celery worker never
imports ``adscan_core``, so it mirrors each value it acts on, and a contract
test keeps the mirror equal (``tests/unit/appliance/``).

The other statuses ``ci`` returns are defined where they are decided: ``0``
success, ``1`` failure, ``2`` a refused configuration or a failed post-scan
check, ``4`` (:data:`CI_EXIT_DELIVERABLE_FAILED`) a completed scan whose
deliverable did not render, ``42`` a PRO command on a LITE image, ``78``
(``adscan_core.enterprise_license.LICENSE_BLOCKED_EXIT_CODE``) a license refusal.
A run ended by a signal exits ``128 + N`` (see :data:`SIGNAL_EXIT_BASE`); that
holds for every engine command, not only ``ci``.
"""

from __future__ import annotations

#: The scan ran to its end, but the core of the authenticated assessment
#: (domain collection and attack-path discovery) never completed for the target
#: domain, or ran and was cut off (a collection stage lost its domain controller
#: mid-read: ``scan_progress.mark_phase_incomplete``). The run produced real
#: findings from the checks that did run, but it
#: holds no evidence that the domain resisted compromise, so it must not be
#: reported as a successful assessment. The worker records the scan as not
#: completed, with a reason that says which part did not run.
CI_EXIT_ASSESSMENT_INCOMPLETE = 3

#: The scan completed and its results stand, but the deliverable it was asked
#: for (``--generate-report``) did not render. Distinct from a failed scan and
#: from :data:`CI_EXIT_ASSESSMENT_INCOMPLETE`: everything the scan observed is in
#: the workspace and is reported, and the deliverable can be rendered again from
#: it (``adscan deliver``) without rescanning. A pipeline that asked for the
#: deliverable must not read this as a success, so it is not ``0``. The worker
#: records the scan as completed and the kit as failed, with a re-render offered.
CI_EXIT_DELIVERABLE_FAILED = 4

#: Base of the shell convention for "terminated by signal N": the status is
#: ``128 + N`` (130 Ctrl+C, 129 SIGHUP, 143 SIGTERM, 137 SIGKILL). The engine
#: exits with it after its graceful shutdown on a signal, so a scan stopped from
#: outside (a ``docker stop``, a closed terminal) never reads as a success to
#: whoever ran it. Docker reports a container killed outright the same way.
SIGNAL_EXIT_BASE = 128

#: Highest signal number the convention covers on Linux (real-time signals
#: included). A status above ``SIGNAL_EXIT_BASE + SIGNAL_EXIT_MAX_SIGNUM`` is
#: not a signal termination.
SIGNAL_EXIT_MAX_SIGNUM = 64


def scan_results_stand(exit_code: int | None) -> bool:
    """Whether a ``ci`` exit status means the scan itself completed.

    True for ``0`` and for :data:`CI_EXIT_DELIVERABLE_FAILED`: a deliverable
    that did not render never makes a finished scan read as failed.
    """
    return exit_code in (0, CI_EXIT_DELIVERABLE_FAILED)


def exit_code_for_signal(signum: int) -> int:
    """Return the process exit status for a run ended by signal ``signum``."""
    return SIGNAL_EXIT_BASE + int(signum)


def signal_from_exit_code(exit_code: int | None) -> int | None:
    """Return the signal a status reports, or ``None`` when it reports none.

    Accepts both forms a caller meets: the shell's ``128 + N`` (what an engine,
    a container or a shell-wrapped process returns) and Python's ``-N`` (what
    ``subprocess`` reports for a child killed directly by a signal).
    """
    if exit_code is None:
        return None
    try:
        code = int(exit_code)
    except (TypeError, ValueError):
        return None
    if code < 0:
        return -code if -code <= SIGNAL_EXIT_MAX_SIGNUM else None
    signum = code - SIGNAL_EXIT_BASE
    if 1 <= signum <= SIGNAL_EXIT_MAX_SIGNUM:
        return signum
    return None


__all__ = [
    "CI_EXIT_ASSESSMENT_INCOMPLETE",
    "CI_EXIT_DELIVERABLE_FAILED",
    "SIGNAL_EXIT_BASE",
    "SIGNAL_EXIT_MAX_SIGNUM",
    "exit_code_for_signal",
    "scan_results_stand",
    "signal_from_exit_code",
]
