"""Engine helpers for a stoppable host sweep: its step, and what it left unchecked.

A post-compromise sweep (the SMB, WinRM, SQL Server and RDP access checks, the
local-admin reuse checks, a bulk credential dump) runs as a LONG step of the
scan control plane (:mod:`adscan_core.scan_control`), so Ctrl+C offers "Stop this
step and keep what it found". The fan-out itself lives in
:mod:`adscan_core.scan_control.fanout`; this module is the engine side every
sweep shares:

* :func:`sweep_step` opens the step with a client-safe label;
* :func:`announce_not_checked` names the hosts a stop left unchecked, so the
  operator never reads them as "no access";
* :func:`note_outside_scope` records the hosts the engagement scope kept out of
  the sweep (the scope SSOT already announced them), a fourth outcome that is
  neither "checked" nor "not checked because of a stop";
* :func:`checked_only` keeps only the checked hosts for anything persisted (a
  probe-history record of "unconfirmed" for a host that was never contacted
  would make the next run skip it as already tested);
* :func:`stop_ends_operation` tells a caller looping over several sweeps whether
  the stop was for this sweep only or for the whole phase or scan.
"""

from __future__ import annotations

import contextlib
from typing import Any, Iterable, Iterator

from adscan_core.rich_output import mark_sensitive, print_warning
from adscan_core.scan_control import ControlAction, StepScope, scan_control
from adscan_core.scan_control.fanout import SweepCoverage

#: Display labels of the service-access sweeps (operator menu + gap statement).
SERVICE_SWEEP_LABELS: dict[str, str] = {
    "smb": "SMB access sweep",
    "winrm": "WinRM access sweep",
    "mssql": "SQL Server access sweep",
    "rdp": "RDP access sweep",
}

#: Hosts named one by one in the not-checked line before it summarises the rest.
_NAMED_HOSTS_LIMIT = 10


def service_sweep_step_id(service: str) -> str:
    """Stable step id of a service-access sweep (``smb_access_sweep``)."""
    return f"{str(service or 'service').strip().lower()}_access_sweep"


@contextlib.contextmanager
def sweep_step(step_id: str, *, label: str, unit: str = "hosts") -> Iterator[StepScope]:
    """Open a long scan-control step for one sweep.

    The total is recorded at the end with :func:`finish_sweep_step`, from what
    the sweep actually had to check.
    """
    with scan_control().step(step_id, label=label, long=True, unit=unit) as step:
        yield step


def service_sweep_step(service: str) -> Any:
    """:func:`sweep_step` for a service-access sweep."""
    key = str(service or "").strip().lower()
    return sweep_step(
        service_sweep_step_id(key),
        label=SERVICE_SWEEP_LABELS.get(key, f"{key.upper()} access sweep"),
    )


def finish_sweep_step(step: StepScope, coverage: SweepCoverage) -> None:
    """Record the sweep's "N of M" on its step, for the gap statement."""
    step.progress(done=coverage.checked, total=coverage.total)


def announce_not_checked(*, label: str, coverage: SweepCoverage, unit: str = "hosts") -> None:
    """Tell the operator which hosts a stop left unchecked (nothing when none)."""
    if not coverage.stopped or not coverage.not_checked:
        return
    names = [str(item) for item in coverage.not_checked if str(item or "").strip()]
    shown = ", ".join(mark_sensitive(name, "hostname") for name in names[:_NAMED_HOSTS_LIMIT])
    more = len(names) - _NAMED_HOSTS_LIMIT
    if more > 0:
        shown = f"{shown} and {more} more"
    count = len(coverage.not_checked)
    print_warning(
        f"{label} stopped after checking {coverage.checked} of {coverage.total} {unit}. "
        f"{count} {unit} {'was' if count == 1 else 'were'} not checked, so no result "
        f"is recorded for {'it' if count == 1 else 'them'}: {shown}."
    )


def note_outside_scope(
    coverage: SweepCoverage | None, refused: Iterable[Any], *, key: Any = str
) -> None:
    """Record on ``coverage`` the targets the engagement scope kept out of a sweep.

    ``refused`` is ``ScopePartition.refused_items`` from
    :func:`adscan_internal.services.engagement_scope.partition_targets_in_scope`,
    which already told the operator once ("... skipped N hosts excluded by the
    engagement scope"). Recording them here is what keeps them out of anything
    persisted: :func:`checked_only` drops them, so an excluded host is never
    written to probe history as "tested, no access".
    """
    if coverage is None:
        return
    coverage.note_outside_scope(str(key(item) or "") for item in refused)


def checked_only(targets: Iterable[Any], coverage: SweepCoverage) -> list[Any]:
    """``targets`` that were really checked (case-insensitive).

    Drops the ones a stop left unchecked and the ones the engagement scope kept
    out: neither was contacted, so neither may be recorded as a result.
    """
    skipped = {str(item).strip().lower() for item in coverage.not_checked}
    skipped.update(str(item).strip().lower() for item in coverage.outside_scope)
    return [t for t in targets if str(t).strip().lower() not in skipped]


def stop_ends_operation(step: StepScope) -> bool:
    """Whether the stop that ended ``step`` also ends the caller's operation.

    "Stop this step" ends only this sweep: a caller running several sweeps goes
    on with the next. A skipped phase or a stopped scan or command ends them all.
    """
    return bool(step.stopped) and step.stop_action != ControlAction.SKIP_STEP


__all__ = [
    "SERVICE_SWEEP_LABELS",
    "announce_not_checked",
    "checked_only",
    "finish_sweep_step",
    "note_outside_scope",
    "service_sweep_step",
    "service_sweep_step_id",
    "stop_ends_operation",
    "sweep_step",
]
