"""Engine wiring for the scan control plane (``adscan_core.scan_control``).

``adscan_core`` cannot import the engine, so this module installs the three
engine-side pieces the controller needs, once:

* the GAP RECORDER: every stop (a long step stopped, a phase skipped, the scan
  stopped) is persisted through the existing coverage SSOTs, never a parallel
  mechanism: ``scan_progress.mark_phase_incomplete`` (``coverage.json``
  incomplete phases, the end-of-scan recap, ``adscan ci``'s exit status) and the
  ``operator_stop_coverage`` block of ``technical_report.json`` (the PDF report,
  the LITE report and the web);
* the EVENT EMITTER: the ``scan_control`` structured event the web reads to show
  the current step and whether it can be skipped;
* the PHASE TITLE resolver, for the menu and the gap statement.

:func:`operator_scan_scope` is the one way a scan entry point opens its scope.
"""

from __future__ import annotations

import contextlib
import threading
from typing import Any, Iterator

from adscan_core import telemetry
from adscan_core.rich_output import (
    mark_sensitive,
    print_exception,
    print_info,
    print_info_debug,
)
from adscan_core.scan_control import (
    OperatorStop,
    ScanControl,
    scan_control,
    set_phase_title_resolver,
)

_INSTALL_LOCK = threading.Lock()
_INSTALLED = False
#: The shell of the scan in progress (cleared when its scope closes).
_ACTIVE_SHELL: Any = None

#: Reason token prefix written into ``coverage.json`` incomplete phases.
OPERATOR_STOP_REASON = "operator_stop"


def _phase_title(phase_id: str) -> str:
    from adscan_internal.services.scan_phases import get_phase  # noqa: PLC0415

    phase = get_phase(phase_id)
    return str(getattr(phase, "title", "") or "")


def _emit_control_event(fields: dict[str, Any]) -> None:
    from adscan_internal.cli.ci_events import emit_event  # noqa: PLC0415

    emit_event("scan_control", **fields)


def _active_shell() -> Any:
    return _ACTIVE_SHELL


def _resolve_domain(shell: Any, stop: OperatorStop) -> str:
    domain = str(stop.domain or "").strip()
    if domain:
        return domain
    return str(getattr(shell, "domain", "") or "").strip()


def record_operator_stop(stop: OperatorStop, *, shell: Any = None) -> None:
    """Persist one operator stop as a declared coverage gap (the gap recorder).

    Never raises: a stop that cannot be recorded is logged, and the scan
    continues (or unwinds) exactly as the operator asked.
    """
    target = shell if shell is not None else _active_shell()
    if target is None:
        print_info_debug(f"scan-control: no shell to record stop {stop.action}")
        return
    domain = _resolve_domain(target, stop)
    phase_title = _phase_title(stop.phase_id) if stop.phase_id else ""
    try:
        from adscan_core.reporting.operator_stop_coverage import (  # noqa: PLC0415
            build_operator_stop_entry,
        )

        entry = build_operator_stop_entry(
            action=stop.action,
            step_id=stop.step_id,
            label=stop.label,
            phase_id=stop.phase_id,
            phase_title=phase_title,
            examined=stop.examined,
            total=stop.total,
            unit=stop.unit,
            source=stop.source,
        )
        if domain and stop.phase_id:
            from adscan_internal.services.scan_progress import (  # noqa: PLC0415
                mark_phase_incomplete,
            )

            token = f"{OPERATOR_STOP_REASON}:{stop.step_id or stop.action}"
            mark_phase_incomplete(
                target,
                domain,
                stop.phase_id,
                reasons=(token,),
                detail=_detail_sentence(stop),
            )
        if domain:
            from adscan_core.reporting.technical_report import (  # noqa: PLC0415
                record_operator_stop as _persist,
            )

            _persist(target, domain, entry=entry)
        # Tell the platform as it happens: the scan page lists each stop with
        # the same sentence the report will carry.
        try:
            _emit_control_event(
                {
                    "state": "stop_recorded",
                    "action": stop.action,
                    "phase": stop.phase_id or None,
                    "step": stop.step_id or None,
                    "step_label": stop.label or None,
                    "statement": entry["statement"],
                }
            )
        except Exception as exc:  # noqa: BLE001 - observability is best-effort
            print_info_debug(f"scan-control: stop event not emitted ({type(exc).__name__})")
        print_info_debug(
            f"scan-control: recorded {stop.action} step={stop.step_id or '-'} "
            f"phase={stop.phase_id or '-'} domain={mark_sensitive(domain, 'domain')}"
        )
        if stop.action == "skip_step" and stop.step_id:
            print_info(entry["statement"].replace(" in this report", ""))
    except Exception as exc:  # noqa: BLE001 - recording never breaks the scan
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def _detail_sentence(stop: OperatorStop) -> str:
    """The operator-facing "what did not finish" line for the recap and ``ci``."""
    label = stop.label or "the scan"
    if stop.examined is not None and stop.total:
        unit = f" {stop.unit}" if stop.unit else ""
        return f"stopped by the operator during {label}, after {stop.examined} of {stop.total}{unit}"
    return f"stopped by the operator during {label}"


def install_scan_control_wiring(control: ScanControl | None = None) -> ScanControl:
    """Install the recorder, the event emitter and the title resolver (idempotent)."""
    global _INSTALLED
    ctl = control or scan_control()
    with _INSTALL_LOCK:
        if control is not None or not _INSTALLED:
            ctl.set_gap_recorder(record_operator_stop)
            ctl.set_event_emitter(_emit_control_event)
            set_phase_title_resolver(_phase_title)
            if control is None:
                _INSTALLED = True
    return ctl


def _print_policy_launch_line(shell: Any, *, interactive: bool) -> None:
    """Say which policy the scan runs under, once, before it starts."""
    try:
        from adscan_internal.services.scan_controls import (  # noqa: PLC0415
            policy_launch_line,
        )

        line = policy_launch_line(shell, interactive=interactive)
    except Exception as exc:  # noqa: BLE001 - a launch line never blocks a scan
        print_info_debug(f"scan-control: policy line unavailable ({type(exc).__name__})")
        return
    if line:
        print_info(line)


@contextlib.contextmanager
def operator_scan_scope(shell: Any, kind: str) -> Iterator[ScanControl]:
    """Open the scan scope for one scan entry point (``start_auth`` / ``start_unauth``).

    Interactive runs get the Ctrl+C operator menu; unattended runs (``adscan ci``,
    the web worker) stop cleanly on the first SIGINT and read the platform control
    file from the EXECUTION workspace (``current_workspace_dir`` is the ``.run_*``
    root for a live web scan). Swallows the abort; read
    ``scan_control().last_scan_aborted`` afterwards.
    """
    global _ACTIVE_SHELL
    from adscan_internal.interaction import is_non_interactive  # noqa: PLC0415

    ctl = install_scan_control_wiring()
    interactive = not is_non_interactive(shell)
    if not ctl.in_scan():
        _print_policy_launch_line(shell, interactive=interactive)
    previous = _ACTIVE_SHELL
    _ACTIVE_SHELL = shell
    try:
        with ctl.scan(
            kind=kind,
            workspace_dir=getattr(shell, "current_workspace_dir", None),
            interactive=interactive,
            domain=str(getattr(shell, "domain", "") or ""),
        ):
            yield ctl
    finally:
        _ACTIVE_SHELL = previous


__all__ = [
    "OPERATOR_STOP_REASON",
    "install_scan_control_wiring",
    "operator_scan_scope",
    "record_operator_stop",
]
