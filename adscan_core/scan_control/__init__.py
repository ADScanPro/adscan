"""Scan control plane: skip a step, skip a phase, stop the scan.

The SSOT every entry point consumes: the interactive CLI (Ctrl+C operator menu),
``adscan ci`` (SIGINT) and the web worker (a control file in the execution
workspace). Design: docs/superpowers/specs/2026-11-12-scan-control-plane-design.md.

Every long step runs inside a scope::

    from adscan_core.scan_control import scan_control

    with scan_control().step("share_credential_hunt", label="SMB share credential hunt",
                             long=True, unit="shares", total=len(targets)) as step:
        for index, target in enumerate(targets):
            if step.should_stop():
                break
            ...
            step.progress(done=index + 1)

The vocabulary module is pure stdlib so the web backend and the worker import it
without pulling the controller; importing this package does pull the controller,
which itself only depends on the standard library.
"""

from __future__ import annotations

from adscan_core.scan_control.controller import (
    OperatorStop,
    ScanAbortRequested,
    ScanControl,
    StepScope,
    scan_control,
    set_phase_title_resolver,
)
from adscan_core.scan_control.vocabulary import (
    CONTROL_REQUEST_FILENAME,
    ControlAction,
    ControlRequest,
    consume_control_request,
    write_control_request,
)

__all__ = [
    "CONTROL_REQUEST_FILENAME",
    "ControlAction",
    "ControlRequest",
    "OperatorStop",
    "ScanAbortRequested",
    "ScanControl",
    "StepScope",
    "consume_control_request",
    "scan_control",
    "set_phase_title_resolver",
    "write_control_request",
]
