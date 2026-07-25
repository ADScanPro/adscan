"""Persistent per-scan event log for the native CVE scanner.

Subscribes to the same :class:`EventBus` events the dashboard renders
(``CheckEvent``) and writes one line per event to ``scan.log`` inside the
scan directory. Designed for post-mortem debugging — the dashboard only
keeps the last 5 lines on screen, this file keeps the full chronological
trace.

Format::

    <iso8601> <VERB> <aka> <host> <details>

Verbs:

- ``START`` — check started against host
- ``VULN``  — check finished with status ``vulnerable``
- ``CLEAN`` — check finished with status ``not_vulnerable``
- ``ERROR`` — check finished with status ``error``
- ``NA``    — check finished with status ``not_applicable``
- ``SKIP``  — check finished with status ``skipped``
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from adscan_core import telemetry
from adscan_core.rich_output import print_error
from adscan_internal.core.events import Event, EventBus
from adscan_internal.services.cve_scanner.result import CVEResult, CVEStatus
from adscan_core.rich_output import print_exception


_STATUS_VERB: dict[str, str] = {
    CVEStatus.VULNERABLE.value: "VULN",
    CVEStatus.NOT_VULNERABLE.value: "CLEAN",
    CVEStatus.ERROR.value: "ERROR",
    CVEStatus.NOT_APPLICABLE.value: "NA",
    CVEStatus.SKIPPED.value: "SKIP",
    CVEStatus.RUNNING.value: "RUN",
}


class ScanLogWriter:
    """Append-only writer that mirrors CVE check events to ``scan.log``.

    Use :meth:`subscribe` to wire the writer to an :class:`EventBus` —
    it consumes :class:`adscan_internal.services.cve_scanner.runner.CheckEvent`
    instances. Use :meth:`record_result` to log finalised results that
    arrive through the runner's ``on_result`` callback (this captures
    error/summary text the bare ``CheckEvent`` does not carry).
    """

    def __init__(self, log_path: Path) -> None:
        self._path = log_path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # Open in append mode so a partial scan does not lose history if
        # the writer is reused. ``buffering=1`` = line-buffered for live
        # tailability during long scans.
        self._fh = open(self._path, "a", encoding="utf-8", buffering=1)

    @property
    def path(self) -> Path:
        """Return the on-disk log path."""

        return self._path

    def subscribe(self, bus: EventBus) -> None:
        """Subscribe this writer to an event bus for ``CheckEvent`` start lines."""

        bus.subscribe_all(self._handle_event)

    def _handle_event(self, event: Event) -> None:
        # Lazy import to avoid a runner→ux→runner cycle.
        from adscan_internal.services.cve_scanner.runner import CheckEvent

        if not isinstance(event, CheckEvent):
            return
        if event.phase != "started":
            # ``finished`` lines are written via record_result so we get
            # error strings + evidence summaries. Avoid double-writing.
            return
        self._write(
            verb="START",
            aka=event.aka or event.cve_id,
            host=event.host,
            detail="",
        )

    def record_result(self, result: CVEResult) -> None:
        """Write one finalised :class:`CVEResult` to the log."""

        verb = _STATUS_VERB.get(result.status.value, result.status.value.upper())
        detail_parts: list[str] = []
        if result.evidence and result.evidence.summary:
            detail_parts.append(result.evidence.summary)
        if result.error:
            detail_parts.append(result.error)
        detail = " | ".join(detail_parts)
        self._write(
            verb=verb,
            aka=result.aka,
            host=result.host,
            detail=detail,
        )

    def close(self) -> None:
        """Close the underlying file handle."""

        try:
            self._fh.close()
        except OSError as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    def __enter__(self) -> ScanLogWriter:
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    # ------------------------------------------------------------------

    def _write(self, *, verb: str, aka: str, host: str, detail: str) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        line = f"{ts} {verb:<5} {aka} {host}"
        if detail:
            line += f" {detail}"
        try:
            self._fh.write(line + "\n")
        except OSError as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_error(f"[cve_scanner] failed to write scan log: {exc}")


__all__ = ["ScanLogWriter"]
