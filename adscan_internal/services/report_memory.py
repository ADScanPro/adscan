"""Report rendering under the memory doctrine: the ``report`` stage boundary.

Rendering a deliverable reads the workspace (technical report, attack graph,
attack paths) and drives a browser for the PDF. On a machine too small for the
directory that is where a run is killed after an hour of scanning, with no
report and nothing said. So the render runs under
:func:`adscan_core.memory_guard.memory_bounded` (stage ``report``): every document
finished is a unit of work, and crossing the line stops the render cleanly.

A stopped render produces no deliverable (the kit never ships with a requested
document missing). The stop is recorded in the workspace's
``technical_report.json`` under each domain's ``resource_coverage`` block, so the
platform and the next render say which part of the assessment did not finish,
and the operator sees the cause and the remedy on the terminal.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from adscan_core import telemetry
from adscan_core.memory_guard import OUTCOME_STOPPED, memory_bounded
from adscan_core.reporting.resource_coverage import STAGE_REPORT
from adscan_core.rich_output import print_exception

#: What the report stage counts, for the coverage statement.
REPORT_UNIT = "documents"


class _WorkspaceReportShell:
    """The minimal shell ``technical_report`` needs to find the workspace's file."""

    def __init__(self, workspace_dir: Path) -> None:
        self.technical_report_file = str(Path(workspace_dir) / "technical_report.json")
        self.domains_data: dict[str, Any] = {}


def _report_domains(workspace_dir: Path) -> list[str]:
    # Through the one read seam, which refuses a report that does not fit.
    from adscan_core.reporting.technical_report import (  # noqa: PLC0415
        _load_technical_report,
    )

    if not (Path(workspace_dir) / "technical_report.json").is_file():
        return []
    report = _load_technical_report(_WorkspaceReportShell(Path(workspace_dir)))
    domains = report.get("domains") if isinstance(report, dict) else None
    return [str(name) for name in domains] if isinstance(domains, dict) else []


def record_report_stop(
    workspace_dir: Path | str | None, shell: Any = None
) -> Callable[[dict[str, Any]], None]:
    """The ``record`` callback of a render stopped at the memory ceiling.

    Folds the block into every domain of the workspace's technical report (the
    session's ``domains_data`` too, when a scan session rendered it). Never
    raises.
    """

    def _record(block: dict[str, Any]) -> None:
        if not workspace_dir:
            return
        try:
            from adscan_core.reporting.technical_report import (  # noqa: PLC0415
                record_resource_coverage,
            )
            from adscan_internal.services.resource_coverage_recorder import (  # noqa: PLC0415
                record_stage_coverage,
            )

            directory = Path(workspace_dir)
            for domain in _report_domains(directory):
                if shell is not None and getattr(shell, "domains_data", None) is not None:
                    record_stage_coverage(shell, domain, block)
                else:
                    record_resource_coverage(
                        _WorkspaceReportShell(directory), domain, coverage=block
                    )
        except Exception as exc:  # noqa: BLE001 - recording a stop never raises
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    return _record


def clear_report_stop(workspace_dir: Path | str | None, shell: Any = None) -> None:
    """Forget an earlier render stop: this render is judged afresh. Never raises."""
    if not workspace_dir:
        return
    try:
        from adscan_core.reporting.technical_report import (  # noqa: PLC0415
            read_resource_coverage,
            record_resource_coverage,
        )

        directory = Path(workspace_dir)
        report_shell = _WorkspaceReportShell(directory)
        for domain in _report_domains(directory):
            block = read_resource_coverage(report_shell, domain) or {}
            if not any(
                isinstance(item, dict) and item.get("stage") == STAGE_REPORT
                for item in block.get("stages") or ()
            ):
                continue
            if shell is not None and getattr(shell, "domains_data", None) is not None:
                from adscan_internal.services.resource_coverage_recorder import (  # noqa: PLC0415
                    record_stage_coverage,
                )

                record_stage_coverage(
                    shell, domain, {"complete": True, "stages": []}, replace_stage=STAGE_REPORT
                )
            else:
                record_resource_coverage(
                    report_shell,
                    domain,
                    coverage={"complete": True, "stages": []},
                    replace_stage=STAGE_REPORT,
                )
    except Exception as exc:  # noqa: BLE001 - clearing a stop never raises
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def render_bounded(
    render: Callable[[], Any],
    *,
    workspace_dir: Callable[[], Path | str | None] | Path | str | None,
    shell: Any = None,
    total: int | None = None,
) -> tuple[bool, Any]:
    """Run ``render`` (one call) under the ``report`` stage boundary.

    Args:
        render: Renders the deliverable and returns its result.
        workspace_dir: The workspace, or a callable resolving it once the render
            ran (``deliver`` resolves the workspace inside its own flow).
        shell: The scan session when one rendered the report, else ``None``.
        total: Documents the render has in front of it, when known.

    Returns:
        ``(stopped, result)``: ``stopped`` is True when the render reached the
        memory ceiling (recorded and declared); ``result`` is ``render``'s
        return value, ``None`` when stopped.
    """

    def _record(block: dict[str, Any]) -> None:
        target = workspace_dir() if callable(workspace_dir) else workspace_dir
        record_report_stop(target, shell)(block)

    if not callable(workspace_dir):
        clear_report_stop(workspace_dir, shell)

    with memory_bounded(STAGE_REPORT, unit=REPORT_UNIT, total=total, record=_record) as stage:
        result = render()
    if stage.outcome == OUTCOME_STOPPED:
        return True, None
    return False, result


__all__ = ("REPORT_UNIT", "record_report_stop", "render_bounded")
