"""Persist + emit scan widgets — the engine half of the shared widget loop.

One call (:func:`publish_widget`) does both halves of the contract:

* **Live** — emits a structured ``widget`` event on the CI event sink
  (``emit_widget``) so the Celery worker ingests it during the scan.
* **Post-scan** — writes the same payload to a persisted artifact
  (``domains/<domain>/inventory/widgets/<key>.json``) so it is re-viewable
  after the run and ingested as a reconciling backstop.

The persisted shape mirrors the other collector inventory artifacts
(``inventory_persistence.py``): a small envelope with ``schema_version`` /
``domain`` / ``generated_at`` wrapping the widget ``payload``. Persistence is
best-effort and never raises into the scan flow.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from adscan_core import telemetry

from adscan_internal.cli.widgets.widget_contract import Widget
from adscan_internal.workspaces import domain_subpath, write_json_file


def _widgets_dir(shell: object, domain: str) -> str | None:
    """Resolve ``domains/<domain>/inventory/widgets`` for ``shell``.

    Returns ``None`` when the workspace path cannot be resolved (e.g. a
    shell-less unit context) so the caller silently skips persistence.
    """
    workspace_cwd = (
        shell._get_workspace_cwd()  # noqa: SLF001
        if hasattr(shell, "_get_workspace_cwd")
        else getattr(shell, "current_workspace_dir", "")
    )
    if not workspace_cwd:
        return None
    domains_dir = getattr(shell, "domains_dir", "domains")
    return domain_subpath(workspace_cwd, domains_dir, domain, "inventory", "widgets")


def persist_widget(shell: object, *, domain: str, widget: Widget) -> str | None:
    """Write the widget to ``inventory/widgets/<key>.json``. Best-effort.

    Returns the written path, or ``None`` when persistence was skipped/failed.
    """
    try:
        widgets_dir = _widgets_dir(shell, domain)
        if not widgets_dir:
            return None
        os.makedirs(widgets_dir, exist_ok=True)
        envelope: dict[str, Any] = {
            "schema_version": widget.schema_version,
            "domain": domain,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "record_type": "widget",
            "payload": widget.to_payload(),
        }
        path = os.path.join(widgets_dir, f"{widget.key}.json")
        write_json_file(path, envelope)
        return path
    except Exception as exc:  # noqa: BLE001 — persistence never breaks the scan
        telemetry.capture_exception(exc)
        return None


def publish_widget(shell: object | None, *, domain: str | None, widget: Widget) -> None:
    """Emit the widget live AND persist it. The single call sites use.

    Args:
        shell: Runtime shell used to resolve the workspace path for the
            persisted artifact. When ``None`` only the live event is emitted.
        domain: Owning domain (used for the artifact path and event field).
        widget: The :class:`Widget` to publish.
    """
    # Live half — structured event for the worker (no-op unless the sink is on).
    try:
        from adscan_internal.cli.ci_events import emit_widget

        emit_widget(
            widget.widget_type,
            key=widget.key,
            title=widget.title,
            data=widget.data,
            domain=widget.domain if widget.domain is not None else domain,
            schema_version=widget.schema_version,
        )
    except Exception as exc:  # noqa: BLE001 — emission never breaks the scan
        telemetry.capture_exception(exc)

    # Post-scan half — persisted artifact for re-view + reconciling ingest.
    if shell is not None and domain:
        persist_widget(shell, domain=domain, widget=widget)


__all__ = ["persist_widget", "publish_widget"]
