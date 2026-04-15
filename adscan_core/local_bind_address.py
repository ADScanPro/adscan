"""Reusable local bind-address selection helpers for ADscan services."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Sequence

from adscan_core.port_diagnostics import parse_host_port


@dataclass(frozen=True, slots=True)
class BindAddressConflict:
    """Describe why one bind candidate could not be selected."""

    bind_addr: str
    summary: str


def resolve_first_available_bind_addr(
    *,
    candidates: Sequence[str],
    excluded_bind_addrs: Sequence[str] = (),
    is_bind_addr_available: Callable[[str], bool],
    inspect_bind_conflict: Callable[[str], Any | None] | None = None,
    can_bind_privileged_port: Callable[[], bool] | None = None,
    privileged_permission_summary: str = "permission denied",
    on_candidate_unavailable: Callable[[str, str], None] | None = None,
) -> tuple[str | None, list[BindAddressConflict]]:
    """Return the first available bind address plus collected conflict summaries."""

    excluded = {str(item).strip() for item in excluded_bind_addrs if str(item).strip()}
    conflicts: list[BindAddressConflict] = []
    for candidate in candidates:
        bind_addr = str(candidate).strip()
        if not bind_addr or bind_addr in excluded:
            continue
        _host, port = parse_host_port(bind_addr)
        if int(port) < 1024 and callable(can_bind_privileged_port) and not can_bind_privileged_port():
            summary = str(privileged_permission_summary).strip() or "permission denied"
            conflicts.append(BindAddressConflict(bind_addr=bind_addr, summary=summary))
            if callable(on_candidate_unavailable):
                on_candidate_unavailable(bind_addr, summary)
            continue
        if is_bind_addr_available(bind_addr):
            return bind_addr, conflicts
        summary = "busy"
        if callable(inspect_bind_conflict):
            try:
                conflict = inspect_bind_conflict(bind_addr)
            except Exception:  # pragma: no cover - defensive
                conflict = None
            if conflict is not None and hasattr(conflict, "render_summary"):
                try:
                    rendered = str(conflict.render_summary() or "").strip()
                except Exception:  # pragma: no cover - defensive
                    rendered = ""
                if rendered:
                    summary = rendered
        conflicts.append(BindAddressConflict(bind_addr=bind_addr, summary=summary))
        if callable(on_candidate_unavailable):
            on_candidate_unavailable(bind_addr, summary)
    return None, conflicts


__all__ = ["BindAddressConflict", "resolve_first_available_bind_addr"]
