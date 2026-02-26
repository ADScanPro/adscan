"""Attack graph runtime context helpers.

This module provides a small, focused API for tracking the currently executing
attack-graph edge (a.k.a. "active step") in memory and updating its persisted
status in ``attack_graph.json``.

Design goals:
- Keep runtime-only state out of ``variables.json``.
- Centralize logging and status updates in one place.
- Avoid passing "step objects" through every call chain (use a context instead).
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator

from adscan_internal import print_info_debug
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.attack_graph_service import update_edge_status_by_labels


@dataclass(frozen=True, slots=True)
class ActiveAttackGraphStep:
    """Runtime representation of a currently executing attack-graph edge."""

    domain: str
    from_label: str
    relation: str
    to_label: str
    notes: dict[str, object]


def set_active_step(
    shell: Any,
    *,
    domain: str,
    from_label: str,
    relation: str,
    to_label: str,
    notes: dict[str, object] | None = None,
) -> None:
    """Set the active attack-graph edge being executed (runtime-only).

    Args:
        shell: Shell-like object. The active step is stored on this object to
            keep context local to an interactive session.
        domain: Target domain.
        from_label: Source node label.
        relation: Edge relation/action name.
        to_label: Destination node label.
        notes: Optional step metadata.
    """
    payload = ActiveAttackGraphStep(
        domain=domain,
        from_label=from_label,
        relation=relation,
        to_label=to_label,
        notes=notes or {},
    )
    setattr(shell, "_active_attack_graph_step", payload)
    try:
        marked_domain = mark_sensitive(domain, "domain")
        marked_from = mark_sensitive(from_label, "node")
        marked_to = mark_sensitive(to_label, "node")
        print_info_debug(
            "[attack-graph] Active step set: "
            f"domain={marked_domain} from={marked_from} relation={relation} to={marked_to}"
        )
    except Exception:
        # Logging should never break execution flow.
        pass


def clear_active_step(shell: Any) -> None:
    """Clear the active attack-graph edge being executed (runtime-only)."""
    try:
        active = getattr(shell, "_active_attack_graph_step", None)
        if isinstance(active, ActiveAttackGraphStep):
            marked_domain = mark_sensitive(active.domain, "domain")
            marked_from = mark_sensitive(active.from_label, "node")
            marked_to = mark_sensitive(active.to_label, "node")
            print_info_debug(
                "[attack-graph] Active step cleared: "
                f"domain={marked_domain} from={marked_from} relation={active.relation} to={marked_to}"
            )
    except Exception:
        pass
    setattr(shell, "_active_attack_graph_step", None)


def update_active_step_status(
    shell: Any,
    *,
    domain: str,
    status: str,
    notes: dict[str, object] | None = None,
) -> bool:
    """Update the active edge status (if one is set) and persist to the graph.

    Args:
        shell: Shell-like object holding ``_active_attack_graph_step``.
        domain: Domain expected for the active edge.
        status: New status (e.g. discovered/attempted/success/failed).
        notes: Optional notes to merge with the step's stored notes.

    Returns:
        True if an active step existed and was updated, False otherwise.
    """
    active = getattr(shell, "_active_attack_graph_step", None)
    if not isinstance(active, ActiveAttackGraphStep):
        return False
    if active.domain != domain:
        return False
    if not active.from_label or not active.to_label or not active.relation:
        return False

    merged_notes: dict[str, object] = {}
    merged_notes.update(active.notes or {})
    if isinstance(notes, dict):
        merged_notes.update(notes)

    try:
        marked_domain = mark_sensitive(domain, "domain")
        marked_from = mark_sensitive(active.from_label, "node")
        marked_to = mark_sensitive(active.to_label, "node")
        print_info_debug(
            "[attack-graph] Active step status update: "
            f"domain={marked_domain} from={marked_from} relation={active.relation} to={marked_to} status={status}"
        )
    except Exception:
        pass

    return bool(
        update_edge_status_by_labels(
            shell,
            domain,
            from_label=active.from_label,
            relation=active.relation,
            to_label=active.to_label,
            status=status,
            notes=merged_notes or None,
        )
    )


@contextmanager
def active_step(
    shell: Any,
    *,
    domain: str,
    from_label: str,
    relation: str,
    to_label: str,
    notes: dict[str, object] | None = None,
) -> Iterator[None]:
    """Context manager that sets and clears the active step reliably."""
    set_active_step(
        shell,
        domain=domain,
        from_label=from_label,
        relation=relation,
        to_label=to_label,
        notes=notes,
    )
    try:
        yield None
    finally:
        clear_active_step(shell)


__all__ = [
    "ActiveAttackGraphStep",
    "active_step",
    "clear_active_step",
    "clear_attack_path_execution",
    "is_attack_path_execution_active",
    "set_attack_path_execution",
    "set_active_step",
    "update_active_step_status",
]


def set_attack_path_execution(shell: Any) -> None:
    """Mark that an attack path execution is in progress (runtime-only)."""
    setattr(shell, "_attack_path_execution_active", True)
    try:
        print_info_debug("[attack-graph] Attack path execution flag set.")
    except Exception:
        pass


def clear_attack_path_execution(shell: Any) -> None:
    """Clear the attack path execution flag (runtime-only)."""
    try:
        active = bool(getattr(shell, "_attack_path_execution_active", False))
        if active:
            print_info_debug("[attack-graph] Attack path execution flag cleared.")
    except Exception:
        pass
    setattr(shell, "_attack_path_execution_active", False)


def is_attack_path_execution_active(shell: Any) -> bool:
    """Return True when an attack path execution is active."""
    return bool(getattr(shell, "_attack_path_execution_active", False))
