"""Provenance of an attack step ADscan adds after an access (SSOT).

The attack-path engine adds follow-up steps that no directory read produced: the
host's own secrets read after local-admin access, the logged-on user's session
used after a session is found, the SQL host's command execution after sysadmin
access, a child-to-parent escalation across a trust. The graph writer stores
them in ``attack_graph.json`` as ordinary edges, marked with this provenance, so
a client surface can say what the step is instead of presenting it as collected
directory data.

Import-safe (stdlib only): the engine, the PDF report and the web backend all
read the same constants and the same client sentence.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

#: ``edge.notes["origin"]`` of a step the engine added.
ENGINE_FOLLOWUP_ORIGIN = "engine_followup"
#: Note keys of that provenance.
ENGINE_FOLLOWUP_ORIGIN_KEY = "origin"
ENGINE_FOLLOWUP_PARENT_KEY = "parent_edge"

#: The client sentence for such a step (web edge detail, report evidence line).
ENGINE_FOLLOWUP_LABEL = (
    "ADscan adds this step after the access it depends on; "
    "it was not read from the directory."
)


def notes_are_engine_followup(notes: Mapping[str, Any] | None) -> bool:
    """True when an edge's notes carry the engine follow-up provenance."""
    return (
        isinstance(notes, Mapping)
        and notes.get(ENGINE_FOLLOWUP_ORIGIN_KEY) == ENGINE_FOLLOWUP_ORIGIN
    )


def engine_followup_view(notes: Mapping[str, Any] | None) -> dict[str, str] | None:
    """The client view of the provenance, or ``None`` for any other edge."""
    if not notes_are_engine_followup(notes):
        return None
    assert isinstance(notes, Mapping)
    return {
        "origin": ENGINE_FOLLOWUP_ORIGIN,
        "label": ENGINE_FOLLOWUP_LABEL,
        "parent_edge": str(notes.get(ENGINE_FOLLOWUP_PARENT_KEY) or ""),
    }
