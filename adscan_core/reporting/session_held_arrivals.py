"""Session-held arrivals: presence on a host, never control of its account.

A route that reaches a host through an access edge (CanRDP, CanPSRemote,
ExecuteDCOM, SQLAccess, SQLAdmin, a linked-server hop, AdminTo,
ReadLAPSPassword, the RBCD relay) stands on a session there, not on the host's
machine account. The engine never continues such a route along the host's own
edges, and it stamps the fact on the step
(``attack_graph_core.stamp_session_held_targets``) so a view that draws several
routes together can tell presence from control
(``adscan_core.reporting.route_overlay``).

Dependency-light (stdlib only): the engine writes the stamp through these
names, and the report renderers and the web backend read it through them.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

#: Step ``details`` key the engine sets on a step whose TARGET the route holds
#: only through an access session.
SESSION_HELD_DETAILS_KEY = "target_held_as"
#: The value of :data:`SESSION_HELD_DETAILS_KEY` for a session-held target.
SESSION_HELD_VALUE = "session"


def step_target_held_as_session(step: Any) -> bool:
    """True when ``step``'s target is held only through an access session."""
    if not isinstance(step, Mapping):
        return False
    details = step.get("details")
    return (
        isinstance(details, Mapping)
        and details.get(SESSION_HELD_DETAILS_KEY) == SESSION_HELD_VALUE
    )


__all__ = [
    "SESSION_HELD_DETAILS_KEY",
    "SESSION_HELD_VALUE",
    "step_target_held_as_session",
]
