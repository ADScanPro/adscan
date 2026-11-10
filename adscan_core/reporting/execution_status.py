"""The engine's execution-status vocabulary, and its one translation to the web.

The engine writes an execution status on every attack-graph edge
(``attack_graph.json``) and on every attack path (``attack_paths_snapshot.json``):
whether ADscan proved the step or route, tried it, withheld it for safety, found
it closed by configuration, or only mapped it. The web CTEM persists both, and
every figure it shows about validated exposure reads them back. When the web
re-derived them itself it lost them: every edge landed as ``discovered`` and a
partially validated route as ``success``, the second being the one direction the
Exposure-Validation doctrine forbids (a mapped route read as compromise).

So the translation lives here, once:

* :func:`normalize_edge_execution_status` is the stored token of one edge or
  step.
* :func:`engine_path_execution_status` is the stored token of one path. The
  engine's own path status is AUTHORITATIVE; this function never re-derives a
  path from its steps, because only the engine knows which steps count (context
  relations, the support registry, coverage markers).

Rules the mapping keeps, all from CLAUDE.md § Exposure Validation:

* Only a route the engine walked end to end lands on a proven token
  (``success``, or ``domain_compromised`` when its ``path_state`` says so).
* ``partial`` stays ``partial``: one proven step is not a compromised domain.
* ``blocked`` is restraint ONLY with the safety marker stamped by the
  destructive-action classifier; a bare ``blocked`` reads ``attempted``, because
  ADscan never attributes a non-execution to a control in the client's
  environment.
* ``closed_by_configuration`` is the positive "attack surface reduced" bucket and
  is kept as such.
* An unknown token is never read upward: it lands on ``theoretical``.

Stdlib only, so the engine (``path_state``, ``destructive_action_policy``), the
web backend and the Celery worker that runs the ingestion all import it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Final, Optional

#: Marker (``details.blocked_kind``) the destructive-action classifier stamps on a
#: step ADscan hard-refused for safety. ``destructive_action_policy`` re-exports it.
DANGEROUS_DESTRUCTIVE_MARKER: Final[str] = "dangerous_destructive"

#: Engine path statuses meaning the route was walked END TO END. The engine's
#: ``path_state._PROVEN_STATUSES`` is this set, and
#: ``attack_graph_core._FULLY_EXECUTED_PATH_STATUSES`` is locked to it by test.
FULLY_EXECUTED_PATH_STATUSES: Final[frozenset[str]] = frozenset(
    {"success", "exploited", "domain_compromised"}
)

PARTIAL_STATUS: Final[str] = "partial"
CLOSED_BY_CONFIGURATION_STATUS: Final[str] = "closed_by_configuration"
NOT_VULNERABLE_STATUS: Final[str] = "not_vulnerable"
COVERAGE_SAMPLE_STATUS: Final[str] = "coverage_sample"
DOMAIN_COMPROMISED_STATE: Final[str] = "domain_compromised"

# ── Web tokens (``attack_path_records.execution_status``) ─────────────────────
WEB_DOMAIN_COMPROMISED: Final[str] = "domain_compromised"
WEB_SUCCESS: Final[str] = "success"
WEB_PARTIAL: Final[str] = "partial"
#: A route ADscan confirmed and deliberately did not execute (safety marker).
WEB_SAFETY_BLOCKED: Final[str] = "blocked"
WEB_CLOSED_BY_CONFIGURATION: Final[str] = CLOSED_BY_CONFIGURATION_STATUS
WEB_ATTEMPTED: Final[str] = "attempted"
WEB_UNSUPPORTED: Final[str] = "unsupported"
WEB_UNAVAILABLE: Final[str] = "unavailable"
WEB_NOT_VULNERABLE: Final[str] = NOT_VULNERABLE_STATUS
WEB_COVERAGE_SAMPLE: Final[str] = COVERAGE_SAMPLE_STATUS
WEB_THEORETICAL: Final[str] = "theoretical"

WEB_PATH_EXECUTION_STATUSES: Final[frozenset[str]] = frozenset(
    {
        WEB_DOMAIN_COMPROMISED,
        WEB_SUCCESS,
        WEB_PARTIAL,
        WEB_SAFETY_BLOCKED,
        WEB_CLOSED_BY_CONFIGURATION,
        WEB_ATTEMPTED,
        WEB_UNSUPPORTED,
        WEB_UNAVAILABLE,
        WEB_NOT_VULNERABLE,
        WEB_COVERAGE_SAMPLE,
        WEB_THEORETICAL,
    }
)

#: Web tokens that state the route was walked end to end.
WEB_PROVEN_PATH_STATUSES: Final[frozenset[str]] = frozenset(
    {WEB_DOMAIN_COMPROMISED, WEB_SUCCESS}
)

_ATTEMPTED_TOKENS: Final[frozenset[str]] = frozenset(
    {"attempted", "failed", "error", "post_ex_failed"}
)

#: Engine path status -> web token, for every token that needs no further fact.
_PATH_STATUS_TO_WEB: Final[Mapping[str, str]] = {
    "domain_compromised": WEB_DOMAIN_COMPROMISED,
    "exploited": WEB_SUCCESS,
    "success": WEB_SUCCESS,
    "succeeded": WEB_SUCCESS,
    PARTIAL_STATUS: WEB_PARTIAL,
    CLOSED_BY_CONFIGURATION_STATUS: WEB_CLOSED_BY_CONFIGURATION,
    "unsupported": WEB_UNSUPPORTED,
    "unavailable": WEB_UNAVAILABLE,
    NOT_VULNERABLE_STATUS: WEB_NOT_VULNERABLE,
    COVERAGE_SAMPLE_STATUS: WEB_COVERAGE_SAMPLE,
    "theoretical": WEB_THEORETICAL,
    "discovered": WEB_THEORETICAL,
    **{token: WEB_ATTEMPTED for token in _ATTEMPTED_TOKENS},
}

#: Engine edge/step status -> stored edge token. ``theoretical`` and the other
#: "not run" spellings collapse to the historical ``discovered``.
_EDGE_STATUS_TO_WEB: Final[Mapping[str, str]] = {
    "success": "success",
    "succeeded": "success",
    "exploited": "success",
    PARTIAL_STATUS: "partial",
    "attempted": "attempted",
    "failed": "attempted",
    "error": "attempted",
    "blocked": "blocked",
    "policy_blocked": "blocked",
    "unsupported": "unsupported",
    "unavailable": "unavailable",
    CLOSED_BY_CONFIGURATION_STATUS: CLOSED_BY_CONFIGURATION_STATUS,
    NOT_VULNERABLE_STATUS: NOT_VULNERABLE_STATUS,
    "discovered": "discovered",
    "pending": "discovered",
    "theoretical": "discovered",
    "validated": "discovered",
}


def _token(raw: Any) -> str:
    return str(raw or "").strip().lower()


def normalize_edge_execution_status(raw_status: Any) -> str:
    """Return the stored token for one edge's (or step's) engine status.

    Args:
        raw_status: The engine's ``status`` on the edge or step, any casing.

    Returns:
        One stable token. A missing status is ``discovered``; a token this
        module does not know is kept verbatim (lower-cased), so a new engine
        status is never silently folded into a stronger one.
    """
    token = _token(raw_status)
    if not token:
        return "discovered"
    return _EDGE_STATUS_TO_WEB.get(token, token)


def step_is_safety_abstention(step: Any) -> bool:
    """Return True when ONE step was hard-refused for safety (marker-based)."""
    if not isinstance(step, Mapping):
        return False
    details = step.get("details")
    if not isinstance(details, Mapping):
        return False
    return _token(details.get("blocked_kind")) == DANGEROUS_DESTRUCTIVE_MARKER


def path_has_safety_abstention(path: Any) -> bool:
    """Return True when any step of ``path`` carries the safety marker."""
    if not isinstance(path, Mapping):
        return False
    steps = path.get("steps")
    if not isinstance(steps, Sequence) or isinstance(steps, (str, bytes)):
        return False
    return any(step_is_safety_abstention(step) for step in steps)


def engine_path_execution_status(path: Optional[Mapping[str, Any]]) -> Optional[str]:
    """Return the web token for a path, from the ENGINE's own verdict.

    Args:
        path: One engine path record (snapshot or technical-report shape). Reads
            ``status``, ``path_state`` and, for ``blocked``, the steps' safety
            marker.

    Returns:
        A member of :data:`WEB_PATH_EXECUTION_STATUSES`, or ``None`` when the
        record carries no engine status at all (a legacy record; the caller then
        decides, and must not read it upward either).
    """
    if not isinstance(path, Mapping):
        return None
    status = _token(path.get("status"))
    state = _token(path.get("path_state"))
    if state == DOMAIN_COMPROMISED_STATE:
        return WEB_DOMAIN_COMPROMISED
    if not status:
        return None
    if status == "blocked":
        return WEB_SAFETY_BLOCKED if path_has_safety_abstention(path) else WEB_ATTEMPTED
    return _PATH_STATUS_TO_WEB.get(status, WEB_THEORETICAL)


__all__ = [
    "CLOSED_BY_CONFIGURATION_STATUS",
    "COVERAGE_SAMPLE_STATUS",
    "DANGEROUS_DESTRUCTIVE_MARKER",
    "DOMAIN_COMPROMISED_STATE",
    "FULLY_EXECUTED_PATH_STATUSES",
    "NOT_VULNERABLE_STATUS",
    "PARTIAL_STATUS",
    "WEB_PATH_EXECUTION_STATUSES",
    "WEB_PROVEN_PATH_STATUSES",
    "engine_path_execution_status",
    "normalize_edge_execution_status",
    "path_has_safety_abstention",
    "step_is_safety_abstention",
]
