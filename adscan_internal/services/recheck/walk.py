"""Path walk and step exercise: the existing attack-path loop, recorded.

``recheck`` adds no path list, ordering, filter, actor logic or executor
(spec section 10.4a). A path is resolved from the same canonical listing the
report and the web show (``compute_report_attack_paths``, identified by the
web's ordered-route fingerprint), and executed by handing that one summary to
``offer_attack_paths_for_execution_summaries``, the loop ``attack_paths`` uses,
with its scan-policy, readiness, destructive-action and change-ledger gates. A
listener on :class:`AttackPathExecutionRun` reads each step's outcome when the
run finishes; this module maps it to the walk vocabulary and to ledger step ids.

Exercising one step is the same thing with a one-step summary sliced from the
canonical path that contains it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Collection, Mapping, Optional, Sequence

from adscan_core.engagement.identity import compute_attack_path_fingerprint, normalize_identity_token
from adscan_core.engagement.recheck import (
    WALK_COMPLETED,
    WALK_NOT_WALKED,
    WALK_STOPPED,
    RecheckError,
    WalkStep,
)

#: Explanation codes meaning the credential the step needed was refused.
CREDENTIAL_REFUSED_CODES = frozenset(
    {"KDC_ERR_PREAUTH_FAILED", "KDC_ERR_CLIENT_REVOKED", "invalidCredentials", "STATUS_LOGON_FAILURE"}
)

#: Path statuses a walk may (re-)execute: every one, including proven paths.
WALKABLE_STATUSES = frozenset({"theoretical", "attempted", "partial", "exploited", "blocked"})


@dataclass(frozen=True)
class ResolvedPath:
    """One canonical path record and where it lives."""

    domain: str
    path_id: str
    record: dict[str, Any]


def path_id_of(record: Mapping[str, Any], domain: str) -> str:
    """The path id the report and the web CTEM show (ordered-route fingerprint)."""
    details = record.get("details") if isinstance(record.get("details"), Mapping) else {}
    return compute_attack_path_fingerprint(
        steps=record.get("steps"),
        nodes=details.get("nodes") or record.get("nodes") or [],
        domain=domain,
        source=record.get("source") or details.get("source"),
        target=details.get("target") or record.get("target"),
        title=record.get("title"),
    )


def canonical_paths(workspace_dir: str, domains: Sequence[str]) -> list[ResolvedPath]:
    """The canonical domain listing of every domain (the report SSOT)."""
    from adscan_internal.services.report_attack_paths import (  # noqa: PLC0415
        compute_report_attack_paths,
    )

    out: list[ResolvedPath] = []
    for domain in domains:
        for record in compute_report_attack_paths(workspace_dir, domain) or []:
            if isinstance(record, dict):
                out.append(ResolvedPath(domain, path_id_of(record, domain), record))
    return out


def find_path(paths: Sequence[ResolvedPath], token: str) -> ResolvedPath:
    """The path whose id starts with ``token`` (unambiguous prefix)."""
    token = token.strip().lower()
    hits = {p.path_id: p for p in paths if p.path_id.startswith(token)}
    if not hits:
        raise RecheckError(
            f"No attack path with id '{token}' in the current listing of this workspace's "
            "attack paths (the id the report and the web show for each path)."
        )
    if len(hits) > 1:
        raise RecheckError(f"'{token}' matches {len(hits)} paths; give more characters of the id.")
    return next(iter(hits.values()))


# ---------------------------------------------------------------------------
# Step identity: display step -> ledger step item id.
# ---------------------------------------------------------------------------


def load_graph(workspace_dir: str, domain: str) -> Optional[dict[str, Any]]:
    path = Path(workspace_dir) / "domains" / domain / "attack_graph.json"
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def _label_index(nodes: Mapping[str, Any]) -> dict[str, list[str]]:
    index: dict[str, list[str]] = {}
    for node_id, node in nodes.items():
        if not isinstance(node, Mapping):
            continue
        for label in {node.get("label"), node.get("name"), node_id}:
            if label:
                index.setdefault(normalize_identity_token(label), []).append(str(node_id))
    return index


def ledger_step_ids(graph: Optional[Mapping[str, Any]], steps: Sequence[Any], domain: str) -> list[str]:
    """Ledger step id of each display step (``""`` when it cannot be pinned).

    A display step names its endpoints by label; the ledger keys an edge by the
    stable ids of both endpoints plus what tells twin edges apart. A step that
    matches no graph edge, or several edges with different identities, is left
    unpinned rather than guessed.
    """
    from adscan_core.reporting.engagement_items import step_item_id  # noqa: PLC0415

    if not isinstance(graph, Mapping):
        return ["" for _ in steps]
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), Mapping) else {}
    edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
    labels = _label_index(nodes)
    out: list[str] = []
    for step in steps:
        details = step.get("details") if isinstance(step, Mapping) and isinstance(step.get("details"), Mapping) else {}
        relation = normalize_identity_token(step.get("action") if isinstance(step, Mapping) else "")
        sources = set(labels.get(normalize_identity_token(details.get("from")), ()))
        targets = set(labels.get(normalize_identity_token(details.get("to")), ()))
        ids = set()
        for edge in edges:
            if not isinstance(edge, Mapping):
                continue
            rel = normalize_identity_token(edge.get("relation") or edge.get("edge_type") or edge.get("type"))
            src = str(edge.get("from") or edge.get("source") or "")
            dst = str(edge.get("to") or edge.get("target") or "")
            if rel != relation or src not in sources or dst not in targets:
                continue
            notes = edge.get("notes") if isinstance(edge.get("notes"), Mapping) else {}
            ids.add(
                step_item_id(
                    str(edge.get("relation") or rel), nodes.get(src), nodes.get(dst), notes, domain,
                    source_ref=src, target_ref=dst,
                )
            )
        out.append(next(iter(ids)) if len(ids) == 1 else "")
    return out


def path_step_item_ids(workspace_dir: str, resolved: ResolvedPath) -> list[str]:
    """Ordered ledger step ids of a path; raises when a step cannot be pinned."""
    graph = load_graph(workspace_dir, resolved.domain)
    ids = ledger_step_ids(graph, resolved.record.get("steps") or [], resolved.domain)
    if not ids or any(not i for i in ids):
        raise RecheckError(
            "Some steps of this path cannot be tied to the engagement ledger (the attack "
            "graph changed since the path was listed). Run a scan to refresh it."
        )
    return ids


def one_step_summary(record: Mapping[str, Any], index: int) -> dict[str, Any]:
    """A summary holding only step ``index`` (0-based) of ``record``."""
    steps = list(record.get("steps") or [])
    step = dict(steps[index])
    details = step.get("details") if isinstance(step.get("details"), Mapping) else {}
    source, target = details.get("from"), details.get("to")
    return {
        **record,
        "steps": [step],
        "relations": [step.get("action")],
        "nodes": [source, target],
        "length": 1,
        "source": source,
        "target": target,
        "status": step.get("status") or record.get("status"),
    }


def find_step_summary(
    paths: Sequence[ResolvedPath], workspace_dir: str, step_id: str
) -> tuple[ResolvedPath, dict[str, Any]]:
    """A one-step summary for ledger step ``step_id`` from a canonical path."""
    graphs: dict[str, Optional[dict[str, Any]]] = {}
    for path in paths:
        if path.domain not in graphs:
            graphs[path.domain] = load_graph(workspace_dir, path.domain)
        ids = ledger_step_ids(graphs[path.domain], path.record.get("steps") or [], path.domain)
        if step_id in ids:
            return path, one_step_summary(path.record, ids.index(step_id))
    raise RecheckError(
        "This step is not on any mapped attack path, so there is no route context to "
        "re-execute it from; re-check it with --depth observe."
    )


# ---------------------------------------------------------------------------
# Execution and recording.
# ---------------------------------------------------------------------------


def _principal_token(label: Any) -> str:
    text = str(label or "").strip()
    if "\\" in text:
        text = text.split("\\", 1)[1]
    return text.split("@", 1)[0].strip().casefold()


def walk_steps_from_outcomes(
    outcomes: Sequence[Any],
    step_ids: Sequence[str],
    *,
    removed_principals: Collection[str] = (),
) -> list[WalkStep]:
    """Map a finished run's step outcomes to walk steps on ledger ids.

    ``outcomes`` are the run's :class:`StepOutcome` (executable steps only, each
    with its 1-based ``index`` in the summary); ``step_ids`` holds the ledger id
    of every summary step, in order. A step proven earlier and not run again is
    reported as not re-executed, never as completed.

    ``removed_principals`` (case-folded names) are the principals whose stored
    credential the workspace secret purge removed. A step from one of them that
    did not complete is reported as ``credential_removed``: the route stopped
    because the foothold it started from was deleted on purpose, which is not a
    statement about the client's directory.
    """
    removed = {str(name).casefold() for name in removed_principals}
    from adscan_core.reporting.attack_path_execution_events import (  # noqa: PLC0415
        OUTCOME_NOT_REACHED,
        OUTCOME_SAFETY_BLOCKED,
        OUTCOME_SKIPPED,
        OUTCOME_SUCCESS,
    )

    out: list[WalkStep] = []
    broken = False
    for outcome in sorted(outcomes, key=lambda o: o.index):
        position = int(outcome.index) - 1
        step_id = step_ids[position] if 0 <= position < len(step_ids) else ""
        if not step_id:
            continue
        if broken or outcome.outcome == OUTCOME_NOT_REACHED:
            out.append(WalkStep(step_id, WALK_NOT_WALKED))
            continue
        if outcome.outcome == OUTCOME_SUCCESS:
            if outcome.executed:
                out.append(WalkStep(step_id, WALK_COMPLETED))
            else:
                out.append(WalkStep(step_id, WALK_NOT_WALKED, "reused_earlier_proof"))
            continue
        broken = True
        if outcome.outcome == OUTCOME_SAFETY_BLOCKED:
            out.append(WalkStep(step_id, WALK_STOPPED, "not_run"))
        elif removed and _principal_token(getattr(outcome, "from_label", "")) in removed:
            out.append(WalkStep(step_id, WALK_STOPPED, "credential_removed"))
        elif outcome.outcome == OUTCOME_SKIPPED:
            out.append(WalkStep(step_id, WALK_STOPPED, "not_run"))
        elif str(outcome.explanation.get("code") or "") in CREDENTIAL_REFUSED_CODES:
            out.append(WalkStep(step_id, WALK_STOPPED, "credential_invalid"))
        else:
            out.append(WalkStep(step_id, WALK_STOPPED, "unknown"))
    return out


def execute_summary(shell: Any, domain: str, summary: dict[str, Any]) -> list[Any]:
    """Run one summary through the ``attack_paths`` loop; return step outcomes.

    Returns the :class:`StepOutcome` list of the run (empty when the loop did
    not start one: the scan policy, the readiness gate or the operator declined).
    """
    from adscan_internal.cli.attack_path_execution import (  # noqa: PLC0415
        offer_attack_paths_for_execution_summaries,
    )
    from adscan_internal.services.attack_path_execution_run import (  # noqa: PLC0415
        add_run_finished_listener,
        remove_run_finished_listener,
    )

    captured: list[Any] = []

    def _listener(run: Any, _summary: dict[str, Any]) -> None:
        if not captured:
            captured.extend(run.step_outcomes())

    add_run_finished_listener(shell, _listener)
    try:
        offer_attack_paths_for_execution_summaries(
            shell,
            domain,
            summaries=[summary],
            max_display=1,
            execute_only_statuses=set(WALKABLE_STATUSES),
            retry_attempted=True,
            reexecute_exploited_default=True,
        )
    finally:
        remove_run_finished_listener(shell, _listener)
    return captured


__all__ = (
    "CREDENTIAL_REFUSED_CODES",
    "ResolvedPath",
    "canonical_paths",
    "execute_summary",
    "find_path",
    "find_step_summary",
    "ledger_step_ids",
    "one_step_summary",
    "path_id_of",
    "path_step_item_ids",
    "walk_steps_from_outcomes",
)
