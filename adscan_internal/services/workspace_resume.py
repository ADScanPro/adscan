"""Workspace resume — premium UX for re-entering an existing scan workspace.

When a pentester re-runs ``adscan enum`` against a domain whose workspace already
holds Phase 1 results, ADscan must let them choose between four orthogonal
intents instead of silently reusing cached data:

    Resume    — keep the existing graph, continue with the analysis pipeline.
                Cheapest. Default for the common "I just want to keep going" case.
    Refresh   — re-collect the graph from AD (slow), then re-run analysis.
                Used when the operator wants to capture environment changes
                or after a credential upgrade.
    Replay    — keep the graph, re-run analysis only. Fast.
                Used when ADscan itself was upgraded (new attack rules) but the
                AD environment has not changed.
    Inspect   — open the workspace shell without running anything.
                Used when the operator wants to read previous output before
                deciding what to do.

The previous UX silently skipped the graph collector when ``phase1_complete``
was set and offered a single confusing yes/no prompt to "re-run Phase 1" that
in practice only re-ran the analysis steps. That made "Refresh" impossible
without manual workspace surgery and trained pentesters not to trust the
prompt. This module fixes that by surfacing the four intents explicitly, with
a single rich panel that summarises what already exists in the workspace.

The chosen action is also mirrored to the structured event sink
(``stderr-json``) so the ADscan web service can surface it on the run dashboard.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


class WorkspaceAction(str, Enum):
    """Operator intent when re-entering a workspace with prior results."""

    RESUME = "resume"
    REFRESH = "refresh"
    REPLAY = "replay"
    INSPECT = "inspect"


@dataclass(frozen=True)
class WorkspaceSnapshot:
    """Read-only view of what already exists in a domain workspace.

    Populated from filesystem artefacts (no AD access). Drives the rendered
    summary so the operator sees the cost of each action up front.
    """

    domain: str
    workspace_dir: str
    has_attack_graph: bool
    node_count: int
    edge_count: int
    last_collection_at: str | None  # ISO-8601 UTC, when attack_graph.json was last written
    last_collection_age_human: str  # "3h ago", "5d ago", "just now"
    phase1_complete: bool
    has_attack_paths: bool
    credential_count: int
    last_run_at: str | None  # ISO-8601 UTC of last run (mtime of newest artefact)
    domain_auth: str  # "unauth" | "auth" | "pwned"


# ---------------------------------------------------------------------------
# Inspection — read filesystem artefacts to build a WorkspaceSnapshot
# ---------------------------------------------------------------------------


def inspect_workspace(shell: Any, domain: str) -> WorkspaceSnapshot:
    """Build a read-only snapshot of the workspace state for ``domain``.

    Pure filesystem read. Never raises — if a file is missing or unreadable
    the corresponding field is reported as "absent" / 0 / None.
    """
    from adscan_internal.workspaces import domain_subpath

    workspace_dir = shell.current_workspace_dir or os.getcwd()
    domains_dir = getattr(shell, "domains_dir", "domains")

    graph_path = Path(domain_subpath(workspace_dir, domains_dir, domain, "attack_graph.json"))
    paths_path = Path(domain_subpath(workspace_dir, domains_dir, domain, "attack_paths.json"))
    creds_path = Path(domain_subpath(workspace_dir, domains_dir, domain, "credentials.json"))

    node_count, edge_count = _count_graph_size(graph_path)
    has_attack_graph = graph_path.is_file() and node_count > 0
    last_collection_at = _file_mtime_iso(graph_path) if has_attack_graph else None
    last_collection_age_human = (
        _humanize_age(graph_path.stat().st_mtime) if has_attack_graph else "never"
    )
    has_attack_paths = paths_path.is_file() and paths_path.stat().st_size > 16
    credential_count = _count_credentials(creds_path)
    phase1_complete = bool(
        getattr(shell, "domains_data", {}).get(domain, {}).get("phase1_complete")
    )
    graph_is_entry_vectors_only = _is_entry_vectors_only_graph(graph_path)

    last_run_at = _newest_artefact_iso(
        [graph_path, paths_path, creds_path],
        Path(domain_subpath(workspace_dir, domains_dir, domain, "enabled_computers.txt")),
        Path(domain_subpath(workspace_dir, domains_dir, domain, "enabled_users.txt")),
    )

    return WorkspaceSnapshot(
        domain=domain,
        workspace_dir=workspace_dir,
        has_attack_graph=has_attack_graph,
        node_count=node_count,
        edge_count=edge_count,
        last_collection_at=last_collection_at,
        last_collection_age_human=last_collection_age_human,
        phase1_complete=phase1_complete,
        has_attack_paths=has_attack_paths,
        credential_count=credential_count,
        last_run_at=last_run_at,
        domain_auth="unauth" if graph_is_entry_vectors_only else "auth",
    )


def _count_graph_size(graph_path: Path) -> tuple[int, int]:
    """Return ``(node_count, edge_count)`` from ``attack_graph.json`` or ``(0, 0)``.

    Streamed (``graph_compact.count_graph_file``): opening a workspace never
    parses a whole format-2 export just to count it.
    """
    from adscan_core.graph_compact import count_graph_file  # noqa: PLC0415

    if not graph_path.is_file():
        return (0, 0)
    try:
        return count_graph_file(graph_path)
    except (OSError, ValueError):
        return (0, 0)


def _is_entry_vectors_only_graph(graph_path: Path) -> bool:
    """Return True when every node in the graph is synthetic (unauth entry-vectors only).

    A graph produced by an authenticated LDAP/BloodHound collection has at least one
    node with a real objectId (SID). A graph that only records unauthenticated entry
    vectors (ASREPRoasting, anonymous bind) contains exclusively synthetic fallback
    nodes — those have ``properties.synthetic == true`` and ``objectId == null``.
    """
    if not graph_path.is_file():
        return False
    try:
        data = json.loads(graph_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    nodes = data.get("nodes")
    if not nodes:
        return False
    if isinstance(nodes, dict):
        node_iter = nodes.values()
    elif isinstance(nodes, list):
        node_iter = nodes
    else:
        return False
    return all(
        node.get("properties", {}).get("synthetic") is True
        for node in node_iter
    )


def _count_credentials(creds_path: Path) -> int:
    """Best-effort credential count from ``credentials.json``; 0 on any error."""
    if not creds_path.is_file():
        return 0
    try:
        data = json.loads(creds_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 0
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        creds = data.get("credentials")
        if isinstance(creds, list):
            return len(creds)
    return 0


def _file_mtime_iso(path: Path) -> str | None:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()
    except OSError:
        return None


def _newest_artefact_iso(*paths: Path | list[Path]) -> str | None:
    """Return ISO-8601 UTC of the newest artefact's mtime across ``paths``."""
    flat: list[Path] = []
    for entry in paths:
        if isinstance(entry, list):
            flat.extend(entry)
        else:
            flat.append(entry)
    newest: float | None = None
    for path in flat:
        if not path.is_file():
            continue
        try:
            mtime = path.stat().st_mtime
        except OSError:
            continue
        if newest is None or mtime > newest:
            newest = mtime
    if newest is None:
        return None
    return datetime.fromtimestamp(newest, tz=timezone.utc).isoformat()


def _humanize_age(mtime: float) -> str:
    """Render a friendly ``5m ago`` / ``3h ago`` / ``2d ago`` from a unix mtime."""
    delta = max(0.0, time.time() - mtime)
    if delta < 60:
        return "just now"
    if delta < 3600:
        return f"{int(delta // 60)}m ago"
    if delta < 86400:
        return f"{int(delta // 3600)}h ago"
    days = int(delta // 86400)
    return f"{days}d ago" if days < 30 else f"{days // 30}mo ago"
