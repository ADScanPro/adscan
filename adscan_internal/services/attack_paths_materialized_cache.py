from __future__ import annotations

import json
import os
from importlib import import_module
from dataclasses import dataclass
from pathlib import Path
from adscan_internal.rich_output import mark_sensitive, print_info_debug
from adscan_internal.workspaces import domain_subpath

try:
    pa = import_module("pyarrow")
    pq = import_module("pyarrow.parquet")
except Exception:  # pragma: no cover - optional dependency fallback
    pa = None
    pq = None


@dataclass(slots=True)
class MaterializedAttackPathArtifacts:
    """Derived graph/snapshot artifacts reused across attack-path computations."""

    fingerprint: str
    node_id_by_label: dict[str, str]
    recursive_groups_by_principal: dict[str, tuple[str, ...]]
    storage_format: str


@dataclass(slots=True)
class MaterializedPreparedRuntimeGraph:
    """Prepared runtime graph reused across attack-path computations."""

    fingerprint: str
    graph: dict[str, object]
    storage_format: str


def _file_token(path: str) -> tuple[int | None, int | None]:
    """Return `(mtime_ns, size)` for *path* when available."""
    try:
        stat = os.stat(path)
    except OSError:
        return (None, None)
    return (int(getattr(stat, "st_mtime_ns", 0) or 0), int(stat.st_size))


def build_attack_path_artifact_fingerprint(
    *,
    graph_path: str,
    snapshot_path: str | None,
    schema_version: str,
) -> str:
    """Build a stable fingerprint for materialized attack-path artifacts."""
    graph_token = _file_token(graph_path)
    snapshot_token = _file_token(snapshot_path or "")
    raw = json.dumps(
        {
            "schema_version": schema_version,
            "graph": graph_token,
            "snapshot": snapshot_token,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    import hashlib

    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def attack_path_cache_dir(shell: object, domain: str) -> Path:
    """Return the per-domain attack-path cache directory."""
    workspace_cwd = getattr(shell, "current_workspace_dir", "") or os.getcwd()
    domains_dir = getattr(shell, "domains_dir", "domains")
    return Path(domain_subpath(workspace_cwd, domains_dir, domain, ".attack_paths_cache"))


def artifact_metadata_path(shell: object, domain: str) -> Path:
    """Return the JSON metadata path for a domain cache directory."""
    return attack_path_cache_dir(shell, domain) / "artifacts_meta.json"


def prepared_runtime_graph_metadata_path(shell: object, domain: str) -> Path:
    """Return the metadata path for the prepared runtime graph cache."""
    return attack_path_cache_dir(shell, domain) / "runtime_graph_meta.json"


def invalidate_attack_path_artifacts(shell: object, domain: str) -> None:
    """Best-effort delete of materialized attack-path artifacts for a domain."""
    cache_dir = attack_path_cache_dir(shell, domain)
    if not cache_dir.exists():
        return
    for path in cache_dir.iterdir():
        try:
            if path.is_file():
                path.unlink()
        except OSError:
            continue
    try:
        cache_dir.rmdir()
    except OSError:
        pass


def load_materialized_attack_path_artifacts(
    *,
    shell: object,
    domain: str,
    fingerprint: str,
) -> MaterializedAttackPathArtifacts | None:
    """Load cached derived artifacts when the fingerprint matches."""
    cache_dir = attack_path_cache_dir(shell, domain)
    meta_path = artifact_metadata_path(shell, domain)
    if not cache_dir.exists() or not meta_path.exists():
        return None
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(meta, dict) or str(meta.get("fingerprint") or "") != fingerprint:
        return None

    storage_format = str(meta.get("storage_format") or "json").strip().lower()
    if storage_format == "parquet" and pa is not None and pq is not None:
        node_path = cache_dir / "node_index.parquet"
        groups_path = cache_dir / "recursive_memberships.parquet"
        if not node_path.exists() or not groups_path.exists():
            return None
        try:
            node_table = pq.read_table(node_path)
            groups_table = pq.read_table(groups_path)
        except Exception:
            return None
        node_rows = node_table.to_pylist()
        group_rows = groups_table.to_pylist()
    else:
        node_path = cache_dir / "node_index.json"
        groups_path = cache_dir / "recursive_memberships.json"
        if not node_path.exists() or not groups_path.exists():
            return None
        try:
            node_rows = json.loads(node_path.read_text(encoding="utf-8"))
            group_rows = json.loads(groups_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return None

    node_id_by_label: dict[str, str] = {}
    for row in node_rows or []:
        if not isinstance(row, dict):
            continue
        label = str(row.get("canonical_label") or "").strip()
        node_id = str(row.get("node_id") or "").strip()
        if label and node_id:
            node_id_by_label[label] = node_id

    recursive_groups_by_principal: dict[str, list[str]] = {}
    for row in group_rows or []:
        if not isinstance(row, dict):
            continue
        principal = str(row.get("principal_label") or "").strip()
        group_label = str(row.get("group_label") or "").strip()
        if not principal or not group_label:
            continue
        recursive_groups_by_principal.setdefault(principal, []).append(group_label)

    return MaterializedAttackPathArtifacts(
        fingerprint=fingerprint,
        node_id_by_label=node_id_by_label,
        recursive_groups_by_principal={
            principal: tuple(groups)
            for principal, groups in recursive_groups_by_principal.items()
        },
        storage_format=storage_format,
    )


def load_materialized_prepared_runtime_graph(
    *,
    shell: object,
    domain: str,
    fingerprint: str,
) -> MaterializedPreparedRuntimeGraph | None:
    """Load a prepared runtime graph when the fingerprint matches."""
    cache_dir = attack_path_cache_dir(shell, domain)
    meta_path = prepared_runtime_graph_metadata_path(shell, domain)
    if not cache_dir.exists() or not meta_path.exists():
        return None
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(meta, dict) or str(meta.get("fingerprint") or "") != fingerprint:
        return None

    storage_format = str(meta.get("storage_format") or "json").strip().lower()
    if storage_format == "parquet" and pa is not None and pq is not None:
        nodes_path = cache_dir / "runtime_graph_nodes.parquet"
        edges_path = cache_dir / "runtime_graph_edges.parquet"
        if not nodes_path.exists() or not edges_path.exists():
            return None
        try:
            node_rows = pq.read_table(nodes_path).to_pylist()
            edge_rows = pq.read_table(edges_path).to_pylist()
        except Exception:
            return None
        graph = {
            "nodes": {
                str(row.get("node_id") or ""): json.loads(str(row.get("node_json") or "{}"))
                for row in node_rows
                if str(row.get("node_id") or "").strip()
            },
            "edges": [json.loads(str(row.get("edge_json") or "{}")) for row in edge_rows],
            "_attack_paths_terminal_memberships_materialized": True,
        }
    else:
        graph_path = cache_dir / "runtime_graph.json"
        if not graph_path.exists():
            return None
        try:
            graph = json.loads(graph_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return None
        if not isinstance(graph, dict):
            return None
    return MaterializedPreparedRuntimeGraph(
        fingerprint=fingerprint,
        graph=graph,
        storage_format=storage_format,
    )


def persist_materialized_attack_path_artifacts(
    *,
    shell: object,
    domain: str,
    artifacts: MaterializedAttackPathArtifacts,
) -> None:
    """Persist derived artifacts to disk using Parquet when available."""
    cache_dir = attack_path_cache_dir(shell, domain)
    cache_dir.mkdir(parents=True, exist_ok=True)

    node_rows = [
        {"canonical_label": label, "node_id": node_id}
        for label, node_id in sorted(artifacts.node_id_by_label.items())
    ]
    group_rows = [
        {"principal_label": principal, "group_label": group_label}
        for principal, groups in sorted(artifacts.recursive_groups_by_principal.items())
        for group_label in groups
    ]

    storage_format = "json"
    if pa is not None and pq is not None:
        node_table = pa.Table.from_pylist(
            node_rows,
            schema=pa.schema(
                [
                    ("canonical_label", pa.string()),
                    ("node_id", pa.string()),
                ]
            ),
        )
        group_table = pa.Table.from_pylist(
            group_rows,
            schema=pa.schema(
                [
                    ("principal_label", pa.string()),
                    ("group_label", pa.string()),
                ]
            ),
        )
        pq.write_table(node_table, cache_dir / "node_index.parquet")
        pq.write_table(
            group_table,
            cache_dir / "recursive_memberships.parquet",
        )
        storage_format = "parquet"
    else:
        (cache_dir / "node_index.json").write_text(
            json.dumps(node_rows, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        (cache_dir / "recursive_memberships.json").write_text(
            json.dumps(group_rows, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    meta = {
        "fingerprint": artifacts.fingerprint,
        "storage_format": storage_format,
        "domain": domain,
    }
    artifact_metadata_path(shell, domain).write_text(
        json.dumps(meta, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    print_info_debug(
        f"[attack_paths] materialized artifacts stored: domain={mark_sensitive(domain, 'domain')} "
        f"format={storage_format} principals={len(artifacts.recursive_groups_by_principal)} "
        f"nodes={len(artifacts.node_id_by_label)}"
    )


def persist_materialized_prepared_runtime_graph(
    *,
    shell: object,
    domain: str,
    prepared_graph: MaterializedPreparedRuntimeGraph,
) -> None:
    """Persist a prepared runtime graph using Parquet when available."""
    cache_dir = attack_path_cache_dir(shell, domain)
    cache_dir.mkdir(parents=True, exist_ok=True)

    graph = dict(prepared_graph.graph)
    graph["_attack_paths_terminal_memberships_materialized"] = True
    storage_format = "json"
    if pa is not None and pq is not None:
        nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
        edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
        node_rows = [
            {"node_id": str(node_id), "node_json": json.dumps(node, sort_keys=True)}
            for node_id, node in sorted(nodes.items())
            if isinstance(node, dict)
        ]
        edge_rows = [
            {"edge_json": json.dumps(edge, sort_keys=True)}
            for edge in edges
            if isinstance(edge, dict)
        ]
        pq.write_table(
            pa.Table.from_pylist(
                node_rows,
                schema=pa.schema([("node_id", pa.string()), ("node_json", pa.string())]),
            ),
            cache_dir / "runtime_graph_nodes.parquet",
        )
        pq.write_table(
            pa.Table.from_pylist(
                edge_rows,
                schema=pa.schema([("edge_json", pa.string())]),
            ),
            cache_dir / "runtime_graph_edges.parquet",
        )
        storage_format = "parquet"
    else:
        (cache_dir / "runtime_graph.json").write_text(
            json.dumps(graph, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    prepared_runtime_graph_metadata_path(shell, domain).write_text(
        json.dumps(
            {
                "fingerprint": prepared_graph.fingerprint,
                "storage_format": storage_format,
                "domain": domain,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    print_info_debug(
        f"[attack_paths] prepared runtime graph stored: domain={mark_sensitive(domain, 'domain')} "
        f"format={storage_format}"
    )
