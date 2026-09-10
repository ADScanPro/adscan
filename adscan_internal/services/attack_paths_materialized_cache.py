from __future__ import annotations

import hashlib
import json
import os
from importlib import import_module
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from adscan_internal.rich_output import mark_sensitive, print_info_debug
from adscan_internal.workspaces import domain_subpath

try:
    pa = import_module("pyarrow")
    pq = import_module("pyarrow.parquet")
except Exception:  # pragma: no cover - optional dependency fallback
    pa = None
    pq = None


def _env_flag(name: str, default: bool) -> bool:
    """Return a boolean env toggle, best-effort."""
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, *, minimum: int = 1) -> int:
    """Return an int env value clamped to a minimum, best-effort."""
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return max(minimum, int(raw.strip()))
    except (TypeError, ValueError):
        return default


# L2 disk RESULT cache — persists the FINAL attack-path record set so a cold-start
# process (one-shot ``adscan ci`` / ``adscan execute`` reopening a workspace)
# reuses a prior run's path set instead of recomputing the full DFS +
# postprocessing. Local disk only — never gated by ``ADSCAN_OFFLINE``.
DISK_RESULT_CACHE_ENABLED = _env_flag(
    "ADSCAN_ATTACK_PATHS_DISK_RESULT_CACHE_ENABLED", True
)
# File-count LRU backstop (Guard 1's active-unlink-on-save is the primary hygiene;
# this bounds litter from stale files a key change left behind without a
# ``save_attack_graph`` unlink in this process).
DISK_RESULT_CACHE_MAX_FILES = _env_int(
    "ADSCAN_ATTACK_PATHS_DISK_RESULT_CACHE_MAX_FILES", 200
)


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


# --- L2 disk RESULT cache (final path set) ---------------------------------
#
# The disk sidecar persists the FINAL ``list[dict]`` record set that the L1
# in-memory LRU stores, keyed by the SAME cache key L1 uses
# (``_attack_paths_cache_base_key`` output). The filename is a hash of that key,
# which already carries the shared graph epoch (mtime OR structural, per
# ``attack_paths_epoch_fingerprint``) + the full query ``params`` tuple, so the
# disk layer inherits L1's never-stale contract for free: any topology change
# moves the epoch -> new key -> new hash -> the old file is unreachable. There is
# NO new correctness reasoning here; the key IS the correctness.


def attack_path_results_key_hash(cache_key: tuple[Any, ...]) -> str:
    """Return the disk filename hash for an attack-path L1 cache key.

    The hash is ``sha256(canonical_json(cache_key))[:32]``. The key tuple carries
    the shared graph epoch + the full query params (scope, target, depth,
    force_perterminal, ...), so two DIFFERENT queries (or a topology change that
    moved the epoch) hash to DIFFERENT files and can never cross-serve. Tuples in
    the key serialize as JSON lists deterministically; we only hash the key, never
    read it back, so the tuple/list distinction is irrelevant.
    """
    canonical = json.dumps(
        cache_key, sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


def _attack_path_results_dir(shell: object, domain: str) -> Path:
    """Return the per-domain disk results directory (created lazily on write)."""
    return attack_path_cache_dir(shell, domain) / "results"


def _attack_path_results_file(shell: object, domain: str, key_hash: str) -> Path:
    """Return the sidecar path for a given key hash."""
    return _attack_path_results_dir(shell, domain) / f"{key_hash}.json"


def load_disk_cached_attack_path_results(
    *,
    shell: object,
    domain: str,
    cache_key: tuple[Any, ...],
) -> list[dict[str, Any]] | None:
    """Load a disk-cached attack-path record set for a key, or None.

    Best-effort: any read/parse error returns None (fall back to compute), never
    raises, never serves a partial/stale set. The filename is the epoch-bearing
    key hash, so a match is provably for THIS exact graph state + query.
    """
    if not DISK_RESULT_CACHE_ENABLED:
        return None
    key_hash = attack_path_results_key_hash(cache_key)
    path = _attack_path_results_file(shell, domain, key_hash)
    try:
        if not path.exists():
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None
    records = payload.get("records")
    if not isinstance(records, list):
        return None
    # Refresh the file mtime so the LRU backstop treats a served entry as recent.
    try:
        os.utime(path, None)
    except OSError:
        pass
    print_info_debug(
        f"[attack_paths] disk result cache hit: domain={mark_sensitive(domain, 'domain')} "
        f"records={len(records)}"
    )
    return records


def _epoch_token(epoch: tuple[Any, ...] | None) -> str:
    """Canonical string form of an epoch tuple for the sidecar stamp (or "")."""
    if epoch is None:
        return ""
    try:
        return json.dumps(list(epoch), separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        return str(epoch)


def persist_attack_path_results_to_disk(
    *,
    shell: object,
    domain: str,
    cache_key: tuple[Any, ...],
    records: list[dict[str, Any]],
    epoch: tuple[Any, ...] | None = None,
) -> bool:
    """Write an attack-path record set to the disk sidecar. Returns True on write.

    The current graph ``epoch`` (the shared ``attack_paths_epoch_fingerprint``
    output) is stamped into the payload so Guard 1's active unlink can delete ONLY
    files written under a DIFFERENT epoch — which is what preserves the structural
    epoch's warm-serve on a status-only write (same epoch -> the file survives the
    save, gets served, and its status is re-derived).

    Best-effort: any write error returns False (the in-memory result is still
    served), never raises. The caller is responsible for the byte-budget / win
    gates — this only serializes. UTF-8 JSON, so it is byte-identical across
    Linux/macOS/Windows.
    """
    if not DISK_RESULT_CACHE_ENABLED:
        return False
    key_hash = attack_path_results_key_hash(cache_key)
    results_dir = _attack_path_results_dir(shell, domain)
    path = results_dir / f"{key_hash}.json"
    try:
        results_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "key_hash": key_hash,
            "domain": domain,
            "epoch": _epoch_token(epoch),
            "records": records,
        }
        path.write_text(
            json.dumps(payload, separators=(",", ":")),
            encoding="utf-8",
        )
    except (OSError, TypeError, ValueError):
        return False
    _prune_attack_path_results_dir(shell, domain)
    print_info_debug(
        f"[attack_paths] disk result cache store: domain={mark_sensitive(domain, 'domain')} "
        f"records={len(records)}"
    )
    return True


def unlink_attack_path_results_for_domain(
    shell: object, domain: str, *, current_epoch: tuple[Any, ...] | None = None
) -> int:
    """Actively delete STALE disk result sidecars for a domain (Guard 1).

    Called from ``save_attack_graph``. A file whose stamped epoch differs from
    ``current_epoch`` is stale (a topology change moved the epoch) and is deleted.
    A file stamped with the CURRENT epoch is kept — this is what preserves the
    structural epoch's warm-serve across a status-only write (the epoch is
    unchanged, so the file is not deleted and can be served with a re-derived
    status). When ``current_epoch`` is None (defensive / unknown), ALL files are
    deleted — the safe direction (never serve a possibly-stale set). Best-effort:
    returns the count deleted, never raises.
    """
    results_dir = _attack_path_results_dir(shell, domain)
    current = _epoch_token(current_epoch) if current_epoch is not None else None
    removed = 0
    try:
        if not results_dir.exists():
            return 0
        for path in results_dir.iterdir():
            if not path.is_file() or path.suffix != ".json":
                continue
            if current is not None and _sidecar_epoch(path) == current:
                # Same epoch -> not stale. Keep it (structural warm-serve).
                continue
            try:
                path.unlink()
                removed += 1
            except OSError:
                continue
    except OSError:
        return removed
    return removed


def _sidecar_epoch(path: Path) -> str | None:
    """Read the stamped epoch from a sidecar, or None on any error."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    if isinstance(payload, dict):
        return str(payload.get("epoch") or "")
    return None


def _prune_attack_path_results_dir(shell: object, domain: str) -> None:
    """Bound the results dir to ``DISK_RESULT_CACHE_MAX_FILES`` (LRU by mtime).

    Best-effort backstop for litter that Guard 1's active-unlink did not catch
    (a key that changed within a process without a ``save_attack_graph``). Deletes
    the oldest files by mtime until the count is within budget. Never raises.
    """
    results_dir = _attack_path_results_dir(shell, domain)
    try:
        files = [p for p in results_dir.iterdir() if p.is_file() and p.suffix == ".json"]
    except OSError:
        return
    if len(files) <= DISK_RESULT_CACHE_MAX_FILES:
        return
    try:
        files.sort(key=lambda p: p.stat().st_mtime)
    except OSError:
        return
    for path in files[: len(files) - DISK_RESULT_CACHE_MAX_FILES]:
        try:
            path.unlink()
        except OSError:
            continue
