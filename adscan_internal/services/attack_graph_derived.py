"""Insert ``derived`` edges into the attack graph after a confirmed exploit.

A *derived* edge represents the result of a post-exploitation technique
that yielded credential material proving control over another principal.
Examples:

* ``DumpedHashOf`` — LSASS / NTDS / SAM dump that recovered the NT hash
  of a target principal.
* ``ForgedTicketFor`` — Golden / Silver ticket forged for a target.
* ``ReadGMSAPasswordOf`` — gMSA password material extracted on-host.
* ``OwnsCertificateFor`` — authentication certificate obtained for a
  principal.

These edges are *not* discovered by enumeration; they are created
**after the fact** by the post-exploitation orchestrator when it has
proof. The downstream attack-graph and materializer treat them as
canonical control edges (``EdgeKind.DERIVED``) so the next attack-path
recomputation lifts the freshly-compromised principal into Tier 0
reachability whenever appropriate.

Design notes:

* This module never mutates the live in-memory graph object — it writes
  to ``domains/<domain>/attack_graph.json`` so subsequent runs of the
  materializer (or its cache invalidator) pick the change up
  deterministically.
* It is idempotent: re-inserting the same ``(source, relation, target,
  derived_from)`` tuple is a no-op.
* It records an ``evidence`` block (technique id, evidence path, ISO
  timestamp) so reports can render the proof and auditors can trace the
  derivation back to the exploit run that produced it.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from adscan_core import telemetry
from adscan_core.rich_output import print_error, print_info_verbose
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.edge_kind import EdgeKind, classify_edge_kind
from adscan_internal.workspaces import domain_subpath
from adscan_core.rich_output import print_exception


# Allow-list of relations callers may insert. Anything outside this set is
# rejected so a typo in a future technique never silently produces an
# UNKNOWN edge in the canonical graph.
ALLOWED_DERIVED_RELATIONS: frozenset[str] = frozenset(
    {
        "DumpedHashOf",
        "ForgedTicketFor",
        "ReadGMSAPasswordOf",
        "OwnsCertificateFor",
        # Native CVE scanner — coercion techniques confirmed at runtime
        "CoercePetitPotam",
        "CoercePrinterBug",
        "CoerceShadowCoerce",
        "CoerceMSEvenCoerce",
        "CoerceDFSCoerce",
        # Native CVE scanner Slice 2 — DC-pack vulnerabilities confirmed at runtime
        "Zerologon",
        "NoPac",
        "PrintNightmare",
        "BadSuccessor",
        # Native CVE scanner Slice 3 — host-level CVEs and NTLM enablers
        "MS17-010",
        "SMBGhost",
        "PrinterBugSurface",
        "WebDAVEnabled",
        "DropTheMIC",
        "NTLMReflection",
        # NTLMv1 relay surface marker (sub-project #3) — promoted by the
        # ntlmv1_relay_graph_builder when an NTLMv1 host is observed.
        "Ntlmv1Enabled",
    }
)

# Backwards-compatible private alias — this set is the canonical allow-list of
# relations a derived edge may carry, and any catalog whose entry produces a
# derived edge is validated against it at import time (see the CVE catalog).
_ALLOWED_DERIVED_RELATIONS = ALLOWED_DERIVED_RELATIONS


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _attack_graph_path(shell: object, domain: str) -> Path:
    workspace_dir = getattr(shell, "current_workspace_dir", "") or ""
    domains_dir = getattr(shell, "domains_dir", "domains")
    return Path(domain_subpath(workspace_dir, domains_dir, domain, "attack_graph.json"))


def _load_graph(graph_path: Path) -> dict[str, Any]:
    # ``nodes`` defaults to a MAPPING, the shape every persisted attack graph
    # uses (``upsert_nodes`` keys it by node id) and the shape the canonical save
    # path reads when it prunes Tier-0-source edges.
    if not graph_path.exists():
        return {"nodes": {}, "edges": []}
    try:
        data = json.loads(graph_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {"nodes": {}, "edges": []}
    if not isinstance(data, dict):
        return {"nodes": {}, "edges": []}
    data.setdefault("nodes", {})
    data.setdefault("edges", [])
    return data


def _edge_signature(edge: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(edge.get("source") or edge.get("from") or ""),
        str(edge.get("relation") or edge.get("kind_label") or ""),
        str(edge.get("target") or edge.get("to") or ""),
        str(((edge.get("evidence") or {}).get("technique_id")) or ""),
    )


def insert_derived_edge(
    *,
    shell: object,
    domain: str,
    source: str,
    relation: str,
    target: str,
    technique_id: str,
    evidence_path: str | Path | None,
    extra: dict[str, Any] | None = None,
) -> bool:
    """Insert one derived edge into ``domains/<domain>/attack_graph.json``.

    Args:
        shell: The ADscan main shell — used to locate the workspace.
        domain: Target domain (graph file owner).
        source: Source principal label (e.g. ``"DC01.FOREST.LOCAL"``).
        relation: One of the canonical derived relations
            (``DumpedHashOf``, ``ForgedTicketFor``, ``ReadGMSAPasswordOf``,
            ``OwnsCertificateFor``).
        target: Target principal label (the principal whose credential
            material the technique recovered, e.g. ``"krbtgt@FOREST.LOCAL"``
            or ``"Administrator@FOREST.LOCAL"``).
        technique_id: Catalog id of the technique that produced the proof.
        evidence_path: Workspace-relative path to the evidence artifact
            (LSASS dump, secretsdump output, certificate, ...). May be
            ``None`` when the technique stores no on-disk artifact.
        extra: Optional opaque metadata persisted alongside the edge
            (host, credential type, ticket lifetime, ...). Never put
            cleartext secrets here — store them in the evidence file.

    Returns:
        ``True`` when the edge was inserted, ``False`` when the same
        ``(source, relation, target, technique_id)`` tuple already
        existed (idempotent no-op).
    """
    if relation not in _ALLOWED_DERIVED_RELATIONS:
        raise ValueError(
            f"insert_derived_edge: relation {relation!r} is not a canonical "
            f"derived edge. Allowed: {sorted(_ALLOWED_DERIVED_RELATIONS)}"
        )
    # Defensive: classify_edge_kind must agree with the allow-list.
    if classify_edge_kind(relation) is not EdgeKind.DERIVED:
        raise ValueError(
            f"insert_derived_edge: relation {relation!r} is not classified as "
            f"DERIVED in edge_kind.py — refusing to insert."
        )

    source_clean = str(source or "").strip()
    target_clean = str(target or "").strip()
    if not source_clean or not target_clean:
        raise ValueError("insert_derived_edge: source and target must be non-empty")

    graph_path = _attack_graph_path(shell, domain)
    graph_path.parent.mkdir(parents=True, exist_ok=True)
    graph = _load_graph(graph_path)

    new_edge: dict[str, Any] = {
        "source": source_clean,
        "target": target_clean,
        "relation": relation,
        "kind": EdgeKind.DERIVED.value,
        "evidence": {
            "technique_id": str(technique_id or ""),
            "evidence_path": str(evidence_path) if evidence_path is not None else "",
            "recorded_at": _utc_now_iso(),
        },
    }
    if extra:
        new_edge["evidence"]["extra"] = dict(extra)

    new_sig = _edge_signature(new_edge)
    edges_list = graph.get("edges")
    if not isinstance(edges_list, list):
        edges_list = []
        graph["edges"] = edges_list

    for existing in edges_list:
        if isinstance(existing, dict) and _edge_signature(existing) == new_sig:
            print_info_verbose(
                f"[attack_graph_derived] derived edge already present "
                f"({mark_sensitive(source_clean, 'host')} -{relation}-> "
                f"{mark_sensitive(target_clean, 'user')}); no-op"
            )
            return False

    edges_list.append(new_edge)

    # Persist through the canonical seam, never a raw write: it is what stamps
    # ``category`` / ``vuln_key`` onto the new edge (without which the finding
    # derivation cannot see it), invalidates the materialized attack-path
    # artifacts, and syncs technical findings. A raw ``write_text`` here is
    # exactly how noPac and PrintNightmare stayed out of the client's report.
    try:
        from adscan_internal.services.attack_graph_service import (  # noqa: PLC0415
            save_attack_graph,
        )

        save_attack_graph(shell, domain, graph)
    except Exception as exc:  # noqa: BLE001 — telemetry sink
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(f"[attack_graph_derived] failed to write attack_graph.json: {exc}")
        return False

    print_info_verbose(
        f"[attack_graph_derived] inserted derived edge "
        f"{mark_sensitive(source_clean, 'host')} -{relation}-> "
        f"{mark_sensitive(target_clean, 'user')} "
        f"(technique={technique_id})"
    )
    return True


__all__ = ["insert_derived_edge", "ALLOWED_DERIVED_RELATIONS"]
