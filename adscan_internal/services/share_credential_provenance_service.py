"""Helpers to build share-origin credential provenance artifacts.

Centralizes creation of:
- ``source_context`` payloads used by spraying flows.
- ``CredentialSourceStep`` lists used by ``add_credential`` attack-graph recording.
"""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from pathlib import PurePosixPath
from typing import Any

from adscan_core.rich_output import print_exception
from adscan_internal.services.base_service import BaseService

# The collector stamps share-ACL read edges with ``method = "share_acl:<Share>"``
# and records the read-capability proof in ``notes.verification``. A read we
# actually PROVED opening is ``self_mxac``; a read inferred only from parsing the
# share's security descriptor is ``share_acl_only`` (lower confidence). Anything
# that is not a read capability (a write/FullControl record whose verification is
# only an ACL parse) is irrelevant to "who could have READ this leaked file".
_SELF_MXAC = "self_mxac"
_SHARE_ACL_ONLY = "share_acl_only"

# Relation names the share collector uses for share-ACL edges that grant READ.
# FullControl/Change/Write relations also grant read, so they count as read-capable
# sources for provenance purposes.
_READ_CAPABLE_RELATIONS = frozenset(
    {
        "readshare",
        "changeshare",
        "writeshare",
        "fullcontrolshare",
    }
)


class ShareCredentialProvenanceService(BaseService):
    """Build standardized provenance metadata for share-derived credentials."""

    def resolve_share_read_capable_sources(
        self,
        *,
        artifact: str | None = None,
        host: str | None = None,  # noqa: ARG002  (reserved; share name is the join key today)
        share: str | None = None,
        domain: str | None = None,
        shell: object | None = None,
        relationships_path: str | None = None,
    ) -> list[dict[str, str]]:
        """Resolve the measured read-capable principals for a share, keyed by SID.

        Reads the share collector's ``inventory/relationships.json`` and returns
        one entry per principal the collector measured as able to READ the share
        the leaked ``artifact`` came from — the real credential-edge source, not a
        synthetic ``Domain Users`` placeholder.

        Args:
            artifact: The leaked file's UNC path (``\\\\host\\<share>\\...``); the
                ``<share>`` segment is the join key when ``share`` is not given.
            host: Reserved; the join is on the share name today, not the host.
            share: Explicit share name (wins over parsing it from ``artifact``).
            domain: Domain whose inventory to read (for the production path derive).
            shell: Session shell exposing ``current_workspace_dir`` / ``domains_dir``
                — the production source of the inventory path. May be ``None``.
            relationships_path: Direct path to ``relationships.json`` — injected by
                unit tests so the resolver runs without a shell. Wins over the
                shell-derived path.

        Returns:
            A list of ``{"sid", "label", "verification", "method"}`` dicts, one per
            read-capable principal, deduped by SID and preferring ``self_mxac``
            records. Empty when no read-set is available (caller uses the fallback
            ladder). Never returns a record without a SID.
        """
        share_name = str(share or "").strip() or self._share_from_artifact(artifact)
        if not share_name:
            return []

        records = self._load_relationship_records(
            domain=domain, shell=shell, relationships_path=relationships_path
        )
        if not records:
            return []

        share_key = share_name.lower()
        self_mxac: dict[str, dict[str, str]] = {}
        share_acl_only: dict[str, dict[str, str]] = {}
        for record in records:
            if not isinstance(record, dict):
                continue
            relation = str(record.get("relation") or "").strip().lower()
            if relation not in _READ_CAPABLE_RELATIONS:
                continue
            notes = record.get("notes") if isinstance(record.get("notes"), dict) else {}
            if str(notes.get("share_name") or "").strip().lower() != share_key:
                continue
            sid = str(record.get("source_object_id") or "").strip()
            if not sid:
                # Exposure-Validation: never fabricate a principal without a SID.
                continue
            verification = str(notes.get("verification") or "").strip().lower()
            entry = {
                "sid": sid,
                "label": str(record.get("source_name") or "").strip(),
                "verification": verification or _SHARE_ACL_ONLY,
                "method": str(record.get("method") or "").strip(),
            }
            bucket = self_mxac if verification == _SELF_MXAC else share_acl_only
            # Dedupe by SID, preferring the first occurrence within the bucket.
            bucket.setdefault(sid, entry)

        # Prefer proven reads; only fall back to ACL-only reads when nothing proven.
        preferred = self_mxac if self_mxac else share_acl_only
        return list(preferred.values())

    @staticmethod
    def _share_from_artifact(artifact: str | None) -> str:
        """Parse the share name from a ``\\\\host\\<share>\\...`` UNC path."""
        text = str(artifact or "").strip().replace("\\", "/")
        if not text:
            return ""
        # Drop the leading ``//`` of the UNC and split: host / share / rest.
        parts = [segment for segment in PurePosixPath(text).parts if segment not in {"/", "//"}]
        # After normalizing backslashes, an absolute UNC ``//host/share/...`` yields
        # parts like ["//", "host", "share", ...] on POSIX PurePosixPath; guard both.
        cleaned = [segment for segment in text.split("/") if segment]
        if len(cleaned) >= 2:
            return cleaned[1].strip()
        if len(parts) >= 2:
            return parts[1].strip()
        return ""

    def _load_relationship_records(
        self,
        *,
        domain: str | None,
        shell: object | None,
        relationships_path: str | None,
    ) -> list[Any]:
        """Load ``records`` from the inventory ``relationships.json`` (best-effort)."""
        path = str(relationships_path or "").strip()
        if not path and shell is not None:
            path = self._derive_relationships_path(shell, domain)
        if not path or not os.path.isfile(path):
            return []
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
        except Exception as exc:  # noqa: BLE001
            print_exception(exception=exc)
            return []
        if not isinstance(data, dict):
            return []
        records = data.get("records")
        return records if isinstance(records, list) else []

    @staticmethod
    def _derive_relationships_path(shell: object, domain: str | None) -> str:
        """Derive ``domains/<domain>/inventory/relationships.json`` from the shell."""
        domain_text = str(domain or "").strip()
        if not domain_text:
            return ""
        try:
            from adscan_internal.workspaces import domain_subpath

            workspace_cwd = (
                shell._get_workspace_cwd()  # noqa: SLF001
                if hasattr(shell, "_get_workspace_cwd")
                else getattr(shell, "current_workspace_dir", "")
            )
            domains_dir = getattr(shell, "domains_dir", "domains")
            inventory_dir = domain_subpath(workspace_cwd, domains_dir, domain_text, "inventory")
            return os.path.join(inventory_dir, "relationships.json")
        except Exception as exc:  # noqa: BLE001
            print_exception(exception=exc)
            return ""

    def build_source_context(
        self,
        *,
        hosts: Sequence[str] | None = None,
        shares: Sequence[str] | None = None,
        artifact: str | None = None,
        auth_username: str | None = None,
        origin: str = "share_spidering",
        access_vector: str | None = None,
        include_origin_without_fields: bool = True,
    ) -> dict[str, object] | None:
        """Build a normalized source_context dictionary for spraying flows."""
        host_values = self._normalize_values(hosts)
        share_values = self._normalize_values(shares)
        artifact_text = str(artifact or "").strip()
        auth_text = str(auth_username or "").strip()
        context: dict[str, object] = {}

        if host_values:
            context["hosts"] = host_values
        if share_values:
            context["shares"] = share_values
        if artifact_text:
            context["artifact"] = artifact_text
            artifact_kind = self._infer_artifact_kind(artifact_text)
            if artifact_kind != "unknown":
                context["artifact_kind"] = artifact_kind
        if auth_text:
            context["auth_username"] = auth_text
        access_vector_text = str(access_vector or "").strip()
        if access_vector_text:
            context["access_vector"] = access_vector_text
        if origin and (include_origin_without_fields or context):
            context["origin"] = origin
        return context or None

    def build_credential_source_steps(
        self,
        *,
        relation: str,
        edge_type: str,
        source: str,
        secret: str | None = None,
        hosts: Sequence[str] | None = None,
        shares: Sequence[str] | None = None,
        artifact: str | None = None,
        auth_username: str | None = None,
        origin: str = "share_spidering",
        share: str | None = None,
        perspective: str | None = None,
        domain: str | None = None,
        shell: object | None = None,
        relationships_path: str | None = None,
    ) -> list[object]:
        """Build ``CredentialSourceStep``s for a share-derived credential.

        When the share collector measured a read-capable set for the share the
        credential came from, emit ONE step per read-capable principal (keyed by
        its SID in ``notes["source_sid"]`` so the recorder can fuse a well-known
        SID onto its shared node). When no read-set is available, fall back to a
        single step using the honest entry-label ladder (never ``Domain Users``).
        """
        relation_text = str(relation or "").strip()
        edge_type_text = str(edge_type or "").strip()
        source_text = str(source or "").strip()
        if not relation_text or not edge_type_text:
            return []

        try:
            from adscan_internal.services.attack_graph_service import (
                CredentialSourceStep,
                resolve_entry_label_for_auth,
            )
        except Exception:  # noqa: BLE001
            return []

        host_values = self._normalize_values(hosts)
        share_values = self._normalize_values(shares)
        artifact_text = str(artifact or "").strip()
        auth_text = str(auth_username or "").strip()
        secret_text = str(secret or "").strip()
        notes: dict[str, Any] = {}
        if source_text:
            notes["source"] = source_text
        if origin:
            notes["origin"] = origin
        if artifact_text:
            notes["artifact"] = artifact_text
            artifact_kind = self._infer_artifact_kind(artifact_text)
            if artifact_kind != "unknown":
                notes["artifact_kind"] = artifact_kind
        if host_values:
            notes["hosts"] = ", ".join(host_values)
            notes["hosts_list"] = host_values
        if share_values:
            notes["shares"] = ", ".join(share_values)
            notes["shares_list"] = share_values
        if auth_text:
            notes["auth_username"] = auth_text
        if secret_text:
            notes["secret"] = secret_text

        sources = self.resolve_share_read_capable_sources(
            artifact=artifact or (share_values[0] if share_values else None),
            share=share or (share_values[0] if share_values else None),
            domain=domain,
            shell=shell,
            relationships_path=relationships_path,
        )
        if sources:
            return [
                CredentialSourceStep(
                    relation=relation_text,
                    edge_type=edge_type_text,
                    entry_label=src["label"] or src["sid"],
                    entry_kind="group",
                    notes={
                        **notes,
                        "source_sid": src["sid"],
                        "verification": src["verification"],
                        "method": src["method"],
                    },
                )
                for src in sources
            ]

        entry_label = resolve_entry_label_for_auth(auth_text, perspective=perspective)
        return [
            CredentialSourceStep(
                relation=relation_text,
                edge_type=edge_type_text,
                entry_label=entry_label,
                notes=notes,
            )
        ]

    def build_share_password_edge_payload(
        self,
        *,
        source_context: dict[str, object] | None,
        spray_type: str | None = None,
        secret: str | None = None,
        verified_via: str = "spraying",
        perspective: str | None = None,
        domain: str | None = None,
        shell: object | None = None,
        relationships_path: str | None = None,
    ) -> tuple[str, dict[str, object]] | None:
        """Build ``(entry_label, notes)`` for ``PasswordInShare`` edge upserts.

        Resolves the edge source from the measured read-capable set when the share
        collector observed one (threading the winning SID into ``notes``), else
        falls back to the honest entry-label ladder. ``Domain Users`` is never a
        fallback.
        """
        if not isinstance(source_context, dict):
            return None
        origin = str(source_context.get("origin") or "").strip().lower()
        if origin != "share_spidering":
            return None

        auth_text = str(source_context.get("auth_username") or "").strip()
        artifact_text = str(source_context.get("artifact") or "").strip()
        share_values = self._normalize_context_values(source_context.get("shares"))
        source_sid = ""
        verification = ""
        method = ""
        sources = self.resolve_share_read_capable_sources(
            artifact=artifact_text or (share_values[0] if share_values else None),
            share=share_values[0] if share_values else None,
            domain=domain,
            shell=shell,
            relationships_path=relationships_path,
        )
        if sources:
            winner = sources[0]
            entry_label = winner["label"] or winner["sid"]
            source_sid = winner["sid"]
            verification = winner["verification"]
            method = winner["method"]
        else:
            try:
                from adscan_internal.services.attack_graph_service import (
                    resolve_entry_label_for_auth,
                )

                entry_label = resolve_entry_label_for_auth(auth_text, perspective=perspective)
            except Exception:  # noqa: BLE001
                # The ladder's own authenticated default, never Domain Users.
                entry_label = "Authenticated Users"

        notes: dict[str, object] = {
            "verified_via": str(verified_via or "spraying"),
            "origin": "share_spidering",
        }
        if source_sid:
            notes["source_sid"] = source_sid
        if verification:
            notes["verification"] = verification
        if method:
            notes["method"] = method
        spray_type_text = str(spray_type or "").strip()
        if spray_type_text:
            notes["spray_type"] = spray_type_text
        artifact_kind = str(source_context.get("artifact_kind") or "").strip().lower()
        if not artifact_kind and artifact_text:
            artifact_kind = self._infer_artifact_kind(artifact_text)
        if artifact_text:
            notes["artifact"] = artifact_text
        if artifact_kind and artifact_kind != "unknown":
            notes["artifact_kind"] = artifact_kind
        secret_text = str(secret or "").strip()
        if secret_text:
            notes["password"] = secret_text

        host_values = self._normalize_context_values(source_context.get("hosts"))
        if host_values:
            notes["hosts"] = ", ".join(host_values)
            notes["hosts_list"] = host_values
        if share_values:
            notes["shares"] = ", ".join(share_values)
            notes["shares_list"] = share_values
        if auth_text:
            notes["auth_username"] = auth_text
        return entry_label, notes

    def build_password_artifact_source_steps(
        self,
        *,
        source_context: dict[str, object] | None,
        spray_type: str | None = None,
        secret: str | None = None,
        verified_via: str = "spraying",
    ) -> list[object]:
        """Build generic artifact/share credential provenance steps from source context."""
        if not isinstance(source_context, dict):
            return []

        origin = str(source_context.get("origin") or "").strip().lower()
        if origin not in {"share_spidering", "artifact_filesystem"}:
            return []

        relation = "PasswordInShare" if origin == "share_spidering" else "PasswordInFile"
        edge_type = "share_password" if origin == "share_spidering" else "file_password"
        auth_text = str(source_context.get("auth_username") or "").strip()
        host_values = self._normalize_context_values(source_context.get("hosts"))
        share_values = self._normalize_context_values(source_context.get("shares"))
        artifact_text = str(source_context.get("artifact") or "").strip()
        artifact_kind = str(source_context.get("artifact_kind") or "").strip().lower()
        if not artifact_kind and artifact_text:
            artifact_kind = self._infer_artifact_kind(artifact_text)
        secret_text = str(secret or "").strip()
        spray_type_text = str(spray_type or "").strip()
        access_vector_text = str(source_context.get("access_vector") or "").strip()

        notes: dict[str, Any] = {
            "origin": origin,
            "verified_via": str(verified_via or "spraying"),
        }
        if access_vector_text:
            notes["access_vector"] = access_vector_text
        if spray_type_text:
            notes["spray_type"] = spray_type_text
        if artifact_text:
            notes["artifact"] = artifact_text
        if artifact_kind and artifact_kind != "unknown":
            notes["artifact_kind"] = artifact_kind
        if secret_text:
            notes["password"] = secret_text
        if auth_text:
            notes["auth_username"] = auth_text
        if host_values:
            notes["hosts"] = ", ".join(host_values)
            notes["hosts_list"] = host_values
        if share_values:
            notes["shares"] = ", ".join(share_values)
            notes["shares_list"] = share_values

        try:
            from adscan_internal.services.attack_graph_service import (
                CredentialSourceStep,
                resolve_entry_label_for_auth,
            )
        except Exception:  # noqa: BLE001
            return []

        entry_label = resolve_entry_label_for_auth(auth_text)
        entry_kind = ""
        if origin == "artifact_filesystem" and host_values:
            entry_label = host_values[0]
            entry_kind = "computer"

        return [
            CredentialSourceStep(
                relation=relation,
                edge_type=edge_type,
                entry_label=entry_label,
                entry_kind=entry_kind,
                notes=notes,
            )
        ]

    @staticmethod
    def _normalize_values(values: Sequence[str] | None) -> list[str]:
        """Return de-duplicated, non-empty string values preserving order."""
        if not values:
            return []
        normalized: list[str] = []
        seen: set[str] = set()
        for value in values:
            text = str(value or "").strip()
            if not text:
                continue
            key = text.lower()
            if key in seen:
                continue
            seen.add(key)
            normalized.append(text)
        return normalized

    @classmethod
    def _normalize_context_values(cls, value: object) -> list[str]:
        """Normalize context values that may be a single str or a sequence."""
        if value is None:
            return []
        if isinstance(value, str):
            return cls._normalize_values([value])
        if isinstance(value, Sequence):
            return cls._normalize_values([str(item) for item in value])
        return cls._normalize_values([str(value)])

    @staticmethod
    def _infer_artifact_kind(artifact: str) -> str:
        """Infer a coarse artifact kind from a path-like artifact string."""
        artifact_text = str(artifact or "").strip().replace("\\", "/")
        if not artifact_text:
            return "unknown"

        path = PurePosixPath(artifact_text)
        filename = path.name.lower()
        suffixes = [suffix.lower() for suffix in path.suffixes]
        suffix_key = "".join(suffixes[-2:]) if len(suffixes) >= 2 else (suffixes[-1] if suffixes else "")

        archive_suffixes = {
            ".zip",
            ".7z",
            ".rar",
            ".tar",
            ".tgz",
            ".gz",
            ".bz2",
            ".xz",
            ".cab",
            ".iso",
            ".tar.gz",
            ".tar.bz2",
            ".tar.xz",
        }
        config_suffixes = {
            ".cfg",
            ".cnf",
            ".conf",
            ".config",
            ".env",
            ".ini",
            ".json",
            ".properties",
            ".toml",
            ".xml",
            ".yaml",
            ".yml",
        }
        document_suffixes = {
            ".csv",
            ".doc",
            ".docx",
            ".odt",
            ".ods",
            ".pdf",
            ".ppt",
            ".pptx",
            ".rtf",
            ".xls",
            ".xlsx",
        }
        text_suffixes = {
            ".log",
            ".md",
            ".ps1",
            ".reg",
            ".sh",
            ".sql",
            ".txt",
        }
        binary_suffixes = {
            ".accdb",
            ".bin",
            ".dat",
            ".db",
            ".dll",
            ".exe",
            ".kdbx",
            ".mdb",
            ".p12",
            ".pfx",
            ".sqlite",
        }

        if suffix_key in archive_suffixes or (filename.endswith(".bak") and "config" not in filename):
            return "archive"
        if suffix_key in config_suffixes:
            return "config"
        if suffix_key in document_suffixes:
            return "document"
        if suffix_key in text_suffixes:
            return "text"
        if suffix_key in binary_suffixes:
            return "binary"
        if any(keyword in filename for keyword in {"config", "settings"}):
            return "config"
        if any(keyword in filename for keyword in {"backup", "archive"}):
            return "archive"
        return "unknown"


# Relations whose source is a share-file credential read-set (the only edges this
# reconciliation pass touches). Lower-cased for case-insensitive comparison.
_SHARE_FILE_EDGE_RELATIONS: frozenset[str] = frozenset(
    {"gpppassword", "gppautologon", "passwordinshare", "passwordinfile"}
)

# Origins stamped by the share-credential provenance builder. An edge must carry
# one of these in ``notes.origin`` to be a reconciliation candidate.
_SHARE_FILE_EDGE_ORIGINS: frozenset[str] = frozenset(
    {"unauth_enrichment", "share_spidering", "artifact_filesystem"}
)

# Node ids the provisional (read-set-absent) fallback ladder produces before
# collection has measured the share read-set. A share-file edge still sourced
# from one of these is what the reconciliation pass rewrites. Guests (S-1-5-32-546)
# and Authenticated Users (S-1-5-11) are Group-kind → keyed by SID; Anonymous
# Logon (S-1-5-7) is User-kind → keyed by name; Domain Users is matched
# structurally below (its id is domain-scoped and localized).
_PROVISIONAL_FALLBACK_NODE_IDS: frozenset[str] = frozenset(
    {
        "name:s-1-5-7",
        "name:anonymous logon",
        "name:s-1-5-32-546",
        "name:guests",
        "name:s-1-5-11",
        "name:authenticated users",
        "name:domain users",
    }
)


def _is_provisional_fallback_source(from_id: str) -> bool:
    """Return True when an edge's ``from`` is a read-set-absent fallback node.

    A reconciliation candidate's source is one of the honest fallbacks the
    provenance builder uses when no read-set was available (Anonymous Logon /
    Guests / Authenticated Users / Everyone placeholder / a Domain Users node).
    A Domain Users node id is domain-scoped and may be localized, so it is matched
    structurally by its RID-513 suffix as well as by the canonical label.
    """
    normalized = str(from_id or "").strip().lower()
    if normalized in _PROVISIONAL_FALLBACK_NODE_IDS:
        return True
    # Domain Users is keyed by RID 513 (e.g. ``name:S-1-5-21-...-513``) or by the
    # canonical ``name:domain users@<domain>`` membership label.
    return normalized.endswith("-513") or normalized.startswith("name:domain users@")


def reconcile_share_credential_edge_sources(
    shell: object,
    domain: str,
    graph: dict[str, Any],
) -> int:
    """Re-point share-file credential edges to the measured read-capable source.

    The unauth GPP / share-spidering credential edge is built in Phase 2.5,
    BEFORE the native share collector writes ``inventory/relationships.json`` in
    Phase 2. At edge-build time the read-set does not exist, so the edge source
    falls to the honest anonymous/authenticated fallback. This pass — run AFTER
    collection persisted both ``relationships.json`` and the attack graph —
    rewrites any share-file edge still on that provisional fallback to the
    measured read-capable SID node(s) for the edge's artifact share.

    Contract (Exposure-Validation discipline):
        - Only edges whose ``relation`` is a share-file credential relation AND
          whose ``notes.origin`` is a share-file origin AND whose current ``from``
          is a provisional-fallback node are candidates.
        - An edge already sourced from a measured read-set principal is NEVER
          rewritten.
        - When the share has no measured read-set, the honest fallback is LEFT in
          place — never fabricated into a read-set principal.
        - Idempotent: re-running makes no further change (the rewritten source is
          no longer a provisional fallback).

    The source node is resolved through the SAME well-known-SID fusion the
    credential-recording path uses (``_resolve_wellknown_source_entry`` →
    ``ensure_entry_node_for_domain``), and the edge ``from`` is rewritten through
    the graph edge-mutation SSOT (``upsert_edge``) — the stale edge is removed and
    a new one upserted so status and notes are preserved.

    Args:
        shell: Session shell exposing the workspace context.
        domain: Domain whose inventory / attack graph to reconcile.
        graph: The loaded attack graph dict (mutated in place).

    Returns:
        The number of edges reconciled (0 when none qualified or no read-set).
    """
    edges = graph.get("edges")
    if not isinstance(edges, list) or not edges:
        return 0

    # Lazy import to avoid a module-level import cycle (attack_graph_service
    # imports this module's classes for CredentialSourceStep building).
    from adscan_internal.services.attack_graph_service import (
        _resolve_wellknown_source_entry,
        ensure_entry_node_for_domain,
        upsert_edge,
    )

    service = ShareCredentialProvenanceService()
    reconciled = 0

    # Snapshot the candidate edges first: upsert_edge appends/rewrites the edges
    # list, so iterate over a stable copy.
    candidates = [edge for edge in edges if isinstance(edge, dict)]
    for edge in candidates:
        relation = str(edge.get("relation") or "").strip().lower()
        if relation not in _SHARE_FILE_EDGE_RELATIONS:
            continue
        notes = edge.get("notes") if isinstance(edge.get("notes"), dict) else {}
        origin = str(notes.get("origin") or "").strip().lower()
        if origin not in _SHARE_FILE_EDGE_ORIGINS:
            continue
        from_id = str(edge.get("from") or "").strip()
        if not _is_provisional_fallback_source(from_id):
            continue  # already on a measured read-set principal — never rewrite

        artifact = str(notes.get("artifact") or "").strip()
        share = str(notes.get("share") or notes.get("shares") or "").strip()
        sources = service.resolve_share_read_capable_sources(
            artifact=artifact or None,
            share=share or None,
            domain=domain,
            shell=shell,
            relationships_path=None,
        )
        if not sources:
            continue  # no read-set → leave the honest fallback, never fabricate

        to_id = str(edge.get("to") or "").strip()
        edge_type = str(edge.get("edge_type") or "").strip()
        status = str(edge.get("status") or "discovered").strip()
        if not to_id or not edge_type:
            continue

        # Resolve the read-set source node(s) through the SAME fusion the
        # credential-recording path uses. When several principals read the share,
        # each becomes its own source edge to the credential owner.
        resolved_any = False
        for src in sources:
            src_notes = {k: v for k, v in notes.items()}
            src_notes["source_sid"] = src.get("sid", "")
            if src.get("verification"):
                src_notes["verification"] = src["verification"]
            if src.get("method"):
                src_notes["method"] = src["method"]
            entry_label = str(src.get("label") or src.get("sid") or "").strip()
            entry_id = _resolve_wellknown_source_entry(graph, entry_label, src_notes)
            if entry_id is None:
                entry_id = ensure_entry_node_for_domain(
                    shell, domain, graph, label=entry_label, entry_kind="group"
                )
            if not entry_id or entry_id == from_id:
                continue
            new_edge = upsert_edge(
                graph,
                from_id=entry_id,
                to_id=to_id,
                relation=edge.get("relation") or relation,
                edge_type=edge_type,
                status=status,
                notes=src_notes,
            )
            if new_edge:
                resolved_any = True

        if not resolved_any:
            continue

        # Remove the stale provisional-fallback edge now that the measured source
        # edge(s) are in place. Identity by the original dict object.
        graph["edges"] = [e for e in graph.get("edges", []) if e is not edge]
        reconciled += 1

    return reconciled
