"""Helpers to build share-origin credential provenance artifacts.

Centralizes creation of:
- ``source_context`` payloads used by spraying flows.
- ``CredentialSourceStep`` lists used by ``add_credential`` attack-graph recording.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import PurePosixPath
from typing import Any

from adscan_internal.services.base_service import BaseService


class ShareCredentialProvenanceService(BaseService):
    """Build standardized provenance metadata for share-derived credentials."""

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
    ) -> list[object]:
        """Build one ``CredentialSourceStep`` for a share-derived credential."""
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
        entry_label = resolve_entry_label_for_auth(auth_text)
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
    ) -> tuple[str, dict[str, object]] | None:
        """Build ``(entry_label, notes)`` for ``PasswordInShare`` edge upserts."""
        if not isinstance(source_context, dict):
            return None
        origin = str(source_context.get("origin") or "").strip().lower()
        if origin != "share_spidering":
            return None

        auth_text = str(source_context.get("auth_username") or "").strip()
        try:
            from adscan_internal.services.attack_graph_service import (
                resolve_entry_label_for_auth,
            )

            entry_label = resolve_entry_label_for_auth(auth_text)
        except Exception:  # noqa: BLE001
            entry_label = "Domain Users"

        notes: dict[str, object] = {
            "verified_via": str(verified_via or "spraying"),
            "origin": "share_spidering",
        }
        spray_type_text = str(spray_type or "").strip()
        if spray_type_text:
            notes["spray_type"] = spray_type_text
        artifact_text = str(source_context.get("artifact") or "").strip()
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
        share_values = self._normalize_context_values(source_context.get("shares"))
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
