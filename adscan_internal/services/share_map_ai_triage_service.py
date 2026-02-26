"""AI triage helpers for consolidated SMB share mapping JSON.

This module prepares analysis prompts that let an LLM prioritize which files
from the spider_plus aggregate mapping should be reviewed for sensitive data.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import base64
import json
import re

from adscan_internal.services.base_service import BaseService


@dataclass(frozen=True)
class ShareMapPriorityFile:
    """One prioritized file candidate selected by AI triage."""

    host: str
    share: str
    path: str
    why: str = ""
    expected_artifact: str = ""


@dataclass(frozen=True)
class ShareMapFileCredential:
    """One credential-like finding returned by AI for a file."""

    credential_type: str
    username: str
    secret: str
    confidence: str
    evidence: str


@dataclass(frozen=True)
class ShareMapFileAnalysisResult:
    """Parsed AI analysis result for one prioritized file."""

    status: str
    summary: str
    credentials: list[ShareMapFileCredential]
    raw_response: str


@dataclass(frozen=True)
class ShareMapFileSizeInfo:
    """Size metadata for one mapped share file."""

    size_text: str
    size_bytes: int | None


@dataclass(frozen=True)
class ShareMapTriageParseDiagnostics:
    """Diagnostics describing how triage response parsing behaved."""

    prioritized_files: list[ShareMapPriorityFile]
    parse_status: str
    payload_present: bool
    raw_priority_items: int
    valid_priority_items: int
    stop_reason: str
    notes: list[str]


class ShareMapAITriageService(BaseService):
    """Build analysis prompts from a consolidated SMB share map."""

    def load_full_mapping_json(self, *, aggregate_map_path: str) -> str:
        """Load full aggregate share mapping JSON as text.

        Args:
            aggregate_map_path: Absolute path to consolidated mapping JSON.

        Returns:
            Full JSON payload as a UTF-8 string.

        Raises:
            FileNotFoundError: If mapping file does not exist.
            ValueError: If mapping file content is not valid JSON.
        """
        path = Path(aggregate_map_path)
        if not path.exists():
            raise FileNotFoundError(f"Share map file not found: {aggregate_map_path}")
        raw_text = path.read_text(encoding="utf-8")
        try:
            json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise ValueError("Share map file is not valid JSON.") from exc
        return raw_text

    @staticmethod
    def build_triage_prompt(
        *,
        domain: str,
        search_scope: str,
        mapping_json: str,
    ) -> str:
        """Build a deterministic analysis prompt for share-map triage.

        Args:
            domain: Target domain name.
            search_scope: One of ``credentials``, ``sensitive_data``, ``both``.
            mapping_json: Full consolidated spider_plus map as JSON text.

        Returns:
            Prompt string instructing the model to prioritize file candidates.
        """
        scope_rules = {
            "credentials": (
                "Focus only on credentials/secrets useful for domain compromise "
                "(passwords, hashes, keys, dumps, config secrets)."
            ),
            "sensitive_data": (
                "Focus only on sensitive business/personal data exposure "
                "(identity docs, payroll, medical/banking records, account data)."
            ),
            "both": (
                "Focus on both credential exposure and sensitive data exposure."
            ),
        }
        scope_text = scope_rules.get(search_scope, scope_rules["credentials"])

        return (
            "You are ADscan share triage assistant.\n"
            "Analysis-only mode:\n"
            "- Do not request command execution.\n"
            "- Do not return adscan_action.\n"
            "- Prioritize files most likely to contain target data.\n"
            f"- Scope: {scope_text}\n\n"
            "Return STRICT JSON with this shape:\n"
            "{\n"
            '  "scope":"credentials|sensitive_data|both",\n'
            '  "priority_files":[\n'
            '    {"host":"...", "share":"...", "path":"...", "why":"...", '
            '"expected_artifact":"..."}\n'
            "  ],\n"
            '  "stop_reason":"...",\n'
            '  "notes":["..."]\n'
            "}\n\n"
            f"Target domain: {domain}\n"
            "Consolidated share mapping JSON (full):\n"
            f"{mapping_json}"
        )

    def count_total_file_entries(self, *, mapping_json: str) -> int:
        """Count total file entries in the consolidated share map payload."""
        try:
            payload = json.loads(mapping_json)
        except json.JSONDecodeError:
            return 0

        if not isinstance(payload, dict):
            return 0

        hosts = payload.get("hosts", {})
        if not isinstance(hosts, dict):
            return 0

        total = 0
        for host_entry in hosts.values():
            if not isinstance(host_entry, dict):
                continue
            shares = host_entry.get("shares", {})
            if not isinstance(shares, dict):
                continue
            for share_entry in shares.values():
                if not isinstance(share_entry, dict):
                    continue
                files = share_entry.get("files", {})
                if isinstance(files, dict):
                    total += len(files)
        return total

    def resolve_principal_allowed_shares(
        self,
        *,
        mapping_json: str,
        domain: str,
        username: str,
    ) -> tuple[str, set[tuple[str, str]]]:
        """Resolve readable host/share pairs for a principal from aggregate map.

        Returns:
            Tuple ``(principal_key, allowed_pairs)`` where ``allowed_pairs`` is a
            set of ``(host_lower, share_lower)`` entries with read access.
        """
        principal = f"{str(domain).strip()}\\{str(username).strip()}".strip()
        if not domain.strip() or not username.strip():
            return "", set()

        try:
            payload = json.loads(mapping_json)
        except json.JSONDecodeError:
            return "", set()
        if not isinstance(payload, dict):
            return "", set()

        principals = payload.get("principals", {})
        if not isinstance(principals, dict):
            return "", set()

        normalized = principal.lower()
        principal_key = ""
        if principal in principals:
            principal_key = principal
        else:
            lookup: dict[str, str] = {}
            for key in principals.keys():
                if not isinstance(key, str):
                    continue
                key_text = key.strip()
                if not key_text:
                    continue
                lookup.setdefault(key_text.lower(), key_text)
            principal_key = lookup.get(normalized, "")

        if not principal_key:
            return "", set()

        principal_entry = principals.get(principal_key, {})
        if not isinstance(principal_entry, dict):
            return principal_key, set()

        host_share_permissions = principal_entry.get("host_share_permissions", {})
        if not isinstance(host_share_permissions, dict):
            return principal_key, set()

        allowed_pairs: set[tuple[str, str]] = set()
        for host, shares in host_share_permissions.items():
            if not isinstance(host, str) or not isinstance(shares, dict):
                continue
            host_lower = host.strip().lower()
            if not host_lower:
                continue
            for share, perms in shares.items():
                if not isinstance(share, str):
                    continue
                share_lower = share.strip().lower()
                if not share_lower:
                    continue
                perms_text = str(perms or "").strip().lower()
                if "read" in perms_text:
                    allowed_pairs.add((host_lower, share_lower))

        return principal_key, allowed_pairs

    def filter_mapping_json_by_allowed_shares(
        self,
        *,
        mapping_json: str,
        allowed_share_pairs: set[tuple[str, str]],
    ) -> str:
        """Return mapping JSON constrained to host/share pairs in allowlist."""
        if not allowed_share_pairs:
            return mapping_json

        try:
            payload = json.loads(mapping_json)
        except json.JSONDecodeError:
            return mapping_json
        if not isinstance(payload, dict):
            return mapping_json

        hosts = payload.get("hosts", {})
        if not isinstance(hosts, dict):
            return mapping_json

        filtered_hosts: dict[str, Any] = {}
        for host, host_entry in hosts.items():
            if not isinstance(host, str) or not isinstance(host_entry, dict):
                continue
            host_lower = host.strip().lower()
            if not host_lower:
                continue
            shares = host_entry.get("shares", {})
            if not isinstance(shares, dict):
                continue

            filtered_shares: dict[str, Any] = {}
            for share, share_entry in shares.items():
                if not isinstance(share, str):
                    continue
                if (host_lower, share.strip().lower()) not in allowed_share_pairs:
                    continue
                filtered_shares[share] = share_entry

            if not filtered_shares:
                continue

            host_copy = dict(host_entry)
            host_copy["shares"] = filtered_shares
            filtered_hosts[host] = host_copy

        payload["hosts"] = filtered_hosts
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def filter_priority_files_by_allowed_shares(
        *,
        prioritized_files: list[ShareMapPriorityFile],
        allowed_share_pairs: set[tuple[str, str]],
    ) -> list[ShareMapPriorityFile]:
        """Filter AI-prioritized files to host/share pairs allowed to principal."""
        if not allowed_share_pairs:
            return prioritized_files

        selected: list[ShareMapPriorityFile] = []
        for candidate in prioritized_files:
            key = (
                str(candidate.host).strip().lower(),
                str(candidate.share).strip().lower(),
            )
            if key in allowed_share_pairs:
                selected.append(candidate)
        return selected

    def parse_triage_priority_files(
        self,
        *,
        response_text: str,
    ) -> list[ShareMapPriorityFile]:
        """Parse AI triage response and return ordered prioritized files."""
        diagnostics = self.parse_triage_response(response_text=response_text)
        return diagnostics.prioritized_files

    def parse_triage_response(
        self,
        *,
        response_text: str,
    ) -> ShareMapTriageParseDiagnostics:
        """Parse triage response and return priority files with diagnostics."""
        payload = self._extract_json_object(response_text)
        if not isinstance(payload, dict):
            return ShareMapTriageParseDiagnostics(
                prioritized_files=[],
                parse_status="no_json_object",
                payload_present=False,
                raw_priority_items=0,
                valid_priority_items=0,
                stop_reason="",
                notes=[],
            )

        stop_reason = str(payload.get("stop_reason", "")).strip()
        payload_notes = payload.get("notes", [])
        notes: list[str] = []
        if isinstance(payload_notes, list):
            for item in payload_notes:
                if isinstance(item, str) and item.strip():
                    notes.append(item.strip())

        raw_candidates = payload.get("priority_files")
        if not isinstance(raw_candidates, list):
            return ShareMapTriageParseDiagnostics(
                prioritized_files=[],
                parse_status="invalid_priority_files_shape",
                payload_present=True,
                raw_priority_items=0,
                valid_priority_items=0,
                stop_reason=stop_reason,
                notes=notes,
            )

        selected: list[ShareMapPriorityFile] = []
        seen_keys: set[tuple[str, str, str]] = set()
        for item in raw_candidates:
            if not isinstance(item, dict):
                continue
            host = str(item.get("host", "")).strip()
            share = str(item.get("share", "")).strip()
            path = str(item.get("path", "")).strip()
            if not host or not share or not path:
                continue
            key = (host.lower(), share.lower(), path.lower())
            if key in seen_keys:
                continue
            seen_keys.add(key)
            selected.append(
                ShareMapPriorityFile(
                    host=host,
                    share=share,
                    path=path,
                    why=str(item.get("why", "")).strip(),
                    expected_artifact=str(item.get("expected_artifact", "")).strip(),
                )
            )
        if not raw_candidates:
            parse_status = "empty_priority_files"
        elif selected:
            parse_status = "ok"
        else:
            parse_status = "no_valid_priority_entries"
        return ShareMapTriageParseDiagnostics(
            prioritized_files=selected,
            parse_status=parse_status,
            payload_present=True,
            raw_priority_items=len(raw_candidates),
            valid_priority_items=len(selected),
            stop_reason=stop_reason,
            notes=notes,
        )

    def build_file_analysis_prompt(
        self,
        *,
        domain: str,
        search_scope: str,
        candidate: ShareMapPriorityFile,
        file_bytes: bytes,
        truncated: bool,
        max_bytes: int,
    ) -> str:
        """Build analysis prompt for one file read from SMB by byte stream."""
        content_block = self._build_content_block(file_bytes=file_bytes)
        return self.build_file_analysis_prompt_from_content(
            domain=domain,
            search_scope=search_scope,
            candidate=candidate,
            content_block=content_block,
            truncated=truncated,
            max_bytes=max_bytes,
            extraction_mode="raw_bytes",
            extraction_notes=[],
        )

    def build_file_analysis_prompt_from_content(
        self,
        *,
        domain: str,
        search_scope: str,
        candidate: ShareMapPriorityFile,
        content_block: str,
        truncated: bool,
        max_bytes: int,
        extraction_mode: str,
        extraction_notes: list[str],
    ) -> str:
        """Build analysis prompt for one file using pre-extracted content."""
        scope_rules = {
            "credentials": (
                "Focus on credentials/secrets useful for domain compromise."
            ),
            "sensitive_data": (
                "Focus on sensitive personal/business data exposure."
            ),
            "both": "Focus on both credentials and sensitive data.",
        }
        scope_text = scope_rules.get(search_scope, scope_rules["credentials"])

        truncation_note = (
            f"Byte stream truncated to first {max_bytes} bytes."
            if truncated
            else "Byte stream captured completely."
        )
        notes_block = "\n".join(f"- {note}" for note in extraction_notes if note.strip())
        if not notes_block:
            notes_block = "- No extractor notes."

        return (
            "You are ADscan SMB file analysis assistant.\n"
            "Analysis-only mode:\n"
            "- Do not request command execution.\n"
            "- Do not return adscan_action.\n"
            f"- Scope: {scope_text}\n"
            f"- {truncation_note}\n\n"
            f"Content extraction mode: {extraction_mode}\n"
            "Extractor notes:\n"
            f"{notes_block}\n\n"
            "Return STRICT JSON with this shape:\n"
            "{\n"
            '  "status":"interesting|not_interesting|error",\n'
            '  "summary":"...",\n'
            '  "credentials":[\n'
            '    {"type":"password|hash|secret|token","username":"...",'
            '"secret":"...","confidence":"high|medium|low","evidence":"..."}\n'
            "  ]\n"
            "}\n\n"
            f"Target domain: {domain}\n"
            f"Host: {candidate.host}\n"
            f"Share: {candidate.share}\n"
            f"Path: {candidate.path}\n"
            f"Triage rationale: {candidate.why or 'N/A'}\n"
            f"Expected artifact: {candidate.expected_artifact or 'N/A'}\n\n"
            f"{content_block}"
        )

    def parse_file_analysis_response(
        self,
        *,
        response_text: str,
    ) -> ShareMapFileAnalysisResult:
        """Parse model JSON output for one file analysis response."""
        payload = self._extract_json_object(response_text)
        if not isinstance(payload, dict):
            return ShareMapFileAnalysisResult(
                status="error",
                summary="Invalid JSON response from AI analyzer.",
                credentials=[],
                raw_response=response_text,
            )

        status = str(payload.get("status", "error")).strip().lower() or "error"
        summary = str(payload.get("summary", "")).strip()
        raw_creds = payload.get("credentials", [])

        parsed_creds: list[ShareMapFileCredential] = []
        if isinstance(raw_creds, list):
            for item in raw_creds:
                if not isinstance(item, dict):
                    continue
                parsed_creds.append(
                    ShareMapFileCredential(
                        credential_type=str(item.get("type", "")).strip(),
                        username=str(item.get("username", "")).strip(),
                        secret=str(item.get("secret", "")).strip(),
                        confidence=str(item.get("confidence", "")).strip(),
                        evidence=str(item.get("evidence", "")).strip(),
                    )
                )

        return ShareMapFileAnalysisResult(
            status=status,
            summary=summary,
            credentials=parsed_creds,
            raw_response=response_text,
        )

    def build_file_size_index(
        self,
        *,
        mapping_json: str,
    ) -> dict[tuple[str, str, str], ShareMapFileSizeInfo]:
        """Build lookup index for file sizes from consolidated mapping JSON."""
        try:
            payload = json.loads(mapping_json)
        except json.JSONDecodeError:
            return {}
        if not isinstance(payload, dict):
            return {}

        hosts = payload.get("hosts", {})
        if not isinstance(hosts, dict):
            return {}

        index: dict[tuple[str, str, str], ShareMapFileSizeInfo] = {}
        for host, host_entry in hosts.items():
            if not isinstance(host, str) or not isinstance(host_entry, dict):
                continue
            shares = host_entry.get("shares", {})
            if not isinstance(shares, dict):
                continue
            for share, share_entry in shares.items():
                if not isinstance(share, str) or not isinstance(share_entry, dict):
                    continue
                files = share_entry.get("files", {})
                if not isinstance(files, dict):
                    continue
                for path, metadata in files.items():
                    if not isinstance(path, str):
                        continue
                    size_text = ""
                    if isinstance(metadata, dict):
                        size_text = str(metadata.get("size", "")).strip()
                    key = (host.lower(), share.lower(), path.lower())
                    index[key] = ShareMapFileSizeInfo(
                        size_text=size_text,
                        size_bytes=self._parse_size_to_bytes(size_text),
                    )
        return index

    @staticmethod
    def _build_content_block(*, file_bytes: bytes) -> str:
        """Serialize read bytes as text snippet or base64 block for AI analysis."""
        if not file_bytes:
            return "File byte stream is empty."

        text = file_bytes.decode("utf-8", errors="replace")
        printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
        printable_ratio = printable / max(1, len(text))

        if printable_ratio >= 0.85:
            snippet = text[:12000]
            return "UTF-8 text snippet:\n" + snippet

        encoded = base64.b64encode(file_bytes).decode("ascii")
        return "Binary content (base64):\n" + encoded[:16000]

    @staticmethod
    def _extract_json_object(response_text: str) -> dict[str, Any] | None:
        """Extract first valid JSON object from model response text/code fences."""
        text = (response_text or "").strip()
        if not text:
            return None

        candidates: list[str] = [text]
        if "```" in text:
            for block in text.split("```"):
                chunk = block.strip()
                if not chunk:
                    continue
                if chunk.startswith("json"):
                    chunk = chunk[4:].strip()
                candidates.append(chunk)

        brace_match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if brace_match:
            candidates.append(brace_match.group(0))

        for candidate in candidates:
            try:
                parsed = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                return parsed
        return None

    @staticmethod
    def _parse_size_to_bytes(size_text: str) -> int | None:
        """Parse spider_plus human-readable size value into bytes."""
        text = (size_text or "").strip()
        if not text:
            return None

        match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)\s*([A-Za-z]+)?", text)
        if not match:
            return None

        value = float(match.group(1))
        unit = (match.group(2) or "B").upper()
        factors = {
            "B": 1,
            "KB": 1024,
            "MB": 1024 * 1024,
            "GB": 1024 * 1024 * 1024,
            "TB": 1024 * 1024 * 1024 * 1024,
        }
        factor = factors.get(unit)
        if factor is None:
            return None
        return int(value * factor)
