"""Deterministic analyzers for prioritized SMB share files.

This service complements AI-based file inspection with format-specific analyzers
that can extract credentials without relying on LLM inference.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Callable
import io
import os
import re
import shlex
import subprocess
import zipfile

from adscan_internal.file_content_type import detect_file_content_type
from adscan_internal.integrations.impacket.parsers import parse_secretsdump_output
from adscan_internal.services.base_service import BaseService


CommandExecutor = Callable[..., subprocess.CompletedProcess[str] | None]
_NTLM_HASH_DUMP_TEXT_EXTENSIONS = (".txt", ".log", ".csv")


@dataclass(frozen=True)
class ShareFileAnalyzerFinding:
    """Credential finding produced by a deterministic analyzer."""

    credential_type: str
    username: str
    secret: str
    confidence: str
    evidence: str


@dataclass(frozen=True)
class ShareFileAnalyzerResult:
    """Deterministic analysis outcome for one prioritized file."""

    handled: bool
    continue_with_ai: bool
    summary: str
    findings: list[ShareFileAnalyzerFinding]
    notes: list[str]


class ShareFileAnalyzerService(BaseService):
    """Run deterministic analyzers before AI fallback in SMB triage flows."""

    def __init__(
        self,
        *,
        command_executor: CommandExecutor | None = None,
        pypykatz_path: str | None = None,
    ) -> None:
        """Initialize deterministic analyzer service."""
        super().__init__()
        self._command_executor = command_executor
        self._pypykatz_path = pypykatz_path or "pypykatz"

    def analyze(
        self,
        *,
        source_path: str | None = None,
        remote_path: str | None = None,
        file_bytes: bytes,
        truncated: bool,
    ) -> ShareFileAnalyzerResult:
        """Analyze one file with deterministic analyzers when applicable."""
        effective_source_path = str(source_path or remote_path or "").strip()
        lowered_path = effective_source_path.lower()
        if not file_bytes:
            return ShareFileAnalyzerResult(
                handled=False,
                continue_with_ai=True,
                summary="",
                findings=[],
                notes=[],
            )

        if lowered_path.endswith(".dmp"):
            findings, notes = self._analyze_dmp_bytes(
                source_path=effective_source_path,
                dmp_bytes=file_bytes,
                truncated=truncated,
            )
            summary = (
                f"Deterministic DMP analysis found {len(findings)} credential candidate(s)."
                if findings
                else "Deterministic DMP analysis found no credential candidates."
            )
            return ShareFileAnalyzerResult(
                handled=True,
                continue_with_ai=not bool(findings),
                summary=summary,
                findings=findings,
                notes=notes,
            )

        detection = detect_file_content_type(file_bytes=file_bytes)
        if lowered_path.endswith(".zip") or detection.kind == "zip_archive":
            return self._analyze_zip_archive(
                source_path=effective_source_path,
                file_bytes=file_bytes,
                truncated=truncated,
            )
        if lowered_path.endswith(".xml"):
            text = file_bytes.decode("utf-8", errors="replace")
            findings, notes = self._analyze_gpp_xml_text(
                source_path=effective_source_path,
                text=text,
            )
            summary = (
                f"Deterministic GPP XML analysis found {len(findings)} cpassword candidate(s)."
                if findings
                else "Deterministic GPP XML analysis found no cpassword candidates."
            )
            return ShareFileAnalyzerResult(
                handled=True,
                continue_with_ai=not bool(findings),
                summary=summary,
                findings=findings,
                notes=notes,
            )
        if lowered_path.endswith((".kdbx", ".kdb")):
            return ShareFileAnalyzerResult(
                handled=True,
                continue_with_ai=False,
                summary=(
                    "Deterministic KeePass artifact analysis will attempt cracking "
                    "and entry extraction."
                ),
                findings=[
                    ShareFileAnalyzerFinding(
                        credential_type="keepass_artifact",
                        username="-",
                        secret="-",
                        confidence="high",
                        evidence="KeePass database",
                    )
                ],
                notes=[],
            )
        if lowered_path.endswith((".yml", ".yaml")):
            text = file_bytes.decode("utf-8", errors="replace")
            findings, notes = self._analyze_ansible_vault_text(
                source_path=effective_source_path,
                text=text,
            )
            summary = (
                "Deterministic YAML analysis found "
                f"{len(findings)} Ansible Vault block(s)."
                if findings
                else "Deterministic YAML analysis found no Ansible Vault blocks."
            )
            return ShareFileAnalyzerResult(
                handled=True,
                continue_with_ai=not bool(findings),
                summary=summary,
                findings=findings,
                notes=notes,
            )
        if lowered_path.endswith(_NTLM_HASH_DUMP_TEXT_EXTENSIONS):
            text = file_bytes.decode("utf-8", errors="replace")
            findings, notes = self._analyze_ntlm_hash_dump_text(
                source_path=effective_source_path,
                text=text,
            )
            if not findings:
                return ShareFileAnalyzerResult(
                    handled=False,
                    continue_with_ai=True,
                    summary="",
                    findings=[],
                    notes=notes,
                )
            summary = (
                "Deterministic NTLM dump analysis found "
                f"{len(findings)} credential candidate(s)."
            )
            return ShareFileAnalyzerResult(
                handled=True,
                continue_with_ai=not bool(findings),
                summary=summary,
                findings=findings,
                notes=notes,
            )

        return ShareFileAnalyzerResult(
            handled=False,
            continue_with_ai=True,
            summary="",
            findings=[],
            notes=[],
        )

    def analyze_local_file(
        self,
        *,
        source_path: str,
    ) -> ShareFileAnalyzerResult:
        """Analyze one local file path with deterministic analyzers."""
        path = Path(str(source_path or "").strip())
        if not path.exists() or not path.is_file():
            return ShareFileAnalyzerResult(
                handled=False,
                continue_with_ai=True,
                summary="",
                findings=[],
                notes=[f"Local source file not found: {source_path}."],
            )
        lowered_path = path.name.lower()
        if lowered_path.endswith(".dmp"):
            findings, notes = self._analyze_dmp_path(source_path=str(path))
            summary = (
                f"Deterministic DMP analysis found {len(findings)} credential candidate(s)."
                if findings
                else "Deterministic DMP analysis found no credential candidates."
            )
            return ShareFileAnalyzerResult(
                handled=True,
                continue_with_ai=not bool(findings),
                summary=summary,
                findings=findings,
                notes=notes,
            )
        if lowered_path.endswith(".zip"):
            return self._analyze_zip_archive_from_path(source_path=str(path))
        if lowered_path.endswith(".xml"):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except Exception as exc:  # noqa: BLE001
                return ShareFileAnalyzerResult(
                    handled=True,
                    continue_with_ai=True,
                    summary="Deterministic XML analysis failed; falling back to AI.",
                    findings=[],
                    notes=[f"XML read failure: {type(exc).__name__}."],
                )
            findings, notes = self._analyze_gpp_xml_text(
                source_path=str(path),
                text=text,
            )
            summary = (
                f"Deterministic GPP XML analysis found {len(findings)} cpassword candidate(s)."
                if findings
                else "Deterministic GPP XML analysis found no cpassword candidates."
            )
            return ShareFileAnalyzerResult(
                handled=True,
                continue_with_ai=not bool(findings),
                summary=summary,
                findings=findings,
                notes=notes,
            )
        if lowered_path.endswith((".yml", ".yaml")):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except Exception as exc:  # noqa: BLE001
                return ShareFileAnalyzerResult(
                    handled=True,
                    continue_with_ai=True,
                    summary="Deterministic YAML analysis failed; falling back to AI.",
                    findings=[],
                    notes=[f"YAML read failure: {type(exc).__name__}."],
                )
            findings, notes = self._analyze_ansible_vault_text(
                source_path=str(path),
                text=text,
            )
            summary = (
                "Deterministic YAML analysis found "
                f"{len(findings)} Ansible Vault block(s)."
                if findings
                else "Deterministic YAML analysis found no Ansible Vault blocks."
            )
            return ShareFileAnalyzerResult(
                handled=True,
                continue_with_ai=not bool(findings),
                summary=summary,
                findings=findings,
                notes=notes,
            )
        if lowered_path.endswith(_NTLM_HASH_DUMP_TEXT_EXTENSIONS):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except Exception as exc:  # noqa: BLE001
                return ShareFileAnalyzerResult(
                    handled=True,
                    continue_with_ai=True,
                    summary="Deterministic NTLM dump analysis failed; falling back to AI.",
                    findings=[],
                    notes=[f"Text read failure: {type(exc).__name__}."],
                )
            findings, notes = self._analyze_ntlm_hash_dump_text(
                source_path=str(path),
                text=text,
            )
            if not findings:
                return ShareFileAnalyzerResult(
                    handled=False,
                    continue_with_ai=True,
                    summary="",
                    findings=[],
                    notes=notes,
                )
            summary = (
                "Deterministic NTLM dump analysis found "
                f"{len(findings)} credential candidate(s)."
            )
            return ShareFileAnalyzerResult(
                handled=True,
                continue_with_ai=not bool(findings),
                summary=summary,
                findings=findings,
                notes=notes,
            )
        if lowered_path.endswith(".xlsm"):
            findings, notes = self._analyze_xlsm_path(source_path=str(path))
            summary = (
                "Deterministic XLSM macro analysis found "
                f"{len(findings)} credential candidate(s)."
                if findings
                else "Deterministic XLSM macro analysis found no credential candidates."
            )
            return ShareFileAnalyzerResult(
                handled=True,
                continue_with_ai=not bool(findings),
                summary=summary,
                findings=findings,
                notes=notes,
            )
        if lowered_path.endswith((".kdbx", ".kdb")):
            return ShareFileAnalyzerResult(
                handled=True,
                continue_with_ai=False,
                summary=(
                    "Deterministic KeePass artifact analysis will attempt cracking "
                    "and entry extraction."
                ),
                findings=[
                    ShareFileAnalyzerFinding(
                        credential_type="keepass_artifact",
                        username="-",
                        secret="-",
                        confidence="high",
                        evidence="KeePass database",
                    )
                ],
                notes=[],
            )
        return ShareFileAnalyzerResult(
            handled=False,
            continue_with_ai=True,
            summary="",
            findings=[],
            notes=[],
        )

    def _analyze_ntlm_hash_dump_text(
        self,
        *,
        source_path: str,
        text: str,
    ) -> tuple[list[ShareFileAnalyzerFinding], list[str]]:
        """Parse secretsdump/SAM-style NTLM hash dumps from text files."""
        parsed_hashes = parse_secretsdump_output(text)
        findings: list[ShareFileAnalyzerFinding] = []
        for parsed_hash in parsed_hashes:
            username = str(getattr(parsed_hash, "username", "") or "").strip()
            ntlm_hash = str(getattr(parsed_hash, "ntlm_hash", "") or "").strip()
            if not username or not ntlm_hash:
                continue
            findings.append(
                ShareFileAnalyzerFinding(
                    credential_type="ntlm_hash",
                    username=username,
                    secret=ntlm_hash,
                    confidence="high",
                    evidence=f"secretsdump-format line in {source_path}",
                )
            )
        return findings, []

    def _analyze_zip_archive(
        self,
        *,
        source_path: str,
        file_bytes: bytes,
        truncated: bool,
    ) -> ShareFileAnalyzerResult:
        """Analyze ZIP archives and process embedded DMP entries deterministically."""
        try:
            archive = zipfile.ZipFile(io.BytesIO(file_bytes))
        except Exception as exc:  # noqa: BLE001
            if truncated:
                return ShareFileAnalyzerResult(
                    handled=True,
                    continue_with_ai=True,
                    summary=(
                        "ZIP archive appears truncated; deterministic ZIP inspection "
                        "could not parse embedded entries."
                    ),
                    findings=[],
                    notes=[f"ZIP parse failure: {type(exc).__name__}."],
                )
            return ShareFileAnalyzerResult(
                handled=True,
                continue_with_ai=True,
                summary="Deterministic ZIP inspection failed; falling back to AI.",
                findings=[],
                notes=[f"ZIP parse failure: {type(exc).__name__}."],
            )

        try:
            dmp_entries = [
                info
                for info in archive.infolist()
                if not info.is_dir() and info.filename.lower().endswith(".dmp")
            ]
            if not dmp_entries:
                return ShareFileAnalyzerResult(
                    handled=False,
                    continue_with_ai=True,
                    summary="",
                    findings=[],
                    notes=[],
                )

            findings: list[ShareFileAnalyzerFinding] = []
            notes: list[str] = []
            max_entry_bytes = self._resolve_max_dmp_entry_bytes()
            processed_entries = 0

            for entry in dmp_entries:
                entry_name = entry.filename
                entry_size = int(getattr(entry, "file_size", 0) or 0)
                if entry_size <= 0:
                    notes.append(f"Skipped empty DMP entry: {entry_name}.")
                    continue
                if isinstance(max_entry_bytes, int) and entry_size > max_entry_bytes:
                    notes.append(
                        "Skipped DMP entry due size limit: "
                        f"{entry_name} ({entry_size} bytes > {max_entry_bytes} bytes)."
                    )
                    continue

                try:
                    with archive.open(entry, "r") as handle:
                        if isinstance(max_entry_bytes, int):
                            entry_bytes = handle.read(max_entry_bytes + 1)
                        else:
                            entry_bytes = handle.read()
                except Exception as exc:  # noqa: BLE001
                    notes.append(
                        f"Could not read DMP entry {entry_name}: {type(exc).__name__}."
                    )
                    continue

                if isinstance(max_entry_bytes, int) and len(entry_bytes) > max_entry_bytes:
                    notes.append(
                        "Skipped DMP entry due read cap overflow: "
                        f"{entry_name} (> {max_entry_bytes} bytes)."
                    )
                    continue

                processed_entries += 1
                entry_findings, entry_notes = self._analyze_dmp_bytes(
                    source_path=f"{source_path}::{entry_name}",
                    dmp_bytes=entry_bytes,
                    truncated=False,
                )
                findings.extend(entry_findings)
                notes.extend(entry_notes)

            summary = (
                "Deterministic ZIP->DMP analysis found "
                f"{len(findings)} credential candidate(s) across {processed_entries} "
                f"DMP entr{'y' if processed_entries == 1 else 'ies'}."
            )
            return ShareFileAnalyzerResult(
                handled=True,
                continue_with_ai=not bool(findings),
                summary=summary,
                findings=findings,
                notes=notes,
            )
        finally:
            archive.close()

    def _analyze_zip_archive_from_path(
        self,
        *,
        source_path: str,
    ) -> ShareFileAnalyzerResult:
        """Analyze local ZIP archives and process embedded DMP entries."""
        try:
            archive = zipfile.ZipFile(source_path)
        except Exception as exc:  # noqa: BLE001
            return ShareFileAnalyzerResult(
                handled=True,
                continue_with_ai=True,
                summary="Deterministic ZIP inspection failed; falling back to AI.",
                findings=[],
                notes=[f"ZIP parse failure: {type(exc).__name__}."],
            )

        try:
            dmp_entries = [
                info
                for info in archive.infolist()
                if not info.is_dir() and info.filename.lower().endswith(".dmp")
            ]
            if not dmp_entries:
                return ShareFileAnalyzerResult(
                    handled=False,
                    continue_with_ai=True,
                    summary="",
                    findings=[],
                    notes=[],
                )
            findings: list[ShareFileAnalyzerFinding] = []
            notes: list[str] = []
            max_entry_bytes = self._resolve_max_dmp_entry_bytes()
            processed_entries = 0
            for entry in dmp_entries:
                entry_name = entry.filename
                entry_size = int(getattr(entry, "file_size", 0) or 0)
                if entry_size <= 0:
                    notes.append(f"Skipped empty DMP entry: {entry_name}.")
                    continue
                if isinstance(max_entry_bytes, int) and entry_size > max_entry_bytes:
                    notes.append(
                        "Skipped DMP entry due size limit: "
                        f"{entry_name} ({entry_size} bytes > {max_entry_bytes} bytes)."
                    )
                    continue
                try:
                    with archive.open(entry, "r") as handle:
                        if isinstance(max_entry_bytes, int):
                            entry_bytes = handle.read(max_entry_bytes + 1)
                        else:
                            entry_bytes = handle.read()
                except Exception as exc:  # noqa: BLE001
                    notes.append(
                        f"Could not read DMP entry {entry_name}: {type(exc).__name__}."
                    )
                    continue
                if isinstance(max_entry_bytes, int) and len(entry_bytes) > max_entry_bytes:
                    notes.append(
                        "Skipped DMP entry due read cap overflow: "
                        f"{entry_name} (> {max_entry_bytes} bytes)."
                    )
                    continue

                processed_entries += 1
                entry_findings, entry_notes = self._analyze_dmp_bytes(
                    source_path=f"{source_path}::{entry_name}",
                    dmp_bytes=entry_bytes,
                    truncated=False,
                )
                findings.extend(entry_findings)
                notes.extend(entry_notes)
            summary = (
                "Deterministic ZIP->DMP analysis found "
                f"{len(findings)} credential candidate(s) across {processed_entries} "
                f"DMP entr{'y' if processed_entries == 1 else 'ies'}."
            )
            return ShareFileAnalyzerResult(
                handled=True,
                continue_with_ai=not bool(findings),
                summary=summary,
                findings=findings,
                notes=notes,
            )
        finally:
            archive.close()

    def _analyze_dmp_bytes(
        self,
        *,
        source_path: str,
        dmp_bytes: bytes,
        truncated: bool,
    ) -> tuple[list[ShareFileAnalyzerFinding], list[str]]:
        """Analyze DMP bytes with pypykatz and return parsed credential findings."""
        if self._command_executor is None:
            return [], ["Deterministic DMP analyzer unavailable: no command executor."]

        temp_path: str | None = None
        try:
            with NamedTemporaryFile(delete=False, suffix=".dmp") as handle:
                handle.write(dmp_bytes)
                handle.flush()
                temp_path = handle.name

            pypykatz_cmd = self._pypykatz_path or "pypykatz"
            command = (
                f"{shlex.quote(pypykatz_cmd)} lsa minidump "
                f"{shlex.quote(temp_path)} -p msv"
            )
            proc = self._command_executor(command, timeout=300)
            if proc is None:
                return [], [f"pypykatz returned no result for {source_path}."]
            if proc.returncode != 0:
                stderr_text = str(proc.stderr or "").strip()
                details = stderr_text or f"return_code={proc.returncode}"
                return [], [f"pypykatz failed for {source_path}: {details}."]

            output = str(proc.stdout or "")
            findings = self._parse_pypykatz_output(output=output)
            notes: list[str] = []
            if truncated:
                notes.append(
                    "DMP byte stream was truncated before deterministic analysis."
                )
            notes.append(
                f"pypykatz processed {Path(source_path).name}: findings={len(findings)}."
            )
            return findings, notes
        except Exception as exc:  # noqa: BLE001
            return [], [f"Deterministic DMP analysis failed: {type(exc).__name__}."]
        finally:
            if temp_path:
                try:
                    os.unlink(temp_path)
                except Exception:  # noqa: BLE001
                    pass

    def _analyze_dmp_path(
        self,
        *,
        source_path: str,
    ) -> tuple[list[ShareFileAnalyzerFinding], list[str]]:
        """Analyze an on-disk DMP file with pypykatz."""
        if self._command_executor is None:
            return [], ["Deterministic DMP analyzer unavailable: no command executor."]
        try:
            pypykatz_cmd = self._pypykatz_path or "pypykatz"
            command = (
                f"{shlex.quote(pypykatz_cmd)} lsa minidump "
                f"{shlex.quote(source_path)} -p msv"
            )
            proc = self._command_executor(command, timeout=300)
            if proc is None:
                return [], [f"pypykatz returned no result for {source_path}."]
            if proc.returncode != 0:
                stderr_text = str(proc.stderr or "").strip()
                details = stderr_text or f"return_code={proc.returncode}"
                return [], [f"pypykatz failed for {source_path}: {details}."]
            output = str(proc.stdout or "")
            findings = self._parse_pypykatz_output(output=output)
            return findings, [
                f"pypykatz processed {Path(source_path).name}: findings={len(findings)}."
            ]
        except Exception as exc:  # noqa: BLE001
            return [], [f"Deterministic DMP analysis failed: {type(exc).__name__}."]

    @staticmethod
    def _parse_pypykatz_output(*, output: str) -> list[ShareFileAnalyzerFinding]:
        """Parse pypykatz output and extract username->NT hash findings."""
        cred_pattern = r"Username:\s*([^\n]+).*?NT:\s*([a-fA-F0-9]{32})"
        matches = re.finditer(cred_pattern, output or "", re.DOTALL)
        findings: list[ShareFileAnalyzerFinding] = []
        seen: set[tuple[str, str]] = set()
        for match in matches:
            username = str(match.group(1) or "").strip()
            nt_hash = str(match.group(2) or "").strip()
            if not username or not nt_hash:
                continue
            if username.startswith(("UMFD-", "DWM-")):
                continue
            key = (username, nt_hash)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                ShareFileAnalyzerFinding(
                    credential_type="ntlm_hash",
                    username=username,
                    secret=nt_hash,
                    confidence="high",
                    evidence=f"pypykatz msv: Username={username} NT={nt_hash}",
                )
            )
        return findings

    @staticmethod
    def _analyze_gpp_xml_text(
        *,
        source_path: str,
        text: str,
    ) -> tuple[list[ShareFileAnalyzerFinding], list[str]]:
        """Extract cpassword entries from GPP-like XML content."""
        combined_pattern = re.compile(
            r'(?is)(?:userName="(?P<user>[^"]+)".*?cpassword="(?P<pass>[^"]+)"|'
            r'cpassword="(?P<pass_alt>[^"]+)".*?userName="(?P<user_alt>[^"]+)")'
        )
        entries: list[tuple[str, str]] = []
        for match in combined_pattern.finditer(text or ""):
            username = (match.group("user") or match.group("user_alt") or "").strip()
            cpassword = (match.group("pass") or match.group("pass_alt") or "").strip()
            if cpassword:
                entries.append((username or "-", cpassword))

        if not entries:
            standalone = re.compile(r'cpassword="([^"]+)"', re.IGNORECASE)
            for match in standalone.finditer(text or ""):
                cpassword = str(match.group(1) or "").strip()
                if cpassword:
                    entries.append(("-", cpassword))

        findings: list[ShareFileAnalyzerFinding] = []
        seen: set[tuple[str, str]] = set()
        for username, cpassword in entries:
            key = (username, cpassword)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                ShareFileAnalyzerFinding(
                    credential_type="cpassword",
                    username=username,
                    secret=cpassword,
                    confidence="high",
                    evidence=f"GPP XML cpassword in {Path(source_path).name}",
                )
            )
        notes = [f"GPP XML parsed: entries={len(findings)}."]
        return findings, notes

    @staticmethod
    def _analyze_ansible_vault_text(
        *,
        source_path: str,
        text: str,
    ) -> tuple[list[ShareFileAnalyzerFinding], list[str]]:
        """Extract Ansible Vault blocks from YAML content."""
        vault_pattern = re.compile(
            r"(?:!vault \|(?:\n[\s]+\$ANSIBLE_VAULT;[^\n]*(?:\n[\s]+[0-9a-f]+)+)+)",
            re.MULTILINE,
        )
        matches = vault_pattern.findall(text or "")
        findings: list[ShareFileAnalyzerFinding] = []
        for idx, vault_content in enumerate(matches, start=1):
            vault_lines = vault_content.split("\n")[1:]
            vault_lines = [line.strip() for line in vault_lines if line.strip()]
            vault_text = "\n".join(vault_lines).strip()
            if not vault_text:
                continue
            findings.append(
                ShareFileAnalyzerFinding(
                    credential_type="ansible_vault",
                    username="-",
                    secret=vault_text,
                    confidence="high",
                    evidence=f"Ansible Vault block #{idx} in {Path(source_path).name}",
                )
            )
        notes = [f"YAML vault parser: blocks={len(findings)}."]
        return findings, notes

    def _analyze_xlsm_path(
        self,
        *,
        source_path: str,
    ) -> tuple[list[ShareFileAnalyzerFinding], list[str]]:
        """Run olevba over XLSM and extract credential-like assignments."""
        if self._command_executor is None:
            return [], ["XLSM analyzer unavailable: no command executor."]
        try:
            command = f'olevba {shlex.quote(source_path)}'
            proc = self._command_executor(command, timeout=300)
            if proc is None:
                return [], [f"olevba returned no result for {source_path}."]
            if proc.returncode != 0:
                stderr_text = str(proc.stderr or "").strip()
                details = stderr_text or f"return_code={proc.returncode}"
                return [], [f"olevba failed for {source_path}: {details}."]
            output = str(proc.stdout or "")
            password_pattern = re.compile(
                r"(password|pass|passwd|pwd|contraseña|pasahitza)\s*=\s*['\"]?([^\s'\"]+)",
                re.IGNORECASE,
            )
            user_pattern = re.compile(
                r"(Uid|user|username|usuario)\s*=\s*['\"]?([^;'\"\\s]+)",
                re.IGNORECASE,
            )
            passwords = [str(match[1]).strip() for match in password_pattern.findall(output)]
            users = [str(match[1]).strip() for match in user_pattern.findall(output)]
            if not passwords:
                return [], [f"olevba processed {Path(source_path).name}: no password patterns found."]

            findings: list[ShareFileAnalyzerFinding] = []
            for idx, password in enumerate(passwords):
                username = users[idx] if idx < len(users) else (users[0] if users else "-")
                evidence_user = username if username else "-"
                findings.append(
                    ShareFileAnalyzerFinding(
                        credential_type="macro_password",
                        username=evidence_user,
                        secret=password,
                        confidence="medium",
                        evidence=(
                            f"olevba pattern in {Path(source_path).name}: "
                            f"user={evidence_user}"
                        ),
                    )
                )
            return findings, [
                f"olevba processed {Path(source_path).name}: findings={len(findings)}."
            ]
        except Exception as exc:  # noqa: BLE001
            return [], [f"Deterministic XLSM analysis failed: {type(exc).__name__}."]

    @staticmethod
    def _resolve_max_dmp_entry_bytes() -> int | None:
        """Return max ZIP-embedded DMP bytes; ``None`` means unlimited."""
        raw = os.getenv("ADSCAN_AI_DMP_MAX_BYTES", "0").strip()
        try:
            value = int(raw)
        except ValueError:
            return None
        if value <= 0:
            return None
        return max(1024 * 1024, value)
