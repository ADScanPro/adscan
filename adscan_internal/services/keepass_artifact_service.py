"""Deterministic KeePass artifact processing."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import importlib
import json
import os

from adscan_internal import print_info_debug, print_warning, telemetry
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.base_service import BaseService
from adscan_internal.services.john_artifact_cracking_service import (
    JohnArtifactCrackingService,
)


@dataclass(frozen=True)
class KeePassEntryRecord:
    """One extracted KeePass credential entry."""

    group_path: str
    title: str
    username: str
    password: str
    url: str
    notes: str


@dataclass(frozen=True)
class KeePassArtifactProcessResult:
    """Result of one KeePass artifact cracking and extraction run."""

    source_path: str
    hash_file: str | None
    entries_report_path: str | None
    cracked_password: str | None
    entries: list[KeePassEntryRecord]
    extraction_supported: bool = True
    error_message: str | None = None


class KeePassArtifactService(BaseService):
    """Crack KeePass databases and extract entries when possible."""

    def __init__(
        self,
        *,
        john_service: JohnArtifactCrackingService | None = None,
    ) -> None:
        """Initialize KeePass artifact dependencies."""
        super().__init__()
        self._john_service = john_service or JohnArtifactCrackingService()

    def process_local_artifact(
        self,
        *,
        domain: str,
        source_path: str,
        wordlist_path: str,
        keepass2john_path: str,
        python_executable: str | None = None,
        report_dir: str | None = None,
    ) -> KeePassArtifactProcessResult:
        """Crack one local KeePass database and extract password-bearing entries."""
        normalized_source_path = str(source_path or "").strip()
        if not normalized_source_path or not os.path.isfile(normalized_source_path):
            return KeePassArtifactProcessResult(
                source_path=normalized_source_path,
                hash_file=None,
                entries_report_path=None,
                cracked_password=None,
                entries=[],
                error_message="KeePass artifact path does not exist.",
            )

        artifact_root = (
            str(report_dir or "").strip()
            or f"domains/{domain}/smb/keepass"
        )
        os.makedirs(artifact_root, exist_ok=True)
        source_name = Path(normalized_source_path).name
        hash_file = str(Path(artifact_root) / f"{source_name}.keepass.hash")
        entries_report_path = str(Path(artifact_root) / f"{source_name}.entries.json")

        converter_ok = self._john_service.extract_hash_with_script(
            script_path=keepass2john_path,
            input_paths=[normalized_source_path],
            hash_file=hash_file,
            python_executable=python_executable,
        )
        if not converter_ok:
            return KeePassArtifactProcessResult(
                source_path=normalized_source_path,
                hash_file=hash_file,
                entries_report_path=None,
                cracked_password=None,
                entries=[],
                error_message="keepass2john did not produce a usable hash.",
            )

        cracking_result = self._john_service.crack_hash(
            hash_file=hash_file,
            wordlist_path=wordlist_path,
        )
        if not cracking_result.cracked_secret:
            return KeePassArtifactProcessResult(
                source_path=normalized_source_path,
                hash_file=hash_file,
                entries_report_path=None,
                cracked_password=None,
                entries=[],
                error_message="John did not crack the KeePass master password.",
            )

        entries, extraction_supported, extraction_error = self._extract_entries_from_database(
            source_path=normalized_source_path,
            password=cracking_result.cracked_secret,
        )
        if entries:
            self._save_entries_report(
                report_path=entries_report_path,
                source_path=normalized_source_path,
                entries=entries,
            )
        return KeePassArtifactProcessResult(
            source_path=normalized_source_path,
            hash_file=hash_file,
            entries_report_path=entries_report_path if entries else None,
            cracked_password=cracking_result.cracked_secret,
            entries=entries,
            extraction_supported=extraction_supported,
            error_message=extraction_error,
        )

    @staticmethod
    def _load_pykeepass() -> Any:
        """Load PyKeePass lazily so tests/builds can monkeypatch the import."""
        module = importlib.import_module("pykeepass")
        return getattr(module, "PyKeePass")

    def _extract_entries_from_database(
        self,
        *,
        source_path: str,
        password: str,
    ) -> tuple[list[KeePassEntryRecord], bool, str | None]:
        """Open one KeePass database and return password-bearing entries."""
        lowered_name = Path(source_path).name.casefold()
        if lowered_name.endswith(".kdb"):
            return (
                [],
                False,
                "Legacy KeePass .kdb extraction is not automated. The cracked "
                "master password was recovered and can be used manually.",
            )
        try:
            pykeepass_cls = self._load_pykeepass()
            database = pykeepass_cls(source_path, password=password)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning(
                "Could not open KeePass database with cracked password: "
                f"{mark_sensitive(source_path, 'path')}"
            )
            return (
                [],
                True,
                "Could not open KeePass database with the cracked master password.",
            )

        entries: list[KeePassEntryRecord] = []
        seen_entries: set[tuple[str, str, str, str, str, str]] = set()
        for entry in getattr(database, "entries", []) or []:
            password_value = str(getattr(entry, "password", "") or "").strip()
            if not password_value:
                continue
            username = str(getattr(entry, "username", "") or "").strip()
            title = str(getattr(entry, "title", "") or "").strip()
            url = str(getattr(entry, "url", "") or "").strip()
            notes = str(getattr(entry, "notes", "") or "").strip()
            group_path = self._resolve_group_path(entry)
            key = (group_path, title, username, password_value, url, notes)
            if key in seen_entries:
                continue
            seen_entries.add(key)
            entries.append(
                KeePassEntryRecord(
                    group_path=group_path,
                    title=title,
                    username=username,
                    password=password_value,
                    url=url,
                    notes=notes,
                )
            )
        print_info_debug(
            "KeePass extraction completed: "
            f"source={mark_sensitive(source_path, 'path')} entries={len(entries)}"
        )
        return entries, True, None

    @staticmethod
    def _resolve_group_path(entry: Any) -> str:
        """Return a stable group path for one KeePass entry."""
        group = getattr(entry, "group", None)
        parts: list[str] = []
        while group is not None:
            name = str(getattr(group, "name", "") or "").strip()
            if name:
                parts.append(name)
            group = getattr(group, "parentgroup", None) or getattr(group, "parent", None)
        if not parts:
            return "-"
        return "/".join(reversed(parts))

    @staticmethod
    def _save_entries_report(
        *,
        report_path: str,
        source_path: str,
        entries: list[KeePassEntryRecord],
    ) -> None:
        """Persist KeePass entries for later manual review."""
        os.makedirs(os.path.dirname(report_path) or ".", exist_ok=True)
        with open(report_path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "source_path": source_path,
                    "entry_count": len(entries),
                    "entries": [
                        {
                            "group_path": item.group_path,
                            "title": item.title,
                            "username": item.username,
                            "password": item.password,
                            "url": item.url,
                            "notes": item.notes,
                        }
                        for item in entries
                    ],
                },
                handle,
                indent=2,
                ensure_ascii=False,
            )
