"""Persistent history helpers for cracking attempts.

This service keeps cracking-attempt metadata in workspace state so the CLI can
warn about repeated operations across hashcat and John-based flows without
duplicating persistence logic in every caller.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable


_MAX_HISTORY_ENTRIES_PER_DOMAIN = 250


@dataclass(frozen=True)
class CrackingAttempt:
    """Normalized cracking attempt description used for history matching."""

    tool: str
    crack_type: str
    wordlist_name: str | None
    wordlist_path: str | None
    hash_file: str | None
    hash_file_fingerprint: str | None
    hash_count: int
    target_users: list[str]
    artifact_paths: list[str]
    result: str
    cracked_count: int


def get_cracking_history(shell: Any) -> dict[str, Any]:
    """Return the persistent cracking history store attached to the shell."""
    history = getattr(shell, "cracking_history", None)
    if not isinstance(history, dict):
        history = {}
        shell.cracking_history = history
    return history


def _normalize_users_from_hash_file(hash_file: str | None) -> list[str]:
    """Extract user identifiers from a hash file when present."""
    if not hash_file or not Path(hash_file).exists():
        return []

    users: list[str] = []
    seen: set[str] = set()
    try:
        for raw_line in Path(hash_file).read_text(
            encoding="utf-8", errors="ignore"
        ).splitlines():
            line = raw_line.strip()
            if not line or ":" not in line:
                continue
            user = line.split(":", 1)[0].strip()
            if not user:
                continue
            user_key = user.lower()
            if user_key in seen:
                continue
            seen.add(user_key)
            users.append(user)
    except OSError:
        return []
    return users


def _fingerprint_file(path: str | None) -> tuple[str | None, int]:
    """Return a deterministic fingerprint and line count for one file."""
    if not path:
        return None, 0
    file_path = Path(path)
    if not file_path.exists() or not file_path.is_file():
        return None, 0
    try:
        data = file_path.read_bytes()
    except OSError:
        return None, 0

    line_count = len([line for line in data.splitlines() if line.strip()])
    return sha256(data).hexdigest(), line_count


def build_cracking_attempt(
    *,
    tool: str,
    crack_type: str,
    wordlist_name: str | None,
    wordlist_path: str | None = None,
    hash_file: str | None = None,
    original_files: Iterable[str] | None = None,
    result: str,
    cracked_count: int,
) -> CrackingAttempt:
    """Build a normalized cracking-attempt record."""
    fingerprint, hash_count = _fingerprint_file(hash_file)
    artifact_paths = [str(path).strip() for path in (original_files or []) if str(path).strip()]
    return CrackingAttempt(
        tool=str(tool or "").strip().lower(),
        crack_type=str(crack_type or "").strip().lower(),
        wordlist_name=str(wordlist_name or "").strip() or None,
        wordlist_path=str(wordlist_path or "").strip() or None,
        hash_file=str(hash_file or "").strip() or None,
        hash_file_fingerprint=fingerprint,
        hash_count=hash_count,
        target_users=_normalize_users_from_hash_file(hash_file),
        artifact_paths=artifact_paths,
        result=str(result or "").strip().lower() or "unknown",
        cracked_count=max(0, int(cracked_count or 0)),
    )


def find_matching_attempt(
    shell: Any,
    *,
    domain: str,
    attempt: CrackingAttempt,
) -> dict[str, Any] | None:
    """Return the most recent equivalent cracking attempt for a domain."""
    history = get_cracking_history(shell)
    domain_entry = history.get(domain, {})
    attempts = domain_entry.get("attempts", []) if isinstance(domain_entry, dict) else []
    if not isinstance(attempts, list):
        return None

    for previous in reversed(attempts):
        if not isinstance(previous, dict):
            continue
        if str(previous.get("tool") or "").strip().lower() != attempt.tool:
            continue
        if str(previous.get("crack_type") or "").strip().lower() != attempt.crack_type:
            continue
        if str(previous.get("wordlist_path") or "").strip() != str(attempt.wordlist_path or ""):
            continue
        if str(previous.get("hash_file_fingerprint") or "").strip() != str(attempt.hash_file_fingerprint or ""):
            continue
        if list(previous.get("artifact_paths") or []) != attempt.artifact_paths:
            continue
        return previous
    return None


def register_cracking_attempt(shell: Any, *, domain: str, attempt: CrackingAttempt) -> None:
    """Persist one normalized cracking attempt in workspace state."""
    history = get_cracking_history(shell)
    domain_entry = history.setdefault(domain, {})
    attempts = domain_entry.setdefault("attempts", [])
    if not isinstance(attempts, list):
        attempts = []
        domain_entry["attempts"] = attempts

    attempts.append(
        {
            "tool": attempt.tool,
            "crack_type": attempt.crack_type,
            "wordlist_name": attempt.wordlist_name,
            "wordlist_path": attempt.wordlist_path,
            "hash_file": attempt.hash_file,
            "hash_file_fingerprint": attempt.hash_file_fingerprint,
            "hash_count": attempt.hash_count,
            "target_users": attempt.target_users,
            "artifact_paths": attempt.artifact_paths,
            "result": attempt.result,
            "cracked_count": attempt.cracked_count,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )
    if len(attempts) > _MAX_HISTORY_ENTRIES_PER_DOMAIN:
        del attempts[:-_MAX_HISTORY_ENTRIES_PER_DOMAIN]

