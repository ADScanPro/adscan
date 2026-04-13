"""Helpers for building focused Kerberos username wordlists.

This module centralizes the logic for:
- loading built-in statistically-likely username lists
- loading the compact ADscan username-format inference wordlist
- generating username candidates from known names and a chosen corporate format
- persisting merged wordlists and source metadata for Kerberos enumeration
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re
from typing import Any
import unicodedata

from adscan_core.username_patterns import (
    USERNAME_PATTERN_LABELS,
    generate_username_candidates_for_name_pairs,
    normalize_username_candidate,
)


STATISTICALLY_LIKELY_BASE_DIR_CANDIDATES: tuple[Path, ...] = (
    Path("/usr/share/wordlists/statistically-likely-usernames"),
    Path("/opt/adscan/wordlists/statistically-likely-usernames"),
)

GENERAL_COMMON_USERNAME_WORDLIST_CANDIDATES: tuple[Path, ...] = (
    Path("/usr/share/wordlists/statistically-likely-usernames/top-formats.txt"),
    Path("/opt/adscan/wordlists/statistically-likely-usernames/top-formats.txt"),
)

_REPO_WORDLIST_ASSET_DIR = Path(__file__).resolve().parents[1] / "assets" / "wordlists"

KERBEROS_FORMAT_INFERENCE_WORDLIST_CANDIDATES: tuple[Path, ...] = (
    Path("/opt/adscan/wordlists/kerberos-format-inference.txt"),
    _REPO_WORDLIST_ASSET_DIR / "kerberos-format-inference.txt",
)

KERBEROS_FORMAT_INFERENCE_METADATA_CANDIDATES: tuple[Path, ...] = (
    Path("/opt/adscan/wordlists/kerberos-format-inference.json"),
    _REPO_WORDLIST_ASSET_DIR / "kerberos-format-inference.json",
)

SUPPORTED_KERBEROS_PATTERN_KEYS: tuple[str, ...] = (
    "single",
    "first.last",
    "firstlast",
    "flast",
    "f.last",
    "firstl",
    "lastfi",
)

LINKEDIN_SUPPORTED_PATTERN_KEYS: tuple[str, ...] = (
    "single",
    "first.last",
    "flast",
    "f.last",
    "firstl",
    "lastfi",
)

STATISTICALLY_LIKELY_PATTERN_FILES: dict[str, str] = {
    "single": "john.txt",
    "first.last": "john.smith.txt",
    "firstlast": "johnsmith.txt",
    "flast": "jsmith.txt",
    "firstl": "johns.txt",
    "lastfi": "smithj.txt",
}


@dataclass(frozen=True)
class KerberosWordlistSourceMetadata:
    """Describe one source that contributed candidates to a generated wordlist."""

    source: str
    pattern_key: str | None
    candidate_count: int
    details: dict[str, Any]


class KerberosUsernameWordlistService:
    """Build focused Kerberos username candidate wordlists."""

    def __init__(self) -> None:
        self._inference_metadata_cache: dict[str, tuple[str, ...]] | None = None

    def get_general_common_wordlist_path(self) -> Path | None:
        """Return the built-in generic Kerberos username wordlist if present."""
        for candidate in GENERAL_COMMON_USERNAME_WORDLIST_CANDIDATES:
            if candidate.exists() and candidate.is_file():
                return candidate
        return None

    def get_format_inference_wordlist_path(self) -> Path | None:
        """Return the compact runtime wordlist used to infer username formats."""
        for candidate in KERBEROS_FORMAT_INFERENCE_WORDLIST_CANDIDATES:
            if candidate.exists() and candidate.is_file():
                return candidate
        return None

    def get_format_inference_metadata_path(self) -> Path | None:
        """Return the metadata mapping inference candidates back to format keys."""
        for candidate in KERBEROS_FORMAT_INFERENCE_METADATA_CANDIDATES:
            if candidate.exists() and candidate.is_file():
                return candidate
        return None

    def load_format_inference_metadata(self) -> dict[str, tuple[str, ...]]:
        """Load and cache ``candidate -> pattern_keys`` mappings for inference."""
        if self._inference_metadata_cache is not None:
            return self._inference_metadata_cache

        metadata_path = self.get_format_inference_metadata_path()
        if metadata_path is None:
            self._inference_metadata_cache = {}
            return self._inference_metadata_cache

        try:
            raw_payload = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self._inference_metadata_cache = {}
            return self._inference_metadata_cache

        candidate_patterns = raw_payload.get("candidate_patterns")
        if not isinstance(candidate_patterns, dict):
            self._inference_metadata_cache = {}
            return self._inference_metadata_cache

        normalized: dict[str, tuple[str, ...]] = {}
        for candidate, raw_patterns in candidate_patterns.items():
            normalized_candidate = normalize_username_candidate(str(candidate or ""))
            if not normalized_candidate:
                continue
            if not isinstance(raw_patterns, list):
                continue
            filtered_patterns = tuple(
                pattern
                for pattern in raw_patterns
                if isinstance(pattern, str) and pattern in SUPPORTED_KERBEROS_PATTERN_KEYS
            )
            if filtered_patterns:
                normalized[normalized_candidate] = filtered_patterns

        self._inference_metadata_cache = normalized
        return normalized

    def rank_inferred_patterns_from_candidates(
        self, candidates: list[str] | set[str] | tuple[str, ...]
    ) -> list[tuple[str, int]]:
        """Rank likely username patterns from observed valid usernames.

        The compact inference wordlist stores a reverse mapping from candidate
        username to the pattern(s) that generated it. We score patterns by how
        many validated usernames map back to each pattern.
        """
        metadata = self.load_format_inference_metadata()
        if not metadata:
            return []

        scores: dict[str, int] = {key: 0 for key in SUPPORTED_KERBEROS_PATTERN_KEYS}
        for raw_candidate in candidates:
            candidate = normalize_username_candidate(str(raw_candidate or ""))
            if not candidate:
                continue
            for pattern_key in metadata.get(candidate, ()):
                scores[pattern_key] = scores.get(pattern_key, 0) + 1

        order = {key: idx for idx, key in enumerate(SUPPORTED_KERBEROS_PATTERN_KEYS)}
        ranked = sorted(
            (
                (pattern_key, score)
                for pattern_key, score in scores.items()
                if score > 0
            ),
            key=lambda item: (-item[1], order.get(item[0], 999), item[0]),
        )
        return ranked

    def get_statistically_likely_wordlist_path(self, pattern_key: str) -> Path | None:
        """Resolve the statistically-likely wordlist for a supported pattern."""
        filename = STATISTICALLY_LIKELY_PATTERN_FILES.get(pattern_key)
        if not filename:
            return None
        for base_dir in STATISTICALLY_LIKELY_BASE_DIR_CANDIDATES:
            candidate = base_dir / filename
            if candidate.exists() and candidate.is_file():
                return candidate
        return None

    def load_candidates_from_file(self, path: Path) -> set[str]:
        """Load normalized username candidates from a text file."""
        candidates: set[str] = set()
        with path.open(encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                candidate = normalize_username_candidate(line)
                if candidate:
                    candidates.add(candidate)
        return candidates

    def generate_candidates_from_names(
        self,
        names: list[tuple[str, str]],
        *,
        pattern_key: str,
    ) -> set[str]:
        """Generate candidates from first/last-name pairs using one pattern."""
        return generate_username_candidates_for_name_pairs(
            names,
            pattern_keys=(pattern_key,),
        )

    def generate_candidates_from_linkedin_names(
        self,
        full_names: list[str],
        *,
        pattern_key: str,
    ) -> set[str]:
        """Generate candidates from LinkedIn-style full names.

        This intentionally mirrors the useful behavior of ``linkedin2username``:
        when a person has more than two tokens, the penultimate token is treated
        as an additional surname candidate. This is important for environments
        where usernames may be derived from either of the last two surnames.
        """
        candidates: set[str] = set()
        for full_name in full_names:
            parsed = self._split_linkedin_name(full_name)
            if not parsed:
                continue
            first = parsed["first"]
            secondary_last = parsed["second"]
            primary_last = parsed["last"]
            for candidate_last in (primary_last, secondary_last):
                if not candidate_last:
                    continue
                generated = generate_username_candidates_for_name_pairs(
                    [(first, candidate_last)],
                    pattern_keys=(pattern_key,),
                )
                candidates.update(generated)
            if pattern_key == "single":
                single = normalize_username_candidate(first)
                if single:
                    candidates.add(single)
        return candidates

    def _split_linkedin_name(self, full_name: str) -> dict[str, str] | None:
        """Normalize and split a LinkedIn full name similarly to linkedin2username."""
        text = str(full_name or "").strip().lower()
        if not text:
            return None
        text = unicodedata.normalize("NFKD", text)
        text = text.encode("ascii", "ignore").decode("ascii")
        text = re.sub(r"\([^()]*\)", "", text)
        text = re.sub(r"[^a-zA-Z -]", "", text)
        text = re.sub(
            r"\b(mr|miss|mrs|phd|prof|professor|md|dr|mba)\b",
            "",
            text,
        )
        tokens = [token for token in re.split(r"[\s-]+", text.strip()) if token]
        if len(tokens) < 2:
            return None
        if len(tokens) > 2:
            return {"first": tokens[0], "second": tokens[-2], "last": tokens[-1]}
        return {"first": tokens[0], "second": "", "last": tokens[-1]}

    def write_generated_wordlist(
        self,
        *,
        kerberos_dir: Path,
        output_name: str,
        candidates: set[str],
        metadata: list[KerberosWordlistSourceMetadata],
        domain: str,
    ) -> Path:
        """Persist a generated Kerberos username wordlist and metadata artifact."""
        kerberos_dir.mkdir(parents=True, exist_ok=True)
        output_path = kerberos_dir / output_name
        output_path.write_text(
            "\n".join(sorted(candidate for candidate in candidates if candidate)) + "\n",
            encoding="utf-8",
        )
        metadata_path = kerberos_dir / f"{output_path.stem}_sources.json"
        metadata_payload = {
            "domain": domain,
            "output_wordlist": output_path.name,
            "total_candidates": len(candidates),
            "sources": [asdict(item) for item in metadata],
        }
        metadata_path.write_text(
            json.dumps(metadata_payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return output_path


def format_supported_pattern_label(pattern_key: str, *, sample_value: str) -> str:
    """Render a friendly label for Kerberos username format selection."""
    from adscan_core.username_patterns import format_username_pattern_option

    return format_username_pattern_option(pattern_key, sample_value)


__all__ = [
    "GENERAL_COMMON_USERNAME_WORDLIST_CANDIDATES",
    "KerberosUsernameWordlistService",
    "KerberosWordlistSourceMetadata",
    "LINKEDIN_SUPPORTED_PATTERN_KEYS",
    "STATISTICALLY_LIKELY_PATTERN_FILES",
    "SUPPORTED_KERBEROS_PATTERN_KEYS",
    "USERNAME_PATTERN_LABELS",
    "format_supported_pattern_label",
]
