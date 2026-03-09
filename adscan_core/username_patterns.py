"""Shared username-pattern helpers for inference and wordlist generation."""

from __future__ import annotations

from collections.abc import Sequence
import re


USERNAME_PATTERN_LABELS: dict[str, str] = {
    "single": "single token",
    "first.last": "firstname.lastname",
    "firstlast": "firstnamelastname",
    "flast": "fLastname",
    "f.last": "f.lastname",
    "lastfirst": "lastnamefirstname",
    "last.first": "lastname.firstname",
    "lastfi": "lastnamef",
    "first3last3": "firlas",
    "first3.last3": "fir.las",
}

DEFAULT_INFERENCE_PATTERN_KEYS: tuple[str, ...] = (
    "single",
    "first.last",
    "firstlast",
    "flast",
    "f.last",
    "lastfirst",
    "last.first",
    "lastfi",
)

DEFAULT_WORDLIST_PATTERN_KEYS: tuple[str, ...] = (
    "firstlast",
    "first.last",
    "first3last3",
    "first3.last3",
    "flast",
    "f.last",
    "lastfirst",
    "last.first",
    "lastfi",
    "single",
)


def normalize_username_candidate(value: str) -> str:
    """Return a conservative normalized username candidate."""
    cleaned = re.sub(r"[^A-Za-z0-9._$-]+", "", str(value or "").strip().lower())
    return cleaned


def split_name_tokens(value: str) -> list[str]:
    """Split a human-readable name/CN into normalized username tokens."""
    text = re.sub(r"\([^)]*\)", " ", str(value or ""))
    text = text.replace(",", " ").replace("'", " ")
    tokens = [
        normalize_username_candidate(part)
        for part in re.split(r"\s+", text.strip())
        if part.strip()
    ]
    return [token for token in tokens if token]


def build_username_pattern_candidates(
    value: str,
    *,
    pattern_keys: Sequence[str] | None = None,
) -> dict[str, str]:
    """Generate username candidates for a name/CN using known pattern keys."""
    tokens = split_name_tokens(value)
    if not tokens:
        return {}

    requested = tuple(pattern_keys or DEFAULT_INFERENCE_PATTERN_KEYS)
    if len(tokens) == 1:
        token = tokens[0]
        return {"single": token} if "single" in requested else {}

    first = tokens[0]
    last = tokens[-1]
    first_initial = first[:1]
    first3 = first[:3]
    last3 = last[:3]

    all_candidates = {
        "single": first,
        "first.last": normalize_username_candidate(f"{first}.{last}"),
        "firstlast": normalize_username_candidate(f"{first}{last}"),
        "flast": normalize_username_candidate(f"{first_initial}{last}"),
        "f.last": normalize_username_candidate(f"{first_initial}.{last}"),
        "lastfirst": normalize_username_candidate(f"{last}{first}"),
        "last.first": normalize_username_candidate(f"{last}.{first}"),
        "lastfi": normalize_username_candidate(f"{last}{first_initial}"),
        "first3last3": normalize_username_candidate(f"{first3}{last3}"),
        "first3.last3": normalize_username_candidate(f"{first3}.{last3}"),
    }
    return {
        key: candidate
        for key, candidate in all_candidates.items()
        if key in requested and candidate
    }


def rank_username_patterns_from_observed_pairs(
    observed_pairs: Sequence[tuple[str, str]],
    *,
    pattern_keys: Sequence[str] | None = None,
) -> list[tuple[str, int]]:
    """Rank username patterns using observed ``display-name -> sam`` pairs."""
    keys = tuple(pattern_keys or DEFAULT_INFERENCE_PATTERN_KEYS)
    scores: dict[str, int] = {key: 0 for key in keys}

    for display_name, samaccountname in observed_pairs:
        name = str(display_name or "").strip()
        sam = normalize_username_candidate(samaccountname)
        if not name or not sam:
            continue
        for pattern_key, candidate in build_username_pattern_candidates(
            name, pattern_keys=keys
        ).items():
            if candidate == sam:
                scores[pattern_key] = scores.get(pattern_key, 0) + 1

    ranked = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
    return [(pattern, score) for pattern, score in ranked if score > 0]


def format_username_pattern_option(pattern_key: str, sample_value: str) -> str:
    """Render a friendly UI option label for a username pattern."""
    candidates = build_username_pattern_candidates(sample_value)
    example = candidates.get(pattern_key) or normalize_username_candidate(sample_value)
    label = USERNAME_PATTERN_LABELS.get(pattern_key, pattern_key)
    return f"{label} (e.g. {example})"


def generate_username_candidates_for_name_pairs(
    names: Sequence[tuple[str, str]],
    *,
    pattern_keys: Sequence[str] | None = None,
) -> set[str]:
    """Generate a de-duplicated username candidate set for first/last name pairs."""
    keys = tuple(pattern_keys or DEFAULT_WORDLIST_PATTERN_KEYS)
    candidates: set[str] = set()
    for first, last in names:
        full_name = f"{str(first or '').strip()} {str(last or '').strip()}".strip()
        for candidate in build_username_pattern_candidates(
            full_name, pattern_keys=keys
        ).values():
            if candidate:
                candidates.add(candidate)
    return candidates
