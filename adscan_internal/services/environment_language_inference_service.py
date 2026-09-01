"""Infer the Active Directory environment's OS-install language from RID signals.

Windows renames its built-in security principals when the operating system is
installed in a non-English language, but their RELATIVE IDENTIFIERS (RIDs) are
fixed and language-independent:

    RID 500  built-in Administrator   ("Administrator" / "Administrador" / ...)
    RID 501  built-in Guest           ("Guest"         / "Invitado"     / ...)
    RID 512  Domain Admins group      ("Domain Admins" / "Administradores del dominio" / ...)
    RID 513  Domain Users group       ("Domain Users"  / "Usuarios del dominio"        / ...)

So the reliable signal is: resolve the object whose SID ends in ``-500`` (and,
as reinforcement, ``-501`` / ``-512`` / ``-513``), read its localized name, and
map that name back to a language via a localized-name table. This is the inverse
of searching AD for the string "Administrator" — that search is CIRCULAR (it
already assumes English) and useless on a Spanish DC where the account is named
"Administrador". We therefore key on the RID, never on the name.

Why this matters for spraying: forced-rotation policies push users toward
``<current-period><year>`` passwords (``March2026``, ``Marzo2026``,
``Verano2026``). Knowing whether the environment is English or Spanish lets the
generator prefer the right language's month/season words instead of always
spraying both, which halves the per-user candidate count where the language is
known — important in ``adscan ci`` (non-interactive), where the operator cannot
be asked.

IMPORTANT NUANCE — the OS-install language is a SMART DEFAULT, not ground truth.
The language Windows was installed in is NOT necessarily the language the
employees choose for their passwords: an English-language OS can host a wholly
Spanish (or Basque, or Catalan) employee base, and vice versa. This module
infers the OS language only; the consumer (spraying) MUST allow an operator
override on top of it. See :func:`set_environment_language`.

Confidence is graded, never certain:

* ``high``   — two or more of the RID 500/501/512/513 signals agree on one
  language (or an operator override was recorded).
* ``medium`` — exactly one RID signal resolved a language.
* ``low``    — nothing resolved; language is ``"unknown"``. We NEVER guess a
  language from a low-confidence signal.

Read order for signals (prefer already-collected data; no new LDAP query):

1. The persisted result in ``domains_data`` (cache / operator override).
2. The authenticated attack graph (``attack_graph.json`` nodes carry
   ``objectid`` = SID and ``samaccountname`` / ``name`` / ``label``).
3. The per-domain membership snapshot (``memberships.json`` → ``sid_to_label``).
4. The unauthenticated user inventory (``users.json`` → each user's ``rid``).

If none of those carry the RID-500 object we return ``"unknown"`` / ``low``
rather than firing an LDAP query — the caller decides whether an extra query is
worth it. In practice the attack graph or the membership snapshot carries the
built-in Administrator in every authenticated scan, so this is L1-testable with
fixtures and costs zero extra DC round-trips.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Mapping

from adscan_core.rich_output import print_exception
from adscan_internal import telemetry
from adscan_internal.rich_output import mark_sensitive, print_info_debug
from adscan_internal.workspaces import domain_subpath


LanguageCode = Literal["en", "es", "unknown"]
Confidence = Literal["high", "medium", "low"]

# Key under ``domains_data[domain]`` where the resolved/override result lives.
_DOMAINS_DATA_KEY = "environment_language"

# Well-known RIDs whose localized NAME reveals the OS-install language. The
# built-in Administrator (500) is the strongest single signal; the others
# reinforce it. Keep them ordered by reliability so the primary signal is 500.
_LANGUAGE_SIGNAL_RIDS: tuple[int, ...] = (500, 501, 512, 513)


# --------------------------------------------------------------------------- #
# Extensible localized-name table.
#
# ONE data structure, keyed by RID then by language code, mapping each
# well-known principal's localized name(s) for that language. Adding a language
# (euskera, català, français, العربية, हिन्दी, ...) is a matter of adding one
# column here — no logic changes. Only EN and ES are populated today (the
# supported set); the rest live in BACKLOG.md until a real environment needs
# them. The reverse index (name -> language) is derived below, so a name is
# never mapped in two places.
#
# Names are the canonical Windows localized strings for each RID. Comparison is
# case-insensitive and accent-sensitive (``casefold``), matching how Windows
# renders them.
# --------------------------------------------------------------------------- #
_LOCALIZED_PRINCIPAL_NAMES: dict[int, dict[str, tuple[str, ...]]] = {
    500: {
        "en": ("Administrator",),
        "es": ("Administrador",),
    },
    501: {
        "en": ("Guest",),
        "es": ("Invitado",),
    },
    512: {
        "en": ("Domain Admins",),
        "es": ("Administradores del dominio",),
    },
    513: {
        "en": ("Domain Users",),
        "es": ("Usuarios del dominio",),
    },
}

# Languages this module can currently INFER (a language must have a name for the
# primary RID 500 to be inferable). Extending the table above extends this set.
SUPPORTED_LANGUAGES: tuple[str, ...] = tuple(
    sorted(_LOCALIZED_PRINCIPAL_NAMES[500].keys())
)


def _build_name_to_language_index() -> dict[int, dict[str, str]]:
    """Derive the reverse ``{rid: {casefolded_name: language}}`` index."""
    index: dict[int, dict[str, str]] = {}
    for rid, by_language in _LOCALIZED_PRINCIPAL_NAMES.items():
        rid_index: dict[str, str] = {}
        for language, names in by_language.items():
            for name in names:
                key = str(name).strip().casefold()
                if key and key not in rid_index:
                    rid_index[key] = language
        index[rid] = rid_index
    return index


_NAME_TO_LANGUAGE_BY_RID: dict[int, dict[str, str]] = _build_name_to_language_index()


@dataclass(frozen=True)
class EnvironmentLanguage:
    """Inferred (or overridden) environment language for one domain.

    Attributes:
        language: ``"en"``, ``"es"`` or ``"unknown"``. ``"unknown"`` means no
            signal resolved a language — NEVER a guess.
        confidence: ``"high"`` (>=2 concurring RID signals or an operator
            override), ``"medium"`` (exactly one RID signal) or ``"low"``
            (nothing resolved / unknown).
        signal: Short human-readable description of the strongest signal used,
            e.g. ``"rid500_name:Administrador"``, ``"operator_override"`` or
            ``"none"``. Diagnostic only.
        source: Where the result came from: ``"attack_graph"``,
            ``"membership_snapshot"``, ``"users_json"``, ``"cache"``,
            ``"operator_override"`` or ``"none"``.
        rid_signals: Mapping of the RID that yielded a language to the inferred
            language, for auditability (e.g. ``{500: "es", 512: "es"}``).
    """

    language: LanguageCode
    confidence: Confidence
    signal: str
    source: str
    rid_signals: dict[int, str]

    def to_serializable(self) -> dict[str, Any]:
        """Return a JSON-serializable dict for ``domains_data`` persistence.

        Only JSON-native types (str / int / dict) are used so the result is safe
        for ``save_workspace_data`` — no sets, no dataclass instances.
        """
        return {
            "language": self.language,
            "confidence": self.confidence,
            "signal": self.signal,
            "source": self.source,
            # JSON object keys must be strings.
            "rid_signals": {str(rid): lang for rid, lang in self.rid_signals.items()},
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

    @classmethod
    def from_serializable(cls, data: Mapping[str, Any]) -> "EnvironmentLanguage | None":
        """Rehydrate from a persisted ``domains_data`` dict, or ``None``."""
        if not isinstance(data, Mapping):
            return None
        language = str(data.get("language") or "").strip().lower()
        if language not in ("en", "es", "unknown"):
            return None
        confidence = str(data.get("confidence") or "").strip().lower()
        if confidence not in ("high", "medium", "low"):
            confidence = "low"
        raw_signals = data.get("rid_signals")
        rid_signals: dict[int, str] = {}
        if isinstance(raw_signals, Mapping):
            for rid_key, lang in raw_signals.items():
                try:
                    rid_signals[int(rid_key)] = str(lang)
                except (TypeError, ValueError):
                    continue
        return cls(
            language=language,  # type: ignore[arg-type]
            confidence=confidence,  # type: ignore[arg-type]
            signal=str(data.get("signal") or "cache"),
            source=str(data.get("source") or "cache"),
            rid_signals=rid_signals,
        )


def _unknown(*, source: str = "none", signal: str = "none") -> EnvironmentLanguage:
    """Return the canonical unknown/low result (never a guess)."""
    return EnvironmentLanguage(
        language="unknown",
        confidence="low",
        signal=signal,
        source=source,
        rid_signals={},
    )


def _rid_from_sid(value: Any) -> int | None:
    """Return the trailing RID of a SID string, or ``None``.

    Mirrors the SID-token parsing used across the codebase
    (``compromise_class._node_rid``): the RID is the last ``-``-separated
    component of a ``S-1-5-21-<auth>-<RID>`` (or ``S-1-5-32-<RID>``) SID.
    """
    if not isinstance(value, str):
        return None
    token = value.strip().upper()
    if not token.startswith("S-1-"):
        return None
    try:
        return int(token.rsplit("-", 1)[-1])
    except (ValueError, IndexError):
        return None


def _language_from_name(rid: int, name: Any) -> str | None:
    """Map a well-known principal's localized name to a language code."""
    if not isinstance(name, str):
        return None
    principal = name.strip()
    if not principal:
        return None
    # Strip common decorations: ``DOMAIN\Administrador``, ``Administrador@corp``.
    principal = principal.split("@", 1)[0].split("\\", 1)[-1].strip()
    if not principal:
        return None
    return _NAME_TO_LANGUAGE_BY_RID.get(rid, {}).get(principal.casefold())


def _grade(rid_signals: dict[int, str]) -> tuple[LanguageCode, Confidence, str]:
    """Reduce per-RID language votes to a (language, confidence, signal).

    * >=2 RID signals agreeing on one language -> that language, ``high``.
    * exactly one RID signal -> that language, ``medium``.
    * zero, or conflicting signals with no clear majority -> ``unknown`` / low.
    """
    if not rid_signals:
        return "unknown", "low", "none"

    votes: dict[str, list[int]] = {}
    for rid, language in rid_signals.items():
        votes.setdefault(language, []).append(rid)

    # Winner = most RID votes; tie -> conflicting, refuse to guess.
    ranked = sorted(votes.items(), key=lambda kv: len(kv[1]), reverse=True)
    top_language, top_rids = ranked[0]
    if len(ranked) > 1 and len(ranked[1][1]) == len(top_rids):
        # Ambiguous: equal support for two languages. Do not guess.
        return "unknown", "low", "conflict"

    if top_language not in ("en", "es"):
        return "unknown", "low", "none"

    # Prefer the primary RID (500) in the signal description when it voted.
    signal_rid = 500 if 500 in top_rids else sorted(top_rids)[0]
    signal = f"rid{signal_rid}_lang:{top_language}"
    confidence: Confidence = "high" if len(top_rids) >= 2 else "medium"
    return top_language, confidence, signal  # type: ignore[return-value]


# --------------------------------------------------------------------------- #
# Signal collection from already-collected data (no new LDAP query).
# Each collector returns ``{rid: language}`` for whatever RID objects it found.
# --------------------------------------------------------------------------- #
def _signals_from_attack_graph(shell: Any, domain: str) -> dict[int, str]:
    """Collect RID->language votes from ``attack_graph.json`` nodes.

    Attack-graph nodes carry ``objectid`` / ``objectId`` (SID) plus
    ``samaccountname`` / ``name`` / ``label``. We read the graph lazily and
    cheaply — a plain JSON read, NOT ``load_attack_graph`` (which runs expensive
    maintenance passes) — because we only need node identity, not path logic.
    """
    votes: dict[int, str] = {}
    try:
        workspace_cwd = str(getattr(shell, "current_workspace_dir", "") or "").strip()
        domains_dir = str(getattr(shell, "domains_dir", "domains") or "domains").strip()
        if not workspace_cwd:
            return votes
        path = domain_subpath(workspace_cwd, domains_dir, domain, "attack_graph.json")
        if not os.path.exists(path):
            return votes
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        print_info_debug(
            "[environment-language] attack_graph read failed for "
            f"{mark_sensitive(domain, 'domain')}: {exc}"
        )
        return votes

    nodes = data.get("nodes") if isinstance(data, dict) else None
    node_iter: Any
    if isinstance(nodes, dict):
        node_iter = nodes.values()
    elif isinstance(nodes, list):
        node_iter = nodes
    else:
        return votes

    for node in node_iter:
        if not isinstance(node, Mapping):
            continue
        props = node.get("properties")
        props = props if isinstance(props, Mapping) else {}
        sid = (
            props.get("objectid")
            or props.get("objectId")
            or node.get("objectid")
            or node.get("objectId")
        )
        rid = _rid_from_sid(sid)
        if rid is None or rid not in _LANGUAGE_SIGNAL_RIDS or rid in votes:
            continue
        name = (
            props.get("samaccountname")
            or node.get("samaccountname")
            or node.get("name")
            or node.get("label")
        )
        language = _language_from_name(rid, name)
        if language:
            votes[rid] = language
    return votes


def _signals_from_membership_snapshot(shell: Any, domain: str) -> dict[int, str]:
    """Collect RID->language votes from ``memberships.json`` (``sid_to_label``).

    Reads the file directly (a plain JSON read of the ``sid_to_label`` map)
    rather than through ``load_membership_snapshot``: we only need SID->name
    identity, and the full loader runs graph-preparation passes and keeps a
    process-global cache that we neither need nor want to perturb here.
    """
    votes: dict[int, str] = {}
    try:
        workspace_cwd = str(getattr(shell, "current_workspace_dir", "") or "").strip()
        domains_dir = str(getattr(shell, "domains_dir", "domains") or "domains").strip()
        if not workspace_cwd:
            return votes
        path = domain_subpath(workspace_cwd, domains_dir, domain, "memberships.json")
        if not os.path.exists(path):
            return votes
        with open(path, "r", encoding="utf-8") as handle:
            snapshot = json.load(handle)
    except (OSError, ValueError) as exc:
        print_info_debug(
            "[environment-language] memberships.json read failed for "
            f"{mark_sensitive(domain, 'domain')}: {exc}"
        )
        return votes
    if not isinstance(snapshot, dict):
        return votes
    sid_to_label = snapshot.get("sid_to_label")
    if not isinstance(sid_to_label, dict):
        return votes
    for sid, label in sid_to_label.items():
        rid = _rid_from_sid(sid)
        if rid is None or rid not in _LANGUAGE_SIGNAL_RIDS or rid in votes:
            continue
        language = _language_from_name(rid, label)
        if language:
            votes[rid] = language
    return votes


def _signals_from_users_json(shell: Any, domain: str) -> dict[int, str]:
    """Collect the RID-500 vote from the unauth ``users.json`` inventory.

    ``users.json`` (the authenticated/unauth canonical inventory written by
    ``unauth_inventory.write_users_json``) stores per-user records carrying
    ``samaccountname`` and ``rid``. Only the RID-bearing records are useful here
    — ``users.txt`` is a bare name list with no RID, so it cannot be used to
    identify the built-in Administrator without circular name matching.
    """
    votes: dict[int, str] = {}
    try:
        workspace_cwd = str(getattr(shell, "current_workspace_dir", "") or "").strip()
        domains_dir = str(getattr(shell, "domains_dir", "domains") or "domains").strip()
        if not workspace_cwd:
            return votes
        path = domain_subpath(workspace_cwd, domains_dir, domain, "users.json")
        if not os.path.exists(path):
            return votes
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        print_info_debug(
            "[environment-language] users.json read failed for "
            f"{mark_sensitive(domain, 'domain')}: {exc}"
        )
        return votes

    if not isinstance(data, list):
        return votes
    for record in data:
        if not isinstance(record, Mapping):
            continue
        try:
            rid = int(record.get("rid")) if record.get("rid") is not None else None
        except (TypeError, ValueError):
            rid = None
        if rid is None or rid not in _LANGUAGE_SIGNAL_RIDS or rid in votes:
            continue
        language = _language_from_name(rid, record.get("samaccountname"))
        if language:
            votes[rid] = language
    return votes


# --------------------------------------------------------------------------- #
# domains_data access (case-insensitive; JSON-native persistence only).
# --------------------------------------------------------------------------- #
def _get_domain_entry(shell: Any, domain: str) -> dict[str, Any] | None:
    """Return the mutable per-domain dict (case-insensitive), or ``None``."""
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return None
    domain_key = str(domain or "").strip()
    if not domain_key:
        return None
    if domain_key in domains_data and isinstance(domains_data[domain_key], dict):
        return domains_data[domain_key]
    normalized = domain_key.casefold()
    for key, value in domains_data.items():
        if str(key).strip().casefold() == normalized and isinstance(value, dict):
            return value
    return None


def _persist(shell: Any, domain: str, result: EnvironmentLanguage) -> None:
    """Persist a result under ``domains_data[domain]["environment_language"]``.

    Best-effort: creates the domain entry if missing. Stores only JSON-native
    types so ``save_workspace_data`` never chokes. Does NOT itself call
    ``save_workspace_data`` — the caller's autosave persists it, matching the
    idiom of the other per-domain state services.
    """
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return
    entry = _get_domain_entry(shell, domain)
    if entry is None:
        entry = {}
        domains_data[str(domain or "").strip()] = entry
    entry[_DOMAINS_DATA_KEY] = result.to_serializable()


def _read_cache(shell: Any, domain: str) -> EnvironmentLanguage | None:
    """Read a previously persisted result (cache or override), or ``None``."""
    entry = _get_domain_entry(shell, domain)
    if entry is None:
        return None
    raw = entry.get(_DOMAINS_DATA_KEY)
    if not isinstance(raw, Mapping):
        return None
    hydrated = EnvironmentLanguage.from_serializable(raw)
    if hydrated is None:
        return None
    # An operator override keeps its provenance so consumers can tell it apart
    # from a machine inference; a plain inference cache-hit is relabelled
    # ``"cache"`` so the caller knows it was not freshly re-inferred this call.
    if hydrated.source == "operator_override":
        return hydrated
    return EnvironmentLanguage(
        language=hydrated.language,
        confidence=hydrated.confidence,
        signal=hydrated.signal,
        source="cache",
        rid_signals=hydrated.rid_signals,
    )


# --------------------------------------------------------------------------- #
# Public API.
# --------------------------------------------------------------------------- #
def infer_environment_language(shell: Any, domain: str) -> EnvironmentLanguage:
    """Infer the OS-install language from already-collected AD RID signals.

    Does NOT read or write the cache — this is the pure inference step. Use
    :func:`get_environment_language` for the cache-first path used by consumers.

    Reads (in order, stopping only to merge votes) the attack graph, the
    membership snapshot and the unauth user inventory for the RID 500/501/512/513
    objects, maps each object's localized name to a language, and grades the
    result by how many RID signals agree.

    Args:
        shell: Active shell exposing ``current_workspace_dir`` / ``domains_dir``.
        domain: Target domain to infer for.

    Returns:
        An :class:`EnvironmentLanguage`. ``language="unknown"`` / ``low`` when no
        RID-bearing built-in object is present in the collected data — never a
        guess, and never a new LDAP query.
    """
    votes: dict[int, str] = {}
    source = "none"
    try:
        for collector, collector_source in (
            (_signals_from_attack_graph, "attack_graph"),
            (_signals_from_membership_snapshot, "membership_snapshot"),
            (_signals_from_users_json, "users_json"),
        ):
            found = collector(shell, domain)
            for rid, language in found.items():
                if rid not in votes:
                    votes[rid] = language
                    if source == "none":
                        source = collector_source
            # RID 500 is the primary signal; once we have it plus a reinforcer,
            # we already have enough for high confidence.
            if 500 in votes and len(votes) >= 2:
                break
    except Exception as exc:  # noqa: BLE001 - best-effort inference, never abort caller
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(
            "[environment-language] inference failed for "
            f"{mark_sensitive(domain, 'domain')}: {exc}"
        )
        return _unknown()

    language, confidence, signal = _grade(votes)
    if language == "unknown":
        return _unknown(source=source if votes else "none", signal=signal)
    return EnvironmentLanguage(
        language=language,
        confidence=confidence,
        signal=signal,
        source=source,
        rid_signals=dict(votes),
    )


def get_environment_language(shell: Any, domain: str) -> EnvironmentLanguage:
    """Return the cached/overridden language, inferring + persisting if absent.

    Cache-first: if ``domains_data[domain]["environment_language"]`` already
    holds a result (a prior inference OR an operator override), it is returned
    unchanged and NO re-inference happens. Otherwise this infers from collected
    data and persists the result (even ``unknown`` — so a domain with no signal
    is not re-scanned every call; a later scan that adds the built-in object can
    be picked up by clearing the key or calling :func:`infer_environment_language`
    directly).

    This is the entry point spraying (and future consumers) should call.

    Args:
        shell: Active shell.
        domain: Target domain.

    Returns:
        The resolved :class:`EnvironmentLanguage`.
    """
    cached = _read_cache(shell, domain)
    if cached is not None:
        return cached
    result = infer_environment_language(shell, domain)
    _persist(shell, domain, result)
    return result


def set_environment_language(
    shell: Any,
    domain: str,
    language: str,
    *,
    source: str = "operator_override",
) -> EnvironmentLanguage:
    """Record an explicit language for a domain (operator override), persisted.

    Use this when the operator knows the password language differs from the
    OS-install language (an English-language OS with a Spanish/Basque/Catalan
    employee base, or vice versa) — the exact mismatch the module docstring
    warns about. The override is persisted like any inference and wins over it
    on the next :func:`get_environment_language` (cache-first) call.

    Args:
        shell: Active shell.
        domain: Target domain.
        language: ``"en"``, ``"es"`` or ``"unknown"``. Any other value raises.
        source: Provenance tag; defaults to ``"operator_override"``.

    Returns:
        The persisted :class:`EnvironmentLanguage` (``confidence="high"`` for an
        explicit ``en``/``es`` override; ``low`` for ``unknown``).

    Raises:
        ValueError: If ``language`` is not one of the accepted values.
    """
    normalized = str(language or "").strip().lower()
    if normalized not in ("en", "es", "unknown"):
        raise ValueError(
            f"unsupported language {language!r}; expected one of en, es, unknown"
        )
    confidence: Confidence = "low" if normalized == "unknown" else "high"
    result = EnvironmentLanguage(
        language=normalized,  # type: ignore[arg-type]
        confidence=confidence,
        signal=source,
        source=source,
        rid_signals={},
    )
    _persist(shell, domain, result)
    return result


def spray_languages_for(
    shell: Any,
    domain: str,
    *,
    default: tuple[str, ...] = ("en", "es"),
) -> tuple[str, ...]:
    """Return the ordered language list a spray should generate for a domain.

    Convenience adapter for the spraying consumer: resolves the environment
    language cache-first and translates it into the ``languages`` tuple the
    month/season generator expects.

    * A confident ``en``/``es`` result -> just that language (halves the
      per-user candidate count where the language is known).
    * ``unknown`` / ``low`` -> the ``default`` (both languages), because a spray
      must never silently DROP a language it is unsure about.

    Args:
        shell: Active shell.
        domain: Target domain.
        default: Fallback language order when the environment language is
            unknown or low-confidence.

    Returns:
        An ordered, de-duplicated tuple of language codes.
    """
    resolved = get_environment_language(shell, domain)
    if resolved.language in ("en", "es") and resolved.confidence in ("high", "medium"):
        return (resolved.language,)
    return default


__all__ = [
    "Confidence",
    "EnvironmentLanguage",
    "LanguageCode",
    "SUPPORTED_LANGUAGES",
    "get_environment_language",
    "infer_environment_language",
    "set_environment_language",
    "spray_languages_for",
]
