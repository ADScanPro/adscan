"""Filename-aware multilingual credential extractor.

Complements CredSweeper by covering three classes of files CredSweeper cannot
structurally handle:

1. Bare-string files — filename is the signal, content has no keyword anchor
   (e.g. ``Pass.txt`` whose entire content is ``sergioxmega``).
2. Multi-line context — keyword on line N, value on line M up to N+5
   (e.g. ``CONTRASENYA.txt`` with ``Cambiada a`` on one line and
   ``Ais_barcelona1`` five lines later).
3. Binary files with a high-value filename — e.g. ``contraseñas.docx``.
   Content cannot be decoded as text; the filename signal is emitted as a
   ``filename_aware/binary_flag`` finding so the operator is alerted.
   CredSweeper's document phase may extract the content independently, but
   lacks the filename signal that this module provides.

Vault/container formats (``.kdbx``, ``.rdp``, ``.gpg``, ``.pfx``) are
intentionally excluded here — ADscan's existing keepass pipeline
(``keepass_artifact_service``, ``share_file_analyzer_service``,
``windows_ai_sensitive_analysis_service``) handles them end-to-end, including
hash extraction, cracking, and credential dump.

Designed to be async-friendly, multilingual, and extensible per language pack.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from adscan_core import telemetry
from adscan_internal import (
    print_info_verbose,
    print_warning_debug,
)
from adscan_internal.services.secret_scoring import (
    ScoreBreakdown,
    ScoringPolicy,
    confidence_label,
    score_finding,
)
from adscan_internal.services.secret_stop_words import ALL_STOP_WORDS
from adscan_core.rich_output import print_exception


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


class FileTier(Enum):
    """Confidence tier derived from the filename signal."""

    STRONG = "strong"   # Pass.txt, CONTRASENYA.txt — content treated as credential
    MEDIUM = "medium"   # passwords.xlsx — extract structured content
    NONE = "none"       # filename gives no signal


@dataclass(frozen=True)
class SecretFinding:
    """A confirmed credential extracted from file content.

    A SecretFinding represents a value that the engine extracted with enough
    confidence to feed into the credential pipeline (validation, attack-path
    materialization, report). It is NOT the same as a SecretIndicator.

    Attributes:
        value: Extracted credential string.
        file_path: Absolute path to the source file.
        line_num: 1-based line number.
        rule: Dotted rule identifier, e.g. ``filename_aware/bare_string``.
        confidence: Human-readable tier — ``"strong"``, ``"moderate"``, or ``"weak"``.
            Derived from ``confidence_score`` via :func:`confidence_label`.
        confidence_score: Continuous score in [0.0, 1.0] from the scoring engine.
        score_breakdown: Per-dimension contributions that sum to ``confidence_score``.
        context_line: The line (or composite snippet) that triggered the finding.
        tier: Filename-tier classification.
    """

    value: str
    file_path: str
    line_num: Optional[int]
    rule: str
    confidence: str
    confidence_score: float
    score_breakdown: ScoreBreakdown
    context_line: str
    tier: FileTier


class IndicatorReason(Enum):
    """Why a file was flagged for manual review without yielding a finding.

    Indicators feed the operator review queue; they NEVER feed the credential
    pipeline and NEVER become attack paths. The distinction is critical to
    preserve the pay-as-you-go guarantee — an attack path implies the engine
    extracted and validated a credential, while an indicator only means the
    engine could not, but the filename suggests the operator should look.
    """

    BINARY_UNPARSEABLE = "binary_unparseable"
    """Filename matches a STRONG-tier pattern but the content cannot be decoded
    as text (e.g. ``contraseñas.docx`` ZIP container). CredSweeper's document
    phase may extract content downstream; this indicator surfaces the filename
    signal that CredSweeper alone lacks."""

    FILENAME_MATCH_NO_EXTRACTION = "filename_match_no_extraction"
    """Filename matches a STRONG-tier pattern, content is text and non-empty,
    but neither bare-string nor multi-line context extraction produced a
    finding. Operator should review manually — content may be encrypted,
    obfuscated, in an unexpected format, or describing rather than containing
    a credential."""


@dataclass(frozen=True)
class SecretIndicator:
    """A signal that a file deserves manual review without an extracted value.

    Indicators are intentionally separate from SecretFinding to prevent the
    review queue from contaminating the credential pipeline.

    Attributes:
        file_path: Absolute path to the source file.
        file_name: Bare filename for display.
        reason: Why this file was surfaced (see :class:`IndicatorReason`).
        detail: Human-readable explanation, suitable for CLI display.
        tier: Filename-tier classification (currently always STRONG).
    """

    file_path: str
    file_name: str
    reason: IndicatorReason
    detail: str
    tier: FileTier


@dataclass(frozen=True)
class SecretIntelligenceResult:
    """Combined output of one :meth:`SecretIntelligenceService.analyze_path` call.

    Splitting findings from indicators is the key contract of this module:
    callers must merge ``findings`` into the credential pipeline and route
    ``indicators`` to the operator review queue (CLI panel, web bucket, report
    appendix). They are never interchangeable.
    """

    findings: list[SecretFinding] = field(default_factory=list)
    indicators: list[SecretIndicator] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Filename pattern packs  (extensible — add language IDs as new keys)
# ---------------------------------------------------------------------------

# STRONG tier: the filename itself is a clear password-bearing signal.
# Values: list of compiled patterns matched against the bare filename (not path).
FILENAME_PATTERNS_STRONG: dict[str, list[re.Pattern[str]]] = {
    "es_password": [
        re.compile(r"(?i)^pass(words?)?[\d._\-]*\."),  # Pass.txt, Pass131224.xlsx, Pass_2024.xlsx
        re.compile(r"(?i)^contrase[ñn]as?(\.|_|-|$)"),
        re.compile(r"(?i)contrasen[yñ]a"),              # Catalan: contrasenya
        re.compile(r"(?i)credenciales?"),
        re.compile(r"(?i)^claves?(\.|_|-|$)"),
    ],
    "de_password": [
        re.compile(r"(?i)kennw[oö]rt(?:er)?"),
        re.compile(r"(?i)passw[oö]rt(?:er)?"),
    ],
    "fr_password": [
        re.compile(r"(?i)mot[\s_-]?de[\s_-]?passe"),
    ],
    "pt_password": [
        re.compile(r"(?i)^senhas?(\.|_|-|$)"),
    ],
    "eus_password": [
        re.compile(r"(?i)pasahitz"),                # Basque
    ],
    "en_password": [
        re.compile(r"(?i)^pwd?(\.|_|-|$)"),
        re.compile(r"(?i)^logins?(\.|_|-|$)"),
    ],
    "en_credentials": [
        re.compile(r"(?i)^creds?(\.|_|-|$)"),
        re.compile(r"(?i)secrets?(\.|_|-|$)"),
    ],
}

# ---------------------------------------------------------------------------
# Multilingual narrative keyword regexes (multi-line extraction)
# ---------------------------------------------------------------------------

# Primary: heading/label keywords that introduce a credential on a following line
NARRATIVE_KEYWORDS: re.Pattern[str] = re.compile(
    r"(?i)\b(?:"
    r"contrase[ñn]a|contrasen[yñ]a|contrasenya|contrasenyes|"
    r"kennw[oö]rt(?:er)?|passw[oö]rt(?:er)?|"
    r"mot\s+de\s+passe|"
    r"senhas?|"
    r"pasahitza|"
    r"password|passwd|"
    r"clau\s+d['']acc[eé]s"
    r")\b"
)

# Secondary: change-verb anchors (signal that the next non-empty line is the new value)
NARRATIVE_VERBS: re.Pattern[str] = re.compile(
    r"(?i)\b(?:"
    r"cambiada|cambiado|canviada|canviat|nueva|nuevo|nova|nou|"
    r"changed|new|updated|reset|set|"
    r"geändert|neue?|"
    r"chang[eé]e?|nouvelle?|"
    r"alterada|nova"
    r")\b"
)

# Size limit: STRONG-tier bare-string files must be smaller than this
_BARE_STRING_MAX_BYTES = 5_000
# Line count limit for bare-string mode
_BARE_STRING_MAX_LINES = 30
# How many lines ahead to look after a narrative keyword
_NARRATIVE_LOOKAHEAD = 5
# Read limit to avoid accidentally slurping large binaries
_FILE_READ_LIMIT_BYTES = 512_000

# Score threshold below which a finding is silenced (replaces the stop-word
# destructive filter for natural-language vocabulary). Findings below this
# threshold have near-zero operational value and produce noise in the pipeline.
# Set to 0.0 to disable; use ADSCAN_SECRET_MIN_SCORE env var to override at
# runtime without a code change.
_DEFAULT_MIN_SCORE: float = 0.2


# ---------------------------------------------------------------------------
# Service class
# ---------------------------------------------------------------------------


class SecretIntelligenceService:
    """Filename-aware multilingual credential extractor.

    Runs independently of CredSweeper and covers the structural blind spots
    described in the module docstring. Instantiate and call ``analyze_path()``.

    Vault/container formats (``.kdbx``, ``.rdp``, ``.gpg``, ``.pfx``) are
    not processed here — they are handled by the dedicated keepass pipeline
    (``keepass_artifact_service``, ``share_file_analyzer_service``).
    """

    # ------------------------------------------------------------------
    # Public async entry point
    # ------------------------------------------------------------------

    async def analyze_path(
        self,
        root: Path,
        *,
        policy: Optional[ScoringPolicy] = None,
    ) -> SecretIntelligenceResult:
        """Walk ``root`` recursively and produce findings + review indicators.

        Designed to coexist with CredSweeper output — the two engines cover
        non-overlapping signal classes. Findings feed the credential pipeline;
        indicators feed the operator review queue and never become attack paths.

        Args:
            root: Root directory (or single file) to walk.
            policy: Optional scoring policy. Defaults to ``ScoringPolicy()``
                (AD default parameters). Phase B will pass a posture-derived
                policy via the orchestrator.

        Returns:
            :class:`SecretIntelligenceResult` with deduplicated findings and
            indicators. Both lists may be empty.
        """
        effective_policy = policy or ScoringPolicy()
        # Store as instance attribute for the duration of this call so
        # helper methods can access it without parameter threading.
        self._active_policy: ScoringPolicy = effective_policy

        findings: list[SecretFinding] = []
        indicators: list[SecretIndicator] = []
        iterator = root.rglob("*") if root.is_dir() else iter([root])

        for path in iterator:
            if not path.is_file():
                continue
            try:
                file_findings, file_indicators = self._analyze_one_file(path)
                findings.extend(file_findings)
                indicators.extend(file_indicators)
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                print_warning_debug(
                    f"[secret_intelligence] Skipping {path.name}: {type(exc).__name__}"
                )
                continue

        deduped_findings = self._dedupe(findings)
        deduped_indicators = self._dedupe_indicators(indicators)
        print_info_verbose(
            "[secret_intelligence] Completed: "
            f"root={root} findings={len(deduped_findings)} "
            f"indicators={len(deduped_indicators)}"
        )
        return SecretIntelligenceResult(
            findings=deduped_findings,
            indicators=deduped_indicators,
        )

    # ------------------------------------------------------------------
    # Per-file dispatch
    # ------------------------------------------------------------------

    def _analyze_one_file(
        self, path: Path
    ) -> tuple[list[SecretFinding], list[SecretIndicator]]:
        """Return ``(findings, indicators)`` for a single file.

        Three exit shapes:

        1. No filename signal → empty findings, empty indicators (CredSweeper's
           content-based pipeline covers these files).
        2. Filename STRONG, content not text → empty findings, one
           ``BINARY_UNPARSEABLE`` indicator.
        3. Filename STRONG, content text → bare-string + multi-line extraction.
           If both yield nothing AND the content is non-empty, emit one
           ``FILENAME_MATCH_NO_EXTRACTION`` indicator so the file surfaces in
           the review queue.
        """
        tier_lang = self._classify_filename(path)
        if tier_lang is None:
            # No filename signal — CredSweeper (content-based) covers this
            return [], []

        content = self._safe_read(path)
        if content is None:
            return [], [SecretIndicator(
                file_path=str(path),
                file_name=path.name,
                reason=IndicatorReason.BINARY_UNPARSEABLE,
                detail="content not decodable as text (likely binary container)",
                tier=FileTier.STRONG,
            )]

        findings: list[SecretFinding] = []
        findings.extend(self._extract_bare_string(path, content))
        findings.extend(self._extract_multi_line_context(path, content))

        if not findings and content.strip():
            # Filename matched STRONG but content yielded nothing. Surface as
            # review-queue item — the operator should look manually because the
            # filename strongly suggests credentials are present.
            return [], [SecretIndicator(
                file_path=str(path),
                file_name=path.name,
                reason=IndicatorReason.FILENAME_MATCH_NO_EXTRACTION,
                detail=(
                    f"filename matches the {tier_lang} pattern but no credential "
                    "was extracted from content"
                ),
                tier=FileTier.STRONG,
            )]

        return findings, []

    # ------------------------------------------------------------------
    # Filename classification
    # ------------------------------------------------------------------

    def _classify_filename(self, path: Path) -> Optional[str]:
        """Return the matching language-pack key for STRONG tier, or None.

        Args:
            path: File path whose ``.name`` is tested.

        Returns:
            Language-pack key string (e.g. ``"es_password"``), or ``None``
            if no STRONG-tier pattern matches.
        """
        name = path.name
        for lang_key, patterns in FILENAME_PATTERNS_STRONG.items():
            for pat in patterns:
                if pat.search(name):
                    return lang_key
        return None

    # ------------------------------------------------------------------
    # Bare-string extraction
    # ------------------------------------------------------------------

    def _extract_bare_string(self, path: Path, content: str) -> list[SecretFinding]:
        """Extract credentials from short STRONG-tier files with no keyword anchor.

        In a file named ``Pass.txt``, every non-comment, non-stop-word line that
        passes the ``_looks_like_password`` heuristic is a candidate. Each
        candidate is scored and only findings that clear the minimum score
        threshold are kept — this replaces the destructive vocabulary stop-list.

        Args:
            path: Source file path.
            content: Already-decoded text content.

        Returns:
            List of findings. Empty when the file is too large or too long.
        """
        try:
            file_size = path.stat().st_size
        except OSError:
            return []
        if file_size > _BARE_STRING_MAX_BYTES:
            return []

        raw_lines = [(ln_no, ln.strip()) for ln_no, ln in enumerate(content.splitlines(), 1) if ln.strip()]
        if len(raw_lines) > _BARE_STRING_MAX_LINES:
            return []

        policy = getattr(self, "_active_policy", ScoringPolicy())
        findings: list[SecretFinding] = []
        for ln_no, line in raw_lines:
            # Skip comment-like lines
            if line.startswith(("#", "//", ";", "--")):
                continue
            stripped = line.strip(" \t\"'`,.;:")
            if not self._looks_like_password(stripped):
                continue
            if stripped.lower() in ALL_STOP_WORDS:
                continue
            breakdown = score_finding(
                value=stripped,
                rule="filename_aware/bare_string",
                tier=FileTier.STRONG,
                has_keyword_context=False,
                policy=policy,
            )
            if breakdown.total < _DEFAULT_MIN_SCORE:
                continue
            findings.append(
                SecretFinding(
                    value=stripped,
                    file_path=str(path),
                    line_num=ln_no,
                    rule="filename_aware/bare_string",
                    confidence=confidence_label(breakdown.total),
                    confidence_score=breakdown.total,
                    score_breakdown=breakdown,
                    context_line=line,
                    tier=FileTier.STRONG,
                )
            )
        return findings

    # ------------------------------------------------------------------
    # Multi-line context extraction
    # ------------------------------------------------------------------

    def _extract_multi_line_context(self, path: Path, content: str) -> list[SecretFinding]:
        """Scan for narrative keywords and grab the value from nearby lines.

        When a STRONG-tier file contains a label like ``"Cambiada a"`` followed by
        a bare value on a later line, CredSweeper misses it because the two pieces
        of information appear on different lines. This method bridges that gap.

        Same-line ``keyword: value`` patterns are deliberately NOT handled here —
        they are CredSweeper custom rules' responsibility (multilingual single-line
        patterns live in ``custom_config.yaml`` with ``use_ml: false``). This method
        focuses exclusively on the cross-line case that CredSweeper structurally
        cannot reach.

        Args:
            path: Source file path.
            content: Already-decoded text content.

        Returns:
            List of findings. One finding per keyword instance at most.
        """
        policy = getattr(self, "_active_policy", ScoringPolicy())
        findings: list[SecretFinding] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines):
            if not NARRATIVE_KEYWORDS.search(line) and not NARRATIVE_VERBS.search(line):
                continue

            # Look ahead up to _NARRATIVE_LOOKAHEAD non-empty lines
            for offset in range(1, _NARRATIVE_LOOKAHEAD + 1):
                look_idx = idx + offset
                if look_idx >= len(lines):
                    break
                candidate = lines[look_idx].strip()
                if not candidate:
                    continue
                stripped = candidate.strip(" \t\"'`,.;:")
                if not self._looks_like_password(stripped):
                    continue
                if stripped.lower() in ALL_STOP_WORDS:
                    break
                breakdown = score_finding(
                    value=stripped,
                    rule="multilang/multi_line_context",
                    tier=FileTier.STRONG,
                    has_keyword_context=True,
                    policy=policy,
                )
                if breakdown.total >= _DEFAULT_MIN_SCORE:
                    findings.append(
                        SecretFinding(
                            value=stripped,
                            file_path=str(path),
                            line_num=look_idx + 1,
                            rule="multilang/multi_line_context",
                            confidence=confidence_label(breakdown.total),
                            confidence_score=breakdown.total,
                            score_breakdown=breakdown,
                            context_line=f"{line.strip()} ... {candidate}",
                            tier=FileTier.STRONG,
                        )
                    )
                break  # one value per keyword/verb instance
        return findings

    # ------------------------------------------------------------------
    # Password-shape heuristic
    # ------------------------------------------------------------------

    @staticmethod
    def _looks_like_password(value: str) -> bool:
        """Return True if ``value`` looks like a credential token.

        Intentionally permissive — false negatives on real creds are worse
        than false positives that the scoring engine will downrank.

        Args:
            value: Candidate string after stripping surrounding punctuation.

        Returns:
            Boolean decision.
        """
        v = value.strip()
        if not (4 <= len(v) <= 120):
            return False
        # Must contain at least one alphanumeric character
        if not re.search(r"[A-Za-z0-9]", v):
            return False
        # Reject bare URLs — those belong to URL extraction, not password extraction
        if v.lower().startswith(("http://", "https://", "ftp://", "file://")):
            return False
        # Reject strings with internal whitespace (natural language phrases, not passwords)
        if " " in v or "\t" in v:
            return False
        return True

    # ------------------------------------------------------------------
    # Safe file reader
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_read(path: Path) -> Optional[str]:
        """Read a file as text, returning ``None`` on binary/decode errors.

        Limits the read to ``_FILE_READ_LIMIT_BYTES`` to avoid accidentally
        processing multi-MB files.

        Args:
            path: File to read.

        Returns:
            Decoded text content, or ``None`` if the file cannot be decoded as
            UTF-8 / Latin-1 text.
        """
        try:
            raw = path.read_bytes()
        except OSError:
            return None
        if not raw:
            return ""
        # Hard size guard: skip files exceeding the analysis limit
        if len(raw) > _FILE_READ_LIMIT_BYTES:
            raw = raw[:_FILE_READ_LIMIT_BYTES]
        # Binary-content heuristic: if more than 30 % of the first 512 bytes are
        # non-printable non-whitespace, treat the file as binary
        sample = raw[:512]
        non_text = sum(1 for b in sample if b < 9 or (13 < b < 32) or b == 127)
        if len(sample) > 0 and non_text / len(sample) > 0.30:
            return None
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            pass
        try:
            return raw.decode("latin-1")
        except UnicodeDecodeError:
            return None

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    @staticmethod
    def _dedupe(findings: list[SecretFinding]) -> list[SecretFinding]:
        """Remove exact duplicates by ``(file_path, value)`` key.

        Preserves the first occurrence (highest-signal extraction wins because
        bare_string runs before multi_line_context).

        Args:
            findings: Raw finding list, possibly with duplicates.

        Returns:
            Deduplicated list in original order.
        """
        seen: set[tuple[str, str]] = set()
        out: list[SecretFinding] = []
        for f in findings:
            key = (f.file_path, f.value)
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out

    @staticmethod
    def _dedupe_indicators(
        indicators: list[SecretIndicator],
    ) -> list[SecretIndicator]:
        """Remove exact duplicates by ``(file_path, reason)`` key.

        Preserves the first occurrence in input order.

        Args:
            indicators: Raw indicator list, possibly with duplicates.

        Returns:
            Deduplicated list in original order.
        """
        seen: set[tuple[str, IndicatorReason]] = set()
        out: list[SecretIndicator] = []
        for ind in indicators:
            key = (ind.file_path, ind.reason)
            if key in seen:
                continue
            seen.add(key)
            out.append(ind)
        return out


__all__ = [
    "FileTier",
    "SecretFinding",
    "SecretIntelligenceService",
    "FILENAME_PATTERNS_STRONG",
    "NARRATIVE_KEYWORDS",
    "NARRATIVE_VERBS",
    "ScoreBreakdown",
    "ScoringPolicy",
]
