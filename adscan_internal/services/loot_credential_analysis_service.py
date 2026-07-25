"""Shared post-loot credential analysis service for SMB and WinRM.

This layer is intentionally protocol-agnostic. Callers provide a local
``loot_dir`` plus protocol-specific persistence paths and source labels.
The service then handles:

- engine selection (`CredSweeper` / `AI` / `CredSweeper + AI` / `Skip`)
- optional AI historical context reuse
- optional deeper AI pass
- normalization and merge of findings
- SecretIntelligenceService pass (filename-aware, always runs alongside CredSweeper)
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.prompt import Confirm

from adscan_core import telemetry
from adscan_internal import (
    print_info,
    print_info_debug,
    print_warning,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.credsweeper_service import (
    CREDSWEEPER_RULES_PROFILE_FILESYSTEM_DOC,
    CREDSWEEPER_RULES_PROFILE_FILESYSTEM_TEXT,
)
from adscan_internal.services.domain_posture import get_posture
from adscan_internal.services.secret_intelligence_service import (
    SecretFinding,
    SecretIndicator,
    SecretIntelligenceService,
)
from adscan_internal.services.secret_scoring import (
    ScoringPolicy,
    is_cs_custom_rule,
    score_cs_finding,
)
from adscan_internal.services.share_loot_ai_analysis_service import (
    ShareLootAICredentialFinding,
    ShareLootAIAnalysisService,
)
from adscan_core.rich_output import print_exception

ENGINE_CREDSWEEPER = "credsweeper"
ENGINE_AI = "ai"
ENGINE_BOTH = "credsweeper_plus_ai"
ENGINE_SKIP = "skip"


@dataclass(frozen=True)
class LootCredentialAnalysisResult:
    """Normalized result for one post-loot credential analysis phase.

    ``findings`` feeds the credential pipeline (validation, attack-path
    materialization). ``indicators`` is a separate list of files surfaced for
    operator review without an extracted credential — these never feed the
    credential pipeline and never become attack paths. ``secret_findings``
    carries the rich :class:`SecretFinding` objects produced by
    :class:`SecretIntelligenceService` (with confidence_score and
    score_breakdown) so the CLI can render the ranked tier panels.
    """

    analysis_engine: str
    findings: dict[str, list[tuple[Any, Any, Any, Any, Any]]]
    ai_findings: list[ShareLootAICredentialFinding]
    ai_attempted: bool
    ai_success: bool | None
    used_prior_context: bool
    indicators: list[SecretIndicator] = field(default_factory=list)
    secret_findings: list[SecretFinding] = field(default_factory=list)


def is_dev_loot_analysis_mode(*, shell: Any) -> bool:
    """Return whether dev-mode selectors should be shown for loot analysis."""
    session_env = str(getattr(shell, "session_env", "") or "").strip().lower()
    if session_env == "dev":
        return True
    return str(__import__("os").getenv("ADSCAN_SESSION_ENV", "") or "").strip().lower() == "dev"


def select_loot_credential_analysis_engine(
    *,
    shell: Any,
    analysis_context: dict[str, Any],
    phase: str,
    phase_label: str,
    candidate_files: int,
) -> str:
    """Resolve the post-loot credential engine independently per phase."""
    phase_engines = analysis_context.setdefault("credential_analysis_engine_by_phase", {})
    cached_engine = str(dict(phase_engines).get(phase, "") or "").strip()
    if cached_engine:
        print_info_debug(
            "Post-loot credential analysis engine reused from phase cache: "
            f"phase={mark_sensitive(phase_label, 'text')} "
            f"candidate_files={candidate_files} engine={mark_sensitive(cached_engine, 'text')}"
        )
        return cached_engine

    ai_configured = bool(analysis_context.get("ai_configured"))
    selector = getattr(shell, "_questionary_select", None)
    selection_reason = "interactive_default"
    if getattr(shell, "auto", False):
        selected = ENGINE_CREDSWEEPER
        selection_reason = "shell_auto_mode"
    else:
        if not callable(selector):
            selected = ENGINE_CREDSWEEPER
            selection_reason = "questionary_select_unavailable"
        elif not ai_configured:
            selected_idx = selector(
                f"Credential analysis engine for {phase_label}:",
                ["CredSweeper (default)", "Skip credential analysis"],
                default_idx=0,
            )
            selected = ENGINE_SKIP if selected_idx == 1 else ENGINE_CREDSWEEPER
            selection_reason = (
                "ai_unavailable_skip_selected"
                if selected == ENGINE_SKIP
                else "ai_unavailable_default_credsweeper"
            )
        else:
            selected_idx = selector(
                f"Credential analysis engine for {phase_label}:",
                [
                    "CredSweeper (default)",
                    "AI (Codex on local loot)",
                    "CredSweeper + AI",
                    "Skip credential analysis",
                ],
                default_idx=0,
            )
            if selected_idx == 1:
                selected = ENGINE_AI
            elif selected_idx == 2:
                selected = ENGINE_BOTH
            elif selected_idx == 3:
                selected = ENGINE_SKIP
            else:
                selected = ENGINE_CREDSWEEPER
            selection_reason = f"interactive_idx_{selected_idx}"
    phase_engines[phase] = selected
    print_info_debug(
        "Post-loot credential analysis engine selected: "
        f"phase={mark_sensitive(phase_label, 'text')} "
        f"candidate_files={candidate_files} engine={mark_sensitive(selected, 'text')} "
        f"ai_configured={ai_configured} selector_available={callable(selector)} "
        f"reason={mark_sensitive(selection_reason, 'text')}"
    )
    return selected


def select_dev_ai_history_action(
    *,
    shell: Any,
    phase_label: str,
    history_path: str,
    prior_findings: int,
) -> str:
    """Ask whether unchanged-loot AI should use prior context in dev mode."""
    if not is_dev_loot_analysis_mode(shell=shell):
        return "use_context"
    selector = getattr(shell, "_questionary_select", None)
    if not callable(selector):
        return "use_context"
    selected_idx = selector(
        (
            "AI prior-context policy:\n"
            f"Phase: {phase_label}\n"
            f"History: {history_path}\n"
            f"Prior findings: {prior_findings}"
        ),
        [
            "Use prior AI context (default)",
            "Run fresh AI without prior context",
        ],
        default_idx=0,
    )
    if selected_idx == 1:
        return "fresh"
    return "use_context"


def should_run_deeper_ai_loot_pass(
    *,
    shell: Any,
    phase_label: str,
    findings_count: int,
) -> bool:
    """Ask whether AI should run one deeper pass on the same loot."""
    if findings_count <= 0 or getattr(shell, "auto", False):
        return False
    prompt = (
        f"AI found {findings_count} credential-like finding(s) in {phase_label}. "
        "Do you want to run one deeper AI pass on the same loot to search for more?"
    )
    confirmer = getattr(shell, "_questionary_confirm", None)
    if callable(confirmer):
        return bool(confirmer(prompt, default=False))
    return Confirm.ask(prompt, default=False)


def merge_grouped_credential_findings(
    *findings_groups: dict[str, list[tuple[str, float | None, str, int, str]]],
) -> dict[str, list[tuple[str, float | None, str, int, str]]]:
    """Merge grouped findings from multiple passes."""
    merged: dict[str, list[tuple[str, float | None, str, int, str]]] = {}
    seen: set[tuple[str, str, int | None, str]] = set()
    for findings in findings_groups:
        if not isinstance(findings, dict):
            continue
        for rule_name, entries in findings.items():
            if not isinstance(entries, list):
                continue
            bucket = merged.setdefault(str(rule_name), [])
            for entry in entries:
                if not isinstance(entry, tuple) or len(entry) < 5:
                    continue
                dedup_key = (
                    str(rule_name),
                    str(entry[0] or ""),
                    int(entry[3] or 0),
                    str(entry[4] or ""),
                )
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                bucket.append(entry)
    return merged


def normalize_secret_intelligence_findings_to_grouped_credentials(
    findings: list[SecretFinding],
) -> dict[str, list[tuple[str, float | None, str, int | None, str]]]:
    """Convert :class:`SecretFinding` objects into the grouped credential format.

    The grouped format is:
    ``{rule_name: [(value, ml_probability, context_line, line_num, file_path), ...]}``

    The second slot is named ``ml_probability`` for compatibility with the
    CredSweeper-shaped tuple, but the spray pipeline treats it as a generic
    [0.0, 1.0] confidence prior used for prioritization and dedup
    (see ``normalize_credsweeper_ml_probability`` in
    ``adscan_internal.cli.creds``). We populate it with the deterministic
    :attr:`SecretFinding.confidence_score` from the scoring engine so the
    existing spray prioritization, deduplication, and lockout-aware filters
    operate on SI findings as first-class citizens — direct credentials
    rank above spray candidates above permutation seeds without any
    additional plumbing in the spray code path.

    Args:
        findings: Raw SecretFinding list from SecretIntelligenceService.

    Returns:
        Dict keyed by rule name, values are 5-tuples in the CredSweeper format.
    """
    normalized: dict[str, list[tuple[str, float | None, str, int | None, str]]] = {}
    seen: set[tuple[str, str, int | None, str]] = set()
    for finding in findings:
        rule_key = f"secret_intel/{finding.rule}"
        dedup_key = (finding.value, finding.file_path, finding.line_num, rule_key)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        normalized.setdefault(rule_key, []).append(
            (
                finding.value,
                float(finding.confidence_score),
                finding.context_line,
                finding.line_num,
                finding.file_path,
            )
        )
    return normalized


def _rescore_cs_custom_findings(
    findings: dict[str, list[tuple]],
    policy: "ScoringPolicy",
) -> dict[str, list[tuple]]:
    """Replace ``ml_prob=0.0`` with a computed :func:`score_cs_finding` score
    for every CredSweeper custom-rule finding.

    CredSweeper primary findings (JWT, AWS keys, etc.) carry real ML
    probabilities and are left untouched. Custom rule findings carry
    ``ml_prob=0.0`` by default — this function populates them with a
    policy-aware :class:`ScoreBreakdown` total so they participate in the
    same tier display as :class:`SecretIntelligenceService` findings.

    Args:
        findings: Grouped credential dict from the CredSweeper pass.
        policy: AD password policy derived from posture (or defaults).

    Returns:
        A new dict with the same structure. Custom-rule entries have their
        second tuple element replaced with the computed score.
    """
    rescored: dict[str, list[tuple]] = {}
    for rule_name, entries in findings.items():
        if not is_cs_custom_rule(rule_name):
            # Primary rule — keep original ML probability unchanged
            rescored[rule_name] = entries
            continue
        rescored_entries: list[tuple] = []
        for entry in entries:
            if len(entry) < 5:
                rescored_entries.append(entry)
                continue
            value, _ml_prob, context_line, line_num, file_path = entry[:5]
            if not value:
                rescored_entries.append(entry)
                continue
            breakdown = score_cs_finding(
                value=str(value),
                rule_name=rule_name,
                policy=policy,
            )
            rescored_entries.append(
                (value, float(breakdown.total), context_line, line_num, file_path)
            )
        rescored[rule_name] = rescored_entries
    return rescored


def _run_secret_intelligence_pass(
    loot_dir: str,
    *,
    scoring_policy: "ScoringPolicy | None" = None,
) -> tuple[
    dict[str, list[tuple[str, float | None, str, int | None, str]]],
    list[SecretIndicator],
    list[SecretFinding],
]:
    """Run SecretIntelligenceService over the loot directory synchronously.

    SecretIntelligenceService exposes an ``async def analyze_path()`` entry
    point. This wrapper runs it inside a temporary event loop so it can be
    called from the sync ``run_loot_credential_analysis`` orchestrator without
    nesting loops.

    Args:
        loot_dir: Absolute path to the loot directory.
        scoring_policy: Optional posture-derived :class:`ScoringPolicy`. When
            ``None`` SI uses its built-in defaults (Windows 2003 baseline).
            The orchestrator passes a posture-derived policy when available.

    Returns:
        Tuple ``(grouped_findings, indicators)``. ``grouped_findings`` is the
        CredSweeper-shaped dict that merges into the credential pipeline.
        ``indicators`` is the operator review queue — files surfaced because
        their filename suggests credentials but no value was extracted.
        Both are empty on failure.
    """
    try:
        svc = SecretIntelligenceService()
        si_result = asyncio.run(svc.analyze_path(Path(loot_dir), policy=scoring_policy))
        si_grouped = normalize_secret_intelligence_findings_to_grouped_credentials(
            si_result.findings
        )
        total = sum(len(v) for v in si_grouped.values())
        print_info_debug(
            "[secret_intelligence] Pass completed: "
            f"loot_dir={loot_dir} total_findings={total} "
            f"grouped_rules={len(si_grouped)} "
            f"indicators={len(si_result.indicators)}"
        )
        return si_grouped, list(si_result.indicators), list(si_result.findings)
    except RuntimeError as exc:
        # asyncio.run() raises RuntimeError when called inside an existing loop.
        # In that case, fall back to creating a dedicated loop to avoid breaking
        # the caller's async context.
        if "cannot be called from a running event loop" not in str(exc):
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(
                f"[secret_intelligence] Pass skipped due to error: {type(exc).__name__}"
            )
            return {}, [], []
        try:
            loop = asyncio.new_event_loop()
            try:
                svc = SecretIntelligenceService()
                si_result = loop.run_until_complete(
                    svc.analyze_path(Path(loot_dir), policy=scoring_policy)
                )
                si_grouped = normalize_secret_intelligence_findings_to_grouped_credentials(
                    si_result.findings
                )
                total = sum(len(v) for v in si_grouped.values())
                print_info_debug(
                    "[secret_intelligence] Pass completed (dedicated loop): "
                    f"loot_dir={loot_dir} total_findings={total} "
                    f"grouped_rules={len(si_grouped)} "
                    f"indicators={len(si_result.indicators)}"
                )
                return si_grouped, list(si_result.indicators), list(si_result.findings)
            finally:
                loop.close()
        except Exception as inner_exc:  # noqa: BLE001
            telemetry.capture_exception(inner_exc)
            print_exception(exception=inner_exc)
            print_info_debug(
                f"[secret_intelligence] Pass skipped (dedicated loop error): {type(inner_exc).__name__}"
            )
            return {}, [], []
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(
            f"[secret_intelligence] Pass skipped due to error: {type(exc).__name__}"
        )
        return {}, []


def parse_ai_loot_local_source(
    *,
    loot_dir: str,
    local_source: str,
    line_number: int | None,
) -> tuple[str, int | None]:
    """Resolve one AI-reported local source path into an absolute loot file path."""
    raw_source = str(local_source or "").strip()
    if not raw_source:
        return "", None
    resolved_line = line_number if isinstance(line_number, int) and line_number > 0 else None
    path_part = raw_source
    if resolved_line is None and ":" in raw_source:
        maybe_path, maybe_line = raw_source.rsplit(":", 1)
        try:
            parsed_line = int(maybe_line)
        except ValueError:
            parsed_line = None
        if parsed_line and parsed_line > 0:
            path_part = maybe_path
            resolved_line = parsed_line
    absolute_path = str(Path(loot_dir, path_part).resolve(strict=False))
    return absolute_path, resolved_line


def normalize_ai_loot_findings_to_grouped_credentials(
    *,
    loot_dir: str,
    findings: list[Any],
) -> dict[str, list[tuple[str, float | None, str, int | None, str]]]:
    """Normalize AI loot findings into the grouped credential structure used by UX."""
    normalized: dict[str, list[tuple[str, float | None, str, int | None, str]]] = {}
    seen: set[tuple[str, str, int | None, str]] = set()
    for finding in findings:
        secret = str(getattr(finding, "secret", "") or "").strip()
        if not secret:
            continue
        absolute_path, resolved_line = parse_ai_loot_local_source(
            loot_dir=loot_dir,
            local_source=str(getattr(finding, "local_source", "") or "").strip(),
            line_number=getattr(finding, "line_number", None),
        )
        if not absolute_path:
            continue
        evidence = str(getattr(finding, "evidence", "") or "").strip()
        username = str(getattr(finding, "username", "") or "").strip()
        if username:
            evidence = f"user={username} | {evidence}" if evidence else f"user={username}"
        grouped_key = (
            str(getattr(finding, "credential_type", "") or "ai_credential").strip().lower()
            or "ai_credential"
        )
        dedupe_key = (secret, absolute_path, resolved_line, grouped_key)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        normalized.setdefault(grouped_key, []).append(
            (secret, None, evidence, resolved_line, absolute_path)
        )
    return normalized


def run_loot_credential_analysis(
    shell: Any,
    *,
    domain: str,
    loot_dir: str,
    phase: str,
    phase_label: str,
    candidate_files: int,
    analysis_context: dict[str, Any],
    ai_history_path: str,
    credsweeper_path: str,
    credsweeper_output_dir: str,
    jobs: int,
    credsweeper_findings: dict[str, list[tuple[Any, Any, Any, Any, Any]]] | None = None,
) -> LootCredentialAnalysisResult:
    """Run the configured credential analysis engine for one local loot directory.

    SecretIntelligenceService always runs alongside CredSweeper (merge mode).
    Its findings cover structural blind spots (bare-string files, multi-line
    context, vault containers) that CredSweeper cannot detect regardless of rules.
    """
    analysis_engine = select_loot_credential_analysis_engine(
        shell=shell,
        analysis_context=analysis_context,
        phase=phase,
        phase_label=phase_label,
        candidate_files=candidate_files,
    )
    findings = dict(credsweeper_findings or {})
    indicators: list[SecretIndicator] = []
    secret_findings: list[SecretFinding] = []
    ai_attempted = False
    ai_success: bool | None = None
    used_prior_context = False

    if analysis_engine == ENGINE_SKIP:
        print_info(
            f"Skipping credential analysis for {mark_sensitive(phase_label, 'text')} after loot acquisition."
        )
        return LootCredentialAnalysisResult(
            analysis_engine=analysis_engine,
            findings={},
            ai_findings=[],
            ai_attempted=False,
            ai_success=None,
            used_prior_context=False,
        )

    # Resolve scoring policy once — used for both CS custom rescoring and SI.
    # Position: before the CS pass so that CS custom findings are rescored
    # with the same policy that SI uses.
    scoring_policy: ScoringPolicy | None = None
    if analysis_engine in {ENGINE_CREDSWEEPER, ENGINE_BOTH}:
        try:
            posture = get_posture(getattr(shell, "domains_data", None) or {}, domain=domain)
            scoring_policy = ScoringPolicy.from_password_policy(
                getattr(posture, "password_policy", None)
            )
            print_info_debug(
                "[scoring] Policy resolved before CS+SI passes: "
                f"min_length={scoring_policy.min_length} "
                f"require_complexity={scoring_policy.require_complexity} "
                f"source={scoring_policy.source}"
            )
        except Exception as _exc:  # noqa: BLE001
            telemetry.capture_exception(_exc)
            print_exception(exception=_exc)
            print_info_debug(
                f"[scoring] Policy lookup failed; using defaults: {type(_exc).__name__}"
            )

    if analysis_engine in {ENGINE_CREDSWEEPER, ENGINE_BOTH} and not findings:
        credsweeper_service = shell._get_credsweeper_service()
        findings = credsweeper_service.analyze_path_with_options(
            loot_dir,
            credsweeper_path=credsweeper_path,
            json_output_dir=credsweeper_output_dir,
            include_custom_rules=True,
            rules_profile=(
                CREDSWEEPER_RULES_PROFILE_FILESYSTEM_DOC
                if "document" in phase
                else CREDSWEEPER_RULES_PROFILE_FILESYSTEM_TEXT
            ),
            custom_ml_threshold="0.0",
            doc="document" in phase,
            jobs=jobs,
        )
        # Rescore CS custom rule findings — replace ml_prob=0.0 with a
        # policy-aware confidence_score so they rank in the same tier system
        # as SI findings (Direct / Spray / Seeds).
        if findings and scoring_policy is not None:
            findings = _rescore_cs_custom_findings(findings, scoring_policy)
            print_info_debug(
                "[scoring] CS custom findings rescored: "
                f"phase={mark_sensitive(phase_label, 'text')}"
            )

    # Always run SecretIntelligenceService alongside CredSweeper — covers the
    # bare-string / multi-line / binary cases CredSweeper structurally cannot handle.
    # Findings merge into the credential pipeline; indicators stay separate as
    # operator review-queue items (never become attack paths).
    # scoring_policy was already resolved before the CS pass and is reused here.
    if analysis_engine in {ENGINE_CREDSWEEPER, ENGINE_BOTH}:
        si_grouped, si_indicators, si_findings = _run_secret_intelligence_pass(
            loot_dir, scoring_policy=scoring_policy
        )
        if si_grouped:
            findings = merge_grouped_credential_findings(findings, si_grouped)
            si_total = sum(len(v) for v in si_grouped.values())
            print_info_debug(
                "[secret_intelligence] Merged into main findings: "
                f"phase={mark_sensitive(phase_label, 'text')} "
                f"si_findings={si_total}"
            )
        if si_indicators:
            indicators.extend(si_indicators)
            print_info_debug(
                "[secret_intelligence] Review-queue indicators emitted: "
                f"phase={mark_sensitive(phase_label, 'text')} "
                f"indicators={len(si_indicators)}"
            )
        if si_findings:
            secret_findings.extend(si_findings)

    if analysis_engine in {ENGINE_AI, ENGINE_BOTH}:
        ai_attempted = True
        ai_service = ShareLootAIAnalysisService()
        prior_context = ai_service.load_matching_history_context(
            history_path=ai_history_path,
            loot_fingerprint=ai_service.compute_loot_fingerprint(Path(loot_dir)),
        )
        include_prior_context = True
        if prior_context:
            include_prior_context = (
                select_dev_ai_history_action(
                    shell=shell,
                    phase_label=phase_label,
                    history_path=ai_history_path,
                    prior_findings=len(list(prior_context.get("findings") or [])),
                )
                != "fresh"
            )
        print_info(
            "Running AI credential analysis on downloaded share loot "
            f"({mark_sensitive(phase_label, 'text')})."
        )
        ai_result = ai_service.analyze_loot_dir(
            loot_dir=loot_dir,
            domain=domain,
            phase=phase,
            phase_label=phase_label,
            candidate_files=candidate_files,
            history_path=ai_history_path,
            include_prior_context=include_prior_context,
        )
        used_prior_context = ai_result.used_prior_context
        if not ai_result.completed and not ai_result.findings:
            if ai_result.error_message:
                print_warning(
                    "AI loot analysis did not complete successfully: "
                    f"{mark_sensitive(ai_result.error_message, 'text')}"
                )
            ai_success = False
            if analysis_engine == ENGINE_AI:
                return LootCredentialAnalysisResult(
                    analysis_engine=analysis_engine,
                    findings={},
                    ai_findings=[],
                    ai_attempted=True,
                    ai_success=False,
                    used_prior_context=used_prior_context,
                    indicators=indicators,
                )
        else:
            ai_findings = normalize_ai_loot_findings_to_grouped_credentials(
                loot_dir=loot_dir,
                findings=ai_result.findings,
            )
            findings = merge_grouped_credential_findings(findings, ai_findings)
            ai_findings_count = sum(len(items) for items in ai_findings.values())
            ai_success = ai_result.completed
            print_info(
                "AI loot analysis summary: "
                f"phase={mark_sensitive(phase_label, 'text')} "
                f"files_with_findings={len({str(item[4]) for items in ai_findings.values() for item in items})} "
                f"credential_like_findings={ai_findings_count} "
                f"used_prior_context={mark_sensitive(str(bool(ai_result.used_prior_context)).lower(), 'text')}"
            )
            for note in ai_result.notes:
                print_info_debug(f"AI loot analysis note: {mark_sensitive(note, 'text')}")
            if should_run_deeper_ai_loot_pass(
                shell=shell,
                phase_label=phase_label,
                findings_count=ai_findings_count,
            ):
                deeper_result = ai_service.analyze_loot_dir(
                    loot_dir=loot_dir,
                    domain=domain,
                    phase=phase,
                    phase_label=f"{phase_label} (deeper pass)",
                    candidate_files=candidate_files,
                    history_path=ai_history_path,
                    include_prior_context=include_prior_context,
                )
                deeper_findings = normalize_ai_loot_findings_to_grouped_credentials(
                    loot_dir=loot_dir,
                    findings=deeper_result.findings,
                )
                findings = merge_grouped_credential_findings(findings, deeper_findings)
                ai_success = bool(ai_success and deeper_result.completed)

    return LootCredentialAnalysisResult(
        analysis_engine=analysis_engine,
        findings=findings,
        ai_findings=list(ai_result.findings) if ai_attempted else [],
        ai_attempted=ai_attempted,
        ai_success=ai_success,
        used_prior_context=used_prior_context,
        indicators=indicators,
        secret_findings=secret_findings,
    )
