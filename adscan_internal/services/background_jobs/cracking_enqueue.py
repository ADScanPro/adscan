"""Policy-gated seam: enqueue a cracking job for a freshly-captured hash.

Called right after a poisoning capture is persisted, or from the audit crack
effort selector for a Kerberoast / AS-REP capture. Resolves the concrete hashcat
``mode`` (5500/5600 NetNTLM, 13100/18200 and their AES variants for roast). For
NetNTLM it classifies the captured principal (machine vs user) and the resulting
crack policy, then either launches a :class:`CrackingJobRuntime` (user hashes —
wordlist-crackable), surfaces a rainbow-pending notification (machine NTLMv1 —
needs an offline rainbow rig, no wordlist job), or does nothing (machine NTLMv2 —
not recoverable). Roast hashes are always user/service accounts, so they always
get a wordlist job. Idempotent by ``(kind="cracking", scope=<user>.m<mode>)`` and
best-effort: any failure is swallowed + telemetered, never raised.
"""
from __future__ import annotations

from typing import Any, Optional

from adscan_core import telemetry
from adscan_core.paths import get_adscan_home
from adscan_internal.services.background_jobs.cracking_job import CrackingJobRuntime
from adscan_internal.services.background_jobs.registry import get_or_create_registry
from adscan_internal.services.background_jobs.results_bus import (
    JobResult,
    make_registry_result_sink,
)
from adscan_internal.services.captured_credential_policy import (
    classify_principal,
    crack_policy,
)
from adscan_internal.services.cracking_benchmark import get_or_run_benchmark
from adscan_internal.services.cracking_wordlist_policy import (
    EFFORT_LEVELS,
    resolve_effort,
    wordlist_tiers_for_workspace,
)

_KIND = "cracking"

# Fixed NetNTLM modes. Everything else ADscan cracks in the background is a roast
# hash (Kerberoast / AS-REP, RC4 + AES etypes) — always a user/service account,
# so the machine-vs-user crack policy does not apply to it.
_NETNTLM_MODES = {"5500", "5600"}


def _resolve_mode_and_version(
    mode: Optional[str], ntlm_version: Optional[str]
) -> "tuple[Optional[str], str]":
    """Resolve ``(hashcat_mode, ntlm_version)`` from either input.

    An explicit ``mode`` (any hashcat mode) wins; when only the legacy
    ``ntlm_version`` is given, the NetNTLM mode is derived from it so existing
    callers keep working. Returns ``(None, version)`` when neither yields a
    usable mode.
    """
    version = str(ntlm_version or "").strip().lower()
    if mode is not None and str(mode).strip():
        mode_str = str(mode).strip()
        if not version:
            if mode_str == "5500":
                version = "v1"
            elif mode_str == "5600":
                version = "v2"
        return mode_str, version
    if version in {"v1", "ntlmv1", "netntlmv1"}:
        return "5500", "v1"
    if version in {"v2", "ntlmv2", "netntlmv2"}:
        return "5600", "v2"
    return None, version


def enqueue_cracking_job(
    shell: Any, *, domain: str, user: str, hash_file: str,
    mode: Optional[str] = None, ntlm_version: Optional[str] = None,
    effort: Optional[str] = None,
) -> Optional[str]:
    """Classify + (for crackable hashes) auto-crack in the background. Best-effort.

    ``mode`` is the concrete hashcat mode (5500/5600 NetNTLM, 13100/18200 and
    their AES variants for roast). ``ntlm_version`` is the legacy NetNTLM-only
    input, still accepted: when ``mode`` is omitted it is derived from the
    version, so existing NetNTLM callers work unchanged. At least one of the two
    must resolve to a mode.

    ``effort`` is an ADDITIVE opt-in: when given, the job walks the
    rule-aware EffortTier ladder from ``resolve_effort()`` (base wordlist x
    rules, benchmark-capped); when omitted (the default, and every existing
    caller before this change), the job walks the legacy per-workspace-type
    wordlist list — byte-for-byte unchanged.

    Returns:
        The active job id when a wordlist crack job is running (either just
        launched or already active for this scope); ``None`` for
        ``rainbow_only`` (a notification is enqueued instead) and
        ``no_crack``, and on any internal failure.
    """
    try:
        mode_str, version = _resolve_mode_and_version(mode, ntlm_version)
        if not mode_str:
            return None

        scope = f"{user}.m{mode_str}"
        registry = get_or_create_registry(shell)
        existing = registry.find_active(_KIND, scope)
        if existing is not None:
            return existing.id

        # The machine-vs-user crack policy applies ONLY to NetNTLM. Roast hashes
        # are always user/service accounts (a machine account is never
        # Kerberoastable / AS-REP-roastable), so they always get a wordlist job.
        if mode_str in _NETNTLM_MODES:
            account = classify_principal(user, getattr(shell, "domains_data", None), domain)
            policy = crack_policy(account, version)
            if policy == "no_crack":
                # A machine NTLMv2 is neither wordlist- nor rainbow-recoverable
                # (relay-only). Surface it so it still enters the scan-end
                # harvest review as "not crackable (machine)" — never a job.
                _mark_uncrackable_machine(registry, domain, user, version, hash_file)
                return None
            if policy == "rainbow_only":
                _mark_rainbow_pending(registry, domain, user, version, hash_file)
                return None

        wordlists_dir = _wordlists_dir(shell)
        workspace_type = str(getattr(shell, "type", "") or "")
        runtime_kwargs: dict[str, Any] = {}
        max_effort = ""
        if effort:
            effort_tiers = _resolve_effort_tiers(
                shell, effort, workspace_type=workspace_type, domain=domain,
                wordlists_dir=wordlists_dir,
            )
            if effort_tiers:
                runtime_kwargs["effort_tiers"] = effort_tiers
                max_effort = _highest_effort_level(effort_tiers)
        if "effort_tiers" not in runtime_kwargs:
            runtime_kwargs["wordlist_tiers"] = wordlist_tiers_for_workspace(
                workspace_type, domain, wordlists_dir
            )
        if not max_effort and str(effort or "").strip().lower() in EFFORT_LEVELS:
            max_effort = str(effort).strip().lower()

        job = registry.create(kind=_KIND, scope=scope)
        sink = make_registry_result_sink(registry)
        runtime = CrackingJobRuntime(
            shell, domain=domain, user=user, mode=mode_str, ntlm_version=version,
            hash_file=hash_file, background=True, max_effort=max_effort,
            sink=sink, job_id=job.id, **runtime_kwargs,
        )
        if not runtime.start():
            registry.mark(job.id, state="failed")
            return None
        registry.attach_runtime(job.id, runtime)
        return job.id
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return None


def _resolve_effort_tiers(
    shell: Any, effort: str, *, workspace_type: str, domain: str, wordlists_dir: str
) -> Optional[list]:
    """Resolve the effort ladder via the benchmark-aware SSOT. Best-effort —
    a benchmark/resolve failure returns None so the caller falls back to the
    legacy bare wordlist_tiers_for_workspace path, never breaking
    capture->crack."""
    try:
        benchmark = get_or_run_benchmark(shell)
        return resolve_effort(
            effort, workspace_type=workspace_type, domain=domain,
            wordlists_dir=wordlists_dir, benchmark=benchmark,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return None


def _highest_effort_level(effort_tiers: list) -> str:
    """Highest EFFORT_LEVEL name present in a resolved tier ladder.

    ``resolve_effort`` prepends a ``"custom"`` tier and climbs from the
    requested level up to ``"thorough"``, so the highest generic tier walked is
    what the harvest record stamps as ``max_effort`` (the escalation gate).
    Returns ``""`` when no tier carries a recognised effort-level name (e.g. a
    custom-only ladder), so the caller falls back to the requested effort.
    """
    levels = [
        str(getattr(t, "name", "") or "").strip().lower()
        for t in (effort_tiers or [])
    ]
    present = [lvl for lvl in levels if lvl in EFFORT_LEVELS]
    if not present:
        return ""
    return max(present, key=EFFORT_LEVELS.index)


def _mark_uncrackable_machine(registry, domain, user, ntlm_version, hash_file) -> None:
    """A machine NTLMv2: no job (not recoverable) — surface it for the review."""
    try:
        registry.enqueue_notification(
            JobResult(
                job_id="", kind=_KIND, scope=f"{user}.m5600",
                summary=(
                    f"Machine NetNTLMv2 captured for {user} — not crackable "
                    "(machine account, relay-only)."
                ),
                detail={
                    "status": "uncrackable_machine", "user": user, "domain": domain,
                    "hash_file": hash_file, "version": ntlm_version,
                },
            )
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)


def _mark_rainbow_pending(registry, domain, user, ntlm_version, hash_file) -> None:
    """A machine NTLMv1: no wordlist job — surface it for the operator's rainbow rig."""
    try:
        registry.enqueue_notification(
            JobResult(
                job_id="", kind=_KIND, scope=f"{user}.m5500",
                summary=(
                    f"Machine NetNTLMv1 captured for {user} — rainbow-table crack "
                    "needed (offline, your own rig); hash in the workspace."
                ),
                detail={
                    "status": "rainbow_pending", "user": user, "domain": domain,
                    "hash_file": hash_file, "version": ntlm_version,
                },
            )
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)


def _wordlists_dir(shell: Any) -> str:  # noqa: ARG001 — kept for parity with call-site shape
    """Resolve the bundled wordlists dir the same way ``cli/cracking.py`` does."""
    return str(get_adscan_home() / "wordlists")
