"""Idempotent posture freshness guard.

Single Policy Enforcement Point (PEP) for posture freshness. Any operation
that consumes posture calls :func:`ensure_posture_fresh` at entry; the guard
either no-ops (everything already fresh) or runs the appropriate probe
phase to refresh the missing/stale categories.

Design goals:
- Idempotent: safe to call multiple times in the same flow.
- Single source of truth: lifecycle code stops directly invoking probes.
- Race-safe: ``asyncio.Lock`` per ``(domain, phase)`` key prevents double-
  probe when concurrent operations request the same posture.
- Session-memoized: even when workspace data is mutated mid-flow, we don't
  re-render the live panel twice in the same shell session for the same
  ``(domain, phase)``.
- Testable: probe functions are dependency-injected, default to the real
  ``arun_posture_probe`` from ``posture_probe_lifecycle``.

Anti-patterns intentionally avoided:
- Decorator magic (hides control flow).
- Lazy probing inside ``get_posture`` (impure read functions).
- Mandatory context manager for the guard (too ceremonial).
- Lifting all auth operations into a base class (YAGNI).
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Optional

from adscan_core import telemetry
from adscan_core.rich_output import print_info_debug, print_warning
from adscan_internal.services.domain_posture import (
    ConstraintCategory,
    SignalConfidence,
    TriState,
    get_posture,
)
from adscan_internal.services.posture_probe import (
    ProbeCredentials,
    ProbePhase,
    ProbeResult,
)
from adscan_core.rich_output import print_exception


# Categories each phase covers — used by the freshness check to decide
# whether the phase needs to run at all.
_UNAUTH_CATEGORIES: frozenset[ConstraintCategory] = frozenset(
    {
        ConstraintCategory.LDAPS_AVAILABLE,
        ConstraintCategory.LDAP_SIGNING,
        # CBT lives in UNAUTH because the bogus-credential technique used
        # by U3 does not require a real principal — see ``probe_unauth``
        # docstring for the rationale.
        ConstraintCategory.LDAP_CHANNEL_BINDING,
    }
)
_AUTH_CATEGORIES: frozenset[ConstraintCategory] = frozenset(
    {
        ConstraintCategory.NTLM_AUTHENTICATION,
        ConstraintCategory.KERBEROS_RC4,
        ConstraintCategory.KERBEROS_AES_ONLY,
        ConstraintCategory.KERBEROS_ETYPE_PROBE,
        ConstraintCategory.SMB_SIGNING,
    }
)


class FreshnessOutcome(str, Enum):
    """High-level outcome of a single :func:`ensure_posture_fresh` call."""

    PROBED = "probed"
    ALREADY_FRESH = "already_fresh"
    SESSION_CACHED = "session_cached"
    FAILED = "failed"
    SKIPPED_NO_DOMAIN = "skipped_no_domain"
    SKIPPED_DISABLED = "skipped_disabled"


@dataclass(frozen=True)
class PostureFreshness:
    """Structured outcome the caller can inspect or log."""

    domain: str
    phase: ProbePhase
    outcome: FreshnessOutcome
    elapsed_s: float
    results: tuple[ProbeResult, ...] = field(default_factory=tuple)
    error: Optional[str] = None


# Internal session memo: tracks (domain_normalized, phase) tuples whose probe
# widget already rendered in this shell session. Cleared via
# :func:`clear_session_cache`.
_session_probed: set[tuple[str, ProbePhase]] = set()

# Per-(domain, phase) lock to serialize concurrent probe attempts.
_probe_locks: dict[tuple[str, ProbePhase], asyncio.Lock] = {}
_locks_mutex = asyncio.Lock()


def clear_session_cache() -> None:
    """Reset the per-session memo. Called on shell shutdown / new workspace."""
    _session_probed.clear()


# Type alias for the probe runner the orchestrator delegates to. Tests
# override; default value is ``arun_posture_probe``.
ProbeRunner = Callable[..., Awaitable[list[ProbeResult]]]


def _is_disabled() -> bool:
    """Return True when the posture probe is disabled via env var."""
    from adscan_internal.cli.posture_probe_lifecycle import is_posture_probe_disabled

    return is_posture_probe_disabled()


async def _get_lock(key: tuple[str, ProbePhase]) -> asyncio.Lock:
    """Return (and lazily create) the lock guarding probes for ``key``."""
    async with _locks_mutex:
        lock = _probe_locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            _probe_locks[key] = lock
        return lock


def _is_category_fresh(state) -> bool:  # type: ignore[no-untyped-def]
    """Return True when a ``ConstraintState`` is fresh + HIGH + non-stale + non-obsolete.

    A constraint is considered fresh enough to short-circuit re-probing
    when ALL of the following hold:
      * Known state (non-UNKNOWN).
      * HIGH confidence.
      * Not stale (within TTL).
      * Not produced by an obsolete probe-code version (see
        ``adscan_internal.services.posture_probe._PROBE_SCHEMA_VERSION``).
        Records emitted before schema-version tracking, or by an earlier
        version of the probe, are treated as obsolete so the new code
        runs at least once and stamps the current version into the
        cache.
    """
    if state.state == TriState.UNKNOWN:
        return False
    if state.confidence != SignalConfidence.HIGH:
        return False
    if state.is_stale:
        return False
    # Local import avoids a posture_probe → posture_orchestration cycle
    # at module-import time (posture_probe imports orchestration types
    # indirectly via ProbePhase). The const lookup is cheap.
    from adscan_internal.services.posture_probe import _PROBE_SCHEMA_VERSION

    if state.is_schema_outdated(_PROBE_SCHEMA_VERSION):
        return False
    return True


async def ensure_posture_fresh(
    shell: Any,
    *,
    domain: str,
    dc_ip: str,
    creds: Optional[ProbeCredentials] = None,
    phase: Optional[ProbePhase] = None,
    render_ui: bool = True,
    force: bool = False,
    probe_runner: Optional[ProbeRunner] = None,
) -> PostureFreshness:
    """Idempotent posture freshness guard. Safe to call from any consumer.

    Args:
        shell: PentestShell instance (for ``domains_data`` + console access).
        domain: Target domain.
        dc_ip: PDC IP for the target domain.
        creds: Required for AUTH phase. ``None`` → caller intends UNAUTH only.
        phase: Explicit phase. ``None`` = auto: AUTH if creds else UNAUTH.
        render_ui: When True (default), the live panel + summary render on
            first probe per session. When False, probe runs silently.
        force: Force re-probe even if posture is fresh. Used by ``posture probe``.
        probe_runner: Injectable probe orchestrator. Defaults to
            ``arun_posture_probe`` from posture_probe_lifecycle.

    Returns:
        :class:`PostureFreshness` with outcome + results + elapsed time.
        Never raises — failures are captured into a ``FAILED`` outcome with
        ``.error`` set.
    """
    started = time.monotonic()
    domain_str = (domain or "").strip()
    dc_ip_str = (dc_ip or "").strip()

    if not domain_str or not dc_ip_str:
        return PostureFreshness(
            domain=domain_str,
            phase=phase or ProbePhase.UNAUTH,
            outcome=FreshnessOutcome.SKIPPED_NO_DOMAIN,
            elapsed_s=time.monotonic() - started,
        )

    if _is_disabled():
        return PostureFreshness(
            domain=domain_str,
            phase=phase or ProbePhase.UNAUTH,
            outcome=FreshnessOutcome.SKIPPED_DISABLED,
            elapsed_s=time.monotonic() - started,
        )

    effective_phase = phase
    if effective_phase is None:
        effective_phase = ProbePhase.AUTH if creds is not None else ProbePhase.UNAUTH

    domain_norm = domain_str.lower()
    key = (domain_norm, effective_phase)

    lock = await _get_lock(key)
    async with lock:
        if not force and key in _session_probed:
            return PostureFreshness(
                domain=domain_str,
                phase=effective_phase,
                outcome=FreshnessOutcome.SESSION_CACHED,
                elapsed_s=time.monotonic() - started,
            )

        # Read current posture and decide whether anything needs probing.
        try:
            domains_data = getattr(shell, "domains_data", None)
            posture = get_posture(domains_data, domain=domain_str)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            posture = None

        relevant = (
            _UNAUTH_CATEGORIES
            if effective_phase == ProbePhase.UNAUTH
            else _AUTH_CATEGORIES
        )

        if not force and posture is not None:
            if all(_is_category_fresh(posture.get(cat)) for cat in relevant):
                return PostureFreshness(
                    domain=domain_str,
                    phase=effective_phase,
                    outcome=FreshnessOutcome.ALREADY_FRESH,
                    elapsed_s=time.monotonic() - started,
                )

        runner = probe_runner
        if runner is None:
            from adscan_internal.cli.posture_probe_lifecycle import (
                arun_posture_probe,
            )

            runner = arun_posture_probe

        kwargs: dict[str, Any] = {
            "domain": domain_str,
            "dc_ip": dc_ip_str,
            "force": force,
            "render_ui": render_ui,
        }
        if creds is not None:
            kwargs["username"] = creds.username
            kwargs["password"] = creds.password
            kwargs["nt_hash"] = creds.nt_hash
            kwargs["aes_key"] = creds.aes_key
            kwargs["ccache_path"] = creds.ccache_path

        try:
            results = await runner(shell, **kwargs)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_warning(
                f"Posture freshness guard failed: {type(exc).__name__}. "
                "Continuing with conservative defaults."
            )
            return PostureFreshness(
                domain=domain_str,
                phase=effective_phase,
                outcome=FreshnessOutcome.FAILED,
                elapsed_s=time.monotonic() - started,
                error=f"{type(exc).__name__}: {exc}",
            )

        _session_probed.add(key)
        results_tuple: tuple[ProbeResult, ...] = (
            tuple(results) if results is not None else ()
        )
        print_info_debug(
            f"[posture_orchestration] probed domain={domain_str} "
            f"phase={effective_phase.value} results={len(results_tuple)}"
        )
        return PostureFreshness(
            domain=domain_str,
            phase=effective_phase,
            outcome=FreshnessOutcome.PROBED,
            elapsed_s=time.monotonic() - started,
            results=results_tuple,
        )


__all__ = [
    "FreshnessOutcome",
    "PostureFreshness",
    "ProbeRunner",
    "clear_session_cache",
    "ensure_posture_fresh",
]
