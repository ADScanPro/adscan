"""PAL physical clock-step seam (per-OS).

Kerberos tolerates only a small clock skew, so ADscan must be able to step the
host wall clock to the DC's time. Measurement (SMB2 NEGOTIATE) and the in-memory
kerbad skew seed are OS-neutral and stay in ``services/dc_time.py``. This module
provides ONLY the per-OS PHYSICAL-STEP seam.

Design point:
- On POSIX the physical step stays centralized in the privileged host helper
  (``ADSCAN_HOST_HELPER_SOCK``), wired by a later phase. So the POSIX
  ``step_system_clock`` / ``set_ntp_service`` here return a neutral
  "delegated_to_host_helper" placeholder result rather than duplicating that op.
- On Windows the real work is done here: ``w32tm`` via subprocess when elevated,
  degrading honestly (``stepped=False`` + reason) when not.

Every function returns a result dataclass / bool / None and NEVER raises.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

from adscan_core.pal.platform import current_os, is_windows

__all__ = [
    "ClockStepResult",
    "can_step_system_clock",
    "step_system_clock",
    "set_ntp_service",
    "is_domain_time_synced_natively",
]

_HOST_HELPER_SOCK_ENV = "ADSCAN_HOST_HELPER_SOCK"
_DELEGATION_REASON = "delegated_to_host_helper"
_W32TM_TIMEOUT = 30


@dataclass(frozen=True)
class ClockStepResult:
    """Outcome of a physical clock-step attempt.

    Attributes:
        stepped: True only when the wall clock was physically changed.
        reason: Human-readable English explanation of the outcome.
        os: The PAL OS the attempt ran under (``"windows"`` or ``"posix"``).
    """

    stepped: bool
    reason: str
    os: str


def _windows_is_elevated() -> bool:
    """Return True when the current Windows process is elevated (admin).

    Guarded: on any platform without ``ctypes.windll`` (i.e. non-Windows) or on
    any probe error this returns False. Exposed at module level so tests can
    monkeypatch it deterministically on a POSIX CI host.
    """
    try:
        import ctypes  # local import: only meaningful on Windows

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 — probe must never raise
        return False


def _posix_host_helper_available() -> bool:
    """True when a host-helper socket is configured OR a stepping tool exists."""
    import os

    if os.environ.get(_HOST_HELPER_SOCK_ENV, "").strip():
        return True
    return bool(shutil.which("timedatectl") or shutil.which("date"))


def can_step_system_clock() -> bool:
    """Report whether a physical clock step is possible on this host.

    POSIX: True when the privileged host-helper socket is configured OR a
    stepping utility (``timedatectl`` / ``date``) is on PATH. Windows: True only
    when the process is elevated.
    """
    if is_windows():
        return _windows_is_elevated()
    return _posix_host_helper_available()


def _run_w32tm(args: list[str]) -> tuple[bool, str]:
    """Run ``w32tm`` with the given args. Return (ok, detail). Never raises."""
    exe = shutil.which("w32tm") or "w32tm"
    try:
        completed = subprocess.run(  # noqa: S603 — fixed w32tm invocation
            [exe, *args],
            capture_output=True,
            text=True,
            timeout=_W32TM_TIMEOUT,
        )
    except Exception as exc:  # noqa: BLE001 — subprocess seam must never raise
        return (False, f"w32tm invocation failed: {exc}")
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        return (False, f"w32tm exit {completed.returncode}: {detail}"[:400])
    return (True, (completed.stdout or "").strip()[:400])


def step_system_clock(iso_utc: str) -> ClockStepResult:
    """Physically step the host clock toward ``iso_utc`` (best-effort).

    Args:
        iso_utc: Target time as an ISO-8601 UTC string. On Windows the actual
            resync is driven by ``w32tm`` against the configured time source, so
            the value is advisory here; a garbage value still yields a result,
            never an exception.

    Returns:
        A :class:`ClockStepResult`. POSIX always returns
        ``stepped=False, reason="delegated_to_host_helper"`` (the physical step
        lives in the host helper, wired in a later phase). Windows attempts
        ``w32tm /resync`` when elevated, else degrades with a reason.
    """
    os_name = current_os()
    if os_name != "windows":
        return ClockStepResult(stepped=False, reason=_DELEGATION_REASON, os=os_name)

    if not _windows_is_elevated():
        return ClockStepResult(
            stepped=False,
            reason="requires admin on Windows",
            os=os_name,
        )

    ok, detail = _run_w32tm(["/resync", "/nowait"])
    if ok:
        return ClockStepResult(
            stepped=True,
            reason=f"w32tm /resync succeeded: {detail}" if detail else "w32tm /resync succeeded",
            os=os_name,
        )
    return ClockStepResult(stepped=False, reason=detail, os=os_name)


def set_ntp_service(enabled: bool) -> bool:
    """Enable/disable the OS time-sync service (best-effort). Never raises.

    POSIX: placeholder returning False — the ``timedatectl set-ntp`` op stays in
    the privileged host helper (wired in a later phase). Windows: control the
    W32Time service via ``w32tm`` when elevated, returning a success bool.
    """
    if not is_windows():
        return False

    if not _windows_is_elevated():
        return False

    if enabled:
        # Re-enable and kick the sync source.
        ok, _ = _run_w32tm(["/resync"])
        return ok
    # Disable: clear the manual peer list so W32Time stops actively syncing.
    ok, _ = _run_w32tm(["/config", "/manualpeerlist:", "/update"])
    return ok


def is_domain_time_synced_natively() -> bool | None:
    """Report whether the OS already keeps time synced to the domain.

    A domain-joined Windows host usually already syncs to the DC, so a physical
    step is unnecessary — this is the fast-path probe.

    Returns:
        Windows: True/False from ``w32tm /query /status`` (best-effort); None
        when the probe is inconclusive. POSIX: None (not applicable — POSIX time
        sync is handled by the host helper, not queried here).
    """
    if not is_windows():
        return None

    ok, detail = _run_w32tm(["/query", "/status"])
    if not ok:
        return None
    text = detail.lower()
    # A synced host reports a real source and a non-"unspecified" stratum.
    if "unspecified" in text or "not been synchronized" in text or "0x80070426" in text:
        return False
    if "source:" in text or "stratum:" in text:
        return True
    return None
