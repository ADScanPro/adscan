"""Put the host wall clock back after a scan stepped it to a domain controller.

Kerberos PKINIT needs the host clock physically stepped to the DC's time
(``adscan_internal/services/dc_time.py``). A DC may be hours or days away from
real time, and the host used to keep that time after the scan. On a machine
that visits many domains (the bare-metal laptop profile, an appliance assessing
several clients) one DC days ahead then raised the licence's clock high-water
mark and blocked every later assessment as a clock rollback.

The rule (decision D5 of the bare-metal laptop design): at scan end the wall
clock goes back to the time it had before the first step plus the time that
has really elapsed since, measured on a clock a wall-clock step does not move
(``CLOCK_BOOTTIME`` on Linux, which also counts suspend; ``time.monotonic()``
elsewhere). The DC's clock is never trusted afterwards.

Two ways a session reaches that rule:

* **Through the privileged host helper** (Docker runtime). The helper owns the
  baseline in :data:`DEFAULT_BASELINE_PATH`, written just before the first
  clock-stepping operation of any session and shared by every concurrent
  session on the host. Each helper registers as a holder; the clock is
  restored when the LAST live holder releases (an explicit request at engine
  exit, the helper's own shutdown, or the next helper start finding only dead
  holders after a crash). So one scan ending never pulls the clock from under
  another scan still running against a skewed DC.
* **In process** (native Linux, Windows): :class:`SessionClock` captures the
  baseline at session start and, at exit, detects whether the clock was moved
  (the wall clock disagrees with baseline plus elapsed by more than
  :data:`STEP_DETECTION_SECONDS`), which covers every stepping path without
  hooking each one.

Stdlib only; importable by the launcher (host), the engine and the helper.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

#: Shared by every host-helper process on the host. tmpfs: gone after a reboot,
#: which also resets the clock from the hardware clock.
DEFAULT_BASELINE_PATH = Path("/run/adscan-host-helper/clock-baseline.json")
#: A wall clock that disagrees with "baseline + elapsed" by more than this was
#: moved during the session. Matches the clock-sync guard's tolerance: below it
#: nothing in ADscan steps the clock.
STEP_DETECTION_SECONDS = 120.0
_BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")


def elapsed_clock() -> float:
    """Seconds on a clock a wall-clock step does not move.

    ``CLOCK_BOOTTIME`` where it exists (Linux: monotonic AND counts suspend, so
    a laptop closed mid-scan still restores to the right time), else
    ``time.monotonic()``.
    """
    boottime = getattr(time, "CLOCK_BOOTTIME", None)
    if boottime is not None:
        try:
            return time.clock_gettime(boottime)
        except OSError:
            pass
    return time.monotonic()


def boot_id() -> str:
    """Kernel boot id, or ``""`` where there is none (Windows, macOS)."""
    try:
        return _BOOT_ID_PATH.read_text(encoding="ascii").strip()
    except OSError:
        return ""


@dataclass(frozen=True)
class WallClockBaseline:
    """The wall clock and the elapsed clock read at the same instant."""

    wall: float
    elapsed: float
    boot: str = ""

    @classmethod
    def capture(cls) -> WallClockBaseline:
        return cls(wall=time.time(), elapsed=elapsed_clock(), boot=boot_id())

    def restored_wall_time(self, *, elapsed_now: float | None = None) -> datetime:
        """The real time now: baseline wall + elapsed since the baseline."""
        now = elapsed_clock() if elapsed_now is None else elapsed_now
        return datetime.fromtimestamp(self.wall + max(0.0, now - self.elapsed), tz=timezone.utc)

    def drift_seconds(self, *, wall_now: float | None = None, elapsed_now: float | None = None) -> float:
        """How far the current wall clock is from the restored time."""
        wall = time.time() if wall_now is None else wall_now
        expected = self.restored_wall_time(elapsed_now=elapsed_now).timestamp()
        return wall - expected

    def same_boot(self) -> bool:
        current = boot_id()
        return not self.boot or not current or self.boot == current


def format_for_date_command(value: datetime) -> str:
    """ISO 8601 UTC with an explicit offset (accepted by ``date -u -s``)."""
    return value.astimezone(timezone.utc).isoformat(timespec="seconds")


# ── Shared baseline with holders (host helper) ──────────────────────────────


@contextlib.contextmanager
def _locked(path: Path) -> Iterator[None]:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle = open(path.with_suffix(".lock"), "a+b")  # noqa: SIM115 - closed below
    try:
        try:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        except (ImportError, OSError):
            pass
        yield
    finally:
        handle.close()


def _read(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _write(path: Path, data: dict[str, Any]) -> None:
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _live_holders(data: dict[str, Any]) -> list[int]:
    holders = []
    for value in data.get("holders") or []:
        try:
            pid = int(value)
        except (TypeError, ValueError):
            continue
        if _pid_alive(pid) and pid not in holders:
            holders.append(pid)
    return holders


def _baseline_from(data: dict[str, Any]) -> WallClockBaseline | None:
    try:
        return WallClockBaseline(
            wall=float(data["wall"]), elapsed=float(data["elapsed"]), boot=str(data.get("boot") or "")
        )
    except (KeyError, TypeError, ValueError):
        return None


def register_step_holder(holder: int, *, path: Path = DEFAULT_BASELINE_PATH) -> None:
    """Join the baseline before a clock-stepping operation.

    The FIRST holder captures the baseline, at this instant, before any step.
    A baseline from a previous boot is discarded. Best-effort.
    """
    with contextlib.suppress(OSError):
        with _locked(path):
            data = _read(path)
            baseline = _baseline_from(data) if data else None
            if baseline is None or not baseline.same_boot():
                captured = WallClockBaseline.capture()
                data = {
                    "wall": captured.wall,
                    "elapsed": captured.elapsed,
                    "boot": captured.boot,
                    "stepped": False,
                    "holders": [],
                }
            holders = _live_holders(data)
            if holder not in holders:
                holders.append(holder)
            data["holders"] = holders
            _write(path, data)


def mark_stepped(*, path: Path = DEFAULT_BASELINE_PATH) -> None:
    """Record that a step really happened (only then is a restore needed)."""
    with contextlib.suppress(OSError):
        with _locked(path):
            data = _read(path)
            if not data:
                return
            data["stepped"] = True
            _write(path, data)


@dataclass(frozen=True)
class ReleaseOutcome:
    """What releasing a holder decided."""

    restore_to: datetime | None
    #: True when no live holder remains (the shared baseline is gone).
    last_holder: bool
    #: True when there was a baseline at all.
    had_baseline: bool


def release_step_holder(holder: int | None, *, path: Path = DEFAULT_BASELINE_PATH) -> ReleaseOutcome:
    """Leave the baseline; return the time to restore when this was the last holder.

    ``holder=None`` only prunes dead holders (a helper starting after a crash).
    The caller sets the clock to ``restore_to``; this function never touches it.
    """
    try:
        with _locked(path):
            data = _read(path)
            if not data:
                return ReleaseOutcome(restore_to=None, last_holder=True, had_baseline=False)
            baseline = _baseline_from(data)
            holders = [pid for pid in _live_holders(data) if pid != holder]
            if holders:
                data["holders"] = holders
                _write(path, data)
                return ReleaseOutcome(restore_to=None, last_holder=False, had_baseline=True)
            with contextlib.suppress(OSError):
                path.unlink()
            if baseline is None or not baseline.same_boot() or not data.get("stepped"):
                return ReleaseOutcome(restore_to=None, last_holder=True, had_baseline=True)
            return ReleaseOutcome(
                restore_to=baseline.restored_wall_time(), last_holder=True, had_baseline=True
            )
    except OSError:
        return ReleaseOutcome(restore_to=None, last_holder=False, had_baseline=False)


# ── In-process session clock (native Linux, Windows) ────────────────────────


class SessionClock:
    """Baseline captured when a session starts; decides the restore at exit."""

    def __init__(self, baseline: WallClockBaseline | None = None) -> None:
        self.baseline = baseline or WallClockBaseline.capture()

    def restore_target(self, *, wall_now: float | None = None, elapsed_now: float | None = None) -> datetime | None:
        """The time to set, or None when the clock was not moved this session."""
        if not self.baseline.same_boot():
            return None
        drift = self.baseline.drift_seconds(wall_now=wall_now, elapsed_now=elapsed_now)
        if abs(drift) <= STEP_DETECTION_SECONDS:
            return None
        return self.baseline.restored_wall_time(elapsed_now=elapsed_now)


__all__ = [
    "DEFAULT_BASELINE_PATH",
    "ReleaseOutcome",
    "STEP_DETECTION_SECONDS",
    "SessionClock",
    "WallClockBaseline",
    "boot_id",
    "elapsed_clock",
    "format_for_date_command",
    "mark_stepped",
    "register_step_holder",
    "release_step_holder",
]
