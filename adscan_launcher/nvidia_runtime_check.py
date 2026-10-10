"""Host NVIDIA stack probe — can this host's GPU be handed to a container?

``docker run --gpus all`` does not fail gracefully. When the host's NVIDIA
stack is healthy it works; when it is not, the container never starts and the
operator gets a line of runc internals naming a missing socket:

    OCI runtime create failed: ... failed to fulfil mount request:
    open /run/nvidia-persistenced/socket: no such file or directory

That message does not name the cause (a driver upgrade that landed while the
old kernel module was still loaded), does not name the fix (restart the host),
and does not say that the thing which failed was optional. The whole scan dies
for a GPU that only password cracking wanted.

The presence checks the launcher already did — ``/dev/nvidia*`` exists, Docker
advertises the ``nvidia`` runtime — are both still true on exactly that broken
host, so neither can catch it. What catches it is asking the stack whether it
answers, which is what ``nvidia-container-cli info`` does: it is the toolkit's
own probe, it is the component ``--gpus`` relies on, and on a broken host it
fails in about 15 ms with the real reason.

This module is the probe and the classifier only. It never decides policy and
never prints: it returns a verdict, and the caller drops ``--gpus`` and renders
the notice. The subprocess runner is injected so the classification is pure and
unit-testable with no NVIDIA hardware present.

Linux/Docker only, by construction. Windows runs the engine in-process with no
container and no ``--gpus``, so this probe has no Windows counterpart; the
Windows GPU degradation is hashcat's own backend probe falling back to John on
CPU (see ``adscan_internal/cli/cracking.py``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from adscan_core.gpu_runtime import (
    GPU_DRIVER_UNAVAILABLE,
    GPU_DRIVER_VERSION_MISMATCH,
    GPU_OK,
    GPU_TOOLKIT_MISSING,
    GPU_UNKNOWN,
)

#: Where the loaded kernel module reports its own version.
_PROC_DRIVER_VERSION = Path("/proc/driver/nvidia/version")

#: ``NVRM version: NVIDIA UNIX ... Kernel Module for x86_64  595.91.07  Release``
_PROC_VERSION_RE = re.compile(r"\b(\d+\.\d+(?:\.\d+)?)\b")

#: ``NVML library version: 595.99`` — emitted by nvidia-smi when it mismatches.
_NVML_VERSION_RE = re.compile(
    r"NVML library version:\s*(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE
)

#: The exact phrase both NVML and the container CLI use for the mismatch. This
#: is the signature of the one failure whose fix is a restart.
_MISMATCH_MARKERS: tuple[str, ...] = (
    "driver/library version mismatch",
    "driver / library version mismatch",
)

#: Markers that mean the driver is present but not answering, for a reason
#: other than a version mismatch.
_DRIVER_ERROR_MARKERS: tuple[str, ...] = (
    "nvml error",
    "libnvidia-ml",
    "driver error",
    "insufficient permissions",
    "no such device",
    "device error",
)

#: Markers that mean the probe binary itself is not installed. Distinct from a
#: driver failure: pointing that operator at nvidia-smi would be misleading.
_TOOLKIT_MISSING_MARKERS: tuple[str, ...] = (
    "nvidia-container-cli: not found",
    "command not found",
    "no such file or directory",
)


@dataclass(frozen=True)
class NvidiaRuntimeVerdict:
    """Outcome of probing the host NVIDIA stack.

    Attributes:
        probe_ok: Whether the probe reached a conclusion. ``False`` means
            UNKNOWN, and callers MUST fail open — keep ``--gpus`` and say
            nothing, since we did not prove a problem and a host that works
            today must not lose its GPU to a flaky probe.
        usable: Whether the GPU can be handed to a container. Only meaningful
            when ``probe_ok`` is ``True``.
        code: One of the ``adscan_core.gpu_runtime`` ``GPU_*`` codes, which is
            what selects the operator copy and what the container is told.
        loaded_driver: Kernel module version in memory, when readable.
        installed_driver: Installed userspace driver version, when readable.
        detail: The first line of the probe's own error, for ``--debug``.
    """

    probe_ok: bool
    usable: bool
    code: str
    loaded_driver: str | None = None
    installed_driver: str | None = None
    detail: str = ""

    @property
    def degraded(self) -> bool:
        """Whether the caller should drop ``--gpus`` and warn."""
        return self.probe_ok and not self.usable


def _first_marker(text: str, markers: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in markers)


def read_loaded_driver_version(*, proc_path: Path | None = None) -> str | None:
    """Return the NVIDIA kernel module version currently loaded, if readable."""
    path = _PROC_DRIVER_VERSION if proc_path is None else proc_path
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        if "version" not in line.lower():
            continue
        match = _PROC_VERSION_RE.search(line)
        if match:
            return match.group(1)
    return None


def _classify_probe_output(output: str) -> tuple[bool, str]:
    """Map a failed probe's output to ``(conclusive, code)``.

    The order matters. A mismatch is checked first because its message also
    contains ``nvml error``, and a mismatch is the only diagnosis whose fix is
    a restart — collapsing it into the generic driver error would send the
    operator to inspect a driver that is installed perfectly well.
    """
    if not output.strip():
        return False, GPU_UNKNOWN
    if _first_marker(output, _MISMATCH_MARKERS):
        return True, GPU_DRIVER_VERSION_MISMATCH
    if _first_marker(output, _DRIVER_ERROR_MARKERS):
        return True, GPU_DRIVER_UNAVAILABLE
    if _first_marker(output, _TOOLKIT_MISSING_MARKERS):
        return True, GPU_TOOLKIT_MISSING
    # Something failed that we cannot name. Treat as inconclusive rather than
    # asserting a cause: an unexplained probe failure must not cost a working
    # host its GPU.
    return False, GPU_UNKNOWN


def _installed_driver_version(run_fn) -> str | None:
    """Read the installed userspace driver version from nvidia-smi's output.

    Only called once the probe has already failed, so the cost is paid on a
    broken host and never on a healthy one. On a mismatched host nvidia-smi
    fails immediately and prints the NVML version it loaded, which is exactly
    the number the operator needs to see next to the module version.
    """
    try:
        proc = run_fn(["nvidia-smi"])
    except Exception:  # noqa: BLE001 — diagnostics only, never load-bearing
        return None
    combined = (
        f"{getattr(proc, 'stdout', '') or ''}\n{getattr(proc, 'stderr', '') or ''}"
    )
    match = _NVML_VERSION_RE.search(combined)
    return match.group(1) if match else None


def probe_nvidia_runtime(*, run_fn=None, timeout: int = 10) -> NvidiaRuntimeVerdict:
    """Ask the host NVIDIA stack whether a container can be given the GPU.

    Runs ``nvidia-container-cli info``: the toolkit's own probe, and the
    component ``docker run --gpus`` depends on. Exit code 0 means a container
    can be wired up; a failure carries the reason in its message.

    Args:
        run_fn: Injected runner taking an argv list and returning an object
            with ``returncode``/``stdout``/``stderr``. Defaults to a plain
            subprocess call. Injected in tests so the classification is
            exercised without NVIDIA hardware.
        timeout: Seconds to allow the probe. It normally answers in
            milliseconds; a hang is treated as inconclusive.

    Returns:
        A verdict. Fail-open (``probe_ok=False``) whenever the probe could not
        reach a conclusion, so a GPU that works today keeps working.
    """
    if run_fn is None:
        import subprocess  # noqa: PLC0415 — keep module import cost at zero

        def run_fn(args):  # type: ignore[misc]
            return subprocess.run(  # noqa: S603
                args,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

    try:
        proc = run_fn(["nvidia-container-cli", "info"])
    except FileNotFoundError:
        # The toolkit CLI is absent. Docker advertising the nvidia runtime
        # while its CLI is missing is a genuine, nameable misconfiguration.
        return NvidiaRuntimeVerdict(
            probe_ok=True,
            usable=False,
            code=GPU_TOOLKIT_MISSING,
            loaded_driver=read_loaded_driver_version(),
            detail="nvidia-container-cli not found on PATH",
        )
    except Exception as exc:  # noqa: BLE001 — a flaky probe must not cost the GPU
        return NvidiaRuntimeVerdict(
            probe_ok=False,
            usable=True,
            code=GPU_UNKNOWN,
            detail=f"{type(exc).__name__}: {exc}",
        )

    if int(getattr(proc, "returncode", 1) or 0) == 0:
        return NvidiaRuntimeVerdict(probe_ok=True, usable=True, code=GPU_OK)

    stdout = getattr(proc, "stdout", "") or ""
    stderr = getattr(proc, "stderr", "") or ""
    combined = f"{stdout}\n{stderr}".strip()
    conclusive, code = _classify_probe_output(combined)
    detail = next((line.strip() for line in combined.splitlines() if line.strip()), "")
    if not conclusive:
        return NvidiaRuntimeVerdict(
            probe_ok=False, usable=True, code=code, detail=detail
        )

    loaded = read_loaded_driver_version()
    installed = (
        _installed_driver_version(run_fn)
        if code == GPU_DRIVER_VERSION_MISMATCH
        else None
    )
    return NvidiaRuntimeVerdict(
        probe_ok=True,
        usable=False,
        code=code,
        loaded_driver=loaded,
        installed_driver=installed,
        detail=detail,
    )
