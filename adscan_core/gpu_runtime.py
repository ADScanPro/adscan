"""Shared vocabulary for GPU-availability degradation.

Two layers see the same event from opposite ends and must never word it
differently:

* The **host launcher** (Linux/Docker only) DETECTS that the host's NVIDIA
  stack cannot be handed to a container, drops ``--gpus`` and renders the
  operator notice.
* The **container runtime** later REPORTS the cracking degradation that
  follows, when hashcat finds no compute device.

Before this module the container's guidance was generic ("ensure
nvidia-container-toolkit is installed"), which is actively misleading on the
most common failure: the toolkit IS installed and working, and the real fix is
to reboot, because the driver was upgraded while the old kernel module was
still loaded. The launcher knows which failure it is; the container does not.
So the launcher forwards its diagnosis through :data:`ENV_GPU_DEGRADED` and
both surfaces read their copy from here.

Dependency-light by design (stdlib only): ``adscan_core`` is imported by the
host launcher and the container alike.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping

#: Diagnosis code the launcher forwards into the container.
ENV_GPU_DEGRADED = "ADSCAN_GPU_DEGRADED"

#: The kernel module version currently loaded on the host, when known.
ENV_GPU_DRIVER_LOADED = "ADSCAN_GPU_DRIVER_LOADED"

#: The userspace driver/NVML version installed on the host, when known.
ENV_GPU_DRIVER_INSTALLED = "ADSCAN_GPU_DRIVER_INSTALLED"

#: The host GPU stack answered; a container can be given the GPU.
GPU_OK = "ok"

#: The loaded kernel module and the installed userspace driver are different
#: versions. A driver upgrade landed while the old module was still in memory.
#: The ONLY fix is to reboot (or reload the module) so the versions match.
GPU_DRIVER_VERSION_MISMATCH = "driver_version_mismatch"

#: The driver is present but does not answer (NVML initialisation fails for a
#: reason other than a version mismatch, the library is missing, the device
#: nodes are unusable).
GPU_DRIVER_UNAVAILABLE = "driver_unavailable"

#: The container toolkit itself is absent, so Docker cannot wire a GPU in even
#: though the host has one.
GPU_TOOLKIT_MISSING = "toolkit_missing"

#: Something failed that we could not classify. Kept distinct from the three
#: above so the copy never asserts a cause we did not observe.
GPU_UNKNOWN = "unknown"

_DEGRADED_CODES: frozenset[str] = frozenset(
    {
        GPU_DRIVER_VERSION_MISMATCH,
        GPU_DRIVER_UNAVAILABLE,
        GPU_TOOLKIT_MISSING,
        GPU_UNKNOWN,
    }
)


@dataclass(frozen=True)
class GpuDegradationCopy:
    """Client-facing copy for one GPU-degradation diagnosis.

    Attributes:
        title: Panel title, already carrying the severity glyph.
        headline: What was observed, in the operator's terms. States only the
            observation, never a guess about why.
        fix_lines: The concrete fix, most likely first. Empty when there is no
            action the operator can take from here.
        verify_command: The command that proves the fix worked, if any.
        requires_restart: True when the fix is to restart the host. Surfaced
            separately because it is the one fix an operator does not expect
            from a security scanner and will otherwise not try.
        container_sentence: One sentence the CONTAINER prints when hashcat
            finds no device, so the in-scan message names the same cause as
            the launcher panel.
    """

    title: str
    headline: str
    fix_lines: tuple[str, ...]
    verify_command: str | None
    requires_restart: bool
    container_sentence: str


def is_degraded_code(code: str | None) -> bool:
    """Return whether ``code`` names a GPU degradation worth reporting."""
    return str(code or "").strip().lower() in _DEGRADED_CODES


def gpu_degradation_copy(
    code: str,
    *,
    loaded_driver: str | None = None,
    installed_driver: str | None = None,
) -> GpuDegradationCopy:
    """Return the copy for one diagnosis code.

    Args:
        code: One of the ``GPU_*`` codes. An unknown value degrades to
            :data:`GPU_UNKNOWN` rather than raising, so a newer launcher
            talking to an older container never breaks the message.
        loaded_driver: Host kernel module version, when the launcher read it.
        installed_driver: Host userspace driver version, when known.

    Returns:
        The copy both surfaces render.
    """
    normalized = str(code or "").strip().lower()
    if normalized == GPU_DRIVER_VERSION_MISMATCH:
        versions = ""
        if loaded_driver and installed_driver:
            versions = (
                f" The kernel module in memory is {loaded_driver} while the "
                f"installed driver is {installed_driver}."
            )
        return GpuDegradationCopy(
            title="Reduced Cracking Mode · host GPU driver needs a restart",
            headline=(
                "The host's NVIDIA kernel module and its installed driver are "
                "different versions, so the GPU cannot be handed to the scan "
                "container." + versions
            ),
            fix_lines=(
                "Restart this host. The driver was upgraded while the old "
                "module was still loaded; a restart loads the matching one.",
                "Or skip the GPU for this run: ADSCAN_DOCKER_GPU=0",
            ),
            verify_command="nvidia-smi",
            requires_restart=True,
            container_sentence=(
                "The host GPU is unavailable because its NVIDIA kernel module "
                "and installed driver are different versions. Restart the host "
                "to use GPU cracking."
            ),
        )
    if normalized == GPU_DRIVER_UNAVAILABLE:
        return GpuDegradationCopy(
            title="Reduced Cracking Mode · host GPU driver not responding",
            headline=(
                "The host has an NVIDIA device but its driver does not answer, "
                "so the GPU cannot be handed to the scan container."
            ),
            fix_lines=(
                "Check the host driver with nvidia-smi, then restart the host "
                "if it reports an error.",
                "Or skip the GPU for this run: ADSCAN_DOCKER_GPU=0",
            ),
            verify_command="nvidia-smi",
            requires_restart=False,
            container_sentence=(
                "The host GPU is unavailable because its NVIDIA driver does not "
                "answer. Check nvidia-smi on the host."
            ),
        )
    if normalized == GPU_TOOLKIT_MISSING:
        return GpuDegradationCopy(
            title="Reduced Cracking Mode · container GPU support missing",
            headline=(
                "The host has an NVIDIA device, but the container toolkit that "
                "passes it into a container is not installed."
            ),
            fix_lines=(
                "Install nvidia-container-toolkit on the host and restart the "
                "Docker daemon.",
            ),
            verify_command="nvidia-container-cli info",
            requires_restart=False,
            container_sentence=(
                "The host GPU is unavailable because the NVIDIA container "
                "toolkit is not installed on the host."
            ),
        )
    return GpuDegradationCopy(
        title="Reduced Cracking Mode · host GPU unavailable",
        headline=(
            "The host has an NVIDIA device, but it could not be handed to the "
            "scan container."
        ),
        fix_lines=(
            "Check the host GPU stack with nvidia-smi and nvidia-container-cli info.",
            "Or skip the GPU for this run: ADSCAN_DOCKER_GPU=0",
        ),
        verify_command="nvidia-container-cli info",
        requires_restart=False,
        container_sentence=("The host GPU could not be handed to this container."),
    )


def gpu_degradation_from_env(
    env: Mapping[str, str] | None = None,
) -> GpuDegradationCopy | None:
    """Return the copy the launcher forwarded, or None when it forwarded none.

    This is the container's entry point: the launcher sets
    :data:`ENV_GPU_DEGRADED` when it dropped ``--gpus`` after a conclusive
    probe, so an in-scan "no compute device" message can name the real cause
    and the real fix instead of guessing.
    """
    source = os.environ if env is None else env
    code = str(source.get(ENV_GPU_DEGRADED, "") or "").strip().lower()
    if not is_degraded_code(code):
        return None
    return gpu_degradation_copy(
        code,
        loaded_driver=str(source.get(ENV_GPU_DRIVER_LOADED, "") or "").strip() or None,
        installed_driver=str(source.get(ENV_GPU_DRIVER_INSTALLED, "") or "").strip()
        or None,
    )
