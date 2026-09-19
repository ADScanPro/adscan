"""Shared diagnosis for the NumPy x86-64-v2 baseline failure (SSOT).

NumPy 2.x is built against the x86-64-v2 CPU baseline (it needs SSE4.2 and
POPCNT). Any bundled tool that imports numpy or pandas (credential scanning,
and others) inherits that requirement and refuses to import on a CPU that
lacks it. The realistic trigger is a virtual machine whose hypervisor exposes
a generic virtual CPU model (QEMU/KVM ``kvm64`` / ``qemu64``) that hides those
instructions, even though the physical host supports them. The raw
``RuntimeError: NumPy was built with baseline optimizations: (X86_V2) ...``
reads like a broken install, so ADscan names the real cause and the fix.

This module is the single source of truth for detecting that failure and for
the remediation wording, so every surface that can hit it (the startup tool
check, a scan-time credential-scan crash) says the same thing. It is a
LITE-safe leaf: it imports nothing beyond the standard library, so it is safe
to import from both ``adscan_internal/cli`` and ``adscan_internal/services``.
"""

from __future__ import annotations


def is_numpy_baseline_failure(text: str | None) -> bool:
    """Return True when ``text`` is a NumPy x86-64-v2 baseline import failure.

    Matches the NumPy runtime message regardless of whether a full traceback was
    captured: the ``baseline optimizations`` phrase is unique to it, and the
    ``x86_v2`` / ``doesn't support`` tokens alongside ``numpy`` are a belt-and-
    suspenders fallback for a truncated or reworded variant.

    Args:
        text: The captured error / traceback / stderr text to inspect.

    Returns:
        True if the text is the NumPy baseline-unsupported failure.
    """
    lowered = (text or "").lower()
    if "baseline optimizations" in lowered:
        return True
    return "numpy" in lowered and ("x86_v2" in lowered or "doesn't support" in lowered)


def numpy_baseline_warning(subject: str) -> str:
    """Return the one-line cause message, naming ``subject`` (the tool/feature)."""
    return (
        f"{subject} could not start because this machine's CPU is missing the "
        "x86-64-v2 instruction set (SSE4.2 / POPCNT) that NumPy 2.x needs."
    )


def numpy_baseline_instructions() -> tuple[str, str]:
    """Return the two remediation lines (VM cause, then the host-CPU fix)."""
    return (
        "This is common inside a VM: many hypervisors (QEMU/KVM) default to a "
        "generic virtual CPU that hides those instructions.",
        "Fix: give the VM the host CPU. QEMU/KVM: `-cpu host`; libvirt/virt-manager: "
        "CPU model 'host-passthrough'; then restart the VM. (VirtualBox usually works as-is.)",
    )


__all__ = [
    "is_numpy_baseline_failure",
    "numpy_baseline_warning",
    "numpy_baseline_instructions",
]
