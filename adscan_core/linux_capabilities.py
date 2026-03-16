"""Minimal Linux capability helpers shared across ADscan components."""

from __future__ import annotations

import subprocess


CAP_NET_BIND_SERVICE_BIT = 10
CAP_NET_ADMIN_BIT = 12


def process_has_capability(bit: int) -> bool:
    """Return whether the current process has one effective Linux capability bit."""

    try:
        with open("/proc/self/status", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("CapEff:"):
                    raw_value = line.split(":", 1)[1].strip()
                    effective_caps = int(raw_value, 16)
                    return bool(effective_caps & (1 << int(bit)))
    except Exception:
        return False
    return False


def get_binary_capabilities(binary_path: str) -> str:
    """Return the raw `getcap` output for one binary, if available."""

    candidate = str(binary_path or "").strip()
    if not candidate:
        return ""
    try:
        result = subprocess.run(
            ["getcap", candidate],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        return ""
    return " ".join(
        part.strip()
        for part in (result.stdout, result.stderr)
        if str(part).strip()
    ).strip()


def binary_has_capability(binary_path: str, capability_name: str) -> bool:
    """Return whether one binary carries the requested file capability."""

    capability = str(capability_name or "").strip()
    if not capability:
        return False
    return capability in get_binary_capabilities(binary_path)


__all__ = [
    "CAP_NET_ADMIN_BIT",
    "CAP_NET_BIND_SERVICE_BIT",
    "binary_has_capability",
    "get_binary_capabilities",
    "process_has_capability",
]
