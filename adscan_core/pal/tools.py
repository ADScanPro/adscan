"""External-tool capability registry for the PAL.

A declarative map of "capability -> per-OS strategy". Each capability is served
one of three ways on a given OS:

* ``NATIVE`` — implemented in-process in pure Python (e.g. mass DNS resolution
  via dnspython), so it is always available regardless of what is on disk.
* ``EMBEDDED_BINARY`` — a bundled or installed helper executable (hashcat, john,
  rclone, chromium via Playwright, …); available iff the binary is found.
* ``DEGRADE`` — deliberately not shipped on this OS; the capability is
  unavailable and the report says so honestly, with the native alternative the
  operator uses instead.

Callers ask :func:`capability_available` "can I do X here?" and the report uses
:func:`build_tools_coverage` / :func:`tools_coverage_view` to declare which
capabilities were available on the run platform and which degraded — the same
"what ran / what was unavailable" shape as
:mod:`adscan_core.reporting.cracking_coverage`, so a client meets both gap
declarations worded consistently.

Pure logic against the PAL: no console, no network, no ``adscan_internal`` /
``adscan_launcher`` imports. ``resolve_strategy`` and ``capability_available``
never raise — an unknown key degrades cleanly rather than blowing up a caller.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from adscan_core.pal import paths as pal_paths
from adscan_core.pal.platform import current_os, is_windows


class Strategy(Enum):
    """How a capability is served on a given OS."""

    NATIVE = "native"
    EMBEDDED_BINARY = "embedded_binary"
    DEGRADE = "degrade"


@dataclass(frozen=True, slots=True)
class ToolCapability:
    """One external-tool capability and its per-OS delivery strategy.

    Attributes:
        key: Stable capability identifier callers ask for.
        title: Human-facing name for the report.
        strategy_by_os: Map of OS name (``"posix"`` / ``"windows"``) to the
            :class:`Strategy` used there.
        binary_name: Executable to resolve when the strategy is
            ``EMBEDDED_BINARY``; ``None`` for native or externally-managed
            capabilities (e.g. Playwright-managed Chromium).
        native_note: Honest, client-safe explanation of what happens when the
            capability degrades (the native alternative the operator uses).
    """

    key: str
    title: str
    strategy_by_os: dict[str, Strategy] = field(default_factory=dict)
    binary_name: str | None = None
    native_note: str | None = None


@dataclass(frozen=True, slots=True)
class ToolStatus:
    """Resolved availability of one capability on the current platform."""

    key: str
    available: bool
    strategy: Strategy
    reason: str
    os: str


_TOOL_REGISTRY: dict[str, ToolCapability] = {
    "cracking_gpu": ToolCapability(
        key="cracking_gpu",
        title="GPU password recovery",
        strategy_by_os={"posix": Strategy.EMBEDDED_BINARY, "windows": Strategy.EMBEDDED_BINARY},
        binary_name="hashcat",
    ),
    "cracking_cpu": ToolCapability(
        key="cracking_cpu",
        title="CPU password recovery",
        strategy_by_os={"posix": Strategy.EMBEDDED_BINARY, "windows": Strategy.EMBEDDED_BINARY},
        binary_name="john",
    ),
    "kerberos_bruteforce": ToolCapability(
        key="kerberos_bruteforce",
        title="Kerberos user enumeration and spraying",
        strategy_by_os={"posix": Strategy.EMBEDDED_BINARY, "windows": Strategy.EMBEDDED_BINARY},
        binary_name="kerbrute",
    ),
    "share_mapping": ToolCapability(
        key="share_mapping",
        title="Share mapping and file transfer",
        strategy_by_os={"posix": Strategy.EMBEDDED_BINARY, "windows": Strategy.EMBEDDED_BINARY},
        binary_name="rclone",
    ),
    "report_pdf": ToolCapability(
        key="report_pdf",
        title="PDF report rendering",
        strategy_by_os={"posix": Strategy.EMBEDDED_BINARY, "windows": Strategy.EMBEDDED_BINARY},
        binary_name=None,
    ),
    "dns_mass_resolution": ToolCapability(
        key="dns_mass_resolution",
        title="Mass DNS resolution",
        strategy_by_os={"posix": Strategy.NATIVE, "windows": Strategy.NATIVE},
        binary_name=None,
    ),
    "share_spider": ToolCapability(
        key="share_spider",
        title="Share spidering",
        strategy_by_os={"posix": Strategy.EMBEDDED_BINARY, "windows": Strategy.DEGRADE},
        binary_name="manspider",
        native_note="rclone is the primary path; manspider is the fallback, not shipped on Windows v1",
    ),
    "vm_forensics": ToolCapability(
        key="vm_forensics",
        title="Memory-image forensics",
        strategy_by_os={"posix": Strategy.EMBEDDED_BINARY, "windows": Strategy.DEGRADE},
        binary_name="volatility",
    ),
    "rdp_interactive": ToolCapability(
        key="rdp_interactive",
        title="Interactive RDP session",
        strategy_by_os={"posix": Strategy.EMBEDDED_BINARY, "windows": Strategy.DEGRADE},
        binary_name="xfreerdp",
        native_note="operator uses native mstsc on Windows",
    ),
    "local_resolver": ToolCapability(
        key="local_resolver",
        title="Local recursive DNS resolver",
        strategy_by_os={"posix": Strategy.EMBEDDED_BINARY, "windows": Strategy.DEGRADE},
        binary_name="unbound",
        native_note="Windows uses the host DNS resolver",
    ),
}


# How deep the bundled-tool recursive search descends under ``tools/<name>/``.
# The real nested layouts are at most ``tools/<name>/<versioned>/run/<name>.exe``
# (john) — three levels below ``tools/<name>``. The cap keeps the walk bounded so
# a pathological deep tree can never turn the lookup into an unbounded scan.
_BUNDLED_SEARCH_MAX_DEPTH = 4


def _bundled_binary_filename(binary_name: str) -> str:
    """Return the on-disk filename for a tool on the current platform."""

    return f"{binary_name}.exe" if is_windows() else binary_name


def resolve_bundled_tool(binary_name: str) -> Path | None:
    """Locate a bundled helper binary under the PAL tools dir, layout-aware.

    The bundled tools are each nested differently under ``tools/``:

    * ``tools/<name>[.exe]``                        (flat — kept for the future),
    * ``tools/<name>/<name>[.exe]``                 (kerbrute, rclone),
    * ``tools/<name>/<versioned>/<name>[.exe]``     (hashcat),
    * ``tools/<name>/<versioned>/run/<name>[.exe]`` (john).

    The versioned nesting is covered by a bounded recursive search under
    ``tools/<name>/`` (depth ``<= _BUNDLED_SEARCH_MAX_DEPTH``). Only a real FILE
    matches — the ``tools/<name>`` directory itself never counts. This is the
    single source of truth every consumer (``resolve_john_path``, hashcat and
    rclone discovery) should call so PAL availability and the per-tool resolvers
    can never disagree.

    Returns the resolved path, or ``None`` when no bundled binary exists.
    Best-effort: any filesystem error is treated as absent (never raises).
    """

    name = str(binary_name or "").strip()
    if not name:
        return None

    filename = _bundled_binary_filename(name)
    try:
        tools_root = pal_paths.tools_dir()
    except Exception:
        return None

    # Fast paths for the known-shallow layouts (avoid a walk when possible).
    for candidate in (tools_root / filename, tools_root / name / filename):
        try:
            if candidate.is_file():
                return candidate
        except Exception:
            continue

    # Bounded recursive search under tools/<name>/ for the versioned/run nesting.
    tool_dir = tools_root / name
    try:
        if not tool_dir.is_dir():
            return None
    except Exception:
        return None

    try:
        base_depth = len(tool_dir.parts)
        for path in tool_dir.rglob(filename):
            try:
                if not path.is_file():
                    continue
                if len(path.parts) - base_depth > _BUNDLED_SEARCH_MAX_DEPTH:
                    continue
                return path
            except Exception:
                continue
    except Exception:
        return None
    return None


def _binary_present(binary_name: str) -> bool:
    """Return whether a helper binary can be found on the current platform.

    Checks the PAL-resolved bundled locations first (layout-aware, via
    :func:`resolve_bundled_tool`), then the operator's PATH. Best-effort: any
    resolution error is treated as absent.
    """

    try:
        if resolve_bundled_tool(binary_name) is not None:
            return True
    except Exception:
        pass
    try:
        return shutil.which(binary_name) is not None
    except Exception:
        return False


def resolve_strategy(key: str) -> Strategy:
    """Return the delivery strategy for a capability on the current OS.

    An unknown key, or a capability with no strategy declared for the current
    OS, resolves to :attr:`Strategy.DEGRADE`. Never raises.
    """

    capability = _TOOL_REGISTRY.get(str(key or "").strip())
    if capability is None:
        return Strategy.DEGRADE
    return capability.strategy_by_os.get(current_os(), Strategy.DEGRADE)


def capability_available(key: str) -> ToolStatus:
    """Resolve whether a capability is available on the current platform.

    * ``NATIVE`` is always available.
    * ``EMBEDDED_BINARY`` is available iff the binary is found (PAL tools dir or
      PATH). A capability with no ``binary_name`` (externally managed, e.g.
      Playwright-managed Chromium) is treated as available under this strategy.
    * ``DEGRADE`` is unavailable; the reason is the capability's ``native_note``
      when set, otherwise a generic honest note.

    Never raises: an unknown key yields an unavailable, degraded status.
    """

    os_name = current_os()
    normalized = str(key or "").strip()
    capability = _TOOL_REGISTRY.get(normalized)
    if capability is None:
        return ToolStatus(
            key=normalized,
            available=False,
            strategy=Strategy.DEGRADE,
            reason="No capability registered under this key.",
            os=os_name,
        )

    strategy = capability.strategy_by_os.get(os_name, Strategy.DEGRADE)

    if strategy == Strategy.NATIVE:
        reason = capability.native_note or "Served in-process (native)."
        return ToolStatus(key=normalized, available=True, strategy=strategy, reason=reason, os=os_name)

    if strategy == Strategy.EMBEDDED_BINARY:
        if capability.binary_name is None:
            return ToolStatus(
                key=normalized,
                available=True,
                strategy=strategy,
                reason="Externally managed helper.",
                os=os_name,
            )
        if _binary_present(capability.binary_name):
            return ToolStatus(
                key=normalized,
                available=True,
                strategy=strategy,
                reason=f"'{capability.binary_name}' is available.",
                os=os_name,
            )
        return ToolStatus(
            key=normalized,
            available=False,
            strategy=strategy,
            reason=f"'{capability.binary_name}' was not found on this platform.",
            os=os_name,
        )

    # DEGRADE
    reason = capability.native_note or f"{capability.title} is not available on {os_name}."
    return ToolStatus(key=normalized, available=False, strategy=strategy, reason=reason, os=os_name)


def build_tools_coverage(statuses: list[ToolStatus]) -> dict[str, Any]:
    """Build the ``tools_coverage`` block from resolved capability statuses.

    Mirrors :func:`adscan_core.reporting.cracking_coverage.build_cracking_coverage`:
    a persisted block the report reads back through :func:`tools_coverage_view`,
    declaring which capabilities were available on the run platform and which
    degraded. The block always carries ``statement`` so a consumer never has to
    derive one.

    Returns a mapping with:
      * ``available`` — capability keys available on this platform;
      * ``degraded`` — ``{key, reason}`` for each unavailable capability;
      * ``os`` — the platform the run resolved against;
      * ``complete`` — ``True`` when nothing degraded;
      * ``statement`` — the client-facing sentence.
    """

    available: list[str] = []
    degraded: list[dict[str, str]] = []
    os_name = current_os()
    for status in statuses or ():
        if not isinstance(status, ToolStatus):
            continue
        os_name = status.os or os_name
        if status.available:
            available.append(status.key)
        else:
            degraded.append({"key": status.key, "reason": status.reason})

    complete = not degraded
    return {
        "complete": complete,
        "available": available,
        "degraded": degraded,
        "os": os_name,
        "statement": _statement_for(complete, degraded, os_name),
    }


def _statement_for(complete: bool, degraded: list[dict[str, str]], os_name: str) -> str:
    """Render the client-facing sentence for a tools-coverage block."""

    if complete:
        return f"Every assessment capability was available on this platform ({os_name})."
    names = ", ".join(item.get("key", "") for item in degraded if item.get("key"))
    return (
        f"Some assessment capabilities were unavailable on this platform ({os_name}) and "
        f"used their native alternative or were not run: {names}."
    )


def tools_coverage_view(block: Any) -> dict[str, Any]:
    """Return the render-ready view of a persisted ``tools_coverage`` block.

    The one shape the PDF report and the web platform both read, so a
    capability gap is worded identically wherever a client meets it. Mirrors
    :func:`adscan_core.reporting.cracking_coverage.cracking_coverage_view`.

    An absent or unreadable block yields ``has_gap=False`` with an empty
    statement — a scan predating this record must render exactly as before
    rather than grow a gap notice nobody observed.
    """

    if not isinstance(block, Mapping):
        return {"has_gap": False, "statement": "", "degraded": [], "os": ""}

    degraded_raw = block.get("degraded")
    degraded: list[dict[str, str]] = []
    if isinstance(degraded_raw, (list, tuple)):
        for item in degraded_raw:
            if isinstance(item, Mapping):
                degraded.append(
                    {
                        "key": str(item.get("key") or "").strip(),
                        "reason": str(item.get("reason") or "").strip(),
                    }
                )

    complete = bool(block.get("complete", not degraded))
    statement = str(block.get("statement") or "").strip()
    has_gap = bool(not complete and degraded)
    return {
        "has_gap": has_gap,
        "statement": statement if has_gap else "",
        "degraded": degraded,
        "os": str(block.get("os") or "").strip(),
    }


__all__ = [
    "Strategy",
    "ToolCapability",
    "ToolStatus",
    "resolve_strategy",
    "resolve_bundled_tool",
    "capability_available",
    "build_tools_coverage",
    "tools_coverage_view",
]
