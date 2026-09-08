"""Network-capability availability seam for the PAL.

Answers "does this host have network capability X?" so the application can
degrade honestly when a capability is unavailable, and a Windows backend can
report availability rather than crash.

The three capability names unify the two existing vocabularies:
``adscan_core.linux_capabilities`` (BIND_SERVICE / NET_ADMIN bits) and the raw
``CAP_NET_RAW`` bit (13). Every query returns a :class:`CapabilityStatus` and
NEVER raises — an unknown capability, a Windows host lacking NET_RAW/NET_ADMIN,
or any probe failure all degrade to ``available=False`` with an honest reason.

``adscan_core.linux_capabilities`` is imported ONLY inside the POSIX branch: it
reads ``/proc`` and shells ``getcap``, so it is Linux-only. Importing this
module on Windows must succeed.
"""
from __future__ import annotations

from dataclasses import dataclass

from adscan_core.pal.platform import current_os, is_windows

# Unified capability vocabulary.
NET_BIND_PRIVILEGED = "NET_BIND_PRIVILEGED"
NET_RAW = "NET_RAW"
NET_ADMIN = "NET_ADMIN"

# CAP_NET_RAW is Linux capability bit 13 (not exported by linux_capabilities).
_CAP_NET_RAW_BIT = 13


@dataclass(frozen=True)
class CapabilityStatus:
    """Result of a capability query.

    Attributes:
        available: Whether the capability is usable on this host right now.
        reason: Short, human-readable English explanation of the verdict.
        os: The resolved PAL OS ("windows" or "posix").
    """

    available: bool
    reason: str
    os: str


def _euid_is_root() -> bool:
    """Return whether the current POSIX process runs as root (euid 0)."""

    try:
        import os

        return hasattr(os, "geteuid") and os.geteuid() == 0
    except Exception:
        return False


def _windows_is_elevated() -> bool:
    """Best-effort check for an elevated Windows process; False on any failure."""

    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


def _capability_available_windows(name: str) -> CapabilityStatus:
    """Resolve a capability on Windows without raising."""

    if name == NET_BIND_PRIVILEGED:
        if _windows_is_elevated():
            return CapabilityStatus(
                available=True,
                reason="running elevated (administrator)",
                os="windows",
            )
        return CapabilityStatus(
            available=False,
            reason="binding privileged ports requires an elevated process on Windows (degraded)",
            os="windows",
        )
    if name in (NET_RAW, NET_ADMIN):
        return CapabilityStatus(
            available=False,
            reason="requires Npcap / admin on Windows (degraded)",
            os="windows",
        )
    return CapabilityStatus(
        available=False,
        reason=f"unknown capability '{name}'",
        os="windows",
    )


def _capability_available_posix(name: str) -> CapabilityStatus:
    """Resolve a capability on POSIX without raising."""

    try:
        # Linux-only: reads /proc and shells getcap. Import inside the branch so
        # the module imports cleanly on Windows.
        from adscan_core.linux_capabilities import (
            CAP_NET_ADMIN_BIT,
            CAP_NET_BIND_SERVICE_BIT,
            process_has_capability,
        )
    except Exception as exc:  # noqa: BLE001
        return CapabilityStatus(
            available=False,
            reason=f"could not query Linux capabilities: {exc}",
            os="posix",
        )

    try:
        if name == NET_BIND_PRIVILEGED:
            if process_has_capability(CAP_NET_BIND_SERVICE_BIT) or _euid_is_root():
                return CapabilityStatus(
                    available=True,
                    reason="process has CAP_NET_BIND_SERVICE or runs as root",
                    os="posix",
                )
            return CapabilityStatus(
                available=False,
                reason="process lacks CAP_NET_BIND_SERVICE and is not root",
                os="posix",
            )
        if name == NET_ADMIN:
            if process_has_capability(CAP_NET_ADMIN_BIT):
                return CapabilityStatus(
                    available=True,
                    reason="process has CAP_NET_ADMIN",
                    os="posix",
                )
            return CapabilityStatus(
                available=False,
                reason="process lacks CAP_NET_ADMIN",
                os="posix",
            )
        if name == NET_RAW:
            if process_has_capability(_CAP_NET_RAW_BIT) or _euid_is_root():
                return CapabilityStatus(
                    available=True,
                    reason="process has CAP_NET_RAW or runs as root",
                    os="posix",
                )
            return CapabilityStatus(
                available=False,
                reason="process lacks CAP_NET_RAW and is not root",
                os="posix",
            )
    except Exception as exc:  # noqa: BLE001
        return CapabilityStatus(
            available=False,
            reason=f"capability probe failed: {exc}",
            os="posix",
        )

    return CapabilityStatus(
        available=False,
        reason=f"unknown capability '{name}'",
        os="posix",
    )


def capability_available(name: str) -> CapabilityStatus:
    """Return whether one network capability is available on this host.

    Never raises. An unknown capability name degrades to an unavailable status
    with an honest reason.

    Args:
        name: One of :data:`NET_BIND_PRIVILEGED`, :data:`NET_RAW`,
            :data:`NET_ADMIN` (any other value is treated as unknown).

    Returns:
        A :class:`CapabilityStatus` describing availability and the reason.
    """

    try:
        if is_windows():
            return _capability_available_windows(name)
        return _capability_available_posix(name)
    except Exception as exc:  # noqa: BLE001
        return CapabilityStatus(
            available=False,
            reason=f"capability query failed: {exc}",
            os=current_os(),
        )


def can_bind_privileged_port() -> bool:
    """Return whether this host can bind privileged (<1024) ports."""

    return capability_available(NET_BIND_PRIVILEGED).available


def _is_valid_ipv4(candidate: str) -> bool:
    """Return whether ``candidate`` parses as an IPv4 address."""

    try:
        import ipaddress

        ipaddress.ip_address(candidate)
        return True
    except Exception:
        return False


def interface_names() -> list[str]:
    """Return the names of all local network interfaces.

    POSIX enumerates via ``netifaces.interfaces()``; Windows via
    ``psutil.net_if_addrs()``. Returns an empty list on any error.
    """

    try:
        if is_windows():
            import psutil

            return list(psutil.net_if_addrs().keys())
        import netifaces

        return [str(name) for name in netifaces.interfaces()]
    except Exception:
        return []


def interface_ipv4_addresses_for(interface_name: str) -> list[str]:
    """Return all IPv4 addresses configured on one named interface.

    POSIX reads ``netifaces.ifaddresses(iface)[AF_INET]``; Windows filters
    ``psutil.net_if_addrs()[iface]`` entries on ``socket.AF_INET``. Returns an
    empty list on any error rather than raising.
    """

    if not interface_name:
        return []
    try:
        values: list[str] = []
        if is_windows():
            import socket

            import psutil

            entries = psutil.net_if_addrs().get(interface_name) or []
            for entry in entries:
                if entry.family != socket.AF_INET:
                    continue
                candidate = str(entry.address or "").strip()
                if candidate and _is_valid_ipv4(candidate):
                    values.append(candidate)
            return values

        import netifaces

        addresses = netifaces.ifaddresses(interface_name)
        for entry in addresses.get(netifaces.AF_INET) or []:
            candidate = str(entry.get("addr", "")).strip()
            if candidate and _is_valid_ipv4(candidate):
                values.append(candidate)
        return values
    except Exception:
        return []


def interface_ipv4_for(interface_name: str) -> str | None:
    """Return the first IPv4 address bound to one named interface, or ``None``."""

    addresses = interface_ipv4_addresses_for(interface_name)
    return addresses[0] if addresses else None


def interface_ipv4_addresses() -> list[str]:
    """Return all IPv4 addresses configured across local interfaces.

    OS-aware: POSIX via ``netifaces``, Windows via ``psutil.net_if_addrs()``.
    Returns an empty list on any error rather than raising.
    """

    values: list[str] = []
    for interface in interface_names():
        values.extend(interface_ipv4_addresses_for(interface))
    return values


def interface_mac_ipv4_linklocal(interface_name: str) -> tuple[str, str, str] | None:
    """Return ``(mac, ipv4, ipv6_linklocal)`` for one interface, or ``None``.

    All three are required (mitm6 needs the MAC, an IPv4, and the first
    ``fe80:`` link-local IPv6 with any ``%scope`` suffix stripped); ``None`` is
    returned if any is missing or on any error.

    POSIX reads ``netifaces`` ``AF_LINK`` / ``AF_INET`` / ``AF_INET6``; Windows
    reads ``psutil.AF_LINK`` (MAC), ``socket.AF_INET`` (IPv4), and
    ``socket.AF_INET6`` (link-local). This mirrors the historical
    ``mitm6/core.py`` selection exactly on POSIX.
    """

    if not interface_name:
        return None
    try:
        if is_windows():
            import socket

            import psutil

            entries = psutil.net_if_addrs().get(interface_name) or []
            mac = next(
                (str(e.address) for e in entries if e.family == psutil.AF_LINK and e.address),
                None,
            )
            ipv4 = next(
                (str(e.address) for e in entries if e.family == socket.AF_INET and e.address),
                None,
            )
            linklocal = None
            for entry in entries:
                if entry.family != socket.AF_INET6:
                    continue
                bare = str(entry.address or "").split("%", 1)[0]
                if bare.lower().startswith("fe80:"):
                    linklocal = bare
                    break
        else:
            import netifaces

            addrs = netifaces.ifaddresses(interface_name)
            mac_entries = addrs.get(netifaces.AF_LINK, [])
            ipv4_entries = addrs.get(netifaces.AF_INET, [])
            ipv6_entries = addrs.get(netifaces.AF_INET6, [])
            mac = next((e["addr"] for e in mac_entries if e.get("addr")), None)
            ipv4 = next((e["addr"] for e in ipv4_entries if e.get("addr")), None)
            linklocal = None
            for entry in ipv6_entries:
                # netifaces returns link-local with %iface scope appended on Linux.
                bare = entry.get("addr", "").split("%", 1)[0]
                if bare.lower().startswith("fe80:"):
                    linklocal = bare
                    break

        if not (mac and ipv4 and linklocal):
            return None
        return mac, ipv4, linklocal
    except Exception:
        return None


__all__ = [
    "NET_ADMIN",
    "NET_BIND_PRIVILEGED",
    "NET_RAW",
    "CapabilityStatus",
    "can_bind_privileged_port",
    "capability_available",
    "interface_ipv4_addresses",
    "interface_ipv4_addresses_for",
    "interface_ipv4_for",
    "interface_mac_ipv4_linklocal",
    "interface_names",
]
