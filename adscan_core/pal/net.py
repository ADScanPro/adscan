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

The module also owns interface ENUMERATION (names, IPv4 addresses, the MAC /
link-local triple) and interface TYPING (:func:`interface_kind`). Typing lives
here for the same reason enumeration does: whether an interface is a real NIC, a
bridge or container plumbing is an OS fact the kernel already records, so it is
read from the kernel behind one API with a Linux and a Windows side, never
guessed from the interface's name in a caller.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum

from adscan_core.pal.platform import current_os, is_windows

# Unified capability vocabulary.
NET_BIND_PRIVILEGED = "NET_BIND_PRIVILEGED"
NET_RAW = "NET_RAW"
NET_ADMIN = "NET_ADMIN"

# CAP_NET_RAW is Linux capability bit 13 (not exported by linux_capabilities).
_CAP_NET_RAW_BIT = 13


class InterfaceKind(StrEnum):
    """What kind of device one network interface is.

    A ``StrEnum`` so it serialises naturally into a telemetry payload or a debug
    line. The vocabulary is deliberately about what the interface *is*, not about
    what a caller should do with it: ordering and usability are policy decisions
    that belong to the consumer (see
    ``adscan_internal.services.listener_ip``), not to the PAL.
    """

    #: A real NIC with backing hardware: ethernet, wifi, a VM's own virtio NIC.
    PHYSICAL = "physical"
    #: Rides a real NIC: a VLAN subinterface, a bond, a bridge that enslaves a
    #: physical port (a libvirt host bridging guests onto the client LAN).
    STACKED = "stacked"
    #: A tunnel that carries routed traffic: tun/tap (OpenVPN, Tailscale),
    #: WireGuard, IP-in-IP / GRE / SIT encapsulation.
    TUNNEL = "tunnel"
    #: A local-only L2 bridge with no physical port: ``docker0``, a compose
    #: ``br-<id>``, ``virbr0``, a Kubernetes ``cni0``/``cbr0``.
    BRIDGE = "bridge"
    #: Virtual plumbing that reaches nothing outside this host: a veth pair end
    #: (which is what a bridge-mode container's own ``eth0`` is), an overlay
    #: encapsulation device, a dummy, a VMware ``vmnet`` host-only adapter.
    VIRTUAL_OTHER = "virtual_other"
    #: The loopback device.
    LOOPBACK = "loopback"
    #: The OS exposes no kind for this interface. Windows (``psutil`` carries no
    #: adapter description) and an unreadable ``/sys`` both land here. NOT a
    #: verdict about the interface: the caller falls back to its own heuristic.
    UNKNOWN = "unknown"


#: Where the Linux kernel publishes per-interface facts.
_SYSFS_NET_ROOT = "/sys/class/net"

#: Path segment every software-only device sits under. Checked as a RELATIVE
#: segment, not an absolute prefix, so a fake sysfs tree in a test behaves the
#: same as the real one.
_SYSFS_VIRTUAL_SEGMENT = os.path.join("devices", "virtual", "net")

#: ``/sys/class/net/<n>/type`` values that settle the kind on their own. These
#: are the ``ARPHRD_*`` constants from ``<linux/if_arp.h>``; measured against a
#: real kernel rather than taken from documentation.
_ARPHRD_LOOPBACK = 772
_ARPHRD_IP_TUNNEL_TYPES = frozenset(
    {
        768,  # ARPHRD_TUNNEL  - IP-in-IP (ipip, and Calico's tunl0)
        769,  # ARPHRD_TUNNEL6 - IPv6 tunnel
        776,  # ARPHRD_SIT     - IPv6-in-IPv4
        778,  # ARPHRD_IPGRE   - GRE over IP
    }
)

#: ``DEVTYPE`` values (from ``/sys/class/net/<n>/uevent``, set by the driver's
#: ``struct device_type``). Only a driver that declares one appears here, so the
#: absence of a ``DEVTYPE`` is never evidence of anything.
_DEVTYPE_BRIDGE = frozenset({"bridge"})
_DEVTYPE_STACKED = frozenset({"vlan", "bond"})
_DEVTYPE_TUNNEL = frozenset({"wireguard"})
#: Reaches the same verdict as the final fallthrough, and kept explicit so that
#: "is a vxlan handled?" has an answer at the point of classification rather than
#: by elimination. ``gretap``/``erspan`` are deliberately absent: measured
#: against a real kernel, their drivers declare no ``DEVTYPE`` at all.
_DEVTYPE_OVERLAY = frozenset({"vxlan", "geneve", "openvswitch"})


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


def _sysfs_text(path: str) -> str:
    """Return a stripped sysfs attribute's text, or ``""`` if unreadable."""

    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read().strip()
    except OSError:
        return ""


def _sysfs_devtype(interface_dir: str) -> str:
    """Return the lower-cased ``DEVTYPE=`` from an interface's ``uevent``."""

    for line in _sysfs_text(os.path.join(interface_dir, "uevent")).splitlines():
        if line.startswith("DEVTYPE="):
            return line.partition("=")[2].strip().lower()
    return ""


def _sysfs_arphrd_type(interface_dir: str) -> int | None:
    """Return the interface's ``ARPHRD_*`` type number, or ``None``."""

    raw = _sysfs_text(os.path.join(interface_dir, "type"))
    try:
        return int(raw)
    except ValueError:
        return None


def _sysfs_has_backing_device(interface_dir: str) -> bool:
    """Return whether this interface has real hardware behind it.

    Two independent signals, OR-ed deliberately toward "physical": the ``device``
    symlink a driver gets from ``SET_NETDEV_DEV``, and the interface NOT living
    under ``devices/virtual/net``. Either one alone is enough, because the costly
    mistake here is demoting a real NIC, never promoting a virtual one.
    """

    if os.path.exists(os.path.join(interface_dir, "device")):
        return True
    try:
        resolved = os.path.realpath(interface_dir)
    except OSError:
        return False
    return _SYSFS_VIRTUAL_SEGMENT not in resolved


def _stacked_on_physical(interface_dir: str, sysfs_net_root: str) -> bool:
    """Return whether this device sits directly on top of a real NIC.

    The kernel publishes netdev adjacency as symlinks on BOTH ends:
    ``lower_<name>`` on the device points DOWN to what it sits on, while
    ``master`` and ``upper_<name>`` point UP to what owns it. Only ``lower_*`` is
    read here, which is what keeps a veth end enslaved to ``docker0`` out: that
    veth has ``master`` and ``upper_docker0`` and no ``lower_*`` at all, so it
    cannot be promoted by this test however the bridge above it is arranged.

    This is the generic form of the ``brif/`` membership test above, and it
    answers the devices whose driver declares no ``DEVTYPE``: ``team`` (the Red
    Hat family's NIC aggregation), ``macvlan`` and ``ipvlan``. ``vlan`` and
    ``bond`` never reach here because they declare one.

    ONE HOP, and the lower device must itself be PHYSICAL by the same
    two-signal test rung 2 uses. One hop is bounded by construction, needs no
    depth cap and no reasoning about cycles, and covers the whole named case (a
    team over real NICs, a macvlan or ipvlan over a real NIC). It deliberately
    declines a chain: a macvlan over a LAN bridge, or over a team, stays
    ``VIRTUAL_OTHER``. That is a shape nobody here has, and it is a RANK rather
    than a reject, so the cost of declining it is that such a device sorts
    behind a real NIC and is still returned when it is the only candidate.
    """

    try:
        entries = os.listdir(interface_dir)
    except OSError:
        return False
    for entry in entries:
        if not entry.startswith("lower_"):
            continue
        lower_name = entry[len("lower_") :]
        if not lower_name or os.sep in lower_name or ".." in lower_name:
            continue
        lower_dir = os.path.join(sysfs_net_root, lower_name)
        if os.path.isdir(lower_dir) and _sysfs_has_backing_device(lower_dir):
            return True
    return False


def _bridge_interface_kind(interface_dir: str, sysfs_net_root: str) -> InterfaceKind:
    """Classify a bridge by whether it enslaves a physical port.

    A bridge carrying a real NIC (a libvirt or Proxmox host that bridges guests
    onto the client LAN, where the bridge holds the only routable address) is
    reachable and reads as :attr:`InterfaceKind.STACKED`. A bridge whose ports
    are all veth ends, or which has no port at all, is container plumbing and
    reads as :attr:`InterfaceKind.BRIDGE`. The name cannot tell these apart,
    which is the whole reason to ask the kernel.
    """

    brif = os.path.join(interface_dir, "brif")
    try:
        members = os.listdir(brif)
    except OSError:
        return InterfaceKind.BRIDGE
    for member in members:
        member_dir = os.path.join(sysfs_net_root, member)
        if os.path.isdir(member_dir) and _sysfs_has_backing_device(member_dir):
            return InterfaceKind.STACKED
    return InterfaceKind.BRIDGE


def interface_kind(
    interface_name: str,
    *,
    sysfs_net_root: str | None = None,
) -> InterfaceKind:
    """Return what kind of device one network interface is.

    "Is this interface container plumbing or a real path off this host?" is an OS
    fact, so it is answered from the kernel rather than guessed from the name. On
    Linux every signal comes from ``/sys/class/net/<name>/``, measured against a
    real kernel: a backing ``device`` link (physical), ``DEVTYPE=bridge`` or a
    ``bridge/`` directory, ``DEVTYPE=wireguard``, a ``tun_flags`` attribute
    (tun/tap, which is how OpenVPN and Tailscale appear), the ``ARPHRD_*``
    ``type`` number for IP-in-IP / GRE / SIT, ``DEVTYPE=vlan``/``bond``, and
    finally a ``lower_*`` adjacency link onto a real NIC (which is how a
    ``team``, ``macvlan`` or ``ipvlan`` is recognised, since those declare no
    ``DEVTYPE``).

    The order of those checks is load-bearing, not incidental: a bridge and an
    overlay BOTH carry ``lower_*`` links, so the adjacency check runs last, after
    every branch that rests on a signal a driver declares.

    Never raises, and never guesses: an interface the kernel does not type, a
    missing or unreadable ``/sys``, and Windows all return
    :attr:`InterfaceKind.UNKNOWN` so the caller can apply its own fallback
    instead of inheriting a fabricated verdict.

    Windows returns ``UNKNOWN`` by design. The PAL's Windows backend is
    ``psutil``, which exposes addresses and link stats but no adapter kind or
    description, and the available alternatives are worse than honest ignorance:
    a WMI dependency is not worth taking for a ranking hint, and a MAC-OUI guess
    would misclassify the real NIC of any ADscan instance running inside a VM.

    Args:
        interface_name: The interface name as the OS reports it.
        sysfs_net_root: Override the sysfs net directory. For tests, which must
            not depend on the NICs of whatever machine runs them.

    Returns:
        The :class:`InterfaceKind`; :attr:`InterfaceKind.UNKNOWN` when the OS
        does not say.
    """

    name = str(interface_name or "").strip()
    if not name or os.sep in name or (os.altsep and os.altsep in name) or ".." in name:
        return InterfaceKind.UNKNOWN

    root = sysfs_net_root
    if root is None:
        if is_windows():
            return InterfaceKind.UNKNOWN
        root = _SYSFS_NET_ROOT

    try:
        interface_dir = os.path.join(root, name)
        if not os.path.isdir(interface_dir):
            return InterfaceKind.UNKNOWN

        if _sysfs_arphrd_type(interface_dir) == _ARPHRD_LOOPBACK:
            return InterfaceKind.LOOPBACK
        if _sysfs_has_backing_device(interface_dir):
            return InterfaceKind.PHYSICAL

        devtype = _sysfs_devtype(interface_dir)
        if devtype in _DEVTYPE_BRIDGE or os.path.isdir(
            os.path.join(interface_dir, "bridge")
        ):
            return _bridge_interface_kind(interface_dir, root)
        if devtype in _DEVTYPE_TUNNEL:
            return InterfaceKind.TUNNEL
        if os.path.exists(os.path.join(interface_dir, "tun_flags")):
            return InterfaceKind.TUNNEL
        if _sysfs_arphrd_type(interface_dir) in _ARPHRD_IP_TUNNEL_TYPES:
            return InterfaceKind.TUNNEL
        if devtype in _DEVTYPE_STACKED:
            return InterfaceKind.STACKED
        if devtype in _DEVTYPE_OVERLAY:
            return InterfaceKind.VIRTUAL_OTHER
        # LAST before the fallthrough, and the position is the correctness
        # question. A bridge carries lower_* links to its ports and a vxlan bound
        # to a NIC carries lower_<nic>, both measured, so reading lower_* any
        # earlier would relabel a container bridge or an overlay as STACKED. Every
        # branch above claims its device from a signal the driver declares; this
        # one only refines what is otherwise unclassified.
        if _stacked_on_physical(interface_dir, root):
            return InterfaceKind.STACKED
        # Under devices/virtual/net with no driver-declared kind and nothing real
        # underneath: a veth end (a bridge-mode container's own eth0), a dummy, a
        # VMware vmnet, a macvlan stacked on another virtual device.
        return InterfaceKind.VIRTUAL_OTHER
    except Exception:  # noqa: BLE001 - an unreadable /sys is honest ignorance
        return InterfaceKind.UNKNOWN


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
    "InterfaceKind",
    "can_bind_privileged_port",
    "capability_available",
    "interface_ipv4_addresses",
    "interface_ipv4_addresses_for",
    "interface_ipv4_for",
    "interface_kind",
    "interface_mac_ipv4_linklocal",
    "interface_names",
]
