"""Can a target call back to this interface? The kernel-first verdict.

The SSOT for "what kind of interface is this, and can a remote AD target dial
an address on it", shared by every surface that has to decide or show it: the
CLI callback ladder (``adscan_internal.services.listener_ip``, which re-exports
these names), the interface picker, the segment map, and the web backend's
interface list (which ships ``adscan_core`` but never ``adscan_internal``).

The kernel is the authority (:func:`adscan_core.pal.net.interface_kind`); this
module adds only the policy the kernel cannot express on its own. Dependency
light on purpose: stdlib plus the PAL.
"""

from __future__ import annotations

from adscan_core.pal import net as pal_net
from adscan_core.pal.net import InterfaceKind

#: BEST-EFFORT FALLBACK, not the primary classification. Interface names that
#: look like container/bridge plumbing whose address lives only on this host.
#: Consulted ONLY where the OS declines to type the interface
#: (:attr:`InterfaceKind.UNKNOWN`): Windows, whose ``psutil`` backend carries no
#: adapter kind, and an unreadable ``/sys``. On Linux the kernel answers and this
#: list is never reached. Matched case-insensitively as a NAME PREFIX.
#:
#: It deliberately excludes ``tun``/``tap``/``wg``/``tailscale``/``zt``/``ppp``
#: (VPN and overlay tunnels an operator legitimately pivots AD traffic through:
#: HTB and GOAD are reached over ``tun0``) and ``vlan``/``bond``/``eth``/``en``/
#: ``wl`` (real NICs and client VLAN subinterfaces). It SHRANK when the kernel
#: became the primary signal: ``nerdctl``, ``cni``, ``cbr``, ``kube``,
#: ``flannel``, ``antrea``, ``genev`` and ``vxlan`` were dropped because every
#: one of them is a bridge, a vxlan, a geneve, a veth or a dummy that
#: :func:`adscan_core.pal.net.interface_kind` types from the kernel, and none of
#: them can appear on Windows, which is the only platform the fallback serves in
#: practice. What remains, and why:
#:   docker / br- / podman : Docker/Podman bridge networks (local only)
#:   veth                  : container veth pair ends
#:   virbr / vnet          : libvirt/KVM NAT bridge and guest taps
#:   cali / tunl           : Calico workload ifaces and its IPIP device
#:   vethernet             : Windows Hyper-V / WSL virtual switch
#:   loopback pseudo-...   : the Windows loopback adapter
_VIRTUAL_INTERFACE_NAME_PREFIXES: tuple[str, ...] = (
    "docker",
    "br-",
    "podman",
    "veth",
    "virbr",
    "vnet",
    "cali",
    "tunl",
    "vethernet",
    "loopback pseudo-interface",
)

#: Interface names that are virtual by EXACT match (no useful prefix). ``lo`` is
#: already rejected by its loopback address, but naming it keeps the predicate
#: honest for callers that classify by name alone.
_VIRTUAL_INTERFACE_NAMES: frozenset[str] = frozenset({"lo", "ovs-system"})

#: Names the KERNEL types as a usable tunnel but which are in fact hypervisor or
#: container-network plumbing, so the name is the only discriminator there is:
#:
#:   tunl* : the IP-in-IP device a Calico node runs. ``ARPHRD_TUNNEL`` is
#:           indistinguishable from an operator's own IPIP tunnel to a VPS.
#:   vnet* : a libvirt guest TAP, which carries a ``tun_flags`` attribute
#:           exactly like an OpenVPN ``tun0``.
#:
#: Deliberately NOT ``tun``: ``tun0`` is the callback interface for an HTB or
#: GOAD engagement over VPN, and ``"tun0".startswith("tunl")`` is False, which is
#: the point of spelling the prefix with the l. This list can only ever DEMOTE a
#: kernel verdict of ``TUNNEL``; it never overrides ``PHYSICAL``, so an operator
#: who renames a real NIC is not punished for the name they chose.
_KERNEL_BLIND_VIRTUAL_NAME_PREFIXES: tuple[str, ...] = ("tunl", "vnet")

#: Kinds whose addresses no remote AD target can dial back to.
_NON_CALLBACK_INTERFACE_KINDS: frozenset[InterfaceKind] = frozenset(
    {
        InterfaceKind.BRIDGE,
        InterfaceKind.VIRTUAL_OTHER,
        InterfaceKind.LOOPBACK,
    }
)


def interface_name_is_virtual(interface_name: object) -> bool:
    """Return whether a NIC NAME looks like container/bridge/overlay plumbing.

    The BEST-EFFORT FALLBACK, not the primary classification: prefer
    :func:`resolve_interface_kind` (kernel-first), which consults this only where
    the OS declines to type the interface. Kept as a public, named function
    because "what the name suggests" and "what the kernel knows" are genuinely
    different claims, and collapsing them would hide which one answered.

    The classification is NAME-based (see
    :data:`_VIRTUAL_INTERFACE_NAME_PREFIXES`) and case-insensitive. VPN tunnels
    an operator legitimately pivots through (``tun``/``tap``/``wg``/
    ``tailscale``/``zt``/``ppp``) are NOT virtual by this test: ``tun0`` is the
    callback interface for an HTB or GOAD engagement over VPN.
    """

    name = str(interface_name or "").strip().lower()
    if not name:
        return False
    if name in _VIRTUAL_INTERFACE_NAMES:
        return True
    return name.startswith(_VIRTUAL_INTERFACE_NAME_PREFIXES)


def resolve_interface_kind(interface_name: object) -> InterfaceKind:
    """Return what kind of interface this is, asking the kernel first.

    The SSOT for "what is this interface" everywhere in ADscan that has to decide
    whether an address can receive a coerced callback. The kernel is the
    authority (:func:`adscan_core.pal.net.interface_kind` reads
    ``/sys/class/net``); this function adds the two policy adjustments the kernel
    cannot make on its own, and nothing else:

    * A kernel verdict of ``TUNNEL`` whose NAME is known hypervisor or CNI
      plumbing is demoted (see
      :data:`_KERNEL_BLIND_VIRTUAL_NAME_PREFIXES`). ``ARPHRD_TUNNEL`` and a
      ``tun_flags`` attribute are the same bytes for a Calico ``tunl0``, a
      libvirt guest tap and an operator's own OpenVPN ``tun0``.
    * When the OS says ``UNKNOWN`` (Windows, or an unreadable ``/sys``) the NAME
      heuristic answers instead: a recognised plumbing name reads
      ``VIRTUAL_OTHER``, anything else stays ``UNKNOWN``. ``UNKNOWN`` is left as
      ``UNKNOWN`` rather than promoted to ``PHYSICAL``, because "the OS did not
      say" is not evidence of a real NIC, and the consumers below already treat
      it as usable without needing it relabelled.

    Why the kernel and not the name. A bridge-mode container (macOS Docker
    Desktop, or any run without ``--network host``) sees its own ``eth0``, a veth
    end carrying an address no AD target can dial. ``eth0`` is a real NIC's name
    by every naming convention there is, so no name list can ever demote it,
    while the kernel files it under ``devices/virtual/net`` with no backing
    device. The same holds for a VMware ``vmnet`` adapter, which no name list
    here ever covered.
    """

    # Linux interface names are case-SENSITIVE, so the kernel lookup gets the
    # name verbatim; only the name comparisons below fold case.
    raw = str(interface_name or "").strip()
    name = raw.lower()
    try:
        kind = pal_net.interface_kind(raw)
    except Exception:  # noqa: BLE001 - inconclusive, fall through to the name
        kind = InterfaceKind.UNKNOWN

    if kind is InterfaceKind.UNKNOWN:
        if interface_name_is_virtual(name):
            return InterfaceKind.VIRTUAL_OTHER
        return InterfaceKind.UNKNOWN
    if kind is InterfaceKind.TUNNEL and name.startswith(
        _KERNEL_BLIND_VIRTUAL_NAME_PREFIXES
    ):
        return InterfaceKind.VIRTUAL_OTHER
    return kind


def interface_can_receive_callback(interface_name: object) -> bool:
    """Return whether a target could dial back to an address on this interface.

    ``False`` only for a kind that provably reaches nothing off this host: a
    container bridge, virtual plumbing (a veth end, an overlay device, a
    host-only hypervisor adapter), or loopback. A real NIC, a VLAN or bond, a
    tunnel, and an interface the OS declines to type all return ``True`` —
    "unknown" must never read as "unusable", or an unrecognised Windows adapter
    would silently lose the operator their callback address.
    """

    return kind_can_receive_callback(resolve_interface_kind(interface_name))


def kind_can_receive_callback(kind: InterfaceKind) -> bool:
    """Return whether an interface of ``kind`` can receive a coerced callback.

    The policy half of :func:`interface_can_receive_callback`, for a caller that
    already holds the kind (or injects one in a test) and must not re-ask the
    kernel.
    """

    return kind not in _NON_CALLBACK_INTERFACE_KINDS


def describe_interface_kind(kind: InterfaceKind) -> str:
    """Return a short operator-facing note on what ``kind`` means for a callback.

    Used to ANNOTATE an interface the operator is choosing, never to hide it:
    inside a bridge-mode container the only interface is a veth end, and a
    picker that removed it would leave the operator nothing to choose.
    """

    notes = {
        InterfaceKind.BRIDGE: "container bridge, a target cannot call back here",
        InterfaceKind.VIRTUAL_OTHER: "virtual interface, a target cannot call back here",
        InterfaceKind.LOOPBACK: "loopback, a target cannot call back here",
        InterfaceKind.TUNNEL: "tunnel",
        InterfaceKind.STACKED: "VLAN or bond",
    }
    return notes.get(kind, "")


__all__ = [
    "describe_interface_kind",
    "interface_can_receive_callback",
    "interface_name_is_virtual",
    "kind_can_receive_callback",
    "resolve_interface_kind",
]
