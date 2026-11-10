"""Interface choices shown to the operator, and the one ADscan picks unattended.

Two different situations, two different rules, one kernel verdict
(:func:`adscan_internal.services.listener_ip.resolve_interface_kind`):

* **The operator chooses** (the interactive picker): every interface is listed,
  sorted so the ones a target can call back to come first, and each is ANNOTATED
  with what the kernel says about it ("container bridge, a target cannot call
  back here"). Nothing is removed. Inside a bridge-mode container the only
  interface is a veth end, which types as virtual, and a picker that pruned it
  would leave the operator with nothing to pick.
* **ADscan guesses** (the unattended auto-resolve, and the picker's pre-selected
  default): the guess is HARD-filtered to an interface a target can call back to
  and that has an IPv4 to announce. A guess of ``docker0`` was the root cause of
  a callback advertised on a container bridge. When nothing qualifies there is no
  guess (``None``), and the caller says so instead of picking plumbing.

A tunnel (an OpenVPN ``tun0``, a Ligolo TUN) is a normal callback interface: it
is how HTB and GOAD engagements are reached. A Ligolo TUN may carry no IPv4 at
all; it stays selectable (an L3 vantage) and is simply not the unattended guess.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

from adscan_core.pal.net import InterfaceKind

KindLookup = Callable[[str], InterfaceKind]


@dataclass(frozen=True, slots=True)
class InterfaceOption:
    """One row of the interface picker."""

    name: str
    ipv4s: tuple[str, ...]
    kind: InterfaceKind
    can_receive_callback: bool
    note: str

    @property
    def label(self) -> str:
        """The text shown for this option (addresses plus the kernel's note)."""
        addresses = f"[{', '.join(self.ipv4s)}]" if self.ipv4s else "(no IPv4)"
        suffix = f" · {self.note}" if self.note else ""
        return f"🌐 {self.name}  {addresses}{suffix}"


def build_interface_options(
    annotated: Iterable[tuple[str, Iterable[str]]],
    *,
    kind_lookup: KindLookup | None = None,
) -> list[InterfaceOption]:
    """Annotate and sort ``(name, ipv4s)`` pairs for the picker. Never removes one.

    Order: callback-capable with an IPv4, callback-capable without one, then the
    interfaces a target cannot call back to; enumeration order within each group.
    """
    from adscan_core.callback_interfaces import (  # noqa: PLC0415
        describe_interface_kind,
        kind_can_receive_callback,
        resolve_interface_kind,
    )

    lookup = kind_lookup or resolve_interface_kind
    options: list[InterfaceOption] = []
    for name, ipv4s in annotated:
        try:
            kind = lookup(str(name))
        except Exception:  # noqa: BLE001 - the OS declined to type it
            kind = InterfaceKind.UNKNOWN
        options.append(
            InterfaceOption(
                name=str(name),
                ipv4s=tuple(str(ip) for ip in ipv4s or ()),
                kind=kind,
                can_receive_callback=kind_can_receive_callback(kind),
                note=describe_interface_kind(kind),
            )
        )

    def _rank(option: InterfaceOption) -> int:
        if not option.can_receive_callback:
            return 2
        return 0 if option.ipv4s else 1

    return sorted(options, key=_rank)  # sorted() is stable: enumeration order kept


def auto_pick_index(
    options: list[InterfaceOption],
    *,
    is_l3_vantage: Callable[[str], bool] | None = None,
) -> int | None:
    """Index of the interface ADscan may pick unattended, or ``None``.

    Hard filter: a target must be able to call back to it, and it must carry an
    IPv4 to announce. Only when nothing qualifies, an L3 vantage
    (``is_l3_vantage``, a Ligolo TUN in practice) is accepted, as the picker has
    always done: it routes the scan, and callbacks are resolved per target by the
    egress resolver.
    """
    for idx, option in enumerate(options):
        if option.can_receive_callback and option.ipv4s:
            return idx
    if is_l3_vantage is not None:
        for idx, option in enumerate(options):
            if option.can_receive_callback and is_l3_vantage(option.name):
                return idx
    return None


__all__ = ["InterfaceOption", "auto_pick_index", "build_interface_options"]
