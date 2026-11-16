"""Inventory of the broadcast and multicast sends the scan can make.

A broadcast or multicast frame is not addressed to one host, so neither the
asset-scope primary seams (which gate a named or addressed target) nor the
socket egress backstop (which reads a destination address) can hold it to the
engagement scope. This is a stated limitation of an asset scope, not a defect:
the frames below are link-local group traffic, and the scan only ACTS on a
reply once it can attribute the responder to a host (the poisoning responders
check the querying host's address, and the mitm6 DHCPv6 layer checks the
client's FQDN, both against the asset scope).

This module is the single list the reporting layer (P7) renders in the asset
scope disclosure, so the client is told exactly which group traffic the scan
may emit on the local segment. It is data only: declarative, importable by any
surface, and it depends on nothing.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BroadcastSend:
    """One broadcast or multicast send a technique can make.

    Attributes:
        technique: The operator-facing technique name.
        destination: The group or broadcast destination (not a host).
        purpose: Why the frame is sent, in one clause.
        attributed_before_action: Whether the scan can attribute the resulting
            exchange to a host before it acts on it (so the asset scope still
            governs the ACTION, only not the frame itself).
    """

    technique: str
    destination: str
    purpose: str
    attributed_before_action: bool


#: Every broadcast or multicast send the scan can emit on the local segment.
#: Kept in technique order; the reporting disclosure renders it verbatim.
BROADCAST_MULTICAST_SENDS: tuple[BroadcastSend, ...] = (
    BroadcastSend(
        technique="mDNS responder",
        destination="224.0.0.251:5353 / [ff02::fb]:5353",
        purpose="answer a name query on the multicast group",
        attributed_before_action=True,
    ),
    BroadcastSend(
        technique="mitm6 router advertisement",
        destination="[ff02::1] (all-nodes)",
        purpose="advertise the scanning host as an IPv6 router so clients request a lease",
        attributed_before_action=False,
    ),
)


def broadcast_multicast_disclosure() -> list[dict[str, str]]:
    """The inventory as plain rows for the asset-scope disclosure.

    One row per send, each a flat mapping so the renderer needs no import of
    this module's dataclass. ``attributed`` reads ``yes`` / ``no``.
    """

    return [
        {
            "technique": send.technique,
            "destination": send.destination,
            "purpose": send.purpose,
            "attributed": "yes" if send.attributed_before_action else "no",
        }
        for send in BROADCAST_MULTICAST_SENDS
    ]


__all__ = [
    "BroadcastSend",
    "BROADCAST_MULTICAST_SENDS",
    "broadcast_multicast_disclosure",
]
