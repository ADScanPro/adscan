"""Scored Domain-Controller confidence model — single source of truth.

This module replaces the historical lax heuristic that flagged a host as a
"probable DC" the moment a single AD-related TCP port was observed open. A
file server, a workstation, or an AD-LDS host can all expose one of those
ports without being a domain controller, so a one-open-port rule produces
false positives that drive ADscan to offer DC-only actions against hosts that
are not domain controllers.

The model maps the signals ADscan already collects during discovery
(open TCP ports plus any LDAP/Kerberos/RootDSE fingerprint already gathered)
to a graded :class:`DcConfidence` tier. The scoring is pure logic — no network
I/O — so it is fully unit-testable at L1.

Signal weights and the resulting tiers (the scoring table)
----------------------------------------------------------

Port signals (TCP):

==================  =========================================================
Port                Meaning for DC classification
==================  =========================================================
88  (Kerberos)      Strongest single signal — only a KDC answers here, and in
                    practice only domain controllers run the KDC.
389 (LDAP)          AD directory service. Present on real DCs, but also on
                    AD-LDS / AD-LDS-like and other LDAP hosts, so on its own
                    it is only a *weak/possible* DC signal.
636 (LDAPS)         Same directory meaning as 389 (treated as an LDAP signal).
445 (SMB)           Ubiquitous — member servers, file servers, workstations
                    all expose it. Contributes nothing on its own.
53  (DNS)           A DC commonly runs DNS, but so does any standalone
                    resolver. Weak signal alone; meaningful as corroboration.
==================  =========================================================

Fingerprint signals (already-collected, optional):

* ``has_kerberos`` — a Kerberos service / KDC was positively fingerprinted
  (e.g. an AS-REQ got a Kerberos-shaped answer). Equivalent in strength to
  observing port 88 open.
* ``ldap_rootdse_is_dc`` — the LDAP RootDSE looked like a real domain DC
  (e.g. it advertised ``isSynchronized`` / a domain naming context / a
  ``LDAP`` service SPN), as opposed to an AD-LDS instance. This promotes a
  bare LDAP observation from POSSIBLE to LIKELY.
* ``ldap_is_adlds`` — the LDAP RootDSE looked like AD-LDS / a non-domain LDAP
  host. This *caps* a bare-LDAP host at POSSIBLE even with corroboration, so
  an AD-LDS / member-server LDAP host is never mistaken for a real DC.

Tier rules (evaluated against the combined signals)
---------------------------------------------------

==============  ============================================================
Tier            When
==============  ============================================================
CONFIRMED       Kerberos (88 or ``has_kerberos``) **and** LDAP (389/636)
                **and** the LDAP RootDSE confirmed it is a real domain DC.
                The full DC service stack is present and identity-confirmed.
VERY_LIKELY     Kerberos present (88 open or ``has_kerberos``). Only DCs run
                the KDC, so this alone is a very strong signal — promoted by
                LDAP/DNS corroboration but already VERY_LIKELY on its own.
LIKELY          LDAP present (389/636) with a DC-like RootDSE, **or** LDAP
                corroborated by DNS (53) — without Kerberos. Real DC-shaped
                but the strongest single signal (KDC) was not observed.
POSSIBLE        Bare LDAP with no DC confirmation (could be AD-LDS / a
                non-DC LDAP host / member server), or DNS-only (53), or an
                explicit AD-LDS fingerprint. A weak "might be AD" hint.
UNKNOWN         No discriminating signal: only 445 open, or nothing AD-like.
                A member server, file server, or workstation all land here —
                we genuinely cannot tell.
==============  ============================================================
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import IntEnum


class DcConfidence(IntEnum):
    """Graded confidence that a host is an Active Directory Domain Controller.

    Ordered so callers can gate with ``>=`` comparisons (e.g. ``>= LIKELY``
    for "offer DC-only actions", ``>= POSSIBLE`` for a softer "might be a DC"
    hint). Higher value means stronger evidence.
    """

    UNKNOWN = 0
    POSSIBLE = 1
    LIKELY = 2
    VERY_LIKELY = 3
    CONFIRMED = 4

    @property
    def is_dc_like(self) -> bool:
        """True when the tier is strong enough to treat the host as a DC.

        This is the ``>= LIKELY`` threshold used by the DC-action offer gate.
        """
        return self >= DcConfidence.LIKELY

    @property
    def is_possible_dc(self) -> bool:
        """True for the softer ``>= POSSIBLE`` "might be a DC" hint threshold."""
        return self >= DcConfidence.POSSIBLE


# AD-related TCP ports recognised by the scorer.
KERBEROS_PORT = 88
LDAP_PORT = 389
LDAPS_PORT = 636
SMB_PORT = 445
DNS_PORT = 53

_LDAP_PORTS = frozenset({LDAP_PORT, LDAPS_PORT})


def score_dc_confidence(
    open_ports: Iterable[int] | None,
    *,
    has_kerberos: bool = False,
    ldap_rootdse_is_dc: bool = False,
    ldap_is_adlds: bool = False,
) -> DcConfidence:
    """Score how confidently a host looks like an AD Domain Controller.

    Pure function: maps observed signals to a :class:`DcConfidence` tier per
    the scoring table in the module docstring. Never raises on malformed port
    input — non-integer entries are ignored.

    Args:
        open_ports: Observed open TCP ports (any iterable of ints; ``None`` /
            empty is treated as "no port evidence").
        has_kerberos: A Kerberos service / KDC was positively fingerprinted
            (treated as strong as port 88 being open).
        ldap_rootdse_is_dc: The LDAP RootDSE looked like a real domain DC
            (promotes bare LDAP from POSSIBLE to LIKELY, and — with Kerberos —
            to CONFIRMED).
        ldap_is_adlds: The LDAP RootDSE looked like AD-LDS / a non-domain LDAP
            host (caps a bare-LDAP host at POSSIBLE).

    Returns:
        The :class:`DcConfidence` tier for the combined signals.
    """
    ports: set[int] = set()
    for port in open_ports or ():
        try:
            ports.add(int(port))
        except (TypeError, ValueError):
            continue

    kerberos = has_kerberos or (KERBEROS_PORT in ports)
    has_ldap = bool(ports & _LDAP_PORTS)
    has_dns = DNS_PORT in ports

    # Kerberos is the decisive single signal: only DCs run the KDC.
    if kerberos:
        if has_ldap and ldap_rootdse_is_dc:
            # Full DC service stack present and identity-confirmed.
            return DcConfidence.CONFIRMED
        return DcConfidence.VERY_LIKELY

    # No Kerberos below this point.
    if has_ldap:
        # An explicit AD-LDS / non-DC LDAP fingerprint caps the host at POSSIBLE:
        # AD-LDS and member-server LDAP hosts must never be mistaken for a DC.
        if ldap_is_adlds:
            return DcConfidence.POSSIBLE
        # A DC-like RootDSE, or LDAP corroborated by DNS, is DC-shaped — LIKELY.
        if ldap_rootdse_is_dc or has_dns:
            return DcConfidence.LIKELY
        # Bare LDAP with nothing to confirm it: could be AD-LDS or a non-DC
        # LDAP host. A weak "might be AD" hint only.
        return DcConfidence.POSSIBLE

    # No Kerberos, no LDAP. DNS alone is a weak hint; SMB-only / nothing is
    # indistinguishable from a member server, file server, or workstation.
    if has_dns:
        return DcConfidence.POSSIBLE

    return DcConfidence.UNKNOWN
