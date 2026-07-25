"""Parse a CA security descriptor (MS-CSRA GetCASecurity) into ESC7 edges.

The CA's own security descriptor — read over the DCOM ``GetCASecurity`` call —
is the AUTHORITATIVE source of who holds the ManageCA / ManageCertificates
rights on an Enterprise CA. The CA object's LDAP ``nTSecurityDescriptor`` only
lists the DEFAULT holders; a principal delegated management through the CA MMC
snap-in (a non-default holder) appears ONLY in this descriptor. Emitting those
holders as ``ManageCA`` / ``ManageCertificates`` edges — both already accepted
by ``_CA_MANAGEMENT_RELATIONS`` and deduped by SID inside ``detect_esc7`` —
closes that collection gap without double-counting the LDAP defaults.

Parity reference: Certipy ``lib/constants.py`` (MANAGE_CA=1, MANAGE_CERTIFICATES=2)
and ``lib/security.py`` (per-ACE mask OR loop). ADscan's own
``adscan_internal/services/adcs/ca_admin.py`` mirrors the same bit values.
"""

from __future__ import annotations

from typing import Any

from adscan_internal.rich_output import print_info_debug
from adscan_internal.services.collector.models import CollectorEdge

# CA management right bits carried in a CA security-descriptor ACE mask.
_CA_RIGHT_MANAGE_CA = 1
_CA_RIGHT_MANAGE_CERTIFICATES = 2

# winacl ``ACEType.ACCESS_ALLOWED_ACE_TYPE`` (0x00).
_ACCESS_ALLOWED_ACE_TYPE = 0x00


def _ace_type(ace: Any) -> int | None:
    ace_type = getattr(ace, "AceType", None)
    if ace_type is None:
        return None
    value = getattr(ace_type, "value", None)
    if value is not None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    try:
        return int(ace_type)
    except (TypeError, ValueError):
        return None


def _ace_mask(ace: Any) -> int:
    mask = getattr(ace, "Mask", None)
    if isinstance(mask, int):
        return mask
    nested = getattr(mask, "Mask", None)
    if isinstance(nested, int):
        return nested
    try:
        return int(mask)
    except (TypeError, ValueError):
        return 0


def _ace_sid(ace: Any) -> str:
    try:
        return str(getattr(ace, "Sid", "") or "")
    except Exception:
        return ""


def parse_ca_security_edges(
    sd_bytes: bytes | None, ca_object_id: str
) -> list[CollectorEdge]:
    """Return ManageCA / ManageCertificates edges from a raw CA security descriptor.

    Args:
        sd_bytes: Self-relative security-descriptor bytes returned by
            ``GetCASecurity`` (MS-CSRA). Empty / ``None`` yields ``[]``.
        ca_object_id: The EnterpriseCA node's synthetic object id (edge target).

    Returns:
        One ``ManageCA`` edge per allowed ACE granting bit 1, and one
        ``ManageCertificates`` edge per allowed ACE granting bit 2. Never raises:
        a winacl parse failure logs at debug level and returns ``[]`` so ADCS
        collection is never aborted by a malformed descriptor.
    """
    if not sd_bytes or not ca_object_id:
        return []

    try:
        from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR  # type: ignore

        sd = SECURITY_DESCRIPTOR.from_bytes(sd_bytes)
    except Exception as exc:  # noqa: BLE001
        print_info_debug(f"[adcs-collector] CA security SD parse failed: {exc}")
        return []

    dacl = getattr(sd, "Dacl", None)
    if not dacl:
        return []

    edges: list[CollectorEdge] = []
    for ace in getattr(dacl, "aces", []) or []:
        if _ace_type(ace) != _ACCESS_ALLOWED_ACE_TYPE:
            continue
        sid = _ace_sid(ace)
        if not sid:
            continue
        mask = _ace_mask(ace)
        if mask & _CA_RIGHT_MANAGE_CA:
            edges.append(
                CollectorEdge(
                    source_object_id=sid,
                    target_object_id=ca_object_id,
                    relation="ManageCA",
                    source="ca_security",
                    method="csra",
                )
            )
        if mask & _CA_RIGHT_MANAGE_CERTIFICATES:
            edges.append(
                CollectorEdge(
                    source_object_id=sid,
                    target_object_id=ca_object_id,
                    relation="ManageCertificates",
                    source="ca_security",
                    method="csra",
                )
            )
    return edges
