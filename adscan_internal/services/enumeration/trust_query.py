"""Native badldap query for ``trustedDomain`` objects.

This module is the single source of truth for trust enumeration in ADscan.
Both the recursive trust enumerator (``DomainService.enumerate_trusts``) and
the attack-graph LDAP collector (``LDAPCollector._collect_trusts``) call into
:func:`query_trusted_domains` so decoding logic stays consistent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from adscan_core import telemetry
from adscan_core.rich_output import print_info_debug


# trustAttributes bits (Microsoft [MS-ADTS] 6.1.6.7.9).
_TRUST_ATTR_BITS: list[tuple[int, str]] = [
    (0x00000001, "NON_TRANSITIVE"),
    (0x00000002, "UPLEVEL_ONLY"),
    (0x00000004, "QUARANTINED_DOMAIN"),
    (0x00000008, "FOREST_TRANSITIVE"),
    (0x00000010, "CROSS_ORGANIZATION"),
    (0x00000020, "WITHIN_FOREST"),
    (0x00000040, "TREAT_AS_EXTERNAL"),
    (0x00000080, "USES_RC4_ENCRYPTION"),
    (0x00000100, "CROSS_ORGANIZATION_NO_TGT_DELEGATION"),
    (0x00000200, "PIM_TRUST"),
    (0x00000800, "TRUST_USES_AES_KEYS"),
]

_TRUST_DIRECTION_MAP: dict[int, str] = {
    0: "Disabled",
    1: "Inbound",
    2: "Outbound",
    3: "Bidirectional",
}

_TRUST_TYPE_FALLBACK: dict[int, str] = {
    1: "Windows NT",
    2: "External",
    3: "MIT",
    4: "DCE",
}


@dataclass
class TrustedDomainEntry:
    """Decoded ``trustedDomain`` LDAP object.

    Attributes:
        partner: FQDN of the partner domain (lowercased).
        direction: Human-readable trust direction.
        trust_type: Human-readable trust classification derived from
            ``trustAttributes`` first, then ``trustType``.
        trust_attributes: Raw ``trustAttributes`` bitmask.
        attribute_flags: Decoded list of ``trustAttributes`` bit names.
        sid: Partner domain SID (``S-1-5-21-…``) when available.
    """

    partner: str
    direction: str
    trust_type: str
    trust_attributes: int = 0
    attribute_flags: list[str] = field(default_factory=list)
    sid: str | None = None


def decode_trust_attributes(value: int | None) -> list[str]:
    """Return the list of bit-names set on ``trustAttributes``."""
    if not value:
        return []
    return [name for bit, name in _TRUST_ATTR_BITS if value & bit]


def classify_trust_type(trust_attributes: int | None, trust_type: int | None) -> str:
    """Pick a human label for the trust based on attributes/type bits."""
    flags = set(decode_trust_attributes(trust_attributes))
    if "WITHIN_FOREST" in flags:
        return "Parent-Child"
    if "FOREST_TRANSITIVE" in flags:
        return "Forest"
    if "TREAT_AS_EXTERNAL" in flags:
        return "External"
    if "CROSS_ORGANIZATION" in flags:
        return "External"
    if trust_type is not None and trust_type in _TRUST_TYPE_FALLBACK:
        return _TRUST_TYPE_FALLBACK[trust_type]
    return "Unknown"


def decode_trust_direction(value: int | None) -> str:
    if value is None:
        return "Unknown"
    return _TRUST_DIRECTION_MAP.get(int(value), "Unknown")


def _decode_sid(raw: Any) -> str | None:
    if raw is None:
        return None
    if isinstance(raw, bytes):
        try:
            from winacl.dtyp.sid import SID

            return str(SID.from_bytes(raw))
        except Exception:  # noqa: BLE001
            return None
    text = str(raw).strip()
    return text or None


def _attrs(entry: Any) -> dict[str, list[Any]]:
    raw = getattr(entry, "entry_raw_attributes", {}) or {}
    decoded = getattr(entry, "entry_attributes_as_dict", {}) or {}
    keys = set(raw) | set(decoded)
    out: dict[str, list[Any]] = {}
    binary_keys = {"securityidentifier", "objectsid", "objectguid"}
    for key in keys:
        key_text = str(key)
        if key_text.casefold() in binary_keys:
            values = raw.get(key)
        else:
            values = decoded.get(key)
        if values is None:
            values = raw.get(key, [])
        if not isinstance(values, (list, tuple, set)):
            values = [values]
        out[key_text] = [v for v in values if v is not None]
    return out


def _first(attrs: dict[str, list[Any]], name: str) -> Any:
    for key, values in attrs.items():
        if key.casefold() == name.casefold():
            return values[0] if values else None
    return None


def _first_str(attrs: dict[str, list[Any]], name: str) -> str:
    val = _first(attrs, name)
    return str(val).strip() if val is not None else ""


def _first_int(attrs: dict[str, list[Any]], name: str) -> int | None:
    val = _first(attrs, name)
    try:
        return int(val) if val is not None else None
    except (TypeError, ValueError):
        return None


def query_trusted_domains(conn: Any, domain_dn: str) -> list[TrustedDomainEntry]:
    """Enumerate ``trustedDomain`` objects under ``CN=System,<domain_dn>``.

    Args:
        conn: An active :class:`ADscanLDAPConnection` (or anything exposing
            ``search()`` and ``entries`` like ldap3).
        domain_dn: The domain root DN, e.g. ``DC=corp,DC=local``.

    Returns:
        Decoded entries. On search failure returns an empty list (telemetry
        records the exception).
    """
    if not domain_dn:
        return []

    base = f"CN=System,{domain_dn}"
    try:
        conn.search(
            search_base=base,
            search_filter="(objectClass=trustedDomain)",
            attributes=[
                "trustPartner",
                "trustDirection",
                "trustType",
                "trustAttributes",
                "securityIdentifier",
                "whenCreated",
                "whenChanged",
            ],
            search_scope="SUBTREE",
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(f"trust_query: search failed under {base}: {exc}")
        return []

    decoded: list[TrustedDomainEntry] = []
    for entry in getattr(conn, "entries", []) or []:
        try:
            attrs = _attrs(entry)
            partner = _first_str(attrs, "trustPartner").lower()
            if not partner:
                continue
            direction_raw = _first_int(attrs, "trustDirection")
            type_raw = _first_int(attrs, "trustType")
            attrs_raw = _first_int(attrs, "trustAttributes") or 0
            sid_raw = _first(attrs, "securityIdentifier")

            decoded.append(
                TrustedDomainEntry(
                    partner=partner,
                    direction=decode_trust_direction(direction_raw),
                    trust_type=classify_trust_type(attrs_raw, type_raw),
                    trust_attributes=attrs_raw,
                    attribute_flags=decode_trust_attributes(attrs_raw),
                    sid=_decode_sid(sid_raw),
                )
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(f"trust_query: entry decode failed: {exc}")

    return decoded
