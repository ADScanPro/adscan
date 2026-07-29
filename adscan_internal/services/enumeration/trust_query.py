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
from adscan_core.rich_output import print_exception


# trustAttributes bits (Microsoft [MS-ADTS] 6.1.6.7.9).
#
# CANONICAL SOURCE: the vendored badldap enum
# ``vendor/badldap/badldap/ldap_objects/adtrust.py`` (``TrustAttributes``),
# which mirrors MS-ADTS 6.1.6.7.9 verbatim. Keep this table byte-identical to
# it. The bits at/above 0x100 were previously mis-mapped (0x100/0x200/0x800 all
# shifted), which is *not* cosmetic: a 2019+ forest trust with
# CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION (0x800) set — the exact
# misconfiguration that makes cross-trust unconstrained-delegation abuse viable —
# was decoded and reported to the client as ``TRUST_USES_AES_KEYS``, i.e. a
# hardening signal with the OPPOSITE meaning. Locked by
# ``tests/unit/services/enumeration/test_trust_query.py``.
_TRUST_ATTR_BITS: list[tuple[int, str]] = [
    (0x00000001, "NON_TRANSITIVE"),
    (0x00000002, "UPLEVEL_ONLY"),
    (0x00000004, "QUARANTINED_DOMAIN"),
    (0x00000008, "FOREST_TRANSITIVE"),
    (0x00000010, "CROSS_ORGANIZATION"),
    (0x00000020, "WITHIN_FOREST"),
    (0x00000040, "TREAT_AS_EXTERNAL"),
    (0x00000080, "USES_RC4_ENCRYPTION"),
    (0x00000100, "TRUST_USES_AES_KEYS"),
    (0x00000200, "CROSS_ORGANIZATION_NO_TGT_DELEGATION"),
    (0x00000400, "PIM_TRUST"),
    (0x00000800, "CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION"),
    (0x00001000, "DISABLE_AUTH_TARGET_VALIDATION"),
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


# ── Trust posture judging ─────────────────────────────────────────────────
#
# ADscan decodes ``trustAttributes`` (above); these helpers are the single
# source of truth that *judges* the decoded flags and turns the two dangerous
# conditions into report findings. Wired at the collector seam
# (``ldap_collector._collect_trusts``) off the ALREADY-decoded
# ``TrustedDomainEntry`` — no re-decode, no extra LDAP round-trip.

#: Canonical vuln-catalog keys the two trust-posture conditions map to. Both
#: are declared in ``adscan_internal/pro/reporting/vuln_catalog.py`` (full
#: prose) and the LITE-safe ``adscan_core/reporting/vuln_catalog_meta.py``
#: slice (severity/title/mitre). The web CTEM gates ingestion on the meta
#: slice, so these keys reach both the PDF and the web automatically.
TRUST_TGT_DELEGATION_FINDING_KEY = "trust_tgt_delegation_enabled"
TRUST_SID_FILTERING_FINDING_KEY = "trust_sid_filtering_disabled"


@dataclass(frozen=True)
class TrustPostureIssue:
    """One judged trust-posture weakness derived from a decoded trust.

    Plain JSON-serialisable scalars only (mirrors the collector-result
    convention) so it flows straight into a technical-report finding's
    ``details`` payload.

    Attributes:
        finding_key: Canonical vuln-catalog key this weakness maps to.
        partner: FQDN of the partner domain (lowercased).
        trust_type: Human label of the trust (Forest / External / ...).
        direction: Human-readable trust direction.
        reason: Short, client-safe explanation of the observed weakness.
        attribute_flags: Decoded ``trustAttributes`` bit names (evidence).
    """

    finding_key: str
    partner: str
    trust_type: str
    direction: str
    reason: str
    attribute_flags: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_key": self.finding_key,
            "partner": self.partner,
            "trust_type": self.trust_type,
            "direction": self.direction,
            "reason": self.reason,
            "attribute_flags": list(self.attribute_flags),
        }


def sid_filtering_quarantined(trust_attributes: int | None) -> bool:
    """Return whether SID filtering (domain quarantine) is enforced.

    Reuses the vendored badldap SSOT expression
    (``vendor/badldap/badldap/ldap_objects/adtrust.py`` line 177:
    ``QUARANTINED_DOMAIN in TrustAttributes(...)``) rather than re-deriving the
    bit locally, so this stays byte-identical to the collector's BloodHound
    trust export. Falls back to the local bit table only if the vendored enum
    cannot be imported (never happens in a real build).
    """
    if not trust_attributes:
        return False
    try:
        from badldap.ldap_objects.adtrust import TrustAttributes

        return TrustAttributes.QUARANTINED_DOMAIN in TrustAttributes(trust_attributes)
    except Exception:  # noqa: BLE001 — a vendor enum quirk must not break enum
        return bool(int(trust_attributes) & 0x00000004)


def evaluate_trust_posture(entry: TrustedDomainEntry) -> list[TrustPostureIssue]:
    """Judge one decoded trust and return the weaknesses ADscan reports.

    Pure logic over the flags already decoded by
    :func:`decode_trust_attributes` (``entry.attribute_flags``) plus the raw
    ``entry.trust_attributes`` for the vendored SID-filtering check. No LDAP
    round-trip, no re-decode.

    Conditions judged:

      1. **TGT delegation enabled across a forest trust** — the
         ``CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION`` (0x800) flag on a
         ``FOREST_TRANSITIVE`` (0x8) trust. This is the misconfiguration that
         makes cross-trust unconstrained-delegation abuse viable.
      2. **SID filtering not enforced** — an external trust missing domain
         quarantine (``QUARANTINED_DOMAIN``), or any cross-forest trust
         explicitly relaxed to external-level filtering via
         ``TREAT_AS_EXTERNAL`` (0x40).

    A healthy same-forest (``WITHIN_FOREST``) trust and a plain forest trust
    that still enforces default forest-wide SID filtering (no
    ``TREAT_AS_EXTERNAL`` relaxation) yield no issues — reporting those would
    be noise that buries the two real weaknesses.

    Args:
        entry: A decoded ``trustedDomain`` object.

    Returns:
        Zero or more :class:`TrustPostureIssue` for the trust.
    """
    flags = set(entry.attribute_flags)
    issues: list[TrustPostureIssue] = []

    is_within_forest = "WITHIN_FOREST" in flags
    if is_within_forest:
        # Intra-forest (parent-child / tree-root) trust: not a cross-boundary
        # SID-filtering or TGT-delegation exposure. Nothing to judge.
        return issues

    is_forest_transitive = "FOREST_TRANSITIVE" in flags
    treat_as_external = "TREAT_AS_EXTERNAL" in flags
    is_external_trust = (not is_forest_transitive) and (
        "CROSS_ORGANIZATION" in flags or entry.trust_type == "External"
    )

    # Condition 1 — TGT delegation enabled across a forest trust (headline).
    if is_forest_transitive and "CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION" in flags:
        issues.append(
            TrustPostureIssue(
                finding_key=TRUST_TGT_DELEGATION_FINDING_KEY,
                partner=entry.partner,
                trust_type=entry.trust_type,
                direction=entry.direction,
                reason=(
                    "The forest trust is configured to forward Kerberos "
                    "ticket-granting tickets across the trust boundary "
                    "(CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION is set), which "
                    "permits unconstrained-delegation abuse to reach across the "
                    "trust."
                ),
                attribute_flags=tuple(entry.attribute_flags),
            )
        )

    # Condition 2 — SID filtering not enforced on a cross-boundary trust.
    #   * TREAT_AS_EXTERNAL explicitly relaxes a forest trust's SID filtering
    #     to the weaker external level — an observed weakening → always flag.
    #   * An external trust with no QUARANTINED_DOMAIN quarantine is not
    #     applying SID filtering → flag. (A plain forest trust without the
    #     quarantine bit still enforces default forest-wide SID filtering, so
    #     it is deliberately NOT flagged — avoiding a finding on every healthy
    #     forest trust.)
    quarantined = sid_filtering_quarantined(entry.trust_attributes)
    if treat_as_external:
        issues.append(
            TrustPostureIssue(
                finding_key=TRUST_SID_FILTERING_FINDING_KEY,
                partner=entry.partner,
                trust_type=entry.trust_type,
                direction=entry.direction,
                reason=(
                    "The cross-forest trust is relaxed to external-level SID "
                    "filtering (TREAT_AS_EXTERNAL is set), weakening the SID "
                    "filtering that normally protects the forest boundary."
                ),
                attribute_flags=tuple(entry.attribute_flags),
            )
        )
    elif is_external_trust and not quarantined:
        issues.append(
            TrustPostureIssue(
                finding_key=TRUST_SID_FILTERING_FINDING_KEY,
                partner=entry.partner,
                trust_type=entry.trust_type,
                direction=entry.direction,
                reason=(
                    "The external trust does not apply domain quarantine / SID "
                    "filtering (QUARANTINED_DOMAIN is not set), so SID-History "
                    "values from the trusted domain are honoured across the "
                    "boundary."
                ),
                attribute_flags=tuple(entry.attribute_flags),
            )
        )

    return issues


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
        print_exception(exception=exc)
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
            print_exception(exception=exc)
            print_info_debug(f"trust_query: entry decode failed: {exc}")

    return decoded
