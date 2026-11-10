"""Native badldap query for ``trustedDomain`` objects.

This module is the single source of truth for trust ENUMERATION in ADscan.
Both the recursive trust enumerator (``DomainService.enumerate_trusts``) and
the attack-graph LDAP collector (``LDAPCollector._collect_trusts``) call into
:func:`query_trusted_domains` so decoding logic stays consistent.

The DECODING of the values it reads lives one layer down, in
``adscan_core.ad_trust``, because the web backend needs the same answers and
cannot import this module (it lazily imports ``winacl`` and ``badldap``, which
the appliance backend image is barred from carrying). Everything below
delegates there; the public names and labels are unchanged, so the CLI table,
the attack graph and the report findings read exactly as before.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from adscan_core import telemetry
from adscan_core.ad_trust import (
    TRUST_ATTRIBUTE_BITS,
    TRUST_ATTR_CROSS_ORG_TGT_DELEGATION as _CORE_TGT_DELEGATION_BIT,
    TRUST_ATTR_QUARANTINED_DOMAIN,
    TRUST_DIRECTION_OPERATOR_LABELS,
    TRUST_SID_FILTERING_FINDING_KEY as _CORE_SID_FILTERING_KEY,
    TRUST_TGT_DELEGATION_FINDING_KEY as _CORE_TGT_DELEGATION_KEY,
    classify_trust_kind,
    decode_trust_attribute_flags,
    decode_trust_facts,
    legacy_trust_type_label,
    normalize_trust_direction,
)
from adscan_core.rich_output import print_info_debug
from adscan_core.rich_output import print_exception


# trustAttributes bits (Microsoft [MS-ADTS] 6.1.6.7.9).
#
# CANONICAL SOURCE: ``adscan_core.ad_trust.TRUST_ATTRIBUTE_BITS``, itself kept
# byte-identical to the vendored badldap enum
# ``vendor/badldap/badldap/ldap_objects/adtrust.py`` (``TrustAttributes``). The
# bits at/above 0x100 were once mis-mapped (0x100/0x200/0x800 all shifted),
# which is *not* cosmetic: a 2019+ forest trust with
# CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION (0x800) set — the exact
# misconfiguration that makes cross-trust unconstrained-delegation abuse viable —
# was decoded and reported to the client as ``TRUST_USES_AES_KEYS``, i.e. a
# hardening signal with the OPPOSITE meaning. Locked by
# ``tests/unit/services/enumeration/test_trust_query.py``.
_TRUST_ATTR_BITS: list[tuple[int, str]] = list(TRUST_ATTRIBUTE_BITS)


@dataclass
class TrustedDomainEntry:
    """Decoded ``trustedDomain`` LDAP object.

    Attributes:
        partner: FQDN of the partner domain (lowercased).
        direction: Human-readable trust direction.
        direction_raw: Raw ``trustDirection`` integer when it was readable.
        trust_type: Human-readable trust classification derived from
            ``trustAttributes`` first, then ``trustType``.
        trust_type_raw: Raw ``trustType`` integer when it was readable.
        trust_attributes: Raw ``trustAttributes`` bitmask.
        attribute_flags: Decoded list of ``trustAttributes`` bit names.
        sid: Partner domain SID (``S-1-5-21-…``) when available.
        local_domain: Dotted name of the domain whose ``trustedDomain`` object
            this is, when the search base allowed deriving it.
    """

    partner: str
    direction: str
    trust_type: str
    trust_attributes: int = 0
    attribute_flags: list[str] = field(default_factory=list)
    sid: str | None = None
    direction_raw: int | None = None
    trust_type_raw: int | None = None
    local_domain: str = ""


def decode_trust_attributes(value: int | None) -> list[str]:
    """Return the list of bit-names set on ``trustAttributes``."""
    return decode_trust_attribute_flags(value)


#: ``trustAttributes`` bit for cross-organization TGT-delegation forwarding
#: (MS-ADTS 6.1.6.7.9). Verified against the vendored badldap ``TrustAttributes``
#: enum. When set on a forest trust, Kerberos TGTs are forwarded across the
#: forest boundary — the misconfiguration that turns a cross-forest trust into a
#: cross-forest unconstrained-delegation escalation path.
TRUST_ATTR_CROSS_ORG_TGT_DELEGATION: int = _CORE_TGT_DELEGATION_BIT


def cross_org_tgt_delegation_enabled(trust_attributes: int | None) -> bool:
    """Return whether ``CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION`` is set.

    A pure predicate over the raw ``trustAttributes`` bitmask, so every consumer
    (collector persistence, attack-graph coupling, report finding) asks the same
    question through one SSOT instead of re-deriving the bit. Reuses the vendored
    badldap ``TrustAttributes`` enum when importable (byte-identical to the
    BloodHound trust export) and falls back to the local bit constant otherwise.
    """
    if not trust_attributes:
        return False
    try:
        from badldap.ldap_objects.adtrust import TrustAttributes

        return (
            TrustAttributes.CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION
            in TrustAttributes(trust_attributes)
        )
    except Exception:  # noqa: BLE001 — a vendor enum quirk must not break enum
        return bool(int(trust_attributes) & TRUST_ATTR_CROSS_ORG_TGT_DELEGATION)


def classify_trust_type(
    trust_attributes: int | None,
    trust_type: int | None,
    *,
    local_domain: str | None = None,
    partner_domain: str | None = None,
) -> str:
    """Pick a human label for the trust based on attributes/type bits.

    Passing both domain names refines a same-forest trust into a parent-child
    relation or a second domain tree; without them the parent-child reading is
    kept, which is the answer this function has always given.
    """
    return legacy_trust_type_label(
        classify_trust_kind(
            trust_attributes,
            trust_type,
            local_domain=local_domain,
            partner_domain=partner_domain,
        )
    )


def decode_trust_direction(value: int | None) -> str:
    """Return the operator-facing label for a raw ``trustDirection`` value."""
    direction, _raw = normalize_trust_direction(value)
    return TRUST_DIRECTION_OPERATOR_LABELS.get(direction, "Unknown")


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
TRUST_TGT_DELEGATION_FINDING_KEY = _CORE_TGT_DELEGATION_KEY
TRUST_SID_FILTERING_FINDING_KEY = _CORE_SID_FILTERING_KEY


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
        return bool(int(trust_attributes) & TRUST_ATTR_QUARANTINED_DOMAIN)


def evaluate_trust_posture(entry: TrustedDomainEntry) -> list[TrustPostureIssue]:
    """Judge one decoded trust and return the weaknesses ADscan reports.

    Pure logic over the raw ``entry.trust_attributes``, resolved by the shared
    decoder :func:`adscan_core.ad_trust.decode_trust_facts`. No LDAP round-trip.

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
    facts = decode_trust_facts(
        trust_attributes=entry.trust_attributes,
        trust_direction=entry.direction,
        partner_domain=entry.partner,
    )
    # The two weakenings and their client-facing sentences are resolved by the
    # shared decoder, so this finding and the web trust panel state the same
    # sentence about the same condition instead of two drifting copies.
    return [
        TrustPostureIssue(
            finding_key=key,
            partner=entry.partner,
            trust_type=entry.trust_type,
            direction=entry.direction,
            reason=note,
            attribute_flags=tuple(entry.attribute_flags),
        )
        for key, note in zip(facts.finding_keys, facts.exposure_notes)
    ]


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


@dataclass
class DomainControllerEntry:
    """One enumerated domain controller of a domain.

    Attributes:
        fqdn: The DC's ``dNSHostName`` (FQDN) when known, else ``None``.
        server_dn: The Configuration-NC ``server`` object DN (evidence).
    """

    fqdn: str | None
    server_dn: str = ""


def _parent_dn(dn: str) -> str:
    """Return the immediate parent DN of ``dn`` (empty when it has none)."""
    text = str(dn or "").strip()
    if not text or "," not in text:
        return ""
    # A DN component is comma-separated; the first comma that is not escaped
    # (``\,``) delimits the RDN from its parent. AD server/nTDSDSA DNs never use
    # escaped commas in these RDNs, so a plain split is correct and robust here.
    return text.split(",", 1)[1].strip()


def _is_no_such_object(exc: BaseException) -> bool:
    """True when an LDAP error is the benign ``noSuchObject`` search result."""
    text = str(exc).lower()
    return "nosuchobject" in text or "no such object" in text


def _dsa_hosts_domain(attrs: dict[str, list[Any]], domain_dn: str) -> bool | None:
    """Whether an nTDSDSA hosts ``domain_dn`` as its domain NC (``None``: unknown).

    ``msDS-HasDomainNCs`` names the one domain a DC serves; ``hasMasterNCs``
    (the older attribute) lists its writable NCs, the domain NC among the
    Configuration and Schema NCs. Neither readable means unknown.
    """
    wanted = str(domain_dn or "").strip().casefold()
    if not wanted:
        return None
    for name in ("msDS-HasDomainNCs", "hasMasterNCs", "msDS-hasMasterNCs"):
        values = [
            str(v).strip().casefold()
            for key, vals in attrs.items()
            if key.casefold() == name.casefold()
            for v in (vals or [])
            if str(v).strip()
        ]
        if values:
            return wanted in values
    return None


def query_domain_controllers(
    conn: Any, config_dn: str, *, domain_dn: str | None = None
) -> list[DomainControllerEntry]:
    """Enumerate a domain's full DC set from its own Configuration NC.

    Discovers every domain controller by locating the ``nTDSDSA`` objects (each
    represents one DC's directory-service instance) under
    ``CN=Sites,<config_dn>`` and reading the ``dNSHostName`` of each DSA's parent
    ``server`` object. This is the DC-locator LDAP pattern: it enumerates the
    real replicating DCs (not merely computer objects in the Domain Controllers
    OU), so it does not miss an RODC or over-count a decommissioned entry.

    MUST be called against the TARGET domain's OWN DC in its OWN realm — the
    Configuration NC is per-forest but the ``server``/``nTDSDSA`` objects are
    read over the already-authenticated connection to that domain's DC, so no
    cross-realm auth is attempted here.

    Args:
        conn: An active :class:`ADscanLDAPConnection` (or any object exposing
            ``search()`` + ``entries`` like ldap3), bound to the domain's DC.
        config_dn: The forest Configuration NC DN, e.g.
            ``CN=Configuration,DC=corp,DC=local``.

    The Sites container is FOREST-wide: it lists every DC of every domain in
    the forest. Pass ``domain_dn`` to keep only the DCs that host that domain's
    naming context (``msDS-HasDomainNCs`` / ``hasMasterNCs`` on the DSA);
    without it, a child domain recorded its parent's DCs as its own, and the
    collection of the child then contacted them. A DSA whose NC attributes are
    unreadable is kept (the count must not shrink on a read gap).

    Returns:
        One :class:`DomainControllerEntry` per discovered DC. On any search
        failure returns an empty list (telemetry records the exception); the
        caller degrades gracefully to the PDC-only view.
    """
    if not config_dn:
        return []

    sites_base = f"CN=Sites,{config_dn}"

    # 1) Enumerate the nTDSDSA objects → their parent ``server`` DNs are the DCs.
    server_dns: list[str] = []
    seen_server_dns: set[str] = set()
    try:
        conn.search(
            search_base=sites_base,
            search_filter="(objectCategory=nTDSDSA)",
            attributes=[
                "distinguishedName",
                "msDS-HasDomainNCs",
                "hasMasterNCs",
                "msDS-hasMasterNCs",
            ],
            search_scope="SUBTREE",
        )
    except Exception as exc:  # noqa: BLE001
        if _is_no_such_object(exc):
            # Expected outcome (container not visible from this vantage): the
            # caller degrades to the PDC-only view. Not a defect, no traceback.
            print_info_debug(
                f"trust_query: {sites_base} not found; using PDC-only view"
            )
            return []
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(
            f"trust_query: nTDSDSA search failed under {sites_base}: {exc}"
        )
        return []

    for entry in getattr(conn, "entries", []) or []:
        try:
            parent = _parent_dn(getattr(entry, "dn", "") or "")
            if domain_dn and _dsa_hosts_domain(_attrs(entry), domain_dn) is False:
                continue
            key = parent.casefold()
            if parent and key not in seen_server_dns:
                seen_server_dns.add(key)
                server_dns.append(parent)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    if not server_dns:
        return []

    # 2) Read each ``server`` object's dNSHostName (the DC FQDN). A single
    #    SUBTREE search over the Sites container returns every ``server``; we key
    #    by DN so only the DCs discovered in step 1 are kept, and a server whose
    #    dNSHostName is absent still yields a DC record (FQDN None) so the count
    #    stays correct even when the attribute is not readable.
    fqdn_by_server_dn: dict[str, str | None] = {}
    try:
        conn.search(
            search_base=sites_base,
            search_filter="(objectClass=server)",
            attributes=["dNSHostName", "distinguishedName"],
            search_scope="SUBTREE",
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(
            f"trust_query: server search failed under {sites_base}: {exc}"
        )
        # nTDSDSA discovery already succeeded — keep those DCs with unknown FQDN
        # rather than losing the count.
        return [DomainControllerEntry(fqdn=None, server_dn=dn) for dn in server_dns]

    for entry in getattr(conn, "entries", []) or []:
        try:
            server_dn = str(getattr(entry, "dn", "") or "").strip()
            if not server_dn:
                continue
            attrs = _attrs(entry)
            fqdn = _first_str(attrs, "dNSHostName").lower() or None
            fqdn_by_server_dn[server_dn.casefold()] = fqdn
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    return [
        DomainControllerEntry(
            fqdn=fqdn_by_server_dn.get(dn.casefold()),
            server_dn=dn,
        )
        for dn in server_dns
    ]


def domain_from_dn(domain_dn: str) -> str:
    """Return the dotted DNS name of a domain root DN.

    ``DC=north,DC=sevenkingdoms,DC=local`` becomes
    ``north.sevenkingdoms.local``. Needed so a same-forest trust can be told
    apart by name containment: a partner under the local domain is a
    parent-child relation, a partner beside it is a second domain tree.
    Returns an empty string for anything that is not a domain root DN.
    """
    labels = [
        part.split("=", 1)[1].strip()
        for part in str(domain_dn or "").split(",")
        if part.strip().lower().startswith("dc=") and "=" in part
    ]
    return ".".join(label for label in labels if label).lower()


def query_trusted_domains(
    conn: Any,
    domain_dn: str,
    *,
    on_error: Callable[[BaseException], Any] | None = None,
) -> list[TrustedDomainEntry]:
    """Enumerate ``trustedDomain`` objects under ``CN=System,<domain_dn>``.

    Args:
        conn: An active :class:`ADscanLDAPConnection` (or anything exposing
            ``search()`` and ``entries`` like ldap3).
        domain_dn: The domain root DN, e.g. ``DC=corp,DC=local``.
        on_error: Called with the search exception before the empty return, so
            a caller that must tell "no trusts" from "the read failed" (the
            collector's integrity record) can.

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
        if on_error is not None:
            try:
                on_error(exc)
            except Exception:  # noqa: BLE001 - a callback never breaks the query
                pass
        return []

    local_domain = domain_from_dn(domain_dn)

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
                    direction_raw=direction_raw,
                    trust_type=classify_trust_type(
                        attrs_raw,
                        type_raw,
                        local_domain=local_domain,
                        partner_domain=partner,
                    ),
                    trust_type_raw=type_raw,
                    trust_attributes=attrs_raw,
                    attribute_flags=decode_trust_attributes(attrs_raw),
                    sid=_decode_sid(sid_raw),
                    local_domain=local_domain,
                )
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(f"trust_query: entry decode failed: {exc}")

    return decoded
