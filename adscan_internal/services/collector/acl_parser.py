from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import UUID

from adscan_internal import telemetry
from adscan_internal.rich_output import print_info_debug, print_warning_debug
from adscan_internal.services.collector.models import CollectorEdge, NodeKind
from adscan_core.rich_output import print_exception

if TYPE_CHECKING:
    from adscan_internal.services.ldap_transport_service import ADscanLDAPConnection

_ADS_RIGHT_DS_SELF = 0x00000008          # Validated Write — "Self" (e.g. Self-Membership on group)
_ADS_RIGHT_DS_WRITE_PROP = 0x20
_ADS_RIGHT_DS_READ_PROP = 0x10
_ADS_RIGHT_GENERIC_ALL = 0x10000000
_ADS_RIGHT_GENERIC_WRITE = 0x40000000
_ADS_RIGHT_WRITE_DACL = 0x00040000
_ADS_RIGHT_WRITE_OWNER = 0x00080000
_ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100
_FULL_CONTROL_MASK = 0x000F01FF

_ACCESS_ALLOWED_ACE_TYPE = 0x00
_ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05

# AceFlags bits (MS-DTYP §2.4.4.1)
_ACE_INHERIT_ONLY = 0x08

# ACCESS_ALLOWED_OBJECT_ACE.Flags bits (MS-DTYP §2.4.4.4)
_ACE_OBJECT_TYPE_PRESENT = 0x01

GENERIC_ACL_RIGHTS: dict[int, str] = {
    _ADS_RIGHT_GENERIC_ALL: "GenericAll",
    _FULL_CONTROL_MASK: "GenericAll",
    _ADS_RIGHT_GENERIC_WRITE: "GenericWrite",
    _ADS_RIGHT_WRITE_DACL: "WriteDACL",
    _ADS_RIGHT_WRITE_OWNER: "WriteOwner",
    _ADS_RIGHT_DS_CONTROL_ACCESS: "AllExtendedRights",
}

WRITE_PROPERTY_GUID_TO_RELATION: dict[str, str] = {
    "scriptPath": "WriteLogonScript",
    "msDS-RevealOnDemandGroup": "ManageRODCPrp",
    "msDS-NeverRevealGroup": "ManageRODCPrp",
    "member": "AddMember",
    "servicePrincipalName": "WriteSPN",
    "msDS-KeyCredentialLink": "AddKeyCredentialLink",
}

# READ_PROP grants on these LAPS attributes ARE the real read authority — the DC
# returns the cleartext/encrypted local-admin password to any principal the DACL
# grants READ_PROP on the attribute, so these mappings are correct and load-bearing.
#
# Deliberately EXCLUDED: "msDS-ManagedPassword" (gMSA). A DACL READ_PROP grant on
# the gMSA managed-password attribute is INERT — the DC returns the confidential
# managed password ONLY to principals listed in msDS-GroupMSAMembership
# (PrincipalsAllowedToRetrieveManagedPassword), regardless of the DACL. Mapping it
# here produced a phantom "Everyone (S-1-1-0) --ReadGMSAPassword--> <gMSA>" edge
# (the gMSA DACL grants S-1-1-0 READ_PROP on the attribute, but Everyone can never
# actually read it). The genuine ReadGMSAPassword edge is parsed from the
# msDS-GroupMSAMembership security descriptor in
# ldap_collector._parse_gmsa_membership_sd, so this exclusion loses no real edge.
# Do NOT re-add msDS-ManagedPassword here.
READ_PROPERTY_GUID_TO_RELATION: dict[str, str] = {
    "ms-Mcs-AdmPwd": "ReadLAPSPassword",
    "msLAPS-Password": "ReadLAPSPassword",
    "msLAPS-EncryptedPassword": "ReadLAPSPassword",
}

# Well-known property-set GUIDs. Granted via DS_WRITE_PROP on the property set.
# These are stable Windows constants — no LDAP schema lookup needed.
PROPERTY_SET_GUID_TO_RELATION: dict[str, str] = {
    "4c164200-20c0-11d0-a768-00aa006e0529": "WriteAccountRestrictions",  # User-Account-Restrictions
}

# Well-known extended-right GUIDs (CN=Extended-Rights,CN=Configuration).
# Granted via DS_CONTROL_ACCESS on an OBJECT_ACE. Stable across all AD environments.
EXTENDED_RIGHT_GUID_TO_RELATION: dict[str, str] = {
    "00299570-246d-11d0-a768-00aa006e0529": "ForceChangePassword",
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "AddSelf",  # Self-Membership
    "0e10c968-78fb-11d2-90d4-00c04f79dc55": "Enroll",  # Certificate-Enrollment
    "a05b8cc2-17bc-4802-a710-e7c15ab866a2": "AutoEnroll",  # Certificate-AutoEnrollment
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "GetChanges",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "GetChangesAll",
    "89e95b76-444d-4c62-991a-0facbeda640c": "GetChangesInFilteredSet",
}

# Validated-write GUIDs for DS_SELF (0x8) ACEs.
# DS_SELF + one of these GUIDs means the trustee can perform the named validated
# write against their own identity only — distinct from DS_WRITE_PROP (AddMember)
# which grants unrestricted writes.  AD encodes the Self-Membership validated
# write via the *same* GUID as the `member` attribute (bf9679c0-…) but with
# the DS_SELF bit instead of DS_WRITE_PROP.  This is a deliberate AD design:
# the GUID distinguishes *which* attribute; the mask bit determines *who* can
# be written (self only vs anyone).
SELF_WRITE_GUID_TO_RELATION: dict[str, str] = {
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "AddSelf",  # member — Self-Membership
}

# Static, PRIMARY source for attribute schemaIDGUIDs.
#
# Base-schema attributes are defined by MS-ADSC and their schemaIDGUID is FIXED
# across every AD forest — Microsoft never regenerates them — so resolving them
# needs no per-attribute CN=Schema query. Querying the DC once per attribute is
# both fragile (a transient LDAP failure could drop the scoped ACL edge) and
# unnecessary for these constants, so they are served from this table and the
# live schema lookup is kept only as a fallback for the rest.
#
# Sourcing note: reference/ (SharpHound/BloodHound common-lib well-known-GUID
# lists, bloodyAD, ldeep) was NOT populated when this table was authored, so
# every GUID below is a base-schema MS-ADSC constant taken from the published
# schema — not invented from memory. ``member`` is additionally cross-checked
# against SELF_WRITE_GUID_TO_RELATION in this same file (same GUID,
# bf9679c0-…). Attributes whose schemaIDGUID is per-forest / schema-extension
# generated and therefore NOT fixed — legacy LAPS ``ms-Mcs-AdmPwd``, the
# Windows LAPS ``msLAPS-*`` attributes, and the RODC reveal groups
# ``msDS-RevealOnDemandGroup`` / ``msDS-NeverRevealGroup`` — are deliberately
# ABSENT here and resolve through the live CN=Schema fallback instead.
_WELL_KNOWN_SCHEMA_ID_GUIDS: dict[str, str] = {
    "scriptPath": "bf9679a8-0de6-11d0-a285-00aa003049e2",
    "member": "bf9679c0-0de6-11d0-a285-00aa003049e2",
    "servicePrincipalName": "f3a64788-5306-11d1-a9c5-0000f80367c1",
    "msDS-KeyCredentialLink": "5b47d60f-6090-40b2-9f37-2a4de88f3063",
}

PROPERTY_GUID_TO_RELATION: dict[str, str] = {
    **WRITE_PROPERTY_GUID_TO_RELATION,
    **READ_PROPERTY_GUID_TO_RELATION,
}


# Each non-generic relation is only meaningful on a restricted set of target
# kinds. Inherited / property-set ACEs on parent containers (Domain, OU,
# Container) carry GUIDs for ``ForceChangePassword`` / ``AddMember`` etc.
# whose semantic is "applicable to child objects of class X" — but the parser
# materializes them as edges to the parent. Without this filter, the graph
# ends up with nonsense like ``EWP -ForceChangePassword-> Domain`` which is
# not a real attack step (you can't reset the Domain's password) and pollutes
# attack-path UX. Generic edges (GenericAll/Write, WriteDACL, WriteOwner)
# remain valid on every target kind.
_RELATION_VALID_TARGET_KINDS: dict[str, frozenset[str]] = {
    "ForceChangePassword": frozenset({"User", "Computer"}),
    "AddMember": frozenset({"Group"}),
    "AddSelf": frozenset({"Group"}),
    "AddKeyCredentialLink": frozenset({"User", "Computer"}),
    "WriteSPN": frozenset({"User", "Computer"}),
    "ReadLAPSPassword": frozenset({"Computer"}),
    "ReadGMSAPassword": frozenset({"User", "Computer"}),
    "WriteAccountRestrictions": frozenset({"User", "Computer"}),
    "WriteLogonScript": frozenset({"User", "Computer"}),
    "ManageRODCPrp": frozenset({"Computer"}),
    "Enroll": frozenset({"CertTemplate"}),
    "AutoEnroll": frozenset({"CertTemplate"}),
    "GetChanges": frozenset({"Domain"}),
    "GetChangesAll": frozenset({"Domain"}),
    "GetChangesInFilteredSet": frozenset({"Domain"}),
}


# LDAP result codes that are a DEFINITIVE answer from the directory: the object
# or attribute genuinely is not there. They are the exact opposite of a transport
# failure and must be cached as a negative, not retried once per ACL-bearing
# object. badldap surfaces them as an ``LDAPSearchException`` (raised, not
# returned), so a definitive result arrives through the same ``except`` as a
# connection reset — hence this classifier.
#
# ``noSuchObject``            (32) — the search base does not exist.
# ``undefinedAttributeType``  (17) — the attribute is not in the schema.
# ``noSuchAttribute``         (16) — the requested attribute is absent.
_DEFINITIVE_LDAP_ABSENCE_RESULTS: frozenset[str] = frozenset(
    {"noSuchObject", "undefinedAttributeType", "noSuchAttribute"}
)
_DEFINITIVE_LDAP_ABSENCE_CODES: dict[int, str] = {
    16: "noSuchAttribute",
    17: "undefinedAttributeType",
    32: "noSuchObject",
}
# Windows maps the same condition into the diagnostic message, which badldap
# decodes into the WINERROR name. Present when the DC answers a search over a
# base that does not exist.
_DEFINITIVE_LDAP_ABSENCE_DIAGNOSTICS: tuple[str, ...] = (
    "ERROR_DS_OBJ_NOT_FOUND",
    "ERROR_DS_NO_SUCH_OBJECT",
)


def classify_ldap_absence(exc: BaseException) -> str | None:
    """Return the LDAP result name when ``exc`` is a DEFINITIVE absence.

    Returns ``None`` for anything else — a connection reset, a timeout, an
    LDAP signing/CBT renegotiation, an unclassifiable error — so the caller
    keeps treating those as transient and retry-able.

    Duck-typed on purpose: badldap's ``LDAPServerException`` carries
    ``resultname``/``resultcode``, but the classifier must not depend on that
    import (or on the exception surviving a vendor rebase unchanged), so it
    falls back to the numeric code and finally to the rendered message.
    """
    name = getattr(exc, "resultname", None)
    if isinstance(name, str) and name in _DEFINITIVE_LDAP_ABSENCE_RESULTS:
        return name

    code = getattr(exc, "resultcode", None)
    try:
        mapped = _DEFINITIVE_LDAP_ABSENCE_CODES.get(int(code))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        mapped = None
    if mapped:
        return mapped

    text = str(exc or "")
    for marker in _DEFINITIVE_LDAP_ABSENCE_DIAGNOSTICS:
        if marker in text:
            return "noSuchObject"
    for result_name in _DEFINITIVE_LDAP_ABSENCE_RESULTS:
        if result_name in text:
            return result_name
    return None


def _relation_valid_for_target(relation: str, target_kind: str) -> bool:
    """Return True when ``relation`` makes operational sense on ``target_kind``.

    Generic relations (GenericAll, GenericWrite, WriteDACL, WriteOwner,
    AllExtendedRights, Owns) are valid on any object class. Specialized
    relations are restricted via :data:`_RELATION_VALID_TARGET_KINDS`.
    """
    valid = _RELATION_VALID_TARGET_KINDS.get(relation)
    if valid is None:
        return True
    return str(target_kind or "") in valid


class ACLParser:
    """Parse nTSecurityDescriptor bytes into CollectorEdge instances."""

    def __init__(self, domain: str, connection: ADscanLDAPConnection | None) -> None:
        self.domain = domain
        self._connection = connection
        self._guid_cache: dict[str, str | None] = {}
        # Tri-state, memoized for the whole run: None = not probed yet,
        # True = the schema base answered, False = the DC definitively says it
        # is not there, so every live fallback lookup is disabled after ONE
        # warning instead of failing once per ACL-bearing object.
        self._schema_base_available: bool | None = None

    def parse_sd(
        self,
        sd_bytes: bytes,
        target_object_id: str,
        target_kind: NodeKind,
    ) -> list[CollectorEdge]:
        if not sd_bytes:
            return []
        try:
            from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR  # type: ignore
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_warning_debug(f"acl_parser: winacl unavailable: {exc}")
            return []

        try:
            sd = SECURITY_DESCRIPTOR.from_bytes(sd_bytes)
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(f"acl_parser: Failed to parse SD: {exc}")
            return []

        dacl = getattr(sd, "Dacl", None)
        if not dacl:
            return []

        write_property_guid_map = self._build_property_guid_map(
            WRITE_PROPERTY_GUID_TO_RELATION
        )
        read_property_guid_map = self._build_property_guid_map(
            READ_PROPERTY_GUID_TO_RELATION
        )
        # SELF_WRITE_GUID_TO_RELATION uses stable Windows GUIDs — no schema
        # lookup needed; they are the same across all AD versions.
        self_write_guid_map = {k: v for k, v in SELF_WRITE_GUID_TO_RELATION.items()}
        edges: list[CollectorEdge] = []

        for ace in getattr(dacl, "aces", []) or []:
            ace_type = self._ace_type(ace)
            if ace_type not in (
                _ACCESS_ALLOWED_ACE_TYPE,
                _ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            ):
                continue

            # INHERIT_ONLY ACEs do not apply to the object that holds them —
            # only to their child objects via inheritance. Materializing them
            # as direct edges produces phantom GenericAll/WriteDACL on the
            # parent (typical false positive on Domain/OU objects).
            ace_flags = self._ace_flags(ace)
            if ace_flags & _ACE_INHERIT_ONLY:
                continue

            trustee = self._trustee_sid(ace)
            if not trustee or trustee == target_object_id:
                continue

            mask = self._ace_mask(ace)
            if mask is None:
                continue

            if ace_type == _ACCESS_ALLOWED_OBJECT_ACE_TYPE:
                obj_guid = self._object_type_guid(ace)
                # ACE_OBJECT_TYPE_PRESENT means the mask is RESTRICTED to the
                # specific schema element identified by ``ObjectType``. The
                # ACE does NOT grant generic rights over the whole object —
                # treating it as such is the canonical RustHound-CE issue #33
                # (Exchange schema GUIDs surfacing as ``GenericAll`` on the
                # Domain root). We therefore look up the GUID against our
                # closed catalogs; anything outside them must be skipped, not
                # downgraded to a generic relation.
                object_type_present = bool(
                    self._ace_object_flags(ace) & _ACE_OBJECT_TYPE_PRESENT
                ) or bool(obj_guid)
                if object_type_present:
                    property_relation = self._classify_object_ace(
                        mask=mask,
                        obj_guid=obj_guid or "",
                        write_property_guid_map=write_property_guid_map,
                        read_property_guid_map=read_property_guid_map,
                        self_write_guid_map=self_write_guid_map,
                    )
                    if property_relation and _relation_valid_for_target(
                        property_relation, str(target_kind)
                    ):
                        edges.append(
                            CollectorEdge(
                                source_object_id=trustee,
                                target_object_id=target_object_id,
                                relation=property_relation,
                                source="acl_parser",
                                method="acl",
                            )
                        )
                    # Whether the GUID matched a known relation or not, the
                    # ACE is scoped to that GUID — never fall through to the
                    # generic-relation branch.
                    continue

            relation = self._generic_relation(mask)
            if relation:
                edges.append(
                    CollectorEdge(
                        source_object_id=trustee,
                        target_object_id=target_object_id,
                        relation=relation,
                        source="acl_parser",
                        method="acl",
                    )
                )
                continue

        return edges

    def _classify_object_ace(
        self,
        *,
        mask: int,
        obj_guid: str,
        write_property_guid_map: dict[str, str],
        read_property_guid_map: dict[str, str],
        self_write_guid_map: dict[str, str] | None = None,
    ) -> str | None:
        """Classify an OBJECT_ACE whose mask is scoped to ``obj_guid``.

        Returns the canonical relation name when the GUID is one we know how
        to map (extended-right grants like DCSync, write-property grants like
        AddMember, read-property grants like ReadLAPSPassword, well-known
        property sets, or validated-write Self grants like AddSelf).
        Returns ``None`` for any GUID outside those catalogs — including
        Exchange schema GUIDs and other vendor extensions whose scope cannot
        be reduced to a domain-control edge.

        The ``DS_SELF`` (0x8) branch handles validated-write "Self" ACEs.
        AD uses the *same GUID* for the `member` attribute (schemaIDGUID) and
        the Self-Membership extended right (rightsGUID), but distinguishes
        them via the mask bit:
          - DS_SELF (0x8)         → AddSelf  (trustee can only add themselves)
          - DS_WRITE_PROP (0x20)  → AddMember (trustee can add anyone)
          - DS_CONTROL_ACCESS (0x100) on ext-right GUID → AddSelf (alternative form)
        """
        if not obj_guid:
            return None
        # DS_SELF (validated-write Self): trustee can write their own identity
        # into the attribute — the canonical "Self-Membership" grant on groups.
        if mask & _ADS_RIGHT_DS_SELF:
            smap = self_write_guid_map or SELF_WRITE_GUID_TO_RELATION
            relation = smap.get(obj_guid)
            if relation:
                return relation
        if mask & _ADS_RIGHT_DS_CONTROL_ACCESS:
            relation = EXTENDED_RIGHT_GUID_TO_RELATION.get(obj_guid)
            if relation:
                return relation
        if mask & _ADS_RIGHT_DS_WRITE_PROP:
            relation = write_property_guid_map.get(obj_guid)
            if relation:
                return relation
            relation = PROPERTY_SET_GUID_TO_RELATION.get(obj_guid)
            if relation:
                return relation
        if mask & (
            _ADS_RIGHT_DS_READ_PROP
            | _ADS_RIGHT_DS_CONTROL_ACCESS
            | _ADS_RIGHT_GENERIC_ALL
        ):
            relation = read_property_guid_map.get(obj_guid)
            if relation:
                return relation
        return None

    def _generic_relation(self, mask: int) -> str | None:
        """Map an unscoped mask (whole-object ACE) to a relation name.

        Only called for ACEs that grant rights over the entire object — i.e.
        ``ACCESS_ALLOWED_ACE`` and ``ACCESS_ALLOWED_OBJECT_ACE`` whose
        ``ObjectType`` is absent. Object ACEs scoped to a specific schema
        GUID are routed through :meth:`_classify_object_ace` instead and
        never reach this method.
        """
        if mask & _ADS_RIGHT_GENERIC_ALL:
            return "GenericAll"
        if mask == _FULL_CONTROL_MASK:
            return "GenericAll"
        if mask & _ADS_RIGHT_GENERIC_WRITE:
            return "GenericWrite"
        if mask & _ADS_RIGHT_DS_WRITE_PROP:
            return "GenericWrite"
        if mask & _ADS_RIGHT_WRITE_DACL:
            return "WriteDACL"
        if mask & _ADS_RIGHT_WRITE_OWNER:
            return "WriteOwner"
        if mask & _ADS_RIGHT_DS_CONTROL_ACCESS:
            return "AllExtendedRights"
        return None

    def _build_property_guid_map(self, attrs: dict[str, str]) -> dict[str, str]:
        result: dict[str, str] = {}
        for attr_name, relation in attrs.items():
            guid = self._resolve_property_guid(attr_name)
            if guid:
                result[guid] = relation
        return result

    def _resolve_property_guid(self, attr_name: str) -> str | None:
        """Resolve an attribute's ``schemaIDGUID`` (lowercased string form).

        Resolution order:
          1. Positive cache — a GUID already resolved this run.
          2. Static well-known table (:data:`_WELL_KNOWN_SCHEMA_ID_GUIDS`) —
             the PRIMARY source for base-schema attributes whose GUID is fixed
             across every forest. No LDAP round-trip, so a transient DC failure
             can never drop these scoped ACL edges.
          3. Live ``CN=Schema`` lookup — the FALLBACK for per-forest /
             schema-extension attributes (LAPS, RODC reveal groups) absent from
             the static table.

        Negative caching is DEFINITIVE-ONLY (mirrors the posture doctrine
        "cache observations, never cache absences"), and "definitive" covers
        BOTH shapes the DC answers in:

        * the search succeeded and returned zero matching entries, and
        * the search raised with a definitive LDAP result code —
          ``noSuchObject`` / ``undefinedAttributeType`` / ``noSuchAttribute``
          (see :func:`classify_ldap_absence`). badldap raises these instead of
          returning them, so without the classifier a definitive answer looked
          exactly like a transport failure: no negative caching, plus a
          telemetry event and a red traceback once per ACL-bearing object. On a
          forest with no LAPS schema extension that is guaranteed and permanent
          (152 identical failures in one collection, in the field).

        A missing/empty ``config_dn`` (UNKNOWN) or a genuinely transient
        exception (connection reset, LDAP signing/CBT renegotiation, timeout)
        still returns ``None`` WITHOUT caching, so a later call retries instead
        of the whole run silently dropping this attribute's scoped ACL edges.

        ``noSuchObject`` is treated as a statement about the SEARCH BASE, not
        about one attribute: it means ``CN=Schema,<config_dn>`` itself is not
        there, so every remaining live lookup this run would fail identically.
        The first one disables the fallback for the run (one warning, no extra
        probe round-trip), which is what turns 152 failed searches into 1.
        """
        if attr_name in self._guid_cache:
            return self._guid_cache[attr_name]

        static_guid = _WELL_KNOWN_SCHEMA_ID_GUIDS.get(attr_name)
        if static_guid is not None:
            self._guid_cache[attr_name] = static_guid
            return static_guid

        if not self._connection:
            # No schema connection — UNKNOWN for this attribute, not a
            # definitive not-found. Do not poison the cache.
            return None

        config_dn = getattr(self._connection, "config_dn", None)
        if not config_dn:
            # An empty/None config_dn would build a malformed "CN=Schema," base.
            # UNKNOWN, not not-found — return None WITHOUT caching so a later
            # call (once config_dn is populated) can retry.
            return None

        if self._schema_base_available is False:
            # The DC already told us this base does not exist. Every live
            # lookup would fail identically, so cache the negative and skip the
            # round-trip entirely.
            self._guid_cache[attr_name] = None
            return None

        schema_base = f"CN=Schema,{config_dn}"
        try:
            self._connection.search(
                search_base=schema_base,
                search_filter=f"(lDAPDisplayName={attr_name})",
                attributes=["schemaIDGUID"],
                search_scope="SUBTREE",
            )
            entries = self._connection.entries
            raw_guid_list = (
                entries[0].entry_raw_attributes.get("schemaIDGUID") or []
                if entries
                else []
            )
            raw_guid = raw_guid_list[0] if raw_guid_list else None
        except Exception as exc:
            absence = classify_ldap_absence(exc)
            if absence:
                # The DC answered definitively. Cache the negative, stay quiet
                # (an unextended forest is normal), and never spend telemetry
                # on it.
                self._guid_cache[attr_name] = None
                if absence == "noSuchObject" and self._schema_base_available is None:
                    self._schema_base_available = False
                    print_warning_debug(
                        "acl_parser: the directory schema container is not "
                        "present at the expected base; attributes that need a "
                        "live schema lookup (LAPS, RODC reveal groups) are "
                        "skipped for the rest of this run."
                    )
                else:
                    print_info_debug(
                        f"acl_parser: {attr_name} is not present in this "
                        f"forest's schema ({absence}); scoped ACL edges for it "
                        "are skipped."
                    )
                return None
            # Transient failure (connection reset, signing/CBT renegotiation,
            # timeout, ...). Retry-able — return None WITHOUT caching so the
            # whole run is not poisoned for this attribute.
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(
                f"acl_parser: transient GUID resolution failure for {attr_name}: {exc}"
            )
            return None

        # The base answered, so it exists — record that, and a later stray
        # ``noSuchObject`` can no longer disable the fallback for the run.
        self._schema_base_available = True

        if not raw_guid:
            # The search DEFINITIVELY succeeded and returned no schemaIDGUID for
            # this attribute — a real not-found. Safe to cache the negative.
            self._guid_cache[attr_name] = None
            return None

        try:
            guid_str = str(UUID(bytes_le=raw_guid)).lower()
        except Exception as exc:
            # Malformed GUID bytes — do not cache; a re-query is cheap and a
            # cached None here would drop the edge for the whole run.
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(
                f"acl_parser: could not parse schemaIDGUID for {attr_name}: {exc}"
            )
            return None

        self._guid_cache[attr_name] = guid_str
        return guid_str

    def _ace_type(self, ace: Any) -> int | None:
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

    def _ace_flags(self, ace: Any) -> int:
        """Return ``AceHeader.AceFlags`` (header-level) as int, 0 on failure."""
        try:
            value = getattr(ace, "AceFlags", 0)
            inner = getattr(value, "value", None)
            if inner is not None:
                return int(inner)
            return int(value or 0)
        except Exception:
            return 0

    def _ace_object_flags(self, ace: Any) -> int:
        """Return ``ACCESS_ALLOWED_OBJECT_ACE.Flags`` (per-ACE-body bitmap).

        Distinct from ``AceFlags`` (the header field). ``Flags`` carries
        ``ACE_OBJECT_TYPE_PRESENT`` (0x01) and
        ``ACE_INHERITED_OBJECT_TYPE_PRESENT`` (0x02) and tells us whether
        ``ObjectType`` / ``InheritedObjectType`` are meaningful.
        """
        try:
            value = getattr(ace, "Flags", 0)
            inner = getattr(value, "value", None)
            if inner is not None:
                return int(inner)
            return int(value or 0)
        except Exception:
            return 0

    def _ace_mask(self, ace: Any) -> int | None:
        mask = getattr(ace, "Mask", None)
        if mask is None:
            return None
        if isinstance(mask, int):
            return mask
        nested = getattr(mask, "Mask", None)
        if isinstance(nested, int):
            return nested
        try:
            return int(mask)
        except (TypeError, ValueError):
            return None

    def _trustee_sid(self, ace: Any) -> str | None:
        try:
            return str(getattr(ace, "Sid", "") or "")
        except Exception:
            return None

    def _object_type_guid(self, ace: Any) -> str | None:
        try:
            raw = getattr(ace, "ObjectType", None)
        except Exception:
            return None
        if not raw:
            return None
        try:
            if isinstance(raw, bytes):
                return str(UUID(bytes_le=raw)).lower()
            return str(raw).lower()
        except Exception:
            return None
