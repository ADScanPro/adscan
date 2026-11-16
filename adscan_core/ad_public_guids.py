"""GUIDs that are the same in every Active Directory forest: public constants.

The extended rights, property sets and base-schema attributes the ACL parser
maps to attack relations, plus the two default Group Policy objects every
domain is created with. None of them identifies a client, so telemetry keeps
them readable (``adscan_core.sensitive``), and the ACL parser reads its tables
from here, so the two can never disagree about what is public.

Pure data, stdlib only: importable from the launcher, the engine and the web.
"""

from __future__ import annotations

import re

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
WELL_KNOWN_SCHEMA_ID_GUIDS: dict[str, str] = {
    "scriptPath": "bf9679a8-0de6-11d0-a285-00aa003049e2",
    "member": "bf9679c0-0de6-11d0-a285-00aa003049e2",
    "servicePrincipalName": "f3a64788-5306-11d1-a9c5-0000f80367c1",
    "msDS-KeyCredentialLink": "5b47d60f-6090-40b2-9f37-2a4de88f3063",
}

#: The policy GUIDs of the two Group Policy objects every domain is created with.
DEFAULT_GPO_GUIDS: dict[str, str] = {
    "31b2f340-016d-11d2-945f-00c04fb984f9": "Default Domain Policy",
    "6ac1786c-016f-11d2-945f-00c04fb984f9": "Default Domain Controllers Policy",
}

#: Every GUID above, lower case, no braces.
PUBLIC_AD_GUIDS: frozenset[str] = frozenset(
    {
        *PROPERTY_SET_GUID_TO_RELATION,
        *EXTENDED_RIGHT_GUID_TO_RELATION,
        *SELF_WRITE_GUID_TO_RELATION,
        *(guid.lower() for guid in WELL_KNOWN_SCHEMA_ID_GUIDS.values()),
        *DEFAULT_GPO_GUIDS,
    }
)

_GUID_RE = re.compile(r"^\{?([0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12})\}?$")


def is_public_ad_guid(value: str) -> bool:
    """Whether ``value`` (with or without braces, any case) is one of :data:`PUBLIC_AD_GUIDS`."""
    match = _GUID_RE.match(str(value or "").strip())
    return bool(match) and match.group(1).lower() in PUBLIC_AD_GUIDS


__all__ = (
    "DEFAULT_GPO_GUIDS",
    "EXTENDED_RIGHT_GUID_TO_RELATION",
    "PROPERTY_SET_GUID_TO_RELATION",
    "PUBLIC_AD_GUIDS",
    "SELF_WRITE_GUID_TO_RELATION",
    "WELL_KNOWN_SCHEMA_ID_GUIDS",
    "is_public_ad_guid",
)
