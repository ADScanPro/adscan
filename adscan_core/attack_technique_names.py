"""Boundary-safe snapshot of attack-graph technique / edge names.

``adscan_core`` cannot import ``adscan_internal`` (host/launcher vs container
layering — see CLAUDE.md § Module ownership), but the telemetry sanitizer in
``adscan_core/telemetry.py`` must know which tokens are *public technique /
edge names* so it never pseudonymizes them. Mangling ``ADCSESC1`` into
``ISSSOND8`` or a table-cell ``GenericAll`` into noise destroys triage
readability while protecting nothing — these labels are vendor-neutral
technique identifiers documented in BloodHound / MITRE, not customer data.

The authoritative source of these names lives in ``adscan_internal``:

- ``adscan_internal/services/edge_phrasing.py`` — ``_EDGE_TRANSLATIONS`` keys
  and ``_ADCS_ESC_NAMES`` keys
- ``adscan_internal/services/edge_kind.py`` — the ``EdgeKind`` enum values and
  the closed edge catalogs (``_CONTROL_EDGES`` … ``_ESCALATION_EDGES``)

This module is a **frozen mirror** of those names so the sanitizer can consult
them without crossing the import boundary. A drift-guard test
(``tests/unit/test_attack_technique_names_drift.py``) imports BOTH this
snapshot and the ``adscan_internal`` SSOT and fails CI if they diverge — so a
newly-added technique can never silently start getting sanitized, and a removed
one can never silently linger here.

Matching policy (enforced by the sanitizer): a value is preserved only when it
is shaped like a technique name — exact membership in
:data:`ATTACK_TECHNIQUE_NAMES` (CamelCase / mixed-case edge labels), or the
``ADCSESC<N>`` pattern. Bare all-caps tokens are NOT preserved by shape alone,
so a host literally named ``DCSYNC`` still redacts.
"""

from __future__ import annotations

import re
from typing import Final


# ---------------------------------------------------------------------------
# Snapshot of edge / technique / ESC names. Kept in sync with the SSOT in
# adscan_internal by tests/unit/test_attack_technique_names_drift.py.
# ---------------------------------------------------------------------------

#: Edge-translation labels (mirror of ``edge_phrasing._EDGE_TRANSLATIONS`` keys).
_EDGE_TRANSLATION_NAMES: Final[frozenset[str]] = frozenset(
    {
        # Object control
        "GenericAll",
        "GenericWrite",
        "WriteDacl",
        "WriteOwner",
        "Owns",
        "AllExtendedRights",
        # Group manipulation
        "AddMember",
        "AddSelf",
        "MemberOf",
        # Credential abuse
        "ForceChangePassword",
        "DCSync",
        "GetChanges",
        "GetChangesAll",
        "GetChangesInFilteredSet",
        "ReadGMSAPassword",
        "ReadLAPSPassword",
        "Kerberoasting",
        "ASREPRoasting",
        # Delegation
        "AllowedToDelegate",
        "AllowedToAct",
        "SPNJack",
        # Session and execution
        "HasSession",
        "AdminTo",
        "CanRDP",
        "CanPSRemote",
        "ExecuteDCOM",
        # Trust and SID history
        "TrustedBy",
        "HasSIDHistory",
        # Privileged group escalations
        "BackupOperatorsEscalation",
        "DnsAdminsEscalation",
        "AccountOperatorsEscalation",
        "PrintOperatorsEscalation",
        "ServerOperatorsEscalation",
        "SchemaAdminsEscalation",
        "ExchangeAclEscalation",
        # Containment
        "Contains",
        "GPLink",
        # Derived (Phase 6)
        "DumpedHashOf",
        "ForgedTicketFor",
        "ReadGMSAPasswordOf",
        "OwnsCertificateFor",
    }
)


#: Edge catalog names (mirror of ``edge_kind`` ``_CONTROL_EDGES`` …
#: ``_ESCALATION_EDGES``). Names with embedded hyphens / digits (e.g.
#: ``MS17-010``) are included verbatim.
_EDGE_CATALOG_NAMES: Final[frozenset[str]] = frozenset(
    {
        # Control
        "GenericAll",
        "GenericWrite",
        "WriteDacl",
        "WriteOwner",
        "Owns",
        "AllExtendedRights",
        "AddMember",
        "AddSelf",
        "ForceChangePassword",
        "AddKeyCredentialLink",
        "HasShadowCredentials",
        "DCSync",
        "GetChanges",
        "GetChangesAll",
        "GetChangesInFilteredSet",
        "ReadGMSAPassword",
        "ReadLAPSPassword",
        "AllowedToDelegate",
        "AllowedToAct",
        "UnconstrainedDelegation",
        "AddAllowedToAct",
        "ManageRODCPrp",
        "WriteLogonScript",
        "WriteAccountRestrictions",
        "WriteSPN",
        "WriteSMBPath",
        "SyncLAPSPassword",
        "GPPPassword",
        "PasswordInShare",
        "PasswordInFile",
        "ReadShare",
        "WriteShare",
        "FullControlShare",
        # Auth
        "CanPSRemote",
        "CanRDP",
        "AdminTo",
        "ExecuteDCOM",
        "HasSession",
        "SQLAdmin",
        "SQLAccess",
        "GuestSession",
        "LDAPAnonymousBind",
        "UserDescription",
        # Membership
        "MemberOf",
        # Trust
        "TrustedBy",
        "HasSIDHistory",
        "Contains",
        "GPLink",
        # Derived
        "DumpedHashOf",
        "ForgedTicketFor",
        "ReadGMSAPasswordOf",
        "OwnsCertificateFor",
        "GoldenCert",
        "DumpLSA",
        "DumpLSASS",
        "DumpSAM",
        "DumpDPAPI",
        "ScheduledTask",
        "PrepareRODCCredentialCaching",
        "ExtractRODCKrbtgtSecret",
        "ForgeRODCGoldenTicket",
        "KerberosKeyList",
        "CoercePetitPotam",
        "CoercePrinterBug",
        "CoerceShadowCoerce",
        "CoerceMSEvenCoerce",
        "CoerceDFSCoerce",
        "PetitPotam",
        "PrinterBug",
        "DfsCoerce",
        "MsEven",
        "CoerceAndRelayNTLMToADCS",
        "CoerceToTGT",
        "Zerologon",
        "NoPac",
        "PrintNightmare",
        "BadSuccessor",
        "MS17-010",
        "MS17010",
        "SMBGhost",
        "PrinterBugSurface",
        "WebDAVEnabled",
        "DropTheMIC",
        "NTLMReflection",
        "Ntlmv1Enabled",
        "MssqlS4U2selfEscalation",
        # Escalation
        "BackupOperatorsEscalation",
        "DnsAdminsEscalation",
        "AccountOperatorsEscalation",
        "PrintOperatorsEscalation",
        "ServerOperatorsEscalation",
        "SchemaAdminsEscalation",
        "ExchangeAclEscalation",
        "BackupOperatorEscalation",
        "DnsAdminAbuse",
        "PrintOperatorAbuse",
        "Kerberoasting",
        "ASREPRoasting",
        "Timeroasting",
        "PrivilegedGroupControl",
        "LocalAdminPassReuse",
        "DomainPassReuse",
        "DomainPassReuseSource",
        "LocalCredReuseSource",
        "LocalCredToDomainReuse",
        "PasswordSpray",
        "UserAsPass",
        "BlankPassword",
        "ComputerPre2k",
        "MssqlSeImpersonateEscalation",
        "MssqlTokenTheftEscalation",
        "MssqlLinkedServerLateral",
        "MssqlImpersonateLogin",
        "MssqlTrustworthyDbEscalation",
        "MssqlNtlmv2Theft",
        "Ntlmv1RelayRBCD",
        "Ntlmv1RelayShadowCreds",
        "SPNJack",
        "CrackNTLMv1",
        "PoisonCaptureNtlmv2Crack",
    }
)


#: ADCS ESC technique names (mirror of ``edge_phrasing._ADCS_ESC_NAMES`` keys).
#: These also match the ``ADCSESC<N>`` shape pattern below; the explicit set
#: keeps them covered even if the numbering scheme ever changes.
_ADCS_ESC_NAMES: Final[frozenset[str]] = frozenset(
    {f"ADCSESC{n}" for n in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 16)}
)


#: EdgeKind enum *values* (mirror of ``edge_kind.EdgeKind``). Lowercase tokens
#: like ``control`` / ``auth`` are short generic words; they are NOT added to
#: the preserve set (they would over-preserve ordinary prose). They are mirrored
#: only so the drift guard can confirm the snapshot stays aware of the enum.
EDGE_KIND_VALUES: Final[frozenset[str]] = frozenset(
    {"control", "auth", "membership", "trust", "derived", "escalation", "unknown"}
)


#: The closed set of public technique / edge labels the telemetry sanitizer must
#: NEVER pseudonymize. Exact, case-sensitive membership.
ATTACK_TECHNIQUE_NAMES: Final[frozenset[str]] = (
    _EDGE_TRANSLATION_NAMES | _EDGE_CATALOG_NAMES | _ADCS_ESC_NAMES
)


#: Shape gate for ADCS ESC labels (``ADCSESC1`` … ``ADCSESC16`` and beyond).
_ADCS_ESC_SHAPE_RE: Final[re.Pattern[str]] = re.compile(r"^ADCSESC\d+$")


def is_attack_technique_name(value: str) -> bool:
    """Return True when ``value`` is a public technique / edge label.

    The match is shape-gated so it preserves only tokens that *look like* a
    technique name and would never be customer data:

    - exact membership in :data:`ATTACK_TECHNIQUE_NAMES` (CamelCase / mixed-case
      edge labels such as ``GenericAll``, ``MemberOf``, ``ADCSESC1``), or
    - the ``ADCSESC<N>`` pattern.

    A bare all-caps token (e.g. a host literally named ``DCSYNC``) is NOT
    matched by shape alone and therefore still redacts.

    Args:
        value: A candidate token (already stripped of surrounding whitespace by
            the caller is acceptable; this strips defensively).

    Returns:
        True if the value is a known public technique / edge name.
    """
    if not value or not isinstance(value, str):
        return False
    token = value.strip()
    if not token:
        return False
    if token in ATTACK_TECHNIQUE_NAMES:
        return True
    return bool(_ADCS_ESC_SHAPE_RE.match(token))
