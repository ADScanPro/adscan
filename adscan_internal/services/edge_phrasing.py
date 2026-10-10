"""Edge translation between BloodHound technical labels and business language.

The canonical taxonomy is documented in:
- ``adscan-private-tool/CLAUDE.md`` (§ Nomenclature Standard)
- ``adscan-obsidian/business/12_nomenclature_standard.md``

CLI consumers should keep the technical edge label visible (pentester
audience). Report PDF and web app should render the human translation
by default and only expose the technical label inside a "technical view"
toggle. This module is the single source of truth for both surfaces.

Translations target a single locale: idiomatic enterprise English. ICP
reads Microsoft Docs and MITRE ATT&CK in English daily — there is no
i18n layer and no plan to add one. Keep copy short, active, and free of
filler.
"""

from __future__ import annotations

from typing import Final


_ADCS_ESC_PATTERN: Final[str] = "ADCSESC"


_EDGE_TRANSLATIONS: Final[dict[str, str]] = {
    # Object control
    "GenericAll": "Full control over the object",
    "GenericWrite": "Write access to critical attributes",
    "WriteDacl": "Can modify the object's access control list",
    "WriteOwner": "Can take ownership of the object",
    "Owns": "Owner of the object in Active Directory",
    "AllExtendedRights": "Holds all extended rights on the object",
    # Group manipulation
    "AddMember": "Can add members to the group",
    "AddSelf": "Can add self to the group",
    "MemberOf": "Group membership",
    # Credential abuse
    "ForceChangePassword": "Can reset the password without knowing the current one",
    "DCSync": "Can replicate domain credentials (DCSync)",
    "GetChanges": "Partial directory replication rights",
    "GetChangesAll": "Full directory replication rights",
    "GetChangesInFilteredSet": "Filtered directory replication rights",
    "ReadGMSAPassword": "Can read gMSA password",
    "ReadLAPSPassword": "Can read LAPS password",
    "Kerberoasting": "Offline password recovery via Kerberos service ticket",
    "ASREPRoasting": "Offline password recovery via missing Kerberos pre-auth",
    # Delegation
    "AllowedToDelegate": "Constrained delegation configured to this host",
    "AllowedToAct": "Resource-based constrained delegation (RBCD)",
    "SPNJack": "Host takeover via SPN hijacking and constrained delegation",
    # Session and execution
    "HasSession": "Active user session on the host",
    "AdminTo": "Local admin access on the host",
    "CanRDP": "Remote Desktop access to the host",
    "CanPSRemote": "PowerShell Remoting access to the host",
    "ExecuteDCOM": "Remote execution via DCOM",
    # Trust and SID history
    "TrustedBy": "Inbound trust from another domain",
    "HasSIDHistory": "SID history crossing domain boundaries",
    # Privileged group escalations
    "BackupOperatorsEscalation": (
        "Backup Operators escalation against the Domain Controller"
    ),
    "DnsAdminsEscalation": "DNS service DLL hijack via DnsAdmins",
    "AccountOperatorsEscalation": ("Privileged account takeover via Account Operators"),
    "PrintOperatorsEscalation": ("Malicious print driver loaded via Print Operators"),
    "ServerOperatorsEscalation": ("Privileged service tampering via Server Operators"),
    "SchemaAdminsEscalation": (
        "Active Directory schema modification via Schema Admins"
    ),
    "ExchangeAclEscalation": "Domain escalation via Exchange ACL rights",
    # Containment
    "Contains": "Contains the object in the AD hierarchy",
    "GPLink": "Group Policy linked to the object",
    # Derived (Phase 6 — promoted by ADscan post-exploitation when proof exists)
    "DumpedHashOf": "Credentials extracted after confirmed compromise",
    "ForgedTicketFor": "Forged Kerberos ticket on behalf of the object",
    "ReadGMSAPasswordOf": "gMSA password successfully retrieved",
    "OwnsCertificateFor": "Authentication certificate obtained for the object",
    # Certighost (CVE-2026-54121) — CA chase-fallback DC impersonation
    "certighost": "CA issues a domain-controller certificate to an impostor",
}


# Authoritative ADCS ESC name table — kept compact; full names are appended
# in the translator output for traceability.
_ADCS_ESC_NAMES: Final[dict[str, str]] = {
    "ADCSESC1": "Editable SAN allows impersonation",
    "ADCSESC2": "Any Purpose EKU allows impersonation",
    "ADCSESC3": "Enrollment Agent template abuse",
    "ADCSESC4": "Weak permissions on certificate template",
    "ADCSESC5": "Weak permissions on PKI objects",
    "ADCSESC6": "EDITF_ATTRIBUTESUBJECTALTNAME2 enabled on the CA",
    "ADCSESC7": "Vulnerable permissions on the CA",
    "ADCSESC8": "NTLM relay to AD CS Web Enrollment",
    "ADCSESC9": "Template skips identity verification",
    "ADCSESC10": "Template uses SChannel without verification",
    "ADCSESC11": "NTLM relay to ICPR endpoint",
    "ADCSESC13": "Template with abusable issuance policy OID",
    "ADCSESC14": "Template with mappable altSecurityIdentities",
    "ADCSESC15": "Template with wildcard EKU and editable SAN",
    "ADCSESC16": "Weak permissions allow template takeover",
}


def describe_esc9_derived_edge(
    from_label: str | None,
    notes: dict | None,
    *,
    relation: str = "ADCSESC9",
) -> str:
    """Return a sentence-form description for a derived ESC9/10 edge.

    When ``notes.vulnerable_resources`` contains a puppet entry (``role=puppet``),
    the description names the puppet account so the operator knows which user
    to target. When no puppet is present (old workspace or unexploitable edge),
    falls back to the generic translation.

    Args:
        from_label: The writer principal (e.g. ``"missandei@essos.local"``).
        notes: The ``notes`` dict from the attack-graph edge.
        relation: The raw relation (``"ADCSESC9"`` or ``"ADCSESC10"``).

    Returns:
        An English description suitable for CLI and report surfaces.
    """
    writer = str(from_label or "").strip()
    if "@" in writer:
        writer = writer.split("@", 1)[0]
    writer = writer or "attacker"

    resources = (notes or {}).get("vulnerable_resources") or []
    puppet_names = [
        str(r.get("name") or "").split("@", 1)[0].strip()
        for r in resources
        if isinstance(r, dict)
        and str(r.get("role") or "").lower() == "puppet"
        and str(r.get("name") or "").strip()
    ]

    rel_upper = relation.upper()
    generic = _ADCS_ESC_NAMES.get(rel_upper, "AD CS identity-verification bypass")

    if not puppet_names:
        return f"{generic} ({rel_upper})"

    puppet_str = (
        puppet_names[0] if len(puppet_names) == 1 else puppet_names[0] + " (and others)"
    )
    return (
        f"{writer} can impersonate Domain Admins via {rel_upper} "
        f"by abusing {puppet_str} as a puppet account. ({generic})"
    )


def translate_edge(raw: str | None, *, fallback_to_raw: bool = True) -> str:
    """Return the business-language translation of one BloodHound edge label.

    Args:
        raw: The raw BloodHound edge label (e.g. ``"GenericAll"``,
            ``"DCSync"``, ``"ADCSESC1"``).
        fallback_to_raw: When ``True`` (the default), return the raw
            label when no translation is registered. When ``False``,
            return an empty string for unknown edges.

    Returns:
        The English business-language translation, or — for ADCS ESCs —
        a translation that includes both the human description and the
        technique identifier in parentheses for traceability.
    """
    canonical = (raw or "").strip()
    if not canonical:
        return ""

    direct = _EDGE_TRANSLATIONS.get(canonical)
    if direct is not None:
        return direct

    upper = canonical.upper()
    if upper.startswith(_ADCS_ESC_PATTERN):
        esc_name = _ADCS_ESC_NAMES.get(upper)
        if esc_name is not None:
            return f"{esc_name} ({upper})"
        return f"AD CS certificate template abuse ({upper})"

    return canonical if fallback_to_raw else ""


def has_translation(raw: str | None) -> bool:
    """Return True when a non-fallback translation exists for ``raw``."""
    canonical = (raw or "").strip()
    if not canonical:
        return False
    if canonical in _EDGE_TRANSLATIONS:
        return True
    return canonical.upper().startswith(_ADCS_ESC_PATTERN)


def all_translations() -> dict[str, str]:
    """Return a copy of the translation table for inspection or export.

    Used by the TypeScript port script and by tests that assert parity
    between the Python and TypeScript translation tables.
    """
    return dict(_EDGE_TRANSLATIONS)
