"""Attack-relation label vocabulary — shared by every reporting surface.

Layer 1 of the four-layer reporting split (``CLAUDE.md`` § "Dual-tier
reporting"): the label vocabulary is **shared data**, so the free report, the
paid deliverable and the web CTEM say the same words about the same edge.

Two registers, one data model (the Nomenclature Standard):

``format_relation_label``
    The TECHNICAL token, normalised — ``genericall`` becomes ``GenericAll``.
    What the CLI speaks.
``format_business_relation_label``
    The CLIENT headline — ``"Full Control of the Target Object (GenericAll)"``.
    What the report and the web speak, so a CISO never reads a bare
    BloodHound edge token as a headline.

It lives outside ``adscan_internal/pro`` because a table that translates public
BloodHound edge names into plain English is vocabulary, not product knowledge,
and the LITE image deletes the whole PRO tree — leaving the map there meant the
free report had no way to say "Replicate Directory Secrets" and fell back to
printing ``DCSync:`` at a client. ``pro.reporting.attack_path_narratives``
re-exports both functions, so every existing import keeps resolving.

Standard library only, so any tier and the appliance backend can import it.
"""

from __future__ import annotations


def format_relation_label(relation: str) -> str:
    """Normalize a relation label into a human-readable title."""
    if not relation:
        return "Step"
    rel = str(relation).strip()
    normalized = rel.lower()
    label_map = {
        "asreproasting": "ASREPRoasting",
        "kerberoasting": "Kerberoasting",
        "timeroasting": "Timeroasting",
        "adcsesc1": "ADCS ESC1",
        "adcsesc3": "ADCS ESC3",
        "adcsesc4": "ADCS ESC4",
        "adcsesc5": "ADCS ESC5",
        "adcsesc6": "ADCS ESC6",
        "adcsesc6a": "ADCS ESC6a",
        "adcsesc6b": "ADCS ESC6b",
        "adcsesc7": "ADCS ESC7",
        "adcsesc8": "ADCS ESC8",
        "adcsesc9": "ADCS ESC9",
        "adcsesc9a": "ADCS ESC9a",
        "adcsesc9b": "ADCS ESC9b",
        "adcsesc2": "ADCS ESC2",
        "adcsesc11": "ADCS ESC11",
        "adcsesc13": "ADCS ESC13",
        "adcsesc14": "ADCS ESC14",
        "adcsesc15": "ADCS ESC15",
        "adcsesc16": "ADCS ESC16",
        "adcsesc17": "ADCS ESC17",
        "adcsesc10": "ADCS ESC10",
        "adcsesc10a": "ADCS ESC10a",
        "adcsesc10b": "ADCS ESC10b",
        "zerologon": "Zerologon",
        "nopac": "NoPac",
        "printnightmare": "PrintNightmare",
        "dfscoerce": "DFSCoerce",
        "petitpotam": "PetitPotam",
        "ms17-010": "MS17-010",
        "mseven": "EfsCoerce",
        "printerbug": "PrinterBug",
        "genericall": "GenericAll",
        "genericwrite": "GenericWrite",
        "writedacl": "WriteDACL",
        "writeowner": "WriteOwner",
        "owns": "Owns",
        "forcechangepassword": "ForceChangePassword",
        "addmember": "AddMember",
        "addself": "AddSelf",
        "writespn": "WriteSPN",
        "writelogonscript": "WriteLogonScript",
        "addkeycredentiallink": "AddKeyCredentialLink",
        "readlapspassword": "ReadLAPSPassword",
        "readgmsapassword": "ReadGMSAPassword",
        "allowedtodelegate": "AllowedToDelegate",
        "coercetotgt": "CoerceToTGT",
        "allowedtoactonbehalfofotheridentity": "AllowedToActOnBehalfOfOtherIdentity",
        "adminto": "AdminTo",
        "canrdp": "CanRDP",
        "canpsremote": "CanPSRemote",
        "executedcom": "ExecuteDCOM",
        "dcsync": "DCSync",
        "dumplsa": "DumpLSA",
        "dumpdpapi": "DumpDPAPI",
        "dumplsass": "DumpLSASS",
        "getchanges": "GetChanges",
        "getchangesall": "GetChangesAll",
        "sqladmin": "SQLAdmin",
        "sqlaccess": "SQLAccess",
        "managerodcprp": "ManageRODCPrp",
        "writesmbpath": "WriteSmbPath",
        "memberof": "MemberOf",
        "ldapanonymousbind": "LDAPAnonymousBind",
        "userdescription": "UserDescription",
        "passwordinshare": "PasswordInShare",
        "passwordinfile": "PasswordInFile",
        "gpppassword": "GPPPassword",
        "domainpassreuse": "Domain Pass Reuse",
        "domainpassreusesource": "Domain Pass Reuse Source",
        "localadminpassreuse": "Local Admin Pass Reuse",
        "localcredreusesource": "Local Credential Reuse Source",
        "localcredtodomainreuse": "Local Credential To Domain Reuse",
        "ntlmv1enabled": "NTLMv1 Enabled",
        "ntlmv1relayrbcd": "NTLMv1 Relay → RBCD",
        "ntlmv1relayshadowcreds": "NTLMv1 Relay → Shadow Credentials",
        "crackntlmv1": "NTLMv1 Offline Crack",
    }
    return label_map.get(normalized, rel)


# ── Business-headline map (client report + web) ─────────────────────────────
# Nomenclature Standard: "one canonical data model, two translations". The CLI
# speaks technical (raw BloodHound edge tokens); the client report and web
# dashboard speak business. Rendering a raw ``GENERICALL`` / ``DCSYNC`` /
# ``ADMINTO`` as a client HEADLINE breaks that rule — a CISO reads it as jargon.
#
# This map is the single source of truth for the BUSINESS phrase of each edge.
# ``format_business_relation_label`` pairs it with the canonical technical token
# in parentheses (e.g. "Replicate Directory Secrets (DCSync)"), so the executive
# reader gets plain-language impact while the technical reader still sees the
# exact edge. The technical ``format_relation_label`` above is NOT removed — the
# CLI keeps using it; this is the report/web translation only.
#
# Keys mirror the normalized (lowercase) relation tokens of ``format_relation_label``.
_BUSINESS_RELATION_HEADLINES: dict[str, str] = {
    # Object-control edges (ACL abuse) ────────────────────────────────────
    "genericall": "Full Control of the Target Object",
    "genericwrite": "Modify the Target Object",
    "writedacl": "Rewrite Object Permissions",
    "writeowner": "Seize Object Ownership",
    "owns": "Object Ownership",
    "forcechangepassword": "Reset the Account Password",
    "addmember": "Add a Member to the Group",
    "addself": "Add Self to the Group",
    "writespn": "Set a Service Principal Name",
    "writelogonscript": "Set the Account Logon Script",
    "addkeycredentiallink": "Add Shadow Credentials",
    "readlapspassword": "Read the Local Administrator Password",
    "readgmsapassword": "Read the Managed Service Account Password",
    "allowedtodelegate": "Constrained Delegation Abuse",
    "coercetotgt": "Coerce Authentication to a Ticket",
    "allowedtoactonbehalfofotheridentity": "Resource-Based Delegation Abuse",
    # Access / lateral-movement edges ─────────────────────────────────────
    "adminto": "Local Administrator Access",
    "canrdp": "Remote Desktop Access",
    "canpsremote": "Remote PowerShell Access",
    "executedcom": "Remote DCOM Execution",
    "sqladmin": "Database Administrator Access",
    "sqlaccess": "Database Session Access",
    "writesmbpath": "Write Access to a Network Share",
    "hassession": "Abuse a Logged-On User Session",
    "mssqllinkedserverlateral": "SQL Server Linked-Server Lateral Movement",
    # Membership / structural ─────────────────────────────────────────────
    "memberof": "Group Membership",
    "managerodcprp": "Read-Only Domain Controller Replication Control",
    # Credential access / post-exploitation ───────────────────────────────
    "dcsync": "Replicate Directory Secrets",
    "dumplsa": "Extract LSA Secrets",
    "dumpdpapi": "Extract Stored Credentials",
    "dumplsass": "Extract Credentials from Memory",
    "dumpsam": "Extract Local Account Hashes",
    "getchanges": "Directory Replication Right",
    "getchangesall": "Directory Replication Right",
    "scheduledtask": "Session User Impersonation via Scheduled Task",
    "xpcmdshell": "Command Execution on the SQL Server Host",
    # Credential-theft roasting ───────────────────────────────────────────
    "kerberoasting": "Service Account Credential Theft",
    "asreproasting": "Pre-Authentication-less Credential Theft",
    "timeroasting": "Computer Account Credential Theft",
    # ADCS certificate-services escalation ────────────────────────────────
    "adcsesc1": "Certificate Template Privilege Escalation",
    "adcsesc2": "Certificate Services Privilege Escalation",
    "adcsesc3": "Certificate Request-Agent Escalation",
    "adcsesc4": "Certificate Template Takeover",
    "adcsesc5": "Certificate Infrastructure Takeover",
    "adcsesc6": "Certificate Authority Misconfiguration Abuse",
    "adcsesc6a": "Certificate Authority Misconfiguration Abuse",
    "adcsesc6b": "Certificate Authority Misconfiguration Abuse",
    "adcsesc7": "Certificate Authority Administration Abuse",
    "adcsesc8": "Certificate Enrollment Relay",
    "adcsesc9": "Certificate Mapping Abuse",
    "adcsesc9a": "Certificate Mapping Abuse",
    "adcsesc9b": "Certificate Mapping Abuse",
    "adcsesc10": "Certificate Mapping Abuse",
    "adcsesc10a": "Certificate Mapping Abuse",
    "adcsesc10b": "Certificate Mapping Abuse",
    "adcsesc11": "Certificate Enrollment Relay",
    "adcsesc13": "Certificate-Bound Group Escalation",
    "adcsesc14": "Certificate Mapping Abuse",
    "adcsesc15": "Certificate Application-Policy Abuse",
    "adcsesc16": "Certificate Extension Abuse",
    "adcsesc17": "Certificate Services Privilege Escalation",
    # Named CVEs / coercion ───────────────────────────────────────────────
    "zerologon": "Domain Controller Takeover",
    "nopac": "Kerberos Privilege Escalation",
    "printnightmare": "Remote Code Execution via Print Spooler",
    "dfscoerce": "Authentication Coercion",
    "petitpotam": "Authentication Coercion",
    "printerbug": "Authentication Coercion",
    "mseven": "Authentication Coercion",
    "ms17-010": "Remote Code Execution via SMBv1",
    # Findings / credential exposure ──────────────────────────────────────
    "ldapanonymousbind": "Anonymous Directory Access",
    "userdescription": "Credentials in an Account Description",
    "passwordinshare": "Credentials in a Network Share",
    "passwordinfile": "Credentials in a File",
    "gpppassword": "Password in Group Policy Preferences",
    "domainpassreuse": "Domain Password Reuse",
    "domainpassreusesource": "Domain Password Reuse Source",
    "localadminpassreuse": "Local Administrator Password Reuse",
    "localcredreusesource": "Local Credential Reuse Source",
    "localcredtodomainreuse": "Local-to-Domain Credential Reuse",
    "ntlmv1enabled": "Legacy NTLMv1 Authentication Allowed",
    "ntlmv1relayrbcd": "Credential Relay to Delegation",
    "ntlmv1relayshadowcreds": "Credential Relay to Shadow Credentials",
    "crackntlmv1": "Offline NTLMv1 Credential Recovery",
    # Trust abuse ──────────────────────────────────────────────────────────
    "crossorgtgtdelegation": "Cross-Forest Kerberos Ticket Delegation",
    "raisechild": "Child-to-Forest-Root Escalation",
}


def format_business_relation_label(relation: str) -> str:
    """Business-facing headline for a relation/edge (client report + web).

    Returns ``"<business phrase> (<technical token>)"`` so an executive reader
    gets the plain-language impact while the technical reader still sees the
    canonical BloodHound edge token — the Nomenclature Standard's "one data
    model, two translations". When no business phrase is defined for the
    relation, falls back to the technical label (``format_relation_label``).

    This is the report/web translation ONLY; the CLI keeps using
    ``format_relation_label``.
    """
    technical = format_relation_label(relation)
    if not relation:
        return technical
    business = _BUSINESS_RELATION_HEADLINES.get(str(relation).strip().lower())
    if not business:
        return technical
    return f"{business} ({technical})"


__all__ = [
    "format_business_relation_label",
    "format_relation_label",
]
