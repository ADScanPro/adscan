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

The technical map is ALSO the name a client reads in the scan-policy editor,
because the check registry builds each technique's title from
``format_relation_label``. A relation with no entry there does not fail, it
renders its own identifier in the table a client reads while deciding what to
authorise against their production directory. So an entry here is client-facing
prose and is bound by the catalog rules (no offensive tool or competitor product
names, no em-dash); Microsoft feature and privilege names are welcome, because
the reader who owns the feature is the one who has to allow it.
``tests/unit/scan_policy/test_check_titles_are_named.py`` fails when a catalog
relation has no name in either map.

Standard library only, so any tier and the appliance backend can import it.
"""

from __future__ import annotations


def _relation_key(relation: str) -> str:
    """The lookup key for a relation token, case- and underscore-insensitive.

    The same technique arrives under two token shapes: the attack-step catalog
    declares the ADscan-native relations with underscores
    (``mssql_token_theft_escalation``), while the BloodHound-derived ones and
    both label maps below are written without them. Folding the underscore out
    means one entry serves both, so a name can never be authored under a key
    the catalog's own token will not reach. That is the defect this normalizer
    exists to prevent: eight SQL Server relations carried a written name that
    nothing ever looked up, and the scan-policy editor fell through to the raw
    identifier in front of a client deciding what to authorise.
    """
    return str(relation).strip().lower().replace("_", "")


#: Technical token per relation, the register the CLI and the scan-policy
#: editor speak. Keys are matched through :func:`_relation_key`, so either
#: token shape resolves. A relation with a recognised public token keeps it
#: (``DumpSAM``, ``HasSession``); an ADscan-native technique with no public
#: token gets the terse noun phrase that names the thing
#: (``OPENROWSET Bulk File Read``). Client-facing, so the catalog prose rules
#: bind these: Microsoft feature and privilege names are welcome, offensive
#: tool and competitor product names are not.
_TECHNICAL_RELATION_LABELS: dict[str, str] = {
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
    "adcsesc12": "ADCS ESC12",
    "adcsesc13": "ADCS ESC13",
    "adcsesc14": "ADCS ESC14",
    "adcsesc15": "ADCS ESC15",
    "adcsesc16": "ADCS ESC16",
    "adcsesc17": "ADCS ESC17",
    "adcsesc10": "ADCS ESC10",
    "adcsesc10a": "ADCS ESC10a",
    "adcsesc10b": "ADCS ESC10b",
    "certighost": "Certighost (AD CS)",
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
    "unconstraineddelegation": "UnconstrainedDelegation",
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
    "backupoperatorescalation": "BackupOperatorEscalation",
    "allextendedrights": "AllExtendedRights",
    "allowedtoact": "AllowedToAct",
    "blankpassword": "BlankPassword",
    "coerceandrelayntlmtoadcs": "CoerceAndRelayNTLMToADCS",
    "computerpre2k": "ComputerPre2k",
    "fullcontrolshare": "FullControlShare",
    "getchangesinfilteredset": "GetChangesInFilteredSet",
    "guestsession": "GuestSession",
    "hasshadowcredentials": "HasShadowCredentials",
    "ms17010": "MS17010",
    # SQL Server. These relations are ADscan-native and have no BloodHound
    # token, so each is named after the SQL Server or Windows feature it turns
    # on: the reader who has to decide whether to allow it is the DBA who owns
    # that feature, and the remediation line names the same knob.
    "mssql_impersonate_login": "SQL Login Impersonation",
    "mssql_linked_server_lateral": "Linked Server Execution",
    "mssql_ntlmv2_theft": "SQL Server Coerced Authentication",
    "mssql_openrowset_bulk_read": "OPENROWSET Bulk File Read",
    "mssql_seimpersonate_escalation": "SeImpersonate Privilege Abuse",
    "mssql_token_theft_escalation": "SQL Service Token Theft",
    "mssql_trustworthy_db_escalation": "Trustworthy Database Escalation",
    "xp_cmdshell": "xp_cmdshell Command Execution",
    "passwordspray": "PasswordSpray",
    "poisoncapturentlmv2crack": "PoisonCaptureNtlmv2Crack",
    "readshare": "ReadShare",
    "spnjack": "SPNJack",
    "synclapspassword": "SyncLAPSPassword",
    "useraspass": "UserAsPass",
    "writeaccountrestrictions": "WriteAccountRestrictions",
    "writeshare": "WriteShare",
    "dnsadminabuse": "DnsAdminAbuse",
    "extractrodckrbtgtsecret": "ExtractRODCKrbtgtSecret",
    "forgerodcgoldenticket": "ForgeRODCGoldenTicket",
    "kerberoskeylist": "KerberosKeyList",
    "preparerodccredentialcaching": "PrepareRODCCredentialCaching",
    "printoperatorabuse": "PrintOperatorAbuse",
    "privilegedgroupcontrol": "PrivilegedGroupControl",
    "dumpsam": "DumpSAM",
    "hassession": "HasSession",
    "scheduledtask": "ScheduledTask",
    "crossorgtgtdelegation": "Cross-Org TGT Delegation",
    "raisechild": "Child Domain Escalation",
}

#: Resolved lookup, keyed through :func:`_relation_key` so a token written with
#: underscores and one written without reach the same entry.
_TECHNICAL_LABELS_BY_KEY: dict[str, str] = {
    _relation_key(token): label for token, label in _TECHNICAL_RELATION_LABELS.items()
}


def format_relation_label(relation: str) -> str:
    """Normalize a relation label into a human-readable title."""
    if not relation:
        return "Step"
    rel = str(relation).strip()
    return _TECHNICAL_LABELS_BY_KEY.get(_relation_key(rel), rel)


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
    "unconstraineddelegation": "Unconstrained Kerberos Delegation",
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
    "mssql_linked_server_lateral": "SQL Server Linked-Server Lateral Movement",
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
    "xp_cmdshell": "Command Execution on the SQL Server Host",
    # Credential-theft roasting ───────────────────────────────────────────
    "kerberoasting": "Service Account Credential Theft",
    "asreproasting": "Pre-Authentication-less Credential Theft",
    "timeroasting": "Computer Account Credential Theft",
    # ADCS certificate-services escalation ────────────────────────────────
    "adcsesc1": "Certificate Template Privilege Escalation",
    "adcsesc2": "Any-Purpose Certificate Template Abuse",
    "adcsesc3": "Certificate Request-Agent Escalation",
    "adcsesc4": "Certificate Template Takeover",
    "adcsesc5": "Certificate Infrastructure Takeover",
    "adcsesc6": "Certificate Authority Accepts Requester-Supplied Names",
    "adcsesc6a": "Certificate Authority Accepts Requester-Supplied Names",
    "adcsesc6b": "Certificate Authority Accepts Requester-Supplied Names",
    "adcsesc7": "Certificate Authority Administration Abuse",
    "adcsesc8": "Credential Relay to Web Certificate Enrollment",
    "adcsesc9": "Certificate Mapping Abuse via a Template Without the SID Extension",
    "adcsesc9a": "Certificate Mapping Abuse via a Template Without the SID Extension",
    "adcsesc9b": "Certificate Mapping Abuse via a Template Without the SID Extension",
    "adcsesc10": "Certificate Mapping Abuse via Weak Domain Controller Mapping Settings",
    "adcsesc10a": "Certificate Mapping Abuse via Weak Domain Controller Mapping Settings",
    "adcsesc10b": "Certificate Mapping Abuse via Weak Domain Controller Mapping Settings",
    "adcsesc11": "Credential Relay to RPC Certificate Enrollment",
    "adcsesc12": "Certificate Authority Key Misuse",
    "adcsesc13": "Certificate-Bound Group Escalation",
    "adcsesc14": "Certificate Mapping Abuse via a Weak Explicit Mapping",
    "adcsesc15": "Certificate Application-Policy Abuse",
    "adcsesc16": "Certificate Mapping Abuse via a CA Without the SID Extension",
    "adcsesc17": "Server Authentication Certificate Abuse",
    "certighost": "Certificate Authority Domain Controller Impersonation",
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
    # Backup-privilege escalation ─────────────────────────────────────────
    "backupoperatorescalation": "Backup Operators Escalation to Domain Secrets",
    # Additional object-control / ACL edges ───────────────────────────────
    "allextendedrights": "Full Extended-Rights Control of the Target Object",
    "allowedtoact": "Resource-Based Constrained Delegation Abuse",
    "getchangesinfilteredset": "Directory Replication Right",
    "hasshadowcredentials": "Shadow Credential Authentication Key",
    "writeaccountrestrictions": "Modify Delegation Settings via Account Restrictions",
    # Share access ─────────────────────────────────────────────────────────
    "readshare": "Read Access to a Network Share",
    "writeshare": "Write Access to a Network Share",
    "fullcontrolshare": "Full Control of a Network Share",
    "guestsession": "Anonymous Guest Session Access",
    # Credential-recovery / weak-secret findings ──────────────────────────
    "blankpassword": "Authentication with a Blank Password",
    "computerpre2k": "Legacy Pre-Windows-2000 Computer Password",
    "useraspass": "Username Used as the Account Password",
    "passwordspray": "Password Spraying Across Many Accounts",
    "poisoncapturentlmv2crack": "Network Authentication Poisoning and Credential Recovery",
    "synclapspassword": "Replicate the Local Administrator Password",
    "spnjack": "Service Principal Name Hijack for Delegation Abuse",
    # Named CVEs / coercion ────────────────────────────────────────────────
    "ms17010": "Remote Code Execution via SMBv1",
    "coerceandrelayntlmtoadcs": "Certificate Enrollment via Coerced Authentication Relay",
    # Privileged-group escalation ──────────────────────────────────────────
    "dnsadminabuse": "DNS Administrators Escalation to Domain Controller Compromise",
    "printoperatorabuse": "Print Operators Escalation to Domain Controller Compromise",
    "privilegedgroupcontrol": "Control of a Privileged Group",
    # RODC credential-theft chain ──────────────────────────────────────────
    "preparerodccredentialcaching": "Read-Only Domain Controller Credential Caching Setup",
    "extractrodckrbtgtsecret": "Read-Only Domain Controller Credential Extraction",
    "forgerodcgoldenticket": "Forged Golden Ticket via a Read-Only Domain Controller",
    "kerberoskeylist": "Kerberos Key List Credential Recovery",
    # MSSQL escalation / lateral movement ──────────────────────────────────
    "mssql_impersonate_login": "SQL Login Impersonation Escalation",
    "mssql_trustworthy_db_escalation": "Privilege Escalation via a Trusted SQL Database",
    "mssql_ntlmv2_theft": "Credential Theft via SQL Server-Coerced Authentication",
    "mssql_seimpersonate_escalation": "Privilege Escalation to SYSTEM via SQL Service Impersonation",
    "mssql_token_theft_escalation": "Privilege Escalation to SYSTEM via SQL Session Token Theft",
    "mssql_openrowset_bulk_read": "Arbitrary File Read via the SQL Server",
}

#: Resolved lookup, keyed exactly like the technical one above.
_BUSINESS_HEADLINES_BY_KEY: dict[str, str] = {
    _relation_key(token): phrase for token, phrase in _BUSINESS_RELATION_HEADLINES.items()
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
    business = _BUSINESS_HEADLINES_BY_KEY.get(_relation_key(relation))
    if not business:
        return technical
    return f"{business} ({technical})"


def business_relation_phrase(relation: str) -> str:
    """Plain-language phrase for a relation, with no parenthetical token.

    Like :func:`format_business_relation_label` but returns ONLY the business
    headline (``"Credentials in a Network Share"``) without the trailing
    ``"(<Token>)"``. Intended for flowing prose — a narrative sentence that
    lists several techniques reads cleanly without a CamelCase slug or a
    parenthetical on each item. When no business phrase is defined, falls back
    to the normalized technical label (``format_relation_label``), which is
    still title-cased and never a raw lowercase slug.
    """
    if not relation:
        return format_relation_label(relation)
    business = _BUSINESS_HEADLINES_BY_KEY.get(_relation_key(relation))
    if business:
        return business
    return format_relation_label(relation)


__all__ = [
    "business_relation_phrase",
    "format_business_relation_label",
    "format_relation_label",
]
