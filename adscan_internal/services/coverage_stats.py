"""Single source of truth for ADscan coverage headline figures.

This module computes the canonical counts that describe ADscan's coverage — the
number of Active Directory attack techniques, the number of reported finding
types, and the ADCS ESC class span — directly from the live product catalogs.
Every surface that quotes these numbers (the public README, the marketing site,
the coverage-matrix PDF, the docs) must derive them from here so they can never
drift apart.

Design notes:
- Like ``attack_step_catalog``, this module has **no top-level dependency on the
  ``pro`` package**. ``ATTACK_STEP_CATALOG`` is a shared service with no ``pro``
  imports; ``VULN_CATALOG`` lives under ``pro`` and is imported lazily inside
  :func:`build_technique_stats` so the module stays importable in contexts where
  ``pro`` is not needed.
- The exclusion rule (``context`` category entries are attack-graph plumbing, not
  customer-facing techniques) is defined ONCE here as ``STEP_CATEGORY_EXCLUDE``
  and re-used by ``scripts/export_coverage_matrix.py``.
"""

from __future__ import annotations

import re
from typing import Any

from adscan_internal.services.attack_step_catalog import ATTACK_STEP_CATALOG

# ``context`` entries are pure attack-graph pivots (membership / credential-reuse
# plumbing), not a detect/exploit technique a customer sees as coverage. This is
# the single definition of the exclusion rule; other modules import it from here.
STEP_CATEGORY_EXCLUDE = {"context"}

# ESC keys look like ``adcsesc1`` … ``adcsesc16a`` — pull the leading integer.
_ESC_KEY_PREFIX = "adcsesc"


def _adcs_esc_numbers(step_catalog: dict[str, Any]) -> list[int]:
    """Return the sorted, de-duplicated ESC class numbers present in the catalog.

    ADCS templates are catalog keys of the form ``adcsesc<N>[<variant>]``
    (e.g. ``adcsesc1``, ``adcsesc6a``). Variants collapse to their integer class.
    """
    numbers: set[int] = set()
    for key, entry in step_catalog.items():
        if getattr(entry, "category", None) in STEP_CATEGORY_EXCLUDE:
            continue
        if not key.startswith(_ESC_KEY_PREFIX):
            continue
        m = re.match(r"(\d+)", key[len(_ESC_KEY_PREFIX):])
        if m:
            numbers.add(int(m.group(1)))
    return sorted(numbers)


def _adcs_esc_span(step_catalog: dict[str, Any]) -> str:
    """Compute the ADCS ESC span string (e.g. ``ESC1–ESC17``) from the catalog.

    The span is ``ESC<min>–ESC<max>`` using an en-dash, matching the register the
    site and reports already use. Empty string when no ESC techniques exist.
    """
    numbers = _adcs_esc_numbers(step_catalog)
    if not numbers:
        return ""
    return f"ESC{numbers[0]}–ESC{numbers[-1]}"


# Human-facing labels for the catalog's internal category keys. Only the keys
# that do not read well when title-cased need an entry; ``_category_label``
# falls back to a title-cased key for anything missing, so a new category never
# breaks generation — it just renders less prettily until it is added here.
CATEGORY_LABELS: dict[str, str] = {
    "acl_ace": "ACL / ACE Abuse",
    "adcs": "AD CS — Certificate Services",
    "coercion": "Authentication Coercion",
    "collection": "Collection",
    "credential_access": "Credential Access",
    "cve": "Known CVEs",
    "delegation": "Delegation Abuse",
    "entry_vector": "Initial Access",
    "execution": "Execution",
    "kerberos": "Kerberos Attacks",
    "lateral_movement": "Lateral Movement",
    "ntlm": "NTLM Weaknesses",
    "ntlm_relay": "NTLM Relay",
    "privilege": "Privilege Escalation",
    "trust": "Trust Abuse",
}

# Short display names for catalog relations whose key does not title-case into
# something a reader recognises. Anything absent falls back to the title-cased
# key, so this map only has to grow when a new relation reads badly.
DISPLAY_NAME_OVERRIDES: dict[str, str] = {
    "kerberoasting": "Kerberoasting",
    "addmember": "Add Member to Group",
    "addself": "Add Self to Group",
    "domainpassreuse": "Domain Password Reuse",
    "localcredtodomainreuse": "Local-to-Domain Credential Reuse",
    "addkeycredentiallink": "Shadow Credentials (Key Credential Link)",
    "adminto": "Local Admin Rights",
    "allextendedrights": "All Extended Rights",
    "allowedtoact": "Resource-Based Constrained Delegation (inbound)",
    "allowedtodelegate": "Constrained Delegation",
    # ESC5's public name is the ACL weakness, not the MITRE technique title
    # (T1649 belongs in the MITRE field). The exploitation ADscan carries for it
    # is CA-object takeover → CA private-key theft → offline certificate forgery.
    "adcsesc5": "AD CS ESC5 — Vulnerable PKI Object Access Control",
    "asreproasting": "AS-REP Roasting",
    "backupoperatorescalation": "Backup Operators Escalation",
    "blankpassword": "Blank Password",
    "canpsremote": "PowerShell Remoting Access",
    "canrdp": "RDP Access",
    "coerceandrelayntlmtoadcs": "Coerce and Relay NTLM to AD CS (ESC8)",
    "coercetotgt": "Coercion to TGT (Unconstrained Delegation)",
    "computerpre2k": "Pre-Windows 2000 Computer Account",
    "crackntlmv1": "NetNTLMv1 Offline Recovery",
    "dcsync": "DCSync",
    "dfscoerce": "DFSCoerce",
    "dnsadminabuse": "DnsAdmins Abuse",
    "dumpdpapi": "DPAPI Secret Extraction",
    "dumplsa": "LSA Secrets Extraction",
    "dumplsass": "LSASS Credential Extraction",
    "executedcom": "DCOM Execution",
    "extractrodckrbtgtsecret": "RODC krbtgt Secret Extraction",
    "forcechangepassword": "Force Change Password",
    "forgerodcgoldenticket": "RODC Golden Ticket",
    "fullcontrolshare": "Full Control Share",
    "genericall": "GenericAll",
    "genericwrite": "GenericWrite",
    "getchanges": "DS-Replication-Get-Changes",
    "getchangesall": "DS-Replication-Get-Changes-All",
    "getchangesinfilteredset": "DS-Replication-Get-Changes-In-Filtered-Set",
    "gpppassword": "Group Policy Preferences Password",
    "guestsession": "Guest Session",
    "hasshadowcredentials": "Shadow Credentials Present",
    "hassession": "Privileged Session Abuse",
    "kerberoskeylist": "Kerberos Key List (RODC)",
    "ldapanonymousbind": "Anonymous LDAP Bind",
    "localadminpassreuse": "Local Admin Password Reuse",
    "managerodcprp": "RODC Password Replication Policy Control",
    "memberof": "Group Membership",
    "ms17-010": "MS17-010 (EternalBlue)",
    "mseven": "MS14-068 / Kerberos PAC Forgery",
    "mssql_impersonate_login": "MSSQL Login Impersonation",
    "mssql_linked_server_lateral": "MSSQL Linked Server Lateral Movement",
    "mssql_ntlmv2_theft": "MSSQL NetNTLMv2 Theft",
    "mssql_openrowset_bulk_read": "MSSQL OPENROWSET Bulk Read",
    "mssql_seimpersonate_escalation": "MSSQL SeImpersonate Escalation",
    "mssql_token_theft_escalation": "MSSQL Token Theft Escalation",
    "mssql_trustworthy_db_escalation": "MSSQL TRUSTWORTHY Database Escalation",
    "nopac": "noPac (CVE-2021-42278/42287)",
    "ntlmv1enabled": "NetNTLMv1 Enabled",
    "ntlmv1relayrbcd": "NetNTLMv1 Relay to RBCD",
    "ntlmv1relayshadowcreds": "NetNTLMv1 Relay to Shadow Credentials",
    "owns": "Object Ownership",
    "passwordinfile": "Password in File",
    "passwordinshare": "Password in Share",
    "passwordspray": "Password Spraying",
    "petitpotam": "PetitPotam",
    "poisoncapturentlmv2crack": "LLMNR/NBT-NS Poisoning and NetNTLMv2 Recovery",
    "preparerodccredentialcaching": "RODC Credential Caching",
    "printerbug": "PrinterBug (MS-RPRN)",
    "printnightmare": "PrintNightmare",
    "printoperatorabuse": "Print Operators Abuse",
    "privilegedgroupcontrol": "Privileged Group Control",
    "readgmsapassword": "Read gMSA Password",
    "crossorgtgtdelegation": "Cross-Forest TGT Delegation",
    "raisechild": "Child-to-Forest-Root Escalation",
    "readlapspassword": "Read LAPS Password",
    "readshare": "Readable Share",
    "scheduledtask": "Scheduled Task Execution",
    "spnjack": "SPN-Jacking",
    "sqlaccess": "MSSQL Access",
    "sqladmin": "MSSQL Sysadmin",
    "synclapspassword": "Sync LAPS Password",
    "timeroasting": "Timeroasting",
    "useraspass": "Username as Password",
    "userdescription": "Credentials in User Description",
    "writeaccountrestrictions": "Write Account Restrictions",
    "writedacl": "WriteDACL",
    "writelogonscript": "Write Logon Script",
    "writeowner": "WriteOwner",
    "writeshare": "Writable Share",
    "writesmbpath": "Writable SMB Path",
    "writespn": "Write SPN",
    "xp_cmdshell": "xp_cmdshell Execution",
    "zerologon": "Zerologon (CVE-2020-1472)",
}

# How ``support_kind`` is presented to a reader. ADscan's Exposure-Validation
# doctrine requires these to stay honest: "Executed" means ADscan runs the
# technique end to end; "Detected" means it is identified and mapped but not
# executed; the safety label states that ADscan deliberately refuses to run a
# destructive technique. Never relabel a non-execution as a defensive block.
SUPPORT_KIND_LABELS: dict[str, str] = {
    "supported": "Executed",
    "unsupported": "Detected",
    "policy_blocked": "Detected · not executed (safety)",
    # A condition or pivot ADscan observes and chains into an attack path
    # (credential reuse, NTLMv1 enabled, a writable staging path) rather than a
    # standalone step it runs. "Observed" keeps that distinct from "Detected",
    # which implies a discrete technique that was identified but not executed.
    "context": "Observed (attack-path pivot)",
}


def _category_label(category: str) -> str:
    return CATEGORY_LABELS.get(category, category.replace("_", " ").title())


def _display_name(relation: str) -> str:
    """Reader-facing name for a catalog relation key.

    Order: explicit override, then the ``adcsesc<N>[<variant>]`` family rule (18
    keys that would otherwise render as ``Adcsesc1``), then a title-cased key.
    """
    override = DISPLAY_NAME_OVERRIDES.get(relation)
    if override:
        return override
    esc = re.fullmatch(rf"{_ESC_KEY_PREFIX}(\d+)([a-z]?)", relation)
    if esc:
        variant = esc.group(2).upper()
        return f"AD CS ESC{esc.group(1)}{variant}"
    return relation.replace("_", " ").title()


def build_technique_inventory() -> list[dict[str, Any]]:
    """Return one row per customer-facing technique, for generated coverage docs.

    Applies exactly the same ``STEP_CATEGORY_EXCLUDE`` rule as
    :func:`build_technique_stats`, so the published list and the published count
    are computed from one filter and can never disagree. A unit test locks that
    invariant (``len(inventory) == technique_count``).

    Returns:
        Rows sorted by category label then display name, each containing the
        catalog ``relation`` key, a human ``display_name``, the raw ``category``
        and its ``category_label``, the catalog ``description``, the MITRE
        ATT&CK id/name, the raw ``support_kind`` plus its reader-facing
        ``support_label``, and the linked ``vuln_key`` when the technique maps to
        a reported finding.
    """
    rows: list[dict[str, Any]] = []
    for relation, entry in ATTACK_STEP_CATALOG.items():
        category = getattr(entry, "category", None)
        if not category or category in STEP_CATEGORY_EXCLUDE:
            continue
        support_kind = getattr(entry, "support_kind", None) or ""
        rows.append(
            {
                "relation": relation,
                "display_name": _display_name(relation),
                "category": category,
                "category_label": _category_label(category),
                "description": (getattr(entry, "description", None) or "").strip(),
                "mitre_technique_id": getattr(entry, "mitre_technique_id", None) or "",
                "mitre_technique_name": getattr(entry, "mitre_technique_name", None)
                or "",
                "support_kind": support_kind,
                "support_label": SUPPORT_KIND_LABELS.get(support_kind, "Detected"),
                "vuln_key": getattr(entry, "vuln_key", None) or "",
            }
        )
    rows.sort(key=lambda r: (r["category_label"], r["display_name"]))
    return rows


def build_technique_stats() -> dict[str, Any]:
    """Assemble the canonical coverage figures from the live catalogs.

    Returns:
        A dict with:
          - ``technique_count``: number of attack-step techniques excluding the
            ``context`` category.
          - ``finding_count``: number of reported finding types (``VULN_CATALOG``).
          - ``by_category``: technique count per (non-excluded) category, sorted
            by category name for deterministic output.
          - ``adcs_esc_span``: ``ESC<min>–ESC<max>`` computed from the catalog.
    """
    # Lazy import: keeps the module free of a top-level ``pro`` dependency.
    from adscan_internal.pro.reporting.vuln_catalog import (  # noqa: PLC0415
        VULN_CATALOG,
    )

    by_category: dict[str, int] = {}
    supported_count = 0
    for entry in ATTACK_STEP_CATALOG.values():
        cat = getattr(entry, "category", None)
        if not cat or cat in STEP_CATEGORY_EXCLUDE:
            continue
        by_category[cat] = by_category.get(cat, 0) + 1
        # "supported" = ADscan executes the technique end to end (as opposed to
        # unsupported / policy_blocked, which are detected/mapped but not run).
        # This is the "supported AD techniques" figure the platform pages quote,
        # distinct from the total technique count.
        if getattr(entry, "support_kind", None) == "supported":
            supported_count += 1

    by_category = dict(sorted(by_category.items()))
    technique_count = sum(by_category.values())
    finding_count = len(VULN_CATALOG)
    adcs_esc_span = _adcs_esc_span(ATTACK_STEP_CATALOG)

    return {
        "technique_count": technique_count,
        "supported_technique_count": supported_count,
        "finding_count": finding_count,
        "by_category": by_category,
        "adcs_esc_span": adcs_esc_span,
    }


if __name__ == "__main__":  # pragma: no cover - manual inspection helper
    import json

    print(json.dumps(build_technique_stats(), indent=2, ensure_ascii=False))
