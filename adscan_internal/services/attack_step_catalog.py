"""Canonical attack-step catalog.

This module centralizes known attack-step relations and their metadata so the CLI,
graph services, and reporting layers can share one source of truth.

Scope:
- Execution support classification (supported, unsupported, policy_blocked, context)
- Human-readable relation notes for UX
- Optional CTEM vulnerability key mapping for exploitation-style relations
- Remediation complexity, effort, and full-mitigation flag per step
- MITRE ATT&CK technique mapping per step
- Windows Event IDs for SOC detection per step
- BloodHound CE native edge flag and Cypher type names

remediation_complexity values:
  low        – Single GPO/registry/ACL change, minimal testing required.
  medium     – Configuration change requiring planning and testing; possible service impact.
  high       – Significant infrastructure change or architectural limitation; operational risk.
  very_high  – Requires architecture overhaul, PKI rebuild, or has persistent attacker capability.

can_fully_mitigate:
  True   – The step can be fully eliminated from attack paths.
  False  – The step is architecturally inherent to Windows AD (e.g., unconstrained delegation
           on DCs); the risk can only be reduced, not eliminated.

bh_native / bh_cypher_names:
  bh_native=True means the edge exists natively in BloodHound CE's graph (added by its
  collectors). Such edges are NOT uploaded via OpenGraph — they are already present.
  bh_cypher_names lists the exact PascalCase Cypher relationship type(s) used in BH CE
  queries. Some catalog entries map to multiple BH CE variants (e.g. ADCSESC6a/6b).
  ADscan-custom relations (LocalAdminPassReuse, Timeroasting, DumpLSA, etc.) have
  bh_native=False and are NOT included in BH CE Cypher queries.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any, Literal


SupportKind = Literal["supported", "unsupported", "policy_blocked", "context"]
ExecutionTargetAccessRequirement = Literal["none", "computer_reachable"]
CompromiseSemantics = Literal[
    "direct_target_compromise",
    "access_capability_only",
    "context_only",
    "other",
]
CompromiseEffort = Literal[
    "none",
    "immediate",
    "low",
    "medium",
    "high",
    "other",
]

_COMPLEXITY_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "very_high": 3}


@dataclass(frozen=True, slots=True)
class AttackStepCatalogEntry:
    """Definition for one attack-step relation."""

    relation: str
    support_kind: SupportKind
    support_reason: str
    compromise_semantics: CompromiseSemantics
    compromise_effort: CompromiseEffort
    category: str
    description: str
    vuln_key: str | None = None
    remediation_complexity: str = "medium"  # low | medium | high | very_high
    remediation_effort: str = ""
    can_fully_mitigate: bool = True
    mitre_technique_id: str | None = None  # e.g. "T1558.003"
    mitre_technique_name: str | None = (
        None  # e.g. "Steal or Forge Kerberos Tickets: Kerberoasting"
    )
    detection_event_ids: tuple[str, ...] = ()  # Windows Event IDs for SOC detection
    bh_native: bool = False  # True = edge exists natively in BloodHound CE's graph
    bh_cypher_names: tuple[
        str, ...
    ] = ()  # Cypher relationship type(s) for BH CE queries
    is_acl_edge: bool = False  # True = ACL/ACE-derived object-control or extended-right edge
    execution_relation_alias: str | None = None  # canonical execution-family relation
    requires_execution_context: bool = False
    counts_for_execution_readiness: bool = False
    execution_target_access_requirement: ExecutionTargetAccessRequirement = "none"
    # BloodHound-style narrative templates with placeholders.
    # Placeholders resolved at render time by render_step_narrative():
    #   {source}      — display name of source principal
    #   {target}      — display name of target principal
    #   {source_type} — "user" | "computer" | "group" | "domain" | "service account"
    #   {target_type} — same, for the destination
    #   {template}    — ADCS template name (if applicable; "" otherwise)
    #   {relation}    — human-formatted relation label (e.g. "Kerberoasting")
    # Long form: used in attack-path narratives section of the report.
    narrative_template: str = ""
    # Short form: one-liner used in cards / chips / tooltips (web + PDF).
    short_narrative_template: str = ""
    # Structured remediation steps (ordered). Each string may also contain
    # the same placeholder set as narrative_template.
    remediation_steps: tuple[str, ...] = ()


def _entry(
    relation: str,
    *,
    support_kind: SupportKind,
    support_reason: str,
    compromise_semantics: CompromiseSemantics = "other",
    compromise_effort: CompromiseEffort = "other",
    category: str,
    description: str,
    vuln_key: str | None = None,
    remediation_complexity: str = "medium",
    remediation_effort: str = "",
    can_fully_mitigate: bool = True,
    mitre_technique_id: str | None = None,
    mitre_technique_name: str | None = None,
    detection_event_ids: tuple[str, ...] = (),
    bh_native: bool = False,
    bh_cypher_names: tuple[str, ...] = (),
    is_acl_edge: bool = False,
    execution_relation_alias: str | None = None,
    requires_execution_context: bool = False,
    counts_for_execution_readiness: bool = False,
    execution_target_access_requirement: ExecutionTargetAccessRequirement = "none",
    narrative_template: str = "",
    short_narrative_template: str = "",
    remediation_steps: tuple[str, ...] = (),
) -> AttackStepCatalogEntry:
    """Build a normalized catalog entry."""
    return AttackStepCatalogEntry(
        relation=str(relation or "").strip().lower(),
        support_kind=support_kind,
        support_reason=support_reason,
        compromise_semantics=compromise_semantics,
        compromise_effort=compromise_effort,
        category=category,
        description=description,
        vuln_key=vuln_key,
        remediation_complexity=remediation_complexity,
        remediation_effort=remediation_effort,
        can_fully_mitigate=can_fully_mitigate,
        mitre_technique_id=mitre_technique_id,
        mitre_technique_name=mitre_technique_name,
        detection_event_ids=detection_event_ids,
        bh_native=bh_native,
        bh_cypher_names=bh_cypher_names,
        is_acl_edge=is_acl_edge,
        execution_relation_alias=(
            str(execution_relation_alias or "").strip().lower() or None
        ),
        requires_execution_context=requires_execution_context,
        counts_for_execution_readiness=counts_for_execution_readiness,
        execution_target_access_requirement=execution_target_access_requirement,
        narrative_template=narrative_template.strip(),
        short_narrative_template=short_narrative_template.strip(),
        remediation_steps=tuple(remediation_steps),
    )


_CATALOG_ENTRIES: tuple[AttackStepCatalogEntry, ...] = (
    # ── Context / expansion ─────────────────────────────────────────────────
    _entry(
        "memberof",
        support_kind="context",
        support_reason="Context only (membership expansion); not executed",
        compromise_semantics="context_only",
        compromise_effort="none",
        category="context",
        description="Group membership pivot used for path expansion",
        remediation_complexity="low",
        remediation_effort="Remove the user/group from the over-privileged group.",
        can_fully_mitigate=True,
        # No MITRE — pure graph context node, not an attack technique
        bh_native=True,
        bh_cypher_names=("MemberOf",),
    ),
    _entry(
        "privilegedgroupcontrol",
        support_kind="unsupported",
        support_reason="Membership-derived direct control outcome; no separate execution step",
        compromise_semantics="direct_target_compromise",
        compromise_effort="immediate",
        category="privilege",
        description="Direct control achieved through membership in a terminal privileged group",
        remediation_complexity="low",
        remediation_effort="Remove the principal from the privileged control group.",
        can_fully_mitigate=True,
    ),
    _entry(
        "backupoperatorescalation",
        support_kind="unsupported",
        support_reason="Backup Operators follow-up is modeled but not executed automatically yet",
        compromise_semantics="direct_target_compromise",
        compromise_effort="medium",
        category="privilege",
        description="Potential domain compromise path via Backup Operators follow-up abuse",
        remediation_complexity="medium",
        remediation_effort="Remove unnecessary membership from Backup Operators and constrain backup privileges.",
        can_fully_mitigate=True,
    ),
    _entry(
        "printoperatorabuse",
        support_kind="unsupported",
        support_reason="Print Operators follow-up is modeled but not executed automatically yet",
        compromise_semantics="access_capability_only",
        compromise_effort="medium",
        category="privilege",
        description="Potential escalation path unlocked by Print Operators membership",
        remediation_complexity="medium",
        remediation_effort="Remove unnecessary membership from Print Operators and restrict DC local execution paths.",
        can_fully_mitigate=True,
    ),
    _entry(
        "dnsadminabuse",
        support_kind="policy_blocked",
        support_reason="DNSAdmins abuse is intentionally blocked in production-safe execution mode",
        compromise_semantics="direct_target_compromise",
        compromise_effort="medium",
        category="privilege",
        description="Potential domain compromise path via DNSAdmins abuse",
        remediation_complexity="medium",
        remediation_effort="Remove unnecessary DNSAdmins membership and harden DNS administration workflows.",
        can_fully_mitigate=True,
    ),
    _entry(
        "preparerodccredentialcaching",
        support_kind="supported",
        support_reason="RODC PRP preparation is supported through the dedicated RODC follow-up workflow",
        compromise_semantics="access_capability_only",
        compromise_effort="high",
        category="privilege",
        description="Prepare RODC credential caching by modifying the RODC password-replication policy",
        remediation_complexity="high",
        remediation_effort="Remove unnecessary RODC PRP delegation and review all principals allowed to modify RODC password-replication policy.",
        can_fully_mitigate=True,
    ),
    _entry(
        "extractrodckrbtgtsecret",
        support_kind="supported",
        support_reason="RODC per-krbtgt extraction is supported through the dedicated follow-up workflow",
        compromise_semantics="credential_access_only",
        compromise_effort="high",
        category="credential_access",
        description="Extract the per-RODC krbtgt secret from the compromised RODC",
        remediation_complexity="high",
        remediation_effort="Prevent unauthorized RODC host access and monitor RODC memory/LSA extraction activity closely.",
        can_fully_mitigate=False,
    ),
    _entry(
        "forgerodcgoldenticket",
        support_kind="supported",
        support_reason="RODC golden ticket forging is supported once per-RODC krbtgt material exists",
        compromise_semantics="credential_access_only",
        compromise_effort="high",
        category="kerberos",
        description="Forge a reusable RODC golden ticket from recovered per-RODC krbtgt material",
        remediation_complexity="high",
        remediation_effort="Rotate affected per-RODC krbtgt material and investigate unauthorized Kerberos ticket creation.",
        can_fully_mitigate=False,
    ),
    _entry(
        "kerberoskeylist",
        support_kind="supported",
        support_reason="Kerberos Key List is supported when AES material is available for the per-RODC krbtgt account",
        compromise_semantics="direct_target_compromise",
        compromise_effort="high",
        category="kerberos",
        description="Use the forged RODC golden ticket to request Key List data from a writable domain controller",
        remediation_complexity="high",
        remediation_effort="Review and reset replicated target credentials, rotate per-RODC krbtgt material, and investigate Key List abuse activity.",
        can_fully_mitigate=False,
    ),
    _entry(
        "localadminpassreuse",
        support_kind="context",
        support_reason="Observed local admin password reuse pivot; no direct execution step",
        compromise_semantics="context_only",
        compromise_effort="none",
        category="lateral_movement",
        description="Credential reuse pivot between hosts sharing local admin credentials",
        remediation_complexity="medium",
        remediation_effort=(
            "Deploy LAPS to ensure unique local administrator passwords on every machine. "
            "Rotate local admin credentials on all affected hosts immediately."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1078.003",
        mitre_technique_name="Valid Accounts: Local Accounts",
        detection_event_ids=("4624", "4648"),
        bh_cypher_names=("LocalAdminPassReuse",),
    ),
    _entry(
        "localcredreusesource",
        support_kind="context",
        support_reason="Observed host where the reused local credential was recovered",
        compromise_semantics="context_only",
        compromise_effort="none",
        category="context",
        description="Host-to-credential-cluster context edge used for SAM reuse correlation",
        remediation_complexity="medium",
        remediation_effort=(
            "Prevent credential extraction from endpoints by hardening local admin usage, "
            "deploying EDR protections, and reducing local admin privileges."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1003.002",
        mitre_technique_name="OS Credential Dumping: Security Account Manager",
        detection_event_ids=("4688", "4656"),
        bh_cypher_names=("LocalCredReuseSource",),
    ),
    _entry(
        "localcredtodomainreuse",
        support_kind="context",
        support_reason="Observed local credential reused successfully against domain account(s)",
        compromise_semantics="context_only",
        compromise_effort="none",
        category="credential_access",
        description="Credential reuse pivot from local credential material to domain identity",
        remediation_complexity="medium",
        remediation_effort=(
            "Eliminate shared credential patterns between local and domain accounts. "
            "Enforce unique strong passwords and rotate exposed credentials."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1078.002",
        mitre_technique_name="Valid Accounts: Domain Accounts",
        detection_event_ids=("4624", "4648", "4768", "4769"),
        bh_cypher_names=("LocalCredToDomainReuse",),
    ),
    _entry(
        "domainpassreusesource",
        support_kind="context",
        support_reason="Observed source user participating in a reused domain password cluster",
        compromise_semantics="context_only",
        compromise_effort="none",
        category="context",
        description="Source principal for password/hash reuse between domain users",
        remediation_complexity="medium",
        remediation_effort=(
            "Eliminate password reuse between domain accounts and enforce unique secrets per identity."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1078.002",
        mitre_technique_name="Valid Accounts: Domain Accounts",
        detection_event_ids=("4624", "4768", "4769"),
        bh_cypher_names=("DomainPassReuseSource",),
    ),
    _entry(
        "domainpassreuse",
        support_kind="context",
        support_reason="Observed domain users sharing the same password/hash material",
        compromise_semantics="context_only",
        compromise_effort="none",
        category="credential_access",
        description="Domain account credential reuse pivot through clustered shared secret material",
        remediation_complexity="medium",
        remediation_effort=(
            "Enforce unique random passwords for every domain user and rotate all accounts in the reuse cluster."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1078.002",
        mitre_technique_name="Valid Accounts: Domain Accounts",
        detection_event_ids=("4624", "4648", "4768", "4769"),
        bh_cypher_names=("DomainPassReuse",),
    ),
    _entry(
        "hassession",
        support_kind="supported",
        support_reason="Executable via schtask_as session abuse workflow",
        category="privilege",
        description=(
            "High-value user session observed on a non-Tier-0 computer that can be "
            "abused for scheduled-task impersonation"
        ),
        vuln_key="da_sessions",
        remediation_complexity="medium",
        remediation_effort=(
            "Restrict Domain Admin logons to Tier 0 assets only. "
            "Use PAWs for privileged operations and prohibit DA logons on member servers/workstations. "
            "Enforce ESAE/PAW model and monitor tier-zero session exposure."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1053.005",
        mitre_technique_name="Scheduled Task/Job: Scheduled Task",
        detection_event_ids=("4624", "4672"),
        bh_native=True,
        bh_cypher_names=("HasSession",),
        execution_target_access_requirement="computer_reachable",
    ),
    # ── Network exploitation / CVEs ─────────────────────────────────────────
    _entry(
        "zerologon",
        support_kind="policy_blocked",
        support_reason="High-risk / potentially disruptive (disabled by design)",
        category="cve",
        description="Netlogon cryptographic flaw exploitation path",
        vuln_key="zerologon",
        remediation_complexity="low",
        remediation_effort=(
            "Apply CVE-2020-1472 patch and enforce full Secure Channel enforcement "
            "(FullSecureChannelProtection=1 registry key on all DCs)."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1210",
        mitre_technique_name="Exploitation of Remote Services",
        detection_event_ids=("4742",),
        bh_cypher_names=("Zerologon",),
    ),
    _entry(
        "nopac",
        support_kind="policy_blocked",
        support_reason="High-risk / potentially disruptive (disabled by design)",
        category="cve",
        description="NoPac domain takeover path",
        vuln_key="nopac",
        remediation_complexity="low",
        remediation_effort=(
            "Apply November 2021 Patch Tuesday updates (KB5008380 / KB5008602). "
            "Set ms-DS-MachineAccountQuota=0 to prevent domain users from creating machine accounts."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1068",
        mitre_technique_name="Exploitation for Privilege Escalation",
        detection_event_ids=("4741", "4742", "4768", "4769"),
        bh_cypher_names=("NoPAC",),
    ),
    _entry(
        "printnightmare",
        support_kind="policy_blocked",
        support_reason="High-risk / potentially disruptive (disabled by design)",
        category="cve",
        description="PrintNightmare privileged code execution path",
        vuln_key="printnightmare",
        remediation_complexity="medium",
        remediation_effort=(
            "Apply CVE-2021-34527 patch. Disable the Print Spooler service on all DCs. "
            "If DC-side printing is required, enforce Point and Print restrictions via GPO."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1068",
        mitre_technique_name="Exploitation for Privilege Escalation",
        detection_event_ids=("316",),
        bh_cypher_names=("PrintNightmare",),
    ),
    _entry(
        "ms17-010",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        category="cve",
        description="EternalBlue SMBv1 remote code execution path",
        vuln_key="ms17-010",
        remediation_complexity="low",
        remediation_effort=(
            "Apply MS17-010 patch (KB4012212 or later). "
            "Disable SMBv1 on all systems via GPO "
            "(Set-SmbServerConfiguration -EnableSMB1Protocol $false)."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1210",
        mitre_technique_name="Exploitation of Remote Services",
        detection_event_ids=(),
        bh_cypher_names=("MS17010",),
    ),
    _entry(
        "mseven",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        category="cve",
        description="MSEven coercion-style authentication trigger path",
        vuln_key="mseven",
        remediation_complexity="low",
        remediation_effort=(
            "Apply MS17-010 patch (KB4012212 or later). "
            "Disable SMBv1 on all systems via GPO "
            "(Set-SmbServerConfiguration -EnableSMB1Protocol $false)."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1187",
        mitre_technique_name="Forced Authentication",
        detection_event_ids=("4768",),
        bh_cypher_names=("MSEven",),
    ),
    # ── Kerberos ────────────────────────────────────────────────────────────
    _entry(
        "allowedtodelegate",
        support_kind="supported",
        support_reason="Kerberos constrained delegation enumeration/exploitation",
        category="delegation",
        description="Abuse AllowedToDelegate paths to impersonate users to delegated services",
        vuln_key="constrained_delegation",
        remediation_complexity="high",
        remediation_effort=(
            "Audit msDS-AllowedToDelegateTo and remove unnecessary delegated SPNs. "
            "Restrict protocol transition (TrustedToAuthForDelegation) to services that require it. "
            "Mark privileged and sensitive accounts as 'Account is sensitive and cannot be delegated'."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1558",
        mitre_technique_name="Steal or Forge Kerberos Tickets",
        detection_event_ids=("4769",),
        bh_native=True,
        bh_cypher_names=("AllowedToDelegate",),
    ),
    _entry(
        "allowedtoact",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        category="delegation",
        description="Resource-based constrained delegation attack path",
        vuln_key="rbcd_exploitable",
        remediation_complexity="medium",
        remediation_effort=(
            "Remove or clear the msDS-AllowedToActOnBehalfOfOtherIdentity attribute "
            "on the target computer object. Restrict write access to this attribute."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1134.001",
        mitre_technique_name="Access Token Manipulation: Token Impersonation/Theft",
        detection_event_ids=("4769", "5136"),
        bh_native=True,
        bh_cypher_names=("AllowedToAct",),
    ),
    _entry(
        "addallowedtoact",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        category="delegation",
        description="Write msDS-AllowedToActOnBehalfOfOtherIdentity rights",
        vuln_key="rbcd_exploitable",
        remediation_complexity="medium",
        remediation_effort=(
            "Remove write access to the msDS-AllowedToActOnBehalfOfOtherIdentity attribute "
            "from non-privileged principals on computer objects."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1134.001",
        mitre_technique_name="Access Token Manipulation: Token Impersonation/Theft",
        detection_event_ids=("5136",),
        bh_native=True,
        bh_cypher_names=("AddAllowedToAct",),
    ),
    _entry(
        "coercetotgt",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        category="delegation",
        description="Coerce a target into providing a usable TGT for delegation abuse",
        vuln_key="unconstrained_delegation",
        remediation_complexity="medium",
        remediation_effort=(
            "Block authentication coercion by disabling vulnerable RPC endpoints. "
            "Enable EPA on LDAP and ADCS. Mark sensitive accounts as delegation-exempt."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1187",
        mitre_technique_name="Forced Authentication",
        detection_event_ids=("4768", "4769"),
        bh_native=True,
        bh_cypher_names=("CoerceToTGT",),
    ),
    _entry(
        "kerberoasting",
        support_kind="supported",
        support_reason="Extract and crack Kerberos TGS hashes for a target user",
        compromise_semantics="direct_target_compromise",
        compromise_effort="high",
        category="kerberos",
        description="Offline crack service ticket material for credential recovery",
        vuln_key="kerberoast",
        remediation_complexity="medium",
        remediation_effort=(
            "Migrate SPN-bearing service accounts to Group Managed Service Accounts (gMSA). "
            "Where not possible: use 25+ char random passwords, enforce AES encryption, "
            "and restrict SPN-bearing accounts to least privilege."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1558.003",
        mitre_technique_name="Steal or Forge Kerberos Tickets: Kerberoasting",
        detection_event_ids=("4769",),
        bh_cypher_names=("Kerberoasting",),
    ),
    _entry(
        "asreproasting",
        support_kind="supported",
        support_reason="Extract and crack Kerberos AS-REP hashes for a target user",
        compromise_semantics="direct_target_compromise",
        compromise_effort="high",
        category="kerberos",
        description="Offline crack AS-REP material from users without preauth",
        vuln_key="asreproast",
        remediation_complexity="low",
        remediation_effort=(
            "Enable Kerberos pre-authentication on all accounts "
            "(UF_DONT_REQUIRE_PREAUTH must not be set)."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1558.004",
        mitre_technique_name="Steal or Forge Kerberos Tickets: AS-REP Roasting",
        detection_event_ids=("4768",),
        bh_cypher_names=("ASREPRoasting",),
    ),
    _entry(
        "timeroasting",
        support_kind="supported",
        support_reason="Extract and crack MS-SNTP machine-account material",
        category="credential_access",
        description="Offline crack MS-SNTP challenge material from machine accounts",
        remediation_complexity="medium",
        remediation_effort=(
            "Keep automatic machine-account password rotation enabled. Reset or rejoin "
            "computer accounts that were manually assigned weak passwords, and "
            "investigate stale machine passwords that have not rotated in 30 days."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1110.002",
        mitre_technique_name="Brute Force: Password Cracking",
        bh_cypher_names=("Timeroasting",),
    ),
    # ── Lateral movement / execution ────────────────────────────────────────
    _entry(
        "adminto",
        support_kind="supported",
        support_reason="Confirm local admin access via SMB (AdminTo)",
        compromise_semantics="access_capability_only",
        compromise_effort="medium",
        category="lateral_movement",
        description="Administrative access from one principal to a host",
        remediation_complexity="medium",
        remediation_effort=(
            "Remove local administrator rights from non-privileged accounts on target machines. "
            "Deploy LAPS for local admin password management. "
            "Implement tiered access model (PAWs for admin tasks)."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1021.002",
        mitre_technique_name="Remote Services: SMB/Windows Admin Shares",
        detection_event_ids=("4624", "4648", "4672"),
        bh_native=True,
        bh_cypher_names=("AdminTo",),
        execution_target_access_requirement="computer_reachable",
    ),
    _entry(
        "sqlaccess",
        support_kind="supported",
        support_reason="Confirm MSSQL authenticated access (SQLAccess)",
        compromise_semantics="access_capability_only",
        compromise_effort="medium",
        category="lateral_movement",
        description="Authenticated access over MSSQL without confirmed sysadmin-level control",
        remediation_complexity="medium",
        remediation_effort=(
            "Remove unnecessary SQL login access for the identified principal. "
            "Audit Windows-integrated SQL logins and limit who can connect to SQL Server instances."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1078",
        mitre_technique_name="Valid Accounts",
        detection_event_ids=("4624",),
        bh_cypher_names=("SQLAccess",),
        execution_relation_alias="sqladmin",
        execution_target_access_requirement="computer_reachable",
    ),
    _entry(
        "sqladmin",
        support_kind="supported",
        support_reason="Confirm MSSQL administrative access (SQLAdmin)",
        compromise_semantics="access_capability_only",
        compromise_effort="medium",
        category="lateral_movement",
        description="Administrative access over MSSQL control surface",
        remediation_complexity="medium",
        remediation_effort=(
            "Remove sysadmin or db_owner rights from the identified SQL login. "
            "Audit SQL Server logins and Windows-integrated authentication principals."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1078",
        mitre_technique_name="Valid Accounts",
        detection_event_ids=("4624",),
        bh_native=True,
        bh_cypher_names=("SQLAdmin",),
        execution_target_access_requirement="computer_reachable",
    ),
    _entry(
        "canrdp",
        support_kind="supported",
        support_reason="Confirm RDP login capability (CanRDP)",
        compromise_semantics="access_capability_only",
        compromise_effort="medium",
        category="lateral_movement",
        description="Interactive login capability via RDP",
        remediation_complexity="medium",
        remediation_effort=(
            "Remove the principal from the Remote Desktop Users group on target hosts. "
            "Restrict RDP access via GPO and firewall rules."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1021.001",
        mitre_technique_name="Remote Services: Remote Desktop Protocol",
        detection_event_ids=("4624", "4778"),
        bh_native=True,
        bh_cypher_names=("CanRDP",),
        execution_target_access_requirement="computer_reachable",
    ),
    _entry(
        "canpsremote",
        support_kind="supported",
        support_reason="Confirm remote PowerShell/WinRM capability (CanPSRemote)",
        compromise_semantics="access_capability_only",
        compromise_effort="medium",
        category="lateral_movement",
        description="Remote command execution capability over WinRM/PowerShell",
        remediation_complexity="medium",
        remediation_effort=(
            "Remove the principal from the Remote Management Users group on target hosts. "
            "Restrict WinRM access via GPO and firewall rules."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1021.006",
        mitre_technique_name="Remote Services: Windows Remote Management",
        detection_event_ids=("4624",),
        bh_native=True,
        bh_cypher_names=("CanPSRemote",),
        execution_target_access_requirement="computer_reachable",
    ),
    _entry(
        "guestsession",
        support_kind="supported",
        support_reason="Enumerate SMB guest-authenticated shares and permissions",
        category="lateral_movement",
        description="Guest SMB session accepted, enabling unauthenticated share access",
        vuln_key="smb_guest_shares",
        remediation_complexity="low",
        remediation_effort=(
            "Disable guest SMB access and null sessions via GPO. "
            "Require authenticated SMB access and remove anonymous share permissions."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1135",
        mitre_technique_name="Network Share Discovery",
        detection_event_ids=("4624", "5140"),
        bh_cypher_names=("GuestSession",),
    ),
    _entry(
        "executedcom",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        category="lateral_movement",
        description="Remote command execution capability over DCOM",
        remediation_complexity="medium",
        remediation_effort=(
            "Remove DCOM permissions from non-privileged principals via DCOMCNFG "
            "or registry ACL hardening on target hosts."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1021.003",
        mitre_technique_name="Remote Services: Distributed Component Object Model",
        detection_event_ids=("4624", "4688"),
        bh_native=True,
        bh_cypher_names=("ExecuteDCOM",),
        execution_target_access_requirement="computer_reachable",
    ),
    # ── ADCS / PKI ──────────────────────────────────────────────────────────
    _entry(
        "adcsesc1",
        support_kind="supported",
        support_reason="Request an authentication certificate via ADCS ESC1",
        compromise_semantics="direct_target_compromise",
        compromise_effort="high",
        category="adcs",
        description="Enroll exploitable template and authenticate as target",
        vuln_key="adcs_esc1",
        remediation_complexity="medium",
        remediation_effort=(
            "Disable CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT on the certificate template, "
            "or restrict enrollment to specific privileged security groups."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1649",
        mitre_technique_name="Steal or Forge Authentication Certificates",
        detection_event_ids=("4886", "4887"),
        bh_native=True,
        bh_cypher_names=("ADCSESC1",),
    ),
    _entry(
        "adcsesc2",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        compromise_semantics="direct_target_compromise",
        compromise_effort="high",
        category="adcs",
        description="ADCS ESC2 privilege escalation path",
        vuln_key="adcs_esc2",
        remediation_complexity="medium",
        remediation_effort=(
            "Remove Any Purpose EKU or CA issuance rights from the template. "
            "Enable CA manager approval for issuance."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1649",
        mitre_technique_name="Steal or Forge Authentication Certificates",
        detection_event_ids=("4886", "4887"),
        bh_native=False,
        bh_cypher_names=("ADCSESC2",),
    ),
    _entry(
        "adcsesc3",
        support_kind="supported",
        support_reason="Request an agent certificate and impersonate a target via ADCS ESC3",
        compromise_semantics="direct_target_compromise",
        compromise_effort="high",
        category="adcs",
        description="Use enrollment agent cert to request impersonation certs",
        vuln_key="adcs_esc3",
        remediation_complexity="medium",
        remediation_effort=(
            "Remove enrollment agent rights from the template or restrict "
            "to a dedicated enrollment agent account with auditing and approval workflow."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1649",
        mitre_technique_name="Steal or Forge Authentication Certificates",
        detection_event_ids=("4886", "4887"),
        bh_native=True,
        bh_cypher_names=("ADCSESC3",),
    ),
    _entry(
        "adcsesc4",
        support_kind="supported",
        support_reason="Make a certificate template vulnerable via ADCS ESC4",
        compromise_semantics="direct_target_compromise",
        compromise_effort="high",
        category="adcs",
        description="Modify template permissions/configuration for abuse",
        vuln_key="adcs_esc4",
        remediation_complexity="medium",
        remediation_effort=(
            "Remove GenericWrite/WriteDACL/WriteOwner permissions from "
            "non-privileged principals on the certificate template AD object."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1649",
        mitre_technique_name="Steal or Forge Authentication Certificates",
        detection_event_ids=("5136", "4886", "4887"),
        bh_native=True,
        bh_cypher_names=("ADCSESC4",),
    ),
    _entry(
        "adcsesc5",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        compromise_semantics="direct_target_compromise",
        compromise_effort="high",
        category="adcs",
        description="ADCS ESC5 privilege escalation path",
        vuln_key="adcs_esc5",
        remediation_complexity="medium",
        remediation_effort=(
            "Restrict ACL permissions on CA objects and PKI containers in AD. "
            "Remove non-privileged write access to CA configuration objects."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1649",
        mitre_technique_name="Steal or Forge Authentication Certificates",
        detection_event_ids=("5136", "4886", "4887"),
        bh_native=False,
        bh_cypher_names=("ADCSESC5",),
    ),
    _entry(
        "adcsesc6",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        compromise_semantics="direct_target_compromise",
        compromise_effort="high",
        category="adcs",
        description="ADCS ESC6 privilege escalation path",
        vuln_key="adcs_esc6",
        remediation_complexity="high",
        remediation_effort=(
            "Remove EDITF_ATTRIBUTESUBJECTALTNAME2 flag from the CA via certutil. "
            "Requires CA service restart and testing — may break applications using this flag."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1649",
        mitre_technique_name="Steal or Forge Authentication Certificates",
        detection_event_ids=("4886", "4887"),
        bh_native=True,
        bh_cypher_names=("ADCSESC6a", "ADCSESC6b"),
    ),
    _entry(
        "adcsesc7",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        compromise_semantics="direct_target_compromise",
        compromise_effort="high",
        category="adcs",
        description="ADCS ESC7 privilege escalation path",
        vuln_key="adcs_esc7",
        remediation_complexity="high",
        remediation_effort=(
            "Remove the ManageCA or ManageCertificates rights from non-privileged principals. "
            "Audit CA officer and manager role assignments."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1649",
        mitre_technique_name="Steal or Forge Authentication Certificates",
        detection_event_ids=("4886", "4887"),
        bh_native=False,
        bh_cypher_names=("ADCSESC7",),
    ),
    _entry(
        "adcsesc8",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        compromise_semantics="direct_target_compromise",
        compromise_effort="high",
        category="adcs",
        description="ADCS ESC8 privilege escalation path",
        vuln_key="adcs_esc8",
        remediation_complexity="high",
        remediation_effort=(
            "Enforce HTTPS on all CA web enrollment endpoints. "
            "Enable Extended Protection for Authentication (EPA) on IIS. "
            "Disable HTTP enrollment. May require IIS and CA reconfiguration."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1649",
        mitre_technique_name="Steal or Forge Authentication Certificates",
        detection_event_ids=("4886", "4887"),
        bh_native=False,
        bh_cypher_names=("ADCSESC8",),
        execution_relation_alias="coerceandrelayntlmtoadcs",
    ),
    _entry(
        "adcsesc9",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        compromise_semantics="direct_target_compromise",
        compromise_effort="high",
        category="adcs",
        description="ADCS ESC9 privilege escalation path",
        vuln_key="adcs_esc9",
        remediation_complexity="high",
        remediation_effort=(
            "Deploy KB5014754 and set StrongCertificateBindingEnforcement=2 on all DCs. "
            "Restrict write access to UPN attributes. "
            "Requires thorough testing before full enforcement."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1649",
        mitre_technique_name="Steal or Forge Authentication Certificates",
        detection_event_ids=("5136", "4886", "4887"),
        bh_native=True,
        bh_cypher_names=("ADCSESC9a", "ADCSESC9b"),
    ),
    _entry(
        "adcsesc10",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        compromise_semantics="direct_target_compromise",
        compromise_effort="high",
        category="adcs",
        description="ADCS ESC10 privilege escalation path",
        vuln_key="adcs_esc10",
        remediation_complexity="high",
        remediation_effort=(
            "Set StrongCertificateBindingEnforcement=2 on all DCs. "
            "Remove registry compat mode. May break legacy certificate-based auth."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1649",
        mitre_technique_name="Steal or Forge Authentication Certificates",
        detection_event_ids=("4886", "4887"),
        bh_native=True,
        bh_cypher_names=("ADCSESC10a", "ADCSESC10b"),
    ),
    _entry(
        "adcsesc11",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        compromise_semantics="direct_target_compromise",
        compromise_effort="high",
        category="adcs",
        description="ADCS ESC11 privilege escalation path",
        vuln_key="adcs_esc11",
        remediation_complexity="high",
        remediation_effort=(
            "Enforce HTTPS and EPA on ICPR/RPC endpoint for the CA. "
            "Disable insecure transport for certificate enrollment."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1649",
        mitre_technique_name="Steal or Forge Authentication Certificates",
        detection_event_ids=("4886", "4887"),
        bh_native=False,
        bh_cypher_names=("ADCSESC11",),
    ),
    _entry(
        "adcsesc13",
        support_kind="supported",
        support_reason="Not implemented yet in ADscan",
        compromise_semantics="direct_target_compromise",
        compromise_effort="high",
        category="adcs",
        description="ADCS ESC13 privilege escalation path",
        vuln_key="adcs_esc13",
        remediation_complexity="medium",
        remediation_effort=(
            "Remove OID group link from the issuance policy on the template, "
            "or restrict enrollment rights to prevent unauthorized group membership acquisition."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1649",
        mitre_technique_name="Steal or Forge Authentication Certificates",
        detection_event_ids=("4886", "4887"),
        bh_native=True,
        bh_cypher_names=("ADCSESC13",),
    ),
    _entry(
        "adcsesc14",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        compromise_semantics="direct_target_compromise",
        compromise_effort="high",
        category="adcs",
        description="ADCS ESC14 privilege escalation path",
        vuln_key="adcs_esc14",
        remediation_complexity="high",
        remediation_effort=(
            "Remove weak explicit certificate mappings from altSecurityIdentities, "
            "and enforce strong certificate binding."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1649",
        mitre_technique_name="Steal or Forge Authentication Certificates",
        detection_event_ids=("5136", "4886", "4887"),
        bh_native=False,
        bh_cypher_names=("ADCSESC14",),
    ),
    _entry(
        "adcsesc15",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        compromise_semantics="direct_target_compromise",
        compromise_effort="high",
        category="adcs",
        description="ADCS ESC15 privilege escalation path",
        vuln_key="adcs_esc15",
        remediation_complexity="medium",
        remediation_effort=(
            "Upgrade the certificate template schema version to v2 or higher, "
            "which requires explicit EKU specification and prevents schema-v1 authentication abuse."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1649",
        mitre_technique_name="Steal or Forge Authentication Certificates",
        detection_event_ids=("4886", "4887"),
        bh_native=False,
        bh_cypher_names=("ADCSESC15",),
    ),
    _entry(
        "adcsesc16",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        compromise_semantics="direct_target_compromise",
        compromise_effort="high",
        category="adcs",
        description="ADCS ESC16 privilege escalation path",
        vuln_key="adcs_esc16",
        remediation_complexity="high",
        remediation_effort=(
            "Re-enable szOID_NTDS_CA_SECURITY_EXT on the CA and enforce strong "
            "certificate binding on domain controllers."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1649",
        mitre_technique_name="Steal or Forge Authentication Certificates",
        detection_event_ids=("4886", "4887"),
        bh_native=False,
        bh_cypher_names=("ADCSESC16",),
    ),
    _entry(
        "adcsesc17",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        compromise_semantics="indirect_target_compromise",
        compromise_effort="high",
        category="adcs",
        description="ADCS ESC17 privilege escalation path",
        vuln_key="adcs_esc17",
        remediation_complexity="high",
        remediation_effort=(
            "Restrict enrollment on Server Authentication templates and disable "
            "enrollee-supplied subject names where not strictly required."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1557",
        mitre_technique_name="Adversary-in-the-Middle",
        detection_event_ids=("4886", "4887"),
        bh_native=False,
        bh_cypher_names=("ADCSESC17",),
    ),
    _entry(
        "coerceandrelayntlmtoadcs",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        compromise_semantics="direct_target_compromise",
        compromise_effort="high",
        category="adcs",
        description="Coerce NTLM authentication and relay it to ADCS endpoints",
        remediation_complexity="high",
        remediation_effort=(
            "Enable EPA on all ADCS HTTP endpoints. Enforce HTTPS. "
            "Block coercion techniques at the firewall (disable vulnerable RPC services on DCs)."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1187",
        mitre_technique_name="Forced Authentication",
        detection_event_ids=("4768",),
        bh_native=True,
        bh_cypher_names=("CoerceAndRelayNTLMToADCS",),
    ),
    _entry(
        "goldencert",
        support_kind="supported",
        support_reason="Backup CA private key, forge certificate, and run Pass-the-Certificate",
        category="adcs",
        description="Certificate authority compromise persistence path",
        remediation_complexity="very_high",
        remediation_effort=(
            "Prevention: Deploy an HSM (Hardware Security Module) to store the CA private key — "
            "this makes the key non-exportable even with admin access to the CA server. "
            "Treat the CA server as Tier-0 (same level as DCs). "
            "If the CA private key is already compromised: revoke the CA certificate, "
            "remove it from the NTAuth Store and all certificate trust lists, "
            "deploy a new CA with a new key pair (preferably in an HSM), "
            "and re-enroll all certificates issued by the compromised CA. "
            "This constitutes a full PKI rebuild and causes significant operational disruption."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1649",
        mitre_technique_name="Steal or Forge Authentication Certificates",
        detection_event_ids=("5058", "5061"),
        bh_native=True,
        bh_cypher_names=("GoldenCert",),
    ),
    # ── ACL / Object control ─────────────────────────────────────────────────
    _entry(
        "genericall",
        support_kind="supported",
        support_reason="ACL/ACE abuse (GenericAll)",
        compromise_semantics="direct_target_compromise",
        compromise_effort="immediate",
        category="acl_ace",
        description="Full object control over target principal/object",
        remediation_complexity="medium",
        remediation_effort=(
            "Remove GenericAll permission from the target object ACL. "
            "Audit AD ACLs regularly using tools such as BloodHound or ADACLScanner. "
            "Apply least-privilege delegation."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1098",
        mitre_technique_name="Account Manipulation",
        detection_event_ids=("5136", "4662"),
        bh_native=True,
        bh_cypher_names=("GenericAll",),
        is_acl_edge=True,
    ),
    _entry(
        "genericwrite",
        support_kind="supported",
        support_reason="ACL/ACE abuse (GenericWrite)",
        compromise_semantics="direct_target_compromise",
        compromise_effort="low",
        category="acl_ace",
        description="Write permissions over target object attributes",
        remediation_complexity="medium",
        remediation_effort=(
            "Remove GenericWrite permission from the target object ACL. "
            "Replace broad write rights with specific delegated attributes only."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1098",
        mitre_technique_name="Account Manipulation",
        detection_event_ids=("5136",),
        bh_native=True,
        bh_cypher_names=("GenericWrite",),
        is_acl_edge=True,
    ),
    _entry(
        "owns",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        category="acl_ace",
        description="Object ownership grants implicit GenericAll-equivalent rights",
        remediation_complexity="medium",
        remediation_effort=(
            "Transfer object ownership to Domain Admins or SYSTEM. "
            "Audit ownership of high-value objects (GPOs, OUs, user/computer accounts)."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1222.001",
        mitre_technique_name="Windows File and Directory Permissions Modification",
        detection_event_ids=("4662",),
        bh_native=True,
        bh_cypher_names=("Owns",),
        is_acl_edge=True,
    ),
    _entry(
        "forcechangepassword",
        support_kind="supported",
        support_reason="ACL/ACE abuse (ForceChangePassword)",
        compromise_semantics="direct_target_compromise",
        compromise_effort="immediate",
        category="acl_ace",
        description="Reset target account password without current password",
        vuln_key="force_change_password",
        remediation_complexity="low",
        remediation_effort=(
            "Remove ForceChangePassword (User-Force-Change-Password extended right) "
            "from the target user's ACL for non-privileged principals."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1098",
        mitre_technique_name="Account Manipulation",
        detection_event_ids=("4723", "4724"),
        bh_native=True,
        bh_cypher_names=("ForceChangePassword",),
        is_acl_edge=True,
    ),
    _entry(
        "addself",
        support_kind="supported",
        support_reason="ACL/ACE abuse (AddSelf)",
        compromise_semantics="direct_target_compromise",
        compromise_effort="low",
        category="acl_ace",
        description="Self-add to controlled group under permissive ACL",
        remediation_complexity="low",
        remediation_effort=(
            "Remove Self-Membership right from non-privileged principals on the target group."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1098",
        mitre_technique_name="Account Manipulation",
        detection_event_ids=("4728", "4732", "4756"),
        bh_native=True,
        bh_cypher_names=("AddSelf",),
        is_acl_edge=True,
    ),
    _entry(
        "addmember",
        support_kind="supported",
        support_reason="ACL/ACE abuse (AddMember)",
        compromise_semantics="direct_target_compromise",
        compromise_effort="low",
        category="acl_ace",
        description="Add arbitrary members to target group",
        remediation_complexity="low",
        remediation_effort=(
            "Remove AddMember rights from non-privileged principals on the target group. "
            "Monitor group membership changes for privileged groups."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1098",
        mitre_technique_name="Account Manipulation",
        detection_event_ids=("4728", "4732", "4756"),
        bh_native=True,
        bh_cypher_names=("AddMember",),
        is_acl_edge=True,
    ),
    _entry(
        "readgmsapassword",
        support_kind="supported",
        support_reason="ACL/ACE abuse (ReadGMSAPassword)",
        compromise_semantics="direct_target_compromise",
        compromise_effort="low",
        category="acl_ace",
        description="Read gMSA managed password material",
        vuln_key="gmsa_readable",
        remediation_complexity="low",
        remediation_effort=(
            "Restrict PrincipalsAllowedToRetrieveManagedPassword to only the specific "
            "service hosts that require the gMSA password."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1555",
        mitre_technique_name="Credentials from Password Stores",
        detection_event_ids=("4662",),
        bh_native=True,
        bh_cypher_names=("ReadGMSAPassword",),
        is_acl_edge=True,
    ),
    _entry(
        "readlapspassword",
        support_kind="supported",
        support_reason="ACL/ACE abuse (ReadLAPSPassword)",
        compromise_semantics="direct_target_compromise",
        compromise_effort="low",
        category="acl_ace",
        description="Read LAPS local administrator password",
        vuln_key="laps_readable",
        remediation_complexity="low",
        remediation_effort=(
            "Restrict read access on ms-Mcs-AdmPwd (legacy LAPS) or "
            "msLAPS-Password (Windows LAPS) to authorized IT admin groups only via AD ACL."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1555",
        mitre_technique_name="Credentials from Password Stores",
        detection_event_ids=("4662",),
        bh_native=True,
        bh_cypher_names=("ReadLAPSPassword",),
        is_acl_edge=True,
    ),
    _entry(
        "synclapspassword",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        category="acl_ace",
        description="Read/replicate LAPS password material",
        vuln_key="laps_readable",
        remediation_complexity="low",
        remediation_effort=(
            "Restrict SyncLAPSPassword (DS-Sync-LAPS-Password) right to LAPS admin groups only."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1555",
        mitre_technique_name="Credentials from Password Stores",
        detection_event_ids=("4662",),
        bh_native=True,
        bh_cypher_names=("SyncLAPSPassword",),
        is_acl_edge=True,
    ),
    _entry(
        "writedacl",
        support_kind="supported",
        support_reason="ACL/ACE abuse (WriteDacl)",
        compromise_semantics="direct_target_compromise",
        compromise_effort="low",
        category="acl_ace",
        description="Rewrite ACLs to grant further privileges",
        remediation_complexity="medium",
        remediation_effort=(
            "Remove WriteDACL from non-privileged principals on the target object. "
            "Enable AdminSDHolder propagation for protected accounts."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1222.001",
        mitre_technique_name="Windows File and Directory Permissions Modification",
        detection_event_ids=("5136",),
        bh_native=True,
        bh_cypher_names=("WriteDacl",),
        is_acl_edge=True,
    ),
    _entry(
        "writeowner",
        support_kind="supported",
        support_reason="ACL/ACE abuse (WriteOwner)",
        compromise_semantics="direct_target_compromise",
        compromise_effort="low",
        category="acl_ace",
        description="Take ownership to unlock privilege escalation",
        remediation_complexity="medium",
        remediation_effort=(
            "Remove WriteOwner right from non-privileged principals. "
            "Ensure object ownership is held by Domain Admins or SYSTEM only."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1222.001",
        mitre_technique_name="Windows File and Directory Permissions Modification",
        detection_event_ids=("5136",),
        bh_native=True,
        bh_cypher_names=("WriteOwner",),
        is_acl_edge=True,
    ),
    _entry(
        "writeaccountrestrictions",
        support_kind="supported",
        support_reason="Not implemented yet in ADscan",
        compromise_semantics="direct_target_compromise",
        compromise_effort="low",
        category="acl_ace",
        description=(
            "Modify account-restriction property sets on the target user/computer object"
        ),
        remediation_complexity="medium",
        remediation_effort=(
            "Remove WriteAccountRestrictions from non-privileged principals on the "
            "target object. Restrict delegated property-set writes on privileged "
            "user and computer objects."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1098",
        mitre_technique_name="Account Manipulation",
        detection_event_ids=("5136", "4662"),
        bh_native=True,
        bh_cypher_names=("WriteAccountRestrictions",),
        is_acl_edge=True,
    ),
    _entry(
        "writespn",
        support_kind="supported",
        support_reason="ACL/ACE abuse (WriteSPN / targeted Kerberoast)",
        compromise_semantics="direct_target_compromise",
        compromise_effort="high",
        category="acl_ace",
        description="Set SPN to force kerberoastable ticket generation",
        remediation_complexity="low",
        remediation_effort=(
            "Remove write access to servicePrincipalName attribute for non-privileged principals. "
            "Prevents targeted Kerberoasting via SPN injection."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1558.003",
        mitre_technique_name="Steal or Forge Kerberos Tickets: Kerberoasting",
        detection_event_ids=("5136",),
        bh_native=True,
        bh_cypher_names=("WriteSPN",),
        is_acl_edge=True,
    ),
    _entry(
        "writelogonscript",
        support_kind="supported",
        support_reason=(
            "Discovered via LDAP ACL analysis with prerequisite validation against "
            "NETLOGON share/path access"
        ),
        compromise_semantics="direct_target_compromise",
        compromise_effort="high",
        category="acl_ace",
        description="Write the user's logon script path to attacker-controlled content",
        remediation_complexity="low",
        remediation_effort=(
            "Remove write access to the scriptPath attribute for non-privileged principals. "
            "Audit user objects for unexpected logon scripts and restrict writable SMB shares "
            "that could host malicious script content."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1098",
        mitre_technique_name="Account Manipulation",
        detection_event_ids=("5136",),
        is_acl_edge=True,
    ),
    _entry(
        "managerodcprp",
        support_kind="context",
        support_reason=(
            "Contextual delegated RODC PRP-control edge discovered via LDAP ACL analysis; "
            "not executed directly"
        ),
        compromise_semantics="context_only",
        compromise_effort="none",
        category="acl_ace",
        description="Modify the RODC password-replication policy on the RODC computer object",
        remediation_complexity="medium",
        remediation_effort=(
            "Remove delegated write access to msDS-RevealOnDemandGroup and "
            "msDS-NeverRevealGroup from non-privileged principals. Review RODC "
            "delegation groups for unnecessary membership."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1098",
        mitre_technique_name="Account Manipulation",
        detection_event_ids=("5136", "4662"),
        is_acl_edge=True,
    ),
    _entry(
        "writesmbpath",
        support_kind="supported",
        support_reason="Validated theoretically via Impacket SMB share ACL and path ACL analysis",
        compromise_semantics="context_only",
        compromise_effort="none",
        category="acl_ace",
        description="Theoretical write access to an SMB share/path that can host attack payloads",
        remediation_complexity="low",
        remediation_effort=(
            "Remove write permissions from non-privileged principals on sensitive SMB paths such as "
            "NETLOGON and SYSVOL. Restrict payload staging locations to tightly controlled admins only."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1105",
        mitre_technique_name="Ingress Tool Transfer",
        detection_event_ids=("5145",),
    ),
    _entry(
        "addkeycredentiallink",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        category="acl_ace",
        description="Write msDS-KeyCredentialLink to add shadow credentials",
        remediation_complexity="low",
        remediation_effort=(
            "Remove write access to the msDS-KeyCredentialLink attribute for non-privileged principals. "
            "Prevents Shadow Credentials / PKINIT abuse."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1649",
        mitre_technique_name="Steal or Forge Authentication Certificates",
        detection_event_ids=("5136",),
        bh_native=True,
        bh_cypher_names=("AddKeyCredentialLink",),
        is_acl_edge=True,
    ),
    _entry(
        "allextendedrights",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        category="acl_ace",
        description="Broad extended rights over directory object",
        vuln_key="all_extended_rights",
        remediation_complexity="medium",
        remediation_effort=(
            "Audit and remove AllExtendedRights grants from non-privileged principals. "
            "Replace with specific extended rights delegations only."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1098",
        mitre_technique_name="Account Manipulation",
        detection_event_ids=("4662",),
        bh_native=True,
        bh_cypher_names=("AllExtendedRights",),
        is_acl_edge=True,
    ),
    # ── Credential access ───────────────────────────────────────────────────
    _entry(
        "dcsync",
        support_kind="supported",
        support_reason="ACL/ACE abuse / post-exploitation (DCSync)",
        category="credential_access",
        description="Replicate AD secrets remotely from domain controller",
        vuln_key="dcsync",
        remediation_complexity="medium",
        remediation_effort=(
            "Remove GetChanges (DS-Replication-Get-Changes) and GetChangesAll "
            "(DS-Replication-Get-Changes-All) permissions from all non-DC accounts "
            "on the domain naming context object."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1003.006",
        mitre_technique_name="OS Credential Dumping: DCSync",
        detection_event_ids=("4662",),
        bh_native=True,
        bh_cypher_names=("DCSync",),
        is_acl_edge=True,
    ),
    _entry(
        "getchanges",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan (partial DCSync right)",
        category="credential_access",
        description="Partial replication right; combined with GetChangesAll enables DCSync",
        remediation_complexity="medium",
        remediation_effort=(
            "Remove DS-Replication-Get-Changes permission from non-DC accounts on the domain object."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1003.006",
        mitre_technique_name="OS Credential Dumping: DCSync",
        detection_event_ids=("4662",),
        bh_native=True,
        bh_cypher_names=("GetChanges",),
        is_acl_edge=True,
    ),
    _entry(
        "getchangesall",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan (partial DCSync right)",
        category="credential_access",
        description="Extended replication right; combined with GetChanges enables DCSync",
        remediation_complexity="medium",
        remediation_effort=(
            "Remove DS-Replication-Get-Changes-All permission from non-DC accounts on the domain object."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1003.006",
        mitre_technique_name="OS Credential Dumping: DCSync",
        detection_event_ids=("4662",),
        bh_native=True,
        bh_cypher_names=("GetChangesAll",),
        is_acl_edge=True,
    ),
    _entry(
        "dumplsa",
        support_kind="supported",
        support_reason="Execute LSA secrets dump via NetExec",
        category="credential_access",
        description="Credential extraction from LSA secrets",
        remediation_complexity="medium",
        remediation_effort=(
            "Restrict local admin access to servers. Enable LSA Protection (RunAsPPL). "
            "Deploy EDR with credential dump detection."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1003.004",
        mitre_technique_name="OS Credential Dumping: LSA Secrets",
        detection_event_ids=("4656", "4663"),
        bh_cypher_names=("DumpLSA",),
    ),
    _entry(
        "dumpdpapi",
        support_kind="supported",
        support_reason="Execute DPAPI credential dump via NetExec",
        category="credential_access",
        description="Credential extraction from DPAPI-protected material",
        remediation_complexity="medium",
        remediation_effort=(
            "Remove unnecessary local admin access. "
            "Minimize use of DPAPI-protected credentials on servers. "
            "Enable EDR-based detection for DPAPI abuse."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1555.004",
        mitre_technique_name="Credentials from Password Stores: Windows Credential Manager",
        detection_event_ids=("4663",),
        bh_cypher_names=("DumpDPAPI",),
    ),
    _entry(
        "dumplsass",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        category="credential_access",
        description="Credential extraction from LSASS memory",
        remediation_complexity="medium",
        remediation_effort=(
            "Enable Credential Guard. Enable LSA Protection (RunAsPPL). "
            "Deploy EDR with LSASS dump detection and blocking."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1003.001",
        mitre_technique_name="OS Credential Dumping: LSASS Memory",
        detection_event_ids=("4656",),
        bh_cypher_names=("DumpLSASS",),
    ),
    # ── Coercion ─────────────────────────────────────────────────────────────
    _entry(
        "dfscoerce",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        category="coercion",
        description="Coerce machine authentication via DFS endpoint behavior",
        vuln_key="dfscoerce",
        remediation_complexity="medium",
        remediation_effort=(
            "Block MS-DFSNM RPC calls to DCs via firewall. "
            "Enable EPA on target services (LDAP, ADCS) to prevent relay. "
            "Apply available patches for DFS-R coercion."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1187",
        mitre_technique_name="Forced Authentication",
        detection_event_ids=("4768",),
        bh_cypher_names=("DFSCoerce",),
    ),
    _entry(
        "petitpotam",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        category="coercion",
        description="MS-EFSRPC coercion path (PetitPotam)",
        vuln_key="petitpotam",
        remediation_complexity="medium",
        remediation_effort=(
            "Apply CVE-2021-36942 patch. Enable EPA on AD CS HTTP endpoints. "
            "Disable EFS RPC on DCs where not required. "
            "Enable LDAP signing and channel binding."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1187",
        mitre_technique_name="Forced Authentication",
        detection_event_ids=("4768",),
        bh_cypher_names=("PetitPotam",),
    ),
    _entry(
        "printerbug",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        category="coercion",
        description="Spooler coercion path (PrinterBug)",
        vuln_key="printerbug",
        remediation_complexity="medium",
        remediation_effort=(
            "Disable the Print Spooler service on all DCs and servers that do not require it. "
            "May break networked printing from DCs — evaluate impact before applying."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1187",
        mitre_technique_name="Forced Authentication",
        detection_event_ids=("4768",),
        bh_cypher_names=("PrinterBug",),
    ),
    # ── Entry vectors ────────────────────────────────────────────────────────
    _entry(
        "ldapanonymousbind",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        category="entry_vector",
        description="Anonymous LDAP bind entry vector",
        remediation_complexity="low",
        remediation_effort=(
            "Disable anonymous LDAP binds and restrict Anonymous Logon read access "
            "to directory objects and attributes."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1087.002",
        mitre_technique_name="Account Discovery: Domain Account",
        detection_event_ids=(),
        bh_cypher_names=("LDAPAnonymousBind",),
    ),
    _entry(
        "passwordspray",
        support_kind="supported",
        support_reason="Executable via built-in password spraying workflows",
        compromise_semantics="direct_target_compromise",
        compromise_effort="medium",
        category="entry_vector",
        description="Password spraying entry vector",
        remediation_complexity="medium",
        remediation_effort=(
            "Enforce strong password policies and account lockout thresholds. "
            "Enable MFA on all externally-accessible services. Monitor for spray patterns."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1110.003",
        mitre_technique_name="Brute Force: Password Spraying",
        detection_event_ids=("4625", "4771"),
        bh_cypher_names=("PasswordSpray",),
    ),
    _entry(
        "useraspass",
        support_kind="supported",
        support_reason="Executable via built-in username-as-password spraying workflows",
        compromise_semantics="direct_target_compromise",
        compromise_effort="low",
        category="entry_vector",
        description="Username-as-password entry vector",
        remediation_complexity="medium",
        remediation_effort=(
            "Prevent predictable password choices that mirror usernames or account names. "
            "Enforce strong password policies, MFA, and monitor for spray patterns."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1110.003",
        mitre_technique_name="Brute Force: Password Spraying",
        detection_event_ids=("4625", "4771"),
        bh_cypher_names=("UserAsPass",),
    ),
    _entry(
        "blankpassword",
        support_kind="supported",
        support_reason="Executable via built-in blank-password validation workflow",
        compromise_semantics="direct_target_compromise",
        compromise_effort="low",
        category="entry_vector",
        description="Blank-password entry vector",
        remediation_complexity="low",
        remediation_effort=(
            "Disable blank passwords for all domain accounts and enforce password policy "
            "validation during provisioning and account review."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1110.001",
        mitre_technique_name="Brute Force: Password Guessing",
        detection_event_ids=("4625", "4771"),
        bh_cypher_names=("BlankPassword",),
    ),
    _entry(
        "computerpre2k",
        support_kind="supported",
        support_reason="Executable via built-in pre2k computer-account validation workflow",
        compromise_semantics="direct_target_compromise",
        compromise_effort="low",
        category="entry_vector",
        description="Pre2k computer-account password entry vector",
        remediation_complexity="medium",
        remediation_effort=(
            "Rotate computer account passwords, remove legacy pre-Windows 2000 style secrets, "
            "and review machine-account provisioning for predictable host-based passwords."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1110.003",
        mitre_technique_name="Brute Force: Password Spraying",
        detection_event_ids=("4625", "4771"),
        bh_cypher_names=("ComputerPre2k",),
    ),
    _entry(
        "passwordinshare",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        compromise_semantics="direct_target_compromise",
        compromise_effort="low",
        category="entry_vector",
        description="Credentials discovered in SMB share content",
        remediation_complexity="low",
        remediation_effort=(
            "Scan SMB shares for credentials and remove them. "
            "Rotate any discovered credentials immediately."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1552.001",
        mitre_technique_name="Unsecured Credentials: Credentials In Files",
        detection_event_ids=(),
        bh_cypher_names=("PasswordInShare",),
    ),
    _entry(
        "passwordinfile",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        compromise_semantics="direct_target_compromise",
        compromise_effort="low",
        category="entry_vector",
        description="Credentials discovered in host filesystem artifacts after service access",
        remediation_complexity="low",
        remediation_effort=(
            "Scan host filesystem artifacts and backups for credentials, remove embedded secrets, "
            "and rotate any exposed accounts immediately."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1552.001",
        mitre_technique_name="Unsecured Credentials: Credentials In Files",
        detection_event_ids=(),
        bh_cypher_names=("PasswordInFile",),
    ),
    _entry(
        "gpppassword",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        compromise_semantics="direct_target_compromise",
        compromise_effort="low",
        category="entry_vector",
        description="Credentials recovered from Group Policy Preferences artifacts",
        remediation_complexity="low",
        remediation_effort=(
            "Remove GPP XML files containing cpassword fields from SYSVOL. "
            "Apply MS14-025 (KB2962486) to prevent new GPP password creation."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1552.006",
        mitre_technique_name="Unsecured Credentials: Group Policy Preferences",
        detection_event_ids=(),
        bh_cypher_names=("GPPPassword",),
    ),
    _entry(
        "userdescription",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        compromise_semantics="direct_target_compromise",
        compromise_effort="low",
        category="entry_vector",
        description="Credentials recovered from LDAP user description fields",
        remediation_complexity="low",
        remediation_effort=(
            "Audit and clear credentials stored in user Description or info attributes in AD. "
            "Rotate any discovered credentials immediately."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1087.002",
        mitre_technique_name="Account Discovery: Domain Account",
        detection_event_ids=("4662",),
        bh_cypher_names=("UserDescription",),
    ),
)

ATTACK_STEP_CATALOG: dict[str, AttackStepCatalogEntry] = {
    entry.relation: entry for entry in _CATALOG_ENTRIES if entry.relation
}

_RELATIONS_REQUIRING_EXECUTION_CONTEXT: frozenset[str] = frozenset(
    {
        "adminto",
        "sqlaccess",
        "sqladmin",
        "canrdp",
        "canpsremote",
        "hassession",
        "allowedtodelegate",
        "adcsesc1",
        "adcsesc3",
        "adcsesc4",
        "dumplsa",
        "dumpdpapi",
        "genericall",
        "genericwrite",
        "forcechangepassword",
        "addself",
        "addmember",
        "readgmsapassword",
        "readlapspassword",
        "writedacl",
        "writeowner",
        "writespn",
        "dcsync",
        "kerberoasting",
        "writelogonscript",
    }
)
_RELATIONS_COUNTING_FOR_EXECUTION_READINESS: frozenset[str] = frozenset(
    _RELATIONS_REQUIRING_EXECUTION_CONTEXT | {"asreproasting"}
)
for _relation, _entry_value in list(ATTACK_STEP_CATALOG.items()):
    ATTACK_STEP_CATALOG[_relation] = replace(
        _entry_value,
        requires_execution_context=(
            _relation in _RELATIONS_REQUIRING_EXECUTION_CONTEXT
        ),
        counts_for_execution_readiness=(
            _relation in _RELATIONS_COUNTING_FOR_EXECUTION_READINESS
        ),
    )

_RELATION_ALIASES_BY_KEY: dict[str, str] = {
    # BloodHound CE ADCS relation variants.
    "adcsesc6a": "adcsesc6",
    "adcsesc6b": "adcsesc6",
    "adcsesc9a": "adcsesc9",
    "adcsesc9b": "adcsesc9",
    "adcsesc10a": "adcsesc10",
    "adcsesc10b": "adcsesc10",
    # Delegation relation names in CE.
    "allowedtoactonbehalfofotheridentity": "allowedtoact",
    "addallowedtoactonbehalfofotheridentity": "addallowedtoact",
    # KeyCredentialLink typo variants (BloodHound uses various spellings).
    "addkeycreatentiallink": "addkeycredentiallink",
    "addkeycredentiallinks": "addkeycredentiallink",
    # Account restriction property-set variants.
    "writeaccountrestriction": "writeaccountrestrictions",
    "writeaccountrestrictions": "writeaccountrestrictions",
    # MS17-010 alias.
    "ms17010": "ms17-010",
}


def _relation_lookup_key(relation: str) -> str:
    """Return a punctuation-insensitive key for relation lookup."""
    return re.sub(r"[^a-z0-9]+", "", str(relation or "").strip().lower())


def normalize_relation(relation: str) -> str:
    """Normalize relation names for robust catalog lookups."""
    raw = str(relation or "").strip().lower()
    if not raw:
        return ""
    alias = _RELATION_ALIASES_BY_KEY.get(_relation_lookup_key(raw))
    if alias:
        return alias
    return raw


def get_attack_step_entry(relation: str) -> AttackStepCatalogEntry | None:
    """Return one catalog entry by relation name."""
    return ATTACK_STEP_CATALOG.get(normalize_relation(relation))


def normalize_execution_relation(relation: str) -> str:
    """Return the canonical execution-family relation for one relation."""
    entry = get_attack_step_entry(relation)
    if entry and entry.execution_relation_alias:
        return entry.execution_relation_alias
    return normalize_relation(relation)


def list_attack_step_entries() -> list[AttackStepCatalogEntry]:
    """Return all catalog entries sorted by relation."""
    return [ATTACK_STEP_CATALOG[key] for key in sorted(ATTACK_STEP_CATALOG.keys())]


def get_relation_notes_by_support_kind(support_kind: SupportKind) -> dict[str, str]:
    """Return relation->reason map for one support kind."""
    return {
        relation: entry.support_reason
        for relation, entry in ATTACK_STEP_CATALOG.items()
        if entry.support_kind == support_kind
    }


def relation_requires_execution_context(relation: str) -> bool:
    """Return whether a relation needs an execution credential context."""
    entry = get_attack_step_entry(normalize_execution_relation(relation))
    if entry is None:
        return False
    return bool(entry.requires_execution_context)


def relation_counts_for_execution_readiness(relation: str) -> bool:
    """Return whether a relation should gate attack-path readiness checks."""
    entry = get_attack_step_entry(normalize_execution_relation(relation))
    if entry is None:
        return False
    return bool(entry.counts_for_execution_readiness)


def relation_requires_reachable_computer_target(relation: str) -> bool:
    """Return whether a relation needs the target computer to be reachable now."""
    entry = get_attack_step_entry(normalize_execution_relation(relation))
    if entry is None:
        return False
    return entry.execution_target_access_requirement == "computer_reachable"


def get_exploitation_relation_vuln_keys() -> dict[str, str]:
    """Return relation->vuln_key mappings for exploitation-style classification."""
    return {
        relation: str(entry.vuln_key)
        for relation, entry in ATTACK_STEP_CATALOG.items()
        if isinstance(entry.vuln_key, str) and entry.vuln_key.strip()
    }


# ── BloodHound CE edge helpers ─────────────────────────────────────────────────


def get_bh_native_relations() -> frozenset[str]:
    """Return the set of catalog relation keys that exist natively in BH CE's graph.

    ADscan-custom relations (LocalAdminPassReuse, Timeroasting, DumpLSA, etc.)
    are excluded because they are not stored as edges in BloodHound.
    """
    return frozenset(
        rel for rel, entry in ATTACK_STEP_CATALOG.items() if entry.bh_native
    )


def get_bh_native_acl_cypher_names() -> frozenset[str]:
    """Return BH-native Cypher type names for ACL/ACE-derived edges.

    The catalog marks ACL semantics explicitly via ``is_acl_edge`` so Phase 2
    BloodHound queries and similar collection logic stay synchronized when new
    ACL-backed attack steps are added.
    """
    result: set[str] = set()
    for entry in ATTACK_STEP_CATALOG.values():
        if not entry.bh_native or not entry.is_acl_edge:
            continue
        result.update(entry.bh_cypher_names)
    return frozenset(result)


def get_bh_cypher_relation_types() -> tuple[str, ...]:
    """Return BH CE Cypher relationship type names for all catalog entries that have them.

    Includes both BH-native edges and ADscan opengraph edges (e.g. Kerberoasting,
    ASREPRoasting, PasswordSpray, UserAsPass, BlankPassword, ComputerPre2k)
    that ADscan writes into BH CE via opengraph sync.

    Use this to build the ``[:TypeA|TypeB|...*1..N]`` filter in attack-path
    Cypher queries so the query is automatically kept in sync with the catalog.

    Returns a sorted, deduplicated tuple of PascalCase type strings.
    """
    result: list[str] = []
    for entry in ATTACK_STEP_CATALOG.values():
        if entry.bh_cypher_names:
            result.extend(entry.bh_cypher_names)
    return tuple(sorted(set(result)))


def get_bh_canonical_cypher_name(relation: str) -> str:
    """Return the canonical BH CE Cypher type name for a relation string.

    Handles variants like ``ADCSESC9`` → ``ADCSESC9a`` where BH CE splits a
    single ESC into multiple sub-types (a/b).  The first ``bh_cypher_name`` in
    the catalog entry is used as the canonical form.  If the relation is unknown
    or already canonical, the input is returned unchanged.

    Args:
        relation: Raw relation string (e.g. ``"ADCSESC9"``, ``"adcsesc9"``).

    Returns:
        Canonical BH CE Cypher type string (e.g. ``"ADCSESC9a"``).
    """
    key = str(relation or "").strip().lower().replace("-", "")
    # Direct catalog key match (e.g. "adcsesc9" → entry with bh_cypher_names=("ADCSESC9a","ADCSESC9b"))
    entry = ATTACK_STEP_CATALOG.get(key)
    if entry and entry.bh_cypher_names:
        return entry.bh_cypher_names[0]
    # Try matching against existing bh_cypher_names (e.g. "adcsesc9a" already canonical)
    for catalog_entry in ATTACK_STEP_CATALOG.values():
        if key in {n.lower() for n in catalog_entry.bh_cypher_names}:
            return catalog_entry.bh_cypher_names[0]
    # Unknown — return as-is (uppercase for Cypher conventions)
    return str(relation or "").strip()


def get_bh_native_adcs_cypher_names() -> frozenset[str]:
    """Return Cypher type names for ADCS escalation edges that BH CE creates natively.

    These are the ESC techniques that BloodHound CE's own ingestor adds to the
    graph.  Non-native ADCS variants (ESC2, ESC5, ESC7, ESC8, ESC11, ESC15) are
    excluded because BH CE does not create those edges natively.
    """
    _adcs_prefixes = ("ADCS",)
    _adcs_exact = {"CoerceAndRelayNTLMToADCS", "GoldenCert"}
    result: set[str] = set()
    for entry in ATTACK_STEP_CATALOG.values():
        if not entry.bh_native:
            continue
        for name in entry.bh_cypher_names:
            if any(name.startswith(p) for p in _adcs_prefixes) or name in _adcs_exact:
                result.add(name)
    return frozenset(result)


# ── Remediation metadata helpers ──────────────────────────────────────────────


def get_step_metadata(relation: str) -> dict[str, Any]:
    """Return remediation + MITRE metadata for a relation as a plain dict."""
    entry = get_attack_step_entry(relation)
    if entry is None:
        return {}
    return {
        "remediation_complexity": entry.remediation_complexity,
        "remediation_effort": entry.remediation_effort,
        "can_fully_mitigate": entry.can_fully_mitigate,
        "mitre_technique_id": entry.mitre_technique_id,
        "mitre_technique_name": entry.mitre_technique_name,
        "detection_event_ids": entry.detection_event_ids,
    }


def get_step_remediation_complexity(relation: str) -> str:
    """Return remediation complexity for a relation. Defaults to 'medium'."""
    entry = get_attack_step_entry(relation)
    return entry.remediation_complexity if entry else "medium"


def get_step_complexity_rank(relation: str) -> int:
    """Return numeric rank for sorting by remediation complexity (higher = harder)."""
    return _COMPLEXITY_ORDER.get(get_step_remediation_complexity(relation), 1)


def can_fully_mitigate_step(relation: str) -> bool:
    """Return True if the step can be fully eliminated from attack paths."""
    entry = get_attack_step_entry(relation)
    return entry.can_fully_mitigate if entry else True


def get_step_mitre(relation: str) -> tuple[str | None, str | None]:
    """Return (mitre_technique_id, mitre_technique_name) for a relation."""
    entry = get_attack_step_entry(relation)
    if entry is None:
        return None, None
    return entry.mitre_technique_id, entry.mitre_technique_name


def get_step_detection_event_ids(relation: str) -> tuple[str, ...]:
    """Return Windows Event IDs relevant for detecting this step."""
    entry = get_attack_step_entry(relation)
    return entry.detection_event_ids if entry else ()


# ── Narrative rendering (BloodHound-style, reusable from web + reports) ───────

# Narrative templates for the most common relations. These are kept here (and
# not in the report template) so the CLI, PDF report, DOCX report, and web
# service can all share one source of truth. Placeholder syntax:
#   {source} / {target}           — display names
#   {source_type} / {target_type} — "user" | "computer" | "group" | ...
#   {template}                    — ADCS template name (when applicable)
#   {relation}                    — human-formatted relation label
#
# The templates are registered after the main _CATALOG_ENTRIES tuple so we
# don't have to retype the existing 99 entries; a separate overlay dict keeps
# this manageable and easy to extend incrementally.

_NARRATIVE_OVERLAYS: dict[str, dict[str, Any]] = {
    "kerberoasting": {
        "short": "Kerberoasting: {source} can request service tickets for {target} and crack the TGS-REP offline to recover the service account password.",
        "long": (
            "Kerberoasting allows {source_type} {source} to request a Kerberos service "
            "ticket (TGS-REP) for the service account {target}. Because the ticket is "
            "encrypted with the target account's NTLM hash, an attacker can extract it "
            "and mount an offline brute-force attack against weak passwords. "
            "Once cracked, the attacker fully impersonates {target}."
        ),
        "remediation": (
            "Enforce strong, random passwords (25+ chars) or migrate the account to a Group Managed Service Account (gMSA).",
            "Enable AES-only encryption on the service account (msDS-SupportedEncryptionTypes) and disable RC4 where possible.",
            "Monitor Windows Event ID 4769 with ticket_encryption_type=0x17 (RC4) to detect roasting attempts.",
        ),
    },
    "asreproasting": {
        "short": "ASREPRoasting: {target} has pre-authentication disabled, so {source} can request an AS-REP and crack it offline.",
        "long": (
            "ASREPRoasting targets accounts — in this path, {target} — that have "
            "Kerberos pre-authentication disabled (DONT_REQ_PREAUTH flag). Any "
            "unauthenticated attacker (including {source}) can request an AS-REP "
            "message encrypted with the account's password-derived key and crack "
            "it offline. Successful cracking yields full credentials for {target}."
        ),
        "remediation": (
            "Enable Kerberos pre-authentication for {target} (clear DONT_REQ_PREAUTH in userAccountControl).",
            "Enforce strong passwords on accounts that must keep pre-auth disabled.",
            "Monitor Event ID 4768 with pre-authentication type 0 for anomalous requests.",
        ),
    },
    "genericall": {
        "short": "GenericAll: {source_type} {source} has full control over {target_type} {target}.",
        "long": (
            "GenericAll grants {source_type} {source} full read and write control "
            "over {target_type} {target}. This allows the source to reset the "
            "target's password, add Shadow Credentials (msDS-KeyCredentialLink), "
            "set a Service Principal Name to enable Kerberoasting, or write a "
            "logon script — any of which results in complete compromise of {target}."
        ),
        "remediation": (
            "Remove the GenericAll ACE granting control from {source} over {target}.",
            "Apply least privilege: replace with narrow rights (e.g. ReadProperty) if some access is still required.",
            "Enable AD Protected Users / tier-0 protection on sensitive accounts.",
        ),
    },
    "genericwrite": {
        "short": "GenericWrite: {source} can modify most attributes of {target}, enabling takeover via Shadow Credentials or SPN.",
        "long": (
            "GenericWrite gives {source_type} {source} the ability to modify most "
            "attributes of {target_type} {target}. Typical abuse paths include "
            "writing msDS-KeyCredentialLink (Shadow Credentials) to obtain a PKINIT "
            "certificate, setting a servicePrincipalName to enable Kerberoasting, "
            "or modifying scriptPath / msDS-AllowedToActOnBehalfOfOtherIdentity. "
            "Any of these leads to full compromise of {target}."
        ),
        "remediation": (
            "Remove the GenericWrite ACE from {source} on {target}.",
            "Audit msDS-KeyCredentialLink writes (Event 5136) to detect Shadow Credentials.",
        ),
    },
    "writedacl": {
        "short": "WriteDACL: {source} can rewrite the ACL of {target} and grant itself full control.",
        "long": (
            "WriteDACL lets {source} modify the discretionary access control list "
            "(DACL) of {target}. An attacker simply adds a GenericAll (or DCSync) "
            "ACE granting themselves full control, then escalates as if they owned "
            "the object directly. This is a two-step takeover chain."
        ),
        "remediation": (
            "Remove the WriteDACL ACE from {source} on {target}.",
            "Monitor Event ID 5136 for ACL modifications on sensitive objects.",
        ),
    },
    "writeowner": {
        "short": "WriteOwner: {source} can take ownership of {target} and grant itself full control.",
        "long": (
            "WriteOwner allows {source} to take ownership of {target}. Once "
            "ownership is seized, the attacker can rewrite the DACL at will, "
            "effectively granting full control over the object."
        ),
        "remediation": (
            "Remove the WriteOwner permission from {source} on {target}.",
            "Re-own the object to its intended administrative group (e.g. Domain Admins).",
        ),
    },
    "forcechangepassword": {
        "short": "ForceChangePassword: {source} can reset the password of {target} without knowing the old one.",
        "long": (
            "The User-Force-Change-Password extended right lets {source} set a new "
            "password on {target} without knowing the current password. The "
            "attacker resets the password and authenticates as {target} directly, "
            "completely taking over the account."
        ),
        "remediation": (
            "Remove the User-Force-Change-Password extended right from {source} on {target}.",
            "Review delegated password-reset rights — they should be granted only to helpdesk / tier-appropriate personnel.",
        ),
    },
    "addmember": {
        "short": "AddMember: {source} can add itself to {target}, inheriting all of the group's privileges.",
        "long": (
            "AddMember on the {target} group lets {source} add arbitrary principals "
            "(including itself) as members. Any privilege granted to {target} — "
            "often through nested group chains — is inherited immediately by the "
            "attacker."
        ),
        "remediation": (
            "Remove the AddMember extended right from {source} on {target}.",
            "Audit recent group membership changes via Event ID 4728/4732/4756.",
        ),
    },
    "addself": {
        "short": "AddSelf: {source} can join the {target} group directly.",
        "long": (
            "AddSelf lets {source} add itself (but not others) to the {target} "
            "group. After self-insertion, {source} inherits every privilege held "
            "by {target} — often a fast path to tier-0 via nested group chains."
        ),
        "remediation": (
            "Remove the AddSelf extended right from {source} on {target}.",
        ),
    },
    "readlapspassword": {
        "short": "ReadLAPSPassword: {source} can read the local administrator password of {target} from AD.",
        "long": (
            "The ReadLAPSPassword edge means {source} has the Control Access right "
            "on the ms-Mcs-AdmPwd (or ms-LAPS-Password) attribute of {target}. "
            "{source} simply queries the attribute via LDAP to retrieve the local "
            "Administrator password in cleartext and pivots to {target}."
        ),
        "remediation": (
            "Remove the Control Access ACE on ms-Mcs-AdmPwd / ms-LAPS-Password from {source} on {target}.",
            "Audit LDAP reads of ms-LAPS-Password via Event ID 4662 with the LAPS GUID.",
        ),
    },
    "readgmsapassword": {
        "short": "ReadGMSAPassword: {source} can retrieve the managed password of gMSA {target}.",
        "long": (
            "ReadGMSAPassword lets {source} read the msDS-ManagedPassword attribute "
            "of the group-Managed Service Account {target}, yielding the current "
            "password blob. {source} then derives the NT hash and impersonates "
            "{target} directly."
        ),
        "remediation": (
            "Remove {source} from the msDS-GroupMSAMembership of {target}.",
            "Minimize the gMSA password-retrieval principals to the service hosts that actually need them.",
        ),
    },
    "allowedtodelegate": {
        "short": "Constrained Delegation: {source} can impersonate any user (including Domain Admins) to {target}.",
        "long": (
            "{source} is configured for Kerberos constrained delegation to "
            "services on {target} (msDS-AllowedToDelegateTo). An attacker who "
            "controls {source} can request tickets as any user in the domain "
            "(including tier-0 admins) to services on {target}, fully compromising "
            "it."
        ),
        "remediation": (
            "Remove services from msDS-AllowedToDelegateTo on {source}, or replace with Resource-Based Constrained Delegation.",
            "Add sensitive accounts to the Protected Users group or flag them as 'Account is sensitive and cannot be delegated'.",
        ),
    },
    "allowedtoact": {
        "short": "Resource-Based Constrained Delegation: {source} can impersonate any user to {target}.",
        "long": (
            "Resource-Based Constrained Delegation (RBCD) on {target} lists "
            "{source} in msDS-AllowedToActOnBehalfOfOtherIdentity. An attacker "
            "with control of {source} can request S4U2Self + S4U2Proxy tickets "
            "to impersonate any user (including Domain Admins) to {target}, "
            "fully compromising the host."
        ),
        "remediation": (
            "Clear msDS-AllowedToActOnBehalfOfOtherIdentity on {target} (or prune the offending entry).",
            "Audit writes to msDS-AllowedToActOnBehalfOfOtherIdentity (Event 5136) as high-severity.",
        ),
    },
    "addkeycredentiallink": {
        "short": "Shadow Credentials: {source} can attach a certificate-backed key to {target} and authenticate as it via PKINIT.",
        "long": (
            "AddKeyCredentialLink lets {source} write a new "
            "msDS-KeyCredentialLink entry on {target}. {source} then authenticates "
            "as {target} via PKINIT using the attacker-controlled certificate, "
            "obtaining a TGT and the NT hash of {target} without touching the "
            "password."
        ),
        "remediation": (
            "Remove the Write rights on msDS-KeyCredentialLink from {source} on {target}.",
            "Deploy the KeyCredentialLink auditing rule and alert on Event ID 5136 with attribute msDS-KeyCredentialLink.",
        ),
    },
    "dcsync": {
        "short": "DCSync: {source} can replicate secrets from the domain and extract the krbtgt hash.",
        "long": (
            "{source} holds the Replicating Directory Changes and Replicating "
            "Directory Changes All extended rights on the domain, meaning it can "
            "pull password hashes for any account via the DRSUAPI protocol "
            "(DCSync). Extracting the krbtgt hash yields persistent golden-ticket "
            "capability and full domain compromise."
        ),
        "remediation": (
            "Remove DS-Replication-Get-Changes and DS-Replication-Get-Changes-All extended rights from {source} on the domain.",
            "Limit these rights to DCs and approved replication service accounts only.",
            "Alert on DCSync via Event ID 4662 with the replication GUIDs from non-DC sources.",
        ),
    },
    "memberof": {
        "short": "Group membership: {source} is a member of {target} and inherits its privileges.",
        "long": (
            "{source} is a direct or nested member of {target}. All privileges "
            "held by {target} — including any onward attack-path edges — are "
            "inherited by {source}."
        ),
        "remediation": (
            "Remove {source} from {target} if the membership is not strictly required.",
            "Audit group membership periodically and enforce tiering boundaries.",
        ),
    },
    "adcsesc1": {
        "short": "ADCS ESC1: {source} can enroll in misconfigured certificate template {template} and impersonate any domain user.",
        "long": (
            "ADCS ESC1: the certificate template {template} allows {source_type} "
            "{source} to request certificates where the subject alternative name "
            "(SAN) is supplied by the requester. By specifying a privileged user "
            "(e.g. Domain Admin) in the SAN, the attacker obtains a certificate "
            "that authenticates as that user via PKINIT, fully compromising "
            "{target}."
        ),
        "remediation": (
            "Disable 'Enrollee supplies subject' on template {template}, or require manager approval for enrollment.",
            "Restrict enrollment permissions on {template} to authorized identities only.",
            "Apply the KB5014754 enforcement mode on the CA to block weak SAN mapping.",
        ),
    },
    "unconstraineddelegation": {
        "short": "Unconstrained Delegation: {source} can capture the TGT of any user that authenticates to it.",
        "long": (
            "{source} is marked TRUSTED_FOR_DELEGATION (unconstrained delegation). "
            "Any user that authenticates to {source} — including Domain Admins "
            "coerced via the Printer Bug / PetitPotam — deposits a forwardable "
            "TGT in {source}'s LSASS. The attacker dumps the TGT and pivots as "
            "that user to {target}."
        ),
        "remediation": (
            "Remove TRUSTED_FOR_DELEGATION from {source} unless strictly required; prefer constrained or resource-based delegation.",
            "Add tier-0 accounts to Protected Users or flag 'Account is sensitive and cannot be delegated'.",
        ),
    },
}


# Apply narrative overlays to the base catalog. We do this here (rather than
# retyping 99 _entry() calls) so the overlay dict stays focused on narratives.
_CATALOG_WITH_NARRATIVES: dict[str, AttackStepCatalogEntry] = {}
for _rel, _entry_obj in ATTACK_STEP_CATALOG.items():
    _overlay = _NARRATIVE_OVERLAYS.get(_rel)
    if _overlay:
        _CATALOG_WITH_NARRATIVES[_rel] = replace(
            _entry_obj,
            narrative_template=_overlay.get("long", _entry_obj.narrative_template),
            short_narrative_template=_overlay.get("short", _entry_obj.short_narrative_template),
            remediation_steps=tuple(_overlay.get("remediation", _entry_obj.remediation_steps)),
        )
    else:
        _CATALOG_WITH_NARRATIVES[_rel] = _entry_obj
ATTACK_STEP_CATALOG = _CATALOG_WITH_NARRATIVES  # type: ignore[assignment]


def _infer_node_type(display: str) -> str:
    """Infer a node type label from a display name. Heuristic, matches renderer logic."""
    if not display:
        return "principal"
    name = display.strip()
    lower = name.lower()
    sam = name.split("@", 1)[0] if "@" in name else name
    if "admin" in lower or "da@" in lower:
        return "privileged account"
    if sam.rstrip().endswith("$"):
        return "computer"
    if "@" not in name and "." in name:
        return "domain"
    # Heuristic for groups: common SAM suffixes
    group_hints = ("admins", "operators", " users", "group")
    if any(h in lower for h in group_hints):
        return "group"
    return "user"


def _extract_step_placeholders(step: dict[str, Any]) -> dict[str, str]:
    """Extract placeholder values from a raw attack-path step dict."""
    details = step.get("details") if isinstance(step.get("details"), dict) else {}

    def _get_display(primary_keys: tuple[str, ...], fallback_keys: tuple[str, ...]) -> str:
        for k in primary_keys:
            v = details.get(k) if isinstance(details, dict) else None
            if isinstance(v, str) and v.strip():
                return v.strip()
        for k in fallback_keys:
            v = step.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
        return ""

    source = _get_display(("from", "source_username", "source"), ("source", "from"))
    target = _get_display(
        ("display_to", "to", "target_username", "target"),
        ("target", "to", "display_to"),
    )
    if not source:
        source = "the source principal"
    if not target:
        target = "the target object"

    relation_raw = step.get("action") or step.get("relation") or step.get("type") or ""
    # Human-formatted label (lazy import to avoid circular deps with reporting layer).
    try:
        from adscan_internal.pro.reporting.attack_path_narratives import (
            format_relation_label,
        )
        relation_label = format_relation_label(str(relation_raw))
    except Exception:
        relation_label = str(relation_raw or "Step")

    template = ""
    if isinstance(details, dict):
        tmpl = details.get("template")
        if isinstance(tmpl, str):
            template = tmpl.strip()

    return {
        "source": source,
        "target": target,
        "source_type": _infer_node_type(source),
        "target_type": _infer_node_type(target),
        "template": template,
        "relation": relation_label,
    }


def render_step_narrative(
    step: dict[str, Any],
    *,
    short: bool = False,
) -> str:
    """Render a narrative sentence for a single attack-path step.

    Uses the step's relation to look up a catalog entry. If the entry has a
    ``narrative_template`` (or ``short_narrative_template`` when ``short=True``),
    placeholders are substituted from the step's details.

    Args:
        step: Raw step dict with at least ``action``/``relation`` and optional
            ``details`` dict (from / to / display_to / template / etc.).
        short: If True, prefer the short one-liner template.

    Returns:
        The rendered sentence, or an empty string when no template exists.
        Callers may fall back to legacy :func:`describe_attack_step`.
    """
    if not isinstance(step, dict):
        return ""
    relation_raw = step.get("action") or step.get("relation") or step.get("type") or ""
    entry = get_attack_step_entry(str(relation_raw))
    if entry is None:
        return ""
    tmpl = entry.short_narrative_template if short else entry.narrative_template
    if not tmpl:
        return ""
    placeholders = _extract_step_placeholders(step)
    try:
        return tmpl.format(**placeholders)
    except (KeyError, IndexError):
        # Missing placeholder — return template with as many substitutions as possible.
        out = tmpl
        for k, v in placeholders.items():
            out = out.replace("{" + k + "}", v)
        return out


def render_step_remediation(step: dict[str, Any]) -> list[str]:
    """Render structured remediation steps for one attack-path step."""
    if not isinstance(step, dict):
        return []
    relation_raw = step.get("action") or step.get("relation") or step.get("type") or ""
    entry = get_attack_step_entry(str(relation_raw))
    if entry is None or not entry.remediation_steps:
        return []
    placeholders = _extract_step_placeholders(step)
    rendered: list[str] = []
    for item in entry.remediation_steps:
        try:
            rendered.append(item.format(**placeholders))
        except (KeyError, IndexError):
            out = item
            for k, v in placeholders.items():
                out = out.replace("{" + k + "}", v)
            rendered.append(out)
    return rendered


_STATUS_PHRASE: dict[str, str] = {
    "exploited": "was successfully exploited during active testing",
    "attempted": "was probed but not fully executed in the engagement window",
    "blocked": "was attempted but stopped by an existing control",
    "unsupported": "is mapped but not actionable via ADscan's current toolkit",
    "theoretical": "is a theoretical route derived from configuration analysis",
}


def render_path_summary(path: dict[str, Any]) -> str:
    """Render a 2-3 sentence executive narrative for a full attack path.

    Pulls source / target / steps from the path dict and synthesizes a
    BloodHound-style one-paragraph narrative suitable for report headers or
    web detail views. Works with any step sequence — no hardcoded relations.
    """
    if not isinstance(path, dict):
        return ""

    nodes = path.get("nodes") or []
    steps = path.get("steps") or []
    status_raw = str(path.get("status") or "theoretical").strip().lower()
    if status_raw in {"success", "succeeded"}:
        status_raw = "exploited"
    elif status_raw in {"failed", "error", "partial"}:
        status_raw = "attempted"

    # Resolve display names for the endpoints
    source = str(path.get("source") or "").strip()
    target = str(path.get("target") or "").strip()
    if not source and steps:
        first = steps[0] if isinstance(steps[0], dict) else {}
        details = first.get("details") if isinstance(first, dict) else {}
        if isinstance(details, dict):
            source = str(details.get("from") or "").strip()
    if not target and steps:
        last = steps[-1] if isinstance(steps[-1], dict) else {}
        details = last.get("details") if isinstance(last, dict) else {}
        if isinstance(details, dict):
            target = str(details.get("display_to") or details.get("to") or "").strip()
    source_is_placeholder = not source
    target_is_placeholder = not target
    if source_is_placeholder:
        source = "an unprivileged foothold"
    if target_is_placeholder:
        target = "the target principal"

    # Collect unique technique labels in path order
    try:
        from adscan_internal.pro.reporting.attack_path_narratives import (
            format_relation_label,
        )
        label_fn = format_relation_label
    except Exception:
        def label_fn(s: str) -> str:  # type: ignore[misc]
            return str(s)

    seen: set[str] = set()
    techniques: list[str] = []
    for step in steps:
        if not isinstance(step, dict):
            continue
        rel = step.get("action") or step.get("relation") or step.get("type")
        if not rel:
            continue
        lbl = label_fn(str(rel))
        if lbl.lower() in seen:
            continue
        seen.add(lbl.lower())
        techniques.append(lbl)

    step_count = len([s for s in steps if isinstance(s, (dict, str))])
    step_word = "step" if step_count == 1 else "steps"
    status_phrase = _STATUS_PHRASE.get(status_raw, _STATUS_PHRASE["theoretical"])

    source_phrase = source if source_is_placeholder else source
    target_phrase = target if target_is_placeholder else target

    parts: list[str] = []
    if len(nodes) >= 2:
        parts.append(
            f"Starting from {source_phrase}, an attacker can reach "
            f"{target_phrase} in {step_count} {step_word}."
        )
    else:
        parts.append(f"This path targets {target_phrase}.")

    if techniques:
        if len(techniques) == 1:
            parts.append(f"The path abuses {techniques[0]}.")
        elif len(techniques) == 2:
            parts.append(f"The path chains {techniques[0]} and {techniques[1]}.")
        else:
            head = ", ".join(techniques[:-1])
            parts.append(f"The path chains {head}, and {techniques[-1]}.")

    parts.append(f"This attack path {status_phrase}.")
    return " ".join(parts)
