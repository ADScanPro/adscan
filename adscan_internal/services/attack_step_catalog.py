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

remediation_complexity values:
  low        – Single GPO/registry/ACL change, minimal testing required.
  medium     – Configuration change requiring planning and testing; possible service impact.
  high       – Significant infrastructure change or architectural limitation; operational risk.
  very_high  – Requires architecture overhaul, PKI rebuild, or has persistent attacker capability.

can_fully_mitigate:
  True   – The step can be fully eliminated from attack paths.
  False  – The step is architecturally inherent to Windows AD (e.g., unconstrained delegation
           on DCs); the risk can only be reduced, not eliminated.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal


SupportKind = Literal["supported", "unsupported", "policy_blocked", "context"]

_COMPLEXITY_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "very_high": 3}


@dataclass(frozen=True, slots=True)
class AttackStepCatalogEntry:
    """Definition for one attack-step relation."""

    relation: str
    support_kind: SupportKind
    support_reason: str
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


def _entry(
    relation: str,
    *,
    support_kind: SupportKind,
    support_reason: str,
    category: str,
    description: str,
    vuln_key: str | None = None,
    remediation_complexity: str = "medium",
    remediation_effort: str = "",
    can_fully_mitigate: bool = True,
    mitre_technique_id: str | None = None,
    mitre_technique_name: str | None = None,
    detection_event_ids: tuple[str, ...] = (),
) -> AttackStepCatalogEntry:
    """Build a normalized catalog entry."""
    return AttackStepCatalogEntry(
        relation=str(relation or "").strip().lower(),
        support_kind=support_kind,
        support_reason=support_reason,
        category=category,
        description=description,
        vuln_key=vuln_key,
        remediation_complexity=remediation_complexity,
        remediation_effort=remediation_effort,
        can_fully_mitigate=can_fully_mitigate,
        mitre_technique_id=mitre_technique_id,
        mitre_technique_name=mitre_technique_name,
        detection_event_ids=detection_event_ids,
    )


_CATALOG_ENTRIES: tuple[AttackStepCatalogEntry, ...] = (
    # ── Context / expansion ─────────────────────────────────────────────────
    _entry(
        "memberof",
        support_kind="context",
        support_reason="Context only (membership expansion); not executed",
        category="context",
        description="Group membership pivot used for path expansion",
        remediation_complexity="low",
        remediation_effort="Remove the user/group from the over-privileged group.",
        can_fully_mitigate=True,
        # No MITRE — pure graph context node, not an attack technique
    ),
    _entry(
        "localadminpassreuse",
        support_kind="context",
        support_reason="Observed local admin password reuse pivot; no direct execution step",
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
    ),
    # ── Kerberos ────────────────────────────────────────────────────────────
    _entry(
        "allowedtodelegate",
        support_kind="supported",
        support_reason="Kerberos delegation exploitation (constrained/unconstrained)",
        category="delegation",
        description="Abuse delegation rights to obtain elevated service tickets",
        vuln_key="unconstrained_delegation",
        remediation_complexity="high",
        remediation_effort=(
            "Remove unconstrained delegation from the account if not required. "
            "For DCs: cannot be removed (architecturally required). "
            "Mitigate by marking sensitive accounts with 'Account is sensitive and cannot be delegated', "
            "blocking coercion techniques via firewall rules on DC ports (135, 139, 445)."
        ),
        can_fully_mitigate=False,
        mitre_technique_id="T1558",
        mitre_technique_name="Steal or Forge Kerberos Tickets",
        detection_event_ids=("4769",),
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
    ),
    _entry(
        "coercetotgt",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
        category="delegation",
        description="Coerce a target into providing a usable TGT for delegation abuse",
        remediation_complexity="medium",
        remediation_effort=(
            "Block authentication coercion by disabling vulnerable RPC endpoints. "
            "Enable EPA on LDAP and ADCS. Mark sensitive accounts as delegation-exempt."
        ),
        can_fully_mitigate=True,
        mitre_technique_id="T1187",
        mitre_technique_name="Forced Authentication",
        detection_event_ids=("4768", "4769"),
    ),
    _entry(
        "kerberoasting",
        support_kind="supported",
        support_reason="Extract and crack Kerberos TGS hashes for a target user",
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
    ),
    _entry(
        "asreproasting",
        support_kind="supported",
        support_reason="Extract and crack Kerberos AS-REP hashes for a target user",
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
    ),
    # ── Lateral movement / execution ────────────────────────────────────────
    _entry(
        "adminto",
        support_kind="supported",
        support_reason="Confirm local admin access via SMB (AdminTo)",
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
    ),
    _entry(
        "sqladmin",
        support_kind="supported",
        support_reason="Confirm MSSQL administrative access (SQLAdmin)",
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
    ),
    _entry(
        "canrdp",
        support_kind="supported",
        support_reason="Confirm RDP login capability (CanRDP)",
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
    ),
    _entry(
        "canpsremote",
        support_kind="supported",
        support_reason="Confirm remote PowerShell/WinRM capability (CanPSRemote)",
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
    ),
    # ── ADCS / PKI ──────────────────────────────────────────────────────────
    _entry(
        "adcsesc1",
        support_kind="supported",
        support_reason="Request an authentication certificate via ADCS ESC1",
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
    ),
    _entry(
        "adcsesc2",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
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
    ),
    _entry(
        "adcsesc3",
        support_kind="supported",
        support_reason="Request an agent certificate and impersonate a target via ADCS ESC3",
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
    ),
    _entry(
        "adcsesc4",
        support_kind="supported",
        support_reason="Make a certificate template vulnerable via ADCS ESC4",
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
    ),
    _entry(
        "adcsesc5",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
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
    ),
    _entry(
        "adcsesc6",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
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
    ),
    _entry(
        "adcsesc7",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
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
    ),
    _entry(
        "adcsesc8",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
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
    ),
    _entry(
        "adcsesc9",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
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
    ),
    _entry(
        "adcsesc10",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
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
    ),
    _entry(
        "adcsesc11",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
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
    ),
    _entry(
        "adcsesc13",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
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
    ),
    _entry(
        "adcsesc15",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
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
    ),
    _entry(
        "coerceandrelayntlmtoadcs",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
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
    ),
    # ── ACL / Object control ─────────────────────────────────────────────────
    _entry(
        "genericall",
        support_kind="supported",
        support_reason="ACL/ACE abuse (GenericAll)",
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
    ),
    _entry(
        "genericwrite",
        support_kind="supported",
        support_reason="ACL/ACE abuse (GenericWrite)",
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
    ),
    _entry(
        "forcechangepassword",
        support_kind="supported",
        support_reason="ACL/ACE abuse (ForceChangePassword)",
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
    ),
    _entry(
        "addself",
        support_kind="supported",
        support_reason="ACL/ACE abuse (AddSelf)",
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
    ),
    _entry(
        "addmember",
        support_kind="supported",
        support_reason="ACL/ACE abuse (AddMember)",
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
    ),
    _entry(
        "readgmsapassword",
        support_kind="supported",
        support_reason="ACL/ACE abuse (ReadGMSAPassword)",
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
    ),
    _entry(
        "readlapspassword",
        support_kind="supported",
        support_reason="ACL/ACE abuse (ReadLAPSPassword)",
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
    ),
    _entry(
        "writedacl",
        support_kind="supported",
        support_reason="ACL/ACE abuse (WriteDacl)",
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
    ),
    _entry(
        "writeowner",
        support_kind="supported",
        support_reason="ACL/ACE abuse (WriteOwner)",
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
    ),
    _entry(
        "writespn",
        support_kind="supported",
        support_reason="ACL/ACE abuse (WriteSPN / targeted Kerberoast)",
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
    ),
    # ── Entry vectors ────────────────────────────────────────────────────────
    _entry(
        "passwordspray",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
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
    ),
    _entry(
        "passwordinshare",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
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
    ),
    _entry(
        "gpppassword",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
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
    ),
    _entry(
        "userdescription",
        support_kind="unsupported",
        support_reason="Not implemented yet in ADscan",
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
    ),
)

ATTACK_STEP_CATALOG: dict[str, AttackStepCatalogEntry] = {
    entry.relation: entry for entry in _CATALOG_ENTRIES if entry.relation
}

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


def get_exploitation_relation_vuln_keys() -> dict[str, str]:
    """Return relation->vuln_key mappings for exploitation-style classification."""
    return {
        relation: str(entry.vuln_key)
        for relation, entry in ATTACK_STEP_CATALOG.items()
        if isinstance(entry.vuln_key, str) and entry.vuln_key.strip()
    }


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
