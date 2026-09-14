"""CVSS 3.1 Base vectors + ADscan contextual risk overlay.

IMPORTANT
---------
- ``cvss_vector`` is ONLY the CVSS v3.1 Base vector.
- ``elevation_rules`` are ADscan contextual severity overlays for prioritization
  and reporting. They are NOT CVSS Base metrics.
- If a finding is primarily posture, attack-graph state, or a chaining
  prerequisite rather than a clean standalone vulnerability, ``cvss_vector``
  is set to ``None``. In those cases, use ADscan contextual severity rather
  than pretending there is a formal Base CVSS.

Why this split matters
----------------------
CVSS Base must describe intrinsic characteristics of the vulnerability that are
stable across environments. Asset criticality (Tier-0, DC, crown jewel),
confirmed exploitation, and attack-path amplification are environment/threat
context, not Base CVSS.

References
----------
- FIRST CVSS v3.1 specification / user guide
- FIRST CVSS v4.0 specification / implementation guide
- NVD / MSRC for concrete CVE vectors
"""

from __future__ import annotations

from dataclasses import dataclass, field

from adscan_core.cvss.models import (
    CONDITION_DC_TARGETS,
    CONDITION_EXPLOITATION,
    CONDITION_RELAY_CONFIRMED,
    CONDITION_TIER_ZERO,
    CvssElevationRule,
    FindingType,
)


@dataclass
class VulnCvssDefinition:
    """Base CVSS metadata plus ADscan contextual severity rules.

    Attributes:
        finding_type:
            Canonical taxonomy classification (Vulnerability / Chain
            Prerequisite / Posture). Drives how the calculator combines the
            base score and elevation rules. See ``FindingType`` docstring
            for the scoring contract per category.
        cvss_vector:
            Formal CVSS 3.1 Base vector string, or ``None`` if the finding is
            not cleanly representable as a standalone Base CVSS issue. Must
            be ``None`` for ``CHAIN_PREREQUISITE`` and ``POSTURE`` types —
            the calculator validates this at startup.
        elevation_rules:
            ADscan contextual severity overlays evaluated in declaration order.
            First match wins. These are NOT part of CVSS Base.
    """

    finding_type: FindingType
    cvss_vector: str | None
    elevation_rules: list[CvssElevationRule] = field(default_factory=list)


CVSS_RULES: dict[str, VulnCvssDefinition] = {
    # ------------------------------------------------------------------
    # Kerberos roasting
    # ------------------------------------------------------------------
    "kerberoast": VulnCvssDefinition(
        # Authenticated attacker can request a TGS and obtain offline-crackable
        # credential material. Direct impact is limited disclosure, not
        # guaranteed plaintext compromise.
        finding_type=FindingType.VULNERABILITY,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=8.8,
                reason=(
                    "Kerberoastable Tier-0/high-value accounts detected. "
                    "Successful cracking would expose privileged credentials"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=8.0,
                reason="Hash cracking confirmed: plaintext credential recovered",
            ),
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=7.5,
                reason=(
                    "Kerberoastable DC-related service accounts detected. "
                    "Credential compromise materially improves DC attack paths"
                ),
            ),
        ],
    ),
    "asreproast": VulnCvssDefinition(
        # Same reasoning as Kerberoast, but PR:N because pre-auth is disabled.
        # The direct outcome is still offline-crackable credential material,
        # not guaranteed plaintext compromise.
        finding_type=FindingType.VULNERABILITY,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.1,
                reason=(
                    "AS-REP roastable Tier-0/high-value accounts detected. "
                    "Unauthenticated credential material retrieval affects "
                    "privileged identities"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=8.8,
                reason="Hash cracking confirmed: plaintext credential recovered",
            ),
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=8.0,
                reason=(
                    "DC-related accounts are AS-REP roastable. "
                    "Unauthenticated credential material retrieval impacts "
                    "critical identities"
                ),
            ),
        ],
    ),

    # ------------------------------------------------------------------
    # Delegation
    # ------------------------------------------------------------------
    "unconstrained_delegation": VulnCvssDefinition(
        # Dangerous posture/attack-path amplifier, but not a clean standalone
        # CVSS Base issue without modeling an additional foothold on the host.
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.5,
                reason=(
                    "Unconstrained delegation reachable by Tier-0 principals. "
                    "The TGT capture path can yield immediate privileged compromise"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.8,
                reason="TGT capture confirmed: pass-the-ticket is viable",
            ),
        ],
    ),
    "constrained_delegation": VulnCvssDefinition(
        # Similar problem: strong attack-path signal, but the standalone Base
        # vector is highly dependent on the delegated SPNs and how you reach the
        # principal that can perform S4U abuse.
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=8.5,
                reason=(
                    "Constrained delegation reaches Tier-0 services. "
                    "An effective privileged impersonation path exists"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=8.0,
                reason=(
                    "Constrained delegation reaches DC services. "
                    "An effective DC lateral movement path exists"
                ),
            ),
        ],
    ),

    # ------------------------------------------------------------------
    # SMB
    # ------------------------------------------------------------------
    "smb_relay_targets": VulnCvssDefinition(
        # Relay target posture. Adjacent + High complexity is reasonable in v3.1
        # because exploitation generally needs MITM/coercion/on-path conditions.
        finding_type=FindingType.CHAIN_PREREQUISITE,
        cvss_vector="CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=9.0,
                reason=(
                    "DCs are relayable SMB targets. Relaying to a DC meaningfully "
                    "raises privilege-escalation potential"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.0,
                reason=(
                    "Tier-0 assets are relayable SMB targets. "
                    "Captured authentication can yield privileged access"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.0,
                reason="SMB relay confirmed: authenticated session obtained",
            ),
        ],
    ),
    "smb_null_domain": VulnCvssDefinition(
        finding_type=FindingType.VULNERABILITY,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=7.5,
                reason=(
                    "Null session accepted on DCs. "
                    "Unauthenticated domain enumeration expands the attack surface"
                ),
            ),
        ],
    ),
    "smb_guest_shares": VulnCvssDefinition(
        # Model this as read exposure. If you also detect anonymous/guest write,
        # split that into a separate finding instead of baking I:L here.
        finding_type=FindingType.VULNERABILITY,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=9.0,
                reason=(
                    "Guest-accessible shares on DCs materially raise the chance "
                    "of policy/secrets exposure"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.0,
                reason="Credential material recovered from guest-accessible shares",
            ),
        ],
    ),
    "smbv1_enabled": VulnCvssDefinition(
        # SMBv1 enabled is posture, not the CVE itself. Do not pretend it is
        # equivalent to EternalBlue-class RCE unless you separately detected a
        # concrete vulnerable build/CVE. Elevation stays in Medium territory
        # because "protocol enabled" is not "host vulnerable".
        finding_type=FindingType.CHAIN_PREREQUISITE,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=6.5,
                reason=(
                    "SMBv1 enabled on DCs. Legacy protocol surface; not equivalent "
                    "to a confirmed CVE such as EternalBlue (MS17-010)"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=6.5,
                reason=(
                    "SMBv1 enabled on Tier-0 assets. Legacy protocol surface; "
                    "confirm a concrete CVE before treating as critical"
                ),
            ),
        ],
    ),
    "smb_share_secrets": VulnCvssDefinition(
        # Authenticated exposure of credential material in shares.
        finding_type=FindingType.VULNERABILITY,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.5,
                reason=(
                    "Credentials found in shares belong to or enable Tier-0 "
                    "access. A direct privileged path exists"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.0,
                reason="Exposed credentials verified: valid account access confirmed",
            ),
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=8.8,
                reason="Credential material found in DC-relevant share exposure",
            ),
        ],
    ),

    # ------------------------------------------------------------------
    # LDAP
    # ------------------------------------------------------------------
    "ldap_anonymous": VulnCvssDefinition(
        finding_type=FindingType.VULNERABILITY,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=7.5,
                reason=(
                    "Anonymous LDAP bind accepted on DCs. "
                    "Directory enumeration is available without authentication"
                ),
            ),
        ],
    ),
    "ldap_security_posture": VulnCvssDefinition(
        # Signing/channel binding not enforced -> relay posture. This is
        # defensible as a standalone misconfiguration because the service itself
        # lacks required integrity protections.
        finding_type=FindingType.CHAIN_PREREQUISITE,
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=9.0,
                reason=(
                    "LDAP protections not enforced on DCs. "
                    "Relaying to LDAP can enable privileged directory operations"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.0,
                reason="LDAP relay exploitation confirmed",
            ),
        ],
    ),

    # ------------------------------------------------------------------
    # GPP
    # ------------------------------------------------------------------
    "gpp_passwords": VulnCvssDefinition(
        # Direct issue is credential disclosure to any authenticated domain user.
        # Do not mark integrity impact in the Base vector just because the
        # recovered credential might later be used to modify things. The contextual
        # overlay reaches Critical ONLY on a proven chain into a Tier-0 terminal —
        # a recovery/decryption alone stays High, so the render matches the
        # edge-severity verdict (CRITICAL only when the forward chain reaches
        # Tier-0, else HIGH) and never overclaims domain compromise.
        finding_type=FindingType.VULNERABILITY,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.5,
                reason=(
                    "GPP credentials grant Tier-0 access. "
                    "Trivial decryption yields privileged credential material"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=8.5,
                reason="GPP credentials decrypted and verified",
            ),
        ],
    ),
    "gpp_autologin": VulnCvssDefinition(
        finding_type=FindingType.VULNERABILITY,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.5,
                reason=(
                    "Autologin credentials enable Tier-0 access. "
                    "Credential disclosure directly affects privileged identities"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.0,
                reason="Autologin credentials decrypted and verified",
            ),
        ],
    ),

    # ------------------------------------------------------------------
    # LAPS
    # ------------------------------------------------------------------
    "laps": VulnCvssDefinition(
        # POSTURE finding: LAPS not deployed on the affected hosts.
        # No formal CVSS vector — this is absence of a control, not an exploit.
        # Elevation stays Medium/Medium-High because a missing rotation
        # control on a DC widens blast radius of any future credential leak,
        # but by itself does not confirm exposure. The credential-readable
        # case lives in `laps_readable` and remains High/Critical there.
        finding_type=FindingType.POSTURE,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=7.0,
                reason=(
                    "LAPS not deployed on Domain Controllers. Static local "
                    "admin credentials on DCs widen the blast radius of any "
                    "credential leak; no exposure confirmed yet"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=7.0,
                reason=(
                    "LAPS not deployed on Tier-0 assets. Privileged hosts "
                    "rely on a static local admin secret"
                ),
            ),
        ],
    ),
    "laps_readable": VulnCvssDefinition(
        finding_type=FindingType.VULNERABILITY,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=9.0,
                reason=(
                    "LAPS attributes readable for DCs. "
                    "Non-admin principals can retrieve DC local admin secrets"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=8.8,
                reason=(
                    "LAPS attributes readable for Tier-0 assets: "
                    "privileged local admin credential exposure"
                ),
            ),
        ],
    ),

    # ------------------------------------------------------------------
    # Account hygiene / identity posture
    # ------------------------------------------------------------------
    "password_not_req": VulnCvssDefinition(
        # Weak-account posture modeled conservatively as low C/I impact.
        finding_type=FindingType.VULNERABILITY,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=8.5,
                reason=(
                    "Tier-0 accounts do not require a password. "
                    "Privileged account takeover risk is extreme"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=8.5,
                reason="Empty-password account access confirmed",
            ),
        ],
    ),
    "password_never_expires": VulnCvssDefinition(
        # Exposure posture only; do not force a formal Base CVSS.
        finding_type=FindingType.POSTURE,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=6.5,
                reason=(
                    "Tier-0 accounts have non-expiring passwords. "
                    "Stale privileged credentials persist indefinitely"
                ),
            ),
        ],
    ),
    "stale_enabled_users": VulnCvssDefinition(
        finding_type=FindingType.POSTURE,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=6.0,
                reason=(
                    "Dormant enabled accounts include Tier-0/high-value identities"
                ),
            ),
        ],
    ),
    "stale_passwords": VulnCvssDefinition(
        # Passwords set before the last policy modification — credentials may
        # not comply with the current policy and have never been rotated since
        # requirements were tightened.
        finding_type=FindingType.POSTURE,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=6.0,
                reason=(
                    "Privileged accounts carry credentials that predate the last "
                    "policy hardening. Stale high-value credentials persist under "
                    "weaker historical requirements"
                ),
            ),
        ],
    ),
    "machine_account_quota_risk": VulnCvssDefinition(
        # MAQ > 0 is the AD provisioning default — an enabler for RBCD/ADCS-ESC8
        # attacks, not confirmed exploitation on its own.
        finding_type=FindingType.POSTURE,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=8.8,
                reason=(
                    "MAQ abuse confirmed: an attacker added a machine account and "
                    "used it for RBCD or ADCS-ESC8 privilege escalation"
                ),
            ),
        ],
    ),
    "smb_v1_enabled": VulnCvssDefinition(
        # SMBv1 is deprecated with known critical CVEs (EternalBlue MS17-010).
        # HIGH baseline regardless of patch status — the protocol itself is unsafe.
        # Escalates to CRITICAL on DCs (Tier-0) or when exploitation is confirmed.
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.0,
                reason=(
                    "Domain Controller with SMBv1 enabled. EternalBlue on a DC "
                    "yields direct OS-level access to the Kerberos trust root"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.8,
                reason="SMBv1 exploit confirmed: remote code execution achieved",
            ),
        ],
    ),
    "smb_signing_disabled": VulnCvssDefinition(
        # SMB signing not required — enables NTLM relay attacks.
        # Severity escalates on DCs (Tier-0) because they are the highest-value
        # relay target. Further escalates when relay exploitation is confirmed.
        finding_type=FindingType.POSTURE,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=8.0,
                reason=(
                    "Domain Controller with SMB signing not required. An ideal relay "
                    "target; successful relay against a DC yields LDAP/SMB access "
                    "as the DC machine account"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.0,
                reason=(
                    "NTLM relay via unsigned SMB confirmed: credential relayed "
                    "and used to authenticate to a target service"
                ),
            ),
        ],
    ),
    "password_not_required": VulnCvssDefinition(
        # PASSWD_NOTREQD UAC flag — account is exempt from the domain password
        # requirement and may have a blank password. Posture-only until a blank-
        # password spray confirms it, at which point it escalates to HIGH.
        finding_type=FindingType.POSTURE,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=6.0,
                reason=(
                    "Privileged account with PASSWD_NOTREQD set. A blank or absent "
                    "credential on a Tier-0 identity is a direct domain threat"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.0,
                reason=(
                    "Blank password confirmed via spray: the account has no credential "
                    "and authentication succeeds with an empty string"
                ),
            ),
        ],
    ),
    "krbtgt_password_age": VulnCvssDefinition(
        # Hygiene/rotation finding. Golden Ticket forgery requires the krbtgt
        # hash (DCSync, which already implies DA). Promotes to CRITICAL only when
        # secret recovery or Golden Ticket usage is observed — that path is
        # tracked separately by the krbtgt_pass finding.
        finding_type=FindingType.POSTURE,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.8,
                reason=(
                    "krbtgt hash recovered or Golden Ticket usage confirmed. "
                    "Indefinite domain persistence is available until rotation"
                ),
            ),
        ],
    ),
    "tier0_highvalue_sprawl": VulnCvssDefinition(
        finding_type=FindingType.POSTURE,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=8.5,
                reason=(
                    "Confirmed attack path was enabled by privileged identity sprawl"
                ),
            ),
        ],
    ),

    # ------------------------------------------------------------------
    # Sessions / compromise state
    # ------------------------------------------------------------------
    "da_sessions": VulnCvssDefinition(
        # This is an exposure/attack-path state, not a clean standalone CVSS
        # vulnerability.
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.5,
                reason="DA session actively harvested: privileged credential confirmed",
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.0,
                reason=(
                    "DA sessions present on hosts with privileged attack paths"
                ),
            ),
        ],
    ),
    "krbtgt_pass": VulnCvssDefinition(
        # Ambiguous catalog key. If this means "KRBTGT secret recovered", that is
        # a confirmed compromise state, not CVSS. If it means "KRBTGT password
        # hygiene issue", it is posture. Split the catalog key later if needed.
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.8,
                reason=(
                    "KRBTGT secret material was recovered or validated. "
                    "Golden Ticket persistence is available"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.0,
                reason="KRBTGT/Tier-0 credential exposure affects the Kerberos trust root",
            ),
        ],
    ),

    # ------------------------------------------------------------------
    # Concrete CVEs / vendor-scored issues
    # ------------------------------------------------------------------
    "zerologon": VulnCvssDefinition(
        # NVD official CVSS 3.1
        finding_type=FindingType.VULNERABILITY,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        elevation_rules=[],
    ),
    "nopac": VulnCvssDefinition(
        # Composite attack name, not a single CVE. Split into the underlying
        # CVEs (e.g. 42278 / 42287) if you want formal CVSS.
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[],
    ),
    "printnightmare": VulnCvssDefinition(
        # Microsoft/NVD 8.8
        finding_type=FindingType.VULNERABILITY,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        elevation_rules=[],
    ),
    "ms17-010": VulnCvssDefinition(
        # Bulletin/rollup label rather than a single CVE. Prefer exact CVE keys
        # if you want formal vendor/NVD vectors.
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[],
    ),

    # ------------------------------------------------------------------
    # Coercion / chain prerequisites
    # ------------------------------------------------------------------
    # NOTE: Coercion primitives (PetitPotam, DFSCoerce, MS-EFSRPC, PrinterBug)
    # are NOT vulnerabilities by themselves. They produce impact only when
    # chained with a vulnerable relay target (ADCS Web Enrollment without EPA,
    # LDAP without signing/CB, SMB without signing). Without that chain
    # confirmed in the same workspace, they are Medium-grade attack-chain
    # prerequisites — not High and certainly not Critical. Inflating these
    # scores is exactly what blue teams reject as "vendor padding".
    "petitpotam": VulnCvssDefinition(
        finding_type=FindingType.CHAIN_PREREQUISITE,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.2,
                reason=(
                    "PetitPotam coercion was chained into a confirmed "
                    "relay/certificate/LDAP abuse outcome"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_RELAY_CONFIRMED,
                elevated_score=8.5,
                reason=(
                    "PetitPotam coercion + a vulnerable relay target was "
                    "identified in this workspace (e.g. ADCS Web Enrollment "
                    "without EPA, or LDAP without signing/CB). The full chain "
                    "is materially viable"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=6.5,
                reason=(
                    "PetitPotam coercion primitive against a Domain Controller. "
                    "No vulnerable relay target was confirmed in this workspace; "
                    "chain to ADCS ESC8 or LDAP-no-signing required for impact"
                ),
            ),
        ],
    ),
    "dfscoerce": VulnCvssDefinition(
        finding_type=FindingType.CHAIN_PREREQUISITE,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.2,
                reason=(
                    "DFSCoerce was chained into a confirmed "
                    "relay/certificate/LDAP abuse outcome"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_RELAY_CONFIRMED,
                elevated_score=8.5,
                reason=(
                    "DFSCoerce + a vulnerable relay target was identified "
                    "in this workspace. A chain to ADCS or LDAP-no-signing "
                    "is materially viable"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=6.5,
                reason=(
                    "DFSCoerce primitive against a Domain Controller. No "
                    "vulnerable relay target was confirmed in this workspace; "
                    "chain to ADCS ESC8 or LDAP-no-signing required for impact"
                ),
            ),
        ],
    ),
    "mseven": VulnCvssDefinition(
        finding_type=FindingType.CHAIN_PREREQUISITE,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.2,
                reason=(
                    "MS-EFSRPC coercion was chained into a confirmed "
                    "relay/certificate/LDAP abuse outcome"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_RELAY_CONFIRMED,
                elevated_score=8.5,
                reason=(
                    "MS-EFSRPC coercion + a vulnerable relay target was "
                    "identified in this workspace. A chain to ADCS or "
                    "LDAP-no-signing is materially viable"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=6.5,
                reason=(
                    "MS-EFSRPC coercion primitive against a Domain Controller. "
                    "No vulnerable relay target was confirmed in this workspace; "
                    "chain to ADCS ESC8 or LDAP-no-signing required for impact"
                ),
            ),
        ],
    ),
    "printerbug": VulnCvssDefinition(
        finding_type=FindingType.CHAIN_PREREQUISITE,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.0,
                reason=(
                    "PrinterBug coercion was chained into a confirmed relay abuse outcome"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_RELAY_CONFIRMED,
                elevated_score=8.5,
                reason=(
                    "PrinterBug + a vulnerable relay target was identified "
                    "in this workspace. A chain to ADCS or LDAP-no-signing "
                    "is materially viable"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=6.5,
                reason=(
                    "PrinterBug coercion primitive against a Domain Controller. "
                    "No vulnerable relay target was confirmed in this workspace; "
                    "chain to ADCS ESC8 or LDAP-no-signing required for impact"
                ),
            ),
        ],
    ),
    "webdav": VulnCvssDefinition(
        # WebDAV enabled is a chain helper / coercion surface, not a formal Base
        # CVSS issue by itself.
        finding_type=FindingType.CHAIN_PREREQUISITE,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=8.0,
                reason=(
                    "WebDAV on DC-related assets increases relay/coercion path viability"
                ),
            ),
        ],
    ),

    # ------------------------------------------------------------------
    # Active Directory Certificate Services
    # ------------------------------------------------------------------
    "adcs_esc8": VulnCvssDefinition(
        # AD CS relay exposure. The standalone posture is high; it becomes
        # critical only when ADscan confirms a relay/certificate abuse outcome
        # or an explicit Tier-0/DC-impacting path.
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.5,
                reason="AD CS relay/certificate abuse was confirmed",
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.0,
                reason="ESC8 provides a Tier-0 certificate abuse path",
            ),
        ],
    ),
    "adcs_esc11": VulnCvssDefinition(
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.5,
                reason="AD CS RPC relay/certificate abuse was confirmed",
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.0,
                reason="ESC11 provides a Tier-0 certificate abuse path",
            ),
        ],
    ),

    "certifried": VulnCvssDefinition(
        # Microsoft/NVD 8.8
        finding_type=FindingType.VULNERABILITY,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        elevation_rules=[],
    ),

    # ------------------------------------------------------------------
    # ADCS ESC variants without dedicated rules above.
    # All follow the same model as ESC8: standalone misconfiguration is
    # high-severity posture; Critical only when ADscan confirms enrollment
    # abuse, certificate request, or a Tier-0 certificate path.
    # ------------------------------------------------------------------
    "adcs_esc1": VulnCvssDefinition(
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.9,
                reason="ESC1 abuse confirmed: certificate enrollment with attacker-supplied SAN succeeded",
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.0,
                reason="ESC1 template enables Tier-0 impersonation via SAN-supplied certificate",
            ),
        ],
    ),
    "adcs_esc2": VulnCvssDefinition(
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.9,
                reason="ESC2 abuse confirmed: 'Any Purpose' EKU certificate issued",
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.0,
                reason="ESC2 'Any Purpose' template usable for Tier-0 client authentication",
            ),
        ],
    ),
    "adcs_esc3": VulnCvssDefinition(
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.9,
                reason="ESC3 abuse confirmed: enrollment-agent certificate used to enroll on behalf of privileged user",
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.0,
                reason="ESC3 enrollment-agent template enables Tier-0 enrollment-on-behalf-of",
            ),
        ],
    ),
    "adcs_esc4": VulnCvssDefinition(
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.9,
                reason="ESC4 abuse confirmed: vulnerable template ACL was modified to enable certificate abuse",
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.0,
                reason="ESC4 template ACL grants modification rights affecting Tier-0 enrollment",
            ),
        ],
    ),
    "adcs_esc5": VulnCvssDefinition(
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.9,
                reason="ESC5 abuse confirmed: PKI object ACL modification enabled certificate abuse",
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.0,
                reason="ESC5 PKI ACL exposure affects Tier-0 trust",
            ),
        ],
    ),
    "adcs_esc6": VulnCvssDefinition(
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.9,
                reason="ESC6 abuse confirmed: EDITF_ATTRIBUTESUBJECTALTNAME2 used to inject attacker-supplied SAN",
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.0,
                reason="ESC6 CA flag enables Tier-0 impersonation via SAN injection on any template",
            ),
        ],
    ),
    "adcs_esc7": VulnCvssDefinition(
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.9,
                reason="ESC7 abuse confirmed: CA management rights used to issue privileged certificate",
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.0,
                reason="ESC7 CA management rights enable Tier-0 certificate issuance",
            ),
        ],
    ),
    "adcs_esc9": VulnCvssDefinition(
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.9,
                reason="ESC9 abuse confirmed: no security extension allowed certificate-based authentication bypass",
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.0,
                reason="ESC9 template lacks security extension on Tier-0-relevant authentication path",
            ),
        ],
    ),
    "adcs_esc10": VulnCvssDefinition(
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.5,
                reason="ESC10 abuse confirmed: weak certificate mapping enabled authentication bypass",
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=8.8,
                reason="ESC10 weak certificate mapping affects Tier-0 authentication",
            ),
        ],
    ),
    "adcs_esc13": VulnCvssDefinition(
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.9,
                reason="ESC13 abuse confirmed: OID group link granted unintended group membership via certificate",
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.0,
                reason="ESC13 OID group link reaches a Tier-0 group",
            ),
        ],
    ),
    "adcs_esc14": VulnCvssDefinition(
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.5,
                reason="ESC14 abuse confirmed: weak explicit certificate mapping enabled authentication bypass",
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.0,
                reason="ESC14 explicit mapping weakness affects Tier-0 authentication",
            ),
        ],
    ),
    "adcs_esc15": VulnCvssDefinition(
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.5,
                reason="ESC15 abuse confirmed: schema v1 template injection enabled certificate abuse",
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=8.8,
                reason="ESC15 schema v1 template usable for Tier-0 abuse",
            ),
        ],
    ),
    "adcs_esc16": VulnCvssDefinition(
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.5,
                reason="ESC16 abuse confirmed: CA-wide security extension disabled enabled certificate abuse",
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.0,
                reason="ESC16 CA-wide extension disabled affects Tier-0 authentication",
            ),
        ],
    ),
    "adcs_esc17": VulnCvssDefinition(
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.5,
                reason="ESC17 abuse confirmed: certificate misuse path validated end-to-end",
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=8.8,
                reason="ESC17 misconfiguration reaches a Tier-0 certificate authentication path",
            ),
        ],
    ),

    # ------------------------------------------------------------------
    # Privilege / ACL / delegation
    # ------------------------------------------------------------------
    "gmsa_readable": VulnCvssDefinition(
        # Same model as laps_readable: a non-admin principal can read the
        # service-account password. Direct credential exposure on a privileged
        # account.
        finding_type=FindingType.VULNERABILITY,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.0,
                reason="gMSA password retrieved by an unprivileged principal",
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.0,
                reason="gMSA exposes credentials of a Tier-0 service account",
            ),
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=8.8,
                reason="gMSA password readable on a Domain Controller: direct privileged access",
            ),
        ],
    ),
    "dcsync": VulnCvssDefinition(
        # DCSync rights assigned (posture) is distinct from DCSync executed.
        # If exploitation_confirmed, this is a domain compromise — 9.9.
        # If only the ACL is detected, that is High but not Critical until
        # someone replays it. Note: catalog Base remains for backward compat;
        # contextual elevation is what differentiates.
        finding_type=FindingType.VULNERABILITY,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.9,
                reason="DCSync was executed and credential material was replicated from the DC",
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.5,
                reason="DCSync rights assigned to a non-Tier-0 principal: full domain replication possible",
            ),
        ],
    ),
    "rbcd_exploitable": VulnCvssDefinition(
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.5,
                reason="RBCD abuse confirmed: S4U2Self/Proxy chain produced a privileged ticket",
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.0,
                reason="RBCD writeable on a Tier-0 computer: direct path to privileged impersonation",
            ),
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=9.0,
                reason="RBCD writeable on a Domain Controller object: full DC takeover possible",
            ),
        ],
    ),
    "shadow_credentials_present": VulnCvssDefinition(
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.5,
                reason="Shadow Credentials abuse confirmed: PKINIT authentication produced a TGT for the target",
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.5,
                reason="Shadow Credentials writeable on a Tier-0 principal: PKINIT impersonation path",
            ),
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=9.0,
                reason="Shadow Credentials writeable on a Domain Controller object",
            ),
        ],
    ),
    "force_change_password": VulnCvssDefinition(
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=8.8,
                reason="Force-change-password right exercised: target account credentials reset by the attacker",
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=8.8,
                reason="Force-change-password right grants control over a Tier-0 account password",
            ),
        ],
    ),
    "all_extended_rights": VulnCvssDefinition(
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=8.8,
                reason="All-extended-rights privilege exercised: object compromise confirmed",
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=8.8,
                reason="All-extended-rights granted over a Tier-0 object: full control of the principal",
            ),
        ],
    ),
    "ntlmv1_enabled": VulnCvssDefinition(
        finding_type=FindingType.CHAIN_PREREQUISITE,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.0,
                reason="NTLMv1 negotiation captured and credentials cracked or relayed",
            ),
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=8.5,
                reason="NTLMv1 accepted by Domain Controllers: challenge/response is trivially crackable",
            ),
        ],
    ),
    "credential_in_ldap_attribute": VulnCvssDefinition(
        # Plaintext / recoverable secret stored in a readable LDAP attribute
        # (description, comment, info, custom). Anyone with read on the
        # attribute can pull it.
        finding_type=FindingType.VULNERABILITY,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.0,
                reason="Credential recovered from an LDAP attribute and used to authenticate",
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.5,
                reason="Credential exposed in an LDAP attribute belongs to a Tier-0 principal",
            ),
        ],
    ),
}


def get_vuln_cvss_definition(vuln_key: str) -> VulnCvssDefinition | None:
    return CVSS_RULES.get(vuln_key)
