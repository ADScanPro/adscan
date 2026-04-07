"""Per-vulnerability CVSS 3.1 vectors and contextual elevation rules.

Each entry in ``CVSS_RULES`` maps a vulnerability catalog key to a
``VulnCvssDefinition`` that carries:

- The CVSS 3.1 Base vector string (shown in reports and the web UI).
- An ordered list of ``CvssElevationRule`` objects evaluated against the
  ``CvssContext`` produced at scan-result ingestion time.

Rules are evaluated in declaration order; the **first matching** rule wins.
This means higher-priority conditions (e.g. Tier-0 targets) must be listed
before lower-priority ones (e.g. DC targets only).

Vulnerability keys must match the canonical keys used in ``vuln_catalog.py``
(both the CLI catalog and the web-service catalog).

References:
- CVSS 3.1 Spec: https://www.first.org/cvss/v3.1/specification-document
- NVD calculator:  https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator
"""

from __future__ import annotations

from dataclasses import dataclass, field

from adscan_core.cvss.models import (
    CONDITION_DC_TARGETS,
    CONDITION_EXPLOITATION,
    CONDITION_TIER_ZERO,
    CvssElevationRule,
)


@dataclass
class VulnCvssDefinition:
    """CVSS metadata and contextual elevation rules for one vulnerability type.

    Attributes:
        cvss_vector: CVSS 3.1 Base Score vector string.  ``None`` for
            vulnerability types without a formally assigned vector (e.g.
            detection-only informational findings).
        elevation_rules: Ordered list of rules; first match wins.
            May be empty for vulnerabilities whose severity never changes with
            context (e.g. fixed CVEs like ZeroLogon with score 10.0).
    """

    cvss_vector: str | None
    elevation_rules: list[CvssElevationRule] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Contextual elevation rules catalogue
# Keys must match vuln_catalog.py keys exactly.
# ---------------------------------------------------------------------------

CVSS_RULES: dict[str, VulnCvssDefinition] = {
    # ------------------------------------------------------------------
    # Kerberos attacks
    # ------------------------------------------------------------------
    "kerberoast": VulnCvssDefinition(
        # Base: authenticated user can request TGS, needs offline crack.
        # Confidentiality = Low (hash exposure, not plaintext yet).
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=8.8,
                reason=(
                    "Kerberoastable Tier-0 or high-value accounts detected — "
                    "successful crack directly yields domain-level credential material"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=8.0,
                reason="Hash cracking confirmed — plaintext credential recovered",
            ),
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=7.5,
                reason=(
                    "Domain Controller service accounts are Kerberoastable — "
                    "credential compromise enables DC-level lateral movement"
                ),
            ),
        ],
    ),
    "asreproast": VulnCvssDefinition(
        # Base: no pre-auth required, unauthenticated hash capture possible.
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.1,
                reason=(
                    "AS-REP Roastable Tier-0 accounts detected — unauthenticated "
                    "hash capture of privileged credentials enables direct domain compromise"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=8.8,
                reason="Hash cracking confirmed — plaintext credential of affected account recovered",
            ),
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=8.0,
                reason=(
                    "Domain Controller accounts are AS-REP Roastable — "
                    "credential exposure enables DC authentication without prior access"
                ),
            ),
        ],
    ),
    # ------------------------------------------------------------------
    # Delegation attacks
    # ------------------------------------------------------------------
    "unconstrained_delegation": VulnCvssDefinition(
        # Base: compromising host captures TGTs of all authenticating users
        # including DAs; Scope = Changed (affects other hosts/users).
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.5,
                reason=(
                    "Non-DC host with unconstrained delegation is reachable by Tier-0 principals — "
                    "TGT capture + coercion path yields immediate domain admin"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.8,
                reason="TGT capture confirmed — domain takeover via pass-the-ticket is viable",
            ),
        ],
    ),
    "constrained_delegation": VulnCvssDefinition(
        # Base: impersonation limited to specific services, still dangerous if
        # the allowed service is sensitive.
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=8.5,
                reason=(
                    "Constrained delegation allows impersonation to a Tier-0 service — "
                    "effective domain privilege escalation path exists"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=8.0,
                reason=(
                    "Delegation allows impersonation to Domain Controller services — "
                    "lateral movement to DC is achievable"
                ),
            ),
        ],
    ),
    # ------------------------------------------------------------------
    # SMB
    # ------------------------------------------------------------------
    "smb_relay_targets": VulnCvssDefinition(
        # Base: adjacent-network relay attack; requires capturing auth first.
        cvss_vector="CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=9.0,
                reason=(
                    "Domain Controllers have SMB signing disabled — "
                    "NTLM relay to DC enables LDAP privilege escalation or DCSync"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.0,
                reason=(
                    "Tier-0 assets are relayable SMB targets — "
                    "captured authentication yields immediate privileged access"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.0,
                reason="SMB relay confirmed — authenticated session on target obtained",
            ),
        ],
    ),
    "smb_null_domain": VulnCvssDefinition(
        # Base: unauthenticated enumeration of domain info via null session.
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=7.5,
                reason=(
                    "Null session accepted on Domain Controllers — "
                    "unauthenticated domain enumeration exposes credential attack surface"
                ),
            ),
        ],
    ),
    "smb_guest_shares": VulnCvssDefinition(
        # Base: unauthenticated share access, data exposure without creds.
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=9.0,
                reason=(
                    "Domain Controller shares accessible via guest session — "
                    "SYSVOL/NETLOGON exposure enables GPP and policy credential harvest"
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
        # Base: deprecated protocol on domain hosts, wormable exposure.
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=9.8,
                reason=(
                    "SMBv1 enabled on Domain Controllers — "
                    "EternalBlue/WannaCry-class exploitation path to DC compromise"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.8,
                reason="SMBv1 enabled on Tier-0 assets — direct exploit path to privileged host",
            ),
        ],
    ),
    "smb_share_secrets": VulnCvssDefinition(
        # Base: authenticated access to shares with credential material.
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.5,
                reason=(
                    "Credentials found in shares belong to or enable access to Tier-0 accounts — "
                    "direct path to domain compromise"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.0,
                reason="Exposed credentials successfully verified — confirmed valid account access",
            ),
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=8.8,
                reason="Credential material found on DC-accessible shares",
            ),
        ],
    ),
    # ------------------------------------------------------------------
    # LDAP
    # ------------------------------------------------------------------
    "ldap_anonymous": VulnCvssDefinition(
        # Base: unauthenticated LDAP enumeration of directory data.
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=7.5,
                reason=(
                    "Anonymous LDAP bind accepted on Domain Controllers — "
                    "full unauthenticated directory enumeration accelerates credential attacks"
                ),
            ),
        ],
    ),
    "ldap_security_posture": VulnCvssDefinition(
        # Base: unsigned LDAP allows relay to DC — high impact, high complexity.
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=9.0,
                reason=(
                    "LDAP signing/channel-binding not enforced on DCs — "
                    "NTLM relay to LDAP enables ACL modification, DCSync, or shadow credentials"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.0,
                reason="LDAP relay exploitation confirmed — privileged LDAP operations executed",
            ),
        ],
    ),
    # ------------------------------------------------------------------
    # GPP
    # ------------------------------------------------------------------
    "gpp_passwords": VulnCvssDefinition(
        # Base: any domain user can decrypt SYSVOL cpassword field.
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.5,
                reason=(
                    "GPP credentials belong to or grant access to Tier-0 accounts — "
                    "trivial decryption yields privileged credential material"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.0,
                reason="GPP credentials decrypted and verified — confirmed valid account access",
            ),
        ],
    ),
    "gpp_autologin": VulnCvssDefinition(
        # Base: autologin creds in SYSVOL, any domain user can retrieve.
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.5,
                reason=(
                    "GPP autologin credentials enable Tier-0 access — "
                    "trivial decryption leads to domain privilege escalation"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.0,
                reason="Autologin credentials decrypted and account access confirmed",
            ),
        ],
    ),
    # ------------------------------------------------------------------
    # LAPS
    # ------------------------------------------------------------------
    "laps": VulnCvssDefinition(
        # Base: authenticated user retrieves LAPS password → local admin on host.
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=9.0,
                reason=(
                    "LAPS password readable for Domain Controllers — "
                    "direct local admin access to DC bypasses tiered administration"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=8.8,
                reason=(
                    "LAPS password readable for Tier-0 hosts — "
                    "local admin access to privileged systems enables credential harvesting"
                ),
            ),
        ],
    ),
    "laps_readable": VulnCvssDefinition(
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=9.0,
                reason=(
                    "LAPS attributes readable for Domain Controllers — "
                    "non-admin principals can retrieve DC local administrator credentials"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=8.8,
                reason=(
                    "LAPS attributes readable for Tier-0 assets — "
                    "privilege escalation path via local admin credential exposure"
                ),
            ),
        ],
    ),
    # ------------------------------------------------------------------
    # Account hygiene / policy
    # ------------------------------------------------------------------
    "password_not_req": VulnCvssDefinition(
        # Base: accounts may have no password → unauthenticated access possible.
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=8.5,
                reason=(
                    "Tier-0 accounts have no password required — "
                    "unauthenticated access to privileged accounts is possible"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=8.5,
                reason="Empty-password Tier-0 account access confirmed",
            ),
        ],
    ),
    "password_never_expires": VulnCvssDefinition(
        # Base: informational/hygiene; increases credential-theft probability.
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=6.5,
                reason=(
                    "Tier-0 accounts have non-expiring passwords — "
                    "stale privileged credentials persist indefinitely"
                ),
            ),
        ],
    ),
    "stale_enabled_users": VulnCvssDefinition(
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=8.0,
                reason=(
                    "Stale enabled accounts are Tier-0 or high-value identities — "
                    "dormant privileged accounts significantly increase attack surface"
                ),
            ),
        ],
    ),
    "tier0_highvalue_sprawl": VulnCvssDefinition(
        # Base: identity sprawl finding — always about Tier-0 by definition.
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        elevation_rules=[
            # Exploitation confirmation is the only meaningful escalation here.
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=8.5,
                reason=(
                    "Confirmed exploitation path leverages Tier-0 identity sprawl — "
                    "excess privileged accounts directly enabled the attack"
                ),
            ),
        ],
    ),
    # ------------------------------------------------------------------
    # Privilege / sessions
    # ------------------------------------------------------------------
    "da_sessions": VulnCvssDefinition(
        # Base: DA sessions on workstations allow credential harvest.
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.5,
                reason="DA session on endpoint actively harvested — domain credential confirmed",
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.0,
                reason=(
                    "Domain Admin sessions present on hosts that are Tier-0 or "
                    "have Tier-0 attack paths — session harvest yields immediate DA"
                ),
            ),
        ],
    ),
    "krbtgt_pass": VulnCvssDefinition(
        # Already critical — no elevation needed. Vector shown for transparency.
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        elevation_rules=[],
    ),
    # ------------------------------------------------------------------
    # CVEs — fixed NVD scores, no contextual elevation.
    # Vectors sourced from NVD / MSRC advisories.
    # ------------------------------------------------------------------
    "zerologon": VulnCvssDefinition(
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        elevation_rules=[],
    ),
    "nopac": VulnCvssDefinition(
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        elevation_rules=[],
    ),
    "printnightmare": VulnCvssDefinition(
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        elevation_rules=[],
    ),
    "ms17-010": VulnCvssDefinition(
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        elevation_rules=[],
    ),
    "petitpotam": VulnCvssDefinition(
        # Authentication coercion; actual impact depends on what it's chained with.
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=9.0,
                reason=(
                    "PetitPotam coercion path targets Domain Controllers — "
                    "NTLM relay to ADCS or LDAP enables domain compromise"
                ),
            ),
        ],
    ),
    "dfscoerce": VulnCvssDefinition(
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=9.0,
                reason=(
                    "DFSCoerce coercion path targets Domain Controllers — "
                    "NTLM relay chain to DC enables domain takeover"
                ),
            ),
        ],
    ),
    "mseven": VulnCvssDefinition(
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=9.0,
                reason=(
                    "MS-EFSRPC coercion path targets Domain Controllers — "
                    "relay chain to DC enables privilege escalation"
                ),
            ),
        ],
    ),
    "printerbug": VulnCvssDefinition(
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=8.8,
                reason=(
                    "PrinterBug coercion path targets Domain Controllers — "
                    "DC authentication coercion enables relay attacks"
                ),
            ),
        ],
    ),
    "webdav": VulnCvssDefinition(
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=8.0,
                reason=(
                    "WebDAV enabled on Domain Controllers — "
                    "coercion chain via WebDAV enables NTLM relay to DC services"
                ),
            ),
        ],
    ),
    "certifried": VulnCvssDefinition(
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        elevation_rules=[],
    ),
}


def get_vuln_cvss_definition(vuln_key: str) -> VulnCvssDefinition | None:
    """Return the CVSS definition for *vuln_key*, or ``None`` if not defined.

    Args:
        vuln_key: Canonical vulnerability catalog key (e.g. ``"kerberoast"``).

    Returns:
        ``VulnCvssDefinition`` or ``None``.
    """
    return CVSS_RULES.get(vuln_key)
