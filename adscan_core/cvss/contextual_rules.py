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
        # A configuration finding: the host accepts SMB sessions without
        # signing, so relayed NTLM authentication can be used against it. What
        # the scan PROVED is the setting, not a relay. Medium baseline, High
        # when an affected host is a domain controller or Tier 0, Critical only
        # when a relay against it was actually walked in this run. Graded in
        # lockstep with ``smb_signing_disabled`` (same weakness, second producer).
        finding_type=FindingType.CHAIN_PREREQUISITE,
        cvss_vector="CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=8.0,
                reason=(
                    "A domain controller does not require SMB signing. Relayed "
                    "authentication accepted by a domain controller can reach "
                    "privileged access, so the exposure is rated High"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=8.0,
                reason=(
                    "A Tier 0 host does not require SMB signing. Relayed "
                    "authentication accepted by a Tier 0 host can reach "
                    "privileged access, so the exposure is rated High"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.0,
                reason=(
                    "A relay against an unsigned SMB host was carried out in "
                    "this assessment and produced an authenticated session"
                ),
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
        # concrete vulnerable build/CVE (that is the ``ms17-010`` finding).
        # Medium baseline, High when the affected host is Tier 0 or a DC.
        # Mirrors the canonical ``smb_v1_enabled`` definition below (same
        # weakness, second producer); keep the two in lockstep.
        finding_type=FindingType.CHAIN_PREREQUISITE,
        cvss_vector=None,
        elevation_rules=[
            # DC first: on a tie the earlier rule wins, and "domain controller"
            # is the more specific explanation when the finding carries it.
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=7.5,
                reason=(
                    "SMBv1 is enabled on a domain controller. A domain controller "
                    "that still accepts SMBv1 is exposed to the SMBv1 exploit "
                    "family if it is missing patches. Whether a host is actually "
                    "vulnerable to MS17-010 is tested separately and reported as "
                    "its own finding"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=7.5,
                reason=(
                    "SMBv1 is enabled on a Tier 0 host. A host in the identity "
                    "control plane that still accepts SMBv1 is exposed to the "
                    "SMBv1 exploit family if it is missing patches. Whether a "
                    "host is actually vulnerable to MS17-010 is tested "
                    "separately and reported as its own finding"
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
        # A configuration finding: LDAP signing or channel binding is not
        # enforced, so relayed NTLM authentication can be used against the
        # directory. What the scan PROVED is the setting, not a relay. Medium
        # baseline, High when the affected host is a domain controller or Tier 0
        # (in practice always: the setting is answered by the DC), Critical only
        # when a relay to LDAP was actually walked in this run.
        finding_type=FindingType.CHAIN_PREREQUISITE,
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=8.0,
                reason=(
                    "A domain controller does not enforce LDAP signing or channel "
                    "binding. Relayed authentication accepted by the directory can "
                    "change privileged objects, so the exposure is rated High"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=8.0,
                reason=(
                    "A Tier 0 host does not enforce LDAP signing or channel "
                    "binding. Relayed authentication accepted by the directory can "
                    "change privileged objects, so the exposure is rated High"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.0,
                reason=(
                    "A relay to LDAP was carried out in this assessment and "
                    "changed the directory"
                ),
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
        # A hardening finding: a legacy protocol left enabled. What the scan
        # PROVED is that the host negotiates the SMBv1 dialect, not that it is
        # exploitable. The severe outcome (unauthenticated SYSTEM code
        # execution) needs a separate, specific defect, MS17-010, which the CVE
        # scanner probes on its own and reports as its own ``ms17-010`` finding
        # (graded Critical when the probe confirms the host vulnerable). Grading
        # this finding at that outcome would double-count it and, on a patched
        # host, overclaim it. So: Medium baseline, High when an affected host is
        # Tier 0 (the stamped tier read by ``extract_context_from_details``) or
        # a domain controller, and never Critical from this key alone. No
        # exploitation rule either: ADscan never runs the SMBv1 exploit, and a
        # confirmed vulnerability belongs to the MS17-010 finding.
        # Mirrors the ``smbv1_enabled`` alias above (same weakness, second
        # producer); keep the two in lockstep.
        finding_type=FindingType.CHAIN_PREREQUISITE,
        cvss_vector=None,
        elevation_rules=[
            # DC first: on a tie the earlier rule wins, and "domain controller"
            # is the more specific explanation when the finding carries it.
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=7.5,
                reason=(
                    "SMBv1 is enabled on a domain controller. A domain controller "
                    "that still accepts SMBv1 is exposed to the SMBv1 exploit "
                    "family if it is missing patches. Whether a host is actually "
                    "vulnerable to MS17-010 is tested separately and reported as "
                    "its own finding"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=7.5,
                reason=(
                    "SMBv1 is enabled on a Tier 0 host. A host in the identity "
                    "control plane that still accepts SMBv1 is exposed to the "
                    "SMBv1 exploit family if it is missing patches. Whether a "
                    "host is actually vulnerable to MS17-010 is tested "
                    "separately and reported as its own finding"
                ),
            ),
        ],
    ),
    "smb_signing_disabled": VulnCvssDefinition(
        # A configuration finding: SMB signing is not required, so relayed NTLM
        # authentication can be used against the host. Medium baseline, High
        # when an affected host is a domain controller or Tier 0, Critical only
        # when a relay against it was actually walked in this run. Graded in
        # lockstep with ``smb_relay_targets`` (same weakness, second producer).
        finding_type=FindingType.POSTURE,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=8.0,
                reason=(
                    "A domain controller does not require SMB signing. Relayed "
                    "authentication accepted by a domain controller can reach "
                    "privileged access, so the exposure is rated High"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=8.0,
                reason=(
                    "A Tier 0 host does not require SMB signing. Relayed "
                    "authentication accepted by a Tier 0 host can reach "
                    "privileged access, so the exposure is rated High"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.0,
                reason=(
                    "A relay against an unsigned SMB host was carried out in "
                    "this assessment and produced an authenticated session"
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
    "adcs_esc12": VulnCvssDefinition(
        finding_type=FindingType.VULNERABILITY,
        # High privileges (administrator of the CA host) are the precondition;
        # the scope changes because a certificate signed with the CA key is
        # trusted domain-wide.
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.0,
                reason="ESC12 CA signing key usable to forge Tier-0 logon certificates",
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
    "rbcd_configured": VulnCvssDefinition(
        finding_type=FindingType.VULNERABILITY,
        # Base is Medium: a populated msDS-AllowedToActOnBehalfOfOtherIdentity is
        # a delegation trust to investigate (it may be a legitimate front-end
        # service or a planted backdoor), not a proven exposure on its own. It
        # elevates when the configured delegation is confirmed abusable or the
        # affected computer's own tier makes an unauthorised trust high-impact.
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
                reason="Inbound RBCD configured on a Tier-0 computer: direct path to privileged impersonation",
            ),
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=9.0,
                reason="Inbound RBCD configured on a Domain Controller object: full DC takeover possible",
            ),
        ],
    ),
    "recovered_account_passwords": VulnCvssDefinition(
        finding_type=FindingType.VULNERABILITY,
        # Base is HIGH: enabled accounts whose plaintext password is now known is
        # a serious, actionable hygiene outcome. It elevates on the ADMIN-LIKE
        # count, never on volume, because an administrative password in hand is
        # an incident and a volume-driven score would average it away inside the
        # ordinary-user total.
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.1,
                reason="An administrative account's password was recovered: an attacker can authenticate as that role with no exploit",
            ),
        ],
    ),
    "shadow_credentials_present": VulnCvssDefinition(
        finding_type=FindingType.VULNERABILITY,
        # Base is Medium: the presence of an msDS-KeyCredentialLink entry is a
        # persistence indicator to investigate, not a proven exposure (ADscan
        # cannot use the entry without the pre-existing private key). It
        # elevates only when the affected object's own tier makes an
        # unauthorised entry near-certainly high-impact.
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=8.8,
                reason="Key credential present on a Tier-0 principal: an unauthorised entry here is standing domain compromise",
            ),
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=9.0,
                reason="Key credential present on a Domain Controller object: an unauthorised entry here is standing domain compromise",
            ),
        ],
    ),
    "excessive_cross_tier_rights": VulnCvssDefinition(
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=8.8,
                reason="Cross-tier control right exercised: the higher-tier object was taken over by its lower-tier holder",
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.0,
                reason="A lower-tier principal holds a control right over a Tier-0 object: a direct privilege-escalation path",
            ),
        ],
    ),
    "ntlmv1_enabled": VulnCvssDefinition(
        # A configuration finding: a host still answers with NTLMv1. Medium
        # baseline, High when the host is a domain controller or Tier 0, Critical
        # only when an NTLMv1 response was actually cracked or relayed in this
        # run. The routes that walk it are their own findings
        # (``ntlmv1_relay_rbcd`` / ``ntlmv1_relay_shadowcreds`` / ``ntlmv1_crack``).
        finding_type=FindingType.CHAIN_PREREQUISITE,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=8.0,
                reason=(
                    "A domain controller answers with NTLMv1. Its response can be "
                    "cracked offline or relayed, and on a domain controller that "
                    "reaches the whole domain, so the exposure is rated High"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=8.0,
                reason=(
                    "A Tier 0 host answers with NTLMv1. Its response can be "
                    "cracked offline or relayed, and on a Tier 0 host that reaches "
                    "the whole domain, so the exposure is rated High"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.0,
                reason=(
                    "An NTLMv1 response was cracked or relayed in this assessment"
                ),
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

    # ------------------------------------------------------------------
    # Host and domain hardening conditions
    # ------------------------------------------------------------------
    # Configuration findings: what the scan PROVED is a setting, not an attack.
    # Medium baseline (the catalog band), High when an affected asset is a
    # domain controller or Tier 0 (the stamped tier read by
    # ``extract_context_from_details``). No exploitation rule: no attack step a
    # run executes is recorded against these findings, so nothing can lift one
    # to Critical from a mapping alone.
    "lsa_protection_disabled": VulnCvssDefinition(
        # LSASS is not running as a protected process (RunAsPPL off).
        finding_type=FindingType.POSTURE,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=7.5,
                reason=(
                    "LSA Protection is off on a domain controller. A local "
                    "administrator there can read the credentials of the most "
                    "privileged accounts from memory, so the exposure is rated High"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=7.5,
                reason=(
                    "LSA Protection is off on a Tier 0 host. A local administrator "
                    "there can read the credentials of privileged accounts from "
                    "memory, so the exposure is rated High"
                ),
            ),
        ],
    ),
    "wdigest_enabled": VulnCvssDefinition(
        # WDigest caches the cleartext password of interactive logons.
        finding_type=FindingType.POSTURE,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=7.5,
                reason=(
                    "WDigest cleartext caching is on on a domain controller. The "
                    "plaintext passwords of privileged accounts that sign in there "
                    "are kept in memory, so the exposure is rated High"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=7.5,
                reason=(
                    "WDigest cleartext caching is on on a Tier 0 host. The "
                    "plaintext passwords of privileged accounts that sign in there "
                    "are kept in memory, so the exposure is rated High"
                ),
            ),
        ],
    ),
    "lm_hash_storage_enabled": VulnCvssDefinition(
        # The host still stores the weak LM hash of passwords.
        finding_type=FindingType.POSTURE,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=7.5,
                reason=(
                    "A domain controller stores LM password hashes. They include "
                    "those of privileged accounts and crack quickly, so the "
                    "exposure is rated High"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=7.5,
                reason=(
                    "A Tier 0 host stores LM password hashes. They include those of "
                    "privileged accounts and crack quickly, so the exposure is "
                    "rated High"
                ),
            ),
        ],
    ),
    "obsolete_computers": VulnCvssDefinition(
        # A host runs a Windows version past end of support. The finding
        # records the version, never that a specific flaw was exploited.
        finding_type=FindingType.POSTURE,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=7.5,
                reason=(
                    "A domain controller runs an unsupported Windows version. It no "
                    "longer receives security fixes, and a flaw on a domain "
                    "controller reaches the whole domain, so the exposure is rated "
                    "High"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=7.5,
                reason=(
                    "A Tier 0 host runs an unsupported Windows version. It no "
                    "longer receives security fixes, and a flaw on a Tier 0 host "
                    "reaches the whole domain, so the exposure is rated High"
                ),
            ),
        ],
    ),
    "reversible_encryption_enabled": VulnCvssDefinition(
        # A domain or fine-grained password policy stores passwords with
        # reversible encryption. The finding is domain-wide, so its affected
        # asset is the domain, which carries no tier; the Tier 0 signal comes
        # from the policy scope instead (``_reversible_encryption_context`` in
        # the calculator): the Default Domain Password Policy covers privileged
        # accounts, a fine-grained policy alone is not shown to.
        finding_type=FindingType.POSTURE,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=7.5,
                reason=(
                    "Reversible encryption is set on the Default Domain Password "
                    "Policy, which covers privileged accounts unless a "
                    "fine-grained policy overrides it, so the exposure is rated "
                    "High"
                ),
            ),
        ],
    ),

    # ------------------------------------------------------------------
    # NTLMv1 routes (mapped by the relay graph builder)
    # ------------------------------------------------------------------
    # A route finding is emitted while the builder maps the avenue open (status
    # theoretical / discovered / attempted / blocked); a configuration close or
    # a data gap emits nothing. Mapped is High (the catalog band); Critical only
    # when the route was walked in this run, i.e. an edge behind the finding
    # carries ``status == "success"`` (stamped ``exploitation_confirmed`` by the
    # attack-graph finding derivation). No tier rule: a mapped route landing on
    # a domain controller is still a mapped route.
    "ntlmv1_relay_rbcd": VulnCvssDefinition(
        # Route finding: High when mapped, Critical only when walked.
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.5,
                reason=(
                    "The NTLMv1 relay to resource-based constrained delegation was carried out in this assessment"
                ),
            ),
        ],
    ),
    "ntlmv1_relay_shadowcreds": VulnCvssDefinition(
        # Route finding: High when mapped, Critical only when walked.
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.5,
                reason=(
                    "The NTLMv1 relay to shadow credentials was carried out in this assessment"
                ),
            ),
        ],
    ),
    "ntlmv1_crack": VulnCvssDefinition(
        # Route finding: High when mapped, Critical only when walked.
        finding_type=FindingType.VULNERABILITY,
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.5,
                reason=(
                    "A captured NTLMv1 response was cracked to the machine account hash in this assessment"
                ),
            ),
        ],
    ),
}


def get_vuln_cvss_definition(vuln_key: str) -> VulnCvssDefinition | None:
    return CVSS_RULES.get(vuln_key)
