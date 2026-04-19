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
    CONDITION_TIER_ZERO,
    CvssElevationRule,
)


@dataclass
class VulnCvssDefinition:
    """Base CVSS metadata plus ADscan contextual severity rules.

    Attributes:
        cvss_vector:
            Formal CVSS 3.1 Base vector string, or ``None`` if the finding is
            not cleanly representable as a standalone Base CVSS issue.
        elevation_rules:
            ADscan contextual severity overlays evaluated in declaration order.
            First match wins. These are NOT part of CVSS Base.
    """

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
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=8.8,
                reason=(
                    "Kerberoastable Tier-0/high-value accounts detected — "
                    "successful cracking would expose privileged credentials"
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
                    "Kerberoastable DC-related service accounts detected — "
                    "credential compromise materially improves DC attack paths"
                ),
            ),
        ],
    ),
    "asreproast": VulnCvssDefinition(
        # Same reasoning as Kerberoast, but PR:N because pre-auth is disabled.
        # The direct outcome is still offline-crackable credential material,
        # not guaranteed plaintext compromise.
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.1,
                reason=(
                    "AS-REP roastable Tier-0/high-value accounts detected — "
                    "unauthenticated credential material retrieval affects "
                    "privileged identities"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=8.8,
                reason="Hash cracking confirmed — plaintext credential recovered",
            ),
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=8.0,
                reason=(
                    "DC-related accounts are AS-REP roastable — "
                    "unauthenticated credential material retrieval impacts "
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
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.5,
                reason=(
                    "Unconstrained delegation reachable by Tier-0 principals — "
                    "TGT capture path can yield immediate privileged compromise"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.8,
                reason="TGT capture confirmed — pass-the-ticket path is viable",
            ),
        ],
    ),
    "constrained_delegation": VulnCvssDefinition(
        # Similar problem: strong attack-path signal, but the standalone Base
        # vector is highly dependent on the delegated SPNs and how you reach the
        # principal that can perform S4U abuse.
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=8.5,
                reason=(
                    "Constrained delegation reaches Tier-0 services — "
                    "effective privileged impersonation path exists"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=8.0,
                reason=(
                    "Constrained delegation reaches DC services — "
                    "effective DC lateral movement path exists"
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
        cvss_vector="CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=9.0,
                reason=(
                    "DCs are relayable SMB targets — relay to DC meaningfully "
                    "raises privilege-escalation potential"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.0,
                reason=(
                    "Tier-0 assets are relayable SMB targets — "
                    "captured authentication can yield privileged access"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.0,
                reason="SMB relay confirmed — authenticated session obtained",
            ),
        ],
    ),
    "smb_null_domain": VulnCvssDefinition(
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=7.5,
                reason=(
                    "Null session accepted on DCs — "
                    "unauthenticated domain enumeration expands attack surface"
                ),
            ),
        ],
    ),
    "smb_guest_shares": VulnCvssDefinition(
        # Model this as read exposure. If you also detect anonymous/guest write,
        # split that into a separate finding instead of baking I:L here.
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
        # concrete vulnerable build/CVE.
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=8.5,
                reason=(
                    "SMBv1 enabled on DCs — obsolete protocol materially raises "
                    "legacy remote-exploitation risk"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=8.5,
                reason="SMBv1 enabled on Tier-0 assets — legacy exposure on privileged hosts",
            ),
        ],
    ),
    "smb_share_secrets": VulnCvssDefinition(
        # Authenticated exposure of credential material in shares.
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.5,
                reason=(
                    "Credentials found in shares belong to or enable Tier-0 "
                    "access — direct privileged path exists"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.0,
                reason="Exposed credentials verified — valid account access confirmed",
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
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=7.5,
                reason=(
                    "Anonymous LDAP bind accepted on DCs — "
                    "directory enumeration is available without authentication"
                ),
            ),
        ],
    ),
    "ldap_security_posture": VulnCvssDefinition(
        # Signing/channel binding not enforced -> relay posture. This is
        # defensible as a standalone misconfiguration because the service itself
        # lacks required integrity protections.
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=9.0,
                reason=(
                    "LDAP protections not enforced on DCs — "
                    "relay to LDAP can enable privileged directory operations"
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
        # recovered credential might later be used to modify things.
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.5,
                reason=(
                    "GPP credentials grant Tier-0 access — "
                    "trivial decryption yields privileged credential material"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.0,
                reason="GPP credentials decrypted and verified",
            ),
        ],
    ),
    "gpp_autologin": VulnCvssDefinition(
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=9.5,
                reason=(
                    "Autologin credentials enable Tier-0 access — "
                    "credential disclosure directly affects privileged identities"
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
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=9.0,
                reason=(
                    "LAPS password readable for DCs — "
                    "direct privileged local access to a DC-equivalent asset"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=8.8,
                reason=(
                    "LAPS password readable for Tier-0 hosts — "
                    "privileged local admin access path exists"
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
                    "LAPS attributes readable for DCs — "
                    "non-admin principals can retrieve DC local admin secrets"
                ),
            ),
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=8.8,
                reason=(
                    "LAPS attributes readable for Tier-0 assets — "
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
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=8.5,
                reason=(
                    "Tier-0 accounts do not require a password — "
                    "privileged account takeover risk is extreme"
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
        cvss_vector=None,
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
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_TIER_ZERO,
                elevated_score=8.0,
                reason=(
                    "Dormant enabled accounts include Tier-0/high-value identities"
                ),
            ),
        ],
    ),
    "tier0_highvalue_sprawl": VulnCvssDefinition(
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
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_EXPLOITATION,
                elevated_score=9.5,
                reason="DA session actively harvested — privileged credential confirmed",
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
        cvss_vector=None,
        elevation_rules=[],
    ),

    # ------------------------------------------------------------------
    # Concrete CVEs / vendor-scored issues
    # ------------------------------------------------------------------
    "zerologon": VulnCvssDefinition(
        # NVD official CVSS 3.1
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        elevation_rules=[],
    ),
    "nopac": VulnCvssDefinition(
        # Composite attack name, not a single CVE. Split into the underlying
        # CVEs (e.g. 42278 / 42287) if you want formal CVSS.
        cvss_vector=None,
        elevation_rules=[],
    ),
    "printnightmare": VulnCvssDefinition(
        # Microsoft/NVD 8.8
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        elevation_rules=[],
    ),
    "ms17-010": VulnCvssDefinition(
        # Bulletin/rollup label rather than a single CVE. Prefer exact CVE keys
        # if you want formal vendor/NVD vectors.
        cvss_vector=None,
        elevation_rules=[],
    ),

    # ------------------------------------------------------------------
    # Coercion / chain prerequisites
    # ------------------------------------------------------------------
    "petitpotam": VulnCvssDefinition(
        # Authentication coercion primitive. Direct impact depends on the relay
        # target and environment; model as attack-path risk, not Base CVSS.
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=9.0,
                reason=(
                    "Coercion path reaches DC-related relay targets — "
                    "domain-impacting relay chain is plausible"
                ),
            ),
        ],
    ),
    "dfscoerce": VulnCvssDefinition(
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=9.0,
                reason=(
                    "DFSCoerce path reaches DC-related relay targets"
                ),
            ),
        ],
    ),
    "mseven": VulnCvssDefinition(
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=9.0,
                reason=(
                    "MS-EFSRPC coercion path reaches DC-related relay targets"
                ),
            ),
        ],
    ),
    "printerbug": VulnCvssDefinition(
        cvss_vector=None,
        elevation_rules=[
            CvssElevationRule(
                condition=CONDITION_DC_TARGETS,
                elevated_score=8.8,
                reason=(
                    "PrinterBug coercion path reaches DC-related relay targets"
                ),
            ),
        ],
    ),
    "webdav": VulnCvssDefinition(
        # WebDAV enabled is a chain helper / coercion surface, not a formal Base
        # CVSS issue by itself.
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

    "certifried": VulnCvssDefinition(
        # Microsoft/NVD 8.8
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        elevation_rules=[],
    ),
}


def get_vuln_cvss_definition(vuln_key: str) -> VulnCvssDefinition | None:
    return CVSS_RULES.get(vuln_key)