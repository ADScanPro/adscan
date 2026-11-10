"""Detector families: which check observes each finding key and attack-step relation.

The observation record (``observations.py``) is keyed by check id. This table is
the declaration that ties every catalog finding key and every attack-step
relation to the ONE detector family that observes it, so three consumers read
the same answer:

* reconciliation, through :func:`adscan_core.engagement.specs.spec_for`, which
  requires the detector's own observation for an ``instrumented`` family on top
  of its phase checks (a CVE probe that errored keeps its finding open even
  though the CVE phase completed);
* compliance positives: each positive control key belongs to one detector, and
  the positive is derived from that detector's observation;
* recheck (Phase 6a): ``reobserve`` says how the family can be re-observed
  without rerunning the whole scan, and the finding/step pair of one detector is
  the join a recheck expands through (one observation updates both).

A family is ``instrumented`` only when the engine records its observation for
EVERY outcome (clear, finding, not assessed, failed) at the code that ran the
check. A family that only records its good outcome must stay uninstrumented:
requiring an observation that a failing run never writes would keep a fixed
finding open forever (a missed closure).

``tests/unit/core/engagement/test_detectors.py`` fails when a finding key, a
step relation or a positive control key belongs to no detector, or to two.

Stdlib only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional

from adscan_core.engagement.specs import (
    C_ADCS,
    C_ANALYSIS,
    C_AUDIT,
    C_AUDIT_HOSTS,
    C_COLLECTION,
    C_COLLECTION_HOSTS,
    C_COLLECTION_MSSQL,
    C_CRACKING,
    C_PATHS,
    C_PRIV_EXERCISE,
    C_QUICK_WINS,
    C_SHARES,
    C_SPRAY,
    POSTURE_PREFIX,
)

#: How a family can be re-observed by a recheck (spec section 10.5).
REOBSERVE_DOMAIN_POLICY = "domain_policy_read"
REOBSERVE_OBJECT = "object_read"
REOBSERVE_PROBE = "protocol_probe"
REOBSERVE_CONDITION = "condition_check"
REOBSERVE_FULL_PHASE = "full_phase"
#: Capture-, crack- or execution-derived: re-observing means re-executing.
REOBSERVE_EXECUTE_ONLY = "execute_only"
REOBSERVE_MODES = frozenset(
    {
        REOBSERVE_DOMAIN_POLICY,
        REOBSERVE_OBJECT,
        REOBSERVE_PROBE,
        REOBSERVE_CONDITION,
        REOBSERVE_FULL_PHASE,
        REOBSERVE_EXECUTE_ONLY,
    }
)


@dataclass(frozen=True)
class Detector:
    """One detector family.

    Attributes:
        check_id: Id the family's observation is recorded under.
        phase_check: The coarse phase check whose run the family belongs to.
        finding_keys: Catalog finding keys this family observes.
        step_relations: Attack-step relations (lowercase) it observes.
        positive_keys: Compliance positive keys its clear observation greens.
        reobserve: How a recheck re-observes it (``REOBSERVE_*``).
        instrumented: The engine records every outcome of this family, so its
            observation is required before an absent item can close.
    """

    check_id: str
    phase_check: str
    finding_keys: tuple[str, ...] = ()
    step_relations: tuple[str, ...] = ()
    positive_keys: tuple[str, ...] = ()
    reobserve: str = REOBSERVE_FULL_PHASE
    instrumented: bool = False


def _d(
    check_id: str,
    phase_check: str,
    findings: str = "",
    steps: str = "",
    positives: str = "",
    *,
    reobserve: str = REOBSERVE_FULL_PHASE,
    instrumented: bool = False,
) -> Detector:
    return Detector(
        check_id=check_id,
        phase_check=phase_check,
        finding_keys=tuple(findings.split()),
        step_relations=tuple(steps.split()),
        positive_keys=tuple(positives.split()),
        reobserve=reobserve,
        instrumented=instrumented,
    )


def _posture(category: str) -> str:
    return POSTURE_PREFIX + category


#: CVE probe id (``cve_scanner.catalog``) -> detector check id. The CVE scanner
#: reports every probe's verdict per host, so these families are instrumented.
CVE_CHECK_IDS: Mapping[str, str] = {
    "CVE-2020-1472": "cve.zerologon",
    "CVE-2021-42278": "cve.nopac",
    "CVE-2017-0144": "cve.ms17_010",
    "CVE-2021-34527": "cve.printnightmare",
    "ADSCAN-COERCION-PETITPOTAM": "cve.petitpotam",
    "ADSCAN-COERCION-PRINTERBUG": "cve.printerbug",
    "ADSCAN-COERCION-DFSCOERCE": "cve.dfscoerce",
    "ADSCAN-COERCION-MSEVENCOERCE": "cve.mseven",
    "ADSCAN-COERCION-SHADOWCOERCE": "cve.shadowcoerce",
    "ADSCAN-WEBDAV-ENABLED": "cve.webdav",
    "ADSCAN-PRINTERBUG-SURFACE": "cve.printerbug_surface",
    "ADSCAN-BADSUCCESSOR-2025": "cve.badsuccessor",
    "CVE-2020-0796": "cve.smbghost",
    # These two detector ids are persisted in observation records, so they keep
    # their original spelling: cve.drop_the_mic observes CVE-2019-1166 (Drop the
    # MIC 2) and cve.ntlm_reflection observes CVE-2019-1040 (Drop the MIC; the
    # check was mislabelled "NTLM reflection" before 13.2). The id is opaque;
    # the CVE key on the left is what identifies the flaw.
    "CVE-2019-1166": "cve.drop_the_mic",
    "CVE-2019-1040": "cve.ntlm_reflection",
}

_ESC_NUMBERS = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 16, 17)
#: ESC families decided from values read on the CA host (EditFlags /
#: InterfaceFlags), not from the collected directory. They record their own
#: outcome per CA, so a collected CA never marks them clear by absence.
_ESC_CA_HOST_READS = frozenset({6, 11})
_ESC_POSITIVES = {
    9: "esc9_implicit_mapping_mitigated",
    14: "esc14_weak_explicit_mapping_mitigated",
    15: "esc15_application_policy_injection_mitigated",
}


def adcs_check_id(esc_number: int | str) -> str:
    """Detector check id of one AD CS escalation (``adcs.esc4``)."""
    return f"adcs.esc{int(str(esc_number).lower().removeprefix('adcsesc').removeprefix('esc'))}"


def _build() -> tuple[Detector, ...]:
    out: list[Detector] = [
        # -- directory reads by the collector -------------------------------
        _d("ldap.roastable_accounts", C_COLLECTION, "kerberoast asreproast",
           "kerberoasting asreproasting", "kerberos_roastable_accounts_absent",
           reobserve=REOBSERVE_OBJECT),
        _d("ldap.object_acl", C_COLLECTION, "excessive_cross_tier_rights",
           "genericall genericwrite writedacl writeowner owns allextendedrights "
           "forcechangepassword addmember addself addkeycredentiallink "
           "writeaccountrestrictions writespn writelogonscript",
           "delegated_object_rights_absent", reobserve=REOBSERVE_OBJECT),
        _d("ldap.replication_rights", C_COLLECTION,
           "dcsync unauthorized_external_tenant_replication",
           "dcsync getchanges getchangesall getchangesinfilteredset",
           "directory_replication_rights_confined", reobserve=REOBSERVE_OBJECT),
        _d("ldap.delegation", C_COLLECTION,
           "constrained_delegation unconstrained_delegation rbcd_configured "
           "trust_tgt_delegation_enabled",
           "allowedtodelegate allowedtoact unconstraineddelegation "
           "crossorgtgtdelegation spnjack", reobserve=REOBSERVE_OBJECT),
        _d("ldap.gmsa", C_COLLECTION, "gmsa_readable", "readgmsapassword",
           reobserve=REOBSERVE_OBJECT),
        _d("ldap.laps", C_COLLECTION, "laps laps_readable",
           "readlapspassword synclapspassword", reobserve=REOBSERVE_OBJECT),
        _d("ldap.shadow_credentials", C_COLLECTION, "shadow_credentials_present",
           "hasshadowcredentials", reobserve=REOBSERVE_OBJECT),
        _d("ldap.account_hygiene", C_COLLECTION,
           "password_never_expires password_not_req password_not_required "
           "stale_enabled_computers stale_enabled_users stale_passwords "
           "obsolete_computers duplicate_computer_dns krbtgt_password_age",
           "computerpre2k", reobserve=REOBSERVE_OBJECT),
        _d("ldap.attribute_secrets", C_COLLECTION,
           "credential_in_ldap_attribute ldap_user_description_password_leak "
           "user_description_credential_leak", "userdescription",
           reobserve=REOBSERVE_OBJECT),
        _d("ldap.trusts", C_COLLECTION, "trust_sid_filtering_disabled raise_child_forest_root",
           "raisechild", reobserve=REOBSERVE_OBJECT),
        _d("ldap.membership", C_COLLECTION, "",
           "memberof privilegedgroupcontrol backupoperatorescalation printoperatorabuse "
           "dnsadminabuse managerodcprp preparerodccredentialcaching",
           reobserve=REOBSERVE_OBJECT),
        _d("graph.tier0_exposure", C_PATHS,
           "tier0_access_exposure tier0_highvalue_sprawl mssql_bulk_operations_overprivilege"),
        # -- certificate services ------------------------------------------
        *(
            _d(f"adcs.esc{n}", C_ADCS, f"adcs_esc{n}", f"adcsesc{n}",
               _ESC_POSITIVES.get(n, ""),
               reobserve=REOBSERVE_PROBE if n in _ESC_CA_HOST_READS else REOBSERVE_OBJECT,
               instrumented=n in _ESC_CA_HOST_READS)
            for n in _ESC_NUMBERS
        ),
        # ESC12 is read on the CA host itself, not derived from the collected
        # directory, and its detector records every outcome (finding, clear,
        # not assessed with the reason) per CA. So it is instrumented and the
        # directory-collection pass never marks it clear by absence.
        _d("adcs.esc12", C_ADCS, "adcs_esc12", "adcsesc12",
           reobserve=REOBSERVE_PROBE, instrumented=True),
        _d("adcs.ntauth", C_ADCS, "adcs_orphaned_ca_ntauth", reobserve=REOBSERVE_OBJECT),
        _d("adcs.relay_to_web_enrollment", C_ADCS, "", "coerceandrelayntlmtoadcs"),
        # -- domain policy reads --------------------------------------------
        _d("policy.password", C_ANALYSIS, "weak_password_policy", "",
           "strong_password_policy", reobserve=REOBSERVE_DOMAIN_POLICY),
        _d("policy.machine_account_quota", C_ANALYSIS, "machine_account_quota_risk", "",
           "machine_account_quota_zero", reobserve=REOBSERVE_DOMAIN_POLICY),
        _d("policy.machine_password_rotation", C_ANALYSIS,
           "machine_password_rotation_disabled machine_password_rotation_relaxed",
           reobserve=REOBSERVE_DOMAIN_POLICY),
        _d("policy.rc4_accounts", C_ANALYSIS, "rc4_only_accounts", reobserve=REOBSERVE_OBJECT),
        _d("policy.reversible_encryption", C_ANALYSIS, "reversible_encryption_enabled", "",
           "reversible_encryption_disabled", reobserve=REOBSERVE_DOMAIN_POLICY),
        # -- posture categories (observed by the posture probe) ---------------
        _d(_posture("kerberos_rc4"), C_ANALYSIS, "kerberos_rc4_domain_accepted",
           reobserve=REOBSERVE_PROBE),
        _d(_posture("kerberos_aes_only"), C_ANALYSIS, "kerberos_aes_not_forced", "",
           "kerberos_aes_only", reobserve=REOBSERVE_PROBE),
        _d(_posture("ldap_signing"), C_ANALYSIS, "ldap_security_posture", "",
           "ldap_signing_required", reobserve=REOBSERVE_PROBE),
        _d(_posture("ldap_channel_binding"), C_ANALYSIS, "", "",
           "ldap_channel_binding_required", reobserve=REOBSERVE_PROBE),
        _d(_posture("ntlm_authentication"), C_ANALYSIS, "ntlm_authentication_accepted", "",
           "ntlm_likely_disabled", reobserve=REOBSERVE_PROBE),
        _d(_posture("ldaps_available"), C_ANALYSIS, "ldaps_unavailable", "",
           "ldaps_available", reobserve=REOBSERVE_PROBE),
        _d(_posture("ldap_starttls_available"), C_ANALYSIS, "", "",
           "starttls_available", reobserve=REOBSERVE_PROBE),
        _d(_posture("smb_signing"), C_ANALYSIS, "smb_signing_disabled smb_relay_targets", "",
           "smb_signing_required", reobserve=REOBSERVE_PROBE),
        # -- protocol probes ------------------------------------------------
        _d("probe.ldap_anonymous", C_ANALYSIS, "ldap_anonymous", "ldapanonymousbind",
           reobserve=REOBSERVE_PROBE),
        _d("probe.ntlmv1", C_ANALYSIS, "ntlmv1_enabled", "ntlmv1enabled",
           reobserve=REOBSERVE_PROBE),
        _d("probe.smb_null_session", C_ANALYSIS, "smb_null_domain", reobserve=REOBSERVE_PROBE),
        _d("probe.http_relay_surface", C_ANALYSIS, "http_spn_relay_surface",
           reobserve=REOBSERVE_PROBE),
        # -- per-host reads -------------------------------------------------
        _d("host.smbv1", C_ANALYSIS, "smbv1_enabled smb_v1_enabled", "", "smbv1_disabled",
           reobserve=REOBSERVE_PROBE),
        # One family per registry control: each control has its own outcome,
        # so they can never share one observation (a weak value on one control
        # must not hide the hardened value observed on another).
        *(
            _d(f"host.registry.{name}", C_ANALYSIS, finding, "", positive,
               reobserve=REOBSERVE_OBJECT)
            for name, finding, positive in (
                ("lsa_protection", "lsa_protection_disabled", "lsa_protection_enabled"),
                ("wdigest", "wdigest_enabled", "wdigest_disabled"),
                ("lm_hash_storage", "lm_hash_storage_enabled", "lm_hash_storage_disabled"),
                ("lm_compatibility", "weak_lm_compatibility_level", "lm_compatibility_hardened"),
                ("ntlm_min_session_security", "ntlm_min_session_security_weak",
                 "ntlm_min_session_security_hardened"),
                ("lsass_custom_ssp", "lsass_custom_ssp_allowed", "lsass_custom_ssp_disallowed"),
            )
        ),
        _d("host.endpoint_protection", C_ANALYSIS, "", "", "endpoint_protection_present",
           reobserve=REOBSERVE_OBJECT),
        _d("host.access", C_COLLECTION_HOSTS, "",
           "adminto canrdp canpsremote executedcom scheduledtask",
           reobserve=REOBSERVE_CONDITION),
        _d("host.sessions", C_COLLECTION_HOSTS, "da_sessions", "hassession",
           reobserve=REOBSERVE_CONDITION),
        _d("smb.share_access", C_COLLECTION_HOSTS, "",
           "readshare writeshare fullcontrolshare guestsession writesmbpath",
           reobserve=REOBSERVE_CONDITION),
        _d("mssql.access", C_COLLECTION_MSSQL, "",
           "sqlaccess sqladmin mssql_impersonate_login mssql_linked_server_lateral",
           reobserve=REOBSERVE_CONDITION),
        # -- CVE and coercion probes (every outcome recorded) ----------------
        _d("cve.zerologon", C_AUDIT, "zerologon", "zerologon", "zerologon_not_vulnerable",
           reobserve=REOBSERVE_PROBE, instrumented=True),
        _d("cve.nopac", C_AUDIT, "nopac", "nopac", "nopac_not_vulnerable",
           reobserve=REOBSERVE_PROBE, instrumented=True),
        _d("cve.ms17_010", C_AUDIT_HOSTS, "ms17-010", "ms17-010", "ms17_010_not_present",
           reobserve=REOBSERVE_PROBE, instrumented=True),
        _d("cve.printnightmare", C_AUDIT_HOSTS, "printnightmare", "printnightmare",
           reobserve=REOBSERVE_PROBE, instrumented=True),
        _d("cve.petitpotam", C_AUDIT_HOSTS, "petitpotam", "petitpotam",
           reobserve=REOBSERVE_PROBE, instrumented=True),
        _d("cve.printerbug", C_AUDIT_HOSTS, "printerbug", "printerbug",
           reobserve=REOBSERVE_PROBE, instrumented=True),
        _d("cve.dfscoerce", C_AUDIT_HOSTS, "dfscoerce", "dfscoerce",
           reobserve=REOBSERVE_PROBE, instrumented=True),
        _d("cve.mseven", C_AUDIT_HOSTS, "mseven", "mseven",
           reobserve=REOBSERVE_PROBE, instrumented=True),
        _d("cve.webdav", C_AUDIT_HOSTS, "webdav", reobserve=REOBSERVE_PROBE, instrumented=True),
        *(
            _d(check, C_AUDIT_HOSTS, reobserve=REOBSERVE_PROBE, instrumented=True)
            for check in (
                "cve.shadowcoerce",
                "cve.printerbug_surface",
                "cve.badsuccessor",
                "cve.smbghost",
                "cve.drop_the_mic",
                "cve.ntlm_reflection",
            )
        ),
        _d("cve.certighost", C_AUDIT_HOSTS, "certighost", "certighost", reobserve=REOBSERVE_PROBE,
           instrumented=True),
        # -- credential hunting ---------------------------------------------
        _d("hunt.gpp", C_QUICK_WINS, "gpp_autologin gpp_passwords", "gpppassword",
           reobserve=REOBSERVE_FULL_PHASE),
        _d("hunt.share_secrets", C_SHARES, "smb_guest_shares smb_share_secrets",
           "passwordinshare passwordinfile", reobserve=REOBSERVE_FULL_PHASE),
        # -- capture, crack and execution outcomes (never closed by absence) --
        _d("credential.recovered", C_CRACKING,
           "recovered_account_passwords krbtgt_pass ntlmv1_crack timeroast",
           "timeroasting crackntlmv1 poisoncapturentlmv2crack",
           reobserve=REOBSERVE_EXECUTE_ONLY),
        _d("credential.spray", C_SPRAY, "", "blankpassword useraspass passwordspray",
           reobserve=REOBSERVE_EXECUTE_ONLY),
        _d("credential.reuse", C_PRIV_EXERCISE, "",
           "domainpassreuse domainpassreusesource localadminpassreuse "
           "localcredreusesource localcredtodomainreuse",
           reobserve=REOBSERVE_EXECUTE_ONLY),
        _d("execution.credential_dump", C_PRIV_EXERCISE, "",
           "dumpdpapi dumplsa dumplsass dumpsam extractrodckrbtgtsecret "
           "forgerodcgoldenticket kerberoskeylist", reobserve=REOBSERVE_EXECUTE_ONLY),
        _d("execution.relay", C_PRIV_EXERCISE, "ntlmv1_relay_rbcd ntlmv1_relay_shadowcreds",
           "ntlmv1relayrbcd ntlmv1relayshadowcreds", reobserve=REOBSERVE_EXECUTE_ONLY),
        _d("execution.mssql", C_PRIV_EXERCISE, "",
           "mssql_ntlmv2_theft mssql_openrowset_bulk_read mssql_seimpersonate_escalation "
           "mssql_token_theft_escalation mssql_trustworthy_db_escalation xp_cmdshell",
           reobserve=REOBSERVE_EXECUTE_ONLY),
    ]
    return tuple(out)


DETECTORS: tuple[Detector, ...] = _build()

_BY_ID: Mapping[str, Detector] = {d.check_id: d for d in DETECTORS}
_BY_FINDING: Mapping[str, Detector] = {k: d for d in DETECTORS for k in d.finding_keys}
_BY_STEP: Mapping[str, Detector] = {r: d for d in DETECTORS for r in d.step_relations}
_BY_POSITIVE: Mapping[str, Detector] = {k: d for d in DETECTORS for k in d.positive_keys}


def detector_by_id(check_id: str) -> Optional[Detector]:
    """The detector recorded under ``check_id``, or ``None``."""
    return _BY_ID.get(check_id)


def detector_for(kind: str, key: str) -> Optional[Detector]:
    """The detector that observes a finding key (``kind="finding"``) or step relation."""
    if kind == "finding":
        return _BY_FINDING.get(str(key))
    if kind in {"step", "structural_step"}:
        return _BY_STEP.get(str(key).lower())
    return None


def detector_for_positive_key(key: str) -> Optional[Detector]:
    """The detector whose clear observation greens compliance positive ``key``."""
    return _BY_POSITIVE.get(str(key))


def finding_keys_for_step(relation: str) -> tuple[str, ...]:
    """Finding keys observed together with ``relation`` (same detector)."""
    det = detector_for("step", relation)
    return det.finding_keys if det is not None else ()


def step_relations_for_finding(key: str) -> tuple[str, ...]:
    """Step relations observed together with finding ``key`` (same detector)."""
    det = detector_for("finding", key)
    return det.step_relations if det is not None else ()


def instrumented_check_for(kind: str, key: str) -> Optional[str]:
    """The detector check an absent item additionally needs, when instrumented."""
    det = detector_for(kind, key)
    return det.check_id if det is not None and det.instrumented else None


__all__ = (
    "CVE_CHECK_IDS",
    "DETECTORS",
    "Detector",
    "REOBSERVE_MODES",
    "adcs_check_id",
    "detector_by_id",
    "detector_for",
    "detector_for_positive_key",
    "finding_keys_for_step",
    "instrumented_check_for",
    "step_relations_for_finding",
)
