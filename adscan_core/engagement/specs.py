"""Observation specs: which checks observe which finding key / step relation.

A spec answers "if this item is absent from a run, what must have happened for
that absence to mean it is fixed?". Reconciliation fails closed: an item with no
spec, or with ``reeval="never_auto"``, is never closed by absence.

Check ids are, for now, scan-phase ids (``domain_collection``,
``domain_analysis`` ...): the coarsest unit the engine can truthfully report as
having run to completion per domain. Finer check ids (``ldap.password_policy``)
plug in later by extending :data:`CHECK_TO_PHASE`; nothing else changes.

The tables below were bootstrapped by phase from the inventory in
``tests/unit/core/engagement/fixtures/inventory.json``. They are deliberately
CONSERVATIVE: requiring a check that did not run only leaves an item
``NOT_REEVALUATED`` (a missed closure); it can never produce a false closure.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional

from adscan_core.engagement.model import Vantage


@dataclass(frozen=True)
class ObservationSpec:
    """How the absence of one item is to be interpreted.

    Attributes:
        observed_by: Check ids that must all have run on the item's scope.
        scope: ``domain``, ``object`` or ``host``: the granularity of the item.
        requires_vantage: Minimum run vantage able to observe the item.
        reeval: ``auto`` (absence can prove closure) or ``never_auto``
            (absence never closes it: capture- or execution-derived items).
    """

    observed_by: tuple[str, ...]
    scope: str
    requires_vantage: Vantage
    reeval: str = "auto"


# Check ids (coarse, one per scan phase that observes something).
C_COLLECTION = "domain_collection"
C_ANALYSIS = "domain_analysis"
C_PATHS = "attack_paths_discovery"
C_QUICK_WINS = "quick_credential_wins"
C_SPRAY = "password_spraying"
C_SHARES = "share_credential_hunt"
C_UNAUTH_SURFACE = "unauthenticated_attack_surface"
C_AUDIT = "audit_extras"
#: Per-host fan-out of the collector (SAMR / shares / MSSQL). Split from
#: ``domain_collection`` so a bounded or partly unreachable host sweep blocks
#: closing HOST-scoped items without blocking the identity graph, which is
#: always complete.
C_COLLECTION_HOSTS = "domain_collection.hosts"
#: Offline password cracking. No auto-closable spec observes it today (every
#: crack-derived item is ``never_auto``); recorded so its gap is not lost.
C_CRACKING = "credential_cracking"
#: Exercise of privileges the directory proves (replication etc.). Same status.
C_PRIV_EXERCISE = "privilege_exercise"
#: The every-host pass of CVE verification. ``audit_extras`` itself is the
#: domain-controller pass, which always runs when the phase runs; the every-host
#: pass is skipped when the CVE scope is narrowed to domain controllers (and on
#: non-audit engagements under the default scope).
C_AUDIT_HOSTS = "audit_extras.hosts"
#: The certificate-services detection reached a conclusive answer (a CA was
#: found, or the directory was read and holds none). An inconclusive detection
#: makes the absence of every certificate-services item meaningless.
C_ADCS = "adcs.detection"
#: The MSSQL access sweep. It records no per-host examined set yet, so it is
#: always reported PARTIAL and the MSSQL access edges are never closed by
#: absence (they used to be, on any absence at all).
C_COLLECTION_MSSQL = "domain_collection.mssql"

#: Per-category posture observations. The finding a category produces is only
#: absent for a reason when the category was actually OBSERVED (a definitive,
#: high-confidence answer from the DC); a probe that timed out or was never
#: attempted leaves the category unknown and its finding open. Values are the
#: ``ConstraintCategory`` values of ``adscan_internal.services.domain_posture``.
POSTURE_PREFIX = "posture."
C_POSTURE_NTLM = POSTURE_PREFIX + "ntlm_authentication"
C_POSTURE_RC4 = POSTURE_PREFIX + "kerberos_rc4"
C_POSTURE_AES_ONLY = POSTURE_PREFIX + "kerberos_aes_only"
C_POSTURE_LDAPS = POSTURE_PREFIX + "ldaps_available"
C_POSTURE_LDAP_SIGNING = POSTURE_PREFIX + "ldap_signing"
C_POSTURE_LDAP_CBT = POSTURE_PREFIX + "ldap_channel_binding"
POSTURE_CHECKS: tuple[str, ...] = (
    C_POSTURE_NTLM,
    C_POSTURE_RC4,
    C_POSTURE_AES_ONLY,
    C_POSTURE_LDAPS,
    C_POSTURE_LDAP_SIGNING,
    C_POSTURE_LDAP_CBT,
)

#: Check id -> scan phase id (``scan_phases.SCAN_PHASES``). Identity for now.
CHECK_TO_PHASE: Mapping[str, str] = {
    C_COLLECTION: C_COLLECTION,
    C_ANALYSIS: C_ANALYSIS,
    C_PATHS: C_PATHS,
    C_QUICK_WINS: C_QUICK_WINS,
    C_SPRAY: C_SPRAY,
    C_SHARES: C_SHARES,
    C_UNAUTH_SURFACE: C_UNAUTH_SURFACE,
    C_AUDIT: C_AUDIT,
    C_COLLECTION_HOSTS: C_COLLECTION,
    C_CRACKING: C_QUICK_WINS,
    C_PRIV_EXERCISE: C_PATHS,
    C_AUDIT_HOSTS: C_AUDIT,
    C_ADCS: C_COLLECTION,
    C_COLLECTION_MSSQL: C_COLLECTION,
    **{check: C_ANALYSIS for check in POSTURE_CHECKS},
}


def _auto(
    checks: tuple[str, ...], vantage: Vantage, scope: str = "domain"
) -> ObservationSpec:
    return ObservationSpec(checks, scope, vantage)


def _never(scope: str = "domain") -> ObservationSpec:
    return ObservationSpec((), scope, Vantage.UNAUTH, reeval="never_auto")


_DIR = (C_COLLECTION,)
_GRAPH = (C_COLLECTION, C_PATHS)
_ADCS_GRAPH = (C_COLLECTION, C_PATHS, C_ADCS)
_HOST_CVE = (C_AUDIT, C_AUDIT_HOSTS)


def _build_finding_specs() -> dict[str, ObservationSpec]:
    specs: dict[str, ObservationSpec] = {}

    def put(keys: str, spec: ObservationSpec) -> None:
        for key in keys.split():
            specs[key] = spec

    # Directory facts read over LDAP/SAMR by the collector (object scope).
    put(
        "kerberoast asreproast constrained_delegation unconstrained_delegation "
        "rbcd_configured gmsa_readable laps laps_readable password_never_expires "
        "password_not_req password_not_required stale_enabled_computers "
        "stale_enabled_users stale_passwords obsolete_computers "
        "duplicate_computer_dns shadow_credentials_present "
        "unauthorized_external_tenant_replication credential_in_ldap_attribute "
        "ldap_user_description_password_leak user_description_credential_leak "
        "krbtgt_password_age trust_sid_filtering_disabled "
        "trust_tgt_delegation_enabled",
        _auto(_DIR, Vantage.AUTH, "object"),
    )
    # Certificate services: collected, derived on the graph, and only
    # interpretable when the CA detection itself was conclusive.
    put(
        "adcs_esc1 adcs_esc2 adcs_esc3 adcs_esc4 adcs_esc5 adcs_esc6 adcs_esc7 "
        "adcs_esc8 adcs_esc9 adcs_esc10 adcs_esc11 adcs_esc12 adcs_esc13 adcs_esc14 "
        "adcs_esc15 adcs_esc16 adcs_esc17 adcs_orphaned_ca_ntauth",
        _auto(_ADCS_GRAPH, Vantage.AUTH, "object"),
    )
    # Other graph-derived exposure: collected, then derived on the graph.
    put(
        "dcsync excessive_cross_tier_rights tier0_access_exposure "
        "tier0_highvalue_sprawl mssql_bulk_operations_overprivilege",
        _auto(_GRAPH, Vantage.AUTH, "object"),
    )
    # Domain-wide controls that only an authenticated read can observe. These are
    # exactly the former AUTH_GATED_CONTROL_KEYS of the web ingestion.
    put(
        "rc4_only_accounts weak_password_policy machine_account_quota_risk "
        "machine_password_rotation_disabled machine_password_rotation_relaxed",
        _auto((C_ANALYSIS,), Vantage.AUTH),
    )
    # Findings emitted from a posture observation (``posture_findings_emitter``):
    # their absence means "fixed" only when the category was observed.
    put("kerberos_rc4_domain_accepted", _auto((C_ANALYSIS, C_POSTURE_RC4), Vantage.AUTH))
    put("kerberos_aes_not_forced", _auto((C_ANALYSIS, C_POSTURE_AES_ONLY), Vantage.AUTH))
    put(
        "ldap_security_posture",
        _auto((C_ANALYSIS, C_POSTURE_LDAP_SIGNING, C_POSTURE_LDAP_CBT), Vantage.AUTH),
    )
    put("ntlm_authentication_accepted", _auto((C_ANALYSIS, C_POSTURE_NTLM), Vantage.UNAUTH))
    put("ldaps_unavailable", _auto((C_ANALYSIS, C_POSTURE_LDAPS), Vantage.UNAUTH))
    # Domain-wide posture probes an unauthenticated vantage can observe too.
    put(
        "ntlmv1_enabled "
        "ldap_anonymous smb_signing_disabled smb_relay_targets smbv1_enabled "
        "smb_v1_enabled smb_null_domain ntlm_min_session_security_weak "
        "weak_lm_compatibility_level lm_hash_storage_enabled "
        "reversible_encryption_enabled wdigest_enabled lsa_protection_disabled "
        "lsass_custom_ssp_allowed http_spn_relay_surface",
        _auto((C_ANALYSIS,), Vantage.UNAUTH),
    )
    # CVE probes that target domain controllers only: the DC pass covers them.
    put("zerologon nopac", _auto((C_AUDIT,), Vantage.AUTH, "host"))
    # Host-level exposure verified by the every-host CVE / coercion pass.
    put(
        "ms17-010 mseven printnightmare petitpotam dfscoerce "
        "printerbug certighost webdav raise_child_forest_root",
        _auto(_HOST_CVE, Vantage.AUTH, "host"),
    )
    # Credential-harvest findings observed by their own hunting phase.
    put("gpp_autologin gpp_passwords", _auto((C_QUICK_WINS,), Vantage.AUTH, "object"))
    put("smb_guest_shares smb_share_secrets", _auto((C_SHARES,), Vantage.AUTH, "host"))
    # Capture-, crack- or execution-derived: absence is never proof of a fix.
    put(
        "recovered_account_passwords ntlmv1_crack timeroast krbtgt_pass "
        "da_sessions ntlmv1_relay_rbcd ntlmv1_relay_shadowcreds",
        _never("object"),
    )
    return specs


def _build_step_specs() -> dict[str, ObservationSpec]:
    specs: dict[str, ObservationSpec] = {}

    def put(rels: str, spec: ObservationSpec) -> None:
        for rel in rels.split():
            specs[rel] = spec

    # Edges the collector reads from the directory, ACLs, delegation and ADCS.
    put(
        "memberof genericall genericwrite writedacl writeowner owns "
        "allextendedrights forcechangepassword addmember addself "
        "addkeycredentiallink writeaccountrestrictions writespn "
        "writelogonscript privilegedgroupcontrol backupoperatorescalation "
        "printoperatorabuse dnsadminabuse allowedtodelegate allowedtoact "
        "unconstraineddelegation crossorgtgtdelegation readgmsapassword "
        "readlapspassword synclapspassword hasshadowcredentials "
        "computerpre2k kerberoasting asreproasting timeroasting dcsync getchanges "
        "getchangesall getchangesinfilteredset raisechild spnjack "
        "managerodcprp preparerodccredentialcaching",
        _auto(_DIR, Vantage.AUTH, "object"),
    )
    # Certificate-services edges: also need a conclusive CA detection.
    put(
        "adcsesc1 adcsesc2 adcsesc3 adcsesc4 adcsesc5 adcsesc6 adcsesc7 adcsesc8 "
        "adcsesc9 adcsesc10 adcsesc11 adcsesc12 adcsesc13 adcsesc14 adcsesc15 adcsesc16 "
        "adcsesc17 coerceandrelayntlmtoadcs",
        _auto((C_COLLECTION, C_ADCS), Vantage.AUTH, "object"),
    )
    # Host access and share edges from the SAMR / shares host sweep.
    put(
        "adminto canrdp canpsremote executedcom hassession "
        "readshare writeshare fullcontrolshare guestsession writesmbpath "
        "scheduledtask",
        _auto((C_COLLECTION, C_COLLECTION_HOSTS), Vantage.AUTH, "host"),
    )
    # MSSQL access edges: their own sweep, which records no examined set yet.
    put(
        "sqlaccess sqladmin mssql_impersonate_login mssql_linked_server_lateral",
        _auto((C_COLLECTION, C_COLLECTION_HOSTS, C_COLLECTION_MSSQL), Vantage.AUTH, "host"),
    )
    # CVE / coercion probes (DC-only CVEs need only the DC pass).
    put("zerologon nopac", _auto((C_AUDIT,), Vantage.AUTH, "host"))
    put(
        "ms17-010 mseven printnightmare petitpotam printerbug dfscoerce certighost",
        _auto(_HOST_CVE, Vantage.AUTH, "host"),
    )
    # Posture-derived relations.
    put("ldapanonymousbind ntlmv1enabled", _auto((C_ANALYSIS,), Vantage.UNAUTH))
    # Credential-hunt relations.
    put("gpppassword userdescription", _auto((C_QUICK_WINS,), Vantage.AUTH, "object"))
    put("passwordinshare passwordinfile", _auto((C_SHARES,), Vantage.AUTH, "host"))
    # Executed or credential-derived outcomes: absence never proves a fix.
    put(
        "blankpassword useraspass passwordspray domainpassreuse "
        "domainpassreusesource localadminpassreuse localcredreusesource "
        "localcredtodomainreuse dumpdpapi dumplsa dumplsass dumpsam "
        "extractrodckrbtgtsecret forgerodcgoldenticket kerberoskeylist "
        "crackntlmv1 poisoncapturentlmv2crack ntlmv1relayrbcd "
        "ntlmv1relayshadowcreds mssql_ntlmv2_theft mssql_openrowset_bulk_read "
        "mssql_seimpersonate_escalation mssql_token_theft_escalation "
        "mssql_trustworthy_db_escalation xp_cmdshell",
        _never("host"),
    )
    return specs


FINDING_SPECS: Mapping[str, ObservationSpec] = _build_finding_specs()
STEP_SPECS: Mapping[str, ObservationSpec] = _build_step_specs()

#: Default for a STRUCTURAL graph edge (containment, GPO link, trust, ...) that is
#: not an attack-step relation: the collector owns it. Only consumed where the
#: edge's category is known to be structural, never as a fallback for an unknown
#: attack step.
STRUCTURAL_EDGE_SPEC = ObservationSpec(_DIR, "object", Vantage.AUTH)


#: Item kind of a graph edge whose category is a structural relationship.
KIND_STRUCTURAL_STEP = "structural_step"


def edge_spec_lookup(kind: str, key: str) -> Optional[ObservationSpec]:
    """``spec_lookup`` for graph edges (attack steps and structural edges).

    A ``"step"`` is an attack-step relation and uses its catalog spec only: an
    uncatalogued attack step stays unclosable. A ``"structural_step"`` is a
    structural relationship; when it is not an attack-step relation it falls
    back to :data:`STRUCTURAL_EDGE_SPEC` (the collector owns it).
    """
    if kind == KIND_STRUCTURAL_STEP:
        return spec_for("step", key) or STRUCTURAL_EDGE_SPEC
    return spec_for(kind, key)


def spec_for(kind: str, key: str) -> Optional[ObservationSpec]:
    """Return the observation spec of a finding key or step relation.

    Args:
        kind: ``"finding"`` or ``"step"``.
        key: The finding key or the step relation (case-insensitive for steps).

    Returns:
        The spec, or ``None`` when none is declared (reconciliation then treats
        the item as never auto-closable). When the item's detector family is
        instrumented (``detectors.py``: the engine records every outcome of the
        family), the family's own check is appended to ``observed_by``, so an
        absent item closes only when its detector observed it in this run, not
        merely when the phase that hosts the detector completed.
    """
    if kind == "finding":
        spec = FINDING_SPECS.get(key)
    elif kind == "step":
        spec = STEP_SPECS.get(str(key).lower())
    else:
        return None
    if spec is None or spec.reeval == "never_auto":
        return spec
    from adscan_core.engagement.detectors import instrumented_check_for  # noqa: PLC0415

    detector_check = instrumented_check_for(kind, key)
    if detector_check and detector_check not in spec.observed_by:
        return ObservationSpec(
            spec.observed_by + (detector_check,),
            spec.scope,
            spec.requires_vantage,
            spec.reeval,
        )
    return spec
