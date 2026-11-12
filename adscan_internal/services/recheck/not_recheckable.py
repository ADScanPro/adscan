"""What ``adscan recheck`` cannot re-observe read-only, and why (one declaration each).

Every detector family in ``adscan_core.engagement.detectors`` is decided once
for the recheck: EITHER it has a read-only observer in
``observers.OBSERVERS``, OR it is listed in :data:`NOT_RECHECKABLE` with the
reason it has none. Nothing is left implicit: a new detector that is in
neither map fails ``tests/unit/services/recheck/test_recheck_coverage_declared.py``,
so whoever adds it has to decide.

A family that IS observed can still hold keys its observer never closes (a
relation the collector does not produce, a finding a per-object read can
confirm but not close, a verdict that needs data the recheck does not re-read).
Those are declared per key in :data:`NOT_RECHECKABLE_KEYS`, and the ACL
observers read their gaps from it, so the declaration and the behaviour cannot
drift apart.

**Why the declaration lives here, in the recheck package, and not on the
detector registry.** The detector registry is the stdlib-only SSOT of what the
SCAN observes; the web backend and the reconciliation import it. Whether a
family has an observer is a fact about this release's recheck, and its other
half (``OBSERVERS``) lives in this package, so both halves of one decision are
reviewed together. This module is a leaf (no imports from the observers) because
``acl_observers`` consumes :data:`NOT_RECHECKABLE_KEYS` and ``observers``
imports ``acl_observers``.

The reasons are operator copy: ``adscan recheck`` prints them and
``recheck_result.json`` carries them as ``not_recheckable_reason``. One line,
plain English, the real cause. ``adscan_internal`` code names stay in the
comments, never in a reason.
"""

from __future__ import annotations

from typing import Mapping, Optional

_POSITIVE_ONLY = (
    "Observes a compliance control only, with no finding or attack step, and a re-check targets "
    "findings and attack steps."
)
_NO_TARGET = "Backs no finding or attack step, so a re-check has nothing to target."
_HOST_REGISTRY = (
    "Read from each host's registry during host collection; the re-check reads the directory and "
    "the domain controller only, not member hosts."
)
_EXECUTE_CLAUSE = (
    "re-observing it means executing the step again (--step <id> --depth exercise, or --path <id> "
    "--depth walk), never a read."
)
_EXECUTE_STEP = (
    "Re-observing it means executing the step again (--step <id> --depth exercise, or --path <id> "
    "--depth walk), never a read."
)

#: Detector check id -> why it has no read-only observer in this release.
NOT_RECHECKABLE: Mapping[str, str] = {
    # -- directory reads with no observer wired yet --------------------------
    # Graded from the whole collected graph (attack_graph_findings over the
    # delegation attributes, SPNs and trusts), not by a per-object function.
    "ldap.delegation": (
        "No read-only observer yet: delegation findings and steps are graded from the whole "
        "collected graph, not by a check that re-reads one object."
    ),
    # positive_control_evidence segments the finding by the stamped privilege
    # tier of every holder (shadow_credential_segmentation).
    "ldap.shadow_credentials": (
        "No read-only observer yet: the finding is split by the privilege tier the scan grades "
        "over the whole graph, which re-reading the key credentials alone cannot reproduce."
    ),
    # audit_analyzer.analyze_audit_findings takes the whole CollectionResult.
    "ldap.account_hygiene": (
        "No read-only observer yet: account hygiene is graded over every collected account and "
        "computer at once, not by a check that re-reads one object."
    ),
    # credential_in_ldap_attribute is confirmed by a sign-in with the text found
    # (cli/ldap.py); the description findings come from a credential scan of
    # the collected descriptions.
    "ldap.attribute_secrets": (
        "Graded by scanning attribute text for credentials and confirming them with a sign-in; a "
        "re-check neither rescans that text nor signs in as another account."
    ),
    # trust_query enumerates every trust from each side.
    "ldap.trusts": (
        "No read-only observer yet: trust findings come from the scan's enumeration of every "
        "trust, which the re-check does not repeat."
    ),
    # Membership steps come from membership_snapshot and the privileged-group
    # classifier over the whole graph.
    "ldap.membership": (
        "No read-only observer yet: membership steps come from the scan's membership snapshot "
        "and its classification of privileged groups across the whole graph."
    ),
    "graph.tier0_exposure": (
        "Derived from the whole attack graph, including host and SQL Server collection; only a new "
        "scan re-derives it."
    ),
    # -- certificate services -------------------------------------------------
    "adcs.esc10": (
        "The scan does not read the domain controllers' certificate binding setting, so there is "
        "no scan verdict to reproduce."
    ),
    "adcs.esc12": (
        "Read on the CA host and only with proven CA-host administrator rights; the scan records "
        "it with its own check, which the re-check does not repeat."
    ),
    "adcs.esc14": (
        "Rests on a write right over a user object, not on a template or CA setting the AD CS "
        "re-check reads."
    ),
    "adcs.esc16": "No detector exists for this escalation, so the scan never raises it.",
    "adcs.esc17": "No detector exists for this escalation, so the scan never raises it.",
    # Graded inside the AD CS intelligence pass (cli/intelligence.py).
    "adcs.ntauth": (
        "No read-only observer yet: the orphaned NTAuth entry is graded inside the scan's AD CS "
        "analysis, not by a check that re-reads the NTAuth store."
    ),
    "adcs.role_separation": _POSITIVE_ONLY,
    "adcs.relay_to_web_enrollment": (
        "The step is a coerced authentication relayed to web enrollment; " + _EXECUTE_CLAUSE
    ),
    # -- domain policy ------------------------------------------------------
    # audit_analyzer.analyze_machine_rotation_finding reads GptTmpl.inf.
    "policy.machine_password_rotation": (
        "Read from Group Policy files in SYSVOL, not from the directory; the re-check reads the "
        "directory only."
    ),
    "policy.rc4_accounts": (
        "No read-only observer yet: RC4-only accounts are graded in the scan's account hygiene "
        "pass over every account."
    ),
    # audit_analyzer._analyze_reversible_encryption reads the domain root AND
    # every fine-grained password policy (PSO) of the collection.
    "policy.reversible_encryption": (
        "Needs the fine-grained password policies as well as the domain policy; the re-check "
        "reads the domain policy only."
    ),
    # -- posture categories --------------------------------------------------
    "posture.ldap_channel_binding": (
        "Observes a compliance control only; its answer is re-read by the LDAP signing re-check, "
        "which decides the LDAP security finding."
    ),
    "posture.ldap_starttls_available": _POSITIVE_ONLY,
    # -- protocol probes ------------------------------------------------------
    "probe.ldap_anonymous": (
        "Tested with an anonymous bind; the re-check signs in as an account, so it cannot repeat "
        "the unauthenticated test."
    ),
    # cli/ntlm_capture.py: coerced PDC capture.
    "probe.ntlmv1": (
        "Detected by coercing the domain controller into authenticating and reading the response "
        "it sends, which is not a read."
    ),
    "probe.smb_null_session": (
        "Tested with an anonymous SMB session; the re-check signs in as an account, so it cannot "
        "repeat the unauthenticated test."
    ),
    # Derived in persistence._persist_derived_attack_steps (the SPN pass).
    "probe.http_relay_surface": (
        "No read-only observer yet: derived in the scan's pass over every account's service "
        "principal names."
    ),
    # -- per-host reads ------------------------------------------------------
    "host.smbv1": (
        "Probed on each host during host collection; the re-check reads the directory and the "
        "domain controller only, not member hosts."
    ),
    "host.registry.lsa_protection": _HOST_REGISTRY,
    "host.registry.wdigest": _HOST_REGISTRY,
    "host.registry.lm_hash_storage": _HOST_REGISTRY,
    "host.registry.lm_compatibility": _HOST_REGISTRY,
    "host.registry.ntlm_min_session_security": _HOST_REGISTRY,
    "host.registry.lsass_custom_ssp": _HOST_REGISTRY,
    "host.endpoint_protection": _POSITIVE_ONLY,
    "host.access": (
        "Established by signing in to each host during host collection; " + _EXECUTE_CLAUSE
    ),
    "host.sessions": (
        "Logged-on sessions are listed on each host during host collection and change constantly; "
        "the re-check reads the directory only."
    ),
    "smb.share_access": (
        "Share access is tested on each host during host collection; the re-check reads the "
        "directory only."
    ),
    "mssql.access": (
        "Established by signing in to each SQL Server instance during collection; " + _EXECUTE_CLAUSE
    ),
    # -- vulnerability phase probes (cve_scanner) ------------------------------
    "cve.zerologon": (
        "Tested with Netlogon authentication attempts against each domain controller, which is not "
        "a read; only a new scan re-tests it."
    ),
    "cve.nopac": (
        "Tested by requesting tickets from the domain controller with and without a PAC, which is "
        "not a read; only a new scan re-tests it."
    ),
    "cve.ms17_010": (
        "Tested with an SMBv1 transaction probe on each host, which is not a read; only a new scan "
        "re-tests it."
    ),
    "cve.printnightmare": (
        "Read on each host over SMB and the remote registry by the vulnerability phase; the "
        "re-check reads the directory and the domain controller only."
    ),
    "cve.petitpotam": (
        "Tested by calling the RPC method that makes the host authenticate outward, which is not a "
        "read; only a new scan re-tests it."
    ),
    "cve.printerbug": (
        "Tested by calling the RPC method that makes the host authenticate outward, which is not a "
        "read; only a new scan re-tests it."
    ),
    "cve.dfscoerce": (
        "Tested by calling the RPC method that makes the host authenticate outward, which is not a "
        "read; only a new scan re-tests it."
    ),
    "cve.mseven": (
        "Tested by calling the RPC method that makes the host authenticate outward, which is not a "
        "read; only a new scan re-tests it."
    ),
    "cve.webdav": (
        "Tested by listing the named pipes of each host by the vulnerability phase; the re-check "
        "reads the directory and the domain controller only."
    ),
    "cve.shadowcoerce": _NO_TARGET,
    "cve.printerbug_surface": _NO_TARGET,
    "cve.badsuccessor": _NO_TARGET,
    "cve.smbghost": _NO_TARGET,
    "cve.drop_the_mic": _NO_TARGET,
    "cve.ntlm_reflection": _NO_TARGET,
    # adcs_collector derives it from the CA registry probe (the ESC6 / ESC11
    # inputs); adcs_observers does not map the relation.
    "cve.certighost": (
        "No read-only observer yet: graded from the CA registry values the ESC6 and ESC11 "
        "re-checks read, but no re-check grades this flaw from them."
    ),
    # -- credential hunting ---------------------------------------------------
    "hunt.gpp": (
        "Found by searching the Group Policy files in SYSVOL for stored passwords; only a new "
        "scan repeats that search."
    ),
    "hunt.share_secrets": (
        "Found by searching the content of every readable share; only a new scan repeats that "
        "search."
    ),
    # -- capture, crack and execution outcomes --------------------------------
    "credential.recovered": (
        "A password recovered by capture or cracking; only repeating the capture or the crack "
        "re-observes it, never a read."
    ),
    "credential.spray": _EXECUTE_STEP,
    "credential.reuse": _EXECUTE_STEP,
    "execution.credential_dump": _EXECUTE_STEP,
    "execution.relay": _EXECUTE_STEP,
    "execution.mssql": _EXECUTE_STEP,
}

#: Observed detector check id -> {finding key or step relation (lowercase) ->
#: why its observer never decides, or never closes, that key}.
NOT_RECHECKABLE_KEYS: Mapping[str, Mapping[str, str]] = {
    "ldap.object_acl": {
        # The native collector never produces an Owns edge: no scan predicate.
        "owns": "The scan's collector does not produce this right, so there is no scan verdict to reproduce.",
        "excessive_cross_tier_rights": (
            "A re-read of the recorded objects can confirm this finding but not close it: a right "
            "on an object the re-check did not read would be missed."
        ),
    },
    "ldap.laps": {
        "synclapspassword": (
            "The scan's collector does not produce this right, so there is no scan verdict to reproduce."
        ),
        "laps": (
            "A re-read of the recorded computers can confirm this finding but not close it: a "
            "right on a computer the re-check did not read would be missed."
        ),
        "laps_readable": (
            "A re-read of the recorded computers can confirm this finding but not close it: a "
            "right on a computer the re-check did not read would be missed."
        ),
    },
    "ldap.replication_rights": {
        "unauthorized_external_tenant_replication": (
            "The verdict needs the directory synchronization account inventory, which the "
            "re-check does not re-read."
        ),
    },
    "posture.smb_signing": {
        # posture_observers reads the domain controller only.
        "smb_signing_disabled": (
            "The re-check probes the domain controller only: it can confirm this finding but not "
            "close it, because member hosts are not re-read."
        ),
        "smb_relay_targets": (
            "Rests on member hosts that do not require SMB signing; the re-check probes the "
            "domain controller only."
        ),
    },
}


def declared_reason(check_id: Optional[str], kind: str, key: str, *, observed: bool) -> str:
    """The declared reason an item cannot be re-checked read-only, or ``""``.

    Args:
        check_id: The item's detector check id (``None``: no detector).
        kind: ``finding`` or a step kind.
        key: The finding key or the step relation.
        observed: Whether the detector has a read-only observer.
    """
    if not check_id:
        return ""
    if not observed:
        return NOT_RECHECKABLE.get(check_id, "")
    token = str(key) if kind == "finding" else str(key).lower()
    return NOT_RECHECKABLE_KEYS.get(check_id, {}).get(token, "")


def undecided_keys(check_id: str) -> frozenset[str]:
    """Keys of an observed family that its observer never decides or never closes."""
    return frozenset(NOT_RECHECKABLE_KEYS.get(check_id, {}))


__all__ = (
    "NOT_RECHECKABLE",
    "NOT_RECHECKABLE_KEYS",
    "declared_reason",
    "undecided_keys",
)
