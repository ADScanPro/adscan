"""Emit POSITIVE control evidence from OBSERVED-GOOD verdicts.

Single source of truth for the "we actively observed this hardened, so it is a
green control in the compliance scorecard" channel. Complements the negative
findings channel: a hardened environment must be able to show "verified OK", not
only "N broken". See CLAUDE.md § "Persist the POSITIVE result too" (the third-state
doctrine) and the compliance engine's ``build_requirement_control_evidence``, which
greens a control ONLY when the evidence ``status == "observed"``.

THE HARD BOUNDARY (never cross): emit a positive ONLY for an OBSERVED-GOOD verdict —
actively probed, definitive. NEVER for NOT_ASSESSED or INFERRED_BY_ABSENCE:

* Posture keys: emit ONLY when the constraint's ``effective_state`` is the hardened
  value AND ``confidence == HIGH``. This inherits the posture system's "observe,
  never infer" guarantee — a timeout / UNKNOWN / LOW never reaches a hardened state
  at HIGH, so it never emits (see § "Posture caching policy" — inferred-by-absence
  stays UNKNOWN/LOW).
* CVE keys: emit ONLY on a definitive ``NOT_VULNERABLE`` result from a probe that
  actually RAN (never ``SKIPPED`` / ``ERROR`` — those are data gaps, not verdicts).
* Password policy: emit ONLY when the default-domain-policy snapshot was READ (an
  actual LDAP read, not the assumed default) AND meets the CIS bar. Any required
  field unread → no emit (not_assessed, never green).

All emits are best-effort: wrapped in ``try/except`` + ``telemetry.capture_exception``
+ ``print_exception`` (mirrors ``integrations/impacket/runner.py``). Failing to
record a positive must never break the calling flow. The ``record_control_evidence``
recorder is resolved LITE-safe (it is a ``_CORE_REPORT_ATTRS`` member, so it lands in
``adscan_core.reporting.technical_report`` even when the PRO report service is
stripped from the LITE image).

Client-safe by construction: titles / details name only observed DC facts, never an
offensive tool.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Mapping, Optional

from adscan_core import telemetry
from adscan_core.reporting.principal_display import humanize_principal_for_prose
from adscan_core.rich_output import print_exception, print_info_debug
from adscan_internal.reporting_compat import load_optional_report_service_attr
from adscan_internal.services.domain_posture import (
    ConstraintCategory,
    DomainPosture,
    PasswordPolicySnapshot,
    SignalConfidence,
    TriState,
    get_posture,
)

# CIS Microsoft Windows Server Benchmark — the strong-password bar these controls
# green against (mirrored in the mapping spec the coordinator wires into the
# framework modules).
_CIS_MIN_PASSWORD_LENGTH = 14


def _resolve_recorder() -> Optional[Callable[..., None]]:
    """Return the LITE-safe ``record_control_evidence`` recorder, or ``None``."""
    recorder = load_optional_report_service_attr(
        "record_control_evidence",
        action="Positive control evidence",
        debug_printer=print_info_debug,
        prefix="[positive-control]",
    )
    return recorder if callable(recorder) else None


def _is_hardened_high(posture: DomainPosture, category: ConstraintCategory, hardened: TriState) -> bool:
    """True iff the constraint is OBSERVED at the hardened value with HIGH confidence.

    Reads ``effective_state`` (not ``state``) so a stale observation degrades to
    UNKNOWN and never emits — the "observe, never infer" boundary.
    """
    state = posture.get(category)
    return (
        state.effective_state is hardened
        and state.confidence is SignalConfidence.HIGH
    )


# Each row: (posture category, hardened TriState, positive key, title, evidence-note).
_POSTURE_POSITIVES: tuple[
    tuple[ConstraintCategory, TriState, str, str, str], ...
] = (
    (
        ConstraintCategory.LDAP_SIGNING,
        TriState.REQUIRED,
        "ldap_signing_required",
        "LDAP Signing Enforced",
        "The domain controller rejected an unsigned LDAP bind — LDAP signing is required.",
    ),
    (
        ConstraintCategory.LDAP_CHANNEL_BINDING,
        TriState.REQUIRED,
        "ldap_channel_binding_required",
        "LDAP Channel Binding Enforced",
        "The domain controller enforced LDAP channel binding (EPA) on the TLS bind.",
    ),
    (
        ConstraintCategory.SMB_SIGNING,
        TriState.REQUIRED,
        "smb_signing_required",
        "SMB Signing Enforced",
        "The domain controller negotiated SMB signing as required.",
    ),
    (
        ConstraintCategory.LDAPS_AVAILABLE,
        TriState.ENABLED,
        "ldaps_available",
        "LDAPS Available for Encrypted Directory Traffic",
        "The domain controller completed an LDAPS (TCP 636) TLS handshake: encrypted "
        "directory transport is available.",
    ),
    (
        ConstraintCategory.LDAP_STARTTLS_AVAILABLE,
        TriState.ENABLED,
        "starttls_available",
        "StartTLS Available for Encrypted Directory Traffic",
        "The domain controller completed a StartTLS upgrade on LDAP (TCP 389): encrypted "
        "directory transport is available.",
    ),
    (
        ConstraintCategory.KERBEROS_AES_ONLY,
        TriState.ENABLED,
        "kerberos_aes_only",
        "Kerberos AES Encryption Enforced (RC4 Refused)",
        "The KDC refused the legacy RC4 (arcfour-hmac) Kerberos encryption type — "
        "only AES etypes are accepted.",
    ),
)


def emit_posture_positives(shell: Any, domain: str) -> None:
    """Emit positive control evidence for every OBSERVED-GOOD posture constraint.

    Idempotent: ``record_control_evidence`` updates the existing entry by key, so
    calling this after every posture refresh (probed OR already-fresh) is safe.
    Reads the finalized posture from ``shell.domains_data`` via ``get_posture``.
    """
    domain_name = str(domain or "").strip()
    if not domain_name:
        return
    try:
        recorder = _resolve_recorder()
        if recorder is None:
            return
        posture = get_posture(getattr(shell, "domains_data", None), domain=domain_name)
        for category, hardened, key, title, note in _POSTURE_POSITIVES:
            if not _is_hardened_high(posture, category, hardened):
                continue
            recorder(
                shell,
                domain_name,
                key=key,
                title=title,
                category="Authentication Posture",
                status="observed",
                details={
                    "confidence": "high",
                    "observed_state": hardened.value,
                    "source": "posture_probe",
                    "evidence": note,
                },
            )
    except Exception as exc:  # pragma: no cover - best effort sync
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"[positive-control] posture positives emit failed: {exc}")


def _password_policy_meets_cis(snapshot: PasswordPolicySnapshot) -> bool:
    """True iff the default-domain-policy snapshot was READ and meets the CIS bar.

    Bar: min length >= 14 AND complexity on AND a finite lockout threshold (>0) AND
    reversible encryption OFF. Any required field unread (``store_cleartext_passwords``
    is ``None`` on a workspace saved before this field existed) → not assessed → no
    green. ``source`` must be the real read, not the assumed default.
    """
    if snapshot.source != "ad_default_domain_policy":
        return False
    if snapshot.store_cleartext_passwords is None:
        return False
    return (
        snapshot.min_length >= _CIS_MIN_PASSWORD_LENGTH
        and bool(snapshot.require_complexity)
        and snapshot.lockout_threshold > 0
        and snapshot.store_cleartext_passwords is False
    )


def emit_password_policy_positive(shell: Any, domain: str) -> None:
    """Emit ``strong_password_policy`` when the default domain policy meets CIS.

    Scope = default domain password policy (PSOs are out of scope). No emit unless
    every required field was actually read and meets the bar.
    """
    domain_name = str(domain or "").strip()
    if not domain_name:
        return
    try:
        recorder = _resolve_recorder()
        if recorder is None:
            return
        posture = get_posture(getattr(shell, "domains_data", None), domain=domain_name)
        snapshot = posture.password_policy
        if snapshot is None or not _password_policy_meets_cis(snapshot):
            return
        recorder(
            shell,
            domain_name,
            key="strong_password_policy",
            title="Strong Default Domain Password Policy",
            category="Password Policy",
            status="observed",
            details={
                "scope": "default_domain_policy",
                "min_length": snapshot.min_length,
                "require_complexity": bool(snapshot.require_complexity),
                "lockout_threshold": snapshot.lockout_threshold,
                "reversible_encryption_disabled": True,
                "source": snapshot.source,
                "evidence": (
                    "Default domain policy read via directory: minimum length "
                    f">= {_CIS_MIN_PASSWORD_LENGTH}, complexity enabled, account "
                    "lockout enforced, reversible encryption disabled."
                ),
            },
        )
    except Exception as exc:  # pragma: no cover - best effort sync
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"[positive-control] password policy positive emit failed: {exc}")


def emit_domain_policy_positives(
    shell: Any, domain: str, domain_policy: Any, psos: Any = None
) -> None:
    """Emit standalone domain-policy positives when read with certainty.

    Two controls whose observed-good state is a definitive directory read on the
    default domain policy (``result.domain_policy``), independent of the composite
    ``strong_password_policy`` positive so a domain that fails one policy knob can
    still green the controls it passes:

    - ``reversible_encryption_disabled`` — reversible password storage is off
      across BOTH policy scopes: the reversible-storage bit of ``pwdProperties``
      on the domain root, and every fine-grained password policy's
      ``msDS-PasswordReversibleEncryptionEnabled``. ``psos`` carries
      ``result.psos`` so this positive checks the SAME two scopes the negative
      finding does (``audit_analyzer._analyze_reversible_encryption``). Passing
      ``None`` reads as "no fine-grained policies were collected", which narrows
      the declared scope rather than widening the claim.
    - ``machine_account_quota_zero`` — ``ms-DS-MachineAccountQuota == 0``, so no
      standard user can join a computer (closes the "add a machine account then
      RBCD/shadow-creds" avenue at the source).

    Third-state discipline: only a definitive read emits. ``None`` (attribute not
    read) or the insecure value (``True`` / ``> 0``) never greens — that would be
    the INFERRED_BY_ABSENCE falsehood the doctrine forbids.

    **SCOPE, and why it is in the client-visible evidence rather than only in
    ``details``.** Judged as a sentence this positive was honest, and it still
    misled: in a deliverable listing recovered account passwords, the clause
    "cleartext-equivalent storage is disabled" read as a contradiction, and the
    green tick reached the compliance scorecard while the scope qualifier stayed
    in a ``details`` dict nobody renders. So the evidence now states the scope it
    covers (the password POLICIES) and the sub-scope it never read (the
    per-account reversible-encryption flag, ``userAccountControl`` ``0x80``),
    because under the three-state doctrine an unread sub-scope must not ride
    along inside a green. The compliance MAPPING was narrowed for the same
    reason: the mapping, not the sentence, is what reaches the scorecard.
    """
    domain_name = str(domain or "").strip()
    if not domain_name or domain_policy is None:
        return
    try:
        recorder = _resolve_recorder()
        if recorder is None:
            return

        reversible = getattr(domain_policy, "reversible_encryption_enabled", None)
        # Both policy scopes, the same pair the negative finding checks. A
        # fine-grained policy that ENABLES reversible storage blocks the green
        # outright; one that did not return the attribute is counted as unread and
        # declared, never folded in as a clean read.
        pso_list = list(psos or ())
        pso_enabled = any(
            getattr(pso, "reversible_encryption_enabled", None) is True
            for pso in pso_list
        )
        psos_read = sum(
            1
            for pso in pso_list
            if getattr(pso, "reversible_encryption_enabled", None) is False
        )
        psos_unread = len(pso_list) - psos_read - (1 if pso_enabled else 0)
        if reversible is False and not pso_enabled:
            policies_read = 1 + psos_read
            policies_noun = "policy" if policies_read == 1 else "policies"
            unread_clause = ""
            if psos_unread > 0:
                pol = "policy" if psos_unread == 1 else "policies"
                did = "did" if psos_unread == 1 else "did"
                unread_clause = (
                    f", and {psos_unread} fine-grained {pol} {did} not return "
                    "the attribute"
                )
            recorder(
                shell,
                domain_name,
                key="reversible_encryption_disabled",
                title="Reversible Password Storage Disabled in Policy",
                category="Password Policy",
                status="observed",
                details={
                    "scope": "password_policy",
                    "reversible_encryption_enabled": False,
                    "policies_read": policies_read,
                    "policies_unread": max(psos_unread, 0),
                    # The sub-scope this control does NOT cover, machine-readable
                    # so a consumer can qualify the green without parsing prose.
                    "per_account_flag_read": False,
                    "source": "directory",
                    "evidence": (
                        f"Reversible password storage is disabled across the "
                        f"{policies_read} password {policies_noun} read in this "
                        "domain: the reversible-storage bit is off on the domain "
                        "root, and no fine-grained password policy enables it. "
                        "This covers the policy scope. The per-account "
                        "reversible-encryption flag was not read in this "
                        "assessment, so this states nothing about an individual "
                        f"account carrying it{unread_clause}."
                    ),
                },
            )

        maq = getattr(domain_policy, "machine_account_quota", None)
        if isinstance(maq, int) and maq == 0:  # definitive read; None/>0 must NOT green
            recorder(
                shell,
                domain_name,
                key="machine_account_quota_zero",
                title="Machine Account Quota Set to Zero",
                category="Domain Configuration",
                status="observed",
                details={
                    "scope": "domain",
                    "machine_account_quota": 0,
                    "source": "directory",
                    "evidence": (
                        "ms-DS-MachineAccountQuota read via directory and equals 0 — "
                        "no standard domain user can join a computer account, closing "
                        "the machine-account creation avenue for RBCD/shadow-credential "
                        "abuse."
                    ),
                },
            )
    except Exception as exc:  # pragma: no cover - best effort sync
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"[positive-control] domain policy positives emit failed: {exc}")


# CVE id → (positive key, title). Only definitive NOT_VULNERABLE results emit.
_CVE_NOT_VULNERABLE_POSITIVES: dict[str, tuple[str, str]] = {
    "CVE-2020-1472": (
        "zerologon_not_vulnerable",
        "Zerologon Not Exploitable — Domain Controller Patched",
    ),
    "CVE-2021-42278": (
        "nopac_not_vulnerable",
        "NoPac (sAMAccountName spoofing) Not Exploitable — Domain Controller Patched",
    ),
    "CVE-2017-0144": (
        "ms17_010_not_present",
        "MS17-010 (EternalBlue) Not Present — Host Patched",
    ),
}


def emit_cve_not_vulnerable_positives(
    shell: Any, results: Any, *, host_to_domain: Optional[dict[str, str]] = None, default_domain: Optional[str] = None
) -> None:
    """Emit ``*_not_vulnerable`` positives for definitive NOT_VULNERABLE CVE results.

    ``results`` is any iterable of ``CVEResult``. Only ``NOT_VULNERABLE`` (a probe
    that ran and returned a verdict) emits; ``SKIPPED`` / ``ERROR`` / ``NOT_APPLICABLE``
    are data gaps and are ignored. The positive is recorded against the domain the
    checked host belongs to (``host_to_domain`` map, falling back to
    ``default_domain``).
    """
    try:
        recorder = _resolve_recorder()
        if recorder is None:
            return
        # Deferred import avoids a hard dependency at module import time.
        from adscan_internal.services.cve_scanner.result import CVEStatus

        host_map = host_to_domain or {}
        default = str(default_domain or "").strip()
        for result in results or ():
            key_title = _CVE_NOT_VULNERABLE_POSITIVES.get(str(getattr(result, "cve_id", "")))
            if key_title is None:
                continue
            if getattr(result, "status", None) is not CVEStatus.NOT_VULNERABLE:
                continue
            host = str(getattr(result, "host", "") or "").strip()
            domain_name = str(host_map.get(host) or default or "").strip()
            if not domain_name:
                continue
            key, title = key_title
            recorder(
                shell,
                domain_name,
                key=key,
                title=title,
                category="Patch State",
                status="observed",
                details={
                    "cve_id": str(getattr(result, "cve_id", "")),
                    "host": host,
                    "verdict": "not_vulnerable",
                    "source": "cve_probe",
                    "evidence": (
                        f"Active vulnerability check ran against {host} and returned "
                        "a definitive not-vulnerable verdict."
                    ),
                },
            )
    except Exception as exc:  # pragma: no cover - best effort sync
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"[positive-control] CVE not-vulnerable positives emit failed: {exc}")


# ── Registry-hardening positives (per-host, admin-gated) ─────────────────────
# The Fase-2b registry stage reads six HKLM hardening values per host (gated on
# local-admin, stamping ``reg_admin_gate=True`` on the node). When a value is
# OBSERVED good with certainty, it is a positive-control fact for the SAME control
# the insecure value would fail. These are PER-HOST, so a positive is emitted as a
# domain-level control_evidence entry whose ``evidence`` lists the good hosts and
# whose ``details`` states the coverage DENOMINATOR (M of N assessed hosts) — never
# a claim about hosts we could not assess (the absence trap: a host without
# ``reg_admin_gate`` was NOT assessed, so it counts toward neither good nor total).

# finding_key -> (positive_key, title, prop, observed-good predicate)
def _reg_good_ppl(state, val):  # RunAsPPL: present and 1/2 = protected
    return state == "present" and isinstance(val, int) and val >= 1
def _reg_good_off_or_absent(state, val):  # secure when 0 or absent (WDigest, CustomSSP)
    return state == "absent" or (state == "present" and val == 0)
def _reg_good_on(state, val):  # secure when present and 1 (NoLmHash)
    return state == "present" and val == 1
def _reg_good_lmcompat(state, val):  # secure when present and >= 5
    return state == "present" and isinstance(val, int) and val >= 5
def _reg_good_ntlmsec(state, val):  # secure when present and NTLMv2(0x80000)+128bit(0x20000000) set
    return state == "present" and isinstance(val, int) and (val & 0x20000000) and (val & 0x00080000)

_REGISTRY_POSITIVES = (
    # (positive_key, title, [(prop_key, good_predicate), ...] — ALL props must be good)
    ("lsa_protection_enabled", "LSASS Protection (RunAsPPL) Enabled",
     [("reg_lsa_runasppl", _reg_good_ppl)]),
    ("wdigest_disabled", "WDigest Cleartext Credential Caching Disabled",
     [("reg_wdigest_uselogoncredential", _reg_good_off_or_absent)]),
    ("lm_hash_storage_disabled", "LAN Manager Hash Storage Disabled",
     [("reg_lsa_nolmhash", _reg_good_on)]),
    ("lm_compatibility_hardened", "LAN Manager Authentication Level Hardened",
     [("reg_lsa_lmcompatibilitylevel", _reg_good_lmcompat)]),
    ("ntlm_min_session_security_hardened", "NTLM SSP Minimum Session Security Enforced",
     [("reg_msv1_0_ntlmminclientsec", _reg_good_ntlmsec),
      ("reg_msv1_0_ntlmminserversec", _reg_good_ntlmsec)]),
    ("lsass_custom_ssp_disallowed", "Custom SSP/AP Loading Into LSASS Disallowed",
     [("reg_lsa_allowcustomsspsaps", _reg_good_off_or_absent)]),
)


def emit_registry_positives(shell: Any, domain: str, nodes: Any) -> None:
    """Emit OBSERVED-GOOD registry-hardening positives from the collected hosts.

    Args:
        shell: The pentest shell (holds the technical report).
        domain: The domain the hosts belong to.
        nodes: An iterable of collected host nodes carrying the ``reg_*`` /
            ``reg_*_state`` properties + ``reg_admin_gate`` (only admin-assessed
            hosts have the gate True; others were NOT assessed and are excluded).

    A control is emitted GREEN only for the hosts where its value was observed
    good; the coverage denominator (assessed hosts) is recorded so the client sees
    "M of N assessed", never a claim about un-assessed hosts. Best-effort.
    """
    recorder = _resolve_recorder()
    if recorder is None:
        return
    domain_name = str(domain or "").strip()
    if not domain_name:
        return
    try:
        host_nodes = [
            n for n in (nodes or [])
            if getattr(n, "properties", None) and n.properties.get("reg_admin_gate") is True
        ]
        if not host_nodes:
            return  # no host was admin-assessed → nothing observed, nothing green
        assessed_total = len(host_nodes)
        for pos_key, title, checks in _REGISTRY_POSITIVES:
            good_hosts: list[str] = []
            for n in host_nodes:
                props = n.properties
                ok = True
                for prop_key, pred in checks:
                    state = str(props.get(f"{prop_key}_state") or "").strip().lower()
                    if state == "error" or state == "":
                        ok = False  # not conclusively observed on this host
                        break
                    if not pred(state, props.get(prop_key)):
                        ok = False
                        break
                if ok:
                    name = str(getattr(n, "samaccountname", "") or getattr(n, "name", "") or "").strip()
                    if name:
                        good_hosts.append(name)
            if not good_hosts:
                continue  # this control was not observed good on any assessed host
            recorder(
                shell,
                domain_name,
                key=pos_key,
                title=title,
                category="Endpoint Hardening",
                status="observed",
                details={
                    "hosts_conformant": len(good_hosts),
                    "hosts_assessed": assessed_total,
                    "source": "registry_collector",
                    "evidence": (
                        f"Observed hardened on {len(good_hosts)} of {assessed_total} "
                        "host(s) where the registry could be read (local admin). "
                        "Hosts that could not be assessed are not counted."
                    ),
                },
                evidence=[{"host": h} for h in good_hosts[:64]],
            )
    except Exception as exc:  # pragma: no cover - best effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"[positive-control] registry positives emit failed: {exc}")


def emit_smbv1_positive(shell: Any, domain: str, nodes: Any) -> None:
    """Emit ``smbv1_disabled`` from the active per-host SMBv1 probe.

    ``smb_collector.smb1_probe`` sends a raw ``NT LM 0.12`` negotiate to each
    host and stamps the tri-state ``smb_v1`` property: ``True`` (enabled → the
    finding), ``False`` (host answered and REFUSED SMBv1 → observed-good), and
    ABSENT when the probe was inconclusive (error/timeout → NOT_ASSESSED). Only
    an explicit ``False`` greens; a host with no ``smb_v1`` key was not
    conclusively probed and counts toward neither good nor the denominator — so
    the client sees "M of N probed", never a claim about un-probed hosts.
    """
    recorder = _resolve_recorder()
    if recorder is None:
        return
    domain_name = str(domain or "").strip()
    if not domain_name:
        return
    try:
        # Only nodes where the probe was CONCLUSIVE (property present) count.
        probed = [
            n for n in (nodes or [])
            if getattr(n, "properties", None) is not None
            and "smb_v1" in n.properties
        ]
        if not probed:
            return
        assessed_total = len(probed)
        good_hosts: list[str] = []
        for n in probed:
            if n.properties.get("smb_v1") is False:  # observed refused, with certainty
                name = str(
                    getattr(n, "samaccountname", "") or getattr(n, "name", "") or ""
                ).strip()
                if name:
                    good_hosts.append(name)
        if not good_hosts:
            return  # SMBv1 was not observed-disabled on any conclusively probed host
        recorder(
            shell,
            domain_name,
            key="smbv1_disabled",
            title="SMBv1 Protocol Disabled",
            category="Endpoint Hardening",
            status="observed",
            details={
                "hosts_conformant": len(good_hosts),
                "hosts_assessed": assessed_total,
                "source": "smb_negotiate_probe",
                "evidence": (
                    f"Active NT LM 0.12 negotiate probe: {len(good_hosts)} of "
                    f"{assessed_total} conclusively probed host(s) refused SMBv1. "
                    "Hosts the probe could not reach are not counted."
                ),
            },
            evidence=[{"host": h} for h in good_hosts[:64]],
        )
    except Exception as exc:  # pragma: no cover - best effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"[positive-control] SMBv1 positive emit failed: {exc}")


# ── Endpoint-protection positives (per-host, admin-gated) ────────────────────
# The Fase-2b registry stage additionally runs a defensive-posture inventory
# (see ``adscan_internal/services/collector/host_collector.py``
# ``_do_endpoint_protection_inventory``) that stamps ``endpoint_products`` /
# ``edr_active`` / ``av_active`` / ``endpoint_posture_assessed`` on each
# admin-assessed Computer node. This is inventory, not a finding: a host where
# no product was detected is NOT_ASSESSED-for-absence (never a "missing
# protection" finding — see the hard boundary in the module docstring), so only
# the PRESENT case emits, exactly mirroring ``emit_registry_positives`` above.


def emit_endpoint_protection_positive(shell: Any, domain: str, nodes: Any) -> None:
    """Emit ``endpoint_protection_present`` from the collected hosts.

    Args:
        shell: The pentest shell (holds the technical report).
        domain: The domain the hosts belong to.
        nodes: An iterable of collected host nodes carrying
            ``endpoint_posture_assessed`` / ``edr_active`` / ``av_active`` /
            ``endpoint_products`` (only admin-assessed hosts carry the flag;
            others were NOT assessed and are excluded from both counts).

    A control is emitted GREEN only listing the hosts where an ACTIVE
    endpoint-protection product was actually observed; the coverage
    denominator (assessed hosts) is recorded so the client sees "M of N
    assessed", never a claim about un-assessed hosts. Best-effort — a
    detection failure never breaks collection persistence.
    """
    recorder = _resolve_recorder()
    if recorder is None:
        return
    domain_name = str(domain or "").strip()
    if not domain_name:
        return
    try:
        assessed_nodes = [
            n for n in (nodes or [])
            if getattr(n, "properties", None)
            and n.properties.get("endpoint_posture_assessed") is True
        ]
        if not assessed_nodes:
            return  # no host was assessed → nothing observed, nothing green
        assessed_total = len(assessed_nodes)
        good_hosts: list[dict[str, Any]] = []
        for n in assessed_nodes:
            props = n.properties
            if not (bool(props.get("edr_active")) or bool(props.get("av_active"))):
                continue
            name = str(getattr(n, "samaccountname", "") or getattr(n, "name", "") or "").strip()
            if not name:
                continue
            products = props.get("endpoint_products") or []
            product_names = sorted(
                {
                    str(p.get("name") or "").strip()
                    for p in products
                    if isinstance(p, dict) and p.get("active") and p.get("name")
                }
            )
            good_hosts.append({"host": name, "products": product_names})
        if not good_hosts:
            return  # observed, but no active protection found on any assessed host
        recorder(
            shell,
            domain_name,
            key="endpoint_protection_present",
            title="Endpoint Protection Software Deployed",
            category="Endpoint Hardening",
            status="observed",
            details={
                "hosts_conformant": len(good_hosts),
                "hosts_assessed": assessed_total,
                "source": "endpoint_protection_inventory",
                "evidence": (
                    f"Active endpoint-protection software (AV/EDR) observed on "
                    f"{len(good_hosts)} of {assessed_total} host(s) where the "
                    "inventory could be read (local admin). Hosts that could not "
                    "be assessed are not counted, and a host with no detected "
                    "product is treated as not assessed for this purpose, never "
                    "as a finding."
                ),
            },
            evidence=good_hosts[:64],
        )
    except Exception as exc:  # pragma: no cover - best effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"[positive-control] endpoint protection positive emit failed: {exc}")


# ── Control-plane sync account (Azure AD Connect) hardening items ────────────
# An Azure AD Connect ("AAD Connect" / DirSync) account named MSOL_<12 hex> holds
# directory-replication (DCSync-equivalent) rights on the domain BY DESIGN, to
# support Password Hash Sync. ADscan suppresses the anomalous DCSync finding for a
# confirmed one (attack_graph_findings._is_tier0_source_legitimate_edge, keyed on
# the stamped Tier-0 label). This must NOT leave the report silent about a Tier-0
# asset (the third-state doctrine), so in place of the suppressed finding ADscan
# surfaces a Tier-0 asset-HARDENING item — a positive/action item, never a
# vulnerability. The tri-state SSOT node_is_control_plane_sync_account decides
# CONFIRMED (both signals) vs AMBIGUOUS (name only, provenance unconfirmed).


def _parse_aad_connect_description(description: str) -> tuple[str, str]:
    """Best-effort extract (install_host, tenant) from an AAD Connect description.

    The installer writes the description in the install locale, so the surrounding
    prose is localized, but the ``computer <HOST>`` and ``tenant <tenant>`` tokens
    are stable enough to anchor on when present. Returns empty strings for any
    field that could not be read — the item then simply omits it rather than
    guessing (the placeholder doctrine: name the real value or nothing).
    """
    text = description or ""
    host_match = re.search(
        r"running on computer\s+([A-Za-z0-9._-]+)", text, re.IGNORECASE
    )
    tenant_match = re.search(
        r"synchronize to tenant\s+([A-Za-z0-9._-]+)", text, re.IGNORECASE
    )
    install_host = host_match.group(1).strip().rstrip(".") if host_match else ""
    tenant = tenant_match.group(1).strip().rstrip(".") if tenant_match else ""
    return install_host, tenant


def _domain_to_dn(domain: str) -> str:
    """Return the LDAP base DN for *domain* (``corp.example`` -> ``DC=corp,DC=example``)."""
    parts = [p for p in str(domain or "").split(".") if p]
    return ",".join(f"DC={p}" for p in parts) if parts else "DC=<your-domain>"


def _sync_account_display(samaccountname: str) -> str:
    """Client-prose display of an MSOL sync account: bare sAMAccountName, lower-cased.

    Runs through the principal-display SSOT first (to strip any ``DOMAIN\\`` /
    ``@realm`` qualifier the way every deliverable does), then lower-cases: an MSOL
    account is a machine-generated identifier stored mixed-case (``MSOL_<hex>``),
    and AD names are case-insensitive, so the human form is the lower-cased account
    that also matches the native remediation commands.
    """
    display = humanize_principal_for_prose(
        label=str(samaccountname or ""),
        samaccountname=str(samaccountname or ""),
        kind="user",
    )
    return display.lower()


def emit_control_plane_sync_account_items(shell: Any, domain: str, graph: Any) -> None:
    """Emit a Tier-0 asset-hardening item for each Azure AD Connect sync account.

    Reframes the by-design DCSync of a control-plane sync account as an asset to
    protect rather than a finding. Two states, both persisted as ``control_evidence``:

    * CONFIRMED (AAD Connect provenance + MSOL name) -> a Tier-0 asset-hardening
      item: protect the AAD Connect server, treat the account as Tier 0. Reads the
      install host and tenant from the persisted ``description`` when present.
    * AMBIGUOUS (MSOL name only, provenance unconfirmed) -> a single client-
      confirmation item: confirm the account belongs to an authorized installation.

    One entry per account (keyed by sAMAccountName), so several MSOL accounts do
    not collapse onto one. Idempotent (``record_control_evidence`` updates by key)
    and best-effort. Native remediation only; no offensive-tool names; English.
    """
    domain_name = str(domain or "").strip()
    if not domain_name:
        return
    nodes = graph.get("nodes") if isinstance(graph, dict) else None
    if not isinstance(nodes, dict):
        return
    try:
        # Deferred import keeps the classification SSOT out of the module import
        # graph until an actual sync-account emit is requested.
        from adscan_internal.services.compromise_class import (
            SyncAccountState,
            node_is_control_plane_sync_account,
        )

        recorder = _resolve_recorder()
        if recorder is None:
            return

        domain_dn = _domain_to_dn(domain_name)
        for node in nodes.values():
            if not isinstance(node, dict):
                continue
            state = node_is_control_plane_sync_account(node)
            if state is SyncAccountState.NONE:
                continue

            props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
            sam = str(props.get("samaccountname") or node.get("name") or node.get("label") or "").strip()
            if not sam:
                continue
            account = _sync_account_display(sam)
            account_lower = sam.split("\\")[-1].split("@")[0].strip().lower()
            install_host, tenant = _parse_aad_connect_description(
                str(props.get("description") or "")
            )

            provenance = ""
            if install_host and tenant:
                provenance = (
                    f" The account runs on {install_host} and synchronizes to tenant "
                    f"{tenant}; confirm this installation is authorized."
                )
            elif install_host:
                provenance = f" The account runs on {install_host}; confirm this installation is authorized."

            if state is SyncAccountState.CONFIRMED:
                guidance = (
                    f"{account} is an Azure AD Connect directory-synchronization account. "
                    "Its directory-replication rights are granted at installation to support "
                    "Password Hash Sync, so this access is expected and is not a "
                    "misconfiguration. Anyone who controls this account, or the server it runs "
                    "on, can replicate every credential in the domain, which makes it a Tier 0 "
                    "identity. Protect the Azure AD Connect server to the same standard as a "
                    "domain controller, restrict this account's sign-in to that server, and "
                    "manage its password under your Tier 0 rotation policy." + provenance
                )
                remediation = (
                    f"Confirm the account and its provenance: Get-ADUser {account_lower} "
                    "-Properties Description,MemberOf,whenCreated. Review the directory-"
                    f'replication grant on the domain head: dsacls "{domain_dn}". Restrict '
                    "interactive and remote sign-in to the Azure AD Connect server with a "
                    "Group Policy 'Deny log on' assignment, and place the account in a Tier 0 "
                    "organizational unit governed by your privileged-access policy."
                )
                recorder(
                    shell,
                    domain_name,
                    key=f"control_plane_sync_account_tier0::{account_lower}",
                    title="Azure AD Connect Sync Account (Tier 0 Asset)",
                    category="Tier 0 Asset Hardening",
                    status="observed",
                    details={
                        "account": account,
                        "install_host": install_host,
                        "tenant": tenant,
                        "sync_account_state": "confirmed",
                        "source": "attack_graph",
                        "evidence": guidance,
                        "remediation": remediation,
                    },
                )
            else:  # SyncAccountState.AMBIGUOUS
                guidance = (
                    f"{account} matches the naming pattern of an Azure AD Connect directory-"
                    "synchronization account, but its Azure AD Connect provenance could not be "
                    "confirmed from the directory because the account description is absent or "
                    "edited. A legitimate synchronization account and an account created by an "
                    "attacker that borrows this naming pattern are indistinguishable in the "
                    "directory apart from that provenance, so this one needs a human decision. "
                    "Confirm with your identity team whether the account belongs to an "
                    "authorized Azure AD Connect installation. If it does, protect it as a "
                    "Tier 0 identity. If no such installation exists, its directory-replication "
                    "rights are unauthorized and should be removed." + provenance
                )
                remediation = (
                    f"Verify provenance: Get-ADUser {account_lower} -Properties "
                    "Description,whenCreated,MemberOf. Review the directory-replication grant it "
                    f'holds on the domain head: dsacls "{domain_dn}". If the account is not part '
                    "of an authorized Azure AD Connect deployment, remove its Get-Changes and "
                    "Get-Changes-All grant on the domain object."
                )
                recorder(
                    shell,
                    domain_name,
                    key=f"control_plane_sync_account_ambiguous::{account_lower}",
                    title="Confirm Azure AD Connect Sync Account Is Authorized",
                    category="Tier 0 Asset Hardening",
                    status="needs_confirmation",
                    details={
                        "account": account,
                        "install_host": install_host,
                        "tenant": tenant,
                        "sync_account_state": "ambiguous",
                        "source": "attack_graph",
                        "evidence": guidance,
                        "remediation": remediation,
                    },
                )
    except Exception as exc:  # pragma: no cover - best effort sync
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"[positive-control] sync-account hardening emit failed: {exc}")


# ── Foreign-tenant replication: the finding, and the item it reconciles with ──
# A sync account whose replication TARGET tenant carries none of the organization's
# own identity tokens is the one case where the by-design reading above does not
# hold: the rights are real, and the destination is not the client's. That is a
# CLIENT FINDING, so it is recorded as one HERE, in the engine, under the catalogued
# key EXTERNAL_TENANT_REPLICATION_KEY. It used to be synthesized inside the PDF
# renderer and again inside the bonus playbook, which is why the paid report asserted
# one more critical than the scan had recorded and the free report, the posture score,
# the compliance annex and the web CTEM never saw it at all.
#
# The verdict needs the FULL assessed domain set (the client's own identity tokens
# come from every domain in the report), and a domain enumerated later must be able
# to change it, so it cannot be settled per-domain while the scan runs. It is settled
# once, at the reconciliation seam both tiers pass through before reading the report.


def _foreign_sync_account_guidance(
    *, account: str, tenant: str, install_host: str, finding_title: str
) -> str:
    """Author the hardening guidance for a FOREIGN-tenant sync account.

    The third state, alongside the CONFIRMED and AMBIGUOUS prose authored in
    :func:`emit_control_plane_sync_account_items`. It exists because the CONFIRMED
    text states that the replication access "is expected and is not a
    misconfiguration", which is true of an account synchronizing to the
    organization's own tenant and false of this one. Shipping both that sentence
    and a critical finding about the same account in one report is a contradiction
    a reader is right to distrust, so the reassurance is withdrawn and the item
    points at the finding instead.
    """
    where = ""
    if install_host:
        where = f", running on {install_host}"
    return (
        f"{account} matches the naming of an Azure AD Connect directory-"
        "synchronization account and holds the directory-replication rights such an "
        f"account is given at installation{where}. Its synchronization target, "
        f"tenant {tenant or 'an external tenant'}, carries none of this "
        "organization's own identifiers, so the usual reading of those rights as "
        "expected does not apply here and this account is not treated as assured. "
        f"It is raised as the finding {finding_title}, which carries the full "
        "analysis and the steps to take. Verify this account before the rest of "
        "this section: confirm with your identity team that the installation exists "
        "and is authorized. If it does, protect the account and its server as "
        "Tier 0 identities. If no such installation is authorized, the replication "
        "rights are unauthorized and have to be removed."
    )


def reconcile_external_tenant_replication(shell: Any) -> None:
    """Record, refresh or retract the external-tenant replication finding.

    Folds the persisted Tier-0 hardening control evidence across EVERY domain in
    the report through the shared verdict SSOT
    (:func:`~adscan_core.reporting.tier0_hardening.build_tier0_hardening_items`),
    so the coverage card's "does not match this organization's domains" verdict
    and the existence of the finding can never disagree: both read one derivation
    over one domain set.

    Per owning domain, for the accounts whose sync target is foreign:

    * records the catalogued finding, carrying the real account, tenant and
      install host so the remediation commands and the affected-assets block name
      the actual objects rather than a fill-in token;
    * rewords that account's hardening item so the report does not call the same
      account expected and critical at once.

    Retracts the finding for a domain that no longer has a foreign-tenant account,
    because ``technical_report.json`` outlives a single scan and a stale critical
    is a claim the client cannot reproduce.

    Idempotent (both recorders update by key) and best-effort: a failure here must
    never break a render.
    """
    try:
        from adscan_core.reporting.tier0_hardening import (  # noqa: PLC0415
            EXTERNAL_TENANT_REPLICATION_KEY,
            FOREIGN_TENANT_SAR_FINDING,
            build_tier0_hardening_items,
        )

        record_finding = load_optional_report_service_attr(
            "record_technical_finding",
            action="External-tenant replication finding",
            debug_printer=print_info_debug,
            prefix="[positive-control]",
        )
        retract_finding = load_optional_report_service_attr(
            "retract_technical_finding",
            action="External-tenant replication retraction",
            debug_printer=print_info_debug,
            prefix="[positive-control]",
        )
        record_evidence = _resolve_recorder()
        if not callable(record_finding) or not callable(retract_finding):
            return

        # Read the report through the LITE-safe core reader (always present; the
        # PRO report service only re-exports the writers).
        from adscan_core.reporting.technical_report import (  # noqa: PLC0415
            _load_technical_report,
        )

        report = _load_technical_report(shell)
        domains = report.get("domains") if isinstance(report, dict) else None
        if not isinstance(domains, dict):
            return
        blocks = [
            (str(name), block)
            for name, block in domains.items()
            if isinstance(block, dict)
        ]
        if not blocks:
            return

        rows = [
            row
            for row in build_tier0_hardening_items(blocks)
            if isinstance(row, dict) and not row.get("tenant_matches", True)
        ]

        # One finding per OWNING domain (the first domain a cross-domain account
        # was seen in), so an account visible through two domains is not counted
        # as two findings.
        by_domain: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            owner = next(
                (d for d in (row.get("domains") or []) if str(d).strip()), ""
            )
            if owner:
                by_domain.setdefault(owner, []).append(row)

        for domain_name, _block in blocks:
            domain_rows = by_domain.get(domain_name) or []
            if not domain_rows:
                retract_finding(shell, domain_name, key=EXTERNAL_TENANT_REPLICATION_KEY)
                continue

            accounts = [
                {
                    "samaccountname": str(row.get("account") or "").strip(),
                    "sync_target": str(row.get("tenant") or "").strip(),
                    "install_host": str(row.get("install_host") or "").strip(),
                }
                for row in domain_rows
                if str(row.get("account") or "").strip()
            ]
            if not accounts:
                retract_finding(shell, domain_name, key=EXTERNAL_TENANT_REPLICATION_KEY)
                continue

            record_finding(
                shell,
                domain_name,
                key=EXTERNAL_TENANT_REPLICATION_KEY,
                status="confirmed",
                details={
                    "accounts": accounts,
                    # The finding's own subject principal, read by the shared
                    # command personalizer to fill the ``<ACCOUNT>`` token.
                    "username": accounts[0]["samaccountname"],
                    "tenants": sorted(
                        {a["sync_target"] for a in accounts if a["sync_target"]}
                    ),
                    "install_hosts": sorted(
                        {a["install_host"] for a in accounts if a["install_host"]}
                    ),
                },
            )

            if not callable(record_evidence):
                continue
            for row in domain_rows:
                evidence_key = str(row.get("key") or "").strip()
                if not evidence_key:
                    continue
                record_evidence(
                    shell,
                    domain_name,
                    key=evidence_key,
                    title=str(row.get("title") or "").strip() or None,
                    category="Tier 0 Asset Hardening",
                    status="needs_confirmation",
                    details={
                        "sync_target_is_foreign": True,
                        "evidence": _foreign_sync_account_guidance(
                            account=str(row.get("account") or "").strip(),
                            tenant=str(row.get("tenant") or "").strip(),
                            install_host=str(row.get("install_host") or "").strip(),
                            finding_title=FOREIGN_TENANT_SAR_FINDING,
                        ),
                    },
                )
    except Exception as exc:  # pragma: no cover - best effort reconciliation
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(
            f"[positive-control] external-tenant replication reconcile failed: {exc}"
        )


# ── Shadow credentials: separate the Hello rollout from the planted ones ──────
# ``msDS-KeyCredentialLink`` is populated both by a sanctioned Windows Hello /
# hybrid-join rollout and by an attacker planting a backdoor, and one entry looks
# identical either way. Reported as one aggregate finding the number means
# nothing: on a reference engagement it covered 86 Tier-2 computers and 3 Tier-0
# users, and an AD team dismisses 89 objects as "our Hello rollout" in thirty
# seconds, taking the three that mattered with it.
#
# The discriminators are already in the workspace (object type, privilege tier,
# population scale, an observed sync account as hybrid corroboration), so the
# finding is SEGMENTED here rather than hedged. Pure shape logic lives in the
# LITE-safe SSOT ``adscan_core.reporting.shadow_credential_segmentation``; this
# resolves its inputs from the stamped graph and persists the two outcomes.

#: ``control_evidence`` key for the observed rollout. Deliberately NOT a
#: POSITIVE_CONTROL_KEYS member: observing the attribute populated at scale
#: proves key registration was DEPLOYED, not that passwordless authentication is
#: ENFORCED, and greening an authentication control on the weaker fact is the
#: over-claim the third-state doctrine forbids. It is recorded as an observation
#: of the environment, which is what makes the segmented finding legible.
_WHFB_ROLLOUT_EVIDENCE_KEY = "whfb_key_credential_rollout"


def _graph_node_tier0_index(graph: Any) -> dict[str, bool]:
    """Map lower-cased sAMAccountName to its stamped Tier-0 verdict.

    Reads the stamped, membership+ACL-aware ``privilege_tier`` via the SSOT
    predicate, never the raw ``isTierZero`` boolean: the two legitimately
    diverge, and the raw flag is collector-time output that misses any
    membership- or ACL-derived Tier 0.
    """
    index: dict[str, bool] = {}
    nodes = graph.get("nodes") if isinstance(graph, dict) else None
    if not isinstance(nodes, dict):
        return index
    try:
        from adscan_internal.services.compromise_class import (  # noqa: PLC0415
            node_is_tier0_by_stamped_label,
        )
    except Exception:  # noqa: BLE001 - no stamp available, every object reads Tier-2
        return index
    for node in nodes.values():
        if not isinstance(node, dict):
            continue
        props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
        name = str(props.get("samaccountname") or "").strip().lower()
        if not name:
            label = str(node.get("label") or node.get("name") or "").strip()
            name = label.split("@", 1)[0].split("\\")[-1].strip().lower()
        if not name:
            continue
        try:
            is_tier0 = bool(node_is_tier0_by_stamped_label(node))
        except Exception:  # noqa: BLE001 - a malformed node is simply not Tier-0
            is_tier0 = False
        # A name seen twice keeps the STRONGER verdict: never downgrade a Tier-0
        # object because a second node carried the same sAMAccountName.
        index[name] = index.get(name, False) or is_tier0
    return index


def _workspace_is_hybrid(domain_block: Any) -> bool:
    """Whether this domain carries an observed Azure AD Connect sync account.

    Independent corroboration that a hybrid rollout exists, read from the
    control evidence the sync-account emit above already persisted, so hybridness
    is an observed fact rather than an assumption about the environment.
    """
    if not isinstance(domain_block, Mapping):
        return False
    entries = domain_block.get("control_evidence")
    if not isinstance(entries, list):
        return False
    return any(
        isinstance(entry, Mapping)
        and str(entry.get("category") or "").strip() == "Tier 0 Asset Hardening"
        for entry in entries
    )


def reconcile_shadow_credential_segmentation(shell: Any, domain: str, graph: Any) -> None:
    """Scope the shadow-credential finding to the objects a rollout cannot explain.

    Re-reads the raw ``shadow_credentials_present`` finding the collector
    recorded, resolves each object's stamped privilege tier from the graph,
    segments it by population shape, and persists the two outcomes:

    * the objects to confirm stay the finding, now scoped and Tier-0 first, so
      the contextual Tier-0 CVSS elevation applies to the accounts that earned
      it instead of to an 89-object blob;
    * the rollout is recorded as control evidence, an observation of the
      environment and never a weakness.

    Retracts the finding outright when every object belongs to the rollout: a
    managed Hello deployment is not a client finding.

    Idempotent (both recorders update by key) and best-effort.
    """
    try:
        from adscan_core.reporting.shadow_credential_segmentation import (  # noqa: PLC0415
            ShadowCredentialObject,
            segment_shadow_credentials,
        )
        from adscan_core.reporting.technical_report import (  # noqa: PLC0415
            _load_technical_report,
        )

        domain_name = str(domain or "").strip()
        if not domain_name:
            return

        record_finding = load_optional_report_service_attr(
            "record_technical_finding",
            action="Shadow credential segmentation",
            debug_printer=print_info_debug,
            prefix="[positive-control]",
        )
        retract_finding = load_optional_report_service_attr(
            "retract_technical_finding",
            action="Shadow credential retraction",
            debug_printer=print_info_debug,
            prefix="[positive-control]",
        )
        if not callable(record_finding) or not callable(retract_finding):
            return

        report = _load_technical_report(shell)
        domains = report.get("domains") if isinstance(report, dict) else None
        domain_block = domains.get(domain_name) if isinstance(domains, dict) else None
        if not isinstance(domain_block, Mapping):
            return
        findings = domain_block.get("findings")
        if not isinstance(findings, list):
            return
        raw = next(
            (
                item
                for item in findings
                if isinstance(item, Mapping)
                and item.get("key") == "shadow_credentials_present"
            ),
            None,
        )
        if raw is None:
            return
        details = raw.get("details") if isinstance(raw.get("details"), Mapping) else {}
        objects = details.get("objects")
        if not isinstance(objects, list) or not objects:
            return
        # Already segmented by an earlier pass: re-segmenting the scoped set would
        # judge the confirm list as its own population and could baseline it.
        if details.get("segmented_by_population_shape"):
            return

        tier0_index = _graph_node_tier0_index(graph)
        records = []
        for entry in objects:
            if not isinstance(entry, Mapping):
                continue
            name = str(entry.get("samaccountname") or "").strip()
            if not name:
                continue
            records.append(
                ShadowCredentialObject(
                    samaccountname=name,
                    kind=str(entry.get("kind") or ""),
                    is_tier0=tier0_index.get(name.lower(), False),
                    key_count=int(entry.get("key_count") or 1),
                )
            )
        if not records:
            return

        by_name = {
            str(e.get("samaccountname") or "").strip().lower(): e
            for e in objects
            if isinstance(e, Mapping)
        }
        segmentation = segment_shadow_credentials(
            records, hybrid=_workspace_is_hybrid(domain_block)
        )

        if segmentation.has_accounts_to_confirm:
            scoped = []
            for obj in segmentation.accounts_to_confirm:
                original = dict(by_name.get(obj.samaccountname.lower()) or {})
                original["samaccountname"] = obj.samaccountname
                original["kind"] = obj.kind
                original["is_tier0"] = obj.is_tier0
                scoped.append(original)
            record_finding(
                shell,
                domain_name,
                key="shadow_credentials_present",
                status="confirmed",
                details={
                    "objects": scoped,
                    "count": len(scoped),
                    "tier0_count": segmentation.tier0_count,
                    "segmented_by_population_shape": True,
                    "rollout_baseline_count": len(segmentation.rollout_baseline),
                    "rollout_computer_count": segmentation.computer_count,
                    "rollout_user_count": segmentation.user_count,
                    "rollout_threshold": segmentation.rollout_threshold,
                    "hybrid_environment": segmentation.hybrid,
                },
            )
        else:
            retract_finding(shell, domain_name, key="shadow_credentials_present")

        if not segmentation.has_rollout_baseline:
            return
        recorder = _resolve_recorder()
        if not callable(recorder):
            return
        computers = segmentation.computer_count
        users = segmentation.user_count
        population: list[str] = []
        if computers:
            population.append(f"{computers} computer account{'s' if computers != 1 else ''}")
        if users:
            population.append(f"{users} user account{'s' if users != 1 else ''}")
        population_phrase = " and ".join(population) or "accounts"
        corroboration = (
            " A directory-synchronization account for Azure AD Connect was also "
            "observed in this domain, which is consistent with a hybrid "
            "deployment."
            if segmentation.hybrid
            else ""
        )
        guidance = (
            f"{population_phrase} carry a key credential "
            "(msDS-KeyCredentialLink), the attribute written when a device or a "
            "user is enrolled for certificate-based logon through Windows Hello "
            "for Business or hybrid directory join. At this scale the population "
            "reads as a managed rollout rather than individually planted entries, "
            "so it is recorded as an observation of the environment and not as a "
            f"weakness.{corroboration} Key credentials are device-bound and "
            "phishing-resistant, so a rollout is good hygiene. Objects whose entry "
            "the rollout does not account for are reported separately under "
            "Shadow Credentials, which is where the accounts needing a decision "
            "are listed."
        )
        remediation = (
            "Keep enrolment under sanctioned policy so new key credentials stay "
            "attributable: confirm the rollout scope with Get-ADObject -LDAPFilter "
            "'(msDS-KeyCredentialLink=*)' -Properties msDS-KeyCredentialLink, and "
            "audit writes to the attribute (Event ID 5136) through the Default "
            "Domain Controllers Policy so an entry added outside the rollout is "
            "visible."
        )
        recorder(
            shell,
            domain_name,
            key=_WHFB_ROLLOUT_EVIDENCE_KEY,
            title="Certificate-Based Logon Enrolment Observed (Windows Hello / Hybrid Join)",
            category="Control Evidence",
            status="observed",
            details={
                "computer_count": computers,
                "user_count": users,
                "rollout_threshold": segmentation.rollout_threshold,
                "hybrid_environment": segmentation.hybrid,
                "source": "attack_graph",
                "evidence": guidance,
                "remediation": remediation,
            },
        )
    except Exception as exc:  # pragma: no cover - best effort reconciliation
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(
            f"[positive-control] shadow-credential segmentation failed: {exc}"
        )


def emit_esc15_hardened_positive(
    shell: Any,
    domain: str,
    *,
    template: Optional[str] = None,
    ca_name: Optional[str] = None,
    reason: Optional[str] = None,
) -> None:
    """Emit ``esc15_application_policy_injection_mitigated`` from a confirm-mode hardened verdict.

    The ESC15 (EKUwu / CVE-2024-49019) NON-DESTRUCTIVE confirm-mode enrolled a
    self-subject certificate with a canary application policy and OBSERVED that
    the CA stripped the injected policy from the issued certificate — a
    definitive, actively-probed positive (the CA is patched). This greens the
    control the ESC15 finding would otherwise fail, exactly like the CVE
    ``*_not_vulnerable`` positives: only the OBSERVED-GOOD verdict emits (the
    caller calls this only for the ``hardened`` verdict, never for
    ``attempted`` / ``indeterminate``, which are data gaps).

    Best-effort and idempotent (``record_control_evidence`` updates by key).
    Client-safe: names only observed PKI facts, never an offensive tool.
    """
    domain_name = str(domain or "").strip()
    if not domain_name:
        return
    try:
        recorder = _resolve_recorder()
        if recorder is None:
            return
        details: dict[str, Any] = {
            "verdict": "hardened",
            "cve_id": "CVE-2024-49019",
            "source": "adcs_esc15_confirm",
            "evidence": (
                "ADscan enrolled a self-subject certificate with an injected "
                "application policy and observed that the certification authority "
                "stripped it from the issued certificate. The CA does not honour "
                "attacker-supplied application policies, so the EKUwu escalation "
                "(ESC15 / CVE-2024-49019) is not exploitable on this CA."
            ),
        }
        if template:
            details["template"] = str(template)
        if ca_name:
            details["ca_name"] = str(ca_name)
        if reason:
            details["observation"] = str(reason)
        recorder(
            shell,
            domain_name,
            key="esc15_application_policy_injection_mitigated",
            title="ADCS Application-Policy Injection Not Honoured (ESC15 / EKUwu Patched)",
            category="Certificate Services",
            status="observed",
            details=details,
        )
    except Exception as exc:  # pragma: no cover - best effort sync
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"[positive-control] ESC15 hardened positive emit failed: {exc}")


def emit_esc14_hardened_positive(
    shell: Any,
    domain: str,
    *,
    scbe: Optional[int] = None,
    reason: Optional[str] = None,
) -> None:
    """Emit ``esc14_weak_explicit_mapping_mitigated`` from a hardened SCBE verdict.

    The ESC14 (weak explicit certificate mapping) NON-DESTRUCTIVE confirm READ
    StrongCertificateBindingEnforcement on every domain controller over Remote
    Registry and OBSERVED Full enforcement (== 2) everywhere — a definitive,
    actively-probed positive: a weak ``altSecurityIdentities`` mapping is refused,
    so the explicit-mapping abuse is not exploitable. This greens the control the
    ESC14 finding would otherwise fail, exactly like the CVE ``*_not_vulnerable``
    positives: only the OBSERVED-GOOD verdict emits (the caller calls this only for
    the hardened verdict, never for a pending / confirmed one, which are data gaps
    or live findings).

    Best-effort and idempotent (``record_control_evidence`` updates by key).
    Client-safe: names only observed DC facts, never an offensive tool.
    """
    domain_name = str(domain or "").strip()
    if not domain_name:
        return
    try:
        recorder = _resolve_recorder()
        if recorder is None:
            return
        details: dict[str, Any] = {
            "verdict": "hardened",
            "source": "adcs_esc14_confirm",
            "evidence": (
                "ADscan read StrongCertificateBindingEnforcement on every domain "
                "controller and observed Full enforcement (value 2) throughout. "
                "Domain controllers refuse weak explicit certificate mappings "
                "(altSecurityIdentities), so the ESC14 explicit-mapping escalation "
                "is not exploitable (KB5014754)."
            ),
        }
        if isinstance(scbe, int):
            details["strong_certificate_binding_enforcement"] = scbe
        if reason:
            details["observation"] = str(reason)
        recorder(
            shell,
            domain_name,
            key="esc14_weak_explicit_mapping_mitigated",
            title="Strong Certificate Binding Enforced (ESC14 Explicit-Mapping Abuse Mitigated)",
            category="Certificate Services",
            status="observed",
            details=details,
        )
    except Exception as exc:  # pragma: no cover - best effort sync
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"[positive-control] ESC14 hardened positive emit failed: {exc}")


def emit_esc9_hardened_positive(
    shell: Any,
    domain: str,
    *,
    scbe: Optional[int] = None,
    reason: Optional[str] = None,
) -> None:
    """Emit ``esc9_implicit_mapping_mitigated`` from a hardened ESC9/10 verdict.

    The ESC9/ESC10 (implicit certificate mapping) NON-DESTRUCTIVE confirm OBSERVED
    that the domain controllers enforce strong certificate binding (KB5014754 Full):
    either the registry read reported Full on every DC, or the behavioral canary saw
    a Kerberos code-66 refusal of a self no-SID certificate. A certificate with no
    SID security extension is refused, so the implicit-mapping escalation is not
    exploitable. This greens the control the ESC9/10 finding would otherwise fail,
    exactly like the CVE ``*_not_vulnerable`` positives: only the OBSERVED-GOOD
    verdict emits (the caller calls this only for the hardened verdict, never for a
    pending / confirmed one).

    The note records BOTH the active mitigation AND the latent template weakness
    (the template still carries ``CT_FLAG_NO_SECURITY_EXTENSION``), the
    defence-in-depth signal: the escalation becomes exploitable again if strong
    certificate binding is ever lowered. Best-effort and idempotent
    (``record_control_evidence`` updates by key). Client-safe: names only observed
    DC/PKI facts, never an offensive tool.
    """
    domain_name = str(domain or "").strip()
    if not domain_name:
        return
    try:
        recorder = _resolve_recorder()
        if recorder is None:
            return
        details: dict[str, Any] = {
            "verdict": "hardened",
            "source": "adcs_esc9_confirm",
            "evidence": (
                "ADscan observed that the domain controllers enforce strong "
                "certificate binding (KB5014754 Full): a certificate carrying no SID "
                "security extension is refused for implicit mapping, so the ESC9 / "
                "ESC10 escalation is not exploitable on this domain. Note the "
                "underlying certificate template still carries "
                "CT_FLAG_NO_SECURITY_EXTENSION, so the escalation would become "
                "exploitable again if strong certificate binding is lowered — keep "
                "StrongCertificateBindingEnforcement at Full and remove the flag "
                "from the template for defence in depth."
            ),
        }
        if isinstance(scbe, int):
            details["strong_certificate_binding_enforcement"] = scbe
        if reason:
            details["observation"] = str(reason)
        recorder(
            shell,
            domain_name,
            key="esc9_implicit_mapping_mitigated",
            title="Strong Certificate Binding Enforced (ESC9 / ESC10 Implicit-Mapping Abuse Mitigated)",
            category="Certificate Services",
            status="observed",
            details=details,
        )
    except Exception as exc:  # pragma: no cover - best effort sync
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"[positive-control] ESC9 hardened positive emit failed: {exc}")


__all__ = [
    "emit_posture_positives",
    "emit_password_policy_positive",
    "emit_cve_not_vulnerable_positives",
    "emit_registry_positives",
    "emit_endpoint_protection_positive",
    "emit_control_plane_sync_account_items",
    "emit_esc15_hardened_positive",
    "emit_esc14_hardened_positive",
    "emit_esc9_hardened_positive",
    "reconcile_external_tenant_replication",
    "reconcile_shadow_credential_segmentation",
]
