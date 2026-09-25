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
from typing import Any, Callable, Optional

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
        "The domain controller completed an LDAPS (TCP 636) TLS handshake — encrypted "
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


def emit_domain_policy_positives(shell: Any, domain: str, domain_policy: Any) -> None:
    """Emit standalone domain-policy positives when read with certainty.

    Two controls whose observed-good state is a definitive directory read on the
    default domain policy (``result.domain_policy``), independent of the composite
    ``strong_password_policy`` positive so a domain that fails one policy knob can
    still green the controls it passes:

    - ``reversible_encryption_disabled`` — the domain does NOT store passwords with
      reversible encryption (``reversible_encryption_enabled is False``). Reversible
      encryption is cleartext-equivalent; its absence is a real hardening fact.
    - ``machine_account_quota_zero`` — ``ms-DS-MachineAccountQuota == 0``, so no
      standard user can join a computer (closes the "add a machine account then
      RBCD/shadow-creds" avenue at the source).

    Third-state discipline: only a definitive read emits. ``None`` (attribute not
    read) or the insecure value (``True`` / ``> 0``) never greens — that would be
    the INFERRED_BY_ABSENCE falsehood the doctrine forbids.
    """
    domain_name = str(domain or "").strip()
    if not domain_name or domain_policy is None:
        return
    try:
        recorder = _resolve_recorder()
        if recorder is None:
            return

        reversible = getattr(domain_policy, "reversible_encryption_enabled", None)
        if reversible is False:  # definitive read; None (unread) must NOT green
            recorder(
                shell,
                domain_name,
                key="reversible_encryption_disabled",
                title="Reversible Password Encryption Disabled",
                category="Password Policy",
                status="observed",
                details={
                    "scope": "default_domain_policy",
                    "reversible_encryption_enabled": False,
                    "source": "directory",
                    "evidence": (
                        "Default domain policy read via directory: passwords are "
                        "NOT stored with reversible encryption (cleartext-equivalent "
                        "storage is disabled)."
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
# confirmed one (attack_graph_findings._is_breaker_held_legitimate_edge, keyed on
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


__all__ = [
    "emit_posture_positives",
    "emit_password_policy_positive",
    "emit_cve_not_vulnerable_positives",
    "emit_registry_positives",
    "emit_endpoint_protection_positive",
    "emit_control_plane_sync_account_items",
]
