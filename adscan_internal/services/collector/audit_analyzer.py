"""Hygiene and misconfiguration audit findings for audit-mode workspaces.

Only called when collection_scope == "audit". All analysis runs on already-
collected CollectionResult data — no additional LDAP queries.
"""

from __future__ import annotations

import time
from typing import Any

from adscan_internal.services.collector.models import (
    AuditFinding,
    CollectionResult,
    CollectorNode,
    DomainPolicy,
)

_FILETIME_EPOCH_OFFSET = 116_444_736_000_000_000
_100NS_PER_SECOND = 10_000_000

_OBSOLETE_OS_SUBSTRINGS = (
    "Windows XP",
    "Windows 7",
    "Windows Server 2003",
    "Windows Server 2008",
    "Windows Server 2012",
)


def _filetime_to_unix(filetime: int) -> float:
    return (filetime - _FILETIME_EPOCH_OFFSET) / _100NS_PER_SECOND


def _days_since_filetime(filetime: int | None) -> float | None:
    if not filetime:
        return None
    unix = _filetime_to_unix(filetime)
    return (time.time() - unix) / 86400


def _is_obsolete_os(os_string: str) -> bool:
    os_lower = os_string.lower()
    return any(obs.lower() in os_lower for obs in _OBSOLETE_OS_SUBSTRINGS)


def _password_compliance_findings(
    result: CollectionResult,
) -> list[AuditFinding]:
    """Build AuditFinding rows from the password compliance snapshot.

    The full per-user table lives on ``result.password_compliance`` and is
    persisted as ``password_compliance.json`` for downstream consumers
    (report, web, spraying). The hygiene panel only needs aggregate
    findings — one per affected user plus, optionally, a single
    domain-level note when the policy has never been modified.
    """
    from adscan_internal.services.password_policy_compliance import (
        analyze_password_compliance,
    )

    report = analyze_password_compliance(result)
    if report is None:
        return []
    result.password_compliance = report

    findings: list[AuditFinding] = []

    if report.policy_never_modified:
        findings.append(
            AuditFinding(
                category="pwd_policy_never_modified",
                samaccountname="(domain)",
                object_id="",
                detail=(
                    "Default Domain Policy has not been modified since the "
                    "domain was created — running the original provisioning "
                    "template, typically with weaker defaults."
                ),
                severity="medium",
            )
        )

    for entry in report.entries:
        if not entry.pwd_predates_policy:
            continue
        findings.append(
            AuditFinding(
                category="pwd_predates_policy",
                samaccountname=entry.samaccountname,
                object_id=entry.object_id,
                detail=(
                    f"pwdLastSet predates last modification of "
                    f"{entry.applied_policy_name}"
                    + (
                        f" ({entry.pwd_age_days}d ago)"
                        if entry.pwd_age_days is not None
                        else ""
                    )
                ),
                severity=entry.risk_level,
                highvalue=entry.is_admin_like,
            )
        )

    return findings


def analyze_audit_findings(
    result: CollectionResult,
    domain_policy: DomainPolicy | None,
    *,
    stale_days: int = 90,
    krbtgt_age_days: int = 180,
) -> list[AuditFinding]:
    """Compute hygiene findings from CollectionResult. Returns [] for ctf scope."""
    if result.collection_scope != "audit":
        return []

    findings: list[AuditFinding] = []

    def _is_human_user(node: Any) -> bool:
        """True for enabled, NON-``$`` User nodes — the hygiene audit's human scope.

        Intentionally NARROWER than the inventory predicate
        ``get_enabled_users`` (graph_queries/inventories.py): that predicate now
        keeps gMSAs in the Users inventory, but stale-logon / password-not-required
        hygiene findings target HUMAN accounts.  A gMSA has a machine-managed
        password (no ``passwordnotreqd``) and a service-account logon cadence, so
        ``$``-suffixed managed service accounts are deliberately excluded here.
        """
        return (
            node.kind == "User"
            and bool(node.enabled)
            and not str(node.samaccountname).endswith("$")
        )

    for node in result.nodes.values():
        if _is_human_user(node):
            lastlogon = node.properties.get("lastlogon")
            days_ago = _days_since_filetime(lastlogon)
            if days_ago is not None and days_ago > stale_days:
                is_hv = bool(node.highvalue or node.properties.get("admincount"))
                findings.append(
                    AuditFinding(
                        category="stale_user",
                        samaccountname=node.samaccountname,
                        object_id=node.object_id,
                        detail=f"Last logon {int(days_ago)} days ago",
                        # Catalog baseline: LOW (3.5); Tier-0 elevation: MEDIUM (6.0)
                        severity="medium" if is_hv else "low",
                        highvalue=is_hv,
                    )
                )

            if node.properties.get("passwordnotreqd"):
                is_hv = bool(node.highvalue or node.properties.get("admincount"))
                findings.append(
                    AuditFinding(
                        category="passwd_notreqd",
                        samaccountname=node.samaccountname,
                        object_id=node.object_id,
                        detail="PASSWD_NOTREQD UAC flag set — account may have blank password",
                        # Catalog baseline: LOW (3.5); Tier-0 elevation: MEDIUM (6.0).
                        # Escalates to HIGH via blank-password spray confirmation
                        # (CONDITION_EXPLOITATION in contextual_rules.py).
                        severity="medium" if is_hv else "low",
                        highvalue=is_hv,
                    )
                )

            # Exclude krbtgt (RID -502) — has its own dedicated krbtgt_age category.
            if node.properties.get("pwdneverexpires") and not node.object_id.endswith("-502"):
                is_hv = bool(node.highvalue or node.properties.get("admincount"))
                findings.append(
                    AuditFinding(
                        category="pwd_never_expires",
                        samaccountname=node.samaccountname,
                        object_id=node.object_id,
                        detail="DONT_EXPIRE_PASSWORD UAC flag set",
                        # Catalog baseline: LOW (3.7); Tier-0 elevation: MEDIUM (6.5)
                        severity="medium" if is_hv else "low",
                        highvalue=is_hv,
                    )
                )

            if node.properties.get("rc4_only"):
                findings.append(
                    AuditFinding(
                        category="rc4_only",
                        samaccountname=node.samaccountname,
                        object_id=node.object_id,
                        detail="Only RC4 (no AES) in msDS-SupportedEncryptionTypes",
                        severity="medium",
                        highvalue=bool(node.highvalue or node.properties.get("admincount")),
                    )
                )

        if node.kind == "User" and node.object_id.endswith("-502"):
            pwdlastset = node.properties.get("pwdlastset")
            days_ago = _days_since_filetime(pwdlastset)
            if days_ago is not None and days_ago > krbtgt_age_days:
                findings.append(
                    AuditFinding(
                        category="krbtgt_age",
                        samaccountname=node.samaccountname,
                        object_id=node.object_id,
                        detail=f"krbtgt password last changed {int(days_ago)} days ago",
                        # MEDIUM baseline — hygiene/rotation issue. Golden Ticket
                        # forgery requires the krbtgt hash, which already implies
                        # Domain Admin (DCSync). Promotes to CRITICAL via the
                        # separate krbtgt_pass finding when secret recovery or
                        # Golden Ticket usage is confirmed.
                        severity="medium",
                    )
                )

        if node.kind == "Computer":
            # Stale enabled computer — the machine analogue of stale_user. An
            # enabled computer account with no recent logon is typically a
            # decommissioned/renamed host that was never disabled. Beyond the
            # account-hygiene risk, its leftover DNS A-record can still resolve
            # to a now-reused IP and misdirect Kerberos SPN resolution (observed
            # on Cyberzaintza: stale CZN007$ shared an IP with the live CZN012$).
            # Staleness MUST key off lastLogonTimestamp (real authentication
            # activity), NOT pwdLastSet. pwdLastSet is a false proxy: legacy /
            # pre-Win2000-compat / manually-set machine passwords (the Timeroast
            # targets) keep an old pwdLastSet for years while the host is still
            # actively logging on. lastLogonTimestamp reflects activity regardless
            # of password rotation. When it is unavailable (0/None — e.g. a domain
            # that disabled lastLogonTimestamp updates) we DO NOT flag, to avoid
            # false positives; better to miss than to mislabel a live legacy host.
            if bool(node.enabled):
                days_ago = _days_since_filetime(node.properties.get("lastlogon"))
                if days_ago is not None and days_ago > stale_days:
                    findings.append(
                        AuditFinding(
                            category="stale_computer",
                            samaccountname=node.samaccountname,
                            object_id=node.object_id,
                            detail=(
                                f"Enabled computer, last logon {int(days_ago)} days "
                                "ago — host inactive but the account was never "
                                "disabled (stale account; a leftover DNS record can "
                                "misdirect Kerberos SPNs to a now-reused IP)"
                            ),
                            severity="medium" if bool(node.highvalue) else "low",
                            highvalue=bool(node.highvalue),
                        )
                    )

            os_str = str(node.properties.get("os") or "")
            if os_str and _is_obsolete_os(os_str):
                findings.append(
                    AuditFinding(
                        category="obsolete_os",
                        samaccountname=node.samaccountname,
                        object_id=node.object_id,
                        detail=f"Obsolete OS: {os_str}",
                        # LOW baseline — MAQ > 0 is the AD default, an enabler not confirmed exploitation.
                    severity="low",
                        highvalue=bool(node.highvalue),
                    )
                )

            if node.properties.get("rc4_only"):
                findings.append(
                    AuditFinding(
                        category="rc4_only",
                        samaccountname=node.samaccountname,
                        object_id=node.object_id,
                        detail="Only RC4 (no AES) in msDS-SupportedEncryptionTypes",
                        severity="medium",
                        highvalue=bool(node.highvalue or node.properties.get("admincount")),
                    )
            )

    if domain_policy is not None:
        maq = domain_policy.machine_account_quota
        if maq is not None and maq > 0:
            findings.append(
                AuditFinding(
                    category="machine_quota_risk",
                    samaccountname="(domain)",
                    object_id="",
                    detail=(
                        f"ms-DS-MachineAccountQuota = {maq} — "
                        "any domain user can add computers"
                    ),
                    # LOW baseline — MAQ > 0 is the AD default, an enabler not confirmed exploitation.
                    severity="low",
                )
            )

        wpp = _analyze_weak_password_policy(domain_policy)
        if wpp is not None:
            findings.append(wpp)

    rev = _analyze_reversible_encryption(result, domain_policy)
    if rev is not None:
        findings.append(rev)

    findings.extend(_password_compliance_findings(result))

    return findings


# CIS Microsoft Windows Server benchmark threshold for the
# Default Domain Password Policy minimum length. Below this we
# call the policy "weak" (NIST 800-63B Memorized Secrets §5.1.1
# recommends ≥8 for users, but in an enterprise DDPP context
# CIS / DISA STIG / Microsoft Baseline align on 14 as
# the bar for enterprise environments).
_WEAK_PWD_POLICY_MIN_LENGTH = 14
# Hard-failure threshold — below this, a single 8-char password
# is crackable in hours with a consumer GPU and a wordlist+rules
# pass. Treated as a high-severity sub-issue on its own.
_CRACKABLE_PWD_POLICY_MIN_LENGTH = 8


def _analyze_weak_password_policy(
    domain_policy: DomainPolicy,
) -> AuditFinding | None:
    """Consolidate weak Default Domain Password Policy sub-issues.

    Three independent CIS-aligned checks against the Default Domain
    Password Policy:

    * **Account lockout disabled** (lockoutThreshold == 0) — password
      spraying carries no lockout risk. CIS calls for ≥5 attempts
      threshold; Microsoft Baseline asks for 10.
    * **Min password length below threshold** (<14 chars) — falls
      below CIS / DISA STIG / Microsoft Baseline for enterprise. A
      sub-issue at <8 is "crackable in hours" territory and elevates
      severity on its own.
    * **Complexity disabled** (DOMAIN_PASSWORD_COMPLEX bit unset) —
      passwords need not include character-class diversity, dropping
      effective entropy.

    All three sub-issues collapse into ONE consolidated finding with
    dynamic severity so the report renders a single, accurate
    "Weak Domain Password Policy" entry instead of three near-duplicate
    rows. The composite ``detail`` string enumerates the active
    sub-issues so the auditor sees exactly which knobs are loose.

    Returns ``None`` when the policy meets every threshold — no
    finding emitted.
    """
    sub_issues: list[str] = []
    has_no_lockout = False
    has_short_pwd = False
    has_crackable_pwd = False
    has_no_complexity = False

    if domain_policy.lockout_threshold == 0:
        sub_issues.append("account lockout disabled (spray-safe)")
        has_no_lockout = True

    min_len = domain_policy.min_pwd_length
    if isinstance(min_len, int) and 0 < min_len < _WEAK_PWD_POLICY_MIN_LENGTH:
        sub_issues.append(
            f"min length {min_len} chars (CIS recommends ≥{_WEAK_PWD_POLICY_MIN_LENGTH})"
        )
        has_short_pwd = True
        if min_len < _CRACKABLE_PWD_POLICY_MIN_LENGTH:
            has_crackable_pwd = True

    # ``complexity_enabled is None`` means the attribute was unreadable
    # (insufficient permissions, very old DC). Skip the sub-issue rather
    # than reporting a false positive — we cannot prove it is disabled.
    if domain_policy.complexity_enabled is False:
        sub_issues.append("complexity requirement disabled")
        has_no_complexity = True

    if not sub_issues:
        return None

    # Dynamic severity matrix:
    #   - 3 sub-issues all active                            → HIGH
    #     (full spraying + crack + weak passwords = trivial credential access)
    #   - Crackable length (<8) + any other sub-issue        → HIGH
    #     (sub-8 alone is already at hashcat reach in minutes)
    #   - 2 sub-issues active                                → MEDIUM
    #   - 1 sub-issue active                                 → LOW
    #     unless it is the crackable-length case             → MEDIUM
    active_count = sum((has_no_lockout, has_short_pwd, has_no_complexity))
    if active_count >= 3:
        severity = "high"
    elif has_crackable_pwd and active_count >= 2:
        severity = "high"
    elif active_count == 2:
        severity = "medium"
    elif has_crackable_pwd:
        severity = "medium"
    else:
        severity = "low"

    detail = "Weak Default Domain Password Policy — " + " · ".join(sub_issues)

    # Capture the concrete observed knobs (structured) alongside the human
    # ``detail`` string. Keys mirror the ``recommended`` block in the
    # ``weak_password_policy`` catalog entry exactly so report/web can compare
    # observed-vs-recommended per knob. Reversible encryption
    # (pwdProperties bit 0x10 / the per-PSO attribute) is NOT a knob of this
    # consolidated finding — it is a hard cleartext-storage weakness with its
    # own dedicated finding (``reversible_encryption_enabled``, see
    # ``_analyze_reversible_encryption``).
    observed: dict[str, Any] = {
        "min_pwd_length": domain_policy.min_pwd_length,
        "complexity_enabled": domain_policy.complexity_enabled,
        "lockout_threshold": domain_policy.lockout_threshold,
        "lockout_window_minutes": domain_policy.lockout_window_minutes,
        "max_pwd_age_days": domain_policy.max_pwd_age_days,
        "pwd_history_length": domain_policy.pwd_history_length,
    }

    return AuditFinding(
        category="weak_password_policy",
        samaccountname="(domain)",
        object_id="",
        detail=detail,
        severity=severity,
        observed=observed,
    )


def _analyze_reversible_encryption(
    result: CollectionResult,
    domain_policy: DomainPolicy | None,
) -> AuditFinding | None:
    """Flag reversible-encryption password storage (CIS 1.1.7).

    Storing passwords with reversible encryption is equivalent to cleartext:
    any principal that can read the stored form recovers the plaintext. Two
    places can enable it, both read with zero extra I/O off data already
    collected:

    * The Default Domain Password Policy - the ``DOMAIN_PASSWORD_STORE_CLEARTEXT``
      (0x10) bit of ``pwdProperties`` on the domain root object
      (``domain_policy.reversible_encryption_enabled``).
    * Any Fine-Grained Password Policy (PSO) with
      ``msDS-PasswordReversibleEncryptionEnabled == True``
      (``result.psos[*].reversible_encryption_enabled``).

    Returns a single consolidated finding when EITHER source enables it. When
    ``pwdProperties`` was unreadable (``None``) the domain default is treated
    as "not observed" (we do not claim it is enabled) - a PSO can still trigger
    the finding on its own. Returns ``None`` when reversible encryption is not
    observed anywhere.
    """
    scopes: list[str] = []
    domain_default_on = (
        domain_policy is not None
        and domain_policy.reversible_encryption_enabled is True
    )
    if domain_default_on:
        scopes.append("the Default Domain Password Policy")

    enabling_psos = [
        pso.name or pso.distinguished_name
        for pso in result.psos
        if pso.reversible_encryption_enabled is True
    ]
    for pso_name in enabling_psos:
        scopes.append(f"PSO '{pso_name}'")

    if not scopes:
        return None

    detail = (
        "Reversible password encryption is enabled on "
        + " and ".join(scopes)
        + " - passwords are stored in a recoverable (cleartext-equivalent) form."
    )
    return AuditFinding(
        category="reversible_encryption_enabled",
        samaccountname="(domain)",
        object_id="",
        detail=detail,
        # HIGH: cleartext-equivalent storage of every affected principal's
        # password. Any read of the stored credential yields the plaintext
        # directly, removing the offline-cracking step entirely.
        severity="high",
        observed={
            "reversible_encryption_enabled": True,
            "default_domain_policy": domain_default_on,
            "psos_enabling": list(enabling_psos),
        },
    )


# ---------------------------------------------------------------------------
# Host-local registry credential-protection posture (admin-gated \winreg reads)
# ---------------------------------------------------------------------------
#
# The remote-registry collection stage (host_collector._do_registry) reads six
# HKLM values on every host where the scan principal is a local admin and stamps
# each onto the Computer node's properties as ``<prop_key>`` (the decoded int, when
# present) plus ``<prop_key>_state`` (``present`` / ``absent`` / ``error``). Below
# we turn those raw reads into config-posture findings, mirroring how
# ``smb_signing_disabled`` is emitted from ``smb_signing_required``.
#
# A finding is emitted ONLY when the value was actually observed with certainty to
# be insecure (present-and-bad, or — for RunAsPPL/NoLmHash — provably absent). An
# ``error`` state (denied / transport) is NOT_ASSESSED: never a finding, never a
# false positive. The observed-good value is noted per finding for a follow-up
# positive-evidence emit (a separate concern, not built here).
#
# NTLMMinClientSec / NTLMMinServerSec are bitmasks; the 128-bit-encryption bit is
# NTLM_128BIT_ENCRYPTION (0x20000000). "NTLMv2 session security + 128-bit" is the
# hardened bar; anything missing the 128-bit bit is weak.
_NTLM_128BIT_ENCRYPTION = 0x20000000


def _reg_state(node: Any, prop_key: str) -> str | None:
    """Return the persisted per-key read state (present/absent/error) or None."""
    val = node.properties.get(f"{prop_key}_state")
    return str(val) if val is not None else None


def _registry_hardening_findings(node: Any) -> list[AuditFinding]:
    """Six credential-protection config-posture findings from HKLM registry reads.

    Emits per-host findings only for a CERTAIN-observed insecure value. DC /
    high-value hosts elevate the medium NTLM-policy findings to high (a hardened
    baseline matters most on the identity control plane). Returns ``[]`` when the
    registry stage did not run on this host (no ``reg_admin_gate`` property).
    """
    # The stage only ran (as an admin) when it stamped the gate flag True. When it
    # was skipped, or the principal was not a local admin, nothing was assessed.
    if node.properties.get("reg_admin_gate") is not True:
        return []

    findings: list[AuditFinding] = []
    is_hv = bool(node.highvalue)

    def _elevate(base: str) -> str:
        return "high" if is_hv else base

    # 1) LSASS protection (RunAsPPL) — absent OR 0 is insecure. Observed-good = 1.
    ppl_state = _reg_state(node, "reg_lsa_runasppl")
    ppl_val = node.properties.get("reg_lsa_runasppl")
    if ppl_state == "present" and ppl_val in (0, None):
        _ppl_insecure = True
    elif ppl_state == "absent":
        _ppl_insecure = True
    else:
        _ppl_insecure = False
    if _ppl_insecure:
        findings.append(
            AuditFinding(
                category="lsa_protection_disabled",
                samaccountname=node.samaccountname,
                object_id=node.object_id,
                detail=(
                    "LSASS is not running as a protected process (RunAsPPL is "
                    + ("not set" if ppl_state == "absent" else "0")
                    + "). LSASS memory is readable by any local-admin process, so "
                    "credential material (hashes, tickets, cleartext) can be "
                    "harvested from it."
                ),
                # HIGH: LSASS PPL is a primary credential-theft mitigation. Its
                # absence directly enables offline credential dumping.
                severity="high",
                highvalue=is_hv,
            )
        )

    # 2) WDigest cleartext credentials — UseLogonCredential == 1 is insecure.
    #    Absent is SECURE (WDigest cleartext caching is off by default on modern
    #    Windows). Observed-good = 0 or absent.
    wdigest_state = _reg_state(node, "reg_wdigest_uselogoncredential")
    wdigest_val = node.properties.get("reg_wdigest_uselogoncredential")
    if wdigest_state == "present" and wdigest_val == 1:
        findings.append(
            AuditFinding(
                category="wdigest_enabled",
                samaccountname=node.samaccountname,
                object_id=node.object_id,
                detail=(
                    "WDigest credential caching is enabled (UseLogonCredential = "
                    "1). Windows stores the cleartext password of every "
                    "interactive logon in LSASS memory, so a local-admin memory "
                    "read recovers plaintext credentials directly."
                ),
                # HIGH: cleartext credentials in memory — removes the offline
                # cracking step entirely.
                severity="high",
                highvalue=is_hv,
            )
        )

    # 3) LM hash storage (NoLmHash) — absent OR 0 is insecure. Observed-good = 1.
    lm_state = _reg_state(node, "reg_lsa_nolmhash")
    lm_val = node.properties.get("reg_lsa_nolmhash")
    if lm_state == "present" and lm_val in (0, None):
        _lm_insecure = True
    elif lm_state == "absent":
        _lm_insecure = True
    else:
        _lm_insecure = False
    if _lm_insecure:
        findings.append(
            AuditFinding(
                category="lm_hash_storage_enabled",
                samaccountname=node.samaccountname,
                object_id=node.object_id,
                detail=(
                    "The host stores LM password hashes (NoLmHash is "
                    + ("not set" if lm_state == "absent" else "0")
                    + "). The LM hash is a weak, fast-to-crack representation of "
                    "the password; storing it undermines every account with a "
                    "password of 14 characters or fewer."
                ),
                # HIGH: LM hashes are trivially crackable and should never be
                # stored on a modern estate.
                severity="high",
                highvalue=is_hv,
            )
        )

    # 4) LAN Manager authentication level — < 5 permits LM/NTLMv1 on the wire.
    #    Observed-good = 5 (send NTLMv2 only, refuse LM & NTLM).
    lmcompat_state = _reg_state(node, "reg_lsa_lmcompatibilitylevel")
    lmcompat_val = node.properties.get("reg_lsa_lmcompatibilitylevel")
    if lmcompat_state == "present" and isinstance(lmcompat_val, int) and lmcompat_val < 5:
        findings.append(
            AuditFinding(
                category="weak_lm_compatibility_level",
                samaccountname=node.samaccountname,
                object_id=node.object_id,
                detail=(
                    f"NTLM/LM authentication level is {lmcompat_val} (below the "
                    "recommended baseline of 5) — a configuration read from the "
                    "host registry. At this level the host MAY send or accept "
                    "legacy LM / NTLMv1 responses, which are crackable offline and "
                    "relayable. This is the configuration root cause; NTLMv1 "
                    "acceptance was not empirically confirmed for this host in this "
                    "scan (that requires the coercion-based NTLM capture check)."
                ),
                # MEDIUM baseline; HIGH on a DC / Tier-0 host, where weak NTLM
                # levels widen the relay and offline-crack surface most.
                severity=_elevate("medium"),
                highvalue=is_hv,
            )
        )

    # 5) NTLM SSP minimum session security — the client/server minimums must both
    #    require NTLMv2 session security AND 128-bit encryption. The 128-bit bit
    #    (0x20000000) missing on EITHER side is weak. A value present-but-0, or a
    #    value missing the bit, is insecure. Observed-good = both include the bit.
    client_state = _reg_state(node, "reg_msv1_0_ntlmminclientsec")
    server_state = _reg_state(node, "reg_msv1_0_ntlmminserversec")
    client_val = node.properties.get("reg_msv1_0_ntlmminclientsec")
    server_val = node.properties.get("reg_msv1_0_ntlmminserversec")

    def _min_sec_weak(state: str | None, val: Any) -> bool:
        # Insecure when the value is absent (default does not require 128-bit) or
        # present without the 128-bit-encryption bit. An ``error`` read is not
        # assessed here (returns False so it never manufactures a finding).
        if state == "absent":
            return True
        if state == "present" and isinstance(val, int):
            return (val & _NTLM_128BIT_ENCRYPTION) == 0
        return False

    client_weak = _min_sec_weak(client_state, client_val)
    server_weak = _min_sec_weak(server_state, server_val)
    # Only assert weakness when at least one side was actually assessed (present or
    # absent) — a pair of pure ``error`` reads stays NOT_ASSESSED.
    _assessed = {client_state, server_state} & {"present", "absent"}
    if _assessed and (client_weak or server_weak):
        weak_sides = []
        if client_weak:
            weak_sides.append("client (NTLMMinClientSec)")
        if server_weak:
            weak_sides.append("server (NTLMMinServerSec)")
        findings.append(
            AuditFinding(
                category="ntlm_min_session_security_weak",
                samaccountname=node.samaccountname,
                object_id=node.object_id,
                detail=(
                    "Minimum NTLM SSP session security does not require NTLMv2 "
                    "session security with 128-bit encryption on the "
                    + " and ".join(weak_sides)
                    + " side. NTLM sessions may be negotiated without message "
                    "integrity / 128-bit encryption, weakening them against "
                    "downgrade and relay."
                ),
                # MEDIUM baseline; HIGH on a DC / Tier-0 host.
                severity=_elevate("medium"),
                highvalue=is_hv,
            )
        )

    # 6) Custom Security Support Providers allowed into LSASS — 1 is insecure.
    #    Observed-good = 0 or absent.
    ssp_state = _reg_state(node, "reg_lsa_allowcustomsspsaps")
    ssp_val = node.properties.get("reg_lsa_allowcustomsspsaps")
    if ssp_state == "present" and ssp_val == 1:
        findings.append(
            AuditFinding(
                category="lsass_custom_ssp_allowed",
                samaccountname=node.samaccountname,
                object_id=node.object_id,
                detail=(
                    "Custom Security Support Providers / Authentication Packages "
                    "are allowed to load into LSASS (AllowCustomSSPsAPs = 1). An "
                    "attacker with local admin can register a malicious SSP to "
                    "capture credentials as they authenticate."
                ),
                # MEDIUM baseline; HIGH on a DC / Tier-0 host.
                severity=_elevate("medium"),
                highvalue=is_hv,
            )
        )

    return findings


def analyze_host_audit_findings(result: CollectionResult) -> list[AuditFinding]:
    """Hygiene findings that require SMB host-collection data.

    Called by the orchestrator AFTER collect_domain_hosts() so that Computer
    nodes already carry smb_signing_required / smb_dialect from the SMB
    negotiate phase. Safe to call even if host collection was skipped — nodes
    will simply lack the relevant properties and no findings are emitted.

    Note on SMBv1: SMBv1 is actively probed by ``smb_collector.smb1_probe`` — a
    raw ``NT LM 0.12`` negotiate sent alongside the SMB2+ ``protocol_test`` (the
    same probe NXC uses). The node property ``smb_v1`` is a tri-state:
    ``True`` (host accepted the SMBv1 negotiate) fires this finding, ``False``
    (host answered but refused SMBv1) is an observed-good positive, and the
    property is ABSENT when the probe was inconclusive (error/timeout) — never
    assumed either way.
    """
    if result.collection_scope != "audit":
        return []

    findings: list[AuditFinding] = []

    for node in result.nodes.values():
        if node.kind != "Computer":
            continue

        # Registry credential-protection posture (admin-gated \winreg reads). Runs
        # per host regardless of the SMB-signing property below, since a host may
        # answer the registry stage without exposing a signing verdict.
        findings.extend(_registry_hardening_findings(node))

        # smb_signing_required is only present when host collection ran.
        signing_required = node.properties.get("smb_signing_required")
        if signing_required is None:
            continue

        if not signing_required:
            findings.append(
                AuditFinding(
                    category="smb_signing_disabled",
                    samaccountname=node.samaccountname,
                    object_id=node.object_id,
                    detail=(
                        f"SMB signing not required — "
                        f"dialect {node.properties.get('smb_dialect') or 'unknown'}"
                    ),
                    # HIGH if DC/high-value (ideal relay target), MEDIUM otherwise.
                    # Catalog baseline: MEDIUM (5.0); Tier-0 elevation: HIGH (8.0).
                    severity="high" if node.highvalue else "medium",
                    highvalue=node.highvalue,
                )
            )

        if node.properties.get("smb_v1"):
            findings.append(
                AuditFinding(
                    category="smb_v1_enabled",
                    samaccountname=node.samaccountname,
                    object_id=node.object_id,
                    detail="SMBv1 (NT LM 0.12) protocol accepted by host",
                    # HIGH — SMBv1 is deprecated, has known critical CVEs
                    # (EternalBlue/MS17-010), and should never be enabled.
                    severity="high" if node.highvalue else "medium",
                    highvalue=node.highvalue,
                )
            )

    return findings


def analyze_duplicate_dns_findings(result: CollectionResult) -> list[AuditFinding]:
    """Flag IPs that more than one ENABLED computer resolves to.

    A stale forward A-record left behind by a renamed/decommissioned machine
    (or genuine IP reuse) makes two enabled computer FQDNs point at one IP with
    no reverse PTR to disambiguate. This silently breaks Kerberos SPN targeting:
    the resolver may pick the stale name, the KDC mints a TGS for it, and the
    LIVE host at the IP rejects it (KRB_ERR_GENERIC). It also misleads any
    IP-based targeting. Requires ``resolve_computer_nodes`` to have populated
    ``node.properties['ip_address']`` (Phase 2 DNS), so it only fires when SMB/
    share collection ran. Best-effort: nodes without a resolved IP are skipped.
    """
    if getattr(result, "collection_scope", None) == "ctf":
        return []

    by_ip: dict[str, list[CollectorNode]] = {}
    for node in result.nodes.values():
        if node.kind != "Computer" or not bool(node.enabled):
            continue
        ip = str(node.properties.get("ip_address") or "").strip()
        if ip:
            by_ip.setdefault(ip, []).append(node)

    findings: list[AuditFinding] = []
    for ip, nodes in by_ip.items():
        if len(nodes) < 2:
            continue
        names = sorted(
            str(
                node.properties.get("dnshostname")
                or node.samaccountname
                or node.name
                or ""
            )
            .split("@")[0]
            .strip()
            for node in nodes
        )
        findings.append(
            AuditFinding(
                category="duplicate_dns_fqdn",
                samaccountname=ip,
                object_id="",
                detail=(
                    f"{len(nodes)} enabled computers resolve to {ip}: "
                    f"{', '.join(n for n in names if n)} — stale DNS A-record or "
                    "IP reuse. Kerberos SPN targeting may hit the wrong host "
                    "(KRB_ERR_GENERIC); remove the obsolete record / disable the "
                    "dead computer account."
                ),
                # MEDIUM: an operational + targeting hazard (and an audit-trail
                # red flag) rather than a direct privilege issue.
                severity="medium",
                highvalue=any(bool(node.highvalue) for node in nodes),
            )
        )
    return findings


def analyze_machine_rotation_finding(result: CollectionResult) -> list[AuditFinding]:
    """Flag disabled / relaxed machine-account password rotation from GPO policy.

    Consumes ``result.machine_password_policy`` (recovered from SYSVOL GptTmpl.inf
    by the orchestrator). When members do not rotate their computer passwords,
    every machine password is static → a durable, domain-wide Timeroast / cracking
    surface. Emitted once at domain level. No policy / default-and-enabled → no
    finding.
    """
    if getattr(result, "collection_scope", None) == "ctf":
        return []
    policy = getattr(result, "machine_password_policy", None)
    if policy is None:
        return []

    if getattr(policy, "disable_password_change", False):
        gpos = ", ".join(getattr(policy, "source_gpos", ()) or ()) or "a linked GPO"
        return [
            AuditFinding(
                category="machine_pwd_rotation_disabled",
                samaccountname="(domain)",
                object_id="",
                detail=(
                    f"Machine-account password rotation is DISABLED by GPO ({gpos}). "
                    "Domain members never change their computer passwords, so every "
                    "machine password is static and crackable (Timeroast / silver "
                    "ticket). Re-enable 'Domain member: Disable machine account "
                    "password changes' = Disabled."
                ),
                # HIGH: domain-wide enabler that makes every machine a durable target.
                severity="high",
            )
        ]

    max_age = getattr(policy, "max_age_days", None)
    if isinstance(max_age, int) and max_age > 60:
        return [
            AuditFinding(
                category="machine_pwd_rotation_relaxed",
                samaccountname="(domain)",
                object_id="",
                detail=(
                    f"Machine-account password max age is relaxed to {max_age} days "
                    "by GPO (default 30). Longer-lived machine passwords widen the "
                    "Timeroast / cracking window."
                ),
                severity="medium",
            )
        ]
    return []


__all__ = [
    "analyze_audit_findings",
    "analyze_host_audit_findings",
    "analyze_duplicate_dns_findings",
    "analyze_machine_rotation_finding",
]
