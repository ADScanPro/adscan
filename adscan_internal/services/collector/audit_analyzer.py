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
    # observed-vs-recommended per knob. ``reversible_encryption_enabled`` is
    # intentionally NOT captured here — it requires an additional LDAP probe
    # (pwdProperties bit 0x10 / per-PSO attribute) the domain-root collection
    # does not currently read; deferred as a follow-up.
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


def analyze_host_audit_findings(result: CollectionResult) -> list[AuditFinding]:
    """Hygiene findings that require SMB host-collection data.

    Called by the orchestrator AFTER collect_domain_hosts() so that Computer
    nodes already carry smb_signing_required / smb_dialect from the SMB
    negotiate phase. Safe to call even if host collection was skipped — nodes
    will simply lack the relevant properties and no findings are emitted.

    Note on SMBv1: the current smb_collector.py negotiate only offers SMB2+
    dialects (SMB202…SMB311). SMBv1 detection would require adding the legacy
    NT LM 0.12 dialect code to the offered list — tracked as a future change.
    """
    if result.collection_scope != "audit":
        return []

    findings: list[AuditFinding] = []

    for node in result.nodes.values():
        if node.kind != "Computer":
            continue

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
