"""Build shared widgets from the engine's already-structured source objects.

These builders are the *tap* the audit confirmed: the Posture and Hygiene
panels are built from structured objects (``AuditFinding`` /
``DomainPolicy`` / ``DomainPosture``) and then stringified for the Rich panel.
Here we tap the same structured data BEFORE stringification and reduce it to
the transport-neutral widget contract, so the one payload drives both the CLI
Rich renderer and the web premium component.

Client-safe by construction: these widgets name client-owned configuration
(password policy, SMB signing, LDAP signing, NTLM, Kerberos encryption) and
carry no offensive-tool names.
"""

from __future__ import annotations

from typing import Any, Iterable

from adscan_internal.cli.widgets.widget_contract import (
    FindingRow,
    FindingTableData,
    KpiItem,
    KpiStripData,
    MatrixPanelData,
    MatrixRow,
    MatrixSection,
    Widget,
    build_widget,
)

# Severity rank for "worst severity" reduction across a category's findings.
_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

# Human labels for hygiene finding categories. Mirrors the legacy
# ``category_labels`` map in ``cli/intelligence.py`` verbatim so the converted
# panel reads identically to the one it replaces.
_HYGIENE_CATEGORY_LABELS: dict[str, str] = {
    "stale_user": "Stale enabled users (>90d no logon)",
    "stale_computer": "Stale enabled computers (>90d no logon)",
    "pwd_never_expires": "Password never expires",
    "pwd_predates_policy": "Passwords older than current policy",
    "passwd_notreqd": "PASSWD_NOTREQD (no password required)",
    "krbtgt_age": "Krbtgt password age",
    "machine_quota_risk": "Machine Account Quota risk",
    "obsolete_os": "Obsolete operating systems",
    "smb_v1_enabled": "SMBv1 protocol enabled",
    "smb_signing_disabled": "SMB signing not required",
    "duplicate_dns_fqdn": "Duplicate computer DNS (multiple FQDNs to one IP)",
    "machine_pwd_rotation_disabled": "Machine password rotation disabled (GPO)",
    "machine_pwd_rotation_relaxed": "Machine password rotation relaxed (GPO)",
    "rc4_only": "RC4-only accounts",
    "weak_password_policy": "Weak password policy",
    "pwd_policy_never_modified": "Password policy never modified",
}

_USER_HYGIENE_CATS = frozenset(
    {"stale_user", "pwd_never_expires", "pwd_predates_policy", "passwd_notreqd"}
)
_COMPUTER_HYGIENE_CATS = frozenset(
    {"obsolete_os", "smb_signing_disabled", "smb_v1_enabled", "stale_computer"}
)

HYGIENE_WIDGET_KEY = "domain_hygiene"
POSTURE_WIDGET_KEY = "domain_posture"


def build_hygiene_widget(
    *,
    domain: str,
    audit_findings: Iterable[Any],
    total_enabled_users: int,
    total_computers: int,
    pwd_policy_last_changed: str | None = None,
) -> Widget:
    """Reduce hygiene ``AuditFinding`` rows to a ``finding-table`` widget.

    One row per finding category, carrying the worst severity in that category,
    a contextual count (``X/Y enabled users`` etc.) and the privileged subset.
    The ``footnote`` holds the contextual "policy last modified" date that the
    legacy panel rendered dim under the findings.

    Args:
        domain: Owning domain.
        audit_findings: ``AuditFinding`` objects (``category`` / ``severity`` /
            ``detail`` / ``highvalue``).
        total_enabled_users: Denominator for user-scoped categories.
        total_computers: Denominator for computer-scoped categories.
        pwd_policy_last_changed: ISO date string of the last policy change.

    Returns:
        A :class:`Widget` of type ``finding-table``.
    """
    by_category: dict[str, list[Any]] = {}
    for finding in audit_findings:
        by_category.setdefault(str(getattr(finding, "category", "")), []).append(finding)

    rows: list[FindingRow] = []
    for cat, items in by_category.items():
        if not cat:
            continue
        label = _HYGIENE_CATEGORY_LABELS.get(cat, cat)
        worst = min(
            (str(getattr(f, "severity", "info")) for f in items),
            key=lambda s: _SEVERITY_ORDER.get(s, 9),
        )
        count = len(items)
        value = _hygiene_value(cat, items, count, total_enabled_users, total_computers)
        privileged = sum(1 for f in items if getattr(f, "highvalue", False))
        rows.append(
            FindingRow(
                label=label,
                value=value,
                severity=_normalize_severity(worst),
                privileged_count=privileged,
            )
        )

    rows.sort(key=lambda r: _SEVERITY_ORDER.get(r.severity, 9))

    footnote = ""
    if pwd_policy_last_changed:
        footnote = (
            f"Password policy attributes last modified: {pwd_policy_last_changed[:10]}"
        )

    data = FindingTableData(rows=rows, footnote=footnote)
    return build_widget(
        "finding-table",
        key=HYGIENE_WIDGET_KEY,
        title=f"Domain Hygiene Audit — {domain}",
        data=data,
        domain=domain,
    )


def build_hygiene_kpi_widget(
    *,
    domain: str,
    audit_findings: Iterable[Any],
    total_enabled_users: int,
    total_computers: int,
) -> Widget:
    """Build the ``kpi-strip`` headline counts for the hygiene panel.

    Two HYGIENE-specific KPIs: total findings and privileged-targeting findings.
    The tone of the privileged-findings cell escalates with count so a non-zero
    privileged exposure reads as a warning.

    Enabled-user and computer counts are deliberately NOT emitted here: the live
    asset strip already owns those headline counts (HOSTS / USERS / COMPROMISED),
    and duplicating them across two panels showed the same number twice in two
    styles. ``total_enabled_users`` / ``total_computers`` remain parameters
    because the hygiene-audit categories below use them as their denominators.
    """
    findings = list(audit_findings)
    total_findings = len(findings)
    privileged = sum(1 for f in findings if getattr(f, "highvalue", False))

    items = [
        KpiItem(label="Hygiene findings", value=str(total_findings), tone="neutral"),
        KpiItem(
            label="Targeting privileged",
            value=str(privileged),
            tone="permissive" if privileged > 0 else "secure",
        ),
    ]
    return build_widget(
        "kpi-strip",
        key=f"{HYGIENE_WIDGET_KEY}_kpis",
        title=f"Domain Hygiene Overview — {domain}",
        data=KpiStripData(items=items),
        domain=domain,
    )


def _hygiene_value(
    cat: str,
    items: list[Any],
    count: int,
    total_enabled_users: int,
    total_computers: int,
) -> str:
    """Compute the human headline value for one hygiene category row.

    Mirrors the contextual X/total + special-case logic from the legacy panel.
    """
    if cat == "machine_quota_risk":
        detail = str(getattr(items[0], "detail", "") or "")
        import re

        match = re.search(r"=\s*(\d+)", detail)
        if match:
            return f"{match.group(1)} — any domain user can join computers"
        return "MAQ > 0 — any domain user can join computers"
    if cat == "weak_password_policy":
        detail = str(getattr(items[0], "detail", "") or "")
        sub_part = detail.split("— ", 1)[-1]
        if sub_part and sub_part != detail:
            return sub_part
        return f"{count} sub-issue(s)"
    if cat == "krbtgt_age":
        import re

        for item in items:
            match = re.search(r"(\d+)\s+days", str(getattr(item, "detail", "") or ""))
            if match:
                return f"{match.group(1)} days since last rotation (>180d recommended)"
        return f"{count} (rotation overdue)"
    if cat in _USER_HYGIENE_CATS and total_enabled_users > 0:
        return f"{count}/{total_enabled_users} enabled users"
    if cat in _COMPUTER_HYGIENE_CATS and total_computers > 0:
        return f"{count}/{total_computers} computers"
    return str(count)


def _normalize_severity(value: str) -> str:
    sev = str(value or "info").strip().lower()
    return sev if sev in _SEVERITY_ORDER else "info"


# --------------------------------------------------------------------------- #
# Posture — matrix-panel
# --------------------------------------------------------------------------- #


def build_posture_widget(
    *,
    domain: str,
    detected_hardening: Iterable[tuple[str, str, str]],
    permissive: Iterable[tuple[str, str]],
) -> Widget:
    """Build the domain-hardening ``matrix-panel`` widget.

    Two sections — "Detected hardening" (secure tone) and "Permissive"
    (permissive tone) — built from already-labelled posture rows. The caller
    (posture probe lifecycle) resolves the human labels and confidence from the
    posture-probe label maps, so this builder stays free of posture enums.

    Args:
        domain: Owning domain.
        detected_hardening: ``(label, confidence, detail)`` per detected control.
        permissive: ``(label, detail)`` per permissive/downgrade control.

    Returns:
        A :class:`Widget` of type ``matrix-panel``.
    """
    detected_rows = [
        MatrixRow(label=label, state="Enforced", state_tone="secure", confidence=conf, detail=detail)
        for (label, conf, detail) in detected_hardening
    ]
    permissive_rows = [
        MatrixRow(label=label, state="Permissive", state_tone="permissive", detail=detail)
        for (label, detail) in permissive
    ]

    sections: list[MatrixSection] = []
    if detected_rows:
        sections.append(MatrixSection(label="Detected hardening", rows=detected_rows))
    if permissive_rows:
        sections.append(
            MatrixSection(label="Permissive (no hardening detected)", rows=permissive_rows)
        )
    if not sections:
        sections.append(
            MatrixSection(
                label="Posture",
                rows=[
                    MatrixRow(
                        label="No defensive hardening detected",
                        state="Permissive across probed controls",
                        state_tone="permissive",
                    )
                ],
            )
        )

    return build_widget(
        "matrix-panel",
        key=POSTURE_WIDGET_KEY,
        title=f"Domain Hardening Posture — {domain}",
        data=MatrixPanelData(sections=sections),
        domain=domain,
    )


__all__ = [
    "HYGIENE_WIDGET_KEY",
    "POSTURE_WIDGET_KEY",
    "build_hygiene_widget",
    "build_hygiene_kpi_widget",
    "build_posture_widget",
]
