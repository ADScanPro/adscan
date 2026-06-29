"""Single source of truth for cleanup/rollback reporting vocabulary.

Both surfaces that report environment changes — the WeasyPrint PDF section and
the web platform — read their bucket labels, kind display strings, status icons,
and client-safe native remediation templates from THIS module. Neither surface
re-derives buckets, labels, or instructions. ``cleanup_ux.py`` (terminal),
``html_pdf_generator.py`` (PDF), ``appendices_render.py`` (legacy docx), and the
web ingestion service all import from here.

The remediation templates are CLIENT-FACING PDF/web prose (subject to the
"baked technique narratives are client-facing" CLAUDE.md rule): they contain
ONLY native Microsoft/PowerShell commands the client runs, never offensive-tool
or vendor names. A structural test greps these strings against the offensive-tool
blocklist.
"""

from __future__ import annotations

# ── Cleanup status taxonomy (the persisted ``revert_status`` vocabulary) ──────
# Transient (non-terminal) states.
STATUS_PENDING = "pending"
STATUS_REVERT_IN_PROGRESS = "revert_in_progress"
STATUS_REVERT_FAILED_RETRYING = "revert_failed_retrying"
# Terminal states.
STATUS_REVERTED_CONFIRMED = "reverted_confirmed"
STATUS_KEPT = "kept"
STATUS_MANUAL_REQUIRED = "manual_required"

# Legacy statuses kept only for back-compat reads of old (1.0) workspaces.
STATUS_LEGACY_REVERTED = "reverted"
STATUS_LEGACY_FAILED = "failed"
STATUS_LEGACY_OPERATOR_REQUIRED = "operator_required"

TERMINAL_STATUSES = frozenset(
    {STATUS_REVERTED_CONFIRMED, STATUS_KEPT, STATUS_MANUAL_REQUIRED}
)

# ── Surface buckets — the THREE+1 report categories both surfaces render ──────
CLEANUP_BUCKET_REVERTED = "reverted"  # the good side (undone AND re-verified)
CLEANUP_BUCKET_MANUAL = "manual"  # the legal-critical side
CLEANUP_BUCKET_KEPT = "kept"  # durable operator_confirmed, intentionally retained
CLEANUP_BUCKET_IN_PROGRESS = "in_progress"  # not yet terminal

CLEANUP_BUCKETS = (
    CLEANUP_BUCKET_REVERTED,
    CLEANUP_BUCKET_MANUAL,
    CLEANUP_BUCKET_KEPT,
    CLEANUP_BUCKET_IN_PROGRESS,
)

# ── manual_reason discriminator (why a change landed in the MANUAL bucket) ────
MANUAL_REASON_REVERT_FAILED = "revert_failed"
MANUAL_REASON_NOT_ATTEMPTED = "not_attempted"
MANUAL_REASON_SESSION_DIED = "session_died"
MANUAL_REASON_MISSING_CREDENTIAL = "missing_credential"
MANUAL_REASON_MISSING_METADATA = "missing_metadata"
MANUAL_REASON_ACCESS_DENIED = "access_denied"

_MANUAL_REASON_LABELS: dict[str, str] = {
    MANUAL_REASON_REVERT_FAILED: "Automatic rollback failed after retries",
    MANUAL_REASON_NOT_ATTEMPTED: "No automatic rollback is possible",
    MANUAL_REASON_SESSION_DIED: "Session ended before rollback completed",
    MANUAL_REASON_MISSING_CREDENTIAL: "No usable rollback credential was available",
    MANUAL_REASON_MISSING_METADATA: "Original-state metadata was unavailable",
    MANUAL_REASON_ACCESS_DENIED: "Rollback was denied by the directory",
}


def manual_reason_label(reason: str | None) -> str:
    """Return a humanized, client-safe label for a manual_reason discriminator."""
    return _MANUAL_REASON_LABELS.get(
        str(reason or "").strip().lower(),
        "Manual cleanup required",
    )


def cleanup_bucket(revert_status: str | None) -> str:
    """Map any (current or legacy) ``revert_status`` to a surface bucket.

    Args:
        revert_status: The persisted status string from a ledger record.

    Returns:
        One of ``CLEANUP_BUCKET_*``. Unknown / transient values fall back to
        ``CLEANUP_BUCKET_IN_PROGRESS`` so a half-state is never silently shown
        as done.
    """
    s = (revert_status or "").strip().lower()
    if s in (STATUS_REVERTED_CONFIRMED, STATUS_LEGACY_REVERTED):
        return CLEANUP_BUCKET_REVERTED
    if s in (
        STATUS_MANUAL_REQUIRED,
        STATUS_LEGACY_FAILED,
        STATUS_LEGACY_OPERATOR_REQUIRED,
    ):
        return CLEANUP_BUCKET_MANUAL
    if s == STATUS_KEPT:
        return CLEANUP_BUCKET_KEPT
    return CLEANUP_BUCKET_IN_PROGRESS


# ── Status icon / label / style maps (terminal UX + report) ───────────────────
STATUS_ICON: dict[str, str] = {
    STATUS_REVERTED_CONFIRMED: "✓",
    STATUS_LEGACY_REVERTED: "✓",
    STATUS_KEPT: "★",
    STATUS_PENDING: "●",
    STATUS_REVERT_IN_PROGRESS: "◐",
    STATUS_REVERT_FAILED_RETRYING: "↻",
    STATUS_MANUAL_REQUIRED: "⚠",
    STATUS_LEGACY_FAILED: "✗",
    STATUS_LEGACY_OPERATOR_REQUIRED: "⚠",
    "not_applicable": "–",
}

STATUS_STYLE: dict[str, str] = {
    STATUS_REVERTED_CONFIRMED: "green",
    STATUS_LEGACY_REVERTED: "green",
    STATUS_KEPT: "cyan",
    STATUS_PENDING: "dim",
    STATUS_REVERT_IN_PROGRESS: "blue",
    STATUS_REVERT_FAILED_RETRYING: "yellow",
    STATUS_MANUAL_REQUIRED: "bold red",
    STATUS_LEGACY_FAILED: "bold red",
    STATUS_LEGACY_OPERATOR_REQUIRED: "yellow",
    "not_applicable": "dim",
}

STATUS_LABEL: dict[str, str] = {
    STATUS_REVERTED_CONFIRMED: "Reverted (confirmed)",
    STATUS_LEGACY_REVERTED: "Reverted",
    STATUS_KEPT: "Kept by operator",
    STATUS_PENDING: "Pending",
    STATUS_REVERT_IN_PROGRESS: "Revert in progress",
    STATUS_REVERT_FAILED_RETRYING: "Retrying revert",
    STATUS_MANUAL_REQUIRED: "Requires manual cleanup",
    STATUS_LEGACY_FAILED: "Requires manual cleanup",
    STATUS_LEGACY_OPERATOR_REQUIRED: "Requires manual cleanup",
}


def status_label(revert_status: str | None) -> str:
    """Return a humanized label for a (current or legacy) status string."""
    s = (revert_status or "").strip().lower()
    return STATUS_LABEL.get(s, s.replace("_", " ").title() or "Pending")


# ── Change-kind display strings (SSOT) ────────────────────────────────────────
KIND_DISPLAY: dict[str, str] = {
    "group_membership_added": "Group membership",
    "group_membership_changed": "Group membership",
    "file_uploaded": "File upload",
    "user_created": "User created",
    "password_changed": "Password reset",
    "template_modified": "Template modified",
    "acl_modified": "ACL modified",
    "shadow_credentials_added": "Shadow credentials",
    "dacl_ace_added": "DACL ACE (GenericAll)",
    "owner_changed": "Object owner",
    "spn_added": "SPN (Kerberoast)",
    "machine_account_created": "Machine account",
    "rbcd_delegation_added": "RBCD delegation",
    "keycredentiallink_added": "KeyCredentialLink",
}


def kind_display(kind: str | None) -> str:
    """Return the display string for a change kind (falls back to the raw kind)."""
    raw = str(kind or "").strip()
    return KIND_DISPLAY.get(raw, raw)


# ── Client-safe native remediation templates (SSOT) ───────────────────────────
# Native Microsoft/PowerShell only — NEVER offensive-tool or vendor names.
MANUAL_SHADOW_CREDS = (
    "Review msDS-KeyCredentialLink on the target and remove only the value that was "
    "added during the engagement. Do not clear the whole attribute unless the client "
    "has confirmed there are no legitimate Windows Hello for Business or other PKINIT "
    "credentials on the object."
)

MANUAL_DACL_ACE = (
    "Remove the access control entry added during the engagement:\n"
    "  $acl = Get-Acl 'AD:TARGET'\n"
    "  # remove the ACE granting rights to TRUSTEE, then:\n"
    "  Set-Acl -Path 'AD:TARGET' -AclObject $acl"
)

MANUAL_OWNER = (
    "Restore the original owner of the object manually:\n"
    "  $sd = Get-ADObject TARGET -Properties ntSecurityDescriptor\n"
    "  $sd.ntSecurityDescriptor.SetOwner([System.Security.Principal.NTAccount]'ORIGINAL_OWNER')\n"
    "  Set-ADObject TARGET -Replace @{ntSecurityDescriptor=$sd.ntSecurityDescriptor}"
)

MANUAL_SPN = (
    "Remove the injected service principal name manually:\n"
    "  Set-ADUser -Identity TARGET -ServicePrincipalNames @{Remove='SPN'}\n"
    "  or: Set-ADComputer -Identity TARGET -ServicePrincipalNames @{Remove='SPN'}"
)

MANUAL_PASSWORD = (
    "Coordinate with the client to reset the target account password to a known value:\n"
    "  Set-ADAccountPassword -Identity TARGET -NewPassword"
    " (ConvertTo-SecureString 'NewPass' -AsPlainText -Force)\n"
    "  This account's previous credential has been permanently replaced."
)

MANUAL_GROUP_MEMBERSHIP = (
    "Remove the group member added during the engagement manually:\n"
    "  Remove-ADGroupMember -Identity 'GROUP' -Members 'MEMBER' -Confirm:$false"
)

MANUAL_RBCD = (
    "Clear or restore msDS-AllowedToActOnBehalfOfOtherIdentity on the target:\n"
    "  Set-ADComputer -Identity TARGET -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'"
)

MANUAL_KEYCREDENTIALLINK = (
    "Restore msDS-KeyCredentialLink on the target to its prior value list, removing "
    "the value added during the engagement:\n"
    "  Get-ADObject TARGET -Properties msDS-KeyCredentialLink\n"
    "  Set-ADObject TARGET -Clear 'msDS-KeyCredentialLink'  # only if originally empty"
)

MANUAL_MACHINE_ACCOUNT = (
    "Remove the machine account created during the engagement with a privileged account:\n"
    "  Remove-ADComputer -Identity 'TARGET' -Confirm:$false"
)

# Per-kind remediation template (raw, with TARGET/SPN/GROUP/MEMBER placeholders).
KIND_REMEDIATION_TEMPLATE: dict[str, str] = {
    "shadow_credentials_added": MANUAL_SHADOW_CREDS,
    "dacl_ace_added": MANUAL_DACL_ACE,
    "owner_changed": MANUAL_OWNER,
    "spn_added": MANUAL_SPN,
    "password_changed": MANUAL_PASSWORD,
    "group_membership_changed": MANUAL_GROUP_MEMBERSHIP,
    "group_membership_added": MANUAL_GROUP_MEMBERSHIP,
    "rbcd_delegation_added": MANUAL_RBCD,
    "keycredentiallink_added": MANUAL_KEYCREDENTIALLINK,
    "machine_account_created": MANUAL_MACHINE_ACCOUNT,
}


def remediation_template_for_kind(kind: str | None) -> str:
    """Return the raw (placeholder-bearing) remediation template for a kind."""
    raw = str(kind or "").strip()
    return KIND_REMEDIATION_TEMPLATE.get(
        raw, "Manually revert the 'KIND' change on 'TARGET'.".replace("KIND", raw)
    )


__all__ = [
    "STATUS_PENDING",
    "STATUS_REVERT_IN_PROGRESS",
    "STATUS_REVERT_FAILED_RETRYING",
    "STATUS_REVERTED_CONFIRMED",
    "STATUS_KEPT",
    "STATUS_MANUAL_REQUIRED",
    "STATUS_LEGACY_REVERTED",
    "STATUS_LEGACY_FAILED",
    "STATUS_LEGACY_OPERATOR_REQUIRED",
    "TERMINAL_STATUSES",
    "CLEANUP_BUCKET_REVERTED",
    "CLEANUP_BUCKET_MANUAL",
    "CLEANUP_BUCKET_KEPT",
    "CLEANUP_BUCKET_IN_PROGRESS",
    "CLEANUP_BUCKETS",
    "MANUAL_REASON_REVERT_FAILED",
    "MANUAL_REASON_NOT_ATTEMPTED",
    "MANUAL_REASON_SESSION_DIED",
    "MANUAL_REASON_MISSING_CREDENTIAL",
    "MANUAL_REASON_MISSING_METADATA",
    "MANUAL_REASON_ACCESS_DENIED",
    "manual_reason_label",
    "cleanup_bucket",
    "status_label",
    "kind_display",
    "STATUS_ICON",
    "STATUS_STYLE",
    "STATUS_LABEL",
    "KIND_DISPLAY",
    "MANUAL_SHADOW_CREDS",
    "MANUAL_DACL_ACE",
    "MANUAL_OWNER",
    "MANUAL_SPN",
    "MANUAL_PASSWORD",
    "MANUAL_GROUP_MEMBERSHIP",
    "MANUAL_RBCD",
    "MANUAL_KEYCREDENTIALLINK",
    "MANUAL_MACHINE_ACCOUNT",
    "KIND_REMEDIATION_TEMPLATE",
    "remediation_template_for_kind",
]
