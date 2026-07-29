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


# ── Change kinds that need a named constant ───────────────────────────────────
# A certificate the CA issued during the assessment. It is an environment change
# like any other — the certificate lives in the CA database and stays usable for
# authentication until it expires or is revoked — and revocation needs CA rights
# the assessment does not hold, so it is always a MANUAL cleanup item.
KIND_ISSUED_CERTIFICATE = "issued_certificate"

# ── Change-kind display strings (SSOT) ────────────────────────────────────────
# Every kind any writer registers needs an entry here, or the client-facing
# disclosure prints the raw snake_case token. Keep this in step with the
# ``kind=`` arguments passed to ``EnvironmentChangeLedger.register``; a missing
# key is not a crash, it is a `template_mutated` in a customer's PDF.
KIND_DISPLAY: dict[str, str] = {
    "group_membership_added": "Group membership",
    "group_membership_changed": "Group membership",
    "file_uploaded": "File upload",
    "user_created": "User created",
    "password_changed": "Password reset",
    "template_modified": "Certificate template modified",
    "template_mutated": "Certificate template modified",
    "ca_template_enabled": "Certificate template published",
    KIND_ISSUED_CERTIFICATE: "Certificate issued by your CA",
    "acl_modified": "ACL modified",
    "shadow_credentials_added": "Shadow credentials",
    "dacl_ace_added": "DACL ACE (GenericAll)",
    "owner_changed": "Object owner",
    "spn_added": "SPN (Kerberoast)",
    "spn_relocated": "SPN moved between accounts",
    "machine_account_created": "Machine account",
    "computer_account_created": "Computer account",
    "rbcd_delegation_added": "RBCD delegation",
    "keycredentiallink_added": "KeyCredentialLink",
    "upn_changed": "User principal name",
    "altsecurityidentities_written": "Certificate mapping attribute",
    "gpo_ldap_attribute_modified": "Group Policy object attribute",
    "gpo_gpt_ini_modified": "Group Policy version file",
    "gpo_sysvol_dir_created": "Group Policy folder in SYSVOL",
    "gpo_sysvol_file_created": "Group Policy file in SYSVOL",
    "mssql_admin_account_created": "Database administrator account",
    "mssql_postex_account": "Database account",
    "mssql_clr_assembly_loaded": "Database CLR assembly",
    "mssql_clr_config_changed": "Database CLR configuration",
    "mssql_xp_cmdshell_enabled": "Database command execution setting",
}


def kind_display(kind: str | None) -> str:
    """Return the display string for a change kind.

    Falls back to a humanized form of the raw kind rather than the raw token
    itself: an unmapped kind then reads as "Template mutated" in a client
    document instead of ``template_mutated``.
    """
    raw = str(kind or "").strip()
    mapped = KIND_DISPLAY.get(raw)
    if mapped:
        return mapped
    if not raw:
        return ""
    humanized = raw.replace("_", " ").strip()
    return humanized[:1].upper() + humanized[1:]


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

# A certificate the CA issued during the assessment. Revoking it needs
# certificate-manager rights on the issuing CA, which the assessment does not
# hold — so this is always a manual item, and the client's administrator needs
# enough detail to find the record, revoke it, publish the result and check it.
# Placeholders (SERIAL_NUMBER / REQUEST_ID / CA_CONFIG) are filled in by
# :func:`issued_certificate_remediation`; the raw template is the fallback used
# when a record reaches the report without them.
MANUAL_ISSUED_CERTIFICATE = (
    "Your certification authority issued this certificate during the assessment. It stays "
    "valid for authentication until it expires or is revoked, and revoking it requires "
    "certificate-manager rights on the CA, so your team has to complete this step.\n"
    "Run the commands below on the CA server, or on any host with the Certification "
    "Authority tools installed, as a member of the CA's Certificate Managers group (or the "
    "CA host's local Administrators):\n"
    "  1. Locate the record and confirm it is still live\n"
    '     certutil -config "CA_CONFIG" -view -restrict "RequestId=REQUEST_ID" '
    '-out "RequestId,Request.RequesterName,Certificate.SerialNumber,'
    'Certificate.NotAfter,Request.Disposition"\n'
    "     A Disposition of 20 means the certificate is issued and usable.\n"
    "  2. Revoke it. Reason code 1 is key compromise, which is the accurate reason here: "
    "the private key was generated outside your control.\n"
    '     certutil -config "CA_CONFIG" -revoke SERIAL_NUMBER 1\n'
    "  3. Publish a fresh CRL so domain members learn of the revocation\n"
    '     certutil -config "CA_CONFIG" -CRL\n'
    "  4. Verify the change took effect\n"
    '     certutil -config "CA_CONFIG" -view -restrict "SerialNumber=SERIAL_NUMBER" '
    '-out "Request.Disposition,Request.RevokedReason"\n'
    "     Disposition must now read 21 (revoked).\n"
    "Two caveats worth planning for. The certificate keeps working until the new CRL has "
    "replicated to every CRL distribution point published in it, so confirm distribution "
    "with certutil -verify -urlfetch against a copy of the certificate. And revocation "
    "only stops future authentication: any Kerberos ticket already obtained with the "
    "certificate remains valid until it expires under Default Domain Policy > Computer "
    "Configuration > Policies > Windows Settings > Security Settings > Account Policies > "
    "Kerberos Policy. If the certificate carried the identity of a privileged or machine "
    "account, reset that account's password once the revocation is confirmed."
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
    KIND_ISSUED_CERTIFICATE: MANUAL_ISSUED_CERTIFICATE,
}


def issued_certificate_remediation(
    *,
    serial: str | None = None,
    request_id: int | str | None = None,
    ca_name: str | None = None,
    ca_host: str | None = None,
    template: str | None = None,
    principal: str | None = None,
    not_after: str | None = None,
) -> str:
    """Render the client-facing revocation instructions for one issued certificate.

    Prepends a one-line identification of the certificate (who it authenticates
    as, which template and CA produced it, how long it stays valid) to the
    native ``certutil`` revocation procedure, then substitutes the concrete
    serial / request id / CA configuration string into it.

    Args:
        serial: Hex serial number as recorded by the CA.
        request_id: Request ID assigned by the CA.
        ca_name: CA common name (e.g. ``ESSOS-CA``).
        ca_host: Host running the CA (used to build ``host\\CA name``).
        template: Certificate template the request used.
        principal: Account the certificate authenticates as.
        not_after: Expiry, already formatted for a human reader.

    Returns:
        A single client-safe string using only native Microsoft tooling.
    """
    ca_config = "CA_HOST\\CA_NAME"
    if ca_host and ca_name:
        ca_config = f"{ca_host}\\{ca_name}"
    elif ca_name:
        ca_config = ca_name

    identity_bits: list[str] = []
    if principal:
        identity_bits.append(f"authenticates as {principal}")
    if template:
        identity_bits.append(f"issued from template {template}")
    if ca_name:
        identity_bits.append(f"by {ca_name}")
    if not_after:
        identity_bits.append(f"valid until {not_after}")
    header = ("Certificate " + ", ".join(identity_bits) + ".\n") if identity_bits else ""

    body = MANUAL_ISSUED_CERTIFICATE.replace("CA_CONFIG", ca_config)
    body = body.replace("SERIAL_NUMBER", str(serial) if serial else "SERIAL_NUMBER")
    body = body.replace(
        "REQUEST_ID", str(request_id) if request_id is not None else "REQUEST_ID"
    )
    return header + body


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
    "MANUAL_ISSUED_CERTIFICATE",
    "KIND_ISSUED_CERTIFICATE",
    "issued_certificate_remediation",
    "KIND_REMEDIATION_TEMPLATE",
    "remediation_template_for_kind",
]
