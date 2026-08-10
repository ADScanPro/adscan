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
MANUAL_REASON_OPERATOR_DECLINED = "operator_declined"

_MANUAL_REASON_LABELS: dict[str, str] = {
    MANUAL_REASON_REVERT_FAILED: "Automatic rollback failed after retries",
    MANUAL_REASON_NOT_ATTEMPTED: "No automatic rollback is possible",
    MANUAL_REASON_SESSION_DIED: "Session ended before rollback completed",
    MANUAL_REASON_MISSING_CREDENTIAL: "No usable rollback credential was available",
    MANUAL_REASON_MISSING_METADATA: "Original-state metadata was unavailable",
    MANUAL_REASON_ACCESS_DENIED: "Rollback was denied by the directory",
    MANUAL_REASON_OPERATOR_DECLINED: "Operator chose to keep the object instead of reverting it",
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

# AD CS ESC5 (CA key theft + offline forge) disclosure kinds.
#
# The CA private key copied off the CA host. A signing key outside the client's
# control is a permanent CA compromise — the only remediation is retiring the
# key, never a per-object revert, so this is ALWAYS a manual item.
KIND_CA_PRIVATE_KEY_EXFILTRATED = "ca_private_key_exfiltrated"
# A certificate forged offline with that stolen key. It has NO enrollment request
# and NO row in the CA database, so the normal revocation procedure cannot reach
# it — distinct from ``issued_certificate`` (which the CA did issue and can
# revoke by request id). Always manual.
KIND_FORGED_CERTIFICATE = "forged_certificate"
# The transient Windows service created on the CA host to run the key-backup
# command, and the temporary key file it writes. Both have a lifecycle: ADscan
# tries to delete them and marks the record reverted only on a confirmed delete,
# otherwise manual_required.
KIND_CA_BACKUP_SERVICE = "ca_backup_service"
KIND_CA_BACKUP_TEMP_PFX = "ca_backup_temp_pfx"

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
    KIND_CA_PRIVATE_KEY_EXFILTRATED: "CA private key copied off the CA host",
    KIND_FORGED_CERTIFICATE: "Forged certificate (outside your CA database)",
    KIND_CA_BACKUP_SERVICE: "Temporary service on the CA host",
    KIND_CA_BACKUP_TEMP_PFX: "Temporary key-backup file on the CA host",
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

# ── AD CS ESC5 (CA key theft + offline forge) remediation templates ───────────
# The private CA key left the CA host, so no per-object revert exists: the only
# fix is to retire the compromised key and rebuild trust. Placeholders
# (CA_IDENTITY / CA_CONFIG) are filled by :func:`ca_private_key_remediation`.
MANUAL_CA_PRIVATE_KEY_EXFILTRATED = (
    "The private key of this certification authority (CA_IDENTITY) was copied off the CA "
    "host during the assessment. A copy of a CA signing key outside your control is a "
    "permanent compromise of the CA: anyone holding it can forge a certificate for ANY "
    "identity in the forest — including Domain Admins and domain controllers — that your "
    "PKI will trust, with no enrollment request and no record in the CA database. Deleting "
    "files or revoking individual certificates does NOT undo this; the only remediation is "
    "to retire the compromised key.\n"
    "  1. Treat this CA's key as compromised and plan a maintenance window: retiring a CA "
    "certificate invalidates every certificate it issued.\n"
    "  2. Back up the CA database, then stand up a replacement CA with a NEW key pair — do "
    "not reuse the key or its backup:\n"
    '     certutil -config "CA_CONFIG" -backupDB "C:\\CA-DB-Backup"\n'
    "  3. Retire the compromised CA certificate — revoke it at its parent for a subordinate "
    "CA, or roll out a new root and trust chain for a root CA — then publish a fresh CRL so "
    "domain members learn of it:\n"
    '     certutil -config "CA_CONFIG" -CRL\n'
    "  4. Remove the old CA certificate from the enterprise NTAuth store and the trusted "
    "root/intermediate stores once migration is complete, and confirm it is gone:\n"
    "     certutil -viewdelstore -enterprise NTAuth\n"
    "  5. Because a forged certificate can carry any identity, once the new PKI is trusted "
    "reset the krbtgt account password twice and reset the passwords of privileged accounts "
    "(Domain Admins, Enterprise Admins) and domain controller machine accounts.\n"
    "Until the compromised key is retired, assume any certificate-based authentication in "
    "the forest can be spoofed."
)

# A forged certificate cannot be revoked individually — it is not in the CA
# database. Placeholders filled by :func:`forged_certificate_remediation`.
MANUAL_FORGED_CERTIFICATE = (
    "A certificate was forged offline during the assessment using the compromised CA "
    "private key, and it authenticates as FORGED_IDENTITY. Because it was signed outside "
    "the CA, it has NO enrollment request, does NOT appear in the CA database, and the "
    "normal revocation procedure cannot reach it — there is no request id or database row "
    "to revoke. Its serial number (SERIAL_NUMBER) was chosen by the assessment.\n"
    "  1. You cannot revoke this certificate individually. It stays usable for "
    "authentication until it expires (valid until VALID_UNTIL) OR until the signing CA key "
    "it was forged with is retired.\n"
    "  2. Retire the compromised CA key as described in the CA private-key remediation — "
    "that is the only action that invalidates this forged certificate.\n"
    "  3. Reset the password of the impersonated account (FORGED_IDENTITY) so any Kerberos "
    "material already obtained with the forged certificate stops granting access, and "
    "review Event 4768 (a Kerberos ticket was requested) with a certificate mapping to "
    "that account from unexpected hosts."
)

# The transient service used to run the backup. Placeholders filled by
# :func:`ca_backup_service_remediation`.
MANUAL_CA_BACKUP_SERVICE = (
    "A temporary Windows service (SERVICE_NAME) was created on the CA host (CA_HOST) to run "
    "the key-backup command, and ADscan could not confirm it was removed. Remove it "
    "manually with local administrator rights on that host:\n"
    "  1. Confirm it exists:\n"
    '     Get-Service -ComputerName "CA_HOST" -Name "SERVICE_NAME"\n'
    "  2. Delete it:\n"
    '     sc.exe \\\\CA_HOST delete "SERVICE_NAME"\n'
    "  3. Review Event ID 7045 (a service was installed in the system) on CA_HOST around "
    "the assessment window and confirm no other unexpected service remains."
)

# The temporary CA key file written under C:\Windows\Tasks. Placeholders filled
# by :func:`ca_backup_temp_pfx_remediation`.
MANUAL_CA_BACKUP_TEMP_PFX = (
    "The CA private key was written to a temporary file on the CA host during the backup "
    "(PFX_PATH), protected only by a fixed, publicly-known password, and ADscan could not "
    "confirm the file was deleted. Anyone who can read it recovers the CA signing key. "
    "Remove it with local administrator rights on the CA host:\n"
    "  1. Delete the file (and the parent working directory if present):\n"
    '     Remove-Item -Path "PFX_PATH" -Force\n'
    "  2. Search the working directory for any leftover key material:\n"
    "     Get-ChildItem 'C:\\Windows\\Tasks' -Include *.p12,*.pfx -Recurse\n"
    "  3. Because the file held the CA signing key under a known password, treat the CA key "
    "as exposed and follow the CA private-key remediation even if the file is already gone."
)


def _ca_config_string(ca_name: str | None, ca_host: str | None) -> str:
    """Build the ``host\\CA name`` config string certutil expects."""
    if ca_host and ca_name:
        return f"{ca_host}\\{ca_name}"
    if ca_name:
        return ca_name
    return "CA_HOST\\CA_NAME"


def ca_private_key_remediation(
    *,
    ca_subject: str | None = None,
    ca_name: str | None = None,
    ca_host: str | None = None,
) -> str:
    """Render the client-facing remediation for an exfiltrated CA private key."""
    identity = ca_subject or ca_name or (f"the CA on {ca_host}" if ca_host else "this CA")
    body = MANUAL_CA_PRIVATE_KEY_EXFILTRATED.replace("CA_IDENTITY", identity)
    return body.replace("CA_CONFIG", _ca_config_string(ca_name, ca_host))


def forged_certificate_remediation(
    *,
    principal: str | None = None,
    serial: str | None = None,
    not_after: str | None = None,
) -> str:
    """Render the client-facing remediation for an offline-forged certificate."""
    body = MANUAL_FORGED_CERTIFICATE.replace(
        "FORGED_IDENTITY", principal or "an unnamed principal"
    )
    body = body.replace("SERIAL_NUMBER", str(serial) if serial else "an assessment-chosen serial")
    return body.replace("VALID_UNTIL", not_after or "its embedded expiry")


def ca_backup_service_remediation(
    *, service_name: str | None = None, ca_host: str | None = None
) -> str:
    """Render the client-facing remediation for the transient CA-backup service."""
    body = MANUAL_CA_BACKUP_SERVICE.replace(
        "SERVICE_NAME", service_name or "the temporary service"
    )
    return body.replace("CA_HOST", ca_host or "the CA host")


def ca_backup_temp_pfx_remediation(*, unc_path: str | None = None) -> str:
    """Render the client-facing remediation for the temporary CA key file."""
    return MANUAL_CA_BACKUP_TEMP_PFX.replace(
        "PFX_PATH", unc_path or "C:\\Windows\\Tasks"
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
    KIND_CA_PRIVATE_KEY_EXFILTRATED: MANUAL_CA_PRIVATE_KEY_EXFILTRATED,
    KIND_FORGED_CERTIFICATE: MANUAL_FORGED_CERTIFICATE,
    KIND_CA_BACKUP_SERVICE: MANUAL_CA_BACKUP_SERVICE,
    KIND_CA_BACKUP_TEMP_PFX: MANUAL_CA_BACKUP_TEMP_PFX,
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
    "MANUAL_REASON_OPERATOR_DECLINED",
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
    "KIND_CA_PRIVATE_KEY_EXFILTRATED",
    "KIND_FORGED_CERTIFICATE",
    "KIND_CA_BACKUP_SERVICE",
    "KIND_CA_BACKUP_TEMP_PFX",
    "MANUAL_CA_PRIVATE_KEY_EXFILTRATED",
    "MANUAL_FORGED_CERTIFICATE",
    "MANUAL_CA_BACKUP_SERVICE",
    "MANUAL_CA_BACKUP_TEMP_PFX",
    "ca_private_key_remediation",
    "forged_certificate_remediation",
    "ca_backup_service_remediation",
    "ca_backup_temp_pfx_remediation",
    "KIND_REMEDIATION_TEMPLATE",
    "remediation_template_for_kind",
]
