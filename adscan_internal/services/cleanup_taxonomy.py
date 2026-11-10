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

from adscan_core.reporting import cleanup_commands as _cleanup_commands
# A computer account ADscan created and could only disable (shared copy SSOT).
from adscan_core.reporting.cleanup_disclosures import (
    KEPT_LABEL_DEFAULT,
    MANUAL_REASON_NEUTRALIZED,
    MANUAL_REASON_NEUTRALIZED_LABEL,
)
# Why a change is still in place and whose action it needs (shared with the
# reports and the web CTEM): the outcome classes, their copy, the revert roles.
from adscan_core.reporting.cleanup_outcome import (
    REASON_NO_PRIVILEGED_CREDENTIAL,
    REASON_NO_PRIVILEGED_CREDENTIAL_LABEL,
    REVERT_ROLE_LABELS,
)

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
#: The revert RAN (the directory accepted the undo) but no credential could
#: open a follow-up read to confirm the change is gone. Distinct from
#: ``revert_failed``: nothing says the change is still present, only that it is
#: unconfirmed, so the client is asked to check rather than told it failed.
MANUAL_REASON_REVERT_UNCONFIRMED = "revert_unconfirmed"
#: A password the assessment reset whose previous value it never held (not the
#: scan account, not cracked, not recovered as a hash), so nothing could put it
#: back. Replaces the old ``not_attempted`` for this case: the reason is the
#: missing secret, and the report says so.
MANUAL_REASON_ORIGINAL_SECRET_UNKNOWN = "original_secret_unknown"
#: The previous password was put back from its NT hash only (SAMR
#: ``UserInternal1Information``). Sign-in with the old password works again, but
#: the account's Kerberos AES keys cannot be rebuilt from a hash, so its owner
#: has to change the password once. A client action, hence the manual bucket.
MANUAL_REASON_PASSWORD_RESTORED_FROM_HASH = "password_restored_from_hash"
#: Automatic reversion was on, but no account available to the assessment had
#: the rights to undo the change: no client cleanup account and no verified
#: privileged account among the candidates the revert had or tried. Recorded
#: by ``revert_credentials.stamp_revert_rights`` when the revert gives up, never
#: inferred later. A missing input, not a failed revert, and the client closes
#: it by providing a cleanup account.
MANUAL_REASON_NO_PRIVILEGED_CREDENTIAL = REASON_NO_PRIVILEGED_CREDENTIAL

#: ``manual_required`` reasons a later attempt (another credential, the exit
#: cleanup, the final retry pass) can still overturn into a confirmed revert.
RETRYABLE_REVERT_REASONS = frozenset(
    {
        MANUAL_REASON_REVERT_FAILED,
        MANUAL_REASON_REVERT_UNCONFIRMED,
        MANUAL_REASON_NO_PRIVILEGED_CREDENTIAL,
    }
)

_MANUAL_REASON_LABELS: dict[str, str] = {
    MANUAL_REASON_REVERT_FAILED: "Automatic rollback failed after retries",
    MANUAL_REASON_NOT_ATTEMPTED: "No automatic rollback is possible",
    MANUAL_REASON_SESSION_DIED: "Session ended before rollback completed",
    MANUAL_REASON_MISSING_CREDENTIAL: "No usable rollback credential was available",
    MANUAL_REASON_MISSING_METADATA: "Original-state metadata was unavailable",
    MANUAL_REASON_ACCESS_DENIED: "Rollback was denied by the directory",
    MANUAL_REASON_OPERATOR_DECLINED: "Operator chose to keep the object instead of reverting it",
    MANUAL_REASON_REVERT_UNCONFIRMED: (
        "Rollback ran, but a follow-up read could not confirm it"
    ),
    MANUAL_REASON_NO_PRIVILEGED_CREDENTIAL: REASON_NO_PRIVILEGED_CREDENTIAL_LABEL,
    MANUAL_REASON_ORIGINAL_SECRET_UNKNOWN: (
        "The previous password was not known, so it could not be put back"
    ),
    MANUAL_REASON_PASSWORD_RESTORED_FROM_HASH: (
        "Previous password restored. Its owner must change it once"
    ),
    MANUAL_REASON_NEUTRALIZED: MANUAL_REASON_NEUTRALIZED_LABEL,
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
    STATUS_KEPT: KEPT_LABEL_DEFAULT,
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

# ── Preparatory lifecycle writes (an account enabled, an object restored) ─────
# Not the attack step itself: the change ADscan makes so the step can run. Each
# is a directory change the client must see. An account ADscan enabled is set
# back to disabled at exit and re-read to confirm it; a restored object is left
# for the client to decide (deleting it again is their call), so it is always a
# manual item.
KIND_ACCOUNT_ENABLED = "account_enabled"
KIND_OBJECT_RESTORED = "object_restored"
# ESC7: ADscan granted itself the CA officer role (Issue and Manage
# Certificates) through ManageCA, and removes it again at the end of the step.
KIND_CA_OFFICER_ADDED = "ca_officer_added"

# ── Directory writes of the ACL write seams (``cli/exploits.py``) ─────────────
# Recorded at the seam every caller funnels through (the attack-path ACE step,
# the interactive ACL menu, the post-step follow-ups), via
# ``services/directory_write_ledger.py``.
#: A password ADscan reset (ForceChangePassword, the GenericAll fallback, the
#: must-change rotation, or the reset a staged logon script performs). The
#: previous secret is gone, so it is always a MANUAL item.
KIND_PASSWORD_CHANGED = "password_changed"
#: A service principal name ADscan added to an account for targeted
#: Kerberoasting. Removed at exit (that one value only) and re-read to confirm.
KIND_SPN_ADDED = "spn_added"
#: An access control entry ADscan added to an object's DACL.
KIND_DACL_ACE_ADDED = "dacl_ace_added"
#: An object whose owner ADscan changed.
KIND_OWNER_CHANGED = "owner_changed"
#: A group membership ADscan added (never a membership that already existed).
KIND_GROUP_MEMBERSHIP_ADDED = "group_membership_added"

# ── Remote-artefact kinds (files ADscan writes on an assessed HOST) ───────────
# These are not directory objects: nothing in Active Directory changes, but a
# file exists on the client's machine that did not exist before. A credential
# dump, a saved registry hive and an uploaded helper executable all land here.
# They carry the same lifecycle as any other change (deleted and confirmed, or
# manual_required with the exact path), and the disclosure must separate them
# from directory writes so neither statement overstates the other.
#: A file ADscan created on the target (a process dump, a saved registry hive).
KIND_REMOTE_FILE_WRITTEN = "file_written"
#: A file ADscan pushed to the target (a helper executable it then ran).
KIND_REMOTE_FILE_UPLOADED = "file_uploaded"
#: Every kind whose object lives on a host filesystem rather than in the
#: directory. The SSOT for "was this a directory change or a file on a host?".
HOST_ARTIFACT_KINDS: frozenset[str] = frozenset(
    {KIND_REMOTE_FILE_WRITTEN, KIND_REMOTE_FILE_UPLOADED}
)


def kind_is_host_artifact(kind: str | None) -> bool:
    """Whether a change kind is a file on a host rather than a directory object.

    Args:
        kind: The ``kind`` recorded on a ledger entry.

    Returns:
        True for a remote file ADscan wrote or uploaded, False for every
        directory change.
    """
    return str(kind or "").strip().lower() in HOST_ARTIFACT_KINDS

# ── Change-kind display strings (SSOT) ────────────────────────────────────────
# Every kind any writer registers needs an entry here, or the client-facing
# disclosure prints the raw snake_case token. Keep this in step with the
# ``kind=`` arguments passed to ``EnvironmentChangeLedger.register``; a missing
# key is not a crash, it is a `template_mutated` in a customer's PDF.
KIND_DISPLAY: dict[str, str] = {
    "group_membership_added": "Group membership",
    "group_membership_changed": "Group membership",
    KIND_REMOTE_FILE_WRITTEN: "File written on an assessed host",
    KIND_REMOTE_FILE_UPLOADED: "File uploaded to an assessed host",
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
    "dns_record_added": "ADIDNS record",
    "keycredentiallink_added": "KeyCredentialLink",
    "upn_changed": "User principal name",
    "altsecurityidentities_written": "Certificate mapping attribute",
    "victim_attribute_written": "Attribute on the computer account ADscan created",
    "dacl_grant_dcsync": "Replication rights granted on the domain object",
    "gpo_ldap_attribute_modified": "Group Policy object attribute",
    "gpo_gpt_ini_modified": "Group Policy version file",
    "gpo_sysvol_dir_created": "Group Policy folder in SYSVOL",
    "gpo_sysvol_file_created": "Group Policy file in SYSVOL",
    "mssql_admin_account_created": "Database administrator account",
    "mssql_postex_account": "Administrator account or Domain Admins membership",
    "mssql_clr_assembly_loaded": "Database CLR assembly",
    "mssql_clr_config_changed": "Database CLR configuration",
    "mssql_xp_cmdshell_enabled": "Database command execution setting",
    "scheduled_task_created": "Scheduled task created on an assessed host",
    "logon_script_path_modified": "Logon script path (scriptPath)",
    "rodc_prp_modified": "RODC password-replication policy (msDS-RevealOnDemandGroup)",
    KIND_ACCOUNT_ENABLED: "Disabled account enabled",
    KIND_OBJECT_RESTORED: "Deleted object restored from the AD Recycle Bin",
    KIND_CA_OFFICER_ADDED: "Certificate manager (officer) right on your CA",
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
    "Remove the access control entry added during the engagement. RIGHTS_NOTEThis "
    "removes every ACE the trustee holds on the object, so confirm the trustee has "
    "no legitimate rights on it before running it.\n"
    "  Import-Module ActiveDirectory\n"
    '  dsacls "OBJECT_DN" /R "TRUSTEE"\n'
    "Then confirm the entry is gone. The check counts the entries the trustee still "
    "holds on the object and should print 0.\n"
    "  @((Get-Acl \"AD:OBJECT_DN\").Access | "
    "Where-Object { $_.IdentityReference -like '*TRUSTEE_NAME*' }).Count"
)


def _object_reference_to_dn(obj: str | None, domain: str | None) -> str:
    """Best-effort distinguished name for a client-facing cleanup command.

    An already-DN reference is returned unchanged; a domain-like token
    (``htb.local``) becomes its ``DC=htb,DC=local`` DN; a bare name is left as
    is (the client substitutes the object's DN). Falls back to the domain DN
    when no object reference is available.
    """
    ref = str(obj or "").strip()
    if "=" in ref:
        return ref
    if ref and "." in ref and " " not in ref:
        return ",".join(f"DC={part}" for part in ref.lower().split("."))
    if not ref and domain:
        return ",".join(f"DC={part}" for part in str(domain).strip().lower().split("."))
    return ref


def dacl_ace_remediation(
    *,
    object_dn: str | None = None,
    trustee: str | None = None,
    rights_type: str | None = None,
    domain: str | None = None,
) -> str:
    """Render the cleanup for an ACE ADscan added, with this engagement's values.

    Fills the object DN and the NetBIOS-qualified trustee into a runnable
    ``dsacls /R`` command (the same native form the attack-path remediation
    renders), instead of leaving the ``OBJECT_DN``/``TRUSTEE`` template tokens
    for the client to guess. Names the rights that were granted (e.g. DCSync)
    so the reader knows what the ACE did.
    """
    dn = _object_reference_to_dn(object_dn, domain)
    trustee_name = str(trustee or "").strip()
    netbios = ""
    if domain:
        first_label = str(domain).strip().split(".", 1)[0]
        netbios = first_label.upper()
    principal = f"{netbios}\\{trustee_name}" if netbios and trustee_name else (trustee_name or "TRUSTEE")
    rights_note = ""
    if rights_type:
        raw = str(rights_type).strip().lower()
        label = {
            "dcsync": "directory-replication (DCSync)",
            "writedacl": "write-DACL",
            "genericall": "full-control (GenericAll)",
        }.get(raw, raw)
        rights_note = f"This ACE granted {label} rights. "
    body = MANUAL_DACL_ACE.replace("OBJECT_DN", dn or "TARGET")
    body = body.replace("TRUSTEE_NAME", trustee_name or "the trustee")
    body = body.replace("TRUSTEE", principal)
    body = body.replace("RIGHTS_NOTE", rights_note)
    return body

#: The owner is written through ``DirectoryEntry`` with ``SecurityMasks`` set
#: to ``Owner``: that sends the LDAP SD-flags control for the owner alone. A
#: ``Set-ADObject -Replace @{nTSecurityDescriptor=...}`` round trip returns
#: without error and leaves the owner unchanged (measured on a lab domain
#: controller, 2026-11-06), so it must never be the instruction.
MANUAL_OWNER = (
    "Restore the original owner of TARGET. The commands below write the owner only, so "
    "the object's permissions stay as they are. Run them as a domain administrator.\n"
    "  Import-Module ActiveDirectory\n"
    "  $dn = (Get-ADObject -LDAPFilter '(|(sAMAccountName=TARGET)(name=TARGET))')"
    ".DistinguishedName\n"
    "  $entry = [ADSI]\"LDAP://$dn\"\n"
    "  $entry.psbase.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Owner\n"
    "  $entry.psbase.ObjectSecurity.SetOwner("
    "[System.Security.Principal.NTAccount]'ORIGINAL_OWNER')\n"
    "  $entry.psbase.CommitChanges()\n"
    "Then confirm the owner. The check should print ORIGINAL_OWNER.\n"
    "  ([ADSI]\"LDAP://$dn\").psbase.ObjectSecurity"
    ".GetOwner([System.Security.Principal.NTAccount]).Value"
)

MANUAL_SPN = (
    "Remove the injected service principal name manually:\n"
    "  Set-ADUser -Identity TARGET -ServicePrincipalNames @{Remove='SPN'}\n"
    "For a computer account, use this instead:\n"
    "  Set-ADComputer -Identity TARGET -ServicePrincipalNames @{Remove='SPN'}"
)

MANUAL_PASSWORD = (
    "The password of TARGET was reset during the engagement and its previous value "
    "is no longer in place. Coordinate with the account's owner, then set a password "
    "they control:\n"
    "  Set-ADAccountPassword -Identity 'TARGET' -Reset -NewPassword "
    "(Read-Host -AsSecureString 'New password')\n"
    "For an account a person signs in with, require a new password at the next "
    "sign-in:\n"
    "  Set-ADUser -Identity 'TARGET' -ChangePasswordAtLogon $true\n"
    "Then confirm the reset. PasswordLastSet should be later than the engagement:\n"
    "  Get-ADUser -Identity 'TARGET' -Properties PasswordLastSet"
)

#: The previous password was put back from its NT hash: the owner changes it
#: once so the account's Kerberos AES keys exist again.
MANUAL_PASSWORD_RESTORED_FROM_HASH = (
    "The password of TARGET was reset during the engagement and then put back from "
    "its stored hash, so the account's owner can sign in with the previous password "
    "again. A hash cannot rebuild the account's Kerberos AES keys, so ask the owner to "
    "change the password once, or set one they control:\n"
    "  Set-ADUser -Identity 'TARGET' -ChangePasswordAtLogon $true\n"
    "Then confirm the change. PasswordLastSet should be later than the engagement:\n"
    "  Get-ADUser -Identity 'TARGET' -Properties PasswordLastSet"
)

#: The reset a staged logon script performs runs on the target's own logon,
#: outside ADscan's observation, so the record must not claim it happened. Used
#: until ADscan confirms the new credential; then :data:`MANUAL_PASSWORD` applies.
MANUAL_PASSWORD_PENDING_LOGON = (
    "A logon script staged during the engagement resets this account's password the "
    "next time the user who runs it logs on. Check whether the reset ran:\n"
    "  Get-ADUser -Identity TARGET -Properties PasswordLastSet\n"
    "If PasswordLastSet is later than the time the script was staged, the previous "
    "password is gone; reset it to a value the client controls:\n"
    "  Set-ADAccountPassword -Identity TARGET -Reset -NewPassword"
    " (ConvertTo-SecureString 'NewPass' -AsPlainText -Force)"
)

MANUAL_GROUP_MEMBERSHIP = (
    "Remove the group member added during the engagement manually:\n"
    "  Remove-ADGroupMember -Identity 'GROUP' -Members 'MEMBER' -Confirm:$false"
)

MANUAL_DNS_RECORD = (
    "Remove the ADIDNS record created during the engagement:\n"
    "  Remove-DnsServerResourceRecord -ZoneName 'ZONE' -Name 'RECORD'"
    " -RRType A -Force"
)

MANUAL_RBCD = (
    "Clear or restore msDS-AllowedToActOnBehalfOfOtherIdentity on the target:\n"
    "  Set-ADComputer -Identity TARGET -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'"
)

MANUAL_ACCOUNT_ENABLED = (
    "Disable the account again. It was disabled before the engagement:\n"
    "  Disable-ADAccount -Identity 'TARGET'\n"
    "Then verify the change. Enabled should read False:\n"
    "  Get-ADObject -LDAPFilter '(sAMAccountName=TARGET)' -Properties userAccountControl"
)

MANUAL_OBJECT_RESTORED = (
    "This object was deleted before the engagement and was restored from the AD "
    "Recycle Bin. Confirm with its owner whether it should stay restored; if not, "
    "delete it again:\n"
    "  Remove-ADObject -Identity 'OBJECT_DN' -Confirm:$false"
)

MANUAL_CA_OFFICER = (
    "Remove the Issue and Manage Certificates permission granted to TARGET on the "
    "certificate authority: open the Certification Authority console (certsrv.msc) "
    "on the CA host, then Properties > Security, select the account and clear "
    "'Issue and Manage Certificates'. Then confirm the account no longer holds it. "
    "Run this on the CA host:\n"
    "  certutil -getreg CA\\Security"
)

MANUAL_KEYCREDENTIALLINK = (
    "Restore msDS-KeyCredentialLink on the target to its prior value list, removing "
    "the value added during the engagement:\n"
    "  Get-ADObject TARGET -Properties msDS-KeyCredentialLink\n"
    "Clear the whole attribute only if it was empty before the engagement:\n"
    "  Set-ADObject TARGET -Clear 'msDS-KeyCredentialLink'"
)

MANUAL_MACHINE_ACCOUNT = (
    "Remove the machine account created during the engagement with a privileged account:\n"
    "  Remove-ADComputer -Identity 'TARGET' -Confirm:$false"
)

# A user account ADscan created during the engagement (e.g. the HasSession
# create-and-elevate plan). Deleting it with a privileged account removes both
# the account and any group membership it held.
MANUAL_USER_ACCOUNT = (
    "Delete the account created during the engagement with a privileged account:\n"
    "  Remove-ADUser -Identity 'TARGET' -Confirm:$false\n"
    "For a host-local account instead of a domain one, run this on the host:\n"
    "  Remove-LocalUser -Name 'TARGET'\n"
    "Then confirm a domain account is gone. The check should return nothing:\n"
    "  Get-ADUser -Filter \"sAMAccountName -eq 'TARGET'\""
)

# A scheduled task ADscan registered on an assessed host to run a command as the
# logged-on user. Removing it needs local administrator rights on that host.
MANUAL_SCHEDULED_TASK = (
    "A scheduled task (TASK_NAME) was registered on ARTIFACT_HOST during the engagement to "
    "run a command, and ADscan could not confirm it was removed. Remove it with local "
    "administrator rights on that host:\n"
    "  1. Confirm it exists:\n"
    '     Get-ScheduledTask -TaskName "TASK_NAME" -CimSession "ARTIFACT_HOST"\n'
    "  2. Delete it:\n"
    '     Unregister-ScheduledTask -TaskName "TASK_NAME" -CimSession "ARTIFACT_HOST" -Confirm:$false\n'
    "  3. Review Event ID 4698 (a scheduled task was created) on ARTIFACT_HOST around the "
    "assessment window and confirm no other unexpected task remains."
)

# The target user's scriptPath (logon script) was overwritten during the
# engagement. Restoring it means clearing the injected value, or setting it back
# to the value the client had before, with a privileged account.
MANUAL_LOGON_SCRIPT_PATH = (
    "The logon script (scriptPath) of TARGET was overwritten during the engagement so that "
    "a script runs the next time an affected user logs on. Restore it with a privileged "
    "account:\n"
    "  1. Read the current value:\n"
    "     Get-ADUser -Identity 'TARGET' -Properties scriptPath | Select-Object scriptPath\n"
    "  2. Clear it if the account had no logon script before:\n"
    "     Set-ADUser -Identity 'TARGET' -Clear scriptPath\n"
    "     If it had one, set it back to the original value instead:\n"
    "     Set-ADUser -Identity 'TARGET' -ScriptPath 'ORIGINAL_SCRIPT'\n"
    "  3. Remove the staged script file from the NETLOGON share and confirm it is gone."
)

# The RODC password-replication policy (msDS-RevealOnDemandGroup) was modified to
# let the read-only DC cache the target's secrets. Restoring it removes the
# principal added during the engagement, with a privileged account.
MANUAL_RODC_PRP = (
    "The read-only domain controller's password-replication policy "
    "(msDS-RevealOnDemandGroup on TARGET) was modified during the engagement to allow the "
    "target principal's secrets to be cached. Restore it with a privileged account:\n"
    "  1. Read the current allowed-list:\n"
    "     Get-ADObject 'TARGET' -Properties msDS-RevealOnDemandGroup\n"
    "  2. Remove the principal added during the engagement (REVEAL_PRINCIPAL):\n"
    "     Set-ADObject 'TARGET' -Remove @{'msDS-RevealOnDemandGroup'='REVEAL_PRINCIPAL'}\n"
    "  3. If the engagement also emptied msDS-NeverRevealGroup, restore its prior members, "
    "then clear any cached secrets with Reset-ADServiceAccountPassword on affected service "
    "accounts and consider resetting the exposed accounts' passwords."
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
    "that account from unexpected hosts:\n"
    "     Set-ADAccountPassword -Identity 'FORGED_IDENTITY' -Reset -NewPassword "
    "(Read-Host -AsSecureString 'New password')"
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


# A file ADscan wrote or uploaded on an assessed host and could not confirm it
# removed. Placeholders filled by :func:`remote_artifact_remediation`.
MANUAL_REMOTE_ARTIFACT = (
    "ADscan wrote the file ARTIFACT_PATH on ARTIFACT_HOST while running the technique, and "
    "could not confirm it was deleted afterwards. A process dump or a saved registry hive "
    "holds credential material that is readable by anyone who can read the file, so remove "
    "it before the host returns to normal use. Local administrator rights on that host are "
    "enough:\n"
    "  1. Confirm the file is still there:\n"
    '     Test-Path "ARTIFACT_PATH"\n'
    "  2. Delete it:\n"
    '     Remove-Item -Path "ARTIFACT_PATH" -Force\n'
    "  3. Confirm it is gone (this must return False):\n"
    '     Test-Path "ARTIFACT_PATH"\n'
    "  4. Review the rest of the temporary directory for anything else left from the "
    "assessment window:\n"
    "     Get-ChildItem 'C:\\Windows\\Temp' | Sort-Object LastWriteTime -Descending | "
    "Select-Object -First 20"
)


def remote_artifact_remediation(
    *, remote_path: str | None = None, host: str | None = None
) -> str:
    """Render the client-facing remediation for a file left on an assessed host.

    Args:
        remote_path: The local Windows path on the target (e.g.
            ``C:\\Windows\\Temp\\ab12cd.dmp``).
        host: The host the file sits on.

    Returns:
        A single client-safe string using only native Windows tooling.
    """
    body = MANUAL_REMOTE_ARTIFACT.replace(
        "ARTIFACT_PATH", remote_path or "the temporary file"
    )
    return body.replace("ARTIFACT_HOST", host or "the assessed host")


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


def object_restored_remediation(object_dn: str | None) -> str:
    """Render the client-facing note for an object restored from the Recycle Bin."""
    return MANUAL_OBJECT_RESTORED.replace("OBJECT_DN", object_dn or "the restored object")


def ca_backup_temp_pfx_remediation(*, unc_path: str | None = None) -> str:
    """Render the client-facing remediation for the temporary CA key file."""
    return MANUAL_CA_BACKUP_TEMP_PFX.replace(
        "PFX_PATH", unc_path or "C:\\Windows\\Tasks"
    )


# ── Templates for the kinds whose writers stamp their own procedure ───────────
# The writer of each kind below normally stores a fully rendered command when it
# settles the change. These are the fallback for a record that ends up still in
# place without one (kept by policy, or a session that died), so no change is
# ever disclosed without a way to remove it.
MANUAL_TEMPLATE_MODIFIED = (
    "The certificate template TARGET was modified during the engagement. Read its "
    "current settings and compare them with your change records or a backup of the "
    "template:\n"
    "  Get-ADObject -SearchBase ('CN=Certificate Templates,CN=Public Key Services,"
    "CN=Services,' + (Get-ADRootDSE).configurationNamingContext) "
    "-LDAPFilter '(cn=TARGET)' -Properties *\n"
    "Restore the changed attributes (enrollment flags, extended key usages, "
    "permissions) in the Certificate Templates console (certtmpl.msc)."
)

MANUAL_CA_TEMPLATE_ENABLED = (
    "The certificate template TARGET was published on your certification authority "
    "during the engagement. If it was not published before, remove it from the CA's "
    "issued templates. Run this on the CA host:\n"
    "  certutil -SetCATemplates -TARGET\n"
    "Then confirm it is no longer listed:\n"
    "  certutil -CATemplates"
)

MANUAL_ACL_MODIFIED = (
    "The permissions of TARGET were changed during the engagement. List the access "
    "control entries and remove the ones added during the engagement:\n"
    "  $dn = (Get-ADObject -LDAPFilter '(|(sAMAccountName=TARGET)(name=TARGET))')"
    ".DistinguishedName\n"
    "  (Get-Acl \"AD:$dn\").Access | Format-Table IdentityReference, "
    "ActiveDirectoryRights, AccessControlType"
)

MANUAL_SPN_RELOCATED = (
    "The service principal name SPN was moved to TARGET during the engagement. "
    "Remove it from that account and give it back to ORIGINAL_OWNER:\n"
    "  Set-ADObject -Identity (Get-ADObject -LDAPFilter '(sAMAccountName=TARGET)')"
    ".DistinguishedName -Remove @{servicePrincipalName='SPN'}\n"
    "  Set-ADObject -Identity (Get-ADObject -LDAPFilter "
    "'(sAMAccountName=ORIGINAL_OWNER)').DistinguishedName -Add @{servicePrincipalName='SPN'}"
)

MANUAL_UPN_CHANGED = (
    "The user principal name of TARGET was changed during the engagement. Set it back "
    "to its previous value:\n"
    "  Set-ADUser -Identity 'TARGET' -UserPrincipalName 'ORIGINAL_UPN'\n"
    "Then confirm it:\n"
    "  Get-ADUser -Identity 'TARGET' -Properties UserPrincipalName"
)

MANUAL_ALTSECID = (
    "A certificate mapping (altSecurityIdentities) was written on TARGET during the "
    "engagement. Read the attribute and remove the value added during the engagement:\n"
    "  Get-ADObject -Identity (Get-ADObject -LDAPFilter '(sAMAccountName=TARGET)')"
    ".DistinguishedName -Properties altSecurityIdentities\n"
    "  Set-ADObject -Identity (Get-ADObject -LDAPFilter '(sAMAccountName=TARGET)')"
    ".DistinguishedName -Remove @{altSecurityIdentities='MAPPING'}"
)

MANUAL_VICTIM_ATTRIBUTE = (
    "An attribute was written on the computer account TARGET, which the assessment "
    "created. Deleting that computer account removes the change:\n"
    "  Remove-ADComputer -Identity 'TARGET' -Confirm:$false"
)

MANUAL_DCSYNC_GRANT = (
    "Directory replication rights were granted to TRUSTEE on the domain object during "
    "the engagement. Remove them. This removes every permission the trustee holds on "
    "the domain object, so confirm it has no legitimate rights there first.\n"
    "  Import-Module ActiveDirectory\n"
    "  dsacls (Get-ADDomain).DistinguishedName /R 'TRUSTEE'\n"
    "Then confirm the entries are gone. The check counts the entries the trustee still "
    "holds on the domain object and should print 0.\n"
    "  @((Get-Acl \"AD:$((Get-ADDomain).DistinguishedName)\").Access | "
    "Where-Object { $_.IdentityReference -like '*TRUSTEE_NAME*' }).Count"
)

MANUAL_GPO_CHANGE = (
    "The Group Policy object TARGET was changed during the engagement to run an "
    "immediate scheduled task. Remove the task from the policy and confirm the policy "
    "no longer carries it:\n"
    "  Get-GPO -Guid 'GPO_GUID' | Format-List DisplayName, ModificationTime\n"
    "Open the policy in the Group Policy Management console (gpmc.msc), go to "
    "Preferences > Control Panel Settings > Scheduled Tasks, and delete the task "
    "added during the engagement. Then run a policy update on an affected host:\n"
    "  gpupdate /force"
)

MANUAL_MSSQL_ACCOUNT = (
    "A database or host account (TARGET) was created during the engagement. Delete "
    "it with an administrator account:\n"
    "  Remove-ADUser -Identity 'TARGET' -Confirm:$false\n"
    "For a host-local account instead of a domain one, run this on the host:\n"
    "  Remove-LocalUser -Name 'TARGET'"
)

MANUAL_MSSQL_CONFIGURATION = (
    "A SQL Server setting (OPTION) was changed on TARGET during the engagement. "
    "Set it back to its previous value as a sysadmin:\n"
    "  Invoke-Sqlcmd -ServerInstance 'TARGET' -Query \"EXEC sp_configure 'OPTION', "
    "ORIGINAL_VALUE; RECONFIGURE;\"\n"
    "Then confirm the running value:\n"
    "  Invoke-Sqlcmd -ServerInstance 'TARGET' -Query \"EXEC sp_configure 'OPTION';\""
)

MANUAL_MSSQL_ASSEMBLY = (
    "A CLR assembly (ASSEMBLY) was loaded into the msdb database on TARGET during the "
    "engagement. Drop it as a sysadmin:\n"
    "  Invoke-Sqlcmd -ServerInstance 'TARGET' -Database msdb -Query "
    "\"DROP ASSEMBLY [ASSEMBLY];\""
)

MANUAL_COMPUTER_ACCOUNT = MANUAL_MACHINE_ACCOUNT


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
    "dns_record_added": MANUAL_DNS_RECORD,
    "keycredentiallink_added": MANUAL_KEYCREDENTIALLINK,
    "machine_account_created": MANUAL_MACHINE_ACCOUNT,
    "user_created": MANUAL_USER_ACCOUNT,
    "scheduled_task_created": MANUAL_SCHEDULED_TASK,
    "logon_script_path_modified": MANUAL_LOGON_SCRIPT_PATH,
    "rodc_prp_modified": MANUAL_RODC_PRP,
    KIND_ACCOUNT_ENABLED: MANUAL_ACCOUNT_ENABLED,
    KIND_OBJECT_RESTORED: MANUAL_OBJECT_RESTORED,
    KIND_CA_OFFICER_ADDED: MANUAL_CA_OFFICER,
    KIND_ISSUED_CERTIFICATE: MANUAL_ISSUED_CERTIFICATE,
    KIND_CA_PRIVATE_KEY_EXFILTRATED: MANUAL_CA_PRIVATE_KEY_EXFILTRATED,
    KIND_FORGED_CERTIFICATE: MANUAL_FORGED_CERTIFICATE,
    KIND_CA_BACKUP_SERVICE: MANUAL_CA_BACKUP_SERVICE,
    KIND_CA_BACKUP_TEMP_PFX: MANUAL_CA_BACKUP_TEMP_PFX,
    # The write seam stamps the fully rendered command (it knows the real path
    # and host); this entry is the fallback for a record that reaches
    # ``finalize()`` without one.
    KIND_REMOTE_FILE_WRITTEN: MANUAL_REMOTE_ARTIFACT,
    KIND_REMOTE_FILE_UPLOADED: MANUAL_REMOTE_ARTIFACT,
    "template_modified": MANUAL_TEMPLATE_MODIFIED,
    "template_mutated": MANUAL_TEMPLATE_MODIFIED,
    "ca_template_enabled": MANUAL_CA_TEMPLATE_ENABLED,
    "acl_modified": MANUAL_ACL_MODIFIED,
    "spn_relocated": MANUAL_SPN_RELOCATED,
    "computer_account_created": MANUAL_COMPUTER_ACCOUNT,
    "upn_changed": MANUAL_UPN_CHANGED,
    "altsecurityidentities_written": MANUAL_ALTSECID,
    "victim_attribute_written": MANUAL_VICTIM_ATTRIBUTE,
    "dacl_grant_dcsync": MANUAL_DCSYNC_GRANT,
    "gpo_ldap_attribute_modified": MANUAL_GPO_CHANGE,
    "gpo_gpt_ini_modified": MANUAL_GPO_CHANGE,
    "gpo_sysvol_dir_created": MANUAL_GPO_CHANGE,
    "gpo_sysvol_file_created": MANUAL_GPO_CHANGE,
    "mssql_admin_account_created": MANUAL_MSSQL_ACCOUNT,
    "mssql_postex_account": MANUAL_MSSQL_ACCOUNT,
    "mssql_clr_assembly_loaded": MANUAL_MSSQL_ASSEMBLY,
    "mssql_clr_config_changed": MANUAL_MSSQL_CONFIGURATION,
    "mssql_xp_cmdshell_enabled": MANUAL_MSSQL_CONFIGURATION,
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


#: Who undid a change, as the report's "Performed as" column names it. The
#: revert precedence (``revert_credentials``) is: the client's cleanup account,
#: then a privileged account the assessment verified, then the account that made
#: the change. Keys mirror ``revert_credentials.ROLE_*``.
#: What each revert role is called ("Performed as", the accounts a revert
#: tried). Owned by ``adscan_core.reporting.cleanup_outcome`` so the web CTEM
#: names the roles with the same words.
REVERT_ROLE_PERFORMED_AS: dict[str, str] = REVERT_ROLE_LABELS


def revert_performed_as(role: str | None, principal: str | None) -> str:
    """Render the "Performed as" value: the role, then the account in brackets."""
    label = REVERT_ROLE_PERFORMED_AS.get(str(role or ""), "Assessment account")
    name = str(principal or "").strip()
    return f"{label} ({name})" if name else label


def remediation_template_for_kind(kind: str | None) -> str:
    """Return the raw (placeholder-bearing) remediation template for a kind."""
    raw = str(kind or "").strip()
    return KIND_REMEDIATION_TEMPLATE.get(
        raw, "Manually revert the 'KIND' change on 'TARGET'.".replace("KIND", raw)
    )



# ── The instruction for ONE ledger record (the SSOT every surface reads) ──────
#
# A change left in place for ANY reason (kept by policy or by the operator, a
# revert that failed or could not be confirmed, a revert never attempted, a
# session that died) is disclosed with a runnable instruction built from the
# values the ledger recorded: the object, the trustee, the rights, the previous
# owner, the exact key-credential value. ``remediation_for_entry`` is the one
# place that builds it; the ledger stamps it when a record becomes kept or
# manual, ``finalize()`` stamps it on any record left without one, and the
# report normalizer derives it at display time for workspaces written before
# this existed. A writer that already stored its own rendered command keeps it.

#: Tokens of the raw templates that must never reach a client unfilled when the
#: ledger holds the value. A test asserts a record with full detail renders
#: none of them.
TEMPLATE_TOKENS = (
    "TARGET",
    "OBJECT_DN",
    "TRUSTEE_NAME",
    "TRUSTEE",
    "RIGHTS_NOTE",
    "ORIGINAL_OWNER",
    "GROUP",
    "MEMBER",
)


# The PowerShell building blocks live in ``adscan_core`` so the web CTEM, which
# cannot import the engine, rebuilds a superseded stored instruction with the
# exact same code.
_ps_quote = _cleanup_commands.ps_quote
_is_dn = _cleanup_commands.is_dn
_bare_name = _cleanup_commands.bare_name
_dn_expression = _cleanup_commands.dn_expression


def _netbios(domain: str) -> str:
    first = str(domain or "").strip().split(".", 1)[0]
    return first.upper()


def _trustee_principal(detail: dict, domain: str) -> tuple[str, str]:
    """``(DOMAIN\\\\name, name)`` of the principal an added ACE names.

    A trustee recorded only as a SID is the executing principal on every write
    seam (``run_exploit_write_dacl`` grants to its own SID), so the executor's
    name is the account the client looks for.
    """
    trustee = str(detail.get("trustee_name") or detail.get("trustee") or "").strip()
    if not trustee or trustee.upper().startswith("S-1-"):
        trustee = str(
            detail.get("executor_username") or detail.get("exec_username") or trustee
        ).strip()
    name = _bare_name(trustee)
    if not name:
        return "", ""
    if name.upper().startswith("S-1-"):
        return name, name
    netbios = _netbios(domain)
    return (f"{netbios}\\{name}" if netbios else name), name


def _trustee_sid(detail: dict) -> str:
    """The SID of the principal an added ACE names, when the record holds it."""
    for key in ("trustee_sid", "trustee"):
        value = str(detail.get(key) or "").strip()
        if value.upper().startswith("S-1-"):
            return value
    return ""


def _dacl_ace_instruction(entry_target: str, object_dn: str, detail: dict, domain: str) -> str:
    principal, name = _trustee_principal(detail, domain)
    rights = str(detail.get("rights_type") or "").strip().lower()
    rights_label = {
        "dcsync": "directory-replication (DCSync)",
        "writedacl": "write-DACL",
        "genericall": "full-control (GenericAll)",
    }.get(rights, rights)
    granted = f" It granted {rights_label} rights." if rights_label else ""
    target_label = _bare_name(entry_target) or entry_target or "the object"
    who = principal or "the trustee"
    sid = _trustee_sid(detail)
    if sid:
        # Read back by SID, explicit entries only: exactly what ``dsacls /R``
        # removes, and still correct when the account name no longer resolves.
        check = (
            "  @((Get-Acl \"AD:$dn\").GetAccessRules($true, $false, "
            "[System.Security.Principal.SecurityIdentifier]) | "
            f"Where-Object {{ $_.IdentityReference.Value -eq {_ps_quote(sid)} }}).Count"
        )
    else:
        check = (
            "  @((Get-Acl \"AD:$dn\").Access | Where-Object { $_.IdentityReference -like "
            f"{_ps_quote('*' + (name or 'trustee') + '*')} }}).Count"
        )
    return (
        f"An access control entry for {who} was added to {target_label} during the "
        f"engagement.{granted} The command below removes every entry that account holds "
        "on the object, so confirm it has no legitimate rights there before running it.\n"
        "  Import-Module ActiveDirectory\n"
        f"  $dn = {_dn_expression(entry_target, object_dn)}\n"
        f"  dsacls $dn /R {_ps_quote(who)}\n"
        "Then confirm the entries are gone. The check counts the entries that account "
        "still holds on the object and should print 0.\n"
        f"{check}"
    )


def _key_credential_instruction(entry_target: str, object_dn: str, detail: dict) -> str:
    value = str(detail.get("added_key_credential_value") or "").strip()
    target_label = _bare_name(entry_target) or entry_target or "the object"
    if not value:
        # The exact value was not recorded: read the attribute, then remove the
        # one value added during the engagement (never clear the attribute).
        dn_expr = _dn_expression(entry_target, object_dn)
        return (
            f"{MANUAL_SHADOW_CREDS} Read the values on {target_label}:\n"
            f"  $dn = {dn_expr}\n"
            "  (Get-ADObject -Identity $dn -Properties msDS-KeyCredentialLink)"
            ".'msDS-KeyCredentialLink'\n"
            "Then remove the one added during the engagement, by its exact value:\n"
            "  Set-ADObject -Identity $dn -Remove "
            "@{'msDS-KeyCredentialLink'='<value added during the engagement>'}"
        )
    # A DN-with-binary value ends with the DN of the object that holds it.
    holder_dn = value.rsplit(":", 1)[-1] if value.count(":") >= 3 else ""
    dn_expr = _dn_expression(entry_target, object_dn or holder_dn)
    return (
        f"A key credential (msDS-KeyCredentialLink) was added to {target_label} during "
        "the engagement. Remove that one value, and only that one, so any Windows Hello "
        "for Business or other key the object legitimately holds stays in place:\n"
        f"  $dn = {dn_expr}\n"
        f"  Set-ADObject -Identity $dn -Remove @{{'msDS-KeyCredentialLink'={_ps_quote(value)}}}\n"
        "Then confirm the value is gone:\n"
        "  (Get-ADObject -Identity $dn -Properties msDS-KeyCredentialLink)"
        ".'msDS-KeyCredentialLink'"
    )


def _rbcd_instruction(entry_target: str, object_dn: str, detail: dict) -> str:
    target_label = _bare_name(entry_target) or entry_target or "the computer"
    dn_expr = _dn_expression(entry_target, object_dn or str(detail.get("target_dn") or ""))
    if detail.get("prior_attribute_empty") is True:
        return (
            f"Resource-based constrained delegation was configured on {target_label} "
            "during the engagement, and the attribute was empty before. Clear it:\n"
            f"  Set-ADObject -Identity {dn_expr} "
            "-Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'\n"
            "Then confirm it is empty:\n"
            f"  Get-ADObject -Identity {dn_expr} "
            "-Properties msDS-AllowedToActOnBehalfOfOtherIdentity"
        )
    return (
        f"Resource-based constrained delegation was configured on {target_label} "
        "during the engagement. Review who may delegate to it and remove the account "
        "added during the engagement, keeping any delegation that was there before:\n"
        f"  Get-ADComputer -Identity {_ps_quote(target_label)} "
        "-Properties PrincipalsAllowedToDelegateToAccount\n"
        "If the attribute was empty before the engagement, clear it:\n"
        f"  Set-ADObject -Identity {dn_expr} "
        "-Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'"
    )


def _template_fill(template: str, *, target: str, detail: dict) -> str:
    """Fill the generic tokens of a raw template from the record."""
    target_name = _bare_name(target) or target
    gpo_dn = str(detail.get("gpo_dn") or "")
    gpo_guid = ""
    if "{" in gpo_dn and "}" in gpo_dn:
        gpo_guid = gpo_dn[gpo_dn.index("{") + 1 : gpo_dn.index("}")]
    replacements = (
        ("ORIGINAL_OWNER", str(detail.get("original_owner") or "the original account")),
        ("ORIGINAL_UPN", str(detail.get("original_upn") or detail.get("prior_upn") or "<previous value>")),
        ("ORIGINAL_VALUE", str(detail.get("original_run_value") if detail.get("original_run_value") is not None else "0")),
        ("ORIGINAL_SCRIPT", str(detail.get("original_script_path") or "<previous value>")),
        ("MAPPING", str(detail.get("mapping") or detail.get("altsecurityidentities_value") or "<value added during the engagement>")),
        ("ASSEMBLY", str(detail.get("assembly") or "<assembly>")),
        ("OPTION", str(detail.get("option") or ("xp_cmdshell" if detail.get("host") else "<option>"))),
        ("GPO_GUID", gpo_guid or "<policy GUID>"),
        ("SPN", str(detail.get("spn") or detail.get("vehicle_spn") or "<service principal name>")),
        ("TARGET", str(detail.get("host") or detail.get("account") or target_name) if template in (MANUAL_MSSQL_CONFIGURATION, MANUAL_MSSQL_ASSEMBLY, MANUAL_MSSQL_ACCOUNT) else target_name),
    )
    out = template
    for token, value in replacements:
        out = out.replace(token, value)
    return out


def stored_remediation_is_superseded(entry: dict) -> bool:
    """Whether the instruction stored on a record is a known non-working form.

    A record carrying one is re-rendered from its own values, so a report built
    from an older workspace never hands the client a command that runs cleanly
    and changes nothing. The marker table is shared with the web CTEM
    (``adscan_core.reporting.cleanup_commands``).
    """
    return _cleanup_commands.stored_instruction_is_superseded(entry)


def remediation_for_entry(entry: dict) -> str:
    """The client-facing instruction that removes ONE recorded change.

    Returns the instruction the writer already stored when it has one, and
    otherwise builds it from the record's own values. Never empty: every kind
    resolves to a native procedure, so a change left in place is never listed
    without a way to remove it.

    Args:
        entry: A ledger record (``kind``, ``target``, ``domain``, ``detail``,
            optional ``remediation_command`` / ``remediation_object_dn``).

    Returns:
        A client-safe instruction: prose lines before command lines, no comments.
    """
    if not isinstance(entry, dict):
        return ""
    stored = str(
        entry.get("remediation_command") or entry.get("manual_cleanup_instructions") or ""
    ).strip()
    if stored and not stored_remediation_is_superseded(entry):
        return stored
    kind = str(entry.get("kind") or "").strip()
    target = str(entry.get("target") or "").strip()
    domain = str(entry.get("domain") or "").strip()
    detail = entry.get("detail") if isinstance(entry.get("detail"), dict) else {}
    detail = dict(detail or {})
    object_dn = str(entry.get("remediation_object_dn") or detail.get("target_dn") or "").strip()
    target_domain = str(detail.get("target_domain") or domain).strip()
    reason = str(entry.get("manual_reason") or "").strip().lower()

    # The trustee of an added ACE is the executing principal, whose account
    # lives in the executor's domain (cross-domain writes differ from the
    # object's domain).
    trustee_domain = str(
        detail.get("executor_auth_domain") or detail.get("credential_lookup_domain") or target_domain
    ).strip()
    if kind == "dacl_ace_added":
        return _dacl_ace_instruction(
            str(detail.get("target_object") or target), object_dn, detail, trustee_domain
        )
    if kind == "dacl_grant_dcsync":
        principal, name = _trustee_principal(detail, trustee_domain)
        return (
            MANUAL_DCSYNC_GRANT.replace("TRUSTEE_NAME", name or "trustee")
            .replace("TRUSTEE", principal or "the trustee")
        )
    if kind == "owner_changed":
        return _cleanup_commands.owner_restore_instruction(
            str(detail.get("target_object") or target), object_dn, detail, target_domain
        )
    if kind in ("shadow_credentials_added", "keycredentiallink_added"):
        return _key_credential_instruction(
            str(detail.get("target_object") or detail.get("target_user") or target),
            object_dn,
            detail,
        )
    if kind == "rbcd_delegation_added":
        return _rbcd_instruction(target, object_dn, detail)
    if kind in ("group_membership_added", "group_membership_changed"):
        group = str(detail.get("target_group") or detail.get("group") or "").strip()
        member = str(detail.get("added_user") or detail.get("username") or "").strip()
        if (not group or not member) and "->" in target:
            left, right = (part.strip() for part in target.split("->", 1))
            member = member or left
            group = group or right
        return (
            MANUAL_GROUP_MEMBERSHIP.replace("GROUP", group or "<group>")
            .replace("MEMBER", _bare_name(member) or "<member>")
        )
    if kind == KIND_PASSWORD_CHANGED:
        account = str(detail.get("target_user") or detail.get("target_object") or target)
        template = (
            MANUAL_PASSWORD_RESTORED_FROM_HASH
            if reason == MANUAL_REASON_PASSWORD_RESTORED_FROM_HASH
            else MANUAL_PASSWORD
        )
        return template.replace("TARGET", _bare_name(account) or account)
    if kind == KIND_OBJECT_RESTORED:
        return object_restored_remediation(object_dn or target)
    if kind in HOST_ARTIFACT_KINDS:
        return remote_artifact_remediation(
            remote_path=str(detail.get("remote_path") or detail.get("path") or "") or None,
            host=str(detail.get("host") or "") or None,
        )
    if kind == KIND_ISSUED_CERTIFICATE:
        return issued_certificate_remediation(
            serial=str(detail.get("serial") or "") or None,
            request_id=detail.get("request_id"),
            ca_name=str(detail.get("ca_name") or "") or None,
            ca_host=str(detail.get("ca_host") or "") or None,
            template=str(detail.get("template") or "") or None,
            principal=str(detail.get("principal") or "") or None,
        )
    if kind == KIND_FORGED_CERTIFICATE:
        return forged_certificate_remediation(
            principal=str(detail.get("principal") or detail.get("upn") or "") or None,
            serial=str(detail.get("serial") or "") or None,
            not_after=str(detail.get("not_after") or "") or None,
        )
    if kind == KIND_CA_PRIVATE_KEY_EXFILTRATED:
        return ca_private_key_remediation(
            ca_subject=str(detail.get("ca_subject") or "") or None,
            ca_name=str(detail.get("ca_name") or "") or None,
            ca_host=str(detail.get("ca_host") or "") or None,
        )
    if kind == KIND_CA_BACKUP_SERVICE:
        return ca_backup_service_remediation(
            service_name=str(detail.get("service_name") or "") or None,
            ca_host=str(detail.get("ca_host") or "") or None,
        )
    if kind == KIND_CA_BACKUP_TEMP_PFX:
        return ca_backup_temp_pfx_remediation(
            unc_path=str(detail.get("unc_path") or detail.get("path") or "") or None
        )
    template = KIND_REMEDIATION_TEMPLATE.get(kind)
    if template is None:
        label = kind_display(kind) or "change"
        return (
            f"A change of type '{label}' was made to {target or 'an object'} during the "
            "engagement and is still in place. Review the object with its owner and "
            "restore its previous state:\n"
            f"  Get-ADObject -Identity {_dn_expression(target, object_dn)} -Properties *"
        )
    return _template_fill(template, target=target, detail=detail)


__all__ = [
    "REVERT_ROLE_PERFORMED_AS",
    "TEMPLATE_TOKENS",
    "remediation_for_entry",
    "stored_remediation_is_superseded",
    "MANUAL_REASON_ORIGINAL_SECRET_UNKNOWN",
    "MANUAL_REASON_PASSWORD_RESTORED_FROM_HASH",
    "MANUAL_PASSWORD_RESTORED_FROM_HASH",
    "revert_performed_as",
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
    "MANUAL_REASON_REVERT_UNCONFIRMED",
    "RETRYABLE_REVERT_REASONS",
    "MANUAL_REASON_NO_PRIVILEGED_CREDENTIAL",
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
    "MANUAL_PASSWORD_PENDING_LOGON",
    "KIND_PASSWORD_CHANGED",
    "KIND_SPN_ADDED",
    "KIND_DACL_ACE_ADDED",
    "KIND_OWNER_CHANGED",
    "KIND_GROUP_MEMBERSHIP_ADDED",
    "MANUAL_GROUP_MEMBERSHIP",
    "MANUAL_RBCD",
    "MANUAL_KEYCREDENTIALLINK",
    "MANUAL_MACHINE_ACCOUNT",
    "MANUAL_USER_ACCOUNT",
    "MANUAL_SCHEDULED_TASK",
    "MANUAL_LOGON_SCRIPT_PATH",
    "MANUAL_RODC_PRP",
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
    "dacl_ace_remediation",
    "KIND_REMEDIATION_TEMPLATE",
    "remediation_template_for_kind",
    "KIND_REMOTE_FILE_WRITTEN",
    "KIND_REMOTE_FILE_UPLOADED",
    "HOST_ARTIFACT_KINDS",
    "kind_is_host_artifact",
    "MANUAL_REMOTE_ARTIFACT",
    "remote_artifact_remediation",
]
