"""Native PowerShell building blocks for the client's cleanup instructions.

The engine's cleanup taxonomy builds every instruction from these, and the web
CTEM (which cannot import the engine) calls :func:`effective_stored_instruction`
on each ingested ledger record, so a stored instruction an earlier version
wrote that does not work is replaced by the working one on every surface.

Stdlib only: the web backend bundles ``adscan_core``.
"""

from __future__ import annotations

from typing import Any, Mapping

__all__ = [
    "KIND_OWNER_CHANGED",
    "ps_quote",
    "is_dn",
    "bare_name",
    "dn_expression",
    "adsi_path",
    "owner_restore_instruction",
    "KIND_MSSQL_XP_CMDSHELL_ENABLED",
    "mssql_xp_cmdshell_instruction",
    "stored_instruction_is_superseded",
    "effective_stored_instruction",
]

#: Ledger ``kind`` of an object whose owner the assessment changed (mirrors
#: ``cleanup_taxonomy.KIND_OWNER_CHANGED``).
KIND_OWNER_CHANGED = "owner_changed"


def ps_quote(value: str) -> str:
    """A PowerShell single-quoted literal (embedded quotes doubled)."""
    return "'" + str(value or "").replace("'", "''") + "'"


def is_dn(value: str) -> bool:
    """Whether a value reads as a distinguished name."""
    return "=" in str(value or "") and "," in str(value or "")


def bare_name(value: str) -> str:
    """``DOMAIN\\\\name`` / ``name@realm`` reduced to the account name."""
    name = str(value or "").strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name.strip()


def dn_expression(target: str, object_dn: str = "") -> str:
    """A PowerShell expression that yields the object's distinguished name.

    The ledger frequently records a sAMAccountName (``KingsGuard``), and the
    directory cmdlets need a DN, so a bare name is resolved inline rather than
    left for the client to look up.
    """
    if is_dn(object_dn):
        return ps_quote(object_dn)
    if is_dn(target):
        return ps_quote(target)
    name = bare_name(target)
    return (
        f"(Get-ADObject -LDAPFilter {ps_quote(f'(sAMAccountName={name})')})"
        ".DistinguishedName"
    )


def adsi_path(domain: str) -> str:
    """The ``[ADSI]`` path of ``$dn``, bound to the object's domain when known.

    Naming the domain makes the bind locate a domain controller of THAT domain,
    so the instruction also works from a host joined to another domain of the
    forest.
    """
    server = str(domain or "").strip()
    return f'"LDAP://{server}/$dn"' if server else '"LDAP://$dn"'


def owner_restore_instruction(
    entry_target: str, object_dn: str, detail: Mapping[str, Any], domain: str = ""
) -> str:
    """Restore a changed owner, then read the owner back.

    The write goes through ``DirectoryEntry`` with ``SecurityMasks = Owner``,
    which sends the LDAP SD-flags control for the owner alone, so the DACL is
    left as it is. ``Set-ADObject -Replace @{nTSecurityDescriptor=...}`` is NOT
    used: on a lab domain controller it returned without error and left the
    owner unchanged (2026-11-06).
    """
    original_sid = str(detail.get("original_owner_sid") or "").strip()
    original_name = str(detail.get("original_owner") or "").strip()
    target_label = bare_name(entry_target) or entry_target or "the object"
    if original_sid:
        identity_type = "[System.Security.Principal.SecurityIdentifier]"
        owner_value = original_sid
        owner_text = f"its previous owner ({original_sid})"
        expected = original_sid
    elif original_name:
        identity_type = "[System.Security.Principal.NTAccount]"
        owner_value = original_name
        owner_text = f"its previous owner ({original_name})"
        expected = original_name
    else:
        identity_type = "[System.Security.Principal.NTAccount]"
        owner_value = "<previous owner, from your change records>"
        owner_text = "its previous owner"
        expected = "the previous owner"
    path = adsi_path(domain)
    return (
        f"The owner of {target_label} was changed during the engagement. Set it back to "
        f"{owner_text}. The commands below write the owner only, so the object's "
        "permissions stay as they are. Run them as a domain administrator.\n"
        "  Import-Module ActiveDirectory\n"
        f"  $dn = {dn_expression(entry_target, object_dn)}\n"
        f"  $entry = [ADSI]{path}\n"
        "  $entry.psbase.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Owner\n"
        f"  $entry.psbase.ObjectSecurity.SetOwner({identity_type}{ps_quote(owner_value)})\n"
        "  $entry.psbase.CommitChanges()\n"
        f"Then confirm the owner. The check reads it back and should print {expected}.\n"
        f"  ([ADSI]{path}).psbase.ObjectSecurity.GetOwner({identity_type}).Value"
    )


#: Ledger ``kind`` of an ``xp_cmdshell`` the assessment turned on.
KIND_MSSQL_XP_CMDSHELL_ENABLED = "mssql_xp_cmdshell_enabled"

#: What a command carries in place of a value the assessment did not record.
_UNRECORDED_VALUE = "<value before the change>"


def _recorded_setting(value: Any) -> tuple[str, bool]:
    """A recorded ``sp_configure`` value as ``(text for the command, recorded)``."""
    if value is None:
        return _UNRECORDED_VALUE, False
    if isinstance(value, bool):
        return ("1" if value else "0"), True
    text = str(value).strip().lower()
    if text in ("1", "true"):
        return "1", True
    if text in ("0", "false"):
        return "0", True
    return _UNRECORDED_VALUE, False


def mssql_xp_cmdshell_instruction(entry_target: str, detail: Mapping[str, Any]) -> str:
    """Put back BOTH settings an ``xp_cmdshell`` enable changed, then read them.

    Turning ``xp_cmdshell`` on also turns ``show advanced options`` on, so the
    instruction restores each to the value the ledger recorded before the
    change. A value that was not recorded (a linked server, or a read that
    failed) is never assumed: the command carries a fill-in token and the text
    says what the product default is.

    Args:
        entry_target: The ledger record's ``target`` (the instance).
        detail: The record's ``detail`` (``host``, ``linked_server``,
            ``original_xp_cmdshell``, ``original_advanced_options``).

    Returns:
        Prose lines followed by indented commands, no comments.
    """
    linked = str(detail.get("linked_server") or "").strip()
    host = str(detail.get("host") or "").strip()
    instance = linked or host or bare_name(entry_target) or str(entry_target or "").strip()
    instance = instance or "<SQL Server instance>"
    where = f"{linked}, a linked server reached through {host}" if linked and host else instance
    xp_value, xp_known = _recorded_setting(detail.get("original_xp_cmdshell"))
    adv_value, adv_known = _recorded_setting(detail.get("original_advanced_options"))
    notes: list[str] = []
    if not xp_known and not adv_known:
        notes.append(
            "ADscan did not record either value before the change. The SQL Server default "
            "for both is 0."
        )
    elif not xp_known:
        notes.append(
            "ADscan did not record the value of 'xp_cmdshell' before the change. The SQL "
            "Server default is 0."
        )
    elif not adv_known:
        notes.append(
            "ADscan did not record the value of 'show advanced options' before the change. "
            "The SQL Server default is 0."
        )
    if adv_known and adv_value == "1":
        intro = (
            f"'xp_cmdshell' was enabled on {where} during the engagement. 'show advanced "
            "options' was already on before the change and stays on. Set 'xp_cmdshell' back "
            f"to its value before the change ({xp_value})."
        )
        query = f"EXEC sp_configure 'xp_cmdshell', {xp_value}; RECONFIGURE;"
    else:
        intro = (
            f"Two SQL Server settings were changed on {where} during the engagement: "
            "'xp_cmdshell' was enabled, and 'show advanced options' was turned on to allow "
            "it. Set both back to their values before the change: 'xp_cmdshell' to "
            f"{xp_value} and 'show advanced options' to {adv_value}."
        )
        query = (
            "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; "
            f"EXEC sp_configure 'xp_cmdshell', {xp_value}; RECONFIGURE; "
            f"EXEC sp_configure 'show advanced options', {adv_value}; RECONFIGURE;"
        )
    lines = [" ".join([intro, *notes, "Run this as a sysadmin."])]
    lines.append(f'  Invoke-Sqlcmd -ServerInstance {ps_quote(instance)} -Query "{query}"')
    lines.append("Then confirm both running values.")
    lines.append(
        f"  Invoke-Sqlcmd -ServerInstance {ps_quote(instance)} -Query "
        "\"SELECT name, value_in_use FROM sys.configurations WHERE name IN "
        "('xp_cmdshell', 'show advanced options');\""
    )
    return "\n".join(lines)


#: Stored instructions an earlier version wrote that do not do what they say,
#: per kind, as lower-case substrings.
_SUPERSEDED_MARKERS: dict[str, tuple[str, ...]] = {
    # The owner restore through ``Set-ADObject -Replace @{nTSecurityDescriptor}``
    # left the owner unchanged on a domain controller (lab, 2026-11-06).
    KIND_OWNER_CHANGED: ("-replace @{ntsecuritydescriptor",),
}


#: What a stored instruction of a kind must mention to be complete, as
#: lower-case substrings. One that lacks any of them is rebuilt.
_REQUIRED_MARKERS: dict[str, tuple[str, ...]] = {
    # Earlier versions restored 'xp_cmdshell' alone, to an assumed 0, and left
    # 'show advanced options' as the assessment had set it.
    KIND_MSSQL_XP_CMDSHELL_ENABLED: ("show advanced options",),
}


def _stored(entry: Mapping[str, Any]) -> str:
    return str(
        entry.get("remediation_command") or entry.get("manual_cleanup_instructions") or ""
    )


def stored_instruction_is_superseded(entry: Mapping[str, Any]) -> bool:
    """Whether the instruction stored on a ledger record is a known non-working form."""
    if not isinstance(entry, Mapping):
        return False
    kind = str(entry.get("kind") or "").strip()
    stored = _stored(entry).lower()
    if not stored.strip():
        return False
    required = _REQUIRED_MARKERS.get(kind)
    if required and any(marker not in stored for marker in required):
        return True
    markers = _SUPERSEDED_MARKERS.get(kind)
    if not markers:
        return False
    return any(marker in stored for marker in markers)


def _rebuild(entry: Mapping[str, Any]) -> str:
    detail = entry.get("detail") if isinstance(entry.get("detail"), Mapping) else {}
    detail = detail or {}
    kind = str(entry.get("kind") or "").strip()
    if kind == KIND_OWNER_CHANGED:
        target = str(detail.get("target_object") or entry.get("target") or "")
        object_dn = str(entry.get("remediation_object_dn") or detail.get("target_dn") or "")
        domain = str(detail.get("target_domain") or entry.get("domain") or "")
        return owner_restore_instruction(target, object_dn, detail, domain)
    if kind == KIND_MSSQL_XP_CMDSHELL_ENABLED:
        return mssql_xp_cmdshell_instruction(str(entry.get("target") or ""), detail)
    return ""


def effective_stored_instruction(entry: Mapping[str, Any]) -> str:
    """The stored instruction of a record, rebuilt when it is a superseded form.

    Args:
        entry: A persisted ledger record.

    Returns:
        The stored instruction, or the working one rebuilt from the record's
        own values when the stored one is known not to work. Empty when the
        record stores nothing.
    """
    if not isinstance(entry, Mapping):
        return ""
    if stored_instruction_is_superseded(entry):
        rebuilt = _rebuild(entry)
        if rebuilt:
            return rebuilt
    return _stored(entry)
