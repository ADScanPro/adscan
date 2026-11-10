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


#: Stored instructions an earlier version wrote that do not do what they say,
#: per kind, as lower-case substrings.
_SUPERSEDED_MARKERS: dict[str, tuple[str, ...]] = {
    # The owner restore through ``Set-ADObject -Replace @{nTSecurityDescriptor}``
    # left the owner unchanged on a domain controller (lab, 2026-11-06).
    KIND_OWNER_CHANGED: ("-replace @{ntsecuritydescriptor",),
}


def _stored(entry: Mapping[str, Any]) -> str:
    return str(
        entry.get("remediation_command") or entry.get("manual_cleanup_instructions") or ""
    )


def stored_instruction_is_superseded(entry: Mapping[str, Any]) -> bool:
    """Whether the instruction stored on a ledger record is a known non-working form."""
    if not isinstance(entry, Mapping):
        return False
    markers = _SUPERSEDED_MARKERS.get(str(entry.get("kind") or "").strip())
    if not markers:
        return False
    stored = _stored(entry).lower()
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
