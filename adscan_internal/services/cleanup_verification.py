"""Fail-closed verify-the-undo re-reads for environment-change rollback.

After a cleanup service reverts an AD change (removes a group member, removes a
DACL ACE, restores an owner, clears an SPN, removes a KeyCredentialLink, clears
RBCD, deletes a machine account), it MUST re-read the object to confirm the
change is actually gone before the ledger may reach ``reverted_confirmed``. A
revert call returning ``success=True`` is NOT proof — only a confirming re-read
is.

Every verifier here:
- reads through the LDAP transport SSOT (``ADscanLDAPConnection``) — never raw
  badldap — reusing the SAME connection the revert used;
- is **fail-closed**: any exception, timeout, or missing object means the revert
  could not be confirmed, so the verifier returns ``False`` and the caller marks
  the change ``manual_required``, never silently ``reverted``.

This is the legal-critical default: an unverifiable revert is reported as
manual, not as done.
"""

from __future__ import annotations

from typing import Any

from adscan_internal import telemetry
from adscan_internal.rich_output import mark_sensitive, print_info_debug

# Re-export the canonical SD-flags control name lazily to avoid a hard import
# cycle at module load; resolved inside the functions that need it.

VERIFY_GROUP_MEMBERSHIP = "group_membership_reread"
VERIFY_DACL_ACE = "dacl_reread"
VERIFY_OWNER = "owner_sid_reread"
VERIFY_SPN = "spn_reread"
VERIFY_KEYCREDENTIAL = "keycredentiallink_reread"
VERIFY_RBCD = "rbcd_reread"
VERIFY_MACHINE_ACCOUNT = "machine_account_reread"


def _domain_dn(conn: Any) -> str:
    """Return the connection's default naming context DN (best-effort)."""
    try:
        return str(getattr(conn, "domain_dn", "") or "")
    except Exception:  # noqa: BLE001
        return ""


def _escape_filter_value(value: str) -> str:
    """Escape an LDAP filter literal (RFC 4515)."""
    out = []
    for ch in str(value or ""):
        if ch == "\\":
            out.append("\\5c")
        elif ch == "*":
            out.append("\\2a")
        elif ch == "(":
            out.append("\\28")
        elif ch == ")":
            out.append("\\29")
        elif ch == "\x00":
            out.append("\\00")
        else:
            out.append(ch)
    return "".join(out)


def _looks_like_dn(value: str) -> bool:
    v = str(value or "").strip().lower()
    return v.startswith(("cn=", "ou=", "dc=", "uid="))


def _resolve_object_dn(conn: Any, identity: str, *, group: bool = False) -> str | None:
    """Resolve a DN, sAMAccountName, CN, or SID to a DN via the live connection."""
    value = str(identity or "").strip()
    if not value:
        return None
    if _looks_like_dn(value):
        return value
    escaped = _escape_filter_value(value)
    base = _domain_dn(conn)
    if not base:
        return None
    if group:
        ldap_filter = (
            f"(&(objectClass=group)(|(sAMAccountName={escaped})(cn={escaped})(name={escaped})))"
        )
    else:
        ldap_filter = (
            "(&(|(objectClass=user)(objectClass=computer)(objectClass=group))"
            f"(|(sAMAccountName={escaped})(cn={escaped})(name={escaped})(objectSid={escaped})))"
        )
    conn.search(
        search_base=base,
        search_filter=ldap_filter,
        attributes=["distinguishedName"],
    )
    entries = list(getattr(conn, "entries", []) or [])
    if not entries:
        return None
    return entries[0].dn or None


def _read_attr_values(conn: Any, dn: str, attr: str, *, controls: Any = None) -> list[Any]:
    """BASE-read one attribute on a DN; return its value list (possibly empty)."""
    conn.search(
        search_base=dn,
        search_filter="(objectClass=*)",
        attributes=[attr],
        search_scope="BASE",
        controls=controls,
    )
    entries = list(getattr(conn, "entries", []) or [])
    if not entries:
        return []
    entry = entries[0]
    decoded = entry.entry_attributes_as_dict.get(attr)
    if decoded:
        return list(decoded)
    raw = entry.entry_raw_attributes.get(attr)
    return list(raw or [])


def _norm(value: Any) -> str:
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", "replace").strip().lower()
        except Exception:  # noqa: BLE001
            return repr(value).strip().lower()
    return str(value or "").strip().lower()


# ── Per-kind verifiers (all fail-closed: any error / unknown → False) ──────────


def verify_group_membership_removed(conn: Any, *, group: str, member: str) -> bool:
    """Confirm ``member`` is NO LONGER in ``group`` by re-reading the group.

    Args:
        conn: A live ``ADscanLDAPConnection``.
        group: Group identity (DN, sAMAccountName, or CN).
        member: Member identity (DN, sAMAccountName, or CN) that was removed.

    Returns:
        True only when the re-read group's ``member`` list does not contain the
        member's DN. False on any error / unresolvable object (fail-closed).
    """
    try:
        group_dn = _resolve_object_dn(conn, group, group=True)
        if not group_dn:
            return False
        member_dn = _resolve_object_dn(conn, member, group=False)
        members = _read_attr_values(conn, group_dn, "member")
        member_norms = {_norm(m) for m in members}
        if member_dn and _norm(member_dn) in member_norms:
            return False
        # Also defend against a member stored by sAMAccountName/CN form.
        target_token = _norm(member)
        for m in member_norms:
            if target_token and target_token in m:
                return False
        return True
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"cleanup-verify group_membership re-read failed "
            f"({mark_sensitive(str(member), 'user')}): {exc}"
        )
        return False


def verify_dacl_ace_removed(conn: Any, *, target: str, trustee_sid: str) -> bool:
    """Confirm no DACL ACE for ``trustee_sid`` remains on ``target``'s SD.

    Re-reads ``nTSecurityDescriptor`` with the DACL SD-flags control and asserts
    no ACE's trustee matches ``trustee_sid``. Fail-closed.
    """
    try:
        from adscan_internal.services.ldap_transport_service import (  # noqa: PLC0415
            SD_FLAGS_DACL_CONTROL,
        )
        from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR  # noqa: PLC0415

        target_dn = _resolve_object_dn(conn, target, group=False)
        if not target_dn:
            return False
        wanted = str(trustee_sid or "").strip().upper()
        if not wanted:
            return False
        raw = _read_attr_values(
            conn, target_dn, "nTSecurityDescriptor", controls=SD_FLAGS_DACL_CONTROL
        )
        if not raw or not isinstance(raw[0], bytes):
            # No SD returned — cannot confirm removal. Fail-closed.
            return False
        sd = SECURITY_DESCRIPTOR.from_bytes(raw[0])
        if sd.Dacl is None:
            return True
        for ace in sd.Dacl.aces:
            ace_sid = str(getattr(ace, "Sid", "") or "").strip().upper()
            if ace_sid and ace_sid == wanted:
                return False
        return True
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(f"cleanup-verify dacl_ace re-read failed: {exc}")
        return False


def verify_owner_restored(conn: Any, *, target: str, original_owner_sid: str) -> bool:
    """Confirm ``target``'s owner SID equals ``original_owner_sid``. Fail-closed."""
    try:
        from adscan_internal.services.ldap_transport_service import (  # noqa: PLC0415
            SD_FLAGS_OWNER_CONTROL,
        )
        from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR  # noqa: PLC0415

        target_dn = _resolve_object_dn(conn, target, group=False)
        if not target_dn:
            return False
        wanted = str(original_owner_sid or "").strip().upper()
        if not wanted:
            return False
        raw = _read_attr_values(
            conn, target_dn, "nTSecurityDescriptor", controls=SD_FLAGS_OWNER_CONTROL
        )
        if not raw or not isinstance(raw[0], bytes):
            return False
        sd = SECURITY_DESCRIPTOR.from_bytes(raw[0])
        current_owner = str(getattr(sd, "Owner", "") or "").strip().upper()
        return bool(current_owner) and current_owner == wanted
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(f"cleanup-verify owner re-read failed: {exc}")
        return False


def verify_spn_removed(conn: Any, *, target: str, spn: str) -> bool:
    """Confirm ``spn`` is absent from ``target``'s servicePrincipalName. Fail-closed."""
    try:
        target_dn = _resolve_object_dn(conn, target, group=False)
        if not target_dn:
            return False
        wanted = _norm(spn)
        if not wanted:
            return False
        values = _read_attr_values(conn, target_dn, "servicePrincipalName")
        return all(_norm(v) != wanted for v in values)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(f"cleanup-verify spn re-read failed: {exc}")
        return False


def verify_keycredential_removed(conn: Any, *, target: str, key_credential_value: str) -> bool:
    """Confirm the added msDS-KeyCredentialLink value is gone from ``target``.

    Fail-closed. When ``key_credential_value`` is empty we cannot identify which
    value to confirm absent, so we conservatively return False (manual review).
    """
    try:
        target_dn = _resolve_object_dn(conn, target, group=False)
        if not target_dn:
            return False
        wanted = _norm(key_credential_value)
        if not wanted:
            return False
        values = _read_attr_values(conn, target_dn, "msDS-KeyCredentialLink")
        return all(wanted not in _norm(v) for v in values)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(f"cleanup-verify keycredential re-read failed: {exc}")
        return False


def verify_rbcd_removed(conn: Any, *, target_dn: str, delegate_sid: str | None = None) -> bool:
    """Confirm msDS-AllowedToActOnBehalfOfOtherIdentity no longer grants delegate.

    When ``delegate_sid`` is provided, asserts that SID is not present in the
    re-read SD's DACL. When not provided, asserts the attribute is empty/absent.
    Fail-closed.
    """
    try:
        dn = str(target_dn or "").strip()
        if not dn:
            return False
        raw = _read_attr_values(conn, dn, "msDS-AllowedToActOnBehalfOfOtherIdentity")
        if not raw:
            return True  # attribute cleared entirely
        sd_bytes = raw[0] if isinstance(raw[0], bytes) else None
        if sd_bytes is None:
            # A non-empty non-bytes value means something is still set.
            return False
        if not delegate_sid:
            # Attribute should have been cleared; a present SD means not removed.
            return False
        from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR  # noqa: PLC0415

        sd = SECURITY_DESCRIPTOR.from_bytes(sd_bytes)
        wanted = str(delegate_sid or "").strip().upper()
        if sd.Dacl is None:
            return True
        for ace in sd.Dacl.aces:
            ace_sid = str(getattr(ace, "Sid", "") or "").strip().upper()
            if ace_sid and ace_sid == wanted:
                return False
        return True
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(f"cleanup-verify rbcd re-read failed: {exc}")
        return False


def verify_machine_account_gone(conn: Any, *, sam_account_name: str) -> bool:
    """Confirm a machine account is deleted OR disabled. Fail-closed.

    A low-privilege creator may only be able to DISABLE (not delete) the account;
    both outcomes neutralize it, so either deletion or ACCOUNTDISABLE counts as a
    confirmed revert.
    """
    try:
        sam = str(sam_account_name or "").strip()
        if not sam:
            return False
        base = _domain_dn(conn)
        if not base:
            return False
        escaped = _escape_filter_value(sam)
        conn.search(
            search_base=base,
            search_filter=f"(&(objectClass=computer)(sAMAccountName={escaped}))",
            attributes=["userAccountControl", "distinguishedName"],
        )
        entries = list(getattr(conn, "entries", []) or [])
        if not entries:
            return True  # object deleted
        uac_values = entries[0].entry_attributes_as_dict.get("userAccountControl") or []
        try:
            uac = int(str(uac_values[0])) if uac_values else 0
        except (ValueError, TypeError):
            uac = 0
        return bool(uac & 0x2)  # ACCOUNTDISABLE
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"cleanup-verify machine_account re-read failed "
            f"({mark_sensitive(str(sam_account_name), 'user')}): {exc}"
        )
        return False


__all__ = [
    "VERIFY_GROUP_MEMBERSHIP",
    "VERIFY_DACL_ACE",
    "VERIFY_OWNER",
    "VERIFY_SPN",
    "VERIFY_KEYCREDENTIAL",
    "VERIFY_RBCD",
    "VERIFY_MACHINE_ACCOUNT",
    "verify_group_membership_removed",
    "verify_dacl_ace_removed",
    "verify_owner_restored",
    "verify_spn_removed",
    "verify_keycredential_removed",
    "verify_rbcd_removed",
    "verify_machine_account_gone",
]
