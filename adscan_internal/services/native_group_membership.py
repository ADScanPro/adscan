"""Native LDAP helpers for RID-based AD group membership lookups."""

from __future__ import annotations

from typing import Any, Literal

from adscan_internal import telemetry
from adscan_internal.rich_output import mark_sensitive, print_info_debug
from adscan_internal.services.ldap_query_service import query_shell_ldap_attribute_values

_LDAP_MATCHING_RULE_IN_CHAIN = "1.2.840.113556.1.4.1941"

# Built-in domain group RIDs that always carry a fixed, language-independent
# sAMAccountName. Used as a last-resort filter when the domain SID cannot be
# resolved, so a missing SID degrades to a name-based lookup instead of the
# opaque ``inappropriateMatching`` rejection raised by the constructed
# ``primaryGroupToken`` attribute.
_WELL_KNOWN_GROUP_SAM_NAMES: dict[int, str] = {
    512: "Domain Admins",
    513: "Domain Users",
    514: "Domain Guests",
    515: "Domain Computers",
    516: "Domain Controllers",
    518: "Schema Admins",
    519: "Enterprise Admins",
    520: "Group Policy Creator Owners",
    521: "Read-only Domain Controllers",
    525: "Protected Users",
    526: "Key Admins",
    527: "Enterprise Key Admins",
}


def _resolve_group_dn_filter_by_rid(shell: Any, domain: str, rid_value: int) -> str | None:
    """Build a group-DN-lookup LDAP filter for ``rid`` that AD will accept.

    ``primaryGroupToken`` is a CONSTRUCTED attribute: AD computes it per object
    and rejects any search filter that references it
    (``ERROR_DS_FILTER_USES_CONTRUCTED_ATTRS`` / ``inappropriateMatching``).
    The correct, stored attribute to match a group on is ``objectSid``, built as
    ``<domain_sid>-<rid>`` and encoded as raw LDAP filter bytes.

    Resolution order:
      1. ``(&(objectCategory=group)(objectSid=<encoded domain_sid-rid>))`` — the
         canonical, exact match, preferred whenever the domain SID is known.
      2. ``(&(objectCategory=group)(sAMAccountName=<well-known name>))`` — a
         name-based fallback for built-in RIDs when the domain SID is missing.
      3. ``None`` — neither is available; the caller surfaces a clear error
         instead of emitting a filter AD will reject.
    """
    from adscan_internal.services.attack_graph_service import _resolve_domain_sid
    from adscan_internal.services.exploitation.acl import _sid_to_ldap_filter_bytes

    marked_domain = mark_sensitive(domain, "domain")

    domain_sid: str | None = None
    try:
        snapshot: dict[str, Any] = {}
        domain_sid = _resolve_domain_sid(shell, domain, snapshot)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        domain_sid = None

    if domain_sid:
        group_sid = f"{domain_sid}-{rid_value}"
        encoded = _sid_to_ldap_filter_bytes(group_sid)
        if encoded:
            return f"(&(objectCategory=group)(objectSid={encoded}))"
        print_info_debug(
            f"[ldap-group-rid] domain SID {mark_sensitive(domain_sid, 'user')} for "
            f"{marked_domain} could not be encoded for RID {rid_value}; trying name fallback."
        )

    well_known = _WELL_KNOWN_GROUP_SAM_NAMES.get(rid_value)
    if well_known:
        print_info_debug(
            f"[ldap-group-rid] domain SID unavailable for {marked_domain}; resolving group "
            f"RID {rid_value} by well-known sAMAccountName '{well_known}'."
        )
        return f"(&(objectCategory=group)(sAMAccountName={escape_ldap_filter_value(well_known)}))"

    print_info_debug(
        f"[ldap-group-rid] cannot build a valid group filter for RID {rid_value} in "
        f"{marked_domain}: domain SID unavailable and RID is not a built-in group."
    )
    return None


def escape_ldap_filter_value(value: str) -> str:
    """Escape a value for use inside an LDAP filter assertion."""
    return (
        str(value or "")
        .replace("\\", r"\5c")
        .replace("*", r"\2a")
        .replace("(", r"\28")
        .replace(")", r"\29")
        .replace("\x00", r"\00")
    )


def _object_filter(kind: Literal["user", "computer", "principal"]) -> str:
    if kind == "user":
        return "(objectCategory=person)(objectClass=user)"
    if kind == "computer":
        return "(objectCategory=computer)"
    return "(|(objectCategory=person)(objectClass=user)(objectCategory=computer))"


def resolve_enabled_group_members_by_rid_native(
    shell: Any,
    domain: str,
    rid: int,
    *,
    member_kind: Literal["user", "computer", "principal"] = "user",
    operation_name: str | None = None,
) -> list[str] | None:
    """Return enabled direct/recursive members of a domain group RID via native LDAP."""
    rid_value = int(rid)
    marked_domain = mark_sensitive(domain, "domain")
    group_dn_filter = _resolve_group_dn_filter_by_rid(shell, domain, rid_value)
    if group_dn_filter is None:
        print_info_debug(
            f"[ldap-group-rid] no resolvable group filter for RID {rid_value} in "
            f"{marked_domain}; falling back to primaryGroupID-only member lookup."
        )
        group_dns: list[Any] | None = []
    else:
        group_dns = query_shell_ldap_attribute_values(
            shell,
            domain=domain,
            ldap_filter=group_dn_filter,
            attribute="distinguishedName",
            prefer_kerberos=True,
            allow_ntlm_fallback=True,
            operation_name=operation_name or f"group RID {rid_value} DN lookup",
        )
        if group_dns is None:
            return None

    member_filters = [f"(primaryGroupID={rid_value})"]
    for group_dn in group_dns:
        group_dn = str(group_dn or "").strip()
        if not group_dn:
            continue
        escaped_dn = escape_ldap_filter_value(group_dn)
        member_filters.append(
            f"(memberOf:{_LDAP_MATCHING_RULE_IN_CHAIN}:={escaped_dn})"
        )

    if len(member_filters) == 1:
        print_info_debug(
            f"[ldap-group-rid] group RID {rid_value} DN unresolved for "
            f"{marked_domain}; trying primaryGroupID only."
        )

    object_filter = _object_filter(member_kind)
    members = query_shell_ldap_attribute_values(
        shell,
        domain=domain,
        ldap_filter=(
            f"(&{object_filter}"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
            f"(|{''.join(member_filters)}))"
        ),
        attribute="sAMAccountName",
        prefer_kerberos=True,
        allow_ntlm_fallback=True,
        operation_name=operation_name or f"group RID {rid_value} member lookup",
    )
    if members is None:
        return None

    normalized = [
        str(member).strip().lower()
        for member in members
        if str(member or "").strip()
    ]
    return sorted(set(normalized), key=str.lower)


def is_principal_member_of_rid_native(
    shell: Any,
    domain: str,
    principal: str,
    rid: int,
    *,
    operation_name: str | None = None,
) -> bool | None:
    """Return whether a user/computer is recursively member of a domain group RID."""
    rid_value = int(rid)
    escaped_principal = escape_ldap_filter_value(str(principal or "").strip())
    if not escaped_principal:
        return None

    try:
        dns = query_shell_ldap_attribute_values(
            shell,
            domain=domain,
            ldap_filter=(
                f"(&{_object_filter('principal')}(sAMAccountName={escaped_principal}))"
            ),
            attribute="distinguishedName",
            prefer_kerberos=True,
            allow_ntlm_fallback=True,
            operation_name=operation_name or f"principal RID {rid_value} DN lookup",
        )
        primary_group_ids = query_shell_ldap_attribute_values(
            shell,
            domain=domain,
            ldap_filter=(
                f"(&{_object_filter('principal')}(sAMAccountName={escaped_principal}))"
            ),
            attribute="primaryGroupID",
            prefer_kerberos=True,
            allow_ntlm_fallback=True,
            operation_name=operation_name
            or f"principal RID {rid_value} primary group lookup",
        )
        if dns is None or primary_group_ids is None:
            return None
        if any(str(value).strip() == str(rid_value) for value in primary_group_ids):
            return True
        principal_dn = str(dns[0]).strip() if dns else ""
        if not principal_dn:
            return False
        escaped_dn = escape_ldap_filter_value(principal_dn)
        group_sids = query_shell_ldap_attribute_values(
            shell,
            domain=domain,
            ldap_filter=(
                "(&(objectCategory=group)"
                f"(member:{_LDAP_MATCHING_RULE_IN_CHAIN}:={escaped_dn}))"
            ),
            attribute="objectSid",
            prefer_kerberos=True,
            allow_ntlm_fallback=True,
            operation_name=operation_name or f"principal RID {rid_value} group lookup",
        )
        if group_sids is None:
            return None
        target_suffix = f"-{rid_value}"
        return any(str(sid).strip().upper().endswith(target_suffix) for sid in group_sids)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        marked_domain = mark_sensitive(domain, "domain")
        marked_principal = mark_sensitive(principal, "user")
        print_info_debug(
            f"[ldap-group-rid] native RID {rid_value} membership check failed for "
            f"{marked_principal}@{marked_domain}: {mark_sensitive(str(exc), 'detail')}"
        )
        return None

