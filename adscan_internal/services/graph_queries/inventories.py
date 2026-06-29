from __future__ import annotations

from typing import Any

from adscan_internal.services.graph_queries.filters import (
    STALE_DAYS_DEFAULT,
    domain_matches,
    is_enabled,
    is_stale,
)
from adscan_internal.services.graph_queries.tier_classification import (
    is_tier0_or_high_value,
)


def _nodes_props(graph: dict[str, Any], kind: str, domain: str) -> list[dict[str, Any]]:
    return [
        node.get("properties") or {}
        for node in (graph.get("nodes") or {}).values()
        if node.get("kind") == kind and domain_matches(node, domain)
    ]


def _prop_enabled(props: dict[str, Any]) -> bool:
    v = props.get("enabled")
    return bool(v) if v is not None else True


def _is_managed_service_account(props: dict[str, Any]) -> bool:
    """Return True when a node is a (group) managed service account.

    Detects gMSAs/sMSAs across the two shapes the data can take:

    * Native graph nodes — the LDAP collector sets ``is_gmsa=True`` /
      ``account_type="gmsa"`` and a ``distinguishedname`` under
      ``CN=Managed Service Accounts``.  ``objectClass`` is NOT carried into the
      graph properties, so the ``is_gmsa`` / DN signals are what fire here.
    * Raw LDAP-shaped props — an ``objectClass`` list still carrying
      ``msDS-GroupManagedServiceAccount`` / ``msDS-ManagedServiceAccount``.
    """
    if bool(props.get("is_gmsa")):
        return True
    if str(props.get("account_type") or "").strip().casefold() in {"gmsa", "smsa"}:
        return True

    distinguished_name = str(props.get("distinguishedname") or "").casefold()
    if "cn=managed service accounts," in distinguished_name:
        return True

    object_classes = props.get("objectclasses") or props.get("objectClass") or []
    if isinstance(object_classes, str):
        object_classes = [object_classes]
    return any(
        str(value).casefold()
        in {"msds-managedserviceaccount", "msds-groupmanagedserviceaccount"}
        for value in object_classes
    )


def _is_machine_or_trust_user(props: dict[str, Any]) -> bool:
    """Return True for machine/trust principals surfaced as User nodes — but NOT gMSAs.

    Native collection can surface inter-domain trust accounts and some
    machine-like principals as BloodHound-compatible User nodes.  They are valid
    graph entities, but they must not enter the human user inventory or
    user-focused attack workflows.

    Machine accounts are ``kind="Computer"`` nodes (already excluded by
    ``get_enabled_users``' ``kind="User"`` filter), so among User nodes a
    ``$``-suffixed principal is either an inter-domain TRUST account or a group
    managed service account (gMSA).  A gMSA IS a real service-account user
    (a user-like, attack-relevant principal — kerberoastable, ACL-bearing), so
    it must stay IN the user inventory.  We therefore exclude ``$``-suffixed
    principals ONLY when they are not a managed service account — that carve-out
    is the distinguisher between a trust account (excluded) and a gMSA (kept),
    since the graph carries no explicit trust marker beyond the ``$`` suffix.
    """
    samaccountname = str(props.get("samaccountname") or "").strip()
    if not samaccountname.endswith("$"):
        return False
    return not _is_managed_service_account(props)


# ---------------------------------------------------------------------------
# LDAP-query MIRROR of the predicates above — single source of truth.
#
# The predicates (_prop_enabled / _is_machine_or_trust_user /
# _is_managed_service_account) and get_enabled_users/get_enabled_computers define
# "a real enabled user/computer" for the SCAN, which filters already-collected
# graph nodes. The `adscan doctor` preflight issues a raw paged LDAP COUNT BEFORE
# any collection, so it needs the SAME definition expressed as an LDAP filter.
# These constants are that mirror and MUST stay in lockstep with the predicates
# (locked by tests/unit/services/graph_queries/test_enabled_inventory_parity.py).
#
#   enabled       = ACCOUNTDISABLE (0x2) NOT set on userAccountControl.
#   real user     = a normal user (objectCategory=person + objectClass=user)
#                   OR a (group) managed service account — a gMSA/sMSA is a real
#                   service-account user (kerberoastable, ACL-bearing), so it
#                   stays IN the user inventory.  EXCLUDES only inter-domain TRUST
#                   accounts (sAMAccountType=805306370).  Machine accounts are
#                   objectClass=computer and never match the user branch.  This
#                   mirrors _is_machine_or_trust_user, whose `$`-suffix exclusion
#                   carves OUT gMSAs via `not _is_managed_service_account`.
#                   gMSAs are objectClass=msDS-GroupManagedServiceAccount (NOT
#                   objectCategory=person), so a person-only filter would drop
#                   them — the explicit MSA branch keeps them.
#   real computer = objectCategory=computer already excludes gMSAs/sMSAs (those
#                   are objectCategory=msDS-*ManagedServiceAccount) — mirrors
#                   _is_managed_service_account for the computer inventory.
#
# The MSA objectClass names below are read from _is_managed_service_account so
# the two forms cannot drift.
ENABLED_NOT_DISABLED_LDAP = "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
# sAMAccountType for an INTERDOMAIN_TRUST_ACCOUNT (0x30000002 = 805306370).
_SAM_ACCOUNT_TYPE_TRUST = "805306370"
NOT_TRUST_ACCOUNT_LDAP = f"(!(sAMAccountType={_SAM_ACCOUNT_TYPE_TRUST}))"
# gMSA/sMSA objectClass tokens, kept in lockstep with _is_managed_service_account.
_MSA_OBJECT_CLASSES = ("msDS-GroupManagedServiceAccount", "msDS-ManagedServiceAccount")
_MSA_OBJECTCLASS_LDAP = "".join(f"(objectClass={oc})" for oc in _MSA_OBJECT_CLASSES)
# Normal users OR managed service accounts (gMSA/sMSA).
_USER_OR_MSA_LDAP = f"(|(&(objectCategory=person)(objectClass=user)){_MSA_OBJECTCLASS_LDAP})"
ENABLED_REAL_USERS_LDAP_FILTER = (
    f"(&{_USER_OR_MSA_LDAP}"
    f"{ENABLED_NOT_DISABLED_LDAP}{NOT_TRUST_ACCOUNT_LDAP})"
)
ENABLED_REAL_COMPUTERS_LDAP_FILTER = (
    f"(&(objectCategory=computer){ENABLED_NOT_DISABLED_LDAP})"
)


def get_enabled_users(graph: dict[str, Any], domain: str) -> list[dict[str, Any]]:
    return [
        p
        for p in _nodes_props(graph, "User", domain)
        if _prop_enabled(p) and not _is_machine_or_trust_user(p)
    ]


def get_enabled_computers(graph: dict[str, Any], domain: str) -> list[dict[str, Any]]:
    return [
        p
        for p in _nodes_props(graph, "Computer", domain)
        if _prop_enabled(p) and not _is_managed_service_account(p)
    ]


def get_high_value_users(graph: dict[str, Any], domain: str) -> list[dict[str, Any]]:
    return [
        node.get("properties") or {}
        for node in (graph.get("nodes") or {}).values()
        if node.get("kind") == "User"
        and domain_matches(node, domain)
        and is_enabled(node)
        and is_tier0_or_high_value(node)
    ]


def get_kerberoastable_users(
    graph: dict[str, Any], domain: str
) -> list[dict[str, Any]]:
    return [p for p in get_enabled_users(graph, domain) if p.get("hasspn")]


def get_asreproastable_users(
    graph: dict[str, Any], domain: str
) -> list[dict[str, Any]]:
    return [p for p in get_enabled_users(graph, domain) if p.get("dontreqpreauth")]


def get_stale_users(
    graph: dict[str, Any],
    domain: str,
    stale_days: int = STALE_DAYS_DEFAULT,
) -> list[dict[str, Any]]:
    return [
        node.get("properties") or {}
        for node in (graph.get("nodes") or {}).values()
        if node.get("kind") == "User"
        and domain_matches(node, domain)
        and is_enabled(node)
        and is_stale(node, stale_days)
    ]


def get_admincount_users(graph: dict[str, Any], domain: str) -> list[dict[str, Any]]:
    return [p for p in get_enabled_users(graph, domain) if p.get("admincount")]


def get_laps_computers(graph: dict[str, Any], domain: str) -> list[dict[str, Any]]:
    return [p for p in get_enabled_computers(graph, domain) if p.get("haslaps")]


def get_non_laps_computers(graph: dict[str, Any], domain: str) -> list[dict[str, Any]]:
    return [p for p in get_enabled_computers(graph, domain) if not p.get("haslaps")]


def get_sessions(graph: dict[str, Any], domain: str) -> list[dict[str, Any]]:
    return [
        {"computer_id": e.get("from"), "user_id": e.get("to")}
        for e in (graph.get("edges") or [])
        if e.get("relation") == "HasSession"
    ]


def get_pwdneverexpires_users(
    graph: dict[str, Any], domain: str
) -> list[dict[str, Any]]:
    return [p for p in get_enabled_users(graph, domain) if p.get("pwdneverexpires")]


def get_passwordnotreqd_users(
    graph: dict[str, Any], domain: str
) -> list[dict[str, Any]]:
    return [p for p in get_enabled_users(graph, domain) if p.get("passwordnotreqd")]
