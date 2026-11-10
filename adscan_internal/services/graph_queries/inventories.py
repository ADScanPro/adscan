from __future__ import annotations

from typing import Any

from adscan_core.kerberos_roasting import (
    AccountSignals,
    is_asrep_roastable,
    is_kerberoastable,
)
from adscan_core.kerberos_roasting import (
    MANAGED_SERVICE_ACCOUNT_OBJECT_CLASSES as _MSA_OBJECT_CLASSES,
)
from adscan_core.kerberos_roasting import (
    is_managed_service_account as _is_managed_service_account,
)
from adscan_internal.services.graph_queries.filters import (
    STALE_DAYS_DEFAULT,
    domain_matches,
    is_active,
    is_stale,
    is_tombstoned,
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


def is_managed_service_account(props: dict[str, Any]) -> bool:
    """Return True when a node is a (group) managed service account.

    The graph-shaped adapter over the cross-tier predicate
    ``adscan_core.kerberos_roasting.is_managed_service_account``, which is where
    "is this principal a gMSA/sMSA" is decided for the engine, the deliverable
    and the web product alike. This wrapper exists so the inventory callers here
    and the account-population resolver behind the account KPIs
    (``services/account_population.py``) keep passing flat graph properties.

    The core predicate reads four signals rather than one because no single
    field is present in every artifact: a native graph node carries ``is_gmsa``
    / ``account_type``, a graph written before those existed carries only the
    ``CN=Managed Service Accounts`` distinguished name, and raw LDAP-shaped
    props carry only ``objectClass``. The trailing ``$`` on the sAMAccountName
    is deliberately not among them — every MSA has it, but so does every
    inter-domain trust account, which is a different class handled by
    :func:`_is_machine_or_trust_user`.
    """
    return _is_managed_service_account(AccountSignals.from_properties(props))


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
    (a user-like, attack-relevant principal — ACL-bearing, and whoever may
    retrieve its managed password holds it), so it must stay IN the user
    inventory.  It is NOT exposed to offline ticket cracking, which is a
    separate question answered by ``adscan_core.kerberos_roasting`` and not by
    membership of this inventory.  We therefore exclude ``$``-suffixed
    principals ONLY when they are not a managed service account — that carve-out
    is the distinguisher between a trust account (excluded) and a gMSA (kept),
    since the graph carries no explicit trust marker beyond the ``$`` suffix.
    """
    samaccountname = str(props.get("samaccountname") or "").strip()
    if not samaccountname.endswith("$"):
        return False
    return not is_managed_service_account(props)


def is_machine_or_trust_user(props: dict[str, Any]) -> bool:
    """Public name of :func:`_is_machine_or_trust_user` for other population counts.

    Any figure that counts the domain's people (the exposure KPI's standard-user
    denominator included) must drop inter-domain trust accounts exactly as the
    user inventory does. A second definition counted the parent-trust account
    ``SEVENKINGDOMS$`` as an ordinary user and printed "11 of 11" beside a
    population of 10.
    """
    return _is_machine_or_trust_user(props)


# ---------------------------------------------------------------------------
# LDAP-query MIRROR of the predicates above — single source of truth.
#
# The predicates (is_active / _is_machine_or_trust_user /
# is_managed_service_account) and get_enabled_users/get_enabled_computers define
# "a real enabled user/computer" for the SCAN, which filters already-collected
# graph nodes. The `adscan doctor` preflight issues a raw paged LDAP COUNT BEFORE
# any collection, so it needs the SAME definition expressed as an LDAP filter.
# These constants are that mirror and MUST stay in lockstep with the predicates
# (locked by tests/unit/services/graph_queries/test_enabled_inventory_parity.py).
#
#   active        = LIVE (not a CN=Deleted Objects tombstone) AND enabled.
#                   A raw paged LDAP search never returns tombstones (they need
#                   the SHOW_DELETED control), so the LDAP form expresses the
#                   live half implicitly, and the two sides agree only now that
#                   the graph predicates exclude deletions too.
#   enabled       = ACCOUNTDISABLE (0x2) NOT set on userAccountControl.
#   real user     = a normal user (objectCategory=person + objectClass=user)
#                   OR a (group) managed service account — a gMSA/sMSA is a real
#                   service-account user (ACL-bearing, and held by whoever may
#                   retrieve its managed password), so it stays IN the user
#                   inventory.  EXCLUDES only inter-domain TRUST
#                   accounts (sAMAccountType=805306370).  Machine accounts are
#                   objectClass=computer and never match the user branch.  This
#                   mirrors _is_machine_or_trust_user, whose `$`-suffix exclusion
#                   carves OUT gMSAs via `not is_managed_service_account`.
#                   gMSAs are objectClass=msDS-GroupManagedServiceAccount (NOT
#                   objectCategory=person), so a person-only filter would drop
#                   them — the explicit MSA branch keeps them.
#   real computer = objectCategory=computer already excludes gMSAs/sMSAs (those
#                   are objectCategory=msDS-*ManagedServiceAccount) — mirrors
#                   is_managed_service_account for the computer inventory.
#
# The MSA objectClass names below are read from is_managed_service_account so
# the two forms cannot drift.
ENABLED_NOT_DISABLED_LDAP = "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
# sAMAccountType for an INTERDOMAIN_TRUST_ACCOUNT (0x30000002 = 805306370).
_SAM_ACCOUNT_TYPE_TRUST = "805306370"
NOT_TRUST_ACCOUNT_LDAP = f"(!(sAMAccountType={_SAM_ACCOUNT_TYPE_TRUST}))"
# gMSA/sMSA objectClass tokens, read from the cross-tier SSOT
# (adscan_core.kerberos_roasting) so no form can drift from another.
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
    """Return the domain's ACTIVE user population: live (not deleted) AND enabled.

    ``is_active`` rather than a raw enabled check, because a tombstone preserves
    its ``userAccountControl`` and therefore reaches here as ``enabled=True``
    whenever it was enabled on the day it was deleted. Counting one as part of
    the domain's user population inflates every figure derived from this list:
    the spray population, the estate-size telemetry, the exposure-KPI
    denominator, and the ``enabled_users.txt`` artifact this feeds. Deleted
    accounts stay fully available through :func:`get_tombstoned_users`.
    """
    return [
        p
        for p in _nodes_props(graph, "User", domain)
        if is_active(p) and not _is_machine_or_trust_user(p)
    ]


def get_enabled_computers(graph: dict[str, Any], domain: str) -> list[dict[str, Any]]:
    """Return the domain's ACTIVE computer population: live AND enabled.

    See :func:`get_enabled_users` for why deletion is excluded here rather than
    left to each consumer.
    """
    return [
        p
        for p in _nodes_props(graph, "Computer", domain)
        if is_active(p) and not is_managed_service_account(p)
    ]


def get_tombstoned_users(graph: dict[str, Any], domain: str) -> list[dict[str, Any]]:
    """Return the domain's DELETED user objects (AD Recycle Bin tombstones).

    The complement of :func:`get_enabled_users` on the live/deleted axis, so a
    surface whose subject IS the deleted population (a restorable-tombstone
    finding, a "deleted accounts an attacker can reanimate" count) reads it
    explicitly instead of leaning on the active inventory having let them
    through. Each record keeps its raw ``enabled`` flag, which is what says
    whether reanimating it yields a usable account.
    """
    return [p for p in _nodes_props(graph, "User", domain) if is_tombstoned(p)]


def get_high_value_users(graph: dict[str, Any], domain: str) -> list[dict[str, Any]]:
    return [
        node.get("properties") or {}
        for node in (graph.get("nodes") or {}).values()
        if node.get("kind") == "User"
        and domain_matches(node, domain)
        and is_active(node)
        and is_tier0_or_high_value(node)
    ]


def get_kerberoastable_users(
    graph: dict[str, Any], domain: str
) -> list[dict[str, Any]]:
    """Return the enabled accounts whose service ticket is worth cracking.

    A published service principal name is the entry condition, but it is not
    sufficient: a managed service account publishes SPNs and holds a
    directory-generated password, so its ticket is not crackable and listing it
    here would be a false positive in the client's "exploitable today" view. The
    exclusion is the cross-tier predicate, shared with the collector's edge
    derivation and the web product, so all three agree on the same population.
    """
    return [
        p
        for p in get_enabled_users(graph, domain)
        if is_kerberoastable(
            AccountSignals.from_properties(p), has_spn=bool(p.get("hasspn"))
        )
    ]


def get_asreproastable_users(
    graph: dict[str, Any], domain: str
) -> list[dict[str, Any]]:
    """Return the enabled accounts whose AS-REP is worth cracking.

    Same shape as :func:`get_kerberoastable_users`: pre-authentication disabled
    is the entry condition, and an account whose password the directory
    generates is excluded whatever that flag says.
    """
    return [
        p
        for p in get_enabled_users(graph, domain)
        if is_asrep_roastable(
            AccountSignals.from_properties(p),
            preauth_required=not p.get("dontreqpreauth"),
        )
    ]


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
        and is_active(node)
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
