"""LDAP collection scope — opt-in per query group.

Anonymous binds typically can't read ACLs, tokenGroups, or large object
inventories. Authenticated DA binds read everything. The scope object makes
this explicit instead of hiding it inside the collector. Each phase of
:class:`ADscanLDAPCollector` consults the matching flag and skips early when
False — no LDAP roundtrip is issued for disabled phases.

Construct via the named factories:

* ``LDAPCollectionScope.full_authenticated()`` — every phase enabled, no caps.
* ``LDAPCollectionScope.quick_audit()`` — fast authenticated sweep, no ACLs.
* ``LDAPCollectionScope.narrow_unauth()`` — conservative anonymous sweep,
  capped, with high-cost / often-denied phases disabled.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from adscan_core.scan_pacing import active_pacing, component_pacing


def _pacing_page_size() -> int:
    """LDAP page size from the scan pacing (``ldap.paged_search``)."""
    return int(component_pacing(active_pacing(), "ldap.paged_search")["page_size"])


@dataclass(frozen=True, slots=True)
class LDAPCollectionScope:
    """Per-phase opt-in flags + per-object caps for one LDAP collection run."""

    # Core data — cheap, almost always available.
    domain_node: bool = True
    domain_policy: bool = True
    users: bool = True
    groups: bool = True
    computers: bool = True
    gpos: bool = True
    organizational_units: bool = True
    containers: bool = True

    # High-cost / often-denied queries.
    acls: bool = True
    group_memberships: bool = True
    gpo_links: bool = True
    trusts: bool = True
    adcs: bool = True

    # Caps — enforced via LDAP ``size_limit`` and post-collection truncation.
    max_users: int | None = None
    max_groups: int | None = None
    max_computers: int | None = None
    # Page size from the scan pacing (``ldap.paged_search``: 1000 at the default level).
    paged_size: int = field(default_factory=_pacing_page_size)

    # ------------------------------------------------------------------ #
    # Convenience
    # ------------------------------------------------------------------ #

    @property
    def collects_objects(self) -> bool:
        """True when at least one of users/groups/computers/gpos/OUs/containers is enabled."""
        return any(
            (
                self.users,
                self.groups,
                self.computers,
                self.gpos,
                self.organizational_units,
                self.containers,
            )
        )

    def object_class_filter(self) -> str:
        """Return the LDAP filter for the enabled object classes.

        Returns an empty string when no object classes are enabled (caller
        should skip the search entirely).
        """
        clauses: list[str] = []
        if self.users:
            clauses.append("(objectClass=user)")
        if self.computers:
            clauses.append("(objectClass=computer)")
        if self.groups:
            clauses.append("(objectClass=group)")
        if self.organizational_units:
            clauses.append("(objectClass=organizationalUnit)")
        if self.containers:
            clauses.append("(objectClass=container)")
        if self.gpos:
            clauses.append("(objectClass=groupPolicyContainer)")
        if not clauses:
            return ""
        if len(clauses) == 1:
            return clauses[0]
        return "(|" + "".join(clauses) + ")"

    # ------------------------------------------------------------------ #
    # Factories
    # ------------------------------------------------------------------ #

    @classmethod
    def full_authenticated(cls) -> LDAPCollectionScope:
        """Full BloodHound-style collection — every phase enabled, no caps."""
        return cls()

    @classmethod
    def quick_audit(cls) -> LDAPCollectionScope:
        """Fast authenticated sweep — users + groups + computers, no ACLs.

        For pre-CI surface mapping when the operator just needs a domain
        summary without paying for ACL parsing or ADCS enumeration.
        """
        return cls(
            acls=False,
            group_memberships=False,
            gpo_links=False,
            trusts=False,
            adcs=False,
            max_users=2000,
        )

    @classmethod
    def narrow_unauth(cls) -> LDAPCollectionScope:
        """Conservative anonymous sweep — opt OUT of high-cost queries that
        anonymous binds typically can't satisfy.

        Hardened DCs (RestrictAnonymous=2) deny ACL reads, group membership
        walks, and trust enumeration. Asking for them anyway just wastes
        round-trips and pollutes the workspace with empty artifacts. We
        default to a minimal user/group/computer inventory plus descriptions,
        capped at 500 entries to keep the sweep fast.
        """
        return cls(
            acls=False,
            group_memberships=False,
            gpo_links=False,
            trusts=False,
            adcs=False,
            organizational_units=False,
            containers=False,
            gpos=False,
            max_users=500,
            max_groups=200,
            max_computers=200,
        )
