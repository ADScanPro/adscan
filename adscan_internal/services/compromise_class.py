"""Canonical compromise classification for ADscan.

This module defines the single source of truth for the customer-facing
compromise taxonomy used across CLI, report and web surfaces.

The taxonomy intentionally separates *what kind of impact* an account
represents from *how* that impact was discovered. It is the public
vocabulary documented in `CLAUDE.md` and
`adscan-obsidian/business/12_nomenclature_standard.md`.

Four classes (priority order, highest first):

* ``DOMAIN_BREAKER`` — accounts whose privileges directly equal domain
  compromise (Domain Admins, Enterprise Admins, BUILTIN\\Administrators,
  Schema Admins, krbtgt). One-step. No escalation required.
* ``PRIVILEGED_ESCALATOR`` — accounts in privileged groups that are not
  themselves domain compromise but whose membership unlocks a confirmed
  one-technique escalation (Backup Operators, Account Operators,
  DnsAdmins, Print/Server Operators, Cert Publishers, Key Admins,
  Exchange Trusted Subsystem, Exchange Windows Permissions, etc.).
* ``COMPROMISE_ENABLER`` — accounts without privileged group membership
  that nonetheless reach the domain through a confirmed multi-step
  attack path. This bucket is currently populated from attack-graph
  evidence (path-derived), not from group membership semantics.
* ``TIER0_FOOTHOLD`` *(Phase 1 refactor, 2026-05-02)* — paths that
  terminate in an :attr:`EdgeKind.AUTH` edge against a Tier 0 asset
  (DC, Exchange, ADCS CA). Confirms access — but not control — to a
  critical asset; the actual domain compromise requires post-exploitation
  to succeed.

The single attribute callers should read is :data:`CompromiseClass`. The
historical booleans (``is_direct_control``, ``is_enabler`` and
``is_high_impact``) remain as derivation inputs for backward
compatibility while the rest of the codebase is migrated.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Iterable, Mapping

from adscan_internal.services.edge_kind import EdgeKind, classify_edge_kind


class CompromiseClass(str, Enum):
    """Canonical customer-facing compromise classes."""

    DOMAIN_BREAKER = "domain_breaker"
    PRIVILEGED_ESCALATOR = "privileged_escalator"
    COMPROMISE_ENABLER = "compromise_enabler"
    TIER0_FOOTHOLD = "tier0_foothold"
    UNAUTHENTICATED_PRINCIPAL = "unauthenticated_principal"
    NONE = "none"

    @property
    def display_label(self) -> str:
        """Return the human label used in report and web surfaces."""
        return _DISPLAY_LABELS[self]

    @property
    def cli_badge(self) -> str:
        """Return the bracketed badge used in CLI output."""
        return _CLI_BADGES[self]


_DISPLAY_LABELS: dict[CompromiseClass, str] = {
    CompromiseClass.DOMAIN_BREAKER: "Domain Breaker",
    CompromiseClass.PRIVILEGED_ESCALATOR: "Privileged Escalator",
    CompromiseClass.COMPROMISE_ENABLER: "Compromise Enabler",
    CompromiseClass.TIER0_FOOTHOLD: "Critical Asset Access (post-exploitation pending)",
    CompromiseClass.UNAUTHENTICATED_PRINCIPAL: "Unauthenticated Principal (null session)",
    CompromiseClass.NONE: "Standard",
}

_CLI_BADGES: dict[CompromiseClass, str] = {
    CompromiseClass.DOMAIN_BREAKER: "[T0/Domain Breaker]",
    CompromiseClass.PRIVILEGED_ESCALATOR: "[T0/Privileged Esc.]",
    CompromiseClass.COMPROMISE_ENABLER: "[Compromise Enabler]",
    CompromiseClass.TIER0_FOOTHOLD: "[T0/Foothold]",
    CompromiseClass.UNAUTHENTICATED_PRINCIPAL: "[Unauth]",
    CompromiseClass.NONE: "[Standard]",
}


def derive_compromise_class(
    *,
    is_direct_control: bool = False,
    is_privileged_escalator: bool = False,
    has_path_to_domain: bool = False,
) -> CompromiseClass:
    """Derive the canonical compromise class from primitive evidence flags.

    Priority is highest-impact-wins: a principal that satisfies
    ``is_direct_control`` is a Domain Breaker even if it also has lower
    classifications. This matches how the CLI, report and web surfaces
    must label the principal — the highest impact wins.

    Args:
        is_direct_control: True when membership grants intrinsic domain
            compromise (Domain Admins, Enterprise Admins, etc.).
        is_privileged_escalator: True when membership grants a privileged
            group that has a confirmed one-technique escalation but is
            not itself domain compromise (Backup Operators, DnsAdmins,
            Account Operators, etc.).
        has_path_to_domain: True when attack-graph evidence shows a
            confirmed multi-step path from this principal to the domain
            without privileged group membership.

    Returns:
        The canonical compromise class. Returns
        :attr:`CompromiseClass.NONE` when no evidence applies.

    Note:
        This is the legacy flag-based API kept for backward compatibility.
        New call sites should prefer
        :func:`derive_compromise_class_from_path` which classifies based
        on the canonical EdgeKind of the path's last real edge.
    """
    if is_direct_control:
        return CompromiseClass.DOMAIN_BREAKER
    if is_privileged_escalator:
        return CompromiseClass.PRIVILEGED_ESCALATOR
    if has_path_to_domain:
        return CompromiseClass.COMPROMISE_ENABLER
    return CompromiseClass.NONE


def derive_compromise_class_from_semantics(
    semantics: dict[str, Any],
    *,
    has_path_to_domain: bool = False,
) -> CompromiseClass:
    """Derive the canonical compromise class from a control-semantics dict.

    This is the call site adapter for code that already produces the
    semantics dict returned by
    :func:`adscan_internal.services.control_semantics.classify_membership_control_semantics`.
    """
    return derive_compromise_class(
        is_direct_control=bool(semantics.get("is_direct_control")),
        is_privileged_escalator=bool(semantics.get("is_privileged_escalator"))
        or bool(semantics.get("is_enabler")),
        has_path_to_domain=has_path_to_domain,
    )


# ---------------------------------------------------------------------------
# Phase 1 — path-based classifier (NEW canonical API)
# ---------------------------------------------------------------------------


# Names of privileged-escalator groups whose membership unlocks a
# one-technique path to Tier 0. Mirrors the table in
# 12_nomenclature_standard.md. We compare case-insensitively against the
# target node's ``name`` or ``samaccountname`` field.
_PRIVILEGED_ESCALATOR_GROUP_NAMES: frozenset[str] = frozenset(
    name.lower()
    for name in (
        "Schema Admins",
        "Backup Operators",
        "Server Operators",
        "Account Operators",
        "Print Operators",
        "DnsAdmins",
        "Hyper-V Administrators",
        "Storage Replica Administrators",
        "AD Recycle Bin",
        "Cert Publishers",
        "Key Admins",
        "Enterprise Key Admins",
        "Exchange Trusted Subsystem",
        "Exchange Windows Permissions",
    )
)


def _node_tier(node: Mapping[str, Any] | None) -> int | None:
    """Extract the tier from a node dict if present.

    Recognises every Tier-0 signal used across the ADscan stack:

    * Explicit ``tier`` / ``tier_level`` / ``asset_tier`` integer fields.
    * Snake-case ``is_tier0`` / ``is_dc`` flags (legacy).
    * Camel-case ``isTierZero`` flag (collector / BloodHound CE convention).
    * ``system_tags`` containing ``admin_tier_0`` (canonical Tier-0 tag).
    * ``kind == "Domain"`` — the Domain object IS the canonical domain
      compromise terminal in the new model. Controlling it (WriteDACL,
      GenericAll, AddMember on krbtgt-replicating principals, etc.) is by
      definition Tier-0.
    * ``target_terminal_class == "direct_compromise"`` — final fallback for
      principals classified as direct-compromise sinks (DA, EA, krbtgt…)
      via ``_node_target_terminal_class``.
    """
    if not node:
        return None
    for key in ("tier", "tier_level", "asset_tier"):
        value = node.get(key)
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())
    if bool(node.get("is_tier0")) or bool(node.get("is_dc")):
        return 0
    if bool(node.get("isTierZero")):
        return 0
    props = (
        node.get("properties") if isinstance(node.get("properties"), Mapping) else {}
    )
    if isinstance(props, Mapping) and bool(props.get("isTierZero")):
        return 0
    if str(node.get("kind") or "").strip().lower() == "domain":
        return 0
    tags = node.get("system_tags")
    if isinstance(tags, str) and "admin_tier_0" in tags.lower():
        return 0
    if isinstance(tags, list) and any(
        str(t).strip().lower() == "admin_tier_0" for t in tags
    ):
        return 0
    if isinstance(props, Mapping):
        prop_tags = props.get("system_tags")
        if isinstance(prop_tags, str) and "admin_tier_0" in prop_tags.lower():
            return 0
        if isinstance(prop_tags, list) and any(
            str(t).strip().lower() == "admin_tier_0" for t in prop_tags
        ):
            return 0
        if (
            str(props.get("target_terminal_class") or "").strip().lower()
            == "direct_compromise"
        ):
            return 0
    if (
        str(node.get("target_terminal_class") or "").strip().lower()
        == "direct_compromise"
    ):
        return 0
    return None


def _node_name(node: Mapping[str, Any] | None) -> str:
    if not node:
        return ""
    for key in ("name", "samaccountname", "label"):
        value = node.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


# RIDs whose compromise IS a direct domain compromise (Tier 2 of the terminal
# taxonomy in docs/superpowers/specs/2026-06-03-attack-path-terminal-ordering.md):
# Administrator account (500), Domain Admins (512), Domain Controllers group
# (516), Enterprise Admins (519), BUILTIN\Administrators (544), krbtgt (502).
# DC computer accounts are also direct (handled via the ``is_dc`` flag below).
#
# Deliberately EXCLUDED (they are compromise ENABLERS — controlling them needs a
# further abuse, and the canonical nomenclature table classifies them as
# Privileged Escalators): Schema Admins (518, schema-write is delayed/indirect),
# Enterprise/Read-Only DCs (498/521, read-only — partial secrets), and every
# other Tier-0 group (GPCO, Cert Publishers, DnsAdmins, *Operators, Key Admins,
# Exchange groups, …).
_DIRECT_DOMAIN_BREAKER_RIDS: frozenset[int] = frozenset({500, 512, 516, 519, 544, 502})

# Name-based fallback for the same set, for nodes that carry only a name
# (no resolvable objectid/RID — common in synthesized targets and tests).
_DIRECT_DOMAIN_BREAKER_NAMES: frozenset[str] = frozenset(
    name.lower()
    for name in (
        "Administrator",
        "Administrators",
        "Domain Admins",
        "Enterprise Admins",
        "Domain Controllers",
        "Enterprise Domain Controllers",
        "krbtgt",
    )
)


# Well-known GROUP RIDs whose MEMBERSHIP confers a tier (NOT the principal's own
# RID — those are :data:`_DIRECT_DOMAIN_BREAKER_RIDS`). A computer/user that is a
# MEMBER of one of these groups is classified by these sets, so a SID-based
# membership (``S-1-5-21-...-<RID>`` or BUILTIN ``S-1-5-32-<RID>``) classifies
# even when the group node carries no resolvable name. This is the robust,
# locale-independent counterpart to the name sets above; both are matched
# (belt-and-suspenders — DnsAdmins/Exchange groups have no well-known RID, so
# they are caught only by name).
#
# Direct domain-breaker GROUP RIDs — membership IS immediate domain ownership:
#   512 Domain Admins, 516 Domain Controllers, 518 Schema Admins,
#   519 Enterprise Admins (domain ``S-1-5-21-...-<RID>``);
#   544 BUILTIN\\Administrators (``S-1-5-32-544``).
# NB: 518 Schema Admins is a direct breaker HERE (membership) even though the
# path classifier excludes RID 518 from ``_DIRECT_DOMAIN_BREAKER_RIDS`` (a CONTROL
# edge onto the Schema Admins group is delayed/indirect). Being a member of
# Schema Admins is full control-plane membership — Tier 0 direct.
_DIRECT_DOMAIN_BREAKER_GROUP_RIDS: frozenset[int] = frozenset({512, 516, 518, 519, 544})

# Privileged-escalator GROUP RIDs — membership owns the forest via ONE known
# technique (Tier 0 escalation-capable), but is not immediate domain ownership:
#   BUILTIN ``S-1-5-32-<RID>``: 548 Account Operators, 549 Server Operators,
#     550 Print Operators, 551 Backup Operators;
#   domain ``S-1-5-21-...-<RID>``: 517 Cert Publishers, 526 Key Admins,
#     527 Enterprise Key Admins, 498 Enterprise Read-only Domain Controllers,
#     521 Read-only Domain Controllers.
#
# RODC placement (498/521): a MEMBER of the Read-only Domain Controllers /
# Enterprise RODC group is Tier 0 *escalation-capable* — an RODC holds partial
# secrets (cached credentials of its allowed accounts) and a compromised RODC
# reaches the domain through known techniques, but it is not the read-write
# control plane, so it ranks below a writable DC. The orthogonal case — a
# computer whose OWN role is a (read-only) DC (``primaryGroupID`` 521) — is
# Tier 0 *direct* as the DC machine, and is decided by the caller's ``is_dc``
# fast-path BEFORE this membership classifier runs ("highest impact wins").
_PRIVILEGED_ESCALATOR_GROUP_RIDS: frozenset[int] = frozenset(
    {548, 549, 550, 551, 517, 526, 527, 498, 521}
)


def _rid_from_group_token(value: str) -> int | None:
    """Return the well-known RID a group SID token resolves to, or ``None``.

    Recognises both SID shapes that carry a group RID we match on:

    * a domain group SID ``S-1-5-21-<auth>-<RID>`` — the trailing RID; and
    * a BUILTIN alias SID ``S-1-5-32-<RID>`` — the trailing RID.

    Any non-SID token (a resolved group name like ``Cert Publishers``) returns
    ``None`` so the caller falls through to name matching.
    """
    token = str(value or "").strip()
    if not token:
        return None
    upper = token.upper()
    if not (upper.startswith("S-1-5-21-") or upper.startswith("S-1-5-32-")):
        return None
    try:
        return int(upper.rsplit("-", 1)[-1])
    except (ValueError, IndexError):
        return None


def _node_rid(node: Mapping[str, Any] | None) -> int | None:
    """Return the RID (trailing SID component) of a node, or ``None``."""
    if not node:
        return None
    props = node.get("properties") if isinstance(node.get("properties"), Mapping) else {}
    for value in (
        props.get("objectid") if isinstance(props, Mapping) else None,
        props.get("objectId") if isinstance(props, Mapping) else None,
        node.get("objectid"),
        node.get("objectId"),
    ):
        if isinstance(value, str) and value.strip():
            try:
                return int(value.strip().upper().rsplit("-", 1)[-1])
            except (ValueError, IndexError):
                continue
    return None


def _is_direct_domain_breaker_target(node: Mapping[str, Any] | None) -> bool:
    """Return whether reaching *node* IS a direct domain compromise.

    True for the domain object itself, the canonical direct-compromise
    principals (:data:`_DIRECT_DOMAIN_BREAKER_RIDS`), and DC computer accounts.
    A control edge landing here is a real ``DOMAIN_BREAKER``; a control edge to
    any other Tier-0 group is a ``PRIVILEGED_ESCALATOR`` (compromise enabler).
    """
    if not node:
        return False
    if str(node.get("kind") or "").strip().lower() == "domain":
        return True
    rid = _node_rid(node)
    if rid is not None and rid in _DIRECT_DOMAIN_BREAKER_RIDS:
        return True
    # Name fallback when the node carries no resolvable RID.
    name = _node_name(node).strip().lower()
    if name:
        # Strip a trailing @domain suffix (label form) before matching.
        bare = name.split("@", 1)[0].strip()
        if bare in _DIRECT_DOMAIN_BREAKER_NAMES:
            return True
    if bool(node.get("is_dc")):
        return True
    props = node.get("properties") if isinstance(node.get("properties"), Mapping) else {}
    if isinstance(props, Mapping) and bool(props.get("is_dc")):
        return True
    return False


# Public aliases — consumed by tier_lattice (SSOT for per-target tier). The
# underscore-prefixed originals stay for in-module use; these expose the same
# logic as a stable public API across the services package.
def node_tier(node: Mapping[str, Any] | None) -> int | None:
    """Public wrapper for :func:`_node_tier` — see its docstring."""
    return _node_tier(node)


def is_direct_domain_breaker_target(node: Mapping[str, Any] | None) -> bool:
    """Public wrapper for :func:`_is_direct_domain_breaker_target`."""
    return _is_direct_domain_breaker_target(node)


def _is_privileged_escalator_target(node: Mapping[str, Any] | None) -> bool:
    return _node_name(node).lower() in _PRIVILEGED_ESCALATOR_GROUP_NAMES


def is_privileged_escalator_target(node: Mapping[str, Any] | None) -> bool:
    """Public wrapper for :func:`_is_privileged_escalator_target`.

    A privileged-escalator group (DnsAdmins, Backup/Server/Account/Print
    Operators, Cert Publishers, Key Admins, Exchange groups, ...) is a domain
    compromise *enabler* — controlling it requires a further abuse to reach the
    domain object. Consumed by ``tier_lattice.domain_compromise_tier`` as the
    Tier-2 detector (mirrors how :func:`is_direct_domain_breaker_target` is the
    Tier-3/4 detector). The underscore-prefixed original stays for in-module use.
    """
    return _is_privileged_escalator_target(node)


# ---------------------------------------------------------------------------
# Per-principal classifier — classify a single account by its OWN group
# memberships (NOT by an attack path). Used to label each user in the
# inventory the web product serves, so an operator sees at a glance that
# ``administrator`` is a Domain Admin (direct domain compromise), a Backup
# Operators member is a compromise enabler, and the rest are low-privilege.
# ---------------------------------------------------------------------------


# Names that ARE a direct domain breaker when the principal IS that group, or
# is a direct member of it. Reuses :data:`_DIRECT_DOMAIN_BREAKER_NAMES` (the
# group/account names) so there is exactly ONE list of direct-breaker names in
# the module. ``Administrators`` (BUILTIN) is included via that set.
def _normalize_group_token(value: str) -> str:
    """Lower-case + strip a trailing ``@domain`` suffix from a group token."""
    bare = str(value or "").strip().lower()
    if "@" in bare:
        bare = bare.split("@", 1)[0].strip()
    return bare


def classify_principal_by_groups(
    group_names: Iterable[str],
    sid: str | None = None,
    rid: int | None = None,
) -> CompromiseClass:
    """Classify ONE principal by its own (transitive) group memberships.

    This is the per-account counterpart to
    :func:`derive_compromise_class_from_path`: instead of asking "what does
    this attack path achieve", it asks "what does this account's membership
    make it", which is what the customer-facing Users inventory needs.

    The buyer-facing taxonomy collapses to three buckets:

    * **Direct domain compromise** — the account IS, or is a member of, a
      direct domain-breaker group/account (Domain Admins, Enterprise Admins,
      BUILTIN\\Administrators, Domain Controllers, krbtgt, the built-in
      Administrator at RID 500). Returned as :attr:`CompromiseClass.DOMAIN_BREAKER`.
    * **Compromise enabler** — the account is a member of a privileged group
      whose membership unlocks a one-technique escalation (Backup Operators,
      Server/Account/Print Operators, DnsAdmins, Cert Publishers, Key Admins,
      Exchange groups, ...). Returned as :attr:`CompromiseClass.PRIVILEGED_ESCALATOR`.
    * **Low-privilege** — everything else. Returned as :attr:`CompromiseClass.NONE`.

    The group sets are the SAME ones the path classifier uses
    (:data:`_DIRECT_DOMAIN_BREAKER_NAMES`, :data:`_DIRECT_DOMAIN_BREAKER_RIDS`,
    :data:`_PRIVILEGED_ESCALATOR_GROUP_NAMES`) — there is no parallel list.
    Highest impact wins: a Domain Admin who is also a Backup Operator is a
    Domain Breaker.

    Group memberships are matched by BOTH name AND well-known group RID
    (:data:`_DIRECT_DOMAIN_BREAKER_GROUP_RIDS`,
    :data:`_PRIVILEGED_ESCALATOR_GROUP_RIDS`). The RID path is what makes this
    classifier work for **computer** memberships, which the attack graph stores
    as SIDs (``BRAAVOS$ -MemberOf-> S-1-5-21-...-517`` = Cert Publishers,
    ``MEEREEN$ -MemberOf-> S-1-5-21-...-516`` = Domain Controllers): a SID-only
    membership never matches the NAME sets. Both paths are kept — DnsAdmins and
    the Exchange groups have no well-known RID, so they classify only by name.

    Args:
        group_names: Names OR SIDs of every group the principal belongs to,
            transitively (the caller is responsible for nested-group
            expansion). A token shaped like a SID (``S-1-5-21-...-<RID>`` or
            BUILTIN ``S-1-5-32-<RID>``) is matched by RID; any other token is
            matched case-insensitively by name with a trailing ``@domain`` label
            suffix stripped. Mixed name/SID lists are fine.
        sid: The principal's SID, used to read its own RID when ``rid`` is not
            supplied (so the built-in ``Administrator`` at RID 500 and
            ``krbtgt`` at 502 classify as direct breakers by RID).
        rid: The principal's own RID, when already parsed by the caller.

    Returns:
        The canonical :class:`CompromiseClass`. Use :func:`principal_class_label`
        for the buyer-facing display string.
    """
    own_rid = rid
    if own_rid is None and sid:
        tail = str(sid).strip().rstrip("/").rsplit("-", 1)[-1]
        try:
            own_rid = int(tail)
        except (TypeError, ValueError):
            own_rid = None

    # A principal whose OWN RID is a direct-breaker RID is a domain breaker
    # regardless of group membership (built-in Administrator 500, krbtgt 502).
    if own_rid is not None and own_rid in _DIRECT_DOMAIN_BREAKER_RIDS:
        return CompromiseClass.DOMAIN_BREAKER

    # Split each membership token into the RID it resolves to (SID tokens) and
    # the normalized name (non-SID tokens). A token is matched on exactly one
    # axis — a SID never has a usable name, a name never a usable RID.
    name_tokens: set[str] = set()
    group_rids: set[int] = set()
    for token in group_names:
        token_rid = _rid_from_group_token(token)
        if token_rid is not None:
            group_rids.add(token_rid)
        else:
            name_tokens.add(_normalize_group_token(token))
    name_tokens.discard("")

    # Highest impact wins — check direct-breaker membership first, on BOTH axes.
    if (name_tokens & _DIRECT_DOMAIN_BREAKER_NAMES) or (
        group_rids & _DIRECT_DOMAIN_BREAKER_GROUP_RIDS
    ):
        return CompromiseClass.DOMAIN_BREAKER
    if (name_tokens & _PRIVILEGED_ESCALATOR_GROUP_NAMES) or (
        group_rids & _PRIVILEGED_ESCALATOR_GROUP_RIDS
    ):
        return CompromiseClass.PRIVILEGED_ESCALATOR
    return CompromiseClass.NONE


# Buyer-facing labels for the three-bucket per-principal taxonomy. These are
# the strings a customer reads on the Users list / asset cards. They mirror the
# canonical :data:`_DISPLAY_LABELS` vocabulary but use the most recognizable
# wording for a non-technical reviewer (a CISO scanning the user inventory).
_PRINCIPAL_CLASS_LABELS: dict[CompromiseClass, str] = {
    CompromiseClass.DOMAIN_BREAKER: "Domain Admin",
    CompromiseClass.PRIVILEGED_ESCALATOR: "Compromise Enabler",
    CompromiseClass.COMPROMISE_ENABLER: "Compromise Enabler",
    CompromiseClass.NONE: "Standard User",
}


def principal_class_label(cls: CompromiseClass) -> str:
    """Return the buyer-facing label for a per-principal compromise class."""
    return _PRINCIPAL_CLASS_LABELS.get(cls, "Standard User")


# ---------------------------------------------------------------------------
# Privilege Tier — the ESAE/Microsoft-Tiered-Admin axis (axis 1).
#
# Two orthogonal axes, NEVER conflated (see CLAUDE.md § Nomenclature Standard,
# "Two orthogonal axes"):
#
#   * Axis 1 — Privilege Tier (THIS section): what a principal/asset IS
#     GRANTED, statically, by group membership (for principals) or by machine
#     role (for computers). Tier 0 is a CONTAINMENT BOUNDARY, sub-split by
#     directness into "direct" (immediate domain ownership) and
#     "escalation-capable" (owns the forest via one known technique).
#   * Axis 2 — Compromise Reach (the path's ``CompromiseClass``): the highest
#     tier a principal can ATTACK INTO via a validated attack path. NOT
#     recomputed here — :func:`compromise_reach_label` only provides its client
#     label SSOT.
#
# Tier 0's direct vs escalation-capable split IS the principal's own
# :class:`CompromiseClass` from :func:`classify_principal_by_groups`:
# ``DOMAIN_BREAKER`` → Tier 0 direct; ``PRIVILEGED_ESCALATOR`` /
# ``COMPROMISE_ENABLER`` → Tier 0 escalation-capable. There is NO parallel
# group taxonomy — the group lists live once, above.
# ---------------------------------------------------------------------------


class PrivilegeTier(Enum):
    """ESAE Tiered-Admin-Model tier, with Tier 0 split by directness.

    Axis 1 of the nomenclature standard: the tier a principal or asset is
    GRANTED. The ordering (``rank``, highest first) drives prioritization so a
    Tier-0-direct principal outranks a Tier-0-escalation-capable one, which
    outranks Tier 1, which outranks Tier 2 — the same directness-first ordering
    the attack-path engine already uses.
    """

    TIER0_DIRECT = "tier0_direct"
    TIER0_ESCALATION_CAPABLE = "tier0_escalation_capable"
    TIER1 = "tier1"
    TIER2 = "tier2"

    @property
    def rank(self) -> int:
        """Return the prioritization rank (higher = more privileged)."""
        return _PRIVILEGE_TIER_RANK[self]

    @property
    def is_tier0(self) -> bool:
        """Return whether this tier is inside the Tier 0 containment boundary."""
        return self in (
            PrivilegeTier.TIER0_DIRECT,
            PrivilegeTier.TIER0_ESCALATION_CAPABLE,
        )

    @property
    def label(self) -> str:
        """Return the buyer-facing client label (SSOT for axis 1)."""
        return privilege_tier_label(self)


# Directness-first ordering: direct > escalation-capable > tier1 > tier2.
_PRIVILEGE_TIER_RANK: dict[PrivilegeTier, int] = {
    PrivilegeTier.TIER0_DIRECT: 3,
    PrivilegeTier.TIER0_ESCALATION_CAPABLE: 2,
    PrivilegeTier.TIER1: 1,
    PrivilegeTier.TIER2: 0,
}


# Map a principal's OWN compromise class (from group membership) to its tier.
# DOMAIN_BREAKER membership = inside Tier 0, immediate domain ownership.
# PRIVILEGED_ESCALATOR / COMPROMISE_ENABLER membership = inside Tier 0 too, but
# owns the forest only via one known technique (Backup Operators, DnsAdmins, …).
# Everything else is a standard Tier 2 principal.
_COMPROMISE_CLASS_TO_PRIVILEGE_TIER: dict[CompromiseClass, PrivilegeTier] = {
    CompromiseClass.DOMAIN_BREAKER: PrivilegeTier.TIER0_DIRECT,
    CompromiseClass.PRIVILEGED_ESCALATOR: PrivilegeTier.TIER0_ESCALATION_CAPABLE,
    CompromiseClass.COMPROMISE_ENABLER: PrivilegeTier.TIER0_ESCALATION_CAPABLE,
}


def privilege_tier_for_principal(
    group_names: Iterable[str],
    sid: str | None = None,
    rid: int | None = None,
) -> PrivilegeTier:
    """Return the :class:`PrivilegeTier` a principal IS GRANTED by membership.

    Reuses :func:`classify_principal_by_groups` (the SSOT for the group lists)
    and maps its :class:`CompromiseClass` to a tier. No group list is
    duplicated here.

    Args:
        group_names: Every group the principal belongs to, transitively
            (caller expands nested groups). Matched case-insensitively; a
            trailing ``@domain`` suffix is stripped.
        sid: The principal's SID, used to read its RID when ``rid`` is absent
            (so RID 500 Administrator / 502 krbtgt classify as Tier 0 direct).
        rid: The principal's own RID, when already parsed by the caller.

    Returns:
        The :class:`PrivilegeTier`. A principal with no Tier-0 group
        membership is :attr:`PrivilegeTier.TIER2`.
    """
    cls = classify_principal_by_groups(group_names, sid=sid, rid=rid)
    return _COMPROMISE_CLASS_TO_PRIVILEGE_TIER.get(cls, PrivilegeTier.TIER2)


def privilege_tier_for_computer(
    *,
    group_names: Iterable[str] | None = None,
    sid: str | None = None,
    rid: int | None = None,
    is_dc: bool = False,
    is_tier0_asset: bool = False,
    is_server: bool = False,
) -> PrivilegeTier:
    """Return the :class:`PrivilegeTier` a computer IS GRANTED.

    The single source of truth for both axis-1 surfaces that need a computer's
    Privilege Tier: the persisted ``privilege_tier`` attribute the collector
    stamps on ``computers.json`` and the graded ``target_privilege_tier`` the
    severity engine consumes.

    The Tier 0 boundary is GROUP-MEMBERSHIP-driven, exactly like a principal:
    the computer's (transitive) group memberships are classified by
    :func:`classify_principal_by_groups` and the resulting
    :class:`CompromiseClass` is mapped to a tier. This is why an ADCS CA host
    (``BRAAVOS$``, a member of **Cert Publishers** RID 517) grades Tier 0
    escalation-capable and a DC (``MEEREEN$``, a member of **Domain Controllers**
    RID 516) grades Tier 0 direct — generically, by membership, with no per-role
    special case. ANY Tier 0 group (Cert Publishers, Read-only Domain
    Controllers, the Operators, Key Admins, …) classifies a computer the same
    way, automatically.

    The Tier 0 boundary is graded by directness (CLAUDE.md § Nomenclature
    Standard): membership of a direct domain-breaker group (Domain Controllers,
    Domain Admins, …) → ``TIER0_DIRECT``; membership of an escalation-capable
    group (Cert Publishers, the Operators, Key Admins, RODC, …) →
    ``TIER0_ESCALATION_CAPABLE``. Both are inside Tier 0, but not equal.

    Args:
        group_names: Names OR SIDs of every group the computer belongs to,
            transitively (the caller expands nested groups). SID tokens are
            matched by well-known group RID, names case-insensitively — see
            :func:`classify_principal_by_groups`. The computer membership graph
            stores these as SIDs, so the RID path is the load-bearing one.
        sid: The computer's own SID (unused for tiering today — computer RIDs
            are not direct-breaker RIDs — but threaded through to the classifier
            for symmetry with the principal path).
        rid: The computer's own RID, when already parsed by the caller.
        is_dc: True when the machine is a Domain Controller (read-write or
            read-only), resolved from ``primaryGroupID`` (516/521). DCs are the
            machine arm of the Tier 0 control plane. Fast-path: wins over every
            other signal ("highest impact wins"), so a read-only DC computer is
            Tier 0 *direct* even though a mere MEMBER of the RODC group is only
            escalation-capable.
        is_tier0_asset: DEGRADED last-resort fallback ONLY. True when the graph
            tags the host as a Tier 0 asset (``highvalue`` / ``isTierZero``) and
            no resolvable group membership classified it. The primary, robust
            path is ``group_names``; this boolean exists for a host the graph
            flagged Tier 0 with no membership data to derive directness from, and
            grades it escalation-capable (the conservative non-direct verdict).
        is_server: True when the machine is a member server (its
            ``operatingSystem`` contains "Server"). Member servers are Tier 1.
            Only consulted when no Tier 0 signal fired.

    Returns:
        :attr:`PrivilegeTier.TIER0_DIRECT` for a DC or a member of a direct
        domain-breaker group, :attr:`PrivilegeTier.TIER0_ESCALATION_CAPABLE` for
        a member of an escalation-capable Tier 0 group (or the degraded
        ``is_tier0_asset`` fallback), :attr:`PrivilegeTier.TIER1` for a plain
        member server, :attr:`PrivilegeTier.TIER2` for a workstation.
    """
    # Fast-path: a DC machine is Tier 0 direct regardless of group membership.
    if is_dc:
        return PrivilegeTier.TIER0_DIRECT

    # Primary, robust path — classify by the computer's own group memberships,
    # exactly like a principal. Maps DOMAIN_BREAKER → direct,
    # PRIVILEGED_ESCALATOR / COMPROMISE_ENABLER → escalation-capable.
    if group_names is not None:
        cls = classify_principal_by_groups(group_names, sid=sid, rid=rid)
        tier = _COMPROMISE_CLASS_TO_PRIVILEGE_TIER.get(cls)
        if tier is not None:
            return tier

    # Degraded fallback: the graph tagged this host Tier 0 but no group
    # membership was resolvable to derive directness — grade it escalation-
    # capable (the conservative, non-direct verdict).
    if is_tier0_asset:
        return PrivilegeTier.TIER0_ESCALATION_CAPABLE
    if is_server:
        return PrivilegeTier.TIER1
    return PrivilegeTier.TIER2


def privilege_tier_for_computer_node(
    node: Mapping[str, Any] | None,
    *,
    is_tier0_asset: bool = False,
) -> PrivilegeTier:
    """Return the :class:`PrivilegeTier` a Computer graph node IS GRANTED.

    The degraded-fallback resolver over :func:`privilege_tier_for_computer` for
    callers that only have an attack-graph node (no transitive group-membership
    closure): DC-ness via the collector SSOT
    (:func:`computer_node_role.classify_computer_node_role`,
    ``primaryGroupID`` 516/521 + RODC UAC bit + krbtgt SPN), the server-vs-
    workstation split from ``operatingSystem``, and the caller-supplied
    ``is_tier0_asset`` degraded signal (a non-DC Tier 0 role — ADCS CA,
    Exchange, or a generic ``isTierZero``/``highvalue`` tag — the caller
    resolves what "Tier 0 asset" means for its own context; this function only
    consumes the boolean).

    This is the single source of truth two callers share:
    :func:`adscan_internal.cli.intelligence._resolve_target_privilege_tier`
    (attack-path target nodes) and
    :func:`adscan_internal.services.credential_harvest_classification.classify_harvested_principal_tier`
    (a harvested machine-account credential's host). Do not re-derive the
    DC/server-vs-workstation logic at a new call site — call this function.

    Args:
        node: A BloodHound/ADscan-shaped Computer node dict (``kind``,
            ``properties``). Returns :attr:`PrivilegeTier.TIER2` for
            ``None`` or a non-mapping input — never raises.
        is_tier0_asset: True when the caller has already determined this
            host is a Tier 0 asset via a role/tag signal outside group
            membership (ADCS CA, Exchange, ``isTierZero``, ``highvalue``).

    Returns:
        :attr:`PrivilegeTier.TIER0_DIRECT` for a DC, the degraded
        ``TIER0_ESCALATION_CAPABLE`` when ``is_tier0_asset`` and not a DC,
        :attr:`PrivilegeTier.TIER1` for a plain member server, else
        :attr:`PrivilegeTier.TIER2`.
    """
    from adscan_internal.services.computer_node_role import (  # noqa: PLC0415
        classify_computer_node_role,
    )

    if not isinstance(node, Mapping):
        return PrivilegeTier.TIER2

    dc_role = classify_computer_node_role(dict(node))

    props = node.get("properties") if isinstance(node.get("properties"), Mapping) else {}
    os_str = ""
    for key in ("operatingsystem", "operatingSystem"):
        val = (props or {}).get(key) or node.get(key)
        if val:
            os_str = str(val).lower()
            break

    return privilege_tier_for_computer(
        is_dc=dc_role is not None,
        is_tier0_asset=is_tier0_asset,
        is_server="server" in os_str,
    )


# ---------------------------------------------------------------------------
# Client label SSOT — the two functions Phase 2 (CLI / report / platform) all
# translate from. One source; make the strings final and clear.
# ---------------------------------------------------------------------------


# Axis 1 — the tier a principal/asset IS IN. Bank-auditor-clear wording that
# names the containment boundary and the directness split.
_PRIVILEGE_TIER_LABELS: dict[PrivilegeTier, str] = {
    PrivilegeTier.TIER0_DIRECT: "Tier 0: Domain Control",
    PrivilegeTier.TIER0_ESCALATION_CAPABLE: "Tier 0: Escalation-capable",
    PrivilegeTier.TIER1: "Tier 1: Server / Application Admin",
    PrivilegeTier.TIER2: "Tier 2: Standard",
}


def privilege_tier_label(tier: PrivilegeTier) -> str:
    """Return the canonical buyer-facing label for a :class:`PrivilegeTier`."""
    return _PRIVILEGE_TIER_LABELS.get(tier, "Tier 2: Standard")


# Axis 2 — Compromise Reach. The highest tier a principal can ATTACK INTO via a
# validated attack path. Keyed by the PATH's CompromiseClass (already computed
# by ``derive_compromise_class_from_path`` — NOT recomputed here).
_COMPROMISE_REACH_LABELS: dict[CompromiseClass, str] = {
    CompromiseClass.DOMAIN_BREAKER: "Validated path to full domain compromise (control of a Tier 0 asset)",
    CompromiseClass.TIER0_FOOTHOLD: "Foothold on a Tier 0 asset (control pending validation)",
    CompromiseClass.PRIVILEGED_ESCALATOR: "Control of a Tier 0 escalation group (one technique from domain)",
    CompromiseClass.COMPROMISE_ENABLER: "Validated path that advances toward Tier 0",
    CompromiseClass.UNAUTHENTICATED_PRINCIPAL: "Unauthenticated reach",
    CompromiseClass.NONE: "Standard reach",
}


def compromise_reach_label(cls: CompromiseClass) -> str:
    """Return the canonical client label for axis 2 (Compromise Reach).

    This is the label SSOT for "what tier the principal can REACH" — the
    effective/dynamic axis derived from a validated attack path. The
    :class:`CompromiseClass` argument is the PATH's class
    (:func:`derive_compromise_class_from_path`); this function only translates
    it to client wording, it does not recompute reach.
    """
    return _COMPROMISE_REACH_LABELS.get(cls, "Standard reach")


# Axis 2, SHORT form — the same Compromise Reach axis, worded for KPI ROWS and
# cards where the full sentence above is too long to read at a glance. Bank-clear,
# buyer-facing, and the ONE source the executive exposure-KPI row labels come from
# on BOTH surfaces: the premium PDF money-shot cards and the web dashboard impact
# table. Keep it in lock-step with :data:`_COMPROMISE_REACH_LABELS` — the long form
# is the prose, this is the column header for the same thing.
_COMPROMISE_REACH_LABELS_SHORT: dict[CompromiseClass, str] = {
    CompromiseClass.DOMAIN_BREAKER: "Full domain compromise",
    CompromiseClass.TIER0_FOOTHOLD: "Tier 0 foothold",
    CompromiseClass.PRIVILEGED_ESCALATOR: "Tier 0 group takeover",
    CompromiseClass.COMPROMISE_ENABLER: "Stepping-stone to Tier 0",
    CompromiseClass.UNAUTHENTICATED_PRINCIPAL: "Unauthenticated reach",
    CompromiseClass.NONE: "Standard reach",
}


def compromise_reach_label_short(cls: CompromiseClass) -> str:
    """Return the SHORT client label for axis 2 (Compromise Reach).

    The concise counterpart to :func:`compromise_reach_label`, for KPI rows and
    cards where the full sentence does not fit. This is the single source of
    truth the executive exposure-KPI row labels translate from on every surface
    (the premium PDF money-shot and the web dashboard impact table), so the two
    read identically. The :class:`CompromiseClass` argument is the PATH's class;
    this only translates it to wording — it never recomputes reach.
    """
    return _COMPROMISE_REACH_LABELS_SHORT.get(cls, "Standard reach")


# ---------------------------------------------------------------------------
# Tier glossary — the legend the report and platform render. SSOT for the
# glossary CONTENT only; Phase 2 owns the rendering (PDF legend, web panel).
# ---------------------------------------------------------------------------


def tier_glossary() -> list[dict[str, str]]:
    """Return the buyer-facing tier legend (one entry per tier, ordered).

    Each entry is a flat string dict the report/platform can render directly:

    * ``tier`` — the :class:`PrivilegeTier` ``.value`` (stable key).
    * ``label`` — the canonical client label (:func:`privilege_tier_label`).
    * ``groups`` — which groups / roles put a principal or asset in this tier.
    * ``meaning`` — one-line plain-English meaning for a non-technical reader.

    Ordered most-privileged-first to mirror the prioritization ranking.
    """
    return [
        {
            "tier": PrivilegeTier.TIER0_DIRECT.value,
            "label": privilege_tier_label(PrivilegeTier.TIER0_DIRECT),
            "groups": (
                "Domain Admins, Enterprise Admins, BUILTIN\\Administrators, "
                "Domain Controllers, Schema Admins, krbtgt, the built-in "
                "Administrator (RID 500); Domain Controller computers."
            ),
            "meaning": (
                "Identity control plane. Compromise is immediate, one-step "
                "ownership of the domain."
            ),
        },
        {
            "tier": PrivilegeTier.TIER0_ESCALATION_CAPABLE.value,
            "label": privilege_tier_label(PrivilegeTier.TIER0_ESCALATION_CAPABLE),
            "groups": (
                "Backup Operators, Account Operators, Server Operators, "
                "Print Operators, DnsAdmins, Cert Publishers, Key Admins, "
                "and the Exchange privileged groups."
            ),
            "meaning": (
                "Inside the Tier 0 boundary: not immediate domain ownership, "
                "but owns the forest through one known escalation technique "
                "(e.g. Backup Operators reading NTDS.dit)."
            ),
        },
        {
            "tier": PrivilegeTier.TIER1.value,
            "label": privilege_tier_label(PrivilegeTier.TIER1),
            "groups": "Member servers and the accounts that administer them.",
            "meaning": (
                "Server and application plane. Controls business workloads "
                "and their data, but not the identity control plane."
            ),
        },
        {
            "tier": PrivilegeTier.TIER2.value,
            "label": privilege_tier_label(PrivilegeTier.TIER2),
            "groups": "Standard users and workstations.",
            "meaning": (
                "Standard user plane. No granted privilege over servers or "
                "the domain by membership alone."
            ),
        },
    ]


# Per-class one-line "what the path's last edge does" meaning for the reach
# ladder. SSOT for the glossary CONTENT (Phase 2 owns rendering: PDF annex + web
# legend). Client-safe English, no em dashes, no offensive-tool names.
_COMPROMISE_REACH_MEANINGS: dict[CompromiseClass, str] = {
    CompromiseClass.DOMAIN_BREAKER: (
        "The path's final step takes control of a Tier 0 asset (a Domain "
        "Admin, a Domain Controller, or the domain object itself), so the "
        "domain is fully compromised."
    ),
    CompromiseClass.TIER0_FOOTHOLD: (
        "The path's final step lands an interactive session on a Tier 0 "
        "machine (for example remote access to a Domain Controller). Full "
        "control of that machine is the next step and is pending validation."
    ),
    CompromiseClass.PRIVILEGED_ESCALATOR: (
        "The path's final step takes control of a Tier 0 escalation group "
        "(such as Backup Operators or DnsAdmins). Membership in that group "
        "reaches the domain through one further known technique."
    ),
    CompromiseClass.COMPROMISE_ENABLER: (
        "The path's final step lands on a waypoint below Tier 0 that "
        "meaningfully advances toward domain compromise without yet reaching "
        "a Tier 0 asset."
    ),
}


def reach_glossary() -> list[dict[str, str]]:
    """Return the buyer-facing Compromise Reach ladder (axis 2 legend).

    The companion to :func:`tier_glossary` for the second axis: what a
    validated attack path can TAKE OVER, classified by its last real edge.
    Ordered most-severe-first (the prioritization ranking). Each entry is a
    flat string dict the report annex and the platform legend render directly:

    * ``klass`` — the :class:`CompromiseClass` ``.value`` (stable key).
    * ``label`` — the full client label (:func:`compromise_reach_label`).
    * ``label_short`` — the card label (:func:`compromise_reach_label_short`).
    * ``meaning`` — one line on what the path's last edge does.

    The four classes the dashboard and report surface (the unauthenticated and
    "none" reach states are not part of the ladder legend).
    """
    ordered = (
        CompromiseClass.DOMAIN_BREAKER,
        CompromiseClass.TIER0_FOOTHOLD,
        CompromiseClass.PRIVILEGED_ESCALATOR,
        CompromiseClass.COMPROMISE_ENABLER,
    )
    return [
        {
            "klass": cls.value,
            "label": compromise_reach_label(cls),
            "label_short": compromise_reach_label_short(cls),
            "meaning": _COMPROMISE_REACH_MEANINGS[cls],
        }
        for cls in ordered
    ]


# ---------------------------------------------------------------------------
# Domain-takeover KPI segmentation — the executive "accounts that can take
# over the domain" headline. SSOT for the split AND the severity state both
# the premium PDF and the web dashboard render. Defined ONCE here so the two
# surfaces never recompute (and drift) the segmentation or the colour.
#
# Two axes, one vocabulary (CLAUDE.md § Nomenclature Standard):
#   * total          — the honest blast radius (every account that can take
#                      over the domain, reconciles to the affected-account list).
#   * escalator_count— the FINDING: lower-tier (Tier 1 + Tier 2) accounts that
#                      hold a validated path to domain compromise. An ORDINARY
#                      account seizing the domain (12_nomenclature_standard.md
#                      severity rule 2: Compromise Enabler -> Domain = CRITICAL).
#   * tier0_count    — expected administrators (baseline). Already inside Tier 0;
#                      they take over because they ARE admins, not a new finding
#                      (severity rule 1: Domain Breaker -> Domain = INFO).
#
# The severity STATE is driven by the escalator count, NEVER by the total, so a
# domain whose only takeover-capable accounts are the expected admins reads as a
# clean, intact tier separation instead of a red headline.
# ---------------------------------------------------------------------------


class DomainTakeoverKpiState(str, Enum):
    """Severity state for the domain-takeover KPI, driven by the escalators.

    * ``CRITICAL`` — at least one ordinary (Tier 1 / Tier 2) account holds a
      validated path to domain compromise. Red. The finding the PoV sells.
    * ``BASELINE`` — no ordinary account can take over; the only takeover-capable
      accounts are the expected administrators. Green / neutral baseline.
    * ``CLEAN`` — no account can take over the domain at all. Green.
    """

    CRITICAL = "critical"
    BASELINE = "baseline"
    CLEAN = "clean"


# Maps the KPI state to the presentation tone the two surfaces share. The web
# mirror (lib/compromise-reach.ts) MUST mirror these exact tone strings; the
# contract test asserts equality.
_DOMAIN_TAKEOVER_KPI_TONE: dict[DomainTakeoverKpiState, str] = {
    DomainTakeoverKpiState.CRITICAL: "critical",
    DomainTakeoverKpiState.BASELINE: "baseline",
    DomainTakeoverKpiState.CLEAN: "clean",
}


def domain_takeover_kpi_tone(state: DomainTakeoverKpiState) -> str:
    """Return the presentation tone (``critical`` / ``baseline`` / ``clean``)."""
    return _DOMAIN_TAKEOVER_KPI_TONE[state]


def domain_takeover_kpi_state(
    *, escalator_count: int, tier0_count: int, total: int
) -> DomainTakeoverKpiState:
    """Return the KPI severity state from the escalator / tier-0 / total counts.

    The colour rule (12_nomenclature_standard.md severity rules 1 and 2):

    * ``escalator_count >= 1``  -> :attr:`DomainTakeoverKpiState.CRITICAL`
      (an ordinary account can seize the domain — rule 2).
    * ``escalator_count == 0`` and ``tier0_count >= 1``
      -> :attr:`DomainTakeoverKpiState.BASELINE` (only the expected admins —
      rule 1, Domain Breaker -> Domain = INFO).
    * ``total == 0`` -> :attr:`DomainTakeoverKpiState.CLEAN`.

    Driven by the ESCALATOR count, never the total: a domain with nine
    takeover-capable accounts that are all expected administrators is a clean
    baseline, not a red headline.
    """
    if escalator_count >= 1:
        return DomainTakeoverKpiState.CRITICAL
    if tier0_count >= 1:
        return DomainTakeoverKpiState.BASELINE
    # total == 0 (or an inconsistent zero-escalator / zero-tier0 input): clean.
    return DomainTakeoverKpiState.CLEAN


def domain_takeover_kpi_segments(
    *, total: int, tier0: int, tier1: int, tier2: int
) -> dict[str, Any]:
    """Segment the domain-takeover KPI into its canonical parts + severity state.

    The single definition the premium PDF tile and the web dashboard KPI card
    both consume so the headline segmentation and the colour never drift. It
    does NOT recompute any tier — the caller passes the engine-stamped
    ``tier_breakdown {tier0, tier1, tier2}`` (from
    :func:`privilege_tier_for_principal`, via the exposure-KPI aggregator) and
    the honest ``total`` blast radius.

    Args:
        total: The honest blast radius — every account that can take over the
            domain (reconciles to the affected-account list).
        tier0: Accounts already inside Tier 0 (expected administrators).
        tier1: Tier 1 accounts (server / application admins) reaching Tier 0.
        tier2: Tier 2 accounts (standard) reaching Tier 0.

    Returns:
        A flat dict both surfaces render directly:

        * ``total``           — the headline blast-radius integer.
        * ``escalator_count`` — ``tier1 + tier2`` (the emphasized FINDING).
        * ``tier0_count``     — ``tier0`` (the baseline context).
        * ``state``           — the :class:`DomainTakeoverKpiState` ``.value``.
        * ``tone``            — the presentation tone string for ``state``.
    """
    escalator_count = max(0, int(tier1)) + max(0, int(tier2))
    tier0_count = max(0, int(tier0))
    state = domain_takeover_kpi_state(
        escalator_count=escalator_count,
        tier0_count=tier0_count,
        total=max(0, int(total)),
    )
    return {
        "total": max(0, int(total)),
        "escalator_count": escalator_count,
        "tier0_count": tier0_count,
        "state": state.value,
        "tone": domain_takeover_kpi_tone(state),
    }


def _last_real_edge(edges: Iterable[Mapping[str, Any]]) -> Mapping[str, Any] | None:
    """Return the last edge that is not a pure ``MemberOf`` traversal.

    MemberOf is structural — it never determines the compromise class.
    The classifier looks at the last edge that actually grants something.
    """
    last: Mapping[str, Any] | None = None
    for edge in edges:
        relation = str(edge.get("relation") or edge.get("kind_label") or "")
        if classify_edge_kind(relation) is EdgeKind.MEMBERSHIP:
            continue
        last = edge
    return last


def derive_compromise_class_from_path(
    path_edges: list[dict[str, Any]],
    target_node: Mapping[str, Any] | None,
) -> CompromiseClass:
    """Classify an attack path by its **last real edge**, not by flags.

    This is the canonical Phase 1 classifier. It implements the rule
    documented in ``12_nomenclature_standard.md`` (§ Fase 1, "Regla del
    clasificador"):

    * If the last non-membership edge is ``control``/``derived``/
      ``escalation`` and lands on a Tier 0 asset → ``DOMAIN_BREAKER``.
    * If the last non-membership edge is ``auth`` and lands on a Tier 0
      asset → ``TIER0_FOOTHOLD`` (NEW Phase 1 — fixes the HTB Forest
      false positive where ``CanPSRemote`` to a DC was wrongly flagged
      as Domain Breaker).
    * If the last edge is ``control``/``escalation`` and the target is a
      privileged-escalator group → ``PRIVILEGED_ESCALATOR``.
    * Else, if the path contains any known terminal technique (control,
      derived or escalation kind) at all → ``COMPROMISE_ENABLER``.
    * Otherwise → ``NONE``.

    Args:
        path_edges: Ordered list of edge dicts. Each edge MUST expose a
            ``relation`` field with the BloodHound (or ADscan synthetic)
            label. Other fields are ignored by this classifier.
        target_node: The terminal node dict. Used to read ``tier`` and
            ``name``. May be ``None`` when the caller only knows the
            edges (in which case Tier 0 detection is best-effort and the
            classifier falls back to ``COMPROMISE_ENABLER`` if the path
            ends with a terminal kind).

    Returns:
        The canonical :class:`CompromiseClass`. Coexists with
        :func:`derive_compromise_class` during Phase 1 — call-site
        migration to this API is Phase 2.
    """
    if not path_edges:
        return CompromiseClass.NONE

    last = _last_real_edge(path_edges)
    if last is None:
        # Path is pure-membership — structural, never a compromise class.
        return CompromiseClass.NONE

    relation = str(last.get("relation") or last.get("kind_label") or "")
    last_kind = classify_edge_kind(relation)
    target_tier = _node_tier(target_node)

    if last_kind in {EdgeKind.CONTROL, EdgeKind.DERIVED, EdgeKind.ESCALATION}:
        if target_tier == 0:
            # A control edge to a Tier-0 asset is a DOMAIN_BREAKER only when the
            # asset IS a direct domain compromise (the domain object, DA/EA/
            # Administrators/Schema Admins/DCs/krbtgt). Every other Tier-0 group
            # (GPCO, Cert Publishers, DnsAdmins, *Operators, …) is a compromise
            # ENABLER: controlling it requires a further abuse (create GPO, ADCS
            # ESC, DLL) to actually break the domain, so it must rank below the
            # direct domain-compromise paths. See spec
            # 2026-06-03-attack-path-terminal-ordering.md.
            if _is_direct_domain_breaker_target(target_node):
                return CompromiseClass.DOMAIN_BREAKER
            return CompromiseClass.PRIVILEGED_ESCALATOR
        if _is_privileged_escalator_target(target_node):
            return CompromiseClass.PRIVILEGED_ESCALATOR
        # Terminal kind but target is not Tier 0 nor an escalator group:
        # the path is still a confirmed enabler when it had any technique.
        return CompromiseClass.COMPROMISE_ENABLER

    if last_kind is EdgeKind.AUTH and target_tier == 0:
        return CompromiseClass.TIER0_FOOTHOLD

    # Auth edges to non-Tier-0, trust edges, unknown — none of these
    # constitute a domain-compromise classification on their own.
    if any(
        classify_edge_kind(str(edge.get("relation") or ""))
        in {EdgeKind.CONTROL, EdgeKind.DERIVED, EdgeKind.ESCALATION}
        for edge in path_edges
    ):
        return CompromiseClass.COMPROMISE_ENABLER

    return CompromiseClass.NONE


# ---------------------------------------------------------------------------
# Phase 3 — materializer wiring
# ---------------------------------------------------------------------------


# Mapping from canonical CompromiseClass to the legacy ``outcome_class`` /
# ``target_terminal_class`` strings consumed by:
#   * adscan_core.output._attack_paths (CLI table)
#   * adscan_internal.pro.reporting.attack_path_render (PDF report)
#   * adscan_internal.pro.reporting.html_pdf_generator (executive PDF)
#   * adscan_internal.pro.reporting.templates/premium/report.html
#
# We keep the legacy strings to avoid invalidating cached records and the
# whole compliance/reporting layer in one go. The new ``tier0_foothold``
# string is the only addition; the rest are preserved verbatim.
_COMPROMISE_CLASS_TO_OUTCOME: dict[CompromiseClass, str] = {
    CompromiseClass.DOMAIN_BREAKER: "direct_compromise",
    CompromiseClass.PRIVILEGED_ESCALATOR: "followup_terminal",
    CompromiseClass.TIER0_FOOTHOLD: "tier0_foothold",
    CompromiseClass.COMPROMISE_ENABLER: "graph_extension",
    CompromiseClass.NONE: "pivot",
}


def compromise_class_to_outcome_class(cls: CompromiseClass) -> str:
    """Return the legacy ``outcome_class`` string for a canonical class."""
    return _COMPROMISE_CLASS_TO_OUTCOME.get(cls, "pivot")


def _record_path_edges(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the path edges for one materialized record.

    Materialized records carry a ``relations`` list (BloodHound/ADscan
    labels) parallel to a ``nodes`` list. We rebuild a thin edge dict so
    the path-based classifier in
    :func:`derive_compromise_class_from_path` can run against the same
    contract as Phase 1/2 unit tests.
    """
    relations = record.get("relations")
    nodes = record.get("nodes")
    if not isinstance(relations, list):
        return []
    src_nodes: list[str] = []
    dst_nodes: list[str] = []
    if isinstance(nodes, list):
        for idx, _ in enumerate(relations):
            src_nodes.append(str(nodes[idx]) if idx < len(nodes) else "")
            dst_nodes.append(str(nodes[idx + 1]) if idx + 1 < len(nodes) else "")
    edges: list[dict[str, Any]] = []
    for idx, rel in enumerate(relations):
        edges.append(
            {
                "relation": str(rel or ""),
                "from": src_nodes[idx] if idx < len(src_nodes) else "",
                "to": dst_nodes[idx] if idx < len(dst_nodes) else "",
            }
        )
    return edges


def apply_path_based_classification(
    record: dict[str, Any],
    target_node: Mapping[str, Any] | None,
) -> CompromiseClass:
    """Stamp the canonical compromise class onto a materialized path record.

    This is the Phase 3 wiring helper invoked by the materializer right
    after :func:`_annotate_record_target_priority` has populated the
    target-node-derived fields (``target_priority_class``,
    ``target_terminal_class``, ``target_followup_status``).

    The path-based classifier is the single source of truth for the
    customer-facing compromise class. When it disagrees with the legacy
    target-node heuristic — e.g. an ``auth`` edge to a Tier 0 asset that
    the legacy heuristic would label ``direct_compromise`` — the
    path-based result wins.

    Mutates ``record`` in place by setting:

    * ``compromise_class``   — canonical :class:`CompromiseClass` value (str).
    * ``outcome_class``      — legacy outcome string consumed by renderers.
    * ``target_terminal_class`` — overridden when the new class disagrees
      with the legacy value, so downstream sort keys and section grouping
      reflect the new classification.

    Returns:
        The :class:`CompromiseClass` chosen by the path-based classifier.
    """
    edges = _record_path_edges(record)
    cls = derive_compromise_class_from_path(edges, target_node)
    outcome = compromise_class_to_outcome_class(cls)
    record["compromise_class"] = cls.value
    record["outcome_class"] = outcome
    # Override target_terminal_class so the existing sort keys and
    # section bucketing pick up the new classification. Only override when
    # the path classifier produced a non-NONE class — otherwise we keep
    # the target-node-derived value (which may legitimately be "pivot").
    if cls is not CompromiseClass.NONE:
        record["target_terminal_class"] = outcome
    return cls
