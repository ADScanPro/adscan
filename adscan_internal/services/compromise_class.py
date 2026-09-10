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

from adscan_internal.services.edge_kind import (
    ControlStrength,
    EdgeKind,
    classify_edge_kind,
    edge_control_strength,
)


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


# ADCS node kinds whose identity IS a Tier-0 escalation surface (axis 1). The
# collector emits these kinds (:data:`collector.models.NodeKind`): the
# Certification Authority objects (EnterpriseCA / RootCA / AIACA) and the
# certificate templates (CertTemplate). Reaching an ESC-vulnerable template or a
# CA is a one-technique path to domain compromise, so they grade
# ``tier0_escalation_capable`` from their kind — the SSOT no longer needs the
# collector's ``isTierZero`` side-flag to know a CA is Tier 0. NTAuthStore is the
# trust anchor, not itself an escalation target, so it is deliberately excluded.
_ADCS_ESCALATION_NODE_KINDS: frozenset[str] = frozenset(
    {"enterpriseca", "rootca", "aiaca", "certificationauthority", "certtemplate"}
)

# Directory CONTAINER kinds that are NOT security principals and therefore carry
# no granted Privilege Tier. Their tier must never be derived from a name match
# (the ``Domain Controllers`` OU is the canonical trap) — controlling a container
# is an edge-severity concern, not a tier the container itself holds.
_STRUCTURAL_CONTAINER_NODE_KINDS: frozenset[str] = frozenset({"ou", "container", "gpo"})


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
# HEURISTIC domain-assigned RIDs (Phase 2 / tier-label SSOT). The collector
# GUESSES these for DNSAdmins / Exchange because those groups have NO fixed
# well-known RID (unlike 512 Domain Admins). Because the guess is not a stable
# identity, matching a node's OWN rid against them mis-grades an ordinary USER
# that happens to hold that RID (measured: PETYER.BAELISH@...-1121 wrongly
# promoted). So they are gated to GROUP nodes only in
# :func:`_is_privileged_escalator_principal` — never applied to a User/Computer.
_HEURISTIC_ESCALATOR_GROUP_RIDS: frozenset[int] = frozenset({1101, 1119, 1121})


# Privileged-escalator GROUP RIDs whose membership owns the forest via ONE known
# technique (Tier 0 escalation-capable). RECONCILED (tier-label SSOT, 2026-09-09)
# to equal the collector's tier-zero target set minus the direct breakers — one
# reconciled definition DERIVED from the collector's frozenset so the two can
# never drift again. Adds GPCO 520, RODC-family 498/521, Cert Publishers 517,
# Key Admins 526/527, the Operators 548-551, Incoming Forest Trust Builders 557,
# and the heuristic Exchange/DNSAdmins RIDs 1101/1119/1121; 559 Performance Log
# Users / 562 Distributed COM Users / 569 Cryptographic Operators are included
# for BloodHound parity, NOT because they are direct escalators (see the client
# glossary basis + `classification_basis`). This MOVES the computed path set
# (measured Goad sevenkingdoms domain-all 44->46, Forest domain-all 722->725) via
# the `source_privilege_tier` decoration + the domain-listing collapse, so it
# ships WITH the deliberate Phase-2 snapshot re-baseline. Import is deferred to
# avoid a circular import at module load (privileged_group_classifier imports
# nothing from here, but the direction is kept lazy for safety).
def _reconciled_escalator_group_rids() -> frozenset[int]:
    """Return the collector's tier-zero escalation RID set (superset - breakers)."""
    from adscan_internal.services.privileged_group_classifier import (  # noqa: PLC0415
        _DIRECT_TIER_ZERO_RIDS,
        _TIER_ZERO_TARGET_RIDS,
    )

    return _TIER_ZERO_TARGET_RIDS - _DIRECT_TIER_ZERO_RIDS


_PRIVILEGED_ESCALATOR_GROUP_RIDS: frozenset[int] = _reconciled_escalator_group_rids()


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
    props = (
        node.get("properties") if isinstance(node.get("properties"), Mapping) else {}
    )
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
    props = (
        node.get("properties") if isinstance(node.get("properties"), Mapping) else {}
    )
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


def _is_privileged_escalator_principal(node: Mapping[str, Any] | None) -> bool:
    """Return whether *node* IS a Tier 0 escalation-capable group (axis 1).

    Matches the same two axes as :func:`_is_direct_domain_breaker_target`,
    against the same frozensets used everywhere else — the well-known group RID
    first (locale-independent), then the name with a trailing ``@domain`` label
    suffix stripped. No group list is duplicated; only the normalization
    differs.

    That normalization is why this is a separate function from
    :func:`_is_privileged_escalator_target` rather than a fix to it. An
    attack-graph node carries its identity as a LABEL
    (``DNSADMINS@ESSOS.LOCAL``), so the bare comparison in that predicate
    matches only the ``{"name": "DnsAdmins"}`` stub shape and never a real graph
    node. Widening it in place is the correct end state, but it feeds
    :func:`derive_compromise_class_from_path` and
    ``tier_lattice.domain_compromise_tier``, and raising an escalation group's
    rank in that total order changes which representative the domain-listing
    collapse keeps: measured on ``Goad-example``/``essos.local`` it traded ten
    distinct terminals (including a ``partial``, whose validated segment must
    never be hidden) for one. That is a path-engine change and belongs in its
    own measured change set, not in a reporting fix.
    """
    if not node:
        return False
    rid = _node_rid(node)
    if rid is not None and rid in _PRIVILEGED_ESCALATOR_GROUP_RIDS:
        # Trap #2 (tier-label SSOT): the HEURISTIC RIDs (DNSAdmins / Exchange,
        # 1101/1119/1121) are guessed per-domain and are NOT stable identities,
        # so they must match a GROUP node only — matching them on a User/Computer
        # node's OWN rid mis-grades an ordinary principal that happens to hold
        # that RID. The FIXED well-known escalator RIDs (520, 549, ...) are real
        # group RIDs and match regardless of the node's (sometimes unresolved)
        # kind.
        if rid in _HEURISTIC_ESCALATOR_GROUP_RIDS:
            if str(node.get("kind") or "").strip().lower() == "group":
                return True
        else:
            return True
    name = _node_name(node).strip().lower()
    if not name:
        return False
    return name.split("@", 1)[0].strip() in _PRIVILEGED_ESCALATOR_GROUP_NAMES


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


class TierBasis(str, Enum):
    """How a computer's :class:`PrivilegeTier` was inferred (axis-1 confidence).

    Tier 0 is deterministic (control-plane group membership / DC role) — a HIGH-
    confidence verdict. Tier 1 is heuristic (the current Microsoft AD DS tier
    model, updated 2026-05, states there is NO canonical AD attribute or group
    for Tier 1: "the credential and the keyboard define the tier, not the IP
    address" — it is org-assigned). ``tier_basis`` records WHICH signal produced a
    given verdict so the client report can declare Tier 1 as an inference and stay
    honest about it, and so a customer override is explainable.

    Only the non-Tier-0 refinement path carries a basis; a Tier 0 verdict from
    group membership or the DC fast-path needs none (it is deterministic).
    """

    #: Deterministic — control-plane group membership or the DC fast-path.
    TIER0_GROUP = "tier0_group"
    #: Heuristic Tier 1 — member server by OS/SPN role, no stronger signal.
    SERVER_HEURISTIC = "server_heuristic"
    #: Heuristic Tier 1, STRENGTHENED — publishes an application-class SPN
    #: (MSSQLSvc / Exchange / SharePoint), a positive "this is a real app server"
    #: signal beyond the generic every-server SPNs.
    APP_SPN = "app_spn"
    #: Tier 2 correction — a member server where ordinary users log on
    #: interactively (RDS / Citrix / Terminal server). Microsoft's #1 documented
    #: Tier-1 misclassification: these are Tier 2 clients despite being "Server".
    RDS_DOWNGRADE = "rds_downgrade"
    #: Tier 0 correction — a "server" that controls a Tier 0 asset (a jump server
    #: used to reach a DC, a hypervisor of a Tier-0 VM, a backup/EDR/monitoring
    #: agent with Tier-0 control). Microsoft: these are Tier 0, NOT Tier 1.
    TIER0_CONTROL = "tier0_control"


# Application-class SPN service classes: publishing one is a positive signal that
# a member server runs a real line-of-business application (Tier 1), beyond the
# generic SPNs EVERY domain-joined server carries. Matched case-insensitively
# against the service-class prefix (the token before the first ``/``).
#
# DELIBERATELY EXCLUDED — the generic SPNs on every server, which carry NO tier
# signal: HOST, WSMAN (every server exposes WinRM), TERMSRV (present on every
# server incl. DCs — see GOAD winterfell/braavos), RESTRICTEDKRBHOST, RPC, DNS,
# GC, LDAP, DFSR, CIFS. HTTP is INCLUDED — a bare HTTP SPN marks a Kerberos web
# endpoint (SharePoint / IIS app), a genuine application role, unlike WSMAN.
_APP_SERVER_SPN_CLASSES: frozenset[str] = frozenset(
    {
        "mssqlsvc",  # Microsoft SQL Server
        "exchangemdb",  # Exchange mailbox database
        "exchangeab",  # Exchange address book
        "exchangerfr",  # Exchange referral
        "http",  # SharePoint / IIS / any Kerberos web app
    }
)


def spns_indicate_app_server(spns: Iterable[str] | None) -> bool:
    """Return whether any SPN marks a member server as an application server.

    Reads the service-class prefix (token before the first ``/``) of each SPN and
    tests it against :data:`_APP_SERVER_SPN_CLASSES` (MSSQL / Exchange /
    SharePoint-HTTP). Generic every-server SPNs (HOST, WSMAN, TERMSRV,
    RestrictedKrbHost, RPC, DNS, GC, LDAP, DFSR) never match — they carry no tier
    signal. Case-insensitive; tolerant of ``None`` / non-string entries.

    Args:
        spns: The computer's ``serviceprincipalnames`` list, or ``None``.

    Returns:
        ``True`` iff at least one SPN is an application-class service.
    """
    if not spns:
        return False
    for spn in spns:
        if not spn:
            continue
        service_class = str(spn).split("/", 1)[0].strip().lower()
        if service_class in _APP_SERVER_SPN_CLASSES:
            return True
    return False


def refine_server_privilege_tier(
    base_tier: PrivilegeTier,
    *,
    controls_tier0_asset: bool = False,
    has_broad_interactive_logon: bool = False,
    has_app_server_spn: bool = False,
) -> tuple[PrivilegeTier, str | None]:
    """Refine a member server's heuristic Tier-1 verdict with graph signals.

    Axis 1 (GRANT tier). Grounded in the current Microsoft AD DS tier model
    (https://learn.microsoft.com/windows-server/identity/ad-ds/tier-model,
    updated 2026-05): a member server is Tier 1 by default, but three documented
    corrections apply, each detectable from collected graph edges. This function
    is PURE — the caller (collector-side or load-side stamp) derives the three
    boolean signals from the edges it holds and passes them in, mirroring how
    ``is_dc`` / ``is_server`` are already explicit inputs to
    :func:`privilege_tier_for_computer`.

    **Tier 0 is never touched.** A ``base_tier`` inside the Tier 0 boundary
    (DC / control-plane group membership) is deterministic and returned unchanged
    with basis :attr:`TierBasis.TIER0_GROUP`. A base ``TIER1`` (member server by
    OS) is refined; a base ``TIER2`` is refined ONLY when it publishes an
    application-class SPN (which itself proves it is a server, even with no OS
    string) — otherwise a plain workstation stays Tier 2. Precedence, highest-
    impact first:

    1. **controls_tier0_asset → Tier 0 (escalation-capable),
       :attr:`TierBasis.TIER0_CONTROL`.** The server holds a control / admin /
       exec / delegation edge onto a Tier 0 asset — a jump server used to reach a
       DC, a hypervisor of a Tier-0 VM, or a backup/EDR/monitoring agent with
       Tier-0 control. Microsoft is explicit these are Tier 0, NOT Tier 1.
       Graded escalation-capable (not direct): control OVER a Tier-0 asset is one
       technique from domain, not membership of a direct-breaker group.
    2. **has_broad_interactive_logon → Tier 2,
       :attr:`TierBasis.RDS_DOWNGRADE`.** A broad user population
       (Domain Users / Authenticated Users / Everyone) can log on interactively —
       an RDS / Citrix / Terminal server, which Microsoft classifies as a Tier 2
       CLIENT despite the "Server" OS. This is the single most common field
       Tier-1 misclassification. Superseded by (1): a jump server also carrying
       broad logon is still Tier 0 (controlling a DC outranks being a shared
       host).
    3. **Otherwise Tier 1**, with basis :attr:`TierBasis.APP_SPN` when the server
       publishes an application-class SPN (MSSQL / Exchange / SharePoint — a
       positive "real app server" signal), else :attr:`TierBasis.SERVER_HEURISTIC`
       (member server by OS role alone, the low-confidence default).

    Args:
        base_tier: The tier from :func:`privilege_tier_for_computer` (group
            membership + DC + server heuristic), refined only when it is
            ``TIER1``.
        controls_tier0_asset: The server has an outbound control/admin/exec/
            delegation edge onto a Tier 0 asset (jump-server / hypervisor / EDR
            over Tier 0). See the collector-side derivation.
        has_broad_interactive_logon: A broad user group can interactively log on
            to the server (RDS / Citrix), detected via a broad-group ``CanRDP``
            edge into it.
        has_app_server_spn: The server publishes an application-class SPN
            (:func:`spns_indicate_app_server`).

    Returns:
        A ``(PrivilegeTier, tier_basis)`` pair. ``tier_basis`` is a
        :class:`TierBasis` ``.value`` (or ``None`` when the base is Tier 2 with no
        server role, so the compact-artifact contract — no field for a plain
        Tier 2 — is preserved).
    """
    if base_tier.is_tier0:
        return base_tier, TierBasis.TIER0_GROUP.value

    # An application-class SPN (MSSQL / Exchange / SharePoint) is itself proof the
    # host is a server, even when the OS string is absent (the collector often
    # cannot read operatingSystem). So it PROMOTES a base Tier 2 (no OS-based
    # server detection) to a member server, in addition to strengthening an
    # already-detected server's confidence. This is conservative — only the
    # curated app-class SPN classes qualify, never the generic every-server SPNs.
    is_member_server = base_tier is PrivilegeTier.TIER1 or has_app_server_spn
    if not is_member_server:
        # Plain Tier 2 workstation with no server signal — no refinement applies
        # and no basis is recorded (keeps the artifact compact).
        return base_tier, None

    # Member server. Apply the corrections highest-impact-first.
    if controls_tier0_asset:
        return PrivilegeTier.TIER0_ESCALATION_CAPABLE, TierBasis.TIER0_CONTROL.value
    if has_broad_interactive_logon:
        return PrivilegeTier.TIER2, TierBasis.RDS_DOWNGRADE.value
    if has_app_server_spn:
        return PrivilegeTier.TIER1, TierBasis.APP_SPN.value
    return PrivilegeTier.TIER1, TierBasis.SERVER_HEURISTIC.value


#: Control strengths that count as ADMINISTERING a host BY GRANT (axis 1). A
#: principal holding one of these over a computer manages that computer, so its
#: effective tier is floored by that computer's tier. FULL = local admin
#: (``AdminTo``); CONDITIONAL_EXEC = DB sysadmin (``SQLAdmin``). SESSION
#: (CanRDP/CanPSRemote/ExecuteDCOM) and LOW (SQLAccess) are REACH, not grant —
#: they never promote the tier (that is axis-2 reach).
_ADMIN_GRANT_CONTROL_STRENGTHS: frozenset[ControlStrength] = frozenset(
    {ControlStrength.FULL, ControlStrength.CONDITIONAL_EXEC}
)


def relation_is_admin_grant(relation: str | None) -> bool:
    """Return whether an edge relation ADMINISTERS its target host BY GRANT.

    ``True`` for ``AdminTo`` (FULL local admin) and ``SQLAdmin`` (DB sysadmin) —
    the full-control grants that make a principal an administrator of the target,
    flooring the principal's effective Privilege Tier (axis 1). ``False`` for
    session/reach edges (CanRDP / CanPSRemote / ExecuteDCOM / SQLAccess), which
    are axis-2 reach and never promote the tier. Reuses the
    :func:`edge_control_strength` SSOT — no relation list is duplicated.
    """
    return edge_control_strength(relation) in _ADMIN_GRANT_CONTROL_STRENGTHS


def privilege_tier_for_principal_with_admin_assets(
    membership_tier: PrivilegeTier,
    administered_asset_tiers: Iterable[PrivilegeTier] | None = None,
) -> PrivilegeTier:
    """Return a principal's effective Tier: membership floored by administered assets.

    Axis 1 (GRANT tier). A principal's effective Privilege Tier is the HIGHEST
    tier of the assets it ADMINISTERS BY GRANT (AdminTo / SQLAdmin — full
    control, see :func:`relation_is_admin_grant`), floored by its own
    group-membership tier. This is Microsoft-documented, not novel: the current
    AD DS tier model defines Tier 1 as "member servers AND the identities that
    manage them", so a principal that administers a Tier-1 server IS Tier 1.

    **Group membership still wins (highest-impact-wins).** A Tier-0 principal
    stays Tier 0 regardless of what it administers — its membership tier already
    outranks any member server. Conversely a Tier-2 principal that is local admin
    over a Tier-1 app server is promoted to Tier 1; over only Tier-2 assets it
    stays Tier 2.

    **Scope discipline (axis 1 vs axis 2).** This ONLY floors by the administered
    asset's OWN granted tier. It deliberately does NOT auto-promote a principal to
    Tier 0 from an ``AdminTo`` onto a DC: reaching a Tier 0 asset by an access
    grant is an axis-2 REACH finding (``Tier0Foothold``), computed by the
    attack-path engine, not a change to the principal's axis-1 granted tier. So an
    administered Tier-0 asset floors the principal at most to Tier 0
    escalation-capable ONLY when it is already governed by membership — here we
    clamp the administered-asset contribution to Tier 1, because admin-over-a-DC
    is the axis-2 concern and must not silently reclassify the principal's grant.

    Args:
        membership_tier: The principal's tier from group membership
            (:func:`privilege_tier_for_principal`).
        administered_asset_tiers: The granted tiers of every computer the
            principal administers by grant (AdminTo / SQLAdmin). Empty / ``None``
            → the membership tier is returned unchanged.

    Returns:
        The effective :class:`PrivilegeTier` — the higher (by ``rank``) of the
        membership tier and the strongest administered-asset contribution.
    """
    effective = membership_tier
    if membership_tier.is_tier0:
        # A Tier 0 principal already outranks any member server it administers.
        return membership_tier
    for asset_tier in administered_asset_tiers or ():
        # Axis-1 clamp: admin over a Tier-0 asset does NOT promote the principal's
        # GRANT tier to Tier 0 — that is the axis-2 reach finding. It contributes
        # at most Tier 1 (managing infrastructure). A Tier-1 asset contributes
        # Tier 1; a Tier-2 asset contributes Tier 2.
        contribution = PrivilegeTier.TIER1 if asset_tier.is_tier0 else asset_tier
        if contribution.rank > effective.rank:
            effective = contribution
    return effective


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

    props = (
        node.get("properties") if isinstance(node.get("properties"), Mapping) else {}
    )
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


def privilege_tier_for_principal_node(
    node: Mapping[str, Any] | None,
    *,
    is_tier0_asset: bool = False,
) -> PrivilegeTier:
    """Return the :class:`PrivilegeTier` a user/group graph node IS GRANTED.

    The principal-side sibling of :func:`privilege_tier_for_computer_node`, for
    callers that hold an attack-graph node rather than a resolved membership
    closure. Grades against the SAME frozensets the path classifier and the tier
    lattice use — :func:`_is_direct_domain_breaker_target` then
    :func:`_is_privileged_escalator_principal` — so a group's tier is derived
    from one taxonomy. No group list is duplicated here.

    Without this, a caller holding only a node had no way to grade a group and
    fell back to the node's ``isTierZero``/``highvalue`` tag. That tag is a
    collector convenience, not the taxonomy: DnsAdmins ships untagged and would
    grade Tier 2 (it is Tier 0 escalation-capable), and Domain Admins ships
    tagged and would grade escalation-capable through the conservative fallback
    (it is Tier 0 direct). Both misreadings contradict the client glossary.

    Args:
        node: A BloodHound/ADscan-shaped principal node dict (``kind``,
            ``label``/``name``, ``objectId``). ``None`` or a non-mapping yields
            :attr:`PrivilegeTier.TIER2` — never raises.
        is_tier0_asset: Degraded Tier 0 signal the caller resolved outside group
            identity (an ``isTierZero``/``highvalue`` tag). Consulted only when
            neither detector matched, and then grades the conservative
            non-direct verdict.

    Returns:
        :attr:`PrivilegeTier.TIER0_DIRECT` for the domain object and the direct
        domain-breaker principals (Domain Admins, Enterprise Admins,
        BUILTIN\\Administrators, Domain Controllers, krbtgt, RID 500),
        :attr:`PrivilegeTier.TIER0_ESCALATION_CAPABLE` for an escalation group
        (DnsAdmins, Cert Publishers, Key Admins, the Operators, Exchange, …),
        else :attr:`PrivilegeTier.TIER2`.
    """
    if not isinstance(node, Mapping):
        return PrivilegeTier.TIER2
    if _is_direct_domain_breaker_target(node):
        return PrivilegeTier.TIER0_DIRECT
    if _is_privileged_escalator_principal(node):
        return PrivilegeTier.TIER0_ESCALATION_CAPABLE
    if is_tier0_asset:
        return PrivilegeTier.TIER0_ESCALATION_CAPABLE
    return PrivilegeTier.TIER2


def privilege_tier_for_node(
    node: Mapping[str, Any] | None,
    *,
    is_tier0_asset: bool = False,
) -> PrivilegeTier:
    """Return the granted :class:`PrivilegeTier` of ANY attack-graph node.

    The kind-dispatching front door over the two node resolvers above, so a
    caller holding a node dict does not have to know whether it is looking at a
    Computer, a user, a group or the Domain object. Domain objects are Tier 0
    direct by definition; Computers grade through
    :func:`privilege_tier_for_computer_node` (DC role / Tier-0-asset / server /
    workstation); everything else through
    :func:`privilege_tier_for_principal_node` (direct domain breaker →
    Tier 0 direct, escalation group → Tier 0 escalation-capable).

    No group list, RID set or name heuristic is introduced here — this only
    routes to the existing axis-1 SSOT.

    Args:
        node: A BloodHound/ADscan-shaped node dict, or ``None``.
        is_tier0_asset: Degraded Tier 0 signal the caller resolved outside group
            identity (``isTierZero`` / ``highvalue`` / an ADCS CA or Exchange
            role). Consulted only when group identity did not classify.

    Returns:
        The :class:`PrivilegeTier`; :attr:`PrivilegeTier.TIER2` for ``None``.
    """
    if not isinstance(node, Mapping):
        return PrivilegeTier.TIER2
    kind = str(node.get("kind") or "").strip().lower()
    if kind == "domain":
        return PrivilegeTier.TIER0_DIRECT
    if kind in _STRUCTURAL_CONTAINER_NODE_KINDS:
        # A directory CONTAINER — an OU, a generic Container, a GPO — is not a
        # security PRINCIPAL and has no granted Privilege Tier. Without this guard,
        # the ``Domain Controllers`` OU (kind=OU, a GUID objectid, no SID) matches
        # ``_is_direct_domain_breaker_target`` purely by its NAME and grades
        # Tier-0 direct, which then (via the stamped-label reader) mis-promotes the
        # container to a Tier-0 asset. Controlling a container is a real ACL
        # finding, but that is the EDGE's severity, not the container's own tier.
        return PrivilegeTier.TIER2
    if kind in _ADCS_ESCALATION_NODE_KINDS:
        # A CA or certificate template is a Tier-0 escalation surface by kind —
        # no group membership or collector side-flag needed. This closes GAP-C's
        # axis-1 half: an ADCS node's granted tier is derived from its identity.
        return PrivilegeTier.TIER0_ESCALATION_CAPABLE
    if kind == "computer":
        return privilege_tier_for_computer_node(node, is_tier0_asset=is_tier0_asset)
    return privilege_tier_for_principal_node(node, is_tier0_asset=is_tier0_asset)


def node_stamped_privilege_tier(node: Mapping[str, Any] | None) -> PrivilegeTier | None:
    """Return the :class:`PrivilegeTier` STAMPED on a graph node, or ``None``.

    Reads ``properties["privilege_tier"]`` (or the top-level ``privilege_tier``)
    written at collection time by the membership-aware stamp (Phase 1c,
    ``collector/persistence._stamp_privilege_tier_on_payloads``). This is the
    SSOT reader for Phase 2: it returns the tier a User/Computer was graded WITH
    its transitive group closure (GAP-B) and a Group/Domain/ADCS node was graded
    by its own identity — a signal a per-node bare resolver cannot reproduce for a
    Domain Admins MEMBER. Returns ``None`` when the node carries no stamp (an
    older graph, or a synthetic node), so callers fall back to the bare resolver.
    """
    if not isinstance(node, Mapping):
        return None
    raw = None
    props = (
        node.get("properties") if isinstance(node.get("properties"), Mapping) else None
    )
    if isinstance(props, Mapping):
        raw = props.get("privilege_tier")
    if raw is None:
        raw = node.get("privilege_tier")
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        return PrivilegeTier(raw.strip().lower())
    except ValueError:
        return None


def node_is_tier0_by_stamped_label(node: Mapping[str, Any] | None) -> bool:
    """Return whether a node's STAMPED ``privilege_tier`` places it in Tier 0.

    ``True`` iff the stamped label is ``tier0_direct`` or
    ``tier0_escalation_capable``. Returns ``False`` when the node carries no
    stamp (the caller decides the fallback). This is the label-based replacement
    for the legacy ``isTierZero`` flag read, consumed unconditionally by the
    attack-path engine's Tier-0 readers (``_node_is_tier0`` /
    ``_share_node_is_tier0`` in ``attack_graph_core``, ``_is_stamped_direct_breaker``
    in ``tier_lattice``).
    """
    tier = node_stamped_privilege_tier(node)
    return tier is not None and tier.is_tier0


def _node_group_tokens_for_kind(node: Mapping[str, Any]) -> tuple[str, ...]:
    """Return the SID + name tokens a group node contributes to a membership set.

    Both the group's SID (``objectId`` / ``properties.objectid``) and its name
    (``label`` / ``properties.name``) are emitted so the tier classifier's RID
    path (SID-only memberships, e.g. a computer in Cert Publishers) AND its name
    path (name-only groups, e.g. DnsAdmins / Exchange) both fire — mirroring the
    collector-side ``_classify_principals_by_membership._group_tokens``.
    """
    tokens: list[str] = []
    props = (
        node.get("properties") if isinstance(node.get("properties"), Mapping) else {}
    )
    sid = str((props or {}).get("objectid") or node.get("objectId") or "").strip()
    if sid:
        tokens.append(sid)
    name = str(
        (props or {}).get("name") or node.get("label") or node.get("name") or ""
    ).strip()
    if name:
        tokens.append(name)
    return tuple(tokens)


#: Well-known SIDs whose membership is the ENTIRE authenticated / user population
#: (RDS/Citrix downgrade signal). Mirrors the collector-side
#: ``inventory_persistence._BROAD_LOGON_WELL_KNOWN_SIDS``. Domain Users is matched
#: by its ``-513`` RID suffix; a scoped group (Remote Desktop Users) is NOT broad.
_BROAD_LOGON_WELL_KNOWN_SIDS: frozenset[str] = frozenset(
    {"S-1-1-0", "S-1-5-11", "S-1-5-32-545"}
)
#: Names of the broad populations, for graphs that key the source by name only.
_BROAD_LOGON_NAMES: frozenset[str] = frozenset(
    {"everyone", "authenticated users", "users", "domain users"}
)


def _graph_node_is_broad_logon_source(node: Mapping[str, Any] | None) -> bool:
    """Return whether a node is the whole authenticated / standard-user population.

    ``True`` for Everyone / Authenticated Users / BUILTIN\\Users / Domain Users —
    the broad populations whose ``CanRDP`` right marks an RDS / Citrix server. Reads
    the node's SID (``objectid`` / ``objectId``) and, as a fallback, its name/label.
    """
    if not isinstance(node, Mapping):
        return False
    props = (
        node.get("properties") if isinstance(node.get("properties"), Mapping) else {}
    )
    sid = str((props or {}).get("objectid") or node.get("objectId") or "").strip().upper()
    if sid:
        if sid in _BROAD_LOGON_WELL_KNOWN_SIDS or sid.endswith("-513"):
            return True
    name = str(
        (props or {}).get("name") or node.get("label") or node.get("name") or ""
    ).strip().lower()
    # Strip a trailing @domain to match "domain users@corp.local".
    name = name.split("@", 1)[0].strip()
    return name in _BROAD_LOGON_NAMES


def stamp_membership_aware_privilege_tier(graph: Mapping[str, Any]) -> None:
    """Stamp ``properties["privilege_tier"]`` on every graph node, in place.

    The MEMBERSHIP-AWARE tier SSOT for a persisted attack-graph dict (``nodes``
    keyed by node id, ``edges`` a list of ``{"from","to","relation"}``). This is
    the load-side counterpart to the collector-side
    ``collector.persistence._stamp_privilege_tier_on_payloads`` — it resolves the
    SAME thing (GAP-B) from the SAME source (the graph's own ``MemberOf`` edges)
    so a Domain Admins MEMBER grades ``tier0_direct`` via its transitive group
    closure, and a Backup Operators member grades ``tier0_escalation_capable`` —
    a signal the bare per-node resolver (which reads only a node's OWN identity)
    cannot reproduce.

    Reuses the tier-classification SSOT — :func:`privilege_tier_for_principal`
    (users) / :func:`privilege_tier_for_computer` (computers) fed the transitive
    group tokens, :func:`privilege_tier_for_node` (groups / Domain / ADCS on
    their own identity) — never a parallel tier taxonomy. The MemberOf closure
    itself is a cycle-safe walk over the graph's edges (the collector does the
    equivalent over ``result.edges``); the tier verdict is never re-derived here.

    Additive + idempotent: only WRITES ``privilege_tier`` (never removes another
    field) and skips a node that already carries a stamp, so re-running it is a
    no-op and it never changes a graph that already carries stamps.

    Args:
        graph: A parsed attack-graph dict. No-op when ``nodes`` is not a dict.
    """
    nodes = graph.get("nodes")
    if not isinstance(nodes, dict):
        return
    edges = graph.get("edges")

    # Build MemberOf parent adjacency by node id: principal/group -> {parent group}.
    # The edge from/to are node-dict keys, so the closure walks on ids directly.
    parents_by_id: dict[str, set[str]] = {}
    if isinstance(edges, list):
        for edge in edges:
            if not isinstance(edge, dict):
                continue
            if str(edge.get("relation") or "").strip() != "MemberOf":
                continue
            src = str(edge.get("from") or "").strip()
            dst = str(edge.get("to") or "").strip()
            if src and dst:
                parents_by_id.setdefault(src, set()).add(dst)

    def _expand_groups(start: str) -> set[str]:
        """Return every group node id reachable from ``start`` (cycle-safe)."""
        seen: set[str] = set()
        stack: list[str] = list(parents_by_id.get(start, ()))
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            stack.extend(parents_by_id.get(current, ()))
        return seen

    def _group_tokens(node_id: str) -> list[str]:
        tokens: list[str] = []
        for group_id in _expand_groups(node_id):
            group_node = nodes.get(group_id)
            if isinstance(group_node, Mapping):
                tokens.extend(_node_group_tokens_for_kind(group_node))
        return tokens

    # ── Edge-signal indices for the Tier-1 refinements (PART A + PART B) ──────
    # Mirror the collector-side derivation exactly, but keyed on graph NODE IDS
    # (the edge from/to are node-dict keys here, not necessarily SIDs).
    admin_grant_targets_by_src: dict[str, set[str]] = {}
    broad_logon_targets: set[str] = set()
    deleg_targets_by_src: dict[str, set[str]] = {}
    if isinstance(edges, list):
        for edge in edges:
            if not isinstance(edge, dict):
                continue
            relation = str(edge.get("relation") or "").strip()
            src = str(edge.get("from") or "").strip()
            dst = str(edge.get("to") or "").strip()
            if not src or not dst:
                continue
            if relation_is_admin_grant(relation):
                admin_grant_targets_by_src.setdefault(src, set()).add(dst)
            elif relation == "CanRDP" and _graph_node_is_broad_logon_source(
                nodes.get(src)
            ):
                broad_logon_targets.add(dst)
            elif relation == "AllowedToDelegate":
                deleg_targets_by_src.setdefault(src, set()).add(dst)

    from adscan_internal.services.computer_node_role import (  # noqa: PLC0415
        classify_computer_node_role,
    )

    def _graph_target_is_tier0(target_id: str, self_id: str) -> bool:
        """Return whether a target node is a Tier 0 asset (for PART A control)."""
        target = nodes.get(target_id)
        if not isinstance(target, Mapping) or target_id == self_id:
            return False
        if classify_computer_node_role(dict(target)) is not None:
            return True
        if node_is_tier0_by_stamped_label(target):
            return True
        tprops = (
            target.get("properties")
            if isinstance(target.get("properties"), Mapping)
            else {}
        )
        if bool(target.get("isTierZero")) or bool((tprops or {}).get("isTierZero")):
            return True
        # Tier-0 group membership via the target's OWN transitive closure.
        tier = privilege_tier_for_node(target, is_tier0_asset=False)
        if tier.is_tier0:
            return True
        cls = classify_principal_by_groups(
            _group_tokens(target_id),
            sid=str((tprops or {}).get("objectid") or target.get("objectId") or "")
            or None,
        )
        return _COMPROMISE_CLASS_TO_PRIVILEGE_TIER.get(
            cls, PrivilegeTier.TIER2
        ).is_tier0

    # Resolved computer tiers by node id — PASS 1 fills, PASS 2 (PART B) reads.
    computer_tier_by_id: dict[str, PrivilegeTier] = {}

    def _resolve_and_stamp_computer(node_id: str, node: dict[str, Any]) -> None:
        props = node.setdefault("properties", {})
        if not isinstance(props, dict):
            props = {}
            node["properties"] = props
        if props.get("privilege_tier") or node.get("privilege_tier"):
            # Already stamped — record the tier for PART B, never recompute.
            existing = node_stamped_privilege_tier(node)
            if existing is not None:
                computer_tier_by_id[node_id] = existing
            return
        sid = str(props.get("objectid") or node.get("objectId") or "").strip() or None
        is_tier0_flag = bool(node.get("isTierZero")) or bool(props.get("isTierZero"))
        os_str = str(
            props.get("os")
            or props.get("operatingsystem")
            or props.get("operatingSystem")
            or node.get("operatingsystem")
            or ""
        ).lower()
        # Mirror the collector-side computer stamp EXACTLY (DC fast-path wins).
        base_tier = privilege_tier_for_computer(
            group_names=_group_tokens(node_id),
            sid=sid,
            is_dc=classify_computer_node_role(dict(node)) is not None,
            is_tier0_asset=is_tier0_flag,
            is_server="server" in os_str,
        )
        controls_tier0 = any(
            _graph_target_is_tier0(t, node_id)
            for t in admin_grant_targets_by_src.get(node_id, set())
            | deleg_targets_by_src.get(node_id, set())
        )
        spns = (props or {}).get("serviceprincipalnames")
        refined_tier, basis = refine_server_privilege_tier(
            base_tier,
            controls_tier0_asset=controls_tier0,
            has_broad_interactive_logon=node_id in broad_logon_targets,
            has_app_server_spn=spns_indicate_app_server(
                spns if isinstance(spns, (list, tuple)) else None
            ),
        )
        computer_tier_by_id[node_id] = refined_tier
        props["privilege_tier"] = refined_tier.value
        if basis is not None:
            props["privilege_tier_basis"] = basis

    # ── PASS 1 — Computers (PART A) — before principals so PART B reads them ──
    for node_id, node in nodes.items():
        if not isinstance(node, dict):
            continue
        if str(node.get("kind") or "").strip().lower() == "computer":
            _resolve_and_stamp_computer(node_id, node)

    # ── PASS 2 — Users + all other node kinds ────────────────────────────────
    for node_id, node in nodes.items():
        if not isinstance(node, dict):
            continue
        kind = str(node.get("kind") or "").strip().lower()
        if kind == "computer":
            continue  # already stamped in PASS 1
        props = node.get("properties")
        if not isinstance(props, dict):
            props = {}
            node["properties"] = props
        if props.get("privilege_tier") or node.get("privilege_tier"):
            # Already stamped (a fresh scan, or a prior backfill) — never recompute.
            continue

        sid = str(props.get("objectid") or node.get("objectId") or "").strip() or None
        is_tier0_flag = bool(node.get("isTierZero")) or bool(props.get("isTierZero"))

        if kind == "user":
            tier = privilege_tier_for_principal(_group_tokens(node_id), sid=sid)
            if tier is PrivilegeTier.TIER2 and is_tier0_flag:
                # No resolvable Tier-0 membership but the collector flagged it
                # Tier-0 — honour the degraded signal via the node resolver
                # (conservative escalation-capable verdict, never a lost finding).
                tier = privilege_tier_for_principal_node(node, is_tier0_asset=True)
            # PART B — floor by the tier of the computers this user administers by
            # grant (AdminTo/SQLAdmin). Session/reach edges never entered the index.
            administered = [
                computer_tier_by_id[t]
                for t in admin_grant_targets_by_src.get(node_id, ())
                if t in computer_tier_by_id
            ]
            if administered:
                tier = privilege_tier_for_principal_with_admin_assets(
                    tier, administered
                )
        else:
            # Group / Domain / ADCS / container — tier is a property of the node's
            # own identity; the enriched node resolver already grades these.
            tier = privilege_tier_for_node(node, is_tier0_asset=is_tier0_flag)

        props["privilege_tier"] = tier.value


def is_structural_hierarchy_source(node: Mapping[str, Any] | None) -> bool:
    """Return whether an edge OUT of *node* is built-in AD hierarchy, not a finding.

    A principal that is ALREADY Tier 0 direct cannot escalate — every right it
    holds and every group it belongs to is how Active Directory is built. The
    rights such an edge represents are the product's own control plane:
    ``Domain Admins`` is a member of ``BUILTIN\\Administrators`` because Windows
    puts it there when the first DC is promoted, ``Domain Controllers`` holds
    the replication extended rights because that is what replication IS, and a
    DC computer account is a member of ``Domain Controllers`` because that is
    what makes it a DC. Telling a client to remove any of those is telling them
    to break their directory.

    This is the node-level restatement of the rule
    :func:`adscan_internal.services.severity.compute_edge_severity` already
    implements as Rule 1 (``source_compromise_class is DOMAIN_BREAKER`` →
    ``INFO``) and that CLAUDE.md § Nomenclature Standard states as hard rule 3
    (``Domain Breaker → anything`` = INFO, structural AD hierarchy, not a
    finding). It exists so the surfaces that hold a node but do not compute a
    severity — the choke-point classifier, the per-step remediation renderer —
    ask the SAME taxonomy instead of growing their own group list.

    An edge like this stays VISIBLE in the attack path: it is how the chain
    works, and hiding it would break the narrative. What it must not do is
    become a choke point, carry "remove it" advice, or grade above INFO. The
    exposure is upstream — at the step that lets a lower-tier principal reach
    this source in the first place.

    Args:
        node: The edge's SOURCE node (any kind), or ``None``.

    Returns:
        ``True`` when the source is already Tier 0 direct, else ``False``
        (including for ``None``, so a missing node never suppresses a real
        finding).
    """
    return privilege_tier_for_node(node) is PrivilegeTier.TIER0_DIRECT


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


# Axis 2, TERMINUS form — the same Compromise Reach axis worded as the thing a
# route ENDS AT: the last node of a chain diagram, the right-hand side of a path
# header, and the verdict banner under the steps. Those three used to be worded
# independently, which is how one page could head a route "MISSANDEI → DOMAIN
# ADMINS", draw its chain ending on a DOMAIN ADMINS node, and then close with
# "DOMAIN COMPROMISED" — three answers to one question. A route also has to
# terminate at an OUTCOME and never at a group or a technique name: naming the
# group as the destination breaks the nomenclature rule, and naming the
# technique ("… → ESC13") leaves the reader with something they cannot act on.
_COMPROMISE_TERMINUS_LABELS: dict[CompromiseClass, str] = {
    CompromiseClass.DOMAIN_BREAKER: "Domain Compromised",
    CompromiseClass.TIER0_FOOTHOLD: "Tier 0 Foothold",
    CompromiseClass.PRIVILEGED_ESCALATOR: "Tier 0 Group Takeover",
    CompromiseClass.COMPROMISE_ENABLER: "Stepping Stone to Tier 0",
    CompromiseClass.UNAUTHENTICATED_PRINCIPAL: "Unauthenticated Reach",
    CompromiseClass.NONE: "Standard Reach",
}


def compromise_terminus_label(cls: CompromiseClass) -> str:
    """Return the label for what a route of this class ENDS AT.

    The single source of truth for the chain's terminal node, the path header's
    destination, and the verdict banner — so a client reads one answer, not
    three. The :class:`CompromiseClass` argument is the PATH's class; this only
    translates it to wording, it never recomputes reach.
    """
    return _COMPROMISE_TERMINUS_LABELS.get(cls, "Standard Reach")


def compromise_terminus_label_for_key(value: str) -> str:
    """Return the terminus label for a raw ``compromise_class`` string.

    Convenience for renderers that carry the class as the plain string stamped
    on a path record rather than the enum. An unknown value falls back to the
    domain-breaker terminus, matching the report's own default for a path whose
    class did not resolve.
    """
    key = (value or "").strip().lower()
    for member in CompromiseClass:
        if member.value == key:
            return compromise_terminus_label(member)
    return compromise_terminus_label(CompromiseClass.DOMAIN_BREAKER)


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
                "Group Policy Creator Owners, the read-only Domain Controller "
                "groups, and the Exchange privileged groups; the Certification "
                "Authority and certificate templates."
            ),
            "meaning": (
                "Inside the Tier 0 boundary: not immediate domain ownership, "
                "but owns the forest through one known escalation technique "
                "(e.g. Backup Operators reading NTDS.dit)."
            ),
            # The classification-basis note (axis: escalation_technique vs
            # tooling_parity), derived from the collector follow-up mode so the
            # auditor question "why is Cryptographic Operators Tier 0?" has one
            # documented answer. Client-safe, native-tool-neutral prose.
            "basis": (
                "Most groups in this tier have a concrete single-step escalation "
                "to domain control. A small set (Cryptographic Operators, "
                "Distributed COM Users, Performance Log Users) is included for "
                "industry-tooling parity: they are flagged conservatively as "
                "Tier 0 even though no single-step domain-compromise technique is "
                "known for them today."
            ),
        },
        {
            "tier": PrivilegeTier.TIER1.value,
            "label": privilege_tier_label(PrivilegeTier.TIER1),
            "groups": (
                "Member servers (SQL, Exchange, SharePoint, line-of-business "
                "application servers) and the accounts that administer them."
            ),
            "meaning": (
                "Server and application plane. Controls business workloads "
                "and their data, but not the identity control plane."
            ),
            # Tier 1 has NO canonical AD attribute or group (unlike Tier 0). The
            # current Microsoft AD DS tier model states the tier is defined by
            # scope of control, not a static attribute, so ADscan infers it and
            # says so — the customer can override any Tier 1 verdict.
            "basis": (
                "Tier 1 is inferred, not read from a fixed attribute: a machine "
                "is graded Tier 1 from its server role (operating system and "
                "published service names such as SQL or Exchange), and an account "
                "is graded Tier 1 when it holds full administrative control over a "
                "Tier 1 server. A server where ordinary users log on interactively "
                "(a Remote Desktop or Citrix host) is treated as Tier 2, and a "
                "server that administers a Domain Controller or other Tier 0 asset "
                "is treated as Tier 0. These inferences are conservative and "
                "customer-overridable."
            ),
        },
        {
            "tier": PrivilegeTier.TIER2.value,
            "label": privilege_tier_label(PrivilegeTier.TIER2),
            "groups": "Standard user accounts and workstations.",
            "meaning": (
                "Standard user plane. No granted privilege over servers or "
                "the domain by membership alone — where an intrusion begins and "
                "what ADscan measures reach FROM."
            ),
        },
    ]


def tier_model_notes() -> list[dict[str, str]]:
    """Return the tier-model explanatory notes for the client glossary/legend.

    The companion prose to :func:`tier_glossary`: how ADscan's Tier 0/1/2 maps to
    the current Microsoft AD DS tier model, the confidence of each tier, and the
    optional Enterprise Access Model (EAM) plane mapping. SSOT for the CONTENT so
    the PDF report annex and any platform legend render the SAME text; client-safe,
    vendor-neutral, English. Each entry is a ``{"heading", "body"}`` string dict.
    """
    return [
        {
            "heading": "Confidence of each tier",
            "body": (
                "Tier 0 is determined deterministically from control-plane group "
                "membership and Domain Controller role, so it is a high-confidence "
                "classification. Tier 1 is inferred from server role and "
                "administrative control, because Active Directory has no fixed "
                "attribute for it; every Tier 1 verdict is a conservative "
                "inference and is customer-overridable."
            ),
        },
        {
            "heading": "How ADscan maps to Microsoft's tier model",
            "body": (
                "ADscan applies Microsoft's AD DS tier model. Tier 0 (the "
                "identity control plane) and Tier 1 (server and application "
                "administration) follow Microsoft's definitions directly. For "
                "Tier 2, ADscan uses the attack-path convention — every standard "
                "user account — because that is where an intrusion begins and what "
                "ADscan measures reach FROM. Microsoft's tier model is an "
                "administration framework; ADscan is an exposure framework, so the "
                "two describe the same boundary from different sides."
            ),
        },
        {
            "heading": "Enterprise Access Model mapping",
            "body": (
                "For teams that use Microsoft's newer Enterprise Access Model, the "
                "tiers map as follows: Tier 0 corresponds to the Control plane, "
                "Tier 1 to the Management and Data/Workload plane, and Tier 2 to "
                "User and Application access. Tier 0/1/2 remains the primary label "
                "throughout this report."
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


#: Everyone-/most-Tier-0 guard threshold. When the Tier-0 population is at least
#: this SHARE of the enabled domain-user population, the WHOLE domain is
#: effectively privileged — everyone-Tier-0 (all in Account/Print Operators, or a
#: bloated Domain Admins) is ~100% ransomware exposure BY CONSTRUCTION, so the KPI
#: is forced CRITICAL and never reads as a green baseline. Conservative default;
#: tune in the ransomware-exposure joint session.
_TIER0_DOMINANCE_THRESHOLD: float = 0.50


def domain_takeover_kpi_state(
    *,
    escalator_count: int,
    tier0_count: int,
    total: int,
    domain_user_count: int | None = None,
) -> DomainTakeoverKpiState:
    """Return the KPI severity state from the escalator / tier-0 / total counts.

    The colour rule (12_nomenclature_standard.md severity rules 1 and 2):

    * ``escalator_count >= 1``  -> :attr:`DomainTakeoverKpiState.CRITICAL`
      (an ordinary account can seize the domain — rule 2).
    * Tier-0 population dominates the enabled domain-user population
      (``tier0_count >= _TIER0_DOMINANCE_THRESHOLD * domain_user_count``)
      -> :attr:`DomainTakeoverKpiState.CRITICAL` (the everyone-Tier-0 guard).
    * ``escalator_count == 0`` and ``tier0_count >= 1``
      -> :attr:`DomainTakeoverKpiState.BASELINE` (only the expected admins —
      rule 1, Domain Breaker -> Domain = INFO).
    * ``total == 0`` -> :attr:`DomainTakeoverKpiState.CLEAN`.

    Driven by the ESCALATOR count, never the raw total: a domain with nine
    takeover-capable accounts that are all expected administrators is a clean
    baseline, not a red headline. The one exception is the everyone-/most-Tier-0
    guard: when (nearly) every domain user is ALREADY Tier-0, ``escalator_count``
    is zero (there are no lower-tier accounts left to escalate), yet the domain is
    the WORST possible ransomware posture — practically the entire population can
    encrypt the domain. Reading that as a green baseline is a client-risk
    misrepresentation, so a dominant Tier-0 share forces CRITICAL. The guard only
    engages when ``domain_user_count`` is known (``> 0``); callers that cannot
    supply the population keep the escalator-driven behaviour unchanged.

    Args:
        escalator_count: Lower-tier (Tier 1 + Tier 2) accounts with a validated
            domain-compromise path.
        tier0_count: Already-Tier-0 accounts with a domain-compromise path.
        total: The honest takeover blast radius (drives CLEAN only).
        domain_user_count: Enabled domain-user population, the denominator for the
            everyone-Tier-0 guard. ``None`` / ``<= 0`` disables the guard.

    Returns:
        The :class:`DomainTakeoverKpiState`.
    """
    if escalator_count >= 1:
        return DomainTakeoverKpiState.CRITICAL
    # Everyone-/most-Tier-0 guard: a dominant Tier-0 share is ~100% ransomware
    # exposure by construction — never a green baseline.
    if (
        domain_user_count is not None
        and domain_user_count > 0
        and tier0_count >= _TIER0_DOMINANCE_THRESHOLD * domain_user_count
    ):
        return DomainTakeoverKpiState.CRITICAL
    if tier0_count >= 1:
        return DomainTakeoverKpiState.BASELINE
    # total == 0 (or an inconsistent zero-escalator / zero-tier0 input): clean.
    return DomainTakeoverKpiState.CLEAN


def domain_takeover_kpi_segments(
    *,
    total: int,
    tier0: int,
    tier1: int,
    tier2: int,
    domain_user_count: int | None = None,
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
        domain_user_count: Enabled domain-user population — the denominator for
            the everyone-/most-Tier-0 guard in :func:`domain_takeover_kpi_state`.
            ``None`` / ``<= 0`` disables the guard (escalator-driven behaviour).

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
        domain_user_count=domain_user_count,
    )
    return {
        "total": max(0, int(total)),
        "escalator_count": escalator_count,
        "tier0_count": tier0_count,
        "state": state.value,
        "tone": domain_takeover_kpi_tone(state),
    }


#: Share of the enabled user population that must ALREADY hold Tier 0 before
#: privilege sprawl outranks path exposure as the headline. At one account in
#: four, "does the tier separation hold" has stopped being a meaningful
#: question — there is no separation left to hold — so the sprawl figure leads
#: and path exposure becomes the second line.
_TIER0_SPRAWL_SHARE: float = 0.25

#: Absolute floor paired with the share, so a small directory cannot trip the
#: precedence rule on arithmetic alone. Every domain carries a built-in
#: Administrator, so a ten-account directory reads 10% Tier 0 before anybody has
#: done anything wrong, and the local sample tops out at 15% (two Tier 0
#: accounts against eleven to seventeen Tier 2) on perfectly ordinary shapes.
#: Five is also already past Microsoft's guidance for the direct control-plane
#: groups, which is that they hold a handful of accounts and that Enterprise and
#: Schema Admins sit empty outside forest operations — so a directory clearing
#: BOTH tests is outside published guidance on both axes at once, not merely
#: small.
_TIER0_SPRAWL_FLOOR: int = 5


def derive_tier0_population_stat(
    *,
    tier0: int,
    domain_user_count: int,
    tier0_direct: int | None = None,
) -> dict[str, Any]:
    """Derive the Tier 0 PRIVILEGE SPRAWL figure — how many accounts already ARE Tier 0.

    The companion to :func:`derive_ordinary_breaker_stat`, and the reason that
    function is honest. The two answer different questions and a domain needs
    both:

    * Sprawl (here): *do you have tiering at all?* How many accounts hold the
      control plane by membership, needing no attack path because they are
      already the destination.
    * Path exposure (there): *does your tiering hold?* How many ordinary
      accounts reach the control plane through a route ADscan found.

    **Why they cannot be one number.** Excluding the already-privileged accounts
    from the path metric is only defensible while their count is reported
    beside it — otherwise the exclusion does not clean the figure, it hides the
    population. A domain of a hundred where forty are Domain Admins might show
    little path exposure and still be catastrophically compromised: forty people
    do not need a route to the destination when they are the destination. And in
    a directory where every account sits in a Tier-0 escalation group — Account
    Operators is the real-world case, a legacy group Microsoft documents as one
    that should stay empty and almost nobody empties — the path metric has no
    denominator at all and would otherwise print "0 of 0" against the most
    severe finding available.

    A single blended figure was considered and rejected: (already privileged +
    reached by a path) over the population is one number and is honest about
    magnitude, but it makes a directory whose fix is one certificate template
    read identically to one whose fix is an eighteen-month identity-governance
    programme. The two carry different remediation owners and different time
    horizons, so collapsing them yields a figure a CISO cannot assign to
    anybody.

    **Precedence.** ``leads`` is the rule: when sprawl is pathological it is the
    headline and path exposure is the indented second line, because asking
    whether a separation holds is moot where there is no separation. It is
    pathological when the share reaches :data:`_TIER0_SPRAWL_SHARE` AND the
    count reaches :data:`_TIER0_SPRAWL_FLOOR`, or unconditionally when the
    ordinary population is empty (there is nothing left for the path metric to
    measure).

    **One trigger, two headlines — and deliberately not two thresholds.** Forty
    Domain Admins and forty Print Operators are both bad and not identically
    bad: the first forty already hold domain control, the second forty are one
    known technique away (Print Operators can load a driver on a domain
    controller, which is SYSTEM). ADscan's prioritisation rule is that
    directness, not tier, drives weight — so the two get DIFFERENT wording, via
    ``dominant_kind``. They do not get different precedence thresholds, because
    precedence answers one narrow question: is the path-exposure figure still
    meaningful? It is moot for the same reason in both cases. Every one of those
    accounts is already inside the containment boundary, so measuring whether
    they can *reach* it measures nothing — a Print Operator does not need the
    route ADscan enumerates, it has a shorter one the graph never draws.

    Args:
        tier0: Enabled accounts that ARE Tier 0, by group membership.
        domain_user_count: The enabled user population.
        tier0_direct: How many of ``tier0`` hold Tier 0 DIRECTLY (Domain Admins,
            Enterprise Admins, BUILTIN\\Administrators, RID 500). The remainder
            are escalation-capable (Account/Print/Server/Backup Operators,
            DnsAdmins, …). ``None`` leaves the split unknown and the wording
            falls back to the neutral form.

    Returns:
        A flat dict every surface renders directly: ``tier0_count``,
        ``tier0_direct`` / ``tier0_escalation_capable``, ``dominant_kind``,
        ``ordinary_count`` (the population that can be exposed), ``pct``,
        ``leads``, ``degenerate`` (no ordinary population at all) and
        ``available``.
    """
    count = max(0, int(tier0))
    total = max(0, int(domain_user_count))
    direct = min(count, max(0, int(tier0_direct))) if tier0_direct is not None else None
    escalation = (count - direct) if direct is not None else None
    ordinary = max(0, total - count)
    pct = round(count / total * 100.0, 1) if total > 0 else 0.0
    degenerate = total > 0 and ordinary == 0
    leads = bool(
        total > 0
        and count > 0
        and (
            degenerate
            or (count >= _TIER0_SPRAWL_FLOOR and pct >= _TIER0_SPRAWL_SHARE * 100.0)
        )
    )
    if direct is None:
        dominant = "unknown"
    elif direct >= (escalation or 0):
        dominant = "direct"
    else:
        dominant = "escalation_capable"
    return {
        "tier0_count": count,
        "tier0_direct": direct,
        "tier0_escalation_capable": escalation,
        "dominant_kind": dominant,
        "ordinary_count": ordinary,
        "domain_user_count": total,
        "pct": pct,
        "leads": leads,
        "degenerate": degenerate,
        "available": total > 0 and count > 0,
    }


def derive_ordinary_breaker_stat(
    *, tier0: int, tier1: int, tier2: int, domain_user_count: int
) -> dict[str, Any]:
    """Derive the tier-aware, NON-CIRCULAR ordinary-account domain-compromise stat.

    This is the SSOT for the domain-breaker blast-radius HEADLINE both the PDF
    report and the web dashboard render. It answers the question a CISO actually
    cares about: how many ORDINARY (non-Tier-0) domain users hold a validated
    path to FULL domain compromise, out of the total ordinary domain population.

    Why exclude the already-Tier-0 accounts. When the domain-compromise path
    originates at a broad group (Domain Users / Authenticated Users), 100% of
    domain users "hold" the path — including the handful of accounts that ARE
    the domain (Domain Admins, the built-in Administrator, the DC computer
    accounts). Counting "they have a path TO compromising the domain" for an
    account that already IS Tier 0 is circular: it inflates and confuses the
    headline. The finding is the ordinary users, so the numerator and the
    denominator both drop the Tier-0 population.

    Denominator. ``ordinary_total`` is the domain's non-Tier-0 user population,
    ``domain_user_count - tier0``. When the whole domain is in scope (the broad
    group case), the affected Tier-0 count equals the domain's Tier-0 count, so
    ``domain_user_count - tier0`` equals the ordinary users that hold the path
    and the stat reads X of X (100% of non-administrative accounts). In a
    partial-scope case the affected Tier-0 count is a lower bound of the
    domain's Tier-0 population, so the denominator is an upper bound of the true
    ordinary total — a conservative percentage that never overstates the alarm.
    The denominator is floored at ``ordinary_with_breaker`` so a degenerate
    input (unknown / zero ``domain_user_count``) can never report more affected
    than the population.

    Args:
        tier0: Tier-0 accounts with a validated domain-compromise path (the
            already-privileged baseline, i.e. the compromise target itself).
        tier1: Tier-1 accounts with a validated domain-compromise path.
        tier2: Tier-2 accounts with a validated domain-compromise path.
        domain_user_count: Total enabled domain users (the population). ``0`` /
            unknown disables the percentage denominator gracefully.

    Returns:
        A flat dict both surfaces render directly:

        * ``ordinary_with_breaker`` — ``tier1 + tier2`` (the FINDING numerator:
          non-administrative accounts with a full-compromise path).
        * ``ordinary_total`` — the denominator (non-Tier-0 domain population).
        * ``pct_non_admin`` — ``ordinary_with_breaker / ordinary_total * 100``.
        * ``total_with_breaker`` — ``tier0 + tier1 + tier2`` (context: every
          account with the path, ordinary + already-privileged).
        * ``tier0_with_breaker`` — ``tier0`` (context: already-privileged, the
          compromise target itself — never the alarming number).
        * ``tier_breakdown`` — ``{tier0, tier1, tier2}`` echoed (the tuple the
          web-mirror contract test compares against).
        * ``available`` — whether there is anything to render. Requires an
          ORDINARY POPULATION, not merely some affected account: a domain where
          every enabled account already holds Tier 0 has no denominator for this
          question, and the figure must go silent rather than print "0 of 0" or
          a percentage of nothing. That shape is real — a production domain
          where every user sat in Print Operators — and it is where the two
          individually-correct behaviours combine badly: the group rightly
          produces a finding, and this metric would rightly have nothing to say,
          exactly when the finding is most severe. Silence here is what forces
          the sprawl figure (:func:`derive_tier0_population_stat`) to take the
          headline.
    """
    t0 = max(0, int(tier0))
    t1 = max(0, int(tier1))
    t2 = max(0, int(tier2))
    total_users = max(0, int(domain_user_count))
    ordinary_with_breaker = t1 + t2
    ordinary_total = max(total_users - t0, ordinary_with_breaker)
    pct_non_admin = (
        round(ordinary_with_breaker / ordinary_total * 100.0, 1)
        if ordinary_total > 0
        else 0.0
    )
    return {
        "ordinary_with_breaker": ordinary_with_breaker,
        "ordinary_total": ordinary_total,
        "pct_non_admin": pct_non_admin,
        "total_with_breaker": t0 + t1 + t2,
        "tier0_with_breaker": t0,
        "tier_breakdown": {"tier0": t0, "tier1": t1, "tier2": t2},
        "available": (t0 + t1 + t2) > 0 and ordinary_total > 0,
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


# The inverse of the table above, plus the OLDER legacy spellings that predate
# it and still appear in cached/synthetic records. Two distinct legacy
# vocabularies exist and they are NOT interchangeable: the renderer strings
# (``direct_compromise`` / ``followup_terminal`` / ``graph_extension``) and the
# pre-canonical taxonomy (``direct_domain_control`` / ``domain_compromise_enabler``
# / ``high_impact_privilege``). Any consumer that keys a table on the canonical
# class name must normalise through here first — the compliance annex did not,
# so every ``domain_breaker`` path (including the only chain executed end to end)
# silently missed its controls while the handful of classes that happen to share
# a spelling were the only evidence the annex ever showed.
_OUTCOME_CLASS_TO_COMPROMISE_CLASS: dict[str, CompromiseClass] = {
    # Renderer strings emitted by ``compromise_class_to_outcome_class``.
    "direct_compromise": CompromiseClass.DOMAIN_BREAKER,
    "followup_terminal": CompromiseClass.PRIVILEGED_ESCALATOR,
    "tier0_foothold": CompromiseClass.TIER0_FOOTHOLD,
    "graph_extension": CompromiseClass.COMPROMISE_ENABLER,
    "pivot": CompromiseClass.NONE,
    # Pre-canonical taxonomy.
    "direct_domain_control": CompromiseClass.DOMAIN_BREAKER,
    "domain_compromise_enabler": CompromiseClass.PRIVILEGED_ESCALATOR,
    "high_impact_privilege": CompromiseClass.PRIVILEGED_ESCALATOR,
    # Canonical names, so the resolver accepts either vocabulary.
    "domain_breaker": CompromiseClass.DOMAIN_BREAKER,
    "privileged_escalator": CompromiseClass.PRIVILEGED_ESCALATOR,
    "compromise_enabler": CompromiseClass.COMPROMISE_ENABLER,
    "unauthenticated_principal": CompromiseClass.UNAUTHENTICATED_PRINCIPAL,
    "none": CompromiseClass.NONE,
}


def compromise_class_from_outcome_class(value: str | None) -> CompromiseClass | None:
    """Return the canonical class for a legacy ``outcome_class`` string.

    The documented inverse of :func:`compromise_class_to_outcome_class`, widened
    to accept the pre-canonical taxonomy and the canonical names themselves.
    Returns ``None`` for an unrecognised value so a caller can decide whether to
    fall back rather than silently getting ``NONE``.
    """
    if not value:
        return None
    return _OUTCOME_CLASS_TO_COMPROMISE_CLASS.get(str(value).strip().lower())


def resolve_record_compromise_class(record: Mapping[str, Any]) -> CompromiseClass:
    """Return the canonical compromise class for one attack-path record.

    Prefers the engine-stamped ``compromise_class``; falls back to normalising
    ``outcome_class`` for legacy/synthetic records. Mirrors the precedence
    already used by ``exposure_score_service.report_tier_for_record``, so every
    consumer reads a path's class the same way.
    """
    if not isinstance(record, Mapping):
        return CompromiseClass.NONE
    resolved = compromise_class_from_outcome_class(record.get("compromise_class"))
    if resolved is not None:
        return resolved
    details = record.get("details")
    fallback = record.get("outcome_class")
    if not fallback and isinstance(details, Mapping):
        fallback = details.get("outcome_class")
    resolved = compromise_class_from_outcome_class(fallback)
    return resolved if resolved is not None else CompromiseClass.NONE


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
