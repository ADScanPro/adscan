"""What a client can actually change about one attack-graph edge — and how.

Every remediation surface ADscan ships (the free exposure report's choke-point
table, the paid deliverable's technique priorities, the web CTEM's remediation
page) has to answer one question before it prints a row: *can the client change
this, and what is the change?* This module is the single source of truth for
that answer.

WHY THIS EXISTS
---------------
The predicate it replaces, :func:`~adscan_internal.services.edge_kind.is_structural_relation`,
answers it from the RELATION NAME alone — every ``MemberOf`` is unfixable, every
``DCSync`` is fixable. Measured across the attack graphs on the development
machine, that is wrong in both directions:

* Of 85 distinct ``MemberOf`` instances traversed by ranked paths, **41 are
  discretionary** — "remove this account from this group", the most common
  remediation in Active Directory — and all 85 were suppressed. The split is not
  built-in-versus-custom either: primary-group membership (``… → DOMAIN USERS``)
  and a domain controller's membership of ``DOMAIN CONTROLLERS`` are equally
  non-discretionary despite one endpoint being an ordinary object.
* Of 109 ``DCSync`` instances, 92 originate from a built-in administrative group
  and the remaining 17 from a **domain controller's machine account**. Directory
  replication is how a DC works; the right cannot be removed from it. Yet
  ``DCSync`` ranked as the client's first remediation at 39% of all paths.

So the verdict belongs to the EDGE INSTANCE, not the relation, and it must carry
the fix rather than a boolean: "remediable: yes" is worth much less to the reader
than "remediable by removing a group membership" versus "remediable by dropping a
linked server", and the report needs that sentence anyway.

NEVER CLASSIFY BY DISPLAY NAME
------------------------------
``MEEREEN$`` carries nothing in its name to say it is a domain controller, and
``USUARIOS DEL DOMINIO`` is ``Domain Users`` on a Spanish-locale DC. Every rule
here keys on a structural signal:

* the object SID — a synthetic well-known SID (``S-1-1-0``, ``S-1-5-11``), a
  ``BUILTIN`` alias (``S-1-5-32-544``), or a domain RID below 1000;
* ``primaryGroupID`` (513 Domain Users, 515 Domain Computers, 516 Domain
  Controllers, 521 Read-only Domain Controllers);
* the domain-controller role of a Computer node, via the existing pure SSOT
  :func:`~adscan_internal.services.computer_node_role.classify_computer_node_role`
  (``primaryGroupID`` 516/521, the local ``krbtgt`` SPN, the RODC UAC bit);
* the Privilege Tier a principal's own SID grants it, via the existing SSOT
  :func:`~adscan_internal.services.compromise_class.privilege_tier_for_principal`.

A node that carries a resolvable SID is never classified by its label. Nodes
without one fall back to the conservative verdict (not remediable), because
inventing a fix for an object we cannot identify is worse than staying quiet.

.. note::

   ``userAccountControl`` is NOT stamped on graph nodes by the collector (checked
   across every workspace on the development machine), so the
   ``SERVER_TRUST_ACCOUNT`` bit is unavailable here. ``primaryGroupID`` is present
   on every LDAP-collected user and computer and carries the same fact, and
   ``classify_computer_node_role`` already reads the RODC UAC bit when it is
   present. Do not add a rule that depends on a field the collector does not write.

RELATION TO ``is_structural_relation``
--------------------------------------
That predicate stays exactly as it is. It is load-bearing for edge-KIND
classification — ``exposure_score_service._path_exploitability`` reads it through
``classify_relation_support``, and the frontend mirrors it — and changing it would
move the exposure score, which is a different question from remediability. This
module is a second, instance-level predicate beside it, not a replacement for it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any, Final


__all__ = [
    "PrincipalFacts",
    "Remediability",
    "RemediationKind",
    "HOST_SCOPED_RELATIONS",
    "chain_execution_host",
    "chain_host_for_step",
    "classify_edge_remediability",
    "principal_facts_from_node",
    "refine_chain_remediability",
    "remediability_for_step",
    "remediability_in_chain",
]


class RemediationKind(str, Enum):
    """The SHAPE of the change a client would make, not the change itself.

    Two edges can both be remediable and still need different sentences, a
    different owner and a different change window: revoking an ACE is a directory
    permission change, dropping a linked server is a database change, and
    patching is a maintenance window. Grouping by kind is what lets a roadmap
    batch the work the same team does in one sitting.
    """

    #: Take a principal out of a group (domain group, or a local group on a host).
    MEMBERSHIP_REMOVAL = "membership_removal"
    #: Remove an access-control entry from an object's security descriptor.
    ACL_REVOCATION = "acl_revocation"
    #: Change a setting/attribute that produces the edge, rather than the edge.
    CONFIG_CHANGE = "config_change"
    #: Apply a vendor security update.
    PATCH = "patch"
    #: Rotate or stop exposing a secret.
    CREDENTIAL_ROTATION = "credential_rotation"
    #: Remove a configured service/link entirely.
    SERVICE_REMOVAL = "service_removal"
    #: Nothing the client can change closes this edge.
    NOT_REMEDIABLE = "not_remediable"


@dataclass(frozen=True)
class Remediability:
    """Whether one edge instance can be changed, and the change if it can.

    Attributes:
        kind: The :class:`RemediationKind`.
        verb: One imperative sentence naming the concrete change, with the real
            principal names interpolated ("Remove BB.MORGAN@RUSTYKEY.HTB from
            IT@RUSTYKEY.HTB"). Empty only when no names were resolvable.
        why_not: Why the client cannot change it. Set only when
            :attr:`kind` is ``NOT_REMEDIABLE``; this is the sentence a report
            prints instead of a fix, so it is written for the client.
        inherent: True when the edge is how Active Directory works for THIS
            holder (a domain controller's replication right, a child domain's
            reach into its forest root, a built-in nesting), so a report may
            tell the client "no change needed, by design". False for a
            non-remediable edge whose fix lives on another step (a logon
            session), which is not by design.
    """

    kind: RemediationKind
    verb: str = ""
    why_not: str = ""
    inherent: bool = False

    @property
    def is_remediable(self) -> bool:
        """Return True when this edge may be offered to the client as a fix."""
        return self.kind is not RemediationKind.NOT_REMEDIABLE

    def as_dict(self) -> dict[str, Any]:
        """Return the JSON-safe form stamped onto an attack-path step.

        ``inherent`` is written only when set, so every stamp that is not a
        by-design verdict keeps the shape it always had.
        """
        stamped: dict[str, Any] = {
            "kind": self.kind.value,
            "verb": self.verb,
            "why_not": self.why_not,
        }
        if self.inherent:
            stamped["inherent"] = True
        return stamped

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any] | None) -> "Remediability | None":
        """Rebuild from the stamped form; ``None`` when the stamp is unusable."""
        if not isinstance(raw, Mapping):
            return None
        token = str(raw.get("kind") or "").strip().lower()
        if not token:
            return None
        try:
            kind = RemediationKind(token)
        except ValueError:
            return None
        return cls(
            kind=kind,
            verb=str(raw.get("verb") or ""),
            why_not=str(raw.get("why_not") or ""),
            inherent=bool(raw.get("inherent")),
        )


# ── Structural identity of one graph node ─────────────────────────────────────


#: Synthetic well-known principals with no member list anyone can edit. Windows
#: computes membership of these at logon; there is no group object to modify.
_SYNTHETIC_WELL_KNOWN_SIDS: Final[frozenset[str]] = frozenset(
    {
        "S-1-0-0",  # Nobody
        "S-1-1-0",  # Everyone
        "S-1-5-2",  # Network
        "S-1-5-4",  # Interactive
        "S-1-5-6",  # Service
        "S-1-5-7",  # Anonymous Logon
        "S-1-5-9",  # Enterprise Domain Controllers
        "S-1-5-10",  # Principal Self
        "S-1-5-11",  # Authenticated Users
        "S-1-5-14",  # Remote Interactive Logon
        "S-1-5-17",  # IUSR
        "S-1-5-18",  # Local System
        "S-1-5-19",  # Local Service
        "S-1-5-20",  # Network Service
    }
)

#: Group RIDs that are a member's PRIMARY group. Windows refuses to remove a
#: principal from its primary group, so the membership is not a fix.
#: 513 Domain Users · 515 Domain Computers · 516 Domain Controllers ·
#: 521 Read-only Domain Controllers.
_PRIMARY_GROUP_RIDS: Final[frozenset[int]] = frozenset({513, 515, 516, 521})

#: Directory-replication rights. Domain controllers and the domain's built-in
#: administrative groups hold these by design.
_REPLICATION_RELATIONS: Final[frozenset[str]] = frozenset(
    {"dcsync", "getchanges", "getchangesall", "getchangesinfilteredset"}
)

#: Below this, a domain RID is a built-in / well-known object Windows ships.
_BUILTIN_RID_CEILING: Final[int] = 1000


@dataclass(frozen=True)
class PrincipalFacts:
    """The structural identity of one attack-graph node.

    Built by :func:`principal_facts_from_node`. Every field is read from the
    object itself — never from its display name — so the rules below hold on a
    non-English domain.
    """

    #: Display label, used ONLY to compose the remediation sentence.
    label: str = ""
    #: Real sAMAccountName from the node, when the collector resolved it. Carries
    #: the correct human casing (``michael.wrightson`` / ``Backup Operators``) the
    #: prose helper prefers over the (usually shouting) label.
    samaccountname: str = ""
    #: ``objectId`` — a SID for a security principal, a GUID for a container.
    object_id: str = ""
    #: Lower-cased node kind (``user`` / ``computer`` / ``group`` / ``domain`` …).
    kind: str = ""
    #: Trailing RID of a domain (``S-1-5-21-…-<RID>``) or ``BUILTIN`` SID.
    rid: int | None = None
    #: ``primaryGroupID``, when the collector resolved it.
    primary_group_id: int | None = None
    #: True for a ``S-1-5-32-*`` alias.
    is_builtin_alias: bool = False
    #: True for a synthetic well-known principal with no editable member list.
    is_synthetic_well_known: bool = False
    #: True when the node is a writable DC or an RODC (node-role SSOT).
    is_domain_controller: bool = False
    #: True when the principal's OWN SID grants Tier 0 — direct (Domain Admins,
    #: Enterprise Admins, BUILTIN\\Administrators, Domain Controllers, RID
    #: 500/502, the domain object itself).
    is_direct_tier0: bool = False
    #: True when the graph stamped this node's compromise class in the direct
    #: band (``domain_breaker`` / ``tier0_control``): a member of Domain Admins,
    #: for one. This is the signal the severity grade reads for its "source
    #: already controls the domain" rule, read here through the same predicate
    #: (:func:`~adscan_internal.services.compromise_class.is_direct_tier0_control_class`).
    stamped_domain_control: bool = False
    #: True when the principal sits anywhere inside the Tier 0 boundary: direct,
    #: or escalation-capable (the Operators, DnsAdmins, Cert Publishers, the
    #: Exchange groups), from the stamped ``privilege_tier`` or its own identity.
    is_tier0: bool = False
    #: True for one of the Exchange security groups (the ``compromise_class``
    #: list, never a copy of it).
    is_exchange_group: bool = False
    #: True for the organisational unit Exchange setup creates for its groups.
    is_exchange_container: bool = False
    #: True when AdminSDHolder protects the object: ``adminCount`` is set, or its
    #: own SID is one of the protected accounts and groups. Default delegations
    #: (Account Operators) do not reach these objects.
    is_adminsdholder_protected: bool = False
    #: True when a computer is a member of Cert Publishers, which is how a host
    #: running an enterprise certification authority is recorded.
    hosts_certificate_authority: bool = False
    #: Lower-cased DNS domain the object belongs to, when the node records it.
    domain: str = ""

    @property
    def has_sid(self) -> bool:
        """True when the node carries a resolvable security identifier."""
        return self.object_id.upper().startswith("S-1-")

    @property
    def is_builtin(self) -> bool:
        """True for an object Windows ships: a BUILTIN alias or a RID below 1000."""
        if self.is_builtin_alias:
            return True
        return self.rid is not None and self.rid < _BUILTIN_RID_CEILING

    @property
    def display(self) -> str:
        """The name to put in a remediation sentence.

        Runs the raw label through the client-prose SSOT so a remediation verb
        reads as a consultant writes it (``Remove emily.oscars from Backup
        Operators.``), never with the collector's shouting UPN (``Remove
        EMILY.OSCARS@CICADA.HTB from BACKUP OPERATORS@CICADA.HTB.``). Best-effort:
        any failure falls back to the raw label. A cross-forest object is not
        disambiguated here (the short verb has no report-domain context); the
        report/writeup narrative that surrounds it carries that qualification.
        """
        raw = self.label or self.object_id
        try:
            from adscan_internal.services.well_known_principals import (  # noqa: PLC0415
                humanize_principal_for_prose,
            )

            return humanize_principal_for_prose(
                label=raw, samaccountname=self.samaccountname, kind=self.kind
            )
        except Exception:  # pragma: no cover - humanization is best-effort
            return raw


def _rid_of(object_id: str) -> int | None:
    """Return the trailing RID of a domain or BUILTIN SID, else ``None``."""
    token = object_id.strip().upper()
    if not (token.startswith("S-1-5-21-") or token.startswith("S-1-5-32-")):
        return None
    try:
        return int(token.rsplit("-", 1)[-1])
    except (TypeError, ValueError):
        return None


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _node_is_direct_tier0(node: Mapping[str, Any], facts_kind: str, sid: str) -> bool:
    """Return True when this principal's OWN identity is Tier 0 — direct.

    Delegates to the Privilege-Tier SSOT
    (:func:`~adscan_internal.services.compromise_class.privilege_tier_for_principal`)
    by classifying the principal against its own SID: a GROUP node's SID is the
    membership it confers (RID 512 Domain Admins, 516 Domain Controllers,
    ``S-1-5-32-544`` BUILTIN\\Administrators), and a USER node's own RID catches
    the built-in Administrator (500) and krbtgt (502). No RID list is duplicated
    here.

    Only ``TIER0_DIRECT`` counts. Tier 0 escalation-capable (Cert Publishers, the
    Operators, Key Admins) deliberately does NOT: a CA host holding directory
    replication rights is a real finding a client can act on, and calling it "by
    design" would bury it.
    """
    if facts_kind == "domain":
        return True
    if not sid.upper().startswith("S-1-"):
        return False
    try:
        from adscan_internal.services.compromise_class import (  # noqa: PLC0415
            PrivilegeTier,
            privilege_tier_for_principal,
        )
    except Exception:  # pragma: no cover - defensive; a missing SSOT is not fatal
        return False
    try:
        tier = privilege_tier_for_principal([sid], sid=sid)
    except Exception:  # pragma: no cover - defensive
        return False
    return tier is PrivilegeTier.TIER0_DIRECT


def _node_is_domain_controller(node: Mapping[str, Any], facts_kind: str) -> bool:
    """Return True when a Computer node is a writable DC or an RODC.

    Uses the pure node-role SSOT
    (:func:`~adscan_internal.services.computer_node_role.classify_computer_node_role`
    — ``primaryGroupID`` 516/521, a local ``krbtgt`` SPN, the RODC UAC bit).

    This is deliberately the NODE-shaped resolver rather than
    ``models.domain.resolve_domain_controllers``: that one answers "is this HOST
    STRING a DC", and exists to defeat the IP↔FQDN alias trap. Here we hold the
    object, so there is no alias to reconcile and no host string to match. A
    caller that only has a host string should use
    ``domain_controller_classifier.is_dc_host`` instead.
    """
    if facts_kind != "computer":
        return False
    try:
        from adscan_internal.services.computer_node_role import (  # noqa: PLC0415
            classify_computer_node_role,
        )
    except Exception:  # pragma: no cover - defensive
        return False
    try:
        return classify_computer_node_role(dict(node)) is not None
    except Exception:  # pragma: no cover - defensive
        return False


#: RIDs of the accounts and groups AdminSDHolder protects (Windows Server 2016
#: and later): Administrator, krbtgt, Domain Admins, Domain Controllers, Schema
#: Admins, Enterprise Admins, Read-only Domain Controllers, Key Admins,
#: Enterprise Key Admins, and the BUILTIN Administrators, Account / Server /
#: Print / Backup Operators and Replicator aliases.
_ADMINSDHOLDER_PROTECTED_RIDS: Final[frozenset[int]] = frozenset(
    {500, 502, 512, 516, 518, 519, 521, 526, 527, 544, 548, 549, 550, 551, 552}
)

#: Account Operators (BUILTIN). By default it holds full control over every user,
#: group and computer object AdminSDHolder does not protect.
_ACCOUNT_OPERATORS_SID: Final[str] = "S-1-5-32-548"

#: Inheritance placeholders. An ACE for CREATOR OWNER is copied to the object's
#: real owner when a child object is created, and SELF stands for the object
#: itself; neither is a principal anyone can hold or be removed from.
_INHERITANCE_PLACEHOLDER_SIDS: Final[frozenset[str]] = frozenset({"S-1-3-0", "S-1-5-10"})

#: The organisational unit Exchange setup creates for its security groups. Its
#: name is not localised.
_EXCHANGE_CONTAINER_DN_PREFIX: Final[str] = "ou=microsoft exchange security groups,"


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    return bool(value)


def _node_is_tier0_any(
    node: Mapping[str, Any],
    props: Mapping[str, Any],
    kind: str,
    sid: str,
    names: Sequence[str],
) -> bool:
    """Return True when the node sits anywhere inside the Tier 0 boundary.

    The stamped ``privilege_tier`` wins when the graph carries it (membership-
    and ACL-aware, the authoritative tier). Without it, the principal's own
    identity is classified by the Privilege-Tier SSOT: its SID, and for a group
    its own name (the Exchange groups and DnsAdmins carry no well-known RID).
    """
    stamped = str(props.get("privilege_tier") or node.get("privilege_tier") or "").strip().lower()
    if stamped:
        return stamped.startswith("tier0")
    if kind == "domain":
        return True
    try:
        from adscan_internal.services.compromise_class import (  # noqa: PLC0415
            privilege_tier_for_principal,
        )
    except Exception:  # pragma: no cover - defensive
        return False
    tokens = [sid] if sid.upper().startswith("S-1-") else []
    if kind == "group":
        tokens.extend(name for name in names if name)
    if not tokens:
        return False
    try:
        return privilege_tier_for_principal(tokens, sid=sid or None).is_tier0
    except Exception:  # pragma: no cover - defensive
        return False


def _node_is_exchange_group(kind: str, names: Sequence[str]) -> bool:
    """True for an Exchange security group, by the ``compromise_class`` list."""
    if kind != "group":
        return False
    try:
        from adscan_internal.services.compromise_class import (  # noqa: PLC0415
            is_exchange_security_group_name,
        )
    except Exception:  # pragma: no cover - defensive
        return False
    return any(is_exchange_security_group_name(name) for name in names if name)


def _node_stamped_domain_control(node: Mapping[str, Any], props: Mapping[str, Any]) -> bool:
    """True when the node's stamped compromise class is in the direct band."""
    token = node.get("compromise_class") or props.get("compromise_class")
    if not token:
        return False
    try:
        from adscan_internal.services.compromise_class import (  # noqa: PLC0415
            is_direct_tier0_control_class,
        )
    except Exception:  # pragma: no cover - defensive
        return False
    return is_direct_tier0_control_class(token)


def _node_hosts_certificate_authority(kind: str, props: Mapping[str, Any]) -> bool:
    """True when a computer is recorded as a Cert Publishers member (a CA host)."""
    if kind != "computer":
        return False
    keys = props.get("tier0_membership_keys")
    if isinstance(keys, (list, tuple, set, frozenset)):
        return any(str(key).strip().lower() == "cert_publishers" for key in keys)
    return False


def _node_domain(props: Mapping[str, Any], label: str) -> str:
    """The object's DNS domain, from the node or its ``name@domain`` label."""
    domain = str(props.get("domain") or "").strip().lower()
    if domain:
        return domain
    if "@" in label:
        return label.rsplit("@", 1)[-1].strip().lower()
    return ""


def principal_facts_from_node(node: Mapping[str, Any] | None) -> PrincipalFacts | None:
    """Read the structural identity off one attack-graph node.

    Args:
        node: A node from ``attack_graph.json`` (``label`` / ``objectId`` /
            ``kind`` / ``properties``). ``None`` or a non-mapping returns
            ``None``, so callers can pass an unresolved endpoint straight
            through.

    Returns:
        The :class:`PrincipalFacts`, or ``None`` when there is no node.
    """
    if not isinstance(node, Mapping):
        return None
    props = node.get("properties")
    props = props if isinstance(props, Mapping) else {}

    sid = str(node.get("objectId") or props.get("objectid") or "").strip()
    kind = str(node.get("kind") or "").strip().lower()
    label = str(node.get("label") or props.get("name") or "").strip()

    synthetic = bool(props.get("well_known_sid")) or sid.upper() in _SYNTHETIC_WELL_KNOWN_SIDS
    samaccountname = str(props.get("samaccountname") or props.get("sAMAccountName") or "").strip()
    names = (samaccountname, label, str(props.get("name") or ""))
    rid = _rid_of(sid)
    dn = str(props.get("distinguishedname") or props.get("distinguishedName") or "").strip().lower()
    protected = _truthy(props.get("admincount") or props.get("adminCount")) or (
        rid is not None and rid in _ADMINSDHOLDER_PROTECTED_RIDS
    )

    return PrincipalFacts(
        label=label,
        samaccountname=samaccountname,
        object_id=sid,
        kind=kind,
        rid=rid,
        primary_group_id=_int_or_none(props.get("primarygroupid") or props.get("primaryGroupID")),
        is_builtin_alias=sid.upper().startswith("S-1-5-32-"),
        is_synthetic_well_known=synthetic,
        is_domain_controller=_node_is_domain_controller(node, kind),
        is_direct_tier0=_node_is_direct_tier0(node, kind, sid),
        stamped_domain_control=_node_stamped_domain_control(node, props),
        is_tier0=_node_is_tier0_any(node, props, kind, sid, names),
        is_exchange_group=_node_is_exchange_group(kind, names),
        is_exchange_container=kind == "ou" and dn.startswith(_EXCHANGE_CONTAINER_DN_PREFIX),
        is_adminsdholder_protected=protected,
        hosts_certificate_authority=_node_hosts_certificate_authority(kind, props),
        domain=_node_domain(props, label),
    )


def _coerce(value: PrincipalFacts | Mapping[str, Any] | None) -> PrincipalFacts | None:
    if isinstance(value, PrincipalFacts):
        return value
    return principal_facts_from_node(value)


# ── Per-family classification ─────────────────────────────────────────────────


@dataclass(frozen=True)
class _Family:
    """The default remediation shape and sentence for one relation family."""

    kind: RemediationKind
    #: ``str.format`` template over ``source`` / ``target``.
    template: str
    #: Sentence used when neither endpoint resolved to a name.
    generic: str


def _f(kind: RemediationKind, template: str, generic: str) -> _Family:
    return _Family(kind=kind, template=template, generic=generic)


_REMOVE_MEMBERSHIP = _f(
    RemediationKind.MEMBERSHIP_REMOVAL,
    "Remove {source} from {target}.",
    "Remove the group membership that grants this access.",
)
_REVOKE_ACE = _f(
    RemediationKind.ACL_REVOCATION,
    "Revoke the permissions {source} holds on {target}.",
    "Revoke the delegated permissions on the target object.",
)

# One entry per relation the attack graph emits (see ``edge_kind``). The kind
# decides WHO does the work and in which change window; the template decides the
# sentence the client reads. Prose here is client-facing: native Microsoft
# vocabulary only, never a tool name.
_FAMILY_BY_RELATION: Final[dict[str, _Family]] = {
    # ── Group membership ─────────────────────────────────────────────────────
    "memberof": _REMOVE_MEMBERSHIP,
    "adminto": _f(
        RemediationKind.MEMBERSHIP_REMOVAL,
        "Remove {source} from the local Administrators group on {target}.",
        "Remove the account from the host's local Administrators group.",
    ),
    "canrdp": _f(
        RemediationKind.MEMBERSHIP_REMOVAL,
        "Remove {source} from the Remote Desktop Users group on {target}.",
        "Remove the account from the host's Remote Desktop Users group.",
    ),
    "canpsremote": _f(
        RemediationKind.MEMBERSHIP_REMOVAL,
        "Remove {source} from the Remote Management Users group on {target}.",
        "Remove the account from the host's Remote Management Users group.",
    ),
    "executedcom": _f(
        RemediationKind.MEMBERSHIP_REMOVAL,
        "Remove {source} from the Distributed COM Users group on {target}.",
        "Remove the account from the host's Distributed COM Users group.",
    ),
    # ── Object permissions ───────────────────────────────────────────────────
    "genericall": _REVOKE_ACE,
    "genericwrite": _REVOKE_ACE,
    "writedacl": _REVOKE_ACE,
    "writeowner": _REVOKE_ACE,
    "owns": _f(
        RemediationKind.ACL_REVOCATION,
        "Reassign ownership of {target} away from {source} to a Tier 0 "
        "administrative group.",
        "Reassign ownership of the object to an administrative group.",
    ),
    "allextendedrights": _REVOKE_ACE,
    "addmember": _f(
        RemediationKind.ACL_REVOCATION,
        "Revoke the write-membership permission {source} holds on {target}.",
        "Revoke the write-membership permission on the group.",
    ),
    "addself": _REVOKE_ACE,
    "forcechangepassword": _f(
        RemediationKind.ACL_REVOCATION,
        "Revoke the Reset Password permission {source} holds on {target}.",
        "Revoke the Reset Password permission on the account.",
    ),
    "addkeycredentiallink": _f(
        RemediationKind.ACL_REVOCATION,
        "Revoke the write permission {source} holds on the "
        "msDS-KeyCredentialLink attribute of {target}.",
        "Revoke write access to the msDS-KeyCredentialLink attribute.",
    ),
    "hasshadowcredentials": _f(
        RemediationKind.ACL_REVOCATION,
        "Clear the attacker-controlled key credential from {target} and revoke "
        "the write permission that allowed it.",
        "Clear the key credential and revoke the permission that allowed it.",
    ),
    "readgmsapassword": _f(
        RemediationKind.ACL_REVOCATION,
        "Remove {source} from the principals allowed to retrieve the managed "
        "password of {target}.",
        "Restrict which principals may retrieve the managed password.",
    ),
    "readlapspassword": _f(
        RemediationKind.ACL_REVOCATION,
        "Revoke the permission {source} holds to read the local administrator "
        "password of {target}.",
        "Revoke read access to the managed local administrator password.",
    ),
    "synclapspassword": _f(
        RemediationKind.ACL_REVOCATION,
        "Revoke the replication permission {source} holds over the local "
        "administrator password of {target}.",
        "Revoke the local-administrator-password replication permission.",
    ),
    "managerodcprp": _REVOKE_ACE,
    "writelogonscript": _f(
        RemediationKind.ACL_REVOCATION,
        "Revoke the write permission {source} holds on the logon-script "
        "attribute of {target}.",
        "Revoke write access to the logon-script attribute.",
    ),
    "writeaccountrestrictions": _f(
        RemediationKind.ACL_REVOCATION,
        "Revoke the write permission {source} holds on the account-restrictions "
        "attributes of {target}.",
        "Revoke write access to the account-restrictions attributes.",
    ),
    "writespn": _f(
        RemediationKind.ACL_REVOCATION,
        "Revoke the write permission {source} holds on the "
        "servicePrincipalName attribute of {target}.",
        "Revoke write access to the servicePrincipalName attribute.",
    ),
    "writesmbpath": _REVOKE_ACE,
    "readshare": _f(
        RemediationKind.ACL_REVOCATION,
        "Remove {source} from the share and NTFS permissions on {target}.",
        "Tighten the share and NTFS permissions.",
    ),
    "writeshare": _f(
        RemediationKind.ACL_REVOCATION,
        "Remove {source}'s write permission from the share and NTFS "
        "permissions on {target}.",
        "Remove write access from the share and NTFS permissions.",
    ),
    "fullcontrolshare": _f(
        RemediationKind.ACL_REVOCATION,
        "Remove {source}'s full-control permission from the share and NTFS "
        "permissions on {target}.",
        "Remove full control from the share and NTFS permissions.",
    ),
    # ── Directory replication (instance rule below decides remediability) ────
    "dcsync": _f(
        RemediationKind.ACL_REVOCATION,
        "Revoke the directory replication rights (Replicating Directory Changes "
        "and Replicating Directory Changes All) granted to {source} on {target}.",
        "Revoke the directory replication rights granted on the domain object.",
    ),
    "getchanges": _f(
        RemediationKind.ACL_REVOCATION,
        "Revoke the Replicating Directory Changes right granted to {source} on "
        "{target}.",
        "Revoke the Replicating Directory Changes right on the domain object.",
    ),
    "getchangesall": _f(
        RemediationKind.ACL_REVOCATION,
        "Revoke the Replicating Directory Changes All right granted to {source} "
        "on {target}.",
        "Revoke the Replicating Directory Changes All right on the domain object.",
    ),
    "getchangesinfilteredset": _f(
        RemediationKind.ACL_REVOCATION,
        "Revoke the filtered-set replication right granted to {source} on "
        "{target}.",
        "Revoke the filtered-set replication right on the domain object.",
    ),
    # ── Delegation and account configuration ─────────────────────────────────
    "allowedtodelegate": _f(
        RemediationKind.CONFIG_CHANGE,
        "Clear msDS-AllowedToDelegateTo on {source} so it can no longer "
        "impersonate users to {target}.",
        "Clear the constrained-delegation configuration on the account.",
    ),
    "allowedtoact": _f(
        RemediationKind.CONFIG_CHANGE,
        "Clear msDS-AllowedToActOnBehalfOfOtherIdentity on {target} so {source} "
        "can no longer impersonate users to it.",
        "Clear the resource-based delegation configuration on the target.",
    ),
    "unconstraineddelegation": _f(
        RemediationKind.CONFIG_CHANGE,
        "Turn off unconstrained delegation on {target} and move the service to "
        "constrained delegation.",
        "Turn off unconstrained delegation and move to constrained delegation.",
    ),
    "kerberoasting": _f(
        RemediationKind.CONFIG_CHANGE,
        "Move {target} to a group managed service account, or remove its service "
        "principal name if the service no longer needs one.",
        "Move the service account to a group managed service account.",
    ),
    "asreproasting": _f(
        RemediationKind.CONFIG_CHANGE,
        "Re-enable Kerberos pre-authentication on {target}.",
        "Re-enable Kerberos pre-authentication on the account.",
    ),
    "guestsession": _f(
        RemediationKind.CONFIG_CHANGE,
        "Disable guest and anonymous access on {target}.",
        "Disable guest and anonymous access.",
    ),
    "ldapanonymousbind": _f(
        RemediationKind.CONFIG_CHANGE,
        "Require authenticated LDAP binds on {target}.",
        "Require authenticated LDAP binds.",
    ),
    # ── Database ─────────────────────────────────────────────────────────────
    "sqladmin": _f(
        RemediationKind.CONFIG_CHANGE,
        "Remove {source} from the sysadmin server role on {target}.",
        "Remove the login from the sysadmin server role.",
    ),
    "sqlaccess": _f(
        RemediationKind.CONFIG_CHANGE,
        "Remove the login mapping that lets {source} connect to {target}.",
        "Remove the database login mapping.",
    ),
    "mssqllinkedserverlateral": _f(
        RemediationKind.SERVICE_REMOVAL,
        "Drop the linked server that connects {source} to {target}, or restrict "
        "the login it maps to so it is not privileged on the remote instance.",
        "Drop the linked server, or restrict the login it maps to.",
    ),
    "trustedlink": _f(
        RemediationKind.SERVICE_REMOVAL,
        "Drop the linked server that connects {source} to {target}, or restrict "
        "the login it maps to so it is not privileged on the remote instance.",
        "Drop the linked server, or restrict the login it maps to.",
    ),
    "mssqlimpersonatelogin": _f(
        RemediationKind.CONFIG_CHANGE,
        "Revoke the IMPERSONATE permission {source} holds on {target}.",
        "Revoke the IMPERSONATE permission on the database login.",
    ),
    "mssqltrustworthydbescalation": _f(
        RemediationKind.CONFIG_CHANGE,
        "Turn off the TRUSTWORTHY database property on {target}.",
        "Turn off the TRUSTWORTHY database property.",
    ),
    "mssqlntlmv2theft": _f(
        RemediationKind.CONFIG_CHANGE,
        "Restrict outbound SMB from {target} and remove the permissions that "
        "allow arbitrary directory listing.",
        "Restrict outbound SMB from the database host.",
    ),
    "xpcmdshell": _f(
        RemediationKind.CONFIG_CHANGE,
        "Disable xp_cmdshell on {target} and run the database service under a "
        "least-privilege account.",
        "Disable xp_cmdshell and run the service least-privileged.",
    ),
    "mssqlopenrowsetbulkread": _f(
        RemediationKind.CONFIG_CHANGE,
        "Revoke ADMINISTER BULK OPERATIONS and bulkadmin membership from "
        "{source} on {target}.",
        "Revoke the bulk-operations permission from the login.",
    ),
    # ── NTLM, coercion and relay ─────────────────────────────────────────────
    "ntlmv1enabled": _f(
        RemediationKind.CONFIG_CHANGE,
        "Raise LmCompatibilityLevel on {target} so it refuses NTLMv1.",
        "Raise LmCompatibilityLevel so NTLMv1 is refused.",
    ),
    "crackntlmv1": _f(
        RemediationKind.CONFIG_CHANGE,
        "Raise LmCompatibilityLevel on {target} so it refuses NTLMv1, and rotate "
        "its account password.",
        "Raise LmCompatibilityLevel so NTLMv1 is refused.",
    ),
    "ntlmv1relayrbcd": _f(
        RemediationKind.CONFIG_CHANGE,
        "Raise LmCompatibilityLevel on {target}, and require SMB signing and "
        "LDAP channel binding so the captured response cannot be relayed.",
        "Refuse NTLMv1 and require signing and channel binding.",
    ),
    "ntlmv1relayshadowcreds": _f(
        RemediationKind.CONFIG_CHANGE,
        "Raise LmCompatibilityLevel on {target}, and require LDAP signing and "
        "channel binding so the captured response cannot be relayed.",
        "Refuse NTLMv1 and require LDAP signing and channel binding.",
    ),
    "coerceandrelayntlmtoadcs": _f(
        RemediationKind.CONFIG_CHANGE,
        "Require channel binding and HTTPS on the certificate enrolment endpoint, "
        "and disable the coercion surface on {target}.",
        "Require channel binding on certificate enrolment and close the coercion "
        "surface.",
    ),
    "webdavenabled": _f(
        RemediationKind.CONFIG_CHANGE,
        "Disable the WebClient service on {target}.",
        "Disable the WebClient service.",
    ),
    "printerbugsurface": _f(
        RemediationKind.CONFIG_CHANGE,
        "Disable the Print Spooler service on {target} unless the host prints.",
        "Disable the Print Spooler service where it is not needed.",
    ),
    # ── Patch ────────────────────────────────────────────────────────────────
    "zerologon": _f(
        RemediationKind.PATCH,
        "Apply the Netlogon secure-channel security update on {target} and "
        "enforce secure RPC.",
        "Apply the Netlogon secure-channel security update.",
    ),
    "nopac": _f(
        RemediationKind.PATCH,
        "Apply the Kerberos privilege-attribute security update on {target}.",
        "Apply the Kerberos privilege-attribute security update.",
    ),
    "printnightmare": _f(
        RemediationKind.PATCH,
        "Apply the Print Spooler security update on {target} and restrict driver "
        "installation to administrators.",
        "Apply the Print Spooler security update.",
    ),
    "badsuccessor": _f(
        RemediationKind.PATCH,
        "Apply the delegated managed service account security update on {target} "
        "and restrict who may create those objects.",
        "Apply the delegated managed service account security update.",
    ),
    "ms17-010": _f(
        RemediationKind.PATCH,
        "Apply MS17-010 on {target} and disable SMBv1.",
        "Apply MS17-010 and disable SMBv1.",
    ),
    "ms17010": _f(
        RemediationKind.PATCH,
        "Apply MS17-010 on {target} and disable SMBv1.",
        "Apply MS17-010 and disable SMBv1.",
    ),
    "smbghost": _f(
        RemediationKind.PATCH,
        "Apply the SMBv3 compression security update on {target}.",
        "Apply the SMBv3 compression security update.",
    ),
    "dropthemic": _f(
        RemediationKind.PATCH,
        "Apply the NTLM message-integrity security update on {target}.",
        "Apply the NTLM message-integrity security update.",
    ),
    "dropthemic2": _f(
        RemediationKind.PATCH,
        "Apply the NTLM message-integrity security update on {target}.",
        "Apply the NTLM message-integrity security update.",
    ),
    # Legacy relation name of the CVE-2019-1040 (Drop the MIC) edge in graphs
    # written before the rename; same flaw, same fix.
    "ntlmreflection": _f(
        RemediationKind.PATCH,
        "Apply the NTLM message-integrity security update on {target}.",
        "Apply the NTLM message-integrity security update.",
    ),
    # ── Credential exposure and reuse ────────────────────────────────────────
    "gpppassword": _f(
        RemediationKind.CREDENTIAL_ROTATION,
        "Delete the Group Policy preference holding the password, then rotate "
        "the password of {target}.",
        "Delete the Group Policy preference holding the password and rotate it.",
    ),
    "passwordinshare": _f(
        RemediationKind.CREDENTIAL_ROTATION,
        "Remove the stored credential from the share and rotate the password of "
        "{target}.",
        "Remove the stored credential and rotate the password.",
    ),
    "passwordinfile": _f(
        RemediationKind.CREDENTIAL_ROTATION,
        "Remove the stored credential from the file and rotate the password of "
        "{target}.",
        "Remove the stored credential and rotate the password.",
    ),
    "userdescription": _f(
        RemediationKind.CREDENTIAL_ROTATION,
        "Clear the credential from the description of {target} and rotate its "
        "password.",
        "Clear the credential from the object description and rotate it.",
    ),
    "timeroasting": _f(
        RemediationKind.CREDENTIAL_ROTATION,
        "Reset the computer account password of {target} so it is machine-"
        "generated, and restrict anonymous time synchronisation.",
        "Reset the computer account password and restrict anonymous time "
        "synchronisation.",
    ),
    "computerpre2k": _f(
        RemediationKind.CREDENTIAL_ROTATION,
        "Reset the computer account password of {target} and clear its "
        "pre-Windows 2000 compatibility flag.",
        "Reset the computer account password and clear the legacy flag.",
    ),
    "passwordspray": _f(
        RemediationKind.CREDENTIAL_ROTATION,
        "Rotate the password of {target} and enforce a password policy that "
        "rejects the guessed value.",
        "Rotate the password and enforce a stronger password policy.",
    ),
    "useraspass": _f(
        RemediationKind.CREDENTIAL_ROTATION,
        "Rotate the password of {target}; it matches the account name.",
        "Rotate the password; it matches the account name.",
    ),
    "blankpassword": _f(
        RemediationKind.CREDENTIAL_ROTATION,
        "Set a password on {target} and require one through policy.",
        "Set a password and require one through policy.",
    ),
    "localadminpassreuse": _f(
        RemediationKind.CREDENTIAL_ROTATION,
        "Deploy managed local administrator passwords so {target} no longer "
        "shares its local administrator password with other hosts.",
        "Deploy managed, per-host local administrator passwords.",
    ),
    "domainpassreuse": _f(
        RemediationKind.CREDENTIAL_ROTATION,
        "Rotate the shared password so {target} no longer reuses the password of "
        "another domain account.",
        "Rotate the reused password.",
    ),
    "domainpassreusesource": _f(
        RemediationKind.CREDENTIAL_ROTATION,
        "Rotate the shared password held by {source}.",
        "Rotate the reused password.",
    ),
    "localcredreusesource": _f(
        RemediationKind.CREDENTIAL_ROTATION,
        "Rotate the local credential held by {source} so it is not reused in the "
        "domain.",
        "Rotate the reused local credential.",
    ),
    "localcredtodomainreuse": _f(
        RemediationKind.CREDENTIAL_ROTATION,
        "Rotate the password of {target} so it no longer matches a local account "
        "credential.",
        "Rotate the password so it no longer matches a local credential.",
    ),
    "poisoncapturentlmv2crack": _f(
        RemediationKind.CONFIG_CHANGE,
        "Disable LLMNR, NBT-NS and mDNS by policy, and enforce a password policy "
        "that survives offline cracking for {target}.",
        "Disable LLMNR, NBT-NS and mDNS by policy.",
    ),
    "forgedticketfor": _f(
        RemediationKind.CREDENTIAL_ROTATION,
        "Reset the krbtgt account password twice, allowing for replication "
        "between the two resets.",
        "Reset the krbtgt account password twice.",
    ),
    # ── Credential material read from a compromised host ─────────────────────
    # These name the HOST the step runs on ({host}), never the step's target:
    # the graph draws a session-borne dump as ``user -> user`` (the signed-in
    # account's own material), so "{target}" printed "Enable Credential Guard on
    # robb.stark", a user. The host is the target when the directory says the
    # target IS a computer, else it comes from the chain
    # (:func:`refine_chain_remediability`). With no host the verb is empty, so no
    # surface prints a change aimed at an object that is not a host.
    "dumplsa": _f(
        RemediationKind.CONFIG_CHANGE,
        "Enable Credential Guard on {host} and stop privileged accounts from "
        "logging on to it interactively.",
        "Enable Credential Guard and stop privileged interactive logons.",
    ),
    "dumplsass": _f(
        RemediationKind.CONFIG_CHANGE,
        "Enable Credential Guard on {host} and stop privileged accounts from "
        "logging on to it interactively.",
        "Enable Credential Guard and stop privileged interactive logons.",
    ),
    "dumpsam": _f(
        RemediationKind.CONFIG_CHANGE,
        "Deploy managed local administrator passwords on {host} so the local "
        "account database yields nothing reusable.",
        "Deploy managed, per-host local administrator passwords.",
    ),
    "dumpdpapi": _f(
        RemediationKind.CONFIG_CHANGE,
        "Stop storing reusable secrets in user credential vaults on {host}.",
        "Stop storing reusable secrets in user credential vaults.",
    ),
    # Borrowing a signed-in account's session through the Task Scheduler. The
    # change that closes it is keeping that account off the host, so the sentence
    # names both: the account ({source}) and the host it signs in to ({host}).
    "scheduledtask": _f(
        RemediationKind.CONFIG_CHANGE,
        "Stop {source} from signing in interactively to {host}, so an "
        "administrator of that host cannot run a task in its session.",
        "Keep privileged accounts from signing in to hosts of a lower tier.",
    ),
    "dumpedhashof": _f(
        RemediationKind.CREDENTIAL_ROTATION,
        "Rotate the password of {target}; its hash was recovered from a "
        "compromised host.",
        "Rotate the recovered account's password.",
    ),
    # ── Trusts ───────────────────────────────────────────────────────────────
    "trustedby": _f(
        RemediationKind.CONFIG_CHANGE,
        "Enable SID filtering, and selective authentication where the business "
        "allows it, on the trust between {source} and {target}.",
        "Enable SID filtering and selective authentication on the trust.",
    ),
    "hassidhistory": _f(
        RemediationKind.CONFIG_CHANGE,
        "Clear the stale sIDHistory value from {source} and enable SID filtering "
        "on the trust that honours it.",
        "Clear stale sIDHistory values and enable SID filtering.",
    ),
    # ── Privileged-group escalations ─────────────────────────────────────────
    "backupoperatorsescalation": _f(
        RemediationKind.MEMBERSHIP_REMOVAL,
        "Empty {source} of standing members; its privilege reaches the domain "
        "database in one step.",
        "Empty the privileged operators group of standing members.",
    ),
    "backupoperatorescalation": _f(
        RemediationKind.MEMBERSHIP_REMOVAL,
        "Empty {source} of standing members; its privilege reaches the domain "
        "database in one step.",
        "Empty the privileged operators group of standing members.",
    ),
    "dnsadminsescalation": _f(
        RemediationKind.MEMBERSHIP_REMOVAL,
        "Empty {source} of standing members; its privilege loads attacker code "
        "into the DNS service on a domain controller.",
        "Empty the DNS administrators group of standing members.",
    ),
    "dnsadminabuse": _f(
        RemediationKind.MEMBERSHIP_REMOVAL,
        "Empty {source} of standing members; its privilege loads attacker code "
        "into the DNS service on a domain controller.",
        "Empty the DNS administrators group of standing members.",
    ),
    "accountoperatorsescalation": _f(
        RemediationKind.MEMBERSHIP_REMOVAL,
        "Empty {source} of standing members; it can modify most accounts in the "
        "directory.",
        "Empty the account operators group of standing members.",
    ),
    "printoperatorsescalation": _f(
        RemediationKind.MEMBERSHIP_REMOVAL,
        "Empty {source} of standing members; it can load drivers on a domain "
        "controller.",
        "Empty the print operators group of standing members.",
    ),
    "printoperatorabuse": _f(
        RemediationKind.MEMBERSHIP_REMOVAL,
        "Empty {source} of standing members; it can load drivers on a domain "
        "controller.",
        "Empty the print operators group of standing members.",
    ),
    "serveroperatorsescalation": _f(
        RemediationKind.MEMBERSHIP_REMOVAL,
        "Empty {source} of standing members; it can reconfigure services on a "
        "domain controller.",
        "Empty the server operators group of standing members.",
    ),
    "schemaadminsescalation": _f(
        RemediationKind.MEMBERSHIP_REMOVAL,
        "Empty {source} of standing members; schema changes are forest-wide and "
        "irreversible.",
        "Empty the schema administrators group of standing members.",
    ),
    # The fix is one change for every Exchange group that holds it, so the
    # sentence names the domain and not the group: identical sentences merge into
    # one action on the ranked row.
    "exchangeaclescalation": _f(
        RemediationKind.ACL_REVOCATION,
        "Remove the Exchange permission inherited from the root of {target}. "
        "Install the current Exchange cumulative update and run Setup "
        "/PrepareAD, or move Exchange to the split permissions model.",
        "Remove the Exchange permission inherited from the domain root. Install "
        "the current Exchange cumulative update and run Setup /PrepareAD, or "
        "move Exchange to the split permissions model.",
    ),
    "privilegedgroupcontrol": _REVOKE_ACE,
    # ── Not remediable ───────────────────────────────────────────────────────
    "contains": _f(
        RemediationKind.NOT_REMEDIABLE,
        "",
        "",
    ),
    "hassession": _f(
        RemediationKind.NOT_REMEDIABLE,
        "",
        "",
    ),
    "gplink": _f(
        RemediationKind.NOT_REMEDIABLE,
        "",
        "",
    ),
    # Inside one forest a compromised child domain can always take over the
    # forest root: the domains share the trust key and SID filtering cannot apply
    # within a forest. The catalog says so (``can_fully_mitigate`` is False, and
    # the finding states it is not a misconfiguration), yet the generic fallback
    # put "Remove the configuration on <root> that lets <child> reach it" in a
    # client's work order.
    "raisechild": _f(
        RemediationKind.NOT_REMEDIABLE,
        "",
        "",
    ),
}

#: Why each ``NOT_REMEDIABLE`` relation family cannot be fixed. The report prints
#: this sentence in place of a fix, so it reads for the client.
_WHY_NOT_BY_RELATION: Final[dict[str, str]] = {
    "contains": (
        "Directory topology. Moving the object to another organisational unit "
        "changes where it lives, not who can reach it."
    ),
    "hassession": (
        "A logon observed at a point in time, not a permission. The change that "
        "closes it is on whatever grants that account the right to log on there."
    ),
    "gplink": (
        "The policy link itself grants nothing. The change that closes it is on "
        "the permissions of the linked Group Policy object."
    ),
    "raisechild": (
        "Inside one forest, whoever controls a child domain can take over the "
        "forest root. The domains share a trust key, and SID filtering cannot "
        "apply within a forest, so no setting closes this step. Protect each "
        "child domain to the same standard as the forest root."
    ),
}

#: Relations whose change is made ON A HOST. Their sentence names ``{host}``,
#: which is the step's target only when the directory says the target is a
#: computer; a session-borne step is drawn ``user -> user`` and takes its host
#: from the chain (:func:`refine_chain_remediability`).
_HOST_SCOPED_RELATIONS: Final[frozenset[str]] = frozenset(
    {"dumplsa", "dumplsass", "dumpsam", "dumpdpapi", "scheduledtask"}
)
#: Public name, read by the step catalog so its narrative ``{target}`` names the
#: same host the remediation does.
HOST_SCOPED_RELATIONS: Final[frozenset[str]] = _HOST_SCOPED_RELATIONS

#: Relations whose "no change closes this" is a property of how Active Directory
#: works, not an observation that happens to carry no permission. Only these
#: are offered to a client as "by design" (``Remediability.inherent``); a logon
#: session (``hassession``) is not by design, its fix lives on another step.
_INHERENT_RELATIONS: Final[frozenset[str]] = frozenset({"raisechild"})

#: Families whose privilege FOLLOWS from the source already controlling the
#: domain, so the edge is a fact of the hierarchy rather than a separate
#: misconfiguration (CLAUDE.md § Nomenclature Standard, "Domain Breaker →
#: anything = INFO"). Credential-recovery, patch and coercion families are
#: deliberately absent: those are not privileges anybody granted.
_BY_DESIGN_KINDS: Final[frozenset[RemediationKind]] = frozenset(
    {RemediationKind.MEMBERSHIP_REMOVAL, RemediationKind.ACL_REVOCATION}
)


def _family_for(relation: str) -> _Family:
    """Return the relation's family, falling back to its :class:`EdgeKind`."""
    family = _FAMILY_BY_RELATION.get(relation)
    if family is not None:
        return family
    if relation.startswith("adcsesc"):
        return _f(
            RemediationKind.CONFIG_CHANGE,
            "Correct the certificate template and certification authority "
            "configuration that lets {source} obtain a certificate for {target}.",
            "Correct the vulnerable certificate template or certification "
            "authority configuration.",
        )
    if relation.startswith(("coerce", "petitpotam", "printerbug", "dfscoerce", "mseven")):
        return _f(
            RemediationKind.CONFIG_CHANGE,
            "Close the authentication-coercion surface on {target} and require "
            "SMB signing and LDAP channel binding so a coerced logon cannot be "
            "relayed.",
            "Close the coercion surface and require signing and channel binding.",
        )

    # An unmapped relation stays REMEDIABLE. Dropping a technique row because the
    # catalog has not caught up would silently shrink the client's fix list.
    kind_token = ""
    try:
        from adscan_internal.services.edge_kind import classify_edge_kind  # noqa: PLC0415

        kind_token = str(classify_edge_kind(relation).value)
    except Exception:  # pragma: no cover - defensive
        kind_token = ""
    if kind_token == "membership":
        return _REMOVE_MEMBERSHIP
    if kind_token == "control":
        return _REVOKE_ACE
    # No sentence. The old fallback composed one from the endpoint names ("Remove
    # the configuration on robb.stark that lets robb.stark reach it"), which names
    # nothing a client can change, and it reached a paid work order. An empty verb
    # lets each surface fall back to the technique's own catalog guidance.
    return _f(RemediationKind.CONFIG_CHANGE, "", "")


def _host_display(target: PrincipalFacts | None, host: PrincipalFacts | str | None) -> str:
    """The host a host-scoped change is made on, or ``""`` when none is known.

    An explicit ``host`` wins (the chain resolved it). Otherwise the target is the
    host only when the directory says it is a computer: the node kind, read from
    collected data, never inferred from the shape of a name.
    """
    if isinstance(host, PrincipalFacts):
        return host.display
    if isinstance(host, str) and host.strip():
        return PrincipalFacts(label=host.strip(), kind="computer").display
    if target is not None and target.kind == "computer":
        return target.display
    return ""


def _sentence(
    family: _Family,
    source: PrincipalFacts | None,
    target: PrincipalFacts | None,
    host: PrincipalFacts | str | None = None,
) -> str:
    """Render the family's template with whatever names resolved.

    A template naming ``{host}`` renders only when a host is known. Without one
    it returns ``""`` rather than aiming the change at the step's target, which
    on a session-borne step is a user. A family with no template (the unmapped
    fallback) has no sentence at all.
    """
    if not family.template:
        return ""
    src = source.display if source else ""
    dst = target.display if target else ""
    if "{host}" in family.template:
        host_name = _host_display(target, host)
        if not host_name:
            return ""
        try:
            return family.template.format(
                source=src or "the signed-in account",
                target=dst or "the target object",
                host=host_name,
            )
        except (KeyError, IndexError):  # pragma: no cover - defensive
            return ""
    if not src and not dst:
        return family.generic
    try:
        return family.template.format(source=src or "the source principal", target=dst or "the target object")
    except (KeyError, IndexError):  # pragma: no cover - defensive
        return family.generic


#: A membership INTO a group that already controls the domain is the
#: administrative role itself, so the sentence asks the client to confirm it
#: before removing it. "Remove robb.stark from Administrators" reads as advice to
#: dismantle an intended administrator; whether that account should hold the role
#: is the client's call, and the attack path is the reason to ask.
_TIER0_MEMBERSHIP_TEMPLATE: Final[str] = (
    "Confirm that {source} needs to be in {target}, and remove it if not. Every "
    "member of {target} controls the domain."
)


def _memberof_verdict(
    source: PrincipalFacts | None, target: PrincipalFacts | None
) -> Remediability | None:
    """Return the SYSTEM verdict for a group membership, or ``None`` if it is a fix.

    The four rules, in order, each keyed on a structural signal:

    1. The group is a synthetic well-known principal — Windows computes its
       membership at logon and there is no member list to edit.
    2. The group is the member's PRIMARY group (RID 513/515/516/521 and the
       member is a user or a computer). Windows refuses the removal.
    3. BOTH endpoints are objects Windows ships (a ``BUILTIN`` alias, or a domain
       RID below 1000) — the nesting is Microsoft's, not the client's. The test
       is on the PAIR: ``BACKUPADMIN → ENTERPRISE ADMINS`` has a built-in target
       and is the most valuable remediation in its domain.
    4. The group could not be identified at all (no SID) — stay quiet rather than
       invent a fix.
    """
    if target is None or not target.has_sid:
        return Remediability(
            kind=RemediationKind.NOT_REMEDIABLE,
            why_not=(
                "The group could not be identified in the collected directory "
                "data, so no membership change can be recommended for it."
            ),
        )
    if target.is_synthetic_well_known:
        return Remediability(
            kind=RemediationKind.NOT_REMEDIABLE,
            why_not=(
                "Windows evaluates membership of this built-in identity at logon. "
                "It has no member list to edit."
            ),
            inherent=True,
        )
    if (
        target.rid in _PRIMARY_GROUP_RIDS
        and source is not None
        and source.kind in {"user", "computer"}
    ):
        return Remediability(
            kind=RemediationKind.NOT_REMEDIABLE,
            why_not=(
                "This is the account's primary group. Active Directory will not "
                "remove an account from its own primary group."
            ),
            inherent=True,
        )
    if source is not None and source.has_sid and source.is_builtin and target.is_builtin:
        return Remediability(
            kind=RemediationKind.NOT_REMEDIABLE,
            why_not=(
                "Windows creates and maintains this nesting between two built-in "
                "groups. It cannot be removed."
            ),
            inherent=True,
        )
    return None


def holds_domain_control(source: PrincipalFacts | Mapping[str, Any] | None) -> bool:
    """Return True when a principal already controls its domain.

    The single predicate behind "this edge follows from a role, it is not a
    finding". True for any of:

    * the graph stamped its compromise class in the direct band
      (``domain_breaker`` / ``tier0_control``), read through
      :func:`~adscan_internal.services.compromise_class.is_direct_tier0_control_class`,
      the same predicate :func:`~adscan_internal.services.severity.compute_edge_severity`
      uses to grade such a source INFO. That shared predicate is what keeps the
      severity grade and the "Start here" list from disagreeing: an edge graded
      INFO for its source is never offered as a fix;
    * its own SID is Tier 0 direct (Domain Admins, Enterprise Admins,
      BUILTIN\\\\Administrators, RID 500/502, the domain object);
    * it is a domain controller.

    The last two are structural signals the severity grade does not read (a DC
    node carries no stamped compromise class), so on those edges this side
    answers "by design" while severity may still grade the edge on its target.
    """
    facts = _coerce(source)
    if facts is None:
        return False
    return facts.stamped_domain_control or facts.is_direct_tier0 or facts.is_domain_controller


def _holds_by_design(source: PrincipalFacts | None) -> bool:
    """True when the source already controls the domain, so the edge follows."""
    return holds_domain_control(source)


def _principal_holds_domain_control(source: PrincipalFacts | None) -> bool:
    """:func:`holds_domain_control` without the domain-controller signal.

    The severity grade's own signal (the stamped direct-band class) plus a Tier 0
    direct SID. Used for the families outside ACL and membership changes, where
    a DC node on the graph often stands for a service running on it rather than
    for the DC's machine account.
    """
    if source is None:
        return False
    return source.stamped_domain_control or source.is_direct_tier0


def _is_direct_tier0_target(target: PrincipalFacts) -> bool:
    """True when the target is Tier 0 direct by its own SID OR by its stamped class.

    The stamped class is what the severity grade reads for a target in the
    direct band, so a target severity treats as a domain breaker (Cloneable
    Domain Controllers, for one) is never filed under a by-design default here.
    """
    return target.is_direct_tier0 or target.stamped_domain_control


def _crosses_domain(source: PrincipalFacts | None, target: PrincipalFacts | None) -> bool:
    """True when both endpoints record a domain and the domains differ."""
    if source is None or target is None:
        return False
    return bool(source.domain and target.domain and source.domain != target.domain)


#: Relations that grant rights over a share or its files. They are ACL changes on
#: a host, not directory delegations, so a default directory delegation (Account
#: Operators) never explains them.
_SHARE_RELATIONS: Final[frozenset[str]] = frozenset({"readshare", "writeshare", "fullcontrolshare"})

#: Directory object kinds Account Operators administers by default.
_ACCOUNT_OBJECT_KINDS: Final[frozenset[str]] = frozenset({"user", "group", "computer"})

_ACCOUNT_OPERATORS_TEMPLATE: Final[str] = (
    "Keep {source} empty; by default it has full control over every account and "
    "group that AdminSDHolder does not protect."
)

#: Shown in place of a fix on every Exchange-internal edge, so one sentence
#: covers the whole family wherever it appears.
_EXCHANGE_BY_DESIGN_WHY_NOT: Final[str] = (
    "Exchange grants this to its own security groups, and removing it breaks "
    "Exchange. Treat the Exchange servers and the Exchange security groups as "
    "Tier 0."
)

_SOURCE_CONTROLS_DOMAIN_WHY_NOT: Final[str] = (
    "The source already controls the domain, so this step adds no exposure of "
    "its own. Reduce who holds that control instead."
)

_DC_HOST_WHY_NOT: Final[str] = (
    "This step runs with administrative access to a domain controller, which "
    "already means control of the domain. Nothing on the domain controller "
    "itself closes it. The change is upstream, on whatever granted that access."
)

_DC_HOST_CREDENTIAL_GUARD_NOTE: Final[str] = (
    " Microsoft does not recommend Credential Guard on domain controllers."
)

#: Host-scoped relations whose usual fix is Credential Guard on the host.
_CREDENTIAL_GUARD_RELATIONS: Final[frozenset[str]] = frozenset({"dumplsa", "dumplsass"})

_CA_HOST_WHY_NOT: Final[str] = (
    "This domain controller also hosts the certification authority, so it "
    "controls the authority by design. It already controls the domain, and the "
    "change is upstream, on whatever gives control of it."
)


def _dc_host_verdict(relation: str) -> Remediability:
    """The verdict for a host-scoped step whose host is a domain controller."""
    why_not = _DC_HOST_WHY_NOT
    if relation in _CREDENTIAL_GUARD_RELATIONS:
        why_not += _DC_HOST_CREDENTIAL_GUARD_NOTE
    return Remediability(kind=RemediationKind.NOT_REMEDIABLE, why_not=why_not)


def _host_is_domain_controller(
    target: PrincipalFacts | None, host: PrincipalFacts | str | None
) -> bool:
    """True when the host a host-scoped step runs on is a domain controller.

    Same resolution as :func:`_host_display`: an explicit host wins, else the
    target when the directory says it is a computer. A bare host name carries no
    role, so it never reads as a domain controller.
    """
    if isinstance(host, PrincipalFacts):
        return host.is_domain_controller
    if isinstance(host, str) and host.strip():
        return False
    return target is not None and target.kind == "computer" and target.is_domain_controller


def _account_operators_default(
    relation: str,
    family: _Family,
    source: PrincipalFacts | None,
    target: PrincipalFacts | None,
) -> bool:
    """True when the edge is Account Operators' default full control.

    Account Operators holds full control over every user, group and computer
    object AdminSDHolder does not protect, out of the box. An edge it holds on
    such an object is that default, and the fix is the group's membership, not a
    per-object ACE. An edge onto a protected object, a domain controller or a
    Tier 0 direct principal is NOT the default and stays a per-object finding.
    """
    if source is None or target is None:
        return False
    if source.object_id.upper() != _ACCOUNT_OPERATORS_SID:
        return False
    if family.kind is not RemediationKind.ACL_REVOCATION:
        return False
    if relation in _SHARE_RELATIONS or relation in _REPLICATION_RELATIONS:
        return False
    if target.kind not in _ACCOUNT_OBJECT_KINDS:
        return False
    return not (
        target.is_adminsdholder_protected
        or _is_direct_tier0_target(target)
        or target.is_domain_controller
    )


def _exchange_internal_verdict(
    relation: str,
    family: _Family,
    source: PrincipalFacts | None,
    target: PrincipalFacts | None,
) -> Remediability | None:
    """The verdict for an edge an Exchange security group holds, or ``None``.

    Exchange setup nests its groups and delegates them broad rights over
    mailbox users and groups; removing either breaks Exchange. So:

    * a membership of an Exchange group into another Exchange group, or into a
      group outside Tier 0 (Managed Availability Servers), is by design;
    * a permission it holds on the domain object is the real finding (the
      inherited domain-root ACE), with the cumulative update and /PrepareAD, or
      split permissions, as the fix;
    * a permission on an Exchange group, the Exchange organisational unit, or
      any object outside Tier 0 is by design.

    A membership or permission reaching a non-Exchange Tier 0 object (Domain
    Admins, DnsAdmins) is not something Exchange needs, so it stays a per-object
    finding and this returns ``None``.
    """
    if source is None or target is None or not source.is_exchange_group:
        return None
    by_design = Remediability(
        kind=RemediationKind.NOT_REMEDIABLE,
        why_not=_EXCHANGE_BY_DESIGN_WHY_NOT,
        inherent=True,
    )
    if relation == "memberof":
        if _is_direct_tier0_target(target):
            return None
        if target.is_exchange_group or not target.is_tier0:
            return by_design
        return None
    if family.kind is not RemediationKind.ACL_REVOCATION or relation in _SHARE_RELATIONS:
        return None
    if target.kind == "domain":
        return Remediability(
            kind=RemediationKind.ACL_REVOCATION,
            verb=_sentence(_FAMILY_BY_RELATION["exchangeaclescalation"], source, target),
        )
    if _is_direct_tier0_target(target):
        return None
    if target.is_exchange_group or target.is_exchange_container or not target.is_tier0:
        return by_design
    return None


def classify_edge_remediability(
    relation: str | None,
    source: PrincipalFacts | Mapping[str, Any] | None = None,
    target: PrincipalFacts | Mapping[str, Any] | None = None,
    host: PrincipalFacts | Mapping[str, Any] | str | None = None,
) -> Remediability:
    """Return whether ONE edge instance can be changed, and the change if so.

    Args:
        relation: The edge label (``"MemberOf"``, ``"DCSync"``, ``"ADCSESC1"``).
            Matched case-insensitively.
        source: The edge's source, as :class:`PrincipalFacts` or a raw
            attack-graph node. ``None`` when the caller has no node — the
            verdict then falls back to what the relation alone can support.
        target: The edge's target, same shapes.
        host: For a host-scoped relation (:data:`_HOST_SCOPED_RELATIONS`), the
            computer the step runs on when the target is not that computer: a
            :class:`PrincipalFacts`, a raw node, or a host name. ``None`` uses
            the target when the directory says it is a computer and otherwise
            leaves the verb empty.

    Returns:
        A :class:`Remediability`. With no endpoint facts, an instance-dependent
        family answers conservatively: a group membership reads
        ``NOT_REMEDIABLE`` (matching the behaviour before this module existed),
        while every family whose fix does not depend on WHO holds the privilege
        answers with its normal verb.
    """
    rel = str(relation or "").strip().lower()
    if not rel:
        return Remediability(
            kind=RemediationKind.NOT_REMEDIABLE,
            why_not="The step carries no recognisable relation.",
        )

    src = _coerce(source)
    dst = _coerce(target)
    host_facts: PrincipalFacts | str | None = host if isinstance(host, str) else _coerce(host)
    family = _family_for(rel)

    if family.kind is RemediationKind.NOT_REMEDIABLE:
        return Remediability(
            kind=RemediationKind.NOT_REMEDIABLE,
            why_not=_WHY_NOT_BY_RELATION.get(rel, "There is no client-side change that closes this."),
            inherent=rel in _INHERENT_RELATIONS,
        )

    # ── Instance rules ───────────────────────────────────────────────────────
    if src is not None and src.object_id.upper() in _INHERITANCE_PLACEHOLDER_SIDS:
        return Remediability(
            kind=RemediationKind.NOT_REMEDIABLE,
            why_not=(
                "This entry is an inheritance placeholder, not a principal. Windows "
                "applies it to the object's owner or to the object itself. Review "
                "who owns the object instead."
            ),
            inherent=True,
        )

    if rel == "memberof":
        verdict = _memberof_verdict(src, dst)
        if verdict is not None:
            return verdict

    if rel in _REPLICATION_RELATIONS and _holds_by_design(src):
        # Domain controllers and the domain's built-in administrative groups hold
        # directory replication rights because replication is how the directory
        # works. The finding is a NON-default holder, never the right itself.
        return Remediability(
            kind=RemediationKind.NOT_REMEDIABLE,
            why_not=(
                "Directory replication is how a domain controller works, and the "
                "domain's built-in administrative groups hold the same rights by "
                "design. They cannot be revoked from these holders. What is worth "
                "reviewing is any OTHER principal holding them."
            ),
            inherent=True,
        )

    # A group membership is never excused by the member's STAMPED class: that
    # class is usually derived from this very membership (a user is a domain
    # breaker BECAUSE it is in Domain Admins), and removing it is the fix. Only
    # the structural signals count there. Severity never grades a membership on
    # its source either (membership is STRUCTURAL before its source rule).
    if rel == "memberof":
        source_holds_domain = src is not None and (src.is_direct_tier0 or src.is_domain_controller)
    else:
        source_holds_domain = _holds_by_design(src)
    if family.kind in _BY_DESIGN_KINDS and source_holds_domain:
        return Remediability(
            kind=RemediationKind.NOT_REMEDIABLE,
            why_not=(
                "The source already holds domain-wide administrative control, so "
                "this access follows from that role rather than from a separate "
                "misconfiguration. Reduce who holds the role instead."
            ),
            inherent=True,
        )

    # Any other step taken by a PRINCIPAL that already controls its domain (a
    # member of Domain Admins, the built-in Administrator) adds no exposure of
    # its own inside that domain: it is exactly what the severity grade calls
    # INFO for the same source. A step into ANOTHER domain is kept.
    #
    # A domain controller is deliberately not a source here. The graph draws a
    # host-local step on a DC as the DC's own node (``dc02 -XpCmdshell-> dc02``
    # runs as the SQL service account, not as the domain controller), and
    # disabling xp_cmdshell on that host is a real fix on a cross-forest chain.
    if (
        rel != "memberof"
        and _principal_holds_domain_control(src)
        and not _crosses_domain(src, dst)
    ):
        return Remediability(
            kind=RemediationKind.NOT_REMEDIABLE,
            why_not=_SOURCE_CONTROLS_DOMAIN_WHY_NOT,
            inherent=True,
        )

    # A domain controller that hosts the certification authority controls the
    # authority by design (ESC5 / ESC7 from the DC onto its own CA).
    if (
        rel.startswith("adcsesc")
        and src is not None
        and src.is_domain_controller
        and src.hosts_certificate_authority
        and not _crosses_domain(src, dst)
    ):
        return Remediability(
            kind=RemediationKind.NOT_REMEDIABLE,
            why_not=_CA_HOST_WHY_NOT,
            inherent=True,
        )

    if rel in _HOST_SCOPED_RELATIONS and _host_is_domain_controller(dst, host_facts):
        return _dc_host_verdict(rel)

    if _account_operators_default(rel, family, src, dst):
        account_operators = _Family(
            RemediationKind.MEMBERSHIP_REMOVAL, _ACCOUNT_OPERATORS_TEMPLATE, family.generic
        )
        return Remediability(
            kind=RemediationKind.MEMBERSHIP_REMOVAL,
            verb=_sentence(account_operators, src, dst),
        )

    exchange_verdict = _exchange_internal_verdict(rel, family, src, dst)
    if exchange_verdict is not None:
        return exchange_verdict

    if (
        rel == "memberof"
        and dst is not None
        and dst.is_direct_tier0
        and src is not None
        and src.kind in {"user", "computer", "group"}
    ):
        tier0_family = _Family(family.kind, _TIER0_MEMBERSHIP_TEMPLATE, family.generic)
        return Remediability(kind=family.kind, verb=_sentence(tier0_family, src, dst))

    return Remediability(kind=family.kind, verb=_sentence(family, src, dst, host_facts))


# ── Chain context ─────────────────────────────────────────────────────────────
#
# One edge cannot always name the object its change is made on. A session-borne
# dump or task is drawn ``robb.stark -> robb.stark`` (the signed-in account's own
# material), and the HOST it happens on is the computer one step back, where the
# session was observed. The stamp seam classifies one edge at a time, so the
# chain pass below resolves that host from the finished step list and rewrites
# the verb. It reads only stamped step details (``source_kind`` from the
# directory, never the shape of a name), so it is idempotent and safe to run on
# a record that was stamped before it existed.


def _details(step: Mapping[str, Any]) -> Mapping[str, Any]:
    details = step.get("details")
    return details if isinstance(details, Mapping) else {}


def _step_relation(step: Mapping[str, Any]) -> str:
    for key in ("action", "relation", "type"):
        value = step.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return ""


def _same_principal(left: Any, right: Any) -> bool:
    a = str(left or "").strip().casefold()
    b = str(right or "").strip().casefold()
    return bool(a) and a == b


def _facts_from_details(details: Mapping[str, Any], side: str) -> PrincipalFacts | None:
    """Build display facts for one endpoint from a stamped step's details."""
    label = str(details.get("from" if side == "source" else "to") or "").strip()
    sam = str(details.get(f"{side}_samaccountname") or "").strip()
    kind = str(details.get(f"{side}_kind") or "").strip().lower()
    if not label and not sam:
        return None
    # A computer the engine stamped Tier 0 direct is a domain controller: Domain
    # Controllers membership is what puts a computer in that tier. The step
    # details carry the stamped tier, not the node's primaryGroupID.
    tier = str(details.get(f"{side}_privilege_tier") or "").strip().lower()
    return PrincipalFacts(
        label=label or sam,
        samaccountname=sam,
        kind=kind,
        is_domain_controller=kind == "computer" and tier == "tier0_direct",
    )


def chain_host_for_step(steps: Sequence[Any], index: int) -> PrincipalFacts | str | None:
    """Return the computer a host-scoped step at ``index`` runs on, or ``None``.

    Resolution, most authoritative first:

    1. The step's own target, when the directory says it is a computer.
    2. Walking back along the chain: the step that delivered this step's source
       principal (its ``to`` is this step's ``from``). If that step starts at a
       computer, the session lives on it (``castelblack$ -HasSession-> robb``). A
       self-loop on the same principal (a task followed by a dump) is skipped.
    3. The ``target_host`` the engine folded into the step's notes.
    """
    if not (0 <= index < len(steps)) or not isinstance(steps[index], Mapping):
        return None
    details = _details(steps[index])
    if str(details.get("target_kind") or "").strip().lower() == "computer":
        return _facts_from_details(details, "target")
    principal = details.get("from")
    for back in range(index - 1, -1, -1):
        prev = steps[back]
        if not isinstance(prev, Mapping):
            break
        prev_details = _details(prev)
        if not _same_principal(prev_details.get("to"), principal):
            break
        if str(prev_details.get("source_kind") or "").strip().lower() == "computer":
            return _facts_from_details(prev_details, "source")
        if not _same_principal(prev_details.get("from"), principal):
            break
    target_host = str(details.get("target_host") or "").strip()
    return target_host or None


def chain_execution_host(steps: Sequence[Any], index: int) -> dict[str, str]:
    """The host a host-scoped step runs on, as the identity a renderer needs.

    ``{}`` when the step is not host-scoped, its target is already a computer
    (the step names its own host), or no host resolves. Otherwise
    ``{"execution_host", "execution_host_samaccountname",
    "execution_host_dnshostname"}``: the display name for prose, and the account
    and DNS names for commands. Same resolution as the remediation verb
    (:func:`chain_host_for_step`), so the narrative, the commands and the fix
    name one host.
    """
    if not (0 <= index < len(steps)) or not isinstance(steps[index], Mapping):
        return {}
    step = steps[index]
    if _step_relation(step) not in _HOST_SCOPED_RELATIONS:
        return {}
    details = _details(step)
    if str(details.get("target_kind") or "").strip().lower() == "computer":
        return {}
    host = chain_host_for_step(steps, index)
    if isinstance(host, PrincipalFacts):
        sam = host.samaccountname
        dns = ""
        # The step that supplied the host carries its DNS name beside it.
        for back in range(index - 1, -1, -1):
            prev_details = _details(steps[back]) if isinstance(steps[back], Mapping) else {}
            if str(prev_details.get("source_samaccountname") or "") == sam and sam:
                dns = str(prev_details.get("source_dnshostname") or "").strip()
                break
        if not dns:
            dns = str(details.get("target_host") or "").strip()
        return {
            "execution_host": host.display,
            "execution_host_samaccountname": sam,
            "execution_host_dnshostname": dns,
        }
    fqdn = str(host).strip() if isinstance(host, str) else ""
    if fqdn:
        return {
            "execution_host": PrincipalFacts(label=fqdn, kind="computer").display,
            "execution_host_samaccountname": "",
            "execution_host_dnshostname": fqdn,
        }
    return {}


def remediability_in_chain(steps: Sequence[Any], index: int) -> Remediability | None:
    """Return the verdict of the step at ``index``, completed with chain context.

    The stamped verdict, except that a host-scoped relation whose stamp could not
    name its host (the edge alone did not carry it) gets its verb re-rendered
    against the host the chain resolves, or an empty verb when none resolves.
    Never mutates ``steps``.
    """
    if not (0 <= index < len(steps)) or not isinstance(steps[index], Mapping):
        return None
    step = steps[index]
    verdict = remediability_for_step(step)
    rel = _step_relation(step)
    if verdict is None or not verdict.is_remediable or rel not in _HOST_SCOPED_RELATIONS:
        return verdict
    details = _details(step)
    host = chain_host_for_step(steps, index)
    if isinstance(host, PrincipalFacts) and host.is_domain_controller:
        return _dc_host_verdict(rel)
    verb = _sentence(
        _family_for(rel),
        _facts_from_details(details, "source"),
        _facts_from_details(details, "target"),
        host if host is not None else "",
    )
    return Remediability(kind=verdict.kind, verb=verb, why_not=verdict.why_not)


def refine_chain_remediability(steps: Sequence[Any]) -> None:
    """Rewrite each host-scoped step's stamped verb with its chain's host, in place.

    Called by the engine wherever it finalises a display record's step list,
    after the per-edge stamp, so every consumer (the remediation ranking, the
    web's step panel, the persisted snapshot) reads a verb that names the host
    the change is made on. Idempotent.
    """
    for index, step in enumerate(steps or ()):
        if not isinstance(step, dict) or not isinstance(step.get("remediability"), Mapping):
            continue
        if _step_relation(step) not in _HOST_SCOPED_RELATIONS:
            continue
        refined = remediability_in_chain(steps, index)
        if refined is not None:
            step["remediability"] = refined.as_dict()
        # The same host, recorded on the step so a single-step renderer (the
        # narrative, the verification commands) names it too. Without it the
        # narrative read "reaches SYSTEM on robb.stark", a user.
        host = chain_execution_host(steps, index)
        details = step.get("details")
        if host and isinstance(details, dict):
            details.update(host)


def remediability_for_step(step: Mapping[str, Any] | None) -> Remediability | None:
    """Return the verdict stamped on one attack-path step, if it carries one.

    The engine stamps every display-path step at derivation time (where the graph
    nodes are in hand) so no consumer has to re-resolve the endpoints. Returns
    ``None`` for a step with no stamp, which the caller reads as "fall back to
    what the relation alone supports".
    """
    if not isinstance(step, Mapping):
        return None
    return Remediability.from_mapping(step.get("remediability"))
