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

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any, Final


__all__ = [
    "PrincipalFacts",
    "Remediability",
    "RemediationKind",
    "classify_edge_remediability",
    "principal_facts_from_node",
    "remediability_for_step",
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
    """

    kind: RemediationKind
    verb: str = ""
    why_not: str = ""

    @property
    def is_remediable(self) -> bool:
        """Return True when this edge may be offered to the client as a fix."""
        return self.kind is not RemediationKind.NOT_REMEDIABLE

    def as_dict(self) -> dict[str, str]:
        """Return the JSON-safe form stamped onto an attack-path step."""
        return {"kind": self.kind.value, "verb": self.verb, "why_not": self.why_not}

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
        """The name to put in a remediation sentence."""
        return self.label or self.object_id


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

    return PrincipalFacts(
        label=label,
        object_id=sid,
        kind=kind,
        rid=_rid_of(sid),
        primary_group_id=_int_or_none(props.get("primarygroupid") or props.get("primaryGroupID")),
        is_builtin_alias=sid.upper().startswith("S-1-5-32-"),
        is_synthetic_well_known=synthetic,
        is_domain_controller=_node_is_domain_controller(node, kind),
        is_direct_tier0=_node_is_direct_tier0(node, kind, sid),
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
    "ntlmreflection": _f(
        RemediationKind.CONFIG_CHANGE,
        "Require SMB signing and LDAP channel binding on {target}.",
        "Require SMB signing and LDAP channel binding.",
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
    "goldencert": _f(
        RemediationKind.CREDENTIAL_ROTATION,
        "Revoke and reissue the certification authority key pair for {target}, "
        "and store the new key in a hardware security module.",
        "Revoke and reissue the certification authority key pair.",
    ),
    "forgedticketfor": _f(
        RemediationKind.CREDENTIAL_ROTATION,
        "Reset the krbtgt account password twice, allowing for replication "
        "between the two resets.",
        "Reset the krbtgt account password twice.",
    ),
    # ── Credential material read from a compromised host ─────────────────────
    "dumplsa": _f(
        RemediationKind.CONFIG_CHANGE,
        "Enable Credential Guard on {target} and stop privileged accounts from "
        "logging on to it interactively.",
        "Enable Credential Guard and stop privileged interactive logons.",
    ),
    "dumplsass": _f(
        RemediationKind.CONFIG_CHANGE,
        "Enable Credential Guard on {target} and stop privileged accounts from "
        "logging on to it interactively.",
        "Enable Credential Guard and stop privileged interactive logons.",
    ),
    "dumpsam": _f(
        RemediationKind.CONFIG_CHANGE,
        "Deploy managed local administrator passwords on {target} so the local "
        "account database yields nothing reusable.",
        "Deploy managed, per-host local administrator passwords.",
    ),
    "dumpdpapi": _f(
        RemediationKind.CONFIG_CHANGE,
        "Stop storing reusable secrets in user credential vaults on {target}.",
        "Stop storing reusable secrets in user credential vaults.",
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
    "exchangeaclescalation": _f(
        RemediationKind.ACL_REVOCATION,
        "Remove the inherited Exchange permissions {source} holds on {target}.",
        "Remove the inherited Exchange permissions from the domain object.",
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
}

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
    # catalog has not caught up would silently shrink the client's fix list; the
    # generic sentence is honest about carrying no detail.
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
    return _f(
        RemediationKind.CONFIG_CHANGE,
        "Remove the configuration on {target} that lets {source} reach it.",
        "Remove the configuration that enables this step.",
    )


def _sentence(family: _Family, source: PrincipalFacts | None, target: PrincipalFacts | None) -> str:
    """Render the family's template with whatever names resolved."""
    src = source.display if source else ""
    dst = target.display if target else ""
    if not src and not dst:
        return family.generic
    try:
        return family.template.format(source=src or "the source principal", target=dst or "the target object")
    except (KeyError, IndexError):  # pragma: no cover - defensive
        return family.generic


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
        )
    if source is not None and source.has_sid and source.is_builtin and target.is_builtin:
        return Remediability(
            kind=RemediationKind.NOT_REMEDIABLE,
            why_not=(
                "Windows creates and maintains this nesting between two built-in "
                "groups. It cannot be removed."
            ),
        )
    return None


def _holds_by_design(source: PrincipalFacts | None) -> bool:
    """True when the source already controls the domain, so the edge follows."""
    if source is None:
        return False
    return source.is_direct_tier0 or source.is_domain_controller


def classify_edge_remediability(
    relation: str | None,
    source: PrincipalFacts | Mapping[str, Any] | None = None,
    target: PrincipalFacts | Mapping[str, Any] | None = None,
) -> Remediability:
    """Return whether ONE edge instance can be changed, and the change if so.

    Args:
        relation: The edge label (``"MemberOf"``, ``"DCSync"``, ``"ADCSESC1"``).
            Matched case-insensitively.
        source: The edge's source, as :class:`PrincipalFacts` or a raw
            attack-graph node. ``None`` when the caller has no node — the
            verdict then falls back to what the relation alone can support.
        target: The edge's target, same shapes.

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
    family = _family_for(rel)

    if family.kind is RemediationKind.NOT_REMEDIABLE:
        return Remediability(
            kind=RemediationKind.NOT_REMEDIABLE,
            why_not=_WHY_NOT_BY_RELATION.get(rel, "There is no client-side change that closes this."),
        )

    # ── Instance rules ───────────────────────────────────────────────────────
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
        )

    if family.kind in _BY_DESIGN_KINDS and _holds_by_design(src):
        return Remediability(
            kind=RemediationKind.NOT_REMEDIABLE,
            why_not=(
                "The source already holds domain-wide administrative control, so "
                "this access follows from that role rather than from a separate "
                "misconfiguration. Reduce who holds the role instead."
            ),
        )

    return Remediability(kind=family.kind, verb=_sentence(family, src, dst))


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
