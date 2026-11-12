"""Whether this run may make a change only a cleanup account can undo.

A ``reverted_when_permitted`` check writes a change the assessment's own
credentials cannot remove: a computer account created under the machine-account
quota (its creator holds no Delete right on it), or an attribute a relayed
computer wrote on itself (its identity is gone by the time the change is
reverted). The client can supply a cleanup account to undo exactly these.

Two decisions, one module, pure and stdlib only so the engine, the report and
the web read the same answer:

1. **Before the run** (:class:`adscan_core.scan_policy.resolve.RevertPermissionContext`):
   is a cleanup account supplied at all? Without one, a policy that allows no
   manual cleanup leaves these checks out (``resolve_policy``).
2. **Before each write, per domain** (:func:`decide_revert_permission`): does
   the account hold the right to undo it in THIS domain? Established read-only
   from the collected directory membership (the engine reads it through the
   membership SSOT; this module only decides). The rule the design holds
   throughout: an unresolvable answer counts as not undoable, never as safe.

Design: docs/superpowers/specs/2026-11-06-reversible-by-construction-design.md § 3, § 8.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Mapping

from adscan_core.scan_policy.revert_rights import (
    ROLE_ADMINISTRATORS,
    ROLE_DOMAIN_ADMINS,
    ROLE_ENTERPRISE_ADMINS,
    SCOPE_CA,
    STATE_NOT_PERMITTED,
    STATE_PERMITTED,
    STATE_UNDETERMINABLE,
    registered_revert_rights,
)

REASON_VERIFIED_ADMIN = "verified_admin"
REASON_NO_CLEANUP_ACCOUNT = "no_cleanup_account"
REASON_LACKS_RIGHT = "lacks_right"
REASON_NO_MEMBERSHIP_DATA = "no_membership_data"
REASON_PRINCIPAL_NOT_FOUND = "principal_not_found"
REASON_OTHER_DOMAIN = "other_domain"
#: The account belongs to another forest: an administrator of one forest holds
#: nothing across a forest trust, so this is an observation, not a gap in data.
REASON_OTHER_FOREST = "other_forest"

#: Directory roles that hold each DIRECTORY right (domain or forest scope), read
#: from the revert-right registry so a new token needs no edit here. Deliberately
#: narrow: a delegated right (Account Operators, an OU-level Delete grant) cannot
#: be confirmed from group membership alone, so it is not counted, and the account
#: reads as not verified rather than as able to undo the change. A CA right is
#: never answered here: the CA answers it (``revert_rights.decide_ca_right``).
_ADMIN_ROLES = frozenset({ROLE_DOMAIN_ADMINS, ROLE_ENTERPRISE_ADMINS, ROLE_ADMINISTRATORS})
RIGHT_GRANTING_ROLES: Mapping[str, frozenset[str]] = {
    r.token: r.granting_roles for r in registered_revert_rights() if r.scope != SCOPE_CA
}

#: Domain key the cleanup store uses for "any domain of the run".
ANY_DOMAIN = "*"

_ROLE_RIDS: Mapping[int, str] = {512: ROLE_DOMAIN_ADMINS, 519: ROLE_ENTERPRISE_ADMINS}
_BUILTIN_ADMINISTRATORS_SID = "S-1-5-32-544"


@dataclass(frozen=True)
class RevertPermissionVerdict:
    """The answer for one domain. JSON-safe through :meth:`to_dict`.

    Attributes:
        domain: The domain the change would be made in.
        state: ``permitted`` / ``not_permitted`` / ``undeterminable``.
        reason: One of the ``REASON_*`` codes.
        principal: The cleanup account (never a secret), or ``""``.
        rights: The rights the verdict was asked about.
        roles: The administrative roles found for the account in that domain.
        changes_made: How many changes of the kinds only a cleanup account can
            undo the change ledger records in that domain for this run, or
            ``None`` when the run did not look (a verdict recorded before the
            count existed). What the client sentence says about whether those
            steps ran comes from this number and nothing else.
        changes_reverted: How many of them the ledger records as reverted and
            confirmed. ``None`` whenever ``changes_made`` is.
    """

    domain: str
    state: str
    reason: str
    principal: str = ""
    rights: tuple[str, ...] = ()
    roles: tuple[str, ...] = field(default_factory=tuple)
    changes_made: int | None = None
    changes_reverted: int | None = None

    @property
    def permitted(self) -> bool:
        return self.state == STATE_PERMITTED

    def to_dict(self) -> dict[str, object]:
        return {
            "domain": self.domain,
            "state": self.state,
            "reason": self.reason,
            "principal": self.principal,
            "rights": list(self.rights),
            "roles": list(self.roles),
            "changes_made": self.changes_made,
            "changes_reverted": self.changes_reverted,
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "RevertPermissionVerdict":
        return cls(
            domain=str(data.get("domain") or ""),
            state=str(data.get("state") or STATE_UNDETERMINABLE),
            reason=str(data.get("reason") or ""),
            principal=str(data.get("principal") or ""),
            rights=tuple(str(r) for r in (data.get("rights") or ())),  # type: ignore[union-attr]
            roles=tuple(str(r) for r in (data.get("roles") or ())),  # type: ignore[union-attr]
            changes_made=_optional_count(data.get("changes_made")),
            changes_reverted=_optional_count(data.get("changes_reverted")),
        )


def _optional_count(value: object) -> int | None:
    """A non-negative count, or ``None`` when the record carries none."""
    if value is None or isinstance(value, bool):
        return None
    try:
        return max(0, int(value))  # type: ignore[call-overload]
    except (TypeError, ValueError):
        return None


def admin_roles_from_group_sids(group_sids: Iterable[str], *, domain_sid: str) -> frozenset[str]:
    """The administrative roles a transitive group-SID set confers in ONE domain.

    Only the target domain's own Domain Admins (RID 512) and Enterprise Admins
    (RID 519, the forest root's group) and BUILTIN\\Administrators count. A 512
    from another domain (a foreign security principal) is not an administrator
    here, so it is ignored.
    """
    prefix = str(domain_sid or "").strip().upper()
    roles: set[str] = set()
    for raw in group_sids:
        sid = str(raw or "").strip().upper()
        if not sid:
            continue
        if sid == _BUILTIN_ADMINISTRATORS_SID:
            roles.add(ROLE_ADMINISTRATORS)
            continue
        head, _, rid = sid.rpartition("-")
        if prefix and head == prefix and rid.isdigit() and int(rid) in _ROLE_RIDS:
            roles.add(_ROLE_RIDS[int(rid)])
    return frozenset(roles)


def decide_revert_permission(
    *,
    domain: str,
    rights: Iterable[str],
    principal: str | None,
    principal_domain: str | None,
    membership_available: bool,
    principal_found: bool,
    roles: Iterable[str] = (),
    same_forest: bool | None = None,
) -> RevertPermissionVerdict:
    """The decision table. Every branch that cannot establish the right refuses.

    ``same_forest`` is set by a caller that resolved the account across domains
    (its roles are then already the roles it holds in THIS domain, Enterprise
    Admins included): ``False`` is an observation (another forest), ``True`` lets
    an account of another domain of the forest be judged on those roles.

    | cleanup account for the domain | account's domain | membership data | account found | roles cover every right | verdict |
    |---|---|---|---|---|---|
    | none | | | | | not permitted (no cleanup account) |
    | yes | another forest | | | | not permitted (other forest) |
    | yes | another named domain, forest unresolved | | | | undeterminable (other domain) |
    | yes | this domain or any | missing | | | undeterminable (no membership data) |
    | yes | this domain or any | present | no | | undeterminable (principal not found) |
    | yes | this domain or any | present | yes | yes | permitted |
    | yes | this domain or any | present | yes | no | not permitted (lacks the right) |
    """
    wanted = tuple(sorted({str(r) for r in rights if str(r or "").strip()}))
    name = str(principal or "").strip()
    target = str(domain or "").strip().lower()
    if not name:
        return RevertPermissionVerdict(target, STATE_NOT_PERMITTED, REASON_NO_CLEANUP_ACCOUNT, "", wanted)
    if same_forest is False:
        return RevertPermissionVerdict(target, STATE_NOT_PERMITTED, REASON_OTHER_FOREST, name, wanted)
    home = str(principal_domain or "").strip().lower()
    if home and home != ANY_DOMAIN and home != target and same_forest is not True:
        return RevertPermissionVerdict(target, STATE_UNDETERMINABLE, REASON_OTHER_DOMAIN, name, wanted)
    if not membership_available:
        return RevertPermissionVerdict(target, STATE_UNDETERMINABLE, REASON_NO_MEMBERSHIP_DATA, name, wanted)
    if not principal_found:
        return RevertPermissionVerdict(target, STATE_UNDETERMINABLE, REASON_PRINCIPAL_NOT_FOUND, name, wanted)
    held = frozenset(str(r) for r in roles)
    # A right nobody mapped to a role is never assumed to be held.
    covered = all(held & RIGHT_GRANTING_ROLES.get(right, frozenset()) for right in wanted)
    if wanted and covered:
        return RevertPermissionVerdict(
            target, STATE_PERMITTED, REASON_VERIFIED_ADMIN, name, wanted, tuple(sorted(held))
        )
    return RevertPermissionVerdict(
        target, STATE_NOT_PERMITTED, REASON_LACKS_RIGHT, name, wanted, tuple(sorted(held))
    )


# ── client-facing wording (one place; pass the adscan-writing gate) ───────────


def _n(count: int, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


def _names(titles: list[str]) -> str:
    shown = titles[:4]
    text = ", ".join(shown)
    if len(titles) > 4:
        text += f" and {len(titles) - 4} more"
    return text


def conditional_line(titles: list[str]) -> str:
    """Checks included because a cleanup account was supplied, or ``""``."""
    if not titles:
        return ""
    one = len(titles) == 1
    return (
        f"{_n(len(titles), 'attack step', 'attack steps')} "
        f"{'runs' if one else 'run'} because a cleanup account was supplied "
        f"({_names(titles)}). In each domain ADscan first confirms, without changing "
        f"anything, that the account is an administrator there, then undoes "
        f"{'its' if one else 'their'} change with it and re-reads to confirm. Where "
        f"it cannot confirm that, {'the step does' if one else 'those steps do'} not run."
    )


def conditional_ca_line(titles: list[str]) -> str:
    """Certificate-issuing checks included because a cleanup account was supplied, or ``""``.

    The undo of a certificate is its revocation, and the right that allows it
    lives on each certification authority, not in a directory group, so the
    sentence names the CA check rather than the administrator check.
    """
    if not titles:
        return ""
    one = len(titles) == 1
    return (
        f"{_n(len(titles), 'attack step', 'attack steps')} that request a certificate "
        f"from your certification authority {'runs' if one else 'run'} because a "
        f"cleanup account was supplied ({_names(titles)}). Before requesting one, "
        "ADscan confirms on that CA, without changing anything, that the account can "
        "revoke it, then revokes it with that account and re-reads the CA database to "
        f"confirm. Where it cannot confirm that, {'the step does' if one else 'those steps do'} "
        "not run."
    )


def excluded_line(titles: list[str], *, run_context: bool) -> str:
    """Checks left out for lack of a cleanup account, or ``""``.

    ``run_context`` False is a policy read on its own (the editor, an export):
    it states the condition rather than a fact about a run.
    """
    if not titles:
        return ""
    one = len(titles) == 1
    subject = _n(len(titles), "attack step", "attack steps")
    if run_context:
        return (
            f"{subject} {'was' if one else 'were'} left out because undoing "
            f"{'its' if one else 'their'} change needs a cleanup account and none was "
            f"supplied ({_names(titles)})."
        )
    return (
        f"{subject} {'runs' if one else 'run'} only when a cleanup account is supplied "
        f"for the scan, because only such an account can undo "
        f"{'its' if one else 'their'} change ({_names(titles)})."
    )


def verdict_line(verdict: RevertPermissionVerdict) -> str:
    """What the run established for one domain, in one sentence."""
    domain = verdict.domain or "this domain"
    who = f"the cleanup account {verdict.principal}" if verdict.principal else "the cleanup account"
    if verdict.state == STATE_PERMITTED:
        lead = (
            f"In {domain}, {who} was confirmed as an administrator, so the steps whose "
            "change only it can undo were allowed to run there"
        )
        made, reverted = verdict.changes_made, verdict.changes_reverted
        if made is None:
            # The run did not record what happened: claim nothing beyond the permission.
            return f"{lead}."
        if made == 0:
            return f"{lead}, but none of them made a change in this scan."
        if reverted is not None and reverted >= made:
            return f"{lead}. They ran there and were reverted with it."
        return (
            f"{lead}. They ran there and made {_n(made, 'change', 'changes')}, of which "
            f"{reverted or 0} {'is' if (reverted or 0) == 1 else 'are'} confirmed reverted. "
            "The change ledger records the status of each."
        )
    if verdict.reason == REASON_NO_CLEANUP_ACCOUNT:
        return (
            f"In {domain}, no cleanup account was supplied, so the steps whose change "
            "only such an account can undo did not run there."
        )
    if verdict.reason == REASON_OTHER_FOREST:
        return (
            f"In {domain}, {who} belongs to another forest, and an administrator of one "
            "forest holds nothing across a forest trust, so the steps whose change only "
            "such an account can undo did not run there."
        )
    if verdict.reason == REASON_LACKS_RIGHT:
        return (
            f"In {domain}, {who} is not an administrator of the domain, so the steps "
            "whose change only such an account can undo did not run there."
        )
    return (
        f"In {domain}, ADscan could not confirm that {who} is an administrator of the "
        "domain, so the steps whose change only such an account can undo did not run "
        "there."
    )


__all__ = (
    "ANY_DOMAIN",
    "REASON_LACKS_RIGHT",
    "REASON_NO_CLEANUP_ACCOUNT",
    "REASON_NO_MEMBERSHIP_DATA",
    "REASON_OTHER_DOMAIN",
    "REASON_OTHER_FOREST",
    "REASON_PRINCIPAL_NOT_FOUND",
    "REASON_VERIFIED_ADMIN",
    "RIGHT_GRANTING_ROLES",
    "RevertPermissionVerdict",
    "STATE_NOT_PERMITTED",
    "STATE_PERMITTED",
    "STATE_UNDETERMINABLE",
    "admin_roles_from_group_sids",
    "conditional_ca_line",
    "conditional_line",
    "decide_revert_permission",
    "excluded_line",
    "verdict_line",
)
