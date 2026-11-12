"""The revert-right registry: what undoing a change needs, where, and who holds it.

ONE registry for every right a cleanup account may be asked to hold. Each token
(``REVERT_RIGHT_*`` in :mod:`adscan_core.scan_policy.model`, recorded per check in
``revert_rights``) declares:

* its **scope**, the thing it resolves against: a ``domain``, a ``forest`` (the
  forest-wide configuration partition, resolved against the forest root), or a
  ``ca`` (one certification authority);
* the **roles that grant it** by default: directory roles for a domain or forest
  token, CA roles (the bits ``GetMyRoles`` returns) for a CA token;
* the **probe** that establishes it, registered engine-side against the same
  token (``adscan_internal.services.revert_right_probes``), so the decision never
  rests on what anyone says the account is.

Extension point. A new case is: one token in ``model.py``, one
:func:`register_revert_right` call here, one probe registered engine-side
(``register_revert_right_probe``), and the change kind declared against the token
(``safeguard_profile.CLEANUP_ACCOUNT_REVERT_RIGHTS`` when only an account holding
the right can undo it, ``BACKSTOP_REVERT_RIGHTS`` when the change's own author
undoes it and the cleanup account is the backup). The pre-scan checklist, the
gate and the report then read it with no further code.

Every decision here is pure and stdlib-only, so the engine, the report and the
web read the same answer. The rule the design holds throughout: an answer that
cannot be established counts as "not undoable", never as safe.

Design: docs/superpowers/specs/2026-11-06-reversible-by-construction-design.md § 5-8.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from adscan_core.scan_policy.model import (
    REVERT_RIGHT_DELETE_COMPUTER_ACCOUNT,
    REVERT_RIGHT_LABELS,
    REVERT_RIGHT_MANAGE_CA,
    REVERT_RIGHT_REVOKE_CERTIFICATE,
    REVERT_RIGHT_UNDO_DIRECTORY_CHANGE,
    REVERT_RIGHT_WRITE_FOREST_CONFIGURATION,
    REVERT_RIGHT_WRITE_KEY_CREDENTIAL_LINK,
    REVERT_RIGHT_WRITE_RBCD_DELEGATION,
)

# ── scopes ───────────────────────────────────────────────────────────────────
SCOPE_DOMAIN = "domain"
SCOPE_FOREST = "forest"
SCOPE_CA = "ca"
SCOPES: tuple[str, ...] = (SCOPE_DOMAIN, SCOPE_FOREST, SCOPE_CA)

# ── roles ────────────────────────────────────────────────────────────────────
#: Directory roles, established from directory data (the account's token group
#: SIDs or the collected membership snapshot), never from a group's name.
ROLE_DOMAIN_ADMINS = "domain_admins"
ROLE_ENTERPRISE_ADMINS = "enterprise_admins"
ROLE_ADMINISTRATORS = "administrators"
#: CA roles, as the CA itself reports them (``GetMyRoles``).
CA_ROLE_ADMIN = "ca_admin"  # CA_ACCESS_ADMIN 0x1, "Manage CA"
CA_ROLE_OFFICER = "ca_officer"  # CA_ACCESS_OFFICER 0x2, "Issue and Manage Certificates"
CA_ROLE_BITS: Mapping[str, int] = {CA_ROLE_ADMIN: 0x1, CA_ROLE_OFFICER: 0x2}

_DOMAIN_ADMIN_ROLES = frozenset({ROLE_DOMAIN_ADMINS, ROLE_ENTERPRISE_ADMINS, ROLE_ADMINISTRATORS})

# ── verdict states (same vocabulary as scan_policy.revert_permission) ────────
STATE_PERMITTED = "permitted"
STATE_NOT_PERMITTED = "not_permitted"
STATE_UNDETERMINABLE = "undeterminable"

REASON_VERIFIED = "verified"
REASON_LACKS_RIGHT = "lacks_right"
REASON_NO_CLEANUP_ACCOUNT = "no_cleanup_account"
REASON_OTHER_FOREST = "other_forest"
REASON_NO_DIRECTORY_DATA = "no_directory_data"
REASON_PRINCIPAL_NOT_FOUND = "principal_not_found"
REASON_CA_UNREACHABLE = "ca_unreachable"
REASON_ROLES_UNREADABLE = "roles_unreadable"
#: The CA refused to read the account's roles (E_ACCESSDENIED): it holds no CA role there.
REASON_NO_CA_ROLE = "no_ca_role"
REASON_ROLE_SEPARATION_UNREADABLE = "role_separation_unreadable"
REASON_ROLE_SEPARATION_BOTH_ROLES = "role_separation_both_roles"
REASON_OFFICER_RIGHTS_UNREADABLE = "officer_rights_unreadable"
REASON_OFFICER_RIGHTS_RESTRICTED = "officer_rights_restricted"
REASON_PROBE_FAILED = "probe_failed"

# ── what a change kind needs from the cleanup account ────────────────────────
#: Only an account holding the right can undo the change: the step is gated on it.
NEED_REQUIRED = "required"
#: The change's author undoes it; the cleanup account is the backup.
NEED_BACKSTOP = "backstop"


@dataclass(frozen=True)
class RevertRight:
    """One token of the registry.

    Attributes:
        token: The ``REVERT_RIGHT_*`` value.
        scope: ``domain`` / ``forest`` / ``ca``.
        label: Completes "an account allowed to ..." (client-facing).
        row_label: The checklist subject, a plural noun phrase (client-facing).
        granting_roles: Directory roles (domain/forest) or CA roles (ca).
        console_name: The permission's name in the Windows console, for the
            narrower ask ("Issue and Manage Certificates"). Empty for a
            directory right, where the ask is the administrative group.
        checklist_order: Position of its row inside a section.
    """

    token: str
    scope: str
    label: str
    row_label: str
    granting_roles: frozenset[str]
    console_name: str = ""
    checklist_order: int = 100


_REGISTRY: dict[str, RevertRight] = {}


def register_revert_right(right: RevertRight) -> RevertRight:
    """Add (or replace) a token in the registry. Returns it."""
    if right.scope not in SCOPES:
        raise ValueError(f"unknown revert-right scope {right.scope!r}")
    if not right.granting_roles:
        raise ValueError(f"revert right {right.token!r} names no granting role")
    _REGISTRY[right.token] = right
    return right


def revert_right(token: str) -> RevertRight | None:
    """The registered definition of ``token``, or ``None``."""
    return _REGISTRY.get(str(token or ""))


def registered_revert_rights() -> tuple[RevertRight, ...]:
    """Every token, in checklist order."""
    return tuple(sorted(_REGISTRY.values(), key=lambda r: (r.checklist_order, r.token)))


def rights_for_scope(scope: str, tokens: Iterable[str] | None = None) -> tuple[RevertRight, ...]:
    """Registered tokens of one scope (optionally restricted to ``tokens``)."""
    wanted = None if tokens is None else {str(t) for t in tokens}
    return tuple(
        r for r in registered_revert_rights() if r.scope == scope and (wanted is None or r.token in wanted)
    )


register_revert_right(
    RevertRight(
        token=REVERT_RIGHT_DELETE_COMPUTER_ACCOUNT,
        scope=SCOPE_DOMAIN,
        label=REVERT_RIGHT_LABELS[REVERT_RIGHT_DELETE_COMPUTER_ACCOUNT],
        row_label="computer accounts ADscan creates",
        granting_roles=_DOMAIN_ADMIN_ROLES,
        checklist_order=10,
    )
)
register_revert_right(
    RevertRight(
        token=REVERT_RIGHT_WRITE_RBCD_DELEGATION,
        scope=SCOPE_DOMAIN,
        label=REVERT_RIGHT_LABELS[REVERT_RIGHT_WRITE_RBCD_DELEGATION],
        row_label="delegation a relayed computer writes on itself",
        granting_roles=_DOMAIN_ADMIN_ROLES,
        checklist_order=20,
    )
)
register_revert_right(
    RevertRight(
        token=REVERT_RIGHT_WRITE_KEY_CREDENTIAL_LINK,
        scope=SCOPE_DOMAIN,
        label=REVERT_RIGHT_LABELS[REVERT_RIGHT_WRITE_KEY_CREDENTIAL_LINK],
        row_label="key credentials a relayed computer writes on itself",
        granting_roles=_DOMAIN_ADMIN_ROLES,
        checklist_order=30,
    )
)
register_revert_right(
    RevertRight(
        token=REVERT_RIGHT_UNDO_DIRECTORY_CHANGE,
        scope=SCOPE_DOMAIN,
        label=REVERT_RIGHT_LABELS[REVERT_RIGHT_UNDO_DIRECTORY_CHANGE],
        row_label="other directory changes (permissions, owners, group memberships, attributes)",
        granting_roles=_DOMAIN_ADMIN_ROLES,
        checklist_order=40,
    )
)
register_revert_right(
    RevertRight(
        token=REVERT_RIGHT_WRITE_FOREST_CONFIGURATION,
        scope=SCOPE_FOREST,
        label=REVERT_RIGHT_LABELS[REVERT_RIGHT_WRITE_FOREST_CONFIGURATION],
        row_label="certificate templates and the templates a CA publishes",
        # The configuration partition is forest-wide: a Domain Admin of a child
        # domain holds nothing there, so only Enterprise Admins is counted.
        granting_roles=frozenset({ROLE_ENTERPRISE_ADMINS}),
        checklist_order=50,
    )
)
register_revert_right(
    RevertRight(
        token=REVERT_RIGHT_REVOKE_CERTIFICATE,
        scope=SCOPE_CA,
        label=REVERT_RIGHT_LABELS[REVERT_RIGHT_REVOKE_CERTIFICATE],
        row_label="certificates ADscan requests",
        granting_roles=frozenset({CA_ROLE_OFFICER}),
        console_name="Issue and Manage Certificates",
        checklist_order=60,
    )
)
register_revert_right(
    RevertRight(
        token=REVERT_RIGHT_MANAGE_CA,
        scope=SCOPE_CA,
        label=REVERT_RIGHT_LABELS[REVERT_RIGHT_MANAGE_CA],
        row_label="certificate manager rights ADscan grants on the CA",
        granting_roles=frozenset({CA_ROLE_ADMIN}),
        console_name="Manage CA",
        checklist_order=70,
    )
)


# ── verdict ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RightVerdict:
    """Whether one account holds one right on one target. JSON-safe via :meth:`to_dict`.

    Attributes:
        token: The revert right.
        scope: Its scope.
        target: The domain, the forest root, or the CA key (``host\\name``).
        state: ``permitted`` / ``not_permitted`` / ``undeterminable``.
        reason: One of the ``REASON_*`` codes.
        principal: The account (never a secret).
        roles: The roles that were established (directory or CA).
        checked_at: ISO-8601 UTC timestamp of the probe (display only: every scan
            re-verifies, the stamp is never the decision on its own).
        detail: Facts behind the verdict (CA reads, the forest), JSON-safe.
    """

    token: str
    scope: str
    target: str
    state: str
    reason: str
    principal: str = ""
    roles: tuple[str, ...] = ()
    checked_at: str = ""
    detail: Mapping[str, Any] = field(default_factory=dict)

    @property
    def permitted(self) -> bool:
        return self.state == STATE_PERMITTED

    def to_dict(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "scope": self.scope,
            "target": self.target,
            "state": self.state,
            "reason": self.reason,
            "principal": self.principal,
            "roles": list(self.roles),
            "checked_at": self.checked_at,
            "detail": dict(self.detail),
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "RightVerdict":
        detail = data.get("detail")
        return cls(
            token=str(data.get("token") or ""),
            scope=str(data.get("scope") or ""),
            target=str(data.get("target") or ""),
            state=str(data.get("state") or STATE_UNDETERMINABLE),
            reason=str(data.get("reason") or ""),
            principal=str(data.get("principal") or ""),
            roles=tuple(str(r) for r in (data.get("roles") or ())),
            checked_at=str(data.get("checked_at") or ""),
            detail=dict(detail) if isinstance(detail, Mapping) else {},
        )


# ── directory roles, from directory data ─────────────────────────────────────

_BUILTIN_ADMINISTRATORS_SID = "S-1-5-32-544"


def directory_roles(
    group_sids: Iterable[str],
    *,
    home_domain_sid: str,
    target_domain_sid: str,
    forest_root_sid: str,
    same_forest: bool,
) -> frozenset[str]:
    """The administrative roles an account holds in ONE target domain.

    ``group_sids`` is the account's transitive group SID set as a domain
    controller of its HOME domain computes it (``tokenGroups``) or as the
    collected membership snapshot resolves it. Three facts, each from SIDs:

    * Enterprise Admins is the forest root's RID 519, and it administers every
      domain of ITS forest only (a forest trust carries nothing across).
    * Domain Admins (RID 512) and BUILTIN\\Administrators count only in the
      account's own domain: the forest root's Domain Admins is not an
      administrator of a child domain.
    """
    sids = {str(s or "").strip().upper() for s in group_sids if str(s or "").strip()}
    home = str(home_domain_sid or "").strip().upper()
    target = str(target_domain_sid or "").strip().upper()
    root = str(forest_root_sid or "").strip().upper()
    roles: set[str] = set()
    if same_forest and root and f"{root}-519" in sids:
        roles.add(ROLE_ENTERPRISE_ADMINS)
    if home and target and home == target:
        if f"{target}-512" in sids:
            roles.add(ROLE_DOMAIN_ADMINS)
        if _BUILTIN_ADMINISTRATORS_SID in sids:
            roles.add(ROLE_ADMINISTRATORS)
    return frozenset(roles)


def decide_directory_right(
    right: RevertRight,
    *,
    target: str,
    principal: str | None,
    same_forest: bool | None,
    directory_data: bool,
    principal_found: bool,
    roles: Iterable[str] = (),
    checked_at: str = "",
    detail: Mapping[str, Any] | None = None,
) -> RightVerdict:
    """The decision for a ``domain`` or ``forest`` token.

    | account | same forest | directory data | account found | roles grant it | verdict |
    |---|---|---|---|---|---|
    | none | | | | | not permitted (no cleanup account) |
    | yes | no | | | | not permitted (other forest) |
    | yes | unknown | | | | undeterminable (no directory data) |
    | yes | yes | missing | | | undeterminable (no directory data) |
    | yes | yes | present | no | | undeterminable (principal not found) |
    | yes | yes | present | yes | yes | permitted |
    | yes | yes | present | yes | no | not permitted (lacks the right) |
    """
    name = str(principal or "").strip()
    held = tuple(sorted({str(r) for r in roles}))

    def _v(state: str, reason: str) -> RightVerdict:
        return RightVerdict(
            right.token, right.scope, target, state, reason, name, held, checked_at, dict(detail or {})
        )

    if not name:
        return _v(STATE_NOT_PERMITTED, REASON_NO_CLEANUP_ACCOUNT)
    if same_forest is False:
        return _v(STATE_NOT_PERMITTED, REASON_OTHER_FOREST)
    if same_forest is None or not directory_data:
        return _v(STATE_UNDETERMINABLE, REASON_NO_DIRECTORY_DATA)
    if not principal_found:
        return _v(STATE_UNDETERMINABLE, REASON_PRINCIPAL_NOT_FOUND)
    if set(held) & right.granting_roles:
        return _v(STATE_PERMITTED, REASON_VERIFIED)
    return _v(STATE_NOT_PERMITTED, REASON_LACKS_RIGHT)


# ── CA rights, from what the CA itself answers ──────────────────────────────


#: The HRESULT a CA answers when it refuses the caller (E_ACCESSDENIED).
CA_ACCESS_DENIED_HRESULT = 0x80070005


def is_ca_access_denied(error_code: Any) -> bool:
    """Whether a CA read failed because the CA refused the caller (E_ACCESSDENIED).

    Only the CA's own HRESULT counts. A transport or RPC-runtime failure, or an
    error with no code, is not an answer from the CA.
    """
    if isinstance(error_code, bool) or not isinstance(error_code, int):
        return False
    return (int(error_code) & 0xFFFFFFFF) == CA_ACCESS_DENIED_HRESULT


def role_separation_state(value: Any) -> bool | None:
    """The CA's role-separation flag read definitively, or ``None``.

    [MS-WCCE] 3.2.1.4.3.2.23: the CA MUST return 1 when role separation is
    enabled and 0 when it is disabled. Only those two values are an answer. A
    missing, unparseable or out-of-range value is "could not be confirmed",
    never "on" (which would refuse a valid account) and never "off".
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    if number == 1:
        return True
    if number == 0:
        return False
    return None


def ca_roles_from_bits(bits: int | None) -> frozenset[str]:
    """The CA roles a ``GetMyRoles`` bitmask grants."""
    if bits is None:
        return frozenset()
    return frozenset(role for role, bit in CA_ROLE_BITS.items() if int(bits) & bit)


def decide_ca_right(
    right: RevertRight,
    *,
    target: str,
    principal: str | None,
    reachable: bool,
    roles_bits: int | None,
    role_separation: int | None,
    officer_rights_enabled: bool | None,
    roles_refused: bool = False,
    checked_at: str = "",
    detail: Mapping[str, Any] | None = None,
) -> RightVerdict:
    """The decision for a ``ca`` token (design § 6, the four facts).

    1. ``GetMyRoles`` must answer and carry the bit the right needs. A read that
       failed for an unknown reason (transport, packet privacy, an unparsed
       answer) is undeterminable. A read the CA itself REFUSED with access denied
       (``roles_refused``, E_ACCESSDENIED from the CA) is the CA's answer: the
       account holds no CA role there it could act with, so it is "not with this
       account", never "could not be confirmed". A read that answered without the
       bit is the same observation.
    2. Role separation must be read DEFINITIVELY (:func:`role_separation_state`).
       Only a value the CA reported as on (1) counts as on; an unreadable or
       out-of-range value is undeterminable, never "on" and never "off". With it
       on, an account holding BOTH CA roles is refused every action, so that is
       undeterminable.
    3. For the officer right only: officer rights must be unrestricted
       (``GetOfficerRights`` answered disabled). A restriction list is a second
       access check the roles do not show, so it is undeterminable.
    4. The CA administration interface answered remotely at all (``reachable``).

    Anything short of all four is undeterminable.
    """
    name = str(principal or "").strip()
    held = tuple(sorted(ca_roles_from_bits(roles_bits)))

    def _v(state: str, reason: str) -> RightVerdict:
        return RightVerdict(
            right.token, right.scope, target, state, reason, name, held, checked_at, dict(detail or {})
        )

    if not name:
        return _v(STATE_NOT_PERMITTED, REASON_NO_CLEANUP_ACCOUNT)
    if not reachable:
        return _v(STATE_UNDETERMINABLE, REASON_CA_UNREACHABLE)
    if roles_bits is None:
        if roles_refused:
            return _v(STATE_NOT_PERMITTED, REASON_NO_CA_ROLE)
        return _v(STATE_UNDETERMINABLE, REASON_ROLES_UNREADABLE)
    if not set(held) & right.granting_roles:
        return _v(STATE_NOT_PERMITTED, REASON_LACKS_RIGHT)
    separation = role_separation_state(role_separation)
    if separation is None:
        return _v(STATE_UNDETERMINABLE, REASON_ROLE_SEPARATION_UNREADABLE)
    if separation and {CA_ROLE_ADMIN, CA_ROLE_OFFICER} <= set(held):
        return _v(STATE_UNDETERMINABLE, REASON_ROLE_SEPARATION_BOTH_ROLES)
    if CA_ROLE_OFFICER in right.granting_roles:
        if officer_rights_enabled is None:
            return _v(STATE_UNDETERMINABLE, REASON_OFFICER_RIGHTS_UNREADABLE)
        if officer_rights_enabled:
            return _v(STATE_UNDETERMINABLE, REASON_OFFICER_RIGHTS_RESTRICTED)
    return _v(STATE_PERMITTED, REASON_VERIFIED)


def ca_key(ca_host: str, ca_name: str) -> str:
    """The CA's stable key (``host\\name``, lower-cased host)."""
    return f"{str(ca_host or '').strip().lower()}\\{str(ca_name or '').strip()}"


__all__ = (
    "CA_ACCESS_DENIED_HRESULT",
    "CA_ROLE_ADMIN",
    "CA_ROLE_BITS",
    "CA_ROLE_OFFICER",
    "NEED_BACKSTOP",
    "NEED_REQUIRED",
    "REASON_CA_UNREACHABLE",
    "REASON_LACKS_RIGHT",
    "REASON_NO_CA_ROLE",
    "REASON_NO_CLEANUP_ACCOUNT",
    "REASON_NO_DIRECTORY_DATA",
    "REASON_OFFICER_RIGHTS_RESTRICTED",
    "REASON_OFFICER_RIGHTS_UNREADABLE",
    "REASON_OTHER_FOREST",
    "REASON_PRINCIPAL_NOT_FOUND",
    "REASON_PROBE_FAILED",
    "REASON_ROLES_UNREADABLE",
    "REASON_ROLE_SEPARATION_BOTH_ROLES",
    "REASON_ROLE_SEPARATION_UNREADABLE",
    "REASON_VERIFIED",
    "ROLE_ADMINISTRATORS",
    "ROLE_DOMAIN_ADMINS",
    "ROLE_ENTERPRISE_ADMINS",
    "RevertRight",
    "RightVerdict",
    "SCOPES",
    "SCOPE_CA",
    "SCOPE_DOMAIN",
    "SCOPE_FOREST",
    "STATE_NOT_PERMITTED",
    "STATE_PERMITTED",
    "STATE_UNDETERMINABLE",
    "ca_key",
    "ca_roles_from_bits",
    "decide_ca_right",
    "decide_directory_right",
    "directory_roles",
    "is_ca_access_denied",
    "role_separation_state",
    "register_revert_right",
    "registered_revert_rights",
    "revert_right",
    "rights_for_scope",
)
