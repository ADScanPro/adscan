"""Which account a by-hand command runs as: ONE rule, for the report and the web.

A verify, exploit or remediation command a client reproduces authenticates as
somebody. Filling that account with a guess produces a command that fails on the
client's directory, which is worse than an honest fill-in: the reader trusts the
filled value. So the account is resolved from what the workspace PROVES, by the
command's declared requirement, and anything not proven stays a token whose
name says what is needed.

The requirement each command declares (``requires`` on a verification item,
``adscan_core.reporting.verification_model``):

* ``authenticated``: any domain account can run it (a read-only LDAP query).
  Filled with the account the scan itself used.
* ``source_principal``: it must run as a principal that holds the abused right,
  the source of the attack-graph edge behind the finding:

  - a user or computer: that principal;
  - a broad built-in identity (Authenticated Users, Domain Users, Everyone):
    every account is a member, so the scan's own account qualifies;
  - any other group: a known member from the membership SSOT, preferring one
    the assessment controls (stamped by the engine as ``member_example``);
    with no known member, the token stays.

  A finding that is not an attack step has no source principal, so the token
  stays.
* ``local_admin`` / ``local_admin:<host>``: local administrator rights on the
  host. Filled only with a principal the workspace proved holds them.
* ``domain_admin``: filled only with a verified Domain Admin the assessment
  controls.

Secrets are never touched here: a password, hash or key is a different token.

Stdlib only; the web backend imports it (``adscan_core`` ships whole).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from adscan_core.reporting.affected_asset_roles import broad_identity_key

REQUIRES_AUTHENTICATED = "authenticated"
REQUIRES_SOURCE_PRINCIPAL = "source_principal"
REQUIRES_LOCAL_ADMIN = "local_admin"
REQUIRES_DOMAIN_ADMIN = "domain_admin"

#: Every requirement a command can declare (``local_admin`` may carry ``:<host>``).
REQUIREMENTS: tuple[str, ...] = (
    REQUIRES_AUTHENTICATED,
    REQUIRES_SOURCE_PRINCIPAL,
    REQUIRES_LOCAL_ADMIN,
    REQUIRES_DOMAIN_ADMIN,
)

#: The fill-in token left standing when the requirement is not proven, by base.
FILL_IN_TOKENS: dict[str, str] = {
    REQUIRES_AUTHENTICATED: "<user>",
    REQUIRES_SOURCE_PRINCIPAL: "<account_holding_the_right>",
    REQUIRES_LOCAL_ADMIN: "<local_admin_account>",
    REQUIRES_DOMAIN_ADMIN: "<domain_admin_account>",
}

#: The fill-in left for a group source with no known member.
GROUP_MEMBER_FILL_IN = "<member_of_the_source_group>"


def normalize_requirement(value: Any, *, default: str) -> str:
    """Return a valid requirement string, ``default`` when ``value`` is not one."""
    text = str(value or "").strip()
    base, _, host = text.partition(":")
    base = base.strip().lower()
    if base == REQUIRES_LOCAL_ADMIN and host.strip():
        return f"{REQUIRES_LOCAL_ADMIN}:{host.strip()}"
    return base if base in REQUIREMENTS else default


def requirement_base(requires: str) -> str:
    """The requirement without its ``:<host>`` qualifier."""
    return str(requires or "").split(":", 1)[0].strip().lower()


def requirement_text(requires: str) -> str:
    """Client copy naming the account a command needs (for an unfilled token)."""
    base = requirement_base(requires)
    host = str(requires or "").partition(":")[2].strip()
    if base == REQUIRES_LOCAL_ADMIN:
        where = f" on {host}" if host else " on the target host"
        return f"An account with local administrator rights{where}"
    if base == REQUIRES_DOMAIN_ADMIN:
        return "A Domain Admin account"
    if base == REQUIRES_SOURCE_PRINCIPAL:
        return "An account that holds the right this finding describes"
    return "Any domain account"


@dataclass(frozen=True)
class CommandPrincipal:
    """The resolved account a command runs as.

    Attributes:
        requires: The requirement the command declared.
        value: The proven account (sAMAccountName), or ``""``.
        fill_in: The token left standing when ``value`` is empty.
        basis: How ``value`` was proven (``scan_account`` / ``source_principal``
            / ``group_member_controlled`` / ``group_member`` /
            ``broad_identity`` / ``proven_admin``), ``""`` when unresolved.
        needed: Client copy naming what the command needs.
    """

    requires: str
    value: str = ""
    fill_in: str = ""
    basis: str = ""
    needed: str = ""

    @property
    def text(self) -> str:
        """The value to put in the command: the account, or its fill-in token."""
        return self.value or self.fill_in

    def to_dict(self) -> dict[str, str]:
        """Serialize for an API."""
        return {
            "requires": self.requires,
            "value": self.value,
            "fill_in": self.fill_in,
            "basis": self.basis,
            "needed": self.needed,
        }


#: Broad identities the scan's own USER account always belongs to. Domain
#: Computers is broad too, but a user account is not in it, so it is not here.
_SCAN_ACCOUNT_IS_MEMBER: frozenset[str] = frozenset(
    {"authenticated_users", "everyone", "builtin_users", "domain_users", "anonymous_logon"}
)


def _account_name(entity: Mapping[str, Any]) -> str:
    """The sAMAccountName a command names for a user or computer entity."""
    etype = str(entity.get("type") or "").lower()
    ident = str(entity.get("identifier") or entity.get("display") or "").strip()
    if not ident:
        return ""
    if etype == "computer":
        if ident.endswith("$"):
            return ident
        return ident.split(".", 1)[0] + "$"
    return ident


def principal_for_source_entity(
    entity: Mapping[str, Any], *, scan_principal: str = ""
) -> tuple[str, str]:
    """``(account, basis)`` for one source entity, ``("", "")`` when not proven.

    The single per-principal rule: a user or computer is itself, a broad
    built-in identity is the scan's own account, any other group is its stamped
    ``member_example`` (a controlled member first).
    """
    etype = str(entity.get("type") or "").lower()
    if etype in ("user", "computer"):
        name = _account_name(entity)
        return (name, "source_principal") if name else ("", "")
    if etype == "group":
        broad = broad_identity_key(
            sid=str(entity.get("sid") or ""),
            label=str(entity.get("identifier") or entity.get("display") or ""),
        )
        if broad in _SCAN_ACCOUNT_IS_MEMBER:
            return (scan_principal, "broad_identity") if scan_principal else ("", "")
        member = str(entity.get("member_example") or "").strip()
        if member:
            basis = (
                "group_member_controlled"
                if entity.get("member_controlled")
                else "group_member"
            )
            return member, basis
    return "", ""


def resolve_command_principal(
    requires: str,
    *,
    exploiters: Sequence[Mapping[str, Any]] = (),
    attack_step: bool = False,
    scan_principal: str = "",
    proven_domain_admin: str = "",
    proven_local_admins: Mapping[str, str] | None = None,
) -> CommandPrincipal:
    """Resolve the account one command runs as, from what the workspace proves.

    Args:
        requires: The command's declared requirement.
        exploiters: The finding's source entities (who can exploit it), in the
            engine's priority order.
        attack_step: Whether the finding is an attack step.
        scan_principal: The account the scan authenticated as (non-secret).
        proven_domain_admin: A verified Domain Admin the assessment controls.
        proven_local_admins: ``{host (lower-case FQDN or short): account}`` the
            workspace proved holds local administrator rights there.

    Returns:
        The resolved :class:`CommandPrincipal`; never a guess.
    """
    base = requirement_base(requires)
    needed = requirement_text(requires)
    fill_in = FILL_IN_TOKENS.get(base, FILL_IN_TOKENS[REQUIRES_AUTHENTICATED])

    if base == REQUIRES_AUTHENTICATED:
        if scan_principal:
            return CommandPrincipal(requires, scan_principal, fill_in, "scan_account", needed)
        return CommandPrincipal(requires, "", fill_in, "", needed)

    if base == REQUIRES_DOMAIN_ADMIN:
        if proven_domain_admin:
            return CommandPrincipal(requires, proven_domain_admin, fill_in, "proven_admin", needed)
        return CommandPrincipal(requires, "", fill_in, "", needed)

    if base == REQUIRES_LOCAL_ADMIN:
        host = str(requires or "").partition(":")[2].strip().lower()
        admins = proven_local_admins or {}
        account = ""
        if host:
            account = admins.get(host) or admins.get(host.split(".", 1)[0]) or ""
        if not account and proven_domain_admin:
            # A Domain Admin is a local administrator on every domain member.
            account = proven_domain_admin
        if account:
            return CommandPrincipal(requires, account, fill_in, "proven_admin", needed)
        return CommandPrincipal(requires, "", fill_in, "", needed)

    # source_principal
    if not attack_step or not exploiters:
        return CommandPrincipal(requires, "", fill_in, "", needed)
    group_without_member = False
    # An account the assessment controls first (a controlled user, a group
    # whose stamped member is controlled), then the engine's order.
    ordered = sorted(
        exploiters,
        key=lambda e: 0 if (e.get("controlled") or e.get("member_controlled")) else 1,
    )
    for entity in ordered:
        account, basis = principal_for_source_entity(entity, scan_principal=scan_principal)
        if account:
            return CommandPrincipal(requires, account, fill_in, basis, needed)
        if str(entity.get("type") or "").lower() == "group":
            group_without_member = True
    if group_without_member:
        return CommandPrincipal(requires, "", GROUP_MEMBER_FILL_IN, "", needed)
    return CommandPrincipal(requires, "", fill_in, "", needed)


__all__ = [
    "CommandPrincipal",
    "FILL_IN_TOKENS",
    "GROUP_MEMBER_FILL_IN",
    "REQUIREMENTS",
    "REQUIRES_AUTHENTICATED",
    "REQUIRES_DOMAIN_ADMIN",
    "REQUIRES_LOCAL_ADMIN",
    "REQUIRES_SOURCE_PRINCIPAL",
    "normalize_requirement",
    "principal_for_source_entity",
    "requirement_base",
    "requirement_text",
    "resolve_command_principal",
]
