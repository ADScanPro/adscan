"""Shared "create-new-or-reuse a privileged account" primitive (SSOT).

Several post-exploitation follow-ups need an attacker-controlled principal they
can elevate and then use for the next step: the RBCD/delegation relay mints (or
reuses) a machine account, and the HasSession / scheduled-task follow-up creates
(or selects an already-owned) domain user and adds it to a privileged group. Both
made the SAME two operator-facing decisions with slightly different wording, and
both need to elevate to the RIGHT group for the target — domain-wide when the
target is a DC, host-local otherwise.

This module centralizes exactly those transport-agnostic decisions so every
consumer resolves them identically:

* :func:`resolve_elevation_scope` — decide the elevation SCOPE from the target
  host, reusing the landed DC-set SSOT (:func:`resolve_domain_controllers`). If
  the target IS a DC of the domain, elevate domain-wide (Domain Admins, RID 512);
  if it is NOT a DC, the account is inherently LOCAL to that host, so elevate to
  the host's local Administrators group and say so to the operator.
* :func:`decide_provisioning_action` — the create-new-vs-reuse-an-owned operator
  choice, routed through the centralized prompt helper so non-interactive runs
  auto-resolve to a SAFE default (create a fresh account — never silently reuse
  someone else's principal).
* :func:`plan_privileged_account` — the one call a consumer makes: it returns a
  typed :class:`PrivilegedAccountPlan` describing WHAT to do (create a new named
  principal, or reuse a specific owned one) and WHICH group to elevate it into.
  The consumer then performs the actual create/reuse + elevation with its own
  transport (native LDAP add-computer, or a remote ``net user`` / ``net group``
  via the scheduled task) — this module deliberately does NOT own that transport,
  because authenticated LDAP, relay-authenticated LDAP, and schtask command
  execution all have different security constraints while sharing this decision
  surface.

English-only. Any account name / group offered to the operator is visible (the
pentester must record what they provisioned) and ``mark_sensitive``'d in the
telemetry recording by the centralized prompt helper.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Sequence

from adscan_internal.models.domain import resolve_domain_controllers

# Well-known RIDs used for the elevation scope. Domain Admins is a domain group
# (RID 512, relative to the domain SID); local Administrators is the BUILTIN
# group (RID 544) local to every machine.
RID_DOMAIN_ADMINS = 512
RID_BUILTIN_ADMINISTRATORS = 544


class ProvisioningAction(str, Enum):
    """What the operator chose to do for the privileged principal."""

    CREATE_NEW = "create_new"
    REUSE_EXISTING = "reuse_existing"
    CANCEL = "cancel"


class ElevationTargetScope(str, Enum):
    """Where the provisioned account gets its privilege.

    ``DOMAIN`` — the target is a DC, so a domain group (Domain Admins) is the
    right elevation and the account is a domain-wide principal.

    ``LOCAL`` — the target is NOT a DC, so a new account is inherently local to
    that host and only the host's local Administrators group is in reach; the
    account is NOT domain-wide, which the operator must be told.
    """

    DOMAIN = "domain"
    LOCAL = "local"


@dataclass(frozen=True, slots=True)
class ElevationScope:
    """Resolved elevation scope for a privileged-account provisioning follow-up."""

    scope: ElevationTargetScope
    group_name: str
    group_rid: int
    target_host: str
    is_domain_wide: bool
    # Human-readable, client/operator-safe rationale, e.g. why a local account.
    rationale: str


@dataclass(frozen=True, slots=True)
class PrivilegedAccountPlan:
    """A resolved plan for a privileged-account provisioning follow-up.

    The consumer executes it with its own transport: for ``CREATE_NEW`` it creates
    ``account_name`` (with ``account_secret`` when the transport sets a password),
    for ``REUSE_EXISTING`` it uses the already-owned ``account_name`` /
    ``account_secret``; either way it elevates into ``elevation.group_name``.
    """

    action: ProvisioningAction
    account_name: str
    account_secret: str | None
    elevation: ElevationScope
    # True only when REUSE_EXISTING was resolved against a known owned principal.
    reused_owned: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_cancelled(self) -> bool:
        """Return whether the operator cancelled the provisioning."""
        return self.action is ProvisioningAction.CANCEL


def resolve_elevation_scope(
    *,
    domain: str,
    target_host: str,
    domains_data: dict[str, Any] | None,
) -> ElevationScope:
    """Decide the elevation SCOPE for a provisioning follow-up from the target.

    Reuses the landed DC-set SSOT (:func:`resolve_domain_controllers`): if
    ``target_host`` aliases a DC of ``domain`` (alias-aware IP/short/FQDN via the
    ``DomainControllers`` value object), the account is elevated domain-wide to
    Domain Admins; otherwise the account is inherently local to that host, so the
    elevation target is the host's local Administrators group.

    Args:
        domain: The AD domain the follow-up runs against.
        target_host: The host the account will operate on (DC or member server).
        domains_data: The session ``domains_data`` mapping (used only to resolve
            the DC topology for ``domain``). ``None`` / missing is treated as "DC
            topology unknown" and resolves to the conservative LOCAL scope.

    Returns:
        An :class:`ElevationScope`. When the DC topology is unknown or the host
        is not recognized as a DC, the scope is ``LOCAL`` (a local account is the
        safe, non-over-claiming default — never claim domain-wide privilege the
        provisioning cannot actually reach).
    """
    domain_data = {}
    if isinstance(domains_data, dict):
        domain_data = domains_data.get(domain) or {}

    is_dc = False
    try:
        controllers = resolve_domain_controllers(domain_data)
        # A non-None record means target_host aliases a known DC (alias-aware).
        is_dc = controllers._record_for_host(target_host) is not None
    except Exception:  # noqa: BLE001 - topology read is best-effort
        is_dc = False

    if is_dc:
        return ElevationScope(
            scope=ElevationTargetScope.DOMAIN,
            group_name="Domain Admins",
            group_rid=RID_DOMAIN_ADMINS,
            target_host=str(target_host or "").strip(),
            is_domain_wide=True,
            rationale=(
                "Target is a domain controller; the account is elevated "
                "domain-wide to Domain Admins."
            ),
        )

    return ElevationScope(
        scope=ElevationTargetScope.LOCAL,
        group_name="Administrators",
        group_rid=RID_BUILTIN_ADMINISTRATORS,
        target_host=str(target_host or "").strip(),
        is_domain_wide=False,
        rationale=(
            "Target is not a domain controller; the account is LOCAL to this "
            "host and is elevated to the host's local Administrators group only "
            "(it is not a domain-wide privilege)."
        ),
    )


def decide_provisioning_action(
    shell: Any,
    *,
    reuse_candidates: Sequence[str] | None = None,
    prompt_title: str = "Privileged account provisioning",
    create_label: str = "Create a new account, then elevate (recommended)",
    reuse_label_prefix: str = "Reuse an owned account: ",
    allow_cancel: bool = True,
) -> tuple[ProvisioningAction, str | None]:
    """Resolve the create-new-vs-reuse-an-owned operator choice (SSOT).

    Routed through the centralized prompt helper (``questionary_select_index``)
    so non-interactive runs auto-resolve to the SAFE default: create a fresh
    account. The safe default is deliberately "create new" — silently reusing a
    principal the operator did not choose would be the surprising, dangerous
    direction (see CLAUDE.md § "Interactive prompts MUST auto-resolve").

    Args:
        shell: Active shell (threaded so the non-interactive predicate can see
            ``shell.auto`` / posture). May be ``None``.
        reuse_candidates: Already-owned principals eligible for reuse. When empty,
            the only outcome is ``CREATE_NEW`` (no prompt is shown).
        prompt_title: Title of the selection prompt.
        create_label: Label for the create-new option (index 0 — the default).
        reuse_label_prefix: Prefix prepended to each reuse candidate label.
        allow_cancel: When ``True`` (default) a "Cancel" option is offered and a
            cancel resolves to ``CANCEL``. When ``False`` no Cancel row is shown
            and an aborted/backed-out prompt resolves to ``CREATE_NEW`` — the
            legacy behaviour of the RBCD delegate selector, which had no Cancel
            row and fell through to minting a fresh account.

    Returns:
        A ``(action, chosen_name)`` tuple. ``chosen_name`` is the selected owned
        principal for ``REUSE_EXISTING`` and ``None`` otherwise. ``CANCEL`` is
        returned only when ``allow_cancel`` is set and the operator explicitly
        cancels an interactive prompt.
    """
    from adscan_core.output import questionary_select_index  # noqa: PLC0415

    candidates = [
        str(name).strip()
        for name in (reuse_candidates or [])
        if str(name or "").strip()
    ]
    if not candidates:
        # Nothing to reuse — the only sensible action is to create a fresh one.
        return ProvisioningAction.CREATE_NEW, None

    options = [create_label]
    options.extend(f"{reuse_label_prefix}{name}" for name in candidates)
    if allow_cancel:
        options.append("Cancel")

    idx = questionary_select_index(
        title=prompt_title,
        options=options,
        default_idx=0,  # safe default: create a fresh account (also the CI answer)
        shell=shell,
    )
    # A backed-out / cancelled prompt (idx is None) resolves to CANCEL when a
    # Cancel row was offered, else to CREATE_NEW (fall through to a fresh account).
    if idx is None:
        return (
            (ProvisioningAction.CANCEL, None)
            if allow_cancel
            else (ProvisioningAction.CREATE_NEW, None)
        )
    if allow_cancel and idx >= len(options) - 1:
        return ProvisioningAction.CANCEL, None
    if idx == 0:
        return ProvisioningAction.CREATE_NEW, None
    return ProvisioningAction.REUSE_EXISTING, candidates[idx - 1]


def plan_privileged_account(
    shell: Any,
    *,
    domain: str,
    target_host: str,
    default_account_name: str,
    default_account_secret: str | None = None,
    domains_data: dict[str, Any] | None = None,
    reuse_pool: dict[str, str] | None = None,
    prompt_title: str = "Privileged account provisioning",
    create_label: str = "Create a new account, then elevate (recommended)",
    reuse_label_prefix: str = "Reuse an owned account: ",
) -> PrivilegedAccountPlan:
    """Resolve a full privileged-account provisioning plan (create/reuse + scope).

    Combines :func:`decide_provisioning_action` and
    :func:`resolve_elevation_scope` into the single call a consumer makes before
    it provisions. The consumer then performs the actual create/reuse and the
    elevation into ``plan.elevation.group_name`` with its own transport.

    Args:
        shell: Active shell (drives the non-interactive predicate).
        domain: The AD domain the follow-up runs against.
        target_host: The host the account will operate on (drives the elevation
            scope: DC -> Domain Admins, non-DC -> local Administrators).
        default_account_name: Name to offer / use when creating a new account.
        default_account_secret: Secret to attach to a newly created account (the
            transport that sets it). ``None`` when the caller sets it later.
        domains_data: Session ``domains_data`` (used to resolve the DC topology).
            Falls back to ``shell.domains_data`` when omitted.
        reuse_pool: Mapping ``owned_principal -> secret`` of already-owned
            principals eligible for reuse. When empty, the plan is always
            ``CREATE_NEW``.
        prompt_title / create_label / reuse_label_prefix: Prompt customization
            forwarded to :func:`decide_provisioning_action`.

    Returns:
        A :class:`PrivilegedAccountPlan`. ``action`` is ``CANCEL`` when the
        operator cancelled; otherwise it carries the account to act on and the
        resolved elevation scope.
    """
    effective_domains_data = domains_data
    if effective_domains_data is None:
        effective_domains_data = getattr(shell, "domains_data", None)

    elevation = resolve_elevation_scope(
        domain=domain,
        target_host=target_host,
        domains_data=effective_domains_data
        if isinstance(effective_domains_data, dict)
        else None,
    )

    pool = reuse_pool if isinstance(reuse_pool, dict) else {}
    action, chosen = decide_provisioning_action(
        shell,
        reuse_candidates=list(pool.keys()),
        prompt_title=prompt_title,
        create_label=create_label,
        reuse_label_prefix=reuse_label_prefix,
    )

    if action is ProvisioningAction.CANCEL:
        return PrivilegedAccountPlan(
            action=ProvisioningAction.CANCEL,
            account_name="",
            account_secret=None,
            elevation=elevation,
        )

    if action is ProvisioningAction.REUSE_EXISTING and chosen:
        return PrivilegedAccountPlan(
            action=ProvisioningAction.REUSE_EXISTING,
            account_name=chosen,
            account_secret=str(pool.get(chosen) or "") or None,
            elevation=elevation,
            reused_owned=True,
        )

    return PrivilegedAccountPlan(
        action=ProvisioningAction.CREATE_NEW,
        account_name=str(default_account_name or "").strip(),
        account_secret=default_account_secret,
        elevation=elevation,
    )


__all__ = [
    "ElevationScope",
    "ElevationTargetScope",
    "PrivilegedAccountPlan",
    "ProvisioningAction",
    "RID_BUILTIN_ADMINISTRATORS",
    "RID_DOMAIN_ADMINS",
    "decide_provisioning_action",
    "plan_privileged_account",
    "resolve_elevation_scope",
]
