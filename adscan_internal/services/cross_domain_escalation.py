"""Shared cross-domain escalation step (post-compromise, mode-agnostic).

After a domain is compromised, ADscan asks ONE mode-agnostic question — *can this
just-compromised domain escalate INTO another domain?* — and fires the escalation
techniques that APPLY. This runs for BOTH ``ctf`` and ``audit`` (escalating across
a trust is not mode-specific) and BEFORE the mode-specific followups (ctf flags /
audit re-collection + dump campaign), because reaching another domain opens surface
those followups should then cover.

Two techniques ship today; the registry is extensible (SID-history abuse,
unconstrained-delegation-across-trust, foreign-group-membership append here):

* ``CrossOrgTgtDelegation`` — a compromised TRUSTED forest escalates into the
  TRUSTING forest via a forwardable-TGT capture (the DarkZero ``.ext -> .htb`` case).
* ``RaiseChild`` — a compromised CHILD domain escalates to the forest ROOT via an
  inter-realm ticket carrying the root's SID history (the GOAD child->parent case).

Re-entrancy: an escalation fires an attack step (coerce/capture/DCSync) and then
re-materializes the graph and recurses, exactly the hazard the audit
post-compromise pipeline avoids by QUEUEING. So this step is queued on promote and
drained at a safe checkpoint (``execute_cross_domain_escalation``), deferring while
attack-path execution is active — NEVER run inline inside ``promote_to_pwned``.

Each registered technique's ``relation`` MUST be a member of
``attack_graph_core._CROSS_DOMAIN_ESCALATION_RELATIONS`` (locked by a test) so the
DFS terminal-lift SSOT and this execution registry cannot drift.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from adscan_core import telemetry
from adscan_core.rich_output import print_exception, print_info_debug
from adscan_internal.models.domain import resolve_dc_ip
from adscan_internal.rich_output import mark_sensitive


@dataclass(frozen=True)
class EscalationTarget:
    """One applicable escalation from a compromised domain into another domain.

    Attributes:
        target_domain: The domain this escalation would compromise (the escalation
            terminal — the trusting forest, or the parent/forest root).
        relation: The graph relation this escalation corresponds to (must be a
            member of ``_CROSS_DOMAIN_ESCALATION_RELATIONS``).
        params: Technique-specific parameters the fire function consumes.
    """

    target_domain: str
    relation: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EscalationResult:
    """Outcome of firing one escalation technique."""

    success: bool
    compromised_domain: str | None = None  # the domain now owned, on success
    error: str | None = None


@dataclass(frozen=True)
class CrossDomainEscalationTechnique:
    """A cross-domain escalation technique in the registry.

    ``applies`` returns 0..N ``EscalationTarget`` for a just-compromised domain;
    ``fire`` executes one target and returns whether it compromised the target.
    Both take the live ``shell`` (source of ``domains_data`` + credentials).
    """

    key: str
    relation: str
    applies: Callable[[Any, str], list[EscalationTarget]]
    fire: Callable[[Any, str, str, str, EscalationTarget], EscalationResult]


# --------------------------------------------------------------------------- #
# Technique 1 — CrossOrgTgtDelegation (trusted forest -> trusting forest)
# --------------------------------------------------------------------------- #


def _cross_org_applies(shell: Any, compromised_domain: str) -> list[EscalationTarget]:
    """Return the trusting forests reachable from a compromised trusted forest.

    Reuses the trust-attribute detection SSOT
    (``attack_graph_core._iter_cross_org_tgt_delegation_trusts``): a record's
    ``target_domain`` is the TRUSTED (compromised) forest and ``source_domain`` is
    the TRUSTING forest = the escalation TARGET. So filter records whose
    ``target_domain`` equals the just-compromised domain.
    """
    from adscan_internal.services.attack_graph_core import (
        _CROSS_ORG_TGT_DELEGATION_RELATION,
        _iter_cross_org_tgt_delegation_trusts,
    )

    domains_data = getattr(shell, "domains_data", {}) or {}
    compromised = str(compromised_domain or "").strip().lower()
    targets: list[EscalationTarget] = []
    seen: set[str] = set()
    for trust in _iter_cross_org_tgt_delegation_trusts(None, domains_data):
        if str(trust.get("target_domain") or "").strip().lower() != compromised:
            continue
        trusting = str(trust.get("source_domain") or "").strip().lower()
        if not trusting or trusting == compromised or trusting in seen:
            continue
        seen.add(trusting)
        targets.append(
            EscalationTarget(
                target_domain=trusting,
                relation=_CROSS_ORG_TGT_DELEGATION_RELATION,
                params={"service_domain": compromised},
            )
        )
    return targets


def _cross_org_fire(
    shell: Any,
    compromised_domain: str,
    username: str,
    credential: str,
    target: EscalationTarget,
) -> EscalationResult:
    """Fire the cross-org escalation via the executor seam (async)."""
    from adscan_internal.services.async_bridge import run_async_sync
    from adscan_internal.services.cross_forest_tgt_delegation_step import (
        run_cross_org_tgt_delegation_step,
    )

    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "") or None
    try:
        result = run_async_sync(
            run_cross_org_tgt_delegation_step(
                shell,
                trusting_domain=target.target_domain,
                service_domain=str(target.params.get("service_domain") or compromised_domain),
                workspace_dir=workspace_dir or "",
            )
        )
    except Exception as exc:  # noqa: BLE001 — never break the post-compromise flow
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return EscalationResult(success=False, error=str(exc))
    ok = bool(getattr(result, "success", False))
    return EscalationResult(
        success=ok,
        compromised_domain=target.target_domain if ok else None,
        error=None if ok else str(getattr(result, "error", "") or "did not complete"),
    )


# --------------------------------------------------------------------------- #
# Technique 2 — RaiseChild (child domain -> parent / forest root)
# --------------------------------------------------------------------------- #


def _raise_child_applies(shell: Any, compromised_domain: str) -> list[EscalationTarget]:
    """Return the forest root when the compromised domain is a same-forest child.

    Mirrors ``run_raise_child``'s own child/parent identification (the parent is
    the DNS suffix and must be a known, initialized domain) but hardens the DC-IP
    reads through the ``resolve_dc_ip`` SSOT (a child/parent DC is often multi-homed).
    """
    from adscan_internal.services.attack_graph_core import _RAISE_CHILD_RELATION

    domains_data = getattr(shell, "domains_data", {}) or {}
    child = str(compromised_domain or "").strip().lower()
    parts = child.split(".", 1)
    if len(parts) < 2:
        return []
    parent = parts[1]
    if parent == child or parent not in {
        str(k).strip().lower() for k in domains_data.keys()
    }:
        return []
    # Require a WITHIN_FOREST trust child->parent (avoid a DNS-suffix coincidence).
    child_data = domains_data.get(compromised_domain) or domains_data.get(child) or {}
    has_within_forest = any(
        str(t.get("target_domain") or "").strip().lower() == parent
        and "WITHIN_FOREST"
        in {str(f).strip().upper() for f in (t.get("attribute_flags") or ())}
        for t in (child_data.get("trusts") or ())
        if isinstance(t, dict)
    )
    if not has_within_forest:
        return []
    # Both DCs must resolve (SSOT — never a bare .get("pdc")).
    parent_data = domains_data.get(parent) or {}
    if not resolve_dc_ip(child_data) or not resolve_dc_ip(parent_data):
        return []
    return [
        EscalationTarget(
            target_domain=parent,
            relation=_RAISE_CHILD_RELATION,
            params={"child_domain": child},
        )
    ]


def _raise_child_fire(
    shell: Any,
    compromised_domain: str,
    username: str,
    credential: str,
    target: EscalationTarget,
) -> EscalationResult:
    """Fire RaiseChild via the native escalation entry point."""
    from adscan_internal.cli.privileges import run_raise_child

    try:
        run_raise_child(
            shell, domain=compromised_domain, username=username, password=credential
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return EscalationResult(success=False, error=str(exc))
    # run_raise_child add_credentials the forest-root secrets on success and does
    # not return a status; treat a compromise of the parent as proven when the
    # parent domain now holds recovered credentials. The drain layer verifies via
    # promote_to_pwned idempotency, so a failed forge simply escalates nothing.
    parent_creds = (
        (getattr(shell, "domains_data", {}) or {}).get(target.target_domain) or {}
    ).get("credentials") or {}
    ok = bool(parent_creds)
    return EscalationResult(
        success=ok,
        compromised_domain=target.target_domain if ok else None,
        error=None if ok else "raise_child did not recover forest-root credentials",
    )


# --------------------------------------------------------------------------- #
# The registry (extensible — append new techniques here)
# --------------------------------------------------------------------------- #

CROSS_DOMAIN_ESCALATION_TECHNIQUES: list[CrossDomainEscalationTechnique] = [
    CrossDomainEscalationTechnique(
        key="cross_org_tgt_delegation",
        relation="CrossOrgTgtDelegation",
        applies=_cross_org_applies,
        fire=_cross_org_fire,
    ),
    CrossDomainEscalationTechnique(
        key="raise_child",
        relation="RaiseChild",
        applies=_raise_child_applies,
        fire=_raise_child_fire,
    ),
]


# --------------------------------------------------------------------------- #
# Queue + drain (mirrors the audit post-compromise queue in cli/post_da.py)
# --------------------------------------------------------------------------- #


def _get_pending(shell: Any) -> dict[str, dict[str, str]]:
    pending = getattr(shell, "_cross_domain_escalation_pending", None)
    if not isinstance(pending, dict):
        pending = {}
        shell._cross_domain_escalation_pending = pending  # type: ignore[attr-defined]
    return pending


def _get_dispatched(shell: Any) -> set:
    """Set of (compromised_domain, target_domain, technique) already fired."""
    dispatched = getattr(shell, "_cross_domain_escalation_dispatched", None)
    if not isinstance(dispatched, set):
        dispatched = set()
        shell._cross_domain_escalation_dispatched = dispatched  # type: ignore[attr-defined]
    return dispatched


def _dispatch_key(
    compromised_domain: str, target_domain: str, technique_key: str
) -> tuple[str, str, str]:
    """Canonical, case-folded dedup key for the dispatched set.

    Case-folding matters: the same real technique may be requested from two
    seams that carry the domain string in different case (the attack-path
    dispatch has the path's ``domain`` verbatim; the drain has whatever
    ``promote_to_pwned`` queued). Without normalization a case-only variant
    forks the key and the exactly-once guarantee breaks — that is precisely
    the RaiseChild double-fire this SSOT exists to prevent.
    """
    return (
        str(compromised_domain or "").strip().casefold(),
        str(target_domain or "").strip().casefold(),
        str(technique_key or "").strip().casefold(),
    )


def is_technique_dispatched(
    shell: Any, *, compromised_domain: str, target_domain: str, technique_key: str
) -> bool:
    """True when this exact (child, target, technique) escalation already fired.

    SSOT read of the shared dispatched set. Both entry points that can execute a
    cross-domain escalation — the attack-path step dispatcher and the
    post-compromise drain — consult and write THIS set, so a technique fired
    inline by one is never re-fired by the other.
    """
    return _dispatch_key(compromised_domain, target_domain, technique_key) in (
        _get_dispatched(shell)
    )


def mark_technique_dispatched(
    shell: Any, *, compromised_domain: str, target_domain: str, technique_key: str
) -> None:
    """Record a cross-domain escalation as fired in the shared dispatched set.

    The attack-path RaiseChild dispatcher calls this immediately before it runs
    ``run_raise_child`` inline, so the subsequent post-compromise drain (which the
    child DCSync's ``promote_to_pwned`` queued) sees the ``(child, parent,
    "raise_child")`` key already present and skips it — one execution, one
    credential shape, never a competing degraded re-fire. This is the ONE SSOT for
    "did this escalation already run"; do not add a parallel guard.
    """
    _get_dispatched(shell).add(
        _dispatch_key(compromised_domain, target_domain, technique_key)
    )


def queue_cross_domain_escalation(
    shell: Any, *, domain: str, username: str, credential: str
) -> None:
    """Queue cross-domain escalation for a just-compromised ``domain``.

    Mode-agnostic (ctf AND audit). Queue-only — drained at a safe checkpoint by
    :func:`execute_cross_domain_escalation`; NEVER run inline (re-entrancy). A
    per-domain queue entry that is already queued is overwritten with the latest
    credential (idempotent by construction; the dispatched set gates re-fires).
    """
    dom = str(domain or "").strip()
    if not dom:
        return
    _get_pending(shell)[dom] = {
        "username": str(username or ""),
        "credential": str(credential or ""),
    }


def execute_cross_domain_escalation(shell: Any, domain: str) -> None:
    """Drain the queued cross-domain escalation for ``domain`` when safe.

    * No-op when nothing is queued for the domain.
    * Defers (stays queued) while attack-path execution is active — the fire runs
      DCSync + re-discovery and must not re-enter the attack-path engine.
    * For each registered technique, runs ``applies`` then ``fire`` for each target
      not already dispatched. On success, RECURSES via ``promote_to_pwned`` so the
      newly-owned domain runs its own post-compromise (flags/dumps/further
      escalation). Cycle-safe: the dispatched set + ``promote_to_pwned`` idempotency
      (an already-pwned domain is a no-op) prevent an A->B->A trust loop.
    """
    dom = str(domain or "").strip()
    if not dom:
        return
    pending = _get_pending(shell)
    ctx = pending.get(dom)
    if ctx is None:
        return

    try:
        from adscan_internal.services.attack_graph_runtime_service import (
            is_attack_path_execution_active,
        )

        if is_attack_path_execution_active(shell):
            print_info_debug(
                "[cross-domain-escalation] deferring "
                f"{mark_sensitive(dom, 'domain')} (attack-path execution active)"
            )
            return
    except Exception as exc:  # noqa: BLE001 — never block on the guard import
        telemetry.capture_exception(exc)

    # Remove from the queue up front so a re-entrant drain cannot double-fire it.
    pending.pop(dom, None)
    dispatched = _get_dispatched(shell)
    username = str(ctx.get("username") or "")
    credential = str(ctx.get("credential") or "")

    newly_owned: list[tuple[str, str, str]] = []
    for technique in CROSS_DOMAIN_ESCALATION_TECHNIQUES:
        try:
            targets = technique.applies(shell, dom)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            continue
        for target in targets:
            fire_key = _dispatch_key(dom, target.target_domain, technique.key)
            if fire_key in dispatched:
                # Already fired — either by a prior drain, or INLINE by the
                # attack-path step dispatcher (which marks the same SSOT key
                # before it runs run_raise_child). This is what stops the
                # RaiseChild double-fire (and its RC4-degraded re-fire).
                continue
            dispatched.add(fire_key)
            print_info_debug(
                "[cross-domain-escalation] firing "
                f"{mark_sensitive(technique.key, 'text')}: "
                f"{mark_sensitive(dom, 'domain')} -> "
                f"{mark_sensitive(target.target_domain, 'domain')}"
            )
            try:
                result = technique.fire(shell, dom, username, credential, target)
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                continue
            if result.success and result.compromised_domain:
                newly_owned.append(
                    (result.compromised_domain, username, credential)
                )

    # Recurse: promote each newly-owned domain so it runs its own post-compromise
    # (and its own further escalation). promote_to_pwned is idempotent, so a domain
    # already pwned (a trust cycle back to the origin) is a safe no-op.
    if newly_owned:
        from adscan_internal.services.domain_compromise_promotion import (
            CompromiseEvidence,
            promote_to_pwned,
        )

        for owned_domain, owned_user, owned_secret in newly_owned:
            try:
                promote_to_pwned(
                    shell,
                    domain=owned_domain,
                    evidence=CompromiseEvidence.CROSS_DOMAIN_ESCALATION,
                    username=owned_user,
                    credential=owned_secret,
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)


def has_pending_cross_domain_escalation(shell: Any) -> bool:
    """True when any domain still has a queued cross-domain escalation.

    Used to gate the CTF objective-met stop so a trusted-forest win does not end
    the scan while an origin-forest escalation is still pending.
    """
    return bool(_get_pending(shell))


def drain_pending_cross_domain_escalations(shell: Any) -> None:
    """Drain the queued cross-domain escalation for EVERY pending domain.

    Runs :func:`execute_cross_domain_escalation` for each domain currently in the
    pending queue. Best-effort and re-entrancy-safe by construction: the per-domain
    drain pops its own domain up front and gates re-fires via the dispatched set,
    and it still self-defers while attack-path execution is active (so calling this
    before the execution flag is cleared is a safe no-op).

    The intended caller is the end of an attack-path run, once the execution flag
    has been cleared: ``promote_to_pwned`` queues a cross-domain escalation while
    attack-path execution is active (so :func:`execute_cross_domain_escalation`
    defers it), and this drain is what fires the queued escalation once the flag is
    down — otherwise it would be silently left pending.
    """
    for dom in list(_get_pending(shell).keys()):
        execute_cross_domain_escalation(shell, dom)


__all__ = [
    "CrossDomainEscalationTechnique",
    "EscalationTarget",
    "EscalationResult",
    "CROSS_DOMAIN_ESCALATION_TECHNIQUES",
    "queue_cross_domain_escalation",
    "execute_cross_domain_escalation",
    "has_pending_cross_domain_escalation",
    "drain_pending_cross_domain_escalations",
    "is_technique_dispatched",
    "mark_technique_dispatched",
]
