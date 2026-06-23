"""Post-compromise orchestration helpers for audit workflows.

This module centralizes the post-Domain-Admin logic that refreshes ADscan's
relationship graph and re-runs attack-path analysis in audit mode.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol

from adscan_internal import (
    print_exception,
    print_info,
    print_info_debug,
    print_panel,
    print_warning,
    telemetry,
)
from adscan_internal.rich_output import mark_sensitive


class PostDAShell(Protocol):
    """Minimal shell interface required by post-DA helpers."""

    type: str | None
    domains_data: dict[str, object]
    license_mode: str | None

    def do_graph_collection(
        self,
        target_domain: str,
        *,
        auth_username: str | None = None,
        auth_password: str | None = None,
        auth_domain: str | None = None,
    ) -> list[str]: ...

    def do_attack_paths(self, args: str) -> None: ...

    def ask_for_post_da_host_dumps(
        self, domain: str, username: str, password: str
    ) -> None: ...

    def ask_for_dcsync(self, domain: str, username: str, password: str) -> None: ...


def get_domain_post_da_state(shell: PostDAShell, domain: str) -> dict[str, object]:
    """Return mutable post-DA state bucket for a domain."""
    domain_state = shell.domains_data.setdefault(domain, {})
    if not isinstance(domain_state, dict):
        domain_state = {}
        shell.domains_data[domain] = domain_state
    post_da = domain_state.get("post_da")
    if isinstance(post_da, dict):
        return post_da
    post_da = {}
    domain_state["post_da"] = post_da
    return post_da


def _should_offer_privileged_refresh(shell: PostDAShell, domain: str) -> bool:
    """Return whether audit post-DA refresh should be offered for a domain."""
    policy = str(
        getattr(shell, "audit_post_da_bh_refresh_policy", "once") or "once"
    ).strip().lower()
    if policy in {"off", "false", "0", "never", "disabled"}:
        return False

    state = get_domain_post_da_state(shell, domain)
    runs = int(state.get("bh_da_refresh_runs", 0) or 0)
    max_cycles = int(getattr(shell, "audit_post_da_bh_refresh_max_cycles", 1) or 1)
    if max_cycles > 0 and runs >= max_cycles:
        return False
    if policy == "once" and runs >= 1:
        return False
    return True


def _prompt_opt_in_privileged_refresh(
    *,
    shell: PostDAShell,
    domain: str,
    username: str,
) -> bool:
    """Prompt user to opt-in to optional privileged refresh in audit workflows.

    This prompt is meant to be explicit and user-friendly. It focuses on what will
    happen (extra data collection + re-analysis), the tradeoffs (time/noise), and
    that it is optional. The user's choice is persisted in the per-domain post-DA
    state to avoid re-prompting.

    Args:
        shell: Shell object holding run state.
        domain: Target domain key.
        username: Current credential label (shown as sensitive).
    Returns:
        True if user opted in, False otherwise.
    """
    from rich.prompt import Confirm

    marked_domain = mark_sensitive(domain, "domain")
    marked_user = mark_sensitive(username, "user")

    info_lines = [
        "[bold]Optional advanced phase (audit)[/bold]",
        f"Domain: {marked_domain}",
        f"Identity: {marked_user}",
        "",
        "This phase performs an additional privileged data refresh and then re-runs graph analysis.",
        "It can improve coverage/visibility for relationships and permissions discovered later in a run.",
        "",
        "[bold]Tradeoffs[/bold]",
        "- Extra runtime (one additional privileged collection cycle)",
        "- Additional directory/graph collection traffic (more noise)",
        "- Requires your BloodHound ingestion path to be configured",
        "",
        "[dim]Tip: In audit mode this is usually worth it; in time-boxed runs you may skip.[/dim]",
    ]
    print_panel(
        "\n".join(info_lines),
        title="[bold cyan]Privileged Refresh[/bold cyan]",
        border_style="cyan",
        expand=False,
    )

    proceed = bool(
        Confirm.ask(
            "Run the optional privileged refresh now?",
            default=True,
        )
    )
    return proceed


def collect_attack_path_snapshot_counts(shell: PostDAShell, domain: str) -> tuple[int, int]:
    """Return persisted summary attack-path counts for one domain.

    The user-facing attack-path snapshot is the source of truth here. The tuple is:
    ``(summary_paths_total, unresolved_paths_total)`` where unresolved currently
    means ``blocked + unsupported``.
    """
    try:
        from adscan_internal.session_summary import (
            get_attack_path_snapshot_metrics,
        )

        metrics = get_attack_path_snapshot_metrics(shell, domains=[domain])
        return int(metrics.total or 0), int(metrics.unresolved or 0)
    except Exception as exc:
        telemetry.capture_exception(exc)
        return 0, 0


def run_audit_post_da_graph_refresh(
    shell: PostDAShell,
    domain: str,
    username: str,
    password: str,
) -> None:
    """Refresh graph collection and rerun path analysis after DA in audit mode."""

    if shell.type != "audit":
        return
    if not _should_offer_privileged_refresh(shell, domain):
        return

    state = get_domain_post_da_state(shell, domain)
    marked_domain = mark_sensitive(domain, "domain")
    marked_user = mark_sensitive(username, "user")

    if not _prompt_opt_in_privileged_refresh(
        shell=shell,
        domain=domain,
        username=username,
    ):
        state["bh_da_refresh_last_opt_in"] = False
        print_info(
            f"Skipping optional privileged refresh for {marked_domain}. Continuing with remaining phases."
        )
        return

    state["bh_da_refresh_last_opt_in"] = True
    previous_total, previous_unresolved = collect_attack_path_snapshot_counts(
        shell, domain
    )
    upload_ok = True
    print_info(
        "Refreshing relationship-graph collection as "
        f"{marked_user} for {marked_domain} (single cycle)."
    )

    try:
        # Re-collect the relationship graph with Domain-Admin visibility — the
        # valuable part: more ACLs/objects become visible as the DA. We do NOT
        # re-run attack-path discovery here. The domain is compromised at this
        # point, so the owned-scope discovery is exhausted; the holistic
        # remaining-paths view (DOMAIN scope, from any low-priv) is computed,
        # displayed and re-offered later by the "Audit Post-Compromise:
        # Remaining Attack Paths" block in run_enumeration. Re-running
        # owned-scope discovery here would be a redundant compute + offer.
        shell.do_graph_collection(
            domain,
            auth_username=username,
            auth_password=password,
            auth_domain=domain,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_warning(
            "Post-DA graph refresh failed. Continuing with remaining post-compromise actions."
        )
        print_exception(show_locals=False, exception=exc)
        return

    current_total, current_unresolved = collect_attack_path_snapshot_counts(
        shell, domain
    )
    state["bh_da_refresh_done"] = True
    state["bh_da_refresh_username"] = str(username or "").strip().lower()
    state["bh_da_refresh_at"] = datetime.now(timezone.utc).isoformat()
    state["bh_da_refresh_upload_ok"] = bool(upload_ok)
    state["bh_da_refresh_runs"] = int(state.get("bh_da_refresh_runs", 0) or 0) + 1
    state["bh_da_refresh_last_summary_paths_before"] = previous_total
    state["bh_da_refresh_last_unresolved_paths_before"] = previous_unresolved
    state["bh_da_refresh_last_summary_paths_after"] = current_total
    state["bh_da_refresh_last_unresolved_paths_after"] = current_unresolved


def run_audit_post_da_bloodhound_refresh(
    shell: PostDAShell,
    domain: str,
    username: str,
    password: str,
) -> None:
    """Backward-compatible alias for the post-DA graph refresh workflow."""
    run_audit_post_da_graph_refresh(
        shell=shell,
        domain=domain,
        username=username,
        password=password,
    )


# ──────────────────────────────────────────────────────────────────────────
# Audit post-compromise queue/flush — mirror of the CTF post-compromise
# mechanism (adscan.py:_ctf_queue/_execute_post_compromise_actions).
#
# When a domain is promoted to "pwned" (e.g. a Domain Admin credential
# obtained via DCSync as a terminal attack-path step), audit mode must run the
# full post-compromise pipeline: re-collect the relationship graph AS the
# obtained DA + re-run attack-path analysis, then offer the host
# credential-harvesting campaign (SAM/LSA/DPAPI).
#
# That pipeline re-runs the attack-path engine (``do_attack_paths``), so it
# MUST NOT execute re-entrantly while an attack-path execution is still active
# — and ``promote_to_pwned`` frequently fires mid-execution (the DCSync step
# runs inside Phase 2). The robust design is therefore queue-on-promote /
# drain-at-a-safe-checkpoint: the queue is populated when the domain is
# promoted, and drained at points where no attack-path execution is active
# (top of ``run_enumeration``, after each enumeration step, and the
# privileged-group membership branch). Idempotent: the pipeline runs at most
# once per domain.
# ──────────────────────────────────────────────────────────────────────────


def _get_audit_pending(shell: PostDAShell) -> dict[str, dict[str, str]]:
    """Lazily-initialised per-domain queue of pending post-compromise actions."""
    pending = getattr(shell, "_audit_post_compromise_pending", None)
    if not isinstance(pending, dict):
        pending = {}
        shell._audit_post_compromise_pending = pending  # type: ignore[attr-defined]
    return pending


def _get_audit_dispatched(shell: PostDAShell) -> set:
    """Lazily-initialised set of domains whose pipeline has already dispatched."""
    dispatched = getattr(shell, "_audit_post_compromise_dispatched", None)
    if not isinstance(dispatched, set):
        dispatched = set()
        shell._audit_post_compromise_dispatched = dispatched  # type: ignore[attr-defined]
    return dispatched


def _pick_best_da_credential(
    shell: PostDAShell, domain: str, fallback_user: str, fallback_secret: str
) -> tuple[str, str]:
    """Return the highest-tier admin credential known for ``domain``.

    The queued/explicit credential may be an NT hash, a low-priv account, or a
    ccache. Mirror the CTF picker so the graph re-collection and host dumps run
    with a credential that actually has the required access. Falls back to the
    provided credential when the picker yields nothing.
    """
    try:
        from adscan_internal.services.credentials import (
            pick_credential_for_local_admin,
        )

        domain_data = (getattr(shell, "domains_data", {}) or {}).get(domain, {})
        pdc_host = domain_data.get("pdc_hostname") or domain_data.get("pdc")
        best = pick_credential_for_local_admin(
            shell, domain=domain, target_host=pdc_host
        )
        if best is not None:
            picked_user, picked_secret, _kind = best
            return picked_user, picked_secret
    except Exception as exc:  # noqa: BLE001 — best effort, never block the flow
        telemetry.capture_exception(exc)
    return fallback_user, fallback_secret


def queue_audit_post_compromise(
    shell: PostDAShell,
    domain: str,
    username: str,
    credential: str,
) -> None:
    """Queue the audit post-compromise pipeline for a pwned ``domain``.

    No-op outside audit mode and for a domain already dispatched. Drained later
    by :func:`execute_audit_post_compromise` at a safe (non-re-entrant)
    checkpoint. Whether the pipeline runs a full DCSync ("all") is decided
    STATE-driven at drain time (``is_full_ntds_replicated``), not here.
    """
    if getattr(shell, "type", None) != "audit":
        return
    if domain in _get_audit_dispatched(shell):
        return
    _get_audit_pending(shell)[domain] = {
        "username": str(username or ""),
        "credential": str(credential or ""),
    }


def execute_audit_post_compromise(
    shell: PostDAShell,
    domain: str,
    username: str | None = None,
    credential: str | None = None,
) -> None:
    """Drain the audit post-compromise pipeline for ``domain`` when safe.

    Args:
        shell: Active shell.
        domain: Target domain key.
        username: Explicit DA credential (privileged-group membership branch).
            When ``None`` the queued credential is used (DCSync attack-path
            case).
        credential: Explicit secret matching ``username``.

    Behaviour:
        * No-op outside audit mode.
        * Defers (stays queued, runs nothing) while an attack-path execution is
          active — the graph refresh re-runs the attack-path engine and must
          not re-enter.
        * No-op when there is nothing queued and no explicit credential was
          passed (speculative checkpoint drain).
        * Runs the full pipeline at most once per domain.
    """
    if getattr(shell, "type", None) != "audit":
        return

    pending = _get_audit_pending(shell)
    has_pending = domain in pending
    if username is None and credential is None and not has_pending:
        return  # speculative drain with an empty queue — nothing to do

    from adscan_internal.services.attack_graph_runtime_service import (
        is_attack_path_execution_active,
    )

    if is_attack_path_execution_active(shell):
        print_info_debug(
            "[audit-post-compromise] deferring "
            f"{mark_sensitive(domain, 'domain')} (attack-path execution active)"
        )
        return

    dispatched = _get_audit_dispatched(shell)
    ctx = pending.pop(domain, {})
    if domain in dispatched:
        return
    dispatched.add(domain)

    resolved_user = username or str(ctx.get("username") or "")
    resolved_secret = credential or str(ctx.get("credential") or "")
    picked_user, picked_secret = _pick_best_da_credential(
        shell, domain, resolved_user, resolved_secret
    )
    print_info_debug(
        "[audit-post-compromise] dispatching for "
        f"{mark_sensitive(domain, 'domain')} as "
        f"{mark_sensitive(picked_user or resolved_user, 'user')}"
    )

    # 0) DCSync the FULL domain credential database FIRST (symmetric with CTF).
    # Validating a client's AD exposure means demonstrating that, once Domain
    # Admin is reached, every credential is replicable — and the dumped hashes
    # feed the graph refresh and host campaign below (e.g. logon-capable
    # principals the DC denies a network logon get a usable secret). STATE-aware
    # via is_full_ntds_replicated: skipped when an attack-path DCSync step
    # already replicated "all", run otherwise — so it happens exactly once
    # regardless of which compromise path fired (DA membership, ESC8→DC, etc.).
    from adscan_internal.services.domain_compromise_promotion import (
        is_full_ntds_replicated,
    )

    if not is_full_ntds_replicated(shell, domain):
        try:
            shell.ask_for_dcsync(domain, picked_user, picked_secret)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning(
                "Audit post-compromise DCSync failed. "
                "Continuing with the graph refresh and host dump campaign."
            )

    # 1) Re-collect the relationship graph AS the obtained DA + re-run analysis.
    try:
        run_audit_post_da_graph_refresh(
            shell=shell,
            domain=domain,
            username=picked_user,
            password=picked_secret,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning(
            "Audit post-compromise graph refresh failed. "
            "Continuing with the host dump campaign."
        )

    # 2) Host credential-harvesting campaign (SAM/LSA/DPAPI).
    try:
        shell.ask_for_post_da_host_dumps(domain, picked_user, picked_secret)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)


__all__ = [
    "collect_attack_path_snapshot_counts",
    "get_domain_post_da_state",
    "queue_audit_post_compromise",
    "execute_audit_post_compromise",
    "run_audit_post_da_graph_refresh",
    "run_audit_post_da_bloodhound_refresh",
]
