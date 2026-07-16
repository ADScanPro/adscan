"""Premium ``adscan smb shares`` command — native + composer + kit.

Single user-facing entry point that orchestrates:

1. **Live probe** — :func:`enumerate_shares_native_sync` against the
   target host using the credentials currently stored in the shell.
2. **Graph load** — :func:`load_graph_share_snapshot` from the domain's
   ``attack_graph.json`` (collected earlier by the share collector).
3. **Composition** — :func:`compose_share_views` fuses both into a
   per-share :class:`ShareView` with a :class:`ShareDelta` classification.
4. **Render** — Premium CLI kit: operation header, status spinner,
   unified table with delta-coloured rows, and a closing summary footer
   that emits the canonical JSON envelope (``smb.shares``) per
   ``docs/cli_style.md``.
5. **Persistence** — Writes the structured snapshot to
   ``workspaces/<domain>/smb/shares.json`` so future re-runs and the web
   surface read one stable file.

Four invocation modes (set by :class:`SharesViewMode`):

* ``FUSION`` — both sources, full table with deltas (default).
* ``LIVE`` — live probe only; no attack graph required.
* ``GRAPH`` — graph only; no network access (offline analysis).
* ``DELTA`` — fusion, but the table is filtered to rows where
  ``delta == LIVE_EXCEEDS_GRAPH``. The discovery view.

This module is the home of the single-host operator UX; the legacy
``execute_netexec_shares`` nxc multi-host sweep it replaced has been removed.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional


from adscan_core import telemetry
from adscan_core.output import (
    create_styled_table,
    operation_timer,
    print_empty_state,
    print_info_debug,
    print_operation_header,
    print_operation_summary_footer,
    print_remediation_card,
    print_table,
    print_warning,
    suppress_rich,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.enumeration.smb_shares_native import (
    NativeSharesResult,
    enumerate_shares_native_sync,
)
from adscan_internal.models.domain import resolve_dc_ip
from adscan_internal.services._kerberos_spn import is_ip_address
from adscan_internal.services.kerberos_hostname_inventory import (
    load_workspace_ip_hostname_inventory,
)
from adscan_internal.services.kerberos_spn_resolution import (
    resolve_spn_or_decide_ntlm,
)
from adscan_internal.services.smb_transport import SMBConfig
from adscan_internal.services.views._graph_share_reader import (
    GraphShareSnapshot,
    load_graph_share_snapshot,
)
from adscan_internal.services.views.share_view_composer import (
    ShareDelta,
    ShareView,
    ShareViewSet,
    compose_share_views,
)
from adscan_internal.workspaces.subpaths import domain_path


# ---------------------------------------------------------------------------
# Mode enum
# ---------------------------------------------------------------------------


class SharesViewMode(str, Enum):
    """Operator-selected lens over the share view set."""

    FUSION = "fusion"   # default: live + graph + delta
    LIVE = "live"       # live only (no graph load)
    GRAPH = "graph"     # graph only (no network)
    DELTA = "delta"     # fusion filtered to LIVE_EXCEEDS_GRAPH

    @classmethod
    def parse(cls, raw: str | None) -> "SharesViewMode":
        if not raw:
            return cls.FUSION
        for member in cls:
            if member.value == raw.strip().lower():
                return member
        raise ValueError(
            f"Invalid shares mode {raw!r}. Expected one of: "
            f"{', '.join(m.value for m in cls)}"
        )


# ---------------------------------------------------------------------------
# Delta presentation map — single source of truth
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _DeltaStyle:
    icon: str
    label: str
    color: str


_DELTA_STYLES: Dict[ShareDelta, _DeltaStyle] = {
    ShareDelta.LIVE_EXCEEDS_GRAPH: _DeltaStyle("⬆", "live > graph", "red"),
    ShareDelta.GRAPH_EXCEEDS_LIVE: _DeltaStyle("⬇", "graph > live", "yellow"),
    ShareDelta.ALIGNED: _DeltaStyle("≡", "aligned", "green"),
    ShareDelta.NO_GRAPH_DATA: _DeltaStyle("?", "no graph", "cyan"),
    ShareDelta.NO_LIVE_DATA: _DeltaStyle("·", "no live", "dim"),
    ShareDelta.INACCESSIBLE: _DeltaStyle("○", "inaccessible", "dim"),
}


# ---------------------------------------------------------------------------
# Public entry — sync, called from the legacy CLI dispatcher
# ---------------------------------------------------------------------------


def run_native_shares_view(
    shell: Any,
    *,
    domain: str,
    host: Optional[str] = None,
    mode: SharesViewMode | str = SharesViewMode.FUSION,
    timeout: int = 30,
    username: Optional[str] = None,
    credential: Optional[str] = None,
) -> ShareViewSet:
    """Run the premium shares command and return the composed view set.

    Args:
        shell: The active ``PentestShell`` (provides ``domains_data``,
            ``domains_dir``, ``_get_workspace_cwd``, etc.).
        domain: Target domain (key into ``shell.domains_data``).
        host: Optional explicit host. Defaults to the domain's PDC.
        mode: One of :class:`SharesViewMode` (or its string value).
        timeout: Per-operation timeout in seconds for the live probe.
        username: Optional credential override — username.
        credential: Optional credential override — password, NT hash, or
            path to a ``.ccache`` file.

    Returns:
        :class:`ShareViewSet` — the same data the table and JSON envelope
        rendered. Callers can chain follow-up operations off it.

    Side effects:
        * Renders to stdout (Rich panels/tables) when ``OutputMode.HUMAN``.
        * Emits a ``smb.shares`` JSON envelope when not human.
        * Writes a structured snapshot to
          ``workspaces/<domain>/smb/shares.json``.
    """
    resolved_mode = (
        mode if isinstance(mode, SharesViewMode) else SharesViewMode.parse(mode)
    )
    target_host = _resolve_target_host(shell, domain, host)

    # ── 1. Header ──────────────────────────────────────────────────────────
    _render_header(
        shell=shell,
        domain=domain,
        target_host=target_host,
        mode=resolved_mode,
    )

    # ── 2. Run the operation under a timer + status spinner ────────────────
    live: Optional[NativeSharesResult] = None
    graph: Optional[GraphShareSnapshot] = None
    error_during_live: Optional[str] = None

    with operation_timer() as timer:
        if resolved_mode in (SharesViewMode.FUSION, SharesViewMode.LIVE, SharesViewMode.DELTA):
            live, error_during_live = _run_live_probe(
                shell=shell,
                domain=domain,
                target_host=target_host,
                timeout=timeout,
                username_override=username,
                credential_override=credential,
            )
        if resolved_mode in (SharesViewMode.FUSION, SharesViewMode.GRAPH, SharesViewMode.DELTA):
            graph = _load_graph(shell=shell, domain=domain, host=target_host)

    view_set = compose_share_views(host=target_host, live=live, graph=graph)
    if resolved_mode == SharesViewMode.DELTA:
        view_set = _filter_delta(view_set)
    # Carry the live-probe error out to multi-host sweep callers so the shared
    # SweepLockoutGuard can abort on a locked-out / rejected credential instead
    # of re-asserting the lockout against every remaining host.
    view_set.live_error = error_during_live

    # ── 3. Render the result table ─────────────────────────────────────────
    _render_view_set(view_set=view_set, mode=resolved_mode)

    # ── 4. Persist the snapshot ────────────────────────────────────────────
    saved_path = _persist_snapshot(
        shell=shell, domain=domain, view_set=view_set, mode=resolved_mode
    )

    # ── 5. Footer (also emits JSON envelope when not human) ────────────────
    _render_footer(
        view_set=view_set,
        mode=resolved_mode,
        domain=domain,
        target_host=target_host,
        saved_path=saved_path,
        duration_ms=timer.duration_ms,
        started_at=timer.started_at,
        error=error_during_live,
        shell=shell,
    )

    return view_set


# ---------------------------------------------------------------------------
# Step helpers
# ---------------------------------------------------------------------------


def _resolve_target_host(shell: Any, domain: str, host: Optional[str]) -> str:
    if host:
        return host.strip()
    domain_data = (shell.domains_data.get(domain) or {}) if hasattr(shell, "domains_data") else {}
    pdc_hostname = str(domain_data.get("pdc_hostname") or "").strip()
    pdc_ip = str(domain_data.get("pdc") or "").strip()
    return pdc_hostname or pdc_ip or domain


def _render_header(
    *,
    shell: Any,
    domain: str,
    target_host: str,
    mode: SharesViewMode,
) -> None:
    if suppress_rich():
        return

    domain_data = (shell.domains_data.get(domain) or {}) if hasattr(shell, "domains_data") else {}
    auth_state = str(domain_data.get("auth") or "unauth").strip().lower()
    auth_label = {"auth": "authenticated", "pwned": "pwned", "unauth": "unauth"}.get(
        auth_state, auth_state
    )
    posture_summary = _summarise_posture(domain_data)

    details = {
        "Target": target_host,
        "Domain": domain,
        "Auth": auth_label,
        "Mode": mode.value,
    }
    if posture_summary:
        details["Domain Posture"] = posture_summary

    print_operation_header("SMB Share Enumeration", details, icon="📂")


def _summarise_posture(domain_data: Dict[str, Any]) -> str:
    posture = domain_data.get("posture") or {}
    bits: List[str] = []
    if posture.get("ntlm_disabled"):
        bits.append("NTLM disabled")
    if posture.get("aes_only"):
        bits.append("AES enforced")
    if posture.get("ldap_signing") == "required":
        bits.append("LDAP signing required")
    if posture.get("smb_signing") == "required":
        bits.append("SMB signing required")
    return " · ".join(bits)


def _run_live_probe(
    *,
    shell: Any,
    domain: str,
    target_host: str,
    timeout: int,
    username_override: Optional[str] = None,
    credential_override: Optional[str] = None,
) -> tuple[Optional[NativeSharesResult], Optional[str]]:
    """Build SMBConfig from shell state and call the native enumerator.

    When ``username_override`` and ``credential_override`` are provided they
    are used instead of the credentials stored in the shell — useful for
    post-exploitation followups that probe with a specific user (e.g. after
    adding them to a new group or acquiring a delegated CIFS ticket).
    """
    try:
        config = _build_smb_config_for_host(
            shell=shell,
            domain=domain,
            target_host=target_host,
            timeout=timeout,
            username_override=username_override,
            credential_override=credential_override,
        )
    except _NoCredentialsError as exc:
        # Surface a remediation card; the composer will mark NO_LIVE_DATA.
        if not suppress_rich():
            print_remediation_card(
                error=f"Cannot run live probe: {exc}",
                cause="No usable credentials in the shell for this domain.",
                commands=[
                    f"adscan domain creds set --domain {domain} --user <u> --password <p>",
                    f"adscan smb shares --domain {domain} --output json --mode graph",
                ],
            )
        return None, str(exc)
    except Exception as exc:  # noqa: BLE001
        # Config-build can fail before the native enumerator's own soft-error
        # boundary is reached — e.g. a Kerberos pre-mint / get_TGT preauth
        # rejection on an AES-only / non-default-salt DC. Without this catch the
        # exception escapes run_native_shares_view to the REPL, which dumps a
        # raw multi-frame Rich traceback. Classify it (the same Kerberos-posture
        # mapping the enumerator's errors use) and render a clean one-line card.
        telemetry.capture_exception(exc)
        if not suppress_rich():
            print_remediation_card(
                error=f"Live SMB share probe failed: {exc}",
                cause=_classify_error_cause(str(exc)),
                commands=_remediation_commands(domain=domain, status="error"),
            )
        return None, str(exc)

    result = enumerate_shares_native_sync(config=config, timeout=timeout)

    if result.status not in {"ok", "partial"}:
        if not suppress_rich():
            cause = _classify_error_cause(result.error or "")
            print_remediation_card(
                error=f"Live SMB share probe failed: {result.error or 'unknown'}",
                cause=cause,
                commands=_remediation_commands(domain=domain, status=result.status),
            )
        return result, result.error

    return result, None


def _load_graph(*, shell: Any, domain: str, host: str) -> Optional[GraphShareSnapshot]:
    try:
        workspace_cwd = (
            shell._get_workspace_cwd()
            if hasattr(shell, "_get_workspace_cwd")
            else getattr(shell, "current_workspace_dir", os.getcwd())
        )
        domains_dir = getattr(shell, "domains_dir", "domains")
        graph_path = domain_path(workspace_cwd, domains_dir, domain, "attack_graph.json")
        return load_graph_share_snapshot(graph_path=graph_path, host=host)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return None


def _filter_delta(view_set: ShareViewSet) -> ShareViewSet:
    filtered = [v for v in view_set.views if v.delta == ShareDelta.LIVE_EXCEEDS_GRAPH]
    return ShareViewSet(host=view_set.host, views=filtered, sources=dict(view_set.sources))


# ---------------------------------------------------------------------------
# Table render
# ---------------------------------------------------------------------------


def _render_view_set(*, view_set: ShareViewSet, mode: SharesViewMode) -> None:
    if suppress_rich():
        return

    if not view_set.views:
        _render_empty_state(view_set=view_set, mode=mode)
        return

    # In LIVE-only mode with no graph snapshot, the Graph max and Δ columns
    # are always "—" / "? no graph" — pure visual noise for the operator.
    # Only show them when there is actual graph data to compare against.
    has_graph_data = any(
        v.graph_acl is not None for v in view_set.views
    )
    show_graph_cols = mode != SharesViewMode.LIVE or has_graph_data

    table = create_styled_table(
        title=f"Shares — {view_set.host}",
        show_lines=False,
    )
    table.add_column("Share", style="cyan", no_wrap=True)
    table.add_column("Type", style="dim")
    table.add_column("Access", justify="left")
    if show_graph_cols:
        table.add_column("Graph max", justify="left")
        table.add_column("Δ", justify="center", no_wrap=True)
    table.add_column("Remark", style="dim", overflow="fold")

    for view in view_set.views:
        row = [
            mark_sensitive(view.name, "share"),
            view.type or "-",
            _format_effective(view),
        ]
        if show_graph_cols:
            delta_style = _DELTA_STYLES.get(
                view.delta, _DeltaStyle("·", view.delta.value, "dim")
            )
            row.append(_format_graph_max(view))
            row.append(
                f"[{delta_style.color}]{delta_style.icon} {delta_style.label}[/{delta_style.color}]"
            )
        row.append(view.remark or "")
        table.add_row(*row)

    print_table(table)


def _format_effective(view: ShareView) -> str:
    if not view.live_present:
        return "[dim]—[/dim]"
    if not view.live_accessible:
        return "[dim]denied[/dim]"
    if not view.live_permissions:
        return "[dim](none)[/dim]"

    # Translate the raw permission bits to READ / WRITE for the operator.
    # Writable shares are highlighted — they are the actionable signal.
    perms = view.live_permissions
    is_write = any(p in perms for p in ("WRITE", "WRITE_DAC", "FULL_CONTROL"))
    is_read = "READ" in perms

    parts: list[str] = []
    if is_read:
        parts.append("[cyan]READ[/cyan]")
    if is_write:
        parts.append("[bold red]WRITE[/bold red]")
    if not parts:
        # Edge case: only exotic bits like READ_CONTROL, EXECUTE
        parts.append(f"[dim]{', '.join(perms[:2])}[/dim]")
    return "  ".join(parts)


def _format_graph_max(view: ShareView) -> str:
    if view.graph_acl is None:
        return "[dim]—[/dim]"
    if not view.graph_acl.principals:
        return "[dim]no aces[/dim]"
    best = ""
    best_rank = -1
    for principal in view.graph_acl.principals:
        for perm in principal.permissions:
            rank = ("READ", "WRITE", "FULL_CONTROL").index(perm) if perm in ("READ", "WRITE", "FULL_CONTROL") else -1
            if rank > best_rank:
                best_rank = rank
                best = perm
    if not best:
        return "[dim]—[/dim]"
    return f"{best} [dim]({len(view.graph_acl.principals)} principal(s))[/dim]"


def _render_empty_state(*, view_set: ShareViewSet, mode: SharesViewMode) -> None:
    if mode == SharesViewMode.DELTA:
        print_empty_state(
            "shares with live > graph",
            cause="No share grants the active credential more access than the attack graph maps.",
            suggestions=[
                "This is the expected outcome on a posture-collected, well-modelled domain.",
                "Try a different credential or a host the collector did not visit.",
            ],
        )
        return

    live_status = view_set.sources.get("live", "missing")
    graph_status = view_set.sources.get("graph", "missing")

    if live_status == "denied":
        print_empty_state(
            "SMB shares",
            cause="Authentication denied on this host.",
            suggestions=[
                "Try a different credential",
                "Verify the host is reachable: nmap -p 445 <host>",
            ],
        )
        return
    if live_status == "error" and graph_status == "missing":
        print_empty_state(
            "SMB shares",
            cause="Live probe failed and no attack graph data is available for this host.",
            suggestions=[
                "Run an authenticated scan first: adscan ci",
                "Check posture: adscan posture --domain <domain>",
            ],
        )
        return
    print_empty_state(
        "SMB shares",
        cause=f"Live probe status: {live_status}; graph status: {graph_status}.",
        suggestions=[
            "Re-run with --output json to inspect the structured envelope",
            "Try --mode live to bypass the graph",
        ],
    )


# ---------------------------------------------------------------------------
# Footer + JSON
# ---------------------------------------------------------------------------


def _render_footer(
    *,
    view_set: ShareViewSet,
    mode: SharesViewMode,
    domain: str,
    target_host: str,
    saved_path: Optional[str],
    duration_ms: Optional[int],
    started_at,
    error: Optional[str],
    shell: Any,
) -> None:
    counts = view_set.counts
    status: str
    if error and counts["total"] == 0:
        status = "error"
    elif counts["total"] == 0:
        status = "empty"
    elif view_set.sources.get("live", "ok") == "partial":
        status = "partial"
    else:
        status = "ok"

    next_command = _suggest_next_command(view_set=view_set, mode=mode, domain=domain)

    extra: Dict[str, Any] = {
        "mode": mode.value,
        "sources": dict(view_set.sources),
    }

    # Surface only the counts that carry signal for the operator.
    # In LIVE mode without graph data, live_exceeds_graph is always 0 and
    # no_graph_data is always N — omit them to avoid visual noise.
    has_graph_data = counts.get("total", 0) > 0 and (
        counts.get("aligned", 0) > 0
        or counts.get("live_exceeds_graph", 0) > 0
        or counts.get("graph_exceeds_live", 0) > 0
    )
    operator_counts: Dict[str, Any] = {
        "total": counts.get("total", 0),
        "readable": counts.get("readable", 0),
        "writable": counts.get("writable", 0),
    }
    if has_graph_data:
        operator_counts["live_exceeds_graph"] = counts.get("live_exceeds_graph", 0)
        operator_counts["no_graph_data"] = counts.get("no_graph_data", 0)

    print_operation_summary_footer(
        "smb.shares",
        status=status,
        target={"domain": domain, "host": target_host},
        posture=_posture_for_envelope(shell=shell, domain=domain),
        findings=operator_counts,
        saved_to=[saved_path] if saved_path else None,
        next_command=next_command,
        duration_ms=duration_ms,
        started_at=started_at,
        error={"message": error} if error else None,
        extra=extra,
        title="SMB Shares",
    )


def _suggest_next_command(
    *, view_set: ShareViewSet, mode: SharesViewMode, domain: str
) -> Optional[str]:
    # Prioritise the most operationally valuable next step:
    # writable shares → hunt for credentials / drop payloads first.
    writable = [v for v in view_set.views if getattr(v, "is_writable_live", False)]
    readable = [v for v in view_set.views if getattr(v, "is_readable", False)]
    if writable or readable:
        share_names = ",".join(v.name for v in (writable or readable)[:2])
        return f"adscan smb hunt --domain {domain} --shares {share_names}"
    if any(v.delta == ShareDelta.LIVE_EXCEEDS_GRAPH for v in view_set.views):
        return f"adscan smb shares --domain {domain} --mode delta"
    if view_set.sources.get("graph") == "missing":
        return f"adscan ci --domain {domain}"
    return f"adscan smb sessions --domain {domain}"


def _posture_for_envelope(*, shell: Any, domain: str) -> Dict[str, Any]:
    if not hasattr(shell, "domains_data"):
        return {}
    data = shell.domains_data.get(domain) or {}
    posture = data.get("posture") or {}
    if isinstance(posture, dict):
        return dict(posture)
    return {}


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def _persist_snapshot(
    *, shell: Any, domain: str, view_set: ShareViewSet, mode: SharesViewMode
) -> Optional[str]:
    """Write the snapshot to ``workspaces/<domain>/smb/shares.json``.

    The persisted file is the JSON envelope's ``findings``-equivalent: a
    detailed list of :class:`ShareView` records with full live and graph
    perspectives. The web surface, the report renderer, and any future
    consumer should read this file (not re-derive the data).
    """
    try:
        workspace_cwd = (
            shell._get_workspace_cwd()
            if hasattr(shell, "_get_workspace_cwd")
            else getattr(shell, "current_workspace_dir", os.getcwd())
        )
        domains_dir = getattr(shell, "domains_dir", "domains")
        out_dir = domain_path(workspace_cwd, domains_dir, domain, "smb")
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, "shares.json")
        payload = {
            "version": 1,
            "mode": mode.value,
            **view_set.to_dict(),
        }
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=False)
        return out_path
    except Exception as exc:  # noqa: BLE001 — UX-best-effort, not fatal
        telemetry.capture_exception(exc)
        if not suppress_rich():
            print_warning(f"Could not persist shares snapshot: {exc}")
        return None


# ---------------------------------------------------------------------------
# Internal helpers — config + remediation
# ---------------------------------------------------------------------------


class _NoCredentialsError(RuntimeError):
    """Raised when the shell has no credentials usable for the live probe."""


def _load_ip_hostname_inventory(shell: Any, domain: str) -> Dict[str, List[str]]:
    """Load the persisted workspace IP -> hostname candidate map for *domain*.

    Mirrors the loader call used by other Kerberos-aware callers (e.g.
    :mod:`credential_store_service`): the map bridges an IP target to its own
    FQDN so the Kerberos SPN binds to the host we connect to. Best-effort — a
    missing workspace or report yields an empty map (the resolver then falls
    back to live PTR, and finally to NTLM).
    """
    try:
        workspace_dir = (
            shell._get_workspace_cwd()
            if hasattr(shell, "_get_workspace_cwd")
            else getattr(shell, "current_workspace_dir", "")
        ) or ""
        domains_dir = getattr(shell, "domains_dir", "domains") or "domains"
        return (
            load_workspace_ip_hostname_inventory(
                workspace_dir=str(workspace_dir),
                domains_dir=str(domains_dir),
                domain=domain,
            )
            or {}
        )
    except Exception as exc:  # noqa: BLE001 — inventory is best-effort
        telemetry.capture_exception(exc)
        return {}


def _build_smb_config_for_host(
    *,
    shell: Any,
    domain: str,
    target_host: str,
    timeout: int,
    username_override: Optional[str] = None,
    credential_override: Optional[str] = None,
) -> SMBConfig:
    """Build an ``SMBConfig`` for the target host.

    Credential resolution priority:
    1. Explicit override: when ``username_override`` is not ``None`` the
       caller has supplied credentials explicitly.  This path is always taken
       regardless of the shell auth state so that post-exploitation flows
       (RBCD ccache, guest probes, specific test accounts) work correctly.
       The credential may be an empty string (null/guest sessions).
    2. Shell stored credentials when the domain is in ``auth``/``pwned`` state.
    3. Null session fallback.

    Credential format detection (applied to the resolved credential value):
    - ``.ccache`` suffix  → ``ccache_path`` field (Kerberos ticket).
    - 32-hex / LM:NT pair → ``nt_hash`` field (NTLM hash).
    - Everything else     → ``password`` field (plaintext, including empty
      string for null and guest sessions).
    """
    domain_data = (shell.domains_data.get(domain) or {}) if hasattr(shell, "domains_data") else {}
    auth_state = str(domain_data.get("auth") or "unauth").strip().lower()

    pdc_hostname = str(domain_data.get("pdc_hostname") or "").strip() or None
    pdc_ip = str(domain_data.get("pdc") or "").strip()

    # Caller-supplied override — username_override is not None means explicit.
    # credential_override may be empty string (guest / null session).
    if username_override is not None or auth_state in ("auth", "pwned"):
        if username_override is not None:
            username = username_override
            cred_raw = credential_override if credential_override is not None else ""
        else:
            # auth/pwned path — read from shell; both must be set.
            username = str(domain_data.get("username") or "").strip()
            cred_raw = str(domain_data.get("password") or "").strip()
            if not username or not cred_raw:
                raise _NoCredentialsError(
                    "Domain marked authenticated but credentials are not set."
                )

        # Route credential to the correct SMBConfig field.
        cred_stripped = cred_raw.strip()
        is_ccache = cred_stripped.lower().endswith(".ccache")
        is_hash = (
            bool(cred_stripped) and not is_ccache and (
                shell.is_hash(cred_stripped)
                if hasattr(shell, "is_hash")
                else (len(cred_stripped) == 32 and all(c in "0123456789abcdef" for c in cred_stripped.lower()))
            )
        )

        # Include the domain posture snapshot so smb_machine_with_fallback
        # can apply hardening-aware decisions (NTLM disabled, AES-only Kerberos,
        # channel binding required, SMB signing, etc.).
        try:
            from adscan_internal.services.domain_posture import get_posture  # noqa: PLC0415
            posture_snapshot = get_posture(
                getattr(shell, "domains_data", {}), domain=domain
            )
        except Exception:  # noqa: BLE001
            posture_snapshot = None

        # Kerberos SPN host — resolve the SPN for the host we ACTUALLY connect
        # to, never the PDC's. The historic ``pdc_hostname or target_host``
        # default requested ``cifs/<pdc-fqdn>`` against every host in the
        # share-enum loop, so a non-DC host received a service ticket bound to
        # the wrong SPN and rejected the AP-REQ (the client only ever sees a
        # GSSAPI / AP-REP parse error -> "Live SMB share probe failed", no
        # shares). Reuse the canonical resolver (single source of truth — the
        # same path lsass.py uses) so a short label / IP is promoted to its OWN
        # FQDN via the workspace inventory -> live PTR, and drop to NTLM when no
        # FQDN is recoverable instead of fabricating one or reusing the PDC's.
        inventory = _load_ip_hostname_inventory(shell, domain)
        target = str(target_host or pdc_ip or "").strip()

        spn_host: Optional[str]
        if not cred_stripped:
            # Guest / null session (empty credential): there is no secret to
            # obtain a Kerberos TGT, and a Kerberos-first bind would crash while
            # building the auth URL ('NoneType' object has no attribute 'native').
            # Force the NTLM-anonymous/guest path. The per-host Kerberos SPN
            # resolution below only applies when we hold a usable credential
            # (password / NT hash / ccache).
            spn_host = None
            use_kerberos = False
        else:
            resolver_ip = resolve_dc_ip(domain_data) or (pdc_ip or None)
            target_is_dc = bool(target) and bool(resolver_ip) and target == resolver_ip
            resolution = resolve_spn_or_decide_ntlm(
                target_host=target or None,
                domain=domain,
                domains_data=getattr(shell, "domains_data", {}),
                ip_hostname_inventory=inventory or None,
                resolver_ip=resolver_ip,
                posture_snapshot=posture_snapshot,
                is_dc_target=target_is_dc,
            )
            use_kerberos = True
            if resolution.kerberos_viable and resolution.spn_host:
                spn_host = resolution.spn_host
            elif target and not is_ip_address(target):
                # Already a hostname/FQDN the resolver could not promote further —
                # keep it as the SPN host (e.g. a caller-supplied FQDN target).
                spn_host = target
            else:
                # No FQDN is recoverable for this IP. Do NOT inject the PDC's name
                # or request ``cifs/<ip>`` (the server rejects it). Drop to NTLM;
                # the posture plan still honours an observed NTLM-disabled signal.
                spn_host = None
                use_kerberos = False

        # Diagnostic for the cross-realm AP-REP-parse case: a foreign-suffix host
        # reached via a pivot whose FQDN is in inventory may still drop to cifs/<ip>
        # if the resolver wasn't given the host's inventory or rejected the foreign
        # realm. Log the per-host SPN decision (bracket-free marker; Rich eats [..])
        # so the next occurrence is diagnosable without changing behavior.
        print_info_debug(
            "smb-probe-spn: "
            f"host={mark_sensitive(target or '-', 'hostname')} "
            f"spn_host={mark_sensitive(spn_host or '-', 'hostname')} "
            f"kerberos={use_kerberos} "
            f"domain={mark_sensitive(domain, 'domain')}"
        )

        return SMBConfig(
            target_ip=target or pdc_ip,
            target_hostname=spn_host or target or pdc_ip,
            domain=domain,
            username=username,
            password=None if (is_ccache or is_hash) else (cred_stripped or None),
            nt_hash=cred_stripped if is_hash else None,
            ccache_path=cred_stripped if is_ccache else None,
            auth_domain=domain,
            kdc_ip=pdc_ip or None,
            use_kerberos=use_kerberos,
            ip_hostname_inventory=inventory or None,
            timeout=timeout,
            posture_snapshot=posture_snapshot,
        )

    # Unauthenticated path — null session (no posture needed).
    # Null / guest session — no credentials at all.  Kerberos requires a
    # principal name and a ticket; with empty username/password the posture
    # plan's Kerberos-first policy would crash when building the auth URL
    # (NoneType has no attribute 'native').  Force NTLM-anonymous path.
    return SMBConfig(
        target_ip=target_host or pdc_ip,
        target_hostname=pdc_hostname or target_host,
        domain=domain,
        username="",
        password="",
        auth_domain=domain,
        use_kerberos=False,
        timeout=timeout,
    )


def _classify_error_cause(error_text: str) -> str:
    """Map an error string to a short human-readable probable cause.

    badauth now decodes a GSSAPI-wrapped KRB-ERROR on the AP exchange into the
    real Kerberos error-code instead of blindly parsing it as an AP-REP (which
    destroyed the code). So when the error string carries a concrete Kerberos
    error name, classify on THAT — never guess "wrong SPN" from an opaque
    AP-REP parse failure that may actually be a non-default salt/etype or clock
    skew. The wrong-SPN message is reserved for the codes that genuinely mean it.
    """
    upper = error_text.upper()

    # Concrete, decoded Kerberos AP-exchange error codes — diagnose precisely.
    # Match both the symbolic code AND the human-readable strings that surface
    # from a get_TGT preauth rejection on an AES-only / RC4-disabled DC, so a
    # raw "KDC has no support for encryption type" is never mislabeled as an
    # unknown SMB transport error.
    if (
        "KDC_ERR_ETYPE_NOTSUPP" in upper
        or "KDC HAS NO SUPPORT FOR ENCRYPTION TYPE" in upper
        or "KDC_ERR_PREAUTH_FAILED" in upper
        or "PREAUTH" in upper
    ):
        return (
            "The DC rejected the Kerberos encryption type (the domain may be "
            "AES-only / RC4-disabled, or the account uses a non-default "
            "Kerberos salt) — see the domain posture."
        )
    if "KRB_AP_ERR_SKEW" in upper:
        return (
            "Kerberos clock skew is too large — the host clock and the DC differ "
            "by more than the allowed 5 minutes."
        )
    if (
        "KRB_AP_ERR_MODIFIED" in upper
        or "KRB_AP_ERR_BADMATCH" in upper
        or "KRB_AP_ERR_NOT_US" in upper
    ):
        return (
            "Kerberos service ticket was issued for a different host's SPN "
            "(the target's own FQDN was not used)."
        )

    # Opaque AP-REP / GSSAPI / SPNEGO failures with no decoded error-code. These
    # are a Kerberos AP-exchange leg problem; without a concrete code we cannot
    # claim it is the SPN specifically — describe it honestly so a non-SPN cause
    # (salt/etype/skew) is not misattributed.
    if (
        "AP_REP" in upper
        or "AP-REP" in upper
        or "AP EXCHANGE REJECTED" in upper
        or "GSSAPI" in upper
        or "GSS-API" in upper
        or "SPNEGO" in upper
        or "SEC_E_LOGON_DENIED" in upper
    ):
        return (
            "The Kerberos AP exchange was rejected by the target (wrong SPN, "
            "non-default salt/encryption type, or clock skew). NTLM is retried "
            "automatically when it is not disabled in this domain."
        )
    if "ACCESS_DENIED" in upper or "LOGON_FAILURE" in upper:
        return "The credentials were rejected (wrong password, locked account, or auth method blocked)."
    if "SIGNING" in upper:
        return "SMB signing is required by the server but the client did not negotiate it."
    if "TIMEOUT" in upper or "TIMED OUT" in upper:
        return "Network timeout — host unreachable or filtering port 445."
    if "CONNECTION" in upper or "REFUSED" in upper or "UNREACHABLE" in upper:
        return "Could not reach the SMB service on this host."
    return "Unknown SMB transport error — check the workspace log for details."


def _remediation_commands(*, domain: str, status: str) -> List[str]:
    if status == "denied":
        return [
            f"adscan domain creds rotate --domain {domain}",
            f"adscan smb shares --domain {domain} --mode graph",
        ]
    if status == "error":
        return [
            f"adscan domain check --domain {domain}",
            f"adscan smb shares --domain {domain} --mode graph",
        ]
    return [f"adscan smb shares --domain {domain} --output json"]


__all__ = [
    "SharesViewMode",
    "run_native_shares_view",
]
