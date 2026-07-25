"""Phase 7 — SMB Share Exposure orchestrator.

A global overview of every exposed share, then two numbered sub-steps:

* **Step 1/2 — Writable-Share Capture** — drop NTLMv2 bait on writable shares
  and capture hashes when a privileged user browses (reuses the shared core
  ``smb.run_ntlmv2_capture_for_writable_shares``).
* **Step 2/2 — Readable-Share Credential Hunt** — loot readable shares for
  embedded credentials (reuses ``smb.run_smb_share_credential_hunt``).

Pure orchestration: it loads the graph share inventory (effective access),
splits writable vs readable, and delegates to existing, lab-validated
executors. No new AD-protocol code lives here; all capture gating
(CTF/audit × interactive/CI) is inherited from the reused core.

Both sub-steps authenticate as the SAME principal against many hosts — a
mass-auth sweep. They share ONE :class:`~adscan_internal.services.
sweep_credential.SweepLockoutGuard` circuit-breaker (created once in
:func:`run_smb_share_exposure_phase` and threaded into both substeps) so a
credential that locks out or is rejected during Step 1 stops the Step-1 host
loop immediately AND prevents Step 2 from starting at all — instead of
re-asserting the lockout against every remaining host across both steps.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable

from adscan_core import telemetry
from adscan_core.rich_output import (
    print_info,
    print_info_debug,
    print_info_verbose,
    print_phase_header,
    print_warning,
)
from adscan_core.rich_output import print_exception

if TYPE_CHECKING:
    from adscan_internal.services.sweep_credential import SweepLockoutGuard

#: A share is a WRITE target when the scanning identity's effective access
#: includes Write or Full Control.
_WRITE_ACCESS = {"Write", "Full Control"}
#: A share is a READ (loot) target when effective access includes any of these
#: — WRITE implies READ on Windows, so writable shares are also loot candidates.
_READ_ACCESS = {"Read", "Write", "Full Control"}
#: For ``type == "audit"`` engagements the readable-share credential hunt is
#: bounded to the top-N highest-risk shares to keep runtime and OPSEC exposure
#: predictable on large client environments. The cap is a function of the
#: engagement type (audit), not of CI mode: it applies in both ``adscan ci``
#: (auto-selects the top-N) and the interactive picker (pre-selects the top-N as
#: the default while still offering every share). CTF engagements scan all
#: (small envs + autonomy). ``rows`` are already risk-ranked, so ``rows[:N]`` is
#: the top-N by risk.
_AUDIT_HUNT_SHARE_LIMIT = 25


def _emit_share_operation_progress(
    *,
    label: str,
    phase: str,
    current: int | None = None,
    total: int | None = None,
    detail: str | None = None,
    estimator: Any | None = None,
    done: bool = False,
) -> None:
    """Emit one current-operation tick for the share-enumeration long step.

    Live observability only — drives the platform's current-operation surface
    ("Share enumeration · 3 of 12 · domain"). When an ``estimator`` (a shared
    :class:`ProgressEstimator`) is supplied it is observed with the current/total
    so the tick carries the live rate / ETA / elapsed — the same throughput
    computation the CLI rich.live dashboards use. Best-effort and a no-op unless
    the structured event sink is enabled (see ``emit_operation_progress``).

    Pass ``done=True`` on the FINAL tick (the phase finished) so the platform's
    live strip clears the operation immediately instead of freezing on the last
    host count.
    """
    try:
        from adscan_internal.cli.ci_events import emit_operation_progress  # noqa: PLC0415

        rate: float | None = None
        eta_seconds: float | None = None
        elapsed_seconds: float | None = None
        if estimator is not None and current is not None:
            estimator.observe(current, total)
            measured_rate = estimator.rate
            rate = measured_rate if measured_rate > 0 else None
            eta_seconds = estimator.eta_seconds
            elapsed_seconds = estimator.elapsed_seconds

        emit_operation_progress(
            operation="share_enumeration",
            label=label,
            phase=phase,
            phase_label="SMB Share Exposure",
            current=current,
            total=total,
            rate=rate,
            eta_seconds=eta_seconds,
            elapsed_seconds=elapsed_seconds,
            detail=detail,
            done=done,
        )
    except Exception as exc:  # noqa: BLE001 — telemetry must never abort the phase
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def _row_access(row: dict[str, Any]) -> set[str]:
    acc = row.get("access")
    return acc if isinstance(acc, set) else set(acc or [])


def _split_share_rows(
    rows: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return (writable_rows, readable_rows). Write implies read."""
    writable = [r for r in rows if _WRITE_ACCESS & _row_access(r)]
    readable = [r for r in rows if _READ_ACCESS & _row_access(r)]
    return writable, readable


def _group_writable_share_names_by_host(
    writable: list[dict[str, Any]],
) -> dict[str, list[str]]:
    """Group writable share names per host, preserving order and de-duping."""
    by_host: dict[str, list[str]] = {}
    for row in writable:
        host = str(row.get("host") or "").strip()
        share = str(row.get("share") or "").strip()
        if not host or not share:
            continue
        names = by_host.setdefault(host, [])
        if share not in names:
            names.append(share)
    return by_host


def _hunt_option_label(row: dict[str, Any]) -> str:
    """Picker label: ``\\\\host\\share  [Access]  ←  principals``."""
    access = _row_access(row)
    if "Full Control" in access:
        acc = "Full Control"
    elif "Write" in access and "Read" in access:
        acc = "Read+Write"
    elif "Write" in access:
        acc = "Write"
    else:
        acc = "Read Only"
    principals = sorted(str(p) for p in (row.get("principals") or set()) if str(p).strip())
    via = ", ".join(principals[:3])
    host = str(row.get("host") or "")
    share = str(row.get("share") or "")
    return f"\\\\{host}\\{share}  [{acc}]  ←  {via}"


def _select_shares_for_hunt(
    shell: Any,
    rows: list[dict[str, Any]],
    *,
    _non_interactive: Callable[[Any], bool] | None = None,
) -> list[dict[str, Any]]:
    """Let the operator pick which readable shares to loot. CI auto-selects all.

    ``_non_interactive`` is injectable for tests; defaults to the canonical
    predicate.
    """
    if _non_interactive is None:
        from adscan_internal.interaction import is_non_interactive as _non_interactive  # noqa: PLC0415
    if _non_interactive(shell):
        is_ctf = str(getattr(shell, "type", "") or "").strip().lower() == "ctf"
        if is_ctf:
            return rows
        # Audit CI: bound to the top-N highest-risk readable shares (rows are
        # already risk-ranked). Not a silent cap; log what was bounded.
        if len(rows) > _AUDIT_HUNT_SHARE_LIMIT:
            print_info(
                f"Audit: credential hunt bounded to the top "
                f"{_AUDIT_HUNT_SHARE_LIMIT} of {len(rows)} readable shares by "
                "risk; re-run interactively to scan more."
            )
            return rows[:_AUDIT_HUNT_SHARE_LIMIT]
        return rows
    checkbox = getattr(shell, "_questionary_checkbox", None)
    if not callable(checkbox):
        return rows
    options = [_hunt_option_label(r) for r in rows]
    # Audit pre-selects only the top-N highest-risk shares as the default (rows
    # are already risk-ranked) while still listing every share so the operator
    # can widen the selection. CTF pre-selects all. The cap is a function of the
    # engagement type, not of CI mode.
    is_ctf = str(getattr(shell, "type", "") or "").strip().lower() == "ctf"
    if not is_ctf and len(options) > _AUDIT_HUNT_SHARE_LIMIT:
        default_values = options[:_AUDIT_HUNT_SHARE_LIMIT]
        print_info(
            f"Audit: pre-selected the top {_AUDIT_HUNT_SHARE_LIMIT} of "
            f"{len(options)} readable shares by risk; select more to widen the hunt."
        )
    else:
        default_values = options
    chosen = checkbox(
        "Select readable shares to scan for credentials:",
        options,
        default_values=default_values,
    )
    if not chosen:
        return []
    chosen_set = set(chosen)
    return [r for r, opt in zip(rows, options) if opt in chosen_set]


def _select_droppable_shares(
    *,
    host: str,
    names: list[str],
    access_by_host_share: dict[str, dict[str, Any]],
    held_by_sid: dict[str, str],
    group_closure: dict[str, "frozenset[str]"],
    active_username: str,
) -> list[str]:
    """Keep only shares the AUTHENTICATING credential can actually write.

    A writable share whose per-principal ``share_access`` map shows it is writable
    only by a principal that is NOT the credential we drop as is honest-skipped
    (with a message naming who can write it) instead of attempted — that attempt
    is the misleading ``LOGON_FAILURE`` on a confirmed-writable target (#2, session
    731456ac). Fail-open: a share with no map (legacy/live path) or no recorded
    writer, or a host with no resolution context, falls through UNCHANGED so the
    established behavior is preserved wherever the map is unavailable.
    """
    from adscan_internal.rich_output import mark_sensitive  # noqa: PLC0415
    from adscan_internal.services.attack_paths_core import _normalize_account  # noqa: PLC0415
    from adscan_internal.services.post_exploitation.ntlmv2_share_capture_service import (  # noqa: PLC0415
        resolve_bait_drop_principals,
        share_writer_sids,
    )

    access = access_by_host_share.get(host, {})
    if not held_by_sid or not access:
        return names  # no resolution context → preserve legacy behavior
    active_norm = _normalize_account(active_username)
    droppable: list[str] = []
    for share in names:
        share_access = access.get(share)
        if not isinstance(share_access, dict):
            droppable.append(share)  # no per-principal map for this share → fall back
            continue
        writers = share_writer_sids(share_access)
        if not writers:
            droppable.append(share)  # writable but no principal recorded → fall back
            continue
        resolved = resolve_bait_drop_principals(
            writable_by_principal=writers,
            held_creds_by_sid=held_by_sid,
            group_closure=group_closure,
        )
        if active_norm in {_normalize_account(r) for r in resolved}:
            droppable.append(share)  # the credential we drop AS can write it
            continue
        marked = mark_sensitive(share, "share")
        if resolved:
            who = ", ".join(mark_sensitive(r, "user") for r in resolved[:3])
            print_info(
                f"[~] {marked}: writable, but by a different held principal ({who}) — "
                f"dropping as {mark_sensitive(active_username, 'user')} would fail; skipped."
            )
        else:
            print_info(
                f"[~] {marked}: writable by a principal ADscan holds no credential for "
                "— no bait dropped (an honest coverage gap, not an auth failure)."
            )
    return droppable


def _run_writable_capture_substep(
    shell: Any,
    *,
    domain: str,
    writable: list[dict[str, Any]],
    domain_data: dict[str, Any],
    username: str | None = None,
    credential: str | None = None,
    guard: "SweepLockoutGuard | None" = None,
) -> None:
    """Step 1/2 — drop NTLMv2 bait on writable shares (per host).

    ``username``/``credential`` pin the principal to drop bait AS — this MUST be
    the principal whose effective access the surface was computed for (the user
    being assessed), not the domain's active credential. The live per-user
    surface passes them explicitly; only when absent do we fall back to
    ``domain_data`` (the all-users Phase 7 overview path). Dropping bait as the
    wrong principal yields ACCESS_DENIED on shares the assessed user can write.

    ``guard`` is a shared :class:`~adscan_internal.services.sweep_credential.
    SweepLockoutGuard` circuit-breaker — one credential authenticating across
    every writable host is a mass-auth sweep, so a lockout or repeated logon
    failure aborts the host loop immediately instead of re-asserting the
    lockout against every remaining host. Callers that omit it (direct/legacy
    calls, tests) get a fresh single-use guard scoped to this call only.
    """
    from adscan_internal.cli.smb import run_ntlmv2_capture_for_writable_shares  # noqa: PLC0415
    from adscan_internal.services.sweep_credential import SweepLockoutGuard  # noqa: PLC0415

    by_host = _group_writable_share_names_by_host(writable)
    if not by_host:
        print_info_verbose("No writable shares — skipping Step 1/2 (writable-share capture).")
        return
    if guard is not None and guard.aborted:
        # The SAME credential/guard already tripped elsewhere in this sweep
        # (e.g. the live per-host share enumeration that preceded this
        # surface) — never start a fresh round of SMB auth attempts with a
        # credential already known locked out / rejected.
        print_warning(
            "Step 1/2 (Writable-Share Capture) skipped — "
            f"{guard.abort_reason or 'the credential was locked out / rejected earlier in this sweep.'}"
        )
        return
    username = str(username or domain_data.get("username") or "").strip()
    credential = str(credential or domain_data.get("password") or "").strip()
    if not username or not credential:
        print_info_verbose("No domain credentials — skipping Step 1/2 (writable-share capture).")
        return
    # Resolve which principal each writable share is ACTUALLY writable by, so bait
    # is dropped only where the authenticating credential can write it — reusing
    # the membership SSOT (build_bait_principal_context). Best-effort: any failure
    # leaves the context empty, which fails open to the established behavior.
    from adscan_internal.services.post_exploitation.ntlmv2_share_capture_service import (  # noqa: PLC0415
        build_bait_principal_context,
    )

    held_usernames = list((domain_data.get("credentials") or {}).keys()) + [username]
    try:
        from adscan_internal.services.attack_graph_service import (  # noqa: PLC0415
            load_attack_graph,
        )

        bait_graph = load_attack_graph(shell, domain)
    except Exception:  # noqa: BLE001 — resolution is best-effort; never break capture
        bait_graph = None
    held_by_sid, group_closure = build_bait_principal_context(bait_graph, held_usernames)
    access_by_host_share: dict[str, dict[str, Any]] = {}
    # A graph-derived row's ``host`` is the computer's DISPLAY label
    # (``HOST$@REALM``), which does NOT SMB-connect; ``host_ip`` carries the
    # connectable IP/DNS. Map label -> connectable host so the drop/enum
    # authenticates against a real host, not the account principal (the audit
    # LOGON_FAILURE bug). Live-enumerated rows have no ``host_ip`` and their
    # ``host`` is already an IP, so the fallback below keeps them working.
    host_ip_by_label: dict[str, str] = {}
    for row in writable:
        row_host = str(row.get("host") or "").strip()
        row_share = str(row.get("share") or "").strip()
        row_access = row.get("share_access")
        if row_host and row_share and isinstance(row_access, dict):
            access_by_host_share.setdefault(row_host, {})[row_share] = row_access
        row_host_ip = str(row.get("host_ip") or "").strip()
        if row_host and row_host_ip and row_host not in host_ip_by_label:
            host_ip_by_label[row_host] = row_host_ip
    print_phase_header(
        "Step 1/2 · Writable-Share Capture",
        details={"Domain": domain, "Writable hosts": str(len(by_host))},
        icon="📤",
    )
    if guard is None:
        guard = SweepLockoutGuard()
    total_hosts = len(by_host)
    # One shared estimator across the host loop yields the live rate / ETA /
    # elapsed the platform strip shows, identical to the CLI dashboards.
    from adscan_core.tui.progress_dashboard import ProgressEstimator  # noqa: PLC0415

    estimator = ProgressEstimator()
    for index, (host, names) in enumerate(by_host.items(), start=1):
        _emit_share_operation_progress(
            label="Share enumeration",
            phase="share_credential_hunt",
            current=index,
            total=total_hosts,
            detail=domain,
            estimator=estimator,
        )
        names = _select_droppable_shares(
            host=host,
            names=names,
            access_by_host_share=access_by_host_share,
            held_by_sid=held_by_sid,
            group_closure=group_closure,
            active_username=username,
        )
        if not names:
            continue  # every writable share on this host was honest-skipped

        # Resolve the connectable host via the shared SSOT: prefer the collected
        # IP (``host_ip``, DNS-independent), fall back to the FQDN derived from the
        # ``HOST$@REALM`` label, then the label. Same resolver the read
        # credential-hunt uses — neither path authenticates against the
        # non-routable account-principal string (the audit LOGON_FAILURE bug).
        from adscan_internal.cli.smb import (  # noqa: PLC0415
            resolve_connectable_share_host,
        )

        connect_host = resolve_connectable_share_host(
            host, host_ip_by_label.get(host), domain
        )

        # CTF vs audit routing. The bait is a WAIT-for-a-user-to-browse technique:
        # blocking the scan on it is fine in a targeted CTF (operator actively
        # waiting), but a real audit cannot block for minutes/hours/days — so audit
        # routes the plant + wait through the BACKGROUND job (shared :445 broker),
        # letting the scan proceed. The launch seam gates enable/consent + plants;
        # CTF keeps the blocking path.
        from adscan_internal.services.background_jobs.scan_seam import (  # noqa: PLC0415
            writeshare_bait_enabled,
        )

        is_ctf = str(getattr(shell, "type", "") or "").strip().lower() == "ctf"
        if not is_ctf:
            # Respect a pre-tripped lockout guard: if the SAME credential was
            # already locked out / rejected earlier in this sweep, do not keep
            # planting bait (each plant authenticates) host after host.
            if guard is not None and guard.aborted:
                break
            from adscan_internal.services.background_jobs.scan_seam import (  # noqa: PLC0415
                maybe_launch_writeshare_bait_job,
            )
            from adscan_internal.services.post_exploitation.ntlmv2_share_capture_service import (  # noqa: PLC0415
                DropTarget,
            )
            from adscan_internal.services.egress_resolver import (  # noqa: PLC0415
                resolve_egress_for_target,
            )

            # Resolve the inbound-callback IP per-share-host: the bait's :445
            # listener BINDS this IP and the icon UNC ADVERTISES it, so it must be
            # a locally-bindable address that the victim on that segment reaches.
            # A ``direct`` vantage yields exactly that (kernel-chosen src toward
            # the host).
            vantage = resolve_egress_for_target(shell, connect_host)
            listener_ip = str(getattr(shell, "myip", "") or "")
            listener_bind_ip: str | None = None
            pivot_plan = None

            if vantage.is_direct:
                listener_ip = vantage.callback_ip
            elif vantage.vantage == "pivot":
                # A pivot (Ligolo TUN) vantage cannot bind the remote redirector
                # locally — it needs the agent-listener reverse channel. Plan it
                # honestly: on a viable plan the bait advertises the agent-segment
                # redirector host and binds the broker locally for the tunneled
                # redirect; otherwise honest-skip THIS host (no false callback).
                from adscan_internal.services.ligolo_pivot_capture import (  # noqa: PLC0415
                    plan_pivot_capture,
                )

                from adscan_internal.rich_output import mark_sensitive  # noqa: PLC0415

                pivot_plan = plan_pivot_capture(shell, connect_host)
                if not pivot_plan.viable:
                    print_warning(
                        "Write-share bait skipped for "
                        f"{mark_sensitive(connect_host, 'ip')}: reached through a "
                        "Ligolo pivot with no inbound-callback path. "
                        f"{pivot_plan.notes}."
                    )
                    print_info_debug(
                        "writeshare-bait: pivot capture skipped for "
                        f"{mark_sensitive(connect_host, 'ip')} "
                        f"(reason={pivot_plan.skip_reason or 'unknown'})."
                    )
                    continue
                listener_ip = pivot_plan.callback_ip or listener_ip
                listener_bind_ip = pivot_plan.bind_ip

            maybe_launch_writeshare_bait_job(
                shell,
                domain,
                target_host=connect_host,
                targets=[DropTarget(share=n) for n in names],
                creds={
                    "username": username,
                    "password": credential,
                    "auth_domain": domain,
                },
                listener_ip=listener_ip,
                listener_bind_ip=listener_bind_ip,
                pivot_plan=pivot_plan,
            )
            continue  # background — never block the audit scan on this host

        if not writeshare_bait_enabled(shell):
            continue  # CTF but the bait was explicitly disabled via --scan-config

        auth_error = run_ntlmv2_capture_for_writable_shares(
            shell,
            domain=domain,
            host=connect_host,
            writable_share_names=names,
            username=username,
            credential=credential,
        )
        decision = guard.record(host, auth_error)
        if decision.should_abort:
            print_warning(
                f"{decision.reason}\n\n"
                f"Writable-share capture aborted after {index} of {total_hosts} "
                f"host(s) — the remaining {total_hosts - index} host(s) were "
                "skipped to protect the account."
            )
            break


def _run_readable_hunt_substep(
    shell: Any,
    *,
    domain: str,
    readable: list[dict[str, Any]],
    username: str | None = None,
    credential: str | None = None,
    guard: "SweepLockoutGuard | None" = None,
) -> None:
    """Step 2/2 — loot readable shares for embedded credentials.

    ``username``/``credential`` pin the principal to loot AS — this MUST be the
    principal whose effective READ access the surface was computed for (the user
    being assessed), not the domain's active credential. The live per-user
    surface passes them explicitly; absent them the hunt falls back to
    ``domain_data`` (the all-users Phase 7 path). Looting as the wrong principal
    yields permission-denied on shares only the assessed user can read, silently
    missing the embedded credentials inside them.

    ``guard`` is the SAME :class:`SweepLockoutGuard` Step 1 fed — same
    credential, one guard. If Step 1 already tripped it (lockout / repeated
    logon failure), Step 2 must not start at all: it would authenticate the
    same dead credential against a DIFFERENT, larger set of hosts, re-asserting
    the lockout the guard exists to prevent.
    """
    if guard is not None and guard.aborted:
        print_warning(
            "Step 2/2 (Readable-Share Credential Hunt) skipped — "
            f"{guard.abort_reason or 'the credential was locked out / rejected during Step 1/2.'}"
        )
        return

    from adscan_internal.cli.smb import run_smb_share_credential_hunt  # noqa: PLC0415

    if not readable:
        print_info_verbose("No readable shares — skipping Step 2/2 (credential hunt).")
        return
    print_phase_header(
        "Step 2/2 · Readable-Share Credential Hunt",
        details={"Domain": domain, "Readable shares": str(len(readable))},
        icon="📂",
    )
    selected = _select_shares_for_hunt(shell, readable)
    if not selected:
        return
    _emit_share_operation_progress(
        label="Share enumeration",
        phase="share_credential_hunt",
        current=len(selected),
        total=len(selected),
        detail=domain,
    )
    run_smb_share_credential_hunt(
        shell,
        domain=domain,
        targets=[
            {"host": str(r.get("host") or "").strip(), "share": str(r.get("share") or "").strip()}
            for r in selected
            if str(r.get("host") or "").strip() and str(r.get("share") or "").strip()
        ],
        username=username,
        credential=credential,
    )


def run_smb_share_exposure_phase(shell: Any, *, domain: str) -> None:
    """Phase 7 — SMB Share Exposure: overview -> write capture -> read hunt."""
    from adscan_internal.services.scan_phases import phase_is_enabled  # noqa: PLC0415

    if not phase_is_enabled(shell, "share_credential_hunt"):
        print_info("SMB Share Exposure skipped (disabled in scan configuration).")
        return
    if getattr(shell, "_is_ctf_domain_pwned", lambda _d: False)(domain):
        return

    from adscan_internal.services.attack_graph_service import load_attack_graph  # noqa: PLC0415
    from adscan_internal.services.attack_graph_core import (  # noqa: PLC0415
        collect_share_exposures_from_graph,
    )
    from adscan_core.output._attack_paths import render_smb_exposed_resources_panel  # noqa: PLC0415

    try:
        raw_graph = load_attack_graph(shell, domain)
    except Exception:  # noqa: BLE001
        raw_graph = None
    if not raw_graph:
        return

    domain_data = getattr(shell, "domains_data", {}).get(domain, {})
    domain_sid = str(domain_data.get("domain_sid", "") or "").strip() or None
    try:
        # Comprehensive inventory — no silent truncation of the capture set
        # (the bait step must see every writable share, not just the top 20).
        rows = collect_share_exposures_from_graph(raw_graph, domain_sid=domain_sid, limit=None)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return
    if not rows:
        # No share-access rows in the graph. Distinguish a genuine "no exposure"
        # result (stay quiet) from an aborted collection (surface it): otherwise
        # the phase "Completes" silently and an incomplete enumeration reads as
        # "no shares". The collector persisted the abort coverage into domains_data.
        _share_coverage = domain_data.get("share_collection")
        if isinstance(_share_coverage, dict):
            _aborted = [
                (str(h.get("host") or ""), str(h.get("ip") or ""))
                for h in (_share_coverage.get("aborted_hosts") or [])
                if isinstance(h, dict)
            ]
            if _aborted:
                from adscan_internal.services.collector.share_collection_notify import (  # noqa: PLC0415
                    emit_phase_share_abort_notice,
                )

                emit_phase_share_abort_notice(
                    _aborted, int(_share_coverage.get("reached_hosts") or 0)
                )
        return

    # -- Global overview (Access column already encodes R/W severity) --
    try:
        render_smb_exposed_resources_panel(rows, domain=domain)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)

    writable, readable = _split_share_rows(rows)

    # ONE credential (the domain-active / assessed principal), ONE guard —
    # shared across BOTH sub-steps so a lockout / repeated logon failure
    # observed in Step 1 stops the Step-1 host loop immediately AND prevents
    # Step 2 from starting at all (Step 2 authenticates the SAME credential
    # against a different, larger host set). SSOT: sweep_credential.
    from adscan_internal.services.sweep_credential import SweepLockoutGuard  # noqa: PLC0415

    guard = SweepLockoutGuard()

    # Sub-steps are independent WRT their own errors: a failure in one never
    # aborts the other (except the shared-guard trip above, which is deliberate
    # account protection, not an error). The whole phase shares one
    # ``share_enumeration`` operation, so a single terminal done tick fires in
    # the ``finally`` once both substeps have run — the live strip clears
    # immediately instead of freezing on the last host count, even if a
    # substep raised.
    try:
        try:
            _run_writable_capture_substep(
                shell, domain=domain, writable=writable, domain_data=domain_data, guard=guard
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
        try:
            _run_readable_hunt_substep(shell, domain=domain, readable=readable, guard=guard)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
    finally:
        _emit_share_operation_progress(
            label="Share enumeration",
            phase="share_credential_hunt",
            detail=domain,
            done=True,
        )


__all__ = ["run_smb_share_exposure_phase"]
