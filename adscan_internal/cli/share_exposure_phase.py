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
"""
from __future__ import annotations

from typing import Any, Callable

from adscan_core import telemetry
from adscan_core.rich_output import print_info, print_info_verbose, print_phase_header

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


def _run_writable_capture_substep(
    shell: Any,
    *,
    domain: str,
    writable: list[dict[str, Any]],
    domain_data: dict[str, Any],
    username: str | None = None,
    credential: str | None = None,
) -> None:
    """Step 1/2 — drop NTLMv2 bait on writable shares (per host).

    ``username``/``credential`` pin the principal to drop bait AS — this MUST be
    the principal whose effective access the surface was computed for (the user
    being assessed), not the domain's active credential. The live per-user
    surface passes them explicitly; only when absent do we fall back to
    ``domain_data`` (the all-users Phase 7 overview path). Dropping bait as the
    wrong principal yields ACCESS_DENIED on shares the assessed user can write.
    """
    from adscan_internal.cli.smb import run_ntlmv2_capture_for_writable_shares  # noqa: PLC0415

    by_host = _group_writable_share_names_by_host(writable)
    if not by_host:
        print_info_verbose("No writable shares — skipping Step 1/2 (writable-share capture).")
        return
    username = str(username or domain_data.get("username") or "").strip()
    credential = str(credential or domain_data.get("password") or "").strip()
    if not username or not credential:
        print_info_verbose("No domain credentials — skipping Step 1/2 (writable-share capture).")
        return
    print_phase_header(
        "Step 1/2 · Writable-Share Capture",
        details={"Domain": domain, "Writable hosts": str(len(by_host))},
        icon="📤",
    )
    for host, names in by_host.items():
        run_ntlmv2_capture_for_writable_shares(
            shell,
            domain=domain,
            host=host,
            writable_share_names=names,
            username=username,
            credential=credential,
        )


def _run_readable_hunt_substep(
    shell: Any,
    *,
    domain: str,
    readable: list[dict[str, Any]],
    username: str | None = None,
    credential: str | None = None,
) -> None:
    """Step 2/2 — loot readable shares for embedded credentials.

    ``username``/``credential`` pin the principal to loot AS — this MUST be the
    principal whose effective READ access the surface was computed for (the user
    being assessed), not the domain's active credential. The live per-user
    surface passes them explicitly; absent them the hunt falls back to
    ``domain_data`` (the all-users Phase 7 path). Looting as the wrong principal
    yields permission-denied on shares only the assessed user can read, silently
    missing the embedded credentials inside them.
    """
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
        return
    if not rows:
        return

    # -- Global overview (Access column already encodes R/W severity) --
    try:
        render_smb_exposed_resources_panel(rows, domain=domain)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)

    writable, readable = _split_share_rows(rows)

    # Sub-steps are independent: a failure in one never aborts the other.
    try:
        _run_writable_capture_substep(
            shell, domain=domain, writable=writable, domain_data=domain_data
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
    try:
        _run_readable_hunt_substep(shell, domain=domain, readable=readable)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)


__all__ = ["run_smb_share_exposure_phase"]
