"""Shared UX flow for NTLM hash findings extracted from filesystem-like scans."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import json
import os

import rich
from rich.table import Table

from adscan_internal import (
    print_info,
    print_info_debug,
    print_info_table,
    print_panel,
    telemetry,
)
from adscan_internal.rich_output import (
    BRAND_COLORS,
    mark_sensitive,
    print_panel_with_table,
)


def _should_skip_ntlm_hash_validation_for_ctf_pwned(*, shell: Any, domain: str) -> bool:
    """Return True when optional validation prompts should be skipped for CTF+pwned."""
    checker = getattr(shell, "_is_ctf_domain_pwned", None)
    if callable(checker):
        try:
            if bool(checker(domain)):
                return True
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
    workspace_type = str(getattr(shell, "type", "") or "").strip().lower()
    auth_state = str(
        getattr(shell, "domains_data", {}).get(domain, {}).get("auth", "") or ""
    ).strip().lower()
    return workspace_type == "ctf" and auth_state == "pwned"


def _summarize_ntlm_hash_sources(
    *,
    source_paths: list[str],
    preview_limit: int = 2,
) -> str:
    """Render a compact source preview for one grouped NTLM hash finding."""
    if not source_paths:
        return "-"
    ordered = sorted({str(path).strip() for path in source_paths if str(path).strip()})
    preview = ", ".join(mark_sensitive(path, "path") for path in ordered[:preview_limit])
    if len(ordered) > preview_limit:
        preview += f", +{len(ordered) - preview_limit} more"
    return preview or "-"


def _classify_ntlm_principal_risk(
    shell: Any,
    *,
    domain: str,
    usernames: list[str],
) -> dict[str, dict[str, str | bool]]:
    """Best-effort classify NTLM hash principals as user/computer and risk."""
    from adscan_internal.services.high_value import (
        classify_users_tier0_high_value,
        is_node_high_value,
        is_node_tier0,
    )

    results: dict[str, dict[str, str | bool]] = {}
    normalized_usernames = [
        str(username).strip() for username in usernames if str(username).strip()
    ]
    user_accounts = [
        username for username in normalized_usernames if not username.endswith("$")
    ]
    computer_accounts = [
        username for username in normalized_usernames if username.endswith("$")
    ]

    try:
        risk_flags = classify_users_tier0_high_value(
            shell,
            domain=domain,
            usernames=user_accounts,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        risk_flags = {}

    for username in user_accounts:
        flags = risk_flags.get(username.strip().lower())
        is_tier0 = bool(getattr(flags, "is_tier0", False))
        is_high_value = bool(getattr(flags, "is_high_value", False))
        results[username.strip().lower()] = {
            "kind": "User",
            "risk_label": "Tier Zero"
            if is_tier0
            else "High Value"
            if is_high_value
            else "Standard",
            "is_tier0": is_tier0,
            "is_high_value": is_high_value,
        }

    bh_service_getter = getattr(shell, "_get_bloodhound_service", None)
    bh_service = bh_service_getter() if callable(bh_service_getter) else None
    for username in computer_accounts:
        normalized = username.strip().lower()
        hostname = username.strip().rstrip("$")
        node: dict[str, Any] | None = None
        if bh_service is not None:
            try:
                resolver = getattr(bh_service, "get_computer_node_by_name", None)
                if callable(resolver):
                    node = resolver(domain, hostname) or resolver(
                        domain, f"{hostname}.{domain}"
                    )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
        is_tier0 = bool(is_node_tier0(node or {}))
        is_high_value = bool(is_node_high_value(node or {}))
        results[normalized] = {
            "kind": "Computer",
            "risk_label": "Tier Zero"
            if is_tier0
            else "High Value"
            if is_high_value
            else "Computer",
            "is_tier0": is_tier0,
            "is_high_value": is_high_value,
        }

    return results


def _persist_ntlm_hash_summary(
    *,
    loot_dir: str,
    grouped_rows: list[dict[str, Any]],
) -> str | None:
    """Persist grouped NTLM hash findings for later manual review."""
    try:
        phase_root = os.path.dirname(str(loot_dir or "").rstrip(os.sep))
        if not phase_root:
            return None
        summary_path = os.path.join(phase_root, "ntlm_hash_findings.json")
        os.makedirs(os.path.dirname(summary_path), exist_ok=True)
        with open(summary_path, "w", encoding="utf-8") as handle:
            json.dump({"findings": grouped_rows}, handle, indent=2)
        return summary_path
    except OSError as exc:
        telemetry.capture_exception(exc)
        return None


def _offer_ntlm_hash_domain_validation(
    shell: Any,
    *,
    domain: str,
    grouped_rows: list[dict[str, Any]],
    source_scope: str,
) -> None:
    """Offer optional domain validation for extracted NTLM hashes."""
    if not grouped_rows:
        return
    if _should_skip_ntlm_hash_validation_for_ctf_pwned(shell=shell, domain=domain):
        print_info(
            "Skipping NTLM hash domain validation because the CTF domain is already pwned."
        )
        return

    confirmer = getattr(shell, "_questionary_confirm", None)
    if not callable(confirmer):
        print_info_debug(
            "Skipping NTLM hash validation prompt because questionary confirm is unavailable."
        )
        return
    if not bool(
        confirmer(
            "Validate selected extracted NTLM hashes against domain users now?",
            default=True,
        )
    ):
        print_info("Skipping NTLM hash domain validation for now.")
        return

    from adscan_internal.cli.spraying import (
        DomainReuseValidationCandidate,
        handle_validated_domain_hits_followup,
        select_domain_reuse_candidates_for_validation,
        validate_selected_domain_reuse_candidates,
    )

    candidates = [
        DomainReuseValidationCandidate(
            credential=str(row.get("ntlm_hash") or "").strip(),
            credential_type="hash",
            accounts=[str(row.get("username") or "").strip()],
            source_hostnames=sorted(
                str(host).strip()
                for host in (row.get("source_hosts") or [])
                if str(host).strip()
            ),
        )
        for row in grouped_rows
        if str(row.get("username") or "").strip()
        and str(row.get("ntlm_hash") or "").strip()
    ]
    selection = select_domain_reuse_candidates_for_validation(
        shell,
        domain=domain,
        candidates=candidates,
        source_scope=source_scope,
    )
    if selection is None:
        return
    selected_candidates, eligibility = selection
    if not selected_candidates:
        return

    print_info(
        "Running NTLM hash domain validation for "
        f"{len(selected_candidates)} selected hash variant(s) in {mark_sensitive(domain, 'domain')}."
    )
    result_rows, _domain_results_by_credential, validated_domain_hits = (
        validate_selected_domain_reuse_candidates(
            shell,
            domain=domain,
            candidates=selected_candidates,
            eligibility=eligibility,
        )
    )
    if result_rows:
        print_info_table(
            result_rows,
            [
                "Accounts",
                "Credential Type",
                "Credential",
                "Status",
                "Domain Hits",
                "Local->Domain Steps",
                "DomainPassReuse",
                "Outcome Summary",
            ],
            title="File NTLM Hash -> Domain Validation Results",
        )
    auth_state = str(shell.domains_data.get(domain, {}).get("auth", "")).strip().lower()
    if validated_domain_hits and auth_state != "pwned":
        handle_validated_domain_hits_followup(
            shell,
            domain=domain,
            hits=validated_domain_hits,
            discovery_label="validated",
        )


def render_ntlm_hash_findings_flow(
    shell: Any,
    *,
    domain: str,
    loot_dir: str,
    loot_rel: str,
    phase_label: str,
    ntlm_hash_findings: list[dict[str, str]],
    source_scope: str,
    fallback_source_hosts: list[str] | None = None,
    fallback_source_shares: list[str] | None = None,
) -> None:
    """Render one reusable premium UX flow for NTLM hash filesystem findings."""
    if not ntlm_hash_findings:
        return

    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for item in ntlm_hash_findings:
        username = str(item.get("username") or "").strip()
        ntlm_hash = str(item.get("ntlm_hash") or "").strip()
        source_path = str(item.get("source_path") or "").strip()
        if not username or not ntlm_hash or not source_path:
            continue
        key = (username.lower(), ntlm_hash.lower())
        bucket = grouped.setdefault(
            key,
            {
                "username": username,
                "ntlm_hash": ntlm_hash,
                "source_paths": set(),
                "source_hosts": set(str(host).strip() for host in (fallback_source_hosts or []) if str(host).strip()),
                "source_shares": set(str(share).strip() for share in (fallback_source_shares or []) if str(share).strip()),
            },
        )
        bucket["source_paths"].add(source_path)
        try:
            relative = Path(source_path).resolve(strict=False).relative_to(
                Path(loot_dir).resolve(strict=False)
            )
            parts = relative.parts
            # Infer SMB-style host/share context only when the relative layout
            # clearly contains at least host/share/file.
            if len(parts) >= 3:
                bucket["source_hosts"].add(parts[0])
                bucket["source_shares"].add(parts[1])
        except ValueError:
            continue

    grouped_rows = list(grouped.values())
    if not grouped_rows:
        return

    risk_by_user = _classify_ntlm_principal_risk(
        shell,
        domain=domain,
        usernames=[str(row.get("username") or "") for row in grouped_rows],
    )
    rows_with_key: list[tuple[tuple[int, str], dict[str, str]]] = []
    export_rows: list[dict[str, Any]] = []
    source_file_count = len(
        {
            str(path).strip()
            for row in grouped_rows
            for path in row.get("source_paths", set())
            if str(path).strip()
        }
    )
    tier_zero_count = 0
    high_value_count = 0

    for row in grouped_rows:
        username = str(row.get("username") or "").strip()
        ntlm_hash = str(row.get("ntlm_hash") or "").strip()
        risk = risk_by_user.get(
            username.lower(),
            {
                "kind": "Computer" if username.endswith("$") else "User",
                "risk_label": "Computer" if username.endswith("$") else "Standard",
                "has_direct_domain_control": False,
                "is_control_exposed": False,
            },
        )
        if bool(risk.get("has_direct_domain_control")):
            tier_zero_count += 1
        elif bool(risk.get("is_control_exposed")):
            high_value_count += 1
        risk_label = str(risk.get("risk_label") or "-")
        risk_rank = (
            0
            if risk_label == "Tier Zero"
            else 1
            if risk_label == "High Value"
            else 2
        )
        source_paths = sorted(
            str(path).strip()
            for path in row.get("source_paths", set())
            if str(path).strip()
        )
        source_hosts = sorted(
            str(host).strip()
            for host in row.get("source_hosts", set())
            if str(host).strip()
        )
        source_shares = sorted(
            str(share).strip()
            for share in row.get("source_shares", set())
            if str(share).strip()
        )
        rows_with_key.append(
            (
                (risk_rank, username.lower()),
                {
                    "Principal": mark_sensitive(username, "user"),
                    "Kind": str(risk.get("kind") or "-"),
                    "Risk": risk_label,
                    "NT Hash": mark_sensitive(ntlm_hash, "password"),
                    "Seen": str(len(source_paths)),
                    "Sources": _summarize_ntlm_hash_sources(source_paths=source_paths),
                },
            )
        )
        export_rows.append(
            {
                "username": username,
                "ntlm_hash": ntlm_hash,
                "kind": str(risk.get("kind") or "-"),
                "risk": risk_label,
                "source_hosts": source_hosts,
                "source_shares": source_shares,
                "source_paths": source_paths,
            }
        )

    ordered_rows = [row for _, row in sorted(rows_with_key, key=lambda item: item[0])]
    summary_path = _persist_ntlm_hash_summary(
        loot_dir=loot_dir,
        grouped_rows=export_rows,
    )
    preview_rows = ordered_rows[:20]
    table = Table(
        title="[bold cyan]NTLM Hashes Extracted From Files[/bold cyan]",
        header_style="bold magenta",
        box=rich.box.SIMPLE_HEAVY,
    )
    table.add_column("#", style="dim", justify="right")
    table.add_column("Principal", style="cyan")
    table.add_column("Kind", style="green")
    table.add_column("Risk", style="magenta")
    table.add_column("NT Hash", style="yellow")
    table.add_column("Seen", style="green", justify="right")
    table.add_column("Sources", style="white")
    for idx, row in enumerate(preview_rows, start=1):
        table.add_row(
            str(idx),
            str(row["Principal"]),
            str(row["Kind"]),
            str(row["Risk"]),
            str(row["NT Hash"]),
            str(row["Seen"]),
            str(row["Sources"]),
        )
    print_panel_with_table(table, border_style=BRAND_COLORS["warning"])

    summary_lines = [
        f"Phase: {phase_label}",
        f"Domain: {mark_sensitive(domain, 'domain')}",
        f"Unique NTLM hashes: {len(ordered_rows)}",
        f"Distinct source files: {source_file_count}",
        f"Tier Zero principals: {tier_zero_count}",
        f"High-value principals: {high_value_count}",
        f"Loot: {mark_sensitive(loot_rel, 'path')}",
    ]
    if len(ordered_rows) > len(preview_rows):
        summary_lines.append(
            f"Preview shown: {len(preview_rows)} of {len(ordered_rows)} unique findings"
        )
    if summary_path:
        summary_lines.append(f"Full summary: {mark_sensitive(summary_path, 'path')}")
    print_panel(
        "\n".join(summary_lines),
        title="[bold yellow]NTLM Hash Dump Summary[/bold yellow]",
        border_style="yellow",
        expand=False,
    )

    _offer_ntlm_hash_domain_validation(
        shell,
        domain=domain,
        grouped_rows=export_rows,
        source_scope=source_scope,
    )
