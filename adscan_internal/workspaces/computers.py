"""Helpers for workspace computer lists."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from adscan_internal.workspaces import domain_subpath


def has_enabled_computer_list(
    workspace_dir: str,
    domains_dir: str,
    domain: str,
) -> bool:
    """Return True if enabled_computers.txt exists and is non-empty."""
    abs_path = domain_subpath(
        workspace_dir, domains_dir, domain, "enabled_computers.txt"
    )
    try:
        path = Path(abs_path)
        return path.exists() and path.stat().st_size > 0
    except OSError:
        return False


def load_enabled_computer_samaccounts(
    workspace_dir: str,
    domains_dir: str,
    domain: str,
) -> list[str]:
    """Load enabled computer accounts as sAMAccountName values.

    This reads ``enabled_computers.txt`` and converts each hostname/FQDN to
    ``HOST$`` format. Duplicates are removed (case-insensitive), preserving
    first-seen order.

    Args:
        workspace_dir: Workspace root directory (absolute or relative).
        domains_dir: Domains directory (relative to workspace).
        domain: Target domain.

    Returns:
        List of unique computer sAMAccountName values.

    Raises:
        OSError: If the file cannot be read.
    """
    abs_path = domain_subpath(
        workspace_dir, domains_dir, domain, "enabled_computers.txt"
    )

    data = Path(abs_path).read_text(encoding="utf-8", errors="ignore").splitlines()
    seen: set[str] = set()
    results: list[str] = []

    for raw in data:
        line = raw.strip()
        if not line:
            continue
        hostname = line.split(".", 1)[0].strip()
        if not hostname:
            continue
        sam = hostname if hostname.endswith("$") else f"{hostname}$"
        key = sam.lower()
        if key in seen:
            continue
        seen.add(key)
        results.append(sam)

    return results


def count_enabled_computer_accounts(
    workspace_dir: str,
    domains_dir: str,
    domain: str,
) -> int:
    """Return the number of unique enabled computer accounts in the workspace list.

    Args:
        workspace_dir: Workspace root directory (absolute or relative).
        domains_dir: Domains directory (relative to workspace).
        domain: Target domain.

    Returns:
        Number of unique enabled computer accounts derived from
        ``enabled_computers.txt``.

    Raises:
        OSError: If the file cannot be read.
    """

    return len(load_enabled_computer_samaccounts(workspace_dir, domains_dir, domain))


def ensure_enabled_computer_ip_file(
    workspace_dir: str,
    domains_dir: str,
    domain: str,
    domain_data: dict[str, object] | None = None,
) -> tuple[str | None, str]:
    """Return a usable `enabled_computers_ips.txt` path, repairing it if needed.

    Resolution order:
    1. Existing non-empty `enabled_computers_ips.txt`
    2. Existing non-empty `dcs.txt`
    3. Persisted `pdc` from `domain_data`, written into `enabled_computers_ips.txt`

    Returns:
        Tuple of `(absolute_path_or_none, source_label)`.
    """
    domain_info = domain_data or {}
    ip_file = Path(domain_subpath(workspace_dir, domains_dir, domain, "enabled_computers_ips.txt"))
    dcs_file = Path(domain_subpath(workspace_dir, domains_dir, domain, "dcs.txt"))

    try:
        if ip_file.exists() and ip_file.stat().st_size > 0:
            return str(ip_file), "enabled_computers_ips"
    except OSError:
        pass

    try:
        if dcs_file.exists() and dcs_file.stat().st_size > 0:
            ip_file.parent.mkdir(parents=True, exist_ok=True)
            ip_file.write_text(dcs_file.read_text(encoding="utf-8"), encoding="utf-8")
            return str(ip_file), "dcs_fallback"
    except OSError:
        pass

    pdc_ip = str(domain_info.get("pdc") or "").strip()
    if not pdc_ip:
        return None, "none"

    try:
        ip_file.parent.mkdir(parents=True, exist_ok=True)
        ip_file.write_text(f"{pdc_ip}\n", encoding="utf-8")
    except OSError:
        return None, "none"
    return str(ip_file), "pdc_fallback"


def resolve_domain_service_target_file(
    workspace_dir: str,
    domains_dir: str,
    domain: str,
    *,
    service: str,
    domain_data: dict[str, object] | None = None,
    scope_preference: str = "optimized",
) -> tuple[str | None, str]:
    """Return the best target file for one service in the current workspace.

    Resolution order is intentionally biased toward current-vantage evidence.

    Scope preferences:

    - ``optimized``: service-open -> reachable -> full
    - ``reachable``: reachable -> full
    - ``full``: full only

    1. Non-empty ``domains/<domain>/<service>/ips.txt``
       Preferred because it reflects hosts where the service port was actually
       observed as open (for example from the important-port Nmap scan).
    2. Non-empty ``enabled_computers_reachable_ips.txt``
       Safer fallback when we know the host responded from the current vantage
       but we do not have a service-specific host list.
    3. ``ensure_enabled_computer_ip_file(...)``
       Broad fallback for completeness when no reachability inventory exists.
    """
    service_name = str(service or "").strip().lower()
    service_ips = Path(
        domain_subpath(workspace_dir, domains_dir, domain, service_name, "ips.txt")
    )
    reachable_ips = Path(
        domain_subpath(
            workspace_dir, domains_dir, domain, "enabled_computers_reachable_ips.txt"
        )
    )
    reachability_report = Path(
        domain_subpath(
            workspace_dir, domains_dir, domain, "network_reachability_report.json"
        )
    )

    report_has_current_vantage_scan = False
    preference = str(scope_preference or "optimized").strip().lower()
    try:
        if reachability_report.exists() and reachability_report.stat().st_size > 0:
            payload = json.loads(
                reachability_report.read_text(encoding="utf-8", errors="ignore")
            )
            summary = payload.get("summary", {}) if isinstance(payload, dict) else {}
            report_has_current_vantage_scan = bool(
                isinstance(summary, dict)
                and summary.get("important_port_scan_performed")
            )
    except (OSError, json.JSONDecodeError):
        report_has_current_vantage_scan = False

    if preference == "prioritized_full":
        preference = "full"

    if preference not in {"optimized", "reachable", "full"}:
        preference = "optimized"

    if preference == "optimized":
        try:
            if service_ips.exists() and service_ips.stat().st_size > 0:
                source = (
                    f"{service_name}_ips_current_vantage"
                    if report_has_current_vantage_scan
                    else f"{service_name}_ips"
                )
                return str(service_ips), source
        except OSError:
            pass
        if report_has_current_vantage_scan:
            return None, f"{service_name}_no_open_hosts_current_vantage"

    if preference in {"optimized", "reachable"}:
        try:
            if reachable_ips.exists() and reachable_ips.stat().st_size > 0:
                source = (
                    "reachable_ips_current_vantage"
                    if report_has_current_vantage_scan
                    else "reachable_ips"
                )
                return str(reachable_ips), source
        except OSError:
            pass

    return ensure_enabled_computer_ip_file(
        workspace_dir,
        domains_dir,
        domain,
        domain_data,
    )


def count_target_file_entries(path_value: str | None) -> int:
    """Count non-empty lines in one target file."""
    if not path_value:
        return 0
    try:
        return sum(
            1
            for line in Path(path_value).read_text(
                encoding="utf-8",
                errors="ignore",
            ).splitlines()
            if line.strip()
        )
    except OSError:
        return 0


def load_target_entries(path_value: str | None) -> set[str]:
    """Return normalized targets for one host or target-file path."""
    if not path_value:
        return set()
    candidate = str(path_value).strip()
    if not candidate:
        return set()

    path = Path(candidate)
    if path.exists() and path.is_file():
        try:
            return {
                line.strip().lower()
                for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
                if line.strip()
            }
        except OSError:
            return set()
    return {candidate.lower()}


def _read_network_reachability_summary(
    workspace_dir: str,
    domains_dir: str,
    domain: str,
) -> dict[str, object]:
    """Return the persisted network reachability summary for one domain."""
    report_path = Path(
        domain_subpath(
            workspace_dir,
            domains_dir,
            domain,
            "network_reachability_report.json",
        )
    )
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return {}
    summary = payload.get("summary", {}) if isinstance(payload, dict) else {}
    return summary if isinstance(summary, dict) else {}


def consume_service_targeting_fallback_notice(
    shell: Any,
    *,
    workspace_dir: str,
    domains_dir: str,
    domain: str,
    service: str,
    source: str,
) -> str | None:
    """Return one fallback-targeting notice once per domain/service/source.

    The notice is emitted only when service-specific host discovery was not
    performed earlier, forcing a fallback to broader host lists.
    """
    normalized_service = str(service or "").strip().lower()
    normalized_source = str(source or "").strip().lower()
    if normalized_source.startswith(f"{normalized_service}_ips"):
        return None

    summary = _read_network_reachability_summary(workspace_dir, domains_dir, domain)
    if bool(summary.get("important_port_scan_performed")):
        return None

    notice_key = (str(domain).lower(), normalized_service, normalized_source)
    seen = getattr(shell, "_service_targeting_fallback_notices_emitted", None)
    if not isinstance(seen, set):
        seen = set()
        setattr(shell, "_service_targeting_fallback_notices_emitted", seen)
    if notice_key in seen:
        return None
    seen.add(notice_key)

    service_name = normalized_service.upper()
    if normalized_source.startswith("reachable_ips"):
        return (
            f"Service-specific port discovery was skipped or unavailable earlier, so "
            f"ADscan is using current-vantage reachable hosts for {service_name} targeting."
        )
    return (
        f"Service-specific port discovery was skipped or unavailable earlier, so "
        f"ADscan is using the full enabled host scope for {service_name} targeting."
    )


def _is_dev_scope_prompt_enabled(shell: Any) -> bool:
    """Return True when advanced scope UX should be exposed."""
    if str(getattr(shell, "session_command_type", "") or "").strip().lower() == "ci":
        return False
    return os.getenv("ADSCAN_DOCKER_CHANNEL", "").strip().lower() == "dev"


def _scope_option_label(*, scope: str, source: str, count: int, service: str) -> str:
    """Build a short operator-facing label for one scope option."""
    service_name = service.upper()
    if scope == "optimized":
        if source.startswith(f"{service}_ips"):
            return f"{service_name}-open hosts from current vantage ({count} targets, Recommended)"
        if source.startswith("reachable_ips"):
            return f"Current-vantage reachable hosts ({count} targets, Recommended fallback)"
        return f"Full enabled host scope ({count} targets, Recommended fallback)"
    if scope == "reachable":
        return f"Current-vantage reachable hosts ({count} targets)"
    return f"Full enabled host scope ({count} targets)"


def resolve_domain_service_scope_preference(
    shell: Any,
    *,
    workspace_dir: str,
    domains_dir: str,
    domain: str,
    service: str,
    domain_data: dict[str, object] | None = None,
    prompt_title: str,
) -> str:
    """Return the chosen scope preference for one service.

    Production defaults to ``optimized``. In ``--dev`` mode, show the scope
    selector only when multiple scope choices resolve to distinct target sets.
    """
    if not _is_dev_scope_prompt_enabled(shell):
        return "optimized"
    if not hasattr(shell, "_questionary_select"):
        return "optimized"

    domain_info = domain_data or {}
    option_specs: list[tuple[str, str, str | None, set[str]]] = []
    for scope in ("optimized", "reachable", "full"):
        path_value, source = resolve_domain_service_target_file(
            workspace_dir,
            domains_dir,
            domain,
            service=service,
            domain_data=domain_info,
            scope_preference=scope,
        )
        entries = load_target_entries(path_value)
        if not entries:
            continue
        option_specs.append((scope, source, path_value, entries))

    deduped: list[tuple[str, str, str | None, set[str]]] = []
    seen_entry_sets: set[frozenset[str]] = set()
    for spec in option_specs:
        entry_fingerprint = frozenset(spec[3])
        if entry_fingerprint in seen_entry_sets:
            continue
        seen_entry_sets.add(entry_fingerprint)
        deduped.append(spec)

    if len(deduped) <= 1:
        return "optimized"

    labels = [
        _scope_option_label(
            scope=scope,
            source=source,
            count=len(entries),
            service=service,
        )
        for scope, source, _path, entries in deduped
    ]
    selected_idx = shell._questionary_select(  # type: ignore[attr-defined]
        prompt_title,
        labels,
        default_idx=0,
    )
    if not isinstance(selected_idx, int) or selected_idx < 0 or selected_idx >= len(deduped):
        return "optimized"
    return deduped[selected_idx][0]
