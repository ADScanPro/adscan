"""Helpers for workspace computer lists."""

from __future__ import annotations

from pathlib import Path

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
