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
