"""Owned privileged escalation helper.

This module provides a small batch helper used by scan phases to quickly check
whether any owned (compromised) user already belongs to a privileged group,
and optionally trigger the existing privilege actions (DCSync, etc.).

It intentionally reuses `shell.check_privileged_groups(...)` as the source of
truth and keeps the privileged-group action UX centralized in `adscan.py`.
"""

from __future__ import annotations

import os
import sys
from typing import Any

from rich.prompt import Confirm

from adscan_internal.rich_output import (
    mark_sensitive,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_warning,
)
from adscan_internal.services.attack_graph_service import get_owned_domain_usernames


def _get_domain_credentials_map(shell: Any, domain: str) -> dict[str, str]:
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return {}
    domain_data = domains_data.get(domain)
    if not isinstance(domain_data, dict):
        # Best-effort: try case-insensitive matching (avoid invisible marker mismatch).
        target_norm = str(domain or "").strip().lower()
        for key, value in domains_data.items():
            if not isinstance(key, str) or not isinstance(value, dict):
                continue
            if key.strip().lower() == target_norm:
                domain_data = value
                break
    if not isinstance(domain_data, dict):
        return {}
    creds = domain_data.get("credentials")
    return creds if isinstance(creds, dict) else {}


def _membership_rank(membership: dict[str, object]) -> int:
    """Return an exploitation priority rank from a membership dict."""
    if bool(membership.get("domain_admin")):
        return 3
    if bool(membership.get("Administrators")):
        return 2
    if bool(membership.get("account_operators")):
        return 1
    if bool(membership.get("backup_operators")):
        return 1
    return 0


def offer_owned_privileged_escalation(shell: Any, domain: str) -> bool:
    """Check owned users for privileged group membership and offer escalation.

    Returns:
        True if a privileged escalation flow was started, otherwise False.
    """
    owned_users = get_owned_domain_usernames(shell, domain)
    if not owned_users:
        return False

    creds_map = _get_domain_credentials_map(shell, domain)
    if not creds_map:
        return False

    is_ci = bool(os.getenv("CI") or os.getenv("GITHUB_ACTIONS"))
    interactive = bool(sys.stdin.isatty() and not is_ci)

    marked_domain = mark_sensitive(domain, "domain")
    print_info_verbose(
        f"Checking whether owned users belong to privileged groups in {marked_domain}."
    )

    candidates: list[tuple[int, str]] = []
    for username in owned_users:
        credential = creds_map.get(username)
        if not isinstance(credential, str) or not credential.strip():
            continue

        try:
            membership = shell.check_privileged_groups(
                domain, username, credential, execute_actions=False
            )
        except Exception as exc:  # pragma: no cover - best effort
            print_info_debug(
                f"[owned-priv] membership check failed for {mark_sensitive(username, 'user')}: {exc}"
            )
            continue

        if not isinstance(membership, dict) or not membership:
            continue

        rank = _membership_rank(membership)
        if rank <= 0:
            continue
        candidates.append((rank, username))
        if rank >= 3:
            break

    if not candidates:
        return False

    # Prefer highest rank (Domain Admin > Administrators > Backup Operators).
    candidates.sort(key=lambda item: (-int(item[0]), str(item[1]).lower()))

    for _, username in candidates:
        marked_user = mark_sensitive(username, "user")
        print_warning(
            f"Owned user {marked_user} appears to belong to a privileged group in {marked_domain}."
        )
        if interactive and not Confirm.ask(
            f"Proceed with privileged escalation checks/actions using {marked_user}?",
            default=True,
        ):
            continue

        credential = creds_map.get(username)
        if not isinstance(credential, str) or not credential.strip():
            continue

        # Delegate to the centralized privilege handler (it will prompt for actions).
        shell.check_privileged_groups(
            domain, username, credential, execute_actions=True
        )
        print_info(f"Privileged escalation flow started for {marked_user}.")
        return True

    return False
