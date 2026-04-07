"""Owned privileged escalation helper.

This module provides a small batch helper used by scan phases to quickly check
whether any owned (compromised) principal already has direct privileged access
or belongs to a privileged group, and optionally trigger the existing follow-up
actions (DCSync, enrichment, etc.).

It intentionally reuses ``shell.check_privileged_groups(...)`` as the source of
truth for group-driven follow-ups and keeps the privilege-action UX
centralized in ``adscan.py``.
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
from adscan_internal.principal_utils import is_machine_account
from adscan_internal.services.attack_graph_service import get_owned_domain_usernames
from adscan_internal.services.privileged_group_classifier import (
    resolve_privileged_followup_decision,
)


_WRITABLE_DC_DIRECT_FOLLOWUP_RANK = 500


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

def offer_owned_privileged_escalation(shell: Any, domain: str) -> bool:
    """Check owned principals for privileged access and offer escalation.

    Returns:
        True if a privileged escalation flow was started, otherwise False.
    """
    owned_principals = get_owned_domain_usernames(shell, domain)
    if not owned_principals:
        return False

    creds_map = _get_domain_credentials_map(shell, domain)
    if not creds_map:
        return False

    is_ci = bool(os.getenv("CI") or os.getenv("GITHUB_ACTIONS"))
    interactive = bool(sys.stdin.isatty() and not is_ci)

    marked_domain = mark_sensitive(domain, "domain")
    print_info_verbose(
        f"Checking whether owned principals already have privileged access in {marked_domain}."
    )

    direct_candidates: list[tuple[int, str, str]] = []
    enrichment_candidates: list[str] = []
    for principal in owned_principals:
        credential = creds_map.get(principal)
        if not isinstance(credential, str) or not credential.strip():
            continue

        if is_machine_account(principal):
            try:
                dc_role = shell.get_user_dc_role(domain, principal)
            except Exception as exc:  # pragma: no cover - best effort
                print_info_debug(
                    "[owned-priv] machine-role check failed for "
                    f"{mark_sensitive(principal, 'user')}: {exc}"
                )
                dc_role = "not_dc"

            if dc_role == "writable_dc":
                direct_candidates.append(
                    (_WRITABLE_DC_DIRECT_FOLLOWUP_RANK, principal, "writable_dc")
                )
                break

        try:
            membership = shell.check_privileged_groups(
                domain, principal, credential, execute_actions=False
            )
        except Exception as exc:  # pragma: no cover - best effort
            print_info_debug(
                "[owned-priv] membership check failed for "
                f"{mark_sensitive(principal, 'user')}: {exc}"
            )
            continue

        if not isinstance(membership, dict) or not membership:
            continue

        decision = resolve_privileged_followup_decision(membership)
        if not decision.has_actionable_membership:
            continue
        if decision.skip_attack_path_search:
            direct_candidates.append(
                (decision.highest_rank, principal, "privileged_group")
            )
        elif decision.should_run_enrichment_followup:
            enrichment_candidates.append(principal)
        if decision.highest_rank >= 400:
            break

    for principal in enrichment_candidates:
        credential = creds_map.get(principal)
        if not isinstance(credential, str) or not credential.strip():
            continue
        shell.check_privileged_groups(
            domain, principal, credential, execute_actions=True
        )

    if not direct_candidates:
        return False

    # Prefer the centralized privileged follow-up priority.
    direct_candidates.sort(key=lambda item: (-int(item[0]), str(item[1]).lower()))

    for _, principal, reason in direct_candidates:
        marked_principal = mark_sensitive(principal, "user")
        if reason == "writable_dc":
            print_warning(
                f"Owned machine account {marked_principal} appears to be a writable Domain Controller in {marked_domain}."
            )
            prompt = (
                "Proceed with privileged escalation checks/actions using "
                f"{marked_principal}?"
            )
        else:
            print_warning(
                f"Owned principal {marked_principal} appears to belong to a privileged group in {marked_domain}."
            )
            prompt = (
                "Proceed with privileged escalation checks/actions using "
                f"{marked_principal}?"
            )
        if interactive and not Confirm.ask(
            prompt,
            default=True,
        ):
            continue

        credential = creds_map.get(principal)
        if not isinstance(credential, str) or not credential.strip():
            continue

        if reason == "writable_dc":
            shell.check_admin_count(domain, principal, credential, logging=True)
        else:
            # Delegate to the centralized privilege handler (it will prompt for actions).
            shell.check_privileged_groups(
                domain, principal, credential, execute_actions=True
            )
        print_info(f"Privileged escalation flow started for {marked_principal}.")
        return True

    return False
