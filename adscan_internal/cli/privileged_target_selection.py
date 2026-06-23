"""Helpers for selecting privileged target accounts across multiple workflows.

This module centralizes operator-facing target selection for workflows that
need a privileged account choice, such as ADCS certificate abuse, delegation-
based attacks, and RODC follow-ups. Callers can optionally apply delegation
eligibility filters (e.g. NOT_DELEGATED and Protected Users).
"""

from __future__ import annotations

from typing import Any

from rich.prompt import Prompt

from adscan_internal import print_info_debug, print_warning, telemetry
from adscan_internal.rich_output import mark_sensitive, print_panel
from adscan_internal.services.attack_graph_service import resolve_group_members_by_rid


def _deduplicate_preserving_order(values: list[str]) -> list[str]:
    """Return unique non-empty strings while preserving the original order."""
    seen: set[str] = set()
    result: list[str] = []
    for raw in values:
        value = str(raw or "").strip()
        if not value:
            continue
        lowered = value.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        result.append(value)
    return result


def _select_option_index(
    shell: Any,
    *,
    title: str,
    options: list[str],
    default_idx: int = 0,
) -> int | None:
    """Select one option using the shell questionary selector when available."""
    if not options:
        return None
    selector = getattr(shell, "_questionary_select", None)
    if callable(selector):
        try:
            return selector(title, options, default_idx=default_idx)
        except TypeError:
            return selector(title, options)
    return default_idx


def _resolve_protected_users(shell: Any, domain: str) -> list[str]:
    """Return members of the Protected Users group when snapshot data is available."""
    try:
        resolved = resolve_group_members_by_rid(shell, domain, 525, enabled_only=True)
        if isinstance(resolved, list):
            return _deduplicate_preserving_order([str(item) for item in resolved])
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
    return []


def _render_excluded_candidates_panel(
    *,
    domain: str,
    purpose: str,
    excluded: dict[str, list[str]],
) -> None:
    """Render a concise note explaining why some candidates were excluded."""
    if not excluded:
        return
    lines: list[str] = []
    for username, reasons in excluded.items():
        marked_user = mark_sensitive(username, "user")
        reason_text = ", ".join(sorted(set(reasons)))
        lines.append(f"- {marked_user}: {reason_text}")
    if not lines:
        return
    marked_domain = mark_sensitive(domain, "domain")
    print_panel(
        "\n".join(lines),
        title=f"Excluded Privileged Targets ({marked_domain})",
        subtitle=purpose,
        border_style="yellow",
    )


def _bare_account_key(value: str) -> str:
    """Normalize a principal to a bare lowercased account (drop DOMAIN\\, @realm).

    Mirrors the logon-denied cache key normalization so caller-supplied exclusion
    sets (stored as bare keys) match candidates returned as ``DOMAIN\\user`` or
    ``user@realm`` sAMAccountNames. A trailing ``$`` is preserved (machine vs user).
    """
    v = str(value or "").strip().lower()
    if "\\" in v:
        v = v.rsplit("\\", 1)[-1]
    if "@" in v:
        v = v.split("@", 1)[0]
    return v.strip()


def resolve_privileged_target_candidates(
    shell: Any,
    *,
    domain: str,
    purpose: str,
    require_domain_admin: bool = True,
    exclude_not_delegated: bool = False,
    exclude_protected_users: bool = False,
    exclude_principals: set[str] | None = None,
    exclude_principals_reason: str = "excluded",
    render_excluded_panel: bool = True,
) -> list[str]:
    """Resolve the filtered privileged-target candidate list WITHOUT prompting.

    Single source of the candidate enumeration + exclusion logic shared by
    :func:`resolve_privileged_target_user` (which then prompts) and callers that
    build their own selector — e.g. the RBCD-against-a-DC flow, which prepends
    the DC machine account as the recommended option so the operator sees ONE
    merged prompt instead of two (the generic DA picker followed by a separate
    machine-account-vs-DA selector). Optionally renders the excluded-candidates
    panel as a side effect (disable for fully silent resolution).

    Args:
        shell: Interactive shell object exposing optional LDAP helpers.
        domain: Target domain.
        purpose: Short human-readable purpose shown in the excluded panel.
        require_domain_admin: When True, candidates come from Domain Admins.
        exclude_not_delegated: Exclude users marked as sensitive/non-delegable.
        exclude_protected_users: Exclude members of the Protected Users group.
        exclude_principals: Bare account keys to exclude unconditionally (e.g.
            principals a target has already denied a network logon).
        exclude_principals_reason: Reason shown in the excluded panel.
        render_excluded_panel: When True, render the excluded-candidates panel.

    Returns:
        The filtered candidate usernames, in resolution order.
    """
    marked_domain = mark_sensitive(domain, "domain")
    candidates: list[str] = []

    if require_domain_admin:
        get_admins = getattr(shell, "get_domain_admins", None)
        if callable(get_admins):
            try:
                resolved = get_admins(domain)
                if isinstance(resolved, list):
                    candidates = _deduplicate_preserving_order(
                        [str(item) for item in resolved]
                    )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_warning(
                    f"Could not enumerate Domain Admins for {marked_domain} ({purpose})."
                )

    excluded_reasons: dict[str, list[str]] = {}
    if exclude_not_delegated:
        get_not_delegated = getattr(shell, "get_not_delegated_users", None)
        if callable(get_not_delegated):
            try:
                for user in _deduplicate_preserving_order(
                    [str(item) for item in get_not_delegated(domain) or []]
                ):
                    excluded_reasons.setdefault(user, []).append(
                        "account is sensitive and cannot be delegated"
                    )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)

    if exclude_protected_users:
        for user in _resolve_protected_users(shell, domain):
            excluded_reasons.setdefault(user, []).append("member of Protected Users")

    if exclude_principals:
        _excluded_keys = {
            _bare_account_key(p) for p in exclude_principals if _bare_account_key(p)
        }
        for candidate in candidates:
            if _bare_account_key(candidate) in _excluded_keys:
                excluded_reasons.setdefault(candidate, []).append(
                    exclude_principals_reason
                )

    filtered_candidates = [
        candidate
        for candidate in candidates
        if candidate.lower() not in {name.lower() for name in excluded_reasons}
    ]

    if excluded_reasons and render_excluded_panel:
        _render_excluded_candidates_panel(
            domain=domain,
            purpose=purpose,
            excluded=excluded_reasons,
        )

    return filtered_candidates


def resolve_privileged_target_user(
    shell: Any,
    *,
    domain: str,
    purpose: str,
    require_domain_admin: bool = True,
    exclude_not_delegated: bool = False,
    exclude_protected_users: bool = False,
    exclude_principals: set[str] | None = None,
    exclude_principals_reason: str = "excluded",
) -> str | None:
    """Resolve a privileged target user and let the operator select the final account.

    Args:
        shell: Interactive shell object exposing optional LDAP helpers.
        domain: Target domain.
        purpose: Short human-readable purpose shown in the selector.
        require_domain_admin: When True, candidates come from Domain Admins.
        exclude_not_delegated: Exclude users marked as sensitive/non-delegable.
        exclude_protected_users: Exclude members of the Protected Users group.
        exclude_principals: Bare account keys to exclude unconditionally (e.g.
            principals a target has already denied a network logon — ground truth
            from a prior ST probe, persisted so they are never re-offered).
        exclude_principals_reason: Human-readable reason shown in the excluded
            panel for ``exclude_principals`` entries.

    Returns:
        Selected username, or ``None`` when no valid selection is made.
    """
    marked_domain = mark_sensitive(domain, "domain")
    filtered_candidates = resolve_privileged_target_candidates(
        shell,
        domain=domain,
        purpose=purpose,
        require_domain_admin=require_domain_admin,
        exclude_not_delegated=exclude_not_delegated,
        exclude_protected_users=exclude_protected_users,
        exclude_principals=exclude_principals,
        exclude_principals_reason=exclude_principals_reason,
    )

    if not filtered_candidates:
        print_warning(
            f"Unable to resolve eligible privileged targets for {marked_domain} ({purpose})."
        )
        manual = Prompt.ask(
            (
                f"Specify a privileged username for {marked_domain} "
                "(leave blank to cancel)"
            ),
            default="",
        ).strip()
        if not manual:
            return None
        marked_manual = mark_sensitive(manual, "user")
        print_info_debug(
            f"[privileged-target] Using operator-specified target for {marked_domain}: {marked_manual}"
        )
        return manual

    options = [*filtered_candidates, "Enter manually", "Cancel"]
    selected_idx = _select_option_index(
        shell,
        title=f"Select a privileged account for {marked_domain} ({purpose}):",
        options=options,
        default_idx=0,
    )
    if selected_idx is None:
        return None

    selected = options[selected_idx]
    if selected == "Cancel":
        return None
    if selected == "Enter manually":
        manual = Prompt.ask(
            (
                f"Specify a privileged username for {marked_domain} "
                "(leave blank to cancel)"
            ),
            default="",
        ).strip()
        if not manual:
            return None
        marked_manual = mark_sensitive(manual, "user")
        print_info_debug(
            f"[privileged-target] Using operator-specified target for {marked_domain}: {marked_manual}"
        )
        return manual

    marked_selected = mark_sensitive(selected, "user")
    print_info_debug(
        f"[privileged-target] Selected privileged target for {marked_domain}: {marked_selected}"
    )
    return selected
