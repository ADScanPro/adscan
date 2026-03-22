"""CLI orchestration for password spraying attacks.

This module keeps password spraying *UI + reporting* logic out of the monolith.
The service layer (adscan_internal.spraying) performs the tool execution and basic parsing; this module:
- resolves workspace paths
- prints operation headers
- updates reports + telemetry
- renders Rich tables
- handles user prompts for spraying operations
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional, Protocol

from adscan_internal import (
    print_error,
    print_info,
    print_info_debug,
    print_info_table,
    print_info_verbose,
    print_instruction,
    print_warning,
    print_warning_debug,
    print_warning_verbose,
    telemetry,
)
from adscan_internal.cli.common import build_lab_event_fields
from adscan_internal.rich_output import (
    mark_sensitive,
    print_exception,
    print_panel,
    print_table,
)
from adscan_internal.subprocess_env import command_string_needs_clean_env
from adscan_internal.text_utils import strip_ansi_codes
from adscan_internal.workspaces import domain_relpath, domain_subpath
from adscan_internal.workspaces.computers import (
    count_enabled_computer_accounts,
    has_enabled_computer_list,
    load_enabled_computer_samaccounts,
)
from adscan_internal.integrations.netexec.parsers import (
    parse_netexec_computer_badpwd,
)
from rich.prompt import Confirm, Prompt
from rich.table import Table

# Import from internal spraying module
from adscan_internal.spraying import (
    SprayEligibilityResult,
    build_kerbrute_command,
    build_kerbrute_bruteforce_command,
    build_netexec_computers_query_command,
    build_netexec_pass_pol_command,
    build_netexec_password_spray_command,
    build_netexec_users_command,
    compute_spray_eligibility,
    parse_netexec_lockout_threshold_result,
    parse_netexec_users_badpwd,
    read_user_list,
    safe_log_filename_fragment,
    write_temp_combo_file,
    write_temp_users_file,
)


def _extract_typed_source_steps(source_steps: list[object] | None) -> list[object]:
    """Return only typed credential provenance steps usable by the attack graph."""
    if not source_steps:
        return []
    try:
        from adscan_internal.services.attack_graph_service import CredentialSourceStep
    except Exception:  # noqa: BLE001
        return []
    return [step for step in source_steps if isinstance(step, CredentialSourceStep)]


def _domain_hit_is_hash(shell: object, credential: str) -> bool:
    """Return whether a validated domain credential looks like an NTLM hash."""
    is_hash_fn = getattr(shell, "is_hash", None)
    if callable(is_hash_fn):
        try:
            return bool(is_hash_fn(credential))
        except Exception:  # noqa: BLE001
            pass
    return bool(re.fullmatch(r"[0-9a-fA-F]{32}", str(credential or "").strip()))


def _normalize_validated_domain_hits(
    shell: object, hits: list[dict[str, object]]
) -> list[dict[str, object]]:
    """Deduplicate validated domain hits, preferring plaintext over hashes."""
    deduped: dict[str, dict[str, object]] = {}
    for hit in hits:
        username = str(hit.get("username") or "").strip()
        credential = str(hit.get("credential") or "").strip()
        if not username or not credential:
            continue
        is_hash = bool(hit.get("is_hash", _domain_hit_is_hash(shell, credential)))
        key = username.lower()
        existing = deduped.get(key)
        if existing is None:
            deduped[key] = {
                "username": username,
                "credential": credential,
                "is_hash": is_hash,
            }
            continue
        if bool(existing.get("is_hash")) and not is_hash:
            deduped[key] = {
                "username": username,
                "credential": credential,
                "is_hash": False,
            }
    return sorted(deduped.values(), key=lambda item: str(item.get("username") or "").lower())


def handle_validated_domain_hits_followup(
    shell: SprayShell,
    *,
    domain: str,
    hits: list[dict[str, object]],
    source_steps: list[object] | None = None,
    discovery_label: str = "validated",
) -> bool:
    """Handle post-validation UX for confirmed domain credentials.

    This centralizes the post-hit flow shared by spraying and SAM->Domain reuse:
    store credentials, classify Tier-0/high-value users, offer attack paths, and
    optionally enumerate selected users when no path is available.
    """
    import sys

    from adscan_internal.cli.attack_path_execution import (
        offer_attack_paths_for_execution_for_principals,
    )
    from adscan_internal.services.credential_store_service import CredentialStoreService
    from adscan_internal.services.high_value import (
        UserRiskFlags,
        classify_users_tier0_high_value,
    )
    from adscan_internal.rich_output import BRAND_COLORS, print_panel
    from rich.prompt import Confirm
    from rich.table import Table
    from rich.text import Text

    normalized_hits = _normalize_validated_domain_hits(shell, hits)
    if not normalized_hits:
        return False

    is_interactive = bool(
        sys.stdin.isatty() and not (os.getenv("CI") or os.getenv("GITHUB_ACTIONS"))
    )
    store = CredentialStoreService()

    for hit in normalized_hits:
        user = str(hit.get("username") or "")
        credential = str(hit.get("credential") or "")
        if not user or not credential:
            continue
        store.update_domain_credential(
            domains_data=shell.domains_data,
            domain=domain,
            username=user,
            credential=credential,
            is_hash=bool(hit.get("is_hash")),
        )

    risk_flags_by_user: dict[str, UserRiskFlags] = {}
    try:
        risk_flags_by_user = classify_users_tier0_high_value(
            shell,
            domain=domain,
            usernames=[str(hit.get("username") or "") for hit in normalized_hits],
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            "[domain-hits] Failed to classify validated users as Tier-0/high-value (continuing)."
        )

    privileged_hits = [
        hit
        for hit in normalized_hits
        if (
            risk_flags_by_user.get(
                str(hit.get("username") or "").strip().lower(),
                UserRiskFlags(),
            ).is_tier0
            or risk_flags_by_user.get(
                str(hit.get("username") or "").strip().lower(),
                UserRiskFlags(),
            ).is_high_value
        )
    ]

    if privileged_hits:
        privileged_table = Table(
            title=Text(
                "Privileged Credentials Detected",
                style=f"bold {BRAND_COLORS['warning']}",
            ),
            show_header=True,
            header_style=f"bold {BRAND_COLORS['warning']}",
            show_lines=True,
        )
        privileged_table.add_column("#", style="dim", width=4, justify="right")
        privileged_table.add_column("Username", style="bold")
        privileged_table.add_column("Risk", style="bold")

        for idx, hit in enumerate(privileged_hits, start=1):
            user = str(hit.get("username") or "")
            flags = risk_flags_by_user.get(user.strip().lower(), UserRiskFlags())
            risk_label = "Tier-0" if flags.is_tier0 else "High-Value"
            privileged_table.add_row(str(idx), mark_sensitive(user, "user"), risk_label)

        message = Text()
        message.append(
            "One or more privileged domain credentials were validated.\n\n",
            style="bold yellow",
        )
        message.append(
            "Pivoting with a Tier-0/high-value account is typically the fastest route to domain compromise.\n",
            style="yellow",
        )

        print_panel(
            [message, privileged_table],
            title=Text("Privileged Credentials Found", style="bold yellow"),
            border_style="yellow",
            expand=False,
        )

        pivot_now = (
            Confirm.ask(
                "Do you want to continue with one of these privileged users now?",
                default=True,
            )
            if is_interactive
            else False
        )

        if pivot_now:
            selected = privileged_hits[0]
            if len(privileged_hits) > 1 and hasattr(shell, "_questionary_select"):
                options = [str(hit.get("username") or "") for hit in privileged_hits] + [
                    "Cancel"
                ]
                selected_idx = shell._questionary_select(
                    "Select a privileged user to continue with:",
                    options,
                    default_idx=0,
                )
                if selected_idx is None or selected_idx >= len(options) - 1:
                    selected = privileged_hits[0]
                else:
                    selected = privileged_hits[selected_idx]

            shell.add_credential(
                domain,
                str(selected.get("username") or ""),
                str(selected.get("credential") or ""),
                source_steps=source_steps,
            )
            return True

    principals = [str(hit.get("username") or "") for hit in normalized_hits]
    # Use --all for small spraying results (bounded, affordable); fall back to
    # highvalue-only when there are many principals to avoid expensive traversal.
    _spray_target = "all" if len(principals) <= 15 else "highvalue"
    executed = offer_attack_paths_for_execution_for_principals(
        shell,
        domain,
        max_display=20,
        principals=principals,
        max_depth=10,
        target=_spray_target,
    )
    if executed:
        return True

    marked_domain = mark_sensitive(domain, "domain")
    print_warning(
        f"No attack paths found from {discovery_label} users to high-value targets in {marked_domain}."
    )
    print_info_verbose(
        "Tip: use `attack_paths <domain> owned --all` to include non-high-value targets."
    )

    if not (is_interactive or hasattr(shell, "_questionary_select")):
        auth_state = shell.domains_data.get(domain, {}).get("auth", "")
        if auth_state not in {"auth", "pwned"} and normalized_hits:
            first_hit = normalized_hits[0]
            shell.add_credential(
                domain,
                str(first_hit.get("username") or ""),
                str(first_hit.get("credential") or ""),
                source_steps=source_steps,
                prompt_for_user_privs_after=False,
            )
            return True
        return False

    selection: list[dict[str, object]] = []
    if len(normalized_hits) == 1:
        only_hit = normalized_hits[0]
        if hasattr(shell, "_questionary_select"):
            choice_idx = shell._questionary_select(
                "No attack paths found. Enumerate this user now?",
                ["Enumerate user", "Skip"],
                default_idx=0,
            )
            if choice_idx == 0:
                selection = [only_hit]
        else:
            prompt = (
                "Do you want to enumerate this user now "
                f"({mark_sensitive(str(only_hit.get('username') or ''), 'user')})?"
            )
            if Confirm.ask(prompt, default=True):
                selection = [only_hit]
    else:
        options = ["All users", "Select one user", "Select multiple users", "Skip"]
        if hasattr(shell, "_questionary_select"):
            choice_idx = shell._questionary_select(
                "No attack paths found. Choose users to enumerate now:",
                options,
                default_idx=0,
            )
        else:
            choice_idx = (
                0
                if Confirm.ask(
                    "No attack paths found. Enumerate all users now?",
                    default=False,
                )
                else 3
            )

        if choice_idx == 0:
            selection = normalized_hits
        elif choice_idx == 1:
            user_options = [str(hit.get("username") or "") for hit in normalized_hits] + [
                "Cancel"
            ]
            if hasattr(shell, "_questionary_select"):
                idx = shell._questionary_select(
                    "Select a user to enumerate:",
                    user_options,
                    default_idx=0,
                )
                if idx is not None and idx < len(user_options) - 1:
                    selection = [normalized_hits[idx]]
        elif choice_idx == 2:
            user_options = ["All users"] + [
                str(hit.get("username") or "") for hit in normalized_hits
            ]
            if hasattr(shell, "_questionary_checkbox"):
                selected_values = shell._questionary_checkbox(
                    "Select users to enumerate:",
                    user_options,
                )
                if isinstance(selected_values, list) and selected_values:
                    if "All users" in selected_values:
                        selection = normalized_hits
                    else:
                        requested = {
                            str(item).strip().lower()
                            for item in selected_values
                            if str(item).strip()
                        }
                        selection = [
                            hit
                            for hit in normalized_hits
                            if str(hit.get("username") or "").lower() in requested
                        ]
            if not selection:
                print_warning(
                    "Multi-select prompt cancelled. Please choose a single user instead."
                )
                user_options = [str(hit.get("username") or "") for hit in normalized_hits] + [
                    "Cancel"
                ]
                if hasattr(shell, "_questionary_select"):
                    idx = shell._questionary_select(
                        "Select a user to enumerate:",
                        user_options,
                        default_idx=0,
                    )
                    if idx is not None and idx < len(user_options) - 1:
                        selection = [normalized_hits[idx]]

    if selection:
        for hit in selection:
            shell.add_credential(
                domain,
                str(hit.get("username") or ""),
                str(hit.get("credential") or ""),
                source_steps=source_steps,
                prompt_for_user_privs_after=True,
            )
        return True

    auth_state = shell.domains_data.get(domain, {}).get("auth", "")
    if auth_state not in {"auth", "pwned"} and normalized_hits:
        first_hit = normalized_hits[0]
        shell.add_credential(
            domain,
            str(first_hit.get("username") or ""),
            str(first_hit.get("credential") or ""),
            source_steps=source_steps,
            prompt_for_user_privs_after=False,
        )
        return True
    return False


class SprayShell(Protocol):
    """Minimal shell surface used by the spraying controller."""

    console: object
    domains: list[str]
    domains_dir: str
    kerberos_dir: str
    domain: str | None
    type: str | None
    auto: bool
    scan_mode: str | None
    current_workspace_dir: str | None
    domains_data: dict
    kerbrute_path: str | None
    netexec_path: str | None
    password_spraying_history: dict | None

    def _get_workspace_cwd(self) -> str: ...

    def _questionary_select(
        self, title: str, options: list[str], default_idx: int = 0
    ) -> int | None: ...

    def _questionary_checkbox(
        self,
        title: str,
        options: list[str],
        default_values: list[str] | None = None,
    ) -> list[str] | None: ...

    def do_sync_clock_with_pdc(self, domain: str, verbose: bool = False) -> bool: ...

    def _run_netexec(
        self,
        command: str,
        domain: str | None = None,
        timeout: int | None = None,
        shell: bool = False,
        capture_output: bool = False,
        text: bool = False,
    ) -> subprocess.CompletedProcess[str] | None: ...

    def run_command(
        self, command: str, *, timeout: int | None = None, **kwargs
    ) -> subprocess.CompletedProcess[str] | None: ...

    def add_credential(
        self,
        domain: str,
        user: str,
        cred: str,
        host: str | None = None,
        service: str | None = None,
        skip_hash_cracking: bool = False,
        source_steps: list[object] | None = None,
        prompt_for_user_privs_after: bool = True,
        allow_empty_credential: bool = False,
    ) -> None: ...

    def ask_for_pass_policy(self, domain: str) -> None: ...

    def do_netexec_pass_policy(self, domain: str) -> None: ...


_SPRAYING_UX_STATE_KEY = "_spraying_ux"
_RECOMMENDED_SPRAY_CATEGORIES = {
    "useraspass",
    "useraspass_lower",
    "useraspass_upper",
    "computer_pre2k",
}
_SPRAYING_OPTION_USER_AS_PASS = "Username as password"
_SPRAYING_OPTION_USER_AS_PASS_LOWER = "Username as password in lowercase"
_SPRAYING_OPTION_USER_AS_PASS_UPPER = "Username as password in uppercase"
_SPRAYING_OPTION_BLANK_PASSWORD = "Users with a blank password"
_SPRAYING_OPTION_CUSTOM_PASSWORD = "Username with a specific password"
_SPRAYING_OPTION_COMPUTER_PRE2K = "Computer accounts (pre2k: hostname as password)"
_SPRAYING_OPTION_RETRY_PASSWORDS = "Retry saved password candidates"
_SPRAYING_OPTION_RETRY_DOMAIN_REUSE = "Retry saved SAM -> domain reuse candidates"
_DOMAIN_HASH_SPRAY_LINE_RE = re.compile(
    r"^\s*SMB\s+\S+\s+\d+\s+\S+\s+\[(?P<status>[^\]]+)\]\s+(?P<rest>.*)$"
)
_DOMAIN_SPRAY_FAILURE_CODE_RE = re.compile(
    r"\b(?P<code>(?:STATUS|NT_STATUS|KDC_ERR)_[A-Z0-9_]+)\b"
)
_NETEXEC_POLICY_QUERY_MAX_ATTEMPTS = 3
_DEFAULT_MULTI_SPRAY_RESERVE = 2
_MAX_MULTI_SPRAY_PREVIEW = 10


@dataclass(frozen=True, slots=True)
class PendingSprayPasswordCandidate:
    """Persisted password candidate awaiting a later spraying attempt."""

    password: str
    reason_not_sprayed: str
    deferred_at: str
    source: dict[str, object]


@dataclass(frozen=True, slots=True)
class DomainReuseValidationCandidate:
    """One SAM-derived credential variant eligible for domain reuse validation."""

    credential: str
    credential_type: str
    accounts: list[str]
    source_hostnames: list[str]


@dataclass(frozen=True, slots=True)
class PendingDomainReuseValidationCandidate:
    """Persisted SAM-derived credential variant awaiting later domain validation."""

    credential: str
    credential_type: str
    accounts: list[str]
    source_hostnames: list[str]
    source_scope: str
    reason_not_validated: str
    deferred_at: str


def _run_netexec_query_with_parse_retry(
    shell: SprayShell,
    *,
    command: str,
    domain: str,
    query_label: str,
    parse_ok: Callable[[str], bool],
    timeout: int = 300,
) -> subprocess.CompletedProcess[str] | None:
    """Run a NetExec query and retry when output is present but not parseable."""
    def _drop_kerberos_flag(cmd: str) -> tuple[str, bool]:
        try:
            argv = shlex.split(cmd)
        except ValueError:
            return cmd, False
        filtered: list[str] = []
        removed = False
        for token in argv:
            if not removed and token == "-k":
                removed = True
                continue
            filtered.append(token)
        if not removed:
            return cmd, False
        return shlex.join(filtered), True

    last_proc: subprocess.CompletedProcess[str] | None = None
    current_command = command
    kerberos_fallback_used = False
    for attempt in range(1, _NETEXEC_POLICY_QUERY_MAX_ATTEMPTS + 1):
        proc = shell._run_netexec(
            current_command,
            domain=domain,
            timeout=timeout,
            shell=True,
            capture_output=True,
            text=True,
        )
        last_proc = proc
        stdout = strip_ansi_codes(getattr(proc, "stdout", "") or "")
        if stdout and parse_ok(stdout):
            if attempt > 1:
                print_info_debug(
                    f"[eligibility] {query_label} output became parseable on retry "
                    f"{attempt}/{_NETEXEC_POLICY_QUERY_MAX_ATTEMPTS}."
                )
            return proc
        if not kerberos_fallback_used:
            ntlm_command, removed_kerberos = _drop_kerberos_flag(current_command)
            if removed_kerberos:
                kerberos_fallback_used = True
                current_command = ntlm_command
                if attempt < _NETEXEC_POLICY_QUERY_MAX_ATTEMPTS:
                    print_warning_debug(
                        f"{query_label} output was empty or not parseable while using "
                        f"Kerberos (attempt {attempt}/{_NETEXEC_POLICY_QUERY_MAX_ATTEMPTS}). "
                        "Retrying with NTLM fallback."
                    )
                    continue
        if attempt < _NETEXEC_POLICY_QUERY_MAX_ATTEMPTS:
            print_warning_debug(
                f"{query_label} output was empty or not parseable "
                f"(attempt {attempt}/{_NETEXEC_POLICY_QUERY_MAX_ATTEMPTS}). Retrying."
            )
    return last_proc


def _get_spraying_ux_state(shell: SprayShell, domain: str) -> dict[str, object]:
    """Return mutable UX state for spraying prompts in the given domain."""
    domain_state = shell.domains_data.get(domain)
    if not isinstance(domain_state, dict):
        domain_state = {}
        shell.domains_data[domain] = domain_state
    ux_state = domain_state.get(_SPRAYING_UX_STATE_KEY)
    if not isinstance(ux_state, dict):
        ux_state = {}
        domain_state[_SPRAYING_UX_STATE_KEY] = ux_state
    return ux_state


def _capture_spraying_ux_event(
    shell: SprayShell,
    event: str,
    domain: str,
    *,
    extra: dict[str, object] | None = None,
) -> None:
    """Best-effort telemetry capture for spraying UX events."""
    try:
        properties: dict[str, object] = {
            "domain": domain,
            "workspace_type": getattr(shell, "type", None),
            "scan_mode": getattr(shell, "scan_mode", None),
            "auto_mode": getattr(shell, "auto", False),
        }
        if extra:
            properties.update(extra)
        properties.update(build_lab_event_fields(shell=shell, include_slug=True))
        telemetry.capture(event, properties)
    except Exception as exc:  # pragma: no cover - telemetry must not break UX
        telemetry.capture_exception(exc)


def _mark_recommended_spraying_attempt(
    shell: SprayShell, domain: str, category: str
) -> None:
    """Record that a recommended CTF spraying technique was attempted."""
    ux_state = _get_spraying_ux_state(shell, domain)
    attempted = ux_state.get("recommended_attempted_categories")
    if not isinstance(attempted, list):
        attempted = []
        ux_state["recommended_attempted_categories"] = attempted
    if category not in attempted:
        attempted.append(category)


def _has_recommended_spraying_attempt(shell: SprayShell, domain: str) -> bool:
    """Return True when a recommended spray type was already attempted."""
    ux_state = _get_spraying_ux_state(shell, domain)
    attempted = ux_state.get("recommended_attempted_categories")
    if not isinstance(attempted, list):
        return False
    return any(str(item) in _RECOMMENDED_SPRAY_CATEGORIES for item in attempted)


def _get_enabled_computer_account_count(shell: SprayShell, domain: str) -> int | None:
    """Return the enabled computer count for the domain, or None when unavailable."""

    workspace_cwd = shell.current_workspace_dir or os.getcwd()
    try:
        count = count_enabled_computer_accounts(workspace_cwd, shell.domains_dir, domain)
    except OSError as exc:
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            "[spray] Unable to count enabled computers for "
            f"{marked_domain}: {mark_sensitive(str(exc), 'detail')}"
        )
        return None

    marked_domain = mark_sensitive(domain, "domain")
    print_info_debug(
        f"[spray] enabled computer count for {marked_domain}: {count}"
    )
    return count


def _should_recommend_pre2k_for_ctf(shell: SprayShell, domain: str) -> bool:
    """Return True when pre2k is a meaningful recommendation in a CTF workspace."""

    count = _get_enabled_computer_account_count(shell, domain)
    if count is None:
        print_info_debug(
            "[spray] pre2k recommendation gate: enabled computer count unavailable; "
            "keeping recommendation enabled."
        )
        return True
    if count <= 1:
        print_info_debug(
            "[spray] pre2k recommendation gate: disabled because there is "
            f"only {count} enabled computer account."
        )
        return False
    print_info_debug(
        "[spray] pre2k recommendation gate: enabled because there are "
        f"{count} enabled computer accounts."
    )
    return True


def maybe_offer_ctf_pre2k_followup(shell: SprayShell, domain: str, *, reason: str) -> None:
    """Offer a premium CTF follow-up to run only pre2k when it was skipped so far."""

    if str(getattr(shell, "type", "") or "").strip().lower() != "ctf":
        return
    if shell.domains_data.get(domain, {}).get("auth") == "pwned":
        return
    if not _should_recommend_pre2k_for_ctf(shell, domain):
        return

    history = get_password_spraying_history(shell)
    domain_history = history.get(domain, {})
    if isinstance(domain_history.get("computer_pre2k"), dict):
        print_info_debug(
            "[spray] premium pre2k follow-up skipped because computer_pre2k "
            "was already attempted."
        )
        return

    ux_state = _get_spraying_ux_state(shell, domain)
    repeat_on_explicit_user_skip = reason in {
        "ask_for_spraying_declined",
        "spraying_menu_cancelled",
    }
    if bool(ux_state.get("pre2k_followup_prompted", False)) and not repeat_on_explicit_user_skip:
        print_info_debug(
            "[spray] premium pre2k follow-up already shown in this session."
        )
        return

    marked_domain = mark_sensitive(domain, "domain")
    print_panel(
        "\n".join(
            [
                f"Domain: {marked_domain}",
                "Computer pre2k spraying has not been attempted yet.",
                "In many CTFs this is the intended foothold path when multiple computer accounts exist.",
                "",
                "Recommended focused action:",
                "Run only the pre2k computer check now.",
            ]
        ),
        title="[bold yellow]Recommended CTF Follow-up: Pre2k[/bold yellow]",
        border_style="yellow",
        expand=False,
    )
    ux_state["pre2k_followup_prompted"] = True
    _capture_spraying_ux_event(
        shell,
        "ctf_pre2k_followup_prompted",
        domain,
        extra={"reason": reason},
    )

    if getattr(shell, "auto", False):
        print_info_debug(
            "[spray] auto mode active; not prompting for premium pre2k follow-up."
        )
        return

    if Confirm.ask(
        "Do you want to run only the computer pre2k check now?",
        default=True,
    ):
        _capture_spraying_ux_event(
            shell,
            "ctf_pre2k_followup_accepted",
            domain,
            extra={"reason": reason},
        )
        do_computer_pre2k_spraying(shell, domain)
    else:
        _capture_spraying_ux_event(
            shell,
            "ctf_pre2k_followup_declined",
            domain,
            extra={"reason": reason},
        )


def maybe_show_ctf_spraying_recommendation(
    shell: SprayShell,
    domain: str,
    *,
    reason: str,
) -> None:
    """Show one-time CTF recommendation when no recommended spraying was attempted."""
    if str(getattr(shell, "type", "") or "").strip().lower() != "ctf":
        return
    if shell.domains_data.get(domain, {}).get("auth") == "pwned":
        return
    if _has_recommended_spraying_attempt(shell, domain):
        return
    if not _should_recommend_pre2k_for_ctf(shell, domain):
        print_info_debug(
            "[spray] skipping CTF spraying recommendation because pre2k does not "
            "add value with <= 1 enabled computer account."
        )
        return

    ux_state = _get_spraying_ux_state(shell, domain)
    if bool(ux_state.get("recommended_hint_shown", False)):
        return

    marked_domain = mark_sensitive(domain, "domain")
    panel_lines = [
        f"Domain: {marked_domain}",
        "In many HTB/CTF environments, a first foothold comes from spraying.",
        "",
        "High-value quick checks:",
        "1) Computer accounts (pre2k: hostname as password)",
        "2) Username as password (normal/lower/upper variants)",
        "",
        f"Run now: spraying {domain}",
    ]
    print_panel(
        "\n".join(panel_lines),
        title="[bold yellow]Recommended CTF Next Step[/bold yellow]",
        border_style="yellow",
        expand=False,
    )
    print_instruction(
        "If you skip spraying in CTF, you can miss the intended foothold path."
    )
    ux_state["recommended_hint_shown"] = True
    _capture_spraying_ux_event(
        shell,
        "ctf_spraying_recommendation_shown",
        domain,
        extra={"reason": reason},
    )


def _ensure_spraying_clock_sync(shell: SprayShell, domain: str, *, source: str) -> bool:
    """Ensure clock sync before spraying and emit consistent diagnostics on failure."""
    marked_domain = mark_sensitive(domain, "domain")
    print_info_debug(f"[spray] Clock sync requested ({source}) for {marked_domain}")
    if shell.do_sync_clock_with_pdc(domain, verbose=True):
        print_info_debug(f"[spray] Clock sync succeeded ({source}) for {marked_domain}")
        return True

    print_warning(
        "Clock synchronization failed; skipping password spraying for this attempt."
    )
    print_instruction(
        "Retry after fixing clock sync (or run `sync-clock <domain>`), then run spraying again."
    )
    print_info_debug(f"[spray] Clock sync failed ({source}) for {marked_domain}")
    _capture_spraying_ux_event(
        shell,
        "spraying_aborted_clock_sync_failed",
        domain,
        extra={"source": source},
    )
    return False


def _build_domain_reuse_eligibility(
    shell: SprayShell,
    *,
    domain: str,
) -> SprayEligibilityResult | None:
    """Return eligibility list used by SAM -> domain reuse validations."""
    auth_state = str(shell.domains_data[domain].get("auth", "")).strip().lower()
    requires_auth_users = auth_state in {"auth", "pwned"}
    user_list_rel = get_spraying_user_list_path(
        shell,
        domain,
        requires_auth_users=requires_auth_users,
    )
    if not user_list_rel:
        return None
    workspace_cwd = shell.current_workspace_dir or os.getcwd()
    user_list_file = domain_subpath(
        workspace_cwd,
        shell.domains_dir,
        domain,
        os.path.basename(user_list_rel),
    )
    auth_state = str(shell.domains_data[domain].get("auth", "")).strip().lower()
    safe_threshold = 2 if auth_state in {"auth", "pwned"} else 0
    eligibility = compute_spraying_eligibility(
        shell,
        domain=domain,
        user_list_file=user_list_file,
        safe_threshold=safe_threshold,
    )
    if eligibility is None:
        return None
    print_spraying_eligibility(shell, domain, eligibility)
    default_confirm = shell.type == "ctf"
    if not _enforce_lockout_guardrail(
        domain=domain,
        eligibility=eligibility,
        prompt_text=(
            "Continue with SAM-to-domain reuse validation using the full user list?"
        ),
        default_confirm=default_confirm,
    ):
        return None
    if not eligibility.eligible_users:
        print_warning(
            "No eligible users available for domain reuse validation with current safety rules."
        )
        return None
    return eligibility


def _summarize_domain_spray_outcomes(log_text: str) -> tuple[list[str], dict[str, int]]:
    """Parse NetExec SMB spray output for successful usernames and failure codes."""
    hits_by_user: dict[str, str] = {}
    outcome_counts: dict[str, int] = {}
    if not log_text:
        return [], outcome_counts

    def _extract_username(rest: str) -> str:
        account_token = str(rest or "").split(":", 1)[0].strip()
        return account_token.split("\\")[-1].split("@", 1)[0].strip()

    for raw_line in log_text.splitlines():
        line = strip_ansi_codes(raw_line)
        parsed = _DOMAIN_HASH_SPRAY_LINE_RE.match(line)
        if not parsed and "SMB " in line:
            smb_idx = line.find("SMB ")
            if smb_idx > 0:
                parsed = _DOMAIN_HASH_SPRAY_LINE_RE.match(line[smb_idx:])
        if not parsed:
            continue

        status = str(parsed.group("status") or "").strip()
        rest = str(parsed.group("rest") or "").strip()
        if not rest:
            continue

        if status == "+":
            username = _extract_username(rest)
            if not username:
                continue
            hits_by_user.setdefault(username.lower(), username)
            outcome_counts["SUCCESS"] = int(outcome_counts.get("SUCCESS", 0)) + 1
            continue

        failure_match = _DOMAIN_SPRAY_FAILURE_CODE_RE.search(rest)
        if failure_match:
            code = str(failure_match.group("code") or "").upper()
            if code:
                if code in {"STATUS_PASSWORD_MUST_CHANGE", "KDC_ERR_KEY_EXPIRED"}:
                    username = _extract_username(rest)
                    if username:
                        hits_by_user.setdefault(username.lower(), username)
                outcome_counts[code] = int(outcome_counts.get(code, 0)) + 1
                continue
        if "connection error" in rest.lower():
            outcome_counts["CONNECTION_ERROR"] = (
                int(outcome_counts.get("CONNECTION_ERROR", 0)) + 1
            )
            continue
        outcome_counts["OTHER_FAILURE"] = (
            int(outcome_counts.get("OTHER_FAILURE", 0)) + 1
        )

    return sorted(hits_by_user.values(), key=str.lower), outcome_counts


def _summarize_outcomes_for_table(
    outcomes: dict[str, int],
    *,
    limit: int = 3,
    excluded_codes: set[str] | None = None,
) -> str:
    """Render compact top-N outcome summary for UX tables."""
    if not outcomes:
        return "-"
    excluded = {str(code).upper() for code in (excluded_codes or set())}
    normalized: dict[str, int] = {}
    for raw_code, raw_count in outcomes.items():
        code = str(raw_code or "").strip().upper()
        if not code or code in excluded:
            continue
        normalized[code] = int(normalized.get(code, 0)) + int(raw_count or 0)
    if not normalized:
        return "-"
    ordered = sorted(normalized.items(), key=lambda item: (-item[1], item[0]))
    summary = ", ".join(f"{code}={count}" for code, count in ordered[:limit])
    if len(ordered) > limit:
        summary += f", +{len(ordered) - limit} more"
    return summary


def _render_valid_spray_hits_panel(
    hits: list[dict[str, str]],
    *,
    spray_type: str | None,
) -> None:
    """Render a concise panel listing the discovered spray hits."""
    from adscan_internal.rich_output import BRAND_COLORS, print_panel
    from rich.table import Table
    from rich.text import Text

    table = Table(
        title=Text(
            "Valid Credentials Found", style=f"bold {BRAND_COLORS['info']}"
        ),
        show_header=True,
        header_style=f"bold {BRAND_COLORS['info']}",
        show_lines=True,
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Username", style="bold")
    table.add_column("Method", style="dim")
    table.add_column("Accepted Secret", style="yellow")

    hits_sorted = sorted(
        hits, key=lambda item: str(item.get("username", "")).lower()
    )
    for idx, hit in enumerate(hits_sorted[:10], start=1):
        user = str(hit.get("username") or "")
        password = str(hit.get("password") or "")
        accepted_secret = (
            "Blank password"
            if spray_type == "Blank Password" or password == ""
            else "Password accepted"
        )
        table.add_row(
            str(idx),
            mark_sensitive(user, "user"),
            spray_type or "Password spray",
            accepted_secret,
        )

    if len(hits_sorted) > 10:
        print_warning(
            f"Showing 10/{len(hits_sorted)} valid credentials. Use `creds show` to see stored credentials."
        )

    print_panel(
        [table],
        title=Text(
            f"Spraying Results ({len(hits_sorted)} success{'es' if len(hits_sorted) != 1 else ''})",
            style=f"bold {BRAND_COLORS['info']}",
        ),
        border_style=BRAND_COLORS["info"],
        expand=False,
    )
    if spray_type == "Blank Password":
        print_info(
            "These hits authenticated with a blank password. ADscan will treat them as explicit blank-password credentials."
        )


def _persist_and_record_spray_hits(
    shell: SprayShell,
    *,
    domain: str,
    hits: list[dict[str, str]],
    spray_type: str | None,
    entry_label: str | None,
    source_context: dict[str, object] | None,
    source_steps: list[object] | None,
    persist_via_add_credential: bool = False,
    allow_empty_credential: bool = False,
) -> None:
    """Persist spray hits and record related attack-graph provenance."""
    from adscan_internal.services.attack_graph_service import (
        record_credential_source_steps,
        upsert_domain_password_reuse_edges,
        upsert_password_spray_entry_edge,
        upsert_share_password_entry_edge,
    )
    from adscan_internal.services.share_credential_provenance_service import (
        ShareCredentialProvenanceService,
    )

    typed_source_steps = _extract_typed_source_steps(source_steps)
    share_provenance_service = ShareCredentialProvenanceService()
    share_edge_payload = share_provenance_service.build_share_password_edge_payload(
        source_context=source_context,
        spray_type=spray_type,
        verified_via="spraying",
    )
    hits_sorted = sorted(
        hits, key=lambda item: str(item.get("username", "")).lower()
    )

    grouped_hits: dict[str, set[str]] = {}
    for hit in hits_sorted:
        username = str(hit.get("username") or "").strip()
        credential = str(hit.get("password") or "")
        if not username:
            continue
        grouped_hits.setdefault(credential.lower(), set()).add(username)

    evidence_source = "password_spraying"
    if isinstance(source_context, dict):
        origin = str(source_context.get("origin") or "").strip().lower()
        if origin:
            evidence_source = f"password_spraying:{origin}"

    domain_reuse_created = 0
    for hit in hits_sorted:
        username = str(hit.get("username") or "").strip()
        credential = str(hit.get("password") or "")
        if not username:
            continue
        grouped = grouped_hits.get(credential.lower())
        if not grouped:
            continue
        targets = sorted(grouped, key=str.lower)
        if len(targets) < 2:
            grouped_hits.pop(credential.lower(), None)
            continue
        domain_reuse_created += int(
            upsert_domain_password_reuse_edges(
                shell,
                domain,
                source_usernames=targets,
                target_usernames=targets,
                credential=credential,
                status="discovered",
                evidence_source=evidence_source,
            )
            or 0
        )
        grouped_hits.pop(credential.lower(), None)
    if domain_reuse_created > 0:
        print_info_debug(
            f"[spray] Recorded {domain_reuse_created} DomainPassReuse edge(s)."
        )

    spray_type_label = spray_type or "Custom Password"
    should_record_spray_edge = (
        spray_type_label.startswith("Username as Password")
        or spray_type_label == "Blank Password"
        or spray_type_label == "Computer Pre2k"
    )

    for hit in hits_sorted:
        username = str(hit.get("username") or "")
        password = str(hit.get("password") or "")
        if typed_source_steps:
            try:
                record_credential_source_steps(
                    shell,
                    domain,
                    username=username,
                    steps=typed_source_steps,
                    status="success",
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_info_debug(
                    "[spray] Failed to record inherited credential provenance "
                    "steps in attack graph (continuing)."
                )
        if should_record_spray_edge and not typed_source_steps:
            try:
                upsert_password_spray_entry_edge(
                    shell,
                    domain,
                    username=username,
                    password=password,
                    spray_type=spray_type,
                    spray_category=_normalize_spray_type_key(spray_type),
                    status="success",
                    entry_label=entry_label or "Domain Users",
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_info_debug(
                    "[spray] Failed to record spray entry edge in attack graph (continuing)."
                )
        if share_edge_payload:
            try:
                share_entry_label, share_notes = share_edge_payload
                share_notes = dict(share_notes)
                if password or allow_empty_credential:
                    share_notes["password"] = password
                upsert_share_password_entry_edge(
                    shell,
                    domain,
                    username=username,
                    entry_label=share_entry_label,
                    status="success",
                    notes=share_notes,
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_info_debug(
                    "[spray] Failed to record PasswordInShare edge (continuing)."
                )

    if persist_via_add_credential:
        for hit in hits_sorted:
            username = str(hit.get("username") or "").strip()
            password = str(hit.get("password") or "")
            if not username:
                continue
            shell.add_credential(
                domain,
                username,
                password,
                source_steps=source_steps,
                prompt_for_user_privs_after=True,
                allow_empty_credential=allow_empty_credential,
            )
        return

    handle_validated_domain_hits_followup(
        shell,
        domain=domain,
        hits=[
            {
                "username": str(hit.get("username") or ""),
                "credential": str(hit.get("password") or ""),
                "is_hash": False,
            }
            for hit in hits_sorted
        ],
        source_steps=source_steps,
        discovery_label="sprayed",
    )


def validate_domain_reuse_with_ntlm_hash(
    shell: SprayShell,
    *,
    domain: str,
    nt_hash: str,
    eligibility: SprayEligibilityResult | None = None,
) -> dict[str, object]:
    """Validate SAM-derived credential reuse against domain accounts using NTLM hash spray."""
    from adscan_internal.cli.kerberos import ensure_kerberos_output_dir
    from adscan_internal.services.credential_store_service import CredentialStoreService

    normalized_hash = str(nt_hash or "").strip()
    marked_domain = mark_sensitive(domain, "domain")
    result: dict[str, object] = {
        "status": "error",
        "method": "netexec_ntlm_hash",
        "credential_type": "hash",
        "credential": normalized_hash,
        "attempted_users": 0,
        "hits": [],
        "outcome_counts": {},
        "error": None,
    }

    if not getattr(shell, "netexec_path", None):
        message = "NetExec is not configured."
        print_warning(f"Skipping domain reuse validation in {marked_domain}: {message}")
        result["error"] = message
        return result
    if not re.fullmatch(r"[0-9a-fA-F]{32}", normalized_hash):
        message = "Credential is not a valid NTLM hash."
        print_warning(f"Skipping domain reuse validation in {marked_domain}: {message}")
        result["error"] = message
        return result

    effective_eligibility = eligibility or _build_domain_reuse_eligibility(
        shell, domain=domain
    )
    if effective_eligibility is None:
        result["status"] = "skipped"
        return result

    result["attempted_users"] = len(effective_eligibility.eligible_users)
    kerberos_output_dir = ensure_kerberos_output_dir(shell, domain)
    temp_users_path = write_temp_users_file(
        list(effective_eligibility.eligible_users),
        directory=kerberos_output_dir,
    )
    workspace_cwd = shell.current_workspace_dir or os.getcwd()
    log_rel = domain_relpath(
        shell.domains_dir,
        domain,
        "smb",
        f"sam_domain_hash_spray_{safe_log_filename_fragment(normalized_hash, max_length=16)}.log",
    )
    log_abs = domain_subpath(
        workspace_cwd,
        shell.domains_dir,
        domain,
        "smb",
        f"sam_domain_hash_spray_{safe_log_filename_fragment(normalized_hash, max_length=16)}.log",
    )
    os.makedirs(os.path.dirname(log_abs), exist_ok=True)
    command = (
        f"{shell.netexec_path} smb {shell.domains_data[domain]['pdc']} "
        f"-u {shlex.quote(temp_users_path)} -H {shlex.quote(normalized_hash)} "
        f"-d {shlex.quote(domain)} --log {shlex.quote(log_rel)}"
    )
    print_info_debug(f"[sam-domain-reuse] Hash spray command: {command}")

    try:
        completed = shell.run_command(
            command,
            timeout=1200,
            shell=True,
            capture_output=True,
            text=True,
            use_clean_env=command_string_needs_clean_env(command),
        )
        stdout_text = str(getattr(completed, "stdout", "") or "") if completed else ""
        stderr_text = str(getattr(completed, "stderr", "") or "") if completed else ""
        log_text = ""
        if os.path.exists(log_abs):
            try:
                with open(log_abs, "r", encoding="utf-8", errors="ignore") as handle:
                    log_text = handle.read()
            except OSError as exc:
                telemetry.capture_exception(exc)

        hits, outcomes = _summarize_domain_spray_outcomes(
            "\n".join(text for text in (stdout_text, stderr_text, log_text) if text)
        )
        result["hits"] = hits
        result["outcome_counts"] = outcomes
        store = CredentialStoreService()
        for username in hits:
            store.update_domain_credential(
                domains_data=shell.domains_data,
                domain=domain,
                username=username,
                credential=normalized_hash,
                is_hash=True,
            )

        result["status"] = "success" if hits else "no_hits"
        return result
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        result["error"] = str(exc)
        return result
    finally:
        try:
            os.remove(temp_users_path)
        except OSError:
            pass


def validate_domain_reuse_with_password(
    shell: SprayShell,
    *,
    domain: str,
    password: str,
    eligibility: SprayEligibilityResult | None = None,
) -> dict[str, object]:
    """Validate SAM-derived credential reuse against domain accounts using Kerberos spray."""
    from adscan_internal.cli.kerberos import ensure_kerberos_output_dir
    from adscan_internal.services.credential_service import CredentialService
    from adscan_internal.services.credential_store_service import CredentialStoreService

    clear_password = str(password or "").strip()
    marked_domain = mark_sensitive(domain, "domain")
    result: dict[str, object] = {
        "status": "error",
        "method": "kerbrute_password",
        "credential_type": "password",
        "credential": clear_password,
        "attempted_users": 0,
        "hits": [],
        "outcome_counts": {},
        "error": None,
    }
    if not clear_password:
        result["error"] = "Empty password."
        return result
    if not getattr(shell, "kerbrute_path", None):
        message = "Kerbrute is not configured."
        print_warning(f"Skipping domain reuse validation in {marked_domain}: {message}")
        result["error"] = message
        return result

    effective_eligibility = eligibility or _build_domain_reuse_eligibility(
        shell, domain=domain
    )
    if effective_eligibility is None:
        result["status"] = "skipped"
        return result
    result["attempted_users"] = len(effective_eligibility.eligible_users)

    kerberos_output_dir = ensure_kerberos_output_dir(shell, domain)
    temp_users_path = write_temp_users_file(
        list(effective_eligibility.eligible_users),
        directory=kerberos_output_dir,
    )
    output_file = os.path.join(
        "domains",
        domain,
        "kerberos",
        f"sam_domain_password_spray_{safe_log_filename_fragment(clear_password)}.log",
    )
    command = build_kerbrute_command(
        kerbrute_path=shell.kerbrute_path,
        domain=domain,
        dc_ip=shell.domains_data[domain]["pdc"],
        users_file=temp_users_path,
        output_file=output_file,
        password=clear_password,
        user_as_pass=False,
    )
    print_info_debug(f"[sam-domain-reuse] Password spray command: {command}")

    try:
        service = CredentialService()

        def _executor(cmd: str, timeout: int | None) -> object:
            return shell.run_command(
                cmd,
                timeout=timeout,
                shell=True,
                capture_output=True,
                text=True,
                use_clean_env=command_string_needs_clean_env(cmd),
            )

        spray_result = service.execute_password_spraying(
            command=command,
            domain=domain,
            executor=_executor,
        )
        hit_entries = spray_result.get("credentials", [])
        if not isinstance(hit_entries, list):
            hit_entries = []
        hits: list[str] = []
        for item in hit_entries:
            if not isinstance(item, dict):
                continue
            username = str(item.get("username") or "").strip()
            if not username:
                continue
            hits.append(username)

        deduped_hits = sorted(
            {user.lower(): user for user in hits}.values(), key=str.lower
        )
        result["hits"] = deduped_hits
        outcomes = _summarize_domain_spray_outcomes(
            "\n".join(
                [
                    str(spray_result.get("stdout") or ""),
                    str(spray_result.get("stderr") or ""),
                ]
            )
        )[1]
        result["outcome_counts"] = outcomes
        store = CredentialStoreService()
        for username in deduped_hits:
            store.update_domain_credential(
                domains_data=shell.domains_data,
                domain=domain,
                username=username,
                credential=clear_password,
                is_hash=False,
            )
        result["status"] = "success" if deduped_hits else "no_hits"
        return result
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        result["error"] = str(exc)
        return result
    finally:
        try:
            os.remove(temp_users_path)
        except OSError:
            pass


def validate_selected_domain_reuse_candidates(
    shell: SprayShell,
    *,
    domain: str,
    candidates: list[DomainReuseValidationCandidate],
    eligibility: SprayEligibilityResult,
) -> tuple[list[dict[str, object]], dict[str, dict[str, object]], list[dict[str, object]]]:
    """Validate selected SAM-derived credential variants against the domain."""
    result_rows: list[dict[str, object]] = []
    domain_results_by_credential: dict[str, dict[str, object]] = {}
    validated_domain_hits: list[dict[str, object]] = []

    for candidate in candidates:
        credential = str(candidate.credential or "").strip()
        credential_type = str(candidate.credential_type or "-")
        account_values = list(candidate.accounts)
        if _domain_hit_is_hash(shell, credential):
            spray_result = validate_domain_reuse_with_ntlm_hash(
                shell,
                domain=domain,
                nt_hash=credential,
                eligibility=eligibility,
            )
        else:
            spray_result = validate_domain_reuse_with_password(
                shell,
                domain=domain,
                password=credential,
                eligibility=eligibility,
            )

        status = str(spray_result.get("status") or "-")
        hits_raw = spray_result.get("hits")
        hits = (
            [str(item).strip() for item in hits_raw if str(item).strip()]
            if isinstance(hits_raw, list)
            else []
        )
        outcomes_raw = spray_result.get("outcome_counts")
        outcomes = outcomes_raw if isinstance(outcomes_raw, dict) else {}
        source_hostnames = list(candidate.source_hostnames)
        created_graph_steps = 0
        created_domain_pass_reuse_steps = 0
        if hits and source_hostnames:
            try:
                from adscan_internal.services.attack_graph_service import (
                    upsert_domain_password_reuse_edges,
                    upsert_local_cred_to_domain_reuse_edges,
                )

                created_graph_steps = int(
                    upsert_local_cred_to_domain_reuse_edges(
                        shell,
                        domain,
                        source_hosts=source_hostnames,
                        domain_usernames=hits,
                        credential=credential,
                        status="discovered",
                    )
                    or 0
                )
                created_domain_pass_reuse_steps = int(
                    upsert_domain_password_reuse_edges(
                        shell,
                        domain,
                        source_usernames=hits,
                        target_usernames=hits,
                        credential=credential,
                        status="discovered",
                        evidence_source="sam_domain_reuse_validation",
                    )
                    or 0
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)

        outcome_summary = _summarize_outcomes_for_table(outcomes, excluded_codes={"SUCCESS"})
        domain_results_by_credential[credential] = {
            "status": status,
            "hits": hits,
            "outcome_counts": outcomes,
            "created_graph_steps": created_graph_steps,
            "created_domain_pass_reuse_steps": created_domain_pass_reuse_steps,
        }
        validated_domain_hits.extend(
            {
                "username": username,
                "credential": credential,
                "is_hash": _domain_hit_is_hash(shell, credential),
            }
            for username in hits
        )
        result_rows.append(
            {
                "Accounts": ", ".join(
                    mark_sensitive(account, "user") for account in account_values[:2]
                )
                + (
                    f" (+{len(account_values) - 2} more)"
                    if len(account_values) > 2
                    else ""
                ),
                "Credential Type": credential_type,
                "Credential": mark_sensitive(credential, "password"),
                "Status": status,
                "Domain Hits": len(hits),
                "Local->Domain Steps": created_graph_steps,
                "DomainPassReuse": created_domain_pass_reuse_steps,
                "Outcome Summary": outcome_summary or "-",
            }
        )

    return result_rows, domain_results_by_credential, validated_domain_hits


def get_spraying_user_list_path(
    shell: SprayShell, domain: str, requires_auth_users: bool
) -> str | None:
    """Return the user list path required for spraying, ensuring it exists and is not empty."""
    primary_filename = "enabled_users.txt" if requires_auth_users else "users.txt"
    fallback_filename = "users.txt" if requires_auth_users else "enabled_users.txt"
    candidate_filenames = [primary_filename]
    if fallback_filename != primary_filename:
        candidate_filenames.append(fallback_filename)

    workspace_cwd = shell.current_workspace_dir or os.getcwd()

    try:
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            f"[spray] Resolving user list for {marked_domain}: "
            f"requires_auth_users={requires_auth_users}, "
            f"primary={mark_sensitive(domain_relpath(shell.domains_dir, domain, primary_filename), 'path')}, "
            f"fallback={mark_sensitive(domain_relpath(shell.domains_dir, domain, fallback_filename), 'path')}"
        )
        candidate_reasons: list[tuple[str, str]] = []
        for idx, filename in enumerate(candidate_filenames):
            relative_path = domain_relpath(shell.domains_dir, domain, filename)
            absolute_path = domain_subpath(
                workspace_cwd, shell.domains_dir, domain, filename
            )
            marked_path = mark_sensitive(relative_path, "path")
            if not os.path.exists(absolute_path):
                candidate_reasons.append((relative_path, "missing"))
                print_info_debug(f"[spray] Missing user list file: {marked_path}")
                continue

            size = os.path.getsize(absolute_path)
            if size == 0:
                candidate_reasons.append((relative_path, "empty"))
                print_info_debug(f"[spray] User list file is empty: {marked_path}")
                continue

            if idx > 0:
                print_info_debug(
                    f"[spray] Falling back to alternate user list file: {marked_path}"
                )
            print_info_debug(
                f"[spray] User list file size: {size} bytes ({marked_path})"
            )
            return relative_path

        attempted_paths = ", ".join(
            domain_relpath(shell.domains_dir, domain, f) for f in candidate_filenames
        )
        print_warning(
            "Cannot perform password spraying: no valid user list file found "
            f"({attempted_paths})."
        )
        print_info(
            "Generate the user list first (e.g., run the corresponding enumeration command) "
            "and try again."
        )
        for candidate_path, reason in candidate_reasons:
            print_info_debug(
                "[spray] Candidate user list rejected: "
                f"path={mark_sensitive(candidate_path, 'path')} reason={reason}"
            )
        return None
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_error(f"Unable to validate spraying user list for domain {domain}: {exc}")
        print_info_debug(
            f"[spray] Exception while validating user list: {type(exc).__name__}: {exc}"
        )
        return None


def get_password_spraying_history(shell: SprayShell) -> dict:
    """Return the password spraying history dict, initializing it if needed.

    Structure:
        {
            "<domain>": {
                "<category>": {
                    "count": int,
                    "last_run": str,  # ISO 8601 UTC
                    # For category == "password":
                    # "passwords": {
                    #     "<password>": {"count": int, "last_run": str}
                    # }
                }
            }
        }
    """
    history = getattr(shell, "password_spraying_history", None)
    if not isinstance(history, dict):
        history = {}
        shell.password_spraying_history = history
    return history


def register_spraying_attempt(
    shell: SprayShell, domain: str, category: str, password: Optional[str] = None
) -> None:
    """Record a password spraying attempt in the in-memory history."""
    try:
        history = get_password_spraying_history(shell)
        domain_history = history.setdefault(domain, {})
        category_entry = domain_history.setdefault(category, {})
        now_iso = datetime.now(timezone.utc).isoformat()

        if category == "password":
            passwords_entry = category_entry.setdefault("passwords", {})
            if password is None:
                return
            pwd_entry = passwords_entry.setdefault(
                password, {"count": 0, "last_run": None}
            )
            pwd_entry["count"] = int(pwd_entry.get("count", 0)) + 1
            pwd_entry["last_run"] = now_iso
        else:
            category_entry["count"] = int(category_entry.get("count", 0)) + 1
            category_entry["last_run"] = now_iso
    except Exception as exc:
        telemetry.capture_exception(exc)


def should_proceed_with_repeated_spraying(
    shell: SprayShell, domain: str, category: str, password: Optional[str] = None
) -> bool:
    """Check if this spraying is a repeat and, if so, warn and ask for confirmation.

    Returns:
        bool: True if spraying should continue, False if it should be cancelled.
    """
    try:
        history = get_password_spraying_history(shell)
        domain_history = history.get(domain, {})
        category_entry = domain_history.get(category, {})

        is_repeat = False
        last_run = None

        if category == "password":
            passwords_entry = category_entry.get("passwords", {})
            if password is not None and password in passwords_entry:
                is_repeat = True
                last_run = passwords_entry[password].get("last_run")
        else:
            if category_entry:
                is_repeat = True
                last_run = category_entry.get("last_run")

        if not is_repeat:
            # First time: just register and continue silently
            register_spraying_attempt(shell, domain, category, password)
            return True

        marked_domain = mark_sensitive(domain, "domain")
        category_labels = {
            "useraspass": "Username as password",
            "useraspass_lower": "Username as password in lowercase",
            "useraspass_upper": "Username as password in uppercase",
            "blank_password": "Blank password",
            "password": "Specific password",
            "computer_pre2k": "Computer accounts (pre2k)",
        }
        category_label = category_labels.get(category, category)

        lines: list[str] = []
        lines.append(
            f"You have already performed a password spraying in domain {marked_domain}"
        )
        if category == "password" and password is not None:
            marked_password = mark_sensitive(password, "password")
            lines.append(
                f"using the password {marked_password} (same password spraying type)."
            )
        else:
            lines.append(f"with type: {category_label}.")

        if last_run:
            lines.append(f"Last execution time (UTC): {last_run}")

        lines.append(
            "\nRepeating the same spraying may increase the risk of account lockouts "
            "or violate password policy guidance."
        )
        lines.append(
            "Only continue if you are sure this is allowed and expected for your engagement."
        )

        panel_content = "\n".join(lines)

        print_panel(
            panel_content,
            title="[bold yellow]Repeated Password Spraying Detected[/bold yellow]",
            border_style="yellow",
            expand=False,
        )

        proceed = Confirm.ask(
            "Taking this into account, do you still want to continue with this password spraying?",
            default=False,
        )
        if not proceed:
            return False

        # User explicitly accepted the risk, register attempt
        register_spraying_attempt(shell, domain, category, password)
        return True
    except Exception as exc:
        telemetry.capture_exception(exc)
        # If anything goes wrong, do not block spraying flow
        return True


def compute_spraying_eligibility(
    shell: SprayShell,
    *,
    domain: str,
    user_list_file: str,
    safe_threshold: int,
) -> SprayEligibilityResult | None:
    """Compute eligible and excluded users for password spraying.

    This is a best-effort implementation that tries to use NetExec policy
    data (Account Lockout Threshold + BadPwdCount) when credentials are
    available for the current domain context. If policy data cannot be
    obtained or parsed, it falls back to the full user list.

    Returns:
        A `SprayEligibilityResult` instance (from `adscan_internal.spraying`)
        on success, or None on fatal errors (e.g., cannot read user list).
    """
    try:
        file_users = read_user_list(user_list_file)
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_error("Unable to read the spraying user list file.")
        print_exception(show_locals=False, exception=exc)
        return None

    auth_state = str(shell.domains_data[domain].get("auth", "")).strip().lower()
    is_auth = auth_state in {"auth", "pwned"}
    pdc_ip = shell.domains_data[domain]["pdc"]
    marked_domain = mark_sensitive(domain, "domain")

    lockout_threshold = None
    badpwd_by_user = None
    no_lockout_enforced = False

    print_info_verbose(
        f"Starting spray eligibility computation for {marked_domain} "
        f"(safe remaining threshold={safe_threshold}, users in list={len(file_users)})."
    )

    if is_auth and shell.netexec_path:
        auth_domain: str | None = None
        preferred_domain_data = shell.domains_data.get(domain, {})
        preferred_username = preferred_domain_data.get("username")
        preferred_password = preferred_domain_data.get("password")
        if preferred_username and preferred_password:
            auth_domain = domain
        elif getattr(shell, "domain", None):
            auth_domain = getattr(shell, "domain", None)
        auth_username = shell.domains_data.get(auth_domain or "", {}).get("username")
        auth_password = shell.domains_data.get(auth_domain or "", {}).get("password")

        if not auth_domain or not auth_username or not auth_password:
            print_warning_verbose(
                "Skipping password policy lookup because authenticated domain "
                "credentials are incomplete."
            )
            return compute_spray_eligibility(
                file_users=file_users,
                lockout_threshold=lockout_threshold,
                badpwd_by_user=badpwd_by_user,
                safe_remaining_threshold=safe_threshold,
                strict_missing_badpwd=True,
            )
        if auth_domain and auth_username and auth_password:
            pass_pol_cmd = build_netexec_pass_pol_command(
                nxc_path=shell.netexec_path,
                dc_ip=pdc_ip,
                username=auth_username,
                password=auth_password,
                domain=auth_domain,
                kerberos=True,
            )
            print_info_debug(f"[netexec pass-pol] {pass_pol_cmd}")

            users_cmd = build_netexec_users_command(
                nxc_path=shell.netexec_path,
                dc_ip=pdc_ip,
                username=auth_username,
                password=auth_password,
                domain=auth_domain,
                kerberos=True,
            )

            pass_pol_proc = _run_netexec_query_with_parse_retry(
                shell,
                command=pass_pol_cmd,
                domain=auth_domain,
                query_label="NetExec --pass-pol",
                parse_ok=lambda output: (
                    parse_netexec_lockout_threshold_result(output).explicit_none
                    or parse_netexec_lockout_threshold_result(output).threshold
                    is not None
                ),
            )
            if pass_pol_proc and pass_pol_proc.stdout:
                threshold_result = parse_netexec_lockout_threshold_result(
                    strip_ansi_codes(pass_pol_proc.stdout)
                )
                lockout_threshold = threshold_result.threshold
                if threshold_result.explicit_none:
                    no_lockout_enforced = True
                    print_info_verbose(
                        "Password policy returned 'None' for account lockout threshold. "
                        "No lockout is enforced; spraying cannot lock accounts."
                    )
                elif lockout_threshold is not None:
                    print_info_verbose(
                        f"Parsed account lockout threshold={lockout_threshold}."
                    )
                else:
                    print_warning_verbose(
                        "Password policy output did not contain a parseable account "
                        "lockout threshold; treating the policy as unknown."
                    )
            else:
                print_warning_verbose(
                    "Password policy command produced no output; "
                    "lockout threshold unavailable."
                )

            if no_lockout_enforced or lockout_threshold == 0:
                print_info_debug(
                    "[eligibility] Skipping user BadPwdCount lookup because "
                    f"no lockout is enforced (threshold={lockout_threshold})."
                )
            else:
                users_proc = _run_netexec_query_with_parse_retry(
                    shell,
                    command=users_cmd,
                    domain=auth_domain,
                    query_label="NetExec --users",
                    parse_ok=lambda output: bool(parse_netexec_users_badpwd(output)),
                )
                if users_proc and users_proc.stdout:
                    badpwd_by_user = parse_netexec_users_badpwd(
                        strip_ansi_codes(users_proc.stdout)
                    )
                    print_info_verbose(
                        f"Parsed BadPwdCount data for {len(badpwd_by_user)} user(s)."
                    )
                    if len(badpwd_by_user) == 0:
                        print_warning_verbose(
                            "User query returned output but no BadPwdCount values were "
                            "recognized."
                        )
                else:
                    print_warning_verbose(
                        "User query command produced no output; BadPwdCount data "
                        "unavailable."
                    )
    else:
        if not is_auth:
            print_warning_verbose(
                f"Skipping password policy lookup for {marked_domain} because the "
                "current domain context is not authenticated."
            )
        elif not shell.netexec_path:
            print_warning_verbose(
                "Skipping password policy lookup because the policy query tool is "
                "not configured."
            )

    return compute_spray_eligibility(
        file_users=file_users,
        lockout_threshold=lockout_threshold,
        badpwd_by_user=badpwd_by_user,
        safe_remaining_threshold=safe_threshold,
        no_lockout_enforced=no_lockout_enforced,
        strict_missing_badpwd=True,
    )


def _load_enabled_computer_sams(shell: SprayShell, domain: str) -> list[str]:
    """Load enabled computer names and convert to sAMAccountName format."""
    workspace_cwd = shell.current_workspace_dir or os.getcwd()
    rel_path = domain_relpath(shell.domains_dir, domain, "enabled_computers.txt")
    abs_path = domain_subpath(
        workspace_cwd, shell.domains_dir, domain, "enabled_computers.txt"
    )

    marked_domain = mark_sensitive(domain, "domain")
    if not os.path.exists(abs_path):
        print_warning(
            "Cannot perform computer pre2k check: enabled_computers.txt does not exist."
        )
        print_info(
            "Generate the computer list first (e.g., run the corresponding enumeration command) "
            "and try again."
        )
        print_info_debug(
            f"[spray] Missing enabled_computers.txt for {marked_domain}: {mark_sensitive(rel_path, 'path')}"
        )
        return []

    try:
        results = load_enabled_computer_samaccounts(
            workspace_cwd, shell.domains_dir, domain
        )
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_error("Unable to read enabled_computers.txt.")
        print_info_debug(
            f"[spray] Failed reading enabled_computers.txt for {marked_domain}: {exc}"
        )
        return []

    print_info_debug(
        f"[spray] Loaded {len(results)} computer account(s) from enabled_computers.txt for {marked_domain}"
    )
    return results


def compute_computer_spraying_eligibility(
    shell: SprayShell,
    *,
    domain: str,
    computer_sams: list[str],
    safe_threshold: int,
) -> SprayEligibilityResult | None:
    """Compute eligible computer accounts for pre2k checks."""
    lockout_threshold = None
    badpwd_by_user = None
    no_lockout_enforced = False

    auth_state = str(shell.domains_data[domain].get("auth", "")).strip().lower()
    is_auth = auth_state in {"auth", "pwned"}
    pdc_ip = shell.domains_data[domain]["pdc"]
    marked_domain = mark_sensitive(domain, "domain")

    print_info_verbose(
        f"Starting computer pre2k eligibility computation for {marked_domain} "
        f"(safe remaining threshold={safe_threshold}, computers={len(computer_sams)})."
    )

    if is_auth and shell.netexec_path:
        auth_domain: str | None = None
        preferred_domain_data = shell.domains_data.get(domain, {})
        preferred_username = preferred_domain_data.get("username")
        preferred_password = preferred_domain_data.get("password")
        if preferred_username and preferred_password:
            auth_domain = domain
        elif getattr(shell, "domain", None):
            auth_domain = getattr(shell, "domain", None)
        auth_username = shell.domains_data.get(auth_domain or "", {}).get("username")
        auth_password = shell.domains_data.get(auth_domain or "", {}).get("password")

        if not auth_domain or not auth_username or not auth_password:
            print_warning_verbose(
                "Skipping computer BadPwdCount lookup because authenticated "
                "domain credentials are incomplete."
            )
            return compute_spray_eligibility(
                file_users=computer_sams,
                lockout_threshold=lockout_threshold,
                badpwd_by_user=badpwd_by_user,
                safe_remaining_threshold=safe_threshold,
                strict_missing_badpwd=True,
            )

        pass_pol_cmd = build_netexec_pass_pol_command(
            nxc_path=shell.netexec_path,
            dc_ip=pdc_ip,
            username=auth_username,
            password=auth_password,
            domain=auth_domain,
        )
        print_info_debug(f"[netexec pass-pol] {pass_pol_cmd}")

        computers_cmd = build_netexec_computers_query_command(
            nxc_path=shell.netexec_path,
            dc_ip=pdc_ip,
            username=auth_username,
            password=auth_password,
            domain=auth_domain,
            kerberos=True,
        )
        print_info_debug(f"[netexec computers] {computers_cmd}")

        pass_pol_proc = _run_netexec_query_with_parse_retry(
            shell,
            command=pass_pol_cmd,
            domain=auth_domain,
            query_label="NetExec --pass-pol",
            parse_ok=lambda output: (
                parse_netexec_lockout_threshold_result(output).explicit_none
                or parse_netexec_lockout_threshold_result(output).threshold is not None
            ),
        )
        if pass_pol_proc and pass_pol_proc.stdout:
            threshold_result = parse_netexec_lockout_threshold_result(
                strip_ansi_codes(pass_pol_proc.stdout)
            )
            lockout_threshold = threshold_result.threshold
            if threshold_result.explicit_none:
                no_lockout_enforced = True
                print_info_verbose(
                    "Password policy returned 'None' for account lockout threshold. "
                    "No lockout is enforced; spraying cannot lock accounts."
                )
            elif lockout_threshold is not None:
                print_info_verbose(
                    f"Parsed account lockout threshold={lockout_threshold}."
                )
            else:
                print_warning_verbose(
                    "Password policy output did not contain a parseable account "
                    "lockout threshold; treating the policy as unknown."
                )
        else:
            print_warning_verbose(
                "Password policy command produced no output; "
                "lockout threshold unavailable."
            )

        if no_lockout_enforced:
            print_info_debug(
                "[eligibility] Skipping computer BadPwdCount lookup because "
                "the domain reports no lockout threshold."
            )
        else:
            computers_proc = _run_netexec_query_with_parse_retry(
                shell,
                command=computers_cmd,
                domain=auth_domain,
                query_label="NetExec computer BadPwdCount query",
                parse_ok=lambda output: bool(parse_netexec_computer_badpwd(output)),
            )
            if computers_proc and computers_proc.stdout:
                badpwd_by_user = parse_netexec_computer_badpwd(
                    strip_ansi_codes(computers_proc.stdout)
                )
                print_info_verbose(
                    f"Parsed BadPwdCount data for {len(badpwd_by_user)} computer(s)."
                )
                if len(badpwd_by_user) == 0:
                    print_warning_verbose(
                        "Computer query returned output but no BadPwdCount values were "
                        "recognized."
                    )
            else:
                print_warning_verbose(
                    "Computer query command produced no output; BadPwdCount data "
                    "unavailable."
                )
    else:
        if not is_auth:
            print_warning_verbose(
                f"Skipping computer BadPwdCount lookup for {marked_domain} because the "
                "current domain context is not authenticated."
            )
        elif not shell.netexec_path:
            print_warning_verbose(
                "Skipping computer BadPwdCount lookup because the query tool is "
                "not configured."
            )

    return compute_spray_eligibility(
        file_users=computer_sams,
        lockout_threshold=lockout_threshold,
        badpwd_by_user=badpwd_by_user,
        safe_remaining_threshold=safe_threshold,
        no_lockout_enforced=no_lockout_enforced,
        strict_missing_badpwd=True,
    )


def print_spraying_eligibility(
    shell: SprayShell, domain: str, eligibility: SprayEligibilityResult
) -> None:
    """Render eligibility info for spraying in a user-friendly way."""
    marked_domain = mark_sensitive(domain, "domain")
    summary_lines: list[str] = [
        f"Domain: {marked_domain}",
        f"Users in list: {len(eligibility.input_users)}",
        f"Eligible users: {len(eligibility.eligible_users)}",
        f"Excluded users: {len(eligibility.excluded_users)}",
    ]
    if eligibility.lockout_threshold is not None:
        summary_lines.append(
            f"Account lockout threshold: {eligibility.lockout_threshold}"
        )
        summary_lines.append(
            f"Safe remaining attempts threshold: {eligibility.safe_remaining_threshold}"
        )
    if eligibility.notes:
        summary_lines.append("")
        summary_lines.extend(eligibility.notes)

    print_panel(
        "\n".join(summary_lines),
        title="[bold cyan]Spray Eligibility Summary[/bold cyan]",
        border_style="cyan",
        expand=False,
    )

    if eligibility.excluded_users:
        table = Table(title="Excluded users (preview)", show_lines=False)
        table.add_column("User")
        table.add_column("Reason")
        table.add_column("BadPwdCount", justify="right")
        table.add_column("Remaining", justify="right")

        preview = eligibility.excluded_users[:20]
        for excluded in preview:
            marked_user = mark_sensitive(excluded.username, "user")
            badpwd_str = (
                str(excluded.badpwd_count) if excluded.badpwd_count is not None else "-"
            )
            remaining_str = (
                str(excluded.remaining_attempts)
                if excluded.remaining_attempts is not None
                else "-"
            )
            table.add_row(marked_user, excluded.reason, badpwd_str, remaining_str)
        print_table(table)
        if len(eligibility.excluded_users) > len(preview):
            print_info_verbose(
                f"Excluded users total: {len(eligibility.excluded_users)} "
                f"(showing first {len(preview)})."
            )


def _resolve_multi_credential_spray_budget(
    *,
    shell: SprayShell,
    eligibility: SprayEligibilityResult,
    requested_count: int,
) -> tuple[int, str]:
    """Return the safe credential budget for one multi-attempt spray flow."""
    if requested_count <= 0:
        return 0, "No sprayable credentials were provided."

    if any("no lockout enforced" in note.lower() for note in eligibility.notes):
        return requested_count, "Domain reports no account lockout threshold."

    if eligibility.used_policy_data and eligibility.minimum_remaining_attempts is not None:
        safe_budget = max(
            0,
            eligibility.minimum_remaining_attempts
            - int(eligibility.safe_remaining_threshold),
        )
        if safe_budget <= 0:
            return (
                0,
                "Current BadPwdCount values leave no safe room for additional credential "
                "attempts after applying the reserve margin.",
            )
        return safe_budget, (
            "Safe credential budget derived from lockout policy and the worst eligible "
            "BadPwdCount value."
        )

    workspace_type = str(getattr(shell, "type", "") or "").strip().lower()
    if workspace_type == "ctf":
        return 1, (
            "Lockout threshold could not be determined. Restricting automated multi-credential "
            "attempts to one credential in CTF mode."
        )
    return 1, (
        "Lockout threshold could not be determined. Restricting automated multi-credential "
        "attempts to one credential until the policy is known."
    )


def _resolve_multi_password_spray_budget(
    *,
    shell: SprayShell,
    eligibility: SprayEligibilityResult,
    requested_count: int,
) -> tuple[int, str]:
    """Backward-compatible wrapper for password spraying budget resolution."""
    budget, reason = _resolve_multi_credential_spray_budget(
        shell=shell,
        eligibility=eligibility,
        requested_count=requested_count,
    )
    return budget, reason.replace("credential", "password")


def _build_password_selection_option(password: str, *, selected: bool = False) -> str:
    """Return one stable, compact checkbox label for one password."""
    preview = password if len(password) <= 60 else f"{password[:57]}..."
    selected_marker = "[selected]" if selected else ""
    return f"{mark_sensitive(preview, 'password')} {selected_marker}".strip()


def _select_values_with_limit(
    shell: SprayShell,
    *,
    values: list[str],
    max_selectable: int,
    title: str,
    option_builder: Callable[[str], str],
    item_label: str,
) -> list[str] | None:
    """Interactively select up to ``max_selectable`` values from a list."""
    if not values:
        return []
    if max_selectable <= 0:
        return []

    if bool(getattr(shell, "auto", False)):
        return list(values[:max_selectable])

    options: list[str] = []
    option_map: dict[str, str] = {}
    default_values: list[str] = []
    for index, value in enumerate(values, start=1):
        option = f"{index:>2}. {option_builder(value)}"
        options.append(option)
        option_map[option] = value
        if index <= max_selectable:
            default_values.append(option)
    skip_option = "Skip spraying for now"
    options.append(skip_option)

    checkbox = getattr(shell, "_questionary_checkbox", None)
    if not callable(checkbox):
        return list(values[:max_selectable])

    while True:
        selected_values = checkbox(
            title,
            options,
            default_values=default_values,
        )
        if selected_values is None:
            return None
        if skip_option in selected_values:
            return []
        selected_items = [option_map[item] for item in selected_values if item in option_map]
        if len(selected_items) <= max_selectable:
            return selected_items
        print_warning(
            f"You can select at most {max_selectable} {item_label}(s) safely for this spray."
        )
        default_values = selected_values[:max_selectable]


def _select_passwords_for_spraying(
    shell: SprayShell,
    *,
    passwords: list[str],
    max_selectable: int,
    title: str,
) -> list[str] | None:
    """Interactively select up to ``max_selectable`` passwords for spraying."""
    return _select_values_with_limit(
        shell,
        values=passwords,
        max_selectable=max_selectable,
        title=title,
        option_builder=_build_password_selection_option,
        item_label="password",
    )


def _build_domain_reuse_selection_option(candidate: DomainReuseValidationCandidate) -> str:
    """Return one compact checkbox label for one domain reuse candidate."""
    preview = (
        candidate.credential
        if len(candidate.credential) <= 48
        else f"{candidate.credential[:45]}..."
    )
    accounts = (
        ", ".join(mark_sensitive(account, "user") for account in candidate.accounts[:2])
        if candidate.accounts
        else "N/A"
    )
    if len(candidate.accounts) > 2:
        accounts += f" (+{len(candidate.accounts) - 2} more)"
    return (
        f"[{candidate.credential_type}] {mark_sensitive(preview, 'password')} "
        f"from {accounts}"
    )


def select_domain_reuse_candidates_for_validation(
    shell: SprayShell,
    *,
    domain: str,
    candidates: list[DomainReuseValidationCandidate],
    source_scope: str,
) -> tuple[list[DomainReuseValidationCandidate], SprayEligibilityResult] | None:
    """Select safe SAM-derived credential variants for domain reuse validation."""
    if not candidates:
        return None

    eligibility = _build_domain_reuse_eligibility(shell, domain=domain)
    if eligibility is None:
        return None

    budget, budget_reason = _resolve_multi_credential_spray_budget(
        shell=shell,
        eligibility=eligibility,
        requested_count=len(candidates),
    )
    print_panel(
        "\n".join(
            [
                f"Credential variants: {len(candidates)}",
                f"Safe validation budget: {budget}",
                f"Reason: {budget_reason}",
                f"Source: {source_scope}",
            ]
        ),
        title="[bold cyan]SAM -> Domain Reuse Validation Plan[/bold cyan]",
        border_style="cyan",
        expand=False,
    )
    if budget <= 0:
        deferred_path = _persist_deferred_domain_reuse_candidates(
            shell,
            domain=domain,
            candidates=candidates,
            source_scope=source_scope,
            reason=budget_reason,
        )
        print_warning(
            "Automated SAM-to-domain reuse validation was skipped because no safe validation budget remains."
        )
        if deferred_path:
            print_info(
                "Deferred SAM-to-domain reuse candidates saved to "
                f"{mark_sensitive(deferred_path, 'path')}."
            )
        return None

    option_map: dict[str, DomainReuseValidationCandidate] = {}
    option_values: list[str] = []
    for candidate in candidates:
        option = _build_domain_reuse_selection_option(candidate)
        option_map[option] = candidate
        option_values.append(option)

    selected_values = _select_values_with_limit(
        shell,
        values=option_values,
        max_selectable=min(budget, len(option_values)),
        title=(
            "Select the SAM-derived credential variants to validate against the domain "
            f"(max {min(budget, len(option_values))}):"
        ),
        option_builder=lambda value: value,
        item_label="credential variant",
    )
    if selected_values is None:
        _persist_deferred_domain_reuse_candidates(
            shell,
            domain=domain,
            candidates=candidates,
            source_scope=source_scope,
            reason="User cancelled SAM-to-domain reuse validation.",
        )
        print_info("SAM-to-domain reuse validation cancelled by user.")
        return None
    if not selected_values:
        deferred_path = _persist_deferred_domain_reuse_candidates(
            shell,
            domain=domain,
            candidates=candidates,
            source_scope=source_scope,
            reason="User skipped SAM-to-domain reuse validation for now.",
        )
        print_info("SAM-to-domain reuse validation skipped for now.")
        if deferred_path:
            print_info(
                "Deferred SAM-to-domain reuse candidates saved to "
                f"{mark_sensitive(deferred_path, 'path')}."
            )
        return None

    selected_candidates = [
        option_map[value] for value in selected_values if value in option_map
    ]
    deferred_candidates = [
        candidate for candidate in candidates if candidate not in selected_candidates
    ]
    deferred_path = _persist_deferred_domain_reuse_candidates(
        shell,
        domain=domain,
        candidates=deferred_candidates,
        source_scope=source_scope,
        reason="Deferred by user selection.",
    )
    preview_values = [
        f"{candidate.credential_type}:{mark_sensitive(candidate.credential, 'password')}"
        for candidate in selected_candidates[:3]
    ]
    if len(selected_candidates) > 3:
        preview_values.append(f"+{len(selected_candidates) - 3} more")
    print_info(
        "Selected credential variants for SAM-to-domain validation: "
        + ", ".join(preview_values)
    )
    if deferred_candidates and deferred_path:
        print_info(
            f"Deferred {len(deferred_candidates)} SAM-to-domain reuse candidate(s) for later review at "
            f"{mark_sensitive(deferred_path, 'path')}."
        )
    return selected_candidates, eligibility


def _sanitize_spraying_context_for_json(
    source_context: dict[str, object] | None,
) -> dict[str, object]:
    """Best-effort JSON-safe serialization of spraying source context."""
    if not source_context:
        return {}
    sanitized: dict[str, object] = {}
    for key, value in source_context.items():
        if value is None or isinstance(value, (str, int, float, bool)):
            sanitized[str(key)] = value
            continue
        if isinstance(value, list):
            sanitized[str(key)] = [
                item if isinstance(item, (str, int, float, bool)) or item is None else str(item)
                for item in value
            ]
            continue
        if isinstance(value, dict):
            sanitized[str(key)] = {
                str(sub_key): (
                    sub_value
                    if isinstance(sub_value, (str, int, float, bool)) or sub_value is None
                    else str(sub_value)
                )
                for sub_key, sub_value in value.items()
            }
            continue
        sanitized[str(key)] = str(value)
    return sanitized


def _get_pending_spraying_passwords_path(shell: SprayShell, *, domain: str) -> str:
    """Return the workspace path for deferred password spray candidates."""
    workspace_cwd = shell.current_workspace_dir or os.getcwd()
    spraying_dir = domain_subpath(workspace_cwd, shell.domains_dir, domain, "spraying")
    os.makedirs(spraying_dir, exist_ok=True)
    return os.path.join(spraying_dir, "pending_password_candidates.json")


def _load_pending_spraying_password_candidates(
    shell: SprayShell,
    *,
    domain: str,
) -> list[PendingSprayPasswordCandidate]:
    """Load deferred spraying passwords for one domain."""
    pending_path = _get_pending_spraying_passwords_path(shell, domain=domain)
    if not os.path.exists(pending_path):
        return []
    try:
        with open(pending_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning_debug(
            f"[spray] Failed to read pending password candidates file at {pending_path}: {exc}"
        )
        return []

    if not isinstance(payload, dict) or not isinstance(payload.get("passwords"), list):
        return []

    candidates: list[PendingSprayPasswordCandidate] = []
    for entry in payload["passwords"]:
        if not isinstance(entry, dict):
            continue
        password = str(entry.get("password") or "").strip()
        if not password:
            continue
        source = entry.get("source")
        candidates.append(
            PendingSprayPasswordCandidate(
                password=password,
                reason_not_sprayed=str(entry.get("reason_not_sprayed") or "").strip(),
                deferred_at=str(entry.get("deferred_at") or "").strip(),
                source=_sanitize_spraying_context_for_json(source if isinstance(source, dict) else {}),
            )
        )
    return candidates


def _save_pending_spraying_password_candidates(
    shell: SprayShell,
    *,
    domain: str,
    candidates: list[PendingSprayPasswordCandidate],
) -> str | None:
    """Persist the full pending-password set for one domain."""
    pending_path = _get_pending_spraying_passwords_path(shell, domain=domain)
    payload = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "passwords": [
            {
                "password": candidate.password,
                "reason_not_sprayed": candidate.reason_not_sprayed,
                "deferred_at": candidate.deferred_at,
                "source": candidate.source,
            }
            for candidate in candidates
        ],
    }
    try:
        with open(pending_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
        return pending_path
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning(
            "Failed to persist deferred password spray candidates for later reuse."
        )
        print_info_debug(f"[spray] Deferred password persistence failed: {exc}")
        return None


def _persist_deferred_spraying_passwords(
    shell: SprayShell,
    *,
    domain: str,
    passwords: list[str],
    reason: str,
    source_context: dict[str, object] | None = None,
) -> str | None:
    """Persist not-yet-sprayed password candidates for later manual reuse."""
    if not passwords:
        return None

    existing_entries = _load_pending_spraying_password_candidates(shell, domain=domain)
    source_payload = _sanitize_spraying_context_for_json(source_context)
    existing_keys = {
        (
            entry.password,
            entry.reason_not_sprayed,
            json.dumps(entry.source, sort_keys=True, ensure_ascii=False),
        )
        for entry in existing_entries
    }
    now_iso = datetime.now(timezone.utc).isoformat()
    added = 0
    for password in passwords:
        entry = PendingSprayPasswordCandidate(
            password=password,
            reason_not_sprayed=reason,
            deferred_at=now_iso,
            source=source_payload,
        )
        key = (
            entry.password,
            entry.reason_not_sprayed,
            json.dumps(entry.source, sort_keys=True, ensure_ascii=False),
        )
        if key in existing_keys:
            continue
        existing_keys.add(key)
        existing_entries.append(entry)
        added += 1
    pending_path = _save_pending_spraying_password_candidates(
        shell,
        domain=domain,
        candidates=existing_entries,
    )
    if added and pending_path:
        print_info_debug(
            f"[spray] Deferred {added} password candidate(s) to {mark_sensitive(pending_path, 'path')}"
        )
    return pending_path


def _remove_pending_spraying_password_candidates(
    shell: SprayShell,
    *,
    domain: str,
    passwords: list[str],
) -> str | None:
    """Remove sprayed password candidates from the pending file."""
    if not passwords:
        return None
    pending_entries = _load_pending_spraying_password_candidates(shell, domain=domain)
    if not pending_entries:
        return _get_pending_spraying_passwords_path(shell, domain=domain)
    removal_set = {str(password or "").strip() for password in passwords if str(password or "").strip()}
    retained_entries = [
        entry for entry in pending_entries if entry.password not in removal_set
    ]
    return _save_pending_spraying_password_candidates(
        shell,
        domain=domain,
        candidates=retained_entries,
    )


def _get_pending_domain_reuse_candidates_path(shell: SprayShell, *, domain: str) -> str:
    """Return the workspace path for deferred SAM->domain reuse candidates."""
    workspace_cwd = shell.current_workspace_dir or os.getcwd()
    spraying_dir = domain_subpath(workspace_cwd, shell.domains_dir, domain, "spraying")
    os.makedirs(spraying_dir, exist_ok=True)
    return os.path.join(spraying_dir, "pending_domain_reuse_candidates.json")


def _load_pending_domain_reuse_candidates(
    shell: SprayShell,
    *,
    domain: str,
) -> list[PendingDomainReuseValidationCandidate]:
    """Load deferred SAM->domain reuse validation candidates for one domain."""
    pending_path = _get_pending_domain_reuse_candidates_path(shell, domain=domain)
    if not os.path.exists(pending_path):
        return []
    try:
        with open(pending_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning_debug(
            f"[spray] Failed to read pending domain reuse candidates at {pending_path}: {exc}"
        )
        return []

    if not isinstance(payload, dict) or not isinstance(payload.get("candidates"), list):
        return []

    candidates: list[PendingDomainReuseValidationCandidate] = []
    for entry in payload["candidates"]:
        if not isinstance(entry, dict):
            continue
        credential = str(entry.get("credential") or "").strip()
        if not credential:
            continue
        accounts_raw = entry.get("accounts")
        source_hostnames_raw = entry.get("source_hostnames")
        candidates.append(
            PendingDomainReuseValidationCandidate(
                credential=credential,
                credential_type=str(entry.get("credential_type") or "-").strip() or "-",
                accounts=(
                    [str(item).strip() for item in accounts_raw if str(item).strip()]
                    if isinstance(accounts_raw, list)
                    else []
                ),
                source_hostnames=(
                    [str(item).strip() for item in source_hostnames_raw if str(item).strip()]
                    if isinstance(source_hostnames_raw, list)
                    else []
                ),
                source_scope=str(entry.get("source_scope") or "").strip(),
                reason_not_validated=str(entry.get("reason_not_validated") or "").strip(),
                deferred_at=str(entry.get("deferred_at") or "").strip(),
            )
        )
    return candidates


def _save_pending_domain_reuse_candidates(
    shell: SprayShell,
    *,
    domain: str,
    candidates: list[PendingDomainReuseValidationCandidate],
) -> str | None:
    """Persist deferred SAM->domain reuse candidates for one domain."""
    pending_path = _get_pending_domain_reuse_candidates_path(shell, domain=domain)
    payload = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "candidates": [
            {
                "credential": candidate.credential,
                "credential_type": candidate.credential_type,
                "accounts": candidate.accounts,
                "source_hostnames": candidate.source_hostnames,
                "source_scope": candidate.source_scope,
                "reason_not_validated": candidate.reason_not_validated,
                "deferred_at": candidate.deferred_at,
            }
            for candidate in candidates
        ],
    }
    try:
        with open(pending_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
        return pending_path
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning(
            "Failed to persist deferred SAM-to-domain reuse candidates for later reuse."
        )
        print_info_debug(f"[spray] Deferred domain reuse persistence failed: {exc}")
        return None


def _persist_deferred_domain_reuse_candidates(
    shell: SprayShell,
    *,
    domain: str,
    candidates: list[DomainReuseValidationCandidate],
    source_scope: str,
    reason: str,
) -> str | None:
    """Persist not-yet-validated SAM->domain reuse candidates for later reuse."""
    if not candidates:
        return None

    existing_entries = _load_pending_domain_reuse_candidates(shell, domain=domain)
    existing_keys = {
        (
            entry.credential,
            entry.credential_type,
            tuple(entry.accounts),
            tuple(entry.source_hostnames),
            entry.source_scope,
            entry.reason_not_validated,
        )
        for entry in existing_entries
    }
    now_iso = datetime.now(timezone.utc).isoformat()
    added = 0
    for candidate in candidates:
        entry = PendingDomainReuseValidationCandidate(
            credential=candidate.credential,
            credential_type=candidate.credential_type,
            accounts=list(candidate.accounts),
            source_hostnames=list(candidate.source_hostnames),
            source_scope=source_scope,
            reason_not_validated=reason,
            deferred_at=now_iso,
        )
        key = (
            entry.credential,
            entry.credential_type,
            tuple(entry.accounts),
            tuple(entry.source_hostnames),
            entry.source_scope,
            entry.reason_not_validated,
        )
        if key in existing_keys:
            continue
        existing_keys.add(key)
        existing_entries.append(entry)
        added += 1
    pending_path = _save_pending_domain_reuse_candidates(
        shell,
        domain=domain,
        candidates=existing_entries,
    )
    if added and pending_path:
        print_info_debug(
            "[spray] Deferred "
            f"{added} SAM-to-domain reuse candidate(s) to {mark_sensitive(pending_path, 'path')}"
        )
    return pending_path


def _remove_pending_domain_reuse_candidates(
    shell: SprayShell,
    *,
    domain: str,
    candidates: list[DomainReuseValidationCandidate],
) -> str | None:
    """Remove executed SAM->domain reuse candidates from the pending file."""
    if not candidates:
        return None
    pending_entries = _load_pending_domain_reuse_candidates(shell, domain=domain)
    if not pending_entries:
        return _get_pending_domain_reuse_candidates_path(shell, domain=domain)
    removal_keys = {
        (
            candidate.credential,
            candidate.credential_type,
            tuple(candidate.accounts),
            tuple(candidate.source_hostnames),
        )
        for candidate in candidates
    }
    retained_entries = [
        entry
        for entry in pending_entries
        if (
            entry.credential,
            entry.credential_type,
            tuple(entry.accounts),
            tuple(entry.source_hostnames),
        )
        not in removal_keys
    ]
    return _save_pending_domain_reuse_candidates(
        shell,
        domain=domain,
        candidates=retained_entries,
    )


def _show_lockout_policy_prompt(
    *,
    domain: str,
    eligibility: SprayEligibilityResult,
    prompt_text: str,
    default_confirm: bool = False,
) -> bool:
    """Show lockout policy UX and optionally prompt for confirmation.

    Returns:
        True if execution should continue, False if it should stop.
    """
    marked_domain = mark_sensitive(domain, "domain")
    if eligibility.lockout_threshold is None and any(
        "no lockout enforced" in note.lower() for note in eligibility.notes
    ):
        info_lines = [
            "[bold green]No account lockout enforced[/bold green]",
            f"Domain: {marked_domain}",
            "The domain reports no lockout threshold.",
            "Spraying attempts will not lock accounts, but proceed responsibly.",
        ]
        print_panel(
            "\n".join(info_lines),
            title="[bold green]Lockout Policy[/bold green]",
            border_style="green",
            expand=False,
        )
        return True

    warning_lines = [
        "[bold red]Lockout threshold unavailable[/bold red]",
        f"Domain: {marked_domain}",
        "Account lockout policy or BadPwdCount data could not be determined.",
        "Proceeding may lock accounts. It is recommended to wait at least 1 hour "
        "between attempts when the lockout threshold is unknown.",
    ]
    print_panel(
        "\n".join(warning_lines),
        title="[bold red]Caution[/bold red]",
        border_style="red",
        expand=False,
    )
    return bool(
        Confirm.ask(
            prompt_text,
            default=default_confirm,
        )
    )


def _enforce_lockout_guardrail(
    *,
    domain: str,
    eligibility: SprayEligibilityResult,
    prompt_text: str,
    default_confirm: bool = False,
) -> bool:
    """Apply the centralized lockout guardrail for all spraying executions.

    Returns:
        True when execution can continue, False when it must stop.
    """
    if eligibility.used_policy_data:
        return True
    print_info_debug("[eligibility] Lockout data unavailable; showing policy UX.")
    return _show_lockout_policy_prompt(
        domain=domain,
        eligibility=eligibility,
        prompt_text=prompt_text,
        default_confirm=default_confirm,
    )


def ask_for_spraying(shell: SprayShell, domain: str) -> None:
    """Prompt user to perform password spraying on a domain."""
    if shell.domains_data[domain]["auth"] == "pwned":
        return

    workspace_cwd = shell.current_workspace_dir or os.getcwd()
    kerberos_path = domain_subpath(
        workspace_cwd, shell.domains_dir, domain, shell.kerberos_dir
    )

    if not os.path.exists(kerberos_path):
        os.makedirs(kerberos_path)

    ux_state = _get_spraying_ux_state(shell, domain)
    ux_state["prompted"] = True
    _capture_spraying_ux_event(shell, "ctf_spraying_prompt_shown", domain)

    marked_domain = mark_sensitive(domain, "domain")
    marked_auth_1 = mark_sensitive(shell.domains_data[domain]["auth"], "domain")
    wants_spraying = Confirm.ask(
        f"Do you want to perform password spraying on domain {marked_domain} using a {marked_auth_1} session?",
        default=True,
    )
    if wants_spraying:
        if shell.domains_data[domain]["auth"] == "auth":
            shell.ask_for_pass_policy(domain)
        do_spraying(shell, domain)
        return

    if str(getattr(shell, "type", "") or "").strip().lower() == "ctf":
        ux_state["initial_declined"] = True
        _capture_spraying_ux_event(shell, "ctf_spraying_skipped", domain)
        maybe_offer_ctf_pre2k_followup(
            shell,
            domain,
            reason="ask_for_spraying_declined",
        )


def do_spraying(shell: SprayShell, domain: str) -> None:
    """
    Performs password spraying on the specified domain.

    This method displays a menu to select the type of spraying to perform on the specified domain.
    The available options are:

    1. Username as password in lowercase
    2. Username as password (First letter uppercase)
    3. Username with a specific password

    If the domain uses credential-based authentication, the user's credentials will be requested.
    If the domain uses Kerberos authentication, the domain's PDC will be used for spraying.

    After selecting an option, the method executes the corresponding command and
    saves the result to a log file in the domain directory.

    Args:
        shell: The shell instance with spraying capabilities.
        domain: The domain in which to perform spraying.
    """
    has_kerbrute = bool(getattr(shell, "kerbrute_path", None))
    has_netexec = bool(getattr(shell, "netexec_path", None))
    if not has_kerbrute and not has_netexec:
        print_error(
            "Password spraying requires kerbrute and/or NetExec. Please run 'adscan install'."
        )
        return

    # Professional password spraying header
    from adscan_internal import print_operation_header
    from adscan_internal.cli.kerberos import ensure_kerberos_output_dir

    pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")
    auth_type = shell.domains_data.get(domain, {}).get("auth", "N/A")
    print_operation_header(
        "Password Spraying Attack",
        details={
            "Domain": domain,
            "PDC": pdc,
            "Authentication Type": auth_type.upper(),
            "Protocol": (
                "Kerberos Pre-Authentication / SMB"
                if has_kerbrute and has_netexec
                else "Kerberos Pre-Authentication"
                if has_kerbrute
                else "SMB (NetExec)"
            ),
        },
        icon="💦",
    )

    # Ensure kerberos output directory exists for spray logs
    ensure_kerberos_output_dir(shell, domain)

    auth_state = str(shell.domains_data[domain].get("auth", "")).strip().lower()
    requires_auth_users = auth_state in {"auth", "pwned"}
    user_list_file = get_spraying_user_list_path(
        shell,
        domain,
        requires_auth_users=requires_auth_users,
    )
    if not user_list_file:
        return

    options: list[str] = []
    if has_kerbrute:
        options.extend(
            [
                _SPRAYING_OPTION_USER_AS_PASS,
                _SPRAYING_OPTION_USER_AS_PASS_LOWER,
                _SPRAYING_OPTION_USER_AS_PASS_UPPER,
                _SPRAYING_OPTION_CUSTOM_PASSWORD,
            ]
        )
    if has_netexec:
        options.append(_SPRAYING_OPTION_BLANK_PASSWORD)
    pending_candidates = _load_pending_spraying_password_candidates(shell, domain=domain)
    pending_domain_reuse_candidates = _load_pending_domain_reuse_candidates(
        shell, domain=domain
    )
    workspace_cwd = shell.current_workspace_dir or os.getcwd()
    ctf_mode = str(getattr(shell, "type", "") or "").strip().lower() == "ctf"
    pre2k_recommended = _should_recommend_pre2k_for_ctf(shell, domain) if ctf_mode else True
    if has_enabled_computer_list(workspace_cwd, shell.domains_dir, domain) and (
        not ctf_mode or pre2k_recommended
    ):
        options.append(_SPRAYING_OPTION_COMPUTER_PRE2K)
    if pending_candidates:
        options.append(_SPRAYING_OPTION_RETRY_PASSWORDS)
    if pending_domain_reuse_candidates:
        options.append(_SPRAYING_OPTION_RETRY_DOMAIN_REUSE)

    default_idx = 0
    if ctf_mode:
        pre2k_idx = next(
            (idx for idx, opt in enumerate(options) if opt == _SPRAYING_OPTION_COMPUTER_PRE2K),
            None,
        )
        if pre2k_idx is not None and pre2k_recommended:
            default_idx = pre2k_idx
            print_info(
                "CTF recommendation: try Computer accounts (pre2k) first when available."
            )
        else:
            print_info(
                "CTF recommendation: try Username-as-password spraying as an early foothold check."
            )

    if not _ensure_spraying_clock_sync(shell, domain, source="do_spraying"):
        return

    current_row = shell._questionary_select(
        f"Select a type of spraying from domain {domain}:",
        options,
        default_idx=default_idx,
    )
    if current_row is None:
        print_warning("Spraying cancelled by user")
        if ctf_mode:
            maybe_offer_ctf_pre2k_followup(
                shell,
                domain,
                reason="spraying_menu_cancelled",
            )
        return

    selected_option = options[current_row]
    auth_state = str(shell.domains_data[domain].get("auth", "")).strip().lower()
    is_auth = auth_state in {"auth", "pwned"}
    pdc_ip = shell.domains_data[domain]["pdc"]
    safe_threshold = 2 if is_auth else 0

    # Confirm repeating sprays before doing heavier eligibility checks.
    spray_password: str | None = None
    spray_category: str
    user_transform: str | None = None
    user_as_pass = True

    if selected_option == _SPRAYING_OPTION_RETRY_DOMAIN_REUSE:
        retry_pending_domain_reuse_validation(shell, domain)
        return
    if selected_option == _SPRAYING_OPTION_RETRY_PASSWORDS:
        retry_pending_password_spraying(shell, domain)
        return
    if selected_option == _SPRAYING_OPTION_USER_AS_PASS:
        spray_category = "useraspass"
    elif selected_option == _SPRAYING_OPTION_USER_AS_PASS_LOWER:
        spray_category = "useraspass_lower"
        user_transform = "lower"
    elif selected_option == _SPRAYING_OPTION_USER_AS_PASS_UPPER:
        spray_category = "useraspass_upper"
        user_transform = "capitalize"
    elif selected_option == _SPRAYING_OPTION_BLANK_PASSWORD:
        spray_password = ""
        spray_category = "blank_password"
        user_as_pass = False
    elif selected_option == _SPRAYING_OPTION_CUSTOM_PASSWORD:
        spray_password = Prompt.ask("Enter the password for spraying")
        spray_category = "password"
        user_as_pass = False
    elif selected_option == _SPRAYING_OPTION_COMPUTER_PRE2K:
        spray_category = "computer_pre2k"
        user_as_pass = False
    else:
        print_error(f"Invalid option selected: {selected_option}")
        return

    if spray_category == "computer_pre2k":
        _capture_spraying_ux_event(
            shell,
            "ctf_pre2k_selected" if ctf_mode else "spraying_pre2k_selected",
            domain,
        )
        do_computer_pre2k_spraying(shell, domain)
        return

    if not should_proceed_with_repeated_spraying(
        shell, domain, spray_category, spray_password
    ):
        print_info("Password spraying cancelled by user.")
        return

    eligibility = compute_spraying_eligibility(
        shell,
        domain=domain,
        user_list_file=user_list_file,
        safe_threshold=safe_threshold,
    )
    if eligibility is None:
        return

    default_mode = shell.type == "ctf"
    if not _enforce_lockout_guardrail(
        domain=domain,
        eligibility=eligibility,
        prompt_text="Continue with spraying using the full user list?",
        default_confirm=default_mode,
    ):
        print_info("Password spraying cancelled by user.")
        return

    print_spraying_eligibility(shell, domain, eligibility)

    if not eligibility.eligible_users:
        print_warning(
            "No eligible users available for spraying with the current safety rules."
        )
        return

    # Transform usernames for the spraying mode when using user-as-pass.
    eligible_for_kerbrute = list(eligibility.eligible_users)
    if user_as_pass and user_transform:
        if user_transform == "lower":
            eligible_for_kerbrute = [u.lower() for u in eligible_for_kerbrute]
        elif user_transform == "capitalize":
            eligible_for_kerbrute = [u.capitalize() for u in eligible_for_kerbrute]

    kerberos_output_dir = ensure_kerberos_output_dir(shell, domain)
    temp_users_path = write_temp_users_file(
        eligible_for_kerbrute, directory=kerberos_output_dir
    )

    try:
        spray_type = (
            "Username as Password"
            if spray_category == "useraspass"
            else "Username as Password (lowercase)"
            if spray_category == "useraspass_lower"
            else "Username as Password (uppercase)"
            if spray_category == "useraspass_upper"
            else "Blank Password"
            if spray_category == "blank_password"
            else "Custom Password"
        )
        if spray_category in _RECOMMENDED_SPRAY_CATEGORIES:
            _mark_recommended_spraying_attempt(shell, domain, spray_category)
            _capture_spraying_ux_event(
                shell,
                "ctf_recommended_spraying_started"
                if ctf_mode
                else "spraying_recommended_started",
                domain,
                extra={"category": spray_category, "spray_type": spray_type},
            )

        if spray_category == "blank_password":
            output_file = os.path.join(
                "domains",
                domain,
                "smb",
                "auth_spray_blank.log" if is_auth else "unauth_spray_blank.log",
            )
            netexec_cmd = build_netexec_password_spray_command(
                nxc_path=shell.netexec_path,
                dc_ip=pdc_ip,
                users_file=temp_users_path,
                password=spray_password,
                domain=domain,
                log_file=output_file,
            )
            netexec_spraying_command(
                shell,
                netexec_cmd,
                domain,
                spray_type=spray_type,
            )
        else:
            if is_auth:
                password_fragment = (
                    safe_log_filename_fragment(spray_password) if spray_password else None
                )
                output_file = os.path.join(
                    "domains",
                    domain,
                    "kerberos",
                    (
                        "auth_spray.log"
                        if spray_category == "useraspass"
                        else "auth_spray_low.log"
                        if spray_category == "useraspass_lower"
                        else "auth_spray_up.log"
                        if spray_category == "useraspass_upper"
                        else f"auth_spray_{password_fragment}.log"
                    ),
                )
            else:
                password_fragment = (
                    safe_log_filename_fragment(spray_password) if spray_password else None
                )
                output_file = os.path.join(
                    "domains",
                    domain,
                    "kerberos",
                    (
                        "unauth_spray.log"
                        if spray_category == "useraspass"
                        else "unauth_spray_low.log"
                        if spray_category == "useraspass_lower"
                        else "unauth_spray_up.log"
                        if spray_category == "useraspass_upper"
                        else f"unauth_spray_{password_fragment}.log"
                    ),
                )

            kerbrute_cmd = build_kerbrute_command(
                kerbrute_path=shell.kerbrute_path,
                domain=domain,
                dc_ip=pdc_ip,
                users_file=temp_users_path,
                output_file=output_file,
                password=spray_password,
                user_as_pass=user_as_pass,
            )
            spraying_command(shell, kerbrute_cmd, domain, spray_type=spray_type)
    finally:
        try:
            os.remove(temp_users_path)
        except OSError:
            pass


def spraying_with_password(
    shell: SprayShell,
    domain: str,
    password: str,
    *,
    entry_label: str | None = None,
    source_context: dict[str, object] | None = None,
    source_steps: list[object] | None = None,
) -> None:
    """
    Performs password spraying on the specified domain using a specific password.

    This is a simplified version of do_spraying that directly uses the provided password
    without showing a menu.

    Args:
        shell: The shell instance with spraying capabilities.
        domain: The domain in which to perform spraying.
        password: The password to use for spraying.
    """
    if not getattr(shell, "kerbrute_path", None):
        print_error(
            "kerbrute is not installed. Please run 'adscan install' to install it."
        )
        return

    marked_domain = mark_sensitive(domain, "domain")
    auth_mode = shell.domains_data.get(domain, {}).get("auth")
    print_info_debug(
        f"[spray] Starting spraying_with_password for {marked_domain} "
        f"(auth={auth_mode!r}, kerbrute_path={shell.kerbrute_path})"
    )
    eligibility = _prepare_password_spraying_eligibility(
        shell,
        domain=domain,
        spray_category="password",
        spray_password=password,
        guardrail_prompt="Continue with custom-password spraying using the full user list?",
        clock_sync_source="spraying_with_password",
    )
    if eligibility is None:
        print_info_debug(
            f"[spray] Aborting spraying_with_password for {marked_domain}: no eligible execution context"
        )
        return
    _execute_single_password_spraying(
        shell,
        domain=domain,
        password=password,
        eligibility=eligibility,
        entry_label=entry_label,
        source_context=source_context,
        source_steps=source_steps,
        show_intro=True,
    )


def _execute_single_password_spraying(
    shell: SprayShell,
    *,
    domain: str,
    password: str,
    eligibility: SprayEligibilityResult,
    entry_label: str | None = None,
    source_context: dict[str, object] | None = None,
    source_steps: list[object] | None = None,
    show_intro: bool = False,
) -> bool:
    """Execute one custom-password spray using a prevalidated eligibility set."""
    from adscan_internal.cli.kerberos import ensure_kerberos_output_dir

    if not eligibility.eligible_users:
        print_warning(
            "No eligible users available for spraying with the current safety rules."
        )
        return False

    marked_domain = mark_sensitive(domain, "domain")
    if show_intro:
        marked_password = mark_sensitive(password, "password")
        print_info(
            f"Performing password spraying on domain {marked_domain} with {marked_password} password..."
        )

    kerberos_output_dir = ensure_kerberos_output_dir(shell, domain)
    temp_users_path = write_temp_users_file(
        list(eligibility.eligible_users), directory=kerberos_output_dir
    )
    try:
        output_file = os.path.join(
            "domains",
            domain,
            "kerberos",
            f"{'auth' if shell.domains_data[domain]['auth'] == 'auth' else 'unauth'}_spray_"
            f"{safe_log_filename_fragment(password)}.log",
        )
        kerbrute_cmd = build_kerbrute_command(
            kerbrute_path=shell.kerbrute_path,
            domain=domain,
            dc_ip=shell.domains_data[domain]["pdc"],
            users_file=temp_users_path,
            output_file=output_file,
            password=password,
            user_as_pass=False,
        )
        spraying_command(
            shell,
            kerbrute_cmd,
            domain,
            spray_type="Custom Password",
            entry_label=entry_label,
            source_context=source_context,
            source_steps=source_steps,
        )
        return True
    finally:
        try:
            os.remove(temp_users_path)
        except OSError:
            pass


def _prepare_password_spraying_eligibility(
    shell: SprayShell,
    *,
    domain: str,
    spray_category: str,
    spray_password: str | None,
    guardrail_prompt: str,
    clock_sync_source: str,
) -> SprayEligibilityResult | None:
    """Return a validated eligibility set for one spraying attempt."""
    auth_state = str(shell.domains_data[domain].get("auth", "")).strip().lower()
    requires_auth_users = auth_state in {"auth", "pwned"}
    user_list_file = get_spraying_user_list_path(
        shell,
        domain,
        requires_auth_users=requires_auth_users,
    )
    if not user_list_file:
        return None

    if not _ensure_spraying_clock_sync(shell, domain, source=clock_sync_source):
        return None

    if not should_proceed_with_repeated_spraying(
        shell,
        domain,
        spray_category,
        spray_password,
    ):
        print_info("Password spraying cancelled by user.")
        return None

    eligibility = compute_spraying_eligibility(
        shell,
        domain=domain,
        user_list_file=user_list_file,
        safe_threshold=2 if auth_state in {"auth", "pwned"} else 0,
    )
    if eligibility is None:
        return None

    default_mode = shell.type == "ctf"
    if not _enforce_lockout_guardrail(
        domain=domain,
        eligibility=eligibility,
        prompt_text=guardrail_prompt,
        default_confirm=default_mode,
    ):
        print_info("Password spraying cancelled by user.")
        return None

    print_spraying_eligibility(shell, domain, eligibility)
    return eligibility


def spraying_with_username_as_password(
    shell: SprayShell,
    domain: str,
    *,
    transform: str | None = None,
    source_context: dict[str, object] | None = None,
    source_steps: list[object] | None = None,
    entry_label: str | None = None,
) -> None:
    """Perform a username-as-password spray using the requested username transform."""
    from adscan_internal.cli.kerberos import ensure_kerberos_output_dir

    if not getattr(shell, "kerbrute_path", None):
        print_error(
            "kerbrute is not installed. Please run 'adscan install' to install it."
        )
        return

    transform_key = str(transform or "").strip().lower()
    spray_category = (
        "useraspass_lower"
        if transform_key == "lower"
        else "useraspass_upper"
        if transform_key in {"upper", "uppercase", "capitalize"}
        else "useraspass"
    )
    spray_type = (
        "Username as Password (lowercase)"
        if spray_category == "useraspass_lower"
        else "Username as Password (uppercase)"
        if spray_category == "useraspass_upper"
        else "Username as Password"
    )
    guardrail_prompt = (
        "Continue with username-as-password spraying using the full user list?"
        if spray_category == "useraspass"
        else "Continue with transformed username-as-password spraying using the full user list?"
    )
    eligibility = _prepare_password_spraying_eligibility(
        shell,
        domain=domain,
        spray_category=spray_category,
        spray_password=None,
        guardrail_prompt=guardrail_prompt,
        clock_sync_source=f"spraying_with_{spray_category}",
    )
    if eligibility is None:
        return
    if not eligibility.eligible_users:
        print_warning(
            "No eligible users available for spraying with the current safety rules."
        )
        return

    kerberos_output_dir = ensure_kerberos_output_dir(shell, domain)
    eligible_for_kerbrute = list(eligibility.eligible_users)
    if spray_category == "useraspass_lower":
        eligible_for_kerbrute = [user.lower() for user in eligible_for_kerbrute]
    elif spray_category == "useraspass_upper":
        eligible_for_kerbrute = [user.capitalize() for user in eligible_for_kerbrute]

    temp_users_path = write_temp_users_file(
        eligible_for_kerbrute, directory=kerberos_output_dir
    )
    try:
        auth_state = str(shell.domains_data[domain].get("auth", "")).strip().lower()
        is_auth = auth_state in {"auth", "pwned"}
        output_file = os.path.join(
            "domains",
            domain,
            "kerberos",
            (
                "auth_spray.log"
                if spray_category == "useraspass" and is_auth
                else "auth_spray_low.log"
                if spray_category == "useraspass_lower" and is_auth
                else "auth_spray_up.log"
                if spray_category == "useraspass_upper" and is_auth
                else "unauth_spray.log"
                if spray_category == "useraspass"
                else "unauth_spray_low.log"
                if spray_category == "useraspass_lower"
                else "unauth_spray_up.log"
            ),
        )
        kerbrute_cmd = build_kerbrute_command(
            kerbrute_path=shell.kerbrute_path,
            domain=domain,
            dc_ip=shell.domains_data[domain]["pdc"],
            users_file=temp_users_path,
            output_file=output_file,
            password=None,
            user_as_pass=True,
        )
        spraying_command(
            shell,
            kerbrute_cmd,
            domain,
            spray_type=spray_type,
            entry_label=entry_label,
            source_context=source_context,
            source_steps=source_steps,
        )
    finally:
        try:
            os.remove(temp_users_path)
        except OSError:
            pass


def spraying_with_blank_password(
    shell: SprayShell,
    domain: str,
    *,
    source_context: dict[str, object] | None = None,
    source_steps: list[object] | None = None,
    entry_label: str | None = None,
) -> None:
    """Perform a blank-password spray against the selected domain."""
    from adscan_internal.cli.kerberos import ensure_kerberos_output_dir

    if not getattr(shell, "netexec_path", None):
        print_error(
            "NetExec is not installed or configured. Please run 'adscan install'."
        )
        return

    eligibility = _prepare_password_spraying_eligibility(
        shell,
        domain=domain,
        spray_category="blank_password",
        spray_password="",
        guardrail_prompt="Continue with blank-password spraying using the full user list?",
        clock_sync_source="spraying_with_blank_password",
    )
    if eligibility is None:
        return
    if not eligibility.eligible_users:
        print_warning(
            "No eligible users available for spraying with the current safety rules."
        )
        return

    auth_state = str(shell.domains_data[domain].get("auth", "")).strip().lower()
    is_auth = auth_state in {"auth", "pwned"}
    kerberos_output_dir = ensure_kerberos_output_dir(shell, domain)
    temp_users_path = write_temp_users_file(
        list(eligibility.eligible_users), directory=kerberos_output_dir
    )
    try:
        output_file = os.path.join(
            "domains",
            domain,
            "smb",
            "auth_spray_blank.log" if is_auth else "unauth_spray_blank.log",
        )
        netexec_cmd = build_netexec_password_spray_command(
            nxc_path=shell.netexec_path,
            dc_ip=shell.domains_data[domain]["pdc"],
            users_file=temp_users_path,
            password="",
            domain=domain,
            log_file=output_file,
        )
        netexec_spraying_command(
            shell,
            netexec_cmd,
            domain,
            spray_type="Blank Password",
            entry_label=entry_label,
            source_context=source_context,
            source_steps=source_steps,
        )
    finally:
        try:
            os.remove(temp_users_path)
        except OSError:
            pass


def _normalize_spray_type_key(spray_type: str | None) -> str:
    """Normalize spray-type labels to one internal dispatch key."""
    normalized = str(spray_type or "").strip().lower()
    aliases = {
        "username as password": "useraspass",
        "username as password (lowercase)": "useraspass_lower",
        "username as password (uppercase)": "useraspass_upper",
        "users with a blank password": "blank_password",
        "blank password": "blank_password",
        "username with a specific password": "custom_password",
        "custom password": "custom_password",
        "computer accounts (pre2k: hostname as password)": "computer_pre2k",
        "computer pre2k": "computer_pre2k",
    }
    return aliases.get(normalized, normalized)


def execute_password_spray_attack_step(
    shell: SprayShell,
    domain: str,
    *,
    spray_type: str | None,
    password: str | None = None,
    entry_label: str | None = None,
    source_context: dict[str, object] | None = None,
    source_steps: list[object] | None = None,
) -> bool:
    """Execute one spray-derived attack-path step from recorded graph metadata."""
    mode_key = _normalize_spray_type_key(spray_type)
    if mode_key == "computer_pre2k":
        do_computer_pre2k_spraying(shell, domain)
        return True
    if mode_key == "blank_password":
        spraying_with_blank_password(
            shell,
            domain,
            source_context=source_context,
            source_steps=source_steps,
            entry_label=entry_label,
        )
        return True
    if mode_key == "custom_password":
        if password is None:
            print_warning(
                "Cannot execute spray step: custom-password metadata is missing the password."
            )
            return False
        spraying_with_password(
            shell,
            domain,
            password,
            entry_label=entry_label,
            source_context=source_context,
            source_steps=source_steps,
        )
        return True
    if mode_key in {"useraspass", "useraspass_lower", "useraspass_upper"}:
        transform = (
            "lower"
            if mode_key == "useraspass_lower"
            else "capitalize"
            if mode_key == "useraspass_upper"
            else None
        )
        spraying_with_username_as_password(
            shell,
            domain,
            transform=transform,
            source_context=source_context,
            source_steps=source_steps,
            entry_label=entry_label,
        )
        return True

    print_warning(
        f"Cannot execute spray step: unsupported spray type {mark_sensitive(str(spray_type or 'N/A'), 'detail')}."
    )
    return False


def spraying_with_passwords(
    shell: SprayShell,
    domain: str,
    passwords: list[str],
    *,
    source_context: dict[str, object] | None = None,
    source_steps: list[object] | None = None,
    source_label: str | None = None,
) -> list[str]:
    """Safely spray multiple candidate passwords with one centralized UX flow."""
    if not passwords:
        return []
    if domain not in getattr(shell, "domains", []):
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            f"Domain {marked_domain} is not configured. Skipping automated password spraying."
        )
        return []

    unique_passwords: list[str] = []
    seen_passwords: set[str] = set()
    for password in passwords:
        normalized = str(password or "").strip()
        if not normalized or normalized in seen_passwords:
            continue
        seen_passwords.add(normalized)
        unique_passwords.append(normalized)
    if not unique_passwords:
        return []

    if str(getattr(shell, "type", "") or "").strip().lower() == "ctf":
        is_pwned = getattr(shell, "_is_ctf_domain_pwned", None)
        if callable(is_pwned):
            try:
                if bool(is_pwned(domain)):
                    print_info_debug(
                        "Skipping multi-password spraying because the CTF domain is already pwned."
                    )
                    return []
            except Exception:  # noqa: BLE001
                pass

    auth_state = str(shell.domains_data[domain].get("auth", "")).strip().lower()
    requires_auth_users = auth_state in {"auth", "pwned"}
    user_list_file = get_spraying_user_list_path(
        shell,
        domain,
        requires_auth_users=requires_auth_users,
    )
    if not user_list_file:
        return []
    if not _ensure_spraying_clock_sync(shell, domain, source="spraying_with_passwords"):
        return []

    eligibility = compute_spraying_eligibility(
        shell,
        domain=domain,
        user_list_file=user_list_file,
        safe_threshold=2 if auth_state in {"auth", "pwned"} else 0,
    )
    if eligibility is None:
        return []
    default_mode = str(getattr(shell, "type", "") or "").strip().lower() == "ctf"
    if not _enforce_lockout_guardrail(
        domain=domain,
        eligibility=eligibility,
        prompt_text="Continue with multi-password spraying using the full user list?",
        default_confirm=default_mode,
    ):
        print_info("Password spraying cancelled by user.")
        return []
    print_spraying_eligibility(shell, domain, eligibility)

    budget, budget_reason = _resolve_multi_password_spray_budget(
        shell=shell,
        eligibility=eligibility,
        requested_count=len(unique_passwords),
    )
    summary_lines = [
        f"Candidate passwords: {len(unique_passwords)}",
        f"Safe spray budget: {budget}",
        f"Reason: {budget_reason}",
    ]
    if source_label:
        summary_lines.append(f"Source: {source_label}")
    print_panel(
        "\n".join(summary_lines),
        title="[bold cyan]Multi-Password Spraying Plan[/bold cyan]",
        border_style="cyan",
        expand=False,
    )

    if budget <= 0:
        deferred_path = _persist_deferred_spraying_passwords(
            shell,
            domain=domain,
            passwords=unique_passwords,
            reason=budget_reason,
            source_context=source_context,
        )
        print_warning(
            "Automated password spraying was skipped because no safe spraying budget remains."
        )
        if deferred_path:
            print_info(
                "Deferred password candidates saved to "
                f"{mark_sensitive(deferred_path, 'path')}."
            )
            print_instruction(
                f"Retry later with `spraying {mark_sensitive(domain, 'domain')}` once the lockout window has reset."
            )
        return []

    max_selectable = min(budget, len(unique_passwords))
    selection_title = (
        "Select the passwords to spray now "
        f"(max {max_selectable}; unselected passwords will be deferred):"
    )
    selected_passwords = _select_passwords_for_spraying(
        shell,
        passwords=unique_passwords,
        max_selectable=max_selectable,
        title=selection_title,
    )
    if selected_passwords is None:
        print_info("Password spraying cancelled by user.")
        return []

    deferred_passwords = [
        password for password in unique_passwords if password not in selected_passwords
    ]
    deferred_reason = (
        "Deferred by user selection."
        if selected_passwords
        else "User skipped automated password spraying for now."
    )
    deferred_path = _persist_deferred_spraying_passwords(
        shell,
        domain=domain,
        passwords=deferred_passwords if deferred_passwords else ([] if selected_passwords else unique_passwords),
        reason=deferred_reason,
        source_context=source_context,
    )
    if not selected_passwords:
        print_info("Password spraying skipped for now.")
        if deferred_path:
            print_info(
                "Deferred password candidates saved to "
                f"{mark_sensitive(deferred_path, 'path')}."
            )
        return []

    preview_passwords = [
        mark_sensitive(password, "password")
        for password in selected_passwords[:_MAX_MULTI_SPRAY_PREVIEW]
    ]
    if len(selected_passwords) > _MAX_MULTI_SPRAY_PREVIEW:
        preview_passwords.append(
            f"+{len(selected_passwords) - _MAX_MULTI_SPRAY_PREVIEW} more"
        )
    print_info(
        "Selected passwords for spraying now: " + ", ".join(str(item) for item in preview_passwords)
    )
    if deferred_passwords and deferred_path:
        print_info(
            f"Deferred {len(deferred_passwords)} password(s) for later review at "
            f"{mark_sensitive(deferred_path, 'path')}."
        )

    executed_passwords: list[str] = []
    for index, password in enumerate(selected_passwords, start=1):
        marked_password = mark_sensitive(password, "password")
        print_info(
            f"Spraying password {index}/{len(selected_passwords)} on domain "
            f"{mark_sensitive(domain, 'domain')}: {marked_password}"
        )
        if not should_proceed_with_repeated_spraying(shell, domain, "password", password):
            print_info(
                f"Skipping password {marked_password} because repeated spraying was not approved."
            )
            continue
        if _execute_single_password_spraying(
            shell,
            domain=domain,
            password=password,
            eligibility=eligibility,
            source_context=source_context,
            source_steps=source_steps,
            show_intro=False,
        ):
            executed_passwords.append(password)

    result_lines = [
        f"Sprayed now: {len(executed_passwords)}",
        f"Deferred: {len(deferred_passwords)}",
    ]
    if deferred_path:
        result_lines.append(f"Deferred file: {mark_sensitive(deferred_path, 'path')}")
    print_panel(
        "\n".join(result_lines),
        title="[bold green]Multi-Password Spraying Result[/bold green]",
        border_style="green",
        expand=False,
    )
    return executed_passwords


def retry_pending_password_spraying(shell: SprayShell, domain: str) -> list[str]:
    """Resume spraying from deferred password candidates saved in the workspace."""
    pending_candidates = _load_pending_spraying_password_candidates(shell, domain=domain)
    if not pending_candidates:
        print_warning("No saved password spray candidates were found for this domain.")
        return []

    table = Table(title="Saved Password Spray Candidates", show_lines=False)
    table.add_column("#", justify="right", style="dim", width=4)
    table.add_column("Password", style="bold")
    table.add_column("Deferred", style="dim", width=24)
    table.add_column("Reason", style="yellow")
    table.add_column("Source", style="dim")
    for index, candidate in enumerate(pending_candidates, start=1):
        source_summary = str(candidate.source.get("artifact") or candidate.source.get("origin") or "N/A")
        table.add_row(
            str(index),
            mark_sensitive(candidate.password, "password"),
            candidate.deferred_at or "-",
            candidate.reason_not_sprayed or "-",
            mark_sensitive(source_summary, "path") if source_summary != "N/A" else source_summary,
        )
    print_table(table)

    deduped_passwords: list[str] = []
    seen_passwords: set[str] = set()
    for candidate in pending_candidates:
        if candidate.password in seen_passwords:
            continue
        seen_passwords.add(candidate.password)
        deduped_passwords.append(candidate.password)

    source_context = pending_candidates[0].source if pending_candidates else None
    executed_passwords = spraying_with_passwords(
        shell,
        domain,
        deduped_passwords,
        source_context=source_context,
        source_label="Saved deferred password candidates",
    )
    if executed_passwords:
        pending_path = _remove_pending_spraying_password_candidates(
            shell,
            domain=domain,
            passwords=executed_passwords,
        )
        if pending_path:
            print_info(
                "Updated deferred password candidate file: "
                f"{mark_sensitive(pending_path, 'path')}."
            )
    return executed_passwords


def retry_pending_domain_reuse_validation(shell: SprayShell, domain: str) -> list[str]:
    """Resume SAM-to-domain reuse validation from deferred credential variants."""
    pending_candidates = _load_pending_domain_reuse_candidates(shell, domain=domain)
    if not pending_candidates:
        print_warning("No saved SAM-to-domain reuse candidates were found for this domain.")
        return []

    table = Table(title="Saved SAM -> Domain Reuse Candidates", show_lines=False)
    table.add_column("#", justify="right", style="dim", width=4)
    table.add_column("Credential", style="bold")
    table.add_column("Type", style="dim")
    table.add_column("Accounts", style="yellow")
    table.add_column("Deferred", style="dim", width=24)
    table.add_column("Reason", style="dim")
    for index, candidate in enumerate(pending_candidates, start=1):
        table.add_row(
            str(index),
            mark_sensitive(candidate.credential, "password"),
            candidate.credential_type or "-",
            ", ".join(mark_sensitive(account, "user") for account in candidate.accounts[:2])
            + (f" (+{len(candidate.accounts) - 2} more)" if len(candidate.accounts) > 2 else ""),
            candidate.deferred_at or "-",
            candidate.reason_not_validated or "-",
        )
    print_table(table)

    candidates = [
        DomainReuseValidationCandidate(
            credential=item.credential,
            credential_type=item.credential_type,
            accounts=list(item.accounts),
            source_hostnames=list(item.source_hostnames),
        )
        for item in pending_candidates
    ]
    source_scope = next(
        (item.source_scope for item in pending_candidates if item.source_scope),
        "Saved SAM -> Domain reuse candidates",
    )
    selection = select_domain_reuse_candidates_for_validation(
        shell,
        domain=domain,
        candidates=candidates,
        source_scope=source_scope,
    )
    if selection is None:
        return []
    selected_candidates, eligibility = selection
    (
        result_rows,
        _domain_results_by_credential,
        validated_domain_hits,
    ) = validate_selected_domain_reuse_candidates(
        shell,
        domain=domain,
        candidates=selected_candidates,
        eligibility=eligibility,
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
            title="Saved SAM -> Domain Reuse Validation Results",
        )
    auth_state = str(shell.domains_data.get(domain, {}).get("auth", "")).strip().lower()
    if validated_domain_hits and auth_state != "pwned":
        handle_validated_domain_hits_followup(
            shell,
            domain=domain,
            hits=validated_domain_hits,
            discovery_label="validated",
        )
    pending_path = _remove_pending_domain_reuse_candidates(
        shell,
        domain=domain,
        candidates=selected_candidates,
    )
    if pending_path:
        print_info(
            "Updated deferred SAM-to-domain reuse file: "
            f"{mark_sensitive(pending_path, 'path')}."
        )
    return [candidate.credential for candidate in selected_candidates]


def spraying_command(
    shell: SprayShell,
    command: str,
    domain: str,
    *,
    spray_type: str | None = None,
    entry_label: str | None = None,
    source_context: dict[str, object] | None = None,
    source_steps: list[object] | None = None,
) -> None:
    """Wrapper for executing spraying command with operation header."""
    # Professional operation header
    from adscan_internal import print_operation_header

    # Determine spray type from command
    resolved_spray_type = spray_type or "Custom Password"
    if spray_type is None:
        if "--user-as-pass" in command:
            if "spray_low" in command:
                resolved_spray_type = "Username as Password (lowercase)"
            elif "spray_up" in command:
                resolved_spray_type = "Username as Password (uppercase)"
            else:
                resolved_spray_type = "Username as Password"
        elif "bruteforce" in command:
            resolved_spray_type = "Bruteforce"

    print_operation_header(
        "Password Spraying Attack",
        details={
            "Domain": domain,
            "Spray Type": resolved_spray_type,
            "User List": "Domain Users",
            "PDC": shell.domains_data[domain].get("pdc", "N/A"),
        },
        icon="💧",
    )

    print_info_debug(f"Command: {command}")
    execute_spraying_command(
        shell,
        command,
        domain,
        spray_type=resolved_spray_type,
        entry_label=entry_label,
        source_context=source_context,
        source_steps=source_steps,
    )


def netexec_spraying_command(
    shell: SprayShell,
    command: str,
    domain: str,
    *,
    spray_type: str | None = None,
    entry_label: str | None = None,
    source_context: dict[str, object] | None = None,
    source_steps: list[object] | None = None,
) -> None:
    """Wrapper for NetExec-based spraying commands with the standard header."""
    from adscan_internal import print_operation_header

    resolved_spray_type = spray_type or "Custom Password"
    print_operation_header(
        "Password Spraying Attack",
        details={
            "Domain": domain,
            "Spray Type": resolved_spray_type,
            "User List": "Domain Users",
            "PDC": shell.domains_data[domain].get("pdc", "N/A"),
            "Protocol": "SMB (NetExec)",
        },
        icon="💧",
    )

    print_info_debug(f"Command: {command}")
    execute_netexec_spraying_command(
        shell,
        command,
        domain,
        spray_type=resolved_spray_type,
        entry_label=entry_label,
        source_context=source_context,
        source_steps=source_steps,
    )


def execute_spraying_command(
    shell: SprayShell,
    command: str,
    domain: str,
    *,
    spray_type: str | None = None,
    entry_label: str | None = None,
    source_context: dict[str, object] | None = None,
    source_steps: list[object] | None = None,
) -> None:
    """Execute the spraying command and process results."""
    from adscan_internal.cli.common import SECRET_MODE

    marked_domain = mark_sensitive(domain, "domain")
    print_warning(
        f"Performing the spraying on {marked_domain}. Please be patient (this can take a while)"
    )

    try:
        # Use run_command instead of spawn_command to avoid output interleaving
        # run_command automatically handles clean_env and provides better error handling
        use_clean_env = command_string_needs_clean_env(command)
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            f"[spray] Executing spraying command with "
            f"use_clean_env={use_clean_env} on domain {marked_domain}"
        )

        completed_process = shell.run_command(
            command,
            timeout=None,  # No timeout for spraying (can take a long time)
            shell=True,
            capture_output=True,
            text=True,
            use_clean_env=use_clean_env,
        )

        if completed_process is None:
            print_error("Failed to execute password spraying command")
            return

        # Process output after command completes (avoids interleaving)
        raw_output = completed_process.stdout or ""
        raw_stderr_output = completed_process.stderr or ""
        output = strip_ansi_codes(raw_output)
        stderr_output = strip_ansi_codes(raw_stderr_output)
        output_lines = output.splitlines() if output else []

        hits_by_user: dict[str, dict[str, str]] = {}
        # Process output to find valid logins (batch).
        for line in output_lines:
            line_stripped = line.strip()
            if not line_stripped:
                continue

            if "VALID LOGIN" not in line_stripped:
                continue

            try:
                creds = line_stripped.split("VALID LOGIN:")[1].strip()
                user_domain, password = creds.split(":", 1)
                username = user_domain.split("@")[0].strip()
                if not username:
                    continue
                key = username.lower()
                hits_by_user.setdefault(
                    key, {"username": username, "password": password}
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_warning_debug("[spray] Failed to parse a VALID LOGIN line.")
                continue

        found_credentials = bool(hits_by_user)

        if found_credentials:
            hits = list(hits_by_user.values())
            _render_valid_spray_hits_panel(
                hits,
                spray_type=spray_type,
            )
            _persist_and_record_spray_hits(
                shell,
                domain=domain,
                hits=hits,
                spray_type=spray_type,
                entry_label=entry_label,
                source_context=source_context,
                source_steps=source_steps,
            )

        # Handle command result
        if completed_process.returncode != 0:
            print_error(
                f"Password spraying command failed with return code: {completed_process.returncode}"
            )
            # Detailed debug context for troubleshooting spray/kerbrute behaviour
            print_warning_debug(
                f"[spray] Debug context: returncode={completed_process.returncode}, "
                f"use_clean_env={use_clean_env}, stdout_len={len(output)}, "
                f"stderr_len={len(stderr_output)}"
            )

            if output_lines:
                print_warning("Command output (last 20 lines):")
                for line in output_lines[-20:]:
                    print_info_verbose(f"  {line}")
            if stderr_output:
                # Always log stderr in debug mode to aid troubleshooting
                print_warning_debug("[spray] Error output:")
                for line in stderr_output.splitlines():
                    clean_line = strip_ansi_codes(line)
                    print_info_debug(f"[spray][stderr] {clean_line}")
        elif not found_credentials:
            print_warning("No valid credentials found.")
            if output_lines and SECRET_MODE:
                print_info_verbose("Full command output:")
                for line in output_lines:
                    print_info_verbose(f"  {line}")
            elif output_lines:
                # Show summary even in non-SECRET mode
                error_lines = [
                    line
                    for line in output_lines
                    if "error" in line.lower() or "failed" in line.lower()
                ]
                if error_lines:
                    print_warning("Errors detected in output:")
                    for line in error_lines[:5]:  # Show first 5 error lines
                        print_info_verbose(f"  {line}")
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error executing password spraying command.")
        print_exception(show_locals=False, exception=e)


def execute_netexec_spraying_command(
    shell: SprayShell,
    command: str,
    domain: str,
    *,
    spray_type: str | None = None,
    entry_label: str | None = None,
    source_context: dict[str, object] | None = None,
    source_steps: list[object] | None = None,
) -> None:
    """Execute a NetExec-based spray and process its hits."""
    from adscan_internal.cli.common import SECRET_MODE

    marked_domain = mark_sensitive(domain, "domain")
    print_warning(
        f"Performing the spraying on {marked_domain}. Please be patient (this can take a while)"
    )

    try:
        print_info_debug(
            f"[spray] Executing NetExec spraying command on domain {marked_domain}"
        )
        completed_process = shell._run_netexec(
            command,
            domain=domain,
            timeout=None,
            shell=True,
            capture_output=True,
            text=True,
        )

        if completed_process is None:
            print_error("Failed to execute password spraying command")
            return

        raw_output = str(getattr(completed_process, "stdout", "") or "")
        raw_stderr_output = str(getattr(completed_process, "stderr", "") or "")
        combined_output = "\n".join(
            text for text in (raw_output, raw_stderr_output) if text
        )
        hit_usernames, outcome_counts = _summarize_domain_spray_outcomes(combined_output)
        hits = [{"username": username, "password": ""} for username in hit_usernames]

        if hits:
            _render_valid_spray_hits_panel(hits, spray_type=spray_type)
            _persist_and_record_spray_hits(
                shell,
                domain=domain,
                hits=hits,
                spray_type=spray_type,
                entry_label=entry_label,
                source_context=source_context,
                source_steps=source_steps,
                persist_via_add_credential=True,
                allow_empty_credential=True,
            )

        if completed_process.returncode != 0 and not hits:
            print_error(
                f"Password spraying command failed with return code: {completed_process.returncode}"
            )
            outcome_summary = _summarize_outcomes_for_table(outcome_counts, limit=4)
            if outcome_summary != "-":
                print_warning(
                    f"NetExec spray outcomes for {marked_domain}: {outcome_summary}"
                )
            if raw_stderr_output:
                print_warning_debug(f"stderr: {raw_stderr_output}")
        elif not hits:
            outcome_summary = _summarize_outcomes_for_table(outcome_counts, limit=4)
            if outcome_summary != "-":
                print_warning(
                    f"No credentials found during spraying. NetExec outcomes: {outcome_summary}"
                )
            else:
                print_warning("No valid credentials found.")
        else:
            print_info_verbose("Password spraying completed successfully")
    except Exception as e:  # noqa: BLE001
        telemetry.capture_exception(e)
        if not SECRET_MODE:
            print_error("Error executing password spraying command.")
            print_warning(
                "No credentials were captured during spraying. Check the log above for signs of must-change accounts, "
                "logon failures, or connectivity issues."
            )
        else:
            print_exception(show_locals=False, exception=e)


def do_computer_pre2k_spraying(shell: SprayShell, domain: str) -> None:
    """Attempt pre2k password checks for computer accounts (hostname as password)."""
    from adscan_internal import print_operation_header
    from adscan_internal.cli.kerberos import ensure_kerberos_output_dir

    if not getattr(shell, "netexec_path", None):
        print_error(
            "NetExec is not installed or configured. Please run 'adscan install'."
        )
        return
    if not getattr(shell, "kerbrute_path", None):
        print_error(
            "kerbrute is not installed. Please run 'adscan install' to install it."
        )
        return

    marked_domain = mark_sensitive(domain, "domain")
    auth_mode = shell.domains_data.get(domain, {}).get("auth")
    if auth_mode != "auth":
        print_warning(
            f"Computer pre2k checks require an authenticated session for {marked_domain}."
        )
        return

    print_operation_header(
        "Computer Pre2k Check",
        details={
            "Domain": domain,
            "Method": "Kerberos LDAP",
            "Password Pattern": "hostname (lowercase, without $)",
        },
        icon="🖥️",
    )

    computer_sams = _load_enabled_computer_sams(shell, domain)
    if not computer_sams:
        print_warning("No enabled computers available for pre2k checks.")
        return

    print_info_debug(
        "[spray] launching computer pre2k check with "
        f"{len(computer_sams)} enabled computer account(s)."
    )

    if not should_proceed_with_repeated_spraying(shell, domain, "computer_pre2k", None):
        print_info("Computer pre2k check cancelled by user.")
        return

    safe_threshold = 2
    eligibility = compute_computer_spraying_eligibility(
        shell,
        domain=domain,
        computer_sams=computer_sams,
        safe_threshold=safe_threshold,
    )
    if eligibility is None:
        return

    if not _enforce_lockout_guardrail(
        domain=domain,
        eligibility=eligibility,
        prompt_text="Continue with computer pre2k checks using the full list?",
        default_confirm=False,
    ):
        print_info("Computer pre2k check cancelled by user.")
        return

    print_spraying_eligibility(shell, domain, eligibility)
    if not eligibility.eligible_users:
        print_warning("No eligible computer accounts available for pre2k checks.")
        return

    summary_lines = [
        f"Domain: {marked_domain}",
        f"Computers in list: {len(eligibility.input_users)}",
        f"Eligible computers: {len(eligibility.eligible_users)}",
        "Password pattern: hostname (lowercase, without $)",
    ]
    print_panel(
        "\n".join(summary_lines),
        title="[bold cyan]Pre2k Scan Plan[/bold cyan]",
        border_style="cyan",
        expand=False,
    )

    pdc_ip = shell.domains_data.get(domain, {}).get("pdc")
    kerberos_output_dir = ensure_kerberos_output_dir(shell, domain)
    combos = [f"{sam}:{sam.rstrip('$').lower()}" for sam in eligibility.eligible_users]
    combos_path = write_temp_combo_file(combos, directory=kerberos_output_dir)

    try:
        output_file = os.path.join(
            "domains",
            domain,
            "kerberos",
            "auth_pre2k_spray.log",
        )
        kerbrute_cmd = build_kerbrute_bruteforce_command(
            kerbrute_path=shell.kerbrute_path,
            domain=domain,
            dc_ip=pdc_ip,
            combos_file=combos_path,
            output_file=output_file,
        )
        _mark_recommended_spraying_attempt(shell, domain, "computer_pre2k")
        _capture_spraying_ux_event(
            shell,
            "ctf_recommended_spraying_started"
            if str(getattr(shell, "type", "") or "").strip().lower() == "ctf"
            else "spraying_recommended_started",
            domain,
            extra={
                "category": "computer_pre2k",
                "spray_type": "Computer Pre2k",
            },
        )
        spraying_command(
            shell,
            kerbrute_cmd,
            domain,
            spray_type="Computer Pre2k",
            entry_label="Domain Users",
        )
    finally:
        try:
            os.remove(combos_path)
        except OSError:
            pass
