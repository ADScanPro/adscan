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
from typing import Callable, Protocol

from adscan_internal import (
    print_error,
    print_info,
    print_info_debug,
    print_info_table,
    print_info_verbose,
    print_instruction,
    print_success,
    print_warning,
    print_warning_debug,
    print_warning_verbose,
    telemetry,
)
from adscan_internal.cli.common import build_lab_event_fields
from adscan_internal.rich_output import (
    confirm_ask,
    mark_sensitive,
    print_exception,
    print_panel,
    print_table,
    questionary_select_index,
)
from adscan_internal.subprocess_env import command_string_needs_clean_env
from adscan_internal.text_utils import strip_ansi_codes
from adscan_internal.workspaces import domain_relpath, domain_subpath
from adscan_core.theme import ADSCAN_PRIMARY
from adscan_core.tui.progress_dashboard import (
    ProgressDashboard,
    ProgressDashboardConfig,
)
from adscan_core.tui.stream_runner import stream_command_lines
from adscan_internal.workspaces.computers import (
    count_enabled_computer_accounts,
    has_enabled_computer_list,
    load_enabled_computer_samaccounts,
)
from adscan_internal.services.credentials.privilege_role import (
    set_credential_origin as _set_credential_origin,
)
from adscan_internal.services.credentials.credential_origin import (
    ORIGIN_BLANK_PASSWORD,
    ORIGIN_COMPUTER_PRE2K,
    ORIGIN_CREDENTIAL_REUSE,
    ORIGIN_PASSWORD_SPRAY,
    ORIGIN_SPRAY,
    ORIGIN_USERNAME_AS_PASSWORD,
)
from adscan_internal.services.captured_credential_policy import classify_principal
from adscan_internal.services.compromise_class import CompromiseClass, PrivilegeTier
from adscan_internal.services.credential_harvest_classification import (
    classify_harvested_principal_tier,
    classify_harvested_principals_reach,
)
from adscan_internal.services.credential_harvest_record import HarvestedPrincipal
from adscan_internal.services.credential_harvest_store import append_harvest_records
from adscan_internal.cli.widgets.credential_harvest_panel import (
    build_credential_harvest_panel,
    offer_credential_harvest_actions,
)
from rich.markup import escape as _rich_markup_escape
from rich.prompt import Confirm, Prompt
from rich.table import Table

# Import from internal spraying module
from adscan_internal.spraying import (
    SprayEligibilityResult,
    build_kerbrute_command,
    build_kerbrute_bruteforce_command,
    compute_spray_eligibility,
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


def _build_lockout_context_from_eligibility(
    eligibility: "SprayEligibilityResult | None",
) -> dict[str, object] | None:
    """Return a lockout-context dict the hits panel can render inline.

    The hits panel surfaces this as a status-bar-style reminder so the
    operator does not have to mentally hold the threshold across a
    multi-minute spray (tui-design § Principle 6, Contextual Intelligence).
    """
    if eligibility is None:
        return None
    notes = getattr(eligibility, "notes", []) or []
    no_lockout = any("no lockout" in str(note).lower() for note in notes)
    return {
        "threshold": getattr(eligibility, "lockout_threshold", None),
        "minimum_remaining": getattr(
            eligibility, "minimum_remaining_attempts", None
        ),
        "safe_reserve": getattr(eligibility, "safe_remaining_threshold", None),
        "no_lockout": no_lockout,
    }


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
    return sorted(
        deduped.values(), key=lambda item: str(item.get("username") or "").lower()
    )


def handle_validated_domain_hits_followup(
    shell: SprayShell,
    *,
    domain: str,
    hits: list[dict[str, object]],
    source_steps: list[object] | None = None,
    discovery_label: str = "validated",
    credential_origin: str = ORIGIN_SPRAY,
) -> bool:
    """Handle post-validation UX for confirmed domain credentials.

    This centralizes the post-hit flow shared by spraying and SAM->Domain reuse:
    store credentials, classify Tier-0/high-value users, offer attack paths, and
    optionally enumerate selected users when no path is available.

    Args:
        credential_origin: Specific provenance slug for the validated hits
            (e.g. ``useraspass``, ``blankpassword``, ``credential_reuse``).
            Defaults to the generic ``spray`` slug; spray callers pass the
            mode-specific origin so the Provenance column differentiates by
            spray type.
    """
    from adscan_internal.cli.attack_path_execution import (
        offer_attack_paths_for_execution_for_principals,
    )
    from adscan_internal.services.credential_store_service import CredentialStoreService
    from rich.prompt import Confirm

    normalized_hits = _normalize_validated_domain_hits(shell, hits)
    if not normalized_hits:
        return False

    from adscan_internal.interaction import is_non_interactive as _is_non_interactive
    is_interactive = not _is_non_interactive(shell)
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
        # The store bypasses add_credential's provenance API, so tag the origin
        # explicitly to keep the Provenance column off "via unknown".
        _set_credential_origin(
            shell, domain=domain, username=user, origin=credential_origin
        )

    # Persist credentials to disk immediately so downstream attack-path execution
    # can always resolve the password even when the function returns early (e.g.
    # after offer_attack_paths_for_execution_for_principals succeeds).
    save_fn = getattr(shell, "save_workspace_data", None)
    if callable(save_fn):
        try:
            save_fn()
        except Exception:  # noqa: BLE001
            pass

    # Build a classified HarvestedPrincipal record for EVERY validated hit —
    # covering all three tiers (user Tier-0/high-value AND machine-account
    # Tier 1), routed through the shared classification SSOT (Task 3). This
    # fixes the pre-existing gap where the bespoke user-only classifier never
    # graded machine-account harvests. Reach (axis 2) is computed once in a
    # single batched attack-path call.
    usernames = [str(hit.get("username") or "") for hit in normalized_hits]
    reach_by_user = classify_harvested_principals_reach(
        shell, domain=domain, usernames=usernames
    )
    harvest_records: list[HarvestedPrincipal] = []
    for hit in normalized_hits:
        user = str(hit.get("username") or "")
        if not user:
            continue
        account_type = classify_principal(user, shell.domains_data, domain)
        tier = classify_harvested_principal_tier(
            shell, domain=domain, username=user, account_type=account_type
        )
        # ``tier`` / ``reach`` may be None (UNDETERMINED — no membership/graph
        # data yet); persist None so the row renders "Unknown" / "Not assessed"
        # rather than a false Tier 2 / Standard reach.
        reach = reach_by_user.get(user.strip().lower())
        harvest_records.append(
            HarvestedPrincipal(
                domain=domain,
                username=user,
                source="spraying",
                account_type=account_type,
                ntlm_version="",
                crack_status="captured",
                privilege_tier=tier.value if tier is not None else None,
                compromise_reach=reach.value if reach is not None else None,
                hash_file="",
                captured_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            )
        )

    if harvest_records:
        append_harvest_records(shell, harvest_records)
        console = getattr(shell, "console", None)
        if console is not None:
            console.print(build_credential_harvest_panel(harvest_records))

    harvest_by_user = {r.username: r for r in harvest_records}
    _neutral_record = HarvestedPrincipal(
        domain=domain,
        username="",
        source="",
        account_type="user",
        ntlm_version="",
        crack_status="captured",
        privilege_tier=PrivilegeTier.TIER2.value,
        compromise_reach=CompromiseClass.NONE.value,
        hash_file="",
        captured_at="",
    )
    privileged_hits = [
        hit
        for hit in normalized_hits
        if harvest_by_user.get(
            str(hit.get("username") or ""), _neutral_record
        ).privilege_tier
        in (
            PrivilegeTier.TIER0_DIRECT.value,
            PrivilegeTier.TIER0_ESCALATION_CAPABLE.value,
        )
    ]

    if privileged_hits:
        # The shared actions helper (Task 6) now owns the select -> add_credential
        # -> pivot UX centrally, non-interactive-safe. If it authenticated the
        # domain as one of these principals, stop here.
        offer_credential_harvest_actions(shell, domain, harvest_records)
        auth_state_after = shell.domains_data.get(domain, {}).get("auth", "")
        if auth_state_after in {"auth", "pwned"}:
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
        # Canonical CLI/client mode: terminate at the domain object
        # ("Domain Compromised") and preserve relevant paths. ``tier0`` (the
        # function default) collapses short paths into kill-chains and can hide
        # them — object mode is the standard for the post-hit display (shared by
        # spraying and SAM->Domain reuse). See skill adscan-attack-paths-debug.
        target_mode="object",
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
                credential_origin=credential_origin,
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
            user_options = [
                str(hit.get("username") or "") for hit in normalized_hits
            ] + ["Cancel"]
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
                user_options = [
                    str(hit.get("username") or "") for hit in normalized_hits
                ] + ["Cancel"]
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
                credential_origin=credential_origin,
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
            credential_origin=credential_origin,
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

    def spawn_command(self, command, **kwargs) -> subprocess.Popen[str] | None: ...

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
_DEFAULT_MULTI_SPRAY_RESERVE = 2
_MAX_MULTI_SPRAY_PREVIEW = 10
_ADAPTIVE_YEAR_SUMMARY_PREVIEW_PER_YEAR = 5

LOCKOUT_FREE_VARIATION_SPRAY_ENABLED: bool = True

# Substrings marking an EXPECTED authentication negative -- the normal outcome of
# spraying a wrong/blank password (a rejected credential), NOT a tool or transport
# error. Such a line may still contain the words "failed"/"error" (e.g.
# "KDC_ERR_PREAUTH_FAILED", "authentication failed"), so a naive substring grep
# false-positives on every empty spray. These must never be surfaced as errors.
_EXPECTED_SPRAY_AUTH_NEGATIVE_MARKERS: tuple[str, ...] = (
    "kdc_err_preauth_failed",
    "preauth failed",
    "preauth_failed",
    "authentication failed",
    "logon failure",
    "logon_failure",
    "status_logon_failure",
    "kdc_err_c_principal_unknown",  # account does not exist -- expected, not an error
    "kdc_err_client_revoked",  # account disabled/locked-out -- reported elsewhere
    "account_locked_out",
    "status_account_locked_out",
    "wrong password",
    "invalid credentials",
)


def _is_expected_spray_auth_negative(line: str) -> bool:
    """Return True when *line* is an expected auth negative, not a real error.

    A rejected credential (wrong/blank password, unknown/locked account) is the
    normal result of a spray and must never be reported as an error even though
    the underlying tool prints it with the words "failed"/"error".
    """
    lowered = line.lower()
    return any(marker in lowered for marker in _EXPECTED_SPRAY_AUTH_NEGATIVE_MARKERS)


def _genuine_spray_error_lines(output_lines: list[str]) -> list[str]:
    """Return only genuine tool/transport error lines from spray output.

    Keeps lines mentioning "error"/"failed" that are NOT an expected auth
    negative -- i.e. real failures the operator should see (connection refused,
    timeouts, unhandled tracebacks), never the routine rejected-credential lines
    an empty spray produces.
    """
    genuine: list[str] = []
    for line in output_lines:
        lowered = line.lower()
        if "error" not in lowered and "failed" not in lowered:
            continue
        if _is_expected_spray_auth_negative(line):
            continue
        genuine.append(line)
    return genuine


@dataclass(frozen=True, slots=True)
class _BatchPasswordCombo:
    """One username/password combo in a batched Kerbrute bruteforce plan."""

    username: str
    password: str
    base_password: str
    mode: str
    pwdlastset_year: int | None = None


@dataclass(frozen=True, slots=True)
class _BatchPasswordSprayPlan:
    """Execution plan for one batched multi-password Kerbrute bruteforce run."""

    combos: tuple[_BatchPasswordCombo, ...]
    base_passwords: tuple[str, ...]
    adaptive_base_passwords: tuple[str, ...]
    flat_base_passwords: tuple[str, ...]


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


def _pre2k_already_attempted(shell: SprayShell, domain: str) -> bool:
    """True when a computer-pre2k spray was already attempted in THIS workspace.

    pre2k is intentionally excluded from the unified per-(user, password) spray
    history (one trivial credential per machine — not worth per-combo dedup), so
    its "attempted" state lives as a domain-level marker in the spraying UX state
    (``recommended_attempted_categories``), which is persisted in ``domains_data``
    and therefore survives leaving and re-entering the workspace. This is the
    single source of truth both the Step-1 pre2k runner and the pre2k follow-up
    consult so pre2k is never silently re-offered/re-sprayed across sessions.
    """
    ux_state = _get_spraying_ux_state(shell, domain)
    attempted = ux_state.get("recommended_attempted_categories")
    return isinstance(attempted, list) and "computer_pre2k" in attempted


def _get_enabled_computer_account_count(shell: SprayShell, domain: str) -> int | None:
    """Return the enabled computer count for the domain, or None when unavailable."""

    workspace_cwd = shell.current_workspace_dir or os.getcwd()
    try:
        count = count_enabled_computer_accounts(
            workspace_cwd, shell.domains_dir, domain
        )
    except OSError as exc:
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            "[spray] Unable to count enabled computers for "
            f"{marked_domain}: {mark_sensitive(str(exc), 'detail')}"
        )
        return None

    marked_domain = mark_sensitive(domain, "domain")
    print_info_debug(f"[spray] enabled computer count for {marked_domain}: {count}")
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


def _pre2k_followup_is_actionable(shell: SprayShell, domain: str) -> bool:
    """Return True only when a pre2k computer follow-up can actually run.

    This is STRICTER than ``_should_recommend_pre2k_for_ctf`` (which gates the
    general spraying hint that also covers username-as-password and is valid
    unauthenticated). The pre2k computer check has two hard preconditions in
    ``do_computer_pre2k_spraying``: an authenticated session, and known enabled
    computer accounts to spray. Mirror both here so the follow-up is never
    offered when it cannot possibly succeed.

    - No authenticated session (e.g. a ``start_unauth`` flow) -> suppress; pre2k
      would immediately fail with "requires an authenticated session".
    - Enabled-computer count UNAVAILABLE (no ``enabled_computers.txt`` because
      nothing was collected) -> suppress. "Unavailable" means "no computers
      known", not "probably many" — do NOT fail open here.
    - One or zero enabled computers -> suppress (nothing meaningful to spray).
    """

    if shell.domains_data.get(domain, {}).get("auth") != "auth":
        print_info_debug(
            "[spray] pre2k follow-up gate: disabled because there is no "
            "authenticated session (pre2k computer checks require auth)."
        )
        return False

    count = _get_enabled_computer_account_count(shell, domain)
    if count is None:
        print_info_debug(
            "[spray] pre2k follow-up gate: disabled because the enabled computer "
            "count is unavailable (no computers collected)."
        )
        return False
    if count <= 1:
        print_info_debug(
            "[spray] pre2k follow-up gate: disabled because there is "
            f"only {count} enabled computer account."
        )
        return False
    return True


def maybe_offer_ctf_pre2k_followup(
    shell: SprayShell, domain: str, *, reason: str
) -> None:
    """Offer a focused pre2k follow-up when it was skipped so far."""

    if shell.domains_data.get(domain, {}).get("auth") == "pwned":
        return
    if not _pre2k_followup_is_actionable(shell, domain):
        return

    if _pre2k_already_attempted(shell, domain):
        # Persisted across workspace re-entry (UX-state marker — pre2k is excluded
        # from the per-(user, password) history on purpose). This is the store
        # do_computer_pre2k_spraying actually writes to, so the dedup is real.
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
    if (
        bool(ux_state.get("pre2k_followup_prompted", False))
        and not repeat_on_explicit_user_skip
    ):
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
                "This is often a high-value foothold path when multiple computer accounts exist.",
                "",
                "Recommended focused action:",
                "Run only the pre2k computer check now.",
            ]
        ),
        title="[bold yellow]Recommended Follow-up: Pre2k[/bold yellow]",
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
    """Show one-time spraying recommendation when no recommended spraying was attempted."""
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
    workspace_type = str(getattr(shell, "type", "") or "").strip().lower()
    panel_lines = [
        f"Domain: {marked_domain}",
        (
            "In many HTB/CTF environments, a first foothold comes from spraying."
            if workspace_type == "ctf"
            else "An early foothold often comes from targeted spraying checks."
        ),
        "",
        "High-value quick checks:",
        "1) Computer accounts (pre2k: hostname as password)",
        "2) Username as password (normal/lower/upper variants)",
        "",
        f"Run now: spraying {domain}",
    ]
    print_panel(
        "\n".join(panel_lines),
        title=(
            "[bold yellow]Recommended CTF Next Step[/bold yellow]"
            if workspace_type == "ctf"
            else "[bold yellow]Recommended Next Step[/bold yellow]"
        ),
        border_style="yellow",
        expand=False,
    )
    if workspace_type == "ctf":
        print_instruction(
            "If you skip spraying in CTF, you can miss the intended foothold path."
        )
    else:
        print_instruction(
            "If you skip spraying here, you can miss an early foothold path."
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
    if not print_spraying_eligibility(shell, domain, eligibility):
        print_info("Password spraying cancelled by user.")
        return None
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


def _parse_kerbrute_valid_login_line(line: str) -> tuple[str, str] | None:
    """Extract ``(username, password)`` from one kerbrute ``VALID LOGIN`` line.

    Single source of truth for parsing kerbrute ``passwordspray`` /
    ``bruteforce`` hits, used by BOTH the live streaming counter and the
    authoritative end-of-run hit collection so they never diverge. kerbrute
    wraps the line in ANSI colour codes and a log prefix, e.g. (ESC literal):
        \x1b[32m2026/... >  [+] VALID LOGIN:\t user@domain.local:Password1\x1b[0m
    The ``VALID LOGIN:`` marker survives the colour codes; the trailing
    ``user@domain:password`` is split off it.

    Args:
        line: One kerbrute output line (ANSI codes tolerated).

    Returns:
        ``(username, password)`` when the line is a VALID LOGIN with a
        non-empty username, else ``None``.
    """
    stripped = strip_ansi_codes(line).strip()
    if "VALID LOGIN" not in stripped:
        return None
    try:
        creds = stripped.split("VALID LOGIN:")[1].strip()
        user_domain, password = creds.split(":", 1)
        username = user_domain.split("@")[0].strip()
    except (IndexError, ValueError):
        return None
    if not username:
        return None
    return username, password


# kerbrute prints (with ``-v``) one ``[!] user@domain:pw - reason`` line per
# attempted-but-failed login and one ``[+] VALID LOGIN`` line per hit. Counting
# both gives a DETERMINATE ``tested / N`` bar. The ``:`` after the ``user@dom``
# token (the password) plus the ``@`` distinguish a login attempt line from
# banner / ``Done!`` noise.
_KERBRUTE_INVALID_LOGIN_MARKER = "[!]"
_KERBRUTE_VALID_LOGIN_MARKER = "VALID LOGIN"


def _is_kerbrute_login_attempt_line(line: str) -> bool:
    """True if ``line`` is one attempted-login log line (valid OR invalid).

    Drives the determinate spray ``tested / N`` counter. An attempt line is a
    ``[+] VALID LOGIN`` hit or a ``[!] user@domain:pw - <reason>`` miss (both
    emitted under ``-v``); both carry an ``@`` token. Banner / ``Using KDC(s)``
    / ``Done!`` lines have no ``@`` token and are excluded.

    Args:
        line: One raw kerbrute output line (ANSI codes tolerated).

    Returns:
        True when the line represents exactly one tested login.
    """
    text = strip_ansi_codes(line)
    if "@" not in text:
        return False
    if _KERBRUTE_VALID_LOGIN_MARKER in text:
        return True
    if _KERBRUTE_INVALID_LOGIN_MARKER in text:
        return True
    return False


def _count_spray_attempt_total(command: str) -> int | None:
    """Best-effort count of the logins a kerbrute spray will attempt.

    Used as the determinate bar's ``total``. kerbrute spray commands carry the
    input file (userlist for ``passwordspray``, ``user:pass`` combos for
    ``bruteforce``, or the userlist after ``--user-as-pass``) as a positional
    token; its line count is exactly how many logins kerbrute will try. We
    shlex-split the command and count the lines of the first existing-file
    token that is not the ``-o`` output file. Fully defensive: any failure
    returns ``None`` so the dashboard degrades to the indeterminate "found N"
    spinner rather than showing a wrong total.

    Args:
        command: The full kerbrute spray command string.

    Returns:
        The attempt count (>0), or ``None`` when it cannot be determined.
    """
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    if not tokens:
        return None

    # kerbrute spray flags that take a VALUE -- the token after each is an
    # argument, never the positional input file (so it must be skipped). ``-o``
    # is the output file; ``-d``/``--dc``/``-t``/``--delay`` are config values.
    _value_flags = {"-o", "-d", "--dc", "-t", "--delay", "--downgrade"}
    skip_next = False
    # Token 0 is the kerbrute executable (an existing file on disk!) and token 1
    # is the subcommand -- never the input wordlist. Start scanning after them.
    for idx in range(2, len(tokens)):
        tok = tokens[idx]
        if skip_next:
            skip_next = False
            continue
        if not tok:
            continue
        if tok.startswith("-"):
            if tok in _value_flags:
                skip_next = True
            continue
        # A positional token: candidate input file. Count its non-blank lines,
        # but only if it actually looks like a text wordlist (the FIRST 4KB
        # decode cleanly as UTF-8) -- this rejects a binary mis-token and the
        # password positional (which is not a path).
        try:
            if not os.path.isfile(tok):
                continue
            with open(tok, "rb") as bf:
                head = bf.read(4096)
            try:
                head.decode("utf-8")
            except UnicodeDecodeError:
                continue  # binary file (e.g. mis-tokenised) -- not a wordlist.
            with open(tok, encoding="utf-8", errors="strict") as fh:
                n = sum(1 for line in fh if line.strip())
            if n > 0:
                return n
        except (OSError, UnicodeDecodeError):
            continue
    return None


# Number of most-recent VALID logins to show in the spray dashboard's
# bounded "recent found" window. DISPLAY cap only -- every hit is still
# parsed from the full stdout and persisted to the credential store.
_SPRAY_RECENT_HITS = 15
# Bounded concurrency for the native (kerbad) blank-password spray. Each eligible
# user gets ONE empty-password AS-REQ; the cap keeps big user bases fast without
# flooding the KDC. Matches the conservative sweep concurrency used elsewhere.
_BLANK_SPRAY_CONCURRENCY = 16
# Max rows shown per eligibility table (eligible / excluded) so a 1-2k-user domain
# does not flood the panel. The full counts are in the header; overflow is noted.
_ELIGIBILITY_TABLE_LIMIT = 20
# Conservative lockout threshold assumed for a user whose PSO is assigned but whose
# PSO OBJECT cannot be read (no access to the Password Settings Container). With the
# 2-attempt safety margin this caps such users at a SINGLE spray attempt — safe even
# if their real (unknown) PSO threshold is as low as 3. Privileged Tier-0 accounts
# are exactly the ones behind unreadable PSOs, so erring safe here is mandatory.
_UNREADABLE_PSO_FALLBACK_THRESHOLD = 3


def _build_spray_dashboard(spray_label: str, total: int | None = None) -> ProgressDashboard:
    """Spray dashboard driven by kerbrute's streaming stdout.

    kerbrute buffers its ``-o`` file but flushes one log line per attempted
    login to stdout in real time (with ``-v``), so streaming stdout drives a
    live counter. Two modes, selected by ``total``:

    * **Determinate** (``total`` = number of logins kerbrute will attempt): a
      real ``tested / N`` bar + rate + ETA, ticked from the per-attempt lines,
      with valid hits surfaced in the success-counter row.
    * **Indeterminate** (``total is None``): spinner + elapsed + "found N
      logins", ticked from ``[+] VALID LOGIN`` hits only.

    Args:
        spray_label: Human-readable label for the panel title.
        total: Login-attempt count for the determinate bar, or ``None``.

    Returns:
        A configured :class:`ProgressDashboard`.
    """
    return ProgressDashboard(
        ProgressDashboardConfig(
            title=f"Password Spraying · {spray_label}",
            total=total if (total and total > 0) else None,
            unit="logins",
            last_item_type="user",
            # Bounded rolling list of the most-recent VALID logins -- a valid
            # user+password is the high-value spray finding, so surface them
            # LIVE. The deque(maxlen=K) cap holds the panel at a fixed height
            # even with hundreds of hits (CLAUDE.md stable-line-count rule).
            # DISPLAY-ONLY: every hit is still parsed + persisted to the
            # credential store below.
            recent_max=_SPRAY_RECENT_HITS,
            recent_item_type="user",
            recent_label="found",
        )
    )


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
    risk_flags: dict[str, object] | None = None,
    lockout_context: dict[str, object] | None = None,
    domain: str | None = None,
) -> None:
    """Render a concise, action-oriented panel listing the discovered spray hits.

    Args:
        hits: List of hit dicts with at minimum ``username`` and ``password`` keys.
        spray_type: Human-readable spray method label (e.g. ``"Custom Password"``).
        risk_flags: Optional pre-computed risk flags keyed by lower-cased username.
            Each value must expose ``.is_tier0`` and ``.is_high_value`` attributes.
            When provided, each row gains a privilege badge (Tier-0 / High-Value /
            Standard).  Pass ``None`` (default) when classification data is not
            available at the call site — the column is omitted in that case.
        lockout_context: Optional dict with lockout posture state to surface
            inline as a status-bar-style reminder under the hits table. Keys:
            ``threshold`` (int|None), ``minimum_remaining`` (int|None),
            ``safe_reserve`` (int|None), ``no_lockout`` (bool).
        domain: Domain the spray was executed against. Interpolated into the
            ``attack_paths {domain} owned`` follow-up hint so the operator can
            copy-paste it verbatim. When ``None``, the literal ``<domain>``
            placeholder is shown — never the bare ``attack_paths owned`` form,
            which the CLI would parse as ``domain=owned`` and fail.
    """
    from adscan_core.theme import COLOR_AMBER, COLOR_CRIMSON, COLOR_SAGE
    from adscan_internal.rich_output import print_panel
    from rich.table import Table
    from rich.text import Text

    # ── Zero-hits path — dim informational panel ──────────────────────────────
    if not hits:
        print_panel(
            "[dim]No valid credentials found for this spray attempt.[/dim]\n"
            "[dim]Adjust the password list, wait for the observation window to "
            "reset, or try a different spray type.[/dim]",
            title="[dim]Spraying Results — No Hits[/dim]",
            border_style="dim",
            expand=False,
        )
        return

    # ── Sorting: Tier-0 first, High-Value second, Standard last ──────────────
    _rf = risk_flags or {}

    def _sort_key(item: dict[str, str]) -> tuple[int, str]:
        ukey = str(item.get("username") or "").strip().lower()
        flags = _rf.get(ukey)
        if flags is not None:
            if getattr(flags, "is_tier0", False):
                return (0, ukey)
            if getattr(flags, "is_high_value", False):
                return (1, ukey)
        return (2, ukey)

    hits_sorted = sorted(hits, key=_sort_key)
    total = len(hits_sorted)
    _DISPLAY_LIMIT = 5
    display_hits = hits_sorted[:_DISPLAY_LIMIT]

    # ── Build table ───────────────────────────────────────────────────────────
    # Hierarchy beyond color (tui-design § Visual Hierarchy):
    # privilege class is encoded by glyph + text + color + row weight so the
    # signal survives monochrome terminals and red/green color-blindness.
    show_privilege_col = bool(_rf)
    table = Table(
        show_header=True,
        header_style=f"bold {COLOR_SAGE}",
        show_lines=True,
        box=None,
    )
    table.add_column("#", style="dim", width=4, justify="right")
    if show_privilege_col:
        table.add_column("Privilege", width=16)
    table.add_column("Username")
    table.add_column("Method", style="dim")
    table.add_column("Credential")

    # Track the highest-priority class found across ALL hits (not just the
    # truncated display window) so the contextual footer in § Next surfaces
    # the right next-action even when Tier-0 sits beyond the display cap.
    top_class = "standard"
    for hit in hits_sorted:
        ukey = str(hit.get("username") or "").strip().lower()
        flags = _rf.get(ukey)
        if flags is not None and getattr(flags, "is_tier0", False):
            top_class = "tier0"
            break
        if flags is not None and getattr(flags, "is_high_value", False):
            top_class = "high_value"

    for idx, hit in enumerate(display_hits, start=1):
        user = str(hit.get("username") or "")
        password = str(hit.get("password") or "")
        cred_label = (
            "Blank password"
            if spray_type == "Blank Password" or password == ""
            else "Password accepted"
        )

        row_class = "standard"
        if show_privilege_col:
            ukey = user.strip().lower()
            flags = _rf.get(ukey)
            if flags is not None and getattr(flags, "is_tier0", False):
                # Glyph ▲ + text + crimson so the badge reads identically
                # in monochrome and to red/green color-blind operators.
                priv_badge = Text("▲ TIER-0", style=f"bold {COLOR_CRIMSON}")
                row_class = "tier0"
            elif flags is not None and getattr(flags, "is_high_value", False):
                priv_badge = Text("◆ HIGH VALUE", style=f"bold {COLOR_AMBER}")
                row_class = "high_value"
            else:
                priv_badge = Text("· Standard", style="dim")

        # Visual weight per row — bold for Tier-0, normal for high-value,
        # dim for standard. This restores hierarchy when color is stripped.
        if row_class == "tier0":
            user_text = Text(mark_sensitive(user, "user"), style=f"bold {COLOR_CRIMSON}")
            cred_text = Text(cred_label, style="bold yellow")
            num_text = Text(str(idx), style=f"bold {COLOR_CRIMSON}")
        elif row_class == "high_value":
            user_text = Text(mark_sensitive(user, "user"), style="bold")
            cred_text = Text(cred_label, style="yellow")
            num_text = Text(str(idx), style="bold")
        else:
            user_text = Text(mark_sensitive(user, "user"))
            cred_text = Text(cred_label, style="yellow")
            num_text = Text(str(idx), style="dim")

        if show_privilege_col:
            table.add_row(
                num_text,
                priv_badge,
                user_text,
                spray_type or "Password spray",
                cred_text,
            )
        else:
            table.add_row(
                num_text,
                user_text,
                spray_type or "Password spray",
                cred_text,
            )

    # ── Panel title — hit count prominent, color-coded ────────────────────────
    panel_title = Text()
    # ✓ glyph so the success signal survives mono / no-color rendering.
    panel_title.append(
        f" ✓ {total} valid credential{'' if total == 1 else 's'} found ",
        style=f"bold {COLOR_SAGE}",
    )

    footer_lines: list[str] = []
    if total > _DISPLAY_LIMIT:
        footer_lines.append(
            f"[dim]Showing {_DISPLAY_LIMIT} of {total}. "
            f"Run [bold]creds show[/bold] to view all stored credentials.[/dim]"
        )
    if spray_type == "Blank Password":
        footer_lines.append(
            "[dim]These accounts authenticated with a blank password — "
            "credentials stored as empty-password entries.[/dim]"
        )

    # ── Status-bar-style lockout reminder (tui-design Principle 6) ────────────
    # The eligibility panel is shown once upfront; after a multi-minute spray
    # the operator no longer recalls the threshold. Surface it inline.
    if lockout_context:
        try:
            no_lockout_flag = bool(lockout_context.get("no_lockout"))
            threshold_val = lockout_context.get("threshold")
            min_remaining = lockout_context.get("minimum_remaining")
            safe_reserve = lockout_context.get("safe_reserve")
            if no_lockout_flag:
                footer_lines.append(
                    "[dim]Lockout: [/dim]"
                    f"[{COLOR_SAGE}]✓ none enforced[/{COLOR_SAGE}] [dim]· spray may continue freely[/dim]"
                )
            elif isinstance(threshold_val, int) and threshold_val > 0:
                if isinstance(min_remaining, int):
                    if min_remaining <= 1:
                        rem_style = COLOR_CRIMSON
                        rem_glyph = "!"
                    elif min_remaining <= 3:
                        rem_style = COLOR_AMBER
                        rem_glyph = "⚠"
                    else:
                        rem_style = COLOR_SAGE
                        rem_glyph = "✓"
                    reserve_str = (
                        f" · reserve {safe_reserve}"
                        if isinstance(safe_reserve, int) and safe_reserve > 0
                        else ""
                    )
                    footer_lines.append(
                        "[dim]Lockout: [/dim]"
                        f"[{rem_style}]{rem_glyph} {min_remaining} attempts left per account[/{rem_style}]"
                        f" [dim]· threshold {threshold_val}{reserve_str}[/dim]"
                    )
                else:
                    footer_lines.append(
                        f"[dim]Lockout: threshold {threshold_val} · per-account remaining unknown[/dim]"
                    )
        except Exception:  # noqa: BLE001
            pass

    # ── Context-aware Next action (tui-design Principle 6) ────────────────────
    # The operator's next move depends on what was captured. A static
    # "attack_paths or enum" line treats all outcomes equally and wastes
    # the highest-leverage moment of the run.
    #
    # IMPORTANT — CLI syntax: `attack_paths` requires the domain as the
    # FIRST positional argument. The previous strings here used invented
    # second positionals ("tier0", "highvalue") that the CLI would parse
    # as a username and reject. Real flags are `--tier0-only` (for Tier-0
    # targets) and the default (high-value targets). For "lateral / pivot
    # without escalation" use `--lowpriv`.
    domain_token = (domain or "").strip() or "<domain>"
    if top_class == "tier0":
        footer_lines.append(
            f"[bold {COLOR_CRIMSON}]▶ Next:[/bold {COLOR_CRIMSON}] "
            "[dim]Tier-0 credential captured — pivot immediately with "
            f"[bold]attack_paths {domain_token} owned --tier0-only[/bold] or run "
            "[bold]enum[/bold] on the Tier-0 user to confirm DA rights.[/dim]"
        )
    elif top_class == "high_value":
        footer_lines.append(
            f"[bold {COLOR_AMBER}]▶ Next:[/bold {COLOR_AMBER}] "
            "[dim]High-value account captured — review "
            f"[bold]attack_paths {domain_token} owned[/bold] for escalation routes.[/dim]"
        )
    elif show_privilege_col:
        footer_lines.append(
            f"[{COLOR_SAGE}]▶ Next:[/{COLOR_SAGE}] "
            "[dim]Standard accounts captured — run "
            f"[bold]attack_paths {domain_token} owned[/bold] to look for derived control, "
            "or [bold]enum[/bold] to expand reach.[/dim]"
        )
    else:
        # No classification available — keep the previous neutral guidance.
        footer_lines.append(
            f"[{COLOR_SAGE}]▶ Next:[/{COLOR_SAGE}] "
            "[dim]Review attack paths with [bold]attack_paths[/bold] "
            "or pivot with [bold]enum[/bold] on a high-value account.[/dim]"
        )

    content_parts: list[object] = [table]
    if footer_lines:
        content_parts.append(Text.from_markup("\n" + "\n".join(footer_lines)))

    print_panel(
        content_parts,
        title=panel_title,
        border_style=COLOR_SAGE,
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
    run_validated_hits_followup: bool = True,
) -> None:
    """Persist spray hits and record related attack-graph provenance."""
    from adscan_internal.services.attack_graph_service import (
        record_credential_source_steps,
        upsert_domain_password_reuse_edges,
        upsert_password_spray_entry_edge,
    )
    from adscan_internal.services.share_credential_provenance_service import (
        ShareCredentialProvenanceService,
    )

    typed_source_steps = _extract_typed_source_steps(source_steps)
    share_provenance_service = ShareCredentialProvenanceService()
    artifact_source_steps = (
        share_provenance_service.build_password_artifact_source_steps(
            source_context=source_context,
            spray_type=spray_type,
            secret=None,
            verified_via="spraying",
        )
    )
    hits_sorted = sorted(hits, key=lambda item: str(item.get("username", "")).lower())

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
        if artifact_source_steps:
            try:
                typed_artifact_source_steps = []
                for step in artifact_source_steps:
                    notes = getattr(step, "notes", None)
                    copied_notes = dict(notes) if isinstance(notes, dict) else {}
                    if password or allow_empty_credential:
                        copied_notes["password"] = password
                    typed_artifact_source_steps.append(
                        type(step)(
                            relation=getattr(step, "relation", "PasswordInFile"),
                            edge_type=getattr(step, "edge_type", "file_password"),
                            entry_label=getattr(step, "entry_label", "Domain Users"),
                            entry_kind=getattr(step, "entry_kind", ""),
                            notes=copied_notes,
                            record_on_failure=getattr(step, "record_on_failure", False),
                        )
                    )
                record_credential_source_steps(
                    shell,
                    domain,
                    username=username,
                    status="success",
                    steps=typed_artifact_source_steps,
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_info_debug(
                    "[spray] Failed to record artifact/share credential provenance edge (continuing)."
                )

    # Mint a Kerberos TGT for every validated hit as soon as the
    # credential is confirmed. Without this, downstream operations that
    # later need to authenticate as the new principal call the LDAP
    # transport with ``username + password + ccache=None``; the
    # transport then silently falls back to ``KRB5CCNAME`` (carrying the
    # ccache of an earlier principal) and binds as the WRONG user.
    # Observed on HTB Puppy 2026-05-21: post-spray ``enable_user`` ran
    # as LEVI.JAMES instead of the just-sprayed ant.edwards, and the
    # modify was rejected with ``insufficientAccessRights`` because
    # LEVI.JAMES had no GenericAll over the target. Minting the TGT
    # here writes the ccache to the canonical per-user location
    # (``<workspace>/domains/<domain>/kerberos/tickets/<user>.ccache``),
    # which ``ensure_user_ccache`` and ``KerberosTicketService.get_ticket_for_user``
    # both consult first — closing the hijack without any change to the
    # downstream call sites.
    #
    # Best-effort: minting is wrapped in try/except so a Kerberos AS-REQ
    # failure (e.g. KDC unreachable, clock skew not yet synced) does
    # NOT block the spray success — the credential is still recorded
    # and the downstream caller falls back to fresh AS-REQ via the
    # LDAP transport's password slot.
    try:
        from adscan_internal.services.kerberos_ticket_service import (
            ensure_user_ccache,
        )

        for hit in hits_sorted:
            username = str(hit.get("username") or "").strip()
            password = str(hit.get("password") or "")
            if not username or not password:
                continue
            try:
                ticket_path = ensure_user_ccache(
                    shell,
                    user=username,
                    domain=domain,
                    credential=password,
                    force_refresh=True,
                )
                if ticket_path:
                    print_info_debug(
                        "[spray] minted TGT for sprayed credential: "
                        f"user={mark_sensitive(username, 'user')} "
                        f"domain={mark_sensitive(domain, 'domain')}"
                    )
                else:
                    print_info_debug(
                        "[spray] TGT mint returned no ticket path; "
                        "downstream auth will fall back to AS-REQ via the "
                        f"LDAP password slot. user={mark_sensitive(username, 'user')}"
                    )
            except Exception as mint_exc:  # noqa: BLE001 — best-effort
                telemetry.capture_exception(mint_exc)
                print_info_debug(
                    f"[spray] TGT mint raised for {mark_sensitive(username, 'user')}: "
                    f"{type(mint_exc).__name__}: {mint_exc}. Downstream auth will "
                    "fall back to fresh AS-REQ via the LDAP password slot."
                )
    except ImportError:
        # ensure_user_ccache lives in the runtime image; the public
        # repo strip may exclude it. Falling back silently is correct —
        # the LDAP transport's password slot handles the AS-REQ on
        # demand, just without the per-user ccache reuse benefit.
        pass

    # Differentiate the persisted provenance by spray TYPE so the Provenance
    # column shows the specific mode (username-as-password / blank / pre2k /
    # custom) instead of a generic "spray".
    spray_credential_origin = _spray_origin_for_type(spray_type)

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
                credential_origin=spray_credential_origin,
            )
        return

    if run_validated_hits_followup:
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
            credential_origin=spray_credential_origin,
        )


def validate_domain_reuse_with_ntlm_hash(
    shell: SprayShell,
    *,
    domain: str,
    nt_hash: str,
    eligibility: SprayEligibilityResult | None = None,
) -> dict[str, object]:
    """Validate SAM-derived credential reuse against domain accounts using NTLM hash spray."""
    from adscan_internal.services.credential_store_service import CredentialStoreService

    normalized_hash = str(nt_hash or "").strip()
    marked_domain = mark_sensitive(domain, "domain")
    result: dict[str, object] = {
        "status": "error",
        "method": "native_ntlm_hash",
        "credential_type": "hash",
        "credential": normalized_hash,
        "attempted_users": 0,
        "hits": [],
        "outcome_counts": {},
        "error": None,
    }

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

    eligible_users = list(effective_eligibility.eligible_users)
    result["attempted_users"] = len(eligible_users)
    if not eligible_users:
        result["status"] = "no_hits"
        return result

    from adscan_internal.models.domain import resolve_dc_ip
    from adscan_internal.services.domain_posture import get_posture

    domain_data = shell.domains_data.get(domain, {}) or {}
    dc_ip = resolve_dc_ip(domain_data) or domain_data.get("pdc")
    if not dc_ip:
        message = "Cannot resolve the domain controller IP for the hash-reuse spray."
        print_warning(f"Skipping domain reuse validation in {marked_domain}: {message}")
        result["error"] = message
        return result
    posture_snapshot = get_posture(shell.domains_data, domain=domain)

    # Mass-auth safety (sweep_credential SSOT): pass-the-hash reuse validation
    # tests MANY domain principals — each eligible user tried ONCE with the SAME
    # NT hash — against the single DC. That is NOT one owned principal across many
    # hosts, so ``resolve_sweep_credential``'s single-TGT pre-mint does not apply
    # (there is no one principal to mint for). The hash flows through the canonical
    # single-attempt verifier (``_run_native_domain_spray`` →
    # ``CredentialService._verify_via_kerberos``), which makes exactly ONE
    # credential-checking auth per user with NO NTLM<->Kerberos re-attempt — so
    # each user's badPwdCount rises at most once, the same lockout-safety invariant
    # the native password spray relies on.
    import asyncio

    try:
        hits, outcomes = asyncio.run(
            _run_native_domain_spray(
                domain=domain,
                dc_ip=str(dc_ip),
                users=eligible_users,
                password=normalized_hash,
                posture_snapshot=posture_snapshot,
                credential_type="hash",
            )
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        result["error"] = str(exc)
        return result

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
        # NTLM-hash reuse spray bypasses add_credential; tag the provenance.
        _set_credential_origin(
            shell, domain=domain, username=username, origin=ORIGIN_CREDENTIAL_REUSE
        )

    result["status"] = "success" if hits else "no_hits"
    return result


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
            # Cleartext SAM->domain reuse bypasses add_credential; tag the
            # provenance as credential reuse (not a generic spray).
            _set_credential_origin(
                shell, domain=domain, username=username, origin=ORIGIN_CREDENTIAL_REUSE
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
) -> tuple[
    list[dict[str, object]], dict[str, dict[str, object]], list[dict[str, object]]
]:
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

        outcome_summary = _summarize_outcomes_for_table(
            outcomes, excluded_codes={"SUCCESS"}
        )
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

    Schema (v2 — granular per (domain, user, password)):
        {
            "<domain>": {
                "<user_lower>": {
                    "<password>": {
                        "first_run": str,   # ISO 8601 UTC
                        "last_run":  str,   # ISO 8601 UTC
                        "count":     int,
                        "modes":     ["password" | "variation" | "adaptive_year"
                                       | "useraspass" | "useraspass_lower"
                                       | "useraspass_upper" | "batch", ...]
                    }
                }
            }
        }

    Persisted via ``adscan_internal/workspaces/state.py`` so repeats are
    detected across sessions, not just within one. ``user_lower`` is the
    sAMAccountName casefolded for case-insensitive matching; the password
    is stored verbatim.
    """
    history = getattr(shell, "password_spraying_history", None)
    if not isinstance(history, dict):
        history = {}
        shell.password_spraying_history = history
    return history


def register_user_spray_attempts(
    shell: SprayShell,
    *,
    domain: str,
    combos: list[tuple[str, str]],
    mode: str,
) -> None:
    """Record N (user, password) attempts in the workspace-persisted history.

    Idempotent: re-registering the same combo bumps count + last_run and
    appends the mode to the entry's mode list (deduplicated). Empty
    usernames or passwords are silently skipped — the caller should not
    pass them but defensive filtering keeps the helper safe.
    """
    try:
        history = get_password_spraying_history(shell)
        now_iso = datetime.now(timezone.utc).isoformat()
        for username, password in combos:
            if not username or not password:
                continue
            domain_history = history.setdefault(domain, {})
            user_lower = str(username).casefold()
            user_entry = domain_history.setdefault(user_lower, {})
            pwd_entry = user_entry.setdefault(password, None)
            if pwd_entry is None or not isinstance(pwd_entry, dict):
                user_entry[password] = {
                    "first_run": now_iso,
                    "last_run": now_iso,
                    "count": 1,
                    "modes": [mode],
                }
            else:
                pwd_entry["count"] = int(pwd_entry.get("count", 0)) + 1
                pwd_entry["last_run"] = now_iso
                existing_modes = pwd_entry.get("modes")
                if not isinstance(existing_modes, list):
                    pwd_entry["modes"] = [mode]
                elif mode not in existing_modes:
                    existing_modes.append(mode)
    except Exception as exc:
        telemetry.capture_exception(exc)


def find_already_attempted_combos(
    shell: SprayShell,
    *,
    domain: str,
    combos: list[tuple[str, str]],
) -> dict[tuple[str, str], dict]:
    """Return {combo: history_entry} for combos that have an entry in history.

    Lookup is case-insensitive on user, case-sensitive on password.
    """
    try:
        history = get_password_spraying_history(shell)
        domain_history = history.get(domain, {})
        result: dict[tuple[str, str], dict] = {}
        for username, password in combos:
            if not username or not password:
                continue
            user_lower = str(username).casefold()
            user_entry = domain_history.get(user_lower)
            if not isinstance(user_entry, dict):
                continue
            pwd_entry = user_entry.get(password)
            if isinstance(pwd_entry, dict):
                result[(username, password)] = pwd_entry
        return result
    except Exception as exc:
        telemetry.capture_exception(exc)
        return {}


# Blank-password sprays cannot be tracked by the granular (user, password)
# history because ``register_user_spray_attempts`` skips empty passwords. Store
# them under a reserved sentinel password so blank coverage de-dups uniformly
# through the SAME history dict (no parallel store).
BLANK_PASSWORD_SENTINEL = "\x00<blank>"


def register_blank_spray_attempts(shell: SprayShell, *, domain: str, users: list[str]) -> None:
    """Record blank-password sprays via the sentinel so blank coverage is tracked."""
    register_user_spray_attempts(
        shell,
        domain=domain,
        combos=[(u, BLANK_PASSWORD_SENTINEL) for u in users if u],
        mode="blank",
    )


def blank_already_attempted(
    shell: SprayShell, *, domain: str, users: list[str]
) -> set[str]:
    """Return the casefolded usernames already sprayed with a blank password."""
    found = find_already_attempted_combos(
        shell,
        domain=domain,
        combos=[(u, BLANK_PASSWORD_SENTINEL) for u in users if u],
    )
    return {str(u).casefold() for (u, _p) in found}


def confirm_with_history_check(
    shell: SprayShell,
    *,
    domain: str,
    proposed_combos: list[tuple[str, str]],
    mode_label: str,
    multi_combo: bool = False,
) -> list[tuple[str, str]] | None:
    """Check history; if any proposed combos are repeats, prompt the operator.

    Returns the combos that should actually be sprayed, or None if the
    operator cancelled.

    UX:
      - No repeats:  return proposed_combos as-is (no panel shown).
      - Repeats and multi_combo == False:  yellow panel listing N
        already-attempted users + last_run summary, then a binary
        Confirm.ask (default=False). Returns proposed_combos if accepted,
        None if not.
      - Repeats and multi_combo == True:  yellow panel showing repeat
        count + a 3-way questionary.select:
            (1) Spray everything (force re-test) [default]
            (2) Skip already-tested combos
            (3) Cancel
        Returns proposed_combos for (1), filtered list for (2),
        None for (3).
    """
    try:
        already_tried = find_already_attempted_combos(
            shell, domain=domain, combos=proposed_combos
        )
        if not already_tried:
            return proposed_combos

        marked_domain = mark_sensitive(domain, "domain")
        repeat_count = len(already_tried)
        lines: list[str] = [
            f"Domain: {marked_domain}",
            f"Spray type: {mode_label}",
            f"Proposed combos: {len(proposed_combos)}",
            f"Already attempted: {repeat_count}",
        ]

        # Show last_run for up to 5 repeat entries
        sample = list(already_tried.items())[:5]
        if sample:
            lines.append("")
            lines.append("Sample of repeated combos (user / last seen):")
            for (username, _password), entry in sample:
                last_run = entry.get("last_run", "unknown")
                lines.append(f"  {mark_sensitive(username, 'user')} — {last_run}")
            if repeat_count > 5:
                lines.append(f"  ... and {repeat_count - 5} more")

        lines.append("")
        lines.append(
            "Repeating the same spraying may increase the risk of account lockouts "
            "or violate password policy guidance."
        )
        lines.append(
            "Only continue if you are sure this is allowed and expected for your engagement."
        )

        print_panel(
            "\n".join(lines),
            title="[bold yellow]Repeated Password Spraying Detected[/bold yellow]",
            border_style="yellow",
            expand=False,
        )

        if not multi_combo:
            proceed = Confirm.ask(
                "Do you still want to continue with this spray?",
                default=False,
            )
            return proposed_combos if proceed else None

        # 3-way choice for multi-combo modes
        _CHOICE_SPRAY_ALL = "Spray everything (force re-test)"
        _CHOICE_SKIP = "Skip already-tested combos"
        _CHOICE_CANCEL = "Cancel"

        select_fn = getattr(shell, "_questionary_select", None)
        if callable(select_fn):
            choice_idx = select_fn(
                "How do you want to proceed?",
                [_CHOICE_SPRAY_ALL, _CHOICE_SKIP, _CHOICE_CANCEL],
                default_idx=0,
            )
            if choice_idx is None:
                return None
            choice = [_CHOICE_SPRAY_ALL, _CHOICE_SKIP, _CHOICE_CANCEL][choice_idx]
        else:
            # Non-interactive fallback: default to spray all
            choice = _CHOICE_SPRAY_ALL

        if choice == _CHOICE_CANCEL:
            return None
        if choice == _CHOICE_SKIP:
            filtered = [c for c in proposed_combos if c not in already_tried]
            return filtered if filtered else None
        return proposed_combos
    except Exception as exc:
        telemetry.capture_exception(exc)
        # If history check fails, do not block spraying
        return proposed_combos


def _compute_spray_eligibility_pso_aware(
    *,
    file_users: list[str],
    badpwd_by_user: dict[str, int],
    default_threshold: int | None,
    pso_threshold_by_user: dict[str, int | None],
    safe_remaining_threshold: int,
    no_lockout_enforced: bool,
    locked_users: set[str] | None = None,
    pso_source_by_user: dict[str, str] | None = None,
) -> SprayEligibilityResult:
    """Compute spray eligibility using per-user PSO-effective lockout thresholds.

    For users with a PSO assigned, the PSO's lockoutThreshold overrides the
    domain default.  Users without a PSO fall back to the domain default.
    ``pso_source_by_user`` maps a user to a human-readable lockout-policy source
    (e.g. ``"PSO 'TIER0'"`` or ``"PSO 'TIER0' unreadable"``) for the eligibility UX.
    """
    from adscan_internal.spraying import EligibleUser, ExcludedUser  # noqa: PLC0415

    notes: list[str] = []
    eligible: list[str] = []
    excluded: list[ExcludedUser] = []
    eligible_details: list[EligibleUser] = []
    pso_source = pso_source_by_user or {}

    def _policy_note(norm: str, threshold: "int | None") -> "str | None":
        """Per-user lockout-policy label for the eligibility panel (None = domain)."""
        source = pso_source.get(norm)
        if not source or source == "domain":
            return None
        return f"{source} · thr {threshold}" if threshold is not None else source

    if no_lockout_enforced:
        notes.append("No lockout enforced (threshold=0 or None). All users eligible.")
        return SprayEligibilityResult(
            input_users=list(file_users),
            eligible_users=list(file_users),
            excluded_users=[],
            lockout_threshold=default_threshold,
            safe_remaining_threshold=safe_remaining_threshold,
            minimum_remaining_attempts=None,
            used_policy_data=False,
            notes=notes,
            no_lockout_enforced=True,
            eligible_details=[EligibleUser(username=u) for u in file_users],
        )

    pso_users = sum(1 for u in pso_threshold_by_user if u in badpwd_by_user)
    if pso_users:
        notes.append(
            f"PSO-aware eligibility: {pso_users} user(s) have a fine-grained "
            "password policy that overrides the domain default."
        )
    n_unreadable_pso = sum(
        1
        for u in file_users
        if "unreadable" in (pso_source.get(u.strip().lower()) or "")
    )
    if n_unreadable_pso:
        notes.append(
            f"{n_unreadable_pso} user(s) have a PSO whose object could not be read "
            f"(no access to the Password Settings Container) — a conservative "
            f"lockout threshold of {_UNREADABLE_PSO_FALLBACK_THRESHOLD} was assumed "
            "so they are capped at a single attempt (cannot accidentally lock a "
            "stricter Tier-0 account)."
        )

    minimum_remaining: int | None = None
    locked_lower = locked_users or set()
    if locked_lower:
        notes.append(
            f"{sum(1 for u in file_users if u.strip().lower() in locked_lower)} "
            "account(s) excluded as currently LOCKED OUT (lockoutTime set)."
        )

    for user in file_users:
        norm = user.strip().lower()
        # Currently locked-out accounts reset badPwdCount to 0, so they look
        # 'eligible' — but spraying them is pointless and extends the lockout.
        if norm in locked_lower:
            excluded.append(
                ExcludedUser(
                    username=user,
                    reason="Account locked out",
                    badpwd_count=badpwd_by_user.get(norm),
                    remaining_attempts=0,
                )
            )
            continue
        effective_threshold = pso_threshold_by_user.get(norm, default_threshold)
        if effective_threshold is None:
            # No threshold data — include conservatively
            eligible.append(user)
            eligible_details.append(
                EligibleUser(username=user, policy_note=_policy_note(norm, None))
            )
            continue

        badpwd = badpwd_by_user.get(norm)
        if badpwd is None:
            excluded.append(
                ExcludedUser(
                    username=user, reason="No BadPwdCount data (safer to skip)"
                )
            )
            continue

        src = pso_source.get(norm) or "domain"
        remaining = effective_threshold - badpwd
        if remaining > safe_remaining_threshold:
            eligible.append(user)
            eligible_details.append(
                EligibleUser(
                    username=user,
                    badpwd_count=badpwd,
                    remaining_attempts=remaining,
                    policy_note=_policy_note(norm, effective_threshold),
                )
            )
            minimum_remaining = (
                remaining
                if minimum_remaining is None
                else min(minimum_remaining, remaining)
            )
        else:
            excluded.append(
                ExcludedUser(
                    username=user,
                    reason=(
                        f"Too close to lockout (remaining={remaining}, "
                        f"{src} threshold={effective_threshold})"
                    ),
                    badpwd_count=badpwd,
                    remaining_attempts=remaining,
                )
            )

    return SprayEligibilityResult(
        input_users=list(file_users),
        eligible_users=eligible,
        excluded_users=excluded,
        lockout_threshold=default_threshold,
        safe_remaining_threshold=safe_remaining_threshold,
        minimum_remaining_attempts=minimum_remaining,
        used_policy_data=True,
        notes=notes,
        eligible_details=eligible_details,
    )


def _exclude_locked_from_result(
    result: "SprayEligibilityResult | None", locked_users: set[str]
) -> "SprayEligibilityResult | None":
    """Move currently locked-out accounts from eligible -> excluded on a result.

    Universal post-step so the locked exclusion applies regardless of which
    eligibility split produced the result (the PSO-aware path is only taken when
    PSO objects are readable; when ``pso_count`` is 0 — e.g. the spray user cannot
    read the PSO container — the non-PSO core split runs instead). Idempotent: a
    locked user already in ``excluded`` is left as-is.
    """
    if not locked_users or result is None:
        return result
    from dataclasses import replace  # noqa: PLC0415

    from adscan_internal.spraying import ExcludedUser  # noqa: PLC0415

    locked = {str(u).casefold() for u in locked_users}
    kept = [u for u in result.eligible_users if str(u).casefold() not in locked]
    if len(kept) == len(result.eligible_users):
        return result  # none of the eligible are locked
    newly_excluded = [
        ExcludedUser(
            username=u,
            reason="Account locked out",
            badpwd_count=None,
            remaining_attempts=0,
        )
        for u in result.eligible_users
        if str(u).casefold() in locked
    ]
    # SprayEligibilityResult is frozen — rebuild via replace().
    return replace(
        result,
        eligible_users=kept,
        eligible_details=[
            e
            for e in result.eligible_details
            if str(e.username).casefold() not in locked
        ],
        excluded_users=list(result.excluded_users) + newly_excluded,
    )


@dataclass(frozen=True)
class LockoutAuthorityTarget:
    """Where to READ account-lockout counters (badPwdCount / observation window).

    Scope-aware DC/PDC selection (2026-07-12): when the operator knowingly kept
    a non-PDC replica as the operational DC (``lockout_authority == "replica"``),
    the replica's local badPwdCount can lag the PDC and read stale-low — spraying
    off it risks locking live accounts. This resolves the read target:

    * ``read_ip`` — the IP to read lockout counters from. The true PDC when it is
      reachable-for-reads (even if out of scope for active auth); otherwise the
      operational DC.
    * ``kerberos_hostname`` — the FQDN for the LDAP service SPN when ``read_ip``
      is the authoritative PDC (a Kerberos read against an IP with the wrong SPN
      fails; see CLAUDE.md "Kerberos SPNs — always FQDN").
    * ``is_authoritative_pdc`` — True when the read is redirected to the true PDC.
    * ``conservative`` — True when the domain is on a replica AND the true PDC is
      NOT reachable-for-reads: the caller MUST spray conservatively (strict
      exclude of unknown counts, at most one attempt per window) or skip.

    The OPERATIONAL auth attempts (the actual spray + LDAP/SMB) still go to the
    chosen operational DC — only the *counting read* is authoritative-sourced.
    """

    read_ip: str | None
    kerberos_hostname: str | None
    is_authoritative_pdc: bool
    conservative: bool


def _tcp_reachable_for_ldap_reads(ip: str, timeout: float = 2.0) -> bool:
    """Best-effort sync check that ``ip`` accepts an LDAP(S) connection.

    Tries LDAPS (636) then LDAP (389), mirroring the transport's LDAPS→LDAP
    fallback. "Reachable for reads" means either port completes a TCP connect —
    the PDC can be out of scope for active auth yet still answer read-only
    lockout queries. Never raises; a filtered PDC simply reads unreachable.
    """
    import socket  # noqa: PLC0415

    for port in (636, 389):
        sock = None
        try:
            sock = socket.create_connection((ip, port), timeout=timeout)
            return True
        except OSError:
            continue
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    return False


def resolve_lockout_authority_ip(
    shell: SprayShell, domain: str
) -> LockoutAuthorityTarget:
    """Resolve where to read account-lockout counters for spray safety.

    See :class:`LockoutAuthorityTarget`. Redirects the lockout-accounting read to
    the true PDC when the operator overrode the operational DC with a replica and
    the PDC is reachable-for-reads; otherwise signals conservative mode (or the
    normal operational DC when no override is in effect).
    """
    from adscan_internal.models.domain import resolve_dc_ip  # noqa: PLC0415

    domain_info = shell.domains_data.get(domain, {}) or {}
    operational_ip = resolve_dc_ip(domain_info) or domain_info.get("pdc")

    authority = str(domain_info.get("lockout_authority", "")).strip().lower()
    if authority != "replica":
        # No override: the operational DC IS the lockout authority (unchanged
        # behaviour for every existing workspace / non-override path).
        return LockoutAuthorityTarget(
            read_ip=operational_ip,
            kerberos_hostname=None,
            is_authoritative_pdc=False,
            conservative=False,
        )

    pdc_ip = str(domain_info.get("authoritative_pdc_ip") or "").strip() or None
    pdc_hostname = (
        str(domain_info.get("authoritative_pdc_hostname") or "").strip() or None
    )
    # A Kerberos read against the PDC needs its FQDN for the LDAP SPN. Without
    # both the PDC IP AND its FQDN we cannot safely redirect the (Kerberos) read
    # — fall to conservative mode rather than reading stale replica counters.
    if pdc_ip and pdc_hostname and _tcp_reachable_for_ldap_reads(pdc_ip):
        return LockoutAuthorityTarget(
            read_ip=pdc_ip,
            kerberos_hostname=pdc_hostname,
            is_authoritative_pdc=True,
            conservative=False,
        )

    return LockoutAuthorityTarget(
        read_ip=operational_ip,
        kerberos_hostname=None,
        is_authoritative_pdc=False,
        conservative=True,
    )


def maybe_gate_replica_spraying(shell: SprayShell, domain: str) -> bool:
    """Spray-entry safety gate for a replica-DC override (2026-07-12).

    When the operator kept a non-PDC replica as the operational DC, decide how
    spraying should proceed based on whether the true PDC is reachable for
    lockout reads:

    * PDC reachable-for-reads → confirmation toast (mockup C); spraying stays
      lockout-safe because the counting reads redirect to the PDC. Proceeds.
    * PDC unreachable-for-reads → persistent posture panel (mockup B) + an
      explicit confirm (default No). Only a knowing "yes" proceeds — otherwise
      spraying is skipped to protect live accounts. Non-interactive runs
      auto-resolve to No (skip), so ``adscan ci`` never sprays off an
      unverified replica.

    Returns True to proceed with spraying, False to abort. A no-op (returns
    True) for every non-override domain, keeping the normal path unchanged.
    """
    domain_info = shell.domains_data.get(domain, {}) or {}
    if str(domain_info.get("lockout_authority", "")).strip().lower() != "replica":
        return True

    shown = getattr(shell, "_spray_replica_gate_shown", None)
    if not isinstance(shown, set):
        shown = set()
        shell._spray_replica_gate_shown = shown

    target = resolve_lockout_authority_ip(shell, domain)
    operational_ip = domain_info.get("pdc")
    pdc_ip = domain_info.get("authoritative_pdc_ip")
    marked_op = (
        mark_sensitive(str(operational_ip), "ip") if operational_ip else "the scan DC"
    )
    marked_pdc = mark_sensitive(str(pdc_ip), "ip") if pdc_ip else "the PDC"

    if target.is_authoritative_pdc:
        # Mockup C — reachable PDC, once per domain.
        if domain not in shown:
            print_success(
                f"Using {marked_op} as the scan DC. Lockout counters will be read "
                f"from the PDC {marked_pdc} (reachable for reads), so spraying "
                "stays lockout-safe."
            )
            shown.add(domain)
        return True

    # Conservative mode — the true PDC is out of scope AND not reachable for
    # reads (or unknown). Render the posture panel (mockup B) once per domain,
    # then require an explicit acknowledgement every time before spraying.
    if domain not in shown:
        print_panel(
            "[bold]This scan uses a replica Domain Controller. The PDC "
            "emulator is out of scope and not reachable for lockout reads.[/bold]"
            "\n\n"
            f"  Scan DC (replica)     {marked_op}\n"
            f"  PDC emulator          {marked_pdc}  [dim](unreachable)[/dim]\n\n"
            "badPwdCount on a replica can lag the PDC, so attempts-remaining may "
            "be optimistic. ADscan sprays at most one attempt per observation "
            "window and excludes any account whose count is unknown, to avoid "
            "locking out live accounts.\n\n"
            "  Mode                  conservative (replica-sourced counters)",
            title="[bold]⚠ Spraying against a replica DC[/bold]",
            border_style="yellow",
            padding=(1, 2),
        )
        shown.add(domain)

    proceed = confirm_ask(
        "Proceed with conservative spraying against the replica?",
        default=False,
    )
    if not proceed:
        print_warning(
            "Spraying skipped: on a replica DC with the PDC unreachable for "
            "lockout reads, ADscan will not spray to protect live accounts."
        )
        telemetry.capture(
            "spray_replica_gate",
            properties={"domain_scope": "replica", "action": "skipped"},
        )
        return False
    telemetry.capture(
        "spray_replica_gate",
        properties={"domain_scope": "replica", "action": "proceed_conservative"},
    )
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

    # Exclude already-owned principals from the spray set: spraying an account we
    # already control yields no new access, adds badPwdCount noise, and — because
    # authenticating as that account (e.g. password-policy enumeration) resets its
    # badPwdCount — would otherwise keep it perpetually "eligible" and re-sprayed.
    # Centralized here (the eligibility SSOT) so the spray, the coverage
    # denominator, and the selector all exclude owned users consistently.
    file_users = _drop_owned(shell, domain, file_users, context="eligibility")

    lockout_threshold = None
    badpwd_by_user = None
    no_lockout_enforced = False

    print_info_verbose(
        f"Starting spray eligibility computation for {marked_domain} "
        f"(safe remaining threshold={safe_threshold}, users in list={len(file_users)})."
    )

    # Captured once the native policy fetch succeeds; applied as a universal
    # post-step to whichever eligibility split runs (the PSO-aware split is only
    # reached when PSO objects are readable, so the non-PSO core split must exclude
    # locked accounts too). Empty for the NetExec fallback / no-policy paths.
    locked_users_for_result: set[str] = set()

    if is_auth:
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

        # --- Native LDAP path (badldap, PSO-aware) ---
        native_policy_ok = False
        try:
            from adscan_internal.services.spray_policy_service import (  # noqa: PLC0415
                fetch_spray_policy_sync,
            )
            from adscan_internal.services.ldap_transport_service import (  # noqa: PLC0415
                resolve_ldap_target_endpoints,
            )

            print_info_verbose("Fetching password policy via native LDAP...")
            ldap_endpoints = resolve_ldap_target_endpoints(
                target_domain=domain,
                domain_data=shell.domains_data.get(domain, {}),
                kerberos_ready=True,
            )
            # Scope-aware DC/PDC selection (2026-07-12): read lockout counters
            # from the true PDC when the operational DC is a replica override and
            # the PDC is reachable-for-reads. The operational auth still targets
            # the chosen DC — only this counting read is authority-sourced.
            lockout_target = resolve_lockout_authority_ip(shell, domain)
            spray_policy = fetch_spray_policy_sync(
                domain=domain,
                dc_ip=lockout_target.read_ip or pdc_ip,
                username=auth_username,
                password=auth_password,
                use_kerberos=True,
                kerberos_target_hostname=(
                    lockout_target.kerberos_hostname
                    if lockout_target.is_authoritative_pdc
                    else ldap_endpoints.kerberos_target_hostname
                ),
                auth_domain=auth_domain,
            )

            if not spray_policy.fetch_errors:
                locked_users_for_result = spray_policy.locked_users
                dp = spray_policy.default_policy
                lockout_threshold = dp.lockout_threshold
                no_lockout_enforced = dp.no_lockout_enforced or lockout_threshold == 0
                native_policy_ok = True

                pso_count = len(spray_policy.pso_by_dn)
                pso_assigned = len(spray_policy.pso_dn_by_user)
                if no_lockout_enforced:
                    print_info_verbose(
                        "Password policy: no lockout enforced (threshold=0 or None). "
                        "Spraying cannot lock accounts."
                    )
                elif lockout_threshold is not None:
                    pso_info = (
                        f", {pso_count} PSO(s) found ({pso_assigned} user(s) assigned)"
                        if pso_count
                        else ""
                    )
                    print_info_verbose(
                        f"Password policy: lockout threshold={lockout_threshold}"
                        f"{pso_info}."
                    )
                else:
                    print_warning_verbose(
                        "Password policy: lockout threshold unavailable from native LDAP."
                    )
                    native_policy_ok = False

                if native_policy_ok and not (
                    no_lockout_enforced or lockout_threshold == 0
                ):
                    if spray_policy.badpwd_by_user:
                        # Build effective per-user badPwdCount using PSO-aware thresholds
                        badpwd_by_user = {}
                        for u, count in spray_policy.badpwd_by_user.items():
                            badpwd_by_user[u] = count
                        print_info_verbose(
                            f"Fetched badPwdCount for {len(badpwd_by_user)} user(s)"
                            + (
                                f" (PSO-aware: {pso_assigned} users have fine-grained policy)"
                                if pso_assigned
                                else ""
                            )
                            + "."
                        )

                        # Per-user PSO-aware eligibility. Gated on pso_assigned (NOT
                        # pso_count): when a user has a PSO whose OBJECT we cannot
                        # read (no access to the Password Settings Container), we
                        # must NOT silently fall back to the domain threshold — a
                        # stricter PSO would be over-estimated and a spray could lock
                        # the account. lockout_threshold_with_source() returns the
                        # readable PSO threshold, or a conservative fallback for
                        # unreadable PSOs, plus a human-readable source for the UX.
                        if pso_assigned:
                            pso_effective: dict[str, int | None] = {}
                            pso_source: dict[str, str] = {}
                            for u in spray_policy.pso_dn_by_user:
                                thr, source, _is_fallback = (
                                    spray_policy.lockout_threshold_with_source(
                                        u,
                                        unreadable_pso_fallback=_UNREADABLE_PSO_FALLBACK_THRESHOLD,
                                    )
                                )
                                pso_effective[u] = thr
                                pso_source[u] = source

                            return _compute_spray_eligibility_pso_aware(
                                file_users=file_users,
                                badpwd_by_user=badpwd_by_user,
                                default_threshold=lockout_threshold,
                                pso_threshold_by_user=pso_effective,
                                safe_remaining_threshold=safe_threshold,
                                no_lockout_enforced=no_lockout_enforced,
                                locked_users=spray_policy.locked_users,
                                pso_source_by_user=pso_source,
                            )
                    else:
                        print_warning_verbose(
                            "Native LDAP returned policy but no badPwdCount data."
                        )
                        native_policy_ok = False
            else:
                print_warning_verbose(
                    f"Native policy fetch had errors: {'; '.join(spray_policy.fetch_errors)}. "
                    "Falling back to NetExec."
                )
        except Exception as _native_exc:  # noqa: BLE001
            telemetry.capture_exception(_native_exc)
            print_warning_verbose(
                f"Native policy fetch raised an exception: {_native_exc}. "
                "Falling back to NetExec."
            )

        if not native_policy_ok:
            # Native (LDAP) password-policy fetch failed. There is no NetExec
            # fallback here: the native path and NetExec both query the same DC
            # over LDAP, so a native failure almost always means the DC is
            # unreachable and NetExec would fail identically. Fail CLOSED —
            # compute_spray_eligibility(strict_missing_badpwd=True) below then
            # conservatively excludes users with unknown badPwdCount.
            print_warning_verbose(
                "Native password-policy fetch failed; account lockout policy and "
                "badPwdCount are unknown — excluding users conservatively."
            )
    else:
        if not is_auth:
            print_warning_verbose(
                f"Skipping password policy lookup for {marked_domain} because the "
                "current domain context is not authenticated."
            )

    return _exclude_locked_from_result(
        compute_spray_eligibility(
            file_users=file_users,
            lockout_threshold=lockout_threshold,
            badpwd_by_user=badpwd_by_user,
            safe_remaining_threshold=safe_threshold,
            no_lockout_enforced=no_lockout_enforced,
            strict_missing_badpwd=True,
        ),
        locked_users_for_result,
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
    """Compute eligible computer accounts for pre2k checks.

    The lockout policy and per-machine ``badPwdCount`` are read via native LDAP
    (``spray_policy_service``, the same PSO-aware, observation-window-reset path
    the user spray uses) — no subprocess. Machine accounts carry ``badPwdCount``
    and the live ``msDS-User-Account-Control-Computed`` UF_LOCKOUT bit exactly
    like user accounts, so the identical safety controls apply: near-lockout
    machines are excluded, currently-locked machines are dropped, and a failed
    policy fetch fails CLOSED via ``strict_missing_badpwd=True``.
    """
    lockout_threshold = None
    badpwd_by_user = None
    no_lockout_enforced = False
    locked_users_for_result: set[str] = set()

    auth_state = str(shell.domains_data[domain].get("auth", "")).strip().lower()
    is_auth = auth_state in {"auth", "pwned"}
    pdc_ip = shell.domains_data[domain]["pdc"]
    marked_domain = mark_sensitive(domain, "domain")

    print_info_verbose(
        f"Starting computer pre2k eligibility computation for {marked_domain} "
        f"(safe remaining threshold={safe_threshold}, computers={len(computer_sams)})."
    )

    if is_auth:
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

        native_policy_ok = False
        try:
            from adscan_internal.services.spray_policy_service import (  # noqa: PLC0415
                fetch_spray_policy_sync,
            )
            from adscan_internal.services.ldap_transport_service import (  # noqa: PLC0415
                resolve_ldap_target_endpoints,
            )

            print_info_verbose(
                "Fetching lockout policy + computer BadPwdCount via native LDAP..."
            )
            ldap_endpoints = resolve_ldap_target_endpoints(
                target_domain=domain,
                domain_data=shell.domains_data.get(domain, {}),
                kerberos_ready=True,
            )
            # Scope-aware DC/PDC selection (2026-07-12): redirect the lockout
            # counting read to the true PDC on a replica override (see the user
            # spray path above for the full rationale).
            lockout_target = resolve_lockout_authority_ip(shell, domain)
            spray_policy = fetch_spray_policy_sync(
                domain=domain,
                dc_ip=lockout_target.read_ip or pdc_ip,
                username=auth_username,
                password=auth_password,
                use_kerberos=True,
                kerberos_target_hostname=(
                    lockout_target.kerberos_hostname
                    if lockout_target.is_authoritative_pdc
                    else ldap_endpoints.kerberos_target_hostname
                ),
                auth_domain=auth_domain,
                account_scope="computer",
            )

            if not spray_policy.fetch_errors:
                locked_users_for_result = spray_policy.locked_users
                dp = spray_policy.default_policy
                lockout_threshold = dp.lockout_threshold
                no_lockout_enforced = (
                    dp.no_lockout_enforced or lockout_threshold == 0
                )
                native_policy_ok = True

                if no_lockout_enforced:
                    print_info_verbose(
                        "Password policy: no lockout enforced (threshold=0 or None). "
                        "Spraying cannot lock computer accounts."
                    )
                elif lockout_threshold is not None:
                    print_info_verbose(
                        f"Password policy: lockout threshold={lockout_threshold}."
                    )
                else:
                    print_warning_verbose(
                        "Password policy: lockout threshold unavailable from native LDAP."
                    )
                    native_policy_ok = False

                if native_policy_ok and not no_lockout_enforced:
                    if spray_policy.badpwd_by_user:
                        badpwd_by_user = dict(spray_policy.badpwd_by_user)
                        print_info_verbose(
                            f"Fetched BadPwdCount for {len(badpwd_by_user)} computer(s)."
                        )
                    else:
                        print_warning_verbose(
                            "Native LDAP returned policy but no computer BadPwdCount data."
                        )
                        native_policy_ok = False
            else:
                print_warning_verbose(
                    "Native policy fetch had errors: "
                    f"{'; '.join(spray_policy.fetch_errors)}."
                )
        except Exception as _native_exc:  # noqa: BLE001
            telemetry.capture_exception(_native_exc)
            print_warning_verbose(
                f"Native policy fetch raised an exception: {_native_exc}."
            )
            native_policy_ok = False

        if not native_policy_ok and not no_lockout_enforced:
            # Fail CLOSED: the native LDAP fetch failed, so lockout policy and
            # computer BadPwdCount are unknown. compute_spray_eligibility with
            # strict_missing_badpwd=True conservatively excludes machines with
            # unknown BadPwdCount below.
            print_warning_verbose(
                "Native lockout-policy fetch failed; account lockout policy and "
                "computer BadPwdCount are unknown — excluding conservatively."
            )
    else:
        print_warning_verbose(
            f"Skipping computer BadPwdCount lookup for {marked_domain} because the "
            "current domain context is not authenticated."
        )

    return _exclude_locked_from_result(
        compute_spray_eligibility(
            file_users=computer_sams,
            lockout_threshold=lockout_threshold,
            badpwd_by_user=badpwd_by_user,
            safe_remaining_threshold=safe_threshold,
            no_lockout_enforced=no_lockout_enforced,
            strict_missing_badpwd=True,
        ),
        locked_users_for_result,
    )


def print_spraying_eligibility(
    shell: SprayShell, domain: str, eligibility: SprayEligibilityResult
) -> bool:
    """Render eligibility info for spraying and confirm continuation when needed.

    Returns:
        bool: True when the calling flow should continue, False when the user
            cancels after reviewing excluded accounts.
    """
    from adscan_core.theme import COLOR_AMBER, COLOR_CRIMSON, COLOR_MUTED, COLOR_SAGE
    from rich.text import Text

    marked_domain = mark_sensitive(domain, "domain")
    threshold = eligibility.lockout_threshold

    # ── Lockout badge — the most safety-critical piece of information ─────────
    # Glyph-paired text (✓ / ⚠ / ! / ?) so the badge survives both monochrome
    # rendering and red/green color blindness (tui-design § Accessibility).
    no_lockout = any("no lockout" in note.lower() for note in eligibility.notes)
    if no_lockout or threshold == 0:
        lockout_badge = Text(
            " ✓ NO LOCKOUT ENFORCED — spray freely ",
            style=f"bold {COLOR_SAGE}",
        )
        lockout_border = COLOR_SAGE
    elif threshold is not None and threshold <= 3:
        lockout_badge = Text(
            f" ! LOCKOUT THRESHOLD: {threshold} — spray conservatively ",
            style=f"bold {COLOR_CRIMSON}",
        )
        lockout_border = COLOR_CRIMSON
    elif threshold is not None and threshold <= 10:
        lockout_badge = Text(
            f" ⚠ LOCKOUT THRESHOLD: {threshold} — moderate risk ",
            style=f"bold {COLOR_AMBER}",
        )
        lockout_border = COLOR_AMBER
    elif threshold is not None:
        lockout_badge = Text(
            f" ⚠ LOCKOUT THRESHOLD: {threshold} ",
            style=f"bold {COLOR_AMBER}",
        )
        lockout_border = COLOR_AMBER
    else:
        lockout_badge = Text(
            " ? LOCKOUT THRESHOLD: unknown — proceed with one password ",
            style=f"bold {COLOR_AMBER}",
        )
        lockout_border = COLOR_AMBER

    # ── Eligible / excluded counts ────────────────────────────────────────────
    n_eligible = len(eligibility.eligible_users)
    n_excluded = len(eligibility.excluded_users)
    n_total = len(eligibility.input_users)
    n_locked = sum(
        1 for e in eligibility.excluded_users if e.reason == "Account locked out"
    )

    eligible_text = Text()
    eligible_text.append("  Domain: ", style="dim")
    eligible_text.append(f"{marked_domain}\n", style="bold")
    eligible_text.append("  Target users: ", style="dim")
    eligible_text.append(
        f"{n_eligible} eligible",
        style=f"bold {COLOR_SAGE}" if n_eligible > 0 else f"bold {COLOR_CRIMSON}",
    )
    eligible_text.append(f" / {n_total} total", style="dim")
    if n_excluded > 0:
        if n_locked > 0:
            breakdown = f"{n_locked} locked out, {n_excluded - n_locked} near lockout"
        else:
            breakdown = "see table below"
        eligible_text.append(
            f"  ({n_excluded} excluded — {breakdown})",
            style=f" {COLOR_AMBER}",
        )
    eligible_text.append("\n")

    if eligibility.safe_remaining_threshold:
        eligible_text.append("  Safe-attempt reserve: ", style="dim")
        eligible_text.append(
            f"{eligibility.safe_remaining_threshold} attempt(s) held back per account\n",
            style="dim",
        )
    if eligibility.minimum_remaining_attempts is not None:
        eligible_text.append(
            "  Minimum remaining attempts (worst eligible account): ", style="dim"
        )
        remaining = eligibility.minimum_remaining_attempts
        remaining_style = (
            f"bold {COLOR_CRIMSON}"
            if remaining <= 1
            else (f"bold {COLOR_AMBER}" if remaining <= 3 else f"bold {COLOR_SAGE}")
        )
        eligible_text.append(f"{remaining}\n", style=remaining_style)

    if eligibility.notes:
        eligible_text.append("\n")
        for note in eligibility.notes:
            eligible_text.append(f"  {note}\n", style=f"dim {COLOR_MUTED}")

    panel_content: list[object] = [lockout_badge, Text(""), eligible_text]

    print_panel(
        panel_content,
        title="[bold]Spray Eligibility[/bold]",
        border_style=lockout_border,
        expand=False,
    )

    # ── Severe-action confirmation when remaining ≤ 1 ────────────────────────
    # Pattern from tui-design § Dialogs & Confirmation: severe actions
    # require resource-name input, not a y/n with default-true. One more
    # failure on the worst eligible account triggers lockout here.
    min_remaining = eligibility.minimum_remaining_attempts
    if (
        eligibility.used_policy_data
        and isinstance(min_remaining, int)
        and min_remaining <= 1
        and not getattr(shell, "auto", False)
        and threshold is not None
        and threshold > 0
    ):
        print_warning(
            f"Worst eligible account has only {min_remaining} attempt(s) before "
            f"lockout. One failed spray will lock at least one account."
        )
        try:
            confirmation = Prompt.ask(
                f"Type the domain name [bold]{domain}[/bold] to proceed, "
                f"or press Enter to abort",
                default="",
                show_default=False,
            )
        except (EOFError, KeyboardInterrupt):
            print_warning("Spray aborted (no confirmation received).")
            return False
        if (confirmation or "").strip().lower() != domain.strip().lower():
            print_warning(
                "Domain name not entered — aborting spray to protect eligible accounts."
            )
            return False

    # ── Eligible accounts table (these WILL be sprayed) ──────────────────────
    # Surfaced with the same shape as the excluded table so the operator can see
    # exactly which accounts get sprayed and their current lockout headroom — not
    # just the excluded ones. Capped + colour-coded (green) to distinguish from
    # the excluded (amber) table.
    if eligibility.eligible_users:
        from rich.box import MINIMAL as _BOX_MINIMAL
        from adscan_internal.spraying import EligibleUser as _EligibleUser

        elig_table = Table(
            title=Text(
                f"Eligible accounts ({n_eligible}) — these WILL be sprayed",
                style=f"dim {COLOR_SAGE}",
            ),
            show_lines=False,
            box=_BOX_MINIMAL,
            header_style="dim",
        )
        elig_table.add_column("User", style=COLOR_SAGE)
        elig_table.add_column("BadPwdCount", justify="right", style="dim")
        elig_table.add_column("Remaining", justify="right", style="dim")
        elig_table.add_column("Lockout policy", style="dim")

        elig_details = eligibility.eligible_details or [
            _EligibleUser(username=u) for u in eligibility.eligible_users
        ]
        elig_preview = elig_details[:_ELIGIBILITY_TABLE_LIMIT]
        for elig in elig_preview:
            marked_user = mark_sensitive(elig.username, "user")
            badpwd_str = (
                str(elig.badpwd_count) if elig.badpwd_count is not None else "-"
            )
            remaining_str = (
                str(elig.remaining_attempts)
                if elig.remaining_attempts is not None
                else "-"
            )
            # Non-domain (PSO) policy is highlighted; an unreadable PSO using the
            # conservative fallback is amber so it stands out as a safety estimate.
            policy = getattr(elig, "policy_note", None) or "domain"
            policy_style = (
                COLOR_AMBER
                if "unreadable" in policy
                else (COLOR_MUTED if policy == "domain" else COLOR_SAGE)
            )
            elig_table.add_row(
                marked_user,
                badpwd_str,
                remaining_str,
                Text(policy, style=policy_style),
            )
        print_table(elig_table)
        if len(elig_details) > len(elig_preview):
            print_info_verbose(
                f"Eligible users total: {len(elig_details)} "
                f"(showing first {len(elig_preview)})."
            )

    if eligibility.excluded_users:
        from rich.box import MINIMAL as _BOX_MINIMAL

        excl_table = Table(
            title=Text(
                f"Excluded accounts ({n_excluded}) — these will NOT be sprayed",
                style=f"dim {COLOR_AMBER}",
            ),
            show_lines=False,
            box=_BOX_MINIMAL,
            header_style="dim",
        )
        excl_table.add_column("User", style="dim")
        excl_table.add_column("Reason", style="dim")
        excl_table.add_column("BadPwdCount", justify="right", style="dim")
        excl_table.add_column("Remaining", justify="right", style="dim")

        preview = eligibility.excluded_users[:_ELIGIBILITY_TABLE_LIMIT]
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
            excl_table.add_row(marked_user, excluded.reason, badpwd_str, remaining_str)
        print_table(excl_table)
        if len(eligibility.excluded_users) > len(preview):
            print_info_verbose(
                f"Excluded users total: {len(eligibility.excluded_users)} "
                f"(showing first {len(preview)})."
            )
        if not eligibility.eligible_users:
            return True
        # Locked accounts are auto-excluded (they cannot be sprayed at all) — that
        # is not a decision the operator needs to confirm, so it must not trigger
        # the "continue?" prompt. Only prompt when accounts were held back for
        # SAFETY (near lockout / no policy data) — i.e. non-locked exclusions.
        non_locked_excluded = [
            e for e in eligibility.excluded_users if e.reason != "Account locked out"
        ]
        if not non_locked_excluded:
            return True
        if getattr(shell, "auto", False):
            print_info_debug(
                "[eligibility] Auto mode detected; continuing without excluded-user confirmation."
            )
            return True
        return bool(
            Confirm.ask(
                f"{len(non_locked_excluded)} account(s) were held back for safety "
                "(near lockout). Continue with the eligible users only?",
                default=True,
            )
        )
    return True



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

    if (
        eligibility.used_policy_data
        and eligibility.minimum_remaining_attempts is not None
    ):
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
        selected_items = [
            option_map[item] for item in selected_values if item in option_map
        ]
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


def _build_domain_reuse_selection_option(
    candidate: DomainReuseValidationCandidate,
) -> str:
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
                item
                if isinstance(item, (str, int, float, bool)) or item is None
                else str(item)
                for item in value
            ]
            continue
        if isinstance(value, dict):
            sanitized[str(key)] = {
                str(sub_key): (
                    sub_value
                    if isinstance(sub_value, (str, int, float, bool))
                    or sub_value is None
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
                source=_sanitize_spraying_context_for_json(
                    source if isinstance(source, dict) else {}
                ),
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
    removal_set = {
        str(password or "").strip()
        for password in passwords
        if str(password or "").strip()
    }
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
                    [
                        str(item).strip()
                        for item in source_hostnames_raw
                        if str(item).strip()
                    ]
                    if isinstance(source_hostnames_raw, list)
                    else []
                ),
                source_scope=str(entry.get("source_scope") or "").strip(),
                reason_not_validated=str(
                    entry.get("reason_not_validated") or ""
                ).strip(),
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
    from adscan_internal.services.scan_phases import phase_is_enabled

    if not phase_is_enabled(shell, "password_spraying"):
        print_info("Password Spraying skipped (disabled in scan configuration).")
        return
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
        # Phase 4 uses the coverage-driven continue-loop (maximum coverage for ci,
        # default-yes guided flow for interactive start). The legacy do_spraying
        # menu stays available for manual / power-user invocation.
        from adscan_internal.interaction import is_non_interactive

        run_spray_coverage(
            shell, domain, interactive=not is_non_interactive(shell)
        )
        return

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

    # Scope-aware DC/PDC selection (2026-07-12): when the operational DC is a
    # replica override, gate spraying on whether the true PDC is reachable for
    # lockout reads (toast when it is, conservative confirm/skip when it is not).
    if not maybe_gate_replica_spraying(shell, domain):
        return

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
    pending_candidates = _load_pending_spraying_password_candidates(
        shell, domain=domain
    )
    pending_domain_reuse_candidates = _load_pending_domain_reuse_candidates(
        shell, domain=domain
    )
    workspace_cwd = shell.current_workspace_dir or os.getcwd()
    ctf_mode = str(getattr(shell, "type", "") or "").strip().lower() == "ctf"
    pre2k_recommended = (
        _should_recommend_pre2k_for_ctf(shell, domain) if ctf_mode else True
    )
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
            (
                idx
                for idx, opt in enumerate(options)
                if opt == _SPRAYING_OPTION_COMPUTER_PRE2K
            ),
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

    if not print_spraying_eligibility(shell, domain, eligibility):
        print_info("Password spraying cancelled by user.")
        return

    if not eligibility.eligible_users:
        print_warning(
            "No eligible users available for spraying with the current safety rules."
        )
        return

    # History check uses (user, password) combos — computed now that we have eligible_users.
    # blank_password is excluded from history tracking.
    if spray_category != "blank_password":
        if spray_category == "password" and spray_password is not None:
            _proposed_combos = [(u, spray_password) for u in eligibility.eligible_users]
            _mode_label = "Specific password"
        elif spray_category == "useraspass":
            _proposed_combos = [(u, u) for u in eligibility.eligible_users]
            _mode_label = "Username as password"
        elif spray_category == "useraspass_lower":
            _proposed_combos = [(u, u.lower()) for u in eligibility.eligible_users]
            _mode_label = "Username as password (lowercase)"
        elif spray_category == "useraspass_upper":
            _proposed_combos = [(u, u.capitalize()) for u in eligibility.eligible_users]
            _mode_label = "Username as password (uppercase)"
        else:
            _proposed_combos = None
            _mode_label = None
        if _proposed_combos is not None and _mode_label is not None:
            _accepted = confirm_with_history_check(
                shell,
                domain=domain,
                proposed_combos=_proposed_combos,
                mode_label=_mode_label,
                multi_combo=False,
            )
            if _accepted is None:
                print_info("Password spraying cancelled by user.")
                return

    if spray_category == "password" and spray_password is not None:
        _spray_combos = [(u, spray_password) for u in eligibility.eligible_users]
        _execute_single_password_spraying(
            shell,
            domain=domain,
            password=spray_password,
            eligibility=eligibility,
        )
        register_user_spray_attempts(
            shell, domain=domain, combos=_spray_combos, mode="password"
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
            # Native blank-password sweep against the DC — one auth attempt per
            # eligible user (no NetExec subprocess). Uses the same eligible-user
            # set already gated by the lockout-safe eligibility computation.
            domain_spray_command(
                shell,
                list(eligibility.eligible_users),
                domain,
                password=spray_password or "",
                spray_type=spray_type,
            )
        else:
            if is_auth:
                password_fragment = (
                    safe_log_filename_fragment(spray_password)
                    if spray_password
                    else None
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
                    safe_log_filename_fragment(spray_password)
                    if spray_password
                    else None
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
            # Register per-(user, password) history for useraspass modes.
            if spray_category == "useraspass":
                register_user_spray_attempts(
                    shell,
                    domain=domain,
                    combos=[(u, u) for u in eligibility.eligible_users],
                    mode="useraspass",
                )
            elif spray_category == "useraspass_lower":
                register_user_spray_attempts(
                    shell,
                    domain=domain,
                    combos=[(u, u.lower()) for u in eligibility.eligible_users],
                    mode="useraspass_lower",
                )
            elif spray_category == "useraspass_upper":
                register_user_spray_attempts(
                    shell,
                    domain=domain,
                    combos=[(u, u.capitalize()) for u in eligibility.eligible_users],
                    mode="useraspass_upper",
                )
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
    _swp_combos = [(u, password) for u in eligibility.eligible_users]
    _swp_accepted = confirm_with_history_check(
        shell,
        domain=domain,
        proposed_combos=_swp_combos,
        mode_label="Specific password",
        multi_combo=False,
    )
    if _swp_accepted is None:
        print_info("Password spraying cancelled by user.")
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
    register_user_spray_attempts(
        shell, domain=domain, combos=_swp_combos, mode="password"
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
    offer_adaptive_year: bool = True,
    offer_variation_spray: bool = True,
) -> bool:
    """Execute one custom-password spray using a prevalidated eligibility set."""
    from adscan_internal.cli.kerberos import ensure_kerberos_output_dir
    from adscan_internal.services.password_year_variant_service import (
        extract_password_year_candidates,
    )

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
        auth_state = str(shell.domains_data[domain].get("auth", "")).strip().lower()
        output_file = os.path.join(
            "domains",
            domain,
            "kerberos",
            f"{'auth' if auth_state in {'auth', 'pwned'} else 'unauth'}_spray_"
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
        has_year_candidate = (
            offer_adaptive_year and len(extract_password_year_candidates(password)) == 1
        )
        _spray_lockout_ctx = _build_lockout_context_from_eligibility(eligibility)
        base_hits = execute_spraying_command(
            shell,
            kerbrute_cmd,
            domain,
            spray_type="Custom Password",
            entry_label=entry_label,
            source_context=source_context,
            source_steps=source_steps,
            persist_hits=not has_year_candidate,
            run_validated_hits_followup=not has_year_candidate,
            render_hits_panel=not has_year_candidate,
            lockout_context=_spray_lockout_ctx,
        )
        if not has_year_candidate:
            if offer_variation_spray and eligibility.no_lockout_enforced:
                _maybe_execute_lockout_free_variation_spraying(
                    shell,
                    domain=domain,
                    password=password,
                    eligibility=eligibility,
                    source_context=source_context,
                    source_steps=source_steps,
                )
            return True

        print_panel(
            "\n".join(
                [
                    f"Base password: {mark_sensitive(password, 'password')}",
                    f"Users tested: {len(eligibility.eligible_users)}",
                    f"Base spray hits: {len(base_hits)}",
                    f"Unmatched users: {max(len(eligibility.eligible_users) - len(base_hits), 0)}",
                ]
            ),
            title="[bold cyan]Base Spraying Result[/bold cyan]",
            border_style="cyan",
            expand=False,
        )

        # Offer variation spray first when applicable (audit + lockout=0).
        # Variation is more comprehensive than adaptive-year (it sweeps years
        # globally rather than per-user pwdLastSet), so when the operator
        # accepts it, adaptive-year is redundant and we skip it. When the
        # operator rejects variation OR the gate filters it out (CTF
        # workspace, lockout enforced, missing eligibility), the existing
        # adaptive-year flow runs as a fallback for year-tokenised bases.
        if offer_variation_spray and _maybe_execute_lockout_free_variation_spraying(
            shell,
            domain=domain,
            password=password,
            eligibility=eligibility,
            source_context=source_context,
            source_steps=source_steps,
        ):
            if base_hits:
                _render_valid_spray_hits_panel(
                    base_hits,
                    spray_type="Custom Password",
                    lockout_context=_spray_lockout_ctx,
                    domain=domain,
                )
                _persist_and_record_spray_hits(
                    shell,
                    domain=domain,
                    hits=base_hits,
                    spray_type="Custom Password",
                    entry_label=entry_label,
                    source_context=source_context,
                    source_steps=source_steps,
                )
            return True

        hit_users = {
            str(hit.get("username") or "").strip().casefold()
            for hit in base_hits
            if str(hit.get("username") or "").strip()
        }
        unmatched_users = [
            user
            for user in eligibility.eligible_users
            if str(user or "").strip() and str(user).strip().casefold() not in hit_users
        ]
        if not unmatched_users:
            if base_hits:
                _render_valid_spray_hits_panel(
                    base_hits,
                    spray_type="Custom Password",
                    lockout_context=_spray_lockout_ctx,
                    domain=domain,
                )
                _persist_and_record_spray_hits(
                    shell,
                    domain=domain,
                    hits=base_hits,
                    spray_type="Custom Password",
                    entry_label=entry_label,
                    source_context=source_context,
                    source_steps=source_steps,
                )
            return True

        followup_prompt_lines = [
            f"Base password hits: {len(base_hits)}",
            f"Unmatched users: {len(unmatched_users)}",
        ]
        followup_eligibility = eligibility
        if unmatched_users:
            subset_users_path = write_temp_users_file(
                unmatched_users,
                directory=kerberos_output_dir,
            )
            try:
                followup_eligibility = (
                    compute_spraying_eligibility(
                        shell,
                        domain=domain,
                        user_list_file=subset_users_path,
                        safe_threshold=eligibility.safe_remaining_threshold,
                    )
                    or eligibility
                )
            finally:
                try:
                    os.remove(subset_users_path)
                except OSError:
                    pass

        if (
            followup_eligibility.lockout_threshold is not None
            and followup_eligibility.lockout_threshold > 0
            and not followup_eligibility.eligible_users
        ):
            followup_prompt_lines.append(
                "Adaptive follow-up unavailable: no safe spray budget remains for unmatched users."
            )
            print_panel(
                "\n".join(followup_prompt_lines),
                title="[bold cyan]Adaptive Follow-Up Summary[/bold cyan]",
                border_style="cyan",
                expand=False,
            )
            if base_hits:
                _render_valid_spray_hits_panel(
                    base_hits,
                    spray_type="Custom Password",
                    lockout_context=_spray_lockout_ctx,
                    domain=domain,
                )
                _persist_and_record_spray_hits(
                    shell,
                    domain=domain,
                    hits=base_hits,
                    spray_type="Custom Password",
                    entry_label=entry_label,
                    source_context=source_context,
                    source_steps=source_steps,
                )
            return True

        adaptive_followup_hits = _maybe_execute_adaptive_year_password_spraying(
            shell,
            domain=domain,
            password=password,
            eligibility=followup_eligibility,
            source_context=source_context,
            source_steps=source_steps,
            return_hits=True,
            only_for_users=unmatched_users,
            prompt_preamble_lines=followup_prompt_lines,
        )
        combined_hits_by_user = {
            str(hit.get("username") or "").strip().casefold(): hit
            for hit in base_hits
            if str(hit.get("username") or "").strip()
        }
        for hit in adaptive_followup_hits:
            username = str(hit.get("username") or "").strip()
            if not username:
                continue
            combined_hits_by_user.setdefault(username.casefold(), hit)
        combined_hits = list(combined_hits_by_user.values())
        if combined_hits:
            _render_valid_spray_hits_panel(
                combined_hits,
                spray_type="Combined Password Spray",
                lockout_context=_spray_lockout_ctx,
                domain=domain,
            )
            print_panel(
                "\n".join(
                    [
                        f"Base spray hits: {len(base_hits)}",
                        f"Adaptive follow-up hits: {len(adaptive_followup_hits)}",
                        f"Combined valid credentials: {len(combined_hits)}",
                    ]
                ),
                title="[bold green]Combined Spraying Result[/bold green]",
                border_style="green",
                expand=False,
            )
            _persist_and_record_spray_hits(
                shell,
                domain=domain,
                hits=combined_hits,
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


def _execute_adaptive_year_password_spraying(
    shell: SprayShell,
    *,
    domain: str,
    plan: object,
    source_context: dict[str, object] | None = None,
    source_steps: list[object] | None = None,
    persist_hits: bool = True,
    run_validated_hits_followup: bool = True,
    render_hits_panel: bool = True,
) -> bool | list[dict[str, str]]:
    """Execute a pwdLastSet-adaptive Kerbrute bruteforce combo spray."""
    from adscan_internal.cli.kerberos import ensure_kerberos_output_dir

    combos = getattr(plan, "combos", ())
    if not combos:
        print_warning("No adaptive year spray combos were generated.")
        return False

    kerberos_output_dir = ensure_kerberos_output_dir(shell, domain)
    combo_lines = [
        f"{getattr(combo, 'username')}:{getattr(combo, 'password')}"
        for combo in combos
        if getattr(combo, "username", None) and getattr(combo, "password", None)
    ]
    if not combo_lines:
        print_warning("No valid adaptive year spray combos were generated.")
        return False

    combos_path = write_temp_combo_file(combo_lines, directory=kerberos_output_dir)
    try:
        auth_state = str(shell.domains_data[domain].get("auth", "")).strip().lower()
        output_file = os.path.join(
            "domains",
            domain,
            "kerberos",
            f"{'auth' if auth_state in {'auth', 'pwned'} else 'unauth'}_spray_adaptive_year_"
            f"{safe_log_filename_fragment(str(getattr(plan, 'base_password', 'password')))}.log",
        )
        kerbrute_cmd = build_kerbrute_bruteforce_command(
            kerbrute_path=shell.kerbrute_path,
            domain=domain,
            dc_ip=shell.domains_data[domain]["pdc"],
            combos_file=combos_path,
            output_file=output_file,
        )
        hits = execute_spraying_command(
            shell,
            kerbrute_cmd,
            domain,
            spray_type="Adaptive Year Password",
            source_context={
                **(source_context or {}),
                "origin": str(
                    (source_context or {}).get("origin") or "adaptive_year_spray"
                ),
                "adaptive_year_spray": True,
                "pwdlastset_source": str(getattr(plan, "source", "unknown")),
                "base_year": getattr(plan, "original_year", None),
            },
            source_steps=source_steps,
            persist_hits=persist_hits,
            run_validated_hits_followup=run_validated_hits_followup,
            render_hits_panel=render_hits_panel,
        )
        if persist_hits:
            return True
        return hits
    finally:
        try:
            os.remove(combos_path)
        except OSError:
            pass


def _maybe_execute_adaptive_year_password_spraying(
    shell: SprayShell,
    *,
    domain: str,
    password: str,
    eligibility: SprayEligibilityResult,
    source_context: dict[str, object] | None = None,
    source_steps: list[object] | None = None,
    pwdlastset_years_by_user: dict[str, int] | None = None,
    return_hits: bool = False,
    only_for_users: list[str] | None = None,
    prompt_preamble_lines: list[str] | None = None,
) -> bool | list[dict[str, str]]:
    """Offer and execute pwdLastSet-adaptive spraying for one fixed password."""
    marked_password = mark_sensitive(password, "password")
    try:
        from adscan_internal.services.password_year_spray_plan_service import (
            build_adaptive_year_spray_plan,
            resolve_bloodhound_pwdlastset_years,
        )
        from adscan_internal.services.password_year_variant_service import (
            extract_password_year_candidates,
        )

        if len(extract_password_year_candidates(password)) != 1:
            return [] if return_hits else False
        if pwdlastset_years_by_user is None:
            pwdlastset_years_by_user = resolve_bloodhound_pwdlastset_years(
                shell,
                domain=domain,
                users=list(only_for_users or eligibility.eligible_users),
            )
        adaptive_plan = build_adaptive_year_spray_plan(
            base_password=password,
            users=list(only_for_users or eligibility.eligible_users),
            pwdlastset_years_by_user=pwdlastset_years_by_user,
            source="bloodhound",
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[adaptive-year-spray] plan resolution failed for {marked_password}: {exc}"
        )
        return [] if return_hits else False

    if adaptive_plan is None:
        return [] if return_hits else False

    combos = list(getattr(adaptive_plan, "combos", ()))
    original_year = getattr(adaptive_plan, "original_year", None)
    original_year_int = original_year if isinstance(original_year, int) else None
    grouped = _group_adaptive_year_combos_by_year(combos)
    summary_rows = _format_adaptive_year_summary_lines(
        grouped_combos=grouped,
        original_year=original_year_int,
        include_examples=True,
    )
    prompt_lines = list(prompt_preamble_lines or [])
    prompt_lines.extend(
        [
            f"Base password: {marked_password}",
            f"Detected year: {original_year if original_year is not None else 'N/A'}",
            f"pwdLastSet source: {getattr(adaptive_plan, 'source', 'unknown')}",
            f"Generated combos: {len(combos)}",
            f"Year buckets: {len(grouped)}",
        ]
    )
    if summary_rows:
        prompt_lines.append("")
        prompt_lines.append("Generated password distribution:")
        prompt_lines.extend(summary_rows)
    print_panel(
        "\n".join(prompt_lines),
        title="[bold cyan]Adaptive Year Spray Available[/bold cyan]",
        border_style="cyan",
        expand=False,
    )
    use_adaptive = Confirm.ask(
        (
            "Run pwdLastSet-adaptive Kerbrute bruteforce follow-up for the "
            "unmatched users?"
            if only_for_users is not None
            else "Run pwdLastSet-adaptive Kerbrute bruteforce instead of the normal spray for this password?"
        ),
        default=True,
    )
    if not use_adaptive:
        return [] if return_hits else False

    _adaptive_combos_for_history = [
        (str(getattr(c, "username", "")), str(getattr(c, "password", "")))
        for c in combos
        if getattr(c, "username", None) and getattr(c, "password", None)
    ]
    _accepted_adaptive = confirm_with_history_check(
        shell,
        domain=domain,
        proposed_combos=_adaptive_combos_for_history,
        mode_label="Adaptive year password",
        multi_combo=False,
    )
    if _accepted_adaptive is None:
        print_info(
            f"Skipping adaptive year spray for {marked_password} — repeated spraying not approved."
        )
        return [] if return_hits else True

    manifest_path = _persist_adaptive_year_spray_manifest(
        shell,
        domain=domain,
        base_password=password,
        original_year=original_year_int,
        source=str(getattr(adaptive_plan, "source", "unknown")),
        combos=combos,
        suffix="single",
    )
    if manifest_path:
        print_info(
            "Adaptive year combo manifest saved to "
            f"{mark_sensitive(manifest_path, 'path')}."
        )

    result = _execute_adaptive_year_password_spraying(
        shell,
        domain=domain,
        plan=adaptive_plan,
        source_context=source_context,
        source_steps=source_steps,
        persist_hits=not return_hits,
        run_validated_hits_followup=not return_hits,
        render_hits_panel=not return_hits,
    )
    register_user_spray_attempts(
        shell,
        domain=domain,
        combos=_adaptive_combos_for_history,
        mode="adaptive_year",
    )
    if return_hits:
        return result if isinstance(result, list) else []
    return bool(result)


def _group_adaptive_year_combos_by_year(
    combos: list[object],
) -> dict[int, list[object]]:
    """Group adaptive spray combos by pwdLastSet year."""
    grouped: dict[int, list[object]] = {}
    for combo in combos:
        year = getattr(combo, "pwdlastset_year", None)
        if not isinstance(year, int):
            continue
        grouped.setdefault(year, []).append(combo)
    return dict(sorted(grouped.items(), key=lambda item: item[0], reverse=True))


def _format_adaptive_year_summary_lines(
    *,
    grouped_combos: dict[int, list[object]],
    original_year: int | None,
    include_examples: bool,
) -> list[str]:
    """Build user-facing summary lines for adaptive year transformations."""
    lines: list[str] = []
    for year, year_combos in grouped_combos.items():
        original_marker = " (original year)" if original_year == year else ""
        lines.append(f"{year}{original_marker}: {len(year_combos)} users")
        if not include_examples:
            continue
        for combo in year_combos[:_ADAPTIVE_YEAR_SUMMARY_PREVIEW_PER_YEAR]:
            username = mark_sensitive(str(getattr(combo, "username", "")), "user")
            password = mark_sensitive(str(getattr(combo, "password", "")), "password")
            lines.append(f"  {username} -> {password}")
        remaining = len(year_combos) - _ADAPTIVE_YEAR_SUMMARY_PREVIEW_PER_YEAR
        if remaining > 0:
            lines.append(f"  +{remaining} more")
    return lines


def _persist_adaptive_year_spray_manifest(
    shell: SprayShell,
    *,
    domain: str,
    base_password: str,
    original_year: int | None,
    source: str,
    combos: list[object],
    suffix: str,
) -> str | None:
    """Persist the full adaptive year mapping for later diagnostics."""
    workspace_cwd = shell.current_workspace_dir or os.getcwd()
    kerberos_dir = domain_subpath(workspace_cwd, shell.domains_dir, domain, "kerberos")
    os.makedirs(kerberos_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = (
        f"adaptive_year_plan_{safe_log_filename_fragment(base_password)}_"
        f"{safe_log_filename_fragment(suffix)}_{timestamp}.json"
    )
    manifest_path = os.path.join(kerberos_dir, filename)
    grouped = _group_adaptive_year_combos_by_year(combos)
    payload = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "domain": domain,
        "base_password": base_password,
        "original_year": original_year,
        "pwdlastset_source": source,
        "combo_count": len(combos),
        "year_summary": {
            str(year): {
                "count": len(year_combos),
                "is_original_year": year == original_year,
            }
            for year, year_combos in grouped.items()
        },
        "combos": [
            {
                "username": str(getattr(combo, "username", "")),
                "generated_password": str(getattr(combo, "password", "")),
                "base_password": str(getattr(combo, "base_password", base_password)),
                "pwdlastset_year": getattr(combo, "pwdlastset_year", None),
                "mode": str(getattr(combo, "mode", "adaptive_year")),
            }
            for combo in combos
        ],
    }
    try:
        with open(manifest_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
        print_info_debug(
            "[adaptive-year-spray] Persisted full adaptive plan manifest at "
            f"{mark_sensitive(manifest_path, 'path')}"
        )
        return manifest_path
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning("Failed to persist adaptive year spray diagnostic manifest.")
        print_info_debug(f"[adaptive-year-spray] Manifest persistence failed: {exc}")
        return None


def _render_variation_spray_panel(
    plan: "VariationSprayPlan",  # noqa: F821
    base_password: str,
) -> None:
    """Render the variation spray info panel using print_panel."""

    marked = mark_sensitive(base_password, "password")
    total_combos = len(plan.combos)
    lines = [
        f"Base password:        {marked}",
        "Domain lockout:       DISABLED (lockoutThreshold = 0)",
        f"Eligible users:       {plan.cohort_compliant_count + plan.cohort_legacy_count}",
        f"  \u251c\u2500 Compliant:          {plan.cohort_compliant_count}   (filtered: current policy minLen + complexity)",
        f"  \u2514\u2500 Legacy:             {plan.cohort_legacy_count}   (relaxed filter \u2014 never-expires or predates current policy)",
    ]
    if plan.applied_policies:
        lines.append(f"Applied policies:     {', '.join(plan.applied_policies)}")
    lines += [
        "",
        f"Variation tier:       Tier {plan.max_tier}",
        f"Year sweep range:     {plan.year_sweep_min}–{plan.year_sweep_min + plan.year_sweep_back} "
        f"({plan.year_sweep_back} years, derived from oldest pwdLastSet in the legacy cohort)",
        f"Budget cap:           {plan.budget:,} authentications",
        f"Estimated auths:      {total_combos:,}",
    ]
    if plan.truncated:
        lines.append(
            f"  Budget cap hit at Tier {plan.truncated_at_tier} "
            "\u2014 some users received partial coverage"
        )
    else:
        headroom = plan.budget - total_combos
        lines.append(
            f"  Budget headroom:    {headroom:,} (could promote tier within budget)"
        )

    lines += [
        "",
        "OPSEC notice:",
        f"  This will generate \u2248{total_combos:,} pre-authentication failures on the KDC",
        "  (Event 4771 Kerberos / 4625 NTLM). Microsoft Defender for Identity",
        "  raises a 'Password spray attack' alert above ~100 failures/min.",
        "  Ensure the customer has been notified before proceeding.",
    ]
    print_panel(
        "\n".join(lines),
        title="[bold cyan]Lockout-Free Variation Spray Available[/bold cyan]",
        border_style="cyan",
        expand=False,
    )


def _prompt_variation_spray(
    preview_plan: "VariationSprayPlan",  # noqa: F821
    base_password: str,
    prefs: "SprayVariationPreferences",  # noqa: F821
    ddp_min_length: int,
    ddp_complexity: bool,
    *,
    inventory_dir: str,
    eligible_users: list[str],
    compliance_report: object,
) -> tuple[bool, "VariationSprayPlan | None", "SprayVariationPreferences | None"]:  # noqa: F821
    """Run the interactive prompt sequence for variation spray.

    Returns (accepted, final_plan, updated_prefs_or_None).
    ``updated_prefs`` is non-None when the operator changed values and
    agreed to save them.
    """
    from rich.prompt import Confirm, IntPrompt  # noqa: PLC0415

    from adscan_internal.services.password_variation_plan_service import (  # noqa: PLC0415
        build_variation_spray_plan,
    )
    from adscan_internal.services.spray_preferences_service import (  # noqa: PLC0415
        SprayVariationPreferences,
    )
    import datetime as _dt  # noqa: PLC0415

    accepted = Confirm.ask(
        "Run lockout-free variation spray? (replaces single-password spray)",
        default=True,
    )
    if not accepted:
        return False, None, None

    tier_options = [
        "Tier 1 — ~15 variations/user",
        "Tier 2 — ~40 variations/user",
        "Tier 3 — ~80 variations/user",
    ]
    tier_default_idx = max(0, min(2, prefs.max_tier_default - 1))
    selected_tier_idx = questionary_select_index(
        title="Maximum tier to include",
        options=tier_options,
        default_idx=tier_default_idx,
    )
    if selected_tier_idx is None:
        selected_tier_idx = tier_default_idx
    max_tier = selected_tier_idx + 1

    budget = IntPrompt.ask(
        "Budget (max authentications)",
        default=prefs.budget,
    )
    budget = max(1, int(budget))

    current_year = _dt.date.today().year
    final_plan = build_variation_spray_plan(
        base_password=base_password,
        eligible_users=eligible_users,
        compliance_report=compliance_report,
        ddp_min_length=ddp_min_length,
        ddp_complexity=ddp_complexity,
        pso_policies={},
        max_tier=max_tier,
        budget=budget,
        current_year=current_year,
    )

    changed = max_tier != prefs.max_tier_default or budget != prefs.budget
    updated_prefs: SprayVariationPreferences | None = None
    if changed:
        save_default = Confirm.ask(
            "Save as your default for future runs?", default=False
        )
        if save_default:
            never_ask = Confirm.ask(
                "Skip this prompt entirely on future runs and just use saved values?",
                default=False,
            )
            updated_prefs = SprayVariationPreferences(
                budget=budget,
                auto_accept=never_ask,
                max_tier_default=max_tier,
            )

    if max_tier != preview_plan.max_tier or budget != preview_plan.budget:
        _render_variation_spray_panel(final_plan, base_password)
        proceed = Confirm.ask("Proceed with these settings?", default=True)
        if not proceed:
            return False, None, None

    return True, final_plan, updated_prefs


def _execute_variation_spray(
    shell: SprayShell,
    *,
    domain: str,
    plan: "VariationSprayPlan",  # noqa: F821
    source_context: dict[str, object] | None = None,
    source_steps: list[object] | None = None,
) -> bool:
    """Convert a VariationSprayPlan to a _BatchPasswordSprayPlan and execute."""
    if not plan.combos:
        print_warning("No variation combos were generated after policy filtering.")
        return False

    # Convert to _BatchPasswordCombo format expected by the existing engine
    batch_combos = tuple(
        _BatchPasswordCombo(
            username=c.username,
            password=c.password,
            base_password=c.base_password,
            mode="variation",
        )
        for c in plan.combos
    )
    batch_plan = _BatchPasswordSprayPlan(
        combos=batch_combos,
        base_passwords=(plan.base_password,),
        adaptive_base_passwords=(),
        flat_base_passwords=(plan.base_password,),
    )

    # Persist manifest before execution so it's available even on error
    _persist_variation_spray_manifest(shell, domain=domain, plan=plan)

    _execute_batch_password_spraying(
        shell,
        domain=domain,
        plan=batch_plan,
        source_context={
            **(source_context or {}),
            "origin": str(
                (source_context or {}).get("origin") or "lockout_free_variation"
            ),
            "lockout_free_variation": True,
            "max_tier": plan.max_tier,
            "budget": plan.budget,
            "cohort_compliant": plan.cohort_compliant_count,
            "cohort_legacy": plan.cohort_legacy_count,
        },
        source_steps=source_steps,
    )
    return True


def _persist_variation_spray_manifest(
    shell: SprayShell,
    *,
    domain: str,
    plan: "VariationSprayPlan",  # noqa: F821
) -> None:
    """Write variation spray manifest JSON to the workspace."""
    import datetime as _dt  # noqa: PLC0415

    try:
        workspace_cwd = shell._get_workspace_cwd()  # noqa: SLF001
    except Exception:  # noqa: BLE001
        workspace_cwd = getattr(shell, "current_workspace_dir", "") or os.getcwd()

    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    spray_dir = domain_subpath(
        workspace_cwd, shell.domains_dir, domain, "spraying", "variations"
    )
    os.makedirs(spray_dir, exist_ok=True)
    manifest_path = os.path.join(spray_dir, f"{ts}.json")

    by_tier: dict[str, int] = {}
    by_cohort: dict[str, int] = {}
    for c in plan.combos:
        by_tier[str(c.tier)] = by_tier.get(str(c.tier), 0) + 1
        key = c.cohort.value if hasattr(c.cohort, "value") else str(c.cohort)
        by_cohort[key] = by_cohort.get(key, 0) + 1

    payload = {
        "schema_version": 2,
        "timestamp_utc": ts,
        "domain": domain,
        # Raw base password — this is a workspace artifact (not console output),
        # so mark_sensitive is not applied here. Keep consistent with the
        # adaptive-year manifest which stores the raw value.
        "base_password": plan.base_password,
        "max_tier": plan.max_tier,
        "budget": plan.budget,
        "policy_never_modified": plan.policy_never_modified,
        "applied_policies": list(plan.applied_policies),
        "cohort_compliant_count": plan.cohort_compliant_count,
        "cohort_legacy_count": plan.cohort_legacy_count,
        "truncated": plan.truncated,
        "truncated_at_tier": plan.truncated_at_tier,
        "combos_total": len(plan.combos),
        "combos_by_tier": by_tier,
        "combos_by_cohort": by_cohort,
        # Per-user combo list — forensic evidence of what was attempted.
        # Different users may receive different variation sets depending on
        # their cohort (compliant vs legacy) and applied policy (DDP vs PSO).
        # Mirrors the adaptive-year manifest schema for consistency.
        "combos": [
            {
                "username": c.username,
                "password": c.password,
                "tier": c.tier,
                "rule": c.rule,
                "cohort": c.cohort.value
                if hasattr(c.cohort, "value")
                else str(c.cohort),
            }
            for c in plan.combos
        ],
        # Hits are appended here by the report/web layer when available;
        # the initial write is empty because the Kerbrute run is still pending.
        "hits": [],
    }
    try:
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        print_info(
            f"Variation spray manifest saved to {mark_sensitive(manifest_path, 'path')}."
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning("Failed to persist variation spray manifest.")


def _maybe_execute_lockout_free_variation_spraying(
    shell: SprayShell,
    *,
    domain: str,
    password: str,
    eligibility: SprayEligibilityResult,
    source_context: dict[str, object] | None = None,
    source_steps: list[object] | None = None,
) -> bool:
    """Offer and execute lockout-free variation spray for one base password.

    Returns True when the spray was accepted and launched (regardless of
    whether it produced hits), False when skipped or ineligible.
    """
    if not LOCKOUT_FREE_VARIATION_SPRAY_ENABLED:
        return False

    # Gate by workspace type: variation spray is an audit-engagement feature,
    # not a CTF technique. CTF challenges have authored solve paths
    # (Kerberoasting, ESC1, ACL abuse, share creds) — brute-forcing variations
    # would be noise. Operators who genuinely need it on a CTF can flip the
    # workspace type or call the orchestrator directly.
    workspace_type = str(getattr(shell, "type", "") or "").strip().lower()
    if workspace_type != "audit":
        return False

    if not eligibility.no_lockout_enforced:
        return False

    if not eligibility.eligible_users:
        return False

    from adscan_internal.services.password_variation_plan_service import (  # noqa: PLC0415
        build_variation_spray_plan,
        load_compliance_report_from_workspace,
        load_ddp_policy_from_workspace,
    )
    from adscan_internal.services.spray_preferences_service import (  # noqa: PLC0415
        load_spray_variation_preferences,
        save_spray_variation_preferences,
    )

    # Resolve workspace inventory dir
    try:
        workspace_cwd = shell._get_workspace_cwd()  # noqa: SLF001
    except Exception:  # noqa: BLE001
        workspace_cwd = getattr(shell, "current_workspace_dir", "") or os.getcwd()

    inventory_dir = domain_subpath(
        workspace_cwd, shell.domains_dir, domain, "inventory"
    )

    compliance_report = load_compliance_report_from_workspace(inventory_dir)
    ddp_min_length, ddp_complexity = load_ddp_policy_from_workspace(inventory_dir)
    prefs = load_spray_variation_preferences()

    # Build preview plan with saved defaults so panel shows real numbers
    import datetime as _dt  # noqa: PLC0415

    current_year = _dt.date.today().year
    preview_plan = build_variation_spray_plan(
        base_password=password,
        eligible_users=list(eligibility.eligible_users),
        compliance_report=compliance_report,
        ddp_min_length=ddp_min_length,
        ddp_complexity=ddp_complexity,
        pso_policies={},
        max_tier=prefs.max_tier_default,
        budget=prefs.budget,
        current_year=current_year,
    )

    _render_variation_spray_panel(preview_plan, password)

    if prefs.auto_accept:
        final_plan = preview_plan
    else:
        accepted, final_plan, updated_prefs = _prompt_variation_spray(
            preview_plan,
            password,
            prefs,
            ddp_min_length,
            ddp_complexity,
            inventory_dir=inventory_dir,
            eligible_users=list(eligibility.eligible_users),
            compliance_report=compliance_report,
        )
        if not accepted:
            return False
        if updated_prefs is not None:
            save_spray_variation_preferences(updated_prefs)

    _variation_combos_for_history = [
        (str(c.username), str(c.password))
        for c in final_plan.combos
        if c.username and c.password
    ]
    _accepted_variation = confirm_with_history_check(
        shell,
        domain=domain,
        proposed_combos=_variation_combos_for_history,
        mode_label="Lockout-free variation spray",
        multi_combo=True,
    )
    if _accepted_variation is None:
        print_info(
            f"Skipping variation spray for {mark_sensitive(password, 'password')} "
            "— repeated spraying not approved."
        )
        return True
    if _accepted_variation is not _variation_combos_for_history:
        # Operator chose "Skip already-tested combos" — rebuild the plan with
        # only the accepted combos.
        _accepted_set = set(_accepted_variation)
        _filtered_combos = tuple(
            c for c in final_plan.combos if (c.username, c.password) in _accepted_set
        )
        if not _filtered_combos:
            print_info(
                "No new variation combos to spray after filtering already-tested ones."
            )
            return True
        import dataclasses as _dc  # noqa: PLC0415

        final_plan = _dc.replace(final_plan, combos=_filtered_combos)
        _variation_combos_for_history = list(_accepted_variation)

    _executed = _execute_variation_spray(
        shell,
        domain=domain,
        plan=final_plan,
        source_context=source_context,
        source_steps=source_steps,
    )
    register_user_spray_attempts(
        shell,
        domain=domain,
        combos=_variation_combos_for_history,
        mode="variation",
    )
    return _executed


def _build_batch_password_spray_plan(
    *,
    passwords: list[str],
    eligible_users: list[str],
    adaptive_pwdlastset_years_by_user: dict[str, int],
) -> _BatchPasswordSprayPlan | None:
    """Build a single Kerbrute bruteforce plan for selected passwords.

    Passwords with one clear year token use pwdLastSet-adaptive combos when
    BloodHound data is available. Other passwords fall back to flat
    user:password combos, which are equivalent to passwordspray attempts but
    cheaper to execute as one Kerbrute process.
    """
    from adscan_internal.services.password_year_spray_plan_service import (
        build_adaptive_year_spray_plan,
    )
    from adscan_internal.services.password_year_variant_service import (
        extract_password_year_candidates,
    )

    combos: list[_BatchPasswordCombo] = []
    base_passwords: list[str] = []
    adaptive_base_passwords: list[str] = []
    flat_base_passwords: list[str] = []
    unique_users = []
    seen_users: set[str] = set()
    for raw_user in eligible_users:
        username = str(raw_user or "").strip()
        user_key = username.casefold()
        if not username or user_key in seen_users:
            continue
        seen_users.add(user_key)
        unique_users.append(username)

    for password in passwords:
        if not password:
            continue
        base_passwords.append(password)
        adaptive_plan = None
        if (
            adaptive_pwdlastset_years_by_user
            and len(extract_password_year_candidates(password)) == 1
        ):
            adaptive_plan = build_adaptive_year_spray_plan(
                base_password=password,
                users=unique_users,
                pwdlastset_years_by_user=adaptive_pwdlastset_years_by_user,
                source="bloodhound",
            )
        if adaptive_plan is not None:
            adaptive_base_passwords.append(password)
            for combo in adaptive_plan.combos:
                combos.append(
                    _BatchPasswordCombo(
                        username=combo.username,
                        password=combo.password,
                        base_password=password,
                        mode="adaptive_year",
                        pwdlastset_year=combo.pwdlastset_year,
                    )
                )
            continue

        flat_base_passwords.append(password)
        for username in unique_users:
            combos.append(
                _BatchPasswordCombo(
                    username=username,
                    password=password,
                    base_password=password,
                    mode="flat",
                )
            )

    if not combos:
        return None
    return _BatchPasswordSprayPlan(
        combos=tuple(combos),
        base_passwords=tuple(base_passwords),
        adaptive_base_passwords=tuple(adaptive_base_passwords),
        flat_base_passwords=tuple(flat_base_passwords),
    )


def _execute_batch_password_spraying(
    shell: SprayShell,
    *,
    domain: str,
    plan: _BatchPasswordSprayPlan,
    source_context: dict[str, object] | None = None,
    source_steps: list[object] | None = None,
) -> bool:
    """Execute one batched Kerbrute bruteforce plan."""
    from adscan_internal.cli.kerberos import ensure_kerberos_output_dir

    combo_lines = [f"{combo.username}:{combo.password}" for combo in plan.combos]
    if not combo_lines:
        print_warning("No batched password spray combos were generated.")
        return False

    kerberos_output_dir = ensure_kerberos_output_dir(shell, domain)
    adaptive_combos = [combo for combo in plan.combos if combo.mode == "adaptive_year"]
    if adaptive_combos:
        manifest_path = _persist_adaptive_year_spray_manifest(
            shell,
            domain=domain,
            base_password=f"batch_{len(plan.base_passwords)}_passwords",
            original_year=None,
            source="bloodhound",
            combos=list(adaptive_combos),
            suffix="batch",
        )
        if manifest_path:
            print_info(
                "Adaptive year combo manifest saved to "
                f"{mark_sensitive(manifest_path, 'path')}."
            )
    combos_path = write_temp_combo_file(combo_lines, directory=kerberos_output_dir)
    try:
        auth_state = str(shell.domains_data[domain].get("auth", "")).strip().lower()
        output_file = os.path.join(
            "domains",
            domain,
            "kerberos",
            f"{'auth' if auth_state in {'auth', 'pwned'} else 'unauth'}_spray_batch_"
            f"{len(plan.base_passwords)}_passwords.log",
        )
        kerbrute_cmd = build_kerbrute_bruteforce_command(
            kerbrute_path=shell.kerbrute_path,
            domain=domain,
            dc_ip=shell.domains_data[domain]["pdc"],
            combos_file=combos_path,
            output_file=output_file,
        )
        spraying_command(
            shell,
            kerbrute_cmd,
            domain,
            spray_type="Batch Password",
            source_context={
                **(source_context or {}),
                "origin": str(
                    (source_context or {}).get("origin") or "batch_password_spray"
                ),
                "batch_password_spray": True,
                "password_count": len(plan.base_passwords),
                "combo_count": len(plan.combos),
                "adaptive_password_count": len(plan.adaptive_base_passwords),
                "flat_password_count": len(plan.flat_base_passwords),
            },
            source_steps=source_steps,
        )
        return True
    finally:
        try:
            os.remove(combos_path)
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

    if not print_spraying_eligibility(shell, domain, eligibility):
        print_info("Password spraying cancelled by user.")
        return None
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

    # History check for useraspass modes.
    if spray_category == "useraspass":
        _uap_mode = "useraspass"
        _uap_combos = [(u, u) for u in eligibility.eligible_users]
        _uap_label = "Username as password"
    elif spray_category == "useraspass_lower":
        _uap_mode = "useraspass_lower"
        _uap_combos = [(u, u.lower()) for u in eligibility.eligible_users]
        _uap_label = "Username as password (lowercase)"
    else:
        _uap_mode = "useraspass_upper"
        _uap_combos = [(u, u.capitalize()) for u in eligibility.eligible_users]
        _uap_label = "Username as password (uppercase)"
    _uap_accepted = confirm_with_history_check(
        shell,
        domain=domain,
        proposed_combos=_uap_combos,
        mode_label=_uap_label,
        multi_combo=False,
    )
    if _uap_accepted is None:
        print_info("Password spraying cancelled by user.")
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
        register_user_spray_attempts(
            shell, domain=domain, combos=_uap_combos, mode=_uap_mode
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
    """Native (kerbad) blank-password spray over the eligible user base.

    Migrated off NetExec/SMB to the native Kerberos stack (kerbad AS-REQ with an
    empty password). Validated against GOAD/Essos: detects a genuinely blank
    account AND does NOT false-positive a DONT_REQ_PREAUTH account (kerbrute/gokrb5
    cannot test blank at all — it rejects an empty password client-side). Drives
    the SAME centralized live dashboard the kerbrute sprays use, so big user bases
    show live progress / rate / ETA / found-hits. Bounded concurrency keeps it fast
    at scale; each eligible user gets exactly ONE empty-password attempt, within the
    2-attempt lockout margin the eligibility computation already enforces.
    """
    import asyncio  # noqa: PLC0415

    from adscan_internal.models.domain import resolve_dc_ip  # noqa: PLC0415
    from adscan_internal.services.blank_password_native import (  # noqa: PLC0415
        check_blank_password,
    )

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
    users = list(eligibility.eligible_users)
    if not users:
        print_warning(
            "No eligible users available for spraying with the current safety rules."
        )
        return

    domain_data = shell.domains_data.get(domain, {}) or {}
    kdc_ip = resolve_dc_ip(domain_data) or domain_data.get("pdc")
    if not kdc_ip:
        print_error("No KDC/DC IP resolved for blank-password spraying.")
        return

    posture_snapshot = None
    try:
        from adscan_internal.services.domain_posture import get_posture  # noqa: PLC0415

        posture_snapshot = get_posture(shell.domains_data, domain=domain)
    except Exception:  # noqa: BLE001 — posture is optional
        posture_snapshot = None

    dashboard = _build_spray_dashboard("Blank Password (Kerberos)", total=len(users))
    hits: list[str] = []
    state = {"tested": 0, "errors": 0, "in_flight": 0}
    sem = asyncio.Semaphore(_BLANK_SPRAY_CONCURRENCY)

    async def _check_one(user: str) -> None:
        async with sem:
            state["in_flight"] += 1
            try:
                result = await check_blank_password(
                    domain=domain,
                    username=user,
                    kdc_ip=kdc_ip,
                    posture_snapshot=posture_snapshot,
                )
            finally:
                state["in_flight"] -= 1
        state["tested"] += 1
        if result is True:
            hits.append(user)
            try:
                dashboard.record_recent(user, push_frame=True)  # masked at render
            except Exception:  # noqa: BLE001 — render must not abort the spray
                pass
        elif result is None:
            state["errors"] += 1
        # A hit forces an immediate frame; otherwise coalesce to ~every 20 to
        # avoid thrashing the render on big user bases.
        if result is True or state["tested"] % 20 == 0 or state["tested"] == len(users):
            try:
                dashboard.update(
                    done=state["tested"],
                    success=len(hits),
                    error=state["errors"],
                    in_flight=max(0, state["in_flight"]),
                    last=user,
                )
            except Exception:  # noqa: BLE001
                pass

    async def _run() -> None:
        await asyncio.gather(*[_check_one(u) for u in users], return_exceptions=True)

    try:
        with dashboard.live_session():
            asyncio.run(_run())
            try:
                dashboard.update(
                    done=state["tested"], success=len(hits), error=state["errors"], in_flight=0
                )
            except Exception:  # noqa: BLE001
                pass
    except Exception as exc:  # noqa: BLE001 — streaming/LiveSession setup failed
        telemetry.capture_exception(exc)

    # Persist hits through the centralized path (credential store + TGT mint +
    # attack-graph provenance), then record the blank sentinel for coverage de-dup.
    if hits:
        _persist_and_record_spray_hits(
            shell,
            domain=domain,
            hits=[{"username": u, "password": ""} for u in hits],
            spray_type="Blank Password",
            entry_label=entry_label,
            source_context=source_context,
            source_steps=source_steps,
            persist_via_add_credential=True,
            allow_empty_credential=True,
        )
    register_blank_spray_attempts(shell, domain=domain, users=users)

    if hits:
        marked = ", ".join(mark_sensitive(u, "user") for u in hits[:_SPRAY_RECENT_HITS])
        print_success(
            f"Blank-password spray: {len(hits)} account(s) with an EMPTY password — {marked}"
        )
    else:
        print_info(
            "Blank-password spray complete: no accounts with an empty password."
        )


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


def _spray_origin_for_type(spray_type: str | None) -> str:
    """Map a spray-type label to its specific credential-origin slug.

    The slug equals the matching ``attack_step_catalog`` entry-vector join key
    where one exists (``useraspass`` / ``blankpassword`` / ``computerpre2k`` /
    ``passwordspray``) so provenance and the attack step share a single join.
    Any unrecognized / non-determinable mode falls back to the generic
    ``spray`` origin rather than guessing.

    Args:
        spray_type: Human-readable spray method label (e.g. ``"Blank Password"``,
            ``"Username as Password (lowercase)"``, ``"Computer Pre2k"``).

    Returns:
        Canonical origin slug for that spray mode.
    """
    mode_key = _normalize_spray_type_key(spray_type)
    if mode_key in {"useraspass", "useraspass_lower", "useraspass_upper"}:
        return ORIGIN_USERNAME_AS_PASSWORD
    if mode_key == "blank_password":
        return ORIGIN_BLANK_PASSWORD
    if mode_key == "computer_pre2k":
        return ORIGIN_COMPUTER_PRE2K
    if mode_key in {
        "custom_password",
        "combined password spray",
        "adaptive year password",
        "batch password",
        "bruteforce",
        "near-threshold",
    }:
        return ORIGIN_PASSWORD_SPRAY
    # Determinable nothing else — keep the generic spray origin.
    return ORIGIN_SPRAY


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
    if not print_spraying_eligibility(shell, domain, eligibility):
        print_info("Password spraying cancelled by user.")
        return []

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
        passwords=deferred_passwords
        if deferred_passwords
        else ([] if selected_passwords else unique_passwords),
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
        "Selected passwords for spraying now: "
        + ", ".join(str(item) for item in preview_passwords)
    )
    if deferred_passwords and deferred_path:
        print_info(
            f"Deferred {len(deferred_passwords)} password(s) for later review at "
            f"{mark_sensitive(deferred_path, 'path')}."
        )

    executed_passwords: list[str] = []
    adaptive_pwdlastset_years_by_user: dict[str, int] | None = None
    no_lockout_enforced = any(
        "no lockout enforced" in note.lower() for note in eligibility.notes
    )
    if len(selected_passwords) > 1:
        try:
            from adscan_internal.services.password_year_spray_plan_service import (
                resolve_bloodhound_pwdlastset_years,
            )
            from adscan_internal.services.password_year_variant_service import (
                extract_password_year_candidates,
            )

            if any(
                len(extract_password_year_candidates(password)) == 1
                for password in selected_passwords
            ):
                adaptive_pwdlastset_years_by_user = resolve_bloodhound_pwdlastset_years(
                    shell,
                    domain=domain,
                    users=list(eligibility.eligible_users),
                )
            else:
                adaptive_pwdlastset_years_by_user = {}
            batch_plan = _build_batch_password_spray_plan(
                passwords=selected_passwords,
                eligible_users=list(eligibility.eligible_users),
                adaptive_pwdlastset_years_by_user=adaptive_pwdlastset_years_by_user,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(f"[batch-spray] plan resolution failed: {exc}")
            batch_plan = None

        if batch_plan is not None:
            prompt_lines = [
                f"Selected passwords: {len(batch_plan.base_passwords)}",
                f"Eligible users: {len(eligibility.eligible_users)}",
                f"Total Kerbrute combos: {len(batch_plan.combos)}",
                f"Adaptive year passwords: {len(batch_plan.adaptive_base_passwords)}",
                f"Flat password rounds: {len(batch_plan.flat_base_passwords)}",
                f"Reason: {'No lockout enforced by domain policy.' if no_lockout_enforced else 'Selected passwords are within the computed safe spray budget.'}",
            ]
            if batch_plan.adaptive_base_passwords:
                prompt_lines.append("")
                prompt_lines.append("Adaptive year distribution:")
                for base_password in batch_plan.adaptive_base_passwords:
                    candidates = extract_password_year_candidates(base_password)
                    original_year = candidates[0].year if len(candidates) == 1 else None
                    adaptive_combos = [
                        combo
                        for combo in batch_plan.combos
                        if combo.base_password == base_password
                        and combo.mode == "adaptive_year"
                    ]
                    grouped = _group_adaptive_year_combos_by_year(list(adaptive_combos))
                    prompt_lines.append(
                        f"{mark_sensitive(base_password, 'password')}: "
                        f"{len(adaptive_combos)} combos"
                    )
                    prompt_lines.extend(
                        _format_adaptive_year_summary_lines(
                            grouped_combos=grouped,
                            original_year=original_year,
                            include_examples=False,
                        )
                    )
            print_panel(
                "\n".join(prompt_lines),
                title="[bold cyan]Batch Kerbrute Plan Available[/bold cyan]",
                border_style="cyan",
                expand=False,
            )
            use_batch = Confirm.ask(
                "Run selected passwords as one Kerbrute bruteforce batch?",
                default=no_lockout_enforced,
            )
            if use_batch:
                # History check: propose the full batch combo list, offer skip/continue/cancel.
                _batch_history_combos = [
                    (str(combo.username), str(combo.password))
                    for combo in batch_plan.combos
                    if combo.username and combo.password
                ]
                _batch_accepted = confirm_with_history_check(
                    shell,
                    domain=domain,
                    proposed_combos=_batch_history_combos,
                    mode_label="Batch password spray",
                    multi_combo=True,
                )
                if _batch_accepted is None:
                    print_info("Batch spray cancelled by user.")
                    return executed_passwords
                # Determine which base-passwords survive after history filtering.
                if _batch_accepted is not _batch_history_combos:
                    _accepted_batch_set = set(_batch_accepted)
                    approved_password_set: set[str] = {
                        combo.base_password
                        for combo in batch_plan.combos
                        if (combo.username, combo.password) in _accepted_batch_set
                    }
                    approved_passwords: list[str] = [
                        p
                        for p in batch_plan.base_passwords
                        if p in approved_password_set
                    ]
                else:
                    approved_password_set = set(batch_plan.base_passwords)
                    approved_passwords = list(batch_plan.base_passwords)
                if approved_passwords:
                    filtered_plan = _BatchPasswordSprayPlan(
                        combos=tuple(
                            combo
                            for combo in batch_plan.combos
                            if combo.base_password in approved_password_set
                        ),
                        base_passwords=tuple(approved_passwords),
                        adaptive_base_passwords=tuple(
                            password
                            for password in batch_plan.adaptive_base_passwords
                            if password in approved_password_set
                        ),
                        flat_base_passwords=tuple(
                            password
                            for password in batch_plan.flat_base_passwords
                            if password in approved_password_set
                        ),
                    )
                    _batch_to_register = [
                        (str(combo.username), str(combo.password))
                        for combo in filtered_plan.combos
                        if combo.username and combo.password
                    ]
                    if _execute_batch_password_spraying(
                        shell,
                        domain=domain,
                        plan=filtered_plan,
                        source_context=source_context,
                        source_steps=source_steps,
                    ):
                        executed_passwords.extend(approved_passwords)
                        register_user_spray_attempts(
                            shell,
                            domain=domain,
                            combos=_batch_to_register,
                            mode="batch",
                        )

                result_lines = [
                    f"Sprayed now: {len(executed_passwords)}",
                    f"Deferred: {len(deferred_passwords)}",
                    "Execution mode: Kerbrute bruteforce batch",
                ]
                if deferred_path:
                    result_lines.append(
                        f"Deferred file: {mark_sensitive(deferred_path, 'path')}"
                    )
                print_panel(
                    "\n".join(result_lines),
                    title="[bold green]Multi-Password Spraying Result[/bold green]",
                    border_style="green",
                    expand=False,
                )
                return executed_passwords

    for index, password in enumerate(selected_passwords, start=1):
        marked_password = mark_sensitive(password, "password")
        print_info(
            f"Spraying password {index}/{len(selected_passwords)} on domain "
            f"{mark_sensitive(domain, 'domain')}: {marked_password}"
        )
        _seq_combos = [(u, password) for u in eligibility.eligible_users]
        _seq_accepted = confirm_with_history_check(
            shell,
            domain=domain,
            proposed_combos=_seq_combos,
            mode_label="Specific password",
            multi_combo=False,
        )
        if _seq_accepted is None:
            print_info(
                f"Skipping password {marked_password} — repeated spraying not approved."
            )
            continue
        if _maybe_execute_adaptive_year_password_spraying(
            shell,
            domain=domain,
            password=password,
            eligibility=eligibility,
            source_context=source_context,
            source_steps=source_steps,
            pwdlastset_years_by_user=adaptive_pwdlastset_years_by_user,
        ):
            # adaptive_year registers its own history entries
            executed_passwords.append(password)
            continue

        if _execute_single_password_spraying(
            shell,
            domain=domain,
            password=password,
            eligibility=eligibility,
            source_context=source_context,
            source_steps=source_steps,
            show_intro=False,
            offer_adaptive_year=False,
        ):
            executed_passwords.append(password)
            register_user_spray_attempts(
                shell, domain=domain, combos=_seq_combos, mode="password"
            )

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
    pending_candidates = _load_pending_spraying_password_candidates(
        shell, domain=domain
    )
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
        source_summary = str(
            candidate.source.get("artifact") or candidate.source.get("origin") or "N/A"
        )
        table.add_row(
            str(index),
            mark_sensitive(candidate.password, "password"),
            candidate.deferred_at or "-",
            candidate.reason_not_sprayed or "-",
            mark_sensitive(source_summary, "path")
            if source_summary != "N/A"
            else source_summary,
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
        print_warning(
            "No saved SAM-to-domain reuse candidates were found for this domain."
        )
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
            ", ".join(
                mark_sensitive(account, "user") for account in candidate.accounts[:2]
            )
            + (
                f" (+{len(candidate.accounts) - 2} more)"
                if len(candidate.accounts) > 2
                else ""
            ),
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
            credential_origin=ORIGIN_CREDENTIAL_REUSE,
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


def domain_spray_command(
    shell: SprayShell,
    users: list[str],
    domain: str,
    *,
    password: str = "",
    spray_type: str | None = None,
    entry_label: str | None = None,
    source_context: dict[str, object] | None = None,
    source_steps: list[object] | None = None,
) -> None:
    """Wrapper for the native domain spray (blank/single-candidate) with a header.

    Runs a native authentication sweep against the DC — one attempt per eligible
    user with the candidate ``password`` — instead of shelling out to NetExec.
    """
    from adscan_internal import print_operation_header

    resolved_spray_type = spray_type or "Custom Password"
    print_operation_header(
        "Password Spraying Attack",
        details={
            "Domain": domain,
            "Spray Type": resolved_spray_type,
            "User List": "Domain Users",
            "PDC": shell.domains_data[domain].get("pdc", "N/A"),
            "Protocol": "Kerberos / SMB (native)",
        },
        icon="💧",
    )

    execute_domain_spray_native(
        shell,
        users=users,
        domain=domain,
        password=password,
        spray_type=resolved_spray_type,
        entry_label=entry_label,
        source_context=source_context,
        source_steps=source_steps,
    )


def _run_spray_with_dashboard(
    shell: SprayShell,
    *,
    command: str,
    spray_label: str,
    use_clean_env: bool,
    domain: str | None = None,
) -> "subprocess.CompletedProcess[str] | None":
    """Run a kerbrute spray LIVE under a streaming progress dashboard.

    Streams kerbrute's stdout via the shared :func:`stream_command_lines`
    (which spawns through ``shell.spawn_command`` -- preserving the PyInstaller
    clean-env handling -- and drains the remaining output). When the number of
    logins to attempt can be derived from the command's input file, this drives
    a DETERMINATE ``tested / N`` bar (ticked from every ``[!]``/``[+] VALID
    LOGIN`` per-attempt line kerbrute emits under ``-v``, with valid hits in the
    success-counter row); otherwise it degrades to a "found N logins" spinner.
    Spray has no timeout (it can run long), so ``timeout_seconds=None``.

    FAIL-SAFE: if the dashboard cannot be built or the process cannot be
    spawned, falls back to the buffered ``shell.run_command`` path so the
    spray always completes and downstream result handling is never skipped.

    Args:
        shell: Active shell exposing ``spawn_command`` + ``run_command``.
        command: Full kerbrute command string (already shell-quoted).
        spray_label: Human-readable label for the dashboard title.
        use_clean_env: Whether the command needs a clean env (buffered path).

    Returns:
        A CompletedProcess-shaped result (``StreamedProcessResult`` on the
        streaming path, ``subprocess.CompletedProcess`` on the fallback), or
        ``None`` if even the fallback could not execute.
    """

    def _buffered() -> "subprocess.CompletedProcess[str] | None":
        # Heartbeat spinner so a non-streaming run still shows it is alive
        # (tui-design Anti-Pattern #8). No-op on non-TTY per rich.Console.
        from adscan_core.output._state import _get_console
        _console = _get_console()
        with _console.status(
            f"[bold {ADSCAN_PRIMARY}]Spraying {spray_label} …[/bold {ADSCAN_PRIMARY}] "
            "[dim](kerbrute streaming, results render when complete)[/dim]",
            spinner="dots",
        ):
            return shell.run_command(
                command,
                timeout=None,  # No timeout for spraying (can take a long time)
                shell=True,
                capture_output=True,
                text=True,
                use_clean_env=use_clean_env,
            )

    # Determinate total = number of logins kerbrute will attempt (input-file
    # line count). None -> the dashboard degrades to the "found N" spinner.
    total = _count_spray_attempt_total(command)

    try:
        dashboard = _build_spray_dashboard(spray_label, total)
    except Exception:  # noqa: BLE001 -- dashboard build must never block spray
        return _buffered()

    determinate = bool(total and total > 0)
    hits_seen: set[str] = set()
    state = {"tested": 0}

    # Live current-operation telemetry — mirror the spray dashboard's forward
    # motion into the structured event stream so the platform shows "Password
    # spraying · X of N accounts" live, not just at completion. Throttled to
    # ~1.5s (same budget as the port-scan emitter) so a large spray never floods
    # the event channel. No secret reaches the event: only counts + the domain.
    _emit_state: dict[str, float] = {"last_emit": 0.0}

    def _maybe_emit_spray_progress(*, force: bool = False, done: bool = False) -> None:
        import time as _time  # noqa: PLC0415

        now = _time.time()
        if not force and now - _emit_state["last_emit"] < 1.5:
            return
        _emit_state["last_emit"] = now
        try:
            from adscan_internal.cli.ci_events import (  # noqa: PLC0415
                emit_operation_progress,
            )

            emit_operation_progress(
                operation="password_spraying",
                label="Password spraying",
                phase="password_spraying",
                phase_label="Password Spraying",
                current=state["tested"] or None,
                total=total if determinate else None,
                detail=domain or None,
                done=done,
            )
        except Exception:  # noqa: BLE001 -- telemetry must not abort the spray
            pass

    def _on_line(line: str) -> None:
        if not _is_kerbrute_login_attempt_line(line):
            return
        state["tested"] += 1
        _maybe_emit_spray_progress()

        current_user: str | None = None
        parsed_login = _parse_kerbrute_valid_login_line(line)
        if parsed_login is not None:
            username, _password = parsed_login
            current_user = username
            if username.lower() not in hits_seen:
                # Feed the RAW username into the bounded "recent found" window
                # (masked at render -- TeeConsole invariant) and force an
                # immediate frame: a valid login is the headline finding. The
                # dashboard caps the displayed rows; the authoritative capture
                # is the full-stdout re-parse + credential store downstream.
                try:
                    dashboard.record_recent(username, push_frame=True)
                except Exception:  # noqa: BLE001 -- render must not abort spray
                    pass
            hits_seen.add(username.lower())

        # Coalesce frames to one per 100 attempts so a huge spray does not
        # thrash the render; a valid hit always forces an immediate frame so
        # "found N" never lags.
        if not (parsed_login is not None or state["tested"] % 100 == 0):
            return
        try:
            # Feed the RAW username (masked at render -- CLAUDE.md TeeConsole).
            if determinate:
                dashboard.update(
                    done=state["tested"],
                    success=len(hits_seen),
                    last=current_user,
                )
            else:
                dashboard.update(done=len(hits_seen), last=current_user)
        except Exception:  # noqa: BLE001 -- render must not abort the spray
            pass

    def _on_drain() -> None:
        # Snap the bar to the final tested count on clean close.
        try:
            if determinate:
                dashboard.update(done=state["tested"], success=len(hits_seen))
            else:
                dashboard.update(done=len(hits_seen))
        except Exception:  # noqa: BLE001 -- final frame is best-effort
            pass
        # Emit the terminal count so the live surface lands on the real total,
        # marked done so the platform's live strip clears the operation instead
        # of freezing on the final tested count.
        _maybe_emit_spray_progress(force=True, done=True)

    try:
        with dashboard.live_session():
            streamed = stream_command_lines(
                shell.spawn_command,
                command=command,
                timeout_seconds=None,
                on_line=_on_line,
                on_drain=_on_drain,
            )
        if streamed is not None:
            return streamed
        # spawn returned None -- fall back to the buffered path.
        return _buffered()
    except Exception:  # noqa: BLE001 -- streaming/LiveSession setup failed
        return _buffered()


def execute_spraying_command(
    shell: SprayShell,
    command: str,
    domain: str,
    *,
    spray_type: str | None = None,
    entry_label: str | None = None,
    source_context: dict[str, object] | None = None,
    source_steps: list[object] | None = None,
    persist_hits: bool = True,
    run_validated_hits_followup: bool = True,
    render_hits_panel: bool = True,
    lockout_context: dict[str, object] | None = None,
) -> list[dict[str, str]]:
    """Execute the spraying command and process results."""
    from adscan_internal.cli.common import SECRET_MODE

    marked_domain = mark_sensitive(domain, "domain")
    # Best-effort eligible-user count for the spinner heartbeat (the kerbrute
    # command already wraps a temp file; we only need a label, not the path).
    _spinner_label_parts: list[str] = []
    if spray_type:
        _spinner_label_parts.append(spray_type)
    _spinner_label_parts.append(f"on {marked_domain}")
    _spinner_label = " ".join(_spinner_label_parts)

    try:
        use_clean_env = command_string_needs_clean_env(command)
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            f"[spray] Executing spraying command with "
            f"use_clean_env={use_clean_env} on domain {marked_domain}"
        )

        # Stream kerbrute's stdout so the "found N logins" counter advances
        # DURING the spray. kerbrute buffers its ``-o`` file but flushes one
        # ``[+] VALID LOGIN`` line per hit to stdout in real time (confirmed in
        # lab), so streaming stdout is the reliable live source. The full
        # stdout is still drained and re-parsed below so the authoritative hit
        # collection + returncode handling are byte-for-byte unchanged.
        # FAIL-SAFE: if the dashboard or spawn fails, fall back to the buffered
        # run_command path so the spray always completes.
        completed_process = _run_spray_with_dashboard(
            shell,
            command=command,
            spray_label=_spinner_label,
            use_clean_env=use_clean_env,
            domain=domain,
        )

        if completed_process is None:
            print_error("Failed to execute password spraying command")
            return []

        # Process output after command completes (avoids interleaving)
        raw_output = completed_process.stdout or ""
        raw_stderr_output = completed_process.stderr or ""
        output = strip_ansi_codes(raw_output)
        stderr_output = strip_ansi_codes(raw_stderr_output)
        output_lines = output.splitlines() if output else []

        hits_by_user: dict[str, dict[str, str]] = {}
        # Authoritative hit collection: re-parse the full streamed stdout via
        # the shared single-source parser (identical to the pre-streaming
        # batch parse, so persisted hits are unchanged).
        for line in output_lines:
            line_stripped = line.strip()
            if not line_stripped:
                continue

            if "VALID LOGIN" not in line_stripped:
                continue

            try:
                parsed_login = _parse_kerbrute_valid_login_line(line_stripped)
                if parsed_login is None:
                    continue
                username, password = parsed_login
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
            if render_hits_panel:
                _render_valid_spray_hits_panel(
                    hits,
                    spray_type=spray_type,
                    lockout_context=lockout_context,
                    domain=domain,
                )
            if persist_hits:
                _persist_and_record_spray_hits(
                    shell,
                    domain=domain,
                    hits=hits,
                    spray_type=spray_type,
                    entry_label=entry_label,
                    source_context=source_context,
                    source_steps=source_steps,
                    run_validated_hits_followup=run_validated_hits_followup,
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
                # Show summary even in non-SECRET mode. An empty spray is a normal
                # negative: rejected credentials (KDC_ERR_PREAUTH_FAILED,
                # "authentication failed") are NOT errors, so filter them out and
                # only warn on genuine tool/transport failures. Detail lines are
                # print_info (visible) so the header is never left dangling.
                error_lines = _genuine_spray_error_lines(output_lines)
                if error_lines:
                    print_warning("Errors detected in output:")
                    for line in error_lines[:5]:  # Show first 5 genuine error lines
                        print_info(f"  {_rich_markup_escape(line)}")
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error executing password spraying command.")
        print_exception(show_locals=False, exception=e)
        return []
    return list(hits_by_user.values()) if found_credentials else []


# Bounded concurrency for the native domain spray. Kept modest so a large spray
# does not flood the KDC with simultaneous AS-REQs (OPSEC + DoS avoidance). Each
# user is an independent principal, so concurrency never changes per-account
# badPwdCount — the one-attempt-per-user invariant is preserved regardless.
_NATIVE_SPRAY_CONCURRENCY = 5

# Native CredentialStatus -> spray outcome-code mapping. VALID and
# PASSWORD_MUST_CHANGE are HITS (the candidate is the correct password — a
# must-change account still proves the password), mirroring the retired NetExec
# path which treated STATUS_PASSWORD_MUST_CHANGE / KDC_ERR_KEY_EXPIRED as valid.
_NATIVE_SPRAY_HIT_STATUSES = frozenset({"valid", "password_must_change"})
_NATIVE_SPRAY_OUTCOME_CODE: dict[str, str] = {
    "valid": "SUCCESS",
    "password_must_change": "STATUS_PASSWORD_MUST_CHANGE",
    "account_locked": "STATUS_ACCOUNT_LOCKED_OUT",
    "account_disabled": "STATUS_ACCOUNT_DISABLED",
    "password_expired": "STATUS_PASSWORD_EXPIRED",
    "invalid": "STATUS_LOGON_FAILURE",
    "user_not_found": "USER_NOT_FOUND",
    "timeout": "CONNECTION_ERROR",
    "error": "OTHER_FAILURE",
}


async def _run_native_domain_spray(
    *,
    domain: str,
    dc_ip: str,
    users: list[str],
    password: str,
    posture_snapshot: object | None,
    credential_type: str = "password",
) -> tuple[list[str], dict[str, int]]:
    """Authenticate the candidate credential as each user, ONE attempt each.

    Uses the native, Kerberos-first credential verifier
    (:meth:`CredentialService._verify_via_kerberos`), which performs exactly one
    credential-checking authentication per call — etype/no-verdict retries never
    touch badPwdCount, and there is NO NTLM<->Kerberos re-attempt on a wrong
    credential. So each (user, candidate) increments badPwdCount at most once, the
    core lockout-safety invariant. Runs with bounded concurrency against the DC.

    ``password`` is the candidate credential value; ``credential_type`` selects
    how it is used — ``"password"`` (default, cleartext spray) or ``"hash"``
    (pass-the-hash domain-reuse validation, where ``password`` carries the 32-hex
    NT hash). Both flow through the same single-attempt verifier, so the
    hash-reuse path inherits the identical lockout-safety guarantee.

    Returns ``(hit_usernames, outcome_counts)`` in the same shape the retired
    NetExec parser produced, so downstream rendering/persistence is unchanged.
    """
    import asyncio  # noqa: PLC0415

    from adscan_internal.services.credential_service import (  # noqa: PLC0415
        CredentialService,
    )

    service = CredentialService()
    semaphore = asyncio.Semaphore(_NATIVE_SPRAY_CONCURRENCY)
    hit_usernames: dict[str, str] = {}
    outcome_counts: dict[str, int] = {}

    async def _verify_one(user: str) -> tuple[str, str]:
        async with semaphore:
            try:
                # Deliberate reuse of the canonical native, Kerberos-first
                # credential verifier — the single-attempt classifier ADscan
                # already trusts for VALID / INVALID / LOCKED / MUST_CHANGE.
                result = await service._verify_via_kerberos(  # pylint: disable=protected-access
                    domain=domain,
                    kdc_ip=dc_ip,
                    username=user,
                    credential=password,
                    credential_type=credential_type,
                    posture_snapshot=posture_snapshot,
                )
                return user, str(getattr(result.status, "value", result.status))
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                return user, "error"

    tasks = [asyncio.ensure_future(_verify_one(user)) for user in users]
    for coro in asyncio.as_completed(tasks):
        user, status = await coro
        code = _NATIVE_SPRAY_OUTCOME_CODE.get(status, "OTHER_FAILURE")
        outcome_counts[code] = outcome_counts.get(code, 0) + 1
        if status in _NATIVE_SPRAY_HIT_STATUSES:
            hit_usernames.setdefault(user.lower(), user)

    return sorted(hit_usernames.values(), key=str.lower), outcome_counts


def execute_domain_spray_native(
    shell: SprayShell,
    *,
    users: list[str],
    domain: str,
    password: str = "",
    spray_type: str | None = None,
    entry_label: str | None = None,
    source_context: dict[str, object] | None = None,
    source_steps: list[object] | None = None,
    lockout_context: dict[str, object] | None = None,
) -> None:
    """Run a native authentication sweep against the DC and process its hits.

    Replaces the ``nxc smb <dc> -u <users> -p <pass>`` subprocess: for each
    eligible user, a single native Kerberos/NTLM authentication attempt with the
    candidate ``password`` (blank for the blank-password spray) is made against
    the DC and classified as valid / must-change / locked / logon-failure. Hits
    (valid + must-change) are rendered and persisted identically to the prior
    path.

    Note on pre-mint: unlike a mass-auth SWEEP as one owned principal (where
    ``resolve_sweep_credential`` pre-mints a single TGT so the operator secret
    hits the wire once), a password spray tests the candidate AS each target
    user — there is no owned principal to mint a TGT for. The invariant that
    protects (secret on the wire once, no per-host lockout amplification) holds
    structurally here: a single target host (the DC) and exactly one attempt per
    user.
    """
    from adscan_internal.cli.common import SECRET_MODE

    marked_domain = mark_sensitive(domain, "domain")

    # De-duplicate the user list case-insensitively so a repeated entry can never
    # produce a second attempt against the same account within one spray window.
    seen_users: set[str] = set()
    unique_users: list[str] = []
    for raw_user in users:
        user = str(raw_user or "").strip()
        if not user:
            continue
        key = user.lower()
        if key in seen_users:
            continue
        seen_users.add(key)
        unique_users.append(user)

    if not unique_users:
        print_warning("No eligible users to spray.")
        return

    try:
        from adscan_internal.models.domain import resolve_dc_ip  # noqa: PLC0415
        from adscan_internal.services.domain_posture import get_posture  # noqa: PLC0415

        dc_ip = resolve_dc_ip(shell.domains_data.get(domain, {}) or {})
        if not dc_ip:
            print_error(
                "Cannot resolve the domain controller IP for the spray; aborting."
            )
            return
        posture_snapshot = get_posture(shell.domains_data, domain=domain)

        _spinner_label_parts: list[str] = []
        if spray_type:
            _spinner_label_parts.append(spray_type)
        _spinner_label_parts.append(f"on {marked_domain}")
        _spinner_label = " ".join(_spinner_label_parts)

        import asyncio  # noqa: PLC0415

        print_info_debug(
            f"[spray] Native domain spray on {marked_domain}: "
            f"{len(unique_users)} user(s), one attempt each."
        )
        from adscan_core.output._state import _get_console  # noqa: PLC0415
        _console = _get_console()
        with _console.status(
            f"[bold {ADSCAN_PRIMARY}]Spraying {_spinner_label} …[/bold {ADSCAN_PRIMARY}] "
            "[dim](native auth attempts, results render when complete)[/dim]",
            spinner="dots",
        ):
            hit_usernames, outcome_counts = asyncio.run(
                _run_native_domain_spray(
                    domain=domain,
                    dc_ip=dc_ip,
                    users=unique_users,
                    password=password,
                    posture_snapshot=posture_snapshot,
                )
            )

        hits = [
            {"username": username, "password": password}
            for username in hit_usernames
        ]

        if hits:
            _render_valid_spray_hits_panel(
                hits,
                spray_type=spray_type,
                lockout_context=lockout_context,
                domain=domain,
            )
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
            print_info_verbose("Password spraying completed successfully")
        else:
            outcome_summary = _summarize_outcomes_for_table(outcome_counts, limit=4)
            if outcome_summary != "-":
                print_warning(
                    f"No credentials found during spraying. Outcomes for "
                    f"{marked_domain}: {outcome_summary}"
                )
            else:
                print_warning("No valid credentials found.")
    except Exception as e:  # noqa: BLE001
        telemetry.capture_exception(e)
        if not SECRET_MODE:
            print_error("Error executing password spraying.")
            print_warning(
                "No credentials were captured during spraying. Check the log above for signs of "
                "must-change accounts, logon failures, or connectivity issues."
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
    # Exclude machine accounts we already own (e.g. a previously-cracked pre2k
    # computer): re-spraying an owned machine account is pointless. Same
    # centralized owned-exclusion as the user sprays, tolerant of the '$' suffix.
    computer_sams = _drop_owned(shell, domain, computer_sams, context="pre2k")
    if not computer_sams:
        print_warning("No enabled computers available for pre2k checks.")
        return

    print_info_debug(
        "[spray] launching computer pre2k check with "
        f"{len(computer_sams)} enabled computer account(s)."
    )

    # pre2k spray is excluded from the unified per-(user, password) history
    # (single trivial credential per machine — not worth dedup tracking).

    summary_lines = [
        f"Domain: {marked_domain}",
        f"Computers in list: {len(computer_sams)}",
        f"Attempted computers: {len(computer_sams)}",
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
    combos = [f"{sam}:{sam.rstrip('$').lower()}" for sam in computer_sams]
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



def register_spraying_attempt(
    shell: "SprayShell", domain: str, category: str, password: "str | None" = None
) -> None:
    """Public wrapper for recording a spraying attempt — delegates to internal helper."""
    _mark_recommended_spraying_attempt(shell, domain, category)


def should_proceed_with_repeated_spraying(
    shell: "SprayShell", domain: str, category: str, password: "str | None" = None
) -> bool:
    """Public wrapper for checking if repeated spraying should proceed."""
    return not _has_recommended_spraying_attempt(shell, domain)


# ── Spray phase orchestration (two-step, lockout-aware, coverage-driven) ───────
# Phase 6 runs in TWO steps:
#   Step 1 — pre2k computer-account spray, behind an educational panel + confirm
#            (default yes; ci auto-yes). Computer accounts never lock, so it leads
#            the phase, but the operator always sees what it is and why first.
#   Step 2 — a coverage-aware spray SELECTOR loop over the three ci spray types
#            (user-as-password -> owned-credential reuse -> blank), each showing
#            live coverage %. Interactive: the operator picks from the selector,
#            which re-appears after each spray (full control). ci: an auto-pick
#            walks the priority order, SKIPPING fully-covered types and types with
#            zero eligible users, and exits when none remain (deterministic; the
#            iteration cap is a hard backstop against any loop). Two extra
#            interactive-only entries (custom password, retry found/share passwords)
#            never enter the ci auto-pick. Per-type eligibility + the 2-attempt
#            lockout margin + per-combo de-dup are still owned by the executors.
_SPRAY_CI_TYPES: tuple[str, ...] = ("useraspass", "reuse", "blank")
_SPRAY_TYPE_LABEL: dict[str, str] = {
    "useraspass": "user-as-password",
    "reuse": "owned-credential reuse",
    "blank": "blank password",
}
_SPRAY_SELECTOR_MAX_ITER = 16  # hard backstop against any selector loop


def _owned_cleartext_passwords(
    shell: "SprayShell", domain: str
) -> list[tuple[str, str]]:
    """Distinct cleartext owned credentials as ``(owner_user, password)``.

    NT hashes are skipped (not reused as cleartext); duplicates are collapsed by
    password so the same secret is sprayed once across the user base.
    """
    creds = (shell.domains_data.get(domain, {}) or {}).get("credentials", {}) or {}
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for user, secret in (creds.items() if isinstance(creds, dict) else []):
        pwd = str(secret or "")
        if not pwd or pwd in seen:
            continue
        try:
            if shell.is_hash(pwd):
                continue
        except Exception:  # noqa: BLE001 — is_hash is best-effort
            pass
        seen.add(pwd)
        out.append((str(user), pwd))
    return out


def _owned_usernames(shell: "SprayShell", domain: str) -> set[str]:
    """Casefolded set of principals we already hold a domain credential for.

    Spraying an account we already own is pointless (no new access), adds
    badPwdCount noise, and — because authenticating as that account (e.g.
    password-policy enumeration) resets its badPwdCount to 0 — would keep it
    perpetually "eligible" and re-sprayed across cycles. ANY stored secret
    (cleartext OR NT hash) means the account is owned, so the presence of the
    credential key is what counts.
    """
    creds = (shell.domains_data.get(domain, {}) or {}).get("credentials", {}) or {}
    if not isinstance(creds, dict):
        return set()
    return {str(user).casefold() for user in creds}


def _drop_owned(
    shell: "SprayShell", domain: str, names, *, context: str
) -> list[str]:
    """Return ``names`` minus already-owned principals — the SINGLE owned-exclusion
    point for EVERY spray path (user sprays AND pre2k computer-account sprays).

    Matching is case-insensitive and tolerant of the trailing ``$`` on machine
    accounts, so a cracked ``WS01$`` in the credential store excludes both
    ``WS01$`` (pre2k list) and ``WS01``. ``context`` only labels the debug line.
    """
    items = list(names)
    owned = _owned_usernames(shell, domain)
    if not owned:
        return items
    owned_bare = {name.rstrip("$") for name in owned}
    kept = [
        name
        for name in items
        if str(name).casefold() not in owned
        and str(name).casefold().rstrip("$") not in owned_bare
    ]
    skipped = len(items) - len(kept)
    if skipped:
        print_info_debug(
            f"[spray] {context}: excluded {skipped} already-owned principal(s) "
            f"from the spray set for {mark_sensitive(domain, 'domain')}"
        )
    return kept


def _eligible_remaining_count(eligible_users, covered_lower: set[str]) -> int:
    """Eligible users not yet covered for a type (covered_lower is casefolded)."""
    return sum(1 for u in eligible_users if u.casefold() not in covered_lower)


def _coverage_row(spray_type: str, *, planned: int, covered: int, eligible: int) -> dict:
    pct = int(round(covered / planned * 100)) if planned else 100
    return {
        "type": spray_type,
        "planned": int(planned),
        "covered": int(covered),
        "pct": max(0, min(100, pct)),
        "eligible": int(eligible),
    }


def _compute_spray_coverage_overview(shell: "SprayShell", domain: str):
    """Compute per-type coverage rows + live eligibility. Read-only; None on failure.

    Coverage is measured against the granular per-(user,password) spray history:
      * user-as-password — covered for a user if ANY case mode (normal / lower /
        upper) was already tried (one mode suffices, per the design).
      * owned-credential reuse — only present when a cleartext credential is held;
        a user is covered only when EVERY owned password was tried.
      * blank — covered when the blank sentinel was tried for the user.
    ``eligible`` is the count of lockout-safe users still uncovered for that type.
    """
    try:
        auth_state = str(shell.domains_data.get(domain, {}).get("auth", "")).strip().lower()
        requires_auth = auth_state in {"auth", "pwned"}
        user_list = get_spraying_user_list_path(shell, domain, requires_auth)
        if not user_list:
            return None
        eligibility = compute_spraying_eligibility(
            shell,
            domain=domain,
            user_list_file=user_list,
            safe_threshold=2 if requires_auth else 0,
        )
        if eligibility is None:
            return None

        eligible_users = list(eligibility.eligible_users)
        # Locked-out accounts can NEVER be sprayed, so they must not inflate the
        # coverage denominator (a locked account would make a type un-completable)
        # nor count as "near lockout". Near-lockout / no-data exclusions DO stay in
        # the denominator — they are coverable once their window resets.
        non_locked_excluded = [
            e for e in eligibility.excluded_users if e.reason != "Account locked out"
        ]
        all_users = eligible_users + [e.username for e in non_locked_excluded]
        owned = _owned_cleartext_passwords(shell, domain)
        owned_pwds = [pwd for (_owner, pwd) in owned]
        threshold = eligibility.lockout_threshold
        lockout_disabled = (not threshold) or int(threshold) <= 0
        near_lockout = len(non_locked_excluded)

        rows: list[dict] = []

        # user-as-password — any case variant counts as covered for that user.
        uap_combos: list[tuple[str, str]] = []
        for user in all_users:
            uap_combos += [(user, user), (user, user.lower()), (user, user.capitalize())]
        uap_hist = find_already_attempted_combos(shell, domain=domain, combos=uap_combos)
        uap_covered = {ku.casefold() for (ku, _p) in uap_hist}
        rows.append(
            _coverage_row(
                "useraspass",
                planned=len(all_users),
                covered=len(uap_covered),
                eligible=_eligible_remaining_count(eligible_users, uap_covered),
            )
        )

        # owned-credential reuse — only when we actually hold a cleartext credential.
        if owned_pwds:
            owned_combos = [(u, p) for u in all_users for p in owned_pwds]
            owned_hist = find_already_attempted_combos(
                shell, domain=domain, combos=owned_combos
            )
            owned_covered_users = {
                u.casefold()
                for u in all_users
                if all((u, p) in owned_hist for p in owned_pwds)
            }
            rows.append(
                _coverage_row(
                    "reuse",
                    planned=len(all_users) * len(owned_pwds),
                    covered=len(owned_hist),
                    eligible=_eligible_remaining_count(eligible_users, owned_covered_users),
                )
            )

        # blank password
        blank_covered = blank_already_attempted(shell, domain=domain, users=all_users)
        rows.append(
            _coverage_row(
                "blank",
                planned=len(all_users),
                covered=len(blank_covered),
                eligible=_eligible_remaining_count(eligible_users, blank_covered),
            )
        )

        return {
            "rows": rows,
            "eligibility": eligibility,
            "owned": owned,
            "owned_pwds": owned_pwds,
            "threshold": threshold,
            "margin": 2,
            "near_lockout": near_lockout,
            "lockout_disabled": lockout_disabled,
        }
    except Exception as exc:  # noqa: BLE001 — overview must never block spraying
        telemetry.capture_exception(exc)
        return None


def _run_pre2k_step(shell: "SprayShell", domain: str, *, interactive: bool) -> None:
    """Step 1 — educational pre2k computer-account spray (gated, default yes).

    Deduped persistently: once pre2k has been attempted in this workspace
    (``_pre2k_already_attempted`` — survives re-entry), it is not auto-re-offered.
    In ci it is skipped as covered; interactively the operator can still force a
    re-run, but the prompt defaults to NO so a re-entered scan does not silently
    re-spray.
    """
    from adscan_internal.services.scan_phases import subphase_is_enabled

    if not subphase_is_enabled(shell, "password_spraying", "pre2k"):
        print_info(
            "Pre2k computer-account spray skipped (disabled in scan configuration)."
        )
        return
    workspace_cwd = shell.current_workspace_dir or os.getcwd()
    if not has_enabled_computer_list(workspace_cwd, shell.domains_dir, domain):
        return  # nothing to pre2k against

    if _pre2k_already_attempted(shell, domain):
        if not interactive:
            print_info_debug(
                "[spray] pre2k already attempted in this workspace — skipping Step 1 (ci, covered)."
            )
            return
        if not confirm_ask(
            "Pre2k computer-account spray was already attempted in this workspace — run it again?",
            default=False,
        ):
            print_info(
                "Pre2k computer-account spray skipped (already attempted this engagement)."
            )
            return
        do_computer_pre2k_spraying(shell, domain)
        return

    try:
        count = count_enabled_computer_accounts(
            workspace_cwd, shell.domains_dir, domain
        )
    except Exception:  # noqa: BLE001
        count = 0
    try:
        from adscan_internal import get_console
        from adscan_internal.cli.widgets.spray_coverage_live import (
            render_pre2k_education_panel,
        )

        get_console().print(render_pre2k_education_panel(domain, computer_count=count))
    except Exception as exc:  # noqa: BLE001 — panel must never block the spray
        telemetry.capture_exception(exc)
    if interactive and not confirm_ask(
        "Run the pre2k computer-account spray now?", default=True
    ):
        print_info("Pre2k computer-account spray skipped by operator.")
        return
    do_computer_pre2k_spraying(shell, domain)


def _ci_pick_spray(rows: list[dict], done: set[str]) -> "str | None":
    """ci auto-pick: highest-priority type not yet run, not 100% covered, eligible>0."""
    priority = {t: i for i, t in enumerate(_SPRAY_CI_TYPES)}
    candidates = sorted(
        (r for r in rows if r["type"] in priority),
        key=lambda r: priority[r["type"]],
    )
    for row in candidates:
        if row["type"] in done:
            continue
        if row["pct"] >= 100 or row["eligible"] <= 0:
            continue
        return row["type"]
    return None


def _select_useraspass_transform(shell: "SprayShell", *, interactive: bool) -> "str | None":
    """Sub-selector for the username-as-password mode. ci default = lowercase."""
    options = ["Normal (as-is)", "lowercase", "uppercase (capitalize)"]
    idx = shell._questionary_select(
        "Username-as-password mode:", options, default_idx=1
    )
    if idx is None:
        return "lower"
    return {0: None, 1: "lower", 2: "capitalize"}.get(idx, "lower")


def _select_owned_passwords(
    shell: "SprayShell", owned: list[tuple[str, str]], *, interactive: bool
) -> list[str]:
    """Sub-selector for which owned credentials to spray. ci/non-interactive = ALL."""
    if not owned:
        return []
    if not interactive:
        return [pwd for (_owner, pwd) in owned]
    from adscan_core.output._prompts import questionary_checkbox_values

    labels = [
        f"{mark_sensitive(owner, 'user')} → {mark_sensitive(pwd, 'password')}"
        for (owner, pwd) in owned
    ]
    selected = questionary_checkbox_values(
        title="Select owned credentials to spray:",
        options=labels,
        default_values=labels,
        shell=shell,
    )
    if not selected:
        return [pwd for (_owner, pwd) in owned]
    by_label = {labels[i]: owned[i][1] for i in range(len(labels))}
    return [by_label[s] for s in selected if s in by_label]


def _interactive_select_spray(
    shell: "SprayShell",
    domain: str,
    overview: dict,
    *,
    has_pending: bool,
    has_reuse: bool,
) -> "str | None":
    """Render the coverage panel + spray selector. Returns a choice key or None (done)."""
    rows = overview["rows"]
    try:
        from adscan_internal import get_console
        from adscan_internal.cli.widgets.spray_coverage_live import (
            render_coverage_selector_panel,
        )

        get_console().print(
            render_coverage_selector_panel(
                rows,
                domain=domain,
                threshold=overview["threshold"],
                margin=overview["margin"],
                near_lockout=overview["near_lockout"],
                lockout_disabled=overview["lockout_disabled"],
            )
        )
    except Exception as exc:  # noqa: BLE001 — panel must never block the selector
        telemetry.capture_exception(exc)

    keys: list[str] = []
    labels: list[str] = []
    for row in rows:
        keys.append(row["type"])
        labels.append(
            f"{_SPRAY_TYPE_LABEL.get(row['type'], row['type'])} "
            f"— {row['pct']}% covered · {row['eligible']} eligible"
        )
    keys.append("custom")
    labels.append("Custom password (type a password to spray)")
    if _resolve_mined_spray_candidates(shell, domain):
        keys.append("mined")
        labels.append("Environment-mined base word (targeted spray)")
    if has_pending:
        keys.append("retry_found")
        labels.append("Retry passwords found in shares")
    if has_reuse:
        keys.append("retry_reuse")
        labels.append("Retry SAM → domain password reuse")
    keys.append("__done__")
    labels.append("Done (finish spraying)")

    idx = shell._questionary_select(
        f"Select a spray to run on {domain}:", labels, default_idx=0
    )
    if idx is None:
        return None
    choice = keys[idx] if 0 <= idx < len(keys) else "__done__"
    return None if choice == "__done__" else choice


def _dispatch_spray_choice(
    shell: "SprayShell", domain: str, choice: str, *, overview: dict, interactive: bool
) -> None:
    """Execute one selected spray via the existing per-type executors.

    Strategy-level scan-config gating: the canonical spray strategies (``blank``,
    ``useraspass``, ``reuse``) map to ``password_spraying`` subphases the client
    can disable individually. The retry/custom selector entries are not strategy
    subphases and are never gated here. Absent config = every strategy runs.
    """
    from adscan_internal.services.scan_phases import subphase_is_enabled

    if choice in {"blank", "useraspass", "reuse"} and not subphase_is_enabled(
        shell, "password_spraying", choice
    ):
        print_info(
            f"Spray strategy '{choice}' skipped (disabled in scan configuration)."
        )
        return
    if choice == "useraspass":
        transform = _select_useraspass_transform(shell, interactive=interactive)
        spraying_with_username_as_password(shell, domain, transform=transform)
    elif choice == "reuse":
        for pwd in _select_owned_passwords(
            shell, overview.get("owned", []), interactive=interactive
        ):
            spraying_with_password(
                shell, domain, pwd, entry_label="owned-credential reuse"
            )
    elif choice == "blank":
        spraying_with_blank_password(shell, domain)
    elif choice == "custom":
        pwd = Prompt.ask("Enter the password to spray")
        if pwd:
            spraying_with_password(shell, domain, pwd)
    elif choice == "mined":
        _spray_mined_base_word(shell, domain)
    elif choice == "retry_found":
        retry_pending_password_spraying(shell, domain)
    elif choice == "retry_reuse":
        retry_pending_domain_reuse_validation(shell, domain)


def _resolve_mined_spray_candidates(shell: "SprayShell", domain: str) -> list[str]:
    """Return environment-mined base-word candidates for a targeted spray.

    Thin wrapper over the SSOT ``custom_wordlist_service.build_spray_candidates``:
    resolves the workspace inventory dir + the domain's ``domains_data`` and asks
    the generator for the mined seed words (company/netbios/OU/description/host
    tokens). Best-effort — any failure yields an empty list so the selector just
    omits the option. These are SEED passwords the operator opts into; each is
    sprayed through the existing lockout-aware executor unchanged.
    """
    try:
        from adscan_internal.services import custom_wordlist_service as cwl

        try:
            workspace_cwd = shell._get_workspace_cwd()  # noqa: SLF001
        except Exception:  # noqa: BLE001
            workspace_cwd = getattr(shell, "current_workspace_dir", "") or os.getcwd()
        domain_data = (getattr(shell, "domains_data", {}) or {}).get(domain, {}) or {}
        return cwl.build_spray_candidates(
            workspace_dir=workspace_cwd, domain=domain, domain_data=domain_data
        )
    except Exception as exc:  # noqa: BLE001 — mining is optional, never blocks spray
        telemetry.capture_exception(exc)
        return []


def _spray_mined_base_word(shell: "SprayShell", domain: str) -> None:
    """Offer environment-mined base words as opt-in spray seeds, spray the pick.

    The operator selects ONE mined base word (or types their own); it is sprayed
    via the existing :func:`spraying_with_password` executor, so the observation
    window + ``badPwdCount`` lockout safety and policy filtering are unchanged —
    this only pre-populates the base password from environment intelligence.
    """
    candidates = _resolve_mined_spray_candidates(shell, domain)
    if not candidates:
        print_info(
            "No environment-mined base words available "
            "(collect inventory first, then retry)."
        )
        return
    # Cap the menu so a large mined set stays readable; the highest-signal words
    # (env-structural provenance) are already ordered first by the generator.
    shortlist = candidates[:20]
    labels = list(shortlist) + ["Type a custom base word"]
    idx = shell._questionary_select(  # noqa: SLF001
        f"Select an environment-mined base word to spray on {domain}:",
        labels,
        default_idx=0,
    )
    if idx is None:
        return
    if idx == len(labels) - 1:
        base_word = Prompt.ask("Enter the base word to spray")
    else:
        base_word = shortlist[idx] if 0 <= idx < len(shortlist) else ""
    base_word = str(base_word or "").strip()
    if base_word:
        spraying_with_password(
            shell, domain, base_word, entry_label="environment-mined base word"
        )


def run_spray_coverage(
    shell: "SprayShell", domain: str, *, interactive: bool, include_pre2k: bool = True
):
    """Run the two-step spray phase (pre2k step + coverage-aware selector loop).

    Returns the :class:`DeferredSprayQueue` of near-threshold combos held back for
    reconciliation. The orchestration never sprays an account within the 2-attempt
    lockout margin (the executors enforce it), and the ci path terminates
    deterministically once every spray type is covered or has no eligible users.

    Args:
        shell: Active spray-capable shell.
        domain: Target domain.
        interactive: True for ``adscan start`` (operator-driven selector); False for
            ``adscan ci`` (priority auto-pick, no prompts, full coverage).
        include_pre2k: Run the pre2k computer-account step first (the full phase
            flow). The manual ``spraying`` REPL command sets this False — pre2k is
            its own command (``pre2k``) there, so the manual flow is just the
            coverage selector loop.
    """
    from adscan_internal.services.spray_deferred_queue import (
        DeferredSprayCombo,
        DeferredSprayQueue,
    )

    queue = DeferredSprayQueue()
    if shell.domains_data.get(domain, {}).get("auth") == "pwned":
        return queue

    # Step 1 — pre2k (educational, gated). Skipped for the manual selector-only flow.
    if include_pre2k:
        _run_pre2k_step(shell, domain, interactive=interactive)
    if shell.domains_data.get(domain, {}).get("auth") == "pwned":
        return queue

    # Step 2 — coverage-aware selector loop.
    ci_done: set[str] = set()
    last_overview: "dict | None" = None
    for _iteration in range(_SPRAY_SELECTOR_MAX_ITER):
        if shell.domains_data.get(domain, {}).get("auth") == "pwned":
            break
        overview = _compute_spray_coverage_overview(shell, domain)
        if overview is None:
            # Coverage could not be computed (no user list / policy). Interactive
            # falls back to the legacy menu once; ci has nothing safe to do.
            if interactive:
                do_spraying(shell, domain)
            break
        last_overview = overview
        rows = overview["rows"]

        # Nothing sprayable right now — every account is locked, near lockout, or
        # owned. Re-prompting an empty selector is noise; finish the phase. (ci
        # already terminates here because _ci_pick_spray finds no eligible type;
        # this makes the interactive path stop too instead of looping on "Done".)
        if not overview["eligibility"].eligible_users:
            print_info(
                "No eligible users remain (all locked, near lockout, or owned) — "
                "password spraying complete."
            )
            break

        if interactive:
            has_pending = bool(
                _load_pending_spraying_password_candidates(shell, domain=domain)
            )
            has_reuse = bool(
                _load_pending_domain_reuse_candidates(shell, domain=domain)
            )
            choice = _interactive_select_spray(
                shell, domain, overview, has_pending=has_pending, has_reuse=has_reuse
            )
            if choice is None:
                break
            row = next((r for r in rows if r["type"] == choice), None)
            if row is not None and row["pct"] < 100 and row["eligible"] <= 0:
                print_warning(
                    "No users are currently eligible for this spray — all are within "
                    "the lockout safety margin. Re-run after the observation window resets."
                )
                continue
        else:
            choice = _ci_pick_spray(rows, ci_done)
            if choice is None:
                break  # every type covered or no eligible users -> phase done
            ci_done.add(choice)

        try:
            _dispatch_spray_choice(
                shell, domain, choice, overview=overview, interactive=interactive
            )
        except Exception as exc:  # noqa: BLE001 — one spray must not abort the loop
            telemetry.capture_exception(exc)
            print_error(f"Spray '{choice}' failed; continuing.")

    # Seed the deferred queue from the final near-threshold exclusions (best-effort).
    try:
        eligibility = (last_overview or {}).get("eligibility")
        for entry in getattr(eligibility, "excluded_users", []) or []:
            queue.upsert(
                DeferredSprayCombo(
                    user=str(getattr(entry, "username", "") or ""),
                    password=BLANK_PASSWORD_SENTINEL,
                    spray_type="near-threshold",
                    earliest_safe_epoch=None,
                )
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
    return queue
