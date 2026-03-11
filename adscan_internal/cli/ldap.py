"""CLI orchestration for LDAP enumeration.

This module keeps interactive CLI concerns (printing, reporting, file persistence)
separate from the LDAP service layer.
"""

from __future__ import annotations

from collections.abc import Callable
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional, Protocol, Tuple

from rich.prompt import Prompt, Confirm
from rich.table import Table

from adscan_core.username_patterns import (
    USERNAME_PATTERN_LABELS,
    build_username_pattern_candidates,
    format_username_pattern_option,
    normalize_username_candidate,
    rank_username_patterns_from_observed_pairs,
)
from adscan_internal import (
    print_error,
    print_exception,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_operation_header,
    print_success,
    print_success_verbose,
    print_warning,
    telemetry,
)
from adscan_internal.core import AuthMode
from adscan_internal.cli.common import SECRET_MODE, build_lab_event_fields
from adscan_internal.cli.tools_env import TOOLS_INSTALL_DIR
from adscan_internal.cli.host_file_picker import (
    is_full_container_runtime,
    maybe_import_host_file_to_workspace,
    select_host_file_via_gui,
)
from adscan_internal.integrations.netexec.parsers import (
    parse_machine_account_quota,
    parse_netexec_group_members,
    parse_netexec_samaccountnames,
)
from adscan_internal.execution_outcomes import output_has_exact_ldap_connection_timeout
from adscan_internal.path_utils import get_adscan_home, get_effective_user_home
from adscan_internal.rich_output import (
    BRAND_COLORS,
    mark_sensitive,
    print_panel_with_table,
)
from adscan_internal.services import EnumerationService
from adscan_internal.services.enumeration.ldap import LDAPAnonymousUserRecord
from adscan_internal.services.credsweeper_service import CredSweeperService
from adscan_internal.services.attack_graph_service import (
    CredentialSourceStep,
    resolve_group_members_by_rid,
)
from adscan_internal.workspaces import domain_relpath, domain_subpath


class LdapShell(Protocol):
    """Minimal shell surface used by the LDAP CLI controller."""

    domains: list[str]
    domains_dir: str
    ldap_dir: str
    domain: str | None
    type: str | None
    auto: bool
    scan_mode: str | None
    current_workspace_dir: str | None
    domains_data: dict
    netexec_path: str | None
    credsweeper_path: str | None
    auto: bool
    kerberos_dir: str
    console: object

    def _get_workspace_cwd(self) -> str: ...

    def _get_service_executor(
        self,
    ) -> Callable[[str, int], subprocess.CompletedProcess[str]]: ...

    def _get_lab_slug(self) -> str | None: ...

    def update_report_field(self, domain: str, field: str, value: object) -> None: ...

    def ask_for_enumerate_user_aces(
        self, domain: str, username: str, password: str
    ) -> None: ...

    def _display_items(self, items: list[str], label: str) -> None: ...

    def _write_domain_list_file(
        self, domain: str, filename: str, values: list[str]
    ) -> str: ...

    def _write_user_list_file(
        self, domain: str, filename: str, users: list[str]
    ) -> str: ...

    def _postprocess_user_list_file(
        self,
        domain: str,
        filename: str,
        *,
        trigger_followups: bool = True,
        source: str | None = None,
    ) -> None: ...

    def build_auth_nxc(
        self, username: str, password: str, domain: str, kerberos: bool = False
    ) -> str: ...

    def run_command(
        self, command: str, timeout: int | None = None, cwd: str | None = None
    ) -> subprocess.CompletedProcess[str]: ...

    def _questionary_select(
        self, message: str, options: list[str], default_idx: int = 0
    ) -> int | None: ...

    def _generate_user_permutations_interactive(self, domain: str) -> str | None: ...

    def ask_for_kerberos_user_enum(
        self, domain: str, relaunch: bool = False
    ) -> None: ...

    def do_enum_with_users(self, domain: str) -> None: ...

    def ask_for_asreproast(self, domain: str) -> None: ...

    def ask_for_spraying(self, domain: str) -> None: ...

    def _is_full_adscan_container_runtime(self) -> bool: ...

    def _run_netexec(
        self, command: str, domain: str | None = None, timeout: int | None = None
    ) -> subprocess.CompletedProcess[str]: ...

    def add_credential(
        self, domain: str, username: str, credential: str, **kwargs: object
    ) -> None: ...

    def do_sync_clock_with_pdc(self, domain: str) -> None: ...

    def ask_for_bloodhound(self, target_domain: str, callback=None) -> None: ...

    def run_enumeration(
        self, domain: str, *, stop_after_phase: int | None = None
    ) -> None: ...

    def do_check_dns(self, domain: str) -> bool: ...

    def do_update_resolv_conf(self, resolv_conf_line: str) -> None: ...

    def convert_hostnames_to_ips_and_scan(
        self, domain: str, computers_file: str, nmap_dir: str
    ) -> None: ...

    def ask_for_smb_descriptions(self, domain: str) -> None: ...

    credsweeper_path: str | None

    base_dn: str | None


def derive_base_dn(domain: str) -> str:
    """Derive Base Distinguished Name (DN) from a domain name.

    Takes a domain name, splits it into its components, and constructs
    the Base DN by joining each component as a Domain Component (DC).

    Args:
        domain: The domain name from which to extract the Base DN.

    Returns:
        The Base DN string (e.g., "DC=example,DC=local" for "example.local").

    Example:
        >>> derive_base_dn("example.local")
        'DC=example,DC=local'
    """
    domain_parts = domain.split(".")
    return ",".join([f"DC={part}" for part in domain_parts])


def extract_base_dn(shell: LdapShell, domain: str) -> str:
    """Extract Base Distinguished Name (DN) from a domain and update shell.

    This function derives the Base DN from the domain name and updates
    the shell's base_dn attribute.

    Args:
        shell: The shell instance to update.
        domain: The domain name from which to extract the Base DN.

    Returns:
        The Base DN string.
    """
    base_dn = derive_base_dn(domain)
    shell.base_dn = base_dn
    return base_dn


def ask_for_ldap_users(shell: LdapShell, target_domain: str) -> None:
    """Prompt to enumerate LDAP users for a domain and run the action if confirmed."""
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return

    marked_target_domain = mark_sensitive(target_domain, "domain")
    answer = Confirm.ask(
        f"Do you want to enumerate LDAP users for the domain {marked_target_domain}?"
    )
    if answer:
        run_ldap_active_users(shell, target_domain)


def ask_for_ldap_computers(shell: LdapShell, target_domain: str) -> None:
    """Prompt to enumerate LDAP computers for a domain and run the action if confirmed."""
    marked_target_domain = mark_sensitive(target_domain, "domain")
    answer = Confirm.ask(
        f"Do you want to enumerate LDAP computers for the domain {marked_target_domain}?"
    )
    if answer:
        run_ldap_computers(shell, target_domain)


_LDAP_ANONYMOUS_DISCOVERY_FILTER = "(objectClass=*)"

_LDAP_NON_USER_DISCOVERY_CNS = {
    "account operators",
    "administrators",
    "backup operators",
    "cert publishers",
    "cloneable domain controllers",
    "cryptographic operators",
    "denied rodc password replication group",
    "distributed com users",
    "dnsadmins",
    "dnsupdateproxy",
    "domain admins",
    "domain computers",
    "domain controllers",
    "domain guests",
    "domain users",
    "enterprise admins",
    "enterprise key admins",
    "event log readers",
    "group policy creator owners",
    "guests",
    "hyper-v administrators",
    "iis_iusrs",
    "incoming forest trust builders",
    "key admins",
    "network configuration operators",
    "performance log users",
    "performance monitor users",
    "pre-windows 2000 compatible access",
    "print operators",
    "protected users",
    "ras and ias servers",
    "rdc denied password replication group",
    "read-only domain controllers",
    "remote desktop users",
    "remote management users",
    "replicator",
    "schema admins",
    "server operators",
    "storage replica administrators",
    "terminal server license servers",
    "users",
    "windows authorization access group",
}

_LDAP_NOISY_USER_CANDIDATE_CNS = {
    "guest",
    "invitado",
    "krbtgt",
}


def _display_ldap_anonymous_pattern_preview(
    records: list[LDAPAnonymousUserRecord],
    *,
    pattern_key: str,
    max_rows: int = 20,
) -> None:
    """Preview how a username pattern applies to CN-only LDAP candidates."""
    if not records:
        return

    table = Table(
        title=(
            "Anonymous LDAP Username Inference Preview "
            f"({USERNAME_PATTERN_LABELS.get(pattern_key, pattern_key)})"
        ),
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("CN", style="cyan", max_width=32)
    table.add_column("Inferred Username", style="white", max_width=40)

    shown_records = records[: max(1, max_rows)]
    for idx, record in enumerate(shown_records, 1):
        candidates = build_username_pattern_candidates(str(record.common_name or ""))
        inferred = candidates.get(pattern_key) or candidates.get("single") or "-"
        table.add_row(str(idx), str(record.common_name), str(inferred))

    if len(records) > max_rows:
        table.caption = (
            f"Showing first {max_rows}. {len(records) - max_rows} more not shown."
        )

    print_panel_with_table(table, border_style=BRAND_COLORS["info"])


def _select_recommended_username_pattern(
    ranked_patterns: list[tuple[str, int]],
) -> str | None:
    """Return the strongest recommended username pattern, if any."""
    if not ranked_patterns:
        return None

    top_pattern, top_score = ranked_patterns[0]
    if len(ranked_patterns) == 1 or (
        len(ranked_patterns) > 1 and ranked_patterns[1][1] < top_score
    ):
        return top_pattern
    return None


def _choose_username_pattern(
    shell: LdapShell,
    *,
    domain: str,
    unresolved_records: list[LDAPAnonymousUserRecord],
    ranked_patterns: list[tuple[str, int]],
) -> str:
    """Choose a naming pattern for CN-only LDAP user objects."""
    if not unresolved_records:
        return "first.last"

    recommended_pattern = _select_recommended_username_pattern(ranked_patterns)
    if recommended_pattern:
        print_info_debug(
            f"[ldap] Recommended username pattern {recommended_pattern} from "
            f"{ranked_patterns[0][1]} confirmed anonymous LDAP match(es)."
        )

    pattern_keys: list[str] = []
    seen_pattern_keys: set[str] = set()
    for record in unresolved_records:
        candidates = build_username_pattern_candidates(str(record.common_name or ""))
        for pattern_key in candidates:
            if pattern_key in seen_pattern_keys:
                continue
            seen_pattern_keys.add(pattern_key)
            pattern_keys.append(pattern_key)

    if recommended_pattern and recommended_pattern not in seen_pattern_keys:
        pattern_keys.append(recommended_pattern)
        seen_pattern_keys.add(recommended_pattern)

    if "single" not in seen_pattern_keys:
        pattern_keys.append("single")
        seen_pattern_keys.add("single")

    example_record = next(
        (
            record
            for record in unresolved_records
            if len(build_username_pattern_candidates(str(record.common_name or ""))) > 1
        ),
        unresolved_records[0],
    )
    sample_cn = str(example_record.common_name or "").strip() or "John Smith"
    options: list[str] = []
    for pattern_key in pattern_keys:
        label = format_username_pattern_option(pattern_key, sample_cn)
        if pattern_key == recommended_pattern:
            label = f"{label} (Recommended)"
        options.append(label)

    selector = getattr(shell, "_questionary_select", None)
    marked_domain = mark_sensitive(domain, "domain")
    if selector and not getattr(shell, "auto", False):
        if recommended_pattern:
            if Confirm.ask(
                (
                    f"Use the recommended username format "
                    f"'{USERNAME_PATTERN_LABELS.get(recommended_pattern, recommended_pattern)}' "
                    f"for {marked_domain}?"
                ),
                default=True,
            ):
                return recommended_pattern

        while True:
            default_idx = 0
            if recommended_pattern and recommended_pattern in pattern_keys:
                default_idx = pattern_keys.index(recommended_pattern)
            idx = selector(
                (
                    f"Anonymous LDAP exposed CN-only users in {marked_domain}. "
                    "Select the username format to validate via Kerberos:"
                ),
                options,
                default_idx,
            )
            chosen_pattern = recommended_pattern or pattern_keys[0]
            if idx is not None and 0 <= idx < len(pattern_keys):
                chosen_pattern = pattern_keys[idx]

            _display_ldap_anonymous_pattern_preview(
                unresolved_records,
                pattern_key=chosen_pattern,
            )
            if Confirm.ask(
                "Use this inferred username format for Kerberos validation?",
                default=True,
            ):
                return chosen_pattern

    if recommended_pattern:
        return recommended_pattern

    default_pattern = pattern_keys[0] if pattern_keys else "first.last"
    print_info_debug(
        f"[ldap] Falling back to default username pattern {default_pattern} for "
        f"anonymous LDAP CN inference in {domain}."
    )
    return default_pattern


def _save_ldap_anonymous_inventory_json(
    shell: LdapShell,
    records: list[LDAPAnonymousUserRecord],
    domain: str,
) -> Optional[str]:
    """Persist anonymous LDAP user inventory for troubleshooting."""
    if not records:
        return None

    try:
        workspace_cwd = shell._get_workspace_cwd()
        ldap_dir = domain_subpath(
            workspace_cwd, shell.domains_dir, domain, shell.ldap_dir
        )
        os.makedirs(ldap_dir, exist_ok=True)
        json_file = os.path.join(ldap_dir, "anonymous_inventory.json")
        with open(json_file, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "domain": domain,
                    "count": len(records),
                    "users": [record.to_dict() for record in records],
                },
                handle,
                indent=2,
                ensure_ascii=False,
            )
        return json_file
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_warning(f"Failed to save anonymous LDAP inventory: {exc}")
        return None


def _display_ldap_anonymous_unresolved_users(
    records: list[LDAPAnonymousUserRecord],
    *,
    pattern_key: str | None = None,
    max_rows: int = 20,
) -> None:
    """Display CN-only users that still need username inference."""
    unresolved = [
        record
        for record in records
        if not str(record.samaccountname or "").strip()
        and str(record.common_name or "").strip()
    ]
    if not unresolved:
        return

    table = Table(
        title=f"Anonymous LDAP Users Requiring Username Inference ({len(unresolved)})",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("CN", style="cyan", max_width=32)
    if pattern_key:
        table.add_column("Inferred Username", style="white", max_width=40)

    for idx, record in enumerate(unresolved[: max(1, max_rows)], 1):
        if pattern_key:
            candidates = build_username_pattern_candidates(str(record.common_name or ""))
            inferred = candidates.get(pattern_key) or candidates.get("single") or "-"
            table.add_row(str(idx), str(record.common_name), str(inferred))
        else:
            table.add_row(str(idx), str(record.common_name))

    if len(unresolved) > max_rows:
        table.caption = (
            f"Showing first {max_rows}. {len(unresolved) - max_rows} more not shown."
        )

    print_panel_with_table(table, border_style=BRAND_COLORS["warning"])


def _display_ldap_anonymous_confirmed_users(
    usernames: list[str], *, max_rows: int = 20
) -> None:
    """Display usernames confirmed directly through anonymous LDAP."""
    if not usernames:
        return

    table = Table(
        title=f"Anonymous LDAP Confirmed Enabled Users ({len(usernames)})",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Username", style="cyan", max_width=40)

    shown = usernames[: max(1, max_rows)]
    for idx, username in enumerate(shown, 1):
        table.add_row(str(idx), username)

    if len(usernames) > max_rows:
        table.caption = (
            f"Showing first {max_rows}. {len(usernames) - max_rows} more not shown."
        )

    print_panel_with_table(table, border_style=BRAND_COLORS["info"])


def _is_likely_ldap_user_candidate(record: LDAPAnonymousUserRecord) -> bool:
    """Best-effort filter for CN-only objects discovered via anonymous LDAP.

    The broad ``(objectClass=*)`` query can expose users without attributes, but
    it also exposes groups, containers and system objects. We keep the heuristic
    intentionally conservative and let Kerberos validation decide the final set.
    """
    dn = str(record.distinguished_name or "").strip()
    common_name = str(record.common_name or "").strip()
    if not dn or not common_name:
        return False

    dn_lower = dn.casefold()
    cn_lower = common_name.casefold()
    if dn.startswith("DC="):
        return False
    if common_name.endswith("$"):
        return False
    if "cn=configuration," in dn_lower or "cn=schema," in dn_lower:
        return False
    if cn_lower in _LDAP_NON_USER_DISCOVERY_CNS:
        return False
    if cn_lower in _LDAP_NOISY_USER_CANDIDATE_CNS:
        return False

    # Keep likely user placements: standard Users container or custom OUs.
    return ",cn=users," in f",{dn_lower}" or ",ou=" in f",{dn_lower}"


def _validate_ldap_anonymous_username_candidates(
    shell: LdapShell,
    domain: str,
    candidates: list[str],
) -> set[str]:
    """Validate inferred usernames with Kerberos pre-auth enumeration."""
    normalized = sorted(
        {
            normalize_username_candidate(candidate)
            for candidate in candidates
            if normalize_username_candidate(candidate)
        }
    )
    if not normalized:
        return set()

    kerbrute_path = os.path.join(TOOLS_INSTALL_DIR, "kerbrute", "kerbrute")
    if not os.path.isfile(kerbrute_path) or not os.access(kerbrute_path, os.X_OK):
        print_warning(
            "kerbrute is not available; skipping validation of anonymous LDAP username candidates."
        )
        return set()

    workspace_cwd = shell._get_workspace_cwd()
    kerberos_dir = domain_subpath(
        workspace_cwd, shell.domains_dir, domain, shell.kerberos_dir
    )
    os.makedirs(kerberos_dir, exist_ok=True)
    wordlist_path = Path(os.path.join(kerberos_dir, "ldap_anonymous_candidates.txt"))
    output_file = Path(
        os.path.join(kerberos_dir, "ldap_anonymous_candidate_validation.log")
    )
    wordlist_path.write_text("\n".join(normalized) + "\n", encoding="utf-8")

    print_info(
        f"Validating {len(normalized)} inferred LDAP anonymous username candidate(s) via Kerberos."
    )
    enum_service = EnumerationService()
    executor = shell._get_service_executor()
    validated = enum_service.kerberos.enumerate_users_kerberos(
        domain=domain,
        pdc=shell.domains_data[domain]["pdc"],
        wordlist=str(wordlist_path),
        kerbrute_path=kerbrute_path,
        output_file=output_file,
        executor=executor,
        scan_id=None,
        timeout=300,
    )
    validated_set = {
        normalize_username_candidate(username) for username in validated if username
    }
    print_info_debug(
        f"[ldap] Validated {len(validated_set)}/{len(normalized)} inferred username "
        "candidate(s) through Kerberos."
    )
    return validated_set


def run_post_user_discovery_followups(
    shell: LdapShell,
    domain: str,
    *,
    source: str,
    pre_with_users_callback: Callable[[], None] | None = None,
    pre_with_users_step: str | None = None,
    allow_with_users: bool = True,
) -> None:
    """Run the shared follow-up workflow after recovering domain users.

    This centralizes the transition from "we recovered users" to optional
    pre-follow-up steps (for example LDAP/SMB descriptions) and finally the
    legacy ``with_users`` flow. The helper avoids duplicated AS-REP/spraying
    prompts by skipping the ``with_users`` transition when the domain is
    already authenticated or already marked as ``with_users``.
    """
    def _capture_followup_event(action: str, **extra: object) -> None:
        """Emit a telemetry event for post-user-discovery flow transitions."""
        try:
            properties: dict[str, object] = {
                "source": source,
                "action": action,
                "auth_type": shell.domains_data.get(domain, {}).get("auth", "unknown"),
                "pre_with_users_step": pre_with_users_step,
                "allow_with_users": allow_with_users,
                "scan_mode": getattr(shell, "scan_mode", None),
                "workspace_type": getattr(shell, "type", None),
                "auto_mode": getattr(shell, "auto", False),
            }
            properties.update(build_lab_event_fields(shell=shell, include_slug=True))
            properties.update(extra)
            telemetry.capture("user_discovery_followups", properties)
        except Exception as exc:  # pragma: no cover - best effort telemetry
            telemetry.capture_exception(exc)

    current_auth = str(shell.domains_data.get(domain, {}).get("auth") or "unknown")
    print_info_debug(
        f"[user_discovery_followups] source={source} domain={domain} "
        f"auth_before={current_auth} allow_with_users={allow_with_users}"
    )
    _capture_followup_event("start", auth_before=current_auth)

    if pre_with_users_callback is not None:
        step_name = pre_with_users_step or "pre_with_users_callback"
        print_info_debug(
            f"[user_discovery_followups] source={source} domain={domain} "
            f"running_pre_step={step_name}"
        )
        pre_with_users_callback()
        current_auth = str(shell.domains_data.get(domain, {}).get("auth") or "unknown")
        print_info_debug(
            f"[user_discovery_followups] source={source} domain={domain} "
            f"auth_after_pre_step={current_auth}"
        )
        _capture_followup_event(
            "pre_step_completed",
            auth_after=current_auth,
            executed_pre_step=step_name,
        )

    if not allow_with_users:
        print_info_debug(
            f"[user_discovery_followups] source={source} domain={domain} "
            "with_users_disabled_for_this_flow=True"
        )
        _capture_followup_event("skip_with_users", reason="allow_with_users_false")
        return

    if current_auth in {"auth", "pwned"}:
        print_info_debug(
            f"[user_discovery_followups] source={source} domain={domain} "
            f"skipping_with_users_due_to_auth={current_auth}"
        )
        _capture_followup_event(
            "skip_with_users",
            reason="domain_already_authenticated",
            auth_after=current_auth,
        )
        return

    if current_auth == "with_users":
        print_info_debug(
            f"[user_discovery_followups] source={source} domain={domain} "
            "skipping_with_users_already_active=True"
        )
        _capture_followup_event(
            "skip_with_users",
            reason="with_users_already_active",
            auth_after=current_auth,
        )
        return

    print_info_debug(
        f"[user_discovery_followups] source={source} domain={domain} "
        "launching_with_users=True"
    )
    _capture_followup_event("launch_with_users", auth_after=current_auth)
    shell.do_enum_with_users(domain)


def _run_ldap_anonymous_followups(shell: LdapShell, domain: str) -> None:
    """Expand an anonymous LDAP bind into user discovery and standard follow-ups."""
    if not shell.netexec_path:
        return

    enum_service = EnumerationService()
    executor = shell._get_service_executor()
    workspace_cwd = shell._get_workspace_cwd()

    active_log_abs = domain_subpath(
        workspace_cwd,
        shell.domains_dir,
        domain,
        shell.ldap_dir,
        "ldap_anonymous_active_users.log",
    )
    query_log_abs = domain_subpath(
        workspace_cwd,
        shell.domains_dir,
        domain,
        shell.ldap_dir,
        "ldap_anonymous_discovery.log",
    )
    os.makedirs(os.path.dirname(active_log_abs), exist_ok=True)

    active_users = enum_service.ldap.enumerate_active_users_anonymous(
        pdc=shell.domains_data[domain]["pdc"],
        netexec_path=shell.netexec_path,
        log_file=active_log_abs,
        executor=executor,
        scan_id=None,
        timeout=120,
    )
    records = enum_service.ldap.query_anonymous_user_inventory(
        pdc=shell.domains_data[domain]["pdc"],
        netexec_path=shell.netexec_path,
        log_file=query_log_abs,
        ldap_filter=_LDAP_ANONYMOUS_DISCOVERY_FILTER,
        executor=executor,
        scan_id=None,
        timeout=180,
    )

    inventory_json = _save_ldap_anonymous_inventory_json(shell, records, domain)
    if inventory_json:
        marked_inventory_json = mark_sensitive(inventory_json, "path")
        print_info_debug(
            f"[ldap] Saved anonymous LDAP inventory to {marked_inventory_json}"
        )

    confirmed_users = {
        normalize_username_candidate(username)
        for username in active_users
        if normalize_username_candidate(username)
    }
    if confirmed_users:
        confirmed_sorted = sorted(confirmed_users)
        _display_ldap_anonymous_confirmed_users(confirmed_sorted)
        print_info(
            f"Anonymous LDAP confirmed {len(confirmed_sorted)} enabled user(s) directly."
        )

    resolved_user_by_dn: dict[str, str] = {}
    direct_sam_records: list[LDAPAnonymousUserRecord] = []
    unresolved_records: list[LDAPAnonymousUserRecord] = []
    active_users_keys = {user.casefold() for user in confirmed_users}

    for record in records:
        record_dn = str(record.distinguished_name or "").strip()
        samaccountname = normalize_username_candidate(record.samaccountname)
        if samaccountname and samaccountname.casefold() in active_users_keys:
            resolved_user_by_dn[record_dn] = samaccountname
            direct_sam_records.append(record)
        elif not samaccountname and _is_likely_ldap_user_candidate(record):
            unresolved_records.append(record)

    # De-duplicate unresolved records by DN while preserving discovery order.
    unresolved_by_dn: dict[str, LDAPAnonymousUserRecord] = {}
    for record in unresolved_records:
        record_dn = str(record.distinguished_name or "").strip()
        if record_dn and record_dn not in unresolved_by_dn:
            unresolved_by_dn[record_dn] = record
    unresolved_records = list(unresolved_by_dn.values())

    if unresolved_records:
        observed_pairs = [
            (str(record.common_name or ""), str(record.samaccountname or ""))
            for record in direct_sam_records
        ]
        ranked_patterns = rank_username_patterns_from_observed_pairs(observed_pairs)
        recommended_pattern = _select_recommended_username_pattern(ranked_patterns)
        _display_ldap_anonymous_unresolved_users(
            unresolved_records,
            pattern_key=recommended_pattern,
        )
        selected_pattern = _choose_username_pattern(
            shell,
            domain=domain,
            unresolved_records=unresolved_records,
            ranked_patterns=ranked_patterns,
        )
        candidate_to_dn: dict[str, str] = {}
        for record in unresolved_records:
            candidates = build_username_pattern_candidates(record.common_name)
            candidate = candidates.get(selected_pattern) or candidates.get("single")
            candidate = normalize_username_candidate(candidate or "")
            if not candidate or candidate in candidate_to_dn:
                continue
            candidate_to_dn[candidate] = str(record.distinguished_name or "").strip()

        if candidate_to_dn:
            print_info(
                f"Anonymous LDAP also exposed {len(candidate_to_dn)} CN-only user candidate(s); validating them via Kerberos."
            )
            validated_candidates = _validate_ldap_anonymous_username_candidates(
                shell, domain, list(candidate_to_dn.keys())
            )
            for candidate in validated_candidates:
                record_dn = candidate_to_dn.get(candidate)
                if not record_dn:
                    continue
                confirmed_users.add(candidate)
                resolved_user_by_dn[record_dn] = candidate

    if confirmed_users:
        shell._write_user_list_file(domain, "users.txt", sorted(confirmed_users))
        try:
            shell._postprocess_user_list_file(
                domain,
                "users.txt",
                trigger_followups=False,
                source="ldap_anonymous",
            )
        except Exception as exc:  # pragma: no cover - defensive
            telemetry.capture_exception(exc)
            print_warning(f"Failed to postprocess anonymous LDAP users.txt: {exc}")
        print_success(
            f"Recovered {len(confirmed_users)} unique username(s) from anonymous LDAP."
        )
    else:
        print_warning(
            "Anonymous LDAP bind succeeded, but no reusable usernames were recovered."
        )

    run_post_user_discovery_followups(
        shell,
        domain,
        source="ldap_anonymous",
        pre_with_users_callback=lambda: run_ldap_descriptions(
            shell, domain, anonymous=True
        ),
        pre_with_users_step="ldap_descriptions_anonymous",
        allow_with_users=bool(confirmed_users),
    )


def run_ldap_anonymous(shell: LdapShell, domain: str) -> dict[str, object] | None:
    """Test anonymous LDAP access via the LDAP service."""
    if domain not in shell.domains_data:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"Unknown domain: {marked_domain}")
        return None

    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return None

    if shell.type == "ctf" and shell.domains_data[domain].get("auth") in [
        "auth",
        "pwned",
    ]:
        return None

    print_operation_header(
        "Anonymous LDAP Access Test",
        details={
            "Domain": domain,
            "PDC": shell.domains_data[domain]["pdc"],
            "Authentication": "Anonymous (Empty Credentials)",
            "Protocol": "LDAP",
        },
        icon="🔓",
    )

    workspace_cwd = shell._get_workspace_cwd()
    log_file_abs = domain_subpath(
        workspace_cwd, shell.domains_dir, domain, shell.ldap_dir, "ldap_anonymous.log"
    )
    os.makedirs(os.path.dirname(log_file_abs), exist_ok=True)

    enum_service = EnumerationService()
    executor = shell._get_service_executor()
    result = enum_service.ldap.test_anonymous_access(
        pdc=shell.domains_data[domain]["pdc"],
        netexec_path=shell.netexec_path,
        log_file=log_file_abs,
        executor=executor,
        scan_id=None,
        timeout=60,
    )

    accessible = bool(result.get("accessible"))
    if accessible:
        print_success("Anonymous LDAP bind succeeded.")
        shell.update_report_field(domain, "ldap_anonymous", True)
        try:
            from adscan_internal.services.attack_graph_service import (
                upsert_ldap_anonymous_bind_entry_edge,
            )

            upsert_ldap_anonymous_bind_entry_edge(
                shell,
                domain,
                status="success",
                notes={
                    "source": "ldap_anonymous",
                    "protocol": "ldap",
                    "authentication": "anonymous_bind",
                    "pdc": shell.domains_data[domain]["pdc"],
                },
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
        _run_ldap_anonymous_followups(shell, domain)
        try:
            from adscan_internal.services.report_service import record_technical_finding

            record_technical_finding(
                shell,
                domain,
                key="ldap_anonymous",
                value=True,
                details={
                    "pdc": shell.domains_data[domain]["pdc"],
                },
                evidence=[
                    {
                        "type": "log",
                        "summary": "LDAP anonymous bind output",
                        "artifact_path": log_file_abs,
                    }
                ],
            )
        except Exception as exc:  # pragma: no cover
            telemetry.capture_exception(exc)
    else:
        print_warning("Anonymous LDAP bind denied.")
        shell.update_report_field(domain, "ldap_anonymous", False)

    return result


def run_bloodhound_collector(shell: LdapShell, target_domain: str) -> None:
    """Backward-compatible wrapper for BloodHound collection orchestration."""
    from adscan_internal.cli.bloodhound import run_bloodhound_collector as _runner

    _runner(shell, target_domain)


def run_ldap_computers(shell: LdapShell, target_domain: str) -> list[str] | None:
    """Enumerate LDAP computers (authenticated) using NetExec LDAP --computers."""
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return None

    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return None

    if not shell.domain or shell.domain not in shell.domains_data:
        print_error("No authenticated domain selected. Select a domain first.")
        return None

    username = shell.domains_data[shell.domain].get("username")
    password = shell.domains_data[shell.domain].get("password")
    if not username or not password:
        print_error(
            "Missing credentials (username/password) for LDAP computer enumeration."
        )
        return None

    output_rel = domain_relpath(shell.domains_dir, target_domain, "computers.txt")
    print_operation_header(
        "LDAP Computer Enumeration",
        details={
            "Target Domain": target_domain,
            "Auth Domain": shell.domain,
            "Username": username,
            "LDAP Server": shell.domains_data[target_domain]["pdc"],
            "Output": output_rel,
        },
        icon="💻",
    )

    enum_service = EnumerationService()
    executor = shell._get_service_executor()
    computers = enum_service.ldap.enumerate_computers(
        domain=target_domain,
        pdc=shell.domains_data[target_domain]["pdc"],
        auth_mode=AuthMode.AUTHENTICATED,
        username=username,
        password=password,
        netexec_path=shell.netexec_path,
        executor=executor,
        scan_id=None,
        timeout=120,
    )

    hostnames = [
        c.dns_hostname or c.hostname
        for c in computers
        if (c.dns_hostname or c.hostname)
    ]
    shell._write_domain_list_file(target_domain, "computers.txt", hostnames)
    shell._display_items(hostnames, "Computers")

    try:
        properties = {
            "count": len(hostnames),
            "scan_mode": getattr(shell, "scan_mode", None),
            "auth_type": shell.domains_data[target_domain].get("auth", "unknown"),
        }
        properties.update(build_lab_event_fields(shell=shell, include_slug=True))
        telemetry.capture("ldap_computers_enumerated", properties)
    except Exception as e:  # pragma: no cover
        telemetry.capture_exception(e)

    return hostnames


def run_enum_delegations(shell: LdapShell, domain: str) -> None:
    """Enumerate Kerberos delegations in the specified domain using the service layer."""
    if domain not in shell.domains_data:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"Domain '{marked_domain}' is not configured.")
        return

    if not shell.netexec_path and not getattr(shell, "impacket_scripts_dir", None):
        print_error(
            "Impacket scripts directory not configured. Please ensure Impacket is installed via 'adscan install'."
        )
        return

    if not getattr(shell, "impacket_scripts_dir", None):
        print_error(
            "Impacket scripts directory not configured. Please ensure Impacket is installed via 'adscan install'."
        )
        return

    find_delegation_path = os.path.join(shell.impacket_scripts_dir, "findDelegation.py")
    if not os.path.isfile(find_delegation_path) or not os.access(
        find_delegation_path, os.X_OK
    ):
        print_error(
            f"findDelegation.py not found or not executable in {shell.impacket_scripts_dir}. Please check Impacket installation."
        )
        return

    auth_domain = shell.domain or domain
    auth_username = shell.domains_data.get(auth_domain, {}).get("username")
    auth_password = shell.domains_data.get(auth_domain, {}).get("password")
    if not auth_username or not auth_password:
        print_error(
            "Missing credentials (username/password) for delegation enumeration."
        )
        return

    # Build Impacket auth string using existing helper on the shell.
    auth = shell.build_auth_impacket_no_host(auth_username, auth_password, auth_domain)
    marked_domain = mark_sensitive(domain, "domain")
    command = f"{find_delegation_path} {auth} -target-domain {marked_domain}"

    print_operation_header(
        "Kerberos Delegation Enumeration",
        details={
            "Domain": domain,
            "Auth Domain": auth_domain,
            "Username": auth_username,
            "Tool": "findDelegation.py",
        },
        icon="🔗",
    )
    print_info_debug(f"Command: {command}")

    enum_service = EnumerationService()
    executor = shell._get_service_executor()
    delegations, delegation_type_counts = enum_service.delegation.enumerate_delegations(
        domain=domain,
        command=command,
        executor=executor,
        timeout=300,
        scan_id=None,
    )

    # Update in-memory state: list of accounts with any delegation.
    shell.domains_data.setdefault(domain, {})
    shell.domains_data[domain]["delegations"] = [
        d.account for d in delegations if d.account
    ]

    # Update report fields based on delegation types.
    has_unconstrained = delegation_type_counts.get("unconstrained", 0) > 0
    has_constrained = any(
        delegation_type_counts.get(key, 0) > 0
        for key in (
            "constrained",
            "constrained_protocol_transition",
            "resource_based_constrained",
        )
    )
    shell.update_report_field(domain, "unconstrained_delegation", has_unconstrained)
    shell.update_report_field(domain, "constrained_delegation", has_constrained)

    # Telemetry
    try:
        properties = {
            "total_delegations": len(delegations),
            "unconstrained_count": delegation_type_counts.get("unconstrained", 0),
            "constrained_count": delegation_type_counts.get("constrained", 0),
            "constrained_protocol_transition_count": delegation_type_counts.get(
                "constrained_protocol_transition", 0
            ),
            "resource_based_constrained_count": delegation_type_counts.get(
                "resource_based_constrained", 0
            ),
            "unknown_count": delegation_type_counts.get("unknown", 0),
            "scan_mode": getattr(shell, "scan_mode", None),
            "auth_type": shell.domains_data[domain].get("auth", "unknown"),
            "workspace_type": shell.type,
            "auto_mode": shell.auto,
        }
        properties.update(build_lab_event_fields(shell=shell, include_slug=True))
        telemetry.capture("delegations_enumerated", properties)
    except Exception as exc:  # pragma: no cover
        telemetry.capture_exception(exc)

    # Pretty-print delegations using existing helper.
    if delegations:
        from adscan_internal.rich_output import print_delegations_summary
        from adscan_internal.services.enumeration.network import (
            is_computer_dc_for_domain,
        )

        try:
            from adscan_internal.services.report_service import record_attack_path
        except ImportError:  # pragma: no cover - public LITE repo excludes reports
            record_attack_path = None

        delegations_full_data = [
            {
                "account": d.account,
                "account_type": d.account_type,
                "delegation_type": d.delegation_type,
                "delegation_to": d.delegation_to,
            }
            for d in delegations
        ]
        print_delegations_summary(domain, delegations_full_data)

        domain_info = shell.domains_data.get(domain, {})
        for delegation in delegations:
            delegation_type_lower = (delegation.delegation_type or "").lower()
            if (
                "constrained" not in delegation_type_lower
                and "resource-based" not in delegation_type_lower
            ):
                continue
            target = delegation.delegation_to or ""
            if not target or target.lower() in {"n/a", "any", "-"}:
                continue
            if "/" in target:
                target_host = target.split("/", 1)[1]
            else:
                target_host = target
            target_host = target_host.split(":", 1)[0].split("@", 1)[0].strip()
            if not target_host:
                continue
            if not is_computer_dc_for_domain(
                domain=domain,
                target_host=target_host,
                domain_info=domain_info,
            ):
                continue
            if record_attack_path is None:
                continue
            record_attack_path(
                shell,
                domain,
                title=f"Delegation path to Domain Admin via {target_host}",
                source="delegation_enumeration",
                confidence="medium",
                status="theoretical",
                steps=[
                    {
                        "step": 1,
                        "action": "Compromise delegatable account",
                        "details": {
                            "account": delegation.account,
                            "account_type": delegation.account_type,
                        },
                    },
                    {
                        "step": 2,
                        "action": "Leverage delegation to target service",
                        "details": {
                            "delegation_type": delegation.delegation_type,
                            "delegation_to": delegation.delegation_to,
                        },
                    },
                    {
                        "step": 3,
                        "action": "Impersonate to Domain Controller service",
                        "details": {
                            "target_host": target_host,
                            "domain": domain,
                        },
                    },
                ],
                details={
                    "account": delegation.account,
                    "delegation_type": delegation.delegation_type,
                    "delegation_to": delegation.delegation_to,
                    "target_host": target_host,
                },
            )


def _run_enum_domain_auth(
    shell: LdapShell,
    domain: str,
    *,
    stop_after_phase: int | None,
) -> None:
    """Shared authenticated domain scan flow with optional early stop."""
    from adscan_internal.rich_output import ScanProgressTracker, mark_sensitive
    from adscan_internal.bloodhound_legacy import get_bloodhound_mode

    username = shell.domains_data.get(domain, {}).get("username", "N/A")
    pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")
    bh_mode = get_bloodhound_mode()
    phase1_complete = bool(shell.domains_data.get(domain, {}).get("phase1_complete"))

    if phase1_complete and stop_after_phase is None:
        try:
            shell.do_sync_clock_with_pdc(domain)  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001
            print_info_debug(f"[DEBUG] Clock sync skipped due to error: {exc}")
        shell.run_enumeration(domain)  # type: ignore[attr-defined]
        return

    # Clock sync must be done against the KDC/realm used for Kerberos authentication.
    # In multi-domain setups, we may be scanning a target domain without having
    # credentials for it, while still using Kerberos tickets from `shell.domain`.
    sync_domain = domain
    try:
        has_target_creds = bool(
            shell.domains_data.get(domain, {}).get("username")
            and shell.domains_data.get(domain, {}).get("username") != "N/A"
        )
    except Exception:
        has_target_creds = False

    if not has_target_creds and getattr(shell, "domain", None):
        sync_domain = shell.domain  # type: ignore[attr-defined]

    if sync_domain != domain:
        print_info_debug(
            "[DEBUG] Authenticated scan clock sync domain mismatch: "
            f"target_domain={mark_sensitive(domain, 'domain')}, "
            f"sync_domain={mark_sensitive(sync_domain, 'domain')}"
        )

    # Initialize progress tracker for authenticated scan.
    tracker = ScanProgressTracker(
        "Authenticated Domain Scan",
        total_steps=2,
    )

    # Start workflow with detailed information
    tracker.start(
        details={
            "Domain": domain,
            "PDC": pdc,
            "Username": username,
            "BloodHound Mode": bh_mode.upper(),
        }
    )

    # Step 1: Clock Synchronization
    sync_details = "Syncing with domain PDC"
    if sync_domain != domain:
        sync_details = (
            f"Syncing with auth-domain PDC ({mark_sensitive(sync_domain, 'domain')})"
        )
    tracker.start_step("Clock Synchronization", details=sync_details)
    try:
        shell.do_sync_clock_with_pdc(sync_domain)  # type: ignore[attr-defined]
        tracker.complete_step(details="Clock synchronized successfully")
    except Exception as exc:  # noqa: BLE001
        tracker.fail_step(details=f"Clock sync error: {str(exc)[:50]}")

    # Step 2: BloodHound Collection
    tracker.start_step(
        "BloodHound Collection",
        details=f"Running BloodHound {bh_mode.upper()} data collector",
    )
    try:
        from adscan_internal.bloodhound_legacy import get_legacy_bloodhound_config_path
        from adscan_internal.cli.post_bloodhound import (
            run_post_bloodhound,
            run_post_bloodhound_ce,
        )

        if get_bloodhound_mode() == "ce":
            shell.ask_for_bloodhound(  # type: ignore[attr-defined]
                domain,
                callback=lambda: run_post_bloodhound_ce(
                    shell,
                    domain,
                    stop_after_phase=stop_after_phase,  # type: ignore[arg-type]
                ),
            )
        else:
            legacy_config_path = get_legacy_bloodhound_config_path()
            shell.ask_for_bloodhound(  # type: ignore[attr-defined]
                domain,
                callback=lambda: run_post_bloodhound(
                    shell,
                    domain,
                    stop_after_phase=stop_after_phase,  # type: ignore[arg-type]
                    legacy_config_path=legacy_config_path,
                ),
            )
        tracker.complete_step(details="BloodHound data collection completed")
    except Exception as exc:  # noqa: BLE001
        tracker.fail_step(details=f"BloodHound error: {str(exc)[:50]}")

    # Print workflow summary
    tracker.print_summary()


def run_enum_domain_auth(shell: LdapShell, domain: str) -> None:
    """Perform an authenticated domain scan orchestrated around BloodHound."""
    _run_enum_domain_auth(shell, domain, stop_after_phase=None)


def run_enum_domain_auth_phase1(shell: LdapShell, domain: str) -> None:
    """Perform an authenticated domain scan through Phase 1 only."""
    _run_enum_domain_auth(shell, domain, stop_after_phase=1)


def run_enum_with_users(shell: LdapShell, domain: str) -> None:
    """Unauthenticated enumeration when only a user list is available.

    This preserves the legacy behaviour of ``do_enum_with_users``: mark the
    domain as ``with_users`` and then offer AS-REP roasting and password
    spraying. If the spraying step compromises the domain, it can update the
    auth state to ``auth``/``pwned`` which is respected by this flow.
    """
    shell.domains_data[domain]["auth"] = "with_users"
    shell.ask_for_asreproast(domain)  # type: ignore[attr-defined]
    if shell.domains_data[domain]["auth"] not in ["auth", "pwned"]:
        shell.ask_for_spraying(domain)  # type: ignore[attr-defined]


def run_ldap_active_users(shell: LdapShell, target_domain: str) -> list[str] | None:
    """Enumerate enabled users via LDAP and persist `enabled_users.txt`."""
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return None

    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return None

    if not shell.domain or shell.domain not in shell.domains_data:
        print_error("No authenticated domain selected. Select a domain first.")
        return None

    username = shell.domains_data[shell.domain].get("username")
    password = shell.domains_data[shell.domain].get("password")
    if not username or not password:
        print_error(
            "Missing credentials (username/password) for LDAP user enumeration."
        )
        return None

    log_file_rel = domain_relpath(
        shell.domains_dir, target_domain, shell.ldap_dir, "enabled_users.log"
    )
    output_rel = domain_relpath(shell.domains_dir, target_domain, "enabled_users.txt")
    print_operation_header(
        "LDAP User Enumeration",
        details={
            "Target Domain": target_domain,
            "Auth Domain": shell.domain,
            "Username": username,
            "LDAP Server": shell.domains_data[target_domain]["pdc"],
            "Mode": "Active users only",
            "Log": log_file_rel,
            "Output": output_rel,
        },
        icon="👤",
    )

    workspace_cwd = shell._get_workspace_cwd()
    log_file_abs = domain_subpath(
        workspace_cwd,
        shell.domains_dir,
        target_domain,
        shell.ldap_dir,
        "enabled_users.log",
    )
    os.makedirs(os.path.dirname(log_file_abs), exist_ok=True)

    enum_service = EnumerationService()
    executor = shell._get_service_executor()
    usernames = enum_service.ldap.enumerate_active_users(
        domain=target_domain,
        pdc=shell.domains_data[target_domain]["pdc"],
        auth_mode=AuthMode.AUTHENTICATED,
        username=username,
        password=password,
        netexec_path=shell.netexec_path,
        log_file=log_file_abs,
        executor=executor,
        scan_id=None,
        timeout=120,
    )

    shell._write_domain_list_file(target_domain, "enabled_users.txt", usernames)
    try:
        shell._postprocess_user_list_file(
            target_domain,
            "enabled_users.txt",
            source="ldap_active_users",
        )
    except Exception as e:  # pragma: no cover
        telemetry.capture_exception(e)
        marked_domain = mark_sensitive(target_domain, "domain")
        print_warning(f"Failed to postprocess enabled users for {marked_domain}: {e}")

    try:
        properties = {
            "count": len(usernames),
            "scan_mode": getattr(shell, "scan_mode", None),
            "auth_type": shell.domains_data[target_domain].get("auth", "unknown"),
        }
        properties.update(build_lab_event_fields(shell=shell, include_slug=True))
        telemetry.capture("ldap_users_enumerated", properties)
    except Exception as e:  # pragma: no cover
        telemetry.capture_exception(e)

    return usernames


def run_ldap_admincount_and_signing(
    shell: LdapShell,
    *,
    domain: str,
    username: str,
    password: str,
    logging: bool = True,
) -> bool | None:
    """Check `adminCount` for a user via NetExec LDAP, handling LDAP Signing.

    This helper encapsula la lógica legacy de:
    - Construir el comando ``netexec ldap ... --query '(sAMAccountName=...)' adminCount``
    - Detectar el mensaje ``LDAP Signing IS Enforced`` y reintentar con Kerberos (-k)
    - Interpretar el resultado:
      - ``True``  → adminCount == 1
      - ``False`` → adminCount != 1 (sin error)
      - ``None``  → credenciales inválidas / error de ejecución
    """
    from adscan_internal import (
        print_info,
        print_success,
    )  # import local para evitar ciclos

    if domain not in shell.domains_data:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"Domain {marked_domain} is not configured.")
        return None

    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return None

    # Build authentication string (password mode primero, Kerberos en fallback)
    auth_str = shell.build_auth_nxc(
        shell.domains_data[domain]["username"],
        shell.domains_data[domain]["password"],
        domain,
        kerberos=False,
    )
    workspace_cwd = shell.current_workspace_dir or shell._get_workspace_cwd()
    ldap_dir_abs = domain_subpath(
        workspace_cwd,
        shell.domains_dir,
        domain,
        shell.ldap_dir,
    )
    os.makedirs(ldap_dir_abs, exist_ok=True)
    marked_domain = mark_sensitive(domain, "domain")
    marked_username = mark_sensitive(username, "user")
    base_log = domain_relpath(
        shell.domains_dir,
        domain,
        shell.ldap_dir,
        f"admincount_{username}.log",
    )

    def _build_command(current_auth: str) -> str:
        return (
            f"{shell.netexec_path} ldap {shell.domains_data[domain]['pdc']} "
            f"{current_auth} --log {base_log} "
            f"--query '(sAMAccountName={username})' adminCount"
        )

    command = _build_command(auth_str)
    if logging:
        print_info(f"Enumerating adminCount for {marked_username}.")
    print_info_debug(f"[ldap-admincount] Command: {command}")

    completed_process = shell.run_command(command, timeout=300)
    if not completed_process:
        return None

    if _is_exact_ldap_connection_timeout_result(completed_process):
        mark_exact_ldap_connection_timeout_state(shell)
        print_info_debug(
            "[ldap-admincount] Exact LDAP connection timeout detected; "
            "skipping Kerberos/signing fallback for adminCount."
        )
        return None

    output_str = completed_process.stdout or ""
    errors_str = completed_process.stderr or ""

    # Handle LDAP Signing enforced: retry with Kerberos (-k)
    if "LDAP Signing IS Enforced" in (
        output_str or ""
    ) or "LDAP Signing IS Enforced" in (errors_str or ""):
        print_error("LDAP Signing is enforced, retrying with Kerberos (-k)...")
        auth_str = shell.build_auth_nxc(
            shell.domains_data[domain]["username"],
            shell.domains_data[domain]["password"],
            domain,
            kerberos=True,
        )
        command = _build_command(auth_str)
        print_info_debug(f"[ldap-admincount] Command (Kerberos): {command}")
        completed_process = shell.run_command(command, timeout=300)
        if _is_exact_ldap_connection_timeout_result(completed_process):
            mark_exact_ldap_connection_timeout_state(shell)
            print_info_debug(
                "[ldap-admincount] Exact LDAP connection timeout detected after "
                "Kerberos retry; stopping adminCount checks."
            )
            return None
        output_str = completed_process.stdout or ""
        errors_str = completed_process.stderr or ""

    if completed_process.returncode != 0:
        error_detail = (errors_str or output_str or "").strip()
        print_error(
            f"Error executing NetExec for adminCount check on {marked_username}. "
            f"Return code: {completed_process.returncode}"
        )
        if error_detail:
            print_error(f"Details: {error_detail}")
        return None

    # Credenciales inválidas
    if "[-]" in (output_str or "") and "Response for object:" not in (output_str or ""):
        if logging:
            print_error(f"Invalid credential for user {marked_username}")
        return None

    # Buscar adminCount==1
    if "adminCount" in (output_str or ""):
        import re

        admin_count_match = re.search(r"adminCount\s+(\d+)", output_str)
        if admin_count_match and int(admin_count_match.group(1)) == 1:
            if logging:
                print_success(
                    f"User {marked_username} has adminCount=1 (likely privileged account)."
                )
            return True

    if logging:
        print_error(
            f"The user {marked_username} does not have elevated privileges according to adminCount in domain {marked_domain}"
        )
    return False


def run_ldap_groupmembership_privileged(
    shell: LdapShell,
    *,
    domain: str,
    username: str,
    password: str,
) -> dict | None:
    """Fallback privilege check using NetExec LDAP `groupmembership` module."""
    if domain not in shell.domains_data:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"Domain {marked_domain} is not configured.")
        return None

    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return None

    if shell.do_sync_clock_with_pdc(domain):
        auth_str = shell.build_auth_nxc(username, password, domain, kerberos=True)
    else:
        auth_str = shell.build_auth_nxc(username, password, domain)

    pdc_hostname = shell.domains_data[domain]["pdc_hostname"]
    pdc_fqdn = f"{pdc_hostname}.{domain}"
    log_path = domain_relpath(
        shell.domains_dir, domain, shell.ldap_dir, f"groupmembership_{username}.txt"
    )
    command = (
        f"{shell.netexec_path} ldap {pdc_fqdn} {auth_str} "
        f"--log {log_path} -M groupmembership -o USER={username}"
    )

    print_info_debug(f"[ldap-groupmembership] Command: {command}")
    completed_process = shell.run_command(command, timeout=300)
    if not completed_process:
        marked_username = mark_sensitive(username, "user")
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"Failed to execute LDAP group membership command for {marked_username}@{marked_domain}."
        )
        return None

    if _is_exact_ldap_connection_timeout_result(completed_process):
        mark_exact_ldap_connection_timeout_state(shell)
        print_info_debug(
            "[ldap-groupmembership] Exact LDAP connection timeout detected; "
            "skipping further LDAP groupmembership handling."
        )
        return None

    if completed_process.returncode != 0:
        output_str = completed_process.stdout or ""
        errors_str = completed_process.stderr or ""
        error_detail = errors_str.strip() if errors_str else output_str.strip()
        marked_username = mark_sensitive(username, "user")
        print_error(
            f"Error executing NetExec for group membership check on {marked_username}. "
            f"Return code: {completed_process.returncode}"
        )
        if error_detail:
            print_error(f"Details: {error_detail}")
        return None

    output_str = completed_process.stdout or ""
    # Reutilizar el parser existente en el shell, si está disponible
    parser = getattr(shell, "_parse_privileged_group_output", None)
    if callable(parser):
        return parser(output_str)

    return None


def _combined_completed_process_output(
    completed_process: subprocess.CompletedProcess[str] | None,
) -> str:
    """Return combined stdout/stderr text for a completed process."""
    if not isinstance(completed_process, subprocess.CompletedProcess):
        return ""
    return f"{completed_process.stdout or ''}\n{completed_process.stderr or ''}"


_EXACT_LDAP_TIMEOUT_STATE_ATTR = "_adscan_exact_ldap_timeout_state"


def clear_exact_ldap_connection_timeout_state(shell: object) -> None:
    """Clear the per-shell exact LDAP timeout state used by higher-level flows."""
    try:
        setattr(shell, _EXACT_LDAP_TIMEOUT_STATE_ATTR, False)
    except Exception:
        pass


def mark_exact_ldap_connection_timeout_state(shell: object) -> None:
    """Record that the current LDAP flow hit the exact NetExec timeout signature."""
    try:
        setattr(shell, _EXACT_LDAP_TIMEOUT_STATE_ATTR, True)
    except Exception:
        pass


def consume_exact_ldap_connection_timeout_state(shell: object) -> bool:
    """Return and clear the exact LDAP timeout state for the current shell."""
    try:
        value = bool(getattr(shell, _EXACT_LDAP_TIMEOUT_STATE_ATTR, False))
        setattr(shell, _EXACT_LDAP_TIMEOUT_STATE_ATTR, False)
        return value
    except Exception:
        return False


def _is_exact_ldap_connection_timeout_result(
    completed_process: subprocess.CompletedProcess[str] | None,
) -> bool:
    """Return True when a NetExec LDAP result matches the exact timeout signature."""
    return output_has_exact_ldap_connection_timeout(
        _combined_completed_process_output(completed_process)
    )


def _run_netexec_ldap_query_attribute_values(
    shell: LdapShell,
    *,
    domain: str,
    ldap_query: str,
    attribute: str,
    auth_username: str,
    auth_password: str,
    pdc: str,
    timeout: int = 300,
    retries: int = 1,
    retry_delay_seconds: float = 1.0,
    retry_backoff: float = 1.5,
    require_non_empty: bool = False,
    prefer_kerberos: bool = True,
    allow_ntlm_fallback: bool = True,
    debug_label: str = "ldap-query",
) -> list[str] | None:
    """Run a NetExec LDAP query and parse attribute values with retries.

    This helper centralizes a robust execution policy used by runtime privilege
    verification flows:
    - Prefer Kerberos authentication for LDAP queries.
    - Optionally fallback to NTLM if Kerberos does not return usable data.
    - Retry transient failures and optional empty result-sets with backoff.
    """
    from adscan_internal.integrations.netexec.parsers import (
        parse_netexec_ldap_query_attribute_values,
    )

    if domain not in shell.domains_data:
        return None
    if not getattr(shell, "netexec_path", None):
        return None

    netexec_runner = getattr(shell, "_run_netexec", None)
    use_netexec_runner = callable(netexec_runner)

    def _run(command: str) -> subprocess.CompletedProcess[str] | None:
        if use_netexec_runner:
            return netexec_runner(command, domain=domain, timeout=timeout)  # type: ignore[misc]
        return shell.run_command(command, timeout=timeout)

    attempts = max(1, int(retries))
    delay = max(0.0, float(retry_delay_seconds))
    backoff = max(1.0, float(retry_backoff))

    marked_auth_user = mark_sensitive(str(auth_username), "user")
    marked_auth_pass = mark_sensitive(str(auth_password), "password")
    marked_domain = mark_sensitive(str(domain), "domain")
    marked_pdc = mark_sensitive(
        str(pdc), "ip" if str(pdc).replace(".", "").isdigit() else "hostname"
    )

    auth_modes: list[bool] = [bool(prefer_kerberos)]
    if prefer_kerberos and allow_ntlm_fallback:
        auth_modes.append(False)

    saw_successful_query = False

    for auth_mode in auth_modes:
        successful_empty_result = False
        auth_str = shell.build_auth_nxc(
            str(auth_username),
            str(auth_password),
            domain,
            kerberos=auth_mode,
        )
        auth_str = auth_str.replace(str(auth_username), str(marked_auth_user)).replace(
            str(auth_password), str(marked_auth_pass)
        )
        auth_str = auth_str.replace(str(domain), str(marked_domain))

        auth_label = "kerberos" if auth_mode else "ntlm"
        for attempt in range(1, attempts + 1):
            command = (
                f"{shell.netexec_path} ldap {marked_pdc} {auth_str} "
                f'--query "{ldap_query}" {attribute}'
            )
            print_info_debug(
                f"[ldap-in-chain] {debug_label} command "
                f"({auth_label}, attempt {attempt}/{attempts}): {command}"
            )

            completed_process = _run(command)
            if not completed_process:
                if attempt < attempts:
                    time.sleep(delay * (backoff ** (attempt - 1)))
                continue
            if completed_process.returncode != 0:
                if _is_exact_ldap_connection_timeout_result(completed_process):
                    mark_exact_ldap_connection_timeout_state(shell)
                    print_info_debug(
                        "[ldap-in-chain] "
                        f"{debug_label} hit the exact LDAP connection-timeout signature "
                        f"({auth_label}, attempt {attempt}/{attempts}) via error result; "
                        "stopping retries and skipping auth fallback."
                    )
                    return None
                output = str(completed_process.stderr or "").strip() or str(
                    completed_process.stdout or ""
                ).strip()
                if output:
                    print_info_debug(
                        "[ldap-in-chain] "
                        f"{debug_label} failed ({auth_label}, attempt {attempt}/{attempts}): "
                        f"{mark_sensitive(output[:400], 'detail')}"
                    )
                if attempt < attempts:
                    time.sleep(delay * (backoff ** (attempt - 1)))
                continue

            saw_successful_query = True
            values = parse_netexec_ldap_query_attribute_values(
                completed_process.stdout or "", attribute
            )
            values = [str(value).strip() for value in values if str(value).strip()]
            if values:
                return values

            if not require_non_empty:
                return []

            successful_empty_result = True
            if _is_exact_ldap_connection_timeout_result(completed_process):
                mark_exact_ldap_connection_timeout_state(shell)
                print_info_debug(
                    "[ldap-in-chain] "
                    f"{debug_label} hit the exact LDAP connection-timeout signature "
                    f"({auth_label}, attempt {attempt}/{attempts}); stopping retries "
                    "and skipping auth fallback."
                )
                return None

            if attempt < attempts:
                print_info_debug(
                    "[ldap-in-chain] "
                    f"{debug_label} returned 0 {attribute} values "
                    f"({auth_label}, attempt {attempt}/{attempts}); retrying."
                )
                time.sleep(delay * (backoff ** (attempt - 1)))

        if auth_mode and successful_empty_result:
            print_info_debug(
                "[ldap-in-chain] "
                f"{debug_label} exhausted Kerberos retries with 0 {attribute} values; "
                "skipping NTLM fallback."
            )
            return []

    if saw_successful_query:
        return []
    return None


def get_recursive_user_groups_in_chain(
    shell: LdapShell,
    *,
    domain: str,
    target_username: str,
    auth_username: str | None = None,
    auth_password: str | None = None,
    pdc: str | None = None,
    timeout: int = 300,
    retries: int = 3,
    retry_delay_seconds: float = 1.0,
    retry_backoff: float = 1.5,
    retry_on_empty: bool = True,
    prefer_kerberos: bool = True,
    allow_ntlm_fallback: bool = True,
) -> list[str] | None:
    """Return recursive group memberships for a principal via LDAP_MATCHING_RULE_IN_CHAIN.

    This is a runtime helper used when we need accurate group memberships even
    after in-engagement changes (e.g., adding the operator to a group).

    It performs 2 LDAP queries via NetExec:
      1) Resolve the principal's distinguishedName (DN) using sAMAccountName.
      2) Query groups whose ``member`` chain contains that DN using:
            member:1.2.840.113556.1.4.1941:=<USER_DN>

    Args:
        shell: Shell instance providing NetExec execution.
        domain: Target AD domain.
        target_username: Principal sAMAccountName whose groups we want. This
            works for both Users and Computers (including trailing ``$``).
        auth_username: Auth principal used to query LDAP. Defaults to the
            active domain credential in ``shell.domains_data[domain]``.
        auth_password: Auth secret used to query LDAP. Defaults to the active
            domain credential in ``shell.domains_data[domain]``.
        pdc: DC target for the query. Defaults to ``shell.domains_data[domain]["pdc"]``.
        timeout: Command timeout in seconds.

    Returns:
        List of group sAMAccountName values (may include spaces) on success,
        otherwise None when prerequisites are missing or lookup failed.
    """
    if domain not in shell.domains_data:
        return None
    if not getattr(shell, "netexec_path", None):
        return None

    auth_username = auth_username or shell.domains_data[domain].get("username")
    auth_password = auth_password or shell.domains_data[domain].get("password")
    pdc = pdc or shell.domains_data[domain].get("pdc")
    if not auth_username or not auth_password or not pdc:
        return None

    # Fast path: resolve the principal DN from BloodHound when available.
    # This avoids an extra LDAP query and stays aligned with the "prefer BH,
    # fallback to NetExec" approach used elsewhere for node enrichment.
    user_dn = ""
    try:
        if hasattr(shell, "_get_bloodhound_service"):
            service = shell._get_bloodhound_service()  # type: ignore[attr-defined]
            resolver = getattr(service, "get_user_node_by_samaccountname", None)
            if callable(resolver):
                node_props = resolver(domain, str(target_username or "").strip())
                if isinstance(node_props, dict):
                    user_dn = str(
                        node_props.get("distinguishedname")
                        or node_props.get("distinguishedName")
                        or ""
                    ).strip()
                    if user_dn:
                        marked_user = mark_sensitive(str(target_username), "user")
                        marked_domain = mark_sensitive(str(domain), "domain")
                        print_info_debug(
                            "[ldap-in-chain] Resolved distinguishedName from BloodHound for "
                            f"{marked_user}@{marked_domain}"
                        )
    except Exception:
        user_dn = ""

    # 1) Resolve DN for the principal (fallback to NetExec query when BH is unavailable).
    if not user_dn:
        sanitized_target = str(target_username).replace("'", "\\'")
        dn_query = f"(&(|(objectClass=user)(objectClass=computer))(sAMAccountName={sanitized_target}))"
        dn_values = _run_netexec_ldap_query_attribute_values(
            shell,
            domain=domain,
            ldap_query=dn_query,
            attribute="distinguishedName",
            auth_username=str(auth_username),
            auth_password=str(auth_password),
            pdc=str(pdc),
            timeout=timeout,
            retries=max(1, retries),
            retry_delay_seconds=retry_delay_seconds,
            retry_backoff=retry_backoff,
            require_non_empty=True,
            prefer_kerberos=prefer_kerberos,
            allow_ntlm_fallback=allow_ntlm_fallback,
            debug_label="Resolve DN",
        )
        if dn_values is None:
            return None
        user_dn = dn_values[0] if dn_values else ""
        if not user_dn:
            return None

    # 2) Resolve recursive group memberships using in-chain on `member`.
    group_query = (
        f"(&(objectCategory=group)(member:1.2.840.113556.1.4.1941:={user_dn}))"
    )
    groups = _run_netexec_ldap_query_attribute_values(
        shell,
        domain=domain,
        ldap_query=group_query,
        attribute="sAMAccountName",
        auth_username=str(auth_username),
        auth_password=str(auth_password),
        pdc=str(pdc),
        timeout=timeout,
        retries=max(1, retries),
        retry_delay_seconds=retry_delay_seconds,
        retry_backoff=retry_backoff,
        require_non_empty=retry_on_empty,
        prefer_kerberos=prefer_kerberos,
        allow_ntlm_fallback=allow_ntlm_fallback,
        debug_label="Recursive groups",
    )
    if groups is None:
        return None

    # Normalise: keep stable display while avoiding duplicates.
    groups = [g.strip() for g in groups if str(g).strip()]
    if not groups:
        return []
    return sorted(set(groups), key=str.lower)


def get_recursive_principal_group_sids_in_chain(
    shell: LdapShell,
    *,
    domain: str,
    target_samaccountname: str,
    auth_username: str | None = None,
    auth_password: str | None = None,
    pdc: str | None = None,
    timeout: int = 300,
    retries: int = 3,
    retry_delay_seconds: float = 1.0,
    retry_backoff: float = 1.5,
    retry_on_empty: bool = True,
    prefer_kerberos: bool = True,
    allow_ntlm_fallback: bool = True,
) -> list[str] | None:
    """Return recursive group SIDs for a principal via LDAP_MATCHING_RULE_IN_CHAIN.

    This is similar to `get_recursive_user_groups_in_chain`, but returns
    `objectSid` values for each group. This is useful for robust privileged
    group checks because group names can be localized.

    Args:
        shell: Shell instance providing NetExec execution.
        domain: Target AD domain.
        target_samaccountname: Principal sAMAccountName (user or computer).
        auth_username/auth_password/pdc/timeout: Same meaning as in
            `get_recursive_user_groups_in_chain`.

    Returns:
        List of group objectSid strings on success, otherwise None.
    """
    if domain not in shell.domains_data:
        return None
    if not getattr(shell, "netexec_path", None):
        return None

    auth_username = auth_username or shell.domains_data[domain].get("username")
    auth_password = auth_password or shell.domains_data[domain].get("password")
    pdc = pdc or shell.domains_data[domain].get("pdc")
    if not auth_username or not auth_password or not pdc:
        return None

    # Resolve principal DN (BH first, fallback NetExec query).
    user_dn = ""
    try:
        if hasattr(shell, "_get_bloodhound_service"):
            service = shell._get_bloodhound_service()  # type: ignore[attr-defined]
            resolver = getattr(service, "get_user_node_by_samaccountname", None)
            if callable(resolver):
                node_props = resolver(domain, str(target_samaccountname or "").strip())
                if isinstance(node_props, dict):
                    user_dn = str(
                        node_props.get("distinguishedname")
                        or node_props.get("distinguishedName")
                        or ""
                    ).strip()
                    if user_dn:
                        marked_user = mark_sensitive(str(target_samaccountname), "user")
                        marked_domain = mark_sensitive(str(domain), "domain")
                        print_info_debug(
                            "[ldap-in-chain] Resolved distinguishedName from BloodHound for "
                            f"{marked_user}@{marked_domain}"
                        )
    except Exception:
        user_dn = ""

    if not user_dn:
        sanitized_target = str(target_samaccountname).replace("'", "\\'")
        dn_query = f"(&(|(objectClass=user)(objectClass=computer))(sAMAccountName={sanitized_target}))"
        dn_values = _run_netexec_ldap_query_attribute_values(
            shell,
            domain=domain,
            ldap_query=dn_query,
            attribute="distinguishedName",
            auth_username=str(auth_username),
            auth_password=str(auth_password),
            pdc=str(pdc),
            timeout=timeout,
            retries=max(1, retries),
            retry_delay_seconds=retry_delay_seconds,
            retry_backoff=retry_backoff,
            require_non_empty=True,
            prefer_kerberos=prefer_kerberos,
            allow_ntlm_fallback=allow_ntlm_fallback,
            debug_label="Resolve DN",
        )
        if dn_values is None:
            return None
        user_dn = dn_values[0] if dn_values else ""
        if not user_dn:
            return None

    # Resolve recursive group memberships using in-chain on `member`, returning objectSid.
    group_query = (
        f"(&(objectCategory=group)(member:1.2.840.113556.1.4.1941:={user_dn}))"
    )
    sids = _run_netexec_ldap_query_attribute_values(
        shell,
        domain=domain,
        ldap_query=group_query,
        attribute="objectSid",
        auth_username=str(auth_username),
        auth_password=str(auth_password),
        pdc=str(pdc),
        timeout=timeout,
        retries=max(1, retries),
        retry_delay_seconds=retry_delay_seconds,
        retry_backoff=retry_backoff,
        require_non_empty=retry_on_empty,
        prefer_kerberos=prefer_kerberos,
        allow_ntlm_fallback=allow_ntlm_fallback,
        debug_label="Recursive group SIDs",
    )
    if sids is None:
        return None

    sids = [sid.strip() for sid in sids if str(sid).strip()]
    if not sids:
        return []
    return sorted(set(sids), key=str.upper)


def get_recursive_principal_groups_in_chain(
    shell: LdapShell,
    *,
    domain: str,
    target_samaccountname: str,
    auth_username: str | None = None,
    auth_password: str | None = None,
    pdc: str | None = None,
    timeout: int = 300,
) -> list[str] | None:
    """Alias for ``get_recursive_user_groups_in_chain`` (kept for clarity)."""
    return get_recursive_user_groups_in_chain(
        shell,
        domain=domain,
        target_username=target_samaccountname,
        auth_username=auth_username,
        auth_password=auth_password,
        pdc=pdc,
        timeout=timeout,
    )


def get_domain_admins(shell: LdapShell, domain: str) -> list[str]:
    """Return members of the Domain Admins group via NetExec LDAP."""
    try:
        marked_domain = mark_sensitive(domain, "domain")
        snapshot_admins = resolve_group_members_by_rid(
            shell, domain, 512, enabled_only=True
        )
        if snapshot_admins is not None:
            if snapshot_admins:
                return snapshot_admins
            print_info_debug(
                f"[ldap] RID 512 resolved 0 Domain Admins for {marked_domain}; "
                "falling back to LDAP."
            )
        else:
            print_info_debug(
                f"[ldap] RID 512 resolution unavailable for {marked_domain}; "
                "falling back to LDAP."
            )

        auth = shell.build_auth_nxc(
            shell.domains_data[domain]["username"],
            shell.domains_data[domain]["password"],
            domain,
            kerberos=False,
        )
        log_path = domain_relpath(
            shell.domains_dir, domain, shell.ldap_dir, "domain_admins.log"
        )
        command = (
            f"{shell.netexec_path} ldap {shell.domains_data[domain]['pdc']} {auth} "
            f"--log {log_path} --groups 'Domain Admins'"
        )
        print_info_verbose("Retrieving Domain Admins")
        print_info_debug(f"Command: {command}")
        completed_process = shell.run_command(command, timeout=300)
        output = completed_process.stdout or ""
        errors = completed_process.stderr or ""

        if completed_process.returncode != 0:
            print_error(f"Error retrieving Domain Admins: {errors}")
            return []

        admins: list[str] = []
        filtered_lines = [line for line in output.splitlines() if "[" not in line]
        if not filtered_lines:
            admins = []
        else:
            for line in filtered_lines:
                columns = line.split()
                if len(columns) >= 5:
                    admins.append(columns[4])

        if admins:
            return admins

        print_warning(
            f"No Domain Admins resolved via LDAP for {marked_domain}. "
            "Manual selection may be required."
        )
        creds = shell.domains_data.get(domain, {}).get("credentials", {})
        candidate_users = [
            str(user).strip()
            for user in creds.keys()
            if isinstance(user, str) and str(user).strip()
        ]
        candidate_users = sorted(set(candidate_users), key=str.lower)
        if not candidate_users:
            manual = Prompt.ask(
                f"Specify a Domain Admin username for {marked_domain} (leave blank to skip)",
                default="",
            ).strip()
            manual = manual.lower()
            if manual:
                marked_user = mark_sensitive(manual, "user")
                print_info_debug(
                    f"[ldap] Domain Admin selected manually for {marked_domain}: {marked_user}"
                )
                return [manual]
            return []

        if hasattr(shell, "_questionary_select"):
            options = [*candidate_users, "Enter manually", "Skip"]
            selected_idx = shell._questionary_select(
                f"Select a Domain Admin account for {marked_domain}:", options
            )
            if selected_idx is None:
                return []
            choice = options[selected_idx]
            if choice == "Enter manually":
                manual = Prompt.ask(
                    f"Specify a Domain Admin username for {marked_domain} (leave blank to skip)",
                    default="",
                ).strip()
                manual = manual.lower()
                if manual:
                    marked_user = mark_sensitive(manual, "user")
                    print_info_debug(
                        f"[ldap] Domain Admin selected manually for {marked_domain}: {marked_user}"
                    )
                    return [manual]
                return []
            if choice == "Skip":
                return []
            selected = choice.lower()
            marked_user = mark_sensitive(selected, "user")
            print_info_debug(
                f"[ldap] Domain Admin selected from credentials for {marked_domain}: {marked_user}"
            )
            return [selected]

        manual = Prompt.ask(
            f"Specify a Domain Admin username for {marked_domain} (leave blank to skip)",
            default="",
        ).strip()
        manual = manual.lower()
        if manual:
            marked_user = mark_sensitive(manual, "user")
            print_info_debug(
                f"[ldap] Domain Admin selected manually for {marked_domain}: {marked_user}"
            )
            return [manual]
        return []
    except Exception as exc:
        telemetry.capture_exception(exc)


def run_kerberos_enum_users(shell: LdapShell, domain: str) -> None:
    """Enumerate users of the specified domain using Kerberos.

    This is a CLI wrapper around the Kerberos enumeration service that
    preserves the existing UX: wordlist selection, operation header and
    persistence of the aggregated user list under ``domains/<domain>/users.txt``.
    """

    from adscan_internal import print_operation_header

    if domain not in shell.domains_data:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"Unknown domain: {marked_domain}")
        return

    shell.domains_data[domain]["auth"] = "user_enum"

    # Wordlist selection via interactive menu
    options = [
        "Build a custom wordlist based on some known name and surnames",
        "Use a general common username wordlist",
    ]
    choice_idx = shell._questionary_select(
        "Select an option for Kerberos enumeration", options
    )
    if choice_idx is None:
        print_error("Selection cancelled.")
        return

    if choice_idx == 0:
        wordlist = shell._generate_user_permutations_interactive(domain)
        if not wordlist:
            return
    else:
        in_container_runtime = is_full_container_runtime(shell)
        marked_domain = mark_sensitive(domain, "domain")
        wordlist = ""
        if in_container_runtime:
            wordlist = (
                select_host_file_via_gui(
                    shell,
                    title=f"Select the Kerberos username wordlist for domain {domain}",
                    initial_dir=str(get_effective_user_home()),
                    log_prefix="ldap",
                )
                or ""
            ).strip()
            if not wordlist:
                print_info_debug(
                    "[ldap] Host GUI picker not used/failed; falling back to manual path prompt"
                )
        if not wordlist:
            wordlist = (
                Prompt.ask(
                    f"Specify the path of the username wordlist for domain {marked_domain}:"
                )
                or ""
            ).strip()
        if not wordlist:
            print_error("Please provide the path to the wordlist file.")
            return

        wordlist = maybe_import_host_file_to_workspace(
            shell,
            domain=domain,
            source_path=wordlist,
            dest_dir="wordlists_custom",
            log_prefix="ldap",
        )
        if not os.path.exists(wordlist):
            marked_wordlist = mark_sensitive(wordlist, "path")
            print_error(f"The wordlist file {marked_wordlist} does not exist.")
            return

    workspace_cwd = shell._get_workspace_cwd()
    kerberos_dir = domain_subpath(
        workspace_cwd, shell.domains_dir, domain, shell.kerberos_dir
    )
    os.makedirs(kerberos_dir, exist_ok=True)
    output_file = Path(os.path.join(kerberos_dir, "enum_users.log"))

    wordlist_name = os.path.basename(wordlist) if os.path.exists(wordlist) else wordlist
    print_operation_header(
        "Kerberos User Enumeration",
        details={
            "Domain": domain,
            "PDC": shell.domains_data[domain]["pdc"],
            "Wordlist": wordlist_name,
            "Protocol": "Kerberos Pre-Authentication",
        },
        icon="🔑",
    )

    kerbrute_path = os.path.join(TOOLS_INSTALL_DIR, "kerbrute", "kerbrute")
    if not os.path.isfile(kerbrute_path) or not os.access(kerbrute_path, os.X_OK):
        print_error(
            f"kerbrute binary not found or not executable at {kerbrute_path}. "
            "Please ensure tools are installed via 'adscan install'."
        )
        return

    enum_service = EnumerationService()
    executor = shell._get_service_executor()
    users = enum_service.kerberos.enumerate_users_kerberos(
        domain=domain,
        pdc=shell.domains_data[domain]["pdc"],
        wordlist=wordlist,
        kerbrute_path=kerbrute_path,
        output_file=output_file,
        executor=executor,
        scan_id=None,
        timeout=300,
    )

    if not users:
        print_warning("No Kerberos users were discovered.")
        return

    unique_users = sorted(set(users))
    shell._write_user_list_file(domain, "users.txt", unique_users)
    shell._postprocess_user_list_file(
        domain,
        "users.txt",
        trigger_followups=False,
        source="kerberos_user_enum",
    )

    shell.ask_for_kerberos_user_enum(domain, relaunch=True)
    run_post_user_discovery_followups(
        shell,
        domain,
        source="kerberos_user_enum",
    )


def get_domain_controllers(shell: LdapShell, domain: str) -> list[str]:
    """Return members of the Domain Controllers group via NetExec LDAP."""
    try:
        auth = shell.build_auth_nxc(
            shell.domains_data[domain]["username"],
            shell.domains_data[domain]["password"],
            domain,
            kerberos=False,
        )
        log_path = domain_relpath(
            shell.domains_dir, domain, shell.ldap_dir, "domain_controllers.log"
        )
        auth_domain = shell.domain or domain
        command = (
            f"{shell.netexec_path} ldap {shell.domains_data[domain]['pdc']} {auth} "
            f"-d {auth_domain} --log {log_path} --groups 'Domain Controllers'"
        )
        print_info_debug(f"Command: {command}")
        completed_process = shell.run_command(command, timeout=300)
        output = completed_process.stdout or ""
        errors = completed_process.stderr or ""

        if completed_process.returncode != 0:
            print_error(f"Error retrieving Domain Controllers: {errors}")
            return []

        return parse_netexec_group_members(output)
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Error in get_domain_controllers.")
        print_exception(show_locals=False, exception=exc)
        return []


def get_not_delegated_users(shell: LdapShell, domain: str) -> list[str]:
    """Return users with the NOT_DELEGATED UAC flag via NetExec LDAP query."""
    try:
        auth = shell.build_auth_nxc(
            shell.domains_data[domain]["username"],
            shell.domains_data[domain]["password"],
            domain,
            kerberos=False,
        )
        log_path = domain_relpath(
            shell.domains_dir, domain, shell.ldap_dir, "not_delegated_users.log"
        )
        auth_domain = shell.domain or domain
        command = (
            f"{shell.netexec_path} ldap {shell.domains_data[domain]['pdc']} {auth} "
            f"-d {auth_domain} --log {log_path} "
            "--query '(&(objectCategory=person)(objectClass=user)"
            "(userAccountControl:1.2.840.113556.1.4.803:=1048576))' samAccountName"
        )
        print_info_debug(f"Command: {command}")
        completed_process = shell.run_command(command, timeout=300)
        output = completed_process.stdout or ""
        errors = completed_process.stderr or ""

        if completed_process.returncode != 0:
            print_error(f"Error retrieving NOT_DELEGATED users: {errors}")
            return []

        return parse_netexec_samaccountnames(output)
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Error in get_not_delegated_users.")
        print_exception(show_locals=False, exception=exc)
        return []


def check_maq(shell: LdapShell, domain: str, username: str, password: str) -> int:
    """Check MachineAccountQuota using NetExec LDAP module."""
    try:
        auth = shell.build_auth_nxc(username, password, domain, kerberos=False)
        log_path = domain_relpath(shell.domains_dir, domain, shell.ldap_dir, "maq.log")
        command = (
            f"{shell.netexec_path} ldap {shell.domains_data[domain]['pdc']} {auth} "
            f"--log {log_path} -M maq"
        )
        print_success("Checking MachineAccountQuota")
        print_info_debug(f"Command: {command}")
        proc = shell.run_command(command, timeout=300)

        output = (proc.stdout or "") + (proc.stderr or "")
        value = parse_machine_account_quota(output)
        if value is None:
            print_error("Could not retrieve the MachineAccountQuota")
            return 0
        print_success(f"MachineAccountQuota found: {value}")
        return value
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Error checking MAQ.")
        print_exception(show_locals=False, exception=exc)
        return 0


def run_ldap_descriptions(
    shell: LdapShell, target_domain: str, *, anonymous: bool = False
) -> None:
    """Enumerate user descriptions and analyze them for leaked credentials.

    Primary flow: execute NetExec LDAP description-focused modules and parse the
    generated ``UserDesc-*.log`` output artifact.
    """
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return

    username = ""
    password = ""
    pdc_hostname = str(shell.domains_data[target_domain].get("pdc_hostname") or "").strip()
    pdc_target = shell.domains_data[target_domain]["pdc"]
    use_kerberos = False

    if anonymous:
        auth_label = "Anonymous"
    else:
        username = shell.domains_data[shell.domain]["username"]
        password = shell.domains_data[shell.domain]["password"]
        if pdc_hostname:
            pdc_target = f"{pdc_hostname}.{target_domain}"
        use_kerberos = bool(shell.do_sync_clock_with_pdc(target_domain))
        auth_label = "Kerberos" if use_kerberos else "Password"

    print_operation_header(
        "LDAP User Descriptions Enumeration",
        details={
            "Domain": target_domain,
            "PDC": pdc_target,
            "Authentication": auth_label,
            "Modules": "user-desc, get-desc-users, get-unixUserPassword, get-userPassword, get-info-users",
            "Username": username if username else "Anonymous",
        },
        icon="📝",
    )

    # Run the description-focused NetExec modules directly (no --users pre-pass).
    if anonymous:
        auth = '-u "" -p ""'
    else:
        auth = shell.build_auth_nxc(
            username,
            password,
            shell.domain,
            kerberos=use_kerberos,
        )
    marked_pdc_target = mark_sensitive(str(pdc_target), "hostname")
    command = (
        f"{shell.netexec_path} ldap {marked_pdc_target} {auth} "
        "-M user-desc -M get-desc-users -M get-unixUserPassword -M get-userPassword -M get-info-users"
    )
    print_info_debug(f"Command: {command}")
    execute_netexec_ldap_descriptions(
        shell,
        command=command,
        domain=target_domain,
        anonymous=anonymous,
    )


def run_enumerate_user_aces(shell: LdapShell, args: str) -> None:
    """Parse arguments and initiate user ACE enumeration.

    This function parses the command-line arguments (domain, username, password)
    and delegates to the shell's `ask_for_enumerate_user_aces` method.

    Args:
        shell: Shell instance with `ask_for_enumerate_user_aces` method.
        args: Space-separated string containing domain, username, and password.

    Usage:
        run_enumerate_user_aces(shell, "example.local alice Passw0rd!")
    """
    parts = args.split()
    if len(parts) != 3:
        print_error(
            "Usage: enumerate_user_aces <domain> <user> <password>\n"
            "Example: enumerate_user_aces example.local username password"
        )
        return

    domain, username, password = parts
    shell.ask_for_enumerate_user_aces(domain, username, password)


# Helper functions for NetExec LDAP descriptions processing


def _get_nxc_base_dir() -> str:
    """Return the NetExec (nxc) state directory (~/.nxc) for the effective user."""
    return os.path.join(str(get_effective_user_home()), ".nxc")


def _get_credsweeper_rules_paths() -> Tuple[Optional[str], Optional[str]]:
    """Return both primary and custom CredSweeper rules file paths.

    Returns:
        Tuple[Optional[str], Optional[str]]: (primary_rules_path, custom_rules_path)
    """
    import sys

    # Get ADscan base directory
    adscan_home = get_adscan_home()
    adscan_base_dir = str(adscan_home.parent)

    # Primary rules: config.yaml
    primary_rules = None
    # 1) User override in ADscan base directory
    override_path = os.path.join(adscan_base_dir, "credsweeper_config.yaml")
    if os.path.exists(override_path):
        primary_rules = override_path
    else:
        # 2) PyInstaller bundle: config.yaml is bundled via --add-data
        if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
            meipass = getattr(sys, "_MEIPASS", None)  # pylint: disable=no-member
            if meipass:
                bundled_path = os.path.join(meipass, "config.yaml")
                if os.path.isfile(bundled_path):
                    primary_rules = bundled_path
                elif os.path.isdir(bundled_path):
                    nested_path = os.path.join(bundled_path, "config.yaml")
                    if os.path.exists(nested_path):
                        primary_rules = nested_path
        # 3) Development mode: config.yaml in project root
        if not primary_rules:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            root_config = os.path.join(current_dir, "..", "..", "config.yaml")
            if os.path.exists(root_config):
                primary_rules = root_config

    # Custom rules: custom_config.yaml
    custom_rules = None
    # 1) User override in ADscan base directory
    override_path = os.path.join(adscan_base_dir, "custom_config.yaml")
    if os.path.exists(override_path):
        custom_rules = override_path
    else:
        # 2) PyInstaller bundle: custom_config.yaml is bundled via --add-data
        if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
            meipass = getattr(sys, "_MEIPASS", None)  # pylint: disable=no-member
            if meipass:
                bundled_path = os.path.join(meipass, "custom_config.yaml")
                if os.path.isfile(bundled_path):
                    custom_rules = bundled_path
                elif os.path.isdir(bundled_path):
                    nested_path = os.path.join(bundled_path, "custom_config.yaml")
                    if os.path.exists(nested_path):
                        custom_rules = nested_path
        # 3) Development mode: custom_config.yaml in project root
        if not custom_rules:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            root_config = os.path.join(current_dir, "..", "..", "custom_config.yaml")
            if os.path.exists(root_config):
                custom_rules = root_config

    return primary_rules, custom_rules


def _find_and_move_userdesc_log(shell: LdapShell, domain: str) -> Optional[str]:
    """Find the most recent UserDesc log file generated by netexec and move it to our domain directory.

    Args:
        shell: Shell instance with workspace and domain helpers.
        domain: Domain name.

    Returns:
        Path to moved file, or None if not found.
    """
    try:
        nxc_dir = _get_nxc_base_dir()
        if not os.path.exists(nxc_dir):
            print_warning("NetExec log directory not found (~/.nxc).")
            return None

        # Find all UserDesc log files
        userdesc_files = []
        for filename in os.listdir(nxc_dir):
            if filename.startswith("UserDesc-") and filename.endswith(".log"):
                filepath = os.path.join(nxc_dir, filename)
                # Get modification time
                mtime = os.path.getmtime(filepath)
                userdesc_files.append((mtime, filepath, filename))

        if not userdesc_files:
            print_warning("No UserDesc log files found in ~/.nxc/")
            return None

        # Sort by modification time (most recent first)
        userdesc_files.sort(reverse=True)

        # Get the most recent file
        _, source_file, _ = userdesc_files[0]

        workspace_cwd = shell._get_workspace_cwd()
        ldap_dir = domain_subpath(
            workspace_cwd, shell.domains_dir, domain, shell.ldap_dir
        )
        os.makedirs(ldap_dir, exist_ok=True)

        dest_file = os.path.join(ldap_dir, "descriptions.log")
        dest_file_rel = domain_relpath(
            shell.domains_dir, domain, shell.ldap_dir, "descriptions.log"
        )

        # Move the file (not copy)
        if SECRET_MODE:
            print_info_verbose(f"Moving {source_file} to {dest_file}")
        shutil.move(source_file, dest_file)

        print_success(f"Moved UserDesc log to {dest_file_rel}")
        return dest_file

    except Exception as e:
        telemetry.capture_exception(e)
        print_warning(f"Error finding/moving UserDesc log file: {e}")
        return None


def _parse_userdesc_log_file(log_file: str) -> dict[str, str]:
    """Parse netexec UserDesc log file to extract user:description pairs.

    Format:
    User:                     Description:
    Administrator             Built-in account for administering the computer/domain
    Guest                     Built-in account for guest access to the computer/domain

    Args:
        log_file: Path to UserDesc log file.

    Returns:
        Dictionary mapping usernames to their descriptions.
    """
    user_descriptions = {}

    try:
        with open(log_file, "r", encoding="utf-8") as f:
            lines = f.readlines()

        # Skip header line "User:                     Description:"
        # Start from line 2 (index 1)
        for line in lines[1:]:
            line = line.rstrip("\n\r")
            if not line.strip():
                continue

            # Format: "username                     description"
            # Username and description are separated by multiple spaces
            # Split by multiple spaces (2+)
            parts = re.split(r"\s{2,}", line.strip())

            if len(parts) >= 2:
                username = parts[0].strip()
                description = " ".join(
                    parts[1:]
                ).strip()  # Join in case description has spaces

                if username and description:
                    user_descriptions[username] = description
            elif len(parts) == 1 and parts[0].strip():
                # Sometimes description might be empty, skip
                if SECRET_MODE:
                    print_info_debug(f"Skipping line with only username: {parts[0]}")

    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error parsing UserDesc log file.")
        print_exception(show_locals=False, exception=e)

    return user_descriptions


def _save_ldap_descriptions_json(
    shell: LdapShell, user_descriptions: dict[str, str], domain: str
) -> Optional[str]:
    """Save user descriptions to JSON file (for our own format/storage).

    Args:
        shell: Shell instance with workspace helpers.
        user_descriptions: Dictionary mapping usernames to descriptions.
        domain: Domain name.

    Returns:
        Path to saved JSON file, or None if failed.
    """
    if not domain or not user_descriptions:
        return None

    try:
        # Create directory if it doesn't exist
        workspace_cwd = shell._get_workspace_cwd()
        ldap_dir = domain_subpath(
            workspace_cwd, shell.domains_dir, domain, shell.ldap_dir
        )
        os.makedirs(ldap_dir, exist_ok=True)

        # Save as JSON
        json_file = os.path.join(ldap_dir, "descriptions.json")
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "domain": domain,
                    "count": len(user_descriptions),
                    "users": [
                        {"username": username, "description": description}
                        for username, description in sorted(user_descriptions.items())
                    ],
                },
                f,
                indent=2,
                ensure_ascii=False,
            )

        return json_file
    except Exception as e:
        telemetry.capture_exception(e)
        print_warning(f"Error saving LDAP descriptions JSON: {e}")
        return None


def _display_ldap_descriptions_with_rich(
    user_descriptions: dict[str, str], *, max_rows: int = 30
) -> None:
    """Display user descriptions in a structured, aesthetic format using Rich.

    Args:
        user_descriptions: Dictionary mapping usernames to descriptions.
        max_rows: Maximum rows to show (sorted by username).
    """
    if not user_descriptions:
        return

    max_rows = max(1, int(max_rows))

    # Create table
    table = Table(
        title=f"User Descriptions ({len(user_descriptions)} found)",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Username", style="cyan", no_wrap=False, max_width=30)
    table.add_column("Description", style="white", no_wrap=False, max_width=80)

    # Sort by username and limit to a reasonable number of rows.
    sorted_users = sorted(user_descriptions.items())
    shown_users = sorted_users[:max_rows]

    for idx, (username, description) in enumerate(shown_users, 1):
        # Truncate description if too long
        display_description = (
            description[:77] + "..." if len(description) > 80 else description
        )
        table.add_row(str(idx), username, display_description)

    if len(sorted_users) > max_rows:
        remaining = len(sorted_users) - max_rows
        table.caption = f"Showing first {max_rows}. {remaining} more not shown."

    # Display panel
    print_panel_with_table(
        table,
        border_style=BRAND_COLORS["info"],
    )


def _display_ldap_description_candidates_with_rich(
    user_descriptions: dict[str, str],
    *,
    title: str,
    max_rows: int = 30,
) -> None:
    """Display a subset of user descriptions (e.g., those with candidates).

    Args:
        user_descriptions: Dictionary mapping usernames to descriptions.
        title: Table title to display.
        max_rows: Maximum rows to show (sorted by username).
    """
    if not user_descriptions:
        return

    max_rows = max(1, int(max_rows))
    table = Table(title=title, show_header=True, header_style="bold magenta")
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Username", style="cyan", no_wrap=False, max_width=30)
    table.add_column("Description", style="white", no_wrap=False, max_width=80)

    sorted_users = sorted(user_descriptions.items())
    shown_users = sorted_users[:max_rows]

    for idx, (username, description) in enumerate(shown_users, 1):
        display_description = (
            description[:77] + "..." if len(description) > 80 else description
        )
        table.add_row(str(idx), username, display_description)

    if len(sorted_users) > max_rows:
        remaining = len(sorted_users) - max_rows
        table.caption = f"Showing first {max_rows}. {remaining} more not shown."

    print_panel_with_table(table, border_style=BRAND_COLORS["warning"])


def _find_user_for_password_from_line(
    context_line: str, user_descriptions: dict[str, str]
) -> Optional[str]:
    """Find which user a password belongs to based on context line from UserDesc log format.

    Format: "username                     description with password"

    Args:
        context_line: Line containing the password (from UserDesc log).
        user_descriptions: Dictionary mapping usernames to descriptions.

    Returns:
        Username if found, None otherwise.
    """
    # Context line format: "username                     description"
    # Split by multiple spaces to get username
    parts = re.split(r"\s{2,}", context_line.strip())
    if len(parts) >= 1:
        username = parts[0].strip()
        if username in user_descriptions:
            return username
    return None


def _extract_password_candidates_from_credsweeper_findings(
    findings: dict[str, list[tuple[str, Optional[float], str, int, str]]],
    user_descriptions: dict[str, str],
) -> list[dict[str, object]]:
    """Map CredSweeper findings back to LDAP users and return candidate secrets.

    Args:
        findings: CredSweeper findings grouped by rule name.
        user_descriptions: Mapping of usernames -> descriptions.

    Returns:
        List of candidate dicts with username, password, rule, ml_probability, and context.
    """
    candidates: list[dict[str, object]] = []
    for rule_name, items in (findings or {}).items():
        for value, ml_probability, context_line, _line_num, _path in items:
            username = _find_user_for_password_from_line(
                str(context_line or ""), user_descriptions
            )
            if not username:
                continue
            password_value = str(value or "").strip()
            if not password_value or len(password_value) < 3:
                continue
            candidates.append(
                {
                    "username": username,
                    "password": password_value,
                    "rule": str(rule_name or ""),
                    "ml_probability": ml_probability,
                    "context": str(context_line or ""),
                }
            )

    # De-duplicate rule-level duplicates (same username+password found by multiple rules).
    merged: dict[tuple[str, str], dict[str, object]] = {}
    for item in candidates:
        key = (str(item["username"]), str(item["password"]))
        existing = merged.get(key)
        if not existing:
            merged[key] = item
            continue
        # Keep the highest ML probability (when available) and merge rule names.
        existing_rules = (
            set(str(existing.get("rule") or "").split(", "))
            if existing.get("rule")
            else set()
        )
        existing_rules.add(str(item.get("rule") or ""))
        merged[key]["rule"] = ", ".join(sorted(r for r in existing_rules if r))

        existing_prob = existing.get("ml_probability")
        new_prob = item.get("ml_probability")
        if isinstance(existing_prob, (int, float)) and isinstance(
            new_prob, (int, float)
        ):
            merged[key]["ml_probability"] = max(float(existing_prob), float(new_prob))
        elif existing_prob is None and isinstance(new_prob, (int, float)):
            merged[key]["ml_probability"] = float(new_prob)

    return list(merged.values())


def _analyze_descriptions_for_passwords(
    shell: LdapShell,
    descriptions_file: str,
    user_descriptions: dict[str, str],
    domain: str,
    *,
    anonymous: bool = False,
) -> None:
    """Analyze LDAP descriptions with CredSweeper CLI but avoid ML-based filtering.

    CredSweeper's ML validator can drop low-entropy, human-readable passwords
    embedded in natural-language descriptions. For this workflow we set
    ``ml_threshold=0.0`` (export everything that matches the rules) and then
    ask the operator to confirm candidates manually.
    """
    if not os.path.exists(descriptions_file):
        return

    if not getattr(shell, "credsweeper_path", None):
        print_info_verbose(
            "CredSweeper is not available; skipping description analysis."
        )
        return

    try:
        service = CredSweeperService(command_executor=shell.run_command)
        primary_rules, _custom_rules = _get_credsweeper_rules_paths()
        findings = service.analyze_file_with_options(
            descriptions_file,
            credsweeper_path=shell.credsweeper_path,
            rules_path=primary_rules,
            include_custom_rules=False,
            drop_ml_none=False,
            ml_threshold="0.0",
            doc=True,
            no_filters=True,
            timeout=300,
        )

        candidates = _extract_password_candidates_from_credsweeper_findings(
            findings, user_descriptions
        )
        if not candidates:
            print_info_verbose("No passwords detected in LDAP descriptions.")
            return

        candidate_users: dict[str, str] = {}
        for item in candidates:
            username = str(item["username"])
            description = user_descriptions.get(username)
            if description:
                candidate_users[username] = description

        _display_ldap_description_candidates_with_rich(
            candidate_users,
            title=f"Potential Passwords in Descriptions ({len(candidate_users)} found)",
            max_rows=30,
        )

        for item in candidates:
            marked_user = mark_sensitive(str(item["username"]), "user")
            marked_value = mark_sensitive(str(item["password"]), "password")
            selection = shell._questionary_select(
                f"Candidate for {marked_user}: {marked_value}\nHow do you want to handle this?",
                [
                    "Ignore (false positive)",
                    "Save and verify now",
                    "Stop reviewing",
                ],
                default_idx=1,
            )
            if selection is None or selection == 2:
                break
            if selection == 0:
                continue

            username_norm = str(item["username"]).strip().lower()
            value_norm = str(item["password"]).strip()
            shell.add_credential(
                domain,
                username_norm,
                value_norm,
                source_steps=_build_user_description_source_steps(
                    username=username_norm,
                    anonymous=anonymous,
                    secret=value_norm,
                ),
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("Error analyzing LDAP descriptions for potential passwords.")
        print_exception(show_locals=False, exception=exc)


def _build_user_description_source_steps(
    *, username: str, anonymous: bool, secret: str | None = None
) -> list[CredentialSourceStep]:
    """Build credential provenance for a password recovered from LDAP descriptions."""
    username_clean = str(username or "").strip().lower()
    auth_mechanism = "ldap_anonymous_bind" if anonymous else "ldap_authenticated_bind"
    return [
        CredentialSourceStep(
            relation="UserDescription",
            edge_type="user_description",
            entry_label="Domain Users",
            notes={
                "source": "ldap_descriptions",
                "source_username": username_clean,
                "source_protocol": "ldap",
                "auth_mechanism": auth_mechanism,
                **({"secret": str(secret).strip()} if str(secret or "").strip() else {}),
            },
        )
    ]


def execute_netexec_ldap_descriptions(
    shell: LdapShell, *, command: str, domain: str, anonymous: bool = False
) -> None:
    """Execute LDAP descriptions command, find and move netexec's UserDesc log file,
    parse it, display with Rich, and analyze descriptions for passwords using CredSweeper.

    Args:
        shell: Shell instance with NetExec execution and CredSweeper helpers.
        command: Full NetExec command to run.
        domain: Target domain.
    """
    try:
        completed_process = shell._run_netexec(command)

        # Check the process output
        if completed_process.returncode == 0:
            # Find and move the netexec-generated UserDesc log file
            descriptions_file = _find_and_move_userdesc_log(shell, domain)

            if not descriptions_file or not os.path.exists(descriptions_file):
                print_warning(
                    "No UserDesc log file found from netexec. Descriptions may not have been generated."
                )
                return

            # Parse user descriptions from the moved file
            user_descriptions = _parse_userdesc_log_file(descriptions_file)

            # Debug: show parsing results
            if SECRET_MODE:
                print_info_debug(
                    f"Parsed {len(user_descriptions)} user descriptions: {list(user_descriptions.keys())}"
                )

            if user_descriptions:
                # Save to JSON file (for our own format)
                _save_ldap_descriptions_json(shell, user_descriptions, domain)

                # Display with Rich
                _display_ldap_descriptions_with_rich(user_descriptions)

                # Analyze descriptions for passwords (regex-only, no ML)
                if descriptions_file:
                    _analyze_descriptions_for_passwords(
                        shell,
                        descriptions_file,
                        user_descriptions,
                        domain,
                        anonymous=anonymous,
                    )
            else:
                print_warning("No user descriptions found in UserDesc log file.")
                if SECRET_MODE:
                    print_info_debug(
                        f"File content (first 500 chars):\n{open(descriptions_file, 'r').read()[:500]}"
                    )
        else:
            print_error("Error listing LDAP descriptions.")
            if completed_process.stderr:
                print_error(completed_process.stderr)
            elif completed_process.stdout:  # Sometimes errors go to stdout
                print_error(completed_process.stdout)
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error executing netexec for LDAP descriptions.")
        print_exception(show_locals=False, exception=e)


def execute_netexec_users(
    shell: LdapShell, *, command: str, domain: str, filename: str
) -> None:
    """Execute the command to generate user lists (e.g., all, admin, privileged) via BloodHound.

    Args:
        shell: Shell instance with command execution and user list processing.
        command: Full command to run.
        domain: Target domain.
        filename: Output filename (e.g., "admins.txt", "privileged.txt").
    """
    try:
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            f"Executing command for {filename} in domain {marked_domain}: {command}"
        )
        completed_process = shell.run_command(
            command,
            timeout=300,
        )
        errors = completed_process.stderr if completed_process else None
        # output = completed_process.stdout # stdout is not directly used, output is written to file by bloodhound-cli

        # Check the process output
        if completed_process and completed_process.returncode == 0:
            try:
                shell._postprocess_user_list_file(
                    domain,
                    filename,
                    source=f"netexec_users:{filename}",
                )
            except Exception as e:
                telemetry.capture_exception(e)
                print_error("Error reading the users file.")
                print_exception(show_locals=False, exception=e)

        else:
            marked_domain = mark_sensitive(domain, "domain")
            print_error(f"Error enumerating users in domain {marked_domain}.")
            if errors:
                print_error(errors)
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error executing netexec.")
        print_exception(show_locals=False, exception=e)


def execute_ldap_computers(
    shell: LdapShell, *, command: str, domain: str, comp_file: str
) -> None:
    """Execute the provided command to generate the computer list,
    then process and display the result, and finally ask whether to perform a port scan.
    If the comp_file is 'enabled_computers.txt', convert hostnames to IPs in the background and then scan.

    Args:
        shell: Shell instance with command execution and computer processing.
        command: Full command to run.
        domain: Target domain.
        comp_file: Output filename (e.g., "enabled_computers.txt").
    """
    try:
        # Ensure relative output paths like `domains/<domain>/...` are written
        # inside the active workspace, regardless of the process CWD.
        workspace_cwd = shell.current_workspace_dir or os.getcwd()
        completed_process = shell.run_command(command, timeout=300, cwd=workspace_cwd)
        if completed_process is None:
            marked_domain = mark_sensitive(domain, "domain")
            print_error(
                f"Computer enumeration did not return a result (timeout or execution error) for domain {marked_domain}."
            )
            return
        errors = completed_process.stderr
        # stdout = completed_process.stdout # Captured, but not directly used by original logic for command output

        if completed_process.returncode == 0:
            marked_domain = mark_sensitive(domain, "domain")
            print_success_verbose(
                f"Computer list successfully generated on domain {marked_domain}."
            )

            # Path to the computers file and nmap directory
            computers_file = domain_subpath(
                workspace_cwd, shell.domains_dir, domain, comp_file
            )
            nmap_dir = domain_subpath(workspace_cwd, shell.domains_dir, domain, "nmap")

            # Read the computers file and count the non-empty lines
            try:
                if not os.path.exists(computers_file):
                    marked_path = mark_sensitive(computers_file, "path")
                    print_error(
                        f"The file {marked_path} does not exist. Did you run and import bloodhound data?"
                    )
                    return
                marked_path = mark_sensitive(computers_file, "path")
                print_info_debug(f"Computers file: {marked_path}")
                with open(
                    computers_file, "r", encoding="utf-8", errors="ignore"
                ) as file:  # 'file' shadows built-in, but kept for consistency
                    computers = [line.strip() for line in file if line.strip()]
                    marked_computers = [mark_sensitive(c, "host") for c in computers]
                    print_info_debug(f"Computers: {marked_computers}")

                # Telemetry: track computer enumeration results
                try:
                    comp_type = comp_file.replace(".txt", "").replace("_", "_")
                    properties = {
                        "computer_type": comp_type,
                        "count": len(computers),
                        "scan_mode": getattr(shell, "scan_mode", None),
                        "auth_type": shell.domains_data[domain].get(
                            "auth", "unknown"
                        ),
                    }
                    properties.update(
                        build_lab_event_fields(shell=shell, include_slug=True)
                    )
                    telemetry.capture("computers_enumerated", properties)
                except Exception as e:
                    telemetry.capture_exception(e)

                if comp_file == "enabled_computers_with_laps.txt":
                    shell._display_items(computers, "Computers with LAPS")
                elif comp_file == "enabled_computers_without_laps.txt":
                    shell._display_items(computers, "Computers without LAPS")
                else:
                    shell._display_items(computers, "Enabled Computers")
            except Exception as e:
                telemetry.capture_exception(e)
                print_error("Error reading the computers file.")
                print_exception(show_locals=False, exception=e)

            # Create the nmap directory if it does not exist
            if not os.path.exists(nmap_dir):
                os.makedirs(nmap_dir)

            if comp_file == "enabled_computers.txt":
                # Start the hostname-to-IP conversion (and subsequent port scan) sequentially.
                if not shell.do_check_dns(domain):
                    shell.do_update_resolv_conf(
                        f"{domain} {shell.domains_data[domain]['pdc']}"
                    )
                shell.convert_hostnames_to_ips_and_scan(
                    domain, computers_file, nmap_dir
                )
        else:
            marked_domain = mark_sensitive(domain, "domain")
            print_error(f"Error enumerating computers in domain {marked_domain}.")
            if errors:
                print_error(errors)
    except Exception as e:
        telemetry.capture_exception(e)
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"Error enumerating computers in domain {marked_domain}.")
        print_exception(show_locals=False, exception=e)
