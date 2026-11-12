"""Legacy CI command handler.

This module contains the orchestration logic for `adscan ci` (legacy mode).
It is intentionally decoupled from `adscan.py` by injecting the shell factory.
"""

from __future__ import annotations

from adscan_core.scan_policy import settings as policy_settings

from dataclasses import dataclass
from pathlib import Path
import os
import re
import shutil
import time
from typing import Any, Callable, Optional

from adscan_internal import (
    print_error,
    print_exception,
    print_info,
    print_info_verbose,
    print_success,
    print_warning,
    telemetry,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.cli.ci_events import emit_phase, emit_scan_plan
from adscan_internal.cli.session_preflight import (
    SessionPreflightConfig,
    SessionPreflightDeps,
    run_session_preflight,
)
from adscan_internal.workspaces import (
    activate_workspace,
    create_workspace_dir,
    write_initial_workspace_variables,
)
from adscan_internal.workspaces.retention import (
    auto_workspace_name,
    close_run_workspace,
)
from adscan_core.rich_output_collection import (
    PhaseChapter,
    SessionHeader,
    SessionLootCard,
    print_ci_autonomous_callout,
    print_phase_chapter,
    print_session_header,
    print_session_loot_card,
)

try:
    from adscan_internal.services.report_service import (
        ReportService,
        ReportGenerationConfig,
    )
except ImportError:  # pragma: no cover - public LITE repo excludes report generation
    ReportService = None  # type: ignore[assignment]
    ReportGenerationConfig = None  # type: ignore[assignment]


# Coarse CLI-only banner strip for `adscan ci`. ci.py orchestrates a few
# boundaries it can confidently identify in this file; the inner scan phases
# (enumeration, kerberos, ACL, collection, exploitation) live inside
# shell.do_start_auth / do_start_unauth.
#
# This list is purely cosmetic terminal text — it is NOT the machine-readable
# scan plan and feeds nothing the web consumes. The canonical plan (chapters →
# phases → subphases, with the stable ids the structured ``phase`` /
# ``scan_plan`` events and the web render) is the single source of truth in
# ``adscan_internal.services.scan_phases``; this banner is a deliberately
# coarser operator-facing wrapper around it.
_CI_PHASES: tuple[tuple[str, str], ...] = (
    ("Preflight", "DNS validation, connectivity, and credential sanity checks."),
    ("Reconnaissance", "Domain mapping, trust enumeration, and authentication."),
    ("Scan", "Users, groups, kerberoast, ACLs, BloodHound, and exploitation."),
    ("Reporting", "Compile findings, render report, and stage artefacts."),
    ("Loot", "Owned accounts, attack-path materialisation, and summary."),
)


def _chapter(number: int) -> PhaseChapter:
    """Build a PhaseChapter for the given 1-indexed phase number."""
    title, subtitle = _CI_PHASES[number - 1]
    return PhaseChapter(
        number=number,
        title=title,
        subtitle=subtitle,
        all_phases=tuple(name for name, _ in _CI_PHASES),
    )


@dataclass(frozen=True)
class CiConfig:
    """Configuration for running the legacy CI flow."""

    args: object
    requested_pro: bool


@dataclass(frozen=True)
class CiDeps:
    """Dependency bundle for running CI."""

    enable_auto_mode: Callable[[], None]
    build_preflight_args: Callable[[], object]
    handle_check: Callable[[object], bool]
    get_last_check_extra: Callable[[], dict[str, object]]
    track_docs_link_shown: Callable[[str, str], None]
    resolve_license_mode: Callable[[bool], object]
    create_shell: Callable[[object, object], object]
    console: object
    exit: Callable[[int], None]


_ADCS_ESC_RELATION_RE = re.compile(r"^adcsesc\d+", re.IGNORECASE)


def _build_ci_loot_card(
    shell: object,
    domain: str,
    *,
    elapsed_seconds: float,
) -> SessionLootCard:
    """Assemble a populated end-of-run loot card from the scan artifacts.

    Reads the FRESH, re-materialized attack-path snapshot (persisted at the
    scan-finalization seam just before this runs), the reconciled attack graph,
    and the technical-report findings so the card reflects the real outcome
    instead of the ``0 / 0 / ESC 0`` stub. Every read is best-effort — a missing
    artifact degrades a single metric to its default, never blocks exit.
    """
    domains_data = getattr(shell, "domains_data", {}) or {}
    domain_info = (
        domains_data.get(domain, {}) if isinstance(domains_data, dict) else {}
    ) or {}
    owned = list(domain_info.get("owned_accounts", []) or [])

    da_paths = 0
    da_paths_reach = 0
    totals_read = False
    adcs_esc_count = 0
    kerberoastable = 0
    asreproastable = 0
    critical = 0
    high = 0
    total_nodes = 0

    ws_dir = getattr(shell, "current_workspace_dir", "") or ""
    domains_dir = getattr(shell, "domains_dir", "domains") or "domains"

    # --- attack-path counts: DA routes ------------------------------------
    # ``da_paths`` drives the "← PWNED" banner, so it is the END-TO-END WALKED
    # count, never a reach count: a domain-breaker route that was only attempted
    # must not render as PWNED (the exposure-validation doctrine). ``reach`` is
    # the identified-route figure the recap panel prints, carried so a zero can
    # say which zero it is.
    #
    # Both come from the cardinality SSOT, whose first rule is that every
    # human-facing attack-path count comes from there. This site used to walk
    # ``attack_paths_snapshot.json`` itself, which is exactly how the card and
    # the recap panel ended up stating different answers to one question seconds
    # apart, and how a workspace with no readable snapshot printed "No paths
    # found" as though the domain had been measured clean.
    try:
        from adscan_internal.services.attack_path_counts import (
            client_path_totals_for_shell,
        )

        totals = client_path_totals_for_shell(shell, domain)
        da_paths = max(0, int(totals.effective_proven_full_domain_compromise))
        da_paths_reach = max(0, int(totals.paths_full_domain_compromise))
        totals_read = True
    except Exception as exc:  # noqa: BLE001 - the card must never break the run
        # Previously swallowed, which is how a failed count became an absence of
        # findings on the card. It still must not break the run, so it is logged
        # and the card reports the gap.
        totals_read = False
        telemetry.capture_exception(exc)
        print_exception(exception=exc)

    # --- attack-path snapshot: ADCS ESC discovery count --------------------
    # A discovery count over the route inventory, not a path cardinality, so it
    # is not one of the SSOT's named figures and is still read here.
    try:
        from adscan_internal.workspaces import domain_subpath
        from adscan_internal.cli.attack_path_execution import (
            ATTACK_PATH_SNAPSHOT_FILENAME,
        )
        import json as _json

        snap_path = domain_subpath(
            ws_dir, domains_dir, domain, ATTACK_PATH_SNAPSHOT_FILENAME
        )
        if os.path.exists(snap_path):
            from adscan_core.reporting.attack_path_snapshot_scope import (
                domain_listing_snapshot_paths,
            )

            with open(snap_path, "r", encoding="utf-8") as fh:
                snap = _json.load(fh)
            # Only the DOMAIN listing: an operator-scope snapshot holds the
            # routes from the run's own accounts, a subset the card must not
            # present as the domain's ADCS exposure.
            for path in domain_listing_snapshot_paths(snap):
                relations = path.get("relations") or []
                if isinstance(relations, list) and any(
                    _ADCS_ESC_RELATION_RE.match(str(rel or "")) for rel in relations
                ):
                    adcs_esc_count += 1
    except Exception:  # noqa: BLE001
        pass

    # --- attack graph: node count + roastable counts -----------------------
    try:
        from adscan_internal.workspaces import domain_subpath
        import json as _json

        graph_path = domain_subpath(ws_dir, domains_dir, domain, "attack_graph.json")
        if os.path.exists(graph_path):
            with open(graph_path, "r", encoding="utf-8") as fh:
                graph = _json.load(fh)
            nodes = graph.get("nodes")
            total_nodes = len(nodes) if isinstance(nodes, (list, dict)) else 0
            kerb_targets: set[str] = set()
            asrep_targets: set[str] = set()
            for edge in graph.get("edges", []) or []:
                if not isinstance(edge, dict):
                    continue
                rel = str(edge.get("relation") or edge.get("label") or "").strip().lower()
                target = str(edge.get("target") or edge.get("to") or "")
                if rel == "kerberoasting" and target:
                    kerb_targets.add(target)
                elif rel in {"asreproast", "asreproasting"} and target:
                    asrep_targets.add(target)
            kerberoastable = len(kerb_targets)
            asreproastable = len(asrep_targets)
    except Exception:  # noqa: BLE001
        pass

    # --- technical report findings: critical / high rollup -----------------
    # The SAME histogram the recap panel prints and the client report counts
    # (``summarize_findings``: alias-collapsed, reportable findings only, on the
    # contextual band the scan authored). The card used to bucket the raw
    # recorded ``severity`` itself, so it read "0 / 8" a few lines above a recap
    # reading "2 critical · 9 high" for the same run.
    try:
        from adscan_core.reporting.technical_report import summarize_findings

        _findings = summarize_findings(shell, domain=domain)  # type: ignore[arg-type]
        critical = int(_findings.critical)
        high = int(_findings.high)
    except Exception as exc:  # noqa: BLE001 - the card must never break the run
        telemetry.capture_exception(exc)
        print_exception(exception=exc)

    return SessionLootCard(
        domain=domain,
        elapsed_seconds=max(0.0, float(elapsed_seconds)),
        da_paths=da_paths,
        da_paths_reach=da_paths_reach,
        # A zero only means "no route" when the counts were read AND there was a
        # graph to read them from. Either precondition missing is a data gap, and
        # the card says so rather than crediting the domain with a clean result.
        paths_assessed=bool(totals_read and total_nodes > 0),
        adcs_esc_count=adcs_esc_count,
        kerberoastable=kerberoastable,
        asreproastable=asreproastable,
        critical_findings=critical,
        high_findings=high,
        total_nodes=total_nodes,
        owned_accounts=owned,
    )


def _record_scan_compliance_frameworks(shell: object, args: object) -> list[str]:
    """Hand the scan's ``--frameworks`` selection to its finalization seam.

    The scan end stamps the compliance block for these frameworks, so the web's
    Compliance page reflects the scan without a report being rendered. The value
    was already validated by :func:`_ci_compliance_scope_ok`; an invalid one
    here (a LITE run, which skips that gate) records nothing.
    """
    from adscan_internal.cli.attack_path_execution import (
        SCAN_COMPLIANCE_FRAMEWORKS_ATTR,
    )
    from adscan_internal.cli.common import _parse_frameworks

    try:
        selected = _parse_frameworks(getattr(args, "frameworks", None)) or []
    except ValueError:
        selected = []
    try:
        setattr(shell, SCAN_COMPLIANCE_FRAMEWORKS_ATTR, list(selected))
    except Exception:  # noqa: BLE001 - a frozen test double carries no selection
        pass
    return list(selected)


def _ci_workspace_dir(args: object) -> Optional[str]:
    """The ``--workspace`` directory when it already exists (saved-policy lookup)."""
    name = str(getattr(args, "workspace", "") or "").strip()
    if not name:
        return None
    from adscan_core.paths import get_workspaces_dir  # noqa: PLC0415

    path = get_workspaces_dir() / name
    return str(path) if path.is_dir() else None


def _ci_policy_choices(workspace_dir: Optional[str]) -> list:
    """The policies a ``ci`` run could name: built-ins, then saved, with scope."""
    from adscan_core.scan_policy.legacy_type_notice import PolicyChoice  # noqa: PLC0415
    from adscan_internal.services.saved_scan_policies import (  # noqa: PLC0415
        SCOPE_LABELS,
        list_policies,
    )

    try:
        policies = list_policies(workspace_dir)
    except Exception as exc:  # noqa: BLE001 - the guidance still names the built-ins
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return []
    return [
        PolicyChoice(
            flag_value=p.slug,
            label=p.name,
            scope=SCOPE_LABELS.get(p.scope, p.scope).lower(),
        )
        for p in policies
    ]


def resolve_ci_policy_environment(args: object) -> tuple[bool, Optional[str]]:
    """The ``adscan ci`` policy gate: the run must name a scan policy. FAIL FAST.

    Runs before the preflight and before anything touches the network. A run
    names its policy with ``--policy`` (a built-in or a saved policy), or with a
    ``checks`` section in ``--scan-config`` (how the Enterprise worker and a run
    plan deliver theirs, possibly modified for that one scan). The retired
    ``--type`` names none: alone it is refused with the guidance panel; next to a
    policy it is ignored with one warning line. All copy lives in
    :mod:`adscan_core.scan_policy.legacy_type_notice`.

    Returns:
        ``(ok, environment)``: ``ok`` is False when the run must stop (the panel
        was printed); ``environment`` is the named policy's (``lab`` / ``real``)
        when it could be read before the run, else ``None``.
    """
    from adscan_core.scan_policy import legacy_type_notice as guidance  # noqa: PLC0415
    from adscan_core.scan_policy.policy import (  # noqa: PLC0415
        effective_environment,
        policy_display_name,
    )
    from adscan_internal.services.saved_scan_policies import find_policy  # noqa: PLC0415
    from adscan_internal.services.scan_config import ScanConfigError  # noqa: PLC0415
    from rich.markup import escape as escape_markup  # noqa: PLC0415

    legacy_type = str(getattr(args, "type", None) or "").strip().lower()
    policy_name = str(getattr(args, "policy", None) or "").strip()
    workspace_dir = _ci_workspace_dir(args)

    definition = None
    if policy_name:
        found = find_policy(policy_name, workspace_dir)
        if found is None:
            guidance.print_notice(
                guidance.build_missing_policy_notice(
                    _ci_policy_choices(workspace_dir), unknown_name=policy_name
                )
            )
            return False, None
        definition = found.definition
    else:
        try:
            checks = getattr(resolve_ci_scan_config(args), "checks", None)
        except ScanConfigError:
            # Reported with its own message once the run loads the config.
            return True, None
        if checks is not None and not checks.is_default:
            definition = checks.definition

    if definition is None:
        choices = _ci_policy_choices(workspace_dir)
        if legacy_type and guidance.legacy_type_builtin(legacy_type):
            guidance.print_notice(guidance.build_ci_type_notice(legacy_type, choices=choices))
        else:
            guidance.print_notice(guidance.build_missing_policy_notice(choices))
        return False, None
    if legacy_type and guidance.legacy_type_builtin(legacy_type):
        print_warning(
            escape_markup(
                guidance.ci_type_ignored_line(
                    legacy_type, policy_named=policy_display_name(definition)
                )
            )
        )
    return True, effective_environment(definition)


def _ci_compliance_scope_ok(args: object, environment: Optional[str] = None) -> bool:
    """Pre-scan gate: a run for a real environment that will report needs a scoped framework.

    Returns ``True`` when the run may proceed. Prints the canonical error and
    returns ``False`` when a run under a policy for a real environment asked for
    a report without choosing a compliance framework.

    LITE is exempt by construction: the LITE exposure report carries no
    compliance mapping at all, so there is nothing to scope. A lab has no
    regulatory regime, and an unknown environment is a data gap, so neither
    requires one (the SSOT documents both).

    ``--frameworks`` also scopes the SCAN's own compliance mapping (stamped at
    scan end, with or without a report), so an invalid value is refused here
    whether or not a report was asked for: a typo must not silently produce a
    scan with no mapping.

    Args:
        args: The parsed ``ci`` arguments.
        environment: The environment of the policy the run names
            (:func:`resolve_ci_policy_environment`); it is what the scan is about
            to record as its workspace's environment.
    """
    from adscan_core import tier

    if not tier.is_pro():
        return True

    from adscan_internal.cli.common import _parse_frameworks

    try:
        explicit = _parse_frameworks(getattr(args, "frameworks", None))
    except ValueError as exc:
        print_error(str(exc))
        return False

    if not getattr(args, "generate_report", False):
        return True

    from adscan_core.scan_policy.policy import (  # noqa: PLC0415
        workspace_type_for_environment,
    )
    from adscan_internal.services.compliance_scope import (
        missing_framework_error,
        resolve_compliance_scope,
    )

    scope = resolve_compliance_scope(
        explicit=explicit,
        engagement_type=workspace_type_for_environment(environment),
    )
    if scope.missing_required:
        print_error(missing_framework_error())
        return False
    return True


def _apply_auto_revert_flag(shell: Any, flag: Optional[str]) -> None:
    """Fold ``--auto-revert on|off`` into ``scan_config.durable_changes``."""
    if flag not in ("on", "off"):
        return
    import dataclasses  # noqa: PLC0415

    enabled = flag == "on"
    config = getattr(shell, "scan_config", None)
    durable = getattr(config, "durable_changes", None)
    if config is None or durable is None:
        return
    shell.scan_config = dataclasses.replace(
        config,
        durable_changes=dataclasses.replace(durable, auto_revert=enabled, keep=None),
    )
    print_info(
        "Automatic reversion of ADscan's directory changes: "
        f"{'on' if enabled else 'off'} (--auto-revert)."
    )


def resolve_ci_scan_config(args: object):
    """Return the run's validated ``ScanConfig``.

    Precedence: an inline ``scan_config_data`` mapping (set when the run comes
    from a RunPlan, whose scan configuration travels inside the plan), then an
    explicit ``args.scan_config`` path, then the launcher's ``ADSCAN_SCAN_CONFIG``
    mount. None of them = ``DEFAULT_SCAN_CONFIG``, today's behaviour.

    Raises:
        ScanConfigError: The configuration is malformed.
    """
    from adscan_internal.services.scan_config import (  # noqa: PLC0415
        load_scan_config,
        parse_scan_config,
    )

    data = getattr(args, "scan_config_data", None)
    if isinstance(data, dict):
        return parse_scan_config(data)
    scan_config_path = (
        getattr(args, "scan_config", None) or os.environ.get("ADSCAN_SCAN_CONFIG") or ""
    )
    return load_scan_config(scan_config_path)


def run_ci(*, config: CiConfig, deps: CiDeps) -> int:
    """Run a non-interactive scan suitable for CI pipelines.

    Behaviour matches the original `handle_ci` implementation in `adscan.py`.
    """
    args = config.args
    _ci_started_at = time.monotonic()

    deps.enable_auto_mode()

    # Enterprise license gate — FAIL FAST, before anything else. A missing,
    # invalid or expired license on the appliance refuses NEW assessments with a
    # clear reason and exit 78, which the appliance worker maps to a client-safe
    # message. No-op (silent) for LITE and PRO without the Enterprise marker.
    from adscan_internal.cli.enterprise_license_gate import (
        LICENSE_BLOCKED_EXIT_CODE,
        ensure_license_allows_new_scan,
    )

    if not ensure_license_allows_new_scan("ci", workspace_dir=_ci_workspace_dir(args)):
        return LICENSE_BLOCKED_EXIT_CODE

    # PRO partner-tag gate — FAIL FAST, before the heavy preflight.
    #
    # `adscan check` (deps.handle_check, run below) verifies every tool + launches
    # Chromium — tens of seconds. A PRO run with no partner tag is refused anyway,
    # so refusing it AFTER that preflight made a paying customer wait through the
    # whole check only to be told a one-line tag is missing. The gate needs only
    # the resolved license mode (not the shell), and `adscan ci` is always
    # non-interactive (ADSCAN_NONINTERACTIVE is set at entry), so we can resolve
    # the license mode early and gate here. The full gate is a no-op for LITE and
    # for PRO once the tag is resolved, so an already-configured PRO run is
    # unaffected. (`start` keeps its own gate at its interactive seam.)
    license_mode = deps.resolve_license_mode(config.requested_pro)
    from adscan_internal.cli.partner_tag_gate import ensure_partner_tag_for_pro

    if not ensure_partner_tag_for_pro(license_mode):
        return 1

    # Scan-policy gate — FAIL FAST, before the preflight and before any network
    # activity. An unattended scan runs only under a policy the run names.
    policy_ok, policy_environment = resolve_ci_policy_environment(args)
    if not policy_ok:
        deps.exit(2)
        return 2

    # Compliance-scope gate — FAIL FAST, before the scan.
    #
    # A run for a real environment that will produce a report needs its
    # compliance framework scoped up front: it comes from the signed scope, not
    # from anything the binary can infer. Refusing here (rather than at the
    # report phase) means the operator is told before a long scan, not after it.
    # The late gate in ``run_generate_report`` still covers every other entry
    # point; both read the environment of the policy the scan runs under.
    if not _ci_compliance_scope_ok(args, policy_environment):
        return 1

    # Retention gate — FAIL FAST. ``--ephemeral`` deletes the workspace that
    # holds the report, so a report run must say where the report goes.
    if not _ci_retention_flags_ok(args):
        return 2

    # Deliverable gate — FAIL FAST. Retired report flags print their one
    # deprecation line, and --only / --emit / the branding posture are checked
    # now, so a typo or an un-entitled white-label surfaces before the scan.
    if not _announce_report_options(args):
        return 2

    preflight_result = run_session_preflight(
        config=SessionPreflightConfig(
            command_name="ci",
            docs_placement="ci_preflight_failed",
            allow_unsafe_override=False,
        ),
        deps=SessionPreflightDeps(
            build_preflight_args=deps.build_preflight_args,
            handle_check=deps.handle_check,
            get_last_check_extra=deps.get_last_check_extra,
            track_docs_link_shown=deps.track_docs_link_shown,
            confirm_ask=lambda _prompt, _default: False,
            exit=deps.exit,
        ),
    )

    # ``license_mode`` was resolved above for the early partner-tag gate.
    shell = deps.create_shell(deps.console, license_mode)
    shell.session_command_type = "ci"
    _record_scan_compliance_frameworks(shell, args)

    # Persist a client logo passed via --client-logo (the launcher already staged
    # the file into the mounted volume and forwards a container-visible path), so
    # the post-scan report co-brands its cover with the client's mark and later
    # runs reuse it. Best-effort; a cosmetic logo never blocks a scan.
    _client_logo_arg = (getattr(args, "client_logo", None) or "").strip()
    if _client_logo_arg:
        try:
            from adscan_internal.services.client_logo import (
                is_supported_logo_suffix,
                save_client_logo_setting,
            )

            if is_supported_logo_suffix(_client_logo_arg):
                save_client_logo_setting(_client_logo_arg)
            else:
                print_warning(
                    "Unsupported --client-logo file type; the report keeps the "
                    "ADscan mark only."
                )
        except Exception as exc:  # noqa: BLE001 — cosmetic; never block a scan
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    # Load the optional scan configuration (--scan-config). The launcher
    # bind-mounts the file read-only and points ADSCAN_SCAN_CONFIG at it; an
    # explicit ``args.scan_config`` (when the engine parser declares it) takes
    # precedence. Absent / empty = DEFAULT_SCAN_CONFIG = today's interactive
    # behavior, so the no-config path is byte-for-byte unchanged. The resolved
    # config is stored on the shell so the gated decision points (trust enum,
    # attack-path execution) consult one SSOT.
    from adscan_internal.services.scan_config import (
        DEFAULT_SCAN_CONFIG,
        ScanConfigError,
    )

    try:
        shell.scan_config = resolve_ci_scan_config(args)
    except ScanConfigError as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(f"Invalid scan configuration: {exc}")
        deps.exit(2)
        return 2
    if not shell.scan_config.is_default:
        print_info("Scan configuration applied from --scan-config.")
        print_info_verbose(
            "Scan config: "
            f"disabled_phases={list(shell.scan_config.phases.disabled)} "
            f"trust_policy={shell.scan_config.trust_enumeration.policy} "
            f"attack_path_policy={shell.scan_config.attack_paths.policy}"
        )
    else:
        # Keep the attribute present and well-typed even on the default path so
        # downstream getattr(shell, "scan_config", ...) always finds it.
        shell.scan_config = DEFAULT_SCAN_CONFIG

    # --policy <name> names a saved policy; a scan config's ``checks`` section is
    # the other way to give one. Both at once is ambiguous, so the run refuses
    # before anything is resolved (the policy itself is looked up once the
    # workspace is open, because a workspace policy wins over a global one).
    from adscan_internal.services.saved_scan_policies import (
        SavedPolicyError,
        ensure_single_policy_source,
    )

    policy_name = str(getattr(args, "policy", None) or "").strip()
    try:
        ensure_single_policy_source(shell.scan_config, policy_name)
    except SavedPolicyError as exc:
        print_error(str(exc))
        deps.exit(2)
        return 2

    # --read-only / --no-attack-paths: force the attack-path policy to 'none' so
    # paths are still computed and reported but never executed. The CLI flag maps
    # onto the same knob as ``attack_paths.policy: none`` in --scan-config, and
    # takes precedence over whatever the YAML/env config resolved to.
    if getattr(args, "read_only", False):
        import dataclasses

        from adscan_internal.services.scan_config import ATTACK_PATH_POLICY_NONE

        shell.scan_config = dataclasses.replace(
            shell.scan_config,
            attack_paths=dataclasses.replace(
                shell.scan_config.attack_paths,
                policy=ATTACK_PATH_POLICY_NONE,
                selected=(),
            ),
        )
        print_info("Read-only mode: attack paths will be mapped and reported, not executed.")

    # --auto-revert on|off: the ONE automatic-reversion switch, applied onto the
    # same scan-config knob (durable_changes.auto_revert) so every consumer reads
    # one value; the flag wins over the file, like --read-only.
    _apply_auto_revert_flag(shell, getattr(args, "auto_revert", None))

    # (The PRO partner-tag gate already ran as a fail-fast before the preflight,
    # above — a missing tag never reaches this far, so no second check is needed.)

    shell.preflight_check_passed = bool(preflight_result.passed)
    shell.preflight_check_fix_attempted = bool(preflight_result.fix_attempted)
    shell.preflight_check_overridden = bool(preflight_result.overridden)
    shell.ensure_workspaces_dir()

    created_workspace = False
    if getattr(args, "workspace", None):
        ws_dir = os.path.join(shell.workspaces_dir, args.workspace)
        if not os.path.isdir(ws_dir):
            create_workspace_dir(shell.workspaces_dir, args.workspace)
            write_initial_workspace_variables(
                workspace_name=args.workspace,
                workspace_path=ws_dir,
                workspace_type=None,
            )
            created_workspace = True
        # Route activation through the SSOT so the environment-change ledger (and
        # acl_cleanup_actions) is initialized. WITHOUT this, `ci` bypassed
        # activate_workspace and shell.environment_change_ledger stayed None, so
        # EVERY rollback/cleanup registration silently no-opped — and the paid
        # deliverable + the web Enterprise product then FALSELY attested "no
        # modifications to Active Directory" even after real AD writes (e.g. a
        # shadow-cred KeyCredentialLink). activate_workspace only mutates
        # in-memory state (no dir creation), so it is safe for an existing dir.
        activate_workspace(
            shell, workspaces_dir=shell.workspaces_dir, workspace_name=args.workspace
        )
        shell.load_workspace_data(shell.current_workspace_dir)
    else:
        ws = auto_workspace_name("ci", getattr(args, "domain", None), shell.workspaces_dir)
        ws_dir = os.path.join(shell.workspaces_dir, ws)
        os.makedirs(ws_dir, exist_ok=True)
        activate_workspace(
            shell, workspaces_dir=shell.workspaces_dir, workspace_name=ws
        )
        shell.load_workspace_data(shell.current_workspace_dir)
        created_workspace = True

    # The client's cleanup-only account: passed by reference (scan config section
    # or ADSCAN_CLEANUP_* environment, held for this run only), else the one saved
    # in the workspace, announced as such. After the workspace load on purpose:
    # the load is what restores the saved account.
    from adscan_internal.services.cleanup_credential_loader import (  # noqa: PLC0415
        load_cleanup_credential_for_run,
    )

    load_cleanup_credential_for_run(shell)
    # With an account set, state what it can undo in scope (printed, never asked:
    # ``ci`` is unattended). A fresh workspace knows no domain yet; the checklist
    # is printed again before the first attack step, once the directory is read.
    from adscan_internal.services.cleanup_capability import print_once  # noqa: PLC0415

    print_once(shell, force=True)

    # --- Premium session header ---
    _ci_domain = str(getattr(args, "domain", "") or "")
    _ci_dc = str(getattr(args, "dc_ip", "") or "")
    _ci_user = str(getattr(args, "username", "") or "")
    _ci_cred = (
        f"{_ci_user} / {_ci_domain.upper()}" if _ci_user and _ci_domain else _ci_user
    )
    print_session_header(
        SessionHeader(
            workspace=str(shell.current_workspace or ""),
            target_domain=_ci_domain,
            dc_ip=_ci_dc,
            credential_label=_ci_cred,
            scan_mode="ci",
        )
    )
    # Premium one-shot callout that frames the autonomous flow + sets
    # operator expectations (no prompts, defaults applied, fallback paths).
    # Always shown — the cost of redundancy here is much lower than the
    # cost of an operator being surprised by an unattended decision.
    print_ci_autonomous_callout()

    # Scan policy (``checks``) and scan pace (``pacing``, ``--pacing``,
    # ``--pacing-set``): resolved once, after the workspace is open so its
    # persisted controls are the fallback, and before anything sends traffic.
    # A policy that cannot be resolved aborts the run (exit 2), exactly like a
    # malformed scan config: a policy never degrades to "run everything".
    from adscan_internal.cli.scan_policy_cmd import print_ci_scan_controls
    from adscan_internal.services.scan_controls import (
        ScanControlsError,
        apply_ci_scan_controls,
        print_execution_decision,
        stamp_unattended_entry,
    )

    if policy_name:
        from adscan_internal.services.saved_scan_policies import scan_config_with_saved_policy

        try:
            shell.scan_config = scan_config_with_saved_policy(
                shell.scan_config, policy_name, workspace_dir=shell.current_workspace_dir
            )
        except SavedPolicyError as exc:
            print_error(str(exc))
            deps.exit(2)
            return 2

    # --pace-profile <name>: a saved pace profile, looked up once the workspace
    # is open (a workspace profile wins over a global one). An unknown name
    # aborts the run like an unknown policy.
    pace_profile = None
    pace_profile_name = str(getattr(args, "pace_profile", None) or "").strip()
    if pace_profile_name:
        from adscan_internal.cli.pace_profile_cmd import resolve_ci_profile  # noqa: PLC0415
        from adscan_internal.services.saved_pace_profiles import (  # noqa: PLC0415
            SavedPaceProfileError,
        )

        try:
            pace_profile = resolve_ci_profile(pace_profile_name, shell.current_workspace_dir)
        except SavedPaceProfileError as exc:
            print_error(str(exc))
            deps.exit(2)
            return 2

    # The run entry decides whether the policy's attack steps run on their own
    # (execution spec § 4). Stamped before the policy so every gate sees it.
    stamp_unattended_entry(shell, "ci")
    try:
        print_ci_scan_controls(
            apply_ci_scan_controls(
                shell,
                scan_config=shell.scan_config,
                cli_level=getattr(args, "pacing", None),
                cli_assignments=getattr(args, "pacing_set", None),
                workspace_dir=shell.current_workspace_dir,
                non_interactive=True,
                pace_profile=pace_profile,
            )
        )
    except ScanControlsError as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(f"Invalid scan policy or scan pace: {exc}")
        deps.exit(2)
        return 2
    print_execution_decision(shell)
    # Lab / CTF on the Enterprise appliance: refused unless the client's
    # administrator turned it on (adscan_core.scan_policy.lab_policy). Exit 78
    # with the reason beside the run, like a license refusal, so the worker
    # stores the same sentence.
    from adscan_internal.cli.enterprise_license_gate import (  # noqa: PLC0415
        LICENSE_BLOCKED_EXIT_CODE as _LAB_REFUSED_EXIT,
        ensure_lab_policy_allowed,
    )

    if not ensure_lab_policy_allowed(shell):
        deps.exit(_LAB_REFUSED_EXIT)
        return _LAB_REFUSED_EXIT
    try:
        shell.save_workspace_data()
    except Exception as exc:  # noqa: BLE001 - persisting the pace is best-effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)

    from adscan_internal.cli.common import build_telemetry_context
    from adscan_internal.services.scan_controls import workspace_type  # noqa: PLC0415

    telemetry_context = build_telemetry_context(shell=shell, trigger="ci_start")

    telemetry.set_cli_telemetry(shell.telemetry, context=telemetry_context)
    session_properties = {
        "$set": {"installation_status": "installed"},
        "mode": "ci",
        "scan_type": workspace_type(shell),
        "scan_mode": getattr(args, "mode", None),
        "preflight_check_passed": bool(preflight_result.passed),
        "preflight_check_fix_attempted": bool(preflight_result.fix_attempted),
        "preflight_check_overridden": bool(preflight_result.overridden),
        **telemetry_context,
    }
    telemetry.capture("session_start", properties=session_properties)

    shell.interface = args.interface
    # Split-DC/DNS (issue #15): a separate AD-zone DNS server for segmented
    # networks. Stash it session-wide so every resolver-update path picks it up
    # (unauth discovers the domain FROM the DC, so the domain key may not exist
    # yet), and persist it under the known domain for auth mode.
    _ci_dns_server = str(getattr(args, "dns_server", "") or "").strip()
    if _ci_dns_server:
        shell._pending_dns_server = _ci_dns_server
        _ci_dns_domain = str(getattr(args, "domain", "") or "").strip()
        if _ci_dns_domain:
            shell.domains_data.setdefault(_ci_dns_domain, {})["dns_server"] = _ci_dns_server
    try:
        from adscan_internal.services.myip_staleness import check_and_refresh_myip

        check_and_refresh_myip(shell, context="ci_start")
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_verbose(
            "CI could not auto-configure myip from the selected interface: "
            f"{mark_sensitive(str(exc), 'detail')}"
        )
    shell.auto = True

    def _run_auto_auth() -> bool:
        required = [args.domain, args.dc_ip, args.username, args.password]
        if not all(required):
            print_error(
                "Auth mode requires --domain, --dc-ip, --username, and --password"
            )
            return False
        if getattr(shell, "scan_policy", None) is None:
            print_error("The run has no scan policy. Pass --policy NAME (see: adscan policy list).")
            return False
        # No interface requirement here: only broadcast poisoning needs a named
        # NIC, and the poisoning seam skips it with a warning when none was given.
        if shell.auto is None:
            print_error(
                "Auto mode not found. Please configure it using 'set auto <value>'."
            )
            return False
        # Declare the full ordered plan up-front so the web renders the
        # engine-declared chapters → phases → subphases dynamically.
        from adscan_internal.services.scan_phases import (
            COMMAND_AUDIT,
            COMMAND_CI_AUTH,
        )

        emit_scan_plan(
            COMMAND_AUDIT if policy_settings.runs_full_assessment(shell) else COMMAND_CI_AUTH,
            getattr(shell, "scan_config", None),
        )
        # Chapter 1: Preflight (DNS validation, connectivity)
        print_phase_chapter(_chapter(1))
        emit_phase("dns_validation")
        if not shell.do_check_dns(args.domain, args.dc_ip):
            return False
        emit_phase("dns_configuration")
        shell.do_clear_all(None)
        shell.scan_mode = None
        # Chapter 2: Reconnaissance + Chapter 3: Scan are merged here because
        # the entire authenticated scan pipeline runs inside do_start_auth
        # without external phase boundaries we can hook from this file.
        print_phase_chapter(_chapter(2))
        shell.do_start_auth(
            f"{args.domain} {args.dc_ip} {args.username} {args.password}"
        )
        if getattr(shell, "scan_mode", None) != "auth":
            return False
        domain_data = shell.domains_data.get(args.domain)
        if not domain_data:
            print_warning("Authentication scan did not populate domain data.")
            return False
        username_key = args.username.lower()
        if username_key not in domain_data.get("credentials", {}):
            print_warning("Authenticated credential not stored; treating as failure.")
            return False
        return True

    def _run_auto_unauth() -> bool:
        if not args.hosts and not getattr(args, "dc_ip", None):
            print_error("Unauth mode requires --hosts or --dc-ip")
            return False
        if getattr(shell, "scan_policy", None) is None:
            print_error("The run has no scan policy. Pass --policy NAME (see: adscan policy list).")
            return False
        # No interface requirement here: only broadcast poisoning needs a named
        # NIC, and the poisoning seam skips it with a warning when none was given.
        if shell.auto is None:
            print_error(
                "Auto mode not found. Please configure it using 'set auto <value>'."
            )
            return False

        shell.hosts = args.hosts
        shell.do_clear_all(None)
        shell.scan_mode = None
        # Declare the unauth plan up-front for the web renderer.
        from adscan_internal.services.scan_phases import COMMAND_CI_UNAUTH

        emit_scan_plan(COMMAND_CI_UNAUTH, getattr(shell, "scan_config", None))
        # Chapter 2: Reconnaissance — the unauth path is pure recon.
        print_phase_chapter(_chapter(2))
        if getattr(args, "dc_ip", None):
            shell.do_start_unauth(str(args.dc_ip))
        else:
            shell.do_start_unauth(None)
        if getattr(shell, "scan_mode", None) != "unauth":
            return False
        if not shell.domains_data:
            print_warning(
                "Unauthenticated scan completed but did not discover any domains."
            )
            return False
        return True

    from adscan_internal.services.engagement.coverage_recorder import (
        finalize_run_coverage,
        start_run_coverage,
    )

    # Coverage evidence for the reconciliation rule: which checks ran, from which
    # vantage. Written as "interrupted" now so a crash closes nothing.
    # Engagement history (PRO): a workspace scanned before the ledger existed is
    # imported from its flat artifacts now, before this run overwrites them.
    from datetime import datetime as _dt, timezone as _tz  # noqa: PLC0415

    from adscan_internal.services.engagement.importer import (  # noqa: PLC0415
        import_before_run,
    )

    import_before_run(shell.current_workspace_dir, at=_dt.now(_tz.utc).isoformat())
    start_run_coverage(shell, authenticated=args.mode == "auth")
    success = _run_auto_auth() if args.mode == "auth" else _run_auto_unauth()
    # A scan stopped by SIGINT or the platform's "stop the scan" ran its normal
    # finalisation (artifacts, coverage gap), but it is not a successful
    # assessment: exit with the incomplete status and render no deliverable.
    from adscan_core.scan_control import scan_control as _scan_control  # noqa: PLC0415

    operator_stopped = _scan_control().last_scan_aborted
    if operator_stopped:
        success = False
    # The license refused every environment this run tried to assess (its
    # environment entitlement is used up): no report, and exit 78 below so the
    # appliance worker stores the license reason. A refused TRUSTED forest
    # beside an admitted primary one does not land here.
    from adscan_internal.cli.enterprise_license_gate import (  # noqa: PLC0415
        environment_refused_for_run,
        record_scan_identity_usage,
    )

    environment_refused = environment_refused_for_run(shell)
    # Scoped licences: enabled identities of the assessed domains, read from
    # the workspace now, before an ephemeral workspace is removed below.
    record_scan_identity_usage(shell)
    if environment_refused:
        success = False
    # A run that reached its end is still not a successful assessment when the
    # target domain's collection and attack-path discovery never completed: it
    # holds no evidence about whether the domain resisted compromise. Exit with
    # a status of its own so the appliance worker records it as incomplete, and
    # never render a deliverable from it.
    assessment_gap: tuple[str, ...] = ()
    if success and args.mode == "auth":
        assessment_gap = _ci_assessment_gap(shell, str(args.domain or ""))
        if assessment_gap:
            success = False
    finalize_run_coverage(shell, success=bool(success))

    # Flag validation is a lab activity (genuinely environment), and only for a
    # lab that has flags: a GOAD run has none, so it must not exit 2 for them.
    should_validate_flags = (
        success and policy_settings.is_lab(shell) and _ci_lab_has_capture_flags(shell)
    )
    flags_valid = not should_validate_flags
    if should_validate_flags and shell.current_workspace_dir:
        flags_dir = os.path.join(shell.current_workspace_dir, "flags")
        user_flag_path = os.path.join(flags_dir, "user.txt")
        root_flag_path = os.path.join(flags_dir, "root.txt")

        user_flag_exists = os.path.exists(user_flag_path)
        root_flag_exists = os.path.exists(root_flag_path)

        if user_flag_exists and root_flag_exists:
            flag_pattern = re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE)
            try:
                with open(user_flag_path, "r", encoding="utf-8") as file:
                    user_flag = file.read().strip()
                with open(root_flag_path, "r", encoding="utf-8") as file:
                    root_flag = file.read().strip()

                if flag_pattern.match(user_flag) and flag_pattern.match(root_flag):
                    flags_valid = True
                    print_success("Flags validation passed:")
                    print_success(f"   User flag: {user_flag}")
                    print_success(f"   Root flag: {root_flag}")
                else:
                    print_warning("Flags found but format is invalid:")
                    if not flag_pattern.match(user_flag):
                        print_warning(f"   User flag format invalid: {user_flag}")
                    if not flag_pattern.match(root_flag):
                        print_warning(f"   Root flag format invalid: {root_flag}")
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_error("Error reading flag files.")
                print_exception(show_locals=False, exception=exc)
        else:
            missing = []
            if not user_flag_exists:
                missing.append("user.txt")
            if not root_flag_exists:
                missing.append("root.txt")
            print_warning(f"Flag files not found: {', '.join(missing)}")

    # Resolve the durable operator_confirmed AD objects (machine account, RBCD,
    # KeyCredentialLink) BEFORE the report renders, so the deliverable shows
    # their final state (reverted / kept / manual_required) instead of
    # "in progress". do_exit() calls the same hook again; it is a no-op then,
    # because every resolved entry is terminal.
    try:
        from adscan_internal.cli.relay_rbcd import (  # noqa: PLC0415
            run_operator_confirmed_exit_cleanup,
        )

        run_operator_confirmed_exit_cleanup(shell)
    except Exception as exc:  # noqa: BLE001 — never block the report on cleanup
        telemetry.capture_exception(exc)
        print_exception(show_locals=False, exception=exc)
    # The final retry pass, before the report, so the deliverable shows what the
    # best credential of the run could still undo (do_exit runs it again for
    # whatever the ACL exit cleanup leaves; already-tried principals are skipped).
    try:
        from adscan_internal.services.final_revert_pass import (  # noqa: PLC0415
            run_final_revert_retry_pass,
        )

        run_final_revert_retry_pass(shell)
    except Exception as exc:  # noqa: BLE001 — never block the report on cleanup
        telemetry.capture_exception(exc)
        print_exception(show_locals=False, exception=exc)

    report_file_path = None
    deliverable_requested = bool(
        success and flags_valid and getattr(args, "generate_report", False)
    )
    if deliverable_requested:
        # Chapter 4: Reporting
        print_phase_chapter(_chapter(4))
        emit_phase("report_generation")
        print_info("Generating report as requested...")
        if shell.current_workspace_dir:
            report_json_path = os.path.join(
                shell.current_workspace_dir, "technical_report.json"
            )
            report_format = "pdf"
            frameworks_raw = getattr(args, "frameworks", None)
            frameworks = (
                [f.strip() for f in frameworks_raw.split(",") if f.strip()]
                if frameworks_raw
                else None
            )
            # A render that raises must never turn a finished scan into a
            # failed one: the results stand, the deliverable is reported failed
            # (exit CI_EXIT_DELIVERABLE_FAILED) and can be rendered again.
            try:
                report_file_path = _run_ci_report_generation(
                    shell,
                    args,
                    report_json_path=report_json_path,
                    report_format=report_format,
                    frameworks=frameworks,
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(show_locals=False, exception=exc)
                report_file_path = None
            if not report_file_path:
                print_warning("Report generation failed")
        else:
            print_warning("Workspace directory not available, cannot generate report")

    from adscan_core.ci_exit_codes import (  # noqa: PLC0415
        CI_EXIT_ASSESSMENT_INCOMPLETE,
        CI_EXIT_DELIVERABLE_FAILED,
    )

    exit_code = resolve_ci_exit_code(
        success=bool(success),
        flags_valid=flags_valid,
        should_validate_flags=should_validate_flags,
        environment_refused=bool(environment_refused),
        license_blocked_exit_code=LICENSE_BLOCKED_EXIT_CODE,
        assessment_gap=assessment_gap,
        deliverable_failed=deliverable_requested and not report_file_path,
        operator_stopped=operator_stopped,
    )
    if exit_code == 0 and should_validate_flags:
        print_success("CI scan finished successfully with flags validated.")
    elif exit_code == 0:
        print_success("CI scan finished successfully.")
    elif exit_code == 2:
        print_error("CI scan completed but flags validation failed.")
    elif exit_code == CI_EXIT_DELIVERABLE_FAILED:
        print_error(
            "CI scan completed and its results are in the workspace, but the "
            "deliverable did not render. Render it again without rescanning: "
            "adscan deliver --workspace <name> with the same report options."
        )
    elif environment_refused:
        print_error(
            "CI scan stopped: the license does not allow assessing this target "
            "(see the license message above)."
        )
    elif operator_stopped and exit_code == CI_EXIT_ASSESSMENT_INCOMPLETE:
        print_error(
            "CI scan stopped before it finished (interrupt or platform request). "
            "Results collected so far are in the workspace and the coverage record "
            "declares what was not assessed. No report was generated."
        )
    elif exit_code == CI_EXIT_ASSESSMENT_INCOMPLETE:
        print_error(
            f"CI scan incomplete for {mark_sensitive(str(args.domain), 'domain')}: "
            f"{_describe_phases(assessment_gap)} did not complete, so this run "
            "cannot say whether the domain held. No report was generated. See "
            "the log above for the step that ended the scan early."
        )
        for detail in _describe_gap_details(shell, str(args.domain or ""), assessment_gap):
            print_error(f"  {detail}")
    else:
        print_error("CI scan failed. Check the logs above for details.")

    artifact_report_path = None
    if report_file_path and os.path.exists(report_file_path):
        print_success(f"Report generated successfully: {report_file_path}")
        if os.environ.get("GITHUB_ACTIONS") == "true":
            artifacts_dir = os.path.join(os.getcwd(), "artifacts")
            os.makedirs(artifacts_dir, exist_ok=True)
            artifact_report_path = os.path.join(
                artifacts_dir, os.path.basename(report_file_path)
            )
            try:
                shutil.copy2(report_file_path, artifact_report_path)
                print_info(
                    f"Report copied to artifacts directory: {artifact_report_path}"
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                print_warning(f"Failed to copy report to artifacts directory: {exc}")
                artifact_report_path = None

    # Engine contract (adscan run --plan): note which workspace this run used and
    # whether the run is about to remove it. Nothing is written here; legacy ci
    # behaves exactly as before. `adscan run` writes run_summary.json and the
    # artifact manifest after this handler (and so after do_exit) returns, and
    # never for a workspace the run removed.
    from adscan_internal.services.engagement.run_summary import (  # noqa: PLC0415
        note_run_workspace,
    )

    # The workspace and its report are the run's output, so ci KEEPS its
    # workspace by default (adscan_internal/workspaces/retention.py).
    # ``--ephemeral`` opts in to deleting the workspace this run created.
    # ``--output DIR`` copies the report out (the launcher mounts DIR).
    copied_report_path = _copy_ci_report_out(
        report_file_path,
        getattr(args, "output", None),
        kit_files=getattr(args, "_ci_kit_files", None),
    )
    ephemeral_requested = bool(getattr(args, "ephemeral", False))
    ephemeral = bool(created_workspace and ephemeral_requested)
    # Never delete the only copy of the report the run was asked for (the
    # up-front gate requires --output; this covers a copy that failed).
    report_at_risk = ephemeral and _workspace_holds_undelivered_report(
        shell.current_workspace_dir,
        report_file_path,
        copied_out_to=copied_report_path or artifact_report_path,
    )
    workspace_removed = ephemeral and not report_at_risk
    note_run_workspace(shell.current_workspace_dir, removed=workspace_removed)
    # Engagement history (PRO / Enterprise): reconcile this run against the
    # workspace's ledger and keep its evidence in runs/<run_id>/. Never for a
    # workspace this run is about to remove; never fails the scan.
    if not workspace_removed:
        from adscan_internal.services.engagement.ledger_writer import (  # noqa: PLC0415
            record_ci_run_in_ledger,
        )

        record_ci_run_in_ledger(shell.current_workspace_dir, clock_released=False)

    if report_at_risk:
        print_warning(
            f"Workspace '{mark_sensitive(shell.current_workspace, 'workspace')}' kept "
            "despite --ephemeral: the report could not be copied out and would have "
            "been deleted with it."
        )
    # Shared with ``execute``: delete with --ephemeral (a failed run keeps only
    # logs/), otherwise say where the workspace and the report are.
    close_run_workspace(
        name=shell.current_workspace,
        workspace_dir=shell.current_workspace_dir,
        created=created_workspace,
        ephemeral=workspace_removed or (ephemeral_requested and not created_workspace),
        failed=exit_code != 0,
        report_path=report_file_path,
    )

    # --- End-of-run loot card ---
    try:
        # Chapter 5: Loot — final act, the loot card is its centrepiece.
        print_phase_chapter(_chapter(5))
        _loot_domain = str(
            getattr(args, "domain", "") or getattr(shell, "current_domain", "") or ""
        )
        print_session_loot_card(
            _build_ci_loot_card(
                shell,
                _loot_domain,
                elapsed_seconds=time.monotonic() - _ci_started_at,
            )
        )
    except Exception:  # noqa: BLE001
        pass  # loot card is cosmetic — never block exit

    shell.do_exit(exit=False)
    return exit_code


def resolve_ci_exit_code(
    *,
    success: bool,
    flags_valid: bool,
    should_validate_flags: bool,
    environment_refused: bool,
    license_blocked_exit_code: int,
    assessment_gap: tuple[str, ...],
    deliverable_failed: bool = False,
    operator_stopped: bool = False,
) -> int:
    """Return ``adscan ci``'s exit status for how the run ended.

    ``operator_stopped`` (the scan control plane stopped the scan: a SIGINT or
    the platform's stop request) reads as an incomplete assessment, never 0.

    ``success`` is already False when ``assessment_gap`` is non-empty (the
    handler clears it), so an incomplete assessment can never read 0: that
    false green is what the release gate's exit-3 row exists to catch.

    ``deliverable_failed`` (a report was asked for after a complete scan and did
    not render) maps to ``CI_EXIT_DELIVERABLE_FAILED`` only when the scan itself
    would have exited 0: it never masks a failed or incomplete scan, and never
    makes a completed one read as failed.
    """
    from adscan_core.ci_exit_codes import (  # noqa: PLC0415
        CI_EXIT_ASSESSMENT_INCOMPLETE,
        CI_EXIT_DELIVERABLE_FAILED,
    )

    if success and (assessment_gap or operator_stopped):
        success = False
    if success:
        if should_validate_flags and not flags_valid:
            return 2
        if deliverable_failed:
            return CI_EXIT_DELIVERABLE_FAILED
        return 0
    if environment_refused:
        return license_blocked_exit_code
    if assessment_gap or operator_stopped:
        return CI_EXIT_ASSESSMENT_INCOMPLETE
    return 1


def _ci_assessment_gap(shell: Any, domain: str) -> tuple[str, ...]:
    """Return the core phases the target domain never completed in this run.

    Empty when a domain was proven compromised (proof needs no further
    evidence) and when collection and attack-path discovery completed. Same
    SSOT as the end-of-scan panel, so the panel and the exit status agree.
    """
    try:
        from adscan_internal.services.scan_outcome_scope import (  # noqa: PLC0415
            resolve_scan_outcome_scope,
        )
        from adscan_internal.services.scan_progress import (  # noqa: PLC0415
            authenticated_assessment_gap,
        )

        if resolve_scan_outcome_scope(shell).domain_compromised:
            return ()
        return authenticated_assessment_gap(shell, domain, verb="start_auth")
    except Exception as exc:  # noqa: BLE001 - never turn a judged run into a crash
        telemetry.capture_exception(exc)
        print_exception(show_locals=False, exception=exc)
        return ()


def _describe_phases(phase_ids: tuple[str, ...]) -> str:
    """Join the operator-facing titles of ``phase_ids`` ("A and B")."""
    from adscan_internal.services.scan_progress import phase_titles  # noqa: PLC0415

    return " and ".join(phase_titles(phase_ids))


def _describe_gap_details(
    shell: Any, domain: str, phase_ids: tuple[str, ...]
) -> tuple[str, ...]:
    """Return "<Phase>: <what did not finish>" for each phase marked incomplete."""
    try:
        from adscan_internal.services.scan_progress import (  # noqa: PLC0415
            incomplete_phases,
            phase_titles,
        )

        marks = incomplete_phases(shell, domain)
        lines: list[str] = []
        for phase_id, title in zip(phase_ids, phase_titles(phase_ids)):
            detail = str((marks.get(phase_id) or {}).get("detail") or "").strip()
            if detail:
                lines.append(f"{title}: {detail[:1].upper()}{detail[1:]}.")
        return tuple(lines)
    except Exception as exc:  # noqa: BLE001 - a detail line never changes the verdict
        telemetry.capture_exception(exc)
        print_exception(show_locals=False, exception=exc)
        return ()


def run_generate_report(
    shell: object,
    report_file: str,
    report_format: str = "pdf",
    report_profile: str = "full",
    frameworks: Optional[list] = None,
    *,
    engine: str = "",
    renderer: str = "",
    template: str = "",
    theme: str = "",
    display_name: str = "",
) -> Optional[str]:
    """Generate a report from technical report JSON.

    Args:
        shell: Shell instance with license_mode and event_bus
        report_file: Path to technical_report.json
        report_format: Format to generate. Public CLI flows pass "pdf".
        report_profile: Report profile ("full", "technical", "executive")
        frameworks: Compliance frameworks the operator explicitly selected.
            Valid values: ``adscan_core.compliance_frameworks.FRAMEWORK_KEYS``.
            There is NO default: an empty selection renders no compliance
            mapping, and an AUDIT engagement refuses to render at all until the
            operator chooses (see
            ``adscan_internal.services.compliance_scope``, the resolution SSOT
            shared with ``adscan deliver``).
        engine: PDF engine ("chromium" — the only supported engine). Empty = env/default.
        renderer: Attack-path renderer ("graphviz" | "cytoscape"). Empty = env/default.
        template: Report template ("legacy" | "premium"). Empty = env/default.
        theme: Report theme ("corporate_light" | "editorial" | ""). Empty = env/default.

    Returns:
        Path to generated report file, or None on failure
    """
    if ReportService is None or ReportGenerationConfig is None:
        # LITE — the PRO report service is stripped from the image. Render the
        # self-contained HTML exposure report from the scan's own data instead.
        # This is the single LITE render path shared by the REPL
        # ``generate_report`` verb and ``adscan ci`` (the tier decides the
        # output; there is no flag). Returns the written ``.html`` path so CI's
        # artifact handling picks it up like any other report.
        from adscan_internal.services.post_scan_report import (
            TRIGGER_CI,
            generate_report_with_telemetry,
            get_post_scan_report_path,
        )

        # An engagement workspace already had its exposure report rendered at
        # scan completion. Re-rendering here would write a second timestamped
        # pair of files and print the same panel twice, so reuse the artifact
        # this run already produced.
        already_rendered = get_post_scan_report_path(shell)
        if already_rendered and os.path.exists(already_rendered):
            return already_rendered

        return generate_report_with_telemetry(
            shell, trigger=TRIGGER_CI, report_file=report_file
        )

    if not os.path.exists(report_file):
        print_error(f"Report file not found: {report_file}")
        return None

    report_format_lower = report_format.lower()
    if report_format_lower not in {"word", "pdf"}:
        print_error(f"Invalid format '{report_format}'. Valid formats: word, pdf")
        return None
    report_profile_lower = report_profile.lower()
    if report_profile_lower not in {"full", "technical", "executive", "sample"}:
        print_error(
            f"Invalid profile '{report_profile}'. "
            "Valid profiles: full, technical, executive, sample"
        )
        return None

    workspace_dir = Path(os.path.dirname(report_file)) if report_file else Path.cwd()

    # Compliance scoping — resolved through the SSOT ``adscan deliver`` also
    # calls, so the two entry points can never disagree about the same
    # decision again. An AUDIT engagement refuses to render a conformance
    # verdict the operator never scoped; a ctf or unclassified workspace
    # renders with no mapping and says so out loud. Reached by BOTH
    # ``adscan ci --generate-report`` and ``adscan report`` (which calls this
    # function), so neither needs its own framework default.
    from adscan_internal.services.compliance_scope import (
        announce_compliance_scope,
        missing_framework_error,
        persist_compliance_decision,
        resolve_compliance_scope,
    )

    scope = resolve_compliance_scope(
        explicit=frameworks, shell=shell, workspace_dir=workspace_dir
    )
    if scope.missing_required:
        print_error(
            missing_framework_error(
                rerender_hint=(
                    f"adscan report --workspace {workspace_dir.name} "
                    "--frameworks <keys>"
                )
            )
        )
        return None
    announce_compliance_scope(scope)
    # Record the decision this render runs under, so the report states an
    # explicit "no framework applies" as the assessor's decision.
    persist_compliance_decision(scope)
    frameworks = scope.as_list()

    report_path = Path(report_file)
    print_info_verbose(
        f"Using technical report source: {mark_sensitive(str(report_path), 'path')}"
    )

    report_service = ReportService(
        event_bus=getattr(shell, "event_bus", None),
        license_mode=getattr(shell, "license_mode", None),
    )

    config = ReportGenerationConfig(
        report_file=report_path,
        format=report_format_lower,
        profile=report_profile_lower,
        workspace_dir=workspace_dir,
        frameworks=frameworks,
        engine=engine,
        renderer=renderer,
        template=template,
        theme=theme,
        display_name=display_name,
        # The session's live change ledger. This report renders mid-run, before
        # the ledger file is necessarily flushed, so without it the engagement
        # integrity statement reads "the record could not be read" on exactly
        # the run that produced the record.
        ledger=getattr(shell, "environment_change_ledger", None),
    )

    result_path = report_service.generate_report(config)

    # Offer to open the freshly generated report. Auto-skipped in non-interactive
    # contexts (TTY check + ADSCAN_NONINTERACTIVE), so this is safe to call from
    # both the shell `generate_report` command and `adscan ci`.
    if result_path is not None:
        from adscan_internal.services.host_open import prompt_and_open

        result_path_obj = Path(result_path) if not isinstance(result_path, Path) else result_path
        if result_path_obj.is_file():
            prompt_and_open(result_path_obj, prompt="Open the report now?")

    return str(result_path) if result_path else None



def _ci_lab_has_capture_flags(shell: Any) -> bool:
    """Whether the lab this run targets publishes capture flags to validate.

    Asked only on a lab policy. A GOAD run has no ``user.txt`` / ``root.txt``,
    so treating their absence as "flags validation failed" (exit 2) reported a
    complete, successful run as a failure to every unattended caller and skipped
    the report it asked for. An unknown lab keeps the check (see
    ``lab_publishes_capture_flags``).
    """
    from adscan_core.lab_catalog import lab_publishes_capture_flags  # noqa: PLC0415

    if lab_publishes_capture_flags(getattr(shell, "lab_provider", None)):
        return True
    print_info(
        "This lab publishes no capture flags, so flag validation does not apply "
        "to this run."
    )
    return False


def _ci_retention_flags_ok(args: object) -> bool:
    """Refuse ``--ephemeral --generate-report`` without ``--output``.

    Refusing before the scan, rather than deleting the report or silently
    keeping the workspace after it, is the only option that neither throws away
    the run's output nor contradicts the flag the operator passed.
    """
    if not getattr(args, "ephemeral", False) or not getattr(args, "generate_report", False):
        return True
    if getattr(args, "output", None):
        return True
    print_error(
        "--ephemeral deletes the workspace that holds the report: pass --output DIR "
        "to keep a copy of the report, or drop --ephemeral to keep the workspace."
    )
    return False


def _copy_ci_report_out(
    report_file_path: Optional[str],
    output_dir: Optional[str],
    *,
    kit_files: Optional[list] = None,
) -> Optional[str]:
    """Copy the generated report (and its HTML twin) into ``--output``.

    When the run rendered more than the report (``--only report,playbook``),
    the kit ZIP and every other PDF it produced are copied too, so the folder
    holds what was asked for. A report-only run copies the PDF and its HTML
    twin, as it always has.

    Returns:
        The copied PDF path, or None when there was nothing to copy or it failed.
    """
    if not output_dir or not report_file_path or not os.path.exists(report_file_path):
        return None
    try:
        # The shared deliverable-destination SSOT copies (the REPL copy step and
        # the LITE report use the same function); the workspace copy stays.
        from adscan_core.deliverable_destination import copy_to_destination  # noqa: PLC0415

        html_twin = os.path.splitext(report_file_path)[0] + ".html"
        files = [report_file_path, html_twin]
        produced_pdfs = [f for f in (kit_files or []) if str(f).lower().endswith(".pdf")]
        if len(produced_pdfs) > 1:
            files += [str(f) for f in kit_files or [] if str(f) not in files]
        copy_to_destination(files, output_dir)
        copied = os.path.join(output_dir, os.path.basename(report_file_path))
        print_success(f"Report copied to the --output folder: {os.path.basename(copied)}")
        return copied
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_warning(f"Could not copy the report to --output: {exc}")
        return None


def _workspace_holds_undelivered_report(
    workspace_dir: Optional[str],
    report_file_path: Optional[str],
    *,
    copied_out_to: Optional[str] = None,
) -> bool:
    """True when the only copy of the generated report lives in ``workspace_dir``.

    ``ci`` removes the workspace it auto-created at the end of the run. Before
    this check, ``--generate-report`` wrote the PDF into that workspace and the
    same run then deleted it, so the operator got a success line pointing at a
    file that no longer existed.

    Args:
        workspace_dir: The run's workspace directory.
        report_file_path: The report the run generated, if any.
        copied_out_to: Where the report was copied outside the workspace, if it
            was (the GitHub Actions artifact copy).

    Returns:
        True when removing the workspace would remove the report.
    """
    if not workspace_dir or not report_file_path:
        return False
    if not os.path.exists(report_file_path):
        return False
    if copied_out_to and os.path.exists(copied_out_to):
        return False
    workspace_root = os.path.abspath(workspace_dir)
    report = os.path.abspath(report_file_path)
    try:
        return os.path.commonpath([workspace_root, report]) == workspace_root
    except ValueError:
        return False

def _run_ci_report_generation(
    shell: object,
    args: object,
    *,
    report_json_path: str,
    report_format: str,
    frameworks: Optional[list] = None,
) -> Optional[str]:
    """Render ``adscan ci --generate-report`` through the ``deliver`` kit pipeline.

    One pipeline renders every deliverable: ``ci`` builds the ``deliver``
    namespace from the shared report-options model
    (``adscan_core.report_options``) and runs it in-process, so a scan and its
    branded deliverable are one command and render exactly as ``adscan deliver``
    would on the same workspace. The selection defaults to the Security
    Assessment Report alone (:data:`CI_DEFAULT_ONLY`); ``--only`` widens it.

    The PDF it returns is the headline Security Assessment Report of this run
    (published by ``run_deliver`` on the namespace), which CI's artifact copy
    and ``--output`` plumbing consume. Every file the kit produced is kept on
    ``args`` for ``--output`` when the selection is wider than the report.

    LITE images strip the kit engine; ``ci`` is PRO-only there, so the fallback
    to :func:`run_generate_report` (the LITE exposure report) is defensive.

    Returns:
        The path to the Security Assessment Report PDF, or ``None`` on failure.
    """
    try:
        from adscan_internal.cli.deliver import run_deliver_sync as _run_deliver_sync
    except ModuleNotFoundError:
        return run_generate_report(shell, report_json_path, report_format, frameworks=frameworks)

    ns = _ci_deliver_namespace(args, workspace_dir=Path(report_json_path).parent, frameworks=frameworks)
    # The kit reads the change ledger from the workspace. Flush the session's
    # live ledger first: on a first run the file can trail the session by a
    # moment, and the report would then say the record could not be read. This
    # is a read-only, records-nothing flush, so it uses the quiet SSOT accessor
    # (``active_ledger``) rather than a bare getattr or the warning write-seam.
    from adscan_internal.services.ledger_guard import active_ledger  # noqa: PLC0415

    ledger = active_ledger(shell)
    if ledger is not None:
        try:
            ledger.flush()
        except Exception as exc:  # noqa: BLE001 - the render reads what is on disk
            telemetry.capture_exception(exc)
            print_exception(show_locals=False, exception=exc)
    setattr(ns, "_shell", shell)
    rc = _run_deliver_sync(ns)
    if rc != 0:
        return None
    setattr(args, "_ci_kit_files", list(getattr(ns, "_kit_copy_files", []) or []))
    # ``run_deliver`` publishes the headline artefact it actually produced on
    # the namespace. Take it from there rather than rebuilding a staging path:
    # each run stages into its own directory (so a kit can never bundle an
    # earlier run's PDF), and a reconstructed path is exactly how CI used to
    # pick up a stale report when the current run had not produced one.
    headline = getattr(ns, "_headline_pdf", "") or ""
    return headline if headline and Path(headline).is_file() else None


def _ci_deliver_namespace(
    args: object,
    *,
    workspace_dir: Path,
    frameworks: Optional[list],
) -> Any:
    """The ``deliver`` namespace for a CI render, built from the shared model.

    Every deliverable option is copied verbatim from the ``ci`` namespace, so
    nothing ``deliver`` accepts can be lost on the way. Three CI rules apply on
    top: the selection defaults to the report alone, the client falls back to
    the retired ``--display-name`` (and the run plan's ``display_name``), and the
    frameworks are the ones the scan resolved.
    """
    import argparse as _argparse

    from adscan_core.report_options import CI_DEFAULT_ONLY, report_option_values

    values = report_option_values(args)  # type: ignore[arg-type]
    values["only"] = values.get("only") or CI_DEFAULT_ONLY
    values["client"] = (
        values.get("client") or (getattr(args, "display_name", "") or "").strip() or None
    )
    values["frameworks"] = ",".join(frameworks) if frameworks else None
    ns = _argparse.Namespace(
        workspace=str(workspace_dir),
        output=None,
        progress_model=None,
        debug=bool(getattr(args, "debug", False)),
        **values,
    )
    # ``ci`` already said it once, before the scan (see _announce_report_options).
    setattr(ns, "_branding_notice_shown", True)
    # Telemetry tells a scan's report apart from a ``deliver`` run.
    setattr(ns, "_report_entry", "ci")
    # A retired theme was announced before the scan too; do not repeat it, but
    # keep the fact for the theme telemetry.
    from adscan_core.report_options import retired_theme_requested

    if retired_theme_requested(ns):
        setattr(ns, "_retired_theme_notice_shown", True)
    return ns


def _announce_report_options(args: object) -> bool:
    """Validate and announce the deliverable options before the scan starts.

    A scan can run for hours, so a typo in ``--only`` or ``--emit`` and a
    white-label request the install cannot honour are reported at the start,
    not after the scan. Retired report flags print their one deprecation line
    here too. Validation only applies when a report was requested.

    Returns:
        ``False`` when a deliverable option is invalid (the caller exits 2).
    """
    from adscan_core.report_options import (
        CI_DEFAULT_ONLY,
        parse_emit_values,
        parse_only_slugs,
        report_deprecation_notices,
    )

    for notice in report_deprecation_notices(args):  # type: ignore[arg-type]
        print_warning(notice)
    if not getattr(args, "generate_report", False):
        return True
    try:
        parse_only_slugs(getattr(args, "only", None) or CI_DEFAULT_ONLY)
        parse_emit_values(getattr(args, "emit", None))
    except ValueError as exc:
        print_error(str(exc))
        return False
    try:
        from adscan_internal.services.report_branding import whitelabel_downgrade_notice

        notice = whitelabel_downgrade_notice(getattr(args, "branding", None), env=os.environ)
    except Exception as exc:  # noqa: BLE001 - a notice never blocks a scan
        telemetry.capture_exception(exc)
        print_exception(show_locals=False, exception=exc)
        notice = None
    if notice:
        print_warning(notice)
    return True
