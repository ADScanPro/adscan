"""RDP CLI orchestration helpers.

This module extracts RDP-related orchestration logic out of the monolithic
`adscan.py` so it can be reused by future UX layers while keeping runtime
behaviour stable for the current CLI.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import subprocess
import time
from typing import Any

from rich.prompt import Confirm

from adscan_internal import (
    print_error,
    print_exception,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_warning,
    telemetry,
)
from adscan_internal.integrations.netexec.timeouts import (
    resolve_service_command_timeout_seconds,
)
from adscan_internal.rich_output import mark_sensitive, strip_sensitive_markers
from adscan_internal.services.pivot_capability_registry import (
    is_service_pivot_capable,
)
from adscan_internal.services.pivot_opportunity_service import (
    ensure_host_bound_workflow_target_viable,
)
from adscan_internal.services.host_reachability_filter import (
    filter_reachable_hosts_sync,
    print_reachability_summary,
    render_no_reachable_panel,
)
from adscan_internal.services.rdp_login_service import scan_rdp_hosts
from adscan_internal.services.service_access_probe_history import (
    record_service_access_probe_batch,
)
from adscan_internal.services.service_access_results import (
    ServiceAccessFinding,
    render_service_access_results,
    summarize_service_access_categories,
    select_confirmed_service_access_followup_targets,
)
from adscan_internal.text_utils import strip_ansi_codes
from adscan_internal.workspaces.computers import load_target_entries


def _looks_like_ntlm_hash(value: str) -> bool:
    """Return True when value resembles an NTLM hash or LM:NT pair."""
    candidate = value.strip()
    if re.fullmatch(r"[0-9a-fA-F]{32}", candidate):
        return True
    if re.fullmatch(r"[0-9a-fA-F]{32}:[0-9a-fA-F]{32}", candidate):
        return True
    return False


def ask_for_rdp_access(
    shell: Any, *, domain: str, host: str, username: str, password: str
) -> None:
    """Ask to access a host via RDP and execute the connection.

    Args:
        shell: Active `PentestShell` instance.
        domain: User's domain.
        host: Target host.
        username: RDP username.
        password: Password or NTLM hash.
    """
    if (
        ensure_host_bound_workflow_target_viable(
            shell,
            domain=domain,
            target_host=host,
            workflow_label="RDP access workflow",
            service="rdp",
            resume_after_pivot=True,
        )
        is None
    ):
        return

    marked_host = mark_sensitive(host, "hostname")
    marked_username = mark_sensitive(username, "user")
    answer = Confirm.ask(
        f"Do you want to access host {marked_host} via RDP as user {marked_username}?"
    )
    if answer:
        rdp_access(
            shell,
            domain=domain,
            host=host,
            username=username,
            password=password,
        )


def rdp_access(
    shell: Any, *, domain: str, host: str, username: str, password: str
) -> None:
    """Access a host via RDP using xfreerdp.

    This helper extracts the legacy ``PentestShell.rdp_access`` method from
    ``adscan.py`` so that RDP logic can be reused by other UX layers.

    Args:
        shell: Active `PentestShell` instance.
        domain: User's domain.
        host: Target host.
        username: RDP username.
        password: Password or NTLM hash.
    """
    from adscan_internal.docker_runtime import is_docker_env

    rdp_binary = shutil.which("xfreerdp") or shutil.which("xfreerdp3")
    if not rdp_binary:
        print_error(
            "RDP client not found. Please install xfreerdp via 'adscan install'."
        )
        return

    # Import GUI session check functions from adscan.py
    # These are defined at module level in adscan.py
    # We'll need to pass them or import them if available
    try:
        # Try to import from adscan if available (circular import risk, but adscan imports this module)
        import sys

        adscan_module = sys.modules.get("adscan")
        if adscan_module:
            _has_gui_session = getattr(adscan_module, "_has_gui_session", None)
            _is_full_adscan_container_runtime = getattr(
                adscan_module, "_is_full_adscan_container_runtime", None
            )
            if _has_gui_session and _is_full_adscan_container_runtime:
                # Use imported functions
                pass
            else:
                raise AttributeError("Functions not found in adscan module")
        else:
            raise ImportError("adscan module not loaded")
    except (ImportError, AttributeError):
        # Fallback: define inline checks if not available
        def _has_gui_session() -> bool:
            """Check if GUI session is available."""
            display = os.getenv("DISPLAY") or os.getenv("WAYLAND_DISPLAY")
            if display:
                try:
                    # Most X11 clients require the Unix socket directory to be mounted.
                    if os.path.isdir("/tmp/.X11-unix"):
                        return True
                except OSError:
                    pass
            return bool(display)

        def _is_full_adscan_container_runtime() -> bool:
            """Check if running in full ADscan container runtime."""
            if os.getenv("ADSCAN_CONTAINER_RUNTIME") == "1":
                return True
            if not is_docker_env():
                return False
            if os.getenv("ADSCAN_HOME") != "/opt/adscan":
                return False
            return (
                os.path.isdir("/opt/adscan/tool_venvs")
                and os.path.isdir("/opt/adscan/tools")
                and os.path.isdir("/opt/adscan/wordlists")
            )

    if not _has_gui_session():
        in_container = _is_full_adscan_container_runtime() or is_docker_env()
        if in_container:
            # In Docker FULL mode, fall back to launching RDP on the host when
            # container GUI passthrough is not available.
            if _is_full_adscan_container_runtime() and try_launch_rdp_on_host(
                shell,
                domain=domain,
                host=host,
                username=username,
                password=password,
            ):
                return
            print_error(
                "Cannot launch RDP from the container: no GUI session detected "
                "(DISPLAY/WAYLAND_DISPLAY is not set)."
            )
            print_info(
                "Run this from your host desktop session, or restart ADscan with GUI passthrough enabled "
                "(export ADSCAN_DOCKER_GUI=1 on the host before `adscan start`)."
            )
        else:
            print_error(
                "Cannot launch RDP: no GUI session detected (DISPLAY/WAYLAND_DISPLAY is not set)."
            )
            print_info("Run ADscan from a graphical desktop session and try again.")
        return

    marked_domain = mark_sensitive(domain, "domain")
    marked_username = mark_sensitive(username, "user")
    marked_password = mark_sensitive(password, "password")
    marked_host = mark_sensitive(host, "hostname")
    use_ntlm_hash = _looks_like_ntlm_hash(password)

    if use_ntlm_hash:
        command = (
            f"{rdp_binary} /d:'{marked_domain}' /u:'{marked_username}' "
            f"/pth:'{marked_password}' /v:{marked_host} /cert:ignore"
        )
    else:
        command = (
            f"{rdp_binary} /d:'{marked_domain}' /u:'{marked_username}' "
            f"/p:'{marked_password}' /v:{marked_host} /cert:ignore"
        )

    print_info(f"Accessing host {marked_host} via RDP as user {marked_username}")
    execute_rdp_access(shell, command)


def try_launch_rdp_on_host(
    shell: Any, *, domain: str, host: str, username: str, password: str
) -> bool:
    """Best-effort: launch the RDP client on the host when running in Docker FULL mode.

    Args:
        shell: Active `PentestShell` instance.
        domain: User's domain.
        host: Target host.
        username: RDP username.
        password: Password or NTLM hash.

    Returns:
        True if RDP was successfully launched on the host, False otherwise.
    """
    sock_path = os.getenv("ADSCAN_HOST_HELPER_SOCK", "").strip()
    if not sock_path:
        return False
    try:
        from adscan_internal.host_privileged_helper import (
            HostHelperError,
            host_helper_client_request,
        )

        clean_domain = strip_sensitive_markers(domain)
        clean_host = strip_sensitive_markers(host)
        clean_user = strip_sensitive_markers(username)
        clean_pass = strip_sensitive_markers(password)

        resp = host_helper_client_request(
            sock_path,
            op="rdp_launch",
            payload={
                "domain": clean_domain,
                "host": clean_host,
                "username": clean_user,
                "password": clean_pass,
            },
        )
        if resp.ok:
            print_info(
                "RDP launched on the host desktop session (container GUI passthrough not available)."
            )
            marked_host = mark_sensitive(clean_host, "hostname")
            marked_user = mark_sensitive(clean_user, "user")
            print_info(f"Host RDP target: {marked_user}@{marked_host}")
            return True

        if resp.message:
            print_info_verbose(f"[rdp] host-helper: {resp.message}")
        if resp.stderr:
            print_info_verbose(
                f"[rdp] host-helper stderr: {strip_ansi_codes(resp.stderr)[:200]}"
            )
    except HostHelperError as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_verbose(f"[rdp] host-helper error: {exc}")
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_verbose(f"[rdp] host-helper exception: {exc}")
    return False


def execute_rdp_access(shell: Any, command: str) -> bool:
    """Execute an RDP access command.

    This helper extracts the legacy ``PentestShell.execute_rdp_access`` method
    from ``adscan.py`` so that RDP execution logic can be reused by other UX layers.

    Args:
        shell: Active `PentestShell` instance with `spawn_command` method.
        command: RDP command string to execute.

    Returns:
        True if RDP session was launched successfully, False otherwise.
    """
    from adscan_internal.docker_runtime import is_docker_env

    try:
        # RDP is typically interactive; using a blocking command with a timeout can
        # incorrectly surface "errors" if the user keeps the session open.
        # Spawn the RDP client and return immediately.
        print_info(f"Executing RDP command: {command}")

        proc = shell.spawn_command(
            command,
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            ignore_errors=True,
        )
        if not proc:
            print_error("Failed to start RDP client.")
            return False

        # If it exits immediately, treat it as an error; otherwise consider it launched.
        time.sleep(1)
        returncode = proc.poll()
        if returncode is None:
            print_info("RDP session launched. Close the RDP window to end the session.")
            return True

        if returncode == 0:
            print_info("RDP command completed successfully.")
            return True

        stderr_text = ""
        try:
            _, stderr_text = proc.communicate(timeout=1)
        except Exception:
            stderr_text = ""
        clean_stderr = strip_ansi_codes(stderr_text or "").strip()
        normalized = clean_stderr.lower()
        if "failed to open display" in normalized or "$display" in normalized:
            print_error(
                "RDP client could not open a display (GUI not available in this environment)."
            )
            try:
                import sys

                adscan_module = sys.modules.get("adscan")
                if adscan_module:
                    _is_full_adscan_container_runtime = getattr(
                        adscan_module, "_is_full_adscan_container_runtime", None
                    )
                    if not _is_full_adscan_container_runtime:
                        raise AttributeError("Function not found")
                else:
                    raise ImportError("adscan module not loaded")
            except (ImportError, AttributeError):

                def _is_full_adscan_container_runtime() -> bool:
                    """Check if running in full ADscan container runtime."""
                    if os.getenv("ADSCAN_CONTAINER_RUNTIME") == "1":
                        return True
                    if not is_docker_env():
                        return False
                    if os.getenv("ADSCAN_HOME") != "/opt/adscan":
                        return False
                    return (
                        os.path.isdir("/opt/adscan/tool_venvs")
                        and os.path.isdir("/opt/adscan/tools")
                        and os.path.isdir("/opt/adscan/wordlists")
                    )

            if _is_full_adscan_container_runtime() or is_docker_env():
                print_info(
                    "If you're running ADscan in Docker, run RDP from the host desktop session "
                    "or restart with GUI passthrough (export ADSCAN_DOCKER_GUI=1 on the host)."
                )
            else:
                print_info(
                    "Please ensure your $DISPLAY (or Wayland session) is set correctly and try again."
                )
        else:
            print_error("RDP process exited with an error.")
            if clean_stderr:
                print_info_verbose(f"RDP error output: {clean_stderr}")
        return False
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error during RDP command execution.")
        print_exception(show_locals=False, exception=e)
        return False


def run_rdp_service_access_sweep(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    targets: str,
    prompt: bool = True,
    target_count: int = 1,
) -> bool:
    """Enumerate RDP access using the native aardwolf async stack.

    Uses the native aardwolf CredSSP+NTLM client from the vendored skelsec
    stack (vendor/aardwolf/).

    Args:
        shell: Active shell instance.
        domain: Target AD domain.
        username: Username to test.
        password: Plaintext password or NTLM hash.
        targets: Single host or file with one host per line.
        prompt: Whether to ask for interactive RDP access after a hit.
        target_count: Best-effort target count used for timeout/concurrency policy.

    Returns:
        True when one or more hosts grant RDP access, False otherwise.
    """
    is_hash = bool(
        callable(getattr(shell, "is_hash", None)) and shell.is_hash(password)
    )

    target_entries = (
        sorted(load_target_entries(targets))
        if os.path.isfile(str(targets))
        else [str(targets).strip()]
    )
    host_list = [h for h in target_entries if h]

    if not host_list:
        print_error("No valid RDP targets to probe.")
        return False

    global_timeout = resolve_service_command_timeout_seconds(
        service="rdp",
        target_count=target_count,
        return_boolean=False,
    )
    # Per-host connect timeout: use a fraction of the global budget, capped
    # between 5 and 30 seconds so we don't stall on a single unresponsive host.
    connect_timeout = max(5.0, min(30.0, global_timeout / max(len(host_list), 1)))
    # Concurrency: cap at 10 workers, minimum 3.
    workers = min(10, max(3, len(host_list)))

    workspace_cwd = (
        shell._get_workspace_cwd()  # type: ignore[attr-defined]
        if hasattr(shell, "_get_workspace_cwd")
        else getattr(shell, "current_workspace_dir", os.getcwd())
    )
    domains_dir = getattr(shell, "domains_dir", "domains")
    # DC IP for Kerberos fallback (used when NTLM is disabled by GPO).
    dc_ip: str | None = getattr(shell, "dc_ip", None) or getattr(shell, "pdc_ip", None)

    marked_domain = mark_sensitive(domain, "domain")
    marked_username = mark_sensitive(username, "user")
    print_info_debug(
        "[rdp-aardwolf] dispatch: "
        f"domain={marked_domain} user={marked_username} "
        f"targets={mark_sensitive(str(targets), 'path')} "
        f"auth_mode={'pass_the_hash' if is_hash else 'password'} "
        f"hosts={len(host_list)} workers={workers} "
        f"connect_timeout={connect_timeout:.0f}s global_timeout={global_timeout}s"
    )
    if is_hash:
        print_info(f"Using RDP pass-the-hash mode for user {marked_username}")

    # Posture wiring (PR-RDP): skip doomed NTLM round-trip when the workspace
    # already knows NTLM is disabled by GPO; record a signal when our own
    # NTLM-then-Kerberos fallback proves it is.
    posture_sink = None
    posture_snapshot = None
    domains_data = getattr(shell, "domains_data", None)
    if domains_data is not None:
        try:
            from adscan_internal import get_console
            from adscan_internal.cli.widgets.intelligence_update import (
                render_intelligence_update,
            )
            from adscan_internal.services.domain_posture import get_posture
            from adscan_internal.services.posture_sink import (
                make_workspace_posture_sink,
            )

            posture_sink = make_workspace_posture_sink(
                domains_data,
                on_finding=lambda finding: get_console().print(
                    render_intelligence_update(finding)
                ),
            )
            posture_snapshot = get_posture(domains_data, domain=domain)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(f"[rdp-aardwolf] posture wiring skipped: {exc}")

    # Pre-flight TCP probe on 3389 — RDP credential testing waits 5-10s per
    # offline host. Filtering them out first is the difference between minutes
    # and seconds at corporate scale.
    if len(host_list) > 1:
        rdp_reach = filter_reachable_hosts_sync(host_list, port=3389)
        print_reachability_summary(rdp_reach, service_label="RDP")
        if not rdp_reach.reachable:
            render_no_reachable_panel(rdp_reach, operation_label="RDP Login Sweep")
            return
        host_list = list(rdp_reach.reachable)

    try:
        rdp_results = asyncio.run(
            scan_rdp_hosts(
                host_list,
                domain=domain,
                username=username,
                secret=password,
                is_hash=is_hash,
                dc_ip=dc_ip,
                connect_timeout_s=connect_timeout,
                max_workers=workers,
                posture_snapshot=posture_snapshot,
                posture_sink=posture_sink,
                domain_for_posture=domain,
            )
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("RDP enumeration failed.")
        print_exception(show_locals=False, exception=exc)
        return False

    service_findings = [
        ServiceAccessFinding(
            service="rdp",
            host=r.host,
            username=username,
            category="confirmed"
            if r.confirmed
            else ("ambiguous" if r.ambiguous else "denied"),
            reason=r.error or ("CredSSP+NTLM accepted" if r.confirmed else ""),
            status="TRUE" if r.confirmed else ("MAYBE" if r.ambiguous else "FALSE"),
            backend="aardwolf",
        )
        for r in rdp_results
        if r.verdict != "ERROR"
    ]
    for r in rdp_results:
        if r.verdict == "ERROR":
            print_info_debug(
                f"[rdp-aardwolf] error probing {mark_sensitive(r.host, 'hostname')}: {r.error}"
            )

    success_findings = [f for f in service_findings if f.category == "confirmed"]
    if is_hash and not success_findings and service_findings:
        print_warning(
            "RDP pass-the-hash returned no confirmed hosts. "
            "If NTLM is disabled by GPO on this network, PtH is not viable — "
            "obtain a plaintext password or Kerberos key instead."
        )
    render_service_access_results(
        service="rdp",
        username=username,
        findings=service_findings,
        total_targets=target_count,
    )
    category_counts = summarize_service_access_categories(service_findings)
    if (
        category_counts["denied"]
        or category_counts["transport"]
        or category_counts["ambiguous"]
    ):
        print_info_debug(
            "[rdp-aardwolf] unconfirmed result breakdown: "
            f"denied={category_counts['denied']} "
            f"transport={category_counts['transport']} "
            f"ambiguous={category_counts['ambiguous']}"
        )

    found_privileged_hosts = False
    for finding in success_findings:
        found_privileged_hosts = True
        try:
            from adscan_internal.services.attack_graph_service import (
                upsert_netexec_privilege_edge,
            )

            upsert_netexec_privilege_edge(
                shell,
                domain,
                username=finding.username,
                relation="CanRDP",
                target_ip=finding.host,
                target_hostname=None,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    normalized_target_entries = {
        str(e).strip().lower() for e in target_entries if str(e).strip()
    }
    confirmed_targets = [
        entry
        for entry in target_entries
        if str(entry).strip().lower()
        in {
            str(f.host).strip().lower() for f in success_findings if str(f.host).strip()
        }
    ]
    if (
        not confirmed_targets
        and len(normalized_target_entries) == 1
        and success_findings
    ):
        confirmed_targets = list(target_entries)

    try:
        record_service_access_probe_batch(
            workspace_dir=workspace_cwd,
            domains_dir=domains_dir,
            domain=domain,
            username=username,
            service="rdp",
            targets=target_entries,
            confirmed_hosts=confirmed_targets,
            source="run_rdp_service_access_sweep",
            backend="aardwolf",
            pivot_capable=is_service_pivot_capable("rdp"),
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"[rdp-aardwolf] failed to persist probe history: {exc}")

    if prompt and success_findings:
        selected_followups, used_selector = (
            select_confirmed_service_access_followup_targets(
                shell,
                service="rdp",
                findings=success_findings,
            )
        )
        if used_selector:
            for finding in selected_followups:
                marked_host = mark_sensitive(finding.host, "hostname")
                print_info_debug(
                    "[rdp-aardwolf] launching selected follow-up: "
                    f"user={marked_username} host={marked_host}"
                )
                rdp_access(
                    shell,
                    domain=domain,
                    host=finding.host,
                    username=finding.username,
                    password=password,
                )
        else:
            for finding in success_findings:
                marked_host = mark_sensitive(finding.host, "hostname")
                print_info_debug(
                    "[rdp-aardwolf] launching follow-up prompt: "
                    f"user={marked_username} host={marked_host}"
                )
                shell.ask_for_rdp_access(
                    domain, finding.host, finding.username, password
                )
    elif not prompt:
        for finding in success_findings:
            marked_host = mark_sensitive(finding.host, "hostname")
            print_info_debug(
                "[rdp-aardwolf] follow-up prompt suppressed: "
                f"user={marked_username} host={marked_host}"
            )

    return found_privileged_hosts
