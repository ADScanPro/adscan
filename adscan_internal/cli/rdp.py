"""RDP CLI orchestration helpers.

This module extracts RDP-related orchestration logic out of the monolithic
`adscan.py` so it can be reused by future UX layers while keeping runtime
behaviour stable for the current CLI.
"""

from __future__ import annotations

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
from adscan_internal.execution_outcomes import result_is_timeout
from adscan_internal.integrations.medusa import (
    MedusaContext,
    MedusaRunner,
    get_recommended_medusa_settings,
    parse_medusa_account_matches,
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
        print_info_verbose(f"[rdp] host-helper error: {exc}")
    except Exception as exc:
        telemetry.capture_exception(exc)
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
            print_info(
                "RDP session launched. Close the RDP window to end the session."
            )
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


def run_rdp_service_access_sweep_with_medusa(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    targets: str,
    prompt: bool = True,
    target_count: int = 1,
) -> bool:
    """Enumerate RDP access with Medusa.

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
    medusa_path = getattr(shell, "medusa_path", None) or shutil.which("medusa")
    if not medusa_path:
        print_error(
            "Medusa is not available. Rebuild the ADscan runtime image so the new RDP backend is installed."
        )
        return False

    workspace_cwd = (
        shell._get_workspace_cwd()  # type: ignore[attr-defined]
        if hasattr(shell, "_get_workspace_cwd")
        else getattr(shell, "current_workspace_dir", os.getcwd())
    )
    domains_dir = getattr(shell, "domains_dir", "domains")
    log_abs_path = os.path.join(
        workspace_cwd,
        "domains",
        domain,
        "rdp",
        f"{username}_privs_medusa.log",
    )
    os.makedirs(os.path.dirname(log_abs_path), exist_ok=True)

    settings = get_recommended_medusa_settings("rdp", target_count=target_count)
    use_ntlm_hash = bool(
        callable(getattr(shell, "is_hash", None)) and shell.is_hash(password)
    )
    module_arguments = [f"DOMAIN:{domain}"]
    if use_ntlm_hash:
        module_arguments.append("PASS:HASH")

    global_timeout = resolve_service_command_timeout_seconds(
        service="rdp",
        target_count=target_count,
        return_boolean=False,
    )
    context = MedusaContext(
        medusa_path=medusa_path,
        command_runner=lambda command, timeout: shell.run_command(
            command, timeout=timeout
        ),
    )
    runner = MedusaRunner()
    completed_process = runner.execute_login_sweep(
        ctx=context,
        protocol="rdp",
        targets=targets,
        username=username,
        password=password,
        settings=settings,
        log_file=log_abs_path,
        module_arguments=module_arguments,
        timeout=global_timeout,
    )

    marked_domain = mark_sensitive(domain, "domain")
    marked_username = mark_sensitive(username, "user")
    print_info_debug(
        "[rdp-medusa] dispatch: "
        f"domain={marked_domain} user={marked_username} targets={mark_sensitive(str(targets), 'path')} "
        f"auth_mode={'pass_the_hash' if use_ntlm_hash else 'password'} "
        f"threads={settings.total_logins} host_threads={settings.concurrent_hosts} "
        f"connect_timeout={settings.connect_timeout_seconds}s global_timeout={global_timeout}s"
    )
    if use_ntlm_hash:
        print_info(
            f"Using Medusa RDP pass-the-hash mode for user {marked_username}"
        )

    if completed_process is None:
        print_error("RDP enumeration failed before Medusa returned a result.")
        return False

    if result_is_timeout(completed_process, tool_name="medusa"):
        print_warning(
            "Medusa RDP enumeration ended due to timeout recovery being exhausted or declined."
        )
        return False

    combined_output = "\n".join(
        part for part in [completed_process.stdout or "", completed_process.stderr or ""] if part
    )
    findings = parse_medusa_account_matches(combined_output, protocol="rdp")
    if not findings and os.path.exists(log_abs_path):
        try:
            with open(log_abs_path, "r", encoding="utf-8", errors="ignore") as handle:
                findings = parse_medusa_account_matches(
                    handle.read(),
                    protocol="rdp",
                )
        except OSError:
            findings = []

    service_findings = [
        ServiceAccessFinding(
            service="rdp",
            host=str(finding.host).strip(),
            username=str(finding.username).strip(),
            category=finding.result_category,
            reason=finding.result_reason,
            status=str(finding.status).strip(),
            backend="medusa",
        )
        for finding in findings
    ]
    success_findings = [finding for finding in service_findings if finding.category == "confirmed"]
    render_service_access_results(
        service="rdp",
        username=username,
        findings=service_findings,
        total_targets=target_count,
    )
    category_counts = summarize_service_access_categories(service_findings)
    if category_counts["denied"] or category_counts["transport"] or category_counts["ambiguous"]:
        print_info_debug(
            "[rdp-medusa] unconfirmed result breakdown: "
            f"denied={category_counts['denied']} "
            f"transport={category_counts['transport']} "
            f"ambiguous={category_counts['ambiguous']}"
        )

    found_privileged_hosts = False
    for finding in success_findings:
        found_privileged_hosts = True
        host = finding.host
        try:
            from adscan_internal.services.attack_graph_service import (
                upsert_netexec_privilege_edge,
            )

            upsert_netexec_privilege_edge(
                shell,
                domain,
                username=finding.username,
                relation="CanRDP",
                target_ip=host,
                target_hostname=None,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)

    target_entries = (
        sorted(load_target_entries(targets))
        if os.path.isfile(targets)
        else [str(targets).strip()]
    )
    normalized_target_entries = {
        str(entry).strip().lower() for entry in target_entries if str(entry).strip()
    }
    confirmed_targets = [
        entry
        for entry in target_entries
        if str(entry).strip().lower()
        in {
            str(finding.host).strip().lower()
            for finding in success_findings
            if str(finding.host).strip()
        }
    ]
    if not confirmed_targets and len(normalized_target_entries) == 1 and success_findings:
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
            source="run_rdp_service_access_sweep_with_medusa",
            backend="medusa",
            pivot_capable=is_service_pivot_capable("rdp"),
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[rdp-medusa] failed to persist probe history: {exc}"
        )

    if prompt and success_findings:
        selected_followups, used_selector = select_confirmed_service_access_followup_targets(
            shell,
            service="rdp",
            findings=success_findings,
        )
        if used_selector:
            for finding in selected_followups:
                marked_host = mark_sensitive(finding.host, "hostname")
                print_info_debug(
                    "[rdp-medusa] launching selected follow-up: "
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
                    "[rdp-medusa] launching follow-up prompt: "
                    f"user={marked_username} host={marked_host}"
                )
                shell.ask_for_rdp_access(domain, finding.host, finding.username, password)
    elif not prompt:
        for finding in success_findings:
            marked_host = mark_sensitive(finding.host, "hostname")
            print_info_debug(
                "[rdp-medusa] follow-up prompt suppressed: "
                f"user={marked_username} host={marked_host}"
            )

    return found_privileged_hosts
