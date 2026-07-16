"""Docker runtime helpers for ADscan container mode.

This module provides a minimal, dependency-light wrapper around `docker` to:
  - detect whether docker requires sudo
  - pull/inspect images
  - run ADscan inside a container with the workspace mounted

It is intentionally self-contained so `adscan.py` can stay focused on CLI
orchestration and user experience.
"""

from __future__ import annotations

import os
import platform
import pty
import re
import shlex
import shutil
import subprocess
import sys
import time
from selectors import DefaultSelector, EVENT_READ
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Sequence

from adscan_core.version_context import RUNTIME_CONTRACT_VERSION
from adscan_launcher.docker_pull_diagnostics import (
    classify_pull_failure,
    record_last_failure,
    strip_ansi,
)
from adscan_launcher.output import (
    print_info_debug,
    print_panel,
    print_warning,
    print_warning_verbose,
    print_instruction,
)
from adscan_launcher.paths import get_state_dir


_DOCKER_PERMISSION_DENIED_RE = re.compile(
    r"permission denied.*docker\.sock|got permission denied", re.IGNORECASE
)
_DOCKER_PULL_DNS_FAILURE_RE = re.compile(
    # Registry-agnostic: matches ``lookup <any-host>: no such host`` (Docker Hub
    # ``registry-1.docker.io`` AND ``ghcr.io`` / private registries), plus the
    # generic resolver-failure strings Docker/Go surface.
    r"(lookup\s+\S+.*no such host|temporary failure in name resolution|server misbehaving)",
    re.IGNORECASE,
)
_DOCKER_PERMISSION_WARNING_SHOWN = False


_DOCKER_PULL_DNS_LOOKUP_HOST_RE = re.compile(
    r"lookup\s+(?P<host>[A-Za-z0-9._-]+)", re.IGNORECASE
)


def _extract_dns_failure_host(diagnostic: str) -> str | None:
    """Best-effort extraction of the registry host from a DNS-failure diagnostic.

    Docker/Go surface ``lookup <host>: no such host`` on resolution failure;
    the host is whichever registry the pull contacted (Docker Hub's
    ``registry-1.docker.io``, ``ghcr.io``, or a private registry). Returns the
    host so the guidance hint targets the right name, or ``None`` when the
    diagnostic does not name a host.
    """
    match = _DOCKER_PULL_DNS_LOOKUP_HOST_RE.search(diagnostic or "")
    if not match:
        return None
    host = match.group("host").strip().rstrip(".")
    return host or None


def _emit_pull_failure_dns_guidance(*, diagnostic: str) -> None:
    """Emit targeted guidance when docker pull fails due to DNS resolution."""
    if not _DOCKER_PULL_DNS_FAILURE_RE.search(diagnostic or ""):
        return
    resolved_host = _extract_dns_failure_host(diagnostic)
    print_warning("Docker registry DNS resolution failed while pulling images.")
    print_instruction("Verify host DNS settings and internet connectivity, then retry.")
    if resolved_host:
        print_instruction(
            f"If needed, test resolver health with: getent hosts {resolved_host}"
        )
    else:
        print_instruction(
            "If needed, test resolver health with: getent hosts <registry host>"
        )
    print_instruction(
        "If DNS is unstable, switch to a reliable resolver (for example 1.1.1.1 / 8.8.8.8)."
    )
    print_warning_verbose(
        "Pull failure diagnostic indicates name-resolution issues for the Docker registry."
    )


def docker_access_denied(diagnostic: str) -> bool:
    """Return True if diagnostic indicates lack of permissions to docker.sock.

    Args:
        diagnostic: Error message or diagnostic output from docker command

    Returns:
        True if the diagnostic indicates permission denied for docker.sock
    """
    lowered = (diagnostic or "").lower()
    return "permission denied" in lowered and "docker.sock" in lowered


_HOST_TELEMETRY_ID_ENV = "ADSCAN_TELEMETRY_ID"
_HOST_DISTRO_ID_ENV = "ADSCAN_HOST_DISTRO_ID"
_HOST_DISTRO_VERSION_ENV = "ADSCAN_HOST_DISTRO_VERSION"
_HOST_DISTRO_LIKE_ENV = "ADSCAN_HOST_DISTRO_LIKE"
_DOCKER_GUI_ENV = "ADSCAN_DOCKER_GUI"
_X11_SOCKET_DIR_ENV = "ADSCAN_X11_SOCKET_DIR"


def _get_host_x11_socket_dir() -> Path:
    """Return the host X11 unix socket directory (best effort).

    This is intentionally configurable to make CI/tests deterministic.
    """
    return Path(os.environ.get(_X11_SOCKET_DIR_ENV, "/tmp/.X11-unix"))


def _get_host_xauthority_file() -> Path | None:
    """Return the host Xauthority file if present."""
    candidates: list[Path] = []
    xauth = os.environ.get("XAUTHORITY", "").strip()
    if xauth:
        candidates.append(Path(xauth))
    candidates.append(_get_effective_home() / ".Xauthority")
    for candidate in candidates:
        try:
            if candidate.is_file():
                return candidate
        except OSError:
            continue
    return None


def _host_uses_network_host() -> bool:
    """Return True when the host should run the container with ``--network host``.

    ``--network host`` shares the host network namespace directly, which is the
    right default on Linux (routed scanning, broadcast poisoning, and the
    in-container resolver all bind on host interfaces).

    On macOS (Darwin), Docker Desktop runs every container inside a Linux VM, so
    ``--network host`` shares the *VM's* network, not the Mac's — it silently
    breaks anything that expects the host interface. There we fall back to
    bridge/NAT networking (see ``build_adscan_run_command``), which still routes
    outbound traffic to a reachable AD target; only host-Layer-2 features
    (broadcast poisoning) are lost, and those cannot work on Docker Desktop
    regardless. This is the single decision point for the mode — do not scatter
    per-platform checks at call sites.
    """
    return str(platform.system() or "").strip().lower() != "darwin"


@dataclass(frozen=True)
class DockerRunConfig:
    """Configuration for running ADscan in a Docker container."""

    image: str
    workspaces_host_dir: Path
    # Match the in-container ADSCAN_HOME used by the FULL image.
    # This keeps workspaces persistent on the host without requiring any
    # container-side code changes.
    workspaces_container_dir: str = "/opt/adscan/workspaces"
    # Default is platform-aware: True (--network host) on Linux, False
    # (bridge/NAT) on macOS Docker Desktop. Centralized in
    # ``_host_uses_network_host`` so every call site inherits the correct mode
    # without passing the flag explicitly.
    network_host: bool = field(default_factory=_host_uses_network_host)
    interactive: bool = True
    remove: bool = True
    run_as_current_user: bool = True
    extra_run_args: tuple[str, ...] = ()
    # Extra environment variables to pass into the container via `-e KEY=VALUE`.
    # This is preferred over mutating `os.environ` at call sites.
    extra_env: tuple[tuple[str, str], ...] = ()
    # Extra read-only host file bind-mounts as ``(host_path, container_path)``
    # pairs, rendered as ``-v <host>:<container>:ro``. Used to expose a host
    # file the container must read but that lives outside the standard mounted
    # tree (e.g. a ``--scan-config`` file passed by absolute path).
    extra_mounts: tuple[tuple[str, str], ...] = ()
    # Host directory bind-mounted into the container at /run/adscan. When
    # None, defaults to ``workspaces_host_dir.parent / "run"`` for backwards
    # compatibility. Per-launcher session directories live under
    # ``run/sessions/<token>/`` and are passed in here so two launchers do
    # not share the same host-helper socket path.
    run_host_dir: Path | None = None


def _get_effective_home() -> Path:
    """Return the current user's home directory (best effort)."""
    try:
        return Path.home()
    except Exception:
        return Path(os.getenv("HOME", "/"))


def _build_sudo_env() -> dict[str, str]:
    """Build an env dict to avoid /root HOME leakage when using sudo docker."""
    env = os.environ.copy()
    env["HOME"] = str(_get_effective_home())
    env.setdefault("XDG_CONFIG_HOME", str(_get_effective_home() / ".config"))
    return env


def docker_available() -> bool:
    """Return True if docker is available in PATH."""
    return bool(shutil.which("docker"))


def is_docker_env() -> bool:
    """Return True when running inside a Docker/container environment.

    This is used in host-side docker orchestration code to avoid attempting
    Docker-in-Docker operations and to enrich telemetry with a reliable flag.

    Detection is best-effort and intentionally lightweight:
    - explicit ADSCAN container runtime marker
    - /.dockerenv marker
    - /proc/1/cgroup hints (docker/containerd/kubepods)
    """
    if os.environ.get("ADSCAN_CONTAINER_RUNTIME") == "1":
        return True
    try:
        if Path("/.dockerenv").exists():
            return True
    except OSError:
        pass
    try:
        cgroup = Path("/proc/1/cgroup")
        if cgroup.is_file():
            text = cgroup.read_text(encoding="utf-8", errors="ignore")
            lowered = text.lower()
            return any(
                token in lowered for token in ("docker", "containerd", "kubepods")
            )
    except OSError:
        pass
    return False


def docker_needs_sudo(timeout: int = 5) -> bool:
    """Best-effort detection for whether docker commands require sudo."""
    if not docker_available():
        return False
    try:
        proc = subprocess.run(
            ["docker", "ps"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except Exception:  # pragma: no cover
        return False
    diagnostic = (proc.stderr or "") + "\n" + (proc.stdout or "")
    return bool(_DOCKER_PERMISSION_DENIED_RE.search(diagnostic))


# One-shot hook fired immediately before the launcher hands the
# terminal to a containerised process via ``docker run``. The launcher
# session-capture flow uses it to flush the ``launcher_preflight`` Rich
# recording at the exact handoff moment, instead of waiting for the
# container (which may run for hours) to exit. See
# ``_run_host_command_with_session_capture`` in adscan_launcher/cli.py.
#
# Contract:
#   * One-shot: cleared as soon as it fires so a single launcher
#     invocation cannot accidentally double-send the session.
#   * Best-effort: exceptions are swallowed — the hook must never block
#     the real ``docker run`` from happening.
#   * Only fires for ``docker run`` (the actual container exec).
#     ``docker info``, ``docker pull``, ``docker image inspect`` etc.
#     are launcher-only operations and don't trigger the hook.
_pre_container_exec_hook: Callable[[], None] | None = None


def register_pre_container_exec_hook(hook: Callable[[], None] | None) -> None:
    """Install (or clear) the pre-``docker run`` flush hook."""
    global _pre_container_exec_hook  # pylint: disable=global-statement
    _pre_container_exec_hook = hook


def _is_container_exec_argv(argv: Sequence[str]) -> bool:
    """Return True when ``argv`` is a ``docker run`` invocation.

    Recognises both the bare ``["docker", "run", …]`` form and the
    sudo-prefixed ``["sudo", …, "docker", "run", …]`` form that
    ``run_docker`` produces when the daemon socket is root-owned.
    """
    items = list(argv)
    for idx, value in enumerate(items):
        if value == "docker" and idx + 1 < len(items) and items[idx + 1] == "run":
            return True
    return False


def _fire_pre_container_exec_hook(argv: Sequence[str]) -> None:
    """Invoke and clear the pre-``docker run`` hook, once, best-effort."""
    if not _is_container_exec_argv(argv):
        return
    global _pre_container_exec_hook  # pylint: disable=global-statement
    hook = _pre_container_exec_hook
    if hook is None:
        return
    _pre_container_exec_hook = None  # one-shot guard before invoke
    try:
        # ``hook`` is guaranteed non-None here by the early-return above,
        # but pylint's type narrowing from ``is None`` checks is unreliable
        # for module-level Optional vars — silence the false positive
        # rather than complicate the runtime path.
        hook()  # pylint: disable=not-callable
    except Exception as exc:  # noqa: BLE001
        print_info_debug(
            f"[docker] pre-container-exec hook failed: "
            f"{type(exc).__name__}: {exc}"
        )


def run_docker(
    argv: Sequence[str],
    *,
    check: bool,
    capture_output: bool,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run docker, using sudo when required."""
    if not docker_available():
        raise FileNotFoundError("docker not found in PATH")

    global _DOCKER_PERMISSION_WARNING_SHOWN  # pylint: disable=global-statement
    needs_sudo = docker_needs_sudo()
    cmd = list(argv)
    env: dict[str, str] | None = None
    if needs_sudo and os.geteuid() != 0:
        if not _DOCKER_PERMISSION_WARNING_SHOWN:
            print_warning_verbose(
                "Docker daemon requires sudo; using sudo for docker commands."
            )
            _DOCKER_PERMISSION_WARNING_SHOWN = True
        env = _build_sudo_env()
        preserve_env = (
            "HOME,XDG_CONFIG_HOME,ADSCAN_HOME,ADSCAN_SESSION_ENV,CI,GITHUB_ACTIONS"
        )
        cmd = ["sudo", f"--preserve-env={preserve_env}"] + cmd

    # Important: for interactive `docker run -it`, avoid forcing text mode or
    # capturing output. Let Docker inherit the real TTY so interactive UIs
    # (questionary/prompt_toolkit) behave correctly.
    if capture_output:
        _fire_pre_container_exec_hook(cmd)
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=check,
            env=env,
        )
        if not _DOCKER_PERMISSION_WARNING_SHOWN and docker_access_denied(
            (proc.stderr or "") + (proc.stdout or "")
        ):
            print_warning(
                "Docker permissions are missing; add your user to the docker group "
                "or run with sudo."
            )
            _DOCKER_PERMISSION_WARNING_SHOWN = True
        return proc

    _fire_pre_container_exec_hook(cmd)
    return subprocess.run(  # noqa: S603
        cmd,
        timeout=timeout,
        check=check,
        env=env,
    )


def run_docker_command(
    command: str | Sequence[str],
    *,
    shell: bool = False,
    check: bool = True,
    capture_output: bool | None = None,
    text: bool = True,
    timeout: int | None = None,
    run_command_func: Callable[..., subprocess.CompletedProcess] | None = None,
    sudo_validate_func: Callable[[], bool] | None = None,
    build_effective_user_env_func: Callable[..., dict[str, str]] | None = None,
    sudo_preserve_env_keys: tuple[str, ...] | None = None,
    sudo_prefix_args_func: Callable[[], list[str]] | None = None,
) -> subprocess.CompletedProcess:
    """Run a docker command, automatically using sudo when needed.

    This is a compatibility wrapper that can use either the simpler `run_docker()`
    function when possible, or fall back to a more complex `run_command` function
    when shell mode or other advanced features are needed.

    Args:
        command: Docker command as string or list of arguments
        shell: Whether to run command in shell mode
        check: Whether to raise on non-zero exit code
        capture_output: Whether to capture stdout/stderr (None = auto-detect)
        text: Whether to return text output (default: True)
        timeout: Command timeout in seconds
        run_command_func: Optional function to run commands (for shell mode/complex cases)
        sudo_validate_func: Optional function to validate sudo access
        build_effective_user_env_func: Optional function to build effective user env
        sudo_preserve_env_keys: Optional tuple of env keys to preserve with sudo
        sudo_prefix_args_func: Optional function to get sudo prefix arguments

    Returns:
        CompletedProcess from subprocess execution

    Raises:
        RuntimeError: If sudo validation fails when sudo is required
        FileNotFoundError: If docker is not available
    """
    if not docker_available():
        raise FileNotFoundError("docker not found in PATH")

    # For simple non-shell cases, use the existing run_docker() function
    if not shell and isinstance(command, (list, tuple)):
        # Convert to list if needed
        argv = list(command)
        # Use run_docker() which handles sudo automatically
        cap_output = capture_output if capture_output is not None else (check or False)
        return run_docker(
            argv,
            check=check,
            capture_output=cap_output,
            timeout=timeout,
        )

    # For shell mode or string commands, use run_command_func if provided
    if run_command_func is None:
        raise ValueError(
            "run_command_func is required for shell mode or string commands"
        )

    # Check if sudo is needed
    needs_sudo = docker_needs_sudo()
    if needs_sudo and os.geteuid() != 0:
        if sudo_validate_func and not sudo_validate_func():
            raise RuntimeError("sudo validation failed for docker command")

        # Build command with sudo
        if shell:
            if not isinstance(command, str):
                raise TypeError("shell=True requires command to be a string")
            if sudo_preserve_env_keys:
                preserve_env = ",".join(sudo_preserve_env_keys)
                command = f"sudo --preserve-env={preserve_env} {command}"
            else:
                command = f"sudo {command}"
        else:
            if isinstance(command, str):
                argv = shlex.split(command)
            else:
                argv = list(command)
            if sudo_prefix_args_func:
                command = sudo_prefix_args_func() + argv
            else:
                command = ["sudo"] + argv

        # Build environment if needed
        cmd_env: dict[str, str] | None = None
        if build_effective_user_env_func:
            cmd_env = build_effective_user_env_func(command, shell=shell)
    else:
        cmd_env = None

    # Use run_command_func for execution
    # When check=True, run_command typically defaults capture_output=True
    # Allow callers to override via capture_output to avoid hiding sudo prompts
    return run_command_func(
        command,
        shell=shell,
        check=check,
        capture_output=capture_output,
        text=text,
        timeout=timeout,
        env=cmd_env,
    )


def run_docker_stream(
    argv: Sequence[str],
    *,
    timeout: int | None = None,
    capture_limit_bytes: int = 200_000,
) -> tuple[int, str, str]:
    """Run docker while streaming stdout/stderr to the terminal.

    This is primarily used for long-running pulls so users can see progress in
    real-time (including Docker's progress UI when a TTY is available).

    Returns:
        (returncode, stdout_tail, stderr_tail)
    """
    if not docker_available():
        raise FileNotFoundError("docker not found in PATH")

    needs_sudo = docker_needs_sudo()
    cmd = list(argv)
    env: dict[str, str] | None = None
    if needs_sudo and os.geteuid() != 0:
        env = _build_sudo_env()
        preserve_env = (
            "HOME,XDG_CONFIG_HOME,ADSCAN_HOME,ADSCAN_SESSION_ENV,CI,GITHUB_ACTIONS"
        )
        cmd = ["sudo", f"--preserve-env={preserve_env}"] + cmd

    use_pty = bool(sys.stdout.isatty() and sys.stdin.isatty() and not os.getenv("CI"))
    _fire_pre_container_exec_hook(cmd)
    if use_pty:
        # If we pipe stdout/stderr, Docker disables its rich progress UI because it
        # thinks it's not attached to a TTY. Use a PTY in interactive sessions so
        # users see Docker's native progress rendering.
        master_fd, slave_fd = pty.openpty()
        proc = subprocess.Popen(  # noqa: S603
            cmd,
            stdout=slave_fd,
            stderr=slave_fd,
            env=env,
            close_fds=True,
        )
        try:
            os.close(slave_fd)
        except OSError:
            pass
    else:
        master_fd = None
        proc = subprocess.Popen(  # noqa: S603
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
        )

    stdout_tail = bytearray()
    stderr_tail = bytearray()

    def _append_tail(buf: bytearray, chunk: bytes) -> None:
        if capture_limit_bytes <= 0:
            return
        buf.extend(chunk)
        if len(buf) > capture_limit_bytes:
            del buf[: len(buf) - capture_limit_bytes]

    selector = DefaultSelector()
    stdout = proc.stdout
    stderr = proc.stderr
    if master_fd is not None:
        selector.register(master_fd, EVENT_READ, data="pty")
    else:
        assert stdout is not None
        assert stderr is not None
        selector.register(stdout, EVENT_READ, data="stdout")
        selector.register(stderr, EVENT_READ, data="stderr")

    start = time.monotonic()
    deadline = None if timeout is None else (start + timeout)

    try:
        while True:
            if deadline is not None and time.monotonic() >= deadline:
                proc.kill()
                break

            events = selector.select(timeout=0.25)
            for key, _ in events:
                stream_name: str = key.data
                fileobj = key.fileobj
                try:
                    if master_fd is not None:
                        chunk = os.read(int(fileobj), 4096)
                    else:
                        chunk = os.read(fileobj.fileno(), 4096)
                except OSError:
                    chunk = b""

                if not chunk:
                    try:
                        selector.unregister(fileobj)
                    except Exception:
                        pass
                    try:
                        if hasattr(fileobj, "close"):
                            fileobj.close()
                    except Exception:
                        pass
                    continue

                if stream_name == "stdout":
                    _append_tail(stdout_tail, chunk)
                    sys.stdout.buffer.write(chunk)
                    sys.stdout.buffer.flush()
                elif stream_name == "stderr":
                    _append_tail(stderr_tail, chunk)
                    sys.stderr.buffer.write(chunk)
                    sys.stderr.buffer.flush()
                else:
                    # PTY combined stream: keep tail in stdout bucket.
                    _append_tail(stdout_tail, chunk)
                    sys.stdout.buffer.write(chunk)
                    sys.stdout.buffer.flush()

            if proc.poll() is not None and not selector.get_map():
                break
    finally:
        try:
            selector.close()
        except Exception:
            pass
        if master_fd is not None:
            try:
                os.close(master_fd)
            except OSError:
                pass

    # Ensure process is reaped.
    try:
        rc = proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        rc = proc.wait(timeout=5)

    return (
        int(rc),
        stdout_tail.decode("utf-8", errors="replace"),
        stderr_tail.decode("utf-8", errors="replace"),
    )


def _handle_pull_failure(
    *,
    image: str,
    rc: int,
    stdout: str,
    stderr: str,
    timeout: int | None,
    surface_failure: bool,
) -> None:
    """Classify a docker pull failure and route side-effects.

    Three jobs:
    1. Strip ANSI so telemetry / debug logs are readable.
    2. Classify the failure and record it for the higher-level panel
       renderer to consume (``consume_last_failure`` in
       ``docker_pull_diagnostics``).
    3. Emit a compact debug-level log of the cleaned tail (no raw ANSI
       dump to the user — that lives in the premium panel rendered later).

    The DNS-specific guidance and the timeout warning are gated by
    ``surface_failure``. The multi-attempt retry loop in
    ``_ensure_image_pulled_with_legacy_fallback`` passes ``False`` for
    intermediate attempts so the user only sees one coherent message
    per outcome (retrying / recovered / permanently failed) instead of
    a noisy chain of partial failures and warnings.
    """
    clean_stderr = strip_ansi(stderr or "")
    clean_stdout = strip_ansi(stdout or "")
    diagnosis = classify_pull_failure(clean_stderr, clean_stdout)
    record_last_failure(diagnosis)
    timed_out = bool(timeout is not None and rc == -9)
    if timed_out and surface_failure:
        print_warning(
            f"Docker image pull did not finish within {timeout}s and was aborted."
        )
    evidence_blob = "; ".join(diagnosis.evidence) if diagnosis.evidence else "(no tail)"
    print_info_debug(
        f"[docker] pull failed: image={image} rc={rc} kind={diagnosis.kind} "
        f"rate_limit_likely={diagnosis.rate_limit_likely} "
        f"surface={surface_failure} tail={evidence_blob!r}"
    )
    if surface_failure:
        _emit_pull_failure_dns_guidance(diagnostic=f"{clean_stderr}\n{clean_stdout}")


def ensure_image_pulled(
    image: str,
    *,
    timeout: int | None = None,
    stream_output: bool = False,
    surface_failure: bool = True,
) -> bool:
    """Ensure a docker image exists locally (pull if needed).

    Args:
        image: Docker image reference to pull.
        timeout: Hard ceiling in seconds. ``None`` disables it.
        stream_output: When True, the underlying ``docker pull`` streams
            to the terminal directly (progress bar visible). When False,
            stdout/stderr are captured for diagnostics.
        surface_failure: When True (default), a failed pull emits
            user-visible guidance (DNS hints, timeout warning) in
            addition to recording the diagnosis. The retry loop sets
            this to False on intermediate attempts so only the final
            outcome reaches the user — see ``_handle_pull_failure``.
            The diagnosis is always recorded regardless, so the eventual
            failure panel still has full context.
    """
    if not docker_available():
        return False
    # Pull is idempotent and simplest.
    if stream_output:
        rc, stdout, stderr = run_docker_stream(
            ["docker", "pull", image], timeout=timeout
        )
        if rc == 0:
            return True
        _handle_pull_failure(
            image=image,
            rc=rc,
            stdout=stdout,
            stderr=stderr,
            timeout=timeout,
            surface_failure=surface_failure,
        )
        return False

    proc = run_docker(
        ["docker", "pull", image], check=False, capture_output=True, timeout=timeout
    )
    if proc.returncode == 0:
        return True
    _handle_pull_failure(
        image=image,
        rc=int(proc.returncode),
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
        timeout=timeout,
        surface_failure=surface_failure,
    )
    return False


def image_exists(image: str) -> bool:
    """Return True if the docker image exists locally."""
    if not docker_available():
        return False
    proc = run_docker(
        ["docker", "image", "inspect", image],
        check=False,
        capture_output=True,
        timeout=10,
    )
    return proc.returncode == 0


def _read_host_machine_id() -> str | None:
    """Return host machine-id (best effort) for container env propagation."""
    try:
        machine_id = Path("/etc/machine-id")
        if not machine_id.is_file():
            return None
        raw = machine_id.read_text(encoding="utf-8", errors="ignore").strip()
        if not raw:
            return None
        return raw
    except Exception:
        return None


def _compute_host_telemetry_id() -> str | None:
    """Compute a stable host telemetry id for container execution.

    This prevents container runs from deriving telemetry identity from the
    container's `/etc/machine-id` (which is not the host's) or from a
    non-persistent in-container ADSCAN_HOME.

    Returns:
        A short, stable hash string or None if it cannot be derived.
    """
    try:
        raw = _read_host_machine_id()
        if not raw:
            return None
        import hashlib

        return hashlib.sha256(raw.encode()).hexdigest()[:12]
    except Exception:
        return None


def _collect_host_distro_context() -> dict[str, str]:
    """Collect host distro metadata from /etc/os-release (best effort)."""
    try:
        os_release_path = Path("/etc/os-release")
        if not os_release_path.is_file():
            return {}
        data: dict[str, str] = {}
        for line in os_release_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or "=" not in line:
                continue
            key, value = line.split("=", 1)
            data[key] = value.strip().strip('"').strip("'")
        context: dict[str, str] = {}
        if data.get("ID"):
            context["distro_id"] = str(data["ID"]).strip()
        if data.get("VERSION_ID"):
            context["distro_version"] = str(data["VERSION_ID"]).strip()
        if data.get("ID_LIKE"):
            context["distro_like"] = str(data["ID_LIKE"]).strip()
        return {k: v for k, v in context.items() if v}
    except Exception:
        return {}


def _make_docker_accessible_url(url: str) -> str:
    """Rewrite a Redis URL so it is reachable from inside a Docker container.

    Docker containers cannot reach the host via ``localhost`` or ``127.0.0.1``.
    This helper replaces those hostnames with ``host-gateway``, which Docker
    resolves to the host's bridge IP when ``--add-host=host-gateway:host-gateway``
    is passed to ``docker run``.

    Args:
        url: Original Redis URL (e.g. ``redis://localhost:6379/0``).

    Returns:
        URL with ``localhost``/``127.0.0.1`` replaced by ``host-gateway``,
        or the original URL unchanged if no replacement is needed.
    """
    import re

    return re.sub(
        r"(?<=[/@:])(?:localhost|127\.0\.0\.1)(?=[:/]|$)",
        "host-gateway",
        url,
    )


def _render_reduced_runtime_panel(verdict) -> None:
    """Render the premium 'reduced network mode' notice for a rootless runtime."""
    ipv6_ok = bool(getattr(verdict, "net_raw", False))
    tun_ok = bool(getattr(verdict, "net_admin", False))
    ok = "[status.success]✓[/status.success]"
    warn = "[status.warning]⚠[/status.warning]"
    rows = [
        f"  {ok}  Core assessment    LDAP · SMB · Kerberos · RPC · attack paths",
        f"  {ok}  Recon              port / service discovery (TCP connect)",
        f"  {ok if ipv6_ok else warn}  IPv6 poisoning     "
        + ("available" if ipv6_ok else "mitm6 (DHCPv6/RA) — requires NET_RAW"),
        f"  {ok if tun_ok else warn}  Tunnel pivoting    "
        + ("available" if tun_ok else "ligolo-ng TUN — requires NET_ADMIN"),
    ]
    body = (
        "Rootless / user-namespaced runtime detected (rootless Docker or Podman). "
        "The full AD assessment runs normally — the optional offensive extras "
        "below are unavailable in this runtime.\n\n"
        + "\n".join(rows)
        + "\n\n[bold]Full features[/bold] → run on a standard (rootful) Docker daemon.\n"
        "                no sudo: add your user to the [bold]docker[/bold] group."
    )
    print_panel(
        body,
        title="⚠  Reduced Network Mode · rootless container runtime",
        title_align="left",
        border_style="status.warning",
    )


def probe_and_warn_reduced_runtime(cfg: DockerRunConfig) -> None:
    """Detect a rootless / user-namespaced runtime and warn (NON-blocking).

    ADscan still runs — the entrypoint strips the file capabilities so the
    binaries can exec — but in reduced network mode (core assessment unaffected;
    ICMP discovery and ligolo TUN pivoting unavailable). Surfacing a clear panel
    here replaces the cryptic kernel "Operation not permitted" the operator would
    otherwise hit, and points at the real fix (rootful daemon / 'docker' group).

    Best-effort and fail-open: any probe failure is swallowed so a flaky daemon
    never blocks the run. The image must already be present (pulled in preflight).
    """
    try:
        from adscan_launcher.runtime_capability_check import (  # noqa: PLC0415
            probe_runtime_capability,
        )

        cap_add = ["SYS_TIME"]
        if Path("/dev/net/tun").exists():
            cap_add.append("NET_ADMIN")
        verdict = probe_runtime_capability(
            image=cfg.image,
            uid=os.getuid(),
            gid=os.getgid(),
            cap_add=tuple(cap_add),
        )
        if not verdict.probe_ok:
            return  # inconclusive — say nothing (fail-open)
        if verdict.supported and not verdict.degraded:
            return  # full capabilities — nothing to warn about
        print_info_debug(
            "[docker] reduced-runtime verdict: "
            f"supported={verdict.supported} degraded={verdict.degraded} "
            f"userns_remapped={verdict.userns_remapped} "
            f"net_raw={verdict.net_raw} net_admin={verdict.net_admin}"
        )
        _render_reduced_runtime_panel(verdict)
    except Exception as exc:  # noqa: BLE001 — never block the run on a probe error
        try:
            from adscan_core import telemetry  # noqa: PLC0415

            telemetry.capture_exception(exc)
        except Exception:  # noqa: BLE001
            pass


def build_adscan_run_command(
    cfg: DockerRunConfig,
    *,
    adscan_args: Sequence[str],
) -> list[str]:
    """Build docker run argv for running ADscan inside the container."""
    cmd: list[str] = ["docker", "run"]
    # Track whether ``--add-host host-gateway:host-gateway`` has been added so the
    # bridge-networking default and the Redis interactive-bridge block below do
    # not emit it twice.
    host_gateway_added = False
    if cfg.remove:
        cmd.append("--rm")
    if cfg.interactive:
        cmd.extend(["-it"])
    if cfg.network_host:
        cmd.extend(["--network", "host"])
    else:
        # Bridge/NAT networking (macOS Docker Desktop default: --network host only
        # shares the Linux VM's network, not the Mac host's). Outbound routed
        # scanning to the DC works over NAT; expose host-gateway so localhost/
        # 127.0.0.1 rewrites resolve to the host bridge IP.
        cmd.extend(["--add-host", "host-gateway:host-gateway"])
        host_gateway_added = True
    # Allow the container to adjust the host clock when needed for Kerberos.
    # This is intentionally narrower than `--privileged` but still grants the
    # ability to change the system time (CAP_SYS_TIME).
    cmd.extend(["--cap-add", "SYS_TIME"])
    # Coercion-based NTLM capture / relay listeners (NTLM auth-type sweep, ESC8
    # relay) bind PRIVILEGED ports inbound (SMB 445, HTTP 80, LDAP 389). The
    # runtime runs as a non-root --user, so without this it gets EACCES binding
    # <1024 and those features skip with "listener failed to start". CAP_NET_BIND_
    # SERVICE is the minimal capability for this (far narrower than --privileged);
    # Docker 20.10+ also propagates --cap-add to the ambient set so the non-root
    # user can actually use it. --sysctl net.ipv4.ip_unprivileged_port_start is
    # NOT an option here because the runtime uses --network host, which forbids
    # namespaced net sysctls.
    cmd.extend(["--cap-add", "NET_BIND_SERVICE"])
    host_tun_device = Path("/dev/net/tun")
    if host_tun_device.exists():
        cmd.extend(["--cap-add", "NET_ADMIN"])
        cmd.extend(["--device", f"{host_tun_device}:{host_tun_device}"])
        print_info_debug(
            "[docker] enabling ligolo TUN support: "
            "--cap-add NET_ADMIN --device /dev/net/tun"
        )
    else:
        print_info_debug(
            "[docker] host /dev/net/tun not available; ligolo TUN support disabled"
        )
    if cfg.extra_run_args:
        cmd.extend(list(cfg.extra_run_args))

    # Mount host-persisted directories.
    #
    # - workspaces/logs are large and are expected to persist across runs.
    # - .config persists generic local tool configuration across runs.
    # - .codex-container persists Codex CLI OAuth/session state for ADscan only.
    #   This intentionally avoids touching the host user's ~/.codex.
    # - run is a transient runtime directory for host<->container helpers.
    # - state stores small, non-sensitive markers/state that should persist
    #   across container runs (e.g., first-run marker, telemetry toggle state).
    config_host_dir = cfg.workspaces_host_dir.parent / ".config"
    codex_host_dir = cfg.workspaces_host_dir.parent / ".codex-container"
    logs_host_dir = cfg.workspaces_host_dir.parent / "logs"
    run_host_dir = cfg.run_host_dir or (cfg.workspaces_host_dir.parent / "run")
    state_host_dir = cfg.workspaces_host_dir.parent / "state"
    # ``bonuses/`` holds the standalone deliverable PDFs produced by
    # ``adscan cheatsheet`` and the LITE-tier kit fast-path. Without a host
    # bind-mount these end up inside the container's ephemeral layer and
    # disappear when the container exits — the operator runs the command,
    # sees ``Wrote N bytes to ~/.adscan/bonuses/...``, then finds nothing
    # on the host. Mounting it as a sibling of ``workspaces/`` makes the
    # artefact persist (and keeps the host helper's `open_file` route
    # honest: the path it receives actually exists on disk).
    bonuses_host_dir = cfg.workspaces_host_dir.parent / "bonuses"
    bonuses_host_dir.mkdir(parents=True, exist_ok=True)
    cmd.extend(
        [
            "--mount",
            (
                "type=bind,"
                f"src={cfg.workspaces_host_dir},"
                f"dst={cfg.workspaces_container_dir},"
                "bind-propagation=rshared"
            ),
            "-v",
            f"{config_host_dir}:/opt/adscan/.config",
            "-v",
            f"{codex_host_dir}:/opt/adscan/.codex",
            "-v",
            f"{logs_host_dir}:/opt/adscan/logs",
            "-v",
            f"{run_host_dir}:/run/adscan",
            "-v",
            f"{state_host_dir}:/opt/adscan/state",
            "-v",
            f"{bonuses_host_dir}:/opt/adscan/bonuses",
        ]
    )

    # If the host uses systemd-resolved, mount its resolver files into the
    # container so the entrypoint can discover upstream DNS servers.
    for resolved_path in (
        Path("/run/systemd/resolve/resolv.conf"),
        Path("/run/systemd/resolve/stub-resolv.conf"),
    ):
        try:
            if resolved_path.is_file():
                cmd.extend(["-v", f"{resolved_path}:{resolved_path}:ro"])
                print_info_debug(
                    f"[docker] mounting host resolver file: {resolved_path}"
                )
        except OSError:
            continue

    # Extra read-only host file mounts (e.g. a --scan-config file passed by
    # absolute path that lives outside the standard mounted tree).
    for host_path, container_path in cfg.extra_mounts:
        if host_path and container_path:
            cmd.extend(["-v", f"{host_path}:{container_path}:ro"])
            print_info_debug(
                f"[docker] mounting host file read-only: {host_path} -> {container_path}"
            )

    # Default to running as the current user to avoid root-owned files in the host mount.
    if cfg.run_as_current_user:
        # The container entrypoint starts as root, fixes mount ownership, then
        # drops privileges to the host UID/GID via gosu.
        cmd.extend(["-e", f"ADSCAN_UID={os.getuid()}"])
        cmd.extend(["-e", f"ADSCAN_GID={os.getgid()}"])

    for key, value in cfg.extra_env:
        if key and value:
            cmd.extend(["-e", f"{key}={value}"])

    # Let the container know where workspaces live.
    cmd.extend(["-e", f"ADSCAN_WORKSPACES_DIR={cfg.workspaces_container_dir}"])
    # Ensure the container has a stable, writable ADSCAN_HOME independent of the host.
    # The FULL image pre-provisions tools under /opt/adscan and keeps it world-writable
    # so `--user <uid>:<gid>` works for any host user.
    cmd.extend(
        [
            "-e",
            "ADSCAN_HOME=/opt/adscan",
            "-e",
            "HOME=/opt/adscan",
            "-e",
            "XDG_CONFIG_HOME=/opt/adscan/.config",
            "-e",
            "XDG_CACHE_HOME=/opt/adscan/.cache",
            "-e",
            "ADSCAN_STATE_DIR=/opt/adscan/state",
            "-e",
            "ADSCAN_CONTAINER_RUNTIME=1",
            "-e",
            "ADSCAN_OFFICIAL_LAUNCHER=1",
            "-e",
            f"ADSCAN_LAUNCHER_RUNTIME_CONTRACT_VERSION={RUNTIME_CONTRACT_VERSION}",
            "-e",
            f"ADSCAN_RUNTIME_IMAGE={cfg.image}",
            "-e",
            "ADSCAN_HOST_HELPER_SOCK=/run/adscan/host-helper.sock",
        ]
    )

    # Forward debug / instrumentation env vars from host to container when
    # the operator has set them. Without this, an ``ADSCAN_NO_LIVE=1`` on
    # the host shell never reaches the runtime that actually owns the
    # Rich Live surfaces, so the toggle is silently a no-op. Each var is
    # opt-in (only forwarded when explicitly set) so the default runtime
    # behaviour is unchanged.
    _OPT_FORWARD_ENV_VARS = (
        "ADSCAN_NO_LIVE",            # disable LiveSession (probe / dashboards)
        "ADSCAN_TELEMETRY_TRACE",    # extra telemetry diagnostics (chunks, etc.)
        "ADSCAN_NO_POSTURE_PROBE",   # skip proactive posture probe phase
        "ADSCAN_DIAG_RICH",          # rich_output diagnostic stderr trace
    )
    for _name in _OPT_FORWARD_ENV_VARS:
        _value = os.environ.get(_name)
        if _value is not None and _value != "":
            cmd.extend(["-e", f"{_name}={_value}"])

    # Optional GUI passthrough (X11) for interactive desktop features (e.g., xfreerdp).
    #
    # Default behavior:
    # - If ADSCAN_DOCKER_GUI is unset, enable passthrough automatically when running
    #   interactively on a host with a GUI session (DISPLAY + /tmp/.X11-unix).
    # - If ADSCAN_DOCKER_GUI=1, force enable.
    # - If ADSCAN_DOCKER_GUI=0, disable.
    gui_flag = os.environ.get(_DOCKER_GUI_ENV, "").strip().lower()
    if gui_flag in {"0", "false", "no", "off"}:
        gui_enabled = False
    elif gui_flag in {"1", "true", "yes", "on"}:
        gui_enabled = True
    else:
        display = os.environ.get("DISPLAY", "").strip()
        try:
            gui_enabled = bool(
                cfg.interactive and display and _get_host_x11_socket_dir().exists()
            )
        except OSError:
            gui_enabled = False

    if gui_enabled:
        display = os.environ.get("DISPLAY", "").strip()
        if display:
            x11_socket_dir = _get_host_x11_socket_dir()
            try:
                x11_available = x11_socket_dir.exists()
            except OSError:
                x11_available = False
            if x11_available:
                print_info_debug("[docker] enabling X11 GUI passthrough")
                cmd.extend(["-e", f"DISPLAY={display}"])
                cmd.extend(["-v", f"{x11_socket_dir}:/tmp/.X11-unix"])
                xauth_file = _get_host_xauthority_file()
                if xauth_file:
                    cmd.extend(["-e", "XAUTHORITY=/opt/adscan/.Xauthority"])
                    cmd.extend(["-v", f"{xauth_file}:/opt/adscan/.Xauthority:ro"])
            else:
                print_info_debug(
                    f"[docker] GUI passthrough requested but no X11 socket dir found at {x11_socket_dir}"
                )
        else:
            print_info_debug(
                "[docker] GUI passthrough requested but DISPLAY is not set on the host"
            )

    # Forward key host environment variables into the container:
    # - ADSCAN_SESSION_ENV / ADSCAN_ENV: ensure CI/dev/prod detection matches host
    # - ADSCAN_TELEMETRY: respect session/global opt-out
    # - ADSCAN_TELEMETRY_ID: stable identity from host (avoid container machine-id)
    #
    # NOTE: some behaviour toggles should be deterministic inside the container
    # even when the host did not explicitly set them. For those, we pass an
    # explicit default so we don't accidentally inherit image/env defaults.
    attack_path_env_defaults = {
        "ADSCAN_ATTACK_PATH_EXPAND_TERMINAL_MEMBERSHIPS": "1",
        "ADSCAN_ATTACK_GRAPH_PERSIST_MEMBERSHIPS": "1",
    }
    for key, default_value in attack_path_env_defaults.items():
        value = str(os.environ.get(key, default_value)).strip()
        cmd.extend(["-e", f"{key}={value}"])

    passthrough_keys = (
        "ADSCAN_SESSION_ENV",
        "ADSCAN_ENV",
        "ADSCAN_TELEMETRY",
        "ADSCAN_ALLOW_PUBLIC_DNS",
        # Offline / no-external kill switch (PoV appliance). Without forwarding
        # these, an ``ADSCAN_OFFLINE=1`` set on the host (e.g. by the appliance
        # cloud-init / Celery unit) never reaches the scan container, so the
        # weakpass egress guard and telemetry opt-out inside the runtime stay
        # off — the "zero bytes leave the appliance" promise would rest solely
        # on nftables. Opt-in: only forwarded when set, so the default runtime
        # behaviour is unchanged. ``ADSCAN_NO_EXTERNAL`` is the documented alias
        # (see weakpass_service._OFFLINE_ENV_VARS).
        "ADSCAN_OFFLINE",
        "ADSCAN_NO_EXTERNAL",
        # CI event pipeline: forward the structured-event sink config so the container
        # emits JSON events to stderr (read by the Celery worker via PIPE).
        "ADSCAN_EVENT_SINK",
        "ADSCAN_SCAN_ID",
        "ADSCAN_NONINTERACTIVE",
        # Remote interaction bridge: forward the sink type so the container can delegate
        # interactive prompts (e.g. attack path selection) back to the web UI via Redis.
        # The Redis URL is NOT forwarded as-is because localhost/127.0.0.1 is unreachable
        # from inside Docker; instead we compute a host-gateway-based URL below.
        "ADSCAN_INTERACTIVE_SINK",
        "ADSCAN_INTERACTIVE_TIMEOUT_SECONDS",
        "CI",
        "GITHUB_ACTIONS",
        "GITLAB_CI",
        "CIRCLECI",
        "TRAVIS",
        "JENKINS_HOME",
        "TEAMCITY_VERSION",
        "BUILDKITE",
        "DRONE",
        "CONTINUOUS_INTEGRATION",
        "FORCE_COLOR",
        "TERM",
        # Used by telemetry proxy / sentry proxy when present.
        "CLI_SHARED_TOKEN",
        # Used by the host privileged helper (Docker clock sync).
        "CONTAINER_SHARED_TOKEN",
        # Distinguish host launcher version from in-container runtime version.
        "ADSCAN_LAUNCHER_VERSION",
        # Correlate launcher preflight + runtime sessions as one logical run.
        "ADSCAN_SESSION_TRACE_ID",
    )
    for key in passthrough_keys:
        if key in os.environ and str(os.environ.get(key, "")).strip():
            cmd.extend(["-e", f"{key}={os.environ[key]}"])

    # Remote interaction bridge: forward a Docker-accessible Redis URL so the
    # container can reach the host Redis instance when delegating interactive
    # prompts (e.g. attack path selection) to the web UI.
    #
    # The host uses localhost/127.0.0.1 which is unreachable from inside a
    # Docker container.  We rewrite these to the special `host-gateway` hostname
    # that Docker maps to the host's bridge IP, and add --add-host so Docker
    # resolves it correctly on Linux (where host.docker.internal is unavailable).
    _interactive_sink = (
        str(os.environ.get("ADSCAN_INTERACTIVE_SINK", "") or "").strip().lower()
    )
    if _interactive_sink == "redis":
        _host_redis_url = str(
            os.environ.get("ADSCAN_REDIS_URL") or os.environ.get("REDIS_URL") or ""
        ).strip()
        if _host_redis_url:
            _docker_redis_url = _make_docker_accessible_url(_host_redis_url)
            if not host_gateway_added:
                cmd.extend(["--add-host", "host-gateway:host-gateway"])
                host_gateway_added = True
            cmd.extend(["-e", f"ADSCAN_REDIS_URL={_docker_redis_url}"])
            print_info_debug(
                f"[docker] forwarding Redis URL for interactive bridge: "
                f"{_docker_redis_url} (host: {_host_redis_url})"
            )

    # Forward host distro metadata so telemetry inside the container reports the
    # real host distribution instead of the runtime image base distro.
    host_distro = _collect_host_distro_context()
    host_distro_env = (
        (_HOST_DISTRO_ID_ENV, host_distro.get("distro_id", "")),
        (_HOST_DISTRO_VERSION_ENV, host_distro.get("distro_version", "")),
        (_HOST_DISTRO_LIKE_ENV, host_distro.get("distro_like", "")),
    )
    for env_key, env_value in host_distro_env:
        if not env_value:
            continue
        if any(arg.startswith(f"{env_key}=") for arg in cmd):
            continue
        cmd.extend(["-e", f"{env_key}={env_value}"])

    if not any(arg.startswith(f"{_HOST_TELEMETRY_ID_ENV}=") for arg in cmd):
        host_id = _compute_host_telemetry_id()
        if host_id:
            cmd.extend(["-e", f"{_HOST_TELEMETRY_ID_ENV}={host_id}"])

    cmd.append(cfg.image)
    cmd.extend(adscan_args)
    return cmd


def emit_entrypoint_logs_from_state() -> None:
    """Read and forward container entrypoint diagnostics via Rich + telemetry.

    The Docker entrypoint script writes human-readable diagnostics to a log file
    under the ADscan state directory (e.g. /opt/adscan/state/entrypoint.log).
    This helper reads that file (if present) and re-emits each line through
    ``print_info_debug()``, which is wired to the telemetry logger. The log file
    is removed after successful processing to avoid duplicate emission.

    This is intended to be called early in the containerized runtime (when
    running with ``ADSCAN_CONTAINER_RUNTIME=1`` and the state directory is
    mounted by the host launcher).
    """
    if os.getenv("ADSCAN_CONTAINER_RUNTIME") != "1":
        return

    log_path = get_state_dir() / "entrypoint.log"
    try:
        if not log_path.is_file():
            return
        try:
            raw = log_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            print_info_debug(f"[entrypoint] failed to read entrypoint log: {exc}")
            return

        for line in raw.splitlines():
            if not line.strip():
                continue
            # Emit to both debug (for local logs) and telemetry-only console so
            # entrypoint behaviour is visible in Rich session recordings.
            msg = f"[entrypoint] {line}"
            print_info_debug(msg)
            # Launcher does not have a separate telemetry-only console; emit as debug.
            print_info_debug(msg)

        try:
            log_path.unlink()
        except OSError:
            # Best-effort; if removal fails we just risk duplicate logs next run.
            pass
    except Exception as exc:  # pragma: no cover
        # Do not break startup because of telemetry-only diagnostics.
        print_info_debug(f"[entrypoint] error processing entrypoint log: {exc}")


def shell_quote_cmd(argv: Sequence[str]) -> str:
    """Return a shell-escaped string for logging/debug."""
    redacted_keys = {
        "CLI_SHARED_TOKEN",
        "CONTAINER_SHARED_TOKEN",
    }
    safe: list[str] = []
    i = 0
    while i < len(argv):
        item = argv[i]
        if item == "-e" and i + 1 < len(argv):
            kv = argv[i + 1]
            key, sep, value = kv.partition("=")
            if sep and key in redacted_keys and value:
                safe.extend([item, f"{key}=[REDACTED]"])
                i += 2
                continue
        safe.append(item)
        i += 1
    return " ".join(shlex.quote(a) for a in safe)
