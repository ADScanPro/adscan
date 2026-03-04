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
import pty
import re
import shlex
import shutil
import subprocess
import sys
import time
from selectors import DefaultSelector, EVENT_READ
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from adscan_launcher.output import (
    print_info_debug,
    print_warning,
    print_warning_verbose,
    print_error,
)
from adscan_launcher.paths import get_state_dir


_DOCKER_PERMISSION_DENIED_RE = re.compile(
    r"permission denied.*docker\.sock|got permission denied", re.IGNORECASE
)
_DOCKER_PERMISSION_WARNING_SHOWN = False


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


@dataclass(frozen=True)
class DockerRunConfig:
    """Configuration for running ADscan in a Docker container."""

    image: str
    workspaces_host_dir: Path
    # Match the in-container ADSCAN_HOME used by the FULL image.
    # This keeps workspaces persistent on the host without requiring any
    # container-side code changes.
    workspaces_container_dir: str = "/opt/adscan/workspaces"
    network_host: bool = True
    interactive: bool = True
    remove: bool = True
    run_as_current_user: bool = True
    extra_run_args: tuple[str, ...] = ()
    # Extra environment variables to pass into the container via `-e KEY=VALUE`.
    # This is preferred over mutating `os.environ` at call sites.
    extra_env: tuple[tuple[str, str], ...] = ()


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


def ensure_image_pulled(
    image: str, *, timeout: int | None = None, stream_output: bool = False
) -> bool:
    """Ensure a docker image exists locally (pull if needed)."""
    if not docker_available():
        return False
    # Pull is idempotent and simplest.
    if stream_output:
        rc, stdout, stderr = run_docker_stream(
            ["docker", "pull", image], timeout=timeout
        )
        if rc == 0:
            return True
        timed_out = bool(timeout is not None and rc == -9)
        if timed_out:
            print_warning(
                "Docker image pull did not finish within "
                f"{timeout}s and was aborted (rc={rc})."
            )
        print_error(
            f"docker pull failed: image={image!r}, rc={rc}, "
            f"stderr_tail={stderr!r}, stdout_tail={stdout!r}, timeout={timeout!r}"
        )
        return False

    proc = run_docker(
        ["docker", "pull", image], check=False, capture_output=True, timeout=timeout
    )
    if proc.returncode == 0:
        return True
    timed_out = bool(timeout is not None and int(proc.returncode) == -9)
    if timed_out:
        print_warning(
            "Docker image pull did not finish within "
            f"{timeout}s and was aborted (rc={proc.returncode})."
        )
    print_error(
        f"docker pull failed: image={image!r}, rc={proc.returncode}, "
        f"stderr_tail={proc.stderr!r}, stdout_tail={proc.stdout!r}, timeout={timeout!r}"
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


def build_adscan_run_command(
    cfg: DockerRunConfig,
    *,
    adscan_args: Sequence[str],
) -> list[str]:
    """Build docker run argv for running ADscan inside the container."""
    cmd: list[str] = ["docker", "run"]
    if cfg.remove:
        cmd.append("--rm")
    if cfg.interactive:
        cmd.extend(["-it"])
    if cfg.network_host:
        cmd.extend(["--network", "host"])
    # Allow the container to adjust the host clock when needed for Kerberos.
    # This is intentionally narrower than `--privileged` but still grants the
    # ability to change the system time (CAP_SYS_TIME).
    cmd.extend(["--cap-add", "SYS_TIME"])
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
    run_host_dir = cfg.workspaces_host_dir.parent / "run"
    state_host_dir = cfg.workspaces_host_dir.parent / "state"
    cmd.extend(
        [
            "-v",
            f"{cfg.workspaces_host_dir}:{cfg.workspaces_container_dir}",
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
            "ADSCAN_STATE_DIR=/opt/adscan/state",
            "-e",
            "ADSCAN_CONTAINER_RUNTIME=1",
            "-e",
            f"ADSCAN_RUNTIME_IMAGE={cfg.image}",
            "-e",
            "ADSCAN_HOST_HELPER_SOCK=/run/adscan/host-helper.sock",
        ]
    )

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
        "ADSCAN_ATTACK_PATH_GROUP_MEMBERSHIP_PRIMARY": "bloodhound",
        "ADSCAN_ATTACK_PATH_GROUP_MEMBERSHIP_ALLOW_FALLBACK": "0",
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
    )
    for key in passthrough_keys:
        if key in os.environ and str(os.environ.get(key, "")).strip():
            cmd.extend(["-e", f"{key}={os.environ[key]}"])

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
