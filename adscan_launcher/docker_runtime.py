"""Docker runtime helpers for ADscan container mode.

This module provides a minimal, dependency-light wrapper around `docker` to:
  - detect whether docker requires sudo
  - pull/inspect images
  - run ADscan inside a container with the workspace mounted

It is intentionally self-contained so `adscan.py` can stay focused on CLI
orchestration and user experience.
"""

from __future__ import annotations

import importlib
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import time
from selectors import DefaultSelector, EVENT_READ
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator, Sequence

from adscan_core.version_context import RUNTIME_CONTRACT_VERSION
from adscan_launcher.docker_pull_diagnostics import (
    PullFailureDiagnosis,
    classify_pull_failure,
    is_user_interrupt_returncode,
    record_last_failure,
    strip_ansi,
)
from adscan_launcher.output import (
    print_info,
    print_info_debug,
    print_panel,
    print_warning,
    print_warning_verbose,
    print_instruction,
)
from adscan_launcher.paths import get_state_dir
from adscan_core.rich_output import print_exception


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
#   * Only fires when the launcher is SURRENDERING the terminal to that
#     container — i.e. the output is inherited, not captured. A captured
#     ``docker run`` is a short probe the launcher outlives (``adscan check``
#     runs ``--version`` that way); flushing there ended the recording before
#     the command had said anything, so 11 of 11 `check` sessions had no
#     verdict in them. ``run_docker`` knows which case it is and tells the
#     hook; do not infer it from the argv.
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


def _fire_pre_container_exec_hook(
    argv: Sequence[str],
    *,
    surrenders_terminal: bool,
) -> None:
    """Invoke and clear the pre-``docker run`` hook, once, best-effort.

    Args:
        argv: The docker command about to run.
        surrenders_terminal: True when the launcher hands stdio to the
            container and outlives nothing (``adscan start`` / ``ci`` /
            passthrough). False for a captured probe the launcher continues
            past — flushing the session there truncates the recording.
    """
    if not surrenders_terminal:
        return
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
        _fire_pre_container_exec_hook(cmd, surrenders_terminal=False)
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

    _fire_pre_container_exec_hook(cmd, surrenders_terminal=True)
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
    pty_module = None
    if use_pty:
        # ``pty`` is POSIX-only (absent on Windows). Load it lazily so this module
        # imports cleanly off-platform; if it is unavailable, fall back to the
        # no-PTY pipe path below (Docker just loses its rich progress UI).
        try:
            pty_module = importlib.import_module("pty")
        except ImportError:
            use_pty = False
    # Streams to the terminal but returns its output tail to the caller, so the
    # launcher outlives it — not a handoff. (Today this only carries
    # ``docker pull``, which the argv gate ignores anyway.)
    _fire_pre_container_exec_hook(cmd, surrenders_terminal=False)
    if use_pty and pty_module is not None:
        # If we pipe stdout/stderr, Docker disables its rich progress UI because it
        # thinks it's not attached to a TTY. Use a PTY in interactive sessions so
        # users see Docker's native progress rendering.
        master_fd, slave_fd = pty_module.openpty()
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

    A user Ctrl-C during the pull is handled FIRST and separately: the
    return code (``130`` / ``-SIGINT``) — not any stderr text — is the
    only reliable interrupt signal, so it is detected here, recorded as a
    dedicated ``user_interrupt`` diagnosis, shown as a calm cancellation
    message (always, regardless of ``surface_failure`` — a cancel is
    terminal), and re-raised as ``KeyboardInterrupt`` so the launcher
    unwinds to its top-level handler and exits with the conventional
    interrupt code. It is never misclassified as an "unclassified error"
    and never handed to the retry loop.

    Raises:
        KeyboardInterrupt: when ``rc`` indicates the operator cancelled
            the pull with Ctrl-C.
    """
    if is_user_interrupt_returncode(rc):
        record_last_failure(PullFailureDiagnosis(kind="user_interrupt", evidence=[]))
        print_info_debug(f"docker pull interrupted by user: image={image} rc={rc}")
        print_info(
            "Installation cancelled. Rerun `adscan install` when ready; if the "
            "pull was slow, try a faster or less-throttled network."
        )
        raise KeyboardInterrupt
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
    # 25s (not 10s): on a loaded daemon a healthy `docker image inspect` can take
    # well over 10s, and a false timeout here made `get_docker_update_info` treat
    # the image as absent (still recoverable — it pulls anyway) but at the cost of
    # a scary traceback. Kept bounded so the check can never hang the command.
    proc = run_docker(
        ["docker", "image", "inspect", image],
        check=False,
        capture_output=True,
        timeout=25,
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


def runtime_cap_add_list() -> tuple[str, ...]:
    """Return the ``--cap-add`` names the real ADscan container is launched with.

    Single source of truth for ``build_adscan_run_command`` and the capability
    probe. They MUST agree: a probe that adds fewer capabilities than the real
    run measures a container ADscan never runs in, and reports capabilities as
    missing when the actual container has them.

    NET_ADMIN is conditional on the host exposing ``/dev/net/tun``, since that
    is what ligolo's TUN pivoting needs.
    """
    caps = ["SYS_TIME", "NET_BIND_SERVICE"]
    if Path("/dev/net/tun").exists():
        caps.append("NET_ADMIN")
    return tuple(caps)


def _render_reduced_runtime_panel(verdict) -> None:
    """Render the 'reduced network mode' notice for a capability-limited runtime.

    The headline states only what the probe OBSERVED. A remapped user namespace
    is named as such; anything else says the capabilities are missing without
    guessing why, because a rootful daemon can also be missing them (stripped
    caps, no ``/dev/net/tun``) and telling that operator they are "rootless"
    sends them to fix something that is not broken.
    """
    ipv6_ok = bool(getattr(verdict, "net_raw", False))
    tun_ok = bool(getattr(verdict, "net_admin", False))
    remapped = bool(getattr(verdict, "userns_remapped", False))
    ok = "[success]✓[/success]"
    warn = "[warning]⚠[/warning]"
    rows = [
        f"  {ok}  Core assessment    LDAP · SMB · Kerberos · RPC · attack paths",
        f"  {ok}  Recon              port / service discovery (TCP connect)",
        f"  {ok if ipv6_ok else warn}  IPv6 poisoning     "
        + ("available" if ipv6_ok else "mitm6 (DHCPv6/RA) — requires NET_RAW"),
        f"  {ok if tun_ok else warn}  Tunnel pivoting    "
        + ("available" if tun_ok else "ligolo-ng TUN — requires NET_ADMIN"),
    ]
    if remapped:
        headline = (
            "Rootless / user-namespaced runtime detected (rootless Docker or "
            "Podman). The full AD assessment runs normally — the optional "
            "offensive extras below are unavailable in this runtime."
        )
        title = "⚠  Reduced Network Mode · rootless container runtime"
        footer = (
            "\n\n[bold]Full features[/bold] → run on a standard (rootful) Docker daemon.\n"
            "                no sudo: add your user to the [bold]docker[/bold] group."
        )
    else:
        headline = (
            "This container runtime does not grant every network capability "
            "ADscan can use. The full AD assessment runs normally — the "
            "optional offensive extras below are unavailable."
        )
        title = "⚠  Reduced Network Mode · limited container capabilities"
        footer = (
            "\n\n[bold]Full features[/bold] → a runtime that allows NET_RAW and "
            "NET_ADMIN.\n"
            "                TUN pivoting also needs [bold]/dev/net/tun[/bold] on the host."
        )
    body = headline + "\n\n" + "\n".join(rows) + footer
    print_panel(
        body,
        title=title,
        title_align="left",
        border_style="panel.border.warning",
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

        verdict = probe_runtime_capability(
            image=cfg.image,
            uid=os.getuid(),
            gid=os.getgid(),
            cap_add=runtime_cap_add_list(),
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
            print_exception(exception=exc)
        except Exception:  # noqa: BLE001
            pass


#: Non-``ADSCAN_``-prefixed host environment variables forwarded verbatim into
#: the scan container.
#:
#: ADscan's OWN configuration namespace (``ADSCAN_*``) is wildcard-forwarded — see
#: ``LAUNCHER_ONLY_ENV_KEYS`` and ``_iter_forwardable_adscan_env`` below. This tuple
#: only holds the handful of vars OUTSIDE that namespace the container still needs:
#: the CI markers (so in-container CI/non-interactive detection matches the host),
#: the terminal colour hints, and the two shared proxy/helper tokens. They can never
#: be covered by the ``ADSCAN_`` prefix, so they stay an explicit keep-list.
#:
#: Opt-in by design: a key is only forwarded when it is set (and non-empty) on the
#: host, so the default runtime behaviour is unchanged. It is module-level (not a
#: local inside ``build_adscan_run_command``) precisely so tests can assert against
#: it.
PASSTHROUGH_ENV_KEYS: tuple[str, ...] = (
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
)


#: ``ADSCAN_*`` variables the LAUNCHER consumes itself and that must NOT be
#: forwarded into the scan container.
#:
#: The forwarding model is INVERTED: every ``ADSCAN_*`` variable set on the host
#: is forwarded to the container by default (that namespace is ADscan's own
#: product config, not third-party secrets), EXCEPT the ones listed here. The old
#: key-by-key allow-list was the root cause of a recurring bug class — the runtime
#: reads ~196 distinct ``ADSCAN_*`` vars but the launcher only forwarded ~35, so a
#: config var an operator set on the host (e.g. ``ADSCAN_ATTACK_PATHS_COMPUTE_MAX``,
#: their attack-path memory workaround) was silently dropped at the container
#: boundary and never took effect. Inverting to "forward-by-default, exclude
#: explicitly" makes a newly-added runtime var work with zero launcher changes.
#:
#: Every entry here is read by the launcher to drive ``docker run`` mechanics or to
#: carry host identity — forwarding it is at best useless noise inside the container
#: and at worst would override a value the launcher computes and injects itself.
#: Vars the launcher forwards with a COMPUTED value (e.g. ``ADSCAN_UID``/``ADSCAN_GID``,
#: ``ADSCAN_LOCAL_RESOLVER_IP``, ``ADSCAN_RUNTIME_LICENSE_MODE``, ``ADSCAN_HOME``,
#: ``ADSCAN_CONTAINER_RUNTIME``, ``ADSCAN_TELEMETRY_ID``, ``ADSCAN_HOST_DISTRO_*``)
#: do NOT need an entry here: the wildcard skips any key already emitted into the
#: ``docker run`` argv, so the launcher's injected value always wins.
LAUNCHER_ONLY_ENV_KEYS: frozenset[str] = frozenset(
    {
        # --- docker-run mechanics: which image / runtime / channel to launch ---
        "ADSCAN_DOCKER_IMAGE",       # image override (launcher image selection)
        "ADSCAN_DOCKER_CHANNEL",     # stable/dev channel selection
        "ADSCAN_DOCKER_GPU",         # GPU passthrough mode (launcher wires --gpus/--device)
        "ADSCAN_DOCKER_GUI",         # X11 GUI passthrough toggle (launcher-side)
        "ADSCAN_X11_SOCKET_DIR",     # host X11 socket dir the launcher mounts
        "ADSCAN_CONTAINER_RUNTIME",  # marks "inside container"; launcher sets =1 itself
        # --- host preflight / capability escape hatches (launcher-only gates) ---
        "ADSCAN_ALLOW_LEGACY_IMAGE_FALLBACK",
        "ADSCAN_ALLOW_LOW_MEMORY",
        "ADSCAN_ALLOW_PODMAN_DOCKER_API",
        "ADSCAN_ALLOW_UNSUPPORTED_ARCH",
        "ADSCAN_ALLOW_UNSUPPORTED_PLATFORM",
        "ADSCAN_ALLOW_UNSUPPORTED_WSL",
        # --- host-shell integration (launcher install/alias mechanics) ---
        "ADSCAN_CLI_PATH",           # host launcher invocation prefix
        "ADSCAN_SUDO_ALIAS_MARKER",  # marker line for the auto-sudo shell alias
    }
)


def is_env_var_forwarded_to_container(key: str) -> bool:
    """Return whether a host env var named ``key`` reaches the scan container.

    The single source of truth for "will an operator's ``export KEY=...`` take
    effect inside the scan". A start gate that tells the operator to set an env
    var must name one this returns ``True`` for, or the recovery instruction is a
    dead end (the exact PRO partner-tag regression).

    True when either:

    * ``key`` is in the explicit NON-``ADSCAN_`` keep-list (``PASSTHROUGH_ENV_KEYS`` —
      CI markers, colour hints, shared tokens); or
    * ``key`` has the ``ADSCAN_`` prefix and is NOT a launcher-only var
      (``LAUNCHER_ONLY_ENV_KEYS``), i.e. it is covered by the wildcard forward.

    Args:
        key: The environment variable name.

    Returns:
        ``True`` if a host value for ``key`` is forwarded into the container.
    """
    if key in PASSTHROUGH_ENV_KEYS:
        return True
    return key.startswith("ADSCAN_") and key not in LAUNCHER_ONLY_ENV_KEYS


def _iter_forwardable_adscan_env(
    already_emitted: frozenset[str],
) -> Iterator[tuple[str, str]]:
    """Yield ``(key, value)`` for every host ``ADSCAN_*`` var to forward.

    Wildcard-forward ADscan's own configuration namespace into the container,
    with three guards:

    * only keys with the ``ADSCAN_`` prefix (never the whole environment, so no
      third-party host secrets — ``AWS_*``, tokens, ``HOME`` — leak in);
    * never a ``LAUNCHER_ONLY_ENV_KEYS`` var (docker-run mechanics / host identity);
    * never a key already emitted into the ``docker run`` argv (so a value the
      launcher computes and injects itself — UID/GID, resolver IP, license mode,
      ``ADSCAN_HOME``, the attack-path defaults — always wins, never double-set).

    Args:
        already_emitted: ``ADSCAN_*`` keys already present as ``-e KEY=...`` in the
            command being built.

    Yields:
        ``(key, value)`` pairs to append as ``-e KEY=value``.
    """
    for key, value in os.environ.items():
        if not key.startswith("ADSCAN_"):
            continue
        if key in LAUNCHER_ONLY_ENV_KEYS:
            continue
        if key in already_emitted:
            continue
        if not str(value).strip():
            continue
        yield key, value


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
    # Capabilities, from the shared list the capability probe also uses:
    # - SYS_TIME lets the container adjust the host clock for Kerberos. Narrower
    #   than `--privileged`, which is why it is granted individually.
    # - NET_BIND_SERVICE: coercion-based NTLM capture / relay listeners (NTLM
    #   auth-type sweep, ESC8 relay) bind PRIVILEGED ports inbound (SMB 445,
    #   HTTP 80, LDAP 389). The runtime runs as a non-root --user, so without
    #   this it gets EACCES binding <1024 and those features skip with
    #   "listener failed to start". --sysctl net.ipv4.ip_unprivileged_port_start
    #   is NOT an option here because the runtime uses --network host, which
    #   forbids namespaced net sysctls.
    # - NET_ADMIN (when the host has /dev/net/tun) for ligolo TUN pivoting.
    for cap in runtime_cap_add_list():
        cmd.extend(["--cap-add", cap])
    host_tun_device = Path("/dev/net/tun")
    if host_tun_device.exists():
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

    # (Debug / instrumentation ``ADSCAN_*`` toggles — ``ADSCAN_NO_LIVE``,
    # ``ADSCAN_TELEMETRY_TRACE``, ``ADSCAN_NO_POSTURE_PROBE``, ``ADSCAN_DIAG_RICH``,
    # and every other runtime config var — are now forwarded by the wildcard
    # ``ADSCAN_*`` pass below, so no per-var allow-list is needed.)

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

    # Forward the small explicit keep-list of NON-``ADSCAN_`` host vars the
    # container still needs (CI markers, colour hints, shared tokens). These can
    # never match the ``ADSCAN_`` prefix, so they stay a named allow-list —
    # see PASSTHROUGH_ENV_KEYS and tests/unit/launcher/.
    for key in PASSTHROUGH_ENV_KEYS:
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

    # Wildcard-forward ADscan's own configuration namespace (``ADSCAN_*``) LAST,
    # so ``already_emitted`` captures EVERY ``ADSCAN_*`` key the launcher injects
    # with a computed value above (UID/GID, resolver IP, license mode, ADSCAN_HOME,
    # the attack-path defaults, the rewritten Redis URL, host-distro, telemetry id).
    # This inverts the old key-by-key allow-list: any runtime config var an operator
    # sets on the host now actually reaches the scan (attack-path tuning, cache
    # sizes, depth limits, …) instead of being silently dropped at the container
    # boundary. Launcher-only vars (LAUNCHER_ONLY_ENV_KEYS — docker-run mechanics,
    # host identity) and already-emitted keys are skipped, so nothing is double-set
    # and no host value overrides a launcher-computed one.
    _emitted_adscan_keys = frozenset(
        arg.split("=", 1)[0]
        for i, arg in enumerate(cmd)
        if i > 0 and cmd[i - 1] == "-e" and arg.startswith("ADSCAN_") and "=" in arg
    )
    for key, value in _iter_forwardable_adscan_env(_emitted_adscan_keys):
        cmd.extend(["-e", f"{key}={value}"])

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
