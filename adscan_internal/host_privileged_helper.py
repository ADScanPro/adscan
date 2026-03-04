"""Host-side privileged helper for ADscan Docker mode.

This module provides a small, auditable interface for executing a limited set
of privileged host operations (currently time synchronization) on behalf of the
ADscan container runtime.

Why this exists:
  - Containers share the host kernel clock; there is no safe way to "fix Kerberos
    clock skew" purely inside an unprivileged container.
  - Many container images do not run systemd, so `timedatectl`/`systemctl` are
    unavailable inside the container.
  - We do NOT want to run the ADscan container in `--privileged` mode.

Approach:
  - The host launcher starts this helper via `sudo` and exposes a Unix domain
    socket to the container via a bind-mount (e.g., ~/.adscan/run).
  - The container sends signed JSON requests (HMAC) using a shared token
    (`CONTAINER_SHARED_TOKEN`). Requests are validated and mapped to a very small
    command set.

Security notes:
  - This helper intentionally does not accept arbitrary commands.
  - Only IPv4 targets are accepted for NTP sync operations.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import os
import re
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from hashlib import sha256
from io import StringIO
from pathlib import Path
from socket import AF_UNIX, SOCK_STREAM, socket
from typing import Any


_MAX_REQUEST_BYTES = 32_768
_DEFAULT_TIMEOUT_SECONDS = 60
_MAX_RDP_SECRET_LEN = 2048

_SAFE_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,253}[A-Za-z0-9]$")
_SAFE_DOMAIN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,253}[A-Za-z0-9]$")
_SAFE_USERNAME_RE = re.compile(r"^[A-Za-z0-9._$@-]{1,256}$")
_SAFE_SHARE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9$._ -]{0,127}$")
# Workspace creation currently allows names with spaces, so the helper must
# accept them too to keep host-file imports consistent with CLI workspaces.
_SAFE_WORKSPACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$")

_CONTAINER_WORKSPACES_DIR = "/opt/adscan/workspaces"


class HostHelperError(RuntimeError):
    """Raised when the host helper cannot process a request."""


@dataclass(frozen=True)
class HostHelperResponse:
    """A structured response from the helper."""

    ok: bool
    returncode: int | None
    stdout: str | None
    stderr: str | None
    message: str | None = None


def _get_shared_token() -> str:
    token = os.getenv("CONTAINER_SHARED_TOKEN", "").strip()
    if not token:
        raise HostHelperError("Missing CONTAINER_SHARED_TOKEN")
    return token


def _hmac_sig(token: str, payload: bytes) -> str:
    return hmac.new(token.encode(), payload, sha256).hexdigest()


def _canonical_payload(obj: dict[str, Any]) -> bytes:
    """Serialize dict to canonical JSON bytes for signing."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def _validate_ipv4(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as exc:
        raise HostHelperError(f"Invalid IP address: {value}") from exc
    if ip.version != 4:
        raise HostHelperError("Only IPv4 addresses are supported for clock sync")
    return str(ip)


def _validate_host_or_ipv4(value: str) -> str:
    """Validate a host target (IPv4 or hostname/FQDN)."""
    value = (value or "").strip()
    if not value:
        raise HostHelperError("Missing host")
    try:
        return _validate_ipv4(value)
    except HostHelperError:
        pass
    if not _SAFE_HOSTNAME_RE.match(value):
        raise HostHelperError(f"Invalid host: {value}")
    return value


def _invoker_uid_gid() -> tuple[int, int]:
    """Return the invoking user's uid/gid when started via sudo."""
    try:
        sudo_uid = int(os.getenv("SUDO_UID", "0") or "0")
        sudo_gid = int(os.getenv("SUDO_GID", "0") or "0")
    except ValueError:
        sudo_uid = 0
        sudo_gid = 0
    if sudo_uid > 0 and sudo_gid > 0:
        return sudo_uid, sudo_gid
    return os.getuid(), os.getgid()


def _build_invoker_env() -> dict[str, str]:
    """Build env for processes that must run as the invoking user (GUI apps)."""
    env = os.environ.copy()
    home = _invoker_home_dir()
    env["HOME"] = str(home)
    env.setdefault("XDG_CONFIG_HOME", str(home / ".config"))
    env.setdefault("XDG_CACHE_HOME", str(home / ".cache"))
    return env


def _run_detached_as_invoker(
    argv: list[str], *, env: dict[str, str]
) -> HostHelperResponse:
    """Launch a detached process as the invoking (non-root) user."""
    uid, gid = _invoker_uid_gid()
    if uid <= 0:
        return HostHelperResponse(
            ok=False,
            returncode=1,
            stdout=None,
            stderr=None,
            message="Refusing to launch GUI process as root",
        )

    def _preexec() -> None:  # pragma: no cover
        os.setgid(gid)
        os.setuid(uid)
        os.setsid()

    try:
        subprocess.Popen(  # noqa: S603
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            preexec_fn=_preexec,  # noqa: S606
        )
        return HostHelperResponse(ok=True, returncode=0, stdout=None, stderr=None)
    except Exception as exc:  # pragma: no cover
        return HostHelperResponse(
            ok=False,
            returncode=1,
            stdout=None,
            stderr=str(exc),
            message="Failed to launch process",
        )


def _run_capture_as_invoker(
    argv: list[str],
    *,
    env: dict[str, str],
    timeout: int = _DEFAULT_TIMEOUT_SECONDS,
) -> HostHelperResponse:
    """Run a command as the invoking (non-root) user and capture output."""

    uid, gid = _invoker_uid_gid()
    if uid <= 0:
        return HostHelperResponse(
            ok=False,
            returncode=1,
            stdout=None,
            stderr=None,
            message="Refusing to run interactive GUI process as root",
        )

    def _preexec() -> None:  # pragma: no cover
        os.setgid(gid)
        os.setuid(uid)

    try:
        proc = subprocess.run(  # noqa: S603
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
            preexec_fn=_preexec,  # noqa: S606
        )
    except subprocess.TimeoutExpired as exc:
        return HostHelperResponse(
            ok=False,
            returncode=None,
            stdout=getattr(exc, "stdout", None),
            stderr=getattr(exc, "stderr", None),
            message=f"Timeout after {timeout}s",
        )
    except Exception as exc:  # pragma: no cover
        return HostHelperResponse(
            ok=False,
            returncode=None,
            stdout=None,
            stderr=str(exc),
            message="Exception while executing command",
        )

    return HostHelperResponse(
        ok=(proc.returncode == 0),
        returncode=int(proc.returncode),
        stdout=(proc.stdout or None),
        stderr=(proc.stderr or None),
        message=None if proc.returncode == 0 else "Command failed",
    )


def _invoker_home_dir() -> Path:
    """Return the invoking user's home directory (best effort).

    When started via `sudo`, `Path.home()` points to `/root`. Use `SUDO_UID` to
    resolve the original user's home directory instead.
    """
    try:
        sudo_uid = int(os.getenv("SUDO_UID", "0") or "0")
    except ValueError:
        sudo_uid = 0
    if sudo_uid <= 0:
        return Path.home()
    try:
        import pwd

        return Path(pwd.getpwuid(sudo_uid).pw_dir)
    except Exception:  # pragma: no cover
        return Path.home()


def _invoker_adscan_root_dir() -> Path:
    """Return the invoking user's ADscan root directory on host.

    This is intentionally derived from the invoking user rather than `Path.home()`,
    because the helper is frequently started via `sudo` and would otherwise point
    to `/root`.
    """

    return _invoker_home_dir() / ".adscan"


def _safe_resolve_within(base: Path, candidate: Path) -> Path:
    """Resolve candidate and ensure it stays within base (prevents traversal)."""

    base_resolved = base.resolve(strict=False)
    candidate_resolved = candidate.resolve(strict=False)
    if candidate_resolved == base_resolved:
        return candidate_resolved
    if base_resolved not in candidate_resolved.parents:
        raise HostHelperError("Path traversal detected")
    return candidate_resolved


def _copy_file(src: Path, dst: Path) -> None:
    """Copy a file using streaming reads to avoid `shutil` imports."""

    dst.parent.mkdir(parents=True, exist_ok=True)
    with src.open("rb") as src_handle, dst.open("wb") as dst_handle:
        while True:
            chunk = src_handle.read(1024 * 1024)
            if not chunk:
                break
            dst_handle.write(chunk)


def _unique_destination_path(dst: Path) -> Path:
    """Return a non-existing destination path by adding a numeric suffix."""

    if not dst.exists():
        return dst
    stem = dst.stem
    suffix = dst.suffix
    parent = dst.parent
    for i in range(1, 10_000):
        candidate = parent / f"{stem}_{i}{suffix}"
        if not candidate.exists():
            return candidate
    raise HostHelperError("Could not find an available destination filename")


def _validate_bloodhound_compose_path(value: str) -> str:
    """Validate a BloodHound CE docker-compose.yml path.

    The helper must never accept arbitrary filesystem paths. We allow:
    - Managed ADscan path under ``~/.adscan/bloodhound/**/docker-compose.yml``
    - Legacy compatibility path ``~/.config/bloodhound/docker-compose.yml``
    """
    if not value:
        raise HostHelperError("Missing compose_path")
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise HostHelperError("compose_path must be absolute")
    resolved = path.resolve(strict=False)
    legacy_expected = (
        _invoker_home_dir().resolve() / ".config" / "bloodhound" / "docker-compose.yml"
    ).resolve(strict=False)
    managed_root = (_invoker_adscan_root_dir().resolve() / "bloodhound").resolve(
        strict=False
    )

    allowed = False
    if resolved == legacy_expected:
        allowed = True
    elif resolved.name == "docker-compose.yml":
        try:
            _safe_resolve_within(managed_root, resolved)
            allowed = True
        except HostHelperError:
            allowed = False
    if not allowed:
        raise HostHelperError(f"compose_path not allowed: {resolved}")
    if not resolved.is_file():
        raise HostHelperError(f"compose file not found: {resolved}")
    return str(resolved)


def _validate_cifs_mount_root(value: str) -> Path:
    """Validate CIFS mount root under invoking user's workspaces tree."""
    if not isinstance(value, str) or not value.strip():
        raise HostHelperError("Missing mount_root")
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise HostHelperError("mount_root must be absolute")
    resolved = path.resolve(strict=False)
    workspaces_root = (_invoker_adscan_root_dir() / "workspaces").resolve(strict=False)
    _safe_resolve_within(workspaces_root, resolved)
    return resolved


def _validate_cifs_share_name(value: str) -> str:
    """Validate SMB share name for CIFS operations."""
    text = str(value or "").strip()
    if not text or not _SAFE_SHARE_RE.match(text):
        raise HostHelperError("Invalid share")
    return text


def _validate_cifs_username(value: str) -> str:
    """Validate username used for CIFS mount auth."""
    text = str(value or "").strip()
    if not text or len(text) > 256:
        raise HostHelperError("Invalid username")
    return text


def _validate_cifs_password(value: str) -> str:
    """Validate password used for CIFS mount auth."""
    text = str(value or "")
    if len(text) > 4096:
        raise HostHelperError("Password too long")
    return text


def _validate_cifs_domain(value: str | None) -> str:
    """Validate optional domain for CIFS mount auth."""
    text = str(value or "").strip()
    if not text:
        return ""
    if not _SAFE_DOMAIN_RE.match(text):
        raise HostHelperError("Invalid domain")
    return text


def _build_cifs_mount_args(
    *,
    host: str,
    share: str,
    mount_point: Path,
    credentials_file: Path,
    read_only: bool,
) -> list[str]:
    """Build argv for CIFS mount command."""
    options = [
        f"credentials={credentials_file}",
        "vers=3.0",
        "iocharset=utf8",
        "noperm",
    ]
    if read_only:
        options.append("ro")
    else:
        options.append("rw")
    options_arg = ",".join(options)
    mount_cifs_bin = shutil_which("mount.cifs")
    if mount_cifs_bin:
        return [mount_cifs_bin, f"//{host}/{share}", str(mount_point), "-o", options_arg]
    mount_bin = shutil_which("mount")
    if mount_bin:
        return [
            mount_bin,
            "-t",
            "cifs",
            f"//{host}/{share}",
            str(mount_point),
            "-o",
            options_arg,
        ]
    raise HostHelperError("mount/mount.cifs not found")


def _docker_compose_invocation() -> list[str] | None:
    """Return the docker compose invocation prefix, or None if unavailable."""
    if shutil_which("docker"):
        try:
            proc = subprocess.run(
                ["docker", "compose", "version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if proc.returncode == 0:
                return ["docker", "compose"]
        except Exception:
            pass
    if shutil_which("docker-compose"):
        try:
            proc = subprocess.run(
                ["docker-compose", "version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if proc.returncode == 0:
                return ["docker-compose"]
        except Exception:
            pass
    return None


def _run_cmd(
    argv: list[str], *, timeout: int = _DEFAULT_TIMEOUT_SECONDS
) -> HostHelperResponse:
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return HostHelperResponse(
            ok=False,
            returncode=None,
            stdout=getattr(exc, "stdout", None),
            stderr=getattr(exc, "stderr", None),
            message=f"Timeout after {timeout}s",
        )
    except Exception as exc:  # pragma: no cover
        return HostHelperResponse(
            ok=False,
            returncode=None,
            stdout=None,
            stderr=str(exc),
            message="Exception while executing command",
        )

    return HostHelperResponse(
        ok=(proc.returncode == 0),
        returncode=int(proc.returncode),
        stdout=proc.stdout,
        stderr=proc.stderr,
    )


def _handle_request(req: dict[str, Any]) -> HostHelperResponse:
    op = str(req.get("op") or "").strip()
    if not op:
        return HostHelperResponse(False, None, None, None, "Missing op")

    if op == "ping":
        return HostHelperResponse(True, 0, "pong", None, None)

    if op == "timedatectl_set_ntp":
        value = req.get("value")
        if not isinstance(value, bool):
            return HostHelperResponse(
                False, None, None, None, "Invalid value for timedatectl_set_ntp"
            )
        # Best-effort: timedatectl may not exist; report clearly.
        if not shutil_which("timedatectl"):
            return HostHelperResponse(False, 127, None, None, "timedatectl not found")
        return _run_cmd(
            ["timedatectl", "set-ntp", "true" if value else "false"], timeout=30
        )

    if op == "ntpdate":
        host = req.get("host")
        if not isinstance(host, str):
            return HostHelperResponse(
                False, None, None, None, "Invalid host for ntpdate"
            )
        ip = _validate_ipv4(host)
        if not shutil_which("ntpdate") and not shutil_which("ntpdig"):
            return HostHelperResponse(
                False, 127, None, None, "ntpdate/ntpdig not found"
            )
        if shutil_which("ntpdate"):
            return _run_cmd(["ntpdate", ip], timeout=60)
        # ntpdig fallback (ntpsec)
        return _run_cmd(["ntpdig", "-gq", ip], timeout=60)

    if op == "net_time_set":
        host = req.get("host")
        if not isinstance(host, str):
            return HostHelperResponse(
                False, None, None, None, "Invalid host for net_time_set"
            )
        ip = _validate_ipv4(host)
        if not shutil_which("net"):
            return HostHelperResponse(False, 127, None, None, "net not found")
        # `net time set -S <server>` sets local system time based on SMB/RPC.
        return _run_cmd(["net", "time", "set", "-S", ip], timeout=120)

    if op == "docker_ps_names_status":
        if not shutil_which("docker"):
            return HostHelperResponse(False, 127, None, None, "docker not found")
        return _run_cmd(
            ["docker", "ps", "--format", "{{.Names}}\t{{.Status}}"], timeout=20
        )

    if op == "docker_ps_names_images_status":
        if not shutil_which("docker"):
            return HostHelperResponse(False, 127, None, None, "docker not found")
        return _run_cmd(
            ["docker", "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}"],
            timeout=20,
        )

    if op == "bloodhound_ce_compose_up":
        compose_path = req.get("compose_path")
        if not isinstance(compose_path, str):
            return HostHelperResponse(False, None, None, None, "Invalid compose_path")
        try:
            validated = _validate_bloodhound_compose_path(compose_path)
        except HostHelperError as exc:
            return HostHelperResponse(False, None, None, None, str(exc))
        try:
            from contextlib import redirect_stderr, redirect_stdout

            from adscan_internal.bloodhound_ce_compose import compose_up

            buf_out, buf_err = StringIO(), StringIO()
            with redirect_stdout(buf_out), redirect_stderr(buf_err):
                ok = bool(compose_up(Path(validated)))
            stdout = buf_out.getvalue().strip() or None
            stderr = buf_err.getvalue().strip() or None
            return HostHelperResponse(
                ok,
                0 if ok else 1,
                stdout,
                stderr,
                None if ok else "bloodhound compose up failed",
            )
        except Exception as exc:
            return HostHelperResponse(False, 1, None, None, f"exception: {exc}")

    if op == "rdp_launch":
        host = req.get("host")
        domain = req.get("domain")
        username = req.get("username")
        password = req.get("password")
        if (
            not isinstance(host, str)
            or not isinstance(domain, str)
            or not isinstance(username, str)
        ):
            return HostHelperResponse(
                False, None, None, None, "Invalid rdp_launch payload"
            )
        if not isinstance(password, str):
            return HostHelperResponse(
                False, None, None, None, "Invalid password for rdp_launch"
            )

        try:
            validated_host = _validate_host_or_ipv4(host)
        except HostHelperError as exc:
            return HostHelperResponse(False, None, None, None, str(exc))

        domain = domain.strip()
        if not domain or not _SAFE_DOMAIN_RE.match(domain):
            return HostHelperResponse(False, None, None, None, "Invalid domain")
        username = username.strip()
        if not username or not _SAFE_USERNAME_RE.match(username):
            return HostHelperResponse(False, None, None, None, "Invalid username")
        if len(password) > _MAX_RDP_SECRET_LEN:
            return HostHelperResponse(False, None, None, None, "Password too long")

        # Ensure a GUI environment exists on the host (X11 or Wayland).
        if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
            return HostHelperResponse(
                False,
                2,
                None,
                None,
                "No GUI session detected on host (DISPLAY/WAYLAND_DISPLAY is not set)",
            )

        # Resolve the RDP client on the host.
        rdp_bin = shutil_which("xfreerdp3") or shutil_which("xfreerdp")
        if not rdp_bin:
            return HostHelperResponse(
                False,
                127,
                None,
                None,
                "xfreerdp3/xfreerdp not found on host",
            )

        argv = [
            rdp_bin,
            f"/d:{domain}",
            f"/u:{username}",
            f"/p:{password}",
            f"/v:{validated_host}",
            "/cert:ignore",
        ]
        return _run_detached_as_invoker(argv, env=_build_invoker_env())

    if op == "cifs_mount_share":
        host = req.get("host")
        share = req.get("share")
        mount_root = req.get("mount_root")
        username = req.get("username")
        password = req.get("password")
        domain = req.get("domain")
        read_only = req.get("read_only", True)
        if (
            not isinstance(host, str)
            or not isinstance(share, str)
            or not isinstance(mount_root, str)
            or not isinstance(username, str)
            or not isinstance(password, str)
            or not isinstance(read_only, bool)
        ):
            return HostHelperResponse(
                False, None, None, None, "Invalid cifs_mount_share payload"
            )

        try:
            validated_host = _validate_host_or_ipv4(host)
            validated_share = _validate_cifs_share_name(share)
            validated_mount_root = _validate_cifs_mount_root(mount_root)
            validated_username = _validate_cifs_username(username)
            validated_password = _validate_cifs_password(password)
            validated_domain = _validate_cifs_domain(domain if isinstance(domain, str) else "")
        except HostHelperError as exc:
            return HostHelperResponse(False, None, None, None, str(exc))

        mount_point = (
            validated_mount_root / validated_host / validated_share
        ).resolve(strict=False)
        try:
            _safe_resolve_within(validated_mount_root, mount_point)
        except HostHelperError as exc:
            return HostHelperResponse(False, None, None, None, str(exc))

        mount_point.mkdir(parents=True, exist_ok=True)
        if os.path.ismount(mount_point):
            stdout = json.dumps(
                {
                    "mount_point": str(mount_point),
                    "already_mounted": True,
                    "mounted_by_helper": False,
                },
                ensure_ascii=False,
            )
            return HostHelperResponse(
                True,
                0,
                stdout,
                None,
                "CIFS share already mounted",
            )

        credentials_file: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(  # noqa: PTH123
                mode="w",
                prefix="adscan_cifs_",
                suffix=".cred",
                delete=False,
                encoding="utf-8",
            ) as handle:
                credentials_file = Path(handle.name)
                handle.write(f"username={validated_username}\n")
                handle.write(f"password={validated_password}\n")
                if validated_domain:
                    handle.write(f"domain={validated_domain}\n")
            os.chmod(credentials_file, 0o600)

            argv = _build_cifs_mount_args(
                host=validated_host,
                share=validated_share,
                mount_point=mount_point,
                credentials_file=credentials_file,
                read_only=read_only,
            )
            result = _run_cmd(argv, timeout=120)
            if not result.ok:
                return result

            stdout = json.dumps(
                {
                    "mount_point": str(mount_point),
                    "already_mounted": False,
                    "mounted_by_helper": True,
                },
                ensure_ascii=False,
            )
            return HostHelperResponse(
                True,
                0,
                stdout,
                result.stderr,
                "CIFS share mounted",
            )
        finally:
            if credentials_file is not None:
                try:
                    credentials_file.unlink(missing_ok=True)
                except OSError:
                    pass

    if op == "cifs_unmount_share":
        mount_point = req.get("mount_point")
        lazy = req.get("lazy", False)
        if not isinstance(mount_point, str) or not isinstance(lazy, bool):
            return HostHelperResponse(
                False, None, None, None, "Invalid cifs_unmount_share payload"
            )
        try:
            validated_mount_point = Path(mount_point).expanduser().resolve(strict=False)
            validated_root = _validate_cifs_mount_root(str(validated_mount_point.parent.parent))
            _safe_resolve_within(validated_root, validated_mount_point)
        except HostHelperError as exc:
            return HostHelperResponse(False, None, None, None, str(exc))

        if not validated_mount_point.exists():
            stdout = json.dumps(
                {
                    "mount_point": str(validated_mount_point),
                    "was_mounted": False,
                    "unmounted": False,
                },
                ensure_ascii=False,
            )
            return HostHelperResponse(
                True,
                0,
                stdout,
                None,
                "Mount path does not exist",
            )

        if not os.path.ismount(validated_mount_point):
            stdout = json.dumps(
                {
                    "mount_point": str(validated_mount_point),
                    "was_mounted": False,
                    "unmounted": False,
                },
                ensure_ascii=False,
            )
            return HostHelperResponse(
                True,
                0,
                stdout,
                None,
                "Path is not a mountpoint",
            )

        umount_bin = shutil_which("umount")
        if not umount_bin:
            return HostHelperResponse(False, 127, None, None, "umount not found")
        argv = [umount_bin]
        if lazy:
            argv.append("-l")
        argv.append(str(validated_mount_point))
        result = _run_cmd(argv, timeout=60)
        if not result.ok:
            return result
        stdout = json.dumps(
            {
                "mount_point": str(validated_mount_point),
                "was_mounted": True,
                "unmounted": True,
            },
            ensure_ascii=False,
        )
        return HostHelperResponse(
            True,
            0,
            stdout,
            result.stderr,
            "CIFS share unmounted",
        )

    if op == "import_file_to_workspace":
        workspace = req.get("workspace")
        src_path = req.get("src_path")
        dest_rel_path = req.get("dest_rel_path")
        if (
            not isinstance(workspace, str)
            or not isinstance(src_path, str)
            or not isinstance(dest_rel_path, str)
        ):
            return HostHelperResponse(
                False, None, None, None, "Invalid import_file_to_workspace payload"
            )

        workspace = workspace.strip()
        if not workspace or not _SAFE_WORKSPACE_RE.match(workspace):
            return HostHelperResponse(False, None, None, None, "Invalid workspace")

        src = Path(src_path).expanduser()
        try:
            src_resolved = src.resolve(strict=False)
        except OSError:
            src_resolved = src
        if not src_resolved.is_file():
            return HostHelperResponse(False, 2, None, None, "Source file not found")

        rel = Path(dest_rel_path)
        if rel.is_absolute():
            return HostHelperResponse(
                False, None, None, None, "dest_rel_path must be relative"
            )
        if any(part in {"..", ""} for part in rel.parts):
            return HostHelperResponse(False, None, None, None, "Invalid dest_rel_path")

        workspaces_root = _invoker_adscan_root_dir() / "workspaces"
        workspace_dir = workspaces_root / workspace
        try:
            workspace_dir = _safe_resolve_within(workspaces_root, workspace_dir)
        except HostHelperError as exc:
            return HostHelperResponse(False, None, None, None, str(exc))

        dst = workspace_dir / rel
        try:
            dst = _safe_resolve_within(workspace_dir, dst)
        except HostHelperError as exc:
            return HostHelperResponse(False, None, None, None, str(exc))

        try:
            dst = _unique_destination_path(dst)
            _copy_file(src_resolved, dst)
        except HostHelperError as exc:
            return HostHelperResponse(False, 1, None, None, str(exc))
        except OSError as exc:
            return HostHelperResponse(False, 1, None, str(exc), "Copy failed")

        container_dst = (
            f"{_CONTAINER_WORKSPACES_DIR}/{workspace}/{dst.relative_to(workspace_dir)}"
        )
        stdout = json.dumps(
            {"host_dest": str(dst), "container_dest": container_dst},
            ensure_ascii=False,
        )
        return HostHelperResponse(True, 0, stdout, None, "Imported file into workspace")

    if op == "select_file_gui":
        title = req.get("title")
        initial_dir = req.get("initial_dir")
        width = req.get("width")
        height = req.get("height")
        fullscreen = req.get("fullscreen")
        if title is not None and not isinstance(title, str):
            return HostHelperResponse(False, None, None, None, "Invalid title")
        if initial_dir is not None and not isinstance(initial_dir, str):
            return HostHelperResponse(False, None, None, None, "Invalid initial_dir")
        if width is not None and not isinstance(width, int):
            return HostHelperResponse(False, None, None, None, "Invalid width")
        if height is not None and not isinstance(height, int):
            return HostHelperResponse(False, None, None, None, "Invalid height")
        if fullscreen is not None and not isinstance(fullscreen, bool):
            return HostHelperResponse(False, None, None, None, "Invalid fullscreen")

        if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
            return HostHelperResponse(
                False,
                2,
                None,
                None,
                "No GUI session detected on host (DISPLAY/WAYLAND_DISPLAY is not set)",
            )

        gui_env = _build_invoker_env()

        dialog_title = (title or "Select a file").strip()[:200]
        initial_dir_path = (initial_dir or "").strip()
        safe_width = width if isinstance(width, int) and width > 0 else None
        safe_height = height if isinstance(height, int) and height > 0 else None
        want_fullscreen = bool(fullscreen) if isinstance(fullscreen, bool) else False

        # Prefer common Linux file chooser tools.
        zenity = shutil_which("zenity") or shutil_which("qarma")
        if zenity:
            argv = [zenity, "--file-selection", f"--title={dialog_title}", "--modal"]
            if initial_dir_path:
                # zenity expects a trailing slash to treat it as a directory.
                argv.append(f"--filename={initial_dir_path.rstrip('/')}/")
            if safe_width is not None:
                argv.append(f"--width={safe_width}")
            if safe_height is not None:
                argv.append(f"--height={safe_height}")
            resp = _run_capture_as_invoker(argv, env=gui_env, timeout=600)
            if not resp.ok:
                return resp
            selected = (resp.stdout or "").strip()
            if not selected:
                return HostHelperResponse(False, 3, None, None, "No file selected")
            return HostHelperResponse(True, 0, selected, None, "Selected file")

        yad = shutil_which("yad")
        if yad:
            argv = [yad, "--file", f"--title={dialog_title}", "--center"]
            if initial_dir_path:
                argv.append(f"--filename={initial_dir_path.rstrip('/')}/")
            if safe_width is not None:
                argv.append(f"--width={safe_width}")
            if safe_height is not None:
                argv.append(f"--height={safe_height}")
            if want_fullscreen:
                argv.append("--fullscreen")
            resp = _run_capture_as_invoker(argv, env=gui_env, timeout=600)
            if not resp.ok:
                return resp
            selected = (resp.stdout or "").strip()
            if not selected:
                return HostHelperResponse(False, 3, None, None, "No file selected")
            return HostHelperResponse(True, 0, selected, None, "Selected file")

        kdialog = shutil_which("kdialog")
        if kdialog:
            argv = [kdialog, "--getopenfilename"]
            if initial_dir_path:
                argv.append(initial_dir_path)
            if safe_width is not None and safe_height is not None:
                argv.extend(["--geometry", f"{safe_width}x{safe_height}"])
            resp = _run_capture_as_invoker(argv, env=gui_env, timeout=600)
            if not resp.ok:
                return resp
            selected = (resp.stdout or "").strip()
            if not selected:
                return HostHelperResponse(False, 3, None, None, "No file selected")
            return HostHelperResponse(True, 0, selected, None, "Selected file")

        return HostHelperResponse(
            False,
            127,
            None,
            None,
            "No supported file chooser found on host (zenity/yad/kdialog)",
        )

    return HostHelperResponse(False, None, None, None, f"Unsupported op: {op}")


def shutil_which(cmd: str) -> str | None:
    """Tiny `which` to avoid importing shutil in PyInstaller edge cases."""
    for path in os.getenv("PATH", "").split(os.pathsep):
        candidate = Path(path) / cmd
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def run_host_helper_server(socket_path: str) -> int:
    """Run the host helper server (blocking).

    Args:
        socket_path: Path to a unix domain socket. The parent directory must exist.

    Returns:
        Process exit code.
    """
    token = _get_shared_token()
    sock_path = Path(socket_path).expanduser()
    sock_path.parent.mkdir(parents=True, exist_ok=True)

    # Ensure stale socket is removed.
    try:
        if sock_path.exists():
            sock_path.unlink()
    except OSError:
        pass

    should_stop = False

    def _stop(_signum: int, _frame: Any) -> None:  # pragma: no cover
        nonlocal should_stop
        should_stop = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    server = socket(AF_UNIX, SOCK_STREAM)
    try:
        server.bind(str(sock_path))
        # If started via sudo, ensure the invoking user can access the socket.
        try:
            sudo_uid = int(os.getenv("SUDO_UID", "0") or "0")
            sudo_gid = int(os.getenv("SUDO_GID", "0") or "0")
        except ValueError:
            sudo_uid = 0
            sudo_gid = 0
        if sudo_uid > 0:
            try:
                os.chown(str(sock_path), sudo_uid, sudo_gid)
            except OSError:
                pass
        os.chmod(str(sock_path), 0o660)
        server.listen(5)
        server.settimeout(0.5)

        while not should_stop:
            try:
                conn, _addr = server.accept()
            except OSError:
                continue
            with conn:
                try:
                    raw = conn.recv(_MAX_REQUEST_BYTES)
                    if not raw:
                        continue
                    req = json.loads(raw.decode(errors="replace"))
                    if not isinstance(req, dict):
                        raise HostHelperError("Invalid request object")

                    sig = req.pop("sig", None)
                    if not isinstance(sig, str) or not sig:
                        raise HostHelperError("Missing sig")
                    payload = _canonical_payload(req)
                    expected = _hmac_sig(token, payload)
                    if not hmac.compare_digest(sig, expected):
                        raise HostHelperError("Invalid sig")

                    # Basic replay resistance: require timestamp within window.
                    ts = req.get("ts")
                    if not isinstance(ts, (int, float)):
                        raise HostHelperError("Missing ts")
                    if abs(time.time() - float(ts)) > 120:
                        raise HostHelperError("Request timestamp out of window")

                    resp = _handle_request(req)
                    conn.sendall(json.dumps(resp.__dict__, ensure_ascii=False).encode())
                except Exception as exc:
                    error = HostHelperResponse(
                        ok=False,
                        returncode=None,
                        stdout=None,
                        stderr=str(exc),
                        message="Host helper error",
                    )
                    try:
                        conn.sendall(json.dumps(error.__dict__).encode())
                    except Exception:
                        pass
    finally:
        try:
            server.close()
        except Exception:
            pass
        try:
            if sock_path.exists():
                sock_path.unlink()
        except Exception:
            pass
    return 0


def host_helper_client_request(
    socket_path: str,
    *,
    op: str,
    payload: dict[str, Any],
    timeout_seconds: float = 5,
) -> HostHelperResponse:
    """Send a request to the host helper server and return response."""
    path_str = str(socket_path or "").strip()
    if not path_str:
        raise HostHelperError("Invalid host helper socket path")
    sock_path = Path(path_str).expanduser()
    if not sock_path.exists():
        raise HostHelperError(
            f"Host helper socket not found: {sock_path}. "
            "The host helper may not be running."
        )

    token = _get_shared_token()
    req: dict[str, Any] = {"op": op, "ts": time.time()}
    req.update(payload)
    sig = _hmac_sig(token, _canonical_payload(req))
    req["sig"] = sig
    data = json.dumps(req, ensure_ascii=False).encode()

    sock = socket(AF_UNIX, SOCK_STREAM)
    sock.settimeout(timeout_seconds)
    try:
        sock.connect(path_str)
        sock.sendall(data)
        resp_raw = sock.recv(_MAX_REQUEST_BYTES)
    except (FileNotFoundError, ConnectionRefusedError, TimeoutError, OSError) as exc:
        raise HostHelperError(
            f"Host helper request failed (socket={sock_path}, op={op}): {exc}"
        ) from exc
    finally:
        try:
            sock.close()
        except Exception:
            pass
    if not resp_raw:
        raise HostHelperError(
            f"Empty response from host helper (socket={sock_path}, op={op})"
        )
    try:
        resp_obj = json.loads(resp_raw.decode(errors="replace"))
    except json.JSONDecodeError as exc:
        raise HostHelperError(
            f"Invalid JSON response from host helper (socket={sock_path}, op={op})"
        ) from exc
    if not isinstance(resp_obj, dict):
        raise HostHelperError("Invalid response")
    return HostHelperResponse(
        ok=bool(resp_obj.get("ok")),
        returncode=resp_obj.get("returncode"),
        stdout=resp_obj.get("stdout"),
        stderr=resp_obj.get("stderr"),
        message=resp_obj.get("message"),
    )
