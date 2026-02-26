"""Internal helpers for ADscan password spraying.

This module vendors the core functionality previously provided by the external
`spray.py` helper. It is intentionally side-effect-light: it builds commands,
parses outputs, and computes eligibility lists; the caller (typically `adscan.py`)
is responsible for executing commands and handling UI/telemetry.
"""

from __future__ import annotations

import os
import re
import shlex
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional

from adscan_internal.integrations.netexec.helpers import build_auth_nxc
from adscan_internal.text_utils import normalize_cli_output


@dataclass(frozen=True, slots=True)
class ExcludedUser:
    """Represents a user excluded from spraying with a reason."""

    username: str
    reason: str
    badpwd_count: Optional[int] = None
    remaining_attempts: Optional[int] = None


@dataclass(frozen=True, slots=True)
class SprayEligibilityResult:
    """Result of computing eligible users for spraying.

    Attributes:
        input_users: Users loaded from the provided file (in file order).
        eligible_users: Eligible users (subset of input_users).
        excluded_users: Excluded users with reasons (in file order).
        lockout_threshold: Parsed domain lockout threshold (if available).
        safe_remaining_threshold: Safety threshold used for eligibility.
        used_policy_data: True when lockout policy/badpwd counts were used.
        notes: Human-readable notes about fallbacks/limitations.
    """

    input_users: list[str]
    eligible_users: list[str]
    excluded_users: list[ExcludedUser]
    lockout_threshold: Optional[int]
    safe_remaining_threshold: int
    used_policy_data: bool
    notes: list[str]


_ACCOUNT_LOCKOUT_THRESHOLD_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\baccount\s+lockout\s+threshold\s*[:=]\s*(\d+)\b"),
    re.compile(r"(?i)\blockout\s+threshold\s*[:=]\s*(\d+)\b"),
    # Spanish-ish (best-effort)
    re.compile(r"(?i)\bumbral\s+de\s+bloqueo\s+de\s+cuenta\s*[:=]\s*(\d+)\b"),
    re.compile(r"(?i)\bumbral\s+de\s+bloqueo\s*[:=]\s*(\d+)\b"),
)

_BADPWDCOUNT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\bbadpwdcount\s*[:=]\s*(\d+)\b"),
    re.compile(r"(?i)\bbad\s*pwd\s*count\s*[:=]\s*(\d+)\b"),
)

_USERNAME_TOKEN_RE = re.compile(r"(?i)[a-z0-9._$-]+(?:\\[a-z0-9._$-]+)?")


def read_user_list(path: str) -> list[str]:
    """Read a user list file (one username per line).

    Args:
        path: Path to the user list.

    Returns:
        List of usernames in file order (duplicates removed preserving order).

    Raises:
        OSError: When the file cannot be read.
    """
    data = Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
    seen: set[str] = set()
    users: list[str] = []
    for raw in data:
        user = raw.strip()
        if not user:
            continue
        norm = normalize_username(user)
        if norm in seen:
            continue
        seen.add(norm)
        users.append(user)
    return users


def normalize_username(username: str) -> str:
    """Normalize a username for comparisons across tool outputs.

    Normalizes common formats:
    - `DOMAIN\\user` -> `user`
    - `user@domain`  -> `user`
    - strips trailing separators and whitespace
    - lower-cases for consistent matching
    """
    value = (username or "").strip()
    if "\\" in value:
        value = value.rsplit("\\", 1)[-1]
    if "@" in value:
        value = value.split("@", 1)[0]
    return value.strip().lower()


def parse_netexec_lockout_threshold(output: str) -> Optional[int]:
    """Parse Account Lockout Threshold from NetExec `--pass-pol` output.

    Args:
        output: Raw stdout text from NetExec.

    Returns:
        Parsed threshold as integer, or None if it cannot be determined.
    """
    normalized = normalize_cli_output(output)
    for pattern in _ACCOUNT_LOCKOUT_THRESHOLD_PATTERNS:
        match = pattern.search(normalized)
        if match:
            try:
                return int(match.group(1))
            except ValueError:
                return None
    return None


def parse_netexec_users_badpwd(output: str) -> dict[str, int]:
    """Best-effort parser for NetExec `--users` output.

    NetExec output formatting can vary by version/environment. This function aims
    to extract `(username, BadPwdCount)` pairs without relying on fixed column
    positions or language-specific strings.

    Args:
        output: Raw stdout text from NetExec.

    Returns:
        Mapping of normalized username -> bad password count.
    """
    normalized = normalize_cli_output(output)
    lines = [line.rstrip("\r\n") for line in normalized.splitlines()]

    # Restrict parsing to the table block printed by `--users`. This prevents
    # accidentally parsing non-row lines like successful authentication banners
    # (which contain the port number 445 and can be misinterpreted as BadPW).
    header_index: int | None = None
    for idx, line in enumerate(lines):
        lower = line.lower()
        if "-username-" in lower and "-badpw-" in lower:
            header_index = idx
            break

    if header_index is None:
        return {}

    footer_index: int | None = None
    for idx in range(header_index + 1, len(lines)):
        lower = lines[idx].lower()
        if "local users" in lower and "enumerated" in lower:
            footer_index = idx
            break

    if footer_index is None:
        footer_index = len(lines)

    data_lines = lines[header_index + 1 : footer_index]
    results: dict[str, int] = {}

    date_re = re.compile(r"^\d{4}-\d{2}-\d{2}$")
    time_re = re.compile(r"^\d{2}:\d{2}:\d{2}(?:\.\d+)?$")
    for raw_line in data_lines:
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 6:
            continue

        status_idx = next(
            (i for i, token in enumerate(parts) if token in {"[+]", "[-]", "[*]"}),
            None,
        )
        if status_idx is not None:
            username_idx = status_idx + 1
        else:
            # Typical NetExec `--users` rows do not include [+]/[-]/[*] tokens.
            # Format prefix: SMB <ip> <port> <hostname> <username> <date> <time> <badpw> ...
            username_idx = 4

        if username_idx >= len(parts):
            continue

        user_token = parts[username_idx]
        norm_user = normalize_username(user_token)
        if not norm_user:
            continue

        # Determine the index where BadPW should appear:
        # After the username, NetExec prints Last PW Set (date + time OR <never>),
        # then BadPW (integer), then description.
        idx = username_idx + 1
        if idx >= len(parts):
            continue

        if parts[idx].startswith("<") and parts[idx].endswith(">"):
            idx += 1
        elif date_re.fullmatch(parts[idx]) and idx + 1 < len(parts) and time_re.fullmatch(
            parts[idx + 1]
        ):
            idx += 2

        if idx >= len(parts):
            continue

        badpw_value: Optional[int] = None
        # Prefer explicit BadPwdCount tokens when present on the line.
        for pattern in _BADPWDCOUNT_PATTERNS:
            match = pattern.search(line)
            if match:
                try:
                    badpw_value = int(match.group(1))
                    break
                except ValueError:
                    badpw_value = None

        if badpw_value is None:
            try:
                badpw_value = int(parts[idx])
            except ValueError:
                continue

        results[norm_user] = badpw_value

    return results


def compute_spray_eligibility(
    *,
    file_users: list[str],
    lockout_threshold: Optional[int],
    badpwd_by_user: Mapping[str, int] | None,
    safe_remaining_threshold: int,
    strict_missing_badpwd: bool = True,
) -> SprayEligibilityResult:
    """Compute eligible users based on lockout threshold and BadPwdCount.

    If lockout data is unavailable, all users are considered eligible.
    """
    notes: list[str] = []
    eligible: list[str] = []
    excluded: list[ExcludedUser] = []

    used_policy_data = (
        lockout_threshold is not None
        and badpwd_by_user is not None
        and len(badpwd_by_user) > 0
    )

    # Explicitly handle domains with no lockout threshold (e.g., "None" from NetExec)
    if lockout_threshold is None and badpwd_by_user:
        notes.append(
            "Account lockout threshold is None (no lockout enforced). All users are "
            "eligible; spraying cannot lock accounts, but use caution."
        )
        return SprayEligibilityResult(
            input_users=list(file_users),
            eligible_users=list(file_users),
            excluded_users=[],
            lockout_threshold=lockout_threshold,
            safe_remaining_threshold=safe_remaining_threshold,
            used_policy_data=False,
            notes=notes,
        )

    if not used_policy_data:
        notes.append(
            "Lockout policy or BadPwdCount data unavailable; using full user list."
        )
        notes.append(
            "Warning: Account lockout threshold could not be determined. Proceed with "
            "caution to avoid locking accounts; recommended to wait at least 1 hour "
            "between spraying attempts."
        )
        return SprayEligibilityResult(
            input_users=list(file_users),
            eligible_users=list(file_users),
            excluded_users=[],
            lockout_threshold=lockout_threshold,
            safe_remaining_threshold=safe_remaining_threshold,
            used_policy_data=False,
            notes=notes,
        )

    assert lockout_threshold is not None
    assert badpwd_by_user is not None

    for user in file_users:
        norm_user = normalize_username(user)
        if norm_user not in badpwd_by_user:
            if strict_missing_badpwd:
                excluded.append(
                    ExcludedUser(
                        username=user, reason="No BadPwdCount data (safer to skip)"
                    )
                )
            else:
                eligible.append(user)
            continue

        badpwd = int(badpwd_by_user[norm_user])
        remaining = lockout_threshold - badpwd
        if remaining > safe_remaining_threshold:
            eligible.append(user)
        else:
            excluded.append(
                ExcludedUser(
                    username=user,
                    reason=f"Too close to lockout (remaining={remaining})",
                    badpwd_count=badpwd,
                    remaining_attempts=remaining,
                )
            )

    return SprayEligibilityResult(
        input_users=list(file_users),
        eligible_users=eligible,
        excluded_users=excluded,
        lockout_threshold=lockout_threshold,
        safe_remaining_threshold=safe_remaining_threshold,
        used_policy_data=True,
        notes=notes,
    )


def write_temp_users_file(users: list[str], *, directory: str) -> str:
    """Write users to a temporary file and return its path.

    The file is created with mode 0600 when possible.
    """
    Path(directory).mkdir(parents=True, exist_ok=True)
    tmp = tempfile.NamedTemporaryFile(
        mode="w",
        delete=False,
        dir=directory,
        prefix="spray_users_",
        suffix=".txt",
        encoding="utf-8",
    )
    try:
        for user in users:
            tmp.write(user + "\n")
        tmp.flush()
    finally:
        tmp.close()
    try:
        os.chmod(tmp.name, 0o600)
    except OSError:
        # Best-effort; on some FS this may fail.
        pass
    return tmp.name


def build_netexec_pass_pol_command(
    *,
    nxc_path: str,
    dc_ip: str,
    username: str,
    password: str,
    domain: str,
    kerberos: bool = False,
) -> str:
    """Build a NetExec command to query password policy (`--pass-pol`)."""
    auth = build_auth_nxc(username, password, domain, kerberos=kerberos)
    return (
        f"{shlex.quote(nxc_path)} smb {shlex.quote(dc_ip)} "
        f"{auth} --pass-pol"
    )


def build_netexec_users_command(
    *,
    nxc_path: str,
    dc_ip: str,
    username: str,
    password: str,
    domain: str,
    kerberos: bool = False,
) -> str:
    """Build a NetExec command to query users (`--users`)."""
    auth = build_auth_nxc(username, password, domain, kerberos=kerberos)
    return (
        f"{shlex.quote(nxc_path)} smb {shlex.quote(dc_ip)} "
        f"{auth} --users"
    )


def build_netexec_computers_query_command(
    *,
    nxc_path: str,
    dc_ip: str,
    username: str,
    password: str,
    domain: str,
    kerberos: bool = False,
) -> str:
    """Build a NetExec LDAP command to query computer BadPwdCount data."""
    query = "(objectCategory=computer)"
    attrs = "sAMAccountName badPwdCount lockoutTime badPasswordTime"
    auth = build_auth_nxc(username, password, domain, kerberos=kerberos)
    return (
        f"{shlex.quote(nxc_path)} ldap {shlex.quote(dc_ip)} "
        f"{auth} --query {shlex.quote(query)} {shlex.quote(attrs)}"
    )


def build_kerbrute_command(
    *,
    kerbrute_path: Optional[str],
    domain: str,
    dc_ip: str,
    users_file: str,
    output_file: str,
    password: Optional[str] = None,
    user_as_pass: bool = False,
) -> str:
    """Build a kerbrute command for spraying.

    Returns a shell-safe command string (caller typically executes with shell=True).
    """
    kerbrute_cmd = kerbrute_path or "kerbrute"
    parts: list[str] = [
        kerbrute_cmd,
        "passwordspray",
        "-d",
        domain,
        "--dc",
        dc_ip,
    ]
    if user_as_pass:
        parts.extend(["--user-as-pass", users_file])
    else:
        parts.append(users_file)
        if password is not None:
            parts.append(password)
        else:
            # Fallback to brute-force mode (matches prior spray.py behaviour).
            parts[1] = "bruteforce"

    parts.extend(["-o", output_file])
    return " ".join(shlex.quote(part) for part in parts)


def build_kerbrute_bruteforce_command(
    *,
    kerbrute_path: Optional[str],
    domain: str,
    dc_ip: str,
    combos_file: str,
    output_file: str,
) -> str:
    """Build a kerbrute bruteforce command for username:password combos."""
    kerbrute_cmd = kerbrute_path or "kerbrute"
    parts: list[str] = [
        kerbrute_cmd,
        "bruteforce",
        "-d",
        domain,
        "--dc",
        dc_ip,
        combos_file,
        "-o",
        output_file,
    ]
    return " ".join(shlex.quote(part) for part in parts)


def safe_log_filename_fragment(value: str, *, max_length: int = 32) -> str:
    """Return a filesystem-safe fragment for log filenames.

    This is used for user-provided passwords (custom spray password) to avoid
    breaking paths or creating invalid filenames.
    """
    if not value:
        return "empty"
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "_", value).strip("._-")
    if not cleaned:
        cleaned = "value"
    return cleaned[:max_length]


def write_temp_combo_file(
    combos: list[str],
    *,
    directory: str | None = None,
) -> str:
    """Write username:password combos to a temporary file."""
    tmp = tempfile.NamedTemporaryFile(
        mode="w",
        delete=False,
        dir=directory,
        prefix="spray_combos_",
        suffix=".txt",
        encoding="utf-8",
    )
    try:
        for combo in combos:
            tmp.write(combo + "\n")
        tmp.flush()
    finally:
        tmp.close()
    try:
        os.chmod(tmp.name, 0o600)
    except OSError:
        pass
    return tmp.name
