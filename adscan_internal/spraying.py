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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Optional


@dataclass(frozen=True, slots=True)
class ExcludedUser:
    """Represents a user excluded from spraying with a reason."""

    username: str
    reason: str
    badpwd_count: Optional[int] = None
    remaining_attempts: Optional[int] = None


@dataclass(frozen=True, slots=True)
class EligibleUser:
    """An eligible (will-be-sprayed) user with its lockout headroom.

    Mirror of :class:`ExcludedUser` for the accounts that WILL be sprayed, so the
    eligibility panel can show their current BadPwdCount + remaining attempts and
    not just the excluded ones. ``badpwd_count`` / ``remaining_attempts`` are
    ``None`` when the user was included conservatively without policy data.
    ``policy_note`` labels the lockout policy that produced the headroom — e.g.
    ``"PSO 'TIER0' · thr 3"`` (readable PSO) or
    ``"PSO 'TIER0' unreadable · thr 3"`` (conservative fallback) — and is ``None``
    for the plain domain policy.
    """

    username: str
    badpwd_count: Optional[int] = None
    remaining_attempts: Optional[int] = None
    policy_note: Optional[str] = None


@dataclass(frozen=True, slots=True)
class SprayEligibilityResult:
    """Result of computing eligible users for spraying.

    Attributes:
        input_users: Users loaded from the provided file (in file order).
        eligible_users: Eligible users (subset of input_users).
        excluded_users: Excluded users with reasons (in file order).
        lockout_threshold: Parsed domain lockout threshold (if available).
        safe_remaining_threshold: Safety threshold used for eligibility.
        minimum_remaining_attempts: Minimum remaining attempts across eligible
            principals after considering current BadPwdCount values.
        used_policy_data: True when lockout policy/badpwd counts were used.
        notes: Human-readable notes about fallbacks/limitations.
        no_lockout_enforced: True when the domain reports no enforceable lockout
            (``lockout_threshold`` is ``None`` or ``0``, or the policy service
            decided no lockout applies). Stored as an explicit boolean rather
            than derived at every call site because the policy-service computation
            already combined ``lockout_threshold == 0`` with extra signals (PSO
            absence, ``msDS-LockoutThreshold`` reads, etc.) that the bare
            threshold field cannot reproduce. Downstream callers in
            ``cli/spraying.py`` consult this to gate variation sprays and to
            decide whether to enforce the safe-attempt reserve. Defaults to
            ``False`` so legacy constructors that never knew about this flag
            keep behaving like "lockout is enforced" — the conservative direction.
    """

    input_users: list[str]
    eligible_users: list[str]
    excluded_users: list[ExcludedUser]
    lockout_threshold: Optional[int]
    safe_remaining_threshold: int
    minimum_remaining_attempts: Optional[int]
    used_policy_data: bool
    notes: list[str]
    no_lockout_enforced: bool = False
    eligible_details: list["EligibleUser"] = field(default_factory=list)
    """Per-eligible-user lockout headroom (username + BadPwdCount + remaining), for
    the eligibility panel. Empty on legacy/no-policy paths; render falls back to the
    plain ``eligible_users`` list when so."""


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


def compute_spray_eligibility(
    *,
    file_users: list[str],
    lockout_threshold: Optional[int],
    badpwd_by_user: Mapping[str, int] | None,
    safe_remaining_threshold: int,
    no_lockout_enforced: bool = False,
    strict_missing_badpwd: bool = True,
) -> SprayEligibilityResult:
    """Compute eligible users based on lockout threshold and BadPwdCount.

    If lockout data is unavailable, all users are considered eligible.
    """
    notes: list[str] = []
    eligible: list[str] = []
    excluded: list[ExcludedUser] = []

    if no_lockout_enforced:
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
            minimum_remaining_attempts=None,
            used_policy_data=True,
            notes=notes,
            no_lockout_enforced=True,
        )

    if lockout_threshold == 0:
        notes.append(
            "Account lockout threshold is 0 (no lockout enforced). All users are "
            "eligible; spraying cannot lock accounts."
        )
        return SprayEligibilityResult(
            input_users=list(file_users),
            eligible_users=list(file_users),
            excluded_users=[],
            lockout_threshold=lockout_threshold,
            safe_remaining_threshold=safe_remaining_threshold,
            minimum_remaining_attempts=None,
            used_policy_data=True,
            notes=notes,
            no_lockout_enforced=True,
        )

    used_policy_data = (
        lockout_threshold is not None
        and badpwd_by_user is not None
        and len(badpwd_by_user) > 0
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
            minimum_remaining_attempts=None,
            used_policy_data=False,
            notes=notes,
        )

    assert lockout_threshold is not None
    assert badpwd_by_user is not None
    minimum_remaining_attempts: int | None = None
    eligible_details: list[EligibleUser] = []

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
                eligible_details.append(EligibleUser(username=user))
            continue

        badpwd = int(badpwd_by_user[norm_user])
        remaining = lockout_threshold - badpwd
        if remaining > safe_remaining_threshold:
            eligible.append(user)
            eligible_details.append(
                EligibleUser(
                    username=user, badpwd_count=badpwd, remaining_attempts=remaining
                )
            )
            if minimum_remaining_attempts is None:
                minimum_remaining_attempts = remaining
            else:
                minimum_remaining_attempts = min(minimum_remaining_attempts, remaining)
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
        minimum_remaining_attempts=minimum_remaining_attempts,
        used_policy_data=True,
        notes=notes,
        eligible_details=eligible_details,
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
    # ``-v`` makes kerbrute log ONE line per attempted login (valid AND
    # invalid) -- empirically confirmed against lab.local (kerbrute v1.0.3) --
    # so the live dashboard can drive a DETERMINATE ``tested / N`` bar. The
    # authoritative hit parse is ``VALID LOGIN``-anchored, so the extra ``[!]``
    # lines ``-v`` adds are ignored for credential capture.
    parts: list[str] = [
        kerbrute_cmd,
        "passwordspray",
        "-v",
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
    # ``-v``: one log line per attempted combo (valid AND invalid) for the
    # determinate live bar; hit parse stays ``VALID LOGIN``-anchored.
    parts: list[str] = [
        kerbrute_cmd,
        "bruteforce",
        "-v",
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
