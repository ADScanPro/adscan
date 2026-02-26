"""Certipy LDAPS->LDAP fallback helpers.

Certipy frequently defaults to LDAPS for LDAP-backed operations, but many
environments (labs and real deployments) do not have LDAPS enabled on domain
controllers. These helpers provide:

- A conservative heuristic to detect LDAPS/TLS failures from output
- Safe command rewriting to retry with ``-ldap-scheme ldap``
- Marking sensitive values for telemetry sanitization (passwords/hashes)
"""

from __future__ import annotations

import re

from adscan_internal.rich_output import mark_sensitive

_LDAPS_ERROR_TOKENS: tuple[str, ...] = (
    "ldaps",
    "ssl",
    "tls",
    "certificate verify failed",
    "unknown ca",
    "handshake",
    "sslerror",
    "starttls",
    "socket ssl",
    "server is unavailable",
    "can't contact ldap server",
    "connection refused",
    "timed out",
)

_CERTIPY_SCHEME_SUBCOMMANDS: tuple[str, ...] = ("find", "req", "template", "ca")


def sanitize_certipy_command_for_logging(command: str) -> str:
    """Mark sensitive arguments in a Certipy command string (no redaction).

    The CLI should show real values to the operator. Telemetry sanitization is
    handled elsewhere, based on these markers.

    Args:
        command: Raw command string.

    Returns:
        Command string with sensitive values wrapped in ``mark_sensitive``.
    """
    try:
        def _mark_flag_value(match: re.Match[str], *, kind: str) -> str:
            prefix = match.group("prefix")
            value = match.group("value")
            return f"{prefix}{mark_sensitive(value, kind)}"

        command = re.sub(
            r"(?P<prefix>\s-p\s+)(?P<value>'[^']*'|\"[^\"]*\"|\S+)",
            lambda m: _mark_flag_value(m, kind="password"),
            command,
        )
        command = re.sub(
            r"(?P<prefix>\s-hashes\s+)(?P<value>\S+)",
            lambda m: _mark_flag_value(m, kind="hash"),
            command,
        )
        command = re.sub(
            r"(?P<prefix>\s-pfx-password\s+)(?P<value>'[^']*'|\"[^\"]*\"|\S+)",
            lambda m: _mark_flag_value(m, kind="password"),
            command,
        )
        return command
    except Exception:
        return command


def certipy_output_indicates_ldaps_issue(
    stdout: str | None, stderr: str | None
) -> bool:
    """Return True when output likely indicates an LDAPS/TLS/connectivity issue."""
    combined = f"{stdout or ''}\n{stderr or ''}".lower()
    return any(token in combined for token in _LDAPS_ERROR_TOKENS)


def command_includes_scheme(command: str) -> bool:
    """Return True when the command already specifies a scheme."""
    # Certipy v4 used ``-scheme``; Certipy v5 uses ``-ldap-scheme``.
    return bool(re.search(r"\b(-scheme|-ldap-scheme)\b", command))


def command_supports_scheme_fallback(command: str) -> bool:
    """Return True when the command is a Certipy subcommand that supports ``-scheme``."""
    m = re.search(r"\bcertipy\b\s+([a-zA-Z0-9_-]+)\b", command)
    if not m:
        return False
    subcommand = m.group(1).lower()
    return subcommand in _CERTIPY_SCHEME_SUBCOMMANDS


def append_scheme_ldap(command: str) -> str:
    """Append LDAP scheme flags to a Certipy command (if not already present).

    Certipy v5 uses ``-ldap-scheme ldap`` (defaults to LDAPS otherwise).
    """
    if command_includes_scheme(command):
        return command
    return f"{command} -ldap-scheme ldap"


def extract_pfx_path_from_output(output: str) -> str | None:
    """Extract a generated PFX file path from Certipy output.

    Args:
        output: Certipy stdout content.

    Returns:
        PFX file name or path if present, otherwise None.
    """
    match = re.search(r"'([^']+\.pfx)'", output, flags=re.IGNORECASE)
    if match:
        return match.group(1)
    return None


__all__ = [
    "append_scheme_ldap",
    "certipy_output_indicates_ldaps_issue",
    "command_includes_scheme",
    "command_supports_scheme_fallback",
    "extract_pfx_path_from_output",
    "sanitize_certipy_command_for_logging",
]
