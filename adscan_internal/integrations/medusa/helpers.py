"""Command builders and models for Medusa integration."""

from __future__ import annotations

from dataclasses import dataclass
import os
import shlex


@dataclass(frozen=True)
class MedusaSweepSettings:
    """Execution settings for one Medusa login sweep."""

    total_logins: int
    concurrent_hosts: int
    connect_timeout_seconds: int
    retry_count: int
    retry_sleep_seconds: int
    verbose_level: int = 4
    suppress_banner: bool = True


def build_medusa_login_sweep_command(
    *,
    medusa_path: str,
    protocol: str,
    targets: str,
    username: str,
    password: str,
    settings: MedusaSweepSettings,
    log_file: str | None = None,
    module_arguments: list[str] | None = None,
) -> str:
    """Build one Medusa login sweep command."""
    target_value = os.path.expanduser(str(targets or "").strip())
    target_flag = "-H" if os.path.isfile(target_value) else "-h"

    parts = [
        shlex.quote(medusa_path),
        target_flag,
        shlex.quote(target_value),
        "-u",
        shlex.quote(username),
        "-p",
        shlex.quote(password),
        "-M",
        shlex.quote(protocol),
        "-t",
        str(max(settings.total_logins, 1)),
        "-T",
        str(max(settings.concurrent_hosts, 1)),
        "-g",
        str(max(settings.connect_timeout_seconds, 1)),
        "-r",
        str(max(settings.retry_sleep_seconds, 0)),
        "-R",
        str(max(settings.retry_count, 0)),
        "-v",
        str(max(settings.verbose_level, 0)),
    ]

    if settings.suppress_banner:
        parts.append("-b")
    if log_file:
        parts.extend(["-O", shlex.quote(log_file)])
    for module_argument in module_arguments or []:
        normalized_argument = str(module_argument or "").strip()
        if normalized_argument:
            parts.extend(["-m", shlex.quote(normalized_argument)])

    return " ".join(parts)
