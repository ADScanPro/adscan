"""Helpers for legacy BloodHound (Neo4j) configuration.

This module centralizes reading and writing of the old INI-style Neo4j
configuration used when operating BloodHound in *legacy* mode (direct Neo4j
connection instead of BloodHound CE).

Modern ADscan flows use BloodHound CE exclusively and this code path is kept
for backward compatibility and potential future reuse.
"""

from __future__ import annotations

from pathlib import Path
from typing import TypedDict

import configparser
import os
import shutil
import subprocess
import time

from adscan_internal import telemetry
from adscan_internal.rich_output import (
    print_error,
    print_exception,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_success_verbose,
    print_warning,
)
from adscan_internal.path_utils import get_adscan_home


def get_legacy_bloodhound_config_path() -> str:
    """Return the default path for the legacy Neo4j config file."""
    return str(get_adscan_home() / "bloodhound_config")


class LegacyNeo4jConfig(TypedDict, total=False):
    """Typed representation of the legacy Neo4j configuration fields."""

    host: str
    port: str
    db_user: str
    db_password: str


def load_legacy_neo4j_config(config_path: str | Path) -> LegacyNeo4jConfig | None:
    """Load legacy Neo4j configuration from an INI file.

    Args:
        config_path: Path to the INI file (typically ``bloodhound_config``).

    Returns:
        Mapping with any of ``host``, ``port``, ``db_user`` and ``db_password``
        that were present in the file, or ``None`` if the file is missing or
        could not be parsed.
    """
    path = Path(config_path)
    if not path.exists():
        return None

    parser = configparser.ConfigParser()
    try:
        parser.read(path)
        if "NEO4J" not in parser:
            return None
        section = parser["NEO4J"]
    except Exception as exc:  # pragma: no cover - defensive, legacy path
        telemetry.capture_exception(exc)
        return None

    cfg: LegacyNeo4jConfig = {}
    if "host" in section:
        cfg["host"] = section.get("host", "")
    if "port" in section:
        cfg["port"] = section.get("port", "")
    if "db_user" in section:
        cfg["db_user"] = section.get("db_user", "")
    if "db_password" in section:
        cfg["db_password"] = section.get("db_password", "")

    return cfg or None


def update_legacy_neo4j_config(
    config_path: str | Path, variable: str, value: str
) -> LegacyNeo4jConfig | None:
    """Update a single Neo4j setting in the legacy INI file.

    The calling code is responsible for deciding when to call this function.
    This helper mirrors the previous behaviour in ``adscan.py``:
    - If the config file does not exist, nothing is written.
    - Only keys in the ``[NEO4J]`` section are updated.

    Args:
        config_path: Path to the INI file.
        variable: One of ``neo4j_db_password``, ``neo4j_db_user``, ``neo4j_host`` or
            ``neo4j_port``.
        value: New value for the variable.

    Returns:
        Updated configuration mapping (same shape as :class:`LegacyNeo4jConfig`),
        or ``None`` if the file could not be updated.
    """
    path = Path(config_path)
    if not path.exists():
        return None

    parser = configparser.ConfigParser()
    try:
        parser.read(path)
        if "NEO4J" not in parser:
            parser["NEO4J"] = {}
        section = parser["NEO4J"]

        if variable == "neo4j_db_password":
            section["db_password"] = value
        elif variable == "neo4j_db_user":
            section["db_user"] = value
        elif variable == "neo4j_host":
            section["host"] = value
        elif variable == "neo4j_port":
            section["port"] = value
        else:
            # Unknown key – keep behaviour minimal and do nothing.
            return None

        with path.open("w", encoding="utf-8") as config_file:
            parser.write(config_file)
    except Exception as exc:  # pragma: no cover - defensive, legacy path
        telemetry.capture_exception(exc)
        return None

    return load_legacy_neo4j_config(path)


def _find_jdk11() -> str | None:
    """Locate a JDK 11 installation suitable for Neo4j CLI usage.

    Returns:
        Path to JDK11 installation, or None if not found.
    """
    jdk_candidates = [
        "/usr/lib/jvm/java-11-openjdk-amd64",
        "/usr/lib/jvm/java-11-openjdk",
        "/usr/lib/jvm/jdk-11",
        "/usr/lib/jvm/adoptopenjdk-11-hotspot-amd64",
    ]
    for jdk_path in jdk_candidates:
        if os.path.isdir(jdk_path):
            return jdk_path
    return None


def _run_neo4j_command(command: str, timeout: int = 30) -> subprocess.CompletedProcess | None:
    """Run a Neo4j CLI command with a minimal JDK-aware environment.

    Args:
        command: Neo4j sub-command (for example ``status``, ``start``, ``stop``).
        timeout: Command timeout in seconds.

    Returns:
        The completed process instance, or ``None`` if ``neo4j`` is not available
        or an unexpected failure occurred.
    """
    try:
        if not shutil.which("neo4j"):
            return None

        jdk11_path = _find_jdk11()

        env = os.environ.copy()
        if jdk11_path:
            env["JAVA_HOME"] = jdk11_path

        result = subprocess.run(
            ["neo4j", command],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            check=False,
        )
        return result
    except Exception as exc:  # pragma: no cover - defensive, legacy path
        telemetry.capture_exception(exc)
        print_error(f"Error running neo4j {command}.")
        print_exception(show_locals=False, exception=exc)
        return None


def run_neo4j_command(command: str, timeout: int = 30) -> subprocess.CompletedProcess | None:
    """Public wrapper around :func:`_run_neo4j_command`.

    Exposed for legacy CLI paths that need to execute raw Neo4j commands.
    """
    return _run_neo4j_command(command, timeout=timeout)


def check_neo4j_running() -> bool:
    """Return True if the Neo4j service reports itself as running."""
    try:
        result = _run_neo4j_command("status", timeout=30)
        if result:
            return "Neo4j is running" in (result.stdout or "")
        return False
    except Exception as exc:  # pragma: no cover - defensive, legacy path
        telemetry.capture_exception(exc)
        print_error("Error checking Neo4j status.")
        print_exception(show_locals=False, exception=exc)
        return False


def ensure_neo4j_running(max_attempts: int = 5, poll_interval: int = 2) -> bool:
    """Ensure the Neo4j system service is running; try to start it if not.

    Args:
        max_attempts: Maximum number of status checks after starting.
        poll_interval: Seconds to wait between status checks.

    Returns:
        True if Neo4j is running, False otherwise.
    """
    try:
        if check_neo4j_running():
            print_info_verbose("Neo4j is already running")
            return True

        print_info("Starting neo4j...")
        print_info_debug("Running command: neo4j start")
        start_result = _run_neo4j_command("start", timeout=300)

        if start_result:
            print_info_debug(
                f"neo4j start returncode={start_result.returncode}, "
                f"stdout={start_result.stdout}, stderr={start_result.stderr}"
            )
            if start_result.returncode != 0:
                print_error(
                    f"Failed to start Neo4j: return code {start_result.returncode}"
                )
                if start_result.stderr:
                    print_error(start_result.stderr)
                return False

        print_info_verbose("Waiting for Neo4j to initialize...")
        for i in range(max_attempts):
            print_info_debug(f"Polling 'neo4j status' (attempt {i + 1})")
            if check_neo4j_running():
                print_success_verbose(
                    f"Neo4j is running (after {i * poll_interval}s)"
                )
                return True
            time.sleep(poll_interval)

        print_error("Neo4j is not running after start command")
        return False
    except Exception as exc:  # pragma: no cover - defensive, legacy path
        telemetry.capture_exception(exc)
        print_error("Error ensuring Neo4j is running.")
        print_exception(show_locals=False, exception=exc)
        return False


def ensure_neo4j_not_running(max_attempts: int = 5, poll_interval: int = 2) -> bool:
    """Ensure Neo4j is not running; try to stop it to avoid port conflicts.

    This is primarily used to avoid conflicts with the BloodHound CE Neo4j
    container (bolt port 7687).
    """
    try:
        if not check_neo4j_running():
            print_info_verbose(
                "Neo4j service is not running - safe to start BloodHound CE"
            )
            return True

        print_warning(
            "Neo4j service is running and will conflict with BloodHound CE (port 7687)"
        )
        print_info("Stopping Neo4j service...")
        print_info_debug("Running command: neo4j stop")

        stop_result = _run_neo4j_command("stop", timeout=300)

        if stop_result:
            print_info_debug(
                f"neo4j stop returncode={stop_result.returncode}, "
                f"stdout={stop_result.stdout}, stderr={stop_result.stderr}"
            )
            if stop_result.returncode != 0:
                print_error(
                    f"Failed to stop Neo4j: return code {stop_result.returncode}"
                )
                if stop_result.stderr:
                    print_error(stop_result.stderr)
                return False

        print_info_verbose("Waiting for Neo4j to stop...")
        for i in range(max_attempts):
            print_info_debug(f"Polling 'neo4j status' (attempt {i + 1})")
            if not check_neo4j_running():
                print_success_verbose(
                    f"Neo4j stopped successfully (after {i * poll_interval}s)"
                )
                return True
            time.sleep(poll_interval)

        print_error("Neo4j is still running after stop command")
        return False
    except Exception as exc:  # pragma: no cover - defensive, legacy path
        telemetry.capture_exception(exc)
        print_error("Error ensuring Neo4j is stopped.")
        print_exception(show_locals=False, exception=exc)
        return False


def stop_neo4j_if_running() -> None:
    """Stop Neo4j service if active to avoid port 7687 conflicts with BloodHound CE.
    
    This is a simple helper that uses systemctl to stop Neo4j. For more robust
    stopping with polling and verification, use :func:`ensure_neo4j_not_running`.
    """
    try:
        # systemctl path might not exist in containers; handle gracefully
        rc = subprocess.run(
            ["systemctl", "is-active", "--quiet", "neo4j"],
            capture_output=True,
            check=False,
        ).returncode
        if rc == 0:
            print_warning(
                "Neo4j service is active; stopping it to avoid port conflicts with BloodHound CE (bolt 7687)..."
            )
            subprocess.run(["systemctl", "stop", "neo4j"], check=False)
            print_info_verbose("Neo4j service stopped.")
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_warning(f"Could not verify/stop Neo4j service: {exc}")


def get_bloodhound_mode() -> str:
    """Return the active BloodHound mode ('ce', 'legacy' or 'unknown').

    This is a thin wrapper around the canonical helper defined in the main
    CLI module (``adscan.get_bloodhound_mode``), exposed here so that
    internal helpers (for example ``adscan_internal.cli.ldap``) can query
    the current mode without importing the monolithic CLI at module import
    time. The import is intentionally lazy to avoid circular import issues.
    """
    try:
        # Local import to avoid circular imports at module import time.
        from adscan import get_bloodhound_mode as _core_get_bloodhound_mode

        return _core_get_bloodhound_mode()
    except Exception as exc:  # pragma: no cover - defensive
        telemetry.capture_exception(exc)
        return "unknown"


def _check_bloodhound_ce_running() -> bool:
    """Return True if the BloodHound CE containers appear to be running.

    This is a legacy-facing proxy to the canonical helper in ``adscan.py``.
    It keeps the modular CLI paths working without importing the monolith at
    module import time.
    """
    try:
        from adscan import _check_bloodhound_ce_running as _core_check_bh_ce_running

        return _core_check_bh_ce_running()
    except Exception as exc:  # pragma: no cover - defensive, legacy path
        telemetry.capture_exception(exc)
        print_error("Error checking BloodHound CE containers.")
        print_exception(show_locals=False, exception=exc)
        return False


def _start_bloodhound_ce() -> bool:
    """Start the BloodHound CE stack (legacy proxy).

    Delegates to the canonical helper in ``adscan.py`` while retaining the
    legacy module entrypoint for CLI orchestration.
    """
    try:
        from adscan import _start_bloodhound_ce as _core_start_bh_ce

        return _core_start_bh_ce()
    except Exception as exc:  # pragma: no cover - defensive, legacy path
        telemetry.capture_exception(exc)
        print_error("Error starting BloodHound CE.")
        print_exception(show_locals=False, exception=exc)
        return False
