"""Post-BloodHound orchestration helpers.

This module keeps post-collector CE flow logic out of ``adscan.py``.
"""

from __future__ import annotations

from typing import Protocol
import os

from rich.prompt import Prompt

from adscan_internal import (
    print_error,
    print_exception,
    print_instruction,
    telemetry,
)
from adscan_internal.bloodhound_legacy import get_bloodhound_mode
from adscan_internal.cli.bloodhound import upload_bloodhound_ce_zip_files


class PostBloodHoundShell(Protocol):
    """Minimal shell surface required for post-BloodHound helpers."""

    def run_enumeration(
        self,
        domain: str,
        *,
        stop_after_phase: int | None = None,
    ) -> None: ...

    neo4j_host: str
    neo4j_port: str
    neo4j_db_user: str
    neo4j_db_password: str

    def _get_bloodhound_cli_path(self) -> str | None: ...


def run_post_bloodhound(
    shell: PostBloodHoundShell,
    domain: str,
    *,
    stop_after_phase: int | None = None,
    legacy_config_path: str,
) -> None:
    """Handle post-BloodHound flow for CE and legacy modes."""
    Prompt.ask(
        "Press Enter once you have completed the import to continue with the enumeration...",
        default="",
    )

    if get_bloodhound_mode() == "ce":
        shell.run_enumeration(domain, stop_after_phase=stop_after_phase)
        return

    if os.path.exists(legacy_config_path):
        shell.run_enumeration(domain, stop_after_phase=stop_after_phase)
        return

    shell.neo4j_host = Prompt.ask("Enter the neo4j host", default="localhost")
    shell.neo4j_port = Prompt.ask("Enter the neo4j port", default="7687")
    shell.neo4j_db_user = Prompt.ask("Enter the neo4j database user", default="neo4j")
    shell.neo4j_db_password = Prompt.ask(
        "Enter the neo4j database password", default="neo4j"
    )

    bh_cli = shell._get_bloodhound_cli_path()
    if not bh_cli:
        print_error("bloodhound-cli is required to configure Neo4j.")
        return

    cmd = (
        f"{bh_cli} set --host {shell.neo4j_host} --port {shell.neo4j_port} "
        f"--db-user {shell.neo4j_db_user} --db-password {shell.neo4j_db_password}"
    )
    from adscan_internal.cli.enum import execute_neo4j_config_and_continue

    execute_neo4j_config_and_continue(shell, cmd, domain)


def run_post_bloodhound_ce(
    shell: PostBloodHoundShell,
    domain: str,
    *,
    stop_after_phase: int | None = None,
) -> None:
    """Handle post-BloodHound CE flow and continue enumeration."""
    try:
        upload_bloodhound_ce_zip_files(
            shell,
            domain,
            wait_for_manual_on_failure=True,
        )
        shell.run_enumeration(domain, stop_after_phase=stop_after_phase)
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Error in post-BloodHound CE processing.")
        print_exception(show_locals=False, exception=exc)
        print_instruction("Please manually upload the ZIP file to BloodHound CE UI.")
        Prompt.ask(
            "Press Enter once you have completed the import to continue with the enumeration...",
            default="",
        )
        shell.run_enumeration(domain, stop_after_phase=stop_after_phase)


__all__ = ["run_post_bloodhound", "run_post_bloodhound_ce"]
