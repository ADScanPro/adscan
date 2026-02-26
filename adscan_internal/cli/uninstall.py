"""Legacy uninstall command handler."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil
from typing import Callable

from adscan_internal import (
    print_error,
    print_exception,
    print_info,
    print_success,
    telemetry,
)


@dataclass(frozen=True)
class UninstallConfig:
    """Configuration for uninstalling ADscan data."""

    adscan_base_dir: str


@dataclass(frozen=True)
class UninstallDeps:
    """Dependency bundle for uninstall flow."""

    confirm_ask: Callable[[str, bool], bool]


def run_uninstall(*, config: UninstallConfig, deps: UninstallDeps) -> None:
    """Remove ADscan data under the base directory, preserving the id file."""
    if not deps.confirm_ask(
        "This will remove all ADscan data (workspaces, installation dependencies, etc). Continue?",
        False,
    ):
        print_info("Uninstall cancelled.")
        return

    base_dir = Path(config.adscan_base_dir)
    id_file = base_dir / "id"
    for entry in base_dir.iterdir():
        if entry == id_file:
            continue
        if entry.is_dir():
            shutil.rmtree(entry, ignore_errors=True)
            continue
        try:
            entry.unlink()
        except Exception as exc:  # noqa: BLE001 - legacy best-effort cleanup
            print_error("Failed to remove.")
            print_exception(show_locals=False, exception=exc)

    print_success("Uninstallation complete. ADscan data removed.")
    telemetry._capture_user_property_event(  # pylint: disable=protected-access
        "uninstalled",
        "installation_status",
        "uninstalled",
    )
