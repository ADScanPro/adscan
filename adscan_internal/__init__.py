"""Internal helper modules for the ADscan CLI.

This package intentionally exposes a convenience surface for the CLI, but it
must stay lightweight at import time because backend/runtime helpers import
submodules such as ``adscan_internal.services.attack_graph_core``.

To avoid pulling optional runtime dependencies (WinRM/DNS/session tooling,
telemetry transports, etc.) just by importing the package root, all public
exports are resolved lazily through ``__getattr__``.
"""
# ruff: noqa: F401

from __future__ import annotations

import importlib
import os
import sys
from typing import TYPE_CHECKING, Any

_STATIC_ANALYSIS = TYPE_CHECKING or "pylint" in sys.modules

# In PyInstaller-frozen binaries, some third-party Pydantic plugins (for example
# observability integrations) call inspect.getsource() during model creation and
# fail with "OSError: could not get source code" because sources are bundled.
# Disable Pydantic plugins globally in that runtime.
if getattr(sys, "frozen", False):
    os.environ.setdefault("PYDANTIC_DISABLE_PLUGINS", "__all__")

if _STATIC_ANALYSIS:
    from .command_runner import CommandRunner, CommandSpec, default_runner
    from .rich_output import (
        TelemetryAwareConsole,
        create_credentials_table,
        create_domains_table,
        create_findings_table,
        create_progress,
        create_status,
        create_status_table,
        create_styled_table,
        create_summary_table,
        get_console,
        init_rich_output,
        print_attack_path_detail_debug,
        print_code,
        print_command,
        print_domain_info,
        print_error,
        print_error_context,
        print_error_debug,
        print_error_verbose,
        print_exception,
        print_group,
        print_info,
        print_info_debug,
        print_info_list,
        print_info_table,
        print_info_verbose,
        print_instruction,
        print_operation_header,
        print_panel,
        print_panel_with_table,
        print_results_summary,
        print_scan_status,
        print_section,
        print_success,
        print_success_debug,
        print_success_tick,
        print_success_verbose,
        print_table,
        print_table_debug,
        print_warning,
        print_warning_debug,
        print_warning_verbose,
        reset_spacing,
        set_telemetry_console,
        update_modes,
    )
    from .sessions import RemoteSession, SessionManager, SessionType
    from .agent_protocol import AgentSession
    from .agent_payload import build_python_agent_one_liner
    from .agent_ng_manager import get_agent_ng_local_path
    from .ligolo_manager import (
        get_current_ligolo_proxy_target,
        get_ligolo_agent_local_path,
        get_ligolo_checksums_url,
        get_ligolo_proxy_local_path,
        get_ligolo_release_asset_name,
        get_ligolo_release_download_url,
    )
    from .runascs_manager import get_runascs_local_path
    from .session_shell import SessionShell
    from . import report_generator, sudo_utils, telemetry, theme


_EXPORT_MODULES: dict[str, str] = {
    "CommandRunner": ".command_runner",
    "CommandSpec": ".command_runner",
    "default_runner": ".command_runner",
    "init_rich_output": ".rich_output",
    "get_console": ".rich_output",
    "set_telemetry_console": ".rich_output",
    "update_modes": ".rich_output",
    "reset_spacing": ".rich_output",
    "print_info": ".rich_output",
    "print_info_verbose": ".rich_output",
    "print_info_debug": ".rich_output",
    "print_success": ".rich_output",
    "print_success_verbose": ".rich_output",
    "print_success_debug": ".rich_output",
    "print_success_tick": ".rich_output",
    "print_warning": ".rich_output",
    "print_warning_verbose": ".rich_output",
    "print_warning_debug": ".rich_output",
    "print_error": ".rich_output",
    "print_error_verbose": ".rich_output",
    "print_error_debug": ".rich_output",
    "print_instruction": ".rich_output",
    "print_panel": ".rich_output",
    "print_table": ".rich_output",
    "print_panel_with_table": ".rich_output",
    "print_exception": ".rich_output",
    "print_section": ".rich_output",
    "print_info_table": ".rich_output",
    "print_info_list": ".rich_output",
    "print_group": ".rich_output",
    "print_table_debug": ".rich_output",
    "print_attack_path_detail_debug": ".rich_output",
    "create_progress": ".rich_output",
    "create_status": ".rich_output",
    "create_styled_table": ".rich_output",
    "create_summary_table": ".rich_output",
    "create_findings_table": ".rich_output",
    "create_status_table": ".rich_output",
    "print_code": ".rich_output",
    "print_command": ".rich_output",
    "print_error_context": ".rich_output",
    "print_operation_header": ".rich_output",
    "print_scan_status": ".rich_output",
    "print_results_summary": ".rich_output",
    "print_domain_info": ".rich_output",
    "create_domains_table": ".rich_output",
    "create_credentials_table": ".rich_output",
    "TelemetryAwareConsole": ".rich_output",
    "SessionManager": ".sessions",
    "SessionType": ".sessions",
    "RemoteSession": ".sessions",
    "AgentSession": ".agent_protocol",
    "build_python_agent_one_liner": ".agent_payload",
    "get_agent_ng_local_path": ".agent_ng_manager",
    "get_current_ligolo_proxy_target": ".ligolo_manager",
    "get_ligolo_agent_local_path": ".ligolo_manager",
    "get_ligolo_checksums_url": ".ligolo_manager",
    "get_ligolo_proxy_local_path": ".ligolo_manager",
    "get_ligolo_release_asset_name": ".ligolo_manager",
    "get_ligolo_release_download_url": ".ligolo_manager",
    "get_runascs_local_path": ".runascs_manager",
    "SessionShell": ".session_shell",
    "sudo_utils": ".sudo_utils",
    "telemetry": ".telemetry",
    "theme": ".theme",
    "report_generator": ".report_generator",
}

__all__ = list(_EXPORT_MODULES)


def __getattr__(name: str) -> Any:
    """Resolve public exports lazily.

    This keeps ``import adscan_internal`` lightweight for secondary consumers
    such as the web backend while preserving the existing convenience API for
    CLI code.
    """
    module_name = _EXPORT_MODULES.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    try:
        module = importlib.import_module(module_name, __name__)
    except ImportError:
        if name == "report_generator":
            globals()[name] = None
            return None
        raise

    value = module if name in {"sudo_utils", "telemetry", "theme", "report_generator"} else getattr(module, name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Return a stable module dir for interactive discovery."""
    return sorted(set(globals()) | set(__all__))
