"""Internal helper modules for the ADscan CLI."""

import os
import sys

# In PyInstaller-frozen binaries, some third-party Pydantic plugins (for example
# observability integrations) call inspect.getsource() during model creation and
# fail with "OSError: could not get source code" because sources are bundled.
# Disable Pydantic plugins globally in that runtime.
if getattr(sys, "frozen", False):
    os.environ.setdefault("PYDANTIC_DISABLE_PLUGINS", "__all__")

from .command_runner import CommandRunner, CommandSpec, default_runner
from .rich_output import (
    init_rich_output,
    get_console,
    set_telemetry_console,
    update_modes,
    reset_spacing,
    print_info,
    print_info_verbose,
    print_info_debug,
    print_success,
    print_success_verbose,
    print_success_debug,
    print_success_tick,
    print_warning,
    print_warning_verbose,
    print_warning_debug,
    print_error,
    print_error_verbose,
    print_error_debug,
    print_instruction,
    print_panel,
    print_table,
    print_panel_with_table,
    print_exception,
    print_section,
    print_info_table,
    print_info_list,
    print_group,
    print_table_debug,
    print_attack_path_detail_debug,
    create_progress,
    create_status,
    create_styled_table,
    create_summary_table,
    create_findings_table,
    create_status_table,
    print_code,
    print_command,
    print_error_context,
    print_operation_header,
    print_scan_status,
    print_results_summary,
    print_domain_info,
    create_domains_table,
    create_credentials_table,
    TelemetryAwareConsole,
)
from .sessions import SessionManager, SessionType, RemoteSession
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
from . import sudo_utils
from . import telemetry
from . import theme
try:
    from . import report_generator
except ImportError:  # pragma: no cover - public LITE repo excludes report generation
    report_generator = None

__all__ = [
    "CommandRunner",
    "CommandSpec",
    "default_runner",
    "init_rich_output",
    "get_console",
    "set_telemetry_console",
    "update_modes",
    "reset_spacing",
    "print_info",
    "print_info_verbose",
    "print_info_debug",
    "print_success",
    "print_success_verbose",
    "print_success_debug",
    "print_success_tick",
    "print_warning",
    "print_warning_verbose",
    "print_warning_debug",
    "print_error",
    "print_error_verbose",
    "print_error_debug",
    "print_instruction",
    "print_panel",
    "print_table",
    "print_panel_with_table",
    "print_exception",
    "print_section",
    "print_info_table",
    "print_info_list",
    "print_group",
    "print_table_debug",
    "print_attack_path_detail_debug",
    "create_progress",
    "create_status",
    "create_styled_table",
    "create_summary_table",
    "create_findings_table",
    "create_status_table",
    "print_code",
    "print_command",
    "print_error_context",
    "print_operation_header",
    "print_scan_status",
    "print_results_summary",
    "print_domain_info",
    "create_domains_table",
    "create_credentials_table",
    "SessionManager",
    "SessionType",
    "RemoteSession",
    "AgentSession",
    "build_python_agent_one_liner",
    "get_agent_ng_local_path",
    "get_current_ligolo_proxy_target",
    "get_ligolo_agent_local_path",
    "get_ligolo_checksums_url",
    "get_ligolo_proxy_local_path",
    "get_ligolo_release_asset_name",
    "get_ligolo_release_download_url",
    "get_runascs_local_path",
    "SessionShell",
    "sudo_utils",
    "telemetry",
    "theme",
    "report_generator",
    "TelemetryAwareConsole",
]
