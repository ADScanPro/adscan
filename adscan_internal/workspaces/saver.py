"""Workspace data saving functionality.

This module handles saving workspace and domain variables to JSON files.
"""

from __future__ import annotations

import os
from typing import Any, Protocol

from adscan_internal import telemetry
from adscan_internal.rich_output import (
    print_error,
    print_exception,
    print_info,
    print_success,
    print_warning,
)
from adscan_internal.workspaces.io import write_json_file
from adscan_internal.workspaces.state import (
    collect_domain_variables_from_shell,
    collect_workspace_variables_from_shell,
)


class WorkspaceSaverShell(Protocol):
    """Protocol for shell methods needed by save functions."""

    current_workspace: str | None
    current_workspace_dir: str | None
    current_domain: str | None
    current_domain_dir: str | None
    variables: dict[str, Any] | None


def save_workspace_data(shell: WorkspaceSaverShell) -> bool:
    """Save the current workspace data (variables) to JSON files.

    Args:
        shell: CLI shell instance that implements WorkspaceSaverShell protocol

    Returns:
        True if saved successfully, False otherwise
    """
    if not shell.current_workspace or not shell.current_workspace_dir:
        # This check is now primarily in workspace_save, but good for direct calls too
        print_warning("No active workspace to save.")
        return False  # Indicate failure

    # print_info(f"Saving workspace data to: {self.current_workspace_dir}")
    saved_successfully = True

    # Ensure the workspace directory exists (it should if selected/created properly)
    try:
        os.makedirs(shell.current_workspace_dir, exist_ok=True)
    except OSError as e:
        telemetry.capture_exception(e)
        print_error(
            f"Could not create or access workspace directory {shell.current_workspace_dir}: {e}"
        )
        print_exception(show_locals=False, exception=e)
        return False

    current_variables = collect_workspace_variables_from_shell(shell)
    # Update shell.variables with the current state before saving
    if hasattr(shell, "variables") and isinstance(shell.variables, dict):
        shell.variables.update(current_variables)
    else:
        shell.variables = current_variables

    variables_file = os.path.join(shell.current_workspace_dir, "variables.json")
    try:
        write_json_file(variables_file, shell.variables)
        # print_info(f"Variables saved to {variables_file}")
    except TypeError as e:
        telemetry.capture_exception(e)
        print_error("TypeError: Could not serialize variables to JSON.")
        print_exception(show_locals=False, exception=e)
        saved_successfully = False
    except OSError as e:
        telemetry.capture_exception(e)
        print_error(f"OS error writing variables to {variables_file}.")
        print_exception(show_locals=False, exception=e)
        saved_successfully = False
    except Exception as e:
        telemetry.capture_exception(e)
        print_error(f"Unexpected error saving variables to {variables_file}.")
        print_exception(show_locals=False, exception=e)
        saved_successfully = False

    # The calling function (workspace_save) will print overall success/failure
    return saved_successfully


def save_domain_data(shell: WorkspaceSaverShell) -> bool:
    """Save the current domain data (variables) to JSON files.

    Args:
        shell: CLI shell instance that implements WorkspaceSaverShell protocol

    Returns:
        True if saved successfully, False otherwise
    """
    if not shell.current_domain or not shell.current_domain_dir:
        print_warning(
            "No active domain selected or domain directory not set. Cannot save domain data."
        )
        return False  # Indicate failure

    print_info(f"Saving domain data to: {shell.current_domain_dir}")
    saved_successfully = True

    # Ensure the domain directory exists
    try:
        os.makedirs(shell.current_domain_dir, exist_ok=True)
    except OSError as e:
        telemetry.capture_exception(e)
        print_error(
            f"Could not create or access domain directory {shell.current_domain_dir}: {e}"
        )
        print_exception(show_locals=False, exception=e)
        return False

    domain_variables = collect_domain_variables_from_shell(shell)

    variables_file = os.path.join(shell.current_domain_dir, "variables.json")
    try:
        write_json_file(variables_file, domain_variables)
        print_info(f"Domain variables saved to {variables_file}")
    except TypeError as e:
        telemetry.capture_exception(e)
        print_error("TypeError: Could not serialize domain variables to JSON.")
        print_exception(show_locals=False, exception=e)
        saved_successfully = False
    except OSError as e:
        telemetry.capture_exception(e)
        print_error(f"OS error writing domain variables to {variables_file}.")
        print_exception(show_locals=False, exception=e)
        saved_successfully = False
    except Exception as e:
        telemetry.capture_exception(e)
        print_error(
            f"Unexpected error saving domain variables to {variables_file}: {e}"
        )
        print_exception(show_locals=False, exception=e)
        saved_successfully = False

    if saved_successfully:
        print_success(
            f"Domain data for '{shell.current_domain}' successfully saved to {shell.current_domain_dir}"
        )
    else:
        print_error(
            f"Failed to fully save domain data for '{shell.current_domain}'. Check errors above."
        )

    return saved_successfully


__all__ = ["save_workspace_data", "save_domain_data", "WorkspaceSaverShell"]

