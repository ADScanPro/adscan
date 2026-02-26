"""MSSQL integration via NetExec.

This package provides integration with NetExec for MSSQL exploitation:
- Remote command execution via xp_cmdshell
- SeImpersonatePrivilege verification
- Privilege escalation through MSSQL

The integration includes:
- Runner: Execute NetExec MSSQL commands with automatic error handling
- Parsers: Extract structured data from command outputs
- Helpers: Utility functions for MSSQL operations

Example usage:
    from adscan_internal.integrations.mssql import (
        MSSQLRunner,
        MSSQLContext,
        parse_whoami_priv_output,
    )

    # Setup context
    ctx = MSSQLContext(
        netexec_path="/path/to/netexec",
        command_runner=run_command_fn,
    )

    # Execute remote command
    runner = MSSQLRunner()
    result = runner.execute_command(
        host="10.0.0.1",
        ctx=ctx,
        username="admin",
        password="pass",
        command="whoami /priv",
    )

    # Check for SeImpersonatePrivilege
    if result:
        has_priv = check_seimpersonate_privilege(result.stdout)
        print(f"Has SeImpersonate: {has_priv}")
"""

from .runner import MSSQLRunner, MSSQLContext, ExecutionResult
from .parsers import (
    parse_whoami_priv_output,
    check_seimpersonate_privilege,
    parse_command_output,
    extract_netexec_mssql_output,
    check_xp_cmdshell_enabled,
    check_xp_cmdshell_disabled,
)
from .helpers import (
    build_mssql_auth_string,
    build_mssql_execute_command,
    is_hash_authentication,
)

__all__ = [
    # Runner
    "MSSQLRunner",
    "MSSQLContext",
    "ExecutionResult",
    # Parser functions
    "parse_whoami_priv_output",
    "check_seimpersonate_privilege",
    "parse_command_output",
    "extract_netexec_mssql_output",
    "check_xp_cmdshell_enabled",
    "check_xp_cmdshell_disabled",
    # Helpers
    "build_mssql_auth_string",
    "build_mssql_execute_command",
    "is_hash_authentication",
]
