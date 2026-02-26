"""Impacket tools integration.

This package provides integration with Impacket tools for credential attacks:
- Kerberoasting (GetUserSPNs)
- AS-REP Roasting (GetNPUsers)
- DCSync and secretsdump (secretsdump)

The integration includes:
- Runner: Execute Impacket tools with automatic error handling
- Parsers: Extract structured data from tool outputs
- Helpers: Utility functions for path management and credential formatting

Example usage:
    from adscan_internal.integrations.impacket import (
        ImpacketRunner,
        ImpacketContext,
        parse_kerberoast_output,
    )

    # Setup context
    ctx = ImpacketContext(
        impacket_scripts_dir="/path/to/impacket",
        validate_script_exists=lambda p: os.path.isfile(p),
        get_domain_pdc=lambda d: "dc.example.local",
    )

    # Run Kerberoasting
    runner = ImpacketRunner(command_runner=cmd_runner)
    result = runner.run_getuserspns(
        domain="example.local",
        ctx=ctx,
        username="user",
        password="pass",
        request=True,
    )

    # Parse output
    if result:
        hashes = parse_kerberoast_output(result.stdout)
        for hash_entry in hashes:
            print(f"Found: {hash_entry.username}")
"""

from .runner import ImpacketRunner, ImpacketContext, ExecutionResult
from .parsers import (
    KerberoastHash,
    ASREPHash,
    NTLMHash,
    parse_kerberoast_output,
    parse_asreproast_output,
    parse_secretsdump_output,
    extract_usernames_from_kerberoast,
    extract_usernames_from_asreproast,
    count_hashes,
)
from .helpers import (
    get_impacket_script_path,
    validate_impacket_script,
    format_hashes_for_impacket,
    get_output_file_path,
    parse_domain_user,
    build_auth_string,
    build_auth_impacket,
    build_auth_impacket_no_host,
)

__all__ = [
    # Runner
    "ImpacketRunner",
    "ImpacketContext",
    "ExecutionResult",
    # Parser types
    "KerberoastHash",
    "ASREPHash",
    "NTLMHash",
    # Parser functions
    "parse_kerberoast_output",
    "parse_asreproast_output",
    "parse_secretsdump_output",
    "extract_usernames_from_kerberoast",
    "extract_usernames_from_asreproast",
    "count_hashes",
    # Helpers
    "get_impacket_script_path",
    "validate_impacket_script",
    "format_hashes_for_impacket",
    "get_output_file_path",
    "parse_domain_user",
    "build_auth_string",
    "build_auth_impacket",
    "build_auth_impacket_no_host",
]
