#!/usr/bin/env python3
"""
BloodHound CLI - Modular Architecture
"""

# pylint: disable=wrong-import-position,redefined-builtin,too-many-branches,too-many-statements,broad-exception-caught,line-too-long,import-outside-toplevel

import os
import sys
import argparse
import configparser

# Fix imports when running as script directly
if __name__ == "__main__" and __package__ is None:
    # Add parent directory to path to allow imports
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    __package__ = "bloodhound_cli"

from . import __version__ as PACKAGE_VERSION
from .core.factory import create_bloodhound_client
from .core.logging_utils import configure_logging, get_logger
from .core.settings import (
    BLOODHOUND_CE_DEFAULT_WEB_PORT,
    CEConfig,
    CONFIG_FILE,
    load_ce_config,
    load_legacy_config,
)

LOGGER = get_logger("cli")


def get_cli_version() -> str:
    """Return the CLI version string."""
    return PACKAGE_VERSION or "unknown"


CLI_VERSION = get_cli_version()


def load_config():
    """Load configuration from the resolved config path."""
    config_path = str(CONFIG_FILE)
    if os.path.exists(config_path):
        config = configparser.ConfigParser()
        config.read(config_path)
        return config
    return None


def output_results(results, output_file=None, verbose=False, result_type="results"):
    """Output results to console or file"""
    if output_file:
        try:
            with open(output_file, "w", encoding="utf-8") as result_file:
                for result in results:
                    result_file.write(f"{result}\n")
            if verbose:
                print(f"Results saved to {output_file}")
        except OSError as exc:
            print(f"Error writing to file {output_file}: {exc}")
            # Fallback to console output
            for result in results:
                print(result)
    else:
        if verbose:
            print(f"Displaying {len(results)} {result_type}")
        for result in results:
            print(result)


def get_client(edition: str, **kwargs):
    """Get BloodHound client based on edition"""
    if edition.lower() == "legacy":
        legacy_settings = load_legacy_config()
        uri = kwargs.get("uri", legacy_settings.uri)
        user = kwargs.get("user", legacy_settings.user)
        password = kwargs.get("password", legacy_settings.password)

        return create_bloodhound_client(
            "legacy",
            uri=uri,
            user=user,
            password=password,
            debug=kwargs.get("debug", False),
            verbose=kwargs.get("verbose", False),
        )

    if edition.lower() == "ce":
        ce_settings = load_ce_config()
        # Convert base_url to string (handles Pydantic AnyHttpUrl objects)
        default_base_url = (
            str(ce_settings.base_url)
            if ce_settings.base_url
            else f"http://localhost:{BLOODHOUND_CE_DEFAULT_WEB_PORT}"
        )
        client = create_bloodhound_client(
            "ce",
            base_url=kwargs.get("base_url", default_base_url),
            api_token=kwargs.get("api_token", ce_settings.api_token),
            debug=kwargs.get("debug", False),
            verbose=kwargs.get("verbose", False),
            verify=kwargs.get("verify", ce_settings.verify),
        )

        if not client.ensure_valid_token():
            username = kwargs.get("username", ce_settings.username)
            password = kwargs.get(
                "ce_password", kwargs.get("password", ce_settings.password)
            )
            if password is None:
                raise ValueError("CE password not provided and not configured")
            client.authenticate(username, password)

        return client

    raise ValueError(f"Unsupported edition: {edition}")


def cmd_users(args):
    """List users in a domain"""
    logger = LOGGER.bind(command="user", edition=args.edition, domain=args.domain)
    client = get_client(
        args.edition,
        uri=args.uri,
        user=args.user,
        password=args.password,
        base_url=args.base_url,
        username=args.username,
        ce_password=getattr(args, "ce_password", "Adscan4thewin!"),
        debug=args.debug,
        verbose=args.verbose,
    )

    try:
        if args.debug:
            logger.debug(
                "creating client",
                password_provided=bool(args.password),
                high_value=args.high_value,
                admin_count=args.admin_count,
                pwd_ne=args.password_never_expires,
                pwd_not_required=args.password_not_required,
                specific_user=args.user or "all",
            )

        # Determine which function to call based on parameters
        if args.password_last_change:
            password_info = client.get_password_last_change(args.domain, args.user)
            if args.verbose:
                if args.user:
                    print(
                        f"Password last change information for user {args.user} in domain {args.domain}:"
                    )
                else:
                    print(
                        f"Password last change information for all users in domain {args.domain}:"
                    )

            # Format password info for output
            results = []
            for info in password_info:
                results.append(
                    f"{info['samaccountname']}: pwdlastset={info['pwdlastset']}, whencreated={info['whencreated']}"
                )

            output_results(results, args.output, args.verbose, "password info")
            return

        if getattr(args, "ou_dn", None):
            if args.edition.lower() != "ce":
                print(
                    "Filtering users by OU is only available for BloodHound CE (--edition ce)."
                )
                return
            users = client.get_users_in_ou(args.domain, args.ou_dn)
            user_type = f"users in OU {args.ou_dn}"
        elif args.high_value:
            users = client.get_highvalue_users(args.domain)
            user_type = "high value users"
        elif args.admin_count:
            users = client.get_admin_users(args.domain)
            user_type = "admin users"
        elif args.password_never_expires:
            users = client.get_password_never_expires_users(args.domain)
            user_type = "users with password never expires"
        elif args.password_not_required:
            users = client.get_password_not_required_users(args.domain)
            user_type = "users with password not required"
        else:
            users = client.get_users(args.domain)
            user_type = "users"

        if args.debug:
            logger.debug("retrieved users", count=len(users), result_type=user_type)

        if args.verbose:
            print(f"Found {len(users)} {user_type} in domain {args.domain}")

        # Output results to console or file
        output_results(users, args.output, False, user_type)

    finally:
        client.close()


def cmd_group(args):
    """List group membership for a user"""
    logger = LOGGER.bind(
        command="group", edition=args.edition, domain=args.domain, user=args.group_user
    )
    client = get_client(
        args.edition,
        uri=args.uri,
        user=args.user,
        password=args.password,
        base_url=args.base_url,
        username=args.username,
        ce_password=getattr(args, "ce_password", "Adscan4thewin!"),
        debug=args.debug,
        verbose=args.verbose,
    )

    recursive = not args.direct_only

    try:
        if args.debug:
            logger.debug("fetching user groups", recursive=recursive)

        groups = client.get_user_groups(
            domain=args.domain, username=args.group_user, recursive=recursive
        )

        if not groups:
            print(f"No groups found for user {args.group_user} in domain {args.domain}")
            return

        if args.verbose:
            scope = "recursive" if recursive else "direct"
            print(
                f"User {args.group_user} belongs to {len(groups)} "
                f"{scope} group(s) in domain {args.domain}"
            )

        output_results(groups, args.output, False, "groups")

    finally:
        client.close()


def cmd_version(args):  # pylint: disable=unused-argument
    """Display the CLI version."""
    print(f"bloodhound-cli {CLI_VERSION}")


def register_group_subcommand(subparsers):
    """Register the 'group' command parser."""
    group_parser = subparsers.add_parser(
        "group", help="List group memberships for a user", aliases=["groups"]
    )
    group_parser.add_argument(
        "-d", "--domain", required=True, help="Domain that contains the user"
    )
    group_parser.add_argument(
        "-u",
        "--user",
        dest="group_user",
        required=True,
        help="User to enumerate group memberships for",
    )
    group_parser.add_argument(
        "--direct-only",
        action="store_true",
        help="Show only direct group memberships (skip recursive expansion)",
    )
    group_parser.set_defaults(func=cmd_group)


def register_version_subcommand(subparsers):
    """Register the 'version' command parser."""
    version_parser = subparsers.add_parser("version", help="Show CLI version")
    version_parser.set_defaults(func=cmd_version)


def cmd_computers(args):
    """List computers in a domain"""
    logger = LOGGER.bind(command="computer", edition=args.edition, domain=args.domain)
    client = get_client(
        args.edition,
        uri=args.uri,
        user=args.user,
        password=args.password,
        base_url=args.base_url,
        username=args.username,
        ce_password=getattr(args, "ce_password", "Adscan4thewin!"),
        debug=args.debug,
        verbose=args.verbose,
    )

    try:
        # Convert laps string to boolean if provided
        laps_filter = None
        if args.laps:
            laps_filter = args.laps.lower() == "true"

        computers = client.get_computers(args.domain, laps=laps_filter)

        if args.verbose:
            print(f"Found {len(computers)} computers in domain {args.domain}")
        if args.debug:
            logger.debug(
                "retrieved computers", count=len(computers), laps_filter=laps_filter
            )

        # Output results to console or file
        output_results(computers, args.output, False, "computers")

    finally:
        client.close()


def cmd_sessions(args):
    """List user sessions in a domain"""
    logger = LOGGER.bind(command="session", edition=args.edition, domain=args.domain)
    client = get_client(
        args.edition,
        uri=args.uri,
        user=args.user,
        password=args.password,
        base_url=args.base_url,
        username=args.username,
        ce_password=getattr(args, "ce_password", "Adscan4thewin!"),
        debug=args.debug,
        verbose=args.verbose,
    )

    try:
        if args.debug:
            logger.debug("fetching sessions", domain_admin_only=args.da)
        sessions = client.get_sessions(args.domain, da=args.da)

        if args.verbose:
            if args.da:
                print(
                    f"Found {len(sessions)} sessions from computer perspective in domain {args.domain}"
                )
            else:
                print(
                    f"Found {len(sessions)} sessions from user perspective in domain {args.domain}"
                )

        # Format sessions for output
        results = []
        for session in sessions:
            if args.da:
                # Computer -> User format
                results.append(f"{session['computer']} -> {session['user']}")
            else:
                # User -> Computer format
                results.append(f"{session['user']} -> {session['computer']}")

        # Output results to console or file
        output_results(results, args.output, args.verbose, "sessions")

    finally:
        client.close()


def cmd_acl(args):
    """List critical ACEs"""
    logger = LOGGER.bind(command="acl", edition=args.edition)

    client = get_client(
        args.edition,
        uri=args.uri,
        user=args.user,
        password=args.password,
        base_url=args.base_url,
        username=args.username,
        ce_password=getattr(args, "ce_password", "Adscan4thewin!"),
        debug=args.debug,
        verbose=args.verbose,
    )

    try:
        # Determine if high-value filter is requested via -t high-value
        high_value = args.target and args.target.lower() == "high-value"

        if args.debug:
            logger.debug(
                "fetching critical aces",
                source_domain=args.source_domain,
                source=args.source,
                relation=args.relation,
                target=args.target,
                high_value=high_value,
            )

        # Use get_critical_aces with all parameters
        source = args.source or "all"
        target = args.target or "all"
        relation = args.relation or "all"

        # If target is "high-value", set it to "all" and use high_value flag
        if target.lower() == "high-value":
            target = "all"

        aces = client.get_critical_aces(
            source_domain=args.source_domain,
            high_value=high_value,
            username=source,
            target_domain=target,
            relation=relation,
        )

        # Print header similar to old_main.py print_aces
        value_suffix = " (high-value targets only)" if high_value else ""
        print(
            f"\nACLs for source: {source}, target: {target}, "
            f"source domain: {args.source_domain}, target domain: {target}{value_suffix}"
        )
        print("=" * 80)

        if not aces:
            print("No ACLs found for the given parameters")
            return

        if args.verbose:
            print(f"Found {len(aces)} critical ACEs")

        # Format ACEs for output - detailed format like old_main.py
        if args.output:
            # For file output, use simple format
            results = []
            for ace in aces:
                ace_str = f"{ace['source']} -> {ace['target']} ({ace['relation']})"
                results.append(ace_str)
            output_results(results, args.output, False, "ACEs")
        else:
            # For console output, use detailed format like print_aces
            for ace in aces:
                print(f"\nSource: {ace['source']}")
                print(f"Source Type: {ace.get('sourceType', 'N/A')}")
                print(f"Source Domain: {ace.get('sourceDomain', 'N/A')}")
                print(f"Target: {ace['target']}")
                print(f"Target Type: {ace.get('targetType', 'N/A')}")
                print(f"Target Domain: {ace.get('targetDomain', 'N/A')}")
                if not ace.get("targetEnabled", True):
                    print(f"Target Enabled: {ace['targetEnabled']}")
                print(f"Relation: {ace['relation']}")
                print("-" * 80)

        if args.debug:
            logger.debug("retrieved aces", count=len(results))

    finally:
        client.close()


def cmd_upload(args):
    """Upload data to BloodHound CE"""
    logger = LOGGER.bind(command="upload")

    client = get_client(
        args.edition,
        uri=args.uri,
        user=args.user,
        password=args.password,
        base_url=args.base_url,
        username=args.username,
        ce_password=getattr(args, "ce_password", "Adscan4thewin!"),
        debug=args.debug,
        verbose=args.verbose,
    )

    try:
        if args.list_jobs:
            # List upload jobs
            if args.debug:
                logger.debug("listing upload jobs")
            jobs = client.list_upload_jobs()
            if args.verbose:
                print(f"Found {len(jobs)} upload jobs")

            results = []
            for job in jobs:
                job_info = f"Job ID: {job.get('id', 'N/A')}, Status: {job.get('status', 'N/A')}, Created: {job.get('created_at', 'N/A')}"
                results.append(job_info)

            output_results(results, args.output, args.verbose, "upload jobs")

        elif args.accepted_types:
            # Show accepted file types
            if args.debug:
                logger.debug("listing accepted upload types")
            types = client.get_accepted_upload_types()
            if args.verbose:
                print(f"Accepted file types: {', '.join(types)}")

            output_results(types, args.output, args.verbose, "accepted types")

        else:
            # Upload file
            if not args.file:
                print(
                    "Error: File path required for upload. Use -f/--file to specify the file to upload."
                )
                return

            if not os.path.exists(args.file):
                print(f"Error: File {args.file} does not exist")
                return

            if args.verbose:
                print(f"Uploading file: {args.file}")
                print(f"Wait for completion: {args.wait}")
                if args.wait:
                    print(f"Poll interval: {args.poll_interval} seconds")
                    print(f"Timeout: {args.timeout} seconds")

            if args.debug:
                logger.debug("starting upload", file=args.file)
            if args.wait:
                # Use the new upload_and_wait method
                success = client.upload_data_and_wait(
                    args.file,
                    poll_interval=args.poll_interval,
                    timeout_seconds=args.timeout,
                )
            else:
                # Use the simple upload method
                success = client.upload_data(args.file)
                if success:
                    if args.verbose:
                        print("✅ File uploaded successfully")
                    else:
                        print("Upload successful")
                else:
                    print("❌ Upload failed")
                    return

    finally:
        client.close()


def cmd_access(args):
    """Find access paths between objects"""
    if args.debug:
        print(f"Debug: Creating client for edition {args.edition}")
        print(f"Debug: Source = {args.source}")
        print(f"Debug: Target = {args.target}")
        print(f"Debug: Domain = {args.domain}")
        print(f"Debug: Relation = {args.relation}")

    client = get_client(
        args.edition,
        uri=args.uri,
        user=args.user,
        password=args.password,
        base_url=args.base_url,
        username=args.username,
        ce_password=getattr(args, "ce_password", "Adscan4thewin!"),
        debug=args.debug,
        verbose=args.verbose,
    )

    try:
        paths = client.get_access_paths(
            source=args.source,
            connection=args.relation or "all",
            target=args.target,
            domain=args.domain,
        )

        if args.verbose:
            print(
                f"\nAccess paths for source: {args.source}, connection: {args.relation or 'all'}, target: {args.target}, domain: {args.domain}"
            )
            print("=" * 80)

        if not paths:
            if args.verbose:
                print("No access paths found")
            else:
                print("No access paths found")
            return

        # Format paths for output
        results = []
        for path in paths:
            if args.verbose:
                print(f"\nSource: {path['source']}")
                print(f"Target: {path['target']}")
                print(f"Relation: {path['relation']}")
                print(f"Path: {path['path']}")
                print("-" * 40)
            else:
                results.append(path["path"])

        if not args.verbose:
            output_results(results, args.output, False, "access paths")

    finally:
        client.close()


def cmd_auth(args):
    """Authenticate to BloodHound CE and save API token"""
    logger = LOGGER.bind(command="auth")
    import getpass

    if args.debug:
        logger.debug("authenticating", base_url=args.url, username=args.username)

    settings = load_ce_config()
    password = args.password or settings.password
    if not password:
        password = getpass.getpass("CE Password: ")

    # Create a temporary client for authentication
    from .core.ce import BloodHoundCEClient

    client = BloodHoundCEClient(base_url=args.url, verify=not args.insecure)

    try:
        # Authenticate
        token = client.authenticate(args.username, password, args.login_path)

        if not token:
            print("Authentication failed")
            return

        new_settings = CEConfig(
            base_url=args.url,
            api_token=token,
            username=args.username,
            password=password,
            verify=not args.insecure,
        )

        config = configparser.ConfigParser()
        if CONFIG_FILE.exists():
            config.read(CONFIG_FILE)

        config["CE"] = {
            "base_url": str(new_settings.base_url),
            "api_token": new_settings.api_token or "",
            "username": new_settings.username,
            "password": new_settings.password or "",
            "verify": str(new_settings.verify).lower(),
        }
        if "GENERAL" not in config:
            config["GENERAL"] = {}
        config["GENERAL"]["edition"] = "ce"

        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as config_file:
                config.write(config_file)
            print(f"CE configuration saved at {CONFIG_FILE}")
            print("Authentication successful. Token saved to configuration.")
            logger.info("token saved", path=CONFIG_FILE)
        except OSError as exc:
            logger.error("failed to save config", error=str(exc), path=CONFIG_FILE)
            print(f"Error saving configuration: {exc}")
            print("Authentication successful, but failed to save token.")

    except Exception as auth_error:  # pylint: disable=broad-exception-caught
        logger.exception("authentication error", error=str(auth_error))
        print(f"Authentication error: {auth_error}")

    finally:
        client.close()


def main():
    """Main CLI entry point"""
    # Load configuration to get default edition
    config = load_config()
    default_edition = "ce"  # fallback default to CE
    if config and "GENERAL" in config and "edition" in config["GENERAL"]:
        default_edition = config["GENERAL"]["edition"]

    parser = argparse.ArgumentParser(description="BloodHound CLI")
    parser.add_argument(
        "--edition",
        choices=["legacy", "ce"],
        default=default_edition,
        help="BloodHound edition to use",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )
    parser.add_argument("-o", "--output", help="Output file to save results")
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {CLI_VERSION}",
        help="Show CLI version and exit",
    )

    # Legacy connection options
    parser.add_argument(
        "--uri", default="bolt://localhost:7687", help="Neo4j URI for legacy edition"
    )
    parser.add_argument("--user", default="neo4j", help="Neo4j username")
    parser.add_argument("--password", help="Neo4j password")

    # CE connection options
    parser.add_argument(
        "--base-url",
        default=f"http://localhost:{BLOODHOUND_CE_DEFAULT_WEB_PORT}",
        help=(
            "BloodHound CE base URL "
            f"(default: http://localhost:{BLOODHOUND_CE_DEFAULT_WEB_PORT})"
        ),
    )
    parser.add_argument("--username", default="admin", help="BloodHound CE username")
    parser.add_argument(
        "--ce-password", default="Adscan4thewin!", help="BloodHound CE password"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Users command
    users_parser = subparsers.add_parser("user", help="List users")
    users_parser.add_argument("-d", "--domain", required=True, help="Domain to query")
    users_parser.add_argument(
        "-u", "--user", help="Specific user to query (for password-last-change)"
    )
    users_parser.add_argument(
        "--ou-dn",
        dest="ou_dn",
        help="Distinguished Name of an OU to list its users (CE only)",
    )
    users_parser.add_argument(
        "--high-value", action="store_true", help="Show only high value users"
    )
    users_parser.add_argument(
        "--admin-count", action="store_true", help="Show only admin users"
    )
    users_parser.add_argument(
        "--password-never-expires",
        action="store_true",
        help="Show only users with password never expires",
    )
    users_parser.add_argument(
        "--password-not-required",
        action="store_true",
        help="Show only users with password not required",
    )
    users_parser.add_argument(
        "--password-last-change",
        action="store_true",
        help="Show password last change information",
    )
    users_parser.set_defaults(func=cmd_users)
    register_group_subcommand(subparsers)

    # Computers command
    computers_parser = subparsers.add_parser("computer", help="List computers")
    computers_parser.add_argument(
        "-d", "--domain", required=True, help="Domain to query"
    )
    computers_parser.add_argument(
        "--laps", choices=["true", "false"], help="Filter by LAPS status (true/false)"
    )
    computers_parser.set_defaults(func=cmd_computers)

    # Sessions command
    sessions_parser = subparsers.add_parser("session", help="List user sessions")
    sessions_parser.add_argument(
        "-d", "--domain", required=True, help="Domain to query"
    )
    sessions_parser.add_argument(
        "--da",
        action="store_true",
        help="Show sessions from computer perspective (Domain Admin view)",
    )
    sessions_parser.set_defaults(func=cmd_sessions)

    # ACL command
    acl_parser = subparsers.add_parser("acl", help="List critical ACEs")
    acl_parser.add_argument("-s", "--source", help="Source username to filter by")
    acl_parser.add_argument(
        "-sd", "--source-domain", required=True, help="Source domain to query"
    )
    acl_parser.add_argument("-r", "--relation", help="Relation type to filter by")
    acl_parser.add_argument(
        "-t",
        "--target",
        help='Target to filter by (use "high-value" for tier 0 targets only)',
    )
    acl_parser.set_defaults(func=cmd_acl)

    # Access command
    access_parser = subparsers.add_parser(
        "access", help="Find access paths between objects"
    )
    access_parser.add_argument(
        "-s", "--source", required=True, help="Source object name"
    )
    access_parser.add_argument("-r", "--relation", help="Relation type to filter by")
    access_parser.add_argument(
        "-t", "--target", required=True, help="Target object name"
    )
    access_parser.add_argument("-d", "--domain", required=True, help="Domain to query")
    access_parser.set_defaults(func=cmd_access)

    # Upload command
    upload_parser = subparsers.add_parser("upload", help="Upload BloodHound data")
    upload_parser.add_argument("-f", "--file", help="Path to ZIP file to upload")
    upload_parser.add_argument(
        "--list-jobs", action="store_true", help="List upload jobs"
    )
    upload_parser.add_argument(
        "--accepted-types", action="store_true", help="Show accepted file types"
    )
    upload_parser.add_argument(
        "--wait",
        action="store_true",
        default=True,
        help="Wait for ingestion to complete (default)",
    )
    upload_parser.add_argument(
        "--no-wait",
        action="store_false",
        dest="wait",
        help="Return immediately after upload is accepted",
    )
    upload_parser.add_argument(
        "--poll-interval",
        type=int,
        default=5,
        help="Seconds between status checks (default: 5)",
    )
    upload_parser.add_argument(
        "--timeout",
        type=int,
        default=1800,
        help="Max seconds to wait for completion (default: 1800)",
    )
    upload_parser.set_defaults(func=cmd_upload)

    # Auth command
    auth_parser = subparsers.add_parser(
        "auth", help="Authenticate to BloodHound CE and save API token"
    )
    auth_parser.add_argument(
        "-u",
        "--url",
        default=f"http://localhost:{BLOODHOUND_CE_DEFAULT_WEB_PORT}",
        help=(
            "BloodHound CE base URL "
            f"(default: http://localhost:{BLOODHOUND_CE_DEFAULT_WEB_PORT})"
        ),
    )
    auth_parser.add_argument(
        "--username", default="admin", help="CE username (default: admin)"
    )
    auth_parser.add_argument(
        "--password", help="CE password (if omitted, prompt securely)"
    )
    auth_parser.add_argument(
        "--login-path",
        default="/api/v2/login",
        help="Login path (default: /api/v2/login)",
    )
    auth_parser.add_argument(
        "--insecure", action="store_true", help="Disable TLS certificate verification"
    )
    auth_parser.set_defaults(func=cmd_auth)

    # Version command
    register_version_subcommand(subparsers)

    args = parser.parse_args()

    configure_logging(debug=args.debug)
    bound_logger = LOGGER.bind(edition=args.edition)

    if not args.command:
        parser.print_help()
        return

    if args.debug:
        bound_logger.debug("command dispatch", command=args.command)

    try:
        args.func(args)
    except Exception as e:
        if args.debug:
            import traceback

            traceback.print_exc()
        else:
            print(f"Error: {e}")


if __name__ == "__main__":
    main()
