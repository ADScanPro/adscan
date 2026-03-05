"""Rich output helpers for elegant, aesthetic, and structured terminal UI.

This module provides improved print functions using Rich library for better UX/UI.
All functions support panels, icons, and consistent styling for a professional look.
Brand colors from the official ADscan logo are integrated throughout the module.

Brand Colors (from docs/assets/brand/adscan_icon.png):
- Primary: #00D4FF (bright cyan) - Used for info messages and brand elements
- Secondary: #2A2A2A (dark metallic gray) - Used for backgrounds and panels
- Standard colors: green (success), yellow (warning), red (error)

All message parameters accept:
- Plain strings: Will be styled with brand colors or default colors
- Rich markup strings: Use Rich markup like [bold]text[/bold], [red]text[/red], etc.
- Rich Text objects: For maximum control and customization

Examples:
    # Plain string (default behavior)
    print_info("Simple message")

    # Rich markup string (full customization)
    print_info("[bold]Important[/bold] [red]error[/red] in [yellow]module[/yellow]")
    print_success("Operation [bold]completed[/bold] successfully")

    # Rich Text object (maximum control)
    from rich.text import Text
    custom_text = Text("Custom", style="bold") + Text(" message", style="dim")
    print_warning(custom_text)

    # With panels (automatic spacing before and after)
    print_info("[bold]Section Title[/bold]\nDetailed information here", panel=True)

    # With items list (also supports markup)
    print_success("Installation complete", items=[
        "[green]Package 1[/green] installed",
        "[green]Package 2[/green] installed"
    ])

    # Spacing control (intelligent by default)
    print_info("Message 1")  # No spacing (first message)
    print_info("Message 2")  # No spacing (same type, grouped)
    print_success("Success!")  # Space before (type changed: info -> success)
    print_error("Error!")  # Space before (type changed: success -> error)

    # Manual spacing control
    print_info("Important", spacing="both")  # Space before and after
    print_success("Done", spacing="none")  # No spacing at all
    print_warning("Warning", spacing="after")  # Space only after

    # Reset spacing tracking (useful for new sections)
    reset_spacing()
    print_info("New section starts here")  # No spacing (reset)

    # Custom panels with full control
    from rich.text import Text
    print_panel(
        Text("Centered content", justify="center"),
        title="[bold]Custom Panel[/bold]",
        expand=False,
        padding=(0, 1)
    )
"""

from typing import Optional, List, Dict, Any, Union, Callable
import ipaddress
import logging
import os
import re
import sys
from contextlib import contextmanager
from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.box import Box, ROUNDED
from rich.progress import (
    Progress,
    ProgressColumn,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
    TimeElapsedColumn,
)
from rich.status import Status
from rich.syntax import Syntax


from adscan_core.theme import (  # noqa: E402
    ADSCAN_PRIMARY,
    ADSCAN_SECONDARY_DARK,
)


def strip_sensitive_markers(text: str) -> str:
    """Remove invisible sensitive markers from a string.

    These markers are used by :func:`mark_sensitive` to tag sensitive values
    (user/domain/ip/path/etc.) in Rich output so telemetry can sanitize them.
    They must never be present in real OS commands or filesystem paths because
    external tools would receive a different byte sequence and fail.

    Args:
        text: Input string that may contain invisible markers.

    Returns:
        The same string with all known markers removed.
    """
    from adscan_core.sensitive import strip_sensitive_markers as _strip

    return _strip(text)


def mark_passthrough(value: str) -> str:
    """Wrap a non-sensitive value with invisible passthrough markers.

    Use this when you want the value to remain unchanged in session recordings
    (telemetry sanitization will skip it), for example public URLs.

    Args:
        value: Public/non-sensitive value to preserve verbatim.

    Returns:
        Value wrapped with invisible passthrough markers.
    """
    from adscan_core.sensitive import mark_passthrough as _mark

    return _mark(value)


def mark_sensitive(value: str, data_type: str) -> str:
    """Wrap sensitive data with invisible markers for automatic sanitization.

    This function wraps sensitive values with zero-width space markers that are
    invisible to users but can be detected by telemetry sanitization code. This
    allows us to show sensitive data to users while automatically sanitizing it
    before uploading to telemetry services.

    Args:
        value: The sensitive value to mark (e.g., "example.local", "10.0.0.1", "admin")
        data_type: Type of sensitive data, one of:
            - "user": Usernames, account names
            - "domain": Domain names, FQDNs
            - "ip": IP addresses
            - "password": Passwords, hashes, credentials
            - "service": Service names, SPNs, delegation targets
            - "path": File paths, registry keys, share paths
            - "hostname": Hostnames, computer names
            - "workspace": Workspace names/identifiers

    Returns:
        String with invisible markers wrapping the value

    Example:
        >>> marked = mark_sensitive("example.local", "domain")
        >>> # User sees: "example.local"
        >>> # Telemetry sees the value wrapped with invisible markers that
        >>> # are later replaced by \"{DOMAIN}\" during sanitization.
    """
    from adscan_core.sensitive import mark_sensitive as _mark

    return _mark(value, data_type)


def mark_dict_values(
    data: Dict[str, str],
    type_mapping: Dict[str, str],
) -> Dict[str, str]:
    """Mark all values in a dictionary based on key-to-type mapping.

    This helper function applies mark_sensitive() to all values in a dictionary
    based on a mapping from dictionary keys to sensitive data types.

    Args:
        data: Dictionary with keys and values to mark
        type_mapping: Dictionary mapping keys to data types (e.g., {"Domain": "domain", "Username": "user"})

    Returns:
        New dictionary with marked values

    Example:
        >>> data = {"Domain": "example.local", "Username": "admin", "Target": "10.0.0.1"}
        >>> mapping = {"Domain": "domain", "Username": "user", "Target": "ip"}
        >>> marked = mark_dict_values(data, mapping)
        >>> # marked = {"Domain": "\\u200b[SENSITIVE:DOMAIN]\\u200bexample.local\\u200b[/SENSITIVE:DOMAIN]\\u200b", ...}
    """
    result = {}
    for key, value in data.items():
        data_type = type_mapping.get(key)
        if data_type:
            result[key] = mark_sensitive(str(value), data_type)
        else:
            result[key] = value
    return result


def _mark_operation_details(details: Dict[str, str]) -> Dict[str, str]:
    """Automatically mark sensitive values in operation details based on key patterns.

    This function intelligently detects sensitive data types based on dictionary key names
    and applies appropriate marking. Used by print_operation_header() and similar functions.

    Args:
        details: Dictionary of operation details (e.g., {"Domain": "example.local", "Username": "admin"})

    Returns:
        New dictionary with sensitive values marked

    Example:
        >>> details = {"Domain": "example.local", "PDC": "10.0.0.1", "Username": "admin"}
        >>> marked = _mark_operation_details(details)
        >>> # All sensitive values are marked with invisible markers
    """
    import re

    marked = {}

    for key, value in details.items():
        if not value or not isinstance(value, str):
            marked[key] = value
            continue

        key_lower = key.lower()
        value_lower = value.lower()

        # Detect IP addresses
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b"
        if re.search(ip_pattern, value):
            marked[key] = mark_sensitive(value, "ip")
            continue

        # Domain-related keys
        if any(
            keyword in key_lower for keyword in ["domain", "fqdn", "realm", "forest"]
        ):
            # Skip generic values
            if value_lower not in ["n/a", "-", "none", "any"]:
                marked[key] = mark_sensitive(value, "domain")
            else:
                marked[key] = value
            continue

        # User-related keys
        if any(
            keyword in key_lower for keyword in ["user", "account", "admin", "owner"]
        ):
            # Skip generic/anonymous values
            if value_lower not in ["n/a", "-", "none", "anonymous", "guest", "system"]:
                marked[key] = mark_sensitive(value, "user")
            else:
                marked[key] = value
            continue

        # Hostname/Computer keys (PDC, DC, Target Host, Computer, Server, etc.)
        # More specific patterns to avoid false positives like "Scan Target" or "Target Domain"
        if any(
            keyword in key_lower
            for keyword in [
                "pdc",
                "dc",
                "target host",
                "target computer",
                "target server",
                "computer name",
                "server name",
                "hostname",
            ]
        ) or (
            key_lower in ["host", "computer", "server"]
        ):  # Exact match only for these
            # Could be IP (already handled) or hostname/FQDN
            if not re.search(ip_pattern, value):
                # Check if it looks like a domain (has dots) or hostname
                if "." in value and value_lower not in ["n/a", "-"]:
                    # Could be FQDN - mark as domain
                    marked[key] = mark_sensitive(value, "domain")
                elif value_lower not in ["n/a", "-", "none", "any", "all"]:
                    # Hostname without domain
                    marked[key] = mark_sensitive(value, "hostname")
                else:
                    marked[key] = value
            else:
                # IP already marked above
                marked[key] = marked.get(key, value)
            continue

        # Path-related keys (Search Path, Output, Registry Key, etc.)
        if any(
            keyword in key_lower
            for keyword in ["path", "output", "directory", "folder", "file", "registry"]
        ):
            if value_lower not in ["n/a", "-", "none"]:
                marked[key] = mark_sensitive(value, "path")
            else:
                marked[key] = value
            continue

        # Service-related keys (Service, Protocol, Scan Target with specific services)
        if any(keyword in key_lower for keyword in ["service", "spn"]):
            if value_lower not in [
                "n/a",
                "-",
                "none",
                "smb",
                "ldap",
                "winrm",
                "rdp",
                "ssh",
                "http",
                "https",
            ]:
                # Don't mark generic protocol names, but mark specific service targets
                if "/" in value or "\\" in value:
                    # Looks like SPN or service path
                    marked[key] = mark_sensitive(value, "service")
                else:
                    marked[key] = value
            else:
                marked[key] = value
            continue

        # Password/Credential Type keys - mark the type but not generic values
        if any(
            keyword in key_lower
            for keyword in ["password", "hash", "credential", "secret"]
        ):
            # Only mark if it looks like actual credential data (long strings, hex patterns, etc.)
            if len(value) > 8 and value_lower not in [
                "password",
                "hash",
                "ntlm",
                "aes",
            ]:
                marked[key] = mark_sensitive(value, "password")
            else:
                marked[key] = value
            continue

        # Default: don't mark
        marked[key] = value

    return marked


# Brand color mappings for message types
BRAND_COLORS = {
    "info": ADSCAN_PRIMARY,  # Info uses primary brand color (cyan)
    "success": "green",  # Success keeps green (standard for positive actions)
    "warning": "yellow",  # Warning uses yellow (standard for warnings)
    "error": "red",  # Error keeps red (standard for critical issues)
    "instruction": "dim",  # Instructions remain dim
}

# Global console instance (will be initialized from adscan.py)
_console: Optional[Console] = None

# Secondary console dedicated to telemetry recording.
# This console is never shown directly to the user; it is used only to
# capture a full Rich session (including info/warning/error messages)
# for sanitized upload to remote storage (Vercel/n8n).
_telemetry_console: Optional[Console] = None

# Global mode flags (will be initialized from adscan.py)
_verbose_mode: bool = False
_debug_mode: bool = False
_secret_mode: bool = False

# Track last message type for intelligent spacing
_last_message_type: Optional[str] = None
_last_was_panel: bool = False

# Logger instance (will be initialized from logging_config)
_logger: Optional[logging.Logger] = None


def _diag_enabled() -> bool:
    return os.getenv("ADSCAN_DIAG_LOGGING", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }


def _diag_log(message: str) -> None:
    if _diag_enabled():
        print(f"[DIAG][rich_output] {message}", file=sys.stderr)


def init_rich_output(
    console: Console,
    verbose_mode: bool = False,
    debug_mode: bool = False,
    secret_mode: bool = False,
    logger: Optional[logging.Logger] = None,
):
    """Initialize the rich output module with console and mode flags.

    Args:
        console: Rich Console instance to use for output
        verbose_mode: Enable verbose output mode
        debug_mode: Enable debug output mode
        secret_mode: Enable secret mode (show internal details)
        logger: Optional logger instance (if None, will get from logging_config)
    """
    global _console, _verbose_mode, _debug_mode, _secret_mode, _logger
    previous_console = _console
    _console = console

    # CRITICAL FIX: If console is already initialized and modes are already active,
    # don't overwrite them with False values (prevents reset during module reimport)
    # Only update if:
    # 1. First initialization (_console is None), OR
    # 2. New values are "better" (activating modes that were previously False)
    if previous_console is None or previous_console is not console:
        # First initialization (or a new Console instance) - set all values
        _verbose_mode = verbose_mode
        _debug_mode = debug_mode
        _secret_mode = secret_mode
        _diag_log(
            "init_rich_output: set modes (new console) "
            f"verbose={_verbose_mode}, debug={_debug_mode}, secret={_secret_mode}"
        )
    else:
        # Already initialized - only update if new values are "better" (activating modes)
        # Don't deactivate modes that are already active
        if verbose_mode and not _verbose_mode:
            _verbose_mode = verbose_mode
        if debug_mode and not _debug_mode:
            _debug_mode = debug_mode
        if secret_mode and not _secret_mode:
            _secret_mode = secret_mode
        _diag_log(
            "init_rich_output: preserved modes (existing console) "
            f"verbose={_verbose_mode}, debug={_debug_mode}, secret={_secret_mode}"
        )
        # Note: We intentionally don't deactivate modes here to prevent reset during reimport

    # Set logger if provided, otherwise get from logging_config
    if logger is not None:
        _logger = logger
        _diag_log("init_rich_output: logger injected")
    else:
        try:
            from .logging_config import get_logger

            _logger = get_logger()
            _diag_log("init_rich_output: logger from logging_config")
        except ImportError:
            # Fallback: create basic logger if logging_config not available
            _logger = logging.getLogger("adscan")
            _diag_log("init_rich_output: fallback logger")


def set_telemetry_console(console: Optional[Console]) -> None:
    """Configure optional telemetry console used for session recordings.

    This console is intended to record ALL rendered output (at least for the
    high-level helpers in this module) regardless of verbose/debug flags, while
    the primary console continues to control what the end user actually sees.
    """
    global _telemetry_console
    _telemetry_console = console


def update_modes(
    verbose_mode: Optional[bool] = None,
    debug_mode: Optional[bool] = None,
    secret_mode: Optional[bool] = None,
):
    """Update mode flags dynamically.

    Args:
        verbose_mode: New verbose mode value (None to keep current)
        debug_mode: New debug mode value (None to keep current)
        secret_mode: New secret mode value (None to keep current)
    """
    global _verbose_mode, _debug_mode, _secret_mode
    if verbose_mode is not None:
        _verbose_mode = verbose_mode
    if debug_mode is not None:
        _debug_mode = debug_mode
    if secret_mode is not None:
        _secret_mode = secret_mode

    _diag_log(
        "update_modes: "
        f"verbose={_verbose_mode}, debug={_debug_mode}, secret={_secret_mode}"
    )

    # Update logging console level when modes change
    try:
        from .logging_config import update_logging_console_level

        # DIAGNOSTIC: Log when update_modes is called (write directly to file handler)
        # COMMENTED: Not directly related to module re-execution tracking
        # try:
        #     from .logging_config import _file_handler
        #     import logging
        #     if _file_handler is not None:
        #         diagnostic_msg = (
        #             f"[LOGGING_DIAG] update_modes called: "
        #             f"verbose_mode={verbose_mode}, debug_mode={debug_mode}, secret_mode={secret_mode}, "
        #             f"_verbose_mode={_verbose_mode}, _debug_mode={_debug_mode}, _secret_mode={_secret_mode}"
        #         )
        #         _file_handler.emit(logging.LogRecord(
        #             name="adscan.diagnostic",
        #             level=logging.DEBUG,
        #             pathname="",
        #             lineno=0,
        #             msg=diagnostic_msg,
        #             args=(),
        #             exc_info=None
        #         ))
        # except Exception:
        #     pass  # Don't fail if diagnostic logging fails

        update_logging_console_level(
            verbose_mode=_verbose_mode,
            debug_mode=_debug_mode,
        )
    except ImportError:
        pass  # logging_config not available, skip


def _get_console() -> Console:
    """Get the global console instance."""
    if _console is None:
        return Console()
    return _console


def _get_telemetry_console() -> Optional[Console]:
    """Get the optional telemetry console instance."""
    return _telemetry_console


def get_console() -> Console:
    """Public accessor for the shared Rich console instance."""
    return _get_console()


def set_output_config(
    *, verbose: bool, debug: bool, telemetry_console: Optional[Console] = None
) -> None:
    """Configure shared Rich output + logging modes.

    This is the canonical setup path for both launcher and runtime callers.
    It mirrors the initialization sequence used by the monolithic CLI:
    1. Initialize Rich-aware logging handlers.
    2. Bind shared console/logger into rich_output.
    3. Apply runtime modes (verbose/debug/secret).
    """
    from .logging_config import init_logging

    console = get_console()
    secret_mode = debug

    logger = init_logging(
        console=console,
        verbose_mode=verbose,
        debug_mode=debug,
        secret_mode=secret_mode,
        telemetry_console=telemetry_console,
    )
    init_rich_output(
        console,
        verbose_mode=verbose,
        debug_mode=debug,
        secret_mode=secret_mode,
        logger=logger,
    )
    if telemetry_console is not None:
        set_telemetry_console(telemetry_console)
    install_prompt_logging_wrappers()
    update_modes(verbose_mode=verbose, debug_mode=debug, secret_mode=secret_mode)


_ORIGINAL_PROMPT_ASK: Optional[Callable[..., Any]] = None
_ORIGINAL_CONFIRM_ASK: Optional[Callable[..., Any]] = None
_PROMPT_LOGGING_WRAPPERS_INSTALLED = False
_PROMPT_AUTO_MODE_ACTIVE = False
_PROMPT_SHOULD_DISABLE_INTERACTIVE: Callable[[object | None], bool] | None = None
_PROMPT_INTERRUPT_LOGGER: Callable[[str, str], None] | None = None
_PROMPT_USE_QUESTIONARY_IN_CONTAINER: Callable[[], bool] | None = None


def _default_should_disable_interactive_prompts(shell: object | None = None) -> bool:
    """Default non-interactive predicate shared by launcher/runtime."""
    from adscan_core.interaction import is_non_interactive

    return is_non_interactive(shell=shell)


def _default_interrupt_logger(kind: str, source: str) -> None:
    """Default interrupt debug logger routed through centralized debug output."""
    from adscan_core.interrupts import emit_interrupt_debug

    emit_interrupt_debug(kind=kind, source=source, print_debug=print_info_debug)


def _default_use_questionary_in_container() -> bool:
    """Return True when Questionary container fallback should be used."""
    return os.getenv("ADSCAN_CONTAINER_RUNTIME") == "1"


def configure_prompt_behavior(
    *,
    should_disable_interactive_prompts: Callable[[object | None], bool] | None = None,
    interrupt_logger: Callable[[str, str], None] | None = None,
    use_questionary_in_container: Callable[[], bool] | None = None,
) -> None:
    """Configure centralized prompt behavior hooks.

    Args:
        should_disable_interactive_prompts: Predicate used to decide whether
            prompts must auto-resolve defaults (non-interactive runs).
        interrupt_logger: Callable invoked on EOF/KeyboardInterrupt.
        use_questionary_in_container: Predicate to enable Questionary fallback
            for Prompt/Confirm when running in container runtime.
    """
    global _PROMPT_SHOULD_DISABLE_INTERACTIVE
    global _PROMPT_INTERRUPT_LOGGER
    global _PROMPT_USE_QUESTIONARY_IN_CONTAINER

    _PROMPT_SHOULD_DISABLE_INTERACTIVE = should_disable_interactive_prompts
    _PROMPT_INTERRUPT_LOGGER = interrupt_logger
    _PROMPT_USE_QUESTIONARY_IN_CONTAINER = use_questionary_in_container


def set_prompt_auto_mode(active: bool) -> None:
    """Enable/disable centralized prompt auto-mode."""
    global _PROMPT_AUTO_MODE_ACTIVE
    _PROMPT_AUTO_MODE_ACTIVE = bool(active)


def is_prompt_auto_mode_enabled() -> bool:
    """Return whether centralized prompt auto-mode is currently active."""
    return bool(_PROMPT_AUTO_MODE_ACTIVE)


def _should_disable_prompt_interaction(shell: object | None = None) -> bool:
    """Best-effort predicate for non-interactive prompt behavior."""
    callback = (
        _PROMPT_SHOULD_DISABLE_INTERACTIVE
        if _PROMPT_SHOULD_DISABLE_INTERACTIVE is not None
        else _default_should_disable_interactive_prompts
    )
    try:
        return bool(callback(shell))
    except Exception:
        return True


def _emit_prompt_interrupt_debug(*, kind: str, source: str) -> None:
    """Emit standardized interrupt debug messages for prompt flows."""
    callback = (
        _PROMPT_INTERRUPT_LOGGER
        if _PROMPT_INTERRUPT_LOGGER is not None
        else _default_interrupt_logger
    )
    try:
        callback(kind, source)
    except Exception:
        return


def _should_use_questionary_prompt() -> bool:
    """Return True when Prompt/Confirm should use Questionary fallback."""
    callback = (
        _PROMPT_USE_QUESTIONARY_IN_CONTAINER
        if _PROMPT_USE_QUESTIONARY_IN_CONTAINER is not None
        else _default_use_questionary_in_container
    )
    try:
        return bool(callback())
    except Exception:
        return False


def _classify_prompt_answer(answer_text: str, *, password_mode: bool) -> str:
    """Best-effort classification for prompt answer sanitization."""
    if password_mode:
        return "password"

    cleaned = str(answer_text or "").strip()
    if not cleaned:
        return "user"

    try:
        ipaddress.ip_network(cleaned, strict=False)
        return "ip"
    except ValueError:
        pass

    if cleaned.startswith(("/", "./", "../", "~")) or re.match(
        r"^[A-Za-z]:\\", cleaned
    ):
        return "path"
    if re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", cleaned):
        return "domain"
    return "user"


def _logged_prompt_ask(*prompt_args: Any, **kwargs: Any) -> str:
    """Prompt.ask wrapper with centralized telemetry/debug answer logging."""
    prompt_message = str(prompt_args[0]) if prompt_args else "?"
    password_mode = bool(kwargs.get("password", False))
    default_value = kwargs.get("default")

    prompt_tag = "[prompt][password]" if password_mode else "[prompt]"
    print_telemetry_only(f"{prompt_tag} {prompt_message}")
    print_info_debug(f"[prompt] Prompt: {prompt_message}")

    if _PROMPT_AUTO_MODE_ACTIVE:
        fallback = "" if default_value is None else str(default_value)
        shown = "[hidden]" if password_mode and fallback else fallback
        print_info(f"{prompt_message} [dim](auto: {shown})[/dim]")
        answer_type = _classify_prompt_answer(fallback, password_mode=password_mode)
        marked_answer = mark_sensitive(fallback, answer_type)
        answer_tag = (
            "[prompt][password][answer]" if password_mode else "[prompt][answer]"
        )
        print_telemetry_only(f"{answer_tag} {prompt_message}: {marked_answer}")
        print_info_debug(f"[prompt] Answer for '{prompt_message}': {marked_answer}")
        return fallback

    if _should_disable_prompt_interaction():
        fallback = "" if default_value is None else str(default_value)
        answer_type = _classify_prompt_answer(fallback, password_mode=password_mode)
        marked_answer = mark_sensitive(fallback, answer_type)
        answer_tag = (
            "[prompt][password][answer]" if password_mode else "[prompt][answer]"
        )
        print_info_debug(
            f"[prompt] Non-interactive mode; using fallback for '{prompt_message}'."
        )
        print_telemetry_only(f"{answer_tag} {prompt_message}: {marked_answer}")
        return fallback

    answer: Any = None
    if _should_use_questionary_prompt():
        try:
            import questionary  # type: ignore
        except Exception:
            questionary = None  # type: ignore[assignment]

        if questionary is not None:
            default_text = "" if default_value is None else str(default_value)
            try:
                if password_mode:
                    answer = questionary.password(prompt_message, default=default_text).ask()
                else:
                    answer = questionary.text(prompt_message, default=default_text).ask()
            except EOFError:
                _emit_prompt_interrupt_debug(
                    kind="eof", source="rich_prompt.ask(container)"
                )
                fallback = "" if default_value is None else str(default_value)
                answer_type = _classify_prompt_answer(
                    fallback, password_mode=password_mode
                )
                marked_answer = mark_sensitive(fallback, answer_type)
                answer_tag = (
                    "[prompt][password][answer]"
                    if password_mode
                    else "[prompt][answer]"
                )
                print_telemetry_only(f"{answer_tag} {prompt_message}: {marked_answer}")
                return fallback
            except KeyboardInterrupt:
                _emit_prompt_interrupt_debug(
                    kind="keyboard_interrupt", source="rich_prompt.ask(container)"
                )
                return ""

    if answer is None:
        if _ORIGINAL_PROMPT_ASK is not None:
            answer = _ORIGINAL_PROMPT_ASK(*prompt_args, **kwargs)
        else:  # pragma: no cover - defensive fallback
            from rich.prompt import Prompt

            answer = Prompt.ask(*prompt_args, **kwargs)

    answer_text = "" if answer is None else str(answer)
    answer_type = _classify_prompt_answer(answer_text, password_mode=password_mode)
    marked_answer = mark_sensitive(answer_text, answer_type)
    answer_tag = "[prompt][password][answer]" if password_mode else "[prompt][answer]"
    print_telemetry_only(f"{answer_tag} {prompt_message}: {marked_answer}")
    print_info_debug(f"[prompt] Answer for '{prompt_message}': {marked_answer}")
    return answer_text


def _logged_confirm_ask(*confirm_args: Any, **kwargs: Any) -> bool:
    """Confirm.ask wrapper with centralized telemetry/debug answer logging."""
    prompt_message = str(confirm_args[0]) if confirm_args else "Confirm?"
    print_telemetry_only(f"[confirm] {prompt_message}")
    print_info_debug(f"[confirm] Prompt: {prompt_message}")

    if _PROMPT_AUTO_MODE_ACTIVE:
        auto_response = bool(kwargs.get("default", True))
        response_text = "Yes" if auto_response else "No"
        print_info(f"{prompt_message} [dim](auto: {response_text})[/dim]")
        print_telemetry_only(f"[confirm][answer] {prompt_message}: {response_text}")
        print_info_debug(f"[confirm] Answer for '{prompt_message}': {response_text}")
        return auto_response

    if _should_disable_prompt_interaction():
        resolved = bool(kwargs.get("default", True))
        answer_text = "Yes" if resolved else "No"
        print_info_debug(
            f"[confirm] Non-interactive mode; using fallback for '{prompt_message}': {resolved}"
        )
        print_telemetry_only(f"[confirm][answer] {prompt_message}: {answer_text}")
        return resolved

    if _should_use_questionary_prompt():
        try:
            import questionary  # type: ignore
        except Exception:
            questionary = None  # type: ignore[assignment]
        if questionary is not None:
            default_value = bool(kwargs.get("default", False))
            try:
                q_answer = questionary.confirm(
                    prompt_message,
                    default=default_value,
                ).ask()
                resolved = default_value if q_answer is None else bool(q_answer)
                answer_text = "Yes" if resolved else "No"
                print_telemetry_only(
                    f"[confirm][answer] {prompt_message}: {answer_text}"
                )
                print_info_debug(f"[confirm] Answer for '{prompt_message}': {answer_text}")
                return resolved
            except EOFError:
                _emit_prompt_interrupt_debug(
                    kind="eof", source="rich_confirm.ask(container)"
                )
                answer_text = "Yes" if default_value else "No"
                print_telemetry_only(
                    f"[confirm][answer] {prompt_message}: {answer_text}"
                )
                return default_value
            except KeyboardInterrupt:
                _emit_prompt_interrupt_debug(
                    kind="keyboard_interrupt", source="rich_confirm.ask(container)"
                )
                answer_text = "Yes" if default_value else "No"
                print_telemetry_only(
                    f"[confirm][answer] {prompt_message}: {answer_text}"
                )
                return default_value

    if _ORIGINAL_CONFIRM_ASK is not None:
        answer = _ORIGINAL_CONFIRM_ASK(*confirm_args, **kwargs)
    else:  # pragma: no cover - defensive fallback
        from rich.prompt import Confirm

        answer = Confirm.ask(*confirm_args, **kwargs)

    resolved = bool(answer)
    answer_text = "Yes" if resolved else "No"
    print_telemetry_only(f"[confirm][answer] {prompt_message}: {answer_text}")
    print_info_debug(f"[confirm] Answer for '{prompt_message}': {answer_text}")
    return resolved


def install_prompt_logging_wrappers() -> None:
    """Install Prompt/Confirm wrappers to centrally log questions and answers."""
    global _ORIGINAL_PROMPT_ASK, _ORIGINAL_CONFIRM_ASK
    global _PROMPT_LOGGING_WRAPPERS_INSTALLED

    if _PROMPT_LOGGING_WRAPPERS_INSTALLED:
        return

    from rich.prompt import Confirm, Prompt

    _ORIGINAL_PROMPT_ASK = Prompt.ask
    _ORIGINAL_CONFIRM_ASK = Confirm.ask
    Prompt.ask = _logged_prompt_ask  # type: ignore[assignment]
    Confirm.ask = _logged_confirm_ask  # type: ignore[assignment]
    _PROMPT_LOGGING_WRAPPERS_INSTALLED = True


def confirm_ask(prompt: str, default: bool) -> bool:
    """Ask a yes/no confirmation prompt with centralized prompt logging."""
    try:
        install_prompt_logging_wrappers()
        from rich.prompt import Confirm

        return bool(Confirm.ask(prompt, default=default))
    except Exception as exc:
        print_info_debug(
            f"[confirm] Fallback to default for '{prompt}': {default} ({type(exc).__name__})"
        )
        answer_text = "Yes" if bool(default) else "No"
        print_telemetry_only(f"[confirm][answer] {prompt}: {answer_text}")
        return default


def prompt_ask(
    prompt: str,
    default: str | None = None,
    *,
    password: bool = False,
    **kwargs: Any,
) -> str:
    """Ask a text prompt with centralized prompt logging and safe fallback."""
    try:
        install_prompt_logging_wrappers()
        from rich.prompt import Prompt

        answer = Prompt.ask(prompt, default=default, password=password, **kwargs)
        return "" if answer is None else str(answer)
    except Exception as exc:
        fallback = "" if default is None else str(default)
        print_info_debug(
            f"[prompt] Fallback to default for '{prompt}': "
            f"{mark_sensitive(fallback, _classify_prompt_answer(fallback, password_mode=password))} "
            f"({type(exc).__name__})"
        )
        answer_tag = "[prompt][password][answer]" if password else "[prompt][answer]"
        data_type = _classify_prompt_answer(fallback, password_mode=password)
        print_telemetry_only(
            f"{answer_tag} {prompt}: {mark_sensitive(fallback, data_type)}"
        )
        return fallback


def questionary_select_value(
    *,
    title: str,
    options: list[str],
) -> str | None:
    """Render a Questionary single-select prompt and return selected value."""
    if not options:
        return None
    try:
        import questionary  # type: ignore
    except Exception:
        return None
    try:
        return questionary.select(
            title,
            choices=list(options),
            style=_questionary_style(questionary),
        ).ask()
    except (EOFError, KeyboardInterrupt):
        return None


def questionary_checkbox_values(
    *,
    title: str,
    options: list[str],
    shell: object | None = None,
) -> list[str] | None:
    """Render a Questionary checkbox prompt and return selected values."""
    if not options:
        return None
    if _should_disable_prompt_interaction(shell):
        print_info_debug(f"[questionary] Non-interactive; skipping checkbox prompt: {title}")
        print_telemetry_only(f"[questionary] Prompt: {title}")
        return None

    print_info_debug(f"[questionary] Prompt: {title}")
    print_telemetry_only(f"[questionary] Prompt: {title}")
    try:
        selected_values = questionary_checkbox_values_raw(title=title, options=options)
    except KeyboardInterrupt:
        _emit_prompt_interrupt_debug(
            kind="keyboard_interrupt", source="questionary.checkbox"
        )
        return None
    except Exception as exc:
        print_info_debug(
            f"[DEBUG] questionary.checkbox failed: {type(exc).__name__}: {exc}"
        )
        return None
    if selected_values is None:
        return None
    print_info_debug(f"[questionary] Selected: {selected_values}")
    print_telemetry_only(
        f"[questionary][answer] {title}: {mark_sensitive(str(selected_values), 'text')}"
    )
    return selected_values


def questionary_checkbox_values_raw(
    *,
    title: str,
    options: list[str],
) -> list[str] | None:
    """Render Questionary checkbox without extra logging logic."""
    if not options:
        return None
    try:
        import questionary  # type: ignore
    except Exception:
        return None
    try:
        selected = questionary.checkbox(
            title,
            choices=list(options),
            style=_questionary_style(questionary),
        ).ask()
    except (EOFError, KeyboardInterrupt):
        return None
    if selected is None:
        return None
    return [str(value) for value in selected if str(value).strip()]


def _questionary_style(questionary_module: Any) -> Any:
    """Return shared Questionary style used across prompts."""
    return questionary_module.Style(
        [
            ("qmark", "fg:#00D4FF bold"),
            ("question", "bold white"),
            ("answer", "fg:#00D4FF bold"),
            ("pointer", "fg:#00D4FF bold"),
            ("highlighted", "fg:#00D4FF bold"),
            ("selected", "fg:#00D4FF bold"),
            ("separator", "fg:#00D4FF"),
            ("instruction", "fg:#cccccc"),
            ("text", "white"),
            ("choice", "white"),
            ("disabled", "fg:#888888 italic"),
        ]
    )


def questionary_select_index(
    *,
    title: str,
    options: list[str],
    default_idx: int = 0,
    shell: object | None = None,
) -> int | None:
    """Select option index via Questionary with centralized fallback/logging."""
    if not options:
        return None

    resolved_default_idx = default_idx
    if resolved_default_idx < 0 or resolved_default_idx >= len(options):
        resolved_default_idx = 0

    if _should_disable_prompt_interaction(shell):
        print_info_debug(
            "[questionary] Non-interactive; selecting default "
            f"idx={resolved_default_idx}: {options[resolved_default_idx]}"
        )
        print_telemetry_only(
            f"[questionary][answer] {title}: "
            f"{mark_sensitive(str(options[resolved_default_idx]), 'text')}"
        )
        return resolved_default_idx

    print_info_debug(f"[questionary] Prompt: {title}")
    print_telemetry_only(f"[questionary] Prompt: {title}")
    try:
        selected_value = questionary_select_value(title=title, options=options)
    except KeyboardInterrupt:
        _emit_prompt_interrupt_debug(
            kind="keyboard_interrupt", source="questionary.select"
        )
        return None
    except Exception as exc:
        print_info_debug(
            f"[DEBUG] questionary.select failed: {type(exc).__name__}: {exc}, "
            "falling back to numeric selection."
        )
        return _fallback_numeric_select_index(
            title=title, options=options, default_idx=resolved_default_idx
        )
    if selected_value is None:
        print_info_debug(f"[questionary] Cancelled: {title}")
        print_telemetry_only(f"[questionary][answer] {title}: [cancelled]")
        return None

    print_info_debug(f"[questionary] Selected: {selected_value}")
    print_telemetry_only(
        f"[questionary][answer] {title}: {mark_sensitive(str(selected_value), 'text')}"
    )
    try:
        return options.index(selected_value)
    except ValueError:
        return None


def _fallback_numeric_select_index(
    *,
    title: str,
    options: list[str],
    default_idx: int,
) -> int | None:
    """Fallback select menu using Rich numbered prompt."""
    if not options:
        return None

    print_info(f"[bold]{title}[/bold]")
    for idx, option in enumerate(options, start=1):
        print_info(f"  {idx}. {option}")

    default_number = (default_idx + 1) if 0 <= default_idx < len(options) else 1
    try:
        from rich.prompt import IntPrompt

        choice_num = IntPrompt.ask(
            "Enter a number (0 to cancel)",
            default=default_number,
        )
    except Exception:
        return None

    if choice_num == 0:
        return None
    if 1 <= choice_num <= len(options):
        return choice_num - 1
    return None


def print_telemetry_only(message: Any) -> None:
    """Print a message only to the telemetry console (if configured).

    This is intentionally silent for the primary user console. It is used to
    record interactive prompt questions (and other internal events) into the
    session recording without duplicating what the user already sees.

    Args:
        message: Any Rich renderable or markup string to record.
    """
    telemetry_console = _get_telemetry_console()
    if telemetry_console is None:
        return
    telemetry_console.print(message)


def _handle_spacing(message_type: str, is_panel: bool, spacing: str = "auto") -> str:
    """Handle intelligent spacing between messages for better UX/UI.

    Spacing rules:
    - Panels: Always have space before and after (visual blocks)
    - Change of message type: Add space before (info -> success, error -> info, etc.)
    - Same message type: No space (group related messages)
    - Manual control: Use spacing parameter

    Args:
        message_type: Type of message ('info', 'success', 'warning', 'error',
            'instruction')
        is_panel: Whether this is a panel (always gets spacing)
        spacing: Spacing control:
            - "auto" (default): Intelligent spacing based on context
            - "none": No spacing
            - "before": Space before message
            - "after": Space after message
            - "both": Space before and after

    Returns:
        String with appropriate newlines ("", "\n", "\n\n", etc.)
    """
    global _last_message_type, _last_was_panel

    # Manual control overrides automatic behavior
    if spacing != "auto":
        if spacing == "none":
            _last_message_type = message_type
            _last_was_panel = is_panel
            return ""
        if spacing == "before":
            _last_message_type = message_type
            _last_was_panel = is_panel
            return "\n"
        if spacing == "after":
            _last_message_type = message_type
            _last_was_panel = is_panel
            return ""  # Will be handled after print
        if spacing == "both":
            _last_message_type = message_type
            _last_was_panel = is_panel
            return "\n"

    # Automatic spacing logic
    spacing_before = ""

    # Panels always get space before (they're visual blocks)
    if is_panel:
        spacing_before = "\n"
    # If last message was a panel, add space (panels need separation)
    elif _last_was_panel:
        spacing_before = "\n"
    # If message type changed, add space (visual separation of different contexts)
    elif _last_message_type is not None and _last_message_type != message_type:
        # Special: errors and warnings get more space when transitioning
        error_warning_types = ("error", "warning")
        if (
            message_type in error_warning_types
            and _last_message_type not in error_warning_types
        ):
            spacing_before = "\n"
        elif (
            _last_message_type in error_warning_types
            and message_type not in error_warning_types
        ):
            spacing_before = "\n"
        else:
            spacing_before = "\n"

    # Update tracking
    _last_message_type = message_type
    _last_was_panel = is_panel

    return spacing_before


def reset_spacing():
    """Reset spacing tracking (useful for new sections or after major operations)."""
    global _last_message_type, _last_was_panel
    _last_message_type = None
    _last_was_panel = False


def _extract_plain_text(message: object) -> str:
    """Extract plain text from Rich message for logging.

    Args:
        message: Rich message (string with markup or Text object)

    Returns:
        Plain text string without Rich markup
    """
    if isinstance(message, Text):
        return message.plain
    if isinstance(message, str):
        # Remove Rich markup tags (simple approach)
        import re

        # Remove [tag]...[/tag] patterns
        plain = re.sub(r"\[/?[^\]]+\]", "", message)
        return plain.strip()
    return str(message)


def _get_logger() -> logging.Logger:
    """Get logger instance, always fresh from logging_config to ensure it has all handlers.

    This function always gets the logger from logging_config.get_logger() to ensure
    it has all handlers (including telemetry handler) that may have been added after
    the logger was first cached. This is critical for telemetry capture.
    """
    try:
        from .logging_config import get_logger

        # Always get fresh logger to ensure it has all handlers (including telemetry)
        # get_logger() returns the same singleton, so this is safe and ensures handlers are up-to-date
        return get_logger()
    except ImportError:
        # Fallback: create basic logger if logging_config not available
        return logging.getLogger("adscan")


def _log_to_file(level: int, message: str) -> None:
    """Log a message only to file handlers, without touching console handlers.

    Kept for backwards compatibility and potential future use. The current
    architecture prefers routing verbose/debug helpers through the main logger
    so that all handlers (file, console, telemetry) can make consistent
    decisions based on their own levels.
    """
    try:
        # Preferred path: delegate to logging_config, which knows about the
        # file and workspace handlers but not the Rich console handlers.
        from .logging_config import log_to_file_only

        log_to_file_only(level, message)
        return
    except Exception:
        # Fallback: use the main logger directly (this may hit console handlers
        # in edge cases, but we prefer persistence over silence).
        logger = _get_logger()
        logger.log(level, message)


def _print_logger_format_fallback(
    level_name: str, message: Union[str, Text], level_color: str = "blue"
) -> None:
    """Print a message with logger-style format (INFO/DEBUG) as fallback when RichHandler is not available.

    This function simulates the RichHandler format to ensure verbose/debug messages
    are visually differentiated even when the RichHandler is not configured correctly.

    Args:
        level_name: Log level name (e.g., "INFO", "DEBUG", "WARNING", "ERROR")
        message: Message to display (supports Rich markup strings or Text objects)
        level_color: Color for the level name (default: "blue" for INFO, "cyan" for DEBUG)
    """
    from rich.text import Text

    console = _get_console()
    telemetry_console = _get_telemetry_console()

    # Extract plain text if needed
    if isinstance(message, Text):
        plain_text = message.plain
    else:
        plain_text = _extract_plain_text(message)

    # Create logger-style format: "LEVEL     message"
    # RichHandler uses 8 characters for level name, left-aligned
    level_padding = 8
    level_text = level_name.ljust(level_padding)

    # Create formatted output similar to RichHandler
    output = Text()
    output.append(level_text, style=f"bold {level_color}")
    output.append(" ")

    # Add the message (preserve Rich markup if it's a string)
    if isinstance(message, Text):
        output.append(message)
    elif "[" in str(message) and "]" in str(message):
        # Rich markup string - parse it
        output.append(Text.from_markup(message))
    else:
        # Plain string
        output.append(plain_text)

    console.print(output)
    if telemetry_console is not None:
        telemetry_console.print(output)


# --- Basic Print Functions with Enhanced Styling ---


def print_info(
    message: Union[str, Text],
    panel: bool = False,
    icon: str = "ℹ",
    items: Optional[List[Union[str, Text]]] = None,
    spacing: str = "auto",
):
    """Print an informational message with optional panel and icon.

    Args:
        message: Message to display. Can be:
            - Plain string: "Hello world"
            - Rich markup string: "[bold]Hello[/bold] [red]world[/red]"
            - Text object: Text("Hello", style="bold")
        panel: If True, display in a panel with border
        icon: Icon to display (default: ℹ)
        items: Optional list of items to display below message (supports same formats as message)
        spacing: Spacing control ("auto", "none", "before", "after", "both"). Default: "auto"
            - "auto": Intelligent spacing based on context
            - "none": No spacing
            - "before": Space before message
            - "after": Space after message
            - "both": Space before and after
    """
    console = _get_console()
    telemetry_console = _get_telemetry_console()

    # Handle spacing
    spacing_before = _handle_spacing("info", panel, spacing)
    if spacing_before:
        console.print()
        if telemetry_console is not None:
            telemetry_console.print()

    # Format icon
    icon_text = Text(f"{icon} ", style=BRAND_COLORS["info"])

    # Format message (preserves Rich markup or Text object)
    if isinstance(message, Text):
        message_text = message
    elif "[" in message and "]" in message:
        # Rich markup string - parse it
        message_text = Text.from_markup(message)
    else:
        # Plain string - apply default style
        message_text = Text(message, style=BRAND_COLORS["info"])

    if panel:
        content = Text()
        content.append(icon_text)
        content.append(message_text)

        if items:
            content.append("\n\n", style=BRAND_COLORS["info"])
            for item in items:
                if isinstance(item, Text):
                    content.append("  • ")
                    content.append(item)
                    content.append("\n")
                elif "[" in item and "]" in item:
                    # Rich markup
                    item_text = Text.from_markup(item)
                    content.append("  • ")
                    content.append(item_text)
                    content.append("\n")
                else:
                    content.append(f"  • {item}\n", style=f"dim {BRAND_COLORS['info']}")

        panel_renderable = Panel(
            content, border_style=BRAND_COLORS["info"], box=ROUNDED, padding=(0, 1)
        )
        console.print(panel_renderable)
        if telemetry_console is not None:
            telemetry_console.print(panel_renderable)
        # Panels always get space after
        if spacing != "none":
            console.print()
            if telemetry_console is not None:
                telemetry_console.print()
    else:
        # Simple output: icon + message (Rich will handle markup)
        output = Text()
        output.append(icon_text)
        output.append(message_text)
        try:
            console.print(output)
        except Exception:
            raise
        if telemetry_console is not None:
            telemetry_console.print(output)

        # Handle spacing after if requested
        if spacing in ("after", "both"):
            console.print()
            if telemetry_console is not None:
                telemetry_console.print()


def print_info_verbose(message: Union[str, Text], panel: bool = False, icon: str = "ℹ"):
    """Print verbose informational message (only if verbose or debug mode enabled).

    This function uses the logger directly, which will:
    - Always log to file (both global and workspace if active)
    - Conditionally show Rich output in console via RichHandler (if verbose/debug mode)
    - Uses RichHandler format (with "INFO" level indicator) to differentiate from normal print_info()

    Args:
        message: Message to display (supports Rich markup strings or Text objects)
        panel: Not used (kept for compatibility)
        icon: Not used (kept for compatibility)
    """
    import logging

    global _verbose_mode, _debug_mode
    plain_text = _extract_plain_text(message)
    logger = _get_logger()

    # DIAGNOSTIC: Log telemetry handler status for debugging
    # COMMENTED: Not directly related to module re-execution tracking
    # Use print_info() directly (not logger) to ensure diagnostic is always visible
    # even if logger has issues
    # try:
    #     from .logging_config import _telemetry_console_handler, _console_handler
    #     has_telemetry_handler = _telemetry_console_handler is not None
    #     telemetry_handler_level = _telemetry_console_handler.level if _telemetry_console_handler else None
    #     logger_handlers_count = len(logger.handlers)
    #     logger_has_telemetry = any(
    #         h == _telemetry_console_handler for h in logger.handlers
    #     ) if _telemetry_console_handler else False
    #
    #     # Get handler types for debugging
    #     handler_types = [type(h).__name__ for h in logger.handlers]
    #
    #     # Print diagnostic info directly (bypasses logger to ensure visibility)
    #     diagnostic_msg = (
    #         f"[TELEMETRY_DIAG] print_info_verbose: "
    #         f"verbose_mode={_verbose_mode}, debug_mode={_debug_mode}, "
    #         f"has_telemetry_handler={has_telemetry_handler}, "
    #         f"telemetry_handler_level={telemetry_handler_level}, "
    #         f"logger_handlers_count={logger_handlers_count}, "
    #         f"logger_has_telemetry={logger_has_telemetry}, "
    #         f"handler_types={handler_types}, "
    #         f"console_handler_level={_console_handler.level if _console_handler else None}, "
    #         f"message_preview={plain_text[:50]}..."
    #     )
    #     # Use print_info() directly to ensure diagnostic is always visible
    #     print_info(diagnostic_msg)
    # except Exception:
    #     # Don't fail if diagnostic logging fails
    #     pass

    # When verbose/debug is disabled, do not emit anything to the console.
    # We still want these messages persisted to the log files.
    if not (_verbose_mode or _debug_mode):
        _diag_log(
            "print_info_verbose: suppressed to file-only "
            f"verbose={_verbose_mode}, debug={_debug_mode}"
        )
        try:
            from adscan_internal import logging_config as _logging_config  # type: ignore

            record = logger.makeRecord(
                logger.name,
                logging.INFO,
                "",
                0,
                plain_text,
                args=(),
                exc_info=None,
            )
            for handler in (
                getattr(_logging_config, "_file_handler", None),
                getattr(_logging_config, "_workspace_file_handler", None),
            ):
                if handler is None:
                    continue
                try:
                    handler.emit(record)
                except Exception:
                    continue
        except Exception:
            pass
        return

    # Verbose/debug enabled: send to logger so RichHandler renders to console + logs to file.
    _diag_log(
        "print_info_verbose: emitting to logger "
        f"verbose={_verbose_mode}, debug={_debug_mode}"
    )
    if isinstance(message, Text):
        logger.info(plain_text, stacklevel=2)
    else:
        logger.info(message, stacklevel=2)

    # DIAGNOSTIC: Verify telemetry handler is receiving messages
    # COMMENTED: Not directly related to module re-execution tracking
    # try:
    #     from .logging_config import _telemetry_console_handler, get_logger
    #     telemetry_console = _get_telemetry_console()
    #     fresh_logger = get_logger()
    #
    #     # Check handler state
    #     has_telemetry_handler = _telemetry_console_handler is not None
    #     handler_console_id = id(_telemetry_console_handler.console) if _telemetry_console_handler and _telemetry_console_handler.console else None
    #     telemetry_console_id = id(telemetry_console) if telemetry_console else None
    #     console_match = handler_console_id == telemetry_console_id
    #
    #     # Check if handler is in logger
    #     logger_has_telemetry = _telemetry_console_handler in fresh_logger.handlers if _telemetry_console_handler else False
    #
    #     # Check buffer length to see if handler is writing to it
    #     buffer_length = None
    #     if telemetry_console and hasattr(telemetry_console, 'file'):
    #         try:
    #             file_obj = telemetry_console.file
    #             if hasattr(file_obj, 'getvalue'):
    #                 buffer_length = len(file_obj.getvalue())
    #         except Exception:
    #             pass
    #
    #     print_info(
    #         f"[TELEMETRY_DIAG] After logger.info() call (verbose): "
    #         f"has_telemetry_handler={has_telemetry_handler}, "
    #         f"handler_console_id={handler_console_id}, "
    #         f"telemetry_console_id={telemetry_console_id}, "
    #         f"console_match={console_match}, "
    #         f"logger_has_telemetry={logger_has_telemetry}, "
    #         f"logger_handlers_count={len(fresh_logger.handlers)}, "
    #         f"buffer_length={buffer_length}"
    #     )
    # except Exception as e:
    #     print_info(f"[TELEMETRY_DIAG] Error checking telemetry handler state (verbose): {e}")
    #
    # # DIAGNOSTIC: Also try to send directly to telemetry console to verify it's working
    # try:
    #     telemetry_console = _get_telemetry_console()
    #     if telemetry_console is not None:
    #         # Try to send diagnostic message directly to telemetry console
    #         diagnostic_msg = f"[TELEMETRY_DIRECT] print_info_verbose: {plain_text[:50]}..."
    #         telemetry_console.print(diagnostic_msg)
    #     else:
    #         print_info("[TELEMETRY_DIAG] telemetry_console is None in print_info_verbose")
    # except Exception as e:
    #     print_info(f"[TELEMETRY_DIAG] Error sending to telemetry console (verbose): {e}")

    # FALLBACK: If RichHandler is not configured or not showing messages,
    # use logger-style format to ensure visibility and differentiation (this should not happen in normal operation)
    # This is a safety net in case the RichHandler level is not configured correctly
    try:
        from .logging_config import _console_handler

        if _console_handler is None or _console_handler.level > logging.INFO:
            # RichHandler not configured or level too high, use logger-style format as fallback
            if _verbose_mode or _debug_mode:
                _print_logger_format_fallback("INFO", message, level_color="blue")
    except (ImportError, AttributeError):
        # logging_config not available or _console_handler not accessible, use logger-style format as fallback
        if _verbose_mode or _debug_mode:
            _print_logger_format_fallback("INFO", message, level_color="blue")


def print_info_debug(message: Union[str, Text], panel: bool = False, icon: str = "ℹ"):
    """Print debug informational message (only if debug mode enabled).

    This function uses the logger directly, which will:
    - Always log to file (both global and workspace if active)
    - Conditionally show Rich output in console via RichHandler (if debug mode)
    - Uses RichHandler format (with "DEBUG" level indicator) to differentiate from normal print_info()

    Args:
        message: Message to display (supports Rich markup strings or Text objects)
        panel: Not used (kept for compatibility)
        icon: Not used (kept for compatibility)
    """
    import logging

    global _debug_mode
    plain_text = _extract_plain_text(message)
    logger = _get_logger()

    # DIAGNOSTIC: Log telemetry handler status for debugging
    # COMMENTED: Not directly related to module re-execution tracking
    # Use print_info() directly (not logger) to ensure diagnostic is always visible
    # even if logger has issues
    # try:
    #     from .logging_config import _telemetry_console_handler, _console_handler
    #     has_telemetry_handler = _telemetry_console_handler is not None
    #     telemetry_handler_level = _telemetry_console_handler.level if _telemetry_console_handler else None
    #     logger_handlers_count = len(logger.handlers)
    #     logger_has_telemetry = any(
    #         h == _telemetry_console_handler for h in logger.handlers
    #     ) if _telemetry_console_handler else False
    #
    #     # Get handler types for debugging
    #     handler_types = [type(h).__name__ for h in logger.handlers]
    #
    #     # Print diagnostic info directly (bypasses logger to ensure visibility)
    #     diagnostic_msg = (
    #         f"[TELEMETRY_DIAG] print_info_debug: "
    #         f"debug_mode={_debug_mode}, "
    #         f"has_telemetry_handler={has_telemetry_handler}, "
    #         f"telemetry_handler_level={telemetry_handler_level}, "
    #         f"logger_handlers_count={logger_handlers_count}, "
    #         f"logger_has_telemetry={logger_has_telemetry}, "
    #         f"handler_types={handler_types}, "
    #         f"console_handler_level={_console_handler.level if _console_handler else None}, "
    #         f"message_preview={plain_text[:50]}..."
    #     )
    #     # Use print_info() directly to ensure diagnostic is always visible
    #     print_info(diagnostic_msg)
    # except Exception:
    #     # Don't fail if diagnostic logging fails
    #     pass

    # Always send to logger - RichHandler will show it in console if debug mode is enabled
    # This gives the distinctive logger format (with "DEBUG" level) to differentiate from normal print_info()
    if isinstance(message, Text):
        logger.debug(plain_text, stacklevel=2)
    else:
        logger.debug(message, stacklevel=2)

    # DIAGNOSTIC: Verify telemetry handler is receiving messages
    # COMMENTED: Not directly related to module re-execution tracking
    # try:
    #     from .logging_config import _telemetry_console_handler, get_logger
    #     telemetry_console = _get_telemetry_console()
    #     fresh_logger = get_logger()
    #
    #     # Check handler state
    #     has_telemetry_handler = _telemetry_console_handler is not None
    #     handler_console_id = id(_telemetry_console_handler.console) if _telemetry_console_handler and _telemetry_console_handler.console else None
    #     telemetry_console_id = id(telemetry_console) if telemetry_console else None
    #     console_match = handler_console_id == telemetry_console_id
    #
    #     # Check if handler is in logger
    #     logger_has_telemetry = _telemetry_console_handler in fresh_logger.handlers if _telemetry_console_handler else False
    #
    #     # Check buffer length to see if handler is writing to it
    #     buffer_length = None
    #     if telemetry_console and hasattr(telemetry_console, 'file'):
    #         try:
    #             file_obj = telemetry_console.file
    #             if hasattr(file_obj, 'getvalue'):
    #                 buffer_length = len(file_obj.getvalue())
    #         except Exception:
    #             pass
    #
    #     print_info(
    #         f"[TELEMETRY_DIAG] After logger.debug() call: "
    #         f"has_telemetry_handler={has_telemetry_handler}, "
    #         f"handler_console_id={handler_console_id}, "
    #         f"telemetry_console_id={telemetry_console_id}, "
    #         f"console_match={console_match}, "
    #         f"logger_has_telemetry={logger_has_telemetry}, "
    #         f"logger_handlers_count={len(fresh_logger.handlers)}, "
    #         f"buffer_length={buffer_length}"
    #     )
    # except Exception as e:
    #     print_info(f"[TELEMETRY_DIAG] Error checking telemetry handler state: {e}")
    #
    # # DIAGNOSTIC: Also try to send directly to telemetry console to verify it's working
    # try:
    #     telemetry_console = _get_telemetry_console()
    #     if telemetry_console is not None:
    #         # Try to send diagnostic message directly to telemetry console
    #         diagnostic_msg = f"[TELEMETRY_DIRECT] print_info_debug: {plain_text[:50]}..."
    #         telemetry_console.print(diagnostic_msg)
    #     else:
    #         print_info("[TELEMETRY_DIAG] telemetry_console is None in print_info_debug")
    # except Exception as e:
    #     print_info(f"[TELEMETRY_DIAG] Error sending to telemetry console: {e}")

    # FALLBACK: If RichHandler is not configured or not showing messages,
    # use logger-style format to ensure visibility and differentiation (this should not happen in normal operation)
    # This is a safety net in case the RichHandler level is not configured correctly
    try:
        from .logging_config import _console_handler

        if _console_handler is None or _console_handler.level > logging.DEBUG:
            # RichHandler not configured or level too high, use logger-style format as fallback
            if _debug_mode:
                _print_logger_format_fallback("DEBUG", message, level_color="cyan")
    except (ImportError, AttributeError):
        # logging_config not available or _console_handler not accessible, use logger-style format as fallback
        if _debug_mode:
            _print_logger_format_fallback("DEBUG", message, level_color="cyan")


def print_success(
    message: Union[str, Text],
    panel: bool = False,
    icon: str = "✓",
    items: Optional[List[Union[str, Text]]] = None,
    spacing: str = "auto",
):
    """Print a success message with optional panel and icon.

    Args:
        message: Message to display. Can be:
            - Plain string: "Operation completed"
            - Rich markup string: "[bold]Operation[/bold] [green]completed[/green]"
            - Text object: Text("Operation", style="bold")
        panel: If True, display in a panel with border
        icon: Icon to display (default: ✓)
        items: Optional list of items to display below message (supports same formats as message)
        spacing: Spacing control ("auto", "none", "before", "after", "both"). Default: "auto"
    """
    console = _get_console()
    telemetry_console = _get_telemetry_console()

    # Handle spacing
    spacing_before = _handle_spacing("success", panel, spacing)
    if spacing_before:
        console.print()
        if telemetry_console is not None:
            telemetry_console.print()

    # Format icon
    icon_text = Text(f"{icon} ", style="green")

    # Format message (preserves Rich markup or Text object)
    if isinstance(message, Text):
        message_text = message
    elif "[" in message and "]" in message:
        # Rich markup string - parse it
        message_text = Text.from_markup(message)
    else:
        # Plain string - apply default style
        message_text = Text(message, style="green")

    if panel:
        content = Text()
        content.append(icon_text)
        content.append(message_text)

        if items:
            content.append("\n\n", style="green")
            for item in items:
                if isinstance(item, Text):
                    content.append("  • ")
                    content.append(item)
                    content.append("\n")
                elif "[" in item and "]" in item:
                    # Rich markup
                    item_text = Text.from_markup(item)
                    content.append("  • ")
                    content.append(item_text)
                    content.append("\n")
                else:
                    content.append(f"  • {item}\n", style="dim green")

        panel_renderable = Panel(
            content, border_style="green", box=ROUNDED, padding=(0, 1)
        )
        console.print(panel_renderable)
        if telemetry_console is not None:
            telemetry_console.print(panel_renderable)
        # Panels always get space after
        if spacing != "none":
            console.print()
            if telemetry_console is not None:
                telemetry_console.print()
    else:
        # Simple output: icon + message
        output = Text()
        output.append(icon_text)
        output.append(message_text)
        console.print(output)
        if telemetry_console is not None:
            telemetry_console.print(output)

        # Handle spacing after if requested
        if spacing in ("after", "both"):
            console.print()
            if telemetry_console is not None:
                telemetry_console.print()


def print_success_verbose(
    message: Union[str, Text], panel: bool = False, icon: str = "✓"
):
    """Print verbose success message (only if verbose mode enabled).

    This function uses the logger directly, which will:
    - Always log to file (both global and workspace if active)
    - Conditionally show Rich output in console via RichHandler (if verbose mode)
    - Uses RichHandler format (with "INFO" level indicator) to differentiate from normal print_success()

    Args:
        message: Message to display (supports Rich markup strings or Text objects)
        panel: Not used (kept for compatibility)
        icon: Not used (kept for compatibility)
    """
    import logging

    global _verbose_mode, _debug_mode
    plain_text = _extract_plain_text(message)
    logger = _get_logger()

    # When verbose/debug is disabled, do not emit anything to the console.
    # We still want these messages persisted to the log files.
    if not (_verbose_mode or _debug_mode):
        _diag_log(
            "print_success_verbose: suppressed to file-only "
            f"verbose={_verbose_mode}, debug={_debug_mode}"
        )
        try:
            from adscan_internal import logging_config as _logging_config  # type: ignore

            record = logger.makeRecord(
                logger.name,
                logging.INFO,
                "",
                0,
                plain_text,
                args=(),
                exc_info=None,
            )
            for handler in (
                getattr(_logging_config, "_file_handler", None),
                getattr(_logging_config, "_workspace_file_handler", None),
            ):
                if handler is None:
                    continue
                try:
                    handler.emit(record)
                except Exception:
                    continue
        except Exception:
            pass
        return

    # Verbose/debug enabled: send to logger so RichHandler renders to console + logs to file.
    _diag_log(
        "print_success_verbose: emitting to logger "
        f"verbose={_verbose_mode}, debug={_debug_mode}"
    )
    if isinstance(message, Text):
        logger.info(plain_text, stacklevel=2)
    else:
        logger.info(message, stacklevel=2)

    # FALLBACK: If RichHandler is not configured or not showing messages,
    # use logger-style format to ensure visibility and differentiation (this should not happen in normal operation)
    # This is a safety net in case the RichHandler level is not configured correctly
    try:
        from .logging_config import _console_handler

        if _console_handler is None or _console_handler.level > logging.INFO:
            # RichHandler not configured or level too high, use logger-style format as fallback
            if _verbose_mode or _debug_mode:
                _print_logger_format_fallback("INFO", message, level_color="green")
    except (ImportError, AttributeError):
        # logging_config not available or _console_handler not accessible, use logger-style format as fallback
        if _verbose_mode or _debug_mode:
            _print_logger_format_fallback("INFO", message, level_color="green")


def print_success_debug(
    message: Union[str, Text], panel: bool = False, icon: str = "✓"
):
    """Print debug success message (only if debug mode enabled).

    This function uses the logger directly, which will:
    - Always log to file (both global and workspace if active)
    - Conditionally show Rich output in console via RichHandler (if debug mode)
    - Uses RichHandler format (with "DEBUG" level indicator) to differentiate from normal print_success()

    Args:
        message: Message to display (supports Rich markup strings or Text objects)
        panel: Not used (kept for compatibility)
        icon: Not used (kept for compatibility)
    """
    import logging

    global _debug_mode
    plain_text = _extract_plain_text(message)
    logger = _get_logger()

    # Always send to logger - RichHandler will show it in console if debug mode is enabled
    # This gives the distinctive logger format (with "DEBUG" level) to differentiate from normal print_success()
    if isinstance(message, Text):
        logger.debug(plain_text, stacklevel=2)
    else:
        logger.debug(message, stacklevel=2)

    # FALLBACK: If RichHandler is not configured or not showing messages,
    # use logger-style format to ensure visibility and differentiation (this should not happen in normal operation)
    # This is a safety net in case the RichHandler level is not configured correctly
    try:
        from .logging_config import _console_handler

        if _console_handler is None or _console_handler.level > logging.DEBUG:
            # RichHandler not configured or level too high, use logger-style format as fallback
            if _debug_mode:
                _print_logger_format_fallback("DEBUG", message, level_color="cyan")
    except (ImportError, AttributeError):
        # logging_config not available or _console_handler not accessible, use logger-style format as fallback
        if _debug_mode:
            _print_logger_format_fallback("DEBUG", message, level_color="cyan")


def print_success_tick(message: Union[str, Text], panel: bool = False):
    """Print success message with tick icon (alias for print_success with tick).

    Args:
        message: Message to display (supports Rich markup strings or Text objects)
        panel: If True, display in a panel with border
    """
    print_success(message, panel=panel, icon="✓")


def print_warning(
    message: Union[str, Text],
    panel: bool = False,
    icon: str = "⚠",
    items: Optional[List[Union[str, Text]]] = None,
    spacing: str = "auto",
):
    """Print a warning message with optional panel and icon.

    Args:
        message: Message to display. Can be:
            - Plain string: "Warning message"
            - Rich markup string: "[bold]Warning[/bold] [yellow]message[/yellow]"
            - Text object: Text("Warning", style="bold")
        panel: If True, display in a panel with border
        icon: Icon to display (default: ⚠)
        items: Optional list of items to display below message (supports same formats as message)
        spacing: Spacing control ("auto", "none", "before", "after", "both"). Default: "auto"
    """
    console = _get_console()
    telemetry_console = _get_telemetry_console()

    # Handle spacing
    spacing_before = _handle_spacing("warning", panel, spacing)
    if spacing_before:
        console.print()
        if telemetry_console is not None:
            telemetry_console.print()

    # Format icon
    icon_text = Text(f"{icon} ", style="yellow")

    # Format message (preserves Rich markup or Text object)
    if isinstance(message, Text):
        message_text = message
    elif "[" in message and "]" in message:
        # Rich markup string - parse it
        message_text = Text.from_markup(message)
    else:
        # Plain string - apply default style
        message_text = Text(message, style="yellow")

    if panel:
        content = Text()
        content.append(icon_text)
        content.append(message_text)

        if items:
            content.append("\n\n", style="yellow")
            for item in items:
                if isinstance(item, Text):
                    content.append("  • ")
                    content.append(item)
                    content.append("\n")
                elif "[" in item and "]" in item:
                    # Rich markup
                    item_text = Text.from_markup(item)
                    content.append("  • ")
                    content.append(item_text)
                    content.append("\n")
                else:
                    content.append(f"  • {item}\n", style="dim yellow")

        panel_renderable = Panel(
            content, border_style="yellow", box=ROUNDED, padding=(0, 1)
        )
        console.print(panel_renderable)
        if telemetry_console is not None:
            telemetry_console.print(panel_renderable)
        # Panels always get space after
        if spacing != "none":
            console.print()
            if telemetry_console is not None:
                telemetry_console.print()
    else:
        # Simple output: icon + message
        output = Text()
        output.append(icon_text)
        output.append(message_text)
        console.print(output)
        if telemetry_console is not None:
            telemetry_console.print(output)

        # Handle spacing after if requested
        if spacing in ("after", "both"):
            console.print()
            if telemetry_console is not None:
                telemetry_console.print()


def print_warning_verbose(
    message: Union[str, Text], panel: bool = False, icon: str = "⚠"
):
    """Print verbose warning message (only if verbose mode enabled).

    This function uses the logger directly, which will:
    - Always log to file (both global and workspace if active)
    - Conditionally show Rich output in console via RichHandler (if verbose mode)
    - Uses RichHandler format (with "WARNING" level indicator) to differentiate from normal print_warning()

    Args:
        message: Message to display (supports Rich markup strings or Text objects)
        panel: Not used (kept for compatibility)
        icon: Not used (kept for compatibility)
    """
    import logging

    global _verbose_mode, _debug_mode
    plain_text = _extract_plain_text(message)
    logger = _get_logger()

    # When verbose/debug is disabled, do not emit anything to the console.
    # We still want these messages persisted to the log files.
    if not (_verbose_mode or _debug_mode):
        try:
            from adscan_internal import logging_config as _logging_config  # type: ignore

            record = logger.makeRecord(
                logger.name,
                logging.WARNING,
                "",
                0,
                plain_text,
                args=(),
                exc_info=None,
            )
            for handler in (
                getattr(_logging_config, "_file_handler", None),
                getattr(_logging_config, "_workspace_file_handler", None),
            ):
                if handler is None:
                    continue
                try:
                    handler.emit(record)
                except Exception:
                    continue
        except Exception:
            pass
        return

    # Verbose/debug enabled: send to logger so RichHandler renders to console + logs to file.
    if isinstance(message, Text):
        logger.warning(plain_text, stacklevel=2)
    else:
        logger.warning(message, stacklevel=2)

    # FALLBACK: If RichHandler is not configured or not showing messages,
    # use logger-style format to ensure visibility and differentiation (this should not happen in normal operation)
    # This is a safety net in case the RichHandler level is not configured correctly
    try:
        from .logging_config import _console_handler

        if _console_handler is None or _console_handler.level > logging.WARNING:
            # RichHandler not configured or level too high, use logger-style format as fallback
            if _verbose_mode or _debug_mode:
                _print_logger_format_fallback("WARNING", message, level_color="yellow")
    except (ImportError, AttributeError):
        # logging_config not available or _console_handler not accessible, use logger-style format as fallback
        if _verbose_mode or _debug_mode:
            _print_logger_format_fallback("WARNING", message, level_color="yellow")


def print_warning_debug(
    message: Union[str, Text], panel: bool = False, icon: str = "⚠"
):
    """Print debug warning message (only if debug mode enabled).

    This function uses the logger directly, which will:
    - Always log to file (both global and workspace if active)
    - Conditionally show Rich output in console via RichHandler (if debug mode)
    - Uses RichHandler format (with "DEBUG" level indicator) to differentiate from normal print_warning()

    Args:
        message: Message to display (supports Rich markup strings or Text objects)
        panel: Not used (kept for compatibility)
        icon: Not used (kept for compatibility)
    """
    import logging

    global _debug_mode
    plain_text = _extract_plain_text(message)
    logger = _get_logger()

    # Always send to logger - RichHandler will show it in console if debug mode is enabled
    # This gives the distinctive logger format (with "DEBUG" level) to differentiate from normal print_warning()
    if isinstance(message, Text):
        logger.debug(plain_text, stacklevel=2)
    else:
        logger.debug(message, stacklevel=2)

    # FALLBACK: If RichHandler is not configured or not showing messages,
    # use logger-style format to ensure visibility and differentiation (this should not happen in normal operation)
    # This is a safety net in case the RichHandler level is not configured correctly
    try:
        from .logging_config import _console_handler

        if _console_handler is None or _console_handler.level > logging.DEBUG:
            # RichHandler not configured or level too high, use logger-style format as fallback
            if _debug_mode:
                _print_logger_format_fallback("DEBUG", message, level_color="cyan")
    except (ImportError, AttributeError):
        # logging_config not available or _console_handler not accessible, use logger-style format as fallback
        if _debug_mode:
            _print_logger_format_fallback("DEBUG", message, level_color="cyan")


def print_error(
    message: Union[str, Text],
    panel: bool = False,
    icon: str = "✗",
    items: Optional[List[Union[str, Text]]] = None,
    spacing: str = "auto",
):
    """Print an error message with optional panel and icon.

    Args:
        message: Message to display. Can be:
            - Plain string: "Error occurred"
            - Rich markup string: "[bold]Error[/bold] [red]occurred[/red]"
            - Text object: Text("Error", style="bold")
        panel: If True, display in a panel with border
        icon: Icon to display (default: ✗)
        items: Optional list of items to display below message (supports same formats as message)
        spacing: Spacing control ("auto", "none", "before", "after", "both"). Default: "auto"
    """
    console = _get_console()
    telemetry_console = _get_telemetry_console()

    # Handle spacing
    spacing_before = _handle_spacing("error", panel, spacing)
    if spacing_before:
        console.print()
        if telemetry_console is not None:
            telemetry_console.print()

    # Format icon
    icon_text = Text(f"{icon} ", style="bold red")

    # Format message (preserves Rich markup or Text object)
    if isinstance(message, Text):
        message_text = message
    elif "[" in message and "]" in message:
        # Rich markup string - parse it
        message_text = Text.from_markup(message)
    else:
        # Plain string - apply default style
        message_text = Text(message, style="bold red")

    if panel:
        content = Text()
        content.append(icon_text)
        content.append(message_text)

        if items:
            content.append("\n\n", style="bold red")
            for item in items:
                if isinstance(item, Text):
                    content.append("  • ")
                    content.append(item)
                    content.append("\n")
                elif "[" in item and "]" in item:
                    # Rich markup
                    item_text = Text.from_markup(item)
                    content.append("  • ")
                    content.append(item_text)
                    content.append("\n")
                else:
                    content.append(f"  • {item}\n", style="dim red")

        panel_renderable = Panel(
            content, border_style="red", box=ROUNDED, padding=(0, 1)
        )
        console.print(panel_renderable)
        if telemetry_console is not None:
            telemetry_console.print(panel_renderable)
        # Panels always get space after
        if spacing != "none":
            console.print()
            if telemetry_console is not None:
                telemetry_console.print()
    else:
        # Simple output: icon + message
        output = Text()
        output.append(icon_text)
        output.append(message_text)
        console.print(output)
        if telemetry_console is not None:
            telemetry_console.print(output)

        # Handle spacing after if requested
        if spacing in ("after", "both"):
            console.print()
            if telemetry_console is not None:
                telemetry_console.print()


def print_error_verbose(
    message: Union[str, Text], panel: bool = False, icon: str = "✗"
):
    """Print verbose error message (only if verbose or debug mode enabled).

    This function uses the logger directly, which will:
    - Always log to file (both global and workspace if active)
    - Conditionally show Rich output in console via RichHandler (if verbose/debug mode)
    - Uses RichHandler format (with "ERROR" level indicator) to differentiate from normal print_error()

    Args:
        message: Message to display (supports Rich markup strings or Text objects)
        panel: Not used (kept for compatibility)
        icon: Not used (kept for compatibility)
    """
    import logging

    global _verbose_mode, _debug_mode
    plain_text = _extract_plain_text(message)
    logger = _get_logger()

    # When verbose/debug is disabled, do not emit anything to the console.
    # We still want these messages persisted to the log files.
    if not (_verbose_mode or _debug_mode):
        try:
            from adscan_internal import logging_config as _logging_config  # type: ignore

            record = logger.makeRecord(
                logger.name,
                logging.ERROR,
                "",
                0,
                plain_text,
                args=(),
                exc_info=None,
            )
            for handler in (
                getattr(_logging_config, "_file_handler", None),
                getattr(_logging_config, "_workspace_file_handler", None),
            ):
                if handler is None:
                    continue
                try:
                    handler.emit(record)
                except Exception:
                    continue
        except Exception:
            pass
        return

    # Verbose/debug enabled: send to logger so RichHandler renders to console + logs to file.
    if isinstance(message, Text):
        logger.error(plain_text, stacklevel=2)
    else:
        logger.error(message, stacklevel=2)

    # FALLBACK: If RichHandler is not configured or not showing messages,
    # use logger-style format to ensure visibility and differentiation (this should not happen in normal operation)
    # This is a safety net in case the RichHandler level is not configured correctly
    try:
        from .logging_config import _console_handler

        if _console_handler is None or _console_handler.level > logging.ERROR:
            # RichHandler not configured or level too high, use logger-style format as fallback
            if _verbose_mode or _debug_mode:
                _print_logger_format_fallback("ERROR", message, level_color="red")
    except (ImportError, AttributeError):
        # logging_config not available or _console_handler not accessible, use logger-style format as fallback
        if _verbose_mode or _debug_mode:
            _print_logger_format_fallback("ERROR", message, level_color="red")


def print_error_debug(message: Union[str, Text], panel: bool = False, icon: str = "✗"):
    """Print debug error message (only if debug mode enabled).

    This function uses the logger directly, which will:
    - Always log to file (both global and workspace if active)
    - Conditionally show Rich output in console via RichHandler (if debug mode)
    - Uses RichHandler format (with "DEBUG" level indicator) to differentiate from normal print_error()

    Args:
        message: Message to display (supports Rich markup strings or Text objects)
        panel: Not used (kept for compatibility)
        icon: Not used (kept for compatibility)
    """
    import logging

    global _debug_mode
    plain_text = _extract_plain_text(message)
    logger = _get_logger()

    # Always send to logger - RichHandler will show it in console if debug mode is enabled
    # This gives the distinctive logger format (with "DEBUG" level) to differentiate from normal print_error()
    if isinstance(message, Text):
        logger.debug(plain_text, stacklevel=2)
    else:
        logger.debug(message, stacklevel=2)

    # FALLBACK: If RichHandler is not configured or not showing messages,
    # use logger-style format to ensure visibility and differentiation (this should not happen in normal operation)
    # This is a safety net in case the RichHandler level is not configured correctly
    try:
        from .logging_config import _console_handler

        if _console_handler is None or _console_handler.level > logging.DEBUG:
            # RichHandler not configured or level too high, use logger-style format as fallback
            if _debug_mode:
                _print_logger_format_fallback("DEBUG", message, level_color="cyan")
    except (ImportError, AttributeError):
        # logging_config not available or _console_handler not accessible, use logger-style format as fallback
        if _debug_mode:
            _print_logger_format_fallback("DEBUG", message, level_color="cyan")


def print_instruction(
    message: Union[str, Text], panel: bool = False, spacing: str = "auto"
):
    """Print an instruction message with dimmed style.

    Args:
        message: Message to display. Can be:
            - Plain string: "Enter your name"
            - Rich markup string: "[bold]Enter[/bold] your [dim]name[/dim]"
            - Text object: Text("Enter", style="bold")
        panel: If True, display in a panel with border
        spacing: Spacing control ("auto", "none", "before", "after", "both"). Default: "auto"
    """
    console = _get_console()
    telemetry_console = _get_telemetry_console()

    # Handle spacing
    spacing_before = _handle_spacing("instruction", panel, spacing)
    if spacing_before:
        console.print()
        if telemetry_console is not None:
            telemetry_console.print()

    # Format message (preserves Rich markup or Text object)
    if isinstance(message, Text):
        message_text = message
    elif "[" in message and "]" in message:
        # Rich markup string - parse it
        message_text = Text.from_markup(message)
    else:
        # Plain string - apply default style
        message_text = Text(message, style="dim")

    if panel:
        panel_renderable = Panel(
            message_text, border_style="dim", box=ROUNDED, padding=(0, 1)
        )
        console.print(panel_renderable)
        if telemetry_console is not None:
            telemetry_console.print(panel_renderable)
        # Panels always get space after
        if spacing != "none":
            console.print()
            if telemetry_console is not None:
                telemetry_console.print()
    else:
        output = Text("   ", style="dim")
        output.append(message_text)
        console.print(output)
        if telemetry_console is not None:
            telemetry_console.print(output)

        # Handle spacing after if requested
        if spacing in ("after", "both"):
            console.print()
            if telemetry_console is not None:
                telemetry_console.print()


# --- Advanced Print Functions ---


def print_panel(
    content: Union[str, Text, Group, list[RenderableType], tuple[RenderableType, ...]],
    title: Optional[str] = None,
    subtitle: Optional[str] = None,
    border_style: Optional[str] = None,
    box: Box = ROUNDED,
    padding: tuple = (1, 2),
    expand: bool = True,
    fit: bool = False,
    spacing: str = "auto",
):
    """Print a custom panel with full control over content and styling.

    This function provides a generic way to create panels with custom content,
    maintaining consistency with brand colors and intelligent spacing.

    Args:
        content: Panel content. Can be:
            - Plain string: "Simple content"
            - Rich markup string: "[bold]Content[/bold] with [red]markup[/red]"
            - Text object: Text("Content", style="bold")
            - Group object: Group(Text(...), Text(...)) for multiple renderables
            - List/tuple of renderables: [Table(...), Text(...)] (wrapped in Group)
        title: Optional panel title (supports Rich markup strings)
        border_style: Border color style (defaults to brand color if None)
        box: Box style (MINIMAL, ROUNDED, etc.) - default: MINIMAL
        padding: Padding tuple (vertical, horizontal) - default: (0, 1)
        expand: Whether panel expands to full width - default: True
        fit: If True, use Panel.fit() to fit panel to content width (ignores expand/padding) - default: False
        spacing: Spacing control ("auto", "none", "before", "after", "both"). Default: "auto"
            - "auto": Intelligent spacing (panels always get spacing)
            - "none": No spacing
            - "before": Space before panel
            - "after": Space after panel
            - "both": Space before and after

    Examples:
        # Simple panel with brand color
        print_panel("Simple content", title="Title")

        # Custom panel with Rich markup
        print_panel(
            "[bold]Domain[/bold]: example.local",
            title="[bold]Domain Information[/bold]",
            border_style=BRAND_COLORS["info"],
            expand=False
        )

        # Fit panel to content (like Panel.fit)
        print_panel(
            "Content that fits exactly",
            title="Fitted Panel",
            fit=True,
            border_style="yellow"
        )

        # Centered content panel
        from rich.text import Text
        content = Text("Centered", justify="center")
        print_panel(content, title="Centered Panel", box=ROUNDED)

        # Panel with Group (multiple renderables)
        from rich.console import Group
        group_content = Group(
            Text.from_markup("[bold]Title[/bold]"),
            Text("Body content")
        )
        print_panel(group_content, title="Group Panel")
    """
    console = _get_console()
    telemetry_console = _get_telemetry_console()

    # Use brand color as default border style
    if border_style is None:
        border_style = BRAND_COLORS["info"]

    # Handle spacing (panels always get spacing by default)
    spacing_before = _handle_spacing("info", True, spacing)
    if spacing_before:
        console.print()
        if telemetry_console is not None:
            telemetry_console.print()

    def _coerce_renderable(item: object) -> RenderableType:
        """Convert a supported value into a Rich renderable.

        This avoids Rich calling string-only APIs (e.g. `.translate`) on
        non-strings when callers accidentally pass lists of renderables.
        """
        if isinstance(item, Group):
            return item
        if isinstance(item, Text):
            return item
        if isinstance(item, str) and "[" in item and "]" in item:
            return Text.from_markup(item)
        if isinstance(item, str):
            return Text(item, style="white")
        # For any other Rich renderables (Table, Panel, etc.) pass-through.
        return item  # type: ignore[return-value]

    # Format content (preserves Rich markup, Text object, or Group)
    panel_content: RenderableType
    if isinstance(content, (list, tuple)):
        panel_content = Group(*[_coerce_renderable(item) for item in content])
    else:
        panel_content = _coerce_renderable(content)

    # Create panel (use Panel.fit if fit=True, otherwise regular Panel)
    if fit:
        panel = Panel.fit(
            panel_content,
            title=title,
            subtitle=subtitle,
            border_style=border_style,
            box=box,
            padding=padding,
        )
    else:
        panel = Panel(
            panel_content,
            title=title,
            subtitle=subtitle,
            border_style=border_style,
            box=box,
            padding=padding,
            expand=expand,
        )

    console.print(panel)
    if telemetry_console is not None:
        telemetry_console.print(panel)

    # Handle spacing after
    if spacing != "none":
        if spacing in ("after", "both"):
            console.print()
            if telemetry_console is not None:
                telemetry_console.print()
        else:
            # Auto mode: panels always get space after
            console.print()
            if telemetry_console is not None:
                telemetry_console.print()


def print_section(
    title: str, content: str, border_style: str = "blue", icon: Optional[str] = None
):
    """Print a section with title and content in a panel.

    Args:
        title: Section title
        content: Section content
        border_style: Border color style
        icon: Optional icon to display before title
    """
    console = _get_console()
    telemetry_console = _get_telemetry_console()

    title_text = Text()
    if icon:
        title_text.append(f"{icon} ", style=border_style)
    title_text.append(title, style=f"bold {border_style}")

    panel_content = Text()
    panel_content.append(f"{title_text}\n\n", style=border_style)
    panel_content.append(content, style="white")

    panel_renderable = Panel(
        panel_content, border_style=border_style, box=ROUNDED, padding=(1, 2)
    )
    console.print(panel_renderable)
    if telemetry_console is not None:
        telemetry_console.print(panel_renderable)


def print_info_table(
    data: List[Dict[str, Any]], columns: List[str], title: Optional[str] = None
):
    """Print data in a formatted table.

    Args:
        data: List of dictionaries with data rows
        columns: List of column names (keys from data dictionaries)
        title: Optional table title
    """
    table = Table(
        title=title, show_header=True, header_style="bold magenta", box=ROUNDED
    )

    # Add columns
    for col in columns:
        table.add_column(col, style=BRAND_COLORS["info"])

    # Add rows
    for row in data:
        table.add_row(*[str(row.get(col, "")) for col in columns])

    # Use shared table printer to get consistent spacing behaviour
    print_table(table)


def print_info_list(items: List[str], title: Optional[str] = None, icon: str = "•"):
    """Print a list of items in a formatted panel.

    Args:
        items: List of items to display
        title: Optional panel title
        icon: Icon to use for list items
    """
    console = _get_console()
    telemetry_console = _get_telemetry_console()

    content = Text()
    for item in items:
        content.append(f"{icon} {item}\n", style="white")

    if title:
        panel_renderable = Panel(
            content,
            title=title,
            border_style=BRAND_COLORS["info"],
            box=ROUNDED,
            padding=(1, 2),
        )
    else:
        panel_renderable = Panel(
            content, border_style=BRAND_COLORS["info"], box=ROUNDED, padding=(0, 1)
        )

    console.print(panel_renderable)
    if telemetry_console is not None:
        telemetry_console.print(panel_renderable)


def print_adaptive_table_or_summary(
    items: List[Dict[str, Any]],
    *,
    columns: List[str],
    title: Optional[str] = None,
    threshold: int = 10,
    summary_label: str = "items",
) -> None:
    """Print a detailed table for small sets or a compact summary for large sets.

    - If ``len(items) <= threshold`` → just render a Rich table (no extra summary).
    - If ``len(items) > threshold`` → skip the table and print only a summary line.
    """
    count = len(items)
    if count == 0:
        return

    if count <= threshold:
        print_info_table(items, columns, title=title)
        return

    label = summary_label if count == 1 else summary_label
    print_info(f"Extracted {count} {label}.")


def print_table(
    table: Table,
    spacing: str = "auto",
):
    """Print a Rich Table directly with intelligent spacing.

    This function provides a consistent way to print Rich Table objects
    with proper spacing and brand color integration.

    Args:
        table: Rich Table object to print
        spacing: Spacing control ("auto", "none", "before", "after", "both"). Default: "auto"

    Examples:
        from rich.table import Table
        table = Table(title="My Table")
        table.add_column("Name", style=BRAND_COLORS["info"])
        table.add_row("Value 1", "Value 2")
        print_table(table)
    """
    console = _get_console()
    telemetry_console = _get_telemetry_console()

    # Handle spacing
    spacing_before = _handle_spacing("info", False, spacing)
    if spacing_before:
        console.print()
        if telemetry_console is not None:
            telemetry_console.print()

    console.print(table)
    if telemetry_console is not None:
        telemetry_console.print(table)

    # Handle spacing after
    if spacing in ("after", "both"):
        console.print()
        if telemetry_console is not None:
            telemetry_console.print()


def print_panel_with_table(
    table: Table,
    title: Optional[str] = None,
    border_style: Optional[str] = None,
    box: Box = ROUNDED,
    padding: tuple = (1, 2),
    expand: bool = True,
    spacing: str = "auto",
):
    """Print a Rich Table inside a Panel with consistent styling.

    This is useful for displaying tables in a visually distinct panel,
    such as installation summaries or configuration displays.

    Args:
        table: Rich Table object to display inside the panel
        title: Optional panel title (supports Rich markup strings)
        border_style: Border color style (defaults to brand color if None)
        box: Box style (MINIMAL, ROUNDED, etc.) - default: ROUNDED
        padding: Padding tuple (vertical, horizontal) - default: (1, 2)
        expand: Whether panel expands to full width - default: True
        spacing: Spacing control ("auto", "none", "before", "after", "both"). Default: "auto"

    Examples:
        from rich.table import Table
        table = Table()
        table.add_column("Item", style=BRAND_COLORS["info"])
        table.add_row("Value")
        print_panel_with_table(
            table,
            title="[bold]Installation Summary[/bold]",
            border_style="green"
        )
    """
    console = _get_console()
    telemetry_console = _get_telemetry_console()

    # Use brand color as default border style
    if border_style is None:
        border_style = BRAND_COLORS["info"]

    # Handle spacing (panels always get spacing by default)
    spacing_before = _handle_spacing("info", True, spacing)
    if spacing_before:
        console.print()
        if telemetry_console is not None:
            telemetry_console.print()

    # Create panel with table inside
    panel = Panel(
        table,
        title=title,
        border_style=border_style,
        box=box,
        padding=padding,
        expand=expand,
    )

    console.print(panel)
    if telemetry_console is not None:
        telemetry_console.print(panel)

    # Handle spacing after
    if spacing != "none":
        if spacing in ("after", "both"):
            console.print()
            if telemetry_console is not None:
                telemetry_console.print()
        else:
            # Auto mode: panels always get space after
            console.print()
            if telemetry_console is not None:
                telemetry_console.print()


def print_group(messages: List[tuple], group_title: Optional[str] = None):
    """Print a group of related messages together.

    Args:
        messages: List of tuples (message_type, message) where message_type is
            'info', 'success', 'warning', 'error'
        group_title: Optional title for the group
    """
    console = _get_console()
    telemetry_console = _get_telemetry_console()
    group_items = []

    if group_title:
        title_text = Text(group_title, style=f"bold {BRAND_COLORS['info']}")
        group_items.append(title_text)
        group_items.append(Text(""))  # Empty line

    for msg_type, message in messages:
        if msg_type == "info":
            group_items.append(Text(f"ℹ {message}", style=BRAND_COLORS["info"]))
        elif msg_type == "success":
            group_items.append(Text(f"✓ {message}", style="green"))
        elif msg_type == "warning":
            group_items.append(Text(f"⚠ {message}", style="yellow"))
        elif msg_type == "error":
            group_items.append(Text(f"✗ {message}", style="bold red"))
        else:
            group_items.append(Text(message))

    if group_title:
        panel_renderable = Panel(
            Group(*group_items),
            border_style=BRAND_COLORS["info"],
            box=ROUNDED,
            padding=(1, 2),
        )
        console.print(panel_renderable)
        if telemetry_console is not None:
            telemetry_console.print(panel_renderable)
    else:
        group_renderable = Group(*group_items)
        console.print(group_renderable)
        if telemetry_console is not None:
            telemetry_console.print(group_renderable)


def print_exception(show_locals: bool = False, exception: Optional[Exception] = None):
    """Print exception traceback with Rich formatting.

    **IMPORTANT**: Tracebacks are only shown when `SECRET_MODE = True` to protect
    internal implementation details. When `SECRET_MODE = False`, only a generic
    error message is displayed to end users.

    Args:
        show_locals: If True, show local variables in traceback (default: False)
        exception: Optional exception object to extract message from. If None, uses
            the current exception context (must be called within except block).

    Examples:
        try:
            risky_operation()
        except Exception as e:
            # In SECRET_MODE: shows full traceback
            # In normal mode: shows generic error message
            print_exception(show_locals=True, exception=e)
    """
    console = _get_console()
    telemetry_console = _get_telemetry_console()

    # Only show full tracebacks in SECRET_MODE (protects internal structure)
    if _secret_mode:
        # Rich's Console.print_exception() requires an active exception context.
        # When an exception object is provided (e.g. raised elsewhere and stored),
        # render it explicitly to avoid ValueError: "Value for 'trace' required...".
        if exception is not None:
            from rich.traceback import Traceback

            traceback_renderable = Traceback.from_exception(
                type(exception),
                exception,
                exception.__traceback__,
                show_locals=show_locals,
            )
            console.print(traceback_renderable)
            if telemetry_console is not None:
                telemetry_console.print(traceback_renderable)
        else:
            console.print_exception(show_locals=show_locals)
            if telemetry_console is not None:
                telemetry_console.print_exception(show_locals=show_locals)
    else:
        # Generic error message for end users (no internal details)
        # Never show tracebacks, file paths, or internal structure
        if exception:
            error_type = type(exception).__name__
            error_msg = str(exception)

            # Sanitize: remove all internal details
            import re

            # Remove file paths and line numbers (multiple patterns)
            clean_msg = re.sub(r'File "[^"]+", line \d+', "", error_msg)
            clean_msg = re.sub(r'File "[^"]+"', "", clean_msg)
            clean_msg = re.sub(r", line \d+", "", clean_msg)
            # Remove absolute paths
            clean_msg = re.sub(r"/[^\s:]+", "[path hidden]", clean_msg)
            # Remove relative paths
            clean_msg = re.sub(r"[./][^\s:]+\.py", "[file hidden]", clean_msg)
            # Remove stack trace indicators
            clean_msg = re.sub(r"Traceback \(most recent call last\):", "", clean_msg)
            clean_msg = re.sub(r"^\s+File.*$", "", clean_msg, flags=re.MULTILINE)
            # Remove any remaining path-like patterns
            clean_msg = re.sub(r"/[a-zA-Z0-9_/.-]+", "[path hidden]", clean_msg)

            # Extract just the first line (usually the actual error message)
            clean_msg = clean_msg.split("\n")[0].strip()

            # Remove any remaining technical details
            if (
                "File" in clean_msg
                or "line" in clean_msg
                or "/home" in clean_msg
                or "/usr" in clean_msg
            ):
                # Still contains technical details, use generic message
                print_error(
                    f"An error occurred ({error_type}). Please try again or contact support."
                )
            elif not clean_msg or len(clean_msg) > 200:
                # Message is empty or too long, use generic message
                print_error(
                    f"An error occurred ({error_type}). Please try again or contact support."
                )
            else:
                # Show sanitized error message
                # Use a Text object to avoid Rich markup parsing of bracketed placeholders
                # like "[path hidden]" or "[PATH]" in sanitized messages.
                print_error(Text(f"Error: {clean_msg}", style="bold red"))
        else:
            # No exception object provided, show generic message
            print_error(
                "An unexpected error occurred. Please try again or contact support."
            )


# ============================================================================
# Progress Bars and Status Indicators
# ============================================================================


@contextmanager
def create_progress(
    show_spinner: bool = True,
    show_percentage: bool = True,
    show_time_remaining: bool = False,
    show_time_elapsed: bool = False,
    transient: bool = False,
):
    """Create a Rich Progress context manager with brand styling.

    This provides a consistent progress bar interface for operations that have
    measurable progress (file downloads, installation steps, scanning targets, etc.).

    Args:
        show_spinner: Show animated spinner (default: True)
        show_percentage: Show percentage completion (default: True)
        show_time_remaining: Show estimated time remaining (default: False)
        show_time_elapsed: Show time elapsed (default: False)
        transient: Remove progress bar when complete (default: False)

    Yields:
        Progress: Rich Progress object for tracking tasks

    Examples:
        # Basic progress bar for multiple items
        with create_progress() as progress:
            task = progress.add_task("[cyan]Installing tools...", total=len(tools))
            for tool in tools:
                progress.update(task, description=f"[cyan]Installing {tool}...")
                install_tool(tool)
                progress.advance(task)

        # Progress with time estimation
        with create_progress(show_time_remaining=True) as progress:
            task = progress.add_task("[cyan]Downloading...", total=file_size)
            for chunk in download_chunks():
                progress.update(task, advance=len(chunk))

        # Multiple concurrent tasks
        with create_progress() as progress:
            task1 = progress.add_task("[cyan]Task 1...", total=100)
            task2 = progress.add_task("[green]Task 2...", total=50)
            # Update tasks independently
            progress.update(task1, advance=10)
            progress.update(task2, advance=5)
    """
    console = _get_console()

    # Build columns based on options
    columns: list[ProgressColumn] = []

    if show_spinner:
        columns.append(SpinnerColumn(spinner_name="dots", style=ADSCAN_PRIMARY))

    columns.append(TextColumn("[progress.description]{task.description}"))
    columns.append(BarColumn(complete_style=ADSCAN_PRIMARY, finished_style="green"))

    if show_percentage:
        columns.append(TaskProgressColumn())

    if show_time_remaining:
        columns.append(TimeRemainingColumn())

    if show_time_elapsed:
        columns.append(TimeElapsedColumn())

    # Create progress with brand styling
    progress = Progress(
        *columns,
        console=console,
        transient=transient,
        expand=False,
    )

    try:
        with progress:
            yield progress
    finally:
        pass


@contextmanager
def create_status(
    message: str,
    spinner: str = "dots",
    spinner_style: Optional[str] = None,
):
    """Create a Rich Status context manager with brand styling.

    This provides an animated spinner for indeterminate operations (operations
    where progress cannot be measured, like waiting for network response,
    analyzing data, etc.).

    Args:
        message: Status message to display
        spinner: Spinner animation style (default: "dots")
            Available: dots, line, pipe, simpleDots, star, arrow, bouncingBar,
                      bouncingBall, clock, earth, moon, etc.
        spinner_style: Color style for spinner (default: brand primary color)

    Yields:
        Status: Rich Status object for updating message

    Examples:
        # Basic spinner
        with create_status("Scanning domain..."):
            results = scan_domain()

        # Update message during operation
        with create_status("Initializing...") as status:
            init_tools()
            status.update("Connecting to domain...")
            connect()
            status.update("Analyzing results...")
            analyze()

        # Different spinner style
        with create_status("Processing...", spinner="bouncingBar"):
            long_operation()
    """
    console = _get_console()

    # Use brand color if no style specified
    if spinner_style is None:
        spinner_style = ADSCAN_PRIMARY

    # Create status with brand styling
    status = Status(
        message,
        console=console,
        spinner=spinner,
        spinner_style=spinner_style,
    )

    try:
        with status:
            yield status
    finally:
        pass


def create_progress_simple(total: int, description: str = "Processing...") -> tuple:
    """Create a simple progress bar with single task (convenience wrapper).

    This is a simplified version of create_progress() for the common case of
    tracking a single operation with known total steps.

    Args:
        total: Total number of steps
        description: Description to display (supports Rich markup)

    Returns:
        Tuple of (progress_context, task_id) ready to use

    Examples:
        # Simple usage
        progress, task = create_progress_simple(len(items), "[cyan]Processing items...")
        with progress:
            for item in items:
                process(item)
                progress.advance(task)

        # Update description during processing
        progress, task = create_progress_simple(100, "[cyan]Starting...")
        with progress:
            for i in range(100):
                progress.update(task, description=f"[cyan]Processing {i+1}/100...")
                work()
                progress.advance(task)
    """
    console = _get_console()

    progress = Progress(
        SpinnerColumn(spinner_name="dots", style=ADSCAN_PRIMARY),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(complete_style=ADSCAN_PRIMARY, finished_style="green"),
        TaskProgressColumn(),
        console=console,
        expand=False,
    )

    # Create task (must be done before entering context)
    task_id = progress.add_task(description, total=total)

    return progress, task_id


def create_status_simple(message: str) -> Status:
    """Create a simple status spinner (convenience wrapper).

    This is a simplified version of create_status() for quick spinner creation.

    Args:
        message: Status message to display (supports Rich markup)

    Returns:
        Status object ready to use with 'with' statement

    Examples:
        # Simple usage
        with create_status_simple("Loading..."):
            load_data()

        # Update message
        status = create_status_simple("Initializing...")
        with status:
            init()
            status.update("Processing...")
            process()
    """
    console = _get_console()
    return Status(
        message, console=console, spinner="dots", spinner_style=ADSCAN_PRIMARY
    )


# ============================================================================
# Enhanced Table Creation Functions
# ============================================================================


def create_styled_table(
    title: Optional[str] = None,
    caption: Optional[str] = None,
    show_header: bool = True,
    show_lines: bool = False,
    show_edge: bool = True,
    expand: bool = False,
    box_style: Box = ROUNDED,
) -> Table:
    """Create a Rich Table with consistent ADscan brand styling.

    This function provides a standardized way to create tables with the
    brand color scheme applied automatically.

    Args:
        title: Optional table title (supports Rich markup)
        caption: Optional table caption shown at bottom (supports Rich markup)
        show_header: Show column headers (default: True)
        show_lines: Show lines between rows (default: False)
        show_edge: Show outer border (default: True)
        expand: Expand table to full width (default: False)
        box_style: Box style to use (default: ROUNDED)

    Returns:
        Configured Table object ready for adding columns and rows

    Examples:
        # Basic table
        table = create_styled_table(title="Scan Results")
        table.add_column("Target", style=ADSCAN_PRIMARY)
        table.add_column("Status", justify="center")
        table.add_row("192.168.1.1", "[green]✓[/green]")

        # Detailed table with lines
        table = create_styled_table(
            title="[bold]Findings Summary[/bold]",
            show_lines=True,
            caption="Total: 42 findings"
        )
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        table.add_row("[red]Critical[/red]", "5")
        table.add_row("[yellow]High[/yellow]", "12")
    """
    table = Table(
        title=title,
        caption=caption,
        show_header=show_header,
        show_lines=show_lines,
        show_edge=show_edge,
        expand=expand,
        box=box_style,
        border_style=ADSCAN_PRIMARY,
        header_style=f"bold {ADSCAN_PRIMARY}",
        caption_style=f"dim {ADSCAN_PRIMARY}",
        padding=(0, 1),
    )
    return table


def create_summary_table(items: List[tuple], title: str = "Summary") -> Table:
    """Create a two-column summary table (key-value pairs).

    Convenient for displaying configuration, status, or summary information
    in a clean two-column format.

    Args:
        items: List of (key, value) tuples
        title: Table title (default: "Summary")

    Returns:
        Populated Table ready to print

    Examples:
        summary = create_summary_table([
            ("Domain", "example.local"),
            ("PDC", "dc01.example.local"),
            ("Users Found", "1,234"),
            ("Computers Found", "567"),
        ], title="Domain Information")
        print_table(summary)
    """
    table = create_styled_table(title=title, show_header=False)
    table.add_column("Property", style=f"bold {ADSCAN_PRIMARY}", no_wrap=True)
    table.add_column("Value", style="white")

    for key, value in items:
        table.add_row(key, str(value))

    return table


def create_findings_table(
    findings: List[Dict[str, Any]],
    title: str = "Findings",
    show_severity: bool = True,
) -> Table:
    """Create a findings table with severity color-coding.

    Automatically applies severity-based color coding for security findings.

    Args:
        findings: List of finding dictionaries with keys:
            - target: Target name/IP
            - finding: Finding description
            - severity: Severity level (Critical, High, Medium, Low, Info)
        title: Table title
        show_severity: Show severity column (default: True)

    Returns:
        Populated Table ready to print

    Examples:
        findings = [
            {"target": "DC01", "finding": "Weak password policy", "severity": "High"},
            {"target": "DC01", "finding": "SMB signing disabled", "severity": "Critical"},
            {"target": "SRV01", "finding": "Open share", "severity": "Medium"},
        ]
        table = create_findings_table(findings, title="Security Findings")
        print_table(table)
    """
    table = create_styled_table(title=title, show_lines=True)

    table.add_column("Target", style=ADSCAN_PRIMARY, no_wrap=True)
    table.add_column("Finding", style="white")

    if show_severity:
        table.add_column("Severity", justify="center", no_wrap=True)

    for finding in findings:
        severity = finding.get("severity", "Unknown")
        severity_color = {
            "Critical": "red",
            "High": "orange1",
            "Medium": "yellow",
            "Low": "blue",
            "Info": ADSCAN_PRIMARY,
        }.get(severity, "white")

        severity_icon = {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🔵",
            "Info": "⚪",
        }.get(severity, "⚪")

        if show_severity:
            table.add_row(
                finding.get("target", "N/A"),
                finding.get("finding", "N/A"),
                f"[{severity_color}]{severity_icon} {severity}[/{severity_color}]",
            )
        else:
            table.add_row(
                finding.get("target", "N/A"),
                finding.get("finding", "N/A"),
            )

    return table


def create_status_table(
    items: List[Dict[str, Any]],
    title: str = "Status",
    show_icons: bool = True,
) -> Table:
    """Create a status table with success/failure indicators.

    Useful for showing installation status, verification results, etc.

    Args:
        items: List of dictionaries with keys:
            - name: Item name
            - status: Status (success, failed, pending, etc.)
            - details: Optional details (default: None)
        title: Table title
        show_icons: Show status icons (default: True)

    Returns:
        Populated Table ready to print

    Examples:
        status = [
            {"name": "Docker", "status": "success", "details": "v24.0.7"},
            {"name": "Neo4j", "status": "success", "details": "v5.15.0"},
            {"name": "BloodHound", "status": "failed", "details": "Not installed"},
        ]
        table = create_status_table(status, title="Installation Status")
        print_table(table)
    """
    table = create_styled_table(title=title)

    table.add_column("Component", style=f"bold {ADSCAN_PRIMARY}")
    table.add_column("Status", justify="center", no_wrap=True)
    table.add_column("Details", style="dim")

    for item in items:
        name = item.get("name", "N/A")
        status = item.get("status", "unknown").lower()
        details = item.get("details", "")

        # Status styling
        if status == "success":
            status_text = (
                "[green]✓ Success[/green]" if show_icons else "[green]Success[/green]"
            )
        elif status == "failed":
            status_text = "[red]✗ Failed[/red]" if show_icons else "[red]Failed[/red]"
        elif status == "pending":
            status_text = (
                "[yellow]○ Pending[/yellow]"
                if show_icons
                else "[yellow]Pending[/yellow]"
            )
        elif status == "running":
            status_text = (
                "[cyan]◉ Running[/cyan]" if show_icons else "[cyan]Running[/cyan]"
            )
        else:
            status_text = "[dim]? Unknown[/dim]" if show_icons else "[dim]Unknown[/dim]"

        table.add_row(name, status_text, details)

    return table


# ==================================================================================
# SYNTAX HIGHLIGHTING
# ==================================================================================


def print_code(
    code: str,
    language: str = "python",
    theme: str = "monokai",
    line_numbers: bool = False,
    title: Optional[str] = None,
    background_color: Optional[str] = None,
) -> None:
    """Print code with syntax highlighting.

    Uses Rich's Syntax class to display code with professional syntax highlighting.
    Supports many languages including Python, Bash, JSON, YAML, JavaScript, etc.

    Args:
        code: Source code to display
        language: Programming language for syntax highlighting
            (python, bash, json, yaml, javascript, go, rust, etc.)
        theme: Color theme for syntax highlighting (monokai, dracula, etc.)
        line_numbers: Show line numbers (default: False)
        title: Optional title for the code block
        background_color: Optional background color (default: None for transparent)

    Examples:
        # Python code
        print_code('def hello():\\n    print("Hello")', language="python")

        # Bash command
        print_code('docker ps -a | grep bloodhound', language="bash", line_numbers=True)

        # JSON data
        print_code('{"status": "success", "count": 42}', language="json", title="API Response")

        # With line numbers and custom title
        print_code(
            'import requests\\nresponse = requests.get(url)',
            language="python",
            line_numbers=True,
            title="[bold]Example Code[/bold]"
        )
    """
    console = _get_console()
    telemetry_console = _get_telemetry_console()

    syntax = Syntax(
        code,
        language,
        theme=theme,
        line_numbers=line_numbers,
        background_color=background_color,
    )

    if title:
        renderable: RenderableType = Panel(
            syntax,
            title=title,
            border_style=ADSCAN_PRIMARY,
            padding=(1, 2),
        )
    else:
        renderable = syntax

    console.print(renderable)
    if telemetry_console is not None:
        telemetry_console.print(renderable)


def print_command(
    command: str,
    title: Optional[str] = None,
    show_copy_hint: bool = False,
) -> None:
    """Print a command with bash syntax highlighting.

    Specialized function for displaying shell commands with appropriate styling.
    Automatically uses bash syntax highlighting and brand colors.

    Args:
        command: Shell command to display
        title: Optional title (default: "Command")
        show_copy_hint: Show hint about copying the command (default: False)

    Examples:
        # Simple command
        print_command("adscan install")

        # Multi-line command
        print_command(
            "docker run -d \\\\\\n"
            "  --name neo4j \\\\\\n"
            "  -p 7474:7474 \\\\\\n"
            "  neo4j:latest",
            title="[bold]Docker Command[/bold]"
        )

        # With copy hint
        print_command(
            "git clone https://github.com/example/repo.git",
            title="Installation",
            show_copy_hint=True
        )
    """
    console = _get_console()
    telemetry_console = _get_telemetry_console()

    # Default title if none provided
    if title is None:
        title = f"[bold {ADSCAN_PRIMARY}]Command[/bold {ADSCAN_PRIMARY}]"

    # Create syntax highlighted command
    syntax = Syntax(
        command,
        "bash",
        theme="monokai",
        line_numbers=False,
        background_color=ADSCAN_SECONDARY_DARK,
    )

    # Optional copy hint
    if show_copy_hint:
        hint = Text("💡 Tip: Copy the command above", style="dim italic")
        content = Group(syntax, Text(""), hint)
    else:
        content = syntax

    # Display in panel with brand styling
    panel = Panel(
        content,
        title=title,
        border_style=ADSCAN_PRIMARY,
        padding=(1, 2),
    )

    console.print(panel)
    if telemetry_console is not None:
        telemetry_console.print(panel)


# ==================================================================================
# ERROR CONTEXT PANELS
# ==================================================================================


def print_error_context(
    error_message: str,
    context: Optional[Dict[str, Any]] = None,
    suggestions: Optional[List[str]] = None,
    title: str = "Error Details",
    show_exception: bool = False,
    exception: Optional[Exception] = None,
) -> None:
    """Print error with structured context panel.

    Displays errors in a professional, structured format with contextual information
    and optional suggestions for resolution. Respects SECRET_MODE for exception details.

    Args:
        error_message: Main error message
        context: Optional dictionary of context information (e.g., domain, user, path)
        suggestions: Optional list of suggestions to fix the error
        title: Panel title (default: "Error Details")
        show_exception: Show exception details if SECRET_MODE is enabled (default: False)
        exception: Exception object to display (only if show_exception=True and SECRET_MODE=True)

    Examples:
        # Simple error with context
        print_error_context(
            "Failed to connect to domain controller",
            context={"domain": "example.local", "pdc": "dc01.example.local"},
        )

        # Error with suggestions
        print_error_context(
            "Docker is not installed",
            suggestions=[
                "Install Docker: sudo apt-get install docker.io",
                "Verify installation: docker --version",
                "Start Docker service: sudo systemctl start docker",
            ],
        )

        # Error with full context and exception
        try:
            risky_operation()
        except Exception as e:
            print_error_context(
                "Operation failed",
                context={"operation": "domain_scan", "target": "10.0.0.1"},
                suggestions=["Check network connectivity", "Verify credentials"],
                show_exception=True,
                exception=e,
            )
    """
    console = _get_console()

    # Build content parts
    content_parts = []

    # Main error message
    error_text = Text()
    error_text.append("✗ ", style="bold red")
    error_text.append(error_message, style="bold red")
    content_parts.append(error_text)

    # Context information
    if context:
        content_parts.append(Text(""))  # Blank line
        context_header = Text("Context:", style=f"bold {ADSCAN_PRIMARY}")
        content_parts.append(context_header)

        # Mark sensitive context data using intelligent detection
        marked_context = _mark_operation_details(context)

        for key, value in marked_context.items():
            context_line = Text()
            context_line.append(f"  • {key}: ", style="dim")
            context_line.append(str(value), style="white")
            content_parts.append(context_line)

    # Suggestions
    if suggestions:
        content_parts.append(Text(""))  # Blank line
        suggestions_header = Text("Suggestions:", style="bold yellow")
        content_parts.append(suggestions_header)

        for i, suggestion in enumerate(suggestions, 1):
            suggestion_line = Text()
            suggestion_line.append(f"  {i}. ", style="yellow")
            suggestion_line.append(suggestion, style="white")
            content_parts.append(suggestion_line)

    # Exception details (only if SECRET_MODE is enabled)
    if show_exception and exception:
        # Get SECRET_MODE from globals
        secret_mode = _get_secret_mode()

        if secret_mode:
            content_parts.append(Text(""))  # Blank line
            exception_header = Text("Exception Details:", style="bold red")
            content_parts.append(exception_header)

            exception_text = Text()
            exception_text.append(f"  {type(exception).__name__}: ", style="bold red")
            exception_text.append(str(exception), style="red")
            content_parts.append(exception_text)
        else:
            # Log that exception was hidden
            logger = logging.getLogger(__name__)
            logger.debug(
                "Exception details hidden (SECRET_MODE=False)",
                extra={"exception_type": type(exception).__name__},
            )

    # Create panel with all content
    content = Group(*content_parts)

    panel = Panel(
        content,
        title=f"[bold red]{title}[/bold red]",
        border_style="red",
        padding=(1, 2),
    )

    console.print(panel)
    telemetry_console = _get_telemetry_console()
    if telemetry_console is not None:
        telemetry_console.print(panel)


def _get_secret_mode() -> bool:
    """Get SECRET_MODE from globals safely.

    Returns:
        True if SECRET_MODE is enabled, False otherwise
    """
    try:
        import builtins

        return getattr(builtins, "SECRET_MODE", False)
    except Exception:
        return False


def print_operation_header(
    operation: str,
    details: Optional[Dict[str, str]] = None,
    icon: str = "🔍",
) -> None:
    """Print a professional header for operations (scans, enumeration, etc.).

    Args:
        operation: Operation name (e.g., "SMB Scan", "Trust Enumeration")
        details: Optional dict of key-value details to display
        icon: Icon to display (default: 🔍)

    Example:
        >>> print_operation_header("SMB Scan", {"Target": "10.0.0.0/24", "Mode": "Unauthenticated"})
    """
    console = _get_console()
    telemetry_console = _get_telemetry_console()

    # Build header content
    from rich.text import Text
    from rich.panel import Panel
    from rich.table import Table

    header_text = Text()
    header_text.append(f"{icon} ", style="bold")
    header_text.append(operation, style=f"bold {ADSCAN_PRIMARY}")

    if details:
        # Automatically mark sensitive values based on key patterns
        marked_details = _mark_operation_details(details)

        # Create a mini table for details
        details_table = Table.grid(padding=(0, 2))
        details_table.add_column(style="dim", justify="right")
        details_table.add_column(style="white")

        for key, value in marked_details.items():
            details_table.add_row(f"{key}:", value)

        content = Group(header_text, Text(""), details_table)
    else:
        content = header_text

    panel = Panel(
        content,
        border_style=ADSCAN_PRIMARY,
        padding=(1, 2),
    )

    spacing_before = _handle_spacing("info", True, "auto")
    if spacing_before:
        console.print()
        if telemetry_console is not None:
            telemetry_console.print()

    console.print(panel)
    if telemetry_console is not None:
        telemetry_console.print(panel)


def print_scan_status(
    service: str,
    status: str,
    details: Optional[str] = None,
) -> None:
    """Print scan status with professional styling.

    Args:
        service: Service name (e.g., "SMB", "LDAP")
        status: Status (e.g., "starting", "running", "completed", "failed")
        details: Optional additional details

    Example:
        >>> print_scan_status("SMB", "completed", "15 hosts discovered")
    """
    console = _get_console()
    telemetry_console = _get_telemetry_console()
    from rich.text import Text

    # Status styling
    status_styles = {
        "starting": ("⚡", "bold yellow"),
        "running": ("⏳", "bold cyan"),
        "completed": ("✓", "bold green"),
        "failed": ("✗", "bold red"),
        "pending": ("○", "dim"),
    }

    icon, style = status_styles.get(status.lower(), ("•", "white"))

    text = Text()
    text.append(f"{icon} ", style=style)
    text.append(f"{service} ", style=f"bold {ADSCAN_PRIMARY}")
    text.append(status.title(), style=style)

    if details:
        text.append(" - ", style="dim")
        text.append(details, style="white")

    spacing_before = _handle_spacing("info", False, "auto")
    if spacing_before:
        console.print()
        if telemetry_console is not None:
            telemetry_console.print()

    console.print(text)
    if telemetry_console is not None:
        telemetry_console.print(text)


def print_results_summary(
    title: str,
    results: Dict[str, Any],
    show_panel: bool = True,
) -> None:
    """Print a professional summary of operation results.

    Args:
        title: Summary title
        results: Dictionary of result key-value pairs
        show_panel: Whether to wrap in a panel (default: True)

    Example:
        >>> print_results_summary(
        ...     "Scan Results",
        ...     {"Domains Found": 3, "Hosts Discovered": 15, "Credentials": 5}
        ... )
    """
    console = _get_console()
    telemetry_console = _get_telemetry_console()
    from rich.text import Text
    from rich.panel import Panel
    from rich.table import Table

    # Create results table
    results_table = Table.grid(padding=(0, 2))
    results_table.add_column(style=f"bold {ADSCAN_PRIMARY}", justify="right")
    results_table.add_column(style="white", justify="left")

    for key, value in results.items():
        # Style based on value
        if isinstance(value, (int, float)):
            if value > 0:
                value_style = "bold green"
            else:
                value_style = "dim"
            value_str = str(value)
        elif isinstance(value, bool):
            value_style = "bold green" if value else "bold red"
            value_str = "Yes" if value else "No"
        else:
            value_style = "white"
            value_str = str(value)

        results_table.add_row(f"{key}:", Text(value_str, style=value_style))

    if show_panel:
        panel = Panel(
            results_table,
            title=f"[bold]{title}[/bold]",
            border_style=ADSCAN_PRIMARY,
            padding=(1, 2),
        )
        spacing_before = _handle_spacing("success", True, "auto")
        if spacing_before:
            console.print()
            if telemetry_console is not None:
                telemetry_console.print()

        console.print(panel)
        if telemetry_console is not None:
            telemetry_console.print(panel)
    else:
        spacing_before = _handle_spacing("info", False, "auto")
        if spacing_before:
            console.print()
            if telemetry_console is not None:
                telemetry_console.print()

        console.print(results_table)
        if telemetry_console is not None:
            telemetry_console.print(results_table)


def print_domain_info(
    domain: str,
    pdc: Optional[str] = None,
    credentials: Optional[Dict[str, str]] = None,
    additional_info: Optional[Dict[str, Any]] = None,
) -> None:
    """Print professional domain information panel.

    Args:
        domain: Domain name
        pdc: Primary domain controller (optional)
        credentials: Dictionary with username/password or hash (optional)
        additional_info: Additional key-value information (optional)

    Example:
        >>> print_domain_info(
        ...     "example.local",
        ...     pdc="dc01.example.local",
        ...     credentials={"username": "admin", "type": "password"}
        ... )
    """
    console = _get_console()
    telemetry_console = _get_telemetry_console()
    from rich.text import Text
    from rich.panel import Panel
    from rich.table import Table

    # Create info table
    info_table = Table.grid(padding=(0, 2))
    info_table.add_column(style="dim", justify="right")
    info_table.add_column(style="white")

    # Domain - mark as sensitive
    info_table.add_row(
        "Domain:",
        Text(mark_sensitive(domain, "domain"), style=f"bold {ADSCAN_PRIMARY}"),
    )

    # PDC - mark as sensitive (could be IP or hostname)
    if pdc:
        # Check if PDC is IP or hostname
        import re

        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        if re.search(ip_pattern, pdc):
            marked_pdc = mark_sensitive(pdc, "ip")
        elif "." in pdc:
            # FQDN
            marked_pdc = mark_sensitive(pdc, "domain")
        else:
            # Hostname
            marked_pdc = mark_sensitive(pdc, "hostname")
        info_table.add_row("PDC:", marked_pdc)

    # Credentials
    if credentials:
        if "username" in credentials:
            marked_username = mark_sensitive(credentials["username"], "user")
            info_table.add_row("Username:", marked_username)
        if "type" in credentials:
            cred_type = credentials["type"]
            icon = "🔐" if cred_type == "password" else "🔑"
            info_table.add_row("Auth Type:", f"{icon} {cred_type.title()}")

    # Additional info - mark using intelligent detection
    if additional_info:
        marked_info = _mark_operation_details(additional_info)
        for key, value in marked_info.items():
            info_table.add_row(f"{key}:", str(value))

    panel = Panel(
        info_table,
        title="[bold]🎯 New Domain Discovered[/bold]",
        border_style=ADSCAN_PRIMARY,
        padding=(1, 2),
    )

    spacing_before = _handle_spacing("info", True, "auto")
    if spacing_before:
        console.print()
        if telemetry_console is not None:
            telemetry_console.print()

    console.print(panel)
    if telemetry_console is not None:
        telemetry_console.print(panel)


def create_domains_table(
    domains_data: Dict[str, Dict[str, Any]],
    title: str = "Discovered Domains",
) -> Table:
    """Create a professional table displaying domains and their information.

    Args:
        domains_data: Dictionary mapping domain names to their data
        title: Table title

    Returns:
        Rich Table object

    Example:
        >>> domains_data = {
        ...     "example.local": {"pdc": "10.0.0.1", "auth": "password"},
        ...     "test.local": {"pdc": "10.0.0.2", "auth": "hash"}
        ... }
        >>> table = create_domains_table(domains_data)
        >>> console.print(table)
    """
    table = create_styled_table(title=title)
    table.add_column("Domain", style=f"bold {ADSCAN_PRIMARY}", no_wrap=True)
    table.add_column("PDC", style="cyan")
    table.add_column("Auth", justify="center")
    table.add_column("Users", justify="center")

    for domain, data in domains_data.items():
        pdc = data.get("pdc", "N/A")
        auth = data.get("auth", "N/A")

        # Mark sensitive data
        marked_domain = mark_sensitive(domain, "domain")

        # Mark PDC (could be IP or hostname)
        if pdc != "N/A":
            import re

            ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
            if re.search(ip_pattern, pdc):
                marked_pdc = mark_sensitive(pdc, "ip")
            elif "." in pdc:
                # FQDN
                marked_pdc = mark_sensitive(pdc, "domain")
            else:
                # Hostname
                marked_pdc = mark_sensitive(pdc, "hostname")
        else:
            marked_pdc = pdc

        # Determine auth icon and color
        if auth == "password":
            auth_display = "[green]🔐 Password[/green]"
        elif auth == "hash":
            auth_display = "[yellow]🔑 Hash[/yellow]"
        elif auth == "auth":
            auth_display = "[green]✓ Authenticated[/green]"
        else:
            auth_display = "[dim]○ Unauthenticated[/dim]"

        # Count credentials
        credentials = data.get("credentials", {})
        user_count = len(credentials) if credentials else 0
        user_display = str(user_count) if user_count > 0 else "[dim]0[/dim]"

        table.add_row(marked_domain, marked_pdc, auth_display, user_display)

    return table


def create_credentials_table(
    credentials: Dict[str, str],
    title: str = "Compromised Credentials",
    show_preview: bool = True,
) -> Table:
    """Create a professional table displaying credentials.

    Args:
        credentials: Dictionary mapping usernames to passwords/hashes
        title: Table title
        show_preview: Whether to show credential preview (default: True)

    Returns:
        Rich Table object

    Example:
        >>> creds = {"admin": "Password123!", "user": "aad3b435b51404eeaad3b435b51404ee"}
        >>> table = create_credentials_table(creds)
        >>> console.print(table)
    """
    table = create_styled_table(title=title)
    table.add_column("Username", style=f"bold {ADSCAN_PRIMARY}")
    table.add_column("Type", justify="center")
    table.add_column("Preview", style="dim" if show_preview else "")

    for username, credential in credentials.items():
        # Mark username as sensitive
        marked_username = mark_sensitive(username, "user")

        # Determine if hash or password
        is_hash = len(credential) == 32 and all(
            c in "0123456789abcdefABCDEF" for c in credential
        )

        if is_hash:
            cred_type = "[yellow]🔑 Hash[/yellow]"
            if show_preview:
                # Mark the preview parts separately and reconstruct
                preview_start = mark_sensitive(credential[:8], "password")
                preview_end = mark_sensitive(credential[-4:], "password")
                preview = f"{preview_start}...{preview_end}"
            else:
                preview = "••••••••"
        else:
            cred_type = "[green]🔐 Password[/green]"
            if show_preview:
                # Mark the visible part
                visible_part = credential[:3]
                marked_visible = mark_sensitive(visible_part, "password")
                preview = f"{marked_visible}{'*' * min(len(credential) - 3, 8)}"
            else:
                preview = "••••••••"

        table.add_row(marked_username, cred_type, preview)

    return table


# ==================================================================================
# SCAN PROGRESS AND WORKFLOW UX/UI FUNCTIONS
# ==================================================================================


def print_phase_header(
    phase_name: str,
    phase_number: Optional[int] = None,
    total_phases: Optional[int] = None,
    details: Optional[Dict[str, str]] = None,
    icon: str = "📍",
) -> None:
    """Print a professional phase header to group related scan operations.

    This function creates a visual separator between different phases of a scan workflow,
    helping users understand the overall progress and structure of the operation.

    Args:
        phase_name: Name of the phase (e.g., "Initial Reconnaissance", "Credential Attacks")
        phase_number: Current phase number (e.g., 1 for Phase 1/3)
        total_phases: Total number of phases in the workflow
        details: Optional dict of key-value details to display
        icon: Icon to display (default: 📍)

    Examples:
        # Simple phase header
        print_phase_header("Initial Reconnaissance")

        # With progress tracking
        print_phase_header("Credential Attacks", phase_number=2, total_phases=3)

        # With additional details
        print_phase_header(
            "Domain Enumeration",
            phase_number=1,
            total_phases=2,
            details={"Target": "example.local", "Mode": "Authenticated"}
        )
    """
    console = _get_console()
    telemetry_console = _get_telemetry_console()

    # Build header text with phase progress
    header_text = Text()
    header_text.append(f"{icon} ", style="bold")

    if phase_number is not None and total_phases is not None:
        phase_info = f"Phase {phase_number}/{total_phases}: "
        header_text.append(phase_info, style=f"bold {ADSCAN_PRIMARY}")

    header_text.append(phase_name, style=f"bold {ADSCAN_PRIMARY}")

    # Create content for panel
    if details:
        from rich.table import Table

        details_table = Table.grid(padding=(0, 2))
        details_table.add_column(style="dim", justify="right")
        details_table.add_column(style="white")

        for key, value in details.items():
            details_table.add_row(f"{key}:", value)

        content = Group(header_text, Text(""), details_table)
    else:
        content = header_text

    # Create panel
    panel = Panel(
        content,
        border_style=ADSCAN_PRIMARY,
        padding=(1, 2),
        box=ROUNDED,
    )

    # Handle spacing
    spacing_before = _handle_spacing("info", True, "auto")
    if spacing_before:
        console.print()
        if telemetry_console is not None:
            telemetry_console.print()

    console.print(panel)
    if telemetry_console is not None:
        telemetry_console.print(panel)


def print_step_status(
    step_name: str,
    status: str = "running",
    step_number: Optional[int] = None,
    total_steps: Optional[int] = None,
    details: Optional[str] = None,
) -> None:
    """Print a single step status in a scan workflow with professional styling.

    This function provides real-time feedback on individual steps within a phase,
    showing progress and current status to keep users informed.

    Args:
        step_name: Name of the step (e.g., "SMB Scan", "LDAP Enumeration")
        status: Step status - one of:
            - "starting": Step is about to start (⚡ yellow)
            - "running": Step is currently executing (⏳ cyan)
            - "completed": Step finished successfully (✓ green)
            - "failed": Step failed (✗ red)
            - "skipped": Step was skipped (○ dim)
            - "pending": Step is waiting (○ dim)
        step_number: Current step number (e.g., 1 for Step 1/5)
        total_steps: Total number of steps in this phase
        details: Optional additional details about the step

    Examples:
        # Simple step status
        print_step_status("SMB Scan", status="running")

        # With progress tracking
        print_step_status("LDAP Enumeration", status="completed", step_number=2, total_steps=5)

        # With additional details
        print_step_status(
            "Credential Validation",
            status="running",
            step_number=3,
            total_steps=5,
            details="Testing 15 credentials"
        )
    """
    console = _get_console()
    telemetry_console = _get_telemetry_console()

    # Status styling
    status_styles = {
        "starting": ("⚡", "bold yellow"),
        "running": ("⏳", "bold cyan"),
        "completed": ("✓ ", "bold green"),
        "failed": ("✗", "bold red"),
        "skipped": ("○", "dim"),
        "pending": ("○", "dim"),
    }

    icon, style = status_styles.get(status.lower(), ("•", "white"))

    # Build step text
    text = Text()
    text.append(f"{icon} ", style=style)

    # Add step progress if provided
    if step_number is not None and total_steps is not None:
        progress_text = f"[{step_number}/{total_steps}] "
        text.append(progress_text, style="dim")

    # Add step name
    text.append(f"{step_name} ", style=f"bold {ADSCAN_PRIMARY}")

    # Add status text
    status_text = status.title()
    text.append(status_text, style=style)

    # Add details if provided
    if details:
        text.append(" - ", style="dim")
        text.append(details, style="white")

    console.print(text)
    if telemetry_console is not None:
        telemetry_console.print(text)


def print_workflow_summary(
    workflow_name: str,
    results: Dict[str, Any],
    show_panel: bool = True,
    icon: str = "📊",
) -> None:
    """Print a professional summary of a completed workflow with statistics.

    This function displays a comprehensive summary at the end of a scan workflow,
    showing what was executed, results obtained, and overall status.

    Args:
        workflow_name: Name of the workflow (e.g., "Unauthenticated Scan")
        results: Dictionary of workflow results with keys like:
            - "status": Overall status (Success, Partial, Failed)
            - "steps_completed": Number of steps completed
            - "steps_total": Total number of steps
            - "duration": Duration in seconds (optional)
            - Any other key-value pairs for statistics
        show_panel: Whether to wrap in a panel (default: True)
        icon: Icon to display (default: 📊)

    Examples:
        print_workflow_summary(
            "Unauthenticated Scan",
            {
                "status": "Success",
                "steps_completed": 5,
                "steps_total": 5,
                "duration": 120.5,
                "hosts_found": 15,
                "shares_discovered": 8,
                "users_enumerated": 150,
            }
        )
    """
    console = _get_console()
    telemetry_console = _get_telemetry_console()

    # Build header
    header_text = Text()
    header_text.append(f"{icon} ", style="bold")
    header_text.append(workflow_name, style=f"bold {ADSCAN_PRIMARY}")
    header_text.append(" - Summary", style="bold white")

    # Determine overall status styling
    status = results.get("status", "Unknown")
    if status.lower() in ["success", "completed"]:
        status_color = "green"
        status_icon = "✓"
    elif status.lower() in ["partial", "warning"]:
        status_color = "yellow"
        status_icon = "⚠"
    elif status.lower() in ["failed", "error"]:
        status_color = "red"
        status_icon = "✗"
    else:
        status_color = "white"
        status_icon = "○"

    # Create results table
    results_table = Table.grid(padding=(0, 2))
    results_table.add_column(style=f"bold {ADSCAN_PRIMARY}", justify="right")
    results_table.add_column(style="white", justify="left")

    # Add overall status first
    status_text = Text()
    status_text.append(f"{status_icon} ", style=f"bold {status_color}")
    status_text.append(status, style=f"bold {status_color}")
    results_table.add_row("Status:", status_text)

    # Add step completion if provided
    steps_completed = results.get("steps_completed")
    steps_total = results.get("steps_total")
    if steps_completed is not None and steps_total is not None:
        completion_pct = (steps_completed / steps_total * 100) if steps_total > 0 else 0
        completion_text = Text()
        completion_text.append(f"{steps_completed}/{steps_total}", style="white")
        completion_text.append(f" ({completion_pct:.0f}%)", style="dim")
        results_table.add_row("Steps Completed:", completion_text)

    # Add duration if provided
    duration = results.get("duration")
    if duration is not None:
        if duration < 60:
            duration_str = f"{duration:.1f} seconds"
        elif duration < 3600:
            duration_str = f"{duration / 60:.1f} minutes"
        else:
            duration_str = f"{duration / 3600:.1f} hours"
        results_table.add_row("Duration:", duration_str)

    # Add all other results (excluding metadata keys)
    metadata_keys = {"status", "steps_completed", "steps_total", "duration"}
    for key, value in results.items():
        if key not in metadata_keys:
            # Format key (capitalize first letter, replace underscores)
            formatted_key = key.replace("_", " ").title()

            # Style value based on type and content
            if isinstance(value, bool):
                value_style = "bold green" if value else "bold red"
                value_str = "Yes" if value else "No"
            elif isinstance(value, (int, float)):
                if value > 0:
                    value_style = "bold green"
                else:
                    value_style = "dim"
                value_str = str(value)
            else:
                value_style = "white"
                value_str = str(value)

            results_table.add_row(
                f"{formatted_key}:", Text(value_str, style=value_style)
            )

    # Create content
    content = Group(header_text, Text(""), results_table)

    if show_panel:
        # Determine panel border color based on status
        border_color = status_color if status_color != "white" else ADSCAN_PRIMARY

        panel = Panel(
            content,
            border_style=border_color,
            padding=(1, 2),
            box=ROUNDED,
        )

        spacing_before = _handle_spacing("success", True, "auto")
        if spacing_before:
            console.print()
            if telemetry_console is not None:
                telemetry_console.print()

        console.print(panel)
        if telemetry_console is not None:
            telemetry_console.print(panel)
    else:
        spacing_before = _handle_spacing("info", False, "auto")
        if spacing_before:
            console.print()
            if telemetry_console is not None:
                telemetry_console.print()

        console.print(content)
        if telemetry_console is not None:
            telemetry_console.print(content)


class ScanProgressTracker:
    """Helper class to track and display scan progress in real-time.

    This class provides a clean API for managing multi-step scan workflows,
    automatically handling progress display, status updates, and final summaries.

    Example:
        tracker = ScanProgressTracker("Unauthenticated Scan", total_steps=3)

        tracker.start_step("SMB Scan")
        perform_smb_scan()
        tracker.complete_step()

        tracker.start_step("LDAP Enumeration")
        perform_ldap_enum()
        tracker.complete_step()

        tracker.start_step("Kerberos User Enum")
        perform_kerberos_enum()
        tracker.complete_step()

        tracker.print_summary({"hosts_found": 15, "users_enumerated": 150})
    """

    def __init__(
        self,
        workflow_name: str,
        total_steps: int,
        phase_number: Optional[int] = None,
        total_phases: Optional[int] = None,
    ):
        """Initialize scan progress tracker.

        Args:
            workflow_name: Name of the workflow/scan
            total_steps: Total number of steps in this workflow
            phase_number: Current phase number (optional)
            total_phases: Total number of phases (optional)
        """
        self.workflow_name = workflow_name
        self.total_steps = total_steps
        self.phase_number = phase_number
        self.total_phases = total_phases

        self.current_step = 0
        self.completed_steps = 0
        self.failed_steps = 0
        self.skipped_steps = 0

        self.current_step_name: Optional[str] = None
        self.start_time = None
        self.step_start_time = None

    def start(self, details: Optional[Dict[str, str]] = None) -> None:
        """Start the workflow and display phase header.

        Args:
            details: Optional details to display in phase header
        """
        import time

        # Use monotonic clock so workflow durations are robust to system
        # clock adjustments during long-running operations.
        self.start_time = time.monotonic()

        print_phase_header(
            self.workflow_name,
            phase_number=self.phase_number,
            total_phases=self.total_phases,
            details=details,
        )

    def start_step(self, step_name: str, details: Optional[str] = None) -> None:
        """Start a new step in the workflow.

        Args:
            step_name: Name of the step
            details: Optional details about the step
        """
        import time

        self.current_step += 1
        self.current_step_name = step_name
        # Use monotonic clock to keep step timing stable even if system
        # clock changes between steps.
        self.step_start_time = time.monotonic()

        print_step_status(
            step_name,
            status="running",
            step_number=self.current_step,
            total_steps=self.total_steps,
            details=details,
        )

    def complete_step(self, details: Optional[str] = None) -> None:
        """Mark current step as completed.

        Args:
            details: Optional completion details
        """
        if self.current_step_name:
            self.completed_steps += 1
            print_step_status(
                self.current_step_name,
                status="completed",
                step_number=self.current_step,
                total_steps=self.total_steps,
                details=details,
            )
            self.current_step_name = None

    def fail_step(self, details: Optional[str] = None) -> None:
        """Mark current step as failed.

        Args:
            details: Optional failure details
        """
        if self.current_step_name:
            self.failed_steps += 1
            print_step_status(
                self.current_step_name,
                status="failed",
                step_number=self.current_step,
                total_steps=self.total_steps,
                details=details,
            )
            self.current_step_name = None

    def skip_step(self, step_name: str, details: Optional[str] = None) -> None:
        """Skip a step in the workflow.

        Args:
            step_name: Name of the step to skip
            details: Optional reason for skipping
        """
        self.current_step += 1
        self.skipped_steps += 1
        print_step_status(
            step_name,
            status="skipped",
            step_number=self.current_step,
            total_steps=self.total_steps,
            details=details,
        )

    def print_summary(
        self, additional_results: Optional[Dict[str, Any]] = None
    ) -> None:
        """Print final workflow summary.

        Args:
            additional_results: Optional additional results to include in summary
        """
        import time

        duration = (
            time.monotonic() - self.start_time if self.start_time is not None else 0
        )

        # Determine overall status
        if self.failed_steps > 0:
            status = "Partial" if self.completed_steps > 0 else "Failed"
        elif self.completed_steps == self.total_steps:
            status = "Success"
        else:
            status = "Partial"

        # Build results dict
        results = {
            "status": status,
            "steps_completed": self.completed_steps,
            "steps_total": self.total_steps,
            "duration": duration,
        }

        # Add step breakdown if there were failures or skips
        if self.failed_steps > 0:
            results["steps_failed"] = self.failed_steps
        if self.skipped_steps > 0:
            results["steps_skipped"] = self.skipped_steps

        # Merge additional results
        if additional_results:
            results.update(additional_results)

        print_workflow_summary(self.workflow_name, results)


def print_delegations_summary(
    domain: str,
    delegations_data: List[Dict[str, str]],
    show_empty: bool = True,
) -> None:
    """Display a professional summary of Kerberos delegations grouped by type.

    Args:
        domain: Domain name
        delegations_data: List of delegation dictionaries with keys:
            - account: Account name
            - account_type: Account type (User/Computer)
            - delegation_type: Type of delegation
            - delegation_to: Target of delegation (if applicable)
        show_empty: Whether to show a message when no delegations found

    Example:
        >>> delegations = [
        ...     {
        ...         "account": "WIN-DC$",
        ...         "account_type": "Computer",
        ...         "delegation_type": "Unconstrained",
        ...         "delegation_to": "N/A"
        ...     }
        ... ]
        >>> print_delegations_summary("example.local", delegations)
    """
    from rich.table import Table
    from rich.text import Text

    if not delegations_data:
        if show_empty:
            print_success(f"No Kerberos delegations found in domain {domain}")
        return

    # Group delegations by type
    delegation_groups = {
        "unconstrained": [],
        "constrained": [],
        "constrained_protocol_transition": [],
        "resource_based_constrained": [],
        "unknown": [],
    }

    for delegation in delegations_data:
        delegation_type_lower = delegation.get("delegation_type", "").lower()
        if (
            "unconstrained" in delegation_type_lower
            and "resource-based" not in delegation_type_lower
        ):
            delegation_groups["unconstrained"].append(delegation)
        elif (
            "resource-based" in delegation_type_lower
            or "resource based" in delegation_type_lower
        ):
            delegation_groups["resource_based_constrained"].append(delegation)
        elif (
            "protocol transition" in delegation_type_lower
            and "w/o" not in delegation_type_lower
        ):
            delegation_groups["constrained_protocol_transition"].append(delegation)
        elif "constrained" in delegation_type_lower:
            delegation_groups["constrained"].append(delegation)
        else:
            delegation_groups["unknown"].append(delegation)

    # Count total and by type
    total = len(delegations_data)

    # Create summary header
    summary_text = Text()
    summary_text.append("Kerberos Delegations Found: ", style="bold white")
    summary_text.append(str(total), style=f"bold {BRAND_COLORS['success']}")

    _console.print()
    _console.print(
        Panel(
            summary_text,
            title=f"🔗 Domain: {domain}",
            border_style=BRAND_COLORS["info"],
            padding=(0, 2),
        )
    )

    # Display each delegation type with its own table
    delegation_type_info = {
        "unconstrained": {
            "title": "⚠️  Unconstrained Delegation",
            "description": "High risk - Account can impersonate any user to any service",
            "color": "red",
        },
        "constrained": {
            "title": "🔒 Constrained Delegation",
            "description": "Limited risk - Account can impersonate users to specific services",
            "color": "yellow",
        },
        "constrained_protocol_transition": {
            "title": "🔐 Constrained with Protocol Transition",
            "description": "Moderate risk - Can switch protocols during delegation",
            "color": "yellow",
        },
        "resource_based_constrained": {
            "title": "🎯 Resource-Based Constrained Delegation (RBCD)",
            "description": "Service-controlled - Configured on target resource",
            "color": "cyan",
        },
        "unknown": {
            "title": "❓ Unknown Delegation Type",
            "description": "Could not classify delegation type",
            "color": "dim white",
        },
    }

    for delegation_type, delegations in delegation_groups.items():
        if not delegations:
            continue

        info = delegation_type_info[delegation_type]

        # Create table for this delegation type
        table = Table(
            title=f"{info['title']} ({len(delegations)})",
            title_style=f"bold {info['color']}",
            border_style=info["color"],
            show_header=True,
            header_style=f"bold {info['color']}",
            padding=(0, 1),
        )

        table.add_column("Account", style="cyan", no_wrap=False)
        table.add_column("Type", style="white", justify="center")
        table.add_column("Delegation To", style="yellow", no_wrap=False)

        for delegation in delegations:
            account = delegation.get("account", "N/A")
            account_type = delegation.get("account_type", "N/A")
            delegation_to = delegation.get("delegation_to", "N/A")

            # Add icon based on account type
            if account_type.lower() == "computer":
                account_icon = "💻 "
            elif account_type.lower() == "user":
                account_icon = "👤 "
            else:
                account_icon = "📋 "

            # Mark sensitive data
            marked_account = (
                mark_sensitive(account, "user") if account != "N/A" else account
            )

            if delegation_to != "N/A" and delegation_to.lower() not in [
                "any service",
                "any",
                "-",
            ]:
                marked_delegation_to = mark_sensitive(delegation_to, "service")
            else:
                marked_delegation_to = (
                    delegation_to
                    if delegation_to != "N/A"
                    else "[dim]Any service[/dim]"
                )

            table.add_row(
                f"{account_icon}{marked_account}", account_type, marked_delegation_to
            )

        _console.print()
        _console.print(table)
        _console.print(f"[dim]{info['description']}[/dim]")

    _console.print()


def print_attack_paths_summary(
    domain: str,
    paths: List[Dict[str, object]],
    max_display: int = 5,
    *,
    max_path_steps: int | None = None,
) -> None:
    """Render attack paths in a clear, compact summary."""
    from rich.table import Table
    from rich.text import Text

    if not paths:
        return

    total = len(paths)
    show_count = min(max_display, total)

    summary_text = Text()
    summary_text.append("Attack Paths Found: ", style="bold white")
    summary_text.append(str(total), style=f"bold {BRAND_COLORS['warning']}")
    summary_text.append("  ")
    summary_text.append("Showing: ", style="bold white")
    summary_text.append(str(show_count), style=f"bold {BRAND_COLORS['info']}")

    print_panel(
        summary_text,
        title=f"🧭 Domain: {domain}",
        border_style=BRAND_COLORS["info"],
        padding=(0, 2),
        expand=True,
        spacing="both",
    )

    def _mark_path_node(name: str) -> str:
        if not name:
            return "N/A"
        if "." in name or name.endswith("$"):
            return mark_sensitive(name, "hostname")
        return mark_sensitive(name, "user")

    table = Table(
        title=f"Attack Paths ({show_count})",
        title_style=f"bold {BRAND_COLORS['success']}",
        border_style=BRAND_COLORS["success"],
        show_header=True,
        header_style=f"bold {BRAND_COLORS['success']}",
        padding=(0, 1),
    )
    table.add_column("#", justify="right", width=3)
    table.add_column("Path", style="cyan", no_wrap=False)
    table.add_column("Affected", style="white", no_wrap=False, width=10)
    table.add_column("Status", style="magenta", no_wrap=False, width=10)
    table.add_column("Len", justify="right", width=4)
    format_node_label, format_relation_label = _get_attack_path_narrative_formatters()

    def _format_inline_chain(nodes: list[object], rels: list[object]) -> Text:
        if not nodes:
            return Text("N/A")
        chain = Text()
        truncated = False
        rels_to_render = rels
        nodes_to_render = nodes
        if (
            isinstance(max_path_steps, int)
            and max_path_steps > 0
            and len(rels) > max_path_steps
        ):
            truncated = True
            rels_to_render = rels[:max_path_steps]
            nodes_to_render = nodes[: max_path_steps + 1]

        chain.append(
            _mark_path_node(format_node_label(str(nodes_to_render[0]), domain))
        )
        for idx, rel in enumerate(rels_to_render):
            if idx + 1 >= len(nodes_to_render):
                break
            rel_label = format_relation_label(str(rel))
            chain.append(" → ", style="dim")
            chain.append(rel_label, style=BRAND_COLORS["warning"])
            chain.append(" → ", style="dim")
            chain.append(
                _mark_path_node(
                    format_node_label(str(nodes_to_render[idx + 1]), domain)
                )
            )
        if not truncated and len(nodes) > len(rels) + 1:
            for node in nodes[len(rels) + 1 :]:
                chain.append(" → ", style="dim")
                chain.append(_mark_path_node(format_node_label(str(node), domain)))
        if truncated:
            remaining = max(0, len(rels) - len(rels_to_render))
            chain.append(" → ", style="dim")
            chain.append(f"...(+{remaining} more)", style="dim")
        return chain

    for idx, path in enumerate(paths[:show_count], start=1):
        nodes = path.get("nodes", [])
        rels = path.get("relations", [])
        if not isinstance(nodes, list):
            nodes = []
        if not isinstance(rels, list):
            rels = []

        path_str = _format_inline_chain(nodes, rels)
        length = path.get("length", len(rels))
        status = str(path.get("status") or "theoretical")

        affected_cell = ""
        meta = path.get("meta") if isinstance(path, dict) else None
        if isinstance(meta, dict):
            affected_count = meta.get("affected_user_count")
            if isinstance(affected_count, int):
                affected_cell = str(affected_count)

        row = [str(idx), path_str, affected_cell, status, str(length)]
        table.add_row(*row)

    print_table(table, spacing="both")


_ATTACK_PATH_NARRATIVE_FALLBACK_LOGGED = False


def _fallback_format_attack_path_node_label(label: str, domain: str) -> str:
    """Best-effort node label formatter when reporting narratives are unavailable."""
    value = str(label or "").strip()
    if not value:
        return "N/A"

    if "\\" in value:
        value = value.split("\\", 1)[1].strip()

    if "@" in value:
        left, _, right = value.partition("@")
        if right and right.strip().lower() == str(domain or "").strip().lower():
            return left.strip() or value

    return value


def _fallback_format_attack_path_relation_label(relation: str) -> str:
    """Best-effort relation formatter when reporting narratives are unavailable."""
    import re

    value = str(relation or "").strip()
    if not value:
        return "N/A"
    value = value.replace("_", " ")
    value = re.sub(r"([a-z])([A-Z])", r"\1 \2", value)
    return value


def _get_attack_path_narrative_formatters(
) -> tuple[Callable[[str, str], str], Callable[[str], str]]:
    """Resolve attack-path label formatters with a LITE-safe fallback."""
    global _ATTACK_PATH_NARRATIVE_FALLBACK_LOGGED
    try:
        import importlib

        module = importlib.import_module(
            "adscan_internal.reporting.attack_path_narratives"
        )
        format_node_label = getattr(module, "format_node_label", None)
        format_relation_label = getattr(module, "format_relation_label", None)
        if callable(format_node_label) and callable(format_relation_label):
            return format_node_label, format_relation_label
        raise AttributeError(
            "attack_path_narratives module missing required formatter callables"
        )
    except Exception as exc:  # pragma: no cover - depends on runtime packaging
        if not _ATTACK_PATH_NARRATIVE_FALLBACK_LOGGED:
            _ATTACK_PATH_NARRATIVE_FALLBACK_LOGGED = True
            print_info_debug(
                "Attack-path narrative formatter unavailable; using built-in fallback "
                f"(reason: {exc})"
            )
        return (
            _fallback_format_attack_path_node_label,
            _fallback_format_attack_path_relation_label,
        )


def print_attack_path_detail(
    domain: str,
    path: Dict[str, object],
    *,
    index: int | None = None,
) -> None:
    """Render a detailed single attack path breakdown."""
    from rich.table import Table
    from rich.text import Text

    nodes = path.get("nodes", [])
    rels = path.get("relations", [])
    if not isinstance(nodes, list):
        nodes = []
    if not isinstance(rels, list):
        rels = []

    def _mark_node(name: str) -> str:
        if not name:
            return "N/A"
        if "." in name or name.endswith("$"):
            return mark_sensitive(name, "hostname")
        return mark_sensitive(name, "user")

    def _format_status(value: object) -> Text:
        status = str(value or "discovered").strip().lower()
        if status in {"exploited", "success", "succeeded"}:
            return Text(status, style=f"bold {BRAND_COLORS['success']}")
        if status in {"attempted"}:
            return Text(status, style=f"bold {BRAND_COLORS['warning']}")
        if status in {"failed", "error"}:
            return Text(status, style=f"bold {BRAND_COLORS['error']}")
        return Text(status, style="dim")

    header = Text()
    header.append("Attack Path", style="bold white")
    if index is not None:
        header.append(f" #{index}", style=f"bold {BRAND_COLORS['info']}")
    header.append("  ")
    header.append(f"Domain: {domain}", style="dim")

    print_panel(
        header,
        title="🧭 Path Details",
        border_style=BRAND_COLORS["info"],
        padding=(0, 2),
        expand=True,
        spacing="both",
    )

    steps = path.get("steps", [])
    if not isinstance(steps, list):
        steps = []

    step_status_map: dict[tuple[str, str, str], object] = {}
    for step in steps:
        if not isinstance(step, dict):
            continue
        details = step.get("details")
        if not isinstance(details, dict):
            continue
        from_label = str(details.get("from") or "")
        to_label = str(details.get("to") or "")
        action = str(step.get("action") or "")
        if not (from_label and to_label and action):
            continue
        step_status_map[(from_label, to_label, action)] = step.get("status")

    table = Table(
        show_header=True,
        header_style=f"bold {BRAND_COLORS['success']}",
        border_style=BRAND_COLORS["success"],
        padding=(0, 1),
    )
    table.add_column("#", justify="right", width=3)
    table.add_column("From", style="cyan", no_wrap=False)
    table.add_column("Relation", style="yellow", no_wrap=False)
    table.add_column("To", style="cyan", no_wrap=False)
    table.add_column("Status", style="white", no_wrap=True)

    if nodes and rels:
        for idx, rel in enumerate(rels, start=1):
            if idx > len(nodes) - 1:
                break
            from_node = str(nodes[idx - 1])
            to_node = str(nodes[idx])
            rel_name = str(rel)
            status = step_status_map.get((from_node, to_node, rel_name), "discovered")
            table.add_row(
                str(idx),
                _mark_node(from_node),
                rel_name,
                _mark_node(to_node),
                _format_status(status),
            )
        print_table(table, spacing="after")
        return

    if steps:
        for idx, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                continue
            details = step.get("details")
            if not isinstance(details, dict):
                continue
            from_label = str(details.get("from") or "")
            to_label = str(details.get("to") or "")
            action = str(step.get("action") or "")
            if not (from_label and to_label and action):
                continue
            table.add_row(
                str(idx),
                _mark_node(from_label),
                action,
                _mark_node(to_label),
                _format_status(step.get("status")),
            )
        print_table(table, spacing="after")
        return

    print_info("No graph nodes/relations or steps recorded for this path.", icon="")


def print_attack_steps_summary(
    domain: str,
    steps: List[Dict[str, object]],
    *,
    max_display: int = 10,
    start_user: str | None = None,
) -> None:
    """Render a compact listing of raw attack graph steps (edges).

    This is intended for transparency and debugging. It uses the same step
    table rendering as `print_attack_path_detail` for consistency.
    """
    from rich.panel import Panel
    from rich.text import Text

    if not steps:
        return

    console = _get_console()
    total = len(steps)
    show_count = min(max_display, total)

    header = Text()
    header.append("Attack Steps", style="bold white")
    if start_user:
        header.append("  ", style="dim")
        header.append("User: ", style="dim")
        header.append(mark_sensitive(start_user, "user"), style="dim")

    summary = Text()
    summary.append("Attack Steps Found: ", style="bold white")
    summary.append(str(total), style=f"bold {BRAND_COLORS['warning']}")
    summary.append("  ")
    summary.append("Showing: ", style="bold white")
    summary.append(str(show_count), style=f"bold {BRAND_COLORS['info']}")

    console.print()
    console.print(
        Panel(
            summary,
            title=f"🧩 Domain: {domain}",
            border_style=BRAND_COLORS["info"],
            padding=(0, 2),
        )
    )
    if start_user:
        console.print(header)

    table, truncated = _build_attack_steps_table(steps, max_steps=max_display)
    console.print()
    console.print(table)
    if truncated:
        print_warning(f"Showing first {max_display} steps only ({total} total).")


def _format_attack_step_details(step_details: object) -> str:
    if not isinstance(step_details, dict):
        return ""
    fields: list[str] = []
    from_node = step_details.get("from")
    if isinstance(from_node, str) and from_node:
        from_display = (
            mark_sensitive(from_node, "hostname")
            if "." in from_node or from_node.endswith("$")
            else mark_sensitive(from_node, "user")
        )
        fields.append(f"from={from_display}")
    to_node = step_details.get("to")
    if isinstance(to_node, str) and to_node:
        to_display = (
            mark_sensitive(to_node, "hostname")
            if "." in to_node or to_node.endswith("$")
            else mark_sensitive(to_node, "user")
        )
        fields.append(f"to={to_display}")
    username = step_details.get("username")
    if isinstance(username, str) and username:
        fields.append(f"user={mark_sensitive(username, 'user')}")
    target = step_details.get("target")
    if isinstance(target, str) and target:
        target_display = (
            mark_sensitive(target, "hostname")
            if "." in target or target.endswith("$")
            else mark_sensitive(target, "user")
        )
        fields.append(f"target={target_display}")
    roast_type = step_details.get("roast_type")
    if isinstance(roast_type, str) and roast_type:
        fields.append(f"type={roast_type}")
    delegation_type = step_details.get("delegation_type")
    if isinstance(delegation_type, str) and delegation_type:
        fields.append(f"delegation={delegation_type}")
    delegation_to = step_details.get("delegation_to")
    if isinstance(delegation_to, str) and delegation_to:
        fields.append(f"spn={mark_sensitive(delegation_to, 'service')}")
    edge_type = step_details.get("edge_type")
    if isinstance(edge_type, str) and edge_type:
        fields.append(f"edge={edge_type}")
    wordlist = step_details.get("wordlist")
    if isinstance(wordlist, str) and wordlist:
        fields.append(f"wordlist={wordlist}")
    notes = step_details.get("notes")
    if isinstance(notes, str) and notes:
        fields.append(f"notes={notes}")
    elif isinstance(notes, dict) and notes:
        # Best-effort: show at most a few primitive entries.
        parts: list[str] = []
        for key, value in notes.items():
            if value is None:
                continue
            if isinstance(value, (str, int, float, bool)) and str(value).strip():
                parts.append(f"{key}={value}")
        if parts:
            fields.append("notes=" + " ".join(parts[:4]))
    return ", ".join(fields)


def _build_attack_steps_table(
    steps: List[Dict[str, object]], *, max_steps: int
) -> tuple["Table", bool]:
    from rich.table import Table
    from rich.text import Text

    status_styles = {
        "pending": BRAND_COLORS["warning"],
        "attempted": BRAND_COLORS["info"],
        "discovered": BRAND_COLORS["info"],
        "success": BRAND_COLORS["success"],
        "failed": BRAND_COLORS["error"],
        "error": BRAND_COLORS["error"],
    }

    steps_table = Table(
        title="Steps",
        title_style=f"bold {BRAND_COLORS['info']}",
        border_style=BRAND_COLORS["info"],
        show_header=True,
        header_style=f"bold {BRAND_COLORS['info']}",
        padding=(0, 1),
    )
    steps_table.add_column("#", justify="right", width=3)
    steps_table.add_column("Action", style="cyan", no_wrap=False)
    steps_table.add_column("Status", style="white", no_wrap=False)
    steps_table.add_column("Details", style="dim", no_wrap=False)

    truncated = len(steps) > max_steps
    for idx, step in enumerate(steps[:max_steps], start=1):
        if not isinstance(step, dict):
            continue
        action = step.get("action") or step.get("type") or "N/A"
        status = str(step.get("status") or "pending").lower()
        status_style = status_styles.get(status, BRAND_COLORS["warning"])
        details_text = _format_attack_step_details(step.get("details"))
        steps_table.add_row(
            str(step.get("step") or idx),
            str(action),
            Text(status, style=f"bold {status_style}"),
            details_text or "—",
        )

    return steps_table, truncated


def print_table_debug(table: "Table", *, title: str | None = None) -> None:
    """Print a Rich table only when debug mode is enabled."""
    global _debug_mode
    logger = _get_logger()
    logger.debug(title or "Debug table output")
    if not _debug_mode:
        return
    _console.print(table)
    _console.print()


def print_attack_path_detail_debug(
    domain: str,
    path: Dict[str, object],
    *,
    index: int | None = None,
) -> None:
    """Print a detailed attack path only when debug mode is enabled."""
    global _debug_mode
    if not _debug_mode:
        return
    print_info_debug("DEBUG attack path detail (debug-only output).")
    print_attack_path_detail(domain, path, index=index)
    _get_console().print()


def confirm_operation(
    operation_name: str,
    description: str,
    context: Optional[Dict[str, str]] = None,
    default: bool = True,
    icon: str = "🔍",
    show_panel: bool = True,
) -> bool:
    """Display a professional confirmation prompt for an operation.

    This function provides a rich, informative prompt that helps users understand
    what an operation will do before confirming it. It can display context information
    in a structured format and uses ADscan brand styling.

    Args:
        operation_name: Name of the operation (e.g., "SMB Service Scan")
        description: Brief description of what the operation does
        context: Optional dict of contextual information to display (e.g., {"Domain": "example.local"})
        default: Default answer (True = yes, False = no)
        icon: Emoji icon to display with the operation name
        show_panel: Whether to show a panel with context info (if False, shows compact format)

    Returns:
        bool: True if user confirmed, False otherwise

    Example:
        >>> confirmed = confirm_operation(
        ...     "ADCS Detection",
        ...     "Searches for Active Directory Certificate Services in the domain",
        ...     context={"Domain": "example.local", "PDC": "dc.example.local"},
        ...     icon="🔐"
        ... )
    """
    from rich.panel import Panel
    from rich.text import Text
    from rich.table import Table

    console = _get_console()

    # Build the prompt message
    if show_panel and context:
        # Create a context table
        context_table = Table.grid(padding=(0, 2))
        context_table.add_column(style="bold cyan", justify="right")
        context_table.add_column(style="white")

        for key, value in context.items():
            context_table.add_row(f"{key}:", value)

        # Create a panel with operation info
        panel_content = Group(
            Text(description, style="white"),
            Text(""),  # Empty line
            context_table,
        )

        panel = Panel(
            panel_content,
            title=f"{icon} {operation_name}",
            title_align="left",
            border_style=BRAND_COLORS["info"],
            padding=(1, 2),
        )

        console.print(panel)
        prompt_text = "Proceed with this operation?"
    else:
        # Compact format without panel
        if context:
            context_str = " ".join([f"{k}: {v}" for k, v in context.items()])
            prompt_text = f"{icon} {operation_name} - {description} ({context_str})"
        else:
            prompt_text = f"{icon} {operation_name} - {description}"

    # Show confirmation prompt
    try:
        return confirm_ask(prompt_text, default=default)
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        console.print("\n[yellow]Operation cancelled[/yellow]")
        return False


class TelemetryAwareConsole:
    """Wrapper console that duplicates output to a telemetry console.

    This ensures that direct console.print() calls in the shell (e.g. do_help tables)
    are captured in the session recording, not just output routed through the
    logging system or rich_output helpers.
    """

    def __init__(self, main_console, telemetry_console):
        self.main_console = main_console
        self.telemetry_console = telemetry_console

    def print(self, *args, **kwargs):
        self.main_console.print(*args, **kwargs)
        if self.telemetry_console:
            self.telemetry_console.print(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self.main_console, name)
