"""Decorators for ADScan services.

This module provides decorators for license checks,
authentication requirements, and operation validation.
"""

from functools import wraps
from typing import Callable, Any
import logging

from .enums import AuthMode
from .exceptions import AuthenticationError


logger = logging.getLogger(__name__)


def requires_auth(min_auth_mode: AuthMode) -> Callable:
    """Decorator to mark methods that require specific authentication level.

    Usage:
        @requires_auth(AuthMode.AUTHENTICATED)
        def get_domain_info(self, ...):
            # Method implementation

    Args:
        min_auth_mode: Minimum required AuthMode

    Raises:
        AuthenticationError: If current auth mode is insufficient

    Returns:
        Decorated function
    """

    # Define auth mode hierarchy
    AUTH_HIERARCHY = {
        AuthMode.UNAUTHENTICATED: 0,
        AuthMode.USER_LIST: 1,
        AuthMode.AUTHENTICATED: 2,
    }

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(self, *args, **kwargs) -> Any:
            # Extract current_auth_mode from kwargs or instance
            current_auth_mode = kwargs.get("auth_mode")
            if current_auth_mode is None and hasattr(self, "auth_mode"):
                current_auth_mode = self.auth_mode

            # If no auth mode available, assume authenticated (for backward compatibility)
            if current_auth_mode is None:
                logger.warning(
                    f"{func.__name__} called without auth_mode. Assuming authenticated."
                )
                return func(self, *args, **kwargs)

            # Convert to AuthMode enum if string
            if isinstance(current_auth_mode, str):
                try:
                    current_auth_mode = AuthMode(current_auth_mode)
                except ValueError:
                    logger.error(f"Invalid auth_mode: {current_auth_mode}")
                    raise AuthenticationError(
                        operation=func.__name__,
                        required_auth_mode=min_auth_mode.value,
                        current_auth_mode=str(current_auth_mode),
                    )

            # Check auth level
            required_level = AUTH_HIERARCHY[min_auth_mode]
            current_level = AUTH_HIERARCHY[current_auth_mode]

            if current_level < required_level:
                logger.error(
                    f"Insufficient authentication for {func.__name__}: "
                    f"requires {min_auth_mode.value}, got {current_auth_mode.value}"
                )
                raise AuthenticationError(
                    operation=func.__name__,
                    required_auth_mode=min_auth_mode.value,
                    current_auth_mode=current_auth_mode.value,
                )

            # Sufficient auth - execute normally
            return func(self, *args, **kwargs)

        # Mark function with required auth mode for introspection
        wrapper.__required_auth__ = min_auth_mode
        return wrapper

    return decorator


def requires_tool(tool_name: str, install_hint: str = None) -> Callable:
    """Decorator to check if external tool is available.

    Usage:
        @requires_tool("netexec", "Install with: adscan install")
        def run_netexec_command(self, ...):
            # Method implementation

    Args:
        tool_name: Name of required tool
        install_hint: Optional hint on how to install

    Raises:
        ToolNotFoundError: If tool is not available

    Returns:
        Decorated function
    """
    from .exceptions import ToolNotFoundError

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(self, *args, **kwargs) -> Any:
            # Check if service has method to verify tool
            tool_check_method = f"_is_{tool_name.replace('-', '_')}_available"

            if hasattr(self, tool_check_method):
                is_available = getattr(self, tool_check_method)()
                if not is_available:
                    logger.error(f"Required tool '{tool_name}' not found")
                    raise ToolNotFoundError(tool_name, install_hint)
            else:
                # No check method available, log warning and continue
                logger.warning(
                    f"No availability check for tool '{tool_name}'. "
                    f"Assuming it's available."
                )

            return func(self, *args, **kwargs)

        # Mark function with required tool for introspection
        wrapper.__required_tool__ = tool_name
        return wrapper

    return decorator


def emits_event(event_type: str) -> Callable:
    """Decorator to mark methods that emit events.

    This is mainly for documentation and introspection purposes.

    Usage:
        @emits_event("progress")
        def enumerate_domain(self, ...):
            # Method emits progress events

    Args:
        event_type: Type of event emitted

    Returns:
        Decorated function
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            return func(*args, **kwargs)

        # Mark function for introspection
        wrapper.__emits_event__ = event_type
        return wrapper

    return decorator
