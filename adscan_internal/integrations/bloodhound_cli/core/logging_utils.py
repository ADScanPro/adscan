"""Logging utilities built on top of structlog."""

from __future__ import annotations

import logging
import sys
from functools import lru_cache
from typing import Any, Dict

import structlog


def configure_logging(debug: bool = False, json_output: bool = False) -> None:
    """Configure structlog + standard logging once.

    Args:
        debug: Whether to emit debug-level events.
        json_output: Emit logs as JSON instead of human-readable console output.
    """
    _configure_logging_once(debug, json_output)


@lru_cache(maxsize=1)
def _configure_logging_once(debug: bool, json_output: bool) -> None:
    """Configure structlog exactly once, caching by arguments."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=level, stream=sys.stderr, format="%(message)s")

    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if json_output:
        render_processor = structlog.processors.JSONRenderer()
    else:
        render_processor = structlog.dev.ConsoleRenderer(colors=debug)

    structlog.configure(
        processors=[*shared_processors, render_processor],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        cache_logger_on_first_use=True,
    )


def get_logger(
    name: str | None = None, **initial_context: Any
) -> structlog.BoundLogger:
    """Return a logger bound with optional initial context."""
    logger = structlog.get_logger(name) if name else structlog.get_logger()
    if initial_context:
        return logger.bind(**_sanitize_context(initial_context))
    return logger


def _sanitize_context(context: Dict[str, Any]) -> Dict[str, Any]:
    """Make sure context values are serialisable."""
    cleaned: Dict[str, Any] = {}
    for key, value in context.items():
        if isinstance(value, (str, int, float, bool)) or value is None:
            cleaned[key] = value
        else:
            cleaned[key] = str(value)
    return cleaned
