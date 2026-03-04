"""Logging utilities for BloodHound CLI based on stdlib logging.

This module provides a tiny compatibility wrapper that preserves the existing
call style used in the integration:

``logger = get_logger(...).bind(...); logger.info("event", key=value)``
"""

from __future__ import annotations

import logging
import json
import sys
from functools import lru_cache
from typing import Any, Dict

_JSON_OUTPUT: bool = False


def configure_logging(debug: bool = False, json_output: bool = False) -> None:
    """Configure logging once for BloodHound CLI.

    Args:
        debug: Whether to emit debug-level events.
        json_output: Emit logs as JSON instead of human-readable console output.
    """
    global _JSON_OUTPUT
    _JSON_OUTPUT = bool(json_output)
    _configure_logging_once(debug, json_output)


@lru_cache(maxsize=1)
def _configure_logging_once(debug: bool, json_output: bool) -> None:
    """Configure stdlib logging exactly once, caching by arguments."""
    level = logging.DEBUG if debug else logging.INFO
    _ = json_output
    logging.basicConfig(level=level, stream=sys.stderr, format="%(message)s")


def _sanitize_context(context: Dict[str, Any]) -> Dict[str, Any]:
    """Make sure context values are serializable."""
    cleaned: Dict[str, Any] = {}
    for key, value in context.items():
        if isinstance(value, (str, int, float, bool)) or value is None:
            cleaned[key] = value
        else:
            cleaned[key] = str(value)
    return cleaned


class ContextLogger:
    """Small logger wrapper compatible with the previous contextual call style."""

    def __init__(
        self, logger: logging.Logger, context: Dict[str, Any] | None = None
    ) -> None:
        self._logger = logger
        self._context = dict(context or {})

    def bind(self, **initial_context: Any) -> "ContextLogger":
        """Return a logger with merged bound context."""
        merged = dict(self._context)
        merged.update(_sanitize_context(initial_context))
        return ContextLogger(self._logger, merged)

    def _render(self, event: str, context: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
        merged = dict(self._context)
        merged.update(_sanitize_context(context))
        if not merged:
            return str(event), {}
        if _JSON_OUTPUT:
            payload = {"event": str(event), **merged}
            return json.dumps(payload, ensure_ascii=False, sort_keys=True), merged
        context_text = " ".join(f"{key}={merged[key]!r}" for key in sorted(merged))
        return f"{event} | {context_text}", merged

    def _log(self, level: int, event: str, *, exc_info: bool = False, **context: Any) -> None:
        message, merged = self._render(str(event), context)
        extra: Dict[str, Any] | None = {"context": merged} if merged else None
        self._logger.log(level, message, exc_info=exc_info, extra=extra)

    def debug(self, event: str, **context: Any) -> None:
        self._log(logging.DEBUG, event, **context)

    def info(self, event: str, **context: Any) -> None:
        self._log(logging.INFO, event, **context)

    def warning(self, event: str, **context: Any) -> None:
        self._log(logging.WARNING, event, **context)

    def warn(self, event: str, **context: Any) -> None:
        self.warning(event, **context)

    def error(self, event: str, **context: Any) -> None:
        self._log(logging.ERROR, event, **context)

    def exception(self, event: str, **context: Any) -> None:
        self._log(logging.ERROR, event, exc_info=True, **context)

    def critical(self, event: str, **context: Any) -> None:
        self._log(logging.CRITICAL, event, **context)


def get_logger(name: str | None = None, **initial_context: Any) -> ContextLogger:
    """Return a logger bound with optional initial context."""
    logger_name = name or "adscan.bloodhound_cli"
    logger = logging.getLogger(logger_name)
    bound_context = _sanitize_context(initial_context) if initial_context else {}
    return ContextLogger(logger, bound_context)
