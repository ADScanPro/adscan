"""Who an operator decision is recorded under: one resolution for every seam.

A decision a client will read about later (a licence declaration, an attack
step the operator declined) carries the name of the person who made it.

* On the web, the signed-in console user who answered the relayed request
  (``interactive_requests.last_responder``).
* On the command line there is no sign-in, so the name is the operator's own
  statement: ``ADSCAN_OPERATOR_NAME`` when configured; natively, the OS account
  running ADscan; inside the container (where the OS account is the image's
  service user, never a person) the operator is asked once per session.

Recorded as ``"<name> (command line)"`` so a reader can tell the two apart.
"""

from __future__ import annotations

import os
from typing import Any, Callable

#: Environment variable naming the command-line operator.
OPERATOR_NAME_ENV = "ADSCAN_OPERATOR_NAME"
#: Suffix of a name given on the command line.
COMMAND_LINE_SUFFIX = " (command line)"
#: Longest name kept.
OPERATOR_NAME_MAX_LENGTH = 80
#: Shell attribute caching the command-line name for the session.
_CACHE_ATTR = "_operator_command_line_name"


def clean_operator_name(value: Any) -> str:
    """Collapse whitespace and bound the length of a stated name."""
    return " ".join(str(value or "").split())[:OPERATOR_NAME_MAX_LENGTH]


def command_line_operator_name(
    shell: Any,
    *,
    prompt_text: str,
    prompt: Callable[..., Any] | None = None,
    user_name: Callable[[], Any] | None = None,
) -> str:
    """Return ``"<name> (command line)"``, or ``""`` when nobody gives a name.

    Args:
        shell: The session shell (caches the answer, and is passed to the prompt).
        prompt_text: The question shown when the operator must be asked.
        prompt: The prompt function (``adscan_core.output.prompt_ask`` by
            default); injectable so a caller keeps its own patch point.
        user_name: Returns the OS account name (``pal.process.current_user_name``
            by default).
    """
    cached = getattr(shell, _CACHE_ATTR, None)
    if isinstance(cached, str) and cached:
        return cached
    name = clean_operator_name(os.environ.get(OPERATOR_NAME_ENV))
    if not name and os.environ.get("ADSCAN_CONTAINER_RUNTIME") != "1":
        if user_name is None:
            from adscan_core.pal.process import current_user_name as user_name  # noqa: PLC0415
        name = clean_operator_name(user_name())
    if not name:
        if prompt is None:
            from adscan_core.output import prompt_ask as prompt  # noqa: PLC0415
        name = clean_operator_name(prompt(prompt_text, default="", shell=shell))
    resolved = f"{name}{COMMAND_LINE_SUFFIX}" if name else ""
    if resolved:
        try:
            setattr(shell, _CACHE_ATTR, resolved)
        except Exception:  # noqa: BLE001 - a read-only shell just asks again
            pass
    return resolved


__all__ = [
    "COMMAND_LINE_SUFFIX",
    "OPERATOR_NAME_ENV",
    "OPERATOR_NAME_MAX_LENGTH",
    "clean_operator_name",
    "command_line_operator_name",
]
