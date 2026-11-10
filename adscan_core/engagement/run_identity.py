"""The run identity: one id per engine run, shared by every artifact it writes.

The event stream header, ``coverage.json`` and ``run_summary.json`` must name the
same run, or a consumer cannot tell which events and which summary describe the
coverage it is reading. An orchestrator that dispatched the run (a RunPlan's
``run_id``, a console job id) passes it in ``ADSCAN_RUN_ID``; otherwise the first
writer mints one and exports it, so every later writer in the process, and any
child process, reads the same value.

Stdlib only: the web backend and the node service import ``adscan_core``.
"""

from __future__ import annotations

import os
import re
import uuid

RUN_ID_ENV = "ADSCAN_RUN_ID"

#: Same shape as the contract schemas' ``run_id`` (a token, never a path).
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

_MINTED: str | None = None


def is_valid_run_id(value: object) -> bool:
    """Return whether ``value`` is a contract-shaped run id."""
    return isinstance(value, str) and bool(_RUN_ID_RE.match(value))


def current_run_id() -> str:
    """Return this run's id, minting and exporting one on first use.

    An orchestrator-provided ``ADSCAN_RUN_ID`` wins when it is a valid token; an
    invalid one is ignored rather than propagated into artifacts.
    """
    global _MINTED  # noqa: PLW0603
    provided = os.environ.get(RUN_ID_ENV, "")
    if is_valid_run_id(provided):
        return provided
    if _MINTED is None:
        _MINTED = uuid.uuid4().hex
    os.environ[RUN_ID_ENV] = _MINTED
    return _MINTED


__all__ = ("RUN_ID_ENV", "current_run_id", "is_valid_run_id")
