"""Scan control vocabulary and the control-request file contract.

Pure stdlib on purpose: the engine, the Celery worker, the run executor and the
web backend all import this module, so it carries no Rich, no prompt toolkit and
no engine import. It defines:

* the four control actions (:class:`ControlAction`);
* the request a trigger hands to the engine (:class:`ControlRequest`);
* the cross-process control-request file the platform writes into the scan's
  EXECUTION workspace and the engine consumes (:func:`write_control_request`,
  :func:`consume_control_request`).

The file replaces the per-operation ``.stop_<operation>`` sentinels as the way the
platform talks to a running scan. Those sentinels stay honoured by the engine for
an older worker driving a newer engine.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Mapping

#: File name of the control request, inside the scan's execution workspace root.
CONTROL_REQUEST_FILENAME = ".scan_control_request.json"

#: Schema marker written into every control request (major only; additive
#: fields are ignored by older readers).
CONTROL_REQUEST_SCHEMA = "adscan.scan_control_request/1"


class ControlAction(str, Enum):
    """What the operator (or the platform) asks a running scan to do."""

    #: Stop the current step, keep what it found so far, go to the next step.
    SKIP_STEP = "skip_step"
    #: Stop the current step and skip the rest of the current phase.
    SKIP_PHASE = "skip_phase"
    #: Stop the scan cleanly and return to the prompt (``ci``: non-success exit).
    ABORT_SCAN = "abort_scan"
    #: Nothing changes (the menu's "Keep going").
    CONTINUE = "continue"


#: Where a request came from. Shapes the operator wording and the gap record.
SOURCE_OPERATOR_MENU = "operator_menu"
SOURCE_SIGNAL = "signal"
SOURCE_PLATFORM = "platform"
SOURCE_LEGACY_SENTINEL = "legacy_sentinel"

#: Actions the platform may write into the control file. ``continue`` is a menu
#: answer, never a request worth sending across processes.
PLATFORM_ACTIONS = frozenset(
    {ControlAction.SKIP_STEP, ControlAction.SKIP_PHASE, ControlAction.ABORT_SCAN}
)


def parse_action(value: Any) -> ControlAction | None:
    """Return the :class:`ControlAction` for ``value`` or ``None`` when unknown."""
    try:
        return ControlAction(str(value or "").strip().lower())
    except ValueError:
        return None


@dataclass(frozen=True)
class ControlRequest:
    """One request to change the course of a running scan.

    Attributes:
        action: What to do.
        source: Where it came from (``operator_menu``, ``signal``, ``platform``,
            ``legacy_sentinel``).
        target_step: The step id the requester saw running, or ``""`` for "the
            current step". A request whose target no longer runs is stale.
        target_phase: The phase id the requester saw running, or ``""``.
        request_id: Unique id, for logs and idempotency.
        created_at: Wall-clock creation time (epoch seconds). Only ever compared
            within one process, never used as a duration.
    """

    action: ControlAction
    source: str = SOURCE_OPERATOR_MENU
    target_step: str = ""
    target_phase: str = ""
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    created_at: float = field(default_factory=time.time)

    def to_document(self) -> dict[str, Any]:
        """Serialize for the control file."""
        doc = asdict(self)
        doc["action"] = self.action.value
        doc["schema"] = CONTROL_REQUEST_SCHEMA
        return doc

    @classmethod
    def from_document(cls, doc: Mapping[str, Any]) -> "ControlRequest | None":
        """Parse a control-file document; ``None`` when it is not a valid request."""
        if not isinstance(doc, Mapping):
            return None
        action = parse_action(doc.get("action"))
        if action is None or action == ControlAction.CONTINUE:
            return None
        try:
            created_at = float(doc.get("created_at") or time.time())
        except (TypeError, ValueError):
            created_at = time.time()
        return cls(
            action=action,
            source=str(doc.get("source") or SOURCE_PLATFORM)[:64],
            target_step=str(doc.get("target_step") or "")[:128],
            target_phase=str(doc.get("target_phase") or "")[:128],
            request_id=str(doc.get("request_id") or uuid.uuid4().hex[:16])[:64],
            created_at=created_at,
        )


def control_request_path(workspace_dir: str | os.PathLike[str]) -> str:
    """Absolute path of the control-request file for one workspace root."""
    return os.path.join(str(workspace_dir), CONTROL_REQUEST_FILENAME)


def write_control_request(
    workspace_dir: str | os.PathLike[str], request: ControlRequest
) -> str:
    """Atomically write ``request`` into ``workspace_dir``; return the path.

    The write is a temp file plus ``os.replace`` so the engine never reads a
    half-written document. A newer request replaces an unconsumed older one: the
    latest click is the operator's intent.

    Raises:
        OSError: when the directory is not writable. Callers on the platform side
            log and report it; the engine never calls this.
    """
    path = control_request_path(workspace_dir)
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".scan_control_", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(request.to_document(), handle)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def consume_control_request(
    workspace_dir: str | os.PathLike[str],
) -> ControlRequest | None:
    """Read and delete the pending control request, if any.

    Best-effort and never raises: an unreadable or malformed file is removed and
    reads as "no request" (a broken file must not be re-read forever, nor abort
    the scan).
    """
    path = control_request_path(workspace_dir)
    try:
        if not os.path.exists(path):
            return None
    except OSError:
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            doc = json.load(handle)
    except (OSError, ValueError):
        doc = None
    try:
        os.unlink(path)
    except OSError:
        pass
    return ControlRequest.from_document(doc) if isinstance(doc, Mapping) else None


__all__ = [
    "CONTROL_REQUEST_FILENAME",
    "CONTROL_REQUEST_SCHEMA",
    "ControlAction",
    "ControlRequest",
    "PLATFORM_ACTIONS",
    "SOURCE_LEGACY_SENTINEL",
    "SOURCE_OPERATOR_MENU",
    "SOURCE_PLATFORM",
    "SOURCE_SIGNAL",
    "consume_control_request",
    "control_request_path",
    "parse_action",
    "write_control_request",
]
