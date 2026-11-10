"""Generic opt-in remote interaction bridge for structured scan prompts.

This module allows selected CLI prompts to be delegated to an external
orchestrator without coupling the public CLI to any specific web service.
The bridge is disabled by default and becomes active only when an explicit
interaction sink is configured.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import logging

from adscan_internal.cli.ci_events import emit_event

_LOGGER = logging.getLogger("adscan.interactive")

_INTERACTION_SINK = str(
    os.environ.get("ADSCAN_INTERACTIVE_SINK", "") or ""
).strip().lower()
# ``file`` sink: the directory request/response files are exchanged through.
# Used where the engine cannot reach the orchestrator's Redis (a scanner node);
# the node relays the files and the console bridges them onto the same Redis
# keys the ``redis`` sink uses, so routes and frontend do not change.
_INTERACTION_DIR = str(os.environ.get("ADSCAN_INTERACTIVE_DIR", "") or "").strip()
_SCAN_ID = str(os.environ.get("ADSCAN_SCAN_ID", "") or "").strip()
_REDIS_URL = str(
    os.environ.get("ADSCAN_REDIS_URL")
    or os.environ.get("REDIS_URL")
    or ""
).strip()
_REQUEST_TIMEOUT_SECONDS = int(
    str(os.environ.get("ADSCAN_INTERACTIVE_TIMEOUT_SECONDS", "3600") or "3600")
)
_POLL_INTERVAL_SECONDS = float(
    str(os.environ.get("ADSCAN_INTERACTIVE_POLL_INTERVAL_SECONDS", "1.0") or "1.0")
)
_REQUEST_TTL_SECONDS = int(
    str(os.environ.get("ADSCAN_INTERACTIVE_REQUEST_TTL_SECONDS", "7200") or "7200")
)


# How the most recent request in this process resolved ("answered", "timeout",
# "invalid_response", or None when none was dispatched / the bridge was off).
# A prompt helper returns only the chosen values, so a caller that must tell
# "the operator picked the default" from "nobody answered" (the doctor's
# decision prompt) reads it here instead of re-implementing the channel.
_LAST_RESOLUTION: str | None = None
# Who answered the most recent request: the console's signed-in user, which the
# console stamps on the response it stores (``responded_by``). ``None`` when the
# request timed out or the answer carried no usable name. A decision that must
# record WHO made it (a licence declaration) reads it here.
_LAST_RESPONDER: str | None = None
_RESPONDER_MAX_LENGTH = 128


def last_resolution() -> str | None:
    """Return how the most recent remote request resolved, or ``None``."""
    return _LAST_RESOLUTION


def last_responder() -> str | None:
    """Return who answered the most recent remote request, or ``None``."""
    return _LAST_RESPONDER


def request_timeout_seconds() -> int:
    """How long one relayed request waits for an answer before it times out."""
    return _REQUEST_TIMEOUT_SECONDS


def _record_responder(payload: dict[str, Any] | None) -> None:
    global _LAST_RESPONDER  # noqa: PLW0603
    value = (payload or {}).get("responded_by")
    name = value.strip()[:_RESPONDER_MAX_LENGTH] if isinstance(value, str) else ""
    _LAST_RESPONDER = name or None


def is_remote_interaction_enabled() -> bool:
    """Return whether the remote interaction bridge is explicitly enabled."""
    if _INTERACTION_SINK == "file":
        return bool(_INTERACTION_DIR) and _REQUEST_TIMEOUT_SECONDS > 0
    return (
        _INTERACTION_SINK == "redis"
        and bool(_SCAN_ID)
        and bool(_REDIS_URL)
        and _REQUEST_TIMEOUT_SECONDS > 0
    )


def request_select(
    *,
    title: str,
    options: list[str],
    default_idx: int = 0,
    timeout_result: int | None = None,
    context: dict[str, object] | None = None,
) -> int | None:
    """Request one remote selection from a compatible external orchestrator."""
    if not is_remote_interaction_enabled() or not options:
        return None

    resolved_default_idx = min(max(default_idx, 0), len(options) - 1)
    request_id = str(uuid.uuid4())
    request_payload: dict[str, Any] = {
        "request_id": request_id,
        "scan_id": _SCAN_ID,
        "kind": "select",
        "title": title,
        "default_index": resolved_default_idx,
        "options": [
            {
                "index": index,
                "label": label,
            }
            for index, label in enumerate(options)
        ],
        "context": dict(context or {}),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    response = _dispatch_request(
        request_payload=request_payload,
        timeout_result={"selected_index": timeout_result},
    )
    selected_index = response.get("selected_index")
    if isinstance(selected_index, int) and 0 <= selected_index < len(options):
        return selected_index
    return timeout_result


def request_multiselect(
    *,
    title: str,
    options: list[str],
    default_indices: list[int] | None = None,
    timeout_result: list[int] | None = None,
    context: dict[str, object] | None = None,
) -> list[int] | None:
    """Request one remote multi-selection from a compatible external orchestrator.

    Mirrors :func:`request_select` but resolves to a *set* of chosen option
    indices instead of a single one. Used for the web trust-scope picker, where
    the operator selects N domains to keep in enumeration scope.

    Args:
        title: Prompt text shown to the operator.
        options: Selectable option labels (index-aligned with the returned list).
        default_indices: Indices checked by default (e.g. the origin domain).
        timeout_result: Indices to resolve to when the request times out or the
            bridge is unavailable. Kept distinct from "operator picked nothing"
            so a hung/abandoned session resolves to a safe default (origin-only)
            instead of an empty scope.
        context: Arbitrary decision payload (the trust-topology data rides here).

    Returns:
        The operator's chosen indices, ``timeout_result`` on timeout, or ``None``
        when the bridge is disabled (caller falls back to the local prompt).
    """
    if not is_remote_interaction_enabled() or not options:
        return None

    valid_defaults = sorted(
        {idx for idx in (default_indices or []) if 0 <= idx < len(options)}
    )
    request_id = str(uuid.uuid4())
    request_payload: dict[str, Any] = {
        "request_id": request_id,
        "scan_id": _SCAN_ID,
        "kind": "multiselect",
        "title": title,
        "default_indices": valid_defaults,
        "options": [
            {
                "index": index,
                "label": label,
            }
            for index, label in enumerate(options)
        ],
        "context": dict(context or {}),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    response = _dispatch_request(
        request_payload=request_payload,
        timeout_result={"selected_indices": timeout_result},
    )
    selected_indices = response.get("selected_indices")
    if isinstance(selected_indices, list):
        normalized = sorted(
            {
                idx
                for idx in selected_indices
                if isinstance(idx, int) and 0 <= idx < len(options)
            }
        )
        return normalized
    return timeout_result


def request_confirm(
    *,
    prompt: str,
    default: bool,
    timeout_result: bool | None = None,
    context: dict[str, object] | None = None,
) -> bool | None:
    """Request one remote boolean confirmation from an external orchestrator."""
    if not is_remote_interaction_enabled():
        return None

    request_id = str(uuid.uuid4())
    request_payload: dict[str, Any] = {
        "request_id": request_id,
        "scan_id": _SCAN_ID,
        "kind": "confirm",
        "title": prompt,
        "default_value": default,
        "options": [
            {"value": True, "label": "Approve"},
            {"value": False, "label": "Skip"},
        ],
        "context": dict(context or {}),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    response = _dispatch_request(
        request_payload=request_payload,
        timeout_result={"approved": timeout_result},
    )
    approved = response.get("approved")
    if isinstance(approved, bool):
        return approved
    return timeout_result


def _dispatch_request(
    *,
    request_payload: dict[str, Any],
    timeout_result: dict[str, Any],
) -> dict[str, Any]:
    """Publish one interactive request and wait for one response payload."""
    global _LAST_RESOLUTION  # noqa: PLW0603
    _LAST_RESOLUTION = None
    _record_responder(None)
    if _INTERACTION_SINK == "file":
        return _dispatch_request_via_files(
            request_payload=request_payload, timeout_result=timeout_result
        )
    request_id = str(request_payload["request_id"])
    current_key = _current_request_key(_SCAN_ID)
    response_key = _response_key(_SCAN_ID, request_id)
    redis_client = _get_redis_client()
    if redis_client is None:
        return timeout_result

    try:
        redis_client.set(
            current_key,
            json.dumps(request_payload, ensure_ascii=False),
            ex=_REQUEST_TTL_SECONDS,
        )
        redis_client.delete(response_key)
    except Exception:
        _LOGGER.exception("Failed to publish interactive request state")
        return timeout_result

    emit_event("interactive_request", **request_payload)

    started = time.monotonic()
    try:
        while time.monotonic() - started < _REQUEST_TIMEOUT_SECONDS:
            try:
                raw_response = redis_client.get(response_key)
            except Exception:
                _LOGGER.exception("Failed to poll interactive response")
                break
            if raw_response:
                response_payload = _parse_response(raw_response)
                response_payload.setdefault("request_id", request_id)
                _LAST_RESOLUTION = _clamp_resolution(response_payload.get("resolution"))
                _record_responder(response_payload)
                _emit_resolution(request_id, _LAST_RESOLUTION, response_payload)
                return response_payload
            time.sleep(_POLL_INTERVAL_SECONDS)
    finally:
        try:
            redis_client.delete(current_key)
            redis_client.delete(response_key)
        except Exception:
            _LOGGER.debug(
                "Failed to clear interactive request state for scan %s",
                _SCAN_ID,
                exc_info=True,
            )

    _LAST_RESOLUTION = "timeout"
    _emit_resolution(request_id, "timeout", timeout_result)
    return timeout_result


#: Resolution tokens an ``interactive_resolution`` event may carry. A relay is a
#: separate party (the console, a scanner node); an unknown token is reported as
#: a plain answer, never echoed.
_RESOLUTIONS = frozenset({"answered", "timeout", "invalid_response", "cancelled", "declined"})

#: Answer fields a relay may supply, with the type each must have. Everything
#: else in a response payload is dropped from the event.
_RESPONSE_FIELDS: dict[str, type] = {
    "selected_index": int,
    "selected_indices": list,
    "approved": bool,
}


def _clamp_resolution(value: object) -> str:
    token = str(value or "answered").strip().lower()
    return token if token in _RESOLUTIONS else "answered"


def _emit_resolution(request_id: str, resolution: str, payload: dict[str, Any]) -> None:
    """Emit ``interactive_resolution`` from the engine's own fields only.

    The relay's payload is never splatted into the event: a response key named
    ``type`` or ``event_type`` would otherwise forge the event's type or crash the
    call. The request id is the engine's own, the resolution is clamped, and the
    answer travels as one nested ``response`` object holding only the allow-listed,
    type-checked fields.
    """
    response: dict[str, Any] = {}
    for key, expected in _RESPONSE_FIELDS.items():
        value = payload.get(key)
        if value is None or isinstance(value, bool) != (expected is bool):
            continue
        if expected is list:
            if isinstance(value, list) and all(isinstance(i, int) and not isinstance(i, bool) for i in value):
                response[key] = list(value)
        elif isinstance(value, expected):
            response[key] = value
    emit_event(
        "interactive_resolution",
        request_id=request_id,
        scan_id=_SCAN_ID,
        resolution=resolution,
        response=response,
    )


def _request_file(request_id: str) -> Path:
    return Path(_INTERACTION_DIR) / f"request-{request_id}.json"


def _response_file(request_id: str) -> Path:
    return Path(_INTERACTION_DIR) / f"response-{request_id}.json"


def _write_request_file(path: Path, text: str) -> None:
    """Write the request atomically, so a relay never reads half of one."""
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def _read_response_file(path: Path) -> dict[str, Any] | None:
    """Return the response payload, or ``None`` when it is absent or incomplete.

    A relay is expected to write the response atomically (rename into place);
    a file that does not decode to an object is treated as still being written,
    never as an answer, so a torn write cannot decide for the operator.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        parsed = json.loads(text)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _dispatch_request_via_files(
    *,
    request_payload: dict[str, Any],
    timeout_result: dict[str, Any],
) -> dict[str, Any]:
    """The ``file`` sink: the Redis protocol, carried by two files.

    The request file holds the SAME JSON string the Redis sink publishes; the
    timeout, the polling interval, the default on timeout and the emitted
    ``interactive_request`` / ``interactive_resolution`` events are the Redis
    sink's. Both files are removed once the request resolves.
    """
    global _LAST_RESOLUTION  # noqa: PLW0603
    request_id = str(request_payload["request_id"])
    request_path = _request_file(request_id)
    response_path = _response_file(request_id)
    try:
        request_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        response_path.unlink(missing_ok=True)
        _write_request_file(request_path, json.dumps(request_payload, ensure_ascii=False))
    except OSError:
        _LOGGER.exception("Failed to publish interactive request file")
        return timeout_result

    emit_event("interactive_request", **request_payload)

    started = time.monotonic()
    try:
        while time.monotonic() - started < _REQUEST_TIMEOUT_SECONDS:
            response_payload = _read_response_file(response_path)
            if response_payload is not None:
                response_payload.setdefault("request_id", request_id)
                _LAST_RESOLUTION = _clamp_resolution(response_payload.get("resolution"))
                _record_responder(response_payload)
                _emit_resolution(request_id, _LAST_RESOLUTION, response_payload)
                return response_payload
            time.sleep(_POLL_INTERVAL_SECONDS)
    finally:
        for path in (request_path, response_path):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                _LOGGER.debug("Failed to remove interactive file %s", path, exc_info=True)

    _LAST_RESOLUTION = "timeout"
    _emit_resolution(request_id, "timeout", timeout_result)
    return timeout_result


def _get_redis_client():
    """Create a Redis client lazily when the bridge is enabled."""
    try:
        import redis

        return redis.Redis.from_url(_REDIS_URL, decode_responses=True)
    except Exception:
        _LOGGER.exception("Failed to initialize remote interaction Redis client")
        return None


def _parse_response(raw_response: str) -> dict[str, Any]:
    """Parse one stored response payload safely."""
    try:
        parsed = json.loads(raw_response)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        _LOGGER.debug("Failed to decode interaction response JSON", exc_info=True)
    return {"resolution": "invalid_response"}


def _current_request_key(scan_id: str) -> str:
    """Return the Redis key that stores the current active request for one scan."""
    return f"adscan:scan:interaction:{scan_id}:current"


def _response_key(scan_id: str, request_id: str) -> str:
    """Return the Redis key that stores one response payload."""
    return f"adscan:scan:interaction:{scan_id}:response:{request_id}"
