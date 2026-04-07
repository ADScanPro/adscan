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
from typing import Any

import logging

from adscan_internal.cli.ci_events import emit_event

_LOGGER = logging.getLogger("adscan.interactive")

_INTERACTION_SINK = str(
    os.environ.get("ADSCAN_INTERACTIVE_SINK", "") or ""
).strip().lower()
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


def is_remote_interaction_enabled() -> bool:
    """Return whether the remote interaction bridge is explicitly enabled."""
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
                emit_event("interactive_resolution", **response_payload)
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

    resolution_payload = {
        "request_id": request_id,
        "resolution": "timeout",
    }
    resolution_payload.update(timeout_result)
    emit_event("interactive_resolution", **resolution_payload)
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
