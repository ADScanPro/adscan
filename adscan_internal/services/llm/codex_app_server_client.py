"""Codex app-server JSON-RPC client used for ChatGPT Plus/Pro integration.

This transport keeps one persistent `codex app-server` subprocess and sends
JSON-RPC requests over stdio. It avoids per-prompt `codex exec` wrappers and
matches Roo-style "client -> Codex service" behavior more closely.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable
import json
import math
import os
import select
import subprocess
import threading
import time


class CodexAppServerError(RuntimeError):
    """Raised when Codex app-server transport fails."""


@dataclass(slots=True)
class CodexTurnResult:
    """Result payload returned by one turn in Codex app-server."""

    text: str
    status: str
    raw_turn: dict[str, Any]


class CodexAppServerClient:
    """Minimal JSON-RPC client for `codex app-server` over stdio."""

    def __init__(
        self,
        *,
        command: list[str] | None = None,
        startup_timeout_seconds: int = 15,
        turn_timeout_seconds: int = 180,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        trace: Callable[[str], None] | None = None,
    ) -> None:
        self._command = command or ["codex", "app-server"]
        self._startup_timeout_seconds = max(5, startup_timeout_seconds)
        self._turn_timeout_seconds = max(15, turn_timeout_seconds)
        self._cwd = cwd
        self._env = dict(env) if env is not None else None
        self._trace = trace

        self._process: subprocess.Popen[bytes] | None = None
        self._initialized = False
        self._thread_id: str | None = None
        self._thread_model: str | None = None
        self._thread_reasoning_effort: str | None = None
        self._thread_model_provider: str | None = None
        self._request_id = 0
        self._lock = threading.RLock()
        self._last_transport_line = ""
        self._stdout_buffer = b""

    def close(self) -> None:
        """Stop app-server process and clear session state."""
        with self._lock:
            self._thread_id = None
            self._thread_model = None
            self._thread_reasoning_effort = None
            self._thread_model_provider = None
            self._initialized = False
            process = self._process
            self._process = None

            if process is None:
                return
            if process.poll() is not None:
                return

            self._trace_event("Stopping codex app-server process.")
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)

    def ask(
        self,
        *,
        prompt: str,
        model: str | None = None,
        timeout_seconds: int | None = None,
    ) -> CodexTurnResult:
        """Run one user prompt through Codex app-server and return final text."""
        timeout = max(15, timeout_seconds or self._turn_timeout_seconds)
        deadline = time.monotonic() + timeout
        with self._lock:
            startup_budget = min(
                self._startup_timeout_seconds,
                self._remaining_timeout_seconds(deadline),
            )
            self._trace_event(f"Phase initialize (timeout={startup_budget}s).")
            self._ensure_started(timeout_seconds=startup_budget)
            thread_budget = min(
                self._startup_timeout_seconds,
                self._remaining_timeout_seconds(deadline),
            )
            self._trace_event(f"Phase thread/start (timeout={thread_budget}s).")
            self._ensure_thread_started(
                model=model,
                timeout_seconds=thread_budget,
            )
            assert self._thread_id is not None

            turn_start_budget = self._remaining_timeout_seconds(deadline)
            self._trace_event(f"Phase turn/start (timeout={turn_start_budget}s).")
            turn_response = self._request(
                method="turn/start",
                params={
                    "threadId": self._thread_id,
                    "input": [{"type": "text", "text": prompt}],
                    "cwd": None,
                    "approvalPolicy": "never",
                    "sandboxPolicy": {"type": "readOnly"},
                    "model": self._resolve_model_override(model),
                    "effort": None,
                    "summary": None,
                    "outputSchema": None,
                },
                timeout_seconds=turn_start_budget,
            )

            turn = turn_response.get("turn", {})
            turn_id = str(turn.get("id", "")).strip()
            if not turn_id:
                raise CodexAppServerError(
                    "Codex app-server did not return a valid turn id."
                )

            completion_budget = self._remaining_timeout_seconds(deadline)
            self._trace_event(
                f"Phase turn/completed wait (timeout={completion_budget}s)."
            )
            return self._wait_for_turn_completion(
                thread_id=self._thread_id,
                turn_id=turn_id,
                timeout_seconds=completion_budget,
            )

    def _ensure_started(self, *, timeout_seconds: int | None = None) -> None:
        """Start subprocess and run JSON-RPC initialize handshake."""
        if (
            self._process is not None
            and self._process.poll() is None
            and self._initialized
        ):
            return

        self.close()
        self._trace_event(
            f"Starting codex app-server process: {self._command} (cwd={self._cwd or '.'})"
        )
        self._process = subprocess.Popen(
            self._command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=False,
            bufsize=0,
            cwd=self._cwd,
            env=self._env,
        )
        self._stdout_buffer = b""

        self._trace_event("Sending initialize request.")
        init_response = self._request(
            method="initialize",
            params={
                "clientInfo": {
                    "name": "adscan",
                    "version": "1.0.0",
                }
            },
            timeout_seconds=timeout_seconds or self._startup_timeout_seconds,
        )
        user_agent = str(init_response.get("userAgent", "")).strip()
        if not user_agent:
            raise CodexAppServerError(
                "Codex app-server initialize response is missing userAgent."
            )
        self._trace_event(f"Initialize completed (userAgent={user_agent}).")

        # Complete JSON-RPC lifecycle handshake expected by app-server.
        # This is a notification (no id), not a request/response round-trip.
        self._trace_event("Sending initialized notification.")
        self._write_message({"method": "initialized", "params": {}})

        self._initialized = True
        self._thread_id = None
        self._thread_model = None
        self._thread_reasoning_effort = None
        self._thread_model_provider = None

    def _ensure_thread_started(
        self,
        *,
        model: str | None,
        timeout_seconds: int | None = None,
    ) -> None:
        """Create a thread if this session does not have one yet."""
        if self._thread_id:
            return

        self._trace_event("Sending thread/start request.")
        response = self._request(
            method="thread/start",
            params={
                "model": self._resolve_model_override(model),
                "modelProvider": None,
                "cwd": None,
                "approvalPolicy": "never",
                "sandbox": "read-only",
                "config": None,
                "baseInstructions": None,
                "developerInstructions": (
                    "You are ADscan assistant. "
                    "Never execute shell commands or perform file modifications."
                ),
                "experimentalRawEvents": False,
            },
            timeout_seconds=timeout_seconds or self._startup_timeout_seconds,
        )
        thread = response.get("thread", {})
        thread_id = str(thread.get("id", "")).strip()
        if not thread_id:
            raise CodexAppServerError("Codex app-server did not return a thread id.")
        self._thread_id = thread_id
        model_name = response.get("model")
        if isinstance(model_name, str):
            self._thread_model = model_name.strip() or None
        effort = response.get("reasoningEffort")
        if isinstance(effort, str):
            self._thread_reasoning_effort = effort.strip() or None
        provider = response.get("modelProvider")
        if isinstance(provider, str):
            self._thread_model_provider = provider.strip() or None
        self._trace_event(f"Thread started (thread_id={thread_id}).")

    def _request(
        self,
        *,
        method: str,
        params: dict[str, Any] | None,
        timeout_seconds: int,
    ) -> dict[str, Any]:
        """Send one JSON-RPC request and wait for its response."""
        self._request_id += 1
        request_id = self._request_id

        payload: dict[str, Any] = {"id": request_id, "method": method}
        payload["params"] = params if params is not None else {}
        self._trace_event(
            f"Sending JSON-RPC request id={request_id} method={method} timeout={timeout_seconds}s."
        )
        self._write_message(payload)

        deadline = time.monotonic() + timeout_seconds
        while True:
            message = self._read_message_until(deadline=deadline)
            if message is None:
                raise CodexAppServerError(
                    f"Timeout waiting response for method '{method}'. "
                    f"Last transport line: {self._format_last_transport_line()}"
                )

            if self._is_server_request(message):
                self._handle_server_request(message)
                continue

            if message.get("id") != request_id:
                continue

            if "error" in message:
                raise CodexAppServerError(
                    f"Codex app-server request failed for '{method}': {message['error']}"
                )
            result = message.get("result")
            if not isinstance(result, dict):
                return {}
            self._trace_event(
                f"Received JSON-RPC response id={request_id} method={method}."
            )
            return result

    def _wait_for_turn_completion(
        self,
        *,
        thread_id: str,
        turn_id: str,
        timeout_seconds: int,
    ) -> CodexTurnResult:
        """Read server notifications until turn completion and return output text."""
        deadline = time.monotonic() + timeout_seconds
        chunks: list[str] = []
        stream_error_count = 0

        while True:
            message = self._read_message_until(deadline=deadline)
            if message is None:
                partial = "".join(chunks).strip()
                if partial:
                    self._trace_event(
                        "Turn completion timed out; returning partial assistant output."
                    )
                    return CodexTurnResult(
                        text=self._clip_partial_output(partial),
                        status="partial_timeout",
                        raw_turn={
                            "id": turn_id,
                            "status": "partial_timeout",
                            "timeout_seconds": timeout_seconds,
                        },
                    )
                raise CodexAppServerError(
                    "Timeout waiting for turn completion. "
                    f"Last transport line: {self._format_last_transport_line()}"
                )

            if self._is_server_request(message):
                method_name = str(message.get("method", ""))
                self._trace_event(f"Received server request method={method_name}.")
                self._handle_server_request(message)
                continue

            method = str(message.get("method", ""))
            params = message.get("params", {})
            if not isinstance(params, dict):
                continue

            codex_event = self._extract_codex_event_message(method=method, params=params)
            if codex_event is not None:
                if not self._event_matches_turn(
                    event=codex_event,
                    thread_id=thread_id,
                    turn_id=turn_id,
                ):
                    continue
                event_type = str(codex_event.get("type", "")).strip().lower()
                if event_type == "stream_error":
                    stream_error_count += 1
                    details = (
                        str(codex_event.get("additional_details", "")).strip()
                        or str(codex_event.get("message", "")).strip()
                        or "unknown stream error"
                    )
                    self._trace_event(
                        f"Received stream_error event #{stream_error_count}: {details}"
                    )
                    if self._is_fatal_stream_error(details):
                        raise CodexAppServerError(f"Codex stream error: {details}")
                    if stream_error_count >= 5:
                        raise CodexAppServerError(
                            f"Codex stream error after retries: {details}"
                        )
                    continue
                if event_type in {"agent_message_delta", "agent_message_content_delta"}:
                    delta = codex_event.get("delta")
                    if isinstance(delta, str) and delta:
                        chunks.append(delta)
                    continue
                if event_type in {"task_complete", "turn_complete"}:
                    # Prefer final event payload when present; streamed deltas can
                    # include retransmissions/retries and produce duplicated text.
                    text = self._extract_text_from_codex_event(codex_event)
                    if not text:
                        text = "".join(chunks).strip()
                    if not text:
                        raise CodexAppServerError(
                            "Codex app-server completed turn without text output."
                        )
                    return CodexTurnResult(
                        text=text,
                        status="completed",
                        raw_turn={"id": turn_id, "status": "completed", "event": codex_event},
                    )

            if method == "item/agentMessage/delta":
                if (
                    params.get("threadId") == thread_id
                    and params.get("turnId") == turn_id
                ):
                    delta = params.get("delta")
                    if isinstance(delta, str) and delta:
                        chunks.append(delta)
                continue

            if method == "turn/completed":
                turn = params.get("turn", {})
                if not isinstance(turn, dict):
                    raise CodexAppServerError(
                        "Codex app-server returned invalid turn payload."
                    )
                completed_turn_id = str(turn.get("id", "")).strip()
                if completed_turn_id and completed_turn_id != turn_id:
                    continue

                status = str(turn.get("status", ""))
                if status != "completed":
                    error = turn.get("error")
                    raise CodexAppServerError(
                        f"Codex turn failed with status '{status}': {error}"
                    )

                text = "".join(chunks).strip()
                if not text:
                    text = self._extract_text_from_turn_items(turn.get("items", []))
                if not text:
                    raise CodexAppServerError(
                        "Codex app-server completed turn without text output."
                    )

                return CodexTurnResult(text=text, status=status, raw_turn=turn)

    def _extract_text_from_turn_items(self, items: Any) -> str:
        """Extract assistant text from completed turn items when no deltas arrive."""
        if not isinstance(items, list):
            return ""

        chunks: list[str] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            item_type = str(item.get("type", "")).lower()
            if item_type not in {"agentmessage", "agent_message"}:
                continue
            content = item.get("content")
            if not isinstance(content, list):
                continue
            for part in content:
                if not isinstance(part, dict):
                    continue
                text = part.get("text")
                if isinstance(text, str) and text:
                    chunks.append(text)
        return "".join(chunks).strip()

    @staticmethod
    def _clip_partial_output(text: str) -> str:
        """Clip partial timeout output to a safe terminal-friendly size."""
        max_chars = 4000
        if len(text) <= max_chars:
            return text
        return f"{text[:max_chars].rstrip()}..."

    def _is_server_request(self, message: dict[str, Any]) -> bool:
        """Return whether message is a server-initiated JSON-RPC request."""
        return (
            "id" in message
            and "method" in message
            and "result" not in message
            and "error" not in message
        )

    def _handle_server_request(self, message: dict[str, Any]) -> None:
        """Answer approval-type server requests conservatively (deny by default)."""
        request_id = message.get("id")
        method = str(message.get("method", ""))

        if method in {"item/commandExecution/requestApproval"}:
            self._write_message({"id": request_id, "result": {"decision": "decline"}})
            return
        if method in {"item/fileChange/requestApproval"}:
            self._write_message({"id": request_id, "result": {"decision": "decline"}})
            return
        if method == "execCommandApproval":
            self._write_message({"id": request_id, "result": {"decision": "denied"}})
            return
        if method == "applyPatchApproval":
            self._write_message({"id": request_id, "result": {"decision": "denied"}})
            return

        self._write_message(
            {
                "id": request_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not supported by ADscan client: {method}",
                },
            }
        )

    def _write_message(self, payload: dict[str, Any]) -> None:
        """Write one JSON message to app-server stdin."""
        process = self._get_process()
        # Pylint can infer a dummy process proxy for subprocess.Popen in some
        # environments; runtime objects expose stdin as expected.
        if process.stdin is None:  # pylint: disable=no-member
            raise CodexAppServerError("Codex app-server stdin is unavailable.")
        encoded = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
        process.stdin.write(encoded)  # pylint: disable=no-member
        process.stdin.flush()  # pylint: disable=no-member

    def _read_message_until(self, *, deadline: float) -> dict[str, Any] | None:
        """Read one JSON message from stdout before deadline."""
        process = self._get_process()
        stdout = process.stdout
        if stdout is None:
            raise CodexAppServerError("Codex app-server streams are unavailable.")
        fd = stdout.fileno()

        while time.monotonic() < deadline:
            buffered = self._pop_message_from_buffer()
            if buffered is not None:
                return buffered

            remaining = max(0.0, deadline - time.monotonic())
            ready, _, _ = select.select([fd], [], [], min(0.5, remaining))
            if not ready:
                continue

            try:
                chunk = os.read(fd, 65536)
            except BlockingIOError:
                continue
            if not chunk:
                if process.poll() is not None:
                    return None
                continue

            self._stdout_buffer += chunk
            buffered = self._pop_message_from_buffer()
            if buffered is not None:
                return buffered

        return self._pop_message_from_buffer()

    def _pop_message_from_buffer(self) -> dict[str, Any] | None:
        """Parse and pop next JSON object line from internal stdout buffer."""
        while b"\n" in self._stdout_buffer:
            raw_line, self._stdout_buffer = self._stdout_buffer.split(b"\n", 1)
            stripped = raw_line.strip()
            if not stripped:
                continue
            decoded = stripped.decode("utf-8", errors="replace")
            self._last_transport_line = decoded
            try:
                parsed = json.loads(decoded)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                return parsed
        return None

    def get_runtime_info(self, *, timeout_seconds: int = 8) -> dict[str, Any]:
        """Return best-effort account/rate-limit and session info from app-server."""
        with self._lock:
            session_info = {
                "model": self._thread_model,
                "reasoning_effort": self._thread_reasoning_effort,
                "model_provider": self._thread_model_provider,
                "thread_id": self._thread_id,
            }

            try:
                self._ensure_started(
                    timeout_seconds=min(
                        max(5, timeout_seconds), self._startup_timeout_seconds
                    )
                )
            except Exception:
                return session_info

            account_plan: str | None = None
            try:
                account_result = self._request(
                    method="account/read",
                    params={"refreshToken": False},
                    timeout_seconds=max(5, timeout_seconds),
                )
                account = account_result.get("account")
                if isinstance(account, dict):
                    plan = account.get("planType")
                    if isinstance(plan, str):
                        account_plan = plan
            except Exception:
                account_plan = None

            rate_limits: dict[str, Any] | None = None
            try:
                limits_result = self._request(
                    method="account/rateLimits/read",
                    params={},
                    timeout_seconds=max(5, timeout_seconds),
                )
                primary = limits_result.get("rateLimits")
                if isinstance(primary, dict):
                    rate_limits = primary
                by_id = limits_result.get("rateLimitsByLimitId")
                if rate_limits is None and isinstance(by_id, dict) and by_id:
                    first_value = next(iter(by_id.values()))
                    if isinstance(first_value, dict):
                        rate_limits = first_value
            except Exception:
                rate_limits = None

            return {
                **session_info,
                "account_plan": account_plan,
                "rate_limits": rate_limits,
            }

    def _get_process(self) -> subprocess.Popen[bytes]:
        """Return running process or raise if unavailable."""
        if self._process is None:
            raise CodexAppServerError("Codex app-server process is not started.")
        if self._process.poll() is not None:
            code = self._process.returncode
            raise CodexAppServerError(
                "Codex app-server process exited unexpectedly "
                f"(code={code}). Last transport line: {self._format_last_transport_line()}"
            )
        return self._process

    def _format_last_transport_line(self) -> str:
        """Return compact last-seen transport line for diagnostics."""
        if not self._last_transport_line:
            return "<none>"
        max_chars = 300
        line = self._last_transport_line
        if len(line) <= max_chars:
            return line
        return f"{line[:max_chars]}..."

    def _event_matches_turn(
        self,
        *,
        event: dict[str, Any],
        thread_id: str,
        turn_id: str,
    ) -> bool:
        """Return whether an event belongs to the active turn context."""
        event_thread = str(
            event.get("thread_id") or event.get("threadId") or ""
        ).strip()
        if event_thread and event_thread != thread_id:
            return False
        event_turn = str(event.get("turn_id") or event.get("turnId") or "").strip()
        if event_turn and event_turn != turn_id:
            return False
        return True

    def _extract_text_from_codex_event(self, event: dict[str, Any]) -> str:
        """Extract assistant text from codex/event payload."""
        for key in (
            "last_agent_message",
            "message",
            "text",
            "output",
            "output_text",
            "final_output",
            "assistant_response",
        ):
            value = event.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

        item = event.get("item")
        if isinstance(item, dict):
            nested = self._extract_text_from_turn_items([item])
            if nested:
                return nested

        return ""

    @staticmethod
    def _extract_codex_event_message(
        *,
        method: str,
        params: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Extract codex event message dict from v1/v2 notification forms."""
        if method == "codex/event":
            msg = params.get("msg")
            if isinstance(msg, dict):
                return msg
            return None
        if method.startswith("codex/event/"):
            event_type = method.split("codex/event/", 1)[1]
            payload: dict[str, Any] = {"type": event_type}
            msg = params.get("msg")
            if isinstance(msg, dict):
                payload.update(msg)
            else:
                payload.update(params)
            return payload
        return None

    @staticmethod
    def _is_fatal_stream_error(details: str) -> bool:
        """Return whether stream error should abort turn immediately."""
        lowered = details.lower()
        fatal_markers = (
            "does not exist",
            "do not have access",
            "permission denied",
            "invalid model",
            "not available for your account",
            "unauthorized",
            "forbidden",
            "authentication",
            "invalid api key",
        )
        return any(marker in lowered for marker in fatal_markers)

    def _trace_event(self, message: str) -> None:
        """Emit optional client trace events."""
        if self._trace is None:
            return
        try:
            self._trace(message)
        except Exception:
            return

    @staticmethod
    def _remaining_timeout_seconds(deadline: float) -> int:
        """Return remaining timeout budget in seconds for the current ask turn."""
        remaining = math.ceil(deadline - time.monotonic())
        if remaining <= 0:
            raise CodexAppServerError("Timeout budget exhausted for codex app-server ask.")
        return remaining

    @staticmethod
    def _resolve_model_override(model: str | None) -> str | None:
        """Return explicit model override or `None` for provider default."""
        if model is None:
            return None
        candidate = model.strip()
        if not candidate:
            return None
        if candidate.lower() in {"default", "codex", "auto"}:
            return None
        return candidate

    def __enter__(self) -> CodexAppServerClient:
        """Context manager enter."""
        return self

    def __exit__(
        self,
        _exc_type: Any,
        _exc: Any,
        _tb: Any,
    ) -> None:
        """Context manager exit."""
        self.close()
