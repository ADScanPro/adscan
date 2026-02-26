"""Lightweight agent protocol for ADscan remote sessions.

This module defines a small binary framing protocol inspired by Penelope's
``Messenger`` abstraction, but implemented specifically for ADscan. It is
used to communicate with an optional remote agent over an existing TCP
``RemoteSession`` socket.

Design goals:

- Keep the protocol simple and robust.
- Support a minimal feature set initially (command execution, file upload/
  download) while remaining extensible.
- Avoid coupling to any specific remote implementation so the agent script
  can evolve independently.
"""

from __future__ import annotations

import struct
import threading
import time
from dataclasses import dataclass
from enum import IntEnum
from typing import Dict, Generator, Optional

import socket

from . import telemetry

import logging


logger = logging.getLogger("adscan.agent_protocol")


class MessageType(IntEnum):
    """Supported message types for the agent protocol."""

    SHELL = 1
    EXEC_REQUEST = 2
    EXEC_OUTPUT = 3
    EXEC_DONE = 4
    FILE_UPLOAD = 10
    FILE_UPLOAD_RESULT = 11
    FILE_DOWNLOAD_REQUEST = 12
    FILE_DOWNLOAD_CHUNK = 13
    FILE_DOWNLOAD_END = 14
    ERROR = 255


HEADER_STRUCT = struct.Struct("!HB")  # length (uint16), type (uint8)
MAX_PAYLOAD_SIZE = 65535  # Maximum payload per message (bytes)


def encode_message(msg_type: MessageType, payload: bytes) -> bytes:
    """Encode a message with a length + type header."""
    if len(payload) > MAX_PAYLOAD_SIZE:
        raise ValueError("Payload too large for agent message")
    # The length field encodes the payload size in bytes. The message on the
    # wire is: [length (2 bytes)][type (1 byte)][payload...].
    header = HEADER_STRUCT.pack(len(payload), int(msg_type))
    return header + payload


def feed_messages(
    buffer: bytearray,
) -> Generator[tuple[MessageType, bytes], None, None]:
    """Incrementally parse incoming bytes into protocol messages.

    This implementation avoids holding a persistent ``memoryview`` on
    ``buffer`` while resizing it, which can trigger ``BufferError`` on recent
    Python versions ("Existing exports of data: object cannot be re-sized").
    Given the relatively small maximum payload size, the overhead of slicing
    directly from the bytearray is acceptable and keeps the code simple.
    """
    offset = 0
    buf_len = len(buffer)

    while buf_len - offset >= HEADER_STRUCT.size:
        header_slice = buffer[offset : offset + HEADER_STRUCT.size]
        length, msg_type_raw = HEADER_STRUCT.unpack(header_slice)
        payload_len = int(length)
        total_len = HEADER_STRUCT.size + payload_len
        if buf_len - offset < total_len:
            break

        payload_start = offset + HEADER_STRUCT.size
        payload_end = payload_start + payload_len
        payload = bytes(buffer[payload_start:payload_end])

        try:
            msg_type = MessageType(msg_type_raw)
        except ValueError:
            msg_type = MessageType.ERROR

        yield msg_type, payload
        offset += total_len

    # Keep any leftover bytes that did not form a complete message.
    if offset:
        del buffer[:offset]


@dataclass
class AgentSession:
    """Client-side helper to talk to a remote agent over a socket."""

    sock: socket.socket

    def __post_init__(self) -> None:
        self._sock = self.sock
        self._sock.setblocking(False)
        self._recv_buffer = bytearray()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    # Low-level I/O
    # ------------------------------------------------------------------ #
    def _send_message(self, msg_type: MessageType, payload: bytes) -> None:
        data = encode_message(msg_type, payload)
        logger.debug(
            "[agent_protocol] sending message type=%s payload_len=%d total_len=%d",
            msg_type.name if isinstance(msg_type, MessageType) else msg_type,
            len(payload),
            len(data),
        )
        with self._lock:
            self._sock.sendall(data)

    def _recv_loop(
        self,
        expected_types: tuple[MessageType, ...],
        timeout: float | None = 10.0,
    ) -> Dict[MessageType, list[bytes]]:
        """Receive messages until timeout or no activity after first response.

        The agent protocol does not currently send an explicit "end of
        response" marker for EXEC/ERROR flows, so this helper uses a simple
        heuristic:

        - Read until at least one message of an expected type is seen.
        - After that, if the socket is idle for a short period, assume the
          response for this request is complete and return immediately.

        This avoids waiting for the full timeout on every command, which was
        making agent-backed commands feel very slow in interactive use.
        """
        import select
        import socket as _socket

        # Use monotonic clock for timeouts so they are not affected by
        # system clock adjustments while the agent is running.
        deadline = time.monotonic() + timeout if timeout is not None else None
        messages: Dict[MessageType, list[bytes]] = {t: [] for t in expected_types}
        idle_after_first = 0.5  # seconds of inactivity after first message
        seen_any = False
        last_activity = time.monotonic()

        while True:
            if deadline is not None and time.monotonic() > deadline:
                break
            try:
                rlist, _, _ = select.select([self._sock], [], [], 0.2)
            except (OSError, ValueError) as exc:
                telemetry.capture_exception(exc)
                break
            if not rlist:
                if seen_any and (time.monotonic() - last_activity) >= idle_after_first:
                    # We have at least one response and the socket has been
                    # idle for a short period; treat this as end of reply.
                    break
                continue
            try:
                chunk = self._sock.recv(4096)
            except _socket.error as exc:
                telemetry.capture_exception(exc)
                break
            if not chunk:
                break
            last_activity = time.monotonic()
            self._recv_buffer.extend(chunk)
            for msg_type, payload in feed_messages(self._recv_buffer):
                if msg_type in messages:
                    messages[msg_type].append(payload)
                    seen_any = True
        return messages

    # ------------------------------------------------------------------ #
    # High-level helpers
    # ------------------------------------------------------------------ #
    def _recv_exec(
        self,
        timeout: float | None = 30.0,
    ) -> Dict[MessageType, list[bytes]]:
        """Receive EXEC_OUTPUT / ERROR messages until EXEC_DONE or timeout.

        This specialised receiver is used for command execution responses so we
        no longer rely on timing heuristics (socket idle periods) to decide
        when a reply is complete. Instead, the agent is expected to send an
        explicit ``EXEC_DONE`` marker once all output for a given command has
        been sent.
        """
        import select
        import socket as _socket

        deadline = time.monotonic() + timeout if timeout is not None else None
        messages: Dict[MessageType, list[bytes]] = {
            MessageType.EXEC_OUTPUT: [],
            MessageType.ERROR: [],
            MessageType.EXEC_DONE: [],
        }
        done = False

        while not done:
            if deadline is not None and time.monotonic() > deadline:
                break
            try:
                rlist, _, _ = select.select([self._sock], [], [], 0.2)
            except (OSError, ValueError) as exc:
                telemetry.capture_exception(exc)
                break
            if not rlist:
                continue
            try:
                chunk = self._sock.recv(4096)
            except _socket.error as exc:
                telemetry.capture_exception(exc)
                break
            if not chunk:
                break
            logger.debug(
                "[agent_protocol] _recv_exec received %d bytes from socket",
                len(chunk),
            )
            self._recv_buffer.extend(chunk)
            for msg_type, payload in feed_messages(self._recv_buffer):
                logger.debug(
                    "[agent_protocol] parsed message type=%s len=%d",
                    msg_type.name if isinstance(msg_type, MessageType) else msg_type,
                    len(payload),
                )
                if msg_type in messages:
                    messages[msg_type].append(payload)
                if msg_type in (MessageType.EXEC_DONE, MessageType.ERROR):
                    done = True
        return messages

    def exec_command(self, command: str, timeout: float | None = 30.0) -> str:
        """Execute a command via the remote agent and return its output."""
        try:
            logger.debug("[agent_protocol] sending EXEC_REQUEST command=%r", command)
            self._send_message(MessageType.EXEC_REQUEST, command.encode("utf-8"))
            messages = self._recv_exec(timeout=timeout)
            if messages.get(MessageType.ERROR):
                return messages[MessageType.ERROR][-1].decode("utf-8", errors="ignore")
            output_chunks = messages.get(MessageType.EXEC_OUTPUT) or []
            return b"".join(output_chunks).decode("utf-8", errors="ignore")
        except Exception as exc:  # pragma: no cover - defensive
            telemetry.capture_exception(exc)
            return f"[agent exec error] {exc}"

    def upload_file(
        self,
        remote_path: str,
        data: bytes,
        timeout: float | None = 60.0,
    ) -> bool:
        """Upload file content to the remote agent."""
        import json

        try:
            meta = {"path": remote_path, "size": len(data)}
            meta_payload = json.dumps(meta).encode("utf-8")
            self._send_message(MessageType.FILE_UPLOAD, meta_payload + b"\n" + data)
            messages = self._recv_loop(
                expected_types=(MessageType.FILE_UPLOAD_RESULT, MessageType.ERROR),
                timeout=timeout,
            )
            if messages.get(MessageType.ERROR):
                return False
            return bool(messages.get(MessageType.FILE_UPLOAD_RESULT))
        except Exception as exc:  # pragma: no cover - defensive
            telemetry.capture_exception(exc)
            return False

    def download_file(
        self,
        remote_path: str,
        timeout: float | None = 60.0,
    ) -> Optional[bytes]:
        """Request a file from the remote agent."""
        try:
            self._send_message(
                MessageType.FILE_DOWNLOAD_REQUEST, remote_path.encode("utf-8")
            )
            messages = self._recv_loop(
                expected_types=(
                    MessageType.FILE_DOWNLOAD_CHUNK,
                    MessageType.FILE_DOWNLOAD_END,
                    MessageType.ERROR,
                ),
                timeout=timeout,
            )
            if messages.get(MessageType.ERROR):
                return None
            chunks = messages.get(MessageType.FILE_DOWNLOAD_CHUNK) or []
            if not messages.get(MessageType.FILE_DOWNLOAD_END):
                # No explicit end marker, return whatever we got.
                if not chunks:
                    return None
            return b"".join(chunks)
        except Exception as exc:  # pragma: no cover - defensive
            telemetry.capture_exception(exc)
            return None
