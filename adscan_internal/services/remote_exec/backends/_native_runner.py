"""Shared helpers for the native ``remote_exec`` backends.

All four backends (SMBEXEC, ATEXEC, WMIEXEC, DCOMEXEC) drive an
:class:`aiosmb.commons.interfaces.machine.SMBMachine` opened through
:func:`smb_machine_with_fallback` so NTLM↔Kerberos fallback is uniform.

The helpers here translate aiosmb's ``(value, err)`` return shape to
:class:`RemoteExecResult` and raise :class:`AuthError` on credential
rejection so the cascade aborts cleanly.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, AsyncIterator, Tuple

from adscan_internal import telemetry
from adscan_internal.services.remote_exec.backends._common import (
    classify_native_exec_error,
)
from adscan_internal.services.remote_exec.models import (
    AuthError,
    ExecMethod,
    MethodFailure,
    RemoteExecResult,
)
from adscan_internal.services.smb_transport import (
    SMBAccessDeniedError,
    SMBAuthError,
    SMBConfig,
    SMBTransportError,
    smb_machine_with_fallback,
)
from adscan_core.rich_output import print_exception


def _failure(
    method: ExecMethod, kind: str, message: str, *, started: float
) -> RemoteExecResult:
    """Build a single-failure :class:`RemoteExecResult`."""
    return RemoteExecResult(
        success=False,
        method=method,
        captures_stdout=method in {ExecMethod.SMBEXEC, ExecMethod.ATEXEC},
        elapsed_ms=int((time.monotonic() - started) * 1000),
        errors=(MethodFailure(method=method, error_kind=kind, message=message),),  # type: ignore[arg-type]
    )


def _raise_auth_or_return(
    err: Exception | str, method: ExecMethod, *, started: float
) -> RemoteExecResult:
    """Classify ``err`` and either raise :class:`AuthError` or build a failure result."""
    text = str(err)
    kind, message = classify_native_exec_error(text)
    if kind == "auth":
        raise AuthError(message)
    return _failure(method, kind, message, started=started)


async def run_streaming(
    config: SMBConfig,
    method: ExecMethod,
    open_stream,
    *,
    timeout: int,
    max_bytes: int = 1 << 20,
) -> RemoteExecResult:
    """Drive a stdout-streaming aiosmb primitive (SMBEXEC, ATEXEC).

    Args:
        config: Authenticated SMB config (NTLM↔Kerberos fallback applied).
        method: The :class:`ExecMethod` this backend reports.
        open_stream: Callable ``(machine) -> AsyncIterator[(bytes, err)]``
            that opens the actual aiosmb generator.
        timeout: Per-call wall-clock cap.
        max_bytes: Hard cap on captured stdout to avoid runaway buffers.

    Returns:
        :class:`RemoteExecResult` with ``captures_stdout=True``.

    Raises:
        AuthError: Credentials were rejected.
    """
    started = time.monotonic()
    chunks: list[bytes] = []
    total = 0
    try:
        async with smb_machine_with_fallback(config) as machine:
            gen: AsyncIterator[Tuple[bytes, Exception | None]] = open_stream(machine)
            async for chunk, err in gen:
                if err is not None:
                    return _raise_auth_or_return(err, method, started=started)
                if not chunk:
                    continue
                if total + len(chunk) > max_bytes:
                    chunks.append(chunk[: max_bytes - total])
                    break
                chunks.append(chunk)
                total += len(chunk)
    except SMBAuthError as exc:
        raise AuthError(str(exc)) from exc
    except SMBAccessDeniedError as exc:
        return _failure(method, "access_denied", str(exc)[:240], started=started)
    except SMBTransportError as exc:
        return _failure(method, "network", str(exc)[:240], started=started)
    except asyncio.TimeoutError as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return _failure(
            method, "timeout", f"backend timed out after {timeout}s", started=started
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return _raise_auth_or_return(exc, method, started=started)

    stdout = b"".join(chunks).decode("utf-8", errors="replace").strip()
    return RemoteExecResult(
        success=True,
        method=method,
        stdout=stdout,
        captures_stdout=True,
        elapsed_ms=int((time.monotonic() - started) * 1000),
    )


async def run_blind(
    config: SMBConfig,
    method: ExecMethod,
    invoke,
    *,
    timeout: int,
) -> RemoteExecResult:
    """Drive a blind aiosmb exec primitive (WMI, DCOM siblings).

    Args:
        config: Authenticated SMB config.
        method: Which :class:`ExecMethod` this backend reports.
        invoke: Coroutine factory ``(machine) -> Awaitable[(success, err)]``
            or ``(machine) -> Awaitable[(rc, pid, err)]``. Distinguishes
            between the two shapes by tuple length at runtime.
        timeout: Per-call wall-clock cap.

    Returns:
        :class:`RemoteExecResult` with ``captures_stdout=False``.

    Raises:
        AuthError: Credentials were rejected.
    """
    started = time.monotonic()
    rc: int | None = None
    pid: int | None = None
    err: Any = None
    try:
        async with smb_machine_with_fallback(config) as machine:
            outcome = await asyncio.wait_for(invoke(machine), timeout=timeout)
            if not isinstance(outcome, tuple):
                return _failure(
                    method, "other", "backend returned malformed value", started=started
                )
            if len(outcome) == 3:
                rc, pid, err = outcome
            elif len(outcome) == 2:
                success_flag, err = outcome
                rc = 0 if success_flag and err is None else 1
            else:
                return _failure(
                    method,
                    "other",
                    "backend returned unexpected tuple shape",
                    started=started,
                )
    except SMBAuthError as exc:
        raise AuthError(str(exc)) from exc
    except SMBAccessDeniedError as exc:
        return _failure(method, "access_denied", str(exc)[:240], started=started)
    except SMBTransportError as exc:
        return _failure(method, "network", str(exc)[:240], started=started)
    except asyncio.TimeoutError as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return _failure(
            method, "timeout", f"backend timed out after {timeout}s", started=started
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return _raise_auth_or_return(exc, method, started=started)

    if err is not None:
        return _raise_auth_or_return(err, method, started=started)

    return RemoteExecResult(
        success=True,
        method=method,
        stdout="",
        captures_stdout=False,
        return_code=int(rc) if rc is not None else None,
        process_id=int(pid) if pid is not None else None,
        elapsed_ms=int((time.monotonic() - started) * 1000),
    )


__all__ = ["run_streaming", "run_blind"]
