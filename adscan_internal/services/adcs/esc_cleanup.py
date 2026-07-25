"""Rollback context manager and ledger helpers for ESC exploitation."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Any, Callable, Optional

from adscan_internal import telemetry
from adscan_internal.rich_output import print_error
from adscan_core.rich_output import print_exception


class RollbackQueue:
    """Ordered queue of rollback callables — executes in reverse (LIFO)."""

    def __init__(self) -> None:
        self._fns: list[Callable] = []

    def add(self, fn: Callable) -> None:
        self._fns.append(fn)

    async def run_all(self) -> list[str]:
        errors: list[str] = []
        for fn in reversed(self._fns):
            try:
                result = fn()
                if asyncio.iscoroutine(result):
                    await result
            except Exception as exc:
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                errors.append(str(exc))
        return errors


@asynccontextmanager
async def esc_rollback_scope():
    """Async context manager: runs registered rollbacks in LIFO order on exception."""
    rb = RollbackQueue()
    try:
        yield rb
    except Exception:
        errors = await rb.run_all()
        if errors:
            print_error(f"Rollback errors: {'; '.join(errors)}")
        raise


def register_ldap_change(
    shell: Any,
    *,
    kind: str,
    domain: str,
    target: str,
    detail: dict[str, Any],
    method: str,
) -> Optional[str]:
    """Register a destructive change to the environment ledger. Returns change_id."""
    ledger = getattr(shell, "environment_change_ledger", None)
    if ledger is None:
        return None
    try:
        return ledger.register_change(
            kind=kind, domain=domain, target=target, detail=detail, method=method
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


def mark_reverted(shell: Any, change_id: Optional[str]) -> None:
    if not change_id:
        return
    ledger = getattr(shell, "environment_change_ledger", None)
    if ledger:
        try:
            ledger.mark_reverted(change_id)
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)


def mark_revert_failed(
    shell: Any, change_id: Optional[str], *, error: str, instructions: str
) -> None:
    if not change_id:
        return
    ledger = getattr(shell, "environment_change_ledger", None)
    if ledger:
        try:
            ledger.mark_failed(change_id, error=error, manual_cleanup_instructions=instructions)
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
