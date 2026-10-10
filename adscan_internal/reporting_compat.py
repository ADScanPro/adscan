"""Compatibility helpers for optional reporting/PRO integrations."""

from __future__ import annotations

from collections.abc import Callable
from importlib import import_module
from types import ModuleType
from typing import TypeVar

T = TypeVar("T")


def is_optional_pro_import_error(
    exc: Exception,
    *,
    allowed_missing_modules: tuple[str, ...] = (),
) -> bool:
    """Return whether ``exc`` is an expected optional ``/pro`` import failure."""
    if not isinstance(exc, ModuleNotFoundError):
        return False

    missing_module = str(getattr(exc, "name", "") or "").strip()
    if missing_module in allowed_missing_modules:
        return True
    if missing_module == "adscan_internal.pro" or missing_module.startswith(
        "adscan_internal.pro."
    ):
        return True

    error_message = str(exc)
    return any(module_name in error_message for module_name in allowed_missing_modules) or (
        "adscan_internal.pro." in error_message
    )


def handle_optional_pro_import_exception(
    exc: Exception,
    *,
    action: str,
    debug_printer: Callable[[str], None],
    prefix: str = "[pro]",
    allowed_missing_modules: tuple[str, ...] = (),
) -> bool:
    """Log and suppress expected optional ``/pro`` import failures in LITE builds."""
    if not is_optional_pro_import_error(
        exc,
        allowed_missing_modules=allowed_missing_modules,
    ):
        return False

    debug_printer(
        f"{prefix} {action} unavailable in this build; "
        f"skipping legacy sync ({type(exc).__name__})."
    )
    return True


def import_optional_pro_module(
    module_name: str,
    *,
    action: str,
    debug_printer: Callable[[str], None],
    prefix: str = "[pro]",
) -> ModuleType | None:
    """Import an optional ``/pro`` module, returning ``None`` in LITE builds."""
    try:
        return import_module(module_name)
    except ImportError as exc:
        if handle_optional_pro_import_exception(
            exc,
            action=action,
            debug_printer=debug_printer,
            prefix=prefix,
            allowed_missing_modules=(module_name,),
        ):
            return None
        raise


def load_optional_pro_attr(
    module_name: str,
    attr_name: str,
    *,
    action: str,
    debug_printer: Callable[[str], None],
    prefix: str = "[pro]",
) -> T | None:
    """Load an attribute from an optional ``/pro`` module."""
    module = import_optional_pro_module(
        module_name,
        action=action,
        debug_printer=debug_printer,
        prefix=prefix,
    )
    if module is None:
        return None
    return getattr(module, attr_name, None)


def is_optional_report_service_import_error(exc: Exception) -> bool:
    """Return whether ``exc`` is the expected report-service import failure."""
    return is_optional_pro_import_error(
        exc,
        allowed_missing_modules=(
            "adscan_internal.services.report_service",
            "adscan_internal.pro.services",
            "adscan_internal.pro.services.report_service",
        ),
    )


def handle_optional_report_service_exception(
    exc: Exception,
    *,
    action: str,
    debug_printer: Callable[[str], None],
    prefix: str = "[report]",
) -> bool:
    """Log and suppress expected report-service import failures in LITE builds.

    Call this only where the suppressed import really is the end of the road.
    It announces the failure, so a caller that has a working fallback must not
    route through it: the announcement would then describe a skip that does not
    happen. :func:`load_optional_report_service_attr` is the entry point for
    that case, and it logs after the fallback has been consulted.

    Several ``except Exception`` blocks across the CLI open with this call while
    their body imports from ``adscan_core`` only. That branch cannot fire on the
    import itself and therefore prints nothing; it is kept because the guard
    still suppresses an optional-PRO ``ModuleNotFoundError`` raised anywhere
    beneath the body, and because a body that later grows a PRO import would
    need it back.
    """
    return handle_optional_pro_import_exception(
        exc,
        action=action,
        debug_printer=debug_printer,
        prefix=prefix,
        allowed_missing_modules=(
            "adscan_internal.services.report_service",
            "adscan_internal.pro.services",
            "adscan_internal.pro.services.report_service",
        ),
    )


def try_import_report_service_module(
    module_name: str = "adscan_internal.services.report_service",
) -> tuple[ModuleType | None, Exception | None]:
    """Attempt the report-service import without announcing anything.

    Returns ``(module, None)`` when the import succeeds and ``(None, exc)`` when
    it failed the way a LITE build is expected to fail. An unexpected
    ``ImportError`` propagates, exactly as the announcing wrappers let it.

    This exists so the decision to announce a failure is taken where the outcome
    is known. An import helper cannot make that call: at the point the import
    fails it does not yet know whether its caller has a fallback, so announcing
    there is how a message ends up describing a skip that never happened.
    """
    try:
        return import_module(module_name), None
    except ImportError as exc:
        if is_optional_report_service_import_error(exc):
            return None, exc
        raise


def import_optional_report_service_module(
    module_name: str = "adscan_internal.services.report_service",
    *,
    action: str,
    debug_printer: Callable[[str], None],
    prefix: str = "[report]",
) -> ModuleType | None:
    """Import an optional report-service module, returning ``None`` in LITE builds.

    Announces the failure, so ``None`` from here is reported to the operator as
    a real loss of capability. Use it only when the caller has no fallback;
    otherwise use :func:`load_optional_report_service_attr`.
    """
    module, import_error = try_import_report_service_module(module_name)
    if import_error is not None:
        handle_optional_report_service_exception(
            import_error,
            action=action,
            debug_printer=debug_printer,
            prefix=prefix,
        )
    return module


# Write primitives that were relocated to ``adscan_core`` so they survive the
# LITE image strip (the PRO report service and its shim are removed from LITE).
# When the stripped module is absent, these attrs are resolved from the core
# module instead — that is what makes the LITE technical_report.json populate.
_CORE_REPORT_ATTRS: frozenset[str] = frozenset(
    {
        "record_technical_finding",
        "retract_technical_finding",
        "record_technical_event",
        "record_control_evidence",
        "record_exposure_score",
        "initialize_technical_report",
        "TECHNICAL_REPORT_FILENAME",
        "TECHNICAL_REPORT_SCHEMA_VERSION",
    }
)


_CORE_FALLBACK_NOTICE = (
    "Technical report recorders resolved from the shared writer in "
    "adscan_core; the PRO report service is not part of this build. "
    "Records are written normally."
)

# One notice per process, not one per call. Seven call sites resolve a recorder
# repeatedly during a scan, and a per-call line is what previously made a
# routine fallback read like a recurring failure.
_core_fallback_notice_emitted = False


def load_optional_report_service_attr(
    attr_name: str,
    *,
    action: str,
    debug_printer: Callable[[str], None],
    prefix: str = "[report]",
    module_name: str = "adscan_internal.services.report_service",
) -> T | None:
    """Load an attribute from an optional report-service module.

    Recorders relocated to ``adscan_core.reporting.technical_report`` are
    resolved from the core module when the PRO report service is stripped from
    the LITE image, so the writer no longer no-ops in LITE.

    Nothing is announced until the outcome is known. A resolved attribute is a
    success and logs no failure, whichever module it came from; the
    "unavailable in this build" line is emitted on the ``return None`` path
    below and nowhere else, so a logged failure is a failure.
    """
    global _core_fallback_notice_emitted  # noqa: PLW0603

    module, import_error = try_import_report_service_module(module_name)
    if module is not None:
        attr = getattr(module, attr_name, None)
        if attr is not None:
            return attr

    if attr_name in _CORE_REPORT_ATTRS:
        core_module = import_module("adscan_core.reporting.technical_report")
        core_attr = getattr(core_module, attr_name, None)
        if core_attr is not None:
            if import_error is not None and not _core_fallback_notice_emitted:
                _core_fallback_notice_emitted = True
                debug_printer(f"{prefix} {_CORE_FALLBACK_NOTICE}")
            return core_attr

    if import_error is not None:
        handle_optional_report_service_exception(
            import_error,
            action=action,
            debug_printer=debug_printer,
            prefix=prefix,
        )
    return None
