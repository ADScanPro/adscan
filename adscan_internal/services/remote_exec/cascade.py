"""Public orchestrator for the ``remote_exec`` package.

Owns the cascade — the ordered list of execution methods that are tried
in turn until one succeeds, the credentials are rejected, or the global
deadline is reached.

Two canonical static cascades are exposed:

* :data:`STDOUT_CASCADE` — stdout-capturing backends over two distinct
  transports: SMBEXEC → ATEXEC (both SMB / 445) → WINRM (PSRP / 5985).
  Use this when the caller consumes stdout. WinRM is last-resort: it
  reaches hosts where the SMB-based methods are blocked or the DC
  aggressively resets port-445 sessions, because it rides a completely
  different transport. The selector auto-skips WinRM when the port is
  known-closed / creds known-rejected.
* :data:`DEFAULT_CASCADE` — all four SMB backends, in the order
  SMBEXEC → ATEXEC → WMIEXEC → DCOMEXEC. Use this for fire-and-forget
  executions where output is not needed (set ``require_stdout=False``).

Adaptive mode (``methods=None``) ranks the cascade per host using the
shared :class:`HostIntelligenceCache` and per-host
:class:`EdrIntelligence`. Stealth bias kicks in on hosts with active
EDR; speed bias on hosts with Defender RTP off.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Callable

from adscan_core.rich_output import print_exception
from adscan_internal import print_info_debug, telemetry
from adscan_internal.services.host_intelligence.cache import HostIntelligenceCache
from adscan_internal.services.host_intelligence.fingerprint_service import (
    HostFingerprintService,
)
from adscan_internal.services.host_intelligence.intelligence import EdrIntelligence
from adscan_internal.services.host_intelligence.models import HostFingerprint
from adscan_internal.services.remote_exec.backends import BACKEND_REGISTRY
from adscan_internal.services.remote_exec.method_selector import (
    RemoteExecMethodSelector,
)
from adscan_internal.services.remote_exec.models import (
    AllMethodsFailed,
    AuthError,
    ExecMethod,
    MethodFailure,
    RemoteExecResult,
)
from adscan_internal.services.smb_transport import SMBConfig

# Order: stdout-capable first, blind-exec last. WMI/DCOM run server-side
# detached and do NOT capture process output — only useful for
# fire-and-forget commands or when stdout is shipped via a side channel.
DEFAULT_CASCADE: tuple[ExecMethod, ...] = (
    ExecMethod.SMBEXEC,
    ExecMethod.ATEXEC,
    ExecMethod.WMIEXEC,
    ExecMethod.DCOMEXEC,
)

# Stdout-capable subset — recommended default for any caller that reads
# the result of the command (flag collection, post-ex parsing, etc.).
# SMBEXEC and ATEXEC both ride SMB (port 445); WINRM rides PSRP (port
# 5985), a distinct transport. WinRM is intentionally LAST so the cheap
# SMB methods are tried first, but it is present so a host that resets or
# blocks every SMB session still has a working stdout path. The selector
# auto-skips WinRM when the port is known-closed / creds known-rejected.
STDOUT_CASCADE: tuple[ExecMethod, ...] = (
    ExecMethod.SMBEXEC,
    ExecMethod.ATEXEC,
    ExecMethod.WINRM,
)

# Set of methods that do NOT return process stdout. Used by the cascade
# to skip them automatically when ``require_stdout=True``.
_BLIND_METHODS: frozenset[ExecMethod] = frozenset(
    {ExecMethod.WMIEXEC, ExecMethod.DCOMEXEC}
)


# Substrings in failure messages that strongly suggest an EDR/AV blocked
# the call. Used to attribute a catch to a product when a method fails.
_EDR_BLOCK_HINTS: tuple[str, ...] = (
    "access denied",
    "access_denied",
    "0xc0000022",  # STATUS_ACCESS_DENIED
    "0xc0000005",  # STATUS_ACCESS_VIOLATION
    "blocked",
    "virus",
    "threat",
)


def _looks_like_edr_block(
    failure: MethodFailure, fp: HostFingerprint | None
) -> tuple[str | None, str | None]:
    """Heuristically map a :class:`MethodFailure` to ``(method, product)``.

    Returns ``(method_name, product_name)`` when the message looks like
    an EDR/AV block AND the host has an active product to attribute it
    to. EDR is preferred over AV when both are active.
    """
    if fp is None or not (fp.has_edr or fp.has_av):
        return None, None
    msg = (failure.message or "").lower()
    if not any(h in msg for h in _EDR_BLOCK_HINTS):
        return None, None
    for p in fp.active_products:
        if p.category == "edr":
            return failure.method.value, p.name
    for p in fp.active_products:
        if p.category == "av":
            return failure.method.value, p.name
    return None, None


async def _resolve_methods(
    *,
    config: SMBConfig,
    methods: tuple[ExecMethod, ...] | None,
    fp_override: HostFingerprint | None,
    intel: EdrIntelligence | None,
    intel_cache: HostIntelligenceCache | None,
    workspace_type: str | None,
    require_stdout: bool,
    on_intel_resolved: Callable[[HostFingerprint, list[ExecMethod]], None] | None,
) -> tuple[tuple[ExecMethod, ...], HostFingerprint | None, bool]:
    """Resolve which cascade order to use.

    Returns ``(methods, fingerprint, from_cache)``. ``fingerprint`` is
    None only when an explicit ``methods=`` was passed AND no
    ``fp_override`` / cache / one-shot fingerprint applied.
    """
    if methods is not None:
        return methods, fp_override, False

    fp = fp_override
    from_cache = False
    if fp is None:
        if intel_cache is not None:
            cached_age = intel_cache.cache_age_seconds(config.target_ip)
            fp = await intel_cache.get_or_fingerprint(
                config=config,
                fp_service=HostFingerprintService(),
            )
            from_cache = cached_age is not None
        else:
            fp = await HostFingerprintService().fingerprint(config)

    intel_obj = intel if intel is not None else EdrIntelligence(_EPHEMERAL_INTEL_DIR)
    ranked = RemoteExecMethodSelector.rank(
        fp,
        intel_obj,
        require_stdout=require_stdout,
        workspace_type=workspace_type,
    )
    ranked_methods = tuple(m.method for m in ranked)

    if on_intel_resolved is not None:
        try:
            on_intel_resolved(fp, list(ranked_methods))
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    return ranked_methods, fp, from_cache


# Lazily-created scratch dir for the ephemeral intel object used when no
# workspace-bound EdrIntelligence is supplied. Catches recorded against
# this fall on a tmpfs-style file the launcher cleans up.
import tempfile as _tempfile  # noqa: E402

_EPHEMERAL_INTEL_DIR: str = _tempfile.gettempdir()


async def execute_with_fallback(
    config: SMBConfig,
    command: str,
    *,
    methods: tuple[ExecMethod, ...] | None = None,
    fp_override: HostFingerprint | None = None,
    intel: EdrIntelligence | None = None,
    intel_cache: HostIntelligenceCache | None = None,
    workspace_type: str | None = None,
    timeout: int = 60,
    require_stdout: bool = True,
    on_method_attempt: Callable[[ExecMethod], None] | None = None,
    on_intel_resolved: Callable[[HostFingerprint, list[ExecMethod]], None]
    | None = None,
    shell: Any | None = None,  # accepted for backwards compat; unused
) -> RemoteExecResult:
    """Run ``command`` on the remote host, trying each method in order.

    The first method that succeeds wins. If a backend raises
    :class:`AuthError` the whole cascade aborts immediately — there is
    no point trying more methods with credentials the server already
    rejected.

    Args:
        config: Target host + credentials.
        command: Command line to execute.
        methods: Explicit ordered tuple of methods. When ``None``
            (default) adaptive mode kicks in: a host fingerprint is
            obtained (from ``fp_override`` / ``intel_cache`` / a
            one-shot scan) and ranked by
            :class:`RemoteExecMethodSelector`.
        fp_override: Pre-computed fingerprint to skip the I/O scan.
        intel: Per-host catch history. Updated on success/failure.
        intel_cache: Workspace-scoped fingerprint cache.
        workspace_type: ``"ctf"`` / ``"audit"`` / ``"engagement"``;
            biases the selector slightly toward speed or stealth.
        timeout: Per-method timeout AND, multiplied by the number of
            methods, the global deadline.
        require_stdout: When True (default) backends that do not capture
            stdout (WMI, DCOM) are auto-skipped.
        on_method_attempt: Optional callback invoked once per method
            *before* the attempt. Use for UI progress.
        on_intel_resolved: Optional callback invoked once after the
            fingerprint and ranking are resolved (adaptive mode only).
            Receives ``(fingerprint, ranked_methods)``.
        shell: Reserved. Accepted for source-compat with older callers.

    Returns:
        :class:`RemoteExecResult`.

    Raises:
        AuthError: Credentials were rejected by a backend.
    """
    _ = shell
    started = time.monotonic()

    resolved_methods, fp, from_cache = await _resolve_methods(
        config=config,
        methods=methods,
        fp_override=fp_override,
        intel=intel,
        intel_cache=intel_cache,
        workspace_type=workspace_type,
        require_stdout=require_stdout,
        on_intel_resolved=on_intel_resolved,
    )

    deadline = started + max(1, timeout * max(1, len(resolved_methods)))
    failures: list[MethodFailure] = []
    methods_failed: list[tuple[str, str]] = []

    for method in resolved_methods:
        if require_stdout and method in _BLIND_METHODS:
            failures.append(
                MethodFailure(
                    method=method,
                    error_kind="not_supported",
                    message="skipped: caller requires stdout, backend cannot capture it",
                )
            )
            continue

        if time.monotonic() >= deadline:
            failures.append(
                MethodFailure(
                    method=method,
                    error_kind="timeout",
                    message="global cascade deadline reached before attempt",
                )
            )
            break

        if on_method_attempt is not None:
            try:
                on_method_attempt(method)
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)

        backend = BACKEND_REGISTRY.get(method)
        if backend is None:
            failures.append(
                MethodFailure(
                    method=method,
                    error_kind="not_supported",
                    message=f"no backend registered for {method}",
                )
            )
            continue

        print_info_debug(f"[remote_exec] trying {method}…")
        try:
            result = await asyncio.wait_for(
                backend(config, command, timeout=timeout),
                timeout=timeout + 5,
            )
        except AuthError:
            raise
        except asyncio.TimeoutError as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            failures.append(
                MethodFailure(
                    method=method,
                    error_kind="timeout",
                    message=f"backend exceeded hard cap of {timeout + 5}s",
                )
            )
            methods_failed.append((method.value, "timeout"))
            continue
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            failure = MethodFailure(
                method=method,
                error_kind="other",
                message=str(exc)[:240],
            )
            failures.append(failure)
            methods_failed.append((method.value, "other"))
            _maybe_record_catch(intel, config.target_ip, failure, fp)
            continue

        if result.success:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            _emit_choice_telemetry(
                fp=fp,
                ranked=resolved_methods,
                chosen=method,
                methods_failed=methods_failed,
                from_cache=from_cache,
                workspace_type=workspace_type,
            )
            return RemoteExecResult(
                success=True,
                method=result.method or method,
                stdout=result.stdout,
                stderr=result.stderr,
                return_code=result.return_code,
                captures_stdout=result.captures_stdout,
                process_id=result.process_id,
                elapsed_ms=elapsed_ms,
                errors=tuple(failures),
            )

        for f in result.errors or ():
            failures.append(f)
            methods_failed.append((f.method.value, f.error_kind))
            _maybe_record_catch(intel, config.target_ip, f, fp)
        if not result.errors:
            synth = MethodFailure(
                method=method,
                error_kind="other",
                message="backend reported failure with no diagnostic",
            )
            failures.append(synth)
            methods_failed.append((method.value, "other"))

    elapsed_ms = int((time.monotonic() - started) * 1000)
    _emit_choice_telemetry(
        fp=fp,
        ranked=resolved_methods,
        chosen=None,
        methods_failed=methods_failed,
        from_cache=from_cache,
        workspace_type=workspace_type,
    )
    return RemoteExecResult(
        success=False,
        method=None,
        elapsed_ms=elapsed_ms,
        errors=tuple(failures),
    )


def _maybe_record_catch(
    intel: EdrIntelligence | None,
    host: str,
    failure: MethodFailure,
    fp: HostFingerprint | None,
) -> None:
    if intel is None:
        return
    method_name, product_name = _looks_like_edr_block(failure, fp)
    if not (method_name and product_name and fp):
        return
    category = next(
        (p.category for p in fp.active_products if p.name == product_name),
        "edr",
    )
    try:
        intel.record_catch(
            host=host,
            method=method_name,
            product=product_name,
            category=category,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def _emit_choice_telemetry(
    *,
    fp: HostFingerprint | None,
    ranked: tuple[ExecMethod, ...],
    chosen: ExecMethod | None,
    methods_failed: list[tuple[str, str]],
    from_cache: bool,
    workspace_type: str | None,
) -> None:
    """Emit a single ``remote_exec.adaptive_choice`` telemetry event."""
    try:
        payload = {
            "host": fp.target_ip if fp is not None else None,
            "products_detected": [p.name for p in fp.products] if fp else [],
            "defender_rtp": fp.defender_rtp if fp else None,
            "methods_ranked": [m.value for m in ranked],
            "method_chosen": chosen.value if chosen is not None else None,
            "methods_failed": methods_failed,
            "from_cache": from_cache,
            "workspace_type": workspace_type,
        }
        capture = getattr(telemetry, "capture_event", None)
        if callable(capture):
            capture("remote_exec.adaptive_choice", payload)  # pylint: disable=not-callable
        else:
            print_info_debug(f"[remote_exec.adaptive_choice] {payload}")
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def raise_if_failed(result: RemoteExecResult) -> RemoteExecResult:
    """Convenience: raise :class:`AllMethodsFailed` on a failed result."""
    if not result.success:
        raise AllMethodsFailed(result.errors)
    return result


__all__ = [
    "DEFAULT_CASCADE",
    "STDOUT_CASCADE",
    "execute_with_fallback",
    "raise_if_failed",
]
