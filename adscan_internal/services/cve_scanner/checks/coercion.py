"""Coercion CVE adapter — wraps :mod:`services.coercion` per technique.

This adapter does **not** re-implement RPC. It delegates to the existing
declarative :mod:`adscan_internal.services.coercion` engine, then groups
the per-method results by their public ``technique`` tag and emits one
:class:`CVEResult` per technique (PetitPotam, PrinterBug, ShadowCoerce,
MSEvenCoerce, DFSCoerce).

The adapter accepts an optional ``engine_runner`` callable so tests can
feed canned per-method results without standing up real RPC.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

from adscan_core import telemetry
from adscan_core.rich_output import print_error, print_info
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.coercion import (
    CoercionMethod,
    CoercionMethodResult,
    CoercionRunResult,
    CoercionTarget,
    NativeCoercionRunConfig,
    default_coercion_methods,
    run_native_coercion,
)
from adscan_internal.services.coercion.registry import technique_metadata
from adscan_internal.services.cve_scanner.result import (
    CVEResult,
    CVEStatus,
    Evidence,
    Severity,
)
from adscan_core.rich_output import print_exception

if TYPE_CHECKING:  # pragma: no cover
    from adscan_internal.services.cve_scanner.runner import ScanContext, ScanTarget


EngineRunner = Callable[
    ["ScanTarget", Any, "ScanContext"], Awaitable[CoercionRunResult]
]


class CoercionCVECheck:
    """Adapter that emits one CVEResult per coercion technique."""

    cve_id: str = "ADSCAN-COERCION"

    def __init__(
        self,
        *,
        methods: tuple[CoercionMethod, ...] | None = None,
        engine_runner: EngineRunner | None = None,
    ) -> None:
        self._methods = methods or default_coercion_methods()
        self._engine_runner = engine_runner

    async def run(
        self,
        target: ScanTarget,
        creds: Any | None,
        ctx: ScanContext,
    ) -> list[CVEResult]:
        """Run the coercion sweep against ``target`` and group by technique."""

        started = time.monotonic()
        try:
            run_result = await self._invoke_engine(target, creds, ctx)
        except Exception as exc:  # noqa: BLE001 — surface as error result
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_error(f"Coercion sweep failed for {target.host}: {exc}")
            return [
                _error_result_for_technique(
                    technique=technique,
                    host=target.host,
                    error=str(exc),
                )
                for technique in _all_techniques(self._methods)
            ]

        duration = time.monotonic() - started
        # Compact, always-on per-target digest so the operator learns
        # "coercible or not" without reading the ~75-line debug firehose
        # (which stays debug-gated in services/coercion/core.py). The
        # per-attempt debug lines and all coercion behaviour are
        # unchanged — this is purely additive.
        print_info(_coercion_summary_line(target_host=target.host, run_result=run_result))
        return _group_by_technique(
            target_host=target.host,
            methods=self._methods,
            run_result=run_result,
            duration=duration,
        )

    async def _invoke_engine(
        self,
        target: ScanTarget,
        creds: Any | None,
        ctx: ScanContext,
    ) -> CoercionRunResult:
        if self._engine_runner is not None:
            return await self._engine_runner(target, creds, ctx)
        if ctx.smb_connection_factory is None:
            raise RuntimeError(
                "ScanContext.smb_connection_factory is required to run "
                "the coercion adapter against a real target."
            )
        if not ctx.listener_host:
            raise RuntimeError(
                "ScanContext.listener_host is required for coercion checks."
            )
        # The CVE scanner has no out-of-band capture listener, so it uses the
        # per-attempt heuristic (``probable_auth_triggered``) as the
        # vulnerability indicator and always walks every method. No
        # ``capture_signal`` is supplied; the engine runs the whole catalog.
        config = NativeCoercionRunConfig(
            listener_host=ctx.listener_host,
            protocols=("EFSR", "RPRN", "FSRVP", "EVEN", "DFSNM"),
            show_summary=False,
        )
        return await run_native_coercion(
            connection_factory=ctx.smb_connection_factory,
            target_host=target.host,
            config=config,
            target_name=target.display_name,
        )


def _all_techniques(methods: tuple[CoercionMethod, ...]) -> tuple[str, ...]:
    seen: list[str] = []
    for method in methods:
        if method.technique and method.technique not in seen:
            seen.append(method.technique)
    return tuple(seen)


def _coercion_summary_line(
    *,
    target_host: str,
    run_result: CoercionRunResult,
) -> str:
    """Build a one-line coercion digest for the normal (non-debug) output.

    Aggregates the per-attempt results into a single masked verdict line
    so the operator sees ``coercible or not`` at a glance. The shape is::

        [coercion] target=<masked>: N probes (M methods x P pipes),
        K probable auth triggers -> <verdict>

    where the verdict is either ``not coercible`` or
    ``VULNERABLE: <method> via <pipe>`` naming the first successful
    method/endpoint. All host/method/endpoint values are masked via
    :func:`mark_sensitive`.

    Args:
        target_host: The coerced target host (masked in the output).
        run_result: The :class:`CoercionRunResult` from the engine.

    Returns:
        A single human-readable summary line.
    """

    results = run_result.results
    probes = len(results)
    methods = len({r.method_name for r in results})
    pipes = len({r.endpoint.label for r in results if r.endpoint is not None})
    triggers = run_result.successful_results
    masked_target = mark_sensitive(target_host, "hostname")

    if triggers:
        first = triggers[0]
        endpoint_label = first.endpoint.label if first.endpoint else first.protocol
        verdict = (
            f"VULNERABLE: {mark_sensitive(first.method_name, 'text')} "
            f"via {mark_sensitive(endpoint_label, 'text')}"
        )
    else:
        verdict = "not coercible"

    return (
        f"[coercion] target={masked_target}: {probes} probes "
        f"({methods} methods x {pipes} pipes), {len(triggers)} probable "
        f"auth triggers -> {verdict}"
    )


def _group_by_technique(
    *,
    target_host: str,
    methods: tuple[CoercionMethod, ...],
    run_result: CoercionRunResult,
    duration: float,
) -> list[CVEResult]:
    by_method: dict[str, CoercionMethodResult] = {}
    successes: dict[str, list[CoercionMethodResult]] = {}
    failures: dict[str, list[CoercionMethodResult]] = {}

    method_techniques: dict[str, str | None] = {m.name: m.technique for m in methods}

    for result in run_result.results:
        by_method[result.method_name] = result
        technique = method_techniques.get(result.method_name)
        if technique is None:
            continue
        bucket = successes if result.probable_auth_triggered else failures
        bucket.setdefault(technique, []).append(result)

    out: list[CVEResult] = []
    for technique in _all_techniques(methods):
        meta = technique_metadata(technique) or {}
        cvss = meta.get("cvss_v3")
        cve_id = meta.get("cve_id") or f"ADSCAN-COERCION-{technique.upper()}"
        severity = Severity.from_cvss(cvss)
        success_results = successes.get(technique, [])
        failure_results = failures.get(technique, [])
        if success_results:
            status = CVEStatus.VULNERABLE
            triggered = success_results[0]
            summary = (
                f"{technique} confirmed via {triggered.method_name} "
                f"({triggered.protocol})"
            )
            payload = _evidence_payload(success_results, failure_results)
        elif failure_results:
            status = CVEStatus.NOT_VULNERABLE
            summary = f"{technique} probed; {len(failure_results)} method(s) clean"
            payload = _evidence_payload([], failure_results)
        else:
            # Technique known but never reached (no endpoints / filtered).
            status = CVEStatus.NOT_APPLICABLE
            summary = f"{technique} not reachable on this target"
            payload = {"target": target_host, "methods": []}
        out.append(
            CVEResult(
                cve_id=cve_id,
                aka=technique,
                host=target_host,
                status=status,
                severity=severity,
                cvss_v3=cvss,
                cvss_vector=meta.get("cvss_vector"),
                technique=technique,
                evidence=Evidence(summary=summary, payload=payload),
                duration_seconds=duration,
            )
        )
    return out


def _evidence_payload(
    successes: list[CoercionMethodResult],
    failures: list[CoercionMethodResult],
) -> dict[str, Any]:
    return {
        "triggered": [
            {
                "method": r.method_name,
                "protocol": r.protocol,
                "endpoint": r.endpoint.label if r.endpoint else None,
                "path": r.path,
                "duration_seconds": r.duration_seconds,
            }
            for r in successes
        ],
        "tested_clean": [
            {
                "method": r.method_name,
                "protocol": r.protocol,
                "error_code": r.error_code,
            }
            for r in failures
        ],
    }


def _error_result_for_technique(*, technique: str, host: str, error: str) -> CVEResult:
    meta = technique_metadata(technique) or {}
    cvss = meta.get("cvss_v3")
    return CVEResult(
        cve_id=meta.get("cve_id") or f"ADSCAN-COERCION-{technique.upper()}",
        aka=technique,
        host=host,
        status=CVEStatus.ERROR,
        severity=Severity.from_cvss(cvss),
        cvss_v3=cvss,
        cvss_vector=meta.get("cvss_vector"),
        technique=technique,
        error=error,
        evidence=Evidence(summary=f"{technique} sweep raised: {error}", payload={}),
    )


__all__ = ["CoercionCVECheck", "CoercionTarget"]
