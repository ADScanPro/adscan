"""Pure-logic ranker for remote-exec methods.

No network, no I/O — this module is fully unit-testable. It mirrors the
LSASS selector pattern (``services/exploitation/lsass_orchestrator.py``):
score each method against a host fingerprint plus historic catch
intelligence, sort descending, return the ranked list.
"""

from __future__ import annotations

from adscan_internal.services.host_intelligence.intelligence import EdrIntelligence
from adscan_internal.services.host_intelligence.models import HostFingerprint
from adscan_internal.services.remote_exec.method_catalog import (
    METHOD_META_BY_EXEC,
    REMOTE_EXEC_METHODS,
    RemoteExecMethodMeta,
)
from adscan_internal.services.remote_exec.models import ExecMethod

# Speed-biased order applied when the host is provably permissive
# (Defender RTP off, no AV/EDR active). Mirrors the "lab" cascade.
_SPEED_ORDER: tuple[ExecMethod, ...] = (
    ExecMethod.SMBEXEC,
    ExecMethod.ATEXEC,
    ExecMethod.WMIEXEC,
    ExecMethod.DCOMEXEC,
)

# Detection signatures that are known to mirror well in EDR/AV rules.
_HIGH_DETECTION_SIGNATURES: frozenset[str] = frozenset(
    {"service_create", "wmi_process"}
)


class RemoteExecMethodSelector:
    """Rank remote-exec methods for a given fingerprint + intelligence."""

    @staticmethod
    def rank(
        fp: HostFingerprint,
        intel: EdrIntelligence,
        *,
        require_stdout: bool = True,
        prefer_speed: bool = False,
    ) -> list[RemoteExecMethodMeta]:
        """Return all methods sorted best-first.

        Args:
            fp: AV/EDR fingerprint of the target host.
            intel: Per-host catch history.
            require_stdout: Filter out backends that cannot return
                process output.
            prefer_speed: The scan policy's ``remote_execution`` setting is
                ``speed`` (:func:`adscan_core.scan_policy.settings.prefers_fast_remote_execution`):
                a small bias towards the fastest, noisier methods. Off, the
                ranking is by footprint and catch history alone.

        Returns:
            ``list[RemoteExecMethodMeta]`` ordered from best to worst.
        """
        methods: list[RemoteExecMethodMeta] = list(REMOTE_EXEC_METHODS)
        if require_stdout:
            methods = [m for m in methods if m.captures_stdout]

        # WinRM availability gating — never include WinRM when the host has
        # already proven the port is closed or the credential is rejected.
        winrm_state = getattr(fp, "winrm_available", "unknown")
        if winrm_state in ("auth_failed", "port_closed"):
            methods = [m for m in methods if m.method != ExecMethod.WINRM]

        # Defender RTP off short-circuit — speed ordering, no scoring.
        if fp.defender_rtp is False and not fp.has_edr and not fp.has_av:
            ordered: list[RemoteExecMethodMeta] = []
            seen: set[ExecMethod] = set()
            for em in _SPEED_ORDER:
                meta = METHOD_META_BY_EXEC.get(em)
                if meta is None or em in seen:
                    continue
                if require_stdout and not meta.captures_stdout:
                    continue
                ordered.append(meta)
                seen.add(em)
            return ordered

        active_products = fp.active_products
        active_edr = [p for p in active_products if p.category == "edr"]
        active_av = [p for p in active_products if p.category == "av"]

        scored: list[tuple[int, RemoteExecMethodMeta]] = []
        for meta in methods:
            score = meta.opsec_score * 10
            high_det = meta.detection_signature in _HIGH_DETECTION_SIGNATURES

            if high_det:
                score -= 25 * len(active_edr)
                score -= 10 * len(active_av)

            for product in active_products:
                if intel.was_caught(method=meta.method.value, product=product.name):
                    score -= 40 if product.category == "edr" else 15

            if prefer_speed and meta.opsec_score <= 2:
                score += 5

            if meta.method == ExecMethod.WINRM:
                if winrm_state == "available":
                    score += 5
                    if fp.has_edr:
                        # WinRM admin pipeline is far less mirrored than
                        # service_create / wmi_process under modern EDRs.
                        score += 25

            scored.append((score, meta))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [m for _, m in scored]

    @staticmethod
    def best(
        fp: HostFingerprint,
        intel: EdrIntelligence,
        *,
        require_stdout: bool = True,
        prefer_speed: bool = False,
    ) -> RemoteExecMethodMeta:
        return RemoteExecMethodSelector.rank(
            fp,
            intel,
            require_stdout=require_stdout,
            prefer_speed=prefer_speed,
        )[0]


__all__ = ["RemoteExecMethodSelector"]
