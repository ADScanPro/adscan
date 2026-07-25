"""Generic AV/EDR fingerprinting via native aiosmb.

Detection approach (three independent signals, OR-merged):
  1. **LSARPC LookupNames** — resolve ``NT Service\\<svc_key>`` over the
     ``\\lsarpc`` named pipe.  Robust against Tamper Protection that
     locks down ``HKLM\\SYSTEM\\Services`` and works with any
     authenticated user (no admin / no RemoteRegistry needed).
     Yields installed/not-installed only — no ``Start`` DWORD.
  2. **Service-key registry probe** — open
     ``HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name>`` via RRP.
     Yields the ``Start`` DWORD (auto/manual/disabled) needed to
     classify *active* vs *installed-inactive* products.
  3. **IPC$ pipe enumeration** — ``machine.list_pipes()`` matched
     against per-product pipe substrings.  Confirms the product is
     not just installed but currently running.

Plus: Defender real-time protection — ``DisableRealtimeMonitoring`` DWORD.

LSARPC and registry probes run in parallel (different RPC pipes) to keep
the fingerprint fast.  When one transport fails (e.g. RemoteRegistry
unavailable, or LSARPC null-sessions blocked) the other still produces
a result — we never under-report a host.

This module never imports impacket, netexec, or any subprocess tool.
It also never imports from :mod:`adscan_internal.services.exploitation`
— this is the foundation, not a consumer.
"""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import TypeVar

from adscan_internal import telemetry
from adscan_core.rich_output import print_info_debug
from adscan_internal.services.host_intelligence.models import (
    DetectedProduct,
    HostFingerprint,
)
from adscan_internal.services.host_intelligence.product_catalog import (
    DEFENDER_RTP_KEY,
    DEFENDER_RTP_VAL,
    PRODUCT_CATALOG,
    SERVICES_BASE,
)
from adscan_internal.services.smb_transport import SMBConfig, smb_machine_with_fallback
from adscan_core.rich_output import print_exception

T = TypeVar("T")


class HostFingerprintService:
    """Detect AV/EDR products on a remote Windows host via aiosmb."""

    async def fingerprint(self, config: SMBConfig) -> HostFingerprint:
        """Run AV/EDR fingerprinting.

        Never raises — returns a :class:`HostFingerprint` whose ``error``
        attribute is set on failure so callers can degrade gracefully.

        Args:
            config: SMB connection config.

        Returns:
            A :class:`HostFingerprint` populated with detected products
            and Defender RTP state.
        """
        t0 = time.monotonic()
        fp = HostFingerprint(target_ip=config.target_ip)
        try:
            await self._start_remote_registry_best_effort(config)

            # Use isolated SMB sessions per probe. Some aiosmb/DCERPC paths
            # close the underlying SMB connection on reset; sharing one
            # connection across concurrent LSARPC, RRP, and pipe enumeration can
            # turn one transient failure into an empty fingerprint.
            lsarpc_task = asyncio.create_task(
                self._run_probe_with_fresh_machine(
                    config,
                    "LSARPC",
                    self._detect_via_lsarpc,
                    {},
                )
            )
            services_task = asyncio.create_task(
                self._run_probe_with_fresh_machine(
                    config,
                    "service registry",
                    self._detect_via_services,
                    {},
                )
            )
            pipes_task = asyncio.create_task(
                self._run_probe_with_fresh_machine(
                    config,
                    "IPC pipe",
                    self._detect_via_pipes,
                    {},
                )
            )
            rtp_task = asyncio.create_task(
                self._run_probe_with_fresh_machine(
                    config,
                    "Defender RTP",
                    self._read_defender_rtp,
                    True,
                )
            )

            lsarpc_map = await lsarpc_task
            service_map = await services_task
            running_map = await pipes_task
            fp.defender_rtp = await rtp_task
            print_info_debug(
                "[host_intel] probe summary: "
                f"lsarpc_matches={len(lsarpc_map)} "
                f"service_matches={sum(1 for found, _start in service_map.values() if found)} "
                f"pipe_running={sum(1 for running in running_map.values() if running)} "
                f"defender_rtp={'on-or-assumed' if fp.defender_rtp else 'off'}"
            )

            for product in PRODUCT_CATALOG:
                reg_inst, svc_start = service_map.get(product.name, (False, -1))
                lsa_inst = product.name in lsarpc_map
                inst = reg_inst or lsa_inst
                run = running_map.get(product.name, False)
                if inst or run:
                    rtp = (
                        fp.defender_rtp if product.name == "Windows Defender" else True
                    )
                    fp.products.append(
                        DetectedProduct(
                            name=product.name,
                            category=product.category,
                            installed=inst,
                            running=run,
                            svc_start=svc_start,
                            realtime_protection=rtp,
                        )
                    )
            if fp.detected_products:
                print_info_debug(
                    "[host_intel] detected products: "
                    + ", ".join(
                        f"{product.name}({product.category}, {product.status_label})"
                        for product in fp.detected_products
                    )
                )
            else:
                print_info_debug(
                    "[host_intel] no products detected by LSARPC, service registry, or IPC pipe probes"
                )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            fp.error = str(exc)[:200]
            print_info_debug(f"[host_intel] error: {exc}")
        try:
            self._resolve_winrm_availability(config, fp)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(f"[host_intel] winrm availability error: {exc}")
        fp.elapsed_s = time.monotonic() - t0
        return fp

    # ------------------------------------------------------------------ helpers

    async def _start_remote_registry_best_effort(self, config: SMBConfig) -> None:
        """Start RemoteRegistry using a short-lived SMB session."""
        try:
            async with smb_machine_with_fallback(config) as machine:
                ok, err = await machine.start_service("RemoteRegistry")
                print_info_debug(f"[host_intel] RemoteRegistry start: {ok} / {err}")
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(f"[host_intel] RemoteRegistry start error: {exc}")

    async def _run_probe_with_fresh_machine(
        self,
        config: SMBConfig,
        probe_name: str,
        probe: Callable[[object], Awaitable[T]],
        fallback: T,
    ) -> T:
        """Run one fingerprint probe on an isolated SMB session."""
        try:
            print_info_debug(f"[host_intel] {probe_name} probe start")
            async with smb_machine_with_fallback(config) as machine:
                result = await probe(machine)
            print_info_debug(f"[host_intel] {probe_name} probe complete")
            return result
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(f"[host_intel] {probe_name} probe failed: {exc}")
            return fallback

    async def _read_defender_rtp(self, machine) -> bool:
        """Return True iff Defender real-time protection is enabled.

        Reads ``DisableRealtimeMonitoring`` (DWORD). 0 / absent => RTP on,
        1 => RTP off. Errors degrade to "enabled" so we never under-rate
        the host.
        """
        try:
            rpc, err = await machine.get_regapi()
            if err is not None or rpc is None:
                return True
            async with rpc:
                key, err = await rpc.OpenRegPath(DEFENDER_RTP_KEY)
                if err is not None or key is None:
                    return True
                _vtype, val, err = await rpc.QueryValue(key, DEFENDER_RTP_VAL)
                if err is not None or val is None:
                    return True
                return int(val) == 0
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(f"[host_intel] Defender RTP read error: {exc}")
            return True

    async def _detect_via_lsarpc(self, machine) -> dict[str, set[str]]:
        """Detect installed services via LSARPC ``LsarLookupNames``.

        Resolves ``NT Service\\<svc_key>`` against the local LSA SCM database.
        Successful resolution => the service is registered on the host.

        Returns ``{product_name: {matched_svc_keys}}`` — the caller merges
        this with the registry-probe result to populate ``DetectedProduct``.

        Why LSARPC and not just registry: this transport survives Tamper
        Protection that locks down ``HKLM\\SYSTEM\\Services``, doesn't
        require the RemoteRegistry service to be up, and works for any
        authenticated user (no admin required). Trade-off: yields
        presence/absence only — the registry probe is still needed for
        the ``Start`` DWORD that distinguishes auto/manual/disabled.

        Concurrency: serial within a single LSARPC session because the
        DCERPC connection is not safe for concurrent calls. Short-circuits
        on the first matching service key per product to bound work.
        """
        result: dict[str, set[str]] = {}
        try:
            from aiosmb.dcerpc.v5.interfaces.lsatmgr import lsadrpc_from_smb
            from aiosmb.dcerpc.v5 import lsat as _lsat
        except ImportError as exc:
            print_info_debug(f"[host_intel] LSARPC unavailable (import): {exc}")
            return result

        try:
            async with lsadrpc_from_smb(machine.connection) as lsa:
                ph_id, err = await lsa.open_policy2(
                    permissions=_lsat.POLICY_LOOKUP_NAMES
                )
                if err is not None or ph_id is None:
                    print_info_debug(f"[host_intel] LSARPC open_policy2 failed: {err}")
                    return result
                policy_handle = lsa.policy_handles[ph_id]

                lookups = 0
                for product in PRODUCT_CATALOG:
                    for svc_key in product.service_keys:
                        full_name = f"NT Service\\{svc_key}"
                        lookups += 1
                        try:
                            resp = await _lsat.hLsarLookupNames(
                                lsa.dce, policy_handle, [full_name]
                            )
                        except Exception:  # noqa: BLE001
                            # STATUS_NONE_MAPPED — service not registered.
                            # This is the expected outcome for most lookups
                            # and not actionable; debug-log only when chasing
                            # a specific catalog gap.
                            continue
                        try:
                            sids = resp["TranslatedSids"]["Sids"]
                            if sids and int(sids[0]["Use"]) != 8:  # 8 == SidTypeUnknown
                                result.setdefault(product.name, set()).add(svc_key)
                                print_info_debug(
                                    f"[host_intel] LSARPC match: {product.name} "
                                    f"via key='{svc_key}'"
                                )
                                break  # one match is enough — move to next product
                        except (KeyError, IndexError, TypeError, ValueError):
                            continue
                print_info_debug(
                    f"[host_intel] LSARPC done — {lookups} lookups, "
                    f"{len(result)} product(s) matched"
                )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(f"[host_intel] LSARPC detection error: {exc}")
        return result

    async def _detect_via_services(self, machine) -> dict[str, tuple[bool, int]]:
        """Probe service keys; return ``{name: (installed, svc_start)}``.

        Logs the specific matched service key + Start DWORD at debug level
        so a missing detection can be traced to either: catalog gap, key
        mismatch, or registry-access denial.
        """
        result: dict[str, tuple[bool, int]] = {}
        try:
            rpc, err = await machine.get_regapi()
            if err is not None or rpc is None:
                print_info_debug(
                    f"[host_intel] service probe skipped — get_regapi err={err}"
                )
                return result
            async with rpc:
                for product in PRODUCT_CATALOG:
                    found = False
                    matched_key: str | None = None
                    svc_start = -1
                    for svc_key in product.service_keys:
                        path = f"{SERVICES_BASE}\\{svc_key}"
                        key, err = await rpc.OpenRegPath(path)
                        if err is None and key is not None:
                            found = True
                            matched_key = svc_key
                            try:
                                _vtype, start_val, verr = await rpc.QueryValue(
                                    key, "Start"
                                )
                                if verr is None and start_val is not None:
                                    svc_start = int(start_val)
                            except Exception:  # noqa: BLE001
                                pass
                            break
                    if found:
                        print_info_debug(
                            f"[host_intel] service match: {product.name} "
                            f"via key='{matched_key}' Start={svc_start}"
                        )
                    result[product.name] = (found, svc_start)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(f"[host_intel] service detection error: {exc}")
        return result

    async def _detect_via_pipes(self, machine) -> dict[str, bool]:
        """Enumerate IPC$ pipes; return ``{product_name: running_bool}``.

        Logs the specific matched pipe at debug level so a missing detection
        can be traced to a catalog gap rather than a transport failure.
        """
        result: dict[str, bool] = {}
        try:
            pipe_names: list[str] = []
            async for pipe_name, err in machine.list_pipes():
                if err is not None:
                    print_info_debug(f"[host_intel] pipe enum error: {err}")
                    continue
                if pipe_name:
                    pipe_names.append(pipe_name)
            print_info_debug(f"[host_intel] enumerated {len(pipe_names)} IPC$ pipe(s)")
            for product in PRODUCT_CATALOG:
                matched_pipe: str | None = None
                for pat in product.pipe_patterns:
                    needle = pat.lower()
                    for pname in pipe_names:
                        if needle in pname.lower():
                            matched_pipe = pname
                            break
                    if matched_pipe:
                        break
                running = matched_pipe is not None
                if running:
                    print_info_debug(
                        f"[host_intel] pipe match: {product.name} "
                        f"via pipe='{matched_pipe}'"
                    )
                result[product.name] = running
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(f"[host_intel] pipe detection error: {exc}")
        return result

    # ------------------------------------------------------------------ winrm

    def _resolve_winrm_availability(
        self,
        config: SMBConfig,
        fp: HostFingerprint,
    ) -> None:
        """Set ``fp.winrm_available`` based on workspace inventory only.

        Stage A (port-level confidence) of the WinRM detection flow:
        if the target IP is listed in ``domains/<domain>/winrm/ips.txt``
        from a prior port scan, mark the host ``"available"``. Missing
        files map to ``"unknown"`` — never to ``"port_closed"`` — so a
        user who has not run the port scan is not silently excluded.

        Stage B (auth-level confidence via ``probe_winrm_available``) is
        intentionally not invoked here: it requires workspace context
        (workspace_dir, domain) the fingerprint service does not own.
        The cascade orchestrator may upgrade this field after a runtime
        probe.
        """
        target_ip = (config.target_ip or "").strip()
        if not target_ip:
            return
        adscan_home = os.environ.get("ADSCAN_HOME", "").strip()
        domain = (config.domain or "").strip()
        if not adscan_home or not domain:
            return
        ips_file = (
            Path(adscan_home) / "workspaces" / "domains" / domain / "winrm" / "ips.txt"
        )
        try:
            if not ips_file.exists() or ips_file.stat().st_size == 0:
                return
            entries = {
                line.strip()
                for line in ips_file.read_text(
                    encoding="utf-8", errors="ignore"
                ).splitlines()
                if line.strip()
            }
            if target_ip in entries:
                fp.winrm_available = "available"
                fp.winrm_probed_at = datetime.now(timezone.utc)
        except OSError:
            return


__all__ = ["HostFingerprintService"]
