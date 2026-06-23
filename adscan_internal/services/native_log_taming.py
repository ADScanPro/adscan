"""Single source of truth for taming third-party (vendor) logging noise.

ADscan integrates a sizable surface of third-party libraries — the native AD
stack (aiosmb, msldap, kerbad, asysocks, badldap, badauth, minikerberos,
winacl, asyauth, asyldap), credential parsers (pypykatz), and stdlib loggers
that emit benign chatter as a side-effect of how we use them (asyncio).

These libraries pollute the user's terminal through **four distinct channels**,
each with its own remedy. This module is the canonical place for all four —
do not invent parallel mechanisms in other modules.

================================================================================
Channel 1 — stdlib ``logging`` (rogue StreamHandler at import time)
================================================================================
Native-stack libs install their own ``StreamHandler`` and write raw lines like
``2026-05-02 08:07:36,863 aiosmb ERROR ...`` straight to stderr, bypassing
Rich. :func:`tame_native_stack_loggers` strips those handlers, forces
``propagate=True``, attaches :class:`BenignNativeNoiseFilter` to drop
known-benign post-teardown chatter (SMB ``CONNECTION_ABORTED``, SPNEGO/NEGOEX
cleanup, late callbacks), and attaches the :class:`_NativeStackBridgeHandler`
so the surviving records reach ADscan's centralized output (see "Native-stack
logging bridge" below).

================================================================================
Channel 2 — stdlib ``logging`` (handler-less vendor loggers)
================================================================================
Some vendors (``pypykatz``, ``asyncio``) don't add their own handlers — they
just propagate. We don't need to strip anything, only filter benign noise via
the same :class:`BenignNativeNoiseFilter`. Add the logger name to
:data:`_NATIVE_STACK_LOGGER_NAMES` (handler-stripping is a no-op when there
are no handlers to strip) and the substring to
:data:`BENIGN_NATIVE_NOISE_MARKERS`.

================================================================================
Channel 3 — vendor ``log_callback`` mechanism (bypasses logging entirely)
================================================================================
aiosmb and badldap relay servers use a ``log_callback`` parameter that, by
default, calls ``print()`` directly to stdout. :func:`make_relay_log_callback`
produces a replacement callback that filters lifecycle chatter and packet
dumps and routes the rest through ADscan's ``print_info_debug``. Pass it when
constructing ``SMBServerSettings`` / ``LDAPServerSettings``.

================================================================================
Channel 4 — direct ``print()`` / ``traceback.print_exc()`` in vendor source
================================================================================
Some vendor code prints raw bytes / tracebacks directly (asyauth SPNEGO server,
aiosmb relay exception handlers). These bypass everything. Because ``vendor/``
is committed and IS what ships, the fix is to **patch the vendor file
directly** — silence the print, replace the traceback with ``pass``, or route
through the available callback if one exists. See git history for examples in
``vendor/aiosmb/aiosmb/relay/serverconnection.py`` and
``vendor/asyauth/asyauth/protocols/spnego/server/native.py``.

================================================================================
Native-stack logging bridge (Channel 1 routing)
================================================================================
The native-stack vendor loggers (``aiosmb``, ``badldap``, ``kerbad``,
``winacl``, ``pypykatz``, …) are NOT children of the ``adscan`` logger — they
propagate to the *root* logger, which carries none of ADscan's RichHandlers
(those attach to the ``adscan`` logger, which itself has ``propagate=False``).
Consequently their records reach neither the session telemetry recording nor
the visible console; they only ever surfaced through Python's ``lastResort``
fallback to stderr.

:class:`_NativeStackBridgeHandler` closes that gap WITHOUT touching the vendor
source (the whole point — the fix survives ``scripts/refresh_vendor.sh``). A
single shared instance is attached ONLY to the top-level prefix loggers in
:data:`_NATIVE_STACK_LOGGER_PREFIXES` (``aiosmb``, ``badauth``, ``asysocks``,
…) — never to their children. A record originating on a child logger (e.g.
``badauth.ntlm``) propagates up to its prefix logger (``badauth``), where the
shared bridge fires EXACTLY ONCE. Attaching the bridge to both parent AND child
(as an earlier version did) made every child record emit twice — once on the
child, once again on the parent via propagation — flooding the recording with
duplicate lines. The stdlib ``Logger.callHandlers`` contract guarantees the
single-prefix attach is sufficient: during propagation it walks the parent
chain and fires each handler gated ONLY by ``record.levelno >= handler.level``
(it does NOT re-check ancestor logger effective levels), and the bridge
handler's own level is ``DEBUG`` — so a DEBUG/INFO child record still reaches
the prefix-attached bridge.

The bridge forwards each surviving record to:

* **Telemetry — WARNING and above only.** The record is rendered to the
  telemetry console (``record=True`` buffer) resolved via
  ``adscan_core.output._state._get_telemetry_console`` only when
  ``record.levelno >= logging.WARNING``. Vendor DEBUG/INFO is extremely chatty
  (per-NTLM-message granularity: every Flags/sealkey/signkey/negotiate line)
  and would flood every uploaded recording while needlessly widening the
  secret-exposure surface; it is therefore kept OUT of the always-on telemetry
  buffer. What survives (WARNING+ / ERROR) is scrubbed by the export-time,
  source-agnostic, fail-closed sanitizer in ``telemetry.py`` — plus the
  LAYER-2 :func:`scrub_native_secrets` applied here before the line is queued.
* **Visible console — only under ``--debug`` (all levels, DEBUG+).** When
  ``adscan_core.output._state.is_debug_mode()`` is ``True`` the record is also
  rendered to the shared ``_TeeConsole`` (``get_console()``) so the operator
  can follow the full vendor stream live. ``_TeeConsole.print`` auto-mirrors to
  telemetry, which would re-introduce the DEBUG flood into the recording via
  the console path — so this print is wrapped in
  ``adscan_core.output._state._explicit_telemetry_mirror`` to suppress the
  auto-mirror. The visible ``--debug`` stream therefore does NOT leak vendor
  DEBUG/INFO back into telemetry. During a ``LiveSession`` the deferred-flush
  still captures it because the capture path is separate from the telemetry
  mirror (it appends to the active deferred buffer regardless of the
  auto-mirror opt-out).

Net result: the telemetry recording holds the operator narrative (``print_*``)
plus vendor WARNING+/ERROR only; vendor DEBUG/INFO is a ``--debug``-console
convenience that never reaches the uploaded buffer.

The handler keeps ``propagate=True`` on the vendor loggers untouched: it is a
purely *additive* sink, so the existing/legacy propagation contract (and any
future root handler) is preserved. Because the handler lives only on the
vendor prefix loggers — never on ``adscan`` or root — ADscan's own records are
never double-recorded by it. The handler is best-effort: it never raises,
mirroring the ``_TeeConsole.print`` try/except discipline, so a broken
telemetry buffer can never break the visible flow.

================================================================================
NTLM-handshake noise tier (logger-scoped, ``--debug``-only volume control)
================================================================================
The ``badauth.ntlm`` logger emits a full per-handshake state-machine trace at
DEBUG for EVERY authentication attempt (``Negotiate message constructed``,
``Setting Client sealkey ...``, ``KeyExchangeKey derived``, ``Flags: ...``,
etc.). The NTLMv1 coercion sweep drives dozens-to-hundreds of handshakes
(hosts × coercion methods × pipes), so these markers flood the ``--debug``
console with zero operator-diagnostic value: the NTLMv1/NTLMv2 classification
is already in the sweep results table, and each attempt's outcome is already in
the ADscan-level ``attempt`` / ``completed`` / ``attempt failed`` lines.

:data:`_NTLM_HANDSHAKE_NOISE_MARKERS` lists the high-frequency, zero-value
substrings. :class:`BenignNativeNoiseFilter` drops a record whose
``record.name`` is the NTLM logger (``badauth.ntlm``) AND whose level is
``DEBUG`` AND whose message matches a marker. This filtering is deliberately
SCOPED to ``badauth.ntlm`` and kept SEPARATE from the logger-agnostic
:data:`BENIGN_NATIVE_NOISE_MARKERS`: the bare ``Flags:`` marker, for instance,
must drop NTLM flag chatter but NEVER ``badauth.kerberos`` flags (Kerberos
flags can matter). Because the filter is attached to BOTH the native loggers
and the bridge handler, a dropped record disappears from the visible console
AND telemetry — exactly the intended effect.

**Escape hatch — ``ADSCAN_VENDOR_DEBUG=1``.** A developer who genuinely needs
the raw NTLM handshake trace back can set ``ADSCAN_VENDOR_DEBUG=1`` in the
environment; the NTLM-handshake drop is then skipped (the global benign-noise
markers still apply). Default (env unset) drops the chatter. This does NOT
touch the WARNING+ telemetry gate or the bridge de-dup — only the ``--debug``
console volume of pure handshake markers.

================================================================================
Secret scrubbing (LAYER 2 of the no-exfiltration defence)
================================================================================
Independent of noise control, every line the bridge forwards is passed through
:func:`scrub_native_secrets` — re-exported from the dependency-light SSOT
:mod:`adscan_core.native_secret_scrub` — BEFORE it reaches the telemetry buffer
or the ``--debug`` console. LAYER 1 is the vendor-source redaction (the
``# ADSCAN: do not dump ...`` edits in ``vendor/badauth``); LAYER 2 exists
because ``scripts/refresh_vendor.sh`` can silently re-introduce a raw dump. The
scrubber redacts protocol-recognizable material with NO label (NTLMSSP messages,
NetNTLM hashcat lines, challenge byte-reprs) AND label-gated crypto-key /
Kerberos-ticket blobs — see that module for the detector inventory and the
false-positive guard. The SAME function is applied whole-buffer, fail-closed at
telemetry export time (``adscan_core.telemetry``), so material that never
travelled through the bridge (e.g. ``--debug`` console mirroring of a vendor
``print()``) is still redacted before upload.

================================================================================
Lifecycle
================================================================================
Call :func:`tame_native_stack_loggers` exactly once at runtime startup, right
after ``init_logging`` has configured the root Rich console handler. The
function is idempotent — subsequent calls are no-ops.
"""

from __future__ import annotations

import logging
import os
import traceback
from collections.abc import Callable

# LAYER 2 secret scrubber — single source of truth in the dependency-light
# ``adscan_core`` layer so the telemetry export path (also in ``adscan_core``)
# can share the exact same detectors. Re-exported here under the historical
# names so existing call sites and tests keep working.
from adscan_core.native_secret_scrub import (
    SECRET_LABELS as _SECRET_LABELS,  # noqa: F401 — re-exported for compatibility
    scrub_native_secrets,
)


_NATIVE_STACK_LOGGER_NAMES: tuple[str, ...] = (
    # Native AD stack — strip rogue StreamHandler + filter benign noise.
    "aiosmb",
    "msldap",
    "kerbad",
    "minikerberos",
    "asysocks",
    "asysocks.client",
    "asysocks.client.http",
    "asysocks.unicomm",
    "badldap",
    "badauth",
    "badauth.ntlm",
    "badauth.kerberos",
    "badauth.credssp",
    "winacl",
    "asyauth",
    "asyldap",
    # Credential parsers — emit informational warnings as a side-effect of
    # how we call them (e.g. ``hive path not supplied`` when we deliberately
    # pass only SAM/SYSTEM and skip SECURITY/SOFTWARE).
    "pypykatz",
    # stdlib loggers that emit benign noise as a side-effect of our async
    # socket lifecycle (e.g. ``socket.send() raised exception`` after a
    # short-lived SMB session is torn down with pending writes).
    "asyncio",
)


_NATIVE_STACK_LOGGER_PREFIXES: tuple[str, ...] = tuple(
    sorted({name.split(".", 1)[0] for name in _NATIVE_STACK_LOGGER_NAMES})
)


BENIGN_NATIVE_NOISE_MARKERS: tuple[str, ...] = (
    # aiosmb tears down sockets after a normal session and re-raises the
    # terminal status as an exception — its ``except:`` clause then logs the
    # traceback at ERROR even though the foreground operation has succeeded.
    "SMBConnectionTerminated",
    "CONNECTION_ABORTED",
    "CONNECTION_RESET",
    "__handle_smb_in",
    # SPNEGO / NEGOEX teardown chatter from relay listeners and the auth
    # negotiation re-binding when a peer drops the channel cleanly.
    "NEGTOKEN_LOAD_ERROR",
    "[SPNEGOServer]",
    "[SPNEGORelay]",
    "Value [APPLICATION 28] did not match",
    "authenticate_relay_server",
    # Late callbacks fired once the underlying socket has already gone away.
    "object of type 'NoneType' has no len()",
    "SecurityBufferLength = len(self.Buffer)",
    "'NoneType' object has no attribute 'get_session_key'",
    # pypykatz offline_parser — fired every SAM-only dump because we
    # deliberately don't pass SECURITY/SOFTWARE hives.
    "hive path not supplied",
    # asyncio selector_events / proactor_events — fired when a connection is
    # torn down with pending writes (standard pattern for short-lived SMB).
    "socket.send() raised exception",
    "socket.sendto() raised exception",
    # asyncio emits this at DEBUG every time a new event loop is created (each
    # run_smb_operation / background reader loop). Pure lifecycle chatter — under
    # --debug it floods when many short async operations run back-to-back.
    "Using selector:",
)


def is_benign_native_noise(
    message: str,
    *,
    extra_markers: tuple[str, ...] = (),
) -> bool:
    """Return ``True`` when a third-party message matches a benign pattern.

    ``extra_markers`` lets callers extend the global list with context-specific
    tokens (e.g. the relay listener path adds ``TimeoutError`` and a few
    ``[DEBUG]`` prints that are only safe to drop in that flow).
    """

    if not message:
        return False
    for marker in BENIGN_NATIVE_NOISE_MARKERS:
        if marker in message:
            return True
    for marker in extra_markers:
        if marker in message:
            return True
    return False


# ---------------------------------------------------------------------------
# NTLM-handshake noise tier (logger-scoped to ``badauth.ntlm``, DEBUG-only)
# ---------------------------------------------------------------------------
#
# These are the per-handshake state-machine markers the ``badauth.ntlm`` logger
# emits at DEBUG for EVERY auth attempt. The NTLMv1 coercion sweep drives
# dozens-to-hundreds of handshakes, so they flood the ``--debug`` console with
# zero operator-diagnostic value (the NTLMv1/NTLMv2 result is in the sweep
# table; each attempt's outcome is in the ADscan-level attempt/completed lines).
# Kept SEPARATE from the logger-agnostic ``BENIGN_NATIVE_NOISE_MARKERS`` so the
# filtering is explicitly scoped to ``badauth.ntlm`` — in particular the bare
# ``Flags:`` marker must NOT drop ``badauth.kerberos`` flag lines.
_NTLM_HANDSHAKE_NOISE_MARKERS: tuple[str, ...] = (
    "Negotiate message constructed",
    "Authenticate message received",
    "KeyExchangeKey derived",
    "Setting up crypto",
    "EncryptedRandomSessionKey computed",
    "Setting Client sealkey",
    "Setting Server sealkey",
    "Setting client signkey",
    "Setting server signkey",
    "NTLMAuthenticate constructed",
    "Loading negotiate message",
    "Loading challenge message",
    "Loading authenticate message",
    # The bare ``Flags:`` line — only ever dropped under the ``badauth.ntlm``
    # scope below (Kerberos flags can matter, so they are never touched).
    "Flags:",
)


# Logger names (exact or prefix) whose DEBUG handshake chatter is filtered.
_NTLM_LOGGER_NAME = "badauth.ntlm"


def _vendor_debug_escape_hatch_enabled() -> bool:
    """Return ``True`` when the operator opted into raw vendor handshake debug.

    Reads ``ADSCAN_VENDOR_DEBUG`` at call time (not import time) so a developer
    can toggle it per-run. When set to ``"1"`` the NTLM-handshake noise tier is
    NOT applied, restoring the full ``badauth.ntlm`` DEBUG trace on the
    ``--debug`` console (the logger-agnostic benign-noise markers still apply).
    """

    return os.getenv("ADSCAN_VENDOR_DEBUG") == "1"


def is_ntlm_handshake_noise(record: logging.LogRecord) -> bool:
    """Return ``True`` for a ``badauth.ntlm`` DEBUG per-handshake state marker.

    Scoped on three axes so it never swallows anything diagnostic:

    * **Logger scope** — only ``badauth.ntlm`` records (the bare ``Flags:``
      marker must not touch ``badauth.kerberos``).
    * **Level scope** — only ``DEBUG``; a future NTLM WARNING/ERROR that happens
      to contain one of these substrings still surfaces.
    * **Escape hatch** — disabled entirely when ``ADSCAN_VENDOR_DEBUG=1``.
    """

    if _vendor_debug_escape_hatch_enabled():
        return False
    if record.levelno != logging.DEBUG:
        return False
    if record.name != _NTLM_LOGGER_NAME and not record.name.startswith(
        _NTLM_LOGGER_NAME + "."
    ):
        return False
    try:
        message = record.getMessage()
    except Exception:  # noqa: BLE001 — never break the filter on a bad record
        return False
    if not message:
        return False
    for marker in _NTLM_HANDSHAKE_NOISE_MARKERS:
        if marker in message:
            return True
    return False


class BenignNativeNoiseFilter(logging.Filter):
    """Drop benign post-teardown chatter from third-party native loggers."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003 (stdlib API)
        if not record.name.startswith(_NATIVE_STACK_LOGGER_PREFIXES):
            return True
        # Logger-scoped tier: drop the high-volume ``badauth.ntlm`` DEBUG
        # per-handshake state-machine markers (unless ADSCAN_VENDOR_DEBUG=1).
        # Kept separate from the logger-agnostic global markers below so the
        # ``Flags:`` marker never touches ``badauth.kerberos``.
        if is_ntlm_handshake_noise(record):
            return False
        message = record.getMessage()
        if record.exc_info:
            exc_type, exc_value, exc_tb = record.exc_info
            message = (
                f"{message}\n"
                f"{''.join(traceback.format_exception(exc_type, exc_value, exc_tb))}"
            )
        return not is_benign_native_noise(message)


# ---------------------------------------------------------------------------
# Secret scrubber (durable, refresh-proof safety net)
# ---------------------------------------------------------------------------
#
# LAYER 1 of the no-exfiltration defence is the vendor-source redaction (the
# ``# ADSCAN: do not dump ...`` edits in ``vendor/badauth/.../ntlm`` and
# ``.../kerberos``). LAYER 2 is :func:`scrub_native_secrets`, applied centrally
# to every line the bridge forwards (see ``_NativeStackBridgeHandler.emit``).
#
# The detector implementation now lives in the dependency-light SSOT
# ``adscan_core.native_secret_scrub`` (imported at the top of this module and
# re-exported under the historical ``scrub_native_secrets`` / ``_SECRET_LABELS``
# names) so the telemetry EXPORT path — also in ``adscan_core`` — can share the
# exact same protocol-recognizable + label-gated detectors. ``adscan_core`` must
# never import ``adscan_internal`` (the layering rule), so the shared code had to
# move down into ``adscan_core``; this module consumes it from there.


# ---------------------------------------------------------------------------
# Native-stack logging bridge
# ---------------------------------------------------------------------------


def _format_native_record(record: logging.LogRecord) -> str:
    """Render a vendor log record as a single readable line.

    Deliberately simple — ``logger name | LEVEL | message`` (plus a formatted
    traceback when ``exc_info`` is present). We do not pull in
    :class:`rich.logging.RichHandler`: the goal is a faithful, low-noise text
    line for the telemetry recording and the ``--debug`` console, not a
    second styled rendering pipeline.
    """

    try:
        message = record.getMessage()
    except Exception:  # noqa: BLE001 — never break on a malformed record
        message = str(getattr(record, "msg", ""))
    line = f"{record.name} | {record.levelname} | {message}"
    if record.exc_info:
        try:
            exc_type, exc_value, exc_tb = record.exc_info
            line = (
                f"{line}\n"
                f"{''.join(traceback.format_exception(exc_type, exc_value, exc_tb))}"
            )
        except Exception:  # noqa: BLE001
            pass
    return line


class _NativeStackBridgeHandler(logging.Handler):
    """Forward native-stack vendor records into ADscan's centralized output.

    A single shared instance is attached ONLY to the top-level prefix loggers
    in :data:`_NATIVE_STACK_LOGGER_PREFIXES` (never to their children) so a
    child record fires the bridge exactly once via propagation — see the
    "Native-stack logging bridge" section of the module docstring for the
    propagation-contract reasoning and the double-emit bug it prevents.

    Routing policy (the inverse of the old "telemetry ALWAYS DEBUG+"):

    * **Telemetry — WARNING and above only.** Vendor DEBUG/INFO is too chatty
      (per-NTLM-message granularity) to belong in every uploaded recording and
      needlessly widens the secret-exposure surface, so it is kept out of the
      always-on telemetry buffer. WARNING+ / ERROR is scrubbed for free at
      export time, plus the LAYER-2 :func:`scrub_native_secrets` applied here.
    * **Visible console — only under ``--debug`` (all levels, DEBUG+).** Routed
      via ``adscan_core.output._state.get_console()`` (a ``_TeeConsole``), but
      wrapped in ``_explicit_telemetry_mirror`` so the ``_TeeConsole``
      auto-mirror does NOT re-inject the suppressed DEBUG/INFO flood back into
      telemetry through the console path.

    Every sink is best-effort so a broken buffer can never break the
    user-visible flow.
    """

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        # Defence in depth: the same benign-noise filter the loggers already
        # carry. Cheap, and keeps the bridge correct even if a future caller
        # attaches this handler somewhere the logger-level filter is absent.
        self.addFilter(BenignNativeNoiseFilter())

    def emit(self, record: logging.LogRecord) -> None:
        try:
            line = _format_native_record(record)
        except Exception:  # noqa: BLE001
            return

        # LAYER 2 of the no-exfiltration defence: scrub protocol-recognizable
        # (NTLMSSP messages, NetNTLM hashcat lines, challenge byte-reprs) AND
        # label-gated secret material (crypto keys, Kerberos ticket/enc-part
        # blobs, NTLM/Kerberos response hashes) BEFORE the line reaches the
        # telemetry buffer or the --debug console, so a future vendor-refresh
        # that re-introduces a raw-secret dump cannot leak it. Best-effort;
        # never raises.
        line = scrub_native_secrets(line)

        # Telemetry sink — WARNING and above ONLY. Vendor DEBUG/INFO is
        # per-NTLM-message chatty and would flood every uploaded recording
        # while widening the secret-exposure surface, so it never reaches the
        # always-on telemetry buffer. What survives (WARNING+ / ERROR) is also
        # scrubbed fail-closed by the export-time sanitizer in ``telemetry.py``.
        if record.levelno >= logging.WARNING:
            try:
                from adscan_core.output._state import _get_telemetry_console

                telemetry_console = _get_telemetry_console()
                if telemetry_console is not None:
                    telemetry_console.print(line)
            except Exception:  # noqa: BLE001
                # Best-effort: a broken record buffer must never break the flow.
                pass

        # Visible sink — ONLY under ADscan debug mode (all levels, DEBUG+), so
        # the default run stays clean (premium-panel invariant). The visible
        # console is a ``_TeeConsole`` whose ``print`` auto-mirrors to
        # telemetry; left unguarded, a ``--debug`` run would re-introduce the
        # vendor DEBUG/INFO flood into the recording via this console path. So
        # we suppress the auto-mirror with the sanctioned
        # ``_explicit_telemetry_mirror`` context manager: the line shows on the
        # operator's ``--debug`` console (and, during a LiveSession, is captured
        # by the deferred-flush, which is independent of the auto-mirror
        # opt-out) but does NOT land in the uploaded telemetry buffer.
        try:
            from adscan_core.output._state import (
                _explicit_telemetry_mirror,
                get_console,
                is_debug_mode,
            )

            if is_debug_mode():
                with _explicit_telemetry_mirror():
                    get_console().print(line)
        except Exception:  # noqa: BLE001
            pass


_taming_installed = False

# Single shared bridge instance, created lazily on first install so the module
# import stays side-effect free. Reused across idempotent re-installs so we
# never attach a duplicate handler to a vendor logger.
_bridge_handler: _NativeStackBridgeHandler | None = None


# ---------------------------------------------------------------------------
# Relay log_callback factory
# ---------------------------------------------------------------------------

_PACKET_MARKERS: tuple[str, ...] = ("[PACKET]",)


# Lifecycle chatter from aiosmb relay — emitted on every connection accepted
# by the listener. Useless even at debug level: a single coercion run produces
# 8+ connections, each with [INF] Got new connection / Authenticate results /
# Stopping connection (×N). The information is captured upstream by the probe
# result (success/failure + observation) so we drop these unconditionally.
_RELAY_LIFECYCLE_MARKERS: tuple[str, ...] = (
    "[INF] Got new connection",
    "[INF] Authenticate results",
    "[INF] Stopping connection",
    "[INF] Connection end",
    "[INF] Calling authenticate_relay_server",
)


def make_relay_log_callback(context: str) -> Callable:
    """Return an async ``log_callback`` for aiosmb / badldap relay servers.

    Routes messages through ADscan's output system instead of bare ``print()``:

    - Raw packet dumps (``[PACKET]``) are dropped — they are binary noise that
      is never useful to the user.
    - Messages matching :data:`BENIGN_NATIVE_NOISE_MARKERS` are dropped
      silently (SPNEGO teardown, session-key errors, NEGTOKEN chatter, etc.).
    - ``[ERR]`` messages that survive both filters go to ``print_info_debug``
      so they appear in the debug log file without polluting the UI.
    - All other messages (``[INF]``, ``[DBG]``) go to ``print_info_debug``.

    Args:
        context: Short label shown in the debug message (e.g. ``"smb-relay"``).
    """
    from adscan_core.rich_output import print_info_debug  # local import — avoids circular at module load

    async def _cb(msg: str) -> None:
        if not msg:
            return
        for marker in _PACKET_MARKERS:
            if marker in msg:
                return
        for marker in _RELAY_LIFECYCLE_MARKERS:
            if marker in msg:
                return
        if is_benign_native_noise(msg):
            return
        # LAYER 2 secret scrub on the relay path too: relay log_callback lines
        # can carry serialized NTLM/SPNEGO blobs. Scrub before they reach the
        # debug sink (which auto-mirrors to telemetry via _TeeConsole).
        print_info_debug(f"[{context}] {scrub_native_secrets(msg)}")

    return _cb


def tame_native_stack_loggers() -> None:
    """Strip rogue handlers, install the benign-noise filter and the bridge.

    Idempotent — subsequent calls are no-ops. Safe to invoke before any of the
    native libraries are imported: loggers that do not yet exist are created
    on demand by :func:`logging.getLogger`, the (empty) handler list is left
    alone, and the filter remains in place if/when the library is loaded
    later. Once the library imports and adds its own handler, that handler is
    not retroactively stripped — call this function after ``init_logging``
    and *before* any native-stack import to guarantee a clean console.

    Two passes:

    1. **Over every name in** :data:`_NATIVE_STACK_LOGGER_NAMES` (parents AND
       children): strip rogue import-time handlers, force ``propagate=True``,
       lower the logger to ``DEBUG`` so vendor ``logger.debug()`` /
       ``logger.info()`` records are actually CREATED (otherwise NOTSET loggers
       inherit root's effective WARNING level — ``--debug`` only lowers the
       ``"adscan"`` logger, see ``logging_config.py`` — and the level check
       inside ``Logger.debug()`` drops the record before any handler sees it),
       and attach :class:`BenignNativeNoiseFilter`.
    2. **Over the top-level prefixes in** :data:`_NATIVE_STACK_LOGGER_PREFIXES`
       ONLY: attach the single shared :class:`_NativeStackBridgeHandler`
       (identity-guarded). Children deliberately do NOT carry the bridge: a
       child record propagates up to its prefix logger where the bridge fires
       exactly once. Attaching to both parent and child would double-emit every
       child record (see the module docstring's propagation-contract note).

    The bridge is purely additive; ``propagate`` is left ``True`` so the
    existing propagation contract is untouched.
    """

    global _taming_installed, _bridge_handler
    if _taming_installed:
        return

    noise_filter = BenignNativeNoiseFilter()
    if _bridge_handler is None:
        _bridge_handler = _NativeStackBridgeHandler()
    bridge_handler = _bridge_handler

    # Pass 1 — every name (parents AND children): strip rogue handlers, force
    # propagation, lower to DEBUG so records are created, install noise filter.
    # The bridge handler is intentionally NOT attached here (see Pass 2).
    for name in _NATIVE_STACK_LOGGER_NAMES:
        logger = logging.getLogger(name)
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
        logger.propagate = True
        logger.setLevel(logging.DEBUG)
        logger.addFilter(noise_filter)

    # Pass 2 — top-level prefixes ONLY: attach the single shared bridge handler.
    # A record originating on a child (e.g. ``badauth.ntlm``) propagates up to
    # its prefix logger (``badauth``), where the bridge fires EXACTLY ONCE.
    # ``Logger.callHandlers`` gates each handler during propagation solely by
    # ``record.levelno >= handler.level`` (it does NOT re-check ancestor logger
    # effective levels), and the bridge level is DEBUG — so DEBUG/INFO child
    # records still reach the prefix-attached bridge. Identity-guarded so a
    # manual re-invocation (tests / re-import) never stacks duplicates.
    for prefix in _NATIVE_STACK_LOGGER_PREFIXES:
        logger = logging.getLogger(prefix)
        if bridge_handler not in logger.handlers:
            logger.addHandler(bridge_handler)

    logging.getLogger().addFilter(noise_filter)

    _taming_installed = True
