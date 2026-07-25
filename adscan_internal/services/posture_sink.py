"""Shared posture sink type alias and workspace-sink factory.

Transports (``kerberos_transport``, ``ldap_transport_service``, and — in PR4 —
``smb_transport``) emit :class:`PostureSignal` instances through a sink
callable. To keep the transport modules decoupled from workspace state,
the sink type and the workspace-backed factory live here so every transport
imports from the same place.

This module deliberately stays free of any transport-specific code; it is the
single bridge between the typed posture API in
:mod:`adscan_internal.services.domain_posture` and the side-effects callers
choose to wire (workspace persistence, CLI panel rendering, etc.).
"""

from __future__ import annotations

from typing import Callable, Optional

from adscan_core import telemetry
from adscan_core.rich_output import print_info_debug
from adscan_internal.services.domain_posture import (
    IntelligenceFinding,
    PostureSignal,
)
from adscan_core.rich_output import print_exception


PostureSink = Callable[[PostureSignal], Optional[IntelligenceFinding]]
"""Callable that consumes a posture signal and may return a finding.

Transports stay decoupled from workspace state: when a sink is provided,
posture observations flow through it; when ``None``, signals are dropped.
"""


def make_workspace_posture_sink(
    domains_data: dict,
    *,
    on_finding: Optional[Callable[[IntelligenceFinding], None]] = None,
) -> PostureSink:
    """Build a posture sink that writes to the workspace ``domains_data`` map.

    The transport stays decoupled: callers wire this sink into their config's
    ``posture_sink`` field to persist signals, and optionally pass an
    ``on_finding`` callback to render the future Intelligence Update CLI panel
    (PR5).

    Args:
        domains_data: The shell's ``domains_data`` mapping (mutable; mutated
            in place via
            :func:`adscan_internal.services.domain_posture.update_posture`).
        on_finding: Optional callback invoked once for first-time discoveries
            (the ``IntelligenceFinding`` returned by ``update_posture``).
            ``None`` → silent persistence only.

    Returns:
        A :data:`PostureSink` suitable for any transport's ``posture_sink``
        config field.
    """
    from adscan_internal.services.domain_posture import update_posture as _update

    def _sink(signal: PostureSignal) -> Optional[IntelligenceFinding]:
        try:
            finding = _update(domains_data, signal=signal)
            if finding is not None and on_finding is not None:
                try:
                    on_finding(finding)
                except Exception as cb_exc:
                    telemetry.capture_exception(cb_exc)
                    print_exception(exception=cb_exc)
                    print_info_debug(
                        f"[posture_sink] on_finding callback raised: "
                        f"{type(cb_exc).__name__}: {cb_exc}"
                    )
            return finding
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(f"[posture_sink] sink failed: {type(exc).__name__}: {exc}")
            return None

    return _sink
