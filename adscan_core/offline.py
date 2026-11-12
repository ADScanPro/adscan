"""Single source of truth for the global offline / no-external kill switch.

This lives in ``adscan_core`` (the dependency-light base layer) so BOTH the
telemetry engine (``adscan_core.telemetry``) and the weakpass guard
(``adscan_internal.services.weakpass_service``) consume one definition of
"are we offline". Before this module the offline predicate lived only in
``weakpass_service``; telemetry could not import it (layering: adscan_core must
not import adscan_internal), so ``ADSCAN_OFFLINE`` gated weakpass but NOT
telemetry — an air-gapped engagement still phoned home. Both consumers now
import from here.

When the switch is active, ADscan must never reach ANY external network
service: weakpass lookups, wordlist downloads, telemetry sends, session-recording
uploads, or draining a previously-queued telemetry payload.
"""

from __future__ import annotations

import os

# Either var, set to a truthy value, forces fully OFF. ``ADSCAN_NO_EXTERNAL`` is
# an explicit alias of ``ADSCAN_OFFLINE`` kept for clarity in customer
# engagements.
OFFLINE_ENV_VARS: tuple[str, ...] = ("ADSCAN_OFFLINE", "ADSCAN_NO_EXTERNAL")
_TRUTHY_VALUES: frozenset[str] = frozenset({"1", "true", "yes"})


def offline_mode_enabled(*, env: dict[str, str] | None = None) -> bool:
    """Return True if the global offline kill switch is active.

    Honours ``ADSCAN_OFFLINE`` and its alias ``ADSCAN_NO_EXTERNAL`` (both accept
    ``1`` / ``true`` / ``yes``, case-insensitive).

    Args:
        env: Optional environment mapping to inspect instead of ``os.environ``.
    """
    source = os.environ if env is None else env
    for name in OFFLINE_ENV_VARS:
        if str(source.get(name, "")).strip().lower() in _TRUTHY_VALUES:
            return True
    return False


# The telemetry kill switch the launcher seam sets (``adscan ci --no-telemetry``)
# and the hardened appliance pins. Only the exact value ``"0"`` disables, which is
# how ``adscan_core.telemetry._is_telemetry_enabled`` has always read it.
TELEMETRY_ENV_VAR = "ADSCAN_TELEMETRY"


def telemetry_disabled_by_environment(*, env: dict[str, str] | None = None) -> bool:
    """Return True when the process environment forbids telemetry outright.

    This is the environment half of the telemetry gate: the offline kill switch
    (which turns telemetry off with everything else) or ``ADSCAN_TELEMETRY=0``.
    No persisted preference, CLI override or UI toggle can re-enable telemetry
    while it holds, which is what lets a deployment (the hardened appliance)
    enforce the posture instead of merely defaulting to it. The telemetry engine
    consults it first, and the web backend reads it to report the toggle as
    locked.

    Args:
        env: Optional environment mapping to inspect instead of ``os.environ``.
    """
    if offline_mode_enabled(env=env):
        return True
    source = os.environ if env is None else env
    return source.get(TELEMETRY_ENV_VAR) == "0"
