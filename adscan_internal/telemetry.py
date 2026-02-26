"""Compatibility shim for telemetry helpers.

Canonical implementation: `adscan_core.telemetry`.
"""

from __future__ import annotations

from adscan_core.telemetry import *  # noqa: F403

# `adscan.py` imports a few internal helpers explicitly. Since `import *` does
# not include underscore-prefixed names, re-export them here for compatibility.
from adscan_core.telemetry import (  # noqa: F401,E402
    _build_session_metadata,
    _capture_user_property_event,
    _determine_session_environment,
    _is_telemetry_enabled,
    _sanitize_rich_output,
)
