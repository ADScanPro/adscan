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
    _get_known_base_dns,
    _get_known_domains,
    _get_known_hostnames,
    _get_known_netbios,
    _get_known_passwords,
    _get_known_users,
    _is_telemetry_enabled,
    _maybe_sanitize_rich_output,
    _pseudonymize_value,
    _refresh_workspace_cache_if_needed,
    _sanitize_rich_output,
)
