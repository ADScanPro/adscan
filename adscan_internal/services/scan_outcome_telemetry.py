"""Per-scan ``scan_outcome`` telemetry — compromise tier + why-not hardening signals.

Pure analytics. Emitted exactly once at each scan-completion seam
(``start_unauth`` / ``start_auth`` in :mod:`adscan_internal.cli.start`).

It COMPLEMENTS — never duplicates — the existing point-in-time events:

* ``first_cred_found``  (``cli/creds.py``) — fires the moment the FIRST
  non-self-introduced credential lands.
* ``domain_compromise`` (``services/domain_compromise_promotion.py``) — fires the
  moment the domain is owned.
* ``scan_complete``     (``adscan.py``) — per-DOMAIN case-study metrics.

``scan_outcome`` is the per-SCAN summary keyed on the session compromise TIER, so
PostHog can query the compromise RATE and correlate a NON-compromise with the
target's hardening posture ("why not") directly, instead of inferring the outcome
from a session-review heuristic (which under-reports cred-only and foothold cases).

Secret-free by construction: the payload carries ONLY booleans, integer counts,
tier labels, and durations — never usernames, hostnames, domains, hashes, or SIDs.
Best-effort: any error is captured via ``telemetry.capture_exception`` and never
breaks the scan flow.
"""

from __future__ import annotations

import time
from typing import Any

from adscan_internal import telemetry
from adscan_internal.cli.common import build_lab_event_fields
from adscan_internal.services.domain_posture import (
    ConstraintCategory,
    TriState,
    get_posture,
)
from adscan_internal.services.session_ad_scale_metadata import (
    build_session_ad_scale_metadata,
)
from adscan_internal.services.session_compromise_state_service import (
    SESSION_COMPROMISE_STATUS_DOMAIN,
    SESSION_COMPROMISE_STATUS_USER,
    normalize_session_compromise_status,
)

# Per-scan outcome tiers (PostHog-queryable enum).
SCAN_OUTCOME_DOMAIN_COMPROMISED = "domain_compromised"
SCAN_OUTCOME_CRED_OBTAINED = "cred_obtained"
SCAN_OUTCOME_ENUMERATION_ONLY = "enumeration_only"

SCAN_OUTCOME_EVENT = "scan_outcome"


def _derive_outcome(status: str) -> str:
    """Map the normalized session compromise status to a per-scan outcome tier.

    * ``DOMAIN`` → :data:`SCAN_OUTCOME_DOMAIN_COMPROMISED`
    * ``USER``   → :data:`SCAN_OUTCOME_CRED_OBTAINED`
    * ``NONE`` / ``UNKNOWN`` → :data:`SCAN_OUTCOME_ENUMERATION_ONLY`
    """
    if status == SESSION_COMPROMISE_STATUS_DOMAIN:
        return SCAN_OUTCOME_DOMAIN_COMPROMISED
    if status == SESSION_COMPROMISE_STATUS_USER:
        return SCAN_OUTCOME_CRED_OBTAINED
    return SCAN_OUTCOME_ENUMERATION_ONLY


def _resolve_domain_for_posture(shell: Any) -> str | None:
    """Best-effort resolve the scan's primary domain for the posture read.

    Prefers ``shell.domain`` when it is a real key in ``domains_data``; otherwise
    adopts the single loaded domain when ``domains_data`` holds exactly one. Never
    raises. Returns ``None`` when no unambiguous domain is available (the hardening
    signals then simply degrade to their unknown defaults).
    """
    try:
        domains_data = getattr(shell, "domains_data", None)
        if not isinstance(domains_data, dict) or not domains_data:
            return None
        current = getattr(shell, "domain", None)
        if isinstance(current, str) and current in domains_data:
            return current
        if len(domains_data) == 1:
            only = next(iter(domains_data))
            if isinstance(only, str) and only:
                return only
    except Exception:  # noqa: BLE001 - pure read, never breaks the caller
        return None
    return None


def _elapsed_minutes(start: Any, end: Any) -> float | None:
    """Return ``(end - start)`` in minutes (rounded) or ``None`` when unusable.

    Both timestamps are ``time.monotonic()`` values recorded on the shell.
    """
    if not isinstance(start, (int, float)) or not isinstance(end, (int, float)):
        return None
    return round(max(0.0, float(end) - float(start)) / 60.0, 2)


def _build_hardening_signals(shell: Any, domain: str | None) -> dict[str, Any]:
    """Return telemetry-safe hardening booleans/labels for the "why-not" context.

    Each constraint contributes a definitive boolean (``True`` only when the
    hardened state is OBSERVED and still fresh — via ``effective_state``) plus a
    tri-state label so PostHog can distinguish "known-not-hardened" from "unknown".
    A ``hardening_signals_count`` rolls up the definitively-present constraints so
    a non-compromise can be correlated with environment hardening at a glance.

    Never raises; on any failure returns ``posture_known=False`` with all booleans
    ``False`` and labels ``"unknown"``.
    """
    # Category → (property stem, TriState that means "hardened").
    hardened_by_category: tuple[tuple[ConstraintCategory, str, TriState], ...] = (
        (ConstraintCategory.NTLM_AUTHENTICATION, "ntlm_disabled", TriState.DISABLED),
        (ConstraintCategory.KERBEROS_AES_ONLY, "aes_only", TriState.ENABLED),
        (ConstraintCategory.LDAP_SIGNING, "ldap_signing_required", TriState.REQUIRED),
        (
            ConstraintCategory.LDAP_CHANNEL_BINDING,
            "ldap_channel_binding_required",
            TriState.REQUIRED,
        ),
        (ConstraintCategory.SMB_SIGNING, "smb_signing_required", TriState.REQUIRED),
    )

    signals: dict[str, Any] = {}
    try:
        domains_data = getattr(shell, "domains_data", None)
        posture = get_posture(domains_data, domain=str(domain or ""))
        hardened_count = 0
        for category, stem, hardened_state in hardened_by_category:
            state = posture.get(category).effective_state
            is_hardened = state is hardened_state
            signals[stem] = is_hardened
            signals[f"{stem}_state"] = str(state.value)
            if is_hardened:
                hardened_count += 1

        # LDAPS availability is a capability, not a hardening control — capture it
        # for context (a hardened DC that still offers LDAPS vs one that does not).
        ldaps_state = posture.get(ConstraintCategory.LDAPS_AVAILABLE).effective_state
        signals["ldaps_available"] = ldaps_state is TriState.ENABLED
        signals["ldaps_available_state"] = str(ldaps_state.value)

        signals["hardening_signals_count"] = hardened_count
        signals["posture_known"] = any(
            posture.get(category).effective_state is not TriState.UNKNOWN
            for category, _stem, _hardened in hardened_by_category
        )
        return signals
    except Exception:  # noqa: BLE001 - analytics, never breaks the scan
        # Degrade to a fully-unknown, secret-free payload.
        fallback: dict[str, Any] = {
            "hardening_signals_count": 0,
            "posture_known": False,
        }
        for _category, stem, _hardened in hardened_by_category:
            fallback[stem] = False
            fallback[f"{stem}_state"] = str(TriState.UNKNOWN.value)
        fallback["ldaps_available"] = False
        fallback["ldaps_available_state"] = str(TriState.UNKNOWN.value)
        return fallback


def build_scan_outcome_properties(shell: Any, command_name: str) -> dict[str, Any]:
    """Assemble the secret-free ``scan_outcome`` property payload.

    Pure builder (no capture), so it is directly unit-testable. Never raises for
    missing shell attributes — every read is defensive.
    """
    status = normalize_session_compromise_status(
        getattr(shell, "_session_compromise_status", None)
    )
    outcome = _derive_outcome(status)

    scan_start = getattr(shell, "scan_start_time", None)
    first_cred_time = getattr(shell, "_scan_first_credential_time", None)
    compromise_time = getattr(shell, "_scan_compromise_time", None)

    now = time.monotonic()
    first_cred = bool(first_cred_time) or status in {
        SESSION_COMPROMISE_STATUS_USER,
        SESSION_COMPROMISE_STATUS_DOMAIN,
    }

    properties: dict[str, Any] = {
        "command": str(command_name),
        "outcome": outcome,
        "compromise_status": status,
        "first_cred": first_cred,
        "domain_compromised": status == SESSION_COMPROMISE_STATUS_DOMAIN,
        "scan_mode": getattr(shell, "scan_mode", None),
        "type": getattr(shell, "type", None),
        "auto": bool(getattr(shell, "auto", False)),
        "duration_minutes": _elapsed_minutes(scan_start, now),
        "time_to_first_cred_minutes": _elapsed_minutes(scan_start, first_cred_time),
        "time_to_compromise_minutes": _elapsed_minutes(scan_start, compromise_time),
    }

    # Hardening signals — the "why-not" correlation context.
    properties.update(_build_hardening_signals(shell, _resolve_domain_for_posture(shell)))

    # Anonymous AD-scale counts for scale segmentation (counts only, no names).
    try:
        properties.update(build_session_ad_scale_metadata(shell))
    except Exception:  # noqa: BLE001 - best effort
        pass

    # Shared lab identification fields.
    try:
        properties.update(build_lab_event_fields(shell=shell, include_slug=True))
    except Exception:  # noqa: BLE001 - best effort
        pass

    return properties


def emit_scan_outcome(shell: Any, command_name: str) -> None:
    """Emit the per-scan ``scan_outcome`` PostHog event (single source of truth).

    Called once at each scan-completion seam. Unconditional (analytics) and fully
    best-effort — any failure is captured and swallowed so it can never break the
    scan.

    Args:
        shell: The active ``PentestShell``.
        command_name: The originating command (``"start_unauth"`` / ``"start_auth"``).
    """
    try:
        properties = build_scan_outcome_properties(shell, command_name)
        telemetry.capture(SCAN_OUTCOME_EVENT, properties)
    except Exception as exc:  # noqa: BLE001 - analytics must never break the scan
        try:
            telemetry.capture_exception(exc)
        except Exception:  # noqa: BLE001
            pass
