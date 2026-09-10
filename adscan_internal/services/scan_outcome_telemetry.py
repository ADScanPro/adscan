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

import glob
import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Any

from adscan_core.lab_context import build_workspace_telemetry_fields
from adscan_core.version_context import get_installed_version
from adscan_internal import telemetry
from adscan_internal.cli.common import build_lab_event_fields
from adscan_internal.services.domain_posture import (
    ConstraintCategory,
    TriState,
    get_posture,
)
from adscan_internal.services.path_state import PathState
from adscan_internal.services.session_ad_scale_metadata import (
    build_session_ad_scale_metadata,
)
from adscan_internal.services.session_compromise_state_service import (
    SESSION_COMPROMISE_STATUS_DOMAIN,
    SESSION_COMPROMISE_STATUS_USER,
    normalize_session_compromise_status,
    session_reached_domain_compromise,
)
from adscan_core.rich_output import print_exception
from adscan_internal.workspaces.io import read_json_file

# Per-scan outcome tiers (PostHog-queryable enum).
SCAN_OUTCOME_DOMAIN_COMPROMISED = "domain_compromised"
SCAN_OUTCOME_CRED_OBTAINED = "cred_obtained"
SCAN_OUTCOME_ENUMERATION_ONLY = "enumeration_only"

SCAN_OUTCOME_EVENT = "scan_outcome"

# CTF flag kinds ADscan persists, mapped to the bare-text file the collector
# writes at the WORKSPACE-ROOT ``flags/`` dir. Mirrors the convention in
# tests/lab/shared/workspace_snapshot.py::_CTF_FLAG_FILES.
_CTF_FLAG_FILES = {"user": "user.txt", "root": "root.txt", "system": "system.txt"}

# CTF flag value format: 32-character hexadecimal (case-insensitive).
# Mirrors tests/lab/shared/workspace_snapshot.py::_FLAG_VALUE_RE.
_FLAG_VALUE_RE = re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE)

# Ordinal rank of each PathState value, in the enum's own declared
# least-advanced -> most-advanced order. Used to pick the single most
# advanced status across every domain's attack-path snapshot.
_PATH_STATE_RANK: dict[str, int] = {
    state.value: idx for idx, state in enumerate(PathState)
}


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
    # SSOT reconciliation: promote to domain-compromise when ANY domain in the
    # workspace is proven-pwned (e.g. a trusted secondary domain owned via a
    # cross-domain path whose promotion never threaded the in-memory session
    # marker). Never downgrade. Mirrors build_session_compromise_metadata.
    if status != SESSION_COMPROMISE_STATUS_DOMAIN and session_reached_domain_compromise(
        shell
    ):
        status = SESSION_COMPROMISE_STATUS_DOMAIN
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

    # ``type`` above is NOT in the telemetry sanitizer's safe-string set, so it
    # arrives pseudonymized and the whole event cannot be filtered down to real
    # audits. ``workspace_type`` is the safe-listed field; emit it through the
    # shared normalizer so every event names the audit/ctf split identically.
    # ``type`` is kept for continuity with existing queries.
    properties.update(
        build_workspace_telemetry_fields(workspace_type=getattr(shell, "type", None))
    )

    # Hardening signals — the "why-not" correlation context.
    properties.update(
        _build_hardening_signals(shell, _resolve_domain_for_posture(shell))
    )

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
            print_exception(exception=exc)
        except Exception:  # noqa: BLE001
            pass


def _read_attack_paths_count(ws_dir: str) -> int:
    """Sum materialized attack paths across all domain snapshots, best-effort (0 on miss).

    Each domain's snapshot lives at <ws_dir>/domains/<domain>/attack_paths_snapshot.json
    and carries a top-level "paths" list. Best-effort: missing/unreadable files are
    skipped; the function never raises.
    """
    total = 0
    try:
        pattern = os.path.join(ws_dir, "domains", "*", "attack_paths_snapshot.json")
        for snapshot_path in sorted(glob.glob(pattern)):
            try:
                snapshot = read_json_file(snapshot_path)
                paths = snapshot.get("paths") or []
                if isinstance(paths, list):
                    total += len(paths)
            except Exception:  # noqa: BLE001 - best effort per file
                pass
    except Exception:  # noqa: BLE001 - best effort on glob
        pass
    return total


def _any_domain_pwned(ws_dir: str) -> bool:
    """Return True when ANY domain is marked fully compromised on disk.

    The authoritative compromise signal is ``domains_data[<domain>]["auth"] ==
    "pwned"`` in ``variables.json`` — the single source of truth set by
    ``domain_compromise_promotion.promote_to_pwned`` when ADscan proves full
    domain compromise. This is the ground-truth override: a fully-owned domain
    is ``domain_compromised`` regardless of the per-path snapshot ``status``
    values.
    """
    try:
        variables_path = os.path.join(ws_dir, "variables.json")
        if not os.path.isfile(variables_path):
            return False
        variables = read_json_file(variables_path)
        domains_data = variables.get("domains_data") or {}
        for domain_data in domains_data.values():
            if isinstance(domain_data, dict) and domain_data.get("auth") == "pwned":
                return True
    except Exception:  # noqa: BLE001 - best effort
        pass
    return False


def _snapshot_path_state_value(path_entry: dict[str, Any]) -> str | None:
    """Return the canonical PathState value for one snapshot path entry.

    Prefers the serialized ``path_state`` field (canonical PathState vocab).
    Falls back to the display ``status`` ONLY when it overlaps the PathState
    vocab (``theoretical``).
    """
    path_state = path_entry.get("path_state")
    if path_state in _PATH_STATE_RANK:
        return path_state
    status = path_entry.get("status")
    if status in _PATH_STATE_RANK:
        return status
    return None


def _read_path_state(ws_dir: str) -> str | None:
    """Return the most-advanced PathState value for the workspace.

    Two sources, most-advanced wins:

    1. The AUTHORITATIVE compromise signal (``auth == "pwned"``) — a domain
       ADscan proved fully compromised is ``domain_compromised`` regardless of
       what the per-path snapshot values say.
    2. The snapshot's per-path canonical ``path_state`` (or overlapping
       ``status``) across every domain — the pre-existing signal, for
       partially-progressed paths on domains not (yet) marked pwned.

    Returns ``None`` when neither source yields a state, best-effort.
    """
    if _any_domain_pwned(ws_dir):
        return PathState.DOMAIN_COMPROMISED.value

    best_value: str | None = None
    best_rank = -1
    try:
        pattern = os.path.join(ws_dir, "domains", "*", "attack_paths_snapshot.json")
        for snapshot_path in sorted(glob.glob(pattern)):
            try:
                snapshot = read_json_file(snapshot_path)
                for path_entry in snapshot.get("paths") or []:
                    state = _snapshot_path_state_value(path_entry)
                    rank = _PATH_STATE_RANK.get(state, -1)
                    if rank > best_rank:
                        best_rank = rank
                        best_value = state
            except Exception:  # noqa: BLE001 - best effort per file
                pass
    except Exception:  # noqa: BLE001 - best effort on glob
        pass
    return best_value


def _read_flags(ws_dir: str) -> dict[str, bool]:
    """Map flag kind -> present, from <ws_dir>/flags/{user,root,system}.txt.

    Only the three known CTF flag kinds are considered. Each flag file must:
    - Exist at <ws_dir>/flags/<filename>
    - Be readable
    - Contain a stripped value matching 32-hex pattern (case-insensitive)

    Missing, malformed, or empty files simply omit that kind (best-effort).
    Returns presence map (kind -> True) with no flag values (secret-free).
    """
    out: dict[str, bool] = {}
    flags_dir = os.path.join(ws_dir, "flags")
    for kind, filename in _CTF_FLAG_FILES.items():
        path = os.path.join(flags_dir, filename)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as fp:
                value = fp.read().strip()
        except OSError:  # noqa: BLE001 - best effort
            continue
        if _FLAG_VALUE_RE.match(value):
            out[kind] = True
    return out


def build_scan_summary(shell: Any, command_name: str) -> dict[str, Any]:
    """Assemble the secret-free ``scan_summary.json`` payload for the proof battery.

    Reuses ``build_scan_outcome_properties`` for the timing/compromise values it
    already computes (monotonic-based), so nothing is re-measured. LITE-safe —
    no ``adscan_internal.pro`` import. Never raises.
    """
    props = build_scan_outcome_properties(shell, command_name)
    ws_dir = getattr(shell, "current_workspace_dir", "") or ""
    domain_compromised = bool(props.get("domain_compromised"))
    path_state = _read_path_state(ws_dir)
    # goal_met: domain compromise is the strong oracle; path_state terminal is a fallback.
    goal_met = domain_compromised or path_state == "domain_compromised"
    return {
        "machine": getattr(shell, "current_workspace", None),
        "domain": _resolve_domain_for_posture(shell),
        "adscan_version": get_installed_version(),
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "goal_met": bool(goal_met),
        "domain_compromised": domain_compromised,
        "compromise_status": props.get("compromise_status"),
        "time_to_compromise_minutes": props.get("time_to_compromise_minutes"),
        "time_to_first_cred_minutes": props.get("time_to_first_cred_minutes"),
        "duration_minutes": props.get("duration_minutes"),
        "attack_paths_count": _read_attack_paths_count(ws_dir),
        "path_state": path_state,
        "flags": _read_flags(ws_dir),
    }


def write_scan_summary(shell: Any, command_name: str, ws_dir: str) -> str | None:
    """Write ``<ws_dir>/scan_summary.json``. Best-effort; returns path or None."""
    try:
        summary = build_scan_summary(shell, command_name)
        path = os.path.join(ws_dir, "scan_summary.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2, sort_keys=True)
        return path
    except Exception as exc:  # noqa: BLE001 - best effort
        print_exception(exception=exc)
        return None
