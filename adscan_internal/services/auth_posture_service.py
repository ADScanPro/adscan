"""Persistent authentication posture helpers for domain runtime state.

This module stores high-signal evidence about whether NTLM appears enabled or
disabled for one domain or protocol. The state is intentionally probabilistic:
ADscan should remember observed behavior and bias future auth decisions without
claiming absolute truth from a single tool error.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping


AuthPostureStatus = str
_VALID_NTLM_STATUSES = {"unknown", "likely_enabled", "likely_disabled"}


@dataclass(frozen=True)
class AuthPostureUpdate:
    """Result of persisting one auth-posture signal."""

    domain: str
    protocol: str | None
    status_before: AuthPostureStatus
    status_after: AuthPostureStatus
    domain_status_before: AuthPostureStatus
    domain_status_after: AuthPostureStatus
    changed: bool
    should_notify_user: bool


def get_ntlm_status(
    domains_data: Mapping[str, Any] | None,
    *,
    domain: str | None,
    protocol: str | None = None,
) -> AuthPostureStatus:
    """Return the persisted NTLM posture for a domain/protocol.

    Resolution order:
    1. protocol-specific status
    2. domain-wide status
    3. ``"unknown"``
    """
    domain_entry = _get_domain_entry(domains_data, domain)
    if not isinstance(domain_entry, dict):
        return "unknown"

    posture = domain_entry.get("auth_posture")
    if not isinstance(posture, dict):
        return "unknown"

    ntlm = posture.get("ntlm")
    if not isinstance(ntlm, dict):
        return "unknown"

    protocol_key = str(protocol or "").strip().lower()
    if protocol_key:
        protocol_status = (
            ntlm.get("protocols", {})
            if isinstance(ntlm.get("protocols"), dict)
            else {}
        )
        value = str(protocol_status.get(protocol_key) or "").strip().lower()
        if value in _VALID_NTLM_STATUSES and value != "unknown":
            return value

    value = str(ntlm.get("domain_status") or "").strip().lower()
    if value in _VALID_NTLM_STATUSES:
        return value
    return "unknown"


def record_ntlm_disabled_signal(
    domains_data: dict[str, Any] | None,
    *,
    domain: str | None,
    protocol: str | None,
    source: str,
    signal: str,
    message: str | None = None,
) -> AuthPostureUpdate | None:
    """Persist evidence that NTLM looks disabled/unsupported."""
    return _record_ntlm_evidence(
        domains_data,
        domain=domain,
        protocol=protocol,
        new_status="likely_disabled",
        source=source,
        signal=signal,
        message=message,
    )


def record_ntlm_enabled_signal(
    domains_data: dict[str, Any] | None,
    *,
    domain: str | None,
    protocol: str | None,
    source: str,
    signal: str = "ntlm_success",
    message: str | None = None,
) -> AuthPostureUpdate | None:
    """Persist evidence that NTLM succeeded for a domain/protocol."""
    return _record_ntlm_evidence(
        domains_data,
        domain=domain,
        protocol=protocol,
        new_status="likely_enabled",
        source=source,
        signal=signal,
        message=message,
    )


def _record_ntlm_evidence(
    domains_data: dict[str, Any] | None,
    *,
    domain: str | None,
    protocol: str | None,
    new_status: AuthPostureStatus,
    source: str,
    signal: str,
    message: str | None,
) -> None:
    """Upsert one auth posture evidence entry into ``domains_data``."""
    if not isinstance(domains_data, dict):
        return None
    domain_key = str(domain or "").strip()
    if not domain_key:
        return None

    domain_entry = domains_data.setdefault(domain_key, {})
    if not isinstance(domain_entry, dict):
        return None

    posture = domain_entry.setdefault("auth_posture", {})
    if not isinstance(posture, dict):
        return None

    ntlm = posture.setdefault("ntlm", {})
    if not isinstance(ntlm, dict):
        return None

    protocol_key = str(protocol or "").strip().lower()
    protocol_status_before = get_ntlm_status(domains_data, domain=domain_key, protocol=protocol_key or None)
    domain_status_before = str(ntlm.get("domain_status") or "unknown").strip().lower()
    if domain_status_before not in _VALID_NTLM_STATUSES:
        domain_status_before = "unknown"

    if protocol_key:
        protocols = ntlm.setdefault("protocols", {})
        if isinstance(protocols, dict):
            protocols[protocol_key] = new_status

    ntlm["domain_status"] = _merge_ntlm_status(domain_status_before, new_status)
    ntlm["updated_at"] = _utc_now_iso()
    domain_status_after = str(ntlm.get("domain_status") or "unknown").strip().lower()
    if domain_status_after not in _VALID_NTLM_STATUSES:
        domain_status_after = "unknown"

    evidence = ntlm.setdefault("evidence", [])
    if isinstance(evidence, list):
        evidence.append(
            {
                "source": str(source or "").strip() or "unknown",
                "protocol": protocol_key or None,
                "signal": str(signal or "").strip() or "unknown",
                "message": str(message or "").strip() or None,
                "status": new_status,
                "timestamp": _utc_now_iso(),
            }
        )
        if len(evidence) > 20:
            del evidence[:-20]

    user_notice_emitted = bool(ntlm.get("user_notice_emitted_disabled"))
    should_notify_user = (
        new_status == "likely_disabled"
        and domain_status_before != "likely_disabled"
        and domain_status_after == "likely_disabled"
        and not user_notice_emitted
    )
    if should_notify_user:
        ntlm["user_notice_emitted_disabled"] = True

    status_after = get_ntlm_status(domains_data, domain=domain_key, protocol=protocol_key or None)
    return AuthPostureUpdate(
        domain=domain_key,
        protocol=protocol_key or None,
        status_before=protocol_status_before,
        status_after=status_after,
        domain_status_before=domain_status_before,
        domain_status_after=domain_status_after,
        changed=(protocol_status_before != status_after) or (domain_status_before != domain_status_after),
        should_notify_user=should_notify_user,
    )


def _merge_ntlm_status(
    current_status: AuthPostureStatus,
    new_status: AuthPostureStatus,
) -> AuthPostureStatus:
    """Merge one new NTLM signal into the domain-wide status."""
    if current_status == new_status:
        return current_status
    if current_status == "unknown":
        return new_status
    return current_status


def _get_domain_entry(
    domains_data: Mapping[str, Any] | None,
    domain: str | None,
) -> Mapping[str, Any] | None:
    """Resolve one domain entry from a case-insensitive ``domains_data`` mapping."""
    if not isinstance(domains_data, Mapping):
        return None
    domain_key = str(domain or "").strip()
    if not domain_key:
        return None
    if domain_key in domains_data:
        entry = domains_data.get(domain_key)
        return entry if isinstance(entry, Mapping) else None

    normalized = domain_key.casefold()
    for key, value in domains_data.items():
        if str(key).strip().casefold() == normalized and isinstance(value, Mapping):
            return value
    return None


def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()
