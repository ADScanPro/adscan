"""Helpers for ADCS-dependent targets in ACL-derived attack steps."""

from __future__ import annotations

from adscan_internal import telemetry
from adscan_internal.rich_output import mark_sensitive, print_info_debug
from adscan_internal.services.privileged_group_classifier import (
    is_adcs_followup_group,
    normalize_sid,
)


def _extract_target_sid_like(target: object) -> str | None:
    """Extract a SID-like identifier from a target payload when present."""
    if isinstance(target, str):
        return normalize_sid(target)

    if not isinstance(target, dict):
        return None

    props = target.get("properties") if isinstance(target.get("properties"), dict) else {}
    candidates = [
        target.get("objectid"),
        target.get("objectId"),
        target.get("target_object_id"),
        target.get("targetObjectId"),
        target.get("targetSid"),
        props.get("objectid"),
        props.get("objectId"),
        props.get("targetObjectId"),
        props.get("targetSid"),
    ]
    for candidate in candidates:
        if isinstance(candidate, str):
            sid = normalize_sid(candidate)
            if sid:
                return sid
    return None


def _target_label_from_payload(target: object) -> str:
    """Return a best-effort human-readable label from a target payload."""
    if isinstance(target, str):
        return str(target).strip()
    if not isinstance(target, dict):
        return ""
    props = target.get("properties") if isinstance(target.get("properties"), dict) else {}
    return str(
        target.get("name")
        or target.get("label")
        or target.get("target")
        or props.get("name")
        or props.get("samaccountname")
        or ""
    ).strip()


def is_adcs_tier_zero_group(target: object) -> bool:
    """Return True when the payload represents an ADCS-related Tier Zero group.

    Detection is SID/RID-first so localized names do not affect BloodHound or
    LDAP-backed flows. English-name matching remains as a fallback for legacy
    payloads that only carry labels.
    """
    return is_adcs_followup_group(
        sid=_extract_target_sid_like(target),
        name=_target_label_from_payload(target),
    )


def target_requires_adcs(target: object, domain: str) -> bool:
    """Return True when the target is an ADCS-related Tier Zero group.

    The ``domain`` parameter is kept for backward compatibility with existing
    callers. Current detection is domain-agnostic and relies on stable RIDs.
    """
    _ = domain
    return is_adcs_tier_zero_group(target)


def path_contains_adcs_dependent_node(
    nodes: list[object],
    domain: str,
    *,
    skip_first: bool = True,
) -> bool:
    """Return True when any relevant node in the path requires ADCS.

    Args:
        nodes: Ordered path nodes.
        domain: Domain key used by legacy target checks.
        skip_first: When True, ignore the first node because it is usually the
            source principal/group, not an attack target candidate.
    """
    start_index = 1 if skip_first else 0
    for node in nodes[start_index:]:
        if target_requires_adcs(node, domain):
            return True
    return False


def domain_has_adcs_for_attack_steps(shell: object, domain: str) -> bool:
    """Return whether ADCS is known/present for ACL-derived attack steps."""
    domains_data = getattr(shell, "domains_data", None)
    if isinstance(domains_data, dict):
        domain_data = domains_data.get(domain)
        if isinstance(domain_data, dict):
            if "adcs_detected" in domain_data:
                return bool(domain_data.get("adcs_detected"))
            if domain_data.get("adcs"):
                return True

    detect_adcs = getattr(shell, "_detect_adcs", None)
    if callable(detect_adcs):
        try:
            return bool(
                detect_adcs(
                    domain,
                    silent=True,
                    emit_telemetry=False,
                    source_context="attack_path_filter",
                )
            )
        except TypeError:
            return bool(detect_adcs(domain))
        except Exception as exc:  # pragma: no cover
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[adcs-target-filter] ADCS fallback detection failed for "
                f"{mark_sensitive(domain, 'domain')}: {exc}"
            )
    return False
