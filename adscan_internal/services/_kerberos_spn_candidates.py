"""Dependency-inverted SPN-candidate resolver registry.

The low-level SMB transport must NOT import the workspace or the shell, yet it
needs to recover from a Kerberos AP/KDC failure caused by a STALE-DNS wrong-host
SPN: when an IP has two enabled computer A-records (e.g. a decommissioned
``CZN007`` sharing the IP with the live ``CZN012``, no reverse PTR), targeting the
stale name yields a TGS the live host rejects. The fix is to retry with the LIVE
candidate FQDN for that IP.

This registry mirrors the dependency-inversion used by ``_kerberos_recovery`` (the
clock-resync / ticket-reminter callbacks): ``PentestShell`` injects a callback that
maps ``(ip, domain) → ranked live-first FQDN candidates`` (from the workspace
``load_workspace_ip_hostname_inventory`` — ranked by lastLogonTimestamp). The
transport consults it via :func:`spn_candidates_for_ip`. With no shell registered
(unit tests, headless paths) it returns ``[]`` and the transport behaves as before.
"""

from __future__ import annotations

from typing import Callable, List, Optional

# (ip, domain) -> ranked list of live-first FQDN SPN candidates for that IP.
_resolver: Optional[Callable[[str, str], List[str]]] = None


def register_spn_candidate_resolver(
    resolver: Callable[[str, str], List[str]],
) -> None:
    """Register the IP→candidate-FQDNs resolver (injected once from the shell)."""
    global _resolver  # noqa: PLW0603 — module-level single registry, by design
    _resolver = resolver


def unregister_spn_candidate_resolver() -> None:
    """Drop the registered resolver (test isolation / teardown)."""
    global _resolver  # noqa: PLW0603
    _resolver = None


def spn_candidates_for_ip(ip: str, domain: str) -> List[str]:
    """Return ranked live-first FQDN SPN candidates for ``ip``; ``[]`` if none.

    Best-effort: never raises. An empty list means "no workspace inventory / no
    candidates" and the caller should keep its current behaviour.
    """
    resolver = _resolver
    if resolver is None or not str(ip or "").strip():
        return []
    try:
        candidates = resolver(str(ip).strip(), str(domain or "").strip())
    except Exception:  # noqa: BLE001 — resolution is best-effort
        return []
    if not candidates:
        return []
    # Defensive: dedupe (case-insensitive) preserving rank order.
    seen: set[str] = set()
    ordered: List[str] = []
    for fqdn in candidates:
        key = str(fqdn or "").strip().lower()
        if key and key not in seen:
            seen.add(key)
            ordered.append(str(fqdn).strip())
    return ordered
