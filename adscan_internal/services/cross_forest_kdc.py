"""Single source of truth for the cross-forest KDC (which DC receives the AS-REQ).

When ADscan authenticates as a principal from forest A (``auth_domain``) against a
target in a trusted forest B (``target_domain``), the credential's own AS-REQ / TGT
mint MUST go to forest A's KDC — a KDC only issues an AS-REP for principals in its
OWN realm. Sending ``svc@FORESTA`` to FORESTB's KDC yields ``KDC_ERR_WRONG_REALM`` /
``KDC_ERR_C_PRINCIPAL_UNKNOWN`` and the operation aborts or silently degrades — on a
multi-forest engagement the cross-forest half of the estate then produces an
empty / partial result on a paid scan.

Several caller seams historically collapsed the two realms by pairing the
auth-realm principal with the TARGET realm's KDC (resolved from
``domains_data[target_domain]``). :func:`resolve_auth_kdc_for_cross_forest` is the
one place that answers "which KDC receives this credential's AS-REQ", so no caller
has to re-derive it.

Resolution order (auth realm first, always):

1. ``resolve_dc_ip(domains_data[auth_domain])`` — the auth realm's own DC via the
   landed SSOT (``pdc -> dc_ip -> dcs[0] -> connectivity.summary.pdc_ip``). This is
   the correct KDC for the credential's realm.
2. ``domains_data[target_domain]["auth_kdc"]`` — the auth KDC persisted alongside the
   target-domain record during trust enumeration / scope building. Populated when the
   target was reached over a trust with a foreign credential.
3. ``resolve_dc_ip(domains_data[target_domain])`` — last resort. Only correct in the
   single-domain case (``auth_domain == target_domain``); for a genuine cross-forest
   credential this is the WRONG realm, but it preserves the pre-existing behaviour
   rather than returning ``None`` (a ``None`` KDC makes Kerberos fall back to the
   target host, which is worse).

The single-domain case (``auth_domain == target_domain`` or ``auth_domain`` falsy)
is byte-identical to ``resolve_dc_ip(domains_data[target_domain])`` — step 1 keys the
same record. So wiring this helper at a seam never regresses a same-forest sweep.

Reference implementation that already does this by hand:
``adscan_internal/cli/intelligence.py`` (``auth_kdc = domain_data.get("auth_kdc") or
auth_domain_data.get("pdc") or dc_ip``).
"""

from __future__ import annotations

from typing import Any

from adscan_internal.models.domain import resolve_dc_ip

__all__ = ["resolve_auth_kdc_for_cross_forest"]


def resolve_auth_kdc_for_cross_forest(
    domains_data: dict[str, Any] | None,
    auth_domain: str | None,
    target_domain: str | None,
) -> str | None:
    """Return the KDC IP of the CREDENTIAL's home (auth) realm.

    Args:
        domains_data: The session's ``shell.domains_data`` mapping.
        auth_domain: The domain the credential belongs to (where the user lives).
            May be ``None`` / empty in the single-domain case.
        target_domain: The domain being enumerated / attacked (the hosts' realm).

    Returns:
        The auth realm's KDC IP, or ``None`` when no DC can be resolved for any
        candidate realm. In the single-domain case this equals
        ``resolve_dc_ip(domains_data[target_domain])``.
    """
    data = domains_data if isinstance(domains_data, dict) else {}
    auth = (auth_domain or "").strip()
    target = (target_domain or "").strip()

    # 1. Auth realm's own DC (SSOT). The correct KDC for the credential's realm.
    if auth:
        auth_record = data.get(auth)
        if isinstance(auth_record, dict):
            auth_kdc = resolve_dc_ip(auth_record)
            if auth_kdc:
                return auth_kdc

    target_record = data.get(target) if target else None
    if isinstance(target_record, dict):
        # 2. auth_kdc persisted on the target record during trust enumeration.
        persisted_auth_kdc = str(target_record.get("auth_kdc") or "").strip()
        if persisted_auth_kdc:
            return persisted_auth_kdc
        # 3. Last resort: the target realm's DC (correct only single-domain).
        return resolve_dc_ip(target_record)

    return None
