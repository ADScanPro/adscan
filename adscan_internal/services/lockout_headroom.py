"""Live lockout headroom for the sign-in guard (rule 5 of ``adscan_core.auth_attempt_guard``).

The guard counts the failed sign-ins ADscan itself sent in this session. That
alone cannot keep the promise that ADscan never locks an account in a real
environment: an account that already sits one failure short of its threshold
(the user mistyped, another tool tried) is locked by ADscan's FIRST failure. So
before the first password, hash or key sign-in as a domain principal, the guard
asks this module how much headroom the domain controller leaves:

    effective threshold - reserve margin - effective badPwdCount

Every number comes from an existing single source of truth, never a second copy:

* the read itself is :func:`adscan_internal.services.spray_policy_service.fetch_spray_policy_sync`,
  the spray eligibility reader (domain policy, fine-grained password policies,
  observation-window-adjusted ``badPwdCount``, the live lock bit, case-insensitive
  attribute handling), narrowed to the principals being signed in as;
* the per-account threshold is ``SprayPolicyResult.effective_lockout``, the same
  PSO-aware resolution spraying uses, with every unknown resolved to the
  conservative assumed threshold;
* the reserve margin is ``resolve_password_attempt_rules(shell).reserve_margin``,
  the scan policy's, so no executor chooses one;
* the domain controller read is ``resolve_lockout_authority_ip`` (the PDC
  emulator, or a replica in conservative mode when the PDC cannot be reached);
* the reading principal is the domain's active credential pair through
  ``resolve_principal_credential``, authenticated through ``ensure_user_ccache``.

Lab policies get no live read (``None``), which keeps their behaviour as it was.
A counter that cannot be read is reported as unknown, never as zero, and the
guard then holds the principal to one failed sign-in per window.

A withheld sign-in is announced to the operator once per account and recorded in
the workspace (``domains_data[<domain>]["lockout_protection"]``), so a report can
state the account was skipped to avoid lockout; sign-ins judged without a
readable counter are recorded there too, so the gap is stated rather than
assumed away.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from adscan_core import telemetry
from adscan_core.auth_attempt_guard import (
    LIVE_SKIPPED,
    LiveHeadroom,
    register_live_headroom_provider,
    unknown_headroom,
)
from adscan_core.rich_output import print_exception, print_info_debug, print_warning
from adscan_core.sensitive import mark_sensitive

__all__ = [
    "LOCKOUT_PROTECTION_KEY",
    "headroom_from_spray_policy",
    "read_live_headroom",
    "record_live_headroom_event",
    "register_live_headroom_for_shell",
]

#: Where the guard's live verdicts are recorded per domain in ``domains_data``.
LOCKOUT_PROTECTION_KEY = "lockout_protection"

_AUTHENTICATED_STATES = frozenset({"auth", "pwned"})


@dataclass(frozen=True)
class _Reader:
    """The principal whose session reads the counters."""

    domain: str
    username: str
    secret: Optional[str]
    ccache_path: Optional[str]


def _source_label(lockout_source: str, *, assumed: bool, authority: str) -> str:
    label = "domain lockout policy" if lockout_source == "domain" else str(lockout_source)
    if assumed:
        label = f"{label}, threshold assumed"
    return f"{label}, read from {authority}"


def headroom_from_spray_policy(
    policy: Any,
    principals: "list[str] | tuple[str, ...]",
    *,
    margin: int,
    conservative: bool = False,
    authority: str = "the domain controller",
) -> dict[str, LiveHeadroom]:
    """Turn one ``SprayPolicyResult`` into the guard's headroom per principal.

    Args:
        policy: The result of ``fetch_spray_policy_sync`` for these principals.
        principals: Normalized (lower-case) sAMAccountNames asked for.
        margin: The scan policy's reserve margin.
        conservative: The counters came from a replica that may lag the PDC.
        authority: Which domain controller answered, for the operator line.

    A principal the read did not return (disabled, not readable by the reading
    account, unknown) is unknown, never zero failures.
    """
    from adscan_core.scan_policy.policy import CONSERVATIVE_ASSUMED_THRESHOLD  # noqa: PLC0415

    if getattr(policy, "fetch_errors", None):
        return {
            principal: unknown_headroom("the lockout policy read did not complete")
            for principal in principals
        }
    badpwd_by_user = getattr(policy, "badpwd_by_user", None) or {}
    locked_users = getattr(policy, "locked_users", None) or set()
    out: dict[str, LiveHeadroom] = {}
    for principal in principals:
        user = str(principal or "").strip().lower()
        if user not in badpwd_by_user:
            out[principal] = unknown_headroom(
                "the domain controller returned no failed sign-in count for the account"
            )
            continue
        lockout = policy.effective_lockout(
            user, conservative_threshold=CONSERVATIVE_ASSUMED_THRESHOLD
        )
        out[principal] = LiveHeadroom(
            known=True,
            threshold=int(lockout.threshold),
            bad_count=int(badpwd_by_user[user]),
            locked=user in locked_users,
            margin=max(0, int(margin)),
            conservative=bool(conservative),
            source=_source_label(lockout.source, assumed=lockout.assumed, authority=authority),
        )
    return out


def _domain_for_realm(shell: Any, realm: str) -> Optional[str]:
    from adscan_internal.services.auth_attempt_policy import (  # noqa: PLC0415
        _domain_for_realm as resolve,
    )

    return resolve(shell, realm)


def _domain_entry(shell: Any, domain: Optional[str]) -> dict[str, Any]:
    domains_data = getattr(shell, "domains_data", None)
    if not domain or not isinstance(domains_data, dict):
        return {}
    entry = domains_data.get(domain)
    return entry if isinstance(entry, dict) else {}


def _reader_for(shell: Any, domain: str) -> Optional[_Reader]:
    """The verified credential that reads ``domain``'s counters, or ``None``.

    The target domain's active pair first, then the session's own domain (a read
    across a trust), each through ``resolve_principal_credential`` so the
    username and secret always belong to one principal. A domain whose
    credential has not been verified yet has no reader: the read would itself be
    an unproven sign-in.
    """
    from adscan_internal.services.credential_store_service import (  # noqa: PLC0415
        resolve_principal_credential,
    )

    domains_data = getattr(shell, "domains_data", None)
    candidates = [domain]
    session_domain = _domain_for_realm(shell, str(getattr(shell, "domain", "") or ""))
    if session_domain and session_domain != domain:
        candidates.append(session_domain)
    for candidate in candidates:
        entry = _domain_entry(shell, candidate)
        if str(entry.get("auth", "")).strip().lower() not in _AUTHENTICATED_STATES:
            continue
        credential = resolve_principal_credential(domains_data, domain=candidate)
        if credential is None or not (credential.secret or credential.ccache_path):
            continue
        return _Reader(
            domain=candidate,
            username=credential.username,
            secret=credential.secret,
            ccache_path=credential.ccache_path,
        )
    return None


def read_live_headroom(
    shell: Any, realm: str, principals: "tuple[str, ...]"
) -> Optional[dict[str, LiveHeadroom]]:
    """The guard's live headroom provider for ``shell`` (runs on the guard's worker thread).

    Returns ``None`` when the scan policy is for a lab (no live read), else one
    :class:`LiveHeadroom` per principal, unknown wherever the counter could not
    be read. Never raises.
    """
    from adscan_core.scan_policy.policy import ENVIRONMENT_LAB  # noqa: PLC0415
    from adscan_internal.services.spray_policy_service import (  # noqa: PLC0415
        resolve_password_attempt_rules,
    )

    rules = resolve_password_attempt_rules(shell)
    if rules.environment == ENVIRONMENT_LAB:
        return None

    def _all_unknown(reason: str) -> dict[str, LiveHeadroom]:
        return {principal: unknown_headroom(reason) for principal in principals}

    domain = _domain_for_realm(shell, realm)
    if domain is None:
        return _all_unknown("the account's domain is not part of this assessment's collected data")
    reader = _reader_for(shell, domain)
    if reader is None:
        return _all_unknown(
            "no verified domain credential was available yet to read the account's "
            "failed sign-in count"
        )
    try:
        return _read_with(shell, domain, reader, principals, margin=rules.reserve_margin)
    except Exception as exc:  # noqa: BLE001 - an unreadable counter fails closed
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return _all_unknown("the lockout policy read failed")


def _read_with(
    shell: Any,
    domain: str,
    reader: _Reader,
    principals: "tuple[str, ...]",
    *,
    margin: int,
) -> dict[str, LiveHeadroom]:
    from adscan_internal.cli.spraying import resolve_lockout_authority_ip  # noqa: PLC0415
    from adscan_internal.models.domain import resolve_dc_ip  # noqa: PLC0415
    from adscan_internal.services.domain_posture import get_posture  # noqa: PLC0415
    from adscan_internal.services.ldap_transport_service import (  # noqa: PLC0415
        resolve_ldap_target_endpoints,
    )
    from adscan_internal.services.spray_policy_service import (  # noqa: PLC0415
        fetch_spray_policy_sync,
    )

    domain_data = _domain_entry(shell, domain)
    target = resolve_lockout_authority_ip(shell, domain)
    dc_ip = target.read_ip or resolve_dc_ip(domain_data)
    if not dc_ip:
        return {
            principal: unknown_headroom("no domain controller address is known for the domain")
            for principal in principals
        }
    kerberos_target_hostname = (
        target.kerberos_hostname
        if target.is_authoritative_pdc
        else resolve_ldap_target_endpoints(
            target_domain=domain, domain_data=domain_data, kerberos_ready=True
        ).kerberos_target_hostname
    )
    authority = (
        "a replica domain controller (the PDC emulator was not reachable)"
        if target.conservative
        else "the domain controller that holds the lockout counters"
    )
    cross_realm = reader.domain != domain
    auth_kdc = resolve_dc_ip(_domain_entry(shell, reader.domain)) if cross_realm else None

    ccache_path = reader.ccache_path if not reader.secret else None
    password = reader.secret
    if reader.secret and not cross_realm:
        # Authenticating as a named principal goes through the ccache SSOT: one
        # TGT for the reader, reused by every later read.
        from adscan_internal.services.kerberos_ticket_service import (  # noqa: PLC0415
            ensure_user_ccache,
        )

        minted = ensure_user_ccache(
            shell,
            user=reader.username,
            domain=reader.domain,
            credential=reader.secret,
            dc_ip=resolve_dc_ip(domain_data),
        )
        if minted:
            ccache_path, password = minted, None

    users = [p for p in principals if not str(p).endswith("$")]
    computers = [p for p in principals if str(p).endswith("$")]
    out: dict[str, LiveHeadroom] = {}
    for scope, names in (("user", users), ("computer", computers)):
        if not names:
            continue
        policy = fetch_spray_policy_sync(
            domain=domain,
            dc_ip=dc_ip,
            username=reader.username,
            password=password,
            use_kerberos=True,
            kerberos_target_hostname=kerberos_target_hostname,
            auth_domain=reader.domain,
            auth_kdc=auth_kdc,
            account_scope=scope,
            only_accounts=names,
            ccache_path=ccache_path,
            posture_snapshot=get_posture(getattr(shell, "domains_data", {}), domain=domain),
        )
        out.update(
            headroom_from_spray_policy(
                policy,
                names,
                margin=margin,
                conservative=target.conservative,
                authority=authority,
            )
        )
    known = sum(1 for headroom in out.values() if headroom.known)
    print_info_debug(
        f"[lockout-headroom] domain={mark_sensitive(domain, 'domain')} "
        f"accounts={len(principals)} read={known} conservative={target.conservative}"
    )
    return out


def record_live_headroom_event(
    shell: Any, realm: str, principal: str, kind: str, headroom: LiveHeadroom
) -> None:
    """The guard's sink: tell the operator and record the verdict in the workspace."""
    domain = _domain_for_realm(shell, realm) or str(realm or "").lower()
    marked = f"{mark_sensitive(principal, 'user')}@{mark_sensitive(domain, 'domain')}"
    if kind == LIVE_SKIPPED:
        if headroom.locked:
            why = "the domain controller reports it locked out right now"
        else:
            why = (
                f"the domain controller already counts {int(headroom.bad_count or 0)} failed "
                f"sign-in(s) against a lockout threshold of {int(headroom.threshold or 0)}"
            )
        print_warning(f"Skipped signing in as {marked} to avoid locking the account, because {why}.")
        detail: dict[str, Any] = {
            "reason": "locked_out" if headroom.locked else "no_lockout_headroom",
            "failed_sign_ins": headroom.bad_count,
            "lockout_threshold": headroom.threshold,
            "reserve_margin": headroom.margin,
            "source": headroom.source,
        }
        bucket = "skipped_sign_ins"
    else:
        print_info_debug(
            f"[lockout-headroom] sign-in as {marked} judged without a readable "
            f"failed sign-in count: {headroom.source}"
        )
        detail = {"reason": "counter_unreadable", "source": headroom.source}
        bucket = "unverified_sign_ins"
    entry = _domain_entry(shell, domain)
    if not entry:
        return
    protection = entry.setdefault(LOCKOUT_PROTECTION_KEY, {})
    if isinstance(protection, dict):
        protection.setdefault(bucket, {})[str(principal).lower()] = detail


def register_live_headroom_for_shell(shell: Any) -> None:
    """Install the live read and its sink for this session (from ``register_auth_attempt_guard_for_shell``)."""

    def _provider(realm: str, principals: "tuple[str, ...]") -> Optional[dict[str, LiveHeadroom]]:
        return read_live_headroom(shell, realm, principals)

    def _sink(realm: str, principal: str, kind: str, headroom: LiveHeadroom) -> None:
        try:
            record_live_headroom_event(shell, realm, principal, kind, headroom)
        except Exception as exc:  # noqa: BLE001 - reporting never blocks a sign-in verdict
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    register_live_headroom_provider(_provider, _sink)
