"""Kerberos ccache renewal at the transport auth seam — single source of truth.

An explicit ``ccache_path`` handed to a transport is a *ticket*, and tickets
expire. Before this module, an expired one was used anyway: the transport logged
``expired=True ... past starttime`` and then bound with it, the KDC answered
``KRB_AP_ERR_TKT_EXPIRED``, and the attack step died — even when the principal's
password was one AS-REQ away in the credential store.

The reactive half of the recovery already existed (``_kerberos_recovery``'s
realm-keyed expiry reminter), but it was gated on the presence of a
``CredentialContext``. That gate conflated two unrelated facts: "this ticket
carries capability a re-mint would destroy" and "this caller happened not to
build a CredentialContext". Every ordinary caller that passes a bare
``ccache_path`` — the LAPS reader, the ACL/exploit helpers, the attack-path
executors — fell on the wrong side of it and lost renewal.

This module supplies the missing facts, and does so at the **auth seam** rather
than per caller, mirroring the clock-sync doctrine (CLAUDE.md § Clock-skew
recovery 1a): each Kerberos transport calls :func:`prepare_ccache_for_bind` at
its own connect seam, so ticket renewal is a property of the seam and no caller
— present or future — can forget it.

Three questions, answered once:

1. **Is this ccache capability-bearing?** Decided by the explicit markers, never
   by the absence of a context: the ESC13 PAC-injected TGT marker
   (``credential_store_service.get_capability_bearing_ccache``) and the scoped
   S4U/RBCD/silver ``ServiceTicket`` store. Those are used as-is and are NEVER
   re-minted — a fresh AS-REQ would drop the synthetic group SID or the
   impersonated principal that IS the capability.
2. **Is it already expired?** Read from the ticket itself. Binding with a ticket
   we have just proven dead, and then recovering from the error, is strictly
   worse than renewing first.
3. **Can it be renewed?** Through :func:`ensure_user_ccache` — the SSOT for
   authenticating as a specific principal — which re-mints that exact principal
   from its stored secret, posture- and salt-aware.

When the answer to (3) is no, the preparation reports the ticket unusable and
the transport falls back down its own ladder (fresh Kerberos mint from a
password, then NTLM when posture does not report it disabled). The transports
own that decision; this module only supplies the verdict.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Optional

from adscan_core.rich_output import print_info_debug

#: Session shell, registered once at shell construction (dependency inversion —
#: the transports stay shell-less and call the bridge below). Mirrors
#: ``dc_time._ACTIVE_CLOCK_SHELL``.
_ACTIVE_RENEWAL_SHELL: Any = None

#: A ticket within this many seconds of its endtime is treated as expired: a
#: bind that starts now would very likely finish after the ticket dies.
_EXPIRY_GRACE_SECONDS = 60.0

#: Parsed ticket endtimes, keyed by (path, mtime, size). This runs at every
#: connect — a 2,000-host sweep would otherwise re-parse the same file 2,000
#: times — and the key changes the moment a re-mint rewrites the file, so a
#: renewed ticket is never read from a stale entry.
_ENDTIME_CACHE: dict[tuple[str, float, int], float | None] = {}


def register_ccache_renewal_for_shell(shell: Any) -> None:
    """Arm ccache renewal for this session.

    Called once from the shell constructor. Every Kerberos transport seam then
    resolves the credential store and the re-mint path through this shell
    without importing it, exactly like the clock-resync backstop.
    """
    global _ACTIVE_RENEWAL_SHELL  # noqa: PLW0603
    _ACTIVE_RENEWAL_SHELL = shell


def _shell() -> Any:
    """Return the session shell, or ``None`` when renewal is not armed."""
    return _ACTIVE_RENEWAL_SHELL


@dataclass(frozen=True)
class CcachePreparation:
    """Verdict on one explicit ccache, produced at a transport auth seam.

    Attributes:
        ccache_path: The path the transport should actually bind with. Equal to
            the input unless the ticket was renewed in place or to a new file.
        capability_bearing: The ticket carries capability a re-mint would
            destroy (marked ESC13 PAC-TGT, or a scoped service ticket). It is
            used verbatim; no reminter is armed for it.
        expired: The ticket was already past its endtime when inspected.
        renewed: A fresh TGT was minted for the principal and ``ccache_path``
            now points at it.
        usable: ``False`` only when the ticket is expired AND could not be
            renewed. The transport should then drop it and fall back down its
            own auth ladder rather than bind with a dead ticket.
    """

    ccache_path: Optional[str]
    capability_bearing: bool = False
    expired: bool = False
    renewed: bool = False
    usable: bool = True


def _normalize_path(path: str) -> str:
    """Return a comparable absolute path (never raises)."""
    try:
        return os.path.realpath(os.path.abspath(str(path).strip()))
    except Exception:  # noqa: BLE001 — comparison helper must never fail a bind
        return str(path or "").strip()


def _paths_match(left: str, right: str) -> bool:
    """True when two ccache paths refer to the same file."""
    if not left or not right:
        return False
    return _normalize_path(left) == _normalize_path(right)


def is_capability_bearing_ccache(
    *,
    ccache_path: str,
    domain: str,
    username: str | None = None,
) -> bool:
    """True when *ccache_path* carries capability a fresh mint would destroy.

    Two positive facts, never an inference from a missing credential context:

    * the ESC13 / pass-the-certificate marker written by
      ``mark_capability_bearing_ccache`` names this exact path for a principal;
    * the path belongs to a stored :class:`ServiceTicket` (S4U2Proxy/RBCD,
      constrained delegation, silver, SPN-jack), whose power is the impersonated
      principal encoded in the ticket.

    Both stores are scanned across every known domain, not just *domain*: a
    cross-realm step may bind against one domain with a ticket minted in
    another, and re-minting it there would be just as destructive.

    Returns ``False`` when renewal is not armed or the stores cannot be read —
    the conservative direction is to treat an unknown ticket as ordinary, which
    at worst re-mints a ticket that a fresh AS-REQ reproduces exactly.
    """
    path = str(ccache_path or "").strip()
    if not path:
        return False
    shell = _shell()
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return False

    from adscan_internal.services.credential_store_service import (  # noqa: PLC0415
        CredentialStoreService,
        get_capability_bearing_ccache,
    )

    candidate_domains = [d for d in list(domains_data.keys()) if isinstance(d, str)]
    marker_users = [u for u in (username, None) if u]

    for candidate_domain in candidate_domains:
        # ESC13 / PtC marker — exact principal when we know it, else every
        # principal marked in that domain.
        try:
            domain_record = domains_data.get(candidate_domain) or {}
            marker = (
                domain_record.get("capability_bearing_ccache")
                if isinstance(domain_record, dict)
                else None
            )
            if isinstance(marker, dict):
                if marker_users:
                    for user in marker_users:
                        marked = get_capability_bearing_ccache(
                            domains_data, domain=candidate_domain, username=user
                        )
                        if marked and _paths_match(marked, path):
                            return True
                for marked_path in marker.values():
                    if _paths_match(str(marked_path or ""), path):
                        return True
        except Exception:  # noqa: BLE001 — a marker read must never break a bind
            pass

        # Scoped service tickets (S4U/RBCD/silver/SPN-jack).
        try:
            tickets = CredentialStoreService().iter_service_tickets(
                domains_data=domains_data, domain=candidate_domain
            )
            for ticket in tickets:
                if _paths_match(str(getattr(ticket, "ccache_path", "") or ""), path):
                    return True
        except Exception:  # noqa: BLE001 — same contract as above
            pass

    return False


def ccache_is_expired(ccache_path: str, *, now: float | None = None) -> bool:
    """True only when the ticket file is *provably* past its usable lifetime.

    Reads the ccache with kerbad and inspects the ticket-granting credentials
    (``krbtgt/...``). The verdict is ``True`` only when every candidate ticket
    has an ``endtime`` in the past (minus a small grace so a bind that starts
    now does not die mid-flight). Any parse problem, a ccache with no
    timestamps, or an unreadable file returns ``False`` — an unproven ticket is
    left alone, so this can never discard a ticket that would have worked.
    """
    path = str(ccache_path or "").strip()
    if not path:
        return False
    try:
        stat = os.stat(path)
    except OSError:
        return False

    cache_key = (path, stat.st_mtime, stat.st_size)
    if cache_key in _ENDTIME_CACHE:
        latest_endtime = _ENDTIME_CACHE[cache_key]
    else:
        latest_endtime = _read_latest_tgt_endtime(path)
        _ENDTIME_CACHE[cache_key] = latest_endtime

    if latest_endtime is None:
        return False
    reference = float(now) if now is not None else time.time()
    return latest_endtime <= (reference + _EXPIRY_GRACE_SECONDS)


def _read_latest_tgt_endtime(path: str) -> float | None:
    """Latest ``endtime`` among the ticket-granting credentials, or ``None``.

    ``None`` means "no verdict": unreadable file, no TGT, or no timestamps.
    Service tickets are skipped — the TGT is what governs whether this ccache
    can still open anything new.
    """
    try:
        from kerbad.common.ccache import CCACHE  # noqa: PLC0415

        ccache = CCACHE.from_file(path)
    except Exception as exc:  # noqa: BLE001 — unreadable ticket is not a verdict
        print_info_debug(
            f"[ccache-renewal] could not read ccache for expiry check: "
            f"{type(exc).__name__}: {exc}"
        )
        return None

    endtimes: list[float] = []
    for cred in list(getattr(ccache, "credentials", []) or []):
        try:
            server = getattr(cred, "server", None)
            components = list(getattr(server, "components", None) or [])
            service = components[0].to_string().lower() if components else ""
            if service and service != "krbtgt":
                continue
            endtime = getattr(getattr(cred, "time", None), "endtime", None)
            if isinstance(endtime, (int, float)):
                endtimes.append(float(endtime))
        except Exception:  # noqa: BLE001
            continue
    return max(endtimes) if endtimes else None


def ccache_client_principal(ccache_path: str) -> str | None:
    """Return the client principal name recorded in *ccache_path*, if readable.

    Used by the recovery layer to prove that a re-minted ticket belongs to the
    same principal as the expired one before swapping it in.
    """
    path = str(ccache_path or "").strip()
    if not path or not os.path.isfile(path):
        return None
    try:
        from kerbad.common.ccache import CCACHE  # noqa: PLC0415

        ccache = CCACHE.from_file(path)
        for cred in list(getattr(ccache, "credentials", []) or []):
            client = getattr(cred, "client", None)
            if client is None:
                continue
            name = client.to_string(separator="/")
            if name:
                return str(name).strip()
    except Exception:  # noqa: BLE001
        return None
    return None


def remint_principal_ccache(
    *,
    username: str,
    domain: str,
    dc_ip: str | None = None,
) -> str | None:
    """Mint a fresh TGT for ``username@domain`` through the auth-as-principal SSOT.

    Delegates to :func:`ensure_user_ccache` with ``force_refresh=True`` so the
    principal's stored secret (password, or an NT hash / AES key recovered
    earlier) produces a new, salt- and posture-correct ticket at the canonical
    workspace path. Returns ``None`` when renewal is not armed, no secret is
    stored for that principal, or the AS-REQ failed.
    """
    shell = _shell()
    if shell is None:
        return None
    user = str(username or "").strip()
    realm = str(domain or "").strip()
    if not user or not realm:
        return None
    try:
        from adscan_internal.services.kerberos_ticket_service import (  # noqa: PLC0415
            ensure_user_ccache,
        )

        return ensure_user_ccache(
            shell,
            user=user,
            domain=realm,
            dc_ip=dc_ip or None,
            force_refresh=True,
        )
    except Exception as exc:  # noqa: BLE001 — renewal is best-effort
        print_info_debug(
            f"[ccache-renewal] re-mint raised {type(exc).__name__}: {exc}"
        )
        return None


def _arm_expiry_reminter(
    *,
    realm: str,
    username: str,
    dc_ip: str | None,
) -> None:
    """Register the reactive re-mint callback for ``username@realm``.

    The reminter is principal-scoped, so a mid-bind ``KRB_AP_ERR_TKT_EXPIRED``
    on one principal can never be "recovered" with another principal's ticket.
    It stays registered for the session: it re-mints exactly that principal and
    the recovery layer verifies the result before using it, so a lingering
    registration is harmless and lets later binds inherit renewal for free.
    """
    if not realm or not username:
        return

    from adscan_internal.services import _kerberos_recovery  # noqa: PLC0415

    def _reminter() -> str | None:
        return remint_principal_ccache(
            username=username, domain=realm, dc_ip=dc_ip
        )

    _kerberos_recovery.register_expiry_reminter(
        realm, _reminter, principal=username
    )


def prepare_ccache_for_bind(
    *,
    ccache_path: str | None,
    username: str | None,
    domain: str | None,
    auth_domain: str | None = None,
    dc_ip: str | None = None,
) -> CcachePreparation:
    """Prepare one explicit ccache for an imminent Kerberos bind.

    Called from each transport's connect seam. Synchronous and cheap: the only
    costly branch is an actual re-mint, which happens only when the ticket is
    provably dead.

    Args:
        ccache_path: The explicit ticket the caller wants to bind with.
        username: The principal the caller is authenticating as.
        domain: The target domain.
        auth_domain: The credential's own domain when it differs from *domain*
            (cross-realm); this is the realm a re-mint must target.
        dc_ip: KDC address for the re-mint AS-REQ.

    Returns:
        A :class:`CcachePreparation`. Callers bind with ``.ccache_path`` and,
        when ``.usable`` is ``False``, drop the ticket and continue down their
        own auth ladder.
    """
    decision = _classify_and_arm(
        ccache_path=ccache_path,
        username=username,
        domain=domain,
        auth_domain=auth_domain,
        dc_ip=dc_ip,
    )
    if decision.settled is not None:
        return decision.settled
    fresh = remint_principal_ccache(
        username=decision.username, domain=decision.realm, dc_ip=dc_ip
    )
    return _finish_expired(decision, fresh)


async def prepare_ccache_for_bind_async(
    *,
    ccache_path: str | None,
    username: str | None,
    domain: str | None,
    auth_domain: str | None = None,
    dc_ip: str | None = None,
) -> CcachePreparation:
    """Async wrapper for the async transport seams (LDAP, SMB).

    Classification and reminter arming are pure, cheap and safe inside a running
    loop, so they run inline — this is on every connect, and a per-connect
    thread would be a real cost at collector scale. Only the re-mint, which
    drives its own event loop internally, is offloaded with
    :func:`run_sync_off_loop`, and only when a ticket is actually dead.
    """
    decision = _classify_and_arm(
        ccache_path=ccache_path,
        username=username,
        domain=domain,
        auth_domain=auth_domain,
        dc_ip=dc_ip,
    )
    if decision.settled is not None:
        return decision.settled

    from adscan_internal.services.async_bridge import run_sync_off_loop  # noqa: PLC0415

    fresh = run_sync_off_loop(
        remint_principal_ccache,
        username=decision.username,
        domain=decision.realm,
        dc_ip=dc_ip,
    )
    return _finish_expired(decision, fresh)


@dataclass(frozen=True)
class _RenewalDecision:
    """Intermediate state shared by the sync and async entry points.

    ``settled`` holds the final verdict when no re-mint is needed (no ccache,
    capability-bearing, or still valid); otherwise the ticket is expired and the
    caller performs the re-mint in whichever way suits its execution context.
    """

    path: str
    realm: str
    username: str
    settled: Optional[CcachePreparation] = None


def _classify_and_arm(
    *,
    ccache_path: str | None,
    username: str | None,
    domain: str | None,
    auth_domain: str | None,
    dc_ip: str | None,
) -> _RenewalDecision:
    """Classify the ticket and arm the reactive reminter. No network, no loop."""
    path = str(ccache_path or "").strip()
    realm = str(auth_domain or domain or "").strip()
    user = str(username or "").strip()

    if not path:
        return _RenewalDecision(path, realm, user, settled=CcachePreparation(None))

    if is_capability_bearing_ccache(
        ccache_path=path, domain=realm, username=user or None
    ):
        # Marked ESC13 PAC-TGT or a scoped service ticket: the capability lives
        # in this exact file. Never renewed, never armed for renewal.
        print_info_debug(
            "[ccache-renewal] capability-bearing ccache detected; using it "
            "verbatim (no reminter armed, never re-minted)"
        )
        return _RenewalDecision(
            path,
            realm,
            user,
            settled=CcachePreparation(path, capability_bearing=True),
        )

    _arm_expiry_reminter(realm=realm, username=user, dc_ip=dc_ip)

    if not ccache_is_expired(path):
        return _RenewalDecision(path, realm, user, settled=CcachePreparation(path))

    return _RenewalDecision(path, realm, user)


def _finish_expired(
    decision: _RenewalDecision, fresh: str | None
) -> CcachePreparation:
    """Turn a re-mint result for an expired ticket into the final verdict."""
    if fresh:
        print_info_debug(
            "[ccache-renewal] stored ticket had expired; minted a fresh TGT "
            "before the bind"
        )
        return CcachePreparation(fresh, expired=True, renewed=True)

    print_info_debug(
        "[ccache-renewal] stored ticket has expired and no secret is available "
        "to re-mint it; the transport will fall back to its own auth ladder"
    )
    return CcachePreparation(decision.path, expired=True, usable=False)


__all__ = [
    "CcachePreparation",
    "ccache_client_principal",
    "ccache_is_expired",
    "is_capability_bearing_ccache",
    "prepare_ccache_for_bind",
    "prepare_ccache_for_bind_async",
    "register_ccache_renewal_for_shell",
    "remint_principal_ccache",
]
