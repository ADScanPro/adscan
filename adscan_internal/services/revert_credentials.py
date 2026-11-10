"""Which credential undoes a change: ONE precedence for every revert executor.

Founder decision 2026-11-05 ("Reversion de cambios en el directorio"):

1. the client-provided cleanup account (:mod:`cleanup_credential_store`),
2. the highest-privilege credential the run itself VERIFIED (Domain Admins,
   Enterprise Admins or the RID-500 Administrator, graded from the collected
   directory by :func:`pick_credential_for_local_admin`, never by a name),
3. the principal that made the change.

The first one that confirms the revert wins; every failure falls through to the
next; exhaustion leaves the change ``manual_required`` exactly as before. This
generalises the cascade ESC14 already had (``esc_principal_write``) and replaces
the minimal-first resolver for every revert: a quota-created machine account,
for instance, can almost never be deleted by its creator, so trying the creator
first only produced disabled leftovers that keep consuming the client's quota.

Every attempt is recorded on the ledger entry (principal, role, outcome) and the
successful one names the principal and its ROLE, so the report can say "removed
using the client-provided cleanup account" without ever holding a secret.

Lockout safety: each candidate is a credential the session already holds and has
authenticated with (or the client's dedicated account), tried at most once per
change. Nothing here iterates the credential store.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Optional, Sequence

from adscan_core import telemetry
from adscan_core.rich_output import mark_sensitive, print_exception, print_info_debug

__all__ = [
    "ROLE_CLEANUP",
    "ROLE_CLEANUP_SAVED",
    "ROLE_PRIVILEGED",
    "ROLE_CREATOR",
    "ROLE_SESSION",
    "ROLE_TARGET_TICKET",
    "ROLE_OPERATOR",
    "VERIFY_OPERATOR_ATTESTED",
    "record_operator_attested_revert",
    "RevertCandidate",
    "RevertCascadeResult",
    "revert_candidates",
    "run_revert_cascade",
    "run_ldap_revert_cascade",
    "run_ldap_attribute_restore",
    "run_revert_with_precedence",
    "role_label",
    "tried_principals",
    "record_revert_rights",
]

ROLE_CLEANUP = "cleanup"
#: The same client cleanup account, taken from the workspace where the operator
#: saved it in an earlier session rather than passed with this run. A role of
#: its own so the report can say where the account came from.
ROLE_CLEANUP_SAVED = "cleanup_saved"
ROLE_PRIVILEGED = "privileged"
ROLE_CREATOR = "creator"
ROLE_SESSION = "session"
ROLE_TARGET_TICKET = "target_ticket"
#: The operator cleaned the change up by hand and attested it (no re-read).
ROLE_OPERATOR = "operator"
#: Verification method recorded for an operator attestation.
VERIFY_OPERATOR_ATTESTED = "operator_attested"

KIND_PASSWORD = "password"
KIND_NT_HASH = "nt_hash"
KIND_AES256 = "aes256_key"
KIND_AES128 = "aes128_key"
KIND_CCACHE = "ccache_path"


def role_label(role: str) -> str:
    """Name of a revert credential role (the cleanup-taxonomy SSOT)."""
    from adscan_internal.services.cleanup_taxonomy import (  # noqa: PLC0415
        REVERT_ROLE_PERFORMED_AS,
    )

    return REVERT_ROLE_PERFORMED_AS.get(str(role or ""), "Assessment account")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _strip_markers(value: str) -> str:
    from adscan_core.sensitive import strip_sensitive_markers  # noqa: PLC0415

    return strip_sensitive_markers(str(value or ""))


def _looks_like_nt_hash(secret: str) -> bool:
    value = str(secret or "").strip()
    if ":" in value:
        value = value.split(":")[-1]
    return len(value) == 32 and all(c in "0123456789abcdefABCDEF" for c in value)


@dataclass(frozen=True)
class RevertCandidate:
    """One credential a revert may run as.

    Attributes:
        role: One of the ``ROLE_*`` constants (what the report says it was).
        username: The principal (never a secret; masked when printed).
        domain: The domain the credential authenticates to.
        secret: Password, NT hash, AES key or ccache path (never in ``repr``).
        kind: How to read ``secret`` (``password``/``nt_hash``/``aes*``/``ccache_path``).
    """

    role: str
    username: str
    domain: str
    secret: str = field(repr=False, default="")
    kind: str = KIND_PASSWORD

    @property
    def label(self) -> str:
        """Operator-facing description, principal masked for telemetry."""
        return f"{role_label(self.role)} {mark_sensitive(self.username, 'user')}"

    #: A guest-style creator whose empty secret IS its credential (a guest
    #: session on a share); never set for a stored or privileged account.
    allow_empty_secret: bool = False

    @property
    def usable(self) -> bool:
        return bool(self.username and (self.secret or self.allow_empty_secret))

    def ldap_config(
        self, *, dc_ip: str, dc_fqdn: Optional[str] = None, posture_snapshot: Any = None
    ) -> Any:
        """An :class:`ADscanLDAPConfig` that binds as this candidate."""
        from adscan_internal.services.ldap_transport_service import (  # noqa: PLC0415
            ADscanLDAPConfig,
        )

        common: dict[str, Any] = {
            "domain": self.domain,
            "dc_ip": dc_ip,
            "username": self.username,
            "use_ldaps": True,
            "kerberos_target_hostname": dc_fqdn or None,
        }
        if posture_snapshot is not None:
            common["posture_snapshot"] = posture_snapshot
        if self.kind == KIND_CCACHE:
            return ADscanLDAPConfig(use_kerberos=True, ccache_path=self.secret, **common)
        if self.kind in (KIND_AES256, KIND_AES128):
            return ADscanLDAPConfig(use_kerberos=True, aes_key=self.secret, **common)
        # Password or NT hash: the transport detects the hash form and passes it.
        return ADscanLDAPConfig(use_kerberos=False, password=self.secret, **common)

    def smb_config(
        self,
        *,
        target_ip: str,
        target_hostname: Optional[str] = None,
        kdc_ip: Optional[str] = None,
        posture_snapshot: Any = None,
    ) -> Any:
        """An ``SMBConfig`` that authenticates as this candidate (SMB, SAMR, DCOM)."""
        from adscan_internal.services.smb_transport import SMBConfig  # noqa: PLC0415

        secret = self.secret
        return SMBConfig(
            target_ip=target_ip,
            target_hostname=target_hostname or target_ip,
            domain=self.domain,
            auth_domain=self.domain,
            username=self.username,
            password=secret if self.kind == KIND_PASSWORD else None,
            nt_hash=secret if self.kind == KIND_NT_HASH else None,
            aes_key=secret if self.kind in (KIND_AES256, KIND_AES128) else None,
            ccache_path=secret if self.kind == KIND_CCACHE else None,
            kdc_ip=kdc_ip,
            use_kerberos=self.kind in (KIND_CCACHE, KIND_AES256, KIND_AES128),
            posture_snapshot=posture_snapshot,
        )

    def as_password_or_hash(self) -> Optional[tuple[str, str]]:
        """``(username, secret)`` for callers that only speak password/NT hash."""
        if self.kind in (KIND_PASSWORD, KIND_NT_HASH) and self.usable:
            return self.username, self.secret
        return None


def _cleanup_candidate(domain: str, purpose: str) -> Optional[RevertCandidate]:
    try:
        from adscan_internal.services.cleanup_credential_store import (  # noqa: PLC0415
            SOURCE_WORKSPACE,
            get_for_revert,
        )

        cred = get_for_revert(domain=domain, purpose=purpose)
    except Exception as exc:  # noqa: BLE001 - a broken store never blocks a revert
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None
    if cred is None or not cred.secret:
        return None
    from_workspace = cred.source == SOURCE_WORKSPACE
    return RevertCandidate(
        role=ROLE_CLEANUP_SAVED if from_workspace else ROLE_CLEANUP,
        username=cred.username,
        domain=cred.domain or domain,
        secret=cred.secret,
        kind=KIND_NT_HASH if _looks_like_nt_hash(cred.secret) else KIND_PASSWORD,
    )


def _privileged_candidate(shell: Any, domain: str) -> Optional[RevertCandidate]:
    if shell is None:
        return None
    try:
        from adscan_internal.services.credentials.privilege_role import (  # noqa: PLC0415
            pick_credential_for_local_admin,
        )

        picked = pick_credential_for_local_admin(shell, domain=domain)
    except Exception as exc:  # noqa: BLE001 - an ungraded graph degrades to None
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None
    if not picked:
        return None
    username, secret, kind = picked
    username = _strip_markers(username)
    secret = _strip_markers(secret)
    if not username or not secret:
        return None
    return RevertCandidate(
        role=ROLE_PRIVILEGED,
        username=username,
        domain=domain,
        secret=secret,
        kind=str(getattr(kind, "value", kind) or KIND_PASSWORD),
    )


def _stored_secret(shell: Any, domain: str, username: str) -> str:
    try:
        from adscan_internal.services.cleanup_credential_resolver import (  # noqa: PLC0415
            _lookup_domain_credential,
        )

        return _strip_markers(_lookup_domain_credential(shell, domain, username))
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return ""


def revert_candidates(
    shell: Any,
    *,
    domain: str,
    purpose: str,
    creator_username: str = "",
    creator_secret: str = "",
    creator_domain: str = "",
    session_username: str = "",
    session_secret: str = "",
    extra_before_creator: Iterable[RevertCandidate] = (),
    include_privileged: bool = True,
    exclude: Iterable[str] = (),
    creator_empty_secret_ok: bool = False,
) -> list[RevertCandidate]:
    """The ordered, de-duplicated credentials to try for one revert.

    Args:
        shell: The session shell (credential store + collected graph).
        domain: The domain of the object being reverted.
        purpose: The ledger change kind, passed to the cleanup store's reader.
        creator_username: The principal that made the change.
        creator_secret: Its secret when the caller holds it in memory; resolved
            from the credential store otherwise.
        creator_domain: Where the creator's credential lives (cross-domain
            changes); defaults to ``domain``.
        session_username / session_secret: The domain's context credential, the
            historical last resort of the relay exit path.
        extra_before_creator: Step-specific material (ESC14's freshly minted
            ticket for the compromised target), tried after the privileged
            credential and before the creator.
        include_privileged: False for a caller that must not escalate.
        exclude: Principals already tried for this change (the final retry pass
            skips them: the same account fails the same way, and a second
            failed bind is one more step toward lockout).

    Returns:
        Usable candidates in precedence order, each principal once.
    """
    ordered: list[RevertCandidate] = []
    seen: set[str] = {
        str(p or "").strip().lower().split("@", 1)[0].split("\\")[-1] for p in exclude
    }

    def _add(candidate: Optional[RevertCandidate]) -> None:
        # One attempt per principal: a second bind as the same account has the
        # same rights, so it could only add a failed logon.
        if candidate is None or not candidate.usable:
            return
        key = candidate.username.strip().lower().split("@", 1)[0].split("\\")[-1]
        if key in seen:
            return
        seen.add(key)
        ordered.append(candidate)

    _add(_cleanup_candidate(domain, purpose))
    if include_privileged:
        _add(_privileged_candidate(shell, domain))
    for extra in extra_before_creator:
        _add(extra)
    creator = _strip_markers(creator_username).strip()
    if creator:
        c_domain = creator_domain or domain
        secret = _strip_markers(creator_secret) or _stored_secret(shell, c_domain, creator)
        if not secret and c_domain != domain:
            secret = _stored_secret(shell, domain, creator)
        _add(
            RevertCandidate(
                role=ROLE_CREATOR,
                username=creator,
                domain=c_domain,
                secret=secret,
                kind=KIND_NT_HASH if _looks_like_nt_hash(secret) else KIND_PASSWORD,
                allow_empty_secret=creator_empty_secret_ok,
            )
        )
    session_user = _strip_markers(session_username).strip()
    if session_user:
        session_pw = _strip_markers(session_secret)
        _add(
            RevertCandidate(
                role=ROLE_SESSION,
                username=session_user,
                domain=domain,
                secret=session_pw,
                kind=KIND_NT_HASH if _looks_like_nt_hash(session_pw) else KIND_PASSWORD,
            )
        )
    print_info_debug(
        "revert-cascade "
        f"purpose={purpose} domain={mark_sensitive(domain, 'domain')} "
        f"roles={[c.role for c in ordered]}"
    )
    return ordered


def tried_principals(entry: dict[str, Any]) -> set[str]:
    """Principals already tried for a ledger entry (lower-cased)."""
    attempts = entry.get("revert_credential_attempts") if isinstance(entry, dict) else None
    if not isinstance(attempts, list):
        return set()
    return {
        str(a.get("principal") or "").strip().lower()
        for a in attempts
        if isinstance(a, dict) and str(a.get("principal") or "").strip()
    }


class _AttemptLedger:
    """Ledger proxy for one cascade attempt.

    A non-final attempt must not settle the entry as ``manual_required``: the
    next credential may still succeed. So failures are captured instead of
    forwarded; a confirmation is forwarded and remembered.
    """

    _FAILURE_METHODS = frozenset(
        {"mark_manual_required", "mark_revert_retry", "mark_failed", "mark_operator_required"}
    )
    _SUCCESS_METHODS = frozenset({"mark_reverted_confirmed", "mark_reverted"})

    def __init__(self, ledger: Any, *, defer_failures: bool) -> None:
        self._ledger = ledger
        self._defer = defer_failures
        self.confirmed = False
        self.failure: Optional[str] = None

    def __getattr__(self, name: str) -> Any:
        target = getattr(self._ledger, name)
        if name in self._SUCCESS_METHODS:

            def _success(*args: Any, **kwargs: Any) -> Any:
                self.confirmed = True
                return target(*args, **kwargs)

            return _success
        if name in self._FAILURE_METHODS:

            def _failure(*args: Any, **kwargs: Any) -> Any:
                self.failure = str(kwargs.get("error") or kwargs.get("reason") or name)
                if self._defer:
                    return 0 if name == "mark_revert_retry" else None
                return target(*args, **kwargs)

            return _failure
        return target


@dataclass
class RevertCascadeResult:
    """How a cascade ended."""

    confirmed: bool
    winner: Optional[RevertCandidate] = None
    last_error: Optional[str] = None
    attempted: list[str] = field(default_factory=list)


def _record_attempt(
    ledger: Any, change_id: Optional[str], candidate: RevertCandidate, outcome: str
) -> None:
    if ledger is None or not change_id:
        return
    record = getattr(ledger, "record_revert_credential_attempt", None)
    if not callable(record):
        return
    try:
        record(
            change_id,
            principal=candidate.username,
            role=candidate.role,
            outcome=outcome,
            at=_now_iso(),
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def record_revert_rights(
    ledger: Any, change_id: Optional[str], candidates: Iterable[Any]
) -> None:
    """Record on the entry which accounts with the rights to undo it were available.

    Every revert seam calls this BEFORE its first attempt, with all the
    candidates it had (before a transport filter drops one): when the revert
    later gives up, the ledger classifies the outcome from it, so "no account
    with the rights was available" is never confused with "the revert failed
    with the rights to do it". Best effort; never raises.

    Args:
        ledger: The environment-change ledger (or an attempt proxy), may be None.
        change_id: The entry, or None for an unledgered change.
        candidates: :class:`RevertCandidate` objects, or anything with ``role``.
    """
    if ledger is None or not change_id:
        return
    record = getattr(ledger, "record_revert_rights", None)
    if not callable(record):
        return
    try:
        record(change_id, roles=[str(getattr(c, "role", "") or "") for c in candidates])
    except Exception as exc:  # noqa: BLE001 - the revert itself must still run
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def run_revert_cascade(
    *,
    ledger: Any,
    change_id: Optional[str],
    candidates: Sequence[RevertCandidate],
    attempt: Callable[[RevertCandidate, Any, bool], Optional[bool]],
    on_exhausted: Optional[Callable[[Optional[str]], None]] = None,
) -> RevertCascadeResult:
    """Try ``attempt`` with each candidate until one confirms the revert.

    Args:
        ledger: The environment-change ledger (may be ``None``).
        change_id: The entry being reverted (``None`` for an unledgered change).
        candidates: From :func:`revert_candidates`.
        attempt: ``attempt(candidate, ledger_proxy, final)`` performs the revert
            and settles the entry through ``ledger_proxy``. It may also return
            True/False for an unledgered change. ``final`` is True on the last
            candidate: only then may it fall back to a partial measure (disabling
            an object it cannot delete) or settle ``manual_required``.
        on_exhausted: Called with the last error when no candidate confirmed and
            the final attempt did not settle the entry itself (for example the
            last bind raised before any ledger call).

    Returns:
        A :class:`RevertCascadeResult`.
    """
    result = RevertCascadeResult(confirmed=False)
    record_revert_rights(ledger, change_id, candidates)
    total = len(candidates)
    for index, candidate in enumerate(candidates):
        final = index == total - 1
        proxy = _AttemptLedger(ledger, defer_failures=not final) if ledger is not None else None
        returned: Optional[bool] = None
        try:
            returned = attempt(candidate, proxy, final)
        except Exception as exc:  # noqa: BLE001 - fall through to the next credential
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            result.last_error = str(exc)
        confirmed = bool(proxy.confirmed) if proxy is not None else False
        if proxy is None or change_id is None:
            confirmed = confirmed or bool(returned)
        if proxy is not None and proxy.failure:
            result.last_error = proxy.failure
        result.attempted.append(candidate.role)
        _record_attempt(ledger, change_id, candidate, "reverted" if confirmed else "failed")
        if confirmed:
            result.confirmed = True
            result.winner = candidate
            return result
        if final and (proxy is None or proxy.failure is None) and on_exhausted is not None:
            on_exhausted(result.last_error)
    if not candidates and on_exhausted is not None:
        on_exhausted("No credential available to perform the revert.")
    return result


def run_revert_with_precedence(
    shell: Any,
    *,
    ledger: Any,
    change_id: Optional[str],
    domain: str,
    purpose: str,
    revert_and_confirm: Callable[[RevertCandidate], tuple[bool, Optional[str]]],
    verification_method: str,
    manual_instructions: str,
    object_dn: str = "",
    creator_username: str = "",
    creator_secret: str = "",
    creator_domain: str = "",
    extra_before_creator: Iterable[RevertCandidate] = (),
    exclude: Iterable[str] = (),
    supported_kinds: Optional[Iterable[str]] = None,
    description: str = "Revert",
    creator_empty_secret_ok: bool = False,
) -> RevertCascadeResult:
    """Revert ONE change through the shared precedence, on ANY transport.

    THE seam for a step-scoped revert: LDAP, CA DCOM, SMB file or directory,
    SAMR, SQL. The order is the founder's precedence (client cleanup account,
    verified privileged credential, step-specific material, the principal that
    made the change); every attempt is recorded on the ledger entry, and only
    a CONFIRMED revert settles ``reverted_confirmed``.

    ``revert_and_confirm(candidate)`` performs the undo authenticated as the
    candidate over its own transport AND re-reads the object, returning
    ``(True, None)`` only when the re-read shows the change gone, else
    ``(False, reason)``. A raise is a failed attempt. When no candidate
    confirms, the entry is ``manual_required`` with ``manual_instructions``.

    Args:
        shell: The session shell (credential store and collected graph).
        ledger: The environment-change ledger, or ``None``.
        change_id: The ledger entry, or ``None`` for an unledgered change.
        domain: The domain of the object being reverted.
        purpose: The ledger change kind (passed to the cleanup store).
        revert_and_confirm: The transport-specific undo plus re-read.
        verification_method: Recorded on the confirmed entry.
        manual_instructions: The native command a client runs if all fail.
        object_dn: The object the client acts on (for the manual disclosure).
        creator_username / creator_secret / creator_domain: The principal that
            made the change and its secret, when held in memory.
        extra_before_creator: Step-specific material tried before the creator.
        exclude: Principals already tried for this change.
        supported_kinds: Credential kinds the transport can use (``None`` = all);
            a candidate held only in another form is skipped, never attempted.
        description: Operator-facing name of the revert, for the log.
        creator_empty_secret_ok: The creator authenticated with an empty secret
            (a guest session on a share) and may revert with it.

    Returns:
        A :class:`RevertCascadeResult`.
    """
    from adscan_internal.services import cleanup_taxonomy as _tax  # noqa: PLC0415

    def _settle_manual(target_ledger: Any, error: str) -> None:
        if target_ledger is None or not change_id:
            return
        target_ledger.mark_manual_required(
            change_id,
            reason=_tax.MANUAL_REASON_REVERT_FAILED,
            remediation_command=manual_instructions,
            remediation_object_dn=object_dn,
            error=error,
            manual_cleanup_instructions=manual_instructions,
        )

    def _attempt(candidate: RevertCandidate, proxy: Any, _final: bool) -> bool:
        confirmed, reason = revert_and_confirm(candidate)
        if not confirmed:
            _settle_manual(
                proxy,
                f"{description} as {role_label(candidate.role)} was not confirmed"
                + (f": {reason}" if reason else "."),
            )
            return False
        if proxy is not None and change_id:
            proxy.mark_reverted_confirmed(
                change_id, verification_method=verification_method
            )
        return True

    candidates = revert_candidates(
        shell,
        domain=domain,
        purpose=purpose,
        creator_username=creator_username,
        creator_secret=creator_secret,
        creator_domain=creator_domain,
        extra_before_creator=extra_before_creator,
        exclude=exclude,
        creator_empty_secret_ok=creator_empty_secret_ok,
    )
    # Recorded before the transport filter: an account with the rights that
    # this transport cannot use is ADscan's limitation, never a missing input.
    record_revert_rights(ledger, change_id, candidates)
    if supported_kinds is not None:
        allowed = set(supported_kinds)
        candidates = [c for c in candidates if c.kind in allowed]
    return run_revert_cascade(
        ledger=ledger,
        change_id=change_id,
        candidates=candidates,
        attempt=_attempt,
        on_exhausted=lambda error: _settle_manual(
            ledger, error or "No available credential could perform the revert."
        ),
    )


def run_ldap_revert_cascade(
    shell: Any,
    *,
    ledger: Any,
    change_id: Optional[str],
    domain: str,
    purpose: str,
    dc_ip: str,
    revert: Callable[[Any], bool],
    verify: Callable[[Any], bool],
    verification_method: str,
    manual_instructions: str,
    object_dn: str = "",
    dc_fqdn: Optional[str] = None,
    creator_username: str = "",
    creator_secret: str = "",
    creator_domain: str = "",
    extra_before_creator: Iterable[RevertCandidate] = (),
    exclude: Iterable[str] = (),
    connect: Optional[Callable[[Any], Any]] = None,
    description: str = "Revert",
) -> RevertCascadeResult:
    """:func:`run_revert_with_precedence` over LDAP.

    Each attempt binds as the candidate, runs ``revert(conn)`` and then
    ``verify(conn)`` on the same connection (``connect`` opens it from an
    ``ADscanLDAPConfig``; defaults to :class:`ADscanLDAPConnection`).
    """
    if connect is None:
        from adscan_internal.services.ldap_transport_service import (  # noqa: PLC0415
            ADscanLDAPConnection as connect,
        )

    def _revert_and_confirm(candidate: RevertCandidate) -> tuple[bool, Optional[str]]:
        config = candidate.ldap_config(dc_ip=dc_ip, dc_fqdn=dc_fqdn)
        with connect(config) as conn:
            if not revert(conn):
                return False, "the directory refused the change"
            if not verify(conn):
                return False, "the re-read still shows the change"
        return True, None

    return run_revert_with_precedence(
        shell,
        ledger=ledger,
        change_id=change_id,
        domain=domain,
        purpose=purpose,
        revert_and_confirm=_revert_and_confirm,
        verification_method=verification_method,
        manual_instructions=manual_instructions,
        object_dn=object_dn,
        creator_username=creator_username,
        creator_secret=creator_secret,
        creator_domain=creator_domain,
        extra_before_creator=extra_before_creator,
        exclude=exclude,
        description=description,
    )


def run_ldap_attribute_restore(
    shell: Any,
    *,
    ledger: Any,
    change_id: Optional[str],
    domain: str,
    purpose: str,
    dc_ip: str,
    target: str,
    snapshot: dict[str, Sequence[str]],
    verification_method: str,
    manual_instructions: str,
    object_dn: str = "",
    dc_fqdn: Optional[str] = None,
    creator_username: str = "",
    creator_secret: str = "",
    creator_domain: str = "",
    connect: Optional[Callable[[Any], Any]] = None,
    description: str = "Attribute restore",
) -> RevertCascadeResult:
    """Put attributes of one directory object back to their snapshot.

    :func:`run_ldap_revert_cascade` for the common "an attack step overwrote
    an attribute" shape (``scriptPath``, the RODC password-replication lists).
    ``snapshot`` maps each attribute the step wrote to the values it held
    before (an empty sequence: the attribute was absent). Only attributes whose
    current value differs are written, so a restore never fails on deleting
    an attribute that is already gone; the confirming re-read compares every
    snapshot attribute, order and case ignored. ``target`` may be a DN or a
    principal name, resolved on each candidate's own connection.
    """
    from adscan_internal.services.cleanup_verification import (  # noqa: PLC0415
        attribute_values_match,
        read_attribute_strings,
        resolve_object_dn,
    )

    wanted = {attr: [str(v) for v in (values or ())] for attr, values in snapshot.items()}

    def _revert(conn: Any) -> bool:
        dn = resolve_object_dn(conn, target)
        if not dn:
            return False
        for attribute, values in wanted.items():
            if attribute_values_match(read_attribute_strings(conn, dn, attribute), values):
                continue
            change = ("replace", values) if values else ("delete", [])
            if not conn.modify(dn, {attribute: [change]}):
                return False
        return True

    def _verify(conn: Any) -> bool:
        dn = resolve_object_dn(conn, target)
        if not dn:
            return False
        return all(
            attribute_values_match(read_attribute_strings(conn, dn, attribute), values)
            for attribute, values in wanted.items()
        )

    return run_ldap_revert_cascade(
        shell,
        ledger=ledger,
        change_id=change_id,
        domain=domain,
        purpose=purpose,
        dc_ip=dc_ip,
        revert=_revert,
        verify=_verify,
        verification_method=verification_method,
        manual_instructions=manual_instructions,
        object_dn=object_dn or target,
        dc_fqdn=dc_fqdn,
        creator_username=creator_username,
        creator_secret=creator_secret,
        creator_domain=creator_domain,
        connect=connect,
        description=description,
    )


def record_operator_attested_revert(ledger: Any, change_id: str, *, operator: str = "") -> None:
    """Settle a change the operator cleaned up by hand and confirmed.

    The one path to ``reverted_confirmed`` without a re-read, and it says so: the
    attempt is recorded with the ``operator`` role and the entry carries
    ``verification_method = operator_attested``, so the report names it as the
    operator's manual cleanup rather than a verified revert.
    """
    if ledger is None or not change_id:
        return
    record = getattr(ledger, "record_revert_credential_attempt", None)
    if callable(record):
        record(change_id, principal=operator or "operator", role=ROLE_OPERATOR, outcome="reverted")
    ledger.mark_reverted_confirmed(change_id, verification_method=VERIFY_OPERATOR_ATTESTED)
