"""Engagement scope for ACCOUNTS: the list and actor seams of the asset scope.

The scope SSOT (:mod:`adscan_internal.services.engagement_scope`) decides whether
one directory object may be acted on (:func:`principal_scope_verdict`). This
module is the account-side sibling of its host seams
(``partition_targets_in_scope`` / ``require_host_in_scope``): it asks that one
verdict for every account in a list (a roast list, a spray list, a user
enumeration word list, the candidates that could run an attack step) and keeps
the excluded ones out, so an excluded account is never an acting identity and
never the object of a password check. It decides nothing itself.

Three things live here because the callers need them and the SSOT's public API
is per object:

* the list partition and its ONE collapsed operator line per call;
* the session registration the shell-less seams read (the Kerberos roast
  transport and the user-enumeration service take no shell; the same pattern as
  ``engagement_scope.register_scope_shell``);
* the recorder that tells the attack-path executor a step lost its actor
  BECAUSE of the scope, so the step is reported as outside the scope instead of
  as "no credential".

Fail closed: an account the SSOT cannot place (its verdict is UNDETERMINED, or
the verdict itself fails) is left out, exactly like an excluded one, and said so.
Without an asset scope every function returns its input untouched.

A verdict is a read of what the session knows, so a list seam tells the session
about its list ONCE (:func:`prepare_accounts_for_scope`, one indexed directory
read per account) before it judges it; the list partition here does both.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Callable, Iterable, Iterator, Mapping

from adscan_core import telemetry
from adscan_core.auth_attempt_guard import (
    LOCAL_REALM_PREFIX,
    SQL_REALM_PREFIX,
    is_host_scoped_realm,
)
from adscan_core.reporting.operator_stop_coverage import SOURCE_ENGAGEMENT_SCOPE
from adscan_core.rich_output import (
    print_exception,
    print_info,
    print_info_debug,
    print_info_verbose,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.engagement_scope import (
    ASSET_REASON_DOMAIN_OUTSIDE,
    ASSET_REASON_UNDETERMINED,
    AssetScopeVerdict,
    ScopeOutcome,
    ScopePartition,
    asset_refusal_line,
    asset_scope_recorded,
    host_scope_verdict,
    prepare_scope_principals,
    principal_scope_verdict,
    record_scope_refusals,
)
from adscan_internal.services.engagement_scope_targets import prepare_targets_for_scope

__all__ = (
    "account_scope_refusal",
    "actor_scope_refusal",
    "announce_principals_left_out",
    "partition_principals_in_scope",
    "principal_scope_predicate_for_session",
    "filter_principals_for_session",
    "note_operator_credential",
    "operator_credential_refusal",
    "prepare_accounts_for_scope",
    "recording_actor_scope_drops",
    "register_principal_scope_session",
    "scan_credential_scope_error",
    "session_shell",
    "scope_cannot_place",
    "sign_in_scope_refusal",
    "RUN_ERROR_ATTR",
    "SCOPE_STOP_SOURCE",
    "run_scope_error",
    "stop_run_if_controller_excluded",
    "stop_run_if_operator_credential_excluded",
)

#: Names shown under ``--verbose`` in one collapsed line.
_NAMES_SHOWN = 50

_SESSION_SHELL: Any = None

_ACTOR_DROPS: ContextVar[list[tuple[str, AssetScopeVerdict]] | None] = ContextVar(
    "adscan_engagement_scope_actor_drops", default=None
)


def register_principal_scope_session(shell: Any) -> None:
    """Record the session the shell-less account seams judge against.

    Called once per session beside the sign-in guard's registration
    (``auth_attempt_policy.register_auth_attempt_guard_for_shell``). ``None``
    clears it.
    """
    global _SESSION_SHELL  # noqa: PLW0603 - one session per process, by design
    _SESSION_SHELL = shell


def _session() -> Any:
    return _SESSION_SHELL


def session_shell() -> Any:
    """The session registered for the shell-less scope seams (``None`` without one)."""
    return _SESSION_SHELL


def _qualified(principal: Any, domain: str | None) -> str:
    """``principal`` as the SSOT reads it best: a bare account gets its realm.

    A stored credential and a list entry are bare sAMAccountNames, while the
    directory data the SSOT classifies an object from is keyed ``NAME@DOMAIN``.
    A label that already carries a realm, a NetBIOS qualifier, a SID or a DN is
    passed as it is.
    """
    text = str(principal or "").strip()
    realm = str(domain or "").strip().rstrip(".")
    if not text or not realm:
        return text
    upper = text.upper()
    if "@" in text or "\\" in text or upper.startswith(("S-1-", "CN=", "OU=")):
        return text
    return f"{text}@{realm}"


def _surface_of(what: str) -> str:
    """A machine name for the scope record, from the operator wording of a seam."""
    slug = "".join(ch if ch.isalnum() else "_" for ch in str(what or "").strip().lower())
    return "_".join(part for part in slug.split("_") if part) or "account_list"


def _undetermined() -> AssetScopeVerdict:
    return AssetScopeVerdict(ScopeOutcome.UNDETERMINED, ASSET_REASON_UNDETERMINED, "principal")


def scope_cannot_place(verdict: AssetScopeVerdict) -> bool:
    """True when the SSOT left the account alone because it could not PLACE it.

    The SSOT's UNDETERMINED outcome, and nothing else: a deny entry still
    pending, a subtree entry while the account's DN is unknown, an object whose
    kind the directory has not told us under an allow-list. A REFUSED verdict is
    an established exclusion and is never read as "cannot place". A list or an
    actor choice treats both as a refusal; only the operator's own scan
    credential is let past UNDETERMINED, to read the directory with.
    """
    return verdict.outcome is ScopeOutcome.UNDETERMINED


def _has_asset_scope(shell: Any) -> bool:
    """Whether an asset scope applies (``shell=None`` reads the registered session)."""
    return bool(asset_scope_recorded(shell))


def prepare_accounts_for_scope(
    shell: Any,
    principals: Iterable[Any],
    *,
    domain: str | None,
    key: Callable[[Any], Any] = str,
) -> None:
    """Tell the session what it needs to judge a LIST of accounts, in one call.

    The labels are prepared exactly as :func:`account_scope_refusal` asks about
    them, so the verdicts that follow read what was learned here. Never raises:
    an account the session was not told about reads "not confirmed" and is left
    out, so the list shrinks, never grows.
    """
    if not _has_asset_scope(shell):
        return
    try:
        labels = [
            label
            for label in dict.fromkeys(_qualified(key(item), domain) for item in principals or ())
            if label
        ]
        if labels:
            prepare_scope_principals(shell, labels, domain=domain)
    except Exception as exc:  # noqa: BLE001 - unprepared accounts stay "not confirmed"
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def account_scope_refusal(
    shell: Any,
    *,
    principal: Any,
    domain: str | None = None,
    dn: str | None = None,
    sid: str | None = None,
    dnshostname: str | None = None,
    kind: str | None = None,
) -> AssetScopeVerdict | None:
    """The verdict that keeps ``principal`` out, or ``None`` when it may be used.

    One READ of the scope SSOT. ``None`` at once when the session has no asset
    scope. A verdict that cannot be computed is a refusal (fail closed).
    ``kind`` is what the caller knows the object to be from the query that
    built its list; a caller that knows only a label prepares it first
    (:func:`prepare_accounts_for_scope`).
    """
    if not _has_asset_scope(shell):
        return None
    if not str(principal or "").strip() and not (dn or sid):
        return None
    try:
        verdict = principal_scope_verdict(
            shell,
            principal=_qualified(principal, domain),
            domain=domain,
            dn=dn,
            sid=sid,
            dnshostname=dnshostname,
            kind=kind,
        )
    except Exception as exc:  # noqa: BLE001 - an unreadable verdict is not a permission
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return _undetermined()
    return None if verdict.allowed else verdict


# ── Lists ──────────────────────────────────────────────────────────────────


def announce_principals_left_out(
    what: str,
    refused: list[tuple[Any, AssetScopeVerdict]],
    key: Callable[[Any], Any] = str,
) -> None:
    """The ONE collapsed operator line for the accounts a list left out.

    Counts on the line, names under ``--verbose``. Accounts the scope excludes
    and accounts it could not place are said apart: the second is not a
    statement about the client's choice. A caller that builds its list many
    times passes ``announce=False`` to the partition and calls this once.
    """
    from rich.markup import escape  # noqa: PLC0415

    unsure = [i for i, v in refused if scope_cannot_place(v)]
    excluded = [i for i, v in refused if not scope_cannot_place(v)]
    for group, tail in (
        (excluded, "excluded by the engagement scope."),
        (unsure, "it could not confirm inside the engagement scope."),
    ):
        if not group:
            continue
        names = sorted({str(key(item)) for item in group})
        noun = "account" if len(names) == 1 else "accounts"
        print_info(f"{escape(what)} left out {len(names)} {noun} {tail}")
        print_info_verbose(
            f"{escape(what)}: {mark_sensitive(escape(', '.join(names[:_NAMES_SHOWN])), 'user')}"
            + (f" and {len(names) - _NAMES_SHOWN} more" if len(names) > _NAMES_SHOWN else "")
        )


def partition_principals_in_scope(
    shell: Any,
    principals: Iterable[Any],
    *,
    domain: str | None,
    key: Callable[[Any], Any] = str,
    dnshostname: Callable[[Any], Any] | None = None,
    what: str,
    announce: bool = True,
    surface: str | None = None,
) -> ScopePartition:
    """Split an account list before it is used: a refused account never leaves here.

    The account sibling of ``engagement_scope.partition_targets_in_scope``. The
    session is told about the whole list once, then each account is judged
    (a read). One collapsed operator line per call (names under ``--verbose``),
    and every refusal joins the scope record under ``surface`` (derived from
    ``what`` when not given). Without an asset scope the list is returned
    untouched.

    Args:
        principals: The accounts the caller is about to roast, spray or act as.
        domain: The domain the list belongs to.
        key: Maps an item to its account name.
        dnshostname: Maps an item to its DNS host name, for a computer account.
        what: Operator wording of the operation ("Kerberoasting").
        announce: Print the collapsed line (False when the caller reports it).
    """
    items = list(principals or ())
    if not _has_asset_scope(shell):
        return ScopePartition(allowed=items, refused=[])
    prepare_accounts_for_scope(shell, items, domain=domain, key=key)
    allowed: list[Any] = []
    refused: list[tuple[Any, AssetScopeVerdict]] = []
    for item in items:
        verdict = account_scope_refusal(
            shell,
            principal=key(item),
            domain=domain,
            dnshostname=str(dnshostname(item) or "") if dnshostname else None,
        )
        if verdict is None:
            allowed.append(item)
        else:
            refused.append((item, verdict))
    if refused and announce:
        announce_principals_left_out(what, refused, key)
    if refused:
        try:
            record_scope_refusals(
                shell,
                refused,
                surface=surface or _surface_of(what),
                domain=domain,
                key=lambda item: _qualified(key(item), domain),
            )
        except Exception as exc:  # noqa: BLE001 - the record never changes who is left out
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
        print_info_debug(
            f"engagement-scope accounts: {what}: kept {len(allowed)}, left out {len(refused)}"
        )
    return ScopePartition(allowed=allowed, refused=refused)


def filter_principals_for_session(
    principals: Iterable[Any],
    *,
    domain: str | None,
    what: str,
    key: Callable[[Any], Any] = str,
) -> list[Any]:
    """:func:`partition_principals_in_scope` for a seam that takes no shell.

    Judged against the registered session. Without one, or without an asset
    scope, the list comes back untouched.
    """
    items = list(principals or ())
    return partition_principals_in_scope(
        _session(), items, domain=domain, key=key, what=what
    ).allowed


def principal_scope_predicate_for_session(domain: str | None) -> Callable[[str], bool] | None:
    """A per-name "may this account be used" test for a streamed list, or ``None``.

    ``None`` when the registered session has no asset scope: the caller then
    uses its list as it is, with no copy and no per-name cost.
    """
    shell = _session()
    if not _has_asset_scope(shell):
        return None

    def _allowed(name: str) -> bool:
        # A streamed word list is not a directory list: its names are candidate
        # USER principals (that is what the enumeration asks the KDC about), and
        # that is stated to the SSOT. A name written as a computer account
        # (``NAME$``) states nothing, so it is judged as an object of unknown
        # kind and left out wherever that is not enough.
        text = str(name or "").strip()
        kind = None if text.endswith("$") else "user"
        return account_scope_refusal(shell, principal=text, domain=domain, kind=kind) is None

    return _allowed


# ── Actors of an attack step ───────────────────────────────────────────────


@contextmanager
def recording_actor_scope_drops() -> Iterator[list[tuple[str, AssetScopeVerdict]]]:
    """Collect the candidate actors the scope removed inside this block.

    The step seam resolves a step's actor inside it: no actor together with a
    recorded drop means the step lost its actor to the scope, and is reported so.
    """
    drops: list[tuple[str, AssetScopeVerdict]] = []
    token = _ACTOR_DROPS.set(drops)
    try:
        yield drops
    finally:
        _ACTOR_DROPS.reset(token)


def actor_scope_refusal(
    shell: Any, *, domain: str, username: Any, rung: str = ""
) -> AssetScopeVerdict | None:
    """The verdict that keeps ``username`` from ACTING, or ``None``.

    Every rung of the step-execution actor ladder asks it before it returns a
    principal, so an excluded account is never the identity a step runs as.
    """
    # A no-op when the candidate list was prepared; a rung that holds one
    # account tells the session about it here.
    prepare_accounts_for_scope(shell, [username], domain=domain)
    verdict = account_scope_refusal(shell, principal=username, domain=domain)
    if verdict is None:
        return None
    drops = _ACTOR_DROPS.get()
    if drops is not None:
        drops.append((str(username or ""), verdict))
    print_info_debug(
        "engagement-scope actor: skipping "
        f"{rung or 'candidate'} {mark_sensitive(str(username or ''), 'user')}: {verdict.reason}"
    )
    return verdict


# ── Sign-ins (the backstop the sign-in guard asks) ──────────────────────────


def _norm_account(name: Any) -> str:
    text = str(name or "").strip()
    if "\\" in text:
        text = text.split("\\", 1)[1]
    return text.split("@", 1)[0].strip().lower()


def _workspace_domain(shell: Any, realm: str) -> tuple[str, Mapping[str, Any] | None]:
    """The workspace domain a realm names, and its record (``None`` when unknown)."""
    wanted = str(realm or "").strip().rstrip(".").lower()
    domains_data = getattr(shell, "domains_data", None)
    if isinstance(domains_data, Mapping):
        for name, data in domains_data.items():
            if str(name).strip().rstrip(".").lower() == wanted:
                return str(name), data if isinstance(data, Mapping) else {}
    if wanted and wanted == str(getattr(shell, "domain", "") or "").strip().rstrip(".").lower():
        return wanted, {}
    return wanted, None


#: Shell attribute: the scan credentials the OPERATOR supplied, ``{domain: {account}}``.
_OPERATOR_CREDENTIALS_ATTR = "_engagement_scope_operator_credentials"
#: Shell attribute: why the run cannot continue under the scope (``""`` when it can).
RUN_ERROR_ATTR = "_engagement_scope_run_error"


def note_operator_credential(shell: Any, *, domain: str, username: str) -> None:
    """Record that the operator supplied ``username`` as a scan credential of ``domain``.

    Called where a scan credential ENTERS (``start_auth``, ``ci``, ``execute``):
    the operator typed it or passed it, so they vouch for it. It is the only
    account allowed to sign in while the scope cannot place it yet (nothing
    about an account is known before its domain's directory is read, and
    reading it needs a sign-in). A credential ADscan captured is never recorded
    here: nobody vouches for it, so it is not used until it can be placed.
    """
    name = _norm_account(username)
    realm = str(domain or "").strip().rstrip(".").lower()
    if shell is None or not name or not realm:
        return
    held = getattr(shell, _OPERATOR_CREDENTIALS_ATTR, None)
    if not isinstance(held, dict):
        held = {}
        try:
            setattr(shell, _OPERATOR_CREDENTIALS_ATTR, held)
        except Exception:  # noqa: BLE001 - a frozen double records nothing
            return
    held.setdefault(realm, set()).add(name)


def _operator_credentials(shell: Any, realm: str) -> set[str]:
    held = getattr(shell, _OPERATOR_CREDENTIALS_ATTR, None)
    if not isinstance(held, dict):
        return set()
    return set(held.get(str(realm or "").strip().rstrip(".").lower()) or ())


def _reads_the_directory_first(shell: Any, realm: str, principal: str) -> bool:
    """Whether this sign-in is the operator's own scan credential for the domain.

    Only the credential the operator supplied for the scan
    (:func:`note_operator_credential`) may sign in while the scope cannot place
    it. "Any account while the domain has none" is not enough: a credential
    ADscan captured is not vouched for by anybody.
    """
    name, record = _workspace_domain(shell, realm)
    if record is None:
        return False
    return _norm_account(principal) in _operator_credentials(shell, name)


def operator_credential_refusal(shell: Any, *, domain: str) -> str:
    """Why the operator's scan credential cannot be used any more (``""`` when it can).

    Asked right after a domain's directory is read: the credential that was let
    in while it could not be placed is judged again, now that it can. When it
    resolves to an account the scope EXCLUDES the run cannot continue, and the
    line says so. An account still not placed is left to the sign-in guard.
    """
    realm = str(domain or "").strip().rstrip(".").lower()
    for account in sorted(_operator_credentials(shell, realm)):
        prepare_accounts_for_scope(shell, [account], domain=realm)
        verdict = account_scope_refusal(shell, principal=account, domain=realm)
        if verdict is None or verdict.outcome is not ScopeOutcome.REFUSED:
            continue
        if verdict.reason == ASSET_REASON_DOMAIN_OUTSIDE:
            continue
        return (
            asset_refusal_line("The scan", account, verdict, marked=False)
            + " Use an account inside the scope, or remove it from the exclusions."
        )
    return ""


def _host_of_scoped_realm(realm: str) -> str:
    """The host a ``LOCAL@host`` or ``SQL@host:port`` realm is keyed to."""
    text = str(realm or "").strip()
    upper = text.upper()
    if upper.startswith(LOCAL_REALM_PREFIX):
        return text[len(LOCAL_REALM_PREFIX) :].strip().lower()
    host = text[len(SQL_REALM_PREFIX) :].strip()
    head, sep, port = host.rpartition(":")
    return (head if sep and port.isdigit() else host).strip("[]").lower()


def sign_in_scope_refusal(shell: Any, *, realm: str, principal: str) -> str | None:
    """Why a sign-in must not be sent under the asset scope, or ``None``.

    The sign-in guard asks it immediately before a password, hash or key goes
    on the wire (``auth_attempt_guard.register_scope_provider``): the backstop
    for every account ADscan signs in as, whatever built the call.

    * a host-local account or a SQL login is a sign-in ON a host: the host
      verdict decides;
    * a domain account is refused when the scope excludes it. Its DOMAIN is not
      judged here (that is the domain scope's question, and it needs the route a
      sign-in does not carry). An account the SSOT cannot place yet is refused
      too, except the scan credential the operator supplied for that domain
      (never a captured one), which is judged again once the directory is read.

    ``None`` at once when the session has no asset scope.
    """
    if not _has_asset_scope(shell):
        return None
    if is_host_scoped_realm(realm):
        host = _host_of_scoped_realm(realm)
        if not host:
            return None
        try:
            # One host, named by the sign-in itself: told to the session once.
            prepare_targets_for_scope(shell, [host])
            verdict = host_scope_verdict(shell, host=host)
        except Exception as exc:  # noqa: BLE001 - an unreadable verdict is not a permission
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            verdict = _undetermined()
        return None if verdict.allowed else asset_refusal_line("Local sign-in", host, verdict)
    domain, _record = _workspace_domain(shell, realm)
    # One account, named by the sign-in itself: told to the session once (the
    # session remembers it; later sign-ins as the same account cost a read).
    prepare_accounts_for_scope(shell, [principal], domain=domain)
    verdict = account_scope_refusal(shell, principal=principal, domain=domain)
    if verdict is None or verdict.reason == ASSET_REASON_DOMAIN_OUTSIDE:
        return None
    # An established exclusion is never let through. An account the scope
    # cannot place is, only when the operator supplied it for the scan.
    if scope_cannot_place(verdict) and _reads_the_directory_first(shell, realm, principal):
        print_info_debug(
            "engagement-scope sign-in: "
            f"{mark_sensitive(str(principal), 'user')} cannot be placed yet and is the "
            "scan credential the operator supplied for this domain; allowed"
        )
        return None
    return asset_refusal_line("Sign-in", str(principal or ""), verdict)


#: Source of the scan-control request that ends a run the scope cannot continue.
SCOPE_STOP_SOURCE = SOURCE_ENGAGEMENT_SCOPE


def stop_run_if_operator_credential_excluded(shell: Any, *, domain: str) -> bool:
    """End the run when the operator's scan credential turns out to be excluded.

    Called by the collection right after ``on_directory_committed``: the
    credential was let in while the scope could not place it, and is judged
    again now that the directory can. When it is an account the scope excludes,
    the operator is told why, the reason is kept on the session (an unattended
    run exits 2 with it) and the scan is asked to stop at its next boundary
    through the scan control plane. The sign-in guard refuses the account from
    here on regardless, so nothing more is sent as it either way.

    Returns:
        True when the run was asked to stop.
    """
    error = operator_credential_refusal(shell, domain=domain)
    if not error:
        return False
    _stop_run_for_scope(
        shell,
        error,
        "The scan stops here: the directory shows that the account it signs in "
        "with is excluded from the engagement scope.",
    )
    return True


def stop_run_if_controller_excluded(shell: Any, *, domain: str) -> bool:
    """End the run when the directory shows its domain controller is excluded.

    Called by the collection right after ``on_directory_committed``, beside the
    credential check. The controller the operator named was read while a deny
    entry only the directory can match (a SID, a distinguished name, a name
    that did not resolve) was still open; the directory now says which object
    that entry is. When it is the controller itself, the operator is told so
    in those words and the scan is asked to stop at its next boundary. Every
    contact with the controller is refused from here on regardless.

    Returns:
        True when the run was asked to stop.
    """
    from adscan_internal.models.domain import resolve_dc_ip  # noqa: PLC0415
    from adscan_internal.services.engagement_scope import (  # noqa: PLC0415
        controller_exclusion_error,
    )

    domains_data = getattr(shell, "domains_data", None)
    data = domains_data.get(domain) if isinstance(domains_data, dict) else None
    dc_ip = resolve_dc_ip(data) if isinstance(data, dict) else None
    error = controller_exclusion_error(shell, domain=domain, dc_ip=dc_ip)
    if not error:
        return False
    _stop_run_for_scope(
        shell,
        error,
        "The scan stops here: the directory shows that the domain controller it "
        "reads from is excluded from the engagement scope.",
    )
    return True


def _stop_run_for_scope(shell: Any, error: str, closing: str) -> None:
    """Say why, keep the reason on the session, and ask the scan to stop."""
    from rich.markup import escape  # noqa: PLC0415

    from adscan_core.rich_output import print_error  # noqa: PLC0415

    print_error(escape(error))
    print_error(closing)
    try:
        setattr(shell, RUN_ERROR_ATTR, error)
    except Exception:  # noqa: BLE001 - a frozen double keeps no marker
        pass
    try:
        from adscan_core.scan_control import scan_control  # noqa: PLC0415
        from adscan_core.scan_control.vocabulary import (  # noqa: PLC0415
            ControlAction,
            ControlRequest,
        )

        scan_control().request(
            ControlRequest(action=ControlAction.ABORT_SCAN, source=SCOPE_STOP_SOURCE)
        )
    except Exception as exc:  # noqa: BLE001 - the guard still refuses every sign-in
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def run_scope_error(shell: Any) -> str:
    """Why this run could not continue under the scope (``""`` when it could)."""
    return str(getattr(shell, RUN_ERROR_ATTR, "") or "")


# ── The scan's own credential ──────────────────────────────────────────────


def scan_credential_scope_error(shell: Any, *, domain: str, username: str) -> str:
    """Why the scan cannot run as ``username`` under the scope (``""`` when it can).

    The account a scan signs in with is named by the operator. When the scope
    excludes it, nothing can run, so it is a configuration error stated before
    the scan, not a step refused part way. An account the SSOT cannot place yet
    (the directory is not collected) is not an error here: the first sign-in is
    what lets the directory be read, and the sign-in guard judges it again.
    """
    # A workspace an earlier run collected already knows the account: the
    # session is told about it, so an excluded one is caught before any contact.
    prepare_accounts_for_scope(shell, [username], domain=domain)
    verdict = account_scope_refusal(shell, principal=username, domain=domain)
    if verdict is None or scope_cannot_place(verdict):
        return ""
    if verdict.reason == ASSET_REASON_DOMAIN_OUTSIDE:
        # The account's DOMAIN is the domain scope's question (a credential of
        # another forest is a legitimate way in), never an asset exclusion.
        return ""
    return (
        asset_refusal_line("The scan", str(username or ""), verdict, marked=False)
        + " Use an account inside the scope, or remove it from the exclusions."
    )
