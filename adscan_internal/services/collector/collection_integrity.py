"""Did a domain collection read the whole directory? The SSOT that answers it.

Every stage of the LDAP collector (domain object, policies, objects and ACLs,
group memberships, GPO links, trusts, certificate services) keeps its own
``try/except`` so a single denied read never aborts the sweep. That is the
right behaviour for a REFUSAL, and the wrong one for a LOST CONNECTION: on
2026-11-10 a release-gate run lost its domain controller right after the object
pass, the certificate-services searches died sixteen minutes later with
"Connection closed!", the collector logged them and carried on, the AD CS
absence was then stamped as a valid negative, the panel read "Collection
Complete" and ``adscan ci`` exited 0 with one attack path where a healthy run
maps ten. A partial graph was presented as the directory.

This module is the one place that decides it:

* the collectors call :func:`note_stage_exception` from their stage handlers.
  A transport loss (``auth_error_classification.is_transport_loss_error``) is
  recorded on ``CollectionResult.stage_failures``; any other exception keeps
  its old meaning (logged, the sweep continues, the stage reads as refused);
* the collector also records an aborted connection-scoped block and an
  authenticated object pass that returned no user at all (a result below what
  the stage requires);
* the CLI collection driver calls :func:`declare_collection_integrity` once,
  which marks the ``domain_collection`` phase incomplete through the phase SSOT
  (``scan_progress.mark_phase_incomplete``). From there the end-of-scan verdict,
  ``adscan ci``'s exit status 3 and ``coverage.json`` all read the same record.

Nothing here is a heuristic about the network: a stage is incomplete only when
its own read failed in a way that means it was cut off.
"""

from __future__ import annotations

from typing import Any, Iterable

from adscan_core.engagement.specs import C_COLLECTION, C_COLLECTION_MSSQL

#: The phase a collection failure makes incomplete.
COLLECTION_PHASE_ID = C_COLLECTION
#: The SQL Server authorization collection. It has its own incomplete mark, so a
#: second SQL Server pass is judged afresh without clearing a directory read that
#: did not finish (and the other way round).
MSSQL_COLLECTION_PHASE_ID = C_COLLECTION_MSSQL

#: The connection to the domain controller dropped (or never completed) while
#: the stage was reading.
REASON_TRANSPORT_LOST = "transport_lost"
#: The connection-scoped collection block aborted for any other reason (bind
#: refused, an unreachable realm): every stage after it never ran.
REASON_ABORTED = "collection_aborted"
#: An authenticated object pass returned no user object at all. Any readable
#: domain holds at least its built-in accounts, so this is a truncated read.
REASON_NO_OBJECTS = "no_objects_returned"
#: The collector produced no result for the domain at all.
REASON_NO_RESULT = "no_result"
#: Kerberos refused the read with ``KRB_AP_ERR_SKEW`` and the clock recovery
#: layer could not correct it: the query never ran, which is not a refusal of
#: the data either.
REASON_CLOCK_SKEW = "clock_skew_unrecovered"

#: Markers of a Kerberos clock-skew failure in a library error message.
_CLOCK_SKEW_MARKERS: tuple[str, ...] = ("krb_ap_err_skew", "clock skew too great")

#: Operator-facing name of each collector stage (the prefix before a dot, so
#: ``adcs.enterprise_cas`` reads as certificate services).
_STAGE_LABELS: dict[str, str] = {
    "connect": "the directory connection",
    "domain_node": "the domain object",
    "domain_policy": "the password policy",
    "psos": "the fine-grained password policies",
    "objects_acls": "directory objects and their ACLs",
    "deleted_objects_acls": "deleted objects",
    "group_memberships": "group memberships",
    "gpo_links": "GPO links",
    "trusts": "domain trusts",
    "adcs": "certificate services (AD CS)",
    "collector": "the directory collection",
    "mssql": "SQL Server authorization",
}

#: Operator-facing name of each SQL Server collection query (``mssql.<query>``).
_MSSQL_QUERY_LABELS: dict[str, str] = {
    "server_principals": "SQL Server logins",
    "server_role_members": "SQL Server role memberships",
    "server_permissions": "SQL Server permissions",
    "linked_servers": "SQL Server linked servers",
}


def stage_label(stage: str) -> str:
    """Return the operator-facing label of a collector stage id."""
    text = str(stage or "")
    if text.startswith("mssql."):
        return _MSSQL_QUERY_LABELS.get(text.split(".", 1)[1], "SQL Server authorization")
    key = text.split(".", 1)[0]
    return _STAGE_LABELS.get(key, key.replace("_", " ") or "the directory collection")


def note_stage_exception(result: Any, stage: str, exc: BaseException) -> bool:
    """Record ``exc`` on ``result`` when it means ``stage`` was cut off.

    Returns True when it recorded a failure. Never raises: integrity tracking
    must not turn a degraded collection into a crashed one.
    """
    try:
        from adscan_internal.services.auth_error_classification import (  # noqa: PLC0415
            is_transport_loss_error,
        )

        if not is_transport_loss_error(exc):
            return False
        result.record_stage_failure(stage, REASON_TRANSPORT_LOST, type(exc).__name__)
        return True
    except Exception:  # noqa: BLE001
        return False


def is_clock_skew_error(exc_or_msg: Any) -> bool:
    """True when a failure is Kerberos refusing the request for clock skew."""
    texts: list[str] = []
    current: Any = exc_or_msg
    seen: set[int] = set()
    while isinstance(current, BaseException) and id(current) not in seen:
        seen.add(id(current))
        texts.append(str(current))
        current = current.__cause__ or current.__context__
    if not texts:
        texts.append(str(exc_or_msg or ""))
    return any(marker in text.lower() for text in texts for marker in _CLOCK_SKEW_MARKERS)


def cut_off_read_reason(exc_or_msg: Any) -> str:
    """The reason token when a failed read never happened, else ``""``.

    A lost connection and an unrecovered Kerberos clock skew both mean the data
    was not read. A refusal (access denied, a login without the permission) is
    graceful degradation and returns ``""``. The clock recovery layer has
    already retried by the time a caller sees the error, so a skew that reaches
    here is one it could not correct.
    """
    if not exc_or_msg:
        return ""
    if is_clock_skew_error(exc_or_msg):
        return REASON_CLOCK_SKEW
    try:
        from adscan_internal.services.auth_error_classification import (  # noqa: PLC0415
            is_transport_loss_error,
        )

        if is_transport_loss_error(exc_or_msg):
            return REASON_TRANSPORT_LOST
    except Exception:  # noqa: BLE001
        return ""
    return ""


def failure_tokens(failures: Iterable[Any]) -> tuple[str, ...]:
    """Return ``reason:stage`` tokens (what ``coverage.json`` records)."""
    tokens: list[str] = []
    for failure in failures:
        token = f"{getattr(failure, 'reason', '')}:{getattr(failure, 'stage', '')}"
        if token not in tokens:
            tokens.append(token)
    return tuple(tokens)


def incomplete_parts(failures: Iterable[Any]) -> tuple[str, ...]:
    """Return the operator-facing parts of the directory that were not read."""
    parts: list[str] = []
    for failure in failures:
        label = stage_label(getattr(failure, "stage", ""))
        if label not in parts:
            parts.append(label)
    return tuple(parts)


def _join(parts: list[str]) -> str:
    if len(parts) <= 1:
        return "".join(parts)
    return ", ".join(parts[:-1]) + " and " + parts[-1]


def describe_incomplete(failures: Iterable[Any]) -> str:
    """Return one sentence saying what did not finish, and why."""
    failures = list(failures)
    lost = [stage_label(f.stage) for f in failures if f.reason == REASON_TRANSPORT_LOST]
    aborted = [stage_label(f.stage) for f in failures if f.reason == REASON_ABORTED]
    clauses: list[str] = []
    if lost:
        clauses.append(
            "the connection to the domain controller was lost while reading "
            + _join(list(dict.fromkeys(lost)))
        )
    if aborted:
        clauses.append(
            "the directory read stopped at " + _join(list(dict.fromkeys(aborted)))
        )
    skewed = [stage_label(f.stage) for f in failures if f.reason == REASON_CLOCK_SKEW]
    if skewed:
        clauses.append(
            "Kerberos refused "
            + _join(list(dict.fromkeys(skewed)))
            + " because the clock difference with the domain controller could not be corrected"
        )
    if any(f.reason == REASON_NO_OBJECTS for f in failures):
        clauses.append("the directory returned no user objects")
    if any(f.reason == REASON_NO_RESULT for f in failures):
        clauses.append("the collector produced no result for the domain")
    return "; ".join(clauses) or "the directory read did not finish"


def begin_collection_attempt(shell: Any, domain: str) -> None:
    """Forget an earlier attempt's incomplete mark: this attempt is judged afresh."""
    try:
        from adscan_internal.services import scan_progress  # noqa: PLC0415

        scan_progress.clear_phase_incomplete(shell, domain, COLLECTION_PHASE_ID)
    except Exception:  # noqa: BLE001 - integrity tracking never breaks collection
        pass


def declare_collection_integrity(
    shell: Any, domain: str, result: Any, *, aborted: BaseException | None = None
) -> tuple[str, ...]:
    """Mark ``domain_collection`` incomplete when ``result`` says it did not finish.

    Args:
        shell: The scan shell (the phase record lives in ``domains_data``).
        domain: The domain that was collected.
        result: The domain's ``CollectionResult``; ``None`` when the collector
            produced none.
        aborted: The exception that ended the collection driver early, if any.

    Returns:
        The operator-facing parts that were not read (empty when complete), for
        the collection panel.
    """
    try:
        from adscan_internal.services.collector.models import (  # noqa: PLC0415
            CollectionStageFailure,
        )

        failures = list(getattr(result, "stage_failures", None) or [])
        if result is None:
            failures.append(CollectionStageFailure("collector", REASON_NO_RESULT))
        if aborted is not None:
            failures.append(
                CollectionStageFailure(
                    "collector",
                    REASON_TRANSPORT_LOST
                    if _is_transport_loss(aborted)
                    else REASON_ABORTED,
                    type(aborted).__name__,
                )
            )
        if not failures:
            return ()
        from adscan_internal.services import scan_progress  # noqa: PLC0415

        detail = describe_incomplete(failures)
        scan_progress.mark_phase_incomplete(
            shell,
            domain,
            COLLECTION_PHASE_ID,
            reasons=failure_tokens(failures),
            detail=detail,
        )
        _warn(domain, detail)
        return incomplete_parts(failures)
    except Exception as exc:  # noqa: BLE001 - integrity tracking never breaks collection
        from adscan_core import telemetry  # noqa: PLC0415
        from adscan_core.rich_output import print_exception  # noqa: PLC0415

        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return ()


def begin_mssql_collection_attempt(shell: Any, domain: str) -> None:
    """Forget an earlier SQL Server pass's incomplete mark before a new pass."""
    try:
        from adscan_internal.services import scan_progress  # noqa: PLC0415

        scan_progress.clear_phase_incomplete(shell, domain, MSSQL_COLLECTION_PHASE_ID)
    except Exception:  # noqa: BLE001 - integrity tracking never breaks collection
        pass


def declare_mssql_collection_integrity(
    shell: Any, domain: str, failures: Iterable[Any]
) -> tuple[str, ...]:
    """Mark the SQL Server collection incomplete when a query was cut off.

    ``failures`` are ``CollectionStageFailure`` records (stage
    ``mssql.<query>``). A query that never ran is never logged as a clean pass:
    the edge it would have produced (a linked server, a role) is missing, and
    the run says so through the phase record ``adscan ci`` and ``coverage.json``
    read.

    Returns:
        The operator-facing parts that were not read (empty when complete).
    """
    try:
        failures = list(failures or ())
        if not failures:
            return ()
        from adscan_internal.services import scan_progress  # noqa: PLC0415

        detail = describe_incomplete(failures)
        scan_progress.mark_phase_incomplete(
            shell,
            domain,
            MSSQL_COLLECTION_PHASE_ID,
            reasons=failure_tokens(failures),
            detail=detail,
        )
        from adscan_core.rich_output import mark_sensitive, print_warning  # noqa: PLC0415

        print_warning(
            f"SQL Server collection for {mark_sensitive(domain, 'domain')} is incomplete: "
            f"{detail}. The edges those reads would have produced are missing, and the "
            "run will not report this domain as fully assessed."
        )
        return incomplete_parts(failures)
    except Exception as exc:  # noqa: BLE001 - integrity tracking never breaks collection
        from adscan_core import telemetry  # noqa: PLC0415
        from adscan_core.rich_output import print_exception  # noqa: PLC0415

        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return ()


def _is_transport_loss(exc: BaseException) -> bool:
    from adscan_internal.services.auth_error_classification import (  # noqa: PLC0415
        is_transport_loss_error,
    )

    return is_transport_loss_error(exc)


def _warn(domain: str, detail: str) -> None:
    from adscan_core.rich_output import mark_sensitive, print_warning  # noqa: PLC0415

    print_warning(
        f"Domain Collection for {mark_sensitive(domain, 'domain')} is incomplete: "
        f"{detail}. Attack paths and findings cover only what was read, and the "
        "run will not report this domain as fully assessed."
    )


__all__ = [
    "COLLECTION_PHASE_ID",
    "MSSQL_COLLECTION_PHASE_ID",
    "REASON_CLOCK_SKEW",
    "begin_mssql_collection_attempt",
    "cut_off_read_reason",
    "declare_mssql_collection_integrity",
    "is_clock_skew_error",
    "REASON_ABORTED",
    "REASON_NO_OBJECTS",
    "REASON_NO_RESULT",
    "REASON_TRANSPORT_LOST",
    "begin_collection_attempt",
    "declare_collection_integrity",
    "describe_incomplete",
    "failure_tokens",
    "incomplete_parts",
    "note_stage_exception",
    "stage_label",
]
