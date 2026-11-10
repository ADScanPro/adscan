"""One recheck run, end to end (spec section 10).

resolve target (ledger) -> observe reads / walk through the attack-path loop ->
``build_recheck_decisions`` (shared ``reconcile``) -> one ``recheck`` run applied
to the ledger -> export -> run folder evidence -> events -> operator output.

The run never writes the workspace's flat ``coverage.json`` or reports: those are
the last scan's latest view. Its own evidence is ``runs/<run_id>/``
(``run_manifest.json``, ``coverage.json``, ``recheck_result.json``).
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, ContextManager, Iterator, Mapping, Optional, Sequence

from adscan_core.engagement.coverage_io import run_coverage_to_document
from adscan_core.engagement.model import RUN_COMPLETE, CheckStatus, Transition, Vantage
from adscan_core.engagement.recheck import (
    DEPTH_EXERCISE,
    DEPTH_OBSERVE,
    DEPTH_WALK,
    KIND_RECHECK,
    LEVEL_PATH,
    LEVEL_STEP,
    RESULT_SCHEMA,
    VERDICT_LABELS,
    WALK_STOPPED,
    ReadOutcome,
    RecheckDecisions,
    RecheckError,
    RecheckTarget,
    TargetItem,
    WalkStep,
    build_recheck_decisions,
    plan_document,
)
from adscan_core.engagement.store import (
    EXPORT_DIRNAME,
    STORE_DIRNAME,
    LedgerItem,
    RunRecord,
    open_store,
    store_path,
)
from adscan_internal.services.recheck.observers import ReadContext, run_observer
from adscan_internal.services.recheck.targets import read_plan, select_targets

RESULT_FILENAME = "recheck_result.json"


class DomainUnavailable(RuntimeError):
    """A domain cannot be read in this run; ``str(exc)`` is the reason code."""


Connector = Callable[[str], ContextManager[ReadContext]]
Executor = Callable[[str, dict[str, Any]], list[Any]]


@dataclass(frozen=True)
class RecheckRequest:
    """One recheck invocation."""

    workspace: str
    target: RecheckTarget
    depth: str = DEPTH_OBSERVE


@dataclass
class RecheckReport:
    """What one recheck run did."""

    run_id: str
    decisions: RecheckDecisions
    targets: list[TargetItem]
    walk: list[WalkStep] = field(default_factory=list)
    result_path: str = ""

    def count(self, transition: Transition) -> int:
        return sum(1 for r in self.decisions.results if r.transition is transition)


# ---------------------------------------------------------------------------
# Reads.
# ---------------------------------------------------------------------------


def run_reads(
    plan: dict[tuple[str, str], Optional[frozenset[str]]], connect: Connector
) -> list[ReadOutcome]:
    """Run every planned read, one connection per domain, sequentially."""
    outcomes: list[ReadOutcome] = []
    by_domain: dict[str, list[tuple[str, Optional[frozenset[str]]]]] = {}
    for (check_id, domain_id), objects in sorted(plan.items(), key=lambda kv: kv[0]):
        by_domain.setdefault(domain_id, []).append((check_id, objects))
    for domain_id, checks in by_domain.items():
        try:
            with connect(domain_id) as ctx:
                for check_id, objects in checks:
                    outcomes.append(run_observer(check_id, ctx, objects))
        except DomainUnavailable as exc:
            reason = str(exc) or "domain_unavailable"
            outcomes.extend(
                ReadOutcome(check_id, domain_id, CheckStatus.FAILED, None, {}, reason)
                for check_id, _objects in checks
                if not any(o.check_id == check_id and o.domain_id == domain_id for o in outcomes)
            )
    return outcomes


def _shell_domain(shell: Any, domain_id: str) -> str:
    for name in (getattr(shell, "domains_data", None) or {}):
        if str(name).strip().rstrip(".").lower() == domain_id:
            return str(name)
    return ""


def shell_connector(shell: Any, observations: Optional[list[dict[str, Any]]] = None) -> Connector:
    """Read-only LDAP connections built from the workspace's own credential.

    Per domain: DNS for the domain, the posture guard, ONE credential
    resolution through ``resolve_sweep_credential`` (a failed mint aborts that
    domain's reads, never retries), then ``ADscanLDAPConnection`` (LDAPS with
    the automatic LDAP fallback, posture-aware auth plan).
    """

    @contextmanager
    def _connect(domain_id: str) -> Iterator[ReadContext]:
        from adscan_core import telemetry  # noqa: PLC0415
        from adscan_internal.models.domain import resolve_dc_ip  # noqa: PLC0415
        from adscan_internal.services.domain_posture import get_posture  # noqa: PLC0415
        from adscan_internal.services.ldap_transport_service import (  # noqa: PLC0415
            ADscanLDAPConnection,
            build_ldap_config_for_domain,
        )
        from adscan_internal.services.sweep_credential import (  # noqa: PLC0415
            resolve_sweep_credential,
        )

        domain = _shell_domain(shell, domain_id)
        if not domain:
            raise DomainUnavailable("domain_not_in_workspace")
        data = shell.domains_data.get(domain) or {}
        user = str(data.get("username") or "").strip()
        secret = str(data.get("password") or "")
        if not user or not secret:
            raise DomainUnavailable("no_credential")
        dc_ip = str(resolve_dc_ip(data) or "").strip()
        if not dc_ip:
            raise DomainUnavailable("no_domain_controller")
        try:
            shell.do_check_dns(domain, dc_ip)
        except Exception as exc:  # noqa: BLE001 - DNS setup is best-effort
            telemetry.capture_exception(exc)
        _ensure_posture(shell, domain, dc_ip, user, secret)
        if observations is not None:
            _collect_control_observations(shell, domain, domain_id, observations)
        sweep = resolve_sweep_credential(
            shell, domain=domain, username=user, password=secret, kdc_ip=dc_ip
        )
        if sweep.aborted:
            raise DomainUnavailable("credential_rejected")
        try:
            posture = get_posture(shell.domains_data, domain=domain)
        except Exception:  # noqa: BLE001 - an optimisation, never required
            posture = None
        config = build_ldap_config_for_domain(
            shell.domains_data,
            domain,
            username=user,
            password=sweep.password,
            nt_hash=sweep.nt_hash,
            ccache_path=sweep.ccache_path,
            use_ldaps=True,
            use_kerberos=True if sweep.ccache_path else None,
            posture_snapshot=posture,
        )
        try:
            connection = ADscanLDAPConnection(config)
            conn = connection.__enter__()
        except Exception as exc:  # noqa: BLE001 - a failed bind never closes anything
            telemetry.capture_exception(exc)
            raise DomainUnavailable("connect_failed") from exc
        try:
            yield ReadContext(conn=conn, domain_id=domain_id, domain_dn=conn.domain_dn)
        finally:
            connection.__exit__(None, None, None)

    return _connect


def _collect_control_observations(
    shell: Any, domain: str, domain_id: str, sink: list[dict[str, Any]]
) -> None:
    from adscan_internal.services.positive_control_evidence import (  # noqa: PLC0415
        observed_posture_controls,
    )

    seen = {(o["domain_id"], o["key"]) for o in sink}
    for row in observed_posture_controls(shell, domain):
        if (domain_id, row["key"]) not in seen:
            sink.append({"domain_id": domain_id, **row})


def _ensure_posture(shell: Any, domain: str, dc_ip: str, user: str, secret: str) -> None:
    from adscan_core import telemetry  # noqa: PLC0415

    try:
        import asyncio  # noqa: PLC0415

        from adscan_internal.services.posture_orchestration import (  # noqa: PLC0415
            ensure_posture_fresh,
        )
        from adscan_internal.services.posture_probe import (  # noqa: PLC0415
            ProbeCredentials,
            ProbePhase,
        )

        asyncio.run(
            ensure_posture_fresh(
                shell,
                domain=domain,
                dc_ip=dc_ip,
                creds=ProbeCredentials(username=user, password=secret),
                phase=ProbePhase.AUTH,
                record_evidence=False,
            )
        )
    except Exception as exc:  # noqa: BLE001 - posture is best-effort
        telemetry.capture_exception(exc)


# ---------------------------------------------------------------------------
# The run.
# ---------------------------------------------------------------------------


def _ledger_item(item: TargetItem) -> LedgerItem:
    return LedgerItem(
        item_id=item.item_id,
        kind=item.kind,
        key=item.key,
        domain_id=item.domain_id,
        object_id=item.object_id,
        label=item.label,
    )


def _result_document(
    request: RecheckRequest,
    run_id: str,
    report_targets: Sequence[TargetItem],
    decisions: RecheckDecisions,
    outcomes: Sequence[ReadOutcome],
    walk: Sequence[WalkStep],
    recorded_at: str,
    frame: Any,
) -> dict[str, Any]:
    transitions = {r.item_id: r for r in decisions.results}
    items = []
    for item in report_targets:
        verdict = decisions.verdicts.get(item.item_id)
        result = transitions.get(item.item_id)
        items.append(
            {
                "item_id": item.item_id,
                "kind": item.kind,
                "key": item.key,
                "domain_id": item.domain_id,
                "object_id": item.object_id,
                "label": item.label,
                "check_id": item.check_id,
                "verdict": verdict.code if verdict else "",
                "verdict_text": verdict.text if verdict else "",
                "reason": verdict.reason if verdict else "",
                "transition": result.transition.value if result else "",
            }
        )
    return {
        "schema": RESULT_SCHEMA,
        "run_id": run_id,
        "plan": plan_document(request.target, request.depth, workspace=request.workspace, run_id=run_id),
        "recorded_at": recorded_at,
        "recorded_at_frame": frame,
        "items": items,
        "reads": [
            {
                "check_id": o.check_id,
                "domain_id": o.domain_id,
                "status": o.status.value,
                "scope": "domain" if o.examined_ids is None else "object",
                "examined": None if o.examined_ids is None else len(o.examined_ids),
                "reason": o.reason,
            }
            for o in outcomes
        ],
        "walk": [{"item_id": w.item_id, "outcome": w.outcome, "reason": w.reason} for w in walk],
    }


def _parent_run_id(store: Any) -> str:
    scans = [r for r in store.runs() if r["kind"] != KIND_RECHECK]
    return str(scans[-1]["run_id"]) if scans else ""


def execute_recheck(
    workspace_dir: Path,
    request: RecheckRequest,
    *,
    run_id: str,
    connect: Connector,
    execute: Optional[Executor] = None,
    domains: Sequence[str] = (),
    stamp: Optional[Callable[[], tuple[str, Any]]] = None,
    emit: Optional[Callable[..., None]] = None,
    control_observations: Optional[Sequence[Mapping[str, Any]]] = None,
) -> RecheckReport:
    """Run one recheck against ``workspace_dir``'s ledger and record it.

    Args:
        workspace_dir: The workspace (must hold ``engagement/engagement.sqlite``).
        request: Target and depth (already validated).
        run_id: This run's id.
        connect: ``domain_id -> context manager of ReadContext`` (read-only).
        execute: ``(domain, summary) -> step outcomes`` for exercise / walk.
        domains: Workspace domain names (path resolution).
        stamp: ``() -> (recorded_at, frame)``.
        emit: ``(event_type, **fields)`` for the event stream.
        control_observations: Controls the recheck's reads observed (posture),
            stored in this run's result document, never in the scan's report.

    Raises:
        RecheckError: the target names nothing usable; nothing was written.
    """
    from adscan_internal.services.engagement.run_folder import write_run_evidence  # noqa: PLC0415
    from adscan_internal.services.recheck import walk as walk_mod  # noqa: PLC0415

    emit = emit or (lambda *_a, **_k: None)
    target = request.target
    store = open_store(store_path(workspace_dir))
    try:
        path_steps: Optional[Callable[[str], Sequence[str]]] = None
        paths: list[Any] = []
        resolved = None
        summary: Optional[dict[str, Any]] = None
        if target.level == LEVEL_PATH or (target.level == LEVEL_STEP and request.depth == DEPTH_EXERCISE):
            paths = walk_mod.canonical_paths(str(workspace_dir), domains)
            if target.level == LEVEL_PATH:
                resolved = walk_mod.find_path(paths, target.path)
                step_ids = walk_mod.path_step_item_ids(str(workspace_dir), resolved)
                path_steps = lambda _token: step_ids  # noqa: E731
                summary = resolved.record
        targets = select_targets(store, target, path_steps=path_steps)
        if target.level == LEVEL_STEP and request.depth == DEPTH_EXERCISE:
            resolved, summary = walk_mod.find_step_summary(paths, str(workspace_dir), targets[0].item_id)

        walk: list[WalkStep] = []
        outcomes: list[ReadOutcome] = []
        if request.depth in {DEPTH_WALK, DEPTH_EXERCISE}:
            if execute is None or resolved is None or summary is None:
                raise RecheckError("Exercise and walk need the attack-path executor.")
            step_outcomes = execute(resolved.domain, summary)
            if not step_outcomes:
                raise RecheckError(
                    "The route was not started: the scan policy, the readiness check or "
                    "the operator kept it from running. Nothing was recorded."
                )
            summary_ids = (
                [targets[0].item_id]
                if target.level == LEVEL_STEP
                else walk_mod.path_step_item_ids(str(workspace_dir), resolved)
            )
            from adscan_core.workspace_secret_purge import (  # noqa: PLC0415
                removed_credential_principals,
            )

            walk = walk_mod.walk_steps_from_outcomes(
                step_outcomes,
                summary_ids,
                removed_principals=removed_credential_principals(workspace_dir).get(
                    str(resolved.domain).lower(), set()
                ),
            )
            # A stopped step closes only when its own read confirms the
            # condition is gone: read the stopped steps that have a check.
            stopped = {w.item_id for w in walk if w.outcome == WALK_STOPPED}
            outcomes = run_reads(read_plan([t for t in targets if t.item_id in stopped]), connect)
        else:
            outcomes = run_reads(read_plan(targets, narrowed_objects=target.objects), connect)

        vantage = Vantage.AUTH
        decisions = build_recheck_decisions(targets, outcomes, vantage=vantage, walk=walk, run_id=run_id)
        recorded_at, frame = stamp() if stamp else ("", {})
        store.apply_run(
            RunRecord(
                run_id=run_id,
                kind=KIND_RECHECK,
                status=RUN_COMPLETE,
                vantage=vantage,
                finished_at=recorded_at,
                parent_run_id=_parent_run_id(store),
            ),
            decisions.results,
            [_ledger_item(t) for t in targets],
            decisions.coverage,
            at=recorded_at,
        )
        store.export(Path(workspace_dir) / STORE_DIRNAME / EXPORT_DIRNAME, generated_at=recorded_at)
        result = _result_document(request, run_id, targets, decisions, outcomes, walk, recorded_at, frame)
        result["control_observations"] = [
            {**dict(o), "last_seen": recorded_at} for o in (control_observations or ())
        ]
        from adscan_core.version import get_version  # noqa: PLC0415

        folder = write_run_evidence(
            workspace_dir,
            {
                "run_id": run_id,
                "kind": KIND_RECHECK,
                "parent_run_id": _parent_run_id(store),
                "run_status": RUN_COMPLETE,
                "vantage": int(vantage),
                "engagement_id": store.engagement_id,
                "recorded_at": recorded_at,
                "recorded_at_frame": frame,
                "engine_version": get_version(),
            },
            {
                RESULT_FILENAME: result,
                "coverage.json": run_coverage_to_document(decisions.coverage, run_id=run_id),
            },
        )
        for row in result["items"]:
            emit(
                "recheck_item",
                run_id=run_id,
                item_id=row["item_id"],
                kind=row["kind"],
                verdict=row["verdict"],
                reason=row["reason"],
                transition=row["transition"],
            )
        rel = str((folder / RESULT_FILENAME).relative_to(Path(workspace_dir)))
        return RecheckReport(run_id=run_id, decisions=decisions, targets=list(targets), walk=walk,
                             result_path=rel)
    finally:
        store.close()


def verdict_label(code: str) -> str:
    """Client-facing phrase of a verdict code."""
    return VERDICT_LABELS.get(code, code)


__all__ = (
    "DomainUnavailable",
    "RESULT_FILENAME",
    "RecheckReport",
    "RecheckRequest",
    "execute_recheck",
    "run_reads",
    "shell_connector",
    "verdict_label",
)
