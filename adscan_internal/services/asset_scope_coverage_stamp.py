"""Stamp the asset-scope coverage blocks from the engagement's scope record.

A client can name the hosts and directory objects an assessment must leave
alone (a deny list), or the only ones it may assess (an allow list). The engine
keeps every excluded object out of contact and out of every attack step
(:mod:`adscan_internal.services.engagement_scope`), and records what it refused
in ``scope.json``. This module is the reporting half's write seam: it reads that
record and persists, per domain, the client-facing coverage block built by the
shared SSOT
(:func:`adscan_core.reporting.engagement_scope.build_asset_scope_coverage`),
plus the run-level summary.

It is called from the scan itself (the scan-finalization seam), never only from
a report step, so a run that produces no report still declares the gap: an
excluded object was never contacted or acted on, and must never read as checked
and clean.

Best-effort throughout: a coverage stamp never breaks a scan.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from adscan_core import telemetry
from adscan_core.reporting.engagement_scope import (
    EXCLUSION_REASONS,
    REASON_DC_DIRECTORY_ONLY,
    UNCONFIRMED_REASONS,
    asset_route_counts,
    build_asset_scope_coverage,
    build_asset_scope_summary,
    load_engagement_scope,
)
from adscan_core.reporting.technical_report import (
    record_asset_scope_coverage,
    record_asset_scope_summary,
)
from adscan_core.rich_output import print_exception, print_info_debug


def _clean(value: Any) -> str:
    return str(value or "").strip().rstrip(".").lower()


def _run_domains(shell: Any) -> list[str]:
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return []
    return [d for d in domains_data if isinstance(d, str) and d.strip()]


def _refusal_domain(target: str, domains: list[str]) -> str:
    """The run domain a refused target belongs to (by DNS suffix), or ``""``."""
    name = _clean(target)
    if not name:
        return ""
    best = ""
    for domain in domains:
        low = _clean(domain)
        if name == low or name.endswith("." + low):
            if len(low) > len(best):
                best = low
    if best:
        return best
    return domains[0].strip().lower() if len(domains) == 1 else ""


def _excluded_by_domain(
    refusals: Iterable[Mapping[str, Any]], domains: list[str]
) -> dict[str, list[dict[str, Any]]]:
    """Group the run's asset refusals into excluded-object inputs, per domain.

    The deny entries that resolved to an identity are folded in by the builder
    from the record's resolution; these are the refusals (allow-list misses,
    undetermined targets, and any denied target met before it resolved). Each
    row carries the domain the engine judged it in, so an object known only by
    an address still lands in its own domain's block; a row written before the
    engine recorded that is mapped by DNS suffix. A refusal for one domain
    never counts in another's block.
    """
    out: dict[str, list[dict[str, Any]]] = {}
    run_domains = {_clean(d) for d in domains}
    for row in refusals or ():
        reason = str(row.get("reason") or "")
        if reason not in EXCLUSION_REASONS:
            continue
        target = str(row.get("target") or "")
        recorded = _clean(row.get("domain"))
        domain = recorded if recorded in run_domains else _refusal_domain(target, domains)
        if not domain:
            continue
        # The object's own name when the engine established it, else the form
        # the target was known in.
        label = str(row.get("label") or "").strip() or target
        out.setdefault(domain, []).append(
            {
                "kind": str(row.get("kind") or "computer"),
                "label": label,
                "fqdn": label if "." in label else "",
                "domain": domain,
                "reason": reason,
                "entry": str(row.get("entry") or ""),
                # How the target was known when the engine refused it, and why
                # it could not be placed: both are the engine's own words (the
                # reporting layer infers a cause only for a row without one).
                "known_as": str(row.get("known_as") or target),
                "cause": str(row.get("cause") or ""),
            }
        )
    return out


def _is_account_label(kind: str, target: str) -> bool:
    return kind != "computer" or "@" in target or "\\" in target or target.endswith("$")


def _refusals_as_read_now(
    shell: Any, refusals: list[Mapping[str, Any]], domains: list[str]
) -> list[Mapping[str, Any]]:
    """The run's refusals, with every "not confirmed" row read again NOW.

    A refusal is recorded when a seam leaves a target out. A target the scope
    could not place at that moment (an account named before the directory was
    read, a host whose name had not resolved yet) is recorded as "not
    confirmed", and that row used to stand to the end of the run: the report
    then told the client an object was left alone as a precaution when the
    directory had since placed it inside the scope. So, before the coverage is
    derived, each such row is judged again with what the session knows at the
    end of the run:

    * inside the scope now: the row is dropped (it was a provisional answer);
    * excluded now: it is reported as the exclusion it is, with its entry;
    * still not placed: it stays, with the engine's own cause.

    Established exclusions are never re-read, and without a live session (a
    reader in another process) the rows are returned as recorded.
    """
    pending = [
        (index, row)
        for index, row in enumerate(refusals)
        if str(row.get("reason") or "") in UNCONFIRMED_REASONS and str(row.get("target") or "").strip()
    ]
    if not pending:
        return refusals
    try:
        from adscan_internal.services.engagement_scope import (  # noqa: PLC0415
            ScopeOutcome,
            asset_scope_recorded,
            asset_scope_unreadable,
            host_scope_verdict,
        )
        from adscan_internal.services.engagement_scope_principals import (  # noqa: PLC0415
            account_scope_refusal,
            prepare_accounts_for_scope,
        )
        from adscan_internal.services.engagement_scope_targets import (  # noqa: PLC0415
            prepare_targets_for_scope,
        )

        if not asset_scope_recorded(shell) or asset_scope_unreadable(shell):
            return refusals
        run_domains = {_clean(d) for d in domains}

        def _domain_of(row: Mapping[str, Any]) -> str:
            recorded = _clean(row.get("domain"))
            return recorded if recorded in run_domains else _refusal_domain(str(row.get("target") or ""), domains)

        # One preparation per domain and per kind of label, then reads.
        hosts: dict[str, list[str]] = {}
        accounts: dict[str, list[str]] = {}
        for _index, row in pending:
            target = str(row.get("target") or "").strip()
            bucket = accounts if _is_account_label(str(row.get("kind") or "computer"), target) else hosts
            bucket.setdefault(_domain_of(row), []).append(target)
        for domain, names in hosts.items():
            prepare_targets_for_scope(shell, list(dict.fromkeys(names)), domain=domain or None)
        for domain, names in accounts.items():
            prepare_accounts_for_scope(shell, list(dict.fromkeys(names)), domain=domain or None)

        out: list[Mapping[str, Any] | None] = list(refusals)
        for index, row in pending:
            target = str(row.get("target") or "").strip()
            domain = _domain_of(row) or None
            if _is_account_label(str(row.get("kind") or "computer"), target):
                verdict = account_scope_refusal(shell, principal=target, domain=domain)
            else:
                verdict = host_scope_verdict(shell, host=target, domain=domain)
                if verdict.allowed:
                    verdict = None
            if verdict is None:
                out[index] = None
                continue
            if verdict.outcome is ScopeOutcome.UNDETERMINED:
                if not str(row.get("cause") or "") and verdict.cause:
                    out[index] = {**row, "cause": verdict.cause}
                continue
            out[index] = {
                **row,
                # What the directory now says the object is, and is called.
                "kind": verdict.kind or str(row.get("kind") or ""),
                "label": verdict.label or str(row.get("label") or ""),
                "reason": verdict.reason,
                "entry": verdict.entry_id or "",
                "outcome": "excluded",
                "cause": "",
            }
        return [row for row in out if row is not None]
    except Exception as exc:  # noqa: BLE001 - the rows are then reported as recorded
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return refusals


def _directory_only_dcs(
    refusals: Iterable[Mapping[str, Any]], domains: list[str]
) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for row in refusals or ():
        if str(row.get("reason") or "") != REASON_DC_DIRECTORY_ONLY:
            continue
        target = str(row.get("label") or "").strip() or str(row.get("target") or "")
        recorded = _clean(row.get("domain"))
        domain = (
            recorded
            if recorded in {_clean(d) for d in domains}
            else _refusal_domain(target, domains)
        )
        if not domain or not target:
            continue
        names = out.setdefault(domain, [])
        if target not in names:
            names.append(target)
    return out


def _domain_block(shell: Any, domain: str) -> dict[str, Any] | None:
    """Build (without persisting) the asset-scope block of one domain."""
    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "")
    if not workspace_dir or not domain:
        return None
    payload = load_engagement_scope(workspace_dir)
    asset_block = (payload or {}).get("asset_scope") if isinstance(payload, Mapping) else None
    if not isinstance(asset_block, Mapping):
        return None
    domains = _run_domains(shell) or [domain]
    refusals = [r for r in asset_block.get("refusals") or () if isinstance(r, Mapping)]
    refusals = _refusals_as_read_now(shell, refusals, domains)
    return build_asset_scope_coverage(
        asset_block,
        domain=domain,
        excluded=_excluded_by_domain(refusals, domains).get(_clean(domain), ()),
        directory_only_dcs=_directory_only_dcs(refusals, domains).get(_clean(domain), ()),
    )


def asset_scope_block_for_domain(shell: Any, domain: str) -> dict[str, Any] | None:
    """The asset-scope block of one domain as it stands now, without persisting it.

    ``None`` when the run has no asset scope (none recorded, or cleared). For a
    reader that needs to know whether a scope applies before it counts anything
    (the usage register). Never raises.
    """
    try:
        return _domain_block(shell, domain)
    except Exception as exc:  # noqa: BLE001 - a coverage aid, never a blocker
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


def excluded_host_names(
    shell: Any, domain: str, *, population: str = "excluded"
) -> frozenset[str]:
    """Names of the computers of ``domain`` the asset scope kept out of the assessment.

    ``population`` is ``"excluded"`` (the client's exclusions), ``"unconfirmed"``
    (not confirmed as within the scope) or ``"all"``. For a coverage figure that
    counts computers (the network-reach statement), so such a computer leaves its
    denominator instead of reading as one that did not answer. Empty without an
    asset scope. Never raises.
    """
    try:
        from adscan_core.reporting.engagement_scope import (  # noqa: PLC0415
            ASSET_SCOPE_COVERAGE_KEY,
            excluded_host_aliases,
        )

        block = _domain_block(shell, domain)
        if not block:
            return frozenset()
        return excluded_host_aliases({ASSET_SCOPE_COVERAGE_KEY: block}, population=population)
    except Exception as exc:  # noqa: BLE001 - a coverage aid, never a blocker
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return frozenset()


def _run_verification(shell: Any) -> Mapping[str, Any] | None:
    """The scope verification as the run ends (what the session knows; no lookup)."""
    try:
        from adscan_internal.services.engagement_scope_verify import (  # noqa: PLC0415
            verify_asset_scope,
        )

        return verify_asset_scope(shell, refresh=False)
    except Exception as exc:  # noqa: BLE001 - the block is then written without the rows
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


def _entry_outcomes(
    shell: Any, domain: str, verification: Mapping[str, Any] | None
) -> dict[str, Any] | None:
    """What became of each entry the client wrote, for one domain.

    Which computers answered comes from the run's network-reach figures (the
    domain's reachability report, classified by ``host_reach_states``), never
    from a second measurement.
    """
    if not isinstance(verification, Mapping) or not verification.get("usable", True):
        return None
    try:
        import json  # noqa: PLC0415
        import os  # noqa: PLC0415

        from adscan_core.reporting.engagement_scope import build_entry_outcomes  # noqa: PLC0415
        from adscan_core.reporting.host_reach_coverage import host_reach_states  # noqa: PLC0415
        from adscan_internal.services.graph_runtime import domain_dir_for  # noqa: PLC0415

        report = None
        path = os.path.join(domain_dir_for(shell, domain), "network_reachability_report.json")
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as handle:
                report = json.load(handle)
        return build_entry_outcomes(
            verification.get("entries"),
            domain=domain,
            host_reach=host_reach_states(report),
            host_states=verification.get("host_states"),
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


def stamp_asset_scope_coverage(
    shell: Any, *, listings: Mapping[str, Iterable[Any]] | None = None
) -> None:
    """Record the asset-scope coverage block for every domain of the run.

    ``listings`` are the canonical per-domain attack-path records, so the block
    can count the routes and steps the asset scope kept from running. Never
    raises.
    """
    try:
        workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "")
        domains = _run_domains(shell)
        if not workspace_dir or not domains:
            return
        payload = load_engagement_scope(workspace_dir)
        asset_block = (payload or {}).get("asset_scope") if isinstance(payload, Mapping) else None
        if not isinstance(asset_block, Mapping):
            # No asset scope, or it was cleared: drop a stale run-level summary.
            record_asset_scope_summary(shell, summary=None)
            return
        allow = [r for r in asset_block.get("allow") or () if isinstance(r, Mapping)]
        deny = [r for r in asset_block.get("deny") or () if isinstance(r, Mapping)]
        if not allow and not deny:
            record_asset_scope_summary(shell, summary=None)
            return

        refusals = [r for r in asset_block.get("refusals") or () if isinstance(r, Mapping)]
        refusals = _refusals_as_read_now(shell, refusals, domains)
        excluded_by_domain = _excluded_by_domain(refusals, domains)
        dcs_by_domain = _directory_only_dcs(refusals, domains)
        listings = listings or {}
        verification = _run_verification(shell)
        blocks: list[dict[str, Any]] = []
        for domain in domains:
            counts = asset_route_counts(listings.get(domain) or ())
            block = build_asset_scope_coverage(
                asset_block,
                domain=domain,
                excluded=excluded_by_domain.get(_clean(domain), ()),
                directory_only_dcs=dcs_by_domain.get(_clean(domain), ()),
                entry_outcomes=_entry_outcomes(shell, domain, verification),
                **counts,
            )
            if block is None:
                continue
            record_asset_scope_coverage(shell, domain, coverage=block)
            blocks.append(block)
            print_info_debug(
                "asset-scope coverage stamped: "
                f"domain={domain} excluded_computers={block['excluded_computers']} "
                f"excluded_accounts={block['excluded_accounts']} "
                f"unconfirmed={block['unconfirmed_computers'] + block['unconfirmed_accounts']} "
                f"routes={counts['routes_not_executed']}/{counts['routes_unconfirmed']}"
            )
        summary = build_asset_scope_summary(asset_block, blocks)
        record_asset_scope_summary(shell, summary=summary)
    except Exception as exc:  # noqa: BLE001 - a coverage stamp never breaks a scan
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


__all__ = ["asset_scope_block_for_domain", "excluded_host_names", "stamp_asset_scope_coverage"]
