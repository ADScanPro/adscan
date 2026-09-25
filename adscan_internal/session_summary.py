"""Helpers for ADscan end-of-session summary metrics and UX."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

from adscan_internal import print_info_debug, telemetry
from adscan_internal.workspaces import domain_subpath, read_json_file, resolve_workspace_cwd
from adscan_core.rich_output import print_exception

if TYPE_CHECKING:
    from adscan_internal.services.attack_path_counts import ClientPathTotals


@dataclass(frozen=True)
class AttackPathSnapshotMetrics:
    """Attack-path metrics as counted from the persisted interactive snapshot.

    ``attack_paths_snapshot.json`` is a point-in-time projection written with
    whatever ``scope`` / ``target`` / ``target_mode`` the LAST interactive query
    used, so it is the FALLBACK source for an operator-facing count, not the
    canonical one. The canonical source is the curated client path set the
    report renders, resolved through
    :func:`~adscan_internal.services.attack_path_counts.client_path_totals`;
    :func:`resolve_client_path_totals` prefers it and falls back to this
    snapshot only when a run produced no report artifacts.
    """

    total: int = 0
    exploited: int = 0
    blocked: int = 0
    unsupported: int = 0

    @property
    def unresolved(self) -> int:
        """Return persisted paths that remain non-exploited."""
        return max(0, self.blocked + self.unsupported)

    def to_dict(self) -> dict[str, int]:
        """Return a stable dict representation for existing call sites."""
        return {
            "total": self.total,
            "exploited": self.exploited,
            "blocked": self.blocked,
            "unsupported": self.unsupported,
            "unresolved": self.unresolved,
        }


@dataclass(frozen=True)
class AttackPathVerdict:
    """End-of-scan verdict selected purely from persisted snapshot metrics.

    Pure decision object — no I/O, no session state. ``kind`` is one of:

    - ``"no_paths"`` — no attack paths persisted (``total == 0``). The honest
      "nothing found" message; the caller still splits auth vs unauth wording.
    - ``"identified_unvalidated"`` — paths were persisted but none were proven
      end-to-end (``total > 0`` and ``exploited == 0``). MUST NOT claim the
      domain is "hardened": theoretical/blocked/unsupported paths are exposure,
      not evidence of a defence.
    - ``"exploited"`` — at least one exploited path (``exploited > 0``). The
      victory / PRO-CTA branch.
    """

    kind: str
    scan_mode: str | None
    total: int
    exploited: int
    unvalidated: int


def select_attack_path_verdict(
    metrics: AttackPathSnapshotMetrics,
    *,
    scan_mode: str | None,
    reachable: int = 0,
    domain_compromised: bool = False,
) -> AttackPathVerdict:
    """Select the end-of-scan attack-path verdict from snapshot metrics.

    This is the single source of truth for which closing message the scan emits.
    It reads the persisted snapshot (via :class:`AttackPathSnapshotMetrics`),
    never the legacy in-memory session counter — that counter is never
    incremented, so keying the verdict on it falsely reports every authenticated
    scan as "hardened" even when exploited paths exist.

    Args:
        metrics: Canonical snapshot metrics for the scanned domain(s).
        scan_mode: The scan mode ("auth" / "unauth" / None). Only used to let the
            caller pick auth-vs-unauth wording for the ``no_paths`` verdict.
        reachable: The EFFECTIVE reachable full-domain-compromise count. Under the
            control-mega-hub sampled fallback the materialized snapshot (k) that
            ``metrics.total`` counts collapses to 0 while the reachability set
            still carries routes; the verdict must read the effective figure, so
            a sampled compromised domain is never reported as "no paths".
        domain_compromised: The promote oracle (``auth == "pwned"``). A domain
            ADscan proved compromised is never reported as "no paths"/0, even if
            partial artifacts momentarily leave both k and reachability at 0.

    Returns:
        An :class:`AttackPathVerdict` describing which branch to render and the
        real counts to render it with. When ``reachable``/``domain_compromised``
        are their defaults the output is byte-identical to the pre-effective
        behaviour (healthy domain where materialization succeeded).
    """
    total = max(0, int(metrics.total))
    exploited = max(0, int(metrics.exploited))
    reach = max(0, int(reachable))
    # Effective inventory: k when materialization walked the graph, the reachable
    # set cardinality when the mega-hub fallback emptied it. For a complete run
    # ``reach`` (the domain_breaker figure) never exceeds ``total`` (the full
    # curated inventory), so ``effective_total == total`` — byte-identical.
    effective_total = max(total, reach)
    if domain_compromised:
        # Never render 0/"no paths" for a proven compromise (the golden rule).
        effective_total = max(effective_total, exploited, 1)
    unvalidated = max(0, effective_total - exploited)
    normalized_mode = (str(scan_mode or "").strip().lower()) or None

    if domain_compromised or exploited > 0:
        kind = "exploited"
    elif effective_total > 0:
        kind = "identified_unvalidated"
    else:
        kind = "no_paths"

    return AttackPathVerdict(
        kind=kind,
        scan_mode=normalized_mode,
        total=effective_total,
        exploited=exploited,
        unvalidated=unvalidated,
    )


def count_workspace_credentials(shell: object) -> int:
    """Return compromised credentials stored across all loaded domains.

    Routes through the compromise SSOT (:func:`iter_compromised_credentials`)
    so the scan's own STARTING credential — the INPUT to ``adscan ci auth`` —
    is never counted as a compromise win.
    """
    try:
        from adscan_internal.services.session_compromise_state_service import (
            iter_compromised_credentials,
        )

        domains_data = getattr(shell, "domains_data", {}) or {}
        if not isinstance(domains_data, dict):
            return 0
        total = 0
        for domain in domains_data.keys():
            total += len(iter_compromised_credentials(shell, domain))
        return max(0, total)
    except Exception as exc:  # pragma: no cover - defensive
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return 0


def get_attack_path_snapshot_metrics(
    shell: object, *, domains: list[str] | None = None
) -> AttackPathSnapshotMetrics:
    """Return canonical user-facing attack-path metrics from persisted snapshots."""
    try:
        workspace_cwd = resolve_workspace_cwd(shell)
        domains_dir = getattr(shell, "domains_dir", "domains")
        domains_data = getattr(shell, "domains_data", {}) or {}
        if not isinstance(domains_data, dict):
            return AttackPathSnapshotMetrics()
        requested_domains = {
            str(domain_name or "").strip().lower()
            for domain_name in (domains or [])
            if str(domain_name or "").strip()
        }

        counts = {"total": 0, "exploited": 0, "blocked": 0, "unsupported": 0}
        analyzed_domains = 0
        for domain_name in domains_data.keys():
            domain = str(domain_name or "").strip()
            if not domain:
                continue
            if requested_domains and domain.lower() not in requested_domains:
                continue
            snapshot_path = domain_subpath(
                workspace_cwd,
                domains_dir,
                domain,
                "attack_paths_snapshot.json",
            )
            if not os.path.exists(snapshot_path):
                continue
            payload = read_json_file(snapshot_path)
            paths = payload.get("paths") if isinstance(payload, dict) else None
            if not isinstance(paths, list):
                continue
            analyzed_domains += 1
            for path in paths:
                if not isinstance(path, dict):
                    continue
                counts["total"] += 1
                status = str(path.get("status") or "").strip().lower()
                if status in counts:
                    counts[status] += 1

        if analyzed_domains <= 0:
            return AttackPathSnapshotMetrics()
        return AttackPathSnapshotMetrics(
            total=max(0, counts["total"]),
            exploited=max(0, counts["exploited"]),
            blocked=max(0, counts["blocked"]),
            unsupported=max(0, counts["unsupported"]),
        )
    except Exception as exc:  # pragma: no cover - best effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"[summary] attack-path snapshot breakdown unavailable: {exc}")
        return AttackPathSnapshotMetrics()


def get_attack_path_summary_breakdown(shell: object) -> dict[str, int]:
    """Return snapshot metrics as a dict for legacy call sites."""
    return get_attack_path_snapshot_metrics(shell).to_dict()


def _client_path_totals_memo_key(
    shell: object, domains: list[str] | None, fallback: int
) -> tuple | None:
    """Return a hashable memo key for the session path totals, or ``None``.

    The key binds the RESOLVED (placeholder-free) domain set to each domain's
    graph-epoch fingerprint — the SAME tokens the on-disk attack-path compute
    cache keys on (:func:`attack_paths_epoch_fingerprint`) — so the memo
    inherits that invalidation for free: any topology/graph change to a domain
    changes its fingerprint and the memo misses. ``fallback`` is folded in so
    the zero-path branch (which returns ``fallback``) can never serve a value
    resolved under a different fallback.

    Returns ``None`` on any failure, so the caller falls through to an uncached
    compute rather than serving under a wrong key (best-effort).
    """
    try:
        from adscan_internal.services.attack_graph_service import (
            attack_paths_epoch_fingerprint,
        )
        from adscan_internal.services.attack_step_domain_resolution import (
            is_placeholder_domain,
        )

        if domains is None:
            loaded = getattr(shell, "domains_data", None)
            names = list(loaded.keys()) if isinstance(loaded, dict) else []
        else:
            names = list(domains)

        resolved: list[tuple[str, tuple]] = []
        for name in names:
            domain_name = str(name or "").strip()
            if not domain_name or is_placeholder_domain(domain_name):
                continue
            epoch = tuple(attack_paths_epoch_fingerprint(shell, domain_name))
            resolved.append((domain_name.lower(), epoch))

        # Sort by domain name only (unique keys) so the key is order-stable and
        # heterogeneous epoch tokens are never compared against each other.
        ordered = tuple(sorted(resolved, key=lambda item: item[0]))
        return (frozenset(name for name, _ in ordered), ordered, int(fallback))
    except Exception:  # noqa: BLE001 - a bad key just disables the memo
        return None


def resolve_client_path_totals(
    shell: object,
    *,
    domains: list[str] | None = None,
    fallback_count: int = 0,
) -> "ClientPathTotals":
    """Resolve the canonical user-facing attack-path totals for a session.

    The ONE resolver every operator-facing count goes through, so the exit
    summary, the end-of-scan verdict and the session telemetry state the same
    figures the client's report states. Three sources, in order:

    1. The curated client path set (the counts SSOT
       :mod:`~adscan_internal.services.attack_path_counts`), which prefers the
       ``exposure_kpis`` block stamped by this run's report.
    2. The persisted interactive snapshot, when the run wrote no report
       artifacts. Its scope is whatever the last query used, so it is a
       fallback and never the preferred answer.
    3. ``fallback_count``, for a session with neither.

    Source 1 recomputes the full domain-scope attack-path projection, which is
    seconds of work on a large domain. At exit THREE consumers resolve these
    totals (the session summary, the report CTA, the ``session_end`` telemetry
    event), so the result is memoized on the shell keyed by the graph epoch —
    computed once, shared across the three, and auto-invalidated the instant the
    graph changes.

    Args:
        shell: The active shell (workspace context only).
        domains: Restrict to these domains; ``None`` counts every loaded domain.
        fallback_count: Last-resort total when nothing is on disk.

    Returns:
        A :class:`~adscan_internal.services.attack_path_counts.ClientPathTotals`.
        Sources 2 and 3 populate only ``paths_total`` / ``paths_proven``, since
        a snapshot carries no exposure or hardening split.
    """
    fallback = max(0, int(fallback_count or 0))

    memo_key = _client_path_totals_memo_key(shell, domains, fallback)
    if memo_key is not None:
        memo = getattr(shell, "_client_path_totals_memo", None)
        if isinstance(memo, dict):
            cached = memo.get(memo_key)
            if cached is not None:
                return cached

    result = _resolve_client_path_totals_uncached(
        shell, domains=domains, fallback=fallback
    )

    if memo_key is not None:
        try:
            memo = getattr(shell, "_client_path_totals_memo", None)
            if not isinstance(memo, dict):
                memo = {}
                setattr(shell, "_client_path_totals_memo", memo)
            memo[memo_key] = result
        except Exception:  # noqa: BLE001 - memo is best-effort; never break a scan
            pass
    return result


def _resolve_client_path_totals_uncached(
    shell: object,
    *,
    domains: list[str] | None,
    fallback: int,
) -> "ClientPathTotals":
    """Compute the client path totals without consulting the shell memo.

    Split out from :func:`resolve_client_path_totals` so the memo wrapper owns
    caching and this stays the pure three-source resolution.
    """
    from adscan_internal.services.attack_path_counts import (
        ClientPathTotals,
        client_path_totals_for_session,
    )

    try:
        totals = client_path_totals_for_session(shell, domains=domains)
    except Exception as exc:  # pragma: no cover - defensive
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        totals = ClientPathTotals()
    if totals.paths_total > 0:
        return totals

    # k collapsed to 0 (the control-mega-hub sampled fallback empties the
    # materialized set). Before dropping to the interactive snapshot — which
    # carries neither the reachability set nor the coverage mode — recover the
    # EFFECTIVE totals from the stamped report via the counts SSOT, so a sampled
    # or compromised domain is never mistaken for a clean one.
    recovered = _session_effective_totals(shell, domains)
    if recovered is not None and (
        recovered.reachable_full_domain_compromise > 0
        or recovered.effective_reach_is_sampled
    ):
        return recovered

    snapshot_metrics = get_attack_path_snapshot_metrics(shell, domains=domains)
    if snapshot_metrics.total > 0:
        print_info_debug(
            "[summary] attack-path count resolved from the persisted snapshot "
            f"(no report projection): total={snapshot_metrics.total}"
        )
        return ClientPathTotals(
            paths_total=snapshot_metrics.total,
            paths_proven=snapshot_metrics.exploited,
            paths_not_assessed=snapshot_metrics.unsupported,
        )
    return ClientPathTotals(paths_total=fallback)


def _session_effective_totals(
    shell: object, domains: list[str] | None
) -> "ClientPathTotals | None":
    """Rebuild the session totals from the stamped report, reachability-preserving.

    :func:`~adscan_internal.services.attack_path_counts.client_path_totals_for_session`
    returns ``paths_total == 0`` under the control-mega-hub sampled fallback (k
    collapses), and its inner reader discards the reachability set with it — so
    the caller cannot tell a compromised sampled domain from a clean one. This
    walks the same domains but through the SSOT
    :func:`~adscan_internal.services.attack_path_counts.client_path_totals_for_domain`
    (stamped ``exposure_kpis`` + the persisted snapshot), which preserves the
    reachable-set cardinalities, the coverage mode and the snapshot-sourced
    proven count. Returns ``None`` when no stamped report exists (an older
    workspace), so the caller keeps its snapshot fallback. Never raises.
    """
    try:
        from adscan_internal.services.attack_path_counts import (
            ClientPathTotals,
            _stamped_exposure_kpis,
            client_path_totals_for_domain,
            resolve_scan_workspace_dir,
        )
        from adscan_internal.services.attack_step_domain_resolution import (
            is_placeholder_domain,
        )

        workspace_dir = resolve_scan_workspace_dir(shell)
        if not workspace_dir:
            return None
        domains_dir = getattr(shell, "domains_dir", "domains")
        if domains is None:
            loaded = getattr(shell, "domains_data", None)
            names = list(loaded.keys()) if isinstance(loaded, dict) else []
        else:
            names = list(domains)

        merged = ClientPathTotals()
        saw_stamped = False
        for name in names:
            domain_name = str(name or "").strip()
            if not domain_name or is_placeholder_domain(domain_name):
                continue
            kpis = _stamped_exposure_kpis(workspace_dir, domain_name)
            if kpis is None:
                continue
            saw_stamped = True
            snapshot = None
            try:
                snapshot_path = domain_subpath(
                    workspace_dir,
                    domains_dir,
                    domain_name,
                    "attack_paths_snapshot.json",
                )
                if os.path.exists(snapshot_path):
                    snapshot = read_json_file(snapshot_path)
            except Exception:  # noqa: BLE001 - no snapshot just means no override
                snapshot = None
            merged = merged.merged_with(
                client_path_totals_for_domain(kpis, snapshot=snapshot)
            )
        return merged if saw_stamped else None
    except Exception as exc:  # noqa: BLE001 - best effort; never break a scan
        print_info_debug(f"[summary] effective path totals unavailable: {exc}")
        return None


def _verdict_domain_compromised(shell: object, domains: list[str] | None) -> bool:
    """Return the promote oracle for the verdict's requested domain(s).

    The per-domain SSOT for a proven full compromise is
    ``domains_data[domain]["auth"] == "pwned"``. When ``domains`` is given the
    check is scoped to those domains; otherwise it reflects ANY compromised
    domain in the session. Pure read; never raises.
    """
    try:
        from adscan_internal.services.session_compromise_state_service import (
            DOMAIN_AUTH_STATE_PWNED,
            session_reached_domain_compromise,
        )

        if not domains:
            return session_reached_domain_compromise(shell)
        domains_data = getattr(shell, "domains_data", None)
        if not isinstance(domains_data, dict):
            return False
        wanted = {
            str(name or "").strip().lower()
            for name in domains
            if str(name or "").strip()
        }
        for name, entry in domains_data.items():
            if (
                str(name or "").strip().lower() in wanted
                and isinstance(entry, dict)
                and entry.get("auth") == DOMAIN_AUTH_STATE_PWNED
            ):
                return True
        return False
    except Exception:  # noqa: BLE001 - pure read, never breaks the caller
        return False


def resolve_attack_path_verdict(
    shell: object, *, domains: list[str] | None = None, scan_mode: str | None
) -> AttackPathVerdict:
    """Resolve the end-of-scan verdict, effective-figure and oracle aware.

    The one seam the scan-completion caller uses so the closing message is never
    "no paths"/0 on a domain ADscan reached or compromised. It resolves the
    canonical client totals (:func:`resolve_client_path_totals`), then feeds the
    pure :func:`select_attack_path_verdict` the two signals it needs to survive
    the control-mega-hub fallback: the EFFECTIVE reachable full-domain-compromise
    count (k when complete, the reachable-set cardinality when sampled) and the
    promote oracle (``auth == "pwned"``). The proven ``exploited`` count is the
    snapshot-sourced effective figure, so it is not lost when k collapses.
    """
    totals = resolve_client_path_totals(shell, domains=domains)
    metrics = AttackPathSnapshotMetrics(
        total=totals.paths_total,
        exploited=totals.effective_proven_full_domain_compromise,
        unsupported=totals.paths_not_assessed,
    )
    return select_attack_path_verdict(
        metrics,
        scan_mode=scan_mode,
        reachable=totals.effective_full_domain_compromise,
        domain_compromised=_verdict_domain_compromised(shell, domains),
    )


def resolve_session_attack_paths_for_summary(
    shell: object, *, fallback_count: int
) -> int:
    """Resolve the canonical user-facing attack-path count for the session."""
    return resolve_client_path_totals(shell, fallback_count=fallback_count).paths_total


def get_attack_path_metrics_for_verdict(
    shell: object, *, domains: list[str] | None = None
) -> AttackPathSnapshotMetrics:
    """Return the end-of-scan verdict's metrics, from the client path totals.

    The verdict decides which closing message a scan prints AND prints its
    ``total`` to the operator, so it must count the same paths the recap panel
    and the report count. :func:`select_attack_path_verdict` stays a pure
    decision object; only its input source changes.
    """
    totals = resolve_client_path_totals(shell, domains=domains)
    return AttackPathSnapshotMetrics(
        total=totals.paths_total,
        exploited=totals.paths_proven,
        unsupported=totals.paths_not_assessed,
    )
