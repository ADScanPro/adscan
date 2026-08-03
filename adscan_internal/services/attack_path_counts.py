"""Named attack-path cardinalities — the SSOT for "how many attack paths".

The repo already has one canonical answer for the *status* of a path
(``attack_paths_core._derive_display_status_from_steps``), one for its *reach
label* (``compromise_class.compromise_reach_label_short``) and one for the
report's *path derivation* (``report_attack_paths.compute_report_attack_paths``).
It had none for the **cardinality** of a path set, and that gap was expensive:
one GOAD run answered "how many attack paths" with ``458``, ``33``, ``30``,
``22`` and ``0`` depending on which projection was asked, and two of those
numbers were printed to the operator seconds apart under interchangeable
wording — one of them a raw DFS walk enumeration described as "validated paths".

This module computes nothing new. It gives the concepts NAMES and one entry
point, so two quantities can never again be said to a human under the same
words:

* :attr:`ClientPathTotals.paths_total` — the curated client inventory. What the
  report means by "N identified attack paths".
* :attr:`ClientPathTotals.paths_open_exposure` — the subset that still describes
  exposure the client carries (``carries_client_exposure``). Excludes the
  positive hardening bucket and ADscan's own data gaps.
* :attr:`ClientPathTotals.paths_full_domain_compromise` — the ``domain_breaker``
  open-exposure count. The ONLY figure a "you have N routes to full domain
  compromise" headline may use.
* :attr:`ClientPathTotals.paths_proven` / :attr:`~ClientPathTotals.paths_partial`
  — the evidence split, through the ``_PROVEN_STATUSES`` SSOT (never a bare
  ``status == "exploited"`` literal).
* :attr:`ClientPathTotals.paths_closed_by_configuration` — the POSITIVE bucket.
  Counted, never presented as exposure.
* :attr:`ClientPathTotals.paths_not_assessed` — ADscan had no surface to walk
  the avenue. A data gap, never credited to the client as a defence.

**Rules this module exists to enforce** (locked by
``tests/unit/services/test_attack_path_counts.py``):

1. Every human-facing attack-path count and every telemetry path denominator
   comes from here.
2. A raw graph-walk enumeration is NOT a path count. It is combinatorial and
   depth-sensitive (the same graph yielded 123 walks at depth 3 and 458 at depth
   7 over ONE distinct target), it applies no status filter, and it terminates
   only on the domain object — so it over-counts by permutation and under-scopes
   by terminal at once. It is barred from panels, reports and published ratios.
3. Reach wording comes from :func:`compromise_reach_label_short`, never
   hand-written per surface.

Sourcing is cheap by design. The run-stamped ``exposure_kpis`` block in
``technical_report.json`` is preferred (~1 ms to read; it is written by the same
run, from the same derivation); the fall-back recomputes
``compute_report_attack_paths`` + ``compute_exposure_kpis``, which the report
has usually already warmed in-process. LITE-safe: no ``pro/`` imports.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from adscan_core.rich_output import print_exception, print_info_debug
from adscan_internal.services.compromise_class import (
    CompromiseClass,
    compromise_reach_label_short,
)
from adscan_internal.services.exposure_score_service import (
    PATH_AXIS_NON_STATUS_KEYS,
    open_exposure_total,
    split_open_exposure,
)
from adscan_internal.services.path_state import NOT_ASSESSED_STATUSES
from adscan_internal.services.relay_status_constants import CONFIGURATION_CLOSE_STATUS

#: Compromise classes in descending reach order. The FIRST class in this tuple
#: with open exposure is the run's strongest proven-or-identified reach, which is
#: what a one-line digest names. Mirrors the canonical report order in
#: ``exposure_score_service._KPI_COMPROMISE_CLASSES``.
_REACH_ORDER: tuple[CompromiseClass, ...] = (
    CompromiseClass.DOMAIN_BREAKER,
    CompromiseClass.TIER0_FOOTHOLD,
    CompromiseClass.PRIVILEGED_ESCALATOR,
    CompromiseClass.COMPROMISE_ENABLER,
)


@dataclass(frozen=True)
class ClientPathTotals:
    """The cardinalities of one curated client attack-path set.

    Every field is a DIFFERENT question with a DIFFERENT answer, which is
    exactly why they are named rather than passed around as a bare int. The
    invariant that holds across all of them::

        paths_total >= paths_open_exposure >= paths_full_domain_compromise
        paths_open_exposure >= paths_proven + paths_partial

    ``paths_total`` is the inventory (it keeps the positive
    ``closed_by_configuration`` bucket visible); ``paths_open_exposure`` is the
    only one a client-facing risk figure may use.
    """

    paths_total: int = 0
    paths_open_exposure: int = 0
    paths_full_domain_compromise: int = 0
    paths_proven: int = 0
    paths_partial: int = 0
    paths_closed_by_configuration: int = 0
    paths_not_assessed: int = 0
    #: ``compromise_class`` -> open-exposure path count. Drives the reach label
    #: without any surface re-deriving the class ordering.
    open_exposure_by_class: Mapping[str, int] = field(default_factory=dict)

    def __bool__(self) -> bool:
        """Truthy when the run produced any curated path at all."""
        return self.paths_total > 0

    @property
    def strongest_reach_class(self) -> CompromiseClass | None:
        """Return the highest-reach class that still carries open exposure."""
        for cls in _REACH_ORDER:
            if int(self.open_exposure_by_class.get(cls.value, 0) or 0) > 0:
                return cls
        return None

    @property
    def strongest_reach_label(self) -> str:
        """Return the client label for :attr:`strongest_reach_class`.

        Sourced from :func:`compromise_reach_label_short` — the ONE reach
        vocabulary the PDF cards, the web KPI table and the CLI share. Empty
        string when nothing carries open exposure.
        """
        cls = self.strongest_reach_class
        return compromise_reach_label_short(cls) if cls is not None else ""

    def merged_with(self, other: "ClientPathTotals") -> "ClientPathTotals":
        """Return the sum of two domains' totals (for a multi-domain session)."""
        by_class: dict[str, int] = dict(self.open_exposure_by_class)
        for key, value in other.open_exposure_by_class.items():
            by_class[key] = by_class.get(key, 0) + int(value or 0)
        return ClientPathTotals(
            paths_total=self.paths_total + other.paths_total,
            paths_open_exposure=self.paths_open_exposure + other.paths_open_exposure,
            paths_full_domain_compromise=(
                self.paths_full_domain_compromise + other.paths_full_domain_compromise
            ),
            paths_proven=self.paths_proven + other.paths_proven,
            paths_partial=self.paths_partial + other.paths_partial,
            paths_closed_by_configuration=(
                self.paths_closed_by_configuration + other.paths_closed_by_configuration
            ),
            paths_not_assessed=self.paths_not_assessed + other.paths_not_assessed,
            open_exposure_by_class=by_class,
        )

    def telemetry_properties(self) -> dict[str, int]:
        """Return the path denominators for a telemetry event.

        One projection, named. An event that carries these alongside
        ``paths_total_analyzed`` (the convergence denominator, derived from the
        SAME curated set) can never again ship two mutually incomparable path
        denominators under adjacent names.
        """
        return {
            "paths_total": self.paths_total,
            "paths_open_exposure": self.paths_open_exposure,
            "paths_full_domain_compromise": self.paths_full_domain_compromise,
            "paths_proven": self.paths_proven,
            "paths_partial": self.paths_partial,
            "paths_closed_by_configuration": self.paths_closed_by_configuration,
            "paths_not_assessed": self.paths_not_assessed,
        }


def _coerce_int(value: object) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def client_path_totals_from_kpis(
    exposure_kpis: Mapping[str, Any] | None,
) -> ClientPathTotals:
    """Return the named totals from an ``exposure_kpis`` block. Pure.

    Reads the engine-stamped ``path_axis`` VERBATIM — the block written by
    :func:`~adscan_internal.services.exposure_score_service.compute_exposure_kpis`
    — so this never re-derives a status, a class or an exposure filter.

    Args:
        exposure_kpis: The ``domains[<domain>]["exposure_kpis"]`` block, or
            ``None``.

    Returns:
        The populated :class:`ClientPathTotals`, or an all-zero instance when the
        block is missing or malformed.
    """
    if not isinstance(exposure_kpis, Mapping):
        return ClientPathTotals()
    path_axis = exposure_kpis.get("path_axis")
    if not isinstance(path_axis, Mapping):
        return ClientPathTotals()

    total = 0
    open_exposure = 0
    proven = 0
    partial = 0
    closed_by_configuration = 0
    not_assessed = 0
    by_class: dict[str, int] = {}

    for raw_class, bucket in path_axis.items():
        if not isinstance(bucket, Mapping):
            continue
        cls = str(raw_class or "").strip().lower()
        total += _coerce_int(bucket.get("total"))
        bucket_open = open_exposure_total(bucket)
        open_exposure += bucket_open
        by_class[cls] = bucket_open
        evidence = split_open_exposure(bucket)
        proven += evidence.proven
        partial += evidence.partial
        for token, count in bucket.items():
            if token in PATH_AXIS_NON_STATUS_KEYS:
                continue
            status = str(token or "").strip().lower()
            if status == CONFIGURATION_CLOSE_STATUS:
                closed_by_configuration += _coerce_int(count)
            elif status in NOT_ASSESSED_STATUSES:
                not_assessed += _coerce_int(count)

    return ClientPathTotals(
        paths_total=total,
        paths_open_exposure=open_exposure,
        paths_full_domain_compromise=by_class.get(
            CompromiseClass.DOMAIN_BREAKER.value, 0
        ),
        paths_proven=proven,
        paths_partial=partial,
        paths_closed_by_configuration=closed_by_configuration,
        paths_not_assessed=not_assessed,
        open_exposure_by_class=by_class,
    )


def client_path_totals_from_paths(
    paths: Sequence[Mapping[str, Any]],
    *,
    executions: Sequence[Mapping[str, Any]] | None = None,
) -> ClientPathTotals:
    """Return the named totals for an already-computed path set. Pure.

    Args:
        paths: Curated attack-path summaries, as produced by
            :func:`~adscan_internal.services.report_attack_paths.compute_report_attack_paths`.
        executions: Optional path-execution sidecar rows, so a path's status is
            its executed :class:`PathState` rather than the LDAP-derived display
            status — the same reconciliation the report applies.
    """
    from adscan_internal.services.exposure_score_service import compute_exposure_kpis

    kpis = compute_exposure_kpis(
        list(paths),
        # The path axis does not depend on the user denominator; only the
        # user-axis percentages do, and this module reads neither.
        domain_user_count=None,
        executions=list(executions) if executions else None,
    )
    return client_path_totals_from_kpis(kpis)


def _stamped_exposure_kpis(workspace_dir: str, domain: str) -> Mapping[str, Any] | None:
    """Return the run-stamped ``exposure_kpis`` block, or ``None``.

    The block is written by the same run that produced the report, from the same
    derivation, so reading it is both cheaper than recomputing and guaranteed to
    match what the client's document states.
    """
    try:
        from adscan_internal.workspaces import read_json_file

        report_path = os.path.join(workspace_dir, "technical_report.json")
        if not os.path.exists(report_path):
            return None
        report = read_json_file(report_path)
        domains = report.get("domains") if isinstance(report, dict) else None
        entry = domains.get(domain) if isinstance(domains, dict) else None
        kpis = entry.get("exposure_kpis") if isinstance(entry, dict) else None
        return kpis if isinstance(kpis, Mapping) else None
    except Exception:  # noqa: BLE001 - a missing or unreadable artifact just means "recompute"
        return None


def client_path_totals(workspace_dir: str, domain: str) -> ClientPathTotals:
    """Return the named totals for one domain in one workspace.

    Prefers the run-stamped ``exposure_kpis`` block; recomputes the canonical
    report projection when it is absent (an older artifact, or a run whose
    report has not been written yet). Best-effort by construction: any failure
    yields an all-zero instance rather than raising, because every consumer is a
    panel, a summary or a telemetry event that must never break a scan.

    Args:
        workspace_dir: Workspace root. For a LIVE scan this is the execution
            (``.run_*``) workspace — the directory the scan is writing into.
        domain: The domain whose paths are counted.
    """
    if not workspace_dir or not str(domain or "").strip():
        return ClientPathTotals()
    domain_name = str(domain).strip()

    stamped = _stamped_exposure_kpis(workspace_dir, domain_name)
    if stamped is not None:
        totals = client_path_totals_from_kpis(stamped)
        if totals.paths_total > 0:
            return totals

    try:
        from adscan_internal.services.post_exploitation.path_promotion import (
            load_executions,
        )
        from adscan_internal.services.report_attack_paths import (
            compute_report_attack_paths,
        )

        paths = compute_report_attack_paths(workspace_dir, domain_name)
        if not paths:
            return ClientPathTotals()
        executions = None
        try:
            from types import SimpleNamespace

            executions = load_executions(
                SimpleNamespace(
                    current_workspace_dir=str(workspace_dir), domains_dir="domains"
                ),
                domain_name,
            )
        except Exception:  # noqa: BLE001 - no sidecar just means "display status"
            executions = None
        return client_path_totals_from_paths(paths, executions=executions or None)
    except Exception as exc:  # noqa: BLE001 - counts never break a scan
        print_exception(exception=exc)
        print_info_debug(f"[path-counts] totals unavailable for {domain_name}: {exc}")
        return ClientPathTotals()


def resolve_scan_workspace_dir(shell: Any) -> str:
    """Return the workspace root whose artifacts belong to THIS scan.

    A live scan writes into its execution (``.run_*``) workspace, which is what
    ``current_workspace_dir`` points at while the scan runs — so this resolves
    the same directory the report generator reads.
    """
    getter = getattr(shell, "_get_workspace_cwd", None)
    if callable(getter):
        try:
            resolved = getter()
        except Exception:  # noqa: BLE001
            resolved = None
        if isinstance(resolved, str) and resolved:
            return resolved
    workspace_dir = getattr(shell, "current_workspace_dir", None)
    return workspace_dir if isinstance(workspace_dir, str) and workspace_dir else ""


def client_path_totals_for_shell(shell: Any, domain: str) -> ClientPathTotals:
    """Return the named totals for one domain, resolved from a live shell."""
    return client_path_totals(resolve_scan_workspace_dir(shell), domain)


def client_path_totals_for_session(
    shell: Any, *, domains: Sequence[str] | None = None
) -> ClientPathTotals:
    """Return the named totals summed across a session's domains.

    Args:
        shell: The active shell (workspace context only).
        domains: Restrict to these domains; ``None`` counts every domain the
            session loaded.
    """
    workspace_dir = resolve_scan_workspace_dir(shell)
    if not workspace_dir:
        return ClientPathTotals()

    if domains is None:
        loaded = getattr(shell, "domains_data", None)
        names = list(loaded.keys()) if isinstance(loaded, dict) else []
    else:
        names = list(domains)

    totals = ClientPathTotals()
    for name in names:
        domain_name = str(name or "").strip()
        if not domain_name:
            continue
        totals = totals.merged_with(client_path_totals(workspace_dir, domain_name))
    return totals


__all__ = [
    "ClientPathTotals",
    "client_path_totals",
    "client_path_totals_for_session",
    "client_path_totals_for_shell",
    "client_path_totals_from_kpis",
    "client_path_totals_from_paths",
    "resolve_scan_workspace_dir",
]
