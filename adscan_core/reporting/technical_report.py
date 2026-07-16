"""LITE-safe write primitives for ``technical_report.json``.

This module is the **single source of truth** for the write side of the
technical report: the on-disk JSON shape, the path resolution, and the three
recorders (:func:`record_technical_finding`, :func:`record_technical_event`,
:func:`record_control_evidence`).

It lives under ``adscan_core`` on purpose. The PRO report service
(``adscan_internal/pro/services/report_service.py`` and its shim
``adscan_internal/services/report_service.py``) is physically stripped from
the LITE image — it is listed in ``scripts/sync_public_repo.exclude`` and the
build forbidden-list. ``adscan_core`` ships whole in LITE
(``Dockerfile.runtime`` ``COPY adscan_core``), so relocating these primitives
here is what makes ``technical_report.json`` actually get populated in LITE
instead of silently no-op'ing through an ``ImportError``.

Hard constraints (the reason the recorder used to no-op in LITE):
- This module must NOT import anything from ``adscan_internal.pro``,
  ``adscan_internal.reporting``, ``docx``, ``adscan_internal.template`` or the
  full ``VULN_CATALOG``. Any of those module-level imports drags the PRO
  reporting tree into the import graph and breaks under the LITE strip.
- The finding catalog (title/severity/category lookup) is built from the
  LITE-safe :data:`~adscan_core.reporting.vuln_catalog_meta.VULN_CATALOG_META`
  slice. That slice is drift-locked against the PRO ``VULN_CATALOG`` (title +
  severity match byte-for-byte; see ``tests/unit/test_vuln_catalog_meta_drift``)
  but carries no ``category`` — the recorder defaults to ``"General"`` when a
  category is absent, which the Navigator reader never consumes.

The emitted on-disk shape is::

    {
      "schema_version": "2.0",
      "generated_at": "<iso>",
      "domains": {
        "<fqdn>": {
          "findings": [...],
          "control_evidence": [...],
          "events": [...],
          "attack_paths": [...]
        }
      }
    }

The ``domains`` wrapper and the per-finding ``key`` field are part of the
contract that the MITRE Navigator reader depends on — do not change them.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional, Protocol

from adscan_core import telemetry
from adscan_core.reporting.vuln_catalog_meta import VULN_CATALOG_META
from adscan_core.rich_output import (
    print_error,
    print_exception,
    print_warning,
)

TECHNICAL_REPORT_SCHEMA_VERSION = "2.0"
TECHNICAL_REPORT_FILENAME = "technical_report.json"


class ReportShell(Protocol):
    """Protocol for report management methods on the legacy shell."""

    domains: list[str]
    report_file: str
    report: dict[str, Any]
    technical_report_file: str
    technical_report: dict[str, Any]
    domains_data: dict[str, dict[str, Any]]


# --- Finding catalog injection seam -----------------------------------------
#
# WHY this seam exists: the LITE path builds the title/severity/category lookup
# from ``VULN_CATALOG_META`` (LITE-safe, no ``category``), but the PRO path
# historically derived a richer catalog from the full ``VULN_CATALOG`` —
# including a real ``category`` per finding. ``VULN_CATALOG_META`` is
# drift-locked to ``VULN_CATALOG`` on title/severity, so the only PRO-unique
# field is ``category``. To keep PRO byte-identical without importing the PRO
# catalog into this LITE-safe module, the PRO report service installs its
# richer catalog provider here at import time via
# :func:`set_finding_catalog_provider`. In LITE (PRO stripped) the provider is
# never set and the default ``VULN_CATALOG_META`` builder is used.
_FINDING_CATALOG_PROVIDER: Optional[Callable[[], dict[str, dict[str, Any]]]] = None


def _build_technical_finding_catalog_from_meta() -> dict[str, dict[str, Any]]:
    """Build the LITE-safe finding catalog from the meta slice.

    ``VULN_CATALOG_META`` carries ``title`` + ``severity`` for every key but no
    ``category``; the recorder defaults ``category`` to ``"General"`` (the
    Navigator reader never consumes it). The LITE slice has no rich
    ``knowledge`` sub-object — the PRO provider supplies that when installed.
    """
    catalog: dict[str, dict[str, Any]] = {}
    for key, entry in VULN_CATALOG_META.items():
        catalog[key] = {
            "title": str(entry.get("title") or key.replace("_", " ").title()),
            "severity": str(entry.get("severity") or "medium"),
            "category": str(entry.get("category") or "General"),
        }
    return catalog


def set_finding_catalog_provider(
    provider: Optional[Callable[[], dict[str, dict[str, Any]]]],
) -> None:
    """Install a richer finding-catalog provider (PRO-only injection seam).

    The PRO report service calls this at import time to inject a
    ``VULN_CATALOG``-derived catalog that also carries ``category``. LITE never
    calls it and falls back to the ``VULN_CATALOG_META`` builder. Pass ``None``
    to reset to the LITE default (used by tests).
    """
    global _FINDING_CATALOG_PROVIDER
    _FINDING_CATALOG_PROVIDER = provider


def _finding_catalog() -> dict[str, dict[str, Any]]:
    """Return the active finding catalog (PRO-injected if present, else meta)."""
    if _FINDING_CATALOG_PROVIDER is not None:
        try:
            return _FINDING_CATALOG_PROVIDER()
        except Exception as exc:  # noqa: BLE001 - fall back to LITE-safe default
            telemetry.capture_exception(exc)
    return _build_technical_finding_catalog_from_meta()


def _utc_now_iso() -> str:
    """Return current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _resolve_report_path(report_file: str) -> Path:
    """Resolve a report path relative to the current working directory."""
    path = Path(report_file)
    if path.is_absolute():
        return path
    return Path.cwd() / path


def _get_technical_report_path(shell: ReportShell) -> Path:
    """Return the path to the technical report JSON file."""
    technical_name = getattr(shell, "technical_report_file", TECHNICAL_REPORT_FILENAME)
    technical_path = Path(str(technical_name))
    if technical_path.is_absolute():
        return technical_path

    base_dir: Path | None = None
    report_file = getattr(shell, "report_file", None)
    if isinstance(report_file, str) and report_file:
        base_dir = _resolve_report_path(report_file).parent
    else:
        workspace_dir = getattr(shell, "current_workspace_dir", None)
        if isinstance(workspace_dir, str) and workspace_dir:
            base_dir = Path(workspace_dir)

    if base_dir is None:
        base_dir = Path.cwd()

    return base_dir / technical_path


def _init_technical_report() -> dict[str, Any]:
    """Return a new technical report structure."""
    return {
        "schema_version": TECHNICAL_REPORT_SCHEMA_VERSION,
        "generated_at": _utc_now_iso(),
        "domains": {},
    }


def initialize_technical_report(shell: ReportShell) -> None:
    """Initialize (or reset) `technical_report.json` for the current workspace.

    The technical report is the source of truth for:
    - technical findings (vulnerabilities/misconfigurations)
    - technical events
    - attack paths

    Args:
        shell: The current CLI shell (workspace context).
    """
    report = _init_technical_report()
    domains = getattr(shell, "domains", [])
    if isinstance(domains, list):
        for domain in domains:
            if isinstance(domain, str) and domain:
                _ensure_technical_domain(report, domain)
    _save_technical_report(shell, report)


def _load_technical_report(shell: ReportShell) -> dict[str, Any]:
    """Load the technical report JSON or initialize a new one."""
    report_path = _get_technical_report_path(shell)
    if report_path.exists():
        try:
            with report_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning("Failed to load technical report; creating a new one.")
            print_exception(show_locals=False, exception=exc)
    return _init_technical_report()


def _save_technical_report(shell: ReportShell, report: dict[str, Any]) -> None:
    """Persist the technical report JSON to disk atomically.

    The write goes to a sibling temp file first, then is promoted with
    ``os.replace`` (a POSIX-atomic same-filesystem rename). A concurrent reader
    therefore always sees a COMPLETE old or new ``technical_report.json`` and
    NEVER a half-written file. This matters because the report is regenerated
    during the Reporting phase while the web live-ingestion tick reads it: a
    non-atomic write let the reader observe a partial file, raising
    ``json.JSONDecodeError`` and (downstream) driving false finding remediation.
    Mirrors the ``.tmp.docx`` + replace pattern the PRO report service already
    uses for the DOCX.
    """
    report_path = _get_technical_report_path(shell)
    try:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = report_path.with_name(report_path.name + ".tmp")
        try:
            with tmp_path.open("w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, report_path)
        except Exception:
            try:
                tmp_path.unlink()
            except OSError:
                pass
            raise
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("Error saving technical report.")
        print_exception(show_locals=False, exception=exc)


def _ensure_technical_domain(report: dict[str, Any], domain: str) -> dict[str, Any]:
    """Ensure a domain entry exists in the technical report."""
    domains = report.setdefault("domains", {})
    domain_entry = domains.get(domain)
    if not isinstance(domain_entry, dict):
        domain_entry = {}
    domain_entry.setdefault("findings", [])
    domain_entry.setdefault("control_evidence", [])
    domain_entry.setdefault("events", [])
    domain_entry.setdefault("attack_paths", [])
    domains[domain] = domain_entry
    return domain_entry


def _append_unique(target: list[dict[str, Any]], entry: dict[str, Any]) -> None:
    """Append entry to list if not already present."""
    if entry not in target:
        target.append(entry)


def _summarize_value(value: Any) -> dict[str, Any]:
    """Build a safe summary for a value to store in technical report."""
    if isinstance(value, bool):
        return {"status": value}
    if isinstance(value, list):
        sample = value[:10]
        return {"count": len(value), "sample": sample}
    if isinstance(value, dict):
        summary: dict[str, Any] = {}
        for key, entry in value.items():
            if entry in (None, "NS", False, [], {}):
                continue
            summary[key] = entry
        return summary or {"status": "present"}
    if value is None:
        return {}
    return {"value": value}


def _is_positive_value(value: Any) -> bool:
    """Return True if a value represents a positive finding."""
    if value is True:
        return True
    if isinstance(value, list):
        return len(value) > 0
    if isinstance(value, dict):
        return any(_is_positive_value(v) for v in value.values())
    return False


def record_technical_finding(
    shell: ReportShell,
    domain: str,
    *,
    key: str,
    status: str = "confirmed",
    value: Any | None = None,
    details: dict[str, Any] | None = None,
    evidence: list[dict[str, Any]] | None = None,
    from_attack_graph: bool | None = None,
) -> None:
    """Record or update a technical finding for a domain.

    Args:
        shell: Shell object with report paths.
        domain: Domain name.
        key: Finding key (matches legacy vulnerability keys).
        status: Status label (e.g., confirmed).
        value: Raw value to summarize for details.
        details: Additional structured details to merge.
        evidence: Optional evidence entries.
        from_attack_graph: Whether the finding originated from the attack graph.
    """
    report = _load_technical_report(shell)
    domain_entry = _ensure_technical_domain(report, domain)
    findings = domain_entry["findings"]

    finding = next((item for item in findings if item.get("key") == key), None)
    now = _utc_now_iso()
    catalog = _finding_catalog().get(key, {})
    summary = _summarize_value(value) if value is not None else {}

    # Rich knowledge sub-object (description, impact, remediation, references,
    # summary, recommended, applicable_tabs) supplied by the PRO catalog
    # provider. Self-describing so the web (Phase 2) and report (Phase 3)
    # consume the full per-finding knowledge directly from the artifact. LITE
    # (meta-only catalog) yields no ``knowledge`` key — omitted cleanly.
    knowledge = catalog.get("knowledge") if isinstance(catalog, dict) else None

    if finding is None:
        resolved_from_attack_graph = (
            bool(from_attack_graph) if from_attack_graph is not None else False
        )
        finding = {
            "id": uuid.uuid4().hex,
            "key": key,
            "title": catalog.get("title", key.replace("_", " ").title()),
            "severity": catalog.get("severity", "medium"),
            "category": catalog.get("category", "General"),
            "status": status,
            "from_attack_graph": resolved_from_attack_graph,
            "details": {},
            "evidence": [],
            "discovered_at": now,
            "first_seen": now,
            "last_seen": now,
        }
        if isinstance(knowledge, dict) and knowledge:
            finding["knowledge"] = knowledge
        findings.append(finding)
    else:
        finding["status"] = status
        finding["last_seen"] = now
        if "discovered_at" not in finding:
            finding["discovered_at"] = finding.get("first_seen") or now
        if from_attack_graph is not None:
            finding["from_attack_graph"] = bool(from_attack_graph)
        elif "from_attack_graph" not in finding:
            finding["from_attack_graph"] = False
        # Refresh knowledge on existing findings so a catalog change reaches
        # already-recorded findings on the next scan/replay.
        if isinstance(knowledge, dict) and knowledge:
            finding["knowledge"] = knowledge

    if summary:
        finding["details"].update(summary)
    if details:
        finding["details"].update(details)
    if evidence:
        for entry in evidence:
            _append_unique(finding["evidence"], entry)

    _save_technical_report(shell, report)


def record_technical_event(
    shell: ReportShell,
    domain: str,
    *,
    event_type: str,
    message: str,
    details: dict[str, Any] | None = None,
) -> None:
    """Record a technical event in the report."""
    report = _load_technical_report(shell)
    domain_entry = _ensure_technical_domain(report, domain)
    event = {
        "id": uuid.uuid4().hex,
        "type": event_type,
        "message": message,
        "details": details or {},
        "timestamp": _utc_now_iso(),
    }
    domain_entry["events"].append(event)
    _save_technical_report(shell, report)


def record_control_evidence(
    shell: ReportShell,
    domain: str,
    *,
    key: str,
    title: str | None = None,
    category: str = "Control Evidence",
    status: str = "observed",
    details: dict[str, Any] | None = None,
    evidence: list[dict[str, Any]] | None = None,
) -> None:
    """Record or update positive or neutral control evidence for one domain.

    This store is intentionally separate from technical findings so controls
    that represent favorable posture or heuristic operational evidence do not
    appear as negative findings in reports.
    """
    report = _load_technical_report(shell)
    domain_entry = _ensure_technical_domain(report, domain)
    control_evidence = domain_entry["control_evidence"]

    entry = next((item for item in control_evidence if item.get("key") == key), None)
    now = _utc_now_iso()
    if entry is None:
        entry = {
            "id": uuid.uuid4().hex,
            "key": key,
            "title": title or key.replace("_", " ").title(),
            "category": category,
            "status": status,
            "details": {},
            "evidence": [],
            "discovered_at": now,
            "first_seen": now,
            "last_seen": now,
        }
        control_evidence.append(entry)
    else:
        entry["status"] = status
        entry["last_seen"] = now
        if title:
            entry["title"] = title
        if category:
            entry["category"] = category
        if "discovered_at" not in entry:
            entry["discovered_at"] = entry.get("first_seen") or now

    if details:
        entry["details"].update(details)
    if evidence:
        for item in evidence:
            _append_unique(entry["evidence"], item)

    _save_technical_report(shell, report)


def record_collection_coverage(
    shell: ReportShell,
    domain: str,
    *,
    coverage: dict[str, Any],
) -> None:
    """Persist the collection-coverage statement for *domain*.

    Write-side single source of truth for the audit-defensible coverage statement
    when the operator stops the per-host SMB enrichment sweep early (CLI Ctrl+C or
    the platform button). The identity graph is always complete; this records the
    host-enrichment X-of-Y so the PDF report AND ``adscan_web`` render the SAME
    transparent statement (the scan continued with partial host data — the rest
    were queued, not silently dropped).

    ``coverage`` carries ``identity_graph_complete`` (bool), ``hosts_swept``,
    ``hosts_total``, ``hosts_remaining``, ``ordering``, ``stopped_by`` and a
    rendered ``statement``. Mirrors :func:`record_exposure_score`: stamps the
    value onto ``domains[<domain>]["collection_coverage"]`` so the JSON export
    carries it and downstream consumers read it instead of recomputing. Best-
    effort: ignores a missing/invalid payload and never raises into the caller.
    """
    if not domain or not isinstance(coverage, dict) or "statement" not in coverage:
        return
    report = _load_technical_report(shell)
    domain_entry = _ensure_technical_domain(report, domain)
    domain_entry["collection_coverage"] = coverage
    _save_technical_report(shell, report)


def record_exposure_score(
    shell: ReportShell,
    domain: str,
    *,
    exposure: dict[str, Any],
) -> None:
    """Persist the AD Exposure Score for *domain* into ``technical_report.json``.

    Write-side single source of truth for the headline metric so the JSON export
    carries it (spec §8c) and downstream consumers — notably ``adscan_web``,
    which ingests ``domains[<domain>]["exposure_score"]`` — read the engine value
    instead of recomputing it. ``exposure`` is ``ExposureScore.to_dict()``
    (``overall_pct``, ``proven_pct``, ``by_class``, ``reachable_tier0``,
    ``total_tier0``, ``top_contributors``, ``explanation``, …). Best-effort:
    ignores a missing/invalid payload and never raises into the caller.
    """
    if not domain or not isinstance(exposure, dict) or "overall_pct" not in exposure:
        return
    report = _load_technical_report(shell)
    domain_entry = _ensure_technical_domain(report, domain)
    domain_entry["exposure_score"] = exposure
    _save_technical_report(shell, report)


def record_attack_fanout_rollup(
    shell: ReportShell,
    *,
    rollup: list[dict[str, Any]],
) -> None:
    """Persist the outbound fan-out ("privilege blast radius") rollup.

    Write-side single source of truth for the collapsed capability nodes so the
    JSON export carries them and downstream consumers — the PDF report and
    ``adscan_web`` (Slice 3) — read the engine value instead of recomputing it.
    Unlike the exposure blocks this is a WORKSPACE-scoped, non-domain TOP-LEVEL
    key (``report["attack_fanout_rollup"]``): a flat array of already-serialized
    :func:`adscan_internal.services.attack_fanout_rollup.fanout_step_to_dict`
    dicts, in collapsed (most-severe-first) order. ``adscan_core`` never imports
    the engine, so the caller serializes the steps and hands the plain list here.
    Best-effort: ignores a non-list payload and never raises into the caller.
    An empty list is still written so a re-render clears a stale rollup.

    Args:
        shell: Shell object with report paths.
        rollup: The serialized collapsed fan-out steps (may be empty).
    """
    if not isinstance(rollup, list):
        return
    report = _load_technical_report(shell)
    report["attack_fanout_rollup"] = rollup
    _save_technical_report(shell, report)


def record_exposure_kpis(
    shell: ReportShell,
    domain: str,
    *,
    kpis: dict[str, Any],
) -> None:
    """Persist the exposure KPI block for *domain* into ``technical_report.json``.

    Write-side single source of truth for the path-axis + user-axis blast-radius
    KPIs (``exposure_score_service.compute_exposure_kpis``). Mirrors
    :func:`record_exposure_score`: stamps the engine value so the JSON export
    carries it and downstream consumers - the PDF report and ``adscan_web`` -
    read ``domains[<domain>]["exposure_kpis"]`` instead of recomputing it.
    Best-effort: ignores a missing/invalid payload and never raises.
    """
    if not domain or not isinstance(kpis, dict) or "path_axis" not in kpis:
        return
    report = _load_technical_report(shell)
    domain_entry = _ensure_technical_domain(report, domain)
    domain_entry["exposure_kpis"] = kpis
    _save_technical_report(shell, report)


def record_compliance(
    shell: ReportShell,
    domain: str,
    *,
    compliance: dict[str, Any],
) -> None:
    """Persist the per-framework compliance coverage for *domain*.

    Write-side single source of truth for the compliance block
    (``compliance_artifact.build_compliance_artifact``). Mirrors
    :func:`record_exposure_score`: stamps the engine value so the JSON export
    carries it and ``adscan_web`` ingests ``domains[<domain>]["compliance"]``
    verbatim instead of recomputing coverage from a forked catalog. The block
    carries ``schema_version`` and a ``frameworks`` map keyed by the canonical
    framework keys the engagement selected. Best-effort: ignores a
    missing/invalid payload and never raises.
    """
    if not domain or not isinstance(compliance, dict) or "frameworks" not in compliance:
        return
    report = _load_technical_report(shell)
    domain_entry = _ensure_technical_domain(report, domain)
    domain_entry["compliance"] = compliance
    _save_technical_report(shell, report)


# --- Read-side findings bucket (LITE-safe) ----------------------------------
#
# The write side above records findings into ``technical_report.json``; this is
# the reader-side helper the end-of-scan recap consumes to bucket those findings
# by severity. It lives here (not in ``adscan_internal``) for the same reason
# the write side does: ``adscan_core`` ships whole in LITE, so the recap can read
# real finding counts instead of falling back to placeholder dashes.

_SEVERITY_RANK: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass(frozen=True)
class FindingRow:
    """A single finding row for the recap top-list."""

    title: str
    severity: str  # critical | high | medium | low (lowercased)


@dataclass(frozen=True)
class FindingsSummary:
    """Severity counts + a small top-list read from ``technical_report.json``.

    ``critical``/``high``/``medium``/``low`` count only findings whose severity
    is one of those four canonical levels (there is no ``info`` severity on the
    write side). ``top`` is up to ``top_n`` findings ordered
    critical > high > medium > low, then by title.
    """

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    top: tuple[FindingRow, ...] = field(default_factory=tuple)

    @property
    def total(self) -> int:
        """Return the total count across the four canonical severities."""
        return self.critical + self.high + self.medium + self.low


def summarize_findings(
    shell: ReportShell,
    *,
    domain: str | None = None,
    top_n: int = 3,
) -> FindingsSummary:
    """Read ``technical_report.json`` and bucket findings by severity.

    Reuses :func:`_load_technical_report`. When ``domain`` is ``None`` the counts
    union every domain in the report. Severities are lowercased; unknown
    severities are ignored for the counts but still eligible for the ``top`` list
    at the lowest rank. Best-effort: returns an empty :class:`FindingsSummary` on
    any read error (never raises).

    Args:
        shell: Shell object carrying the technical-report path.
        domain: Restrict to a single domain, or ``None`` to union all.
        top_n: Maximum number of findings in the ``top`` list.

    Returns:
        A :class:`FindingsSummary` with per-severity counts and a top-list.
    """
    try:
        report = _load_technical_report(shell)
        domains = report.get("domains")
        if not isinstance(domains, dict):
            return FindingsSummary()

        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        rows: list[FindingRow] = []
        for dname, dentry in domains.items():
            if domain is not None and dname != domain:
                continue
            if not isinstance(dentry, dict):
                continue
            findings = dentry.get("findings")
            if not isinstance(findings, list):
                continue
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                severity = str(finding.get("severity") or "").strip().lower()
                title = str(finding.get("title") or "").strip()
                if severity in counts:
                    counts[severity] += 1
                if title:
                    rows.append(FindingRow(title=title, severity=severity))

        rows.sort(key=lambda row: (_SEVERITY_RANK.get(row.severity, 99), row.title))
        top = tuple(rows[: max(0, int(top_n))])
        return FindingsSummary(
            critical=counts["critical"],
            high=counts["high"],
            medium=counts["medium"],
            low=counts["low"],
            top=top,
        )
    except Exception as exc:  # noqa: BLE001 - best-effort reader, never breaks exit
        telemetry.capture_exception(exc)
        return FindingsSummary()
