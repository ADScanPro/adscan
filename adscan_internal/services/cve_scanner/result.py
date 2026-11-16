"""Result types for the native CVE scanner.

Severity here is a CVSS-driven, scanner-local enum; it is intentionally
distinct from :class:`adscan_internal.services.severity.Severity`, which
encodes graph-edge severity (a different problem space).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

_PUBLIC_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")


def public_cve_reference(cve_id: str | None) -> str:
    """The identifier an operator surface may print beside a CVE finding.

    The rating ADscan shows is its own severity (``CLAUDE.md`` § "No CVSS on a
    client surface"). A CVSS number is never printed: the catalog carries one
    for every probe, including probes that are not CVEs at all
    (``ADSCAN-PRINTERBUG-SURFACE``), and those numbers are not verified against
    the published scores. What IS an external anchor anyone can check is the
    public CVE identifier, so that is what surfaces: ``CVE-2021-34527`` for a
    real CVE, an empty string for an ADscan-defined check.
    """
    value = str(cve_id or "").strip().upper()
    return value if _PUBLIC_CVE_ID.match(value) else ""


class Severity(str, Enum):
    """CVSS-bucketed severity used by the CVE dashboard and report."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_cvss(cls, score: float | None) -> Severity:
        """Bucket a CVSS v3 base score into a :class:`Severity`."""

        if score is None:
            return cls.INFO
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0:
            return cls.LOW
        return cls.INFO


class CVEStatus(str, Enum):
    """Outcome of one CVE check on one host."""

    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"
    SKIPPED = "skipped"
    RUNNING = "running"


@dataclass(frozen=True)
class Evidence:
    """Structured evidence captured by a CVE check.

    ``payload`` is a free-form dict serialised verbatim into the
    workspace evidence file. It must not contain cleartext secrets;
    sensitive values must be masked at the call site via
    :func:`adscan_internal.rich_output.mark_sensitive` before emission.
    """

    summary: str
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CVEResult:
    """One CVE check outcome, per host."""

    cve_id: str
    aka: str
    host: str
    status: CVEStatus
    severity: Severity
    cvss_v3: float | None
    cvss_vector: str | None
    technique: str | None = None
    error: str | None = None
    evidence: Evidence | None = None
    duration_seconds: float = 0.0
    finished_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def is_vulnerable(self) -> bool:
        """Return True iff the check confirmed the host is vulnerable."""

        return self.status is CVEStatus.VULNERABLE


@dataclass(frozen=True)
class CVEScanReport:
    """Aggregate report for one CVE scan run."""

    scan_id: str
    started_at: datetime
    finished_at: datetime
    targets: tuple[str, ...]
    cve_ids: tuple[str, ...]
    results: tuple[CVEResult, ...]

    @property
    def vulnerable(self) -> tuple[CVEResult, ...]:
        """Return the subset of results with status VULNERABLE."""

        return tuple(r for r in self.results if r.is_vulnerable)

    def severity_counts(self) -> dict[Severity, int]:
        """Tally vulnerable findings by severity bucket."""

        counts: dict[Severity, int] = {s: 0 for s in Severity}
        for result in self.results:
            if result.is_vulnerable:
                counts[result.severity] += 1
        return counts


__all__ = [
    "CVEResult",
    "CVEScanReport",
    "CVEStatus",
    "Evidence",
    "Severity",
]
