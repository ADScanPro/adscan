"""Guest-access coverage: the client-facing statement for unchecked hosts, derived once.

Guest SMB access is probed host by host with the engagement's guest name. When
the name's absence from the directory could not be confirmed (no answer from
the domain controller's Kerberos service), a refused guest sign-in could, in
principle, land on an account that carries the name, so the lockout guard stops
guest probing after a few refusals (rule 6 of
:mod:`adscan_core.auth_attempt_guard`). The hosts after that point were never
asked. Under the Exposure-Validation doctrine that is a **data gap**: the
deliverable states how many hosts were not checked and why, and an unchecked
host never reads as one that refused guest access.

This module is the SSOT for both halves, mirroring
:mod:`adscan_core.reporting.host_enrichment_coverage`:

* :func:`build_guest_access_coverage` turns the count into the block persisted
  under ``domains[<domain>]["guest_access_coverage"]`` by
  :func:`adscan_core.reporting.technical_report.record_guest_access_coverage`;
* :func:`merge_guest_access_coverage` turns the persisted blocks into the
  render-ready shape the PDF report, the LITE report and the web platform read.

Pure logic: no IO, no console, no network.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

#: Per-domain key the block lives under in ``technical_report.json`` and in
#: ``domains_data``.
GUEST_ACCESS_COVERAGE_KEY = "guest_access_coverage"

#: Why guest probing stopped: the guest name's absence was not confirmed.
REASON_ABSENCE_UNCONFIRMED = "absence_unconfirmed"


def _statement(hosts: int) -> str:
    noun = "host" if hosts == 1 else "hosts"
    return (
        f"Guest access not checked on {hosts} {noun}: the guest name's absence from "
        "the directory could not be confirmed, so guest probing stopped after a few "
        "refusals to keep any account that might carry the name from being locked."
    )


def build_guest_access_coverage(
    *, hosts_not_checked: int, reason: str = REASON_ABSENCE_UNCONFIRMED
) -> dict[str, Any]:
    """The persisted block for one domain, or ``{}`` when every host was checked."""
    hosts = int(hosts_not_checked or 0)
    if hosts <= 0:
        return {}
    return {
        "complete": False,
        "reason": str(reason or REASON_ABSENCE_UNCONFIRMED),
        "hosts_not_checked": hosts,
        "statement": _statement(hosts),
    }


def merge_guest_access_coverage(domain_entries: Iterable[Any]) -> dict[str, Any]:
    """Render shape across domains: ``present``, ``hosts_not_checked``, ``statement``."""
    total = 0
    for entry in domain_entries:
        block = entry.get(GUEST_ACCESS_COVERAGE_KEY) if isinstance(entry, Mapping) else None
        if isinstance(block, Mapping) and block.get("complete") is False:
            try:
                total += int(block.get("hosts_not_checked") or 0)
            except (TypeError, ValueError):
                continue
    if total <= 0:
        return {"present": False, "hosts_not_checked": 0, "statement": ""}
    return {"present": True, "hosts_not_checked": total, "statement": _statement(total)}


__all__ = [
    "GUEST_ACCESS_COVERAGE_KEY",
    "REASON_ABSENCE_UNCONFIRMED",
    "build_guest_access_coverage",
    "merge_guest_access_coverage",
]
