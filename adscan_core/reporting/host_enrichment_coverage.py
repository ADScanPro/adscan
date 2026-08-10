"""Host-enrichment coverage: the client-facing statement, derived once.

The LDAP identity graph — every user, group, computer, ACL, ADCS template and
trust — is mapped in full on every scan. Attack paths, ESC findings and reach
compute over that graph, and it is always 100% coverage.

The SMB host-enrichment sweep is the separate, deep second pass: logged-on
sessions, local-administrator membership and share exposure, host by host. On a
large directory that sweep can run for hours, so the operator (or, on a scan
without an operator, a bounded default) may enrich only the highest-value hosts
and leave the rest for a later run.

When that happens the deliverable must say so. Under the Exposure-Validation
doctrine a bounded sweep is a **data gap**, in the same family as ``unsupported``
and the resource-bounded attack-path memory gate: ADscan states where the
enrichment stopped and what that leaves unevaluated, and never lets a capped run
read as an exhaustive one. A report whose "no local admins / no risky shares"
sections are empty because a host was never swept is indistinguishable, to a
reader, from one where the host was swept and nothing was found — and only the
second reading is honest.

This module is the SSOT for both halves, mirroring
:mod:`adscan_core.reporting.cracking_coverage` and
:mod:`adscan_core.reporting.attack_path_memory_gate`:

* :func:`build_host_enrichment_coverage` turns the observed sweep coverage into
  the block persisted by
  :func:`adscan_core.reporting.technical_report.record_host_enrichment_coverage`;
  and
* :func:`host_enrichment_coverage_view` turns that persisted block back into the
  small render-ready shape the PDF report, the LITE report and the paid web
  platform all consume, so the three surfaces cannot word the same gap
  differently.

Pure logic: no IO, no console, no network. Safe to import from ``adscan_core``,
the LITE runtime, the PRO report renderer and the web backend alike.
"""

from __future__ import annotations

from typing import Any, Mapping

#: Per-domain key this block is stamped under, in ``technical_report.json`` and
#: in the renderer's ``report_data``. One name, so the writer, the PDF, the LITE
#: report and the web platform cannot drift apart on where the record lives.
HOST_ENRICHMENT_COVERAGE_KEY = "host_enrichment_coverage"

#: How the sweep was bounded. ``cap`` — the highest-value hosts were enriched and
#: the rest bounded to hold scan time (a proactive scale-gate decision, or a host
#: cap from the scan config / env). ``skip`` — SMB enrichment was declined and the
#: findings rest on the identity graph. ``early_stop`` — the operator halted a
#: running sweep. All three read as the same class of coverage gap to a client;
#: the reason only shapes the sentence.
REASON_CAP = "cap"
REASON_SKIP = "skip"
REASON_EARLY_STOP = "early_stop"

_COMPLETE_STATEMENT = (
    "SMB host enrichment covered every reachable host: logged-on sessions, "
    "local-administrator membership and share exposure were evaluated across "
    "the full estate."
)


def _cap_statement(hosts_swept: int, hosts_total: int) -> str:
    """Render the client-facing sentence for a capped sweep.

    States what was and was not enriched. It never gives the internal reason (a
    time budget is an operator concern, and reads as an apology in a deliverable),
    never a verdict about the client's directory, and never lets a bounded sweep
    read as an exhaustive one. The identity graph line is always affirmed first
    so the reach story is not undersold.
    """
    return (
        "The identity graph is complete: every user, group, computer, ACL and "
        "trust was mapped, and attack paths and reach are computed over the full "
        "directory. SMB host enrichment (logged-on sessions, local-administrator "
        f"membership and share exposure) covered {hosts_swept:,} of "
        f"{hosts_total:,} reachable hosts, highest-value first. Session, "
        "local-admin and share exposure on the remaining hosts was not "
        "evaluated. Re-running host enrichment across the full estate will "
        "settle it."
    )


def _skip_statement(hosts_total: int) -> str:
    """Render the client-facing sentence for a skipped sweep."""
    return (
        "The identity graph is complete: every user, group, computer, ACL and "
        "trust was mapped, and attack paths and reach are computed over the full "
        "directory. SMB host enrichment (logged-on sessions, local-administrator "
        f"membership and share exposure) was not run across the "
        f"{hosts_total:,} reachable hosts in this assessment, so those exposures "
        "were not evaluated. Running host enrichment will add them."
    )


def _early_stop_statement(hosts_swept: int, hosts_total: int) -> str:
    """Render the client-facing sentence for an operator early stop."""
    return (
        "The identity graph is complete: every user, group, computer, ACL and "
        "trust was mapped, and attack paths and reach are computed over the full "
        "directory. SMB host enrichment (logged-on sessions, local-administrator "
        f"membership and share exposure) was stopped after {hosts_swept:,} of "
        f"{hosts_total:,} reachable hosts, highest-value first. The remaining "
        "hosts were not evaluated. Re-running host enrichment will cover them."
    )


def _statement_for(reason: str, hosts_swept: int, hosts_total: int) -> str:
    """Dispatch to the sentence for a given bounding reason."""
    if reason == REASON_SKIP:
        return _skip_statement(hosts_total)
    if reason == REASON_EARLY_STOP:
        return _early_stop_statement(hosts_swept, hosts_total)
    return _cap_statement(hosts_swept, hosts_total)


def build_host_enrichment_coverage(
    *,
    bounded: bool,
    reason: str = REASON_CAP,
    hosts_swept: int = 0,
    hosts_total: int = 0,
) -> dict[str, Any]:
    """Build the ``host_enrichment_coverage`` block for one domain.

    Args:
        bounded: Whether the SMB host-enrichment sweep was bounded (capped,
            skipped or stopped early). ``False`` records a complete sweep (the
            statement affirms full coverage and ``build`` carries
            ``complete=True``).
        reason: Why the sweep was bounded — one of :data:`REASON_CAP`,
            :data:`REASON_SKIP`, :data:`REASON_EARLY_STOP`. Ignored when
            ``bounded`` is ``False``.
        hosts_swept: Reachable hosts actually enriched.
        hosts_total: Reachable hosts in the estate (the denominator).

    Returns:
        The block to hand to ``record_host_enrichment_coverage``. Always carries
        ``statement`` so the recorder accepts it.
    """
    complete = not bounded
    swept = max(0, int(hosts_swept))
    total = max(swept, int(hosts_total))
    clean_reason = (
        reason if reason in (REASON_CAP, REASON_SKIP, REASON_EARLY_STOP) else REASON_CAP
    )
    return {
        "complete": complete,
        "reason": "" if complete else clean_reason,
        "hosts_swept": swept,
        "hosts_total": total,
        "hosts_remaining": max(0, total - swept),
        "identity_graph_complete": True,
        "statement": (
            _COMPLETE_STATEMENT
            if complete
            else _statement_for(clean_reason, swept, total)
        ),
    }


def host_enrichment_coverage_view(coverage: Any) -> dict[str, Any]:
    """Return the render-ready view of a persisted ``host_enrichment_coverage`` block.

    The one shape the PDF report, the LITE report and the web platform all read,
    so a bounded sweep is worded identically wherever a client meets it.

    Returns a mapping with:
      * ``has_gap`` — whether to surface the declaration at all;
      * ``statement`` — the client-facing sentence (empty when complete);
      * ``hosts_swept`` / ``hosts_total`` / ``hosts_remaining`` — the coverage
        boundary, for a machine consumer.

    An absent or unreadable block yields ``has_gap=False`` and an empty statement:
    a scan predating this record, or a complete sweep, must render exactly as it
    did before rather than grow a gap notice nobody observed.
    """
    if not isinstance(coverage, Mapping):
        return {
            "has_gap": False,
            "statement": "",
            "hosts_swept": 0,
            "hosts_total": 0,
            "hosts_remaining": 0,
        }
    complete = bool(coverage.get("complete", True))
    statement = str(coverage.get("statement") or "").strip()

    def _int(key: str) -> int:
        try:
            return max(0, int(coverage.get(key) or 0))
        except (TypeError, ValueError):
            return 0

    swept = _int("hosts_swept")
    total = max(swept, _int("hosts_total"))
    return {
        "has_gap": bool(not complete and statement),
        "statement": statement if not complete else "",
        "hosts_swept": swept,
        "hosts_total": total,
        "hosts_remaining": max(0, total - swept),
    }


def merge_host_enrichment_coverage(domain_entries: Any) -> dict[str, Any]:
    """Fold every domain's recorded coverage into one report-wide view.

    A bounded sweep in any domain means the assessment's host exposure is not
    exhaustive, so the union is a gap for the whole report. The statement returned
    is the one that was RECORDED (never a fresh derivation), so a later change to
    this module cannot silently rewrite a finding an already-delivered report made;
    only when several domains recorded DIFFERENT gap statements is one re-derived
    from the summed host counts.

    ``domain_entries`` is any iterable of per-domain mappings (the renderer passes
    ``report_data.values()``); non-mapping entries and the reserved non-domain
    blocks that ride alongside are skipped. No recorded coverage anywhere yields
    ``has_gap=False`` — the pre-existing render, unchanged.
    """
    statements: list[str] = []
    swept_sum = 0
    total_sum = 0
    saw_gap = False
    for entry in domain_entries or ():
        if not isinstance(entry, Mapping):
            continue
        block = entry.get(HOST_ENRICHMENT_COVERAGE_KEY)
        view = host_enrichment_coverage_view(block)
        if not view["has_gap"]:
            continue
        saw_gap = True
        swept_sum += int(view["hosts_swept"])
        total_sum += int(view["hosts_total"])
        if view["statement"] not in statements:
            statements.append(view["statement"])
    if not saw_gap:
        return host_enrichment_coverage_view(None)

    merged = build_host_enrichment_coverage(
        bounded=True, hosts_swept=swept_sum, hosts_total=total_sum
    )
    if len(statements) == 1:
        merged["statement"] = statements[0]
    return host_enrichment_coverage_view(merged)


__all__ = [
    "HOST_ENRICHMENT_COVERAGE_KEY",
    "REASON_CAP",
    "REASON_EARLY_STOP",
    "REASON_SKIP",
    "build_host_enrichment_coverage",
    "host_enrichment_coverage_view",
    "merge_host_enrichment_coverage",
]
