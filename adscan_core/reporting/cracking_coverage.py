"""Password-cracking coverage: the client-facing statement, derived once.

An empty "Compromised Credentials" section reads, to a client, as *we tried and
nothing broke* — the strongest possible statement about their password hygiene.
That reading is only honest when the attempt actually ran at full strength. When
the audit corpus was absent from the runtime image, the same empty section makes
a claim the assessment never earned.

Under the Exposure-Validation doctrine that is a **data gap**, in the same
family as ``unsupported``: ADscan states where the assessment stopped and why,
and never converts its own missing input into a finding about the client. So the
deliverable says which corpus was unavailable, what that narrows, and what is
therefore unproven — rather than rendering an empty section or, worse, keeping
the methodology note that advertises a 94-million-entry corpus the scan never
opened.

This module is the SSOT for both halves:

* :func:`build_cracking_coverage` turns the observed wordlist state into the
  block persisted by
  :func:`adscan_core.reporting.technical_report.record_cracking_coverage`; and
* :func:`cracking_coverage_view` turns that persisted block back into the small
  render-ready shape the PDF report and the paid web platform both consume, so
  the two surfaces cannot word the same gap differently.

Pure logic: no IO, no console, no network. Safe to import from ``adscan_core``,
the LITE runtime, the PRO report renderer and the web backend alike.
"""

from __future__ import annotations

from typing import Any, Mapping

#: Per-domain key this block is stamped under, in ``technical_report.json`` and
#: in the renderer's ``report_data``. One name, so the writer, the PDF and the
#: web platform cannot drift apart on where the record lives.
CRACKING_COVERAGE_KEY = "cracking_coverage"

#: The audit corpus the report's methodology note advertises by name. Its
#: absence is what turns the advertised claim into an unearned one.
AUDIT_BASE_WORDLIST = "combined_audit_base.txt"

#: Client-facing name for that corpus, as the report brands it.
AUDIT_BASE_LABEL = "ADscan AD Audit Wordlist"

#: The fast/CTF base. Missing on its own it narrows coverage without touching
#: the advertised audit claim.
FAST_BASE_WORDLIST = "rockyou.txt"

_FULL_STATEMENT = (
    "Password recovery ran at full strength: every recovered hash was tested "
    f"against the {AUDIT_BASE_LABEL}."
)


def _clean_names(names: Any) -> tuple[str, ...]:
    """Normalize an arbitrary iterable of wordlist names into a clean tuple."""

    if not isinstance(names, (list, tuple, set, frozenset)):
        return ()
    cleaned = []
    for raw in names:
        name = str(raw or "").strip()
        if name and name not in cleaned:
            cleaned.append(name)
    return tuple(cleaned)


def _statement_for(missing: tuple[str, ...]) -> str:
    """Render the client-facing sentence for a set of absent corpora.

    Names what could not be tested and what that leaves unproven. It states the
    limit of the assessment, never a verdict about the client's passwords, and
    never the internal reason the file was absent — an operator diagnosis in a
    client deliverable reads as an apology, and the operator already got the
    real one on the terminal.

    The wording holds whether or not any account was recovered: the section
    renders with an empty list precisely when the gap is most misleading, so it
    must not point the reader at "the list below".
    """

    if AUDIT_BASE_WORDLIST in missing:
        return (
            f"The {AUDIT_BASE_LABEL} was not available to this assessment, so "
            "recovered password hashes were not tested against it. Password "
            "strength is therefore unproven either way: an account not named "
            "here was not shown to be resistant, only left untested at full "
            "strength. Re-running password recovery with the full corpus "
            "available will settle it."
        )
    return (
        "Part of the password corpus was not available to this assessment, so "
        "password recovery ran with reduced coverage. An account not named here "
        "was not shown to be resistant, only tested against a narrower "
        "candidate set."
    )


def build_cracking_coverage(
    *,
    missing_wordlists: Any = (),
    base_wordlist: str = "",
) -> dict[str, Any]:
    """Build the ``cracking_coverage`` block for one domain.

    Args:
        missing_wordlists: Names of the cracking corpora absent from this
            runtime, as observed by the wordlist verification pass.
        base_wordlist: The corpus password recovery actually used, when known.

    Returns:
        The block to hand to ``record_cracking_coverage``. Always carries
        ``statement`` so the recorder accepts it; ``complete`` is ``True`` when
        nothing was missing, and the statement then affirms full coverage
        instead of describing a gap.
    """

    missing = _clean_names(missing_wordlists)
    complete = not missing
    return {
        "complete": complete,
        "missing_wordlists": list(missing),
        "base_wordlist": str(base_wordlist or "").strip(),
        "audit_base_available": AUDIT_BASE_WORDLIST not in missing,
        "statement": _FULL_STATEMENT if complete else _statement_for(missing),
    }


def cracking_coverage_view(coverage: Any) -> dict[str, Any]:
    """Return the render-ready view of a persisted ``cracking_coverage`` block.

    The one shape the PDF report and the web platform both read, so a gap is
    worded identically wherever a client meets it.

    Returns a mapping with:
      * ``has_gap`` — whether to surface the declaration at all;
      * ``statement`` — the client-facing sentence;
      * ``audit_base_available`` — whether the advertised audit-corpus
        methodology note is still true and may be rendered;
      * ``missing_wordlists`` — the absent corpora, for a machine consumer.

    An absent or unreadable block yields ``has_gap=False`` and
    ``audit_base_available=True``: a scan predating this record, or one whose
    coverage was never written, must render exactly as it did before rather
    than grow a gap notice nobody observed.
    """

    if not isinstance(coverage, Mapping):
        return {
            "has_gap": False,
            "statement": "",
            "audit_base_available": True,
            "missing_wordlists": [],
        }
    missing = _clean_names(coverage.get("missing_wordlists"))
    complete = bool(coverage.get("complete", not missing))
    statement = str(coverage.get("statement") or "").strip()
    audit_available = coverage.get("audit_base_available")
    if audit_available is None:
        audit_available = AUDIT_BASE_WORDLIST not in missing
    return {
        "has_gap": bool(not complete and statement),
        "statement": statement if not complete else "",
        "audit_base_available": bool(audit_available),
        "missing_wordlists": list(missing),
    }


def merge_cracking_coverage(domain_entries: Any) -> dict[str, Any]:
    """Fold every domain's recorded coverage into one report-wide view.

    The corpus is a property of the runtime image, not of a domain, so a gap
    observed for any domain is a gap for the whole assessment — and the
    recovered-credentials section is a single section, not one per domain. The
    union of the absent corpora drives one statement.

    ``domain_entries`` is any iterable of per-domain mappings (the renderer
    passes ``report_data.values()``); non-mapping entries and the reserved
    non-domain blocks that ride alongside are simply skipped. No recorded
    coverage anywhere yields ``has_gap=False`` and ``audit_base_available=True``
    — the pre-existing render, unchanged.

    The statement is the one that was RECORDED, never a fresh derivation from
    the merged names: the wording persisted at scan time is what that
    assessment reported, and re-deriving it would let a later change to this
    module silently rewrite the finding an already-delivered report made. Only
    when several domains recorded DIFFERENT gap statements is a statement
    derived, because there is then no single recorded one to honour.
    """

    missing: list[str] = []
    statements: list[str] = []
    saw_record = False
    for entry in domain_entries or ():
        if not isinstance(entry, Mapping):
            continue
        block = entry.get(CRACKING_COVERAGE_KEY)
        if not isinstance(block, Mapping):
            continue
        saw_record = True
        for name in _clean_names(block.get("missing_wordlists")):
            if name not in missing:
                missing.append(name)
        view = cracking_coverage_view(block)
        if view["has_gap"] and view["statement"] not in statements:
            statements.append(view["statement"])
    if not saw_record:
        return cracking_coverage_view(None)

    merged = build_cracking_coverage(missing_wordlists=missing)
    if len(statements) == 1:
        merged["statement"] = statements[0]
    return cracking_coverage_view(merged)


__all__ = [
    "AUDIT_BASE_LABEL",
    "AUDIT_BASE_WORDLIST",
    "CRACKING_COVERAGE_KEY",
    "FAST_BASE_WORDLIST",
    "build_cracking_coverage",
    "cracking_coverage_view",
    "merge_cracking_coverage",
]
