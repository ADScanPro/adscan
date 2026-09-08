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

#: Vendor-neutral name for each cracking backend class. The client deliverable
#: never names the offensive tool that produced the result — a GPU result is
#: described as GPU-accelerated cracking, a CPU result as CPU-based cracking.
_CRACKER_CLASS_BY_ENGINE: dict[str, str] = {
    "hashcat": "GPU-accelerated password cracking",
    "john": "CPU-based password cracking",
}

#: Vendor-neutral effort description for each internal rule set. The client
#: reads the *strength of the attempt*, never the internal ruleset identifier.
#: ``None`` (a tier that ran without rules) maps to the wordlist-only phrasing.
_RULE_EFFORT_BY_RULESET: dict[str, str] = {
    "adscan_r1": "a standard rule set",
    "adscan_r2": "an extended rule set",
    "adscan_r3": "an exhaustive rule set",
}

#: The phrasing for a tier that ran the wordlist alone, with no rule mutation.
_NO_RULE_EFFORT = "wordlist only (no rule mutation)"

#: Rank each rule set by effort strength, so a report-wide fold can credit the
#: assessment with the STRONGEST attempt it made across its domains. Engine
#: class is not ranked — a GPU vs CPU choice reflects the runtime, not attempt
#: depth — so among equal rulesets the first recorded block wins (stable).
_RULE_EFFORT_RANK: dict[str | None, int] = {
    None: 0,
    "adscan_r1": 1,
    "adscan_r2": 2,
    "adscan_r3": 3,
}


def _effort_rank(engine: Any, ruleset: Any) -> int:
    """Return a sortable effort strength for one recorded (engine, ruleset).

    ``-1`` when no recognised backend was recorded, so a block that carries no
    effort declaration never wins the report-wide fold.
    """

    if not cracker_class_label(engine):
        return -1
    name = None if ruleset is None else str(ruleset).strip().lower()
    return _RULE_EFFORT_RANK.get(name, 0)


def cracker_class_label(engine: Any) -> str:
    """Return the vendor-neutral cracker-class phrase for a backend name.

    Args:
        engine: The backend that produced the result (``"hashcat"``/``"john"``),
            as carried on ``CrackResult.engine``. Any other/absent value yields
            an empty string, so an unrecognised backend never leaks a raw name.

    Returns:
        ``"GPU-accelerated password cracking"``, ``"CPU-based password
        cracking"``, or ``""`` when the engine is unknown.
    """

    return _CRACKER_CLASS_BY_ENGINE.get(str(engine or "").strip().lower(), "")


def rule_effort_label(ruleset: Any) -> str:
    """Return the vendor-neutral rule-effort phrase for a ruleset identifier.

    Args:
        ruleset: The internal rule set applied (e.g. ``"adscan_r1"``), or
            ``None`` when the tier ran without rules, as carried on
            ``CrackResult.ruleset``. Never surfaced to the client verbatim.

    Returns:
        ``"a standard rule set"`` / ``"an extended rule set"`` / ``"an
        exhaustive rule set"``, the wordlist-only phrase for ``None``, or ``""``
        when the identifier is unrecognised.
    """

    name = str(ruleset or "").strip().lower()
    if not name:
        # ``None`` / empty is a real, meaningful state: the tier ran the
        # wordlist with no rule mutation. Distinguish it from an *unknown*
        # engine, which yields "" (see ``effort_statement``).
        return _NO_RULE_EFFORT if ruleset is None or ruleset == "" else ""
    return _RULE_EFFORT_BY_RULESET.get(name, "")


def effort_statement(engine: Any, ruleset: Any) -> str:
    """Render the client-facing sentence stating the strength of the attempt.

    Names the cracker class and the rule effort in vendor-neutral prose, so the
    deliverable is honest about how hard password recovery actually tried. It
    describes ADscan's own work, never a verdict about the client and never a
    defensive control — a state where nothing ran carries no sentence at all.

    Args:
        engine: The backend that produced the result (``CrackResult.engine``).
        ruleset: The rule set applied (``CrackResult.ruleset``), or ``None``.

    Returns:
        The client-safe sentence, or ``""`` when no backend was recorded (so
        the render simply omits the line rather than inventing one).
    """

    cracker = cracker_class_label(engine)
    if not cracker:
        return ""
    effort = rule_effort_label(ruleset)
    if not effort:
        return f"Password recovery used {cracker}."
    return f"Password recovery used {cracker} with {effort}."


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
    engine: Any = None,
    ruleset: Any = None,
) -> dict[str, Any]:
    """Build the ``cracking_coverage`` block for one domain.

    Args:
        missing_wordlists: Names of the cracking corpora absent from this
            runtime, as observed by the wordlist verification pass.
        base_wordlist: The corpus password recovery actually used, when known.
        engine: The backend that actually produced the result
            (``CrackResult.engine`` — ``"hashcat"`` or ``"john"``), or ``None``
            when no crack ran / the backend is unknown. Recorded so the
            deliverable can state which cracker class ran, in vendor-neutral
            prose.
        ruleset: The rule set applied (``CrackResult.ruleset``, e.g.
            ``"adscan_r1"``), or ``None`` when the tier ran without rules. Never
            surfaced verbatim; it is translated to an effort description.

    Returns:
        The block to hand to ``record_cracking_coverage``. Always carries
        ``statement`` so the recorder accepts it; ``complete`` is ``True`` when
        nothing was missing, and the statement then affirms full coverage
        instead of describing a gap. When a backend was recorded the block also
        carries the raw ``engine``/``ruleset`` (for a machine consumer) plus the
        derived vendor-neutral ``cracker_class`` / ``rule_effort`` /
        ``effort_statement`` so every surface renders the same effort prose.
    """

    missing = _clean_names(missing_wordlists)
    complete = not missing
    block: dict[str, Any] = {
        "complete": complete,
        "missing_wordlists": list(missing),
        "base_wordlist": str(base_wordlist or "").strip(),
        "audit_base_available": AUDIT_BASE_WORDLIST not in missing,
        "statement": _FULL_STATEMENT if complete else _statement_for(missing),
    }
    cracker_class = cracker_class_label(engine)
    if cracker_class:
        block["engine"] = str(engine).strip().lower()
        block["ruleset"] = None if ruleset is None else str(ruleset)
        block["cracker_class"] = cracker_class
        block["rule_effort"] = rule_effort_label(ruleset)
        block["effort_statement"] = effort_statement(engine, ruleset)
    return block


def cracking_coverage_view(coverage: Any) -> dict[str, Any]:
    """Return the render-ready view of a persisted ``cracking_coverage`` block.

    The one shape the PDF report and the web platform both read, so a gap is
    worded identically wherever a client meets it.

    Returns a mapping with:
      * ``has_gap`` — whether to surface the declaration at all;
      * ``statement`` — the client-facing sentence;
      * ``audit_base_available`` — whether the advertised audit-corpus
        methodology note is still true and may be rendered;
      * ``missing_wordlists`` — the absent corpora, for a machine consumer;
      * ``cracker_class`` — vendor-neutral cracker class that ran
        (``"GPU-accelerated password cracking"`` / ``"CPU-based password
        cracking"``), or ``""`` when no backend was recorded;
      * ``rule_effort`` — vendor-neutral rule-effort description, or ``""``;
      * ``effort_statement`` — the client-facing sentence declaring the
        strength of the attempt, or ``""`` when nothing ran.

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
            "cracker_class": "",
            "rule_effort": "",
            "effort_statement": "",
        }
    missing = _clean_names(coverage.get("missing_wordlists"))
    complete = bool(coverage.get("complete", not missing))
    statement = str(coverage.get("statement") or "").strip()
    audit_available = coverage.get("audit_base_available")
    if audit_available is None:
        audit_available = AUDIT_BASE_WORDLIST not in missing
    # Prefer the effort prose the block RECORDED (the wording that assessment
    # shipped); fall back to deriving it from the raw engine/ruleset so a block
    # carrying only the machine fields still renders. Absent both, "" — the
    # section then simply omits the effort line rather than inventing one.
    cracker_class = str(coverage.get("cracker_class") or "").strip()
    rule_effort = str(coverage.get("rule_effort") or "").strip()
    effort = str(coverage.get("effort_statement") or "").strip()
    if not cracker_class and "engine" in coverage:
        cracker_class = cracker_class_label(coverage.get("engine"))
        rule_effort = rule_effort_label(coverage.get("ruleset"))
        effort = effort_statement(coverage.get("engine"), coverage.get("ruleset"))
    return {
        "has_gap": bool(not complete and statement),
        "statement": statement if not complete else "",
        "audit_base_available": bool(audit_available),
        "missing_wordlists": list(missing),
        "cracker_class": cracker_class,
        "rule_effort": rule_effort,
        "effort_statement": effort,
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

    The effort declaration (which cracker class + rule effort ran) folds to the
    STRONGEST attempt recorded anywhere: the assessment's real password-recovery
    strength is the hardest run it made, so a GPU/exhaustive run in one domain
    is what the whole assessment gets credit for, not a weaker run elsewhere.
    """

    missing: list[str] = []
    statements: list[str] = []
    best_effort_block: Mapping[str, Any] | None = None
    best_effort_rank = -1
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
        rank = _effort_rank(block.get("engine"), block.get("ruleset"))
        if view["effort_statement"] and rank > best_effort_rank:
            best_effort_rank = rank
            best_effort_block = block
    if not saw_record:
        return cracking_coverage_view(None)

    merged = build_cracking_coverage(missing_wordlists=missing)
    if len(statements) == 1:
        merged["statement"] = statements[0]
    if best_effort_block is not None:
        # Honour the effort prose that block recorded, verbatim, for the same
        # reason the gap statement is honoured: it is what that scan shipped.
        for key in (
            "engine",
            "ruleset",
            "cracker_class",
            "rule_effort",
            "effort_statement",
        ):
            if key in best_effort_block:
                merged[key] = best_effort_block[key]
    return cracking_coverage_view(merged)


__all__ = [
    "AUDIT_BASE_LABEL",
    "AUDIT_BASE_WORDLIST",
    "CRACKING_COVERAGE_KEY",
    "FAST_BASE_WORDLIST",
    "build_cracking_coverage",
    "cracker_class_label",
    "cracking_coverage_view",
    "effort_statement",
    "merge_cracking_coverage",
    "rule_effort_label",
]
