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

#: The local wordlist attack is UNDERWAY against the declared hashes but had not
#: finished when the assessment was written. A bounded computation, so the block
#: reads as incomplete and the statement names the boundary.
LOCAL_ATTACK_RUNNING = "running"

#: The local wordlist attack walked its ladder to the end. Full strength: the
#: declared hashes were tested against the audit corpus.
LOCAL_ATTACK_COMPLETED = "completed"

#: The local wordlist attack STOPPED at its time budget, part-way through the
#: candidate set. A bounded computation, and a state none of the other three can
#: express honestly: ``completed`` would claim a full-strength test that did not
#: happen, which is the "your passwords held" false negative this whole block
#: exists to prevent; ``running`` would promise results that will arrive later,
#: when in fact nothing more is coming; ``unavailable`` would blame a missing
#: engine that was in fact present and working. So the boundary gets its own
#: word: the attack ran, it ran out of time, and what it did not reach is
#: unproven.
LOCAL_ATTACK_TRUNCATED = "truncated"

#: No password-cracking engine was available on the host that ran the
#: assessment, so the declared hashes were never attacked locally at all. A data
#: gap about ADscan's runtime, never a verdict about the client's passwords.
LOCAL_ATTACK_UNAVAILABLE = "unavailable"

#: Every recognised local-attack status. Anything else normalizes to ``""`` (no
#: local attack recorded), so a malformed value can never manufacture a gap.
_LOCAL_ATTACK_STATUSES: frozenset[str] = frozenset(
    {
        LOCAL_ATTACK_RUNNING,
        LOCAL_ATTACK_TRUNCATED,
        LOCAL_ATTACK_COMPLETED,
        LOCAL_ATTACK_UNAVAILABLE,
    }
)

#: Worst-first order for the report-wide fold. A gap any domain had is a gap for
#: the whole assessment, so an unavailable engine outranks an unfinished attack,
#: which outranks one that stopped at its time budget, which outranks a finished
#: one. Unfinished sits above truncated because an attack still in flight leaves
#: the figures provisional, where a truncated one is final and merely partial.
_LOCAL_ATTACK_MERGE_PRECEDENCE: tuple[str, ...] = (
    LOCAL_ATTACK_UNAVAILABLE,
    LOCAL_ATTACK_RUNNING,
    LOCAL_ATTACK_TRUNCATED,
    LOCAL_ATTACK_COMPLETED,
)

#: Map an internal base-wordlist filename to the ONE client-facing name the
#: deliverable brands its cracking corpus with. Both house bases fold to the
#: audit label: the per-finding line and the methodology note must agree, and a
#: recovery the fast base made is a recovery the audit corpus (which contains it)
#: also makes. A genuinely custom/targeted wordlist is NOT one of these and is
#: returned unchanged (already client-meaningful).
_CLIENT_WORDLIST_LABELS: dict[str, str] = {
    AUDIT_BASE_WORDLIST.lower(): AUDIT_BASE_LABEL,
    AUDIT_BASE_LABEL.lower(): AUDIT_BASE_LABEL,
    FAST_BASE_WORDLIST.lower(): AUDIT_BASE_LABEL,
}


def client_wordlist_label(name: Any) -> str:
    """Return the ONE client-facing name for a cracking wordlist.

    The deliverable's methodology note brands its corpus as :data:`AUDIT_BASE_LABEL`;
    a per-finding line that instead printed the raw base filename (``rockyou.txt``)
    read as a different, lesser wordlist than the note advertised. This folds the
    internal base-wordlist names to that one client-facing name so every surface
    agrees. A non-base (custom/targeted) name is returned unchanged.

    Args:
        name: The recorded wordlist name (a filename or label). Empty / non-string
            yields ``""``.

    Returns:
        The branded audit label for a house base, the trimmed name otherwise.
    """

    raw = str(name or "").strip()
    if not raw:
        return ""
    return _CLIENT_WORDLIST_LABELS.get(raw.lower(), raw)

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


def _breach_lookup_clause(count: int, *, standalone: bool) -> str:
    """Declare the hash class that went to a breach-corpus lookup ONLY.

    The two recovery methods answer different questions, and conflating them is
    how a coverage note came to claim a stronger method than the one that ran:

    * a breach-corpus lookup asks "is this exact password already public?";
    * a wordlist attack asks "is this password weak?".

    Passing the first proves only absence from one corpus, so a hash that saw
    only the lookup has NOT been tested at full strength and the statement must
    not imply it was. ``standalone`` renders it as the whole statement; otherwise
    it is appended after a more serious absent-corpus gap.
    """
    if count <= 0:
        return ""
    hashes_noun = "hash" if count == 1 else "hashes"
    if standalone:
        return (
            "Password recovery did not run at one strength for every hash. "
            f"{count:,} {hashes_noun} replicated from the directory were checked "
            "against a public breach-password corpus by lookup, which identifies "
            "a password that is already exposed in a public breach but does not "
            f"test its strength against the {AUDIT_BASE_LABEL}. An account not "
            "named here was not shown to have a strong password, only to be "
            "absent from that public corpus."
        )
    return (
        f"Separately, {count:,} {hashes_noun} replicated from the directory were "
        "checked against a public breach-password corpus by lookup, which reports "
        "a password already exposed in a public breach and does not test strength."
    )


def _local_attack_clause(
    status: str, count: int, *, standalone: bool, audit_available: bool = True
) -> str:
    """Declare what a LOCAL wordlist attack did to a class of recovered hashes.

    A local attack and a breach-corpus lookup answer different questions, and
    this clause exists so the stronger method is never credited to the weaker
    one (nor the other way round):

    * a lookup asks "is this exact password already public?";
    * a local wordlist attack asks "is this password weak?" — the question the
      report's methodology note advertises.

    So the four states a local attack can be in get four distinct sentences: it
    finished (full strength, no gap), it stopped at its time budget part-way
    through the candidate set (a bounded computation — the boundary is declared
    and nothing further is coming), it was still running when the assessment was
    written (also bounded, but provisional: more may yet land), or it could not
    run at all on this host (a data gap about ADscan's own runtime, never a
    verdict about the client). ``standalone`` renders the clause as the whole
    statement; otherwise it is appended after a more serious absent-corpus gap.

    ``audit_available`` decides whether the clause may NAME the advertised
    audit corpus. It must not when that corpus was absent from the runtime:
    the statement would then claim, one sentence after saying the corpus was
    unavailable, that hashes were tested against it.
    """

    if count <= 0 or status not in _LOCAL_ATTACK_STATUSES:
        return ""
    hashes_noun = "hash" if count == 1 else "hashes"
    were = "was" if count == 1 else "were"
    corpus = (
        f"the {AUDIT_BASE_LABEL}"
        if audit_available
        else "the narrower password corpus this assessment carried"
    )
    if status == LOCAL_ATTACK_COMPLETED:
        tested = (
            f"{count:,} recovered password {hashes_noun} {were} tested "
            f"locally against {corpus}."
        )
        if standalone:
            return tested
        return f"Separately, {tested[0].lower()}{tested[1:]}"
    if status == LOCAL_ATTACK_TRUNCATED:
        stopped = (
            f"{count:,} recovered password {hashes_noun} {were} tested locally "
            f"against {corpus}, and that test reached its time budget and "
            "stopped before working through the whole candidate set. Any "
            "password it had not reached is unproven: an account not named in "
            "this report was not shown to have a strong password."
        )
        if standalone:
            return stopped
        return f"Separately, {stopped[0].lower()}{stopped[1:]}"
    if status == LOCAL_ATTACK_RUNNING:
        running = (
            f"a password-strength attack against {corpus} was still "
            f"running over {count:,} recovered password {hashes_noun}, "
            "so any password it recovers after this point is not reflected here."
        )
        if standalone:
            return (
                "Password recovery was still underway when this assessment was "
                f"written: {running}"
            )
        return f"Separately, {running}"
    unavailable = (
        f"{count:,} recovered password {hashes_noun} could not be "
        "tested against a password corpus, because the host running this "
        "assessment had no password-recovery engine available. Their strength is "
        "therefore unproven either way."
    )
    if standalone:
        return unavailable
    return f"Separately, {unavailable[0].lower()}{unavailable[1:]}"


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
    breach_lookup_only_hashes: Any = 0,
    breach_lookup_recovered: Any = 0,
    local_attack_hashes: Any = 0,
    local_attack_recovered: Any = 0,
    local_attack_status: Any = "",
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
        local_attack_hashes: How many recovered hashes were handed to a LOCAL
            wordlist attack (the strong method), as opposed to the
            breach-corpus lookup. A DISTINCT class from
            ``breach_lookup_only_hashes``: conflating the two is how a weaker
            method comes to be reported as a stronger one.
        local_attack_recovered: How many of those the local attack resolved.
        local_attack_status: :data:`LOCAL_ATTACK_RUNNING`,
            :data:`LOCAL_ATTACK_TRUNCATED`, :data:`LOCAL_ATTACK_COMPLETED` or
            :data:`LOCAL_ATTACK_UNAVAILABLE`. Only ``COMPLETED`` is full
            strength; the other three are declared coverage boundaries.

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
    try:
        lookup_only = max(int(breach_lookup_only_hashes or 0), 0)
    except (TypeError, ValueError):
        lookup_only = 0
    try:
        lookup_recovered = max(int(breach_lookup_recovered or 0), 0)
    except (TypeError, ValueError):
        lookup_recovered = 0
    try:
        local_only = max(int(local_attack_hashes or 0), 0)
    except (TypeError, ValueError):
        local_only = 0
    try:
        local_recovered = max(int(local_attack_recovered or 0), 0)
    except (TypeError, ValueError):
        local_recovered = 0
    local_status = str(local_attack_status or "").strip().lower()
    if local_status not in _LOCAL_ATTACK_STATUSES or local_only <= 0:
        # An unrecognised status, or a status with nothing behind it, records NO
        # local-attack class at all — a malformed value must never manufacture
        # either a gap or a full-strength claim.
        local_status = ""
        local_only = 0
        local_recovered = 0
    # A hash class that saw ONLY the breach-corpus lookup is a genuine coverage
    # boundary: it was never tested at full strength, so the block must not read
    # as complete. Same for a local attack that was still running, or that could
    # not run at all on this host. This is the bounded-computation doctrine
    # applied to METHOD rather than to volume.
    local_gap = local_status in {
        LOCAL_ATTACK_RUNNING,
        LOCAL_ATTACK_TRUNCATED,
        LOCAL_ATTACK_UNAVAILABLE,
    }
    complete = not missing and lookup_only == 0 and not local_gap
    audit_available = AUDIT_BASE_WORDLIST not in missing
    local_clause_primary = _local_attack_clause(
        local_status, local_only, standalone=True, audit_available=audit_available
    )
    local_clause_appended = _local_attack_clause(
        local_status, local_only, standalone=False, audit_available=audit_available
    )
    if missing:
        statement = _statement_for(missing)
        for clause in (
            local_clause_appended,
            _breach_lookup_clause(lookup_only, standalone=False),
        ):
            if clause:
                statement = f"{statement} {clause}"
    elif local_gap:
        statement = local_clause_primary
        clause = _breach_lookup_clause(lookup_only, standalone=False)
        if clause:
            statement = f"{statement} {clause}"
    elif lookup_only:
        statement = _breach_lookup_clause(lookup_only, standalone=True)
        if local_clause_appended:
            statement = f"{statement} {local_clause_appended}"
    else:
        statement = _FULL_STATEMENT
    block: dict[str, Any] = {
        "complete": complete,
        "missing_wordlists": list(missing),
        "base_wordlist": str(base_wordlist or "").strip(),
        "audit_base_available": AUDIT_BASE_WORDLIST not in missing,
        # How many hashes were tested by breach-corpus LOOKUP ONLY, and how many
        # of those the lookup resolved. Recorded so a machine consumer can state
        # the method per class instead of inferring one from the recovery count.
        "breach_lookup_only_hashes": lookup_only,
        "breach_lookup_recovered": lookup_recovered,
        # The LOCAL wordlist-attack class, kept strictly apart from the lookup
        # counters above: the two methods prove different things, and one must
        # never be credited with the other's strength.
        "local_attack_hashes": local_only,
        "local_attack_recovered": local_recovered,
        "local_attack_status": local_status,
        "statement": statement,
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
            "breach_lookup_only_hashes": 0,
            "breach_lookup_recovered": 0,
            "local_attack_hashes": 0,
            "local_attack_recovered": 0,
            "local_attack_status": "",
            "cracker_class": "",
            "rule_effort": "",
            "effort_statement": "",
        }
    missing = _clean_names(coverage.get("missing_wordlists"))
    try:
        lookup_only = max(int(coverage.get("breach_lookup_only_hashes") or 0), 0)
    except (TypeError, ValueError):
        lookup_only = 0
    try:
        lookup_recovered = max(int(coverage.get("breach_lookup_recovered") or 0), 0)
    except (TypeError, ValueError):
        lookup_recovered = 0
    try:
        local_hashes = max(int(coverage.get("local_attack_hashes") or 0), 0)
    except (TypeError, ValueError):
        local_hashes = 0
    try:
        local_recovered = max(int(coverage.get("local_attack_recovered") or 0), 0)
    except (TypeError, ValueError):
        local_recovered = 0
    local_status = str(coverage.get("local_attack_status") or "").strip().lower()
    if local_status not in _LOCAL_ATTACK_STATUSES or local_hashes <= 0:
        local_status = ""
        local_hashes = 0
        local_recovered = 0
    # A block written before this record carries no lookup counter, so it reads
    # exactly as it did: default to the block's OWN ``complete``, never infer a
    # method boundary nobody observed.
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
        "breach_lookup_only_hashes": lookup_only,
        "breach_lookup_recovered": lookup_recovered,
        "local_attack_hashes": local_hashes,
        "local_attack_recovered": local_recovered,
        "local_attack_status": local_status,
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
    lookup_only = 0
    lookup_recovered = 0
    # Per local-attack status, the largest (hashes, recovered) any domain
    # recorded. Folded by WORST status (see _LOCAL_ATTACK_MERGE_PRECEDENCE): the
    # assessment-wide statement must report the weakest coverage any domain had,
    # never the strongest — the opposite of the effort fold below, which credits
    # the hardest attempt because that one genuinely ran.
    local_by_status: dict[str, tuple[int, int]] = {}
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
        # Carry the breach-lookup-only class through the fold. The merge rebuilds
        # the block from scratch, so a field it does not re-pass is DROPPED and
        # the report-wide note silently reverts to claiming full strength. The
        # lookup runs once per assessment and is recorded onto every in-scope
        # domain, so the fold takes the MAX rather than a sum.
        lookup_only = max(lookup_only, int(view["breach_lookup_only_hashes"]))
        lookup_recovered = max(lookup_recovered, int(view["breach_lookup_recovered"]))
        local_status = str(view["local_attack_status"] or "")
        if local_status:
            prev_hashes, prev_recovered = local_by_status.get(local_status, (0, 0))
            local_by_status[local_status] = (
                max(prev_hashes, int(view["local_attack_hashes"])),
                max(prev_recovered, int(view["local_attack_recovered"])),
            )
        if view["has_gap"] and view["statement"] not in statements:
            statements.append(view["statement"])
        rank = _effort_rank(block.get("engine"), block.get("ruleset"))
        if view["effort_statement"] and rank > best_effort_rank:
            best_effort_rank = rank
            best_effort_block = block
    if not saw_record:
        return cracking_coverage_view(None)

    merged_status = next(
        (s for s in _LOCAL_ATTACK_MERGE_PRECEDENCE if s in local_by_status), ""
    )
    merged_local_hashes, merged_local_recovered = local_by_status.get(
        merged_status, (0, 0)
    )
    merged = build_cracking_coverage(
        missing_wordlists=missing,
        breach_lookup_only_hashes=lookup_only,
        breach_lookup_recovered=lookup_recovered,
        local_attack_hashes=merged_local_hashes,
        local_attack_recovered=merged_local_recovered,
        local_attack_status=merged_status,
    )
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
    "client_wordlist_label",
    "AUDIT_BASE_WORDLIST",
    "CRACKING_COVERAGE_KEY",
    "FAST_BASE_WORDLIST",
    "LOCAL_ATTACK_COMPLETED",
    "LOCAL_ATTACK_RUNNING",
    "LOCAL_ATTACK_TRUNCATED",
    "LOCAL_ATTACK_UNAVAILABLE",
    "build_cracking_coverage",
    "cracker_class_label",
    "cracking_coverage_view",
    "effort_statement",
    "merge_cracking_coverage",
    "rule_effort_label",
]
