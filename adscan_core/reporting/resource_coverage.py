"""Resource-bounded coverage: the client-facing statement, derived once.

A stage that runs out of memory and stops part-way leaves a result that LOOKS
complete: fewer edges, fewer routes, fewer rows, and nothing to say so. For a
product whose claim is "validated, not estimated", a silently smaller answer is
worse than a crash, because the crash at least told the truth. Under the
Exposure-Validation doctrine a stage that had to stop is a **data gap** in the
same family as ``unsupported``: the deliverable states where the assessment
stopped, and never turns ADscan's own limit into a finding about the client.

This module is the SSOT for that declaration, for every stage that can be bounded
by a resource (collection, graph construction, attack-path discovery, report
rendering, platform ingestion, live computation):

* :func:`build_resource_coverage` turns one stage's stop into the block persisted
  per domain (one entry per stopped stage, see :func:`merge_stage_coverage`);
* :func:`resource_coverage_view` turns that persisted block back into the
  render-ready shape the PDF report and the paid web platform both consume, so
  the two surfaces cannot word the same gap differently; and
* :func:`merge_resource_coverage` folds every domain's block into one
  report-wide view.

Two audiences, two strings, never mixed. The OPERATOR gets the real cause on the
terminal (that is :mod:`adscan_core.memory_guard`'s job). The CLIENT gets the
boundary: which part of the assessment stopped, how far it got, and what that
leaves unproven. The client statement never names the internal reason (memory,
a limit, a host) and never draws a conclusion about the client's directory.

The shape mirrors :mod:`adscan_core.reporting.cracking_coverage`. Pure logic: no
IO, no console, no network. Safe to import from ``adscan_core``, the LITE
runtime, the PRO report renderer and the web backend alike.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

#: Per-domain key this block is stamped under, in ``technical_report.json`` and
#: in the renderer's ``report_data``. One name, so the writer, the PDF and the web
#: platform cannot drift apart on where the record lives.
RESOURCE_COVERAGE_KEY = "resource_coverage"

#: Machine-readable reason recorded on a stage entry. Never rendered to a client:
#: the reason is an operator diagnosis, the client reads only the boundary.
REASON_MEMORY = "memory"

#: Reason of a stage that stopped at a fixed bound on how much it lists (the
#: file review on a database server or on a host over Windows Remote Management:
#: a listing is read in bounded replies and stops at a total). Like every reason, recorded for a machine consumer only.
REASON_LISTING_LIMIT = "listing_limit"

#: Reason of a file listing that ended before the tree was read whole (the
#: listing of a network share ran out of its time budget or ended on an error).
REASON_LISTING_INCOMPLETE = "listing_incomplete"

#: Key of a stage entry naming the run that recorded the stop (since
#: ``technical_report.json`` 2.7). A stop of the graph build is not retried by the
#: SAME run (each attempt would climb to the ceiling again); a later run builds
#: normally and clears it. Absent on entries written before 2.7 and when the stop
#: was recorded without a run identity.
RUN_ID_KEY = "run_id"

# --- Stage identifiers --------------------------------------------------------
#
# One id per pipeline stage that can be resource-bounded (spec 2026-11-12 §15.7).
# A caller passes one of these to ``memory_bounded``; an unknown id still renders,
# under the generic label, so a new stage can never produce an empty sentence.

STAGE_COLLECTION = "collection"
STAGE_GRAPH_BUILD = "graph_build"
STAGE_GRAPH_EXPORT = "graph_export"
STAGE_ATTACK_PATHS = "attack_paths"
STAGE_CHOKEPOINT_ANALYSIS = "chokepoint_analysis"
STAGE_REPORT = "report"
STAGE_WEB_INGESTION = "web_ingestion"
STAGE_WEB_LIVE_COMPUTE = "web_live_compute"
#: The work done on a database server after signing in to it (privilege review,
#: command execution, file review), counted in steps.
STAGE_MSSQL_POST_AUTH = "mssql_post_auth"
#: The file review on a database server, counted in files listed.
STAGE_MSSQL_FILE_REVIEW = "mssql_file_review"
#: The file search on a host reached over Windows Remote Management after
#: signing in to it (listing, fetching and reading files), counted in steps.
STAGE_WINRM_POST_AUTH = "winrm_post_auth"
#: The file listing on a host reached over Windows Remote Management, counted
#: in files listed.
STAGE_WINRM_FILE_REVIEW = "winrm_file_review"
#: The file review of network shares as a whole (list every share, keep the
#: files worth reading), counted in shares. Recorded when it stopped for memory.
STAGE_SHARE_MAPPING = "share_mapping"
#: The file listing of single network shares, counted in shares: recorded when
#: the listing of some shares was cut short (its bound on kept files, its time
#: budget, an error part-way) while the review as a whole went on.
STAGE_SHARE_FILE_LISTING = "share_file_listing"

#: The stage the memory sentinel records when it stopped the process outside
#: any memory-bounded stage. It has its own sentence: there is no stage to name.
STAGE_UNKNOWN = "unknown"

#: Client-facing name for each stage, written as the subject of a sentence.
_STAGE_LABELS: dict[str, str] = {
    STAGE_COLLECTION: "Directory collection",
    STAGE_GRAPH_BUILD: "Building the relationship graph",
    STAGE_GRAPH_EXPORT: "Exporting the relationship graph",
    STAGE_ATTACK_PATHS: "Attack-path discovery",
    STAGE_CHOKEPOINT_ANALYSIS: "Choke-point analysis",
    STAGE_REPORT: "Rendering this report",
    STAGE_WEB_INGESTION: "Loading the assessment into the platform",
    STAGE_WEB_LIVE_COMPUTE: "Live attack-path computation",
    STAGE_MSSQL_POST_AUTH: "The review of a database server after sign-in",
    STAGE_MSSQL_FILE_REVIEW: "The file review on a database server",
    STAGE_WINRM_POST_AUTH: (
        "The file search on a host over Windows Remote Management after sign-in"
    ),
    STAGE_WINRM_FILE_REVIEW: "The file review on a host over Windows Remote Management",
    STAGE_SHARE_MAPPING: "The file review of network shares",
    STAGE_SHARE_FILE_LISTING: "The file listing of network shares",
}

#: Stages whose stop is stated by one fixed sentence instead of the counted one.
#: The choke-point analysis decorates the remediation order (which fix leaves an
#: attacker no other route); it finds no exposure of its own, so "anything beyond
#: that point was not evaluated" would misstate what its stop leaves out.
_FIXED_STAGE_STATEMENTS: dict[str, str] = {
    STAGE_CHOKEPOINT_ANALYSIS: (
        "The choke-point analysis did not finish, so this report does not mark "
        "which fixes leave an attacker no other route, and it leaves out the "
        "choke-point summary. The attack paths and the remediation order do not "
        "depend on it."
    ),
}

#: Label for a stage id this module does not know.
_GENERIC_STAGE_LABEL = "One part of this assessment"

#: The unit a domain collection's DIRECTORY READ counts in. A collection stop
#: in this unit means the directory itself was not read (nothing of the run was
#: committed), so no graph of the domain exists for this run. A collection stop
#: in any other unit (the per-host sweep, ``"hosts"``) leaves the directory read
#: whole: the graph exists and only the host enrichment is declared short.
DIRECTORY_READ_UNIT = "directory objects"

#: Root key a reader's graph carries when the build of the domain's graph
#: stopped at the memory ceiling in this session (``graph_runtime``): the graph
#: handed out is empty and is not the domain's graph.
GRAPH_BUILD_STOPPED_FLAG = "build_stopped"

#: Root key of ``attack_graph.json`` stating whether the file is the export of
#: the run that wrote it (``graph_build.export.mark_export_incomplete``).
GRAPH_EXPORT_STATE_KEY = "export_state"


def stage_label(stage: Any) -> str:
    """Return the client-facing name of a stage, never empty.

    Args:
        stage: A ``STAGE_*`` id. An unknown or empty id yields a generic label, so
            a stage added later still renders a complete sentence.
    """

    return _STAGE_LABELS.get(str(stage or "").strip().lower(), _GENERIC_STAGE_LABEL)


def _non_negative_int(value: Any) -> int | None:
    """Coerce a count to a non-negative int, or ``None`` when absent/unreadable."""

    if value is None or isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return max(number, 0)


def _clean_unit(unit: Any) -> str:
    """Normalize the plural unit noun the stage counts in (``"edges"``)."""

    text = str(unit or "").strip()
    return text or "items"


def _singular(noun: str) -> str:
    """Best-effort singular of a plural unit noun (``edges`` -> ``edge``)."""
    if noun.endswith("ies") and len(noun) > 3:
        return noun[:-3] + "y"
    if noun.endswith("s") and not noun.endswith("ss"):
        return noun[:-1]
    return noun


def _count(number: int, noun: str) -> str:
    """``1 host`` / ``12,000 hosts``."""
    return f"{number:,} {_singular(noun) if number == 1 else noun}"


def stage_statement(*, stage: Any, unit: Any, examined: Any, total: Any = None) -> str:
    """Render the client sentence for one stopped stage.

    States how far the stage got and what that leaves unproven. Names no cause
    and draws no conclusion about the client's environment.

    Args:
        stage: The ``STAGE_*`` id.
        unit: Plural noun for what the stage counts (``"edges"``, ``"hosts"``).
        examined: How many units the stage finished before it stopped, or
            ``None`` when its progress is not known (the memory sentinel stopped
            a stage that does not count its units).
        total: How many units it had in front of it, when known.
    """

    fixed = _FIXED_STAGE_STATEMENTS.get(str(stage or "").strip().lower())
    if fixed:
        return fixed
    if str(stage or "").strip().lower() == STAGE_UNKNOWN:
        return (
            "The assessment stopped before it finished. Anything it had not "
            "reached was not evaluated, so these results do not show whether it "
            "holds further exposure."
        )
    label = stage_label(stage)
    noun = _clean_unit(unit)
    done = _non_negative_int(examined)
    if done is None:
        return (
            f"{label} stopped before it finished. Anything it had not reached was "
            "not evaluated, so this assessment does not show whether it holds "
            "further exposure."
        )
    whole = _non_negative_int(total)
    if whole is not None and whole < done:
        whole = done
    if done == 0:
        return (
            f"{label} stopped before it could start, so nothing it covers was "
            "evaluated in this assessment."
        )
    if whole is not None and whole > done:
        rest = whole - done
        if rest == 1:
            remainder = (
                "The last one was not evaluated, so this assessment does not show "
                "whether it holds further exposure."
            )
        else:
            remainder = (
                f"The other {rest:,} were not evaluated, so this assessment does "
                "not show whether they hold further exposure."
            )
        return f"{label} stopped after {done:,} of {_count(whole, noun)}. {remainder}"
    return (
        f"{label} stopped after {_count(done, noun)}. Anything beyond that point was "
        "not evaluated, so this assessment does not show whether it holds further "
        "exposure."
    )


def _stage_entry(
    *,
    stage: Any,
    unit: Any,
    examined: Any,
    total: Any,
    reason: Any,
    statement: Any = None,
) -> dict[str, Any]:
    """Build one normalized stage entry, statement included.

    ``examined`` is kept as ``None`` when the stage's progress is unknown.
    """

    done = _non_negative_int(examined)
    whole = _non_negative_int(total)
    if whole is not None and done is not None and whole < done:
        whole = done
    text = str(statement or "").strip() or stage_statement(
        stage=stage, unit=unit, examined=done, total=whole
    )
    return {
        "stage": str(stage or "").strip().lower(),
        "unit": _clean_unit(unit),
        "examined": done,
        "total": whole,
        "reason": str(reason or REASON_MEMORY).strip().lower() or REASON_MEMORY,
        "statement": text,
    }


def build_resource_coverage(
    *,
    stage: Any,
    unit: Any,
    examined: Any,
    total: Any = None,
    reason: Any = REASON_MEMORY,
    statement: Any = None,
) -> dict[str, Any]:
    """Build the ``resource_coverage`` block for one stage that stopped.

    Args:
        stage: The ``STAGE_*`` id of the stage that stopped.
        unit: Plural noun for what it counts (``"edges"``, ``"routes"``).
        examined: Units finished before the stop, or ``None`` when unknown.
        total: Units it had in front of it, when known.
        reason: Machine-readable reason (default :data:`REASON_MEMORY`). Recorded
            for a machine consumer, never rendered to the client.
        statement: The client sentence, when the stage already words its own gap
            (attack-path discovery carries the ``attack_path_coverage`` sentence
            here, so one gap is never stated twice in two ways). Default: the
            sentence :func:`stage_statement` derives.

    Returns:
        ``{"complete": False, "stages": [<entry>]}``. Each entry carries the
        statement recorded at scan time, so a later change to the wording here
        never rewrites what an already-delivered report said. Fold further stops
        into it with :func:`merge_stage_coverage`.
    """

    return {
        "complete": False,
        "stages": [
            _stage_entry(
                stage=stage,
                unit=unit,
                examined=examined,
                total=total,
                reason=reason,
                statement=statement,
            )
        ],
    }


def _iter_stage_entries(block: Any) -> Iterable[Mapping[str, Any]]:
    """Yield the well-formed stage entries of a persisted block."""

    if not isinstance(block, Mapping):
        return ()
    stages = block.get("stages")
    if not isinstance(stages, (list, tuple)):
        return ()
    return tuple(
        entry
        for entry in stages
        if isinstance(entry, Mapping) and str(entry.get("stage") or "").strip()
    )


def merge_stage_coverage(existing: Any, new: Any) -> dict[str, Any]:
    """Fold a newly stopped stage into a domain's persisted block.

    One entry per stage id. When the same stage stopped twice (a re-run, a
    retried batch), the entry that examined LESS wins: the declaration must
    report the weakest coverage the result actually rests on, never the best.

    Args:
        existing: The block already recorded for the domain, or ``None``.
        new: A block from :func:`build_resource_coverage`.

    Returns:
        A new block; neither input is mutated.
    """

    by_stage: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for block in (existing, new):
        for entry in _iter_stage_entries(block):
            key = str(entry.get("stage") or "").strip().lower()
            candidate = dict(entry)
            current = by_stage.get(key)
            if current is None:
                by_stage[key] = candidate
                order.append(key)
                continue
            if (
                candidate.get(RUN_ID_KEY)
                and current.get(RUN_ID_KEY)
                and candidate.get(RUN_ID_KEY) != current.get(RUN_ID_KEY)
            ):
                # A stop of a later run describes what this result rests on now.
                by_stage[key] = candidate
                continue
            if (_non_negative_int(candidate.get("examined")) or 0) < (
                _non_negative_int(current.get("examined")) or 0
            ):
                by_stage[key] = candidate
    if not order:
        return {"complete": True, "stages": []}
    return {"complete": False, "stages": [by_stage[key] for key in order]}


def replace_stage_coverage(existing: Any, stage: Any, new: Any = None) -> dict[str, Any]:
    """Set (or clear) ONE stage's entry in a domain's block, keeping the others.

    For a stage whose declaration describes its LATEST computation rather than
    the weakest of several (attack-path discovery: a later canonical run that
    completed, or that recovered into a sampled result, replaces a provisional
    stop). :func:`merge_stage_coverage` is the rule for every other stage.

    Args:
        existing: The block already recorded for the domain, or ``None``.
        stage: The ``STAGE_*`` id to set or clear.
        new: A block from :func:`build_resource_coverage` for that stage, or
            ``None`` to remove the stage's entry.

    Returns:
        A new block; ``{"complete": True, "stages": []}`` when nothing remains.
    """

    key = str(stage or "").strip().lower()
    kept = [
        dict(entry)
        for entry in _iter_stage_entries(existing)
        if str(entry.get("stage") or "").strip().lower() != key
    ]
    added = [
        dict(entry)
        for entry in _iter_stage_entries(new)
        if str(entry.get("stage") or "").strip().lower() == key
    ][:1]
    stages = kept + added
    if not stages:
        return {"complete": True, "stages": []}
    return {"complete": False, "stages": stages}


#: Stages whose gap a surface already states through the stage's OWN block, so
#: a renderer that also prints that block leaves them out of the resource
#: coverage note and the gap reads once. Attack-path discovery declares itself
#: through ``attack_path_coverage``; its entry here carries the same sentence for
#: a machine consumer of ``technical_report.json``.
STAGES_DECLARED_ELSEWHERE: frozenset[str] = frozenset({STAGE_ATTACK_PATHS})


def _keep(entry: Mapping[str, Any], exclude_stages: Iterable[str]) -> bool:
    return str(entry.get("stage") or "").strip().lower() not in exclude_stages


def _empty_view() -> dict[str, Any]:
    return {"has_gap": False, "statement": "", "stages": []}


def resource_coverage_view(
    coverage: Any, *, exclude_stages: Iterable[str] = ()
) -> dict[str, Any]:
    """Return the render-ready view of a persisted ``resource_coverage`` block.

    The one shape the PDF report and the web platform both read.

    Returns a mapping with:
      * ``has_gap`` — whether to surface the declaration at all;
      * ``statement`` — every stopped stage's sentence, in pipeline order;
      * ``stages`` — one dict per stopped stage (``stage``, ``label``, ``unit``,
        ``examined``, ``total``, ``statement``) for a surface that lists them.

    An absent or unreadable block yields ``has_gap=False``: a scan predating this
    record must render exactly as it did, never grow a gap nobody observed.

    ``exclude_stages`` leaves out the stages the surface states through their own
    block (pass :data:`STAGES_DECLARED_ELSEWHERE`), so one gap reads once.
    """

    excluded = frozenset(str(s).strip().lower() for s in exclude_stages)
    entries = [e for e in _iter_stage_entries(coverage) if _keep(e, excluded)]
    if not entries:
        return _empty_view()
    rank = {stage: index for index, stage in enumerate(_STAGE_LABELS)}
    entries.sort(
        key=lambda e: rank.get(str(e.get("stage") or "").strip().lower(), len(rank))
    )
    stages: list[dict[str, Any]] = []
    for entry in entries:
        stage = str(entry.get("stage") or "").strip().lower()
        examined = _non_negative_int(entry.get("examined"))
        total = _non_negative_int(entry.get("total"))
        statement = str(entry.get("statement") or "").strip() or stage_statement(
            stage=stage, unit=entry.get("unit"), examined=examined, total=total
        )
        stages.append(
            {
                "stage": stage,
                "label": stage_label(stage),
                "unit": _clean_unit(entry.get("unit")),
                "examined": examined,
                "total": total,
                "statement": statement,
            }
        )
    statements: list[str] = []
    for item in stages:
        if item["statement"] not in statements:
            statements.append(item["statement"])
    return {"has_gap": True, "statement": " ".join(statements), "stages": stages}


def merge_resource_coverage(
    domain_entries: Any, *, exclude_stages: Iterable[str] = ()
) -> dict[str, Any]:
    """Fold every domain's recorded block into one report-wide view.

    ``domain_entries`` is either a mapping of domain name to per-domain data (the
    renderer's ``report_data``) or any iterable of per-domain mappings
    (``report_data.values()``). Non-mapping entries and reserved non-domain blocks
    are skipped. Stage entries keep their recorded statements. When more than one
    domain recorded a stop and the domain names are known, each statement names
    its domain, so two figures for the same stage never read as one. No record
    anywhere yields the empty view, so a report without a bounded stage renders
    unchanged.
    """

    excluded = frozenset(str(s).strip().lower() for s in exclude_stages)
    if isinstance(domain_entries, Mapping):
        pairs = [(str(name), data) for name, data in domain_entries.items()]
    else:
        pairs = [("", data) for data in (domain_entries or ())]
    per_domain: list[tuple[str, list[Mapping[str, Any]]]] = []
    for name, data in pairs:
        if not isinstance(data, Mapping):
            continue
        entries = [
            e
            for e in _iter_stage_entries(data.get(RESOURCE_COVERAGE_KEY))
            if _keep(e, excluded)
        ]
        if entries:
            per_domain.append((name, entries))
    if not per_domain:
        return _empty_view()
    name_them = len(per_domain) > 1 and all(name for name, _ in per_domain)
    stages: list[dict[str, Any]] = []
    for name, entries in per_domain:
        view = resource_coverage_view({"complete": False, "stages": entries})
        for item in view["stages"]:
            item = dict(item)
            item["domain"] = name
            if name_them:
                text = item["statement"]
                item["statement"] = f"In {name}, {text[:1].lower()}{text[1:]}"
            stages.append(item)
    statements: list[str] = []
    for item in stages:
        if item["statement"] not in statements:
            statements.append(item["statement"])
    return {"has_gap": True, "statement": " ".join(statements), "stages": stages}


# --- "This domain's graph is not available" ------------------------------------
#
# The ONE predicate every reader of a domain's graph consults before it computes
# a figure from it. A build stopped at the memory ceiling leaves no graph, and a
# directory read stopped at the ceiling leaves no inventory of this run to build
# one from. A reader that went ahead would compute over an empty (or earlier)
# graph and state "0 routes" or a clean score: a stop read as a complete result.
# What the reader does instead is declare its own stage not evaluated, naming the
# upstream stage, through :func:`not_evaluated_statement`.


def stamp_stop_run(block: Any, run_id: Any) -> Any:
    """``block`` with every stage entry naming ``run_id`` (a new block; ``block``
    is returned unchanged when ``run_id`` is empty or the block is unreadable)."""
    run = str(run_id or "").strip()
    if not run or not isinstance(block, Mapping):
        return block
    stamped = dict(block)
    stamped["stages"] = [
        {**dict(entry), RUN_ID_KEY: run} for entry in _iter_stage_entries(block)
    ]
    return stamped


def stopped_in_run(coverage: Any, stage: Any, run_id: Any) -> bool:
    """Whether ``coverage`` holds a stop of ``stage`` recorded by run ``run_id``."""
    run = str(run_id or "").strip()
    key = str(stage or "").strip().lower()
    if not run:
        return False
    return any(
        str(entry.get("stage") or "").strip().lower() == key
        and str(entry.get(RUN_ID_KEY) or "") == run
        for entry in _iter_stage_entries(coverage)
    )


def graph_unavailable_stage(coverage: Any = None, *, graph: Any = None) -> str:
    """The upstream stage that left a domain without a graph, or ``""``.

    Args:
        coverage: The domain's persisted ``resource_coverage`` block (from the
            session's ``domains_data`` or ``technical_report.json``).
        graph: The graph a reader was handed, when it has one: the empty graph a
            stopped build hands out carries :data:`GRAPH_BUILD_STOPPED_FLAG`, and
            a file another run left behind carries ``export_state.current`` false.

    Returns:
        :data:`STAGE_GRAPH_BUILD` when the build stopped (or the graph handed out
        says so; a file marked not current names the stage recorded on it),
        :data:`STAGE_COLLECTION` when the directory read stopped, else
        ``""`` (the graph is available). A host-sweep stop is not a missing graph:
        the directory was read whole and the sweep's gap is declared on its own.
    """
    if isinstance(graph, Mapping):
        if graph.get(GRAPH_BUILD_STOPPED_FLAG):
            return STAGE_GRAPH_BUILD
        state = graph.get(GRAPH_EXPORT_STATE_KEY)
        if isinstance(state, Mapping) and state.get("current") is False:
            stage = str(state.get("stage") or "").strip().lower()
            known = {STAGE_COLLECTION, STAGE_GRAPH_BUILD, STAGE_GRAPH_EXPORT}
            return stage if stage in known else STAGE_GRAPH_BUILD
    found = ""
    for entry in _iter_stage_entries(coverage):
        stage = str(entry.get("stage") or "").strip().lower()
        if stage == STAGE_GRAPH_BUILD:
            return STAGE_GRAPH_BUILD
        if stage == STAGE_COLLECTION and _clean_unit(entry.get("unit")) == DIRECTORY_READ_UNIT:
            found = STAGE_COLLECTION
    return found


#: What each downstream stage would have shown, for the not-evaluated sentence.
_STAGE_SUBJECT: dict[str, str] = {
    STAGE_ATTACK_PATHS: "attack paths",
    STAGE_WEB_LIVE_COMPUTE: "attack paths",
}


def not_evaluated_statement(stage: Any, upstream: Any) -> str:
    """The client sentence for a stage that did not run because ``upstream`` stopped.

    Names the boundary, never the cause, and never reads as a result: "0 routes"
    is a measurement, this is the absence of one.

    Args:
        stage: The ``STAGE_*`` id that did not run (``attack_paths``).
        upstream: The ``STAGE_*`` id whose stop left it without input.
    """
    label = stage_label(stage)
    before = stage_label(upstream)
    before = before[:1].lower() + before[1:]
    subject = _STAGE_SUBJECT.get(str(stage or "").strip().lower(), "further exposure")
    return (
        f"{label} did not run, because {before} stopped before it finished. "
        f"This assessment therefore does not show whether the domain holds {subject}."
    )


__all__ = [
    "DIRECTORY_READ_UNIT",
    "RUN_ID_KEY",
    "stamp_stop_run",
    "stopped_in_run",
    "GRAPH_BUILD_STOPPED_FLAG",
    "GRAPH_EXPORT_STATE_KEY",
    "graph_unavailable_stage",
    "not_evaluated_statement",
    "REASON_LISTING_INCOMPLETE",
    "REASON_LISTING_LIMIT",
    "REASON_MEMORY",
    "RESOURCE_COVERAGE_KEY",
    "STAGE_ATTACK_PATHS",
    "STAGE_CHOKEPOINT_ANALYSIS",
    "STAGE_MSSQL_FILE_REVIEW",
    "STAGE_MSSQL_POST_AUTH",
    "STAGE_SHARE_FILE_LISTING",
    "STAGE_SHARE_MAPPING",
    "STAGE_COLLECTION",
    "STAGE_GRAPH_BUILD",
    "STAGE_GRAPH_EXPORT",
    "STAGE_REPORT",
    "STAGE_WINRM_FILE_REVIEW",
    "STAGE_WINRM_POST_AUTH",
    "STAGE_UNKNOWN",
    "STAGE_WEB_INGESTION",
    "STAGE_WEB_LIVE_COMPUTE",
    "STAGES_DECLARED_ELSEWHERE",
    "build_resource_coverage",
    "merge_resource_coverage",
    "merge_stage_coverage",
    "replace_stage_coverage",
    "resource_coverage_view",
    "stage_label",
    "stage_statement",
]
