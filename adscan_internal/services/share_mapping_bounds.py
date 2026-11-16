"""The file review of network shares, kept within memory and declared when short.

Mapping a share means listing its whole tree. On a real file server that is
millions of files, and a mapping that holds every listed file grows with the
estate until the process is killed. The bound here never comes from walking
fewer directories (a path allowlist misses credential files in bespoke
locations): the whole tree of every share is still listed, and three things
keep the memory flat.

* **Only candidate files are kept.** A listing is consumed one entry at a time
  (:class:`ShareListingCollector`) and an entry is kept only when the later
  phases could read it: its file type, or its file name, says so
  (:func:`is_share_mapping_candidate`). The decision looks at the file's name
  alone, never at the folder it sits in.
* **A bound on the candidates kept per share**, applied after that selection, so
  it only bites on a share with an abnormal number of candidate files. Direct
  secret artifacts and virtual-machine images are counted apart from the bulk
  types, so a share full of text files cannot crowd them out.
* **The AI review keeps every file name instead**, because its point is the
  oddly named file no type list would select. Its bound is a total count of
  names per run (:class:`ReviewNameBudget`); past it the candidate selection
  above takes over, and the shares listed after it are a declared gap.
* **The mapping runs as a memory-bounded stage** (:func:`run_share_mapping_bounded`,
  shares as the unit): past the stage line it stops, keeps what it mapped and
  declares the shares it did not reach.

A share whose listing was cut short (the bound, its time budget, an error
part-way) is a declared coverage gap through the one resource-coverage SSOT
(:mod:`adscan_core.reporting.resource_coverage`, stage ``share_file_listing``).
The state of every share's last listing is kept in the workspace
(``share_listing_state.json``), so a later listing that completes clears that
share's gap and no other share's.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Iterable
from functools import lru_cache
from pathlib import Path
from typing import Any

from adscan_core import telemetry
from adscan_core.memory_guard import OUTCOME_STOPPED, memory_bounded
from adscan_core.reporting.resource_coverage import (
    REASON_LISTING_INCOMPLETE,
    REASON_LISTING_LIMIT,
    STAGE_SHARE_FILE_LISTING,
    STAGE_SHARE_MAPPING,
    build_resource_coverage,
)
from adscan_core.rich_output import print_exception, print_warning
from adscan_internal.services.smb_exclusion_policy import (
    is_globally_excluded_smb_relative_path,
)
from adscan_internal.services.smb_sensitive_file_policy import (
    DIRECT_SECRET_ARTIFACT_EXTENSIONS,
    SMB_SENSITIVE_SCAN_PHASES,
    get_sensitive_phase_extensions,
    resolve_effective_sensitive_extension,
)

#: Candidate files kept per share, per class (bulk types, priority types). The
#: same figure the native share walk uses for one host.
MAX_CANDIDATE_FILES_PER_SHARE = 20_000

#: File names kept for one AI review run, across all its shares. The AI review
#: triages every file name, not only the candidate types, so its bound is a
#: total count: the same figure as the file review on a database server.
MAX_AI_REVIEW_FILE_NAMES_PER_RUN = 50_000

#: What the stage and the coverage statement count.
SHARE_MAPPING_UNIT = "shares"

#: The record of how each share's last listing ended, in the domain's SMB folder.
LISTING_STATE_FILENAME = "share_listing_state.json"

#: Root marker of an aggregate map that holds candidate files only.
RETENTION_KEY = "retention"
RETENTION_CANDIDATE_FILES = "candidate_files"
#: Root marker of a map written for the AI review: every file name, up to the
#: run's total, then candidate files.
RETENTION_ALL_FILE_NAMES = "all_file_names"

#: A listing ended only because the account could not read some folders. That
#: is the reach of the account, not a listing cut short: it is counted for the
#: operator and never declared as a coverage gap.
REASON_ACCESS_DENIED = "access_denied"

#: How many listed entries pass between two looks at the memory line.
MEMORY_CHECK_EVERY_ENTRIES = 5_000

#: File names that mark a secret whatever the extension (or without one).
#: Matched against the file's own name, never against its folder.
SENSITIVE_NAME_TOKENS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "credential",
    "unattend",
    "sysprep",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    ".ppk",
)

_ACCESS_DENIED_TOKENS: tuple[str, ...] = (
    "access denied",
    "access is denied",
    "permission denied",
    "status_access_denied",
)


@lru_cache(maxsize=1)
def candidate_extensions() -> frozenset[str]:
    """Every extension a sensitive-data phase reads, lower case with the dot."""
    extensions: set[str] = set()
    for phase in SMB_SENSITIVE_SCAN_PHASES:
        extensions.update(
            str(extension).strip().casefold()
            for extension in get_sensitive_phase_extensions(phase)
            if str(extension).strip()
        )
    return frozenset(extensions)


def _file_name(relative_path: str) -> str:
    # String operations on purpose: ``pathlib`` interns every path part it
    # parses, and this runs once per listed file.
    return str(relative_path or "").replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].casefold()


def _is_vm_artifact(relative_path: str) -> bool:
    from adscan_internal.services.vm_artifact_service import (  # noqa: PLC0415
        classify_vm_artifact,
    )

    return classify_vm_artifact(relative_path) in ("disk", "memory")


def is_priority_candidate(relative_path: str) -> bool:
    """Whether a file is a direct secret artifact, a VM image or secret-named.

    These are few on any share and worth the most, so they are counted apart
    from the bulk file types and a share full of text files cannot push them
    past the bound.
    """
    path = str(relative_path or "").strip()
    if not path:
        return False
    if _is_vm_artifact(path):
        return True
    name = _file_name(path)
    if any(token in name for token in SENSITIVE_NAME_TOKENS):
        return True
    return (
        resolve_effective_sensitive_extension(
            path, allowed_extensions=DIRECT_SECRET_ARTIFACT_EXTENSIONS
        )
        in DIRECT_SECRET_ARTIFACT_EXTENSIONS
    )


def is_share_mapping_candidate(relative_path: str) -> bool:
    """Whether the mapping keeps this file: could a later phase read it?

    The decision is made on the file's own name (its type, with backup suffixes
    such as ``.bak`` looked through, or a secret-like name). The folder is never
    consulted, so a file in a bespoke location is kept exactly like one in a
    well-known place. A virtual-machine image is kept wherever the listing
    reports it, as before.
    """
    path = str(relative_path or "").strip()
    if not path:
        return False
    if _is_vm_artifact(path):
        return True
    if is_globally_excluded_smb_relative_path(path):
        return False
    extensions = candidate_extensions()
    if resolve_effective_sensitive_extension(path, allowed_extensions=extensions) in extensions:
        return True
    name = _file_name(path)
    return any(token in name for token in SENSITIVE_NAME_TOKENS)


class ReviewNameBudget:
    """How many more file names an AI review run may keep, across its shares."""

    def __init__(self, total: int | None = None) -> None:
        self.remaining = max(
            0, int(MAX_AI_REVIEW_FILE_NAMES_PER_RUN if total is None else total)
        )

    def take(self) -> bool:
        """Spend one name; False once the run's total is used up."""
        if self.remaining <= 0:
            return False
        self.remaining -= 1
        return True


class ShareListingCollector:
    """Consume one share's listing an entry at a time, keeping candidates only.

    Memory is bounded by the candidates kept, never by the size of the share:
    a listing of ten million files holds at most twice
    ``max_candidates`` entries.

    With ``name_budget`` (the AI review, which triages every file name and not
    only the candidate types) every file is kept while the run's total lasts.
    Past it the collector goes on exactly as without a budget, so an AI review
    never keeps less than the static one, and a file left out for the total
    makes the share a declared gap.

    Use: ``if collector.admit(path): collector.files[path] = metadata``.
    """

    def __init__(
        self,
        max_candidates: int | None = None,
        *,
        name_budget: ReviewNameBudget | None = None,
    ) -> None:
        self.name_budget = name_budget
        self.names_dropped = 0
        self.max_candidates = max(
            1, int(MAX_CANDIDATE_FILES_PER_SHARE if max_candidates is None else max_candidates)
        )
        self.files: dict[str, dict[str, str]] = {}
        self.entries_listed = 0
        self.candidates_seen = 0
        self.candidates_dropped = 0
        self._bulk_kept = 0
        self._priority_kept = 0

    def admit(self, relative_path: str) -> bool:
        """Count one listed file and say whether the caller should keep it."""
        self.entries_listed += 1
        if relative_path in self.files:
            return True
        if self.name_budget is not None and self.name_budget.take():
            return True
        if not is_share_mapping_candidate(relative_path):
            if self.name_budget is not None:
                self.names_dropped += 1
            return False
        self.candidates_seen += 1
        if is_priority_candidate(relative_path):
            if self._priority_kept < self.max_candidates:
                self._priority_kept += 1
                return True
        elif self._bulk_kept < self.max_candidates:
            self._bulk_kept += 1
            return True
        self.candidates_dropped += 1
        return False

    @property
    def capped(self) -> bool:
        """Whether a file the review would read was left out because of a bound."""
        return self.candidates_dropped > 0 or self.names_dropped > 0

    def outcome(self, *, interrupted_reason: str | None = None) -> dict[str, Any]:
        """How this share's listing ended, for the state file and the summary.

        Args:
            interrupted_reason: Why the listing itself did not run to the end
                (:data:`REASON_LISTING_INCOMPLETE`, :data:`REASON_MEMORY`,
                :data:`REASON_ACCESS_DENIED`), or ``None`` when the whole tree
                was listed.
        """
        reason = interrupted_reason or (REASON_LISTING_LIMIT if self.capped else None)
        return {
            "complete": reason is None,
            "reason": reason,
            "entries_listed": self.entries_listed,
            "candidates_kept": len(self.files),
            "candidates_dropped": self.candidates_dropped,
            **({"names_dropped": self.names_dropped} if self.name_budget is not None else {}),
        }


def stderr_is_access_denied_only(stderr_text: str) -> bool:
    """Whether every error a listing reported is a folder the account cannot read."""
    lines = [
        line.strip().casefold()
        for line in str(stderr_text or "").splitlines()
        if line.strip()
    ]

    def _denied(line: str) -> bool:
        return any(token in line for token in _ACCESS_DENIED_TOKENS)

    if not any(_denied(line) for line in lines):
        return False
    return not any(
        ("error" in line or "failed" in line) and not _denied(line) for line in lines
    )


def outcome_is_declared_gap(outcome: Any) -> bool:
    """Whether a share's outcome is a coverage gap the report states."""
    if not isinstance(outcome, dict) or outcome.get("complete") is not False:
        return False
    return str(outcome.get("reason") or "") != REASON_ACCESS_DENIED


def share_listing_statement(incomplete: int, total: int) -> str:
    """The client sentence for shares whose file review is partial."""
    whole = max(int(total), int(incomplete))
    noun = "network share" if whole == 1 else "network shares"
    where = "that share" if incomplete == 1 else "those shares"
    return (
        f"The file review covered {incomplete:,} of {whole:,} {noun} only in part. "
        f"{whole - incomplete:,} of {whole:,} {noun} were listed in full. "
        f"The files left out on {where} were not evaluated, so this assessment "
        "does not show whether they hold further exposure."
    )


def _read_state(state_path: Path) -> dict[str, dict[str, dict[str, Any]]]:
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    hosts = data.get("hosts") if isinstance(data, dict) else None
    if not isinstance(hosts, dict):
        return {}
    return {
        str(host): {
            str(share): dict(outcome)
            for share, outcome in shares.items()
            if isinstance(outcome, dict)
        }
        for host, shares in hosts.items()
        if isinstance(shares, dict)
    }


def share_listing_coverage_block(
    state: dict[str, dict[str, dict[str, Any]]],
) -> dict[str, Any] | None:
    """The ``resource_coverage`` block for a domain's partial share listings.

    Returns:
        ``None`` when no share's listing is a declared gap. Otherwise the block
        for stage ``share_file_listing``: ``examined`` counts the shares listed
        whole, ``total`` every share listed (the statement states both counts), and the reason is the bound when
        every gap is the bound, the incomplete listing otherwise.
    """
    outcomes = [outcome for shares in state.values() for outcome in shares.values()]
    gaps = [outcome for outcome in outcomes if outcome_is_declared_gap(outcome)]
    if not gaps:
        return None
    reasons = {str(outcome.get("reason") or "") for outcome in gaps}
    reason = REASON_LISTING_LIMIT if reasons == {REASON_LISTING_LIMIT} else REASON_LISTING_INCOMPLETE
    return build_resource_coverage(
        stage=STAGE_SHARE_FILE_LISTING,
        unit=SHARE_MAPPING_UNIT,
        examined=len(outcomes) - len(gaps),
        total=len(outcomes),
        reason=reason,
        statement=share_listing_statement(len(gaps), len(outcomes)),
    )


def record_share_listing_outcomes(
    shell: Any,
    *,
    domain: str,
    state_dir: str | os.PathLike[str] | None,
    outcomes: dict[str, dict[str, dict[str, Any]]] | None,
) -> dict[str, Any] | None:
    """Record how each listed share ended and refresh the domain's declared gap.

    Each share listed in this run replaces its earlier record, so a share that
    now lists whole clears its own gap. Never raises.

    Args:
        shell: The session.
        domain: The domain the shares belong to.
        state_dir: The domain's SMB folder in the workspace.
        outcomes: ``{host: {share: outcome}}`` from the mapping run.

    Returns:
        The coverage block now declared for the domain, or ``None``.
    """
    try:
        state: dict[str, dict[str, dict[str, Any]]] = {}
        state_path = Path(state_dir) / LISTING_STATE_FILENAME if state_dir else None
        if state_path is not None:
            state = _read_state(state_path)
        for host, shares in (outcomes or {}).items():
            if not isinstance(shares, dict):
                continue
            bucket = state.setdefault(str(host), {})
            for share, outcome in shares.items():
                if isinstance(outcome, dict):
                    bucket[str(share)] = dict(outcome)
        if state_path is not None and (state or state_path.exists()):
            state_path.parent.mkdir(parents=True, exist_ok=True)
            state_path.write_text(json.dumps({"hosts": state}, indent=2), encoding="utf-8")
        from adscan_internal.services.resource_coverage_recorder import (  # noqa: PLC0415
            clear_stage_coverage,
            record_stage_coverage,
        )

        coverage = share_listing_coverage_block(state)
        if coverage is None:
            clear_stage_coverage(shell, domain, STAGE_SHARE_FILE_LISTING)
        else:
            record_stage_coverage(
                shell, domain, coverage, replace_stage=STAGE_SHARE_FILE_LISTING
            )
        return coverage
    except Exception as exc:  # noqa: BLE001 - declaring a gap never breaks the review
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


def announce_partial_shares(outcomes: dict[str, dict[str, dict[str, Any]]] | None) -> int:
    """Tell the operator how many shares were reviewed only in part; return it."""
    partial = [
        outcome
        for shares in (outcomes or {}).values()
        if isinstance(shares, dict)
        for outcome in shares.values()
        if outcome_is_declared_gap(outcome)
    ]
    if not partial:
        return 0
    at_limit = [o for o in partial if o.get("reason") == REASON_LISTING_LIMIT]
    past_total = sum(1 for o in at_limit if o.get("names_dropped"))
    capped = len(at_limit) - past_total
    cut_short = len(partial) - len(at_limit)
    parts: list[str] = []
    if past_total:
        parts.append(
            f"{past_total:,} came after the AI review's total of "
            f"{MAX_AI_REVIEW_FILE_NAMES_PER_RUN:,} file names (candidate files "
            "were still kept there)"
        )
    if capped:
        parts.append(
            f"{capped:,} held more candidate files than the limit of "
            f"{MAX_CANDIDATE_FILES_PER_SHARE:,} per share"
        )
    if cut_short:
        parts.append(f"{cut_short:,} did not finish listing")
    print_warning(
        f"The file listing of {len(partial):,} "
        f"{'share is' if len(partial) == 1 else 'shares are'} partial: "
        f"{' and '.join(parts)}. The review continues on the files kept, and the "
        "report states this as a coverage gap."
    )
    return len(partial)


def iter_listing_lines(spool_path: str | os.PathLike[str] | None, fallback_text: str = "") -> Iterable[str]:
    """Yield a listing's lines from its spool file, else from captured text.

    The spool file is read line by line, so a listing of any size costs one
    line of memory. ``fallback_text`` serves an executor that returned the
    listing instead of writing it (it does not run the command through a shell).
    """
    spooled = False
    if spool_path:
        try:
            with open(spool_path, encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    spooled = True
                    yield line
        except OSError:
            spooled = False
    if not spooled and fallback_text:
        yield from fallback_text.splitlines()


def run_share_mapping_bounded(
    shell: Any,
    domain: str,
    *,
    total: int | None,
    generate: Callable[[Any], dict[str, Any]],
    merge: Callable[[], dict[str, Any]],
    state_dir: str | os.PathLike[str] | None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, bool]:
    """Run a share mapping and its merge as one memory-bounded stage.

    ``generate`` lists the shares and is handed the stage: it asks
    ``stage.over_line()`` between shares (and while it reads a long listing),
    stops listing when memory crossed the line, and reports
    ``memory_stopped`` with ``shares_done``. What it mapped is then merged and
    the stage is stopped at its boundary, which declares the shares not reached.

    Args:
        shell: The session.
        domain: The domain the shares belong to.
        total: How many shares the mapping has in front of it, when known.
        generate: ``generate(stage) -> mapping result`` (with ``share_outcomes``).
        merge: Folds the run into the domain's map and returns its summary.
        state_dir: The domain's SMB folder (the share listing state lives there).

    Returns:
        ``(mapping_result, merge_summary, stopped)``. Either dict is ``None``
        when the stage stopped before that step finished.
    """
    from adscan_internal.services.resource_coverage_recorder import (  # noqa: PLC0415
        clear_stage_coverage,
        record_stage_coverage,
    )

    held: dict[str, Any] = {}

    # The stop is declared in the report and the platform. It is not marked on a
    # scan phase yet: the share review sits under no assessment-integrity phase,
    # so ``adscan ci`` does not exit 3 on it (BACKLOG, "R35 class: exit 3 on a
    # hunting-stage memory stop", the same rule as the database-server review).
    def _record(block: dict[str, Any]) -> None:
        record_stage_coverage(shell, domain, block)

    def _body(stage: Any) -> None:
        mapping = generate(stage)
        held["mapping"] = mapping
        held["summary"] = merge()
        if isinstance(mapping, dict) and mapping.get("memory_stopped"):
            stage.progress(int(mapping.get("shares_done") or 0))
            stage.guard.stop_now()

    with memory_bounded(
        STAGE_SHARE_MAPPING,
        unit=SHARE_MAPPING_UNIT,
        total=total,
        record=_record,
    ) as stage:
        _body(stage)
    stopped = stage.outcome == OUTCOME_STOPPED
    mapping = held.get("mapping")
    try:
        if isinstance(mapping, dict):
            record_share_listing_outcomes(
                shell,
                domain=domain,
                state_dir=state_dir,
                outcomes=mapping.get("share_outcomes"),
            )
            announce_partial_shares(mapping.get("share_outcomes"))
        if not stopped:
            clear_stage_coverage(shell, domain, STAGE_SHARE_MAPPING)
    except Exception as exc:  # noqa: BLE001 - declaring never breaks the review
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    return mapping, held.get("summary"), stopped


__all__ = (
    "LISTING_STATE_FILENAME",
    "MAX_AI_REVIEW_FILE_NAMES_PER_RUN",
    "MAX_CANDIDATE_FILES_PER_SHARE",
    "MEMORY_CHECK_EVERY_ENTRIES",
    "REASON_ACCESS_DENIED",
    "RETENTION_ALL_FILE_NAMES",
    "RETENTION_CANDIDATE_FILES",
    "RETENTION_KEY",
    "ReviewNameBudget",
    "SENSITIVE_NAME_TOKENS",
    "SHARE_MAPPING_UNIT",
    "ShareListingCollector",
    "announce_partial_shares",
    "candidate_extensions",
    "is_priority_candidate",
    "is_share_mapping_candidate",
    "iter_listing_lines",
    "outcome_is_declared_gap",
    "record_share_listing_outcomes",
    "run_share_mapping_bounded",
    "share_listing_coverage_block",
    "share_listing_statement",
    "stderr_is_access_denied_only",
)
