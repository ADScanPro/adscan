"""The file review of a host, kept within memory and declared when cut short.

Shared by every transport that reviews the files of a remote Windows host
through bounded listings (a database server through ``xp_cmdshell``, a host
over Windows Remote Management). Two things can leave such a review shorter
than the host:

* **The file listing reached its bound.** The listing is read in bounded replies
  (``WindowsFileMappingService.generate_bounded_file_map``) and stops at a total.
  What it did not list is a coverage gap, stated in the report and the platform
  through the one resource-coverage SSOT
  (:mod:`adscan_core.reporting.resource_coverage`, the profile's file-review
  stage), never a shorter listing that reads as the whole host.
* **The work ran out of memory.** The post-authentication work runs under
  :func:`adscan_core.memory_guard.memory_bounded` (the profile's post-auth
  stage): it stops at the stage line with its own declared gap instead of
  growing until the process is killed.

The state of each host's listing is kept next to its manifest
(``listing_state.json``), so the domain's declaration is always derived from
what the workspace holds: a later listing that completes clears that host's gap
and no other host's.

A transport is one :class:`ReviewCoverageProfile`. A new transport adds a
profile (two stage ids in ``resource_coverage`` and where its states live); it
never copies this module.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from adscan_core import telemetry
from adscan_core.memory_guard import OUTCOME_STOPPED, memory_bounded
from adscan_core.reporting.resource_coverage import (
    REASON_LISTING_LIMIT,
    STAGE_MSSQL_FILE_REVIEW,
    STAGE_MSSQL_POST_AUTH,
    STAGE_WINRM_FILE_REVIEW,
    STAGE_WINRM_POST_AUTH,
    build_resource_coverage,
    stage_statement,
)
from adscan_core.rich_output import print_exception, print_warning
from adscan_internal.rich_output import mark_sensitive

#: What the file review counts, for the coverage statement.
FILE_REVIEW_UNIT = "files"
#: What the post-authentication work counts.
POST_AUTH_UNIT = "steps"
#: The per-host record of how its listing ended, beside ``file_tree_map.json``.
LISTING_STATE_FILENAME = "listing_state.json"
#: The hosts of a domain whose post-authentication work stopped for memory.
POST_AUTH_STOPS_FILENAME = "post_auth_stops.json"


@dataclass(frozen=True, slots=True)
class ReviewCoverageProfile:
    """How one transport declares the gaps of its file review.

    Attributes:
        file_review_stage: Stage id of a listing that stopped at its bound.
        post_auth_stage: Stage id of the memory-bounded work after sign-in.
        hosts_plural: What the reviewed hosts are called in the client sentence
            that counts several of them (``"database servers"``).
        states_root_depth: How many directories above a manifest the folder
            that holds every host's manifest folder sits.
        states_glob: Glob, under that folder, of every host's listing state.
    """

    file_review_stage: str
    post_auth_stage: str
    hosts_plural: str
    states_root_depth: int
    states_glob: str

    def states_root(self, manifest_path: str | Path) -> Path:
        """The folder that holds every host's listing state for one domain."""
        root = Path(manifest_path)
        for _ in range(self.states_root_depth):
            root = root.parent
        return root


#: ``<domain>/mssql/sensitive/<host key>/file_tree_map.json``.
MSSQL_REVIEW = ReviewCoverageProfile(
    file_review_stage=STAGE_MSSQL_FILE_REVIEW,
    post_auth_stage=STAGE_MSSQL_POST_AUTH,
    hosts_plural="database servers",
    states_root_depth=2,
    states_glob=f"*/{LISTING_STATE_FILENAME}",
)

#: ``<domain>/winrm/sensitive/cache/<host key>/mapping/file_tree_map.json``.
WINRM_REVIEW = ReviewCoverageProfile(
    file_review_stage=STAGE_WINRM_FILE_REVIEW,
    post_auth_stage=STAGE_WINRM_POST_AUTH,
    hosts_plural="hosts",
    states_root_depth=3,
    states_glob=f"*/mapping/{LISTING_STATE_FILENAME}",
)


def read_listing_states(
    profile: ReviewCoverageProfile, states_root: Path
) -> list[dict[str, Any]]:
    """Every host's listing state under one domain's review folder."""
    states: list[dict[str, Any]] = []
    for path in sorted(states_root.glob(profile.states_glob)):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            states.append(data)
    return states


def file_review_coverage_block(
    profile: ReviewCoverageProfile, states: list[dict[str, Any]]
) -> dict[str, Any] | None:
    """The ``resource_coverage`` block for a domain's incomplete listings.

    Args:
        profile: The transport.
        states: The listing states of the domain's hosts.

    Returns:
        ``None`` when every listing completed. Otherwise the block for the
        profile's file-review stage: ``examined`` is the shortest listing (the
        weakest coverage the result rests on), and the statement says how many
        hosts stopped early when more than one did.
    """
    incomplete = [
        state
        for state in states
        if isinstance(state.get("listing"), dict)
        and state["listing"].get("complete") is False
    ]
    if not incomplete:
        return None
    examined = min(
        int(state["listing"].get("entries_listed") or 0) for state in incomplete
    )
    statement = None
    if len(incomplete) > 1:
        statement = (
            f"The file review stopped early on {len(incomplete):,} {profile.hosts_plural}, "
            f"the earliest after {examined:,} {FILE_REVIEW_UNIT}. Anything beyond those "
            "points was not evaluated, so this assessment does not show whether it "
            "holds further exposure."
        )
    return build_resource_coverage(
        stage=profile.file_review_stage,
        unit=FILE_REVIEW_UNIT,
        examined=examined,
        reason=REASON_LISTING_LIMIT,
        statement=statement,
    )


def record_listing_state(
    profile: ReviewCoverageProfile,
    shell: Any,
    *,
    domain: str,
    host: str,
    manifest_path: str,
    listing: Any,
) -> bool:
    """Record how one host's file listing ended and refresh the domain's gap.

    Writes the state beside the manifest, then sets or clears the domain's
    file-review entry from every host's state. An incomplete listing is also
    told to the operator on the terminal. Never raises.

    Args:
        profile: The transport.
        shell: The session.
        domain: The domain the host belongs to.
        host: The host.
        manifest_path: The host's ``file_tree_map.json``.
        listing: The manifest's ``listing`` block; anything else (a manifest
            written before bounded listings) counts as complete.

    Returns:
        True when the listing was complete.
    """
    block = dict(listing) if isinstance(listing, dict) else {}
    complete = block.get("complete") is not False
    try:
        manifest = Path(manifest_path)
        state_path = manifest.with_name(LISTING_STATE_FILENAME)
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(
            json.dumps({"host": host, "listing": block}, indent=2), encoding="utf-8"
        )
        from adscan_internal.services.resource_coverage_recorder import (  # noqa: PLC0415
            clear_stage_coverage,
            record_stage_coverage,
        )

        coverage = file_review_coverage_block(
            profile, read_listing_states(profile, profile.states_root(manifest))
        )
        if coverage is None:
            clear_stage_coverage(shell, domain, profile.file_review_stage)
        else:
            record_stage_coverage(
                shell, domain, coverage, replace_stage=profile.file_review_stage
            )
    except Exception as exc:  # noqa: BLE001 - declaring a gap never breaks the review
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    if not complete:
        listed = int(block.get("entries_listed") or 0)
        unlisted = int(block.get("unlisted_directory_count") or 0)
        print_warning(
            f"The file listing on {mark_sensitive(host, 'hostname')} stopped at its "
            f"limit after {listed:,} files; {unlisted:,} "
            f"{'directory was' if unlisted == 1 else 'directories were'} not listed in "
            "full. The review continues on the files listed, and the report states "
            "this as a coverage gap."
        )
    return complete


def listing_gap_statement(profile: ReviewCoverageProfile, listing: Any) -> str:
    """The client sentence for one host's incomplete listing (for a result dict)."""
    block = listing if isinstance(listing, dict) else {}
    return stage_statement(
        stage=profile.file_review_stage,
        unit=FILE_REVIEW_UNIT,
        examined=int(block.get("entries_listed") or 0),
    )


def _stopped_hosts(state_path: Path) -> list[str]:
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    hosts = data.get("hosts") if isinstance(data, dict) else None
    return [str(host) for host in hosts] if isinstance(hosts, list) else []


def _set_host_stopped(state_dir: str | Path | None, host: str, stopped: bool) -> bool:
    """Record whether ``host``'s work stopped; return whether any host still is.

    Without a ``state_dir`` (no workspace) the answer is this host's alone.
    """
    if not state_dir:
        return stopped
    state_path = Path(state_dir) / POST_AUTH_STOPS_FILENAME
    hosts = [name for name in _stopped_hosts(state_path) if name != host]
    if stopped:
        hosts.append(host)
    try:
        if hosts or state_path.exists():
            state_path.parent.mkdir(parents=True, exist_ok=True)
            state_path.write_text(
                json.dumps({"hosts": hosts}, indent=2), encoding="utf-8"
            )
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    return bool(hosts)


def run_post_auth_bounded(
    profile: ReviewCoverageProfile,
    shell: Any,
    domain: str,
    host: str,
    run: Callable[[], Any],
    *,
    state_dir: str | Path | None = None,
    clears_stop: Callable[[Any], bool] | None = None,
) -> tuple[bool, Any]:
    """Run ``run`` (the work after sign-in, one call) under its memory boundary.

    Args:
        profile: The transport.
        shell: The session.
        domain: The domain the host belongs to.
        host: The host.
        run: Runs the work and returns its result.
        state_dir: The domain's folder for this transport in the workspace,
            where the hosts whose work stopped are remembered, so a host that
            completes later clears its own stop and no other host's.
        clears_stop: Says, from the result, whether this run stands for the
            host's work (default: any run that did not stop). A run that was
            skipped or failed leaves an earlier stop of this host in place.

    Returns:
        ``(stopped, result)``: ``stopped`` is True when the work reached the
        memory line (recorded and declared); ``result`` is then ``None``.
    """
    from adscan_internal.services.resource_coverage_recorder import (  # noqa: PLC0415
        clear_stage_coverage,
        record_stage_coverage,
    )

    def _record(block: dict[str, Any]) -> None:
        # Not yet marked on a scan phase, so ``adscan ci`` does not exit 3 for
        # this stop (15.0.1): the work runs under whichever phase launched it,
        # and the exit status reads only the integrity phase ids
        # (``scan_progress.ASSESSMENT_INTEGRITY_PHASE_IDS``). It needs an id of
        # its own there and in ``coverage.json``; the access sweep's phase
        # would misstate what stopped.
        _set_host_stopped(state_dir, host, True)
        record_stage_coverage(shell, domain, block)

    with memory_bounded(
        profile.post_auth_stage, unit=POST_AUTH_UNIT, record=_record
    ) as stage:
        result = run()
    if stage.outcome == OUTCOME_STOPPED:
        return True, None
    try:
        if clears_stop is not None and not clears_stop(result):
            return False, result
        if not _set_host_stopped(state_dir, host, False):
            clear_stage_coverage(shell, domain, profile.post_auth_stage)
    except Exception as exc:  # noqa: BLE001 - clearing a stop never breaks the work
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    return False, result


__all__ = (
    "FILE_REVIEW_UNIT",
    "LISTING_STATE_FILENAME",
    "MSSQL_REVIEW",
    "POST_AUTH_STOPS_FILENAME",
    "POST_AUTH_UNIT",
    "ReviewCoverageProfile",
    "WINRM_REVIEW",
    "file_review_coverage_block",
    "listing_gap_statement",
    "read_listing_states",
    "record_listing_state",
    "run_post_auth_bounded",
)
