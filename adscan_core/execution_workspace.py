"""Execution workspaces (``.run_<logical>_<scanid>``): naming, discovery, removal.

A scan has two workspace identities (CLAUDE.md, "Logical workspace vs live-scan
execution workspace"). The LOGICAL workspace is the stable, customer-facing,
database-keyed name. The EXECUTION workspace is a hidden ``.run_<logical>_<scanid>``
directory, a SIBLING of the logical one, that a single run writes its artifacts
into; at the end of the run they are promoted into the logical workspace.

WHY THIS MODULE EXISTS
----------------------
Because it is a sibling rather than a child, an execution workspace is invisible
to everything that reasons about "the workspace directory", and it holds a full
copy of the engagement: the reports, the technical report, the change ledger, the
logs, the enabled-user and enabled-computer lists, and any certificate with its
private key. Deleting a workspace is the whole end-of-engagement procedure, so
every one of its execution workspaces has to go with it, and its lock file under
``run/locks`` has to go too because that file name carries the logical name.

Three different processes need the same answers and none of them may import each
other, which is why this lives in ``adscan_core``: the container runtime (the
residue purge on ``workspace delete``), the host launcher (housekeeping), and the
web backend (its own delete endpoint, and the execution -> logical resolution the
frontend needs mid-scan).

THE BOUNDARY RULE, WHICH IS THE DANGEROUS PART
----------------------------------------------
"Is this execution workspace MINE?" must be answered on the convention's exact
boundary, never with a prefix test. A logical name can be a prefix of another
one, and on a real machine it is: with logical workspaces ``Essos`` and
``Essos-Demo`` side by side, ``name.startswith(".run_Essos")`` makes deleting
``Essos`` destroy five of ``Essos-Demo``'s runs. So :func:`execution_workspace_belongs_to`
rebuilds the candidate name from the FORWARD convention and compares the whole
string. That is exact for the truncation and the trailing-separator strip the
inverse cannot recover, and it cannot match across a name boundary.

LIVENESS
--------
A running scan's execution workspace must never be removed from under the engine,
so removal is gated on :func:`execution_workspace_is_quiescent` and a directory
that fails the gate is reported to the caller instead of deleted. Note that
``prepare_workspace`` creates a ``.run_*`` without requiring the logical
directory to exist, so "its logical workspace is missing" is NOT on its own
evidence that a directory is finished with.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

#: Prefix the runner gives every execution workspace. Mirrors
#: ``adscan_runner.workspace.execution_workspace_name``.
EXECUTION_WORKSPACE_PREFIX = ".run_"

#: The scan-id suffix is ``str(scan_id).replace("-", "")[:12]`` — up to 12 chars
#: of a hex UUID. Only a trailing ``_<segment>`` that looks like one is treated
#: as a scan id, so a logical name whose own last segment is not a scan id (for
#: example ``Lab_Demo``) is never truncated by accident.
_SCAN_ID_SUFFIX_RE = re.compile(r"^[0-9a-fA-F]{1,12}$")

#: How long a directory must have been untouched before it is treated as
#: finished with, when no lock answers the question. A running scan writes log
#: lines continuously, so any real gap is far shorter than this; the window is
#: deliberately generous because keeping a finished directory one sweep longer
#: costs nothing, while removing a live one destroys an engagement mid-run.
EXECUTION_WORKSPACE_QUIET_SECONDS = 1800


def execution_workspace_name(logical_workspace: str, scan_id: str) -> str:
    """Return the execution workspace name for one scan run.

    MIRROR of ``adscan_runner.workspace.execution_workspace_name``, which is the
    source of truth and is deliberately stdlib-only and never imports this
    package. The two are drift-locked by a round-trip test that AST-extracts the
    runner's function from its real source and compares behaviour, so they
    cannot diverge silently.
    """
    suffix = str(scan_id).replace("-", "")[:12]
    prefix_budget = max(16, 96 - len(suffix))
    trimmed = logical_workspace[:prefix_budget].rstrip("_-")
    return f"{EXECUTION_WORKSPACE_PREFIX}{trimmed}_{suffix}"


def _split_execution_name(name: str) -> tuple[str, str] | None:
    """Split an execution workspace name into ``(head, scan_id_suffix)``.

    ``None`` when the name is not one we built: no prefix, no trailing segment,
    or a trailing segment that does not look like a scan id.
    """
    if not name or not name.startswith(EXECUTION_WORKSPACE_PREFIX):
        return None
    body = name[len(EXECUTION_WORKSPACE_PREFIX):]
    # ``rpartition`` keeps interior underscores in the logical name intact.
    head, sep, tail = body.rpartition("_")
    if not sep or not head or not _SCAN_ID_SUFFIX_RE.match(tail):
        return None
    return head, tail


def is_execution_workspace_name(name: str) -> bool:
    """Whether ``name`` is an execution workspace name this convention produced."""
    return _split_execution_name(name) is not None


def resolve_logical_workspace_name(name: str) -> str:
    """Map ``.run_<logical>_<scanid>`` to ``<logical>``; a logical name is a no-op.

    Single source of truth for the execution -> logical mapping. The web backend
    applies it at every name -> store boundary, because the frontend may hand it
    the execution name mid-scan while every database row is keyed on the logical
    name.

    A garbage or unknown ``.run_`` name with no recognisable scan-id suffix is
    returned UNCHANGED, so a genuinely missing workspace still resolves to a
    missing row (a 404) rather than being masked by a rewrite.

    Note the asymmetry with :func:`execution_workspace_belongs_to`: for a logical
    name long enough to have been truncated, this returns the TRUNCATED head,
    which is what the database keys on but is not equal to the original name.
    Use the predicate, not this function, to decide ownership.
    """
    parts = _split_execution_name(name)
    return name if parts is None else parts[0]


def execution_workspace_belongs_to(name: str, logical_workspace: str) -> bool:
    """Whether execution workspace ``name`` was built for ``logical_workspace``.

    Exact on the convention's own boundary: the candidate's scan-id suffix is
    read back out and the whole name is rebuilt through
    :func:`execution_workspace_name`, so this is correct for a truncated or
    separator-stripped logical name and can never match a DIFFERENT workspace
    whose name merely shares a prefix.

    Args:
        name: A directory name to test.
        logical_workspace: The logical workspace claiming it.

    Returns:
        Whether the name is this logical workspace's execution workspace.
    """
    parts = _split_execution_name(name)
    if parts is None or not logical_workspace:
        return False
    _head, scan_id_suffix = parts
    return execution_workspace_name(logical_workspace, scan_id_suffix) == name


@dataclass(frozen=True)
class ExecutionWorkspace:
    """One execution workspace directory found on disk."""

    name: str
    path: Path
    #: The logical workspace it belongs to: what it declares about itself when
    #: it has a readable record, otherwise what its name parses to.
    logical_workspace: str
    #: Whether ``logical_workspace`` came from the directory's own record rather
    #: than from its name.
    declared: bool


def declared_logical_workspace(execution_root: Path) -> str | None:
    """Read the logical workspace an execution workspace declares for itself.

    ``prepare_workspace`` writes ``logical_workspace`` into the execution
    workspace's ``variables.json``, which is a first-hand record and is better
    evidence than parsing the directory name. ``None`` when the file is missing,
    unreadable, or carries no usable value.
    """
    try:
        with (execution_root / "variables.json").open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    declared = data.get("logical_workspace")
    if not isinstance(declared, str) or not declared.strip():
        return None
    return declared.strip()


def iter_execution_workspaces(
    workspaces_dir: str | os.PathLike[str],
) -> list[ExecutionWorkspace]:
    """List every execution workspace directory under ``workspaces_dir``."""
    found: list[ExecutionWorkspace] = []
    try:
        entries = sorted(Path(workspaces_dir).iterdir(), key=lambda item: item.name)
    except OSError:
        return found
    for entry in entries:
        if not is_execution_workspace_name(entry.name):
            continue
        try:
            if not entry.is_dir():
                continue
        except OSError:
            continue
        parsed = resolve_logical_workspace_name(entry.name)
        declared = declared_logical_workspace(entry)
        found.append(
            ExecutionWorkspace(
                name=entry.name,
                path=entry,
                logical_workspace=declared or parsed,
                declared=declared is not None,
            )
        )
    return found


def execution_workspaces_for(
    workspaces_dir: str | os.PathLike[str], logical_workspace: str
) -> list[ExecutionWorkspace]:
    """Every execution workspace that belongs to ``logical_workspace``.

    Matched two ways, each an exact equality so neither can reach across a name
    boundary: by the naming convention (:func:`execution_workspace_belongs_to`),
    and by the directory's own declared ``logical_workspace``. The second catches
    a directory whose name was truncated or whose run predates the convention;
    the first catches one whose record is missing or unreadable.
    """
    if not logical_workspace:
        return []
    return [
        entry
        for entry in iter_execution_workspaces(workspaces_dir)
        if execution_workspace_belongs_to(entry.name, logical_workspace)
        or (entry.declared and entry.logical_workspace == logical_workspace)
    ]


def orphaned_execution_workspaces(
    workspaces_dir: str | os.PathLike[str],
) -> list[ExecutionWorkspace]:
    """Execution workspaces whose logical workspace is no longer on disk.

    These are the end of an engagement that was only half completed: the
    operator deleted the workspace and this copy of it stayed behind. Removing
    one finishes the delete they already asked for.

    Being an orphan is NOT on its own a licence to remove: a brand new
    workspace's first run creates its ``.run_*`` before the logical directory
    exists, so every caller still gates on
    :func:`execution_workspace_is_quiescent`.
    """
    root = Path(workspaces_dir)
    orphans: list[ExecutionWorkspace] = []
    for entry in iter_execution_workspaces(root):
        logical = entry.logical_workspace
        try:
            if logical and (root / logical).is_dir():
                continue
        except OSError:
            continue
        orphans.append(entry)
    return orphans


def _newest_mtime_within(path: Path, *, cutoff: float) -> bool:
    """Whether anything at or under ``path`` was modified at/after ``cutoff``.

    Returns as soon as one recent file is found, so the expensive case is the
    quiet directory we are about to remove and the cheap case is the live one we
    must not touch.
    """
    try:
        if path.stat().st_mtime >= cutoff:
            return True
    except OSError:
        return False
    try:
        for child in path.rglob("*"):
            try:
                if child.stat().st_mtime >= cutoff:
                    return True
            except OSError:
                continue
    except OSError:
        return False
    return False


def execution_workspace_is_quiescent(
    entry: ExecutionWorkspace,
    *,
    quiet_seconds: float = EXECUTION_WORKSPACE_QUIET_SECONDS,
) -> bool:
    """Whether no run is using this execution workspace any more.

    Two independent signals, because neither is available everywhere:

    * its workspace lock. Authoritative, and it is what the host-side launcher
      has. In the Docker deployment ``run/locks`` is host-only, so from inside
      the container there is no lock file to read and this signal abstains.
    * recent write activity. A running scan writes log lines continuously, so a
      directory untouched for ``quiet_seconds`` is finished with. This is the
      signal that carries the container, and it also covers the window where a
      scan holds no lock yet.

    Both must say "finished" for the answer to be yes.
    """
    from adscan_core.workspace_locks import workspace_lock_is_held  # noqa: PLC0415

    try:
        if workspace_lock_is_held(entry.name):
            return False
    except Exception:  # noqa: BLE001 - an unreadable lock is not a licence to delete
        return False
    return not _newest_mtime_within(entry.path, cutoff=time.time() - quiet_seconds)


@dataclass(frozen=True)
class ExecutionWorkspaceRemoval:
    """What a removal pass did, for the caller's report and for tests."""

    #: Names of the execution workspaces removed.
    removed: tuple[str, ...] = ()
    #: Names left in place because a run still appears to be using them.
    kept_in_use: tuple[str, ...] = ()
    #: Domains those removed directories held, for a caller that purges
    #: domain-keyed artifacts (an execution workspace can hold a domain the
    #: logical workspace never received, when its run never promoted).
    domains: tuple[str, ...] = ()


def _execution_workspace_domains(path: Path) -> list[str]:
    """Domains an execution workspace holds (``<root>/domains/<domain>``)."""
    from adscan_core.workspace_domain_buckets import (  # noqa: PLC0415
        is_reserved_domain_bucket,
    )

    try:
        return sorted(
            entry.name
            for entry in (path / "domains").iterdir()
            if entry.is_dir() and not is_reserved_domain_bucket(entry.name)
        )
    except OSError:
        return []


def remove_execution_workspaces(
    entries: list[ExecutionWorkspace],
    *,
    quiet_seconds: float = EXECUTION_WORKSPACE_QUIET_SECONDS,
) -> ExecutionWorkspaceRemoval:
    """Remove each execution workspace that no run is using, and its lock file.

    A directory a run still appears to be using is LEFT IN PLACE and returned in
    ``kept_in_use`` so the caller can say so: silently deleting the directory a
    running engine is writing into would destroy that engagement mid-scan, and
    the next delete or sweep of the same name collects it once the run ends.

    Best-effort throughout: a directory that cannot be removed must never turn a
    successful delete into an error.
    """
    from adscan_core.workspace_locks import (  # noqa: PLC0415
        remove_workspace_lock_if_free,
    )

    removed: list[str] = []
    kept: list[str] = []
    domains: list[str] = []
    for entry in entries:
        try:
            if not execution_workspace_is_quiescent(entry, quiet_seconds=quiet_seconds):
                kept.append(entry.name)
                continue
            found = _execution_workspace_domains(entry.path)
            shutil.rmtree(entry.path, ignore_errors=True)
            if entry.path.exists():
                kept.append(entry.name)
                continue
            removed.append(entry.name)
            domains.extend(found)
            # The lock file name carries the logical workspace name, so it is
            # engagement residue in its own right.
            remove_workspace_lock_if_free(entry.name)
        except Exception:  # noqa: BLE001 - never block the caller's delete
            continue
    return ExecutionWorkspaceRemoval(
        removed=tuple(removed),
        kept_in_use=tuple(kept),
        domains=tuple(dict.fromkeys(domains)),
    )


class ScanRunState:
    """Where a scan is in its life, as far as reading its artifacts goes.

    The caller maps its own status vocabulary onto these (the web backend uses
    ``ENGINE_LIVE_SCAN_STATUSES``); this module deliberately knows no status
    names, so the liveness rule keeps one owner.
    """

    #: The engine is executing or shutting down: it writes into the execution
    #: workspace, and nothing has been promoted yet.
    LIVE = "live"
    #: Queued, never started: the execution workspace holds nothing of its own.
    NOT_STARTED = "not_started"
    #: Completed, failed, cancelled or stopped: the run has ended, and was
    #: either promoted (and its execution workspace then removed) or not.
    FINISHED = "finished"
    #: No scan record to ask (a pruned row, a caller without database access).
    #: Decided from the filesystem alone, exactly like ``FINISHED``.
    UNKNOWN = "unknown"


def execution_workspace_was_promoted(
    workspaces_dir: str | os.PathLike[str],
    *,
    logical_workspace: str,
    execution_workspace: str,
) -> bool:
    """Whether the logical workspace currently holds THIS run's promoted artifacts.

    ``promote_workspace`` stamps ``execution_workspace`` into the logical
    workspace's ``variables.json`` (the run's own copy carries the same key from
    ``prepare_workspace``), so the logical workspace names the run it was last
    promoted from. A later run's promotion overwrites the stamp, which is
    correct: the logical workspace then no longer holds this run's data.
    """
    if not logical_workspace or not execution_workspace:
        return False
    variables = Path(workspaces_dir) / logical_workspace / "variables.json"
    try:
        with variables.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    return str(data.get("execution_workspace") or "").strip() == execution_workspace


def select_artifact_workspace(
    workspaces_dir: str | os.PathLike[str],
    name: str,
    *,
    run_state: str = ScanRunState.UNKNOWN,
    logical_workspace: str | None = None,
) -> str:
    """Return the workspace directory a reader keyed to ``name`` should read.

    Single source of truth for "where are this scan's artifacts NOW". A scan
    record keeps its ``execution_workspace`` after the run ends, while the
    worker promotes that directory into the logical workspace and then removes
    it; a reader that joined the recorded name onto the workspace root read a
    directory that no longer existed and served nothing for every finished
    scan.

    The rules, for an execution name:

    - ``LIVE``: the execution workspace, while it exists (before the engine
      created it, the logical one holds the latest data).
    - ``NOT_STARTED``: the logical workspace.
    - ``FINISHED`` / ``UNKNOWN``: the logical workspace once this run was
      promoted into it, or once its execution workspace is gone. An execution
      workspace that is still there and was never promoted (a crashed run, a
      partial run the downgrade guard kept out of the logical workspace, a
      failed promotion) is the only copy of what that run produced, so it is
      read in place.

    A logical name is returned unchanged: redirecting a logical name to a live
    run needs the scan record, and is the caller's decision. A ``.run_`` name
    this convention did not produce is returned unchanged too, so a genuinely
    missing workspace still reads as missing.

    Args:
        workspaces_dir: Root holding every workspace directory.
        name: A logical or execution workspace name, as the caller holds it.
        run_state: One of :class:`ScanRunState`.
        logical_workspace: The run's logical workspace when the caller knows it
            (the scan record). Otherwise it is read from the execution
            workspace's own record, then parsed from the name.

    Returns:
        The workspace name to join onto ``workspaces_dir``.
    """
    name = str(name or "").strip()
    if not is_execution_workspace_name(name):
        return name
    root = Path(workspaces_dir)
    execution_root = root / name
    execution_exists = execution_root.is_dir()
    logical = (
        str(logical_workspace or "").strip()
        or (declared_logical_workspace(execution_root) if execution_exists else None)
        or resolve_logical_workspace_name(name)
    )
    if not logical or logical == name:
        return name
    if run_state == ScanRunState.LIVE:
        return name if execution_exists else logical
    if run_state == ScanRunState.NOT_STARTED or not execution_exists:
        return logical
    if execution_workspace_was_promoted(
        root, logical_workspace=logical, execution_workspace=name
    ):
        return logical
    return name


__all__ = [
    "EXECUTION_WORKSPACE_PREFIX",
    "EXECUTION_WORKSPACE_QUIET_SECONDS",
    "ExecutionWorkspace",
    "ExecutionWorkspaceRemoval",
    "ScanRunState",
    "declared_logical_workspace",
    "execution_workspace_was_promoted",
    "select_artifact_workspace",
    "execution_workspace_belongs_to",
    "execution_workspace_is_quiescent",
    "execution_workspace_name",
    "execution_workspaces_for",
    "is_execution_workspace_name",
    "iter_execution_workspaces",
    "orphaned_execution_workspaces",
    "remove_execution_workspaces",
    "resolve_logical_workspace_name",
]
