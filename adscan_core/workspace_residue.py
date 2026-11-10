"""What ADscan keeps about a workspace OUTSIDE its directory, and its removal.

Deleting a workspace is the whole end-of-engagement procedure: hand over the
reports, delete the workspace, and nothing of that client's environment stays
on the machine. Almost everything already lives inside the workspace directory
(variables, credentials, graph, reports, and since 2026-11-05 every log line).
This module removes the few artifacts that are kept elsewhere and are keyed to
the workspace, so ``delete_workspace_dir`` can leave nothing behind:

* ``run/locks/workspace-<name>.lock``: the single-instance lock. Its file name
  is the workspace name. The launcher unlinks it on release; this covers a
  host-mode run killed before releasing (in the Docker deployment ``run/locks``
  is host-only and the launcher sweeps it itself).
* ``wordlists/custom/<domain>/``: the client-targeted cracking wordlist built
  from the domain's users and computers. It is removed only when no other
  workspace still holds that domain (it is rebuilt the next time a targeted
  crack runs for the domain, not before, so a sibling workspace keeps it).
* ``.adscan_history`` at the ADscan home (commands typed before any workspace
  was selected) and in every OTHER workspace (the shell refuses to delete the
  active workspace, so ``workspace delete <name>`` is always typed inside
  another one). The ``workspace create|select|delete <name>`` entries naming
  this workspace are dropped with their timestamp line; every other command is
  kept.
* ``workspaces/.run_<name>_<scanid>/``: the EXECUTION workspaces of this
  workspace. A scan writes its artifacts into one of these hidden directories
  and they are promoted into the logical workspace at the end of the run, but
  because the directory is a SIBLING of the logical one rather than a child, it
  is invisible to everything that reasons about "the workspace directory" while
  holding a full copy of the engagement: the reports, the technical report, the
  change ledger, the logs, the enabled-user and enabled-computer lists, and any
  certificate with its private key. Its lock file goes too, because that file
  name carries the logical workspace name. Matching is on the convention's exact
  boundary (``adscan_core.execution_workspace``), never a prefix test: logical
  names ``Essos`` and ``Essos-Demo`` coexist on a real machine, and a prefix
  test would make deleting one destroy the other's runs. A directory a scan is
  still writing into is KEPT and reported rather than deleted.

  Execution workspaces whose own logical workspace is already gone are swept at
  the same time. Those are an end-of-engagement delete that only half happened,
  so finishing it is completing what the operator already asked for, and nobody
  can be expected to find them by hand (the workspace listing hides every
  dot-prefixed directory).

Everything here is best-effort and never raises: a residue that cannot be
removed must not turn a successful delete into an error.

It lives in ``adscan_core`` because three deletes must run the SAME purge: the
CLI (``adscan_internal.workspaces.manager.delete_workspace_dir``), and the
Enterprise platform, whose backend cannot import the engine and whose
filesystem view stops at the workspaces root, so the platform hands the purge
to its worker on the host (``purge_workspace_residue`` Celery task), which sees
the whole ADscan home. Stdlib and ``adscan_core`` only.
"""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path


def workspace_domains(workspace_root: str | os.PathLike[str]) -> list[str]:
    """Return the domains a workspace has data for (``<root>/domains/<domain>``)."""
    from adscan_core.workspace_domain_buckets import is_reserved_domain_bucket

    domains_dir = Path(workspace_root) / "domains"
    try:
        return sorted(
            entry.name
            for entry in domains_dir.iterdir()
            if entry.is_dir() and not is_reserved_domain_bucket(entry.name)
        )
    except OSError:
        return []


def _remove_workspace_lock(workspace_name: str) -> bool:
    """Remove this workspace's lock file unless a live run holds it.

    Thin wrapper over the shared primitive in ``adscan_core.workspace_locks``,
    which the host launcher and the execution-workspace sweep need too and so
    cannot live here.
    """
    from adscan_core.workspace_locks import remove_workspace_lock_if_free

    return remove_workspace_lock_if_free(workspace_name)


def _domains_held_elsewhere(workspaces_dir: str | None, workspace_name: str) -> set[str]:
    """Domains (case-folded) another workspace under ``workspaces_dir`` still holds.

    "Another workspace" means a different ENGAGEMENT. The directory listing also
    contains hidden ``.run_*`` execution workspaces, and one belonging to the
    workspace being deleted is the same engagement, not another: counting it
    made this workspace's own domain look like it was still in use somewhere
    else, so the targeted cracking wordlist built from that client's directory
    was KEPT even when this was the only workspace holding the domain. Another
    workspace's execution directory does count, because that engagement is live.
    """
    from adscan_core.execution_workspace import (
        execution_workspace_belongs_to,
        resolve_logical_workspace_name,
    )

    held: set[str] = set()
    if not workspaces_dir:
        return held
    try:
        entries = list(Path(workspaces_dir).iterdir())
    except OSError:
        return held
    for entry in entries:
        if entry.name == workspace_name or not entry.is_dir():
            continue
        if execution_workspace_belongs_to(entry.name, workspace_name):
            continue
        if resolve_logical_workspace_name(entry.name) == workspace_name:
            continue
        held.update(domain.casefold() for domain in workspace_domains(entry))
    return held


def _remove_custom_wordlists(
    domains: list[str],
    *,
    workspaces_dir: str | None,
    workspace_name: str,
    adscan_home: Path | None = None,
) -> list[str]:
    from adscan_core.custom_wordlist_paths import custom_wordlist_dir

    still_used = _domains_held_elsewhere(workspaces_dir, workspace_name)
    removed: list[str] = []
    for domain in domains:
        if domain.casefold() in still_used:
            continue
        # The wordlist folder is named after the domain as the cracking step
        # spelled it; a workspace folder may differ only in case.
        for spelling in dict.fromkeys((domain, domain.lower())):
            try:
                target = custom_wordlist_dir(spelling, base_dir=adscan_home)
            except Exception:  # noqa: BLE001
                continue
            if target.is_dir():
                shutil.rmtree(target, ignore_errors=True)
                if not target.exists():
                    removed.append(str(target))
    return removed


_HISTORY_WORKSPACE_COMMAND = (
    r"^\+\s*workspace\s+(?:create|select|delete)\s+{name}\s*$"
)


def _scrub_global_history(workspace_name: str, adscan_home: Path | None = None) -> bool:
    """Drop the history entries that create/select/delete this workspace.

    Two kinds of history file can hold them. The one at the ADscan home keeps
    what was typed before any workspace was selected. Every OTHER workspace
    keeps its own ``.adscan_history``, and the shell refuses to delete the
    workspace that is active, so ``workspace delete <name>`` is always typed
    inside some other workspace and lands in that one's history, where deleting
    ``<name>`` would otherwise never reach it.
    """
    from adscan_core.paths import get_adscan_home_dir

    if not workspace_name:
        return False
    home = Path(adscan_home) if adscan_home is not None else get_adscan_home_dir()
    candidates = [home / ".adscan_history"]
    try:
        candidates.extend(
            entry / ".adscan_history"
            for entry in (home / "workspaces").iterdir()
            if entry.is_dir() and entry.name != workspace_name
        )
    except OSError:
        pass
    scrubbed = False
    for history in candidates:
        scrubbed = _scrub_history_file(history, workspace_name) or scrubbed
    return scrubbed


def _scrub_history_file(history: Path, workspace_name: str) -> bool:
    """Drop the entries of one history file that name ``workspace_name``.

    prompt_toolkit's history file stores each entry as a ``# <timestamp>`` line
    followed by ``+<command>`` line(s). Only an entry whose command is
    ``workspace create|select|delete <name>`` for THIS workspace is dropped,
    timestamp included; a workspace named like a command (``list``) can never
    take unrelated history with it.
    """
    if not history.is_file():
        return False
    pattern = re.compile(
        _HISTORY_WORKSPACE_COMMAND.format(name=re.escape(workspace_name)),
        re.IGNORECASE,
    )
    try:
        lines = history.read_text(encoding="utf-8", errors="replace").splitlines(True)
    except OSError:
        return False
    # Group into entries: leading lines (blank/comment) + the "+" lines after.
    entries: list[list[str]] = []
    current: list[str] = []
    seen_command = False
    for line in lines:
        is_command = line.startswith("+")
        if not is_command and seen_command:
            entries.append(current)
            current, seen_command = [], False
        current.append(line)
        seen_command = seen_command or is_command
    if current:
        entries.append(current)
    kept: list[str] = []
    dropped = False
    for entry in entries:
        commands = [line.rstrip("\r\n") for line in entry if line.startswith("+")]
        if commands and all(pattern.match(command) for command in commands):
            dropped = True
            continue
        kept.extend(entry)
    if not dropped:
        return False
    try:
        history.write_text("".join(kept), encoding="utf-8")
    except OSError:
        return False
    return True


def _purge_execution_workspaces(
    workspace_name: str, *, workspaces_dir: str | None
) -> tuple[list[str], list[str], list[str]]:
    """Remove this workspace's execution workspaces, and any already orphaned.

    Returns ``(removed, kept_in_use, domains)``: the directories removed, the
    ones a scan still appears to be writing into, and the domains the removed
    ones held. A removed execution workspace can carry a domain the logical
    workspace never received (its run never promoted), so its domains join the
    set the cracking-wordlist purge works from.
    """
    from adscan_core.execution_workspace import (
        execution_workspaces_for,
        orphaned_execution_workspaces,
        remove_execution_workspaces,
    )

    if not workspaces_dir:
        return [], [], []
    entries = execution_workspaces_for(workspaces_dir, workspace_name)
    seen = {entry.name for entry in entries}
    # The workspace directory is already gone by the time this runs, so its own
    # execution workspaces are orphans too; dedupe by name.
    entries.extend(
        entry
        for entry in orphaned_execution_workspaces(workspaces_dir)
        if entry.name not in seen
    )
    removal = remove_execution_workspaces(entries)
    return (
        list(removal.removed),
        list(removal.kept_in_use),
        list(removal.domains),
    )


def purge_workspace_residue(
    workspace_name: str,
    *,
    workspace_root: str,
    domains: list[str],
    workspaces_dir: str | None = None,
    adscan_home: str | os.PathLike[str] | None = None,
) -> dict[str, object]:
    """Remove what ADscan keeps about a deleted workspace outside its directory.

    Args:
        workspace_name: The workspace that was deleted.
        workspace_root: Its directory (kept for the caller's debug line).
        domains: The domains it held data for, read BEFORE the directory was
            removed (see :func:`workspace_domains`).
        workspaces_dir: Where the other workspaces live; a domain another
            workspace still holds keeps its cracking wordlist, and this is also
            where the hidden execution workspaces are.
        adscan_home: The ADscan home holding ``wordlists/`` and the
            pre-workspace history. Defaults to this process's home; the
            platform worker passes the parent of its configured workspaces
            root, the layout every deployment uses.

    Returns:
        What was removed, for the caller's debug line and for tests. The
        ``execution_workspaces_in_use`` entry is what the caller must TELL the
        operator about: those directories were left in place because a scan
        still appears to be writing into them.
    """
    result: dict[str, object] = {
        "lock": False,
        "wordlists": [],
        "history": False,
        "execution_workspaces": [],
        "execution_workspaces_in_use": [],
    }
    # The execution workspaces go first: they are a full copy of the engagement,
    # and the domains they hold feed the wordlist purge below.
    try:
        removed, in_use, extra_domains = _purge_execution_workspaces(
            workspace_name, workspaces_dir=workspaces_dir
        )
        result["execution_workspaces"] = removed
        result["execution_workspaces_in_use"] = in_use
        known = {domain.casefold() for domain in domains}
        domains = list(domains) + [
            domain for domain in extra_domains if domain.casefold() not in known
        ]
    except Exception:  # noqa: BLE001
        pass
    try:
        result["lock"] = _remove_workspace_lock(workspace_name)
    except Exception:  # noqa: BLE001
        pass
    home = Path(adscan_home) if adscan_home is not None else None
    try:
        result["wordlists"] = _remove_custom_wordlists(
            domains,
            workspaces_dir=workspaces_dir,
            workspace_name=workspace_name,
            adscan_home=home,
        )
    except Exception:  # noqa: BLE001
        pass
    try:
        result["history"] = _scrub_global_history(workspace_name, home)
    except Exception:  # noqa: BLE001
        pass
    return result


__all__ = ["purge_workspace_residue", "workspace_domains"]
