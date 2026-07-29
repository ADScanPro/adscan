"""Global (user-scoped) telemetry preference — the opt-out single source of truth.

Telemetry consent belongs to the OPERATOR, not to one engagement. Before this
module the only persisted switch was the per-workspace ``telemetry`` flag in
``variables.json``: a user who opted out on one engagement was silently
recorded again on the next workspace, because a freshly created workspace
defaults to telemetry enabled. That is a consent bug, so the preference now
lives once, outside any workspace, and a workspace can only be *stricter*.

Resolution rule (see :func:`resolve_effective_telemetry`):

* global OFF wins over everything a workspace says — silence never resolves in
  the product's favour;
* a workspace may still switch telemetry off while the global preference is on
  (a single sensitive engagement);
* a workspace can never switch telemetry back on when the global preference is
  off.

Storage lives in the ADscan **state** directory (``~/.adscan/state/`` on the
host, ``/opt/adscan/state/`` in the container). That directory is the
established home for small cross-run markers AND — the part that matters — it
is bind-mounted into the runtime container, so a preference set inside the
container survives the container and is visible to the host launcher (and vice
versa). ``~/.adscan/config.json`` is deliberately NOT used: it is not mounted
into the container, so a preference written there from a Docker session would
be discarded when the container exits, which is exactly the class of bug this
module fixes.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from adscan_core.path_utils import get_adscan_home, get_adscan_state_dir

#: File name of the persisted global preference, under the state directory.
PREFERENCE_FILENAME = "telemetry_preference.json"

#: Shell attribute holding the WORKSPACE's own recorded preference, kept apart
#: from ``shell.telemetry`` (the resolved effective state) so a global opt-out
#: is never written back into the workspace as if the user had chosen it there.
WORKSPACE_PREFERENCE_ATTR = "telemetry_workspace_preference"

_ENABLED_KEY = "enabled"
_MIGRATION_KEY = "workspace_migration"

# Cache key: (resolved path, mtime_ns, size) — the last two are ``None`` when
# the file is absent. A stat() per read is cheap and keeps an externally edited
# file (or a test writing a fresh temp file) from being served stale.
_CACHE: Optional[tuple[tuple[str, Optional[int], Optional[int]], Optional[bool]]] = None


@dataclass(frozen=True)
class WorkspaceMigrationOutcome:
    """Result of the one-time per-workspace opt-out migration.

    Attributes:
        migrated: True when at least one workspace had telemetry disabled and
            the global preference was therefore set to off.
        workspaces: Names of the workspaces that were already opted out.
        already_checked: True when the migration had already run (or the user
            had already recorded a global preference), so nothing was scanned.
    """

    migrated: bool = False
    workspaces: tuple[str, ...] = field(default_factory=tuple)
    already_checked: bool = False


def preference_path() -> Path:
    """Return the path of the persisted global telemetry preference."""
    return get_adscan_state_dir() / PREFERENCE_FILENAME


def invalidate_cache() -> None:
    """Drop the in-process cache of the persisted preference."""
    global _CACHE
    _CACHE = None


def _stat_key(path: Path) -> tuple[str, Optional[int], Optional[int]]:
    try:
        stat = path.stat()
    except OSError:
        return (str(path), None, None)
    return (str(path), stat.st_mtime_ns, stat.st_size)


def _read_document(path: Path) -> dict[str, Any]:
    """Read the preference document, returning ``{}`` when absent/unreadable."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_document(path: Path, document: dict[str, Any]) -> bool:
    """Persist the preference document atomically. Returns success."""
    written = False
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_name(path.name + ".tmp")
        tmp_path.write_text(
            json.dumps(document, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        os.replace(tmp_path, path)
        written = True
    except OSError:
        written = False
    invalidate_cache()
    return written


def _coerce_enabled(document: dict[str, Any]) -> Optional[bool]:
    value = document.get(_ENABLED_KEY)
    if isinstance(value, bool):
        return value
    return None


def load_global_preference(*, path: Path | None = None) -> Optional[bool]:
    """Return the persisted global preference.

    Returns:
        ``True``/``False`` when the operator has recorded a preference,
        ``None`` when they never have (so the product default applies).
    """
    resolved = path or preference_path()
    return _coerce_enabled(_read_document(resolved))


def save_global_preference(
    enabled: bool,
    *,
    path: Path | None = None,
    source: str = "cli",
) -> bool:
    """Persist the global telemetry preference. Returns whether the write won.

    Merges into the existing document so the migration marker (and any future
    key) is preserved. Never raises — a failed write is reported through the
    return value so the caller can tell the operator the truth instead of
    claiming an opt-out that was not stored.
    """
    resolved = path or preference_path()
    document = _read_document(resolved)
    document[_ENABLED_KEY] = bool(enabled)
    document["source"] = source
    document["updated_at"] = datetime.now(timezone.utc).isoformat()
    return _write_document(resolved, document)


def global_telemetry_disabled(*, path: Path | None = None) -> bool:
    """Return True when the operator opted out globally.

    Hot path: consulted on every telemetry gate check, so the parsed value is
    cached and revalidated with a single ``stat()``.
    """
    global _CACHE
    resolved = path or preference_path()
    key = _stat_key(resolved)
    cached = _CACHE
    if cached is not None and cached[0] == key:
        return cached[1] is False
    value = _coerce_enabled(_read_document(resolved))
    _CACHE = (key, value)
    return value is False


def resolve_effective_telemetry(
    global_preference: Optional[bool],
    workspace_preference: Optional[bool],
) -> bool:
    """Resolve the effective telemetry state from both scopes.

    Off wins in both directions of *strictness*: a workspace may override the
    global preference towards OFF, never towards ON.
    """
    if global_preference is False:
        return False
    if workspace_preference is False:
        return False
    return True


def effective_telemetry_for_workspace(
    workspace_preference: Optional[bool],
    *,
    path: Path | None = None,
) -> bool:
    """Resolve the effective state for a workspace against the stored global."""
    return resolve_effective_telemetry(
        load_global_preference(path=path), workspace_preference
    )


def default_workspace_telemetry(*, path: Path | None = None) -> bool:
    """Value a NEW workspace should record for its own ``telemetry`` flag.

    A workspace created while the operator is globally opted out must not be
    born with telemetry on.
    """
    return not global_telemetry_disabled(path=path)


def _workspaces_root(workspaces_dir: Path | None) -> Path:
    if workspaces_dir is not None:
        return workspaces_dir
    explicit = os.getenv("ADSCAN_WORKSPACES_DIR", "").strip()
    if explicit:
        return Path(explicit)
    return get_adscan_home() / "workspaces"


def _workspace_opted_out(variables_path: Path) -> bool:
    try:
        data = json.loads(variables_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return False
    return isinstance(data, dict) and data.get("telemetry") is False


def find_opted_out_workspaces(*, workspaces_dir: Path | None = None) -> list[str]:
    """Return the names of workspaces whose persisted telemetry flag is off."""
    root = _workspaces_root(workspaces_dir)
    try:
        entries = sorted(root.iterdir())
    except OSError:
        return []
    opted_out: list[str] = []
    for entry in entries:
        try:
            if not entry.is_dir() or entry.name.startswith("."):
                continue
        except OSError:
            continue
        if _workspace_opted_out(entry / "variables.json"):
            opted_out.append(entry.name)
    return opted_out


def migrate_workspace_opt_out(
    *,
    workspaces_dir: Path | None = None,
    path: Path | None = None,
) -> WorkspaceMigrationOutcome:
    """Promote a pre-existing per-workspace opt-out to the global preference.

    Runs at most once. A user who had already disabled telemetry in a workspace
    made a consent decision under the old per-workspace semantics; moving the
    switch to global scope must not silently re-enable them.
    """
    resolved = path or preference_path()
    document = _read_document(resolved)
    if _ENABLED_KEY in document or _MIGRATION_KEY in document:
        return WorkspaceMigrationOutcome(already_checked=True)

    opted_out = find_opted_out_workspaces(workspaces_dir=workspaces_dir)
    now = datetime.now(timezone.utc).isoformat()
    document[_MIGRATION_KEY] = {"completed_at": now, "workspaces": list(opted_out)}
    if opted_out:
        document[_ENABLED_KEY] = False
        document["source"] = "workspace_migration"
        document["updated_at"] = now
    _write_document(resolved, document)
    return WorkspaceMigrationOutcome(
        migrated=bool(opted_out), workspaces=tuple(opted_out)
    )


def notify_workspace_opt_out_migration(outcome: WorkspaceMigrationOutcome) -> None:
    """Tell the operator once that their opt-out is now global. Best-effort."""
    if not outcome.migrated:
        return
    try:
        from adscan_core.rich_output import print_info

        names = ", ".join(outcome.workspaces[:3])
        if len(outcome.workspaces) > 3:
            names += ", ..."
        print_info(
            "Telemetry stays off. Your earlier opt-out "
            f"(workspace: {names}) now applies to every workspace and every "
            "session. Re-enable it any time with 'set telemetry on'."
        )
    except Exception:  # noqa: BLE001 - a notice must never break startup
        return


def migrate_and_notify(
    *,
    workspaces_dir: Path | None = None,
    path: Path | None = None,
) -> WorkspaceMigrationOutcome:
    """Run the one-time migration and tell the operator when it took effect."""
    try:
        outcome = migrate_workspace_opt_out(workspaces_dir=workspaces_dir, path=path)
    except Exception:  # noqa: BLE001 - never break startup on a preference read
        return WorkspaceMigrationOutcome()
    notify_workspace_opt_out_migration(outcome)
    return outcome


__all__ = [
    "PREFERENCE_FILENAME",
    "WORKSPACE_PREFERENCE_ATTR",
    "WorkspaceMigrationOutcome",
    "default_workspace_telemetry",
    "effective_telemetry_for_workspace",
    "find_opted_out_workspaces",
    "global_telemetry_disabled",
    "invalidate_cache",
    "load_global_preference",
    "migrate_and_notify",
    "migrate_workspace_opt_out",
    "notify_workspace_opt_out_migration",
    "preference_path",
    "resolve_effective_telemetry",
    "save_global_preference",
]
