"""Telemetry preference — the opt-out single source of truth.

Telemetry consent has two scopes, and neither one is a one-way ratchet:

* a **global** preference, recorded once per operator, that new/unset workspaces
  inherit — set with ``set telemetry <on|off> global``;
* a **per-workspace** preference for a single engagement — set with
  ``set telemetry <on|off>`` (no keyword), the default scope.

Resolution rule (see :func:`resolve_effective_telemetry`):

* an **explicit** per-workspace preference always wins, in EITHER direction — a
  workspace may turn telemetry off while global is on, AND back on while global
  is off (so a stale global-off can always be recovered per engagement);
* a workspace with **no** explicit preference inherits the global preference,
  live (a later change to global reaches every still-unset workspace);
* when neither scope has a preference, the tier default applies (ON for the
  Community/PRO tiers — the appliance / air-gapped OFF posture is enforced
  separately at the telemetry gate via ``ADSCAN_OFFLINE`` and is orthogonal to
  these REPL scopes).

Storage lives in the ADscan **state** directory (``~/.adscan/state/`` on the
host, ``/opt/adscan/state/`` in the container). That directory is the
established home for small cross-run markers AND — the part that matters — it
is bind-mounted into the runtime container, so a preference set inside the
container survives the container and is visible to the host launcher (and vice
versa). ``~/.adscan/config.json`` is deliberately NOT used: it is not mounted
into the container, so a preference written there from a Docker session would
be discarded when the container exits.

A per-workspace preference is persisted in each workspace's ``variables.json``
under the ``telemetry`` key. A new workspace records NO explicit value (the key
is absent / ``null``), so it stays UNSET and inherits the global preference at
resolution time rather than freezing a boolean at creation.
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

#: Shell attribute holding the WORKSPACE's own recorded preference (``True`` /
#: ``False`` / ``None`` = unset), kept apart from ``shell.telemetry`` (the
#: resolved effective state) so a global opt-out is never written back into the
#: workspace as if the user had chosen it there.
WORKSPACE_PREFERENCE_ATTR = "telemetry_workspace_preference"

#: Tier default when neither scope has recorded a preference. Community/PRO ship
#: telemetry ON; the appliance / air-gapped OFF posture is enforced upstream at
#: the telemetry gate (``ADSCAN_OFFLINE`` / ``ADSCAN_TELEMETRY``), not here.
_TIER_DEFAULT_TELEMETRY = True

_ENABLED_KEY = "enabled"
_SOURCE_KEY = "source"
_MIGRATION_KEY = "workspace_migration"
#: ``source`` value written by the 11.0.0 workspace->global promotion. A record
#: bearing it is NOT a deliberate global opt-out and is treated as unset.
_MIGRATION_SOURCE = "workspace_migration"

# Cache key: (resolved path, mtime_ns, size) — the last two are ``None`` when
# the file is absent. A stat() per read is cheap and keeps an externally edited
# file (or a test writing a fresh temp file) from being served stale.
_CACHE: Optional[tuple[tuple[str, Optional[int], Optional[int]], Optional[bool]]] = None


@dataclass(frozen=True)
class WorkspaceMigrationOutcome:
    """Result of neutralizing the legacy workspace->global opt-out promotion.

    Attributes:
        neutralized: True when a stale 11.0.0 promotion record was found and its
            fake global-off was dropped.
        workspaces: Names of the workspaces the stale record had listed (their
            own per-workspace opt-out in ``variables.json`` is left untouched).
        already_checked: True when there was nothing to undo (no promotion
            record, or a genuine global preference was in place).
    """

    neutralized: bool = False
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


def _global_enabled_from_document(document: dict[str, Any]) -> Optional[bool]:
    """Effective GLOBAL preference from a raw document.

    A record written by the 11.0.0 workspace->global promotion
    (``source == "workspace_migration"``) is NOT a deliberate global opt-out —
    it is treated as UNSET so a per-engagement opt-out never floors telemetry
    everywhere. Genuine ``set telemetry ... global`` records (source ``cli``)
    are honoured.
    """
    if document.get(_SOURCE_KEY) == _MIGRATION_SOURCE:
        return None
    return _coerce_enabled(document)


def load_global_preference(*, path: Path | None = None) -> Optional[bool]:
    """Return the persisted global preference.

    Returns:
        ``True``/``False`` when the operator has recorded a deliberate global
        preference, ``None`` when they never have (so the tier default applies).
        A stale migration-promotion record resolves to ``None``.
    """
    resolved = path or preference_path()
    return _global_enabled_from_document(_read_document(resolved))


def save_global_preference(
    enabled: bool,
    *,
    path: Path | None = None,
    source: str = "cli",
) -> bool:
    """Persist the global telemetry preference. Returns whether the write won.

    Merges into the existing document but overwrites ``source`` so a deliberate
    change (default source ``cli``) supersedes any stale migration marker. Never
    raises — a failed write is reported through the return value so the caller
    can tell the operator the truth instead of claiming an opt-out that was not
    stored.
    """
    resolved = path or preference_path()
    document = _read_document(resolved)
    document[_ENABLED_KEY] = bool(enabled)
    document[_SOURCE_KEY] = source
    document["updated_at"] = datetime.now(timezone.utc).isoformat()
    return _write_document(resolved, document)


def global_telemetry_disabled(*, path: Path | None = None) -> bool:
    """Return True when the operator has a deliberate global opt-out.

    Hot path: consulted on every telemetry gate check, so the parsed value is
    cached and revalidated with a single ``stat()``. A stale migration record
    is treated as unset (not disabled).
    """
    global _CACHE
    resolved = path or preference_path()
    key = _stat_key(resolved)
    cached = _CACHE
    if cached is not None and cached[0] == key:
        return cached[1] is False
    value = _global_enabled_from_document(_read_document(resolved))
    _CACHE = (key, value)
    return value is False


def resolve_effective_telemetry(
    global_preference: Optional[bool],
    workspace_preference: Optional[bool],
) -> bool:
    """Resolve the effective telemetry state from both scopes.

    An explicit per-workspace preference wins in EITHER direction (it can turn
    telemetry off while global is on, and back on while global is off — there is
    no ratchet). A workspace with no explicit preference inherits the global
    preference; when global is also unset, the tier default applies.
    """
    if workspace_preference is not None:
        return workspace_preference
    if global_preference is not None:
        return global_preference
    return _TIER_DEFAULT_TELEMETRY


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
    """Effective telemetry a workspace with NO explicit preference resolves to.

    This is a LIVE read (global preference or, failing that, the tier default) —
    it is for display/indicator use, NOT for freezing a boolean into a new
    workspace. A new workspace stays unset so a later global change still
    reaches it.
    """
    return resolve_effective_telemetry(load_global_preference(path=path), None)


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
    workspaces_dir: Path | None = None,  # noqa: ARG001 - kept for call-site parity
    path: Path | None = None,
) -> WorkspaceMigrationOutcome:
    """Neutralize the legacy 11.0.0 workspace->global opt-out promotion.

    11.0.0 (never shipped to production) promoted a single per-engagement
    opt-out to a GLOBAL off, which defeated scoping: opting out of one
    engagement silenced telemetry everywhere, including brand-new workspaces.
    Per-workspace opt-outs live in each workspace's ``variables.json`` and are
    honoured by the resolver directly, so no promotion was ever needed.

    This now only *undoes* a stale promotion: when the persisted global record
    was written by that migration (``source == "workspace_migration"``), drop
    its fake global-off while keeping the audit marker so it runs at most once.
    The affected workspaces keep their own ``variables.json`` opt-out, so their
    telemetry stays off; every other workspace returns to the tier default.
    """
    resolved = path or preference_path()
    document = _read_document(resolved)
    if document.get(_SOURCE_KEY) != _MIGRATION_SOURCE:
        return WorkspaceMigrationOutcome(already_checked=True)

    marker = document.get(_MIGRATION_KEY)
    workspaces: tuple[str, ...] = ()
    if isinstance(marker, dict):
        listed = marker.get("workspaces")
        if isinstance(listed, list):
            workspaces = tuple(str(name) for name in listed)

    document.pop(_ENABLED_KEY, None)
    document.pop(_SOURCE_KEY, None)
    document.pop("updated_at", None)
    _write_document(resolved, document)
    return WorkspaceMigrationOutcome(
        neutralized=True, workspaces=workspaces, already_checked=True
    )


def notify_workspace_opt_out_migration(outcome: WorkspaceMigrationOutcome) -> None:
    """Tell the operator once that consent is per-workspace again. Best-effort."""
    if not outcome.neutralized or not outcome.workspaces:
        return
    try:
        from adscan_core.rich_output import print_info

        names = ", ".join(outcome.workspaces[:3])
        if len(outcome.workspaces) > 3:
            names += ", ..."
        print_info(
            "Telemetry consent is per-workspace again. Your earlier opt-out "
            f"(workspace: {names}) still applies to that engagement; other "
            "workspaces use the default. Opt out everywhere with "
            "'set telemetry off global'."
        )
    except Exception:  # noqa: BLE001 - a notice must never break startup
        return


def migrate_and_notify(
    *,
    workspaces_dir: Path | None = None,
    path: Path | None = None,
) -> WorkspaceMigrationOutcome:
    """Run the one-time neutralization and tell the operator when it took effect."""
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
