"""Saved pace profiles in the CLI: named paces kept beside saved scan policies.

A pace profile is a YAML file with a name, a description and a pace::

    format: adscan.pace_profile
    format_version: 1
    name: Slow WAN site
    description: Branch offices behind a 10 Mbit link.
    revision: 2
    level: polite
    overrides:
      max_parallel_hosts: 4
      max_requests_per_second: 20

Two stores, the same layout as saved policies
(:mod:`adscan_internal.services.saved_scan_policies`):

* **workspace**: ``<workspace>/pace_profiles/<slug>.yaml``, travels with it;
* **global**: ``<state dir>/pace_profiles/<slug>.yaml``.

On a name collision the workspace profile wins. Validation is the pacing SSOT
(:func:`adscan_core.scan_pacing.parse_pace_profile`). A profile holds no scope
and no safety setting, and is not limited when saved: a scan clamps it to its
policy's ceiling (:func:`adscan_core.scan_pacing.fit_to_ceiling`).

Design: docs/superpowers/specs/2026-11-06-saved-pace-profiles-design.md.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from adscan_core.paths import get_state_dir
from adscan_core.scan_pacing.pacing_profiles import (
    PROFILE_DESCRIPTION_MAX,
    PaceProfile,
    PaceProfileError,
    normalise_profile_name,
    parse_pace_profile,
)

PROFILE_DIRNAME = "pace_profiles"
PROFILE_SUFFIX = ".yaml"

SCOPE_WORKSPACE = "workspace"
SCOPE_GLOBAL = "global"
SAVE_SCOPES: tuple[str, ...] = (SCOPE_WORKSPACE, SCOPE_GLOBAL)
SCOPE_LABELS: dict[str, str] = {
    SCOPE_WORKSPACE: "this workspace",
    SCOPE_GLOBAL: "all workspaces",
}


class SavedPaceProfileError(ValueError):
    """A pace profile cannot be read, written or found."""


@dataclass(frozen=True)
class SavedPaceProfile:
    """A pace profile on disk.

    Attributes:
        profile: The parsed profile, identity stamped (``<scope>:<slug>``).
        scope: :data:`SCOPE_WORKSPACE` or :data:`SCOPE_GLOBAL`.
        path: The file.
        shadowed: A global profile hidden by a workspace one of the same name.
    """

    profile: PaceProfile
    scope: str
    path: Path
    shadowed: bool = False

    @property
    def name(self) -> str:
        return self.profile.name

    @property
    def slug(self) -> str:
        return profile_slug(self.profile.name)

    @property
    def reference(self) -> str:
        return f"{self.scope}:{self.slug}"


_SLUG_RE = re.compile(r"[^a-z0-9]+")


def profile_slug(name: str) -> str:
    """File stem for a profile name (``Slow WAN site`` -> ``slow-wan-site``)."""
    return _SLUG_RE.sub("-", str(name or "").strip().lower()).strip("-")[:64].strip("-")


def global_profiles_dir() -> Path:
    """Directory of the global pace profiles (host and container see the same)."""
    return get_state_dir() / PROFILE_DIRNAME


def workspace_profiles_dir(workspace_dir: str | os.PathLike[str]) -> Path:
    """Directory of a workspace's pace profiles."""
    return Path(workspace_dir) / PROFILE_DIRNAME


def _store_dir(scope: str, workspace_dir: str | os.PathLike[str] | None) -> Path:
    if scope == SCOPE_GLOBAL:
        return global_profiles_dir()
    if scope == SCOPE_WORKSPACE:
        if not workspace_dir:
            raise SavedPaceProfileError("Open a workspace first: a workspace profile is saved in it.")
        return workspace_profiles_dir(workspace_dir)
    raise SavedPaceProfileError(f"A pace profile is saved to the workspace or globally, not '{scope}'.")


def _yaml() -> Any:
    import yaml  # noqa: PLC0415 - optional at import time, always present in the runtime

    return yaml


def read_profile_text(text: str, *, default_name: str = "") -> PaceProfile:
    """Parse a profile document from YAML or JSON text."""
    try:
        data = _yaml().safe_load(text)
    except Exception as exc:  # noqa: BLE001 - any YAML error is a user error here
        raise SavedPaceProfileError(f"Not a readable pace profile: {exc}") from exc
    try:
        return parse_pace_profile(data, default_name=default_name)
    except PaceProfileError as exc:
        raise SavedPaceProfileError(str(exc)) from exc


def read_profile_file(path: str | os.PathLike[str]) -> PaceProfile:
    """Read one profile file."""
    target = Path(path).expanduser()
    try:
        text = target.read_text(encoding="utf-8")
    except OSError as exc:
        raise SavedPaceProfileError(f"Cannot read {target}: {exc.strerror or exc}") from exc
    return read_profile_text(text, default_name=target.stem)


def dump_profile_yaml(profile: PaceProfile) -> str:
    """The YAML a profile is saved as."""
    return _yaml().safe_dump(profile.to_document(), sort_keys=False, allow_unicode=True)


def _stamp(profile: PaceProfile, scope: str) -> PaceProfile:
    return replace(profile, profile_id=f"{scope}:{profile_slug(profile.name)}")


def _load_store(scope: str, directory: Path) -> list[SavedPaceProfile]:
    if not directory.is_dir():
        return []
    out: list[SavedPaceProfile] = []
    for path in sorted(directory.glob(f"*{PROFILE_SUFFIX}")):
        try:
            profile = read_profile_file(path)
        except SavedPaceProfileError:
            continue
        out.append(SavedPaceProfile(profile=_stamp(profile, scope), scope=scope, path=path))
    return out


def unreadable_profile_files(workspace_dir: str | os.PathLike[str] | None = None) -> list[tuple[Path, str]]:
    """Profile files that cannot be read, with the reason (for ``pace list``)."""
    dirs = [global_profiles_dir()]
    if workspace_dir:
        dirs.insert(0, workspace_profiles_dir(workspace_dir))
    bad: list[tuple[Path, str]] = []
    for directory in dirs:
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob(f"*{PROFILE_SUFFIX}")):
            try:
                read_profile_file(path)
            except SavedPaceProfileError as exc:
                bad.append((path, str(exc)))
    return bad


def list_profiles(
    workspace_dir: str | os.PathLike[str] | None = None, *, include_shadowed: bool = False
) -> list[SavedPaceProfile]:
    """Workspace profiles, then global ones, each by name; workspace wins on a name."""
    workspace = (
        _load_store(SCOPE_WORKSPACE, workspace_profiles_dir(workspace_dir)) if workspace_dir else []
    )
    slugs = {p.slug for p in workspace}
    global_: list[SavedPaceProfile] = []
    for saved in _load_store(SCOPE_GLOBAL, global_profiles_dir()):
        if saved.slug in slugs:
            if include_shadowed:
                global_.append(replace(saved, shadowed=True))
            continue
        global_.append(saved)
    by_name = lambda p: p.name.lower()  # noqa: E731 - local sort key
    return sorted(workspace, key=by_name) + sorted(global_, key=by_name)


def find_profile(
    name: str,
    workspace_dir: str | os.PathLike[str] | None = None,
    *,
    scope: str | None = None,
) -> SavedPaceProfile | None:
    """Find a profile by name or slug (case-insensitive); the workspace one first."""
    token = str(name or "").strip()
    if not token:
        return None
    lowered = token.lower()
    slug = profile_slug(token)
    for saved in list_profiles(workspace_dir):
        if scope and saved.scope != scope:
            continue
        if lowered == saved.name.lower() or slug == saved.slug:
            return saved
    return None


def require_profile(name: str, workspace_dir: str | os.PathLike[str] | None = None) -> SavedPaceProfile:
    """:func:`find_profile`, or an error listing the profiles that exist."""
    saved = find_profile(name, workspace_dir)
    if saved is None:
        names = ", ".join(p.name for p in list_profiles(workspace_dir)) or "none yet"
        raise SavedPaceProfileError(f"No pace profile named '{name}'. Saved profiles: {names}.")
    return saved


def save_profile(
    profile: PaceProfile,
    *,
    scope: str,
    workspace_dir: str | os.PathLike[str] | None = None,
    overwrite: bool = False,
) -> SavedPaceProfile:
    """Validate and save a profile; the revision increases on every overwrite.

    Raises:
        SavedPaceProfileError: Bad name or description, or an existing profile
            without ``overwrite``.
    """
    try:
        name = normalise_profile_name(profile.name)
    except PaceProfileError as exc:
        raise SavedPaceProfileError(str(exc)) from exc
    description = str(profile.description or "").strip()
    if len(description) > PROFILE_DESCRIPTION_MAX:
        raise SavedPaceProfileError(
            f"A pace profile description has at most {PROFILE_DESCRIPTION_MAX} characters."
        )
    directory = _store_dir(scope, workspace_dir)
    path = directory / f"{profile_slug(name)}{PROFILE_SUFFIX}"
    revision = 1
    if path.exists():
        if not overwrite:
            raise SavedPaceProfileError(
                f"A pace profile named '{name}' is already saved for {SCOPE_LABELS[scope]}. "
                "Add --force to replace it."
            )
        try:
            revision = read_profile_file(path).revision + 1
        except SavedPaceProfileError:
            revision = 1
    stored = replace(profile, name=name, description=description, revision=revision, profile_id="")
    # Round-trip through the validator so nothing unparseable is ever written.
    text = dump_profile_yaml(stored)
    read_profile_text(text)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)
    return SavedPaceProfile(profile=_stamp(stored, scope), scope=scope, path=path)


def delete_profile(
    name: str,
    *,
    workspace_dir: str | os.PathLike[str] | None = None,
    scope: str | None = None,
) -> SavedPaceProfile:
    """Delete a saved profile (the workspace one first when the name exists in both)."""
    saved = find_profile(name, workspace_dir, scope=scope)
    if saved is None:
        raise SavedPaceProfileError(f"No pace profile named '{name}'.")
    saved.path.unlink()
    return saved


__all__ = [
    "PROFILE_DIRNAME",
    "SAVE_SCOPES",
    "SCOPE_GLOBAL",
    "SCOPE_LABELS",
    "SCOPE_WORKSPACE",
    "SavedPaceProfile",
    "SavedPaceProfileError",
    "delete_profile",
    "dump_profile_yaml",
    "find_profile",
    "global_profiles_dir",
    "list_profiles",
    "profile_slug",
    "read_profile_file",
    "read_profile_text",
    "require_profile",
    "save_profile",
    "unreadable_profile_files",
    "workspace_profiles_dir",
]
