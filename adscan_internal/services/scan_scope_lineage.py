"""The asset scope a scan ran under, and how the current one differs from it.

A scan resumed under other lists than the ones it ran under mixes two
engagements in one result: hosts the client has since excluded keep what was
read from them, and hosts since added are skipped by the phases already
finished. Every resume decision asks ONE comparison,
:func:`asset_scope_change_since_scan`:

* ``adscan ci`` (unattended) resumes only when nothing changed, and starts
  clean otherwise (``cli/ci.py::ci_resume_decision``);
* the interactive offers (``cli/workspace_resume_offer.py``,
  ``cli/start_resume_frontdoor.py``) say what changed before the operator
  chooses, and a resume applies the change at the one seam where a resume
  starts (:func:`apply_asset_scope_change_on_resume`).

The scan record carries the DIGEST of the scope the scan last ran under
(``scan_progress.ASSET_SCOPE_DIGEST_KEY``). The lists themselves, needed to say
whether the scope was narrowed or widened, are kept beside the domain's data
(``<workspace>/domains/<domain>/scan_asset_scope.json``): they live and die with
the collected data, and a list of a hundred thousand entries never enters the
session's variables. A record with no such file (written before it existed, or
the file removed) is a change of unknown direction, treated as a widening.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

from adscan_core import telemetry
from adscan_core.engagement_scope_model import (
    AssetScope,
    narrowing_changes,
    widening_changes,
)
from adscan_core.rich_output import print_exception, print_info, print_info_debug

#: File beside a domain's data holding the scope its scan last ran under.
SCAN_SCOPE_FILENAME = "scan_asset_scope.json"


@dataclass(frozen=True)
class ScanScopeChange:
    """How the asset scope in force differs from the one a recorded scan ran under.

    Attributes:
        changed: The two scopes differ (their digests do).
        narrowed: The current scope excludes something the scan was allowed.
        widened: The current scope allows something the scan was not.
        known: The earlier lists could be read. ``False`` is a change of unknown
            direction: it is treated as a widening, the direction that matters.
        details: What changed, entry counts only (never an entry's value).
    """

    changed: bool = False
    narrowed: bool = False
    widened: bool = False
    known: bool = True
    details: tuple[str, ...] = ()

    @property
    def same(self) -> bool:
        """The scan ran under the scope in force now."""
        return not self.changed

    @property
    def may_add_assets(self) -> bool:
        """The current scope may hold assets the recorded scan never assessed."""
        return self.changed and (self.widened or not self.known)

    @property
    def direction(self) -> str:
        """``narrowed``, ``widened``, ``narrowed and widened``, ``changed`` or ``""``."""
        if not self.changed:
            return ""
        if not self.known:
            return "changed"
        if self.narrowed and self.widened:
            return "narrowed and widened"
        if self.widened:
            return "widened"
        if self.narrowed:
            return "narrowed"
        return "changed"

    def headline(self) -> str:
        """One line naming what changed (``""`` when nothing did)."""
        if not self.changed:
            return ""
        if not self.known:
            return (
                "The engagement scope changed since this scan ran, and the earlier "
                "lists are not on record, so the change is treated as a widening."
            )
        what = f" ({'; '.join(self.details)})" if self.details else ""
        if self.direction == "changed":
            return f"The engagement scope changed since this scan ran{what}."
        return f"The engagement scope was {self.direction} since this scan ran{what}."

    def resume_consequence(self, *, finished_phases_rerun: bool = False) -> str:
        """What continuing under the current scope does (``""`` when nothing changed).

        ``finished_phases_rerun`` is a replay: every phase runs again, the
        collection does not.
        """
        if not self.changed:
            return ""
        if not self.may_add_assets:
            return (
                "Continuing keeps what was collected. Nothing is sent to what the "
                "scope now excludes, and no step runs against it."
            )
        not_rerun = (
            "The collection is not run again"
            if finished_phases_rerun
            else "The collection and the phases already finished are not run again"
        )
        return (
            "Continuing keeps what was collected and holds every contact to the "
            f"current scope. {not_rerun}, so what the scope now adds is not assessed "
            "by them and the result is marked incomplete. Start a fresh scan to "
            "assess it in full."
        )


_UNCHANGED = ScanScopeChange()
_UNKNOWN_CHANGE = ScanScopeChange(changed=True, known=False)


def _snapshot_path(shell: Any, domain: str) -> str:
    workspace = str(getattr(shell, "current_workspace_dir", "") or "")
    if not workspace or not domain:
        return ""
    domains_dir = str(getattr(shell, "domains_dir", "domains") or "domains")
    return os.path.join(workspace, domains_dir, domain, SCAN_SCOPE_FILENAME)


def _current_scope(shell: Any) -> AssetScope | None:
    """The asset scope in force (``None``: none recorded). Raises when unreadable."""
    from adscan_internal.services.engagement_scope import asset_scope  # noqa: PLC0415

    scope = asset_scope(shell)
    if scope is not None and getattr(scope, "unreadable", False):
        raise ValueError("the engagement scope record cannot be read")
    return scope


def remember_scan_asset_scope(shell: Any, domain: str, digest: str) -> None:
    """Keep the lists the scan of ``domain`` runs under, beside the domain's data.

    Called when the scan record is stamped (``scan_progress.mark_scan_running``).
    Writes only when the file does not already hold ``digest``. With no scope in
    force the file is removed. Never raises: without the file a later comparison
    answers "changed, direction unknown", which is the careful reading.
    """
    path = _snapshot_path(shell, domain)
    if not path:
        return
    try:
        if not digest:
            if os.path.isfile(path):
                os.remove(path)
            return
        held = _read_snapshot(path)
        if held is not None and held[0] == digest:
            return
        scope = _current_scope(shell)
        if scope is None or scope.digest() != digest:
            return
        os.makedirs(os.path.dirname(path), exist_ok=True)
        temporary = f"{path}.tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump({"digest": digest, "scope": scope.to_dict()}, handle, separators=(",", ":"))
        os.replace(temporary, path)
    except Exception as exc:  # noqa: BLE001 - the snapshot is an aid, never a blocker
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def _read_snapshot(path: str) -> tuple[str, AssetScope] | None:
    """``(digest, scope)`` held in the snapshot file (``None``: absent or unusable)."""
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
        scope = AssetScope.from_dict(payload.get("scope"))
        digest = str(payload.get("digest") or "")
    except Exception:  # noqa: BLE001 - an unreadable snapshot is "direction unknown"
        return None
    if not digest or scope.digest() != digest:
        return None
    return digest, scope


def asset_scope_change_since_scan(shell: Any, domain: str) -> ScanScopeChange:
    """THE comparison every resume decision asks, unattended and interactive.

    Compares the scope ``domain``'s recorded scan ran under with the one in
    force now. Never raises: a scope that cannot be read is a change of unknown
    direction (a resume is then never assumed safe).
    """
    from adscan_internal.services import scan_progress  # noqa: PLC0415

    stored = str(
        scan_progress.read_scan_progress(shell, domain).get(scan_progress.ASSET_SCOPE_DIGEST_KEY) or ""
    )
    if stored == scan_progress.current_asset_scope_digest(shell):
        return _UNCHANGED
    try:
        current = _current_scope(shell) or AssetScope.create()
        if stored:
            held = _read_snapshot(_snapshot_path(shell, domain))
            if held is None or held[0] != stored:
                return _UNKNOWN_CHANGE
            earlier = held[1]
        else:
            earlier = AssetScope.create()
        widened = widening_changes(earlier, current)
        narrowed = narrowing_changes(earlier, current)
    except Exception as exc:  # noqa: BLE001 - an unknown change is never "the same scope"
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return _UNKNOWN_CHANGE
    return ScanScopeChange(
        changed=True,
        narrowed=bool(narrowed),
        widened=bool(widened),
        known=True,
        details=(*narrowed, *widened),
    )


def apply_asset_scope_change_on_resume(shell: Any, domain: str) -> ScanScopeChange:
    """A scan of ``domain`` is being resumed: hold it to the scope in force now.

    Called at the one seam where a resume starts. With an unchanged scope it
    does nothing. Otherwise:

    * every cached verdict is dropped, so each contact and each attack step is
      judged again under the current scope: nothing collected under the earlier
      scope is contacted or acted on if it is now outside;
    * when the current scope may hold assets the recorded scan never assessed,
      the work that will not run again (the collection and the finished phases)
      is marked incomplete with the reason ``asset_scope_widened``, so the
      result never reads as a complete assessment of the wider scope.

    Returns the change, for the caller's own line. Never raises.
    """
    return _hold_to_current_scope(
        shell, domain, asset_scope_change_since_scan(shell, domain), finished_phases_rerun=False
    )


def declare_replay_under_changed_scope(shell: Any, domain: str, change: ScanScopeChange) -> None:
    """A replay runs every phase again over the collected data: declare what it cannot.

    ``change`` is read by the caller BEFORE it drops the checkpoint (which holds
    the scope the data was collected under). Under a wider scope the phases run
    again, but the collection does not, so the collection is marked incomplete.
    """
    _hold_to_current_scope(shell, domain, change, finished_phases_rerun=True)


def _hold_to_current_scope(
    shell: Any, domain: str, change: ScanScopeChange, *, finished_phases_rerun: bool
) -> ScanScopeChange:
    if change.same:
        return change
    try:
        from adscan_internal.services import scan_progress  # noqa: PLC0415
        from adscan_internal.services.engagement_scope import (  # noqa: PLC0415
            invalidate_scope_verdicts,
        )

        invalidate_scope_verdicts(shell)
        print_info(
            f"Engagement scope: {change.headline()} "
            f"{change.resume_consequence(finished_phases_rerun=finished_phases_rerun)}"
        )
        if change.may_add_assets:
            scan_progress.declare_asset_scope_widened(
                shell, domain, finished_phases=not finished_phases_rerun
            )
        print_info_debug(
            f"[scope-lineage] resume under a changed scope: direction={change.direction!r} "
            f"known={change.known} finished_phases_rerun={finished_phases_rerun}"
        )
    except Exception as exc:  # noqa: BLE001 - the seams still judge every contact
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    return change


__all__ = [
    "SCAN_SCOPE_FILENAME",
    "ScanScopeChange",
    "apply_asset_scope_change_on_resume",
    "declare_replay_under_changed_scope",
    "asset_scope_change_since_scan",
    "remember_scan_asset_scope",
]
