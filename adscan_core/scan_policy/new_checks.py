"""Checks a saved policy gained since it was saved (the "new checks" notice).

A saved policy records the registry version it was saved against
(``ScanPolicyDefinition.saved_at_registry_version``). Every check carries the
registry version that introduced it (``CheckDefinition.introduced_in``). The
checks introduced after the policy was saved are the ones its author never saw:

* ``new_checks: follow_base`` (the default): they take the base's default, so
  some of them run without the author having chosen it;
* ``new_checks: disabled``: they stay off until someone turns them on.

Either way the user is told, on every surface that shows the policy (CLI
``policy show``, the ``start`` selector, the web policy card and editor), and
the report lists the new checks that ran under a policy nobody has reviewed
since. Reviewing (``policy review-new`` in the CLI, "Review" in the web)
re-saves the policy at the current registry version, which acknowledges them.
There is no separate policy version: the registry version is the version.

This module is pure (stdlib + the scan-policy core) so the CLI, the report and
the web backend share one derivation and one sentence.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Iterable

from adscan_core.scan_policy.model import (
    GROUP_LABELS,
    LOCKED_NEVER_EXECUTED,
)
from adscan_core.scan_policy.policy import (
    BASE_RULES,
    BUILTIN_LABELS,
    NEW_CHECKS_DISABLED,
    ScanPolicyDefinition,
)
from adscan_core.scan_policy.registry import CheckRegistry, load_registry
from adscan_core.scan_policy.resolve import ResolvedScanPolicy, resolve_policy


@dataclass(frozen=True)
class NewCheck:
    """One check introduced after the policy was saved."""

    check_id: str
    title: str
    group: str
    group_label: str
    introduced_in: int
    on: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "group": self.group,
            "group_label": self.group_label,
            "introduced_in": self.introduced_in,
            "on": self.on,
        }


@dataclass(frozen=True)
class NewChecksNotice:
    """What a saved policy gained since it was saved, and how it treats them."""

    saved_at_registry_version: int
    registry_version: int
    base: str
    base_label: str
    follows_base: bool
    checks: tuple[NewCheck, ...]

    @property
    def count(self) -> int:
        return len(self.checks)

    @property
    def on(self) -> int:
        return sum(1 for c in self.checks if c.on)

    @property
    def off(self) -> int:
        return self.count - self.on

    @property
    def line(self) -> str:
        """The one sentence every surface shows (empty when nothing arrived)."""
        return new_checks_line(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "saved_at_registry_version": self.saved_at_registry_version,
            "registry_version": self.registry_version,
            "base": self.base,
            "base_label": self.base_label,
            "follows_base": self.follows_base,
            "count": self.count,
            "on": self.on,
            "off": self.off,
            "checks": [c.to_dict() for c in self.checks],
        }


def _plural(count: int, one: str, many: str) -> str:
    return f"{count} {one if count == 1 else many}"


def new_checks_line(notice: Any) -> str:
    """Client-facing sentence for a notice mapping (``NewChecksNotice.to_dict()``)."""
    if not isinstance(notice, dict) or not int(notice.get("count") or 0):
        return ""
    count = int(notice["count"])
    head = f"This policy gained {_plural(count, 'check', 'checks')} since it was saved."
    if not notice.get("follows_base"):
        return f"{head} {'It stays' if count == 1 else 'They stay'} off until you turn them on."
    on, off = int(notice.get("on") or 0), int(notice.get("off") or 0)
    label = str(notice.get("base_label") or notice.get("base") or "its base")
    split = []
    if on:
        split.append(f"{on} {'is' if on == 1 else 'are'} on")
    if off:
        split.append(f"{off} {'is' if off == 1 else 'are'} off")
    return (
        f"{head} {'It follows' if count == 1 else 'They follow'} its base, {label}, "
        f"so {' and '.join(split)}."
    )


def new_checks_since_saved(
    definition: ScanPolicyDefinition | None,
    *,
    registry: CheckRegistry | None = None,
    resolved: ResolvedScanPolicy | None = None,
) -> NewChecksNotice | None:
    """The checks introduced after ``definition`` was saved, or ``None``.

    ``None`` for a built-in or an inline definition (``saved_at_registry_version``
    0: it always follows the current registry and has nothing to acknowledge)
    and for a policy saved at the current version. Checks ADscan never runs and
    paired detections (reported with their attack step) are not counted.
    """
    if definition is None or int(definition.saved_at_registry_version or 0) <= 0:
        return None
    reg = registry or load_registry()
    saved_at = int(definition.saved_at_registry_version)
    if saved_at >= int(reg.version):
        return None
    res = resolved or resolve_policy(definition, reg)
    checks = tuple(
        NewCheck(
            check_id=c.check_id,
            title=c.title or c.check_id,
            group=c.group,
            group_label=GROUP_LABELS.get(c.group, ""),
            introduced_in=int(c.introduced_in),
            on=c.check_id in res.effective_ids,
        )
        for c in reg.checks
        if int(c.introduced_in) > saved_at
        and c.locked_state != LOCKED_NEVER_EXECUTED
        and not c.is_paired_detection
    )
    if not checks:
        return None
    return NewChecksNotice(
        saved_at_registry_version=saved_at,
        registry_version=int(reg.version),
        base=definition.base,
        base_label=BUILTIN_LABELS.get(definition.base, definition.base),
        follows_base=definition.new_checks != NEW_CHECKS_DISABLED,
        checks=checks,
    )


def acknowledge_new_checks(
    definition: ScanPolicyDefinition,
    notice: NewChecksNotice,
    keep_on: Iterable[str],
    *,
    registry: CheckRegistry | None = None,
) -> ScanPolicyDefinition:
    """The definition with each new check pinned to the reviewer's choice.

    A check whose chosen state differs from what the base gives it becomes an
    explicit ``enabled`` / ``disabled`` entry, so re-saving the policy at the
    current registry version (which is what acknowledges the checks) changes
    nothing that runs unless the reviewer changed it. The caller re-saves; the
    CLI store and the web stamp the registry version on save.
    """
    reg = registry or load_registry()
    wanted_on = set(keep_on)
    base_rule = BASE_RULES[definition.base]
    enabled = list(definition.enabled)
    disabled = list(definition.disabled)
    for check in notice.checks:
        entry = reg.get(check.check_id)
        base_on = bool(base_rule(entry)) if entry is not None else False
        want = check.check_id in wanted_on
        enabled = [s for s in enabled if s != check.check_id]
        disabled = [s for s in disabled if s != check.check_id]
        if want and not base_on:
            enabled.append(check.check_id)
        elif not want and base_on:
            disabled.append(check.check_id)
    return replace(definition, enabled=tuple(enabled), disabled=tuple(disabled))


def unreviewed_checks_ran_line(notice: Any) -> str:
    """Report sentence naming the new checks that ran under a policy nobody reviewed.

    ``notice`` is ``NewChecksNotice.to_dict()``; only the checks that were on
    are named. Empty when none ran.
    """
    if not isinstance(notice, dict):
        return ""
    ran = [c for c in (notice.get("checks") or ()) if isinstance(c, dict) and c.get("on")]
    if not ran:
        return ""
    titles = ", ".join(str(c.get("title") or c.get("check_id")) for c in ran)
    if len(ran) == 1:
        return (
            "One check added to ADscan after this policy was saved ran under it before anyone "
            f"reviewed it, following the policy's base. It is {titles}."
        )
    return (
        f"{len(ran)} checks added to ADscan after this policy was saved ran under it before "
        f"anyone reviewed them, following the policy's base. They are {titles}."
    )


__all__ = (
    "acknowledge_new_checks",
    "NewCheck",
    "NewChecksNotice",
    "new_checks_line",
    "new_checks_since_saved",
    "unreviewed_checks_ran_line",
)
