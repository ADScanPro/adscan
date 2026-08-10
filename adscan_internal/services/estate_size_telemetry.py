"""Estate-size counters for the scan telemetry events.

A field statistic derived from our own telemetry is only defensible if a
mislabelled workspace can be excluded from it: someone running an HTB box with
``workspace_type=audit`` is indistinguishable from a real corporate domain until
you can see the estate is twelve accounts wide. ``scan_complete`` carried no
size at all, so the lab-exclusion filter such a figure needs
(``user_count >= 150``) referenced a property that did not exist.

The counts come from the enumeration artefacts the scan already wrote —
``enabled_users.txt`` and ``enabled_computers.txt``, the same two files the
``environment_enumerated`` event counts — so the two events are directly
comparable and no extra AD query is issued. Counting non-empty lines in a text
file the scan just produced costs milliseconds; nothing here re-enumerates
anything, which is the point: a large scan must never pay for a recount just to
fill in an analytics property.

Only integers leave. An ``int`` passes the telemetry sanitizer verbatim, and no
account, host or domain name is ever read out of those files — the line COUNT is
the only thing that crosses the boundary.

``None`` means "never enumerated" (the artefact is absent — an unauthenticated
run, or one that never reached LDAP), which is deliberately not the same as
``0``. Emitting a zero there would be a wrong number rather than a missing one
and would drag down any median computed across audits.
"""

from __future__ import annotations

import os
from typing import Any, Optional

from adscan_internal.workspaces import domain_subpath

#: The enumeration artefacts the counts are read from, keyed by the telemetry
#: property they populate. Both events read this same mapping, so a rename can
#: never leave one event counting a file the other does not.
_ARTIFACT_BY_PROPERTY: dict[str, str] = {
    "user_count": "enabled_users.txt",
    "computer_count": "enabled_computers.txt",
}


def _count_nonempty_lines(path: str) -> Optional[int]:
    """Return the number of non-empty lines in ``path``, or ``None``.

    ``None`` is returned when the artefact does not exist or cannot be read, so
    a caller can tell "not enumerated" apart from "enumerated and empty".
    """
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            return sum(1 for line in handle if line.strip())
    except OSError:
        return None


def build_estate_size_properties(
    shell: Any, domain: str
) -> dict[str, Optional[int]]:
    """Return ``user_count`` / ``computer_count`` for one domain.

    Best-effort by construction: a missing workspace, a missing artefact or an
    unreadable file yields ``None`` for that count rather than raising, because
    this rides on a scan seam and must never break a scan.

    Args:
        shell: The active ``PentestShell`` (read for its workspace paths only).
        domain: The domain whose enumeration artefacts are counted.

    Returns:
        A mapping with ``user_count`` and ``computer_count``, each an ``int``
        when the matching artefact exists and ``None`` when it does not.
    """
    workspace_dir = getattr(shell, "current_workspace_dir", None) or os.getcwd()
    domains_dir = getattr(shell, "domains_dir", "domains")

    counts: dict[str, Optional[int]] = {}
    for property_name, filename in _ARTIFACT_BY_PROPERTY.items():
        try:
            path = domain_subpath(workspace_dir, domains_dir, domain, filename)
        except (OSError, TypeError, ValueError):
            counts[property_name] = None
            continue
        counts[property_name] = _count_nonempty_lines(path)
    return counts


__all__ = ["build_estate_size_properties"]
