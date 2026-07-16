"""Operator notification for the SMB share-collection stage — three states.

The share collection has three distinguishable outcomes, and conflating them is
exactly the bug this module exists to prevent: a connection abort that zeroed
coverage looks identical to a genuine "no shares" result unless it is surfaced.

* enumerated, genuinely empty   -> quiet (one info line)
* enumerated, shares found      -> the existing exposure panel (rendered elsewhere)
* enumeration failed / aborted  -> a loud warning panel listing the affected hosts

Shared by the collection-complete summary (``host_collector``) and the Phase 7
"SMB Share Exposure" entry (``share_exposure_phase``) so both surfaces agree on
the copy and the ``M of N`` count. Rendering goes through the ADscan output SSOTs
(``print_panel`` / ``print_info`` / ``print_warning``), so the ``_TeeConsole``
auto-mirrors every line into the session recording.
"""
from __future__ import annotations

from typing import Iterable, Literal

ShareCollectionState = Literal["aborted", "found", "empty"]


def classify_share_collection_state(
    *, aborted_count: int, share_count: int
) -> ShareCollectionState:
    """Map the share-stage counters to one of the three operator-facing states.

    ``aborted`` takes precedence: if ANY reached host had its share enumeration
    dropped, coverage is unknown and must be surfaced — even when other hosts
    returned shares. Only when nothing aborted do we split ``found`` (share access
    was proven) from ``empty`` (enumeration ran clean and there was nothing).
    """
    if aborted_count > 0:
        return "aborted"
    if share_count > 0:
        return "found"
    return "empty"


def _format_host_entries(aborted_hosts: Iterable[tuple[str, str]]) -> list[str]:
    """Bullet lines for the affected hosts (``hostname (ip)`` / ``hostname`` / ``ip``)."""
    entries: list[str] = []
    for host, ip in aborted_hosts:
        label = (host or "").strip()
        ip_s = (ip or "").strip()
        if label and ip_s:
            entries.append(f"  • {label} ({ip_s})")
        elif label:
            entries.append(f"  • {label}")
        elif ip_s:
            entries.append(f"  • {ip_s}")
    return entries


def _abort_counts(aborted_hosts: list[tuple[str, str]], reached_hosts: int) -> tuple[int, int]:
    """Return ``(affected, total)`` for the ``M of N`` headline, defensively clamped."""
    affected = max(len(aborted_hosts), 1)
    total = max(reached_hosts, affected)
    return affected, total


def build_share_abort_panel(aborted_hosts: list[tuple[str, str]], reached_hosts: int):
    """Build the loud ``(renderable, title)`` warning panel for the abort state.

    Content is assembled from ``rich.text.Text`` objects (no markup parsing) so an
    arbitrary hostname / IP can never raise a ``MarkupError``.
    """
    from rich.console import Group
    from rich.text import Text

    affected, total = _abort_counts(aborted_hosts, reached_hosts)
    lines: list[Text] = [
        Text(
            "The SMB connection was aborted mid-enumeration, so shares were NOT "
            "collected on:",
            style="yellow",
        )
    ]
    lines.extend(Text(entry) for entry in _format_host_entries(aborted_hosts))
    lines.append(Text(""))
    lines.append(
        Text(
            'Share exposure results are INCOMPLETE for these hosts — this is not '
            'a "no shares" result.',
            style="yellow",
        )
    )
    lines.append(
        Text("Re-run the SMB sweep to retry share collection on the affected hosts.")
    )
    title = (
        f"⚠  SMB share enumeration failed on {affected} of {total} "
        "reachable host(s)"
    )
    return Group(*lines), title


def emit_collection_complete_share_notice(
    *,
    aborted_hosts: list[tuple[str, str]],
    reached_hosts: int,
    share_count: int,
) -> None:
    """Surface 1 — the collection-complete share-stage notice (host collector).

    * ``aborted`` -> the loud warning panel (coverage incomplete).
    * ``empty``   -> one quiet info line confirming a clean, genuinely-empty result.
    * ``found``   -> stay quiet; the exposure panel renders the shares later.
    """
    from adscan_core.output import print_panel
    from adscan_core.rich_output import print_info

    state = classify_share_collection_state(
        aborted_count=len(aborted_hosts), share_count=share_count
    )
    if state == "aborted":
        content, title = build_share_abort_panel(aborted_hosts, reached_hosts)
        print_panel(content, title=title, border_style="yellow")
    elif state == "empty":
        print_info(
            "SMB share enumeration completed — no exposed shares found on "
            f"{max(reached_hosts, 0)} host(s)."
        )


def emit_phase_share_abort_notice(
    aborted_hosts: list[tuple[str, str]], reached_hosts: int
) -> None:
    """Surface 2 — Phase 7 "SMB Share Exposure" incomplete-collection warning.

    Rendered in place of the silent ``if not rows: return`` path so the phase's
    "Completed" is never read as "no exposure" when the enumeration actually
    aborted. Concise (the collection-complete panel already showed the detail).
    """
    from adscan_core.rich_output import print_warning

    affected, total = _abort_counts(aborted_hosts, reached_hosts)
    print_warning(
        f"SMB share enumeration failed on {affected} of {total} reachable host(s) "
        "during collection — share exposure results are INCOMPLETE, not a "
        '"no shares" result. Re-run the SMB sweep to retry the affected hosts.'
    )


__all__ = [
    "ShareCollectionState",
    "classify_share_collection_state",
    "build_share_abort_panel",
    "emit_collection_complete_share_notice",
    "emit_phase_share_abort_notice",
]
