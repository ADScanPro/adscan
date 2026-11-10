"""The attack-path execution offer, as relayed to a remote operator: one shape.

When an attended scan asks which mapped route to execute, the engine offers
only the routes whose first pending step may run (routes the scan policy
excludes or that act outside the engagement scope stay mapped, with a reason,
and are never a choice). The question reaches the web console as a relayed
``select`` prompt whose options are labels, numbered by position. The console
used to rebuild the list from its own route snapshot and map a route to an
option by ``route number - 1``: correct only when the offer happened to start
at route 1. When the engine offered routes 14 and 15 as options 0 and 1, no
route mapped to an option and the console kept "Execute selected path"
disabled, so the operator could only skip.

The offer therefore carries, in the prompt's ``context``, which route each
option IS and which mapped routes are not offered and why. The console renders
exactly that and answers with the option's own index. Standard library only:
the engine builds it, the web reads it.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, Mapping, Sequence

#: ``context`` key: one entry per offered route option, in option order.
OFFERED_PATHS_KEY = "offered_paths"
#: ``context`` key: the mapped routes shown in the listing that are NOT a choice.
MAPPED_NOT_OFFERED_KEY = "mapped_not_offered"


def display_label(label: str, domain: str | None) -> str:
    """A route endpoint as a client reads it, through the label SSOT.

    The raw engine label (``ADSCAN@NORTH.EXAMPLE``, ``Authenticated
    Users@WELLKNOWN``) stays the matching key; this is the text a console
    prints. Never raises: an unrenderable label is returned as it came.
    """
    text = str(label or "")
    if not text:
        return ""
    try:
        from adscan_core.reporting.principal_display import (  # noqa: PLC0415
            format_graph_node_label,
        )

        return format_graph_node_label(text, domain) or text
    except Exception:  # noqa: BLE001 - display only
        return text


def _route_fields(summary: Mapping[str, Any], domain: str | None = None) -> dict[str, str]:
    source = str(summary.get("source") or "")
    target = str(summary.get("target") or "")
    return {
        "source": source,
        "target": target,
        "source_display": display_label(source, domain),
        "target_display": display_label(target, domain),
        "status": str(summary.get("status") or ""),
    }


def _not_offered_reason(summary: Mapping[str, Any]) -> str:
    meta = summary.get("meta") if isinstance(summary.get("meta"), Mapping) else {}
    return str((meta or {}).get("execution_support_reason") or "").strip()


def build_path_offer_context(
    summaries: Sequence[Mapping[str, Any]],
    offer_indices: Iterable[int],
    *,
    max_display: int,
    offerable: Callable[[Mapping[str, Any]], bool],
    domain: str | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """The ``context`` entries describing one execution offer.

    ``offer_indices`` are the summary indices offered, in option order, so the
    option at position ``i`` is route number ``offer_indices[i] + 1`` (the
    number the listing and the option label print). Mapped routes in the
    displayed window that ``offerable`` rejects are listed with the reason the
    readiness overlay recorded. Each entry carries the raw endpoints (the
    console matches graph routes on them) and their ``*_display`` form.
    """
    offered = [
        {"option_index": position, "path_number": idx + 1, **_route_fields(summaries[idx], domain)}
        for position, idx in enumerate(offer_indices)
    ]
    mapped = [
        {
            "path_number": idx + 1,
            **_route_fields(summary, domain),
            "reason": _not_offered_reason(summary),
        }
        for idx, summary in enumerate(summaries[:max_display])
        if not offerable(summary)
    ]
    return {OFFERED_PATHS_KEY: offered, MAPPED_NOT_OFFERED_KEY: mapped}
