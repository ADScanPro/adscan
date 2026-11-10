"""Client copy for a route whose Tier-0 asset also reaches other domains.

On a multi-domain (forest or trust) workspace one Tier-0 asset can lead to the
compromise of several domains. The attack-path engine ends each domain's
listing in that domain and records the OTHER domains the same asset reaches on
the route as ``also_reaches_domains`` (``attack_graph_core.ALSO_REACHES_DOMAINS_KEY``):
a list of ``{"domain": "<plain.dotted.name>", "closure_length": <steps>}``.

This module is the ONE place that turns that field into the client sentence,
so the PRO report, the LITE report and the web CTEM read the same words.
Dependency-light (stdlib only) because the web backend imports it.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

__all__ = ["also_reaches_domain_names", "also_reaches_domains_line"]


def also_reaches_domain_names(value: Any) -> list[str]:
    """The plain dotted domain names in an ``also_reaches_domains`` field.

    Lower-cased, de-duplicated, order preserved (the engine emits them in its
    total seed order). Anything malformed is skipped, never raised on.
    """
    if not isinstance(value, Iterable) or isinstance(value, (str, bytes)):
        return []
    names: list[str] = []
    for entry in value:
        raw = entry.get("domain") if isinstance(entry, Mapping) else entry
        name = str(raw or "").strip().rstrip(".").lower()
        if name and name not in names:
            names.append(name)
    return names


def also_reaches_domains_line(value: Any) -> str:
    """The sentence a route entry carries, or ``""`` when it reaches no other domain."""
    names = also_reaches_domain_names(value)
    if not names:
        return ""
    if len(names) == 1:
        listed = names[0]
        closes = "closes both"
    else:
        listed = ", ".join(names[:-1]) + f" and {names[-1]}"
        closes = "closes all of them"
    return (
        f"This route also reaches {listed}. Fixing any step up to the Tier 0 "
        f"asset it passes through {closes}."
    )
