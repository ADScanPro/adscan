"""How many rows a folded attack-path listing shows, and how many routes they hold.

A domain listing folds same-story routes that reach one terminal by one edge
sequence from several entry points into ONE row
(``attack_graph_core.fold_origin_stories``), stamping the number of routes the
row stands for as ``origin_route_count``. A count of the rows alone ("Attack
Paths Found: 7") then disagrees with every surface that counts each entry point
(the final summary's "10 routes"), with nothing on screen saying why.

This module states both numbers in ONE sentence, so the CLI listing and the web
CTEM listing word a folded listing identically. Pure and stdlib-only: the
engine, the console renderer in ``adscan_core.output`` and the web backend all
import it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping


@dataclass(frozen=True)
class FoldedRouteCount:
    """Rows shown versus routes they represent.

    Attributes:
        rows: Listing rows after the origin fold.
        routes: Routes those rows stand for, counting each entry point
            (the sum of every row's ``origin_route_count``, 1 when absent).
    """

    rows: int
    routes: int

    @property
    def folded(self) -> bool:
        """True when at least one row stands for more than one route."""
        return self.routes > self.rows

    def phrase(self) -> str:
        """Return ``"7"`` or ``"7 routes (10 counting each entry point)"``.

        The bare number when nothing folded, so an unfolded listing reads as it
        always did.
        """
        if not self.folded:
            return f"{self.rows:,}"
        noun = "route" if self.rows == 1 else "routes"
        return f"{self.rows:,} {noun} ({self.routes:,} counting each entry point)"


def _origin_route_count(record: Mapping[str, Any]) -> int:
    try:
        value = int(record.get("origin_route_count") or 1)
    except (TypeError, ValueError):
        return 1
    return max(1, value)


def folded_route_count(records: Iterable[Any]) -> FoldedRouteCount:
    """Count rows and the routes they stand for over a (possibly folded) listing."""
    rows = 0
    routes = 0
    for record in records or ():
        if not isinstance(record, Mapping):
            continue
        rows += 1
        routes += _origin_route_count(record)
    return FoldedRouteCount(rows=rows, routes=routes)


def folded_route_count_phrase(records: Iterable[Any]) -> str:
    """Shorthand for ``folded_route_count(records).phrase()``."""
    return folded_route_count(records).phrase()


__all__ = [
    "FoldedRouteCount",
    "folded_route_count",
    "folded_route_count_phrase",
]
