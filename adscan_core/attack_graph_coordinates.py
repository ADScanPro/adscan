"""The scan coordinates stamped on the root of ``attack_graph.json``.

``save_attack_graph`` stamps the values a verification command is filled with
(the domain, the DC's address and DNS name, the NetBIOS name, the account the
scan authenticated as, the certification authority). None of them is a
secret. Every reader that renders an edge's technique text reads them through
:class:`GraphCoordinates`, so the engine, the web edge panel and the web
ingestion that keeps them for that panel agree on the set.

Lives in ``adscan_core`` because the web ingestion projection imports no
``adscan_internal``; ``adscan_internal.services.edge_knowledge`` re-exports it.
Stdlib only.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, fields
from typing import Any

#: ``DomainRecord.stats`` key under which the web keeps a domain's coordinates.
GRAPH_COORDINATES_STATS_KEY = "graph_coordinates"


@dataclass(frozen=True)
class GraphCoordinates:
    """The graph-level values a command is filled with. Never a secret.

    Read from the root of ``attack_graph.json`` (``from_graph``) so a reader
    with only the file renders the same commands as the engine.
    """

    domain: str = ""
    dc_ip: str = ""
    dc_fqdn: str = ""
    netbios: str = ""
    scan_principal: str = ""
    ca_name: str = ""
    ca_host: str = ""

    @classmethod
    def from_graph(cls, graph: Mapping[str, Any] | None) -> GraphCoordinates:
        """Coordinates stamped on a graph document's root (or a stored copy)."""
        if not isinstance(graph, Mapping):
            return cls()
        return cls(**{f.name: str(graph.get(f.name) or "").strip() for f in fields(cls)})

    def as_dict(self) -> dict[str, str]:
        """The non-empty coordinates, keyed as on the graph root."""
        return {f.name: value for f in fields(self) if (value := getattr(self, f.name))}

    def verification_env(self) -> dict[str, str]:
        """The coordinates under the step-detail keys the catalog fills from."""
        env: dict[str, str] = {}
        for attribute, details_key in (
            ("dc_ip", "dc_ip"),
            ("domain", "domain"),
            ("dc_fqdn", "dc_fqdn"),
            ("netbios", "netbios_domain"),
            ("scan_principal", "scan_principal"),
            ("ca_name", "ca_name"),
            ("ca_host", "ca_host"),
        ):
            value = getattr(self, attribute)
            if value:
                env[details_key] = value
        return env


__all__ = ("GRAPH_COORDINATES_STATS_KEY", "GraphCoordinates")
