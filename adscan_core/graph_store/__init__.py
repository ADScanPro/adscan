"""Workspace graph store: raw inventory, runtime overlay and build state of one domain.

Import the record types from :mod:`adscan_core.graph_store.records` and the
interface plus the factory from :mod:`adscan_core.graph_store.interface`.
Design: ``docs/superpowers/specs/2026-11-12-inventory-first-graph-persistence.md``.
"""

from adscan_core.graph_store.interface import (
    GRAPH_STORE_DIRNAME,
    GraphStore,
    GraphStoreError,
    GraphStoreFrozenError,
    GraphStoreVersionError,
    UnitWriter,
    graph_store_dir,
    graph_store_exists,
    open_graph_store,
)
from adscan_core.graph_store.records import (
    GRAPH_STORE_SCHEMA_VERSION,
    DatumRecord,
    EdgeRef,
    ExportRecord,
    FactRecord,
    ObjectRecord,
    OverlayOp,
    StageRun,
    StoreGeneration,
    StoreStats,
)

__all__ = (
    "GRAPH_STORE_DIRNAME",
    "GRAPH_STORE_SCHEMA_VERSION",
    "DatumRecord",
    "EdgeRef",
    "ExportRecord",
    "FactRecord",
    "GraphStore",
    "GraphStoreError",
    "GraphStoreFrozenError",
    "GraphStoreVersionError",
    "ObjectRecord",
    "OverlayOp",
    "StageRun",
    "StoreGeneration",
    "StoreStats",
    "UnitWriter",
    "graph_store_dir",
    "graph_store_exists",
    "open_graph_store",
)
