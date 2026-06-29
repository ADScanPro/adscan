"""Compose live + graph views of SMB shares into a unified operator model.

Two upstream services answer different questions about shares:

* :mod:`services.enumeration.smb_shares_native` answers
  *"what can the credential I am using right now actually do?"*
  via ``SMB tree_connect → maximal_access``.

* :mod:`services.collector.share_collector` answers
  *"who can do what to this share according to the security descriptor?"*
  and persists the result as ACL edges in ``attack_graph.json``.

Both are valuable; neither replaces the other. This composer fuses them
into a :class:`ShareView` per share with three perspectives — ``live``,
``graph``, and a computed :class:`ShareDelta` highlighting where the two
disagree (typically the highest-signal observation: the live credential
exceeds what the collector mapped, meaning the operator just discovered
access that the graph did not know about).

The composer is pure logic: no network, no I/O beyond what the upstream
services already produced. Tests can drive every delta case with mocked
inputs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from adscan_internal.services.enumeration.smb_shares_native import (
    NativeSharesResult,
    NativeShareEntry,
)
from adscan_internal.services.views._graph_share_reader import (
    GraphShareACL,
    GraphShareSnapshot,
)
from adscan_internal.services.collector.share_ntfs_verification import (
    VERIFICATION_SHARE_ACL_ONLY,
)


# ---------------------------------------------------------------------------
# Permission ordering — higher index implies the lower ones
# ---------------------------------------------------------------------------


_PERMISSION_LADDER = ("READ", "WRITE", "FULL_CONTROL")


def _permission_rank(perm: str) -> int:
    try:
        return _PERMISSION_LADDER.index(perm)
    except ValueError:
        return -1


def _max_permission(perms: List[str]) -> Optional[str]:
    """Return the highest-rank permission in ``perms`` (None if empty)."""
    best: Optional[str] = None
    best_rank = -1
    for p in perms:
        r = _permission_rank(p)
        if r > best_rank:
            best_rank = r
            best = p
    return best


def _live_to_ladder(perms: List[str]) -> Optional[str]:
    """Translate a live-access label set to the ladder rank (READ/WRITE/FC).

    The live probe uses labels like READ / WRITE / WRITE_DAC / EXECUTE.
    For comparison with the graph we collapse:

    * any of WRITE_DAC → FULL_CONTROL (write-DAC is GA-equivalent)
    * WRITE → WRITE
    * READ (without WRITE) → READ
    """
    if "WRITE_DAC" in perms:
        return "FULL_CONTROL"
    if "WRITE" in perms:
        return "WRITE"
    if "READ" in perms:
        return "READ"
    return None


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


class ShareDelta(str, Enum):
    """Result of comparing live access vs the graph ACL view.

    The semantics intentionally focus on the operator's question:
    "is the credential I am using right now telling me something the
    graph did not already know?".
    """

    ALIGNED = "aligned"
    """Live access matches what the graph implies for the credential."""

    LIVE_EXCEEDS_GRAPH = "live_exceeds_graph"
    """Operator has more access than any graph ACE explains. High signal:
    either a posture-collector ran with weaker creds, or this credential
    inherits access via a path the graph has not modeled (group membership
    not fully resolved, share-level deny ACE, etc.). Surface prominently.
    """

    GRAPH_EXCEEDS_LIVE = "graph_exceeds_live"
    """Graph maps higher-tier principals (e.g. Domain Admins: FULL_CONTROL)
    that this credential is not. Expected for non-privileged creds; useful
    to remind the operator what someone else could do.
    """

    NO_GRAPH_DATA = "no_graph_data"
    """No share-collector data exists for this share — the graph has not
    seen it. Common before the first scan or after a posture change."""

    NO_LIVE_DATA = "no_live_data"
    """The live probe failed for this share (denied, timeout). The view
    is graph-only."""

    INACCESSIBLE = "inaccessible"
    """Both live and graph agree the credential has no rights here."""


@dataclass
class ShareView:
    """Unified per-share view: live + graph + delta."""

    name: str
    type: str = ""
    remark: str = ""

    # Live perspective (current credential, right now)
    live_permissions: List[str] = field(default_factory=list)
    live_accessible: bool = True
    live_probe_error: Optional[str] = None
    live_present: bool = False

    # Graph perspective (collector ACL view, frozen at collection time)
    graph_acl: Optional[GraphShareACL] = None

    # Computed
    delta: ShareDelta = ShareDelta.NO_GRAPH_DATA
    delta_reason: Optional[str] = None

    # ---- derived ---------------------------------------------------------

    @property
    def is_writable_live(self) -> bool:
        return any(p in {"WRITE", "WRITE_DAC"} for p in self.live_permissions)

    @property
    def is_readable_live(self) -> bool:
        return "READ" in self.live_permissions

    @property
    def has_graph(self) -> bool:
        return self.graph_acl is not None and bool(self.graph_acl.principals)

    @property
    def graph_verification(self) -> str:
        """NTFS verification tier recorded by the collector for this share."""
        if self.graph_acl is None:
            return VERIFICATION_SHARE_ACL_ONLY
        return getattr(
            self.graph_acl, "verification", VERIFICATION_SHARE_ACL_ONLY
        )

    @property
    def is_graph_ntfs_verified(self) -> bool:
        """True when the graph access was confirmed against the NTFS ACL.

        ``share_acl_only`` graph access is a real lead but NTFS-unverified — a
        share-ACL grant can be overridden by a denying NTFS folder ACL, so the
        effective access may be lower than the graph implies.
        """
        return self.graph_acl is not None and getattr(
            self.graph_acl, "is_ntfs_verified", False
        )

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "type": self.type,
            "remark": self.remark,
            "live": {
                "present": self.live_present,
                "accessible": self.live_accessible,
                "permissions": list(self.live_permissions),
                "probe_error": self.live_probe_error,
            },
            "graph": self.graph_acl.to_dict() if self.graph_acl else None,
            "graph_verification": self.graph_verification,
            "is_graph_ntfs_verified": self.is_graph_ntfs_verified,
            "delta": self.delta.value,
            "delta_reason": self.delta_reason,
        }


@dataclass
class ShareViewSet:
    """All :class:`ShareView` records for one host plus provenance."""

    host: str
    views: List[ShareView] = field(default_factory=list)
    sources: Dict[str, str] = field(default_factory=dict)
    """Per-perspective status, e.g.::

        {
          "live":  "ok" | "denied" | "error" | "missing",
          "graph": "loaded" | "missing" | "host_not_found",
        }
    """
    live_error: Optional[str] = None
    """The raw live-probe error string for this host, when the probe failed.

    Holds the underlying error (e.g. an NTStatus string like
    ``NTStatus.ACCOUNT_LOCKED_OUT`` / ``STATUS_LOGON_FAILURE``) so a multi-host
    sweep can feed it into the shared :class:`SweepLockoutGuard` circuit-breaker
    and abort on a locked-out / rejected credential instead of re-asserting the
    lockout against every remaining host. ``None`` when the live probe
    succeeded or was not run. NOT serialized into ``to_dict`` (provenance, not
    share data)."""

    @property
    def counts(self) -> Dict[str, int]:
        total = len(self.views)
        readable = sum(1 for v in self.views if v.is_readable_live)
        writable = sum(1 for v in self.views if v.is_writable_live)
        live_exceeds = sum(
            1 for v in self.views if v.delta == ShareDelta.LIVE_EXCEEDS_GRAPH
        )
        return {
            "total": total,
            "readable": readable,
            "writable": writable,
            "live_exceeds_graph": live_exceeds,
            "no_graph_data": sum(
                1 for v in self.views if v.delta == ShareDelta.NO_GRAPH_DATA
            ),
        }

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "sources": dict(self.sources),
            "counts": self.counts,
            "views": [v.to_dict() for v in self.views],
        }


# ---------------------------------------------------------------------------
# Composer
# ---------------------------------------------------------------------------


def compose_share_views(
    *,
    host: str,
    live: Optional[NativeSharesResult] = None,
    graph: Optional[GraphShareSnapshot] = None,
) -> ShareViewSet:
    """Build a :class:`ShareViewSet` from the two upstream sources.

    Either source may be ``None``:

    * ``live=None`` — viewing graph data offline (``--graph`` mode).
    * ``graph=None`` — first-ever scan, or ``--live`` mode.
    * Both ``None`` — empty view set with ``sources`` showing both missing.

    The composer enumerates the union of share names across both sources
    so a share that exists only in the graph (because the live probe
    couldn't see it) still appears, and vice versa.
    """
    sources: Dict[str, str] = {
        "live": _live_status(live),
        "graph": "loaded" if graph is not None else "missing",
    }

    live_by_name: Dict[str, NativeShareEntry] = {}
    if live is not None:
        for entry in live.shares:
            live_by_name[entry.name] = entry

    graph_by_name: Dict[str, GraphShareACL] = {}
    if graph is not None:
        graph_by_name = dict(graph.shares)

    all_names = list(live_by_name.keys())
    for name in graph_by_name.keys():
        if name not in live_by_name:
            all_names.append(name)

    views: List[ShareView] = []
    for name in all_names:
        live_entry = live_by_name.get(name)
        graph_acl = graph_by_name.get(name)
        view = _compose_one(
            name=name,
            live_entry=live_entry,
            graph_acl=graph_acl,
            graph_loaded=graph is not None,
        )
        views.append(view)

    views.sort(key=_view_sort_key)

    return ShareViewSet(host=host, views=views, sources=sources)


def _live_status(live: Optional[NativeSharesResult]) -> str:
    if live is None:
        return "missing"
    return live.status


def _compose_one(
    *,
    name: str,
    live_entry: Optional[NativeShareEntry],
    graph_acl: Optional[GraphShareACL],
    graph_loaded: bool,
) -> ShareView:
    view = ShareView(name=name)

    if live_entry is not None:
        view.type = live_entry.type
        view.remark = live_entry.remark
        view.live_permissions = list(live_entry.permissions)
        view.live_accessible = live_entry.accessible
        view.live_probe_error = live_entry.probe_error
        view.live_present = True

    if graph_acl is not None:
        view.graph_acl = graph_acl
        if not view.type:
            view.type = ""

    view.delta, view.delta_reason = _compute_delta(
        live_entry=live_entry,
        graph_acl=graph_acl,
        graph_loaded=graph_loaded,
    )
    return view


def _compute_delta(
    *,
    live_entry: Optional[NativeShareEntry],
    graph_acl: Optional[GraphShareACL],
    graph_loaded: bool,
) -> tuple[ShareDelta, Optional[str]]:
    """Decide the delta classification and a short human-readable reason.

    The decision tree is intentionally explicit so consumers can audit the
    classification rules without tracing through bit fiddling.
    """
    live_perm = (
        _live_to_ladder(live_entry.permissions) if live_entry is not None else None
    )

    # Case 1 — no live data at all.
    if live_entry is None or not live_entry.accessible:
        if graph_acl is None or not graph_acl.principals:
            return ShareDelta.NO_LIVE_DATA, "Live probe failed and no graph ACL on file."
        return ShareDelta.NO_LIVE_DATA, "Live probe failed; showing graph ACL only."

    # Case 2 — graph data missing entirely.
    if not graph_loaded:
        return (
            ShareDelta.NO_GRAPH_DATA,
            "Attack graph not collected for this domain yet.",
        )
    if graph_acl is None:
        return (
            ShareDelta.NO_GRAPH_DATA,
            "Share absent from collector output — collector ran with weaker creds, "
            "share has no SD ACEs, or it was created after the last collection.",
        )
    if not graph_acl.principals:
        return (
            ShareDelta.NO_GRAPH_DATA,
            "Collector saw the share but recorded no ACL ACEs (sd_source: "
            f"{graph_acl.sd_source}).",
        )

    # Case 3 — live shows nothing meaningful.
    if live_perm is None:
        # Live is accessible but has no recognizable permissions (e.g. only
        # READ_CONTROL / EXECUTE). Treat as "inaccessible" semantically.
        if any(p.permissions for p in graph_acl.principals):
            return (
                ShareDelta.GRAPH_EXCEEDS_LIVE,
                "Graph maps principals with rights this credential does not have.",
            )
        return ShareDelta.INACCESSIBLE, "Neither live nor graph show rights."

    # Case 4 — compare live vs the maximum permission across all graph
    # principals. The graph captures rights for many subjects; here we ask
    # "what is the most powerful access anyone has?" — and compare with
    # what the live credential has.
    graph_max = _graph_max_permission(graph_acl)
    if graph_max is None:
        # Graph principals exist but none have a recognized permission.
        return ShareDelta.LIVE_EXCEEDS_GRAPH, (
            "Live access detected; graph ACEs do not map to any READ/WRITE/FC label."
        )

    if _permission_rank(live_perm) > _permission_rank(graph_max):
        return (
            ShareDelta.LIVE_EXCEEDS_GRAPH,
            f"Live={live_perm} exceeds graph maximum={graph_max} — "
            "credential has access not modeled in the graph.",
        )
    if _permission_rank(live_perm) < _permission_rank(graph_max):
        return (
            ShareDelta.GRAPH_EXCEEDS_LIVE,
            f"Graph maps higher-tier principals (max={graph_max}) than this "
            f"credential's live access ({live_perm}).",
        )
    return ShareDelta.ALIGNED, f"Live and graph maximum agree at {live_perm}."


def _graph_max_permission(acl: GraphShareACL) -> Optional[str]:
    best: Optional[str] = None
    best_rank = -1
    for principal in acl.principals:
        for perm in principal.permissions:
            rank = _permission_rank(perm)
            if rank > best_rank:
                best_rank = rank
                best = perm
    return best


def _view_sort_key(v: ShareView) -> tuple:
    """Sort: high-signal deltas first, then writable, readable, alphabetical.

    Keeps ``LIVE_EXCEEDS_GRAPH`` rows at the top of the operator table —
    that is the discovery the composer was built to surface.
    """
    delta_order = {
        ShareDelta.LIVE_EXCEEDS_GRAPH: 0,
        ShareDelta.NO_GRAPH_DATA: 1,
        ShareDelta.GRAPH_EXCEEDS_LIVE: 2,
        ShareDelta.ALIGNED: 3,
        ShareDelta.NO_LIVE_DATA: 4,
        ShareDelta.INACCESSIBLE: 5,
    }
    return (
        delta_order.get(v.delta, 99),
        0 if v.is_writable_live else 1,
        0 if v.is_readable_live else 1,
        v.name.lower(),
    )


__all__ = [
    "ShareDelta",
    "ShareView",
    "ShareViewSet",
    "compose_share_views",
]
