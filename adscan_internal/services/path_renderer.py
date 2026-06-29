"""Audience-aware rendering of attack-path concepts.

This module is the single source of truth for the *strings* that the CLI
table, the PDF report and the web dashboard render for one attack path.
The canonical rule (CLAUDE.md § Nomenclature Standard) is:

* **CLI default = technical.** Pentesters see Tier 0/1/2 badges and raw
  BloodHound edge labels.
* **Report / web default = executive.** CISOs see business language, no
  raw edge labels in headlines.

The two implementations below — :class:`TechnicalRenderer` and
:class:`ExecutiveRenderer` — share a :class:`PathRenderer` Protocol so
call sites are pluggable. Adding a new audience (e.g. `Localized
ExecutiveRenderer` for an English vs Spanish report) only requires a new
class implementing the Protocol.

The executive translations of edges are delegated to
:mod:`adscan_internal.services.edge_phrasing` — never duplicate that
table here.
"""

from __future__ import annotations

from typing import Any, Literal, Mapping, Protocol

from adscan_internal.services.compromise_class import (
    CompromiseClass,
    compromise_reach_label,
)
from adscan_internal.services.edge_kind import EdgeKind, classify_edge_kind
from adscan_internal.services.edge_phrasing import translate_edge
from adscan_internal.services.path_state import PathState

Audience = Literal["technical", "executive"]


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


class PathRenderer(Protocol):
    """Audience-specific rendering surface for one attack path."""

    audience: Audience

    def render_class_label(self, cls: CompromiseClass) -> str:
        """Return the short label for a compromise class (badge text)."""

    def render_reach_label(self, cls: CompromiseClass) -> str:
        """Return the axis-2 Compromise Reach phrase for a path's class."""

    def render_state_label(self, state: PathState) -> str:
        """Return the customer-facing label for a path lifecycle state."""

    def render_edge(self, edge: Mapping[str, Any]) -> str:
        """Return the customer-facing label for one edge."""

    def render_path_title(self, path: Mapping[str, Any], idx: int) -> str:
        """Return the heading title for one path entry."""

    def render_section_heading(self, cls: CompromiseClass) -> str:
        """Return the section heading for a group of paths of one class."""


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


_PATH_STATE_TECHNICAL: dict[PathState, str] = {
    PathState.THEORETICAL: "theoretical",
    PathState.FOOTHOLD_OBTAINED: "foothold obtained",
    PathState.POST_EX_IN_PROGRESS: "post-ex in progress",
    PathState.POST_EX_FAILED: "post-ex failed",
    PathState.DOMAIN_COMPROMISED: "domain compromised",
}

_PATH_STATE_EXECUTIVE: dict[PathState, str] = {
    PathState.THEORETICAL: "Identified in graph, not executed",
    PathState.FOOTHOLD_OBTAINED: "Access confirmed",
    PathState.POST_EX_IN_PROGRESS: "Post-exploitation in progress",
    PathState.POST_EX_FAILED: "Post-exploitation blocked",
    PathState.DOMAIN_COMPROMISED: "Domain compromise confirmed",
}


def _hop_count(path: Mapping[str, Any]) -> int:
    """Return the shortest path length in *real* edges (excluding MemberOf)."""
    relations = path.get("relations")
    if not isinstance(relations, list):
        return 0
    count = 0
    for rel in relations:
        if classify_edge_kind(str(rel or "")) is EdgeKind.MEMBERSHIP:
            continue
        count += 1
    return count


def _detect_auth_protocol(path: Mapping[str, Any]) -> str:
    """Return the auth protocol used by the last AUTH edge of one path.

    Used by :meth:`TechnicalRenderer.render_path_title` for the
    ``Foothold on Tier 0`` title (CLAUDE.md mandatory format).
    """
    relations = path.get("relations")
    if not isinstance(relations, list):
        return ""
    last_auth = ""
    for rel in relations:
        if classify_edge_kind(str(rel or "")) is EdgeKind.AUTH:
            last_auth = str(rel)
    mapping = {
        "CanPSRemote": "WinRM",
        "CanRDP": "RDP",
        "AdminTo": "SMB",
        "ExecuteDCOM": "DCOM",
        "HasSession": "session",
        "SQLAdmin": "MSSQL",
    }
    return mapping.get(last_auth, last_auth or "")


def _path_compromise_class(path: Mapping[str, Any]) -> CompromiseClass:
    """Read the canonical compromise class from a materialized path dict."""
    raw = str(path.get("compromise_class") or "").strip().lower()
    for cls in CompromiseClass:
        if cls.value == raw:
            return cls
    # Fall back to legacy outcome_class string.
    legacy = str(path.get("outcome_class") or "").strip().lower()
    legacy_map = {
        "direct_compromise": CompromiseClass.DOMAIN_BREAKER,
        "direct_domain_control": CompromiseClass.DOMAIN_BREAKER,
        "domain_breaker": CompromiseClass.DOMAIN_BREAKER,
        "tier0_foothold": CompromiseClass.TIER0_FOOTHOLD,
        "followup_terminal": CompromiseClass.PRIVILEGED_ESCALATOR,
        "domain_compromise_enabler": CompromiseClass.PRIVILEGED_ESCALATOR,
        "privileged_escalator": CompromiseClass.PRIVILEGED_ESCALATOR,
        "high_impact_privilege": CompromiseClass.PRIVILEGED_ESCALATOR,
        "graph_extension": CompromiseClass.COMPROMISE_ENABLER,
        "compromise_enabler": CompromiseClass.COMPROMISE_ENABLER,
    }
    return legacy_map.get(legacy, CompromiseClass.NONE)


# ---------------------------------------------------------------------------
# Technical renderer (CLI default + web technical view)
# ---------------------------------------------------------------------------


_TECHNICAL_SECTION_HEADINGS: dict[CompromiseClass, str] = {
    CompromiseClass.DOMAIN_BREAKER: "Direct Domain Control",
    CompromiseClass.TIER0_FOOTHOLD: "Tier 0 Footholds",
    CompromiseClass.PRIVILEGED_ESCALATOR: "Privileged Escalators",
    CompromiseClass.COMPROMISE_ENABLER: "Compromise Enablers",
    CompromiseClass.NONE: "Pivot Opportunities",
}


class TechnicalRenderer:
    """CLI / web-technical renderer.

    Keeps raw BloodHound labels visible. The badge format follows
    CLAUDE.md § Nomenclature Standard (e.g. ``[T0/Foothold]``).
    """

    audience: Audience = "technical"

    def render_class_label(self, cls: CompromiseClass) -> str:
        return cls.cli_badge

    def render_reach_label(self, cls: CompromiseClass) -> str:
        # Axis 2 (Compromise Reach) — the SAME SSOT phrase the report and web
        # render, so the operator and the client deliverable agree on what a
        # path reaches. The CLI keeps its technical badge for the class; the
        # reach phrase is the shared plain-language axis.
        return compromise_reach_label(cls)

    def render_state_label(self, state: PathState) -> str:
        return _PATH_STATE_TECHNICAL.get(state, state.value)

    def render_edge(self, edge: Mapping[str, Any]) -> str:
        return str(edge.get("relation") or edge.get("kind_label") or "").strip() or "?"

    def render_path_title(self, path: Mapping[str, Any], idx: int) -> str:
        cls = _path_compromise_class(path)
        n = _hop_count(path)
        if cls is CompromiseClass.TIER0_FOOTHOLD:
            protocol = _detect_auth_protocol(path) or "auth"
            return f"Foothold on Tier 0 #{idx} · {protocol} · post-ex pending"
        return (
            f"Path to Domain Compromise #{idx} · {cls.cli_badge.strip('[]')} · "
            f"{n}-hop"
        )

    def render_section_heading(self, cls: CompromiseClass) -> str:
        return _TECHNICAL_SECTION_HEADINGS.get(cls, cls.display_label)


# ---------------------------------------------------------------------------
# Executive renderer (PDF report default + web CISO dashboard)
# ---------------------------------------------------------------------------


_EXECUTIVE_SECTION_HEADINGS: dict[CompromiseClass, str] = {
    CompromiseClass.DOMAIN_BREAKER: "Direct domain compromise",
    CompromiseClass.TIER0_FOOTHOLD: (
        "Critical access — control pending"
    ),
    CompromiseClass.PRIVILEGED_ESCALATOR: "Privileged escalations",
    CompromiseClass.COMPROMISE_ENABLER: (
        "Unprivileged accounts with a path to domain"
    ),
    CompromiseClass.NONE: "Pivot opportunities",
}


_EXECUTIVE_CLASS_LABELS: dict[CompromiseClass, str] = {
    CompromiseClass.DOMAIN_BREAKER: "Direct domain compromise",
    CompromiseClass.PRIVILEGED_ESCALATOR: "Privileged escalation",
    CompromiseClass.TIER0_FOOTHOLD: "Critical asset access (post-ex pending)",
    CompromiseClass.COMPROMISE_ENABLER: "Unprivileged account with a path to domain",
    CompromiseClass.NONE: "Standard",
}


class ExecutiveRenderer:
    """Report PDF / web-executive renderer.

    Translates every edge to business language via
    :func:`edge_phrasing.translate_edge`. No raw BloodHound labels are
    surfaced in headlines or section titles.
    """

    audience: Audience = "executive"

    def render_class_label(self, cls: CompromiseClass) -> str:
        return _EXECUTIVE_CLASS_LABELS.get(cls, cls.display_label)

    def render_reach_label(self, cls: CompromiseClass) -> str:
        # Axis 2 (Compromise Reach) — SSOT phrase, shared verbatim with the CLI
        # and platform so every surface speaks one reach vocabulary.
        return compromise_reach_label(cls)

    def render_state_label(self, state: PathState) -> str:
        return _PATH_STATE_EXECUTIVE.get(state, state.value)

    def render_edge(self, edge: Mapping[str, Any]) -> str:
        return translate_edge(str(edge.get("relation") or "")) or "Vector"

    def render_path_title(self, path: Mapping[str, Any], idx: int) -> str:
        cls = _path_compromise_class(path)
        n = _hop_count(path)
        if cls is CompromiseClass.TIER0_FOOTHOLD:
            protocol = _detect_auth_protocol(path) or "remote access"
            return (
                f"Critical access #{idx} · {protocol} · post-exploitation pending"
            )
        label = _EXECUTIVE_CLASS_LABELS.get(cls, cls.display_label)
        return f"Path to Domain Compromise #{idx} · {label} · {n}-hop"

    def render_section_heading(self, cls: CompromiseClass) -> str:
        return _EXECUTIVE_SECTION_HEADINGS.get(cls, cls.display_label)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def get_renderer(audience: Audience) -> PathRenderer:
    """Return the renderer matching ``audience``.

    Defaults must be set by the caller, not by this factory: the CLI
    chooses ``technical``, the report chooses ``executive``. There is no
    implicit "auto" — that policy belongs to the call site.
    """
    if audience == "technical":
        return TechnicalRenderer()
    if audience == "executive":
        return ExecutiveRenderer()
    raise ValueError(f"Unknown audience: {audience!r}")
