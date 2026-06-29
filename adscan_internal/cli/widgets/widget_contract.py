"""Transport-neutral widget data contract — single source of truth.

A *widget* is structured, render-agnostic data the scan engine emits ONCE.
Both renderers — the CLI Rich renderer (``widget_render.py``) and the web
premium components (``adscan_web/frontend/components/widgets/``) — consume this
one contract. A new panel that fits an existing ``widget_type`` needs no new
render code on either side: the engine builds the payload and calls
``emit_widget`` (see ``adscan_internal/cli/ci_events.py``).

Why this module exists
----------------------
ADscan's CLI and the paid web product share one engine but historically each
panel was hand-built twice — once as a Rich panel, once as a React component —
and the two drifted every time the engine moved. This contract stops the
dual-development rot by sharing the *data*, not the rendering.

The three widget types cover the common panel shapes:

* ``finding-table`` — a list of findings/observations with a severity column.
  (Domain Hygiene Audit.)
* ``kpi-strip``     — a row of headline counts / metrics.
* ``matrix-panel``  — control → state/confidence rows grouped into sections.
  (Domain hardening Posture.)

Everything here is plain JSON-serialisable data: no Rich types, no LDAP types,
no engine objects. The same JSON travels over the structured event sink (live)
and into the persisted widget artifact (post-scan), and is ingested verbatim by
the web. ``WIDGET_SCHEMA_VERSION`` is stamped on every payload so a consumer can
detect a contract change.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

# Bump when the payload shape of any widget type changes in a way a consumer
# must notice. Stamped onto every emitted/persisted widget.
WIDGET_SCHEMA_VERSION = 1

WidgetType = Literal["finding-table", "kpi-strip", "matrix-panel"]

# The canonical set of widget types. The CLI renderer, the web WidgetRenderer,
# and the contract test all key off this exact set. Adding a type here (and a
# branch in both renderers) is the only way to extend the contract.
WIDGET_TYPES: tuple[WidgetType, ...] = (
    "finding-table",
    "kpi-strip",
    "matrix-panel",
)

# Severity / state tone vocabulary, reused across widget types so both
# renderers map one closed set of tokens to their own colour systems. Plain
# lowercase strings — never a Rich style or a CSS class.
Severity = Literal["critical", "high", "medium", "low", "info"]
SEVERITY_TOKENS: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

# State tone for matrix-panel rows. "secure" = hardening present, "permissive"
# = a weakness/downgrade, "neutral" = informational, "unknown" = not observed.
StateTone = Literal["secure", "permissive", "neutral", "unknown"]
STATE_TONES: tuple[str, ...] = ("secure", "permissive", "neutral", "unknown")


# --------------------------------------------------------------------------- #
# finding-table
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class FindingColumn:
    """One column in a ``finding-table``."""

    key: str
    label: str
    align: Literal["left", "right", "center"] = "left"


@dataclass(frozen=True)
class FindingRow:
    """One finding row.

    ``severity`` drives the leading badge and ordering. ``label`` is the human
    description of the observation. ``value`` is the headline count/metric for
    that row (e.g. ``"12/240 enabled users"``). ``privileged_count`` surfaces
    the Tier-0 / admin subset when relevant (0 → not rendered).
    """

    label: str
    value: str = ""
    severity: Severity = "info"
    privileged_count: int = 0
    detail: str = ""


@dataclass(frozen=True)
class FindingTableData:
    """Payload for ``widget_type == "finding-table"``."""

    rows: list[FindingRow] = field(default_factory=list)
    columns: list[FindingColumn] = field(default_factory=list)
    footnote: str = ""


# --------------------------------------------------------------------------- #
# kpi-strip
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class KpiItem:
    """One KPI cell in a ``kpi-strip``."""

    label: str
    value: str
    unit: str = ""
    hint: str = ""
    tone: StateTone = "neutral"


@dataclass(frozen=True)
class KpiStripData:
    """Payload for ``widget_type == "kpi-strip"``."""

    items: list[KpiItem] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# matrix-panel
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class MatrixRow:
    """One control row in a ``matrix-panel`` section."""

    label: str
    state: str
    state_tone: StateTone = "neutral"
    confidence: str = ""
    detail: str = ""


@dataclass(frozen=True)
class MatrixSection:
    """A labelled group of control rows."""

    label: str
    rows: list[MatrixRow] = field(default_factory=list)


@dataclass(frozen=True)
class MatrixPanelData:
    """Payload for ``widget_type == "matrix-panel"``."""

    sections: list[MatrixSection] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Envelope
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Widget:
    """The transport-neutral widget envelope emitted by the engine.

    ``key`` is stable per ``(domain, key)`` so a later emission for the same
    panel replaces the earlier one (live → post-scan reconciliation). ``data``
    is one of the ``*Data`` payloads above, already reduced to plain JSON.
    """

    widget_type: WidgetType
    key: str
    title: str
    data: dict[str, Any]
    domain: str | None = None
    schema_version: int = WIDGET_SCHEMA_VERSION

    def to_payload(self) -> dict[str, Any]:
        """Return the JSON-ready dict (event fields + persisted artifact body)."""
        return {
            "widget_type": self.widget_type,
            "key": self.key,
            "title": self.title,
            "domain": self.domain,
            "schema_version": self.schema_version,
            "data": self.data,
        }


def build_widget(
    widget_type: WidgetType,
    *,
    key: str,
    title: str,
    data: FindingTableData | KpiStripData | MatrixPanelData | dict[str, Any],
    domain: str | None = None,
) -> Widget:
    """Build a :class:`Widget`, reducing a typed payload dataclass to plain JSON.

    Accepts either one of the typed ``*Data`` dataclasses (preferred — the
    call site stays type-checked) or an already-plain dict (escape hatch for
    dynamically-shaped data). The result carries only JSON-serialisable values.

    Args:
        widget_type: One of :data:`WIDGET_TYPES`.
        key: Stable identifier, unique per ``(domain, key)``.
        title: Human-readable panel title.
        data: A typed payload dataclass or a plain dict.
        domain: Optional owning domain (rendered/scoped by consumers).

    Returns:
        A :class:`Widget` ready for ``to_payload()`` / emission / persistence.
    """
    if isinstance(data, dict):
        payload = data
    else:
        payload = asdict(data)
    return Widget(
        widget_type=widget_type,
        key=str(key),
        title=str(title),
        data=payload,
        domain=domain,
    )


__all__ = [
    "WIDGET_SCHEMA_VERSION",
    "WIDGET_TYPES",
    "WidgetType",
    "SEVERITY_TOKENS",
    "STATE_TONES",
    "Severity",
    "StateTone",
    "FindingColumn",
    "FindingRow",
    "FindingTableData",
    "KpiItem",
    "KpiStripData",
    "MatrixRow",
    "MatrixSection",
    "MatrixPanelData",
    "Widget",
    "build_widget",
]
