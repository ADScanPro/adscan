"""Didactic mode — teach each attack technique as it runs.

ADscan is also a **learning tool**: a junior who runs it on an HTB box should
come away understanding the attack, and a senior who meets an unfamiliar
technique should get the by-hand equivalent and the defensive angle without
leaving the shell. This module is the SINGLE source of truth for that teaching
UX. It renders a technique "card" from the attack-step catalog — never from
per-technique hardcoded strings — so a new technique added to the catalog with
its didactic content (narrative, MITRE, detection Event IDs, manual command,
remediation) inherits the explanation automatically.

Consumers:

* ``adscan_internal/cli/attack_path_execution.py`` — shows the card BEFORE the
  "Execute this attack path now?" prompt, at the resolved level, so the operator
  sees what is about to run and why.
* the ``explain`` REPL command — renders the full ``deep`` card for a technique
  on demand, without executing anything.

Three levels (:class:`ExplainLevel`):

* ``OFF``   — render nothing (senior operator, ``--quiet`` / ``set explain_level off``).
* ``BASIC`` — one line ("what it does + why") before each technique. Default for
  ``type=audit`` engagements: it orients a learner without slowing an operator.
* ``DEEP``  — full card: what the technique is + why it works, the manual command
  with the standard tool, MITRE ATT&CK id/name, and how it is detected. Default
  for ``type=ctf`` (lab / HTB) workspaces, where people are there to learn.

The default-by-type + the flag/command override live in :func:`resolve_explain_level`.
"""

from __future__ import annotations

import os
from enum import Enum
from typing import Any

from rich import box
from rich.console import Group, RenderableType
from rich.padding import Padding
from rich.panel import Panel
from rich.text import Text

from adscan_core.theme import (
    ADSCAN_PRIMARY,
    ADSCAN_PRIMARY_BRIGHT,
    COLOR_AMBER,
    COLOR_MUTED,
    COLOR_STEEL,
)
from adscan_internal.services.attack_step_catalog import (
    get_attack_step_entry,
    render_step_manual_command,
    render_step_narrative,
    render_step_verify,
)


# Roles that run / defend their OWN estate — the didactic card leads with the
# DEFENSIVE angle for them (how it is detected + the native Windows command they
# would actually run), rather than the offensive Linux tooling. Every other role
# (consultant / pentester / student / other / unknown) keeps the offensive lead.
_DEFENSIVE_ROLES: frozenset[str] = frozenset(
    {
        "sysadmin_blue_team",
        "security_manager_ciso",
    }
)


def _didactic_emphasis_is_defensive() -> bool:
    """Return True when the persisted operator role wants the defensive lead.

    Reads the local role profile; a defender / own-estate role emphasises
    detection + the native Windows verification command. Never raises — an
    unknown / unreadable role falls back to the offensive lead (the default).
    """
    try:
        from adscan_internal.services.operator_role_profile import get_operator_role

        return get_operator_role() in _DEFENSIVE_ROLES
    except Exception:  # noqa: BLE001
        return False


class ExplainLevel(str, Enum):
    """How much technique explanation the interactive flow renders."""

    OFF = "off"
    BASIC = "basic"
    DEEP = "deep"

    @classmethod
    def coerce(cls, value: Any) -> "ExplainLevel | None":
        """Parse a user/config value into a level, or ``None`` when unset/invalid."""
        if isinstance(value, ExplainLevel):
            return value
        text = str(value or "").strip().lower()
        if not text:
            return None
        # Friendly aliases so `--learn` / `--quiet` map cleanly.
        aliases = {
            "learn": cls.DEEP,
            "full": cls.DEEP,
            "verbose": cls.DEEP,
            "quiet": cls.OFF,
            "none": cls.OFF,
            "one-line": cls.BASIC,
            "oneline": cls.BASIC,
            "short": cls.BASIC,
        }
        if text in aliases:
            return aliases[text]
        try:
            return cls(text)
        except ValueError:
            return None


#: Default level per workspace type. CTF / lab is where people LEARN, so it
#: defaults to the full card; an audit engagement defaults to a one-liner that
#: orients without slowing the operator down.
_DEFAULT_LEVEL_BY_TYPE: dict[str, ExplainLevel] = {
    "ctf": ExplainLevel.DEEP,
    "lab": ExplainLevel.DEEP,
    "training": ExplainLevel.DEEP,
    "audit": ExplainLevel.BASIC,
    "pentest": ExplainLevel.BASIC,
    "red_team": ExplainLevel.OFF,
}


def default_level_for_type(workspace_type: Any) -> ExplainLevel:
    """Return the didactic default for a workspace type (``shell.type``)."""
    key = str(workspace_type or "").strip().lower()
    return _DEFAULT_LEVEL_BY_TYPE.get(key, ExplainLevel.BASIC)


def resolve_explain_level(shell: Any) -> ExplainLevel:
    """Resolve the effective didactic level for this session.

    Precedence (first match wins):

    1. ``ADSCAN_EXPLAIN_LEVEL`` env var (off|basic|deep or an alias) — lets the
       non-interactive ``ci`` runner and the web worker pin a level.
    2. An explicit per-session override the operator set (``set explain_level …``
       / ``--learn`` / ``--quiet``), stored on ``shell.explain_level``.
    3. The default for the workspace type (``shell.type``): ctf/lab → deep,
       audit/pentest → basic, red_team → off.

    Never raises — an unreadable shell falls back to ``BASIC``.
    """
    env = ExplainLevel.coerce(os.environ.get("ADSCAN_EXPLAIN_LEVEL"))
    if env is not None:
        return env
    override = ExplainLevel.coerce(getattr(shell, "explain_level", None))
    if override is not None:
        return override
    return default_level_for_type(getattr(shell, "type", None))


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

#: Placeholder tokens the catalog manual-command strings use for values ADscan
#: resolves at runtime but a learner substitutes by hand.
_TEACHING_BORDER = ADSCAN_PRIMARY


def _step_relation(step_or_relation: Any) -> str:
    """Extract the relation name from a step dict or a bare relation string."""
    if isinstance(step_or_relation, str):
        return step_or_relation
    if isinstance(step_or_relation, dict):
        return str(
            step_or_relation.get("action")
            or step_or_relation.get("relation")
            or step_or_relation.get("type")
            or ""
        )
    return ""


def _technique_title(entry: Any) -> str:
    """Human title for the card header — prefer the MITRE name, else the relation."""
    mitre_name = str(getattr(entry, "mitre_technique_name", "") or "").strip()
    if mitre_name:
        return mitre_name
    relation = str(getattr(entry, "relation", "") or "").strip()
    return relation.replace("_", " ").title() or "Attack technique"


def render_basic_line(step_or_relation: Any) -> Text | None:
    """Build the one-line ``BASIC`` explanation for a step.

    "What it does + why", drawn from the catalog short narrative (which names the
    principals in this concrete path) with the technique's own description as the
    fallback. Returns ``None`` when the catalog has nothing to say, so the caller
    prints nothing rather than an empty line.
    """
    relation = _step_relation(step_or_relation)
    entry = get_attack_step_entry(relation)
    if entry is None:
        return None

    sentence = ""
    if isinstance(step_or_relation, dict):
        sentence = render_step_narrative(step_or_relation, short=True) or ""
    if not sentence:
        sentence = str(getattr(entry, "short_narrative_template", "") or "").strip()
    if not sentence:
        sentence = str(getattr(entry, "description", "") or "").strip()
    if not sentence:
        return None

    line = Text()
    line.append("  ┃ ", style=_TEACHING_BORDER)
    line.append("Learn  ", style=f"bold {ADSCAN_PRIMARY_BRIGHT}")
    line.append(sentence, style="default")
    mitre_id = str(getattr(entry, "mitre_technique_id", "") or "").strip()
    if mitre_id:
        line.append(f"   [{mitre_id}]", style=COLOR_MUTED)
    return line


def _section(pieces: list[RenderableType], heading: str, body: RenderableType) -> None:
    """Append a titled section to the card body."""
    head = Text()
    head.append(heading, style=f"bold {ADSCAN_PRIMARY_BRIGHT}")
    pieces.append(head)
    if isinstance(body, str):
        pieces.append(Text(body, style="default"))
    else:
        pieces.append(body)
    pieces.append(Text())


def _render_manual_command(command: str) -> RenderableType:
    """Render a multi-line manual command block, dimming comment lines."""
    body = Text()
    lines = command.splitlines()
    for idx, raw in enumerate(lines):
        stripped = raw.rstrip()
        if idx:
            body.append("\n")
        if stripped.lstrip().startswith("#"):
            body.append(stripped, style=COLOR_MUTED)
        else:
            body.append(stripped, style=f"bold {COLOR_STEEL}")
    return body


def render_deep_card(step_or_relation: Any) -> Panel | None:
    """Build the full ``DEEP`` teaching card for a step.

    Sections (each omitted when the catalog has no content for it):

    * **What it is** — the technique narrative (why it works), rendered against
      this path's real principals when a step dict is supplied.
    * **Try it by hand** — the manual command with the standard offensive tool.
    * **Check it on Windows** — the native Microsoft / PowerShell verification
      command (defensive lead only).
    * **MITRE ATT&CK** — technique id + name.
    * **How it's detected** — the Windows Event IDs a SOC watches for.

    The section ORDER adapts to the persisted operator role: a defender /
    own-estate operator (sysadmin / blue team / CISO) leads with detection + the
    native Windows check, then the offensive command; every other operator
    (consultant / pentester / student / unknown) leads with the offensive command.
    The content is the same; only the emphasis changes.

    Returns ``None`` when the relation is unknown to the catalog.
    """
    relation = _step_relation(step_or_relation)
    entry = get_attack_step_entry(relation)
    if entry is None:
        return None

    defensive = _didactic_emphasis_is_defensive()

    # Each section is built once into its own piece list, then assembled in an
    # order chosen by the operator's role. A defender / own-estate operator leads
    # with detection + the native Windows command; every other operator leads with
    # the offensive "try it by hand". The content is identical either way — only
    # the emphasis (ordering, and which command headlines) changes.
    what: list[RenderableType] = []
    offensive_cmd: list[RenderableType] = []
    defensive_cmd: list[RenderableType] = []
    mitre_section: list[RenderableType] = []
    detection: list[RenderableType] = []

    # What it is / why it works.
    narrative = ""
    if isinstance(step_or_relation, dict):
        narrative = render_step_narrative(step_or_relation, short=False) or ""
    if not narrative:
        narrative = str(getattr(entry, "narrative_template", "") or "").strip()
    if not narrative:
        narrative = str(getattr(entry, "description", "") or "").strip()
    if narrative:
        _section(what, "What it is", narrative)

    # Offensive manual command with the standard tool. For a concrete step,
    # substitute the real principal/target names; for a bare relation, show the
    # template as-is.
    manual = ""
    if isinstance(step_or_relation, dict):
        manual = render_step_manual_command(step_or_relation) or ""
    if not manual:
        manual = str(getattr(entry, "manual_command", "") or "").strip()
    manual = manual.strip()
    if manual:
        _section(
            offensive_cmd,
            "Try it by hand",
            _render_manual_command(manual),
        )

    # Native Windows verification command — the one a defender actually runs. Only
    # surfaced (as its own section) for the defensive lead; for the offensive lead
    # it stays in the report's independent-verification block, not the card.
    if defensive and isinstance(step_or_relation, dict):
        verify_windows = (render_step_verify(step_or_relation).get("windows") or "").strip()
        if verify_windows:
            _section(
                defensive_cmd,
                "Check it on Windows",
                _render_manual_command(verify_windows),
            )

    # MITRE ATT&CK.
    mitre_id = str(getattr(entry, "mitre_technique_id", "") or "").strip()
    mitre_name = str(getattr(entry, "mitre_technique_name", "") or "").strip()
    if mitre_id or mitre_name:
        mitre = Text()
        if mitre_id:
            mitre.append(mitre_id, style="bold " + COLOR_AMBER)
        if mitre_id and mitre_name:
            mitre.append("  ·  ", style="dim")
        if mitre_name:
            mitre.append(mitre_name, style="default")
        _section(mitre_section, "MITRE ATT&CK", mitre)

    # Detection.
    event_ids = tuple(getattr(entry, "detection_event_ids", ()) or ())
    if event_ids:
        det = Text()
        det.append("Windows Event ID(s): ", style="default")
        det.append(", ".join(str(e) for e in event_ids), style="bold " + COLOR_STEEL)
        _section(detection, "How it's detected", det)

    if defensive:
        # Defender lead: what it is → how it's detected → the native Windows check
        # → MITRE → the offensive command (kept, so they understand the attack).
        ordered = [what, detection, defensive_cmd, mitre_section, offensive_cmd]
    else:
        # Offensive lead (default): what it is → try it by hand → MITRE → detection.
        ordered = [what, offensive_cmd, mitre_section, detection]

    pieces: list[RenderableType] = []
    for section in ordered:
        pieces.extend(section)

    if not pieces:
        return None

    # Drop the trailing blank line the last _section adds.
    if isinstance(pieces[-1], Text) and not str(pieces[-1]):
        pieces.pop()

    title = Text()
    title.append("◆  ", style=ADSCAN_PRIMARY_BRIGHT)
    title.append(_technique_title(entry), style="bold default")

    return Panel(
        Padding(Group(*pieces), (1, 2)),
        title=title,
        subtitle=Text("ADscan · learn as you scan", style=COLOR_MUTED),
        subtitle_align="right",
        border_style=_TEACHING_BORDER,
        box=box.ROUNDED,
    )


def explain_step(shell: Any, step_or_relation: Any, *, level: ExplainLevel | None = None) -> bool:
    """Render the didactic explanation for a step at the session's level.

    Prints the one-liner (``BASIC``) or the full card (``DEEP``) to the shell
    console; renders nothing at ``OFF``. Best-effort: never raises into the scan
    flow (a rendering error must not abort execution). Returns True when
    something was printed.

    ``level`` overrides the resolved session level (used by ``explain <tech>``,
    which always wants the full ``DEEP`` card regardless of session default).
    """
    effective = level if level is not None else resolve_explain_level(shell)
    if effective == ExplainLevel.OFF:
        return False
    try:
        from adscan_internal import get_console  # noqa: PLC0415

        console = get_console()
        if effective == ExplainLevel.BASIC:
            line = render_basic_line(step_or_relation)
            if line is None:
                return False
            console.print(line)
            return True
        card = render_deep_card(step_or_relation)
        if card is None:
            return False
        console.print(card)
        return True
    except Exception:  # noqa: BLE001 — teaching must never break the scan
        return False


# --------------------------------------------------------------------------- #
# `explain <technique>` command support (on-demand card, no execution)
# --------------------------------------------------------------------------- #


def _normalize_query(text: str) -> str:
    """Lowercase and strip separators so 'ADCS ESC1' == 'adcsesc1' == 'adcs-esc1'."""
    return "".join(ch for ch in str(text or "").lower() if ch.isalnum())


def resolve_technique(query: str) -> Any:
    """Resolve a user query ('kerberoasting', 'ADCS ESC1', 'dcsync') to an entry.

    Tries the catalog's own relation lookup first (handles aliases + punctuation),
    then a normalized match against every catalog relation and its MITRE name.
    Returns the :class:`AttackStepCatalogEntry` or ``None``.
    """
    entry = get_attack_step_entry(query)
    if entry is not None:
        return entry
    from adscan_internal.services.attack_step_catalog import (  # noqa: PLC0415
        ATTACK_STEP_CATALOG,
    )

    norm = _normalize_query(query)
    if not norm:
        return None
    for candidate in ATTACK_STEP_CATALOG.values():
        if _normalize_query(candidate.relation) == norm:
            return candidate
        mitre = _normalize_query(getattr(candidate, "mitre_technique_name", "") or "")
        if mitre and norm in mitre:
            return candidate
    return None


def list_explainable_techniques() -> list[tuple[str, str]]:
    """Return ``(relation, title)`` for every technique with didactic content.

    A technique is "explainable" when it has a narrative or a manual command —
    the two things the card is built from. Sorted by category then relation.
    Used by ``explain`` with no argument to show what can be explained.
    """
    # Iterate the ENRICHED catalog (narratives + manual commands applied via the
    # overlay merge), not the raw pre-enrichment tuple from
    # get_attack_step_catalog() — the latter has narrative_template="" on almost
    # every entry, so it would report nothing explainable.
    from adscan_internal.services.attack_step_catalog import (  # noqa: PLC0415
        ATTACK_STEP_CATALOG,
    )

    rows: list[tuple[str, str, str]] = []
    for entry in ATTACK_STEP_CATALOG.values():
        has_content = bool(
            (getattr(entry, "narrative_template", "") or "").strip()
            or (getattr(entry, "manual_command", "") or "").strip()
        )
        if not has_content:
            continue
        rows.append((str(entry.category or ""), entry.relation, _technique_title(entry)))
    rows.sort(key=lambda r: (r[0], r[1]))
    return [(rel, title) for _cat, rel, title in rows]


def explain_technique_by_name(query: str) -> bool:
    """Render the full DEEP card for a technique named on the command line.

    Returns True when a card was printed, False when the query did not resolve
    (the caller then shows usage / the technique list). Always DEEP — the
    ``explain`` command is an explicit request to learn one technique in full.
    """
    entry = resolve_technique(query)
    if entry is None:
        return False
    try:
        from adscan_internal import get_console  # noqa: PLC0415

        card = render_deep_card(entry.relation)
        if card is None:
            return False
        get_console().print(card)
        return True
    except Exception:  # noqa: BLE001
        return False
