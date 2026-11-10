"""Single source of truth for CLI subcommand tier classification.

Used by both the host-side launcher (``adscan_launcher/cli.py``) and the
container-side dispatcher (``adscan.py``) to:

- Render the ``adscan --help`` listing with ``[PRO]`` / ``[LITE]`` badges
  grouped under a "Client Deliverables" category.
- Gate PRO-only commands with the exit-42 protocol (LITE container exits
  42 + JSON; launcher renders the canonical PRO upsell panel).

Keep this module dependency-light — it is imported by both the launcher
(host) and the runtime (container). No heavy imports.
"""

from __future__ import annotations

from typing import Literal

Tier = Literal["LITE", "PRO"]

# Commands that require PRO. Matches the dispatch gate in ``adscan.py``
# and the post-exit-42 upsell in ``adscan_launcher/cli.py``.
#
# PRO-gated commands: ``deliver`` (the full Client Deliverable Kit), and every
# NON-INTERACTIVE entry point: ``ci`` (a whole assessment unattended) and
# ``execute`` (one REPL action from a shell or a script). LITE is
# interactive-only: the LITE user drives ``adscan start``, where every
# ``execute`` verb exists as a REPL command. Gated by module absence like every
# PRO surface: LITE lacks ``adscan_internal.pro`` so ``is_pro()`` is False and
# the dispatch gate returns exit-42.
PRO_ONLY_COMMANDS: frozenset[str] = frozenset({
    "ci",
    "deliver",
    "execute",
    # The engagement ledger (history across runs) is PRO and Enterprise only
    # (engagement-state spec, decision D12a).
    "engagement",
    # Re-verification of findings, attack steps and paths from the ledger is
    # PRO (on demand) and Enterprise (on demand and scheduled), decision D12b.
    "recheck",
})

# Commands the container dispatcher runs NON-INTERACTIVELY (it sets
# ``ADSCAN_NONINTERACTIVE`` for them). Every one of them is PRO-only unless it
# is listed in ``NON_INTERACTIVE_EXEMPT`` with the reason; a structural test
# (``tests/unit/launcher/test_non_interactive_commands_are_pro.py``) fails CI
# otherwise, so a new unattended entry point cannot ship in LITE by accident.
NON_INTERACTIVE_COMMANDS: tuple[str, ...] = ("ci", "run", "execute", "doctor")
NON_INTERACTIVE_EXEMPT: dict[str, str] = {
    "doctor": "a read-only health check of the install and the lab connection",
    "run": "a plan wrapper whose planned command (ci, deliver, doctor) is gated on its own",
}

# Commands that ship in LITE (operator-facing desk references and the
# free entry points). Used purely for help-listing classification.
LITE_DELIVERABLE_COMMANDS: frozenset[str] = frozenset({
    "cheatsheet",
    "mitre-navigator",
})

# All commands that belong to the "Client Deliverables" help category, in
# the order they should be displayed. This tuple's only job is a stable
# display order; the LITE-vs-PRO grouping in the launcher help is derived
# from ``tier_for_command`` at render time, not from this ordering.
DELIVERABLE_COMMAND_ORDER: tuple[str, ...] = (
    "deliver",
    "cheatsheet",
    "mitre-navigator",
)


def tier_for_command(command: str) -> Tier:
    """Return the tier badge for ``command``.

    Defaults to ``"LITE"`` for any command not explicitly listed as PRO.
    """
    return "PRO" if command in PRO_ONLY_COMMANDS else "LITE"


def is_pro_only(command: str) -> bool:
    """Return ``True`` when ``command`` is gated to the PRO tier."""
    return command in PRO_ONLY_COMMANDS


__all__ = (
    "Tier",
    "PRO_ONLY_COMMANDS",
    "NON_INTERACTIVE_COMMANDS",
    "NON_INTERACTIVE_EXEMPT",
    "LITE_DELIVERABLE_COMMANDS",
    "DELIVERABLE_COMMAND_ORDER",
    "tier_for_command",
    "is_pro_only",
)
