"""The two once-ever questions ADscan asks the operator at a clean exit.

Both questions share ONE mechanism: a once-ever state flag under the ADscan
state directory, the centralized prompt helpers (so a non-interactive run never
blocks), and a single low-cardinality telemetry event. Nothing here is a second
prompting system; it is the ``.attribution_asked`` contract that has been live
since the discovery question shipped, generalized to two questions.

**Discovery** (``attribution_source``) asks where the operator first heard about
ADscan. It has been answered by ~190 distinct users, so the seam works, but 42%
of those answers landed on "other" because the option list named seven channels
and ADscan is discovered through more than seven. The list below is derived
from measured referrers (``t.co`` is the single largest source of repo traffic,
ahead of Google, GitHub and LinkedIn) and from the channels the project
actually invests in, plus a free-text field on "Something else" so the list
keeps correcting itself instead of silently rounding to "other".

**Role** (``operator_role``) asks which kind of work the operator does. The open
business question is whether the buyer for the point-in-time report is the
consultancy running the engagement or the organization being tested, and there
is no data either way today.

Placement and ordering:

* Both run at a CLEAN exit only, after the session summary, never on a signal /
  abrupt shutdown. That is the existing seam.
* At most ONE optional question per exit. The rating funnel
  (``session_rating``) has first claim; discovery comes next; role waits for a
  later session. Two questions stacked at one exit is real friction for a
  single answer's worth of signal.
* Discovery goes before role because how you found a tool is the answer that
  decays: it is sharp on the first session and vague by the tenth. Which work
  you do does not decay. An operator who has already been asked about discovery
  gets the role question on their next clean exit.

Nothing renders and nothing is sent when the run is non-interactive, offline
(``ADSCAN_OFFLINE`` / ``ADSCAN_NO_EXTERNAL``, the air-gapped appliance default),
or when telemetry is off. A question whose only purpose is telemetry has no
business appearing on a deployment that will not send the answer.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from adscan_core.offline import offline_mode_enabled
from adscan_core.rich_output import (
    print_info,
    prompt_ask,
    questionary_select_index,
)
from adscan_internal import telemetry

# --------------------------------------------------------------------------- #
# Question vocabularies
# --------------------------------------------------------------------------- #
# (telemetry key, operator-facing label). The key is the stable low-cardinality
# value; the label is free to be reworded without breaking a dashboard.
#
# The first seven keys are the original set and are preserved verbatim so the
# ~190 historic answers still join. ``github_organic`` now also covers PyPI:
# the repo page and the package page are the same investment, so splitting them
# would produce two numbers pointing at one decision.
DISCOVERY_OPTIONS: tuple[tuple[str, str], ...] = (
    ("linkedin", "LinkedIn"),
    ("x_twitter", "X (Twitter)"),
    ("github_organic", "GitHub or PyPI"),
    ("search_engine", "A search engine (Google, DuckDuckGo)"),
    ("ai_assistant", "ChatGPT, Claude, or another AI assistant"),
    ("coworker", "A coworker or colleague"),
    ("word_of_mouth", "Word of mouth (a friend, someone in the community)"),
    ("discord_community", "Discord or another community server"),
    ("blog_newsletter", "A blog post, newsletter, or write-up"),
    ("ctf_lab", "An HTB or CTF lab write-up"),
    ("conference", "A conference or meetup talk"),
    ("landing_web", "The ADscan website or docs"),
    ("other", "Something else"),
    ("prefer_not_to_say", "Prefer not to say"),
)

# Four kinds of work, split on the one axis the business cannot currently see:
# whether the operator tests someone else's estate (consultancy, MSSP, or
# freelance) or their own. Freelancers are named explicitly so they do not fall
# into "Something else"; they run client engagements and belong on that side.
ROLE_OPTIONS: tuple[tuple[str, str], ...] = (
    ("consultancy_pentester", "Pentester or red teamer (consultancy, MSSP, freelance)"),
    ("internal_security", "Pentester or internal security (my own organization)"),
    ("sysadmin_blue_team", "Sysadmin, IT, or blue team"),
    ("student_ctf", "Student, learning, or CTF player"),
    ("prefer_not_to_say", "Prefer not to say"),
)

_FREE_TEXT_KEY = "other"
_DECLINE_KEY = "prefer_not_to_say"

# One line, bounded. Long enough to name a channel, short enough that nothing
# resembling a log excerpt or a pasted credential fits.
_MAX_FREE_TEXT_CHARS = 120
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_WHITESPACE_RUN_RE = re.compile(r"\s+")

_DISCOVERY_FLAG = ".attribution_asked"
_ROLE_FLAG = ".operator_role_asked"

DISCOVERY_EVENT = "attribution_source"
ROLE_EVENT = "operator_role"


# --------------------------------------------------------------------------- #
# Once-ever state (the ``.attribution_asked`` contract, shared by both)
# --------------------------------------------------------------------------- #
def _state_dir() -> Path:
    from adscan_core.paths import get_state_dir

    return get_state_dir()


def _is_asked(flag_name: str) -> bool:
    """Return True once this question has been answered or declined."""
    try:
        return (_state_dir() / flag_name).exists()
    except Exception:  # noqa: BLE001
        # Fail closed: if we cannot read the flag we must not risk re-asking
        # someone who already answered.
        return True


def _mark_asked(flag_name: str) -> None:
    """Persist the once-ever flag (best-effort)."""
    try:
        flag = _state_dir() / flag_name
        flag.parent.mkdir(parents=True, exist_ok=True)
        flag.touch()
    except Exception:  # noqa: BLE001
        pass


def is_discovery_asked() -> bool:
    """Return True once the discovery question has been resolved."""
    return _is_asked(_DISCOVERY_FLAG)


def is_role_asked() -> bool:
    """Return True once the role question has been resolved."""
    return _is_asked(_ROLE_FLAG)


# --------------------------------------------------------------------------- #
# Gating
# --------------------------------------------------------------------------- #
def survey_suppressed(shell: object | None = None) -> bool:
    """Return True when no optional question may render this session.

    Three independent reasons, any one of which is enough:

    * the run is non-interactive (``adscan ci``, the web worker, no TTY), where
      a prompt would either block or auto-resolve into a fabricated answer;
    * the deployment is offline / air-gapped, so the answer could never leave
      the network;
    * telemetry is off, so the answer would be collected and then discarded.
    """
    try:
        from adscan_core.prompting import should_disable_prompt_interaction

        if should_disable_prompt_interaction(shell):
            return True
    except Exception:  # noqa: BLE001
        return True

    try:
        if offline_mode_enabled():
            return True
    except Exception:  # noqa: BLE001
        return True

    try:
        from adscan_core.telemetry import _is_telemetry_enabled

        return not _is_telemetry_enabled()
    except Exception:  # noqa: BLE001
        return True


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _version_fields() -> dict[str, Any]:
    """Best-effort version metadata attached to survey telemetry."""
    try:
        from adscan_internal.version import get_version

        return {"adscan_version": get_version()}
    except Exception:  # noqa: BLE001
        return {}


def normalize_free_text(answer: str | None) -> str:
    """Return a bounded, single-line version of a free-text answer.

    Strips control characters, collapses whitespace, and truncates. This is a
    shape guard, not the confidentiality guard: the value travels under a field
    name outside the telemetry safe-list, so ``capture`` scrubs hostnames, IPs,
    paths, and key material out of it before anything is sent.
    """
    text = _CONTROL_CHARS_RE.sub(" ", str(answer or ""))
    text = _WHITESPACE_RUN_RE.sub(" ", text).strip()
    return text[:_MAX_FREE_TEXT_CHARS]


def _ask_free_text(shell: object | None) -> str:
    """Ask the optional one-line follow-up behind 'Something else'."""
    try:
        answer = prompt_ask(
            "Where? (one line, Enter to skip)",
            default="",
            shell=shell,
        )
    except Exception:  # noqa: BLE001
        return ""
    return normalize_free_text(answer)


def _blank_line(shell: object | None) -> None:
    console = getattr(shell, "console", None)
    if console is None:
        return
    try:
        console.print()
    except Exception:  # noqa: BLE001
        pass


def _ask_choice(
    shell: object | None,
    *,
    lede: str,
    title: str,
    options: tuple[tuple[str, str], ...],
) -> tuple[str, str] | None:
    """Render one optional question. Returns (key, label), or None if cancelled.

    The default index is the last row ("Prefer not to say"), so every path that
    resolves a default resolves to the answer that claims nothing.
    """
    labels = [label for _key, label in options]
    try:
        _blank_line(shell)
        print_info(f"[dim]{lede}[/dim]")
        idx = questionary_select_index(
            title=title,
            options=labels,
            default_idx=len(labels) - 1,
            shell=shell,
        )
    except Exception:  # noqa: BLE001
        return None

    if idx is None or not 0 <= idx < len(options):
        return None
    return options[idx]


# --------------------------------------------------------------------------- #
# The two questions
# --------------------------------------------------------------------------- #
def ask_discovery_source(shell: object | None = None) -> bool:
    """Ask once-ever where the operator first heard about ADscan.

    Returns:
        True if the question took this exit's ask slot (answered, declined, or
        cancelled), False if it was not eligible to run at all.
    """
    if is_discovery_asked() or survey_suppressed(shell):
        return False

    answer = _ask_choice(
        shell,
        lede="One optional question, asked once. It tells us where to show up.",
        title="How did you first hear about ADscan?",
        options=DISCOVERY_OPTIONS,
    )
    if answer is None:
        # Cancelled / interrupted (Ctrl+C). Do NOT persist the flag: marking
        # here would permanently lose the answer of exactly the people who
        # bounce. The prompt still took this exit's slot.
        return True

    key, label = answer
    _mark_asked(_DISCOVERY_FLAG)

    props: dict[str, Any] = {"source": key, "source_label": label}
    if key == _FREE_TEXT_KEY:
        free_text = _ask_free_text(shell)
        if free_text:
            props["source_other"] = free_text
            print_info("[dim]Noted, thank you.[/dim]")
    if key != _DECLINE_KEY:
        props["$set"] = {"attribution_source": key}
    props.update(_version_fields())

    try:
        telemetry.capture(DISCOVERY_EVENT, props)
    except Exception:  # noqa: BLE001
        pass
    return True


def ask_operator_role(shell: object | None = None) -> bool:
    """Ask once-ever which kind of work the operator does.

    Returns:
        True if the question took this exit's ask slot, False otherwise.
    """
    if is_role_asked() or survey_suppressed(shell):
        return False

    answer = _ask_choice(
        shell,
        lede="One optional question, asked once. It tells us who we build for.",
        title="Which of these is closest to your work?",
        options=ROLE_OPTIONS,
    )
    if answer is None:
        return True

    key, label = answer
    _mark_asked(_ROLE_FLAG)

    props: dict[str, Any] = {"role": key, "role_label": label}
    if key != _DECLINE_KEY:
        props["$set"] = {"operator_role": key}
    props.update(_version_fields())

    try:
        telemetry.capture(ROLE_EVENT, props)
    except Exception:  # noqa: BLE001
        pass
    return True


def run_exit_survey(shell: object | None = None) -> bool:
    """Run at most ONE optional question this exit.

    Discovery has priority over role; role reaches an operator on a later
    session, once discovery has been resolved.

    Returns:
        True if a question rendered, False if none was eligible.
    """
    if survey_suppressed(shell):
        return False
    if ask_discovery_source(shell):
        return True
    return ask_operator_role(shell)


__all__ = [
    "DISCOVERY_EVENT",
    "DISCOVERY_OPTIONS",
    "ROLE_EVENT",
    "ROLE_OPTIONS",
    "ask_discovery_source",
    "ask_operator_role",
    "is_discovery_asked",
    "is_role_asked",
    "normalize_free_text",
    "run_exit_survey",
    "survey_suppressed",
]
