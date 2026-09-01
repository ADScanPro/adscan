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

**Role** (``operator_role``) asks which kind of work the operator does. This
question moved OUT of the exit survey and to the **first interactive scan**
(``adscan start``) — see :func:`ask_operator_role_at_startup`. Two things drove
the move:

1. The exit survey asks at most one question per exit and discovery always won
   the slot, so role only fired on a *second* clean exit behind the rating
   funnel. It almost never ran (a handful of answers vs. hundreds for discovery).
2. The role now does real work in-session: it is persisted as a local profile
   (:mod:`adscan_internal.services.operator_role_profile`) that the commercial
   call-to-action branches on (a buyer sees the Enterprise demo, a consultant
   the /pro CLI) and the didactic mode reads to emphasise the defensive or the
   offensive angle. That is only possible if the role is known BEFORE the value
   moment — i.e. at the start, not on the way out.

The v1 role vocabulary (the four keys asked at exit) and its once-ever flag are
kept as legacy; the startup question uses a NEW versioned vocabulary
(:data:`ROLE_OPTIONS_V2`, ``role_survey_version: 2``) and a NEW once-ever flag,
so an operator who answered the old exit question still sees the new one once —
with the new options (CISO/buyer, a writable "Something else").

Placement and ordering (discovery, at exit):

* Discovery still runs at a CLEAN exit only, after the session summary, never on
  a signal / abrupt shutdown. That is the existing seam. Role no longer competes
  for the exit slot, so discovery is the only optional question at exit now.

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

# LEGACY (v1) — the four kinds of work asked at EXIT before the question moved to
# startup. Kept verbatim so the handful of historic ``operator_role`` answers
# still join, and so ``run_exit_survey`` can be read alongside its old vocabulary.
# NOT asked any more (the exit-role branch is legacy — see ``run_exit_survey``).
ROLE_OPTIONS: tuple[tuple[str, str], ...] = (
    ("consultancy_pentester", "Pentester or red teamer (consultancy, MSSP, freelance)"),
    ("internal_security", "Pentester or internal security (my own organization)"),
    ("sysadmin_blue_team", "Sysadmin, IT, or blue team"),
    ("student_ctf", "Student, learning, or CTF player"),
    ("prefer_not_to_say", "Prefer not to say"),
)

# v2 — the role vocabulary asked at STARTUP. Two deliberate additions over v1:
#   * ``security_manager_ciso`` — the BUYER of the point-in-time report (a CISO /
#     security manager evaluating their OWN estate). v1 had no bucket for them, so
#     they fell into "internal security" or "Something else" and the CTA could not
#     route them to the Enterprise demo.
#   * ``other`` is now WRITABLE (a free-text follow-up), so the list keeps
#     correcting itself instead of silently rounding uncovered roles into a bucket
#     that means something else.
# Emitted under ``role_survey_version: 2`` so v2 answers never mix with the v1
# ones in an insight. The keys are a superset of the runtime role profile
# (``operator_role_profile.ROLE_PROFILE_KEYS``).
ROLE_OPTIONS_V2: tuple[tuple[str, str], ...] = (
    ("consultancy_pentester", "Pentester or red teamer (consultancy, MSSP, freelance)"),
    ("internal_security", "Pentester or internal security (my own organization)"),
    ("sysadmin_blue_team", "Sysadmin, IT, or blue team"),
    ("security_manager_ciso", "Security manager, CISO, or security lead"),
    ("student_ctf", "Student, learning, or CTF player"),
    ("other", "Something else"),
    ("prefer_not_to_say", "Prefer not to say"),
)

#: The survey-version stamp on every v2 ``operator_role`` event, so the new
#: answers are separable from the ~14 legacy exit answers in an insight.
ROLE_SURVEY_VERSION = 2

_FREE_TEXT_KEY = "other"
_DECLINE_KEY = "prefer_not_to_say"

#: Sentinel emitted in ``source_other`` / ``role_other`` when the operator SAW the
#: free-text prompt and pressed Enter without typing. It distinguishes "skipped
#: the follow-up" from "the follow-up never rendered" (the field simply absent) —
#: the historic NULL that made every "other" answer indistinguishable.
_FREE_TEXT_SKIPPED = "__skipped__"

# One line, bounded. Long enough to name a channel, short enough that nothing
# resembling a log excerpt or a pasted credential fits.
_MAX_FREE_TEXT_CHARS = 120
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_WHITESPACE_RUN_RE = re.compile(r"\s+")

_DISCOVERY_FLAG = ".attribution_asked"
# LEGACY once-ever flag for the v1 exit-role question. NOT written any more (the
# exit-role branch is legacy). A NEW flag governs the v2 startup question below so
# the ~14 operators who answered v1 see the v2 question exactly once.
_ROLE_FLAG = ".operator_role_asked"
_ROLE_V2_FLAG = ".operator_role_v2_asked"

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
    """Return True once the LEGACY (v1, exit) role question has been resolved."""
    return _is_asked(_ROLE_FLAG)


def is_role_v2_asked() -> bool:
    """Return True once the v2 (startup) role question has been resolved.

    Independent of :func:`is_role_asked` on purpose: an operator who answered the
    legacy exit question must still see the v2 question once (new options).
    """
    return _is_asked(_ROLE_V2_FLAG)


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


def _ask_free_text(shell: object | None, *, prompt: str) -> tuple[bool, str]:
    """Ask the optional one-line follow-up behind 'Something else'.

    Returns ``(prompt_shown, text)``:

    * ``prompt_shown`` is ``True`` when the prompt was actually rendered (even if
      the operator pressed Enter without typing). It is ``False`` only when the
      prompt raised / could not render.
    * ``text`` is the normalized (bounded, single-line) answer, or ``""`` when the
      operator skipped or the prompt did not render.

    The caller uses ``prompt_shown`` to distinguish "operator skipped" from "the
    prompt never appeared" — the two states that used to collapse into an absent
    field, so every historic "other" answer looked the same.
    """
    try:
        answer = prompt_ask(
            prompt,
            default="",
            shell=shell,
        )
    except Exception:  # noqa: BLE001
        return False, ""
    return True, normalize_free_text(answer)


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
        # Always emit ``source_other`` for an "other" answer, with a breadcrumb of
        # whether the follow-up actually rendered. The historic bug attached the
        # field only when the text was truthy, so an Enter-to-skip (the common
        # case) produced NULL — indistinguishable from "prompt never shown", which
        # made 100% of "other" answers unreadable. The sentinel fixes that.
        prompt_shown, free_text = _ask_free_text(
            shell, prompt="Where? (one line, Enter to skip)"
        )
        props["free_text_prompt_shown"] = prompt_shown
        props["source_other"] = free_text if free_text else _FREE_TEXT_SKIPPED
        if free_text:
            print_info("[dim]Noted, thank you.[/dim]")
    if key != _DECLINE_KEY:
        props["$set"] = {"attribution_source": key}
    props.update(_version_fields())

    try:
        telemetry.capture(DISCOVERY_EVENT, props)
    except Exception:  # noqa: BLE001
        pass
    return True


def ask_operator_role_at_startup(shell: object | None = None) -> bool:
    """Ask once-ever, at the FIRST interactive scan, which work the operator does.

    This is the live role question (v2). It is tied to the didactic mode — the
    framing is true, not a pretext: the answer is persisted as a local role
    profile (:mod:`operator_role_profile`) that both the commercial CTA and the
    didactic emphasis read in-session. The framing therefore promises adaptation
    ADscan actually delivers.

    Once-ever via a NEW flag (:data:`_ROLE_V2_FLAG`), independent of the legacy
    exit flag, so an operator who answered the old exit question still sees this
    one exactly once. In a non-interactive / CI / offline / telemetry-off run it
    does not render and does not burn the flag (``survey_suppressed`` covers all
    of those, and the centralized prompt helper auto-resolves without blocking).

    Returns:
        True if the question took a turn this run (answered, declined, or
        cancelled), False if it was not eligible to run at all.
    """
    if is_role_v2_asked() or survey_suppressed(shell):
        return False

    answer = _ask_choice(
        shell,
        lede=(
            "One optional question, asked once. ADscan can adapt what it teaches "
            "to your background — what's closest to your work?"
        ),
        title="Which of these is closest to your work?",
        options=ROLE_OPTIONS_V2,
    )
    if answer is None:
        # Cancelled / interrupted — do NOT burn the flag; re-ask next start.
        return True

    key, label = answer
    _mark_asked(_ROLE_V2_FLAG)

    # Persist the role locally so the CTA + didactic mode can read it in-session.
    # Best-effort; a failed write only means the role defaults at the consumer.
    role_other = ""
    if key == _FREE_TEXT_KEY:
        _prompt_shown, role_other = _ask_free_text(
            shell, prompt="Tell us in a few words (one line, Enter to skip)"
        )
    try:
        from adscan_internal.services.operator_role_profile import set_operator_role

        set_operator_role(key)
    except Exception:  # noqa: BLE001
        pass

    props: dict[str, Any] = {
        "role": key,
        "role_label": label,
        "role_survey_version": ROLE_SURVEY_VERSION,
    }
    if key == _FREE_TEXT_KEY:
        props["role_other"] = role_other if role_other else _FREE_TEXT_SKIPPED
    if key != _DECLINE_KEY:
        props["$set"] = {"operator_role": key, "role_survey_version": ROLE_SURVEY_VERSION}
    props.update(_version_fields())

    try:
        telemetry.capture(ROLE_EVENT, props)
    except Exception:  # noqa: BLE001
        pass
    return True


def run_exit_survey(shell: object | None = None) -> bool:
    """Run the discovery question at a clean exit.

    Discovery (``attribution_source``) is the only optional question at exit now.

    LEGACY: the role question used to run here as a second-priority exit question
    (behind discovery, and behind the rating funnel), which is why it almost never
    fired. It has been REMOVED from the exit flow and moved to the first
    interactive scan (:func:`ask_operator_role_at_startup`), where the answer can
    actually steer the session (CTA lane + didactic emphasis). ``ask_operator_role``
    / :data:`ROLE_OPTIONS` / :data:`_ROLE_FLAG` remain only as read-only legacy for
    the ~14 historic answers; do not re-wire them into the exit.

    Returns:
        True if the discovery question rendered, False if it was not eligible.
    """
    if survey_suppressed(shell):
        return False
    return ask_discovery_source(shell)


__all__ = [
    "DISCOVERY_EVENT",
    "DISCOVERY_OPTIONS",
    "ROLE_EVENT",
    "ROLE_OPTIONS",
    "ROLE_OPTIONS_V2",
    "ROLE_SURVEY_VERSION",
    "ask_discovery_source",
    "ask_operator_role_at_startup",
    "is_discovery_asked",
    "is_role_asked",
    "is_role_v2_asked",
    "normalize_free_text",
    "run_exit_survey",
    "survey_suppressed",
]
