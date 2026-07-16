"""Peak-value session rating funnel (rating -> GitHub star).

At the peak-goodwill moment of a session — right after ADscan proves a real
value moment (a captured credential / attack path, or full domain compromise) —
we ask the operator a single 1-5 rating. That rating is the ONE primary ask
(Hormozi give:ask): only a promoter score (>= 4) then earns the public
GitHub-star ask; a <= 3 score gets a genuine thank-you and an optional one-line
"what would make it a 5?" instead. A skip is a clean no-op.

This is the single source of truth for:

* the once-ever ``.session_rated`` state flag,
* the ``session_rating`` / ``session_rating_feedback`` telemetry events,
* the shared GitHub-star CTA renderer (``show_github_star_cta``) reused by the
  domain-compromise euphoria block so the star fires in exactly ONE place per
  session.

The funnel never blocks a non-interactive run: it is gated on
``is_non_interactive`` and returns early under ``adscan ci`` / the web worker.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from adscan_core.rich_output import (
    mark_passthrough,
    print_info,
    print_panel,
    print_success,
    prompt_ask,
    questionary_select_index,
)
from adscan_internal import telemetry
from adscan_internal.interaction import is_non_interactive

# The value tiers that justify asking for a rating. Anything else (a null-result
# scan) must NEVER trigger the funnel.
VALUE_TIERS: tuple[str, ...] = ("domain_compromise", "findings")

# A rating at or above this score is a promoter and earns the public star ask.
_PROMOTER_THRESHOLD = 4

_STATE_FLAG_NAME = ".session_rated"

_GITHUB_REPO_URL = "https://github.com/ADscanPro/adscan"

# Ordered best-to-worst so the star glyphs read as a natural scale. Each entry
# maps to its numeric score via ``_RATING_BY_INDEX``; the trailing "Skip" row is
# the explicit opt-out.
_RATING_OPTIONS: tuple[str, ...] = (
    "★★★★★   Excellent — exactly what I needed",
    "★★★★☆   Good — solid, a few rough edges",
    "★★★☆☆   Okay — did the job",
    "★★☆☆☆   Meh — expected more",
    "★☆☆☆☆   Poor — it struggled",
    "Skip",
)
_RATING_BY_INDEX: dict[int, int] = {0: 5, 1: 4, 2: 3, 3: 2, 4: 1}
_SKIP_INDEX = len(_RATING_OPTIONS) - 1


def _state_dir() -> Path:
    """Return the persisted ADscan state directory (best-effort, sudo-safe)."""
    from adscan_core.paths import get_state_dir

    return get_state_dir()


def _flag_path() -> Path:
    return _state_dir() / _STATE_FLAG_NAME


def is_rated() -> bool:
    """Return True once the operator has been through the rating funnel."""
    try:
        return _flag_path().exists()
    except Exception:  # noqa: BLE001
        return False


def _mark_rated() -> None:
    """Persist the once-ever rated flag (best-effort)."""
    try:
        flag = _flag_path()
        flag.parent.mkdir(parents=True, exist_ok=True)
        flag.touch()
    except Exception:  # noqa: BLE001
        pass


def _version_fields() -> dict[str, Any]:
    """Best-effort version metadata attached to rating telemetry."""
    try:
        from adscan_internal.version import get_version

        return {"adscan_version": get_version()}
    except Exception:  # noqa: BLE001
        return {}


def rating_funnel_will_run(shell, *, value_tier: str | None) -> bool:
    """Return True if the exit rating funnel is eligible to run this session.

    Eligible when the session reached a real value moment, the run is
    interactive, and the operator has not already been asked. The
    domain-compromise euphoria block consults this to suppress its inline star
    CTA so the funnel owns the single primary ask.
    """
    if value_tier not in VALUE_TIERS:
        return False
    if is_rated():
        return False
    try:
        if is_non_interactive(shell=shell):
            return False
    except Exception:  # noqa: BLE001
        return False
    return True


def show_github_star_cta(
    shell,
    *,
    trigger: str,
    extra_props: dict[str, Any] | None = None,
    respect_cooldown: bool = True,
) -> bool:
    """Render the GitHub-star CTA once per cooldown window.

    Single source of truth for the star ask. Reused by the rating funnel's
    promoter branch and the domain-compromise euphoria block. Respects the
    shared ``github_star`` victory-hint cooldown so the star never fires twice.

    Returns:
        True if the CTA was rendered, False if the cooldown suppressed it.
    """
    mark_shown = None
    if respect_cooldown:
        try:
            import adscan as _adscan_module  # type: ignore[import-not-found]

            should_show = getattr(_adscan_module, "should_show_victory_hint", None)
            mark_shown = getattr(_adscan_module, "mark_victory_hint_shown", None)
            if callable(should_show) and not should_show("github_star", "explicit"):
                return False
        except Exception:  # noqa: BLE001
            mark_shown = None

    try:
        url = mark_passthrough(_GITHUB_REPO_URL)
        console = getattr(shell, "console", None)
        if console is not None:
            try:
                console.print()
            except Exception:  # noqa: BLE001
                pass
        print_info(
            f"[dim]A ⭐ on GitHub helps other pentesters find ADscan → "
            f"[link={_GITHUB_REPO_URL}]{url}[/link][/dim]"
        )
    except Exception:  # noqa: BLE001
        return False

    if callable(mark_shown):
        try:
            mark_shown("github_star")
        except Exception:  # noqa: BLE001
            pass

    try:
        props = {"trigger": trigger}
        if extra_props:
            props.update(extra_props)
        telemetry.capture("star_cta_shown", props)
    except Exception:  # noqa: BLE001
        pass
    return True


def _lede_for_tier(value_tier: str) -> str:
    """Warm, specific opener anchored on what just happened."""
    if value_tier == "domain_compromise":
        return "You just compromised the domain."
    return "You just captured credentials on this engagement."


def _capture_rating(rating: int, value_tier: str) -> None:
    try:
        props: dict[str, Any] = {"rating": rating, "value_tier": value_tier}
        props.update(_version_fields())
        telemetry.capture("session_rating", props)
    except Exception:  # noqa: BLE001
        pass


def _capture_feedback(rating: int, value_tier: str, feedback: str) -> None:
    try:
        props: dict[str, Any] = {
            "rating": rating,
            "value_tier": value_tier,
            "feedback": feedback,
        }
        props.update(_version_fields())
        telemetry.capture("session_rating_feedback", props)
    except Exception:  # noqa: BLE001
        pass


def _handle_promoter(shell) -> None:
    """Promoter (>= 4): bridge line, then the earned public star ask."""
    print_success("Glad it's delivering.")
    show_github_star_cta(shell, trigger="session_rating")


def _handle_detractor(shell, rating: int, value_tier: str) -> None:
    """Score <= 3: genuine thank-you + optional one-line improvement ask.

    No star ask, no defensiveness.
    """
    print_info("Thanks — noted. That's exactly the signal we build against.")
    try:
        answer = prompt_ask(
            "What's the one thing that would make it a 5? (Enter to skip)",
            default="",
            shell=shell,
        )
    except Exception:  # noqa: BLE001
        answer = ""
    feedback = (answer or "").strip()
    if feedback:
        _capture_feedback(rating, value_tier, feedback)
        print_info("[dim]Got it — thank you.[/dim]")


def run_rating_funnel(shell, *, value_tier: str | None) -> bool:
    """Run the peak-value rating -> star funnel, once ever.

    Returns:
        True if the rating prompt took this exit's primary-ask slot (so the
        caller must NOT also ask attribution this exit). False when the funnel
        was not eligible (non-interactive, no value moment, or already rated) —
        the caller proceeds with its normal exit flow.
    """
    if not rating_funnel_will_run(shell, value_tier=value_tier):
        return False

    # ``value_tier`` is guaranteed a real tier by the gate above.
    tier = str(value_tier)

    try:
        console = getattr(shell, "console", None)
        if console is not None:
            try:
                console.print()
            except Exception:  # noqa: BLE001
                pass
        print_panel(
            f"{_lede_for_tier(tier)}\n\n[dim]How's ADscan working for you?[/dim]",
            title="[bold]Quick rating[/bold]",
            title_align="center",
            border_style="cyan",
            padding=(1, 2),
            fit=True,
        )
        idx = questionary_select_index(
            title="Rate this session",
            options=list(_RATING_OPTIONS),
            default_idx=_SKIP_INDEX,
            shell=shell,
        )
    except Exception:  # noqa: BLE001
        idx = None

    if idx is None:
        # Cancelled / interrupted (Ctrl+C): do NOT persist the once-ever flag so
        # the next value-moment exit asks again — but the prompt already took
        # this exit's ask slot, so attribution still waits.
        return True

    # A deliberate answer (a score OR an explicit skip) closes the funnel for
    # good; mirror the attribution once-ever contract.
    _mark_rated()

    if idx == _SKIP_INDEX:
        return True

    rating = _RATING_BY_INDEX.get(idx)
    if rating is None:
        return True

    _capture_rating(rating, tier)

    if rating >= _PROMOTER_THRESHOLD:
        _handle_promoter(shell)
    else:
        _handle_detractor(shell, rating, tier)

    return True


__all__ = [
    "VALUE_TIERS",
    "is_rated",
    "rating_funnel_will_run",
    "run_rating_funnel",
    "show_github_star_cta",
]
