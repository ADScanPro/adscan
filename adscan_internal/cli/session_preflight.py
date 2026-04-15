"""Shared runtime preflight helpers for interactive and CI sessions."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import os
import sys

from adscan_internal import print_error, print_info, print_warning, telemetry


@dataclass(frozen=True)
class SessionPreflightConfig:
    """Configuration for a command-level runtime preflight check.

    Args:
        command_name: Command identifier used in telemetry event names.
        docs_utm_medium: ``utm_medium`` value used for troubleshooting links.
        allow_unsafe_override: Whether the command may offer an interactive
            override after ``adscan check --fix`` already attempted repairs.
    """

    command_name: str
    docs_utm_medium: str
    allow_unsafe_override: bool


@dataclass(frozen=True)
class SessionPreflightDeps:
    """Dependencies required to run the shared preflight flow."""

    build_preflight_args: Callable[[], object]
    handle_check: Callable[[object], bool]
    get_last_check_extra: Callable[[], dict[str, object]]
    track_docs_link_shown: Callable[[str, str], None]
    confirm_ask: Callable[[str, bool], bool]
    exit: Callable[[int], None]
    stdin_isatty: Callable[[], bool] = lambda: sys.stdin.isatty()
    get_env: Callable[[str], str | None] = staticmethod(os.getenv)


@dataclass(frozen=True)
class SessionPreflightResult:
    """Final outcome of the shared session preflight flow."""

    passed: bool
    fix_attempted: bool
    overridden: bool


def _build_issue_counts(last_check: dict[str, object]) -> dict[str, int]:
    """Return normalized issue counters for telemetry payloads."""

    return {
        "missing_tools_count": int(last_check.get("missing_tools_count") or 0),
        "tool_version_issues_count": int(
            last_check.get("tool_version_issues_count") or 0
        ),
        "missing_system_packages_count": int(
            last_check.get("missing_system_packages_count") or 0
        ),
    }


def _print_support_links(
    *,
    docs_url: str,
    docs_tracking_key: str,
    track_docs_link_shown: Callable[[str, str], None],
) -> None:
    """Render the standard troubleshooting and support guidance."""

    print_info(
        "💡 Troubleshooting guide: "
        f"[link={docs_url}]adscanpro.com/docs/guides/troubleshooting[/link]"
    )
    track_docs_link_shown(docs_tracking_key, docs_url)
    print_info("Need help? Open an issue: https://github.com/ADscanPro/adscan/issues")
    print_info("Or ask in Discord: https://discord.com/invite/fXBR3P8H74")


def run_session_preflight(
    *,
    config: SessionPreflightConfig,
    deps: SessionPreflightDeps,
) -> SessionPreflightResult:
    """Run ``adscan check`` preflight shared by ``start`` and ``ci``.

    The helper keeps the preflight UX and telemetry aligned across commands
    while still allowing command-specific policies such as interactive unsafe
    overrides for ``start`` and hard blocking for ``ci``.
    """

    preflight_check_args = deps.build_preflight_args()
    preflight_ok = deps.handle_check(preflight_check_args)
    last_check = deps.get_last_check_extra() or {}
    preflight_fix_attempted = bool(last_check.get("fix_mode"))
    preflight_overridden = False
    event_prefix = f"session_{config.command_name}"
    docs_url = (
        "https://www.adscanpro.com/docs/guides/troubleshooting"
        f"?utm_source=cli&utm_medium={config.docs_utm_medium}"
    )

    if not preflight_ok:
        issue_counts = _build_issue_counts(last_check)
        telemetry.capture(
            f"{event_prefix}_check_failed",
            properties={
                "$set": {"installation_status": "failed"},
                "fix_attempted": preflight_fix_attempted,
                **issue_counts,
            },
        )

        can_prompt_override = (
            config.allow_unsafe_override
            and preflight_fix_attempted
            and deps.stdin_isatty()
            and not deps.get_env("CI")
        )
        if can_prompt_override:
            telemetry.capture(
                f"{event_prefix}_override_prompt_shown",
                properties={
                    "fix_attempted": True,
                    **issue_counts,
                },
            )
            print_warning(
                "Some issues remain even after attempting automatic fixes. "
                "Starting anyway is not recommended and may be unsafe (results may be unreliable)."
            )
            _print_support_links(
                docs_url=docs_url,
                docs_tracking_key=config.docs_utm_medium,
                track_docs_link_shown=deps.track_docs_link_shown,
            )
            proceed_anyway = deps.confirm_ask(
                "Start ADscan anyway (NOT recommended / potentially unsafe)?",
                False,
            )
            if not proceed_anyway:
                telemetry.capture(
                    f"{event_prefix}_override_declined",
                    properties={
                        "fix_attempted": True,
                        "unsafe_override": False,
                        **issue_counts,
                    },
                )
                deps.exit(1)
            telemetry.capture(
                f"{event_prefix}_override_accepted",
                properties={
                    "fix_attempted": True,
                    "unsafe_override": True,
                    **issue_counts,
                },
            )
            preflight_overridden = True
        else:
            print_error("ADscan preflight checks failed.")
            _print_support_links(
                docs_url=docs_url,
                docs_tracking_key=config.docs_utm_medium,
                track_docs_link_shown=deps.track_docs_link_shown,
            )
            deps.exit(1)
    else:
        telemetry.capture(
            f"{event_prefix}_check_passed",
            properties={
                "$set": {"installation_status": "success"},
                "fix_attempted": preflight_fix_attempted,
            },
        )

    return SessionPreflightResult(
        passed=bool(preflight_ok),
        fix_attempted=preflight_fix_attempted,
        overridden=preflight_overridden,
    )
