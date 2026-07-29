"""``set telemetry`` command logic — scope parsing, persistence, and feedback.

The REPL command is thin on purpose: everything a user's opt-out has to get
right (which scope was applied, whether it actually reached disk, what the
effective state now is) lives here so it can be tested without driving the
shell.

Scope model — see :mod:`adscan_core.telemetry_preference` for the resolution
rule. ``set telemetry off`` opts the OPERATOR out everywhere; the optional
``workspace`` scope narrows a change to the current engagement only. A
workspace can be stricter than the global preference, never looser.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from adscan_core.telemetry_preference import (
    WORKSPACE_PREFERENCE_ATTR,
    load_global_preference,
    resolve_effective_telemetry,
    save_global_preference,
)
from adscan_internal import telemetry
from adscan_internal.rich_output import (
    print_error,
    print_info,
    print_success,
    print_warning,
)

SCOPE_GLOBAL = "global"
SCOPE_WORKSPACE = "workspace"

_ON_TOKENS = {"true", "on", "1", "yes", "enable", "enabled"}
_OFF_TOKENS = {"false", "off", "0", "no", "disable", "disabled"}
_SCOPE_TOKENS = {
    SCOPE_GLOBAL: SCOPE_GLOBAL,
    "all": SCOPE_GLOBAL,
    "everywhere": SCOPE_GLOBAL,
    "user": SCOPE_GLOBAL,
    SCOPE_WORKSPACE: SCOPE_WORKSPACE,
    "ws": SCOPE_WORKSPACE,
    "session": SCOPE_WORKSPACE,
}

# No square brackets: Rich parses them as markup and would swallow the token.
USAGE = (
    "Usage: set telemetry <on|off> — applies everywhere. "
    "Add 'workspace' to change only the current workspace: "
    "set telemetry off workspace"
)


@dataclass(frozen=True)
class TelemetrySettingRequest:
    """A parsed ``set telemetry`` invocation."""

    enabled: bool
    scope: str


@dataclass(frozen=True)
class TelemetrySettingResult:
    """Outcome of applying a ``set telemetry`` request."""

    enabled: bool
    scope: str
    persisted: bool
    global_preference: Optional[bool]
    workspace_preference: Optional[bool]


def parse_telemetry_setting(value: str) -> TelemetrySettingRequest | None:
    """Parse the ``set telemetry`` value into a request.

    Accepts ``on``/``off`` (and the usual synonyms) plus an optional scope
    token. Returns ``None`` when the input is not understood; the caller prints
    :data:`USAGE`.
    """
    tokens = [token for token in str(value or "").lower().split() if token]
    if not tokens or len(tokens) > 2:
        return None

    state = tokens[0]
    if state in _ON_TOKENS:
        enabled = True
    elif state in _OFF_TOKENS:
        enabled = False
    else:
        return None

    scope = SCOPE_GLOBAL
    if len(tokens) == 2:
        resolved = _SCOPE_TOKENS.get(tokens[1])
        if resolved is None:
            return None
        scope = resolved

    return TelemetrySettingRequest(enabled=enabled, scope=scope)


def _workspace_label(shell: Any) -> str:
    name = getattr(shell, "current_workspace", None)
    return str(name) if name else "this workspace"


def _sync_runtime_state(shell: Any, enabled: bool) -> None:
    """Push the resolved state into the shell and the telemetry gate."""
    shell.telemetry = enabled
    try:
        from adscan_internal.cli.common import build_telemetry_context

        context = build_telemetry_context(shell=shell, trigger="set_telemetry")
    except Exception:  # noqa: BLE001 - context is decoration, never a blocker
        context = None
    telemetry.set_cli_telemetry(enabled, context=context)


def apply_telemetry_setting(
    shell: Any, request: TelemetrySettingRequest
) -> TelemetrySettingResult:
    """Apply a parsed ``set telemetry`` request and report it on screen.

    Persists the global preference when the scope is global, records the
    workspace's own preference when it is not, resolves the effective state,
    and tells the operator exactly which scope changed — an opt-out the user
    cannot verify is not an opt-out.
    """
    persisted = True
    if request.scope == SCOPE_GLOBAL:
        persisted = save_global_preference(request.enabled)
    else:
        setattr(shell, WORKSPACE_PREFERENCE_ATTR, request.enabled)

    global_preference = load_global_preference()
    workspace_preference = getattr(shell, WORKSPACE_PREFERENCE_ATTR, None)
    if not isinstance(workspace_preference, bool):
        workspace_preference = None

    effective = resolve_effective_telemetry(global_preference, workspace_preference)
    _sync_runtime_state(shell, effective)

    _report(
        request=request,
        effective=effective,
        persisted=persisted,
        workspace_preference=workspace_preference,
        workspace_label=_workspace_label(shell),
    )

    return TelemetrySettingResult(
        enabled=effective,
        scope=request.scope,
        persisted=persisted,
        global_preference=global_preference,
        workspace_preference=workspace_preference,
    )


def _report(
    *,
    request: TelemetrySettingRequest,
    effective: bool,
    persisted: bool,
    workspace_preference: Optional[bool],
    workspace_label: str,
) -> None:
    """Print what actually happened, naming the scope every time."""
    if request.scope == SCOPE_GLOBAL:
        if not persisted:
            print_error(
                "Could not save your telemetry preference to disk. It applies "
                "to this session only — check the permissions on your ADscan "
                "state directory and set it again."
            )
        if request.enabled:
            print_success("Telemetry is on for every workspace and session.")
            if workspace_preference is False:
                print_warning(
                    f"Telemetry stays off in {workspace_label}, which has its own "
                    "opt-out. Run 'set telemetry on workspace' to change that too."
                )
        else:
            print_success(
                "Telemetry is off everywhere. This applies to every workspace, "
                "including new ones, and persists across sessions."
            )
            print_info("Turn it back on with 'set telemetry on'.")
        return

    if request.enabled:
        if effective:
            print_success(f"Telemetry is on for {workspace_label}.")
        else:
            print_warning(
                "Telemetry stays off: you are opted out globally, and a "
                "workspace cannot override that. Run 'set telemetry on' to "
                "turn it back on everywhere."
            )
        return

    print_success(f"Telemetry is off for {workspace_label}.")
    print_info(
        "Other workspaces are unaffected. Use 'set telemetry off' to opt out "
        "everywhere."
    )


__all__ = [
    "SCOPE_GLOBAL",
    "SCOPE_WORKSPACE",
    "TelemetrySettingRequest",
    "TelemetrySettingResult",
    "USAGE",
    "apply_telemetry_setting",
    "parse_telemetry_setting",
]
