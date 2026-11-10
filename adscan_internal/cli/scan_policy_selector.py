"""The scan-policy selector of ``start auth`` / ``start unauth``.

Shown once the domain controller and the credentials are settled and before
the scan starts. It preselects the workspace's last policy (else the built-in
the model adapter names for the workspace type), so the second scan of a
workspace is one Enter. From the same menu the operator can view a policy
family by family, switch to another built-in or saved policy, or build one
from an existing policy and save it to the workspace or for all workspaces.

An interactive scan only uses a policy's exclusions: attack steps are still
confirmed one by one during the scan. The policy goes through the adapter's
``for_interactive_scan`` before it is applied, and the view states it.

Non-interactive runs (``adscan ci``, the web worker) never see this menu: the
policy of an unattended run comes from ``--policy`` or the scan configuration,
already applied by ``adscan ci``, so the selector returns without prompting and
without writing anything.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from rich.markup import escape

from adscan_core import telemetry
from adscan_core.scan_policy.new_checks import new_checks_since_saved
from adscan_core.scan_policy import settings as policy_settings
from adscan_core.scan_policy.policy import PolicyIdentity
from adscan_core.rich_output import (
    print_error,
    print_exception,
    print_info,
    print_success,
    questionary_select_index,
)
from adscan_internal.cli import scan_policy_library as library
from adscan_internal.services import saved_scan_policies as store
from adscan_internal.services.saved_scan_policies import (
    SCOPE_BUILTIN,
    SCOPE_LABELS,
    SCOPE_WORKSPACE,
    SavedPolicy,
)

#: The menu, in order. The first entry is the default (one Enter).
ACTION_USE = 0
ACTION_VIEW = 1
ACTION_CHOOSE = 2
ACTION_CREATE = 3


@dataclass(frozen=True)
class SelectorOutcome:
    """What the selector did (returned for callers and tests)."""

    proceed: bool
    policy_name: str = ""
    changed: bool = False
    prompted: bool = False


def _current_policy(shell: Any, workspace_dir: str) -> SavedPolicy | None:
    """The workspace's last-used policy, as a :class:`SavedPolicy`."""
    from adscan_internal.services.scan_controls import ATTR_POLICY, policy_display_name

    resolved = getattr(shell, ATTR_POLICY, None)
    if resolved is None:
        return None
    definition = resolved.definition
    reference = definition.identity.policy_id
    for policy in store.list_policies(workspace_dir):
        if reference and reference in (policy.reference, f"builtin:{policy.key}"):
            # The saved file may have moved on since; what applies is what the
            # workspace recorded, under the saved policy's name.
            return SavedPolicy(
                name=policy.name, scope=policy.scope, definition=definition,
                description=policy.description, path=policy.path, key=policy.key,
            )
    return SavedPolicy(
        name=policy_display_name(definition), scope=SCOPE_WORKSPACE, definition=definition
    )


def preselected_policy(shell: Any, workspace_dir: str | None) -> tuple[SavedPolicy, bool]:
    """The policy the selector proposes, and whether it is already applied."""
    if workspace_dir:
        current = _current_policy(shell, workspace_dir)
        if current is not None:
            return current, True
    builtin = store.scan_policy_model().default_for_environment(
        policy_settings.policy_environment(shell)
    )
    return (
        SavedPolicy(
            name=builtin.name, scope=SCOPE_BUILTIN, definition=builtin.definition,
            description=builtin.description, key=builtin.key,
        ),
        False,
    )


def _summary_line(policy: SavedPolicy, *, last_used: bool) -> str:
    resolved = library.resolve_for_display(policy.definition)
    origin = "Last used in this workspace" if last_used else f"Default for this workspace ({library.scope_label(policy)})"
    line = (
        f"Scan policy: [bold]{escape(policy.name)}[/bold]. {origin}: "
        f"{library.counts_line(resolved)}, pace {library.pace_label(policy.definition)}."
    )
    # A saved policy that gained checks since it was saved says so here, where
    # the operator decides to use it (spec: scan policies are the configuration SSOT).
    notice = None if policy.read_only else new_checks_since_saved(policy.definition, resolved=resolved)
    if notice is not None:
        line += f" {escape(notice.line)} Review them with: policy review-new {escape(policy.name)}"
    return line


def _choose_other(shell: Any, workspace_dir: str, current: SavedPolicy) -> SavedPolicy | None:
    policies = store.list_policies(workspace_dir)
    options = [f"{p.name}  ({SCOPE_LABELS[p.scope]})" for p in policies] + ["Back"]
    default = next(
        (i for i, p in enumerate(policies) if p.reference == current.reference), len(options) - 1
    )
    idx = questionary_select_index(
        title="Choose a scan policy", options=options, default_idx=default, shell=shell
    )
    if idx is None or idx == len(options) - 1:
        return None
    return policies[idx]


def _create(shell: Any, workspace_dir: str, source: SavedPolicy) -> SavedPolicy | None:
    definition = library.edit_definition_interactive(shell, source)
    if definition is None:
        print_info("No policy was created.")
        return None
    saved, proceed = library.save_interactive(
        shell,
        definition,
        default_name=f"{source.name} (custom)",
        workspace_dir=workspace_dir,
        allow_unsaved=True,
    )
    if not proceed:
        return None
    if saved is not None:
        return saved
    name = f"{source.name} (modified)"
    return SavedPolicy(
        name=name,
        scope=SCOPE_WORKSPACE,
        definition=replace(definition, identity=PolicyIdentity(name=name)),
    )


def _apply(shell: Any, policy: SavedPolicy, *, already_applied: bool) -> bool:
    if already_applied:
        print_info(f"Scan policy '{escape(policy.name)}' applies to this scan.")
        return True
    from adscan_internal.cli.scan_policy_cmd import apply_saved_policy

    resolved = apply_saved_policy(shell, policy, quiet=True)
    if resolved is None:
        return False
    print_success(
        f"Scan policy '{escape(policy.name)}' applies to this scan and is saved as this "
        "workspace's policy."
    )
    return True


def choose_scan_policy_for_start(shell: Any) -> SelectorOutcome:
    """Run the selector. ``proceed`` is False only when the operator cancels.

    Never raises: a failure in the selector leaves the workspace policy as it
    was and lets the scan start (the policy already applied at workspace load
    still governs it).
    """
    from adscan_internal.interaction import is_non_interactive

    if is_non_interactive(shell):
        return SelectorOutcome(proceed=True)
    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "")
    if not workspace_dir:
        return SelectorOutcome(proceed=True)
    try:
        return _run(shell, workspace_dir)
    except Exception as exc:  # noqa: BLE001 - the scan must still be able to start
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error("The scan policy menu failed; the workspace keeps its current policy.")
        return SelectorOutcome(proceed=True)


def _run(shell: Any, workspace_dir: str) -> SelectorOutcome:
    candidate, applied = preselected_policy(shell, workspace_dir)
    last_used = applied
    show_summary = True
    while True:
        if show_summary:
            print_info(_summary_line(candidate, last_used=last_used and applied))
            show_summary = False
        options = [
            f"Use {candidate.name}",
            f"View {candidate.name}",
            "Choose another policy",
            "Create a policy from this one",
        ]
        idx = questionary_select_index(
            title="Scan policy for this scan", options=options, default_idx=ACTION_USE, shell=shell
        )
        if idx is None:
            print_info("Scan start cancelled.")
            return SelectorOutcome(proceed=False, prompted=True)
        if idx == ACTION_USE:
            if not _apply(shell, candidate, already_applied=applied):
                continue
            return SelectorOutcome(
                proceed=True, policy_name=candidate.name, changed=not applied, prompted=True
            )
        if idx == ACTION_VIEW:
            library.browse_policy(shell, candidate)
            continue
        if idx == ACTION_CHOOSE:
            chosen = _choose_other(shell, workspace_dir, candidate)
            if chosen is not None and chosen.reference != candidate.reference:
                candidate, applied, last_used, show_summary = chosen, False, False, True
            continue
        if idx == ACTION_CREATE:
            created = _create(shell, workspace_dir, candidate)
            if created is not None:
                candidate, applied, last_used, show_summary = created, False, False, True
            continue


def scan_policy_header_value(shell: Any) -> str:
    """The ``Scan Policy`` line of the scan header."""
    from adscan_internal.services.scan_controls import ATTR_POLICY, policy_display_name

    resolved = getattr(shell, ATTR_POLICY, None)
    if resolved is None:
        return "None (every check allowed)"
    return policy_display_name(resolved.definition)


__all__ = [
    "SelectorOutcome",
    "choose_scan_policy_for_start",
    "preselected_policy",
    "scan_policy_header_value",
]
