"""Attack step follow-up planning (runtime substeps).

Some BloodHound relationships represent a *capability edge* but the actual
operator playbook requires additional steps to realize the impact. For example:

- WriteDacl -> Domain: grants replication rights, but the operator still needs
  to run DCSync to retrieve credentials.

During attack path execution, ADscan can offer these follow-ups as *runtime*
substeps without mutating the discovered attack path graph.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from adscan_internal.rich_output import BRAND_COLORS, mark_sensitive, print_panel


@dataclass(frozen=True, slots=True)
class FollowupAction:
    """A suggested follow-up action for an executed step."""

    key: str
    title: str
    description: str
    handler: Callable[[], None]


def build_followups_for_step(
    shell: Any,
    *,
    domain: str,
    step_action: str,
    exec_username: str,
    exec_password: str,
    target_kind: str,
    target_label: str,
    target_domain: str,
    target_sam_or_label: str,
) -> list[FollowupAction]:
    """Return follow-up actions for a given executed step (best-effort)."""
    action = (step_action or "").strip().lower()
    kind = (target_kind or "").strip().lower()

    followups: list[FollowupAction] = []

    if action == "writedacl":
        if kind == "domain":
            marked_domain = mark_sensitive(target_label or target_domain, "domain")

            def _handle_dcsync() -> None:
                ask_for_dcsync = getattr(shell, "ask_for_dcsync", None)
                if callable(ask_for_dcsync):
                    ask_for_dcsync(domain, exec_username, exec_password)
                    return
                dcsync = getattr(shell, "dcsync", None)
                if callable(dcsync):
                    dcsync(domain, exec_username, exec_password)
                    return

            followups.append(
                FollowupAction(
                    key="dcsync",
                    title="DCSync",
                    description=f"Attempt DCSync after granting replication rights on {marked_domain}.",
                    handler=_handle_dcsync,
                )
            )
            return followups

        if kind in {"user", "computer"}:
            marked_target = mark_sensitive(target_label, "user")

            def _handle_shadow_credentials() -> None:
                exploit = getattr(shell, "exploit_generic_all_user", None)
                if callable(exploit):
                    exploit(
                        domain,
                        exec_username,
                        exec_password,
                        target_sam_or_label,
                        target_domain,
                        prompt_for_password_fallback=True,
                        prompt_for_user_privs_after=True,
                    )

            followups.append(
                FollowupAction(
                    key="shadow_credentials",
                    title="Shadow Credentials",
                    description=f"Try Shadow Credentials against {marked_target} after DACL changes.",
                    handler=_handle_shadow_credentials,
                )
            )
            return followups

        if kind == "group":
            marked_target = mark_sensitive(target_sam_or_label or target_label, "user")

            def _handle_addmember() -> None:
                exploit = getattr(shell, "exploit_add_member", None)
                if not callable(exploit):
                    return
                marked_user = mark_sensitive(exec_username, "user")
                changed_username = Prompt.ask(
                    f"Enter the user you want to add to group {target_sam_or_label}",
                    default=str(marked_user),
                )
                exploit(
                    domain,
                    exec_username,
                    exec_password,
                    target_sam_or_label,
                    changed_username,
                    target_domain,
                    enumerate_aces_after=True,
                )

            followups.append(
                FollowupAction(
                    key="addmember",
                    title="Add member",
                    description=f"Add a user to group {marked_target} after applying DACL changes.",
                    handler=_handle_addmember,
                )
            )
            return followups

    if action == "writeowner" and kind in {"user", "group"}:
        marked_target = mark_sensitive(target_label, "user")

        def _handle_writedacl() -> None:
            exploit = getattr(shell, "exploit_write_dacl", None)
            if callable(exploit):
                exploit(
                    domain,
                    exec_username,
                    exec_password,
                    target_sam_or_label,
                    target_domain,
                    kind,
                    followup_after=True,
                )

        followups.append(
            FollowupAction(
                key="writedacl",
                title="WriteDacl",
                description=f"Attempt WriteDacl against {marked_target} after becoming owner.",
                handler=_handle_writedacl,
            )
        )

    return followups


def render_followup_actions_panel(
    *,
    step_action: str,
    target_label: str,
    followups: list[FollowupAction],
) -> None:
    """Render a follow-up action list as a panel."""
    table = Table(
        title=Text("Recommended follow-ups", style=f"bold {BRAND_COLORS['info']}"),
        show_header=True,
        header_style=f"bold {BRAND_COLORS['info']}",
        show_lines=True,
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Action", style="bold")
    table.add_column("Description", style="dim", overflow="fold")

    for idx, item in enumerate(followups, start=1):
        table.add_row(str(idx), item.title, item.description)

    title = Text("Follow-up Actions", style=f"bold {BRAND_COLORS['info']}")
    marked_step = mark_sensitive(step_action, "node")
    marked_target = mark_sensitive(target_label, "node")
    subtitle = Text.assemble(
        ("Step: ", "dim"),
        (str(marked_step), "bold"),
        ("  Target: ", "dim"),
        (str(marked_target), "bold"),
    )
    print_panel(
        [subtitle, table], title=title, border_style=BRAND_COLORS["info"], expand=False
    )
