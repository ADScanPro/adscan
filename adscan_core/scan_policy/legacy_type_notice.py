"""The guidance shown where a scan used to take a workspace type, and when ``ci`` names no policy.

The workspace type (``ctf`` / ``audit``) no longer decides anything: the scan
policy does (its checks and its behaviour settings,
:mod:`adscan_core.scan_policy.settings`). The two forms that used to take a
type still parse, only so they can answer with guidance instead of an
"unrecognized argument" error. Neither changes anything:

* ``adscan ci --type ctf|audit`` without ``--policy``: nothing runs. The panel
  names the equivalent ``--policy`` for what was typed, lists the policies the
  run could name and how to create one, and the run exits non-zero.
* ``adscan ci --type ... --policy NAME``: the policy runs; the panel says the
  type was ignored and can be dropped.
* the REPL ``set type ctf|audit``: nothing changes; the panel gives the
  ``policy use`` command for what was typed.

The same module words the refusal ``adscan ci`` prints when a run names no
policy at all, so every one of these reads as the same product. No caller
writes its own text.

Every panel goes through the shared console (``print_panel``), so it reaches
the session recording and prints inline in a non-interactive run (no Live, no
alternate screen). Commands render as unwrapped lines of their own, so a narrow
terminal never splits one; every command here fits an 80-column panel.

Design: docs/superpowers/specs/2026-11-05-scan-policy-settings-replace-workspace-type.md
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from rich.console import Group
from rich.text import Text

from adscan_core.scan_policy.policy import (
    BASE_AUDIT,
    BASE_LAB_CTF,
    BUILTIN_LABELS,
)

#: The built-in each retired workspace type corresponds to. The one table that
#: maps a type to a policy; :func:`legacy_type_builtin` is its only reader.
LEGACY_TYPE_BUILTINS: dict[str, str] = {"ctf": BASE_LAB_CTF, "audit": BASE_AUDIT}

#: The retired values, in the order help text lists them.
LEGACY_TYPE_VALUES: tuple[str, ...] = tuple(LEGACY_TYPE_BUILTINS)

FORM_REPL = "repl"
FORM_CI = "ci"
FORMS: tuple[str, ...] = (FORM_REPL, FORM_CI)

#: Policies the ``ci`` panels list before pointing at the full list.
MAX_LISTED_POLICIES = 10

#: What a policy decides, in one sentence.
POLICY_DECIDES_LINE = (
    "A scan policy decides which checks run, the scan pace and how many password "
    "attempts stay in reserve before an account lockout. Production-sensitive is "
    "the built-in for systems that must not be disturbed."
)

TONE_INFO = "info"
TONE_ERROR = "error"
TONE_WARNING = "warning"

#: Indent of a command under its label.
_COMMAND_INDENT = "  "


def legacy_type_builtin(value: str | None) -> str | None:
    """The built-in id a retired type corresponds to, ``None`` for anything else."""
    return LEGACY_TYPE_BUILTINS.get(str(value or "").strip().lower())


def repl_use_command(builtin_key: str) -> str:
    """The REPL command that selects a built-in, by its display name."""
    label = BUILTIN_LABELS.get(builtin_key, builtin_key)
    return f'policy use "{label}"' if " " in label else f"policy use {label}"


def ci_policy_flag(flag_value: str) -> str:
    """The ``adscan ci`` flag that names a policy."""
    return f"--policy {flag_value}"


@dataclass(frozen=True)
class NoticeLine:
    """One line of a notice.

    Attributes:
        text: The words.
        kind: ``body`` (wraps), ``muted`` (wraps, dimmed), ``label`` (a short
            heading for the command under it), ``command`` (never wraps) or
            ``link`` (``text`` is an outbound-link placement; never wraps).
    """

    text: str
    kind: str = "body"


@dataclass(frozen=True)
class Notice:
    """A titled notice: what :func:`render_notice` draws."""

    title: str
    lines: tuple[NoticeLine, ...]
    tone: str = TONE_INFO

    def plain(self) -> str:
        """The notice as plain text (debug log, tests); a link shows its URL."""
        return "\n".join(
            [
                self.title,
                *(_link_display(ln.text) if ln.kind == "link" else ln.text for ln in self.lines),
            ]
        )

    @property
    def commands(self) -> tuple[str, ...]:
        return tuple(line.text for line in self.lines if line.kind == "command")


@dataclass(frozen=True)
class PolicyChoice:
    """One policy the operator can name with ``--policy``.

    Attributes:
        flag_value: What to type after ``--policy`` (a built-in key or a slug).
        label: The policy's display name.
        scope: ``built-in``, ``workspace`` or ``global``.
    """

    flag_value: str
    label: str
    scope: str


def _choice_lines(choices: Sequence[PolicyChoice]) -> list[NoticeLine]:
    """The ``Policies you can name`` block (capped, then ``adscan policy list``)."""
    if not choices:
        return []
    listed = list(choices[:MAX_LISTED_POLICIES])
    width = max(len(c.flag_value) for c in listed)
    lines = [NoticeLine("Policies you can name:", "label")]
    lines += [
        NoticeLine(f"{c.flag_value.ljust(width)}  {c.label} ({c.scope})", "command")
        for c in listed
    ]
    if len(choices) > len(listed):
        lines.append(NoticeLine(f"And {len(choices) - len(listed)} more:", "label"))
        lines.append(NoticeLine("adscan policy list", "command"))
    return lines


def _require_legacy(value: str) -> tuple[str, str]:
    token = str(value or "").strip().lower()
    builtin_key = legacy_type_builtin(token)
    if builtin_key is None:
        raise ValueError(f"{value!r} is not a retired workspace type")
    return token, builtin_key


#: The scan-policies guide (outbound-link SSOT placement).
DOCS_PLACEMENT = "legacy_type_notice"


def _docs_lines() -> list[NoticeLine]:
    """The one documentation link every panel ends with."""
    return [NoticeLine("The scan-policies guide:", "label"), NoticeLine(DOCS_PLACEMENT, "link")]


def _ci_flag_lines(choices: Sequence[PolicyChoice]) -> list[NoticeLine]:
    """What the ``ci`` panels teach: the flags, then the host commands."""
    return [
        NoticeLine(POLICY_DECIDES_LINE),
        *_choice_lines(choices),
        NoticeLine(
            "The scan pace is optional. Without these, the run uses the policy's own "
            "pace, always within the limit the policy sets."
        ),
        NoticeLine("Choose a pace:", "label"),
        NoticeLine("--pace-profile NAME", "command"),
        NoticeLine("--pacing fragile|polite|normal|fast", "command"),
        NoticeLine("From the host, without opening the shell:", "label"),
        NoticeLine("adscan policy list", "command"),
        NoticeLine("adscan policy create", "command"),
        NoticeLine("adscan pace create", "command"),
        *_docs_lines(),
    ]


def build_ci_type_notice(value: str, *, choices: Sequence[PolicyChoice] = ()) -> Notice:
    """The panel for ``adscan ci --type VALUE`` without ``--policy``: nothing runs.

    Args:
        value: The retired value the operator gave (``ctf`` / ``audit``).
        choices: The policies the run could name, built-ins first.

    Raises:
        ValueError: On a value that is not a retired type.
    """
    token, builtin_key = _require_legacy(value)
    lines: list[NoticeLine] = [
        NoticeLine(
            f"Nothing ran, and nothing was sent to the network. Scan policies "
            f"replaced --type, so --type {token} no longer chooses how a scan "
            "behaves, and adscan ci runs only under a policy you name."
        ),
        NoticeLine("Run the same scan with:", "label"),
        NoticeLine(ci_policy_flag(builtin_key), "command"),
        *_ci_flag_lines(choices),
    ]
    return Notice(title="--type was replaced by scan policies", lines=tuple(lines), tone=TONE_ERROR)


def ci_type_ignored_line(value: str, *, policy_named: str) -> str:
    """The one line ``adscan ci --type VALUE --policy NAME`` prints: the policy runs."""
    token = str(value or "").strip().lower()
    return (
        f"--type {token} was ignored. Scan policies replaced it, and this run follows "
        f"the policy you named, {policy_named}. Drop --type from the command, since it "
        "stops being accepted at the next major release."
    )


def build_missing_policy_notice(
    choices: Sequence[PolicyChoice],
    *,
    unknown_name: str = "",
) -> Notice:
    """The refusal ``adscan ci`` prints when the run names no usable policy.

    Args:
        choices: The policies the run could name, built-ins first.
        unknown_name: The ``--policy`` value that matched nothing, when that is
            the reason (empty when no policy was named at all).
    """
    if unknown_name:
        title = f"No scan policy is called '{unknown_name}'"
        lead = (
            "Nothing ran, and nothing was sent to the network. The name matched no "
            "built-in or saved policy."
        )
    else:
        title = "adscan ci needs a scan policy"
        lead = (
            "Nothing ran, and nothing was sent to the network. adscan ci runs only "
            "under a scan policy you name."
        )
    example = next((c.flag_value for c in choices if c.flag_value == BASE_AUDIT), "")
    example = example or (choices[0].flag_value if choices else BASE_AUDIT)
    lines: list[NoticeLine] = [
        NoticeLine(lead),
        NoticeLine("Add one to the command, for example:", "label"),
        NoticeLine(ci_policy_flag(example), "command"),
        *_ci_flag_lines(choices),
    ]
    return Notice(title=title, lines=tuple(lines), tone=TONE_ERROR)


def build_repl_type_notice(value: str, *, active_policy: str = "") -> Notice:
    """The panel for the REPL ``set type VALUE``, which changes nothing.

    Args:
        value: The retired value the operator gave.
        active_policy: Display name of the policy in force (empty when none).

    Raises:
        ValueError: On a value that is not a retired type.
    """
    token, builtin_key = _require_legacy(value)
    current = (
        f"The workspace keeps its scan policy, {active_policy}."
        if active_policy
        else "The workspace has no scan policy yet."
    )
    lines = (
        NoticeLine(
            f"Nothing changed. Scan policies replaced the workspace type, so "
            f"'set type {token}' no longer chooses how a scan behaves. {current}"
        ),
        NoticeLine("Use the policy it corresponded to:", "label"),
        NoticeLine(repl_use_command(builtin_key), "command"),
        NoticeLine(POLICY_DECIDES_LINE),
        NoticeLine("See every policy:", "label"),
        NoticeLine("policy list", "command"),
        NoticeLine(
            "Create your own in the editor, saved for this workspace or for all "
            "workspaces:",
            "label",
        ),
        NoticeLine("policy create", "command"),
        NoticeLine("Choose the scan pace, within the policy's limit:", "label"),
        NoticeLine("pace use PROFILE", "command"),
        NoticeLine("show pacing", "command"),
        *_docs_lines(),
    )
    return Notice(title="'set type' was replaced by scan policies", lines=lines)


def render_notice(notice: Notice) -> Group:
    """The notice body as Rich renderables (no markup parsing of any value)."""
    rows: list[Text] = []
    previous_kind = ""
    for line in notice.lines:
        if line.kind == "link":
            rows.append(
                Text(
                    _COMMAND_INDENT + _link_display(line.text),
                    style=_link_style(line.text),
                    no_wrap=True,
                    overflow="ignore",
                )
            )
        elif line.kind == "command":
            rows.append(
                Text(
                    _COMMAND_INDENT + line.text,
                    style=_command_style(),
                    no_wrap=True,
                    overflow="ignore",
                )
            )
        elif line.kind == "label":
            if previous_kind and previous_kind != "label":
                rows.append(Text(""))
            rows.append(Text(line.text, style="bold"))
        else:
            if previous_kind:
                rows.append(Text(""))
            rows.append(Text(line.text, style="dim" if line.kind == "muted" else ""))
        previous_kind = line.kind
    return Group(*rows)


def _link_display(placement: str) -> str:
    from adscan_core.outbound_links import cta_display_url  # noqa: PLC0415

    return cta_display_url(placement)


def _link_style(placement: str) -> str:
    from adscan_core.outbound_links import cta_link_style  # noqa: PLC0415

    return cta_link_style(placement, _command_style())


def _command_style() -> str:
    try:
        from adscan_core.rich_output import BRAND_COLORS  # noqa: PLC0415

        return f"bold {BRAND_COLORS['info']}"
    except Exception:  # noqa: BLE001 - colour only
        return "bold"


def print_notice(notice: Notice) -> None:
    """Print a notice through the shared console (recorded, inline in CI)."""
    from adscan_core.rich_output import (  # noqa: PLC0415
        BRAND_COLORS,
        print_info_debug,
        print_panel,
    )

    border = BRAND_COLORS.get(notice.tone, BRAND_COLORS["info"])
    print_panel(
        render_notice(notice),
        title=Text(notice.title, style="bold"),
        title_align="left",
        border_style=border,
        padding=(1, 2),
    )
    print_info_debug("scan-policy guidance: " + notice.plain().replace("\n", " | "))


__all__ = (
    "DOCS_PLACEMENT",
    "FORMS",
    "FORM_CI",
    "FORM_REPL",
    "LEGACY_TYPE_BUILTINS",
    "LEGACY_TYPE_VALUES",
    "MAX_LISTED_POLICIES",
    "POLICY_DECIDES_LINE",
    "TONE_ERROR",
    "TONE_INFO",
    "TONE_WARNING",
    "Notice",
    "NoticeLine",
    "PolicyChoice",
    "build_ci_type_notice",
    "build_missing_policy_notice",
    "build_repl_type_notice",
    "ci_type_ignored_line",
    "ci_policy_flag",
    "legacy_type_builtin",
    "print_notice",
    "render_notice",
    "repl_use_command",
)
