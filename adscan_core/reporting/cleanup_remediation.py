"""Split a stored cleanup instruction into prose and commands.

A ledger record keeps its client-facing cleanup instruction as ONE string that
mixes explanation with the commands to run (``remediation_command``). Every
renderer used to print that string whole, so an explanatory ``#`` line landed
inside the monospace command box and a client copying the block pasted the
comment into a shell.

:func:`remediation_steps` is the single place that turns the string into the
structured shape the rest of the product already uses for client commands
(``intro`` prose shown before the command, ``command`` holding only the
command). It also converts strings stored by an older version, comment lines
included, so an old workspace renders correctly at display time without a
migration.

Dependency-light on purpose (stdlib plus ``runbook_model``): the engine, the
LITE report and the web backend all import it.
"""

from __future__ import annotations

import re
from typing import Any

from adscan_core.reporting.runbook_model import (
    infer_command_platform,
    normalize_runbook_commands,
)

__all__ = ["remediation_steps", "remediation_step_commands"]

#: ``1. Confirm it exists:`` style procedure labels are prose, never a command.
_NUMBERED_RE = re.compile(r"^\d+[.)]\s")
#: First token of a PowerShell cmdlet (``Remove-ADUser``) or a native console tool.
_COMMAND_START_RE = re.compile(
    r"^(?:\$\w|\(|@\(|\[|[A-Za-z]+-[A-Za-z][\w]*\b"
    r"|(?:net|net1|certutil|dsacls|sc|reg|schtasks|del|rm|rd|icacls|takeown|wmic"
    r"|cmd|powershell|pwsh|ntdsutil|repadmin|dnscmd|dcdiag|gpupdate|klist|nltest"
    r"|setspn|ldifde|csvde|esentutl|vssadmin|whoami|sudo)(?:\.exe)?(?:\s|$))",
    re.IGNORECASE,
)
#: A T-SQL statement stored on its own (``EXEC sp_configure ...``). Upper case
#: only, so a sentence that opens with "Use" or "Create" never reads as SQL.
_SQL_START_RE = re.compile(
    r"^(?:EXEC|EXECUTE|DROP|ALTER|CREATE|SELECT|RECONFIGURE|REVOKE|GRANT|DENY|USE)\b"
)
_COMMENT_START = ("#", "//", "--")
#: A sentence that says where, or as whom, the commands run. It is lifted out of
#: the intro and shown as a caption beside the command block, the way every
#: other command surface shows the account a command runs as.
_RUN_NOTE_RE = re.compile(r"^Run\b.*\b(?:as|on)\b", re.IGNORECASE)
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.:)])\s+(?=[A-Z])")
_BELOW_RE = (
    (re.compile(r"\bthe commands below\b"), "these commands"),
    (re.compile(r"\bthe command below\b"), "this command"),
    (re.compile(r"\bthem below\b"), "them"),
)


def _is_comment(stripped: str) -> bool:
    return stripped.startswith(_COMMENT_START) or bool(re.match(r"^rem(?:\s|$)", stripped, re.IGNORECASE))


def _sentence_like(stripped: str) -> bool:
    """Whether an indented line reads as a sentence rather than a command."""
    return (
        stripped.endswith((".", ":"))
        and len(stripped.split()) >= 4
        and not _COMMAND_START_RE.match(stripped)
        and not _SQL_START_RE.match(stripped)
    )


def _is_command_line(raw: str) -> bool:
    stripped = raw.strip()
    if _NUMBERED_RE.match(stripped):
        return False
    if _COMMAND_START_RE.match(stripped) or _SQL_START_RE.match(stripped):
        return True
    indent = len(raw) - len(raw.lstrip(" "))
    return indent >= 2 and not _sentence_like(stripped)


def _prose_text(stripped: str) -> str:
    """A prose line as text: the comment marker and a procedure number dropped.

    Each step renders as its own block, in order, so the ``1.`` the stored
    procedure carried would only repeat what the layout already shows.
    """
    body = stripped.lstrip("#").strip() if _is_comment(stripped) else stripped
    return _NUMBERED_RE.sub("", body, count=1).strip()


def _chunks(text: str) -> list[tuple[list[str], list[str]]]:
    """Split the instruction into ``(runbook lines, outro sentences)`` chunks.

    A prose line indented under a command, and not ending in a colon, explains
    the result of that command (``Disposition must now read 21``): it stays with
    that command as its outro instead of becoming the intro of the next one. Any
    other prose line after a command opens the next chunk. Prose becomes a
    comment line, which the legacy converter turns into the intro of the command
    that follows it; a comment-bearing string stored by an older version goes
    through the same path.
    """
    chunks: list[tuple[list[str], list[str]]] = []
    lines: list[str] = []
    outro: list[str] = []
    after_command = False
    for raw in str(text or "").splitlines():
        stripped = raw.strip()
        if not stripped:
            continue
        if not _is_comment(stripped) and _is_command_line(raw):
            if outro:
                chunks.append((lines, outro))
                lines, outro = [], []
            lines.append(stripped)
            after_command = True
            continue
        body = _prose_text(stripped)
        if not body:
            continue
        indented = len(raw) - len(raw.lstrip(" ")) >= 2
        numbered = bool(_NUMBERED_RE.match(stripped))
        if after_command and indented and not numbered and not body.endswith(":"):
            outro.append(body)
            continue
        if after_command:
            chunks.append((lines, outro))
            lines, outro = [], []
            after_command = False
        lines.append(f"# {body}")
    if lines or outro:
        chunks.append((lines, outro))
    return chunks


def _split_run_note(intro: str) -> tuple[str, str]:
    """Lift the "Run ... as / on ..." sentences out of an intro into a caption."""
    kept: list[str] = []
    notes: list[str] = []
    for sentence in _SENTENCE_SPLIT_RE.split(str(intro or "").strip()):
        if not sentence:
            continue
        if _RUN_NOTE_RE.match(sentence):
            note = sentence.rstrip(" :.")
            for pattern, repl in _BELOW_RE:
                note = pattern.sub(repl, note)
            notes.append(note + ".")
        else:
            kept.append(sentence)
    return " ".join(kept).strip(), " ".join(notes).strip()


def _sentence(text: str) -> str:
    out = re.sub(r"\s+", " ", str(text or "")).strip().rstrip(" :;,")
    return out if not out or out.endswith((".", "!", "?", ")")) else out + "."


def remediation_steps(text: str | None) -> list[dict[str, Any]]:
    """Return the instruction as ordered steps, prose apart from commands.

    Each step is ``{"intro", "command", "platform", "caption", "outro"}``:

    * ``intro``: prose shown before the command (empty when the step is only a
      command);
    * ``command``: command lines only (empty for a prose-only paragraph);
    * ``platform``: where the command runs (``windows``, ``sql`` or ``linux``);
    * ``caption``: the "run it as / on" note shown beside the command, lifted out
      of the intro;
    * ``outro``: what the command's result means, shown after it.

    Every surface draws a step with its shared command block (``TerminalBlock``
    in the web, the runbook command style in the reports). Never raises; an
    empty or unusable value returns ``[]``.
    """
    steps: list[dict[str, Any]] = []
    try:
        for lines, outro in _chunks(str(text or "")):
            items = normalize_runbook_commands(lines) if lines else []
            chunk_steps: list[dict[str, Any]] = []
            for item in items:
                intro = str(item.get("intro") or "")
                command = str(item.get("command") or "")
                caption = ""
                if command.strip():
                    intro, caption = _split_run_note(intro)
                chunk_steps.append(
                    {
                        "intro": intro,
                        "command": command,
                        "platform": infer_command_platform(command) if command.strip() else "windows",
                        "caption": caption,
                        "outro": "",
                    }
                )
            if outro:
                note = " ".join(_sentence(o) for o in outro)
                with_command = [s for s in chunk_steps if s["command"].strip()]
                if with_command:
                    with_command[-1]["outro"] = note
                else:
                    chunk_steps.append(
                        {"intro": note, "command": "", "platform": "windows", "caption": "", "outro": ""}
                    )
            steps.extend(chunk_steps)
    except Exception:  # noqa: BLE001 - display helper, must not break a report
        return []
    return steps


def remediation_step_commands(text: str | None) -> list[str]:
    """Every command line of the instruction, in order, comments excluded."""
    out: list[str] = []
    for step in remediation_steps(text):
        out.extend(line.strip() for line in step["command"].splitlines() if line.strip())
    return out
