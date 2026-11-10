"""The structured fix-runbook command: one shape for remediation, report and web.

A finding's ``remediation_options`` are runbooks: an approach, numbered steps,
the commands that apply the fix and the check that confirms it landed. The
commands used to be a flat list of strings in which explanation and command
alternated as ``#`` comment lines, so a client copying the block pasted the
comments with it and the deliverable printed internal notes inside a command.
The independent-verification block had the same defect and was moved to
structured data (:mod:`adscan_core.reporting.verification_model`); this module
gives the runbook commands the SAME shape, so the web renders both with one
terminal component and the report prints both with one command style::

    Command = {
        "platform": "windows" | "linux" | "sql",
        "audience": "sysadmin",
        "intro": str,        # prose shown BEFORE the block (may stand alone)
        "command": str,      # the pure command, no comment of any kind; "" for a
                             # prose-only instruction (a Group Policy setting)
        "unfilled": [str],   # <token> names still standing after the fill
        "scope_note": str,   # optional: how the command covers several assets
        "applies_to": {"role": str, "count": int, "mode": str},  # optional
    }

Three rules this module owns:

1. A command carries no comment (same detector as verification,
   :func:`~adscan_core.reporting.verification_model.command_comment_violations`).
   :func:`legacy_runbook_items` converts the old flat list deterministically, so a
   runbook baked onto a finding by an older scan renders clean too.
2. A Group Policy path or a console click-path is an instruction, not a command:
   it becomes a prose-only item, never a line in a code block.
3. A command written for ONE affected object covers every affected object of
   that role (:func:`expand_for_assets`): up to :data:`MULTI_ASSET_LIST_LIMIT`
   objects it runs once over an explicit list; above that it uses the finding's
   query selector when one is declared, and otherwise shows one filled example
   and points at the Affected Assets list. It never invents an object.

Dependency-light on purpose (stdlib + ``verification_model``): the finding
catalog, the report and the web backend (appliance bundle, which ships
``adscan_core`` whole) all import it.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping, Sequence

from adscan_core.reporting.verification_model import (
    _inline_hash_comment_index,
    command_comment_violations,
    join_wrapped_comments,
    unfilled_tokens,
)

__all__ = [
    "ASSET_ROLE_TOKENS",
    "MULTI_ASSET_LIST_LIMIT",
    "RUNBOOK_PLATFORMS",
    "assets_by_role_from_roles",
    "expand_for_assets",
    "expand_options_for_assets",
    "infer_command_platform",
    "legacy_runbook_items",
    "normalize_runbook_commands",
    "powershell_quote_context",
    "runbook_command_violations",
    "stamp_unfilled",
]

#: Where a runbook command runs. ``sql`` is a query for SQL Server Management
#: Studio or ``sqlcmd``; it carries no shell prompt.
RUNBOOK_PLATFORMS: tuple[str, ...] = ("windows", "linux", "sql")

#: Up to this many affected objects, a per-object command is written once over
#: an explicit list. Above it the list stops being readable in a code block.
MULTI_ASSET_LIST_LIMIT = 10

#: The canonical per-object tokens, by the affected-asset ROLE that fills them,
#: with the loop variable a multi-object command uses and the noun its scope note
#: reads. ``$host`` is a PowerShell automatic variable, so the SPN host loops as
#: ``$spnHost``.
ASSET_ROLE_TOKENS: dict[str, dict[str, str]] = {
    "account": {"token": "<ACCOUNT>", "var": "account", "noun": "account"},
    "template": {"token": "<TEMPLATE>", "var": "template", "noun": "certificate template"},
    "trustee": {"token": "<TRUSTEE>", "var": "trustee", "noun": "principal holding the right"},
    "computer": {"token": "<COMPUTER>", "var": "computer", "noun": "computer"},
    "spn_host": {"token": "<SPN-HOST>", "var": "spnHost", "noun": "service host"},
    "share": {"token": "<SHARE>", "var": "share", "noun": "share"},
    "ca": {"token": "<CA>", "var": "ca", "noun": "certificate authority"},
    # A host a check or a fix is run against by network name. Not a canonical
    # personalizer token: with one affected host it stays an honest fill-in.
    "host": {"token": "<host>", "var": "targetHost", "noun": "host"},
    # A full service principal name (MSSQLSvc/sql01.corp.example:1433), for a
    # command that moves or removes the exact SPN a roasting finding exposed.
    "spn": {"token": "<service_principal_name>", "var": "spn", "noun": "service principal name"},
    # The account an explicit certificate mapping points at (ESC14). Kept apart
    # from ``account`` on purpose: the single-value personalizer resolves
    # ``<ACCOUNT>`` from the finding's subject, which for ESC14 is the template,
    # and a template name must never land in a mapping command.
    "mapped_account": {"token": "<mapped_account>", "var": "account", "noun": "mapped account"},
}

#: Tokens the personalizer fills from the domain itself. A command may carry them
#: next to a per-object token and still be looped, because they are the same for
#: every object.
_ENVIRONMENT_TOKENS: frozenset[str] = frozenset({"DOMAIN", "DOMAIN-DN", "DC-FQDN", "SHARE-FILE"})

_PLURAL_NOUNS: dict[str, str] = {
    "principal holding the right": "principals holding the right",
    "certificate authority": "certificate authorities",
}

# ── Platform inference ────────────────────────────────────────────────────────

#: A T-SQL statement as the catalog writes it: an upper-case keyword followed by
#: whitespace. Case-sensitive on purpose, so ``Grant-SmbShareAccess`` and
#: ``Update-LapsADSchema`` (PowerShell cmdlets) are not read as SQL.
_SQL_START_RE = re.compile(
    r"^(?:SELECT|REVOKE|GRANT|DENY|ALTER|EXEC(?:UTE)?|USE|CREATE|DROP|UPDATE|INSERT|DELETE)\s"
)
_LINUX_TOOLS: frozenset[str] = frozenset(
    {
        "nmap",
        "nxc",
        "netexec",
        "certipy",
        "certipy-ad",
        "ldapsearch",
        "smbclient",
        "rpcclient",
        "kinit",
        "grep",
        "curl",
        "python3",
        "bloodyad",
        "sudo",
        "openssl",
    }
)


def infer_command_platform(command: str) -> str:
    """Return the platform a command runs on, judged from its first token.

    Used once, by the legacy conversion. An authored command states its platform;
    a contract test asserts the authored value agrees with this inference for the
    two unmistakable cases (a SQL statement, a Linux tool).
    """
    first_line = next((ln.strip() for ln in str(command or "").splitlines() if ln.strip()), "")
    if _SQL_START_RE.match(first_line):
        return "sql"
    first = first_line.split(maxsplit=1)[0].lower() if first_line else ""
    if first in _LINUX_TOOLS or first.startswith("impacket-"):
        return "linux"
    return "windows"


# ── Legacy conversion ─────────────────────────────────────────────────────────


def _prose(text: str) -> str:
    """Normalise a comment fragment into one client-facing sentence.

    Collapses whitespace, turns a dash or arrow joiner into plain words, drops
    a trailing colon and always ends on a full stop, so two fragments joined
    into one intro never run together.
    """
    out = re.sub(r"\s+", " ", str(text or "")).strip()
    out = out.replace(" — ", ", ").replace("—", ", ").replace(" -> ", " to ")
    out = out.rstrip(" :;,")
    if not out:
        return ""
    out = out[0].upper() + out[1:]
    if out[-1] not in ".!?":
        out += "."
    return out

_GPO_RE = re.compile(r"^GPO(?:\s+path)?\s*(?:\(([^)]*)\))?\s*:\s*(.+)$", re.IGNORECASE)
_GUI_RE = re.compile(r"^GUI\s*:\s*(.+)$", re.IGNORECASE)
#: A console click-path written as if it were a command: ``certtmpl.msc > ...``.
_MSC_PATH_RE = re.compile(r"^[\w.-]+\.msc\s*>\s*\S", re.IGNORECASE)
_SETTING_RE = re.compile(r"^(.*\S)\s+=\s+(\S.*)$")


def _instruction_prose(line: str) -> str:
    """Rewrite a Group Policy / console click-path line as an instruction sentence."""
    gpo = _GPO_RE.match(line)
    if gpo:
        scope, body = gpo.group(1), gpo.group(2).strip()
        where = f"In the Group Policy linked to the {scope.strip()}" if scope else "In Group Policy"
        setting = _SETTING_RE.match(body)
        if setting:
            return _prose(f"{where}, set {setting.group(1)} to {setting.group(2)}")
        if ">" in body:
            return _prose(f"{where}, open {body}")
        return _prose(f"{where}, {body[:1].lower()}{body[1:]}")
    gui = _GUI_RE.match(line)
    if gui:
        return _prose(f"In the console, go to {gui.group(1).strip()}")
    if _MSC_PATH_RE.match(line):
        return _prose(f"In the console, go to {line.strip()}")
    return _prose(line)


def _is_instruction_line(stripped: str) -> bool:
    """Whether a non-comment line is a click-path or policy path, not a command."""
    return bool(_GPO_RE.match(stripped) or _GUI_RE.match(stripped) or _MSC_PATH_RE.match(stripped))


def _is_comment(stripped: str) -> bool:
    return (
        stripped.startswith("#")
        or stripped.startswith("-- ")
        or stripped == "--"
        or stripped.startswith("//")
        or bool(re.match(r"^rem(?:\s|$)", stripped, re.IGNORECASE))
    )


def _comment_text(stripped: str) -> str:
    for marker in ("#", "--", "//"):
        if stripped.startswith(marker):
            return stripped[len(marker) :].lstrip("#").strip()
    return re.sub(r"^rem\s*", "", stripped, flags=re.IGNORECASE).strip()


def _split_trailing_comment(line: str, platform: str) -> tuple[str, str]:
    """Return ``(command, trailing_comment)`` for one command line."""
    if platform == "sql":
        quote = ""
        for index, char in enumerate(line):
            if quote:
                if char == quote:
                    quote = ""
            elif char == "'":
                quote = char
            elif line.startswith("--", index) and (index == 0 or line[index - 1].isspace()):
                return line[:index].rstrip(), line[index + 2 :].strip()
        return line.rstrip(), ""
    cut = _inline_hash_comment_index(line)
    if cut < 0:
        return line.rstrip(), ""
    return line[:cut].rstrip(), line[cut:].lstrip("#").strip()


def legacy_runbook_items(lines: Iterable[Any]) -> list[dict[str, Any]]:
    """Convert a legacy flat command list into structured runbook commands.

    Each element of ``lines`` is one line (an element carrying newlines is split).
    A comment line becomes the ``intro`` of the command that follows it; adjacent
    command lines form one block; a trailing ``# ...`` moves into the intro; a
    Group Policy or console click-path line becomes a prose-only item; a comment
    with no command after it becomes a prose-only item too, so no explanation is
    lost and none is left inside a command.

    Args:
        lines: The legacy ``commands`` list (strings).

    Returns:
        Structured items (``platform`` / ``audience`` / ``intro`` / ``command``).
    """
    items: list[dict[str, Any]] = []
    intro_parts: list[str] = []
    block: list[str] = []
    block_platform = ""

    def intro_text(parts: list[str]) -> str:
        # A comment wrapped over several lines stays one sentence.
        return " ".join(p for p in (_prose(x) for x in join_wrapped_comments(parts)) if p)

    def flush() -> None:
        nonlocal block_platform
        if block:
            items.append(
                {
                    "platform": block_platform or "windows",
                    "audience": "sysadmin",
                    "intro": intro_text(intro_parts),
                    "command": "\n".join(block),
                }
            )
            intro_parts.clear()
            block.clear()
        block_platform = ""

    flat: list[str] = []
    for raw in lines or ():
        flat.extend(str(raw).splitlines())
    for raw in flat:
        stripped = raw.strip()
        if not stripped:
            continue
        if _is_comment(stripped):
            flush()
            text = _comment_text(stripped)
            if (_GPO_RE.match(text) or _GUI_RE.match(text)) and text.count(" = ") <= 1:
                # A single setting written as a comment reads as an instruction.
                text = _instruction_prose(text)
            if text:
                intro_parts.append(text)
            continue
        if _is_instruction_line(stripped):
            flush()
            sentence = _instruction_prose(stripped)
            items.append(
                {
                    "platform": "windows",
                    "audience": "sysadmin",
                    "intro": " ".join(p for p in (intro_text(intro_parts), sentence) if p),
                    "command": "",
                }
            )
            intro_parts.clear()
            continue
        platform = infer_command_platform(stripped) if not block else block_platform
        if block and (infer_command_platform(stripped) == "sql") != (block_platform == "sql"):
            # A SQL statement never shares a block with a shell command.
            flush()
            platform = infer_command_platform(stripped)
        line, trailing = _split_trailing_comment(raw, platform)
        if trailing:
            intro_parts.append(trailing)
        if line.strip():
            block.append(line.strip() if not block else line.rstrip())
            block_platform = platform
    flush()
    if intro_parts:
        items.append(
            {"platform": "windows", "audience": "sysadmin", "intro": intro_text(intro_parts), "command": ""}
        )
    return items


# ── Normalization ─────────────────────────────────────────────────────────────


def _clean_item(raw: Mapping[str, Any]) -> dict[str, Any] | None:
    command = str(raw.get("command") or "").strip("\n").rstrip()
    intro = str(raw.get("intro") or "").strip()
    if not command.strip() and not intro:
        return None
    platform = str(raw.get("platform") or "").strip().lower()
    if platform not in RUNBOOK_PLATFORMS:
        platform = infer_command_platform(command) if command.strip() else "windows"
    item: dict[str, Any] = {
        "platform": platform,
        "audience": "sysadmin",
        "intro": intro,
        "command": command,
    }
    for key in ("scope_note",):
        if str(raw.get(key) or "").strip():
            item[key] = str(raw.get(key)).strip()
    applies_to = raw.get("applies_to")
    if isinstance(applies_to, Mapping) and applies_to.get("role"):
        item["applies_to"] = {
            "role": str(applies_to.get("role")),
            "count": int(applies_to.get("count") or 0),
            "mode": str(applies_to.get("mode") or ""),
        }
    unfilled = raw.get("unfilled")
    if isinstance(unfilled, (list, tuple)):
        item["unfilled"] = [str(name) for name in unfilled if str(name).strip()]
    return item


def normalize_runbook_commands(raw: Any) -> list[dict[str, Any]]:
    """Return a runbook ``commands`` value as structured items, never raising.

    Accepts the structured list (dict items), the legacy flat string list, or a
    mix of the two (a run of strings is converted together, so a comment line
    still introduces the command after it).
    """
    if not isinstance(raw, (list, tuple)):
        return []
    out: list[dict[str, Any]] = []
    pending: list[str] = []

    def flush_legacy() -> None:
        if pending:
            for item in legacy_runbook_items(pending):
                cleaned = _clean_item(item)
                if cleaned is not None:
                    out.append(cleaned)
            pending.clear()

    for entry in raw:
        if isinstance(entry, Mapping):
            flush_legacy()
            cleaned = _clean_item(entry)
            if cleaned is not None:
                out.append(cleaned)
        elif isinstance(entry, str) and entry.strip():
            pending.append(entry)
    flush_legacy()
    return out


def stamp_unfilled(items: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Return copies of ``items`` carrying the ``<token>`` names still standing."""
    stamped: list[dict[str, Any]] = []
    for item in items:
        copy = dict(item)
        copy["unfilled"] = unfilled_tokens(str(item.get("command") or ""))
        stamped.append(copy)
    return stamped


def runbook_command_violations(item: Mapping[str, Any]) -> list[str]:
    """Return every authoring violation of one structured runbook command."""
    problems = list(command_comment_violations(str(item.get("command") or "")))
    command = str(item.get("command") or "")
    if command.strip():
        stated = str(item.get("platform") or "")
        inferred = infer_command_platform(command)
        if inferred in ("sql", "linux") and stated != inferred:
            problems.append(f"platform is {stated!r} but the command is a {inferred} command")
    if not command.strip() and not str(item.get("intro") or "").strip():
        problems.append("empty item")
    return problems


# ── Multi-asset expansion ─────────────────────────────────────────────────────


def _powershell_scan(text: str, limit: int) -> tuple[str, list[tuple[int, int]]]:
    """Walk ``text[:limit]`` as PowerShell; return the context at ``limit`` and
    the spans of every single-quoted literal that is still open or closed.

    ``spans`` holds ``(start, end)`` for each completed ``'...'`` literal (end is
    the index of the closing quote) and ``(start, -1)`` for one open at ``limit``.
    """
    stack: list[str] = ["bare"]
    paren: list[int] = []
    spans: list[tuple[int, int]] = []
    open_single = -1
    i = 0
    stop = min(limit, len(text))
    while i < stop:
        ctx = stack[-1]
        char = text[i]
        if ctx == "single":
            if char == "'":
                if i + 1 < len(text) and text[i + 1] == "'":
                    i += 2
                    continue
                stack.pop()
                spans.append((open_single, i))
                open_single = -1
            i += 1
            continue
        if ctx == "double":
            if char == "`":
                i += 2
                continue
            if char == '"':
                stack.pop()
            elif char == "$" and i + 1 < len(text) and text[i + 1] == "(":
                stack.append("subexpr")
                paren.append(1)
                i += 2
                continue
            i += 1
            continue
        if char == "'":
            stack.append("single")
            open_single = i
        elif char == '"':
            stack.append("double")
        elif ctx == "subexpr":
            if char == "(":
                paren[-1] += 1
            elif char == ")":
                paren[-1] -= 1
                if paren[-1] == 0:
                    stack.pop()
                    paren.pop()
        i += 1
    if open_single >= 0:
        spans.append((open_single, -1))
    top = stack[-1]
    return ("single" if top == "single" else "double" if top == "double" else "bare"), spans


def powershell_quote_context(text: str, pos: int) -> str:
    """Return ``"single"``, ``"double"`` or ``"bare"``: the PowerShell string
    context at ``text[pos]``. Handles ``$( ... )`` subexpressions inside a
    double-quoted string, where quotes start fresh."""
    return _powershell_scan(text, pos)[0]


def _closing_single_quote(text: str, start: int) -> int:
    """Index of the quote closing the ``'...'`` literal opened at ``start``."""
    i = start + 1
    while i < len(text):
        if text[i] == "'":
            if i + 1 < len(text) and text[i + 1] == "'":
                i += 2
                continue
            return i
        i += 1
    return len(text) - 1


def _ps_variable_in_line(line: str, token: str, var: str) -> str:
    """Replace ``token`` in one PowerShell line with ``$var`` for its context.

    Bare: ``$var`` (``"${var}"`` when glued to a following name character).
    Double-quoted: ``${var}``. Single-quoted: the enclosing literal does not
    expand variables, so it is rewritten as a double-quoted one with its ``$``,
    backtick and ``"`` escaped, and the token becomes ``${var}``.
    """
    pattern = re.compile(re.escape(token), re.IGNORECASE)
    out = line
    guard = 0
    while guard < 50:
        guard += 1
        match = pattern.search(out)
        if not match:
            break
        context, spans = _powershell_scan(out, match.start())
        if context == "single":
            start = next(s for s, e in reversed(spans) if e == -1)
            end = _closing_single_quote(out, start)
            body = out[start + 1 : end].replace("''", "'")
            body = body.replace("`", "``").replace('"', '`"').replace("$", "`$")
            body = pattern.sub("${" + var + "}", body)
            out = out[:start] + '"' + body + '"' + out[end + 1 :]
            continue
        if context == "double":
            out = out[: match.start()] + "${" + var + "}" + out[match.end() :]
            continue
        following = out[match.end() : match.end() + 1]
        replacement = f"${var}" if not re.match(r"[A-Za-z0-9_$:.\-]", following) else '"${' + var + '}"'
        out = out[: match.start()] + replacement + out[match.end() :]
    return out


def _ps_list(values: Sequence[str]) -> str:
    return ", ".join("'" + str(v).replace("'", "''") + "'" for v in values)


def _bash_quote(value: str) -> str:
    return "'" + str(value).replace("'", "'\\''") + "'"


def _bash_variable_in_line(line: str, token: str, var: str) -> str:
    """Replace ``token`` with ``"$var"`` for its bash quote context."""
    pattern = re.compile(re.escape(token), re.IGNORECASE)
    out = []
    quote = ""
    i = 0
    while i < len(line):
        match = pattern.match(line, i)
        if match:
            if quote == "'":
                out.append("'\"$" + var + "\"'")
            elif quote == '"':
                out.append("${" + var + "}")
            else:
                out.append('"$' + var + '"')
            i = match.end()
            continue
        char = line[i]
        if quote:
            if char == quote:
                quote = ""
        elif char in ("'", '"'):
            quote = char
        out.append(char)
        i += 1
    return "".join(out)


def _plural(noun: str, count: int) -> str:
    if count == 1:
        return noun
    return _PLURAL_NOUNS.get(noun, noun + "s")


def _role_in_command(command: str, roles: Iterable[str]) -> list[str]:
    lowered = command.lower()
    return [role for role in roles if ASSET_ROLE_TOKENS[role]["token"].lower() in lowered]


#: Inside a ``"..."`` string PowerShell expands ``$`` only when the next
#: character begins a variable name (``$word`` / ``$1`` / ``${x}`` / ``$( )``).
#: A ``$`` at the end of the value or before a non-name character (``rstest$``,
#: ``synchost$`` before the closing quote) is already literal and is left as-is,
#: so a common trailing-``$`` machine account renders unchanged.
_DOUBLE_QUOTE_EXPANDING_DOLLAR = re.compile(r"\$(?=[A-Za-z0-9_{(:])")

#: A bareword argument matching this is safe unquoted in a PowerShell / dsacls
#: command: no whitespace, no ``$`` (variable expansion), no metacharacter.
#: Anything else (a ``$``-leading gMSA-style name, a trailing ``$`` machine
#: account, a name with a space) must be single-quoted, or PowerShell expands
#: ``$28f000`` as a variable or splits the argument on the space.
_SAFE_BAREWORD = re.compile(r"[A-Za-z0-9._-]+")


def format_powershell_value(value: str, context: str) -> str:
    """Make an identity ``value`` safe to drop into a PowerShell string context.

    Args:
        value: A sAMAccountName, template CN, trustee, share or host name.
        context: ``"single"``, ``"double"`` or ``"bare"``
            (see :func:`powershell_quote_context`).

    Returns:
        The value escaped (inside a literal) or quoted (bare) as needed.
    """
    if context == "single":
        # A '...' literal never expands $ and keeps spaces; only an embedded
        # single quote needs escaping (PowerShell doubles it).
        return value.replace("'", "''")
    if context == "double":
        # A "..." string expands $ and treats " and backtick specially: escape
        # the backtick, the quote, and only an EXPANDING $.
        escaped = value.replace("`", "``").replace('"', '`"')
        return _DOUBLE_QUOTE_EXPANDING_DOLLAR.sub("`$", escaped)
    if _SAFE_BAREWORD.fullmatch(value):
        return value
    return "'" + value.replace("'", "''") + "'"


def substitute_powershell_value(text: str, token: str, value: str) -> str:
    """Substitute an identity ``token`` in ``text``, quoting ``value`` per occurrence.

    Each occurrence is made safe for the exact PowerShell quoting context it
    sits in: a bareword slot gets single-quoting when needed, a single-quoted
    LDAP filter gets its embedded quotes escaped, a double-quoted slot gets its
    expanding ``$`` backtick-escaped. Matching is case-insensitive.
    """
    pattern = re.compile(re.escape(token), re.IGNORECASE)
    out: list[str] = []
    last = 0
    for match in pattern.finditer(text):
        out.append(text[last : match.start()])
        out.append(format_powershell_value(value, powershell_quote_context(text, match.start())))
        last = match.end()
    out.append(text[last:])
    return "".join(out)


def _fill_single(command: str, token: str, value: str, platform: str = "windows") -> str:
    """Fill ``token`` with one object's name, quoted for the command's shell."""
    if platform == "windows":
        return substitute_powershell_value(command, token, value)
    return re.sub(re.escape(token), lambda _m: value, command, flags=re.IGNORECASE)


def expand_for_assets(
    item: Mapping[str, Any],
    assets_by_role: Mapping[str, Sequence[str]] | None,
    *,
    selectors: Mapping[str, str] | None = None,
    list_limit: int = MULTI_ASSET_LIST_LIMIT,
) -> dict[str, Any]:
    """Rewrite a per-object command so it covers every affected object of its role.

    The command is authored for ONE object through a canonical token
    (``<ACCOUNT>``, ``<TEMPLATE>`` ...). When the finding has several objects of
    that role:

    * up to ``list_limit``: one command over an explicit list
      (``foreach ($account in 'a', 'b') { ... }``), run once;
    * more, with a ``selectors[role]`` query declared for the finding: the same
      loop over the query, run once;
    * more, without a selector: the first object filled in as an example, and a
      note pointing at the full list under Affected Assets.

    A role with exactly ONE object is filled with it directly (the affected-asset
    list is authoritative; the single-value personalizer only fills what this
    leaves). A role with none is left to the personalizer. A command naming tokens
    of two roles that BOTH have several objects is left for the example form,
    since pairing them would be a guess. SQL statements take the example form.

    Args:
        item: A structured runbook command.
        assets_by_role: Affected objects by role (``account``, ``template``,
            ``trustee``, ``computer``, ``spn_host``, ``share``, ``ca``),
            command-safe names, in the order the report lists them.
        selectors: Optional PowerShell expressions, by role, that return the
            affected objects' names (``(Get-ADUser -LDAPFilter '...').SamAccountName``).
        list_limit: The explicit-list ceiling.

    Returns:
        A new item. ``applies_to`` and ``scope_note`` are set when it was expanded.
    """
    result = dict(item)
    command = str(item.get("command") or "")
    if not command.strip() or not assets_by_role:
        return result
    platform = str(item.get("platform") or "windows")

    def objects(role_name: str) -> list[str]:
        return [str(v).strip() for v in (assets_by_role.get(role_name) or ()) if str(v).strip()]

    for single in _role_in_command(command, ASSET_ROLE_TOKENS):
        if len(objects(single)) == 1:
            command = _fill_single(command, ASSET_ROLE_TOKENS[single]["token"], objects(single)[0], platform)
    result["command"] = command
    present = _role_in_command(command, ASSET_ROLE_TOKENS)
    multi = [role for role in present if len(objects(role)) > 1]
    if not multi:
        return result
    role = multi[0]
    spec = ASSET_ROLE_TOKENS[role]
    values = [str(v).strip() for v in assets_by_role.get(role) or () if str(v).strip()]
    count = len(values)
    noun = _plural(spec["noun"], count)
    selector = str((selectors or {}).get(role) or "").strip()

    def example() -> dict[str, Any]:
        result["command"] = _fill_single(command, spec["token"], values[0], platform)
        result["applies_to"] = {"role": role, "count": count, "mode": "example"}
        result["scope_note"] = (
            f"Shown for {values[0]}. Run it for each of the {count} affected {noun}, "
            f"with that {spec['noun']}'s own values. The full list is under Affected Assets."
        )
        return result

    # Any other fill-in left for the reader (a new gMSA name, a certificate's key
    # identifier) is a value each object needs its own copy of: one loop would
    # apply a single value to all of them. Those commands take the example form.
    role_tokens = {entry["token"].strip("<>").upper() for entry in ASSET_ROLE_TOKENS.values()}
    per_object_inputs = [
        name
        for name in unfilled_tokens(command)
        if name.upper() not in role_tokens and name.upper() not in _ENVIRONMENT_TOKENS
    ]
    # A second role in the same command is safe to share across the loop only
    # when the finding names exactly one object for it (one trustee removed from
    # several templates). None means the reader fills it in per object.
    unpaired_roles = [
        other
        for other in present
        if other != role
        and len([v for v in (assets_by_role.get(other) or ()) if str(v).strip()]) != 1
    ]
    if (
        len(multi) > 1
        or unpaired_roles
        or platform == "sql"
        or per_object_inputs
        or item.get("loop") is False
    ):
        return example()
    if count > list_limit and not (selector and platform == "windows"):
        return example()

    lines = command.splitlines()
    if platform == "linux":
        body = [_bash_variable_in_line(ln, spec["token"], spec["var"]) for ln in lines]
        source = " ".join(_bash_quote(v) for v in values)
        if len(body) == 1:
            result["command"] = f"for {spec['var']} in {source}; do {body[0]}; done"
        else:
            result["command"] = "\n".join([f"for {spec['var']} in {source}; do", *("  " + b for b in body), "done"])
        mode = "list"
    else:
        body = [_ps_variable_in_line(ln, spec["token"], spec["var"]) for ln in lines]
        if count > list_limit:
            source, mode = selector, "selector"
        else:
            source, mode = _ps_list(values), "list"
        head = f"foreach (${spec['var']} in {source}) {{"
        if len(body) == 1:
            result["command"] = f"{head} {body[0]} }}"
        else:
            result["command"] = "\n".join([head, *("    " + b for b in body), "}"])
    result["applies_to"] = {"role": role, "count": count, "mode": mode}
    if mode == "selector":
        result["scope_note"] = (
            f"Run this once. Its query selects every affected {spec['noun']}, "
            f"{count} at the time of the assessment."
        )
    elif count == 2:
        result["scope_note"] = f"Run this once. It covers both affected {noun}."
    else:
        result["scope_note"] = f"Run this once. It covers all {count} affected {noun}."
    return result


def _short_host_name(name: str) -> str:
    """``braavos.essos.local`` -> ``braavos``; a short name or ``HOST$`` stays."""
    text = str(name or "").strip()
    if not text or "." not in text or text.replace(".", "").isdigit():
        return text
    return text.split(".", 1)[0]


def assets_by_role_from_roles(roles: Mapping[str, Any] | None) -> dict[str, list[str]]:
    """Map the affected-asset role SSOT onto the runbook token roles.

    ``roles`` is ``FindingAssetRoles.to_dict()``
    (:mod:`adscan_core.reporting.affected_asset_roles`): the finding's objects
    split into who can exploit it, what it exposes and where the weakness lives,
    as the identifiers a command names. This decides which list each canonical
    token iterates, so the runbook covers the same objects the AFFECTED block
    lists:

    * ``<ACCOUNT>``: the user accounts the finding is about (exposed, else the
      misconfigured ones);
    * ``<TRUSTEE>``: the principals holding the abused right;
    * ``<TEMPLATE>`` / ``<CA>``: the certificate templates and authorities;
    * ``<COMPUTER>``: the affected computers, by name (``Get-ADComputer`` takes a
      name, not an FQDN);
    * ``<host>``: the affected computers by network name, for a remote check;
    * ``<SPN-HOST>``: the host part of each exposed service principal name;
    * ``<mapped_account>``: the principals an explicit certificate mapping
      points at (ESC14), computers as ``NAME$``.

    Roles the finding has nothing for are omitted, so their tokens stay with the
    single-value personalizer.
    """
    if not isinstance(roles, Mapping):
        return {}

    def names(key: str) -> list[str]:
        out: list[str] = []
        for value in roles.get(key) or ():
            text = str(value or "").strip()
            if text and text.casefold() not in {v.casefold() for v in out}:
                out.append(text)
        return out

    hosts = names("affected_hosts")
    mapped = names("exposed_accounts") + [
        _short_host_name(h).rstrip("$") + "$" for h in names("exposed_hosts")
    ]
    computers: list[str] = []
    for host in hosts:
        short = _short_host_name(host)
        if short and short.casefold() not in {c.casefold() for c in computers}:
            computers.append(short)
    spn_hosts: list[str] = []
    for spn in names("exposed_spns"):
        host = spn.split("/", 1)[-1].split(":", 1)[0].split("/", 1)[0].strip()
        if host and host.casefold() not in {h.casefold() for h in spn_hosts}:
            spn_hosts.append(host)
    candidate = {
        "spn": names("exposed_spns"),
        "spn_host": spn_hosts,
        "account": names("affected_accounts"),
        "trustee": names("trustees"),
        "template": names("templates"),
        "ca": names("certificate_authorities"),
        "computer": computers,
        "host": hosts,
        "mapped_account": mapped,
    }
    return {role: values for role, values in candidate.items() if values}


def expand_options_for_assets(
    options: Iterable[Mapping[str, Any]],
    assets_by_role: Mapping[str, Sequence[str]] | None,
    *,
    selectors: Mapping[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Apply :func:`expand_for_assets` to every command of every runbook option.

    Options are copied; ``commands`` and ``validation_commands`` are normalised
    to structured items first, so a legacy flat list expands too.
    """
    expanded: list[dict[str, Any]] = []
    for option in options or ():
        if not isinstance(option, Mapping):
            continue
        copy = dict(option)
        for field in ("commands", "validation_commands"):
            if field in option:
                copy[field] = [
                    expand_for_assets(cmd, assets_by_role, selectors=selectors)
                    for cmd in normalize_runbook_commands(option.get(field))
                ]
        expanded.append(copy)
    return expanded
