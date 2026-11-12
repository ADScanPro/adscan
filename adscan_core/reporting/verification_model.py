"""The structured independent-verification block: verify, exploit, references.

Every finding and attack step tells the client two things it can do by hand:

* **verify** -- confirm the condition exists in its own directory, so a finding
  is never taken on trust (the false-positive objection, answered with a command);
* **exploit** -- where the condition is exploitable, the by-hand equivalent of
  what an attacker does with it, so the exposure is reproducible and the didactic
  card teaches the same command the report prints.

Both used to be free strings (``verify_windows`` / ``verify_linux`` and the
didactic ``manual`` command) in which explanation and command were interleaved as
``#`` comment lines. A client pasting that block into a shell gets the comments
with it, and a deliverable that prints a comment inside a command reads as an
internal note. So the block is now structured data, and this module is the one
place that knows its shape. The contract (consumed by the PDF report, the web
CTEM and the didactic card)::

    {
        "verify":  [Command, ...],
        "exploit": [Command, ...],
        "references": [{"title": str, "url": str}, ...],
    }

    Command = {
        "platform": "windows" | "linux",
        "audience": "sysadmin" | "pentester",
        "intro": str,        # prose shown BEFORE the block
        "command": str,      # the pure command, no comment of any kind
        "requires": str,     # what its account needs: "authenticated" |
                             # "source_principal" | "local_admin[:<host>]" |
                             # "domain_admin" (adscan_core.reporting.command_principal)
        "unfilled": [str],   # <token> names still standing after the fill
    }

``requires`` defaults by kind: a read-only ``verify`` command needs any
authenticated account, an ``exploit`` command runs as the principal holding the
abused right. A command whose real need differs (a remote registry read needs a
local administrator, a CA-admin read needs CA rights) declares it explicitly.
The account is then filled ONLY with one the workspace proves meets it
(:func:`render_verification` with ``principal_for``); otherwise its token stays
and the item's ``principal.needed`` says what is required.

Rules this module enforces, so no catalog author has to remember them:

1. A command carries no comment: no ``#`` line, no trailing ``# ...``, no
   ``//``, no ``REM``, no ``Reference:``. Explanation is ``intro`` prose and a URL
   is a ``references`` entry. :func:`command_comment_violations` is the detector
   the structural test runs over every catalog entry.
2. A secret is never filled. Passwords, hashes and keys stay ``<password>`` /
   ``<nt_hash>`` / ``<aes_key>`` in every deliverable; a deliverable must not carry
   a credential. :func:`is_secret_token` names them so a test can lock it.
3. A ``<...>`` left in a command is either a secret or a value the scan genuinely
   could not resolve, and it is listed in ``unfilled`` so a renderer can say so.

Dependency-light on purpose (stdlib only): the attack-step catalog (LITE-safe),
the finding catalog (PRO) and the web backend (appliance bundle, which ships
``adscan_core`` whole) all import it.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Iterable, Mapping

__all__ = [
    "AUDIENCES",
    "DEFAULT_REQUIREMENTS",
    "PRINCIPAL_TOKENS",
    "PLATFORMS",
    "TERMINAL_PLATFORMS",
    "VERIFICATION_KINDS",
    "command_comment_violations",
    "commands_text",
    "empty_verification",
    "is_secret_token",
    "join_wrapped_comments",
    "legacy_text_from_items",
    "legacy_text_to_items",
    "normalize_terminal_platform",
    "normalize_verification",
    "reference_from_url",
    "render_verification",
    "unfilled_tokens",
    "verification_is_empty",
]

#: The two lists a verification block carries.
VERIFICATION_KINDS: tuple[str, ...] = ("verify", "exploit")
#: Where a verification command is run (the catalog's ``verify`` / ``exploit``).
PLATFORMS: tuple[str, ...] = ("windows", "linux")
#: Every console a client-facing command can be shown in, which picks the
#: terminal style it renders with (``report_design.terminal`` in the reports,
#: ``TerminalBlock`` in the web). The style follows what the command IS, never
#: the document it appears in:
#:
#: * ``windows``: PowerShell or cmd on the client's Windows estate.
#: * ``sql``: a SQL Server query, shown in the same Windows chrome (sqlcmd).
#: * ``linux``: a shell command, the ``adscan <subcommand>`` launcher included.
#: * ``adscan``: a verb typed INSIDE the ADscan workbench that ``adscan start``
#:   opens (a ``PentestShell.do_<verb>``). Where a surface already knows which
#:   kind a command is (the cheatsheet's ``RecipeKind``), that is the source,
#:   never a guess from the text.
TERMINAL_PLATFORMS: tuple[str, ...] = ("windows", "sql", "linux", "adscan")


def normalize_terminal_platform(value: Any, *, default: str = "windows") -> str:
    """Return ``value`` as one of :data:`TERMINAL_PLATFORMS`, else ``default``.

    The default is Windows because every client command a deliverable carried
    before the platform field existed was a PowerShell command.
    """
    key = str(value or "").strip().lower()
    return key if key in TERMINAL_PLATFORMS else default


#: Who it is written for: a sysadmin checks with native tooling, a pentester
#: reproduces with the standard offensive tool for the technique.
AUDIENCES: tuple[str, ...] = ("sysadmin", "pentester")

#: A fill-in token: ``<password>``, ``<dc_ip>``, ``<target-object-name>``.
_TOKEN_RE = re.compile(r"<([A-Za-z][A-Za-z0-9_.\-]*)>")

#: Token-name parts that stand for a credential. Matched per part of the NAME
#: (split on ``_`` / ``-`` / ``.``) so a new spelling (``<svc_password>``,
#: ``<new_password>``, ``<nt_hash>``) is caught without a list edit.
_SECRET_NAME_PARTS: frozenset[str] = frozenset(
    {
        "pass",
        "passwd",
        "password",
        "pwd",
        "hash",
        "hashes",
        "nthash",
        "lmhash",
        "aes",
        "aes128",
        "aes256",
        "aeskey",
        "key",
        "secret",
        "cpassword",
        "ticket",
        "pfx",
    }
)


def is_secret_token(name: str) -> bool:
    """Return whether a fill-in token NAME stands for a credential.

    Args:
        name: The token name without angle brackets (``password``, ``nt_hash``).

    Returns:
        ``True`` for passwords, hashes, keys and ticket material, which a
        deliverable never fills.
    """
    lowered = str(name or "").strip().lower()
    if not lowered:
        return False
    if "password" in lowered or "passwd" in lowered:
        return True
    return any(part in _SECRET_NAME_PARTS for part in re.split(r"[_\-.]+", lowered))


#: Angle-bracket markers that are literal syntax of a value, never a fill-in: the
#: explicit certificate mapping format of ``altSecurityIdentities``
#: (``X509:<I>issuer<S>subject``, ``X509:<SKI>...``). Case-sensitive, as written.
_LITERAL_SYNTAX_TOKENS: frozenset[str] = frozenset({"I", "S", "SR", "SKI", "SHA1-PUKEY", "RFC822"})


def unfilled_tokens(command: str) -> list[str]:
    """Return the ``<token>`` names still standing in ``command``, in order, once each.

    Literal value syntax (:data:`_LITERAL_SYNTAX_TOKENS`) is not a fill-in and is
    never listed.
    """
    seen: list[str] = []
    for match in _TOKEN_RE.finditer(str(command or "")):
        name = match.group(1)
        if name in _LITERAL_SYNTAX_TOKENS:
            continue
        if name not in seen:
            seen.append(name)
    return seen


# ── Comment detection ─────────────────────────────────────────────────────────


def _inline_hash_comment_index(line: str) -> int:
    """Index of a ``#`` that starts a trailing comment on ``line``, or ``-1``.

    A ``#`` only starts a comment (in sh and in PowerShell) when it begins a
    word, so a ``#`` inside a quoted string or glued to a token is not one. Quote
    tracking is approximate but sufficient for hand-authored one-liners.
    """
    quote = ""
    previous = " "
    for index, char in enumerate(line):
        if quote:
            if char == quote:
                quote = ""
        elif char in ("'", '"'):
            quote = char
        elif char == "#" and previous.isspace():
            return index
        previous = char
    return -1


_REM_RE = re.compile(r"^rem(?:\s|$)", re.IGNORECASE)
_REFERENCE_RE = re.compile(r"\breferences?\s*:", re.IGNORECASE)


def command_comment_violations(command: str) -> list[str]:
    """Return a description of every comment inside ``command`` (empty when clean).

    A command in a client deliverable is meant to be pasted and run, so it
    carries no comment of any kind: explanation belongs in the ``intro`` prose
    before the block, and a URL belongs in ``references``.
    """
    violations: list[str] = []
    for number, raw in enumerate(str(command or "").splitlines(), start=1):
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith("#") or stripped.startswith("<#"):
            violations.append(f"line {number}: '#' comment line")
            continue
        if stripped.startswith("//"):
            violations.append(f"line {number}: '//' comment line")
            continue
        if stripped.startswith("-- "):
            violations.append(f"line {number}: '--' SQL comment line")
            continue
        if stripped.startswith("::") or _REM_RE.match(stripped):
            violations.append(f"line {number}: REM comment line")
            continue
        if _REFERENCE_RE.search(stripped):
            violations.append(f"line {number}: 'Reference' inside the command")
            continue
        if _inline_hash_comment_index(raw) >= 0:
            violations.append(f"line {number}: trailing '#' comment")
    return violations


# ── Shape ─────────────────────────────────────────────────────────────────────


def empty_verification() -> dict[str, list[Any]]:
    """Return an empty block in the contract shape."""
    return {"verify": [], "exploit": [], "references": []}


def verification_is_empty(block: Mapping[str, Any] | None) -> bool:
    """Return whether ``block`` carries no command at all."""
    if not isinstance(block, Mapping):
        return True
    return not (block.get("verify") or block.get("exploit"))


#: The requirement a command declares when it says nothing, by kind.
DEFAULT_REQUIREMENTS: dict[str, str] = {
    "verify": "authenticated",
    "exploit": "source_principal",
}

#: The tokens that name a command's OWN account (the one it authenticates as).
#: ``{auth_user}`` / ``{executing_principal}`` are the step catalog's
#: placeholders, ``<user>`` the finding catalog's fill-in.
PRINCIPAL_TOKENS: tuple[str, ...] = ("{executing_principal}", "{auth_user}", "<user>")


def _clean_item(raw: Any, kind: str = "verify") -> dict[str, Any] | None:
    from adscan_core.reporting.command_principal import (  # noqa: PLC0415
        normalize_requirement,
    )

    if not isinstance(raw, Mapping):
        return None
    command = str(raw.get("command") or "").strip("\n").rstrip()
    if not command.strip():
        return None
    platform = str(raw.get("platform") or "").strip().lower()
    audience = str(raw.get("audience") or "").strip().lower()
    if platform not in PLATFORMS:
        platform = "linux"
    if audience not in AUDIENCES:
        audience = "sysadmin" if platform == "windows" else "pentester"
    item: dict[str, Any] = {
        "platform": platform,
        "audience": audience,
        "intro": str(raw.get("intro") or "").strip(),
        "command": command,
        "requires": normalize_requirement(
            raw.get("requires"), default=DEFAULT_REQUIREMENTS.get(kind, "authenticated")
        ),
    }
    unfilled = raw.get("unfilled")
    if isinstance(unfilled, (list, tuple)):
        item["unfilled"] = [str(name) for name in unfilled if str(name).strip()]
    return item


def _clean_reference(raw: Any) -> dict[str, str] | None:
    if isinstance(raw, str):
        return reference_from_url(raw)
    if not isinstance(raw, Mapping):
        return None
    url = str(raw.get("url") or "").strip()
    if not url:
        return None
    title = str(raw.get("title") or "").strip() or reference_from_url(url)["title"]
    return {"title": title, "url": url}


def normalize_verification(raw: Any) -> dict[str, list[Any]]:
    """Return ``raw`` coerced to the contract shape, dropping malformed parts.

    Never raises. Commands without text are dropped, an unknown platform reads
    as ``linux`` and an unknown audience follows the platform, references are
    deduplicated by URL.
    """
    block = empty_verification()
    if not isinstance(raw, Mapping):
        return block
    for kind in VERIFICATION_KINDS:
        for item in raw.get(kind) or ():
            cleaned = _clean_item(item, kind)
            if cleaned is not None:
                block[kind].append(cleaned)
    seen_urls: set[str] = set()
    for ref in raw.get("references") or ():
        cleaned_ref = _clean_reference(ref)
        if cleaned_ref is None or cleaned_ref["url"] in seen_urls:
            continue
        seen_urls.add(cleaned_ref["url"])
        block["references"].append(cleaned_ref)
    return block


# ── References ────────────────────────────────────────────────────────────────

_RECIPES_HOST = "thehacker.recipes"


def reference_from_url(url: str) -> dict[str, str]:
    """Return a ``{"title", "url"}`` reference with a readable title for ``url``.

    The title names the page (the last path segment, title-cased) and its source
    so a reader can tell what they are about to open without following it.
    """
    clean = str(url or "").strip()
    path = re.sub(r"^https?://", "", clean).split("?", 1)[0].split("#", 1)[0]
    host, _, rest = path.partition("/")
    segments = [part for part in rest.split("/") if part]
    leaf = segments[-1] if segments else host
    leaf = re.sub(r"\.(?:html?|md)$", "", leaf)
    words = re.split(r"[-_]+", leaf)
    page = " ".join(word.upper() if len(word) <= 4 and word.isalpha() and word.upper() in {
        "ADCS", "ESC", "RBCD", "LAPS", "GMSA", "SPN", "DCOM", "NTDS", "SAM", "LSA", "GPP",
        "AD", "DNS", "SMB", "LDAP", "NTLM", "TGT", "TGS", "PKI",
    } else word.capitalize() for word in words if word)
    if _RECIPES_HOST in host:
        title = f"The Hacker Recipes: {page}" if page else "The Hacker Recipes"
    elif host.endswith("microsoft.com"):
        title = f"Microsoft Learn: {page}" if page else "Microsoft Learn"
    else:
        title = page or host
    return {"title": title, "url": clean}


# ── Legacy free-string conversion ─────────────────────────────────────────────

#: A comment that carries a command after a parenthetical lead-in:
#: ``#   (or, targeting one account)  impacket-GetUserSPNs ...``.
_ALTERNATIVE_RE = re.compile(r"^\(([^)]{2,120})\)\s{1,}(\S.*)$")
_REFERENCE_LINE_RE = re.compile(r"^references?\s*:\s*(\S+)\s*$", re.IGNORECASE)
_URL_RE = re.compile(r"https?://\S+")


def _prose(text: str) -> str:
    """Normalize a comment fragment into a sentence of client-facing prose."""
    out = re.sub(r"\s+", " ", str(text or "")).strip()
    out = out.replace(" — ", ", ").replace("—", ", ")
    out = out.replace(" -> ", " to ")
    out = out.rstrip(" :;,")
    if not out:
        return ""
    out = out[0].upper() + out[1:]
    if out[-1] not in ".!?)":
        out += "."
    return out


def join_wrapped_comments(parts: Iterable[str]) -> list[str]:
    """Merge comment fragments that are one sentence wrapped over several lines.

    A legacy block wraps one long comment over several ``#`` lines ("forge an
    inter-realm" / "ticket carrying ..."). Normalising each line as its own
    sentence printed "forge an inter-realm. Ticket carrying ..., then." in a
    client deliverable. A fragment that closes no sentence (no ``.``, ``!``,
    ``?`` or ``:`` at its end) followed by one starting in lower case is the same
    sentence continued, so the two are joined. Shared by every legacy converter
    (verification blocks here, runbook commands in ``runbook_model``).
    """
    chunks: list[str] = []
    for part in parts:
        text = str(part or "").strip()
        if not text:
            continue
        if chunks and chunks[-1][-1] not in ".!?:" and text[0].islower():
            chunks[-1] = f"{chunks[-1]} {text}"
        else:
            chunks.append(text)
    return chunks


def _join_intro(parts: list[str]) -> str:
    """Join comment fragments into prose, keeping a wrapped sentence whole."""
    return " ".join(p for p in (_prose(x) for x in join_wrapped_comments(parts)) if p)


def _looks_like_prose_lead(line: str) -> bool:
    """Whether a leading legacy line is the explanation, not a command.

    The legacy blocks open with a sentence ending in ``:``; no command line in
    the catalog ends that way.
    """
    stripped = line.strip()
    if not stripped.endswith(":") or len(stripped.split()) < 4:
        return False
    return not stripped.startswith(("-", "/", "'", '"', "(", "[", "$", "\\"))


def _split_trailing_comment(line: str) -> tuple[str, str]:
    """Return ``(command, trailing_comment)`` for one command line."""
    cut = _inline_hash_comment_index(line)
    if cut < 0:
        return line.rstrip(), ""
    return line[:cut].rstrip(), line[cut:].lstrip("#").strip()


def legacy_text_to_items(
    text: str, *, platform: str, audience: str
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Split a legacy free-string block into structured commands + references.

    The legacy blocks interleave explanation and command: an opening prose line
    ending in ``:``, then command lines, with ``#`` comment lines introducing
    each further command and a ``# Reference: <url>`` line at the end. This
    converts that shape deterministically: each comment becomes the ``intro`` of
    the command that follows it, a parenthetical-led comment that embeds its
    own command (``# (or, X) tool ...``) becomes its own command, a trailing
    ``# ...`` on a command line moves into the intro, and a reference line
    becomes a ``references`` entry. No comment survives into a command.

    Args:
        text: The legacy block (a template: ``{placeholder}`` tokens intact).
        platform: ``windows`` or ``linux``.
        audience: ``sysadmin`` or ``pentester``.

    Returns:
        ``(commands, references)``; both empty for an empty block.
    """
    items: list[dict[str, Any]] = []
    references: list[dict[str, str]] = []
    intro_parts: list[str] = []
    command_lines: list[str] = []

    def flush() -> None:
        if command_lines:
            items.append(
                {
                    "platform": platform,
                    "audience": audience,
                    "intro": _join_intro(intro_parts),
                    "command": "\n".join(command_lines),
                }
            )
            intro_parts.clear()
            command_lines.clear()

    for index, raw in enumerate(str(text or "").splitlines()):
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith("#") or stripped.startswith("-- "):
            comment = stripped.lstrip("#").strip()
            if comment.startswith("-- "):
                comment = comment[3:].strip()
            ref_match = _REFERENCE_LINE_RE.match(comment)
            if ref_match:
                references.append(reference_from_url(ref_match.group(1)))
                continue
            if _REFERENCE_RE.search(comment):
                for url in _URL_RE.findall(comment):
                    references.append(reference_from_url(url.rstrip(".,)")))
                continue
            flush()
            alternative = _ALTERNATIVE_RE.match(comment)
            if alternative:
                intro_parts.append(alternative.group(1))
                embedded, trailing = _split_trailing_comment(alternative.group(2))
                if trailing:
                    intro_parts.append(trailing)
                command_lines.append(embedded.strip())
                flush()
                continue
            intro_parts.append(comment)
            continue
        if not command_lines and index == 0 and _looks_like_prose_lead(stripped):
            intro_parts.append(stripped)
            continue
        line, trailing = _split_trailing_comment(raw)
        if trailing:
            intro_parts.append(trailing)
        if line.strip():
            command_lines.append(line)
    flush()
    if intro_parts and items:
        # A comment with no command after it (a closing note) belongs to the last
        # command's explanation rather than vanishing.
        tail = _join_intro(intro_parts)
        items[-1]["intro"] = (items[-1]["intro"] + " " + tail).strip()
    return items, references


def legacy_text_from_items(items: Iterable[Mapping[str, Any]], platform: str) -> str:
    """Render the commands for one platform back into the legacy single string.

    Kept so a surface still reading ``verify_windows`` / ``verify_linux`` shows
    the same content during the transition: each command is preceded by its
    intro on its own line, exactly the shape the legacy block opened with, and
    no ``#`` comment is reintroduced.
    """
    blocks: list[str] = []
    for item in items:
        if str(item.get("platform") or "") != platform:
            continue
        intro = str(item.get("intro") or "").strip()
        command = str(item.get("command") or "").strip("\n")
        blocks.append(f"{intro}\n{command}" if intro else command)
    return "\n\n".join(blocks)


def commands_text(items: Iterable[Mapping[str, Any]]) -> str:
    """Join the commands of ``items`` into one runnable block, intros omitted."""
    return "\n".join(
        str(item.get("command") or "").strip("\n")
        for item in items
        if str(item.get("command") or "").strip()
    )


# ── Rendering ─────────────────────────────────────────────────────────────────


def render_verification(
    template: Mapping[str, Any] | None,
    substitute_command: Callable[[str], str],
    *,
    substitute_intro: Callable[[str], str] | None = None,
    principal_for: Callable[[str], Any] | None = None,
) -> dict[str, list[Any]]:
    """Fill a verification template and stamp each command's ``unfilled`` list.

    Args:
        template: A block in the contract shape whose strings carry the
            caller's placeholder syntax.
        substitute_command: Fills one command string with the environment's
            values. It must never fill a secret token; the result is checked.
        substitute_intro: Fills one intro string (prose). Defaults to
            ``substitute_command``.
        principal_for: Resolves the account a command runs as from its
            ``requires`` (a :class:`~adscan_core.reporting.command_principal
            .CommandPrincipal`). When given, every :data:`PRINCIPAL_TOKENS`
            occurrence is replaced by the proven account, or by the
            requirement's fill-in token when nothing is proven, BEFORE
            ``substitute_command`` runs; the item carries ``principal``. Omitted,
            the command's own placeholders are left to ``substitute_command``.

    Returns:
        The rendered block in the contract shape.
    """
    block = normalize_verification(template)
    intro_fill = substitute_intro or substitute_command
    rendered = empty_verification()
    for kind in VERIFICATION_KINDS:
        for item in block[kind]:
            source = item["command"]
            # Only a command that names its own account gets one resolved; a
            # command run "on the host" as whoever is logged on has nothing to fill.
            names_account = any(token in source for token in PRINCIPAL_TOKENS)
            principal = (
                principal_for(item["requires"]) if principal_for and names_account else None
            )
            if principal is not None:
                for token in PRINCIPAL_TOKENS:
                    source = source.replace(token, principal.text)
            command = substitute_command(source)
            entry: dict[str, Any] = {
                "platform": item["platform"],
                "audience": item["audience"],
                "intro": intro_fill(item["intro"]) if item["intro"] else "",
                "command": command,
                "requires": item["requires"],
                "unfilled": unfilled_tokens(command),
            }
            if principal is not None:
                entry["principal"] = principal.to_dict()
            rendered[kind].append(entry)
    rendered["references"] = [dict(ref) for ref in block["references"]]
    return rendered
