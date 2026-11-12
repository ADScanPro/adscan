"""The client command block every ADscan report draws: one terminal component.

Rule (``CLAUDE.md`` § "Every command a client is shown renders through the
shared terminal block"): a command a client is shown, in any report document,
renders through :func:`render_terminal_block`. The web CTEM draws the same
block with ``TerminalBlock`` (``adscan_web/frontend/components/findings/
finding-verification.tsx``); this module is its print twin and carries the same
palette, prompts and line model.

The command shape is the one the web and the runbooks share
(``adscan_core.reporting.verification_model`` / ``runbook_model``):

``intro``
    Prose BEFORE the block, never inside it.
``command``
    The command alone, no comment.
``platform``
    One of :data:`~adscan_core.reporting.verification_model.TERMINAL_PLATFORMS`.
    It picks the console, and it follows what the command IS: PowerShell or
    sqlcmd on Windows, a Linux shell (the ``adscan`` launcher included), or the
    ADscan workbench prompt for a verb typed inside ``adscan start``.
``audience``
    Optional ``sysadmin`` / ``pentester`` badge in the title bar.
``scope_note``, ``caption``, ``outro``
    Lines printed below the block (how a multi-object command covers the
    objects, where or as whom it runs, what its result means).
``unfilled``
    Fill-in token names. When absent, the ``<token>`` markers in the command
    are detected.

Three properties a printed terminal needs and a web one gets for free:

* **The prompt is not text.** Chromium writes every glyph it draws, pseudo-
  elements and SVG ``<text>`` included, into the PDF text layer, so a client
  selecting a command would paste ``PS C:\\>`` with it. Each prompt is drawn
  from glyph OUTLINES (:mod:`._terminal_glyphs`, built from the shipped
  JetBrains Mono by ``scripts/build_terminal_prompt_glyphs.py``) as a CSS
  background image: vector, crisp, and absent from the text layer.
* **The face ships with ADscan.** The command text is set in JetBrains Mono,
  declared here through the same inert ``adscan-font:`` references the themes
  use, so the engine serves it and an HTML artifact inlines it.
* **Dark in both themes**, as on the web: a terminal is a literal metaphor.

Every Jinja environment that renders a report installs the two globals with
:func:`install_terminal`: ``terminal_block(step, ...)`` for a block and
``terminal_css()`` for the stylesheet, which a template emits once inside a
``<style>``. A template that calls the first without the second renders
unstyled blocks; ``tests/unit/test_client_commands_shared_block.py`` fails on
it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Iterable, Mapping
from urllib.parse import quote

from markupsafe import Markup, escape

from adscan_core.theme import ADSCAN_PRIMARY
from adscan_core.reporting.verification_model import (
    is_secret_token,
    normalize_terminal_platform,
    unfilled_tokens,
)
from adscan_internal.services.report_design._terminal_prompts import (
    PROMPTS,
    WIDE_CHARS,
)
from adscan_internal.services.report_design._terminal_glyphs import (
    ASCENT,
    CELL,
    DESCENT,
    GLYPHS,
)
from adscan_internal.services.report_design.fonts import FONT_REF_SCHEME

# ── Palette ──────────────────────────────────────────────────────────────────
#: The web's ``--term-*`` tokens (``adscan_web/frontend/app/globals.css``),
#: converted from HSL. Declared once there and once here; a drift between the
#: two is caught by ``tests/unit/services/test_report_terminal_block.py``.
WEB_TERMINAL_HSL: dict[str, tuple[int, int, int]] = {
    "linux-bg": (230, 16, 10),
    "linux-bar": (230, 14, 15),
    "linux-text": (220, 20, 90),
    "linux-prompt": (214, 88, 66),
    "linux-user": (212, 96, 76),
    "linux-cmd": (142, 58, 64),
    "linux-comment": (222, 10, 62),
    "ps-bg": (213, 98, 17),
    "ps-bar": (213, 86, 11),
    "ps-text": (210, 32, 93),
    "ps-prompt": (210, 24, 80),
    "ps-cmd": (52, 96, 70),
    "ps-comment": (130, 34, 66),
    "fill": (43, 96, 68),
}

#: The ADscan workbench prompt's own colours (``PentestShell._get_rich_prompt_object``
#: in ``adscan.py``): ``(`` white, ``ADscan`` bold brand info, ``:workspace`` bold
#: yellow, ``/domain`` bold green, the working directory bold magenta. Rich's
#: named colours resolve to the terminal's palette, so they take the hues the
#: Linux terminal above already uses; the brand info colour is literal.
REPL_HSL: dict[str, tuple[int, int, int]] = {
    "repl-white": WEB_TERMINAL_HSL["linux-text"],
    "repl-yellow": WEB_TERMINAL_HSL["ps-cmd"],
    "repl-green": WEB_TERMINAL_HSL["linux-cmd"],
    "repl-magenta": (300, 62, 74),
}
#: ``BRAND_COLORS['info']`` is the brand primary.
REPL_BRAND_HEX = ADSCAN_PRIMARY


def _hsl_to_hex(h: int, s: int, lightness: int) -> str:
    import colorsys

    r, g, b = colorsys.hls_to_rgb(h / 360.0, lightness / 100.0, s / 100.0)
    return "#{:02x}{:02x}{:02x}".format(round(r * 255), round(g * 255), round(b * 255))


@lru_cache(maxsize=1)
def palette() -> dict[str, str]:
    """Every terminal colour role, as hex."""
    colors = {k: _hsl_to_hex(*v) for k, v in {**WEB_TERMINAL_HSL, **REPL_HSL}.items()}
    colors["repl-brand"] = REPL_BRAND_HEX.lower()
    return colors


# ── Prompts ──────────────────────────────────────────────────────────────────
# The prompt text lives in ``_terminal_prompts`` so the glyph builder can read it
# without importing the glyphs it builds.


def _char_cells(char: str) -> int:
    return 2 if char in WIDE_CHARS else 1


def prompt_cells(name: str) -> int:
    """Width of a prompt in terminal cells."""
    return sum(_char_cells(c) for run in PROMPTS[name] for c in run[0])


def prompt_text(name: str) -> str:
    """The prompt as plain text (tests and alt text only; never drawn as text)."""
    return "".join(run[0] for run in PROMPTS[name])


def _prompt_svg(name: str) -> str:
    colors = palette()
    parts: list[str] = []
    x = 0
    for text, role, weight in PROMPTS[name]:
        paths: list[str] = []
        for char in text:
            cells = _char_cells(char)
            glyph = GLYPHS.get((char, weight)) or GLYPHS.get((char, 400))
            if glyph:
                offset = x + (cells * CELL - glyph[0]) / 2
                paths.append(f'<path transform="translate({offset:g} 0)" d="{glyph[1]}"/>')
            x += cells * CELL
        if paths:
            parts.append(f'<g fill="{colors[role]}">{"".join(paths)}</g>')
    height = ASCENT + DESCENT
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 {-ASCENT} {x} {height}">{"".join(parts)}</svg>'
    )


def _prompt_data_uri(name: str) -> str:
    return "data:image/svg+xml," + quote(_prompt_svg(name), safe="")


# ── Labels ───────────────────────────────────────────────────────────────────
_TITLE: dict[str, str] = {
    "windows": "Windows PowerShell",
    "sql": "SQL Server query",
    "linux": "user@linux: ~",
    "adscan": "ADscan workbench",
}
_PLATFORM_NAME: dict[str, str] = {
    "windows": "Windows",
    "sql": "SQL Server",
    "linux": "Linux",
    "adscan": "ADscan workbench",
}
_AUDIENCE_LABEL: dict[str, str] = {"sysadmin": "Sysadmin", "pentester": "Pentester"}
#: Windows and SQL share the PowerShell chrome; Linux and the workbench (which
#: runs in a Linux terminal) share the Linux one.
_TONE: dict[str, str] = {"windows": "ps", "sql": "ps", "linux": "linux", "adscan": "linux"}


# ── Line model (port of ``commandLines`` in the web's finding-verification.ts) ─
_CONTINUATION_RE = re.compile(r"(\||\\|`|\{|\(|,|&&|\|\|)\s*$")
_HEAD_RE = re.compile(r"^\S+")


@dataclass(frozen=True)
class Segment:
    """One run of a command line: ``text``, ``cmd``, ``placeholder`` or ``secret``."""

    kind: str
    text: str


@dataclass(frozen=True)
class Line:
    """One command line: ``command`` (gets a prompt), ``continuation``, ``comment`` or ``blank``."""

    kind: str
    segments: tuple[Segment, ...]


def _is_comment(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith("#") and not stripped.startswith("#!")


def highlight_tokens(command: str, unfilled: Iterable[Any] | None) -> list[str]:
    """The fill-in markers to highlight, as they appear in ``command``.

    ``unfilled`` names them (with or without brackets); when it is not given,
    the ``<token>`` markers in the command are used.
    """
    names = [str(t).strip() for t in (unfilled or []) if str(t).strip()]
    if not names:
        names = unfilled_tokens(command)
    out: list[str] = []
    for name in names:
        bracketed = name if name[:1] in "<{" else f"<{name}>"
        if bracketed in command:
            out.append(bracketed)
        elif name in command:
            out.append(name)
    return list(dict.fromkeys(out))


def _token_is_secret(token: str) -> bool:
    return is_secret_token(token.strip("<>{}"))


def _split_placeholders(line: str, tokens: list[str]) -> list[Segment]:
    if not tokens:
        return [Segment("text", line)]
    pattern = re.compile("|".join(re.escape(t) for t in sorted(tokens, key=len, reverse=True)))
    out: list[Segment] = []
    last = 0
    for match in pattern.finditer(line):
        if match.start() > last:
            out.append(Segment("text", line[last : match.start()]))
        kind = "secret" if _token_is_secret(match.group(0)) else "placeholder"
        out.append(Segment(kind, match.group(0)))
        last = match.end()
    if last < len(line):
        out.append(Segment("text", line[last:]))
    return out


def command_lines(command: str, unfilled: Iterable[Any] | None = None) -> list[Line]:
    """Split a command into lines, each typed for its prompt and colouring."""
    tokens = highlight_tokens(command, unfilled)
    previous = ""
    lines: list[Line] = []
    for raw in str(command).replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if not raw.strip():
            lines.append(Line("blank", (Segment("text", ""),)))
            continue
        if _is_comment(raw):
            lines.append(Line("comment", (Segment("text", raw),)))
            continue
        continuation = raw[:1].isspace() or bool(_CONTINUATION_RE.search(previous))
        previous = raw
        segments = _split_placeholders(raw, tokens)
        if not continuation and segments and segments[0].kind == "text":
            head = _HEAD_RE.match(segments[0].text)
            if head:
                rest = segments[0].text[head.end() :]
                segments[0:1] = [Segment("cmd", head.group(0))] + ([Segment("text", rest)] if rest else [])
        lines.append(Line("continuation" if continuation else "command", tuple(segments)))
    return lines


# ── Rendering ────────────────────────────────────────────────────────────────
def _segment_html(segment: Segment) -> str:
    text = escape(segment.text)
    if segment.kind == "cmd":
        return f'<span class="cterm-cmd">{text}</span>'
    if segment.kind in ("placeholder", "secret"):
        return f'<mark class="cterm-fill">{text}</mark>'
    return str(text)


def _prompt_html(platform: str) -> str:
    if platform == "linux":
        return (
            '<span class="cterm-ps1 cterm-ps1-linux-top" aria-hidden="true"></span>'
            '<span class="cterm-ps1 cterm-ps1-linux" aria-hidden="true"></span>'
        )
    return f'<span class="cterm-ps1 cterm-ps1-{platform}" aria-hidden="true"></span>'


def _body_html(platform: str, command: str, unfilled: Iterable[Any] | None) -> str:
    rendered: list[str] = []
    for line in command_lines(command, unfilled):
        if line.kind == "comment":
            rendered.append(f'<span class="cterm-comment">{escape(line.segments[0].text)}</span>')
            continue
        prompt = _prompt_html(platform) if line.kind == "command" else ""
        rendered.append(prompt + "".join(_segment_html(s) for s in line.segments))
    return "\n".join(rendered)


def _token_list(tokens: list[str]) -> str:
    out: list[str] = []
    for i, token in enumerate(tokens):
        if i:
            out.append(" and " if i == len(tokens) - 1 else ", ")
        out.append(f'<code class="cterm-token">{escape(token)}</code>')
    return "".join(out)


def _field(step: Any, name: str) -> Any:
    if isinstance(step, Mapping):
        return step.get(name)
    return getattr(step, name, None)


def _text(step: Any, name: str) -> str:
    value = _field(step, name)
    return str(value).strip() if value is not None else ""


def render_terminal_block(
    step: Any,
    *,
    platform: str | None = None,
    chrome: bool = True,
    fill_note: bool = True,
    title: str | None = None,
    purpose: str = "",
) -> Markup:
    """Render one client command as the shared terminal block.

    Args:
        step: A mapping (or object) in the shared command shape; see the module
            docstring. A plain string is read as a Windows command.
        platform: Overrides ``step["platform"]``, for a caller that knows the
            console from its own source of truth (the cheatsheet's
            ``RecipeKind``).
        chrome: Draw the title bar. A dense reference grid whose column header
            already names the console may omit it; the prompt always shows.
        fill_note: Print the "Fill in ... before running it" line under the
            block. A section that states the fill-in rule once passes False.
        title: Overrides the title bar text.
        purpose: Optional ``data-cterm-purpose`` value naming what the block
            is for (``verification``), so a client-safety check can tell an
            independent-verification command, which may name a standard tool,
            from a remediation command, which may not.

    Returns:
        Safe HTML. A step with prose but no command renders its intro alone.
    """
    if isinstance(step, str):
        step = {"command": step}
    command = str(_field(step, "command") or "").rstrip()
    intro = _text(step, "intro")
    if not command.strip():
        return Markup(f'<div class="cterm-item"><p class="cterm-intro">{escape(intro)}</p></div>') if intro else Markup("")

    kind = normalize_terminal_platform(platform or _field(step, "platform"))
    tone = _TONE[kind]
    unfilled = _field(step, "unfilled")
    audience = _AUDIENCE_LABEL.get(_text(step, "audience").lower(), "")

    parts: list[str] = ['<div class="cterm-item">']
    if intro:
        parts.append(f'<p class="cterm-intro">{escape(intro)}</p>')
    purpose_attr = f' data-cterm-purpose="{escape(purpose)}"' if purpose else ""
    parts.append(
        f'<div class="cterm cterm-{tone} cterm-is-{kind}"{purpose_attr} role="group" '
        f'aria-label="{escape(_PLATFORM_NAME[kind])} command">'
    )
    if chrome:
        badge = f'<span class="cterm-aud">{escape(audience)}</span>' if audience else ""
        parts.append(
            f'<div class="cterm-bar"><span class="cterm-title">{escape(title or _TITLE[kind])}</span>{badge}</div>'
        )
    parts.append(f'<pre class="cterm-body"><code>{_body_html(kind, command, unfilled)}</code></pre></div>')

    for note_field in ("scope_note", "caption"):
        note = _text(step, note_field)
        if note:
            parts.append(f'<p class="cterm-note">{escape(note)}</p>')
    if fill_note:
        tokens = highlight_tokens(command, unfilled)
        if tokens:
            secrets = [t for t in tokens if _token_is_secret(t)]
            line = f"Fill in {_token_list(tokens)} before running it."
            if secrets:
                line += (
                    " ADscan keeps secrets out of these commands on purpose, so type "
                    f"{_token_list(secrets)} yourself."
                )
            parts.append(f'<p class="cterm-note">{line}</p>')
    outro = _text(step, "outro")
    if outro:
        parts.append(f'<p class="cterm-note">{escape(outro)}</p>')
    parts.append("</div>")
    return Markup("".join(parts))


# ── Stylesheet ───────────────────────────────────────────────────────────────
#: Faces the block uses: the command text and the title bar. The prompt is
#: outlines and needs none.
TERMINAL_FACES: tuple[tuple[str, int], ...] = (("JetBrains Mono", 400), ("JetBrains Mono", 600))


def _font_faces_css() -> str:
    return "\n".join(
        "@font-face{"
        f"font-family:'{family}';font-style:normal;font-weight:{weight};font-display:block;"
        f'src:url("{FONT_REF_SCHEME}{quote(family)}/normal/{weight}") format("woff2")'
        "}"
        for family, weight in TERMINAL_FACES
    )


@lru_cache(maxsize=1)
def terminal_css_text() -> str:
    """The block's stylesheet: faces, palette, layout and the prompt images."""
    colors = palette()
    variables = ";".join(f"--cterm-{role}:{hex_}" for role, hex_ in colors.items())
    line_height = 1.5
    content = (ASCENT + DESCENT) / 1000.0
    half_leading = (line_height - content) / 2.0
    prompts = []
    for name in PROMPTS:
        width = prompt_cells(name) * CELL / 1000.0
        prompts.append(
            f".cterm-ps1-{name}{{width:{width:g}em;background-image:url(\"{_prompt_data_uri(name)}\")}}"
        )
    return f"""
/* ADscan client command block (report_design/terminal.py). Mirrors the web's
   TerminalBlock: the same palette, prompts and line model. */
{_font_faces_css()}
.cterm{{{variables};--cterm-size:var(--cterm-font-size,6.8pt);--cterm-lh:{line_height}}}
.cterm-item{{margin:1.5mm 0 0;break-inside:avoid;page-break-inside:avoid;min-width:0}}
.cterm-item:first-child{{margin-top:0}}
.cterm-intro{{font-size:7.6pt;line-height:1.45;margin:0 0 .6mm;color:var(--text-2,var(--ink-2,inherit));overflow-wrap:break-word}}
.cterm{{border:1px solid rgba(15,20,30,.28);border-radius:1.4mm;overflow:hidden;
  box-sizing:border-box;max-width:100%;-webkit-print-color-adjust:exact;print-color-adjust:exact}}
.cterm-ps{{background:var(--cterm-ps-bg);color:var(--cterm-ps-text)}}
.cterm-linux{{background:var(--cterm-linux-bg);color:var(--cterm-linux-text)}}
.cterm-bar{{display:flex;align-items:center;gap:2mm;padding:.45mm 2.2mm;
  font-family:'JetBrains Mono',monospace;font-size:5.2pt;line-height:1.4;letter-spacing:0}}
.cterm-ps .cterm-bar{{background:var(--cterm-ps-bar);color:var(--cterm-ps-prompt)}}
.cterm-linux .cterm-bar{{background:var(--cterm-linux-bar);color:var(--cterm-linux-comment)}}
.cterm-title{{flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.cterm-aud{{flex:none;border:1px solid rgba(255,255,255,.18);border-radius:.6mm;padding:0 1.2mm;font-size:5.2pt}}
.cterm-body{{margin:0;padding:1.1mm 2.4mm 1.2mm;background:none;border:0;border-radius:0;
  font-family:'JetBrains Mono',monospace;font-size:var(--cterm-size);line-height:var(--cterm-lh);
  font-weight:400;font-variant-ligatures:none;font-feature-settings:"liga" 0,"calt" 0;letter-spacing:0;
  color:inherit;white-space:pre-wrap;overflow-wrap:break-word;word-break:normal;hyphens:none;tab-size:4;text-align:left}}
.cterm-body code{{font:inherit;color:inherit;background:none;border:0;padding:0;white-space:inherit}}
.cterm-ps .cterm-cmd{{color:var(--cterm-ps-cmd)}}
.cterm-linux .cterm-cmd{{color:var(--cterm-linux-cmd)}}
.cterm-ps .cterm-comment{{color:var(--cterm-ps-comment)}}
.cterm-linux .cterm-comment{{color:var(--cterm-linux-comment)}}
.cterm-fill{{color:var(--cterm-fill);background:rgba(250,200,80,.16);border-radius:.4mm;
  box-shadow:inset 0 -1px 0 rgba(250,200,80,.7);padding:0}}
.cterm-ps1{{display:inline-block;height:{content:g}em;vertical-align:-{DESCENT / 1000.0:g}em;
  background-repeat:no-repeat;background-position:0 0;background-size:100% 100%}}
.cterm-ps1-linux-top{{display:block;height:calc(var(--cterm-lh) * 1em);
  background-position:0 {half_leading:.4f}em;background-size:auto {content:g}em}}
{chr(10).join(prompts)}
.cterm-note{{font-size:7pt;line-height:1.45;margin:.7mm 0 0;color:var(--text-3,var(--ink-3,inherit));overflow-wrap:break-word}}
.cterm-token{{font-family:'JetBrains Mono',monospace;font-size:.92em;padding:0 .8mm;border-radius:.4mm;
  background:rgba(250,190,60,.16)}}
"""


def terminal_css() -> Markup:
    """The stylesheet as safe markup, for ``{{ terminal_css() }}`` inside ``<style>``."""
    return Markup(terminal_css_text())


def install_terminal(env: Any) -> Any:
    """Register ``terminal_block`` and ``terminal_css`` on a Jinja environment."""
    env.globals["terminal_block"] = render_terminal_block
    env.globals["terminal_css"] = terminal_css
    return env


__all__ = [
    "Line",
    "PROMPTS",
    "Segment",
    "command_lines",
    "highlight_tokens",
    "install_terminal",
    "palette",
    "prompt_cells",
    "prompt_text",
    "render_terminal_block",
    "terminal_css",
    "terminal_css_text",
]
