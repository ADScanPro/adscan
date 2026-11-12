"""Prompt text for the client command block (see :mod:`.terminal`).

Kept apart from the glyph outlines so ``scripts/build_terminal_prompt_glyphs.py``
can read which characters to build without importing what it builds. Changing a
prompt here means rebuilding the glyphs: the build ``--check`` fails otherwise,
and so does ``tests/unit/services/test_report_terminal_block.py``.
"""

from __future__ import annotations

#: A prompt: runs of (text, colour role, weight). The workbench prompt is a
#: representative static one with fabricated values: ADscan prints the real
#: workspace, domain and working directory.
PROMPTS: dict[str, tuple[tuple[str, str, int], ...]] = {
    "windows": (("PS C:\\> ", "ps-prompt", 400),),
    "sql": (("1> ", "ps-prompt", 400),),
    "linux-top": (
        ("┌──(", "linux-prompt", 400),
        ("user㉿linux", "linux-user", 600),
        (")-[", "linux-prompt", 400),
        ("~", "linux-text", 600),
        ("]", "linux-prompt", 400),
    ),
    "linux": (("└─$ ", "linux-prompt", 400),),
    "adscan": (
        ("(", "repl-white", 400),
        ("ADscan", "repl-brand", 700),
        (":", "repl-white", 400),
        ("demo", "repl-yellow", 700),
        ("/", "repl-white", 400),
        ("corp.example", "repl-green", 700),
        (" ", "repl-white", 400),
        ("~", "repl-magenta", 700),
        (") > ", "repl-white", 400),
    ),
}

#: Characters a terminal draws two cells wide.
WIDE_CHARS = frozenset({"㉿"})


