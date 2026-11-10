"""Keep engine terminal chrome out of any text field a web surface displays.

The engine prints tables and panels to the terminal (Rich boxes, pipe-framed
rows such as ``│ Steps Completed: 2/2 (100%) │``). The scan worker reads that
stream line by line, and a framed row that reached an event message was then
shown under "Completed" on the scan page as raw console text. The structured
value (``current_step`` / ``total_steps``) is what a surface should render; the
terminal row is never a message.

One definition, stdlib only, so the worker, the backend and the report read the
same answer. The web frontend mirrors it in ``lib/console-text-guard.ts``; both
are driven by the same case file, ``adscan_web/frontend/__tests__/fixtures/
console-chrome-cases.json``, so the two cannot drift.
"""

from __future__ import annotations

import re

#: Vertical frame characters a terminal table or panel puts at the line edges.
_FRAME_EDGE = "│┃║|╎╏┆┇┊┋"
#: Corner and junction characters that open or close a box.
_BOX_CORNERS = "╭╮╰╯┌┐└┘├┤┬┴┼╔╗╚╝╠╣╦╩╬┏┓┗┛┣┫┳┻╋╞╡╟╢"
#: Anything in the Unicode box-drawing and block-element ranges.
_BOX_RANGE = re.compile("[─-▟]")
#: A pure ASCII border such as ``+----+----+`` or ``|====|``.
_ASCII_BORDER = re.compile(r"^[+\-=|\s]*[-=]{3,}[+\-=|\s]*$")


def is_console_chrome_line(line: str) -> bool:
    """True when ``line`` is terminal table/panel framing rather than a message.

    A line is chrome when it is a border (box-drawing characters and spaces
    only, or an ASCII ``+---+`` rule), opens or closes a box with a corner, or is
    a row framed by a vertical bar at BOTH edges. A sentence that merely contains
    a bar, or a single box character in the middle of prose, is not.
    """
    text = str(line or "").strip()
    if not text:
        return False
    if _ASCII_BORDER.match(text):
        return True
    if text[0] in _BOX_CORNERS or text[-1] in _BOX_CORNERS:
        return True
    if text[0] in _FRAME_EDGE and text[-1] in _FRAME_EDGE and len(text) > 1:
        return True
    return all(ch.isspace() or _BOX_RANGE.match(ch) for ch in text)


def strip_console_chrome(text: object) -> str:
    """``text`` without its terminal-framing lines; empty when nothing remains."""
    if text is None:
        return ""
    kept = [
        line.rstrip()
        for line in str(text).splitlines()
        if not is_console_chrome_line(line)
    ]
    return "\n".join(kept).strip()


__all__ = ("is_console_chrome_line", "strip_console_chrome")
