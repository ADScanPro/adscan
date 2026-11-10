"""How long a compliance control card's text may be, and how it is cut.

The compliance annex of a Security Assessment Report renders one card per
mapped requirement, two to a row, and each card carries the subject of the
requirement under its title. The card is a fixed box in a two-column grid, so
the text has a budget, and a budget needs somewhere to be declared and some
rule for what happens at its edge.

Both halves of that used to live as literals inside the Jinja expression
(``{{ desc[:160] }}{% if desc|length > 160 %}…{% endif %}``), which produced
the defect this module exists to remove: the slice has no notion of a word, so
a DORA card printed ``protection measures for cryptogra…`` to a paying client,
with the bottom half of the page empty. A budget is a layout fact and a cut is
a typographic rule; neither is something a template should be inventing per
call site.

Two decisions, both deliberate.

**The budget is a constant here, not a number in the template.** The data that
feeds these cards lives in six framework catalogs, and whether a catalog entry
fits is a question only answerable against the budget. With the number in the
template nothing could ask it, so a catalog could grow past the box and the
only witness was the rendered PDF. Declared here, the catalogs are testable
against it.

**The cut falls on a word boundary and the budget is the box, not a guess.**
280 characters is about five lines at the card's 7.5pt over an 85mm column,
which is what the box holds without crowding the finding pills beneath it. The
old 160 was about three, and the page it left was half empty. A text inside the
budget is returned untouched, so the ellipsis is a real signal that something
was cut rather than decoration on every card.

Pure logic: no IO, no console, no Jinja. It lives in ``adscan_core`` so the web
CTEM, which renders the same control cards, can clamp identically if it ever
needs to.
"""

from __future__ import annotations

#: How many characters a control card's subject line may carry.
#:
#: About five lines at the card's own 7.5pt over the two-column grid's 85mm
#: column. Raised from 160 (three lines) after a render review found DORA
#: truncating 9 of 9 descriptions while the page below them stood empty.
CONTROL_CARD_TEXT_BUDGET = 280

#: The marker that says text was cut. A single glyph, so the budget it is
#: appended to stays the budget a reader sees.
CLAMP_ELLIPSIS = "…"


def clamp_card_text(text: object, budget: int = CONTROL_CARD_TEXT_BUDGET) -> str:
    """Return ``text`` fitted to ``budget``, cut only between words.

    The ONE rule every control card cuts by. A text within the budget comes
    back unchanged and carries no ellipsis, so the marker means something.
    Beyond it, the text is cut at the last whitespace inside the budget and the
    ellipsis is appended, which is why no card can print half a word.

    Args:
        text: The text to fit. A non-string or empty value yields ``""``.
        budget: Character budget, defaulting to the card's own.

    Returns:
        The fitted text. Never longer than ``budget`` plus the one-character
        ellipsis, and never ending mid-word.
    """
    raw = str(text or "").strip()
    if not raw or budget <= 0:
        return raw if budget > 0 else ""
    if len(raw) <= budget:
        return raw
    head = raw[:budget]
    cut = head.rfind(" ")
    # A budget shorter than the first word has no boundary to cut on. Taking
    # the whole first word is the lesser evil: a cut inside it is the exact
    # defect this function exists to prevent, and no catalog entry opens with a
    # 280-character word.
    if cut <= 0:
        space = raw.find(" ")
        head = raw if space < 0 else raw[:space]
    else:
        head = head[:cut]
    return f"{head.rstrip().rstrip(',;:')}{CLAMP_ELLIPSIS}"


__all__ = [
    "CLAMP_ELLIPSIS",
    "CONTROL_CARD_TEXT_BUDGET",
    "clamp_card_text",
]
