"""The sentence that joins a leaked attribute value to the account it opens.

A client holding this finding has two true facts in front of them and no way to
join them: a readable directory attribute holds secret-shaped text that did not
authenticate as the account whose attribute held it, and a validated credential
exists for some other account. Reported separately, the first reads as "this
may be stale" and the second as a spray result with no provenance. Together
they are one working credential and one attribute to go and clear.

The sentence has a hard job, and both halves are load-bearing:

* it NAMES the attribute and the object an administrator clears, which is the
  entire remediation, and
* it names the account the value actually authenticates as, which is the
  exposure, while never implying that the LEAKING account is the exposed one.
  That account's password was refused, so asking the client to rotate it as
  though it had fallen would be a false statement about their directory.

It lives in ``adscan_core`` so the paid deliverable, the web CTEM and anything
that later renders the same finding read one wording rather than three. Pure
stdlib, no catalog, no engine: it takes display labels the caller has already
humanized (the directory's own names, per the original-language rule) and
returns text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

#: How many leaking objects the sentence names before it states a count instead.
#: A client reading more than a handful of clauses stops reading them, and the
#: per-asset rows carry the complete set regardless.
_MAX_NAMED_LEAKS = 4


@dataclass(frozen=True)
class CrossAttributedLeak:
    """One leaking object and the accounts its value authenticated as.

    Attributes:
        leaking_display: The object whose attribute held the value, as the
            client's directory names it. May be empty when the run recorded no
            object, and the sentence then degrades rather than guessing one.
        attribute: The attribute the value sits in (``description``, ``info``).
            Empty renders as "a readable attribute", which is honest; naming a
            likely attribute would send an administrator to the wrong field.
        compromised_displays: The accounts the value authenticated as, in
            record order.
    """

    leaking_display: str = ""
    attribute: str = ""
    compromised_displays: tuple[str, ...] = ()


def _join(names: Sequence[str]) -> str:
    """Return ``a``, ``a and b``, or ``a, b and c`` for a list of names."""
    clean = [str(name).strip() for name in names if str(name or "").strip()]
    if not clean:
        return ""
    if len(clean) == 1:
        return clean[0]
    if len(clean) == 2:
        return f"{clean[0]} and {clean[1]}"
    return ", ".join(clean[:-1]) + f" and {clean[-1]}"


def _leak_sentences(leak: CrossAttributedLeak) -> str:
    """Return the sentences describing one leaking object and what it opened.

    Three clauses, in the order the reader needs them: where the value sits,
    that it does NOT open the account holding it, and which account it does
    open, then the action. Deliberately twin sentences rather than one
    "it does not open A, it opens B" clause: the two facts carry equal weight
    and the reader has to take both.
    """
    opened = _join(leak.compromised_displays)
    if not opened:
        return ""
    field = str(leak.attribute or "").strip()
    holder = str(leak.leaking_display or "").strip()

    if holder and field:
        where = f"The value stored in the {field} attribute of {holder}"
        refused = f" did not authenticate as {holder}."
        action = (
            f" Clear the {field} attribute on {holder}, and rotate {opened}, "
            "treating the value as known."
        )
    elif holder:
        where = f"The value stored in a readable attribute of {holder}"
        refused = f" did not authenticate as {holder}."
        action = (
            f" Clear the attribute holding it on {holder}, and rotate {opened}, "
            "treating the value as known."
        )
    else:
        where = "A value recovered from a readable directory attribute"
        refused = " did not authenticate as the account that held it."
        action = f" Rotate {opened}, treating the value as known."

    return f"{where}{refused} It authenticates as {opened}.{action}"


def cross_attributed_secret_statement(leaks: Sequence[CrossAttributedLeak]) -> str:
    """Return the client-facing statement for a cross-attributed leak set.

    Args:
        leaks: The leaking objects and the accounts their value authenticated
            as. A leak carrying no compromised account is skipped: the claim
            this text makes rests on an authentication, so there is nothing to
            say about a leak that produced none.

    Returns:
        The statement, or ``""`` when no leak carries a proven account. An
        empty return means the caller has nothing to add, never a sentence with
        a hole in it.
    """
    usable = [
        leak
        for leak in leaks
        if any(str(name or "").strip() for name in leak.compromised_displays)
    ]
    if not usable:
        return ""
    parts = [
        sentence
        for leak in usable[:_MAX_NAMED_LEAKS]
        if (sentence := _leak_sentences(leak))
    ]
    if not parts:
        return ""
    remaining = len(usable) - _MAX_NAMED_LEAKS
    if remaining > 0:
        parts.append(
            f"A further {remaining} attribute values in this finding "
            "authenticate as an account other than the one holding them; "
            "the affected objects are listed above."
            if remaining > 1
            else "One further attribute value in this finding authenticates "
            "as an account other than the one holding it; the affected "
            "objects are listed above."
        )
    return " ".join(parts)


__all__ = [
    "CrossAttributedLeak",
    "cross_attributed_secret_statement",
]
