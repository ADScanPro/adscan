"""Pure month/season + year password candidate generator for spraying.

No I/O, no network. Callable in L1 unit tests with any month/year. The output
is deterministic and lockout-aware by construction: the caller decides how many
candidates per user to spray (the spraying flow keeps its one-combo-per-user
safety boundary), and this module only produces the ordered candidate strings.

Why month/season patterns matter: forced-rotation policies push users toward
predictable "current period + year" passwords (``March2026!``, ``Spring2026``,
``Verano2026``). Spanish-speaking clients frequently use Spanish month/season
words, so English AND Spanish forms are generated. The report already promises
seasonal spray patterns to the client; this module is what actually produces
them.
"""

from __future__ import annotations

from dataclasses import dataclass


# English month names indexed 1..12 (index 0 unused).
_MONTHS_EN: tuple[str, ...] = (
    "",
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
)

# Spanish month names indexed 1..12 (index 0 unused). Rendered capitalized here;
# Spanish orthography lowercases months in prose, but as a password token users
# capitalize them exactly like the English form, so the capitalized form is the
# primary token and a lowercase variant is emitted too.
_MONTHS_ES: tuple[str, ...] = (
    "",
    "Enero",
    "Febrero",
    "Marzo",
    "Abril",
    "Mayo",
    "Junio",
    "Julio",
    "Agosto",
    "Septiembre",
    "Octubre",
    "Noviembre",
    "Diciembre",
)

# Meteorological seasons, Northern hemisphere (Spain + most client geographies).
# Dec/Jan/Feb -> winter, Mar/Apr/May -> spring, Jun/Jul/Aug -> summer,
# Sep/Oct/Nov -> autumn. English "autumn" and the American "fall" are BOTH common
# in passwords, so both are generated.
_SEASON_EN_BY_MONTH: dict[int, tuple[str, ...]] = {
    12: ("Winter",),
    1: ("Winter",),
    2: ("Winter",),
    3: ("Spring",),
    4: ("Spring",),
    5: ("Spring",),
    6: ("Summer",),
    7: ("Summer",),
    8: ("Summer",),
    9: ("Autumn", "Fall"),
    10: ("Autumn", "Fall"),
    11: ("Autumn", "Fall"),
}

_SEASON_ES_BY_MONTH: dict[int, tuple[str, ...]] = {
    12: ("Invierno",),
    1: ("Invierno",),
    2: ("Invierno",),
    3: ("Primavera",),
    4: ("Primavera",),
    5: ("Primavera",),
    6: ("Verano",),
    7: ("Verano",),
    8: ("Verano",),
    9: ("Otono", "Otoño"),
    10: ("Otono", "Otoño"),
    11: ("Otono", "Otoño"),
}

# Trailing symbols appended to satisfy complexity policies, in priority order.
_SUFFIX_SYMBOLS: tuple[str, ...] = ("!", "@", "#")


@dataclass(frozen=True, slots=True)
class MonthSeasonCandidate:
    """One generated month/season + year password candidate.

    Attributes:
        password: The candidate string (e.g. ``March2026!``, ``Verano2026``).
        rule: Stable identifier for the transformation (e.g.
            ``month_en``, ``season_es_bang``). Used in manifests/telemetry;
            never shown to the operator.
        language: ``"en"`` or ``"es"`` — the language of the base word.
        kind: ``"month"`` or ``"season"``.
        priority: Stable rank (lower = tried first).
    """

    password: str
    rule: str
    language: str
    kind: str
    priority: int


def season_names_for_month(month: int, *, language: str) -> tuple[str, ...]:
    """Return the season word(s) for a month in the requested language.

    Args:
        month: Calendar month, 1..12.
        language: ``"en"`` or ``"es"``.

    Returns:
        Tuple of season words (usually one; autumn yields two), empty when the
        month is out of range.
    """
    table = _SEASON_EN_BY_MONTH if language == "en" else _SEASON_ES_BY_MONTH
    return table.get(int(month), ())


def month_name(month: int, *, language: str) -> str:
    """Return the month name for a month in the requested language.

    Args:
        month: Calendar month, 1..12.
        language: ``"en"`` or ``"es"``.

    Returns:
        Month name, or ``""`` when the month is out of range.
    """
    table = _MONTHS_EN if language == "en" else _MONTHS_ES
    if 1 <= int(month) <= 12:
        return table[int(month)]
    return ""


def generate_month_season_variations(
    *,
    month: int,
    year: int,
    languages: tuple[str, ...] = ("en", "es"),
    include_symbols: bool = True,
    kinds: tuple[str, ...] = ("month", "season"),
) -> list[MonthSeasonCandidate]:
    """Return deduplicated month/season + year candidates in stable order.

    The ordering front-loads the highest-hit-rate forms: the plain
    ``Word+Year`` token, then the complexity-satisfying ``Word+Year+symbol``
    forms, then the lowercase base-word variant. English is emitted before
    Spanish; month before season. The same ``(month, year)`` always produces the
    same ordered list.

    Args:
        month: Calendar month, 1..12. Out-of-range months yield ``[]``.
        year: Four-digit year to append.
        languages: Which languages to generate, in order (default English then
            Spanish).
        include_symbols: When ``True`` also emit the ``!``/``@``/``#`` suffixed
            forms.
        kinds: Which candidate kinds to emit, in order — any of ``"month"`` and
            ``"season"``. Restricting to a single kind is how the spray coverage
            layer generates the ``month_year`` and ``season_year`` passes
            separately from ONE generator (they are distinct CI coverage types,
            each with its own one-combo-per-user boundary).

    Returns:
        Deduplicated list of :class:`MonthSeasonCandidate` in stable order.
    """
    if not 1 <= int(month) <= 12:
        return []
    want_month = "month" in kinds
    want_season = "season" in kinds

    year_token = str(int(year))
    seen: set[str] = set()
    out: list[MonthSeasonCandidate] = []

    def _add(word: str, rule: str, language: str, kind: str) -> None:
        if not word:
            return
        password = f"{word}{year_token}"
        if password not in seen:
            seen.add(password)
            out.append(
                MonthSeasonCandidate(
                    password=password,
                    rule=rule,
                    language=language,
                    kind=kind,
                    priority=len(out),
                )
            )
        if include_symbols:
            for sym in _SUFFIX_SYMBOLS:
                sym_pw = f"{word}{year_token}{sym}"
                if sym_pw not in seen:
                    seen.add(sym_pw)
                    out.append(
                        MonthSeasonCandidate(
                            password=sym_pw,
                            rule=f"{rule}_sym_{sym}",
                            language=language,
                            kind=kind,
                            priority=len(out),
                        )
                    )

    if want_month:
        for language in languages:
            # Months first (more specific than the season), capitalized then lower.
            word = month_name(month, language=language)
            _add(word, f"month_{language}", language, "month")
            if word and word.lower() != word:
                _add(word.lower(), f"month_{language}_lower", language, "month")

    if want_season:
        for language in languages:
            for word in season_names_for_month(month, language=language):
                _add(word, f"season_{language}", language, "season")
                if word.lower() != word:
                    _add(word.lower(), f"season_{language}_lower", language, "season")

    return out


def month_season_passwords(
    *,
    month: int,
    year: int,
    languages: tuple[str, ...] = ("en", "es"),
    include_symbols: bool = True,
    kinds: tuple[str, ...] = ("month", "season"),
) -> list[str]:
    """Return just the candidate strings, in stable order (convenience wrapper).

    Args:
        month: Calendar month, 1..12.
        year: Four-digit year to append.
        languages: Languages to generate, in order.
        include_symbols: Whether to include the symbol-suffixed forms.
        kinds: Which candidate kinds to emit (``"month"`` / ``"season"``).

    Returns:
        Deduplicated candidate strings in stable order.
    """
    return [
        candidate.password
        for candidate in generate_month_season_variations(
            month=month,
            year=year,
            languages=languages,
            include_symbols=include_symbols,
            kinds=kinds,
        )
    ]
