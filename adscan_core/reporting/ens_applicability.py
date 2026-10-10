"""ENS Anexo II applicability: which measures a declared system scope makes exigible.

Why this module exists
----------------------
A compliance scorecard that reports a measure as a non-conformity when the
normative text does not require it for the client's system is a false finding in
a file that goes to certification. Before this module the product carried a flat
mapping with a decorative ``level`` label that no consumer filtered on, so every
system rendered identically regardless of its declared categorisation, and four
of the eleven mapped measures carried a label that was simply wrong.

The exigible set is a FUNCTION of a four-part declared input, resolved from
versioned data:

1. **Normative version.** The table below is Real Decreto 311/2022 (Anexo II,
   apartado 2.4). The measure set differs from the repealed RD 3/2010 (73
   measures against 75) and one identifier changed meaning outright
   (``mp.info.6`` was "Limpieza de documentos" and is now "Copias de
   seguridad"), so a declaration naming another version is refused rather than
   mapped against this one.
2. **Compliance profile.** "General" is one profile, not the base case: the
   CCN registry counts a comparable number of certificates issued against a
   specific compliance profile (art. 30) as against the ALTA category. A
   profile is a different applicability table over the same measures, AND a
   **precondition on the declared scope**: the CCN-STIC guide that publishes
   one states which systems it may be applied to, so a profile can be fully
   transcribed and still not reach the system in front of it. See
   :class:`ComplianceProfile`. A profile with no table, or one whose published
   table predates this normative version, resolves to an honest non-verdict and
   NEVER falls back to the general set.
3. **The five dimension levels** (C, I, T, A, D), each Bajo / Medio / Alto or
   not affected. This is the only input taken: Anexo I apartado 4.1 defines the
   system category as the maximum of its dimensions' levels, so the category is
   DERIVED here rather than accepted alongside them. Accepting both would admit
   a contradiction the resolver would have to arbitrate, and the five levels are
   exactly the breakdown the ITS de Auditoría (apartado VI.7) obliges an audit
   report to declare.
4. **The category**, derived per the above: the selector for 45 of the 73
   measures. The other 28 are selected by the level of one or more dimensions,
   which is why a three-valued category field alone could never resolve them.
   Seven of the eleven measures the product maps today are in that second group.

Output states
-------------
:class:`ApplicabilityState` carries the four normative outcomes
(:attr:`REQUIRED`, :attr:`NOT_APPLICABLE_BY_TABLE`,
:attr:`NOT_APPLICABLE_BY_DIMENSION`, :attr:`COMPENSATORY_MEASURE`) plus three
honest non-verdicts (:attr:`EXIGIBILITY_UNDECLARED`,
:attr:`PROFILE_OUT_OF_SCOPE`, :attr:`NOT_RESOLVABLE`).

The three reasons a declared profile yields no verdict are deliberately
distinct, because a client reading one of them is told something different:
the table was never transcribed, the table exists but the system's own declared
levels fall outside the scope the guide states for it, or the profile was
published against a repealed version of the ENS.

The two ``n.a.`` origins stay distinct because they cite differently and an
auditor asks about both: the table's is derivable from the category, and
dimension-not-affected (Anexo I apartado 3) is not, and is the more frequent of
the two. Anexo II apartado 5.c is explicit that ``n.a.`` means not exigible for
compliance purposes, so a measure in either state sits outside BOTH the
numerator and the denominator of any conformance figure. Its second clause
("sin perjuicio de que su implantación en el sistema pudiera ser beneficioso
técnicamente") is what authorises reporting a weakness found on a non-applicable
measure as a technical observation, which is why findings are retained on the
measure rather than discarded.

The compensatory measure of art. 28.3 is NEVER inferred by the product. It is a
client declaration, read from the declared scope, and it exists here so that a
measure the client satisfies by a declared substitute cannot be reported as an
incumplimiento by another route.

An undeclared workspace
-----------------------
:func:`resolve_ens_applicability` called with no scope does NOT decline to
answer and does NOT assume a category. A measure required from the lowest column
upward is required at every category, so the undeclared default is that common
core: those measures resolve :attr:`REQUIRED` and the remainder resolve
:attr:`EXIGIBILITY_UNDECLARED`, which the surfaces state plainly as depending on
the client's categorisation. Nothing prompts and nothing blocks.

Refuerzos
---------
Of the 133 refuerzos Anexo II describes, 41 are not required in any category or
level: they are the optional ones of apartado 6.e and cannot sustain a
non-conformity. :func:`refuerzo_is_required` is the only way to ask, and it
answers ``False`` for every one of them in every column, so no consumer can
manufacture one. Four measures carry a choice group (apartado 5.e) where one
member satisfies the measure, and two of those groups are NOT incremental
between columns, so the groups are carried per column rather than inherited.

This module is pure data and pure logic (stdlib only, no ADscan imports), and
the table is public normative text, so it lives in ``adscan_core`` where both
the report engine and the appliance backend can read it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Mapping, NamedTuple, Optional

#: The normative version this table transcribes. Stamped on every resolution and
#: compared against a declared scope's own version: an older workspace
#: re-rendered against newer data would otherwise mismap silently, with no error.
ENS_VERSION: str = "RD 311/2022"

#: Long form, for a client-facing scope header.
ENS_VERSION_LONG: str = (
    "Real Decreto 311/2022, de 3 de mayo (BOE-A-2022-7191), Anexo II"
)

#: The general profile of Anexo II: the applicability table of the norm itself,
#: and the profile every other one is read against when it cannot apply.
PROFILE_GENERAL: str = "general"

#: The two published Perfiles de Cumplimiento Específico this build transcribes,
#: keyed by the CCN-STIC guide that defines them. The guide identifier is the
#: only stable key: an entity-shaped name ("municipalities under 20,000") drifts
#: the moment the CCN republishes a guide with a different population band, and
#: two of the three names this product previously offered were inventions that
#: matched no published document.
PROFILE_CCN_STIC_890A: str = "ccn_stic_890a"
PROFILE_CCN_STIC_890C: str = "ccn_stic_890c"

#: The honest answer for a client certified under one of the other published
#: Perfiles de Cumplimiento Específico. The CCN publishes a dozen; this build
#: transcribes two, and the rest are not named here because naming a normative
#: document whose text nobody read is how a fabricated profile gets offered as
#: a real one. Declaring this token records a true fact about the system and
#: resolves to a stated non-verdict, which is worth more than forcing a client
#: to choose between the wrong profile and none.
PROFILE_OTHER_SPECIFIC: str = "other_specific_profile"

#: Citations, by the state they justify. Printed beside a measure so the reason
#: for a non-verdict is auditable without leaving the document.
CITATION_TABLE_NA: str = "RD 311/2022, Anexo II, apdos. 2.4 y 5.c"
CITATION_DIMENSION_NA: str = "RD 311/2022, Anexo I, apdo. 3; Anexo II, apdo. 5.a"
CITATION_REQUIRED: str = "RD 311/2022, Anexo II, apdos. 2.4 y 5.b"
CITATION_COMPENSATORY: str = "RD 311/2022, art. 28.3"
CITATION_CATEGORY_DERIVATION: str = "RD 311/2022, Anexo I, apdos. 4.1 y 4.2"

#: The article that authorises a specific compliance profile to carry its own
#: applicability table, and therefore its own scope of application.
CITATION_SPECIFIC_PROFILE: str = "RD 311/2022, art. 30"


class Dimension(str, Enum):
    """The five security dimensions of Anexo I, by the initials Anexo II uses."""

    C = "C"
    I = "I"  # noqa: E741 - the normative initial for Integridad
    T = "T"
    A = "A"
    D = "D"


#: Declaration order: the order the ITS de Auditoría breakdown is read in.
DIMENSION_ORDER: tuple[Dimension, ...] = (
    Dimension.C,
    Dimension.I,
    Dimension.T,
    Dimension.A,
    Dimension.D,
)

#: Client-facing names, in the language of the norm the client is audited
#: against. The product's user-facing text is English, but these are the names
#: of normative objects an auditor reads off the Declaración de Aplicabilidad.
DIMENSION_NAMES: dict[Dimension, str] = {
    Dimension.C: "Confidencialidad",
    Dimension.I: "Integridad",
    Dimension.T: "Trazabilidad",
    Dimension.A: "Autenticidad",
    Dimension.D: "Disponibilidad",
}


class Level(str, Enum):
    """A dimension's level, admitting "not affected" (Anexo I, apdo. 3)."""

    BAJO = "bajo"
    MEDIO = "medio"
    ALTO = "alto"
    NOT_AFFECTED = "no_afectada"


class Category(str, Enum):
    """A system's security category (Anexo I, apdo. 4.1)."""

    BASICA = "basica"
    MEDIA = "media"
    ALTA = "alta"


#: The column of the Anexo II table each category reads, and each level reads
#: for a dimension-selected measure. One table, two readings of the same three
#: columns (Anexo II, apdo. 5.a).
_COLUMN_BY_CATEGORY: dict[Category, str] = {
    Category.BASICA: "basica",
    Category.MEDIA: "media",
    Category.ALTA: "alta",
}
_COLUMN_BY_LEVEL: dict[Level, str] = {
    Level.BAJO: "basica",
    Level.MEDIO: "media",
    Level.ALTO: "alta",
}
_LEVEL_RANK: dict[Level, int] = {Level.BAJO: 1, Level.MEDIO: 2, Level.ALTO: 3}
_CATEGORY_BY_RANK: dict[int, Category] = {
    1: Category.BASICA,
    2: Category.MEDIA,
    3: Category.ALTA,
}

#: Column labels as the norm writes them: a category for a category-selected
#: measure, a dimension level for a dimension-selected one.
_CATEGORY_LABEL: dict[str, str] = {
    "basica": "BÁSICA",
    "media": "MEDIA",
    "alta": "ALTA",
}
_LEVEL_LABEL: dict[str, str] = {"basica": "BAJO", "media": "MEDIO", "alta": "ALTO"}


class ApplicabilityState(str, Enum):
    """What a declared scope makes of one measure.

    The first four are the normative outcomes. The last three are non-verdicts
    the product states rather than guessing: they are excluded from a
    conformance figure exactly like an untested control, and they are labelled
    separately because the reason differs.
    """

    REQUIRED = "required"
    NOT_APPLICABLE_BY_TABLE = "not_applicable_by_table"
    NOT_APPLICABLE_BY_DIMENSION = "not_applicable_by_dimension"
    COMPENSATORY_MEASURE = "compensatory_measure"
    EXIGIBILITY_UNDECLARED = "exigibility_undeclared"
    PROFILE_OUT_OF_SCOPE = "profile_out_of_scope"
    NOT_RESOLVABLE = "not_resolvable"


#: The states that put a measure outside both the numerator and the denominator
#: of a conformance figure because the norm does not require it.
NOT_APPLICABLE_STATES: frozenset[ApplicabilityState] = frozenset(
    {
        ApplicabilityState.NOT_APPLICABLE_BY_TABLE,
        ApplicabilityState.NOT_APPLICABLE_BY_DIMENSION,
    }
)

#: The states that carry no verdict at all, because the input to decide one was
#: not supplied or could not be honoured.
#:
#: :attr:`ApplicabilityState.PROFILE_OUT_OF_SCOPE` belongs here and not among
#: the ``n.a.`` states: a measure the declared profile cannot speak about is not
#: a measure the norm does not require. The general profile very likely requires
#: it, so reporting it as not applicable would excuse a real obligation, while
#: reporting it as a non-conformity would assert one the profile never stated.
#: Both sides of the conformance figure drop it, exactly like an untested
#: control, and the scope header names the profile that does apply instead.
UNRESOLVED_STATES: frozenset[ApplicabilityState] = frozenset(
    {
        ApplicabilityState.EXIGIBILITY_UNDECLARED,
        ApplicabilityState.PROFILE_OUT_OF_SCOPE,
        ApplicabilityState.NOT_RESOLVABLE,
    }
)


class _Column(NamedTuple):
    """One measure's cell in one column of the Anexo II table."""

    applies: bool
    refuerzos_required: tuple[str, ...]
    refuerzos_choice: tuple[tuple[str, ...], ...]


class _Row(NamedTuple):
    """One measure of Anexo II, with its applicability across the three columns."""

    name: str
    family: str
    apartado: str
    selector: str
    dimensions: tuple[str, ...]
    basica: _Column
    media: _Column
    alta: _Column
    refuerzos_declared: tuple[str, ...]
    refuerzos_never_required: tuple[str, ...]

    def column(self, key: str) -> _Column:
        return _Column(*getattr(self, key))


SELECTOR_CATEGORY = "categoria"
SELECTOR_DIMENSION = "dimension"


class _ProfileRow(NamedTuple):
    """One measure's verdict in a specific compliance profile's own table.

    Attributes:
        applied_column: The column of the measure's Anexo II row whose
            requirements the profile applies, or ``None`` when the profile
            records the measure as not applicable to it. This is the profile's
            ``Aplicación`` column, which carries a CATEGORY label when the
            measure affects all five dimensions and a LEVEL label otherwise:
            the same two-axis reading the general table already has, so it is
            stored as a column key and the label is derived from the measure's
            own selector rather than transcribed twice.
        criteria_apartado: The profile's own apartado 4 subsection that states
            specific application criteria for this measure, or empty. A measure
            carrying one is never rendered as a plain verdict: the criteria
            change what satisfying it means, and in one case they oblige a
            measure the table otherwise records as not applicable.
    """

    applied_column: Optional[str]
    criteria_apartado: str = ""


class ProfileTableStatus(str, Enum):
    """Why a profile does or does not carry an applicability table here.

    Three reasons, and conflating them was the defect this replaced: a profile
    whose table nobody transcribed, a profile whose published table predates the
    normative version this build maps, and a profile that is fully populated are
    three different answers to "why is there no verdict", and a client reading
    "not available" for the second case would be told the wrong thing.
    """

    POPULATED = "populated"
    NOT_TRANSCRIBED = "not_transcribed"
    SUPERSEDED_BY_VERSION = "superseded_by_version"


@dataclass(frozen=True)
class ComplianceProfile:
    """One compliance profile: its table, its citation, and its OWN scope.

    The concept the two published PCE guides forced into the model. A profile is
    not just a different applicability table over the same measures: it is a
    table plus a **precondition on the declared scope**, because the guide that
    publishes it states which systems it may be applied to. Both CCN-STIC 890A
    and 890C exist to make BÁSICA conformance reachable and say so in their own
    apartado 2: they cover a system whose Anexo I valuation is BAJO in every
    security dimension, and nothing above that.

    So a declaration naming a profile the system's own levels put outside it is
    neither a verdict nor a missing table. It is a mismatch between two client
    declarations, and the honest answer names the profile that does apply
    instead of quietly reading a table that was never validated for those
    levels.

    Attributes:
        key: The stable token a declaration carries.
        name: The client-facing name, in English, for a scope header.
        citation: The document and edition the table was transcribed from.
        scope_statement: Who the guide says the profile may be applied to, in
            the document's own terms.
        declaration: The profile's own per-measure table, or ``None`` for the
            general profile, whose table IS Anexo II and is resolved directly.
        table_status: Why there is or is not a table.
        superseded_note: For a superseded profile, what replaced it.
        max_level: The highest dimension level the profile covers, or ``None``
            when it covers any. The precondition.
    """

    key: str
    name: str
    citation: str = ""
    scope_statement: str = ""
    declaration: Optional[Mapping[str, _ProfileRow]] = None
    table_status: ProfileTableStatus = ProfileTableStatus.POPULATED
    superseded_note: str = ""
    max_level: Optional[Level] = None

    @property
    def table_populated(self) -> bool:
        return self.table_status is ProfileTableStatus.POPULATED

    def out_of_scope_reason(self, scope: "EnsScope") -> str:
        """Why this profile cannot be applied to ``scope``, or an empty string.

        Reads the declared levels, not the derived category: the guides phrase
        the precondition per dimension ("nivel bajo en todas las dimensiones de
        seguridad"), and a dimension recorded as not affected carries no level
        to exceed, so it never puts a system out of scope on its own.
        """
        if self.max_level is None:
            return ""
        ceiling = _LEVEL_RANK[self.max_level]
        over = [
            dimension
            for dimension in DIMENSION_ORDER
            if scope.level(dimension) is not Level.NOT_AFFECTED
            and _LEVEL_RANK[scope.level(dimension)] > ceiling
        ]
        if not over:
            return ""
        named = ", ".join(
            f"{DIMENSION_NAMES[dimension]} ({dimension.value}) "
            f"{_LEVEL_LABEL_BY_LEVEL[scope.level(dimension)]}"
            for dimension in over
        )
        return (
            f"{self.name} covers a system valued "
            f"{_LEVEL_LABEL_BY_LEVEL[self.max_level]} in every security "
            f"dimension. This system declares {named}, so the profile's own "
            "scope of application does not reach it."
        )


@dataclass(frozen=True)
class MeasureApplicability:
    """The resolved applicability of ONE measure under ONE declared scope.

    Carries everything a renderer or a conformity classifier needs, so neither
    re-derives it: the state, the citation that justifies it, the column the
    measure was read in, and the refuerzos that column requires.
    """

    measure_id: str
    state: ApplicabilityState
    selector: str
    dimensions: tuple[str, ...]
    column: Optional[str]
    column_label: str
    reason: str
    citation: str
    name: str = ""
    apartado: str = ""
    refuerzos_required: tuple[str, ...] = ()
    refuerzos_choice: tuple[tuple[str, ...], ...] = ()
    refuerzos_never_required: tuple[str, ...] = ()

    @property
    def is_required(self) -> bool:
        return self.state is ApplicabilityState.REQUIRED

    @property
    def is_not_applicable(self) -> bool:
        return self.state in NOT_APPLICABLE_STATES

    @property
    def is_unresolved(self) -> bool:
        return self.state in UNRESOLVED_STATES

    def as_dict(self) -> dict[str, object]:
        """The serializable shape the report artifact and the web CTEM ingest."""
        return {
            "measure_id": self.measure_id,
            "state": self.state.value,
            "selector": self.selector,
            "dimensions": list(self.dimensions),
            "column": self.column,
            "column_label": self.column_label,
            "reason": self.reason,
            "citation": self.citation,
            "name": self.name,
            "anexo_ii_apartado": self.apartado,
            "refuerzos_required": list(self.refuerzos_required),
            "refuerzos_choice": [list(group) for group in self.refuerzos_choice],
            "refuerzos_never_required": list(self.refuerzos_never_required),
            "is_required": self.is_required,
            "is_not_applicable": self.is_not_applicable,
            "is_unresolved": self.is_unresolved,
        }


@dataclass(frozen=True)
class EnsScope:
    """A system's declared ENS scope: the resolver's whole input.

    The category is NOT an attribute: it is derived from
    :attr:`dimension_levels` per Anexo I apartado 4.1, so an inconsistent
    declaration is structurally impossible.

    Attributes:
        dimension_levels: Each of the five dimensions' declared level. A
            dimension absent from the mapping is read as not affected, so a
            partial declaration degrades rather than raising.
        profile: The compliance profile the system certifies under.
        ens_version: The normative version the declaration was made against.
        compensatory_measures: Measure ids the client declares satisfied by a
            compensatory measure under art. 28.3. Never inferred.
        system_label: The system or subsystem the declaration covers (Anexo II
            apdo. 2.2 admits granularity below the system). Carried for the
            scope header; the product never derives applicability from it.
    """

    dimension_levels: Mapping[Dimension, Level] = field(default_factory=dict)
    profile: str = PROFILE_GENERAL
    ens_version: str = ENS_VERSION
    compensatory_measures: frozenset[str] = frozenset()
    system_label: Optional[str] = None

    def level(self, dimension: Dimension) -> Level:
        """The declared level of one dimension; not affected when absent."""
        return self.dimension_levels.get(dimension, Level.NOT_AFFECTED)

    @property
    def category(self) -> Optional[Category]:
        """The derived system category: the maximum of the dimension levels.

        ``None`` when no dimension carries a level, which is a degenerate
        declaration (a system handling no information and providing no service)
        rather than a category.
        """
        ranks = [
            _LEVEL_RANK[self.level(dimension)]
            for dimension in DIMENSION_ORDER
            if self.level(dimension) is not Level.NOT_AFFECTED
        ]
        if not ranks:
            return None
        return _CATEGORY_BY_RANK[max(ranks)]

    @property
    def version_supported(self) -> bool:
        """Whether the declared normative version is the one this table carries."""
        return _normalize_version(self.ens_version) == _normalize_version(ENS_VERSION)

    @property
    def profile_definition(self) -> Optional[ComplianceProfile]:
        """The declared profile, or ``None`` when no published one matches it."""
        return resolve_profile(self.profile)

    @property
    def profile_table(self) -> Optional[str]:
        """The populated table key for the declared profile, or ``None``.

        Kept as the predicate every caller already asks ("is there a table to
        read"), now answered off the profile registry.
        """
        profile = self.profile_definition
        if profile is None or not profile.table_populated:
            return None
        return profile.key

    @property
    def profile_out_of_scope_reason(self) -> str:
        """Why the declared profile cannot be applied here, or an empty string."""
        profile = self.profile_definition
        if profile is None or not profile.table_populated:
            return ""
        return profile.out_of_scope_reason(self)


@dataclass(frozen=True)
class EnsScopeResolution:
    """The resolved applicability of EVERY Anexo II measure under one scope.

    Everything a scope header prints is a field here, so no renderer derives a
    count of its own and no two surfaces can disagree on one.
    """

    declared: bool
    ens_version: str
    version_supported: bool
    profile: str
    profile_table_populated: bool
    category: Optional[Category]
    dimension_levels: Mapping[Dimension, Level]
    measures: Mapping[str, MeasureApplicability]
    note: str = ""
    profile_name: str = ""
    profile_citation: str = ""
    profile_scope_statement: str = ""
    profile_applies: bool = True
    profile_out_of_scope_reason: str = ""

    @property
    def category_label(self) -> str:
        """The derived category as the norm writes it, or an honest absence."""
        if self.category is None:
            return "no declarada"
        return _CATEGORY_LABEL[_COLUMN_BY_CATEGORY[self.category]]

    def measure(self, measure_id: str) -> Optional[MeasureApplicability]:
        """One measure's applicability, or ``None`` when it is not in Anexo II."""
        return self.measures.get(measure_id)

    def ids_in_state(self, state: ApplicabilityState) -> tuple[str, ...]:
        return tuple(
            sorted(mid for mid, m in self.measures.items() if m.state is state)
        )

    def count_in_state(self, state: ApplicabilityState) -> int:
        return sum(1 for m in self.measures.values() if m.state is state)

    @property
    def counts(self) -> dict[str, int]:
        """Per-state totals over the full Anexo II measure set."""
        return {state.value: self.count_in_state(state) for state in ApplicabilityState}

    def dimension_level_labels(self) -> list[dict[str, str]]:
        """The five levels as the audit report declares them, in order."""
        return [
            {
                "dimension": dimension.value,
                "name": DIMENSION_NAMES[dimension],
                "level": self.dimension_levels.get(
                    dimension, Level.NOT_AFFECTED
                ).value,
                "label": _LEVEL_LABEL_BY_LEVEL[
                    self.dimension_levels.get(dimension, Level.NOT_AFFECTED)
                ],
            }
            for dimension in DIMENSION_ORDER
        ]

    def as_header(self) -> dict[str, object]:
        """The scope header every surface prints, as data.

        Carries version, profile, derived category, the five levels and the
        per-state counts, so a renderer states the scope without computing any
        part of it.
        """
        counts = self.counts
        return {
            "declared": self.declared,
            "ens_version": self.ens_version,
            "ens_version_long": ENS_VERSION_LONG,
            "version_supported": self.version_supported,
            "profile": _normalize_profile(self.profile),
            "profile_table_populated": self.profile_table_populated,
            "profile_name": self.profile_name
            or _normalize_profile(self.profile),
            "profile_citation": self.profile_citation,
            "profile_scope_statement": self.profile_scope_statement,
            "profile_applies": self.profile_applies,
            "profile_out_of_scope_reason": self.profile_out_of_scope_reason,
            "specific_profile_citation": CITATION_SPECIFIC_PROFILE,
            "category": self.category.value if self.category else None,
            "category_label": self.category_label,
            "category_derivation_citation": CITATION_CATEGORY_DERIVATION,
            "dimension_levels": self.dimension_level_labels(),
            "measures_total": len(self.measures),
            "required_total": counts[ApplicabilityState.REQUIRED.value],
            "not_applicable_by_table_total": counts[
                ApplicabilityState.NOT_APPLICABLE_BY_TABLE.value
            ],
            "not_applicable_by_dimension_total": counts[
                ApplicabilityState.NOT_APPLICABLE_BY_DIMENSION.value
            ],
            "compensatory_measure_total": counts[
                ApplicabilityState.COMPENSATORY_MEASURE.value
            ],
            "exigibility_undeclared_total": counts[
                ApplicabilityState.EXIGIBILITY_UNDECLARED.value
            ],
            "profile_out_of_scope_total": counts[
                ApplicabilityState.PROFILE_OUT_OF_SCOPE.value
            ],
            "not_resolvable_total": counts[ApplicabilityState.NOT_RESOLVABLE.value],
            "common_core_total": len(COMMON_CORE_MEASURE_IDS),
            "note": self.note,
        }


_LEVEL_LABEL_BY_LEVEL: dict[Level, str] = {
    Level.BAJO: "BAJO",
    Level.MEDIO: "MEDIO",
    Level.ALTO: "ALTO",
    Level.NOT_AFFECTED: "no afectada",
}


def _normalize_version(value: object) -> str:
    """Fold a declared version onto a comparable token.

    Tolerates the forms a client writes ("RD 311/2022", "Real Decreto
    311/2022", "311/2022") because the discriminating part is the number, and
    refusing a correct declaration over its punctuation would be worse than
    reading it.
    """
    text = str(value or "").strip().lower()
    for noise in ("real decreto", "rd", "r.d.", ",", "de 3 de mayo", " "):
        text = text.replace(noise, "")
    return text


def _normalize_profile(value: object) -> str:
    text = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    return text or PROFILE_GENERAL


# The Anexo II applicability table, transcribed from the summary table of
# apartado 2.4 and cross-validated measure by measure against each measure's own
# "Aplicación de la medida" block (apartados 3.x / 4.x.y / 5.x.y). 73 measures,
# 133 declared refuerzos, 219 applicability cells, built twice from the two
# independent locations in the normative text with no discrepancy.
#
# DO NOT hand-edit a cell. A correction belongs in the evidence this was
# transcribed from, and then here as a whole-row replacement with its citation.
_ANEXO_II_GENERAL: dict[str, _Row] = {
    'org.1': _Row(
        name='Política de seguridad',
        family='org',
        apartado='3.1',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=(),
        refuerzos_never_required=(),
    ),
    'org.2': _Row(
        name='Normativa de seguridad',
        family='org',
        apartado='3.2',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=('R1',),
        refuerzos_never_required=('R1',),
    ),
    'org.3': _Row(
        name='Procedimientos de seguridad',
        family='org',
        apartado='3.3',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=('R1',),
        refuerzos_never_required=('R1',),
    ),
    'org.4': _Row(
        name='Proceso de autorización',
        family='org',
        apartado='3.4',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=(),
        refuerzos_never_required=(),
    ),
    'op.pl.1': _Row(
        name='Análisis de riesgos',
        family='op.pl',
        apartado='4.1.1',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, ('R1',), ()),
        alta=(True, ('R2',), ()),
        refuerzos_declared=('R1', 'R2'),
        refuerzos_never_required=(),
    ),
    'op.pl.2': _Row(
        name='Arquitectura de seguridad',
        family='op.pl',
        apartado='4.1.2',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, ('R1',), ()),
        alta=(True, ('R1', 'R2', 'R3'), ()),
        refuerzos_declared=('R1', 'R2', 'R3'),
        refuerzos_never_required=(),
    ),
    'op.pl.3': _Row(
        name='Adquisición de nuevos componentes',
        family='op.pl',
        apartado='4.1.3',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=(),
        refuerzos_never_required=(),
    ),
    'op.pl.4': _Row(
        name='Dimensionamiento / gestión de la capacidad',
        family='op.pl',
        apartado='4.1.4',
        selector='dimension',
        dimensions=('D',),
        basica=(True, (), ()),
        media=(True, ('R1',), ()),
        alta=(True, ('R1',), ()),
        refuerzos_declared=('R1',),
        refuerzos_never_required=(),
    ),
    'op.pl.5': _Row(
        name='Componentes certificados',
        family='op.pl',
        apartado='4.1.5',
        selector='categoria',
        dimensions=(),
        basica=(False, (), ()),
        media=(True, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=('R1', 'R2'),
        refuerzos_never_required=('R1', 'R2'),
    ),
    'op.acc.1': _Row(
        name='Identificación',
        family='op.acc',
        apartado='4.2.1',
        selector='dimension',
        dimensions=('T', 'A'),
        basica=(True, (), ()),
        media=(True, ('R1',), ()),
        alta=(True, ('R1',), ()),
        refuerzos_declared=('R1',),
        refuerzos_never_required=(),
    ),
    'op.acc.2': _Row(
        name='Requisitos de acceso',
        family='op.acc',
        apartado='4.2.2',
        selector='dimension',
        dimensions=('C', 'I', 'T', 'A'),
        basica=(True, (), ()),
        media=(True, (), ()),
        alta=(True, ('R1',), ()),
        refuerzos_declared=('R1', 'R2'),
        refuerzos_never_required=('R2',),
    ),
    'op.acc.3': _Row(
        name='Segregación de funciones y tareas',
        family='op.acc',
        apartado='4.2.3',
        selector='dimension',
        dimensions=('C', 'I', 'T', 'A'),
        basica=(False, (), ()),
        media=(True, (), ()),
        alta=(True, ('R1',), ()),
        refuerzos_declared=('R1', 'R2', 'R3'),
        refuerzos_never_required=('R2', 'R3'),
    ),
    'op.acc.4': _Row(
        name='Proceso de gestión de derechos de acceso',
        family='op.acc',
        apartado='4.2.4',
        selector='dimension',
        dimensions=('C', 'I', 'T', 'A'),
        basica=(True, (), ()),
        media=(True, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=(),
        refuerzos_never_required=(),
    ),
    'op.acc.5': _Row(
        name='Mecanismo de autenticación (usuarios externos)',
        family='op.acc',
        apartado='4.2.5',
        selector='dimension',
        dimensions=('C', 'I', 'T', 'A'),
        basica=(True, (), (('R1', 'R2', 'R3', 'R4'),)),
        media=(True, ('R5',), (('R2', 'R3', 'R4'),)),
        alta=(True, ('R5',), (('R2', 'R3', 'R4'),)),
        refuerzos_declared=('R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7'),
        refuerzos_never_required=('R6', 'R7'),
    ),
    'op.acc.6': _Row(
        name='Mecanismo de autenticación (usuarios de la organización)',
        family='op.acc',
        apartado='4.2.6',
        selector='dimension',
        dimensions=('C', 'I', 'T', 'A'),
        basica=(True, ('R8', 'R9'), (('R1', 'R2', 'R3', 'R4'),)),
        media=(True, ('R5', 'R8', 'R9'), (('R1', 'R2', 'R3', 'R4'),)),
        alta=(True, ('R5', 'R6', 'R7', 'R8', 'R9'), (('R1', 'R2', 'R3', 'R4'),)),
        refuerzos_declared=('R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'R8', 'R9'),
        refuerzos_never_required=(),
    ),
    'op.exp.1': _Row(
        name='Inventario de activos',
        family='op.exp',
        apartado='4.3.1',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=('R1', 'R2', 'R3', 'R4'),
        refuerzos_never_required=('R1', 'R2', 'R3', 'R4'),
    ),
    'op.exp.2': _Row(
        name='Configuración de seguridad',
        family='op.exp',
        apartado='4.3.2',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=(),
        refuerzos_never_required=(),
    ),
    'op.exp.3': _Row(
        name='Gestión de la configuración de seguridad',
        family='op.exp',
        apartado='4.3.3',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, ('R1',), ()),
        alta=(True, ('R1', 'R2', 'R3'), ()),
        refuerzos_declared=('R1', 'R2', 'R3', 'R4', 'R5'),
        refuerzos_never_required=('R4', 'R5'),
    ),
    'op.exp.4': _Row(
        name='Mantenimiento y actualizaciones de seguridad',
        family='op.exp',
        apartado='4.3.4',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, ('R1',), ()),
        alta=(True, ('R1', 'R2'), ()),
        refuerzos_declared=('R1', 'R2', 'R3', 'R4'),
        refuerzos_never_required=('R3', 'R4'),
    ),
    'op.exp.5': _Row(
        name='Gestión de cambios',
        family='op.exp',
        apartado='4.3.5',
        selector='categoria',
        dimensions=(),
        basica=(False, (), ()),
        media=(True, (), ()),
        alta=(True, ('R1',), ()),
        refuerzos_declared=('R1',),
        refuerzos_never_required=(),
    ),
    'op.exp.6': _Row(
        name='Protección frente a código dañino',
        family='op.exp',
        apartado='4.3.6',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, ('R1', 'R2'), ()),
        alta=(True, ('R1', 'R2', 'R3', 'R4'), ()),
        refuerzos_declared=('R1', 'R2', 'R3', 'R4', 'R5'),
        refuerzos_never_required=('R5',),
    ),
    'op.exp.7': _Row(
        name='Gestión de incidentes',
        family='op.exp',
        apartado='4.3.7',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, ('R1', 'R2'), ()),
        alta=(True, ('R1', 'R2', 'R3'), ()),
        refuerzos_declared=('R1', 'R2', 'R3', 'R4'),
        refuerzos_never_required=('R4',),
    ),
    'op.exp.8': _Row(
        name='Registro de la actividad',
        family='op.exp',
        apartado='4.3.8',
        selector='dimension',
        dimensions=('T',),
        basica=(True, (), ()),
        media=(True, ('R1', 'R2', 'R3', 'R4'), ()),
        alta=(True, ('R1', 'R2', 'R3', 'R4', 'R5'), ()),
        refuerzos_declared=('R1', 'R2', 'R3', 'R4', 'R5'),
        refuerzos_never_required=(),
    ),
    'op.exp.9': _Row(
        name='Registro de la gestión de incidentes',
        family='op.exp',
        apartado='4.3.9',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=(),
        refuerzos_never_required=(),
    ),
    'op.exp.10': _Row(
        name='Protección de claves criptográficas',
        family='op.exp',
        apartado='4.3.10',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, ('R1',), ()),
        alta=(True, ('R1',), ()),
        refuerzos_declared=('R1', 'R2'),
        refuerzos_never_required=('R2',),
    ),
    'op.ext.1': _Row(
        name='Contratación y acuerdos de nivel de servicio',
        family='op.ext',
        apartado='4.4.1',
        selector='categoria',
        dimensions=(),
        basica=(False, (), ()),
        media=(True, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=(),
        refuerzos_never_required=(),
    ),
    'op.ext.2': _Row(
        name='Gestión diaria',
        family='op.ext',
        apartado='4.4.2',
        selector='categoria',
        dimensions=(),
        basica=(False, (), ()),
        media=(True, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=(),
        refuerzos_never_required=(),
    ),
    'op.ext.3': _Row(
        name='Protección de la cadena de suministro',
        family='op.ext',
        apartado='4.4.3',
        selector='categoria',
        dimensions=(),
        basica=(False, (), ()),
        media=(False, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=('R1', 'R2', 'R3'),
        refuerzos_never_required=('R1', 'R2', 'R3'),
    ),
    'op.ext.4': _Row(
        name='Interconexión de sistemas',
        family='op.ext',
        apartado='4.4.4',
        selector='categoria',
        dimensions=(),
        basica=(False, (), ()),
        media=(True, (), ()),
        alta=(True, ('R1',), ()),
        refuerzos_declared=('R1',),
        refuerzos_never_required=(),
    ),
    'op.nub.1': _Row(
        name='Protección de servicios en la nube',
        family='op.nub',
        apartado='4.5.1',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, ('R1',), ()),
        alta=(True, ('R1', 'R2'), ()),
        refuerzos_declared=('R1', 'R2'),
        refuerzos_never_required=(),
    ),
    'op.cont.1': _Row(
        name='Análisis de impacto',
        family='op.cont',
        apartado='4.6.1',
        selector='dimension',
        dimensions=('D',),
        basica=(False, (), ()),
        media=(True, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=(),
        refuerzos_never_required=(),
    ),
    'op.cont.2': _Row(
        name='Plan de continuidad',
        family='op.cont',
        apartado='4.6.2',
        selector='dimension',
        dimensions=('D',),
        basica=(False, (), ()),
        media=(False, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=('R1', 'R2'),
        refuerzos_never_required=('R1', 'R2'),
    ),
    'op.cont.3': _Row(
        name='Pruebas periódicas',
        family='op.cont',
        apartado='4.6.3',
        selector='dimension',
        dimensions=('D',),
        basica=(False, (), ()),
        media=(False, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=(),
        refuerzos_never_required=(),
    ),
    'op.cont.4': _Row(
        name='Medios alternativos',
        family='op.cont',
        apartado='4.6.4',
        selector='dimension',
        dimensions=('D',),
        basica=(False, (), ()),
        media=(False, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=('R1',),
        refuerzos_never_required=('R1',),
    ),
    'op.mon.1': _Row(
        name='Detección de intrusión',
        family='op.mon',
        apartado='4.7.1',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, ('R1',), ()),
        alta=(True, ('R1', 'R2'), ()),
        refuerzos_declared=('R1', 'R2', 'R3'),
        refuerzos_never_required=('R3',),
    ),
    'op.mon.2': _Row(
        name='Sistema de métricas',
        family='op.mon',
        apartado='4.7.2',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, ('R1', 'R2'), ()),
        alta=(True, ('R1', 'R2'), ()),
        refuerzos_declared=('R1', 'R2'),
        refuerzos_never_required=(),
    ),
    'op.mon.3': _Row(
        name='Vigilancia',
        family='op.mon',
        apartado='4.7.3',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, ('R1', 'R2'), ()),
        alta=(True, ('R1', 'R2', 'R3', 'R4', 'R5', 'R6'), ()),
        refuerzos_declared=('R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7'),
        refuerzos_never_required=('R7',),
    ),
    'mp.if.1': _Row(
        name='Áreas separadas y con control de acceso',
        family='mp.if',
        apartado='5.1.1',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=(),
        refuerzos_never_required=(),
    ),
    'mp.if.2': _Row(
        name='Identificación de las personas',
        family='mp.if',
        apartado='5.1.2',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=(),
        refuerzos_never_required=(),
    ),
    'mp.if.3': _Row(
        name='Acondicionamiento de los locales',
        family='mp.if',
        apartado='5.1.3',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=(),
        refuerzos_never_required=(),
    ),
    'mp.if.4': _Row(
        name='Energía eléctrica',
        family='mp.if',
        apartado='5.1.4',
        selector='dimension',
        dimensions=('D',),
        basica=(True, (), ()),
        media=(True, ('R1',), ()),
        alta=(True, ('R1',), ()),
        refuerzos_declared=('R1',),
        refuerzos_never_required=(),
    ),
    'mp.if.5': _Row(
        name='Protección frente a incendios',
        family='mp.if',
        apartado='5.1.5',
        selector='dimension',
        dimensions=('D',),
        basica=(True, (), ()),
        media=(True, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=(),
        refuerzos_never_required=(),
    ),
    'mp.if.6': _Row(
        name='Protección frente a inundaciones',
        family='mp.if',
        apartado='5.1.6',
        selector='dimension',
        dimensions=('D',),
        basica=(False, (), ()),
        media=(True, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=(),
        refuerzos_never_required=(),
    ),
    'mp.if.7': _Row(
        name='Registro de entrada y salida de equipamiento',
        family='mp.if',
        apartado='5.1.7',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=(),
        refuerzos_never_required=(),
    ),
    'mp.per.1': _Row(
        name='Caracterización del puesto de trabajo',
        family='mp.per',
        apartado='5.2.1',
        selector='categoria',
        dimensions=(),
        basica=(False, (), ()),
        media=(True, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=('R1',),
        refuerzos_never_required=('R1',),
    ),
    'mp.per.2': _Row(
        name='Deberes y obligaciones',
        family='mp.per',
        apartado='5.2.2',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, ('R1',), ()),
        alta=(True, ('R1',), ()),
        refuerzos_declared=('R1',),
        refuerzos_never_required=(),
    ),
    'mp.per.3': _Row(
        name='Concienciación',
        family='mp.per',
        apartado='5.2.3',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=(),
        refuerzos_never_required=(),
    ),
    'mp.per.4': _Row(
        name='Formación',
        family='mp.per',
        apartado='5.2.4',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=(),
        refuerzos_never_required=(),
    ),
    'mp.eq.1': _Row(
        name='Puesto de trabajo despejado',
        family='mp.eq',
        apartado='5.3.1',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, ('R1',), ()),
        alta=(True, ('R1',), ()),
        refuerzos_declared=('R1',),
        refuerzos_never_required=(),
    ),
    'mp.eq.2': _Row(
        name='Bloqueo de puesto de trabajo',
        family='mp.eq',
        apartado='5.3.2',
        selector='dimension',
        dimensions=('A',),
        basica=(False, (), ()),
        media=(True, (), ()),
        alta=(True, ('R1',), ()),
        refuerzos_declared=('R1',),
        refuerzos_never_required=(),
    ),
    'mp.eq.3': _Row(
        name='Protección de dispositivos portátiles',
        family='mp.eq',
        apartado='5.3.3',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, (), ()),
        alta=(True, ('R1', 'R2'), ()),
        refuerzos_declared=('R1', 'R2'),
        refuerzos_never_required=(),
    ),
    'mp.eq.4': _Row(
        name='Otros dispositivos conectados a la red',
        family='mp.eq',
        apartado='5.3.4',
        selector='dimension',
        dimensions=('C',),
        basica=(True, (), ()),
        media=(True, ('R1',), ()),
        alta=(True, ('R1',), ()),
        refuerzos_declared=('R1', 'R2'),
        refuerzos_never_required=('R2',),
    ),
    'mp.com.1': _Row(
        name='Perímetro seguro',
        family='mp.com',
        apartado='5.4.1',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=(),
        refuerzos_never_required=(),
    ),
    'mp.com.2': _Row(
        name='Protección de la confidencialidad',
        family='mp.com',
        apartado='5.4.2',
        selector='dimension',
        dimensions=('C',),
        basica=(True, (), ()),
        media=(True, ('R1',), ()),
        alta=(True, ('R1', 'R2', 'R3'), ()),
        refuerzos_declared=('R1', 'R2', 'R3', 'R4', 'R5'),
        refuerzos_never_required=('R4', 'R5'),
    ),
    'mp.com.3': _Row(
        name='Protección de la integridad y de la autenticidad',
        family='mp.com',
        apartado='5.4.3',
        selector='dimension',
        dimensions=('I', 'A'),
        basica=(True, (), ()),
        media=(True, ('R1', 'R2'), ()),
        alta=(True, ('R1', 'R2', 'R3', 'R4'), ()),
        refuerzos_declared=('R1', 'R2', 'R3', 'R4', 'R5'),
        refuerzos_never_required=('R5',),
    ),
    'mp.com.4': _Row(
        name='Separación de flujos de información en la red',
        family='mp.com',
        apartado='5.4.4',
        selector='categoria',
        dimensions=(),
        basica=(False, (), ()),
        media=(True, (), (('R1', 'R2', 'R3'),)),
        alta=(True, ('R4',), (('R2', 'R3'),)),
        refuerzos_declared=('R1', 'R2', 'R3', 'R4'),
        refuerzos_never_required=(),
    ),
    'mp.si.1': _Row(
        name='Marcado de soportes',
        family='mp.si',
        apartado='5.5.1',
        selector='dimension',
        dimensions=('C',),
        basica=(False, (), ()),
        media=(True, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=('R1',),
        refuerzos_never_required=('R1',),
    ),
    'mp.si.2': _Row(
        name='Criptografía',
        family='mp.si',
        apartado='5.5.2',
        selector='dimension',
        dimensions=('C', 'I'),
        basica=(False, (), ()),
        media=(True, (), ()),
        alta=(True, ('R1', 'R2'), ()),
        refuerzos_declared=('R1', 'R2'),
        refuerzos_never_required=(),
    ),
    'mp.si.3': _Row(
        name='Custodia',
        family='mp.si',
        apartado='5.5.3',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=(),
        refuerzos_never_required=(),
    ),
    'mp.si.4': _Row(
        name='Transporte',
        family='mp.si',
        apartado='5.5.4',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=(),
        refuerzos_never_required=(),
    ),
    'mp.si.5': _Row(
        name='Borrado y destrucción',
        family='mp.si',
        apartado='5.5.5',
        selector='dimension',
        dimensions=('C',),
        basica=(True, (), ()),
        media=(True, ('R1',), ()),
        alta=(True, ('R1',), ()),
        refuerzos_declared=('R1', 'R2'),
        refuerzos_never_required=('R2',),
    ),
    'mp.sw.1': _Row(
        name='Desarrollo de aplicaciones',
        family='mp.sw',
        apartado='5.6.1',
        selector='categoria',
        dimensions=(),
        basica=(False, (), ()),
        media=(True, ('R1', 'R2', 'R3', 'R4'), ()),
        alta=(True, ('R1', 'R2', 'R3', 'R4'), ()),
        refuerzos_declared=('R1', 'R2', 'R3', 'R4', 'R5'),
        refuerzos_never_required=('R5',),
    ),
    'mp.sw.2': _Row(
        name='Aceptación y puesta en servicio',
        family='mp.sw',
        apartado='5.6.2',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, ('R1',), ()),
        alta=(True, ('R1',), ()),
        refuerzos_declared=('R1', 'R2'),
        refuerzos_never_required=('R2',),
    ),
    'mp.info.1': _Row(
        name='Datos personales',
        family='mp.info',
        apartado='5.7.1',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=(),
        refuerzos_never_required=(),
    ),
    'mp.info.2': _Row(
        name='Calificación de la información',
        family='mp.info',
        apartado='5.7.2',
        selector='dimension',
        dimensions=('C',),
        basica=(False, (), ()),
        media=(True, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=(),
        refuerzos_never_required=(),
    ),
    'mp.info.3': _Row(
        name='Firma electrónica',
        family='mp.info',
        apartado='5.7.3',
        selector='dimension',
        dimensions=('I', 'A'),
        basica=(True, (), ()),
        media=(True, ('R1', 'R2', 'R3'), ()),
        alta=(True, ('R1', 'R2', 'R3', 'R4'), ()),
        refuerzos_declared=('R1', 'R2', 'R3', 'R4', 'R5'),
        refuerzos_never_required=('R5',),
    ),
    'mp.info.4': _Row(
        name='Sellos de tiempo',
        family='mp.info',
        apartado='5.7.4',
        selector='dimension',
        dimensions=('T',),
        basica=(False, (), ()),
        media=(False, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=('R1',),
        refuerzos_never_required=('R1',),
    ),
    'mp.info.5': _Row(
        name='Limpieza de documentos',
        family='mp.info',
        apartado='5.7.5',
        selector='dimension',
        dimensions=('C',),
        basica=(True, (), ()),
        media=(True, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=(),
        refuerzos_never_required=(),
    ),
    'mp.info.6': _Row(
        name='Copias de seguridad',
        family='mp.info',
        apartado='5.7.6',
        selector='dimension',
        dimensions=('D',),
        basica=(True, (), ()),
        media=(True, ('R1',), ()),
        alta=(True, ('R1', 'R2'), ()),
        refuerzos_declared=('R1', 'R2'),
        refuerzos_never_required=(),
    ),
    'mp.s.1': _Row(
        name='Protección del correo electrónico',
        family='mp.s',
        apartado='5.8.1',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, (), ()),
        alta=(True, (), ()),
        refuerzos_declared=(),
        refuerzos_never_required=(),
    ),
    'mp.s.2': _Row(
        name='Protección de servicios y aplicaciones web',
        family='mp.s',
        apartado='5.8.2',
        selector='categoria',
        dimensions=(),
        basica=(True, (), (('R1', 'R2'),)),
        media=(True, (), (('R1', 'R2'),)),
        alta=(True, ('R2', 'R3'), ()),
        refuerzos_declared=('R1', 'R2', 'R3'),
        refuerzos_never_required=(),
    ),
    'mp.s.3': _Row(
        name='Protección de la navegación web',
        family='mp.s',
        apartado='5.8.3',
        selector='categoria',
        dimensions=(),
        basica=(True, (), ()),
        media=(True, (), ()),
        alta=(True, ('R1',), ()),
        refuerzos_declared=('R1', 'R2'),
        refuerzos_never_required=('R2',),
    ),
    'mp.s.4': _Row(
        name='Protección frente a la denegación de servicio',
        family='mp.s',
        apartado='5.8.4',
        selector='dimension',
        dimensions=('D',),
        basica=(False, (), ()),
        media=(True, (), ()),
        alta=(True, ('R1',), ()),
        refuerzos_declared=('R1', 'R2'),
        refuerzos_never_required=('R2',),
    ),
}

#: Every applicability table, by profile. Only the general profile of Anexo II
#: is populated: the specific compliance profiles of art. 30 are published in
#: CCN-STIC guides that could not be obtained, and guessing their deltas would
#: be inventing normative content. A profile absent here resolves to
#: :attr:`ApplicabilityState.NOT_RESOLVABLE`, never to this table.
# The Declaración de Aplicabilidad of the Perfil de Cumplimiento Específico de
# Requisitos Fundamentales de Seguridad, as published in CCN-STIC 890A
# (Entidades Locales) and CCN-STIC 890C (Entidades de menor tamaño), both
# edición noviembre 2025, both written against RD 311/2022.
#
# ONE table for both guides. Their apartado 3 tables were extracted
# independently and compared cell by cell: the verdict and the criteria pointer
# are IDENTICAL for all 73 measures, and their apartado 3.1 enumerations list
# the same 38 applicable measures. The two guides differ in WHO may apply the
# profile, not in what it requires, so a second copy of the same 73 rows would
# only be a second place for a transcription error to hide. A future edition
# that diverges gets its own table and its own citation.
#
# WHICH COLUMN THIS IS. The guides reproduce the general Anexo II requirement
# in three columns headed CAT B / CAT M / CAT A, and state their OWN verdict in
# a fourth column headed "Aplicación". This table transcribes the "Aplicación"
# column. The reproduced columns were not transcribed: they were used as
# evidence instead, compared against the already-validated general matrix above
# at 438 cells with no discrepancy, which both confirms the extraction and
# confirms that those three columns carry no profile-specific content.
#
# The "Aplicación" value is a CATEGORY label (BÁSICA) when the measure affects
# all five dimensions and a LEVEL label (BAJO, MEDIO) otherwise, per the
# guides' own footnote. That is the two-axis reading the general table already
# encodes, so the value is stored as the column key whose requirements the
# profile applies and the label is derived from the measure's selector.
#
# One row is not a subset of the general table at BÁSICA: mp.eq.2 (Bloqueo de
# puesto de trabajo) is n.a. at CAT B in Anexo II and the profile applies it at
# MEDIO. A fundamental requirement the profile ADDS, which is why the table
# carries a column key per measure rather than a boolean.
#
# DO NOT hand-edit a cell. A correction belongs in the guide it was
# transcribed from, and then here as a whole-row replacement.
_PCE_RFS_DECLARATION: dict[str, _ProfileRow] = {
    'org.1': _ProfileRow('basica', ''),
    'org.2': _ProfileRow('basica', ''),
    'org.3': _ProfileRow('basica', ''),
    'org.4': _ProfileRow('basica', ''),
    'op.pl.1': _ProfileRow('basica', '4.1'),
    'op.pl.2': _ProfileRow(None, ''),
    'op.pl.3': _ProfileRow('basica', ''),
    'op.pl.4': _ProfileRow(None, ''),
    'op.pl.5': _ProfileRow(None, ''),
    'op.acc.1': _ProfileRow('basica', ''),
    'op.acc.2': _ProfileRow('basica', ''),
    'op.acc.3': _ProfileRow(None, ''),
    'op.acc.4': _ProfileRow('basica', ''),
    'op.acc.5': _ProfileRow('basica', ''),
    'op.acc.6': _ProfileRow('basica', '4.2'),
    'op.exp.1': _ProfileRow('basica', ''),
    'op.exp.2': _ProfileRow('basica', ''),
    'op.exp.3': _ProfileRow(None, ''),
    'op.exp.4': _ProfileRow('basica', ''),
    'op.exp.5': _ProfileRow(None, ''),
    'op.exp.6': _ProfileRow('basica', ''),
    'op.exp.7': _ProfileRow('basica', ''),
    'op.exp.8': _ProfileRow('basica', '4.3'),
    'op.exp.9': _ProfileRow(None, ''),
    'op.exp.10': _ProfileRow('basica', ''),
    'op.ext.1': _ProfileRow(None, ''),
    'op.ext.2': _ProfileRow(None, ''),
    'op.ext.3': _ProfileRow(None, ''),
    'op.ext.4': _ProfileRow(None, ''),
    'op.nub.1': _ProfileRow(None, ''),
    'op.cont.1': _ProfileRow(None, ''),
    'op.cont.2': _ProfileRow(None, '4.4'),
    'op.cont.3': _ProfileRow(None, ''),
    'op.cont.4': _ProfileRow(None, ''),
    'op.mon.1': _ProfileRow(None, ''),
    'op.mon.2': _ProfileRow('basica', ''),
    'op.mon.3': _ProfileRow(None, ''),
    'mp.if.1': _ProfileRow('basica', '4.5'),
    'mp.if.2': _ProfileRow(None, ''),
    'mp.if.3': _ProfileRow(None, ''),
    'mp.if.4': _ProfileRow(None, ''),
    'mp.if.5': _ProfileRow(None, ''),
    'mp.if.6': _ProfileRow(None, ''),
    'mp.if.7': _ProfileRow(None, ''),
    'mp.per.1': _ProfileRow(None, ''),
    'mp.per.2': _ProfileRow('basica', ''),
    'mp.per.3': _ProfileRow('basica', ''),
    'mp.per.4': _ProfileRow('basica', ''),
    'mp.eq.1': _ProfileRow('basica', ''),
    'mp.eq.2': _ProfileRow('media', ''),
    'mp.eq.3': _ProfileRow('basica', ''),
    'mp.eq.4': _ProfileRow('basica', ''),
    'mp.com.1': _ProfileRow('basica', '4.6'),
    'mp.com.2': _ProfileRow('basica', ''),
    'mp.com.3': _ProfileRow(None, ''),
    'mp.com.4': _ProfileRow(None, ''),
    'mp.si.1': _ProfileRow(None, ''),
    'mp.si.2': _ProfileRow(None, ''),
    'mp.si.3': _ProfileRow('basica', ''),
    'mp.si.4': _ProfileRow('basica', ''),
    'mp.si.5': _ProfileRow('basica', ''),
    'mp.sw.1': _ProfileRow(None, ''),
    'mp.sw.2': _ProfileRow(None, ''),
    'mp.info.1': _ProfileRow('basica', ''),
    'mp.info.2': _ProfileRow(None, ''),
    'mp.info.3': _ProfileRow('basica', ''),
    'mp.info.4': _ProfileRow(None, ''),
    'mp.info.5': _ProfileRow('basica', ''),
    'mp.info.6': _ProfileRow('basica', '4.7'),
    'mp.s.1': _ProfileRow('basica', ''),
    'mp.s.2': _ProfileRow(None, ''),
    'mp.s.3': _ProfileRow('basica', ''),
    'mp.s.4': _ProfileRow(None, ''),
}

#: What CCN-STIC 890A says about the systems it may be applied to, in its own
#: terms (apartado 2), translated without being broadened.
_SCOPE_890A: str = (
    "Systems supporting the services and information of Spanish local "
    "entities: municipalities under 5,000 inhabitants and groupings of them, "
    "and entidades locales menores (Ley 7/1985, art. 24 and following), where "
    "the Anexo I valuation is BAJO in all five security dimensions. The guide "
    "excludes services it values MEDIO or ALTO, naming the population "
    "register, social and sociosanitary services and tax management, and "
    "separately lists municipal services falling under Annexes I and II of "
    "the NIS2 Directive."
)

#: The same, for CCN-STIC 890C.
_SCOPE_890C: str = (
    "Systems supporting the services and information of smaller entities "
    "outside CCN-STIC 890A's scope, where the Anexo I valuation is BAJO in "
    "all five security dimensions: small public entities with limited "
    "resources, and small and medium private-sector enterprises providing "
    "those services to the public sector within ENS scope. Private entities "
    "outside ENS scope may apply it voluntarily."
)

#: Both guides state the same transitional note: an entity inside their
#: scope whose valuation reaches MEDIO or ALTO in a dimension and still wishes to
#: apply the profile has to commit, in writing and on the model of the guide's
#: Anexo III, to raising the system to the level its own categorisation
#: requires. That route is the CLIENT's undertaking with the certification
#: body, not something a scan can assume, so a declaration above the ceiling
#: resolves out of scope and this is what the surfaces say instead.
PROFILE_IMPROVEMENT_COMMITMENT_NOTE: str = (
    "The guide that publishes this profile allows an entity inside its scope "
    "whose valuation reaches MEDIO or ALTO in a dimension to apply the profile "
    "anyway, provided the entity commits in writing, on the model in the "
    "guide's Anexo III, to raising the system progressively to the level its "
    "own categorisation requires. That commitment is an undertaking between "
    "the entity and its certification body, so this assessment does not "
    "assume one."
)

#: The population-band profiles of the CCN-STIC 883 family. Published May 2020
#: against the repealed RD 3/2010, never updated, so their measure set is not
#: the 73-measure Anexo II this build maps. Declared by name because a client
#: certified under one of them should be told why no verdict follows, rather
#: than meeting an "unknown profile" error for a document that does exist.
_SUPERSEDED_883: tuple[tuple[str, str], ...] = (
    ("ccn_stic_883a", "CCN-STIC 883A, local entities under 5,000 inhabitants"),
    ("ccn_stic_883b", "CCN-STIC 883B, local entities under 20,000 inhabitants"),
    (
        "ccn_stic_883c",
        "CCN-STIC 883C, local entities from 20,000 to 75,000 inhabitants",
    ),
    ("ccn_stic_883d", "CCN-STIC 883D, diputaciones and island councils"),
)

_883_SUPERSEDED_NOTE: str = (
    "This profile was published in May 2020 against Real Decreto 3/2010 and "
    "has not been reissued for RD 311/2022. The measure sets differ and one "
    "identifier changed meaning, so its table is not read here. The profiles "
    "published for RD 311/2022 are CCN-STIC 890A for local entities and "
    "CCN-STIC 890C for smaller entities."
)


def _published_profiles() -> dict[str, ComplianceProfile]:
    """Every profile the product recognises, keyed by its declaration token."""
    profiles = {
        PROFILE_GENERAL: ComplianceProfile(
            key=PROFILE_GENERAL,
            name="General profile of Anexo II",
            citation=ENS_VERSION_LONG,
            scope_statement=(
                "Any system within the scope of the ENS that does not certify "
                "under a specific compliance profile."
            ),
            declaration=None,
            table_status=ProfileTableStatus.POPULATED,
        ),
        PROFILE_CCN_STIC_890A: ComplianceProfile(
            key=PROFILE_CCN_STIC_890A,
            name=(
                "CCN-STIC 890A, fundamental security requirements for local "
                "entities"
            ),
            citation=(
                "CCN-STIC 890A, Perfil de Cumplimiento Específico de "
                "Requisitos Fundamentales de Seguridad (Entidades Locales), "
                "edición noviembre 2025, apdos. 2 a 4"
            ),
            scope_statement=_SCOPE_890A,
            declaration=_PCE_RFS_DECLARATION,
            table_status=ProfileTableStatus.POPULATED,
            max_level=Level.BAJO,
        ),
        PROFILE_CCN_STIC_890C: ComplianceProfile(
            key=PROFILE_CCN_STIC_890C,
            name=(
                "CCN-STIC 890C, fundamental security requirements for smaller "
                "entities"
            ),
            citation=(
                "CCN-STIC 890C, Perfil de Cumplimiento Específico de "
                "Requisitos Fundamentales de Seguridad (Entidades de menor "
                "tamaño), edición noviembre 2025, apdos. 2 a 4"
            ),
            scope_statement=_SCOPE_890C,
            declaration=_PCE_RFS_DECLARATION,
            table_status=ProfileTableStatus.POPULATED,
            max_level=Level.BAJO,
        ),
    }
    profiles[PROFILE_OTHER_SPECIFIC] = ComplianceProfile(
        key=PROFILE_OTHER_SPECIFIC,
        name="Another specific compliance profile",
        citation=CITATION_SPECIFIC_PROFILE,
        scope_statement=(
            "A specific compliance profile published by the CCN other than "
            "CCN-STIC 890A and CCN-STIC 890C."
        ),
        declaration=None,
        table_status=ProfileTableStatus.NOT_TRANSCRIBED,
    )
    for key, name in _SUPERSEDED_883:
        profiles[key] = ComplianceProfile(
            key=key,
            name=name,
            citation=f"{name.split(',')[0]}, edición mayo 2020",
            scope_statement=(
                "Published against Real Decreto 3/2010, the repealed ENS."
            ),
            declaration=None,
            table_status=ProfileTableStatus.SUPERSEDED_BY_VERSION,
            superseded_note=_883_SUPERSEDED_NOTE,
        )
    return profiles


#: The profile registry: the one place a profile is declared.
PROFILES: dict[str, ComplianceProfile] = _published_profiles()

#: Tokens a declaration may carry that are not a profile key. The first two are
#: the entity-shaped names this product offered before the guides were read:
#: "entidades_locales" described CCN-STIC 890A's scope, and
#: "ayuntamientos_menos_20000" described the population band of CCN-STIC 883B,
#: which is superseded. Both are mapped to the document they meant, so a
#: declaration already written by hand keeps resolving to something true.
PROFILE_ALIASES: dict[str, str] = {
    "entidades_locales": PROFILE_CCN_STIC_890A,
    "ayuntamientos_menos_20000": "ccn_stic_883b",
    "890a": PROFILE_CCN_STIC_890A,
    "890c": PROFILE_CCN_STIC_890C,
}


def resolve_profile(value: object) -> Optional[ComplianceProfile]:
    """The published profile a declared token names, or ``None``."""
    token = _normalize_profile(value)
    return PROFILES.get(PROFILE_ALIASES.get(token, token))


#: Profiles the product recognises by name, mapped to the key of their
#: applicability table or ``None`` when they hold none. Derived from
#: :data:`PROFILES` so the two can never disagree.
KNOWN_PROFILES: dict[str, Optional[str]] = {
    key: (key if profile.table_populated else None)
    for key, profile in PROFILES.items()
}

_PROFILE_TABLES: dict[str, dict[str, _Row]] = {PROFILE_GENERAL: _ANEXO_II_GENERAL}


def _common_core() -> tuple[str, ...]:
    """Measure ids required in the LOWEST column, hence in every category.

    The conservative answer for an undeclared scope: a measure required from
    Bajo upward is required whether the system turns out BÁSICA, MEDIA or ALTA,
    so it can be evaluated without inferring a categorisation. Derived from the
    table rather than listed, so it cannot drift from it.
    """
    return tuple(
        sorted(
            measure_id
            for measure_id, row in _ANEXO_II_GENERAL.items()
            if row.column("basica").applies
        )
    )


#: The measures an undeclared workspace is still evaluated against.
COMMON_CORE_MEASURE_IDS: tuple[str, ...] = _common_core()


def anexo_ii_measure_ids() -> tuple[str, ...]:
    """Every measure id of Anexo II, in normative order."""
    return tuple(_ANEXO_II_GENERAL.keys())


def measure_name(measure_id: str) -> str:
    """The literal Anexo II name of one measure, or an empty string."""
    row = _ANEXO_II_GENERAL.get(measure_id)
    return row.name if row else ""


def measure_selector(measure_id: str) -> str:
    """Whether a measure is selected by category or by dimension level."""
    row = _ANEXO_II_GENERAL.get(measure_id)
    return row.selector if row else ""


def measure_dimensions(measure_id: str) -> tuple[str, ...]:
    """The dimensions that govern a dimension-selected measure."""
    row = _ANEXO_II_GENERAL.get(measure_id)
    return tuple(row.dimensions) if row else ()


def measure_apartado(measure_id: str) -> str:
    """The Anexo II apartado a measure lives in, for the per-row citation."""
    row = _ANEXO_II_GENERAL.get(measure_id)
    return row.apartado if row else ""


def lowest_required_label(measure_id: str) -> str:
    """The lowest column at which a measure is exigible, as the norm labels it.

    A category ("BÁSICA" / "MEDIA" / "ALTA") for a category-selected measure and
    a dimension level ("BAJO" / "MEDIO" / "ALTO") for a dimension-selected one.
    This is the derivation that replaced the hand-written label the measure
    catalog used to carry, four values of which were wrong: ``op.acc.5``,
    ``op.acc.6``, ``mp.com.2`` and ``mp.com.3`` were labelled MEDIA and are
    exigible from the lowest level, which produced a false non-conformity for a
    BÁSICA system and a wrong label in the paid deliverable for every system.
    """
    row = _ANEXO_II_GENERAL.get(measure_id)
    if row is None:
        return ""
    labels = _LEVEL_LABEL if row.selector == SELECTOR_DIMENSION else _CATEGORY_LABEL
    for column in ("basica", "media", "alta"):
        if row.column(column).applies:
            return labels[column]
    return ""


def refuerzos_declared(measure_id: str) -> tuple[str, ...]:
    """Every refuerzo Anexo II describes for one measure."""
    row = _ANEXO_II_GENERAL.get(measure_id)
    return tuple(row.refuerzos_declared) if row else ()


def refuerzos_never_required(measure_id: str) -> tuple[str, ...]:
    """The measure's refuerzos that no category or level requires.

    The optional refuerzos of Anexo II apartado 6.e. They apply only when the
    client's own risk analysis recommends them, so they cannot sustain a
    non-conformity, which is what :func:`refuerzo_is_required` enforces.
    """
    row = _ANEXO_II_GENERAL.get(measure_id)
    return tuple(row.refuerzos_never_required) if row else ()


def refuerzo_is_required(
    measure_id: str, refuerzo: str, applicability: MeasureApplicability
) -> bool:
    """Whether ONE refuerzo is required for ONE measure under a resolved scope.

    The only way to ask. A refuerzo that no column requires answers ``False``
    everywhere, so no consumer can turn one of the 41 optional refuerzos into a
    non-conformity. A refuerzo in a choice group answers ``False`` too: the group
    is satisfied by any one member (apartado 5.e), so singling one out as
    required would be a finding the norm does not support. Read the group from
    :attr:`MeasureApplicability.refuerzos_choice` instead.
    """
    if not applicability.is_required:
        return False
    if applicability.measure_id != measure_id:
        return False
    token = str(refuerzo or "").strip().upper()
    return token in {r.upper() for r in applicability.refuerzos_required}


def _unresolved(
    measure_id: str,
    row: Optional[_Row],
    state: ApplicabilityState,
    reason: str,
    citation: str,
) -> MeasureApplicability:
    return MeasureApplicability(
        measure_id=measure_id,
        state=state,
        selector=row.selector if row else "",
        dimensions=tuple(row.dimensions) if row else (),
        column=None,
        column_label="",
        reason=reason,
        citation=citation,
        name=row.name if row else "",
        apartado=row.apartado if row else "",
        refuerzos_never_required=tuple(row.refuerzos_never_required) if row else (),
    )


def _resolve_declared_measure(
    measure_id: str,
    row: _Row,
    scope: EnsScope,
    category: Category,
) -> MeasureApplicability:
    """Resolve one measure under a fully declared, supported scope."""
    if measure_id in scope.compensatory_measures:
        return MeasureApplicability(
            measure_id=measure_id,
            state=ApplicabilityState.COMPENSATORY_MEASURE,
            selector=row.selector,
            dimensions=tuple(row.dimensions),
            column=None,
            column_label="",
            reason=(
                "The client declares this measure satisfied by a compensatory "
                "measure in its Declaración de Aplicabilidad."
            ),
            citation=CITATION_COMPENSATORY,
            name=row.name,
            apartado=row.apartado,
            refuerzos_never_required=tuple(row.refuerzos_never_required),
        )

    if row.selector == SELECTOR_DIMENSION:
        governing = [Dimension(initial) for initial in row.dimensions]
        affected = [
            dimension
            for dimension in governing
            if scope.level(dimension) is not Level.NOT_AFFECTED
        ]
        if not affected:
            names = ", ".join(DIMENSION_NAMES[d] for d in governing)
            return MeasureApplicability(
                measure_id=measure_id,
                state=ApplicabilityState.NOT_APPLICABLE_BY_DIMENSION,
                selector=row.selector,
                dimensions=tuple(row.dimensions),
                column=None,
                column_label="",
                reason=(
                    "Not exigible: this measure is selected by the level of "
                    f"{names}, and the declared scope records that dimension as "
                    "not affected, so it is not assigned to any level."
                ),
                citation=CITATION_DIMENSION_NA,
                name=row.name,
                apartado=row.apartado,
                refuerzos_never_required=tuple(row.refuerzos_never_required),
            )
        # Several dimensions may govern one measure; the column is the highest
        # level among the affected ones, the same maximum rule Anexo I applies.
        column = _COLUMN_BY_LEVEL[
            max((scope.level(d) for d in affected), key=lambda lv: _LEVEL_RANK[lv])
        ]
        column_label = _LEVEL_LABEL[column]
    else:
        column = _COLUMN_BY_CATEGORY[category]
        column_label = _CATEGORY_LABEL[column]

    cell = row.column(column)
    if not cell.applies:
        return MeasureApplicability(
            measure_id=measure_id,
            state=ApplicabilityState.NOT_APPLICABLE_BY_TABLE,
            selector=row.selector,
            dimensions=tuple(row.dimensions),
            column=column,
            column_label=column_label,
            reason=(
                f"Not exigible: Anexo II records this measure as n.a. at "
                f"{column_label}, which means it does not apply for compliance "
                "purposes, without prejudice to its technical value."
            ),
            citation=CITATION_TABLE_NA,
            name=row.name,
            apartado=row.apartado,
            refuerzos_never_required=tuple(row.refuerzos_never_required),
        )

    return MeasureApplicability(
        measure_id=measure_id,
        state=ApplicabilityState.REQUIRED,
        selector=row.selector,
        dimensions=tuple(row.dimensions),
        column=column,
        column_label=column_label,
        reason=f"Exigible at {column_label}.",
        citation=CITATION_REQUIRED,
        name=row.name,
        apartado=row.apartado,
        refuerzos_required=tuple(cell.refuerzos_required),
        refuerzos_choice=tuple(cell.refuerzos_choice),
        refuerzos_never_required=tuple(row.refuerzos_never_required),
    )


def _resolve_profile_measure(
    measure_id: str,
    row: _Row,
    scope: EnsScope,
    profile: ComplianceProfile,
) -> MeasureApplicability:
    """Resolve one measure under a specific compliance profile's own table.

    The profile's verdict replaces the general table's column selection: the
    profile states which column's requirements apply, and that is not always
    the column the declared category or level would read. It is the whole point
    of a profile, and it runs in both directions: 35 measures the general table
    requires at BÁSICA are recorded as not applicable to the profile, and
    ``mp.eq.2`` is recorded as applicable at MEDIO where Anexo II makes it
    ``n.a.`` at BÁSICA.

    Two rules of the norm still outrank the profile's table, because the
    profile cannot assign a requirement to something the client did not value:

    * a declared compensatory measure (art. 28.3), as everywhere else;
    * a measure the profile REQUIRES whose governing dimensions are all
      recorded as not affected. Anexo II apartado 5.a assigns such a measure no
      level, so there is no level for the profile to require it at. This is
      checked only after the profile's own verdict, so a measure the profile
      already records as not applicable keeps the profile's reason rather than
      being re-explained by a dimension that was never the point.
    """
    if measure_id in scope.compensatory_measures:
        return MeasureApplicability(
            measure_id=measure_id,
            state=ApplicabilityState.COMPENSATORY_MEASURE,
            selector=row.selector,
            dimensions=tuple(row.dimensions),
            column=None,
            column_label="",
            reason=(
                "The client declares this measure satisfied by a compensatory "
                "measure in its Declaración de Aplicabilidad."
            ),
            citation=CITATION_COMPENSATORY,
            name=row.name,
            apartado=row.apartado,
            refuerzos_never_required=tuple(row.refuerzos_never_required),
        )

    declaration = profile.declaration or {}
    entry = declaration.get(measure_id)
    if entry is None:
        return _unresolved(
            measure_id,
            row,
            ApplicabilityState.NOT_RESOLVABLE,
            (
                "This measure does not appear in the declared profile's own "
                "Declaración de Aplicabilidad."
            ),
            profile.citation or CITATION_SPECIFIC_PROFILE,
        )

    labels = _LEVEL_LABEL if row.selector == SELECTOR_DIMENSION else _CATEGORY_LABEL
    if entry.applied_column is None:
        criteria = ""
        if entry.criteria_apartado:
            criteria = (
                " The profile records specific application criteria for it in "
                f"its apartado {entry.criteria_apartado}, which can oblige it "
                "for particular services; this assessment does not read those "
                "criteria and does not decide whether they bind this system."
            )
        return MeasureApplicability(
            measure_id=measure_id,
            state=ApplicabilityState.NOT_APPLICABLE_BY_TABLE,
            selector=row.selector,
            dimensions=tuple(row.dimensions),
            column=None,
            column_label="",
            reason=(
                "Not exigible: the declared compliance profile records this "
                "measure as not applicable to it, without prejudice to its "
                f"technical value.{criteria}"
            ),
            citation=profile.citation or CITATION_SPECIFIC_PROFILE,
            name=row.name,
            apartado=row.apartado,
            refuerzos_never_required=tuple(row.refuerzos_never_required),
        )

    column = entry.applied_column
    if row.selector == SELECTOR_DIMENSION:
        governing = [Dimension(initial) for initial in row.dimensions]
        if all(
            scope.level(dimension) is Level.NOT_AFFECTED for dimension in governing
        ):
            names = ", ".join(DIMENSION_NAMES[d] for d in governing)
            return MeasureApplicability(
                measure_id=measure_id,
                state=ApplicabilityState.NOT_APPLICABLE_BY_DIMENSION,
                selector=row.selector,
                dimensions=tuple(row.dimensions),
                column=None,
                column_label="",
                reason=(
                    "Not exigible: this measure is selected by the level of "
                    f"{names}, and the declared scope records that dimension as "
                    "not affected, so it is not assigned to any level, and the "
                    "declared compliance profile cannot require it of one."
                ),
                citation=CITATION_DIMENSION_NA,
                name=row.name,
                apartado=row.apartado,
                refuerzos_never_required=tuple(row.refuerzos_never_required),
            )

    cell = row.column(column)
    criteria = ""
    if entry.criteria_apartado:
        criteria = (
            " The profile states specific application criteria for it in its "
            f"apartado {entry.criteria_apartado}, so what satisfies it is "
            "narrower or wider than the Anexo II text alone."
        )
    return MeasureApplicability(
        measure_id=measure_id,
        state=ApplicabilityState.REQUIRED,
        selector=row.selector,
        dimensions=tuple(row.dimensions),
        column=column,
        column_label=labels[column],
        reason=(
            f"Exigible under the declared compliance profile at "
            f"{labels[column]}.{criteria}"
        ),
        citation=profile.citation or CITATION_SPECIFIC_PROFILE,
        name=row.name,
        apartado=row.apartado,
        refuerzos_required=tuple(cell.refuerzos_required),
        refuerzos_choice=tuple(cell.refuerzos_choice),
        refuerzos_never_required=tuple(row.refuerzos_never_required),
    )


def _resolve_undeclared() -> EnsScopeResolution:
    """Resolve the common core, for a workspace that declared no scope.

    Never infers a category and never leaves the answer empty: the measures
    required from the lowest column upward are required at every category, so
    they are evaluated, and the rest are reported as depending on the client's
    categorisation.
    """
    core = set(COMMON_CORE_MEASURE_IDS)
    measures: dict[str, MeasureApplicability] = {}
    for measure_id, row in _ANEXO_II_GENERAL.items():
        if measure_id in core:
            column = "basica"
            labels = (
                _LEVEL_LABEL if row.selector == SELECTOR_DIMENSION else _CATEGORY_LABEL
            )
            cell = row.column(column)
            measures[measure_id] = MeasureApplicability(
                measure_id=measure_id,
                state=ApplicabilityState.REQUIRED,
                selector=row.selector,
                dimensions=tuple(row.dimensions),
                column=column,
                column_label=labels[column],
                reason=(
                    "Exigible at every category: this measure is required from "
                    f"{labels[column]} upward, so it holds whatever the system's "
                    "declared categorisation turns out to be."
                ),
                citation=CITATION_REQUIRED,
                name=row.name,
                apartado=row.apartado,
                refuerzos_required=tuple(cell.refuerzos_required),
                refuerzos_choice=tuple(cell.refuerzos_choice),
                refuerzos_never_required=tuple(row.refuerzos_never_required),
            )
            continue
        measures[measure_id] = _unresolved(
            measure_id,
            row,
            ApplicabilityState.EXIGIBILITY_UNDECLARED,
            (
                "Exigibility depends on the system's declared categorisation, "
                "which this assessment did not receive."
            ),
            CITATION_TABLE_NA,
        )
    return EnsScopeResolution(
        declared=False,
        ens_version=ENS_VERSION,
        version_supported=True,
        profile=PROFILE_GENERAL,
        profile_table_populated=True,
        category=None,
        dimension_levels={},
        measures=measures,
        note=(
            "No ENS scope was declared for this system, so conformance is "
            f"stated against the {len(core)} measures Anexo II requires from the "
            "lowest level upward, which hold at every category. The remaining "
            f"{len(_ANEXO_II_GENERAL) - len(core)} depend on the system's "
            "category and on which security dimensions are affected, and are "
            "reported as pending that declaration rather than assumed."
        ),
        profile_name=PROFILES[PROFILE_GENERAL].name,
        profile_citation=PROFILES[PROFILE_GENERAL].citation,
        profile_scope_statement=PROFILES[PROFILE_GENERAL].scope_statement,
    )


def _profile_fields(scope: EnsScope) -> dict[str, object]:
    """The profile half of a resolution's header, for any outcome."""
    profile = scope.profile_definition
    return {
        "profile_name": profile.name if profile else "",
        "profile_citation": profile.citation if profile else "",
        "profile_scope_statement": profile.scope_statement if profile else "",
    }


def _resolve_all_unresolvable(
    scope: EnsScope,
    reason: str,
    note: str,
    *,
    state: ApplicabilityState = ApplicabilityState.NOT_RESOLVABLE,
    citation: str = CITATION_TABLE_NA,
    profile_applies: bool = True,
    out_of_scope_reason: str = "",
) -> EnsScopeResolution:
    """Every measure carries no verdict, because the scope cannot be honoured."""
    table = _PROFILE_TABLES.get(PROFILE_GENERAL, {})
    measures = {
        measure_id: _unresolved(measure_id, row, state, reason, citation)
        for measure_id, row in table.items()
    }
    return EnsScopeResolution(
        declared=True,
        ens_version=str(scope.ens_version or ""),
        version_supported=scope.version_supported,
        profile=_normalize_profile(scope.profile),
        profile_table_populated=scope.profile_table is not None,
        category=scope.category,
        dimension_levels=dict(scope.dimension_levels),
        measures=measures,
        note=note,
        profile_applies=profile_applies,
        profile_out_of_scope_reason=out_of_scope_reason,
        **_profile_fields(scope),  # type: ignore[arg-type]
    )


def resolve_ens_applicability(scope: Optional[EnsScope]) -> EnsScopeResolution:
    """Resolve every Anexo II measure's applicability under one declared scope.

    Args:
        scope: The system's declared scope, or ``None`` when the workspace
            carries no declaration. ``None`` resolves the common core (see
            :func:`_resolve_undeclared`) rather than declining or assuming a
            category.

    Returns:
        The resolution for all 73 measures, plus the scope-header data every
        surface prints.
    """
    if scope is None:
        return _resolve_undeclared()

    if not scope.version_supported:
        return _resolve_all_unresolvable(
            scope,
            (
                "The declared normative version is not the one this "
                f"assessment's applicability table transcribes ({ENS_VERSION})."
            ),
            (
                f"The system declares ENS version {scope.ens_version!r}, and this "
                f"assessment's applicability table transcribes {ENS_VERSION}. The "
                "measure sets differ between versions and one identifier changed "
                "meaning, so no measure is reported as exigible or as not "
                "applicable rather than mapped across versions."
            ),
        )

    profile = scope.profile_definition
    if profile is None:
        return _resolve_all_unresolvable(
            scope,
            (
                "The declared compliance profile is not one this assessment "
                "recognises."
            ),
            (
                f"The system declares the {_normalize_profile(scope.profile)!r} "
                "compliance profile, which is not among the profiles this "
                "assessment recognises: "
                f"{', '.join(sorted(PROFILES))}. No measure is reported as "
                "exigible or as not applicable under the general profile's "
                "table in its place."
            ),
        )

    if profile.table_status is ProfileTableStatus.SUPERSEDED_BY_VERSION:
        return _resolve_all_unresolvable(
            scope,
            (
                "The declared compliance profile was published against an "
                "earlier version of the ENS."
            ),
            f"{profile.name}. {profile.superseded_note}",
        )

    if not profile.table_populated:
        return _resolve_all_unresolvable(
            scope,
            (
                "The declared compliance profile's applicability table is not "
                "available to this assessment."
            ),
            (
                f"The system declares the {_normalize_profile(scope.profile)!r} "
                "compliance profile. A specific compliance profile "
                f"({CITATION_SPECIFIC_PROFILE}) carries its own applicability "
                "table, which this assessment does not hold, so no measure is "
                "reported as exigible or as not applicable under the general "
                "profile's table instead."
            ),
        )

    category = scope.category
    if category is None:
        return _resolve_all_unresolvable(
            scope,
            (
                "The declared scope records no dimension as affected, so no "
                "system category can be derived from it."
            ),
            (
                "The declared scope records every security dimension as not "
                "affected, so no category can be derived (Anexo I, apdo. 4.1) "
                "and no measure is reported as exigible or as not applicable."
            ),
        )

    out_of_scope = profile.out_of_scope_reason(scope)
    if out_of_scope:
        return _resolve_all_unresolvable(
            scope,
            out_of_scope,
            (
                f"{out_of_scope} No measure is therefore reported as "
                "exigible or as not applicable under it. The general profile "
                "of Anexo II is what applies to a system valued above this "
                "profile's ceiling: declaring it scopes the assessment "
                f"against the {len(_ANEXO_II_GENERAL)} measures of the annex. "
                f"{PROFILE_IMPROVEMENT_COMMITMENT_NOTE}"
            ),
            state=ApplicabilityState.PROFILE_OUT_OF_SCOPE,
            citation=profile.citation or CITATION_SPECIFIC_PROFILE,
            profile_applies=False,
            out_of_scope_reason=out_of_scope,
        )

    if profile.declaration is None:
        measures = {
            measure_id: _resolve_declared_measure(measure_id, row, scope, category)
            for measure_id, row in _ANEXO_II_GENERAL.items()
        }
    else:
        measures = {
            measure_id: _resolve_profile_measure(measure_id, row, scope, profile)
            for measure_id, row in _ANEXO_II_GENERAL.items()
        }
    return EnsScopeResolution(
        declared=True,
        ens_version=str(scope.ens_version or ENS_VERSION),
        version_supported=True,
        profile=_normalize_profile(scope.profile),
        profile_table_populated=True,
        category=category,
        dimension_levels=dict(scope.dimension_levels),
        measures=measures,
        **_profile_fields(scope),  # type: ignore[arg-type]
    )


def parse_level(value: object) -> Level:
    """Read a declared dimension level, tolerating the forms a client writes.

    Anything unrecognised, including an absent value, reads as not affected:
    that withholds the measures the dimension governs instead of inventing a
    level for them, which is the conservative direction.
    """
    text = str(value or "").strip().lower()
    if text in {"bajo", "baja", "low", "b"}:
        return Level.BAJO
    if text in {"medio", "media", "medium", "m"}:
        return Level.MEDIO
    if text in {"alto", "alta", "high", "a"}:
        return Level.ALTO
    return Level.NOT_AFFECTED


def parse_ens_scope(declaration: object) -> Optional[EnsScope]:
    """Build an :class:`EnsScope` from a declared mapping, or ``None``.

    The mapping is the persisted workspace block (see
    ``adscan_core/reporting/compliance_scope_declaration.py``), shaped::

        {
          "ens_version": "RD 311/2022",
          "profile": "general",
          "dimensions": {"C": "medio", "I": "medio", "T": "bajo",
                         "A": "medio", "D": "bajo"},
          "compensatory_measures": ["op.cont.3"],
          "system": "<system or subsystem the declaration covers>"
        }

    Returns ``None`` for anything that is not a usable declaration, so the
    caller resolves the common core instead of a half-read scope. A declaration
    carrying a profile or a version this build cannot honour is NOT rejected
    here: it is returned so :func:`resolve_ens_applicability` can state WHY no
    verdict follows, which a silent ``None`` would hide.
    """
    if not isinstance(declaration, Mapping):
        return None
    raw_dimensions = declaration.get("dimensions")
    levels: dict[Dimension, Level] = {}
    if isinstance(raw_dimensions, Mapping):
        for key, value in raw_dimensions.items():
            initial = str(key or "").strip().upper()[:1]
            if initial not in {d.value for d in Dimension}:
                continue
            level = parse_level(value)
            if level is not Level.NOT_AFFECTED:
                levels[Dimension(initial)] = level
    profile = _normalize_profile(declaration.get("profile"))
    version = str(declaration.get("ens_version") or ENS_VERSION).strip() or ENS_VERSION
    known = set(anexo_ii_measure_ids())
    compensatory = frozenset(
        str(item).strip()
        for item in _as_iterable(declaration.get("compensatory_measures"))
        if str(item).strip() in known
    )
    system = declaration.get("system")
    scope = EnsScope(
        dimension_levels=levels,
        profile=profile,
        ens_version=version,
        compensatory_measures=compensatory,
        system_label=str(system).strip() if system else None,
    )
    # A declaration with nothing usable in it is not a declaration. One that
    # names an unsupported profile or version IS, so the resolver can say so.
    if not levels and scope.version_supported and scope.profile_table is not None:
        return None
    return scope


def _as_iterable(value: object) -> Iterable[object]:
    if isinstance(value, (list, tuple, set, frozenset)):
        return value
    return ()


__all__ = (
    "CITATION_CATEGORY_DERIVATION",
    "CITATION_COMPENSATORY",
    "CITATION_DIMENSION_NA",
    "CITATION_REQUIRED",
    "CITATION_SPECIFIC_PROFILE",
    "CITATION_TABLE_NA",
    "COMMON_CORE_MEASURE_IDS",
    "DIMENSION_NAMES",
    "DIMENSION_ORDER",
    "ENS_VERSION",
    "ENS_VERSION_LONG",
    "KNOWN_PROFILES",
    "NOT_APPLICABLE_STATES",
    "PROFILES",
    "PROFILE_ALIASES",
    "PROFILE_CCN_STIC_890A",
    "PROFILE_CCN_STIC_890C",
    "PROFILE_GENERAL",
    "PROFILE_OTHER_SPECIFIC",
    "PROFILE_IMPROVEMENT_COMMITMENT_NOTE",
    "SELECTOR_CATEGORY",
    "SELECTOR_DIMENSION",
    "UNRESOLVED_STATES",
    "ApplicabilityState",
    "Category",
    "ComplianceProfile",
    "Dimension",
    "EnsScope",
    "EnsScopeResolution",
    "Level",
    "MeasureApplicability",
    "ProfileTableStatus",
    "anexo_ii_measure_ids",
    "lowest_required_label",
    "measure_apartado",
    "measure_dimensions",
    "measure_name",
    "measure_selector",
    "parse_ens_scope",
    "parse_level",
    "refuerzo_is_required",
    "refuerzos_declared",
    "refuerzos_never_required",
    "resolve_ens_applicability",
    "resolve_profile",
)
