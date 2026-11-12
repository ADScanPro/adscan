"""Which compliance frameworks ADscan maps: the one registry every surface reads.

Why this module exists
----------------------
The framework list used to be declared in about ten places: the CLI menu and
valid-set (``adscan_internal/cli/common.py``), the scan-phase choices
(``scan_phases.REPORT_FRAMEWORK_CHOICES``), the deliverable option model
(``adscan_core/report_options.py``), the report engine's canonical keys
(``compliance_artifact.CANONICAL_FRAMEWORK_KEYS``), two copies in the web
backend, the frontend selector, and the help text of three commands. Each copy
was held in step by a contract test against another copy, which catches a
divergence but still makes adding a framework an edit in ten files, and the
help strings were not covered at all (``generate_report`` documented three of
the six).

Now the list, its order, its names and its classification are declared here
once and every surface DERIVES from it:

* the CLI ``--frameworks`` parsing, validation, help text and interactive menu;
* the scan-phase config choices and the deliverable option model;
* the report engine's canonical key set (the engine keeps its own per-framework
  definitions under ``pro/``, and a contract test asserts the two key sets are
  equal, so a framework added here without a definition fails loudly, and the
  reverse);
* the web backend's valid set and display names (the backend ships
  ``adscan_core``);
* the frontend selector, through a generated TypeScript module written by
  ``scripts/sync_technique_count.py`` and locked by a drift test;
* the public site, through ``adscan-site/data/framework_registry.json``,
  written by the same script.

What lives where
----------------
The edition of each text (authority, instrument, version, the date it was read)
is ``adscan_core.reporting.framework_provenance``, and this module reads the
versioned label from there rather than restating it, so no surface can print a
version the provenance record does not carry. This module adds what provenance
does not answer: the order, the class of text (a regulation, a standard or a
benchmark), its geographic scope, the descriptive names a reader sees in both
languages, and how a selector presents it.

The module imports only the standard library and the provenance record, so the
host launcher, the LITE container, the web backend and the sync script can all
load it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Literal

from adscan_core.reporting.framework_provenance import (
    framework_display_name,
    framework_version,
    provenance_for,
)

FrameworkKind = Literal["regulation", "standard", "benchmark"]
FrameworkRegion = Literal["ES", "EU", "global"]

#: Bump when the exported shape (:func:`export_framework_registry`) changes in
#: a way a consumer must notice. Additive fields do not need a bump.
FRAMEWORK_REGISTRY_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class ComplianceFramework:
    """One compliance framework ADscan can map an assessment against.

    Attributes:
        key: Canonical key, the value ``--frameworks`` and the web accept.
        order: Position in every list, starting at 1.
        aliases: Other spellings accepted on input, resolved to ``key``. Empty
            today: the CLI and the web accept the canonical key only, and a new
            alias is a decision both must honour, so it is added here or nowhere.
        short_name: The short form a sentence or list uses ("ENS", "PCI DSS",
            "CIS Benchmark"). Exported as ``short_label``.
        kind: ``regulation`` (law), ``standard`` (a published standard an
            organisation certifies or attests against) or ``benchmark`` (a
            technical hardening baseline, never a legal obligation).
        region: Where the text applies: ``ES``, ``EU`` or ``global``.
        default: Whether the framework is selected when the operator selects
            nothing. False for all of them: a compliance section asserts a
            conformance verdict, so the regime is a scoping input the client
            supplies and ADscan never infers.
        recommended: Whether selectors mark it as the suggested choice.
        tagline_en: One-line context shown beside the label in a selector.
        tagline_es: The same, in Spanish.
        display_name_en_template: The full descriptive name, in English. A
            ``{edition}`` placeholder is filled with the provenance record's
            version suffix, so the version is never typed twice.
        display_name_es_template: The same, in Spanish.
        selector_label_override: The label a narrow selector shows when it is
            deliberately shorter than the provenance label. Empty means the
            provenance label. An override may change wording, never state a
            version (locked by ``tests/unit/core/test_framework_provenance.py``).
    """

    key: str
    order: int
    short_name: str
    kind: FrameworkKind
    region: FrameworkRegion
    tagline_en: str
    tagline_es: str
    display_name_en_template: str
    display_name_es_template: str
    aliases: tuple[str, ...] = ()
    default: bool = False
    recommended: bool = False
    selector_label_override: str = ""

    @property
    def label(self) -> str:
        """The versioned name every report section uses, from provenance."""
        return framework_display_name(self.key, default=self.short_name)

    @property
    def version(self) -> str:
        """The version token in the publisher's own scheme, from provenance."""
        return framework_version(self.key)

    @property
    def _edition_suffix(self) -> str:
        record = provenance_for(self.key)
        return record.name_suffix if record else ""

    @property
    def display_name_en(self) -> str:
        """The full descriptive name in English."""
        return self.display_name_en_template.format(edition=self._edition_suffix)

    @property
    def display_name_es(self) -> str:
        """The full descriptive name in Spanish."""
        return self.display_name_es_template.format(edition=self._edition_suffix)

    @property
    def selector_label(self) -> str:
        """The label a selector shows next to its checkbox."""
        return self.selector_label_override or self.label

    @property
    def selector_description_en(self) -> str:
        """The one line a selector shows under the label."""
        if self.recommended:
            return f"{self.tagline_en} (recommended)"
        return self.tagline_en

    @property
    def menu_label(self) -> str:
        """The entry the interactive CLI menu shows (label plus context)."""
        return f"{self.selector_label} · {self.selector_description_en}"


#: Every framework, in the order every surface lists them.
COMPLIANCE_FRAMEWORKS: tuple[ComplianceFramework, ...] = (
    ComplianceFramework(
        key="ens",
        order=1,
        short_name="ENS",
        kind="regulation",
        region="ES",
        # No category in any name: the ENS category belongs to the SYSTEM (RD
        # 311/2022 art. 40.1) and is derived per workspace from the client's
        # declared dimension levels, so a framework name must not assert one.
        tagline_en="Spain / CCN-CERT",
        tagline_es="España / CCN-CERT",
        display_name_en_template="Esquema Nacional de Seguridad (Real Decreto 311/2022)",
        display_name_es_template="Esquema Nacional de Seguridad (Real Decreto 311/2022)",
        recommended=True,
    ),
    ComplianceFramework(
        key="nis2",
        order=2,
        short_name="NIS2",
        kind="regulation",
        region="EU",
        tagline_en="EU 2022/2555, critical infrastructure",
        tagline_es="UE 2022/2555, infraestructuras críticas",
        display_name_en_template=(
            "Network and Information Security Directive (EU) 2022/2555"
        ),
        display_name_es_template=(
            "Directiva (UE) 2022/2555 relativa a la seguridad de las redes y "
            "sistemas de información"
        ),
    ),
    ComplianceFramework(
        key="iso27001",
        order=3,
        short_name="ISO 27001",
        kind="standard",
        region="global",
        tagline_en="International ISMS standard",
        tagline_es="Norma internacional de SGSI",
        display_name_en_template=(
            "ISO/IEC 27001{edition}, Information security management systems"
        ),
        display_name_es_template=(
            "ISO/IEC 27001{edition}, sistemas de gestión de la seguridad de la "
            "información"
        ),
    ),
    ComplianceFramework(
        key="dora",
        order=4,
        short_name="DORA",
        kind="regulation",
        region="EU",
        tagline_en="EU 2022/2554, financial sector",
        tagline_es="UE 2022/2554, sector financiero",
        display_name_en_template="Digital Operational Resilience Act (EU) 2022/2554",
        display_name_es_template=(
            "Reglamento (UE) 2022/2554 sobre la resiliencia operativa digital "
            "del sector financiero"
        ),
        # The selector column is narrow: the acronym, with the act number in
        # the tagline beside it.
        selector_label_override="DORA",
    ),
    ComplianceFramework(
        key="pci_dss",
        order=5,
        short_name="PCI DSS",
        kind="standard",
        region="global",
        tagline_en="Payment Card Industry",
        tagline_es="Industria de tarjetas de pago",
        display_name_en_template="Payment Card Industry Data Security Standard{edition}",
        display_name_es_template=(
            "Norma de seguridad de datos de la industria de tarjetas de pago "
            "(PCI DSS{edition})"
        ),
    ),
    ComplianceFramework(
        key="cis",
        order=6,
        short_name="CIS Benchmark",
        kind="benchmark",
        region="global",
        # A hardening baseline, NOT a regulation, and every name says so, so an
        # operator never mistakes it for a legal obligation.
        tagline_en="Technical hardening baseline, not a regulation",
        tagline_es="Guía de bastionado técnico, no es una normativa",
        display_name_en_template=(
            "CIS Microsoft Windows Server Benchmark: technical hardening, not a "
            "regulation"
        ),
        display_name_es_template=(
            "CIS Microsoft Windows Server Benchmark, guía de bastionado técnico "
            "que no es una normativa"
        ),
        selector_label_override="CIS Windows Server",
    ),
)

_BY_KEY: dict[str, ComplianceFramework] = {fw.key: fw for fw in COMPLIANCE_FRAMEWORKS}

#: Canonical keys, in registry order.
FRAMEWORK_KEYS: tuple[str, ...] = tuple(fw.key for fw in COMPLIANCE_FRAMEWORKS)

#: What a report maps when the operator chose nothing: nothing.
DEFAULT_FRAMEWORK_KEYS: tuple[str, ...] = tuple(
    fw.key for fw in COMPLIANCE_FRAMEWORKS if fw.default
)

_TOKEN_TO_KEY: dict[str, str] = {
    token.lower(): fw.key
    for fw in COMPLIANCE_FRAMEWORKS
    for token in (fw.key, *fw.aliases)
}


def get_framework(key: str) -> ComplianceFramework | None:
    """Return the registry entry for a canonical key, or ``None``."""
    return _BY_KEY.get((key or "").strip().lower())


def resolve_framework_key(token: str) -> str | None:
    """Resolve a user-supplied token (key or alias, any case) to its key."""
    return _TOKEN_TO_KEY.get((token or "").strip().lower())


def framework_keys_text(separator: str = ", ") -> str:
    """The accepted keys joined for help text ("ens, nis2, ...")."""
    return separator.join(FRAMEWORK_KEYS)


def normalize_framework_tokens(tokens: Iterable[str]) -> tuple[list[str], list[str]]:
    """Resolve tokens to canonical keys, deduplicated in first-seen order.

    Blank tokens are dropped. Returns ``(keys, unknown)``, where ``unknown``
    holds every token that resolved to nothing, as typed (stripped), so each
    caller can word its own error.
    """
    keys: list[str] = []
    unknown: list[str] = []
    for raw in tokens:
        token = (raw or "").strip()
        if not token:
            continue
        key = resolve_framework_key(token)
        if key is None:
            unknown.append(token.lower())
        elif key not in keys:
            keys.append(key)
    return keys, unknown


# ---------------------------------------------------------------------------
# The explicit "no framework applies" answer
# ---------------------------------------------------------------------------
#
# An assessor can audit an organisation that follows none of the frameworks
# above (a company outside the EU, a non-regulated subsidiary). The framework
# is still a scoping decision ADscan never makes for them, so the answer has to
# be stated, and "none" is one of the valid answers. What must never happen is
# a SILENT empty selection, so "nothing chosen" (an empty list) and "none
# applies" (this token) stay two different states on every surface: the CLI
# flag, the interactive picker, the web form, the scan record, the Celery
# command builder and ``technical_report.json``.
#
# "none" is exclusive: it cannot be combined with a framework, because the two
# answers contradict each other.

#: The token every surface accepts for "no compliance framework applies".
NO_FRAMEWORK_KEY = "none"

#: Short label for a selector chip or checkbox.
NO_FRAMEWORK_LABEL = "None"

#: One-line context shown under the label in a selector.
NO_FRAMEWORK_SELECTOR_DESCRIPTION = (
    "This organisation follows none of these frameworks. The report carries "
    "no compliance mapping."
)

#: The interactive picker's option text (``deliver``, the REPL report verb).
NO_FRAMEWORK_MENU_LABEL = (
    "None: this organisation follows none of these frameworks (the report "
    "carries no compliance mapping)"
)

#: What a report says when the assessor decided no framework applies. The
#: deliverable, the terminal and the web compliance view print this sentence.
NO_FRAMEWORK_DECISION_NOTICE = (
    "No compliance framework applies to this organisation, by the assessor's "
    "decision; this report carries no compliance mapping."
)

#: Why "none" cannot be ticked or passed together with a framework.
NO_FRAMEWORK_CONFLICT_REASON = (
    "\"none\" means no compliance framework applies, so it cannot be combined "
    "with a framework. Pick the frameworks, or none on its own."
)


@dataclass(frozen=True)
class FrameworkSelection:
    """One parsed framework answer: frameworks, the explicit "none", or nothing.

    Attributes:
        keys: Canonical framework keys, deduplicated in first-seen order.
        none_declared: The answer named :data:`NO_FRAMEWORK_KEY`.
        unknown: Tokens that resolved to nothing, as typed (lower case).
    """

    keys: tuple[str, ...] = ()
    none_declared: bool = False
    unknown: tuple[str, ...] = ()

    @property
    def conflict(self) -> bool:
        """``none`` was combined with a framework: a contradictory answer."""
        return self.none_declared and bool(self.keys)

    @property
    def provided(self) -> bool:
        """Whether any answer was given at all (frameworks, or "none")."""
        return bool(self.keys) or self.none_declared

    @property
    def valid(self) -> bool:
        """No unknown token and no contradiction."""
        return not self.unknown and not self.conflict

    def as_tokens(self) -> list[str]:
        """The answer as the tokens every surface stores and forwards.

        ``["none"]`` for the explicit no-framework decision, the keys
        otherwise, ``[]`` when nothing was chosen. Call only on a valid
        selection: a conflicting one keeps its keys.
        """
        if self.none_declared and not self.keys:
            return [NO_FRAMEWORK_KEY]
        return list(self.keys)


def is_no_framework_token(token: object) -> bool:
    """Whether a token is the explicit "no framework applies" answer."""
    return str(token or "").strip().lower() == NO_FRAMEWORK_KEY


def parse_framework_selection(tokens: Iterable[str] | None) -> FrameworkSelection:
    """Parse framework tokens, recognising the explicit "none" answer.

    The one parser every surface uses (the CLI flag, the web schemas, the
    scan-end stamp). Blank tokens are dropped; framework tokens resolve through
    :func:`normalize_framework_tokens`. Never raises: the caller words the error
    with :func:`framework_selection_error`.
    """
    none_declared = False
    rest: list[str] = []
    for raw in tokens or ():
        if is_no_framework_token(raw):
            none_declared = True
        else:
            rest.append(raw)
    keys, unknown = normalize_framework_tokens(rest)
    return FrameworkSelection(
        keys=tuple(keys), none_declared=none_declared, unknown=tuple(unknown)
    )


def accepted_framework_values_text(separator: str = ", ") -> str:
    """Every value ``--frameworks`` accepts, the frameworks then "none"."""
    return separator.join((*FRAMEWORK_KEYS, NO_FRAMEWORK_KEY))


def framework_selection_error(
    selection: FrameworkSelection, *, flag: str = "--frameworks"
) -> str | None:
    """The operator-facing error for an invalid selection, or ``None``.

    Args:
        selection: The parsed answer.
        flag: How the field is named where the operator typed it.
    """
    if selection.unknown:
        return (
            f"{flag}: unknown value(s): {', '.join(selection.unknown)}. "
            f"Use one or more of: {framework_keys_text()}, or none when no "
            "framework applies to this organisation."
        )
    if selection.conflict:
        return f"{flag}: {NO_FRAMEWORK_CONFLICT_REASON}"
    return None


def framework_short_names_sentence(and_word: str = "and") -> str:
    """Every framework's short name as a sentence list ("A, B and C")."""
    names = [fw.short_name for fw in COMPLIANCE_FRAMEWORKS]
    if len(names) <= 1:
        return "".join(names)
    return f"{', '.join(names[:-1])} {and_word} {names[-1]}"


def export_framework_registry() -> list[dict[str, object]]:
    """Return the registry as the JSON-serialisable rows a published surface reads.

    Carries only what is safe and meaningful outside the engine: the ADscan
    fields above plus the public facts of the provenance record. The record's
    internal maintenance note (why a change channel could not be established)
    is left out, the same decision ``provenance_statement`` makes for a client.
    """
    rows: list[dict[str, object]] = []
    for fw in COMPLIANCE_FRAMEWORKS:
        record = provenance_for(fw.key)
        rows.append(
            {
                # Field names are the published contract the site reads
                # (adscan-site scripts/derive-figures.mjs, deriveFrameworks).
                # ``id`` and ``key`` carry the same value: ``id`` is what the
                # registry reader keys on, ``key`` joins with
                # compliance_coverage.json ``frameworks[].key``.
                "id": fw.key,
                "key": fw.key,
                "order": fw.order,
                "aliases": list(fw.aliases),
                "short_label": fw.short_name,
                "display_name": fw.label,
                "name_en": fw.display_name_en,
                "name_es": fw.display_name_es,
                "description_en": fw.tagline_en,
                "description_es": fw.tagline_es,
                "kind": fw.kind,
                "scope": fw.region,
                "default": fw.default,
                "recommended": fw.recommended,
                "selector_label": fw.selector_label,
                "version": fw.version,
                "provenance": (
                    {
                        "authority": record.authority,
                        "instrument_scheme": record.instrument_scheme,
                        "instrument_id": record.instrument_id,
                        "instrument_title": record.instrument_title,
                        "citation": record.citation,
                        "edition": record.edition,
                        "edition_date": record.edition_date,
                        "verified_on": record.verified_on,
                        "change_channel_url": record.change_channel_url,
                    }
                    if record
                    else None
                ),
            }
        )
    return rows


__all__ = (
    "COMPLIANCE_FRAMEWORKS",
    "ComplianceFramework",
    "DEFAULT_FRAMEWORK_KEYS",
    "FRAMEWORK_KEYS",
    "FRAMEWORK_REGISTRY_SCHEMA_VERSION",
    "FrameworkKind",
    "FrameworkSelection",
    "NO_FRAMEWORK_CONFLICT_REASON",
    "NO_FRAMEWORK_DECISION_NOTICE",
    "NO_FRAMEWORK_KEY",
    "NO_FRAMEWORK_LABEL",
    "NO_FRAMEWORK_MENU_LABEL",
    "NO_FRAMEWORK_SELECTOR_DESCRIPTION",
    "FrameworkRegion",
    "accepted_framework_values_text",
    "export_framework_registry",
    "framework_selection_error",
    "framework_keys_text",
    "framework_short_names_sentence",
    "get_framework",
    "is_no_framework_token",
    "normalize_framework_tokens",
    "parse_framework_selection",
    "resolve_framework_key",
)
