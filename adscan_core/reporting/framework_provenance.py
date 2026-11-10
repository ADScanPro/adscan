"""Which edition of each compliance framework an assessment was mapped against.

Why this module exists
----------------------
ADscan maps six compliance frameworks and, before this module, recorded nowhere
in a readable field WHICH text it mapped against. The version lived as prose
inside the display label, in six different conventions: DORA carried its
Regulation number, PCI DSS carried a three-part version, CIS kept its version in
a constant of its own, and NIS2 and the ENS carried nothing at all, not even the
directive number or the Real Decreto. Nothing could check any of it, and the web
frontend shipped ``PCI DSS v4.0`` against the engine's ``v4.0.1`` for months.

In an audit-facing deliverable a stale version string costs far more credibility
than its substance warrants: the first thing an auditor does with a mapping is
ask which edition it was built from, and a client who reads a precise version
for one framework and a bare acronym for the next draws a conclusion about the
care behind both.

So the edition is a structured record here, read by every surface that states
it. Six records, one field set, one derivation of the display name.

The field set, and why each field is in it
------------------------------------------
Four facts make a provenance record checkable rather than decorative, and the
record carries each of them separately so a later staleness check can read one
without parsing another out of a sentence:

``authority``
    The body that publishes the text. The address a question about the text goes
    to, and the reason a client's own counsel recognises the citation.
``instrument_scheme`` and ``instrument_id``
    The identifier in the publisher's OWN scheme, kept beside the name of that
    scheme. CELEX for an EU act, the BOE identifier for a Real Decreto, the
    edition for an ISO standard, the version for PCI DSS, the benchmark name and
    version for CIS. Stating the scheme is what makes the id resolvable by
    someone who does not already know which publisher uses which.
``edition``
    The version or date of the text that was transcribed, as the client reads
    it. Distinct from ``verified_on`` below: one is a property of the text, the
    other of our reading of it.
``verified_on``
    The date ADscan last read the text against the publisher. A record with an
    edition and no date says what was read and not when, which is the half that
    goes stale.
``change_channel_url``
    Where to ask whether the text has moved since. A staleness check needs
    somewhere to ask, and the publisher's own channel is the only answer that
    does not depend on a third party's summary.

``text_state`` carries what the publisher's change channel said the last time it
was read: whether the act is amended, consolidated or corrected. It is the
finding the date is a date of.

Two deliberate shapes
---------------------
**A channel that could not be established is declared, never guessed.** A
fabricated URL defeats the whole purpose, so a record either carries
``change_channel_url`` or carries ``change_channel_unestablished_reason``,
exactly one of the two. ISO's catalogue answers an automated request with HTTP
403 from any client, so its URL is not established here and the record says so
rather than asserting a plausible one. The reason is INTERNAL: it is a fact
about our request and our maintenance, so :func:`provenance_statement` does not
emit it to a client. What the record stores and what a client reads are two
separate decisions.

**The display name is derived, and its suffix is data.** ``display_name`` is
``short_label + name_suffix``, computed in one place, so no module can state a
version the record does not carry. The suffix is a field rather than a computed
join because three publishers use three naming conventions that their own
readers recognise (``DORA (EU 2022/2554)``, ``ISO 27001:2022``, ``PCI DSS
v4.0.1``). Inventing a fourth, uniform convention would print a name an
auditor does not.

What this module is NOT
-----------------------
It is not a staleness check, and nothing here fetches anything. A denominator
that moves because a crawler noticed an amendment, with no human having read
that amendment, is precisely the defect the surrounding body of work exists to
prevent. This is the record such a check would one day read.

This module lives in ``adscan_core`` so the appliance backend and the web can
read it without importing ``pro``. The per-framework values are facts about
public texts rather than product knowledge, so they live here outright; the
``pro`` modules consume the record and none of them keeps a second copy.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FrameworkProvenance:
    """The edition of one framework an assessment was mapped against.

    Attributes:
        framework: The engine's canonical framework key.
        authority: The body that publishes the text.
        instrument_scheme: The name of the publisher's identifier scheme.
        instrument_id: The identifier of the text in that scheme.
        instrument_title: The official title of the text.
        edition: The version or date of the text that was transcribed.
        edition_date: The edition's own publication date as an ISO date, when
            the publisher dates it to a day. Empty when it does not: ISO dates
            an edition to a month, so there is no day to record and none is
            invented.
        verified_on: ISO date ADscan last read the text against the publisher.
        text_state: What the publisher's change channel reported at that
            reading: amendments, consolidations and corrections.
        short_label: The framework's name without its version.
        name_suffix: The version suffix, separator included, in the publisher's
            own naming convention. Empty for a framework whose display name
            carries no version.
        change_channel_url: The publisher's own channel for asking whether the
            text has changed. Empty only when it could not be established.
        change_channel_label: What that channel is, for a reader who follows it.
        change_channel_unestablished_reason: Why no channel URL is recorded.
            Required when ``change_channel_url`` is empty, forbidden otherwise.
        requirement_text_note: Where the client reads the authoritative wording
            of each requirement, for a framework whose text ADscan does not
            reproduce. Empty for a framework published as freely available law,
            where the citation already resolves to the text itself.
    """

    framework: str
    authority: str
    instrument_scheme: str
    instrument_id: str
    instrument_title: str
    edition: str
    verified_on: str
    text_state: str
    short_label: str
    name_suffix: str = ""
    edition_date: str = ""
    change_channel_url: str = ""
    change_channel_label: str = ""
    change_channel_unestablished_reason: str = ""
    requirement_text_note: str = ""

    @property
    def display_name(self) -> str:
        """The framework's name as every surface prints it."""
        return f"{self.short_label}{self.name_suffix}"

    @property
    def citation(self) -> str:
        """The instrument id as an auditor cites it, scheme included."""
        return f"{self.instrument_scheme} {self.instrument_id}".strip()


#: The transcribed edition of every framework the product reports against.
#:
#: Each record is filled from a primary source, read on the date it carries.
#: Where a field could not be established against the publisher it is left
#: empty and the record says why, because a guessed identifier is worse than an
#: absent one: it reads as verified.
FRAMEWORK_PROVENANCE: dict[str, FrameworkProvenance] = {
    "ens": FrameworkProvenance(
        framework="ens",
        authority="the Boletín Oficial del Estado",
        instrument_scheme="BOE identifier",
        instrument_id="BOE-A-2022-7191",
        instrument_title=(
            "Real Decreto 311/2022, de 3 de mayo, por el que se regula el "
            "Esquema Nacional de Seguridad"
        ),
        edition="the original text, BOE núm. 106 of 4 May 2022",
        verified_on="2026-10-09",
        text_state=(
            "Anexos I, II and III stand in their original wording. The one "
            "later amendment on record, Real Decreto 1125/2024 "
            "(BOE-A-2024-22935), changes disposición adicional segunda only and "
            "leaves the measure set and its applicability table untouched."
        ),
        short_label="ENS",
        edition_date="2022-05-04",
        change_channel_url=(
            "https://www.boe.es/datosabiertos/api/legislacion-consolidada/"
            "id/BOE-A-2022-7191/analisis"
        ),
        change_channel_label=(
            "Boletín Oficial del Estado, consolidated-legislation amendment "
            "analysis for this Real Decreto"
        ),
    ),
    "nis2": FrameworkProvenance(
        framework="nis2",
        authority="the Publications Office of the European Union",
        instrument_scheme="CELEX",
        instrument_id="32022L2555",
        instrument_title=(
            "Directive (EU) 2022/2555 of the European Parliament and of the "
            "Council of 14 December 2022 on measures for a high common level of "
            "cybersecurity across the Union"
        ),
        edition=(
            "the original Official Journal text, English version, OJ L 333 of "
            "27 December 2022"
        ),
        verified_on="2026-10-13",
        text_state=(
            "No amendment and no consolidated version. The single corrigendum "
            "carrying an English version, 32022L2555R(04), corrects Article "
            "19(1) and does not reach Article 21."
        ),
        short_label="NIS2",
        edition_date="2022-12-27",
        change_channel_url="http://publications.europa.eu/resource/celex/32022L2555",
        change_channel_label=(
            "Cellar, the repository of the Publications Office of the "
            "European Union"
        ),
    ),
    "iso27001": FrameworkProvenance(
        framework="iso27001",
        authority="ISO/IEC",
        instrument_scheme="ISO/IEC standard",
        instrument_id="27001:2022",
        instrument_title=(
            "Information security, cybersecurity and privacy protection. "
            "Information security management systems. Requirements"
        ),
        edition="the third edition of October 2022",
        verified_on="2026-10-13",
        text_state=(
            "Annex A control identifiers and titles were read from the official "
            "free preview of ISO/IEC 27002:2022 (third edition 2022-02, "
            "corrected version 2022-03), whose clauses 5 to 8 carry the same "
            "numbers and titles. The standard's own text is under copyright and "
            "is not transcribed."
        ),
        short_label="ISO 27001",
        name_suffix=":2022",
        change_channel_unestablished_reason=(
            "ISO's catalogue answers an automated request with HTTP 403 from "
            "any client, so no channel URL is recorded here rather than one "
            "that was never confirmed to resolve. A change to this edition is "
            "read from ISO's catalogue entry for the standard by hand."
        ),
        requirement_text_note=(
            "So this report cites each control by its identifier and its "
            "title, which is how a certification auditor cites it, and states "
            "the subject of the control in its own words. The authoritative "
            "wording is in the organisation's own copy of the standard, and "
            "the guidance for implementing it is in ISO/IEC 27002:2022."
        ),
    ),
    "dora": FrameworkProvenance(
        framework="dora",
        authority="the Publications Office of the European Union",
        instrument_scheme="CELEX",
        instrument_id="32022R2554",
        instrument_title=(
            "Regulation (EU) 2022/2554 of the European Parliament and of the "
            "Council of 14 December 2022 on digital operational resilience for "
            "the financial sector"
        ),
        edition=(
            "the original Official Journal text, English version, OJ L 333 of "
            "27 December 2022"
        ),
        verified_on="2026-10-13",
        text_state=(
            "No amendment and no consolidated version. Nine corrigenda are on "
            "record and none of them has an English version, so the English "
            "text transcribed here is the original and uncorrected one."
        ),
        short_label="DORA",
        edition_date="2022-12-27",
        name_suffix=" (EU 2022/2554)",
        change_channel_url="http://publications.europa.eu/resource/celex/32022R2554",
        change_channel_label=(
            "Cellar, the repository of the Publications Office of the "
            "European Union"
        ),
    ),
    "pci_dss": FrameworkProvenance(
        framework="pci_dss",
        authority="the PCI Security Standards Council",
        instrument_scheme="PCI DSS version",
        instrument_id="4.0.1",
        instrument_title=(
            "the Payment Card Industry Data Security Standard: Requirements "
            "and Testing Procedures"
        ),
        edition="version 4.0.1, published 11 June 2024",
        verified_on="2026-04-21",
        text_state=(
            "A limited revision of v4.0 with no new and no deleted "
            "requirements. The future-dated v4.x requirements took effect on "
            "31 March 2025."
        ),
        short_label="PCI DSS",
        edition_date="2024-06-11",
        name_suffix=" v4.0.1",
        change_channel_url="https://www.pcisecuritystandards.org/document_library/",
        change_channel_label="the PCI Security Standards Council document library",
    ),
    "cis": FrameworkProvenance(
        framework="cis",
        authority="the Center for Internet Security",
        instrument_scheme="CIS Benchmark version",
        instrument_id="4.0.0",
        instrument_title="the CIS Microsoft Windows Server 2022 Benchmark",
        edition="version 4.0.0, dated 23 May 2025",
        verified_on="2026-09-10",
        text_state=(
            "A consensus hardening baseline rather than a regulation. ADscan "
            "reports against the recommendations it can observe, and CIS "
            "renumbers recommendations between benchmark versions, so a control "
            "id is cited against the benchmark of the host it was observed on."
        ),
        short_label="CIS Windows Server Benchmark",
        edition_date="2025-05-23",
        change_channel_url="https://www.cisecurity.org/cis-benchmarks",
        change_channel_label="the Center for Internet Security benchmark library",
    ),
}


def provenance_for(framework: str) -> FrameworkProvenance | None:
    """Return one framework's provenance record, or ``None`` when it has none."""
    return FRAMEWORK_PROVENANCE.get(framework)


def framework_display_name(framework: str, *, default: str = "") -> str:
    """Return the framework's display name, derived from its provenance record.

    Every surface that names a framework reads it from here, so the version a
    client sees in the report, in the CLI menu and in the web platform is one
    string with one owner.

    Args:
        framework: The engine's canonical framework key.
        default: What to return for a framework with no record. Defaults to the
            key upper-cased, which is how the compliance engine already falls
            back for an unknown framework.
    """
    record = FRAMEWORK_PROVENANCE.get(framework)
    if record is None:
        return default or framework.upper()
    return record.display_name


def framework_version(framework: str) -> str:
    """Return the framework's version token in its publisher's own scheme.

    The one string a surface should stamp when it needs the version alone: the
    CELEX number for an EU act, ``4.0.1`` for PCI DSS, ``4.0.0`` for the CIS
    benchmark. Empty for a framework with no record.
    """
    record = FRAMEWORK_PROVENANCE.get(framework)
    return record.instrument_id if record else ""


def provenance_statement(framework: str) -> str:
    """Return the sentence a client reads about which edition was mapped.

    Three sentences in audit register: the text and its identifier, when ADscan
    read it and what it found, then where to check for a newer one. A framework
    with no record returns an empty string, which suppresses the block rather
    than printing a sentence with holes in it.

    A framework carrying a ``requirement_text_note`` adds a fourth: where the
    authoritative wording lives, for a text ADscan cites rather than
    reproduces. It travels inside the statement so the one block the report and
    the platform already render carries it, with no second surface to keep in
    step.

    What the client does NOT read is
    ``change_channel_unestablished_reason``. The record keeps it, because a
    channel that could not be established is declared rather than guessed and a
    staleness check will read it, but it describes ADscan's own request and
    ADscan's own maintenance rather than the text, and this statement is about
    the text. Storing a fact and emitting it to a client are two decisions, and
    this function is only the second one.
    """
    record = FRAMEWORK_PROVENANCE.get(framework)
    if record is None:
        return ""

    parts = [
        f"This mapping was built against {record.instrument_title}, "
        f"{record.edition}, published by {record.authority} as "
        f"{record.citation}."
    ]
    verified = _format_verified_on(record.verified_on)
    if verified:
        parts.append(f"ADscan last read that text on {verified}. {record.text_state}")
    else:
        parts.append(record.text_state)

    if record.change_channel_url:
        parts.append(
            f"A later edition would appear at {record.change_channel_url} "
            f"({record.change_channel_label})."
        )
    # ``change_channel_unestablished_reason`` is deliberately NOT emitted here.
    # It is correct provenance and the record keeps it, but it is a fact about
    # ADscan rather than about the text: the ISO reason named the HTTP status
    # our client receives from a catalogue and the fact that a maintainer reads
    # the entry by hand. A client paying for an ISO mapping was reading our
    # error code and our workflow in the largest block on the page, inside
    # eight sentences where the other six were about the standard. The NIS2
    # statement is the register: every sentence is about the text.
    #
    # A reader who needs to know the edition can be checked is served by what
    # the statement already carries, the edition and the date it was read. A
    # later staleness check reads the field off the record.

    if record.requirement_text_note:
        parts.append(record.requirement_text_note)
    return " ".join(part for part in parts if part)


def provenance_view(framework: str) -> dict[str, str] | None:
    """Return one framework's provenance as the dict every surface serialises.

    The persisted compliance block and the web platform both read this shape, so
    the paid PDF and the paid platform cannot word the edition differently. The
    rendered ``statement`` travels with the fields rather than being rebuilt per
    surface, for the same reason.
    """
    record = FRAMEWORK_PROVENANCE.get(framework)
    if record is None:
        return None
    return {
        "framework": record.framework,
        "display_name": record.display_name,
        "authority": record.authority,
        "instrument_scheme": record.instrument_scheme,
        "instrument_id": record.instrument_id,
        "instrument_title": record.instrument_title,
        "citation": record.citation,
        "edition": record.edition,
        "edition_date": record.edition_date,
        "verified_on": record.verified_on,
        "text_state": record.text_state,
        "change_channel_url": record.change_channel_url,
        "change_channel_label": record.change_channel_label,
        "change_channel_unestablished_reason": (
            record.change_channel_unestablished_reason
        ),
        "requirement_text_note": record.requirement_text_note,
        "statement": provenance_statement(framework),
    }


_MONTH_NAMES = (
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


def _format_verified_on(value: str) -> str:
    """Render an ISO date the way the report writes a date, or return it as is.

    A malformed value is returned unchanged rather than dropped: the date is the
    half of the record that goes stale, so it is better read awkwardly than not
    at all.
    """
    parts = value.split("-")
    if len(parts) != 3:
        return value
    try:
        year, month, day = (int(part) for part in parts)
    except ValueError:
        return value
    if not 1 <= month <= 12:
        return value
    return f"{day} {_MONTH_NAMES[month - 1]} {year}"
