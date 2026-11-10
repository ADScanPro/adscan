"""Which compliance requirements an ADscan assessment can evidence, as data.

The engine already derives how much of the ENS regime an assessment measures:
:func:`adscan_core.reporting.ens_mapping_coverage.build_ens_mapping_coverage`
states it inside the Security Assessment Report and the AD Control Coverage
Report. That derivation reaches a client who has already bought and already
run a scan. A CISO facing an ENS audit asks the same question earlier and from
outside: which of the 73 Anexo II measures can this product evidence, and which
can it not.

This module is the answer in publishable form. It reads the SAME two sources the
paid deliverable reads, the Anexo II table in ``adscan_core`` and the mapped
measure ids in ``pro``, and returns rows. It renders nothing, authors no figure,
and holds no copy of either source: a measure mapped tomorrow appears here on
the next generator run with nothing to remember.

Two properties are deliberate.

**Every measure of the annex is a row, not only the mapped ones.** A page that
lists thirteen measures states coverage without a denominator, which is the
defect the coverage sentence exists to prevent. All 73 are published, each
carrying whether this engine maps it, and the five the mapping audit examined
closely carry the reason they were declined.

**A framework whose requirement universe is not declared is published as
UNESTABLISHED, never as zero.** Three of the six frameworks the product reports
against now have a transcribed requirement universe to count against: ENS, from
the Anexo II table in ``adscan_core.reporting.ens_applicability``, and DORA and
NIS2, from ``adscan_core.reporting.regulatory_universe``. The other three are
listed with the reason the figure does not exist yet, because a reader who sees
a framework absent from a coverage page concludes the product maps nothing for
it. That conclusion would be false, and the same rule the compliance scorecard
already follows applies to us: a thing nobody measured is declared unmeasured,
never scored.

**DORA and NIS2 publish a third state.** Some requirements are indivisible and
group one branch an assessment reaches with others it does not. Those enter the
denominator marked ``partially_evidenced``, carrying the branch they evidence
and the subject they leave open, and they never count in the numerator. Folding
them into the mapped count would claim the requirement; folding them into the
unmapped count would discard real evidence.

Lazy ``pro`` imports throughout, mirroring
:mod:`adscan_internal.services.coverage_stats`: this module stays importable
where the ``pro`` package is not installed.
"""

from __future__ import annotations

from typing import Any

#: A framework whose requirement universe is transcribed, so the share of it
#: this engine maps can be stated.
STATUS_DECLARED = "declared"

#: A framework with no transcribed requirement universe. There is no
#: denominator, so there is no share to state, and none is implied.
STATUS_NOT_ESTABLISHED = "not_established"

#: Why a framework with no transcribed requirement universe carries no coverage
#: figure yet.
#:
#: One line per framework, naming the normative document whose requirement set
#: would have to be transcribed first. Deliberately specific: "not established"
#: alone reads as an evasion, while naming the document shows the work that is
#: missing and lets a reader judge it.
_NOT_ESTABLISHED_REASONS: dict[str, str] = {
    "iso27001": (
        "The requirement set would be the Annex A controls of ISO/IEC "
        "27001:2022. The standard's text is not redistributable, so the control "
        "set is not transcribed here and there is no total to state a share of."
    ),
    "pci_dss": (
        "ADscan maps PCI DSS v4.0.1 at the level of the twelve principal "
        "requirements. The standard states its obligations in sub-requirements, "
        "so a share of the principal requirements would overstate the coverage "
        "an assessor reads, and the sub-requirement set is not transcribed here."
    ),
    "cis": (
        "The CIS Microsoft Windows Server Benchmark is a hardening "
        "configuration baseline rather than a regulation, and ADscan reports "
        "against the recommendations it can observe. The benchmark's full "
        "recommendation set is not transcribed here, so there is no total to "
        "state a share of."
    ),
}


def _framework_keys() -> tuple[str, ...]:
    """Every framework the product reports against, in the report's own order."""
    from adscan_internal.pro.reporting.compliance_artifact import (  # noqa: PLC0415
        CANONICAL_FRAMEWORK_KEYS,
    )

    return tuple(CANONICAL_FRAMEWORK_KEYS)


def _framework_display_name(key: str) -> str:
    """One framework's display name, read off its own registry definition.

    Read from the definition rather than listed here, so a framework renamed in
    the deliverable is renamed on the page by the same edit. Falls back the way
    the deliverable itself falls back, so the two cannot label it differently.
    """
    from adscan_internal.pro.reporting.compliance_artifact import (  # noqa: PLC0415
        get_framework_definition,
    )

    definition = get_framework_definition(key)
    return (getattr(definition, "display_name", "") or key.upper()) if definition else key.upper()


def _mapped_ens_measure_ids() -> tuple[str, ...]:
    from adscan_internal.pro.reporting.compliance_artifact import (  # noqa: PLC0415
        mapped_ens_measure_ids,
    )

    return mapped_ens_measure_ids()


def _declined_reasons() -> dict[str, str]:
    from adscan_internal.pro.reporting.ens_compliance import (  # noqa: PLC0415
        ENS_DECLINED_MEASURE_REASONS,
    )

    return dict(ENS_DECLINED_MEASURE_REASONS)


def build_ens_measure_coverage() -> dict[str, Any]:
    """Return the per-measure ENS coverage declaration, every measure included.

    Returns:
        The figures from the shared derivation (read against no declared client
        scope, so the published total is the common core Anexo II requires at
        every category), plus one row per Anexo II measure carrying its
        normative metadata, whether this engine maps it, whether it is part of
        that common core, and the reason it was declined where one is recorded.
    """
    from adscan_core.reporting.ens_applicability import (  # noqa: PLC0415
        COMMON_CORE_MEASURE_IDS,
        DIMENSION_NAMES,
        DIMENSION_ORDER,
        ENS_VERSION,
        ENS_VERSION_LONG,
        anexo_ii_measure_ids,
        lowest_required_label,
        measure_apartado,
        measure_dimensions,
        measure_family,
        measure_marco,
        measure_name,
        measure_selector,
        resolve_ens_applicability,
    )
    from adscan_core.reporting.ens_mapping_coverage import (  # noqa: PLC0415
        build_ens_mapping_coverage,
    )

    mapped = set(_mapped_ens_measure_ids())
    declined = _declined_reasons()
    common_core = set(COMMON_CORE_MEASURE_IDS)

    # No declared scope: the published figure is the one that holds for every
    # reader, which is the set Anexo II requires at every system category. A
    # client's own declared scope resolves it up or down, and the sentence the
    # derivation returns says so.
    coverage = build_ens_mapping_coverage(
        resolve_ens_applicability(None), sorted(mapped)
    )

    measures = [
        {
            "measure_id": measure_id,
            "name": measure_name(measure_id),
            "family": measure_family(measure_id),
            "marco": measure_marco(measure_id),
            "anexo_ii_apartado": measure_apartado(measure_id),
            "selector": measure_selector(measure_id),
            "dimensions": list(measure_dimensions(measure_id)),
            "lowest_required_label": lowest_required_label(measure_id),
            "required_at_every_category": measure_id in common_core,
            "mapped": measure_id in mapped,
            "declined_reason": declined.get(measure_id, ""),
        }
        for measure_id in anexo_ii_measure_ids()
    ]

    return {
        "status": STATUS_DECLARED,
        "ens_version": ENS_VERSION,
        "ens_version_long": ENS_VERSION_LONG,
        "figures": coverage,
        "measures": measures,
        # The five security dimensions, in declaration order, so a reader can
        # expand the single letters a dimension-selected measure is scoped by.
        # Carried rather than left to the consumer: a page that spells out what
        # C, I, T, A and D stand for has to spell out the same five the norm
        # does, and the norm's own names are already here.
        "dimensions": [
            {"code": dimension.value, "name": DIMENSION_NAMES[dimension]}
            for dimension in DIMENSION_ORDER
        ],
    }


def _requirement_universe_coverages() -> dict[str, Any]:
    """Return the per-framework coverage declaration for DORA and NIS2.

    Reads the SAME two sources the paid deliverable reads: the transcribed
    universe in ``adscan_core`` and the mapped set in ``pro``. Holds no copy of
    either, so a requirement mapped tomorrow appears here on the next generator
    run with nothing to remember.
    """
    from adscan_internal.pro.reporting.dora_compliance import (  # noqa: PLC0415
        build_dora_requirement_coverage,
    )
    from adscan_internal.pro.reporting.nis2_compliance import (  # noqa: PLC0415
        build_nis2_requirement_coverage,
    )

    return {
        "dora": build_dora_requirement_coverage(),
        "nis2": build_nis2_requirement_coverage(),
    }


def declared_universe_framework_keys() -> tuple[str, ...]:
    """Return the frameworks whose requirement universe is transcribed.

    ENS counts against the Anexo II table; DORA and NIS2 count against
    ``adscan_core.reporting.regulatory_universe``. Derived from that module
    rather than listed, so transcribing a fourth framework's universe declares
    it here by the same edit.
    """
    from adscan_core.reporting.regulatory_universe import (  # noqa: PLC0415
        FRAMEWORK_UNITS,
    )

    return ("ens",) + tuple(FRAMEWORK_UNITS)


def build_framework_coverage_statuses() -> list[dict[str, Any]]:
    """Return one row per reportable framework: declared, or declared absent.

    A framework whose requirement universe is transcribed resolves to
    :data:`STATUS_DECLARED`. Every other framework resolves to
    :data:`STATUS_NOT_ESTABLISHED` and carries the reason, so its coverage reads
    as unmeasured rather than as nothing.
    """
    declared_keys = set(declared_universe_framework_keys())
    rows: list[dict[str, Any]] = []
    for key in _framework_keys():
        declared = key in declared_keys
        rows.append(
            {
                "key": key,
                "display_name": _framework_display_name(key),
                "status": STATUS_DECLARED if declared else STATUS_NOT_ESTABLISHED,
                "reason": "" if declared else _NOT_ESTABLISHED_REASONS.get(key, ""),
            }
        )
    return rows


def build_compliance_coverage() -> dict[str, Any]:
    """Return the whole publishable compliance-coverage payload.

    One call, so a consumer cannot read one framework's half and miss the
    declaration that the others have no figure. Every half answers the same
    question, and a page that showed only the first would read as if one
    framework were the whole of what the product maps.
    """
    return {
        "ens": build_ens_measure_coverage(),
        "requirement_universes": _requirement_universe_coverages(),
        "frameworks": build_framework_coverage_statuses(),
    }


__all__ = [
    "STATUS_DECLARED",
    "STATUS_NOT_ESTABLISHED",
    "build_compliance_coverage",
    "build_ens_measure_coverage",
    "build_framework_coverage_statuses",
    "declared_universe_framework_keys",
]
