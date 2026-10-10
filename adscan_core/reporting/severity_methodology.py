"""The published method behind every severity this report prints.

Why this exists
---------------
A regulated buyer cannot be asked to take a severity on trust. What DORA, NIS2
and the ENS actually require is that findings be classified and prioritised by a
documented method applied consistently; none of them names the instrument. So
the deliverable carries its own grading model AND the inputs that produce it,
which is the OWASP Testing Guide shape: qualitative bands in the body, an
appendix stating how each band was reached.

Authored here, once, as data. The premium report renders it; the free report can
adopt the same block without a second copy, and a test can assert the annex is
present without parsing a PDF. Keeping the prose at the boundary of authorship
is the same rule the catalog prose follows.

Nothing in this module reads the engine at runtime. It DESCRIBES
``adscan_internal.services.severity`` (the attack-step grade) and
``adscan_core.cvss`` (the finding grade), and the contract test beside it fails
if either model grows or loses an input this annex does not mention.
"""

from __future__ import annotations

from adscan_core.cvss.severity_mapper import severity_bands

#: The inputs to the attack-step grade, in the order the engine consumes them.
#: Mirrors ``adscan_internal.services.severity.EdgeSeverityInput``.
ATTACK_STEP_INPUTS: tuple[tuple[str, str], ...] = (
    (
        "Source privilege",
        "What the account taking the step already holds in the directory.",
    ),
    (
        "Target privilege",
        "What the object on the receiving end of the step holds.",
    ),
    (
        "Kind of step",
        "What the step does to that object: takes control of it, authenticates "
        "into it, inherits it through a group, or crosses a trust.",
    ),
    (
        "Target tier, graded",
        "A domain controller or the domain object itself outranks a certificate "
        "authority or a mail server, even though all of them sit inside the "
        "Tier 0 boundary.",
    ),
    (
        "Proven reach with no credentials",
        "Whether the step was proven from an unauthenticated position, and "
        "whether the proven chain forward from it arrives inside Tier 0. An "
        "attacker who needs no account at all is the worst case, so this is "
        "read from what the assessment executed rather than from what the "
        "configuration permits.",
    ),
)

#: The two consequences of those inputs that explain most of what a reader sees,
#: stated so a surprising row can be checked rather than queried.
ATTACK_STEP_RULES: tuple[str, ...] = (
    "A step that lands on a Tier 0 asset from an account that is not already "
    "privileged is Critical: it crosses the containment boundary.",
    "A step between two accounts that already control the domain is "
    "Informational. It describes how Active Directory is built rather than a "
    "weakness anyone introduced.",
)

#: The inputs to the per-finding grade. Mirrors ``adscan_core.cvss.models`` and
#: the elevation conditions in ``adscan_core.cvss.contextual_rules``.
FINDING_INPUTS: tuple[tuple[str, str], ...] = (
    (
        "Category",
        "Whether the finding is a working exploit, a primitive that enables an "
        "attack chain, or a control that is absent. The three are graded on "
        "different ceilings.",
    ),
    (
        "Baseline grade",
        "What the technique is worth in any directory, before this one is "
        "looked at. It is the same figure in every report, so a raised grade can "
        "be traced to what raised it. ADscan authors it from the technique's "
        "reach in a directory, and it is not read from any CVSS vector. Where a "
        "finding happens to have both, the two often disagree, which is part of "
        "why this report rates on one of them only.",
    ),
    (
        "What this assessment observed",
        "Whether a Tier 0 account or a domain controller is in scope of the "
        "finding, and whether the technique was carried through to a result. "
        "The grade this produces is the one every count in the report is "
        "grouped by, so the figure you are asked to plan from is the figure the "
        "report totals.",
    ),
)

#: The invariants of the per-finding overlay, so a reader can predict it.
FINDING_RULES: tuple[str, ...] = (
    "The observation can only raise a grade, never lower one. Where the two "
    "differ, the card carries the baseline band beside the grade the finding is "
    "rated and counted at.",
    "An absent control is capped at High even on a Tier 0 account, because the "
    "finding records a control nobody turned on rather than an exploited one.",
    "A primitive reaches Critical only once the chain it enables was confirmed "
    "to have somewhere to go.",
)

#: Why no CVSS column appears, stated plainly so its absence cannot read as
#: something withheld. Figures are the catalog's own; see
#: ``adscan_core.cvss.vector_score`` for the arithmetic and
#: ``adscan_core.cvss.disclosure`` for the opt-in.
NO_CVSS_COLUMN_HEADING = "Why no CVSS column appears"

NO_CVSS_COLUMN_BODY: tuple[str, ...] = (
    "A CVSS Base score means something because the reader can recompute it from "
    "the vector behind it. Most Active Directory exposures have no published "
    "vector: a certificate template the whole domain can enrol from, a password "
    "attribute any account can read, a control nobody turned on. A decimal "
    "printed without its vector cannot be verified by the reader, and an "
    "unverifiable figure is the one an auditor queries.",
    "No regime in this report asks for one, on the text of the instruments "
    "themselves. DORA (Reg. (EU) 2022/2554, Art. 24(5)) and its ICT "
    "risk-management technical standard (Reg. (EU) 2024/1774, Art. 10(2)(f)) "
    "require findings to be prioritised and classified by criticality and name "
    "no instrument for it. NIS2 (Dir. (EU) 2022/2555) is qualitative "
    "throughout, as is the implementing regulation that details its "
    "risk-management measures for the entity types that regulation covers "
    "(Reg. (EU) 2024/2690). The ENS (RD 311/2022) and the Instrucción Técnica "
    "de Seguridad de Auditoría that governs its audits (BOE-A-2018-4573) "
    "name "
    "no scoring instrument either. All of them leave the scale to the "
    "assessor. The one standard that does mandate a CVSS, PCI DSS, scopes it "
    "to external scanning by an approved vendor and routes internal assessment "
    "to the entity's own risk ranking.",
    "17 of the 93 finding types ADscan catalogues map to a published Base "
    "vector. Printing a CVSS column would therefore fill 17 rows and leave 76 "
    "blank, so every finding here is graded by the model set out above, with "
    "its bands and its inputs published. Where a finding does map to a vector, "
    "ADscan holds both the vector and the score it computes, and prints them "
    "when an engagement is contractually scoped to CVSS.",
    "A named CVE is the exception, because its score is somebody else's work "
    "and can be checked at the source. Where a finding concerns one, the "
    "report names the CVE so the official NVD score can be looked up against "
    "it.",
)


def severity_methodology_view() -> dict[str, object]:
    """Return the annex as the render context both tiers consume.

    Returns:
        A mapping with the two graded models and the CVSS note, ready to loop
        over in a template. No engine state is read, so it is safe to call from
        a dependency-light surface.
    """
    return {
        "bands": {
            "heading": "The bands a score falls in",
            "lead": (
                "The attack-step grade and the finding grade, set out "
                "below, are both reported on this 0 to 10 scale and these "
                "bands, so a number anywhere in this report can be placed "
                "without looking it up."
            ),
            "rows": [{"label": label, "range": span} for label, span in severity_bands()],
        },
        "attack_step": {
            "heading": "How an attack step is graded",
            "lead": (
                "Five inputs decide the grade, and the same inputs always "
                "produce the same rating. The inputs and the rules below "
                "determine which band a step lands in; the per-technique "
                "baseline figures behind them are available to your auditor "
                "on request."
            ),
            "inputs": [{"name": name, "body": body} for name, body in ATTACK_STEP_INPUTS],
            "rules": list(ATTACK_STEP_RULES),
        },
        "finding": {
            "heading": "How a finding is graded",
            "lead": (
                "Three inputs. Two are the same in every assessment, and the "
                "third is what this directory supplies."
            ),
            "inputs": [{"name": name, "body": body} for name, body in FINDING_INPUTS],
            "rules": list(FINDING_RULES),
        },
        "no_cvss": {
            "heading": NO_CVSS_COLUMN_HEADING,
            "body": list(NO_CVSS_COLUMN_BODY),
        },
    }


__all__ = [
    "ATTACK_STEP_INPUTS",
    "ATTACK_STEP_RULES",
    "FINDING_INPUTS",
    "FINDING_RULES",
    "NO_CVSS_COLUMN_BODY",
    "NO_CVSS_COLUMN_HEADING",
    "severity_methodology_view",
]
