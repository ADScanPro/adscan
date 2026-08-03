"""CVSS v3.x Base score computed from a Base vector string.

Why this module exists
----------------------
A CVSS Base score is only a CVSS Base score if a reader can recompute it. The
number ADscan's vulnerability catalog carries per finding key is an ADscan
severity opinion — a useful prioritisation baseline, but not something anyone
can verify against the FIRST calculator. Printing it beside the label "CVSS
Base" made the deliverable claim a standard it had not applied, and where a
vector WAS also printed the two disagreed, so an auditor could falsify the
number with the report's own vector.

So the formal Base score is derived here, from the vector, using the equations
in the CVSS v3.1 specification (§ 7.1 Base). A finding without a vector has no
formal CVSS Base at all, and the report must say so rather than dress up the
catalog number.

Reference: FIRST CVSS v3.1 specification, section 7.1 (Base equations) and
section 5 (qualitative severity rating scale).
"""

from __future__ import annotations

import math

#: Attack Vector.
_AV: dict[str, float] = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}

#: Attack Complexity.
_AC: dict[str, float] = {"L": 0.77, "H": 0.44}

#: Privileges Required — the value depends on Scope (unchanged vs changed).
_PR_UNCHANGED: dict[str, float] = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED: dict[str, float] = {"N": 0.85, "L": 0.68, "H": 0.50}

#: User Interaction.
_UI: dict[str, float] = {"N": 0.85, "R": 0.62}

#: Confidentiality / Integrity / Availability impact.
_CIA: dict[str, float] = {"H": 0.56, "L": 0.22, "N": 0.0}

#: The Base metrics every valid Base vector must carry.
_REQUIRED_METRICS: tuple[str, ...] = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

#: Prefixes this module understands. A v4.0 vector uses different equations and
#: is deliberately rejected rather than mis-scored with the v3 formula.
_SUPPORTED_PREFIXES: tuple[str, ...] = ("CVSS:3.1", "CVSS:3.0")


def parse_vector(vector: str | None) -> dict[str, str] | None:
    """Return the Base metrics of a CVSS v3.x vector, or ``None``.

    Args:
        vector: A CVSS Base vector string, e.g.
            ``"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"``.

    Returns:
        A mapping of metric abbreviation to value for every Base metric, or
        ``None`` when the string is missing, not a supported CVSS version, or
        does not carry the full Base metric set.
    """
    if not vector or not isinstance(vector, str):
        return None
    parts = [segment.strip() for segment in vector.strip().split("/") if segment.strip()]
    if not parts:
        return None
    if parts[0].upper() not in _SUPPORTED_PREFIXES:
        return None

    metrics: dict[str, str] = {}
    for segment in parts[1:]:
        if ":" not in segment:
            continue
        name, _, value = segment.partition(":")
        metrics[name.strip().upper()] = value.strip().upper()

    if any(name not in metrics for name in _REQUIRED_METRICS):
        return None
    return metrics


def _roundup(value: float) -> float:
    """Return the CVSS v3.1 ``Roundup`` of *value* (spec appendix A).

    The smallest number, to one decimal place, that is greater than or equal to
    the input. Implemented on the integer form the specification prescribes so
    floating-point representation cannot round a boundary the wrong way.
    """
    scaled = int(round(value * 100000))
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def score_from_vector(vector: str | None) -> float | None:
    """Return the CVSS v3.x Base score for *vector*, or ``None``.

    Args:
        vector: A CVSS v3.0/v3.1 Base vector string.

    Returns:
        The Base score rounded per the specification, or ``None`` when the
        vector is absent, of an unsupported version, or incomplete. A caller
        that gets ``None`` has no formal CVSS Base for that finding and must
        not present one.
    """
    metrics = parse_vector(vector)
    if metrics is None:
        return None

    scope_changed = metrics["S"] == "C"
    try:
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[metrics["PR"]]
        ui = _UI[metrics["UI"]]
        conf = _CIA[metrics["C"]]
        integ = _CIA[metrics["I"]]
        avail = _CIA[metrics["A"]]
    except KeyError:
        return None

    iss = 1.0 - ((1.0 - conf) * (1.0 - integ) * (1.0 - avail))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    combined = impact + exploitability
    if scope_changed:
        combined *= 1.08
    return _roundup(min(combined, 10.0))
