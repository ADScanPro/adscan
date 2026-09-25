"""ADCS finding state — the three honest states, derived once for every surface.

Real enterprises run several CAs: some live, some decommissioned-but-still-
registered, some resolvable-but-unreachable. So an ADCS finding is not simply
"vulnerable / not". Under the Exposure-Validation doctrine it renders as exactly
one of three states, worded identically on the CLI, the PDF report and the paid
web CTEM:

* **Validated** — the vulnerable CA / template was reachable and the technique
  executed. The headline finding; the "validated, not estimated" wedge.
* **Not validated — data gap** — the vulnerability exists (the collector detected
  it) but no reachable CA (or publishing CA, for template ESCs) was found: the CA
  host is NXDOMAIN / offline / the enrollment port is closed. Rendered WITH the
  actionable next step ("provide ``ADSCAN_HOST_IP_<HOST>=<ip>`` to validate, or
  confirm the CA is decommissioned"). NEVER a confirmed CRITICAL, NEVER
  ``closed_by_configuration`` (a dead host is a data gap, not observed hardening),
  and NEVER the misleading "check the template DACL / Web Enrollment" message.
* **Hygiene** — an orphaned / decommissioned CA object still registered in AD (a
  ``pKIEnrollmentService`` object whose host is NXDOMAIN and which has no computer
  object). Actionable value the client did not have: clean up the stale CA object.
  This is a hygiene finding, never an exploitable ESC finding.

This module is the SSOT for both halves (mirroring
:mod:`adscan_core.reporting.cracking_coverage`):

* :func:`build_adcs_finding_state` turns the observed inputs into the block
  persisted alongside the finding; and
* :func:`adcs_finding_state_view` turns that persisted block back into the small
  render-ready shape the PDF report and the web CTEM both consume, so the two
  surfaces cannot word the same state differently.

Pure logic: no IO, no console, no network. Safe to import from ``adscan_core``,
the LITE runtime, the PRO report renderer and the web backend alike.
"""

from __future__ import annotations

from typing import Any, Mapping

#: Key an ADCS finding's state block is stamped under, in the persisted finding
#: and in the renderer's data. One name so the writer, the PDF and the web
#: platform cannot drift apart on where the record lives.
ADCS_FINDING_STATE_KEY = "adcs_finding_state"

#: The three honest states.
STATE_VALIDATED = "validated"
STATE_DATA_GAP = "data_gap"
STATE_HYGIENE = "hygiene"

_STATE_LABELS: dict[str, str] = {
    STATE_VALIDATED: "Validated",
    STATE_DATA_GAP: "Not validated (data gap)",
    STATE_HYGIENE: "Hygiene: stale CA object",
}

_VALID_STATES = frozenset(_STATE_LABELS)

#: Relation names (lower-cased) that are ADCS ESC escalations. A step / edge whose
#: relation is one of these renders under the three honest ADCS states. Shared so
#: the report SSOT and the web CTEM gate identically on "is this an ADCS finding".
ADCS_ESC_RELATIONS = frozenset(
    {
        "adcsesc1",
        "adcsesc2",
        "adcsesc3",
        "adcsesc4",
        "adcsesc5",
        "adcsesc6",
        "adcsesc7",
        "adcsesc8",
        "adcsesc9",
        "adcsesc10",
        "adcsesc11",
        "adcsesc13",
        "adcsesc14",
        "adcsesc15",
        "coerceandrelayntlmtoadcs",
    }
)


def is_adcs_esc_relation(relation: Any) -> bool:
    """Return whether ``relation`` is an ADCS ESC escalation (case-insensitive)."""

    return str(relation or "").strip().lower() in ADCS_ESC_RELATIONS


#: Attack-path / step statuses that mean the technique actually executed against a
#: reachable CA. Spans the three status vocabularies' proven tokens.
_PROVEN_STATUSES = frozenset({"success", "exploited", "domain_compromised"})

#: Attack-path / step statuses meaning ADscan could not reach the CA to validate
#: (Part A's honest data-gap abort marks the edge ``unavailable``).
_DATA_GAP_STATUSES = frozenset({"unavailable", "unsupported"})

_VALIDATED_STATEMENT = (
    "The vulnerable certificate authority was reachable and the escalation itself "
    "ran to completion. This exposure is proven, not estimated."
)

_HYGIENE_STATEMENT = (
    "A certificate-authority object is still registered in Active Directory but "
    "its host no longer resolves and has no computer object: a decommissioned CA "
    "left in the directory. This is not an exploitable finding; it is directory "
    "hygiene."
)

_HYGIENE_NEXT_STEP = (
    "Remove the stale CA object from Active Directory if the CA is decommissioned, "
    "so it no longer advertises enrollment services that no longer exist."
)


def _data_gap_next_step(host_label: str) -> str:
    """Actionable next step for a data-gap ADCS finding (never an apology)."""

    host = str(host_label or "").strip()
    hint = (
        f"provide ADSCAN_HOST_IP_{host.upper().replace('.', '_')}=<ip>"
        if host
        else "provide ADSCAN_HOST_IP_<HOST>=<ip>"
    )
    return (
        f"The vulnerability was detected but its certificate authority could not "
        f"be reached to validate it (host unresolved, offline, or the enrollment "
        f"port is closed). To confirm the exposure, {hint} and re-run, or confirm "
        f"the CA is decommissioned."
    )


def _data_gap_statement() -> str:
    """Client statement for a data-gap ADCS finding."""

    return (
        "The vulnerability was detected by directory analysis, but its certificate "
        "authority was not reachable from the assessment vantage, so the escalation "
        "was not executed. It is neither confirmed exploitable nor shown to be "
        "safe here, only left unvalidated."
    )


def build_adcs_finding_state(
    *,
    state: Any = "",
    ca_host: str = "",
) -> dict[str, Any]:
    """Build the ``adcs_finding_state`` block for one ADCS finding.

    Args:
        state: One of :data:`STATE_VALIDATED` / :data:`STATE_DATA_GAP` /
            :data:`STATE_HYGIENE`. An unrecognised value yields an empty block
            (``state=""``) so a caller that could not classify the finding does
            not fabricate a state.
        ca_host: The CA host the finding concerns, used to render the
            ``ADSCAN_HOST_IP_<HOST>`` hint on a data-gap. Never surfaced as a raw
            override token when empty.

    Returns:
        The block to persist alongside the finding. Carries ``state``,
        ``statement`` and (for data-gap / hygiene) ``next_step``.
    """

    name = str(state or "").strip().lower()
    if name not in _VALID_STATES:
        return {"state": "", "statement": "", "next_step": ""}
    if name == STATE_VALIDATED:
        return {"state": name, "statement": _VALIDATED_STATEMENT, "next_step": ""}
    if name == STATE_HYGIENE:
        return {
            "state": name,
            "statement": _HYGIENE_STATEMENT,
            "next_step": _HYGIENE_NEXT_STEP,
        }
    return {
        "state": STATE_DATA_GAP,
        "statement": _data_gap_statement(),
        "next_step": _data_gap_next_step(ca_host),
        "ca_host": str(ca_host or "").strip(),
    }


def classify_adcs_edge_state(
    *,
    status: Any = "",
    is_orphaned_ca: Any = False,
) -> str:
    """Classify one ADCS edge/finding into a three-state name.

    Args:
        status: The persisted attack-path / step status for the ADCS edge.
        is_orphaned_ca: Whether the finding is about a CA object whose host is
            NXDOMAIN and which has no computer object (the hygiene case).

    Returns:
        One of :data:`STATE_VALIDATED` / :data:`STATE_DATA_GAP` /
        :data:`STATE_HYGIENE`, or ``""`` when the status does not map to any state
        (e.g. a plain ``theoretical`` edge that was never executed and is not a
        data gap — it keeps its ordinary theoretical rendering).
    """

    if is_orphaned_ca:
        return STATE_HYGIENE
    name = str(status or "").strip().lower()
    if name in _PROVEN_STATUSES:
        return STATE_VALIDATED
    if name in _DATA_GAP_STATUSES:
        return STATE_DATA_GAP
    return ""


def adcs_finding_state_view(block: Any) -> dict[str, Any]:
    """Return the render-ready view of a persisted ``adcs_finding_state`` block.

    The one shape the PDF report and the web CTEM both read, so a state is worded
    identically wherever a client meets it.

    Returns a mapping with:
      * ``has_state`` — whether to surface a state banner at all;
      * ``state`` — the machine token (``validated`` / ``data_gap`` / ``hygiene``);
      * ``state_label`` — the client-facing state name;
      * ``statement`` — the client-facing sentence;
      * ``next_step`` — the actionable next step (empty for validated);
      * ``is_confirmed_critical`` — ``True`` only for ``validated`` (a data-gap or
        hygiene finding must NEVER render as a confirmed CRITICAL).

    An absent / unreadable block yields ``has_state=False`` so a scan predating
    this record renders exactly as it did before.
    """

    if not isinstance(block, Mapping):
        return {
            "has_state": False,
            "state": "",
            "state_label": "",
            "statement": "",
            "next_step": "",
            "is_confirmed_critical": False,
        }
    name = str(block.get("state") or "").strip().lower()
    if name not in _VALID_STATES:
        return {
            "has_state": False,
            "state": "",
            "state_label": "",
            "statement": "",
            "next_step": "",
            "is_confirmed_critical": False,
        }
    return {
        "has_state": True,
        "state": name,
        "state_label": _STATE_LABELS[name],
        "statement": str(block.get("statement") or "").strip(),
        "next_step": str(block.get("next_step") or "").strip(),
        "is_confirmed_critical": name == STATE_VALIDATED,
    }


__all__ = [
    "ADCS_FINDING_STATE_KEY",
    "ADCS_ESC_RELATIONS",
    "STATE_VALIDATED",
    "STATE_DATA_GAP",
    "STATE_HYGIENE",
    "build_adcs_finding_state",
    "classify_adcs_edge_state",
    "adcs_finding_state_view",
    "is_adcs_esc_relation",
]
