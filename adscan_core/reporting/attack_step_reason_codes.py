"""Structured reason codes for an attack step's non-proven outcome.

An attack step has a SMALL, closed top-level status vocabulary (``success`` /
``attempted`` / ``blocked`` / ...), where each value is a distinct machine
consequence. That vocabulary deliberately does NOT encode WHY a step stopped: a
Kerberoast whose hash was captured but not cracked, an authentication that was
rejected, and a host that was never reachable all land on the same top-level
``attempted`` status. Overloading the status set with a token per cause would
explode it and break every consumer that switches on the small set.

The reason code is the second level: a structured, closed enum describing WHY
an ``attempted`` (or otherwise non-proven) step did not complete, stamped onto
the step / edge WITHOUT changing the top-level status. It is the one field that
carries the cause to the client, so a report and the web CTEM can tell the
reader "the hash is captured, the password was not recovered" instead of a bare
"stopped at Kerberoasting".

Pure data: an enum plus a code -> client-note map and a small render-ready view.
No IO, no console, no network. Safe to import from ``adscan_core``, the LITE
runtime, the PRO report renderer, and the web backend alike, mirroring
:mod:`adscan_core.reporting.adcs_finding_state`. The web backend (a separate
process that must never import ``adscan_internal``) reads the stamped code back
from the ingested edge notes and renders the SAME note the deliverable does, so
the two surfaces cannot word the same cause differently.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

#: Key the reason code is stamped under, on a step's ``details`` dict, on an
#: attack-graph edge's ``notes`` dict, and (once ingested) in the web's
#: ``properties.graph_notes``. One name so the writer, the PDF report and the web
#: CTEM cannot drift apart on where the value lives.
REASON_CODE_KEY = "reason_code"


class ReasonCode(str, Enum):
    """Why a non-proven attack step did not complete.

    A ``str`` enum so a member is JSON-serialisable as its value and compares
    equal to the raw token a consumer reads back from persisted notes.
    """

    #: A roastable hash was captured, but the password was not recovered with the
    #: engagement wordlist. The weakness is proven (the account is roastable and
    #: we hold the material); only the offline crack did not land.
    CRACK_FAILED = "crack_failed"
    #: An ADCS certificate was issued from a vulnerable template, but Pass-the-
    #: Certificate authentication with it did not complete. The template is still
    #: proven vulnerable; the authentication step is what stopped.
    CERT_ISSUED_NOT_AUTHED = "cert_issued_not_authed"
    #: Authentication did not succeed with the credential in hand.
    AUTH_FAILED = "auth_failed"
    #: The target host was not reachable from the current vantage point.
    TARGET_UNREACHABLE = "target_unreachable"
    #: The target refused the request outright.
    REJECTED = "rejected"
    #: No suitable relay target was available to complete the attack.
    NO_RELAY_TARGET = "no_relay_target"
    #: A coercion request was sent, but the target never authenticated back.
    COERCION_NO_CALLBACK = "coercion_no_callback"
    #: This step is not automated and was not executed in this run.
    NOT_AUTOMATED = "not_automated"


#: Client-facing note for each reason code, worded once here and read by every
#: surface. English, anti-slop (no em-dash, no offensive-tool names): the cause
#: is stated vendor-neutrally, so the prose is safe in a paid deliverable.
_REASON_CODE_NOTES: dict[str, str] = {
    ReasonCode.CRACK_FAILED.value: (
        "Hash captured; password not recovered with the engagement wordlist. "
        "A stronger offline attack may succeed."
    ),
    ReasonCode.CERT_ISSUED_NOT_AUTHED.value: (
        "Certificate issued (the template is vulnerable); authentication with it "
        "did not complete."
    ),
    ReasonCode.AUTH_FAILED.value: (
        "Authentication did not succeed with the credential in hand."
    ),
    ReasonCode.TARGET_UNREACHABLE.value: (
        "The target host was not reachable from the current vantage point."
    ),
    ReasonCode.REJECTED.value: ("The target refused the request."),
    ReasonCode.NO_RELAY_TARGET.value: (
        "No suitable relay target was available to complete the attack."
    ),
    ReasonCode.COERCION_NO_CALLBACK.value: (
        "The coercion request was sent, but the target never authenticated back."
    ),
    ReasonCode.NOT_AUTOMATED.value: (
        "This step is not automated and was not run; the manual command above "
        "validates it by hand."
    ),
}

#: The closed set of valid reason-code tokens.
VALID_REASON_CODES: frozenset[str] = frozenset(_REASON_CODE_NOTES)


def normalize_reason_code(code: Any) -> str:
    """Return the canonical reason-code token, or ``""`` when not a known code.

    Accepts a :class:`ReasonCode`, its string value, or any token in any casing.
    An unknown / missing value yields ``""`` so a consumer can treat "no reason
    recorded" and "unrecognised token" identically (render nothing), never raise.
    """

    if isinstance(code, ReasonCode):
        return code.value
    token = str(code or "").strip().lower()
    return token if token in VALID_REASON_CODES else ""


def reason_code_client_note(code: Any) -> str:
    """Return the client-facing note for a reason code, or ``""`` when unknown."""

    return _REASON_CODE_NOTES.get(normalize_reason_code(code), "")


def reason_code_view(code: Any) -> dict[str, Any]:
    """Return the render-ready view of a reason code.

    The one shape the writeup, the PDF report and the web CTEM all read, so the
    same cause is worded identically wherever a client meets it:

      * ``has_reason`` - whether to surface a reason line at all;
      * ``reason_code`` - the machine token (``crack_failed`` / ...);
      * ``client_note`` - the client-facing sentence.

    An absent / unrecognised code yields ``has_reason=False`` so a step with no
    recorded reason renders exactly as it did before.
    """

    token = normalize_reason_code(code)
    note = _REASON_CODE_NOTES.get(token, "")
    if not token or not note:
        return {"has_reason": False, "reason_code": "", "client_note": ""}
    return {"has_reason": True, "reason_code": token, "client_note": note}


__all__ = [
    "REASON_CODE_KEY",
    "ReasonCode",
    "VALID_REASON_CODES",
    "normalize_reason_code",
    "reason_code_client_note",
    "reason_code_view",
]
