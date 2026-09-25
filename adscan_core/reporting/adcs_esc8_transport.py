"""ADCS ESC8 observed transport + EPA — the client-facing remediation, derived once.

The remediation a client must run for an ESC8 (ADCS Web Enrollment relay) finding
depends on WHICH transport was actually exploited and whether Extended Protection
for Authentication (EPA / channel binding) is enforced. A generic "disable web
enrollment or enable EPA" is weaker on two Hormozi axes at once: it costs the
client more effort to work out which half applies, and it is less credible because
it does not name the vector the assessment actually relayed over.

The relay already decides the scheme from a fresh, EPA-aware probe
(``esc_relay._resolve_esc8_scheme`` + ``WebEnrollmentProbeResult``): it knows the
scheme it relayed over, whether HTTP and/or HTTPS offered an NTLM avenue, and the
observed EPA state. This module is the SSOT that turns those observed values into:

* :func:`build_esc8_transport` — the block stamped onto the ESC8 attack-graph edge
  evidence / ``notes`` at execution time; and
* :func:`esc8_transport_view` — the render-ready shape the PDF report and the paid
  web CTEM both read, so the two surfaces cannot word the same remediation
  differently.

Exposure-Validation: the remediation states what was OBSERVED (the scheme actually
relayed plus the probed EPA state), never a guess. State the SCHEME + EPA, never the
raw port number — the scheme conveys the port, and "HTTPS without EPA" is the
actionable signal where "port 443" is noise.

Pure logic: no IO, no console, no network. Safe to import from ``adscan_core``, the
LITE runtime, the PRO report renderer and the web backend alike.
"""

from __future__ import annotations

from typing import Any, Mapping

#: Key this block is stamped under, on the ESC8 attack-graph edge's ``notes`` /
#: ``evidence`` and in the report's per-step details. One name so the writer, the
#: PDF and the web platform cannot drift apart on where the record lives.
ESC8_TRANSPORT_KEY = "esc8_transport"

_SCHEME_LABELS: dict[str, str] = {"http": "HTTP", "https": "HTTPS"}


def _norm_scheme(scheme: Any) -> str:
    """Normalize a relayed-scheme value to ``"http"`` / ``"https"`` / ``""``."""

    name = str(scheme or "").strip().lower()
    return name if name in _SCHEME_LABELS else ""


def build_esc8_transport(
    *,
    observed_scheme: Any = "",
    http_available: Any = None,
    https_available: Any = None,
    epa_enforced: Any = None,
) -> dict[str, Any]:
    """Build the ``esc8_transport`` block for one ESC8 finding.

    Args:
        observed_scheme: The transport the relay actually used (``"http"`` /
            ``"https"``), from the ESC8 relay's scheme decision. Empty when the
            relay never chose a scheme (aborted before coercion).
        http_available: Whether the CA offered an NTLM avenue over HTTP web
            enrollment (``WebEnrollmentProbeResult.http_ntlm``). ``None`` when the
            probe result was not captured.
        https_available: Whether the CA offered an NTLM avenue over HTTPS web
            enrollment (``WebEnrollmentProbeResult.https_ntlm``). ``None`` when the
            probe result was not captured.
        epa_enforced: The observed EPA state on the HTTPS enrollment site
            (``WebEnrollmentProbeResult.epa_enforced``): ``True`` enforced,
            ``False`` not enforced, ``None`` not determined.

    Returns:
        The block to stamp on the ESC8 edge evidence / notes. ``observed`` is
        ``True`` only when a scheme was actually relayed, so a render can tell an
        observed transport from a bare theoretical edge.
    """

    scheme = _norm_scheme(observed_scheme)
    http = None if http_available is None else bool(http_available)
    https = None if https_available is None else bool(https_available)
    epa = None if epa_enforced is None else bool(epa_enforced)
    return {
        "observed": bool(scheme),
        "observed_scheme": scheme,
        "http_available": http,
        "https_available": https,
        "epa_enforced": epa,
    }


def _available_label(http: Any, https: Any) -> str:
    """Render the vendor-neutral 'what is exposed' phrase from the two avenues."""

    both = http is True and https is True
    if both:
        return "HTTP and HTTPS"
    if http is True:
        return "HTTP"
    if https is True:
        return "HTTPS"
    return ""


def _epa_label(epa: Any) -> str:
    """Render the client-facing EPA-state phrase (never a port number)."""

    if epa is True:
        return "enforced"
    if epa is False:
        return "not enforced"
    return "not determined"


def _remediation_lines(scheme: str, http: Any, https: Any, epa: Any) -> list[str]:
    """Return the CONDITIONAL, observation-specific ESC8 remediation lines.

    This panel is the ONE home for the enrollment-endpoint fix keyed to the vector
    the assessment actually relayed over. It leads with the single observed fix and
    does not echo the general relay-hardening printed in the finding's remediation
    block (SMB signing, restricting NTLM, hardening coercion triggers). Native,
    client-runnable, vendor-neutral; state the scheme + EPA, never the port.

    * HTTP web enrollment was the avenue (relayed over HTTP, or HTTP open) →
      LEAD with "disable the HTTP enrollment interface, require HTTPS". HTTP has no
      TLS channel to bind, so channel binding cannot protect it; EPA is demoted to
      a defense-in-depth note on the HTTPS endpoint the client keeps.
    * HTTPS was the avenue with EPA not enforced (relayed over HTTPS, which only
      happens EPA-free, or HTTPS open + EPA off) → LEAD with "enforce EPA (channel
      binding) on the HTTPS enrollment site" — that IS the observed fix.
    """

    lines: list[str] = []
    disable_http = http is True or scheme == "http"
    if disable_http:
        lines.append(
            "Disable the HTTP web-enrollment interface on this CA and require HTTPS "
            "for certificate enrollment. HTTP carries no TLS channel to bind, so it "
            "accepts relayed authentication and channel binding cannot protect it."
        )
        # EPA is defense-in-depth here, not a co-equal fix: it only helps the HTTPS
        # endpoint the client keeps after disabling HTTP.
        lines.append(
            "As defense in depth, enforce Extended Protection for Authentication "
            "(channel binding) on the HTTPS enrollment site you keep, so a relayed "
            "session there is bound to its TLS channel and rejected."
        )
        return lines
    # HTTPS was the avenue and EPA is not enforced: enabling EPA is the observed fix.
    https_avenue = https is True or scheme == "https"
    if https_avenue and epa is not True:
        lines.append(
            "Enforce Extended Protection for Authentication (channel binding) on "
            "the HTTPS certificate-enrollment site so a relayed session is bound to "
            "its TLS channel and rejected."
        )
        return lines
    # No observation strong enough to specialise: fall back to the enrollment-
    # endpoint hardening, still native and client-runnable.
    lines.append(
        "Restrict certificate web enrollment: require HTTPS with Extended "
        "Protection for Authentication (channel binding), and disable the HTTP "
        "enrollment interface where it is not required."
    )
    return lines


def esc8_transport_view(block: Any) -> dict[str, Any]:
    """Return the render-ready view of a persisted ``esc8_transport`` block.

    The one shape the PDF report and the web CTEM both read, so the ESC8
    remediation is worded identically wherever a client meets it.

    Returns a mapping with:
      * ``has_observation`` — whether to surface the observed-transport detail;
      * ``observed_scheme`` — ``"HTTP"`` / ``"HTTPS"`` / ``""`` (the relayed one);
      * ``available`` — ``"HTTP"`` / ``"HTTPS"`` / ``"HTTP and HTTPS"`` / ``""``;
      * ``epa`` — ``"enforced"`` / ``"not enforced"`` / ``"not determined"``;
      * ``summary`` — a one-line client statement of the observed transport + EPA;
      * ``remediation_lines`` — the conditional, observation-specific fixes.

    An absent / unreadable block yields ``has_observation=False`` and empty fields
    so a scan predating this record renders exactly as it did before.
    """

    if not isinstance(block, Mapping):
        return {
            "has_observation": False,
            "observed_scheme": "",
            "available": "",
            "epa": "",
            "summary": "",
            "remediation_lines": [],
        }
    scheme = _norm_scheme(block.get("observed_scheme"))
    http = block.get("http_available")
    https = block.get("https_available")
    http = None if http is None else bool(http)
    https = None if https is None else bool(https)
    epa = block.get("epa_enforced")
    epa = None if epa is None else bool(epa)

    observed = bool(block.get("observed")) or bool(scheme)
    scheme_label = _SCHEME_LABELS.get(scheme, "")
    available = _available_label(http, https)
    epa_label = _epa_label(epa)

    # For an HTTP endpoint there is no TLS channel to bind, so EPA is not "undetermined"
    # — it is inapplicable. Say so, rather than implying we failed to measure it.
    http_epa_inapplicable = "channel binding (EPA) does not apply to an HTTP endpoint"

    summary = ""
    if observed and scheme_label:
        epa_clause = (
            http_epa_inapplicable
            if scheme == "http"
            else f"channel binding (EPA) is {epa_label}"
        )
        summary = f"Web enrollment was relayed over {scheme_label}; {epa_clause}."
    elif available:
        epa_clause = (
            http_epa_inapplicable
            if available == "HTTP"
            else f"channel binding (EPA) is {epa_label}"
        )
        summary = f"Web enrollment is exposed over {available}; {epa_clause}."

    return {
        "has_observation": observed or bool(available),
        "observed_scheme": scheme_label,
        "available": available,
        "epa": epa_label,
        "summary": summary,
        "remediation_lines": _remediation_lines(scheme, http, https, epa),
    }


__all__ = [
    "ESC8_TRANSPORT_KEY",
    "build_esc8_transport",
    "esc8_transport_view",
]
