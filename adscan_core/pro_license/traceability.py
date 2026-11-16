"""Which licence produced a run or a deliverable (a watermark, never a secret).

A leaked build, report or workspace has to be traceable to the grant that
produced it. Every identifier here is one the licence server issued and keeps
in its own records: the grant id, the licence document id and the
installation id. None of them is a secret (no activation key, no private key,
no domain name), and none of them helps anyone use the licence, so they can
travel with an artefact. LITE and an unlicensed PRO carry nothing.

* :func:`licence_trace` — the identifiers of the installed, verified licence.
* :func:`stamp_pdf` — the same identifiers in a PDF's document information,
  appended as an incremental update so the rendered page content (fonts, text
  layer) is byte-for-byte what the renderer produced.

The run record (``technical_report.json``) carries the same block as
``licence`` (:mod:`adscan_core.reporting.technical_report`).
"""

from __future__ import annotations

import io
from typing import Any

#: PDF document-information key carrying the trace (not shown by readers).
PDF_TRACE_KEY = "/ADscanLicence"


def licence_trace() -> dict[str, str] | None:
    """``{license_id, grant_id, installation_id, edition, partner_tag}``, or None. Never raises."""
    try:
        from adscan_core.pro_license.identity import installed_licence_identity

        identity = installed_licence_identity()
        if identity is None:
            return None
        return {
            "license_id": identity.license_id,
            "grant_id": identity.grant_id,
            "installation_id": identity.installation_id,
            "edition": identity.edition,
            "partner_tag": identity.partner_tag,
        }
    except Exception:  # noqa: BLE001 - provenance never breaks a run
        return None


def trace_string(trace: dict[str, Any]) -> str:
    """The compact form written into a PDF."""
    return ";".join(
        f"{key}={trace.get(key) or '-'}" for key in ("grant_id", "license_id", "installation_id", "edition")
    )


def stamp_pdf(pdf_bytes: bytes, trace: dict[str, Any] | None = None) -> bytes:
    """Return ``pdf_bytes`` with the licence trace appended; unchanged without a licence.

    An incremental update: the original bytes are kept as they are and a new
    document-information dictionary is appended, so nothing the renderer laid
    out (pagination, embedded fonts, the searchable text) can change. Any
    failure returns the original bytes.
    """
    trace = trace if trace is not None else licence_trace()
    if not trace or not pdf_bytes:
        return pdf_bytes
    try:
        from pypdf import PdfWriter

        writer = PdfWriter(io.BytesIO(pdf_bytes), incremental=True)
        writer.add_metadata({PDF_TRACE_KEY: trace_string(trace)})
        out = io.BytesIO()
        writer.write(out)
        stamped = out.getvalue()
        return stamped if stamped.startswith(pdf_bytes) else pdf_bytes
    except Exception:  # noqa: BLE001 - an unstamped report beats no report
        return pdf_bytes


__all__ = ["PDF_TRACE_KEY", "licence_trace", "stamp_pdf", "trace_string"]
