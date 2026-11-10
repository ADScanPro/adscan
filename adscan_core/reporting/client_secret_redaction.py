"""A recovered secret value never leaves through a client artifact; its shape may.

**The store is the unsanitized side; every document is the sanitized side.** The
credential store (``variables.json``) and the graph retention sidecar hold the
recovered values on purpose: the operator needs them, and the terminal prints
them in cleartext (wrapped in ``mark_sensitive`` so telemetry scrubs them). A
CLIENT artifact is a different thing. ``technical_report.json`` feeds the PDF
kit, the LITE report and the Enterprise platform's database and API, so it is
written, read and rendered here without the values.

``mark_sensitive`` is not a mask for that purpose. Its markers are invisible:
the value inside them renders verbatim in an HTML or PDF page, and only the
telemetry exporter knows to remove it. So a client surface must never be handed
the value at all, which is what this module guarantees.

Three primitives, one owner:

* :func:`redact_client_secrets` returns a copy of any JSON-shaped projection
  with every key-named secret replaced by the value-free reference the attack
  graph already uses (:mod:`adscan_core.graph_secret_refs`: the account it
  belongs to, the kind, and a ``secret_recovered`` marker), and every free-text
  field that carries a secret by construction withheld. Account NAMES are never
  touched; only the secret is.
* :func:`redact_report_secrets` applies the same to a parsed
  ``technical_report.json`` in place. The writer calls it before every save and
  :func:`adscan_core.reporting.finding_aliases.normalize_technical_report` (the
  one read normalizer the engine loader, the web ingestion and the web live
  readers share) calls it on every read, so a report written by an older build
  is clean the moment anything opens it.
* :func:`client_secret_display` is what a renderer prints where a recovered
  secret was: ``[redacted: 12 characters]``. The shape is the convention the
  writeup already uses (:func:`mask_secret_to_shape`, owned here and re-exported
  by ``writeup_credential_disclosure``); it is evidence (a 32-hex value is a hash
  pulled from the directory, a 12-character value is a login credential) without
  being the secret.

There is no deliverable opt-in to print values. ``adscan writeup
--full-credentials`` is the one document allowed to carry them, and it reads the
credential store directly, never these projections.

Stdlib only: imported by the engine, the report renderers and the web backend.
"""

from __future__ import annotations

import re
from typing import Any

from adscan_core.graph_secret_refs import redact_secrets_deep

#: Fields whose value is FREE TEXT that holds a secret by construction, so a
#: key-based reference cannot stand in for it and the field is withheld whole:
#:
#: * ``matched_text`` / ``matched_value``: the directory-attribute text that
#:   matched a secret pattern (a description reading "temp password ...").
#:   The record keeps the account and the attribute name, which is what the
#:   client needs to go and clear it.
#: * ``raw_output``: a tool's raw stdout, which echoes the credential it ran
#:   with. Written by older builds; nothing renders it.
FREE_TEXT_SECRET_KEYS: frozenset[str] = frozenset(
    {"matched_text", "matched_value", "raw_output"}
)

#: What a renderer prints when only the fact of a recovery is known.
REDACTED_SECRET_DISPLAY = "[redacted]"

_HEX_ONLY = re.compile(r"^[0-9a-fA-F]+$")


def mask_secret_to_shape(value: Any) -> str:
    """Return the SHAPE of a secret: its length and whether it is hex.

    Deliberately not a prefix or a first/last character: a few characters of an
    employee password are a few characters of that password. The shape is what
    a reader needs to read the row as evidence.
    """
    text = str(value or "").strip()
    if not text:
        return ""
    noun = "character" if len(text) == 1 else "characters"
    if _HEX_ONLY.match(text):
        return f"{len(text)} hex {noun}"
    return f"{len(text)} {noun}"


def client_secret_display(value: Any = None) -> str:
    """Return what a client surface prints in place of a recovered secret.

    ``[redacted: <shape>]`` when the value is known to the renderer,
    ``[redacted]`` when only the fact of the recovery is (a reference).
    """
    shape = mask_secret_to_shape(value)
    return f"[redacted: {shape}]" if shape else REDACTED_SECRET_DISPLAY


def _strip_free_text(obj: Any) -> tuple[Any, bool]:
    if isinstance(obj, dict):
        changed = False
        out: dict[Any, Any] = {}
        for key, value in obj.items():
            if key in FREE_TEXT_SECRET_KEYS and value not in (None, "", [], {}):
                changed = True
                continue
            walked, sub_changed = _strip_free_text(value)
            changed = changed or sub_changed
            out[key] = walked
        return out, changed
    if isinstance(obj, list):
        changed = False
        items = []
        for item in obj:
            walked, sub_changed = _strip_free_text(item)
            changed = changed or sub_changed
            items.append(walked)
        return items, changed
    return obj, False


def redact_client_secrets(obj: Any) -> Any:
    """Return a copy of *obj* that carries no recovered secret value.

    Never mutates *obj*. Idempotent: redacting an already-redacted projection
    returns an equal one.
    """
    stripped, _ = _strip_free_text(obj)
    return redact_secrets_deep(stripped)


def redact_report_secrets(report: Any) -> bool:
    """Redact a parsed ``technical_report.json`` IN PLACE.

    Returns ``True`` when anything was removed, so a caller holding the file can
    decide whether to persist the cleaned shape.
    """
    if not isinstance(report, dict):
        return False
    changed = False
    for key in list(report.keys()):
        value = report[key]
        if not isinstance(value, (dict, list)):
            continue
        redacted = redact_client_secrets(value)
        if redacted != value:
            report[key] = redacted
            changed = True
    return changed


__all__ = (
    "FREE_TEXT_SECRET_KEYS",
    "REDACTED_SECRET_DISPLAY",
    "client_secret_display",
    "mask_secret_to_shape",
    "redact_client_secrets",
    "redact_report_secrets",
)
