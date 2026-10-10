"""ESC14 exploitation-variant model — pure SSOT (import-light, no network).

ESC14 (weak explicit certificate mapping, KB5014754) has FOUR documented
exploitation variants, all gated by ``StrongCertificateBindingEnforcement``
(SCBE) accepting weak explicit mappings (SCBE 0/1). They differ ONLY in how the
attacker makes an enrolled certificate carry the identifier a victim's weak
``altSecurityIdentities`` mapping matches:

* **A** — a controlling principal WRITES a strong binding onto a TARGET's
  ``altSecurityIdentities`` and enrolls a certificate it controls (ADscan's
  ``run_esc14``; it mutates the TARGET, not a victim).
* **B** — the target already carries an ``X509:<RFC822>`` (email) mapping. Set a
  controlled VICTIM's ``mail`` to that address; the issued certificate's rfc822
  SAN then matches the mapping.
* **C** — the target already carries an ``X509:<I>…<S>…`` (issuer + subject)
  mapping. Rename the controlled victim's ``cn`` so the issued certificate's
  subject matches the ``<S>`` subject.
* **D** — the target already carries an ``X509:<S>…`` (subject-only) mapping. Set
  the controlled victim's ``dNSHostName`` so a machine-template certificate's
  subject matches.

This module is the single place that maps a weak mapping string to its variant,
to the victim attribute each variant mutates, and to the footprint-ordered
execution sequence the attack-path executor dispatches through. It is pure so the
confirmation SSOT and the executor consume one definition, and it is fully
L1-testable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Optional, Sequence

#: Case-insensitive markers that identify each weak explicit mapping form. The
#: short forms (``<I>``/``<S>``/``<RFC822>``) are what AD CS / Schannel store; the
#: long forms (``<ISSUER>``/``<SUBJECT>``) are the human-readable equivalents an
#: administrator may have typed. Both are accepted.
_RFC822_MARKERS = ("<RFC822>",)
_ISSUER_MARKERS = ("<I>", "<ISSUER>")
_SUBJECT_MARKERS = ("<S>", "<SUBJECT>")


class Esc14ExecVariant(str, Enum):
    """One ESC14 exploitation variant (the letter is the client-facing label)."""

    A = "A"  # write a strong binding onto the TARGET's altSecurityIdentities
    B = "B"  # X509RFC822 (email): set the victim's ``mail``
    C = "C"  # X509IssuerSubject: rename the victim's ``cn``
    D = "D"  # X509SubjectOnly: set the victim's ``dNSHostName``


#: The directory attribute each B/C/D variant mutates on the CONTROLLED VICTIM so
#: the enrolled certificate carries the identifier the target's weak mapping
#: matches. Variant A mutates the target's ``altSecurityIdentities`` directly and
#: is intentionally absent here (it is handled by ``run_esc14``).
ESC14_VICTIM_ATTRIBUTE: dict[Esc14ExecVariant, str] = {
    Esc14ExecVariant.B: "mail",
    Esc14ExecVariant.C: "cn",
    Esc14ExecVariant.D: "dNSHostName",
}

#: Footprint-ordered execution preference (lowest footprint first). A reuses the
#: already-validated write-and-enroll path; among the weak-mapping variants, ``B``
#: (add an otherwise-empty ``mail``) is the most benign, ``D`` sets a machine's
#: ``dNSHostName``, and ``C`` renames the RDN (``cn``), the most identity-visible
#: change, so it is attempted last.
ESC14_FOOTPRINT_ORDER: tuple[Esc14ExecVariant, ...] = (
    Esc14ExecVariant.A,
    Esc14ExecVariant.B,
    Esc14ExecVariant.D,
    Esc14ExecVariant.C,
)


def _has_any(haystack: str, markers: Iterable[str]) -> bool:
    return any(marker in haystack for marker in markers)


def classify_weak_binding(value: str) -> Optional[Esc14ExecVariant]:
    """Map a weak ``altSecurityIdentities`` string to its B/C/D variant.

    Returns ``None`` for a value that is not a weak explicit mapping (an empty
    string, a non-``X509:`` value, or a STRONG mapping carrying ``<SR>``/``<SKI>``
    /``<SHA1-PUKEY>`` — those are not exploitable and must never be classified as
    a variant). Variant A is NOT produced here: it is a write-access fact about an
    edge, not a property of an existing mapping string.
    """
    normalized = str(value or "").strip().upper()
    if not normalized.startswith("X509:"):
        return None
    if _has_any(normalized, ("<SR>", "<SKI>", "<SHA1-PUKEY>", "<SHA1PUKEY>")):
        return None  # strong mapping — not an ESC14 avenue
    if _has_any(normalized, _RFC822_MARKERS):
        return Esc14ExecVariant.B
    has_issuer = _has_any(normalized, _ISSUER_MARKERS)
    has_subject = _has_any(normalized, _SUBJECT_MARKERS)
    if has_issuer and has_subject:
        return Esc14ExecVariant.C
    if has_subject:
        return Esc14ExecVariant.D
    return None


def _marker_span(value: str, markers: Iterable[str]) -> Optional[str]:
    """Return the payload following the FIRST present marker (best-effort).

    The payload runs to the next ``<…>`` marker or the end of the string. Matching
    is case-insensitive on the marker while the ORIGINAL-case payload is returned
    (a DN / email keeps its stored casing).
    """
    upper = value.upper()
    for marker in markers:
        idx = upper.find(marker)
        if idx == -1:
            continue
        start = idx + len(marker)
        rest = value[start:]
        next_marker = re.search(r"<[^>]+>", rest)
        return (rest[: next_marker.start()] if next_marker else rest).strip()
    return None


def _cn_from_dn(dn: str) -> Optional[str]:
    """Extract the leading ``CN=`` relative distinguished name value from a DN."""
    match = re.match(r"\s*CN=([^,]+)", dn.strip(), flags=re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return dn.strip() or None


def extract_victim_match_value(
    variant: Esc14ExecVariant, weak_binding: str
) -> Optional[str]:
    """Return the value to write to the victim's attribute for ``variant``.

    * B → the rfc822 address after ``<RFC822>`` (victim ``mail``).
    * C → the CN component of the ``<S>`` subject DN (victim ``cn``).
    * D → the ``<S>`` subject value, with a leading ``CN=`` stripped (victim
      ``dNSHostName``).

    Best-effort parsing of the stored mapping string; returns ``None`` when the
    expected marker is absent so the caller fails honestly rather than writing a
    wrong value.
    """
    value = str(weak_binding or "")
    if variant is Esc14ExecVariant.B:
        return _marker_span(value, _RFC822_MARKERS) or None
    if variant is Esc14ExecVariant.C:
        subject = _marker_span(value, _SUBJECT_MARKERS)
        return _cn_from_dn(subject) if subject else None
    if variant is Esc14ExecVariant.D:
        subject = _marker_span(value, _SUBJECT_MARKERS)
        if not subject:
            return None
        return _cn_from_dn(subject) or subject
    return None


def select_execution_order(
    confirmed: Iterable[Esc14ExecVariant | str],
) -> list[Esc14ExecVariant]:
    """Order the CONFIRMED variants by footprint (lowest first), deduped.

    The attack-path executor dispatches through this: it tries the first, and
    falls back to the next CONFIRMED variant only when execution fails, stopping
    at the first success (one proven compromise is enough — further destructive
    writes add footprint with zero added certainty).
    """
    present: set[Esc14ExecVariant] = set()
    for item in confirmed:
        try:
            present.add(item if isinstance(item, Esc14ExecVariant) else Esc14ExecVariant(str(item)))
        except ValueError:
            continue
    return [variant for variant in ESC14_FOOTPRINT_ORDER if variant in present]


@dataclass(frozen=True)
class Esc14ExecutionStep:
    """One dispatchable ESC14 attempt, footprint-ordered by the plan builder.

    Variant A carries no victim fields (it writes the target directly via
    ``run_esc14``). Variants B/C/D carry the controlled-victim attribute, the value
    to write, and the real target the weak mapping names.
    """

    variant: Esc14ExecVariant
    victim_attribute: Optional[str] = None
    match_value: Optional[str] = None
    target_samaccountname: Optional[str] = None
    target_dn: Optional[str] = None
    weak_binding: Optional[str] = None
    target_is_tier0: bool = False


def _best_target_for_variant(
    variant: Esc14ExecVariant, targets: Sequence[Any]
) -> Optional[dict]:
    """Pick the highest-value target dict for ``variant`` (Tier-0 first).

    ``targets`` are the serialized ``esc14_weak_mapping_targets`` edge notes (each a
    mapping with ``variant`` / ``samaccountname`` / ``distinguished_name`` /
    ``match_value`` / ``victim_attribute`` / ``weak_binding`` / ``is_tier0``).
    """
    candidates = [
        t
        for t in targets
        if isinstance(t, dict)
        and str(t.get("variant") or "").strip().upper() == variant.value
        and str(t.get("match_value") or "").strip()
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda t: (0 if t.get("is_tier0") else 1))
    return candidates[0]


def build_esc14_execution_plan(
    *,
    confirmed_variants: Iterable[Esc14ExecVariant | str],
    weak_mapping_targets: Sequence[Any] = (),
    has_write_access_puppet: bool = False,
) -> list[Esc14ExecutionStep]:
    """Build the footprint-ordered, confirmed-only ESC14 execution plan (pure).

    The executor runs the plan in order, falling back to the next entry only when
    an attempt fails and stopping at the first success — one proven compromise is
    enough, and further destructive writes add footprint with zero added certainty.

    * Variant A is included only when a write-access puppet is resolvable (A needs
      a target whose ``altSecurityIdentities`` the actor can write).
    * Each B/C/D variant contributes ONE entry, against its highest-value target.
    """
    plan: list[Esc14ExecutionStep] = []
    for variant in select_execution_order(confirmed_variants):
        if variant is Esc14ExecVariant.A:
            if has_write_access_puppet:
                plan.append(Esc14ExecutionStep(variant=Esc14ExecVariant.A))
            continue
        target = _best_target_for_variant(variant, weak_mapping_targets)
        if target is None:
            continue
        plan.append(
            Esc14ExecutionStep(
                variant=variant,
                victim_attribute=ESC14_VICTIM_ATTRIBUTE.get(variant),
                match_value=str(target.get("match_value") or "").strip() or None,
                target_samaccountname=str(target.get("samaccountname") or "").strip()
                or None,
                target_dn=str(target.get("distinguished_name") or "").strip() or None,
                weak_binding=str(target.get("weak_binding") or "").strip() or None,
                target_is_tier0=bool(target.get("is_tier0")),
            )
        )
    return plan


__all__ = [
    "Esc14ExecVariant",
    "Esc14ExecutionStep",
    "ESC14_VICTIM_ATTRIBUTE",
    "ESC14_FOOTPRINT_ORDER",
    "classify_weak_binding",
    "extract_victim_match_value",
    "select_execution_order",
    "build_esc14_execution_plan",
]
