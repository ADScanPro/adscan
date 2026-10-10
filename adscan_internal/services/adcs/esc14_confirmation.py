"""ESC14 (weak explicit certificate mapping) collection-time confirmation — pure SSOT.

The passive LDAP detector (``collector/adcs_detectors/esc14.py``) emits an
``ADCSESC14`` candidate from the TEMPLATE shape plus the ENROLLMENT principals that
hold a right on it (``get_enroll_principal_sids``) — it does NOT establish either
real ESC14 existence condition. ESC14 is exploitable only when BOTH hold:

1. the domain controllers still accept a WEAK explicit ``altSecurityIdentities``
   mapping — governed by ``StrongCertificateBindingEnforcement`` (SCBE) under
   KB5014754: accepted at SCBE 0 (Disabled) / 1 (Compatibility), REFUSED at 2
   (Full); AND
2. there is a concrete abusable mapping / write access:
   * **variant A** — a principal that controls the edge can WRITE a target's
     ``altSecurityIdentities`` (so it plants a weak mapping to a cert it obtains);
   * **variants B/C/D** — a reachable target ALREADY carries a weak-form mapping
     (``X509IssuerSubject`` / ``X509SubjectOnly`` / ``X509RFC822``-email) that an
     enroller can satisfy with an enrolled certificate.

SCBE < 2 ALONE is NECESSARY but NOT SUFFICIENT: on a default domain (SCBE == 1)
every template-shape edge would otherwise be stamped CONFIRMED critical with zero
proof of exploitability — the exact over-report this confirmation exists to kill.
So CONFIRMED requires SCBE < 2 **and** condition #2 established; SCBE < 2 with
neither write access nor a weak mapping stays confirmation-pending.

This module holds the PURE, import-light decision logic. The network/credential
driver (:mod:`adscan_internal.cli.esc14_confirmation_phase`) supplies the two
established facts it reads from production SSOTs: condition #2(a) via the executor's
``_resolve_esc9_puppet_user`` (the collector's write-ACL + group-closure result,
baked onto the edge as a ``role=puppet`` resource) and condition #2(b) via
``AltSecurityIdentitiesService.find_users_with_weak_altsecurityidentities`` (an LDAP
read). Both are READS, so the confirmation is non-destructive — no certificate is
issued.

Verdict -> collection action:

* ``REMOVE_HARDENED`` -> every DC enforces SCBE Full (== 2), so the WEAK-mapping
  existence condition is absent domain-wide: REMOVE the SCBE-gated edges (variants
  B/C/D and implicit mappings) and record a positive control. This does NOT apply to
  a **variant A** (write-access) edge: variant A plants a STRONG explicit mapping
  that the KDC honors regardless of SCBE, so a hardened SCBE never removes it and it
  never earns a positive control (see ``KEEP_CONFIRMED`` below). SCBE Full only
  closes the weak / implicit avenues.
* ``KEEP_CONFIRMED`` -> either (a) a DC accepts weak mappings (SCBE < 2) AND
  condition #2 is established for the edge (variant A write access, or a domain-wide
  weak mapping for B/C/D); or (b) a **variant A** (write-access) edge under Full
  SCBE. Variant A is confirmed on write access ALONE at every SCBE level: it plants a
  STRONG explicit mapping (``X509IssuerSerialNumber``) the KDC honors even under Full
  enforcement, lab-proven on a patched DC — a plain Machine certificate authenticates
  as a different target via the strong mapping and succeeds, so no no-SID-extension /
  ESC9-shaped template is required. Under Full only variant A is confirmed (the weak
  B/C/D avenues stay closed). KEEP and stamp confirmed with the variant.
* ``KEEP_PENDING`` -> SCBE < 2 but condition #2 NOT established, OR SCBE could not
  be read / is indeterminate, OR opt-out / no credential. Never a flat CONFIRMED on
  SCBE < 2 alone.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional, Sequence

#: Opt-out env (mirrors ``ADSCAN_NO_ESC15_CONFIRM`` / ``ADSCAN_NO_POISONING``): skip
#: the active ESC14 confirmation entirely. The edge then falls to
#: confirmation-pending (never silently dropped, never a flat critical).
ESC14_CONFIRM_DISABLED_ENV = "ADSCAN_NO_ESC14_CONFIRM"

_TRUTHY = {"1", "true", "yes", "on"}

_ESC14_RELATION = "ADCSESC14"

#: SCBE value at/above which weak explicit mappings are refused (KB5014754 "Full").
_SCBE_FULL_ENFORCEMENT = 2


def esc14_confirmation_disabled() -> bool:
    """Return True when the active ESC14 confirmation phase is opted out."""
    return str(os.environ.get(ESC14_CONFIRM_DISABLED_ENV, "")).strip().lower() in _TRUTHY


class Esc14CollectionAction(str, Enum):
    """What the collection phase does to an ESC14 edge given a confirm verdict."""

    KEEP_CONFIRMED = "keep_confirmed"
    REMOVE_HARDENED = "remove_hardened"
    KEEP_PENDING = "keep_pending"


class Esc14Variant(str, Enum):
    """Which ESC14 abuse variant established condition #2 for a confirmed edge."""

    #: Variant A — a controlling principal can WRITE the target's altSecurityIdentities.
    WRITE_ACCESS = "A"
    #: Variants B/C/D — a reachable target already carries a weak-form mapping.
    WEAK_MAPPING = "B/C/D"


class ScbeState(str, Enum):
    """Domain-wide StrongCertificateBindingEnforcement posture."""

    #: At least one reachable DC accepts weak explicit mappings (SCBE < 2).
    WEAK = "weak"
    #: Every known DC was read and all enforce Full (== 2).
    HARDENED = "hardened"
    #: Could not conclude (no DC read, value absent, or partial coverage).
    UNKNOWN = "unknown"


class ScbeBasis(str, Enum):
    """How a :class:`ScbeVerdict` was established.

    The extension point for the shared ``scbe_observation`` SSOT: a registry read
    (the default, what ESC14 and the SSOT produce) vs a behavioral observation (the
    ESC9 canary upgrading an UNKNOWN-registry verdict from a code-66 PKINIT refusal
    of a self no-SID certificate — an OBSERVATION of effective enforcement, not an
    absence). ESC6/ESC14 may later adopt the behavioral basis on absent-SCBE DCs
    without redesign.
    """

    #: Read from ``StrongCertificateBindingEnforcement`` over Remote Registry.
    REGISTRY = "registry"
    #: Inferred from a behavioral canary (a PKINIT accept/refuse observation).
    BEHAVIORAL = "behavioral"


@dataclass(frozen=True)
class Esc14DcReading:
    """One DC's StrongCertificateBindingEnforcement reading.

    Attributes:
        host: The DC identifier the read targeted (for the reason string).
        read_succeeded: Whether the Remote-Registry connection itself succeeded.
            ``False`` means the DC could not be reached / authenticated — a data
            gap, NOT evidence of hardening.
        scbe: ``StrongCertificateBindingEnforcement`` DWORD, or ``None`` when the
            registry was reachable but the value is absent (indeterminate effective
            mode — never treated as Full).
        cert_mapping_methods: ``CertificateMappingMethods`` DWORD (Schannel), carried
            for the report evidence; not part of the decisive gate.
    """

    host: str
    read_succeeded: bool
    scbe: Optional[int] = None
    cert_mapping_methods: Optional[int] = None


@dataclass(frozen=True)
class ScbeVerdict:
    """The resolved domain-wide SCBE posture and the evidence behind it."""

    state: ScbeState
    reason: str
    scbe: Optional[int] = None
    cert_mapping_methods: Optional[int] = None
    #: How this verdict was established (registry read vs behavioral canary). The
    #: shared ``scbe_observation`` SSOT produces REGISTRY; the ESC9 behavioral
    #: canary constructs a BEHAVIORAL verdict for its own decision.
    basis: ScbeBasis = ScbeBasis.REGISTRY


@dataclass(frozen=True)
class Esc14WeakMappingTarget:
    """One reachable account carrying a weak explicit mapping (variants B/C/D).

    Resolved by the confirmation driver from the ``AltSecurityIdentitiesService``
    SSOT and carried onto every confirmed ESC14 edge so the executor can dispatch
    the B/C/D variant against the real account the weak mapping names — IP for the
    connect, the stored DN for the LDAP write.

    Attributes:
        variant: The B/C/D variant letter this mapping enables.
        samaccountname: The target account's sAMAccountName.
        distinguished_name: The target account's DN.
        weak_binding: The exact weak ``altSecurityIdentities`` value.
        victim_attribute: The directory attribute the executor mutates on the
            controlled victim (``mail`` / ``cn`` / ``dNSHostName``).
        match_value: The value to write to ``victim_attribute`` so the enrolled
            certificate matches the mapping.
        is_tier0: Whether the target is a Tier-0 / high-value account (the most
            dangerous ESC14 target).
    """

    variant: str
    samaccountname: str
    distinguished_name: str
    weak_binding: str
    victim_attribute: str
    match_value: str
    is_tier0: bool = False

    def as_note(self) -> dict[str, Any]:
        """Serialize for an edge-note list (JSON-safe, report/web consumable)."""
        return {
            "variant": self.variant,
            "samaccountname": self.samaccountname,
            "distinguished_name": self.distinguished_name,
            "weak_binding": self.weak_binding,
            "victim_attribute": self.victim_attribute,
            "match_value": self.match_value,
            "is_tier0": self.is_tier0,
        }


@dataclass(frozen=True)
class Esc14EdgeDecision:
    """The resolved action for ONE ESC14 edge and the evidence behind it."""

    action: Esc14CollectionAction
    reason: str
    variant: Optional[Esc14Variant] = None
    scbe: Optional[int] = None
    cert_mapping_methods: Optional[int] = None
    #: The FULL set of confirmed variant letters for this edge (``A`` from write
    #: access, plus any of ``B``/``C``/``D`` from reachable weak mappings), ordered
    #: by footprint. Empty for a PENDING / REMOVE decision. The client must see how
    #: many avenues are open, not just the first found.
    confirmed_variants: tuple[str, ...] = field(default_factory=tuple)
    #: The weak-mapping targets (B/C/D) the executor can act against.
    weak_mapping_targets: tuple[Esc14WeakMappingTarget, ...] = field(
        default_factory=tuple
    )


def classify_scbe_state(
    readings: Sequence[Esc14DcReading], *, total_dc_count: int
) -> ScbeVerdict:
    """Map the per-DC SCBE readings to the domain-wide posture (pure).

    Conservative: a false "hardened" removes a REAL finding, so hardened requires
    covering every known DC with a concrete Full reading. A reachable DC reporting
    SCBE < 2 makes the domain WEAK; anything short of full coverage (or no reachable
    DC, or an absent value) is UNKNOWN.
    """
    reachable = [r for r in readings if r.read_succeeded]
    weak = [r for r in reachable if r.scbe is not None and r.scbe < _SCBE_FULL_ENFORCEMENT]
    if weak:
        w = weak[0]
        return ScbeVerdict(
            state=ScbeState.WEAK,
            reason=(
                "a domain controller accepts weak explicit certificate mappings "
                f"(StrongCertificateBindingEnforcement = {w.scbe}, below Full "
                "enforcement)"
            ),
            scbe=w.scbe,
            cert_mapping_methods=w.cert_mapping_methods,
        )

    full = [r for r in reachable if r.scbe is not None and r.scbe >= _SCBE_FULL_ENFORCEMENT]
    all_dcs_covered = (
        total_dc_count > 0
        and len(full) >= total_dc_count
        and len(full) == len(reachable)
    )
    if full and all_dcs_covered:
        return ScbeVerdict(
            state=ScbeState.HARDENED,
            reason=(
                "every domain controller enforces StrongCertificateBindingEnforcement "
                "= Full (2), so weak explicit certificate mappings are refused"
            ),
            scbe=_SCBE_FULL_ENFORCEMENT,
            cert_mapping_methods=full[0].cert_mapping_methods,
        )

    if not reachable:
        reason = (
            "StrongCertificateBindingEnforcement could not be read on any domain "
            "controller (Remote Registry unreachable; data gap)"
        )
    elif full:
        reason = (
            "StrongCertificateBindingEnforcement is Full on the domain controllers "
            "read, but enforcement could not be verified on every domain controller"
        )
    else:
        reason = (
            "the StrongCertificateBindingEnforcement registry value is not set, so "
            "the effective binding enforcement mode could not be determined"
        )
    return ScbeVerdict(state=ScbeState.UNKNOWN, reason=reason)


def _confirmed_variant_letters(
    *,
    has_write_access: bool,
    weak_mapping_targets: Sequence["Esc14WeakMappingTarget"],
) -> tuple[str, ...]:
    """Footprint-order the full set of confirmed variant letters for one edge."""
    from adscan_internal.services.adcs.esc14_variants import select_execution_order

    letters: list[str] = ["A"] if has_write_access else []
    letters.extend(t.variant for t in weak_mapping_targets)
    return tuple(v.value for v in select_execution_order(letters))


def resolve_edge_action(
    scbe: ScbeVerdict,
    *,
    has_write_access: bool,
    domain_has_weak_mapping: bool,
    weak_mapping_targets: Sequence["Esc14WeakMappingTarget"] = (),
) -> Esc14EdgeDecision:
    """Resolve ONE ESC14 edge's action from the SCBE posture + condition #2 (pure).

    * HARDENED SCBE -> REMOVE the SCBE-GATED avenues (variants B/C/D and implicit
      mappings; a weak mapping is useless when the DC refuses it) and record a
      positive control. EXCEPT a **variant A** (write-access) edge: variant A plants
      a STRONG explicit ``altSecurityIdentities`` mapping (``X509IssuerSerialNumber``,
      carrying ``<SR>``), which SCBE Full does NOT close. Variant A is confirmed on
      WRITE ACCESS ALONE at every SCBE level (lab-proven on a patched DC at Full): a
      plain Machine certificate authenticating as a different target via the strong
      X509IssuerSerialNumber mapping succeeds under Full enforcement, so no
      no-SID-extension / ESC9-shaped template is required. The edge is therefore
      KEEP_CONFIRMED (variant A) under Full and never recorded as "hardened away";
      SCBE Full only closes the weak / implicit avenues.
    * UNKNOWN SCBE -> PENDING (the decisive gate could not be read).
    * WEAK SCBE -> CONFIRMED only when condition #2 is established: variant A (this
      edge carries proven write access to a target's altSecurityIdentities) or
      variants B/C/D (a reachable target already carries a weak-form mapping). WEAK
      SCBE with neither -> PENDING.

    When ``weak_mapping_targets`` are supplied the decision also carries the FULL
    confirmed-variant set (``confirmed_variants``) and the targets, so the client
    sees every open avenue and the executor can dispatch any of them. The scalar
    ``variant`` (the primary / lowest-footprint one) is preserved for backward
    compatibility.
    """
    if scbe.state is ScbeState.HARDENED:
        if has_write_access:
            # Variant A plants a STRONG explicit mapping (X509IssuerSerialNumber),
            # which the KDC honors at EVERY SCBE level — it is NOT gated by the weak-
            # mapping Full enforcement and NOT gated by the enrolling certificate's
            # SID security extension. Lab-proven on a patched DC (SCBE Full): a plain
            # Machine certificate with a mismatched SID extension PKINITs as a
            # different target via the strong mapping and succeeds, provided the
            # mapping's issuer DN is in root-first order. So write access alone
            # confirms variant A under Full. Under Full the weak B/C/D avenues stay
            # closed, so only variant A is confirmed. KEEP_CONFIRMED ->
            # result.confirmed, which suppresses the hardened positive control for the
            # domain (ESC14 remains exploitable).
            return Esc14EdgeDecision(
                action=Esc14CollectionAction.KEEP_CONFIRMED,
                reason=(
                    "a controlling principal holds write access to a target's "
                    "altSecurityIdentities (variant A), which plants a strong "
                    "certificate mapping the KDC honors even under strong certificate "
                    "binding enforcement (Full)"
                ),
                variant=Esc14Variant.WRITE_ACCESS,
                scbe=scbe.scbe,
                cert_mapping_methods=scbe.cert_mapping_methods,
                confirmed_variants=("A",),
            )
        return Esc14EdgeDecision(
            action=Esc14CollectionAction.REMOVE_HARDENED,
            reason=scbe.reason,
            scbe=scbe.scbe,
            cert_mapping_methods=scbe.cert_mapping_methods,
        )
    if scbe.state is ScbeState.UNKNOWN:
        return Esc14EdgeDecision(
            action=Esc14CollectionAction.KEEP_PENDING,
            reason=scbe.reason,
            scbe=scbe.scbe,
            cert_mapping_methods=scbe.cert_mapping_methods,
        )
    # WEAK — a DC accepts weak mappings; confirm only with a real condition #2.
    targets = tuple(weak_mapping_targets or ())
    has_weak_mapping = bool(domain_has_weak_mapping or targets)
    confirmed_variants = _confirmed_variant_letters(
        has_write_access=has_write_access, weak_mapping_targets=targets
    )
    if has_write_access:
        return Esc14EdgeDecision(
            action=Esc14CollectionAction.KEEP_CONFIRMED,
            reason=(
                scbe.reason
                + ", and a controlling principal holds write access to a target's "
                "altSecurityIdentities (variant A), so a weak mapping can be planted "
                "and abused"
            ),
            variant=Esc14Variant.WRITE_ACCESS,
            scbe=scbe.scbe,
            cert_mapping_methods=scbe.cert_mapping_methods,
            confirmed_variants=confirmed_variants,
            weak_mapping_targets=targets,
        )
    if has_weak_mapping:
        return Esc14EdgeDecision(
            action=Esc14CollectionAction.KEEP_CONFIRMED,
            reason=(
                scbe.reason
                + ", and a reachable account already carries a weak-form "
                "altSecurityIdentities mapping (variant B/C/D) an enroller can satisfy"
            ),
            variant=Esc14Variant.WEAK_MAPPING,
            scbe=scbe.scbe,
            cert_mapping_methods=scbe.cert_mapping_methods,
            confirmed_variants=confirmed_variants,
            weak_mapping_targets=targets,
        )
    return Esc14EdgeDecision(
        action=Esc14CollectionAction.KEEP_PENDING,
        reason=(
            scbe.reason
            + ", but no abusable altSecurityIdentities mapping or write access was "
            "verified — confirmation pending"
        ),
        scbe=scbe.scbe,
        cert_mapping_methods=scbe.cert_mapping_methods,
    )


def esc14_edge_notes_update(decision: Esc14EdgeDecision) -> dict[str, Any]:
    """Build the notes to merge onto a KEPT ESC14 edge for ``decision``.

    ``esc14_confirmed`` / ``confirmation_pending`` are the markers the report and web
    CTEM read (via ``attack_graph_findings`` lifting them to the finding details).
    Only valid for the KEEP actions; REMOVE drops the edge so it carries no notes.
    """
    update: dict[str, Any] = {
        "confirm_verdict": decision.action.value,
        "confirmation_reason": decision.reason,
    }
    if decision.scbe is not None:
        update["strong_certificate_binding_enforcement"] = decision.scbe
    if decision.cert_mapping_methods is not None:
        update["certificate_mapping_methods"] = decision.cert_mapping_methods
    if decision.action is Esc14CollectionAction.KEEP_CONFIRMED:
        update["esc14_confirmed"] = True
        update["confirmation_pending"] = False
        if decision.variant is not None:
            update["esc14_variant"] = decision.variant.value
        if decision.confirmed_variants:
            # The FULL set of confirmed avenues (A and/or B/C/D), footprint-ordered.
            update["esc14_variants"] = list(decision.confirmed_variants)
        if decision.weak_mapping_targets:
            update["esc14_weak_mapping_targets"] = [
                t.as_note() for t in decision.weak_mapping_targets
            ]
    else:  # KEEP_PENDING
        update["esc14_confirmed"] = False
        update["confirmation_pending"] = True
    return update


def graph_has_esc14_edges(graph: dict[str, Any]) -> bool:
    """Return whether the graph carries at least one ADCSESC14 edge."""
    edges = graph.get("edges")
    if not isinstance(edges, list):
        return False
    return any(
        isinstance(edge, dict)
        and str(edge.get("relation") or "").strip() == _ESC14_RELATION
        for edge in edges
    )


@dataclass(frozen=True)
class Esc14ApplyResult:
    """Counts from applying the ESC14 confirmation to a graph."""

    removed: int = 0
    confirmed: int = 0
    pending: int = 0


def apply_esc14_confirmation_to_graph(
    graph: dict[str, Any],
    scbe: ScbeVerdict,
    *,
    domain_has_weak_mapping: bool,
    has_write_access: Callable[[dict[str, Any]], bool],
    weak_mapping_targets: Sequence["Esc14WeakMappingTarget"] = (),
) -> Esc14ApplyResult:
    """Resolve + apply each ESC14 edge's action in place (pure given the inputs).

    ``has_write_access`` is injected by the driver so the pure SSOT never imports the
    executor's puppet resolver; it answers condition #2(a) per edge.
    ``domain_has_weak_mapping`` answers the domain-wide condition #2(b); when the
    richer ``weak_mapping_targets`` are supplied they drive the full confirmed-variant
    annotation AND satisfy condition #2(b) on their own (a non-empty sequence implies
    a weak mapping exists), so both inputs stay consistent.

    Returns:
        An :class:`Esc14ApplyResult` with the removed / confirmed / pending counts.
    """
    edges = graph.get("edges")
    if not isinstance(edges, list):
        return Esc14ApplyResult()

    targets = tuple(weak_mapping_targets or ())
    kept: list[Any] = []
    removed = confirmed = pending = 0
    for edge in edges:
        if (
            not isinstance(edge, dict)
            or str(edge.get("relation") or "").strip() != _ESC14_RELATION
        ):
            kept.append(edge)
            continue
        decision = resolve_edge_action(
            scbe,
            has_write_access=bool(has_write_access(edge)),
            domain_has_weak_mapping=domain_has_weak_mapping,
            weak_mapping_targets=targets,
        )
        if decision.action is Esc14CollectionAction.REMOVE_HARDENED:
            removed += 1
            continue
        notes = edge.get("notes")
        if not isinstance(notes, dict):
            notes = {}
            edge["notes"] = notes
        notes.update(esc14_edge_notes_update(decision))
        if decision.action is Esc14CollectionAction.KEEP_CONFIRMED:
            confirmed += 1
        else:
            pending += 1
        kept.append(edge)

    if removed:
        graph["edges"] = kept
    return Esc14ApplyResult(removed=removed, confirmed=confirmed, pending=pending)


__all__ = [
    "ESC14_CONFIRM_DISABLED_ENV",
    "esc14_confirmation_disabled",
    "Esc14CollectionAction",
    "Esc14Variant",
    "ScbeState",
    "ScbeBasis",
    "Esc14DcReading",
    "ScbeVerdict",
    "Esc14EdgeDecision",
    "Esc14WeakMappingTarget",
    "Esc14ApplyResult",
    "classify_scbe_state",
    "resolve_edge_action",
    "esc14_edge_notes_update",
    "graph_has_esc14_edges",
    "apply_esc14_confirmation_to_graph",
]
