"""Canonical edge severity — fourth dimension of the ADscan attack-graph model.

Severity is **not** a property of an edge. It is a **pure function** of:

* the source's :class:`CompromiseClass`
* the target's :class:`CompromiseClass`
* the edge's :class:`EdgeKind`
* the target's own :class:`PrivilegeTier` — graded, not a flat boolean: a
  ``TIER0_DIRECT`` asset (a DC, the Domain object) outranks a
  ``TIER0_ESCALATION_CAPABLE`` asset (an ADCS CA / Cert Publishers host /
  Exchange). Both are Tier 0; they are not equal.
* the edge's :class:`ControlStrength` — refines auth edges so a full local
  admin (``AdminTo``) outranks a session shell (``CanRDP``/``CanPSRemote``)
  outranks a DB sysadmin (``SQLAdmin``) outranks a DB session (``SQLAccess``)
  into the same target.
* whether the target is the Domain object itself

This separation resolves the false-positive observed on HTB Forest, where the
``Tactical Findings`` panel rendered 444 ``CRIT`` entries — >95% of which were
tautologies of the AD hierarchy (``Administrators -DCSync-> HTB.LOCAL``,
``Enterprise Admins -GenericAll-> HTB.LOCAL``, etc.). Those edges are not
findings; they are the definition of the Microsoft product. When everything is
critical, nothing is.

Reference: ``adscan-obsidian/business/12_nomenclature_standard.md`` §
"Severidad de edges — cuarta dimensión canónica" and ``CLAUDE.md`` §
"Edge severity — fourth canonical dimension".

This module is the single source of truth. CLI panel, report writer and web
app must consume :func:`compute_edge_severity` — never recompute.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from adscan_core.rich_output import print_warning

from adscan_internal.services.compromise_class import CompromiseClass, PrivilegeTier
from adscan_internal.services.edge_kind import ControlStrength, EdgeKind


class Severity(str, Enum):
    """Canonical severity levels for attack-graph edges.

    ``STRUCTURAL`` is reserved for ``MemberOf`` and similar topology edges
    that have no severity of their own — they only contribute to path
    materialization.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    STRUCTURAL = "STRUCTURAL"


# Per-process cache so an unknown EdgeKind warning fires once, not once per
# edge — a single Forest run can hit thousands of edges.
_WARNED_UNKNOWN_KIND: set[str] = set()


@dataclass(frozen=True)
class EdgeSeverityInput:
    """Input bundle for :func:`compute_edge_severity`.

    Attributes:
        source_compromise_class: The source principal's canonical compromise
            class. ``None`` denotes "low-priv / unclassified" — treated as
            equivalent to :attr:`CompromiseClass.COMPROMISE_ENABLER` for
            severity purposes (any unprivileged origin is symmetric).
        target_compromise_class: The target's canonical compromise class.
            ``None`` denotes a target with no membership-based classification
            (e.g. a regular user/computer that is not in any privileged
            group). Combined with the target tier and ``target_is_domain`` to
            determine the severity row.
        edge_kind: The canonical :class:`EdgeKind` of the edge. Use
            :func:`adscan_internal.services.edge_kind.classify_edge_kind`
            to derive it from a relation label.
        target_privilege_tier: The target's own :class:`PrivilegeTier`, graded.
            ``TIER0_DIRECT`` (a DC, the Domain object) outranks
            ``TIER0_ESCALATION_CAPABLE`` (an ADCS CA / Cert Publishers host /
            Exchange) — both are inside the Tier 0 boundary but reaching the
            former is the worse finding. Resolve it from the target node's role
            via :func:`compromise_class.privilege_tier_for_computer` /
            :func:`privilege_tier_for_principal`. ``None`` means "tier not
            resolved" — :attr:`target_is_tier0_asset` is then the only Tier 0
            signal (back-compatible with the pre-grading callers).
        edge_control_strength: The edge's :class:`ControlStrength`, refining
            auth edges (``AdminTo`` FULL > session > ``SQLAdmin`` >
            ``SQLAccess`` LOW). Derive it from the relation via
            :func:`adscan_internal.services.edge_kind.edge_control_strength`.
            Only consulted for ``auth`` edges; defaults to
            :attr:`ControlStrength.NOT_APPLICABLE`.
        target_is_tier0_asset: Legacy flat Tier 0 signal, kept for
            back-compatibility. True when the target is any Tier 0 asset
            (DC, Exchange, ADCS CA). When ``target_privilege_tier`` is supplied
            this is derivable from it; the canonical property
            :attr:`is_target_tier0_asset` reconciles both. Distinct from
            ``target_is_domain`` — a Tier 0 *asset* is a host/server, the
            *domain* is the AD domain object itself.
        target_is_domain: True when the target node is the Domain object
            (kind == "Domain") — the canonical "Domain Compromised"
            terminal.
        proven_unauthenticated_reachable: True when the edge's reach was
            PROVEN over the unauthenticated (null-session) phase — not merely
            a potential unauthenticated source. Set from the edge's
            ``notes.unauthenticated_reachable`` (stamped by Task 1.1 only when
            the read was genuinely proven via ``origin == "unauth_enrichment"``).
            Consulted ONLY inside Rule 4b: when the source is an
            ``UNAUTHENTICATED_PRINCIPAL`` reaching a Tier-0 / domain-compromise
            target, this lifts the conservative HIGH cap to ``CRITICAL``
            (proven > potential — zero credentials to the control plane is the
            worst case, not a hardening-maybe). ``False`` leaves the existing
            conservative cap untouched, so every caller that does not supply it
            is byte-identical.
        proven_unauth_reaches_tier0: True when the edge's OWN target is NOT the
            Tier-0 terminal (e.g. a credential-read entry edge landing on the
            harvested account), but the PROVEN no-credential CHAIN forward from
            that target reaches a Tier-0 / domain-compromise terminal. This is
            the honest input for an unauthenticated credential-read finding whose
            severity reflects its DOWNSTREAM chain, not the edge's immediate
            target. It is the causally-scoped Tier-0 signal (a forward walk over
            executed edges), NOT "the graph has a Tier-0 compromise somewhere".
            Consulted ONLY inside Rule 4b, and ONLY for an
            ``UNAUTHENTICATED_PRINCIPAL`` source — it lifts that entry to
            ``CRITICAL`` exactly as a direct terminal reach would. Never
            repurpose ``target_is_domain`` / ``target_is_tier0_asset`` for this:
            those describe the edge's OWN target node's kind/tier, and the entry
            edge's real target is a regular account, not the domain. ``False``
            keeps the conservative cap; every caller that does not supply it is
            byte-identical.
    """

    source_compromise_class: CompromiseClass | None
    target_compromise_class: CompromiseClass | None
    edge_kind: EdgeKind
    target_privilege_tier: PrivilegeTier | None = None
    edge_control_strength: ControlStrength = ControlStrength.NOT_APPLICABLE
    target_is_tier0_asset: bool = False
    target_is_domain: bool = False
    proven_unauthenticated_reachable: bool = False
    proven_unauth_reaches_tier0: bool = False

    @property
    def is_target_tier0_asset(self) -> bool:
        """Return whether the target is a Tier 0 asset (graded ∪ legacy).

        Honors both signals: an explicit graded ``target_privilege_tier`` inside
        the Tier 0 boundary, OR the legacy flat ``target_is_tier0_asset`` flag.
        This keeps callers that pass only the boolean working unchanged while
        letting graded callers drive the tier from the node's role.
        """
        if self.target_privilege_tier is not None and self.target_privilege_tier.is_tier0:
            return True
        return bool(self.target_is_tier0_asset)

    @property
    def is_target_tier0_direct(self) -> bool:
        """Return True only for a ``TIER0_DIRECT`` target (a DC / the domain).

        ``TIER0_ESCALATION_CAPABLE`` assets (ADCS CA, Exchange) return False —
        that is the whole point of the graded tier. When the tier was not
        resolved (``None``), fall back to ``target_is_domain``: the domain
        object is always direct.
        """
        if self.target_privilege_tier is PrivilegeTier.TIER0_DIRECT:
            return True
        if self.target_privilege_tier is not None:
            return False
        return bool(self.target_is_domain)


def edge_proven_unauthenticated_reachable(edge: object) -> bool:
    """Return the proven-unauthenticated-reachable flag from an edge's notes.

    The flag is stamped on the edge's ``notes`` dict (key
    ``unauthenticated_reachable``) by the share-credential provenance service,
    and ONLY when the read was genuinely proven over the unauthenticated
    (null-session) enrichment phase. This reads it back so the three
    :class:`EdgeSeverityInput` builders all consult the same canonical signal
    rather than each re-deriving it. Best-effort: a missing/odd-shaped edge or
    notes dict yields ``False`` (the conservative, byte-identical default).

    Args:
        edge: A raw attack-graph edge dict (or any mapping with ``notes``).

    Returns:
        ``True`` only when ``edge["notes"]["unauthenticated_reachable"]`` is
        truthy.
    """
    try:
        notes = edge.get("notes") if hasattr(edge, "get") else None
    except Exception:
        return False
    if not isinstance(notes, dict):
        return False
    return bool(notes.get("unauthenticated_reachable"))


def _is_low_priv_source(cls: CompromiseClass | None) -> bool:
    """Return True if source is low-priv / Compromise Enabler.

    The matrix treats unclassified principals (``None`` or
    :attr:`CompromiseClass.NONE`) and ``COMPROMISE_ENABLER`` symmetrically —
    they share the same severity row. Any path that *originates* in a
    non-privileged principal and crosses into Tier 0 is a choke point.
    """
    return cls is None or cls in (
        CompromiseClass.NONE,
        CompromiseClass.COMPROMISE_ENABLER,
        CompromiseClass.TIER0_FOOTHOLD,
    )


def _target_is_domain_or_breaker(inp: EdgeSeverityInput) -> bool:
    """Return True when target is the Domain object or a Domain Breaker."""
    if inp.target_is_domain:
        return True
    return inp.target_compromise_class is CompromiseClass.DOMAIN_BREAKER


def _grade_auth_to_tier0(
    *,
    base: Severity,
    is_direct: bool,
    strength: ControlStrength,
) -> Severity:
    """Refine an auth-edge severity into a Tier 0 asset by control strength.

    Directness dominates: an auth edge into a ``TIER0_DIRECT`` asset (a DC, the
    domain object) keeps its full ``base`` severity regardless of strength —
    landing any session on a DC is already a Tier 0 foothold. The refinement
    only fires for ``TIER0_ESCALATION_CAPABLE`` assets, where a weak edge does
    not warrant the same alarm:

    * ``FULL`` (``AdminTo`` → LSASS/SYSTEM) — keep ``base``.
    * ``SESSION`` (``CanRDP`` / ``CanPSRemote`` / ``ExecuteDCOM``) — keep
      ``base``; a shell on the host is still a real foothold.
    * ``CONDITIONAL_EXEC`` (``SQLAdmin`` — host exec only via an extra step) —
      drop one band.
    * ``LOW`` (``SQLAccess`` — DB session, usually no host code-exec) — drop two
      bands.
    * ``NOT_APPLICABLE`` (auth edge with no mapped strength) — keep ``base``;
      the absence of a strength signal must never *raise* severity, and bare
      auth uncertainty is already capped by the caller's base band.

    Never raises severity above ``base``; only refines downward for weak edges
    into escalation-capable assets.
    """
    if is_direct:
        return base
    if strength in (ControlStrength.FULL, ControlStrength.SESSION, ControlStrength.NOT_APPLICABLE):
        return base
    drop = 1 if strength is ControlStrength.CONDITIONAL_EXEC else 2
    return _lower_severity(base, drop)


# Downward-only severity band ladder (Tier 0 auth-edge refinement). INFO /
# STRUCTURAL are never produced by the refinement — the floor is LOW.
_SEVERITY_LADDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
)


def _lower_severity(base: Severity, steps: int) -> Severity:
    """Return ``base`` lowered by ``steps`` bands, clamped to the LOW floor."""
    if base not in _SEVERITY_LADDER or steps <= 0:
        return base
    idx = min(_SEVERITY_LADDER.index(base) + steps, len(_SEVERITY_LADDER) - 1)
    return _SEVERITY_LADDER[idx]


def compute_edge_severity(inp: EdgeSeverityInput) -> Severity:
    """Compute the canonical severity for one edge.

    This is a **pure function** — same input, same output, no I/O. It
    implements the matrix in ``12_nomenclature_standard.md``.

    Invariant rules (in order of precedence):

    1. ``source = DomainBreaker`` → always ``INFO``. The AD hierarchy
       intrinsically grants Domain Breakers full control; rendering those
       edges as critical is the noise this module exists to remove.
    2. ``membership`` → always ``STRUCTURAL``. Topology, not severity.
    3. ``trust`` → ``INFO`` by default. Cross-domain elevation is a TODO.
    4. ``unknown`` → ``INFO`` with a one-shot verbose warning. Drift
       detection only — production data should classify.
    5. Compromise Enabler / low-priv → Domain or Domain Breaker via
       ``control``/``escalation``/``derived`` → ``CRITICAL``.
    6. Compromise Enabler / low-priv → Tier 0 asset via ``auth`` →
       ``CRITICAL`` for a Tier 0 *direct* target (a DC), refined DOWN by
       :func:`_grade_auth_to_tier0` for a weak edge into a Tier 0
       *escalation-capable* target (e.g. ``SQLAccess`` → SQL host).
    7. Privileged Escalator → Domain/Domain Breaker via ``control``/
       ``escalation`` → ``HIGH``.
    8. Privileged Escalator → Tier 0 asset via ``auth`` → ``HIGH`` (refined
       down by control strength for escalation-capable targets).
    9. Compromise Enabler / low-priv → Privileged Escalator via
       ``control``/``escalation`` → ``HIGH``.
    10. Compromise Enabler / low-priv → Compromise Enabler via ``control``
        → ``MEDIUM`` (multi-hop link).
    11. Default → ``LOW``.

    Target tier (``TIER0_DIRECT`` > ``TIER0_ESCALATION_CAPABLE``) and edge
    control strength (``AdminTo`` > session > ``SQLAdmin`` > ``SQLAccess``)
    grade WITHIN these rules; they never lift a structural/membership edge or
    raise a Domain Breaker source above ``INFO`` (the HTB Forest guard).
    """
    kind = inp.edge_kind

    # Rule 2 — membership is always structural.
    if kind is EdgeKind.MEMBERSHIP:
        return Severity.STRUCTURAL

    # Rule 3 — trust defaults to INFO. TODO(cross-domain): elevate to
    # HIGH/CRITICAL when target_domain is itself comprometible. Requires
    # the trust-graph layer which is not yet wired into this function.
    if kind is EdgeKind.TRUST:
        return Severity.INFO

    # Rule 4 — unknown kinds. One-shot warning, then INFO.
    if kind is EdgeKind.UNKNOWN:
        token = "edge_kind=unknown"
        if token not in _WARNED_UNKNOWN_KIND:
            _WARNED_UNKNOWN_KIND.add(token)
            print_warning(
                "[severity] EdgeKind.UNKNOWN seen — falling back to INFO. "
                "Classify the edge in adscan_internal/services/edge_kind.py"
            )
        return Severity.INFO

    # Rule 1 — Domain Breaker as source is always INFO (AD hierarchy).
    # Applies to control / auth / escalation / derived alike.
    if inp.source_compromise_class is CompromiseClass.DOMAIN_BREAKER:
        return Severity.INFO

    target_is_terminal = _target_is_domain_or_breaker(inp)
    # Graded Tier 0 signal: honors target_privilege_tier when supplied, else the
    # legacy flat boolean (back-compatible). target_is_direct splits the Tier 0
    # boundary so a DC outranks an escalation-capable asset (ADCS CA / Exchange).
    target_is_t0_asset = inp.is_target_tier0_asset
    target_is_direct = inp.is_target_tier0_direct
    strength = inp.edge_control_strength
    target_is_escalator = (
        inp.target_compromise_class is CompromiseClass.PRIVILEGED_ESCALATOR
    )

    # Rule 4b — Unauthenticated Principal (Anonymous Logon, Network, Everyone
    # in a control edge to Tier 0). These principals only constitute a real
    # finding when null sessions / Pre-Windows 2000 Compatible Access are
    # enabled — uncertain without runtime validation. Cap at HIGH so the
    # panel does not raise CRITICAL alarms for what may be a hardened
    # environment.
    #
    # PROVEN > POTENTIAL: when the reach was actually PROVEN over the
    # unauthenticated (null-session) phase (``proven_unauthenticated_reachable``),
    # the "null sessions might be enabled" uncertainty is gone — an attacker
    # needing ZERO credentials to reach the control plane is the worst case, so
    # a proven no-credential path onto a Tier-0 / domain-compromise target
    # uplifts to CRITICAL, above the conservative cap. A merely-potential
    # unauthenticated source keeps the existing HIGH cap.
    if inp.source_compromise_class is CompromiseClass.UNAUTHENTICATED_PRINCIPAL:
        if target_is_terminal and kind in (
            EdgeKind.CONTROL,
            EdgeKind.ESCALATION,
            EdgeKind.DERIVED,
        ):
            if inp.proven_unauthenticated_reachable:
                return Severity.CRITICAL
            return Severity.HIGH
        if target_is_t0_asset and kind is EdgeKind.AUTH:
            if inp.proven_unauthenticated_reachable:
                return Severity.CRITICAL
            return Severity.HIGH
        # The edge's own target is NOT Tier-0 (e.g. a credential-read entry edge
        # landing on a harvested account), but the PROVEN no-credential chain
        # forward from it reaches a Tier-0 / domain-compromise terminal. That is
        # the same worst case — zero credentials to the control plane — so it
        # uplifts to CRITICAL. Requires the proven-reachable flag too, so a
        # merely-potential unauthenticated source never gets here.
        if (
            inp.proven_unauthenticated_reachable
            and inp.proven_unauth_reaches_tier0
            and kind in (EdgeKind.CONTROL, EdgeKind.ESCALATION, EdgeKind.DERIVED)
        ):
            return Severity.CRITICAL
        if kind in (EdgeKind.CONTROL, EdgeKind.ESCALATION, EdgeKind.DERIVED):
            return Severity.MEDIUM
        return Severity.LOW

    # Rule 5/6/7/8 — escalator vs low-priv source crossing into Tier 0.
    if target_is_terminal or target_is_t0_asset:
        if _is_low_priv_source(inp.source_compromise_class):
            # Rule 5 — control/escalation/derived to terminal → CRITICAL
            if target_is_terminal and kind in (
                EdgeKind.CONTROL,
                EdgeKind.ESCALATION,
                EdgeKind.DERIVED,
            ):
                return Severity.CRITICAL
            # Rule 6 — auth to Tier 0 asset → CRITICAL (real foothold),
            # refined DOWN by control strength for a weak edge into an
            # escalation-capable (non-direct) asset: AdminTo/session keep
            # CRITICAL, SQLAdmin drops one band, SQLAccess drops two. A direct
            # Tier 0 target (a DC) keeps CRITICAL regardless of strength.
            if target_is_t0_asset and kind is EdgeKind.AUTH:
                return _grade_auth_to_tier0(
                    base=Severity.CRITICAL,
                    is_direct=target_is_direct or target_is_terminal,
                    strength=strength,
                )
            # derived always >= HIGH (proof of compromise) — keep CRITICAL
            # when it lands on Tier 0 asset, HIGH otherwise.
            if kind is EdgeKind.DERIVED and target_is_t0_asset:
                return Severity.CRITICAL

        if inp.source_compromise_class is CompromiseClass.PRIVILEGED_ESCALATOR:
            # Rule 7 — escalator → terminal via control/escalation → HIGH
            if target_is_terminal and kind in (
                EdgeKind.CONTROL,
                EdgeKind.ESCALATION,
                EdgeKind.DERIVED,
            ):
                return Severity.HIGH
            # Rule 8 — escalator → Tier 0 asset via auth → HIGH, refined down
            # by control strength for an escalation-capable (non-direct) target.
            if target_is_t0_asset and kind is EdgeKind.AUTH:
                return _grade_auth_to_tier0(
                    base=Severity.HIGH,
                    is_direct=target_is_direct or target_is_terminal,
                    strength=strength,
                )

    # Rule 9 — low-priv → Privileged Escalator via control/escalation → HIGH
    if (
        target_is_escalator
        and _is_low_priv_source(inp.source_compromise_class)
        and kind in (EdgeKind.CONTROL, EdgeKind.ESCALATION, EdgeKind.DERIVED)
    ):
        return Severity.HIGH

    # Rule 10 — low-priv → low-priv via control → MEDIUM (multi-hop link)
    if (
        _is_low_priv_source(inp.source_compromise_class)
        and _is_low_priv_source(inp.target_compromise_class)
        and not target_is_t0_asset
        and not target_is_terminal
        and not target_is_escalator
        and kind is EdgeKind.CONTROL
    ):
        return Severity.MEDIUM

    # Rule 11 — default fallback.
    return Severity.LOW


# Render order — used by the panel renderer to sort the visible band.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
    Severity.STRUCTURAL: 5,
}


def severity_rank(sev: Severity) -> int:
    """Return a sort key — lower = more severe — for rendering order."""
    return _SEVERITY_RANK.get(sev, 9)
