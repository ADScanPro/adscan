"""Unauthenticated-reachable path signal: the client copy.

When an attack path's ENTRY edge was proven executable with NO credential — a
share/file read obtained over an SMB null session OR an SMB guest session during
the pre-credential unauthenticated phase — that is the single most severe and
most sellable fact about the path: any actor with network access, holding no
account, can begin it. The collector records this as an ATTRIBUTE on the edge
notes (``notes.unauthenticated_reachable == True`` with ``notes.reached_via`` set
to ``"null_session"`` or ``"guest_session"`` — whichever bind actually performed
the read), stamped by the share-credential provenance service ONLY when the read
was genuinely proven over the unauthenticated phase — never inferred from a broad
source SID such as Everyone.

This module is the single definition of the client-facing copy for that signal
and the predicates that decide when it applies. The writeup, the LITE report, the
PRO report and the paid web platform all read from here, so the signal is worded
identically wherever a client meets it.

Honesty is the whole point of the copy (it is why the signal is valuable and not
just alarming). Two facts the prose must keep straight, both established by the
investigation behind this signal:

* The file is readable by a null session, **NOT** because the Anonymous Logon
  identity holds a permission on the share. Its ACL grants read to broad groups
  such as Everyone and Users, and the anonymous token does not carry those.
  The read works because the server permits null-session access to this
  particular non-standard share (the null-session-share allow-list / restrict
  setting). The copy states this plainly so an auditor who looks for an
  "Anonymous" entry in the ACL and does not find one still trusts the finding.
* ADscan proved the reach by reading the file with no credential. The copy states
  what was proven, not a specific registry value it did not read.

Pure logic: no IO, no console, no network, no ``adscan_internal`` import. Safe to
import from ``adscan_core``, the LITE runtime, the PRO report renderer and the web
backend alike.
"""

from __future__ import annotations

from typing import Any, Mapping

#: The note keys the share-credential provenance service stamps on an edge whose
#: read was proven over the unauthenticated (null-session) phase. Restated here
#: as stable protocol tokens so this copy layer stays free of any
#: ``adscan_internal`` import and the web backend can consume it directly.
UNAUTHENTICATED_REACHABLE_NOTE_KEY = "unauthenticated_reachable"
REACHED_VIA_NOTE_KEY = "reached_via"
REACHED_VIA_NULL_SESSION = "null_session"
#: The read was obtained over an SMB guest session (the server accepted the
#: built-in guest account with no real domain credential). A different honest
#: mechanism from the null session, so it gets its own HOW sentence below.
REACHED_VIA_GUEST_SESSION = "guest_session"

#: The node ``kind`` token of the synthetic ``Unauthenticated`` entry node that the
#: attack-path engine prepends as step 0 of a proven no-credential path. A shared
#: contract: the engine stamps it, the exposure aggregator keys the maximum-exposure
#: affected-count on it, and the web CTEM renders the step-0 node with it. Defined
#: here (not only in the engine) so the web backend can recognize the synthetic
#: entry node WITHOUT importing the engine across the tier boundary.
UNAUTHENTICATED_ENTRY_KIND = "Unauthenticated"

#: The synthetic entry node's display label, keyed by ``reached_via``. This is the
#: exact client-facing string the engine MINTS for the step-0 node, so it is owned
#: here (the client-copy SSOT) and the engine imports it — one producer, one
#: decoder. The web recognizes the step-0 node by this label when the synthetic
#: node is absent from its persisted graph snapshot.
UNAUTHENTICATED_ENTRY_LABELS: dict[str, str] = {
    REACHED_VIA_NULL_SESSION: "Unauthenticated (null session)",
    REACHED_VIA_GUEST_SESSION: "Unauthenticated (guest session)",
}
#: Default entry label (the conservative null-session wording) for an unknown token.
UNAUTHENTICATED_ENTRY_LABEL_DEFAULT = UNAUTHENTICATED_ENTRY_LABELS[REACHED_VIA_NULL_SESSION]

#: Reverse map: a minted entry label (lower-cased) → its ``reached_via`` token, so
#: the ONE producer of the label is also the ONE decoder. Built once at import.
_ENTRY_LABEL_TO_REACHED_VIA: dict[str, str] = {
    label.strip().lower(): via for via, label in UNAUTHENTICATED_ENTRY_LABELS.items()
}


def entry_label_for_reached_via(reached_via: str = REACHED_VIA_NULL_SESSION) -> str:
    """Return the synthetic ``Unauthenticated`` entry label for a bind token.

    The single producer of the step-0 node's display label. An unknown token falls
    back to the null-session wording (the conservative default).
    """
    token = str(reached_via or "").strip() or REACHED_VIA_NULL_SESSION
    return UNAUTHENTICATED_ENTRY_LABELS.get(token, UNAUTHENTICATED_ENTRY_LABEL_DEFAULT)


def is_unauthenticated_entry_label(label: Any) -> bool:
    """Return whether ``label`` is a synthetic ``Unauthenticated`` entry label.

    Matches ONLY the exact labels the engine MINTS for the step-0 node
    (``Unauthenticated (null session)`` / ``(guest session)``) — never a real
    directory principal — so the "never treat a real principal as the synthetic
    entry" honesty invariant holds on every surface that recognizes it.
    """
    return str(label or "").strip().lower() in _ENTRY_LABEL_TO_REACHED_VIA


def reached_via_from_entry_label(label: Any) -> str:
    """Return the ``reached_via`` token (null/guest) encoded by an entry ``label``.

    Decodes a synthetic entry label back to its bind kind. A FALLBACK only — the
    authoritative source is the edge/node ``reached_via`` note. Defaults to
    ``REACHED_VIA_NULL_SESSION`` for any label that is not a recognized entry label.
    """
    return _ENTRY_LABEL_TO_REACHED_VIA.get(
        str(label or "").strip().lower(), REACHED_VIA_NULL_SESSION
    )


#: The finding/vulnerability key(s) whose weakness IS the unauthenticated entry
#: vector a path begins from, keyed by ``reached_via``. A path that starts over a
#: guest or null session carries that entry-vector finding as its step 0 — but the
#: engine records the entry as the synthetic SOURCE NODE (``Unauthenticated (guest
#: session)``), not as an edge relation, so a finding↔path join keyed only on edge
#: relations misses it. This is the single decoder a join consults to credit the
#: entry-vector finding from the path's source. One producer of the entry
#: semantics (the labels above), one consumer list here.
ENTRY_VECTOR_FINDING_KEYS: dict[str, tuple[str, ...]] = {
    REACHED_VIA_GUEST_SESSION: ("smb_guest_shares",),
    REACHED_VIA_NULL_SESSION: ("smb_null_domain",),
}


def entry_vector_finding_keys_for_path(path: Any) -> set[str]:
    """Return the finding keys whose weakness IS this path's unauthenticated entry.

    When a path's source is the synthetic ``Unauthenticated`` entry node, the
    finding that represents that entry vector (guest-session share access / SMB
    null session) is genuinely step 0 of the path even though it is carried as the
    source NODE rather than an edge relation. This returns those keys so a
    finding↔path membership join can credit them. A path with no synthetic entry
    source returns an empty set. Best-effort; never raises.

    Args:
        path: An attack-path summary dict (``source`` / ``nodes`` / per-node
            ``reached_via`` note).

    Returns:
        The entry-vector finding keys (e.g. ``{"smb_guest_shares"}``), or an empty
        set when the path does not begin from a synthetic unauthenticated entry.
    """
    if not isinstance(path, Mapping):
        return set()
    # The source label (or the first node) is the synthetic entry when present.
    source_label = path.get("source")
    if not is_unauthenticated_entry_label(source_label):
        nodes = path.get("nodes")
        source_label = nodes[0] if isinstance(nodes, list) and nodes else None
    if not is_unauthenticated_entry_label(source_label):
        return set()
    reached_via = reached_via_from_entry_label(source_label)
    return set(ENTRY_VECTOR_FINDING_KEYS.get(reached_via, ()))


#: The short badge a client surface shows on the proven-no-credential entry edge
#: (report finding row, LITE/PRO step, web edge-detail chip). Says the certainty,
#: not the mechanism — the mechanism is the HOW sentence below.
UNAUTHENTICATED_REACH_BADGE = "Executable without credentials: confirmed"

#: The stable ``affected_users_source`` token stamped on the synthetic
#: ``Unauthenticated`` entry path. It is NOT a broad-group expansion token (it is
#: deliberately absent from the exposure aggregator's broad-group allow-list), so
#: it never makes a path read as "all enabled domain users". It marks a path whose
#: affected scope is every possible actor and whose affected principal COUNT is
#: the domain's maximum-exposure ceiling, carried on the count rather than a named
#: principal list (a no-credential foothold has no owning account to enumerate).
UNAUTHENTICATED_ENTRY_AFFECTED_SOURCE = "unauthenticated_entry"

#: The honest human-readable affected-scope phrase for the synthetic
#: ``Unauthenticated`` entry. Rendered wherever a client meets the path's affected
#: scope (CLI "Affected Scope" line, report, web), so the phrase is worded
#: identically everywhere. It states the truth — anyone on the network, holding no
#: account — and never invents a named principal the path does not have.
UNAUTHENTICATED_ENTRY_AFFECTED_SCOPE_PHRASE = "any unauthenticated actor"

#: The domain-level KPI key the exposure aggregator stamps when a PROVEN path to
#: FULL domain compromise began from an unauthenticated foothold (a null/guest
#: read during the pre-credential phase). A shared contract token so the report
#: renderers and the web backend read the SAME block without importing the engine
#: across the tier boundary. The block shape is
#: ``{"present": bool, "reached_via": "null_session"|"guest_session"}``.
UNAUTHENTICATED_DOMAIN_BREAKER_KEY = "unauthenticated_domain_breaker"


def unauthenticated_domain_breaker_present(exposure_kpis: Any) -> bool:
    """Return whether a domain's exposure KPIs record a no-credential domain breaker.

    Reads the engine-stamped ``unauthenticated_domain_breaker`` block and returns
    ``True`` only when it marks a proven path to full domain compromise that began
    from an unauthenticated foothold. A missing or odd-shaped block yields
    ``False`` (the conservative default — never fabricate the zero-credential
    lead).

    Args:
        exposure_kpis: A domain's ``exposure_kpis`` mapping (or any mapping that
            carries the block under :data:`UNAUTHENTICATED_DOMAIN_BREAKER_KEY`).

    Returns:
        ``True`` when the block is present and ``present`` is truthy.
    """

    if not isinstance(exposure_kpis, Mapping):
        return False
    block = exposure_kpis.get(UNAUTHENTICATED_DOMAIN_BREAKER_KEY)
    return bool(isinstance(block, Mapping) and block.get("present"))


def unauthenticated_domain_breaker_reached_via(exposure_kpis: Any) -> str:
    """Return the bind token (null/guest) of a no-credential domain breaker.

    Reads ``unauthenticated_domain_breaker.reached_via`` and normalizes it to a
    known token, defaulting to :data:`REACHED_VIA_NULL_SESSION` (the conservative,
    long-standing default) when the block is absent or the value unrecognized.
    """

    if not isinstance(exposure_kpis, Mapping):
        return REACHED_VIA_NULL_SESSION
    block = exposure_kpis.get(UNAUTHENTICATED_DOMAIN_BREAKER_KEY)
    if not isinstance(block, Mapping):
        return REACHED_VIA_NULL_SESSION
    token = str(block.get(REACHED_VIA_NOTE_KEY) or "").strip()
    return token if token in _REACHED_VIA_HOW else REACHED_VIA_NULL_SESSION


def unauthenticated_headline(validated_routes: int = 1) -> str:
    """Return the zero-credential executive lead, worded identically on every tier.

    The single most severe and most sellable fact a deliverable can carry: a
    path to full domain compromise that an attacker walked holding no account at
    all. It LEADS the executive summary on both the PRO report and the LITE
    verdict, and the web CTEM mirrors it, so a client meets the same sentence
    wherever they look. States what ADscan PROVED (routes whose entry was
    executed with no credential), never a potential.

    Args:
        validated_routes: How many routes ADscan confirmed executable with no
            credential. Clamped to at least 1, since the caller only renders this
            lead once such a route exists.

    Returns:
        The two-sentence lead. Plain text: the caller adds its own emphasis.
    """

    routes = max(1, int(validated_routes or 0))
    noun = "route" if routes == 1 else "routes"
    verb = "begins" if routes == 1 else "begin"
    return (
        "An attacker with no credentials reached full domain compromise. "
        f"ADscan confirmed {routes} {noun} that {verb} with no account and no "
        "foothold to obtain first."
    )

#: SO-WHAT (severity / the buyer's fact): this path needs no foothold at all.
UNAUTHENTICATED_REACH_SO_WHAT = (
    "This path to domain compromise starts with no credential. Any actor with "
    "network access to this server, holding no account, can begin it, with no "
    "foothold to obtain first. ADscan confirmed this by reaching the entry "
    "point with no credential, so it is a proven exposure, not a potential one."
)

#: HOW (the honest mechanism — the differentiator). States that the Anonymous
#: identity does NOT hold the share permission, and that the read works through
#: the server's null-session access, so the client is not confused by seeing an
#: "anonymous" read where no Anonymous entry exists in the share's permissions.
UNAUTHENTICATED_REACH_HOW = (
    "The share was readable over an SMB null session: an unauthenticated "
    "connection with no username and no password. This is not because the "
    "Anonymous Logon identity holds a permission on the share: the share's "
    "permissions grant read to broad groups such as Everyone and Users, and the "
    "anonymous token does not carry those. The read works because the server "
    "permits null-session access to this particular non-standard share, while "
    "the default system shares are not reachable this way. ADscan proved it by "
    "reading the file with no credential."
)

#: HOW for a read obtained over an SMB GUEST session. Same honesty discipline as
#: the null-session sentence: the Guests group does NOT hold a permission on the
#: share — the share grants read to broad groups such as Everyone and Users, and
#: the read works because the server accepts the built-in guest logon to this
#: resource. Stated plainly so an auditor who looks for a "Guests" entry in the
#: ACL and does not find one still trusts the finding.
UNAUTHENTICATED_REACH_HOW_GUEST = (
    "The share was readable over an SMB guest session: a logon that required no "
    "real domain credential, because the server accepts the built-in guest "
    "account with a blank or trivial secret. This is not because the Guests "
    "group holds a permission on the share: the share's permissions grant read "
    "to broad groups such as Everyone and Users, and the guest logon lands the "
    "session in one of those. The read works because the server permits guest "
    "logon to this resource. ADscan proved it by reading the file with no domain "
    "credential."
)

#: The HOW sentence keyed by the ``reached_via`` token. Any unknown token falls
#: back to the null-session sentence (the conservative, long-standing default).
_REACHED_VIA_HOW: dict[str, str] = {
    REACHED_VIA_NULL_SESSION: UNAUTHENTICATED_REACH_HOW,
    REACHED_VIA_GUEST_SESSION: UNAUTHENTICATED_REACH_HOW_GUEST,
}

#: The affected-asset display for the access VECTOR, keyed by ``reached_via``.
#: A credential-in-file finding reached over a pre-authentication session lists
#: the vector as an affected asset so the client sees, AT THE VULNERABILITY
#: LEVEL, that the file needs no credential to read. It names the POSITION (a
#: null/guest session), never a directory principal with a permission.
_REACHED_VIA_VECTOR_DISPLAY: dict[str, str] = {
    REACHED_VIA_NULL_SESSION: "Reachable over an unauthenticated SMB null session",
    REACHED_VIA_GUEST_SESSION: "Reachable over an unauthenticated SMB guest session",
}


def unauthenticated_vector_display(reached_via: str = REACHED_VIA_NULL_SESSION) -> str:
    """Return the affected-asset display for a proven no-credential access vector.

    One SSOT for the vector label so the PDF report and the web CTEM word it
    identically. The caller surfaces it only when the finding carries the proven
    ``unauthenticated_reachable`` + ``reached_via`` attributes — this function is
    the copy, not the decision. An unknown token falls back to the null-session
    wording (the conservative default).
    """
    token = str(reached_via or "").strip() or REACHED_VIA_NULL_SESSION
    return _REACHED_VIA_VECTOR_DISPLAY.get(
        token, _REACHED_VIA_VECTOR_DISPLAY[REACHED_VIA_NULL_SESSION]
    )

#: Remediation checklist (native, client-runnable, impact-ordered). Close the
#: null-session avenue, tighten the broad share permission, remove the exposed
#: secret and rotate the account it exposed. Native PowerShell / registry /
#: Group Policy only — no offensive tooling, no competitor product.
UNAUTHENTICATED_REACH_REMEDIATION: tuple[str, ...] = (
    "Remove this share from null-session access: on the server, confirm the "
    "share is not listed under the registry value "
    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\"
    "NullSessionShares, and ensure RestrictNullSessAccess is set to 1 (the "
    "hardened default). List and audit the shares with Get-SmbShare, and tighten "
    "the share's permissions with Set-SmbShare / Grant-SmbShareAccess / "
    "Revoke-SmbShareAccess.",
    "Remove the broad read grant (Everyone / Users) from the share's permissions "
    "so that only the accounts that need the content can read it, and apply the "
    "matching restriction through Group Policy where the share is managed "
    "centrally.",
    "Remove the exposed secret at its source: delete the file that stored the "
    "credential in a recoverable form, and rotate the account it exposed, "
    "confirming no other object still carries the old secret.",
)


def _notes_from_mapping(value: Any) -> Mapping[str, Any]:
    """Return a notes mapping from ``value``, or an empty mapping.

    Accepts either a notes mapping directly, or a step/details mapping that may
    carry the notes spread in (``value["unauthenticated_reachable"]``) or nested
    under ``value["notes"]`` — the same two shapes the share-credential
    verification copy layer already tolerates across the render surfaces.
    """

    if not isinstance(value, Mapping):
        return {}
    if UNAUTHENTICATED_REACHABLE_NOTE_KEY in value:
        return value
    nested = value.get("notes")
    if isinstance(nested, Mapping):
        return nested
    return {}


def notes_are_unauthenticated_reachable(notes: Any) -> bool:
    """Return whether an edge's notes record a PROVEN no-credential reach.

    Args:
        notes: The edge ``notes`` mapping (or any mapping that spreads the note
            in, or nests it under ``notes``).

    Returns:
        ``True`` only when ``notes.unauthenticated_reachable`` is truthy — the
        flag the provenance service stamps ONLY for a read genuinely proven over
        the null-session phase. A missing or odd-shaped notes mapping yields
        ``False`` (the conservative default — never fabricate the signal).
    """

    resolved = _notes_from_mapping(notes)
    return bool(resolved.get(UNAUTHENTICATED_REACHABLE_NOTE_KEY))


def reached_via_from_notes(notes: Any) -> str:
    """Return the ``reached_via`` bind token recorded on an edge's notes.

    The share-credential provenance service stamps ``reached_via`` alongside
    ``unauthenticated_reachable`` to record WHICH bind performed the proven read —
    a null session or a guest session. This is the single place every render
    surface (the writeup, the PRO narrative, the web edge-detail) reads that token
    from, so they all select the same honest HOW sentence instead of each reaching
    into the notes (or defaulting to null) on their own.

    Accepts the same shapes as the predicates above — a notes mapping directly, a
    step/details mapping that spreads the note in, or one that nests it under
    ``notes``. An absent / unknown value normalizes to ``REACHED_VIA_NULL_SESSION``
    (the conservative, long-standing default), which is exactly the token
    ``unauthenticated_reach_view`` expects.

    Args:
        notes: The edge ``notes`` mapping (or a mapping that spreads the note in,
            or nests it under ``notes``).

    Returns:
        ``REACHED_VIA_NULL_SESSION`` or ``REACHED_VIA_GUEST_SESSION`` — a known
        token. Any missing / unrecognized value falls back to the null-session
        token so the caller can pass the result straight into
        ``unauthenticated_reach_view(reached_via=...)``.
    """

    resolved = _notes_from_mapping(notes)
    token = str(resolved.get(REACHED_VIA_NOTE_KEY) or "").strip()
    return token if token in _REACHED_VIA_HOW else REACHED_VIA_NULL_SESSION


def step_reached_via(step: Any) -> str:
    """Return the ``reached_via`` bind token for one attack-path step.

    Reads the step's ``details`` (where the attack-path SSOT spreads the edge
    notes, directly or nested under ``details["notes"]``) and returns the recorded
    bind token via :func:`reached_via_from_notes`. Used by the render surfaces to
    thread the real bind into the HOW sentence, so a guest-session entry is never
    mislabeled as a null session.

    Args:
        step: A raw attack-path step dict with an optional ``details`` dict.

    Returns:
        A known ``reached_via`` token (null-session fallback when absent/unknown).
    """

    if not isinstance(step, Mapping):
        return REACHED_VIA_NULL_SESSION
    return reached_via_from_notes(step.get("details"))


def step_is_unauthenticated_reachable(step: Any) -> bool:
    """Return whether one attack-path step's entry read was proven no-credential.

    Reads the step's ``details`` (where the attack-path SSOT spreads the edge
    notes, directly or nested under ``details["notes"]``). Returns ``True`` only
    when the ``unauthenticated_reachable`` attribute is present and truthy.

    Args:
        step: A raw attack-path step dict with an optional ``details`` dict.

    Returns:
        ``True`` when the step carries the proven-no-credential attribute.
    """

    if not isinstance(step, Mapping):
        return False
    return notes_are_unauthenticated_reachable(step.get("details"))


def _iter_entry_steps(record: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Return the candidate ENTRY steps of a path record (the first real hop).

    The signal is a PATH property that belongs to the FOOTHOLD — the first hop,
    not any later one. But a path's first listed step can be a context / virtual
    hop, so the entry candidates are the leading steps up to and including the
    first one that carries the attribute; checking only ``steps[0]`` would miss a
    path whose real entry read is the second listed step. A non-list ``steps``
    yields no candidates.
    """

    steps = record.get("steps")
    if not isinstance(steps, list):
        return []
    return [step for step in steps if isinstance(step, Mapping)]


def path_is_unauthenticated_reachable(record: Any) -> bool:
    """Return whether a path's ENTRY edge was proven executable with no credential.

    A path is unauthenticated-reachable when its foothold (the entry edge) carries
    the proven ``unauthenticated_reachable`` attribute. Reads the record's
    ``steps`` and returns ``True`` when the entry step carries it.

    The check scans the leading steps rather than only ``steps[0]`` so a path
    whose first listed hop is a context/virtual step still resolves from the real
    entry read. This stays honest: the attribute is only ever stamped on a read
    genuinely proven over the null-session phase, so a later non-entry hop cannot
    carry it spuriously.

    Args:
        record: A single attack-path summary dict (carries ``steps``).

    Returns:
        ``True`` when the path's entry read was proven no-credential.
    """

    if not isinstance(record, Mapping):
        return False
    for step in _iter_entry_steps(record):
        if step_is_unauthenticated_reachable(step):
            return True
    return False


def unauthenticated_reach_view(reached_via: str = REACHED_VIA_NULL_SESSION) -> dict[str, Any]:
    """Return the render view for the unauthenticated-reachable signal.

    One shape the PDF report and the web CTEM both read, so the two surfaces
    cannot word the same signal differently. The caller renders it only when the
    edge/path carries the proven attribute (the predicates above); this function
    does not gate — it is the copy, not the decision.

    Args:
        reached_via: How the no-credential read was obtained —
            ``REACHED_VIA_NULL_SESSION`` (the default, and today's behavior) or
            ``REACHED_VIA_GUEST_SESSION``. It selects the honest ``how`` sentence;
            an unknown token falls back to the null-session copy.

    Returns:
        A dict with ``badge`` (the short chip), ``so_what`` (the severity
        sentence), ``how`` (the honest mechanism for ``reached_via``),
        ``reached_via`` (the stable token, normalized to a known value), and
        ``remediation`` (the ordered checklist tuple).
    """

    token = str(reached_via or "").strip() or REACHED_VIA_NULL_SESSION
    how = _REACHED_VIA_HOW.get(token)
    if how is None:
        token, how = REACHED_VIA_NULL_SESSION, UNAUTHENTICATED_REACH_HOW
    return {
        "badge": UNAUTHENTICATED_REACH_BADGE,
        "so_what": UNAUTHENTICATED_REACH_SO_WHAT,
        "how": how,
        "reached_via": token,
        "remediation": UNAUTHENTICATED_REACH_REMEDIATION,
    }


__all__ = [
    "REACHED_VIA_GUEST_SESSION",
    "REACHED_VIA_NOTE_KEY",
    "REACHED_VIA_NULL_SESSION",
    "UNAUTHENTICATED_DOMAIN_BREAKER_KEY",
    "UNAUTHENTICATED_ENTRY_AFFECTED_SCOPE_PHRASE",
    "UNAUTHENTICATED_ENTRY_AFFECTED_SOURCE",
    "UNAUTHENTICATED_ENTRY_KIND",
    "UNAUTHENTICATED_ENTRY_LABELS",
    "UNAUTHENTICATED_ENTRY_LABEL_DEFAULT",
    "UNAUTHENTICATED_REACHABLE_NOTE_KEY",
    "entry_label_for_reached_via",
    "is_unauthenticated_entry_label",
    "reached_via_from_entry_label",
    "ENTRY_VECTOR_FINDING_KEYS",
    "entry_vector_finding_keys_for_path",
    "UNAUTHENTICATED_REACH_BADGE",
    "UNAUTHENTICATED_REACH_HOW",
    "UNAUTHENTICATED_REACH_HOW_GUEST",
    "UNAUTHENTICATED_REACH_REMEDIATION",
    "UNAUTHENTICATED_REACH_SO_WHAT",
    "notes_are_unauthenticated_reachable",
    "path_is_unauthenticated_reachable",
    "unauthenticated_domain_breaker_present",
    "unauthenticated_domain_breaker_reached_via",
    "unauthenticated_headline",
    "reached_via_from_notes",
    "step_is_unauthenticated_reachable",
    "step_reached_via",
    "unauthenticated_reach_view",
    "unauthenticated_vector_display",
]
