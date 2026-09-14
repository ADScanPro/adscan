"""Structural well-known / built-in principal predicate: the shared SSOT.

A well-known or built-in principal (Everyone, Anonymous, Authenticated Users, the
``BUILTIN\\*`` aliases, and the reserved domain objects such as Domain Admins,
Domain Users, Administrator, krbtgt) is NOT an ordinary, countable, or removable
object:

* It must never enter the ordinary-account **numerator** of an exposure KPI — a
  synthetic no-credential entry whose blast-radius CEILING folds the largest group
  population into the count once printed "4 of 2 domain users / 100%", an
  impossible figure, because a well-known group's population leaked into the
  user-population numerator.
* It must never be offered as a choke-point **object to remove** — "remove
  ``BUILTIN\\Users``" is harmful advice; the alias cannot be deleted, and a fix
  that maps to it is not actionable.

This module is the ONE definition of "is this a structural well-known / built-in
principal", classified by the SID / RID CLASS (not a per-name special case), so
every surface that must exclude such principals — the exposure-KPI aggregator, the
choke ranking, and the paid web CTEM — decides it identically.

Pure logic: no IO, no console, no network, no ``adscan_internal`` import. Safe to
import from ``adscan_core``, the LITE runtime, the PRO report renderer and the web
backend alike.
"""

from __future__ import annotations

#: The broad LOGON populations, keyed by name, for graphs that carry only a label
#: (no SID). This is a STRICT SUBSET of the structural well-known set — it names
#: only the whole authenticated / standard-user populations, NOT every built-in
#: group. ``compromise_class._graph_node_is_broad_logon_source`` (RDS/Citrix
#: detection) consumes THIS set, never the full structural predicate, because a
#: server where Domain Admins — also a built-in group — can log on is not an
#: RDS/Citrix host.
BROAD_LOGON_NAMES: frozenset[str] = frozenset(
    {"everyone", "authenticated users", "users", "domain users"}
)

#: Well-known SIDs that are NOT of the generic ``S-1-5-<n>`` single-subauthority
#: shape (those are handled structurally below) but still name a built-in
#: identity: Null (S-1-0-0), World/Everyone (S-1-1-0), Local (S-1-2-*), and the
#: Creator identities (S-1-3-*). Enumerated because their identifier authority is
#: not ``5`` so the generic NT-authority rule does not reach them.
_EXACT_WELL_KNOWN_SIDS: frozenset[str] = frozenset(
    {
        "S-1-0-0",  # Nobody
        "S-1-1-0",  # Everyone / World
        "S-1-2-0",  # Local
        "S-1-2-1",  # Console Logon
        "S-1-3-0",  # Creator Owner
        "S-1-3-1",  # Creator Group
        "S-1-3-2",  # Creator Owner Server
        "S-1-3-3",  # Creator Group Server
        "S-1-3-4",  # Owner Rights
    }
)

#: The RID floor below which a DOMAIN object is reserved / built-in. Windows mints
#: operator (non-built-in) objects starting at RID 1000; everything below is a
#: reserved well-known RID (500 Administrator, 501 Guest, 502 krbtgt, 512 Domain
#: Admins, 513 Domain Users, 519 Enterprise Admins, ...). This is the generic key
#: the doctrine asks for — NOT a per-name special case.
_DOMAIN_BUILTIN_RID_FLOOR: int = 1000


def _sid_is_structural_well_known(sid: str) -> bool:
    """Return whether a SID names a structural well-known / built-in principal.

    Classified by SID / RID CLASS, never by name:

    * ``S-1-5-32-*`` — every BUILTIN alias (Administrators 544, Users 545, the
      operator groups, ...).
    * ``S-1-5-21-<d1>-<d2>-<d3>[-<RID>]`` — a domain principal: the bare domain
      SID (no RID) is structural, and a RID below :data:`_DOMAIN_BUILTIN_RID_FLOOR`
      is a reserved/built-in object (500/502/512/513/519/...). A RID at or above
      the floor is an operator-minted object — NOT structural.
    * ``S-1-5-<n>`` — a single-subauthority NT-authority SID (Anonymous S-1-5-7,
      Authenticated Users S-1-5-11, Enterprise DCs S-1-5-9, Local System S-1-5-18,
      ...) — all well-known.
    * The enumerated :data:`_EXACT_WELL_KNOWN_SIDS` (non-NT-authority well-knowns).
    """
    s = sid.strip().upper()
    if not s.startswith("S-1-"):
        return False
    if s in _EXACT_WELL_KNOWN_SIDS:
        return True
    if s.startswith("S-1-5-32-"):
        return True
    parts = s.split("-")
    # Domain principal: S, 1, 5, 21, d1, d2, d3[, RID].
    if len(parts) >= 4 and parts[1] == "1" and parts[2] == "5" and parts[3] == "21":
        # A bare domain SID (no RID component) is itself structural.
        if len(parts) <= 7:
            return True
        try:
            rid = int(parts[7])
        except (ValueError, IndexError):
            return False
        return rid < _DOMAIN_BUILTIN_RID_FLOOR
    # Generic single-subauthority NT-authority SID: S-1-5-<n>.
    if len(parts) == 4 and parts[1] == "1" and parts[2] == "5":
        return True
    return False


def _name_token(name: object) -> str:
    """Return a name lower-cased and stripped of a trailing ``@domain`` suffix."""
    token = str(name or "").strip().lower()
    return token.split("@", 1)[0].strip()


def is_structural_well_known_principal(sid: str, name: str | None = None) -> bool:
    """Return whether a principal is a structural well-known / built-in object.

    ``True`` for every identity that is reserved / built-in and therefore neither
    an ordinary countable principal nor a removable object — see the module
    docstring for the two consuming seams (exposure-KPI numerator, choke ranking).

    The SID is the authoritative signal (classified by :func:`_sid_is_structural_well_known`,
    a RID/class rule, never a name allow-list). ``name`` is a FALLBACK only, for a
    graph node that carries a label but no SID: it matches the broad-logon
    populations in :data:`BROAD_LOGON_NAMES` (Everyone / Authenticated Users /
    Users / Domain Users), the structural names a label-only node can state.

    Args:
        sid: The principal's SID (any case; ``""``/``None`` falls through to name).
        name: The principal's name or label (optional), used only when the SID does
            not resolve the question.

    Returns:
        ``True`` when the principal is structurally well-known / built-in.
    """
    if sid and _sid_is_structural_well_known(str(sid)):
        return True
    return _name_token(name) in BROAD_LOGON_NAMES


#: Everyone / World — held by both a GUEST token and, when the DC's
#: "Let Everyone permissions apply to anonymous users" policy is set, a
#: NULL/anonymous token too.
_EVERYONE_SID = "S-1-1-0"

#: BUILTIN\\Guests — held only by a GUEST token.
_BUILTIN_GUESTS_SID = "S-1-5-32-546"

#: Anonymous Logon — held only by a NULL/anonymous token.
_ANONYMOUS_LOGON_SID = "S-1-5-7"


def is_domain_guest_account_sid(sid: str) -> bool:
    """Return whether a SID is a domain Guest account (reserved RID 501).

    Matches ``S-1-5-21-<d1>-<d2>-<d3>-501`` by SID **shape**, never by name —
    the domain SID prefix varies per forest, so this cannot be a fixed literal
    like the other well-known constants in this module. A GUEST token
    provably holds its own domain's Guest-account SID.

    Args:
        sid: The candidate SID (any case).

    Returns:
        ``True`` only for a domain SID whose RID is exactly 501.
    """
    s = (sid or "").strip().upper()
    if not s.startswith("S-1-5-21-"):
        return False
    return s.endswith("-501")


def credential_less_readset_sids(
    reached_via: str, everyone_includes_anonymous: bool = False
) -> frozenset[str]:
    """Return the well-known SID set a credential-less token can use.

    ADscan's guest/null-session foothold techniques authenticate with NO
    domain credential, and a token minted that way carries only a FIXED,
    protocol-defined SID set — never the broad authenticated-domain
    populations. This is the discriminator behind "who can read this with no
    credentials at all": an Authenticated-Users-only (S-1-5-11) read-set entry
    authorizes NEITHER a guest NOR a null token, even though it authorizes
    nearly every real domain user.

    * ``reached_via="guest_session"`` (GUEST token) — Everyone (S-1-1-0) and
      BUILTIN\\Guests (S-1-5-32-546). The domain Guest account itself (RID
      501) is also held by this token but is DOMAIN-SPECIFIC, so it is not a
      member of this fixed set — match it separately with
      :func:`is_domain_guest_account_sid`.
    * ``reached_via="null_session"`` (NULL/anonymous token) — Anonymous Logon
      (S-1-5-7) always; Everyone (S-1-1-0) is added ONLY when
      ``everyone_includes_anonymous`` is True (the DC's "Let Everyone
      permissions apply to anonymous users" policy).

    Neither token ever holds Authenticated Users (S-1-5-11) or
    BUILTIN\\Users (S-1-5-32-545) — those require a real, authenticated
    logon.

    Args:
        reached_via: ``"guest_session"`` or ``"null_session"``.
        everyone_includes_anonymous: When True, the null token also carries
            Everyone (a DC-wide policy observation, not a per-call guess).

    Returns:
        The frozenset of well-known SIDs usable by that token. An
        unrecognized ``reached_via`` fails closed to an empty set.
    """
    if reached_via == "guest_session":
        return frozenset({_EVERYONE_SID, _BUILTIN_GUESTS_SID})
    if reached_via == "null_session":
        if everyone_includes_anonymous:
            return frozenset({_ANONYMOUS_LOGON_SID, _EVERYONE_SID})
        return frozenset({_ANONYMOUS_LOGON_SID})
    return frozenset()


def is_broad_logon_principal(sid: str, name: str | None = None) -> bool:
    """Return whether a principal is a broad LOGON population (NOT all built-ins).

    The whole authenticated / standard-user population — Everyone (S-1-1-0),
    Authenticated Users (S-1-5-11), ``BUILTIN\\Users`` (S-1-5-32-545), Domain Users
    (a domain SID ending ``-513``) — and, as a name fallback, :data:`BROAD_LOGON_NAMES`.

    This is a STRICT SUBSET of :func:`is_structural_well_known_principal`: a
    built-in ADMIN group (Domain Admins, ``BUILTIN\\Administrators``) is structural
    well-known but is NOT a broad logon population. The RDS/Citrix-server signal
    (``compromise_class._graph_node_is_broad_logon_source``) consumes THIS predicate
    so a server reachable only by Domain Admins is not misread as a logon host.

    Args:
        sid: The principal's SID (any case).
        name: The principal's name or label (optional) used as a fallback.

    Returns:
        ``True`` only for the broad logon populations above.
    """
    s = str(sid or "").strip().upper()
    if s:
        if s in {"S-1-1-0", "S-1-5-11", "S-1-5-32-545"} or s.endswith("-513"):
            return True
    return _name_token(name) in BROAD_LOGON_NAMES
