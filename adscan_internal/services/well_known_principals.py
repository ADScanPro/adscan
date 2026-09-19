"""Well-known / synthetic Windows principal identity — SEMANTIC classification.

This is the single source of truth for "is this fixed OS/NT-authority identity a
COMPUTED identity with no manageable membership", plus the attack-graph
classification sets (Tier-0 well-known groups, non-grantee owner abstractions).

The DISPLAY humanizers and the public well-known-SID display table live in the
dependency-light ``adscan_core.reporting.principal_display`` (importable
EVERYWHERE, including the ``adscan_internal``-free web/appliance backend). This
module RE-EXPORTS them so every existing
``from adscan_internal.services.well_known_principals import humanize_principal_*``
call site keeps working, and the CLI report + the web CTEM humanize a principal
through the ONE shared implementation — never a fork.

It lives as a LEAF module directly under ``services/`` (NOT under
``services/collector/``) deliberately: the collector package's ``__init__`` pulls
in the native AD stack (aiosmb/badldap/kerbad), so importing anything under
``collector/`` drags that stack in. The report/writeup/web render surfaces — and
the appliance backend, which ships only the light service leaves plus
``adscan_core`` — must be able to humanize a principal label WITHOUT the engine.
So the semantic helpers here stay ``__future__`` + ``typing`` + ``adscan_core``
only (safe to bundle), and :mod:`adscan_internal.services.collector.well_known_sids`
re-exports them for the collector's own node-injection use.
"""

from __future__ import annotations

# DISPLAY layer — the SSOT lives in adscan_core so the web/appliance backend can
# import it without crossing the adscan_internal tier boundary. Re-exported here
# for the many report/writeup/collector call sites that import from this module.
from adscan_core.reporting.principal_display import (  # noqa: F401
    _CANONICAL_WELLKNOWN_NAME_BY_LOWER,
    _DOMAIN_RELATIVE_RID_NAMES,
    _WELL_KNOWN,
    _looks_like_sid,
    humanize_domain_for_display,
    humanize_principal_for_prose,
    humanize_principal_label,
    resolve_sid_display_name,
    well_known_sid_display_name,
)

# Non-grantee well-known SIDs: owner/creator ABSTRACTIONS, not fixed principals.
# An ACE for one of these does NOT grant a usable principal access to the object —
# it is an inheritance/owner template resolved at runtime (Creator Owner = whoever
# creates a child object and the rights they get ON THAT CHILD; Owner Rights =
# whatever the current owner is granted). You cannot authenticate as them, so an
# access edge (share-access, ACL control) sourced FROM these is a false capability
# — e.g. a "Creator Owner: Full Control" ACE on a read-only share must NOT yield a
# WriteShare edge. Edge emission excludes them.
NON_GRANTEE_SIDS: frozenset[str] = frozenset(
    {
        "S-1-3-0",  # Creator Owner
        "S-1-3-1",  # Creator Group
        "S-1-3-4",  # Owner Rights
    }
)

# Tier-0 well-known SIDs — mark highvalue so the attack graph treats them correctly
_TIER_ZERO_WELL_KNOWN: frozenset[str] = frozenset(
    {
        "S-1-5-9",  # Enterprise Domain Controllers
        "S-1-5-18",  # System
        "S-1-5-32-544",  # Administrators
        "S-1-5-32-548",  # Account Operators
        "S-1-5-32-549",  # Server Operators
        "S-1-5-32-550",  # Print Operators
        "S-1-5-32-551",  # Backup Operators
    }
)

# The subset of well-known identities that have NO manageable member list.
#
# The axis is COMPUTED/IMPLICIT identity, not privilege tier and not "is it
# well-known". Membership in these is assigned at logon or authentication time
# by the OS (SAM/LSA), the KDC, or the authentication subsystem — there is no
# group object whose ``member`` attribute an administrator can edit. So a
# remediation for a step whose target is one of these must NEVER say "remove
# principal X from it": that operation does not exist. The correct fix is to
# scope what the identity is GRANTED (lock down the inherited ACE / the
# world-readable attribute it can read), never to edit a member list it lacks.
#
# NOTE this is orthogonal to tier and to "is it well-known": Backup Operators
# (``S-1-5-32-551``) is well-known AND Tier-0 AND has a real, editable member
# list, so it is NOT here — "remove X from Backup Operators" stays a valid
# remediation. Every BUILTIN ``S-1-5-32-*`` group has real membership and is
# excluded. Domain Users (RID 513) and Domain Computers (RID 515) are implicit
# primary-group identities matched by RID suffix (they are domain-relative, not
# fixed SIDs) — a principal's primary group is never in its ``member`` list.
DYNAMIC_IDENTITY_SIDS: frozenset[str] = frozenset(
    {
        "S-1-1-0",  # Everyone
        "S-1-5-1",  # Dialup
        "S-1-5-2",  # Network
        "S-1-5-3",  # Batch
        "S-1-5-4",  # Interactive
        "S-1-5-6",  # Service
        "S-1-5-7",  # Anonymous Logon
        "S-1-5-9",  # Enterprise Domain Controllers
        "S-1-5-11",  # Authenticated Users
        "S-1-5-14",  # Remote Interactive Logon
        "S-1-5-15",  # This Organization
        "S-1-5-64-10",  # NTLM Authentication
        "S-1-5-64-14",  # SChannel Authentication
        "S-1-5-64-21",  # Digest Authentication
        "S-1-5-80-0",  # All Services
    }
)

# Domain-relative RIDs whose membership is implicit (never in ``memberOf``):
# a principal's primary group. Matched by the RID suffix of an ``S-1-5-21-*`` SID.
_DYNAMIC_IDENTITY_RIDS: frozenset[str] = frozenset({"513", "515"})


def is_dynamic_identity(sid: str) -> bool:
    """Return True when ``sid`` is a computed identity with no manageable membership.

    See :data:`DYNAMIC_IDENTITY_SIDS`. The predicate is by SID (invariant), never
    a tier check or a label-name guess: a fixed dynamic-identity SID, or a
    domain-relative primary-group SID (Domain Users RID 513 / Domain Computers
    RID 515) matched by its RID suffix. Everything else (a real group with an
    editable member list, including BUILTIN privileged groups) is False.
    """
    sid_upper = str(sid or "").strip().upper()
    if not sid_upper:
        return False
    if sid_upper in DYNAMIC_IDENTITY_SIDS:
        return True
    if sid_upper.startswith("S-1-5-21-"):
        return sid_upper.rsplit("-", 1)[-1] in _DYNAMIC_IDENTITY_RIDS
    return False


# Lowercased display names of the dynamic identities, for a label fallback when a
# step carries no stamped SID (an older graph). Derived from the SID sets so the
# two can never disagree. Domain Users / Domain Computers are added by name because
# they are domain-relative (matched by RID above, but their @WELLKNOWN/label form
# needs the name).
_DYNAMIC_IDENTITY_NAMES: frozenset[str] = frozenset(
    {name.lower() for sid in DYNAMIC_IDENTITY_SIDS if (name := _WELL_KNOWN.get(sid, ("", ""))[0])}
    | {"domain users", "domain computers"}
)


def principal_is_dynamic_identity(*, sid: str = "", label: str = "") -> bool:
    """Return True when a principal is a dynamic identity with no manageable membership.

    Prefers the invariant SID; falls back to the label (a bare SID, or a
    ``NAME@WELLKNOWN`` synthetic label, or a real ``NAME@DOMAIN`` node whose name
    is a dynamic identity) for an older graph that carries no stamped SID. Used by
    every surface that renders a "remove principal X from this group" remediation
    — the report, the writeup, and the web CTEM — so none of them offers that
    operation for an unmanageable identity.
    """
    if sid and is_dynamic_identity(sid):
        return True
    raw = str(label or "").strip()
    if not raw:
        return False
    name_part, _, _realm = raw.partition("@")
    name_part = name_part.strip()
    if _looks_like_sid(name_part):
        return is_dynamic_identity(name_part)
    # The dynamic-identity NAMES (Everyone, Authenticated Users, Domain Users, ...)
    # are unambiguous — no manageable group shares one — so a name match holds
    # regardless of the realm suffix. This catches a real LDAP ``Domain Users@DOMAIN``
    # node (RID 513, domain-relative, so its label is not ``@WELLKNOWN``) when no SID
    # was stamped.
    return name_part.lower() in _DYNAMIC_IDENTITY_NAMES
