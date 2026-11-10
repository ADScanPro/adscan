"""Reserved, non-domain buckets under a workspace's ``domains/`` directory.

A workspace stores per-domain state under ``<workspace>/domains/<domain>/``, and
several consumers enumerate that directory to answer "which domains does this
workspace have" — the web's workspace/domain listing, the attack-graph and
timeline readers, the CLI's domain picker. That enumeration is only correct while
EVERY entry under ``domains/`` is a real domain.

It is not. Credential material captured off the wire (a NetNTLM hash lured to the
:445 listener by broadcast poisoning, a write-share bait, or the NTLM auth-type
sweep) arrives with a principal and, sometimes, a NetBIOS domain name — and
neither may be attributable to a collected domain at the instant it lands. The
material is real, it is crackable, and it must not be dropped, so it needs
somewhere to live; but it is NOT a domain, and the directory it lives in must
never be rendered to a client as one. A placeholder that reads like a domain name
is a credibility defect in a paid deliverable: the client asks which of their
domains that is, and the honest answer is that it is not one of them.

So the bucket is RESERVED and named so that nothing can mistake it for a domain:
``_unattributed`` starts with an underscore, which no DNS label may, so it is
syntactically impossible as a domain name. :func:`is_reserved_domain_bucket` is
the one predicate every ``domains/``-enumerating consumer applies, and
:func:`reserved_bucket_display_label` is the one phrase that describes it to a
human when the material itself is worth showing.

``captured`` is carried as a LEGACY reserved name. Workspaces on disk already
hold a ``domains/captured/`` directory written before this module existed, and
that material must not be deleted; treating the old name as reserved makes every
consumer stop rendering it as a domain immediately, with no migration needed. The
engine re-files what it can attribute and merges the remainder under the current
name (see ``captured_credential_attribution.reconcile_unattributed_captures``).

This module is dependency-light and lives in ``adscan_core`` on purpose: the CLI
engine, the report renderers and the ``adscan_web`` backend (which bundles
``adscan_core`` on the appliance and must never import ``adscan_internal``) all
need the SAME predicate. A hardcoded ``!== "captured"`` in one frontend or one
service is exactly the per-surface patch that lets the next reserved name leak.
"""

from __future__ import annotations

from typing import Iterable

#: The current reserved bucket for captured credential material that could not
#: be attributed to a collected domain. The leading underscore is load-bearing:
#: a DNS label cannot start with one, so this can never collide with, or be
#: mistaken for, a real domain name.
UNATTRIBUTED_CREDENTIALS_BUCKET = "_unattributed"

#: Reserved bucket names written by earlier versions. Kept reserved forever so an
#: existing workspace stops rendering them as domains without needing a
#: migration to have run first. NEVER remove a name from this set: the directory
#: it names may still exist on a customer's disk.
LEGACY_RESERVED_DOMAIN_BUCKETS = frozenset({"captured"})

#: Every name under ``domains/`` that is a reserved bucket rather than a domain.
RESERVED_DOMAIN_BUCKETS = frozenset({UNATTRIBUTED_CREDENTIALS_BUCKET}) | LEGACY_RESERVED_DOMAIN_BUCKETS

#: What the bucket IS, in one client-safe phrase. Used wherever the captured
#: material is surfaced on its own terms instead of as a domain.
_UNATTRIBUTED_LABEL = "Credentials captured off the network (not yet attributed to a domain)"


def is_reserved_domain_bucket(name: str | None) -> bool:
    """Return whether a ``domains/`` entry is a reserved bucket, not a domain.

    Case- and whitespace-insensitive, and tolerant of a trailing dot (an FQDN
    root), so a caller never has to normalise before asking. A blank name is not
    a bucket (it is not a domain either; that is the caller's own guard).

    Every consumer that enumerates ``domains/`` directories — or that iterates
    domain keys that may have been seeded from one — filters with this.
    """
    candidate = str(name or "").strip().strip(".").lower()
    if not candidate:
        return False
    return candidate in RESERVED_DOMAIN_BUCKETS


def filter_domain_names(names: Iterable[str | None]) -> list[str]:
    """Return ``names`` with every reserved bucket removed, order preserved.

    The convenience form for the common call shape: a list of directory entries
    or domain keys that is about to be presented, counted, or iterated as "the
    workspace's domains".
    """
    return [str(name) for name in names if name and not is_reserved_domain_bucket(name)]


def reserved_bucket_display_label(name: str | None) -> str:
    """Return the human phrase for a reserved bucket, or ``""`` if not one.

    Client-safe: it states what the material is and that its domain is unknown,
    and it never implies the bucket is a domain the client owns.
    """
    if not is_reserved_domain_bucket(name):
        return ""
    return _UNATTRIBUTED_LABEL


__all__ = [
    "LEGACY_RESERVED_DOMAIN_BUCKETS",
    "RESERVED_DOMAIN_BUCKETS",
    "UNATTRIBUTED_CREDENTIALS_BUCKET",
    "filter_domain_names",
    "is_reserved_domain_bucket",
    "reserved_bucket_display_label",
]
