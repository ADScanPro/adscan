"""Neutral hash-kind registry — the SSOT for hashcat mode ↔ John format mapping.

A :class:`HashKind` is a cracker-agnostic identifier for a family of crackable
hashes (Kerberoast, AS-REP, NetNTLM, NT, ...). Each backend maps a kind to its
own mode/format vocabulary:

- hashcat uses a numeric ``-m`` mode (e.g. ``13100`` for Kerberoast RC4).
- John the Ripper uses a ``--format`` name (e.g. ``krb5tgs``).

Keeping the mapping in ONE place lets the effort engine and the two backends
agree on what a given kind means without duplicating the tables. The old
``_HASHCAT_MODE_TO_JOHN_FORMAT`` dict in ``adscan_internal/cli/cracking.py`` is
now derived from this registry (see that module).

AES roast kinds are the one place hashcat has two modes per kind (AES128 and
AES256, e.g. ``19600``/``19700`` for Kerberoast). This registry picks ONE
canonical mode per kind so the reverse lookup is unambiguous: ``19600`` for
Kerberoast-AES and ``19800`` for AS-REP-AES (the AES128 modes). The AES256 modes
(``19700``/``19900``) still resolve to the same John format via the derived dict
in ``cli/cracking.py`` — they are simply not the canonical representative of the
kind.

``TIMEROAST`` has a hashcat mode (``31300``) but no John format — John cannot
process it. :func:`john_format_for` returns ``None`` for it, an honest capability
gap that Windows CPU-only cracking degrades on.
"""

from __future__ import annotations

from enum import Enum


class HashKind(Enum):
    """Cracker-agnostic identifier for a family of crackable hashes."""

    NETNTLMV2 = "netntlmv2"
    NETNTLMV1 = "netntlmv1"
    KERBEROAST = "kerberoast"
    ASREP = "asrep"
    NT = "nt"
    KERBEROAST_AES = "kerberoast_aes"
    ASREP_AES = "asrep_aes"
    TIMEROAST = "timeroast"


# Canonical hashcat ``-m`` mode per kind. For AES roast kinds this is the AES128
# mode; the AES256 sibling maps to the same John format via the derived dict in
# ``cli/cracking.py`` but is not the canonical representative here.
_HASHCAT_MODE: dict[HashKind, str] = {
    HashKind.NETNTLMV2: "5600",
    HashKind.NETNTLMV1: "5500",
    HashKind.KERBEROAST: "13100",
    HashKind.ASREP: "18200",
    HashKind.NT: "1000",
    HashKind.KERBEROAST_AES: "19600",
    HashKind.ASREP_AES: "19800",
    HashKind.TIMEROAST: "31300",
}

# John the Ripper ``--format`` per kind. A kind absent from this map has no John
# fallback (``TIMEROAST`` — John cannot crack it).
_JOHN_FORMAT: dict[HashKind, str] = {
    HashKind.NETNTLMV2: "netntlmv2",
    HashKind.NETNTLMV1: "netntlmv1",
    HashKind.KERBEROAST: "krb5tgs",
    HashKind.ASREP: "krb5asrep",
    HashKind.NT: "nt",
    HashKind.KERBEROAST_AES: "krb5tgs",
    HashKind.ASREP_AES: "krb5asrep",
}

# Reverse index: canonical hashcat mode -> kind. Built from ``_HASHCAT_MODE`` so
# the two never drift.
_MODE_TO_KIND: dict[str, HashKind] = {
    mode: kind for kind, mode in _HASHCAT_MODE.items()
}

# Non-canonical AES256 roast modes map to the SAME kind as their AES128 sibling
# (the canonical representative). Kept separate from ``_MODE_TO_KIND`` so
# :func:`kind_for_hashcat_mode`'s documented "canonical only" contract is
# unchanged; :func:`resolve_kind_for_mode` is the superset that also resolves
# these, for dispatch paths that hand a raw hashcat mode to a backend.
_AES256_MODE_TO_KIND: dict[str, HashKind] = {
    "19700": HashKind.KERBEROAST_AES,
    "19900": HashKind.ASREP_AES,
}


def hashcat_mode_for(kind: HashKind) -> str:
    """Return the canonical hashcat ``-m`` mode string for ``kind``.

    Args:
        kind: The neutral hash kind.

    Returns:
        The hashcat mode string (e.g. ``"13100"`` for Kerberoast RC4).
    """
    return _HASHCAT_MODE[kind]


def john_format_for(kind: HashKind) -> str | None:
    """Return the John the Ripper ``--format`` for ``kind``, or ``None``.

    Args:
        kind: The neutral hash kind.

    Returns:
        The John ``--format`` name, or ``None`` when John cannot process the
        kind (e.g. ``TIMEROAST``).
    """
    return _JOHN_FORMAT.get(kind)


def kind_for_hashcat_mode(mode: str) -> HashKind | None:
    """Reverse-resolve a canonical hashcat ``-m`` mode to its :class:`HashKind`.

    Only canonical modes resolve — the AES256 siblings (``19700``/``19900``) are
    not canonical representatives and return ``None`` here (use
    :func:`john_format_for` on the kind, or the derived dict in
    ``cli/cracking.py``, when you need those).

    Args:
        mode: The hashcat mode string.

    Returns:
        The matching :class:`HashKind`, or ``None`` when no kind claims ``mode``.
    """
    return _MODE_TO_KIND.get(mode)


def resolve_kind_for_mode(mode: str) -> HashKind | None:
    """Resolve any hashcat ``-m`` mode (canonical OR AES256 sibling) to its kind.

    Superset of :func:`kind_for_hashcat_mode`: it ALSO resolves the non-canonical
    AES256 roast modes (``19700``/``19900``) to the same kind as their AES128
    sibling. Use this in dispatch paths that hand a raw hashcat mode to a backend
    driven by a :class:`HashKind` (e.g. the CPU/John fallback), where an AES256
    capture must still resolve.

    Args:
        mode: The hashcat mode string.

    Returns:
        The matching :class:`HashKind`, or ``None`` when no kind claims ``mode``.
    """
    normalized = str(mode or "").strip()
    return _MODE_TO_KIND.get(normalized) or _AES256_MODE_TO_KIND.get(normalized)
