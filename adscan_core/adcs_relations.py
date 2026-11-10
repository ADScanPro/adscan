"""The single set of attack-graph relations that are AD Certificate Services.

Four copies of this set existed in the tree and all four had drifted, so "is
this relation AD CS" answered differently depending on which surface asked:

====================================================================== ======
Copy                                                                   Size
====================================================================== ======
``adscan_internal/services/adcs_path_display._ADCS_RELATIONS``             23
``adscan_internal/services/affected_assets._ADCS_RELATIONS``               16
``adscan_core/reporting/adcs_finding_state.ADCS_ESC_RELATIONS``            16
``adscan_web/.../adcs_inventory_parser._KNOWN_ADCS_TECHNIQUES``            16
====================================================================== ======

The affected-assets copy was missing every lettered variant (``ADCSESC6a``,
``6b``, ``9a``, ``9b``, ``10a``, ``10b``) and the coercion relay, so an
``ADCSESC9a`` finding never got the AD CS asset treatment that names the
template it abuses. The finding-state copy was missing the lettered variants
plus ``ADCSESC16`` and ``ADCSESC17``, so those escalations never rendered under
the three honest AD CS states.

This module is the one definition. It lives in ``adscan_core`` because the
consumers sit on both sides of the tier boundary: the engine and the report
renderers import ``adscan_internal``, the web backend cannot, and both can
import this.

Why a set and not a prefix test: ``coerceandrelayntlmtoadcs`` and
``certighost`` are AD CS relations that do not start with ``ADCSESC``, so a
prefix filter silently drops the coercion relay path and the chase-fallback DC
impersonation. ``ADCSESC12`` (CA key in a YubiHSM whose KSP password is stored in
the CA host registry) is detected read-only and anchored at the CA host.

Pure logic: stdlib only, no IO, no console, no network.
"""

from __future__ import annotations

from typing import Any, Final

#: Every attack-graph relation that is an AD Certificate Services technique,
#: lower-cased. Compare through :func:`is_adcs_relation`, which normalizes, so
#: a caller never has to remember the casing a given surface stores.
#:
#: Membership rule: a relation belongs here when it abuses the certificate
#: services surface (a template, a CA, the NTAuth store, the enrollment
#: endpoint) to obtain authentication material. The lettered variants are the
#: sub-cases BloodHound CE splits an ESC into (``ADCSESC9a`` = user, ``9b`` =
#: computer); they are the same technique family and must classify the same.
ADCS_RELATIONS: Final[frozenset[str]] = frozenset(
    {
        "adcsesc1",
        "adcsesc2",
        "adcsesc3",
        "adcsesc4",
        "adcsesc5",
        "adcsesc6",
        "adcsesc6a",
        "adcsesc6b",
        "adcsesc7",
        "adcsesc8",
        "adcsesc9",
        "adcsesc9a",
        "adcsesc9b",
        "adcsesc10",
        "adcsesc10a",
        "adcsesc10b",
        "adcsesc11",
        "adcsesc12",
        "adcsesc13",
        "adcsesc14",
        "adcsesc15",
        "adcsesc16",
        "adcsesc17",
        "certighost",
        "coerceandrelayntlmtoadcs",
    }
)


def is_adcs_relation(relation: Any) -> bool:
    """Return whether ``relation`` names an AD CS technique.

    Case-insensitive and whitespace-tolerant, because the same relation is
    stored upper-cased on a graph edge (``ADCSESC4``), lower-cased in a step's
    ``action`` field, and title-cased in some collector records.

    Args:
        relation: The relation / edge-type / technique token, any casing.

    Returns:
        ``True`` when the token is one of :data:`ADCS_RELATIONS`.
    """
    return str(relation or "").strip().lower() in ADCS_RELATIONS


#: Resource kinds, as stamped into an AD CS edge's ``vulnerable_resources``,
#: that name a piece of PKI *configuration* — the object an administrator
#: edits to remove the exposure.
#:
#: The other kinds that appear there (``User``, ``Computer``) are the
#: impersonation victims an ESC9 / ESC14 mapping abuse can reach. Those are
#: still affected objects and are still reported; they are just not PKI
#: configuration, which matters when a surface wants to say "templates and
#: authorities to fix" rather than "objects affected".
ADCS_PKI_OBJECT_KINDS: Final[frozenset[str]] = frozenset(
    {"certtemplate", "enterpriseca", "aiaca", "rootca", "ntauthstore"}
)


def is_adcs_pki_object_kind(kind: Any) -> bool:
    """Return whether ``kind`` names a PKI configuration object."""
    return str(kind or "").strip().lower() in ADCS_PKI_OBJECT_KINDS
