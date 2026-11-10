"""Who is exposed to offline Kerberos ticket cracking: the single predicate.

Kerberoasting and AS-REP roasting both end in the same place: a ticket encrypted
with a key derived from the account's password, taken offline and guessed. The
exposure is therefore a property of WHO SETS THE PASSWORD, and three classes of
account never qualify no matter what their service principal names or their
pre-authentication flag say:

* a **group managed service account** (gMSA) and a **standalone managed service
  account** (sMSA) — the directory generates a 240-character random password and
  rotates it on its own schedule;
* a **machine account** — the same arrangement with a 120-character password the
  computer rotates against the domain.

None of those is guessable, so an account holding one is not a Kerberoasting or
AS-REP roasting exposure and must not be counted, listed or targeted as one. It
is still a real identity with real exposure, and the product says so elsewhere:
whoever may retrieve a gMSA's managed password holds the account (the
``ReadGMSAPassword`` relation in the attack graph), and a managed account that
publishes an ``HTTP/*`` service principal name carries a Kerberos web-service
relay surface of its own (the ``http_spn_relay_surface`` finding). What this
module removes is one specific, wrong claim, not the account.

This module lives in ``adscan_core`` because all three consumers need the same
answer and they cannot share anything else: the engine's collector and inventory
queries, the deliverable, and the web product's Postgres-backed views, which
cannot import ``adscan_internal``. Before it existed each surface decided for
itself and they disagreed, so a gMSA was absent from the report and present in
the paid web product's "exploitable today" panel for the same scan.

Two call shapes are supported deliberately. The engine holds flat graph/inventory
property dictionaries and builds :class:`AccountSignals` through
:meth:`AccountSignals.from_properties`; the web holds an ORM row and constructs
:class:`AccountSignals` directly from the columns it already stores. Both reach
the same predicate.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

__all__ = [
    "AccountSignals",
    "MANAGED_SERVICE_ACCOUNT_CONTAINER_RDN",
    "MANAGED_SERVICE_ACCOUNT_OBJECT_CLASSES",
    "NOT_AD_MANAGED_PASSWORD_LDAP",
    "ROASTABLE_SPN_LDAP_FILTER",
    "account_type_is_managed_service_account",
    "is_asrep_roastable",
    "is_kerberoastable",
    "is_machine_account",
    "is_managed_service_account",
    "password_is_ad_managed",
]


#: The ``objectClass`` values that identify a managed service account. A gMSA is
#: ``msDS-GroupManagedServiceAccount``; the older single-host sMSA is
#: ``msDS-ManagedServiceAccount``. Both hold a directory-generated password.
MANAGED_SERVICE_ACCOUNT_OBJECT_CLASSES: tuple[str, ...] = (
    "msDS-GroupManagedServiceAccount",
    "msDS-ManagedServiceAccount",
)

#: The canonical container both account kinds live under, used as a fallback for
#: collector output that carries neither a decoded flag nor an ``objectClass``.
MANAGED_SERVICE_ACCOUNT_CONTAINER_RDN = "cn=managed service accounts,"

#: ``account_type`` values the native LDAP collector pre-decodes for a managed
#: service account.
_MANAGED_ACCOUNT_TYPES = frozenset({"gmsa", "smsa"})

#: ``account_type`` / ``kind`` values that mean a machine account.
_MACHINE_ACCOUNT_TYPES = frozenset({"computer", "machine"})

#: An LDAP filter fragment excluding every account whose password the directory
#: generates. The live roasting enumeration composes it rather than restating the
#: rule, so the accounts a scan actually requests tickets for are the accounts
#: this module calls exposed. Machine accounts are ``objectCategory=computer``;
#: managed service accounts have their own object categories and would otherwise
#: pass a computer-only negation untouched, which is exactly how a gMSA used to
#: reach the ticket request.
NOT_AD_MANAGED_PASSWORD_LDAP = "(!(objectCategory=computer))" + "".join(
    f"(!(objectClass={object_class}))"
    for object_class in MANAGED_SERVICE_ACCOUNT_OBJECT_CLASSES
)

#: The directory-side form of :func:`is_kerberoastable`: an account publishing a
#: service principal name whose password a human chose.
ROASTABLE_SPN_LDAP_FILTER = f"(&(servicePrincipalName=*){NOT_AD_MANAGED_PASSWORD_LDAP})"


def _normalize(value: Any) -> str:
    return str(value or "").strip().casefold()


def _as_tuple(values: Any) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, str):
        return (values,)
    if isinstance(values, Iterable):
        return tuple(str(value) for value in values if str(value).strip())
    return ()


@dataclass(frozen=True)
class AccountSignals:
    """What an artifact records about an account's class.

    Every field is optional because no single one is present in every artifact
    ADscan reads: a native graph node carries ``account_type`` and ``is_gmsa``, a
    graph written before those existed carries only the distinguished name, raw
    LDAP results carry ``objectClass``, and a persisted web asset row carries a
    decoded boolean. Reading several signals rather than one is what lets the
    same predicate serve all of them.

    The trailing ``$`` on a sAMAccountName is deliberately NOT a signal. Every
    managed service account has one, and so does every inter-domain trust
    account, which is a different class entirely; keying on the suffix is the
    fragile heuristic this module exists to replace.
    """

    account_type: str = ""
    is_gmsa: bool = False
    object_classes: tuple[str, ...] = ()
    distinguished_name: str = ""
    kind: str = ""

    @classmethod
    def from_properties(cls, props: Any) -> "AccountSignals":
        """Build signals from a flat graph-node / inventory property mapping."""
        if not isinstance(props, dict):
            return cls()
        object_classes = (
            props.get("objectclasses")
            or props.get("objectclass")
            or props.get("objectClass")
        )
        return cls(
            account_type=str(props.get("account_type") or ""),
            is_gmsa=bool(props.get("is_gmsa")),
            object_classes=_as_tuple(object_classes),
            distinguished_name=str(props.get("distinguishedname") or ""),
            kind=str(props.get("kind") or ""),
        )


def account_type_is_managed_service_account(account_type: Any) -> bool:
    """Return whether a pre-decoded ``account_type`` names a gMSA or an sMSA."""
    return _normalize(account_type) in _MANAGED_ACCOUNT_TYPES


def is_managed_service_account(signals: AccountSignals) -> bool:
    """Return whether the account is a gMSA or an sMSA.

    The directory generates and rotates its password, so it is neither a human
    identity nor a guessable one. It remains a first-class service identity: it
    stays in the user inventory and keeps its own findings.
    """
    if account_type_is_managed_service_account(signals.account_type):
        return True
    if signals.is_gmsa:
        return True
    for object_class in signals.object_classes:
        normalized = _normalize(object_class).replace("-", "")
        if normalized in {
            _normalize(known).replace("-", "")
            for known in MANAGED_SERVICE_ACCOUNT_OBJECT_CLASSES
        }:
            return True
    return MANAGED_SERVICE_ACCOUNT_CONTAINER_RDN in _normalize(
        signals.distinguished_name
    )


def is_machine_account(signals: AccountSignals) -> bool:
    """Return whether the account is a computer account.

    A computer rotates its own 120-character password against the domain, so a
    service ticket encrypted to it is no more crackable than a gMSA's.
    """
    if _normalize(signals.kind) in _MACHINE_ACCOUNT_TYPES:
        return True
    if _normalize(signals.account_type) in _MACHINE_ACCOUNT_TYPES:
        return True
    return any(_normalize(value) == "computer" for value in signals.object_classes)


def password_is_ad_managed(signals: AccountSignals) -> bool:
    """Return whether the directory, rather than a person, sets this password.

    The one condition behind both roasting predicates below. An account that
    answers True to this cannot be exposed by either technique, whatever its
    service principal names or pre-authentication setting say.
    """
    return is_managed_service_account(signals) or is_machine_account(signals)


def is_kerberoastable(signals: AccountSignals, *, has_spn: bool) -> bool:
    """Return whether a service ticket for this account is worth cracking.

    The caller owns whether the account is enabled and in scope; this answers
    only the technique's own condition. ``has_spn`` is the published service
    principal name that lets any authenticated principal request the ticket.
    """
    return bool(has_spn) and not password_is_ad_managed(signals)


def is_asrep_roastable(signals: AccountSignals, *, preauth_required: bool) -> bool:
    """Return whether an AS-REP for this account is worth cracking.

    ``preauth_required`` mirrors the directory's own sense: False means
    ``DONT_REQ_PREAUTH`` is set and anyone can ask for the response unauthenticated.
    """
    return not preauth_required and not password_is_ad_managed(signals)
