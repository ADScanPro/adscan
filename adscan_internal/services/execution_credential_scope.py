"""Scope of the credential an attack path hands from one step to the next.

A credential carries two independent facts: the PRINCIPAL it authenticates as,
and the AUTHORITY that principal lives in.  The credential stores already keep
them apart — ``credentials`` holds domain principals, ``local_credentials[host]
[service]`` holds accounts that exist only inside one host's SAM, and
``service_tickets`` holds tickets that open exactly one SPN on one host — but
the in-path execution context used to hand the next step only
``(username, secret)``.

That drop is a real defect and not a cosmetic one.  A local ``Administrator``
recovered from LAPS on one member server became indistinguishable from the
domain ``Administrator``: the next step authenticated against the domain, which
fails outright when the two passwords differ, and *succeeds with a different
account* when the same-named domain principal happens to be reachable.  A
silently substituted principal inside a validated attack path is an
evidence-integrity problem — the report would describe a chain that did not
happen that way.

This module is the one place that answers, for every step:

* what scope did the credential we just captured have
  (:func:`derive_carried_credential`);
* which host, if any, does the next step authenticate to
  (:func:`step_authentication_host`);
* may the carried credential be used there
  (:func:`scope_carried_credential_to_step`).

The applicability rule is deliberately asymmetric.  A domain credential is
valid anywhere, so it always carries.  A host-scoped one carries only to a step
that authenticates to that same host; anywhere else it is *withheld*, and the
caller must resolve its own principal rather than inherit a name whose
authority no longer applies.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final, Optional

from adscan_internal.services.credential_store_service import (
    find_local_credential_record,
    hosts_match,
)

SCOPE_DOMAIN: Final[str] = "domain"
SCOPE_LOCAL: Final[str] = "local"

# Why a carried credential did not apply to a step. Surfaced in the operator
# log so a scope change is auditable rather than invisible.
WITHHELD_HOST_MISMATCH: Final[str] = "local_credential_host_mismatch"
WITHHELD_NOT_HOST_AUTHENTICATING: Final[str] = "local_credential_step_not_host_scoped"
APPLIED_DOMAIN: Final[str] = "domain_credential"
APPLIED_LOCAL: Final[str] = "local_credential_host_match"


def _normalize_account(value: str) -> str:
    """Return a comparable account name (no domain prefix, no realm suffix)."""
    name = str(value or "").strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name.strip().lower()


@dataclass(frozen=True)
class CarriedCredential:
    """The credential the in-path execution context currently carries.

    ``scope`` is the authority the principal belongs to.  For
    :data:`SCOPE_LOCAL` the ``host`` (and usually ``service``) complete the key
    the credential store uses — without them the credential is not identifiable
    and cannot be used safely.
    """

    username: str
    secret: str
    scope: str = SCOPE_DOMAIN
    host: Optional[str] = None
    service: Optional[str] = None
    source_action: str = ""

    @property
    def is_local(self) -> bool:
        """Whether this credential names an account local to one host."""
        return self.scope == SCOPE_LOCAL

    @property
    def islocal_flag(self) -> str:
        """The ``islocal`` argument the dump entry points take (``"true"``/``"false"``)."""
        return "true" if self.is_local else "false"

    def applies_to_host(self, host: Optional[str]) -> bool:
        """Whether this credential may be used to authenticate to *host*.

        A domain credential applies everywhere.  A local one applies only to
        its own host — an account in ``BRAAVOS``'s SAM cannot authenticate to
        ``MEEREEN``, and a step that authenticates to the domain (LDAP, the
        KDC, a DC-side write) has no host to match at all.
        """
        if not self.is_local:
            return True
        if not host or not self.host:
            return False
        return hosts_match(self.host, host)

    def matches(self, *, username: str, secret: str) -> bool:
        """Whether *username*/*secret* is exactly this carried credential."""
        return (
            _normalize_account(username) == _normalize_account(self.username)
            and secret == self.secret
        )

    def describe(self) -> str:
        """Return a short, log-safe description of the scope (no secret)."""
        if self.is_local:
            service = self.service or "?"
            return f"local:{self.host or '?'}/{service}"
        return SCOPE_DOMAIN


# ---------------------------------------------------------------------------
# Which host does a step authenticate to?
# ---------------------------------------------------------------------------
#
# A local credential can only ever be used by a step that authenticates to the
# host whose SAM holds the account.  Every other relation authenticates to the
# domain — an LDAP bind or a Kerberos AS/TGS against the DC — where a local
# account does not exist.  So this table is the complete surface on which a
# host-scoped credential is even a candidate, and it is why the fix does not
# need to touch the domain-authenticating branches: they inherit the
# withholding for free.
#
# The two groups differ in WHICH endpoint of the edge is the host:
#   * source-side — the step authenticates to the machine the edge starts at
#     (``DumpLSA``/``DumpDPAPI``/``DumpSAM`` dump the source host;
#     ``HasSession`` runs on the machine that holds the session);
#   * target-side — the step authenticates to the machine the edge points at
#     (``AdminTo``, ``CanRDP``, ``CanPSRemote``, ``ExecuteDCOM``, the MSSQL
#     access edges).
#
# ``DCSync`` is deliberately absent: it authenticates to a domain controller as
# a domain principal, so a member server's local account is never valid for it.
_HOST_AUTH_FROM_SOURCE: Final[frozenset[str]] = frozenset(
    {
        "dumplsa",
        "dumpdpapi",
        "dumpsam",
        "dumplsass",
        "hassession",
    }
)

_HOST_AUTH_FROM_TARGET: Final[frozenset[str]] = frozenset(
    {
        "adminto",
        "canrdp",
        "canpsremote",
        "executedcom",
        "sqladmin",
        "sqlaccess",
    }
)

# The local-credentials ``service`` key each host-authenticating relation binds
# with. Mirrors the service map the executor already uses for the access
# relations, extended with the dump family (all of which bind over SMB).
_RELATION_TO_LOCAL_SERVICE: Final[dict[str, str]] = {
    "dumplsa": "smb",
    "dumpdpapi": "smb",
    "dumpsam": "smb",
    "dumplsass": "smb",
    "hassession": "smb",
    "adminto": "smb",
    "executedcom": "smb",
    "canrdp": "rdp",
    "canpsremote": "winrm",
    "sqladmin": "mssql",
    "sqlaccess": "mssql",
}


def step_authentication_host(
    relation: str, *, from_label: str | None, to_label: str | None
) -> Optional[str]:
    """Return the host a step authenticates TO, or ``None`` for the domain.

    ``None`` means "this step authenticates against the domain, not against one
    machine" — LDAP writes, ADCS enrolment, Kerberos roasting, DCSync.  A local
    credential is never valid for those.
    """
    key = str(relation or "").strip().lower()
    if key in _HOST_AUTH_FROM_SOURCE:
        return str(from_label or "").strip() or None
    if key in _HOST_AUTH_FROM_TARGET:
        return str(to_label or "").strip() or None
    return None


def local_service_for_relation(relation: str) -> Optional[str]:
    """Return the ``local_credentials`` service key a relation binds with."""
    return _RELATION_TO_LOCAL_SERVICE.get(str(relation or "").strip().lower())


def derive_carried_credential(
    domains_data: Any,
    *,
    domain: str,
    username: str,
    secret: str,
    source_action: str = "",
    declared_scope: Optional[str] = None,
    declared_host: Optional[str] = None,
    declared_service: Optional[str] = None,
) -> Optional[CarriedCredential]:
    """Build the carried credential for a step handoff, scope included.

    A producer that knows the scope for certain declares it (``declared_*``).
    Everything else is derived from the stores, which is what makes this correct
    for every existing producer without editing each one: the step wrote the
    credential before handing it off, so the store already records whether it
    went to ``credentials`` or to ``local_credentials[host][service]``.

    Derivation order matters.  The domain store is consulted first: when the
    exact secret is what is stored for that domain principal, the credential IS
    the domain principal's and nothing else needs checking.  Only then is the
    local store scanned for the same ``(username, secret)`` pair.  With no match
    anywhere the credential is treated as domain-scoped, which is the
    pre-existing behaviour and the conservative choice — it never invents a host
    restriction that was not observed.
    """
    normalized_user = str(username or "").strip()
    normalized_secret = str(secret or "")
    if not normalized_user or not normalized_secret:
        return None

    if str(declared_scope or "").strip().lower() == SCOPE_LOCAL:
        host = str(declared_host or "").strip()
        if host:
            return CarriedCredential(
                username=normalized_user,
                secret=normalized_secret,
                scope=SCOPE_LOCAL,
                host=host,
                service=str(declared_service or "").strip() or None,
                source_action=source_action,
            )

    if _is_stored_domain_secret(
        domains_data, domain=domain, username=normalized_user, secret=normalized_secret
    ):
        return CarriedCredential(
            username=normalized_user,
            secret=normalized_secret,
            scope=SCOPE_DOMAIN,
            source_action=source_action,
        )

    record = find_local_credential_record(
        domains_data,
        domain=domain,
        username=normalized_user,
        secret=normalized_secret,
    )
    if record is not None and record.host:
        return CarriedCredential(
            username=normalized_user,
            secret=normalized_secret,
            scope=SCOPE_LOCAL,
            host=record.host,
            service=record.service or None,
            source_action=source_action,
        )

    return CarriedCredential(
        username=normalized_user,
        secret=normalized_secret,
        scope=SCOPE_DOMAIN,
        source_action=source_action,
    )


def _is_stored_domain_secret(
    domains_data: Any, *, domain: str, username: str, secret: str
) -> bool:
    """Whether *secret* is exactly what the DOMAIN store holds for *username*."""
    if not isinstance(domains_data, dict):
        return False
    domain_data = domains_data.get(domain)
    if not isinstance(domain_data, dict):
        return False
    credentials = domain_data.get("credentials")
    if not isinstance(credentials, dict):
        return False
    target = _normalize_account(username)
    for stored_user, stored_secret in credentials.items():
        if _normalize_account(str(stored_user)) != target:
            continue
        return isinstance(stored_secret, str) and stored_secret == secret
    return False


def scope_carried_credential_to_step(
    carried: Optional[CarriedCredential],
    *,
    relation: str,
    from_label: str | None,
    to_label: str | None,
) -> tuple[Optional[CarriedCredential], str]:
    """Return the carried credential a step may use, plus the reason.

    ``(credential, reason)`` where ``credential`` is ``None`` when the carry is
    WITHHELD.  Withholding is the whole point: the caller must then resolve its
    own principal from the stores instead of inheriting a username whose
    authority does not reach this step — which is how a local ``Administrator``
    used to become the domain ``Administrator`` without anything saying so.
    """
    if carried is None:
        return None, ""
    if not carried.is_local:
        return carried, APPLIED_DOMAIN
    host = step_authentication_host(
        relation, from_label=from_label, to_label=to_label
    )
    if host is None:
        return None, WITHHELD_NOT_HOST_AUTHENTICATING
    if not carried.applies_to_host(host):
        return None, WITHHELD_HOST_MISMATCH
    return carried, APPLIED_LOCAL


def islocal_flag_for(
    carried: Optional[CarriedCredential], *, username: str, secret: str
) -> str:
    """Return ``"true"`` when *username*/*secret* is a LOCAL account credential.

    The dump entry points take this as their ``islocal`` argument, and it is
    what decides whether the logon names the host or the domain as its
    authority.  Anything that is not exactly the carried local credential
    resolves to ``"false"`` — the flag is never guessed from the account name.
    """
    if carried is None or not carried.is_local:
        return "false"
    return "true" if carried.matches(username=username, secret=secret) else "false"


__all__ = [
    "APPLIED_DOMAIN",
    "APPLIED_LOCAL",
    "CarriedCredential",
    "SCOPE_DOMAIN",
    "SCOPE_LOCAL",
    "WITHHELD_HOST_MISMATCH",
    "WITHHELD_NOT_HOST_AUTHENTICATING",
    "derive_carried_credential",
    "islocal_flag_for",
    "local_service_for_relation",
    "scope_carried_credential_to_step",
    "step_authentication_host",
]
