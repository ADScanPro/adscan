"""Attribute LSA ``_SC_*`` secrets to the account they actually belong to.

The Local Security Authority caches, under keys beginning with ``_SC_``, the
credentials the Service Control Manager needs to start services. The registry
key name is a **service identifier, never an account name** — so a secret found
under ``_SC_MSSQL$SQLEXPRESS`` belongs to whatever principal that service logs
on as, and a secret found under ``_SC_GMSA_{GUID}_<hash>`` belongs to a group
managed service account the host runs a service as.

Three distinct shapes live under that prefix, and they are not interchangeable:

``_SC_<ServiceName>``
    The service account's **cleartext password**, stored UTF-16LE. The owning
    principal is the service's ``ObjectName`` registry value
    (``HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name>\\ObjectName``), which
    is read live over the remote registry in the same session as the dump.

``_SC_GMSA_{GUID}_<hash>``
    A full ``MSDS_MANAGEDPASSWORD_BLOB`` — the same structure the directory
    returns for ``msDS-ManagedPassword``. It yields an NT hash and Kerberos AES
    keys, but only once the gMSA's own sAMAccountName is known, because the
    account name is part of the Kerberos salt. Parsing and derivation are
    shared with the LDAP read path via
    :mod:`adscan_internal.services.gmsa_managed_password`.

``_SC_GMSA_DPAPI_{GUID}_<hash>``
    Opaque DPAPI key material held for the same gMSA (the two keys carry the
    same trailing hash). It is not a password and cannot authenticate, so it is
    recorded as evidence and never stored as a credential.

The same module also answers the two questions the operator display and the
credential store ask of a completed dump: **which account does each recovered
item belong to**, and **is the item a login credential at all**. A DPAPI master
key and a cached managed-password blob are both worth keeping, but neither can
authenticate, so :func:`build_lsa_harvest` sorts everything the dump returned
into three groups (credential, key material, unattributed) that a caller can
render and count without re-deriving the distinction.

Everything here is pure logic over already-recovered data: no network, no
workspace access. The callers supply the service ``ObjectName`` map (read over
the remote registry) and the gMSA candidates (read from the attack graph), and
get back per-secret decisions that say exactly where each secret belongs and,
when it cannot be attributed, why not.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Sequence

from adscan_internal.services.gmsa_managed_password import derive_gmsa_credentials

#: Built-in service logon identities. These are machine-local NT AUTHORITY
#: principals with no recoverable password; a secret attributed to one of them
#: is evidence, never a credential.
_BUILTIN_LOGON_ACCOUNTS = frozenset(
    {
        "localsystem",
        "system",
        "localservice",
        "networkservice",
        "nt authority\\system",
        "nt authority\\localservice",
        "nt authority\\local service",
        "nt authority\\networkservice",
        "nt authority\\network service",
    }
)

_BUILTIN_LOGON_PREFIXES = ("nt authority\\", "nt service\\")

#: ``_SC_GMSA_DPAPI_{GUID}_<hash>`` must be tested BEFORE ``_SC_GMSA_``: the
#: DPAPI variant is a longer prefix of the same family.
_GMSA_DPAPI_PREFIX = "_SC_GMSA_DPAPI_"
_GMSA_PREFIX = "_SC_GMSA_"
_SC_PREFIX = "_SC_"

_GMSA_KEY_RE = re.compile(
    r"^_SC_GMSA_(?:DPAPI_)?\{[0-9A-Fa-f-]+\}_(?P<tag>[0-9A-Fa-f]+)$"
)

#: LSA keys that are placeholders for an account resolved elsewhere. When the
#: key still reads like this, that resolution did not happen — the secret is
#: real but its owner is unknown, and the literal key name is not a username
#: anything could authenticate as.
_UNATTRIBUTED_PLACEHOLDER_KEYS = frozenset({"DEFAULTPASSWORD", "ASPNET_WP_PASSWORD"})

_PLACEHOLDER_REASONS = {
    "DEFAULTPASSWORD": (
        "the AutoLogon account name could not be read from the host, so the "
        "recovered password cannot be tied to a user"
    ),
    "ASPNET_WP_PASSWORD": (
        "the IIS worker-process account could not be read from the host, so the "
        "recovered password cannot be tied to a user"
    ),
}


#: LSA entries ADscan synthesises itself while parsing the SECURITY hive. They
#: are not ``_SC_*`` service secrets and carry their own meaning, so the
#: ``_SC_*`` attribution pass skips them and :func:`build_lsa_harvest` places
#: each one by name.
MACHINE_ACCOUNT_SECRET_NAME = "$MACHINE.ACC"
DPAPI_MACHINE_SECRET_NAME = "DPAPI_SYSTEM(machine)"
DPAPI_USER_SECRET_NAME = "DPAPI_SYSTEM(user)"

INTERNAL_LSA_SECRET_NAMES = frozenset(
    {
        MACHINE_ACCOUNT_SECRET_NAME,
        DPAPI_MACHINE_SECRET_NAME,
        DPAPI_USER_SECRET_NAME,
    }
)

#: What the two DPAPI_SYSTEM halves actually unlock. Neither is a login.
_DPAPI_SYSTEM_DESCRIPTIONS = {
    DPAPI_MACHINE_SECRET_NAME: "DPAPI machine master key",
    DPAPI_USER_SECRET_NAME: "DPAPI user master key",
}

#: A NetBIOS computer name is at most 15 characters and carries no separators.
_COMPUTER_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62})$")


class LsaSecretKind(str, Enum):
    """What a ``_SC_*`` LSA secret actually holds."""

    SERVICE_PASSWORD = "service_password"
    GMSA_MANAGED_PASSWORD = "gmsa_managed_password"
    GMSA_DPAPI = "gmsa_dpapi"
    OTHER = "other"


class LsaSecretScope(str, Enum):
    """Which credential store an attributed secret belongs in."""

    DOMAIN = "domain"
    LOCAL = "local"


class LsaHarvestGroup(str, Enum):
    """What a recovered item IS, independently of who owns it.

    The three groups answer different operator questions and must never be
    counted together: a credential can be used to authenticate right now, key
    material unlocks other secrets in a later step, and an unattributed secret
    is real material whose owner could not be established.
    """

    CREDENTIAL = "credential"
    KEY_MATERIAL = "key_material"
    UNATTRIBUTED = "unattributed"


@dataclass(frozen=True)
class LsaHarvestRow:
    """One recovered item, ready to be displayed or counted."""

    group: LsaHarvestGroup
    #: ``DOMAIN\\principal`` for a credential, the LSA key name otherwise.
    account: str
    #: The secret itself: a password, an NT hash, or hex-encoded key material.
    value: str
    #: One line saying what the value is, or why it has no owner.
    detail: str


@dataclass(frozen=True)
class AttributedLsaSecret:
    """One LSA secret resolved to the principal it belongs to (or to nothing).

    ``principal`` is set only when the owning account was established with
    certainty. When it is ``None``, ``evidence_reason`` says why, and the caller
    records the material as evidence instead of inventing an account.
    """

    key_name: str
    kind: LsaSecretKind
    #: Service whose SCM entry produced the secret (``_SC_<ServiceName>`` only).
    service_name: str | None = None
    #: Raw ``ObjectName`` value as configured on the service, when read.
    service_logon_account: str | None = None
    principal: str | None = None
    scope: LsaSecretScope | None = None
    #: Password for a service account; NT hash for a gMSA.
    secret: str | None = None
    #: ``"password"`` or ``"nt_hash"``.
    secret_kind: str | None = None
    aes128: str | None = None
    aes256: str | None = None
    evidence_reason: str | None = None
    #: Short client-safe description of the material, for the operator display.
    label: str = ""

    @property
    def is_credential(self) -> bool:
        """True when this secret can be stored as a usable credential."""
        return bool(self.principal and self.secret)


def classify_lsa_secret_key(key_name: str) -> tuple[LsaSecretKind, str | None]:
    """Classify a ``_SC_*`` key and return ``(kind, service_name)``.

    ``service_name`` is the SCM service the key refers to, and is set only for
    the plain ``_SC_<ServiceName>`` form — the gMSA forms encode a GUID and a
    hash, not a service.
    """
    name = str(key_name or "").strip()
    upper = name.upper()

    if upper.startswith(_GMSA_DPAPI_PREFIX):
        return LsaSecretKind.GMSA_DPAPI, None
    if upper.startswith(_GMSA_PREFIX):
        return LsaSecretKind.GMSA_MANAGED_PASSWORD, None
    if upper.startswith(_SC_PREFIX):
        service = name[len(_SC_PREFIX):]
        return LsaSecretKind.SERVICE_PASSWORD, (service or None)
    return LsaSecretKind.OTHER, None


def gmsa_account_tag(key_name: str) -> str | None:
    """Return the trailing account tag shared by a gMSA key pair.

    ``_SC_GMSA_{A}_<tag>`` and ``_SC_GMSA_DPAPI_{B}_<tag>`` carry the same
    trailing hash when they describe the same managed account, which is what
    ties the DPAPI material to the password material on one host.
    """
    match = _GMSA_KEY_RE.match(str(key_name or "").strip())
    return match.group("tag").upper() if match else None


def is_builtin_logon_account(object_name: str | None) -> bool:
    """True when a service ``ObjectName`` is a built-in NT AUTHORITY identity."""
    value = str(object_name or "").strip().rstrip("\x00").strip().lower()
    if not value:
        return False
    if value in _BUILTIN_LOGON_ACCOUNTS:
        return True
    return value.startswith(_BUILTIN_LOGON_PREFIXES)


def resolve_service_logon_principal(
    object_name: str | None,
    *,
    host: str,
    domain: str,
) -> tuple[str | None, LsaSecretScope | None, str | None]:
    """Resolve a service ``ObjectName`` to ``(principal, scope, reason)``.

    ``ObjectName`` comes in several shapes and the shape decides the store:

    * ``DOMAIN\\user`` / ``user@domain.tld`` — a domain principal;
    * ``.\\user`` or ``HOSTNAME\\user`` — an account local to this host;
    * ``LocalSystem`` / ``NT AUTHORITY\\*`` / ``NT SERVICE\\*`` — built-in, no
      recoverable principal.

    When the principal cannot be established, ``reason`` explains why so the
    caller can record honest evidence rather than guess an account.
    """
    raw = str(object_name or "").strip().rstrip("\x00").strip()
    if not raw:
        return None, None, "the service logon account could not be read from the host"

    if is_builtin_logon_account(raw):
        return None, None, f"the service runs as the built-in identity {raw}"

    if "@" in raw and "\\" not in raw:
        account, _, account_domain = raw.partition("@")
        account = account.strip()
        if not account:
            return None, None, f"unrecognised service logon account {raw!r}"
        return account, LsaSecretScope.DOMAIN, None

    if "\\" in raw:
        prefix, _, account = raw.partition("\\")
        prefix = prefix.strip()
        account = account.strip()
        if not account:
            return None, None, f"unrecognised service logon account {raw!r}"
        host_short = str(host or "").split(".")[0].strip().lower()
        if prefix in {".", ""} or (host_short and prefix.lower() == host_short):
            return account, LsaSecretScope.LOCAL, None
        return account, LsaSecretScope.DOMAIN, None

    # A bare name with no qualifier. Windows writes this for local accounts.
    _ = domain
    return raw, LsaSecretScope.LOCAL, None


def gmsa_candidates_for_host(
    graph: dict[str, Any] | None,
    machine_account: str | None,
) -> list[str]:
    """Return the gMSAs this host is authorised to retrieve, from the graph.

    A member server only ever caches a managed password it is allowed to read,
    and the collector already records that authorisation as a
    ``ReadGMSAPassword`` edge from the host's machine account. Reading it back
    attributes the cached blob with no extra traffic against the domain.
    """
    account = str(machine_account or "").strip().rstrip("$").lower()
    if not account or not isinstance(graph, dict):
        return []

    wanted = {account, f"{account}$"}
    found: list[str] = []
    seen: set[str] = set()
    for edge in graph.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        if str(edge.get("relation") or "").strip().lower() != "readgmsapassword":
            continue
        source = _node_label(edge.get("from"))
        if source.lower() not in wanted:
            continue
        target = _node_label(edge.get("to"))
        if not target:
            continue
        key = target.lower()
        if key in seen:
            continue
        seen.add(key)
        found.append(target)
    return found


def _node_label(node_id: Any) -> str:
    """Strip the graph node-id prefix (``name:foo$`` -> ``foo$``)."""
    value = str(node_id or "").strip()
    if ":" in value:
        value = value.split(":", 1)[1]
    return value.strip()


def attribute_lsa_secret(
    key_name: str,
    *,
    plaintext: str | None,
    raw: bytes | None,
    host: str,
    domain: str,
    service_logon_accounts: dict[str, str] | None = None,
    gmsa_candidates: list[str] | None = None,
) -> AttributedLsaSecret:
    """Resolve one ``_SC_*`` LSA secret to the account it belongs to."""
    kind, service_name = classify_lsa_secret_key(key_name)

    if kind is LsaSecretKind.GMSA_MANAGED_PASSWORD:
        return _attribute_gmsa_password(
            key_name,
            raw=raw,
            domain=domain,
            gmsa_candidates=gmsa_candidates or [],
        )

    if kind is LsaSecretKind.GMSA_DPAPI:
        candidates = gmsa_candidates or []
        owner = candidates[0] if len(candidates) == 1 else None
        owner_note = f" held for {owner}" if owner else ""
        return AttributedLsaSecret(
            key_name=key_name,
            kind=kind,
            evidence_reason=(
                f"DPAPI key material{owner_note}, not a login credential"
            ),
            label=(
                f"gMSA DPAPI key material for {owner}"
                if owner
                else "gMSA DPAPI key material"
            ),
        )

    if kind is LsaSecretKind.SERVICE_PASSWORD:
        return _attribute_service_password(
            key_name,
            service_name=service_name,
            plaintext=plaintext,
            host=host,
            domain=domain,
            service_logon_accounts=service_logon_accounts or {},
        )

    if key_name.strip().upper() in _UNATTRIBUTED_PLACEHOLDER_KEYS:
        return AttributedLsaSecret(
            key_name=key_name,
            kind=kind,
            evidence_reason=_PLACEHOLDER_REASONS.get(
                key_name.strip().upper(),
                "the account this secret belongs to could not be identified",
            ),
            label="cached logon password",
        )

    return AttributedLsaSecret(
        key_name=key_name,
        kind=kind,
        principal=key_name,
        scope=LsaSecretScope.DOMAIN,
        secret=plaintext or None,
        secret_kind="password" if plaintext else None,
        label="LSA secret",
    )


def _attribute_service_password(
    key_name: str,
    *,
    service_name: str | None,
    plaintext: str | None,
    host: str,
    domain: str,
    service_logon_accounts: dict[str, str],
) -> AttributedLsaSecret:
    """Attribute an ``_SC_<ServiceName>`` cleartext password to its logon account."""
    object_name = _lookup_service_logon_account(service_name, service_logon_accounts)
    principal, scope, reason = resolve_service_logon_principal(
        object_name, host=host, domain=domain
    )

    if not plaintext:
        reason = reason or "no cleartext password was recovered"
        principal, scope = None, None

    label = (
        f"service account password ({service_name})"
        if service_name
        else "service account password"
    )
    return AttributedLsaSecret(
        key_name=key_name,
        kind=LsaSecretKind.SERVICE_PASSWORD,
        service_name=service_name,
        service_logon_account=object_name,
        principal=principal,
        scope=scope,
        secret=plaintext if principal else None,
        secret_kind="password" if principal and plaintext else None,
        evidence_reason=None if principal else reason,
        label=label,
    )


def _lookup_service_logon_account(
    service_name: str | None,
    service_logon_accounts: dict[str, str],
) -> str | None:
    """Look a service's ``ObjectName`` up case-insensitively."""
    if not service_name:
        return None
    direct = service_logon_accounts.get(service_name)
    if direct:
        return direct
    wanted = service_name.lower()
    for name, value in service_logon_accounts.items():
        if str(name).lower() == wanted:
            return value
    return None


def _attribute_gmsa_password(
    key_name: str,
    *,
    raw: bytes | None,
    domain: str,
    gmsa_candidates: list[str],
) -> AttributedLsaSecret:
    """Derive gMSA credentials from a cached managed-password blob."""
    label = "gMSA managed password"
    if not raw:
        return AttributedLsaSecret(
            key_name=key_name,
            kind=LsaSecretKind.GMSA_MANAGED_PASSWORD,
            evidence_reason="the cached managed-password blob was empty",
            label=label,
        )

    if len(gmsa_candidates) != 1:
        reason = (
            "the managed service account it belongs to could not be identified"
            if not gmsa_candidates
            else (
                "this host can retrieve several managed service accounts "
                f"({', '.join(sorted(gmsa_candidates))}), so the owner is ambiguous"
            )
        )
        return AttributedLsaSecret(
            key_name=key_name,
            kind=LsaSecretKind.GMSA_MANAGED_PASSWORD,
            evidence_reason=reason,
            label=label,
        )

    account = gmsa_candidates[0].rstrip("$") + "$"
    try:
        creds = derive_gmsa_credentials(
            raw, sam_account=account, domain_fqdn=domain
        )
    except Exception as exc:  # noqa: BLE001 - reported as evidence, never raised
        return AttributedLsaSecret(
            key_name=key_name,
            kind=LsaSecretKind.GMSA_MANAGED_PASSWORD,
            principal=account,
            evidence_reason=f"the cached managed-password blob could not be parsed: {exc}",
            label=label,
        )

    return AttributedLsaSecret(
        key_name=key_name,
        kind=LsaSecretKind.GMSA_MANAGED_PASSWORD,
        principal=creds.account,
        scope=LsaSecretScope.DOMAIN,
        secret=creds.nt_hash,
        secret_kind="nt_hash",
        aes128=creds.aes128,
        aes256=creds.aes256,
        label=label,
    )


def _looks_like_ip(value: str) -> bool:
    """True when a target string is an IPv4/IPv6 address rather than a name."""
    try:
        ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return False
    return True


def _short_label(value: str) -> str:
    """Return the first DNS label of a hostname, uppercased and cleaned."""
    label = str(value or "").strip().rstrip(".").rstrip("$").split(".")[0].strip()
    if not label or not _COMPUTER_NAME_RE.match(label):
        return ""
    return label.upper()


def resolve_machine_account_principal(
    *,
    computer_name: str | None,
    host: str,
    hostname_candidates: Sequence[str] | None = None,
) -> tuple[str | None, str]:
    """Resolve the machine account of the host a dump was taken from.

    ``$MACHINE.ACC`` is the computer account password of the **dumped host**, so
    the name it is filed under has to come from that host, never from whichever
    machine happens to be the domain controller. Sources, most authoritative
    first:

    1. ``computer_name`` — read off the target's own registry during the dump.
       True regardless of how the target was addressed.
    2. The target string itself, when it is a name rather than an address.
    3. A hostname candidate the workspace already resolved for that address.

    Returns:
        ``(machine_account, "")`` when the host could be named, otherwise
        ``(None, reason)``. A caller that gets ``None`` records the recovered
        hash as unattributed evidence: a misfiled machine account is a false
        claim in a client report, an unattributed one is still recoverable.
    """
    label = _short_label(computer_name or "")
    if label:
        return f"{label}$", ""

    if not _looks_like_ip(host):
        label = _short_label(host)
        if label:
            return f"{label}$", ""

    for candidate in hostname_candidates or ():
        label = _short_label(candidate)
        if label:
            return f"{label}$", ""

    return None, (
        "the dumped host did not return its own computer name and "
        f"{host or 'the target'} is an address, so the account this password "
        "belongs to cannot be named"
    )


def build_lsa_harvest(
    secrets: Iterable[Any],
    attributions: dict[str, AttributedLsaSecret],
    *,
    domain: str,
    host: str,
    machine_account: str | None,
    machine_account_nt_hash: str | None,
) -> tuple[LsaHarvestRow, ...]:
    """Sort everything an LSA dump returned into the three harvest groups.

    One row per recovered item, in the order the operator should read them.
    ``$MACHINE.ACC`` appears exactly once — as the machine account's usable NT
    hash, never also as its own raw blob, which is the same secret in a form
    nothing can authenticate with.
    """
    rows: list[LsaHarvestRow] = []
    domain_prefix = str(domain or "").strip()
    host_prefix = _short_label(host).lower() or "local"

    if machine_account_nt_hash:
        if machine_account:
            account = (
                f"{domain_prefix}\\{machine_account}"
                if domain_prefix
                else machine_account
            )
            rows.append(
                LsaHarvestRow(
                    group=LsaHarvestGroup.CREDENTIAL,
                    account=account,
                    value=machine_account_nt_hash,
                    detail="machine account · NT hash",
                )
            )
        else:
            rows.append(
                LsaHarvestRow(
                    group=LsaHarvestGroup.UNATTRIBUTED,
                    account=MACHINE_ACCOUNT_SECRET_NAME,
                    value=machine_account_nt_hash,
                    # Short on screen by design: the full explanation goes to
                    # the evidence file and the debug log, where there is room
                    # for it. A table row is a scan surface.
                    detail="machine account NT hash · host could not be named",
                )
            )

    for secret in secrets or ():
        name = str(getattr(secret, "name", "") or "")
        if not name or name == MACHINE_ACCOUNT_SECRET_NAME:
            # Already rendered above in the form that can authenticate.
            continue

        if name in _DPAPI_SYSTEM_DESCRIPTIONS:
            rows.append(
                LsaHarvestRow(
                    group=LsaHarvestGroup.KEY_MATERIAL,
                    account=name,
                    value=_raw_hex(secret),
                    detail=_DPAPI_SYSTEM_DESCRIPTIONS[name],
                )
            )
            continue

        attributed = attributions.get(name)
        if attributed is None:
            rows.append(
                LsaHarvestRow(
                    group=LsaHarvestGroup.UNATTRIBUTED,
                    account=name,
                    value=_secret_display_value(secret),
                    detail="LSA secret · owner not established",
                )
            )
            continue

        if attributed.is_credential:
            prefix = (
                host_prefix if attributed.scope is LsaSecretScope.LOCAL else domain_prefix
            )
            account = (
                f"{prefix}\\{attributed.principal}" if prefix else attributed.principal
            )
            detail = attributed.label or "LSA secret"
            if attributed.secret_kind == "nt_hash":
                detail = f"{detail} · NT hash"
            rows.append(
                LsaHarvestRow(
                    group=LsaHarvestGroup.CREDENTIAL,
                    account=str(account),
                    value=attributed.secret or "",
                    detail=detail,
                )
            )
            continue

        reason = attributed.evidence_reason or "owner not established"
        group = (
            LsaHarvestGroup.KEY_MATERIAL
            if attributed.kind is LsaSecretKind.GMSA_DPAPI
            else LsaHarvestGroup.UNATTRIBUTED
        )
        rows.append(
            LsaHarvestRow(
                group=group,
                account=name,
                value=_secret_display_value(secret),
                detail=(
                    # The group already says "not a login", so key material
                    # only needs to say what it is and whose it is.
                    (attributed.label or reason)
                    if group is LsaHarvestGroup.KEY_MATERIAL
                    else f"{attributed.label or 'LSA secret'} · {reason}"
                ),
            )
        )

    return tuple(rows)


def count_harvest_group(
    rows: Iterable[LsaHarvestRow], group: LsaHarvestGroup
) -> int:
    """Count the rows in one harvest group."""
    return sum(1 for row in rows if row.group is group)


def _raw_hex(secret: Any) -> str:
    """Hex-encode a secret's raw bytes, or return an empty string."""
    raw = getattr(secret, "raw", None)
    if isinstance(raw, (bytes, bytearray)) and raw:
        return bytes(raw).hex()
    return ""


def _secret_display_value(secret: Any) -> str:
    """Return the most useful printable form of a recovered secret."""
    plaintext = getattr(secret, "plaintext", None)
    if plaintext:
        return str(plaintext)
    return _raw_hex(secret)


def service_names_from_lsa_keys(key_names: list[str] | tuple[str, ...]) -> list[str]:
    """Return the SCM service names referenced by a set of ``_SC_*`` keys.

    Used to drive the targeted remote-registry ``ObjectName`` lookups: only the
    services that actually produced a cached secret are queried, so the cost is
    a handful of round trips, not one per service on the host.
    """
    names: list[str] = []
    seen: set[str] = set()
    for key_name in key_names or ():
        _kind, service = classify_lsa_secret_key(key_name)
        if not service:
            continue
        marker = service.lower()
        if marker in seen:
            continue
        seen.add(marker)
        names.append(service)
    return names


__all__ = [
    "AttributedLsaSecret",
    "DPAPI_MACHINE_SECRET_NAME",
    "DPAPI_USER_SECRET_NAME",
    "INTERNAL_LSA_SECRET_NAMES",
    "LsaHarvestGroup",
    "LsaHarvestRow",
    "LsaSecretKind",
    "LsaSecretScope",
    "MACHINE_ACCOUNT_SECRET_NAME",
    "attribute_lsa_secret",
    "build_lsa_harvest",
    "classify_lsa_secret_key",
    "count_harvest_group",
    "gmsa_account_tag",
    "gmsa_candidates_for_host",
    "is_builtin_logon_account",
    "resolve_machine_account_principal",
    "resolve_service_logon_principal",
    "service_names_from_lsa_keys",
]
