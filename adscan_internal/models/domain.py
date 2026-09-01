"""Domain model representing Active Directory domain state.

This module defines the Domain dataclass that maps to the domains_data dictionary
structure used throughout ADScan. It provides a strongly-typed interface for
domain information, authentication state, and discovered credentials.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple
from datetime import datetime
from enum import Enum

from adscan_core.time_utils import utc_now


class CaseInsensitiveDict(dict):
    """A dictionary with case-insensitive string keys.

    This is the SSOT wrapper for ``shell.domains_data``, which is keyed by
    domain FQDN. Attack-path edge labels are UPPERCASE (``DARKZERO.HTB``) while
    collected keys are lowercase (``darkzero.htb``), so every access site must
    resolve regardless of key case. Keys are normalized with ``str.casefold()``
    (correct for non-ASCII, and consistent with ``_resolve_domain_key`` in
    ``adscan.py``). Non-string keys pass through unchanged.

    Lives here (an import-light module: ``re`` + stdlib + ``adscan_core``) so
    both the CLI (``adscan.py``) and the workspace-load seam
    (``adscan_internal.workspaces.state``) can import it without the
    circular-import risk of pulling from the 30k-line ``adscan`` module.
    """

    @staticmethod
    def _norm(key):
        return key.casefold() if isinstance(key, str) else key

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._convert_keys()

    def _convert_keys(self):
        """Casefold every key already present after construction."""
        for k in list(self.keys()):
            v = super().pop(k)
            self.__setitem__(k, v)

    def __getitem__(self, key):
        return super().__getitem__(self._norm(key))

    def __setitem__(self, key, value):
        super().__setitem__(self._norm(key), value)

    def __delitem__(self, key):
        super().__delitem__(self._norm(key))

    def __contains__(self, key):
        return super().__contains__(self._norm(key))

    def get(self, key, default=None):
        return super().get(self._norm(key), default)

    def pop(self, key, *args, **kwargs):
        return super().pop(self._norm(key), *args, **kwargs)

    def setdefault(self, key, default=None):
        # ``dict.setdefault`` bypasses ``__setitem__`` and would store the raw
        # (possibly UPPERCASE) key, re-creating the case-mismatch bug the class
        # exists to prevent. 53 ``domains_data.setdefault(domain, {})`` call
        # sites depend on this casefolding the stored key.
        return super().setdefault(self._norm(key), default)

    def update(self, other=None, **kwargs):
        if other is not None:
            if isinstance(other, CaseInsensitiveDict):
                super().update(other)
            elif hasattr(other, "items"):
                super().update({self._norm(k): v for k, v in other.items()})
            else:
                super().update({self._norm(k): v for k, v in other})
        if kwargs:
            super().update({self._norm(k): v for k, v in kwargs.items()})

    def copy(self):
        # ``dict.copy`` returns a plain ``dict`` and would revert
        # case-insensitivity; keep the wrapper.
        return CaseInsensitiveDict(self)


def resolve_ci(mapping: Any, key: str) -> Any:
    """Return ``mapping[key]`` matched case-insensitively, else ``None``.

    The SSOT for reading a **nested** ``domains_data`` sub-map that is keyed by
    an AD principal or domain name — ``kerberos_keys[username]``,
    ``domains_data[domain]`` when the top-level wrapper is not live, and any
    future principal-keyed store. AD ``sAMAccountName`` (including machine
    accounts like ``DC02$``) and domain names are case-insensitive, but plain
    ``dict`` keys are not, and different producers write different casing
    (DCSync persists ``DC02$`` from SAMR; a consumer derived from
    ``pdc_hostname_fqdn`` queries ``dc02$``). A raw ``mapping.get(key)`` then
    misses a record that IS on disk.

    Complements :class:`CaseInsensitiveDict`, which is the structural fix for
    the **top-level** ``domains_data`` map (where casefolding the STORED key is
    fine because domain FQDNs are already lowercase and not display-sensitive).
    Nested principal-keyed maps keep their ORIGINAL casing on disk (``DC02$``
    reads better than ``dc02$`` in the NTDS panel) and are not re-wrapped on
    workspace load, so they resolve case at READ time via this helper instead
    of mutating the stored key. Use this — never a raw ``.get()`` — for any
    nested map keyed by an AD principal or domain name.

    A direct hit is preferred (fast path, and exact case wins on the rare
    collision); only a miss triggers the casefold scan, so an
    already-normalized key stays zero-cost.
    """
    if not hasattr(mapping, "get"):
        return None
    direct = mapping.get(key)
    if direct is not None:
        return direct
    target = str(key or "").strip().casefold()
    if not target:
        return None
    try:
        items = mapping.items()
    except AttributeError:
        return None
    for candidate, value in items:
        if str(candidate or "").strip().casefold() == target:
            return value
    return None


class AuthStatus(str, Enum):
    """Authentication status for a domain."""

    NONE = "none"  # No authentication attempted
    UNAUTH = "unauth"  # Unauthenticated enumeration only
    WITH_USERS = "with_users"  # Has valid user list
    AUTH = "auth"  # Authenticated with valid credentials
    PWNED = "pwned"  # Domain Administrator access achieved


@dataclass
class Domain:
    """Represents an Active Directory domain and its discovered state.

    This class maps to the domains_data dictionary structure in adscan.py
    and provides type-safe access to domain information.

    Attributes:
        name: Domain name (e.g., "example.local")
        pdc: Primary Domain Controller FQDN
        pdc_hostname: PDC hostname (short name)
        dc_ip: Domain Controller IP address
        base_dn: LDAP Base DN (e.g., "DC=example,DC=local")
        auth_status: Current authentication status
        username: Current authenticated username
        password: Current authenticated password
        hash: Current authenticated hash (NTLM)
        credentials: Dictionary of discovered credentials {username: password/hash}
        local_credentials: Nested dict of local credentials {host: {service: {user: password}}}
        kerberos_tickets: Dictionary of Kerberos tickets {username: ticket_path}
        kerberos_keys: Typed Kerberos keys {username: {aes256/aes128/nt_hash/...}}
        rodc_followup_state: Persisted RODC follow-up milestones keyed by target host
        trusts: List of discovered domain trusts
        users: List of discovered user accounts
        computers: List of discovered computer accounts
        dcs: List of discovered Domain Controllers
        shares: List of discovered SMB shares
        current_phase: Current scan phase (for web progress tracking)
        phase_progress: Progress within current phase (0.0 - 1.0)
        scan_metadata: Additional scan metadata
        created_at: When this domain was first discovered
        updated_at: When this domain was last updated
    """

    # Core identification
    name: str

    # Domain Controllers
    pdc: Optional[str] = None
    pdc_hostname: Optional[str] = None
    dc_ip: Optional[str] = None
    dcs: List[str] = field(default_factory=list)

    # DNS resolver for the domain zone. In segmented AD networks the AD-zone DNS
    # server is a DIFFERENT host from the DC one authenticates against. When set,
    # this feeds ONLY the resolver (Unbound conditional forwarder / SRV
    # discovery / A-record lookups); dc_ip stays the auth/enum target. When None,
    # callers fall back to the DC (resolve_dc_ip) — byte-identical to legacy.
    dns_server: Optional[str] = None

    # LDAP
    base_dn: Optional[str] = None

    # Authentication state
    auth_status: AuthStatus = AuthStatus.NONE
    username: Optional[str] = None
    password: Optional[str] = None
    hash: Optional[str] = None  # NTLM hash

    # Discovered credentials
    credentials: Dict[str, str] = field(
        default_factory=dict
    )  # {username: password/hash}
    local_credentials: Dict[str, Dict[str, Dict[str, str]]] = field(
        default_factory=dict
    )  # {host: {service: {user: password}}}
    kerberos_tickets: Dict[str, str] = field(
        default_factory=dict
    )  # {username: ticket_path} — TGTs only (validated via kerberos_ccache_inspector)
    service_tickets: List[Dict[str, Any]] = field(
        default_factory=list
    )  # Derived STs from RBCD / S4U / constrained delegation / silver tickets.
    # Each entry is a ServiceTicket.to_dict() payload; see
    # adscan_internal.models.service_ticket for the schema.
    kerberos_keys: Dict[str, Dict[str, str]] = field(default_factory=dict)
    rodc_followup_state: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    auth_posture: Dict[str, Any] = field(default_factory=dict)

    # Discovered entities
    trusts: List[Dict[str, Any]] = field(default_factory=list)
    users: List[str] = field(default_factory=list)
    computers: List[str] = field(default_factory=list)
    shares: List[Dict[str, Any]] = field(default_factory=list)

    # Progress tracking (for web UI)
    current_phase: str = "initial"
    phase_progress: float = 0.0

    # Metadata
    scan_metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert domain to dictionary (compatible with domains_data structure).

        Returns:
            Dictionary representation compatible with existing domains_data format
        """
        return {
            "pdc": self.pdc,
            "pdc_hostname": self.pdc_hostname,
            "dc_ip": self.dc_ip,
            "dcs": self.dcs,
            "dns_server": self.dns_server,
            "base_dn": self.base_dn,
            "auth": self.auth_status.value,
            "username": self.username,
            "password": self.password,
            "hash": self.hash,
            "credentials": self.credentials,
            "local_credentials": self.local_credentials,
            "kerberos_tickets": self.kerberos_tickets,
            "service_tickets": self.service_tickets,
            "kerberos_keys": self.kerberos_keys,
            "rodc_followup_state": self.rodc_followup_state,
            "auth_posture": self.auth_posture,
            "trusts": self.trusts,
            "users": self.users,
            "computers": self.computers,
            "shares": self.shares,
            "current_phase": self.current_phase,
            "phase_progress": self.phase_progress,
            "scan_metadata": self.scan_metadata,
        }

    @classmethod
    def from_dict(cls, name: str, data: Dict[str, Any]) -> "Domain":
        """Create Domain from dictionary (from domains_data structure).

        Args:
            name: Domain name
            data: Dictionary from domains_data

        Returns:
            Domain instance
        """
        # Parse auth status
        auth_str = data.get("auth", "none")
        try:
            auth_status = AuthStatus(auth_str)
        except ValueError:
            auth_status = AuthStatus.NONE

        return cls(
            name=name,
            pdc=data.get("pdc"),
            pdc_hostname=data.get("pdc_hostname"),
            dc_ip=data.get("dc_ip"),
            dcs=data.get("dcs", []),
            dns_server=data.get("dns_server"),
            base_dn=data.get("base_dn"),
            auth_status=auth_status,
            username=data.get("username"),
            password=data.get("password"),
            hash=data.get("hash"),
            credentials=data.get("credentials", {}),
            local_credentials=data.get("local_credentials", {}),
            kerberos_tickets=data.get("kerberos_tickets", {}),
            service_tickets=list(data.get("service_tickets", []) or []),
            kerberos_keys=data.get("kerberos_keys", {}),
            rodc_followup_state=data.get("rodc_followup_state", {}),
            auth_posture=data.get("auth_posture", {}),
            trusts=data.get("trusts", []),
            users=data.get("users", []),
            computers=data.get("computers", []),
            shares=data.get("shares", []),
            current_phase=data.get("current_phase", "initial"),
            phase_progress=data.get("phase_progress", 0.0),
            scan_metadata=data.get("scan_metadata", {}),
        )

    def is_authenticated(self) -> bool:
        """Check if domain has valid authentication.

        Returns:
            True if authenticated or pwned
        """
        return self.auth_status in [AuthStatus.AUTH, AuthStatus.PWNED]

    def is_pwned(self) -> bool:
        """Check if domain is fully compromised (DA access).

        Returns:
            True if pwned status
        """
        return self.auth_status == AuthStatus.PWNED

    def add_credential(self, username: str, credential: str) -> None:
        """Add a discovered credential to the domain.

        Args:
            username: Username
            credential: Password or hash
        """
        self.credentials[username] = credential
        self.updated_at = utc_now()

    def add_local_credential(
        self, host: str, service: str, username: str, credential: str
    ) -> None:
        """Add a local credential for a specific host/service.

        Args:
            host: Hostname or IP
            service: Service name (e.g., "smb", "wmi")
            username: Local username
            credential: Password or hash
        """
        if host not in self.local_credentials:
            self.local_credentials[host] = {}
        if service not in self.local_credentials[host]:
            self.local_credentials[host][service] = {}
        self.local_credentials[host][service][username] = credential
        self.updated_at = utc_now()

    def update_progress(self, phase: str, progress: float) -> None:
        """Update scan progress.

        Args:
            phase: Current phase name
            progress: Progress within phase (0.0 - 1.0)
        """
        self.current_phase = phase
        self.phase_progress = max(0.0, min(1.0, progress))  # Clamp to [0, 1]
        self.updated_at = utc_now()


def resolve_dc_ip(domain_data: dict) -> str | None:
    """Return the best-available DC/KDC IP from a domains_data entry.

    Fallback chain: pdc → dc_ip → dcs[0] → connectivity.summary.pdc_ip → None.
    'pdc' is the authoritative IP set at scan start and is the most reliably
    populated field. 'dc_ip' is the model field. 'dcs[0]' is the last resort
    from the discovered DC list. 'connectivity.summary.pdc_ip' covers a
    domain ADscan has NEVER directly enumerated -- a trust-partner realm
    discovered only through the cross-domain connectivity precheck
    (``domain_connectivity_service.merge_domain_connectivity``, run during
    trust enumeration). That precheck resolves the partner's OWN DC via a real
    DNS SRV/A lookup against the foreign realm (never the auth domain's DC),
    so it is a safe last resort -- without it, a caller resolving a trust
    partner's DC IP (e.g. a cross-domain credential handoff after a
    linked-server pivot) silently falls back to nothing, or worse, to the
    WRONG (auth) domain's DC.

    Use this everywhere a KDC or DC IP must be resolved from domains_data
    instead of hand-rolling .get("dc_ip") / .get("pdc") chains at each call site.
    """
    pdc = str(domain_data.get("pdc") or "").strip()
    if pdc:
        return pdc
    dc_ip = str(domain_data.get("dc_ip") or "").strip()
    if dc_ip:
        return dc_ip
    dcs: list = domain_data.get("dcs") or []
    if dcs:
        first = str(dcs[0]).strip()
        if first:
            return first
    connectivity = domain_data.get("connectivity")
    if isinstance(connectivity, dict):
        summary = connectivity.get("summary")
        if isinstance(summary, dict):
            connectivity_pdc_ip = str(summary.get("pdc_ip") or "").strip()
            if connectivity_pdc_ip:
                return connectivity_pdc_ip
    return None


def resolve_dns_server(domain_data: dict) -> str | None:
    """Return the explicitly-configured DNS server for a domains_data entry.

    In segmented AD networks the DNS server that serves the AD zone is a
    DIFFERENT host from the DC one authenticates against. When the operator
    passes ``--dns-server`` (or the interactive split-DNS prompt supplies one),
    it is persisted under ``domains_data[domain]["dns_server"]`` and feeds ONLY
    the resolver (Unbound conditional forwarder, SRV discovery, A-record
    lookups). ``dc_ip``/``resolve_dc_ip`` stay the auth/enum target.

    This reader deliberately does NOT fall back to the DC. It answers exactly
    "is a separate DNS server configured?" — ``None`` means "no", and the caller
    then falls back to :func:`resolve_dc_ip` explicitly::

        resolver_ip = resolve_dns_server(domain_data) or resolve_dc_ip(domain_data)

    Folding the fallback in here would make that question unanswerable and would
    break the byte-identical-when-absent invariant.
    """
    dns_server = str(domain_data.get("dns_server") or "").strip()
    return dns_server or None


# --------------------------------------------------------------------------- #
# Domain-controller topology SSOT — "how many DCs / is host X the sole DC / is
# there an alternate DC to relay to".
#
# ``domains_data[domain]`` records DCs under a MIX of identifiers — ``dc_ip``,
# ``pdc``, ``pdc_hostname``, ``pdc_hostname_fqdn``, ``pdc_fqdn``, ``dc_fqdn`` and
# a ``dcs`` list. These are ALIASES of possibly ONE DC (e.g. MEEREEN present as
# both ``192.168.180.12`` and ``meereen.essos.local``). Naive comparison with
# ``hosts_match`` cannot reconcile IP<->FQDN, so a single DC seen under its IP
# AND its FQDN gets miscounted as two DCs — the essos single-DC false positive
# that let a doomed self-relay proceed.
#
# The fix that makes dedup robust: the PDC field-group all describe the SAME
# primary DC, so they give the IP<->FQDN link FOR FREE. Build ONE primary DC
# record carrying ALL of those as aliases; then a host that is that DC's IP still
# matches the record via its FQDN alias, and vice-versa. Every consumer resolves
# DC topology through :func:`resolve_domain_controllers` — no code re-derives it
# ad-hoc.
# --------------------------------------------------------------------------- #

# The PDC field-group: all keys under ``domains_data[domain]`` that describe the
# SAME primary DC. Collected into one record so its IP/short/FQDN aliases are
# linked (defeats the IP<->FQDN dedup trap).
_PRIMARY_DC_FIELDS: Tuple[str, ...] = (
    "dc_ip",
    "pdc",
    "pdc_hostname",
    "pdc_hostname_fqdn",
    "pdc_fqdn",
    "dc_fqdn",
)


def _looks_like_ipv4(value: str) -> bool:
    """Return True when *value* is a dotted-quad IPv4 literal."""
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", str(value or "").strip()))


def _best_fqdn(aliases: Iterable[str]) -> Optional[str]:
    """Return the first alias that looks like an FQDN (dotted, not an IP)."""
    for alias in aliases:
        a = str(alias or "").strip()
        if a and "." in a and not _looks_like_ipv4(a):
            return a
    return None


def _dc_identifiers_provably_distinct(a: str, b: str) -> bool:
    """Return True only when ``a`` and ``b`` are provably DIFFERENT machines.

    Conservative by construction — a false "different machine" is the dangerous
    direction (it fabricates an alternate DC that lets a doomed self-relay
    proceed):

    * ``hosts_match`` True (alias-aware IP/short/FQDN/``HOST$``) -> same machine.
    * One side an IP literal and the other a name -> INDETERMINATE. ``hosts_match``
      cannot bridge IP<->FQDN, so a DC's own FQDN vs its IP is NOT "different" —
      this is exactly the essos single-DC false positive. Treated as
      not-provably-distinct.
    * Same identifier family (both IPs, or both names) and ``hosts_match`` False ->
      provably a different machine.
    """
    from adscan_internal.services.credential_store_service import (  # noqa: PLC0415
        hosts_match,
    )

    a = str(a or "").strip()
    b = str(b or "").strip()
    if not a or not b:
        return False
    if hosts_match(a, b):
        return False
    if _looks_like_ipv4(a) != _looks_like_ipv4(b):
        return False
    return True


@dataclass(frozen=True)
class _DCRecord:
    """One distinct domain controller and every identifier that denotes it."""

    aliases: Tuple[str, ...]
    fqdn: Optional[str] = None

    def matches(self, host: str) -> bool:
        """Return whether ``host`` denotes this DC (alias-aware IP/short/FQDN)."""
        from adscan_internal.services.credential_store_service import (  # noqa: PLC0415
            hosts_match,
        )

        return any(hosts_match(host, alias) for alias in self.aliases)


@dataclass(frozen=True)
class DomainControllers:
    """Deduped domain-controller topology for one domain (SSOT value object).

    Built by :func:`resolve_domain_controllers` (from ``domains_data``) or by
    :meth:`from_dc_records` (from an already-canonical record set, e.g. the
    attack-graph DC nodes). Every "how many DCs / is host X the sole DC / is
    there an alternate DC to relay to" question resolves through this one type so
    the answer is identical wherever it is asked.
    """

    dcs: Tuple[_DCRecord, ...] = ()

    @property
    def count(self) -> int:
        """Number of DISTINCT domain controllers (deduped by alias)."""
        return len(self.dcs)

    def _record_for_host(self, host: str) -> Optional[_DCRecord]:
        h = str(host or "").strip()
        if not h:
            return None
        for rec in self.dcs:
            if rec.matches(h):
                return rec
        return None

    def is_sole_dc(self, host: str) -> Optional[bool]:
        """Return True iff there is exactly one DC and ``host`` aliases it.

        ``None`` when there are no DC identifiers, ``host`` is empty, or ``host``
        is not a recognized DC (insufficient to decide).
        """
        if not self.dcs or not str(host or "").strip():
            return None
        if self._record_for_host(host) is None:
            return None
        return self.count == 1

    def has_alternate_dc(self, host: str) -> Optional[bool]:
        """Return whether a DC provably distinct from ``host`` exists.

        * ``True`` — a DC that is a provably-different machine than ``host``
          exists (relay has a non-reflecting target).
        * ``False`` — ``host`` IS a recognized DC and it is the only one (the
          single-DC reflection case).
        * ``None`` — indeterminate: no DC identifiers, empty host, or ``host`` is
          not a recognized DC and no DC is provably distinct from it (IP<->name
          indeterminacy). A false "alternate available" is the dangerous
          direction, so indeterminate never returns True.
        """
        if not self.dcs or not str(host or "").strip():
            return None
        matched = self._record_for_host(host)
        if matched is not None:
            return any(rec is not matched for rec in self.dcs)
        if any(
            _dc_identifiers_provably_distinct(alias, host)
            for rec in self.dcs
            for alias in rec.aliases
        ):
            return True
        return None

    def alternate_dc_fqdn(self, host: str) -> Optional[str]:
        """Return the FQDN of a DC distinct from ``host`` (relay target), or None.

        Picks the first provably-distinct / other DC record; returns ``None``
        when there is no alternate or the alternate has no usable FQDN.
        """
        if not self.dcs or not str(host or "").strip():
            return None
        matched = self._record_for_host(host)
        if matched is not None:
            for rec in self.dcs:
                if rec is not matched:
                    return rec.fqdn
            return None
        for rec in self.dcs:
            if any(
                _dc_identifiers_provably_distinct(alias, host)
                for alias in rec.aliases
            ):
                return rec.fqdn
        return None

    @classmethod
    def from_dc_records(
        cls, records: Iterable[Tuple[Iterable[str], Optional[str]]]
    ) -> "DomainControllers":
        """Build from an already-canonical ``(aliases, fqdn)`` record set.

        Used where the DC set is already deduped (e.g. attack-graph DC nodes keyed
        by node id), so the caller gets the SAME count/sole/alternate logic as the
        ``domains_data`` path without re-deriving it. ``fqdn`` is kept EXACTLY as
        supplied (an empty/None fqdn stays "no usable relay endpoint") — it is not
        re-derived from the aliases.
        """
        built: List[_DCRecord] = []
        for aliases, fqdn in records:
            alias_tuple = tuple(
                a for a in (str(x or "").strip() for x in aliases) if a
            )
            fq = str(fqdn or "").strip() or None
            if not alias_tuple and not fq:
                continue
            built.append(_DCRecord(aliases=alias_tuple, fqdn=fq))
        return cls(dcs=tuple(built))


def resolve_domain_controllers(domain_data: Mapping) -> DomainControllers:
    """Return the deduped DC topology for one ``domains_data[domain]`` entry.

    Dedup algorithm:

    1. Build the PRIMARY DC record from the PDC field-group (``dc_ip``, ``pdc``,
       ``pdc_hostname``, ``pdc_hostname_fqdn``, ``pdc_fqdn``, ``dc_fqdn``) — all of
       which describe the SAME primary DC, giving the IP<->FQDN link for free.
    2. For each ``dcs[]`` entry: attach it to a record it aliases (``hosts_match``
       against ANY of that record's aliases — short-name/case/IP/FQDN aware), else
       start a NEW record.

    ``count`` is the number of records. A host that is the primary DC's IP still
    matches the primary record via its FQDN alias, so the single-DC case counts as
    one, not two.
    """
    dd = domain_data or {}

    primary_aliases: List[str] = []
    seen: set[str] = set()
    for key in _PRIMARY_DC_FIELDS:
        val = str(dd.get(key) or "").strip()
        if val and val.lower() not in seen:
            primary_aliases.append(val)
            seen.add(val.lower())

    records: List[_DCRecord] = []
    if primary_aliases:
        records.append(
            _DCRecord(aliases=tuple(primary_aliases), fqdn=_best_fqdn(primary_aliases))
        )

    from adscan_internal.services.credential_store_service import (  # noqa: PLC0415
        hosts_match,
    )

    for entry in dd.get("dcs") or []:
        text = str(entry or "").strip()
        if not text:
            continue
        attached = False
        for idx, rec in enumerate(records):
            if any(hosts_match(text, alias) for alias in rec.aliases):
                if text.lower() not in {a.lower() for a in rec.aliases}:
                    new_aliases = rec.aliases + (text,)
                    records[idx] = _DCRecord(
                        aliases=new_aliases,
                        fqdn=rec.fqdn or _best_fqdn(new_aliases),
                    )
                attached = True
                break
        if not attached:
            records.append(_DCRecord(aliases=(text,), fqdn=_best_fqdn([text])))

    return DomainControllers(dcs=tuple(records))


def resolve_dc_reachability(domain_data: dict) -> bool | None:
    """Return whether this domain's DC is known-reachable from the current vantage.

    Sourced from the cross-domain connectivity precheck
    (``domain_connectivity_service.merge_domain_connectivity``), which is the
    only place ADscan records reachability for a trust-partner domain it has
    never directly enumerated (e.g. a cross-forest MSSQL linked-server target).

    Returns:
        ``True``/``False`` when a connectivity observation exists.
        ``None`` when there is no such observation -- notably the PRIMARY
        scanned domain, whose own reachability is never in question. Callers
        should treat ``None`` as "no reason to skip normal live verification",
        not as "known unreachable".
    """
    connectivity = domain_data.get("connectivity")
    if not isinstance(connectivity, dict):
        return None
    summary = connectivity.get("summary")
    if not isinstance(summary, dict):
        return None
    if "reachable" not in summary:
        return None
    return bool(summary.get("reachable"))


def qualify_host_fqdn(hostname: str | None, domain: str | None) -> str | None:
    """Return a single-suffixed FQDN for a host, robust against double-suffixing.

    Centralised guard for the ``host.domain.domain`` class of bug: any call site
    that unconditionally does ``f"{hostname}.{domain}"`` produces a double suffix
    when ``hostname`` is already qualified (e.g. the native sweep resolves the
    SPN FQDN up front, then an edge-recorder re-appends the realm). The resulting
    name misses the BloodHound node lookup and silently drops the attack-graph
    edge. Routing every FQDN qualification through this one helper keeps that
    impossible, now and at future call sites.

    Behaviour:
        - empty hostname → ``None``
        - empty domain → hostname as-is (lowercased, de-dotted)
        - collapses any accidental repeated trailing ``.domain`` suffix
          (``host.domain.domain`` → ``host.domain``) and logs the correction so
          the offending caller can be traced
        - short label (no dot after collapse) → ``"<host>.<domain>"``
        - already-dotted name (incl. IPs, cross-forest FQDNs whose suffix differs
          from ``domain``) → returned as-is
    """
    h = str(hostname or "").strip().rstrip(".").lower()
    d = str(domain or "").strip().rstrip(".").lower()
    if not h:
        return None
    if not d:
        return h
    suffix = f".{d}"
    collapsed = h
    while collapsed.endswith(suffix + suffix):
        collapsed = collapsed[: -len(suffix)]
    if collapsed != h:
        # Auto-detected + corrected a double suffix — log so the source caller
        # can be found and fixed (lazy import keeps this module startup-light).
        try:
            from adscan_core.rich_output import print_info_debug  # noqa: PLC0415

            print_info_debug(
                f"[qualify_host_fqdn] collapsed repeated domain suffix: "
                f"{h!r} -> {collapsed!r}"
            )
        except Exception:
            pass
    if "." in collapsed:
        return collapsed
    return f"{collapsed}{suffix}"


def resolve_dc_fqdn(
    domain_data: dict,
    *,
    target_domain: str,
    ip_hostname_inventory: dict | None = None,
) -> str | None:
    """Return the best-available DC FQDN for Kerberos SPN targeting.

    Symmetric to ``resolve_dc_ip``: walks the canonical fallback chain over a
    ``domains_data`` entry and returns ``None`` when no FQDN is recoverable.
    Centralises the lookup so transport-config builders never have to remember
    every alias the collector might have populated.

    Fallback chain:
        1. ``pdc_hostname_fqdn`` (collector canonical FQDN)
        2. ``pdc_fqdn``           (legacy alias)
        3. ``dc_fqdn``             (model field)
        4. ``pdc_hostname``        — kept as-is when already FQDN, promoted to
           ``"<host>.<target_domain>"`` when short; rejected when it is an IP.
        5. ``ip_hostname_inventory`` (massdns/reachability map IP → hostnames)
        6. ``None``                (caller decides whether to fail loud)

    Args:
        domain_data: One ``domains_data[domain]`` entry.
        target_domain: DNS domain name; used to promote short hostnames.
        ip_hostname_inventory: Optional ``{ip: [hostname, …]}`` map loaded via
            ``load_workspace_ip_hostname_inventory``. When provided and no
            FQDN was found above, the resolver maps the resolved DC IP to a
            hostname candidate that ends in ``.<target_domain>`` when possible.

    Returns:
        FQDN string with no trailing dot, or ``None``.
    """
    from adscan_internal.services._kerberos_spn import is_ip_address  # noqa: PLC0415

    # Local debug printer — imported lazily to avoid pulling rich_output at
    # module import time (this module is imported very early in startup).
    def _debug(msg: str) -> None:
        try:
            from adscan_core.rich_output import print_info_debug  # noqa: PLC0415

            print_info_debug(f"[resolve_dc_fqdn] {msg}")
        except Exception:
            pass

    target_domain_clean = str(target_domain or "").strip().rstrip(".")

    for key in ("pdc_hostname_fqdn", "pdc_fqdn", "dc_fqdn"):
        candidate = str(domain_data.get(key) or "").strip().rstrip(".")
        if candidate and not is_ip_address(candidate):
            # Provenance log — surfaces *which* key answered. When this
            # comes back with a key holding a value that doesn't share
            # suffix with ``target_domain``, it's worth checking the
            # workspace for stale data from a previous ADscan version
            # (see BACKLOG entry on v8→v9 workspace migration). The
            # function still returns the value because multi-forest AD
            # legitimately has DCs in DNS namespaces unrelated to the
            # AD realm name — this is a hint, not a guard.
            _debug(
                f"realm={target_domain_clean!r} resolved via "
                f"domain_data[{key!r}]={candidate!r}"
            )
            if (
                target_domain_clean
                and "." in candidate
                and not candidate.lower().endswith(
                    "." + target_domain_clean.lower()
                )
            ):
                _debug(
                    f"NOTE: candidate suffix does not match realm "
                    f"({candidate!r} vs realm {target_domain_clean!r}). "
                    "Legitimate for cross-forest AD, but also the "
                    "signature of stale workspace state from v8 → v9 "
                    "migration. Verify with the DNS validation log."
                )
            return candidate

    pdc_hostname = str(domain_data.get("pdc_hostname") or "").strip().rstrip(".")
    if pdc_hostname and not is_ip_address(pdc_hostname):
        if "." in pdc_hostname:
            _debug(
                f"realm={target_domain_clean!r} resolved via "
                f"domain_data['pdc_hostname']={pdc_hostname!r} (already FQDN)"
            )
            return pdc_hostname
        if target_domain_clean:
            promoted = f"{pdc_hostname}.{target_domain_clean}"
            _debug(
                f"realm={target_domain_clean!r} resolved via short-hostname "
                f"promotion: {pdc_hostname!r} → {promoted!r}"
            )
            return promoted

    if ip_hostname_inventory:
        from adscan_internal.services.kerberos_hostname_inventory import (  # noqa: PLC0415
            choose_hostname_for_kerberos_spn,
        )

        dc_ip = resolve_dc_ip(domain_data)
        if dc_ip:
            chosen = choose_hostname_for_kerberos_spn(
                ip=dc_ip,
                domain=target_domain_clean or None,
                inventory=ip_hostname_inventory,
            )
            if chosen and not is_ip_address(chosen):
                _debug(
                    f"realm={target_domain_clean!r} resolved via "
                    f"ip_hostname_inventory[{dc_ip!r}]={chosen!r}"
                )
                return chosen

    _debug(
        f"realm={target_domain_clean!r} — no FQDN candidate available "
        "(all fallback steps returned empty). Downstream Kerberos auth "
        "will likely fail with SEC_E_LOGON_DENIED or PREAUTH_FAILED."
    )
    return None
