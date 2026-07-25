"""Domain model representing Active Directory domain state.

This module defines the Domain dataclass that maps to the domains_data dictionary
structure used throughout ADScan. It provides a strongly-typed interface for
domain information, authentication state, and discovered credentials.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum

from adscan_core.time_utils import utc_now


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
