"""Shared types for the ADCS ESC exploitation engine."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class EscConfig:
    esc: int
    domain: str
    auth_domain: str
    dc_ip: str
    auth_kdc: str
    ca_host: str
    ca_name: str
    template: Optional[str]
    username: str
    password: Optional[str] = None
    min_key_size: Optional[int] = None  # msPKI-Minimal-Key-Size from template LDAP
    nt_hash: Optional[str] = None
    use_kerberos: bool = False
    ccache_path: Optional[str] = None
    aes_key: Optional[str] = None
    target_upn: str = ""
    on_behalf_of: Optional[str] = None
    agent_pfx_path: Optional[str] = None
    agent_pfx_pass: Optional[str] = None
    workspace_dir: str = ""
    shell: Any = None
    # ESC9/14
    target_account: str = ""
    target_account_dn: str = ""
    ca_fqdn: Optional[str] = None
    # ESC8 Kerberos relay
    spn_target: str = (
        ""  # sAMAccountName of account to receive the relay SPN (e.g. "KINGSLANDING$")
    )
    relay_hostname: str = ""  # override auto-generated relay DNS alias
    spn_auth_username: str = (
        ""  # credentials for SPN write (if different from username)
    )
    spn_auth_password: str = (
        ""  # credentials for SPN write (if different from password)
    )
    dc_fqdn: Optional[str] = None
    """FQDN of the DC for Kerberos SMB targets. Populated from
    ``domain_data['pdc_hostname']`` / ``['dc_fqdn']`` and promoted to FQDN by
    ``__post_init__``. Required when ``use_kerberos=True`` because aiosmb
    derives the ``cifs/<host>`` SPN from the SMB target — passing an IP yields
    a ticket the server rejects (same SEC_E_LOGON_DENIED pattern as LDAP)."""
    dns_server: Optional[str] = None
    """Split-DC/DNS (issue #15): a SEPARATE AD-zone DNS server for segmented
    networks. When unset it is auto-populated in ``__post_init__`` from
    ``shell.domains_data[domain]['dns_server']``, and forwarded into the
    ``CertRequestConfig`` / CA-backup resolution so the CA host resolves via the
    DNS server, not the DC. ``None`` -> the DC resolves (byte-identical)."""

    def __post_init__(self) -> None:
        from adscan_internal.services._kerberos_spn import (
            is_ip_address,
            normalize_kerberos_target_hostname,
        )
        from adscan_core.rich_output import mark_sensitive, print_warning

        # Promote short DC hostnames to FQDN. Mirrors the centralisation done
        # in ADscanLDAPConfig / SMBConfig — see services/_kerberos_spn.py.
        self.dc_fqdn = normalize_kerberos_target_hostname(self.dc_fqdn, self.domain)

        # Split-DC/DNS (issue #15): auto-resolve the separate AD DNS server from
        # the shell's domain data when the caller did not pass one explicitly, so
        # every ESC build site inherits it without threading a new kwarg. Absent
        # -> None, and the DC stays the resolver (byte-identical).
        if not (self.dns_server or "").strip() and self.shell is not None:
            try:
                from adscan_internal.models.domain import resolve_dns_server

                domains_data = getattr(self.shell, "domains_data", None) or {}
                entry = domains_data.get(self.domain) or domains_data.get(
                    self.auth_domain
                )
                if isinstance(entry, dict):
                    self.dns_server = resolve_dns_server(entry)
            except Exception:  # noqa: BLE001 — best-effort; absence keeps the DC.
                self.dns_server = None

        # Enforce the ca_host / ca_fqdn consistency invariant: ca_fqdn must
        # either equal ca_host (when ca_host is an FQDN) or be a valid FQDN
        # (when ca_host is an IP).  Mismatches here mean the Kerberos SPN
        # would target the wrong host and the AP-REP decryption would fail.
        ca_host = (self.ca_host or "").strip()
        ca_fqdn = (self.ca_fqdn or "").strip() or None

        host_is_ip = is_ip_address(ca_host) if ca_host else False
        host_is_fqdn = bool(ca_host) and not host_is_ip and "." in ca_host

        if host_is_fqdn:
            if ca_fqdn and ca_fqdn.casefold() != ca_host.casefold():
                print_warning(
                    f"EscConfig: ca_fqdn={mark_sensitive(ca_fqdn, 'hostname')!r} "
                    f"disagrees with ca_host={mark_sensitive(ca_host, 'hostname')!r} "
                    "— using ca_host as the FQDN."
                )
            self.ca_fqdn = ca_host
        elif ca_fqdn and is_ip_address(ca_fqdn):
            print_warning(
                f"EscConfig: ca_fqdn={mark_sensitive(ca_fqdn, 'hostname')!r} "
                "is an IP, not an FQDN — discarding."
            )
            self.ca_fqdn = None

    @property
    def effective_secret(self) -> str:
        """Credential string for consumers that accept a single secret.

        Returns ``password`` when set; falls back to ``nt_hash`` so callers
        do not need to branch on which field is populated.

        Format detection and auth-scheme selection happen in the transport
        config layer (``CertRequestConfig``, ``KerberosConfig``, ``SMBConfig``,
        ``ADscanLDAPConfig``). EscConfig intentionally does NOT mutate the
        credential fields so ``config.password`` always contains whatever
        the caller stored — no silent None after construction.
        """
        return self.password or self.nt_hash or ""


@dataclass
class EscStep:
    label: str
    description: str
    destructive: bool = False
    rollback_label: str = ""


@dataclass
class EscResult:
    success: bool
    esc: int
    nt_hash: Optional[str] = None
    ccache_path: Optional[str] = None
    pfx_path: Optional[str] = None
    pfx_bytes: Optional[bytes] = None
    error: Optional[str] = None
    rollback_ok: bool = True
    rollback_error: Optional[str] = None
    evidence: dict[str, Any] = field(default_factory=dict)
