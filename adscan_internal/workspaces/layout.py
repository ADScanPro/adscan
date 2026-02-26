from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DomainLayout:
    """Canonical per-domain directory names used inside an ADscan workspace."""

    bloodhound: str = "BH"
    nmap: str = "nmap"
    kerberos: str = "kerberos"
    smb: str = "smb"
    winrm: str = "winrm"
    ldap: str = "ldap"
    cracking: str = "cracking"
    dcsync: str = "dcsync"


DEFAULT_DOMAIN_LAYOUT = DomainLayout()

__all__ = [
    "DEFAULT_DOMAIN_LAYOUT",
    "DomainLayout",
]
