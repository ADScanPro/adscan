"""Helpers to build :class:`SMBConfig` instances from a credential.

Lots of call sites in ADscan today build :class:`SMBConfig` by hand,
repeating the same conditional logic that decides whether the secret is
a password, an NT hash, an AES key or a ccache path. This module
centralises that decision so future refactors only have to touch one
place.
"""

from __future__ import annotations

from typing import Literal

from adscan_internal.services.smb_transport import SMBConfig

SecretKind = Literal["password", "nt_hash", "aes_key", "ccache"]


def build_smb_config_from_credential(
    *,
    domain: str,
    username: str,
    secret: str,
    secret_kind: SecretKind,
    target_host: str,
    target_ip: str | None = None,
    kdc_ip: str | None = None,
    auth_domain: str | None = None,
    prefer_kerberos: bool = False,
    timeout: int = 30,
    dns_server: str | None = None,
) -> SMBConfig:
    """Build an :class:`SMBConfig` from a single credential.

    Args:
        domain: Target domain (the realm being enumerated/attacked).
        username: sAMAccountName or UPN local-part of the principal.
        secret: The credential value. Interpretation depends on
            ``secret_kind``.
        secret_kind: One of ``"password"``, ``"nt_hash"``, ``"aes_key"``,
            ``"ccache"``. Selects which auth field of :class:`SMBConfig`
            receives the secret and forces Kerberos for AES/ccache.
        target_host: Hostname (or FQDN) of the target — used as the SPN
            host when Kerberos is selected.
        target_ip: Optional explicit IP. Defaults to ``target_host``
            when omitted. Required if ``target_host`` is not resolvable
            inside the runtime container.
        kdc_ip: KDC address for the credential's domain. Required for
            Kerberos auth across realms.
        auth_domain: Domain the credential lives in. Defaults to
            ``domain`` (single-realm engagement).
        prefer_kerberos: Ask for Kerberos even when secret is a password
            or NT hash. AES keys and ccache paths always force Kerberos
            regardless of this flag.
        timeout: Connection timeout in seconds (default 30).
        dns_server: Split-DC/DNS (issue #15) — a SEPARATE AD-zone DNS server
            for segmented networks. When set, the target host A/PTR resolution
            queries this server instead of the DC/KDC. ``None`` (default) keeps
            the DC as the resolver, byte-identical to before.

    Returns:
        A fully-populated :class:`SMBConfig` ready to hand to
        :func:`smb_machine_for` or :func:`execute_with_fallback`.

    Raises:
        ValueError: ``secret_kind`` is unknown or required field is empty.
    """
    if not target_host:
        raise ValueError("target_host is required")
    if secret_kind not in {"password", "nt_hash", "aes_key", "ccache"}:
        raise ValueError(f"unknown secret_kind: {secret_kind!r}")

    use_kerberos = bool(prefer_kerberos or secret_kind in {"aes_key", "ccache"})

    return SMBConfig(
        target_ip=str(target_ip or target_host),
        target_hostname=str(target_host),
        domain=domain or None,
        username=username or None,
        password=secret if secret_kind == "password" else None,
        nt_hash=secret if secret_kind == "nt_hash" else None,
        aes_key=secret if secret_kind == "aes_key" else None,
        ccache_path=secret if secret_kind == "ccache" else None,
        auth_domain=(auth_domain or domain) or None,
        kdc_ip=kdc_ip or None,
        use_kerberos=use_kerberos,
        dns_server=dns_server or None,
        timeout=int(timeout),
    )


__all__ = ["build_smb_config_from_credential", "SecretKind"]
