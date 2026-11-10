"""LDAP credential model — Pythonic dependency injection for the collector.

Constructed via factory methods, never via the bare initializer. The factories
encode the legitimate authentication shapes ADscan supports:

  * **anonymous** (RFC 4513 §5.1.1 SIMPLE bind with empty creds)
  * **password** (NTLMv2 over SASL or SIMPLE over LDAPS)
  * **NT hash** (pass-the-hash via NTLMv2)
  * **Kerberos** via password / AES key / ccache

The frozen dataclass guarantees that downstream consumers cannot mutate the
credential mid-flight — a class of subtle bugs we avoid up-front.

Use ``LDAPCredentials.to_transport_config()`` to obtain the transport-level
``ADscanLDAPConfig`` consumed by ``ADscanLDAPConnection`` /
``async_connect_with_ldap_fallback``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from adscan_internal.services.domain_posture import DomainPosture
    from adscan_internal.services.ldap_transport_service import ADscanLDAPConfig
    from adscan_internal.services.posture_sink import PostureSink


@dataclass(frozen=True, slots=True)
class LDAPCredentials:
    """Immutable LDAP authentication context.

    Construct via the dedicated factories (``anonymous``, ``password``,
    ``nt_hash``, ``kerberos_password``, ``kerberos_aes``, ``kerberos_ccache``)
    rather than calling the bare initializer — the factories encode the
    invariants between fields (e.g. ``use_simple_bind`` is mutually exclusive
    with ``use_kerberos``).
    """

    domain: str
    dc_ip: str
    username: str = ""
    password: str | None = None
    nt_hash: str | None = None
    aes_key: str | None = None
    ccache_path: str | None = None
    use_kerberos: bool = False
    use_simple_bind: bool = False
    auth_domain: str | None = None
    auth_kdc: str | None = None
    kerberos_target_hostname: str | None = None
    use_ldaps: bool = True
    posture_sink: Optional["PostureSink"] = None
    """Optional posture observer; see PR2 docstring for semantics. Threaded
    into the eventual ``ADscanLDAPConfig`` so the LDAP transport can emit
    signals without the collector knowing about workspace state."""
    posture_snapshot: Optional["DomainPosture"] = None
    """Optional persisted posture snapshot read from workspace ``domains_data``.
    Threaded into the eventual ``ADscanLDAPConfig`` so the auth planner can
    skip speculative attempts when high-confidence prior observations exist."""

    def __post_init__(self) -> None:
        if self.use_simple_bind and self.use_kerberos:
            raise ValueError(
                "LDAPCredentials: use_simple_bind and use_kerberos are mutually exclusive"
            )
        if self.aes_key and not self.use_kerberos:
            raise ValueError("LDAPCredentials: aes_key requires use_kerberos=True")
        if self.ccache_path and not self.use_kerberos:
            raise ValueError("LDAPCredentials: ccache_path requires use_kerberos=True")

    @property
    def is_anonymous(self) -> bool:
        """Return True when no credential material is present."""
        return (
            not self.username
            and not self.password
            and not self.nt_hash
            and not self.aes_key
            and not self.ccache_path
        )

    @classmethod
    def anonymous(
        cls,
        *,
        domain: str,
        dc_ip: str,
        use_ldaps: bool = True,
        kerberos_target_hostname: str | None = None,
        posture_sink: Optional["PostureSink"] = None,
        posture_snapshot: Optional["DomainPosture"] = None,
    ) -> LDAPCredentials:
        """SIMPLE bind with empty username/password (RFC 4513 §5.1.1).

        ``use_simple_bind=True`` causes the transport URL builder to emit
        ``ldap+simple://@host`` so the post-bind connection is in RUNNING
        state and ``pagedsearch`` works. The bare ``ldap://host`` form
        leaves the connection in CONNECTED state and pagedsearch raises
        "Connected, but not bound".
        """
        return cls(
            domain=domain,
            dc_ip=dc_ip,
            use_simple_bind=True,
            use_ldaps=use_ldaps,
            kerberos_target_hostname=kerberos_target_hostname,
            posture_sink=posture_sink,
            posture_snapshot=posture_snapshot,
        )

    @classmethod
    def for_password(
        cls,
        *,
        domain: str,
        dc_ip: str,
        username: str,
        password: str,
        use_ldaps: bool = True,
        auth_domain: str | None = None,
        auth_kdc: str | None = None,
        kerberos_target_hostname: str | None = None,
        posture_sink: Optional["PostureSink"] = None,
        posture_snapshot: Optional["DomainPosture"] = None,
    ) -> LDAPCredentials:
        """NTLMv2 password bind."""
        return cls(
            domain=domain,
            dc_ip=dc_ip,
            username=username,
            password=password,
            use_ldaps=use_ldaps,
            auth_domain=auth_domain,
            auth_kdc=auth_kdc,
            kerberos_target_hostname=kerberos_target_hostname,
            posture_sink=posture_sink,
            posture_snapshot=posture_snapshot,
        )

    @classmethod
    def for_nt_hash(
        cls,
        *,
        domain: str,
        dc_ip: str,
        username: str,
        nt_hash: str,
        use_ldaps: bool = True,
        auth_domain: str | None = None,
        auth_kdc: str | None = None,
        kerberos_target_hostname: str | None = None,
        posture_sink: Optional["PostureSink"] = None,
        posture_snapshot: Optional["DomainPosture"] = None,
    ) -> LDAPCredentials:
        """NTLMv2 pass-the-hash. The transport layer passes the NT hash as
        the password component; ``_is_nt_hash`` heuristic upgrades it to
        ``ntlm-nt://`` automatically.
        """
        return cls(
            domain=domain,
            dc_ip=dc_ip,
            username=username,
            password=nt_hash,
            nt_hash=nt_hash,
            use_ldaps=use_ldaps,
            auth_domain=auth_domain,
            auth_kdc=auth_kdc,
            kerberos_target_hostname=kerberos_target_hostname,
            posture_sink=posture_sink,
            posture_snapshot=posture_snapshot,
        )

    @classmethod
    def for_kerberos_password(
        cls,
        *,
        domain: str,
        dc_ip: str,
        username: str,
        password: str,
        kdc: str | None = None,
        auth_domain: str | None = None,
        use_ldaps: bool = True,
        kerberos_target_hostname: str | None = None,
        posture_sink: Optional["PostureSink"] = None,
        posture_snapshot: Optional["DomainPosture"] = None,
    ) -> LDAPCredentials:
        """Kerberos AS-REQ with a plaintext password."""
        return cls(
            domain=domain,
            dc_ip=dc_ip,
            username=username,
            password=password,
            use_kerberos=True,
            use_ldaps=use_ldaps,
            auth_domain=auth_domain,
            auth_kdc=kdc,
            kerberos_target_hostname=kerberos_target_hostname,
            posture_sink=posture_sink,
            posture_snapshot=posture_snapshot,
        )

    @classmethod
    def for_kerberos_aes(
        cls,
        *,
        domain: str,
        dc_ip: str,
        username: str,
        aes_key: str,
        kdc: str | None = None,
        auth_domain: str | None = None,
        use_ldaps: bool = True,
        kerberos_target_hostname: str | None = None,
        posture_sink: Optional["PostureSink"] = None,
        posture_snapshot: Optional["DomainPosture"] = None,
    ) -> LDAPCredentials:
        """Kerberos AS-REQ with an AES-128 (32 hex) or AES-256 (64 hex) key."""
        return cls(
            domain=domain,
            dc_ip=dc_ip,
            username=username,
            aes_key=aes_key,
            use_kerberos=True,
            use_ldaps=use_ldaps,
            auth_domain=auth_domain,
            auth_kdc=kdc,
            kerberos_target_hostname=kerberos_target_hostname,
            posture_sink=posture_sink,
            posture_snapshot=posture_snapshot,
        )

    @classmethod
    def for_kerberos_ccache(
        cls,
        *,
        domain: str,
        dc_ip: str,
        username: str,
        ccache_path: str,
        kdc: str | None = None,
        auth_domain: str | None = None,
        use_ldaps: bool = True,
        kerberos_target_hostname: str | None = None,
        posture_sink: Optional["PostureSink"] = None,
        posture_snapshot: Optional["DomainPosture"] = None,
    ) -> LDAPCredentials:
        """Kerberos with an existing credential cache (KRB5CCNAME-style file)."""
        return cls(
            domain=domain,
            dc_ip=dc_ip,
            username=username,
            ccache_path=ccache_path,
            use_kerberos=True,
            use_ldaps=use_ldaps,
            auth_domain=auth_domain,
            auth_kdc=kdc,
            kerberos_target_hostname=kerberos_target_hostname,
            posture_sink=posture_sink,
            posture_snapshot=posture_snapshot,
        )

    def to_transport_config(self, *, paged_size: int | None = None) -> ADscanLDAPConfig:
        """Map onto the transport-layer ``ADscanLDAPConfig``.

        Centralizes the kwargs translation so callers never need to know about
        the legacy field shape on ``ADscanLDAPConfig``. The optional
        ``posture_sink`` is propagated through verbatim so the LDAP transport
        can emit posture signals without the collector layer being aware of
        workspace state (PR6a wiring).
        """
        from adscan_internal.services.ldap_transport_service import ADscanLDAPConfig

        return ADscanLDAPConfig(
            domain=self.domain,
            dc_ip=self.dc_ip,
            use_ldaps=self.use_ldaps,
            use_kerberos=self.use_kerberos,
            username=self.username or None,
            password=self.password,
            kerberos_target_hostname=self.kerberos_target_hostname,
            auth_domain=self.auth_domain or self.domain,
            auth_kdc=self.auth_kdc or self.dc_ip,
            aes_key=self.aes_key,
            ccache_path=self.ccache_path,
            use_simple_bind=self.use_simple_bind,
            **({} if paged_size is None else {"paged_size": paged_size}),
            posture_sink=self.posture_sink,
            posture_snapshot=self.posture_snapshot,
        )
