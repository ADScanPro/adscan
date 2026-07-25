"""Centralised persistence helper for machine account credentials.

All dump operations that recover a DC machine account NT hash (Backup Operators
RRP dump, native LSA dump, DCSync fallback) route through
``persist_machine_account_credential`` so that:

- AES-256 and AES-128 keys are always derived from the raw Kerberos password
  bytes (``machine_account_kerberos_password`` from pypykatz LSA parsing) and
  stored alongside the NT hash in ``CredentialMetadata``.
- Environments where RC4 is disabled (AES-only KDC) can still authenticate
  using the stored AES key rather than the NT hash alone.

The AES key derivation uses the Kerberos salt format for computer accounts:
``{REALM}host{fqdn.lower()}`` where ``fqdn = hostname.domain`` (short hostname
resolved to FQDN by appending the domain when no dot is present).

AES keys are verified against the nxc/impacket reference values for Blackfield
HTB (b9dd825c... for AES-256, 0b106a7c... for AES-128 — exact match).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from adscan_core.rich_output import print_info_debug
from adscan_internal import telemetry
from adscan_core.rich_output import print_exception

if TYPE_CHECKING:
    from adscan_internal.services.credentials.credential_metadata import CredentialMetadata


def _derive_aes_keys(
    kerberos_password: bytes,
    nt_hash: str,
    domain: str,
    hostname: str,
) -> "CredentialMetadata | None":
    """Derive AES-256 and AES-128 keys from raw machine account Kerberos password.

    Returns a CredentialMetadata if derivation succeeds, None on failure.
    """
    try:
        from adscan_internal.services.krb_ap_req import derive_service_keys
        from adscan_internal.services.credentials.credential_metadata import CredentialMetadata

        pairs = derive_service_keys(kerberos_password, nt_hash, domain, hostname)
        aes256 = next((k.hex() for etype, k in pairs if etype == 18), None)
        aes128 = next((k.hex() for etype, k in pairs if etype == 17), None)
        if not aes256 and not aes128:
            return None
        print_info_debug(
            f"[machine-account] AES keys derived for {hostname}: "
            f"aes256={'yes' if aes256 else 'no'} aes128={'yes' if aes128 else 'no'}"
        )
        return CredentialMetadata(aes256_key=aes256, aes128_key=aes128)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"[machine-account] AES key derivation failed: {exc}")
        return None


def _is_machine_account_name(username: str | None) -> bool:
    """Minimal guard — full hostname-match validation lives in is_dc_machine_account."""
    return bool(username and username.endswith("$"))


def persist_machine_account_credential(
    shell: Any,
    *,
    domain: str,
    machine_account: str,
    nt_hash: str,
    kerberos_password: bytes | None = None,
    dc_hostname: str | None = None,
    trusted_manual_validation: bool = True,
    ensure_fresh_kerberos_ticket: bool = False,
    prompt_for_user_privs_after: bool = True,
    credential_origin: str = "lsa_dump",
    source_steps: list | None = None,
    skip_hash_cracking: bool = False,
    verify_credential: bool = True,
    ui_silent: bool = False,
) -> None:
    """Persist a machine account NT hash with AES keys derived from raw Kerberos pw.

    All dump paths that recover a DC machine account hash (Backup Operators,
    native LSA dump, DCSync fallback SAM/LSA) should call this instead of
    ``add_credential`` directly so AES keys are always stored.

    Args:
        shell:                    PentestShell instance.
        domain:                   Target domain name.
        machine_account:          sAMAccountName ending with ``$``, e.g. ``DC01$``.
        nt_hash:                  32-char NT hash hex string.
        kerberos_password:        Raw Kerberos password bytes from pypykatz
                                  ``LSASecretMachineAccount.kerberos_password``.
                                  When present, AES-256 and AES-128 are derived
                                  and stored in CredentialMetadata.
        dc_hostname:              Short DC hostname (e.g. ``DC01``).  Used as the
                                  base for the Kerberos salt.  When omitted, the
                                  account name (minus ``$``) is used.
        trusted_manual_validation: Skip re-verification; credential was obtained
                                  from the DC's own LSA secrets.
        ensure_fresh_kerberos_ticket: Skip TGT generation on add (machine
                                  accounts need AES key, not NT hash alone).
        prompt_for_user_privs_after: Offer privilege-enumeration follow-up.
        credential_origin:        Provenance label stored in workspace.
        source_steps:             Attack-graph provenance edge descriptors.
        skip_hash_cracking:       Skip cracking for machine account hashes.
        verify_credential:        Verify the credential against the DC.
        ui_silent:                Suppress Rich panels for this add.
    """
    hostname = dc_hostname or machine_account.rstrip("$")
    meta: "CredentialMetadata | None" = None
    if kerberos_password:
        meta = _derive_aes_keys(kerberos_password, nt_hash, domain, hostname)

    shell.add_credential(
        domain,
        machine_account,
        nt_hash,
        trusted_manual_validation=trusted_manual_validation,
        ensure_fresh_kerberos_ticket=ensure_fresh_kerberos_ticket,
        prompt_for_user_privs_after=prompt_for_user_privs_after,
        credential_origin=credential_origin,
        source_steps=source_steps,
        skip_hash_cracking=skip_hash_cracking,
        verify_credential=verify_credential,
        ui_silent=ui_silent,
        metadata=meta,
    )
