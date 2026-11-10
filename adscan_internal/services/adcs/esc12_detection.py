"""ADCS ESC12 detection: a CA key in a YubiHSM2 whose KSP password sits in the registry.

READ-ONLY. Detection only: ADscan never reads the stored password, never signs
anything with the CA key and writes nothing to the CA host.

What ESC12 is
-------------
Hans-Joachim Knobloch named it in "ESC12 - Shell access to ADCS CA with
YubiHSM" (https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).
When a certification authority keeps its private key in a Yubico YubiHSM2, the
CA reaches the key through the "YubiHSM Key Storage Provider". That provider
authenticates to the HSM with an authentication-key password that Yubico's own
deployment guide stores IN CLEAR TEXT in the CA server's registry, under
``HKLM\\SOFTWARE\\Yubico\\YubiHSM`` value ``AuthKeysetPassword`` (32-bit KSP:
``HKLM\\SOFTWARE\\Wow6432Node\\Yubico\\YubiHSM``), and the provider does not
check which account calls it. Anyone who can read that value, or who holds a
shell on the CA host, can use the CA signing key without exporting it and forge
certificates for any principal. The HSM therefore does not give the isolation a
client expects from it against an administrator of the CA host.

Registry paths, confirmed against the sources (not guessed):

* the original publication above (password location, KSP name);
* Yubico's YubiHSM 2 user guide, "Configure Key Storage Provider" and "Deploy
  for Active Directory Certificate Services CA" (``AuthKeysetPassword`` is a
  string value under ``HKLM\\SOFTWARE\\Yubico\\YubiHSM`` beside ``AuthKeysetID``
  and ``ConnectorURL``; the CA's ``CSP\\Provider`` is set to
  ``"YubiHSM Key Storage Provider"`` under
  ``HKLM\\System\\CurrentControlSet\\Services\\CertSvc\\Configuration\\<CAName>``).

Certipy documents ESC12 but ships no detection for it.

Detection (observe, never infer)
--------------------------------
Two registry reads on the CA host over MS-RRP, with a credential PROVEN to be a
local administrator of that host (Domain Admin, or a verified ``AdminTo`` on the
CA host) through the credential SSOT
:func:`~adscan_internal.services.credentials.pick_credential_for_local_admin`.
Remote registry access to ``HKLM\\SOFTWARE`` is administrator-only on a server,
so a weaker credential could only ever produce an access-denied answer.

1. ``CSP\\Provider`` of the CA configuration key: is the CA key held by the
   YubiHSM KSP?
2. Only when it is: the SIZE of ``AuthKeysetPassword``, read with a zero-length
   buffer (``RRPRPC.QueryValueSize``) so the password never crosses the wire.

Three outcomes, each honest:

* ``confirmed`` - YubiHSM KSP and a non-empty stored password.
* ``not_applicable`` - checked, and the CA key is not in the YubiHSM KSP, or no
  password is stored. This is an existence condition, never a closed avenue.
* ``not_checked`` - no proven local-admin credential, the scan policy excluded
  it, the remote registry was unreachable, access was denied, or a read failed.
  Never rendered as "not vulnerable".
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from adscan_core import telemetry
from adscan_core.rich_output import print_exception, print_info_debug
from adscan_internal.rich_output import mark_sensitive

#: Finding key and attack-step relation this module detects.
ESC12_FINDING_KEY = "adcs_esc12"
ESC12_RELATION = "ADCSESC12"
#: Detector family the observation record is written under.
ESC12_CHECK_ID = "adcs.esc12"

#: Provider name the YubiHSM KSP registers (Yubico deployment guide).
YUBIHSM_KSP_NAME = "YubiHSM Key Storage Provider"
#: Case-insensitive marker matched inside ``CSP\\Provider``. Matching on the
#: vendor token, not the full string, tolerates the ``RSA#``/``ECDSA_P256#``
#: algorithm prefix some installs record.
_YUBIHSM_PROVIDER_MARKER = "yubihsm"

#: CA configuration key (per CA, under HKLM). ``{ca_name}`` is the CA's
#: sanitized name, the same key the CA registry probe reads ``EditFlags`` from.
CA_CSP_KEY_TEMPLATE = "SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{ca_name}\\CSP"
CA_CSP_PROVIDER_VALUE = "Provider"

#: YubiHSM KSP configuration keys: 64-bit KSP first, then the 32-bit KSP.
YUBIHSM_KSP_KEYS: tuple[str, ...] = (
    "SOFTWARE\\Yubico\\YubiHSM",
    "SOFTWARE\\Wow6432Node\\Yubico\\YubiHSM",
)
YUBIHSM_PASSWORD_VALUE = "AuthKeysetPassword"

OUTCOME_CONFIRMED = "confirmed"
OUTCOME_NOT_APPLICABLE = "not_applicable"
OUTCOME_NOT_CHECKED = "not_checked"

#: Stable reason codes (the observation record and the edge notes carry them).
REASON_STORED_HSM_PASSWORD = "stored_hsm_password_readable"
REASON_KEY_NOT_IN_YUBIHSM = "ca_key_not_in_yubihsm"
REASON_NO_STORED_PASSWORD = "no_stored_hsm_password"
REASON_NO_LOCAL_ADMIN = "no_local_admin_on_ca_host"
REASON_EXCLUDED_BY_POLICY = "excluded_by_scan_policy"
REASON_CA_HOST_UNKNOWN = "ca_host_unknown"
REASON_CA_CONFIG_NOT_FOUND = "ca_configuration_key_not_found"
REASON_ACCESS_DENIED = "registry_access_denied"
REASON_REMOTE_REGISTRY_UNAVAILABLE = "remote_registry_unavailable"
REASON_AUTH_FAILED = "authentication_failed"
REASON_READ_FAILED = "registry_read_failed"

_ERROR_FILE_NOT_FOUND = 0x2
_ERROR_ACCESS_DENIED = 0x5

#: REG_SZ / REG_EXPAND_SZ value types: an "empty" string still carries the
#: UTF-16 terminator (2 bytes), so only a longer value holds a password.
_STRING_VALUE_TYPES = frozenset({1, 2})


@dataclass(frozen=True)
class Esc12RegistryReading:
    """What the two registry reads returned. Never carries the password.

    Attributes:
        provider: ``CSP\\Provider`` of the CA (not a secret), ``None`` when absent.
        provider_read: The CSP key was opened and queried.
        csp_key_found: The CA's ``CSP`` configuration key exists.
        password_checked: The YubiHSM keys were examined (only when the provider
            is the YubiHSM KSP).
        password_size: Byte size of ``AuthKeysetPassword`` (type + size only),
            ``None`` when the value is absent.
        password_value_type: Registry type of the value.
        password_key: The key the value was found under (no data).
        error_reason: A ``not_checked`` reason when a read failed.
    """

    provider: str | None = None
    provider_read: bool = False
    csp_key_found: bool = True
    password_checked: bool = False
    password_size: int | None = None
    password_value_type: int | None = None
    password_key: str | None = None
    error_reason: str = ""


@dataclass(frozen=True)
class Esc12CheckResult:
    """The ESC12 verdict for one certification authority.

    ``provider`` and ``password_key`` are configuration facts; the stored
    password itself is never read, so no field here can carry it.
    """

    ca_name: str
    ca_host: str
    outcome: str
    reason: str
    provider: str | None = None
    password_key: str | None = None
    checked_as: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def confirmed(self) -> bool:
        """Whether ESC12 was confirmed on this CA."""
        return self.outcome == OUTCOME_CONFIRMED

    def edge_notes(self) -> dict[str, Any]:
        """Notes stamped on the ``ADCSESC12`` graph edge (no secret material)."""
        return {
            "esc12_outcome": self.outcome,
            "esc12_reason": self.reason,
            "ca_name": self.ca_name,
            "ca_host": self.ca_host,
            "ca_key_storage_provider": self.provider or "",
            "hsm_password_registry_key": f"HKLM\\{self.password_key}" if self.password_key else "",
            "hsm_password_registry_value": YUBIHSM_PASSWORD_VALUE,
            "requires": "local_admin_on_ca_host",
            "read_only": True,
            "exploit_status": "theoretical",
        }


def provider_is_yubihsm(provider: str | None) -> bool:
    """Return whether a ``CSP\\Provider`` value names the YubiHSM KSP."""
    return _YUBIHSM_PROVIDER_MARKER in str(provider or "").casefold()


def stored_password_present(size: int | None, value_type: int | None) -> bool:
    """Return whether a value of ``size`` bytes holds a non-empty password."""
    if size is None:
        return False
    if value_type in _STRING_VALUE_TYPES:
        return int(size) > 2
    return int(size) > 0


def classify_esc12_reading(reading: Esc12RegistryReading) -> tuple[str, str]:
    """Return ``(outcome, reason)`` for a registry reading. Pure.

    A read that did not complete is ``not_checked``; only a completed read
    may yield ``not_applicable`` or ``confirmed``.
    """
    if reading.error_reason:
        return OUTCOME_NOT_CHECKED, reading.error_reason
    if not reading.csp_key_found:
        return OUTCOME_NOT_CHECKED, REASON_CA_CONFIG_NOT_FOUND
    if not reading.provider_read:
        return OUTCOME_NOT_CHECKED, REASON_READ_FAILED
    if not provider_is_yubihsm(reading.provider):
        return OUTCOME_NOT_APPLICABLE, REASON_KEY_NOT_IN_YUBIHSM
    if not reading.password_checked:
        return OUTCOME_NOT_CHECKED, REASON_READ_FAILED
    if not stored_password_present(reading.password_size, reading.password_value_type):
        return OUTCOME_NOT_APPLICABLE, REASON_NO_STORED_PASSWORD
    return OUTCOME_CONFIRMED, REASON_STORED_HSM_PASSWORD


def classify_registry_error(exc: BaseException) -> str:
    """Map a transport / RPC failure to a ``not_checked`` reason code."""
    errno = getattr(exc, "errno", None)
    if errno == _ERROR_ACCESS_DENIED:
        return REASON_ACCESS_DENIED
    text = f"{type(exc).__name__} {exc}".upper()
    if "ACCESS_DENIED" in text or "ACCESS DENIED" in text:
        return REASON_ACCESS_DENIED
    if any(
        marker in text
        for marker in ("OBJECT_NAME_NOT_FOUND", "PIPE_NOT_AVAILABLE", "PIPE_BROKEN", "BAD_NETWORK_NAME")
    ):
        return REASON_REMOTE_REGISTRY_UNAVAILABLE
    if any(marker in text for marker in ("LOGON_FAILURE", "SMBAUTHERROR", "KDC_ERR", "AUTH")):
        return REASON_AUTH_FAILED
    return REASON_READ_FAILED


def _errno_of(err: Any) -> int | None:
    value = getattr(err, "errno", None)
    return int(value) if isinstance(value, int) else None


async def _read_provider(rrp: Any, hklm: Any, ca_name: str) -> tuple[bool, bool, str | None, str]:
    """Return ``(csp_key_found, provider_read, provider, error_reason)``."""
    from aiosmb.dcerpc.v5 import rrp as rrp_ndr  # noqa: PLC0415
    from aiosmb.dcerpc.v5.interfaces.remoteregistry import REG_ACCESS_MASK  # noqa: PLC0415

    key_path = CA_CSP_KEY_TEMPLATE.format(ca_name=ca_name)
    key, err = await rrp.OpenKey(hklm, key_path, access=REG_ACCESS_MASK(rrp_ndr.KEY_READ))  # pylint: disable=no-member  # vendor rrp defines KEY_READ
    if err is not None or key is None:
        code = _errno_of(err)
        if code == _ERROR_FILE_NOT_FOUND:
            return False, False, None, ""
        if code == _ERROR_ACCESS_DENIED:
            return True, False, None, REASON_ACCESS_DENIED
        return True, False, None, REASON_READ_FAILED
    try:
        _val_type, value, err = await rrp.QueryValue(key, CA_CSP_PROVIDER_VALUE)
        if err is not None:
            if _errno_of(err) == _ERROR_FILE_NOT_FOUND:
                return True, True, None, ""
            return True, False, None, REASON_READ_FAILED
        provider = str(value).rstrip("\x00").strip() if value is not None else None
        return True, True, provider or None, ""
    finally:
        await rrp.CloseKey(key)


async def _read_password_presence(
    rrp: Any, hklm: Any
) -> tuple[bool, int | None, int | None, str | None, str]:
    """Return ``(checked, size, value_type, key_path, error_reason)``.

    Reads the TYPE and SIZE of ``AuthKeysetPassword`` only. A key or value
    that does not exist is a completed check with no stored password; an
    access-denied answer is not a completed check.
    """
    from aiosmb.dcerpc.v5 import rrp as rrp_ndr  # noqa: PLC0415
    from aiosmb.dcerpc.v5.interfaces.remoteregistry import REG_ACCESS_MASK  # noqa: PLC0415

    for key_path in YUBIHSM_KSP_KEYS:
        key, err = await rrp.OpenKey(hklm, key_path, access=REG_ACCESS_MASK(rrp_ndr.KEY_READ))  # pylint: disable=no-member  # vendor rrp defines KEY_READ
        if err is not None or key is None:
            code = _errno_of(err)
            if code == _ERROR_FILE_NOT_FOUND:
                continue
            if code == _ERROR_ACCESS_DENIED:
                return False, None, None, None, REASON_ACCESS_DENIED
            return False, None, None, None, REASON_READ_FAILED
        try:
            value_type, size, err = await rrp.QueryValueSize(key, YUBIHSM_PASSWORD_VALUE)
            if err is not None:
                code = _errno_of(err)
                if code == _ERROR_FILE_NOT_FOUND:
                    continue
                if code == _ERROR_ACCESS_DENIED:
                    return False, None, None, None, REASON_ACCESS_DENIED
                return False, None, None, None, REASON_READ_FAILED
            return True, size, value_type, key_path, ""
        finally:
            await rrp.CloseKey(key)
    return True, None, None, None, ""


async def read_esc12_registry(*, smb_config: Any, ca_name: str) -> Esc12RegistryReading:
    """Read the CA's key-storage provider and the YubiHSM password presence.

    Opens ONE SMB connection to the CA host (posture-aware Kerberos / NTLM
    fallback) and ONE ``\\winreg`` pipe; both reads run sequentially on it.
    Never raises: a failure becomes ``error_reason``.
    """
    from aiosmb.dcerpc.v5.interfaces.remoteregistry import (  # noqa: PLC0415
        HKEY,
        rrprpc_from_smb,
    )

    from adscan_internal.services.smb_transport import (  # noqa: PLC0415
        smb_machine_with_fallback,
    )

    try:
        async with smb_machine_with_fallback(smb_config) as machine:
            async with rrprpc_from_smb(machine.connection) as rrp:
                hklm, err = await rrp.ConnectRegistry(HKEY.LOCAL_MACHINE)
                if err is not None:
                    raise err
                try:
                    csp_found, provider_read, provider, reason = await _read_provider(
                        rrp, hklm, ca_name
                    )
                    if reason or not csp_found or not provider_read:
                        return Esc12RegistryReading(
                            provider=provider,
                            provider_read=provider_read,
                            csp_key_found=csp_found,
                            error_reason=reason,
                        )
                    if not provider_is_yubihsm(provider):
                        return Esc12RegistryReading(provider=provider, provider_read=True)
                    checked, size, value_type, key_path, reason = await _read_password_presence(
                        rrp, hklm
                    )
                    return Esc12RegistryReading(
                        provider=provider,
                        provider_read=True,
                        password_checked=checked,
                        password_size=size,
                        password_value_type=value_type,
                        password_key=key_path,
                        error_reason=reason,
                    )
                finally:
                    await rrp.CloseKey(hklm)
    except Exception as exc:  # noqa: BLE001 - a failed read is a data gap, never a verdict
        reason = classify_registry_error(exc)
        if reason == REASON_READ_FAILED:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
        print_info_debug(
            "adcs esc12 registry read did not complete: "
            f"ca={mark_sensitive(ca_name, 'hostname')} reason={reason} "
            f"error={type(exc).__name__}"
        )
        return Esc12RegistryReading(error_reason=reason)


def not_checked(ca_name: str, ca_host: str, reason: str, **detail: Any) -> Esc12CheckResult:
    """Build a ``not_checked`` result (no read was made, or none completed)."""
    return Esc12CheckResult(
        ca_name=ca_name,
        ca_host=ca_host,
        outcome=OUTCOME_NOT_CHECKED,
        reason=reason,
        detail=dict(detail),
    )


@dataclass(frozen=True)
class Esc12Credential:
    """The proven local-admin credential the read runs as, and its SMB config."""

    username: str
    smb_config: Any


def resolve_esc12_credential(
    shell: Any,
    *,
    domain: str,
    ca_host: str,
    connect_ip: str,
    spn_fqdn: str,
    kdc_ip: str | None,
    directory_roles: Mapping[str, Any] | None = None,
    host_domain: str | None = None,
    target_kdc_ip: str | None = None,
) -> Esc12Credential | None:
    """Return a PROVEN local-admin credential for the CA host, or ``None``.

    The gate is the credential SSOT
    :func:`~adscan_internal.services.credentials.pick_credential_for_local_admin`:
    Domain Admin / Enterprise Admin / RID 500, or a verified ``AdminTo`` on
    ``ca_host`` in the attack graph. Nothing else qualifies, so no read is ever
    attempted with a credential that is not known to administer the CA host.

    ``directory_roles`` carries the administrative roles the caller derived from
    directory membership it already collected (the collector, before the graph
    exists); it is forwarded to the picker as one more evidence source.

    ``domain`` is the credential's domain (where it is stored and whose KDC,
    ``kdc_ip``, mints its TGT); ``host_domain`` is the domain that owns the CA
    host (default ``domain``) and ``target_kdc_ip`` its DC. When the two differ
    the session follows the cross-realm referral instead of presenting the
    referral TGT to the CA host (``ca_host_access.ca_host_smb_realms``).

    Kerberos material for the chosen principal is minted through
    ``ensure_user_ccache`` (never an ambient ticket). The password / hash is
    kept as the posture-pruned NTLM leg. Sync: it may drive its own event loop,
    so an async caller runs it through ``run_sync_off_loop``.
    """
    if shell is None or not ca_host:
        return None
    try:
        from adscan_internal.services.credentials import (  # noqa: PLC0415
            CredentialKind,
            pick_credential_for_local_admin,
        )

        picked = pick_credential_for_local_admin(
            shell, domain=domain, target_host=ca_host, directory_roles=directory_roles
        )
        if picked is None and spn_fqdn and spn_fqdn != ca_host:
            picked = pick_credential_for_local_admin(
                shell, domain=domain, target_host=spn_fqdn, directory_roles=directory_roles
            )
        if picked is None:
            return None
        username, secret, kind = picked

        password = nt_hash = aes_key = ccache_path = None
        if kind is CredentialKind.PASSWORD:
            password = secret
        elif kind is CredentialKind.NT_HASH:
            nt_hash = secret
        elif kind in (CredentialKind.AES256_KEY, CredentialKind.AES128_KEY):
            aes_key = secret
        elif kind is CredentialKind.CCACHE_PATH:
            ccache_path = secret

        if ccache_path is None and (password or nt_hash):
            try:
                from adscan_internal.services.kerberos_ticket_service import (  # noqa: PLC0415
                    ensure_user_ccache,
                )

                ccache_path = ensure_user_ccache(
                    shell,
                    user=username,
                    domain=domain,
                    credential=password or nt_hash,
                    dc_ip=kdc_ip,
                )
            except Exception as exc:  # noqa: BLE001 - NTLM leg still available
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                ccache_path = None

        from adscan_internal.services.adcs.ca_host_access import (  # noqa: PLC0415
            ca_host_smb_realms,
        )
        from adscan_internal.services.domain_posture import get_posture  # noqa: PLC0415
        from adscan_internal.services.smb_transport import SMBConfig  # noqa: PLC0415

        realms = ca_host_smb_realms(
            host_domain=host_domain or domain,
            credential_domain=domain,
            auth_kdc=kdc_ip,
            target_kdc=target_kdc_ip,
        )
        try:
            posture_snapshot = get_posture(
                getattr(shell, "domains_data", {}) or {}, domain=realms["domain"] or domain
            )
        except Exception:  # noqa: BLE001 - posture is advisory
            posture_snapshot = None

        config = SMBConfig(
            target_ip=connect_ip or ca_host,
            target_hostname=spn_fqdn or ca_host,
            username=username,
            password=password,
            nt_hash=nt_hash,
            aes_key=aes_key,
            ccache_path=ccache_path,
            use_kerberos=bool(ccache_path or aes_key),
            posture_snapshot=posture_snapshot,
            **realms,
        )
        return Esc12Credential(username=username, smb_config=config)
    except Exception as exc:  # noqa: BLE001 - no credential means not checked
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


async def check_esc12(
    *,
    ca_name: str,
    ca_host: str,
    credential: Esc12Credential | None,
) -> Esc12CheckResult:
    """Run the read-only ESC12 check for one CA with a resolved credential."""
    if not ca_name or not ca_host:
        return not_checked(ca_name, ca_host, REASON_CA_HOST_UNKNOWN)
    if credential is None:
        return not_checked(ca_name, ca_host, REASON_NO_LOCAL_ADMIN)
    reading = await read_esc12_registry(smb_config=credential.smb_config, ca_name=ca_name)
    outcome, reason = classify_esc12_reading(reading)
    result = Esc12CheckResult(
        ca_name=ca_name,
        ca_host=ca_host,
        outcome=outcome,
        reason=reason,
        provider=reading.provider,
        password_key=reading.password_key if outcome == OUTCOME_CONFIRMED else None,
        checked_as=credential.username,
    )
    print_info_debug(
        "adcs esc12 checked: "
        f"ca={mark_sensitive(ca_name, 'hostname')} "
        f"host={mark_sensitive(ca_host, 'hostname')} "
        f"as={mark_sensitive(credential.username, 'user')} "
        f"outcome={outcome} reason={reason}"
    )
    return result


def observe_esc12_result(shell: Any, *, domain: str, result: Esc12CheckResult) -> None:
    """Record the ESC12 observation for one CA (every outcome). Never raises.

    ``confirmed`` is a finding, ``not_applicable`` is a clear reading, and
    ``not_checked`` is ``not_assessed`` with its reason, so an absent ESC12
    finding can never close or read as clear on a CA nobody examined.
    """
    if shell is None:
        return
    try:
        from adscan_core.engagement.observations import Outcome  # noqa: PLC0415
        from adscan_internal.services.engagement.coverage_recorder import (  # noqa: PLC0415
            note_observation,
        )

        if result.outcome == OUTCOME_CONFIRMED:
            outcome = Outcome.FINDING
        elif result.outcome == OUTCOME_NOT_APPLICABLE:
            outcome = Outcome.CLEAR
        else:
            outcome = Outcome.NOT_ASSESSED
        ran = outcome is not Outcome.NOT_ASSESSED
        note_observation(
            shell,
            ESC12_CHECK_ID,
            outcome,
            domain=domain,
            scope_kind="host",
            complete=ran,
            examined=1 if ran else 0,
            total=1,
            reason="" if outcome is Outcome.FINDING else result.reason,
        )
    except Exception as exc:  # noqa: BLE001 - coverage never breaks collection
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


__all__ = [
    "CA_CSP_KEY_TEMPLATE",
    "CA_CSP_PROVIDER_VALUE",
    "ESC12_CHECK_ID",
    "ESC12_FINDING_KEY",
    "ESC12_RELATION",
    "Esc12CheckResult",
    "Esc12Credential",
    "Esc12RegistryReading",
    "OUTCOME_CONFIRMED",
    "OUTCOME_NOT_APPLICABLE",
    "OUTCOME_NOT_CHECKED",
    "YUBIHSM_KSP_KEYS",
    "YUBIHSM_KSP_NAME",
    "YUBIHSM_PASSWORD_VALUE",
    "check_esc12",
    "classify_esc12_reading",
    "classify_registry_error",
    "not_checked",
    "observe_esc12_result",
    "provider_is_yubihsm",
    "read_esc12_registry",
    "resolve_esc12_credential",
    "stored_password_present",
]
