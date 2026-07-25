"""Domain-scope writable-attribute discovery backed by LDAP ACL parsing.

This service discovers attribute-specific write permissions that the standard
BloodHound collectors do not model with enough granularity. Unlike actor-scoped
CLI helpers such as ``bloodyAD get writable --detail``, this collector runs once
per domain and inspects every user object's security descriptor so Phase 2 can
materialize attack steps for all enabled low-privileged users.

Current scope:
- user objects only
- ``scriptPath`` -> ``WriteLogonScript`` relation
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from adscan_internal import telemetry
from adscan_internal.rich_output import print_info_debug, print_warning_debug
from adscan_internal.services.base_service import BaseService
from adscan_internal.services.ldap_transport_service import (
    ADscanLDAPConnection,
    SD_FLAGS_DACL_CONTROL,
    execute_with_ldap_fallback,
)
from adscan_core.rich_output import print_exception

_ADS_RIGHT_DS_WRITE_PROP = 0x20
_ACCESS_ALLOWED_ACE_TYPE = 0x00
_ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05


class DomainWritableAttributeDetectionService(BaseService):
    """Collect domain-wide attribute-write findings from LDAP security descriptors."""

    def _load_modules(self) -> dict[str, Any]:
        """Load native ACL parsing helpers lazily."""
        return {
            "SecurityDescriptorParser": _NativeSecurityDescriptorParser,
            "AccessMask": _NativeAccessMask,
            "bytes_to_sid": _sid_bytes_to_str,
        }

    def build_user_attribute_write_report(
        self,
        *,
        target_domain: str,
        dc_address: str,
        kerberos_target_hostname: str | None = None,
        username: str | None = None,
        password: str | None = None,
        use_kerberos: bool = False,
        use_ldaps: bool = True,
    ) -> dict[str, Any] | None:
        """Build a domain-wide report of writable user attributes."""
        modules = self._load_modules()

        try:
            def _collect(connection: ADscanLDAPConnection) -> dict[str, Any] | None:
                script_path_guid = self._resolve_attribute_schema_guid(
                    connection=connection,
                    attribute_name="scriptPath",
                )
                if not script_path_guid:
                    self.logger.warning(
                        "Could not resolve scriptPath schema GUID; skipping domain-wide writable-attribute detection"
                    )
                    return None

                findings = self._collect_script_path_writers(
                    connection=connection,
                    security_descriptor_parser_cls=modules["SecurityDescriptorParser"],
                    access_mask_cls=modules["AccessMask"],
                    bytes_to_sid=modules["bytes_to_sid"],
                    script_path_guid=script_path_guid,
                )
                return {
                    "schema_version": "writable-attributes-domain-1.0",
                    "detector": "ldap_acl",
                    "domain": target_domain,
                    "attribute_guids": {"scriptPath": script_path_guid},
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "findings": findings,
                }

            report, _used_ldaps = execute_with_ldap_fallback(
                operation_name="Domain writable-attribute detection",
                target_domain=target_domain,
                dc_address=dc_address,
                callback=_collect,
                username=username,
                password=password,
                use_kerberos=use_kerberos,
                prefer_ldaps=use_ldaps,
                kerberos_target_hostname=kerberos_target_hostname,
                allow_password_fallback_on_kerberos_failure=bool(
                    str(username or "").strip() and str(password or "").strip()
                ),
            )
            return report
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_warning_debug(
                "Domain writable-attribute detection report generation failed: "
                f"{type(exc).__name__}: {exc}"
            )
            return None

    def _resolve_attribute_schema_guid(
        self,
        *,
        connection: ADscanLDAPConnection,
        attribute_name: str,
        base_scope: str | None = None,
        subtree_scope: str = "SUBTREE",
    ) -> str | None:
        """Resolve one schema attribute GUID by ``lDAPDisplayName``."""
        _ = base_scope
        try:
            schema_naming_context = f"CN=Schema,{_get_config_dn(connection)}"
            connection.search(
                search_base=schema_naming_context,
                search_filter=f"(&(objectClass=attributeSchema)(lDAPDisplayName={attribute_name}))",
                attributes=["lDAPDisplayName", "schemaIDGUID"],
                search_scope=subtree_scope,
            )
            entries = _get_connection_entries(connection)
            if not entries:
                return None
            raw_guid = entries[0].entry_raw_attributes.get("schemaIDGUID", [None])[0]
            if not raw_guid:
                return None
            return str(UUID(bytes_le=raw_guid)).lower()
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(
                f"[writable-attrs] Failed to resolve schema GUID for {attribute_name}: "
                f"{type(exc).__name__}: {exc}"
            )
            return None

    def _collect_script_path_writers(
        self,
        *,
        connection: ADscanLDAPConnection,
        security_descriptor_parser_cls: type[Any],
        access_mask_cls: Any,
        bytes_to_sid: Any,
        script_path_guid: str,
        subtree_scope: str = "SUBTREE",
    ) -> list[dict[str, Any]]:
        """Collect ``WriteLogonScript`` findings from all domain user objects."""
        connection.search(
            search_base=_get_domain_dn(connection),
            search_filter="(&(objectCategory=person)(objectClass=user))",
            attributes=[
                "distinguishedName",
                "sAMAccountName",
                "objectSid",
                "userAccountControl",
                "nTSecurityDescriptor",
            ],
            search_scope=subtree_scope,
            controls=SD_FLAGS_DACL_CONTROL,
        )

        findings: list[dict[str, Any]] = []
        for entry in _get_connection_entries(connection):
            target_username = str(entry["sAMAccountName"].value or "").strip()
            target_dn = str(entry["distinguishedName"].value or "").strip()
            if not target_username or not target_dn:
                continue

            raw_sd = entry.entry_raw_attributes.get("nTSecurityDescriptor", [None])[0]
            if not raw_sd:
                continue
            raw_sid = entry.entry_raw_attributes.get("objectSid", [None])[0]
            target_object_id = bytes_to_sid(raw_sid) if raw_sid else ""
            try:
                target_uac = int(entry["userAccountControl"].value or 0)
            except (TypeError, ValueError):
                target_uac = 0

            parser = security_descriptor_parser_cls(raw_sd)
            sd = parser.parse()
            dacl = getattr(sd, "dacl", None)
            if not dacl or not isinstance(getattr(dacl, "aces", None), list):
                continue

            for ace in dacl.aces:
                if not getattr(ace, "is_allow", False):
                    continue
                access_mask = int(getattr(ace, "access_mask", 0) or 0)
                if not (access_mask & int(access_mask_cls.DS_WRITE_PROPERTY)):
                    continue

                object_type = str(getattr(ace, "object_type", "") or "").strip().lower()
                applies_to_all_properties = not object_type
                if not applies_to_all_properties and object_type != script_path_guid:
                    continue

                principal_sid = str(getattr(ace, "sid", "") or "").strip()
                if not principal_sid:
                    continue

                findings.append(
                    {
                        "relation": "WriteLogonScript",
                        "attribute": "scriptPath",
                        "target_dn": target_dn,
                        "target_username": target_username,
                        "target_object_id": target_object_id,
                        "target_user_account_control": target_uac,
                        "principal_sid": principal_sid,
                        "ace_object_type": object_type or None,
                        "applies_to_all_properties": applies_to_all_properties,
                        "is_inherited": bool(getattr(ace, "is_inherited", False)),
                    }
                )
        return findings


class _NativeAccessMask:
    """Minimal access-mask namespace used by writable-attribute detection."""

    DS_WRITE_PROPERTY = _ADS_RIGHT_DS_WRITE_PROP


class _NativeAce:
    """Normalized allow ACE extracted from a Windows security descriptor."""

    def __init__(
        self,
        *,
        sid: str,
        access_mask: int,
        object_type: str | None,
        is_inherited: bool,
        is_allow: bool,
    ) -> None:
        self.sid = sid
        self.access_mask = access_mask
        self.object_type = object_type
        self.is_inherited = is_inherited
        self.is_allow = is_allow


class _NativeSecurityDescriptorParser:
    """Small winacl-backed parser compatible with the legacy parser surface."""

    def __init__(self, raw_sd: bytes) -> None:
        self.raw_sd = raw_sd

    def parse(self) -> Any:
        """Parse raw security descriptor bytes into an object with ``dacl.aces``."""
        try:
            from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR  # type: ignore
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError("winacl is required for native ACL parsing") from exc

        sd = SECURITY_DESCRIPTOR.from_bytes(self.raw_sd)
        dacl = getattr(sd, "Dacl", None)
        raw_aces = getattr(dacl, "aces", []) if dacl else []
        normalized_aces: list[_NativeAce] = []
        for ace in raw_aces or []:
            ace_type = _ace_type(ace)
            if ace_type not in (_ACCESS_ALLOWED_ACE_TYPE, _ACCESS_ALLOWED_OBJECT_ACE_TYPE):
                continue
            trustee = _ace_sid(ace)
            access_mask = _ace_mask(ace)
            if not trustee or access_mask is None:
                continue
            normalized_aces.append(
                _NativeAce(
                    sid=trustee,
                    access_mask=access_mask,
                    object_type=_ace_object_type_guid(ace),
                    is_inherited=_ace_is_inherited(ace),
                    is_allow=True,
                )
            )
        return type("_ParsedSecurityDescriptor", (), {"dacl": type("_Dacl", (), {"aces": normalized_aces})()})()


def _get_connection_entries(connection: Any) -> list[Any]:
    """Return LDAP entries across ADscan connection wrappers and test doubles."""
    entries = getattr(connection, "entries", None)
    if entries is not None:
        return list(entries)
    nested_connection = getattr(connection, "connection", None)
    nested_entries = getattr(nested_connection, "entries", None)
    if nested_entries is not None:
        return list(nested_entries)
    return []


def _get_domain_dn(connection: Any) -> str:
    """Return domain DN across ADscan connection wrappers and test doubles."""
    domain_dn = getattr(connection, "domain_dn", None)
    if domain_dn:
        return str(domain_dn)
    config = getattr(connection, "config", None)
    config_domain_dn = getattr(config, "domain_dn", None)
    return str(config_domain_dn or "")


def _get_config_dn(connection: Any) -> str:
    """Return configuration DN across ADscan connection wrappers and test doubles."""
    config_dn = getattr(connection, "config_dn", None)
    if config_dn:
        return str(config_dn)
    config = getattr(connection, "config", None)
    nested_config_dn = getattr(config, "config_dn", None)
    return str(nested_config_dn or "")


def _sid_bytes_to_str(value: bytes | bytearray | memoryview | None) -> str:
    """Convert binary SID bytes to canonical SID text."""
    if not value:
        return ""
    raw = bytes(value)
    if len(raw) < 8:
        return ""
    revision = raw[0]
    sub_authority_count = raw[1]
    authority = int.from_bytes(raw[2:8], byteorder="big")
    expected_len = 8 + (sub_authority_count * 4)
    if len(raw) < expected_len:
        return ""
    sub_authorities = [
        str(int.from_bytes(raw[8 + (idx * 4) : 12 + (idx * 4)], byteorder="little"))
        for idx in range(sub_authority_count)
    ]
    return "-".join([f"S-{revision}", str(authority), *sub_authorities])


def _ace_type(ace: Any) -> int | None:
    raw_type = getattr(ace, "AceType", None)
    value = getattr(raw_type, "value", raw_type)
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _ace_mask(ace: Any) -> int | None:
    raw_mask = getattr(ace, "Mask", None)
    if isinstance(raw_mask, int):
        return raw_mask
    nested_mask = getattr(raw_mask, "Mask", None)
    if isinstance(nested_mask, int):
        return nested_mask
    try:
        return int(raw_mask)
    except (TypeError, ValueError):
        return None


def _ace_sid(ace: Any) -> str:
    try:
        return str(getattr(ace, "Sid", "") or "").strip()
    except Exception:
        return ""


def _ace_object_type_guid(ace: Any) -> str | None:
    try:
        raw = getattr(ace, "ObjectType", None)
    except Exception:
        return None
    if not raw:
        return None
    try:
        if isinstance(raw, bytes):
            return str(UUID(bytes_le=raw)).lower()
        return str(raw).lower()
    except Exception:
        return None


def _ace_is_inherited(ace: Any) -> bool:
    raw_flags = getattr(ace, "AceFlags", 0)
    value = getattr(raw_flags, "value", raw_flags)
    try:
        return bool(int(value) & 0x10)
    except (TypeError, ValueError):
        return False
