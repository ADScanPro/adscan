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
from adscan_internal.services.ldap_transport_service import execute_with_ldap_fallback


class DomainWritableAttributeDetectionService(BaseService):
    """Collect domain-wide attribute-write findings from LDAP security descriptors."""

    def _load_modules(self) -> dict[str, Any]:
        """Load LDAP and ACL parsing modules lazily."""
        from certihound.acl.parser import (  # type: ignore  # pylint: disable=import-error
            SecurityDescriptorParser,
        )
        from certihound.acl.rights import AccessMask  # type: ignore  # pylint: disable=import-error
        from certihound.ldap.connection import (  # type: ignore  # pylint: disable=import-error
            LDAPConfig,
            LDAPConnection,
        )
        from certihound.utils.convert import bytes_to_sid  # type: ignore  # pylint: disable=import-error
        from ldap3 import BASE, SUBTREE  # type: ignore

        return {
            "SecurityDescriptorParser": SecurityDescriptorParser,
            "AccessMask": AccessMask,
            "LDAPConfig": LDAPConfig,
            "LDAPConnection": LDAPConnection,
            "bytes_to_sid": bytes_to_sid,
            "BASE": BASE,
            "SUBTREE": SUBTREE,
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
        """Build a domain-wide report of writable user attributes.

        Args:
            target_domain: Target AD domain.
            dc_address: Domain controller address or FQDN.
            username: Username for non-Kerberos auth.
            password: Password for non-Kerberos auth.
            use_kerberos: Whether to use Kerberos auth.
            use_ldaps: Whether to bind over LDAPS.

        Returns:
            Normalized JSON-serializable report or ``None`` on failure.
        """
        modules = self._load_modules()

        try:
            def _collect(connection: Any) -> dict[str, Any] | None:
                script_path_guid = self._resolve_attribute_schema_guid(
                    connection=connection,
                    attribute_name="scriptPath",
                    base_scope=modules["BASE"],
                    subtree_scope=modules["SUBTREE"],
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
                    subtree_scope=modules["SUBTREE"],
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
                config_cls=modules["LDAPConfig"],
                connection_cls=modules["LDAPConnection"],
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
            print_warning_debug(
                "Domain writable-attribute detection report generation failed: "
                f"{type(exc).__name__}: {exc}"
            )
            return None

    def _resolve_attribute_schema_guid(
        self,
        *,
        connection: Any,
        attribute_name: str,
        base_scope: Any,
        subtree_scope: Any,
    ) -> str | None:
        """Resolve one schema attribute GUID by ``lDAPDisplayName``."""
        try:
            _ = base_scope
            config_dn = str(
                getattr(getattr(connection, "config", None), "config_dn", "") or ""
            ).strip()
            schema_naming_context = (
                f"CN=Schema,{config_dn}" if config_dn else ""
            ).strip()
            if not schema_naming_context:
                return None

            connection.search(
                search_base=schema_naming_context,
                search_filter=(
                    f"(&(objectClass=attributeSchema)(lDAPDisplayName={attribute_name}))"
                ),
                attributes=["lDAPDisplayName", "schemaIDGUID"],
                search_scope=subtree_scope,
            )
            entries = getattr(connection.connection, "entries", []) or []
            if not entries:
                return None
            entry = entries[0]
            raw_guid = (
                entry.entry_raw_attributes.get("schemaIDGUID", [None])[0]
                if hasattr(entry, "entry_raw_attributes")
                else None
            )
            if not raw_guid:
                return None
            return str(UUID(bytes_le=raw_guid)).lower()
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[writable-attrs] Failed to resolve schema GUID for {attribute_name}: "
                f"{type(exc).__name__}: {exc}"
            )
            return None

    def _collect_script_path_writers(
        self,
        *,
        connection: Any,
        security_descriptor_parser_cls: type[Any],
        access_mask_cls: Any,
        bytes_to_sid: Any,
        script_path_guid: str,
        subtree_scope: Any,
    ) -> list[dict[str, Any]]:
        """Collect ``WriteLogonScript`` findings from all domain user objects."""
        findings: list[dict[str, Any]] = []
        connection.search(
            search_base=connection.config.domain_dn,
            search_filter="(&(objectCategory=person)(objectClass=user))",
            attributes=[
                "distinguishedName",
                "sAMAccountName",
                "objectSid",
                "userAccountControl",
                "nTSecurityDescriptor",
            ],
            search_scope=subtree_scope,
        )
        entries = getattr(connection.connection, "entries", []) or []
        for entry in entries:
            target_username = str(getattr(entry["sAMAccountName"], "value", "") or "").strip()
            target_dn = str(getattr(entry["distinguishedName"], "value", "") or "").strip()
            if not target_username or not target_dn:
                continue

            raw_sd = (
                entry.entry_raw_attributes.get("nTSecurityDescriptor", [None])[0]
                if hasattr(entry, "entry_raw_attributes")
                else None
            )
            if not raw_sd:
                continue
            raw_sid = (
                entry.entry_raw_attributes.get("objectSid", [None])[0]
                if hasattr(entry, "entry_raw_attributes")
                else None
            )
            target_object_id = bytes_to_sid(raw_sid) if raw_sid else ""
            try:
                target_uac = int(getattr(entry["userAccountControl"], "value", 0) or 0)
            except Exception:
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
