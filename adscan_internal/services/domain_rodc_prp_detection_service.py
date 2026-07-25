"""Domain-scope RODC PRP-control discovery backed by LDAP ACL parsing.

This detector discovers delegated rights that allow a principal to manage the
password-replication policy (PRP) of a Read-Only Domain Controller (RODC)
computer object. BloodHound CE does not currently emit a dedicated edge for
this capability, so ADscan materializes a custom attack step:

- ``ManageRODCPrp`` -> can modify ``msDS-RevealOnDemandGroup`` and
  ``msDS-NeverRevealGroup`` on the RODC computer object.

The detector is intentionally conservative. It only emits a finding when the
same trustee has write-property rights over both PRP attributes on the same
RODC object. Broader object-control ACLs such as ``GenericAll`` or
``GenericWrite`` are expected to come from native BloodHound edges instead.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from adscan_internal import telemetry
from adscan_internal.rich_output import print_info_debug, print_warning_debug
from adscan_internal.services.base_service import BaseService
from adscan_internal.services.ldap_transport_service import (
    ADscanLDAPConnection,
    LDAPEntry,
    SD_FLAGS_DACL_CONTROL,
    execute_with_ldap_fallback,
)
from adscan_core.rich_output import print_exception


_ADS_RIGHT_DS_WRITE_PROP = 0x20


class DomainRodcPrpDetectionService(BaseService):
    """Collect domain-wide delegated RODC PRP-write findings from LDAP DACLs."""

    def _load_modules(self) -> dict[str, Any]:
        """Load ACL parsing modules lazily."""
        from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR  # type: ignore

        return {"SECURITY_DESCRIPTOR": SECURITY_DESCRIPTOR}

    def build_rodc_prp_write_report(
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
        """Build a domain-wide report of delegated RODC PRP writers."""
        modules = self._load_modules()
        try:
            def _collect(connection: ADscanLDAPConnection) -> dict[str, Any] | None:
                reveal_guid = self._resolve_attribute_schema_guid(
                    connection=connection,
                    target_domain=target_domain,
                    attribute_name="msDS-RevealOnDemandGroup",
                )
                never_guid = self._resolve_attribute_schema_guid(
                    connection=connection,
                    target_domain=target_domain,
                    attribute_name="msDS-NeverRevealGroup",
                )
                if not reveal_guid or not never_guid:
                    self.logger.warning(
                        "Could not resolve RODC PRP schema GUIDs; skipping custom RODC PRP discovery"
                    )
                    return None

                findings = self._collect_rodc_prp_writers(
                    connection=connection,
                    modules=modules,
                    target_domain=target_domain,
                    reveal_guid=reveal_guid,
                    never_guid=never_guid,
                )
                return {
                    "schema_version": "rodc-prp-writers-domain-1.0",
                    "detector": "ldap_rodc_prp_acl",
                    "domain": target_domain,
                    "attribute_guids": {
                        "msDS-RevealOnDemandGroup": reveal_guid,
                        "msDS-NeverRevealGroup": never_guid,
                    },
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "findings": findings,
                }

            report, used_ldaps = execute_with_ldap_fallback(
                operation_name="RODC PRP detection",
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
            if not isinstance(report, dict):
                return None
            report["used_ldaps"] = bool(used_ldaps)
            return report
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_warning_debug(
                f"RODC PRP detection report generation failed: {type(exc).__name__}: {exc}"
            )
            return None

    def _derive_base_dn(self, target_domain: str) -> str:
        """Return a base DN from a DNS domain name."""
        return ",".join(
            f"DC={part}"
            for part in str(target_domain or "").strip().split(".")
            if str(part).strip()
        )

    def _resolve_attribute_schema_guid(
        self,
        *,
        connection: ADscanLDAPConnection,
        target_domain: str,
        attribute_name: str,
    ) -> str | None:
        """Resolve one schema attribute GUID by ``lDAPDisplayName``."""
        try:
            schema_dn = (
                f"CN=Schema,CN=Configuration,{self._derive_base_dn(target_domain)}"
            )
            connection.search(
                search_base=schema_dn,
                search_filter=f"(&(objectClass=attributeSchema)(lDAPDisplayName={attribute_name}))",
                search_scope="SUBTREE",
                attributes=["schemaIDGUID"],
            )
            if not connection.entries:
                return None
            raw_guid = connection.entries[0].entry_raw_attributes.get("schemaIDGUID", [None])[0]
            if not raw_guid:
                return None
            return str(UUID(bytes_le=raw_guid)).lower()
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(
                f"[rodc-prp] Failed to resolve schema GUID for {attribute_name}: "
                f"{type(exc).__name__}: {exc}"
            )
            return None

    def _collect_rodc_prp_writers(
        self,
        *,
        connection: ADscanLDAPConnection,
        modules: dict[str, Any],
        target_domain: str,
        reveal_guid: str,
        never_guid: str,
    ) -> list[dict[str, Any]]:
        """Collect ``ManageRODCPrp`` findings from all RODC computer objects."""
        base_dn = self._derive_base_dn(target_domain)
        connection.search(
            search_base=base_dn,
            search_filter="(objectClass=computer)",
            search_scope="SUBTREE",
            attributes=[
                "distinguishedName",
                "sAMAccountName",
                "objectSid",
                "primaryGroupID",
                "msDS-isRODC",
                "nTSecurityDescriptor",
            ],
            controls=SD_FLAGS_DACL_CONTROL,
        )

        findings: list[dict[str, Any]] = []
        reveal_guid = reveal_guid.lower()
        never_guid = never_guid.lower()
        for entry in connection.entries:
            target_dn = str(entry["distinguishedName"].value or "").strip()
            target_machine = str(entry["sAMAccountName"].value or "").strip()
            raw_sid = entry.entry_raw_attributes.get("objectSid", [None])[0]
            raw_sd = entry.entry_raw_attributes.get("nTSecurityDescriptor", [None])[0]
            if not target_dn or not target_machine or not raw_sid or not raw_sd:
                continue
            if not self._entry_is_rodc(entry):
                continue

            sid_value = self._format_sid_from_bytes(raw_sid)
            if not sid_value:
                continue

            principal_state: dict[str, dict[str, bool]] = defaultdict(
                lambda: {"reveal": False, "never": False}
            )
            security_descriptor = modules["SECURITY_DESCRIPTOR"].from_bytes(raw_sd)
            dacl = getattr(security_descriptor, "Dacl", None)
            for ace in getattr(dacl, "aces", []) or []:
                sid = self._extract_ace_sid(ace)
                if not sid or not self._ace_grants_write_property(ace):
                    continue
                object_type = self._extract_ace_object_type_guid(ace)
                if not object_type:
                    principal_state[sid]["reveal"] = True
                    principal_state[sid]["never"] = True
                    continue
                if object_type == reveal_guid:
                    principal_state[sid]["reveal"] = True
                if object_type == never_guid:
                    principal_state[sid]["never"] = True

            for principal_sid, state in principal_state.items():
                if not (state["reveal"] and state["never"]):
                    continue
                findings.append(
                    {
                        "relation": "ManageRODCPrp",
                        "target_dn": target_dn,
                        "target_machine": target_machine,
                        "target_object_id": sid_value,
                        "principal_sid": principal_sid,
                        "required_attributes": [
                            "msDS-RevealOnDemandGroup",
                            "msDS-NeverRevealGroup",
                        ],
                    }
                )
        return findings

    def _format_sid_from_bytes(self, value: bytes) -> str | None:
        """Return a canonical SID from raw bytes."""
        from winacl.dtyp.sid import SID

        try:
            return str(SID.from_bytes(value))
        except Exception:
            return None

    def _extract_ace_sid(self, ace: Any) -> str | None:
        """Return the trustee SID from one ACE."""
        try:
            return str(getattr(ace, "Sid", "") or "")
        except Exception:
            return None

    def _ace_grants_write_property(self, ace: Any) -> bool:
        """Return True when one ACE includes DS_WRITE_PROPERTY."""
        try:
            mask = int(getattr(getattr(ace, "Mask", None), "Mask", 0) or 0)
        except Exception:
            return False
        return bool(mask & _ADS_RIGHT_DS_WRITE_PROP)

    def _extract_ace_object_type_guid(self, ace: Any) -> str | None:
        """Return the ACE object type GUID when present."""
        try:
            raw_value = getattr(ace, "ObjectType", None)
        except Exception:
            return None
        if not raw_value:
            return None
        try:
            if isinstance(raw_value, bytes):
                return str(UUID(bytes_le=raw_value)).lower()
            return str(raw_value).lower()
        except Exception:
            return None

    def _entry_is_rodc(self, entry: LDAPEntry) -> bool:
        """Return True when one LDAPEntry represents an RODC computer."""
        is_rodc_val = str(entry["msDS-isRODC"].value or "").strip().lower()
        if is_rodc_val in ("true", "1", "yes"):
            return True
        try:
            return int(entry["primaryGroupID"].value or 0) == 521  # RODC group RID
        except (TypeError, ValueError):
            return False
