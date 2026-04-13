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
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from adscan_internal import telemetry
from adscan_internal.rich_output import print_info_debug, print_warning_debug
from adscan_internal.services.base_service import BaseService
from adscan_internal.services.ldap_transport_service import execute_with_ldap_fallback


_ADS_RIGHT_DS_WRITE_PROP = 0x20
_SD_FLAGS_DACL = 0x04


@dataclass
class _NativeLDAPConfig:
    """Minimal LDAP connection config compatible with ADscan's fallback helper."""

    domain: str
    dc_ip: str
    use_ldaps: bool
    use_kerberos: bool
    username: str | None = None
    password: str | None = None
    kerberos_target_hostname: str | None = None


class _NativeLDAPConnection:
    """Small ldap3-backed context manager exposing the CertiHound-like API used here."""

    def __init__(self, config: _NativeLDAPConfig) -> None:
        self.config = config
        self.connection: Any | None = None
        self._server: Any | None = None

    def __enter__(self) -> "_NativeLDAPConnection":
        from ldap3 import Server

        self._server = Server(
            self.config.dc_ip,
            use_ssl=bool(self.config.use_ldaps),
            connect_timeout=10,
        )
        self.connection = (
            self._connect_kerberos()
            if bool(self.config.use_kerberos)
            else self._connect_password()
        )
        if not bool(getattr(self.connection, "bound", False)):
            self.connection.bind()
        return self

    def __exit__(self, *_args: Any) -> None:
        if self.connection is not None:
            self.connection.unbind()

    def _connect_kerberos(self) -> Any:
        from ldap3 import Connection, SASL

        target_host = str(
            self.config.kerberos_target_hostname or self.config.dc_ip
        ).strip()
        return Connection(
            self._server,
            authentication=SASL,
            sasl_mechanism="GSSAPI",
            sasl_credentials=(target_host,),
            auto_bind=False,
            receive_timeout=30,
        )

    def _connect_password(self) -> Any:
        from ldap3 import Connection, NTLM

        username = str(self.config.username or "").strip()
        if "\\" not in username and "@" not in username:
            username = f"{self.config.domain}\\{username}"
        return Connection(
            self._server,
            user=username,
            password=str(self.config.password or ""),
            authentication=NTLM,
            auto_bind=False,
            receive_timeout=30,
        )

    def search(self, *args: Any, **kwargs: Any) -> Any:
        """Proxy ldap3 search calls while preserving ``connection.entries``."""
        if self.connection is None:
            raise RuntimeError("LDAP connection is not open")
        return self.connection.search(*args, **kwargs)


class DomainRodcPrpDetectionService(BaseService):
    """Collect domain-wide delegated RODC PRP-write findings from LDAP DACLs."""

    def _load_modules(self) -> dict[str, Any]:
        """Load LDAP and ACL parsing modules lazily."""
        from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
        from ldap3 import SUBTREE
        from ldap3.protocol.microsoft import security_descriptor_control

        return {
            "LDAPConfig": _NativeLDAPConfig,
            "LDAPConnection": _NativeLDAPConnection,
            "SR_SECURITY_DESCRIPTOR": SR_SECURITY_DESCRIPTOR,
            "SUBTREE": SUBTREE,
            "security_descriptor_control": security_descriptor_control,
        }

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
            def _collect(connection: Any) -> dict[str, Any] | None:
                reveal_guid = self._resolve_attribute_schema_guid(
                    connection=connection,
                    modules=modules,
                    target_domain=target_domain,
                    attribute_name="msDS-RevealOnDemandGroup",
                )
                never_guid = self._resolve_attribute_schema_guid(
                    connection=connection,
                    modules=modules,
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
            if not isinstance(report, dict):
                return None
            report["used_ldaps"] = bool(used_ldaps)
            return report
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
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
        connection: Any,
        modules: dict[str, Any],
        target_domain: str,
        attribute_name: str,
    ) -> str | None:
        """Resolve one schema attribute GUID by ``lDAPDisplayName``."""
        try:
            schema_dn = (
                f"CN=Schema,CN=Configuration,{self._derive_base_dn(target_domain)}"
            )
            connection.search(
                schema_dn,
                f"(&(objectClass=attributeSchema)(lDAPDisplayName={attribute_name}))",
                search_scope=modules["SUBTREE"],
                attributes=["schemaIDGUID"],
            )
            entries = getattr(connection.connection, "entries", []) or []
            if not entries:
                return None
            entry = entries[0]
            raw_guid = getattr(entry, "entry_raw_attributes", {}).get("schemaIDGUID", [None])[0]
            if not raw_guid:
                return None
            return str(UUID(bytes_le=raw_guid)).lower()
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[rodc-prp] Failed to resolve schema GUID for {attribute_name}: "
                f"{type(exc).__name__}: {exc}"
            )
            return None

    def _collect_rodc_prp_writers(
        self,
        *,
        connection: Any,
        modules: dict[str, Any],
        target_domain: str,
        reveal_guid: str,
        never_guid: str,
    ) -> list[dict[str, Any]]:
        """Collect ``ManageRODCPrp`` findings from all RODC computer objects."""
        base_dn = self._derive_base_dn(target_domain)
        controls = modules["security_descriptor_control"](sdflags=_SD_FLAGS_DACL)
        connection.search(
            base_dn,
            "(objectClass=computer)",
            search_scope=modules["SUBTREE"],
            attributes=[
                "distinguishedName",
                "sAMAccountName",
                "objectSid",
                "primaryGroupID",
                "msDS-isRODC",
                "nTSecurityDescriptor",
            ],
            controls=controls,
        )

        findings: list[dict[str, Any]] = []
        reveal_guid = reveal_guid.lower()
        never_guid = never_guid.lower()
        entries = getattr(connection.connection, "entries", []) or []
        for entry in entries:
            target_dn = str(getattr(entry["distinguishedName"], "value", "") or "").strip()
            target_machine = str(getattr(entry["sAMAccountName"], "value", "") or "").strip()
            raw_sid = getattr(entry, "entry_raw_attributes", {}).get("objectSid", [None])[0]
            raw_sd = getattr(entry, "entry_raw_attributes", {}).get("nTSecurityDescriptor", [None])[0]
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
            security_descriptor = modules["SR_SECURITY_DESCRIPTOR"](data=raw_sd)
            dacl = security_descriptor["Dacl"]
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
        from impacket.ldap.ldaptypes import LDAP_SID

        try:
            sid = LDAP_SID(data=value)
            return sid.formatCanonical()
        except Exception:
            return None

    def _extract_ace_sid(self, ace: Any) -> str | None:
        """Return the trustee SID from one ACE."""
        try:
            return ace["Ace"]["Sid"].formatCanonical()
        except Exception:
            return None

    def _ace_grants_write_property(self, ace: Any) -> bool:
        """Return True when one ACE includes DS_WRITE_PROPERTY."""
        try:
            mask = int(ace["Ace"]["Mask"]["Mask"] or 0)
        except Exception:
            return False
        return bool(mask & _ADS_RIGHT_DS_WRITE_PROP)

    def _extract_ace_object_type_guid(self, ace: Any) -> str | None:
        """Return the ACE object type GUID when present."""
        try:
            raw_value = ace["Ace"]["ObjectType"]
        except Exception:
            return None
        if not raw_value:
            return None
        try:
            return str(UUID(bytes_le=raw_value)).lower()
        except Exception:
            return None

    def _entry_is_rodc(self, entry: Any) -> bool:
        """Return True when one ldap3 entry represents an RODC computer."""
        try:
            if bool(getattr(entry["msDS-isRODC"], "value", False)):
                return True
        except Exception:
            pass
        try:
            primary_group_id = int(getattr(entry["primaryGroupID"], "value", 0) or 0)
        except Exception:
            primary_group_id = 0
        return primary_group_id == 521
