"""Writable-attribute attack-step discovery via native LDAP.

This service collects effective per-attribute write permissions that
BloodHound CE collectors do not currently model.  The output is normalized
into an ADscan-native report that the Phase 2 attack-graph pipeline can
consume.

The native implementation issues an LDAP search with the SD flags control
(OWNER+GROUP+DACL = 7) against the domain NC, requesting
``allowedAttributesEffective`` and ``sDRightsEffective``.  AD computes these
computed attributes on the fly and returns only the attributes the
authenticated principal can write.

Current scope:
- user objects only (``sAMAccountType=805306368``)
- ``scriptPath`` -> ``WriteLogonScript`` relation
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from adscan_core.rich_output import print_info_debug, print_warning_debug
from adscan_internal import telemetry
from adscan_internal.services.base_service import BaseService
from adscan_internal.services.ldap_transport_service import (
    ADscanLDAPConnection,
    SD_FLAGS_ALL_CONTROL,
    build_show_deleted_controls,
    execute_with_ldap_fallback,
)


_SAFE_TOKEN_RE = re.compile(r"[^a-zA-Z0-9_.-]+")

_USER_ATTRIBUTE_RELATION_MAP: dict[str, dict[str, str]] = {
    "scriptpath": {
        "relation": "WriteLogonScript",
        "attribute": "scriptPath",
    },
}

# LDAP filter for user objects (sAMAccountType=805306368, excluding deleted)
_USER_ONLY_FILTER = "(&(sAMAccountType=805306368)(!(isDeleted=TRUE)))"


@dataclass(frozen=True, slots=True)
class WritableObjectBlock:
    """One writable-attributes result block for a single object."""

    distinguished_name: str
    writable_attributes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RestorableTombstone:
    """One deleted (tombstoned) object the authenticated principal can reanimate.

    ``live_dn`` is where the object would be restored
    (``CN=<last_known_rdn>,<last_known_parent>``). Neither ADscan's other collectors
    nor BloodHound enumerate the Recycle Bin, so this is the only point that surfaces
    a restore→foothold path (the HTB-Checkpoint first move).
    """

    deleted_dn: str
    sam_account_name: str
    last_known_rdn: str
    last_known_parent: str
    live_dn: str
    writable_attributes: tuple[str, ...]
    object_sid: str = ""


def sanitize_report_username(value: str) -> str:
    """Return a stable filename-safe token for one username."""
    cleaned = _SAFE_TOKEN_RE.sub("_", str(value or "").strip())
    cleaned = cleaned.strip("._")
    return cleaned or "user"


def parse_bloodyad_writable_detail_output(output: str) -> list[WritableObjectBlock]:
    """Parse ``bloodyAD get writable --detail`` text output into object blocks.

    Kept for backwards compatibility with any callers that still pass raw CLI
    text.  New code should use native LDAP collection directly.
    """
    from adscan_core.text_utils import normalize_cli_output

    normalized = normalize_cli_output(output or "")
    if not normalized.strip():
        return []

    blocks: list[WritableObjectBlock] = []
    current_dn = ""
    current_attrs: list[str] = []

    def flush_current() -> None:
        nonlocal current_dn, current_attrs
        if current_dn:
            blocks.append(
                WritableObjectBlock(
                    distinguished_name=current_dn,
                    writable_attributes=tuple(current_attrs),
                )
            )
        current_dn = ""
        current_attrs = []

    for raw_line in normalized.splitlines():
        line = str(raw_line or "").strip()
        if not line:
            flush_current()
            continue
        if line.startswith("distinguishedName:"):
            flush_current()
            current_dn = line.split(":", 1)[1].strip()
            continue
        if not current_dn or ":" not in line:
            continue
        key, value = line.split(":", 1)
        if value.strip().upper() != "WRITE":
            continue
        attribute_name = key.strip()
        if attribute_name:
            current_attrs.append(attribute_name)

    flush_current()
    return blocks


def parse_bloodyad_object_output(output: str) -> dict[str, str]:
    """Parse ``bloodyAD get object`` key/value output.

    Kept for backwards compatibility.
    """
    from adscan_core.text_utils import normalize_cli_output

    normalized = normalize_cli_output(output or "")
    if not normalized.strip():
        return {}

    values: dict[str, str] = {}
    for raw_line in normalized.splitlines():
        line = str(raw_line or "").strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key_clean = key.strip()
        value_clean = value.strip()
        if key_clean and value_clean and key_clean not in values:
            values[key_clean] = value_clean
    return values


class WritableAttributeDiscoveryService(BaseService):
    """Discover custom writable-attribute attack steps via native LDAP."""

    def build_user_attribute_write_report(
        self,
        *,
        bloodyad_path: str,
        dc_address: str,
        target_domain: str,
        auth_domain: str,
        auth_username: str,
        auth_password: str,
        kerberos: bool,
        run_command: Callable[[str, int | None], subprocess.CompletedProcess[str]],
        timeout: int = 600,
    ) -> dict[str, Any] | None:
        """Collect writable user attributes and return a normalized report.

        ``bloodyad_path`` and ``run_command`` are accepted for backwards
        compatibility but ignored — the collection is done via native LDAP.
        """
        _ = bloodyad_path
        _ = run_command

        self.logger.debug(
            "Collecting writable user attributes via native LDAP",
            extra={
                "domain": target_domain,
                "auth_domain": auth_domain,
                "auth_username": auth_username,
                "kerberos": kerberos,
            },
        )

        try:
            def _collect(connection: ADscanLDAPConnection) -> list[WritableObjectBlock]:
                return _collect_writable_user_objects(connection)

            writable_blocks, _used_ldaps = execute_with_ldap_fallback(
                operation_name="Writable-attribute discovery",
                target_domain=target_domain,
                dc_address=dc_address,
                callback=_collect,
                username=auth_username,
                password=auth_password,
                use_kerberos=kerberos,
                prefer_ldaps=True,
                allow_password_fallback_on_kerberos_failure=bool(
                    str(auth_username or "").strip() and str(auth_password or "").strip()
                ),
                auth_domain=auth_domain if auth_domain != target_domain else None,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning_debug(
                f"[writable-attrs] Native LDAP collection failed: "
                f"{type(exc).__name__}: {exc}"
            )
            return None

        if not writable_blocks:
            return {
                "schema_version": "writable-attributes-1.0",
                "detector": "native_ldap",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "actor_username": auth_username,
                "actor_domain": auth_domain,
                "findings": [],
            }

        findings: list[dict[str, Any]] = []
        for block in writable_blocks:
            supported_attributes: list[dict[str, str]] = []
            for attribute_name in block.writable_attributes:
                mapped = _USER_ATTRIBUTE_RELATION_MAP.get(attribute_name.strip().lower())
                if mapped:
                    supported_attributes.append(mapped)
            if not supported_attributes:
                continue

            target_details = self._resolve_target_object(
                dc_address=dc_address,
                target_domain=target_domain,
                auth_username=auth_username,
                auth_password=auth_password,
                kerberos=kerberos,
                auth_domain=auth_domain,
                target_dn=block.distinguished_name,
                timeout=max(60, min(timeout, 180)),
            )
            if not target_details:
                continue

            target_username = str(target_details.get("sAMAccountName") or "").strip()
            target_object_id = str(target_details.get("objectSid") or "").strip()
            if not target_username:
                continue

            for mapped in supported_attributes:
                findings.append(
                    {
                        "relation": mapped["relation"],
                        "attribute": mapped["attribute"],
                        "target_dn": block.distinguished_name,
                        "target_username": target_username,
                        "target_object_id": target_object_id,
                        "raw_writable_attributes": list(block.writable_attributes),
                    }
                )

        return {
            "schema_version": "writable-attributes-1.0",
            "detector": "native_ldap",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "actor_username": auth_username,
            "actor_domain": auth_domain,
            "findings": findings,
        }

    def build_restorable_tombstone_report(
        self,
        *,
        dc_address: str,
        target_domain: str,
        auth_domain: str,
        auth_username: str,
        auth_password: str,
        kerberos: bool,
    ) -> dict[str, Any] | None:
        """Discover deleted accounts the principal can reanimate (Recycle Bin).

        Returns a normalized report whose findings carry relation
        ``CanRestoreDeletedObject`` — each a restore→foothold attack step the
        graph/execution layer can chain (restore → re-evaluate lifecycle → enable if
        disabled → run the technique the right allows).
        """
        try:
            tombstones, _used_ldaps = execute_with_ldap_fallback(
                operation_name="Restorable-tombstone discovery",
                target_domain=target_domain,
                dc_address=dc_address,
                callback=_collect_restorable_tombstones,
                username=auth_username,
                password=auth_password,
                use_kerberos=kerberos,
                prefer_ldaps=True,
                allow_password_fallback_on_kerberos_failure=bool(
                    str(auth_username or "").strip() and str(auth_password or "").strip()
                ),
                auth_domain=auth_domain if auth_domain != target_domain else None,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning_debug(
                f"[tombstones] Native LDAP collection failed: {type(exc).__name__}: {exc}"
            )
            return None

        findings = [
            {
                "relation": "CanRestoreDeletedObject",
                "deleted_dn": tombstone.deleted_dn,
                "restored_dn": tombstone.live_dn,
                "target_username": tombstone.sam_account_name,
                "target_object_id": tombstone.object_sid,
                "last_known_rdn": tombstone.last_known_rdn,
                "last_known_parent": tombstone.last_known_parent,
                "raw_writable_attributes": list(tombstone.writable_attributes),
            }
            for tombstone in (tombstones or [])
        ]
        return {
            "schema_version": "restorable-tombstones-1.0",
            "detector": "native_ldap",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "actor_username": auth_username,
            "actor_domain": auth_domain,
            "findings": findings,
        }

    def _resolve_target_object(
        self,
        *,
        dc_address: str,
        target_domain: str,
        auth_username: str,
        auth_password: str,
        kerberos: bool,
        auth_domain: str,
        target_dn: str,
        timeout: int,
    ) -> dict[str, str]:
        """Resolve one writable DN into identity metadata via native LDAP."""
        _ = timeout  # connection-level timeout is managed by the transport layer

        try:
            def _lookup(connection: ADscanLDAPConnection) -> dict[str, str]:
                return _fetch_object_identity(connection, target_dn)

            result, _used_ldaps = execute_with_ldap_fallback(
                operation_name="Writable-attribute target lookup",
                target_domain=target_domain,
                dc_address=dc_address,
                callback=_lookup,
                username=auth_username,
                password=auth_password,
                use_kerberos=kerberos,
                prefer_ldaps=True,
                auth_domain=auth_domain if auth_domain != target_domain else None,
            )
            return result or {}
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[writable-attrs] Target resolution failed for dn={target_dn}: "
                f"{type(exc).__name__}: {exc}"
            )
            return {}


# ---------------------------------------------------------------------------
# Internal LDAP helpers — module-level so they are easily unit-testable
# ---------------------------------------------------------------------------


def _collect_writable_user_objects(
    connection: ADscanLDAPConnection,
) -> list[WritableObjectBlock]:
    """Search domain NC for user objects and return those with writable attributes.

    Uses the SD flags control (OWNER+GROUP+DACL=7) so that AD computes
    ``allowedAttributesEffective`` and ``sDRightsEffective`` for the
    authenticated principal.
    """
    domain_dn = _get_domain_dn(connection)
    if not domain_dn:
        print_warning_debug("[writable-attrs] Could not determine domain DN; skipping search")
        return []

    connection.search(
        search_base=domain_dn,
        search_filter=_USER_ONLY_FILTER,
        attributes=[
            "distinguishedName",
            "sAMAccountName",
            "objectSid",
            "allowedAttributesEffective",
            "sDRightsEffective",
        ],
        search_scope="SUBTREE",
        controls=SD_FLAGS_ALL_CONTROL,
    )

    blocks: list[WritableObjectBlock] = []
    for entry in _get_connection_entries(connection):
        dn = str(entry.dn or "").strip()
        if not dn:
            # Fall back to distinguishedName attribute if dn field is empty
            dn_vals = entry._raw_attrs.get("distinguishedName") or []
            dn = _decode_first(dn_vals)
        if not dn:
            continue

        writable_attrs = _extract_string_list(
            entry._raw_attrs.get("allowedAttributesEffective") or []
        )
        if not writable_attrs:
            continue

        blocks.append(
            WritableObjectBlock(
                distinguished_name=dn,
                writable_attributes=tuple(writable_attrs),
            )
        )

    return blocks


def _collect_restorable_tombstones(
    connection: ADscanLDAPConnection,
) -> list[RestorableTombstone]:
    """Enumerate deleted account objects the principal can reanimate.

    Searches ``CN=Deleted Objects`` with the Show Deleted Objects + SD_FLAGS_ALL
    controls so AD returns each tombstone's ``allowedAttributesEffective`` /
    ``sDRightsEffective``. A tombstone is restorable when the principal can write its
    attributes (GenericWrite/GenericAll surface a non-empty effective set — the same
    "WRITE" bloodyAD reports) or owns it / can rewrite its DACL.
    """
    domain_dn = _get_domain_dn(connection)
    if not domain_dn:
        print_warning_debug("[tombstones] Could not determine domain DN; skipping search")
        return []

    connection.search(
        search_base=f"CN=Deleted Objects,{domain_dn}",
        search_filter="(&(isDeleted=TRUE)(objectClass=user))",
        attributes=[
            "distinguishedName",
            "sAMAccountName",
            "msDS-LastKnownRDN",
            "lastKnownParent",
            "objectSid",
            "allowedAttributesEffective",
            "sDRightsEffective",
        ],
        search_scope="SUBTREE",
        controls=build_show_deleted_controls(with_sd_flags=True),
    )

    tombstones: list[RestorableTombstone] = []
    for entry in _get_connection_entries(connection):
        attrs = entry._raw_attrs
        writable_attrs = _extract_string_list(attrs.get("allowedAttributesEffective") or [])
        try:
            sd_rights = int(_decode_first(attrs.get("sDRightsEffective") or []) or "0")
        except (TypeError, ValueError):
            sd_rights = 0
        # Precise reanimation gate (validated against a real GenericWrite ACE: AD does
        # surface isDeleted + distinguishedName in allowedAttributesEffective when
        # writable): can write the lifecycle attributes the restore modify touches, OR
        # owns it / can rewrite its DACL (sDRightsEffective OWNER 0x01 | DACL 0x04 →
        # self-grant). Avoids flagging a harmless WriteProperty on an unrelated attr.
        writable_lower = {attr.casefold() for attr in writable_attrs}
        can_reanimate = bool(writable_lower & {"isdeleted", "distinguishedname"})
        can_own_or_write_dacl = bool(sd_rights & 0x05)
        if not can_reanimate and not can_own_or_write_dacl:
            continue

        deleted_dn = str(entry.dn or "").strip() or _decode_first(
            attrs.get("distinguishedName") or []
        )
        rdn = _decode_first(attrs.get("msDS-LastKnownRDN") or [])
        parent = _decode_first(attrs.get("lastKnownParent") or [])
        live_dn = f"CN={rdn},{parent}" if rdn and parent else ""
        tombstones.append(
            RestorableTombstone(
                deleted_dn=deleted_dn,
                sam_account_name=_decode_first(attrs.get("sAMAccountName") or []),
                last_known_rdn=rdn,
                last_known_parent=parent,
                live_dn=live_dn,
                writable_attributes=tuple(writable_attrs),
                object_sid=_sid_bytes_to_str(
                    (attrs.get("objectSid") or [None])[0]
                    if isinstance(attrs.get("objectSid"), list)
                    else attrs.get("objectSid")
                ),
            )
        )

    return tombstones


def _fetch_object_identity(
    connection: ADscanLDAPConnection,
    target_dn: str,
) -> dict[str, str]:
    """Fetch sAMAccountName and objectSid for one DN."""
    connection.search(
        search_base=target_dn,
        search_filter="(objectClass=*)",
        attributes=["distinguishedName", "sAMAccountName", "objectSid", "objectClass"],
        search_scope="BASE",
    )
    entries = _get_connection_entries(connection)
    if not entries:
        return {}

    entry = entries[0]
    result: dict[str, str] = {}

    sam_vals = entry._raw_attrs.get("sAMAccountName") or []
    sam = _decode_first(sam_vals)
    if sam:
        result["sAMAccountName"] = sam

    sid_vals = entry._raw_attrs.get("objectSid") or []
    if sid_vals:
        raw_sid = sid_vals[0]
        if isinstance(raw_sid, bytes):
            result["objectSid"] = _sid_bytes_to_str(raw_sid)
        else:
            result["objectSid"] = str(raw_sid)

    class_vals = entry._raw_attrs.get("objectClass") or []
    classes = _extract_string_list(class_vals)
    if classes:
        result["objectClass"] = ",".join(classes)

    return result


# ---------------------------------------------------------------------------
# Low-level attribute helpers
# ---------------------------------------------------------------------------


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


def _decode_first(values: list[Any]) -> str:
    """Decode the first value in a raw attribute list to a string."""
    if not values:
        return ""
    val = values[0]
    if isinstance(val, bytes):
        try:
            return val.decode("utf-8")
        except UnicodeDecodeError:
            return ""
    return str(val or "").strip()


def _extract_string_list(values: list[Any]) -> list[str]:
    """Decode a list of raw attribute bytes/strings to a list of strings."""
    result: list[str] = []
    for val in values or []:
        if isinstance(val, bytes):
            try:
                decoded = val.decode("utf-8").strip()
            except UnicodeDecodeError:
                continue
        else:
            decoded = str(val or "").strip()
        if decoded:
            result.append(decoded)
    return result


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


__all__ = [
    "WritableAttributeDiscoveryService",
    "WritableObjectBlock",
    "parse_bloodyad_object_output",
    "parse_bloodyad_writable_detail_output",
    "sanitize_report_username",
]
