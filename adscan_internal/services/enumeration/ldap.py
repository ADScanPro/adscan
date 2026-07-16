"""LDAP enumeration mixin.

This module provides LDAP-specific enumeration operations including
user enumeration, group enumeration, and computer enumeration.
"""

from collections.abc import Callable
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
import asyncio
import subprocess

from adscan_internal.core import AuthMode
from adscan_internal.command_runner import CommandSpec, default_runner
from adscan_internal.subprocess_env import (
    command_string_needs_clean_env,
    get_clean_env_for_compilation,
)


CommandExecutor = Callable[[str, int], subprocess.CompletedProcess[str]]


def _default_executor(command: str, timeout: int) -> subprocess.CompletedProcess[str]:
    """Execute a command using the shared command runner.

    Args:
        command: Command string to execute.
        timeout: Timeout in seconds.

    Returns:
        Completed process result.
    """
    use_clean_env = command_string_needs_clean_env(command)
    cmd_env = get_clean_env_for_compilation() if use_clean_env else None
    return default_runner.run(
        CommandSpec(
            command=command,
            timeout=timeout,
            shell=True,
            capture_output=True,
            text=True,
            check=False,
            env=cmd_env,
        )
    )


def _native_anonymous_user_inventory(
    *,
    pdc: str,
    ldap_filter: str,
    timeout: int,
) -> list[dict[str, object]]:
    """Native anonymous LDAP user-object dump via badldap simple-bind.

    Mirrors the connection pattern used by
    :func:`adscan_internal.services.unauth_enrichment_service._enrich_ldap_active_users_native`
    so the unauth flow and any external callers go through the same
    ``ldap+simple://`` simple-bind code path. Returns a list of
    ``{"distinguished_name": str, "attributes": dict[str, list]}`` items.
    Empty list when the directory denies the search after a successful
    anonymous bind.
    """
    from adscan_internal import telemetry as _telemetry
    from adscan_core.rich_output import print_warning_debug
    from adscan_internal.rich_output import mark_sensitive
    from adscan_internal.services.async_bridge import run_async_sync
    from adscan_internal.services.ldap_transport_service import (
        anonymous_default_naming_context,
        async_anonymous_ldap_connection,
    )

    async def _run() -> list[dict[str, object]]:
        # Centralized anonymous SIMPLE-bind with LDAPS->LDAP fallback.
        async with async_anonymous_ldap_connection(
            pdc, timeout=timeout
        ) as (conn, _used_ldaps):
            base_dn = anonymous_default_naming_context(conn)
            if not base_dn:
                return []

            collected: list[dict[str, object]] = []
            try:
                async for item, err in conn.pagedsearch(
                    ldap_filter,
                    ["*"],
                    controls=None,
                    tree=base_dn,
                    search_scope=2,
                ):
                    if err is not None:
                        raise err
                    attrs = dict(item.get("attributes", {}) or {})
                    dn = item.get("objectName") or attrs.get("distinguishedName") or ""
                    if isinstance(dn, list):
                        dn = dn[0] if dn else ""
                    collected.append(
                        {
                            "distinguished_name": str(dn or ""),
                            "attributes": attrs,
                        }
                    )
            except Exception as exc:  # noqa: BLE001
                # Hardened directory: bind OK but search refused. Return
                # what we have (empty) instead of raising "Connected, but
                # not bound." up the stack.
                _telemetry.capture_exception(exc)
                print_warning_debug(
                    f"[ldap] Anonymous LDAP search denied on "
                    f"{mark_sensitive(pdc, 'host')}: {exc}"
                )
                return collected
            return collected

    return run_async_sync(_run())


@dataclass
class LDAPUser:
    """Represents a domain user from LDAP.

    Attributes:
        username: User's sAMAccountName
        distinguished_name: User's DN
        description: User description (may contain passwords)
        user_principal_name: User's UPN
        is_enabled: Whether account is enabled
        password_last_set: When password was last changed
        admin_count: AdminCount attribute (1 = privileged account)
    """

    username: str
    distinguished_name: str = ""
    description: str = ""
    user_principal_name: str = ""
    is_enabled: bool = True
    password_last_set: Optional[str] = None
    admin_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "username": self.username,
            "distinguished_name": self.distinguished_name,
            "description": self.description,
            "user_principal_name": self.user_principal_name,
            "is_enabled": self.is_enabled,
            "password_last_set": self.password_last_set,
            "admin_count": self.admin_count,
        }


@dataclass
class LDAPGroup:
    """Represents a domain group from LDAP.

    Attributes:
        name: Group's sAMAccountName
        distinguished_name: Group's DN
        description: Group description
        member_count: Number of members (if available)
        is_privileged: Whether this is a privileged group
    """

    name: str
    distinguished_name: str = ""
    description: str = ""
    member_count: int = 0
    is_privileged: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "distinguished_name": self.distinguished_name,
            "description": self.description,
            "member_count": self.member_count,
            "is_privileged": self.is_privileged,
        }


@dataclass
class LDAPComputer:
    """Represents a domain computer from LDAP.

    Attributes:
        hostname: Computer's DNS hostname or sAMAccountName
        samaccountname: Computer's sAMAccountName
        distinguished_name: Computer's DN
        operating_system: Operating system name
        os_version: Operating system version
        is_enabled: Whether computer account is enabled
        dns_hostname: Computer's DNS hostname
    """

    hostname: str
    samaccountname: str = ""
    distinguished_name: str = ""
    operating_system: str = ""
    os_version: str = ""
    is_enabled: bool = True
    dns_hostname: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "hostname": self.hostname,
            "samaccountname": self.samaccountname,
            "distinguished_name": self.distinguished_name,
            "operating_system": self.operating_system,
            "os_version": self.os_version,
            "is_enabled": self.is_enabled,
            "dns_hostname": self.dns_hostname,
        }


@dataclass
class LDAPAnonymousUserRecord:
    """Represents a partially-visible user object from anonymous LDAP bind.

    Attributes:
        distinguished_name: Distinguished name of the object.
        common_name: ``cn`` attribute or best-effort DN-derived CN.
        samaccountname: ``sAMAccountName`` when visible to the anonymous bind.
        description: ``description`` attribute, if exposed.
        object_classes: Multi-valued ``objectClass`` entries.
        is_enabled: Best-effort enabled state derived from ``userAccountControl``.
        raw_attributes: Full lower-cased attribute mapping parsed from NetExec.
    """

    distinguished_name: str
    common_name: str = ""
    samaccountname: str = ""
    description: str = ""
    object_classes: list[str] = field(default_factory=list)
    is_enabled: bool = True
    raw_attributes: Dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for persistence/debugging."""
        return {
            "distinguished_name": self.distinguished_name,
            "common_name": self.common_name,
            "samaccountname": self.samaccountname,
            "description": self.description,
            "object_classes": list(self.object_classes),
            "is_enabled": self.is_enabled,
            "raw_attributes": dict(self.raw_attributes),
        }


# ACCOUNTDISABLE bit in userAccountControl (MS-ADTS 2.2.16).
_UAC_ACCOUNTDISABLE = 0x0002


def _ldap_entries_to_computers(
    records: list[dict[str, Any]],
) -> List[LDAPComputer]:
    """Map raw badldap computer entries into ``LDAPComputer`` models.

    Pure logic (no network), so it is unit-testable in isolation from the
    live LDAP transport.

    Args:
        records: List of ``{"dn": str, "attributes": {attr: [values]}}`` items
            as produced by a paged search for ``(objectCategory=computer)``.

    Returns:
        List of populated ``LDAPComputer`` objects, one per record that carries
        at least a ``sAMAccountName`` or a ``dNSHostName``.
    """
    computers: List[LDAPComputer] = []
    for record in records:
        attrs = record.get("attributes") or {}
        if not isinstance(attrs, dict):
            continue

        def _first(name: str, _attrs: dict[str, Any] = attrs) -> str:
            value = _attrs.get(name)
            if isinstance(value, list):
                return str(value[0]).strip() if value else ""
            if value is None:
                return ""
            return str(value).strip()

        sam = _first("sAMAccountName")
        dns_hostname = _first("dNSHostName")
        if not sam and not dns_hostname:
            continue
        hostname = dns_hostname or sam.rstrip("$")

        uac_raw = attrs.get("userAccountControl")
        if isinstance(uac_raw, list):
            uac_raw = uac_raw[0] if uac_raw else None
        try:
            uac = int(uac_raw) if uac_raw is not None else 0
        except (TypeError, ValueError):
            uac = 0

        computers.append(
            LDAPComputer(
                hostname=hostname,
                samaccountname=sam,
                distinguished_name=str(record.get("dn") or "").strip(),
                operating_system=_first("operatingSystem"),
                os_version=_first("operatingSystemVersion"),
                is_enabled=not bool(uac & _UAC_ACCOUNTDISABLE),
                dns_hostname=dns_hostname,
            )
        )
    return computers


def _native_computer_enumeration(
    *,
    domain: str,
    pdc: str,
    username: str,
    password: str,
    timeout: int,
    posture_snapshot: object | None = None,
    posture_sink: object | None = None,
) -> List[LDAPComputer]:
    """Enumerate domain computers via a native badldap paged search.

    Replaces the legacy ``nxc ldap <pdc> --computers`` subprocess. Goes through
    :class:`ADscanLDAPConnection` so the LDAPS->LDAP fallback, sign/seal toggles
    and posture-aware auth planning all stay centralized. ``password`` may be a
    cleartext password or an NT hash; the transport auto-detects the hash and
    performs pass-the-hash over LDAP.

    Args:
        domain: Target AD domain FQDN.
        pdc: Target domain controller IP or hostname.
        username: Authenticating principal sAMAccountName.
        password: Authenticating secret (password or 32-hex NT hash).
        timeout: Per-connect budget in seconds.
        posture_snapshot: Optional posture snapshot for the auth planner.
        posture_sink: Optional posture sink for reactive signal emission.

    Returns:
        List of ``LDAPComputer`` objects.

    Raises:
        ValueError: When credentials are missing.
    """
    from adscan_internal.services.ldap_transport_service import (
        ADscanLDAPConfig,
        ADscanLDAPConnection,
    )

    if not username or not password:
        raise ValueError(
            "Authenticated LDAP computer enumeration requires username + password/nt_hash."
        )

    config = ADscanLDAPConfig(
        domain=domain,
        dc_ip=pdc,
        use_ldaps=True,
        use_kerberos=False,
        username=username,
        password=password,
        posture_snapshot=posture_snapshot,
        posture_sink=posture_sink,
    )

    attributes = [
        "sAMAccountName",
        "dNSHostName",
        "operatingSystem",
        "operatingSystemVersion",
        "userAccountControl",
    ]

    records: list[dict[str, Any]] = []
    with ADscanLDAPConnection(config, connect_timeout=float(timeout)) as conn:
        conn.search(
            search_base=conn.domain_dn,
            search_filter="(objectCategory=computer)",
            attributes=attributes,
            search_scope="SUBTREE",
            paged_size=1000,
        )
        for entry in conn.entries:
            records.append(
                {"dn": entry.dn, "attributes": entry.entry_attributes_as_dict}
            )
    return _ldap_entries_to_computers(records)


class LDAPEnumerationMixin:
    """LDAP enumeration operations.

    This mixin provides LDAP-specific enumeration methods that typically
    require authenticated access to query Active Directory.

    Note: This is a mixin, not a standalone service. It requires a parent
    EnumerationService to provide event_bus, logger, and license_mode.
    """

    def __init__(self, parent_service):
        """Initialize LDAP enumeration mixin.

        Args:
            parent_service: Parent EnumerationService instance
        """
        self.parent = parent_service
        self.logger = parent_service.logger

    def query_anonymous_user_inventory(
        self,
        *,
        pdc: str,
        netexec_path: str,
        log_file: Optional[str] = None,
        ldap_filter: Optional[str] = None,
        executor: CommandExecutor | None = None,
        scan_id: Optional[str] = None,
        timeout: int = 120,
    ) -> List[LDAPAnonymousUserRecord]:
        """Query LDAP anonymously for user objects.

        Native badldap implementation using an explicit ``ldap+simple://`` /
        ``ldaps+simple://`` SIMPLE bind with empty credentials (RFC 4513
        §5.1.1 anonymous), so paged searches actually work. The previous
        sync ``ADscanLDAPConnection`` path used the NONE-protocol URL form
        which leaves the connection in CONNECTED (not BOUND) state and
        crashed pagedsearch with ``Connected, but not bound.`` on every
        hardened DC.

        On hardened directories that allow the anonymous bind but reject
        searches (``operationsError`` / ``ERROR_NOT_AUTHENTICATED``), this
        returns ``[]`` cleanly — no exception escapes.

        ``netexec_path``, ``log_file`` and ``executor`` are accepted for
        backward compatibility with legacy callsites and ignored.
        """
        _ = (netexec_path, log_file, executor)

        effective_filter = (
            ldap_filter
            or "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        )
        self.parent._emit_progress(
            scan_id=scan_id,
            phase="ldap_anonymous_user_inventory",
            progress=0.0,
            message=f"Querying anonymous LDAP user inventory on {pdc}",
        )

        try:
            objects = _native_anonymous_user_inventory(
                pdc=pdc,
                ldap_filter=effective_filter,
                timeout=timeout,
            )
        except Exception as e:
            self.logger.exception(f"Error during anonymous LDAP user inventory: {e}")
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_anonymous_user_inventory",
                progress=1.0,
                message="Anonymous LDAP user inventory failed",
            )
            return []

        records = self._parse_netexec_anonymous_user_inventory(objects)

        self.parent._emit_progress(
            scan_id=scan_id,
            phase="ldap_anonymous_user_inventory",
            progress=1.0,
            message=f"Anonymous LDAP user inventory completed: {len(records)} user object(s) found",
        )
        return records

    def _parse_ldap_entries_anonymous_user_inventory(
        self, entries: list[object]
    ) -> List[LDAPAnonymousUserRecord]:
        """Normalize LDAP entries into anonymous user records."""
        objects: list[dict[str, object]] = []
        for entry in entries:
            dn = str(getattr(entry, "dn", None) or getattr(entry, "entry_dn", "") or "").strip()
            attrs = entry.entry_attributes_as_dict
            if not isinstance(attrs, dict):
                attrs = {}
            objects.append({"distinguished_name": dn, "attributes": attrs})
        return self._parse_netexec_anonymous_user_inventory(objects)

    def enumerate_computers(
        self,
        domain: str,
        pdc: str,
        auth_mode: AuthMode,
        username: str,
        password: str,
        netexec_path: str = "",
        *,
        executor: CommandExecutor | None = None,
        scan_id: Optional[str] = None,
        timeout: int = 120,
        posture_snapshot: object | None = None,
        posture_sink: object | None = None,
    ) -> List[LDAPComputer]:
        """Enumerate domain computers via a native badldap LDAP search.

        This operation requires authenticated access.

        Native implementation: a single paged search for
        ``(objectCategory=computer)`` over :class:`ADscanLDAPConnection` (LDAPS
        with automatic LDAP fallback). Replaces the legacy
        ``nxc ldap <pdc> --computers`` subprocess. ``password`` may be a
        cleartext password or an NT hash — the transport auto-detects the hash
        and performs pass-the-hash over LDAP.

        Args:
            domain: Domain name.
            pdc: PDC hostname/IP.
            auth_mode: Authentication mode (must be AUTHENTICATED).
            username: Username.
            password: Password or NT hash.
            netexec_path: Unused — retained for backward-compatible call sites.
            executor: Unused — retained for backward-compatible call sites.
            scan_id: Optional scan ID.
            timeout: Per-connect budget in seconds.
            posture_snapshot: Optional posture snapshot for the auth planner.
            posture_sink: Optional posture sink for reactive posture signals.

        Returns:
            List of domain computers.
        """
        # Retained for backward compatibility with legacy call sites; the
        # enumeration is now fully native (badldap), no subprocess involved.
        _ = (netexec_path, executor)

        self.parent._emit_progress(
            scan_id=scan_id,
            phase="ldap_computer_enumeration",
            progress=0.0,
            message=f"Enumerating computers via LDAP on {domain}",
        )

        self.logger.info(f"Enumerating computers via LDAP on domain {domain}")

        try:
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_computer_enumeration",
                progress=0.3,
                message="Executing LDAP query",
            )

            computers = _native_computer_enumeration(
                domain=domain,
                pdc=pdc,
                username=username,
                password=password,
                timeout=timeout,
                posture_snapshot=posture_snapshot,
                posture_sink=posture_sink,
            )

            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_computer_enumeration",
                progress=1.0,
                message=f"Computer enumeration completed: {len(computers)} computer(s) found",
            )

            self.logger.info(f"Found {len(computers)} domain computers")
            return computers

        except Exception as e:
            self.logger.exception(f"Error during LDAP computer enumeration: {e}")
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_computer_enumeration",
                progress=1.0,
                message="Computer enumeration failed",
            )
            return []

    def test_anonymous_access(
        self,
        pdc: str,
        netexec_path: str,
        log_file: Optional[str] = None,
        *,
        executor: CommandExecutor | None = None,
        scan_id: Optional[str] = None,
        timeout: int = 60,
    ) -> Dict[str, Any]:
        """Test anonymous LDAP access to the domain controller.

        Attempts to bind to LDAP with empty credentials to test if
        anonymous access is allowed.

        Args:
            pdc: PDC hostname/IP.
            netexec_path: Unused — kept for backward compatibility with the
                legacy NetExec-based signature; the bind is now native.
            log_file: Unused — kept for compatibility.
            executor: Unused — kept for compatibility.
            scan_id: Optional scan ID.
            timeout: Timeout in seconds for the underlying async probe.

        Returns:
            Dictionary with test results:
                - accessible: bool - Whether anonymous access succeeded
                - error: Optional[str] - Error message if failed
        """
        # Backward-compat shim: parameters retained so existing callers continue
        # to work, but we no longer shell out to NetExec.
        _ = (netexec_path, log_file, executor)

        self.parent._emit_progress(
            scan_id=scan_id,
            phase="ldap_anonymous_test",
            progress=0.0,
            message=f"Testing anonymous LDAP access on {pdc}",
        )

        self.logger.info(f"Testing anonymous LDAP access on {pdc}")

        try:
            from adscan_internal.services.unauth_probe_service import (
                _probe_ldap_anonymous,
            )

            probe_result = asyncio.run(_probe_ldap_anonymous(pdc, timeout))

            accessible = probe_result.status == "open"

            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_anonymous_test",
                progress=1.0,
                message=(
                    f"Anonymous LDAP test completed: "
                    f"{'Accessible' if accessible else 'Not accessible'}"
                ),
            )

            error_message: Optional[str] = None
            if not accessible:
                error_message = probe_result.error or "Anonymous access denied."

            self.logger.info(
                f"Anonymous LDAP access test: "
                f"{'SUCCESS' if accessible else 'DENIED'}",
                extra={"pdc": pdc, "accessible": accessible},
            )

            return {"accessible": accessible, "error": error_message}

        except RuntimeError as e:
            # Asyncio loop conflict — caller is already inside an event loop.
            self.logger.exception(
                f"Anonymous LDAP test cannot run synchronously: {e}"
            )
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_anonymous_test",
                progress=1.0,
                message="Test could not run (loop conflict)",
            )
            return {"accessible": False, "error": str(e)}

        except Exception as e:
            self.logger.exception(f"Error during anonymous LDAP test: {e}")
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_anonymous_test",
                progress=1.0,
                message="Test failed",
            )
            return {"accessible": False, "error": str(e)}

    def _parse_netexec_anonymous_user_inventory(
        self, objects: list[dict[str, object]]
    ) -> List[LDAPAnonymousUserRecord]:
        """Normalize NetExec LDAP query objects into anonymous user records."""
        records: list[LDAPAnonymousUserRecord] = []
        seen_dns: set[str] = set()

        for item in objects:
            dn = str(item.get("distinguished_name") or "").strip()
            if not dn:
                continue

            attrs_raw = item.get("attributes") or {}
            if not isinstance(attrs_raw, dict):
                continue

            attrs: dict[str, list[str]] = {}
            for key, values in attrs_raw.items():
                normalized_key = str(key or "").casefold()
                if not normalized_key:
                    continue
                if isinstance(values, list):
                    attrs[normalized_key] = [
                        str(value).strip() for value in values if str(value).strip()
                    ]
                else:
                    value = str(values or "").strip()
                    attrs[normalized_key] = [value] if value else []

            object_classes = [entry.casefold() for entry in attrs.get("objectclass", [])]
            if object_classes and "user" not in object_classes:
                continue

            cn = ""
            if attrs.get("cn"):
                cn = attrs["cn"][0]
            elif dn.upper().startswith("CN="):
                cn = dn.split(",", 1)[0].split("=", 1)[1].strip()

            samaccountname = ""
            if attrs.get("samaccountname"):
                samaccountname = attrs["samaccountname"][0]

            description = " | ".join(attrs.get("description", []))

            is_enabled = True
            if attrs.get("useraccountcontrol"):
                try:
                    uac = int(attrs["useraccountcontrol"][0], 10)
                    is_enabled = not bool(uac & 0x0002)
                except (TypeError, ValueError):
                    is_enabled = True

            key = dn.casefold()
            if key in seen_dns:
                continue
            seen_dns.add(key)
            records.append(
                LDAPAnonymousUserRecord(
                    distinguished_name=dn,
                    common_name=cn,
                    samaccountname=samaccountname,
                    description=description,
                    object_classes=object_classes,
                    is_enabled=is_enabled,
                    raw_attributes=attrs,
                )
            )

        return records

