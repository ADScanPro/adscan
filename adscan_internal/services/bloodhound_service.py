"""BloodHound service integration.

This module integrates the bloodhound-cli functionality as a service layer,
providing unified access to both BloodHound CE and Legacy (Neo4j) instances.

BloodHound is used for Active Directory attack path analysis and provides
capabilities for:
- User and computer enumeration
- Session detection
- ACL/ACE analysis
- Attack path discovery
- Data collection and upload
"""

from typing import List, Dict, Optional, Any
import logging

from adscan_internal import telemetry
from adscan_internal.rich_output import mark_sensitive, print_info_debug
from adscan_internal.services.base_service import BaseService
from adscan_internal.core import (
    EventBus,
    LicenseMode,
    ADScanException,
)


logger = logging.getLogger(__name__)


class BloodHoundServiceError(ADScanException):
    """BloodHound service-specific exceptions."""


class BloodHoundService(BaseService):
    """BloodHound integration service.

    This service provides direct integration with BloodHound for Active Directory
    attack path analysis. It supports both:
    - BloodHound CE (Community Edition) via HTTP API
    - BloodHound Legacy via direct Neo4j connection

    The service wraps bloodhound-cli functionality as Python modules instead of
    subprocess calls for better performance and control.

    Usage:
        # CLI mode with CE
        service = BloodHoundService(edition="ce")
        users = service.get_users(domain="example.local")

        # CLI mode with Legacy
        service = BloodHoundService(
            edition="legacy",
            uri="bolt://localhost:7687",
            user="neo4j",
            password="password"
        )

        # Web mode with events
        bus = EventBus()
        service = BloodHoundService(edition="ce", event_bus=bus)
        sessions = service.get_sessions(domain="example.local", scan_id="scan-123")

    Attributes:
        edition: BloodHound edition ("ce" or "legacy")
        client: Underlying BloodHoundClient instance
    """

    def __init__(
        self,
        edition: str = "ce",
        event_bus: Optional[EventBus] = None,
        license_mode: LicenseMode = LicenseMode.PRO,
        # CE parameters
        base_url: Optional[str] = None,
        api_token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify: bool = True,
        # Legacy parameters
        uri: Optional[str] = None,
        neo4j_user: Optional[str] = None,
        neo4j_password: Optional[str] = None,
        # Common parameters
        debug: bool = False,
        verbose: bool = False,
    ):
        """Initialize BloodHound service.

        Args:
            edition: BloodHound edition ("ce" or "legacy")
            event_bus: Event bus for progress tracking
            license_mode: License mode (LITE or PRO)
            base_url: CE base URL (e.g., "http://localhost:8442")
            api_token: CE API token (obtained via authentication)
            username: CE username (default: "admin")
            password: CE password
            verify: Verify SSL certificates for CE (default: True)
            uri: Legacy Neo4j URI (e.g., "bolt://localhost:7687")
            neo4j_user: Legacy Neo4j username (default: "neo4j")
            neo4j_password: Legacy Neo4j password
            debug: Enable debug mode
            verbose: Enable verbose mode

        Raises:
            BloodHoundServiceError: If bloodhound-cli is not available
            ValueError: If invalid edition specified
        """
        super().__init__(event_bus=event_bus, license_mode=license_mode)

        self.edition = edition.lower()
        self.debug = debug
        self.verbose = verbose

        # Import bloodhound-cli modules from internal integrations
        try:
            from adscan_internal.integrations.bloodhound_cli.core.factory import (
                create_bloodhound_client,
            )
            from adscan_internal.integrations.bloodhound_cli.core.settings import (
                load_ce_config,
                load_legacy_config,
            )

            self._create_client = create_bloodhound_client
            self._load_ce_config = load_ce_config
            self._load_legacy_config = load_legacy_config

        except ImportError as e:
            raise BloodHoundServiceError(
                "bloodhound-cli integration not found. This is a critical error.",
                details={"error": str(e)},
            ) from e

        # Create BloodHound client based on edition
        if self.edition == "ce":
            self.client = self._create_ce_client(
                base_url=base_url,
                api_token=api_token,
                username=username,
                password=password,
                verify=verify,
            )
        elif self.edition == "legacy":
            self.client = self._create_legacy_client(
                uri=uri,
                user=neo4j_user,
                password=neo4j_password,
            )
        else:
            raise ValueError(f"Invalid edition: {edition}. Use 'ce' or 'legacy'")

        self.logger.info(
            f"BloodHoundService initialized with {self.edition} edition",
            extra={"edition": self.edition, "license_mode": license_mode.value},
        )

    def _create_ce_client(
        self,
        base_url: Optional[str] = None,
        api_token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify: bool = True,
    ):
        """Create BloodHound CE client.

        Args:
            base_url: CE base URL
            api_token: CE API token
            username: CE username
            password: CE password
            verify: Verify SSL certificates

        Returns:
            BloodHoundCEClient instance

        Raises:
            BloodHoundServiceError: If authentication fails
        """
        # Load configuration from ~/.bloodhound_config
        settings = self._load_ce_config()

        # Override with provided parameters
        # Convert base_url to string (handles Pydantic AnyHttpUrl objects)
        base_url = base_url or str(settings.base_url)
        api_token = api_token or settings.api_token
        username = username or settings.username
        password = password or settings.password
        verify = verify if verify is not None else settings.verify

        self.logger.debug(
            "Creating CE client",
            extra={"base_url": base_url, "username": username, "verify": verify},
        )

        # Create client (this will automatically load token from ~/.bloodhound_config)
        client = self._create_client(
            "ce",
            base_url=base_url,
            api_token=api_token,
            debug=self.debug,
            verbose=self.verbose,
            verify=verify,
        )

        # The client automatically loads the token from ~/.bloodhound_config during initialization
        # We don't need to authenticate here - ensure_valid_token() will handle token validation
        # and renewal using credentials from the config file when the client is actually used.
        # This allows the service to be created even if the token is expired, as it will be
        # automatically renewed when needed (e.g., during upload_data).
        self.logger.debug(
            "BloodHound CE client created",
            extra={
                "base_url": base_url,
                "has_api_token": bool(client.api_token),
                "has_stored_token": bool(api_token or settings.api_token),
            },
        )

        return client

    def _create_legacy_client(
        self,
        uri: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
    ):
        """Create BloodHound Legacy (Neo4j) client.

        Args:
            uri: Neo4j URI
            user: Neo4j username
            password: Neo4j password

        Returns:
            BloodHoundLegacyClient instance
        """
        # Load configuration from ~/.bloodhound_config
        settings = self._load_legacy_config()

        # Override with provided parameters
        uri = uri or settings.uri
        user = user or settings.user
        password = password or settings.password

        self.logger.debug(
            "Creating Legacy client",
            extra={"uri": uri, "user": user},
        )

        return self._create_client(
            "legacy",
            uri=uri,
            user=user,
            password=password,
            debug=self.debug,
            verbose=self.verbose,
        )

    def get_domain_users_group(self, domain: str) -> dict[str, Any] | None:
        """Return the Domain Users group node properties for a domain (best-effort).

        We prefer using the well-known RID 513 (Domain Users) rather than
        matching by name because the display name can vary by language.

        Args:
            domain: Target domain (e.g., "north.sevenkingdoms.local").

        Returns:
            Node properties dict when found, otherwise None.
        """
        if not domain or "." not in domain:
            return None

        query = f"""
        MATCH (g:Group)
        WHERE toLower(coalesce(g.domain, "")) = toLower("{domain}")
          AND (
            coalesce(g.objectid, g.objectId, "") = coalesce(g.domainsid, g.domainSid, "") + "-513"
          )
        RETURN g
        LIMIT 1
        """
        try:
            rows = self.client.execute_query(query)
            marked_domain = mark_sensitive(domain, "domain")
            print_info_debug(
                f"[domain_users] lookup completed for {marked_domain}: "
                f"rows={len(rows) if isinstance(rows, list) else 'N/A'}"
            )
            if isinstance(rows, list) and rows:
                node = rows[0]
                if isinstance(node, dict):
                    name = str(node.get("name") or "")
                    object_id = str(node.get("objectid") or node.get("objectId") or "")
                    print_info_debug(
                        f"[domain_users] node found for {marked_domain}: "
                        f"name={mark_sensitive(name, 'user')}, "
                        f"objectid={mark_sensitive(object_id, 'user')}"
                    )
                    return node
            print_info_debug(
                f"[domain_users] node not found (RID 513) for {marked_domain}"
            )
        except Exception as exc:  # pragma: no cover - best effort
            telemetry.capture_exception(exc)  # type: ignore[name-defined]
            marked_domain = mark_sensitive(domain, "domain")
            print_info_debug(f"[domain_users] lookup failed for {marked_domain}: {exc}")
            self.logger.exception(
                "Domain Users group lookup failed",
                extra={"domain": domain},
            )
        return None

    def get_domain_node(self, domain: str) -> dict[str, Any] | None:
        """Return the Domain node properties for a domain (best-effort).

        Args:
            domain: Target domain (e.g., "north.sevenkingdoms.local").

        Returns:
            Node properties dict when found, otherwise None.
        """
        if not domain or "." not in domain:
            return None

        try:
            if hasattr(self.client, "get_domain_node"):
                node = self.client.get_domain_node(domain)  # type: ignore[attr-defined]
                rows = [node] if isinstance(node, dict) else []
            else:
                query = f"""
                MATCH (d:Domain)
                WHERE toLower(coalesce(d.name, d.domain, d.label, "")) = toLower("{domain}")
                RETURN d
                LIMIT 1
                """
                rows = self.client.execute_query(query)
            marked_domain = mark_sensitive(domain, "domain")
            print_info_debug(
                f"[domain_node] lookup completed for {marked_domain}: "
                f"rows={len(rows) if isinstance(rows, list) else 'N/A'}"
            )
            if isinstance(rows, list) and rows:
                node = rows[0]
                if isinstance(node, dict):
                    name = str(node.get("name") or "")
                    object_id = str(node.get("objectid") or node.get("objectId") or "")
                    print_info_debug(
                        f"[domain_node] node found for {marked_domain}: "
                        f"name={mark_sensitive(name, 'domain')}, "
                        f"objectid={mark_sensitive(object_id, 'user')}"
                    )
                    return node
            print_info_debug(f"[domain_node] node not found for {marked_domain}")
        except Exception as exc:  # pragma: no cover - best effort
            telemetry.capture_exception(exc)  # type: ignore[name-defined]
            marked_domain = mark_sensitive(domain, "domain")
            print_info_debug(f"[domain_node] lookup failed for {marked_domain}: {exc}")
            self.logger.exception(
                "Domain node lookup failed",
                extra={"domain": domain},
            )
        return None

    def get_user_node_by_samaccountname(
        self, domain: str, username: str
    ) -> dict[str, Any] | None:
        """Return the User node properties for a domain given a username.

        We prefer enriching the attack graph with real BloodHound nodes when
        possible (e.g. to include objectId/SID and other metadata), even when
        the finding comes from outside BloodHound (LDAP descriptions, spraying,
        etc.).

        Args:
            domain: Target domain (e.g., "north.sevenkingdoms.local").
            username: samAccountName (preferred) or other user identifier.

        Returns:
            Node properties dict when found, otherwise None.
        """
        domain_clean = (domain or "").strip()
        user_clean = (username or "").strip()
        if not domain_clean or "." not in domain_clean or not user_clean:
            return None

        try:
            if hasattr(self.client, "get_user_node"):
                node = self.client.get_user_node(domain_clean, user_clean)  # type: ignore[attr-defined]
                rows = [node] if isinstance(node, dict) else []
            else:
                query = f"""
                MATCH (u:User)
                WHERE toLower(coalesce(u.domain, "")) = toLower("{domain_clean}")
                  AND (
                    toLower(coalesce(u.samaccountname, "")) = toLower("{user_clean}")
                    OR toLower(coalesce(u.name, "")) = toLower("{user_clean}")
                  )
                RETURN u
                LIMIT 1
                """
                rows = self.client.execute_query(query)

            marked_domain = mark_sensitive(domain_clean, "domain")
            marked_user = mark_sensitive(user_clean, "user")
            print_info_debug(
                f"[user_node] lookup completed for {marked_domain} user={marked_user}: "
                f"rows={len(rows) if isinstance(rows, list) else 'N/A'}"
            )
            if isinstance(rows, list) and rows:
                node = rows[0]
                if isinstance(node, dict):
                    sam = str(node.get("samaccountname") or "")
                    name = str(node.get("name") or "")
                    object_id = str(node.get("objectid") or node.get("objectId") or "")
                    print_info_debug(
                        f"[user_node] node found for {marked_domain}: "
                        f"sam={mark_sensitive(sam, 'user')}, "
                        f"name={mark_sensitive(name, 'user')}, "
                        f"objectid={mark_sensitive(object_id, 'user')}"
                    )
                    return node
            print_info_debug(
                f"[user_node] node not found for {marked_domain} user={marked_user}"
            )
        except Exception as exc:  # pragma: no cover - best effort
            telemetry.capture_exception(exc)  # type: ignore[name-defined]
            marked_domain = mark_sensitive(domain_clean, "domain")
            marked_user = mark_sensitive(user_clean, "user")
            print_info_debug(
                f"[user_node] lookup failed for {marked_domain} user={marked_user}: {exc}"
            )
            self.logger.exception(
                "User node lookup failed",
                extra={"domain": domain_clean, "username": user_clean},
            )
        return None

    def get_computer_node_by_name(
        self, domain: str, fqdn: str
    ) -> dict[str, Any] | None:
        """Return the Computer node properties for a domain given a hostname/FQDN.

        NetExec-based privilege checks often operate on IPs/hostnames, but the
        attack graph uses BloodHound nodes (e.g. ``CASTELBLACK$``). This helper
        resolves a host back into the BloodHound Computer node so we can upsert
        canonical steps.

        Args:
            domain: Target domain (e.g., "north.sevenkingdoms.local").
            fqdn: Hostname or FQDN (preferred) to look up (e.g.,
                "castelblack.north.sevenkingdoms.local").

        Returns:
            Node properties dict when found, otherwise None.
        """
        domain_clean = (domain or "").strip()
        fqdn_clean = (fqdn or "").strip().rstrip(".")
        if not domain_clean or "." not in domain_clean or not fqdn_clean:
            return None

        try:
            # Prefer client-native helper when available (CE), which centralizes
            # the Cypher in the integration layer.
            if hasattr(self.client, "get_computer_node"):
                node = self.client.get_computer_node(  # type: ignore[attr-defined]
                    domain_clean, fqdn_clean
                )
                rows = [node] if isinstance(node, dict) else []
            else:
                query = f"""
                MATCH (c:Computer)
                WHERE toLower(coalesce(c.domain, "")) = toLower("{domain_clean}")
                  AND toLower(coalesce(c.name, "")) = toLower("{fqdn_clean}")
                RETURN c
                LIMIT 1
                """
                rows = self.client.execute_query(query)
            marked_domain = mark_sensitive(domain_clean, "domain")
            marked_fqdn = mark_sensitive(fqdn_clean, "host")
            print_info_debug(
                f"[computer_node] lookup completed for {marked_domain} fqdn={marked_fqdn}: "
                f"rows={len(rows) if isinstance(rows, list) else 'N/A'}"
            )
            if isinstance(rows, list) and rows:
                node = rows[0]
                if isinstance(node, dict):
                    name = str(node.get("name") or "")
                    sam = str(node.get("samaccountname") or "")
                    object_id = str(node.get("objectid") or node.get("objectId") or "")
                    print_info_debug(
                        f"[computer_node] node found for {marked_domain}: "
                        f"name={mark_sensitive(name, 'host')}, "
                        f"sam={mark_sensitive(sam, 'host')}, "
                        f"objectid={mark_sensitive(object_id, 'user')}"
                    )
                    return node
            print_info_debug(
                f"[computer_node] node not found for {marked_domain} fqdn={marked_fqdn}"
            )
        except Exception as exc:  # pragma: no cover - best effort
            telemetry.capture_exception(exc)  # type: ignore[name-defined]
            marked_domain = mark_sensitive(domain_clean, "domain")
            marked_fqdn = mark_sensitive(fqdn_clean, "host")
            print_info_debug(
                f"[computer_node] lookup failed for {marked_domain} fqdn={marked_fqdn}: {exc}"
            )
            self.logger.exception(
                "Computer node lookup failed",
                extra={"domain": domain_clean, "fqdn": fqdn_clean},
            )
        return None

    def get_group_node_by_samaccountname(
        self, domain: str, group_name: str
    ) -> dict[str, Any] | None:
        """Return the Group node properties for a domain given a group name.

        Args:
            domain: Target domain (e.g., "htb.local").
            group_name: Group identifier. This is typically the group's
                ``samAccountName`` (can contain spaces). Some built-in groups do
                not expose ``samAccountName`` in BloodHound, so we resolve by the
                canonical global name: ``<GROUP>@<DOMAIN>`` (stored as ``g.name``).

        Returns:
            Node properties dict when found, otherwise None.
        """
        domain_clean = (domain or "").strip()
        group_clean = (group_name or "").strip()
        if not domain_clean or "." not in domain_clean or not group_clean:
            return None

        try:
            # Prefer matching on BloodHound's canonical `name` field because it is present
            # for groups even when `samaccountname` is missing (e.g., built-in groups).
            if "@" in group_clean:
                canonical = group_clean
            else:
                canonical = f"{group_clean}@{domain_clean}"
            # Use single-quoted strings for Cypher compatibility (BloodHound CE).
            sanitized = canonical.replace("'", "\\'")
            query = f"""
            MATCH (g:Group)
            WHERE toLower(coalesce(g.name, "")) = toLower('{sanitized}')
            RETURN g
            LIMIT 1
            """
            rows = self.client.execute_query(query)
            marked_domain = mark_sensitive(domain_clean, "domain")
            marked_group = mark_sensitive(group_clean, "user")
            print_info_debug(
                f"[group_node] lookup completed for {marked_domain} group={marked_group}: "
                f"rows={len(rows) if isinstance(rows, list) else 'N/A'}"
            )
            if isinstance(rows, list) and rows:
                node = rows[0]
                if isinstance(node, dict):
                    name = str(node.get("name") or "")
                    sam = str(node.get("samaccountname") or "")
                    object_id = str(node.get("objectid") or node.get("objectId") or "")
                    print_info_debug(
                        f"[group_node] node found for {marked_domain}: "
                        f"sam={mark_sensitive(sam or group_clean, 'user')}, "
                        f"name={mark_sensitive(name or group_clean, 'user')}, "
                        f"objectid={mark_sensitive(object_id, 'user')}"
                    )
                    return node
            print_info_debug(
                f"[group_node] node not found for {marked_domain} group={marked_group}"
            )
        except Exception as exc:  # pragma: no cover - best effort
            telemetry.capture_exception(exc)  # type: ignore[name-defined]
            marked_domain = mark_sensitive(domain_clean, "domain")
            marked_group = mark_sensitive(group_clean, "user")
            print_info_debug(
                f"[group_node] lookup failed for {marked_domain} group={marked_group}: {exc}"
            )
            self.logger.exception(
                "Group node lookup failed",
                extra={"domain": domain_clean, "group": group_clean},
            )
        return None

    def get_users(
        self,
        domain: str,
        filter_type: Optional[str] = None,
        scan_id: Optional[str] = None,
    ) -> List[str]:
        """Get users from domain.

        Args:
            domain: Domain name
            filter_type: Filter type (None, "high_value", "admin", "pwd_never_expires", "pwd_not_required")
            scan_id: Optional scan ID for progress tracking

        Returns:
            List of usernames

        Raises:
            BloodHoundServiceError: If query fails
        """
        self._emit_progress(
            scan_id=scan_id,
            phase="bloodhound_user_enumeration",
            progress=0.0,
            message=f"Querying BloodHound for users in {domain}",
        )

        try:
            if filter_type == "high_value":
                users = self.client.get_highvalue_users(domain)
            elif filter_type == "admin":
                users = self.client.get_admin_users(domain)
            elif filter_type == "pwd_never_expires":
                users = self.client.get_password_never_expires_users(domain)
            elif filter_type == "pwd_not_required":
                users = self.client.get_password_not_required_users(domain)
            else:
                users = self.client.get_users(domain)

            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_user_enumeration",
                progress=1.0,
                message=f"Retrieved {len(users)} users from BloodHound",
            )

            self.logger.info(
                f"Retrieved {len(users)} users",
                extra={
                    "domain": domain,
                    "filter_type": filter_type,
                    "count": len(users),
                },
            )

            return users

        except Exception as e:
            self.logger.exception(
                "Failed to get users from BloodHound",
                extra={"domain": domain, "filter_type": filter_type, "error": str(e)},
            )
            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_user_enumeration",
                progress=1.0,
                message="User enumeration failed",
            )
            raise BloodHoundServiceError(
                "Failed to retrieve users from BloodHound",
                details={"domain": domain, "error": str(e)},
            ) from e

    def get_computers(
        self,
        domain: str,
        laps_filter: Optional[bool] = None,
        scan_id: Optional[str] = None,
    ) -> List[str]:
        """Get computers from domain.

        Args:
            domain: Domain name
            laps_filter: Filter by LAPS status (None=all, True=LAPS enabled, False=LAPS disabled)
            scan_id: Optional scan ID for progress tracking

        Returns:
            List of computer names

        Raises:
            BloodHoundServiceError: If query fails
        """
        self._emit_progress(
            scan_id=scan_id,
            phase="bloodhound_computer_enumeration",
            progress=0.0,
            message=f"Querying BloodHound for computers in {domain}",
        )

        try:
            computers = self.client.get_computers(domain, laps=laps_filter)

            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_computer_enumeration",
                progress=1.0,
                message=f"Retrieved {len(computers)} computers from BloodHound",
            )

            self.logger.info(
                f"Retrieved {len(computers)} computers",
                extra={
                    "domain": domain,
                    "laps_filter": laps_filter,
                    "count": len(computers),
                },
            )

            return computers

        except Exception as e:
            self.logger.exception(
                "Failed to get computers from BloodHound",
                extra={"domain": domain, "laps_filter": laps_filter, "error": str(e)},
            )
            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_computer_enumeration",
                progress=1.0,
                message="Computer enumeration failed",
            )
            raise BloodHoundServiceError(
                "Failed to retrieve computers from BloodHound",
                details={"domain": domain, "error": str(e)},
            ) from e

    def get_timeroast_candidates(
        self,
        domain: str,
        *,
        max_results: int = 250,
        scan_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get enabled computer accounts that match Timeroast heuristics."""
        self._emit_progress(
            scan_id=scan_id,
            phase="bloodhound_computer_enumeration",
            progress=0.0,
            message="Querying BloodHound for Timeroast candidates",
        )

        try:
            if not hasattr(self.client, "get_timeroast_candidates"):
                raise BloodHoundServiceError(
                    "Timeroast candidate queries are not supported by this BloodHound client",
                    details={"edition": self.edition},
                )

            candidates = self.client.get_timeroast_candidates(
                domain,
                max_results=max_results,
            )

            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_computer_enumeration",
                progress=1.0,
                message=f"Retrieved {len(candidates)} Timeroast candidate(s)",
            )

            self.logger.info(
                "Retrieved Timeroast candidates",
                extra={
                    "domain": domain,
                    "count": len(candidates),
                    "max_results": max_results,
                },
            )
            return candidates
        except Exception as e:
            self.logger.exception(
                "Failed to get Timeroast candidates from BloodHound",
                extra={"domain": domain, "error": str(e), "max_results": max_results},
            )
            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_computer_enumeration",
                progress=1.0,
                message="Timeroast candidate query failed",
            )
            raise BloodHoundServiceError(
                "Failed to retrieve Timeroast candidates from BloodHound",
                details={"domain": domain, "error": str(e)},
            ) from e

    def get_users_in_ou(
        self,
        domain: str,
        ou_distinguished_name: str,
        scan_id: Optional[str] = None,
    ) -> List[str]:
        """Get users in a specific OU (CE only).

        Args:
            domain: Domain name.
            ou_distinguished_name: Distinguished name of the OU (e.g. "OU=SERVICE USERS,DC=EXAMPLE,DC=LOCAL").
            scan_id: Optional scan ID for progress tracking.

        Returns:
            List of usernames (samAccountNames).

        Raises:
            BloodHoundServiceError: If query fails.
        """
        self._emit_progress(
            scan_id=scan_id,
            phase="bloodhound_user_enumeration",
            progress=0.0,
            message="Querying BloodHound for OU users",
        )

        try:
            if not hasattr(self.client, "get_users_in_ou"):
                raise BloodHoundServiceError(
                    "OU user filtering is not supported by this BloodHound client",
                    details={"edition": self.edition},
                )

            users = self.client.get_users_in_ou(domain, ou_distinguished_name)

            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_user_enumeration",
                progress=1.0,
                message=f"Retrieved {len(users)} users from OU",
            )

            self.logger.info(
                f"Retrieved {len(users)} OU users",
                extra={"domain": domain, "count": len(users)},
            )
            return users

        except Exception as e:
            self.logger.exception(
                "Failed to get OU users from BloodHound",
                extra={
                    "domain": domain,
                    "ou_dn": ou_distinguished_name,
                    "error": str(e),
                },
            )
            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_user_enumeration",
                progress=1.0,
                message="OU user enumeration failed",
            )
            raise BloodHoundServiceError(
                "Failed to retrieve users from OU via BloodHound",
                details={"domain": domain, "error": str(e)},
            ) from e

    def get_user_groups(
        self,
        domain: str,
        username: str,
        recursive: bool = True,
        scan_id: Optional[str] = None,
    ) -> List[str]:
        """Get group memberships for a user.

        Args:
            domain: Domain name
            username: Username to query
            recursive: Include nested groups (default: True)
            scan_id: Optional scan ID for progress tracking

        Returns:
            List of group names

        Raises:
            BloodHoundServiceError: If query fails
        """
        self._emit_progress(
            scan_id=scan_id,
            phase="bloodhound_group_enumeration",
            progress=0.0,
            message=f"Querying group memberships for {username}",
        )

        try:
            groups = self.client.get_user_groups(domain, username, recursive)

            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_group_enumeration",
                progress=1.0,
                message=f"User {username} belongs to {len(groups)} group(s)",
            )

            self.logger.info(
                f"Retrieved {len(groups)} groups for user",
                extra={
                    "domain": domain,
                    "username": username,
                    "recursive": recursive,
                    "count": len(groups),
                },
            )

            return groups

        except Exception as e:
            self.logger.exception(
                "Failed to get user groups from BloodHound",
                extra={"domain": domain, "username": username, "error": str(e)},
            )
            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_group_enumeration",
                progress=1.0,
                message="Group enumeration failed",
            )
            raise BloodHoundServiceError(
                "Failed to retrieve user groups from BloodHound",
                details={"domain": domain, "username": username, "error": str(e)},
            ) from e

    def get_sessions(
        self,
        domain: str,
        domain_admin_only: bool = False,
        scan_id: Optional[str] = None,
    ) -> List[Dict[str, str]]:
        """Get user sessions (PRO feature).

        Args:
            domain: Domain name
            domain_admin_only: Return only DA sessions on non-DC computers (default: False)
            scan_id: Optional scan ID for progress tracking

        Returns:
            List of session dictionaries with keys:
                - computer: Computer name
                - user: Username (if domain_admin_only=True)

        Raises:
            BloodHoundServiceError: If query fails
            LicenseError: If called with LITE license
        """
        self._emit_progress(
            scan_id=scan_id,
            phase="bloodhound_session_analysis",
            progress=0.0,
            message=f"Analyzing sessions in {domain}",
        )

        try:
            sessions = self.client.get_sessions(domain, da=domain_admin_only)

            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_session_analysis",
                progress=1.0,
                message=f"Found {len(sessions)} sessions",
            )

            self.logger.info(
                f"Retrieved {len(sessions)} sessions",
                extra={
                    "domain": domain,
                    "domain_admin_only": domain_admin_only,
                    "count": len(sessions),
                },
            )

            return sessions

        except Exception as e:
            self.logger.exception(
                "Failed to get sessions from BloodHound",
                extra={
                    "domain": domain,
                    "domain_admin_only": domain_admin_only,
                    "error": str(e),
                },
            )
            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_session_analysis",
                progress=1.0,
                message="Session analysis failed",
            )
            raise BloodHoundServiceError(
                "Failed to retrieve sessions from BloodHound",
                details={"domain": domain, "error": str(e)},
            ) from e

    def get_critical_aces(
        self,
        source_domain: str,
        high_value: bool = False,
        username: str = "all",
        target_domain: str = "all",
        relation: str = "all",
        scan_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get critical ACEs (Access Control Entries) - PRO feature.

        Args:
            source_domain: Source domain to query
            high_value: Filter for high-value targets only (default: False)
            username: Source username filter (default: "all")
            target_domain: Target domain filter (default: "all")
            relation: Relation type filter (default: "all")
            scan_id: Optional scan ID for progress tracking

        Returns:
            List of ACE dictionaries with keys:
                - source: Source principal
                - sourceType: Source type (User, Group, Computer, etc.)
                - sourceDomain: Source domain
                - target: Target principal
                - targetType: Target type
                - targetDomain: Target domain
                - relation: ACE relation type
                - targetEnabled: Whether target is enabled

        Raises:
            BloodHoundServiceError: If query fails
            LicenseError: If called with LITE license
        """
        self._emit_progress(
            scan_id=scan_id,
            phase="bloodhound_ace_analysis",
            progress=0.0,
            message="Analyzing critical ACEs",
        )

        try:
            aces = self.client.get_critical_aces(
                source_domain=source_domain,
                high_value=high_value,
                username=username,
                target_domain=target_domain,
                relation=relation,
            )

            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_ace_analysis",
                progress=1.0,
                message=f"Found {len(aces)} critical ACEs",
            )

            self.logger.info(
                f"Retrieved {len(aces)} critical ACEs",
                extra={
                    "source_domain": source_domain,
                    "high_value": high_value,
                    "username": username,
                    "target_domain": target_domain,
                    "relation": relation,
                    "count": len(aces),
                },
            )

            return aces

        except Exception as e:
            self.logger.exception(
                "Failed to get critical ACEs from BloodHound",
                extra={
                    "source_domain": source_domain,
                    "high_value": high_value,
                    "username": username,
                    "target_domain": target_domain,
                    "relation": relation,
                    "error": str(e),
                },
            )
            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_ace_analysis",
                progress=1.0,
                message="ACE analysis failed",
            )
            raise BloodHoundServiceError(
                "Failed to retrieve critical ACEs from BloodHound",
                details={"source_domain": source_domain, "error": str(e)},
            ) from e

    def get_users_with_dc_access(
        self,
        domain: str,
        scan_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get users with access to Domain Controllers (CE only).

        Args:
            domain: Domain name.
            scan_id: Optional scan ID for progress tracking.

        Returns:
            List of access dictionaries (keys: source, target, path).

        Raises:
            BloodHoundServiceError: If query fails.
        """
        self._emit_progress(
            scan_id=scan_id,
            phase="bloodhound_path_analysis",
            progress=0.0,
            message="Querying BloodHound for DC access paths",
        )

        try:
            if not hasattr(self.client, "get_users_with_dc_access"):
                raise BloodHoundServiceError(
                    "DC access queries are not supported by this BloodHound client",
                    details={"edition": self.edition},
                )

            paths = self.client.get_users_with_dc_access(domain)

            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_path_analysis",
                progress=1.0,
                message=f"Retrieved {len(paths)} access path(s)",
            )

            self.logger.info(
                f"Retrieved {len(paths)} DC access path(s)",
                extra={"domain": domain, "count": len(paths)},
            )
            return paths

        except Exception as e:
            self.logger.exception(
                "Failed to retrieve DC access paths",
                extra={"domain": domain, "error": str(e)},
            )
            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_path_analysis",
                progress=1.0,
                message="DC access query failed",
            )
            raise BloodHoundServiceError(
                "Failed to retrieve DC access paths from BloodHound",
                details={"domain": domain, "error": str(e)},
            ) from e

    def get_low_priv_paths_to_high_value(
        self,
        domain: str,
        *,
        max_depth: int = 4,
        scan_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get low-privilege paths to high-value targets (CE only)."""
        self._emit_progress(
            scan_id=scan_id,
            phase="bloodhound_path_analysis",
            progress=0.0,
            message="Querying low-privilege paths to high-value targets",
        )

        try:
            if not hasattr(self.client, "get_low_priv_paths_to_high_value"):
                raise BloodHoundServiceError(
                    "Low-privilege path queries are not supported by this BloodHound client",
                    details={"edition": self.edition},
                )

            paths = self.client.get_low_priv_paths_to_high_value(
                domain, max_depth=max_depth
            )

            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_path_analysis",
                progress=1.0,
                message=f"Retrieved {len(paths)} path(s)",
            )

            self.logger.info(
                f"Retrieved {len(paths)} low-priv path(s)",
                extra={"domain": domain, "count": len(paths), "max_depth": max_depth},
            )
            return paths
        except Exception as e:
            self.logger.exception(
                "Failed to retrieve low-privilege paths",
                extra={"domain": domain, "error": str(e), "max_depth": max_depth},
            )
            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_path_analysis",
                progress=1.0,
                message="Low-privilege path query failed",
            )
            raise BloodHoundServiceError(
                "Failed to retrieve low-privilege paths from BloodHound",
                details={"domain": domain, "error": str(e)},
            ) from e

    def get_low_priv_acl_paths(
        self,
        domain: str,
        *,
        max_results: int = 1000,
        scan_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get low-privilege ACL/ACE effective paths (CE only)."""
        self._emit_progress(
            scan_id=scan_id,
            phase="bloodhound_path_analysis",
            progress=0.0,
            message="Querying low-privilege ACL/ACE relationships",
        )

        try:
            if not hasattr(self.client, "get_low_priv_acl_paths"):
                raise BloodHoundServiceError(
                    "Low-privilege ACL queries are not supported by this BloodHound client",
                    details={"edition": self.edition},
                )

            paths = self.client.get_low_priv_acl_paths(domain, max_results=max_results)

            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_path_analysis",
                progress=1.0,
                message=f"Retrieved {len(paths)} ACL path(s)",
            )

            self.logger.info(
                f"Retrieved {len(paths)} low-priv ACL path(s)",
                extra={
                    "domain": domain,
                    "count": len(paths),
                    "max_results": max_results,
                },
            )
            return paths
        except Exception as e:
            self.logger.exception(
                "Failed to retrieve low-privilege ACL paths",
                extra={"domain": domain, "error": str(e), "max_results": max_results},
            )
            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_path_analysis",
                progress=1.0,
                message="Low-privilege ACL path query failed",
            )
            raise BloodHoundServiceError(
                "Failed to retrieve low-privilege ACL paths from BloodHound",
                details={"domain": domain, "error": str(e)},
            ) from e

    def get_low_priv_adcs_paths(
        self,
        domain: str,
        *,
        max_results: int = 1000,
        scan_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get low-privilege ADCS escalation paths (CE only)."""
        self._emit_progress(
            scan_id=scan_id,
            phase="bloodhound_path_analysis",
            progress=0.0,
            message="Querying ADCS escalation relationships",
        )

        try:
            if not hasattr(self.client, "get_low_priv_adcs_paths"):
                raise BloodHoundServiceError(
                    "ADCS path queries are not supported by this BloodHound client",
                    details={"edition": self.edition},
                )

            paths = self.client.get_low_priv_adcs_paths(domain, max_results=max_results)

            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_path_analysis",
                progress=1.0,
                message=f"Retrieved {len(paths)} ADCS path(s)",
            )

            self.logger.info(
                f"Retrieved {len(paths)} ADCS path(s)",
                extra={
                    "domain": domain,
                    "count": len(paths),
                    "max_results": max_results,
                },
            )
            return paths
        except Exception as e:
            self.logger.exception(
                "Failed to retrieve ADCS paths",
                extra={"domain": domain, "error": str(e), "max_results": max_results},
            )
            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_path_analysis",
                progress=1.0,
                message="ADCS path query failed",
            )
            raise BloodHoundServiceError(
                "Failed to retrieve ADCS paths from BloodHound",
                details={"domain": domain, "error": str(e)},
            ) from e

    def get_low_priv_access_paths(
        self,
        domain: str,
        *,
        max_results: int = 1000,
        scan_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get low-privilege access/session paths (CE only)."""
        self._emit_progress(
            scan_id=scan_id,
            phase="bloodhound_path_analysis",
            progress=0.0,
            message="Querying access/session relationships",
        )

        try:
            if not hasattr(self.client, "get_low_priv_access_paths"):
                raise BloodHoundServiceError(
                    "Access/session path queries are not supported by this BloodHound client",
                    details={"edition": self.edition},
                )

            paths = self.client.get_low_priv_access_paths(
                domain, max_results=max_results
            )

            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_path_analysis",
                progress=1.0,
                message=f"Retrieved {len(paths)} access path(s)",
            )

            self.logger.info(
                f"Retrieved {len(paths)} access path(s)",
                extra={
                    "domain": domain,
                    "count": len(paths),
                    "max_results": max_results,
                },
            )
            return paths
        except Exception as e:
            self.logger.exception(
                "Failed to retrieve access/session paths",
                extra={"domain": domain, "error": str(e), "max_results": max_results},
            )
            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_path_analysis",
                progress=1.0,
                message="Access/session path query failed",
            )
            raise BloodHoundServiceError(
                "Failed to retrieve access/session paths from BloodHound",
                details={"domain": domain, "error": str(e)},
            ) from e

    def get_high_value_session_paths(
        self,
        domain: str,
        *,
        max_results: int = 1000,
        scan_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get computer→high-value-user session paths (CE only)."""
        self._emit_progress(
            scan_id=scan_id,
            phase="bloodhound_path_analysis",
            progress=0.0,
            message="Querying high-value user session relationships",
        )

        try:
            if not hasattr(self.client, "get_high_value_session_paths"):
                raise BloodHoundServiceError(
                    "High-value session path queries are not supported by this BloodHound client",
                    details={"edition": self.edition},
                )

            paths = self.client.get_high_value_session_paths(
                domain, max_results=max_results
            )

            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_path_analysis",
                progress=1.0,
                message=f"Retrieved {len(paths)} high-value session path(s)",
            )

            self.logger.info(
                f"Retrieved {len(paths)} high-value session path(s)",
                extra={
                    "domain": domain,
                    "count": len(paths),
                    "max_results": max_results,
                },
            )
            return paths
        except Exception as e:
            self.logger.exception(
                "Failed to retrieve high-value session paths",
                extra={"domain": domain, "error": str(e), "max_results": max_results},
            )
            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_path_analysis",
                progress=1.0,
                message="High-value session path query failed",
            )
            raise BloodHoundServiceError(
                "Failed to retrieve high-value session paths from BloodHound",
                details={"domain": domain, "error": str(e)},
            ) from e

    def get_low_priv_delegation_paths(
        self,
        domain: str,
        *,
        max_results: int = 1000,
        scan_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get low-privilege delegation paths (CE only)."""
        self._emit_progress(
            scan_id=scan_id,
            phase="bloodhound_path_analysis",
            progress=0.0,
            message="Querying delegation relationships",
        )

        try:
            if not hasattr(self.client, "get_low_priv_delegation_paths"):
                raise BloodHoundServiceError(
                    "Delegation path queries are not supported by this BloodHound client",
                    details={"edition": self.edition},
                )

            paths = self.client.get_low_priv_delegation_paths(
                domain, max_results=max_results
            )

            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_path_analysis",
                progress=1.0,
                message=f"Retrieved {len(paths)} delegation path(s)",
            )

            self.logger.info(
                f"Retrieved {len(paths)} delegation path(s)",
                extra={
                    "domain": domain,
                    "count": len(paths),
                    "max_results": max_results,
                },
            )
            return paths
        except Exception as e:
            self.logger.exception(
                "Failed to retrieve delegation paths",
                extra={"domain": domain, "error": str(e), "max_results": max_results},
            )
            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_path_analysis",
                progress=1.0,
                message="Delegation path query failed",
            )
            raise BloodHoundServiceError(
                "Failed to retrieve delegation paths from BloodHound",
                details={"domain": domain, "error": str(e)},
            ) from e

    def get_roastable_asreproast_users(
        self,
        domain: str,
        *,
        max_results: int = 1000,
        scan_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get enabled ASREPRoastable users (CE only)."""
        self._emit_progress(
            scan_id=scan_id,
            phase="bloodhound_path_analysis",
            progress=0.0,
            message="Querying ASREPRoastable users",
        )

        try:
            if not hasattr(self.client, "get_roastable_asreproast_users"):
                raise BloodHoundServiceError(
                    "ASREPRoastable user queries are not supported by this BloodHound client",
                    details={"edition": self.edition},
                )

            users = self.client.get_roastable_asreproast_users(
                domain, max_results=max_results
            )

            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_path_analysis",
                progress=1.0,
                message=f"Retrieved {len(users)} ASREPRoastable user(s)",
            )

            self.logger.info(
                f"Retrieved {len(users)} ASREPRoastable user(s)",
                extra={
                    "domain": domain,
                    "count": len(users),
                    "max_results": max_results,
                },
            )
            return users
        except Exception as e:
            self.logger.exception(
                "Failed to retrieve ASREPRoastable users",
                extra={"domain": domain, "error": str(e), "max_results": max_results},
            )
            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_path_analysis",
                progress=1.0,
                message="ASREPRoastable user query failed",
            )
            raise BloodHoundServiceError(
                "Failed to retrieve ASREPRoastable users from BloodHound",
                details={"domain": domain, "error": str(e)},
            ) from e

    def get_roastable_kerberoast_users(
        self,
        domain: str,
        *,
        max_results: int = 1000,
        scan_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get enabled kerberoastable user accounts (CE only)."""
        self._emit_progress(
            scan_id=scan_id,
            phase="bloodhound_path_analysis",
            progress=0.0,
            message="Querying kerberoastable users",
        )

        try:
            if not hasattr(self.client, "get_roastable_kerberoast_users"):
                raise BloodHoundServiceError(
                    "Kerberoastable user queries are not supported by this BloodHound client",
                    details={"edition": self.edition},
                )

            users = self.client.get_roastable_kerberoast_users(
                domain, max_results=max_results
            )

            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_path_analysis",
                progress=1.0,
                message=f"Retrieved {len(users)} kerberoastable user(s)",
            )

            self.logger.info(
                f"Retrieved {len(users)} kerberoastable user(s)",
                extra={
                    "domain": domain,
                    "count": len(users),
                    "max_results": max_results,
                },
            )
            return users
        except Exception as e:
            self.logger.exception(
                "Failed to retrieve kerberoastable users",
                extra={"domain": domain, "error": str(e), "max_results": max_results},
            )
            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_path_analysis",
                progress=1.0,
                message="Kerberoastable user query failed",
            )
            raise BloodHoundServiceError(
                "Failed to retrieve kerberoastable users from BloodHound",
                details={"domain": domain, "error": str(e)},
            ) from e

    def get_last_query_error(self) -> str | None:
        """Return the last query error message from the underlying client."""
        client = getattr(self, "client", None)
        if client and hasattr(client, "get_last_error"):
            return client.get_last_error()
        return None

    def get_last_client_error(self) -> str | None:
        """Return last client-level error (query/upload/auth), if available."""
        client = getattr(self, "client", None)
        if client and hasattr(client, "get_last_error"):
            return client.get_last_error()
        return None

    def get_access_paths(
        self,
        source: str,
        target: str,
        domain: str,
        connection: str = "all",
        scan_id: Optional[str] = None,
    ) -> List[Dict[str, str]]:
        """Get access paths between source and target - PRO feature.

        Args:
            source: Source object name
            target: Target object name (or "all", "dcs")
            domain: Domain to query
            connection: Connection type ("all", "AdminTo", "CanRDP", "CanPSRemote")
            scan_id: Optional scan ID for progress tracking

        Returns:
            List of path dictionaries with keys:
                - source: Source principal
                - target: Target principal
                - relation: Relation type
                - path: Path description

        Raises:
            BloodHoundServiceError: If query fails
            LicenseError: If called with LITE license
        """
        self._emit_progress(
            scan_id=scan_id,
            phase="bloodhound_path_analysis",
            progress=0.0,
            message=f"Finding access paths from {source} to {target}",
        )

        try:
            paths = self.client.get_access_paths(
                source=source,
                connection=connection,
                target=target,
                domain=domain,
            )

            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_path_analysis",
                progress=1.0,
                message=f"Found {len(paths)} access paths",
            )

            self.logger.info(
                f"Retrieved {len(paths)} access paths",
                extra={
                    "source": source,
                    "target": target,
                    "domain": domain,
                    "connection": connection,
                    "count": len(paths),
                },
            )

            return paths

        except Exception as e:
            self.logger.exception(
                "Failed to get access paths from BloodHound",
                extra={
                    "source": source,
                    "target": target,
                    "domain": domain,
                    "connection": connection,
                    "error": str(e),
                },
            )
            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_path_analysis",
                progress=1.0,
                message="Path analysis failed",
            )
            raise BloodHoundServiceError(
                "Failed to retrieve access paths from BloodHound",
                details={"source": source, "target": target, "error": str(e)},
            ) from e

    def execute_query(
        self, query: str, scan_id: Optional[str] = None, **params
    ) -> List[Dict[str, Any]]:
        """Execute a custom Cypher query.

        Args:
            query: Cypher query string
            scan_id: Optional scan ID for progress tracking
            **params: Query parameters

        Returns:
            List of result dictionaries

        Raises:
            BloodHoundServiceError: If query fails
        """
        self._emit_progress(
            scan_id=scan_id,
            phase="bloodhound_custom_query",
            progress=0.0,
            message="Executing custom BloodHound query",
        )

        try:
            results = self.client.execute_query(query, **params)

            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_custom_query",
                progress=1.0,
                message=f"Query returned {len(results)} results",
            )

            self.logger.info(
                f"Executed custom query: {len(results)} results",
                extra={"query_preview": query[:100], "count": len(results)},
            )

            return results

        except Exception as e:
            self.logger.exception(
                "Failed to execute BloodHound query",
                extra={"query_preview": query[:100], "error": str(e)},
            )
            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_custom_query",
                progress=1.0,
                message="Query execution failed",
            )
            raise BloodHoundServiceError(
                "Failed to execute BloodHound query",
                details={"error": str(e)},
            ) from e

    def upload_data(
        self,
        file_path: str,
        wait: bool = True,
        poll_interval: int = 5,
        timeout: int = 1800,
        scan_id: Optional[str] = None,
    ) -> bool:
        """Upload BloodHound data file (CE only).

        Args:
            file_path: Path to ZIP file to upload
            wait: Wait for ingestion to complete (default: True)
            poll_interval: Seconds between status checks (default: 5)
            timeout: Maximum seconds to wait for completion (default: 1800)
            scan_id: Optional scan ID for progress tracking

        Returns:
            True if upload succeeded, False otherwise

        Raises:
            BloodHoundServiceError: If upload fails or edition is not CE
        """
        if self.edition != "ce":
            raise BloodHoundServiceError(
                "Data upload is only available for BloodHound CE",
                details={"edition": self.edition},
            )

        self._emit_progress(
            scan_id=scan_id,
            phase="bloodhound_upload",
            progress=0.0,
            message=f"Uploading BloodHound data: {file_path}",
        )

        try:
            if wait:
                job_id = self.start_upload_job(file_path, scan_id=scan_id)
                success = (
                    self.wait_for_upload_job(
                        job_id,
                        poll_interval=poll_interval,
                        timeout=timeout,
                        scan_id=scan_id,
                    )
                    if job_id is not None
                    else False
                )
            else:
                success = self.start_upload_job(file_path, scan_id=scan_id) is not None

            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_upload",
                progress=1.0,
                message="Upload completed successfully" if success else "Upload failed",
            )

            self.logger.info(
                f"BloodHound upload {'succeeded' if success else 'failed'}",
                extra={"file_path": file_path, "wait": wait, "success": success},
            )

            return success

        except Exception as e:
            self.logger.exception(
                "Failed to upload BloodHound data",
                extra={"file_path": file_path, "error": str(e)},
            )
            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_upload",
                progress=1.0,
                message="Upload failed",
            )
            raise BloodHoundServiceError(
                "Failed to upload BloodHound data",
                details={"file_path": file_path, "error": str(e)},
            ) from e

    def start_upload_job(
        self, file_path: str, scan_id: Optional[str] = None
    ) -> int | None:
        """Start a CE upload job for a file and return the job id.

        Note: This starts the job and uploads the file, but does not wait for ingestion.
        """
        if self.edition != "ce":
            raise BloodHoundServiceError(
                "Data upload is only available for BloodHound CE",
                details={"edition": self.edition},
            )

        self._emit_progress(
            scan_id=scan_id,
            phase="bloodhound_upload",
            progress=0.0,
            message=f"Uploading BloodHound data: {file_path}",
        )

        try:
            job_id = getattr(self.client, "start_file_upload_job")(file_path)
            self.logger.info(
                "BloodHound upload job started",
                extra={"file_path": file_path, "job_id": job_id},
            )
            return int(job_id) if job_id is not None else None
        except Exception as e:
            self.logger.exception(
                "Failed to start BloodHound upload job",
                extra={"file_path": file_path, "error": str(e)},
            )
            raise

    def wait_for_upload_job(
        self,
        job_id: int,
        *,
        poll_interval: int = 5,
        timeout: int = 1800,
        scan_id: Optional[str] = None,
    ) -> bool:
        """Wait for ingestion of a specific CE upload job id."""
        if self.edition != "ce":
            raise BloodHoundServiceError(
                "Data upload is only available for BloodHound CE",
                details={"edition": self.edition},
            )

        try:
            success = getattr(self.client, "wait_for_file_upload_job")(
                int(job_id), poll_interval=poll_interval, timeout_seconds=timeout
            )
            self._emit_progress(
                scan_id=scan_id,
                phase="bloodhound_upload",
                progress=1.0,
                message="Upload completed successfully" if success else "Upload failed",
            )
            self.logger.info(
                "BloodHound upload job complete",
                extra={"job_id": job_id, "success": success},
            )
            return bool(success)
        except Exception as e:
            self.logger.exception(
                "Failed waiting for BloodHound upload job",
                extra={"job_id": job_id, "error": str(e)},
            )
            raise

    def close(self):
        """Close BloodHound client connection."""
        if hasattr(self, "client") and self.client:
            try:
                self.client.close()
                self.logger.info("BloodHound client connection closed")
            except Exception as e:
                self.logger.warning(
                    f"Error closing BloodHound client: {e}",
                    extra={"error": str(e)},
                )

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
