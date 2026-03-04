"""
BloodHound CE implementation using HTTP API
"""

# pylint: skip-file
import configparser
import os
from json import JSONDecodeError
from typing import List, Dict, Optional
from pathlib import Path
import requests
from .base import BloodHoundClient
from .logging_utils import get_logger
from .settings import (
    CONFIG_FILE,
    BLOODHOUND_CE_DEFAULT_WEB_PORT,
    validate_ce_config,
    write_ce_config,
    write_ce_config_skeleton,
)
from adscan_internal.rich_output import (
    mark_sensitive,
    print_error,
    print_info,
    print_info_debug,
    print_success,
    print_warning,
)


def _get_default_admin_password() -> str:
    """Return default BloodHound CE admin password override if set."""
    return (
        os.getenv("ADSCAN_BLOODHOUND_ADMIN_PASSWORD")
        or os.getenv("ADSCAN_BH_ADMIN_PASSWORD")
        or "Adscan4thewin!"
    )


class BloodHoundCEClient(BloodHoundClient):
    """BloodHound CE client using HTTP API."""

    def __init__(
        self,
        base_url: str = None,
        api_token: Optional[str] = None,
        debug: bool = False,
        verbose: bool = False,
        verify: bool = True,
    ):
        super().__init__(debug, verbose)

        # Try to load configuration from ~/.bloodhound_config
        config = self._load_config()
        if config:
            # Convert base_url to string (handles Pydantic AnyHttpUrl objects)
            config_base_url = config.get("base_url")
            if config_base_url is not None:
                self.base_url = self._normalize_base_url(config_base_url)
            else:
                # Convert base_url parameter to string if it's a Pydantic URL object
                default_url = f"http://localhost:{BLOODHOUND_CE_DEFAULT_WEB_PORT}"
                self.base_url = str(base_url or default_url).rstrip("/")
            self.api_token = config.get("api_token", api_token)
        else:
            # Convert base_url to string (handles Pydantic AnyHttpUrl objects)
            default_url = f"http://localhost:{BLOODHOUND_CE_DEFAULT_WEB_PORT}"
            self.base_url = str(base_url or default_url).rstrip("/")
            self.api_token = api_token

        self.verify = verify
        self.session = requests.Session()
        if self.api_token:
            self.session.headers.update({"Authorization": f"Bearer {self.api_token}"})
        self.logger = get_logger("BloodHoundCE", base_url=self.base_url)
        # Store credentials for token renewal
        self._stored_username = None
        self._stored_password = None
        self._last_error: str | None = None

    @staticmethod
    def _normalize_base_url(raw_url: Optional[str]) -> str:
        """Normalize a base_url loaded from config, migrating old defaults.

        Older versions used http://localhost:8080 as the default CE URL. New
        installs use BLOODHOUND_CE_DEFAULT_WEB_PORT instead (for example 8442).
        If the user has not customized the URL and it still points to the old
        default, transparently migrate it to the new default so that CE is
        reachable without manual config edits.
        """
        default_url = f"http://localhost:{BLOODHOUND_CE_DEFAULT_WEB_PORT}"
        if not raw_url:
            return default_url

        stripped = str(raw_url).rstrip("/")
        old_defaults = {
            "http://localhost:8080",
            "http://127.0.0.1:8080",
        }
        if stripped in old_defaults:
            return default_url
        return stripped

    def _debug(self, message: str, **context) -> None:
        if self.debug:
            self.logger.debug(message, **context)

    def _load_config(self) -> Optional[Dict[str, str]]:
        """Load configuration from the resolved config path."""
        config_path = str(CONFIG_FILE)
        if not os.path.exists(config_path):
            return None

        try:
            config = configparser.ConfigParser()
            config.read(config_path)

            if "CE" in config:
                return {
                    "base_url": config["CE"].get("base_url"),
                    "api_token": config["CE"].get("api_token"),
                }
        except Exception:
            pass

        return None

    def authenticate(
        self, username: str, password: str, login_path: str = "/api/v2/login"
    ) -> Optional[str]:
        """Authenticate against CE and return token"""
        url = f"{self.base_url}{login_path}"
        try:
            payload = {
                "login_method": "secret",
                "username": username,
                "secret": password,
            }
            # Remove stale token headers before logging in
            self.session.headers.pop("Authorization", None)
            response = self.session.post(
                url, json=payload, verify=self.verify, timeout=60
            )

            if response.status_code == 200:
                data = response.json()
                token = data.get("data", {}).get("session_token")
                if token:
                    self.api_token = token
                    self.session.headers.update({"Authorization": f"Bearer {token}"})
                    # Store credentials for token renewal
                    self._stored_username = username
                    self._stored_password = password
                    return token
            return None
        except Exception:
            return None

    def execute_query(self, query: str, **params) -> List[Dict]:
        """Execute a Cypher query using BloodHound CE API"""
        try:
            url = f"{self.base_url}/api/v2/graphs/cypher"

            # Clean up query: normalize whitespace but preserve structure
            # Using split() + join() preserves all non-whitespace characters
            cleaned_query = " ".join(query.split())

            payload = {"query": cleaned_query, "include_properties": True}

            self._debug(
                "executing cypher query",
                raw_query=query,
                cleaned_query=cleaned_query,
                url=url,
                params=params,
            )

            response = self.session.post(
                url, json=payload, verify=self.verify, timeout=60
            )

            # Handle authentication errors by attempting token renewal
            if response.status_code == 401:
                self._debug("authentication failed, attempting token renewal")
                if self.ensure_authenticated_robust():
                    # Retry the request with renewed token
                    response = self.session.post(
                        url, json=payload, verify=self.verify, timeout=60
                    )
                    self._debug(
                        "cypher query retry response",
                        status=response.status_code,
                    )
                else:
                    self._debug(
                        "token renewal failed",
                        status=response.status_code,
                        response_text=response.text,
                    )
                    return []

            if response.status_code == 200:
                data = response.json()
                self._debug(
                    "cypher response",
                    keys=list(data.keys()) if isinstance(data, dict) else "non-dict",
                )

                # BloodHound CE returns data in a different format
                if "data" in data and "nodes" in data["data"]:
                    # Convert nodes to list format
                    nodes = []
                    for node_id, node_data in data["data"]["nodes"].items():
                        if "properties" in node_data:
                            nodes.append(node_data["properties"])
                    return nodes
                return []
            else:
                self._debug(
                    "cypher query failed",
                    status=response.status_code,
                    response_text=response.text,
                )
                return []

        except JSONDecodeError as json_error:
            self._debug("failed to parse CE response", error=str(json_error))
            return []
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._debug("cypher query error", error=str(exc))
            return []

    def execute_query_rows(self, query: str) -> List[Dict]:
        """Execute a Cypher query and return row data (non-node results)."""
        try:
            url = f"{self.base_url}/api/v2/graphs/cypher"

            cleaned_query = " ".join(query.split())
            payload = {"query": cleaned_query, "include_properties": True}

            self._debug(
                "executing cypher rows query",
                raw_query=query,
                cleaned_query=cleaned_query,
                url=url,
            )

            response = self.session.post(
                url, json=payload, verify=self.verify, timeout=60
            )

            if response.status_code == 401:
                self._debug("authentication failed, attempting token renewal")
                if self.ensure_authenticated_robust():
                    response = self.session.post(
                        url, json=payload, verify=self.verify, timeout=60
                    )
                else:
                    self._debug(
                        "token renewal failed",
                        status=response.status_code,
                        response_text=response.text,
                    )
                    return []

            if response.status_code != 200:
                self._last_error = (
                    f"HTTP {response.status_code}: {response.text.strip()}"
                )
                self._debug(
                    "cypher rows query failed",
                    status=response.status_code,
                    response_text=response.text,
                )
                return []

            data = response.json()
            self._last_error = None
            payload_data = data.get("data", data)
            if isinstance(payload_data, dict):
                if "rows" in payload_data and isinstance(payload_data["rows"], list):
                    rows = payload_data["rows"]
                    columns = payload_data.get("columns")
                    if (
                        isinstance(columns, list)
                        and rows
                        and all(isinstance(row, list) for row in rows)
                    ):
                        return [dict(zip(columns, row, strict=False)) for row in rows]
                    return rows
                if "results" in payload_data and isinstance(
                    payload_data["results"], list
                ):
                    return payload_data["results"]
                if "data" in payload_data and isinstance(payload_data["data"], list):
                    return payload_data["data"]
            if isinstance(payload_data, list):
                return payload_data
            return []
        except JSONDecodeError as json_error:
            self._last_error = f"JSON decode error: {json_error}"
            self._debug("failed to parse rows response", error=str(json_error))
            return []
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._last_error = f"Query error: {exc}"
            self._debug("cypher rows query error", error=str(exc))
            return []

    def get_last_error(self) -> str | None:
        """Return the last query error message, if any."""
        return self._last_error

    def execute_query_with_relationships(self, query: str) -> Dict:
        """Execute a Cypher query and include relationships in the response"""
        try:
            url = f"{self.base_url}/api/v2/graphs/cypher"

            cleaned_query = " ".join(query.split())
            payload = {
                "query": cleaned_query,
                "include_properties": True,
                "include_relationships": True,
            }

            self._debug(
                "executing relationship query",
                raw_query=query,
                cleaned_query=cleaned_query,
            )

            response = self.session.post(
                url, json=payload, verify=self.verify, timeout=60
            )

            self._debug(
                "relationship query response",
                status=response.status_code,
                headers=dict(response.headers),
            )

            # Handle authentication errors by attempting token renewal
            if response.status_code == 401:
                self._debug("authentication failed, attempting token renewal")
                if self.ensure_authenticated_robust():
                    # Retry the request with renewed token
                    response = self.session.post(
                        url, json=payload, verify=self.verify, timeout=60
                    )
                    self._debug(
                        "relationship query retry response",
                        status=response.status_code,
                    )
                else:
                    self._debug(
                        "token renewal failed",
                        status=response.status_code,
                        response=response.text,
                    )
                    return {}

            if response.status_code == 200:
                data = response.json()
                self._debug(
                    "relationship query data",
                    has_data=isinstance(data, dict),
                    keys=list(data.keys()) if isinstance(data, dict) else None,
                )
                return data.get("data", {})

            self._debug(
                "relationship query failed",
                status=response.status_code,
                response=response.text,
            )
            return {}

        except JSONDecodeError as json_error:
            self._debug("failed to parse relationship response", error=str(json_error))
            return {}
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._debug("relationship query error", error=str(exc))
            return {}

    def get_users(self, domain: str) -> List[str]:
        """Get enabled users using CySQL query"""
        try:
            # Use CySQL query to get enabled users in specific domain
            cypher_query = f"""
            MATCH (u:User) 
            WHERE u.enabled = true AND toUpper(u.domain) = '{domain.upper()}'
            RETURN u
            """

            result = self.execute_query(cypher_query)
            users = []

            # execute_query returns a list of node properties
            if result and isinstance(result, list):
                for node_properties in result:
                    samaccountname = node_properties.get(
                        "samaccountname"
                    ) or node_properties.get("name", "")
                    if samaccountname:
                        # Extract just the username part (before @) if it's in UPN format
                        if "@" in samaccountname:
                            samaccountname = samaccountname.split("@")[0]
                        users.append(samaccountname)

            return users
        except Exception:
            return []

    def get_users_in_ou(self, domain: str, ou_distinguished_name: str) -> List[str]:
        """Get enabled users that belong to a specific OU using its distinguished name.

        Args:
            domain: AD domain name to filter users by (e.g. "north.sevenkingdoms.local").
            ou_distinguished_name: Distinguished Name (DN) of the OU to search under.

        Returns:
            List of `samaccountname` values for users that belong to the OU.
        """
        try:
            # Escape single quotes to avoid breaking the Cypher string
            sanitized_ou_dn = ou_distinguished_name.replace("'", "\\'")

            cypher_query = f"""
            MATCH (ou:OU)
            WHERE toLower(ou.distinguishedname) = toLower('{sanitized_ou_dn}')
            MATCH (u:User)
            WHERE u.enabled = true
              AND toUpper(u.domain) = '{domain.upper()}'
              AND toLower(u.distinguishedname) CONTAINS toLower(ou.distinguishedname)
            RETURN u
            """

            result = self.execute_query(cypher_query)
            users: List[str] = []

            if result and isinstance(result, list):
                for node_properties in result:
                    samaccountname = node_properties.get(
                        "samaccountname"
                    ) or node_properties.get("name", "")
                    if samaccountname:
                        if "@" in samaccountname:
                            samaccountname = samaccountname.split("@")[0]
                        users.append(samaccountname)

            return users
        except Exception:
            return []

    def get_computers(self, domain: str, laps: Optional[bool] = None) -> List[str]:
        """Get enabled computers using CySQL query"""
        try:
            # Build CySQL query with optional LAPS filter
            if laps is not None:
                laps_condition = "true" if laps else "false"
                cypher_query = f"""
                MATCH (c:Computer) 
                WHERE c.enabled = true AND c.haslaps = {laps_condition} AND toUpper(c.domain) = '{domain.upper()}'
                RETURN c
                """
            else:
                cypher_query = f"""
                MATCH (c:Computer) 
                WHERE c.enabled = true AND toUpper(c.domain) = '{domain.upper()}'
                RETURN c
                """

            result = self.execute_query(cypher_query)
            computers = []

            # execute_query returns a list of node properties
            if result and isinstance(result, list):
                for node_properties in result:
                    computer_name = node_properties.get("name", "")
                    if computer_name:
                        # Extract just the computer name part (before @) if it's in UPN format
                        if "@" in computer_name:
                            computer_name = computer_name.split("@")[0]

                        computers.append(computer_name.lower())

            return computers

        except Exception:
            return []

    def get_admin_users(self, domain: str) -> List[str]:
        """Get enabled admin users using CySQL query (admincount approach)"""
        try:
            # Use CySQL query to get enabled users with admincount = true in specific domain
            # Note: CySQL has stricter typing and different null handling
            cypher_query = f"""
            MATCH (u:User) 
            WHERE u.admincount = true AND u.enabled = true AND toUpper(u.domain) = '{domain.upper()}'
            RETURN u
            """

            result = self.execute_query(cypher_query)
            admin_users = []

            # execute_query returns a list of node properties
            if result and isinstance(result, list):
                for node_properties in result:
                    if node_properties.get("admincount") is True:
                        samaccountname = node_properties.get(
                            "samaccountname"
                        ) or node_properties.get("name", "")
                        if samaccountname:
                            # Extract just the username part (before @) if it's in UPN format
                            if "@" in samaccountname:
                                samaccountname = samaccountname.split("@")[0]
                            admin_users.append(samaccountname)

            return admin_users

        except Exception:
            return []

    def get_highvalue_users(self, domain: str) -> List[str]:
        """Get enabled high value users using CySQL query."""
        try:
            # High value users are tagged in system_tags (list) or highvalue flag.
            cypher_query = f"""
            MATCH (u:User) 
            WHERE (u.system_tags = "admin_tier_0"
               OR "admin_tier_0" IN u.system_tags
               OR u.highvalue = true)
              AND u.enabled = true AND toUpper(u.domain) = '{domain.upper()}'
            RETURN u
            """

            result = self.execute_query(cypher_query)
            highvalue_users = []

            # execute_query returns a list of node properties
            if result and isinstance(result, list):
                for node_properties in result:
                    samaccountname = node_properties.get(
                        "samaccountname"
                    ) or node_properties.get("name", "")
                    if samaccountname:
                        # Extract just the username part (before @) if it's in UPN format
                        if "@" in samaccountname:
                            samaccountname = samaccountname.split("@")[0]
                        highvalue_users.append(samaccountname)

            return highvalue_users

        except Exception:
            return []

    def get_password_not_required_users(self, domain: str) -> List[str]:
        """Get enabled users with password not required using CySQL query"""
        try:
            # Use CySQL query to get enabled users with passwordnotreqd = true in specific domain
            cypher_query = f"""
            MATCH (u:User) 
            WHERE u.passwordnotreqd = true AND u.enabled = true AND toUpper(u.domain) = '{domain.upper()}'
            RETURN u
            """

            result = self.execute_query(cypher_query)
            users = []

            # execute_query returns a list of node properties
            if result and isinstance(result, list):
                for node_properties in result:
                    samaccountname = node_properties.get(
                        "samaccountname"
                    ) or node_properties.get("name", "")
                    if samaccountname:
                        # Extract just the username part (before @) if it's in UPN format
                        if "@" in samaccountname:
                            samaccountname = samaccountname.split("@")[0]
                        users.append(samaccountname)

            return users

        except Exception:
            return []

    def get_domain_node(self, domain: str) -> Optional[Dict]:
        """Return the BloodHound `:Domain` node properties for a domain (best-effort)."""
        try:
            cypher_query = f"""
            MATCH (d:Domain)
            WHERE toLower(coalesce(d.name, d.domain, d.label, "")) = toLower('{domain}')
            RETURN d
            LIMIT 1
            """
            result = self.execute_query(cypher_query)
            if isinstance(result, list) and result:
                node_properties = result[0]
                if isinstance(node_properties, dict):
                    return node_properties
            return None
        except Exception:
            return None

    def get_user_node(self, domain: str, username: str) -> Optional[Dict]:
        """Return the BloodHound `:User` node properties for a domain given a username.

        Args:
            domain: Target domain (e.g. "north.sevenkingdoms.local").
            username: Username identifier. Prefer samAccountName (e.g. "jon.snow"),
                but UPN/name values may work depending on the dataset.

        Returns:
            Node properties dict when found, otherwise None.
        """
        try:
            domain_clean = (domain or "").strip()
            user_clean = (username or "").strip()
            if not domain_clean or "." not in domain_clean or not user_clean:
                return None

            sanitized_user = user_clean.replace("'", "\\'")
            cypher_query = f"""
            MATCH (u:User)
            WHERE toLower(coalesce(u.domain, "")) = toLower('{domain_clean}')
              AND (
                toLower(coalesce(u.samaccountname, "")) = toLower('{sanitized_user}')
                OR toLower(coalesce(u.name, "")) = toLower('{sanitized_user}')
              )
            RETURN u
            LIMIT 1
            """
            result = self.execute_query(cypher_query)
            if isinstance(result, list) and result:
                node_properties = result[0]
                if isinstance(node_properties, dict):
                    return node_properties
            return None
        except Exception:
            return None

    def get_computer_node(self, domain: str, fqdn: str) -> Optional[Dict]:
        """Return the BloodHound `:Computer` node properties for a domain given a host/FQDN.

        Args:
            domain: Target domain (e.g. "north.sevenkingdoms.local").
            fqdn: Hostname/FQDN to look up (e.g. "castelblack.north.sevenkingdoms.local").

        Returns:
            Node properties dict when found, otherwise None.
        """
        try:
            domain_clean = (domain or "").strip()
            fqdn_clean = (fqdn or "").strip().rstrip(".")
            if not domain_clean or "." not in domain_clean or not fqdn_clean:
                return None

            cypher_query = f"""
            MATCH (c:Computer)
            WHERE toLower(coalesce(c.domain, "")) = toLower('{domain_clean}')
              AND toLower(coalesce(c.name, "")) = toLower('{fqdn_clean}')
            RETURN c
            LIMIT 1
            """
            result = self.execute_query(cypher_query)
            if isinstance(result, list) and result:
                node_properties = result[0]
                if isinstance(node_properties, dict):
                    return node_properties
            return None
        except Exception:
            return None

    def get_password_never_expires_users(self, domain: str) -> List[str]:
        """Get enabled users with password never expires using CySQL query"""
        try:
            # Use CySQL query to get enabled users with pwdneverexpires = true in specific domain
            cypher_query = f"""
            MATCH (u:User) 
            WHERE u.pwdneverexpires = true AND u.enabled = true AND toUpper(u.domain) = '{domain.upper()}'
            RETURN u
            """

            result = self.execute_query(cypher_query)
            users = []

            # execute_query returns a list of node properties
            if result and isinstance(result, list):
                for node_properties in result:
                    samaccountname = node_properties.get(
                        "samaccountname"
                    ) or node_properties.get("name", "")
                    if samaccountname:
                        # Extract just the username part (before @) if it's in UPN format
                        if "@" in samaccountname:
                            samaccountname = samaccountname.split("@")[0]
                        users.append(samaccountname)

            return users

        except Exception:
            return []

    def get_user_groups(
        self, domain: str, username: str, recursive: bool = True
    ) -> List[str]:
        """Get group memberships for a user (optionally recursive)"""
        try:
            membership_pattern = "-[:MemberOf*1..]->" if recursive else "-[:MemberOf]->"
            sanitized_user = username.replace("'", "\\'")

            cypher_query = f"""
            MATCH (u:User)
            WHERE u.enabled = true
              AND toLower(u.domain) = toLower('{domain}')
              AND (
                toLower(u.samaccountname) = toLower('{sanitized_user}')
                OR toLower(u.name) = toLower('{sanitized_user}')
              )
            MATCH (u){membership_pattern}(g:Group)
            RETURN DISTINCT g
            ORDER BY toLower(g.name)
            """

            result = self.execute_query(cypher_query)
            groups: List[str] = []

            if result and isinstance(result, list):
                for node_properties in result:
                    display_name = node_properties.get("name")
                    if not display_name:
                        group_domain = node_properties.get("domain")
                        samaccountname = node_properties.get("samaccountname")
                        if group_domain and samaccountname:
                            display_name = f"{group_domain}\\{samaccountname}"
                        else:
                            display_name = samaccountname or group_domain

                    if display_name:
                        groups.append(display_name)

            return groups

        except Exception:
            return []

    def get_sessions(self, domain: str, da: bool = False) -> List[Dict]:
        """Get user sessions using CySQL query"""
        try:
            if da:
                # Get sessions from computer perspective
                cypher_query = f"""
                MATCH (c:Computer)-[r:HasSession]->(u:User)
                WHERE toUpper(c.domain) = '{domain.upper()}' AND u.enabled = true
                RETURN c, u
                """
            else:
                # Get sessions from user perspective
                cypher_query = f"""
                MATCH (u:User)-[r:HasSession]->(c:Computer)
                WHERE toUpper(u.domain) = '{domain.upper()}' AND u.enabled = true
                RETURN u, c
                """

            result = self.execute_query(cypher_query)
            sessions = []

            if result and isinstance(result, list):
                for node_properties in result:
                    if da:
                        # Computer -> User session
                        computer_name = node_properties.get("name", "")
                        user_name = node_properties.get("samaccountname", "")
                        if computer_name and user_name:
                            # Extract just the computer name part (before @) if it's in UPN format
                            if "@" in computer_name:
                                computer_name = computer_name.split("@")[0]
                            # Extract just the username part (before @) if it's in UPN format
                            if "@" in user_name:
                                user_name = user_name.split("@")[0]
                            sessions.append(
                                {"computer": computer_name.lower(), "user": user_name}
                            )
                    else:
                        # User -> Computer session
                        user_name = node_properties.get("samaccountname", "")
                        computer_name = node_properties.get("name", "")
                        if user_name and computer_name:
                            # Extract just the username part (before @) if it's in UPN format
                            if "@" in user_name:
                                user_name = user_name.split("@")[0]
                            # Extract just the computer name part (before @) if it's in UPN format
                            if "@" in computer_name:
                                computer_name = computer_name.split("@")[0]
                            sessions.append(
                                {"user": user_name, "computer": computer_name.lower()}
                            )

            return sessions

        except Exception:
            return []

    def get_password_last_change(
        self, domain: str, user: Optional[str] = None
    ) -> List[Dict]:
        """Get password last change information using CySQL query"""
        try:
            if user:
                cypher_query = f"""
                MATCH (u:User)
                WHERE u.enabled = true AND toUpper(u.domain) = '{domain.upper()}'
                  AND u.samaccountname = '{user}'
                RETURN u
                """
            else:
                cypher_query = f"""
                MATCH (u:User)
                WHERE u.enabled = true AND toUpper(u.domain) = '{domain.upper()}'
                RETURN u
                """

            result = self.execute_query(cypher_query)
            password_info = []

            if result and isinstance(result, list):
                for node_properties in result:
                    samaccountname = node_properties.get("samaccountname", "")
                    pwdlastset = node_properties.get("pwdlastset", 0)
                    whencreated = node_properties.get("whencreated", 0)

                    if samaccountname:
                        # Extract just the username part (before @) if it's in UPN format
                        if "@" in samaccountname:
                            samaccountname = samaccountname.split("@")[0]

                        password_info.append(
                            {
                                "samaccountname": samaccountname,
                                "pwdlastset": pwdlastset,
                                "whencreated": whencreated,
                            }
                        )

            return password_info

        except Exception:
            return []

    def get_critical_aces(
        self,
        source_domain: str,
        high_value: bool = False,
        username: str = "all",
        target_domain: str = "all",
        relation: str = "all",
    ) -> List[Dict]:
        """Get critical ACEs using simplified Cypher query compatible with BloodHound CE"""
        try:
            # BloodHound CE doesn't support CASE or UNION, so we need simpler queries
            # We'll run two separate queries and combine results

            aces = []

            # Build filters
            username_filter = ""
            if username.lower() != "all":
                lowered = username.replace("'", "\\'")
                username_filter = (
                    " AND (toLower(n.samaccountname) = toLower('{value}') "
                    "OR toLower(n.name) = toLower('{value}'))"
                ).format(value=lowered)

            target_domain_filter = ""
            if target_domain.lower() != "all" and target_domain.lower() != "high-value":
                target_domain_filter = (
                    f" AND toLower(m.domain) = toLower('{target_domain}')"
                )

            high_value_filter = ""
            if high_value:
                # In BloodHound CE, tier 0 (high value) is tagged in system_tags (list) or highvalue flag.
                high_value_filter = (
                    ' AND (m.system_tags = "admin_tier_0" '
                    'OR "admin_tier_0" IN m.system_tags '
                    "OR m.highvalue = true)"
                )

            relation_filter = ""
            if relation.lower() != "all":
                relation_filter = f":{relation}"

            # Single query using *0.. to include both direct ACEs and through group membership
            # We return n, g, m, r so we can track the original source node (n) even when ACLs are through groups (g)
            cypher_query = f"""
            MATCH (n)-[:MemberOf*0..]->(g)-[r{relation_filter}]->(m)
            WHERE r.isacl = true
              AND toLower(n.domain) = toLower('{source_domain}')
              {username_filter}
              {target_domain_filter}
              {high_value_filter}
            RETURN n, g, m, r
            LIMIT 1000
            """

            result = self.execute_query_with_relationships(cypher_query)
            if result:
                aces.extend(
                    self._process_ace_results_from_graph(
                        result, source_domain, username
                    )
                )

            # Remove duplicates based on source, target, and relation
            unique_aces = []
            seen = set()
            for ace in aces:
                key = (ace["source"], ace["target"], ace["relation"])
                if key not in seen:
                    seen.add(key)
                    unique_aces.append(ace)

            return unique_aces

        except Exception as e:
            if self.debug:
                self._debug("exception processing critical aces", error=str(e))
            return []

    def _process_ace_results_from_graph(
        self, graph_data: Dict, source_domain: str = None, username: str = None
    ) -> List[Dict]:
        """Process ACE query results from BloodHound CE graph format"""
        aces = []

        nodes = graph_data.get("nodes", {})
        edges = graph_data.get("edges", [])  # edges is a list, not dict

        self._debug(
            "processing graph results", node_count=len(nodes), edge_count=len(edges)
        )

        # Find the original source node(s) (n) that match our search criteria
        # This is needed when ACLs are through groups (even nested groups) and the edge source is the group, not the original node
        # The query uses [:MemberOf*0..] which is recursive, so it handles nested groups automatically
        original_source_nodes = []
        if source_domain:
            for node_id, node_data in nodes.items():
                node_props = node_data.get("properties", {})
                node_kind = node_data.get("kind", "")
                node_domain = node_props.get("domain", "")

                # Look for User or Computer (not Group) with matching domain
                if node_kind in ["User", "Computer"]:
                    if node_domain and node_domain.upper() == source_domain.upper():
                        # If username is specified, check if it matches
                        if username and username.lower() != "all":
                            node_sam = node_props.get("samaccountname", "")
                            if node_sam and node_sam.lower() == username.lower():
                                original_source_nodes.append((node_id, node_data))
                                self._debug(
                                    "found source node",
                                    node=node_sam,
                                    node_id=node_id,
                                    kind=node_kind,
                                )
                        else:
                            # If no specific username, collect all matching User/Computer nodes
                            node_sam = node_props.get(
                                "samaccountname", ""
                            ) or node_props.get("name", "")
                            original_source_nodes.append((node_id, node_data))
                            self._debug(
                                "found source node",
                                node=node_sam,
                                node_id=node_id,
                                kind=node_kind,
                            )

        self._debug("identified original sources", count=len(original_source_nodes))

        # Process each edge (relationship) - edges is a list
        for edge_data in edges:
            source_id = str(
                edge_data.get("source")
            )  # Convert to string for dict lookup
            target_id = str(
                edge_data.get("target")
            )  # Convert to string for dict lookup
            edge_label = edge_data.get("label", "Unknown")

            # Get source and target node data
            source_node = nodes.get(source_id, {})
            target_node = nodes.get(target_id, {})

            source_kind = source_node.get("kind", "") if source_node else ""
            use_fallback = (
                not source_node
                or source_id not in nodes
                or (
                    original_source_nodes
                    and username
                    and username.lower() != "all"
                    and source_kind == "Group"
                )
            )
            if use_fallback:
                # Use the first matching original source node
                # If username was specified, there should be only one
                # If username was "all", all edges apply to all matching users
                if original_source_nodes:
                    _, original_node = original_source_nodes[0]
                    source_node = original_node
                    source_props = original_node.get("properties", {})
                    source_domain_value = source_props.get("domain", "N/A")
                    source_kind = original_node.get("kind", "Unknown")
                    self._debug(
                        "using fallback source node",
                        edge_source_id=source_id,
                        fallback_kind=source_kind,
                    )
                else:
                    source_props = {}
                    source_domain_value = "N/A"
            else:
                source_props = source_node.get("properties", {})
                source_domain_value = source_props.get("domain", "N/A")

            target_props = target_node.get("properties", {})

            # Extract source info
            source_name = source_props.get("samaccountname") or source_props.get(
                "name", ""
            )

            # Extract target info
            target_name = target_props.get("samaccountname") or target_props.get(
                "name", ""
            )
            target_domain = target_props.get("domain", "N/A")
            target_enabled = target_props.get("enabled", True)
            target_kind = target_node.get("kind", "Unknown")

            if source_name and target_name:
                # Extract just the name part (before @) if it's in UPN format
                if "@" in source_name:
                    source_name = source_name.split("@")[0]
                if "@" in target_name:
                    target_name = target_name.split("@")[0]

                aces.append(
                    {
                        "source": source_name,
                        "sourceType": source_kind,
                        "target": target_name,
                        "targetType": target_kind,
                        "relation": edge_label,
                        "sourceDomain": source_domain_value.lower()
                        if source_domain_value != "N/A"
                        else "N/A",
                        "targetDomain": target_domain.lower()
                        if target_domain != "N/A"
                        else "N/A",
                        "targetEnabled": target_enabled,
                    }
                )

        return aces

    def get_access_paths(
        self, source: str, connection: str, target: str, domain: str
    ) -> List[Dict]:
        """Get access paths using CySQL query - adapted from old_main.py"""
        try:
            # Determine relationship conditions
            if connection.lower() == "all":
                rel_condition = "AND type(r) IN ['AdminTo','CanRDP','CanPSRemote']"
                rel_pattern = "[r]->"
            else:
                rel_condition = ""
                rel_pattern = f"[r:{connection}]->"

            # Case 1: source != "all" and target == "all" - find what source can access
            if source.lower() != "all" and target.lower() == "all":
                cypher_query = f"""
                MATCH p = (n)-{rel_pattern}(m)
                WHERE toLower(n.samaccountname) = toLower('{source}')
                AND toLower(n.domain) = toLower('{domain}')
                AND m.enabled = true
                {rel_condition}
                RETURN n.samaccountname AS source, m.samaccountname AS target, type(r) AS relation
                """

            # Case 2: source == "all" and target == "all" - find all access paths in domain
            elif source.lower() == "all" and target.lower() == "all":
                cypher_query = f"""
                MATCH p = (n)-{rel_pattern}(m)
                WHERE toLower(n.domain) = toLower('{domain}')
                AND n.enabled = true
                AND m.enabled = true
                {rel_condition}
                RETURN n.samaccountname AS source, m.samaccountname AS target, type(r) AS relation
                """

            # Case 3: source != "all" and target == "dcs" - find users with DC access
            elif source.lower() != "all" and target.lower() == "dcs":
                cypher_query = f"""
                MATCH p = (n)-{rel_pattern}(m)
                WHERE toLower(n.samaccountname) = toLower('{source}')
                AND toLower(n.domain) = toLower('{domain}')
                AND m.enabled = true
                AND (m.operatingsystem CONTAINS 'Windows Server' OR m.operatingsystem CONTAINS 'Domain Controller')
                {rel_condition}
                RETURN n.samaccountname AS source, m.samaccountname AS target, type(r) AS relation
                """

            # Case 4: source == "all" and target == "dcs" - find all users with DC access
            elif source.lower() == "all" and target.lower() == "dcs":
                cypher_query = f"""
                MATCH p = (n)-{rel_pattern}(m)
                WHERE toLower(n.domain) = toLower('{domain}')
                AND n.enabled = true
                AND m.enabled = true
                AND (m.operatingsystem CONTAINS 'Windows Server' OR m.operatingsystem CONTAINS 'Domain Controller')
                {rel_condition}
                RETURN n.samaccountname AS source, m.samaccountname AS target, type(r) AS relation
                """

            # Case 5: specific source to specific target
            else:
                cypher_query = f"""
                MATCH p = (n)-{rel_pattern}(m)
                WHERE toLower(n.samaccountname) = toLower('{source}')
                AND toLower(n.domain) = toLower('{domain}')
                AND toLower(m.samaccountname) = toLower('{target}')
                AND m.enabled = true
                {rel_condition}
                RETURN n.samaccountname AS source, m.samaccountname AS target, type(r) AS relation
                """

            result = self.execute_query(cypher_query)
            paths = []

            if result and isinstance(result, list):
                for record in result:
                    source_name = record.get("source", "")
                    target_name = record.get("target", "")
                    relation = record.get("relation", "")

                    if source_name and target_name:
                        # Extract just the username part (before @) if it's in UPN format
                        if "@" in source_name:
                            source_name = source_name.split("@")[0]
                        if "@" in target_name:
                            target_name = target_name.split("@")[0]

                        paths.append(
                            {
                                "source": source_name,
                                "target": target_name,
                                "relation": relation,
                                "path": f"{source_name} -> {target_name} ({relation})",
                            }
                        )

            return paths

        except Exception:
            return []

    def get_users_with_dc_access(self, domain: str) -> List[Dict]:
        """Get users who have access to Domain Controllers"""
        try:
            # First try to find actual DCs
            cypher_query = f"""
            MATCH (u:User)-[r]->(dc:Computer)
            WHERE u.enabled = true AND toUpper(u.domain) = '{domain.upper()}'
              AND dc.enabled = true AND toUpper(dc.domain) = '{domain.upper()}'
              AND (dc.operatingsystem CONTAINS 'Windows Server' OR dc.operatingsystem CONTAINS 'Domain Controller')
            RETURN u.samaccountname AS user, dc.name AS dc, type(r) AS relation
            """

            result = self.execute_query(cypher_query)
            users_with_access = []

            if result and isinstance(result, list):
                for record in result:
                    user = record.get("user", "")
                    dc = record.get("dc", "")
                    relation = record.get("relation", "")

                    if user and dc:
                        # Extract just the username part (before @) if it's in UPN format
                        if "@" in user:
                            user = user.split("@")[0]
                        if "@" in dc:
                            dc = dc.split("@")[0]

                        users_with_access.append(
                            {
                                "source": user,
                                "target": dc,
                                "path": f"{user} -> {dc} ({relation})",
                            }
                        )

            # If no DCs found, try to find any user-computer relationships
            if not users_with_access:
                fallback_query = f"""
                MATCH (u:User)-[r]->(c:Computer)
                WHERE u.enabled = true AND toUpper(u.domain) = '{domain.upper()}'
                  AND c.enabled = true AND toUpper(c.domain) = '{domain.upper()}'
                RETURN u.samaccountname AS user, c.name AS computer, type(r) AS relation
                """

                result = self.execute_query(fallback_query)

                if result and isinstance(result, list):
                    for record in result:
                        user = record.get("user", "")
                        computer = record.get("computer", "")
                        relation = record.get("relation", "")

                        if user and computer:
                            # Extract just the username part (before @) if it's in UPN format
                            if "@" in user:
                                user = user.split("@")[0]
                            if "@" in computer:
                                computer = computer.split("@")[0]

                            users_with_access.append(
                                {
                                    "source": user,
                                    "target": computer,
                                    "path": f"{user} -> {computer} ({relation})",
                                }
                            )

            return users_with_access

        except Exception:
            return []

    def get_low_priv_paths_to_high_value(
        self, domain: str, *, max_depth: int = 4
    ) -> List[Dict]:
        """Return raw path rows from low-priv users to high-value targets."""
        try:
            depth = max(1, min(max_depth, 8))
            domain_value = domain.replace("'", "\\'")
            source_domain_filter = self._build_domain_filter(
                alias="u",
                domain_value=domain_value,
            )
            source_enabled_filter = self._build_enabled_filter(
                alias="u", default_true=True
            )
            source_high_value_filter = self._build_high_value_filter(alias="u")
            target_high_value_filter = self._build_high_value_filter(alias="h")
            intermediate_high_value_filter = self._build_high_value_filter(alias="n")

            cypher_query = f"""
            MATCH p=(u:User)-[*1..{depth}]->(h)
            WHERE {source_domain_filter}
              AND {source_enabled_filter}
              AND NOT {source_high_value_filter}
              AND {target_high_value_filter}
            WITH p, nodes(p) AS ns, last(nodes(p)) AS lastNode
            WHERE NONE(n IN ns WHERE n <> lastNode AND {intermediate_high_value_filter})
            RETURN p
            """

            graph_data = self.execute_query_with_relationships(cypher_query)
            if not graph_data:
                return []
            return self._extract_paths_from_graph(graph_data, max_depth=depth)
        except Exception:
            return []

    def _build_domain_filter(
        self,
        *,
        alias: str,
        domain_value: str,
        match_domain_by_name_suffix: bool = False,
    ) -> str:
        """Return a Cypher domain predicate for the provided alias."""
        if match_domain_by_name_suffix:
            return (
                f'toLower(coalesce({alias}.name, "")) '
                f"ends with toLower('@{domain_value}')"
            )
        return f"toLower(coalesce({alias}.domain, \"\")) = toLower('{domain_value}')"

    def _build_enabled_filter(self, *, alias: str, default_true: bool = True) -> str:
        """Return a Cypher predicate for enabled principals."""
        default_flag = "true" if default_true else "false"
        return f"coalesce({alias}.enabled, {default_flag}) = true"

    def _build_high_value_filter(self, *, alias: str) -> str:
        """Return a Cypher predicate that identifies Tier Zero/high-value nodes."""
        return (
            "("
            f"coalesce({alias}.highvalue, false) = true "
            f'OR "admin_tier_0" IN coalesce({alias}.system_tags, []) '
            f"OR coalesce({alias}.isTierZero, false) = true"
            ")"
        )

    def _build_low_priv_source_filter(
        self,
        *,
        source_alias: str,
        domain_value: str,
        match_domain_by_name_suffix: bool = False,
    ) -> str:
        """Return a reusable Cypher predicate for low-priv source principals.

        This keeps low-priv filtering consistent across User/Group/Computer
        sources so Tier Zero/high-value principals are excluded regardless of
        source kind.
        """
        domain_predicate = self._build_domain_filter(
            alias=source_alias,
            domain_value=domain_value,
            match_domain_by_name_suffix=match_domain_by_name_suffix,
        )
        enabled_predicate = self._build_enabled_filter(
            alias=source_alias, default_true=True
        )
        high_value_predicate = self._build_high_value_filter(alias=source_alias)

        return f"""
              AND ({source_alias}:User OR {source_alias}:Group OR {source_alias}:Computer)
              AND {domain_predicate}
              AND {enabled_predicate}
              AND NOT {high_value_predicate}
        """

    def get_low_priv_acl_paths(
        self, domain: str, *, max_results: int = 1000
    ) -> List[Dict]:
        """Return ACL/ACE-derived single-step paths from low-priv users.

        This query enumerates ACL-relevant relationships (r.isacl=true) that can
        be exercised by low-priv users either directly or through nested group
        membership (MemberOf*0..).

        It returns paths for visualization in the UI, but we post-process the
        response into single-step "effective" paths shaped as:

            {"nodes": [<user_node>, <target_node>], "rels": [<relation>]}

        which is compatible with the existing attack-graph ingestion helpers.
        """
        try:
            allowed_relations = {
                "GenericAll",
                "GenericWrite",
                "ForceChangePassword",
                "AddSelf",
                "AddMember",
                "ReadGMSAPassword",
                "ReadLAPSPassword",
                "WriteDacl",
                "WriteOwner",
                "DCSync",
            }
            domain_value = domain.replace("'", "\\'")
            limit_value = max(1, min(int(max_results), 5000))
            source_filter = self._build_low_priv_source_filter(
                source_alias="s",
                domain_value=domain_value,
                match_domain_by_name_suffix=True,
            )

            cypher_query = f"""
            MATCH p=(s)-[r]->(t)
            WHERE 1=1
              {source_filter}
              AND type(r) IN {sorted(allowed_relations)!r}
            RETURN p
            LIMIT {limit_value}
            """

            graph_data = self.execute_query_with_relationships(cypher_query)
            if not graph_data:
                return []
            return self._extract_direct_allowed_edges_from_graph(
                graph_data, allowed_relations=allowed_relations
            )
        except Exception:
            return []

    def get_low_priv_adcs_paths(
        self, domain: str, *, max_results: int = 1000
    ) -> List[Dict]:
        """Return ADCS escalation edges for Phase 2 (highest priority).

        This query captures Active Directory Certificate Services escalation
        paths (ESC techniques) exposed as relationships in BloodHound CE.

        Returned entries are normalized to:

            {"nodes": [<source_node>, <target_node>], "rels": [<relation>]}
        """
        try:
            allowed_relations = {
                "ADCSESC1",
                "ADCSESC3",
                "ADCSESC4",
                "ADCSESC6a",
                "ADCSESC6b",
                "ADCSESC9a",
                "ADCSESC9b",
                "ADCSESC10a",
                "ADCSESC10b",
                "ADCSESC13",
                "CoerceAndRelayNTLMToADCS",
                "GoldenCert",
            }
            domain_value = domain.replace("'", "\\'")
            limit_value = max(1, min(int(max_results), 5000))
            source_filter = self._build_low_priv_source_filter(
                source_alias="s",
                domain_value=domain_value,
            )

            cypher_query = f"""
            MATCH p=(s)-[r]->(t)
            WHERE 1=1
              {source_filter}
              AND type(r) IN {sorted(allowed_relations)!r}
            RETURN p
            LIMIT {limit_value}
            """

            graph_data = self.execute_query_with_relationships(cypher_query)
            if not graph_data:
                return []
            return self._extract_direct_allowed_edges_from_graph(
                graph_data, allowed_relations=allowed_relations
            )
        except Exception:
            return []

    def get_low_priv_access_paths(
        self, domain: str, *, max_results: int = 1000
    ) -> List[Dict]:
        """Return access/session-derived direct edges for Phase 2.2.

        This query targets non-ACL but highly actionable relations such as local
        admin rights, remote access, and sessions.

        Returned entries are normalized to:

            {"nodes": [<source_node>, <target_node>], "rels": [<relation>]}
        """
        try:
            allowed_relations = {
                "AdminTo",
                "CanRDP",
                "CanPSRemote",
                "ExecuteDCOM",
                "SQLAdmin",
            }
            domain_value = domain.replace("'", "\\'")
            limit_value = max(1, min(int(max_results), 5000))
            source_filter = self._build_low_priv_source_filter(
                source_alias="s",
                domain_value=domain_value,
            )

            cypher_query = f"""
            MATCH p=(s)-[r]->(t)
            WHERE 1=1
              {source_filter}
              AND type(r) IN {sorted(allowed_relations)!r}
            RETURN p
            LIMIT {limit_value}
            """

            graph_data = self.execute_query_with_relationships(cypher_query)
            if not graph_data:
                return []
            return self._extract_direct_allowed_edges_from_graph(
                graph_data, allowed_relations=allowed_relations
            )
        except Exception:
            return []

    def get_high_value_session_paths(
        self, domain: str, *, max_results: int = 1000
    ) -> List[Dict]:
        """Return computer->high-value-user session edges for Phase 2.

        This query focuses on active user sessions where the session owner is
        high value / Tier 0. It complements low-priv attack-step discovery by
        exposing host pivots that may allow credential theft or token abuse.

        Returned entries are normalized to:

            {"nodes": [<computer_node>, <user_node>], "rels": ["HasSession"]}
        """
        try:
            allowed_relations = {"HasSession"}
            domain_value = domain.replace("'", "\\'")
            limit_value = max(1, min(int(max_results), 5000))
            computer_domain_filter = self._build_domain_filter(
                alias="c",
                domain_value=domain_value,
            )
            user_domain_filter = self._build_domain_filter(
                alias="u",
                domain_value=domain_value,
            )
            computer_enabled_filter = self._build_enabled_filter(
                alias="c", default_true=True
            )
            user_enabled_filter = self._build_enabled_filter(
                alias="u", default_true=True
            )
            user_high_value_filter = self._build_high_value_filter(alias="u")
            computer_high_value_filter = self._build_high_value_filter(alias="c")

            cypher_query = f"""
            MATCH p=(c:Computer)-[r]->(u:User)
            WHERE 1=1
              AND {computer_domain_filter}
              AND {computer_enabled_filter}
              AND NOT ({computer_high_value_filter})
              AND {user_domain_filter}
              AND {user_enabled_filter}
              AND {user_high_value_filter}
              AND type(r) IN {sorted(allowed_relations)!r}
            RETURN p
            LIMIT {limit_value}
            """

            graph_data = self.execute_query_with_relationships(cypher_query)
            if not graph_data:
                return []
            return self._extract_direct_allowed_edges_from_graph(
                graph_data, allowed_relations=allowed_relations
            )
        except Exception:
            return []

    def get_low_priv_delegation_paths(
        self, domain: str, *, max_results: int = 1000
    ) -> List[Dict]:
        """Return delegation-derived direct edges for Phase 2.3.

        For now we keep this minimal and only include the two delegation edges
        requested for initial iteration:
            - AllowedToDelegate (constrained delegation)
            - CoerceToTGT (unconstrained delegation)

        Returned entries are normalized to:

            {"nodes": [<source_node>, <target_node>], "rels": [<relation>]}
        """
        try:
            allowed_relations = {"AllowedToDelegate", "CoerceToTGT"}
            domain_value = domain.replace("'", "\\'")
            limit_value = max(1, min(int(max_results), 5000))
            source_filter = self._build_low_priv_source_filter(
                source_alias="s",
                domain_value=domain_value,
            )

            cypher_query = f"""
            MATCH p=(s)-[r]->(t)
            WHERE 1=1
              {source_filter}
              AND type(r) IN {sorted(allowed_relations)!r}
              AND (t.enabled = true)
            RETURN p
            LIMIT {limit_value}
            """

            graph_data = self.execute_query_with_relationships(cypher_query)
            if not graph_data:
                return []
            return self._extract_direct_allowed_edges_from_graph(
                graph_data, allowed_relations=allowed_relations
            )
        except Exception:
            return []

    def _extract_nodes_by_kind(
        self, graph_data: Dict, *, allowed_kinds: set[str]
    ) -> List[Dict]:
        """Extract nodes from a CE graph response filtered by kind."""
        nodes_map = graph_data.get("nodes", {})
        if not isinstance(nodes_map, dict):
            return []

        nodes: list[dict] = []
        for node in nodes_map.values():
            if not isinstance(node, dict):
                continue
            kind = node.get("kind") or node.get("labels") or node.get("type")
            if isinstance(kind, list) and kind:
                kind_value = str(kind[0])
            else:
                kind_value = str(kind or "")
            if kind_value not in allowed_kinds:
                continue

            props = (
                node.get("properties")
                if isinstance(node.get("properties"), dict)
                else {}
            )
            nodes.append(
                {
                    "label": node.get("label")
                    or props.get("name")
                    or props.get("samaccountname"),
                    "kind": kind_value,
                    "properties": props,
                }
            )
        return nodes

    def get_roastable_asreproast_users(
        self, domain: str, *, max_results: int = 1000
    ) -> List[Dict]:
        """Return enabled ASREPRoastable users for a domain.

        A user is considered ASREPRoastable when `dontreqpreauth=true`.
        """
        try:
            domain_value = domain.replace("'", "\\'")
            limit_value = max(1, min(int(max_results), 5000))

            cypher_query = f"""
            MATCH (u:User)
            WHERE toLower(coalesce(u.domain, "")) = toLower('{domain_value}')
              AND coalesce(u.enabled, true) = true
              AND coalesce(u.dontreqpreauth, false) = true
            RETURN u
            LIMIT {limit_value}
            """
            graph_data = self.execute_query_with_relationships(cypher_query)
            if not graph_data:
                return []

            users = self._extract_nodes_by_kind(graph_data, allowed_kinds={"User"})
            filtered: list[dict] = []
            for user in users:
                props = (
                    user.get("properties")
                    if isinstance(user.get("properties"), dict)
                    else {}
                )
                if not (
                    str(props.get("domain") or "").lower() == domain.lower()
                    and props.get("enabled") is True
                    and props.get("dontreqpreauth") is True
                ):
                    continue
                filtered.append(user)
            return filtered
        except Exception:
            return []

    def get_roastable_kerberoast_users(
        self, domain: str, *, max_results: int = 1000
    ) -> List[Dict]:
        """Return enabled kerberoastable users for a domain.

        A user is considered kerberoastable when:
          - hasspn=true
          - gmsa=false
          - msa=false
        """
        try:
            domain_value = domain.replace("'", "\\'")
            limit_value = max(1, min(int(max_results), 5000))

            cypher_query = f"""
            MATCH (u:User)
            WHERE toLower(coalesce(u.domain, "")) = toLower('{domain_value}')
              AND coalesce(u.enabled, true) = true
              AND coalesce(u.hasspn, false) = true
              AND coalesce(u.gmsa, false) = false
              AND coalesce(u.msa, false) = false
              AND NOT toLower(coalesce(u.distinguishedname, u.dn, "")) CONTAINS "cn=managed service accounts,"
            RETURN u
            LIMIT {limit_value}
            """
            graph_data = self.execute_query_with_relationships(cypher_query)
            if not graph_data:
                return []

            users = self._extract_nodes_by_kind(graph_data, allowed_kinds={"User"})
            filtered: list[dict] = []
            for user in users:
                props = (
                    user.get("properties")
                    if isinstance(user.get("properties"), dict)
                    else {}
                )
                if str(props.get("domain") or "").lower() != domain.lower():
                    continue
                if props.get("enabled") is not True:
                    continue
                if props.get("hasspn") is not True:
                    continue
                if props.get("gmsa") is True or props.get("msa") is True:
                    continue
                dn = str(
                    props.get("distinguishedname") or props.get("dn") or ""
                ).lower()
                if "cn=managed service accounts," in dn:
                    continue
                filtered.append(user)
            return filtered
        except Exception:
            return []

    def _extract_paths_from_graph(
        self, graph_data: Dict, *, max_depth: int
    ) -> List[Dict]:
        """Extract ordered paths from CE graph response."""
        nodes_map = graph_data.get("nodes", {})
        edges = graph_data.get("edges", [])
        if not nodes_map or not edges:
            return []

        def _node_props(node_data: Dict) -> Dict:
            return node_data.get("properties") if isinstance(node_data, dict) else {}

        def _node_is_high_value(node_data: Dict) -> bool:
            props = _node_props(node_data)
            return bool(
                node_data.get("isTierZero")
                or props.get("highvalue")
                or "admin_tier_0" in (props.get("system_tags") or [])
            )

        def _node_is_user(node_data: Dict) -> bool:
            return str(node_data.get("kind", "")).lower() == "user"

        def _node_name(node_data: Dict) -> str:
            props = _node_props(node_data)
            return (
                props.get("samaccountname")
                or props.get("name")
                or node_data.get("label")
                or node_data.get("objectId")
                or ""
            )

        adjacency: Dict[str, List[Dict]] = {}
        for edge in edges:
            source = edge.get("source")
            target = edge.get("target")
            if not source or not target:
                continue
            adjacency.setdefault(source, []).append(
                {"target": target, "label": edge.get("label") or edge.get("kind")}
            )

        start_nodes = [
            node_id
            for node_id, node_data in nodes_map.items()
            if _node_is_user(node_data) and not _node_is_high_value(node_data)
        ]
        target_nodes = {
            node_id
            for node_id, node_data in nodes_map.items()
            if _node_is_high_value(node_data)
        }

        results: List[Dict] = []
        seen_paths: set[tuple[str, ...]] = set()

        for start in start_nodes:
            stack = [(start, [start], [])]
            while stack:
                current, path_nodes, path_rels = stack.pop()
                if current in target_nodes and current != start:
                    path_key = tuple(path_nodes)
                    if path_key in seen_paths:
                        continue
                    seen_paths.add(path_key)
                    results.append(
                        {
                            "nodes": [nodes_map[n] for n in path_nodes],
                            "rels": path_rels,
                        }
                    )
                    continue
                if len(path_rels) >= max_depth:
                    continue
                for edge in adjacency.get(current, []):
                    next_node = edge.get("target")
                    if not next_node or next_node in path_nodes:
                        continue
                    stack.append(
                        (
                            next_node,
                            path_nodes + [next_node],
                            path_rels + [edge.get("label") or ""],
                        )
                    )

        return results

    def _extract_direct_allowed_edges_from_graph(
        self, graph_data: Dict, *, allowed_relations: set[str]
    ) -> List[Dict]:
        """Extract direct (source, relation, target) edges from a graph response."""
        nodes_map = graph_data.get("nodes", {})
        edges = graph_data.get("edges", [])
        if not nodes_map or not edges:
            return []

        results: List[Dict] = []
        seen_keys: set[tuple[str, str, str]] = set()

        for edge in edges:
            src_id = edge.get("source")
            tgt_id = edge.get("target")
            if src_id is None or tgt_id is None:
                continue
            label = (edge.get("label") or edge.get("kind") or "").strip()
            if not label or label not in allowed_relations:
                continue
            src_key = str(src_id)
            tgt_key = str(tgt_id)
            key = (src_key, label, tgt_key)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            src_node = nodes_map.get(src_key)
            tgt_node = nodes_map.get(tgt_key)
            if not isinstance(src_node, dict) or not isinstance(tgt_node, dict):
                continue
            results.append({"nodes": [src_node, tgt_node], "rels": [label]})

        return results

    def get_critical_aces_by_domain(
        self, domain: str, blacklist: List[str], high_value: bool = False
    ) -> List[Dict]:
        """Get critical ACEs by domain using CySQL query"""
        try:
            cypher_query = f"""
            MATCH (s)-[r]->(t)
            WHERE toUpper(s.domain) = '{domain.upper()}'
            RETURN s, r, t
            """

            result = self.execute_query(cypher_query)
            aces = []

            if result and isinstance(result, list):
                for node_properties in result:
                    source_name = node_properties.get("name", "")
                    target_name = node_properties.get("name", "")
                    relation_type = node_properties.get("relation", "")

                    if source_name and target_name:
                        # Extract just the name part (before @) if it's in UPN format
                        if "@" in source_name:
                            source_name = source_name.split("@")[0]
                        if "@" in target_name:
                            target_name = target_name.split("@")[0]

                        aces.append(
                            {
                                "source": source_name,
                                "relation": relation_type,
                                "target": target_name,
                            }
                        )

            return aces

        except Exception:
            return []

    def _get_headers(self):
        """Get headers for API requests"""
        headers = {"User-Agent": "BloodHound-CLI/1.0"}

        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"

        return headers

    def _config_summary(self) -> dict:
        """Return a safe summary of the CE config for logging."""
        summary = {
            "config_path": str(CONFIG_FILE),
            "config_exists": CONFIG_FILE.exists(),
            "has_ce_section": False,
            "has_username": False,
            "has_password": False,
            "has_api_token": False,
            "base_url": None,
        }
        if not CONFIG_FILE.exists():
            return summary
        try:
            config = configparser.ConfigParser()
            config.read(str(CONFIG_FILE))
            if "CE" in config:
                summary["has_ce_section"] = True
                summary["has_username"] = bool(config["CE"].get("username"))
                summary["has_password"] = bool(config["CE"].get("password"))
                summary["has_api_token"] = bool(config["CE"].get("api_token"))
                summary["base_url"] = config["CE"].get("base_url")
        except Exception as exc:
            print_info_debug(f"[bloodhound-ce] config summary failed: {exc}")
        return summary

    def upload_data(self, file_path: str) -> bool:
        """Upload BloodHound data using the file upload API."""
        job_id = self.start_file_upload_job(file_path)
        return job_id is not None

    def _create_file_upload_job_id(self) -> int | None:
        """Create a file upload job and return its ID."""
        create_response = self.session.post(
            f"{self.base_url}/api/v2/file-upload/start",
            headers=self._get_headers(),
            json={"collection_method": "manual"},
        )

        if create_response.status_code not in [200, 201]:
            self._last_error = (
                f"Upload job start failed: HTTP {create_response.status_code} - "
                f"{(create_response.text or '').strip()[:300]}"
            )
            print_error(self._last_error)
            return None

        job_data = create_response.json()
        job_id = job_data.get("data", {}).get("id")
        if not job_id:
            self._last_error = (
                "Upload job start failed: response did not include a valid job id."
            )
            print_error(self._last_error)
            return None

        try:
            self._last_error = None
            return int(job_id)
        except Exception:
            # BloodHound sometimes returns ids as strings; be defensive.
            self._last_error = f"Upload job start failed: invalid job id {job_id!r}."
            print_error(self._last_error)
            return None

    def _upload_file_to_job(self, job_id: int, *, file_path: str) -> bool:
        """Upload a file to an existing upload job."""
        fpath = Path(file_path)
        if not fpath.exists() or not fpath.is_file():
            self._last_error = f"Upload failed: file not found ({file_path})."
            print_error(self._last_error)
            return False

        suffix = fpath.suffix.lower()
        if suffix == ".zip":
            content_type = "application/zip"
        elif suffix == ".json":
            content_type = "application/json"
        else:
            content_type = "application/octet-stream"

        headers = self._get_headers()
        headers["Content-Type"] = content_type

        with open(file_path, "rb") as f:
            body = f.read()
            upload_response = self.session.post(
                f"{self.base_url}/api/v2/file-upload/{job_id}",
                data=body,
                headers=headers,
            )

        if upload_response.status_code >= 400:
            self._last_error = (
                f"Upload failed: HTTP {upload_response.status_code} - "
                f"{(upload_response.text or '').strip()[:300]}"
            )
            print_error(self._last_error)
            return False

        self._last_error = None
        return True

    def _end_file_upload_job(self, job_id: int) -> bool:
        """End a file upload job."""
        end_response = self.session.post(
            f"{self.base_url}/api/v2/file-upload/{job_id}/end",
            headers=self._get_headers(),
        )
        if end_response.status_code >= 400:
            self._last_error = (
                f"Upload finalize failed: HTTP {end_response.status_code} - "
                f"{(end_response.text or '').strip()[:300]}"
            )
            print_error(self._last_error)
            return False
        self._last_error = None
        return True

    def start_file_upload_job(self, file_path: str) -> int | None:
        """Start an upload job for the given file and return the job id.

        This performs the upload and job end request. Use `wait_for_file_upload_job`
        to track ingestion for a specific job id.
        """
        try:
            self._last_error = None
            # Ensure we have a valid token before attempting upload. This will try
            # to auto-renew and, if that fails, interactively prompt the user.
            if not self.ensure_authenticated_robust():
                summary = self._config_summary()
                self._last_error = (
                    "Authentication failed before starting BloodHound upload job."
                )
                print_info_debug(
                    "[bloodhound-ce] upload aborted: authentication failed "
                    f"(config_exists={summary.get('config_exists')}, "
                    f"has_username={summary.get('has_username')}, "
                    f"has_password={summary.get('has_password')}, "
                    f"has_api_token={summary.get('has_api_token')}, "
                    f"base_url={summary.get('base_url')})"
                )
                return None

            job_id = self._create_file_upload_job_id()
            if job_id is None:
                return None

            if not self._upload_file_to_job(job_id, file_path=file_path):
                return None

            if not self._end_file_upload_job(job_id):
                return None

            return job_id

        except Exception as e:
            self._last_error = f"Upload failed with exception: {e}"
            self.logger.error("upload error", error=str(e))
            print_error(f"Error uploading file: {e}")
            return None

    def wait_for_file_upload_job(
        self, job_id: int, *, poll_interval: int = 5, timeout_seconds: int = 1800
    ) -> bool:
        """Wait for ingestion of a specific file upload job."""
        import time

        try:
            start_time = time.time()
            last_status = None

            print_info("Waiting for ingestion to complete...")
            self.logger.info("waiting for ingestion", file_upload_job_id=job_id)

            while True:
                job = self.get_file_upload_job(job_id)
                if job is None:
                    if time.time() - start_time > 15:
                        self.logger.warning(
                            "could not fetch job details", file_upload_job_id=job_id
                        )
                        self._last_error = (
                            f"Upload wait failed: timeout fetching job details (job_id={job_id})."
                        )
                        print_error("Timeout: Could not get job details")
                        return False
                else:
                    status = job.get("status")
                    status_message = job.get("status_message", "")

                    if status != last_status:
                        self.logger.info(
                            "upload status",
                            file_upload_job_id=job_id,
                            status=status,
                            message=status_message,
                        )
                        print_info(f"Job status: {status} - {status_message}")
                        last_status = status

                    # Terminal statuses: -1 invalid, 2 complete, 3 canceled, 4 timed out,
                    # 5 failed, 8 partially complete
                    if status in [-1, 2, 3, 4, 5, 8]:
                        if status == 2:
                            self._last_error = None
                            print_success("Upload and processing completed successfully")
                            self.logger.info(
                                "upload complete",
                                file_upload_job_id=job_id,
                                status=status,
                            )
                            return True
                        if status == 8:
                            self.logger.warning(
                                "upload partial",
                                file_upload_job_id=job_id,
                                status=status,
                                message=status_message,
                            )
                            self._last_error = (
                                "Upload completed with warnings (partially complete). "
                                f"status_message={status_message}"
                            )
                            print_warning(
                                "Upload completed with warnings (partially complete)"
                            )
                            return True

                        self.logger.error(
                            "upload failed",
                            file_upload_job_id=job_id,
                            status=status,
                            message=status_message,
                        )
                        self._last_error = (
                            f"Upload failed with status {status}: {status_message}"
                        )
                        print_error(self._last_error)
                        return False

                if time.time() - start_time > timeout_seconds:
                    self.logger.error(
                        "upload timeout",
                        file_upload_job_id=job_id,
                        timeout_seconds=timeout_seconds,
                    )
                    self._last_error = (
                        f"Upload wait timed out after {timeout_seconds}s for job_id={job_id}."
                    )
                    print_error(f"Timeout after {timeout_seconds} seconds")
                    return False

                time.sleep(max(1, poll_interval))

        except Exception as e:
            self.logger.exception(
                "upload wait error", file_upload_job_id=job_id, error=str(e)
            )
            self._last_error = f"Upload wait failed with exception: {e}"
            print_error(f"Error in upload wait: {e}")
            return False

    def list_upload_jobs(self) -> List[Dict]:
        """List file upload jobs"""
        try:
            response = self.session.get(
                f"{self.base_url}/api/v2/file-upload", headers=self._get_headers()
            )
            response.raise_for_status()
            data = response.json()
            # The response structure might be {"data": [...]} or just [...]
            if isinstance(data, dict) and "data" in data:
                return data["data"]
            elif isinstance(data, list):
                return data
            else:
                return []
        except Exception as e:
            self.logger.error("list upload jobs failed", error=str(e))
            print(f"Error listing upload jobs: {e}")
            return []

    def get_accepted_upload_types(self) -> List[str]:
        """Get accepted file upload types"""
        try:
            response = self.session.get(
                f"{self.base_url}/api/v2/file-upload/accepted-types",
                headers=self._get_headers(),
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self.logger.error("accepted types request failed", error=str(e))
            print(f"Error getting accepted types: {e}")
            return []

    def get_file_upload_job(self, job_id: int) -> Optional[Dict]:
        """Get specific file upload job details"""
        try:
            # Use the list endpoint and filter by job_id
            response = self.session.get(
                f"{self.base_url}/api/v2/file-upload", headers=self._get_headers()
            )
            response.raise_for_status()
            data = response.json()

            # The response structure might be {"data": [...]} or just [...]
            jobs = []
            if isinstance(data, dict) and "data" in data:
                jobs = data["data"]
            elif isinstance(data, list):
                jobs = data

            # Find the job with the matching ID
            for job in jobs:
                if job.get("id") == job_id:
                    return job

            return None
        except Exception as e:
            self.logger.error("get upload job failed", job_id=job_id, error=str(e))
            print(f"Error getting upload job {job_id}: {e}")
            return None

    def infer_latest_file_upload_job_id(self) -> Optional[int]:
        """Infer the latest file upload job ID from the list"""
        try:
            jobs = self.list_upload_jobs()
            if not jobs:
                return None

            # Find the most recent job (highest ID or most recent timestamp)
            latest_job = max(jobs, key=lambda x: x.get("id", 0))
            return latest_job.get("id")
        except Exception as e:
            self.logger.error("infer latest upload job failed", error=str(e))
            print(f"Error inferring latest job ID: {e}")
            return None

    def upload_data_and_wait(
        self, file_path: str, poll_interval: int = 5, timeout_seconds: int = 1800
    ) -> bool:
        """Upload BloodHound data and wait for processing to complete"""
        job_id = self.start_file_upload_job(file_path)
        if job_id is None:
            return False
        return self.wait_for_file_upload_job(
            job_id, poll_interval=poll_interval, timeout_seconds=timeout_seconds
        )

    def verify_token(self) -> bool:
        """Verify if the current token is valid by making a test request"""
        try:
            # Try to make a simple API call to verify the token
            response = self.session.get(
                f"{self.base_url}/api/v2/file-upload", headers=self._get_headers()
            )
            return response.status_code == 200
        except Exception:
            self.logger.exception("token verification error")
            return False

    def auto_renew_token(self) -> bool:
        """Automatically renew the token using stored credentials"""
        try:
            # First try to use credentials stored in memory (from authenticate())
            if self._stored_username and self._stored_password:
                login_url = f"{self.base_url}/api/v2/login"
                payload = {
                    "login_method": "secret",
                    "username": self._stored_username,
                    "secret": self._stored_password,
                }

                # Remove stale token headers before logging in
                self.session.headers.pop("Authorization", None)
                response = self.session.post(
                    login_url, json=payload, verify=self.verify, timeout=60
                )

                if response.status_code == 200:
                    data = response.json()
                    token = data.get("data", {}).get("session_token")
                    if token:
                        self.api_token = token
                        self.session.headers.update(
                            {"Authorization": f"Bearer {token}"}
                        )
                        return True
                return False

            # Fallback: Load config to get stored credentials
            config = configparser.ConfigParser()
            config.read(str(CONFIG_FILE))

            if "CE" not in config:
                return False

            username = config["CE"].get("username", "admin")
            password = config["CE"].get("password")
            raw_base_url = config["CE"].get(
                "base_url", f"http://localhost:{BLOODHOUND_CE_DEFAULT_WEB_PORT}"
            )
            # Normalize legacy defaults (e.g., http://localhost:8080) to the
            # current BLOODHOUND_CE_DEFAULT_WEB_PORT so renewal always hits the
            # actual CE instance.
            base_url = self._normalize_base_url(raw_base_url)

            if not password:
                return False

            # Create a new session for authentication (without the expired token)
            import requests

            temp_session = requests.Session()
            temp_session.verify = self.session.verify

            # Authenticate with stored credentials using the temp session
            login_url = f"{base_url}/api/v2/login"
            payload = {
                "login_method": "secret",
                "username": username,
                "secret": password,
            }

            response = temp_session.post(login_url, json=payload, timeout=60)
            if response.status_code >= 400:
                return False

            try:
                data = response.json()
            except JSONDecodeError as exc:
                # Non‑JSON response (e.g., HTML or empty body) – treat as failure.
                self.logger.exception(
                    "token auto-renew json decode error",
                    error=str(exc),
                    status_code=response.status_code,
                    text=(response.text or "")[:500],
                )
                return False
            token = None
            if isinstance(data, dict):
                data_field = data.get("data")
                if isinstance(data_field, dict):
                    token = data_field.get("session_token")
            if not token:
                token = data.get("token") or data.get("access_token") or data.get("jwt")

            if not token:
                return False

            # Update the stored token, normalized base_url, and our session
            write_ce_config(
                base_url=base_url,
                api_token=token,
                username=username,
                password=password,
                verify=self.verify,
            )

            # Update our session with the new token
            self.api_token = token
            self.session.headers.update({"Authorization": f"Bearer {token}"})

            return True

        except Exception as e:
            self.logger.exception("token auto-renew error", error=str(e))
            print(f"Error auto-renewing token: {e}")
            return False

    def ensure_valid_token(self) -> bool:
        """Ensure we have a valid token, auto-renew if necessary"""
        if not self.api_token:
            return self.auto_renew_token()

        # Check if current token is valid
        if self.verify_token():
            return True

        # Token is invalid, try to renew
        self.logger.info("token expired, attempting renewal")
        print("Token expired, attempting to renew...")
        return self.auto_renew_token()

    def ensure_authenticated_interactive(self) -> bool:
        """Ensure we have a valid token, prompting the user if needed.

        This first attempts non-interactive validation/renewal via
        :meth:`ensure_valid_token`. If that fails, it interactively prompts the
        user for BloodHound CE credentials, validates them against the API, and
        persists the updated credentials and token to ``~/.bloodhound_config``.

        Returns:
            True if a valid token is available (possibly newly obtained),
            False if authentication could not be established.
        """
        # Fast path: existing token is valid or can be auto-renewed.
        if self.ensure_valid_token():
            return True

        # At this point, automatic renewal using stored credentials has failed.
        # Offer the user an opportunity to provide fresh credentials so we can
        # authenticate and update the config (including a new token).
        summary = self._config_summary()
        print_info_debug(
            "[bloodhound-ce] No valid token available; prompting user for credentials "
            f"(config_exists={summary.get('config_exists')}, "
            f"has_username={summary.get('has_username')}, "
            f"has_password={summary.get('has_password')}, "
            f"has_api_token={summary.get('has_api_token')}, "
            f"base_url={summary.get('base_url')})"
        )
        print(
            "Authentication to BloodHound CE is required but the stored token/credentials "
            "are invalid or missing."
        )

        # Try to load existing username from config (fallback to 'admin')
        suggested_username = "admin"
        config: configparser.ConfigParser | None = None
        try:
            config = configparser.ConfigParser()
            config.read(str(CONFIG_FILE))
            if "CE" in config and config["CE"].get("username"):
                suggested_username = config["CE"].get("username", "admin")
        except Exception:
            # If reading config fails, just keep the default suggestion
            config = None

        try:
            user_input = input(
                f"BloodHound CE username [{suggested_username}]: "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            print_info_debug("[bloodhound-ce] prompt aborted: no username provided")
            print("Aborting: no credentials provided.")
            return False

        username = user_input or suggested_username

        try:
            import getpass

            password = getpass.getpass("BloodHound CE password: ")
        except (EOFError, KeyboardInterrupt):
            print_info_debug("[bloodhound-ce] prompt aborted: no password provided")
            print("Aborting: no credentials provided.")
            return False

        if not password:
            print_info_debug("[bloodhound-ce] prompt aborted: empty password")
            print("Aborting: empty password is not allowed.")
            return False

        # Try to authenticate with the provided credentials
        token = self.authenticate(username, password)
        if not token:
            summary = self._config_summary()
            print_info_debug(
                "[bloodhound-ce] authentication failed with provided credentials "
                f"(config_exists={summary.get('config_exists')}, "
                f"has_username={summary.get('has_username')}, "
                f"has_password={summary.get('has_password')}, "
                f"has_api_token={summary.get('has_api_token')}, "
                f"base_url={summary.get('base_url')})"
            )
            print(
                "Error: Invalid BloodHound CE credentials. "
                "Please verify the username/password and try again."
            )
            return False

        # Persist updated credentials and token to the config file so that
        # future runs can auto-renew the token without asking again.
        try:
            write_ce_config(
                base_url=self.base_url,
                api_token=token,
                username=username,
                password=password,
                verify=self.verify,
            )
        except Exception as e:
            # Failure to persist credentials should not stop the current use,
            # but we warn so the user knows auto‑renewal may not work next time.
            self.logger.exception(
                "failed to persist updated BloodHound CE credentials",
                error=str(e),
            )
            print(
                "Warning: Could not persist updated BloodHound CE credentials to the config file. "
                "Authentication will work for this session but automatic renewal may fail next time."
            )

        # Update in-memory token/session as well.
        self.api_token = token
        self.session.headers.update({"Authorization": f"Bearer {token}"})
        return True

    def ensure_authenticated_robust(self) -> bool:
        """Ensure authentication with config validation + interactive fallback."""
        if not CONFIG_FILE.exists():
            default_password = _get_default_admin_password()
            try:
                write_ce_config_skeleton(
                    base_url=self.base_url,
                    username="admin",
                    password=default_password,
                    verify=self.verify,
                )
                print_info_debug(
                    "[bloodhound-ce] created default config skeleton at "
                    f"{mark_sensitive(str(CONFIG_FILE), 'path')}"
                )
            except Exception as exc:
                print_info_debug(
                    "[bloodhound-ce] failed to create config skeleton: "
                    f"{mark_sensitive(str(exc), 'error')}"
                )
            try:
                token = self.authenticate("admin", default_password)
                if token:
                    write_ce_config(
                        base_url=self.base_url,
                        api_token=token,
                        username="admin",
                        password=default_password,
                        verify=self.verify,
                    )
                    self.api_token = token
                    self.session.headers.update({"Authorization": f"Bearer {token}"})
                    print_info_debug(
                        "[bloodhound-ce] default admin authentication succeeded"
                    )
                    return True
                print_info_debug("[bloodhound-ce] default admin authentication failed")
            except Exception as exc:
                print_info_debug(
                    "[bloodhound-ce] default auth attempt failed: "
                    f"{mark_sensitive(str(exc), 'error')}"
                )

        if not validate_ce_config():
            summary = self._config_summary()
            print_info_debug(
                "[bloodhound-ce] config invalid; attempting refresh with stored credentials "
                f"(config_exists={summary.get('config_exists')}, "
                f"has_username={summary.get('has_username')}, "
                f"has_password={summary.get('has_password')})"
            )
            try:
                config = configparser.ConfigParser()
                config.read(str(CONFIG_FILE))
                if "CE" in config and config["CE"].get("password"):
                    username = config["CE"].get("username", "admin")
                    password = config["CE"].get("password")
                    token = self.authenticate(username, password)
                    if token:
                        write_ce_config(
                            base_url=self.base_url,
                            api_token=token,
                            username=username,
                            password=password,
                            verify=self.verify,
                        )
                        self.api_token = token
                        self.session.headers.update(
                            {"Authorization": f"Bearer {token}"}
                        )
            except Exception as exc:
                print_info_debug(f"[bloodhound-ce] config refresh failed: {exc}")

        if self.ensure_valid_token():
            return True

        return self.ensure_authenticated_interactive()

    def close(self):
        """Close the HTTP session"""
        try:
            self.session.close()
        except Exception:
            pass
