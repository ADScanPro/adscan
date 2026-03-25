"""
BloodHound CE implementation using HTTP API
"""

# pylint: skip-file
import configparser
import os
from json import JSONDecodeError
from typing import List, Dict, Optional, Tuple
from pathlib import Path
import time
import requests
from .base import BloodHoundClient
from .settings import (
    CONFIG_FILE,
    BLOODHOUND_CE_DEFAULT_WEB_PORT,
    validate_ce_config,
    write_ce_config,
    write_ce_config_skeleton,
)
from adscan_internal.rich_output import (
    mark_sensitive,
    print_cypher_query,
    print_error,
    print_info,
    print_info_debug,
    print_panel,
    print_success,
    print_warning,
    print_exception
)


def _get_default_admin_password() -> str:
    """Return default BloodHound CE admin password override if set."""
    return (
        os.getenv("ADSCAN_BLOODHOUND_ADMIN_PASSWORD")
        or os.getenv("ADSCAN_BH_ADMIN_PASSWORD")
        or "Adscan4thewin!"
    )


_bh_complexity_warning_shown = False


def _warn_bh_complexity_limit() -> None:
    """Show a one-time actionable warning when BH CE rejects a query as too complex."""
    global _bh_complexity_warning_shown
    if _bh_complexity_warning_shown:
        return
    _bh_complexity_warning_shown = True
    print_panel(
        "[bold yellow]BloodHound CE — Cypher complexity limit triggered[/bold yellow]\n\n"
        "BloodHound CE rejected this query because the Cypher complexity limit is enabled.\n"
        "The managed configuration ships with this limit [bold]disabled[/bold] by default,\n"
        "but the running container was started with an older configuration.\n\n"
        "[bold]To fix:[/bold] run [bold cyan]adscan start[/bold cyan] — it will automatically\n"
        "detect the configuration change and recreate the containers with the updated settings.\n"
        "Your data (Neo4j graph, Postgres) is stored in Docker volumes and will not be affected.",
        title="Action required",
        border_style="yellow",
    )


class BloodHoundCEClient(BloodHoundClient):
    """BloodHound CE client using HTTP API."""

    def __init__(
        self,
        base_url: str = None,
        api_token: Optional[str] = None,
        debug: bool = True,
        verbose: bool = True,
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
        ctx_str = f" {context}" if context else ""
        print_info_debug(f"[bloodhound-ce] {message}{ctx_str}")

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
            print_cypher_query(cleaned_query)

            payload = {"query": cleaned_query, "include_properties": True}

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

    def get_last_error(self) -> str | None:
        """Return the last query error message, if any."""
        return self._last_error

    # ── Path query (fast path) ─────────────────────────────────────────────────

    @staticmethod
    def _parse_path_literals(literals: List[Dict]) -> List[Dict]:
        """Convert BH CE ``literals`` response into path dicts.

        When a Cypher query uses
        ``RETURN nodes(p) AS path_nodes, relationships(p) AS rels``
        instead of ``RETURN p``, BH CE returns a ``literals`` list where pairs
        of entries represent one path each:
          - ``{"key": "path_nodes", "value": [{Id, Labels, Props}, ...]}``
          - ``{"key": "rels",       "value": [{Type, StartId, EndId, Props}, ...]}``

        This converts each pair into ``{"nodes": [node_dict, ...], "rels": [str, ...]}``
        matching the format expected by ``_bh_paths_to_display_records``.

        No DFS needed — BH already reconstructed the ordered paths before
        sending the response.
        """

        def _node_from_literal(raw: Dict) -> Dict:
            props = raw.get("Props") or {}
            labels: List[str] = raw.get("Labels") or []
            # Prefer the most specific label (skip the generic "Base" label).
            kind = next((lbl for lbl in labels if lbl != "Base"), labels[0] if labels else "")
            label = str(
                props.get("name")
                or props.get("samaccountname")
                or raw.get("ElementId")
                or ""
            )
            object_id = str(props.get("objectid") or props.get("objectId") or "")
            is_tier_zero = bool(
                props.get("isTierZero")
                or props.get("highvalue")
                or "admin_tier_0" in str(props.get("system_tags") or "")
            )
            return {
                "label": label,
                "kind": kind,
                "objectId": object_id,
                "isTierZero": is_tier_zero,
                "properties": props,
            }

        results: List[Dict] = []
        i = 0
        while i + 1 < len(literals):
            pn_entry = literals[i]
            rl_entry = literals[i + 1]
            # Defensive: ensure we're reading the right keys.
            if pn_entry.get("key") != "path_nodes" or rl_entry.get("key") != "rels":
                i += 1
                continue
            raw_nodes: List[Dict] = pn_entry.get("value") or []
            raw_rels: List[Dict] = rl_entry.get("value") or []
            if not raw_nodes or not raw_rels or len(raw_nodes) != len(raw_rels) + 1:
                i += 2
                continue
            results.append(
                {
                    "nodes": [_node_from_literal(n) for n in raw_nodes],
                    "rels": [str(r.get("Type") or r.get("kind") or "") for r in raw_rels],
                }
            )
            i += 2
        return results

    def execute_path_query(self, query: str) -> List[Dict]:
        """Execute a path Cypher query and return parsed path dicts.

        Expects the query to use
        ``RETURN nodes(p) AS path_nodes, relationships(p) AS rels``
        so BH CE returns structured per-path data in ``literals`` instead of
        a deduplicated subgraph that requires a Python-side DFS.

        Args:
            query: Cypher query string ending with the ``RETURN nodes(p) … rels``
                   clause (and optionally a ``LIMIT`` clause).

        Returns:
            List of ``{"nodes": [node_dict, ...], "rels": [str, ...]}`` — one
            entry per path — ready for ``_bh_paths_to_display_records``.
        """
        try:
            cleaned_query = " ".join(query.split())
            print_cypher_query(cleaned_query)

            url = f"{self.base_url}/api/v2/graphs/cypher"
            payload = {"query": cleaned_query, "include_properties": True}
            response = self.session.post(url, json=payload, verify=self.verify, timeout=60)

            if response.status_code == 401:
                if self.ensure_authenticated_robust():
                    response = self.session.post(url, json=payload, verify=self.verify, timeout=60)
                else:
                    return []

            self._debug(
                "path query response",
                status=response.status_code,
                headers=dict(response.headers),
            )

            if response.status_code != 200:
                self._debug(
                    "path query failed",
                    status=response.status_code,
                    response_text=(response.text or "")[:300],
                )
                if response.status_code == 400:
                    _body = (response.text or "").lower()
                    if "too complex" in _body or "complexity" in _body:
                        _warn_bh_complexity_limit()
                return []

            data = response.json()
            self._debug(
                "path query data",
                has_data=isinstance(data, dict),
                keys=list(data.keys()) if isinstance(data, dict) else None,
            )
            literals: List[Dict] = (data.get("data") or {}).get("literals") or []
            paths = self._parse_path_literals(literals)
            self._debug("path query parsed", raw_literals=len(literals), parsed_paths=len(paths))
            if paths:
                for i, sample in enumerate(paths[:2]):
                    node_names = " → ".join(
                        str(nd.get("label") or nd.get("objectId") or "?")
                        for nd in (sample.get("nodes") or [])
                    )
                    self._debug(f"path sample [{i}]", nodes=node_names, rels=sample.get("rels"))
                if len(paths) > 4:
                    for i, sample in enumerate(paths[-2:], start=len(paths) - 2):
                        node_names = " → ".join(
                            str(nd.get("label") or nd.get("objectId") or "?")
                            for nd in (sample.get("nodes") or [])
                        )
                        self._debug(f"path sample [{i}]", nodes=node_names, rels=sample.get("rels"))
            return paths

        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._debug("path query error", error=str(exc))
            return []

    def execute_query_with_relationships(self, query: str) -> Dict:
        """Execute a Cypher query and include relationships in the response"""
        try:
            url = f"{self.base_url}/api/v2/graphs/cypher"

            cleaned_query = " ".join(query.split())
            print_cypher_query(cleaned_query)
            payload = {
                "query": cleaned_query,
                "include_properties": True,
                "include_relationships": True,
            }

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

    def get_timeroast_candidates(
        self, domain: str, max_results: int = 250
    ) -> List[Dict]:
        """Return enabled computer accounts matching Timeroast heuristics."""
        try:
            domain_value = str(domain or "").strip().replace("'", "\\'")
            current_epoch = int(time.time())
            max_results_value = max(1, int(max_results or 250))
            month_seconds = 30 * 24 * 60 * 60
            min_gap_seconds = 5 * 60

            cypher_query = f"""
            MATCH (c:Computer)
            WHERE c.enabled = true
              AND toLower(coalesce(c.domain, "")) = toLower('{domain_value}')
              AND coalesce(c.pwdlastset, 0) > 0
              AND coalesce(c.whencreated, 0) > 0
              AND (
                (
                  c.pwdlastset <> c.whencreated
                  AND c.pwdlastset > c.whencreated
                  AND (c.pwdlastset - c.whencreated) >= {min_gap_seconds}
                  AND (c.pwdlastset - c.whencreated) < {month_seconds}
                )
                OR
                (
                  c.pwdlastset > c.whencreated
                  AND (c.pwdlastset - c.whencreated) >= {min_gap_seconds}
                  AND
                  ({current_epoch} - c.pwdlastset) > {month_seconds}
                )
              )
            RETURN c
            ORDER BY c.pwdlastset ASC
            LIMIT {max_results_value}
            """
            result = self.execute_query(cypher_query)
            candidates: List[Dict] = []
            for node_properties in result:
                if not isinstance(node_properties, dict):
                    continue
                samaccountname = node_properties.get("samaccountname") or ""
                if samaccountname and "@" in samaccountname:
                    samaccountname = samaccountname.split("@")[0]
                candidates.append(
                    {
                        "samaccountname": samaccountname,
                        "name": node_properties.get("name"),
                        "dnshostname": node_properties.get("dnshostname"),
                        "objectid": node_properties.get("objectid"),
                        "pwdlastset": node_properties.get("pwdlastset"),
                        "whencreated": node_properties.get("whencreated"),
                        "operatingsystem": node_properties.get("operatingsystem"),
                    }
                )
            return candidates
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

    def _build_bh_edge_type_filter(self) -> str:
        """Return the Cypher relationship-type filter string derived from the catalog.

        Example output: ``[:MemberOf|GenericAll|GenericWrite|...*]``
        When the catalog provides no BH-native types (should not happen), returns
        an empty string so queries fall back to unrestricted traversal.
        """
        try:
            from adscan_internal.services.attack_step_catalog import (
                get_bh_cypher_relation_types,
            )

            types = get_bh_cypher_relation_types()
            if not types:
                return ""
            return ":" + "|".join(types)
        except Exception:
            return ""

    def get_low_priv_paths_to_high_value(
        self,
        domain: str,
        *,
        max_depth: int = 5,
        max_paths: Optional[int] = None,
        target: str = "highvalue",
    ) -> List[Dict]:
        """Return raw path rows from low-priv users to high-value targets.

        When ``target="all"`` the target filter is omitted so paths to any
        non-source node are returned.  When ``target="lowpriv"`` only paths
        to non-high-value nodes are returned.

        Args:
            max_paths: When provided, adds a Cypher ``LIMIT`` clause so Neo4j
                caps the subgraph size before returning it.  This dramatically
                reduces both network transfer and Python-side DFS time when
                there are many paths (large domains).
        """
        try:
            depth = max(1, max_depth)
            domain_value = domain.replace("'", "\\'")
            source_domain_filter = self._build_domain_filter(
                alias="u",
                domain_value=domain_value,
            )
            source_enabled_filter = self._build_enabled_filter(
                alias="u", default_true=True
            )
            source_high_value_filter = self._build_high_value_filter(alias="u")
            edge_filter = self._build_bh_edge_type_filter()
            acyclic_filter = self._build_acyclic_path_filter(nodes_alias="ns")

            named_target_filter = f"\n  AND {self._build_named_node_filter(alias='h')}"

            if target == "highvalue":
                target_clause = f"  AND {self._build_high_value_filter(alias='h')}"
                no_intermediate_hv = f"\n  AND {self._build_no_intermediate_high_value_filter(nodes_alias='ns')}"
                no_terminal_memberof = ""
            elif target == "lowpriv":
                target_clause = f"  AND NOT {self._build_high_value_filter(alias='h')}"
                no_intermediate_hv = f"\n  AND {self._build_no_intermediate_high_value_filter(nodes_alias='ns')}"
                no_terminal_memberof = f"\n  AND {self._build_non_terminal_memberof_filter(nodes_alias='ns', except_highvalue_terminal=False)}"
            else:  # "all"
                target_clause = ""
                no_intermediate_hv = f"\n  AND {self._build_no_intermediate_high_value_filter(nodes_alias='ns')}"
                no_terminal_memberof = f"\n  AND {self._build_non_terminal_memberof_filter(nodes_alias='ns', except_highvalue_terminal=True)}"

            limit_clause = f"\nLIMIT {max(1, max_paths)}" if max_paths is not None else ""
            cypher_query = f"""
            MATCH p=(u:User)-[{edge_filter}*1..{depth}]->(h)
            WHERE {source_domain_filter}
              AND {source_enabled_filter}
              AND NOT {source_high_value_filter}{target_clause}{named_target_filter}
            WITH p, nodes(p) AS ns
            WHERE {acyclic_filter}{no_intermediate_hv}{no_terminal_memberof}
            RETURN ns AS path_nodes, relationships(p) AS rels{limit_clause}
            """

            return self.execute_path_query(cypher_query)
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
        """Return a Cypher predicate that identifies Tier Zero/high-value nodes.

        Uses ``split(system_tags, ' ')`` instead of treating ``system_tags`` as a
        list — in BH CE the property is a space-separated string, so ``IN []``
        never matches and nodes with ``admin_tier_0`` would incorrectly pass the
        filter.
        """
        return (
            "("
            f"coalesce({alias}.highvalue, false) = true "
            f"OR 'admin_tier_0' IN split(coalesce({alias}.system_tags, ''), ' ') "
            f"OR coalesce({alias}.isTierZero, false) = true"
            ")"
        )

    def _build_tier_zero_filter(self, *, alias: str) -> str:
        """Return a Cypher predicate that identifies Tier Zero nodes only."""
        return (
            "("
            f"'admin_tier_0' IN split(coalesce({alias}.system_tags, ''), ' ') "
            f"OR coalesce({alias}.isTierZero, false) = true"
            ")"
        )

    def _build_named_node_filter(self, *, alias: str) -> str:
        """Return a Cypher predicate that excludes stub/incomplete nodes without a name.

        BH CE creates minimal stub nodes (e.g. delegation SPN targets) that only
        carry ``lastseen`` and ``objectid`` but no ``name`` property.  These nodes
        are never meaningful attack targets and must be excluded from all path
        queries regardless of target mode.
        """
        return f"{alias}.name IS NOT NULL"

    def _build_non_membership_path_filter(self, *, path_alias: str = "p") -> str:
        """Return a Cypher predicate requiring at least one non-MemberOf edge in a path."""
        return f"ANY(r IN relationships({path_alias}) WHERE type(r) <> 'MemberOf')"

    def _build_non_terminal_memberof_filter(
        self,
        *,
        path_alias: str = "p",
        nodes_alias: str = "nodes(p)",
        except_highvalue_terminal: bool = False,
    ) -> str:
        """Return a predicate that limits MemberOf as the terminal edge.

        Paths ending with a MemberOf edge after an interesting step (e.g.
        KERBEROAST → JON.SNOW → MemberOf → NIGHT WATCH) add no attack value —
        MemberOf is a property of the compromised principal, not an actionable
        next step.

        When ``except_highvalue_terminal=True`` (``--all`` mode) the filter is
        relaxed: a MemberOf terminal is still allowed when the terminal node IS
        high-value/tier-zero (e.g. USER1 → MemberOf → DOMAIN ADMINS).  That case
        represents a real privilege-escalation finding and must be preserved.

        When ``except_highvalue_terminal=False`` (normal high-value mode) the
        filter is not used at all — callers already require the terminal to be
        high-value, so a MemberOf edge to DOMAIN ADMINS is always valid.
        """
        base = f"type(last(relationships({path_alias}))) <> 'MemberOf'"
        if not except_highvalue_terminal:
            return base
        ns = nodes_alias
        terminal_hv = (
            f"coalesce(last({ns}).highvalue, false) = true"
            f" OR 'admin_tier_0' IN split(coalesce(last({ns}).system_tags, ''), ' ')"
            f" OR coalesce(last({ns}).isTierZero, false) = true"
        )
        return f"({base} OR ({terminal_hv}))"

    def _build_no_intermediate_high_value_filter(self, *, nodes_alias: str = "nodes(p)") -> str:
        """Return a predicate ensuring only the terminal node can be high-value.

        Prevents BH from returning paths that pass *through* a high-value node on
        the way to another high-value node.  Example: WINTERFELL (a DC, tier-zero)
        → MemberOf → DOMAIN CONTROLLERS (also tier-zero) would generate two paths:
        one ending at WINTERFELL and one ending at DOMAIN CONTROLLERS.  The longer
        one is redundant because owning WINTERFELL already gives full domain access.

        Uses ``ALL(n IN ns WHERE n = last(ns) OR NOT <is_highvalue>)`` rather than
        list slicing.  List slicing on path functions (``nodes(p)[..-1]``,
        ``nodes(p)[0..size(nodes(p))-1]``) causes ``Type mismatch: expected List<T>
        but was Integer`` on Neo4j 4.4 / BloodHound CE.  ``last()`` and ``ALL()``
        are first-class Cypher 4.x constructs that work reliably.

        Callers should pass ``nodes_alias="ns"`` and include ``nodes(p) AS ns`` in
        the preceding ``WITH`` clause so the list is computed once per row.

        Only meaningful when ``target="highvalue"`` or ``target="lowpriv"``; callers
        should skip this filter in ``--all`` mode.
        """
        hv = self._build_high_value_filter(alias="n")
        ns = nodes_alias
        return f"ALL(n IN {ns} WHERE n = last({ns}) OR NOT ({hv}))"

    def _build_acyclic_path_filter(self, *, nodes_alias: str = "nodes(p)") -> str:
        """Return a Cypher predicate that rejects paths containing repeated nodes.

        Variable-length BH traversals can return paths where the same node
        appears more than once (e.g. DOMAIN USERS → ... → DOMAIN USERS → ...).
        Filtering these out in Cypher avoids shipping useless rows over the
        network and removes the need for Python-side cyclic detection.

        Uses ``single()`` instead of a nested list comprehension.  The nested
        form ``ALL(n IN nodes(p) WHERE 1 = size([x IN nodes(p) WHERE x = n]))``
        triggers "Variable `x` not defined" on Neo4j 4.4 because the parser
        does not resolve variables introduced inside list comprehensions that
        are nested inside ``ALL()`` predicates.  ``single()`` is a first-class
        predicate function in Neo4j 4.4 and avoids the scoping issue entirely:
        ``single(m IN nodes(p) WHERE id(m) = id(n))`` returns true iff exactly
        one node in the path has the same internal Neo4j id as ``n``.

        Callers should pass ``nodes_alias="ns"`` and include ``nodes(p) AS ns`` in
        the preceding ``WITH`` clause so the list is computed once per row.
        """
        ns = nodes_alias
        return f"ALL(n IN {ns} WHERE single(m IN {ns} WHERE id(m) = id(n)))"

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

    def _build_non_tier_zero_source_filter(
        self,
        *,
        source_alias: str,
        domain_value: str,
        match_domain_by_name_suffix: bool = False,
    ) -> str:
        """Return a predicate for enabled non-TierZero principals, including high-value pivots."""
        domain_predicate = self._build_domain_filter(
            alias=source_alias,
            domain_value=domain_value,
            match_domain_by_name_suffix=match_domain_by_name_suffix,
        )
        enabled_predicate = self._build_enabled_filter(
            alias=source_alias, default_true=True
        )
        tier_zero_predicate = self._build_tier_zero_filter(alias=source_alias)

        return f"""
              AND ({source_alias}:User OR {source_alias}:Group OR {source_alias}:Computer)
              AND {domain_predicate}
              AND {enabled_predicate}
              AND NOT {tier_zero_predicate}
        """

    def get_low_priv_acl_paths(
        self, domain: str, *, max_results: int | None = None
    ) -> List[Dict]:
        """Return ACL/ACE-derived single-step paths from non-TierZero principals.

        This query enumerates ACL-relevant relationships (r.isacl=true) that can
        be exercised by non-TierZero principals either directly or through
        nested group membership (MemberOf*0..).

        It returns paths for visualization in the UI, but we post-process the
        response into single-step "effective" paths shaped as:

            {"nodes": [<user_node>, <target_node>], "rels": [<relation>]}

        which is compatible with the existing attack-graph ingestion helpers.
        """
        try:
            return self._get_low_priv_acl_paths_with_filters(
                domain,
                max_results=max_results,
                target_filter="",
                excluded_source_objectids=None,
            )
        except Exception:
            return []

    def get_low_priv_acl_paths_to_high_value(
        self, domain: str, *, max_results: int = 1000
    ) -> List[Dict]:
        """Return low-priv ACL path steps that participate in short paths to HV targets.

        Unlike the direct ACL helper, this query walks up to four ACL edges deep
        so we can keep intermediate low-priv pivots such as:

            LOWPRIV_GROUP -> AddMember -> INTERMEDIATE_GROUP -> GenericAll -> DOMAIN ADMINS

        The returned value is still normalized into direct single-step edges so
        the existing attack-graph ingestion logic can store each step without
        duplication.
        """
        try:
            allowed_relations = self._get_low_priv_acl_allowed_relations()
            depth = 3
            domain_value = domain.replace("'", "\\'")
            limit_value = max(1, min(int(max_results), 5000))
            source_filter = self._build_low_priv_source_filter(
                source_alias="s",
                domain_value=domain_value,
                match_domain_by_name_suffix=True,
            )
            acyclic_filter = self._build_acyclic_path_filter(nodes_alias="ns")
            no_intermediate_hv = self._build_no_intermediate_high_value_filter(
                nodes_alias="ns"
            )
            target_filter = self._build_high_value_filter(alias="t")
            named_target_filter = self._build_named_node_filter(alias="t")

            cypher_query = f"""
            MATCH p=(s)-[*1..{depth}]->(t)
            WHERE 1=1
              {source_filter}
              AND {target_filter}
              AND {named_target_filter}
            WITH p, nodes(p) AS ns
            WHERE {acyclic_filter}
              AND {no_intermediate_hv}
              AND ALL(r IN relationships(p) WHERE type(r) IN {sorted(allowed_relations)!r})
            RETURN ns AS path_nodes, relationships(p) AS rels
            LIMIT {limit_value}
            """

            paths = self.execute_path_query(cypher_query)
            if not paths:
                return []
            return self._extract_direct_allowed_edges_from_paths(
                paths,
                allowed_relations=allowed_relations,
            )
        except Exception:
            return []

    def get_low_priv_acl_paths_to_non_high_value(
        self,
        domain: str,
        *,
        max_results: int = 1000,
        excluded_source_objectids: List[str] | None = None,
    ) -> List[Dict]:
        """Return low-priv ACL paths whose targets are not high-value / tier-zero.

        Optionally excludes source principals already seen reaching high-value
        targets so the second ACL phase is reserved for additional low-priv pivots.
        """
        try:
            target_filter = f"\n              AND NOT {self._build_high_value_filter(alias='t')}"
            return self._get_low_priv_acl_paths_with_filters(
                domain,
                max_results=max_results,
                target_filter=target_filter,
                excluded_source_objectids=excluded_source_objectids,
            )
        except Exception:
            return []

    def _get_low_priv_acl_paths_with_filters(
        self,
        domain: str,
        *,
        max_results: int | None,
        target_filter: str,
        excluded_source_objectids: List[str] | None,
    ) -> List[Dict]:
        """Execute the shared low-priv ACL query with optional target/source filters."""
        allowed_relations = self._get_low_priv_acl_allowed_relations()
        domain_value = domain.replace("'", "\\'")
        source_filter = self._build_non_tier_zero_source_filter(
            source_alias="s",
            domain_value=domain_value,
            match_domain_by_name_suffix=True,
        )
        excluded_sources_filter = self._build_objectid_exclusion_filter(
            alias="s",
            objectids=excluded_source_objectids,
        )

        limit_clause = ""
        if max_results is not None:
            limit_value = max(1, min(int(max_results), 5000))
            limit_clause = f"\n        LIMIT {limit_value}"

        cypher_query = f"""
        MATCH p=(s)-[r]->(t)
        WHERE 1=1
          {source_filter}
          AND type(r) IN {sorted(allowed_relations)!r}{target_filter}{excluded_sources_filter}
        RETURN p
        """.rstrip() + limit_clause

        graph_data = self.execute_query_with_relationships(cypher_query)
        if not graph_data:
            return []
        return self._extract_direct_allowed_edges_from_graph(
            graph_data, allowed_relations=allowed_relations
        )

    def _get_low_priv_acl_allowed_relations(self) -> set[str]:
        """Return the ACL relationship types used in Phase 2 low-priv collection."""
        return {
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
            "WriteSPN",
        }

    def _build_objectid_exclusion_filter(
        self, *, alias: str, objectids: List[str] | None
    ) -> str:
        """Return a Cypher predicate excluding nodes whose objectId matches any value."""
        cleaned = sorted(
            {
                str(value or "").strip()
                for value in (objectids or [])
                if str(value or "").strip()
            }
        )
        if not cleaned:
            return ""
        escaped = "[" + ", ".join(repr(value) for value in cleaned) + "]"
        return (
            f"\n              AND NOT coalesce({alias}.objectid, {alias}.objectId, '') IN {escaped}"
        )

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
            from adscan_internal.services.attack_step_catalog import (
                get_bh_native_adcs_cypher_names,
            )

            allowed_relations = get_bh_native_adcs_cypher_names()
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
        """Extract all paths from a BH CE subgraph response without Python-side filtering.

        BH CE Cypher queries already apply all filters (high-value targets, MemberOf-only
        paths, domain, etc.) before returning the subgraph.  This method simply
        reconstructs the ordered paths from the nodes/edges the query returned.

        Source nodes are identified structurally as nodes with no incoming edges
        (in-degree 0 in the subgraph); terminal nodes are those with no outgoing edges
        (out-degree 0).  No high-value, kind, or membership checks are performed here.
        """
        nodes_map = graph_data.get("nodes", {})
        edges = graph_data.get("edges", [])
        if not nodes_map or not edges:
            return []

        adjacency: Dict[str, List[Dict]] = {}
        all_targets: set[str] = set()
        for edge in edges:
            source = edge.get("source")
            target = edge.get("target")
            if not source or not target:
                continue
            adjacency.setdefault(source, []).append(
                {"target": target, "label": edge.get("label") or edge.get("kind")}
            )
            all_targets.add(target)

        # Nodes with in-degree 0 are path origins; nodes with out-degree 0 are terminals.
        start_nodes = [nid for nid in nodes_map if nid not in all_targets]
        terminal_nodes = {nid for nid in nodes_map if nid not in adjacency}

        results: List[Dict] = []
        seen_paths: set[tuple[str, ...]] = set()

        for start in start_nodes:
            stack = [(start, [start], [])]
            while stack:
                current, path_nodes, path_rels = stack.pop()
                if current in terminal_nodes and current != start:
                    path_key = tuple(path_nodes)
                    if path_key not in seen_paths:
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

    def _extract_direct_allowed_edges_from_paths(
        self, paths: List[Dict], *, allowed_relations: set[str]
    ) -> List[Dict]:
        """Flatten path rows into unique direct edges.

        This is used when a recursive path query is intentionally expanded into
        single-step attack-graph edges for storage.
        """
        results: List[Dict] = []
        seen_keys: set[tuple[str, str, str]] = set()

        for path in paths:
            nodes = path.get("nodes") or []
            rels = path.get("rels") or []
            if not isinstance(nodes, list) or not isinstance(rels, list):
                continue
            if len(nodes) < 2 or len(rels) != len(nodes) - 1:
                continue

            for idx, rel in enumerate(rels):
                label = str(rel or "").strip()
                if not label or label not in allowed_relations:
                    continue
                src_node = nodes[idx]
                tgt_node = nodes[idx + 1]
                if not isinstance(src_node, dict) or not isinstance(tgt_node, dict):
                    continue
                src_key = str(
                    src_node.get("objectId")
                    or src_node.get("objectid")
                    or src_node.get("label")
                    or src_node.get("name")
                    or idx
                )
                tgt_key = str(
                    tgt_node.get("objectId")
                    or tgt_node.get("objectid")
                    or tgt_node.get("label")
                    or tgt_node.get("name")
                    or idx
                )
                key = (src_key, label, tgt_key)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                results.append({"nodes": [src_node, tgt_node], "rels": [label]})

        return results


    def _bh_paths_to_display_records(
        self,
        bh_paths: List[Dict],
        *,
        domain: str,
        max_paths: Optional[int] = None,
    ) -> Tuple[List[Dict], Dict]:
        """Convert extracted BH paths to display records and a minimal graph dict.

        Args:
            bh_paths: List of ``{"nodes": [node_dict, ...], "rels": [label, ...]}``
                      as returned by ``_extract_paths_from_graph``.
            domain: Domain name (e.g. ``"corp.local"``).
            max_paths: Optional cap on the number of display records returned.

        Returns:
            A tuple ``(display_records, graph)`` where *graph* has the
            ``{"nodes": {key: node_dict}, "edges": []}`` shape expected by
            ``attack_paths_core.apply_affected_user_metadata``.
        """
        display_records: List[Dict] = []
        graph_nodes: Dict = {}

        for path in bh_paths:
            if max_paths is not None and len(display_records) >= max_paths:
                break

            node_dicts: List[Dict] = path.get("nodes") or []
            rels: List[str] = path.get("rels") or []
            if not node_dicts or not rels or len(node_dicts) != len(rels) + 1:
                continue

            # Build canonical string labels from BH ``label`` field.
            node_labels: List[str] = []
            for node in node_dicts:
                label = str(node.get("label") or "").strip()
                if not label:
                    props = (
                        node.get("properties")
                        if isinstance(node.get("properties"), dict)
                        else {}
                    )
                    label = str(props.get("name") or node.get("objectId") or "")
                node_labels.append(label)

            if len(node_labels) < 2:
                continue

            # Populate graph_nodes keyed by objectId (or label fallback).
            for node, label in zip(node_dicts, node_labels):
                node_key = str(node.get("objectId") or label)
                if node_key and node_key not in graph_nodes:
                    graph_nodes[node_key] = {
                        "label": label,
                        "kind": node.get("kind") or "",
                        "objectId": str(node.get("objectId") or ""),
                        "isTierZero": bool(node.get("isTierZero")),
                        "properties": (
                            node.get("properties")
                            if isinstance(node.get("properties"), dict)
                            else {}
                        ),
                    }

            # Build steps list.
            steps: List[Dict] = []
            for i, rel in enumerate(rels):
                src_label = node_labels[i]
                tgt_label = node_labels[i + 1]
                src_short = src_label.split("@")[0] if "@" in src_label else src_label
                tgt_short = tgt_label.split("@")[0] if "@" in tgt_label else tgt_label
                steps.append(
                    {
                        "step": i + 1,
                        "action": str(rel or ""),
                        "details": {"from": src_short, "to": tgt_short},
                    }
                )

            display_records.append(
                {
                    "nodes": node_labels,
                    "relations": [str(r or "") for r in rels],
                    "steps": steps,
                    "length": len(rels),
                    "status": "theoretical",
                    "source": node_labels[0],
                    "target": node_labels[-1],
                    "meta": {},
                }
            )

        graph: Dict = {"nodes": graph_nodes, "edges": []}
        return display_records, graph

    @staticmethod
    def _to_sam_and_domain(name: str, domain: str) -> tuple[str, str]:
        """Extract (samaccountname, domain) from a principal name.

        Matching by ``samaccountname + domain`` instead of ``name`` is
        necessary because BloodHound CE stores user nodes as
        ``SAM@DOMAIN`` but computer nodes as FQDN (e.g.
        ``EXCH01.PIRATE.HTB``), so a ``name``-based filter would never
        match computer accounts supplied as ``exch01$`` or
        ``exch01$@pirate.htb``.
        """
        n = str(name or "").strip()
        if "@" in n:
            sam, _, dom = n.partition("@")
            return sam.lower(), (dom or domain).lower()
        return n.lower(), (domain or "").lower()

    def get_attack_paths_for_user(
        self,
        domain: str,
        username: str,
        *,
        max_depth: int = 6,
        max_paths: Optional[int] = None,
        target: str = "highvalue",
    ) -> List[Dict]:
        """Return extracted BH paths from a specific principal to high-value nodes.

        Args:
            domain: Domain name (e.g. ``"corp.local"``).
            username: Principal UPN (e.g. ``"user@corp.local"``).
            max_depth: Maximum path length (capped at 8).
            max_paths: Optional LIMIT applied to the Cypher query.
            target: ``"highvalue"`` (default) restricts terminal nodes to
                Tier-0/high-value; ``"all"`` removes the filter; ``"lowpriv"``
                restricts to non-high-value terminals.

        Returns:
            List of ``{"nodes": [node_dict, ...], "rels": [label, ...]}`` paths
            suitable for ``_bh_paths_to_display_records``.
        """
        try:
            depth = max(1, max_depth)
            sam, dom = self._to_sam_and_domain(username, domain)
            sam_safe = sam.replace("'", "\\'")
            dom_safe = dom.replace("'", "\\'")
            edge_filter = self._build_bh_edge_type_filter()
            non_membership_filter = self._build_non_membership_path_filter(path_alias="p")
            acyclic_filter = self._build_acyclic_path_filter(nodes_alias="ns")

            named_target_filter = f"\n  AND {self._build_named_node_filter(alias='h')}"

            if target == "highvalue":
                target_filter = self._build_high_value_filter(alias="h")
                where_target = f"  AND {target_filter}"
                no_intermediate_hv = f"\n  AND {self._build_no_intermediate_high_value_filter(nodes_alias='ns')}"
                no_terminal_memberof = ""
            elif target == "lowpriv":
                where_target = f"  AND NOT {self._build_high_value_filter(alias='h')}"
                no_intermediate_hv = f"\n  AND {self._build_no_intermediate_high_value_filter(nodes_alias='ns')}"
                no_terminal_memberof = f"\n  AND {self._build_non_terminal_memberof_filter(nodes_alias='ns', except_highvalue_terminal=False)}"
            else:  # "all"
                where_target = ""
                no_intermediate_hv = f"\n  AND {self._build_no_intermediate_high_value_filter(nodes_alias='ns')}"
                no_terminal_memberof = f"\n  AND {self._build_non_terminal_memberof_filter(nodes_alias='ns', except_highvalue_terminal=True)}"

            limit_clause = f"\nLIMIT {max(1, max_paths)}" if max_paths is not None else ""
            cypher_query = f"""
            MATCH p=(s)-[{edge_filter}*1..{depth}]->(h)
            WHERE toLower(coalesce(s.samaccountname, "")) = toLower('{sam_safe}')
              AND toLower(coalesce(s.domain, "")) = toLower('{dom_safe}'){where_target}{named_target_filter}
            WITH p, nodes(p) AS ns
            WHERE {non_membership_filter}
              AND {acyclic_filter}{no_intermediate_hv}{no_terminal_memberof}
            RETURN ns AS path_nodes, relationships(p) AS rels{limit_clause}
            """

            return self.execute_path_query(cypher_query)
        except Exception:
            return []

    def get_attack_paths_from_owned(
        self,
        domain: str,
        principals: List[str],
        *,
        max_depth: int = 6,
        max_paths: Optional[int] = None,
        target: str = "highvalue",
    ) -> List[Dict]:
        """Return extracted BH paths from a set of owned principals to high-value nodes.

        Args:
            domain: Domain name (e.g. ``"corp.local"``).
            principals: List of principal UPNs (e.g. ``["user@corp.local"]``).
            max_depth: Maximum path length (capped at 8).
            max_paths: Optional LIMIT applied to the Cypher query.
            target: ``"highvalue"`` (default) restricts terminal nodes to
                Tier-0/high-value; ``"all"`` removes the filter; ``"lowpriv"``
                restricts to non-high-value terminals.

        Returns:
            List of ``{"nodes": [node_dict, ...], "rels": [label, ...]}`` paths
            suitable for ``_bh_paths_to_display_records``.
        """
        try:
            if not principals:
                return []
            depth = max(1, max_depth)
            domain_value = str(domain or "").replace("'", "\\'")
            domain_filter = self._build_domain_filter(
                alias="s", domain_value=domain_value
            )
            source_high_value_filter = self._build_high_value_filter(alias="s")
            edge_filter = self._build_bh_edge_type_filter()
            non_membership_filter = self._build_non_membership_path_filter(path_alias="p")
            acyclic_filter = self._build_acyclic_path_filter(nodes_alias="ns")

            named_target_filter = f"\n              AND {self._build_named_node_filter(alias='h')}"

            if target == "highvalue":
                target_filter = self._build_high_value_filter(alias="h")
                where_target = f"\n              AND {target_filter}"
                no_intermediate_hv = f"\n  AND {self._build_no_intermediate_high_value_filter(nodes_alias='ns')}"
                no_terminal_memberof = ""
            elif target == "lowpriv":
                where_target = f"\n              AND NOT {self._build_high_value_filter(alias='h')}"
                no_intermediate_hv = f"\n  AND {self._build_no_intermediate_high_value_filter(nodes_alias='ns')}"
                no_terminal_memberof = f"\n  AND {self._build_non_terminal_memberof_filter(nodes_alias='ns', except_highvalue_terminal=False)}"
            else:  # "all"
                where_target = ""
                no_intermediate_hv = f"\n  AND {self._build_no_intermediate_high_value_filter(nodes_alias='ns')}"
                no_terminal_memberof = f"\n  AND {self._build_non_terminal_memberof_filter(nodes_alias='ns', except_highvalue_terminal=True)}"

            limit_clause = f"\nLIMIT {max(1, max_paths)}" if max_paths is not None else ""
            cypher_query = f"""
            MATCH p=(s)-[{edge_filter}*1..{depth}]->(h)
            WHERE {domain_filter}
              AND COALESCE(s.system_tags, '') CONTAINS 'owned'
              AND NOT {source_high_value_filter}{where_target}{named_target_filter}
            WITH p, nodes(p) AS ns
            WHERE {non_membership_filter}
              AND {acyclic_filter}{no_intermediate_hv}{no_terminal_memberof}
            RETURN ns AS path_nodes, relationships(p) AS rels{limit_clause}
            """

            return self.execute_path_query(cypher_query)
        except Exception:
            return []

    def mark_principal_owned(self, username: str, *, owned: bool = True) -> bool:
        """Mark or unmark a principal as owned in BloodHound via Cypher.

        Args:
            username: Principal UPN (e.g. ``"user@corp.local"``).
            owned: ``True`` to mark as owned, ``False`` to unmark.

        Returns:
            ``True`` if the Cypher executed without exceptions, ``False`` otherwise.
        """
        try:
            sam, dom = self._to_sam_and_domain(str(username or ""), "")
            sam_safe = sam.replace("'", "\\'")
            dom_safe = dom.replace("'", "\\'")
            node_filter = (
                f"toLower(coalesce(n.samaccountname, \"\")) = toLower('{sam_safe}')"
                f" AND toLower(coalesce(n.domain, \"\")) = toLower('{dom_safe}')"
            )

            # Read current tags first to avoid CASE expressions, which BH CE may reject.
            read_query = f"""
            MATCH (n)
            WHERE {node_filter}
            RETURN n
            LIMIT 1
            """
            rows = self.execute_query(read_query) or []
            print_info_debug(f"rows: {rows}")
            if not rows:
                return False

            current_tags = str(rows[0].get("system_tags") or "").strip()
            self._debug(
                "mark_principal_owned current state",
                username=sam_safe,
                current_tags=current_tags,
                owned=owned,
            )
            if owned:
                if current_tags == "owned" or "owned" in [t.strip() for t in current_tags.split(",") if t.strip()]:
                    return True

                if not current_tags:
                    cypher_query = f"""
                    MATCH (n)
                    WHERE {node_filter}
                    SET n.system_tags = 'owned'
                    RETURN n
                    """
                else:
                    cypher_query = f"""
                    MATCH (n)
                    WHERE {node_filter}
                    AND NOT coalesce(n.system_tags, '') CONTAINS 'owned'
                    SET n.system_tags = n.system_tags + ',owned'
                    RETURN n
                    """
            else:
                tag_list = [t.strip() for t in current_tags.split(",") if t.strip()]
                if "owned" not in tag_list:
                    return True

                remaining_tags = [t for t in tag_list if t != "owned"]

                if remaining_tags:
                    new_tags = ",".join(remaining_tags).replace("'", "\\'")
                    cypher_query = f"""
                    MATCH (n)
                    WHERE {node_filter}
                    SET n.system_tags = '{new_tags}'
                    RETURN n
                    """
                else:
                    cypher_query = f"""
                    MATCH (n)
                    WHERE {node_filter}
                    REMOVE n.system_tags
                    RETURN n
                    """

            result = self.execute_query(cypher_query) or []
            return bool(result)
        except Exception as exc:
            print_exception(show_locals=False, exception=exc)
            return False

    def get_bh_owned_principals(self, domain: str) -> set:
        """Return the set of principal names marked as owned in BloodHound for a domain.

        Args:
            domain: Domain name (e.g. ``"corp.local"``).

        Returns:
            Set of lowercase UPN strings for principals with ``owned`` in BH system_tags.
        """
        try:
            domain_value = str(domain or "").replace("'", "\\'")
            cypher_query = f"""
            MATCH (n)
            WHERE toLower(coalesce(n.domain, "")) = toLower('{domain_value}')
            AND COALESCE(n.system_tags, '') CONTAINS 'owned'
            RETURN n
            """
            rows = self.execute_query(cypher_query)
            owned_set: set = set()

            for row in rows:
                sam = str(row.get("samaccountname") or "").strip()
                dom = str(row.get("domain") or "").strip()
                system_tags = str(row.get("system_tags") or "").strip()
                system_tags_raw = row.get("system_tags")
                self._debug(
                    "owned principal row",
                    samaccountname=sam,
                    domain=dom,
                    system_tags_raw=repr(system_tags_raw),
                    system_tags_type=type(system_tags_raw).__name__,
                )
                if not sam:
                    continue

                tags = {t.strip().lower() for t in system_tags.split(",") if t.strip()}
                if "owned" in tags:
                    owned_set.add(f"{sam}@{dom}".lower())

            print_info_debug(f"owned_set: {sorted(owned_set)!r}")
            return owned_set
        except Exception:
            return set()

    def sync_owned_principals(
        self, domain: str, owned_usernames: List[str]
    ) -> Tuple[int, int]:
        """Sync BH ``owned`` state to exactly match the provided authoritative list.

        Marks principals in the list that BH does not know about, and unmarks any
        BH-owned principal that is no longer in the source-of-truth list.

        Args:
            domain: Domain name (e.g. ``"corp.local"``).
            owned_usernames: Authoritative list of owned principal names (UPNs or
                bare samAccountNames).

        Returns:
            Tuple ``(marked_count, unmarked_count)`` for logging.
        """
        source_truth = {
            f"{sam}@{dom}".lower()
            for u in owned_usernames
            if str(u or "").strip()
            for sam, dom in [self._to_sam_and_domain(u, domain)]
            if sam
        }
        bh_owned = {u.strip().lower() for u in self.get_bh_owned_principals(domain)}

        to_mark = source_truth - bh_owned
        to_unmark = bh_owned - source_truth

        marked = sum(
            1 for username in to_mark if self.mark_principal_owned(username, owned=True)
        )
        unmarked = sum(
            1 for username in to_unmark if self.mark_principal_owned(username, owned=False)
        )
        self._debug(
            "owned sync sets",
            source_truth=sorted(source_truth),
            bh_owned=sorted(bh_owned),
            to_mark=sorted(to_mark),
            to_unmark=sorted(to_unmark),
        )
        return marked, unmarked

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

            t0 = time.perf_counter()
            job_id = self._create_file_upload_job_id()
            t1 = time.perf_counter()
            if job_id is None:
                return None

            if not self._upload_file_to_job(job_id, file_path=file_path):
                return None
            t2 = time.perf_counter()

            if not self._end_file_upload_job(job_id):
                return None
            t3 = time.perf_counter()

            try:
                file_size = os.path.getsize(file_path)
            except OSError:
                file_size = -1
            timing = {
                "job_id": job_id,
                "file_size_bytes": file_size,
                "create_job_ms": round((t1 - t0) * 1000),
                "upload_ms": round((t2 - t1) * 1000),
                "end_job_ms": round((t3 - t2) * 1000),
                "total_ms": round((t3 - t0) * 1000),
            }
            print_info_debug(
                f"[bloodhound-ce] upload timing: "
                f"job_id={job_id} "
                f"size={file_size}B "
                f"create={timing['create_job_ms']}ms "
                f"upload={timing['upload_ms']}ms "
                f"end={timing['end_job_ms']}ms "
                f"total={timing['total_ms']}ms"
            )
            return job_id

        except Exception as e:
            self._last_error = f"Upload failed with exception: {e}"
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
            print_info_debug(f"[bloodhound-ce] waiting for ingestion: job_id={job_id}")

            while True:
                job = self.get_file_upload_job(job_id)
                if job is None:
                    if time.time() - start_time > 15:
                        self._last_error = f"Upload wait failed: timeout fetching job details (job_id={job_id})."
                        print_error("Timeout: Could not get job details")
                        return False
                else:
                    status = job.get("status")
                    status_message = job.get("status_message", "")

                    if status != last_status:
                        print_info(f"Job status: {status} - {status_message}")
                        last_status = status

                    # Terminal statuses: -1 invalid, 2 complete, 3 canceled, 4 timed out,
                    # 5 failed, 8 partially complete
                    if status in [-1, 2, 3, 4, 5, 8]:
                        if status == 2:
                            self._last_error = None
                            print_success(
                                "Upload and processing completed successfully"
                            )
                            return True
                        if status == 8:
                            self._last_error = (
                                "Upload completed with warnings (partially complete). "
                                f"status_message={status_message}"
                            )
                            print_warning(
                                "Upload completed with warnings (partially complete)"
                            )
                            return True

                        self._last_error = (
                            f"Upload failed with status {status}: {status_message}"
                        )
                        print_error(self._last_error)
                        return False

                if time.time() - start_time > timeout_seconds:
                    self._last_error = f"Upload wait timed out after {timeout_seconds}s for job_id={job_id}."
                    print_error(f"Timeout after {timeout_seconds} seconds")
                    return False

                time.sleep(max(1, poll_interval))

        except Exception as e:
            self._last_error = f"Upload wait failed with exception: {e}"
            print_error(f"Error in upload wait: {e}")
            return False

    def upsert_opengraph_edge(self, edge: Dict) -> bool:
        """Upsert a single custom edge into BH CE via a Cypher MERGE mutation.

        This is the fast path for custom edge creation (~10-50ms) vs the file
        upload job pipeline (~30-60s ingestion wait).  Requires
        ``bhe_enable_cypher_mutations=true`` on the BH CE container (default).

        Args:
            edge: OpenGraph edge dict with ``kind``, ``start``, ``end``,
                  ``properties`` as produced by ``_build_opengraph_ref``.

        Returns:
            True if the mutation was accepted (HTTP 200), False otherwise.
        """
        try:
            kind = str(edge.get("kind") or "").strip()
            start_ref = edge.get("start") or {}
            end_ref = edge.get("end") or {}
            props = edge.get("properties") or {}

            if not kind or not start_ref or not end_ref:
                return False

            # Build MATCH predicates from the match_by / value refs.
            def _match_clause(var: str, ref: Dict) -> str:
                match_by = str(ref.get("match_by") or "").strip().lower()
                value = str(ref.get("value") or "").replace("'", "\\'")
                if match_by == "id":
                    return f"MATCH ({var}) WHERE toUpper(coalesce({var}.objectid, '')) = toUpper('{value}')"
                # match_by == "name" — stored as NAME@DOMAIN uppercase in BH CE.
                return f"MATCH ({var}) WHERE {var}.name = '{value}'"

            # Sanitize the relationship type for use as a Cypher identifier.
            # Non-alphanumeric chars are rare but backtick-quote just in case.
            safe_kind = kind.replace("`", "")

            # Edge properties to set.
            state = str(props.get("state") or "discovered").replace("'", "\\'")
            source = str(props.get("source") or "adscan").replace("'", "\\'")
            edge_type = str(props.get("edge_type") or "").replace("'", "\\'")
            first_seen = str(props.get("first_seen") or "").replace("'", "\\'")

            query = (
                f"{_match_clause('s', start_ref)} "
                f"{_match_clause('e', end_ref)} "
                f"MERGE (s)-[r:`{safe_kind}` {{source: '{source}'}}]->(e) "
                f"SET r.state = '{state}', r.edge_type = '{edge_type}', r.first_seen = '{first_seen}' "
                f"RETURN type(r) AS kind"
            )

            cleaned_query = " ".join(query.split())
            print_cypher_query(cleaned_query)

            url = f"{self.base_url}/api/v2/graphs/cypher"
            payload = {"query": cleaned_query, "include_properties": False}
            response = self.session.post(url, json=payload, verify=self.verify, timeout=30)

            if response.status_code == 401:
                if self.ensure_authenticated_robust():
                    response = self.session.post(url, json=payload, verify=self.verify, timeout=30)
                else:
                    return False

            if response.status_code == 200:
                self._debug("opengraph cypher upsert accepted", kind=kind)
                return True

            self._debug(
                "opengraph cypher upsert failed",
                kind=kind,
                status=response.status_code,
                response_text=(response.text or "")[:200],
            )
            return False

        except Exception as exc:  # noqa: BLE001
            self._debug("opengraph cypher upsert error", error=str(exc))
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
            print_info_debug(f"[bloodhound-ce] list upload jobs failed: {e}")
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
            print_info_debug(f"[bloodhound-ce] get accepted types failed: {e}")
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
            print_info_debug(f"[bloodhound-ce] get upload job failed: job_id={job_id} error={e}")
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
            print_info_debug(f"[bloodhound-ce] infer latest upload job failed: {e}")
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
                print_info_debug(
                    f"[bloodhound-ce] token auto-renew json decode error: {exc} "
                    f"(status={response.status_code})"
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
            print_info_debug(f"[bloodhound-ce] token auto-renew error: {e}")
            return False

    def ensure_valid_token(self) -> bool:
        """Ensure we have a valid token, auto-renew if necessary"""
        if not self.api_token:
            return self.auto_renew_token()

        # Check if current token is valid
        if self.verify_token():
            return True

        # Token is invalid, try to renew
        print_info_debug("[bloodhound-ce] token expired, attempting renewal")
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
        print_warning(
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
            print_warning("Aborting: no credentials provided.")
            return False

        username = user_input or suggested_username

        try:
            import getpass

            password = getpass.getpass("BloodHound CE password: ")
        except (EOFError, KeyboardInterrupt):
            print_info_debug("[bloodhound-ce] prompt aborted: no password provided")
            print_warning("Aborting: no credentials provided.")
            return False

        if not password:
            print_info_debug("[bloodhound-ce] prompt aborted: empty password")
            print_warning("Aborting: empty password is not allowed.")
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
            print_error(
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
            print_info_debug(
                f"[bloodhound-ce] failed to persist updated credentials: {e}"
            )
            print_warning(
                "Could not persist updated BloodHound CE credentials to the config file. "
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
