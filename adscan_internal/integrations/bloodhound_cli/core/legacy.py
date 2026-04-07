"""
BloodHound Legacy (Neo4j) implementation
"""

# pylint: skip-file
from typing import List, Dict, Optional
import time
from neo4j import GraphDatabase
from .base import BloodHoundClient


class BloodHoundLegacyClient(BloodHoundClient):
    """Legacy BloodHound client using Neo4j"""

    def __init__(
        self,
        uri: str,
        user: str,
        password: str,
        debug: bool = False,
        verbose: bool = False,
    ):
        super().__init__(debug, verbose)
        self.uri = uri
        self.user = user
        self.password = password
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def execute_query(self, query: str, **params) -> List[Dict]:
        """Execute a Cypher query"""
        # Show query in debug mode
        if self.debug:
            try:
                from rich.console import Console
                from rich.syntax import Syntax

                console = Console()
                console.print("\n[bold cyan]Debug: Cypher Query[/bold cyan]")
                syntax = Syntax(query, "cypher", theme="monokai", line_numbers=False)
                console.print(syntax)
                if params:
                    console.print(
                        f"[bold cyan]Debug: Query Parameters[/bold cyan]: {params}\n"
                    )
            except ImportError:
                # Fallback if rich is not available
                print("\n" + "=" * 80)
                print("Debug: Cypher Query")
                print("=" * 80)
                print(query)
                if params:
                    print(f"Debug: Query Parameters: {params}")
                print("=" * 80 + "\n")

        with self.driver.session() as session:
            result = session.run(query, **params).data()

            if self.debug:
                print(f"Debug: Query returned {len(result)} records")

            return result

    def get_users(self, domain: str) -> List[str]:
        query = """
        MATCH (u:User)
        WHERE u.enabled = true AND toLower(u.domain) = toLower($domain)
        RETURN u.samaccountname AS samaccountname
        """
        results = self.execute_query(query, domain=domain)
        return [record["samaccountname"] for record in results]

    def get_computers(self, domain: str, laps: Optional[bool] = None) -> List[str]:
        if laps is None:
            query = """
            MATCH (c:Computer)
            WHERE toLower(c.domain) = toLower($domain) AND c.enabled = true
            RETURN toLower(c.name) AS name
            """
            params = {"domain": domain}
        else:
            query = """
            MATCH (c:Computer)
            WHERE toLower(c.domain) = toLower($domain)
              AND c.haslaps = $laps AND c.enabled = true
            RETURN toLower(c.name) AS name
            """
            params = {"domain": domain, "laps": laps}
        results = self.execute_query(query, **params)
        return [record["name"] for record in results]

    def get_admin_users(self, domain: str) -> List[str]:
        """Get admin users - includes both direct admincount and through group membership"""
        query = """
        MATCH p=(u:User)-[:MemberOf*1..]->(g:Group)
        WHERE g.admincount = true
          AND u.admincount = false
          AND u.enabled = true
          AND toLower(u.domain) = toLower($domain)
        RETURN u.samaccountname AS samaccountname
        UNION
        MATCH (u:User {admincount:true})
        WHERE u.enabled = true
          AND toLower(u.domain) = toLower($domain)
        RETURN u.samaccountname AS samaccountname
        """
        results = self.execute_query(query, domain=domain)
        return [record["samaccountname"] for record in results]

    def get_highvalue_users(self, domain: str) -> List[str]:
        """Get high-value users - includes both direct highvalue and through group membership"""
        query = """
        MATCH (u:User {highvalue: true})
        WHERE u.enabled = true AND toLower(u.domain) = toLower($domain)
        RETURN u.samaccountname AS samaccountname
        UNION
        MATCH p=(u:User)-[:MemberOf*1..]->(g:Group {highvalue: true})-[r1]->(m)
        WHERE u.enabled = true AND toLower(u.domain) = toLower($domain)
        RETURN u.samaccountname AS samaccountname
        """
        results = self.execute_query(query, domain=domain)
        return [record["samaccountname"] for record in results]

    def get_password_not_required_users(self, domain: str) -> List[str]:
        query = """
        MATCH (u:User)
        WHERE u.enabled = true AND toLower(u.domain) = toLower($domain)
          AND u.passwordnotreqd = true
        RETURN u.samaccountname AS samaccountname
        """
        results = self.execute_query(query, domain=domain)
        return [record["samaccountname"] for record in results]

    def get_password_never_expires_users(self, domain: str) -> List[str]:
        query = """
        MATCH (u:User)
        WHERE u.enabled = true AND toLower(u.domain) = toLower($domain)
          AND u.pwdneverexpires = true
        RETURN u.samaccountname AS samaccountname
        """
        results = self.execute_query(query, domain=domain)
        return [record["samaccountname"] for record in results]

    def get_stale_enabled_users(
        self, domain: str, stale_days: int = 180
    ) -> List[Dict]:
        """Legacy client best-effort stale-user query."""
        current_epoch = int(time.time())
        stale_seconds = max(1, int(stale_days or 180)) * 24 * 60 * 60
        query = """
        MATCH (u:User)
        WHERE u.enabled = true AND toLower(u.domain) = toLower($domain)
          AND (
            (coalesce(u.lastlogon, 0) > 0 AND ($current_epoch - u.lastlogon) >= $stale_seconds)
            OR
            (coalesce(u.lastlogon, 0) = 0 AND coalesce(u.whencreated, 0) > 0
             AND ($current_epoch - u.whencreated) >= $stale_seconds)
          )
        RETURN u.samaccountname AS samaccountname, u.lastlogon AS lastlogon, u.whencreated AS whencreated
        """
        results = self.execute_query(
            query,
            domain=domain,
            current_epoch=current_epoch,
            stale_seconds=stale_seconds,
        )
        records: List[Dict] = []
        for record in results:
            if not isinstance(record, dict):
                continue
            sam = record.get("samaccountname")
            if not sam:
                continue
            lastlogon = record.get("lastlogon")
            whencreated = record.get("whencreated")
            last_seen_seconds = (
                int(lastlogon)
                if isinstance(lastlogon, (int, float)) and int(lastlogon) > 0
                else (
                    int(whencreated)
                    if isinstance(whencreated, (int, float)) and int(whencreated) > 0
                    else None
                )
            )
            days_since_last_seen = None
            if last_seen_seconds is not None:
                days_since_last_seen = int((current_epoch - last_seen_seconds) // 86400)
            records.append(
                {
                    "samaccountname": sam,
                    "lastlogon": lastlogon,
                    "whencreated": whencreated,
                    "days_since_last_seen": days_since_last_seen,
                    "stale_days_threshold": max(1, int(stale_days or 180)),
                    "never_logged_on": not bool(lastlogon),
                }
            )
        return records

    def get_domain_node(self, domain: str) -> Optional[Dict]:
        """Return the BloodHound `:Domain` node properties for a domain (best-effort)."""
        query = """
        MATCH (d:Domain)
        WHERE toLower(coalesce(d.name, d.domain, d.label, "")) = toLower($domain)
        RETURN d
        LIMIT 1
        """
        try:
            results = self.execute_query(query, domain=domain)
            if isinstance(results, list) and results:
                row = results[0]
                if isinstance(row, dict) and "d" in row and isinstance(row["d"], dict):
                    return row["d"]
                if isinstance(row, dict):
                    # Some integrations may return node properties directly.
                    return row
            return None
        except Exception:
            return None

    def get_user_groups(
        self, domain: str, username: str, recursive: bool = True
    ) -> List[str]:
        path_clause = "-[:MemberOf*1..]->" if recursive else "-[:MemberOf]->"
        query = f"""
        MATCH (u:User)
        WHERE u.enabled = true
          AND toLower(u.domain) = toLower($domain)
          AND (
            toLower(u.samaccountname) = toLower($username)
            OR toLower(u.name) = toLower($username)
          )
        MATCH (u){path_clause}(g:Group)
        RETURN DISTINCT COALESCE(g.name, g.samaccountname) AS group_name,
                        g.samaccountname AS samaccountname,
                        g.domain AS group_domain
        ORDER BY toLower(group_name)
        """
        params = {"domain": domain, "username": username}
        results = self.execute_query(query, **params)

        groups: List[str] = []
        for record in results:
            display_name = record.get("group_name")
            if not display_name:
                samaccountname = record.get("samaccountname")
                group_domain = record.get("group_domain")
                if group_domain and samaccountname:
                    display_name = f"{group_domain}\\{samaccountname}"
                else:
                    display_name = samaccountname or group_domain

            if display_name:
                groups.append(display_name)

        return groups

    def get_sessions(self, domain: str, da: bool = False) -> List[Dict]:
        """
        Get sessions in a domain.
        If da=True: returns computers with sessions from domain admin users (excluding DCs),
        along with the domain admin username.
        If da=False: returns computers with high-value user sessions.
        """
        if da:
            # Domain admin sessions - exclude DCs and return DA users on non-DC computers
            query = """
            MATCH (dc:Computer)-[r1:MemberOf*0..]->(g1:Group)
            WHERE g1.objectid =~ "S-1-5-.*-516" AND toLower(dc.domain) = toLower($domain)
            WITH COLLECT(dc) AS exclude
            MATCH (c:Computer)-[n:HasSession]->(u:User {enabled:true})
            WHERE NOT c IN exclude AND toLower(c.domain) = toLower($domain)
            AND ((u.highvalue = true OR EXISTS((u)-[:MemberOf*1..]->(:Group {highvalue:true}))))
            RETURN DISTINCT toLower(c.name) AS computer, toLower(u.samaccountname) AS domain_admin
            """
        else:
            # High-value user sessions
            query = """
            MATCH (c:Computer)-[n:HasSession]->(u:User {enabled:true})
            WHERE toLower(c.domain) = toLower($domain)
            AND ((u.highvalue = true OR EXISTS((u)-[:MemberOf*1..]->(:Group {highvalue:true}))))
            RETURN DISTINCT toLower(c.name) AS computer
            """
        return self.execute_query(query, domain=domain)

    def get_password_last_change(
        self, domain: str, user: Optional[str] = None
    ) -> List[Dict]:
        if user:
            query = """
            MATCH (u:User)
            WHERE u.enabled = true AND toLower(u.domain) = toLower($domain)
              AND u.samaccountname = $user
            RETURN u.samaccountname AS samaccountname, u.pwdlastset AS pwdlastset, u.whencreated AS whencreated
            """
            params = {"domain": domain, "user": user}
        else:
            query = """
            MATCH (u:User)
            WHERE u.enabled = true AND toLower(u.domain) = toLower($domain)
            RETURN u.samaccountname AS samaccountname, u.pwdlastset AS pwdlastset, u.whencreated AS whencreated
            """
            params = {"domain": domain}
        return self.execute_query(query, **params)

    def get_timeroast_candidates(
        self, domain: str, max_results: int = 250
    ) -> List[Dict]:
        """Return enabled computer accounts matching Timeroast heuristics."""
        month_seconds = 30 * 24 * 60 * 60
        min_gap_seconds = 5 * 60
        current_epoch = int(time.time())
        query = f"""
        MATCH (c:Computer)
        WHERE c.enabled = true
          AND toLower(coalesce(c.domain, "")) = toLower($domain)
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
              ($current_epoch - c.pwdlastset) > {month_seconds}
            )
          )
        RETURN c
        ORDER BY c.pwdlastset ASC
        LIMIT $max_results
        """
        results = self.execute_query(
            query,
            domain=domain,
            current_epoch=current_epoch,
            max_results=max(1, int(max_results or 250)),
        )
        candidates: List[Dict] = []
        for row in results:
            if not isinstance(row, dict):
                continue
            node_properties = row.get("c") if isinstance(row.get("c"), dict) else row
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

    def get_critical_aces(
        self,
        source_domain: str,
        high_value: bool = False,
        username: str = "all",
        target_domain: str = "all",
        relation: str = "all",
    ) -> List[Dict]:
        """
        Queries ACLs for a specific user (source) with optional filtering on
        source and target domains. If high_value is True, only ACLs for high-value targets are returned.
        """
        # Build domain filters if not "all"
        username_filter = ""
        username_enabled = ""
        relation_filter = "[r1]"
        if relation.lower() != "all":
            relation_filter = "[r1:" + relation + "]"
        if username.lower() != "all":
            username_filter = (
                " toLower(n.samaccountname) = toLower($samaccountname) AND "
            )
        else:
            username_enabled = " {enabled: true}"
        target_filter = ""
        if target_domain.lower() != "all":
            target_filter = " AND toLower(m.domain) = toLower($target_domain) "

        query = (
            """
        MATCH p=(n """
            + username_enabled
            + """)-"""
            + relation_filter
            + """->(m)
        WHERE """
            + username_filter
            + """
          r1.isacl = true
          """
            + (
                """AND ((m.highvalue = true OR EXISTS((m)-[:MemberOf*1..]->(:Group {highvalue:true}))))"""
                if high_value
                else ""
            )
            + """
          AND toLower(n.domain) = toLower($source_domain)
          """
            + (
                """AND NOT ((n.highvalue = true OR EXISTS((n)-[:MemberOf*1..]->(:Group {highvalue:true}))))"""
                if username.lower() == "all"
                else ""
            )
            + """
          """
            + target_filter
            + """
        WITH n, m, r1,
             CASE 
                 WHEN 'User' IN labels(n) THEN 'User'
                 WHEN 'Group' IN labels(n) THEN 'Group'
                 WHEN 'Computer' IN labels(n) THEN 'Computer'
                 WHEN 'OU' IN labels(n) THEN 'OU'
                 WHEN 'GPO' IN labels(n) THEN 'GPO'
                 WHEN 'Domain' IN labels(n) THEN 'Domain'
                 ELSE 'Other'
             END AS sourceType,
             CASE 
                 WHEN 'User' IN labels(n) THEN n.samaccountname
                 WHEN 'Group' IN labels(n) THEN n.samaccountname
                 WHEN 'Computer' IN labels(n) THEN n.samaccountname
                 WHEN 'OU' IN labels(n) THEN n.distinguishedname
                 ELSE n.name
             END AS source,
             CASE 
                 WHEN 'User' IN labels(m) THEN 'User'
                 WHEN 'Group' IN labels(m) THEN 'Group'
                 WHEN 'Computer' IN labels(m) THEN 'Computer'
                 WHEN 'OU' IN labels(m) THEN 'OU'
                 WHEN 'GPO' IN labels(m) THEN 'GPO'
                 WHEN 'Domain' IN labels(m) THEN 'Domain'
                 ELSE 'Other'
             END AS targetType,
             CASE 
                 WHEN 'User' IN labels(m) THEN m.samaccountname
                 WHEN 'Group' IN labels(m) THEN m.samaccountname
                 WHEN 'Computer' IN labels(m) THEN m.samaccountname
                 WHEN 'OU' IN labels(m) THEN m.distinguishedname
                 ELSE m.name
             END AS target,
             CASE
                 WHEN n.domain IS NOT NULL THEN toLower(n.domain)
                 ELSE 'N/A'
             END AS sourceDomain,
             CASE
                 WHEN m.domain IS NOT NULL THEN toLower(m.domain)
                 ELSE 'N/A'
             END AS targetDomain
        RETURN DISTINCT {
            source: source,
            sourceType: sourceType,
            target: target,
            targetType: targetType,
            type: type(r1),
            sourceObjectId: coalesce(n.objectid, n.objectId, ''),
            targetObjectId: coalesce(m.objectid, m.objectId, ''),
            sourceDomain: sourceDomain,
            targetDomain: targetDomain,
            targetEnabled: m.enabled
        } AS result
        UNION
        MATCH p=(n """
            + username_enabled
            + """)-[:MemberOf*1..]->(g:Group)-"""
            + relation_filter
            + """->(m)
        WHERE """
            + username_filter
            + """
          r1.isacl = true
          """
            + (
                """AND ((m.highvalue = true OR EXISTS((m)-[:MemberOf*1..]->(:Group {highvalue:true}))))"""
                if high_value
                else ""
            )
            + """
          AND toLower(n.domain) = toLower($source_domain)
          """
            + (
                """AND NOT ((n.highvalue = true OR EXISTS((n)-[:MemberOf*1..]->(:Group {highvalue:true}))))"""
                if username.lower() == "all"
                else ""
            )
            + """
          """
            + target_filter
            + """
        WITH n, m, r1,
             CASE 
                 WHEN 'User' IN labels(n) THEN 'User'
                 WHEN 'Group' IN labels(n) THEN 'Group'
                 WHEN 'Computer' IN labels(n) THEN 'Computer'
                 WHEN 'OU' IN labels(n) THEN 'OU'
                 WHEN 'GPO' IN labels(n) THEN 'GPO'
                 WHEN 'Domain' IN labels(n) THEN 'Domain'
                 ELSE 'Other'
             END AS sourceType,
             CASE 
                 WHEN 'User' IN labels(n) THEN n.samaccountname
                 WHEN 'Group' IN labels(n) THEN n.samaccountname
                 WHEN 'Computer' IN labels(n) THEN n.samaccountname
                 WHEN 'OU' IN labels(n) THEN n.distinguishedname
                 ELSE n.name
             END AS source,
             CASE 
                 WHEN 'User' IN labels(m) THEN 'User'
                 WHEN 'Group' IN labels(m) THEN 'Group'
                 WHEN 'Computer' IN labels(m) THEN 'Computer'
                 WHEN 'OU' IN labels(m) THEN 'OU'
                 WHEN 'GPO' IN labels(m) THEN 'GPO'
                 WHEN 'Domain' IN labels(m) THEN 'Domain'
                 ELSE 'Other'
             END AS targetType,
             CASE 
                 WHEN 'User' IN labels(m) THEN m.samaccountname
                 WHEN 'Group' IN labels(m) THEN m.samaccountname
                 WHEN 'Computer' IN labels(m) THEN m.samaccountname
                 WHEN 'OU' IN labels(m) THEN m.distinguishedname
                 ELSE m.name
             END AS target,
             CASE
                 WHEN n.domain IS NOT NULL THEN toLower(n.domain)
                 ELSE 'N/A'
             END AS sourceDomain,
             CASE
                 WHEN m.domain IS NOT NULL THEN toLower(m.domain)
                 ELSE 'N/A'
             END AS targetDomain
        RETURN DISTINCT {
            source: source,
            sourceType: sourceType,
            target: target,
            targetType: targetType,
            type: type(r1),
            sourceObjectId: coalesce(n.objectid, n.objectId, ''),
            targetObjectId: coalesce(m.objectid, m.objectId, ''),
            sourceDomain: sourceDomain,
            targetDomain: targetDomain,
            targetEnabled: m.enabled
        } AS result
        """
        )
        return [
            r["result"]
            for r in self.execute_query(
                query,
                samaccountname=username,
                source_domain=source_domain,
                target_domain=target_domain,
                relation=relation,
            )
        ]

    def get_access_paths(
        self, source: str, connection: str, target: str, domain: str
    ) -> List[Dict]:
        """
        Constructs and executes a dynamic query based on the following cases:
        1. If source is not "all" and target is "all":
            - Filters the start node by samaccountname and domain (both case-insensitively).
        2. If source is "all" and target is "all":
            - Returns all start nodes from the specified domain with enabled:true and no admincount.
        3. If source is not "all" and target is "dcs":
            - Filters the start node by samaccountname and domain (case-insensitively) and adds additional filtering for DCs.
        The relationship type in the query is set based on the provided 'connection' parameter.
        """
        # Determine if we use the generic relationship with type IN (...) or a specific one.
        if connection.lower() == "all":
            rel_condition = "AND type(r) IN ['AdminTo','CanRDP','CanPSRemote']"
            rel_pattern = "[r]->"  # Generic relationship without type-template
        else:
            rel_condition = ""
            rel_pattern = f"[r:{connection}]->"

        if source.lower() != "all" and target.lower() == "all":
            # Specific source, all targets
            query = f"""
            MATCH p = (n)-{rel_pattern}(m)
            WHERE toLower(n.samaccountname) = toLower($source)
            AND toLower(n.domain) = toLower($domain)
            AND m.enabled = true
            {rel_condition}
            RETURN {{source: n.samaccountname, target: m.samaccountname, type: type(r)}} AS result
            """
            params = {"source": source, "domain": domain}
        elif source.lower() == "all" and target.lower() == "all":
            # All sources, all targets
            query = f"""
            MATCH p = (n)-{rel_pattern}(m)
            WHERE n.enabled = true
            AND toLower(n.domain) = toLower($domain)
            AND NOT ((n.highvalue = true OR EXISTS((n)-[:MemberOf*1..]->(:Group {{highvalue:true}}))))
            AND m.enabled = true
            {rel_condition}
            RETURN {{source: n.samaccountname, target: m.samaccountname, type: type(r)}} AS result
            """
            params = {"domain": domain}
        elif source.lower() == "all" and target.lower() == "dcs":
            # All sources, DC targets
            query = f"""
            MATCH p = (n)-{rel_pattern}(m)
            WHERE n.enabled = true
            AND toLower(n.domain) = toLower($domain)
            AND m.enabled = true
            {rel_condition}
            AND (n.admincount IS NULL OR n.admincount = false)
            AND EXISTS {{
                MATCH (m)-[:MemberOf]->(dc:Group)
                WHERE dc.objectid =~ '(?i)S-1-5-.*-516'
            }}
            RETURN {{source: n.samaccountname, target: m.samaccountname, type: type(r)}} AS result
            """
            params = {"domain": domain}
        else:
            return []
        return self.execute_query(query, **params)

    def get_critical_aces_by_domain(
        self, domain: str, blacklist: List[str], high_value: bool = False
    ) -> List[Dict]:
        """Get critical ACEs by domain with optional blacklist and high-value filtering"""
        query = (
            """
        MATCH p=(n)-[r1]->(m)
        WHERE r1.isacl = true
          AND toUpper(n.domain) = toUpper($domain)
          AND toUpper(n.domain) <> toUpper(m.domain)
          AND (size($blacklist) = 0 OR NOT toUpper(m.domain) IN $blacklist)
          """
            + ("""AND m.highvalue = true""" if high_value else "")
            + """
        WITH n, m, r1,
             CASE 
                 WHEN 'User' IN labels(n) THEN 'User'
                 WHEN 'Group' IN labels(n) THEN 'Group'
                 WHEN 'Computer' IN labels(n) THEN 'Computer'
                 WHEN 'OU' IN labels(n) THEN 'OU'
                 WHEN 'GPO' IN labels(n) THEN 'GPO'
                 WHEN 'Domain' IN labels(n) THEN 'Domain'
                 ELSE 'Other'
             END AS sourceType,
             CASE 
                 WHEN 'User' IN labels(n) THEN n.samaccountname
                 WHEN 'Group' IN labels(n) THEN n.samaccountname
                 WHEN 'Computer' IN labels(n) THEN n.samaccountname
                 WHEN 'OU' IN labels(n) THEN n.distinguishedname
                 ELSE n.name
             END AS source,
             CASE 
                 WHEN 'User' IN labels(m) THEN 'User'
                 WHEN 'Group' IN labels(m) THEN 'Group'
                 WHEN 'Computer' IN labels(m) THEN 'Computer'
                 WHEN 'OU' IN labels(m) THEN 'OU'
                 WHEN 'GPO' IN labels(m) THEN 'GPO'
                 WHEN 'Domain' IN labels(m) THEN 'Domain'
                 ELSE 'Other'
             END AS targetType,
             CASE 
                 WHEN 'User' IN labels(m) THEN m.samaccountname
                 WHEN 'Group' IN labels(m) THEN m.samaccountname
                 WHEN 'Computer' IN labels(m) THEN m.samaccountname
                 WHEN 'OU' IN labels(m) THEN m.distinguishedname
                 ELSE m.name
             END AS target,
             CASE
                 WHEN n.domain IS NOT NULL THEN toLower(n.domain)
                 ELSE 'N/A'
             END AS sourceDomain,
             CASE
                 WHEN m.domain IS NOT NULL THEN toLower(m.domain)
                 ELSE 'N/A'
             END AS targetDomain
        RETURN DISTINCT {
            source: source,
            sourceType: sourceType,
            target: target,
            targetType: targetType,
            type: type(r1),
            sourceDomain: sourceDomain,
            targetDomain: targetDomain,
            targetEnabled: m.enabled
        } AS result
        UNION
        MATCH p=(n)-[:MemberOf*1..]->(g:Group)-[r1]->(m)
        WHERE r1.isacl = true
          AND toUpper(n.domain) = toUpper($domain)
          AND toUpper(n.domain) <> toUpper(m.domain)
          AND (size($blacklist) = 0 OR NOT toUpper(m.domain) IN $blacklist)
          """
            + ("""AND m.highvalue = true""" if high_value else "")
            + """
        WITH n, m, r1,
             CASE 
                 WHEN 'User' IN labels(n) THEN 'User'
                 WHEN 'Group' IN labels(n) THEN 'Group'
                 WHEN 'Computer' IN labels(n) THEN 'Computer'
                 WHEN 'OU' IN labels(n) THEN 'OU'
                 WHEN 'GPO' IN labels(n) THEN 'GPO'
                 WHEN 'Domain' IN labels(n) THEN 'Domain'
                 ELSE 'Other'
             END AS sourceType,
             CASE 
                 WHEN 'User' IN labels(n) THEN n.samaccountname
                 WHEN 'Group' IN labels(n) THEN n.samaccountname
                 WHEN 'Computer' IN labels(n) THEN n.samaccountname
                 WHEN 'OU' IN labels(n) THEN n.distinguishedname
                 ELSE n.name
             END AS source,
             CASE 
                 WHEN 'User' IN labels(m) THEN 'User'
                 WHEN 'Group' IN labels(m) THEN 'Group'
                 WHEN 'Computer' IN labels(m) THEN 'Computer'
                 WHEN 'OU' IN labels(m) THEN 'OU'
                 WHEN 'GPO' IN labels(m) THEN 'GPO'
                 WHEN 'Domain' IN labels(m) THEN 'Domain'
                 ELSE 'Other'
             END AS targetType,
             CASE 
                 WHEN 'User' IN labels(m) THEN m.samaccountname
                 WHEN 'Group' IN labels(m) THEN m.samaccountname
                 WHEN 'Computer' IN labels(m) THEN m.samaccountname
                 WHEN 'OU' IN labels(m) THEN m.distinguishedname
                 ELSE m.name
             END AS target,
             CASE
                 WHEN n.domain IS NOT NULL THEN toLower(n.domain)
                 ELSE 'N/A'
             END AS sourceDomain,
             CASE
                 WHEN m.domain IS NOT NULL THEN toLower(m.domain)
                 ELSE 'N/A'
             END AS targetDomain
        RETURN DISTINCT {
            source: source,
            sourceType: sourceType,
            target: target,
            targetType: targetType,
            type: type(r1),
            sourceDomain: sourceDomain,
            targetDomain: targetDomain,
            targetEnabled: m.enabled
        } AS result
        """
        )
        results = self.execute_query(
            query, domain=domain.upper(), blacklist=[d.upper() for d in blacklist]
        )
        return [r["result"] for r in results]

    def close(self):
        """Close the Neo4j driver"""
        if hasattr(self, "driver"):
            self.driver.close()
