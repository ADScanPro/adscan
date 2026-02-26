#!/usr/bin/env python3
# pylint: skip-file
import os
import stat
import configparser
from neo4j import GraphDatabase
import argparse
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timezone
import re
import requests
import getpass
from pathlib import Path
import time

from .core.settings import CONFIG_FILE

try:
    from rich.console import Console

    _RICH_AVAILABLE = True
    console = Console()
except Exception:  # pragma: no cover - graceful fallback if rich is unavailable
    _RICH_AVAILABLE = False
    console = None

CONFIG_PATH = str(CONFIG_FILE)


class BloodHoundACEAnalyzer:
    def __init__(
        self,
        uri: str,
        user: str,
        password: str,
        debug: bool = False,
        verbose: bool = False,
    ):
        """Initializes the connection with Neo4j."""
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.debug = debug
        self.verbose = verbose

    def close(self):
        """Closes the connection with Neo4j."""
        self.driver.close()

    def render_query(self, query: str, params: dict) -> str:
        """
        Returns a string with the query where placeholders (like $param) are replaced by
        their actual values (strings are wrapped with quotes).
        This is only for debugging purposes.
        """

        def replacer(match):
            key = match.group(0)[1:]
            value = params.get(key)
            if isinstance(value, str):
                return f"'{value}'"
            else:
                return str(value)

        return re.sub(r"\$\w+", replacer, query)

    def execute_query(self, query: str, **params) -> List:
        """
        Helper method to execute a Cypher query.
        If debug is enabled, prints the original query with its parameters, plus
        a fully rendered query with parameters substituted.
        """
        with self.driver.session() as session:
            if self.debug:
                if _RICH_AVAILABLE:
                    console.rule("[bold yellow]DEBUG: Executing query")
                    console.print(query.strip())
                    console.print({"parameters": params})
                    rendered_query = self.render_query(query, params)
                    console.rule("[bold yellow]DEBUG: Fully rendered query")
                    console.print(rendered_query)
                else:
                    print("DEBUG: Executing query:")
                    print(query.strip())
                    print("DEBUG: With parameters:", params)
                    rendered_query = self.render_query(query, params)
                    print("DEBUG: Fully rendered query:")
                    print(rendered_query)
            return session.run(query, **params).data()

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
                if username_filter.lower() == "all"
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
                if username_filter.lower() == "all"
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
        Constructs and executes a dynamic query based on the following three cases:
        1. If source is not "all" and target is "all":
            - Filters the start node by samaccountname and domain (both case-insensitively).
        2. If source is "all" and target is "all":
            - Returns all start nodes from the specified domain with enabled:true and no admincount.
        3. If source is not "all" and target is "dcs":
            - Filters the start node by samaccountname and domain (case-insensitively) and adds additional filtering for DCs.
        The relationship type in the query is set based on the provided 'connection' parameter.
        The query returns a dictionary (as result) with the same keys as get_critical_aces().
        """
        # Determine if we use the generic relationship with type IN (...) or a specific one.
        if connection.lower() == "all":
            rel_condition = "AND type(r) IN ['AdminTo','CanRDP','CanPSRemote']"
            rel_pattern = "[r]->"  # Generic relationship without type-template
        else:
            rel_condition = ""
            rel_pattern = f"[r:{connection}]->"

        if source.lower() != "all" and target.lower() == "all":
            query = f"""
            MATCH p = (n)-{rel_pattern}(m)
            WHERE toLower(n.samaccountname) = toLower($source)
            AND toLower(n.domain) = toLower($domain)
            AND m.enabled = true
            {rel_condition}
            WITH n, m, r,
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
            RETURN DISTINCT {{ source: source, sourceType: sourceType, target: target, targetType: targetType, type: type(r), sourceDomain: sourceDomain, targetDomain: targetDomain }} AS result
            UNION
            MATCH p = (n)-[:MemberOf*1..]->(g:Group)-{rel_pattern}(m)
            WHERE toLower(n.samaccountname) = toLower($source)
            AND toLower(n.domain) = toLower($domain)
            AND m.enabled = true
            {rel_condition}
            WITH n, m, r,
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
            RETURN DISTINCT {{ source: source, sourceType: sourceType, target: target, targetType: targetType, type: type(r), sourceDomain: sourceDomain, targetDomain: targetDomain }} AS result
            """
            params = {"source": source, "domain": domain}
        elif source.lower() == "all" and target.lower() == "all":
            query = f"""
            MATCH p = (n)-{rel_pattern}(m)
            WHERE n.enabled = true
            AND toLower(n.domain) = toLower($domain)
            AND NOT ((n.highvalue = true OR EXISTS((n)-[:MemberOf*1..]->(:Group {{highvalue:true}}))))
            AND m.enabled = true
            {rel_condition}
            WITH n, m, r,
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
            RETURN DISTINCT {{ source: source, sourceType: sourceType, target: target, targetType: targetType, type: type(r), sourceDomain: sourceDomain, targetDomain: targetDomain }} AS result
            UNION
            MATCH p = (n)-[:MemberOf*1..]->(g:Group)-{rel_pattern}(m)
            WHERE n.enabled = true
            AND toLower(n.domain) = toLower($domain)
            AND NOT ((n.highvalue = true OR EXISTS((n)-[:MemberOf*1..]->(:Group {{highvalue:true}}))))
            AND m.enabled = true
            {rel_condition}
            WITH n, m, r,
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
            RETURN DISTINCT {{ source: source, sourceType: sourceType, target: target, targetType: targetType, type: type(r), sourceDomain: sourceDomain, targetDomain: targetDomain }} AS result
            """
            params = {"domain": domain}
        elif source.lower() == "all" and target.lower() == "dcs":
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
            WITH n, m, r,
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
            RETURN DISTINCT {{ source: source, sourceType: sourceType, target: target, targetType: targetType, type: type(r), sourceDomain: sourceDomain, targetDomain: targetDomain }} AS result
            UNION
            MATCH p = (n)-[:MemberOf*1..]->(g:Group)-{rel_pattern}(m)
            WHERE n.enabled = true
            AND toLower(n.domain) = toLower($domain)
            AND m.enabled = true
            {rel_condition}
            AND (n.admincount IS NULL OR n.admincount = false)
            AND EXISTS {{
                MATCH (m)-[:MemberOf]->(dc:Group)
                WHERE dc.objectid =~ '(?i)S-1-5-.*-516'
            }}
            WITH n, m, r,
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
            RETURN DISTINCT {{ source: source, sourceType: sourceType, target: target, targetType: targetType, type: type(r), sourceDomain: sourceDomain, targetDomain: targetDomain }} AS result
            """
            params = {"domain": domain}
        else:
            return []
        return self.execute_query(query, **params)

    def print_access(self, source: str, connection: str, target: str, domain: str):
        """
        Prints the access paths based on the provided parameters.
        The output format is similar to that of print_aces.
        Expects each record to contain the key 'result' (a dictionary with the desired fields).
        """
        results = self.get_access_paths(source, connection, target, domain)
        print(
            f"\nAccess paths for source: {source}, connection: {connection}, target: {target}, domain: {domain}"
        )
        print("=" * 50)
        if not results:
            print("No access paths found")
            return
        for record in results:
            ace = record.get("result")
            if not ace:
                continue
            print(f"\nSource: {ace['source']}")
            print(f"Source Type: {ace['sourceType']}")
            print(f"Source Domain: {ace['sourceDomain']}")
            print(f"Target: {ace['target']}")
            print(f"Target Type: {ace['targetType']}")
            print(f"Target Domain: {ace['targetDomain']}")
            print(f"Relation: {ace['type']}")
            print("-" * 50)

    def get_critical_aces_by_domain(
        self, domain: str, blacklist: List[str], high_value: bool = False
    ) -> List[Dict]:
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

    def get_computers(self, domain: str, laps: bool = None) -> List[str]:
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

    def get_users(self, domain: str) -> List[str]:
        query = """
        MATCH (u:User)
        WHERE u.enabled = true AND toLower(u.domain) = toLower($domain)
        RETURN u.samaccountname AS samaccountname
        """
        results = self.execute_query(query, domain=domain)
        return [record["samaccountname"] for record in results]

    def get_password_last_change(self, domain: str, user: str = None) -> List[dict]:
        """
        Retrieves the pwdlastset value and the whencreated value for enabled users in the specified domain.
        If a user is specified, only returns the record for that user.
        """
        if user:
            query = """
            MATCH (u:User)
            WHERE toLower(u.domain) = toLower($domain)
              AND toLower(u.samaccountname) = toLower($user)
            RETURN toLower(u.samaccountname) AS user, 
                   u.pwdlastset AS password_last_change,
                   u.whencreated AS when_created
            """
            params = {"domain": domain, "user": user}
        else:
            query = """
            MATCH (u:User)
            WHERE u.enabled = true
              AND toLower(u.domain) = toLower($domain)
            RETURN toLower(u.samaccountname) AS user, 
                   u.pwdlastset AS password_last_change,
                   u.whencreated AS when_created
            """
            params = {"domain": domain}
        return self.execute_query(query, **params)

    def get_admin_users(self, domain: str) -> List[str]:
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
        WHERE u.enabled = true
          AND u.passwordnotreqd = true
          AND toLower(u.domain) = toLower($domain)
        RETURN u.samaccountname AS samaccountname
        """
        results = self.execute_query(query, domain=domain)
        return [record["samaccountname"] for record in results]

    def get_password_never_expires_users(self, domain: str) -> List[str]:
        """Queries users that have 'pwdneverexpires' enabled in the specified domain."""
        query = """
        MATCH (u:User)
        WHERE u.enabled = true
          AND u.pwdneverexpires = true
          AND toLower(u.domain) = toLower($domain)
        RETURN u.samaccountname AS samaccountname
        """
        results = self.execute_query(query, domain=domain)
        return [record["samaccountname"] for record in results]

    def execute_custom_query(self, query: str, output: str = None):
        """Executes a custom Cypher query provided by the user."""
        try:
            results = self.execute_query(query)
            output_str = "\nCustom query results:\n" + "=" * 50 + "\n"
            if not results:
                output_str += "No results found for this query\n"
            else:
                for result in results:
                    output_str += f"{result}\n" + "-" * 50 + "\n"
            if output:
                try:
                    with open(output, "w") as f:
                        f.write(output_str)
                    print(f"Results saved to: {output}")
                except Exception as e:
                    print(f"Error writing the file: {e}")
            else:
                print(output_str)
        except Exception as e:
            print(f"Error executing query: {str(e)}")

    def get_sessions(self, domain: str, da: bool = False) -> List[dict]:
        """
        Retrieves a list of computers with active sessions in the specified domain.
        If 'da' is True, returns computers with sessions from domain admin users,
        along with the domain admin username.
        """
        if da:
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
            query = """
            MATCH (c:Computer)-[n:HasSession]->(u:User {enabled:true})
            WHERE toLower(c.domain) = toLower($domain)
            AND ((u.highvalue = true OR EXISTS((u)-[:MemberOf*1..]->(:Group {highvalue:true}))))
            RETURN DISTINCT toLower(c.name) AS computer
            """
        return self.execute_query(query, domain=domain)

    def print_aces(
        self,
        source: str,
        relation: str,
        target: str,
        source_domain: str,
        target_domain: str,
    ):
        """
        Prints ACLs for the given source with filtering based on target type and domains.
        The target parameter accepts "all" or "high-value". When target equals "high-value",
        the query filters only high-value targets.
        The relation parameter is currently not used for query modifications (only accepts "all").
        """
        high_value = target.lower() == "high-value"
        results = self.get_critical_aces(
            source_domain, high_value, source, target_domain, relation
        )
        print(
            f"\nACLs for source: {source}, target: {target}, "
            f"source domain: {source_domain}, target domain: {target_domain}"
        )
        print("=" * 50)
        if not results:
            print("No ACLs found for the given parameters")
            return
        for ace in results:
            print(f"\nSource: {ace['source']}")
            print(f"Source Type: {ace['sourceType']}")
            print(f"Source Domain: {ace['sourceDomain']}")
            print(f"Target: {ace['target']}")
            print(f"Target Type: {ace['targetType']}")
            print(f"Target Domain: {ace['targetDomain']}")
            if not ace.get("targetEnabled", True):
                print(f"Target Enabled: {ace['targetEnabled']}")
            print(f"Relation: {ace['type']}")
            print("-" * 50)

    def print_critical_aces_by_domain(
        self, domain: str, blacklist: List[str], high_value: bool = False
    ):
        aces = self.get_critical_aces_by_domain(domain, blacklist, high_value)
        value_suffix = " (high-value targets only)" if high_value else ""
        print(f"\nACLs for domain: {domain}{value_suffix}")
        print("=" * 50)
        if not aces:
            print("No ACLs found for this domain")
            return
        for ace in aces:
            print(f"\nSource: {ace['source']}")
            print(f"Source Type: {ace['sourceType']}")
            print(f"Source Domain: {ace['sourceDomain']}")
            print(f"Target: {ace['target']}")
            print(f"Target Type: {ace['targetType']}")
            print(f"Target Domain: {ace['targetDomain']}")
            if not ace.get("targetEnabled", True):
                print(f"Target Enabled: {ace['targetEnabled']}")
            print(f"Relation: {ace['type']}")
            print("-" * 50)

    def print_computers(self, domain: str, output: str = None, laps: bool = None):
        computers = self.get_computers(domain, laps)
        if output:
            try:
                with open(output, "w") as f:
                    for comp in computers:
                        f.write(f"{comp}\n")
                print(f"Results saved to: {output}")
            except Exception as e:
                print(f"Error writing the file: {e}")
        else:
            print(f"\nComputers in domain: {domain}")
            print("=" * 50)
            if not computers:
                print("No computers found for this domain")
            else:
                for comp in computers:
                    print(comp)

    def print_users(self, domain: str, output: str = None):
        users = self.get_users(domain)
        if output:
            try:
                with open(output, "w") as f:
                    for user in users:
                        f.write(f"{user}\n")
                print(f"Results saved to: {output}")
            except Exception as e:
                print(f"Error writing the file: {e}")
        else:
            print(f"\nUsers in domain: {domain}")
            print("=" * 50)
            if not users:
                print("No users found for this domain")
            else:
                for user in users:
                    print(user)

    def print_password_last_change(
        self, domain: str, user: str = None, output: str = None
    ):
        data = self.get_password_last_change(domain, user)
        output_str = (
            f"\nPassword Last Change for users in domain: {domain}\n" + "=" * 50 + "\n"
        )
        if not data:
            output_str += "No users found with password last change data.\n"
        else:
            for record in data:
                ts = record.get("password_last_change")
                try:
                    ts_float = float(ts)
                    if ts_float == 0:
                        wc = record.get("when_created")
                        dt = datetime.fromtimestamp(float(wc), tz=timezone.utc)
                        formatted_date = dt.strftime("%A, %Y-%m-%d %H:%M:%S UTC")
                    else:
                        dt = datetime.fromtimestamp(ts_float, tz=timezone.utc)
                        formatted_date = dt.strftime("%A, %Y-%m-%d %H:%M:%S UTC")
                except Exception as e:
                    formatted_date = f"{ts} (error: {e})"
                output_str += (
                    f"User: {record['user']} | Password Last Change: {formatted_date}\n"
                )
        if output:
            try:
                with open(output, "w") as f:
                    f.write(output_str)
                print(f"Results saved to: {output}")
            except Exception as e:
                print(f"Error writing file: {e}")
        else:
            print(output_str)

    def print_admin_users(self, domain: str, output: str = None):
        admin_users = self.get_admin_users(domain)
        if output:
            try:
                with open(output, "w") as f:
                    for user in admin_users:
                        f.write(f"{user}\n")
                print(f"Results saved to: {output}")
            except Exception as e:
                print(f"Error writing the file: {e}")
        else:
            print(f"\nPrivileged (admin) users in domain: {domain}")
            print("=" * 50)
            if not admin_users:
                print("No privileged users found for this domain")
            else:
                for user in admin_users:
                    print(user)

    def print_highvalue_users(self, domain: str, output: str = None):
        highvalue_users = self.get_highvalue_users(domain)
        if output:
            try:
                with open(output, "w") as f:
                    for user in highvalue_users:
                        f.write(f"{user}\n")
                print(f"Results saved to: {output}")
            except Exception as e:
                print(f"Error writing the file: {e}")
        else:
            print(f"\nHigh-value users in domain: {domain}")
            print("=" * 50)
            if not highvalue_users:
                print("No high-value users found for this domain")
            else:
                for user in highvalue_users:
                    print(user)

    def print_password_not_required_users(self, domain: str, output: str = None):
        users = self.get_password_not_required_users(domain)
        if output:
            try:
                with open(output, "w") as f:
                    for user in users:
                        f.write(f"{user}\n")
                print(f"Results saved to: {output}")
            except Exception as e:
                print(f"Error writing the file: {e}")
        else:
            print(f"\nUsers with password not required in domain: {domain}")
            print("=" * 50)
            if not users:
                print("No users with 'passwordnotreqd' found for this domain")
            else:
                for user in users:
                    print(user)

    def print_password_never_expires_users(self, domain: str, output: str = None):
        users = self.get_password_never_expires_users(domain)
        if output:
            try:
                with open(output, "w") as f:
                    for user in users:
                        f.write(f"{user}\n")
                print(f"Results saved to: {output}")
            except Exception as e:
                print(f"Error writing the file: {e}")
        else:
            print(f"\nUsers with 'pwdneverexpires' enabled in domain: {domain}")
            print("=" * 50)
            if not users:
                print("No users with 'pwdneverexpires' found for this domain")
            else:
                for user in users:
                    print(user)

    def print_sessions(self, domain: str, da: bool = False, output: str = None):
        sessions = self.get_sessions(domain, da)
        if da:
            console_output = (
                f"\nDomain Admin Sessions in domain: {domain}\n" + "=" * 50 + "\n"
            )
        else:
            console_output = f"\nSessions in domain: {domain}\n" + "=" * 50 + "\n"
        file_output = ""
        if not sessions:
            console_output += "No sessions found.\n"
            file_output += "No sessions found.\n"
        else:
            for session_record in sessions:
                if da:
                    console_output += f"Computer: {session_record['computer']} | Domain Admin: {session_record['domain_admin']}\n"
                else:
                    console_output += f"{session_record['computer']}\n"
                file_output += f"{session_record['computer']}\n"
        print(console_output)
        if output:
            try:
                with open(output, "w") as f:
                    f.write(file_output)
                print(f"Results saved to: {output}")
            except Exception as e:
                print(f"Error writing the file: {e}")


class BloodHoundCEClient:
    """Client for BloodHound Community Edition (CE).

    NOTE: CE uses a different backend/API than legacy Neo4j. This skeleton provides
    a pluggable interface so commands can be implemented incrementally without
    impacting legacy users.
    """

    def __init__(
        self,
        base_url: str,
        api_token: Optional[str] = None,
        debug: bool = False,
        verbose: bool = False,
        verify: bool = True,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.debug = debug
        self.verbose = verbose
        self.session = requests.Session()
        self.verify = verify
        if api_token:
            self.session.headers.update({"Authorization": f"Bearer {api_token}"})

    def close(self):
        try:
            self.session.close()
        except Exception:
            pass

    def _log(self, message: str):
        if self.debug and _RICH_AVAILABLE:
            console.log(message)
        elif self.debug:
            print(message)

    def authenticate(
        self, username: str, password: str, login_path: str = "/api/v2/login"
    ) -> Optional[str]:
        """Authenticate against CE and return token. Update session headers if successful.

        The default path is a conservative guess; override with --login-path if your CE differs.
        """
        url = f"{self.base_url}{login_path}"
        self._log(f"POST {url}")
        try:
            # According to OpenAPI v2, body requires login_method+username and secret or otp
            payload = {
                "login_method": "secret",
                "username": username,
                "secret": password,
            }
            if self.debug:
                redacted = dict(payload)
                redacted["secret"] = "***"
                self._log({"request": {"url": url, "json": redacted}})
            response = self.session.post(
                url, json=payload, verify=self.verify, timeout=60
            )
            if self.debug:
                try:
                    self._log(
                        {
                            "response": {
                                "status": response.status_code,
                                "body": response.json(),
                            }
                        }
                    )
                except ValueError:
                    self._log(
                        {
                            "response": {
                                "status": response.status_code,
                                "body": response.text[:500],
                            }
                        }
                    )
            if response.status_code >= 400:
                print(
                    f"Authentication failed: HTTP {response.status_code} {response.text}"
                )
                if (
                    "Neo.ClientError" in response.text
                    or "No authentication header supplied" in response.text
                ):
                    print(
                        "Hint: Parece que estás apuntando al puerto de Neo4j (p.ej., :7474). Usa la URL de la API de BloodHound CE, p.ej., http://localhost:8080"
                    )
                return None
            data = response.json()
            # OpenAPI example nests token under data.session_token
            token = None
            if isinstance(data, dict):
                data_field = data.get("data")
                if isinstance(data_field, dict):
                    token = data_field.get("session_token")
            # Fallbacks
            if not token:
                token = data.get("token") or data.get("access_token") or data.get("jwt")
            if not token:
                print("Authentication response did not contain a token field.")
                return None
            self.api_token = token
            self.session.headers.update({"Authorization": f"Bearer {token}"})
            return token
        except requests.RequestException as exc:
            print(f"Authentication error: {exc}")
            return None

    def upload_files(
        self,
        file_paths: List[str],
        start_path: str = "/api/v2/file-upload/start",
        upload_path_tpl: str = "/api/v2/file-upload/{job_id}",
        end_path_tpl: str = "/api/v2/file-upload/{job_id}/end",
        content_type: Optional[str] = None,
        tag: Optional[str] = None,
    ) -> Dict[str, str]:
        """Upload collector artifacts using v2 file-upload job flow.

        1) POST start_path -> returns job with id
        2) For each file: POST upload_path_tpl (set Content-Type header appropriately) with raw body
        3) POST end_path_tpl
        """
        results: Dict[str, str] = {}
        # Step 1: start job
        start_url = f"{self.base_url}{start_path}"
        self._log(f"POST {start_url}")
        try:
            start_resp = self.session.post(start_url, verify=self.verify, timeout=60)
            if start_resp.status_code >= 400:
                msg = f"Failed to start upload job: HTTP {start_resp.status_code} {start_resp.text[:200]}"
                for p in file_paths:
                    results[p] = msg
                return results
            start_data = start_resp.json()
            job = start_data.get("data") if isinstance(start_data, dict) else None
            job_id = job.get("id") if isinstance(job, dict) else None
            if job_id is None:
                msg = "Upload job response missing id"
                for p in file_paths:
                    results[p] = msg
                return results
        except requests.RequestException as exc:
            msg = f"Failed to start upload job: {exc}"
            for p in file_paths:
                results[p] = msg
            return results

        # Step 2: upload files
        for p in file_paths:
            fpath = Path(p)
            if not fpath.exists() or not fpath.is_file():
                results[p] = "File not found"
                continue
            upload_url = (
                f"{self.base_url}{upload_path_tpl.replace('{job_id}', str(job_id))}"
            )
            headers = {}
            # Determine content type
            ctype = content_type
            if not ctype:
                suffix = fpath.suffix.lower()
                if suffix == ".zip":
                    ctype = "application/zip"
                elif suffix == ".json":
                    ctype = "application/json"
                else:
                    ctype = "application/octet-stream"
            headers["Content-Type"] = ctype
            try:
                with open(fpath, "rb") as fh:
                    self._log(f"POST {upload_url} ({fpath.name})")
                    body = fh.read()
                # If tag is provided and server expects metadata separately, this simple flow may not attach it.
                # Kept minimal per spec (raw body). If server requires multipart, this should be adjusted.
                resp = self.session.post(
                    upload_url,
                    data=body,
                    headers=headers,
                    verify=self.verify,
                    timeout=None,
                )
                if resp.status_code >= 400:
                    results[p] = f"HTTP {resp.status_code}: {resp.text[:200]}"
                else:
                    results[p] = "Accepted"
            except requests.RequestException as exc:
                results[p] = f"Upload error: {exc}"

        # Step 3: end job
        end_url = f"{self.base_url}{end_path_tpl.replace('{job_id}', str(job_id))}"
        try:
            self._log(f"POST {end_url}")
            end_resp = self.session.post(end_url, verify=self.verify, timeout=60)
            if end_resp.status_code >= 400:
                # annotate all results with end error
                for k in list(results.keys()):
                    results[k] = (
                        results[k] + f"; finalize error HTTP {end_resp.status_code}"
                    )
        except requests.RequestException as exc:
            for k in list(results.keys()):
                results[k] = results[k] + f"; finalize error {exc}"

        return results

    def _get_file_upload_job(
        self, job_id: int, list_path: str = "/api/v2/file-upload"
    ) -> Optional[Dict]:
        """Fetch a single file-upload job by id using the list endpoint.

        The OpenAPI defines only a list endpoint with filter params. Some deployments
        may not support filtering by id directly, so we attempt with a query param and
        fall back to client-side filtering.
        """
        url = f"{self.base_url}{list_path}"
        try:
            # First, try server-side filtering
            resp = self.session.get(
                url, params={"id": job_id}, verify=self.verify, timeout=60
            )
            if resp.status_code >= 400:
                # Retry without filter and do client-side filtering
                resp = self.session.get(url, verify=self.verify, timeout=60)
            data = (
                resp.json()
                if resp.headers.get("Content-Type", "").startswith("application/json")
                else {}
            )
            items = []
            if isinstance(data, dict):
                items = data.get("data") or data.get("items") or []
            # items is expected to be a list of jobs
            for item in items:
                try:
                    if int(item.get("id")) == int(job_id):
                        return item
                except Exception:
                    continue
        except requests.RequestException:
            return None
        except ValueError:
            return None
        return None

    def upload_files_and_wait(
        self,
        file_paths: List[str],
        start_path: str = "/api/v2/file-upload/start",
        upload_path_tpl: str = "/api/v2/file-upload/{job_id}",
        end_path_tpl: str = "/api/v2/file-upload/{job_id}/end",
        content_type: Optional[str] = None,
        tag: Optional[str] = None,
        poll_interval: int = 5,
        timeout_seconds: int = 1800,
        list_path: str = "/api/v2/file-upload",
    ) -> Tuple[Dict[str, str], Optional[Dict]]:
        """Upload files and wait until the job has finished processing in BloodHound.

        Returns a tuple: (per-file results mapping, final job dict or None on timeout/error).
        """
        results = self.upload_files(
            file_paths=file_paths,
            start_path=start_path,
            upload_path_tpl=upload_path_tpl,
            end_path_tpl=end_path_tpl,
            content_type=content_type,
            tag=tag,
        )

        # If any upload failed outright, we still proceed to try to get job id from the start response
        # However, current implementation does not expose job id externally. Re-start minimally to obtain it
        # by inferring from latest job in the list. This is a best-effort strategy.

        # Attempt to find the most recent job and poll it if it looks like ours.
        start_time = time.time()
        job = None
        spinner_shown = False
        while True:
            job = self._get_file_upload_job(
                job_id=self._infer_latest_file_upload_job_id(list_path=list_path)
            )
            if job is None:
                # Brief grace period immediately after upload
                if time.time() - start_time > 15:
                    break
            else:
                status = job.get("status")
                status_message = job.get("status_message")
                if _RICH_AVAILABLE:
                    if not spinner_shown:
                        console.rule("[bold cyan]Waiting for ingestion to complete")
                        spinner_shown = True
                    console.log({"status": status, "message": status_message})
                else:
                    print(f"Job status: {status} - {status_message}")

                # Terminal statuses: -1 invalid, 2 complete, 3 canceled, 4 timed out, 5 failed, 8 partially complete
                if status in [-1, 2, 3, 4, 5, 8]:
                    break
            if time.time() - start_time > timeout_seconds:
                break
            time.sleep(max(1, poll_interval))

        return results, job

    def _infer_latest_file_upload_job_id(
        self, list_path: str = "/api/v2/file-upload"
    ) -> Optional[int]:
        """Best-effort helper to get the latest file upload job id for current user.

        The API returns paginated list with sort options, but for simplicity we fetch and
        take the max id as the latest.
        """
        url = f"{self.base_url}{list_path}"
        try:
            resp = self.session.get(url, verify=self.verify, timeout=60)
            data = (
                resp.json()
                if resp.headers.get("Content-Type", "").startswith("application/json")
                else {}
            )
            items = []
            if isinstance(data, dict):
                items = data.get("data") or data.get("items") or []
            ids = []
            for item in items:
                try:
                    ids.append(int(item.get("id")))
                except Exception:
                    continue
            return max(ids) if ids else None
        except Exception:
            return None

    def not_implemented(self, feature: str):
        msg = (
            f"Feature '{feature}' is not yet implemented for BloodHound CE in this CLI. "
            f"Please use the 'custom' subcommand if CE exposes an HTTP API endpoint, "
            f"or run with --edition legacy for Neo4j-backed instances."
        )
        print(msg)

    def print_aces(self, *args, **kwargs):  # placeholder to keep interface symmetry
        self.not_implemented("acl")

    def print_computers(self, *args, **kwargs):
        self.not_implemented("computer")

    def print_users(self, *args, **kwargs):
        self.not_implemented("user")

    def print_password_last_change(self, *args, **kwargs):
        self.not_implemented("user --password-last-change")

    def print_admin_users(self, *args, **kwargs):
        self.not_implemented("user --admin-count")

    def print_highvalue_users(self, *args, **kwargs):
        self.not_implemented("user --high-value")

    def print_password_not_required_users(self, *args, **kwargs):
        self.not_implemented("user --password-not-required")

    def print_password_never_expires_users(self, *args, **kwargs):
        self.not_implemented("user --password-never-expires")

    def print_sessions(self, *args, **kwargs):
        self.not_implemented("session")

    def print_access(self, *args, **kwargs):
        self.not_implemented("access")

    def execute_custom_query(self, query: str, output: str = None):
        """Execute a custom CE HTTP request.

        This is a placeholder implementation. Adjust to CE's actual API endpoint.
        """
        self.not_implemented("custom")


def save_config(host: str, port: str, db_user: str, db_password: str):
    """Saves the Neo4j connection configuration to a file in the user's directory."""
    config = configparser.ConfigParser()
    # Preserve existing config if present
    if os.path.exists(CONFIG_PATH):
        config.read(CONFIG_PATH)
    # Persist selected edition
    config["GENERAL"] = config.get("GENERAL", {}) if "GENERAL" in config else {}
    config["GENERAL"]["edition"] = "legacy"
    config["NEO4J"] = {
        "host": host,
        "port": port,
        "db_user": db_user,
        "db_password": db_password,
    }
    with open(CONFIG_PATH, "w") as configfile:
        config.write(configfile)
    os.chmod(CONFIG_PATH, stat.S_IRUSR | stat.S_IWUSR)
    print(f"Configuration saved at {CONFIG_PATH}")


def save_ce_config(base_url: str, api_token: Optional[str]):
    """Saves the CE connection configuration to the same config file under a CE section."""
    config = configparser.ConfigParser()
    if os.path.exists(CONFIG_PATH):
        config.read(CONFIG_PATH)
    config["CE"] = {"base_url": base_url, "api_token": api_token or ""}
    # Persist selected edition
    config["GENERAL"] = config.get("GENERAL", {}) if "GENERAL" in config else {}
    config["GENERAL"]["edition"] = "ce"
    with open(CONFIG_PATH, "w") as configfile:
        config.write(configfile)
    os.chmod(CONFIG_PATH, stat.S_IRUSR | stat.S_IWUSR)
    print(f"CE configuration saved at {CONFIG_PATH}")


def load_config():
    """Loads the configuration from the file, if it exists."""
    config = configparser.ConfigParser()
    if os.path.exists(CONFIG_PATH):
        config.read(CONFIG_PATH)
        return config["NEO4J"]
    else:
        return None


def load_ce_config() -> Optional[configparser.SectionProxy]:
    """Loads CE configuration if it exists."""
    config = configparser.ConfigParser()
    if os.path.exists(CONFIG_PATH):
        config.read(CONFIG_PATH)
        if "CE" in config:
            return config["CE"]
    return None


def load_default_edition() -> str:
    """Loads default edition from config if set, else returns 'legacy'."""
    config = configparser.ConfigParser()
    if os.path.exists(CONFIG_PATH):
        config.read(CONFIG_PATH)
        if "GENERAL" in config and config["GENERAL"].get("edition"):
            return config["GENERAL"].get("edition", "legacy")
    return "legacy"


def main():
    parser = argparse.ArgumentParser(
        description="CLI to query BloodHound data (Legacy Neo4j and CE skeleton)"
    )
    # Global debug/verbose parameters available for any subcommand
    parser.add_argument(
        "--debug", action="store_true", help="Enable debug mode to show queries"
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument(
        "--edition",
        choices=["legacy", "ce"],
        help="Select BloodHound edition. Defaults to legacy.",
    )
    subparsers = parser.add_subparsers(
        dest="subcommand", required=True, help="Available subcommands"
    )

    # set subcommand
    parser_set = subparsers.add_parser(
        "set", help="Saves the connection configuration for Neo4j (legacy)"
    )
    parser_set.add_argument("--host", required=True, help="Neo4j host")
    parser_set.add_argument("--port", required=True, help="Neo4j port")
    parser_set.add_argument("--db-user", required=True, help="Neo4j user")
    parser_set.add_argument("--db-password", required=True, help="Neo4j password")

    # CE auth subcommand
    parser_auth = subparsers.add_parser(
        "auth", help="Authenticate to BloodHound CE and save API token"
    )
    parser_auth.add_argument(
        "-u",
        "--url",
        default="http://localhost:8080",
        help="BloodHound CE base URL (default: http://localhost:8080)",
    )
    parser_auth.add_argument(
        "--username", default="admin", help="CE username (default: admin)"
    )
    parser_auth.add_argument(
        "--password", help="CE password (if omitted, prompt securely)"
    )
    parser_auth.add_argument(
        "--login-path",
        default="/api/v2/login",
        help="Login path (default: /api/v2/login)",
    )
    parser_auth.add_argument(
        "--insecure", action="store_true", help="Disable TLS certificate verification"
    )

    # CE upload subcommand
    parser_upload = subparsers.add_parser(
        "upload",
        help="Upload collector artifacts to BloodHound CE (v2 file-upload flow)",
    )
    parser_upload.add_argument(
        "-f",
        "--file",
        dest="files",
        required=True,
        nargs="+",
        help="Path(s) to .zip/.json files",
    )
    parser_upload.add_argument(
        "--start-path",
        default="/api/v2/file-upload/start",
        help="Start path (default: /api/v2/file-upload/start)",
    )
    parser_upload.add_argument(
        "--upload-path",
        default="/api/v2/file-upload/{job_id}",
        help="Upload path template (default: /api/v2/file-upload/{job_id})",
    )
    parser_upload.add_argument(
        "--end-path",
        default="/api/v2/file-upload/{job_id}/end",
        help="End path template (default: /api/v2/file-upload/{job_id}/end)",
    )
    parser_upload.add_argument(
        "--content-type",
        help="Force Content-Type (auto-detected from extension if omitted)",
    )
    parser_upload.add_argument(
        "--insecure", action="store_true", help="Disable TLS certificate verification"
    )
    parser_upload.add_argument(
        "--tag", help="Optional tag/label to include with upload (reserved)"
    )
    wait_group = parser_upload.add_mutually_exclusive_group()
    wait_group.add_argument(
        "--wait",
        dest="wait",
        action="store_true",
        help="Wait for ingestion to complete (default)",
    )
    wait_group.add_argument(
        "--no-wait",
        dest="wait",
        action="store_false",
        help="Return immediately after upload is accepted",
    )
    parser_upload.set_defaults(wait=True)
    parser_upload.add_argument(
        "--poll-interval",
        type=int,
        default=5,
        help="Seconds between status checks (default: 5)",
    )
    parser_upload.add_argument(
        "--timeout",
        type=int,
        default=1800,
        help="Max seconds to wait for completion (default: 1800)",
    )

    # acl subcommand (refactored)
    parser_acl = subparsers.add_parser("acl", help="Query ACLs in BloodHound")
    parser_acl.add_argument(
        "-s", "--source", default="all", help="Source samaccountname or 'all'"
    )
    parser_acl.add_argument(
        "-t",
        "--target",
        default="all",
        choices=["all", "high-value"],
        help="Target type: 'all' for all targets, 'high-value' for high-value targets only",
    )
    parser_acl.add_argument(
        "-sd",
        "--source-domain",
        required=True,
        help="Domain for filtering the source node",
    )
    parser_acl.add_argument(
        "-tg",
        "--target-domain",
        default="all",
        help="Domain for filtering the target node; use 'all' to disable filtering",
    )
    parser_acl.add_argument(
        "-r",
        "--relation",
        default="all",
        choices=["all", "DCSync", "ReadGMSAPassword", "ReadLAPSPassword"],
        help="Relation type (currently 'all' and 'DCSync' is supported)",
    )

    # computer subcommand
    parser_computer = subparsers.add_parser(
        "computer", help="Query computers in BloodHound"
    )
    parser_computer.add_argument(
        "-d", "--domain", required=True, help="Domain to enumerate computers"
    )
    parser_computer.add_argument("-o", "--output", help="Path to file to save results")
    parser_computer.add_argument(
        "--laps",
        type=str,
        choices=["True", "False"],
        help="Filter by haslaps: True or False",
    )

    # user subcommand
    parser_user = subparsers.add_parser("user", help="Query users in BloodHound")
    parser_user.add_argument(
        "-d", "--domain", required=True, help="Domain to enumerate users"
    )
    parser_user.add_argument(
        "-u", "--user", help="User (samaccountname) to query (optional)"
    )
    parser_user.add_argument("-o", "--output", help="Path to file to save results")
    group_value = parser_user.add_mutually_exclusive_group()
    group_value.add_argument(
        "--admin-count",
        action="store_true",
        help="Show only users with domain admin privileges (admincount)",
    )
    group_value.add_argument(
        "--high-value", action="store_true", help="Show only high-value users"
    )
    group_value.add_argument(
        "--password-not-required",
        action="store_true",
        help="Show only users with 'passwordnotreqd' enabled",
    )
    group_value.add_argument(
        "--password-never-expires",
        action="store_true",
        help="Show only users with 'pwdneverexpires' enabled",
    )
    group_value.add_argument(
        "--password-last-change",
        action="store_true",
        help="Show the last password change value for user(s)",
    )

    # custom subcommand
    parser_custom = subparsers.add_parser(
        "custom", help="Execute a custom Cypher query in BloodHound"
    )
    parser_custom.add_argument(
        "--query", required=True, help="Custom Cypher query to execute"
    )
    parser_custom.add_argument("-o", "--output", help="Path to file to save results")

    # session subcommand
    parser_session = subparsers.add_parser(
        "session", help="Query sessions in BloodHound"
    )
    parser_session.add_argument(
        "-d", "--domain", required=True, help="Domain to enumerate sessions"
    )
    parser_session.add_argument(
        "--da", action="store_true", help="Show only sessions for domain admins"
    )
    parser_session.add_argument("-o", "--output", help="Path to file to save results")

    # access subcommand
    parser_access = subparsers.add_parser(
        "access", help="Query access paths in BloodHound"
    )
    parser_access.add_argument(
        "-s", "--source", default="all", help="Source samaccountname or 'all'"
    )
    parser_access.add_argument(
        "-r",
        "--relation",
        default="all",
        choices=["all", "AdminTo", "CanRDP", "CanPSRemote"],
        help="Type of relation (or 'all' for any)",
    )
    parser_access.add_argument(
        "-t", "--target", default="all", choices=["all", "dcs"], help="Target type"
    )
    parser_access.add_argument(
        "-d", "--domain", required=True, help="Domain for filtering nodes"
    )

    args = parser.parse_args()

    if args.subcommand == "set":
        save_config(args.host, args.port, args.db_user, args.db_password)
        return

    if args.subcommand not in ("set", "auth") and not os.path.exists(CONFIG_PATH):
        print("Error: Configuration file not found.")
        print(
            "Please run the 'set' subcommand to set the connection variables, for example:"
        )
        print(
            "  bloodhound-cli set --host localhost --port 7687 --db-user neo4j --db-password Bl00dh0und"
        )
        exit(1)

    # Default edition resolution order:
    # 1) CLI flag --edition
    # 2) env BLOODHOUND_EDITION
    # 3) if subcommand == auth -> ce
    # 4) persisted config GENERAL.edition
    # 5) legacy
    env_edition = os.getenv("BLOODHOUND_EDITION")
    persisted = load_default_edition()
    if args.edition:
        selected_edition = args.edition
    elif env_edition:
        selected_edition = env_edition
    elif args.subcommand == "auth":
        selected_edition = "ce"
    elif persisted:
        selected_edition = persisted
    else:
        selected_edition = "legacy"

    analyzer = None
    if selected_edition == "legacy":
        conf = load_config()
        if conf is None:
            print(
                "Error: No connection configuration found. Please run 'bloodhound-cli set ...'"
            )
            exit(1)
        for key in ["host", "port", "db_user", "db_password"]:
            if key not in conf:
                print(
                    f"Error: The key '{key}' was not found in the configuration. Please run 'bloodhound-cli set ...'"
                )
                exit(1)

        host = conf["host"]
        port = conf["port"]
        db_user = conf["db_user"]
        db_password = conf["db_password"]
        uri = f"bolt://{host}:{port}"
        analyzer = BloodHoundACEAnalyzer(
            uri, db_user, db_password, debug=args.debug, verbose=args.verbose
        )
    else:
        # Determine TLS verify per subcommand flags if present
        verify = True
        if hasattr(args, "insecure") and args.insecure:
            verify = False
        if args.subcommand == "auth":
            analyzer = BloodHoundCEClient(
                base_url=args.url,
                api_token=None,
                debug=args.debug,
                verbose=args.verbose,
                verify=verify,
            )
            base_url = args.url
        else:
            ce_conf = load_ce_config()
            if ce_conf is None:
                print(
                    "Error: No CE configuration found. Please run 'bloodhound-cli --edition ce auth --base-url https://bhce.local --username <user>'"
                )
                exit(1)
            if "base_url" not in ce_conf:
                print(
                    "Error: The key 'base_url' was not found in the CE configuration. Please run 'bloodhound-cli --edition ce auth --base-url https://bhce.local --username <user>'"
                )
                exit(1)
            base_url = ce_conf["base_url"]
            api_token = ce_conf.get("api_token", "")
            analyzer = BloodHoundCEClient(
                base_url=base_url,
                api_token=api_token,
                debug=args.debug,
                verbose=args.verbose,
                verify=verify,
            )
    try:
        if args.subcommand == "acl":
            analyzer.print_aces(
                args.source,
                args.relation,
                args.target,
                args.source_domain,
                args.target_domain,
            )
        elif args.subcommand == "computer":
            laps = None
            if args.laps is not None:
                laps = True if args.laps.lower() == "true" else False
            analyzer.print_computers(args.domain, args.output, laps)
        elif args.subcommand == "auth":
            if selected_edition != "ce":
                print("The 'auth' subcommand is only available for --edition ce")
            else:
                password = args.password or getpass.getpass("CE Password: ")
                token = analyzer.authenticate(
                    args.username, password, login_path=args.login_path
                )
                if token:
                    # persist token
                    save_ce_config(base_url, token)
                    print("Authentication successful. Token saved to configuration.")
        elif args.subcommand == "upload":
            if selected_edition != "ce":
                print("The 'upload' subcommand is only available for --edition ce")
            else:
                ce_conf = load_ce_config()
                token_present = ce_conf and ce_conf.get("api_token")
                if not token_present:
                    print(
                        "No CE API token found. Run 'bloodhound-cli --edition ce auth --url http://localhost:7474 --username <user>' first."
                    )
                else:
                    if args.wait:
                        results, job = analyzer.upload_files_and_wait(
                            args.files,
                            start_path=args.start_path,
                            upload_path_tpl=args.upload_path,
                            end_path_tpl=args.end_path,
                            content_type=args.content_type,
                            tag=args.tag,
                            poll_interval=args.poll_interval,
                            timeout_seconds=args.timeout,
                        )
                        print("\nUpload results\n" + "=" * 50)
                        for f, msg in results.items():
                            print(f"{f}: {msg}")
                        # Human-readable status mapping
                        status_map = {
                            -1: "Invalid",
                            0: "Ready",
                            1: "Running",
                            2: "Complete",
                            3: "Canceled",
                            4: "Timed Out",
                            5: "Failed",
                            6: "Ingesting",
                            7: "Analyzing",
                            8: "Partially Complete",
                        }
                        if job:
                            st = job.get("status")
                            st_readable = status_map.get(st, str(st))
                            msg = job.get("status_message")
                            print(
                                "\nIngestion job status: {}{}".format(
                                    st_readable, f" - {msg}" if msg else ""
                                )
                            )
                        else:
                            print(
                                "\nIngestion job status: Unknown (timeout or not found)"
                            )
                    else:
                        results = analyzer.upload_files(
                            args.files,
                            start_path=args.start_path,
                            upload_path_tpl=args.upload_path,
                            end_path_tpl=args.end_path,
                            content_type=args.content_type,
                            tag=args.tag,
                        )
                        print("\nUpload results\n" + "=" * 50)
                        for f, msg in results.items():
                            print(f"{f}: {msg}")
        elif args.subcommand == "user":
            if args.password_last_change:
                analyzer.print_password_last_change(
                    args.domain, user=args.user, output=args.output
                )
            elif args.admin_count:
                analyzer.print_admin_users(args.domain, args.output)
            elif args.high_value:
                analyzer.print_highvalue_users(args.domain, args.output)
            elif args.password_not_required:
                analyzer.print_password_not_required_users(args.domain, args.output)
            elif args.password_never_expires:
                analyzer.print_password_never_expires_users(args.domain, args.output)
            else:
                analyzer.print_users(args.domain, args.output)
        elif args.subcommand == "custom":
            analyzer.execute_custom_query(args.query, args.output)
        elif args.subcommand == "session":
            analyzer.print_sessions(args.domain, da=args.da, output=args.output)
        elif args.subcommand == "access":
            analyzer.print_access(args.source, args.relation, args.target, args.domain)
    except Exception as e:
        print(f"Error: {str(e)}")
    finally:
        analyzer.close()


if __name__ == "__main__":
    main()
