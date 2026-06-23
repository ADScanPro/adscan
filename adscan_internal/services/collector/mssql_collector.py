"""Native MSSQL authorization collector for ADscan.

The SQL-server equivalent of the read-only ACE collection the LDAP/SMB collector
already performs. It materializes the **authorization facts** of every reachable
MSSQL instance into the attack graph as effective ``SQLAccess`` / ``SQLAdmin``
edges between AD principal/group nodes and the instance host node, with the raw
``sys.server_principals`` / ``sys.server_role_members`` / ``sys.server_permissions``
rows stored as edge ``evidence``.

Scope (v1, see ``docs/superpowers/specs/2026-06-16-mssql-collector-design.md`` §6):

  * Instance discovery — ``MSSQLSvc/*`` SPNs from the LDAP graph ∩ ``mssql/ips.txt``
    from the port scan.
  * Authorization enumeration — connect via the existing native TDS path
    (``ImpacketMSSQLBackend``), enumerate logins / role memberships / explicit
    server permissions, compute **effective** sysadmin / ``CONTROL SERVER`` via the
    fixed-role hierarchy, degrade gracefully by the connecting login's privilege.
  * SID correlation — hex SID → ``S-1-5-…`` → match the graph node by ``objectId``.
    A **group** login attaches the edge to the GROUP node, so the existing
    ``MemberOf`` edges deliver the blast radius for free.
  * Edge upsert — effective ``SQLAccess`` (CONNECT) / ``SQLAdmin`` (effective
    sysadmin / CONTROL SERVER) into ``attack_graph.json``, following the canonical
    ``upsert_*`` pattern. Negative facts (no SQLAccess on instance X) are recorded
    on the node so re-collection knows what was already checked.

The **escalation actions** (xp_cmdshell, EXECUTE AS, CLR → SYSTEM) are NOT here —
they stay lazy in the ``ask_for_user_privs`` followup (out of scope, §9). This
module is the single source of truth for "enumerate MSSQL authorization as
credential X"; the followup delegates discovery here (§6.3).

AD constraints (skill ``adscan-ad-constraints``):
  * Native TDS via the existing posture-aware backend — Kerberos SPN promoted to
    FQDN, Kerberos→NTLM infra fallback, ccache login. No new TDS client.
  * FQDN (never IP) for the Kerberos SPN, resolved from the workspace inventory.
  * Enterprise scale (§10) — scoped to discovered instances (few), bounded by an
    ``asyncio.Semaphore``, per-instance connect timeout, reachability pre-filter on
    the caller's side. OPSEC: one login per instance = a couple of 4624/4625.
"""

from __future__ import annotations

import asyncio
import binascii
import os
import struct
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from adscan_core import telemetry
from adscan_core.rich_output import print_info_debug, print_info_verbose
from adscan_internal.rich_output import mark_sensitive


# ---------------------------------------------------------------------------
# Tuning (env-overridable; grounded in AD-constraints §10, not lab-tuned)
# ---------------------------------------------------------------------------

DEFAULT_MSSQL_PORT = 1433
_DEFAULT_PER_INSTANCE_TIMEOUT = 30  # seconds, per TDS login + query
_DEFAULT_CONCURRENCY = 8  # few instances; keep the login fan-out gentle for EDR

# Fixed server role whose membership (direct OR transitive) is sysadmin-equivalent.
_SYSADMIN_ROLE = "sysadmin"
# Explicit server permission that confers sysadmin-equivalent control.
_CONTROL_SERVER_PERMISSION = "control server"

# SQL principal ``type`` codes that correspond to an AD principal we can correlate
# back to a graph node by SID. S=SQL login (local, no AD SID), R=server role.
_AD_BACKED_PRINCIPAL_TYPES = frozenset({"U", "G"})  # Windows user / Windows group
_GROUP_PRINCIPAL_TYPES = frozenset({"G"})


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
        return value if value > 0 else default
    except ValueError:
        return default


# ---------------------------------------------------------------------------
# Config & result models
# ---------------------------------------------------------------------------


@dataclass
class MSSQLCollectorConfig:
    """Credentials + tuning for the MSSQL authorization collection phase."""

    domain: str
    username: str
    secret: str  # password, 32-hex NT hash, or a ``.ccache`` path
    use_kerberos: bool = False
    kdc_host: str | None = None  # DC/KDC IP for impacket's self-minted AS/TGS
    port: int = DEFAULT_MSSQL_PORT
    per_instance_timeout: int = field(
        default_factory=lambda: _env_int(
            "ADSCAN_MSSQL_COLLECTOR_TIMEOUT", _DEFAULT_PER_INSTANCE_TIMEOUT
        )
    )
    concurrency: int = field(
        default_factory=lambda: _env_int(
            "ADSCAN_MSSQL_COLLECTOR_CONCURRENCY", _DEFAULT_CONCURRENCY
        )
    )


@dataclass(frozen=True)
class MSSQLInstance:
    """One discovered MSSQL instance worth probing."""

    host: str  # IP (reachable, from mssql/ips.txt)
    fqdn: str | None = None  # FQDN for the Kerberos SPN (MSSQLSvc/<fqdn>:<port>)
    spn: str | None = None  # the MSSQLSvc SPN that surfaced it (if any)


@dataclass
class MSSQLPrincipalFact:
    """One server principal resolved against the AD graph."""

    principal_id: int
    name: str
    type_code: str  # S/U/G/R/C/K/E/X
    type_desc: str
    is_disabled: bool
    sid: str | None  # normalized S-1-5-… (None for SQL logins / roles)
    is_group: bool
    effective_sysadmin: bool
    # Graph node (objectId) the SID correlated to, when an AD-backed login matched.
    matched_object_id: str | None = None
    matched_label: str | None = None


@dataclass
class MSSQLInstanceAuthorization:
    """Enumeration outcome for one instance under one credential."""

    instance: MSSQLInstance
    connected: bool
    connecting_login: str = ""
    connecting_is_sysadmin: bool = False
    view_any_definition: bool = False  # full cross-principal visibility achieved
    principals: list[MSSQLPrincipalFact] = field(default_factory=list)
    role_members: list[dict[str, Any]] = field(default_factory=list)
    permissions: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None


@dataclass
class MSSQLCollectionSummary:
    """Aggregate outcome of one collection run for telemetry / wiring."""

    instances_discovered: int = 0
    instances_connected: int = 0
    sqlaccess_edges: int = 0
    sqladmin_edges: int = 0
    negative_facts: int = 0
    errors: int = 0


# ---------------------------------------------------------------------------
# SID conversion (hex SID → S-1-5-… ) — pure logic, L1-tested
# ---------------------------------------------------------------------------


def hex_sid_to_string(hex_sid: str) -> str | None:
    """Convert a ``CONVERT(VARCHAR(85), sid, 1)`` hex SID to canonical form.

    Mirrors MSSQLHound's ``convertHexSIDToString`` (and the PowerShell
    ``ConvertTo-SecurityIdentifier`` behaviour): parse the binary SID structure
    (revision, sub-authority count, 6-byte big-endian identifier authority,
    then N little-endian 32-bit sub-authorities) into ``S-<rev>-<auth>-<sub…>``.

    Args:
        hex_sid: A ``0x…`` hex string (impacket may also return raw ``bytes`` —
            the caller normalizes those to hex first).

    Returns:
        The canonical ``S-1-5-21-…`` string, or ``None`` when the value is empty,
        not a valid SID, or a SQL-login placeholder (``0x01`` / ``0x``).
    """
    cleaned = str(hex_sid or "").strip()
    if not cleaned or cleaned.lower() in {"0x", "0x01"}:
        return None
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    if not cleaned:
        return None
    try:
        raw = binascii.unhexlify(cleaned)
    except (binascii.Error, ValueError):
        return None
    if len(raw) < 8:
        return None
    revision = raw[0]
    if revision != 1:
        return None
    sub_auth_count = raw[1]
    expected_len = 8 + sub_auth_count * 4
    if len(raw) < expected_len:
        return None
    authority = int.from_bytes(raw[2:8], byteorder="big")
    parts = [f"S-{revision}-{authority}"]
    for i in range(sub_auth_count):
        offset = 8 + i * 4
        sub = struct.unpack("<I", raw[offset : offset + 4])[0]
        parts.append(str(sub))
    return "-".join(parts)


def _coerce_sid_value(value: Any) -> str | None:
    """Normalize an impacket TDS ``sid`` cell (hex str OR raw bytes) to a SID."""
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        # impacket returns ``varbinary`` sids as raw bytes on some drivers.
        return hex_sid_to_string("0x" + bytes(value).hex())
    return hex_sid_to_string(str(value))


def _truthy(value: Any) -> bool:
    """Coerce a TDS scalar (int/str/bool) to bool — None/0/'0' → False."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "t"}
    return bool(value)


def _to_int(value: Any) -> int | None:
    """Best-effort int coercion of a TDS scalar; ``None`` on failure."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text)
        except ValueError:
            return None
    return None


# ---------------------------------------------------------------------------
# Effective-sysadmin derivation — pure logic, L1-tested
# ---------------------------------------------------------------------------


def compute_effective_sysadmin_ids(
    principals: Iterable[dict[str, Any]],
    role_members: Iterable[dict[str, Any]],
    permissions: Iterable[dict[str, Any]],
) -> set[int]:
    """Return the set of principal_ids that are EFFECTIVE sysadmin.

    A principal is effective sysadmin when it is a member of the ``sysadmin``
    fixed server role — directly or transitively through nested role membership
    — OR holds an explicit ``CONTROL SERVER`` GRANT. DENY of ``CONTROL SERVER``
    does not strip role-derived sysadmin (SQL Server evaluates the fixed role
    first), so we only treat GRANT/GRANT_WITH_GRANT_OPTION as conferring it.

    Pure function over the three catalog rowsets so it is unit-testable without a
    live instance. Mirrors MSSQLHound's ``createFixedRoleEdges`` + CONTROL SERVER
    handling.
    """
    # principal_id → name, and the sysadmin role's principal_id.
    name_by_id: dict[int, str] = {}
    role_principal_ids: set[int] = set()
    sysadmin_role_id: int | None = None
    for row in principals:
        pid = _to_int(row.get("principal_id"))
        if pid is None:
            continue
        name = str(row.get("name") or "").strip()
        name_by_id[pid] = name
        type_code = str(row.get("type") or "").strip().upper()
        if type_code == "R":
            role_principal_ids.add(pid)
            if name.lower() == _SYSADMIN_ROLE:
                sysadmin_role_id = pid

    # Build member → {role_id} adjacency from the role-members rowset. Use the
    # role NAME as a fallback when the sysadmin role id was not in the principal
    # roster (a low-priv login may not see the role principal row itself).
    member_to_roles: dict[int, set[int]] = {}
    sysadmin_role_ids: set[int] = set()
    if sysadmin_role_id is not None:
        sysadmin_role_ids.add(sysadmin_role_id)
    for row in role_members:
        member_id = _to_int(row.get("member_principal_id"))
        role_id = _to_int(row.get("role_principal_id"))
        if member_id is None or role_id is None:
            continue
        member_to_roles.setdefault(member_id, set()).add(role_id)
        role_name = str(row.get("role_name") or "").strip().lower()
        if role_name == _SYSADMIN_ROLE:
            sysadmin_role_ids.add(role_id)

    effective: set[int] = set()

    # Transitive closure: a principal that is (transitively) a member of any
    # sysadmin role id is effective sysadmin. Roles can nest (a custom role can
    # be a member of sysadmin), so walk the membership graph.
    def _reaches_sysadmin(start: int) -> bool:
        stack = [start]
        seen: set[int] = set()
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            roles = member_to_roles.get(current, set())
            if roles & sysadmin_role_ids:
                return True
            # Follow nested role memberships only (members that are roles).
            for role_id in roles:
                if role_id in role_principal_ids and role_id not in seen:
                    stack.append(role_id)
        return False

    for pid in name_by_id:
        if _reaches_sysadmin(pid):
            effective.add(pid)

    # Explicit CONTROL SERVER grant is sysadmin-equivalent.
    for row in permissions:
        perm = str(row.get("permission_name") or "").strip().lower()
        state = str(row.get("state_desc") or "").strip().upper()
        if perm != _CONTROL_SERVER_PERMISSION:
            continue
        if state in {"GRANT", "GRANT_WITH_GRANT_OPTION"}:
            grantee = _to_int(row.get("grantee_principal_id"))
            if grantee is not None:
                effective.add(grantee)

    return effective


# ---------------------------------------------------------------------------
# SPN parsing — pure logic, L1-tested
# ---------------------------------------------------------------------------


def parse_mssql_spn_host(spn: str) -> str | None:
    """Extract the host (FQDN/short) from an ``MSSQLSvc/<host>[:<port|instance>]`` SPN.

    Returns the lower-cased host portion, or ``None`` when ``spn`` is not an
    MSSQLSvc SPN. The ``:port`` / ``:instance`` suffix is stripped. SQL named
    instances use ``MSSQLSvc/host:INSTANCE``; default instances use a port.
    """
    text = str(spn or "").strip()
    if not text:
        return None
    head, sep, rest = text.partition("/")
    if not sep or head.strip().lower() != "mssqlsvc":
        return None
    host = rest.strip()
    if ":" in host:
        host = host.split(":", 1)[0]
    host = host.strip().rstrip(".")
    return host.lower() or None


# ---------------------------------------------------------------------------
# Instance discovery — SPN (from the graph) ∩ mssql/ips.txt (from the scan)
# ---------------------------------------------------------------------------


def _load_mssql_ips(workspace_dir: str, domains_dir: str, domain: str) -> list[str]:
    """Read the reachable MSSQL host IPs from ``<domain>/mssql/ips.txt``."""
    try:
        from adscan_internal.workspaces import domain_subpath

        path = domain_subpath(workspace_dir, domains_dir, domain, "mssql", "ips.txt")
    except Exception as exc:  # noqa: BLE001 — path helper must never break discovery
        telemetry.capture_exception(exc)
        return []
    if not path or not os.path.exists(path):
        return []
    ips: list[str] = []
    seen: set[str] = set()
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                ip = line.strip()
                if ip and ip not in seen:
                    seen.add(ip)
                    ips.append(ip)
    except OSError as exc:
        telemetry.capture_exception(exc)
    return ips


def _spn_hosts_from_graph(graph: dict[str, Any]) -> dict[str, str]:
    """Return ``{spn_host_fqdn: spn}`` for every ``MSSQLSvc/*`` SPN in the graph."""
    out: dict[str, str] = {}
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    for node in nodes.values():
        if not isinstance(node, dict):
            continue
        props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
        spns = props.get("serviceprincipalnames") or props.get("serviceprincipalname")
        if isinstance(spns, str):
            spns = [spns]
        if not isinstance(spns, list):
            continue
        for spn in spns:
            host = parse_mssql_spn_host(str(spn))
            if host:
                out.setdefault(host, str(spn).strip())
    return out


def discover_mssql_instances(
    shell: object,
    domain: str,
    *,
    graph: dict[str, Any] | None = None,
    ip_hostname_inventory: dict[str, list[str]] | None = None,
) -> list[MSSQLInstance]:
    """Discover MSSQL instances: ``mssql/ips.txt`` (reachable) enriched by SPNs.

    Reachable IPs from the port scan are the authoritative connect targets. Each
    is enriched with an FQDN — first from the IP→hostname inventory, then by
    matching a graph ``MSSQLSvc/*`` SPN host against the inventory's FQDNs — so a
    hardened (AES-only / NTLM-disabled) instance still gets a correct Kerberos SPN.

    SPN-only instances (no reachable IP) are intentionally NOT probed in v1 — we
    cannot open a TDS connection to them — but the SPN map is used purely for FQDN
    enrichment of the reachable set.
    """
    domain_clean = str(domain or "").strip()
    if not domain_clean:
        return []

    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "")
    domains_dir = str(getattr(shell, "domains_dir", "") or "")
    if not workspace_dir or not domains_dir:
        return []

    ips = _load_mssql_ips(workspace_dir, domains_dir, domain_clean)
    if not ips:
        print_info_debug(
            "[mssql-collector] no reachable MSSQL IPs in mssql/ips.txt for "
            f"{mark_sensitive(domain_clean, 'domain')}; skipping authorization collection"
        )
        return []

    if graph is None:
        try:
            from adscan_internal.services.attack_graph_service import load_attack_graph

            graph = load_attack_graph(shell, domain_clean)
        except Exception as exc:  # noqa: BLE001 — SPN enrichment is best-effort
            telemetry.capture_exception(exc)
            graph = {}

    spn_by_host = _spn_hosts_from_graph(graph or {})

    # IP → FQDN inventory (best-effort).
    inventory = ip_hostname_inventory
    if inventory is None:
        inventory = _load_ip_hostname_inventory(shell, domain_clean)

    instances: list[MSSQLInstance] = []
    for ip in ips:
        fqdn: str | None = None
        candidates = inventory.get(ip) if isinstance(inventory, dict) else None
        if isinstance(candidates, list):
            for candidate in candidates:
                cand = str(candidate or "").strip().rstrip(".").lower()
                if cand:
                    fqdn = cand
                    break
        spn = None
        if fqdn and fqdn in spn_by_host:
            spn = spn_by_host[fqdn]
        instances.append(MSSQLInstance(host=ip, fqdn=fqdn, spn=spn))

    print_info_debug(
        "[mssql-collector] discovered "
        f"{len(instances)} MSSQL instance(s) for "
        f"{mark_sensitive(domain_clean, 'domain')} "
        f"(spn_hosts={len(spn_by_host)})"
    )
    return instances


def _load_ip_hostname_inventory(shell: object, domain: str) -> dict[str, list[str]]:
    """Load the workspace IP→FQDN inventory; ``{}`` on any failure (best-effort)."""
    try:
        from adscan_internal.services.kerberos_hostname_inventory import (
            load_workspace_ip_hostname_inventory,
        )

        workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "")
        domains_dir = str(getattr(shell, "domains_dir", "") or "")
        if not workspace_dir or not domains_dir:
            return {}
        inventory = load_workspace_ip_hostname_inventory(
            workspace_dir=workspace_dir,
            domains_dir=domains_dir,
            domain=domain,
        )
        return inventory if isinstance(inventory, dict) else {}
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return {}


# ---------------------------------------------------------------------------
# Authorization enumeration — one instance, one credential
# ---------------------------------------------------------------------------


def _enumerate_one_instance(
    instance: MSSQLInstance,
    config: MSSQLCollectorConfig,
) -> MSSQLInstanceAuthorization:
    """Connect to one instance and enumerate authorization (blocking TDS).

    Degrades by the connecting login's privilege: a low-priv (CONNECT-only) login
    sees only its own row in ``sys.server_principals`` (and confirms its own
    sysadmin via ``IS_SRVROLEMEMBER``); a ``VIEW ANY DEFINITION`` / sysadmin login
    sees the full cross-principal roster. Never raises — every failure maps onto
    the result's ``error`` so the bounded gather cannot break.
    """
    from adscan_internal.integrations.mssql import queries
    from adscan_internal.integrations.mssql.native_backend import ImpacketMSSQLBackend

    out = MSSQLInstanceAuthorization(instance=instance, connected=False)
    try:
        backend = ImpacketMSSQLBackend(
            host=instance.host,
            port=config.port,
            kerberos_target_hostname=instance.fqdn,
            domain=config.domain,
            kdc_host=config.kdc_host,
        )

        def _run(query: str):
            return backend.execute_query(
                domain=config.domain,
                username=config.username,
                secret=config.secret,
                query=query,
                timeout=config.per_instance_timeout,
                use_kerberos=config.use_kerberos,
                allow_ntlm_fallback=True,
            )

        # Login + own-sysadmin probe (also our connectivity gate).
        sysadmin_result = _run(queries.IS_SYSADMIN)
        if not sysadmin_result.success:
            out.error = (sysadmin_result.error_message or "MSSQL login failed")[:500]
            return out
        out.connected = True
        out.connecting_login = str(config.username or "").strip()
        out.connecting_is_sysadmin = bool(sysadmin_result.rows) and _truthy(
            sysadmin_result.rows[0].get("is_sysadmin")
        )

        # Full server-scope authorization roster. With insufficient visibility
        # these return only the connecting principal's own rows (or none) — that
        # is the graceful-degradation path, NOT an error.
        principals_result = _run(queries.COLLECT_SERVER_PRINCIPALS)
        role_members_result = _run(queries.COLLECT_SERVER_ROLE_MEMBERS)
        permissions_result = _run(queries.COLLECT_SERVER_PERMISSIONS)

        raw_principals = list(principals_result.rows or [])
        out.role_members = list(role_members_result.rows or [])
        out.permissions = list(permissions_result.rows or [])

        # VIEW ANY DEFINITION (or higher) is implied when we can see more than
        # just our own principal — i.e. AD-backed logins beyond the connector.
        ad_backed = [
            row
            for row in raw_principals
            if str(row.get("type") or "").strip().upper() in _AD_BACKED_PRINCIPAL_TYPES
        ]
        out.view_any_definition = len(ad_backed) > 1 or out.connecting_is_sysadmin

        effective_ids = compute_effective_sysadmin_ids(
            raw_principals, out.role_members, out.permissions
        )

        for row in raw_principals:
            pid = _to_int(row.get("principal_id"))
            if pid is None:
                continue
            type_code = str(row.get("type") or "").strip().upper()
            sid = _coerce_sid_value(row.get("sid"))
            out.principals.append(
                MSSQLPrincipalFact(
                    principal_id=pid,
                    name=str(row.get("name") or "").strip(),
                    type_code=type_code,
                    type_desc=str(row.get("type_desc") or "").strip(),
                    is_disabled=_truthy(row.get("is_disabled")),
                    sid=sid,
                    is_group=type_code in _GROUP_PRINCIPAL_TYPES,
                    effective_sysadmin=pid in effective_ids,
                )
            )
        return out
    except Exception as exc:  # noqa: BLE001 — enumeration must never raise
        telemetry.capture_exception(exc)
        out.error = f"{type(exc).__name__}: {exc}"
        return out


async def _enumerate_instances(
    instances: list[MSSQLInstance],
    config: MSSQLCollectorConfig,
) -> list[MSSQLInstanceAuthorization]:
    """Enumerate every instance concurrently under a bounded semaphore."""
    if not instances:
        return []
    worker_count = max(1, min(config.concurrency, len(instances)))
    semaphore = asyncio.Semaphore(worker_count)

    async def _bounded(instance: MSSQLInstance) -> MSSQLInstanceAuthorization:
        async with semaphore:
            try:
                return await asyncio.wait_for(
                    asyncio.to_thread(_enumerate_one_instance, instance, config),
                    timeout=config.per_instance_timeout + 15,
                )
            except (asyncio.TimeoutError, TimeoutError):
                result = MSSQLInstanceAuthorization(instance=instance, connected=False)
                result.error = "timeout"
                return result

    return list(await asyncio.gather(*(_bounded(i) for i in instances)))


# ---------------------------------------------------------------------------
# SID → AD-node correlation + effective edge upsert
# ---------------------------------------------------------------------------


def _build_sid_index(graph: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Build ``{UPPER(objectId): node}`` for every node carrying a SID."""
    from adscan_internal.services.attack_graph_service import _extract_node_object_id

    index: dict[str, dict[str, Any]] = {}
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    for node in nodes.values():
        if not isinstance(node, dict):
            continue
        oid = _extract_node_object_id(node)
        if oid:
            index[oid.strip().upper()] = node
    return index


def _resolve_instance_host_node(
    shell: object,
    domain: str,
    instance: MSSQLInstance,
) -> tuple[dict[str, Any] | None, str | None]:
    """Resolve an instance to its graph Computer node + canonical FQDN.

    Reuses the shared NetExec target resolver (hostname-first, DNS-reverse
    fallback) so the edge attaches to the same Computer node the rest of the
    graph uses — never invents an IP-based node.
    """
    try:
        from adscan_internal.services.attack_graph_service import (
            _resolve_netexec_target_computer_node,
        )

        service = None
        if hasattr(shell, "_get_graph_service"):
            service = shell._get_graph_service()  # type: ignore[attr-defined]
        if not service or not hasattr(service, "get_computer_node_by_name"):
            return None, None
        return _resolve_netexec_target_computer_node(
            shell,
            service=service,
            domain=domain,
            target_ip=instance.host,
            target_hostname=instance.fqdn,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return None, None


def _principal_evidence(fact: MSSQLPrincipalFact) -> dict[str, Any]:
    """Compact, sanitisation-friendly evidence dict for one principal fact."""
    return {
        "sql_login": fact.name,
        "type": fact.type_code,
        "type_desc": fact.type_desc,
        "is_disabled": fact.is_disabled,
        "sid": fact.sid,
        "is_group": fact.is_group,
        "effective_sysadmin": fact.effective_sysadmin,
    }


def upsert_mssql_access_edges(
    shell: object,
    domain: str,
    authorization: MSSQLInstanceAuthorization,
    *,
    graph: dict[str, Any] | None = None,
    save: bool = True,
) -> tuple[int, int]:
    """Upsert effective ``SQLAccess`` / ``SQLAdmin`` edges for one instance.

    Follows the canonical ``upsert_*`` pattern (``load_attack_graph`` →
    ``upsert_nodes``/``upsert_edge`` → ``save_attack_graph``). An AD-backed login
    correlates to its graph node by SID; a **group** login attaches the edge to
    the GROUP node so the existing ``MemberOf`` edges deliver the blast radius.
    Effective sysadmin / CONTROL SERVER → ``SQLAdmin``, otherwise ``SQLAccess``.
    The raw principal fact is stored as edge ``evidence``.

    Returns ``(sqlaccess_edges, sqladmin_edges)`` newly upserted.
    """
    from adscan_internal.services.attack_graph_service import (
        _node_id,
        load_attack_graph,
        save_attack_graph,
        upsert_edge,
        upsert_nodes,
    )

    domain_clean = str(domain or "").strip()
    if not domain_clean or not authorization.connected:
        return 0, 0

    host_node, fqdn = _resolve_instance_host_node(
        shell, domain_clean, authorization.instance
    )
    if not isinstance(host_node, dict) or not fqdn:
        print_info_verbose(
            "[mssql-collector] no graph Computer node for instance "
            f"{mark_sensitive(authorization.instance.host, 'ip')}; "
            "skipping edge upsert (node not in graph)"
        )
        return 0, 0

    if graph is None:
        graph = load_attack_graph(shell, domain_clean)

    comp_record = {
        "name": str(host_node.get("name") or fqdn),
        "kind": ["Computer"],
        "objectId": host_node.get("objectid") or host_node.get("objectId"),
        "properties": host_node,
    }
    upsert_nodes(graph, [comp_record])
    to_id = _node_id(comp_record)
    if not to_id:
        return 0, 0

    sid_index = _build_sid_index(graph)
    spn_label = authorization.instance.spn or f"MSSQLSvc/{fqdn}"

    # Robustness gate inputs — principals that CANNOT connect must not get a
    # SQLAccess/SQLAdmin edge. We gate on the two AUTHORITATIVE "cannot connect"
    # signals only: a disabled login, and an explicit ``CONNECT SQL`` DENY (DENY
    # always wins in SQL Server). We deliberately do NOT require an explicit
    # CONNECT SQL GRANT — CONNECT can be conferred via a server role and the
    # connecting login's metadata visibility may be degraded, so requiring an
    # explicit grant would risk false NEGATIVES (dropping real access). Removing
    # only disabled / DENY'd logins strips false positives without that risk.
    connect_denied_ids: set[int] = set()
    for _perm_row in authorization.permissions or []:
        if str(_perm_row.get("permission_name") or "").strip().upper() != "CONNECT SQL":
            continue
        if str(_perm_row.get("state_desc") or "").strip().upper() != "DENY":
            continue
        _denied_pid = _to_int(_perm_row.get("grantee_principal_id"))
        if _denied_pid is not None:
            connect_denied_ids.add(_denied_pid)

    sqlaccess = 0
    sqladmin = 0
    for fact in authorization.principals:
        # Only AD-backed logins (Windows user / group) correlate to a graph node.
        if fact.type_code not in _AD_BACKED_PRINCIPAL_TYPES or not fact.sid:
            continue
        # Connect gate: skip logins that cannot actually authenticate.
        if fact.is_disabled or fact.principal_id in connect_denied_ids:
            continue
        principal_node = sid_index.get(fact.sid.strip().upper())
        if not isinstance(principal_node, dict):
            # SID not in the graph (foreign principal, stale node). Record as a
            # principal-level note on the host so re-collection sees it; do not
            # invent a node.
            continue
        from_id = _node_id(principal_node)
        if not from_id or from_id == to_id:
            continue
        fact.matched_object_id = fact.sid
        fact.matched_label = str(
            principal_node.get("label") or principal_node.get("name") or ""
        )

        relation = "SQLAdmin" if fact.effective_sysadmin else "SQLAccess"
        notes: dict[str, Any] = {
            "source": "mssql_collector",
            "ip": authorization.instance.host,
            "fqdn": fqdn,
            "spn": spn_label,
            "via_group": fact.is_group,
            "connecting_login": authorization.connecting_login,
            "view_any_definition": authorization.view_any_definition,
            "evidence": _principal_evidence(fact),
        }
        upsert_edge(
            graph,
            from_id=from_id,
            to_id=to_id,
            relation=relation,
            edge_type="mssql_collector",
            status="discovered",
            notes=notes,
        )
        if relation == "SQLAdmin":
            sqladmin += 1
        else:
            sqlaccess += 1

    # Negative / coverage fact on the host node so re-collection knows this
    # instance was enumerated under this login (and at what visibility).
    try:
        props = comp_record["properties"]
        if isinstance(props, dict):
            coverage = props.setdefault("mssql_authorization_coverage", {})
            if isinstance(coverage, dict):
                coverage[authorization.connecting_login or "?"] = {
                    "view_any_definition": authorization.view_any_definition,
                    "sysadmin": authorization.connecting_is_sysadmin,
                    "sqlaccess_edges": sqlaccess,
                    "sqladmin_edges": sqladmin,
                }
    except Exception as exc:  # noqa: BLE001 — coverage note is best-effort
        telemetry.capture_exception(exc)

    if save:
        save_attack_graph(shell, domain_clean, graph)

    print_info_debug(
        "[mssql-collector] upserted edges for "
        f"{mark_sensitive(fqdn, 'host')}: "
        f"SQLAccess={sqlaccess} SQLAdmin={sqladmin} "
        f"connecting_login={mark_sensitive(authorization.connecting_login or '-', 'user')} "
        f"view_any_definition={authorization.view_any_definition}"
    )
    return sqlaccess, sqladmin


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def collect_mssql_authorization(
    shell: object,
    domain: str,
    config: MSSQLCollectorConfig,
    *,
    instances: Optional[list[MSSQLInstance]] = None,
) -> MSSQLCollectionSummary:
    """Collect MSSQL authorization for one credential and materialize edges.

    Single source of truth for "enumerate MSSQL authorization as credential X".
    Discovers instances (when not supplied), enumerates each concurrently at the
    depth the connecting login's privilege allows, correlates SQL principals to
    AD graph nodes by SID, and upserts effective ``SQLAccess`` / ``SQLAdmin``
    edges (with raw evidence) into ``attack_graph.json``.

    Args:
        shell: Shell exposing ``current_workspace_dir`` / ``domains_dir`` and
            ``_get_graph_service`` for node resolution + graph persistence.
        domain: Target domain whose graph is enriched.
        config: Credentials + tuning for the TDS connections.
        instances: Pre-discovered instances; ``None`` triggers discovery.

    Returns:
        An :class:`MSSQLCollectionSummary` for telemetry / wiring. Never raises.
    """
    summary = MSSQLCollectionSummary()
    domain_clean = str(domain or "").strip()
    if not domain_clean:
        return summary

    try:
        if instances is None:
            instances = discover_mssql_instances(shell, domain_clean)
        summary.instances_discovered = len(instances)
        if not instances:
            return summary

        results = await _enumerate_instances(instances, config)

        # Load the graph ONCE, upsert all instances, save ONCE — avoids re-reading
        # a potentially large attack_graph.json per instance.
        from adscan_internal.services.attack_graph_service import (
            load_attack_graph,
            save_attack_graph,
        )

        graph = load_attack_graph(shell, domain_clean)
        any_edges = False
        for result in results:
            if result.error:
                summary.errors += 1
            if not result.connected:
                continue
            summary.instances_connected += 1
            access, admin = upsert_mssql_access_edges(
                shell, domain_clean, result, graph=graph, save=False
            )
            summary.sqlaccess_edges += access
            summary.sqladmin_edges += admin
            if not (access or admin):
                summary.negative_facts += 1
            else:
                any_edges = True
        if any_edges or summary.instances_connected:
            save_attack_graph(shell, domain_clean, graph)
    except Exception as exc:  # noqa: BLE001 — collection must never raise upward
        telemetry.capture_exception(exc)
        print_info_debug(f"[mssql-collector] collection failed (non-fatal): {exc}")

    print_info_verbose(
        "[mssql-collector] authorization collection complete for "
        f"{mark_sensitive(domain_clean, 'domain')}: "
        f"instances={summary.instances_discovered} "
        f"connected={summary.instances_connected} "
        f"SQLAccess={summary.sqlaccess_edges} SQLAdmin={summary.sqladmin_edges} "
        f"errors={summary.errors}"
    )
    return summary


def collect_mssql_authorization_sync(
    shell: object,
    domain: str,
    config: MSSQLCollectorConfig,
    *,
    instances: Optional[list[MSSQLInstance]] = None,
) -> MSSQLCollectionSummary:
    """Synchronous wrapper around :func:`collect_mssql_authorization`.

    Uses the shared async bridge so it can be called from the synchronous
    ``run_enumeration`` step and the privileges followup. Never raises.
    """
    try:
        from adscan_internal.services.async_bridge import run_async_sync

        return run_async_sync(
            collect_mssql_authorization(shell, domain, config, instances=instances)
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(f"[mssql-collector] sync collection failed (non-fatal): {exc}")
        return MSSQLCollectionSummary()


__all__ = [
    "DEFAULT_MSSQL_PORT",
    "MSSQLCollectorConfig",
    "MSSQLInstance",
    "MSSQLPrincipalFact",
    "MSSQLInstanceAuthorization",
    "MSSQLCollectionSummary",
    "hex_sid_to_string",
    "compute_effective_sysadmin_ids",
    "parse_mssql_spn_host",
    "discover_mssql_instances",
    "upsert_mssql_access_edges",
    "collect_mssql_authorization",
    "collect_mssql_authorization_sync",
]
