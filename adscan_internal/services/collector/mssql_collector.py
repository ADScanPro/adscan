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
from adscan_core.rich_output import print_info, print_info_debug, print_info_verbose
from adscan_internal.rich_output import mark_sensitive
from adscan_core.rich_output import print_exception


# ---------------------------------------------------------------------------
# Tuning (env-overridable; grounded in AD-constraints §10, not lab-tuned)
# ---------------------------------------------------------------------------

DEFAULT_MSSQL_PORT = 1433
_DEFAULT_PER_INSTANCE_TIMEOUT = 30  # seconds, per TDS login + query (socket timeout)
# Per-instance WALL budget for the whole enumeration (auth sweep + linked-server
# discovery + best-effort enrichment probes), enforced by the outer
# ``asyncio.wait_for``. This is a HUNG-INSTANCE safety net, NOT a per-query budget
# the normal path should race against — so it is deliberately GENEROUS and
# DECOUPLED from the per-query socket timeout. An instance runs a bounded but
# growing number of queries (≈5 core + 2 per linked server), and each pays the
# real round-trip latency; over a slow VPN (adscan-ad-constraints §7bis, RTT
# 300-400ms, multi-round-trip TDS auth) a legitimate enumeration with several
# linked servers can take tens of seconds. Sizing the wall budget to the per-query
# timeout (the old ``+15`` = 45s) made the normal path RACE its own safety net:
# once each query got slow (e.g. Kerberos retried per-query on an SPN-less
# instance) the total blew the budget, timed out the WHOLE instance and discarded
# every already-enumerated edge — a best-effort probe silently killing the core
# output. A generous wall budget + fast queries means a working instance never
# trips it; only a genuinely hung instance is killed (each query already bounded
# by the per-query socket timeout).
_DEFAULT_INSTANCE_WALL_BUDGET = 120  # seconds, whole-instance enumeration ceiling
_DEFAULT_CONCURRENCY = 8  # few instances; keep the login fan-out gentle for EDR

# Fixed server role whose membership (direct OR transitive) is sysadmin-equivalent.
_SYSADMIN_ROLE = "sysadmin"
# Explicit server permission that confers sysadmin-equivalent control.
_CONTROL_SERVER_PERMISSION = "control server"
# Fixed server role whose membership (direct OR transitive) confers ADMINISTER
# BULK OPERATIONS-equivalent capability (OPENROWSET(BULK ...) arbitrary-file-read).
_BULK_ADMIN_ROLE = "bulkadmin"
# Explicit server permission that confers OPENROWSET(BULK ...) capability.
_BULK_OPERATIONS_PERMISSION = "administer bulk operations"

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
    # Password / NT hash for the same principal, used only as a posture-aware
    # NTLM fallback when ``secret`` is a ``.ccache`` and the instance has no
    # ``MSSQLSvc`` SPN (Kerberos → ``KDC_ERR_S_PRINCIPAL_UNKNOWN``). Resolved by
    # the caller via the SSOT ``resolve_mssql_ntlm_fallback_secret`` and made
    # sticky on the backend so every collector query carries it. ``None`` when
    # no NTLM fallback should be attempted (non-ccache secret, NTLM known-
    # blocked by posture, or no NTLM-usable secret available).
    ntlm_fallback_secret: str | None = None
    port: int = DEFAULT_MSSQL_PORT
    per_instance_timeout: int = field(
        default_factory=lambda: _env_int(
            "ADSCAN_MSSQL_COLLECTOR_TIMEOUT", _DEFAULT_PER_INSTANCE_TIMEOUT
        )
    )
    # Whole-instance enumeration ceiling (hung-instance safety net) — decoupled
    # from and much larger than the per-query socket timeout above. See
    # ``_DEFAULT_INSTANCE_WALL_BUDGET``.
    instance_wall_budget: int = field(
        default_factory=lambda: _env_int(
            "ADSCAN_MSSQL_COLLECTOR_WALL_BUDGET", _DEFAULT_INSTANCE_WALL_BUDGET
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
    # Effective ADMINISTER BULK OPERATIONS capability (sysadmin, bulkadmin role
    # membership, or an explicit grant) — feeds the OPENROWSET(BULK ...)
    # arbitrary-file-read attack step, chained off SQLAccess/SQLAdmin.
    effective_bulk_admin: bool = False
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
    # Linked servers discovered on this instance (READ-ONLY). Each carries its
    # remote ``data_source`` host + the local↔remote login mappings, from which
    # the collector emits theoretical ``MssqlLinkedServerLateral`` edges.
    linked_servers: list[Any] = field(default_factory=list)
    error: str | None = None


@dataclass
class MSSQLCollectionSummary:
    """Aggregate outcome of one collection run for telemetry / wiring."""

    instances_discovered: int = 0
    instances_connected: int = 0
    sqlaccess_edges: int = 0
    sqladmin_edges: int = 0
    linked_server_edges: int = 0
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


def _compute_effective_ids_for_roles_and_permission(
    principals: Iterable[dict[str, Any]],
    role_members: Iterable[dict[str, Any]],
    permissions: Iterable[dict[str, Any]],
    *,
    target_role_names: frozenset[str],
    target_permission_name: str,
) -> set[int]:
    """Return principal_ids that reach ANY of ``target_role_names`` (transitively
    through nested role membership) OR hold an explicit GRANT of
    ``target_permission_name``.

    Shared walk behind :func:`compute_effective_sysadmin_ids` (target role
    ``sysadmin`` + permission ``CONTROL SERVER``) and
    :func:`compute_effective_bulk_admin_ids` (target roles ``sysadmin`` +
    ``bulkadmin`` + permission ``ADMINISTER BULK OPERATIONS``) — both derive
    from the SAME already-collected catalog rowsets
    (``sys.server_principals`` / ``sys.server_role_members`` /
    ``sys.server_permissions``), so a new privilege-equivalence check is a new
    (role-set, permission) pair over this one walk, never a new round trip.
    """
    # principal_id → name, and the target roles' principal_id(s).
    name_by_id: dict[int, str] = {}
    role_principal_ids: set[int] = set()
    target_role_ids: set[int] = set()
    for row in principals:
        pid = _to_int(row.get("principal_id"))
        if pid is None:
            continue
        name = str(row.get("name") or "").strip()
        name_by_id[pid] = name
        type_code = str(row.get("type") or "").strip().upper()
        if type_code == "R":
            role_principal_ids.add(pid)
            if name.lower() in target_role_names:
                target_role_ids.add(pid)

    # Build member → {role_id} adjacency from the role-members rowset. Use the
    # role NAME as a fallback when the target role id was not in the principal
    # roster (a low-priv login may not see the role principal row itself).
    member_to_roles: dict[int, set[int]] = {}
    for row in role_members:
        member_id = _to_int(row.get("member_principal_id"))
        role_id = _to_int(row.get("role_principal_id"))
        if member_id is None or role_id is None:
            continue
        member_to_roles.setdefault(member_id, set()).add(role_id)
        role_name = str(row.get("role_name") or "").strip().lower()
        if role_name in target_role_names:
            target_role_ids.add(role_id)

    effective: set[int] = set()

    # Transitive closure: a principal that is (transitively) a member of any
    # target role id is effective. Roles can nest (a custom role can be a
    # member of sysadmin), so walk the membership graph.
    def _reaches_target(start: int) -> bool:
        stack = [start]
        seen: set[int] = set()
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            roles = member_to_roles.get(current, set())
            if roles & target_role_ids:
                return True
            # Follow nested role memberships only (members that are roles).
            for role_id in roles:
                if role_id in role_principal_ids and role_id not in seen:
                    stack.append(role_id)
        return False

    for pid in name_by_id:
        if _reaches_target(pid):
            effective.add(pid)

    # Explicit permission grant is equivalent to the role membership above.
    permission_name_lower = target_permission_name.strip().lower()
    for row in permissions:
        perm = str(row.get("permission_name") or "").strip().lower()
        state = str(row.get("state_desc") or "").strip().upper()
        if perm != permission_name_lower:
            continue
        if state in {"GRANT", "GRANT_WITH_GRANT_OPTION"}:
            grantee = _to_int(row.get("grantee_principal_id"))
            if grantee is not None:
                effective.add(grantee)

    return effective


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
    return _compute_effective_ids_for_roles_and_permission(
        principals,
        role_members,
        permissions,
        target_role_names=frozenset({_SYSADMIN_ROLE}),
        target_permission_name=_CONTROL_SERVER_PERMISSION,
    )


def compute_effective_bulk_admin_ids(
    principals: Iterable[dict[str, Any]],
    role_members: Iterable[dict[str, Any]],
    permissions: Iterable[dict[str, Any]],
) -> set[int]:
    """Return the set of principal_ids EFFECTIVELY capable of ``ADMINISTER BULK
    OPERATIONS`` — i.e. able to read arbitrary files the SQL service account can
    reach via ``OPENROWSET(BULK ... , SINGLE_BLOB)``.

    A principal has this capability when it is EFFECTIVE sysadmin (sysadmin
    bypasses every permission check, so it trivially has this too), a
    (transitive) member of the fixed ``bulkadmin`` server role, or holds an
    explicit ``ADMINISTER BULK OPERATIONS`` GRANT. Unlike sysadmin, this
    capability is reachable WITHOUT sysadmin — a plain ``bulkadmin`` member or
    an explicitly-granted login is exactly the ``SQLAccess`` (below-sysadmin)
    case this feeds.

    Mirrors :func:`compute_effective_sysadmin_ids` — same walk, over the SAME
    already-collected rowsets, parametrized by a different (role-set,
    permission) pair. No new round trip.
    """
    return _compute_effective_ids_for_roles_and_permission(
        principals,
        role_members,
        permissions,
        target_role_names=frozenset({_SYSADMIN_ROLE, _BULK_ADMIN_ROLE}),
        target_permission_name=_BULK_OPERATIONS_PERMISSION,
    )


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
# Instance discovery — union of SYN-scan (mssql/ips.txt), SPN (graph MSSQLSvc/*)
# and pivot-reachable hosts, via the service-target-resolution SSOT
# ---------------------------------------------------------------------------


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
) -> list[MSSQLInstance]:
    """Discover MSSQL instances by UNIONING three evidence sources (SSOT).

    Delegates target resolution to
    :func:`service_target_resolution.resolve_service_targets`, which unions:

      * **syn** — the SYN-scan-reachable IPs in ``mssql/ips.txt``.
      * **spn** — graph ``MSSQLSvc/*`` SPN hosts, resolved to an IP via the
        workspace inventory. This is what fixes the pivot / filtered-port gap:
        a host we KNOW runs MSSQL (from its SPN) becomes a connect target even
        when the direct SYN scan never saw port 1433 open.
      * **pivot** — hosts a pivot confirmed reachable on 1433.

    Each target carries an FQDN promoted to a fully-qualified name, so a hardened
    (AES-only / NTLM-disabled) instance still gets a correct ``MSSQLSvc/<fqdn>``
    Kerberos SPN. A per-instance TDS connect is attempted for every target; the
    existing per-instance Kerberos→NTLM fallback + bounded wall budget make a
    dead SPN-seeded host fail cleanly, so the union never introduces a new
    failure mode — only recovers a service the ``ips.txt``-only gate would have
    silently skipped.
    """
    domain_clean = str(domain or "").strip()
    if not domain_clean:
        return []

    if graph is None:
        try:
            from adscan_internal.services.attack_graph_service import load_attack_graph

            graph = load_attack_graph(shell, domain_clean)
        except Exception as exc:  # noqa: BLE001 — SPN enrichment is best-effort
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            graph = {}

    spn_by_host = _spn_hosts_from_graph(graph or {})

    from adscan_internal.services.service_target_resolution import (
        resolve_service_targets,
    )

    resolution = resolve_service_targets(
        shell, domain_clean, service="mssql", spn_hosts=spn_by_host
    )
    instances = [
        MSSQLInstance(host=target.host, fqdn=target.fqdn, spn=target.spn)
        for target in resolution.targets
    ]

    if not instances:
        print_info_debug(
            "[mssql-collector] no MSSQL targets (syn/spn/pivot) for "
            f"{mark_sensitive(domain_clean, 'domain')}; skipping authorization collection"
        )
        return instances

    # Promote the "SYN scan saw nothing but SPNs/pivot know a host runs MSSQL"
    # case from DEBUG to a visible advisory — this is exactly the pivot /
    # filtered-port scenario the union recovers, and the operator should see it.
    spn_only = resolution.spn_only_hosts
    if spn_only:
        seeded = ", ".join(
            mark_sensitive(t.fqdn or t.host, "hostname") for t in spn_only
        )
        print_info(
            f"MSSQL: {len(spn_only)} instance(s) seeded from SPN/pivot evidence "
            f"(not seen by the direct port scan): {seeded}. "
            "Attempting anyway (reachable over a pivot or a non-standard port)."
        )

    print_info_debug(
        "[mssql-collector] discovered "
        f"{len(instances)} MSSQL instance(s) for "
        f"{mark_sensitive(domain_clean, 'domain')} "
        f"(syn={resolution.syn_count} spn={resolution.spn_count} "
        f"pivot={resolution.pivot_count} spn_hosts={len(spn_by_host)})"
    )
    return instances


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
        # Reachable-IP split already resolved upstream: ``instance.host`` is the
        # reachable IP (from mssql/ips.txt via the service-target-resolution SSOT,
        # see the MSSQLInstance.host field) and ``instance.fqdn`` is the Kerberos
        # SPN — no per-site resolve_connect_and_spn needed here.
        backend = ImpacketMSSQLBackend(
            host=instance.host,
            port=config.port,
            kerberos_target_hostname=instance.fqdn,
            domain=config.domain,
            kdc_host=config.kdc_host,
            ntlm_fallback_secret=config.ntlm_fallback_secret,
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
        bulk_admin_effective_ids = compute_effective_bulk_admin_ids(
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
                    effective_bulk_admin=pid in bulk_admin_effective_ids,
                )
            )

        # Linked-server discovery (READ-ONLY). Both queries are SELECT / EXEC
        # sp_help* — they enumerate configured linked servers + their login
        # mappings; they NEVER enable xp_cmdshell or configure anything. Degrades
        # gracefully: a non-sysadmin login may see an empty login map.
        out.linked_servers = _collect_linked_servers(_run, queries)
        return out
    except Exception as exc:  # noqa: BLE001 — enumeration must never raise
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        out.error = f"{type(exc).__name__}: {exc}"
        return out


def _collect_linked_servers(run_query: Any, queries: Any) -> list[Any]:
    """Run the READ-ONLY linked-server queries and return merged ``LinkedServer``s.

    ``run_query`` is the per-instance ``_run`` closure (already bound to the
    sticky-fallback backend). Both queries are ``SELECT`` / ``EXEC sp_help*`` —
    no enable/escalation. Never raises; a query failure yields no linked servers.
    """
    from adscan_internal.integrations.mssql import parsers
    from adscan_internal.integrations.mssql.helpers import is_self_linked_server

    try:
        detail_result = run_query(queries.LINKED_SERVERS_DETAIL)
        if not getattr(detail_result, "success", False):
            return []
        servers = parsers.parse_linked_servers_detail(list(detail_result.rows or []))
        if not servers:
            return []
        # Drop the loopback self-referential linked server (name == @@SERVERNAME)
        # so the inventory never emits a useless <host> -> <host> self-loop edge.
        # Uses the same producer-side SSOT predicate as the native backend.
        self_server_name = ""
        name_result = run_query(queries.SERVER_NAME)
        if getattr(name_result, "success", False) and getattr(name_result, "rows", None):
            self_server_name = str(name_result.rows[0].get("server_name") or "").strip()
        if self_server_name:
            servers = [
                ls for ls in servers if not is_self_linked_server(self_server_name, ls)
            ]
        if not servers:
            return []
        login_result = run_query(queries.LINKED_SERVERS_LOGIN_MAP)
        login_map = {}
        if getattr(login_result, "success", False):
            login_map = parsers.parse_linked_server_login_map(
                list(login_result.rows or [])
            )
        merged = parsers.merge_linked_servers_with_login_map(servers, login_map)
        return [_probe_linked_server_remote_sysadmin(run_query, queries, ls) for ls in merged]
    except Exception as exc:  # noqa: BLE001 — linked-server discovery is best-effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return []


def _probe_linked_server_remote_sysadmin(run_query: Any, queries: Any, linked_server: Any) -> Any:
    """Set ``remote_is_sysadmin`` (and, when sysadmin, ``xp_cmdshell_enabled``) on a
    linked server via READ-ONLY remote probes.

    Runs ``IS_SRVROLEMEMBER('sysadmin')`` on the REMOTE instance through the link
    (under its login mapping) — the exact signal that decides whether xp_cmdshell
    RCE is reachable across the link. When that resolves True, ALSO reads the
    remote ``xp_cmdshell`` run-state (a pure ``sys.configurations`` read) so the
    overlay knows whether the switch is already flipped. Read-only throughout: no
    state change, no xp_cmdshell enable. Best-effort — any failure leaves the
    corresponding field ``None`` (unknown, no claim). Prefers RPC-Out
    (``EXEC ... AT``); falls back to Data-Access (``OPENQUERY``); skips entirely
    when neither transport is enabled.
    """
    import dataclasses  # noqa: PLC0415

    via_rpc = bool(getattr(linked_server, "is_rpc_out_enabled", False))
    if not via_rpc and not getattr(linked_server, "is_data_access_enabled", False):
        return linked_server  # no outbound transport → cannot probe
    try:
        probe = queries.linked_server_sysadmin_probe(linked_server.name, via_rpc=via_rpc)
        result = run_query(probe)
        if not getattr(result, "success", False):
            return linked_server
        from adscan_internal.integrations.mssql import parsers  # noqa: PLC0415

        remote_sysadmin = parsers.parse_linked_server_sysadmin_probe(list(result.rows or []))
        probed = linked_server
        if remote_sysadmin is not None:
            probed = dataclasses.replace(linked_server, remote_is_sysadmin=remote_sysadmin)
            # Only bother reading the remote xp_cmdshell run-state when the mapped
            # login is sysadmin there — otherwise the switch is irrelevant (no
            # rights to flip it) and probing wastes a round-trip.
            if remote_sysadmin is True:
                probed = _probe_linked_server_xp_cmdshell_state(
                    run_query, queries, probed, via_rpc=via_rpc
                )
        # ADMINISTER BULK OPERATIONS is ORTHOGONAL to sysadmin — a bulkadmin-role
        # member or an explicitly-granted login can OPENROWSET(BULK ...) WITHOUT
        # ever being sysadmin, unlike xp_cmdshell (sysadmin-only). So this probe
        # always runs (when an outbound transport exists), regardless of the
        # remote-sysadmin outcome above.
        probed = _probe_linked_server_bulk_admin_state(
            run_query, queries, probed, via_rpc=via_rpc
        )
        return probed
    except Exception as exc:  # noqa: BLE001 — probe is best-effort, never blocks discovery
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return linked_server


def _probe_linked_server_xp_cmdshell_state(
    run_query: Any, queries: Any, linked_server: Any, *, via_rpc: bool
) -> Any:
    """Set ``xp_cmdshell_enabled`` on a linked server via a READ-ONLY remote probe.

    Reads the remote instance's ``xp_cmdshell`` ``run_value`` from
    ``sys.configurations`` through the link (a pure ``SELECT``; NO ``sp_configure``
    / ``RECONFIGURE`` / enable). Best-effort — any failure (or an unresolved
    rowset) leaves ``xp_cmdshell_enabled=None`` (unknown), never blocks discovery.
    """
    import dataclasses  # noqa: PLC0415

    try:
        probe = queries.xp_cmdshell_state_at_link(linked_server.name, via_rpc=via_rpc)
        result = run_query(probe)
        if not getattr(result, "success", False):
            return linked_server
        from adscan_internal.integrations.mssql import parsers  # noqa: PLC0415

        enabled = parsers.parse_xp_cmdshell_state(list(result.rows or []))
        if enabled is None:
            return linked_server
        return dataclasses.replace(linked_server, xp_cmdshell_enabled=enabled)
    except Exception as exc:  # noqa: BLE001 — state probe is best-effort, never blocks discovery
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return linked_server


def _probe_linked_server_bulk_admin_state(
    run_query: Any, queries: Any, linked_server: Any, *, via_rpc: bool
) -> Any:
    """Set ``remote_bulk_admin`` on a linked server via a READ-ONLY remote probe.

    Reads whether the mapped remote login holds ADMINISTER BULK OPERATIONS
    (directly, via ``bulkadmin``, or via sysadmin) on the REMOTE instance
    through the link — the per-edge signal the ``MssqlOpenRowsetBulkRead``
    overlay reads to decide whether the OPENROWSET(BULK ...) arbitrary-file-read
    step is reachable across the link. Pure read (``IS_SRVROLEMEMBER`` /
    ``fn_my_permissions``), no state change. Best-effort — any failure leaves
    ``remote_bulk_admin`` ``None`` (unknown, no claim).
    """
    import dataclasses  # noqa: PLC0415

    try:
        probe = queries.linked_server_bulk_admin_probe(linked_server.name, via_rpc=via_rpc)
        result = run_query(probe)
        if not getattr(result, "success", False):
            return linked_server
        from adscan_internal.integrations.mssql import parsers  # noqa: PLC0415

        bulk_admin = parsers.parse_linked_server_bulk_admin_probe(list(result.rows or []))
        if bulk_admin is None:
            return linked_server
        return dataclasses.replace(linked_server, remote_bulk_admin=bulk_admin)
    except Exception as exc:  # noqa: BLE001 — probe is best-effort, never blocks discovery
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return linked_server


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
                # Generous WALL budget (hung-instance safety net), never smaller
                # than a single query + margin. NOT the per-query timeout — the
                # normal multi-query enumeration must not race its own safety net.
                wall_budget = max(
                    config.instance_wall_budget, config.per_instance_timeout + 15
                )
                return await asyncio.wait_for(
                    asyncio.to_thread(_enumerate_one_instance, instance, config),
                    timeout=wall_budget,
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
        print_exception(exception=exc)
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
        "effective_bulk_admin": fact.effective_bulk_admin,
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
            # Per-principal ADMINISTER BULK OPERATIONS capability — the signal
            # the MssqlOpenRowsetBulkRead overlay reads to decide whether the
            # OPENROWSET(BULK ...) arbitrary-file-read step is reachable on a
            # below-sysadmin SQLAccess login (SQLAdmin is always capable —
            # sysadmin bypasses this permission check entirely).
            "bulk_ops_capable": fact.effective_bulk_admin,
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
        print_exception(exception=exc)

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
# Linked-server lateral edges — theoretical MssqlLinkedServerLateral (READ-ONLY)
# ---------------------------------------------------------------------------


def _normalize_linked_data_source(data_source: str) -> str | None:
    """Normalize a linked-server ``data_source`` to a bare host FQDN/short name.

    SQL Server ``data_source`` values can carry a provider prefix and a named
    instance / port (``tcp:DC02.darkzero.ext,1433``, ``DC02\\SQLEXPRESS``).
    Strip those so the value keys the graph host node. Returns ``None`` when the
    value is empty. IPs are preserved as-is (never invented into an FQDN).
    """
    host = str(data_source or "").strip()
    if not host:
        return None
    # Strip a leading network-library prefix (tcp:, np:, lpc:, ...).
    if ":" in host and not host.count(":") > 1:  # keep IPv6 literals intact
        prefix, _, rest = host.partition(":")
        if prefix.isalpha() and rest:
            host = rest
    # Named instance (HOST\\INSTANCE) and port (HOST,1433) suffixes.
    host = host.split("\\", 1)[0]
    host = host.split(",", 1)[0]
    return host.strip().rstrip(".").lower() or None


def _resolve_linked_server_target_node(
    graph: dict[str, Any],
    data_source_host: str,
) -> tuple[str, bool]:
    """Resolve a linked-server target host to a graph node id, creating one if needed.

    The linked-server ``data_source`` is frequently a host in a DIFFERENT domain
    (e.g. ``DC02.darkzero.ext`` reached from ``darkzero.htb``), which will NOT
    exist in the current domain's graph. Resolution:

    1. Reuse an EXISTING node whose FQDN (``name`` / ``label`` / ``dnshostname``)
       matches ``data_source_host`` exactly (case-insensitive) — this attaches to
       the real host node when the linked server points back into the same graph.
    2. Otherwise create a MINIMAL foreign Computer node keyed by the FQDN, tagged
       as a linked-server target with the derived (foreign) domain. We deliberately
       match ONLY on the exact FQDN — never on a fuzzy short-name — so a
       cross-domain ``DC02.darkzero.ext`` is never mis-merged onto a same-domain
       ``DC02`` node.

    Returns ``(target_node_id, created_foreign_node)``.
    """
    from adscan_internal.services.attack_graph_service import _node_id, upsert_nodes

    host = data_source_host.strip().lower()
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    for node in nodes.values():
        if not isinstance(node, dict):
            continue
        props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
        candidates = {
            str(node.get("name") or "").strip().lower(),
            str(node.get("label") or "").strip().lower(),
            str(props.get("name") or "").strip().lower(),
            str(props.get("dnshostname") or "").strip().lower(),
        }
        candidates.discard("")
        if host in candidates:
            return _node_id(node), False

    # Cross-domain / unknown host: create a minimal foreign Computer placeholder.
    # NOTE: keyed by the FQDN (never a short name) so it cannot collide with a
    # same-domain node; the derived domain is best-effort from the FQDN suffix.
    foreign_domain = host.split(".", 1)[1] if "." in host else ""
    record = {
        "name": host,
        "label": host,
        "kind": ["Computer"],
        "properties": {
            "name": host,
            "dnshostname": host,
            "type": "Computer",
            "mssql_linked_server_target": True,
        },
    }
    if foreign_domain:
        record["properties"]["domain"] = foreign_domain.upper()
    upsert_nodes(graph, [record])
    return _node_id(record), True


def _linked_server_edge_notes(
    authorization: MSSQLInstanceAuthorization,
    source_fqdn: str,
    linked_server: Any,
) -> dict[str, Any]:
    """Build the theoretical linked-server edge notes (metadata + login mapping)."""
    mappings = [
        {
            "local_login": mapping.local_login,
            "remote_login": mapping.remote_login,
            "self_mapping": mapping.is_self_mapping,
        }
        for mapping in getattr(linked_server, "login_mappings", ())
    ]
    # Execution-context annotation: the remote login the source instance uses on
    # the linked server (often higher-privileged). First non-self mapping wins,
    # else any mapping's remote login.
    remote_login = ""
    for mapping in getattr(linked_server, "login_mappings", ()):
        if not mapping.is_self_mapping and mapping.remote_login:
            remote_login = mapping.remote_login
            break
    if not remote_login:
        for mapping in getattr(linked_server, "login_mappings", ()):
            if mapping.remote_login:
                remote_login = mapping.remote_login
                break
    return {
        "source": "mssql_collector",
        "theoretical": True,
        "source_ip": authorization.instance.host,
        "source_fqdn": source_fqdn,
        "connecting_login": authorization.connecting_login,
        "linked_server": linked_server.name,
        "product": linked_server.product,
        "provider": linked_server.provider,
        "data_source": linked_server.data_source,
        "rpc_out_enabled": linked_server.is_rpc_out_enabled,
        "data_access_enabled": linked_server.is_data_access_enabled,
        "remote_login": remote_login,
        # Whether the mapped remote login is sysadmin on the linked instance — the
        # per-edge signal the XpCmdshell overlay reads to decide if RCE is
        # reachable across the link. Omitted when the read-only probe could not
        # resolve (None), so downstream treats absence as "unknown, no RCE claim".
        **(
            {"remote_is_sysadmin": bool(linked_server.remote_is_sysadmin)}
            if getattr(linked_server, "remote_is_sysadmin", None) is not None
            else {}
        ),
        # Whether xp_cmdshell is ALREADY enabled on the linked instance — a
        # read-only observation the XpCmdshell overlay reads to tell "RCE ready
        # now" from "would need to flip the switch". Omitted when the read-only
        # state probe could not resolve (None), so downstream treats absence as
        # "unknown".
        **(
            {"xp_cmdshell_enabled": bool(linked_server.xp_cmdshell_enabled)}
            if getattr(linked_server, "xp_cmdshell_enabled", None) is not None
            else {}
        ),
        # Whether the mapped remote login holds ADMINISTER BULK OPERATIONS on the
        # linked instance — the per-edge signal the MssqlOpenRowsetBulkRead
        # overlay reads to decide if the OPENROWSET(BULK ...) arbitrary-file-read
        # step is reachable across the link. Omitted when the read-only probe
        # could not resolve (None), so downstream treats absence as "unknown, no
        # capability claim". Orthogonal to ``remote_is_sysadmin`` — a bulkadmin
        # or explicitly-granted login can have this even when NOT sysadmin.
        **(
            {"remote_bulk_admin": bool(linked_server.remote_bulk_admin)}
            if getattr(linked_server, "remote_bulk_admin", None) is not None
            else {}
        ),
        "login_mappings": mappings,
    }


def upsert_mssql_linked_server_edges(
    shell: object,
    domain: str,
    authorization: MSSQLInstanceAuthorization,
    *,
    graph: dict[str, Any] | None = None,
    save: bool = True,
) -> int:
    """Upsert theoretical ``MssqlLinkedServerLateral`` edges for one instance.

    Emits ``<source instance host> -MssqlLinkedServerLateral-> <linked data_source
    host>`` for every configured linked server, marked THEORETICAL
    (``status="discovered"`` + ``notes.theoretical=True``). The linked target host
    node is resolved (or minimally created when cross-domain) by
    :func:`_resolve_linked_server_target_node`. Read-only: the collector never
    enables xp_cmdshell or runs any escalation — it records the DISCOVERED
    capability so attack-paths / web / report can render the linked-server hop.

    Returns the number of linked-server edges newly upserted.

    NOTE: when the SOURCE instance host is itself a Tier-0 asset (e.g. the SQL
    instance runs ON a domain controller, as in HTB DarkZero), the graph's
    Tier-0-source suppression (``_edge_has_tier0_source`` in
    ``attack_graph_service``) drops actionable outgoing edges — so the edge will
    not persist in that specific topology. That filter assumes "owning a Tier-0
    source means you already own the domain", which does NOT hold for a linked
    server reaching a DIFFERENT forest. Exempting cross-domain
    ``MssqlLinkedServerLateral`` from that filter is a follow-up in
    ``attack_graph_service`` (out of this collector's scope).
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
        return 0
    linked_servers = [
        ls
        for ls in (authorization.linked_servers or [])
        if _normalize_linked_data_source(getattr(ls, "data_source", ""))
    ]
    if not linked_servers:
        return 0

    host_node, fqdn = _resolve_instance_host_node(
        shell, domain_clean, authorization.instance
    )
    if not isinstance(host_node, dict) or not fqdn:
        print_info_verbose(
            "[mssql-collector] no graph Computer node for linked-server source "
            f"{mark_sensitive(authorization.instance.host, 'ip')}; "
            "skipping linked-server edge upsert (node not in graph)"
        )
        return 0

    if graph is None:
        graph = load_attack_graph(shell, domain_clean)

    comp_record = {
        "name": str(host_node.get("name") or fqdn),
        "kind": ["Computer"],
        "objectId": host_node.get("objectid") or host_node.get("objectId"),
        "properties": host_node,
    }
    upsert_nodes(graph, [comp_record])
    from_id = _node_id(comp_record)
    if not from_id:
        return 0

    emitted = 0
    for linked_server in linked_servers:
        target_host = _normalize_linked_data_source(linked_server.data_source)
        if not target_host:
            continue
        to_id, created_foreign = _resolve_linked_server_target_node(graph, target_host)
        if not to_id or to_id == from_id:
            continue
        notes = _linked_server_edge_notes(authorization, fqdn, linked_server)
        notes["cross_domain_target_created"] = created_foreign
        edge = upsert_edge(
            graph,
            from_id=from_id,
            to_id=to_id,
            relation="MssqlLinkedServerLateral",
            edge_type="mssql_collector",
            status="discovered",
            notes=notes,
        )
        if edge:
            emitted += 1

    if save:
        save_attack_graph(shell, domain_clean, graph)

    if emitted:
        print_info_debug(
            "[mssql-collector] upserted linked-server edges for "
            f"{mark_sensitive(fqdn, 'host')}: "
            f"MssqlLinkedServerLateral={emitted}"
        )
    return emitted


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
            linked = upsert_mssql_linked_server_edges(
                shell, domain_clean, result, graph=graph, save=False
            )
            summary.sqlaccess_edges += access
            summary.sqladmin_edges += admin
            summary.linked_server_edges += linked
            if not (access or admin or linked):
                summary.negative_facts += 1
            else:
                any_edges = True
        if any_edges or summary.instances_connected:
            save_attack_graph(shell, domain_clean, graph)
    except Exception as exc:  # noqa: BLE001 — collection must never raise upward
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"[mssql-collector] collection failed (non-fatal): {exc}")

    print_info_verbose(
        "[mssql-collector] authorization collection complete for "
        f"{mark_sensitive(domain_clean, 'domain')}: "
        f"instances={summary.instances_discovered} "
        f"connected={summary.instances_connected} "
        f"SQLAccess={summary.sqlaccess_edges} SQLAdmin={summary.sqladmin_edges} "
        f"LinkedServer={summary.linked_server_edges} "
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
        print_exception(exception=exc)
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
    "compute_effective_bulk_admin_ids",
    "parse_mssql_spn_host",
    "discover_mssql_instances",
    "upsert_mssql_access_edges",
    "upsert_mssql_linked_server_edges",
    "collect_mssql_authorization",
    "collect_mssql_authorization_sync",
]
