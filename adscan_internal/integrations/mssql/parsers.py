"""Source-agnostic parsers for MSSQL command output.

What lives here:

* :func:`parse_whoami_priv_output` — parses ``whoami /priv`` output, no
  matter how it was executed (native ``xp_cmdshell``, future WinRM,
  whatever). The format is a Windows OS contract.
* :func:`check_seimpersonate_privilege` — boolean wrapper on top.
* :func:`parse_xp_cmdshell_enable_failure_reason` — distils a SQL
  RECONFIGURE error into a one-line user-facing reason. Used to
  classify why a sysadmin attempt to flip ``xp_cmdshell`` failed.
* :class:`WindowsPrivilege` — typed record returned by the parser.

Anything that parsed NetExec stdout markers (``Pwn3d!``, ``[+]
Executed command via linked server``, etc.) was retired alongside the
NetExec subprocess backend.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


_PRIVILEGE_LINE = re.compile(
    r"^(Se\w+Privilege)\s+(.*?)\s+(Enabled|Disabled|Enabled by Default)\s*$",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class WindowsPrivilege:
    """One Windows token privilege parsed out of ``whoami /priv``."""

    name: str
    description: str
    state: str  # "Enabled", "Disabled", or "Enabled by Default"


def parse_whoami_priv_output(output: str) -> list[WindowsPrivilege]:
    """Parse ``whoami /priv`` text into structured privilege entries.

    The shape of ``whoami /priv`` is a Windows OS contract — independent
    of how the command was executed. Lines that do not match the
    privilege grammar are silently skipped.
    """
    if not output:
        return []

    privileges: list[WindowsPrivilege] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = _PRIVILEGE_LINE.match(line)
        if match:
            privileges.append(
                WindowsPrivilege(
                    name=match.group(1),
                    description=match.group(2).strip(),
                    state=match.group(3),
                )
            )
    return privileges


def check_seimpersonate_privilege(output: str) -> bool:
    """Return whether ``SeImpersonatePrivilege`` is present and enabled."""
    if not output:
        return False

    for priv in parse_whoami_priv_output(output):
        if priv.name.lower() == "seimpersonateprivilege":
            return "Enabled" in priv.state

    # Fallback for localized or non-canonical output.
    return "SeImpersonatePrivilege" in output and (
        "Enabled" in output or "Habilitado" in output  # Spanish Windows
    )


def parse_xp_cmdshell_enable_failure_reason(output: str) -> str | None:
    """Distil a one-line user-facing reason from an ``xp_cmdshell`` enable error.

    The output may come from native impacket TDS (``ERROR(...): Line 1:
    You do not have permission ...``) or any future transport — only the
    SQL-side error text is inspected.
    """
    if not output:
        return None

    normalized = output.lower()
    if (
        "do not have permission" in normalized
        or "permission to run the reconfigure statement" in normalized
        or ("failed to enable xp_cmdshell" in normalized and "reconfigure" in normalized)
    ):
        return "insufficient SQL privileges to run RECONFIGURE and enable xp_cmdshell"

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if "Failed to enable xp_cmdshell:" in line:
            return line.split("Failed to enable xp_cmdshell:", 1)[1].strip() or None

    if "xp_cmdshell is disabled" in normalized:
        return "xp_cmdshell is currently disabled and could not be enabled"

    return None


# ---------------------------------------------------------------------------
# Linked-server discovery — row parsers (READ-ONLY)
# ---------------------------------------------------------------------------
#
# The linked-server queries (``queries.LINKED_SERVERS_DETAIL`` +
# ``queries.LINKED_SERVERS_LOGIN_MAP``) return structured TDS rowsets (a list of
# dicts), not free-form text — so "parsing" here is a robust row → dataclass
# mapping that tolerates the column-name variations different drivers / editions
# emit (``sp_helplinkedsrvlogin`` returns ``Linked Server`` / ``Local Login`` /
# ``Is Self Mapping`` / ``Remote Login``, spellings and casing vary). Everything
# here is READ-ONLY: it consumes the output of ``SELECT`` / ``EXEC sp_help*`` and
# never enables or configures anything.


def _row_value(row: dict[str, Any], *candidate_keys: str) -> Any:
    """Return the first matching cell from ``row`` by case/space-insensitive key.

    Different TDS drivers and SQL Server editions return the same logical column
    under slightly different spellings (``data_source`` vs ``Data Source``,
    ``Linked Server`` vs ``linked_server``). Normalise keys by l-casing and
    stripping spaces/underscores so a single parser handles every variant.
    """

    def _norm(key: str) -> str:
        return re.sub(r"[\s_]+", "", str(key or "").strip().lower())

    wanted = {_norm(k) for k in candidate_keys}
    for key, value in row.items():
        if _norm(key) in wanted:
            return value
    return None


def _row_bool(value: Any) -> bool:
    """Coerce a TDS scalar (int / str / bool) to bool. None / 0 / '0' → False."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "t"}
    return bool(value)


@dataclass(frozen=True, slots=True)
class LinkedServerLoginMapping:
    """One local↔remote login mapping for a linked server (sp_helplinkedsrvlogin)."""

    linked_server: str
    local_login: str  # login on the source instance ("" for a self / default mapping)
    remote_login: str  # login used against the remote (linked) server
    is_self_mapping: bool = False


@dataclass(frozen=True, slots=True)
class LinkedServer:
    """One configured linked server discovered on a source MSSQL instance."""

    name: str
    product: str = ""
    provider: str = ""
    data_source: str = ""  # the remote host the link points at (e.g. DC02.darkzero.ext)
    is_rpc_out_enabled: bool = False
    is_data_access_enabled: bool = False
    login_mappings: tuple[LinkedServerLoginMapping, ...] = field(default_factory=tuple)
    # Whether the login this link maps to is sysadmin ON THE REMOTE instance —
    # the signal that decides if xp_cmdshell RCE is reachable across the link.
    # Set by the collector's read-only remote role check; None = not probed /
    # unknown (the probe is best-effort and never blocks discovery).
    remote_is_sysadmin: bool | None = None
    # Whether ``xp_cmdshell`` is CURRENTLY enabled ON THE REMOTE instance — a
    # read-only observation of the target's ``run_value``. Set by the collector's
    # best-effort state probe (only when remote sysadmin is confirmed). None =
    # not probed / unknown (never blocks discovery, never implies a config change).
    xp_cmdshell_enabled: bool | None = None
    # Whether the mapped login holds ADMINISTER BULK OPERATIONS capability ON
    # THE REMOTE instance — directly, via ``bulkadmin``, or via sysadmin. Set by
    # the collector's read-only remote probe; orthogonal to ``remote_is_sysadmin``
    # (a bulkadmin/explicitly-granted login can have this without being
    # sysadmin). None = not probed / unknown (no capability claim).
    remote_bulk_admin: bool | None = None


def parse_linked_servers_detail(rows: list[dict[str, Any]] | None) -> list[LinkedServer]:
    """Parse ``queries.LINKED_SERVERS_DETAIL`` rows into :class:`LinkedServer` records.

    Rows without a linked-server name are skipped. No login mappings are attached
    here — call :func:`parse_linked_server_login_map` and merge with
    :func:`merge_linked_servers_with_login_map`.
    """
    servers: list[LinkedServer] = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        name = str(_row_value(row, "linked_server", "srvname", "name") or "").strip()
        if not name:
            continue
        servers.append(
            LinkedServer(
                name=name,
                product=str(_row_value(row, "product", "productname") or "").strip(),
                provider=str(_row_value(row, "provider", "providername") or "").strip(),
                data_source=str(_row_value(row, "data_source", "datasource") or "").strip(),
                is_rpc_out_enabled=_row_bool(_row_value(row, "rpc_out", "is_rpc_out_enabled", "rpcout")),
                is_data_access_enabled=_row_bool(
                    _row_value(row, "data_access", "is_data_access_enabled", "dataaccess")
                ),
            )
        )
    return servers


def parse_linked_server_login_map(
    rows: list[dict[str, Any]] | None,
) -> dict[str, list[LinkedServerLoginMapping]]:
    """Parse ``sp_helplinkedsrvlogin`` rows into ``{linked_server: [mapping, ...]}``.

    ``sp_helplinkedsrvlogin`` columns are ``Linked Server`` / ``Local Login`` /
    ``Is Self Mapping`` / ``Remote Login`` (spelling/casing varies by edition).
    Rows with no linked-server name are skipped.
    """
    out: dict[str, list[LinkedServerLoginMapping]] = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        linked_server = str(
            _row_value(row, "linked_server", "linkedserver", "srvname") or ""
        ).strip()
        if not linked_server:
            continue
        mapping = LinkedServerLoginMapping(
            linked_server=linked_server,
            local_login=str(_row_value(row, "local_login", "locallogin") or "").strip(),
            remote_login=str(_row_value(row, "remote_login", "remotelogin") or "").strip(),
            is_self_mapping=_row_bool(_row_value(row, "is_self_mapping", "isselfmapping")),
        )
        out.setdefault(linked_server, []).append(mapping)
    return out


def merge_linked_servers_with_login_map(
    servers: list[LinkedServer],
    login_map: dict[str, list[LinkedServerLoginMapping]],
) -> list[LinkedServer]:
    """Attach login mappings (by linked-server name, case-insensitive) to servers."""
    normalized = {str(k).strip().lower(): v for k, v in (login_map or {}).items()}
    merged: list[LinkedServer] = []
    for server in servers:
        mappings = normalized.get(server.name.strip().lower(), [])
        merged.append(
            LinkedServer(
                name=server.name,
                product=server.product,
                provider=server.provider,
                data_source=server.data_source,
                is_rpc_out_enabled=server.is_rpc_out_enabled,
                is_data_access_enabled=server.is_data_access_enabled,
                login_mappings=tuple(mappings),
                remote_is_sysadmin=server.remote_is_sysadmin,
                xp_cmdshell_enabled=server.xp_cmdshell_enabled,
                remote_bulk_admin=server.remote_bulk_admin,
            )
        )
    return merged


def parse_linked_server_sysadmin_probe(
    rows: list[dict[str, Any]] | None,
) -> bool | None:
    """Parse a ``linked_server_sysadmin_probe`` rowset into a tri-state result.

    Returns True/False when the ``is_sysadmin`` column is present, else None
    (empty rowset / probe could not resolve — treated as unknown, no RCE claim).
    """
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        val = _row_value(row, "is_sysadmin", "issysadmin")
        if val is None:
            continue
        return _row_bool(val)
    return None


def parse_linked_server_bulk_admin_probe(
    rows: list[dict[str, Any]] | None,
) -> bool | None:
    """Parse a ``linked_server_bulk_admin_probe`` rowset into a tri-state result.

    Returns True/False when the ``bulk_admin`` column is present, else None
    (empty rowset / probe could not resolve — treated as unknown, no capability
    claim).
    """
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        val = _row_value(row, "bulk_admin", "bulkadmin")
        if val is None:
            continue
        return _row_bool(val)
    return None


def parse_xp_cmdshell_state(
    rows: list[dict[str, Any]] | None,
) -> bool | None:
    """Parse an ``xp_cmdshell_state_at_link`` / :data:`queries.XP_CMDSHELL_STATE` rowset.

    The rowset carries one row per option (``xp_cmdshell`` and ``show advanced
    options``) with ``[option]`` / ``[config_value]`` / ``[run_value]`` columns.

    Returns True when the ``xp_cmdshell`` row reports it is currently enabled — its
    ``run_value`` (preferred; falls back to ``config_value``) is 1 — False when that
    value is 0, and None when the rowset does not resolve an ``xp_cmdshell`` row
    (empty / unknown — no "enabled" claim is made).
    """
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        option = str(_row_value(row, "option", "name") or "").strip().lower()
        if option != "xp_cmdshell":
            continue
        value = _row_value(row, "run_value", "value_in_use")
        if value is None:
            value = _row_value(row, "config_value", "value")
        if value is None:
            return None
        return _row_bool(value)
    return None


__all__ = [
    "WindowsPrivilege",
    "parse_whoami_priv_output",
    "check_seimpersonate_privilege",
    "parse_xp_cmdshell_enable_failure_reason",
    "LinkedServer",
    "LinkedServerLoginMapping",
    "parse_linked_servers_detail",
    "parse_linked_server_login_map",
    "merge_linked_servers_with_login_map",
    "parse_linked_server_sysadmin_probe",
    "parse_linked_server_bulk_admin_probe",
    "parse_xp_cmdshell_state",
]
