"""Native async SAMR helpers — reusable across unauth and auth flows.

Wraps aiosmb's :class:`SAMRRPC` with ADscan-specific result dataclasses and
error translation. Pure helpers — no Rich UX, no workspace I/O. Callers
(``unauth_enrichment_service``, ``cli/smb.py``) handle rendering and
persistence.

Two layering options are exposed:

* High-level entry points
  (:func:`enumerate_samr_users_via`, :func:`fetch_samr_user_details_via`)
  take a logged-in :class:`aiosmb.commons.connection.smbconnection.SMBConnection`
  (or anything with a ``.connection`` attribute exposing one — i.e. an
  ``SMBMachine``) and own the SAMR pipe lifecycle. Suitable for callers that
  just want users + descriptions and do not care about the underlying RPC.

* Lower-level helpers
  (:func:`list_users_in_domain_handle`, :func:`query_user_all_info`)
  operate on an existing :class:`SAMRRPC` and a domain handle. They are
  the building blocks the high-level entries are composed from, and are
  what :mod:`unauth_enrichment_service` reuses to keep its single-session
  guarantee.

Status semantics
----------------
Every public entry point returns a status code as the second tuple element:

* ``"done"`` — operation completed; the data list is authoritative.
* ``"denied"`` — the DC explicitly refused the operation
  (``STATUS_ACCESS_DENIED``, RestrictAnonymousSAM, etc.). The caller can
  surface this as a clean denial instead of a crash.
* ``"error"`` — anything else; the third element holds the error string.

No exception ever escapes the public entry points.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Literal

from adscan_core import telemetry
from adscan_core.rich_output import print_info_debug
from adscan_core.rich_output import print_exception


SAMRStatus = Literal["done", "denied", "error"]


@dataclass
class SAMRUser:
    """One user surfaced through SAMR."""

    username: str
    rid: int
    description: str = ""
    full_name: str = ""
    comment: str = ""
    user_flags: int = 0  # UserAccountControl


@dataclass
class SAMRGroup:
    """One group surfaced through SAMR."""

    name: str
    rid: int


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _samr_string(info: Any, key: str) -> str:
    """Best-effort extraction of a SAMR ``RPC_UNICODE_STRING`` value."""
    try:
        raw = info[key]
    except Exception:
        return ""
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw.strip("\x00").strip()
    try:
        if hasattr(raw, "__getitem__"):
            buf = raw.get("Buffer") if hasattr(raw, "get") else raw["Buffer"]
            if isinstance(buf, str):
                return buf.strip("\x00").strip()
            if isinstance(buf, (bytes, bytearray)):
                return (
                    bytes(buf)
                    .decode("utf-16-le", errors="ignore")
                    .strip("\x00")
                    .strip()
                )
    except Exception:
        pass
    try:
        return str(raw).strip("\x00").strip()
    except Exception:
        return ""


def _is_access_denied(err: Any) -> bool:
    return "ACCESS_DENIED" in str(err).upper()


def _resolve_smb_connection(machine_or_conn: Any) -> Any:
    """Accept either a raw SMBConnection or an SMBMachine and return the connection.

    aiosmb's :class:`SAMRRPC.from_smbconnection` expects the underlying
    connection object. :class:`SMBMachine` exposes it as ``.connection``.
    """
    conn = getattr(machine_or_conn, "connection", None)
    if conn is not None:
        return conn
    return machine_or_conn


# ---------------------------------------------------------------------------
# Lower-level helpers — operate on an existing SAMR RPC + domain handle
# ---------------------------------------------------------------------------


async def list_users_in_domain_handle(
    samrpc: Any,
    domain_handle: Any,
    *,
    max_users: int = 500,
) -> tuple[list[SAMRUser], SAMRStatus, str | None]:
    """List users from an already-opened SAMR domain handle.

    Returns ``(users, status, error)``. Stops after ``max_users`` to bound
    memory on large domains.
    """
    users: list[SAMRUser] = []
    try:
        async for uname, usid, uerr in samrpc.list_domain_users(domain_handle):
            if uerr is not None:
                if _is_access_denied(uerr):
                    return users, "denied", str(uerr)
                # Other iter errors stop further pages but keep what we have.
                return users, "error", str(uerr)
            if not uname or not usid:
                continue
            try:
                rid = int(str(usid).rsplit("-", 1)[-1])
            except (ValueError, IndexError):
                continue
            users.append(SAMRUser(username=str(uname), rid=rid))
            if len(users) >= max_users:
                break
        return users, "done", None
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        msg = str(exc)
        if _is_access_denied(exc):
            return users, "denied", msg
        return users, "error", msg


async def query_user_all_info(
    samrpc: Any,
    domain_handle: Any,
    user: SAMRUser,
) -> tuple[SAMRUser, SAMRStatus, str | None]:
    """Populate description/full_name/comment/user_flags on ``user`` via SAMR.

    Mutates and returns the same SAMRUser instance. ``status`` is ``"done"``
    on success, ``"denied"`` on STATUS_ACCESS_DENIED, ``"error"`` otherwise.
    """
    from aiosmb.dcerpc.v5 import samr

    uhandle = None
    try:
        uhandle, oerr = await samrpc.open_user(domain_handle, user.rid)
        if oerr is not None:
            return user, ("denied" if _is_access_denied(oerr) else "error"), str(oerr)
        resp, qerr = await samr.hSamrQueryInformationUser(
            samrpc.dce,
            uhandle,
            userInformationClass=samr.USER_INFORMATION_CLASS.UserAllInformation,
        )
        if qerr is not None:
            return user, ("denied" if _is_access_denied(qerr) else "error"), str(qerr)
        info = resp["Buffer"]["All"]
        user.description = _samr_string(info, "AdminComment")
        user.full_name = _samr_string(info, "FullName")
        user.comment = _samr_string(info, "UserComment")
        try:
            user.user_flags = int(info["UserAccountControl"])
        except (KeyError, TypeError, ValueError):
            user.user_flags = 0
        return user, "done", None
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return user, ("denied" if _is_access_denied(exc) else "error"), str(exc)
    finally:
        if uhandle is not None:
            try:
                await samrpc.close_handle(uhandle)
                samrpc.user_handles.pop(uhandle, None)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Higher-level entry points — open the SAMR pipe + a domain handle
# ---------------------------------------------------------------------------


async def _open_samrpc_and_pick_domain(
    connection: Any,
    domain_hint: str,
) -> tuple[Any, Any, SAMRStatus, str | None]:
    """Open a SAMR pipe and select a non-Builtin domain.

    Returns ``(samrpc, domain_handle, status, error)``. Caller is responsible
    for closing the samrpc when done. On any failure, ``samrpc`` may still be
    a valid object that needs closing — the helper closes it itself before
    returning a non-"done" status.
    """
    from aiosmb.dcerpc.v5.interfaces.samrmgr import SAMRRPC

    samrpc, err = await SAMRRPC.from_smbconnection(connection)
    if err is not None:
        msg = str(err)
        return None, None, ("denied" if _is_access_denied(err) else "error"), msg

    try:
        domain_names: list[str] = []
        async for name, derr in samrpc.list_domains():
            if derr is not None:
                continue
            if name and name.lower() != "builtin":
                domain_names.append(name)

        chosen: str | None = None
        if domain_hint:
            netbios_hint = domain_hint.split(".")[0].upper()
            for cand in domain_names:
                if cand.upper() == netbios_hint:
                    chosen = cand
                    break
        if chosen is None and domain_names:
            chosen = domain_names[0]
        if chosen is None:
            await _safe_close(samrpc)
            return (
                None,
                None,
                "denied",
                "No domain returned by SAMR EnumerateDomains",
            )

        domain_handle, derr = await samrpc.open_domain_by_name(chosen)
        if derr is not None:
            await _safe_close(samrpc)
            return (
                None,
                None,
                ("denied" if _is_access_denied(derr) else "error"),
                str(derr),
            )

        return samrpc, domain_handle, "done", None
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        await _safe_close(samrpc)
        msg = str(exc)
        return None, None, ("denied" if _is_access_denied(exc) else "error"), msg


async def _safe_close(samrpc: Any) -> None:
    try:
        await samrpc.close()
    except Exception as exc:  # noqa: BLE001
        print_info_debug(f"[native-samr] samrpc close error (ignored): {exc}")


async def enumerate_samr_users_via(
    machine_or_conn: Any,
    *,
    domain_hint: str = "",
    max_users: int = 500,
) -> tuple[list[SAMRUser], SAMRStatus, str | None]:
    """Open SAMR over an existing SMB connection/machine and list domain users.

    ``machine_or_conn`` may be an :class:`SMBMachine` (we pull ``.connection``)
    or a raw :class:`SMBConnection`. On hardened DCs that block SamrConnect to
    null sessions, returns ``status="denied"`` cleanly.
    """
    connection = _resolve_smb_connection(machine_or_conn)
    samrpc, domain_handle, status, error = await _open_samrpc_and_pick_domain(
        connection, domain_hint
    )
    if status != "done" or samrpc is None or domain_handle is None:
        return [], status, error

    try:
        users, list_status, list_err = await list_users_in_domain_handle(
            samrpc, domain_handle, max_users=max_users
        )
        return users, list_status, list_err
    finally:
        await _safe_close(samrpc)


async def fetch_samr_user_details_via(
    machine_or_conn: Any,
    *,
    users: list[SAMRUser],
    domain_hint: str = "",
    max_concurrency: int = 8,
    timeout: int = 60,
) -> tuple[list[SAMRUser], SAMRStatus, str | None]:
    """Hydrate descriptions/full_name/comment on each user via SAMR.

    Mutates the input ``users`` in place AND returns them. The same SMBMachine
    can be reused; the helper opens a fresh SAMR pipe internally so the caller
    does not have to manage RPC state.
    """
    if not users:
        return users, "done", None

    connection = _resolve_smb_connection(machine_or_conn)
    samrpc, domain_handle, status, error = await _open_samrpc_and_pick_domain(
        connection, domain_hint
    )
    if status != "done" or samrpc is None or domain_handle is None:
        return users, status, error

    sem = asyncio.Semaphore(max_concurrency)
    last_error_holder: list[str] = []
    denied_holder: list[bool] = []

    async def _one(u: SAMRUser) -> None:
        async with sem:
            _, st, err = await query_user_all_info(samrpc, domain_handle, u)
            if st == "denied":
                denied_holder.append(True)
            elif st == "error" and err and not last_error_holder:
                last_error_holder.append(err)

    try:
        try:
            await asyncio.wait_for(
                asyncio.gather(*[_one(u) for u in users], return_exceptions=True),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            return users, "error", f"SAMR description fetch timed out after {timeout}s"
    finally:
        await _safe_close(samrpc)

    if denied_holder and not any(
        (u.description or u.full_name or u.comment) for u in users
    ):
        return users, "denied", "STATUS_ACCESS_DENIED on SAMR user info"
    if last_error_holder:
        return users, "done", last_error_holder[0]
    return users, "done", None


# ---------------------------------------------------------------------------
# BUILTIN alias enumeration — local groups (Administrators, RDP, WinRM, …)
# ---------------------------------------------------------------------------


@dataclass
class SAMRAliasMember:
    """One member of a BUILTIN alias (typically a SID we'll resolve later)."""

    sid: str  # full string SID, e.g. "S-1-5-21-…-1103"
    rid: int | None  # parsed trailing RID; None if unparseable


def _parse_trailing_rid(sid_str: str) -> int | None:
    try:
        return int(str(sid_str).rsplit("-", 1)[-1])
    except (ValueError, IndexError, TypeError):
        return None


async def _list_alias_members_into(
    samrpc: Any,
    domain_handle: Any,
    rid: int,
) -> tuple[list[SAMRAliasMember], SAMRStatus, str | None]:
    """Open one alias under ``domain_handle`` and collect its members."""
    members: list[SAMRAliasMember] = []
    alias_handle, err = await samrpc.open_alias(domain_handle, rid)
    if err is not None:
        return (
            members,
            ("denied" if _is_access_denied(err) else "error"),
            str(err),
        )
    if alias_handle is None:
        return members, "error", "open_alias returned no handle"

    last_err: str | None = None
    try:
        async for sid, ierr in samrpc.list_alias_members(alias_handle):
            if ierr is not None:
                if _is_access_denied(ierr):
                    return members, "denied", str(ierr)
                last_err = str(ierr)
                break
            if not sid:
                continue
            sid_str = str(sid)
            members.append(
                SAMRAliasMember(sid=sid_str, rid=_parse_trailing_rid(sid_str))
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return (
            members,
            ("denied" if _is_access_denied(exc) else "error"),
            str(exc),
        )
    finally:
        try:
            await samrpc.close_handle(alias_handle)
            samrpc.alias_handles.pop(alias_handle, None)
        except Exception:
            pass

    return members, "done", last_err


async def enumerate_alias_members_via(
    machine_or_conn: Any,
    *,
    builtin_alias_rids: list[int],
) -> tuple[dict[int, list[SAMRAliasMember]], SAMRStatus, str | None]:
    """Open BUILTIN domain on ``machine_or_conn`` and enumerate the requested aliases.

    Returns ``({rid → [members]}, status, error_msg)``. Status is one of
    ``"done"`` / ``"denied"`` / ``"error"``. Failed aliases are recorded as
    empty lists in the returned dict — partial success is the common case.

    A single SAMR session is used for the whole batch.
    """
    from aiosmb.dcerpc.v5.interfaces.samrmgr import samrrpc_from_smb

    result: dict[int, list[SAMRAliasMember]] = {rid: [] for rid in builtin_alias_rids}
    if not builtin_alias_rids:
        return result, "done", None

    connection = _resolve_smb_connection(machine_or_conn)
    last_err: str | None = None
    any_denied = False
    any_done = False

    try:
        async with samrrpc_from_smb(connection) as samrpc:
            builtin_handle, err = await samrpc.openBuiltinDomain()
            if err is not None or builtin_handle is None:
                msg = (
                    str(err)
                    if err is not None
                    else "openBuiltinDomain returned no handle"
                )
                status: SAMRStatus = (
                    "denied"
                    if (err is not None and _is_access_denied(err))
                    else "error"
                )
                return result, status, msg

            for rid in builtin_alias_rids:
                members, st, err_msg = await _list_alias_members_into(
                    samrpc, builtin_handle, rid
                )
                result[rid] = members
                if st == "done":
                    any_done = True
                    if err_msg and not last_err:
                        last_err = err_msg
                elif st == "denied":
                    any_denied = True
                    if err_msg and not last_err:
                        last_err = err_msg
                    print_info_debug(f"[native-samr] alias rid={rid} denied: {err_msg}")
                else:
                    if err_msg and not last_err:
                        last_err = err_msg
                    print_info_debug(f"[native-samr] alias rid={rid} error: {err_msg}")
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return (
            result,
            ("denied" if _is_access_denied(exc) else "error"),
            str(exc),
        )

    if any_done:
        return result, "done", last_err
    if any_denied:
        return result, "denied", last_err
    return result, "error", last_err


# ---------------------------------------------------------------------------
# BUILTIN\Administrators RID enumeration — local-host admin discovery
# ---------------------------------------------------------------------------


_BUILTIN_ADMINISTRATORS_RID = 544  # S-1-5-32-544


async def get_local_admin_rids_via(
    machine_or_conn: Any,
    *,
    include_well_known: bool = True,
) -> tuple[set[int], SAMRStatus, str | None]:
    """Return RIDs that are members of BUILTIN\\Administrators on this host.

    Mirrors the historical behaviour of ``smb_transport.get_local_admin_rids``:
    opens the BUILTIN domain via ``get_domain_sid("Builtin")`` + ``open_domain``,
    opens the Administrators alias (RID 544), and returns the trailing RIDs of
    every member SID. RID 500 is always added when ``include_well_known=True``.

    Status is ``"done"`` on success, ``"denied"`` on STATUS_ACCESS_DENIED,
    ``"error"`` otherwise. On any failure, returns ``({500} if well-known else
    set(), status, error_msg)`` — never raises.
    """
    from aiosmb.dcerpc.v5.interfaces.samrmgr import samrrpc_from_smb

    admin_rids: set[int] = {500} if include_well_known else set()
    connection = _resolve_smb_connection(machine_or_conn)

    try:
        async with samrrpc_from_smb(connection) as samrpc:
            builtin_sid, err = await samrpc.get_domain_sid("Builtin")
            if err is not None or builtin_sid is None:
                msg = (
                    str(err)
                    if err is not None
                    else "get_domain_sid(Builtin) returned no SID"
                )
                status: SAMRStatus = (
                    "denied"
                    if (err is not None and _is_access_denied(err))
                    else "error"
                )
                return admin_rids, status, msg

            domain_handle, err = await samrpc.open_domain(builtin_sid)
            if err is not None or domain_handle is None:
                msg = (
                    str(err)
                    if err is not None
                    else "open_domain(Builtin) returned no handle"
                )
                status = (
                    "denied"
                    if (err is not None and _is_access_denied(err))
                    else "error"
                )
                return admin_rids, status, msg

            members, st, err_msg = await _list_alias_members_into(
                samrpc, domain_handle, _BUILTIN_ADMINISTRATORS_RID
            )
            for m in members:
                if m.rid is not None:
                    admin_rids.add(m.rid)
            return admin_rids, st, err_msg
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return (
            admin_rids,
            ("denied" if _is_access_denied(exc) else "error"),
            str(exc),
        )


# ---------------------------------------------------------------------------
# Per-user account flags — local machine domain
# ---------------------------------------------------------------------------


async def get_user_flags_for_rids_via(
    machine_or_conn: Any,
    rids: set[int],
    *,
    domain_hint: str = "",
    max_concurrency: int = 8,
) -> tuple[dict[int, int], SAMRStatus, str | None]:
    """Return ``{rid: UserAccountControl}`` for local accounts via SAMR.

    Opens the machine-local domain (not BUILTIN). RIDs that cannot be opened
    individually are silently skipped — partial results are still returned with
    ``status="done"``. Never raises.
    """
    if not rids:
        return {}, "done", None

    connection = _resolve_smb_connection(machine_or_conn)
    samrpc, domain_handle, status, error = await _open_samrpc_and_pick_domain(
        connection, domain_hint
    )
    if status != "done" or samrpc is None or domain_handle is None:
        return {}, status, error

    flags: dict[int, int] = {}
    sem = asyncio.Semaphore(max_concurrency)
    last_error_holder: list[str] = []

    async def _one(rid: int) -> None:
        async with sem:
            user = SAMRUser(username="", rid=rid)
            u, st, err = await query_user_all_info(samrpc, domain_handle, user)
            if st == "done":
                flags[rid] = u.user_flags
            elif err and not last_error_holder:
                last_error_holder.append(err)

    try:
        await asyncio.gather(*[_one(r) for r in rids], return_exceptions=True)
        return flags, "done", last_error_holder[0] if last_error_holder else None
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return flags, "error", str(exc)
    finally:
        await _safe_close(samrpc)
