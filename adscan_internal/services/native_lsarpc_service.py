"""Native async LSARPC helpers — RID cycling and SID translation.

Replaces the netexec ``--rid-brute`` subprocess. Builds SIDs as
``<domain_sid>-<rid>`` for a configurable RID range, batches them into
:func:`hLsarLookupSids` calls, and translates them to
``(domain, name, sid_type)`` tuples. The domain SID is fetched via SAMR's
``SamrLookupDomainInSamServer`` so the same SMB connection drives both
discovery and translation.

This service is a pure helper — no Rich UX, no workspace I/O. The caller
in :mod:`cli/smb.py` is responsible for rendering the table and persisting
the resulting username list to ``users.txt``.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Literal

from adscan_core import telemetry
from adscan_core.rich_output import print_info_debug
from adscan_core.rich_output import print_exception


LSARPCStatus = Literal["done", "denied", "error"]


# SID_NAME_USE values worth surfacing — matches Microsoft's documented enum.
# Only User/Group/Alias normally translate to "an account name"; Domain and
# WellKnownGroup are useful for sanity output but not user list candidates.
SID_TYPE_USER = 1
SID_TYPE_GROUP = 2
SID_TYPE_DOMAIN = 3
SID_TYPE_ALIAS = 4
SID_TYPE_WELLKNOWN_GROUP = 5
SID_TYPE_DELETED = 6
SID_TYPE_INVALID = 7
SID_TYPE_UNKNOWN = 8
SID_TYPE_COMPUTER = 9


@dataclass
class LSARPCRidEntry:
    """One translated SID->name entry from RID cycling."""

    sid: str
    rid: int
    name: str
    domain: str
    sid_type: int  # SID_NAME_USE: 1=user, 2=group, 4=alias, 9=computer, ...

    @property
    def is_user(self) -> bool:
        # Computers (SID_TYPE_COMPUTER) and Users (SID_TYPE_USER) both look
        # like accounts; netexec --rid-brute lumps them together as "User".
        return self.sid_type in (SID_TYPE_USER, SID_TYPE_COMPUTER)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve_smb_connection(machine_or_conn: Any) -> Any:
    conn = getattr(machine_or_conn, "connection", None)
    if conn is not None:
        return conn
    return machine_or_conn


def _is_access_denied(exc: Any) -> bool:
    return "ACCESS_DENIED" in str(exc).upper()


async def _resolve_domain_sid(connection: Any, domain_hint: str) -> tuple[str | None, str, str | None]:
    """Resolve the primary domain SID — LSARPC-first, SAMR fallback.

    nxc's --rid-brute uses LsarQueryInformationPolicy2(PolicyPrimaryDomainInformation)
    which works even when SAMR EnumerateDomains is blocked by RestrictAnonymousSAM.
    We mirror that approach and fall back to SAMR only if LSARPC also fails.

    Returns ``(domain_sid, domain_name, error)``.
    """
    # ── Primary: LSARPC LsarQueryInformationPolicy2 ───────────────────────
    # Works on DCs that block SAMR null/guest sessions (RestrictAnonymousSAM=1).
    try:
        from aiosmb.dcerpc.v5.interfaces.lsatmgr import LSADRPC

        lsadrpc, err = await LSADRPC.from_smbconnection(connection)
        if err is None:
            ph, err = await lsadrpc.open_policy2()
            if err is None:
                domain_sid, err = await lsadrpc.get_domain_sid(ph)
                if err is None and domain_sid:
                    domain_name = domain_hint.split(".")[0].upper() if domain_hint else ""
                    return domain_sid, domain_name, None
    except Exception as _lsa_exc:  # noqa: BLE001
        print_info_debug(f"[native-lsarpc] LSARPC domain SID lookup failed (trying SAMR): {_lsa_exc}")

    # ── Fallback: SAMR EnumerateDomains ──────────────────────────────────
    from aiosmb.dcerpc.v5.interfaces.samrmgr import SAMRRPC

    samrpc, err = await SAMRRPC.from_smbconnection(connection)
    if err is not None:
        return None, "", str(err)
    try:
        domain_names: list[str] = []
        async for name, derr in samrpc.list_domains():
            if derr is not None:
                continue
            if name and name.lower() != "builtin":
                domain_names.append(name)
        if not domain_names:
            return None, "", "No domain returned by SAMR EnumerateDomains"

        chosen: str | None = None
        if domain_hint:
            netbios_hint = domain_hint.split(".")[0].upper()
            for cand in domain_names:
                if cand.upper() == netbios_hint:
                    chosen = cand
                    break
        if chosen is None:
            chosen = domain_names[0]

        sid, err = await samrpc.get_domain_sid(chosen)
        if err is not None:
            return None, chosen, str(err)
        return sid, chosen, None
    finally:
        try:
            await samrpc.close()
        except Exception as exc:  # noqa: BLE001
            print_info_debug(f"[native-lsarpc] samrpc close (ignored): {exc}")


# ---------------------------------------------------------------------------
# Public entry — RID cycling
# ---------------------------------------------------------------------------


async def rid_cycle_via(
    machine_or_conn: Any,
    *,
    domain_hint: str = "",
    rid_start: int = 500,
    rid_end: int = 2000,
    batch_size: int = 64,
    max_concurrency: int = 1,  # DCERPC over a single SMB pipe is not safe to call concurrently
    timeout: int = 120,
) -> tuple[list[LSARPCRidEntry], LSARPCStatus, str | None]:
    """Translate RIDs ``rid_start..rid_end`` into account names via LSARPC.

    Workflow:

    1. SAMR pipe → fetch primary domain SID + NetBIOS name.
    2. LSARPC pipe → ``LsarOpenPolicy2``.
    3. Build SIDs ``<domain_sid>-<rid>`` and chunk them into ``batch_size``
       per :func:`hLsarLookupSids` request.
    4. Run up to ``max_concurrency`` batches in parallel.

    Returns ``(entries, status, error)``. Per-batch failures are recorded but
    do not abort the whole sweep — that mirrors netexec's behaviour.
    """
    from aiosmb.dcerpc.v5 import lsat
    from aiosmb.dcerpc.v5.interfaces.lsatmgr import LSADRPC

    if rid_end < rid_start:
        return [], "error", f"invalid RID range {rid_start}-{rid_end}"

    connection = _resolve_smb_connection(machine_or_conn)

    domain_sid, domain_name, err = await _resolve_domain_sid(connection, domain_hint)
    if err is not None or not domain_sid:
        return [], (
            "denied" if (err and _is_access_denied(err)) else "error"
        ), err or "Could not resolve domain SID"

    lsadrpc, err = await LSADRPC.from_smbconnection(connection)
    if err is not None:
        return [], (
            "denied" if _is_access_denied(err) else "error"
        ), str(err)

    try:
        ph, err = await lsadrpc.open_policy2()
        if err is not None:
            return [], (
                "denied" if _is_access_denied(err) else "error"
            ), str(err)

        # Build SID batches.
        rids = list(range(rid_start, rid_end + 1))
        sid_batches: list[list[tuple[int, str]]] = []
        for i in range(0, len(rids), batch_size):
            chunk = [(r, f"{domain_sid}-{r}") for r in rids[i : i + batch_size]]
            sid_batches.append(chunk)

        sem = asyncio.Semaphore(max_concurrency)
        results: list[LSARPCRidEntry] = []
        first_error_holder: list[str] = []
        denied_holder: list[bool] = []
        results_lock = asyncio.Lock()

        async def _do_batch(batch: list[tuple[int, str]]) -> None:
            sids = [s for _, s in batch]
            async with sem:
                try:
                    resp, err = await lsat.hLsarLookupSids(
                        lsadrpc.dce,
                        lsadrpc.policy_handles[ph],
                        sids,
                        lsat.LSAP_LOOKUP_LEVEL.enumItems.LsapLookupWksta,
                    )
                    if err is not None:
                        # STATUS_SOME_NOT_MAPPED (0x107) is the *expected*
                        # status when only a subset of the batch resolves —
                        # which is the common case at the boundaries of a
                        # RID sweep. The response packet is still attached
                        # to the exception via ``get_packet()``; recover it
                        # and continue parsing.
                        recovered = None
                        try:
                            recovered = err.get_packet()
                        except Exception:
                            recovered = None
                        if recovered is not None and (
                            "SOME_NOT_MAPPED" in str(err).upper()
                            or "0X107" in str(err).upper()
                        ):
                            resp = recovered
                            err = None
                        else:
                            # STATUS_NONE_MAPPED — no SIDs resolved at all;
                            # normal at the high end of the RID range.
                            if "NONE_MAPPED" in str(err).upper():
                                return
                            if _is_access_denied(err):
                                denied_holder.append(True)
                                return
                            if not first_error_holder:
                                first_error_holder.append(str(err))
                            return
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
                    print_exception(exception=exc)
                    if _is_access_denied(exc):
                        denied_holder.append(True)
                        return
                    if "NONE_MAPPED" in str(exc).upper():
                        return
                    if not first_error_holder:
                        first_error_holder.append(str(exc))
                    return

                # Parse the response.
                try:
                    domains = []
                    for entry in resp["ReferencedDomains"]["Domains"]:
                        domains.append(str(entry["Name"] or ""))

                    names = resp["TranslatedNames"]["Names"]
                    batch_entries: list[LSARPCRidEntry] = []
                    for (rid, sid), entry in zip(batch, names):
                        try:
                            sid_type = int(entry["Use"])
                        except (KeyError, TypeError, ValueError):
                            sid_type = SID_TYPE_UNKNOWN
                        if sid_type in (SID_TYPE_UNKNOWN, SID_TYPE_INVALID, SID_TYPE_DELETED):
                            continue
                        try:
                            di = int(entry["DomainIndex"])
                        except (KeyError, TypeError, ValueError):
                            di = -1
                        dom = domains[di] if 0 <= di < len(domains) else ""
                        nm = str(entry["Name"] or "").strip()
                        if not nm:
                            continue
                        batch_entries.append(
                            LSARPCRidEntry(
                                sid=sid,
                                rid=rid,
                                name=nm,
                                domain=dom,
                                sid_type=sid_type,
                            )
                        )
                    if batch_entries:
                        async with results_lock:
                            results.extend(batch_entries)
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
                    print_exception(exception=exc)
                    if not first_error_holder:
                        first_error_holder.append(f"parse error: {exc}")

        try:
            await asyncio.wait_for(
                asyncio.gather(
                    *[_do_batch(b) for b in sid_batches], return_exceptions=True
                ),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            return results, "error", f"RID cycling timed out after {timeout}s"

        # Sort by RID for deterministic output.
        results.sort(key=lambda e: e.rid)

        if denied_holder and not results:
            return results, "denied", "STATUS_ACCESS_DENIED on LSARPC LookupSids"
        return results, "done", first_error_holder[0] if first_error_holder else None
    finally:
        try:
            await lsadrpc.close()
        except Exception as exc:  # noqa: BLE001
            print_info_debug(f"[native-lsarpc] lsadrpc close (ignored): {exc}")
