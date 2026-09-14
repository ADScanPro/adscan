"""Native async share collector for ADscan (Sub-C).

For each Computer node in the CollectionResult, enumerates SMB shares and
their security descriptors.  Creates graph edges:

  ReadShare    (principal → Computer)  — generic or file read/list rights
  WriteShare   (principal → Computer)  — generic or file write/create rights
  FullControlShare (principal → Computer) — generic all or file all access

Three-tier fallback for share SDs (same logic as ShareHound, ported to aiosmb):
  1. SRVSVC NetrShareGetInfo level 502 (requires admin)
  2. Remote Registry: HKLM\\SYSTEM\\...\\LanmanServer\\Shares\\Security\\<name>
  3. Root folder NTFS SD (connect to share, query root dir SD)

Effective-access verification: the share-level ACL alone over-reports access.
Real access is share-ACL ∩ NTFS-folder-ACL. When BOTH the share SD and the
NTFS folder-root SD can be read, the collector captures both raw SDs on the
``_ShareInfo`` so the host-collector can intersect them per-principal and tag
the resulting edges ``ntfs_computed``. Otherwise edges keep the
``share_acl_only`` tier (a real lead, but NTFS-unverified). See
``share_ntfs_verification.py``.

SID → graph node mapping uses the already-collected LDAP node set plus the
well-known SIDs injected by well_known_sids.py — no additional LSA RPC needed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from adscan_internal.services.domain_posture import DomainPosture
    from adscan_internal.services.posture_sink import PostureSink

from adscan_internal import print_info_debug
from adscan_internal.services.smb_exclusion_policy import (
    is_globally_excluded_smb_share,
)

# ---------------------------------------------------------------------------
# Share SD access mask constants
# ---------------------------------------------------------------------------

_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_GENERIC_EXECUTE = 0x20000000
_GENERIC_ALL = 0x10000000
_READ_CONTROL = 0x00020000
_FILE_READ_DATA = 0x00000001
_FILE_WRITE_DATA = 0x00000002
_FILE_APPEND_DATA = 0x00000004
_FILE_READ_EA = 0x00000008
_FILE_WRITE_EA = 0x00000010
_FILE_EXECUTE = 0x00000020
_FILE_READ_ATTRIBUTES = 0x00000080
_FILE_WRITE_ATTRIBUTES = 0x00000100
_FILE_ALL_ACCESS = 0x001F01FF

_FILE_READ_BITS = (
    _READ_CONTROL | _FILE_READ_DATA | _FILE_READ_EA | _FILE_READ_ATTRIBUTES
)
_FILE_WRITE_BITS = (
    _FILE_WRITE_DATA | _FILE_APPEND_DATA | _FILE_WRITE_EA | _FILE_WRITE_ATTRIBUTES
)

# ACCESS_ALLOWED ACE type constant
_ACCESS_ALLOWED_ACE_TYPE = 0x00


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass
class ShareCollectorConfig:
    """Credentials + options for the share collection phase."""

    domain: str
    auth_domain: str
    dc_address: str
    username: str | None = None
    password: str | None = None
    nt_hash: str | None = None
    aes_key: str | None = None
    ccache_path: str | None = None
    use_kerberos: bool = False
    kdc_ip: str | None = None
    port: int = 445
    per_host_timeout: int = 20
    concurrency: int = 15
    skip_admin_shares: bool = True
    posture_sink: Optional["PostureSink"] = None
    posture_snapshot: Optional["DomainPosture"] = None


# ---------------------------------------------------------------------------
# SD parsing helper
# ---------------------------------------------------------------------------


def parse_sd_aces(sd_bytes: bytes) -> list[tuple[str, int]]:
    """Parse a raw security descriptor and return (sid_str, mask) for ALLOW ACEs.

    Compatible with the impacket version in the ADscan runtime which exposes
    DACL ACEs via ``dacl.aces`` (list of ACE objects) rather than
    ``dacl["Data"]`` (older impacket API).
    """
    try:
        from impacket.ldap import ldaptypes

        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd.fromString(sd_bytes)
        dacl = sd["Dacl"]
        if dacl is None:
            return []

        # Runtime impacket: dacl.aces is a list of ACE objects
        ace_list = getattr(dacl, "aces", None)
        if ace_list is None:
            # Older impacket fallback
            ace_list = dacl.get("Data") or []

        result = []
        for ace in ace_list:
            type_name = str(
                ace.fields.get("TypeName") or ace.fields.get("AceType") or ""
            )
            if "ALLOWED" not in type_name.upper() and type_name != "0":
                # Skip non-allow ACEs; also accept raw type 0 (ACCESS_ALLOWED)
                if ace.fields.get("AceType", -1) != _ACCESS_ALLOWED_ACE_TYPE:
                    continue

            try:
                sid_str = ace["Ace"]["Sid"].formatCanonical()
                mask_val = int(ace["Ace"]["Mask"]["Mask"])
            except (KeyError, TypeError, AttributeError):
                continue

            if sid_str and mask_val:
                result.append((sid_str, mask_val))
        return result
    except Exception as exc:
        print_info_debug(f"[share-collector] SD parse error: {exc}")
        return []


def mask_to_edge_kinds(mask: int) -> list[str]:
    """Map a share ACE mask to ADscan edge relation names."""
    kinds = []
    if mask & _GENERIC_ALL or (mask & _FILE_ALL_ACCESS) == _FILE_ALL_ACCESS:
        kinds.append("FullControlShare")
    else:
        if mask & (_GENERIC_READ | _FILE_READ_BITS):
            kinds.append("ReadShare")
        if mask & (
            _GENERIC_WRITE | _GENERIC_EXECUTE | _FILE_WRITE_BITS | _FILE_EXECUTE
        ):
            kinds.append("WriteShare")
    return kinds


# ---------------------------------------------------------------------------
# Share SD retrieval — three-tier fallback
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Per-host share collection — single SRVSVC session
# ---------------------------------------------------------------------------


@dataclass
class _ShareInfo:
    name: str
    share_type: int
    comment: str
    hidden: bool
    aces: list[tuple[str, int]] = field(default_factory=list)
    sd_source: str = "unavailable"
    # Raw security descriptors retained for NTFS-aware effective-access
    # verification (share ACL ∩ NTFS folder-root ACL). ``aces`` is derived
    # from whichever SD was used as the primary lead; these carry the raw
    # bytes for both layers so the host-collector can intersect them.
    share_sd_bytes: bytes = b""  # share-level SD (SRVSVC 502 or SMB2 share root)
    ntfs_sd_bytes: bytes = b""  # NTFS folder-root SD (SMB2 directory QueryInfo)
    # Scanning-identity effective-access mask at the share root, from an MxAc
    # (MAXIMUM_ALLOWED) probe. Populated ONLY when the NTFS root SD was
    # unreadable (the share_acl_only fallback) so the classifier can tag the
    # broad-group edge ``self_mxac`` with the real effective mask instead of the
    # over-reported raw share grant. ``None`` when not probed / no access.
    self_effective_mask: int | None = None
    # NTFS-verification tier + the REAL NTFS read-set, finalized by
    # ``_finalize_share_verification`` once every collection stage above has
    # run. Mirrors ``share_ntfs_verification.VERIFICATION_*`` (kept as plain
    # strings here to avoid a module-level import cycle — see that module for
    # the canonical constants). ``ntfs_computed`` requires BOTH the share SD
    # and the NTFS folder-root SD to have been readable (READ_CONTROL held on
    # both) — never left as ``share_acl_only`` when the NTFS SD is obtainable.
    graph_verification: str = "share_acl_only"
    # (sid, mask) ALLOW-ACE pairs parsed from the REAL NTFS folder-root SD —
    # populated only when ``ntfs_sd_bytes`` was actually read. This is the
    # verified read-set a caller should prefer over the raw share-level
    # ``aces`` when reporting "who can access this share", since the NTFS
    # layer can independently narrow (or deny) a share-level grant.
    ntfs_read_set: list[tuple[str, int]] = field(default_factory=list)


def _sd_object_to_bytes(sd_object: object) -> bytes:
    """Serialize a winacl security descriptor object returned by aiosmb."""
    if sd_object is None:
        return b""
    if isinstance(sd_object, bytes):
        return sd_object
    to_bytes = getattr(sd_object, "to_bytes", None)
    if callable(to_bytes):
        try:
            return bytes(to_bytes())
        except Exception:
            return b""
    return b""


def _build_unc_path(host: str, share: str, path: str = "") -> str:
    """Build a UNC path for aiosmb share-root operations."""
    clean_path = str(path or "").strip("\\")
    if clean_path:
        return f"\\\\{host}\\{share}\\{clean_path}"
    return f"\\\\{host}\\{share}"


async def _read_share_level_sd(
    machine: Any,
    target_host: str,
    share_name: str,
) -> bytes:
    """Read the SHARE-level security descriptor (SMB2 share-root QueryInfo)."""
    from aiosmb.commons.interfaces.share import SMBShare

    share = SMBShare(
        name=share_name,
        fullpath=_build_unc_path(target_host, share_name),
    )
    sd_object, err = await share.get_security_descriptor(machine.connection)
    if err is not None:
        raise err
    return _sd_object_to_bytes(sd_object)


async def _read_ntfs_root_sd(
    machine: Any,
    target_host: str,
    share_name: str,
) -> bytes:
    """Read the NTFS folder-root security descriptor (SMB2 directory QueryInfo)."""
    from aiosmb.commons.interfaces.directory import SMBDirectory

    last_error: Exception | None = None
    for candidate_path in ("", "\\"):
        try:
            directory = SMBDirectory.from_uncpath(
                _build_unc_path(target_host, share_name, candidate_path)
            )
            sd_object, err = await directory.get_security_descriptor(machine.connection)
            if err is not None:
                raise err
            sd_bytes = _sd_object_to_bytes(sd_object)
            if sd_bytes:
                return sd_bytes
        except Exception as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    return b""


async def read_share_root_sd(
    machine: Any,
    target_host: str,
    share_name: str,
) -> tuple[bytes, str]:
    """Read one share/root security descriptor using SMB2 QueryInfo fallbacks.

    Returns the first SD that could be read (share-level preferred, NTFS
    folder-root as fallback) together with a ``sd_source`` label. Kept for
    back-compat with callers that only need a single primary SD;
    :func:`read_share_and_ntfs_sds` returns both layers for verification.
    """
    last_error: Exception | None = None
    try:
        sd_bytes = await _read_share_level_sd(machine, target_host, share_name)
        if sd_bytes:
            return sd_bytes, "smb2_share_root"
    except Exception as exc:
        last_error = exc

    try:
        sd_bytes = await _read_ntfs_root_sd(machine, target_host, share_name)
        if sd_bytes:
            return sd_bytes, "smb2_path_root"
    except Exception as exc:
        last_error = exc

    if last_error is not None:
        raise last_error
    return b"", "unavailable"


async def read_share_and_ntfs_sds(
    machine: Any,
    target_host: str,
    share_name: str,
) -> tuple[bytes, bytes]:
    """Read BOTH the share-level SD and the NTFS folder-root SD.

    Either may be empty when its QueryInfo fails — the caller decides the
    verification tier from which SDs are present. Failures on one layer never
    suppress the other (a low-priv principal may read the share SD but not the
    NTFS root, or vice versa).

    Returns:
        ``(share_sd_bytes, ntfs_sd_bytes)``. Each is ``b""`` when unreadable.
    """
    share_sd = b""
    ntfs_sd = b""
    try:
        share_sd = await _read_share_level_sd(machine, target_host, share_name)
    except Exception as exc:
        print_info_debug(
            "[share-collector] share-level SD read failed: "
            f"host={target_host} share={share_name} error={exc}"
        )
    try:
        ntfs_sd = await _read_ntfs_root_sd(machine, target_host, share_name)
    except Exception as exc:
        print_info_debug(
            "[share-collector] NTFS root SD read failed: "
            f"host={target_host} share={share_name} error={exc}"
        )
    return share_sd, ntfs_sd


async def fill_missing_share_sds(
    machine: Any,
    target_host: str,
    shares: list[_ShareInfo],
) -> dict[str, int]:
    """Populate missing share ACEs through low-privileged SMB2 root SD reads.

    Reads both the share-level and NTFS folder-root SDs so downstream
    effective-access verification can intersect them. The primary ``aces`` are
    derived from the share-level SD when available, otherwise the NTFS root SD.
    """
    stats = {
        "attempted": 0,
        "succeeded": 0,
        "failed": 0,
        "aces": 0,
        "ntfs_sd": 0,
    }
    for share in shares:
        if share.aces:
            continue
        stats["attempted"] += 1
        try:
            share_sd_bytes, ntfs_sd_bytes = await read_share_and_ntfs_sds(
                machine, target_host, share.name
            )
        except Exception as exc:
            stats["failed"] += 1
            print_info_debug(
                "[share-collector] SMB2 root SD fallback failed: "
                f"host={target_host} share={share.name} error={exc}"
            )
            continue

        if share_sd_bytes:
            share.share_sd_bytes = share_sd_bytes
        if ntfs_sd_bytes:
            share.ntfs_sd_bytes = ntfs_sd_bytes
            stats["ntfs_sd"] += 1

        # Primary lead: share SD preferred (it is the share-access boundary);
        # NTFS root SD as fallback so a share with no readable share SD still
        # surfaces a lead.
        primary_bytes = share_sd_bytes or ntfs_sd_bytes
        sd_source = "smb2_share_root" if share_sd_bytes else "smb2_path_root"
        aces = parse_sd_aces(primary_bytes) if primary_bytes else []
        if not aces:
            stats["failed"] += 1
            continue
        share.aces = aces
        share.sd_source = sd_source
        stats["succeeded"] += 1
        stats["aces"] += len(aces)
    return stats


async def collect_shares_for_host(
    machine: Any,
    config: ShareCollectorConfig,
    target_host: str,
) -> tuple[list[_ShareInfo], str | None]:
    """Enumerate shares and their SDs for a single connected host.

    Strategy: one SRVSVC session, try level 502 first (shares + SDs in one
    round-trip, admin only) then fall back to level 1 (names only, always
    works).  This avoids opening a second RPC pipe over the same connection.

    Returns ``(shares, error_reason)``. ``error_reason`` is ``None`` on success
    and the failure string otherwise (e.g. a connection abort) — surfaced so the
    caller's per-stage outcome telemetry can tell a permission denial from a
    connection drop instead of silently counting a swallowed failure as "ok".
    """
    from aiosmb.dcerpc.v5.interfaces.srvsmgr import srvsrpc_from_smb
    from aiosmb.dcerpc.v5 import srvs

    shares: list[_ShareInfo] = []
    error_reason: str | None = None

    try:
        async with srvsrpc_from_smb(machine.connection) as rpc:
            # ── Try level 502 (admin) — shares + SDs in one call ─────────
            got_502 = False
            try:
                resume = 0
                while True:
                    resp, err = await srvs.hNetrShareEnum(
                        rpc.dce, 502, resumeHandle=resume
                    )
                    if err is not None:
                        # Check if it's MORE_ENTRIES (0x00000105) — keep going
                        ec = getattr(err, "error_code", None)
                        if ec == 0x00000105:
                            resp = err.get_packet()
                        else:
                            raise err

                    container = resp["InfoStruct"]["ShareInfo"]["Level502"]["Buffer"]
                    for entry in container:
                        name = str(entry["shi502_netname"]).rstrip("\x00")
                        if not name:
                            continue
                        if config.skip_admin_shares and is_globally_excluded_smb_share(
                            name
                        ):
                            continue
                        stype = int(entry["shi502_type"] or 0)
                        remark = str(entry["shi502_remark"] or "").rstrip("\x00")
                        sd_raw = entry["shi502_security_descriptor"]
                        raw_bytes = b"".join(sd_raw) if sd_raw else b""
                        aces = parse_sd_aces(raw_bytes) if raw_bytes else []
                        shares.append(
                            _ShareInfo(
                                name=name,
                                share_type=stype,
                                comment=remark,
                                hidden=name.endswith("$"),
                                aces=aces,
                                sd_source="srvsvc502" if raw_bytes else "unavailable",
                                # Level 502 returns the SHARE-level SD.
                                share_sd_bytes=raw_bytes,
                            )
                        )

                    resume = resp["ResumeHandle"]
                    if resp["ErrorCode"] != 0x00000105:
                        break

                got_502 = True
            except Exception as exc:
                print_info_debug(
                    f"[share-collector] level 502 failed, falling back to level 1: {exc}"
                )

            # ── Fallback: level 1 (names only, no SDs) ───────────────────
            if not got_502:
                async for name, stype, remark, err in rpc.list_shares(level=1):
                    if err is not None:
                        break
                    if name is None:
                        continue
                    if config.skip_admin_shares and is_globally_excluded_smb_share(
                        name
                    ):
                        continue
                    shares.append(
                        _ShareInfo(
                            name=name,
                            share_type=int(stype or 0),
                            comment=str(remark or ""),
                            hidden=name.endswith("$"),
                        )
                    )

    except Exception as exc:
        error_reason = f"{type(exc).__name__}: {exc}"
        print_info_debug(f"[share-collector] list_shares failed: {exc}")

    # Always attempt the NTFS folder-root SD read so effective-access
    # verification can intersect share ∩ NTFS — even when the share-level ACL
    # already came back from level 502. A share whose ``ntfs_sd_bytes`` is
    # still empty stays ``share_acl_only``.
    await _enrich_ntfs_root_sds(machine, target_host, shares)

    if shares and any(not share.aces for share in shares):
        stats = await fill_missing_share_sds(machine, target_host, shares)
        if stats["attempted"]:
            print_info_debug(
                "[share-collector] SMB2 root SD fallback: "
                f"host={target_host} attempted={stats['attempted']} "
                f"succeeded={stats['succeeded']} failed={stats['failed']} "
                f"aces={stats['aces']} ntfs_sd={stats['ntfs_sd']}"
            )

    # MxAc fallback (MAXIMUM_ALLOWED): for shares whose NTFS root SD we could
    # NOT read — the cases that otherwise stay share_acl_only and over-report a
    # broad-group grant (e.g. Authenticated Users: Full Control on NETLOGON when
    # NTFS actually restricts to Read) — ask the server for OUR effective access
    # at the share root. Cheap: one MxAc open, root-only, reusing the live
    # connection; runs only on the fallback shares. The mask is metadata; the
    # classifier applies it to broad-group edges (which the scanning identity
    # belongs to) as the self_mxac tier. Best-effort — never breaks collection.
    # Fire MxAc for any share that grants a BROAD authentication group
    # (Authenticated Users / Everyone / Users / Domain Users). Those edges are
    # the over-reported false positives: the broad SIDs are OS-computed and have
    # no confident group-closure, so their edges stay share_acl_only forever even
    # when BOTH SDs are readable — so a "missing SD" trigger misses them (the bug
    # this replaces). The scanning identity provably belongs to these groups, so
    # its MxAc self-effective access is the right correction.
    from adscan_internal.services.collector.share_ntfs_verification import (
        is_broad_auth_sid,
    )

    needs_mxac = [
        s for s in shares if any(is_broad_auth_sid(sid) for sid, _ in s.aces)
    ]
    if needs_mxac:
        from adscan_internal.services.smb_effective_access_service import (
            query_effective_root_access_on_machine,
        )

        # winacl FILE access bits (mirrors share_ntfs_verification constants).
        _READ, _WRITE, _FULL = 0x00000001, 0x00000002, 0x001F01FF
        for share in needs_mxac:
            try:
                ea = await query_effective_root_access_on_machine(
                    machine=machine, share=share.name, host=target_host
                )
            except Exception as exc:  # noqa: BLE001 — best-effort metadata probe
                print_info_debug(f"[share-collector] MxAc probe failed: {exc}")
                continue
            if ea.succeeded and ea.has_access:
                mask = 0
                if ea.can_read:
                    mask |= _READ
                if ea.can_write:
                    mask |= _WRITE
                if ea.can_write_dac or ea.can_write_owner:
                    mask |= _FULL
                share.self_effective_mask = mask

    _finalize_share_verification(shares)

    return shares, error_reason


def _finalize_share_verification(shares: list[_ShareInfo]) -> None:
    """Tag each share's NTFS-verification tier and populate its REAL read-set.

    Run once, after every collection stage above (SRVSVC 502, the SMB2 root
    SD fallback, the NTFS enrich pass, and the MxAc probe) has had a chance to
    populate ``share_sd_bytes`` / ``ntfs_sd_bytes`` — regardless of WHICH
    stage supplied the bytes.

    A share-level ACL grant alone over-reports access: the file-system (NTFS)
    folder-root DACL can independently DENY the same principal (the Cicada
    DEV/NETLOGON/SYSVOL guest-session over-report — BUG B). Whenever BOTH the
    share-level SD and the NTFS folder-root SD were actually obtainable (i.e.
    READ_CONTROL was held on both), the share is tagged ``ntfs_computed`` and
    its ``ntfs_read_set`` is populated from the REAL NTFS ACEs (BUG A) —
    never left tagged ``share_acl_only`` (an honest but unverified lead) when
    the NTFS SD is right there to read. When either SD is unreadable, the
    share stays ``share_acl_only`` and ``ntfs_read_set`` stays empty — the raw
    ``aces``/``share_sd_bytes`` are untouched either way, so every existing
    consumer of the raw share-ACL edge is unaffected.
    """
    for share in shares:
        if share.share_sd_bytes and share.ntfs_sd_bytes:
            share.graph_verification = "ntfs_computed"
            share.ntfs_read_set = parse_sd_aces(share.ntfs_sd_bytes)
        else:
            share.graph_verification = "share_acl_only"
            share.ntfs_read_set = []


async def _enrich_ntfs_root_sds(
    machine: Any,
    target_host: str,
    shares: list[_ShareInfo],
) -> None:
    """Read the NTFS folder-root SD for shares that have a share-level ACL.

    Only attempted for shares that already carry ``aces`` (a real share-access
    lead) and no NTFS SD yet — this is the second half of the share ∩ NTFS
    intersection. Best-effort: a failure leaves ``ntfs_sd_bytes`` empty and the
    edge stays ``share_acl_only``.
    """
    for share in shares:
        if share.ntfs_sd_bytes or not share.aces:
            continue
        try:
            ntfs_sd = await _read_ntfs_root_sd(machine, target_host, share.name)
        except Exception as exc:
            print_info_debug(
                "[share-collector] NTFS root SD enrich failed: "
                f"host={target_host} share={share.name} error={exc}"
            )
            continue
        if ntfs_sd:
            share.ntfs_sd_bytes = ntfs_sd
