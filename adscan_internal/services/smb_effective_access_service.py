"""Non-intrusive effective SMB access via the SMB2 MxAc create context.

ADscan's share enumeration historically reported *share-level* access — the
value the server returns in ``tree_connect`` (``maximal_access``), which
reflects only the share ACL. On a hardened file server the share ACL frequently
grants Change/Write while the underlying NTFS DACL denies it, so share-level
access over-reports WRITE. The empirically correct value (what a real write
would actually do) is the *effective* access: ``share permissions ∩ NTFS DACL``
evaluated against the caller's full token.

This module computes that value WITHOUT writing a probe file, by attaching an
``SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST`` ("MxAc") create context to a
read-only open of the share root. The server computes the intersection
server-side and returns it in the matching response create context. This is
authoritative (the server knows the caller's full token and the NTFS DACL) and
needs no client-side SID enumeration.

Entry points:

* :func:`query_effective_root_access` — opens its OWN connection from
  credential arguments. Use for standalone, one-shot checks (e.g. the
  WriteLogonScript precheck, the ``probe_effective_share_access`` script).
* :func:`query_effective_root_access_on_machine` — reuses an EXISTING
  connected ``SMBMachine``. Use inside an enumeration loop that already holds
  a live connection, to avoid one TCP+auth round-trip per share.
* :func:`enumerate_writable_directories` — granular per-FOLDER variant: walks
  the directories within a share (bounded depth + folder cap) and MxAc-verifies
  effective WRITE on each, returning the relative paths (``""`` == root) where
  the caller's token can write. This is what the NTLM share-drop targeting uses
  so a bait can be planted in the sub-folder users actually browse (e.g.
  ``transfer``), not just the share root.

The MxAc primitive (``SMBDirectory.query_maximal_access``) is itself
path-agnostic — it computes effective access for whatever directory the
``SMBDirectory`` points at. The root-access helpers point it at the share root;
:func:`enumerate_writable_directories` points it at each sub-directory in turn.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from adscan_internal import (
    print_info_debug,
    telemetry,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.smb_transport import (
    SMBConfig,
    SMBTransportError,
    run_smb_operation,
    smb_machine_for,
)

#: Default recursion depth for :func:`enumerate_writable_directories`. Depth 1
#: means "share root + its direct sub-directories" — the empirically useful
#: scope (a bait dropped one level down, in the folder users actually browse,
#: e.g. ``transfer``). Configurable per call; kept small by default for OPSEC
#: and scale (a deep recursive MxAc sweep on an enterprise file server is both
#: slow and noisy — see adscan-ad-constraints § 10 "Share enumeration a escala").
DEFAULT_WRITABLE_DIR_DEPTH = 1

#: Default cap on the number of directories MxAc-probed in one enumeration. A
#: file server can hold tens of thousands of folders; without a cap a single
#: enumeration would issue an unbounded number of MxAc opens (FD pressure,
#: SIEM/DLP noise, runtime). When the cap is hit the walk STOPS and records what
#: was skipped — never a silent truncation.
DEFAULT_WRITABLE_DIR_MAX_FOLDERS = 50


@dataclass(frozen=True, slots=True)
class EffectiveAccess:
    """Effective (share ∩ NTFS) access for one SMB share root.

    ``succeeded`` distinguishes a definitive answer from a probe failure.
    When ``succeeded`` is True and ``has_access`` is False, the server denied
    the open — the caller has no effective access at all (this is a real
    observation, not an error). When ``succeeded`` is False, the probe could
    not complete (transport error, MxAc unsupported, parse failure) and the
    access flags are meaningless — callers should fall back to the share-level
    value rather than trust a zeroed mask.
    """

    succeeded: bool
    has_access: bool
    share_name: str
    target_host: str
    raw_mask: int = 0
    can_read: bool = False
    can_write: bool = False
    can_write_dac: bool = False
    can_write_owner: bool = False
    can_delete: bool = False
    can_read_control: bool = False
    auth_mode: str = ""
    error_message: Optional[str] = None


@dataclass(frozen=True, slots=True)
class WritableDirectory:
    """One directory within a share confirmed (by MxAc) to grant effective WRITE.

    ``directory_path`` is the share-relative path (``""`` for the share root,
    ``"transfer"`` for a direct sub-folder, ``"transfer\\incoming"`` deeper). It
    is the exact value :func:`run_multi_share_capture`'s ``DropTarget`` expects.
    """

    share: str
    directory_path: str
    depth: int


@dataclass(slots=True)
class WritableDirEnumeration:
    """Outcome of a granular per-folder writable-directory enumeration.

    ``writable`` is the ordered list of directories (root first) where the
    current token has effective WRITE. ``dirs_probed`` / ``dirs_listed`` give
    the OPSEC/scale footprint. ``hit_cap`` is True when the folder cap stopped
    the walk before it had visited every directory — when True, ``skipped``
    names the directories that were discovered but NOT probed, so the operator
    sees an explicit "truncated here" signal rather than a silent miss.
    """

    share: str
    target_host: str
    succeeded: bool
    writable: list[WritableDirectory] = field(default_factory=list)
    dirs_listed: int = 0
    dirs_probed: int = 0
    hit_cap: bool = False
    skipped: list[str] = field(default_factory=list)
    auth_mode: str = ""
    error_message: Optional[str] = None

    @property
    def writable_paths(self) -> list[str]:
        """Return just the share-relative paths (``""`` == root), root first."""
        return [d.directory_path for d in self.writable]


def _translate_mask(mask: Any) -> dict[str, Any]:
    """Translate an aiosmb ``FileAccessMask`` into READ/WRITE/etc. booleans.

    READ is true when the token can read data OR list a directory (the two
    share the same bit value, ``0x1``). WRITE follows the convention nxc uses:
    the ability to write data / add a file / append. WRITE_DAC, WRITE_OWNER,
    DELETE, and READ_CONTROL are surfaced separately so downstream consumers
    (ACL-abuse paths) can reason about them.
    """
    from aiosmb.wintypes.access_mask import FileAccessMask

    fam = FileAccessMask(int(mask))
    raw = int(fam)

    can_read = bool(
        fam
        & (
            FileAccessMask.FILE_READ_DATA  # 0x1 == FILE_LIST_DIRECTORY
            | FileAccessMask.GENERIC_READ
            | FileAccessMask.GENERIC_ALL
        )
    )
    can_write = bool(
        fam
        & (
            FileAccessMask.FILE_WRITE_DATA  # 0x2 == FILE_ADD_FILE
            | FileAccessMask.FILE_APPEND_DATA  # 0x4 == FILE_ADD_SUBDIRECTORY
            | FileAccessMask.GENERIC_WRITE
            | FileAccessMask.GENERIC_ALL
        )
    )
    can_write_dac = bool(fam & (FileAccessMask.WRITE_DAC | FileAccessMask.GENERIC_ALL))
    can_write_owner = bool(
        fam & (FileAccessMask.WRITE_OWNER | FileAccessMask.GENERIC_ALL)
    )
    can_delete = bool(fam & (FileAccessMask.DELETE | FileAccessMask.GENERIC_ALL))
    can_read_control = bool(
        fam & (FileAccessMask.READ_CONTROL | FileAccessMask.GENERIC_ALL)
    )

    return {
        "raw_mask": raw,
        "can_read": can_read,
        "can_write": can_write,
        "can_write_dac": can_write_dac,
        "can_write_owner": can_write_owner,
        "can_delete": can_delete,
        "can_read_control": can_read_control,
    }


def _effective_from_mxac(
    *,
    mask: Any,
    err: Optional[BaseException],
    share: str,
    host: str,
    auth_mode: str,
) -> EffectiveAccess:
    """Map a ``query_maximal_access`` ``(mask, err)`` pair to an ``EffectiveAccess``.

    Single source of truth for the MxAc result contract, shared by the
    own-connection and reuse-connection entry points:

    * ``err is not None`` → probe failed; ``succeeded=False`` (caller falls
      back to the share-level value).
    * ``mask is None`` (and no error) → server denied the open; ``succeeded=True``,
      ``has_access=False`` (a definitive "no access", not a fallback trigger).
    * otherwise → ``succeeded=True`` with translated access flags.
    """
    if err is not None:
        telemetry.capture_exception(err)
        return EffectiveAccess(
            succeeded=False,
            has_access=False,
            share_name=share,
            target_host=host,
            auth_mode=auth_mode,
            error_message=str(err),
        )
    if mask is None:
        return EffectiveAccess(
            succeeded=True,
            has_access=False,
            share_name=share,
            target_host=host,
            auth_mode=auth_mode,
        )
    translated = _translate_mask(mask)
    return EffectiveAccess(
        succeeded=True,
        has_access=True,
        share_name=share,
        target_host=host,
        auth_mode=auth_mode,
        **translated,
    )


# SMB2 file MxAc (MAXIMUM_ALLOWED / query_maximal_access) returns the maximal
# access against the OBJECT's NTFS security descriptor only. The share-level
# permission (the tree-connect MaximalAccess) is enforced SEPARATELY, per
# operation — so on a READ-ONLY share whose NTFS folder grants write, the file
# MxAc reports write but an actual create is denied (STATUS_ACCESS_DENIED). The
# true effective access is the INTERSECTION: file MxAc ∩ share MaximalAccess.
# Empirically confirmed (HTB Checkpoint DevDrop): share_max=0x1200a9 (read-only)
# ∩ file_mxac=0x1300af (write) = 0x1200a9 (read-only) — matching the live create
# result and nxc. Without the intersection the collector emits a false
# WriteShare edge (over-reports write on read-only shares).
_SHARE_MAX_UNSET: Any = object()


def _intersect_share_cap(file_mask: int, share_max: int) -> int:
    """Effective access = file MxAc (NTFS object SD) ∩ share-level MaximalAccess.

    The share-level (tree-connect) cap is exactly what the file-level MxAc
    misses; the most-restrictive layer wins, so a read-only share gates an
    NTFS folder that grants write. Pure bitwise AND — both inputs are resolved
    (non-generic) access masks as returned by the server.
    """
    return int(file_mask) & int(share_max)


async def _fetch_share_maximal_access(
    connection: Any, host: str, share: str
) -> Optional[int]:
    """Return the share-level (tree-connect) ``MaximalAccess``, or ``None``.

    The cap that file-level MxAc misses. Best-effort — a tree-connect failure
    returns ``None`` so the caller falls back to the file MxAc alone (the
    pre-fix behaviour, never worse). Never raises.
    """
    try:
        from aiosmb.commons.interfaces.share import SMBShare

        sh = SMBShare.from_unc(f"\\\\{host}\\{share}")
        _ok, err = await sh.connect(connection)
        if err is None and sh.maximal_access is not None:
            return int(sh.maximal_access)
    except Exception as exc:  # noqa: BLE001 — best-effort metadata probe
        print_info_debug(f"[smb-effaccess] share-max fetch failed: {share}: {exc}")
    return None


async def _query_maximal_access_for_path(
    *,
    connection: Any,
    host: str,
    share: str,
    directory_path: str,
    auth_mode: str,
    share_maximal_access: Any = _SHARE_MAX_UNSET,
) -> EffectiveAccess:
    """MxAc-probe one directory within a share, reusing an open ``connection``.

    Generalises the root-only probe to an arbitrary share-relative
    ``directory_path`` ("" == root). The MxAc primitive itself is path-agnostic;
    we simply build the UNC for the target directory and let it compute the
    server-side effective access for that path.

    ``share_maximal_access`` is the share-level (tree-connect) cap that file MxAc
    does NOT account for; the file MxAc is intersected with it so a read-only
    share is never reported as writable. Left unset, it is fetched here (one
    tree-connect — correct for root-only callers); the per-directory enumeration
    fetches it ONCE and threads it in to avoid a tree-connect per folder.
    """
    from aiosmb.commons.interfaces.directory import SMBDirectory

    rel = str(directory_path or "").strip().strip("\\")
    unc = f"\\\\{host}\\{share}" + (f"\\{rel}" if rel else "")
    if share_maximal_access is _SHARE_MAX_UNSET:
        share_maximal_access = await _fetch_share_maximal_access(
            connection, host, share
        )
    try:
        directory = SMBDirectory.from_uncpath(unc)
        mask, err = await directory.query_maximal_access(  # pylint: disable=no-member
            connection
        )
        if mask is not None and share_maximal_access is not None:
            effective = _intersect_share_cap(int(mask), int(share_maximal_access))
            if effective != int(mask):
                print_info_debug(
                    f"[smb-effaccess] {share}\\{rel or '(root)'}: file_mxac="
                    f"0x{int(mask):08x} ∩ share_max="
                    f"0x{int(share_maximal_access):08x} = 0x{effective:08x} "
                    "(share-level cap applied — read-only share gates NTFS write)"
                )
            mask = effective
        return _effective_from_mxac(
            mask=mask, err=err, share=share, host=host, auth_mode=auth_mode
        )
    except Exception as exc:  # noqa: BLE001 — boundary; never abort the sweep
        telemetry.capture_exception(exc)
        return EffectiveAccess(
            succeeded=False,
            has_access=False,
            share_name=share,
            target_host=host,
            auth_mode=auth_mode,
            error_message=str(exc),
        )


async def query_effective_root_access_on_machine(
    *,
    machine: Any,
    share: str,
    host: str,
    auth_mode: str = "",
) -> EffectiveAccess:
    """Return effective (share ∩ NTFS) access for ``share``'s root, reusing ``machine``.

    Unlike :func:`query_effective_root_access`, this does NOT open a new
    connection — it reuses the live ``SMBMachine`` the caller already holds
    (e.g. the share-enumeration loop), issuing a single non-intrusive
    MxAc open of the share root on the existing connection. This is the
    efficient variant for per-share probing inside an enumeration sweep.

    Args:
        machine: A connected ``SMBMachine`` (``machine.connection`` is the live
            ``SMBConnection``).
        share: Share name (e.g. ``"Users"``).
        host: Target host (IP or FQDN), used only to build the share-root UNC
            and to label the result.
        auth_mode: Optional auth-mode label for the result envelope.

    Returns:
        An :class:`EffectiveAccess`. Inspect ``succeeded`` before trusting the
        access flags — see the dataclass docstring for the contract.
    """
    connection = getattr(machine, "connection", None)
    if connection is None:
        return EffectiveAccess(
            succeeded=False,
            has_access=False,
            share_name=share,
            target_host=host,
            auth_mode=auth_mode,
            error_message="machine has no live connection",
        )
    return await _query_maximal_access_for_path(
        connection=connection,
        host=host,
        share=share,
        directory_path="",
        auth_mode=auth_mode,
    )


async def _list_subdirectories(
    *,
    connection: Any,
    host: str,
    share: str,
    directory_path: str,
) -> tuple[list[str], Optional[BaseException]]:
    """List the immediate sub-directory names of one directory (read-only).

    Returns ``(child_relative_paths, error)``. ``child_relative_paths`` are
    share-relative ("" stripped), each the parent path joined with the child
    name. On a listing error the names are empty and ``error`` is set — callers
    treat that directory as a leaf (we still keep any MxAc verdict already taken
    on the directory itself).
    """
    from aiosmb.commons.interfaces.directory import SMBDirectory

    rel = str(directory_path or "").strip().strip("\\")
    unc = f"\\\\{host}\\{share}" + (f"\\{rel}" if rel else "")
    try:
        directory = SMBDirectory.from_uncpath(unc)
        _ok, err = await directory.list(connection)
        if err is not None:
            return [], err
        children: list[str] = []
        for name in directory.subdirs:
            if not name or name in {".", ".."}:
                continue
            children.append(f"{rel}\\{name}" if rel else name)
        return children, None
    except Exception as exc:  # noqa: BLE001 — boundary; never abort the sweep
        return [], exc


async def _async_enumerate_writable_directories(
    *,
    config: SMBConfig,
    share: str,
    depth: int,
    max_folders: int,
) -> WritableDirEnumeration:
    """Walk a share's directory tree (bounded) and MxAc-verify effective WRITE.

    Breadth-first from the share root, capped at ``depth`` levels and
    ``max_folders`` total directories probed. One SMB connection serves the
    whole walk. Read-only throughout: MxAc opens for FILE_READ_ATTRIBUTES and
    the directory listings open for FILE_READ_DATA — no probe file is ever
    written during enumeration.
    """
    auth_mode = "kerberos" if config.use_kerberos else "ntlm"
    host = str(config.target_ip or config.target_hostname or "")
    out = WritableDirEnumeration(
        share=share, target_host=host, succeeded=False, auth_mode=auth_mode
    )

    safe_depth = max(int(depth), 0)
    safe_cap = max(int(max_folders), 1)

    try:
        async with smb_machine_for(config) as machine:
            connection = machine.connection
            # Fetch the share-level (tree-connect) maximal-access cap ONCE for the
            # whole walk and thread it into every per-directory MxAc probe — the
            # file MxAc alone over-reports write on a read-only share.
            share_max = await _fetch_share_maximal_access(connection, host, share)
            # BFS queue of (relative_path, level). Root first so it is always
            # the first writable candidate when it qualifies.
            queue: list[tuple[str, int]] = [("", 0)]
            visited: set[str] = set()

            while queue:
                if out.dirs_probed >= safe_cap:
                    # Record everything still queued as skipped (explicit, not
                    # silent) and stop. Names only — no further round-trips.
                    out.hit_cap = True
                    out.skipped.extend(
                        path for (path, _lvl) in queue if path not in out.skipped
                    )
                    break

                rel_path, level = queue.pop(0)
                if rel_path in visited:
                    continue
                visited.add(rel_path)

                effective = await _query_maximal_access_for_path(
                    connection=connection,
                    host=host,
                    share=share,
                    directory_path=rel_path,
                    auth_mode=auth_mode,
                    share_maximal_access=share_max,
                )
                out.dirs_probed += 1
                # Mark the overall enumeration as succeeded once we get at least
                # one definitive MxAc verdict (success OR a clean access-denied).
                if effective.succeeded:
                    out.succeeded = True
                    if effective.has_access and effective.can_write:
                        out.writable.append(
                            WritableDirectory(
                                share=share, directory_path=rel_path, depth=level
                            )
                        )

                # Descend only while under the depth budget. A listing failure
                # (e.g. no LIST on this folder) leaves it a leaf — we keep its
                # own MxAc verdict but cannot enumerate its children.
                if level < safe_depth:
                    children, list_err = await _list_subdirectories(
                        connection=connection,
                        host=host,
                        share=share,
                        directory_path=rel_path,
                    )
                    if list_err is not None:
                        telemetry.capture_exception(list_err)
                    else:
                        out.dirs_listed += 1
                        for child in children:
                            if child not in visited:
                                queue.append((child, level + 1))

            return out
    except SMBTransportError as exc:
        telemetry.capture_exception(exc)
        out.error_message = str(exc)
        return out
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        out.error_message = str(exc)
        return out


def enumerate_writable_directories(
    *,
    host: str,
    share: str,
    username: str | None = None,
    password: str | None = None,
    nt_hash: str | None = None,
    aes_key: str | None = None,
    ccache_path: str | None = None,
    auth_domain: str | None = None,
    domain: str | None = None,
    use_kerberos: bool = False,
    kdc_host: str | None = None,
    spn_host: str | None = None,
    depth: int = DEFAULT_WRITABLE_DIR_DEPTH,
    max_folders: int = DEFAULT_WRITABLE_DIR_MAX_FOLDERS,
    timeout: int = 30,
) -> WritableDirEnumeration:
    """Return the directories within ``share`` where the token has effective WRITE.

    Granular per-folder generalisation of :func:`query_effective_root_access`:
    walks the share's directory tree breadth-first (root included), MxAc-probes
    each directory for effective WRITE, and returns the share-relative paths
    (``""`` == root) that qualify. Read-only and non-intrusive — never writes a
    probe file. Bounded by ``depth`` and ``max_folders`` for OPSEC and scale.

    Args:
        host: Target host (IP or FQDN) to connect to over SMB.
        share: Share name (e.g. ``"share"``, ``"transfer"``).
        username: Credential username (empty/None for guest/anonymous).
        password: Plaintext password, if used.
        nt_hash: NT hash (or LM:NT pair), if used.
        aes_key: Kerberos AES key (32/64 hex), if used.
        ccache_path: Path to a Kerberos ccache, if used.
        auth_domain: Credential domain (where the account lives).
        domain: Target domain (enumeration target); used for SPN/KDC resolution.
        use_kerberos: Force Kerberos authentication.
        kdc_host: KDC FQDN/IP for Kerberos (defaults handled by transport).
        spn_host: Explicit Kerberos SPN hostname (FQDN) for the target.
        depth: Recursion depth (0 == root only, 1 == root + direct sub-folders,
            the default). Configurable to go deeper when the engagement needs it.
        max_folders: Hard cap on the number of directories probed. When hit, the
            walk stops and ``hit_cap``/``skipped`` record the truncation — never
            a silent miss.
        timeout: Per-connection timeout in seconds.

    Returns:
        A :class:`WritableDirEnumeration`. Inspect ``succeeded`` before trusting
        an empty ``writable`` list (a failed probe yields ``succeeded=False``).
    """
    config = SMBConfig(
        target_ip=host,
        target_hostname=spn_host,
        domain=domain,
        username=username,
        password=password,
        nt_hash=nt_hash,
        aes_key=aes_key,
        ccache_path=ccache_path,
        auth_domain=auth_domain,
        kdc_ip=kdc_host,
        use_kerberos=use_kerberos,
        timeout=timeout,
    )

    print_info_debug(
        f"[smb_effective_access] enumerating writable directories in share "
        f"{mark_sensitive(share, 'share')} on {mark_sensitive(host, 'host')} as "
        f"{mark_sensitive(username or '<anonymous>', 'user')} "
        f"(kerberos={use_kerberos}, depth={depth}, max_folders={max_folders})"
    )

    return run_smb_operation(
        _async_enumerate_writable_directories(
            config=config, share=share, depth=depth, max_folders=max_folders
        )
    )


async def _async_query_effective_root_access(
    *,
    config: SMBConfig,
    share: str,
) -> EffectiveAccess:
    """Open the share root with the MxAc create context and read MaximalAccess."""
    auth_mode = "kerberos" if config.use_kerberos else "ntlm"
    host = str(config.target_ip or config.target_hostname or "")

    try:
        async with smb_machine_for(config) as machine:
            return await _query_maximal_access_for_path(
                connection=machine.connection,
                host=host,
                share=share,
                directory_path="",
                auth_mode=auth_mode,
            )
    except SMBTransportError as exc:
        telemetry.capture_exception(exc)
        return EffectiveAccess(
            succeeded=False,
            has_access=False,
            share_name=share,
            target_host=host,
            auth_mode=auth_mode,
            error_message=str(exc),
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return EffectiveAccess(
            succeeded=False,
            has_access=False,
            share_name=share,
            target_host=host,
            auth_mode=auth_mode,
            error_message=str(exc),
        )


def query_effective_root_access(
    *,
    host: str,
    share: str,
    username: str | None = None,
    password: str | None = None,
    nt_hash: str | None = None,
    aes_key: str | None = None,
    ccache_path: str | None = None,
    auth_domain: str | None = None,
    domain: str | None = None,
    use_kerberos: bool = False,
    kdc_host: str | None = None,
    spn_host: str | None = None,
    timeout: int = 30,
) -> EffectiveAccess:
    """Return the effective (share ∩ NTFS) access for ``share``'s root.

    This opens its OWN connection. For per-share probing inside an
    enumeration loop that already holds a live connection, prefer
    :func:`query_effective_root_access_on_machine` to avoid a redundant
    TCP+auth round-trip. It opens the share root with the SMB2 MxAc create
    context and reads the server-computed ``MaximalAccess`` — never creating
    or writing a file. Root-level only; for per-folder granularity use
    :func:`enumerate_writable_directories`.

    Args:
        host: Target host (IP or FQDN) to connect to over SMB.
        share: Share name (e.g. ``"Users"``, ``"share"``).
        username: Credential username (empty/None for guest/anonymous).
        password: Plaintext password, if used.
        nt_hash: NT hash (or LM:NT pair), if used.
        aes_key: Kerberos AES key (32/64 hex), if used.
        ccache_path: Path to a Kerberos ccache, if used.
        auth_domain: Credential domain (where the account lives).
        domain: Target domain (enumeration target); used for SPN/KDC resolution.
        use_kerberos: Force Kerberos authentication.
        kdc_host: KDC FQDN/IP for Kerberos (defaults handled by transport).
        spn_host: Explicit Kerberos SPN hostname (FQDN) for the target.
        timeout: Per-connection timeout in seconds.

    Returns:
        An :class:`EffectiveAccess`. Inspect ``succeeded`` before trusting the
        access flags — see the dataclass docstring for the contract.
    """
    config = SMBConfig(
        target_ip=host,
        target_hostname=spn_host,
        domain=domain,
        username=username,
        password=password,
        nt_hash=nt_hash,
        aes_key=aes_key,
        ccache_path=ccache_path,
        auth_domain=auth_domain,
        kdc_ip=kdc_host,
        use_kerberos=use_kerberos,
        timeout=timeout,
    )

    print_info_debug(
        f"[smb_effective_access] querying MxAc effective access for share "
        f"{mark_sensitive(share, 'share')} on "
        f"{mark_sensitive(host, 'host')} as "
        f"{mark_sensitive(username or '<anonymous>', 'user')} "
        f"(kerberos={use_kerberos})"
    )

    return run_smb_operation(
        _async_query_effective_root_access(config=config, share=share)
    )
