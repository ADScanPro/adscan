"""Source-agnostic recovery of loot secrets (GPP cpassword + PowerShell SecureString).

This module is the single source of truth for the pure, transport-agnostic
*recognition* and *decryption* of two recoverable-offline secret schemes ADscan
harvests from file loot, regardless of how that loot was obtained (SMB share
spidering, WinRM PowerShell history/transcripts, MSSQL file reads, ...):

* **GPP cpassword** — a Group Policy Preferences ``cpassword="..."`` value,
  decryptable with the published static Microsoft AES key.
* **PowerShell key-encrypted SecureString** — a secret exported with
  ``ConvertFrom-SecureString -Key <key>`` whose 32-byte AES key is stored
  alongside the blob (the classic ``secret.ps1``). Recoverable offline whenever
  the inline key is present.

Everything here is pure: no ``shell``, no ``add_credential``, no console
printing, no provenance/attack-graph wiring. It only *recognizes* candidate
values and *decrypts* them into plaintext + (best-effort) owning principal. The
caller owns all shell-side effects (``mark_sensitive`` printing, credential
storage, provenance origin, spray re-injection). Keeping this split lets every
credential funnel reuse the exact same recovery logic instead of re-deriving it
per transport.
"""

from __future__ import annotations

import base64
import glob
import os
import re
from dataclasses import dataclass

from adscan_core import telemetry
from adscan_core.rich_output import print_exception

# ---------------------------------------------------------------------------
# GPP cpassword
# ---------------------------------------------------------------------------

# Known GPP Preferences XML filenames that legitimately carry a ``cpassword``.
_GPP_PREFERENCES_XML_FILES = frozenset(
    {
        "groups.xml",
        "services.xml",
        "scheduledtasks.xml",
        "printers.xml",
        "drives.xml",
        "datasources.xml",
    }
)


def _is_gpp_preferences_xml_path(file_path: str | None) -> bool:
    """Return True if ``file_path`` points at a known GPP Preferences XML file.

    Handles both Windows (``\\``) and POSIX (``/``) separators since the path may
    originate from an SMB UNC share result.

    Args:
        file_path: Source file path of the candidate value.

    Returns:
        True if the basename is one of the GPP Preferences XML files.
    """
    if not file_path:
        return False
    basename = os.path.basename(str(file_path).replace("\\", "/"))
    return basename.lower() in _GPP_PREFERENCES_XML_FILES


def looks_like_cpassword_value(value: str | None) -> bool:
    """Heuristic check to determine if a string resembles a cpassword.

    Args:
        value: String to check

    Returns:
        True if the string looks like a cpassword value, False otherwise
    """
    if not value:
        return False
    candidate = value.strip()
    if len(candidate) < 20 or len(candidate) % 4 != 0:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/=]+", candidate))


def decrypt_cpassword(cpassword: str) -> str | None:
    """Decrypt a GPP cpassword value using the bundled gpp-decrypt library.

    Pure decryption primitive: it emits no console output (the caller owns any
    user-facing messaging) and captures decryption exceptions to telemetry.

    Args:
        cpassword: The cpassword string extracted from GPP XML.

    Returns:
        The decrypted password, or None on failure.
    """
    try:
        from gpp_decrypt import decrypt_password

        normalized_cpassword = "".join(str(cpassword).split())
        decrypted = decrypt_password(  # type: ignore[no-untyped-call]
            normalized_cpassword
        )
        decrypted_str = str(decrypted or "")

        # gpp-decrypt currently returns UTF-16LE text with PKCS#7 padding
        # artifacts (e.g. repeated U+0C0C) for some passwords.
        decrypted_str = decrypted_str.rstrip("\x00")
        while decrypted_str:
            last_ord = ord(decrypted_str[-1])
            low = last_ord & 0xFF
            high = (last_ord >> 8) & 0xFF
            if low == high and 1 <= low <= 16:
                decrypted_str = decrypted_str[:-1]
            else:
                break

        if decrypted_str:
            return decrypted_str.strip() or None
        return None
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


def extract_cpassword_entries(text: str) -> list[tuple[str | None, str]]:
    """Extract ``(username, cpassword)`` pairs from GPP-style text content.

    Recognizes both attribute orderings (``userName`` before/after
    ``cpassword``); when no ``userName`` accompanies a ``cpassword`` attribute it
    falls back to standalone ``cpassword="..."`` values with an unknown
    principal.

    Args:
        text: Text content to scan (a GPP Preferences XML fragment or file).

    Returns:
        A list of ``(username_or_None, cpassword)`` pairs in first-seen order.
    """
    if not text:
        return []
    entries: list[tuple[str | None, str]] = []
    entry_pattern = re.compile(
        r'(?is)(?:userName="(?P<user>[^"]+)".*?cpassword="(?P<pass>[^"]+)"'
        r'|cpassword="(?P<pass_alt>[^"]+)".*?userName="(?P<user_alt>[^"]+)")'
    )
    for match in entry_pattern.finditer(text):
        username = match.group("user") or match.group("user_alt")
        cpassword_value = match.group("pass") or match.group("pass_alt")
        if cpassword_value:
            entries.append((username, cpassword_value))

    if not entries:
        standalone_pattern = re.compile(r'cpassword="([^"]+)"', re.IGNORECASE)
        entries = [(None, value) for value in standalone_pattern.findall(text)]
    return entries


# ---------------------------------------------------------------------------
# PowerShell ConvertFrom-SecureString (-Key) recovery
# ---------------------------------------------------------------------------
#
# A secret exported with ``ConvertFrom-SecureString -Key <key>`` is fully
# recoverable OFFLINE whenever the decryption key is stored alongside the blob
# (the classic ``secret.ps1`` that keeps both the SecureString and its 32-byte
# ``$key`` in the same file). Unlike a DPAPI-protected SecureString (recoverable
# only on the origin host/user), a key-encrypted blob + inline key is a usable
# credential that must chain into the attack graph, not just a passive finding.

# The fixed 32-hex-character magic header PowerShell prepends to a key-encrypted
# SecureString. Its presence distinguishes a recoverable key-encrypted blob from
# a DPAPI-protected one and anchors detection.
_POWERSHELL_SECURESTRING_MAGIC = "76492d1116743f0423413b16050a5345"

# Full blob = magic header + base64 payload. The base64 always begins with the
# UTF-16LE encoding of ``2|`` (version marker), which decodes to bytes 0x32 0x00
# 0x7C — hence the leading ``MgB`` in real-world blobs.
_SECURESTRING_BLOB_RE = re.compile(
    _POWERSHELL_SECURESTRING_MAGIC + r"[A-Za-z0-9+/=]{16,}",
    re.IGNORECASE,
)

# AES key sizes PowerShell accepts for ``-Key`` (128/192/256-bit).
_AES_KEY_LENGTHS = frozenset({16, 24, 32})


def looks_like_securestring_blob(value: str | None) -> bool:
    """Return True if ``value`` contains a PowerShell key-encrypted SecureString blob.

    Args:
        value: Candidate string to inspect.

    Returns:
        True when the magic-prefixed key-encrypted SecureString form is present.
    """
    if not value:
        return False
    return bool(_SECURESTRING_BLOB_RE.search(value))


def find_powershell_securestring_blobs(text: str) -> list[str]:
    """Extract every key-encrypted SecureString blob from arbitrary text.

    Args:
        text: Text content to scan (e.g. a full spidered ``.ps1`` file).

    Returns:
        A de-duplicated list of blob strings, preserving first-seen order.
    """
    if not text:
        return []
    seen: set[str] = set()
    blobs: list[str] = []
    for match in _SECURESTRING_BLOB_RE.finditer(text):
        blob = match.group(0)
        if blob not in seen:
            seen.add(blob)
            blobs.append(blob)
    return blobs


def extract_securestring_key_material(text: str) -> list[bytes]:
    """Extract candidate AES key material for SecureString decryption from text.

    Recognizes the common inline-key encodings a ``ConvertFrom-SecureString
    -Key`` producer leaves behind in the same file: an explicit PowerShell byte
    array (``$key = (1,2,3,...)`` / ``@(0x1,0x2,...)``), a bare comma-separated
    byte array without parentheses (``$keyData = 177,252,...``), a numeric range
    (``(1..32)``), a ``[Convert]::FromBase64String("...")`` argument, and a hex
    or base64 string assigned to a ``*key*`` variable.

    Only lengths PowerShell accepts (16/24/32 bytes) are returned. This is
    permissive on purpose: a wrong candidate simply fails the authoritative
    AES-CBC + PKCS7 + UTF-16LE decrypt validation in
    :func:`decrypt_powershell_securestring`, so over-collection is harmless.

    Args:
        text: Text content to scan for inline key material.

    Returns:
        A de-duplicated list of candidate key byte strings.
    """
    if not text:
        return []
    candidates: list[bytes] = []
    seen: set[bytes] = set()

    def _add(raw: bytes | None) -> None:
        if raw and len(raw) in _AES_KEY_LENGTHS and raw not in seen:
            seen.add(raw)
            candidates.append(raw)

    # 1. Explicit byte arrays: (1,2,3,...) or @(0x1,0x2,...) — comma-separated.
    for match in re.finditer(r"@?\(([^()]*,[^()]*)\)", text):
        tokens = [tok.strip() for tok in match.group(1).split(",") if tok.strip()]
        if len(tokens) not in _AES_KEY_LENGTHS:
            continue
        try:
            values = [
                int(tok, 16) if tok.lower().startswith("0x") else int(tok)
                for tok in tokens
            ]
        except ValueError:
            continue
        if all(0 <= value <= 255 for value in values):
            _add(bytes(values))

    # 1b. Bare comma-separated byte array assigned WITHOUT parentheses:
    #     $keyData = 177, 252, 228, ...   (decimal or 0xNN, no parens). This is
    #     the common ConvertFrom-SecureString key-file form — e.g. the GOAD
    #     secret.ps1 `$keyData = 177, 252, ...` — which the parenthesized form
    #     above does not match. Anchor on `=` and require >=16 numeric tokens.
    for match in re.finditer(
        r"=\s*((?:0x[0-9a-fA-F]{1,2}|\d{1,3})(?:\s*,\s*(?:0x[0-9a-fA-F]{1,2}|\d{1,3})){15,})",
        text,
    ):
        tokens = [tok.strip() for tok in match.group(1).split(",") if tok.strip()]
        if len(tokens) not in _AES_KEY_LENGTHS:
            continue
        try:
            values = [
                int(tok, 16) if tok.lower().startswith("0x") else int(tok)
                for tok in tokens
            ]
        except ValueError:
            continue
        if all(0 <= value <= 255 for value in values):
            _add(bytes(values))

    # 2. Numeric ranges: (1..32) / (0..31).
    for match in re.finditer(r"\(\s*(\d+)\s*\.\.\s*(\d+)\s*\)", text):
        start, end = int(match.group(1)), int(match.group(2))
        step = 1 if end >= start else -1
        values = list(range(start, end + step, step))
        if len(values) in _AES_KEY_LENGTHS and all(0 <= value <= 255 for value in values):
            _add(bytes(values))

    # 3. [Convert]::FromBase64String("...") arguments.
    for match in re.finditer(
        r"FromBase64String\(\s*[\"']([A-Za-z0-9+/=]+)[\"']", text
    ):
        try:
            _add(base64.b64decode(match.group(1)))
        except Exception:  # noqa: BLE001
            pass

    # 4. Hex / base64 string assigned to a *key* variable.
    for match in re.finditer(
        r"(?i)key[\"']?\s*[:=]\s*[\"']([A-Za-z0-9+/=]{16,})[\"']", text
    ):
        token = match.group(1)
        if re.fullmatch(r"[0-9a-fA-F]+", token) and len(token) in {32, 48, 64}:
            try:
                _add(bytes.fromhex(token))
            except ValueError:
                pass
        try:
            _add(base64.b64decode(token))
        except Exception:  # noqa: BLE001
            pass

    return candidates


def _hex_or_b64_decode(token: str) -> bytes:
    """Decode a token that may be hex- or base64-encoded.

    The ``ConvertFrom-SecureString -Key`` wire format uses a base64 IV but a
    HEX-encoded ciphertext; producers vary. Prefer hex when the token is
    entirely hex digits of even length, else fall back to base64.
    """
    token = token.strip()
    if token and len(token) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", token):
        return bytes.fromhex(token)
    return base64.b64decode(token)


def decrypt_powershell_securestring(blob: str, key: bytes) -> str | None:
    """Decrypt a PowerShell key-encrypted SecureString blob to plaintext.

    Implements the ``ConvertFrom-SecureString -Key`` scheme: the magic-prefixed
    base64 payload decodes (UTF-16LE) to ``"<version>|<base64 IV>|<hex
    ciphertext>"`` (the IV is base64, the ciphertext is HEX in the standard
    format; both are decoded hex-or-base64 for robustness); the ciphertext is
    AES-CBC with the supplied key and the embedded IV, PKCS7-padded, and the
    recovered plaintext is UTF-16LE.

    The decode is self-validating: a wrong key yields an invalid PKCS7 pad or a
    non-decodable UTF-16LE result, so a successful return authoritatively
    confirms the key matched the blob.

    Args:
        blob: The key-encrypted SecureString string (with or without the magic).
        key: The AES key bytes (16/24/32).

    Returns:
        The recovered plaintext, or None if the key does not match / input is
        malformed.
    """
    if not blob or not key or len(key) not in _AES_KEY_LENGTHS:
        return None
    payload = blob.strip()
    lowered = payload.lower()
    idx = lowered.find(_POWERSHELL_SECURESTRING_MAGIC)
    if idx == -1:
        return None
    payload = payload[idx + len(_POWERSHELL_SECURESTRING_MAGIC):]
    payload = re.sub(r"[^A-Za-z0-9+/=]", "", payload)
    if not payload:
        return None
    try:
        from cryptography.hazmat.primitives.ciphers import (
            Cipher,
            algorithms,
            modes,
        )

        inner = base64.b64decode(payload).decode("utf-16-le")
        parts = inner.split("|")
        if len(parts) != 3:
            return None
        _version, iv_raw, ct_raw = parts
        iv = _hex_or_b64_decode(iv_raw)
        ciphertext = _hex_or_b64_decode(ct_raw)
        if len(iv) != 16 or not ciphertext or len(ciphertext) % 16 != 0:
            return None
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        if not padded:
            return None
        pad = padded[-1]
        if pad < 1 or pad > 16 or pad > len(padded):
            return None
        if padded[-pad:] != bytes([pad]) * pad:
            return None
        plaintext = padded[:-pad].decode("utf-16-le")
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None
    plaintext = plaintext.rstrip("\x00")
    if not plaintext:
        return None
    # A wrong key that survives PKCS7 + UTF-16LE is astronomically unlikely, but
    # reject control-char garbage as a final guard on a spurious decrypt.
    if any(ord(char) < 32 and char not in "\t" for char in plaintext):
        return None
    return plaintext


# Common ways a PowerShell credential file names the owning principal next to a
# SecureString: a PSCredential constructor, or a user/login/account assignment.
_SECURESTRING_USERNAME_PATTERNS = (
    r"(?i)PSCredential[^\n(]*\(\s*[\"']([^\"']+)[\"']",
    r"(?i)\$(?:user(?:name)?|login|account|samaccountname)\s*=\s*[\"']([^\"']+)[\"']",
    r"(?i)-User(?:name)?\s+[\"']([^\"']+)[\"']",
)


def _extract_securestring_principal(text: str) -> str | None:
    """Return the owning principal named alongside a SecureString, if any.

    Args:
        text: Text content of the credential file.

    Returns:
        The bare sAMAccountName (domain prefix stripped), or None when no
        adjacent principal is present.
    """
    if not text:
        return None
    for pattern in _SECURESTRING_USERNAME_PATTERNS:
        match = re.search(pattern, text)
        if match:
            raw = match.group(1).strip()
            if raw:
                return raw.split("\\")[-1].split("/")[-1].strip() or None
    return None


def _read_full_file_text(file_path: str | None, max_bytes: int = 2_000_000) -> str | None:
    """Read a (bounded) file's text for SecureString recovery.

    Args:
        file_path: Path to the local file (spidered artifact).
        max_bytes: Upper bound on bytes read to keep memory bounded at scale.

    Returns:
        The file text, or None on error / missing path.
    """
    if not file_path:
        return None
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
            return handle.read(max_bytes)
    except OSError:
        return None


# ---------------------------------------------------------------------------
# DPAPI-protected SecureString (keyless) — detectable, NOT offline-recoverable
# ---------------------------------------------------------------------------
#
# ``ConvertFrom-SecureString`` WITHOUT ``-Key`` produces a DPAPI-protected blob:
# a hex string of a Windows DPAPI blob, which begins with the fixed DPAPI blob
# provider GUID. It can ONLY be decrypted with the encrypting user's DPAPI
# masterkey (not offline, not with an AES key), so we DETECT it to distinguish it
# from the recoverable key-encrypted form, but never attempt an AES decrypt and
# never fabricate a plaintext.
_DPAPI_BLOB_PROVIDER_GUID_HEX = "01000000d08c9ddf0115d1118c7a00c04fc297eb"
_DPAPI_SECURESTRING_RE = re.compile(
    _DPAPI_BLOB_PROVIDER_GUID_HEX + r"[0-9a-f]{16,}",
    re.IGNORECASE,
)


def looks_like_dpapi_protected_securestring(value: str | None) -> bool:
    """Return True if ``value`` contains a DPAPI-protected SecureString blob.

    This is the keyless ``ConvertFrom-SecureString`` form — recoverable only with
    the origin user's DPAPI masterkey, NOT offline. Detecting it lets the caller
    annotate a clear "not recoverable offline" reason instead of silently
    treating it like the AES key-encrypted form.

    Args:
        value: Candidate string to inspect.

    Returns:
        True when a DPAPI-provider-GUID-prefixed hex blob is present.
    """
    if not value:
        return False
    return bool(_DPAPI_SECURESTRING_RE.search(value))


# ---------------------------------------------------------------------------
# Referenced / sibling AES key files (out-of-line key material)
# ---------------------------------------------------------------------------
#
# The AES key is frequently NOT inline — a producer stores it in a sibling file
# and reads it back (``$key = Get-Content "encryption.key"``,
# ``[IO.File]::ReadAllBytes("k.bin")``). Given the blob file's directory (and the
# loot dir), resolve a referenced/sibling key file by basename, read it bounded,
# and interpret its bytes as a key. A wrong candidate self-rejects in the decrypt.

# Explicit references to an out-of-line key file.
_KEY_FILE_REFERENCE_PATTERNS = (
    r"(?i)Get-Content\b[^\n\"']*[\"']([^\"'\r\n]+?\.(?:key|bin|dat|txt))[\"']",
    r"(?i)ReadAllBytes\(\s*[\"']([^\"'\r\n]+?)[\"']",
    r"(?i)\$\w*key\w*\s*=\s*[\"']([^\"'\r\n]+?\.(?:key|bin|dat))[\"']",
)

# Sibling filenames to try even without an explicit inline reference. Kept to
# strong key-file signals (``.key`` / ``.bin``) so we do not read every unrelated
# text file in a loot directory.
_SIBLING_KEY_FILE_GLOBS = ("*.key", "*.bin")

# Bounds to keep resolution cheap at scale.
_MAX_KEY_FILES_TRIED = 25
_MAX_KEY_FILE_BYTES = 4096


def find_referenced_key_filenames(text: str) -> list[str]:
    """Return the basenames of out-of-line key files referenced in ``text``.

    Args:
        text: Text content to scan (a ``.ps1`` / log snippet).

    Returns:
        De-duplicated key-file basenames, in first-seen order.
    """
    if not text:
        return []
    names: list[str] = []
    seen: set[str] = set()
    for pattern in _KEY_FILE_REFERENCE_PATTERNS:
        for match in re.finditer(pattern, text):
            ref = match.group(1).strip()
            if not ref:
                continue
            base = os.path.basename(ref.replace("\\", "/")).strip()
            if base and base not in seen:
                seen.add(base)
                names.append(base)
    return names


def _interpret_key_file_bytes(raw: bytes | None) -> list[bytes]:
    """Interpret the bytes of a candidate key file as AES key material.

    Accepts raw bytes at an exact key length, or a text encoding: bare base64,
    bare hex, or PowerShell byte-array / range / ``FromBase64String`` / ``key=``
    forms (reusing :func:`extract_securestring_key_material`).

    Args:
        raw: The (bounded) file bytes.

    Returns:
        A de-duplicated list of candidate key byte strings (16/24/32 bytes).
    """
    if not raw:
        return []
    out: list[bytes] = []
    seen: set[bytes] = set()

    def _add(candidate: bytes | None) -> None:
        if candidate and len(candidate) in _AES_KEY_LENGTHS and candidate not in seen:
            seen.add(candidate)
            out.append(candidate)

    # Raw bytes at an exact key length.
    _add(raw)

    text = raw.decode("utf-8", errors="ignore").strip()
    if text:
        compact = re.sub(r"\s+", "", text)
        if compact and re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
            try:
                _add(base64.b64decode(compact))
            except Exception:  # noqa: BLE001
                pass
        if re.fullmatch(r"[0-9a-fA-F]+", compact) and len(compact) in {32, 48, 64}:
            try:
                _add(bytes.fromhex(compact))
            except ValueError:
                pass
        for candidate in extract_securestring_key_material(text):
            _add(candidate)
    return out


def resolve_referenced_key_material(
    text: str,
    *,
    file_path: str | None = None,
    loot_dir: str | None = None,
) -> list[bytes]:
    """Resolve AES key material from referenced / sibling key files.

    Looks for a key file referenced in ``text`` (or a sibling ``.key`` / ``.bin``
    file) inside the blob file's own directory and ``loot_dir``, resolved by
    basename, then interprets its bytes as key material. Bounded (file count +
    per-file bytes) to stay cheap at scale. Never raises.

    Args:
        text: Text content that may reference a key file.
        file_path: Local path of the blob's source file (its directory is
            searched first).
        loot_dir: Additional directory of downloaded loot to search.

    Returns:
        A de-duplicated list of candidate key byte strings from files on disk.
    """
    base_dirs: list[str] = []
    if file_path:
        blob_dir = os.path.dirname(str(file_path))
        if blob_dir:
            base_dirs.append(blob_dir)
    if loot_dir and loot_dir not in base_dirs:
        base_dirs.append(loot_dir)
    if not base_dirs:
        return []

    candidates: list[bytes] = []
    seen: set[bytes] = set()
    tried = 0

    def _consume(path: str) -> None:
        nonlocal tried
        tried += 1
        try:
            with open(path, "rb") as handle:
                raw = handle.read(_MAX_KEY_FILE_BYTES)
        except OSError:
            return
        for candidate in _interpret_key_file_bytes(raw):
            if candidate not in seen:
                seen.add(candidate)
                candidates.append(candidate)

    # 1. Explicitly referenced key files, resolved by basename in the base dirs.
    for base in find_referenced_key_filenames(text):
        for directory in base_dirs:
            if tried >= _MAX_KEY_FILES_TRIED:
                return candidates
            path = os.path.join(directory, base)
            if os.path.isfile(path):
                _consume(path)

    # 2. Sibling key files in the base dirs (common case: key file sits next to
    #    the blob with no inline reference).
    for directory in base_dirs:
        for pattern in _SIBLING_KEY_FILE_GLOBS:
            for path in sorted(glob.glob(os.path.join(directory, pattern))):
                if tried >= _MAX_KEY_FILES_TRIED:
                    return candidates
                if os.path.isfile(path):
                    _consume(path)
    return candidates


# ---------------------------------------------------------------------------
# Pure recovery orchestrators
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RecoveredSecret:
    """A plaintext secret recovered offline from loot, with optional owner.

    Attributes:
        plaintext: The recovered cleartext secret.
        principal: The owning sAMAccountName when the source named it adjacent to
            the secret, otherwise ``None`` (an unanchored spray candidate).
        scheme: The recovery scheme (``"powershell_securestring"`` /
            ``"gpp_cpassword"``).
    """

    plaintext: str
    principal: str | None
    scheme: str


@dataclass(frozen=True)
class SecureStringRecoveryResult:
    """Outcome of :func:`recover_securestring_secrets`.

    ``blobs_present`` / ``keys_present`` let the caller distinguish the three
    states without re-scanning: no blob at all, a blob with no recoverable inline
    key (stays a passive finding), or a blob that was decrypted.
    """

    secrets: list[RecoveredSecret]
    blobs_present: bool
    keys_present: bool


def recover_securestring_secrets(
    text: str,
    *,
    file_path: str | None = None,
    loot_dir: str | None = None,
) -> SecureStringRecoveryResult:
    """Recover every PowerShell key-encrypted SecureString secret from ``text``.

    Pure + source-agnostic: recognizes the blobs, gathers key material from BOTH
    inline sources AND any referenced/sibling key file resolved relative to
    ``file_path`` / ``loot_dir``, extracts the adjacent principal, and decrypts
    (every key tried against every blob; a wrong key self-rejects). De-duplicates
    recovered plaintexts, preserving first-seen order. Emits nothing and stores
    nothing — the caller owns display and credential wiring.

    The keyless DPAPI-protected form (no magic header, not offline-recoverable)
    is intentionally NOT decrypted here — it does not match the blob regex, so it
    yields ``blobs_present=False``; use :func:`looks_like_dpapi_protected_securestring`
    to distinguish it from "no SecureString at all".

    Args:
        text: Text content to scan (ideally the full source file).
        file_path: Local path of the blob's source file (used to resolve a
            referenced/sibling key file).
        loot_dir: Additional loot directory to search for a key file.

    Returns:
        A :class:`SecureStringRecoveryResult`. ``secrets`` carries the recovered
        plaintexts, each tagged with the adjacent principal (or ``None`` when the
        file named no owner, i.e. a spray candidate).
    """
    if not text:
        return SecureStringRecoveryResult(secrets=[], blobs_present=False, keys_present=False)
    blobs = find_powershell_securestring_blobs(text)
    if not blobs:
        return SecureStringRecoveryResult(secrets=[], blobs_present=False, keys_present=False)
    keys = list(extract_securestring_key_material(text))
    for key in resolve_referenced_key_material(text, file_path=file_path, loot_dir=loot_dir):
        if key not in keys:
            keys.append(key)
    if not keys:
        return SecureStringRecoveryResult(secrets=[], blobs_present=True, keys_present=False)

    principal = _extract_securestring_principal(text)
    secrets: list[RecoveredSecret] = []
    seen_plaintext: set[str] = set()
    for blob in blobs:
        plaintext: str | None = None
        for key in keys:
            plaintext = decrypt_powershell_securestring(blob, key)
            if plaintext:
                break
        if not plaintext or plaintext in seen_plaintext:
            continue
        seen_plaintext.add(plaintext)
        secrets.append(
            RecoveredSecret(
                plaintext=plaintext,
                principal=principal,
                scheme="powershell_securestring",
            )
        )
    return SecureStringRecoveryResult(secrets=secrets, blobs_present=True, keys_present=True)


def recover_cpassword_secrets(text: str, file_path: str | None = None) -> list[RecoveredSecret]:
    """Recover every GPP cpassword secret decryptable from ``text``.

    Pure: extracts ``(userName, cpassword)`` pairs and decrypts each with the
    static Microsoft AES key, de-duplicating by cpassword value. Only successful
    decrypts are returned. Emits nothing and stores nothing.

    Args:
        text: Text content to scan (a GPP Preferences XML fragment or file).
        file_path: Source path of the content, reserved for provenance context
            by the caller (not used for extraction).

    Returns:
        The recovered plaintexts, each tagged with the owning principal named in
        the GPP entry (or ``None`` for a standalone cpassword).
    """
    del file_path  # reserved for caller-side provenance; extraction is path-agnostic
    if not text:
        return []
    secrets: list[RecoveredSecret] = []
    seen_values: set[str] = set()
    for username, cpassword_value in extract_cpassword_entries(text):
        cpassword_value = cpassword_value.strip()
        if not cpassword_value or cpassword_value in seen_values:
            continue
        seen_values.add(cpassword_value)
        plaintext = decrypt_cpassword(cpassword_value)
        if not plaintext:
            continue
        principal = username.split("\\")[-1] if username else None
        secrets.append(
            RecoveredSecret(
                plaintext=plaintext,
                principal=principal,
                scheme="gpp_cpassword",
            )
        )
    return secrets
