"""Shared MSDS_MANAGEDPASSWORD_BLOB parsing and gMSA key derivation.

Single source of truth for turning gMSA managed-password secret material into
usable credentials. Two independent paths recover the same structure and both
consume this module:

* the **LDAP read** path (``ReadGMSAPassword``) — reads the confidential
  ``msDS-ManagedPassword`` attribute from the directory
  (:mod:`adscan_internal.integrations.gmsa`);
* the **LSA dump** path (``DumpLSA``) — recovers the blob the Service Control
  Manager cached on a member server under the ``_SC_GMSA_{GUID}_<hash>`` LSA
  secret, for a gMSA that host runs a service as.

The wire format is identical in both cases, so the parser, the NUL-stripping
rules and the Kerberos string-to-key derivation live here once. A second copy
would drift the moment one path learns something the other does not.

Blob layout (MS-ADTS 2.2.19, all little-endian)::

    0x00  Version                         H
    0x02  Reserved                        H
    0x04  Length                          L
    0x08  CurrentPasswordOffset           H
    0x0A  PreviousPasswordOffset          H
    0x0C  QueryPasswordIntervalOffset     H
    0x0E  UnchangedPasswordIntervalOffset H
    0x10  ... variable-length fields ...
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

_BLOB_HEADER = "<HHLHHHH"
_BLOB_HEADER_SIZE = 16


@dataclass
class GmsaCredentials:
    """Cryptographic credentials derived from a gMSA managed-password secret."""

    account: str
    nt_hash: str
    aes128: str
    aes256: str


def strip_one_utf16le_nul(password_bytes: bytes) -> bytes:
    """Strip exactly one trailing UTF-16LE NUL terminator."""
    if len(password_bytes) >= 2 and password_bytes.endswith(b"\x00\x00"):
        return password_bytes[:-2]
    return password_bytes


def looks_like_managed_password_blob(raw: bytes) -> bool:
    """Return True only when ``raw`` is a well-formed MSDS_MANAGEDPASSWORD_BLOB.

    Used to tell a full blob apart from already-extracted CurrentPassword bytes.
    Every offset is range-checked so an unrelated LSA secret whose first bytes
    happen to read as ``version=1`` is still rejected.
    """
    if not raw or len(raw) < _BLOB_HEADER_SIZE:
        return False

    try:
        (
            version,
            reserved,
            length,
            cur_pw_off,
            prev_pw_off,
            query_off,
            unchanged_off,
        ) = struct.unpack_from(_BLOB_HEADER, raw, 0)
    except struct.error:
        return False

    if version != 1 or reserved != 0:
        return False
    if length < _BLOB_HEADER_SIZE or length > len(raw):
        return False
    if cur_pw_off == 0 or cur_pw_off >= length:
        return False
    if query_off == 0 or query_off > length:
        return False
    if unchanged_off == 0 or unchanged_off > length:
        return False

    if prev_pw_off:
        return cur_pw_off < prev_pw_off <= query_off <= length
    return cur_pw_off < query_off <= length


def parse_managed_password_blob(raw: bytes) -> bytes:
    """Extract CurrentPassword bytes from an MSDS_MANAGEDPASSWORD_BLOB.

    Args:
        raw: The full blob as returned by LDAP or cached in the LSA secret.

    Returns:
        CurrentPassword bytes with the trailing UTF-16LE NUL removed.

    Raises:
        ValueError: When the blob header is malformed.
    """
    if len(raw) < _BLOB_HEADER_SIZE:
        raise ValueError(f"gMSA blob too short: {len(raw)} bytes")

    (
        version,
        reserved,
        length,
        cur_pw_off,
        prev_pw_off,
        query_off,
        unchanged_off,
    ) = struct.unpack_from(_BLOB_HEADER, raw, 0)

    if version != 1:
        raise ValueError(f"invalid gMSA blob version: {version}")
    if reserved != 0:
        raise ValueError(f"invalid gMSA blob reserved field: {reserved}")
    if length < _BLOB_HEADER_SIZE or length > len(raw):
        raise ValueError(f"invalid gMSA blob length: {length} > {len(raw)}")
    if cur_pw_off == 0 or cur_pw_off >= length:
        raise ValueError(f"invalid CurrentPasswordOffset: {cur_pw_off}")
    if query_off == 0 or query_off > length:
        raise ValueError(f"invalid QueryPasswordIntervalOffset: {query_off}")
    if unchanged_off == 0 or unchanged_off > length:
        raise ValueError(f"invalid UnchangedPasswordIntervalOffset: {unchanged_off}")

    end = prev_pw_off if prev_pw_off != 0 else query_off
    if end <= cur_pw_off or end > length:
        raise ValueError(f"invalid CurrentPassword end offset: {end}")

    return strip_one_utf16le_nul(raw[cur_pw_off:end])


def current_password_from_secret_material(secret_bytes: bytes) -> bytes:
    """Return CurrentPassword bytes from either a full blob or bare password bytes.

    The LDAP read of ``msDS-ManagedPassword`` and the ``_SC_GMSA_*`` LSA secret
    both carry the full blob; some helpers hand over already-extracted
    CurrentPassword bytes. The blob header check decides which one this is.
    """
    if looks_like_managed_password_blob(secret_bytes):
        return parse_managed_password_blob(secret_bytes)
    return secret_bytes


def md4_hex(data: bytes) -> str:
    """Return the lowercase MD4 hex digest of ``data`` (the NT hash primitive)."""
    from Cryptodome.Hash import MD4

    digest = MD4.new()
    digest.update(data)
    return digest.hexdigest().lower()


def normalize_current_password(
    password_bytes: bytes,
    expected_nt_hash: str | None = None,
) -> bytes:
    """Normalize CurrentPassword bytes using an NT-hash oracle when available.

    Some upstream helpers return CurrentPassword without its trailing UTF-16LE
    NUL. When the caller already knows the expected NT hash, use it to pick the
    byte string that actually hashes to it instead of guessing.
    """
    if not expected_nt_hash:
        return password_bytes

    expected = expected_nt_hash.lower()
    if md4_hex(password_bytes) == expected:
        return password_bytes

    stripped = strip_one_utf16le_nul(password_bytes)
    if stripped != password_bytes and md4_hex(stripped) == expected:
        return stripped

    return password_bytes


def password_bytes_to_kerberos_string(password_bytes: bytes) -> str:
    """Convert UTF-16LE gMSA password bytes to the string used by Kerberos S2K."""
    try:
        return password_bytes.decode("utf-16-le")
    except UnicodeDecodeError:
        # Defensive: gMSA passwords are valid UTF-16LE for string-to-key, but a
        # malformed lab/tool value must not crash the caller.
        return password_bytes.decode("utf-16-le", "replace")


def gmsa_kerberos_salt(sam_account: str, domain_fqdn: str) -> str:
    """Return the Kerberos salt for a gMSA / machine-class account.

    Format: ``UPPER.DOMAIN`` + ``host`` + lowercase sAMAccountName without the
    trailing ``$`` + ``.`` + ``lower.domain`` (e.g.
    ``ESSOS.LOCALhostgmsadragon.essos.local``).
    """
    account_name = sam_account.rstrip("$").lower()
    domain = domain_fqdn.strip().lower()
    return f"{domain.upper()}host{account_name}.{domain}"


def derive_gmsa_keys(
    password_bytes: bytes,
    sam_account: str,
    domain_fqdn: str,
) -> tuple[str, str, str]:
    """Compute ``(nt_hash, aes128, aes256)`` from CurrentPassword bytes."""
    from kerbad.protocol.encryption import Enctype, string_to_key

    nt_hash = md4_hex(password_bytes)

    salt_bytes = gmsa_kerberos_salt(sam_account, domain_fqdn).encode("utf-8")
    pw_bytes = password_bytes_to_kerberos_string(password_bytes).encode("utf-8")

    aes128 = string_to_key(Enctype.AES128, pw_bytes, salt_bytes).contents.hex()
    aes256 = string_to_key(Enctype.AES256, pw_bytes, salt_bytes).contents.hex()

    return nt_hash, aes128, aes256


def derive_gmsa_credentials(
    secret_material: bytes,
    *,
    sam_account: str,
    domain_fqdn: str,
) -> GmsaCredentials:
    """Turn raw gMSA secret material into a full :class:`GmsaCredentials`.

    Accepts either a full MSDS_MANAGEDPASSWORD_BLOB or bare CurrentPassword
    bytes, so both the LDAP read and the cached LSA secret use one entry point.

    Args:
        secret_material: Blob or CurrentPassword bytes.
        sam_account: The gMSA sAMAccountName (with or without the ``$``).
        domain_fqdn: The DNS domain the account lives in — drives the Kerberos
            salt, so it must be the account's own domain.

    Raises:
        ValueError: When the material is present but not parseable as a blob.
    """
    sam = sam_account.rstrip("$") + "$"
    current_password = current_password_from_secret_material(secret_material)
    nt_hash, aes128, aes256 = derive_gmsa_keys(current_password, sam, domain_fqdn)
    return GmsaCredentials(account=sam, nt_hash=nt_hash, aes128=aes128, aes256=aes256)


__all__ = [
    "GmsaCredentials",
    "current_password_from_secret_material",
    "derive_gmsa_credentials",
    "derive_gmsa_keys",
    "gmsa_kerberos_salt",
    "looks_like_managed_password_blob",
    "md4_hex",
    "normalize_current_password",
    "parse_managed_password_blob",
    "password_bytes_to_kerberos_string",
    "strip_one_utf16le_nul",
]
