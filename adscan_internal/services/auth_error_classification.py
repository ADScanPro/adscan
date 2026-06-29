"""Authentication error classifiers scoped by backend/library.

The Kerberos-first policy allows NTLM fallback only when Kerberos failed for
infrastructure reasons.  Those reasons surface differently depending on the
backend: skelsec-native transports bubble up kerbad/asyauth text, pypsrp uses
pyspnego/GSSAPI wording, and Impacket TDS raises Impacket Kerberos/socket
errors.  Keep those catalogues separate so one backend's broad marker does not
silently change another backend's retry behaviour.
"""

from __future__ import annotations

from typing import Any


NATIVE_KERBEROS_INFRA_ERROR_MARKERS: tuple[str, ...] = (
    # kerbad/minikerberos KerberosError names.
    "ERROR NAME: KDC_ERR_S_PRINCIPAL_UNKNOWN",
    "ERROR NAME: KDC_ERR_C_PRINCIPAL_UNKNOWN",
    "ERROR NAME: KDC_ERR_SVC_UNAVAILABLE",
    "ERROR NAME: KRB_AP_ERR_IAKERB_KDC_NOT_FOUND",
    "ERROR NAME: KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE",
    "KDC_ERR_S_PRINCIPAL_UNKNOWN",
    "KDC_ERR_C_PRINCIPAL_UNKNOWN",
    "KDC_ERR_SVC_UNAVAILABLE",
    "KRB_AP_ERR_IAKERB_KDC_NOT_FOUND",
    "KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE",
    # Microsoft/MIT detail text commonly attached to those Kerberos errors.
    "SERVER NOT FOUND IN KERBEROS DATABASE",
    "CLIENT NOT FOUND IN KERBEROS DATABASE",
    "KDC IS UNAVAILABLE",
    "THE IAKERB PROXY COULD NOT FIND A KDC",
    "THE KDC DID NOT RESPOND TO THE IAKERB PROXY",
    # asysocks / asyncio network wrappers around KDC reachability failures.
    "CONNECTION REFUSED",
    "CONNECTIONREFUSED",
    "TIMED OUT",
    "TIMEDOUT",
    "NETWORK IS UNREACHABLE",
    # Client-side Kerberos AP-exchange processing failures on the mutual-auth
    # leg: the server returned a KRB-ERROR rejecting our AP-REQ, or kerbad could
    # not parse the AP-REP the server sent (e.g. a GSSAPI/SPNEGO wrapping kerbad
    # does not yet handle — observed on Windows 11 / Server 2025 where
    # impacket/nxc parse it fine). These are Kerberos-leg failures, not a
    # credential rejection: when NTLM is available it is the correct fallback
    # (validated on Cyberzaintza 2026-06-17). Specific enough not to match a
    # genuine connection error.
    "ASN1_STRUCTS.AP_REP",
    "ASN1_STRUCTS.AP_REQ",
    "PARSING KERBAD.PROTOCOL.ASN1_STRUCTS",
    "KRB-ERROR ERROR-CODE",
    "REJECTED THE KERBEROS AP-REQ",
    # AP-exchange leg: the server returned a GSSAPI-wrapped KRB-ERROR rejecting
    # our AP-REQ. badauth now decodes the real Kerberos error-code instead of
    # blindly parsing it as an AP-REP (which destroyed the code) — and prefixes
    # the kerbad KerberosError with this extra_msg. The decoded code itself
    # (KRB_AP_ERR_MODIFIED / KDC_ERR_ETYPE_NOTSUPP / KRB_AP_ERR_SKEW) is NOT a
    # generic infra marker — those have dedicated recovery (SPN-candidate retry,
    # ETYPE-INFO2 probe, clock-resync). Only the AP-exchange *rejection envelope*
    # is marked infra: it is a Kerberos-leg failure, not a credential rejection,
    # so NTLM fallback is the correct last-resort recovery when NTLM is available.
    "AP EXCHANGE REJECTED BY SERVER",
)


BADLDAP_KERBEROS_INFRA_ERROR_MARKERS = NATIVE_KERBEROS_INFRA_ERROR_MARKERS
AIOSMB_KERBEROS_INFRA_ERROR_MARKERS = NATIVE_KERBEROS_INFRA_ERROR_MARKERS
AARDWOLF_KERBEROS_INFRA_ERROR_MARKERS = NATIVE_KERBEROS_INFRA_ERROR_MARKERS


PYPSRP_KERBEROS_INFRA_ERROR_MARKERS: tuple[str, ...] = (
    # pypsrp -> pyspnego -> GSSAPI/MIT Kerberos wording.
    "SERVER NOT FOUND IN KERBEROS DATABASE",
    "CLIENT NOT FOUND IN KERBEROS DATABASE",
    "NOT FOUND IN KERBEROS DATABASE",
    "CANNOT FIND KDC",
    "CAN'T FIND KDC",
    "CANNOT CONTACT ANY KDC",
    "NO KDC AVAILABLE",
    "UNABLE TO REACH ANY KDC",
    "CANNOT RESOLVE NETWORK ADDRESS FOR KDC",
    "KDC IS UNAVAILABLE",
    "KDC_UNREACH",
    # pyspnego/GSSAPI could not find a usable local credential to mint a TGT
    # (no krb5.conf/KDC resolution in the container). This is an infrastructure
    # failure, not a credential rejection — route it to the NTLM fallback.
    "MATCHING CREDENTIAL NOT FOUND",
    # Network wrappers below pyspnego.
    "CONNECTION REFUSED",
    "CONNECTIONREFUSED",
    "TIMED OUT",
    "TIMEDOUT",
    "NETWORK IS UNREACHABLE",
)


IMPACKET_TDS_KERBEROS_INFRA_ERROR_MARKERS: tuple[str, ...] = (
    # impacket.krb5 KerberosError names and detail strings.
    "KDC_ERR_S_PRINCIPAL_UNKNOWN",
    "KDC_ERR_C_PRINCIPAL_UNKNOWN",
    "KDC_ERR_SVC_UNAVAILABLE",
    "SERVER NOT FOUND IN KERBEROS DATABASE",
    "CLIENT NOT FOUND IN KERBEROS DATABASE",
    "KDC IS UNAVAILABLE",
    # impacket.krb5.kerberosv5.sendReceive socket wrapper.
    "CONNECTION ERROR (",
    "CONNECTION REFUSED",
    "CONNECTIONREFUSED",
    "TIMED OUT",
    "TIMEDOUT",
    "NETWORK IS UNREACHABLE",
)


def exception_chain_text(exc_or_msg: Any) -> str:
    """Return string text for an exception plus its explicit cause/context chain."""
    if not isinstance(exc_or_msg, BaseException):
        return str(exc_or_msg or "")

    parts: list[str] = []
    seen: set[int] = set()
    current: BaseException | None = exc_or_msg
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        parts.append(str(current))
        current = current.__cause__ or current.__context__
    return " | ".join(part for part in parts if part)


def _matches_any_marker(exc_or_msg: Any, markers: tuple[str, ...]) -> bool:
    text_upper = exception_chain_text(exc_or_msg).upper()
    return any(marker in text_upper for marker in markers)


def is_native_kerberos_infra_error(exc_or_msg: Any) -> bool:
    """Return True for kerbad/asyauth-native Kerberos infrastructure failures."""
    return _matches_any_marker(exc_or_msg, NATIVE_KERBEROS_INFRA_ERROR_MARKERS)


def is_aiosmb_kerberos_infra_error(exc_or_msg: Any) -> bool:
    """Return True for aiosmb Kerberos infrastructure failures."""
    return _matches_any_marker(exc_or_msg, AIOSMB_KERBEROS_INFRA_ERROR_MARKERS)


def is_badldap_kerberos_infra_error(exc_or_msg: Any) -> bool:
    """Return True for badldap Kerberos infrastructure failures."""
    return _matches_any_marker(exc_or_msg, BADLDAP_KERBEROS_INFRA_ERROR_MARKERS)


def is_aardwolf_kerberos_infra_error(exc_or_msg: Any) -> bool:
    """Return True for aardwolf/RDP Kerberos infrastructure failures."""
    return _matches_any_marker(exc_or_msg, AARDWOLF_KERBEROS_INFRA_ERROR_MARKERS)


def is_pypsrp_kerberos_infra_error(exc_or_msg: Any) -> bool:
    """Return True for pypsrp/pyspnego Kerberos infrastructure failures."""
    return _matches_any_marker(exc_or_msg, PYPSRP_KERBEROS_INFRA_ERROR_MARKERS)


def is_impacket_tds_kerberos_infra_error(exc_or_msg: Any) -> bool:
    """Return True for Impacket TDS Kerberos infrastructure failures."""
    return _matches_any_marker(exc_or_msg, IMPACKET_TDS_KERBEROS_INFRA_ERROR_MARKERS)


# ---------------------------------------------------------------------------
# Kerberos soft errors — KDC reachable but cannot authenticate this principal
# for account-level reasons. Kerberos cannot proceed, but NTLM with the same
# credential might still work, so these trigger the same NTLM fallback path
# as infrastructure errors.
# ---------------------------------------------------------------------------

# kerbad KerberosError.__str__ format (vendor/kerbad/kerbad/protocol/errors.py):
#   '%s Error Name: %s Detail: "%s" ' % (extra_msg, errorcode.name, errormsg)
# Example: ' Error Name: KDC_ERR_KEY_EXPIRED Detail: "Password has expired..."'
# The error name is the KerberosErrorCode enum member name (all caps, underscores).
# The detail is the KerberosErrorMessage value string.
KERBEROS_SOFT_ERROR_MARKERS: tuple[str, ...] = (
    # KDC_ERR_KEY_EXPIRED (0x17) — password expired, must change before logon.
    # kerbad error name: "KDC_ERR_KEY_EXPIRED"
    # kerbad detail:     "Password has expired—change password to reset"
    # NTLM still works with the expired credential for SAMR SamrChangePasswordUser.
    "ERROR NAME: KDC_ERR_KEY_EXPIRED",
    "KDC_ERR_KEY_EXPIRED",
    "PASSWORD HAS EXPIRED",
    # KRB_AP_ERR_TKT_EXPIRED (0x1f) — service ticket / TGT in ccache has expired.
    # kerbad error name: "KRB_AP_ERR_TKT_EXPIRED"
    # kerbad detail:     "The ticket has expired"
    # Both NTLM fallback and TGT renewal should be tried when this fires.
    "ERROR NAME: KRB_AP_ERR_TKT_EXPIRED",
    "KRB_AP_ERR_TKT_EXPIRED",
    "THE TICKET HAS EXPIRED",
    # KDC_ERR_CLIENT_REVOKED (0x12) — account disabled/locked.
    # kerbad error name: "KDC_ERR_CLIENT_REVOKED"
    # kerbad detail:     "Client's credentials have been revoked"
    "ERROR NAME: KDC_ERR_CLIENT_REVOKED",
    "KDC_ERR_CLIENT_REVOKED",
    "CREDENTIALS HAVE BEEN REVOKED",
)


def is_kerberos_soft_error(exc_or_msg: Any) -> bool:
    """Return True for account-level Kerberos failures where NTLM fallback is warranted.

    These are NOT infrastructure failures — the KDC responded and rejected the
    request for account reasons (expired password, revoked account). NTLM may
    still succeed where Kerberos cannot, e.g. SamrChangePasswordUser accepts
    NTLM with an expired credential to allow the password change.
    """
    return _matches_any_marker(exc_or_msg, KERBEROS_SOFT_ERROR_MARKERS)


# ---------------------------------------------------------------------------
# Unreachable foreign / trust realm — a partner domain whose KDC the current
# credential cannot authenticate against (cross-forest AES-only KDC, no shared
# trust key, foreign realm we have no usable secret for). The AS-REQ comes back
# with KDC_ERR_ETYPE_NOTSUPP / KDC_ERR_PREAUTH_FAILED, OR kerbad returns a
# ``None`` TGT which downstream asn1crypto tries to ``load(None)`` —
# ``TypeError: encoded_data must be a byte string, not NoneType``. Both are ONE
# root cause: we simply cannot reach that realm with this credential. There is
# no recovery (re-mint, clock-resync and the ETYPE-INFO2 probe all assume we own
# a secret valid in that realm), so the correct end state is a single clean
# "realm not reachable" line, NOT a raw asn1 TypeError or a 160-line
# KerberosError traceback. Both the trust enumerator and the attack-path LDAP
# bind classify with this helper so the user-facing message stays consistent.
# ---------------------------------------------------------------------------
UNREACHABLE_FOREIGN_REALM_ERROR_MARKERS: tuple[str, ...] = (
    # kerbad returned a None ticket → asn1crypto load(None) (asn1crypto/core.py).
    "ENCODED_DATA MUST BE A BYTE STRING, NOT NONETYPE",
    "MUST BE A BYTE STRING, NOT NONETYPE",
    # AES-only / RC4-blocked KDC the credential's etypes do not satisfy. NOT a
    # generic infra marker (KDC_ERR_ETYPE_NOTSUPP owns the ETYPE-INFO2 probe
    # recovery for the LOCAL realm); here it specifically means a FOREIGN realm
    # we cannot satisfy, so the caller gates this only on the cross-realm path.
    "KDC_ERR_ETYPE_NOTSUPP",
    "KDC HAS NO SUPPORT FOR ENCRYPTION TYPE",
    # Foreign-realm preauth we cannot satisfy (no shared trust key / wrong creds
    # for that realm).
    "KDC_ERR_PREAUTH_FAILED",
    "PREAUTH FAILED",
)


def is_unreachable_foreign_realm_error(exc_or_msg: Any) -> bool:
    """Return True when a foreign/trust realm cannot be authenticated to.

    Covers the two ways one root cause (a ``None`` Kerberos ticket from a
    foreign-realm AS-REQ the credential cannot satisfy) surfaces: the
    ``encoded_data must be a byte string, not NoneType`` asn1 ``TypeError`` and
    the ``KDC_ERR_ETYPE_NOTSUPP`` / preauth-failed ``KerberosError``. Used by the
    trust enumerator and the attack-path LDAP bind to render ONE clean
    "realm not reachable" line instead of a raw traceback. There is no recovery
    for this case — the realm is genuinely out of reach with this credential.
    """
    return _matches_any_marker(exc_or_msg, UNREACHABLE_FOREIGN_REALM_ERROR_MARKERS)
