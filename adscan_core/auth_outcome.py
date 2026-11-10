"""What a failed sign-in MEANS for the lockout guard: one classifier, every transport.

``adscan_core.auth_attempt_guard`` refuses a sign-in that could push an account
toward lockout. It may only act on evidence that the DOMAIN CONTROLLER counted
the attempt against the account (``badPwdCount``) or reported the account as
unusable. Everything else a transport can fail with (a blocked protocol, a
missing channel binding, a clock, an etype, a service rejecting a ticket, a
timeout) says nothing about the secret, and the correct credential behind it
must reach the fallback that recovers it. This module turns each transport's
failure into one of five verdicts so that distinction is made once, here, and
not re-derived at every seam:

``SUCCESS``
    The domain validated the secret. The DC resets ``badPwdCount`` to zero.
``WRONG_SECRET``
    The DC rejected the secret itself and counted it. The guard counts it and
    never sends that secret again for the principal.
``ACCOUNT_STATE``
    The account cannot sign in right now (disabled, locked out, expired, a
    password that must change). Not counted; the principal is not tried again
    until a sign-in as it succeeds.
``METHOD_OR_CONFIG``
    The credential may well be right but the method or the configuration is
    not (protocol blocked, channel binding or signing required, etype, clock,
    realm, a ticket the service rejected). Not counted, the secret is not marked
    bad, and the caller's fallback runs as before.
``UNKNOWN``
    The transport cannot tell which of the above happened. Not counted and not
    marked: guessing "wrong secret" here would withhold a correct credential.

Protocol facts this table rests on:

* Kerberos AS exchange, [MS-KILE] 3.3.5.7.1 and RFC 4120 5.9.1: only a failed
  pre-authentication (``KDC_ERR_PREAUTH_FAILED``, 24) is a key mismatch the KDC
  counts against ``badPwdCount``. ``KDC_ERR_CLIENT_REVOKED`` (18) is the
  disabled/locked/expired answer. ``KDC_ERR_KEY_EXPIRED`` (23) means the password
  must change. ``KDC_ERR_ETYPE_NOSUPP`` (14), ``KDC_ERR_PADATA_TYPE_NOSUPP`` (16),
  ``KRB_AP_ERR_SKEW`` (37), ``KDC_ERR_C_PRINCIPAL_UNKNOWN`` (6),
  ``KDC_ERR_WRONG_REALM`` (68) and ``KDC_ERR_CLIENT_NOT_TRUSTED`` (62, PKINIT)
  are about the request, not the secret. A service rejecting a TICKET (AP-REQ:
  ``KRB_AP_ERR_TKT_EXPIRED`` 32, ``KRB_AP_ERR_MODIFIED`` 41 for a wrong SPN, a
  ``SEC_E_LOGON_DENIED`` after a valid TGT) never reaches the account's password
  check at all.
* NTLM, [MS-NLMP] 3.2.5 and [MS-APDS] 3.1.5: the DC answers a pass-through logon
  with an NTSTATUS. ``STATUS_WRONG_PASSWORD`` and ``STATUS_LOGON_FAILURE``
  (``0xC000006A`` / ``0xC000006D``, the latter is what a server returns for a bad
  password) are the wrong-secret signal. ``STATUS_ACCOUNT_DISABLED``,
  ``STATUS_ACCOUNT_LOCKED_OUT``, ``STATUS_ACCOUNT_EXPIRED``,
  ``STATUS_PASSWORD_EXPIRED`` and ``STATUS_PASSWORD_MUST_CHANGE`` are account
  state. ``STATUS_NTLM_BLOCKED`` (Restrict NTLM policy), ``STATUS_INVALID_PARAMETER``
  (a MIC or flags the server refused), ``STATUS_NOT_SUPPORTED`` and
  ``STATUS_DOWNGRADE_DETECTED`` are method. ``STATUS_ACCOUNT_RESTRICTION`` is what
  a Protected Users member gets for any NTLM logon (Microsoft, "Protected Users
  Security Group"): the password is right and Kerberos with AES still works, so
  it is a METHOD verdict, never a block on the principal.
* LDAP bind against AD, [MS-ADTS] 3.1.1.3.3 and the AcceptSecurityContext
  sub-status AD appends as ``data <hex>``: ``52e`` is a bad password; ``525`` an
  unknown user; ``530``/``531`` logon hours or workstation restrictions; ``532``
  password expired; ``533`` disabled; ``701`` account expired; ``773`` must
  reset; ``775`` locked out. ``80090346`` (``SEC_E_BAD_BINDINGS``) is channel
  binding, ``strongerAuthRequired`` is signing. A bare ``invalidCredentials`` /
  ``SEC_E_LOGON_DENIED`` WITHOUT the sub-status is UNKNOWN: it is also what a DC
  answers when NTLM is disabled by policy (the transport's own Rule 3), so it
  cannot be read as a wrong secret.
* HTTP Negotiate (WinRM): a 401 carries no reason. Wrong password, disabled
  account, blocked NTLM and a Protected Users member all look the same, so it is
  UNKNOWN. A Kerberos acquisition done by GSSAPI reports the KDC's error text,
  which is classified as the Kerberos table above.
* TDS (MSSQL): SQL Server masks the reason of a failed login on the wire (error
  18456 state 1; 18452 "untrusted domain" for an integrated logon whose SSPI
  exchange failed), so both are UNKNOWN. Only the lockout (18486), disabled
  (18470) and expiry (18487, 18488) messages are explicit.

An EMPTY secret is not classified at all: the guard refuses to send it (a caller
that reaches a seam with no secret has a bug; see ``auth_attempt_guard``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

__all__ = [
    "AuthOutcome",
    "AuthVerdict",
    "SUCCESS",
    "classify_gssapi_acquisition",
    "classify_http_negotiate",
    "classify_kerberos_as",
    "classify_ldap_bind",
    "classify_ntlm_status",
    "classify_tds_login",
]


class AuthOutcome(str, Enum):
    """The five verdicts the lockout guard acts on."""

    SUCCESS = "success"
    WRONG_SECRET = "wrong_secret"
    ACCOUNT_STATE = "account_state"
    METHOD_OR_CONFIG = "method_or_config"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class AuthVerdict:
    """One classified sign-in outcome.

    Attributes:
        outcome: The verdict.
        reason: Short English reason (an account state such as ``"locked out"``,
            or the protocol signal that decided it). Never contains a secret.
    """

    outcome: AuthOutcome
    reason: str = ""


SUCCESS = AuthVerdict(AuthOutcome.SUCCESS)
_UNKNOWN = AuthVerdict(AuthOutcome.UNKNOWN)


def _verdict(outcome: AuthOutcome, reason: str) -> AuthVerdict:
    return AuthVerdict(outcome, reason)


# --------------------------------------------------------------------------- Kerberos

#: Kerberos error names (kerbad ``KerberosErrorCode`` / impacket ``ErrorCodes``)
#: and their numeric codes, mapped to a verdict.
_KERBEROS_AS_TABLE: dict[str, AuthVerdict] = {
    "KDC_ERR_PREAUTH_FAILED": _verdict(AuthOutcome.WRONG_SECRET, "pre-authentication failed"),
    "KDC_ERR_CLIENT_REVOKED": _verdict(AuthOutcome.ACCOUNT_STATE, "disabled or locked out"),
    "KDC_ERR_KEY_EXPIRED": _verdict(AuthOutcome.ACCOUNT_STATE, "required to change its password"),
    "KDC_ERR_ETYPE_NOSUPP": _verdict(AuthOutcome.METHOD_OR_CONFIG, "encryption type not supported"),
    "KDC_ERR_ETYPE_NOTSUPP": _verdict(AuthOutcome.METHOD_OR_CONFIG, "encryption type not supported"),
    "KDC_ERR_PADATA_TYPE_NOSUPP": _verdict(AuthOutcome.METHOD_OR_CONFIG, "pre-authentication type not supported"),
    "KDC_ERR_PREAUTH_REQUIRED": _verdict(AuthOutcome.METHOD_OR_CONFIG, "pre-authentication required"),
    "KRB_AP_ERR_SKEW": _verdict(AuthOutcome.METHOD_OR_CONFIG, "clock skew"),
    "KRB_AP_ERR_TKT_EXPIRED": _verdict(AuthOutcome.METHOD_OR_CONFIG, "ticket expired"),
    "KRB_AP_ERR_MODIFIED": _verdict(AuthOutcome.METHOD_OR_CONFIG, "ticket rejected by the service"),
    "KDC_ERR_C_PRINCIPAL_UNKNOWN": _verdict(AuthOutcome.METHOD_OR_CONFIG, "principal unknown in this realm"),
    "KDC_ERR_S_PRINCIPAL_UNKNOWN": _verdict(AuthOutcome.METHOD_OR_CONFIG, "service principal unknown"),
    "KDC_ERR_WRONG_REALM": _verdict(AuthOutcome.METHOD_OR_CONFIG, "wrong realm"),
    "KDC_ERR_CLIENT_NOT_TRUSTED": _verdict(AuthOutcome.METHOD_OR_CONFIG, "certificate not trusted"),
    "KDC_ERR_POLICY": _verdict(AuthOutcome.METHOD_OR_CONFIG, "KDC policy rejects the request"),
}
_KERBEROS_CODE_NAMES = {
    24: "KDC_ERR_PREAUTH_FAILED",
    18: "KDC_ERR_CLIENT_REVOKED",
    23: "KDC_ERR_KEY_EXPIRED",
    14: "KDC_ERR_ETYPE_NOSUPP",
    16: "KDC_ERR_PADATA_TYPE_NOSUPP",
    25: "KDC_ERR_PREAUTH_REQUIRED",
    37: "KRB_AP_ERR_SKEW",
    32: "KRB_AP_ERR_TKT_EXPIRED",
    41: "KRB_AP_ERR_MODIFIED",
    6: "KDC_ERR_C_PRINCIPAL_UNKNOWN",
    7: "KDC_ERR_S_PRINCIPAL_UNKNOWN",
    68: "KDC_ERR_WRONG_REALM",
    62: "KDC_ERR_CLIENT_NOT_TRUSTED",
    12: "KDC_ERR_POLICY",
}


def classify_kerberos_as(code: object) -> AuthVerdict:
    """Classify the error of a Kerberos AS exchange (a TGT request with a secret).

    Args:
        code: The error code name (``"KDC_ERR_PREAUTH_FAILED"``), its number
            (``24``), or ``None`` when the exchange raised something that is not
            a Kerberos error (a socket error, a timeout).
    """
    if code is None:
        return _UNKNOWN
    if isinstance(code, int) and not isinstance(code, bool):
        name = _KERBEROS_CODE_NAMES.get(code, "")
    else:
        name = str(getattr(code, "name", code) or "").strip().upper()
    return _KERBEROS_AS_TABLE.get(name, _UNKNOWN)


# --------------------------------------------------------------------------- NTLM

#: NTSTATUS from an NTLM AUTHENTICATE, by name and by value. Order matters only
#: in that every entry is checked; names never overlap.
_NTSTATUS_TABLE: tuple[tuple[str, int, AuthVerdict], ...] = (
    ("STATUS_ACCOUNT_LOCKED_OUT", 0xC0000234, _verdict(AuthOutcome.ACCOUNT_STATE, "locked out")),
    ("STATUS_ACCOUNT_DISABLED", 0xC0000072, _verdict(AuthOutcome.ACCOUNT_STATE, "disabled")),
    ("STATUS_ACCOUNT_EXPIRED", 0xC0000193, _verdict(AuthOutcome.ACCOUNT_STATE, "expired")),
    ("STATUS_PASSWORD_EXPIRED", 0xC0000071, _verdict(AuthOutcome.ACCOUNT_STATE, "required to change its password")),
    ("STATUS_PASSWORD_MUST_CHANGE", 0xC0000224, _verdict(AuthOutcome.ACCOUNT_STATE, "required to change its password")),
    ("STATUS_WRONG_PASSWORD", 0xC000006A, _verdict(AuthOutcome.WRONG_SECRET, "wrong password")),
    ("STATUS_LOGON_FAILURE", 0xC000006D, _verdict(AuthOutcome.WRONG_SECRET, "logon failure")),
    ("STATUS_NTLM_BLOCKED", 0xC0000418, _verdict(AuthOutcome.METHOD_OR_CONFIG, "NTLM blocked by policy")),
    ("STATUS_ACCOUNT_RESTRICTION", 0xC000006E, _verdict(AuthOutcome.METHOD_OR_CONFIG, "account restricts NTLM (Protected Users)")),
    ("STATUS_INVALID_PARAMETER", 0xC000000D, _verdict(AuthOutcome.METHOD_OR_CONFIG, "message rejected (MIC or flags)")),
    ("STATUS_NOT_SUPPORTED", 0xC00000BB, _verdict(AuthOutcome.METHOD_OR_CONFIG, "not supported")),
    ("STATUS_DOWNGRADE_DETECTED", 0xC0000388, _verdict(AuthOutcome.METHOD_OR_CONFIG, "downgrade detected")),
    ("STATUS_LOGON_TYPE_NOT_GRANTED", 0xC000015B, _verdict(AuthOutcome.METHOD_OR_CONFIG, "logon type not granted")),
    ("STATUS_INVALID_LOGON_HOURS", 0xC000006F, _verdict(AuthOutcome.UNKNOWN, "outside logon hours")),
    ("STATUS_INVALID_WORKSTATION", 0xC0000070, _verdict(AuthOutcome.UNKNOWN, "workstation restriction")),
    ("STATUS_NO_LOGON_SERVERS", 0xC000005E, _verdict(AuthOutcome.METHOD_OR_CONFIG, "no logon server")),
    ("STATUS_TRUSTED_RELATIONSHIP_FAILURE", 0xC000018D, _verdict(AuthOutcome.METHOD_OR_CONFIG, "trust failure")),
    ("STATUS_TRUSTED_DOMAIN_FAILURE", 0xC000018C, _verdict(AuthOutcome.METHOD_OR_CONFIG, "trust failure")),
)
_HEX_RE = re.compile(r"0x([0-9a-f]{8})\b|\b(c0[0-9a-f]{6})\b", re.IGNORECASE)


def classify_ntlm_status(text: str) -> AuthVerdict:
    """Classify the NTSTATUS a server returned for an NTLM AUTHENTICATE.

    Use it only where the failing step IS the NTLM authenticate carrying a
    password or hash: an SMB session setup over NTLM, or the ``errorCode`` of a
    CredSSP exchange that carried NTLM. Accepts the status name or its hex
    value anywhere in ``text``.
    """
    upper = str(text or "").upper()
    if not upper:
        return _UNKNOWN
    values = set()
    for match in _HEX_RE.finditer(upper):
        raw = match.group(1) or match.group(2)
        try:
            values.add(int(raw, 16))
        except ValueError:
            continue
    for name, value, verdict in _NTSTATUS_TABLE:
        if name in upper or value in values:
            return verdict
    return _UNKNOWN


# --------------------------------------------------------------------------- LDAP

_LDAP_DATA_TABLE: dict[str, AuthVerdict] = {
    "52E": _verdict(AuthOutcome.WRONG_SECRET, "invalid credentials (data 52e)"),
    "775": _verdict(AuthOutcome.ACCOUNT_STATE, "locked out"),
    "533": _verdict(AuthOutcome.ACCOUNT_STATE, "disabled"),
    "701": _verdict(AuthOutcome.ACCOUNT_STATE, "expired"),
    "532": _verdict(AuthOutcome.ACCOUNT_STATE, "required to change its password"),
    "773": _verdict(AuthOutcome.ACCOUNT_STATE, "required to change its password"),
    "525": _verdict(AuthOutcome.METHOD_OR_CONFIG, "user not found"),
    "530": _verdict(AuthOutcome.UNKNOWN, "outside logon hours"),
    "531": _verdict(AuthOutcome.UNKNOWN, "workstation restriction"),
    "80090346": _verdict(AuthOutcome.METHOD_OR_CONFIG, "channel binding required"),
}
_LDAP_DATA_RE = re.compile(r"\bDATA\s+([0-9A-F]+)\b")
_LDAP_METHOD_MARKERS = (
    ("STRONGERAUTHREQUIRED", "signing required"),
    ("STRONG_AUTH_REQUIRED", "signing required"),
    ("SEC_E_BAD_BINDINGS", "channel binding required"),
    ("80090346", "channel binding required"),
    ("CONFIDENTIALITYREQUIRED", "confidentiality required"),
    ("STATUS_NTLM_BLOCKED", "NTLM blocked by policy"),
    ("SEC_E_UNSUPPORTED_FUNCTION", "NTLM blocked by policy"),
)


def classify_ldap_bind(text: str) -> AuthVerdict:
    """Classify a failed NTLM or SIMPLE bind against an AD domain controller.

    ``text`` must include the raw ``diagnosticMessage`` of the bind response
    when the client library kept it (badldap keeps it on
    ``LDAPServerException.diagnostic_message`` while its formatted message drops
    the ``data`` sub-status), so the sub-status can decide. Without one, a bare
    ``invalidCredentials`` / ``SEC_E_LOGON_DENIED`` is UNKNOWN.
    """
    upper = str(text or "").upper()
    if not upper:
        return _UNKNOWN
    for marker, reason in _LDAP_METHOD_MARKERS:
        if marker in upper:
            return _verdict(AuthOutcome.METHOD_OR_CONFIG, reason)
    for match in _LDAP_DATA_RE.finditer(upper):
        verdict = _LDAP_DATA_TABLE.get(match.group(1))
        if verdict is not None:
            return verdict
    return _UNKNOWN


# --------------------------------------------------------------------------- HTTP / GSSAPI

_GSSAPI_TABLE: tuple[tuple[str, AuthVerdict], ...] = (
    ("CLIENT'S CREDENTIALS HAVE BEEN REVOKED", _KERBEROS_AS_TABLE["KDC_ERR_CLIENT_REVOKED"]),
    ("CLIENT’S CREDENTIALS HAVE BEEN REVOKED", _KERBEROS_AS_TABLE["KDC_ERR_CLIENT_REVOKED"]),
    ("PASSWORD HAS EXPIRED", _KERBEROS_AS_TABLE["KDC_ERR_KEY_EXPIRED"]),
    ("PREAUTHENTICATION FAILED", _KERBEROS_AS_TABLE["KDC_ERR_PREAUTH_FAILED"]),
    ("CLOCK SKEW", _KERBEROS_AS_TABLE["KRB_AP_ERR_SKEW"]),
)


def classify_gssapi_acquisition(text: str) -> AuthVerdict:
    """Classify a GSSAPI initial-credential acquisition from a password.

    MIT krb5 surfaces the KDC's AS error as text (``Preauthentication failed``,
    ``Client's credentials have been revoked``). Anything else is UNKNOWN.
    """
    upper = str(text or "").upper()
    for marker, verdict in _GSSAPI_TABLE:
        if marker in upper:
            return verdict
    for name, verdict in _KERBEROS_AS_TABLE.items():
        if name in upper:
            return verdict
    return _UNKNOWN


def classify_http_negotiate(text: str, *, kerberos_password: bool) -> AuthVerdict:
    """Classify a failed WinRM (HTTP Negotiate) sign-in.

    Args:
        text: The exception chain text.
        kerberos_password: The client was handed a password to acquire its own
            Kerberos credential (GSSAPI), so a KDC error may be in the text.

    A plain HTTP 401 carries no reason and is UNKNOWN.
    """
    if kerberos_password:
        return classify_gssapi_acquisition(text)
    return _UNKNOWN


# --------------------------------------------------------------------------- TDS

_TDS_TABLE: tuple[tuple[str, AuthVerdict], ...] = (
    ("CURRENTLY LOCKED OUT", _verdict(AuthOutcome.ACCOUNT_STATE, "locked out")),
    ("THE ACCOUNT IS DISABLED", _verdict(AuthOutcome.ACCOUNT_STATE, "disabled")),
    ("PASSWORD OF THE ACCOUNT HAS EXPIRED", _verdict(AuthOutcome.ACCOUNT_STATE, "required to change its password")),
    ("PASSWORD OF THE ACCOUNT MUST BE CHANGED", _verdict(AuthOutcome.ACCOUNT_STATE, "required to change its password")),
)


def classify_tds_login(text: str) -> AuthVerdict:
    """Classify the reply to a failed TDS LOGIN7 (SQL or integrated logon).

    SQL Server deliberately hides why a login failed (18456 state 1, or 18452
    for an integrated logon), so only the explicit account-state messages are
    acted on; everything else is UNKNOWN.
    """
    upper = str(text or "").upper()
    for marker, verdict in _TDS_TABLE:
        if marker in upper:
            return verdict
    return _UNKNOWN
