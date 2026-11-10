"""Plain-language explanations for why an attack-path step did not complete.

The single source of truth that turns a protocol error (a Kerberos error name, an
LDAP result code, an NTSTATUS, a certificate-authority disposition) or an ADscan
readiness reason into two layers an operator and a client can both read:

* a high-level ``headline`` ("The domain controller did not accept certificate
  sign-in"), the ``detail`` that explains what that means, and a ``next_step``;
* the technical ``code`` it was derived from (``KDC_ERR_PADATA_TYPE_NOSUPP``).

The CLI renders it and embeds the same view in the execution event, so the web
shows the identical words. Every entry also names the coarse
:class:`~adscan_core.reporting.attack_step_reason_codes.ReasonCode` category it
belongs to, so the report and the web keep one vocabulary for the cause.

Rules every entry follows (Exposure-Validation doctrine and client-safe prose):

* It states what the environment answered, never that a security product
  stopped the step. A closed connection is "the remote host closed the
  connection", not "the EDR blocked it".
* No offensive-tool names, no em dashes. English only.
* An unknown error yields ``None`` from :func:`explain_failure`; callers fall
  back to the reason-code note and never invent a cause.

Pure data and string matching. No IO. Safe to import from ``adscan_core``, the
LITE runtime, the PRO renderer and the web backend.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

from adscan_core.reporting.attack_step_reason_codes import (
    ReasonCode,
    normalize_reason_code,
    reason_code_client_note,
)


@dataclass(frozen=True)
class FailureExplanation:
    """Two-layer explanation of a step that did not complete."""

    #: Canonical technical code shown in the technical layer.
    code: str
    #: Coarse cause category (a :class:`ReasonCode` value).
    reason_code: str
    #: One plain sentence: what happened, in the environment's terms.
    headline: str
    #: What it means for this step.
    detail: str
    #: What the operator can do next.
    next_step: str

    def to_view(self) -> dict[str, str]:
        """Return the render-ready dict carried in execution events."""
        return {
            "code": self.code,
            "reason_code": self.reason_code,
            "headline": self.headline,
            "detail": self.detail,
            "next_step": self.next_step,
        }


@dataclass(frozen=True)
class _Entry:
    code: str
    aliases: tuple[str, ...]
    reason_code: ReasonCode
    headline: str
    detail: str
    next_step: str


_AUTH = ReasonCode.AUTH_FAILED
_UNREACHABLE = ReasonCode.TARGET_UNREACHABLE
_REJECTED = ReasonCode.REJECTED
_NOT_AUTOMATED = ReasonCode.NOT_AUTOMATED

# Ordered: the first entry whose code or alias appears in the text wins, so the
# more specific codes come first (a PKINIT error before a generic logon failure).
_ENTRIES: tuple[_Entry, ...] = (
    # ── Kerberos: certificate sign-in (PKINIT) ──────────────────────────────
    _Entry(
        "KDC_ERR_PADATA_TYPE_NOSUPP",
        ("PADATA_TYPE_NOSUPP",),
        _AUTH,
        "The domain controller did not accept certificate sign-in.",
        "The certificate was obtained, but the domain controller does not offer "
        "Kerberos certificate authentication (PKINIT). This usually means the "
        "domain controller holds no certificate valid for Kerberos authentication.",
        "Authenticate with the certificate over LDAPS instead, or retry once the "
        "domain controllers hold a Kerberos Authentication certificate.",
    ),
    _Entry(
        "KDC_ERR_CLIENT_NOT_TRUSTED",
        ("CLIENT_NOT_TRUSTED",),
        _AUTH,
        "The domain controller did not trust the certificate.",
        "The domain controller rejected the certificate chain. Typical causes are "
        "an issuing authority that is not in the enterprise NTAuth store, or a "
        "clock difference with the domain controller at sign-in time.",
        "Confirm the issuing CA is trusted for authentication and that the host "
        "clock matches the domain controller, then retry the step.",
    ),
    _Entry(
        "KDC_ERR_INCONSISTENT_KEY_PURPOSE",
        ("INCONSISTENT_KEY_PURPOSE", "KDC_ERR_CERTIFICATE_MISMATCH"),
        _AUTH,
        "The certificate is not valid for signing in.",
        "The domain controller read the certificate but its usage does not allow "
        "client authentication, or it does not map to the requested account.",
        "Request the certificate from a template whose usage allows client "
        "authentication, or authenticate it over LDAPS.",
    ),
    # ── Kerberos: account and key ───────────────────────────────────────────
    _Entry(
        "KDC_ERR_PREAUTH_FAILED",
        ("PREAUTH_FAILED",),
        _AUTH,
        "The domain controller rejected the credential.",
        "The password or key used for this account is not the current one.",
        "Refresh the stored credential for this account and retry the step.",
    ),
    _Entry(
        "KDC_ERR_CLIENT_REVOKED",
        ("CLIENT_REVOKED",),
        _AUTH,
        "The account cannot sign in right now.",
        "The domain controller reports the account as disabled, locked out or "
        "expired.",
        "Check the account state in the directory; use another controlled "
        "account for this step.",
    ),
    _Entry(
        "KDC_ERR_KEY_EXPIRED",
        ("KEY_EXPIRED",),
        _AUTH,
        "The account password has expired.",
        "The domain controller requires a password change before this account can "
        "sign in.",
        "Use another controlled account, or record the expired password as a "
        "finding and continue with the next path.",
    ),
    _Entry(
        "KDC_ERR_C_PRINCIPAL_UNKNOWN",
        ("C_PRINCIPAL_UNKNOWN",),
        _AUTH,
        "The domain controller does not know this account.",
        "The account name used for sign-in does not exist in the domain that was "
        "asked, often because the account lives in another domain.",
        "Confirm which domain owns the account and retry against that domain.",
    ),
    _Entry(
        "KDC_ERR_S_PRINCIPAL_UNKNOWN",
        ("S_PRINCIPAL_UNKNOWN",),
        _REJECTED,
        "The domain controller does not know the requested service.",
        "No account in the directory carries the service name that was requested, "
        "so no ticket can be issued for it.",
        "Check the service name and the target host name; retry with the host's "
        "fully qualified name.",
    ),
    _Entry(
        "KDC_ERR_ETYPE_NOSUPP",
        ("ETYPE_NOSUPP", "ETYPE_NOTSUPP"),
        _AUTH,
        "The domain controller refused the requested encryption type.",
        "The account or the domain only allows encryption types that the request "
        "did not offer.",
        "Retry the step; ADscan adapts to the domain's encryption policy once it "
        "has observed it.",
    ),
    _Entry(
        "KDC_ERR_BADOPTION",
        ("ERR_BADOPTION",),
        _REJECTED,
        "The domain controller refused the delegation request.",
        "The account is not allowed to obtain a ticket on behalf of the requested "
        "user, or that user is marked as sensitive and cannot be delegated.",
        "Pick a target user that can be delegated, or record the protected "
        "account as a mitigating configuration.",
    ),
    _Entry(
        "KDC_ERR_POLICY",
        ("ERR_POLICY",),
        _REJECTED,
        "The domain controller refused the request by policy.",
        "A logon restriction applies to this account, for example membership in "
        "a protected group or a workstation restriction.",
        "Check the account's logon restrictions and use another controlled "
        "account for this step.",
    ),
    _Entry(
        "KDC_ERR_WRONG_REALM",
        ("ERR_WRONG_REALM",),
        _AUTH,
        "The request reached a domain controller of another domain.",
        "The account or service belongs to a different Kerberos domain than the "
        "domain controller that answered.",
        "Retry against a domain controller of the account's own domain.",
    ),
    _Entry(
        "KRB_AP_ERR_SKEW",
        ("AP_ERR_SKEW", "CLOCK SKEW TOO GREAT"),
        _AUTH,
        "The host clock is too far from the domain controller.",
        "Kerberos accepts at most five minutes of difference between the two "
        "clocks.",
        "Synchronize the host clock with the domain controller and retry.",
    ),
    _Entry(
        "KRB_AP_ERR_MODIFIED",
        ("AP_ERR_MODIFIED",),
        _AUTH,
        "The target service could not read the ticket.",
        "The ticket was issued for a service name that maps to a different key "
        "than the one the target host uses.",
        "Retry using the target host's fully qualified name.",
    ),
    _Entry(
        "KRB_AP_ERR_TKT_EXPIRED",
        ("TKT_EXPIRED",),
        _AUTH,
        "The Kerberos ticket expired during the step.",
        "The ticket used by the step reached its end of life before the target "
        "accepted it.",
        "Retry the step; a fresh ticket is requested automatically.",
    ),
    # ── Certificate authority ───────────────────────────────────────────────
    _Entry(
        "CERTSRV_E_TEMPLATE_DENIED",
        ("TEMPLATE_DENIED",),
        _REJECTED,
        "The certificate authority denied enrollment on this template.",
        "The account does not hold enrollment rights on the template at this "
        "certificate authority.",
        "Confirm which principal holds enrollment rights and run the step as that "
        "principal.",
    ),
    _Entry(
        "CERTSRV_E_UNSUPPORTED_CERT_TYPE",
        ("UNSUPPORTED_CERT_TYPE",),
        _REJECTED,
        "The certificate authority does not issue this template.",
        "The template exists in the directory but is not published on the "
        "certificate authority that received the request.",
        "Retry against a certificate authority that publishes the template.",
    ),
    _Entry(
        "CR_DISP_UNDER_SUBMISSION",
        ("UNDER_SUBMISSION", "REQUEST IS PENDING", "TAKEN UNDER SUBMISSION"),
        _REJECTED,
        "The certificate request is waiting for approval.",
        "The template requires a certificate manager to approve each request, so "
        "no certificate was issued during the step.",
        "Record the approval requirement as a mitigating configuration; the step "
        "cannot complete unattended.",
    ),
    _Entry(
        "CR_DISP_DENIED",
        ("DISP_DENIED", "REQUEST WAS DENIED"),
        _REJECTED,
        "The certificate authority denied the request.",
        "The certificate authority evaluated the request and refused to issue a "
        "certificate.",
        "Review the request details in the technical log and the template's "
        "issuance requirements.",
    ),
    # ── LDAP ────────────────────────────────────────────────────────────────
    _Entry(
        "insufficientAccessRights",
        ("INSUFFICIENT_ACCESS_RIGHTS", "INSUFFICIENTACCESSRIGHTS", "ERROR_DS_INSUFF_ACCESS_RIGHTS"),
        _REJECTED,
        "The directory refused the change for this account.",
        "The account used for the step does not hold the right on the target "
        "object that the change requires.",
        "Confirm the right is held by the account that ran the step, or run it as "
        "the principal that holds it.",
    ),
    _Entry(
        "strongerAuthRequired",
        ("STRONGERAUTHREQUIRED", "STRONG_AUTH_REQUIRED"),
        _REJECTED,
        "The directory requires a signed or encrypted connection.",
        "The domain controller enforces LDAP signing or channel binding and "
        "refused an unsigned request.",
        "Retry the step; ADscan switches to a signed connection once it has "
        "observed the requirement.",
    ),
    _Entry(
        "constraintViolation",
        ("CONSTRAINTVIOLATION", "CONSTRAINT_VIOLATION"),
        _REJECTED,
        "The directory rejected the value that was written.",
        "The change broke a constraint on the attribute, such as a password "
        "policy or a single-value rule.",
        "Review the attempted value in the technical log; retry with a value the "
        "policy accepts.",
    ),
    _Entry(
        "unwillingToPerform",
        ("UNWILLINGTOPERFORM", "UNWILLING_TO_PERFORM"),
        _REJECTED,
        "The directory declined the operation.",
        "The domain controller refused to perform this change on the object, for "
        "example on a protected or system-owned object.",
        "Review the target object; the step may not apply to it.",
    ),
    _Entry(
        "noSuchObject",
        ("NOSUCHOBJECT", "NO_SUCH_OBJECT"),
        _REJECTED,
        "The target object was not found in the directory.",
        "The object the step acts on no longer exists or lives under another "
        "distinguished name.",
        "Refresh the directory data and retry the path.",
    ),
    _Entry(
        "invalidCredentials",
        ("INVALIDCREDENTIALS", "SEC_E_LOGON_DENIED"),
        _AUTH,
        "The directory rejected the credential.",
        "The domain controller did not accept the credential presented for this "
        "account.",
        "Refresh the stored credential for this account and retry the step.",
    ),
    # ── SMB / NTSTATUS ──────────────────────────────────────────────────────
    _Entry(
        "STATUS_ACCOUNT_LOCKED_OUT",
        ("0XC0000234",),
        _AUTH,
        "The account is locked out.",
        "The host refused sign-in because the account is locked.",
        "Wait for the lockout window to expire or use another controlled account.",
    ),
    _Entry(
        "STATUS_ACCOUNT_DISABLED",
        ("0XC0000072",),
        _AUTH,
        "The account is disabled.",
        "The host refused sign-in because the account is disabled in the "
        "directory.",
        "Use another controlled account for this step.",
    ),
    _Entry(
        "STATUS_PASSWORD_EXPIRED",
        ("0XC0000071",),
        _AUTH,
        "The account password has expired.",
        "The host refused sign-in until the password is changed.",
        "Use another controlled account for this step.",
    ),
    _Entry(
        "STATUS_ACCOUNT_RESTRICTION",
        ("0XC000006E",),
        _AUTH,
        "A sign-in restriction applies to this account.",
        "The account is not allowed to sign in this way, for example because of "
        "a blank password rule or a logon-hours restriction.",
        "Use another controlled account for this step.",
    ),
    _Entry(
        "STATUS_NTLM_BLOCKED",
        ("0XC0000418",),
        _AUTH,
        "The host does not accept NTLM sign-in.",
        "The target only allows Kerberos for this kind of sign-in.",
        "Retry the step; ADscan uses Kerberos once it has observed the policy.",
    ),
    _Entry(
        "STATUS_LOGON_FAILURE",
        ("0XC000006D", "LOGON_FAILURE"),
        _AUTH,
        "The host rejected the credential.",
        "The target did not accept the credential presented for this account.",
        "Refresh the stored credential for this account and retry the step.",
    ),
    _Entry(
        "STATUS_ACCESS_DENIED",
        ("0XC0000022", "ACCESS_DENIED", "ACCESS IS DENIED"),
        _REJECTED,
        "The host denied access for this account.",
        "The account signed in but does not hold the right the step needs on the "
        "target, such as local administrator rights.",
        "Confirm the account's rights on the target, or run the step as an "
        "account that holds them.",
    ),
    _Entry(
        "STATUS_BAD_NETWORK_NAME",
        ("0XC00000CC", "BAD_NETWORK_NAME"),
        _REJECTED,
        "The requested share does not exist on the host.",
        "The step needs a share or service that the target does not expose.",
        "Confirm the target host is the right one for this step.",
    ),
    _Entry(
        "STATUS_PIPE_BROKEN",
        ("0XC000014B", "PIPE_BROKEN", "CONNECTION RESET BY PEER"),
        _REJECTED,
        "The remote host closed the connection during the operation.",
        "The target ended the session before the step completed. The cause is not "
        "visible from the network.",
        "Retry the step; if it repeats, check the target host's state and logs.",
    ),
    # ── Reachability ────────────────────────────────────────────────────────
    _Entry(
        "CONNECTION_REFUSED",
        ("CONNECTIONREFUSED", "CONNECTION REFUSED", "ECONNREFUSED"),
        _UNREACHABLE,
        "The target refused the connection.",
        "Nothing was listening on the port the step needs, or the connection was "
        "refused before any sign-in.",
        "Check the service is running on the target and reachable from this "
        "vantage point.",
    ),
    _Entry(
        "TIMEOUT",
        ("TIMED OUT", "TIMEDOUT", "TIMEOUTERROR", "STATUS_IO_TIMEOUT"),
        _UNREACHABLE,
        "The target did not answer in time.",
        "The step waited for the target and received no answer within its time "
        "budget.",
        "Check reachability from this vantage point and retry the step.",
    ),
    _Entry(
        "NETWORK_UNREACHABLE",
        ("NETWORK IS UNREACHABLE", "NO ROUTE TO HOST", "HOST IS UNREACHABLE"),
        _UNREACHABLE,
        "The target is not reachable from this vantage point.",
        "There is no network route from the scanning host to the target.",
        "Run the step from a vantage point with a route to the target, or through "
        "a pivot.",
    ),
    # ── ADscan readiness reasons (exact tokens) ─────────────────────────────
    _Entry(
        "source_principal_not_controlled",
        (),
        _AUTH,
        "The step starts from an account that is not controlled yet.",
        "The preceding step that grants control of this account has not "
        "succeeded, so ADscan did not run this one as another principal.",
        "Complete the preceding step first, then retry the path.",
    ),
    _Entry(
        "no_usable_execution_context",
        ("missing stored credential", "missing execution user context", "no stored domain credential"),
        _AUTH,
        "No stored credential can run this step.",
        "ADscan holds no credential for the account this step must run as.",
        "Obtain a credential for one of the affected accounts, then retry.",
    ),
    _Entry(
        "no_session_for_required_privilege",
        ("no session or credential provides the required privilege",),
        _AUTH,
        "No proven session on the host gives this step the privilege it needs.",
        "This step runs inside a session that a preceding access step proves on "
        "the host, and no such session or stored credential was available.",
        "Complete the access step that grants it on this host, then retry the path.",
    ),
    _Entry(
        "proven_access_holder_unresolved",
        ("the account holding the proven access could not be resolved",),
        _AUTH,
        "The account holding the proven access could not be identified.",
        "A preceding step proved this access on the host, but ADscan could not "
        "tell which account holds it, so it did not run the step as a different "
        "account.",
        "Check the access step's source principal in the attack graph, then retry "
        "the path.",
    ),
    _Entry(
        "missing_target_host",
        ("missing pdc ip", "missing adcs/ca info"),
        _UNREACHABLE,
        "The step's target could not be resolved.",
        "The data needed to address the target of this step was not collected in "
        "this scan.",
        "Re-run collection for this domain, then retry the path.",
    ),
)

_MATCHERS: tuple[tuple[_Entry, re.Pattern[str]], ...] = tuple(
    (
        entry,
        re.compile(
            "|".join(
                rf"(?<![A-Z0-9_]){re.escape(token.upper())}(?![A-Z0-9_])"
                for token in (entry.code, *entry.aliases)
            )
        ),
    )
    for entry in _ENTRIES
)

_BY_CODE: dict[str, _Entry] = {entry.code.lower(): entry for entry in _ENTRIES}

#: Every canonical code this module explains (for contract tests and docs).
KNOWN_FAILURE_CODES: frozenset[str] = frozenset(entry.code for entry in _ENTRIES)


def _to_explanation(entry: _Entry) -> FailureExplanation:
    return FailureExplanation(
        code=entry.code,
        reason_code=entry.reason_code.value,
        headline=entry.headline,
        detail=entry.detail,
        next_step=entry.next_step,
    )


def _iter_texts(values: Iterable[Any]) -> Iterable[str]:
    for value in values:
        if value is None:
            continue
        if isinstance(value, BaseException):
            seen: set[int] = set()
            current: BaseException | None = value
            while current is not None and id(current) not in seen:
                seen.add(id(current))
                yield f"{type(current).__name__}: {current}"
                current = current.__cause__ or current.__context__
            continue
        if isinstance(value, dict):
            yield from _iter_texts(value.values())
            continue
        if isinstance(value, (list, tuple, set)):
            yield from _iter_texts(value)
            continue
        text = str(value).strip()
        if text:
            yield text


def explain_failure(*sources: Any) -> FailureExplanation | None:
    """Return the explanation for the first known error found in ``sources``.

    Accepts any mix of strings, exceptions (their cause chain is walked), dicts
    (values are scanned, e.g. an edge's ``notes``) and lists. Returns ``None``
    when nothing recognisable is present, so the caller can fall back to a
    reason-code note instead of guessing.
    """

    texts = [text.upper() for text in _iter_texts(sources)]
    if not texts:
        return None
    for text in texts:
        exact = _BY_CODE.get(text.strip().lower())
        if exact is not None:
            return _to_explanation(exact)
    blob = "\n".join(texts)
    for entry, pattern in _MATCHERS:
        if pattern.search(blob):
            return _to_explanation(entry)
    return None


def explain_by_code(code: Any) -> FailureExplanation | None:
    """Return the explanation for a canonical code, or ``None`` when unknown."""

    entry = _BY_CODE.get(str(code or "").strip().lower())
    return _to_explanation(entry) if entry is not None else None


def failure_view(*sources: Any, reason_code: Any = None) -> dict[str, str]:
    """Return the render-ready failure view, never raising.

    Resolution order: a recognised protocol / readiness code in ``sources``;
    else the client note of ``reason_code``; else an empty view (``headline``
    empty), which renderers treat as "no recorded cause".
    """

    explanation = explain_failure(*sources)
    if explanation is not None:
        return explanation.to_view()
    token = normalize_reason_code(reason_code)
    note = reason_code_client_note(token)
    if note:
        return {
            "code": "",
            "reason_code": token,
            "headline": note,
            "detail": "",
            "next_step": "",
        }
    return {"code": "", "reason_code": "", "headline": "", "detail": "", "next_step": ""}


__all__ = [
    "FailureExplanation",
    "KNOWN_FAILURE_CODES",
    "explain_by_code",
    "explain_failure",
    "failure_view",
]
