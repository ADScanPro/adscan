"""NoPac (CVE-2021-42278 / CVE-2021-42287) native check — netexec parity.

Detection-only. Mirrors ``reference/NetExec/nxc/modules/nopac.py:21-55``:
request a TGT for the authenticated user with ``requestPAC=True``, then
again with ``requestPAC=False``. On vulnerable DCs the no-PAC TGT is
strictly smaller than the with-PAC TGT — patched DCs return TGTs of the
same shape.

Restrictive-AD constraints (per ``adscan-ad-constraints``):

* The TGT is issued by the **auth_domain's** KDC (where the user lives).
  In cross-realm scenarios the *target_domain* DC is not where the AS-REQ
  goes — the user does not exist there. We therefore probe against
  ``auth_domain`` / ``auth_kdc_ip`` (defaulting to the target host when
  same-realm). When ``auth_domain != target_domain`` and no auth-realm
  KDC is reachable from the target, the check returns ``SKIPPED`` with
  a documented reason rather than ``ERROR`` so per-target SKIP semantics
  flow up to the lab harness.
* Etype order is AES-first then RC4 (``[18, 17, 23]``), required on
  AES-only KDCs. The ETYPE-INFO2 salt probe in ``kerberos_transport``
  is implicit when ``get_tgt`` is the production provider.
* Clock skew is handled inside ``kerberos_transport.get_tgt`` via
  kerbad's ``with_clock_skew``; no manual retry needed here.
* NTLM hashes are accepted as a Kerberos pre-auth credential (RC4 key
  derived from the NT hash) — ``KerberosConfig.nt_hash`` covers this
  path; we never bail because plaintext is missing.
"""

from __future__ import annotations

import asyncio
from binascii import unhexlify
from typing import TYPE_CHECKING, Any, Callable

from adscan_core import telemetry
from adscan_core.rich_output import print_error, print_info_verbose
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.cve_scanner.result import (
    CVEResult,
    CVEStatus,
    Evidence,
    Severity,
)
from adscan_core.rich_output import print_exception

if TYPE_CHECKING:  # pragma: no cover
    from adscan_internal.services.cve_scanner.runner import ScanContext, ScanTarget


CVE_ID = "CVE-2021-42278"
AKA = "NoPac"
CVSS_V3 = 8.8
CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"

# AES-first etype order: required on AES-only KDCs (RC4 disabled by GPO).
# kerbad / impacket honor the negotiation order; AES is preferred, RC4 falls
# through automatically when the KDC permits it.
_AES_FIRST_ETYPES: tuple[int, ...] = (18, 17, 23)


def _to_hash_bytes(value: str | None) -> bytes:
    """Decode a hex hash string to bytes; empty bytes if blank/None."""
    if not value:
        return b""
    try:
        return unhexlify(value)
    except Exception:  # noqa: BLE001
        return b""


def _request_tgt_pair_impacket(
    *,
    username: str,
    password: str | None,
    domain: str,
    lmhash: str | None,
    nthash: str | None,
    aes_key: str | None,
    kdc_host: str,
) -> tuple[bytes, bytes]:
    """Synchronous fallback using impacket's ``getKerberosTGT``.

    Used when the native ``kerberos_transport`` provider is unavailable
    (test injection / module missing). Source citation:
    ``reference/NetExec/nxc/modules/nopac.py:28-48``.
    """
    from impacket.krb5 import constants
    from impacket.krb5.kerberosv5 import getKerberosTGT
    from impacket.krb5.types import Principal

    user_principal = Principal(
        username, type=constants.PrincipalNameType.NT_PRINCIPAL.value  # pylint: disable=no-member
    )
    lm_b = _to_hash_bytes(lmhash)
    nt_b = _to_hash_bytes(nthash)

    tgt_with_pac, _, _, _ = getKerberosTGT(
        user_principal,
        password or "",
        domain,
        lm_b,
        nt_b,
        aes_key or "",
        kdc_host,
        requestPAC=True,
    )
    tgt_no_pac, _, _, _ = getKerberosTGT(
        user_principal,
        password or "",
        domain,
        lm_b,
        nt_b,
        aes_key or "",
        kdc_host,
        requestPAC=False,
    )
    return tgt_with_pac, tgt_no_pac


def _request_tgt_pair_native(
    *,
    username: str,
    password: str | None,
    domain: str,
    lmhash: str | None,  # noqa: ARG001 — accepted for provider-signature parity
    nthash: str | None,
    aes_key: str | None,
    kdc_host: str,
) -> tuple[bytes, bytes]:
    """Production TGT-pair provider using ADscan's ``kerberos_transport``.

    Calls ``get_tgt`` twice: once with ``requestPAC=True`` and once with
    ``requestPAC=False``. Internally this triggers the ETYPE-INFO2 salt
    probe (AES-only KDC support) and ``with_clock_skew`` retry, both
    required by the AD-constraints checklist.

    Returns a pair of raw TGT bytes (extracted from the ccache wrapper)
    so the size differential check matches netexec's parity contract.
    """
    from adscan_internal.services.kerberos_transport import (  # noqa: PLC0415
        KerberosConfig,
        get_tgt,
    )

    async def _one(*, request_pac: bool) -> bytes:
        cfg = KerberosConfig(
            domain=domain,
            kdc_ip=kdc_host,
            username=username,
            password=password,
            nt_hash=nthash,
            aes_key=aes_key,
            etypes=list(_AES_FIRST_ETYPES),
        )
        # ``get_tgt`` uses kerbad which always sets ``include-pac=True``
        # in the KDC-REQ-BODY KDCOptions. To probe the no-PAC variant we
        # fall back to impacket here (kerbad does not expose the flag);
        # the with-PAC path goes through the native wrapper so the salt
        # probe and clock-skew retry are exercised at least once per
        # target.
        if request_pac:
            ccache_bytes = await get_tgt(cfg)
            return _extract_tgt_from_ccache(ccache_bytes)
        # Mirror with the same credential plumbing but request PAC=False.
        return await asyncio.to_thread(
            _request_one_tgt_impacket_no_pac,
            username=username,
            password=password,
            domain=domain,
            nthash=nthash,
            aes_key=aes_key,
            kdc_host=kdc_host,
        )

    async def _both() -> tuple[bytes, bytes]:
        with_pac = await _one(request_pac=True)
        no_pac = await _one(request_pac=False)
        return with_pac, no_pac

    return asyncio.run(_both())


def _extract_tgt_from_ccache(ccache_bytes: bytes) -> bytes:
    """Pull the raw AS-REP TGT bytes out of a serialized ccache.

    ``getKerberosTGT`` returns the AS-REP DER directly; ``get_tgt`` returns
    the wrapped ccache file. To keep the size differential meaningful
    (it is the *ticket* size that matters, not the ccache wrapper) we
    parse the ccache and serialise the first credential's ticket.
    """
    from kerbad.common.ccache import CCACHE  # noqa: PLC0415

    ccache = CCACHE.from_bytes(ccache_bytes)
    if not ccache.credentials:
        return ccache_bytes
    return bytes(ccache.credentials[0].ticket.to_bytes())


def _request_one_tgt_impacket_no_pac(
    *,
    username: str,
    password: str | None,
    domain: str,
    nthash: str | None,
    aes_key: str | None,
    kdc_host: str,
) -> bytes:
    """One-shot impacket call for the no-PAC half of the pair."""
    from impacket.krb5 import constants
    from impacket.krb5.kerberosv5 import getKerberosTGT
    from impacket.krb5.types import Principal

    user_principal = Principal(
        username, type=constants.PrincipalNameType.NT_PRINCIPAL.value  # pylint: disable=no-member
    )
    nt_b = _to_hash_bytes(nthash)
    tgt_no_pac, _, _, _ = getKerberosTGT(
        user_principal,
        password or "",
        domain,
        b"",
        nt_b,
        aes_key or "",
        kdc_host,
        requestPAC=False,
    )
    return tgt_no_pac


class NoPacCheck:
    """Detection-only NoPac probe via Kerberos TGT-size differential.

    The default provider chain is:

    1. ``kerberos_transport.get_tgt`` (production native path) for the
       with-PAC TGT — exercises ETYPE-INFO2 salt probe, AES-first etype
       order, and clock-skew retry.
    2. impacket ``getKerberosTGT(requestPAC=False)`` for the no-PAC TGT
       (kerbad does not currently expose the no-PAC flag).

    Cross-realm policy: TGTs are issued by the **auth_domain's** KDC.
    When ``auth_domain != target_domain`` we route the AS-REQ to the
    auth_domain KDC (creds come with ``kdc_ip``, the auth-realm KDC).
    If only the target_domain DC IP is known and the user does not live
    there, the probe returns ``SKIPPED`` with a documented reason
    (``creds for auth_domain not authorized by target_domain KDC``).
    """

    cve_id: str = CVE_ID

    def __init__(
        self,
        *,
        tgt_pair_provider: Callable[..., tuple[bytes, bytes]] | None = None,
    ) -> None:
        # Default to the native kerberos_transport provider; tests inject
        # a stub (see ``tests/unit/.../test_nopac.py``).
        if tgt_pair_provider is None:
            self._tgt_pair_provider: Callable[..., tuple[bytes, bytes]] = (
                _request_tgt_pair_native
            )
        else:
            self._tgt_pair_provider = tgt_pair_provider

    async def run(
        self,
        target: "ScanTarget",
        creds: Any | None,
        ctx: "ScanContext",
    ) -> list[CVEResult]:
        """Run the NoPac probe against ``target`` (must be a DC).

        Args:
            target: The DC to probe. Non-DC targets short-circuit to
                NotApplicable.
            creds: ADscan credential object. Recognised attributes:
                ``username`` (required), ``password`` / ``nt_hash`` /
                ``aes_key``, ``domain`` (== ``auth_domain`` — where the
                user lives), ``target_domain`` (the realm being attacked),
                ``kdc_ip`` (auth-realm KDC; defaults to ``target.host``
                when same-realm).
            ctx: Scan context (used as a fallback for ``domain``).
        """
        if not target.is_dc:
            return [_not_applicable(target.host, "NoPac only applies to DCs")]
        if creds is None:
            return [_error(target.host, "NoPac detection requires authenticated creds")]

        username = getattr(creds, "username", None)
        if not username:
            return [_error(target.host, "NoPac requires a username to request TGTs")]

        # auth_domain: where the user lives (== creds.domain). The TGT is
        # always issued by this realm's KDC. target_domain is informational —
        # it tells us whether the lab harness wanted a cross-realm probe.
        auth_domain = (
            getattr(creds, "auth_domain", None)
            or getattr(creds, "domain", None)
            or ctx.domain
        )
        target_domain = (
            getattr(creds, "target_domain", None) or ctx.domain or auth_domain
        )
        if not auth_domain:
            return [_error(target.host, "NoPac: auth_domain not resolvable")]

        # KDC selection: prefer an explicit auth-realm KDC; fall back to
        # the target host (correct for same-realm). Cross-realm with no
        # auth-realm KDC reachable is a SKIP, not an ERROR.
        cross_realm = (
            target_domain is not None and target_domain.lower() != auth_domain.lower()
        )
        kdc_host = (
            getattr(creds, "auth_kdc_ip", None)
            or getattr(creds, "kdc_ip", None)
            or (target.host if not cross_realm else None)
        )
        if kdc_host is None:
            return [
                _skipped(
                    target.host,
                    f"creds for {auth_domain} not authorized by {target_domain} KDC "
                    "(no cross-realm trust path tested)",
                )
            ]

        password = getattr(creds, "password", None)
        nt_hash = getattr(creds, "nt_hash", None)
        lm_hash = getattr(creds, "lm_hash", None)
        aes_key = getattr(creds, "aes_key", None)

        print_info_verbose(
            "[nopac] requesting TGT pair on "
            f"{mark_sensitive(target.host, 'host')} "
            f"(auth_realm={mark_sensitive(auth_domain, 'domain')}, "
            f"target_realm={mark_sensitive(target_domain or '?', 'domain')}, "
            f"kdc={mark_sensitive(kdc_host, 'host')}, "
            f"user={mark_sensitive(username, 'user')})"
        )

        try:
            # Sync providers run in a worker thread; async-native ones
            # (``_request_tgt_pair_native``) own their own event loop via
            # ``asyncio.run`` internally — both shapes are accepted here.
            tgt_with_pac, tgt_no_pac = await asyncio.to_thread(
                self._tgt_pair_provider,
                username=username,
                password=password,
                domain=auth_domain,
                lmhash=lm_hash,
                nthash=nt_hash,
                aes_key=aes_key,
                kdc_host=kdc_host,
            )
        except OSError as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_error(f"[nopac] Kerberos transport failed: {exc}")
            return [_error(target.host, f"Kerberos transport error: {exc}")]
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            err_text = str(exc)
            err_lower = err_text.lower()
            # Cross-realm credential failures degrade to SKIP per the
            # AD-constraints checklist (auth_domain creds genuinely cannot
            # carry without a real cross-realm trust path).
            if cross_realm and any(
                marker in err_lower
                for marker in (
                    "kdc_err_c_principal_unknown",
                    "kdc_err_s_principal_unknown",
                    "kdc_err_wrong_realm",
                    "kdc_err_preauth_failed",
                )
            ):
                return [
                    _skipped(
                        target.host,
                        f"creds for {auth_domain} not authorized by "
                        f"{target_domain} KDC: {err_text}",
                    )
                ]
            return [_error(target.host, f"TGT request failed: {err_text}")]

        return [
            _result_from_sizes(
                target.host,
                len_with_pac=len(tgt_with_pac),
                len_no_pac=len(tgt_no_pac),
            )
        ]


def _result_from_sizes(host: str, *, len_with_pac: int, len_no_pac: int) -> CVEResult:
    """Map TGT-size differential to a :class:`CVEResult`."""
    base = dict(
        cve_id=CVE_ID,
        aka=AKA,
        host=host,
        cvss_v3=CVSS_V3,
        cvss_vector=CVSS_VECTOR,
        severity=Severity.from_cvss(CVSS_V3),
    )
    payload = {
        "tgt_with_pac_size": len_with_pac,
        "tgt_no_pac_size": len_no_pac,
    }
    if len_no_pac < len_with_pac:
        return CVEResult(
            **base,
            status=CVEStatus.VULNERABLE,
            evidence=Evidence(
                summary=(
                    f"NoPac confirmed: TGT-without-PAC ({len_no_pac} bytes) "
                    f"smaller than TGT-with-PAC ({len_with_pac} bytes)"
                ),
                payload=payload,
            ),
        )
    return CVEResult(
        **base,
        status=CVEStatus.NOT_VULNERABLE,
        evidence=Evidence(
            summary=(
                f"NoPac not vulnerable: TGT sizes equal/inverted "
                f"(with_pac={len_with_pac}, no_pac={len_no_pac})"
            ),
            payload=payload,
        ),
    )


def _not_applicable(host: str, reason: str) -> CVEResult:
    return CVEResult(
        cve_id=CVE_ID,
        aka=AKA,
        host=host,
        status=CVEStatus.NOT_APPLICABLE,
        severity=Severity.from_cvss(CVSS_V3),
        cvss_v3=CVSS_V3,
        cvss_vector=CVSS_VECTOR,
        evidence=Evidence(summary=reason, payload={"reason": reason}),
    )


def _skipped(host: str, reason: str) -> CVEResult:
    """Map a documented per-target skip to a :class:`CVEResult`.

    Used when cross-realm semantics make the probe genuinely undefined
    (e.g. essos creds against a sevenkingdoms KDC with no trust path).
    Distinct from ``ERROR`` so the lab harness counts it correctly.
    """
    return CVEResult(
        cve_id=CVE_ID,
        aka=AKA,
        host=host,
        status=CVEStatus.SKIPPED,
        severity=Severity.from_cvss(CVSS_V3),
        cvss_v3=CVSS_V3,
        cvss_vector=CVSS_VECTOR,
        evidence=Evidence(summary=reason, payload={"reason": reason}),
    )


def _error(host: str, message: str) -> CVEResult:
    return CVEResult(
        cve_id=CVE_ID,
        aka=AKA,
        host=host,
        status=CVEStatus.ERROR,
        severity=Severity.from_cvss(CVSS_V3),
        cvss_v3=CVSS_V3,
        cvss_vector=CVSS_VECTOR,
        error=message,
        evidence=Evidence(summary=f"NoPac error: {message}", payload={}),
    )


__all__ = [
    "AKA",
    "CVE_ID",
    "CVSS_V3",
    "CVSS_VECTOR",
    "NoPacCheck",
]
