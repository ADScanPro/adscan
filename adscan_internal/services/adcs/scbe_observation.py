"""Domain StrongCertificateBindingEnforcement (SCBE) observation — shared SSOT.

The DC strong-certificate-binding posture (KB5014754) is ONE observation that
several ADCS confirmations depend on: ESC14 (weak explicit mapping) reads it today,
and ESC9/ESC10 (implicit mapping on a no-SID / NO_SECURITY_EXTENSION certificate)
need the SAME fact. Before this module each confirmation would read SCBE with its
own fresh Remote-Registry RPC per call, so adding ESC9 naively would probe SCBE
twice in one scan.

This centralizes the OBSERVATION — never the per-ESC verdict. Each confirmation
keeps its OWN predicate over the shared :class:`ScbeVerdict`: ESC14 removes the
weak-mapping avenues under Full and keeps a variant-A write-access edge; ESC9/10
remove on Full and confirm on weak. The decisive value object (the integer SCBE
0/1/2 plus the Schannel ``CertificateMappingMethods`` DWORD) and the classifier
(:func:`classify_scbe_state`) are REUSED from :mod:`esc14_confirmation` — this
module only owns the READ, the per-scan memo, and the ``basis`` extension point.

Two invariants (both mirror the posture-caching doctrine "cache observations,
never cache absences"):

* **Probe once per scan.** A definite WEAK/HARDENED verdict is memoized on the
  session ``shell`` (NOT ``domains_data`` — the ``adcs`` key there already holds
  the enrollment-server host string, and a session attr never reaches
  ``save_workspace_data``), keyed on ``(domain, DC-set signature)``, so a second
  caller in the same scan reuses it.
* **Never cache an absence.** An absent / unreachable / partial read is
  :attr:`ScbeState.UNKNOWN` and is returned WITHOUT being memoized, so it is
  re-probe-eligible: a transient failure leaves no stale HARDENED/WEAK fingerprint.

The ``basis`` field on the returned verdict (:class:`ScbeBasis`) is the extension
point for a behavioral upgrade: ESC9's canary can turn an UNKNOWN-registry verdict
into an effective HARDENED/WEAK verdict carrying ``basis=BEHAVIORAL`` for its own
decision (a code-66 PKINIT refusal of a self no-SID certificate is an OBSERVATION,
not an absence). This module only performs REGISTRY reads (``basis=REGISTRY``); the
behavioral upgrade is constructed by the ESC9 driver and is NOT written back into
the shared memo, so the registry observation ESC14 relies on is never contaminated.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from adscan_internal import telemetry
from adscan_core.rich_output import (
    mark_sensitive,
    print_info_debug,
)
from adscan_internal.services.adcs.esc14_confirmation import (
    Esc14DcReading,
    ScbeBasis,
    ScbeState,
    ScbeVerdict,
    classify_scbe_state,
)

#: Session ``shell`` attribute holding the per-scan SCBE observation memo:
#: ``{(domain_norm, dc_set_signature): ScbeVerdict}``. On the shell (never in
#: ``domains_data``) so it never reaches ``save_workspace_data`` and can hold the
#: ``ScbeVerdict`` dataclass directly (no JSON concern).
_SCBE_MEMO_ATTR = "_scbe_observation_memo"

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _memo(shell: Any) -> dict:
    """Return (lazily creating) the per-scan SCBE observation memo on ``shell``."""
    memo = getattr(shell, _SCBE_MEMO_ATTR, None)
    if not isinstance(memo, dict):
        memo = {}
        try:
            setattr(shell, _SCBE_MEMO_ATTR, memo)
        except Exception:  # noqa: BLE001 — shell may be a stub in tests
            return {}
    return memo


def _dc_set_signature(domain_data: dict, dc_ip: Optional[str]) -> str:
    """Build a stable per-scan key for the DC set the read would target.

    Derived from the alias-aware DC-set SSOT so two calls in the same scan share a
    memo entry, and a lab whose DC set changes mid-session re-probes. Falls back to
    the resolved ``dc_ip`` when no DC record is known yet.
    """
    try:
        from adscan_internal.models.domain import (
            resolve_dc_ip,
            resolve_domain_controllers,
        )

        dcs = resolve_domain_controllers(domain_data)
        parts: list[str] = []
        for record in dcs.dcs:
            fqdn = str(getattr(record, "fqdn", None) or "").strip().casefold()
            aliases = sorted(
                str(a or "").strip().casefold()
                for a in getattr(record, "aliases", ())
                if str(a or "").strip()
            )
            parts.append(fqdn + "|" + ",".join(aliases))
        if parts:
            return ";".join(sorted(parts))
        fallback = str(dc_ip or resolve_dc_ip(domain_data) or "").strip().casefold()
        return "dcip:" + fallback if fallback else "unknown"
    except Exception:  # noqa: BLE001 — a signature failure must never break the read
        return "unknown"


def resolve_reading_credential(
    shell: Any, domain: str, credential: Any
) -> tuple[Optional[str], Optional[str]]:
    """Return ``(username, secret)`` for the SCBE read (the shared resolver).

    ``secret`` is a password OR an NT hash (both authenticate over SMB/LDAP via the
    canonical PtH path). A Kerberos/ccache-only credential yields no secret here, so
    the confirmation is left a data gap (UNKNOWN) rather than guessed. Lifted from
    the ESC14 phase so the ESC14 pre-check, the SCBE read and the ESC9 driver all
    resolve the credential identically.
    """
    username = getattr(credential, "username", None)
    secret = getattr(credential, "password", None)
    domain_data = getattr(shell, "domains_data", {}).get(domain, {})
    if not isinstance(domain_data, dict):
        domain_data = {}
    if not username:
        username = domain_data.get("username")
    if not secret:
        secret = domain_data.get("password") or domain_data.get("nt_hash")
    return (
        str(username).strip() if username else None,
        str(secret) if secret else None,
    )


def observe_domain_scbe(
    shell: Any,
    domain: str,
    *,
    credential: Any = None,
    dc_ip: Optional[str] = None,
    auth_domain: Optional[str] = None,
    auth_kdc: Optional[str] = None,
) -> ScbeVerdict:
    """Return the domain-wide SCBE posture (registry read, memoized per scan).

    Reads ``StrongCertificateBindingEnforcement`` on every known DC over aiosmb
    Remote Registry and classifies the domain-wide posture. A definite WEAK/HARDENED
    verdict is memoized on the session shell keyed on ``(domain, DC-set signature)``
    so the probe runs ONCE per scan; an UNKNOWN (no credential, or an
    absent/unreachable/partial read) is returned WITHOUT being memoized, so it is
    re-probe-eligible (never a cached absence). The returned verdict carries
    ``basis=REGISTRY``.
    """
    domain_norm = str(domain or "").strip().casefold()
    domain_data = getattr(shell, "domains_data", {}).get(domain, {})
    if not isinstance(domain_data, dict):
        domain_data = {}

    signature = _dc_set_signature(domain_data, dc_ip)
    memo = _memo(shell)
    cached = memo.get((domain_norm, signature))
    if isinstance(cached, ScbeVerdict):
        return cached

    username, secret = resolve_reading_credential(shell, domain, credential)
    if not username or not secret:
        # Data gap, NOT hardening — never memoized, so the next caller re-probes.
        return ScbeVerdict(
            state=ScbeState.UNKNOWN,
            reason=(
                "no usable domain credential to read DC binding enforcement "
                "(data gap)"
            ),
            basis=ScbeBasis.REGISTRY,
        )

    readings, total_dc_count = read_scbe_across_dcs(
        shell,
        domain=domain,
        username=username,
        secret=secret,
        auth_domain=str(auth_domain or domain),
        dc_ip=dc_ip,
        auth_kdc=auth_kdc,
    )
    verdict = classify_scbe_state(readings, total_dc_count=total_dc_count)

    # Cache only a DEFINITE observation. UNKNOWN (an absence / data gap) is never
    # promoted to a false HARDENED/WEAK and is left re-probe-eligible.
    if verdict.state in (ScbeState.WEAK, ScbeState.HARDENED):
        memo[(domain_norm, signature)] = verdict
    return verdict


def read_scbe_across_dcs(
    shell: Any,
    *,
    domain: str,
    username: str,
    secret: str,
    auth_domain: str,
    dc_ip: Optional[str],
    auth_kdc: Optional[str],
) -> tuple[list, int]:
    """Read SCBE on every known DC. Returns ``(readings, total_dc_count)``.

    ``total_dc_count`` is the number of DISTINCT DCs the domain is known to have
    (the DC-set SSOT), so the classifier requires covering ALL of them before it may
    call the domain hardened — a DC that could not be read blocks that verdict.
    """
    from adscan_internal.models.domain import (
        resolve_dc_ip,
        resolve_domain_controllers,
    )
    from adscan_internal.services.certificate_mapping_service import (
        CertificateMappingService,
    )

    domain_data = getattr(shell, "domains_data", {}).get(domain, {})
    if not isinstance(domain_data, dict):
        domain_data = {}

    dcs = resolve_domain_controllers(domain_data)
    targets: list[tuple[Optional[str], Optional[str]]] = []  # (fqdn, ip)
    for record in dcs.dcs:
        fqdn = getattr(record, "fqdn", None)
        ip = next(
            (a for a in getattr(record, "aliases", ()) if _IPV4_RE.match(str(a or ""))),
            None,
        )
        if fqdn or ip:
            targets.append((fqdn, ip))

    total_dc_count = dcs.count
    if not targets:
        fallback_ip = str(dc_ip or resolve_dc_ip(domain_data) or "").strip() or None
        fallback_fqdn_raw = str(
            domain_data.get("dc_fqdn")
            or domain_data.get("pdc_hostname_fqdn")
            or domain_data.get("pdc_hostname")
            or ""
        ).strip()
        # A short hostname is not a usable Kerberos SPN; only keep a dotted FQDN.
        fallback_fqdn = fallback_fqdn_raw if "." in fallback_fqdn_raw else None
        if fallback_ip or fallback_fqdn:
            targets.append((fallback_fqdn, fallback_ip))
            total_dc_count = 1

    service = CertificateMappingService()
    readings: list[Esc14DcReading] = []
    for fqdn, ip in targets:
        readings.append(
            _read_scbe_for_dc(
                service,
                fqdn=fqdn,
                ip=ip,
                username=username,
                secret=secret,
                auth_domain=auth_domain,
                auth_kdc=auth_kdc,
            )
        )
    return readings, total_dc_count


def _read_scbe_for_dc(
    service: Any,
    *,
    fqdn: Optional[str],
    ip: Optional[str],
    username: str,
    secret: str,
    auth_domain: str,
    auth_kdc: Optional[str],
) -> Esc14DcReading:
    """Read SCBE on one DC, preferring Kerberos (FQDN SPN) then NTLM (IP).

    Kerberos-first honours the hardened-environment constraint (NTLM may be
    disabled); the NTLM-over-IP attempt covers a DC whose FQDN does not resolve from
    the container. Either channel reads the same registry DWORDs.
    """
    label = str(fqdn or ip or "")
    attempts: list[tuple[str, bool, Optional[str]]] = []  # (target_host, use_kerberos, kdc)
    if fqdn:
        kdc = str(auth_kdc or ip or "").strip() or None
        attempts.append((fqdn, True, kdc))
    if ip:
        attempts.append((ip, False, None))

    for target_host, use_kerberos, kdc in attempts:
        try:
            state = service.read_dc_binding_state(
                target_host=target_host,
                username=username,
                credential=secret,
                auth_domain=auth_domain,
                use_kerberos=use_kerberos,
                kdc_host=kdc,
            )
        except Exception as exc:  # noqa: BLE001 — try the next channel
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[scbe-observe] SCBE read error on "
                f"{mark_sensitive(target_host, 'host')} "
                f"(kerberos={use_kerberos}): {exc}"
            )
            continue
        if getattr(state, "success", False):
            return Esc14DcReading(
                host=label,
                read_succeeded=True,
                scbe=getattr(state, "strong_certificate_binding_enforcement", None),
                cert_mapping_methods=getattr(state, "certificate_mapping_methods", None),
            )
    return Esc14DcReading(host=label, read_succeeded=False)


__all__ = [
    "observe_domain_scbe",
    "read_scbe_across_dcs",
    "resolve_reading_credential",
]
