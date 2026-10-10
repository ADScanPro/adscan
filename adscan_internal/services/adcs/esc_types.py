"""Shared types for the ADCS ESC exploitation engine."""

from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import Any, Optional

#: Opt-in env toggle for the ESC15 (EKUwu / CVE-2024-49019) NON-DESTRUCTIVE
#: confirm-mode. When set truthy, the ``adcsesc15`` attack-step executor runs the
#: non-destructive proof (``confirm_esc15_vulnerable``: enroll a self-subject cert
#: with a canary application policy and inspect the issued cert) INSTEAD of the
#: full ``run_esc15`` on-behalf-of exploit. This is defensive validation of a
#: client-report finding — it proves CA exploitability and stops at the issued
#: cert; it never mints or uses a privileged identity. The full exploit stays the
#: default (behind the attack-path execution opt-in).
ESC15_CONFIRM_ONLY_ENV = "ADSCAN_ESC15_CONFIRM_ONLY"


def esc15_confirm_only_enabled() -> bool:
    """Return True when ESC15 confirm-mode is requested via the env toggle."""
    return str(os.environ.get(ESC15_CONFIRM_ONLY_ENV, "")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


@dataclass
class EscConfig:
    esc: int
    domain: str
    auth_domain: str
    dc_ip: str
    auth_kdc: str
    ca_host: str
    ca_name: str
    template: Optional[str]
    username: str
    password: Optional[str] = None
    min_key_size: Optional[int] = None  # msPKI-Minimal-Key-Size from template LDAP
    nt_hash: Optional[str] = None
    use_kerberos: bool = False
    ccache_path: Optional[str] = None
    aes_key: Optional[str] = None
    target_upn: str = ""
    on_behalf_of: Optional[str] = None
    agent_pfx_path: Optional[str] = None
    agent_pfx_pass: Optional[str] = None
    workspace_dir: str = ""
    shell: Any = None
    # ESC9/14
    target_account: str = ""
    target_account_dn: str = ""
    ca_fqdn: Optional[str] = None
    # ESC14 exploitation variant (A = write the target's altSecurityIdentities;
    # B/C/D = satisfy a target's EXISTING weak mapping by setting a controlled
    # victim's mail/cn/dNSHostName). ``run_esc14`` dispatches on this.
    esc14_variant: str = "A"
    #: The target's existing weak altSecurityIdentities value a B/C/D run satisfies.
    esc14_weak_binding: str = ""
    #: The victim attribute a B/C/D run mutates (``mail``/``cn``/``dNSHostName``).
    esc14_victim_attribute: str = ""
    #: The value written to ``esc14_victim_attribute`` so the enrolled certificate
    #: matches the target's weak mapping.
    esc14_match_value: str = ""
    # ESC8 Kerberos relay
    spn_target: str = (
        ""  # sAMAccountName of account to receive the relay SPN (e.g. "KINGSLANDING$")
    )
    relay_hostname: str = ""  # override auto-generated relay DNS alias
    spn_auth_username: str = (
        ""  # credentials for SPN write (if different from username)
    )
    spn_auth_password: str = (
        ""  # credentials for SPN write (if different from password)
    )
    dc_fqdn: Optional[str] = None
    """FQDN of the DC for Kerberos SMB targets. Populated from
    ``domain_data['pdc_hostname']`` / ``['dc_fqdn']`` and promoted to FQDN by
    ``__post_init__``. Required when ``use_kerberos=True`` because aiosmb
    derives the ``cifs/<host>`` SPN from the SMB target — passing an IP yields
    a ticket the server rejects (same SEC_E_LOGON_DENIED pattern as LDAP)."""
    dns_server: Optional[str] = None
    """Split-DC/DNS (issue #15): a SEPARATE AD-zone DNS server for segmented
    networks. When unset it is auto-populated in ``__post_init__`` from
    ``shell.domains_data[domain]['dns_server']``, and forwarded into the
    ``CertRequestConfig`` / CA-backup resolution so the CA host resolves via the
    DNS server, not the DC. ``None`` -> the DC resolves (byte-identical)."""

    def __post_init__(self) -> None:
        from adscan_internal.services._kerberos_spn import (
            is_ip_address,
            normalize_kerberos_target_hostname,
        )
        from adscan_core.rich_output import mark_sensitive, print_warning

        # Promote short DC hostnames to FQDN. Mirrors the centralisation done
        # in ADscanLDAPConfig / SMBConfig — see services/_kerberos_spn.py.
        self.dc_fqdn = normalize_kerberos_target_hostname(self.dc_fqdn, self.domain)

        # Split-DC/DNS (issue #15): auto-resolve the separate AD DNS server from
        # the shell's domain data when the caller did not pass one explicitly, so
        # every ESC build site inherits it without threading a new kwarg. Absent
        # -> None, and the DC stays the resolver (byte-identical).
        if not (self.dns_server or "").strip() and self.shell is not None:
            try:
                from adscan_internal.models.domain import resolve_dns_server

                domains_data = getattr(self.shell, "domains_data", None) or {}
                entry = domains_data.get(self.domain) or domains_data.get(
                    self.auth_domain
                )
                if isinstance(entry, dict):
                    self.dns_server = resolve_dns_server(entry)
            except Exception:  # noqa: BLE001 — best-effort; absence keeps the DC.
                self.dns_server = None

        # Enforce the ca_host / ca_fqdn consistency invariant: ca_fqdn must
        # either equal ca_host (when ca_host is an FQDN) or be a valid FQDN
        # (when ca_host is an IP).  Mismatches here mean the Kerberos SPN
        # would target the wrong host and the AP-REP decryption would fail.
        ca_host = (self.ca_host or "").strip()
        ca_fqdn = (self.ca_fqdn or "").strip() or None

        host_is_ip = is_ip_address(ca_host) if ca_host else False
        host_is_fqdn = bool(ca_host) and not host_is_ip and "." in ca_host

        if host_is_fqdn:
            if ca_fqdn and ca_fqdn.casefold() != ca_host.casefold():
                print_warning(
                    f"EscConfig: ca_fqdn={mark_sensitive(ca_fqdn, 'hostname')!r} "
                    f"disagrees with ca_host={mark_sensitive(ca_host, 'hostname')!r} "
                    "— using ca_host as the FQDN."
                )
            self.ca_fqdn = ca_host
        elif ca_fqdn and is_ip_address(ca_fqdn):
            print_warning(
                f"EscConfig: ca_fqdn={mark_sensitive(ca_fqdn, 'hostname')!r} "
                "is an IP, not an FQDN — discarding."
            )
            self.ca_fqdn = None

    @property
    def effective_secret(self) -> str:
        """Credential string for consumers that accept a single secret.

        Returns ``password`` when set; falls back to ``nt_hash`` so callers
        do not need to branch on which field is populated.

        Format detection and auth-scheme selection happen in the transport
        config layer (``CertRequestConfig``, ``KerberosConfig``, ``SMBConfig``,
        ``ADscanLDAPConfig``). EscConfig intentionally does NOT mutate the
        credential fields so ``config.password`` always contains whatever
        the caller stored — no silent None after construction.
        """
        return self.password or self.nt_hash or ""


@dataclass
class EscStep:
    label: str
    description: str
    destructive: bool = False
    rollback_label: str = ""


@dataclass
class EscResult:
    success: bool
    esc: int
    nt_hash: Optional[str] = None
    ccache_path: Optional[str] = None
    pfx_path: Optional[str] = None
    pfx_bytes: Optional[bytes] = None
    error: Optional[str] = None
    rollback_ok: bool = True
    rollback_error: Optional[str] = None
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Esc15ConfirmDecision:
    """Pure mapping of an ESC15 confirm verdict → attack-step representation.

    The confirm primitive (``confirm_esc15_vulnerable``) returns an
    :class:`EscResult` whose ``evidence['verdict']`` is one of
    ``confirmed_vulnerable`` / ``hardened`` / ``attempted`` / ``indeterminate``.
    This value object maps each verdict to the honest Exposure-Validation
    representation the executor must apply — the attack-graph edge status, the
    severity, and whether the outcome is a PROVEN finding or an OBSERVED-GOOD
    positive control. No side effects: the executor applies the decision.
    """

    verdict: str
    #: Attack-graph edge status to persist for the ``ADCSESC15`` edge.
    edge_status: str
    #: Finding severity, set only for a proven-vulnerable confirmation.
    severity: Optional[str]
    #: True only for ``confirmed_vulnerable`` (the issued cert is the evidence).
    is_proven: bool
    #: True only for ``hardened`` — record the patched CA as a positive control.
    is_positive_control: bool
    #: Short human-facing reason, carried into the edge notes.
    reason: str


def map_esc15_confirm_result(result: EscResult) -> Esc15ConfirmDecision:
    """Map an ESC15 confirm :class:`EscResult` to its :class:`Esc15ConfirmDecision`.

    The single source of truth for ESC15 confirm verdict → status, so the
    executor and the web mirror can never disagree. Keyed on the verdict carried
    in ``result.evidence['verdict']``:

    * ``confirmed_vulnerable`` → edge ``success``, HIGH, proven finding. The CA
      copied the injected application policy into the issued certificate.
    * ``hardened`` → edge ``not_vulnerable`` (dismissed, excluded from exposure)
      + a positive control. The CA stripped the injected policy (patched). This
      is NOT ``closed_by_configuration``: the ESC15 existence condition is
      absent, so there is no residual weakness to report, not a closed avenue.
    * ``indeterminate`` → edge ``unsupported`` (data gap: the CA held the request
      for manager approval, so it can be neither confirmed nor ruled out).
    * anything else (``attempted`` / missing / unknown) → edge ``attempted``, an
      honest non-result that NEVER attributes the stop to a defensive control.

    The ``not_vulnerable`` / ``unsupported`` / ``attempted`` spellings match the
    engine status vocabulary (``path_state`` / ``attack_paths_core``), so the
    derived path status and every exposure/remediation filter treat the outcome
    consistently.
    """
    from adscan_internal.services.path_state import NOT_VULNERABLE_STATUS

    evidence = result.evidence if isinstance(result.evidence, dict) else {}
    verdict = str(evidence.get("verdict") or "").strip().lower()
    reason = str(evidence.get("reason") or result.error or "").strip()

    if verdict == "confirmed_vulnerable":
        return Esc15ConfirmDecision(
            verdict="confirmed_vulnerable",
            edge_status="success",
            severity="HIGH",
            is_proven=True,
            is_positive_control=False,
            reason=reason
            or "injected application-policy OID survived into the issued certificate",
        )
    if verdict == "hardened":
        return Esc15ConfirmDecision(
            verdict="hardened",
            edge_status=NOT_VULNERABLE_STATUS,
            severity=None,
            is_proven=False,
            is_positive_control=True,
            reason=reason
            or "the CA stripped the injected application policy from the issued certificate",
        )
    if verdict == "indeterminate":
        return Esc15ConfirmDecision(
            verdict="indeterminate",
            edge_status="unsupported",
            severity=None,
            is_proven=False,
            is_positive_control=False,
            reason=reason or "request pending manager approval (data gap)",
        )
    return Esc15ConfirmDecision(
        verdict="attempted",
        edge_status="attempted",
        severity=None,
        is_proven=False,
        is_positive_control=False,
        reason=reason or "certificate not issued",
    )


@dataclass(frozen=True)
class Esc9ConfirmDecision:
    """Pure mapping of an ESC9/10 behavioral-canary verdict → its representation.

    The canary (``confirm_esc9_vulnerable``) returns an :class:`EscResult` whose
    ``evidence['verdict']`` is one of ``confirmed_vulnerable`` (the DC honoured the
    implicit mapping of a self no-SID certificate — weak binding present),
    ``hardened`` (a code-66 refusal — strong binding enforced), or ``indeterminate``
    (a data gap). This value object maps each verdict to the honest
    Exposure-Validation representation, which the ESC9 driver converts into the
    domain-wide SCBE verdict (``basis=behavioral``) its predicate consumes. Mirrors
    :class:`Esc15ConfirmDecision`; no side effects.
    """

    verdict: str
    #: True only for ``confirmed_vulnerable`` — the weak-binding existence condition
    #: is proven present (the DC accepted a no-SID certificate).
    is_proven: bool
    #: True only for ``hardened`` — record the strong-binding DC as a positive control.
    is_positive_control: bool
    #: Short human-facing reason, carried into the edge notes / positive control.
    reason: str


def map_esc9_confirm_result(result: EscResult) -> Esc9ConfirmDecision:
    """Map an ESC9 canary :class:`EscResult` to its :class:`Esc9ConfirmDecision`.

    The single source of truth for the ESC9 canary verdict → representation, keyed
    on ``result.evidence['verdict']``:

    * ``confirmed_vulnerable`` → proven finding (weak binding present).
    * ``hardened`` → a positive control (strong certificate binding enforced); the
      ESC9/10 edge is removed because SCBE is ESC9's existence condition (so NOT
      ``closed_by_configuration`` — there is no residual weakness to report).
    * anything else (``indeterminate`` / missing / unknown) → an honest non-result
      that keeps the edge confirmation-pending and NEVER attributes the stop to a
      defensive control.
    """
    evidence = result.evidence if isinstance(result.evidence, dict) else {}
    verdict = str(evidence.get("verdict") or "").strip().lower()
    reason = str(evidence.get("reason") or result.error or "").strip()

    if verdict == "confirmed_vulnerable":
        return Esc9ConfirmDecision(
            verdict="confirmed_vulnerable",
            is_proven=True,
            is_positive_control=False,
            reason=reason
            or (
                "a certificate with no SID extension authenticated via the implicit "
                "mapping, so the domain controller accepts weak certificate binding"
            ),
        )
    if verdict == "hardened":
        return Esc9ConfirmDecision(
            verdict="hardened",
            is_proven=False,
            is_positive_control=True,
            reason=reason
            or (
                "the domain controller enforces strong certificate binding "
                "(KB5014754): a certificate with no SID extension is refused"
            ),
        )
    return Esc9ConfirmDecision(
        verdict="indeterminate",
        is_proven=False,
        is_positive_control=False,
        reason=reason or "the certificate binding could not be observed (data gap)",
    )
