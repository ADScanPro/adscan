"""DNS CLI helpers.

This module hosts interactive DNS management logic used by the legacy CLI.
It intentionally depends on dependency injection (the shell object) to avoid
import cycles into `adscan.py`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, Literal
from collections.abc import Callable, Iterable

import ipaddress
import os
import re
import tempfile

from adscan_internal import telemetry
from adscan_internal.rich_output import (
    confirm_ask,
    create_styled_table,
    mark_sensitive,
    print_error,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_panel,
    print_panel_with_table,
    print_exception,
    print_success,
    print_warning,
    questionary_select_index,
)
from adscan_internal.services._kerberos_spn import is_ip_address
from adscan_internal.services.dc_confidence import (
    DcConfidence,
    score_dc_confidence,
)
from adscan_internal.services.network_discovery import (
    extract_netbios,
    infer_domain_from_ldap_banner,
    infer_domain_from_smb_banner,
)
from adscan_internal.services.enumeration.network import is_computer_dc_for_domain
from adscan_internal.services.network_preflight_service import (
    assess_target_reachability,
)
from adscan_internal.services.dns_discovery_service import (
    normalize_ipv4_candidates,
)
from adscan_internal.services.dns_resolver_service import build_root_forwarders
from rich.prompt import Prompt, Confirm
from rich.text import Text

# Matches an IPv4-shaped token (four dot-separated 1-3 digit groups), used to
# catch malformed IPs (e.g. an out-of-range octet) typed into the domain field
# that ``is_ip_address`` would reject but that are clearly not a DNS domain name.
_IPV4_SHAPED_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class DNSShell(Protocol):
    """Protocol for DNS management methods on the legacy shell."""

    domains_data: dict[str, dict[str, Any]]
    netexec_path: str
    domain: str | None
    pdc: str | None
    pdc_hostname: str | None

    def run_command(self, command: str, **kwargs):  # noqa: ANN001
        ...

    def build_auth_nxc(
        self,
        username: str,
        password: str,
        domain: str | None,
        *,
        kerberos: bool = False,
    ) -> str: ...

    def _get_dns_discovery_service(self):  # noqa: ANN201
        ...

    def _get_dns_resolver_service(self):  # noqa: ANN201
        ...

    def get_local_resolver_ip(self) -> str:  # noqa: ANN201
        """Get the local resolver IP address.

        Returns:
            IP address of the local DNS resolver (typically 127.0.0.1).
        """
        ...

    def _get_existing_nameservers(self) -> list[str]:  # noqa: ANN201
        ...

    def do_check_dns(self, domain: str, ip: str | None = None) -> bool:  # noqa: ANN201
        ...

    def _log_dns_management_debug(self, context: str) -> None:  # noqa: ANN201
        ...

    def _ensure_unbound_available(self) -> bool:  # noqa: ANN201
        ...

    def _clean_domain_entries(self, domain: str) -> None:  # noqa: ANN201
        ...

    def _read_unbound_adscan_forward_zones(
        self,
    ) -> tuple[dict[str, list[str]], list[str]]:  # noqa: ANN201
        ...

    def _write_unbound_adscan_config(
        self,
        *,
        domain_forwarders: dict[str, list[str]],
        root_forwarders: list[str],
    ) -> bool:  # noqa: ANN201
        ...

    def _restart_unbound(self) -> bool:  # noqa: ANN201
        ...

    def _configure_system_dns_for_unbound(
        self, fallback_nameservers: list[str]
    ) -> bool:  # noqa: ANN201
        ...

    def _verify_dns_resolution(self, domain: str) -> bool:  # noqa: ANN201
        ...

    def _is_loopback_ip(self, ip: str) -> bool:  # noqa: ANN201
        ...

    def dns_find_pdc_resolv(self, domain: str, resolver_ip: str) -> str | None:  # noqa: ANN201
        ...

    def do_update_resolv_conf(self, args: str) -> bool:  # noqa: ANN201
        ...

    def add_to_hosts(self, domain: str, dns_a_records: list[str] | None = None) -> bool:  # noqa: ANN201
        ...


def infer_domain_from_fqdn(hostname: str) -> str | None:
    """Infer a domain FQDN from a host FQDN.

    - If the hostname has exactly two labels (e.g., cicada.htb), the domain is the full
      FQDN (not just the TLD).
    - If the hostname has three+ labels, drop the first label (e.g., dc1.corp.local -> corp.local).
    """
    normalized = (hostname or "").strip().rstrip(".").lower()
    if "." not in normalized or ".." in normalized:
        return None
    if not re.match(r"^[a-z0-9.-]+$", normalized):
        return None
    parts = [p for p in normalized.split(".") if p]
    if len(parts) < 2:
        return None
    if len(parts) == 2:
        return normalized
    inferred = ".".join(parts[1:])
    return inferred if "." in inferred else None


@dataclass
class DomainCandidateSummary:
    """Summary of inferred domain candidates from a list of IPs."""

    domain: str
    candidate_ips: list[str]
    methods: list[str]
    hostnames: list[str]


def confidence_from_methods(methods: list[str]) -> str:
    """Return a confidence label based on discovery methods."""
    if "hosts" in methods:
        return "[green]High[/green]"
    if "ldap" in methods:
        return "[green]High[/green]"
    if "smb" in methods:
        return "[yellow]Medium[/yellow]"
    if "ptr" in methods:
        return "[dim]Low[/dim]"
    return "[dim]Unknown[/dim]"


def show_domain_candidates_table(
    *,
    rows: list[tuple[str, int | None, list[str]]],
    title: str,
) -> None:
    """Render a professional table of domain candidates."""
    table = create_styled_table(show_lines=False)
    table.add_column("Domain", style="bold cyan", no_wrap=True)
    table.add_column("Candidates", justify="right")
    table.add_column("Method", style="dim")
    table.add_column("Confidence", justify="center")
    for domain, candidate_count, methods in rows:
        marked_domain = mark_sensitive(domain, "domain")
        methods_text = ", ".join(methods) if methods else "unknown"
        count_text = str(candidate_count) if candidate_count is not None else "—"
        table.add_row(
            marked_domain,
            count_text,
            methods_text,
            confidence_from_methods(methods),
        )

    print_panel_with_table(
        table,
        title=title,
        border_style="blue",
        expand=False,
        padding=(1, 2),
    )


def select_domain_from_rows(
    shell: DNSShell,
    *,
    rows: list[tuple[str, int | None, list[str]]],
    prompt: str,
    title: str,
) -> str | None:
    """Show a domain candidates table and prompt for selection."""
    if not rows:
        return None
    if len(rows) == 1:
        return rows[0][0]

    show_domain_candidates_table(rows=rows, title=title)
    options = [row[0] for row in rows]
    if hasattr(shell, "_questionary_select"):
        selected_idx = shell._questionary_select(
            prompt,
            options,
            default_idx=0,
        )
        if selected_idx is None:
            return None
        return options[selected_idx]
    return options[0]


def infer_domain_from_candidate_ip(
    shell: DNSShell,
    *,
    candidate_ip: str,
    timeout_seconds: int = 60,
    open_tcp_ports: set[int] | None = None,
    credential: tuple[str, str] | None = None,
) -> tuple[str | None, str | None, str | None]:
    """Infer a domain from a candidate DC/DNS IP using robust fallbacks.

    Args:
        shell: Active shell instance.
        candidate_ip: Candidate DC/DNS IP address.
        timeout_seconds: Timeout for SMB fingerprinting probe.
        open_tcp_ports: Optional open-port hints already known for the candidate.
        credential: Optional ``(username, password)`` already captured for this
            scan (e.g. an authenticated ``start_auth`` flow). Forwarded to the
            LDAP rootDSE probe as a RETRY when the anonymous read fails — a
            hardened DC that blocks anonymous LDAP still answers a bind the
            operator already holds valid credentials for. ``None`` (default)
            keeps the probe anonymous-only.

    Returns:
        Tuple of (domain, method, hostname) where method is one of:
        "hosts", "ldap", "smb", "ptr". Values are None when inference fails.
    """
    ip_clean = (candidate_ip or "").strip()
    if not ip_clean:
        return None, None, None

    service = shell._get_dns_discovery_service()
    reverse_getent = getattr(service, "_reverse_resolve_via_getent", None)
    if callable(reverse_getent):
        fqdn = reverse_getent(ip_clean)
        inferred = infer_domain_from_fqdn(fqdn or "") if fqdn else None
        if inferred and fqdn:
            return inferred, "hosts", fqdn

    if open_tcp_ports is None or 389 in open_tcp_ports:
        ldap_domain, ldap_hostname = infer_domain_from_ldap_banner(
            shell,
            target_ip=ip_clean,
            timeout_seconds=timeout_seconds,
            credential=credential,
        )
        if ldap_domain:
            return ldap_domain, "ldap", ldap_hostname
    else:
        marked_ip = mark_sensitive(ip_clean, "ip")
        print_info_debug(
            f"[domain_infer] Skipping LDAP fingerprinting for {marked_ip}; port 389 "
            "was not open in candidate discovery."
        )

    if open_tcp_ports is None or 445 in open_tcp_ports:
        smb_domain, smb_hostname = infer_domain_from_smb_banner(
            shell, target_ip=ip_clean, timeout_seconds=timeout_seconds
        )
        if smb_domain:
            return smb_domain, "smb", smb_hostname
    else:
        marked_ip = mark_sensitive(ip_clean, "ip")
        print_info_debug(
            f"[domain_infer] Skipping SMB fingerprinting for {marked_ip}; port 445 "
            "was not open in candidate discovery."
        )

    fqdn = service.reverse_resolve_fqdn_robust(ip_clean, preferred_resolvers=[ip_clean])
    inferred = infer_domain_from_fqdn(fqdn or "") if fqdn else None
    if inferred and fqdn:
        return inferred, "ptr", fqdn

    return None, None, None


def discover_domains_from_candidate_ips(
    shell: DNSShell,
    *,
    candidate_ips: list[str],
    timeout_seconds: int = 60,
    candidate_open_ports: dict[str, set[int]] | None = None,
) -> list[DomainCandidateSummary]:
    """Infer domains from a list of candidate DC/DNS IPs.

    Args:
        shell: Active shell instance.
        candidate_ips: List of IPs to inspect.
        timeout_seconds: Timeout for SMB fingerprinting probes.
        candidate_open_ports: Optional per-candidate open-port hints from Nmap.

    Returns:
        A list of DomainCandidateSummary entries (sorted by domain).
    """
    domain_map: dict[str, dict[str, set[str]]] = {}
    for ip in candidate_ips or []:
        domain, method, hostname = infer_domain_from_candidate_ip(
            shell,
            candidate_ip=ip,
            timeout_seconds=timeout_seconds,
            open_tcp_ports=(candidate_open_ports or {}).get(ip),
        )
        if not domain:
            continue
        entry = domain_map.setdefault(
            domain,
            {"ips": set(), "methods": set(), "hosts": set()},
        )
        entry["ips"].add(ip)
        if method:
            entry["methods"].add(method)
        if hostname:
            entry["hosts"].add(hostname)

    summaries: list[DomainCandidateSummary] = []
    for domain, data in sorted(domain_map.items(), key=lambda item: item[0]):
        summaries.append(
            DomainCandidateSummary(
                domain=domain,
                candidate_ips=sorted(data["ips"]),
                methods=sorted(data["methods"]),
                hostnames=sorted(data["hosts"]),
            )
        )
    return summaries


@dataclass(frozen=True)
class PdcPreflightResult:
    """Decision returned by the DC/PDC preflight check."""

    action: Literal["use", "reenter", "fallback"]
    domain: str
    pdc_ip: str | None = None
    best_effort: bool = False
    pdc_hostname: str | None = None
    # Scope-aware DC/PDC selection (2026-07-12): when the operator knowingly
    # picks a non-PDC DC as the operational target, ``authoritative_pdc_ip``
    # carries the true SRV-discovered PDC (when known) so spray-safety lockout
    # reads can be redirected to it, and ``operator_overrode_pdc`` records the
    # informed-consent override. Defaults preserve every existing caller and
    # every existing workspace (absent flag behaves exactly as today).
    authoritative_pdc_ip: str | None = None
    authoritative_pdc_hostname: str | None = None
    operator_overrode_pdc: bool = False


def persist_pdc_preflight_result(shell: Any, result: PdcPreflightResult | None) -> None:
    """Persist preflight metadata for later DNS/hosts finalization.

    The start/scan flows often pass around only ``(domain, pdc_ip)`` tuples after the
    preflight. Persisting the richer decision here keeps the best-effort DNS mode and
    the resolved PDC hostname available to ``finalize_domain_context`` without forcing
    every caller to thread extra return values through the whole CLI.
    """
    action = getattr(result, "action", None)
    pdc_ip = getattr(result, "pdc_ip", None)
    domain = getattr(result, "domain", None)
    if not result or action != "use" or not pdc_ip or not domain:
        return

    try:
        domain_info = shell.domains_data.setdefault(domain, {})
    except Exception:
        return

    domain_info["pdc"] = pdc_ip

    # Scope-aware override (2026-07-12): the operator knowingly kept a non-PDC DC
    # as the operational target. Persist the true PDC alongside it and flag the
    # lockout authority as a replica so spray-safety reads can redirect to the
    # real PDC (or fall conservative when it is unreachable). Only the explicit
    # override writes these keys — absent ``lockout_authority`` means the chosen
    # ``pdc`` IS the authority, keeping every existing workspace unchanged.
    overrode = bool(getattr(result, "operator_overrode_pdc", False))
    authoritative_pdc_ip = getattr(result, "authoritative_pdc_ip", None)
    if overrode and authoritative_pdc_ip:
        domain_info["authoritative_pdc_ip"] = authoritative_pdc_ip
        domain_info["lockout_authority"] = "replica"
        domain_info["dns_validation_mode"] = "operator_dc_override"
        authoritative_hostname = _normalize_hostname_label(
            getattr(result, "authoritative_pdc_hostname", None)
        )
        if authoritative_hostname:
            domain_info["authoritative_pdc_hostname"] = authoritative_hostname
    else:
        domain_info["dns_validation_mode"] = (
            "best_effort"
            if bool(getattr(result, "best_effort", False))
            else "validated"
        )

    hostname = _normalize_hostname_label(getattr(result, "pdc_hostname", None))
    if hostname:
        domain_info["pdc_hostname"] = hostname


def is_domain_best_effort_mode(shell: Any, domain: str) -> bool:
    """Return True when the domain is operating in DNS best-effort mode."""
    try:
        domain_info = shell.domains_data.get(domain, {})
    except Exception:
        return False
    return (
        str(domain_info.get("dns_validation_mode", "")).strip().lower()
        == "best_effort"
    )


@dataclass(frozen=True)
class DomainValidationAttempt:
    """One strict DNS validation attempt for a candidate domain namespace."""

    domain: str
    ok: bool
    error: str | None


@dataclass(frozen=True)
class DomainValidationOutcome:
    """DNS validation outcome, including parent-domain fallback attempts."""

    requested_domain: str
    selected_domain: str
    ok: bool
    error: str | None
    attempts: list[DomainValidationAttempt]


@dataclass(frozen=True)
class CandidateIpFingerprintEvidence:
    """Best-effort fingerprint evidence gathered from a candidate DC/DNS IP."""

    domain: str
    method: str
    hostname: str | None


@dataclass(frozen=True)
class CandidateDcPortEvidence:
    """Best-effort AD/DC port evidence gathered for a candidate IP.

    ``dc_likely`` is retained as a coarse boolean for existing callers, but it
    is now derived from the scored DC-confidence SSOT
    (``services.dc_confidence``): ``dc_likely`` is True exactly when the port
    signals reach the ``>= LIKELY`` tier. Use :meth:`confidence` for the full
    graded tier.
    """

    ip: str
    open_tcp_ports: tuple[int, ...]
    dc_likely: bool
    source: str

    def confidence(self) -> DcConfidence:
        """Return the scored DC-confidence tier for the observed open ports."""
        return score_dc_confidence(self.open_tcp_ports)


def _port_evidence_dc_likely(open_ports: Iterable[int] | None) -> bool:
    """Whether the observed open ports reach the DC-action (``>= LIKELY``) tier.

    Single point that replaces the historical lax
    ``389 in ports and (53 or 88)`` boolean with the scored SSOT in
    ``services.dc_confidence``. Keeps the same coarse ``dc_likely`` contract
    every existing caller depends on while making the underlying decision the
    tiered model.
    """
    return score_dc_confidence(open_ports).is_dc_like


# Transient per-session cache of the strongest AD-port observation seen for each
# candidate IP. Lives on the shell (never in ``domains_data`` — it holds a set
# of ports and must not reach ``save_workspace_data()``). A non-root nmap
# connect-scan is flaky: it intermittently reports "no open ports" or "only 445"
# for a host that earlier exposed 389/445. Unioning each round's observation
# against this cache keeps the best-effort continuation offer alive across a
# later flaky re-scan instead of dropping it on a single bad round.
_CANDIDATE_PORT_CACHE_ATTR = "_dns_candidate_dc_port_cache"


def _candidate_port_cache(shell: Any) -> dict[str, set[int]]:
    """Return (creating if needed) the per-session candidate-IP port cache."""
    cache = getattr(shell, _CANDIDATE_PORT_CACHE_ATTR, None)
    if not isinstance(cache, dict):
        cache = {}
        try:
            setattr(shell, _CANDIDATE_PORT_CACHE_ATTR, cache)
        except Exception:  # noqa: BLE001 — best-effort; shell may reject attrs
            return {}
    return cache


def _accumulate_candidate_ports(
    shell: Any,
    *,
    candidate_ip: str,
    observed_ports: set[int] | tuple[int, ...] | list[int] | None,
) -> tuple[int, ...]:
    """Union this round's observed ports into the per-IP cache and return them.

    The cumulative union is what callers should classify against — a host that
    exposed 389/445 in an earlier round must not lose its DC classification on a
    later flaky nmap pass that returns fewer (or no) ports.
    """
    ip_clean = (candidate_ip or "").strip()
    if not ip_clean:
        return tuple(sorted({int(p) for p in (observed_ports or [])}))
    cache = _candidate_port_cache(shell)
    bucket = cache.setdefault(ip_clean, set())
    for port in observed_ports or []:
        try:
            bucket.add(int(port))
        except (TypeError, ValueError):
            continue
    return tuple(sorted(bucket))


@dataclass(frozen=True)
class BestEffortPromptPolicy:
    """Workspace-aware UX policy for offering best-effort continuation."""

    prompt: str
    default: bool
    confirmation_copy: str
    recommendation_copy: str
    show_risk_panel: bool = False


def _fingerprint_is_strong_dc_signal(
    evidence: CandidateIpFingerprintEvidence | None,
) -> bool:
    """Return True when fingerprint evidence strongly suggests a DC/AD host."""
    if evidence is None:
        return False
    return evidence.method in {"hosts", "ldap", "smb"}


def _host_looks_like_dc_candidate(
    *,
    fingerprint_evidence: CandidateIpFingerprintEvidence | None,
    port_evidence: CandidateDcPortEvidence | None,
) -> bool:
    """Return True when the overall evidence supports a DC-like classification.

    This is the strong "offer DC actions / proceed best-effort against the DC"
    gate. It fires when EITHER:

    * the observed AD ports reach the scored ``>= LIKELY`` tier
      (``services.dc_confidence``) — replacing the old lax
      ``one-open-port`` / ``389 + (53 or 88)`` boolean; or
    * a strong SMB/LDAP/hosts fingerprint already identified the host as a DC
      (the ``4554eb40`` recovery path — a flaky nmap round must not suppress a
      continuation offer when ADscan has already fingerprinted the DC).
    """
    if port_evidence is not None and port_evidence.confidence().is_dc_like:
        return True
    return _fingerprint_is_strong_dc_signal(fingerprint_evidence)


def _host_looks_like_dns_candidate(
    *,
    fingerprint_evidence: CandidateIpFingerprintEvidence | None,
    port_evidence: CandidateDcPortEvidence | None,
) -> bool:
    """Return True when the host looks DNS-like but not confidently DC-like."""
    if _host_looks_like_dc_candidate(
        fingerprint_evidence=fingerprint_evidence,
        port_evidence=port_evidence,
    ):
        return False
    if fingerprint_evidence and fingerprint_evidence.method == "ptr":
        return True
    return bool(port_evidence and 53 in port_evidence.open_tcp_ports)


def _should_offer_fingerprint_retry(
    evidence: CandidateIpFingerprintEvidence | None,
) -> bool:
    """Return True when fingerprint-derived domain retry is strong enough to suggest."""
    if evidence is None:
        return False
    if evidence.method not in {"hosts", "ldap", "smb"}:
        return False
    domain_text = str(evidence.domain or "").strip()
    return bool(domain_text and re.search(r"[a-z]", domain_text, flags=re.IGNORECASE))


def _candidate_dc_port_evidence_from_open_ports(
    *,
    candidate_ip: str,
    open_tcp_ports: set[int] | tuple[int, ...] | list[int] | None,
    source: str,
) -> CandidateDcPortEvidence | None:
    """Build DC port evidence from already-known port hints."""
    ip_clean = (candidate_ip or "").strip()
    if not ip_clean:
        return None
    normalized_ports = tuple(sorted({int(port) for port in (open_tcp_ports or [])}))
    if not normalized_ports:
        return CandidateDcPortEvidence(
            ip=ip_clean,
            open_tcp_ports=(),
            dc_likely=False,
            source=source,
        )
    dc_likely = _port_evidence_dc_likely(normalized_ports)
    return CandidateDcPortEvidence(
        ip=ip_clean,
        open_tcp_ports=normalized_ports,
        dc_likely=dc_likely,
        source=source,
    )


def _candidate_domains_for_dns_validation(domain: str) -> list[str]:
    """Return progressively broader domain candidates for strict DNS validation."""
    normalized = (domain or "").strip().rstrip(".").lower()
    if not normalized:
        return []

    labels = [label for label in normalized.split(".") if label]
    candidates = [normalized]
    if len(labels) >= 3:
        parent_domain = ".".join(labels[1:])
        if parent_domain and parent_domain not in candidates:
            candidates.append(parent_domain)
    return candidates


def _build_best_effort_prompt_policy(shell: Any, *, candidate_ip: str) -> BestEffortPromptPolicy:
    """Return workspace-aware UX for best-effort continuation offers."""
    workspace_type = str(getattr(shell, "type", "") or "").strip().lower()
    marked_candidate = mark_sensitive(candidate_ip, "ip")
    if workspace_type == "audit":
        return BestEffortPromptPolicy(
            prompt=(
                f"Continue in best-effort mode with {marked_candidate} as the DC/PDC target "
                "for this audit? (not recommended)"
            ),
            default=False,
            confirmation_copy=(
                "Continuing in best-effort mode for an audit workspace. "
                "ADscan will rely on the explicit DC/IP and /etc/hosts where possible, "
                "but DNS-dependent results may be incomplete."
            ),
            recommendation_copy=(
                "This is an audit workspace. Best-effort mode should only be used if you "
                "have independently verified that this DC/IP is correct and accept that "
                "some DNS-dependent coverage may be incomplete."
            ),
            show_risk_panel=True,
        )
    return BestEffortPromptPolicy(
        prompt=(
            f"Continue in best-effort mode with {marked_candidate} as the DC/PDC target? "
            "(recommended for broken-lab DNS)"
        ),
        default=True,
        confirmation_copy=(
            "Continuing in best-effort mode with the provided DC/PDC target. "
            "ADscan will rely on the explicit DC/IP and /etc/hosts where possible."
        ),
        recommendation_copy=(
            "This host still looks like a Domain Controller candidate. You can continue in "
            "best-effort mode with this DC/IP, or re-enter a different DC/DNS IP."
        ),
        show_risk_panel=False,
    )


def _validate_domain_with_resolver_fallbacks(
    shell: Any,
    *,
    domain: str,
    resolver_ip: str,
) -> DomainValidationOutcome:
    """Validate a domain against a resolver, optionally retrying the parent domain."""
    attempts: list[DomainValidationAttempt] = []
    requested_domain = (domain or "").strip().rstrip(".").lower()
    candidates = _candidate_domains_for_dns_validation(requested_domain)
    marked_requested = mark_sensitive(requested_domain, "domain")
    marked_resolver = mark_sensitive(resolver_ip, "ip")

    print_info_debug(
        f"[pdc_preflight] DNS validation candidates for {marked_requested} via "
        f"{marked_resolver}: {candidates}"
    )

    for idx, candidate_domain in enumerate(candidates, start=1):
        marked_candidate = mark_sensitive(candidate_domain, "domain")
        print_info_debug(
            f"[pdc_preflight] DNS validation attempt {idx}/{len(candidates)}: "
            f"domain={marked_candidate} resolver={marked_resolver}"
        )
        ok, error = _validate_dns_with_resolver(
            shell,
            domain=candidate_domain,
            resolver_ip=resolver_ip,
        )
        attempts.append(
            DomainValidationAttempt(
                domain=candidate_domain,
                ok=ok,
                error=error,
            )
        )
        if ok:
            if candidate_domain != requested_domain:
                print_info_debug(
                    f"[pdc_preflight] Parent-domain fallback succeeded for "
                    f"{marked_requested}: {marked_candidate} via {marked_resolver}"
                )
            return DomainValidationOutcome(
                requested_domain=requested_domain,
                selected_domain=candidate_domain,
                ok=True,
                error=None,
                attempts=attempts,
            )

    last_error = attempts[-1].error if attempts else "invalid_domain"
    print_info_debug(
        f"[pdc_preflight] DNS validation exhausted all candidates for "
        f"{marked_requested} via {marked_resolver}; final_error={last_error}"
    )
    return DomainValidationOutcome(
        requested_domain=requested_domain,
        selected_domain=requested_domain,
        ok=False,
        error=last_error,
        attempts=attempts,
    )


def _format_domain_validation_attempt_lines(
    attempts: list[DomainValidationAttempt],
) -> list[str]:
    """Return human-readable lines describing validation attempts."""
    reason_label = {
        "validation_error": "validation error",
        "no_servers": "resolver did not answer",
        "no_targets": "no SRV targets returned",
        "dns_validation_failed": "DNS validation failed",
        "timeout": "query timed out",
        "servfail": "SERVFAIL",
        "no_answer": "no DNS answer",
    }
    lines: list[str] = []
    for item in attempts:
        status = "[green]OK[/green]" if item.ok else "[red]FAIL[/red]"
        reason = reason_label.get(item.error or "", item.error or "unknown")
        lines.append(
            f"• {status} {mark_sensitive(item.domain, 'domain')}: {reason}"
        )
    return lines


def _inspect_dc_like_candidate_ip(
    shell: Any,
    *,
    candidate_ip: str,
    timeout_seconds: int = 20,
) -> CandidateIpFingerprintEvidence | None:
    """Return best-effort AD/DC-like evidence from a candidate IP."""
    domain, method, hostname = infer_domain_from_candidate_ip(
        shell,
        candidate_ip=candidate_ip,
        timeout_seconds=timeout_seconds,
    )
    if not domain or not method:
        return None
    return CandidateIpFingerprintEvidence(
        domain=domain,
        method=method,
        hostname=hostname,
    )


def _normalize_hostname_label(value: str | None) -> str | None:
    """Normalize a hostname/FQDN to a short hostname label."""
    cleaned = str(value or "").strip().rstrip(".")
    if not cleaned:
        return None
    return cleaned.split(".")[0] or None


def _probe_dc_candidate_ports(
    shell: Any,
    *,
    candidate_ip: str,
    known_open_tcp_ports: set[int] | tuple[int, ...] | list[int] | None = None,
    timeout_seconds: int = 120,
) -> CandidateDcPortEvidence | None:
    """Probe a candidate IP for AD-related TCP ports using the DC discovery path."""
    ip_clean = (candidate_ip or "").strip()
    if not ip_clean:
        return None

    if known_open_tcp_ports is not None:
        union_ports = _accumulate_candidate_ports(
            shell,
            candidate_ip=ip_clean,
            observed_ports=known_open_tcp_ports,
        )
        evidence = _candidate_dc_port_evidence_from_open_ports(
            candidate_ip=ip_clean,
            open_tcp_ports=union_ports,
            source="nmap_cached",
        )
        if evidence is not None:
            print_info_debug(
                f"[pdc_preflight] cached DC probe for {mark_sensitive(ip_clean, 'ip')}: "
                f"open_ports={evidence.open_tcp_ports}, dc_likely={evidence.dc_likely} "
                "(cumulative)"
            )
        return evidence

    marked_ip = mark_sensitive(ip_clean, "ip")
    try:
        from adscan_internal.cli.nmap import discover_dc_candidates_with_nmap_details

        with tempfile.NamedTemporaryFile(suffix=".gnmap", delete=False) as handle:
            output_path = handle.name
        try:
            port_map = discover_dc_candidates_with_nmap_details(
                shell,
                hosts=ip_clean,
                ports=[53, 88, 389, 445],
                output_path=output_path,
                timeout_seconds=timeout_seconds,
            )
        finally:
            try:
                os.unlink(output_path)
            except OSError:
                pass

        open_ports = _accumulate_candidate_ports(
            shell,
            candidate_ip=ip_clean,
            observed_ports=port_map.get(ip_clean, set()),
        )
        dc_likely = _port_evidence_dc_likely(open_ports)
        print_info_debug(
            f"[pdc_preflight] nmap DC probe for {marked_ip}: "
            f"open_ports={open_ports}, dc_likely={dc_likely} (cumulative)"
        )
        return CandidateDcPortEvidence(
            ip=ip_clean,
            open_tcp_ports=open_ports,
            dc_likely=dc_likely,
            source="nmap",
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[pdc_preflight] nmap DC probe failed for {marked_ip}: {exc}"
        )

    try:
        reachability = assess_target_reachability(
            shell,
            target_ip=ip_clean,
            expected_interface=getattr(shell, "interface", None),
            tcp_ports=(53, 88, 389, 445),
        )
        open_ports = _accumulate_candidate_ports(
            shell,
            candidate_ip=ip_clean,
            observed_ports=reachability.open_ports,
        )
        dc_likely = _port_evidence_dc_likely(open_ports)
        print_info_debug(
            f"[pdc_preflight] socket DC probe for {marked_ip}: "
            f"open_ports={open_ports}, dc_likely={dc_likely} (cumulative)"
        )
        return CandidateDcPortEvidence(
            ip=ip_clean,
            open_tcp_ports=open_ports,
            dc_likely=dc_likely,
            source="reachability",
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[pdc_preflight] reachability DC probe failed for {marked_ip}: {exc}"
        )
        return None


def _format_candidate_ip_evidence_lines(
    *,
    evidence: CandidateIpFingerprintEvidence | None,
    requested_domain: str,
    selected_domain: str,
) -> list[str]:
    """Render extra diagnosis lines from the candidate IP fingerprint evidence."""
    if evidence is None:
        return []

    marked_domain = mark_sensitive(evidence.domain, "domain")
    method_label = {
        "hosts": "/etc/hosts",
        "ldap": "LDAP fingerprint",
        "smb": "SMB fingerprint",
        "ptr": "PTR result",
    }.get(evidence.method, evidence.method.upper())
    detail_value = marked_domain
    if evidence.hostname and evidence.method in {"ldap", "smb"}:
        detail_value = (
            f"{marked_domain} (host: {mark_sensitive(evidence.hostname, 'host')})"
        )

    lines = [
        "[bold]Additional host evidence:[/bold]",
        f"• {method_label}: {detail_value}",
    ]
    if evidence.method == "ptr":
        lines.append(
            "• PTR alone is weak evidence. It can identify a DNS namespace, but it does not confirm a Domain Controller."
        )
    elif evidence.domain == selected_domain:
        lines.append(
            "• The host fingerprint still matches the validated domain. This usually points to "
            "DNS/53 filtering, tunnel instability, or a resolver service outage rather than a wrong domain."
        )
    elif evidence.domain == requested_domain:
        lines.append(
            "• The resolved IP still looks AD-related for the original domain candidate, but DNS SRV did not answer."
        )
    else:
        lines.append(
            "• The resolved IP looks AD-related, but it points to a different domain namespace than the one being validated."
        )
    return lines


def _format_candidate_port_probe_lines(
    port_evidence: CandidateDcPortEvidence | None,
) -> list[str]:
    """Render extra diagnosis lines from an AD/DC port probe."""
    if port_evidence is None:
        return []

    if port_evidence.open_tcp_ports:
        open_ports = ", ".join(str(port) for port in port_evidence.open_tcp_ports)
    else:
        open_ports = "none"

    lines = ["[bold]Additional port evidence:[/bold]"]
    if port_evidence.dc_likely:
        lines.append(f"• {port_evidence.source.upper()} AD ports open: {open_ports}")
    else:
        lines.append(f"• {port_evidence.source.upper()} observed open ports: {open_ports}")
    if port_evidence.dc_likely:
        lines.append(
            "• The host still looks like a Domain Controller candidate based on AD-related ports."
        )
    elif port_evidence.open_tcp_ports == (53,):
        lines.append(
            "• Port 53 alone suggests a DNS service, but it is not enough to identify a Domain Controller."
        )
    elif port_evidence.open_tcp_ports:
        lines.append(
            "• The observed ports are not sufficient to classify this host as a Domain Controller."
        )
    return lines


def _is_dns_path_failure(
    *,
    validation: DomainValidationOutcome,
    fingerprint_evidence: CandidateIpFingerprintEvidence | None,
    port_evidence: CandidateDcPortEvidence | None,
) -> bool:
    """Return True when DC identity looks credible but DNS reachability is failing."""
    if validation.error != "no_servers":
        return False
    if not _host_looks_like_dc_candidate(
        fingerprint_evidence=fingerprint_evidence,
        port_evidence=port_evidence,
    ):
        return False
    if fingerprint_evidence and fingerprint_evidence.domain not in {
        validation.requested_domain,
        validation.selected_domain,
    }:
        return False
    return True


def _build_domain_validation_failure_summary(
    *,
    validation: DomainValidationOutcome,
    fingerprint_evidence: CandidateIpFingerprintEvidence | None,
    port_evidence: CandidateDcPortEvidence | None,
) -> str:
    """Return the top-level failure summary copy for DNS validation panels."""
    if _is_dns_path_failure(
        validation=validation,
        fingerprint_evidence=fingerprint_evidence,
        port_evidence=port_evidence,
    ):
        return (
            "[yellow]The host still looks like a Domain Controller for this domain, but DNS "
            "queries to port 53 did not answer from the current network path.[/yellow]"
        )
    if _host_looks_like_dc_candidate(
        fingerprint_evidence=fingerprint_evidence,
        port_evidence=port_evidence,
    ):
        return (
            "[yellow]The host resolved, but it did not answer DNS SRV queries for the tested "
            "domain namespace.[/yellow]"
        )
    if _host_looks_like_dns_candidate(
        fingerprint_evidence=fingerprint_evidence,
        port_evidence=port_evidence,
    ):
        return (
            "[yellow]We found DNS-like evidence for this namespace, but not enough proof that "
            "this IP is an Active Directory Domain Controller.[/yellow]"
        )
    return (
        "[yellow]We could not validate this IP as a Domain Controller or usable AD DNS "
        "resolver for the tested domain.[/yellow]"
    )


def _build_domain_validation_next_step(
    *,
    validation: DomainValidationOutcome,
    fingerprint_evidence: CandidateIpFingerprintEvidence | None,
    port_evidence: CandidateDcPortEvidence | None = None,
) -> str:
    """Return the most actionable next-step guidance for DNS validation failures."""
    if _is_dns_path_failure(
        validation=validation,
        fingerprint_evidence=fingerprint_evidence,
        port_evidence=port_evidence,
    ):
        return (
            "This usually means the domain is correct but DNS/53 is not reachable end-to-end. "
            "Verify UDP+TCP/53 through the VPN/tunnel path, or provide another DC that answers DNS for the same domain."
        )
    if port_evidence and port_evidence.dc_likely:
        return (
            "This host still looks like a Domain Controller candidate. "
            "You can continue in best-effort mode with this DC/IP, or re-enter a different DC/DNS IP."
        )
    if _host_looks_like_dns_candidate(
        fingerprint_evidence=fingerprint_evidence,
        port_evidence=port_evidence,
    ):
        return (
            "This host looks DNS-like, but not DC-like. Provide a known DC/DNS IP, or scan a range "
            "that actually contains Domain Controllers."
        )
    if fingerprint_evidence:
        marked_evidence_domain = mark_sensitive(fingerprint_evidence.domain, "domain")
        if fingerprint_evidence.method == "ptr":
            return (
                f"PTR suggests the namespace {marked_evidence_domain}, but PTR alone is not enough. "
                "Retry with a verified DC/DNS IP or use host-range discovery."
            )
        if fingerprint_evidence.domain == validation.selected_domain:
            return (
                "This host still looks like a DC for the validated domain. "
                "Verify that DNS queries to port 53/TCP+UDP are actually allowed from your network path."
            )
        if fingerprint_evidence.domain == validation.requested_domain:
            return (
                "This host still looks like a DC for the original domain candidate. "
                "Retry with that domain explicitly or verify whether the DNS service is filtered."
            )
        return (
            f"Try {marked_evidence_domain} as the domain for this host, or use discovery "
            "to enumerate a larger AD-connected range."
        )

    if validation.selected_domain != validation.requested_domain:
        return (
            f"Try the validated parent domain {mark_sensitive(validation.selected_domain, 'domain')}, "
            "or re-enter the values if you expected the original subdomain to resolve."
        )
    return "Verify the host is a DC/DNS for that domain, try the parent domain if appropriate, or use discovery."


def _capture_domain_validation_telemetry(
    *,
    mode_label: str,
    validation: DomainValidationOutcome,
    fingerprint_evidence: CandidateIpFingerprintEvidence | None = None,
    port_evidence: CandidateDcPortEvidence | None = None,
) -> None:
    """Capture a compact telemetry event for strict DNS validation attempts."""
    used_parent = validation.selected_domain != validation.requested_domain
    if validation.ok and used_parent:
        result = "parent_fallback"
    elif validation.ok:
        result = "validated"
    else:
        result = "failed"

    telemetry.capture(
        "pdc_preflight_dns_validation",
        properties={
            "mode": mode_label,
            "result": result,
            "attempt_count": len(validation.attempts),
            "used_parent_domain": used_parent,
            "final_error": validation.error,
            "fingerprint_method": (
                fingerprint_evidence.method if fingerprint_evidence else None
            ),
            "fingerprint_domain": (
                fingerprint_evidence.domain if fingerprint_evidence else None
            ),
            "fingerprint_domain_matches_requested": bool(
                fingerprint_evidence
                and fingerprint_evidence.domain == validation.requested_domain
            ),
            "fingerprint_domain_matches_selected": bool(
                fingerprint_evidence
                and fingerprint_evidence.domain == validation.selected_domain
            ),
            "dc_probe_source": port_evidence.source if port_evidence else None,
            "dc_probe_open_ports": (
                list(port_evidence.open_tcp_ports) if port_evidence else None
            ),
            "dc_probe_likely": (
                bool(port_evidence.dc_likely) if port_evidence else False
            ),
        },
    )


@dataclass(frozen=True)
class DcResolverCandidateAssessment:
    """Assessment for one DC/PDC candidate resolver."""

    ip: str
    source: Literal["provided", "pdc_srv", "dc_srv"]
    reachable_route: bool
    tcp53_open: bool
    dns_ok: bool
    reason: str


@dataclass(frozen=True)
class DcResolverSelection:
    """Resolver candidate selection outcome for a domain."""

    selected_ip: str | None
    discovered_pdc_ip: str | None
    discovered_pdc_hostname: str | None
    dc_ips: list[str]
    assessments: list[DcResolverCandidateAssessment]


def _discover_pdc_and_dcs_via_resolver(
    shell: Any,
    *,
    domain: str,
    resolver_ip: str,
) -> tuple[str | None, str | None, list[str]]:
    """Best-effort DNS-only discovery for PDC (SRV) + DC list via a resolver IP."""
    normalized_domain = (domain or "").strip().rstrip(".")
    if not normalized_domain:
        return None, None, []

    try:
        service = shell._get_dns_discovery_service()
        domains_data_pdc = None
        try:
            if getattr(shell, "domains_data", None) and domain in shell.domains_data:
                domains_data_pdc = shell.domains_data[domain].get("pdc")
        except Exception:
            domains_data_pdc = None

        preferred_ips = [resolver_ip, domains_data_pdc, getattr(shell, "pdc", None)]
        preferred_ips = [ip for ip in preferred_ips if ip]

        pdc_ip, pdc_hostname = service.find_pdc_with_selection(
            domain=normalized_domain,
            resolver_ip=resolver_ip,
            preferred_ips=preferred_ips if preferred_ips else None,
            reference_ip=resolver_ip,
        )

        dc_ips, _dc_hostnames, _dc_ip_to_hostname = service.discover_domain_controllers(
            domain=normalized_domain,
            pdc_ip=resolver_ip,
            preferred_ips=preferred_ips if preferred_ips else None,
        )

        return pdc_ip, pdc_hostname, dc_ips
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(show_locals=False, exception=exc)
        return None, None, []


def _validate_dns_with_resolver(
    shell: Any,
    *,
    domain: str,
    resolver_ip: str,
) -> tuple[bool, str | None]:
    """Validate DNS for a domain using an explicit resolver only (no fallback)."""
    marked_domain = mark_sensitive(domain, "domain")
    marked_resolver = mark_sensitive(resolver_ip, "ip")
    try:
        service = shell._get_dns_discovery_service()
        dns_ok, dns_error = service.check_dns_resolution(
            domain=domain,
            resolver_ip=resolver_ip,
            auto_configure=False,
            allow_fallback=False,
        )
        print_info_debug(
            f"[pdc_preflight] strict resolver check: domain={marked_domain} "
            f"resolver={marked_resolver} ok={dns_ok} error={dns_error}"
        )
        return dns_ok, dns_error
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[pdc_preflight] strict resolver check failed for {marked_domain} "
            f"resolver={marked_resolver}: {exc}"
        )
        return False, "validation_error"


def _select_reachable_dc_resolver(
    shell: Any,
    *,
    domain: str,
    provided_ip: str,
) -> DcResolverSelection:
    """Select the best reachable resolver from provided IP + discovered PDC/DC list."""
    discovered_pdc_ip, discovered_pdc_hostname, dc_ips = _discover_pdc_and_dcs_via_resolver(
        shell,
        domain=domain,
        resolver_ip=provided_ip,
    )

    source_by_ip: dict[str, Literal["provided", "pdc_srv", "dc_srv"]] = {}
    if discovered_pdc_ip:
        source_by_ip[discovered_pdc_ip] = "pdc_srv"
    source_by_ip.setdefault(provided_ip, "provided")
    for dc_ip in dc_ips:
        source_by_ip.setdefault(dc_ip, "dc_srv")

    ordered_candidates = normalize_ipv4_candidates(
        [discovered_pdc_ip, provided_ip, *(dc_ips or [])]
    )
    assessments: list[DcResolverCandidateAssessment] = []
    expected_interface = getattr(shell, "interface", None)

    for candidate in ordered_candidates:
        source = source_by_ip.get(candidate, "dc_srv")
        reachability = assess_target_reachability(
            shell,
            target_ip=candidate,
            expected_interface=expected_interface,
            tcp_ports=(53,),
        )
        reachable_route = bool(reachability.route.ok)
        tcp53_open = reachability.is_port_open(53)
        dns_ok = False
        reason = "dns_not_checked"

        if not reachable_route:
            reason = "no_route"
        elif not tcp53_open:
            reason = "tcp53_unreachable"
        else:
            dns_ok, dns_error = _validate_dns_with_resolver(
                shell,
                domain=domain,
                resolver_ip=candidate,
            )
            if dns_ok:
                reason = "dns_ok"
            else:
                reason = dns_error or "dns_validation_failed"

        assessment = DcResolverCandidateAssessment(
            ip=candidate,
            source=source,
            reachable_route=reachable_route,
            tcp53_open=tcp53_open,
            dns_ok=dns_ok,
            reason=reason,
        )
        assessments.append(assessment)
        if assessment.dns_ok:
            return DcResolverSelection(
                selected_ip=candidate,
                discovered_pdc_ip=discovered_pdc_ip,
                discovered_pdc_hostname=discovered_pdc_hostname,
                dc_ips=dc_ips,
                assessments=assessments,
            )

    return DcResolverSelection(
        selected_ip=None,
        discovered_pdc_ip=discovered_pdc_ip,
        discovered_pdc_hostname=discovered_pdc_hostname,
        dc_ips=dc_ips,
        assessments=assessments,
    )


def _render_dc_resolver_failure_panel(
    *,
    domain: str,
    provided_ip: str,
    selection: DcResolverSelection,
) -> None:
    """Render a concise diagnosis panel when no DC/PDC resolver candidate is reachable."""
    marked_domain = mark_sensitive(domain, "domain")
    marked_provided = mark_sensitive(provided_ip, "ip")
    lines = [
        "[bold]No reachable DC/PDC resolver candidates were found.[/bold]",
        "",
        f"Domain: {marked_domain}",
        f"Provided IP: {marked_provided}",
        "",
    ]

    source_label = {"provided": "provided", "pdc_srv": "PDC SRV", "dc_srv": "DC SRV"}
    reason_label = {
        "no_route": "no route from local interfaces",
        "tcp53_unreachable": "TCP/53 not reachable",
        "validation_error": "DNS validation error",
        "no_servers": "resolver not reachable",
        "no_targets": "SRV query returned no targets",
        "dns_validation_failed": "DNS validation failed",
    }

    for item in selection.assessments:
        status = "[green]OK[/green]" if item.dns_ok else "[red]FAIL[/red]"
        reason = reason_label.get(item.reason, item.reason)
        lines.append(
            f"• {status} {mark_sensitive(item.ip, 'ip')} "
            f"({source_label.get(item.source, item.source)}): {reason}"
        )

    lines.extend(
        [
            "",
            "[bold]Recommended actions:[/bold]",
            "• Verify VPN routing to the target subnet(s).",
            "• Ensure DNS (53/TCP+UDP) is reachable on at least one DC.",
            "• If needed, provide a different DC/DNS IP for this domain.",
        ]
    )
    print_panel(
        "\n".join(lines),
        title="[bold]🧭 DC/PDC Reachability[/bold]",
        border_style="red",
        padding=(1, 2),
    )


def preflight_domain_pdc_noninteractive(
    shell: Any,
    *,
    domain: str,
    candidate_ip: str,
    mode_label: str,
    candidate_open_tcp_ports: set[int] | tuple[int, ...] | list[int] | None = None,
) -> PdcPreflightResult:
    """Best-effort DC/PDC preflight without prompting."""
    marked_domain = mark_sensitive(domain, "domain")
    marked_candidate = mark_sensitive(candidate_ip, "ip")
    validation = _validate_domain_with_resolver_fallbacks(
        shell,
        domain=domain,
        resolver_ip=candidate_ip,
    )
    dns_ok = validation.ok
    dns_error = validation.error
    effective_domain = validation.selected_domain
    fingerprint_evidence = None
    port_evidence = None
    if not dns_ok:
        fingerprint_evidence = _inspect_dc_like_candidate_ip(
            shell,
            candidate_ip=candidate_ip,
        )
        port_evidence = _probe_dc_candidate_ports(
            shell,
            candidate_ip=candidate_ip,
            known_open_tcp_ports=candidate_open_tcp_ports,
        )
    _capture_domain_validation_telemetry(
        mode_label=mode_label,
        validation=validation,
        fingerprint_evidence=fingerprint_evidence,
        port_evidence=port_evidence,
    )
    if effective_domain != domain:
        print_info(
            "Primary domain DNS validation failed; parent domain fallback succeeded: "
            f"{mark_sensitive(domain, 'domain')} -> {mark_sensitive(effective_domain, 'domain')}"
        )
        telemetry.capture(
            "pdc_preflight_domain_fallback",
            properties={
                "mode": mode_label,
                "result": "auto_switched_parent_domain",
            },
        )
        domain = effective_domain
        marked_domain = mark_sensitive(domain, "domain")

    if dns_error == "validation_error":
        print_warning(
            "Failed to verify DNS configuration; proceeding with the provided DC target."
        )
        print_info_verbose(
            f"[pdc_preflight_noninteractive] strict DNS check failed for {marked_domain} "
            f"candidate={marked_candidate}: {dns_error}"
        )
        return PdcPreflightResult(action="use", domain=domain, pdc_ip=candidate_ip)

    if not dns_ok:
        print_warning(
            "DNS validation did not succeed; proceeding with the provided DC target."
        )
        next_step = _build_domain_validation_next_step(
            validation=validation,
            fingerprint_evidence=fingerprint_evidence,
            port_evidence=port_evidence,
        )
        if dns_error:
            print_info_verbose(
                f"[pdc_preflight_noninteractive] DNS SRV check failed for {marked_domain} "
                f"using {marked_candidate}: {dns_error}"
            )
            for attempt_line in _format_domain_validation_attempt_lines(validation.attempts):
                print_info_debug(
                    f"[pdc_preflight_noninteractive] {attempt_line}"
                )
        for evidence_line in _format_candidate_ip_evidence_lines(
            evidence=fingerprint_evidence,
            requested_domain=validation.requested_domain,
            selected_domain=validation.selected_domain,
        ):
            print_info(f"{evidence_line}")
        for evidence_line in _format_candidate_port_probe_lines(port_evidence):
            print_info(f"{evidence_line}")
        print_info(f"[bold]Next:[/bold] {next_step}")
        return PdcPreflightResult(
            action="use",
            domain=domain,
            pdc_ip=candidate_ip,
            # A strong SMB/LDAP fingerprint is sufficient to proceed best-effort
            # against the known DC IP — do not gate solely on a flaky nmap round.
            best_effort=_host_looks_like_dc_candidate(
                fingerprint_evidence=fingerprint_evidence,
                port_evidence=port_evidence,
            ),
            pdc_hostname=_normalize_hostname_label(
                fingerprint_evidence.hostname if fingerprint_evidence else None
            ),
        )

    selection = _select_reachable_dc_resolver(
        shell,
        domain=domain,
        provided_ip=candidate_ip,
    )
    # §3.3 resolver-vs-DC consistency: _select_reachable_dc_resolver picks the
    # best DNS *resolver* (port 53), but find_pdc_with_selection /
    # discover_domain_controllers now choose the persisted *DC/KDC* IP via a
    # reachability-aware LDAP/Kerberos probe (389/88). Prefer that reachable DC
    # IP for the realm's pdc; the port-53 resolver pick only drives the resolver.
    persisted_dc_ip = selection.discovered_pdc_ip or selection.selected_ip
    if persisted_dc_ip and persisted_dc_ip != candidate_ip:
        telemetry.capture(
            "pdc_preflight_auto_switched",
            properties={
                "mode": mode_label,
                "candidate_is_dc": bool(candidate_ip in (selection.dc_ips or [])),
            },
        )
        print_info_verbose(
            f"[pdc_preflight_noninteractive] Switching DC target for {marked_domain}: "
            f"{marked_candidate} -> {mark_sensitive(persisted_dc_ip, 'ip')}"
        )
        return PdcPreflightResult(action="use", domain=domain, pdc_ip=persisted_dc_ip)

    if selection.selected_ip is None and selection.discovered_pdc_ip is None:
        print_warning(
            "No reachable SRV-discovered DC/PDC resolver was found. "
            "Keeping the provided DC target."
        )
        _render_dc_resolver_failure_panel(
            domain=domain,
            provided_ip=candidate_ip,
            selection=selection,
        )

    return PdcPreflightResult(action="use", domain=domain, pdc_ip=candidate_ip)


def preflight_domain_pdc_interactive(
    shell: Any,
    *,
    domain: str,
    candidate_ip: str,
    mode_label: str,
    candidate_open_tcp_ports: set[int] | tuple[int, ...] | list[int] | None = None,
) -> PdcPreflightResult:
    """Validate (domain, candidate_ip) and ask user to confirm corrections."""
    from adscan_internal.interaction import is_non_interactive as _is_non_interactive
    if _is_non_interactive(shell):
        return preflight_domain_pdc_noninteractive(
            shell, domain=domain, candidate_ip=candidate_ip, mode_label=mode_label
        )
    marked_domain = mark_sensitive(domain, "domain")
    marked_candidate = mark_sensitive(candidate_ip, "ip")

    # Ensure DNS is usable for this domain before attempting SRV-based validation.
    validation = _validate_domain_with_resolver_fallbacks(
        shell,
        domain=domain,
        resolver_ip=candidate_ip,
    )
    dns_ok = validation.ok
    dns_error = validation.error
    fingerprint_evidence = None
    port_evidence = None
    if not dns_ok:
        fingerprint_evidence = _inspect_dc_like_candidate_ip(
            shell,
            candidate_ip=candidate_ip,
        )
        port_evidence = _probe_dc_candidate_ports(
            shell,
            candidate_ip=candidate_ip,
            known_open_tcp_ports=candidate_open_tcp_ports,
        )
    _capture_domain_validation_telemetry(
        mode_label=mode_label,
        validation=validation,
        fingerprint_evidence=fingerprint_evidence,
        port_evidence=port_evidence,
    )
    if validation.selected_domain != domain:
        parent_domain = validation.selected_domain
        marked_parent = mark_sensitive(parent_domain, "domain")
        attempt_lines = _format_domain_validation_attempt_lines(validation.attempts)
        print_panel(
            "[bold yellow]The original domain did not validate, but a parent-domain fallback did.[/bold yellow]\n\n"
            f"Provided domain: {marked_domain}\n"
            f"Fallback domain: {marked_parent}\n"
            f"IP: {marked_candidate}\n\n"
            + "\n".join(attempt_lines)
            + "\n\n[bold]Next:[/bold] Proceed with the validated parent domain or re-enter values.",
            title="[bold]🧭 Parent Domain Fallback[/bold]",
            border_style="yellow",
            padding=(1, 2),
        )
        print_info_debug(
            f"[pdc_preflight] parent-domain fallback selected: "
            f"{marked_domain} -> {marked_parent} via {marked_candidate}"
        )
        telemetry.capture(
            "pdc_preflight_domain_fallback",
            properties={
                "mode": mode_label,
                "result": "interactive_parent_domain_available",
            },
        )
        if Confirm.ask(
            Text(
                f"Use {marked_parent} as the domain for validation and continue?",
                style="cyan",
            ),
            default=True,
        ):
            domain = parent_domain
            marked_domain = marked_parent
        else:
            if Confirm.ask(
                Text("Re-enter the domain and DC/PDC IP?", style="cyan"),
                default=True,
            ):
                return PdcPreflightResult(action="reenter", domain=domain)
            return PdcPreflightResult(action="fallback", domain=domain)

    if dns_error == "validation_error":
        print_error("Failed to verify DNS configuration.")

    if not dns_ok:
        attempt_lines = _format_domain_validation_attempt_lines(validation.attempts)
        evidence_lines = _format_candidate_ip_evidence_lines(
            evidence=fingerprint_evidence,
            requested_domain=validation.requested_domain,
            selected_domain=validation.selected_domain,
        )
        port_lines = _format_candidate_port_probe_lines(port_evidence)
        next_step = _build_domain_validation_next_step(
            validation=validation,
            fingerprint_evidence=fingerprint_evidence,
            port_evidence=port_evidence,
        )
        looks_like_dc = _host_looks_like_dc_candidate(
            fingerprint_evidence=fingerprint_evidence,
            port_evidence=port_evidence,
        )
        best_effort_policy = (
            _build_best_effort_prompt_policy(shell, candidate_ip=candidate_ip)
            if looks_like_dc
            else None
        )
        if best_effort_policy is not None:
            next_step = best_effort_policy.recommendation_copy
        summary_copy = _build_domain_validation_failure_summary(
            validation=validation,
            fingerprint_evidence=fingerprint_evidence,
            port_evidence=port_evidence,
        )
        print_panel(
            "[bold]We couldn't validate the DC/PDC IP.[/bold]\n\n"
            f"Domain: {marked_domain}\n"
            f"IP: {marked_candidate}\n\n"
            + summary_copy
            + "\n\n"
            + "\n".join(attempt_lines)
            + ("\n\n" + "\n".join(evidence_lines) if evidence_lines else "")
            + ("\n\n" + "\n".join(port_lines) if port_lines else "")
            + f"\n\n[bold]Next:[/bold] {next_step}",
            title="[bold]🧭 Domain Validation Failed[/bold]",
            border_style="red",
            padding=(1, 2),
        )
        if dns_error:
            print_info_debug(
                f"[pdc_preflight] DNS SRV check failed for {marked_domain} "
                f"using {marked_candidate}: {dns_error}"
            )
            for attempt_line in attempt_lines:
                print_info_debug(f"[pdc_preflight] {attempt_line}")
            if fingerprint_evidence:
                print_info_debug(
                    "[pdc_preflight] candidate IP evidence via "
                    f"{fingerprint_evidence.method}: "
                    f"{mark_sensitive(fingerprint_evidence.domain, 'domain')}"
                )
            if port_evidence:
                print_info_debug(
                    "[pdc_preflight] candidate IP AD port probe via "
                    f"{port_evidence.source}: open_ports={port_evidence.open_tcp_ports} "
                    f"dc_likely={port_evidence.dc_likely}"
                )
        if (
            _should_offer_fingerprint_retry(fingerprint_evidence)
            and fingerprint_evidence
            and fingerprint_evidence.domain != validation.selected_domain
            and Confirm.ask(
                Text(
                    f"Retry validation with {mark_sensitive(fingerprint_evidence.domain, 'domain')} "
                    "for this same DC/DNS IP? (recommended)",
                    style="cyan",
                ),
                default=True,
            )
        ):
            print_info_debug(
                "[pdc_preflight] retrying validation with fingerprint-derived domain "
                f"{mark_sensitive(fingerprint_evidence.domain, 'domain')} for "
                f"{marked_candidate}"
            )
            telemetry.capture(
                "pdc_preflight_retry_with_fingerprint_domain",
                properties={
                    "mode": mode_label,
                    "fingerprint_method": fingerprint_evidence.method,
                },
            )
            return preflight_domain_pdc_interactive(
                shell,
                domain=fingerprint_evidence.domain,
                candidate_ip=candidate_ip,
                mode_label=mode_label,
            )
        if looks_like_dc and best_effort_policy is not None:
            if best_effort_policy.show_risk_panel:
                print_panel(
                    "[bold yellow]This workspace is configured as an audit.[/bold yellow]\n\n"
                    f"{best_effort_policy.recommendation_copy}",
                    title="[bold]⚠ Best-Effort Mode[/bold]",
                    border_style="yellow",
                    padding=(1, 2),
                )
            # Route through the centralized prompt helper so the offer stays
            # non-interactive-safe (auto-resolves to the policy default on EOF /
            # in `adscan ci`) instead of hanging on a raw Confirm.ask.
            if confirm_ask(
                best_effort_policy.prompt,
                default=best_effort_policy.default,
            ):
                telemetry.capture(
                    "pdc_preflight_confirmed",
                    properties={
                        "mode": mode_label,
                        "action": "use_best_effort_dc",
                        "dc_probe_source": (
                            port_evidence.source if port_evidence else "fingerprint"
                        ),
                        "workspace_type": str(getattr(shell, "type", "") or "").strip().lower(),
                    },
                )
                print_info(best_effort_policy.confirmation_copy)
                return PdcPreflightResult(
                    action="use",
                    domain=domain,
                    pdc_ip=candidate_ip,
                    best_effort=True,
                    pdc_hostname=_normalize_hostname_label(
                        fingerprint_evidence.hostname if fingerprint_evidence else None
                    ),
                )
        if Confirm.ask(
            Text("Re-enter the domain and DC/PDC IP?", style="cyan"),
            default=True,
        ):
            return PdcPreflightResult(action="reenter", domain=domain)
        return PdcPreflightResult(action="fallback", domain=domain)

    selection = _select_reachable_dc_resolver(
        shell,
        domain=domain,
        provided_ip=candidate_ip,
    )
    discovered_pdc_ip = selection.discovered_pdc_ip
    discovered_pdc_hostname = selection.discovered_pdc_hostname
    dc_ips = selection.dc_ips
    selected_ip = selection.selected_ip
    candidate_is_dc = candidate_ip in (dc_ips or [])
    candidate_is_pdc = bool(discovered_pdc_ip and discovered_pdc_ip == candidate_ip)

    if candidate_is_pdc:
        telemetry.capture(
            "pdc_preflight_validated",
            properties={"result": "candidate_matches_pdc", "mode": mode_label},
        )
        print_panel(
            "[bold]PDC validated via DNS SRV.[/bold]\n\n"
            f"Domain: {marked_domain}\n"
            f"PDC (DNS SRV): {marked_candidate}\n\n"
            "[dim]Confirm to proceed.[/dim]",
            title="[bold]🧭 DC/PDC Validation[/bold]",
            border_style="green",
            padding=(1, 2),
        )
        if Confirm.ask(
            Text(f"Use {marked_candidate} as the DC/PDC target?", style="cyan"),
            default=True,
        ):
            telemetry.capture(
                "pdc_preflight_confirmed",
                properties={"mode": mode_label, "action": "use_verified_pdc"},
            )
            return PdcPreflightResult(
                action="use", domain=domain, pdc_ip=candidate_ip
            )
        if Confirm.ask(
            Text("Re-enter the domain and DC/PDC IP?", style="cyan"),
            default=True,
        ):
            telemetry.capture(
                "pdc_preflight_confirmed",
                properties={"mode": mode_label, "action": "reenter"},
            )
            return PdcPreflightResult(action="reenter", domain=domain)
        telemetry.capture(
            "pdc_preflight_confirmed",
            properties={"mode": mode_label, "action": "fallback_to_discovery"},
        )
        return PdcPreflightResult(action="fallback", domain=domain)

    if selected_ip is None:
        _render_dc_resolver_failure_panel(
            domain=domain,
            provided_ip=candidate_ip,
            selection=selection,
        )
        status_line = (
            "[bold yellow]The provided IP appears to be a Domain Controller, but no reachable DNS resolver candidate was found.[/bold yellow]"
            if candidate_is_dc
            else "[bold red]No reachable DNS resolver candidates were found for this domain.[/bold red]"
        )
        print_panel(
            f"{status_line}\n\n"
            f"Domain: {marked_domain}\n"
            f"Provided IP: {marked_candidate}\n\n"
            "[dim]Recommended: re-enter a DC/PDC IP or use domain discovery.[/dim]",
            title="[bold]🧪 Domain/DC Preflight[/bold]",
            border_style="yellow",
            padding=(1, 2),
        )
        if Confirm.ask(
            Text("Re-enter the domain and DC/PDC IP?", style="cyan"),
            default=True,
        ):
            return PdcPreflightResult(action="reenter", domain=domain)
        if candidate_is_dc and Confirm.ask(
            Text(
                f"Use {marked_candidate} anyway (best effort, DNS may be unstable)?",
                style="cyan",
            ),
            default=False,
        ):
            return PdcPreflightResult(action="use", domain=domain, pdc_ip=candidate_ip)
        return PdcPreflightResult(action="fallback", domain=domain)

    if selected_ip == candidate_ip and discovered_pdc_ip and discovered_pdc_ip != candidate_ip:
        print_panel(
            "[bold yellow]The discovered PDC is not reachable from this host.[/bold yellow]\n\n"
            f"Domain: {marked_domain}\n"
            f"Provided IP: {marked_candidate}\n"
            f"Discovered PDC (SRV): {mark_sensitive(discovered_pdc_ip, 'ip')}\n\n"
            "[dim]ADscan will keep the provided reachable DC for this scan.[/dim]",
            title="[bold]🧭 DC/PDC Validation[/bold]",
            border_style="yellow",
            padding=(1, 2),
        )
        if Confirm.ask(
            Text(f"Use {marked_candidate} as the DC/PDC target?", style="cyan"),
            default=True,
        ):
            return PdcPreflightResult(action="use", domain=domain, pdc_ip=candidate_ip)
        if Confirm.ask(
            Text("Re-enter the domain and DC/PDC IP?", style="cyan"),
            default=True,
        ):
            return PdcPreflightResult(action="reenter", domain=domain)
        return PdcPreflightResult(action="fallback", domain=domain)

    # ── Scope-aware DC/PDC selection (2026-07-12) ────────────────────────────
    # The provided IP is a DC (or an unrecognised IP), but it is not the PDC
    # emulator. Recommend the PDC (freshest data + authoritative lockout owner +
    # domain time source) yet let the operator knowingly keep their in-scope DC
    # when the PDC is out of scope — the reported abandonment loop happened
    # because this branch previously offered no "use my provided DC" escape.
    recommended_ip = discovered_pdc_ip or selected_ip
    recommended_role = "PDC" if discovered_pdc_ip else "DC"
    recommended_hostname = (
        discovered_pdc_hostname
        if (discovered_pdc_ip and recommended_ip == discovered_pdc_ip)
        else None
    )
    marked_recommended = mark_sensitive(recommended_ip, "ip")
    marked_recommended_host = (
        mark_sensitive(recommended_hostname, "hostname")
        if recommended_hostname
        else None
    )
    recommended_display = (
        f"{marked_recommended} ({marked_recommended_host})"
        if marked_recommended_host
        else marked_recommended
    )

    if candidate_is_dc:
        result_kind = "candidate_is_dc_not_pdc"
        offer_provided_override = True
        lead_line = (
            "The IP you provided is a valid Domain Controller, but it is not "
            "the PDC emulator for this domain."
        )
        provided_line = f"{marked_candidate}  [dim](replica)[/dim]"
        border = "cyan"
    else:
        result_kind = "candidate_not_dc"
        # Only invite a use-as-is override for a non-DNS-published IP when it
        # still fingerprints as a DC. Here DNS SRV validated the domain, so we
        # hold no DC evidence for this IP — keep the conservative
        # recommend / re-enter / fallback set (no override option).
        offer_provided_override = _host_looks_like_dc_candidate(
            fingerprint_evidence=fingerprint_evidence,
            port_evidence=port_evidence,
        )
        lead_line = (
            "The IP you provided does not match any Domain Controller published "
            "by DNS SRV for this domain."
        )
        provided_line = marked_candidate
        border = "yellow"

    panel_body = (
        f"[bold]{lead_line}[/bold]\n\n"
        f"  Domain               {marked_domain}\n"
        f"  Provided DC          {provided_line}\n"
        f"  Recommended · {recommended_role:<4} {recommended_display}\n\n"
        "[bold]Why the PDC is recommended[/bold]\n"
        "  · Freshest data: replicas lag by the replication interval.\n"
        "  · Authoritative for account-lockout counting, so password spraying\n"
        "    can measure attempts remaining safely.\n"
        "  · Domain time source, so Kerberos clock sync is most reliable.\n"
    )
    if offer_provided_override:
        panel_body += (
            "\n[bold]If you choose your provided DC instead[/bold]\n"
            "  · Lockout counters read from a replica can be stale: ADscan will\n"
            "    read them from the PDC when it is reachable, otherwise it will\n"
            "    spray more cautiously or skip spraying to protect live accounts.\n"
            "  · If the replica clock drifts, Kerberos may hit skew.\n"
        )

    print_panel(
        panel_body,
        title="[bold]🧭 DC/PDC Selection[/bold]",
        border_style=border,
        padding=(1, 2),
    )

    telemetry.capture(
        "pdc_preflight_mismatch",
        properties={
            "result": result_kind,
            "mode": mode_label,
            "candidate_is_dc": bool(candidate_is_dc),
        },
    )

    option_use_recommended = f"Use the recommended {recommended_role} ({recommended_ip})"
    if candidate_is_dc:
        option_use_provided = (
            f"Use my provided DC ({candidate_ip}) : I understand the PDC is out of scope"
        )
    else:
        option_use_provided = (
            f"Use my provided IP ({candidate_ip}) anyway : not a DNS-published DC"
        )
    option_reenter = "Re-enter the domain and DC/PDC IP"
    option_fallback = "Fall back to domain discovery"

    options = [option_use_recommended]
    if offer_provided_override:
        options.append(option_use_provided)
    options.append(option_reenter)
    options.append(option_fallback)

    selected_idx = questionary_select_index(
        title="Which DC should ADscan use for this scan?",
        options=options,
        default_idx=0,
        shell=shell,
    )
    if selected_idx is None:
        # Cancelled (Ctrl-C / EOF): re-enter, matching the sibling branches.
        selected_idx = options.index(option_reenter)
    chosen = options[selected_idx]

    if chosen == option_use_recommended:
        telemetry.capture(
            "pdc_preflight_confirmed",
            properties={"mode": mode_label, "action": "use_discovered_pdc"},
        )
        return PdcPreflightResult(
            action="use",
            domain=domain,
            pdc_ip=recommended_ip,
            pdc_hostname=_normalize_hostname_label(recommended_hostname),
        )

    if chosen == option_use_provided:
        telemetry.capture(
            "pdc_preflight_confirmed",
            properties={
                "mode": mode_label,
                "action": "use_operator_dc_override",
                "pdc_out_of_scope": True,
            },
        )
        if discovered_pdc_ip:
            print_success(
                f"Using {marked_candidate} as the scan DC. The PDC "
                f"{marked_recommended} is recorded as the lockout authority — "
                "spraying reads lockout counters from it when reachable, and "
                "stays conservative otherwise."
            )
        else:
            print_success(f"Using {marked_candidate} as the scan DC.")
        return PdcPreflightResult(
            action="use",
            domain=domain,
            pdc_ip=candidate_ip,
            authoritative_pdc_ip=discovered_pdc_ip,
            authoritative_pdc_hostname=_normalize_hostname_label(discovered_pdc_hostname),
            operator_overrode_pdc=True,
        )

    if chosen == option_reenter:
        telemetry.capture(
            "pdc_preflight_confirmed",
            properties={"mode": mode_label, "action": "reenter"},
        )
        return PdcPreflightResult(action="reenter", domain=domain)

    telemetry.capture(
        "pdc_preflight_confirmed",
        properties={"mode": mode_label, "action": "fallback_to_discovery"},
    )
    return PdcPreflightResult(action="fallback", domain=domain)


def preflight_domain_pdc(
    shell: Any,
    *,
    domain: str,
    candidate_ip: str,
    interactive: bool,
    mode_label: str,
    candidate_open_tcp_ports: set[int] | tuple[int, ...] | list[int] | None = None,
) -> PdcPreflightResult:
    """Preflight wrapper that avoids interactive prompts when not desired."""
    if interactive:
        return preflight_domain_pdc_interactive(
            shell,
            domain=domain,
            candidate_ip=candidate_ip,
            mode_label=mode_label,
            candidate_open_tcp_ports=candidate_open_tcp_ports,
        )
    return preflight_domain_pdc_noninteractive(
        shell,
        domain=domain,
        candidate_ip=candidate_ip,
        mode_label=mode_label,
        candidate_open_tcp_ports=candidate_open_tcp_ports,
    )


def preflight_domain_pdc_from_candidates(
    shell: Any,
    *,
    domain: str,
    candidate_ips: list[str],
    interactive: bool,
    mode_label: str,
    candidate_open_ports: dict[str, set[int]] | None = None,
) -> PdcPreflightResult:
    """Run DC/PDC preflight over a list of candidate IPs.

    Args:
        shell: Active shell instance.
        domain: Domain name to validate.
        candidate_ips: List of candidate DC/DNS IPs to try.
        interactive: Whether to allow interactive prompts.
        mode_label: Label for telemetry events (e.g., "unauth", "auth").

    Returns:
        PdcPreflightResult describing the selected action and PDC IP (if any).
    """
    normalized_domain = (domain or "").strip().lower()
    if not normalized_domain:
        return PdcPreflightResult(action="fallback", domain=domain)

    normalized_ips: list[str] = []
    for ip in candidate_ips or []:
        ip_clean = (ip or "").strip()
        if ip_clean and ip_clean not in normalized_ips:
            normalized_ips.append(ip_clean)

    if not normalized_ips:
        return PdcPreflightResult(action="fallback", domain=domain)

    marked_domain = mark_sensitive(normalized_domain, "domain")
    for idx, ip in enumerate(normalized_ips, start=1):
        marked_ip = mark_sensitive(ip, "ip")
        print_info_verbose(
            f"[pdc_preflight] Testing DC candidate {idx}/{len(normalized_ips)} "
            f"for {marked_domain}: {marked_ip}"
        )
        decision = preflight_domain_pdc(
            shell,
            domain=normalized_domain,
            candidate_ip=ip,
            interactive=interactive,
            mode_label=mode_label,
            candidate_open_tcp_ports=(candidate_open_ports or {}).get(ip),
        )
        if decision.action == "use" and decision.pdc_ip:
            return decision
        if decision.action in {"reenter", "fallback"}:
            return decision

    return PdcPreflightResult(action="fallback", domain=normalized_domain)


def prompt_pdc_ip_interactive(
    *,
    domain: str | None = None,
    prompt_text: str | None = None,
    default_ip: str | None = None,
) -> str | None:
    """Prompt for a DC/DNS IP address with validation.

    When ``default_ip`` is supplied (e.g. an IP the user mistakenly typed into
    the domain field and chose to reuse), it is offered as the prompt default so
    the operator can accept it with Enter instead of retyping it.
    """
    while True:
        default_prompt = (
            f"Enter a DC/DNS IP address for {domain} (e.g., 10.10.10.100)"
            if domain
            else "Enter a DC/DNS IP address (e.g., 10.10.10.100)"
        )
        ip_input = Prompt.ask(
            Text(prompt_text or default_prompt, style="cyan"),
            default=default_ip or "",
        ).strip()
        if not ip_input:
            return None
        try:
            ipaddress.ip_address(ip_input)
        except ValueError:
            print_warning(
                f"[bold]⚠️  Invalid IP address format:[/bold] {mark_sensitive(ip_input, 'ip')}\n"
                "Please enter a valid IPv4 address (e.g., [yellow]10.10.10.100[/yellow])"
            )
            continue
        return ip_input


def prompt_known_domain_and_pdc_interactive(
    shell: Any,
    *,
    mode_label: str,
) -> tuple[str, str] | None:
    """Prompt for domain + DC/PDC IP and run preflight validation."""
    while True:
        domain_input = (
            Prompt.ask(
                Text("Enter the domain name (e.g., contoso.local)", style="cyan")
            )
            .strip()
            .lower()
        )
        if not domain_input:
            print_warning(
                f"[bold]⚠️  Invalid domain format:[/bold] {mark_sensitive(domain_input, 'domain')}\n"
                "Domain must be a FQDN (e.g., [yellow]contoso.local[/yellow], not just [red]CONTOSO[/red])"
            )
            continue

        # Carried-forward DC/DNS IP when the user typed an IP into the domain field.
        carried_dc_ip: str | None = None
        if is_ip_address(domain_input):
            marked_ip = mark_sensitive(domain_input, "ip")
            print_warning(
                "[bold]⚠️  That looks like an IP address, not a domain (FQDN).[/bold]\n"
                "The domain name should be a DNS name like [yellow]contoso.local[/yellow], "
                f"not an IP like {marked_ip}."
            )
            if confirm_ask(
                f"Use {domain_input} as the DC/DNS IP and just enter the domain name?",
                default=True,
            ):
                carried_dc_ip = domain_input
            continue_to_reprompt = True
        elif _IPV4_SHAPED_RE.match(domain_input):
            marked_ip = mark_sensitive(domain_input, "ip")
            print_warning(
                "[bold]⚠️  That looks like a malformed IP address, not a domain (FQDN).[/bold]\n"
                f"{marked_ip} is not a valid IPv4 address. Enter a DNS domain name like "
                "[yellow]contoso.local[/yellow], or a valid IP at the DC IP prompt."
            )
            continue_to_reprompt = True
        elif "." not in domain_input:
            print_warning(
                f"[bold]⚠️  Invalid domain format:[/bold] {mark_sensitive(domain_input, 'domain')}\n"
                "Domain must be a FQDN (e.g., [yellow]contoso.local[/yellow], not just [red]CONTOSO[/red])"
            )
            continue_to_reprompt = True
        else:
            continue_to_reprompt = False

        if continue_to_reprompt and carried_dc_ip is None:
            continue
        if continue_to_reprompt and carried_dc_ip is not None:
            # Re-prompt for the FQDN, then pre-fill the carried IP at the DC prompt.
            domain_input = (
                Prompt.ask(
                    Text("Enter the domain name (e.g., contoso.local)", style="cyan")
                )
                .strip()
                .lower()
            )
            if not domain_input or is_ip_address(domain_input) or "." not in domain_input:
                print_warning(
                    f"[bold]⚠️  Invalid domain format:[/bold] {mark_sensitive(domain_input, 'domain')}\n"
                    "Domain must be a FQDN (e.g., [yellow]contoso.local[/yellow])"
                )
                continue

        print_panel(
            "[bold]PDC / Domain Controller[/bold]\n\n"
            "To run unauthenticated enumeration (SMB/LDAP/Kerberos) we need a reachable\n"
            "Domain Controller to talk to.\n\n"
            "• If you know a DC/PDC IP, enter it below.\n"
            "• If you don't know any DC IP, choose [yellow]No[/yellow] and use domain discovery.",
            title="[bold]🧭 DC Target Required[/bold]",
            border_style="blue",
            padding=(1, 2),
        )

        ip_input = prompt_pdc_ip_interactive(
            domain=domain_input, default_ip=carried_dc_ip
        )
        if not ip_input:
            continue

        decision = preflight_domain_pdc(
            shell,
            domain=domain_input,
            candidate_ip=ip_input,
            interactive=True,
            mode_label=mode_label,
        )

        if decision.action == "use" and decision.pdc_ip:
            persist_pdc_preflight_result(shell, decision)
            return decision.domain, decision.pdc_ip

        if decision.action == "reenter":
            continue

        if Confirm.ask(
            Text("Use domain discovery instead?", style="cyan"),
            default=True,
        ):
            return None


def confirm_domain_pdc_mapping(
    shell: Any,
    *,
    domain: str,
    candidate_ip: str,
    interactive: bool,
    mode_label: str,
    on_reenter: Callable[[], tuple[str, str] | None] | None = None,
    candidate_open_tcp_ports: set[int] | tuple[int, ...] | list[int] | None = None,
    skip_initial_candidate: bool = False,
) -> tuple[str, str] | None:
    """Confirm/validate a domain ↔ PDC mapping with shared UX."""
    current_domain = domain
    current_ip = candidate_ip
    if skip_initial_candidate and on_reenter:
        updated = on_reenter()
        if not updated:
            return None
        current_domain, current_ip = updated
    while True:
        current_port_hints = (
            candidate_open_tcp_ports if current_ip == candidate_ip else None
        )
        decision = preflight_domain_pdc(
            shell,
            domain=current_domain,
            candidate_ip=current_ip,
            interactive=interactive,
            mode_label=mode_label,
            candidate_open_tcp_ports=current_port_hints,
        )
        if decision.action == "use" and decision.pdc_ip:
            persist_pdc_preflight_result(shell, decision)
            return decision.domain, decision.pdc_ip
        if decision.action == "reenter" and on_reenter:
            updated = on_reenter()
            if not updated:
                return None
            current_domain, current_ip = updated
            continue
        return None


def offer_a_record_fallback(
    *,
    shell: Any,
    service: object,
    domain: str,
    fallback_hint: str,
    confirm: bool = True,
) -> str | None:
    """Offer an A-record based DC candidate when SRV discovery fails."""
    if not service or not hasattr(service, "resolve_ipv4_addresses_robust"):
        return None

    ip_candidates = service.resolve_ipv4_addresses_robust(domain)  # type: ignore[attr-defined]
    if not ip_candidates:
        return None

    marked_domain = mark_sensitive(domain, "domain")
    if len(ip_candidates) > 1:
        options = [f"{ip}" for ip in ip_candidates]
        idx = None
        selector = getattr(shell, "_questionary_select", None)
        if callable(selector):
            try:
                idx = selector(
                    "Multiple A records found. Choose a DC/DNS candidate:", options, 0
                )
            except TypeError:
                idx = selector(
                    "Multiple A records found. Choose a DC/DNS candidate:", options
                )
        if idx is None:
            numbered = [f"{i + 1}. {opt}" for i, opt in enumerate(options)]
            print_panel(
                "[bold]Choose one option:[/bold]\n\n" + "\n".join(numbered),
                title="[bold]🧭 A Record Candidates[/bold]",
                border_style="yellow",
                padding=(1, 2),
            )
            choices = [str(i + 1) for i in range(len(options))]
            selected = Prompt.ask(
                Text("Select candidate", style="cyan"),
                choices=choices,
                default="1",
            )
            try:
                idx = int(selected) - 1
            except ValueError:
                idx = None
        if idx is None or not isinstance(idx, int) or idx < 0 or idx >= len(options):
            return None
        chosen_ip = ip_candidates[idx]
    else:
        chosen_ip = ip_candidates[0]

    marked_ip = mark_sensitive(chosen_ip, "ip")
    print_panel(
        "[bold yellow]No SRV records found.[/bold yellow]\n\n"
        f"Domain: {marked_domain}\n"
        f"A record candidate: {marked_ip}\n\n"
        "[dim]Less reliable than SRV. Use only if the domain's A record points to a DC/PDC.[/dim]\n",
        title="[bold]⚠️  A Record Fallback[/bold]",
        border_style="yellow",
        padding=(1, 2),
    )

    from adscan_internal.interaction import is_non_interactive as _is_non_interactive
    if _is_non_interactive(shell):
        if len(ip_candidates) == 1:
            print_info_debug(
                "[dns] Non-interactive mode: using single A-record candidate as DC/PDC"
            )
            return chosen_ip
        print_warning(
            "Multiple A-record candidates found; provide a DC/DNS IP or use discovery."
        )
        return None

    if confirm:
        if Confirm.ask(
            Text(f"Use {marked_ip} as the DC/PDC target?", style="cyan"),
            default=False,
        ):
            return chosen_ip
        print_info(f"If needed, provide a DC/DNS IP or {fallback_hint}.")
        return None

    print_info_debug("[dns] Skipping A-record confirmation; deferring to preflight.")
    return chosen_ip



def check_dns(shell: DNSShell, domain: str, ip: str | None = None) -> bool:
    """Check DNS resolution for a domain and optionally auto-configure if needed.

    This function uses DNSDiscoveryService to verify DNS resolution and handles
    interactive configuration when resolution fails.

    Args:
        shell: Shell object providing DNS services and domain data.
        domain: Domain name to check.
        ip: Optional IP address of a Domain Controller for auto-configuration.

    Returns:
        True if DNS resolution is working, False otherwise.
    """
    marked_domain = mark_sensitive(domain, "domain")
    marked_ip = mark_sensitive(ip, "ip") if ip else None
    if is_domain_best_effort_mode(shell, domain):
        try:
            domain_info = shell.domains_data.setdefault(domain, {})
        except Exception:
            domain_info = {}

        effective_pdc_ip = (ip or domain_info.get("pdc") or getattr(shell, "pdc", None) or "").strip()
        hostname = _normalize_hostname_label(
            domain_info.get("pdc_hostname") or getattr(shell, "pdc_hostname", None)
        )
        if effective_pdc_ip:
            shell.pdc = effective_pdc_ip
            domain_info["pdc"] = effective_pdc_ip
        if hostname:
            shell.pdc_hostname = hostname
            domain_info["pdc_hostname"] = hostname
            try:
                shell.add_to_hosts(domain)
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_info_debug(
                    f"[check_dns] Failed to refresh /etc/hosts for best-effort domain "
                    f"{marked_domain}: {exc}"
                )
        print_info_verbose(
            f"Best-effort DNS mode active for {marked_domain}; skipping strict DNS validation."
        )
        print_info_debug(
            f"[check_dns] Skipping strict DNS validation for {marked_domain}: "
            f"best_effort=True ip={marked_ip}"
        )
        return True

    local_resolver_ip = shell.get_local_resolver_ip()
    marked_local_resolver_ip = mark_sensitive(local_resolver_ip, "ip")
    print_info_debug(
        f"[check_dns] Starting DNS check for domain: {marked_domain}, ip: {marked_ip}"
    )
    print_info_debug(
        f"[check_dns] local_resolver_ip: {marked_local_resolver_ip}"
    )

    # If the system resolver is not using the local Unbound instance first, ADscan's
    # conditional forwarding may not apply to the rest of the tooling even if the
    # Unbound config is correct. This is a hard requirement for reliable scans.
    try:
        if not getattr(shell, "_resolv_conf_local_warning_sent", False):
            resolv_nameservers: list[str] = []
            try:
                with open("/etc/resolv.conf", encoding="utf-8") as rf:
                    for line in rf:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if line.startswith("nameserver"):
                            parts = line.split()
                            if len(parts) >= 2:
                                resolv_nameservers.append(parts[1].strip())
            except OSError as exc:
                telemetry.capture_exception(exc)
                print_info_debug(f"[dns] Failed to read /etc/resolv.conf: {exc}")

            first_ns = resolv_nameservers[0] if resolv_nameservers else None
            has_local_first = first_ns == local_resolver_ip
            marked_first_ns = (
                mark_sensitive(first_ns, "ip") if first_ns else "[none]"
            )
            print_info_debug(
                "[dns] resolv.conf nameservers: "
                f"count={len(resolv_nameservers)}, first={marked_first_ns}"
            )
            if first_ns and not has_local_first:
                print_warning(
                    f"System DNS is not using the local resolver first ({marked_local_resolver_ip}). "
                    "Some tools may fail to resolve AD domains."
                )
                print_info(
                    f"Fix: ensure /etc/resolv.conf starts with 'nameserver {local_resolver_ip}' "
                    "(then re-run the scan)."
                )
                print_info_debug(
                    "[dns] resolv.conf first nameserver is not local: "
                    f"first={marked_first_ns}, total={len(resolv_nameservers)}"
                )
                shell._log_dns_management_debug(
                    f"resolv.conf first nameserver is not {local_resolver_ip}"
                )
                telemetry.capture(
                    "dns_resolv_conf_not_local_first",
                    properties={
                        "first_is_local": False,
                        "expected_local_nameserver": local_resolver_ip,
                        "has_local_nameserver": local_resolver_ip in resolv_nameservers,
                        "nameserver_count": len(resolv_nameservers),
                    },
                )
                shell._resolv_conf_local_warning_sent = True
                # Attempt self-heal when we know the domain + resolver IP.
                if ip is not None:
                    print_info("Updating DNS")
                    if not update_resolv_conf(shell, f"{domain} {ip}"):
                        return False
                    # Re-check resolv.conf now that we've attempted to configure DNS.
                    try:
                        refreshed = shell._get_existing_nameservers()
                        with open("/etc/resolv.conf", encoding="utf-8") as rf:
                            first_after = None
                            for line in rf:
                                if line.strip().startswith("nameserver"):
                                    first_after = line.split()[1].strip()
                                    break
                        if first_after != local_resolver_ip:
                            marked_first_after = mark_sensitive(first_after, "ip")
                            print_error(
                                "DNS configuration did not take effect: /etc/resolv.conf is still not using "
                                f"{marked_local_resolver_ip} first."
                            )
                            print_info_debug(
                                f"[dns] resolv.conf first after update: {marked_first_after}; fallbacks={len(refreshed)}"
                            )
                            return False
                    except Exception as exc:
                        telemetry.capture_exception(exc)
                else:
                    # No DC IP to auto-fix; treat as DNS failure.
                    return False
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_info_debug(f"[dns] Failed resolv.conf preflight: {exc}")

    # Use DNSDiscoveryService to check DNS resolution
    service = shell._get_dns_discovery_service()
    is_working, error_kind = service.check_dns_resolution(
        domain=domain,
        resolver_ip=ip,
        auto_configure=False,  # We handle auto-configuration interactively below
        allow_fallback=ip is None,
    )

    if is_working:
        return True

    # DNS resolution failed - attempt auto-configuration or prompt user
    if ip is not None:
        print_info("Updating DNS")
        if update_resolv_conf(shell, f"{domain} {ip}"):
            # Retry after configuration
            is_working_retry, _ = service.check_dns_resolution(
                domain=domain,
                resolver_ip=None,  # Use system resolver after config
                auto_configure=False,
            )
            if is_working_retry:
                return True
            print_error(f"DNS resolution failed for {marked_domain}")
            return False
        return False

    # Interactive DNS resolution
    print_error(f"DNS resolution is not working correctly for domain {marked_domain}.")
    print_info(
        "Please provide the IP address of a Domain Controller to configure DNS resolution:"
    )

    while True:
        try:
            default_pdc = (
                shell.domains_data[domain]["pdc"]
                if shell.domains_data and domain in shell.domains_data
                else None
            )
            dc_ip = Prompt.ask("DC IP address", default=default_pdc or "")
            if not dc_ip.strip():
                print_error("DC IP address cannot be empty.")
                continue

            try:
                ipaddress.ip_address(dc_ip.strip())
            except ValueError:
                print_error(
                    "Invalid IP address format. Please enter a valid IP address."
                )
                continue

            if update_resolv_conf(shell, f"{domain} {dc_ip.strip()}"):
                marked_domain = mark_sensitive(domain, "domain")
                print_success(
                    f"DNS resolution configured for {marked_domain} using DC {dc_ip.strip()}"
                )
                return True
            print_error("Failed to configure DNS resolution. Please try again.")
        except KeyboardInterrupt:
            print_error("DNS configuration cancelled.")
            return False


def update_resolver_for_domain(shell: DNSShell, domain: str, ip: str) -> bool:
    """Update local DNS resolver configuration for a domain/DC pair.

    Idempotent per session: this is invoked from every ``finalize_domain_context``
    call site (workspace load, target set, posture, scan-confirm — roughly 4x per
    run), but the underlying Unbound reconfigure + restart + verification is only
    useful the first time for a given (domain, DC) pair. A per-session memo on
    ``shell._dns_configured`` (mirrors the ``ensure_*_fresh`` idempotent-guard
    pattern used for posture/clock-sync) skips the redundant reconfigure work —
    and the warning/success noise pair it produces — on repeat calls. Only a
    *successful* configure is memoized, so a prior failure never blocks a retry
    (same "cache observations, never absences" policy as posture caching).

    Args:
        shell: Shell object providing DNS management helpers and telemetry.
        domain: Active Directory domain name.
        ip: IP address of a Domain Controller to use as upstream resolver.

    Returns:
        True if DNS was configured and verified successfully, False otherwise.
    """
    marked_domain = mark_sensitive(domain, "domain")
    marked_ip = mark_sensitive(ip, "ip")

    memo_key = ((domain or "").strip().rstrip(".").lower(), (ip or "").strip())
    dns_configured = getattr(shell, "_dns_configured", None)
    if dns_configured is None:
        dns_configured = set()
        try:
            shell._dns_configured = dns_configured  # ephemeral, never persisted to domains_data
        except Exception:  # noqa: BLE001 — best-effort memo; a failure to attach
            # the cache attribute just means every call reconfigures (safe fallback).
            dns_configured = None
    if dns_configured is not None and memo_key in dns_configured:
        print_info_debug(
            "[dns] update_resolver_for_domain: already configured this session for "
            f"domain={marked_domain}, dc_ip={marked_ip}; skipping redundant reconfigure"
        )
        return True

    print_info(f"Updating DNS for domain {marked_domain} using DC {marked_ip}")
    print_info_debug(
        f"[dns] update_resolver_for_domain start: domain={marked_domain}, dc_ip={marked_ip}"
    )

    selection = _select_reachable_dc_resolver(
        shell,
        domain=domain,
        provided_ip=ip,
    )
    # §3.3 resolver-vs-DC consistency: ``selection.selected_ip`` is the best
    # DNS *resolver* (port 53) winner, while ``selection.discovered_pdc_ip`` is
    # the reachability-aware DC/KDC IP from the LDAP/Kerberos (389/88) probe in
    # find_pdc_with_selection. The Unbound conditional forwarder must use the
    # port-53 resolver winner, but the value persisted as the realm PDC
    # (``shell.pdc`` + hostname lookup) must prefer the reachable DC/KDC IP so a
    # multi-homed DC whose port-53 address differs from its LDAP/Kerberos
    # address does not strand downstream transport configs. This mirrors
    # ``preflight_domain_pdc_noninteractive`` exactly.
    resolver_ip = selection.selected_ip
    persisted_dc_ip = selection.discovered_pdc_ip or selection.selected_ip
    # Forwarder falls back to the reachable DC IP when no port-53 resolver was
    # selected but a reachable PDC was discovered — never strand the operator.
    pdc_ip = resolver_ip or persisted_dc_ip
    if not pdc_ip and not persisted_dc_ip:
        _render_dc_resolver_failure_panel(
            domain=domain,
            provided_ip=ip,
            selection=selection,
        )
        print_error(
            "Could not find a reachable DC/PDC resolver candidate for domain "
            f"{marked_domain}."
        )
        return False
    if pdc_ip and pdc_ip != ip:
        print_warning(
            "Provided DC/DNS IP was replaced by a reachable SRV-discovered resolver "
            f"for {marked_domain}: {mark_sensitive(pdc_ip, 'ip')}."
        )
    try:
        setattr(shell, "pdc", persisted_dc_ip)
        hostname = resolve_pdc_hostname(shell, domain=domain, pdc_ip=persisted_dc_ip)
        if hostname:
            setattr(shell, "pdc_hostname", hostname)
        # Persist the DNS-discovered FQDN/short hostname to the per-domain
        # workspace state so downstream transport configs (LDAP, SMB,
        # Kerberos) read fresh values instead of stale fields cached by
        # an earlier ADscan version. This is the authoritative writer:
        # any prior value of ``pdc_hostname_fqdn`` / ``pdc_fqdn`` /
        # ``dc_fqdn`` is INTENTIONALLY overwritten because they may have
        # been left over from a previous domain or a previous ADscan
        # release. See BACKLOG entry "v8→v9 workspace migration —
        # stale Kerberos target hostname". Missing this writer was the
        # 2026-05-21 cause of the ``Preauth failed`` LDAP-Kerberos
        # cascade on a workspace migrated from v8.0.0 to v9.0.0.
        try:
            domains_data = getattr(shell, "domains_data", None)
            if domains_data is not None and hostname:
                if domain not in domains_data or not isinstance(
                    domains_data.get(domain), dict
                ):
                    domains_data[domain] = {}
                domain_entry = domains_data[domain]

                # Short form: if `hostname` is a FQDN, strip to the first
                # label; otherwise keep as-is.
                short_hostname = hostname.split(".", 1)[0] if "." in hostname else hostname
                # Full FQDN form: only persist when we actually received
                # a dotted name. When the resolver returned a short name
                # we leave the FQDN keys untouched rather than fabricate
                # ``<short>.<realm>`` — that synthesised form is wrong
                # in multi-forest setups where the DC's DNS namespace is
                # different from the AD realm.
                fqdn_to_persist = hostname if "." in hostname else None

                domain_entry["pdc_hostname"] = short_hostname
                if fqdn_to_persist:
                    # Overwrite ALL three FQDN-style keys to keep one
                    # canonical source of truth and invalidate any
                    # stale legacy values that resolve_dc_fqdn would
                    # otherwise prefer (steps 1-3 of its fallback).
                    domain_entry["pdc_hostname_fqdn"] = fqdn_to_persist
                    domain_entry["pdc_fqdn"] = fqdn_to_persist
                    domain_entry["dc_fqdn"] = fqdn_to_persist

                print_info_debug(
                    "[dns] update_resolver_for_domain: persisted "
                    f"domains_data[{marked_domain}] "
                    f"pdc_hostname={mark_sensitive(short_hostname, 'hostname')} "
                    f"pdc_fqdn={mark_sensitive(fqdn_to_persist, 'hostname') if fqdn_to_persist else '<none>'} "
                    "(overwrote any stale FQDN keys from older sessions)"
                )
        except Exception as persist_exc:  # noqa: BLE001
            telemetry.capture_exception(persist_exc)
            print_info_debug(
                "[dns] update_resolver_for_domain: "
                f"failed to persist hostname to domains_data for {marked_domain}: {persist_exc}"
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            "[dns] update_resolver_for_domain: "
            f"failed to set selected resolver metadata for {marked_domain}: {exc}"
        )
    print_info_debug(
        f"[dns] update_resolver_for_domain: resolved pdc_ip={mark_sensitive(pdc_ip, 'ip')}"
    )

    # Use Unbound as a local resolver with per-domain conditional forwarding.
    if not shell._ensure_unbound_available():
        print_info_debug("[dns] update_resolver_for_domain: unbound unavailable")
        return False
    print_info_debug("[dns] update_resolver_for_domain: unbound available")

    # Clean existing entries for this domain before adding new ones.
    shell._clean_domain_entries(domain)

    # Upstream forwarders for the root zone (".") should come from the host/system
    # configuration so normal internet DNS continues to work. Preserve any existing
    # Unbound root forwarders to avoid losing host DNS once resolv.conf is updated.
    local_ns = shell._get_existing_nameservers()
    domain_forwarders, existing_root = shell._read_unbound_adscan_forward_zones()
    root_forwarders = build_root_forwarders(
        existing_root=list(existing_root or []),
        local_nameservers=list(local_ns or []),
        is_loopback_ip=shell._is_loopback_ip,
    )
    print_info_debug(
        "[dns] update_resolver_for_domain: "
        f"root_forwarders={len(root_forwarders)}, "
        f"local_nameservers={len(local_ns)}, "
        f"existing_root={len(existing_root or [])}"
    )

    # Preserve previously configured zones so multiple domains (and workspaces) can coexist.
    domain_forwarders[domain.lower().rstrip(".")] = [pdc_ip]
    print_info_debug(
        "[dns] update_resolver_for_domain: "
        f"forward_zones={len(domain_forwarders)}"
    )

    if not shell._write_unbound_adscan_config(
        domain_forwarders=domain_forwarders,
        root_forwarders=root_forwarders,
    ):
        print_error("Failed to write unbound configuration.")
        return False
    print_info_debug("[dns] update_resolver_for_domain: wrote unbound config")

    if not shell._restart_unbound():
        print_error("Failed to restart unbound.")
        return False
    print_info_debug("[dns] update_resolver_for_domain: restarted unbound")

    shell._log_dns_management_debug("after unbound restart (pre-resolv.conf update)")
    if not shell._configure_system_dns_for_unbound(root_forwarders):
        print_error("Failed to configure system DNS to use the local resolver.")
        return False
    shell._log_dns_management_debug("after resolv.conf update")

    verified = shell._verify_dns_resolution(domain)
    if verified and dns_configured is not None:
        dns_configured.add(memo_key)
    return verified


def resolve_pdc_hostname(
    shell: DNSShell,
    *,
    domain: str,
    pdc_ip: str,
) -> str | None:
    """Resolve the PDC hostname (short name) using DNS or reverse lookup."""
    normalized_domain = (domain or "").strip().rstrip(".")
    if not normalized_domain or not pdc_ip:
        return None

    service = None
    try:
        service = shell._get_dns_discovery_service()
        selected_ip, hostname = service.find_pdc_with_selection(
            domain=normalized_domain,
            resolver_ip=pdc_ip,
            preferred_ips=[pdc_ip],
            reference_ip=pdc_ip,
        )
        if selected_ip == pdc_ip and hostname:
            return hostname
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[dns] Failed SRV hostname lookup for {mark_sensitive(normalized_domain, 'domain')}: {exc}"
        )

    if service is not None:
        try:
            fqdn = service.reverse_resolve_fqdn_robust(pdc_ip, resolver=pdc_ip)
            fqdn = (fqdn or "").strip().rstrip(".")
            if fqdn and fqdn.lower().endswith(normalized_domain.lower()):
                return fqdn.split(".")[0]
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[dns] Failed reverse DNS hostname lookup for {mark_sensitive(pdc_ip, 'ip')}: {exc}"
            )

    return None


def resolve_pdc_hostname_best_effort(
    shell: DNSShell,
    *,
    domain: str,
    pdc_ip: str,
    hostname_hint: str | None = None,
) -> str | None:
    """Resolve a short PDC hostname with best-effort fallbacks.

    Order:
    1. caller-provided hint
    2. strict DNS-based hostname discovery
    3. LDAP/SMB fingerprinting for the candidate IP
    4. PTR reverse lookup
    """
    normalized_hint = _normalize_hostname_label(hostname_hint)
    if normalized_hint:
        return normalized_hint

    hostname = resolve_pdc_hostname(shell, domain=domain, pdc_ip=pdc_ip)
    if hostname:
        return _normalize_hostname_label(hostname)

    evidence = _inspect_dc_like_candidate_ip(shell, candidate_ip=pdc_ip)
    if evidence and evidence.hostname:
        return _normalize_hostname_label(evidence.hostname)

    try:
        service = shell._get_dns_discovery_service()
        fqdn = service.reverse_resolve_fqdn_robust(pdc_ip, resolver=pdc_ip)
        if fqdn:
            return _normalize_hostname_label(fqdn)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[dns] Failed best-effort hostname lookup for {mark_sensitive(pdc_ip, 'ip')}: {exc}"
        )

    return None


def finalize_domain_context(
    shell: DNSShell,
    *,
    domain: str,
    pdc_ip: str,
    interactive: bool,
    best_effort: bool | None = None,
    pdc_hostname_hint: str | None = None,
    make_active: bool = False,
) -> None:
    """Finalize DNS + /etc/hosts setup after confirming a domain and PDC/DC IP.

    This has two distinct responsibilities that MUST stay decoupled:

    1. POPULATE ``domains_data[domain]`` (pdc/dc_ip/dcs/pdc_hostname + the DC
       FQDN keys) and reconfigure the local DNS resolver / ``/etc/hosts`` for
       this domain. This runs unconditionally for EVERY caller — including the
       trust-enumeration and per-domain scan loops that finalize discovered or
       secondary domains.
    2. MAKE this domain the operator's ACTIVE REPL context (``shell.domain``).
       This is a side effect only the primary ``start_unauth`` / ``start_auth``
       / ``add_credential`` entry points want, so it is gated behind
       ``make_active`` and defaults to ``False``. A looping caller (trust enum,
       automated scan) leaves the default so it never clobbers ``shell.domain``
       with a discovered/secondary domain.

    Args:
        make_active: When ``True``, lock ``domain`` as the shell's active
            context via ``set_active_domain``. Defaults to ``False`` so only the
            explicit primary entry points flip the operator's active domain.
    """
    if not domain or not pdc_ip:
        return

    marked_domain = mark_sensitive(domain, "domain")
    marked_ip = mark_sensitive(pdc_ip, "ip")
    domain_info = (
        shell.domains_data.setdefault(domain, {})
        if hasattr(shell, "domains_data")
        else {}
    )
    if best_effort is None:
        best_effort = str(domain_info.get("dns_validation_mode", "")).strip().lower() == "best_effort"
    if pdc_hostname_hint is None:
        pdc_hostname_hint = domain_info.get("pdc_hostname")
    print_info_debug(
        f"[dns] Finalizing domain context: domain={marked_domain}, pdc_ip={marked_ip}, "
        f"best_effort={best_effort}"
    )

    # Lock the resolved domain as the shell's active context so subsequent bare
    # REPL commands (which default to ``shell.domain``) work after both
    # start_unauth and start_auth — not only on the credentialed path. Single
    # source of truth: ``set_active_domain``. Gated on ``make_active`` so the
    # per-domain trust-enum / scan loops (which finalize discovered or secondary
    # domains) do NOT flip the operator's active context.
    if make_active:
        try:
            from adscan_internal.cli.common import set_active_domain  # noqa: PLC0415

            set_active_domain(shell, domain)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[dns] Failed to set active domain context for {marked_domain}: {exc}"
            )

    try:
        domain_info["pdc"] = pdc_ip
        # Preserve a scope-aware operator DC override (2026-07-12): the operator
        # knowingly kept a non-PDC replica, so keep that marker + the persisted
        # lockout authority rather than downgrading it to "validated".
        if str(domain_info.get("dns_validation_mode", "")).strip().lower() != "operator_dc_override":
            domain_info["dns_validation_mode"] = "best_effort" if best_effort else "validated"
        # Fill the model DC-IP field when absent so ``resolve_dc_ip`` and any
        # direct reader agree with the authoritative PDC IP. Never overwrite a
        # value already discovered by a richer path.
        if not str(domain_info.get("dc_ip") or "").strip():
            domain_info["dc_ip"] = pdc_ip
        # Ensure the resolved PDC/DC IP is represented in the DC list without
        # clobbering a fuller list a discovery/collection pass may have built.
        dcs = domain_info.get("dcs")
        if not isinstance(dcs, list):
            dcs = []
        if pdc_ip not in dcs:
            dcs.append(pdc_ip)
        domain_info["dcs"] = dcs
    except Exception:
        pass
    shell.pdc = pdc_ip

    required_helpers = [
        "dns_find_pdc_resolv",
        "_ensure_unbound_available",
        "_clean_domain_entries",
        "_get_existing_nameservers",
        "_is_loopback_ip",
        "_read_unbound_adscan_forward_zones",
        "_write_unbound_adscan_config",
        "_restart_unbound",
        "_configure_system_dns_for_unbound",
        "_verify_dns_resolution",
    ]
    if best_effort:
        print_info(
            "Skipping local DNS resolver reconfiguration because this domain is "
            "running in best-effort mode."
        )
        print_info_debug(
            f"[dns] Skipping resolver update for {marked_domain}: best-effort mode"
        )
    elif all(hasattr(shell, name) for name in required_helpers):
        try:
            if not update_resolver_for_domain(shell, domain, pdc_ip):
                print_warning(
                    "Failed to update the local DNS resolver configuration. "
                    "Some lookups may still rely on direct DC queries."
                )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[dns] Failed to update resolver for {marked_domain}: {exc}"
            )
    else:
        print_info_debug(
            "[dns] Skipping resolver update: shell missing DNS resolver helpers"
        )

    hostname = (
        _normalize_hostname_label(pdc_hostname_hint)
        or _normalize_hostname_label(getattr(shell, "pdc_hostname", None))
        or _normalize_hostname_label(domain_info.get("pdc_hostname"))
    )
    if not hostname:
        if best_effort:
            hostname = resolve_pdc_hostname_best_effort(
                shell,
                domain=domain,
                pdc_ip=pdc_ip,
                hostname_hint=pdc_hostname_hint,
            )
        else:
            hostname = resolve_pdc_hostname(shell, domain=domain, pdc_ip=pdc_ip)

    if not hostname and interactive:
        print_panel(
            "[bold]Optional: Add /etc/hosts entry for the PDC[/bold]\n\n"
            "If DNS is flaky, adding a static /etc/hosts mapping can improve stability.\n"
            "If you know the PDC hostname, enter it now (short name or FQDN).\n"
            "[dim]Leave empty to skip.[/dim]",
            title="[bold]🧭 PDC Hostname (Optional)[/bold]",
            border_style="blue",
            padding=(1, 2),
        )
        hostname_input = (
            Prompt.ask(
                "PDC hostname (e.g., winterfell)", default=""
            )
            .strip()
            .rstrip(".")
        )
        if hostname_input:
            hostname = hostname_input.split(".")[0]

    if hostname:
        shell.pdc = pdc_ip
        shell.pdc_hostname = hostname
        try:
            domain_info["pdc_hostname"] = hostname
            domain_info["pdc"] = pdc_ip
        except Exception:
            pass

        # Persist the DC FQDN keys so raw readers (those that do NOT route
        # through ``resolve_dc_fqdn`` / a config ``__post_init__``) get a real
        # Kerberos SPN target instead of a bare IP or short label. Runs in BOTH
        # best-effort and validated modes. Guards mirror the multi-forest safety
        # of ``update_resolver_for_domain`` (see its 2580-2595 block):
        #   - only a dotted qualified value is ever written;
        #   - a genuine dotted FQDN already present (e.g. one the validated
        #     ``update_resolver_for_domain`` run just observed from live DNS) is
        #     NEVER overwritten — only an absent/empty/short/IP value is filled,
        #     so the DNS-observed name always wins;
        #   - synthesis only from an existing short ``pdc_hostname`` (guaranteed
        #     inside this ``if hostname:`` block); the IP is never turned into a
        #     synthetic FQDN — the ``resolve_dc_fqdn`` inventory fallback handles
        #     the ``pdc_hostname``-absent case at read time.
        try:
            from adscan_internal.models.domain import qualify_host_fqdn  # noqa: PLC0415

            qualified_fqdn = qualify_host_fqdn(hostname, domain)
            if qualified_fqdn and "." in qualified_fqdn:
                for fqdn_key in ("pdc_hostname_fqdn", "pdc_fqdn", "dc_fqdn"):
                    existing = str(domain_info.get(fqdn_key) or "").strip().rstrip(".")
                    # Fill only when there is no genuine dotted FQDN already:
                    # absent/empty, a short label, or a stray IP are all safe to
                    # replace; a real dotted non-IP FQDN is left intact.
                    if not existing or "." not in existing or is_ip_address(existing):
                        domain_info[fqdn_key] = qualified_fqdn
                print_info_debug(
                    "[dns] finalize_domain_context: persisted DC FQDN keys for "
                    f"{marked_domain} -> {mark_sensitive(qualified_fqdn, 'hostname')} "
                    "(best-effort SSOT; genuine dotted FQDNs left intact)"
                )
        except Exception as exc:  # noqa: BLE001 — best-effort; never break finalize
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[dns] Failed to derive DC FQDN keys for {marked_domain}: {exc}"
            )

        try:
            if not shell.add_to_hosts(domain):
                print_info_debug(
                    f"[dns] /etc/hosts entry not updated for {marked_domain}"
                )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[dns] Failed to add /etc/hosts entry for {marked_domain}: {exc}"
            )
    else:
        print_info_debug(
            f"[dns] Skipping /etc/hosts entry (missing hostname) for {marked_domain}"
        )


def update_resolv_conf(shell: DNSShell, args: str) -> bool:
    """Update the /etc/resolv.conf file with the domain information and the PDC IP.

    Usage: update_resolv_conf <domain> <pdc_ip>

    Args:
        shell: Shell object providing DNS services and domain data.
        args: String containing domain and IP separated by space.

    Returns:
        True if DNS was configured successfully, False otherwise.
    """
    args_list = args.split()
    if len(args_list) != 2:
        print_error("Usage: update_resolv_conf <domain> <ip>")
        return False

    domain, ip = args_list
    return update_resolver_for_domain(shell, domain, ip)


def extract_netbios_name(shell: DNSShell, domain: str) -> str | None:
    """Extract the NetBIOS name of a specified domain.

    This is a thin wrapper around :func:`extract_netbios` in
    ``adscan_internal.services.network_discovery``.

    Args:
        shell: Shell object providing run_command method.
        domain: Domain name to extract NetBIOS from.

    Returns:
        NetBIOS name or None if extraction failed.
    """
    return extract_netbios(shell, domain)


def is_user_dc(shell: DNSShell, domain: str, target_host: str) -> bool:
    """Return True when the machine account is either a writable DC or an RODC."""
    return get_user_dc_role(shell, domain, target_host) in {"writable_dc", "rodc"}


def get_user_dc_role(shell: DNSShell, domain: str, target_host: str) -> str:
    """Classify a machine account as writable DC, RODC, or not a DC."""
    from adscan_internal.rich_output import print_exception
    from adscan_internal.services.attack_graph_service import (
        get_node_by_label,
        is_principal_member_of_rid_from_snapshot,
    )
    from adscan_internal.services.domain_controller_classifier import (
        RID_DOMAIN_CONTROLLERS,
        RID_READ_ONLY_DOMAIN_CONTROLLERS,
        classify_computer_node_role,
    )
    from adscan_internal.services.native_group_membership import (
        is_principal_member_of_rid_native,
    )
    from adscan_internal.principal_utils import normalize_machine_account

    try:
        normalized_machine = normalize_machine_account(target_host)
        marked_target_host = mark_sensitive(normalized_machine, "hostname")

        # Stage 1 — node-property classification (AD-schema definitive).
        # primaryGroupID, krbtgt/<host> SPN, and the UF_PARTIAL_SECRETS_ACCOUNT
        # UAC bit each uniquely identify the role.  These are attributes of
        # the Computer object itself, populated by the LDAP collector — they
        # do not require enumerating MemberOf edges, which RODCs may block.
        node = get_node_by_label(shell, domain, label=normalized_machine)
        if isinstance(node, dict):
            node_role = classify_computer_node_role(node)
            if node_role == "rodc":
                print_info_debug(
                    f"[is_user_dc] {marked_target_host} is an RODC "
                    "(node properties: primaryGroupID/krbtgt-SPN/UAC)."
                )
                print_success(f"{marked_target_host} is a Read-Only Domain Controller")
                return "rodc"
            if node_role == "writable_dc":
                print_info_debug(
                    f"[is_user_dc] {marked_target_host} is a DC "
                    "(node properties: primaryGroupID=516)."
                )
                print_success(f"{marked_target_host} is a Domain Controller")
                return "writable_dc"

        # Stage 2 — recursive membership snapshot (RID 521 / RID 516).
        # Used when node properties were inconclusive; this is the legacy
        # primary path and remains useful for nested or aliased setups.
        rodc_snapshot_result = is_principal_member_of_rid_from_snapshot(
            shell, domain, normalized_machine, RID_READ_ONLY_DOMAIN_CONTROLLERS
        )
        if rodc_snapshot_result is True:
            print_info_debug(
                f"[is_user_dc] {marked_target_host} is an RODC (memberships.json RID 521)."
            )
            print_success(f"{marked_target_host} is a Read-Only Domain Controller")
            return "rodc"

        dc_snapshot_result = is_principal_member_of_rid_from_snapshot(
            shell, domain, normalized_machine, RID_DOMAIN_CONTROLLERS
        )
        if dc_snapshot_result is True:
            print_info_debug(
                f"[is_user_dc] {marked_target_host} is a DC (memberships.json RID 516)."
            )
            print_success(f"{marked_target_host} is a Domain Controller")
            return "writable_dc"

        if rodc_snapshot_result is False and dc_snapshot_result is False:
            print_info_debug(
                f"[is_user_dc] {marked_target_host} is not a DC "
                "(memberships.json RID 516/521)."
            )
            print_warning(f"{marked_target_host} is not a Domain Controller")
            return "not_dc"

        print_info_debug(
            f"[is_user_dc] memberships.json unavailable or missing SID metadata for {marked_target_host}; "
            "falling back to host heuristics/LDAP."
        )

        domain_info = shell.domains_data.get(domain, {})
        pdc_hostname = str(domain_info.get("pdc_hostname") or "").strip()
        if pdc_hostname:
            base = normalized_machine.rstrip("$").lower()
            if base == pdc_hostname.split(".")[0].lower():
                print_info_debug(
                    f"[is_user_dc] {marked_target_host} matches pdc_hostname fallback."
                )
                print_success(f"{marked_target_host} is a Domain Controller")
                return "writable_dc"

        print_info_debug(
            f"[is_user_dc] Falling back to native LDAP RID lookup for {marked_target_host}."
        )
        print_info(f"Verifying if {marked_target_host} is a Domain Controller")
        rodc_native_result = is_principal_member_of_rid_native(
            shell,
            domain,
            normalized_machine,
            RID_READ_ONLY_DOMAIN_CONTROLLERS,
            operation_name="RODC membership check",
        )
        if rodc_native_result is True:
            print_success(f"{marked_target_host} is a Read-Only Domain Controller")
            return "rodc"
        dc_native_result = is_principal_member_of_rid_native(
            shell,
            domain,
            normalized_machine,
            RID_DOMAIN_CONTROLLERS,
            operation_name="Domain Controller membership check",
        )
        if dc_native_result is True:
            print_success(f"{marked_target_host} is a Domain Controller")
            return "writable_dc"

        print_warning(f"{marked_target_host} is not a Domain Controller")
        return "not_dc"
    except Exception as e:
        telemetry.capture_exception(e)
        marked_target_host = mark_sensitive(target_host, "hostname")
        print_error(
            f"An error occurred while checking if {marked_target_host} is a DC: {e}"
        )
        print_exception(show_locals=False, exception=e)
        return "not_dc"


def is_computer_dc(shell: DNSShell, domain: str, target_host: str) -> bool:
    """Check if a host is a Domain Controller using domain data.

    Args:
        shell: Shell object providing domain data.
        domain: Domain name.
        target_host: Target hostname or IP to check.

    Returns:
        True if the host is a Domain Controller, False otherwise.
    """
    domain_info = shell.domains_data.get(domain, {})
    return is_computer_dc_for_domain(
        domain=domain,
        target_host=target_host,
        domain_info=domain_info,
    )
