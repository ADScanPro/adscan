"""DNS resolver service (Unbound) for ADscan.

This service encapsulates the local DNS resolver management that ADscan relies on:
- Ensure Unbound is installed/available
- Maintain ADscan's forward-zone drop-in for per-domain conditional forwarding
- Restart/reload Unbound in both host and container runtimes
- Keep the system resolver pointing to the local Unbound listener

The implementation intentionally keeps low-level privilege boundaries in the caller
(e.g., `PentestShell._run_privileged_command`, `_write_system_file`) to avoid
duplicating sudo/systemd logic in multiple places.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping, Protocol
import os
import re

from adscan_internal import telemetry
from adscan_internal.rich_output import (
    mark_sensitive,
    print_error,
    print_exception,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_warning,
    print_warning_debug,
    print_success,
)
from adscan_internal.services.base_service import BaseService


def normalize_dns_like(value: str) -> str:
    """Normalize domain/FQDN-like tokens for comparison."""
    return (value or "").strip().lower().rstrip(".")


def is_direct_child_fqdn(fqdn: str, domain: str) -> bool:
    """Return True if *fqdn* is exactly one label below *domain*."""
    fqdn_norm = normalize_dns_like(fqdn)
    domain_norm = normalize_dns_like(domain)
    if not fqdn_norm or not domain_norm:
        return False
    if fqdn_norm == domain_norm:
        return False
    if not fqdn_norm.endswith("." + domain_norm):
        return False
    fqdn_labels = [part for part in fqdn_norm.split(".") if part]
    domain_labels = [part for part in domain_norm.split(".") if part]
    return len(fqdn_labels) == len(domain_labels) + 1


def is_adscan_hosts_line_for_domain(stripped_line: str, domain: str) -> bool:
    """Return True if a /etc/hosts line looks like an ADscan-managed mapping for the domain.

    ADscan writes entries as:
        <IP> <HOST>.<DOMAIN> <HOST> <DOMAIN>

    This helper is used to avoid substring bugs when domains are nested (for example,
    north.sevenkingdoms.local contains sevenkingdoms.local).
    """
    stripped = (stripped_line or "").strip()
    if not stripped or stripped.startswith("#"):
        return False
    domain_norm = normalize_dns_like(domain)
    if not domain_norm:
        return False

    parts = re.split(r"\s+", stripped)
    if len(parts) < 4:
        return False

    normalized_tokens = [normalize_dns_like(part) for part in parts[1:]]
    if domain_norm not in normalized_tokens:
        return False

    fqdn_token = next(
        (token for token in normalized_tokens if is_direct_child_fqdn(token, domain_norm)),
        None,
    )
    if not fqdn_token:
        return False
    host_label = fqdn_token.split(".", 1)[0]
    return host_label in normalized_tokens


class _DNSResolverHost(Protocol):
    """Host interface required by DNSResolverService.

    This is a transitional protocol used while migrating logic out of `adscan.py`.
    """

    def run_command(self, command: str, **kwargs):  # noqa: ANN001
        ...

    def _run_privileged_command(self, command: str, **kwargs):  # noqa: ANN001
        ...

    def _write_system_file(self, path: str, content: str, **kwargs) -> bool:  # noqa: ANN001
        ...

    def _ensure_system_dir(self, path: str) -> bool:  # noqa: ANN001
        ...

    def _remove_system_file(self, path: str) -> bool:  # noqa: ANN001
        ...


@dataclass(frozen=True)
class DNSResolverRuntime:
    """Runtime hooks needed to manage Unbound across host/container modes."""

    is_full_container_runtime: Callable[[], bool]
    get_local_resolver_ip: Callable[[], str]
    is_unbound_listening_local: Callable[..., bool]
    start_unbound_without_systemd: Callable[[], bool]
    start_unbound_without_systemd_via_sudo: Callable[[], bool]
    is_loopback_ip: Callable[[str], bool]
    is_systemd_available: Callable[[], bool]


class DNSResolverService(BaseService):
    """Manage ADscan's local DNS resolver (Unbound) and resolver persistence."""

    def __init__(
        self,
        host: _DNSResolverHost,
        runtime: DNSResolverRuntime,
        *,
        unbound_conf_dir: str = "/etc/unbound/unbound.conf.d",
        unbound_adscan_conf_name: str = "10-adscan.conf",
        resolv_conf_path: str = "/etc/resolv.conf",
        dhcpcd_conf_path: str = "/etc/dhcpcd.conf",
        dhcpcd_enter_hook_path: str = "/etc/dhcpcd.enter-hook",
        systemd_resolved_dropin_path: str = "/etc/systemd/resolved.conf.d/10-adscan.conf",
        hosts_path: str = "/etc/hosts",
    ):
        super().__init__()
        self._host = host
        self._rt = runtime
        self._unbound_conf_dir = unbound_conf_dir
        self._unbound_adscan_conf = os.path.join(unbound_conf_dir, unbound_adscan_conf_name)
        self._resolv_conf_path = resolv_conf_path
        self._dhcpcd_conf_path = dhcpcd_conf_path
        self._dhcpcd_enter_hook_path = dhcpcd_enter_hook_path
        self._systemd_resolved_dropin_path = systemd_resolved_dropin_path
        self._hosts_path = hosts_path

    def ensure_unbound_available(self) -> bool:
        """Ensure Unbound is installed and its config directory exists."""
        try:
            if self._rt.is_full_container_runtime():
                result = self._host.run_command("which unbound", timeout=10, ignore_errors=True)
                if not result or result.returncode != 0:
                    print_error("Unbound is not available inside the container image.")
                    return False
                self._host._ensure_system_dir(self._unbound_conf_dir)
                return True

            result = self._host.run_command("which unbound", timeout=30, ignore_errors=True)
            if not result or result.returncode != 0:
                print_info("Installing unbound...")
                if os.geteuid() == 0:
                    install_result = self._host.run_command(
                        "apt-get update && apt-get install -y unbound",
                        timeout=900,
                        ignore_errors=True,
                    )
                else:
                    # Use sudo and show output so users can see the password prompt and apt progress.
                    install_result = self._host.run_command(
                        "sudo apt-get update && sudo apt-get install -y unbound",
                        timeout=900,
                        ignore_errors=True,
                        capture_output=False,
                        use_clean_env=False,
                    )
                if not install_result or install_result.returncode != 0:
                    print_error("Failed to install unbound.")
                    return False
                print_info_verbose("unbound installed successfully")

            # Best-effort: stop dnsmasq if it is actively occupying port 53.
            self._stop_dnsmasq_if_conflicting()

            # Ensure config directories exist.
            self._host._ensure_system_dir(self._unbound_conf_dir)
            return True
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_warning("Failed to ensure Unbound is available.")
            print_exception(show_locals=False, exception=exc)
            return False

    def read_forward_zones(self) -> tuple[dict[str, list[str]], list[str]]:
        """Read ADscan's Unbound forward-zone mappings from the drop-in file."""
        domain_forwarders: dict[str, list[str]] = {}
        root_forwarders: list[str] = []

        try:
            if not os.path.exists(self._unbound_adscan_conf):
                return domain_forwarders, root_forwarders

            current_zone: str | None = None
            current_addrs: list[str] = []
            in_root_zone = False

            with open(self._unbound_adscan_conf, "r", encoding="utf-8", errors="ignore") as f:
                for raw in f:
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue

                    if line.startswith("forward-zone:"):
                        # Commit previous block.
                        if current_zone is not None:
                            if in_root_zone:
                                root_forwarders = list(current_addrs)
                            else:
                                domain_forwarders[current_zone] = list(current_addrs)
                        current_zone = None
                        current_addrs = []
                        in_root_zone = False
                        continue

                    if line.startswith("name:"):
                        zone = line.split(":", 1)[1].strip().strip('"').strip("'").rstrip(".").lower()
                        if zone == "":
                            current_zone = "."
                            in_root_zone = True
                        elif zone == ".":
                            current_zone = "."
                            in_root_zone = True
                        else:
                            current_zone = zone
                        continue

                    if line.startswith("forward-addr:"):
                        addr = line.split(":", 1)[1].strip()
                        if addr:
                            current_addrs.append(addr)

            # Commit last block.
            if current_zone is not None:
                if in_root_zone:
                    root_forwarders = list(current_addrs)
                else:
                    domain_forwarders[current_zone] = list(current_addrs)

            # Normalize: remove loopbacks in root forwarders.
            root_forwarders = [
                ns for ns in root_forwarders if ns and not self._rt.is_loopback_ip(ns)
            ]
            root_forwarders = list(dict.fromkeys(root_forwarders))
            return domain_forwarders, root_forwarders
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_warning_debug("[dns] Failed to parse Unbound forward zones.")
            print_exception(show_locals=False, exception=exc)
            return {}, []

    def write_unbound_config(
        self,
        *,
        domain_forwarders: Mapping[str, list[str]],
        root_forwarders: list[str],
    ) -> bool:
        """Write ADscan's Unbound configuration drop-in for conditional forwarding."""
        try:
            local_resolver_ip = self._rt.get_local_resolver_ip()

            normalized_domain_forwarders: dict[str, list[str]] = {}
            normalized_domains: list[str] = []
            for domain, addrs in (domain_forwarders or {}).items():
                normalized_domain = (domain or "").strip().lower().rstrip(".")
                if not normalized_domain:
                    continue
                normalized_addrs = [
                    addr.strip()
                    for addr in (addrs or [])
                    if addr and addr.strip() and not self._rt.is_loopback_ip(addr.strip())
                ]
                normalized_addrs = list(dict.fromkeys(normalized_addrs))
                if not normalized_addrs:
                    continue
                normalized_domain_forwarders[normalized_domain] = normalized_addrs
                normalized_domains.append(normalized_domain)

            lines: list[str] = [
                "# ADscan Unbound configuration",
                "# Auto-generated - do not edit manually",
                "",
                "server:",
                f"  interface: {local_resolver_ip}",
                "  port: 53",
                "  access-control: 127.0.0.0/8 allow",
                "  do-ip6: no",
            ]

            for domain in sorted(set(normalized_domains)):
                lines.append(f'  private-domain: "{domain}."')
                lines.append(f'  domain-insecure: "{domain}."')

            lines.append("")

            normalized_root = [
                addr.strip()
                for addr in (root_forwarders or [])
                if addr and addr.strip() and not self._rt.is_loopback_ip(addr.strip())
            ]
            normalized_root = list(dict.fromkeys(normalized_root))
            if normalized_root:
                lines.extend(["forward-zone:", '  name: "."'])
                for addr in normalized_root:
                    lines.append(f"  forward-addr: {addr}")
                lines.append("")

            for domain, addrs in sorted(normalized_domain_forwarders.items()):
                lines.extend(["forward-zone:", f'  name: "{domain}."'])
                for addr in addrs:
                    lines.append(f"  forward-addr: {addr}")
                lines.append("  forward-tcp-upstream: yes")
                lines.append("")

            content = "\n".join(lines).rstrip() + "\n"
            ok = self._host._write_system_file(self._unbound_adscan_conf, content, mode=0o644)
            return ok
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_warning("Failed to write unbound ADscan config.")
            print_exception(show_locals=False, exception=exc)
            return False

    def restart_unbound(self) -> bool:
        """Restart/reload Unbound and return True on success."""
        try:
            local_resolver_ip = self._rt.get_local_resolver_ip()

            if self._rt.is_full_container_runtime():
                check = self._host.run_command("unbound-checkconf", timeout=30, ignore_errors=True)
                if check and check.returncode != 0:
                    print_info_debug(
                        f"[dns] unbound-checkconf returned rc={check.returncode}; attempting reload/start anyway"
                    )
                # Prefer unbound-control reload when available (FULL runtime enables remote-control).
                reload_cmd = f"unbound-control -s {local_resolver_ip} reload"
                reload = self._host.run_command(reload_cmd, timeout=15, ignore_errors=True)
                if reload and reload.returncode == 0:
                    return True

                listener_ready = bool(
                    self._rt.is_unbound_listening_local(resolver_ip=local_resolver_ip)
                )
                reload_stderr = str(getattr(reload, "stderr", "") or "").strip()
                reload_stdout = str(getattr(reload, "stdout", "") or "").strip()
                reload_rc = getattr(reload, "returncode", None)
                marked_local_resolver_ip = mark_sensitive(local_resolver_ip, "ip")
                if listener_ready:
                    print_info_debug(
                        "[dns] unbound-control reload failed while Unbound is already "
                        f"listening on {marked_local_resolver_ip}:53 "
                        f"(rc={reload_rc}, stderr={reload_stderr or '<empty>'}, "
                        f"stdout={reload_stdout or '<empty>'})"
                    )
                    print_warning(
                        "Unbound is already listening on the local DNS port, but its "
                        "control interface is unavailable. ADscan could not reload the "
                        "updated resolver configuration."
                    )
                else:
                    print_info_debug(
                        "[dns] unbound-control reload failed and Unbound does not appear "
                        f"to be listening on {marked_local_resolver_ip}:53 "
                        f"(rc={reload_rc}, stderr={reload_stderr or '<empty>'}, "
                        f"stdout={reload_stdout or '<empty>'})"
                    )

                started = self._rt.start_unbound_without_systemd_via_sudo() or self._rt.start_unbound_without_systemd()
                if not started:
                    return False

                reload = self._host.run_command(reload_cmd, timeout=15, ignore_errors=True)
                if reload and reload.returncode != 0:
                    reload_stderr = str(getattr(reload, "stderr", "") or "").strip()
                    reload_stdout = str(getattr(reload, "stdout", "") or "").strip()
                    print_info_debug(
                        "[dns] unbound-control reload still failing after start attempt "
                        f"(rc={reload.returncode}, stderr={reload_stderr or '<empty>'}, "
                        f"stdout={reload_stdout or '<empty>'})"
                    )
                return bool(reload and reload.returncode == 0)

            # Host installs: validate config strictly before restarting.
            check = self._host.run_command("unbound-checkconf", timeout=30, ignore_errors=True)
            if check and check.returncode != 0:
                print_warning("unbound-checkconf reported an invalid configuration.")
                return False

            restart = self._host._run_privileged_command(
                "systemctl restart unbound", timeout=60, ignore_errors=True
            )
            if restart and restart.returncode == 0:
                return True

            restart = self._host._run_privileged_command(
                "service unbound restart", timeout=60, ignore_errors=True
            )
            return bool(restart and restart.returncode == 0)
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_warning("Failed to restart unbound.")
            print_exception(show_locals=False, exception=exc)
            return False

    def get_existing_nameservers(self) -> list[str]:
        """Return current upstream nameservers (best effort).

        Strategy:
        - Prefer /etc/resolv.conf when it contains non-loopback nameservers.
        - If /etc/resolv.conf only points to the local resolver, try the systemd-resolved
          upstream list (when available) to recover host/VPN DNS servers.
        - If nothing else is available, return an empty list.
        """
        public_resolvers = {
            "1.1.1.1",
            "1.0.0.1",
            "8.8.8.8",
            "8.8.4.4",
            "9.9.9.9",
            "149.112.112.112",
        }
        allow_public_dns = (
            str(os.environ.get("ADSCAN_ALLOW_PUBLIC_DNS", "1")).strip() == "1"
        )

        def _read_nameservers(path: str) -> list[str]:
            try:
                names: list[str] = []
                with open(path, encoding="utf-8") as rf:
                    for raw in rf:
                        line = raw.strip()
                        if not line or line.startswith("#"):
                            continue
                        if line.startswith("nameserver"):
                            parts = line.split()
                            if len(parts) >= 2:
                                ns = parts[1].strip()
                                if (
                                    ns
                                    and not self._rt.is_loopback_ip(ns)
                                    and (allow_public_dns or ns not in public_resolvers)
                                    and ns not in names
                                ):
                                    names.append(ns)
                return names
            except OSError:
                return []

        try:
            nameservers = _read_nameservers("/etc/resolv.conf")
            if not nameservers:
                for fallback_path in (
                    "/run/systemd/resolve/resolv.conf",
                    "/run/systemd/resolve/stub-resolv.conf",
                ):
                    nameservers = _read_nameservers(fallback_path)
                    if nameservers:
                        break

            if not nameservers:
                return []
            return nameservers
        except Exception as exc:
            telemetry.capture_exception(exc)
            return []

    def configure_system_dns_for_unbound(self, fallback_nameservers: list[str]) -> bool:
        """Configure system resolver to use Unbound first (best effort)."""
        try:
            local_resolver_ip = self._rt.get_local_resolver_ip()
            allow_public_dns = (
                str(os.environ.get("ADSCAN_ALLOW_PUBLIC_DNS", "1")).strip() == "1"
            )

            if self._rt.is_full_container_runtime():
                try:
                    first_ns: str | None = None
                    with open(self._resolv_conf_path, encoding="utf-8") as rf:
                        for raw in rf:
                            line = raw.strip()
                            if not line or line.startswith("#"):
                                continue
                            if line.startswith("nameserver"):
                                parts = line.split()
                                if len(parts) >= 2:
                                    first_ns = parts[1].strip()
                                    break
                    return bool(first_ns == local_resolver_ip)
                except OSError as exc:
                    telemetry.capture_exception(exc)
                    return False

            safe_fallbacks = [
                ns
                for ns in (fallback_nameservers or [])
                if ns
                and ns.strip()
                and not self._rt.is_loopback_ip(ns.strip())
                and (
                    allow_public_dns
                    or ns.strip()
                    not in {
                        "1.1.1.1",
                        "1.0.0.1",
                        "8.8.8.8",
                        "8.8.4.4",
                        "9.9.9.9",
                        "149.112.112.112",
                    }
                )
            ]
            safe_fallbacks = list(dict.fromkeys(safe_fallbacks))

            resolved_active = False
            try:
                resolved_check = self._host.run_command(
                    "systemctl is-active systemd-resolved",
                    timeout=10,
                    ignore_errors=True,
                )
                resolved_active = bool(resolved_check and resolved_check.returncode == 0)
            except Exception:
                resolved_active = False

            if resolved_active:
                dropin_path = self._systemd_resolved_dropin_path
                dropin_dir = os.path.dirname(dropin_path) or "/etc/systemd/resolved.conf.d"
                if not self._host._ensure_system_dir(dropin_dir):
                    return False
                dropin_content = f"[Resolve]\nDNS={local_resolver_ip}\n"
                if safe_fallbacks:
                    dropin_content += f"FallbackDNS={' '.join(safe_fallbacks)}\n"
                if not self._host._write_system_file(dropin_path, dropin_content, mode=0o644):
                    return False

                restart = self._host._run_privileged_command(
                    "systemctl restart systemd-resolved", timeout=60, ignore_errors=True
                )
                if not restart or restart.returncode != 0:
                    print_warning("Failed to restart systemd-resolved after DNS update.")
                    return False

                self._host._run_privileged_command(
                    "resolvectl flush-caches", timeout=10, ignore_errors=True
                )
                return True

            dhcpcd_running = False
            try:
                dhcpcd_proc = self._host.run_command("pgrep -x dhcpcd", timeout=5, ignore_errors=True)
                dhcpcd_running = bool(dhcpcd_proc and dhcpcd_proc.returncode == 0)
            except Exception:
                dhcpcd_running = False

            resolv_lines = [f"nameserver {local_resolver_ip}"]
            resolv_lines.extend([f"nameserver {ns}" for ns in safe_fallbacks])
            if dhcpcd_running:
                if not self.ensure_dhcpcd_preserves_resolv_conf():
                    return False
                self.ensure_dhcpcd_enter_hook_enforces_resolv_conf(resolv_lines)

            wrote = self._host._write_system_file(
                self._resolv_conf_path, "\n".join(resolv_lines).rstrip() + "\n", mode=0o644
            )
            if not wrote:
                return False

            # Verify and self-heal if DHCP overwrote the file.
            try:
                final_text = ""
                with open(self._resolv_conf_path, "r", encoding="utf-8", errors="ignore") as rf:
                    final_text = rf.read()
                has_nameserver = any(
                    line.strip().startswith("nameserver") for line in final_text.splitlines()
                )
                has_local = any(
                    line.strip() == f"nameserver {local_resolver_ip}" for line in final_text.splitlines()
                )
                if not has_nameserver or not has_local:
                    print_warning(
                        "DNS configuration may have been overwritten by the DHCP client. "
                        "Re-applying local resolver settings."
                    )
                    self.log_dns_management_debug(
                        f"resolv.conf unexpectedly empty/missing {local_resolver_ip}"
                    )
                    self._host._write_system_file(
                        self._resolv_conf_path,
                        "\n".join(resolv_lines).rstrip() + "\n",
                        mode=0o644,
                    )
                    self._restart_dhcpcd_best_effort()
            except Exception as exc:
                telemetry.capture_exception(exc)
                print_info_debug(f"[dns] Failed to verify resolv.conf after update: {exc}")

            return True
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_warning("Error configuring system DNS for Unbound.")
            print_exception(show_locals=False, exception=exc)
            return False

    def clean_domain_entries(self, domain: str) -> bool:
        """Remove ADscan resolver entries for a domain from Unbound and /etc/hosts."""
        try:
            normalized_domain = (domain or "").strip().lower().rstrip(".")
            marked_domain = mark_sensitive(domain, "domain")

            # Unbound forward-zone cleanup.
            try:
                domain_forwarders, root_forwarders = self.read_forward_zones()
                if normalized_domain in domain_forwarders:
                    domain_forwarders.pop(normalized_domain, None)
                    if not root_forwarders:
                        root_forwarders = self.get_existing_nameservers()
                    if self.ensure_unbound_available():
                        self.write_unbound_config(
                            domain_forwarders=domain_forwarders,
                            root_forwarders=root_forwarders,
                        )
                        self.restart_unbound()
            except Exception as exc:
                telemetry.capture_exception(exc)
                print_warning_debug(f"[DNS] Could not clean Unbound forward-zone for {marked_domain}")

            # /etc/hosts cleanup (best effort, managed by markers).
            hosts_path = self._hosts_path
            try:
                if not os.path.exists(hosts_path):
                    return True

                with open(hosts_path, "r", encoding="utf-8", errors="ignore") as f:
                    all_lines = f.readlines()

                cleaned_lines: list[str] = []
                cleaned_hosts = False
                for line in all_lines:
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        cleaned_lines.append(line)
                        continue
                    if is_adscan_hosts_line_for_domain(stripped, domain):
                        cleaned_hosts = True
                        continue
                    cleaned_lines.append(line)

                if cleaned_hosts:
                    if not self._host._write_system_file(hosts_path, "".join(cleaned_lines), mode=0o644):
                        print_warning(f"Could not update /etc/hosts while cleaning entries for {marked_domain}.")
                return True
            except PermissionError as exc:
                telemetry.capture_exception(exc)
                print_warning(f"Permission denied cleaning /etc/hosts for {marked_domain}.")
                print_exception(show_locals=False, exception=exc)
                return False
            except Exception as exc:
                telemetry.capture_exception(exc)
                print_warning(f"Could not clean /etc/hosts for {marked_domain}.")
                print_exception(show_locals=False, exception=exc)
                return False
        except Exception as exc:
            telemetry.capture_exception(exc)
            marked_domain = mark_sensitive(domain, "domain")
            print_warning(f"Error cleaning domain entries for {marked_domain}.")
            print_exception(show_locals=False, exception=exc)
            return False

    def add_hosts_entry(self, domain: str, ip: str | None, hostname: str | None) -> bool:
        """Add or refresh a /etc/hosts entry for a domain's PDC."""
        hosts_path = self._hosts_path
        try:
            domain_norm = normalize_dns_like(domain)
            ip_norm = (ip or "").strip()
            hostname_norm = normalize_dns_like(hostname or "")

            if not domain_norm or not ip_norm or not hostname_norm:
                print_warning(
                    "Cannot add entry to /etc/hosts: missing domain, PDC IP, or hostname."
                )
                return False

            fqdn_norm = f"{hostname_norm}.{domain_norm}"
            entry = f"{ip_norm}\t{fqdn_norm}\t{hostname_norm}\t{domain_norm}"

            if not os.path.exists(hosts_path):
                if not self._host._write_system_file(hosts_path, entry + "\n", mode=0o644):
                    print_warning(
                        f"Could not create {hosts_path} (sudo may be required for this system)."
                    )
                    return False
                marked_hosts = mark_sensitive(hosts_path, "path")
                marked_ip = mark_sensitive(ip_norm, "ip")
                marked_fqdn = mark_sensitive(fqdn_norm, "host")
                marked_host = mark_sensitive(hostname_norm, "host")
                marked_domain = mark_sensitive(domain_norm, "domain")
                print_info_debug(
                    "[dns] Added /etc/hosts entry: "
                    f"{marked_ip}\t{marked_fqdn}\t{marked_host}\t{marked_domain} "
                    f"(file={marked_hosts})"
                )
                return True

            with open(hosts_path, "r", encoding="utf-8") as file:
                content = file.read().splitlines()

            empty_line_count = sum(1 for line in content if not line.strip())
            total_lines = len(content)
            if empty_line_count > max(1000, total_lines * 0.5):
                print_warning(
                    f"Detected excessive empty lines in {hosts_path} ({empty_line_count}/{total_lines}). Cleaning..."
                )
                self._clean_hosts_file()
                with open(hosts_path, "r", encoding="utf-8") as file:
                    content = file.read().splitlines()

            entry_exists = False
            entries_to_remove: list[str] = []
            cleaned_content: list[str] = []
            last_was_empty = False

            for line in content:
                stripped = line.strip()
                if not stripped:
                    if not last_was_empty:
                        cleaned_content.append("")
                        last_was_empty = True
                    continue

                last_was_empty = False

                if stripped.startswith("#"):
                    cleaned_content.append(line)
                    continue

                parts = line.split()
                if len(parts) >= 2:
                    line_ip = parts[0]
                    is_our_domain = is_adscan_hosts_line_for_domain(stripped, domain_norm)
                    if is_our_domain:
                        parts1_norm = normalize_dns_like(parts[1])
                        if line_ip == ip_norm and parts1_norm == fqdn_norm:
                            entry_exists = True
                            cleaned_content.append(line)
                        elif line_ip != ip_norm:
                            entries_to_remove.append(line)
                        else:
                            cleaned_content.append(line)
                    else:
                        cleaned_content.append(line)
                else:
                    cleaned_content.append(line)

            while cleaned_content and not cleaned_content[-1].strip():
                cleaned_content.pop()

            needs_write = entries_to_remove or not entry_exists
            if needs_write:
                final_lines = list(cleaned_content)
                if not entry_exists:
                    final_lines.append(entry)
                final_content = "\n".join(final_lines).rstrip("\n") + "\n"
                if not self._host._write_system_file(hosts_path, final_content, mode=0o644):
                    print_warning(
                        f"Could not update {hosts_path} (sudo may be required for this system)."
                    )
                    return False
                if not entry_exists:
                    marked_hosts = mark_sensitive(hosts_path, "path")
                    marked_ip = mark_sensitive(ip_norm, "ip")
                    marked_fqdn = mark_sensitive(fqdn_norm, "host")
                    marked_host = mark_sensitive(hostname_norm, "host")
                    marked_domain = mark_sensitive(domain_norm, "domain")
                    print_info_debug(
                        "[dns] Added /etc/hosts entry: "
                        f"{marked_ip}\t{marked_fqdn}\t{marked_host}\t{marked_domain} "
                        f"(file={marked_hosts})"
                    )
            return True
        except PermissionError as exc:
            telemetry.capture_exception(exc)
            marked_hosts = mark_sensitive(hosts_path, "path")
            print_error(
                f"Error: Superuser permissions are required to modify {marked_hosts}"
            )
            print_info("Run the script with sudo to add the entries")
            return False
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_error(f"Error modifying {hosts_path}.")
            print_exception(show_locals=False, exception=exc)
            return False

    def _clean_hosts_file(self) -> bool:
        """Clean excessive empty lines from /etc/hosts while preserving structure."""
        hosts_path = self._hosts_path
        try:
            print_info("Cleaning /etc/hosts file from excessive empty lines...")
            with open(hosts_path, "r", encoding="utf-8") as file:
                content = file.read().splitlines()

            print_info_verbose(f"Read {len(content)} lines from /etc/hosts")

            cleaned_content: list[str] = []
            last_was_empty = False
            for line in content:
                stripped = line.strip()
                if not stripped:
                    if not last_was_empty:
                        cleaned_content.append("")
                        last_was_empty = True
                    continue
                last_was_empty = False
                cleaned_content.append(line)

            while cleaned_content and not cleaned_content[-1].strip():
                cleaned_content.pop()

            print_info_verbose(f"Cleaned to {len(cleaned_content)} lines")

            if not self._host._write_system_file(
                hosts_path, "\n".join(cleaned_content).rstrip("\n") + "\n", mode=0o644
            ):
                print_warning(f"Could not write cleaned /etc/hosts to {hosts_path}")
                return False

            print_success("Cleaned /etc/hosts successfully.")
            return True
        except PermissionError as exc:
            telemetry.capture_exception(exc)
            marked_hosts = mark_sensitive(hosts_path, "path")
            print_error(
                f"Error: Superuser permissions are required to clean {marked_hosts}"
            )
            print_info("Run the script with sudo to clean the hosts file")
            return False
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_error("Error cleaning /etc/hosts.")
            print_exception(show_locals=False, exception=exc)
            return False

    def ensure_dhcpcd_enter_hook_enforces_resolv_conf(self, resolv_lines: list[str]) -> bool:
        """Ensure dhcpcd enter-hook enforces /etc/resolv.conf on DHCP events."""
        hook_path = self._dhcpcd_enter_hook_path
        start_marker = "# ADscan resolv.conf enforcement start"
        end_marker = "# ADscan resolv.conf enforcement end"

        desired_resolv_text = "\n".join(resolv_lines).rstrip() + "\n"
        hook_block_lines = [
            start_marker,
            "# Managed by ADscan - ensure resolv.conf stays pointed to the local resolver (Unbound).",
            "# This runs after DHCP events; only applies when /etc/resolv.conf is a regular file.",
            "if [ -e /etc/resolv.conf ] && [ ! -L /etc/resolv.conf ]; then",
            "  umask 022",
            "  cat > /etc/resolv.conf <<'ADSCAN_EOF'",
            desired_resolv_text.rstrip("\n"),
            "ADSCAN_EOF",
            "fi",
            end_marker,
            "",
        ]
        hook_block = "\n".join(hook_block_lines)

        try:
            existing = ""
            if os.path.exists(hook_path):
                with open(hook_path, "r", encoding="utf-8", errors="ignore") as f:
                    existing = f.read()

            if start_marker in existing and end_marker in existing:
                prefix, rest = existing.split(start_marker, 1)
                _, suffix = rest.split(end_marker, 1)
                new_content = prefix.rstrip("\n") + "\n" + hook_block + suffix.lstrip("\n")
            else:
                shebang = "#!/bin/sh\n\n"
                new_content = (existing.rstrip("\n") + "\n\n" + hook_block) if existing.strip() else (shebang + hook_block)

            if not self._host._write_system_file(hook_path, new_content, mode=0o755):
                return False

            print_info_verbose("Ensured dhcpcd enter-hook enforces /etc/resolv.conf")
            return True
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_warning("Failed to configure dhcpcd enter-hook for resolv.conf enforcement.")
            print_exception(show_locals=False, exception=exc)
            return False

    def _stop_dnsmasq_if_conflicting(self) -> None:
        """Stop dnsmasq when it occupies port 53 and blocks Unbound (best effort)."""
        try:
            dnsmasq_active = self._host.run_command("systemctl is-active dnsmasq", timeout=8, ignore_errors=True)
            if not dnsmasq_active or dnsmasq_active.returncode != 0:
                return
            tcp_listeners = self._host.run_command("ss -H -ltnup", timeout=10, ignore_errors=True)
            udp_listeners = self._host.run_command("ss -H -lunp", timeout=10, ignore_errors=True)
            listeners = "\n".join([(tcp_listeners.stdout or "") if tcp_listeners else "", (udp_listeners.stdout or "") if udp_listeners else ""])
            if ":53" in listeners and "dnsmasq" in listeners:
                print_warning("dnsmasq is running and is using port 53; stopping it to allow Unbound to start.")
                is_enabled = self._host.run_command("systemctl is-enabled dnsmasq", timeout=10, ignore_errors=True)
                systemd_available = bool(is_enabled is not None)
                # Reuse the privileged runner path provided by host (interactive when needed).
                self._host._run_privileged_command("systemctl disable --now dnsmasq", timeout=60, ignore_errors=True)
                if systemd_available:
                    self._host._run_privileged_command("systemctl stop dnsmasq", timeout=30, ignore_errors=True)
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_warning_debug("[dns] Failed to stop dnsmasq automatically.")

    def log_dns_management_debug(self, context: str) -> None:
        """Log DNS management context to help diagnose resolv.conf persistence issues."""
        try:
            resolv_conf_path = self._resolv_conf_path
            try:
                resolv_target = os.path.realpath(resolv_conf_path)
                is_symlink = os.path.islink(resolv_conf_path)
            except OSError:
                resolv_target = resolv_conf_path
                is_symlink = False

            marked_target = mark_sensitive(resolv_target, "path")
            marked_resolv = mark_sensitive(resolv_conf_path, "path")
            print_info_debug(
                f"[dns] {context}: resolv.conf={marked_resolv} "
                f"(symlink={is_symlink}, realpath={marked_target})"
            )

            probes: dict[str, str] = {
                "dhcpcd.proc": "pgrep -x dhcpcd",
                "dhcpcd.cmdline": "ps -o pid,args -C dhcpcd",
            }
            if self._rt.is_systemd_available():
                probes.update(
                    {
                        "NetworkManager": "systemctl is-active NetworkManager",
                        "systemd-networkd": "systemctl is-active systemd-networkd",
                        "systemd-resolved": "systemctl is-active systemd-resolved",
                        "dhcpcd.service": "systemctl status dhcpcd --no-pager",
                    }
                )
            for label, cmd in probes.items():
                result = self._host.run_command(cmd, timeout=8, ignore_errors=True)
                status = "unknown"
                details = ""
                if result is not None:
                    status = str(result.returncode)
                    preview = (result.stdout or result.stderr or "").strip().splitlines()[:1]
                    details = preview[0] if preview else ""
                if details:
                    details = details.replace(
                        resolv_conf_path, str(mark_sensitive(resolv_conf_path, "path"))
                    )
                print_info_debug(f"[dns] {context}: {label} rc={status} {details}".rstrip())
        except Exception as exc:  # pragma: no cover
            telemetry.capture_exception(exc)
            print_info_debug(f"[dns] Failed to collect DNS management context: {exc}")

    def ensure_dhcpcd_preserves_resolv_conf(self) -> bool:
        """Ensure dhcpcd does not overwrite resolv.conf (host installs)."""
        local_resolver_ip = self._rt.get_local_resolver_ip()
        dhcpcd_conf = self._dhcpcd_conf_path
        start_marker = "# ADscan resolv.conf management start"
        end_marker = "# ADscan resolv.conf management end"
        block_lines = [
            start_marker,
            "# Managed by ADscan - keeps resolv.conf pointed at the local resolver (Unbound)",
            "nohook resolv.conf",
            f"static domain_name_servers={local_resolver_ip}",
            end_marker,
        ]

        try:
            self.log_dns_management_debug("before dhcpcd.conf update")
            original_content = ""
            lines: list[str] = []
            if os.path.exists(dhcpcd_conf):
                with open(dhcpcd_conf, "r", encoding="utf-8") as conf:
                    original_content = conf.read()
                    lines = original_content.splitlines()

            filtered_lines: list[str] = []
            skip_block = False
            for line in lines:
                stripped = line.strip()
                if stripped == start_marker:
                    skip_block = True
                    continue
                if stripped == end_marker:
                    skip_block = False
                    continue
                if not skip_block:
                    filtered_lines.append(line)

            new_lines = [line.rstrip("\n") for line in filtered_lines if line is not None]
            if new_lines and new_lines[-1].strip():
                new_lines.append("")
            new_lines.extend(block_lines)
            new_content = "\n".join(new_lines).rstrip() + "\n"

            if new_content != (original_content or ""):
                if not self._host._write_system_file(dhcpcd_conf, new_content, mode=0o644):
                    print_warning("Failed to update dhcpcd configuration for resolv.conf persistence.")
                    return False

            self.log_dns_management_debug("after dhcpcd.conf update")
            self._restart_dhcpcd_best_effort()
            return True
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_warning("Failed to configure dhcpcd for resolv.conf persistence.")
            print_exception(show_locals=False, exception=exc)
            return False

    def _restart_dhcpcd_best_effort(self) -> bool:
        """Best-effort restart/reload of dhcpcd after DNS config changes."""
        try:
            restarted = False
            systemctl_result = self._host._run_privileged_command(
                "systemctl restart dhcpcd", timeout=60, ignore_errors=True
            )
            if systemctl_result and systemctl_result.returncode == 0:
                print_info_verbose("Restarted dhcpcd service via systemctl")
                restarted = True
            elif systemctl_result and systemctl_result.stderr:
                stderr = systemctl_result.stderr.strip()
                if "Unit dhcpcd.service not found" in stderr:
                    print_info_debug(
                        "dhcpcd.service not found via systemctl; attempting non-systemd reload"
                    )
                else:
                    print_warning(f"Could not restart dhcpcd via systemctl: {stderr}")

            if not restarted:
                service_result = self._host._run_privileged_command(
                    "service dhcpcd restart", timeout=60, ignore_errors=True
                )
                if service_result and service_result.returncode == 0:
                    print_info_verbose("Restarted dhcpcd service via service command")
                    restarted = True
                elif service_result and service_result.stderr:
                    stderr = service_result.stderr.strip()
                    if "Unit dhcpcd.service not found" in stderr:
                        print_info_debug(
                            "dhcpcd service command not available; attempting non-systemd reload"
                        )
                    else:
                        print_warning(f"Could not restart dhcpcd via service command: {stderr}")

            if not restarted:
                reload_result = self._host._run_privileged_command(
                    "dhcpcd -n", timeout=60, ignore_errors=True
                )
                if reload_result and reload_result.returncode == 0:
                    print_info_verbose("Reloaded dhcpcd via 'dhcpcd -n'")
                    restarted = True

            if not restarted:
                hup_result = self._host._run_privileged_command(
                    "pkill -HUP -x dhcpcd", timeout=30, ignore_errors=True
                )
                if hup_result and hup_result.returncode == 0:
                    print_info_verbose("Reloaded dhcpcd via SIGHUP (pkill -HUP)")
                    restarted = True

            if not restarted:
                print_warning("dhcpcd restart failed. DNS changes will apply on the next DHCP cycle.")
            return restarted
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_warning("Error restarting dhcpcd service.")
            print_exception(show_locals=False, exception=exc)
            return False

    def restart_dhcpcd_service(self) -> bool:
        """Public wrapper for restarting dhcpcd (best effort)."""
        return self._restart_dhcpcd_best_effort()
