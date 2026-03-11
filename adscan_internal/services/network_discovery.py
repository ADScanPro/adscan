"""Network discovery helpers for ADscan.

This module centralises small, reusable pieces of network discovery logic that
were previously embedded in the monolithic ``adscan.py`` shell implementation.

The goal is to keep the heavy lifting here so CLI/interactive code can remain
thin wrappers while still preserving legacy behaviour.
"""

from __future__ import annotations

from typing import Protocol
import re
import shlex
import time

from adscan_internal import telemetry
from adscan_internal.rich_output import (
    mark_sensitive,
    print_error,
    print_exception,
    print_info_debug,
    print_info_verbose,
)


class NetworkDiscoveryHost(Protocol):
    """Host interface required by the network discovery helpers."""

    def run_command(self, command: str, **kwargs):  # noqa: ANN001
        ...

    netexec_path: str | None


_BANNER_DOMAIN_PATTERN = re.compile(r"\(domain:(\S+?)\)", flags=re.IGNORECASE)
_BANNER_NAME_PATTERN = re.compile(r"\(name:(\S+?)\)", flags=re.IGNORECASE)


def _infer_domain_from_netexec_banner(
    host: NetworkDiscoveryHost,
    *,
    protocol: str,
    target_ip: str,
    timeout_seconds: int = 60,
    attempts: int = 3,
    retry_delay_seconds: float = 1.0,
    auth_args: str = "",
) -> tuple[str | None, str | None]:
    """Infer a domain from a NetExec protocol banner.

    Args:
        host: Object providing ``run_command`` and optionally ``netexec_path``.
        protocol: NetExec protocol to probe (for example ``smb`` or ``ldap``).
        target_ip: Target host IP address (DC/DNS candidate).
        timeout_seconds: Max time allowed for the NetExec probe.
        attempts: Number of retries when the probe returns no banner.
        retry_delay_seconds: Delay between retries.
        auth_args: Optional additional CLI arguments for NetExec.

    Returns:
        Tuple of ``(domain_fqdn, hostname)``. Values are ``None`` when inference
        fails.
    """
    try:
        netexec_path = getattr(host, "netexec_path", None)
        if not netexec_path:
            return None, None

        ip_clean = (target_ip or "").strip()
        if not ip_clean:
            return None, None

        auth_suffix = f" {auth_args.strip()}" if auth_args.strip() else ""
        cmd = (
            f"{shlex.quote(netexec_path)} {shlex.quote(protocol)} "
            f"{shlex.quote(ip_clean)}{auth_suffix}"
        )

        last_hostname: str | None = None
        protocol_label = protocol.lower()
        for attempt in range(1, max(attempts, 1) + 1):
            proc = host.run_command(cmd, timeout=timeout_seconds, ignore_errors=True)
            if not proc:
                if attempt < attempts:
                    marked_ip = mark_sensitive(ip_clean, "ip")
                    print_info_debug(
                        f"[{protocol_label}_infer] NetExec returned no result for "
                        f"{marked_ip}; retrying ({attempt}/{attempts})"
                    )
                    time.sleep(retry_delay_seconds)
                    continue
                return None, None

            stdout = (getattr(proc, "stdout", "") or "").strip()
            stderr = (getattr(proc, "stderr", "") or "").strip()
            combined = stdout or stderr
            if not combined:
                if attempt < attempts:
                    print_info_debug(
                        f"[{protocol_label}_infer] Empty {protocol_label.upper()} "
                        f"banner output; retrying ({attempt}/{attempts})"
                    )
                    time.sleep(retry_delay_seconds)
                    continue
                return None, None

            if getattr(proc, "returncode", 0) != 0:
                marked_ip = mark_sensitive(ip_clean, "ip")
                print_info_debug(
                    f"[{protocol_label}_infer] NetExec returned non-zero exit code "
                    f"for {marked_ip}, attempting to parse output anyway."
                )

            domain_matches = _BANNER_DOMAIN_PATTERN.findall(combined)
            name_matches = _BANNER_NAME_PATTERN.findall(combined)
            hostname = name_matches[0].strip().rstrip(".") if name_matches else None
            last_hostname = hostname or last_hostname

            domain = domain_matches[0].strip().rstrip(".") if domain_matches else None
            if not domain:
                if (
                    "first time use detected" in stdout.lower()
                    or "creating home directory structure" in stdout.lower()
                    or "copying default configuration file" in stdout.lower()
                ) and attempt < attempts:
                    print_info_debug(
                        f"[{protocol_label}_infer] NetExec initialization detected; "
                        f"retrying {protocol_label.upper()} banner."
                    )
                    time.sleep(retry_delay_seconds)
                    continue
                return None, hostname

            domain_norm = domain.strip().lower()
            if domain_norm in {"workgroup", "unknown"}:
                return None, hostname

            if "." not in domain_norm:
                return None, hostname

            return domain_norm, hostname

        return None, last_hostname
    except Exception as exc:  # noqa: BLE001 - preserve legacy catch-all semantics
        telemetry.capture_exception(exc)
        print_exception(show_locals=False, exception=exc)
        return None, None


def infer_domain_from_smb_banner(
    host: NetworkDiscoveryHost,
    *,
    target_ip: str,
    timeout_seconds: int = 60,
    attempts: int = 3,
    retry_delay_seconds: float = 1.0,
) -> tuple[str | None, str | None]:
    """Infer a domain (FQDN) from NetExec SMB banner output against a target IP.

    This is used as a best-effort fallback when DNS (PTR/SRV) is unavailable but
    SMB is reachable and NetExec can fingerprint the remote host.

    Args:
        host: Object providing ``run_command`` and optionally ``netexec_path``.
        target_ip: Target host IP address (DC/DNS candidate).
        timeout_seconds: Max time allowed for the NetExec probe.

    Returns:
        Tuple of (domain_fqdn, hostname). Values are ``None`` when inference fails.
    """
    return _infer_domain_from_netexec_banner(
        host,
        protocol="smb",
        target_ip=target_ip,
        timeout_seconds=timeout_seconds,
        attempts=attempts,
        retry_delay_seconds=retry_delay_seconds,
    )


def infer_domain_from_ldap_banner(
    host: NetworkDiscoveryHost,
    *,
    target_ip: str,
    timeout_seconds: int = 60,
    attempts: int = 3,
    retry_delay_seconds: float = 1.0,
) -> tuple[str | None, str | None]:
    """Infer a domain (FQDN) from NetExec LDAP banner output against a target IP.

    LDAP is often available on DCs even when SMB/445 is filtered, so this is a
    stronger fallback than SMB for DC/DNS candidate IPs.
    """
    return _infer_domain_from_netexec_banner(
        host,
        protocol="ldap",
        target_ip=target_ip,
        timeout_seconds=timeout_seconds,
        attempts=attempts,
        retry_delay_seconds=retry_delay_seconds,
        auth_args="-u '' -p ''",
    )


def extract_netbios(host: NetworkDiscoveryHost, domain: str) -> str | None:
    """Extract the NetBIOS name for a domain using ``nmblookup``.

    The behaviour mirrors the legacy ``PentestShell.do_extract_netbios`` method:
    - Try to obtain the NetBIOS name via ``nmblookup -A``.
    - If that fails, fall back to the first label of the domain (upper‑cased).

    Args:
        host: Object providing ``run_command`` (typically the interactive shell).
        domain: Domain name from which to derive NetBIOS.

    Returns:
        The extracted or derived NetBIOS name, or ``None`` in case of error.
    """
    try:
        marked_domain = mark_sensitive(domain, "domain")
        domain_clean = (domain or "").strip()
        if not domain_clean:
            return None

        command = f"nmblookup -A {shlex.quote(domain_clean)} | grep -i group | awk '{{print $1}}' | sort | uniq"
        proc = host.run_command(command, timeout=300)

        if proc and proc.returncode == 0 and proc.stdout:
            netbios = proc.stdout.strip()
            return netbios

        # If NetBIOS is not obtained, take the first part of the domain and convert it to uppercase.
        netbios_default = (domain or "").split(".")[0].upper()
        marked_netbios_default = mark_sensitive(netbios_default, "domain")
        print_info_verbose(
            f"Could not extract NetBIOS from domain {marked_domain}, using {marked_netbios_default} as default."
        )
        return netbios_default
    except Exception as exc:  # noqa: BLE001 - preserve legacy catch-all semantics
        telemetry.capture_exception(exc)
        print_error("Error extracting NetBIOS.")
        print_exception(show_locals=False, exception=exc)
        return None
