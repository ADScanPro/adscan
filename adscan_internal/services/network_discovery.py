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


_SMB_DOMAIN_PATTERN = re.compile(r"\(domain:(\S+?)\)", flags=re.IGNORECASE)
_SMB_NAME_PATTERN = re.compile(r"\(name:(\S+?)\)", flags=re.IGNORECASE)


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
    try:
        netexec_path = getattr(host, "netexec_path", None)
        if not netexec_path:
            return None, None

        ip_clean = (target_ip or "").strip()
        if not ip_clean:
            return None, None

        cmd = f"{shlex.quote(netexec_path)} smb {shlex.quote(ip_clean)}"

        last_hostname: str | None = None
        for attempt in range(1, max(attempts, 1) + 1):
            proc = host.run_command(cmd, timeout=timeout_seconds, ignore_errors=True)
            if not proc:
                if attempt < attempts:
                    marked_ip = mark_sensitive(ip_clean, "ip")
                    print_info_debug(
                        f"[smb_infer] NetExec returned no result for {marked_ip}; "
                        f"retrying ({attempt}/{attempts})"
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
                        f"[smb_infer] Empty SMB banner output; retrying ({attempt}/{attempts})"
                    )
                    time.sleep(retry_delay_seconds)
                    continue
                return None, None

            if getattr(proc, "returncode", 0) != 0:
                try:
                    marked_ip = mark_sensitive(ip_clean, "ip")
                    print_info_debug(
                        f"[smb_infer] NetExec returned non-zero exit code "
                        f"for {marked_ip}, attempting to parse output anyway."
                    )
                except Exception:
                    pass

            domain_matches = _SMB_DOMAIN_PATTERN.findall(combined)
            name_matches = _SMB_NAME_PATTERN.findall(combined)
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
                        "[smb_infer] NetExec initialization detected; retrying SMB banner."
                    )
                    time.sleep(retry_delay_seconds)
                    continue
                return None, hostname

            domain_norm = domain.strip().lower()
            if domain_norm in {"workgroup", "unknown"}:
                return None, hostname

            # Prefer FQDN domains only; NetExec may report a NetBIOS name in some cases.
            if "." not in domain_norm:
                return None, hostname

            return domain_norm, hostname

        return None, last_hostname
    except Exception as exc:  # noqa: BLE001 - preserve legacy catch-all semantics
        telemetry.capture_exception(exc)
        print_exception(show_locals=False, exception=exc)
        return None, None


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
