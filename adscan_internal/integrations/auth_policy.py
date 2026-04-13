"""Shared authentication execution policy for external tooling.

This module centralizes Kerberos-first / NTLM-fallback decisions for tools
that operate against Active Directory. The goal is to keep runner-specific
code focused on command execution while the auth preference logic stays
consistent across NetExec and Impacket integrations.
"""

from __future__ import annotations

import ipaddress
import shlex
from dataclasses import dataclass
from typing import Any, Mapping

from adscan_internal.services.auth_posture_service import get_ntlm_status


_NTLM_DISABLED_MARKERS = (
    "STATUS_NOT_SUPPORTED",
    "NTLM NEGOTIATION FAILED",
    "NTLMAUTHNEGOTIATE REQUEST",
)

_KERBEROS_FAILURE_MARKERS = (
    "KDC_ERR_PREAUTH_FAILED",
    "KRB_AP_ERR",
    "KDC_ERR",
    "NO CREDENTIALS WERE SUPPLIED",
    "CLIENT NOT FOUND IN KERBEROS DATABASE",
    "SERVER NOT FOUND IN KERBEROS DATABASE",
    "PREAUTHENTICATION FAILED",
    "TICKET EXPIRED",
    "GSSError".upper(),
    "GSSAPI",
)

_KERBEROS_INVALID_CREDENTIAL_MARKERS = (
    "KDC_ERR_PREAUTH_FAILED",
    "PREAUTHENTICATION FAILED",
)

_NETEXEC_UNAUTH_USERNAMES = {"", "guest", "anonymous", "null"}
_NETEXEC_KERBEROS_SUPPORTED_PROTOCOLS = {"smb", "ldap"}


@dataclass(frozen=True)
class AuthPolicyDecision:
    """Structured initial auth-mode decision for one runner invocation."""

    prefer_kerberos: bool
    ntlm_status: str
    reason: str


def output_indicates_ntlm_disabled(output: str) -> bool:
    """Return True when tool output indicates NTLM is disabled/unsupported."""
    upper = str(output or "").upper()
    return any(marker in upper for marker in _NTLM_DISABLED_MARKERS)


def output_indicates_kerberos_auth_failure(output: str) -> bool:
    """Return True when tool output looks like a Kerberos auth failure."""
    upper = str(output or "").upper()
    return any(marker in upper for marker in _KERBEROS_FAILURE_MARKERS)


def output_indicates_kerberos_invalid_credentials(output: str) -> bool:
    """Return True when Kerberos definitively rejected the supplied credential.

    These markers already prove the target principal exists and the provided
    secret is wrong, so falling back to NTLM would add a second logon attempt
    with no upside and can unnecessarily increase lockout risk.
    """
    upper = str(output or "").upper()
    return any(marker in upper for marker in _KERBEROS_INVALID_CREDENTIAL_MARKERS)


def should_prefer_kerberos_first(
    *,
    domains_data: Mapping[str, Any] | None,
    domain: str | None,
    protocol: str | None,
    default_preference: bool,
) -> bool:
    """Return whether one runner should start with Kerberos.

    Stored auth posture overrides the runner default:
    - ``likely_disabled`` => Kerberos-first
    - ``likely_enabled`` => NTLM-first
    - ``unknown`` => keep runner default
    """
    status = get_ntlm_status(domains_data, domain=domain, protocol=protocol)
    if status == "likely_disabled":
        return True
    if status == "likely_enabled":
        return False
    return default_preference


def resolve_auth_policy_decision(
    *,
    domains_data: Mapping[str, Any] | None,
    domain: str | None,
    protocol: str | None,
    default_preference: bool,
) -> AuthPolicyDecision:
    """Return the initial auth-mode decision and its reason."""
    status = get_ntlm_status(domains_data, domain=domain, protocol=protocol)
    if status == "likely_disabled":
        return AuthPolicyDecision(
            prefer_kerberos=True,
            ntlm_status=status,
            reason="ntlm_likely_disabled",
        )
    if status == "likely_enabled":
        return AuthPolicyDecision(
            prefer_kerberos=False,
            ntlm_status=status,
            reason="ntlm_likely_enabled",
        )
    return AuthPolicyDecision(
        prefer_kerberos=default_preference,
        ntlm_status=status,
        reason="default_kerberos_first" if default_preference else "default_ntlm_first",
    )


def should_prefer_kerberos_first_for_netexec(
    *,
    command: str,
    domains_data: Mapping[str, Any] | None,
    domain: str | None,
    protocol: str | None,
    domain_configured: bool,
    target_count: int,
) -> bool:
    """Return whether NetExec should start with Kerberos for one command."""
    return resolve_netexec_auth_policy_decision(
        command=command,
        domains_data=domains_data,
        domain=domain,
        protocol=protocol,
        domain_configured=domain_configured,
        target_count=target_count,
    ).prefer_kerberos


def resolve_netexec_auth_policy_decision(
    *,
    command: str,
    domains_data: Mapping[str, Any] | None,
    domain: str | None,
    protocol: str | None,
    domain_configured: bool,
    target_count: int,
) -> AuthPolicyDecision:
    """Return the NetExec initial auth-mode decision and its reason."""
    if _is_netexec_unauth_probe(command):
        return AuthPolicyDecision(
            prefer_kerberos=False,
            ntlm_status="unknown",
            reason="unauth_probe",
        )

    protocol_key = str(protocol or "").strip().lower()
    if protocol_key not in _NETEXEC_KERBEROS_SUPPORTED_PROTOCOLS:
        return AuthPolicyDecision(
            prefer_kerberos=False,
            ntlm_status="unknown",
            reason="protocol_kerberos_unsupported",
        )

    base_decision = resolve_auth_policy_decision(
        domains_data=domains_data,
        domain=domain,
        protocol=protocol,
        default_preference=False,
    )
    if base_decision.ntlm_status in {"likely_disabled", "likely_enabled"}:
        return base_decision

    if not domain_configured:
        return AuthPolicyDecision(
            prefer_kerberos=False,
            ntlm_status=base_decision.ntlm_status,
            reason="domain_not_configured",
        )
    if target_count > 1:
        return AuthPolicyDecision(
            prefer_kerberos=False,
            ntlm_status=base_decision.ntlm_status,
            reason="wide_target_scope",
        )

    target = _extract_netexec_target(command)
    if not target:
        return AuthPolicyDecision(
            prefer_kerberos=False,
            ntlm_status=base_decision.ntlm_status,
            reason="missing_target",
        )
    if _is_ip_address(target):
        return AuthPolicyDecision(
            prefer_kerberos=False,
            ntlm_status=base_decision.ntlm_status,
            reason="ip_target",
        )

    domain_info = _get_domain_entry(domains_data, domain)
    if _target_matches_known_dc(target, domain=domain, domain_info=domain_info):
        return AuthPolicyDecision(
            prefer_kerberos=True,
            ntlm_status=base_decision.ntlm_status,
            reason="known_dc_target",
        )

    if protocol_key == "ldap" and _looks_like_domain_hostname(target, domain):
        return AuthPolicyDecision(
            prefer_kerberos=True,
            ntlm_status=base_decision.ntlm_status,
            reason="ldap_domain_hostname",
        )
    return AuthPolicyDecision(
        prefer_kerberos=False,
        ntlm_status=base_decision.ntlm_status,
        reason="default_ntlm_first",
    )


def netexec_can_use_kerberos(command: str) -> bool:
    """Return whether one NetExec command is eligible for Kerberos auth."""
    try:
        argv = shlex.split(command)
    except ValueError:
        return False
    service = _extract_netexec_service_from_argv(argv)
    if service not in _NETEXEC_KERBEROS_SUPPORTED_PROTOCOLS:
        return False
    if _is_netexec_unauth_probe(command):
        return False
    if "-k" in argv or "--local-auth" in argv or "-no-pass" in argv:
        return False
    if "-u" not in argv:
        return False
    if "-d" not in argv and "--domain" not in argv:
        return False
    if "-p" not in argv and "-H" not in argv:
        return False
    return _flag_has_value(argv, "-u") and (
        _flag_has_value(argv, "-p") or _flag_has_value(argv, "-H")
    )


def build_netexec_kerberos_command(command: str) -> str | None:
    """Insert ``-k`` into one NetExec command in the auth block."""
    if not netexec_can_use_kerberos(command):
        return None
    try:
        argv = shlex.split(command)
    except ValueError:
        return None

    insert_at = len(argv)
    auth_flag_positions = {
        "-u": 1,
        "-p": 1,
        "-H": 1,
        "-d": 1,
        "--domain": 1,
        "--local-auth": 0,
    }
    last_auth_idx = -1
    index = 0
    while index < len(argv):
        token = argv[index]
        if token in auth_flag_positions:
            last_auth_idx = max(last_auth_idx, index + auth_flag_positions[token])
            index += auth_flag_positions[token] + 1
            continue
        if token == "-M":
            insert_at = index
            break
        index += 1

    if last_auth_idx >= 0:
        insert_at = min(insert_at, last_auth_idx + 1)

    argv.insert(insert_at, "-k")
    return shlex.join(argv)


def build_netexec_ntlm_command(command: str) -> str | None:
    """Strip ``-k`` from one NetExec command for NTLM fallback."""
    try:
        argv = shlex.split(command)
    except ValueError:
        return None
    if "-k" not in argv:
        return None
    return shlex.join([token for token in argv if token != "-k"])


def impacket_script_supports_kerberos_first(script_name: str) -> bool:
    """Return whether one Impacket script should use Kerberos-first policy."""
    return script_name in {"GetUserSPNs.py", "GetNPUsers.py", "secretsdump.py"}


def build_impacket_kerberos_command(script_name: str, command: str) -> str | None:
    """Insert ``-k`` into one supported Impacket command."""
    if not impacket_script_supports_kerberos_first(script_name):
        return None

    try:
        tokens = shlex.split(command)
    except ValueError:
        return None

    if len(tokens) < 2 or "-k" in tokens or "-no-pass" in tokens:
        return None

    if script_name == "GetUserSPNs.py":
        return _build_impacket_getuserspns_kerberos_command(tokens)
    if script_name == "GetNPUsers.py":
        return _build_impacket_getnpusers_kerberos_command(tokens)
    return _build_impacket_secretsdump_kerberos_command(tokens)


def build_impacket_ntlm_command(command: str) -> str | None:
    """Strip ``-k`` from one Impacket command for NTLM fallback."""
    try:
        argv = shlex.split(command)
    except ValueError:
        return None
    if "-k" not in argv:
        return None
    return shlex.join([token for token in argv if token != "-k"])


def _build_impacket_getuserspns_kerberos_command(tokens: list[str]) -> str | None:
    auth_index = next(
        (
            index
            for index, token in enumerate(tokens[1:], start=1)
            if not token.startswith("-")
            and "/" in token
            and token not in {"-target-domain", "-outputfile", "-usersfile", "-dc-ip"}
        ),
        None,
    )
    if auth_index is None:
        return None
    has_password_auth = ":" in tokens[auth_index]
    has_hash_auth = "-hashes" in tokens
    if not has_password_auth and not has_hash_auth:
        return None
    target_domain_index = _find_flag_index(tokens, "-target-domain")
    insert_at = target_domain_index if target_domain_index is not None else auth_index + 1
    return shlex.join(_insert_token(tokens, insert_at, "-k"))


def _build_impacket_getnpusers_kerberos_command(tokens: list[str]) -> str | None:
    user_flag_index = _find_flag_index(tokens, "-u")
    password_flag_index = _find_flag_index(tokens, "-p")
    if user_flag_index is None or password_flag_index is None:
        return None
    if user_flag_index + 1 >= len(tokens) or password_flag_index + 1 >= len(tokens):
        return None
    return shlex.join(_insert_token(tokens, password_flag_index + 2, "-k"))


def _build_impacket_secretsdump_kerberos_command(tokens: list[str]) -> str | None:
    if any(token.upper() == "LOCAL" for token in tokens[1:]):
        return None
    has_password_auth = any(
        not token.startswith("-") and "@" in token and ":" in token for token in tokens[1:]
    )
    has_hash_auth = "-hashes" in tokens
    if not has_password_auth and not has_hash_auth:
        return None
    outputfile_index = _find_flag_index(tokens, "-outputfile")
    if outputfile_index is not None:
        target_index = outputfile_index - 1
    else:
        target_index = next(
            (index for index in range(len(tokens) - 1, 0, -1) if not tokens[index].startswith("-")),
            None,
        )
        if target_index is None:
            return None
    return shlex.join(_insert_token(tokens, target_index, "-k"))


def _flag_has_value(argv: list[str], flag: str) -> bool:
    index = _find_flag_index(argv, flag)
    return index is not None and index + 1 < len(argv) and argv[index + 1].strip().strip("'\"") != ""


def _get_flag_value(argv: list[str], flag: str) -> str | None:
    index = _find_flag_index(argv, flag)
    if index is None or index + 1 >= len(argv):
        return None
    value = str(argv[index + 1]).strip().strip("'\"")
    return value


def _is_netexec_unauth_probe(command: str) -> bool:
    """Return whether one NetExec command is an unauthenticated/guest probe."""
    try:
        argv = shlex.split(command)
    except ValueError:
        return False

    username = str(_get_flag_value(argv, "-u") or "").strip().casefold()
    if username in _NETEXEC_UNAUTH_USERNAMES:
        return True

    if username in {"guest", "anonymous"}:
        password = _get_flag_value(argv, "-p")
        if password is None or str(password).strip() == "":
            return True

    return False


def _find_flag_index(tokens: list[str], flag: str) -> int | None:
    try:
        return tokens.index(flag)
    except ValueError:
        return None


def _insert_token(tokens: list[str], index: int, token: str) -> list[str]:
    new_tokens = list(tokens)
    new_tokens.insert(index, token)
    return new_tokens


def _extract_netexec_target(command: str) -> str | None:
    """Extract the target token from a NetExec command."""
    try:
        argv = shlex.split(command)
    except ValueError:
        return None
    service_index = _find_netexec_service_index(argv)
    if service_index is None or service_index + 1 >= len(argv):
        return None
    return str(argv[service_index + 1]).strip() or None


def _find_netexec_service_index(argv: list[str]) -> int | None:
    """Return the index of the NetExec service token in one argv list."""
    services = {"smb", "ldap", "mssql", "rdp", "winrm", "ssh", "vnc", "ftp", "http", "https"}
    return next((idx for idx, token in enumerate(argv) if token in services), None)


def _extract_netexec_service_from_argv(argv: list[str]) -> str | None:
    """Extract the NetExec service token from one argv list."""
    service_index = _find_netexec_service_index(argv)
    if service_index is None:
        return None
    return str(argv[service_index]).strip().lower() or None


def _is_ip_address(value: str) -> bool:
    """Return whether one value is an IP address."""
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def _target_matches_known_dc(
    target: str,
    *,
    domain: str | None,
    domain_info: Mapping[str, Any] | None,
) -> bool:
    """Return whether one target matches persisted DC identity hints."""
    target_value = str(target or "").strip().casefold()
    if not target_value or not isinstance(domain_info, Mapping):
        return False

    pdc_ip = str(domain_info.get("pdc") or "").strip().casefold()
    pdc_hostname = str(domain_info.get("pdc_hostname") or "").strip().casefold()
    pdc_fqdn = str(domain_info.get("pdc_hostname_fqdn") or domain_info.get("pdc_fqdn") or "").strip().casefold()
    domain_name = str(domain or "").strip().casefold()
    candidates = {
        candidate
        for candidate in {
            pdc_ip,
            pdc_hostname,
            pdc_fqdn,
            f"{pdc_hostname}.{domain_name}" if pdc_hostname and domain_name else "",
        }
        if candidate
    }
    return target_value in candidates


def _looks_like_domain_hostname(target: str, domain: str | None) -> bool:
    """Return whether one target looks like a domain hostname."""
    value = str(target or "").strip().casefold()
    domain_name = str(domain or "").strip().casefold()
    if not value or not domain_name:
        return False
    return value.endswith(f".{domain_name}") or "." not in value


def _get_domain_entry(
    domains_data: Mapping[str, Any] | None,
    domain: str | None,
) -> Mapping[str, Any] | None:
    """Resolve one domain entry from a case-insensitive mapping."""
    if not isinstance(domains_data, Mapping):
        return None
    domain_key = str(domain or "").strip()
    if not domain_key:
        return None
    if domain_key in domains_data:
        value = domains_data.get(domain_key)
        return value if isinstance(value, Mapping) else None
    normalized = domain_key.casefold()
    for key, value in domains_data.items():
        if str(key).strip().casefold() == normalized and isinstance(value, Mapping):
            return value
    return None
