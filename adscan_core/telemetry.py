"""Telemetry helpers for ADscan."""

import base64
import binascii
import functools
import gzip
import hashlib
import hmac
import ipaddress
import json
import os
import platform
import re
import secrets
import time
from datetime import datetime, timezone, timedelta
from html import unescape
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Iterator, Optional, TYPE_CHECKING
from urllib.parse import urlparse
import site
import sys
import traceback
import uuid

import certifi
import requests
import sentry_sdk

from .ssl_certificates import configure_ssl_certificates_for_requests
from adscan_core.offline import offline_mode_enabled
from adscan_core.lab_context import (
    build_lab_slug,
    build_lab_telemetry_fields,
    build_workspace_telemetry_fields,
    normalize_workspace_type,
)
from adscan_core.embedded_telemetry_config import (
    get_cli_shared_token,
    get_posthog_proxy_url_dev,
    get_posthog_proxy_url_legacy,
    get_posthog_proxy_url_prod,
    get_sentry_proxy_url,
    get_vercel_sessions_direct_url,
    get_vercel_sessions_proxy_url,
)
from adscan_core.sensitive import (
    MARKER_CHARS,
    PASSTHROUGH_MARKERS,
    SENSITIVE_MARKERS,
    strip_sensitive_markers,
)
from adscan_core.path_utils import (
    get_adscan_home,
    get_adscan_state_dir,
)
from adscan_core.version_context import (
    detect_installer,
    get_installed_version,
    get_telemetry_version_fields,
    resolve_installed_version_info,
)
from adscan_core.native_secret_scrub import scrub_native_secrets_buffer
from adscan_core.attack_technique_names import is_attack_technique_name

try:
    from adscan_internal.services.session_compromise_state_service import (
        build_session_compromise_metadata,
        normalize_session_compromise_status,
    )
except ImportError:
    _SESSION_COMPROMISE_STATUS_UNKNOWN = "unknown"
    _SESSION_COMPROMISE_STATUS_NONE = "none"
    _SESSION_COMPROMISE_STATUS_USER = "user"
    _SESSION_COMPROMISE_STATUS_DOMAIN = "domain"
    _SESSION_COMPROMISE_STATUS_VALUES = frozenset(
        {
            _SESSION_COMPROMISE_STATUS_UNKNOWN,
            _SESSION_COMPROMISE_STATUS_NONE,
            _SESSION_COMPROMISE_STATUS_USER,
            _SESSION_COMPROMISE_STATUS_DOMAIN,
        }
    )

    def normalize_session_compromise_status(value: Any) -> str:
        """Return a valid session compromise status label."""
        normalized = str(value or "").strip().lower()
        if normalized in _SESSION_COMPROMISE_STATUS_VALUES:
            return normalized
        return _SESSION_COMPROMISE_STATUS_UNKNOWN

    def build_session_compromise_metadata(shell: Any) -> dict[str, Any]:
        """Return telemetry-safe compromise metadata for one shell session."""
        status = normalize_session_compromise_status(
            getattr(shell, "_session_compromise_status", None)
        )
        compromised_users = getattr(shell, "_session_compromised_users", set())
        if not isinstance(compromised_users, set):
            compromised_users = set()

        return {
            "compromise_status": status,
            "user_compromised": status in {
                _SESSION_COMPROMISE_STATUS_USER,
                _SESSION_COMPROMISE_STATUS_DOMAIN,
            },
            "domain_compromised": status == _SESSION_COMPROMISE_STATUS_DOMAIN,
            "compromised_users_count": len(compromised_users),
        }

try:
    from adscan_internal.services.session_ad_scale_metadata import (
        build_session_ad_scale_metadata,
    )
except ImportError:

    def build_session_ad_scale_metadata(shell: Any) -> dict[str, Any]:
        """Fallback when adscan_internal is unavailable (host/launcher context)."""
        return {}

if TYPE_CHECKING:
    from rich.text import Text
else:
    Text = Any

_ExcepthookIntegration: Optional[type[Any]]
try:
    from sentry_sdk.integrations.excepthook import (
        ExcepthookIntegration as _ExcepthookIntegration,
    )
except ImportError:
    _ExcepthookIntegration = None

ExcepthookIntegration = _ExcepthookIntegration


_DEFAULT_IP_PASSTHROUGH: tuple[str, ...] = (
    # Localhost / local resolvers (DNS / Unbound / systemd-resolved style).
    "127.0.0.0/24",
    "127.0.0.53/32",
    "172.0.0.53/32",  # kept as requested (even if uncommon)
    # Common public DNS resolvers (not sensitive, helpful for diagnostics).
    "1.1.1.1/32",
    "8.8.8.8/32",
    "8.8.4.4/32",
)

_PUBLIC_URL_PASSTHROUGH_ALLOWLIST: tuple[str, ...] = (
    "https://nmap.org",
)

_PASSTHROUGH_MARKERS = PASSTHROUGH_MARKERS["passthrough"]

# Well-known AD principals (built-in users/groups) that can be preserved in telemetry.
# Default behavior remains "sanitize everything"; preservation is opt-in via env var.
#
# Rationale:
# - These names are generic and useful for debugging (they are not org-specific).
# - Keeping the list small reduces risk of accidental PII leakage.
# - We avoid preserving any value that contains a domain prefix/suffix (DOMAIN\\user, user@domain)
#   because that would leak org identifiers. In those contexts, the domain/user parts are
#   typically sanitized independently by dedicated patterns.
_WELL_KNOWN_PRINCIPALS_PASSTHROUGH: frozenset[str] = frozenset(
    {
        # Built-in users (commonly referenced across tool outputs)
        "administrator",
        "guest",
        "krbtgt",
        # Spanish built-in user names
        "administrador",
        "invitado",
        # Common well-known groups
        "domain admins",
        "enterprise admins",
        "schema admins",
        "administrators",
        "remote management users",
        "remote desktop users",
        "account operators",
        "backup operators",
        "server operators",
        "print operators",
        "dnsadmins",
        "cert publishers",
        "protected users",
        "authenticated users",
        "everyone",
        # NT AUTHORITY well-known security principals (public SIDs, not org-specific).
        # Both the bare label and the "NT AUTHORITY\<name>" qualified form resolve
        # via _is_well_known_principal (whole-string) and _preserve_well_known_qualified
        # (split on \\). S-1-5-18 / -19 / -20 / -11 / -9 / -2 / -7.
        "system",
        "nt authority\\system",
        "local service",
        "nt authority\\local service",
        "network service",
        "nt authority\\network service",
        "authenticated users",
        "nt authority\\authenticated users",
        "enterprise domain controllers",
        "nt authority\\enterprise domain controllers",
        "anonymous logon",
        "nt authority\\anonymous logon",
        # Additional public BUILTIN groups
        "users",
        "guests",
        "replicator",
        "performance log users",
        "performance monitor users",
        "distributed com users",
        "network configuration operators",
        "iis_iusrs",
        "event log readers",
        "access control assistance operators",
        "rds remote access servers",
        "rds endpoint servers",
        "rds management servers",
        "hyper-v administrators",
        "key admins",
        "enterprise key admins",
        "cloneable domain controllers",
        "dnsupdateproxy",
        "group policy creator owners",
        "read-only domain controllers",
        "enterprise read-only domain controllers",
        "domain controllers",
        "domain computers",
        "domain users",
        "domain guests",
        # Spanish group name equivalents (best-effort; environments may differ)
        "administradores del dominio",
        "usuarios del dominio",
        "invitados del dominio",
        "administradores de empresa",
        "administradores de esquema",
        "administradores",
        "usuarios de administracion remota",
        "usuarios de administracion",
        "usuarios de escritorio remoto",
        "operadores de cuenta",
        "operadores de copia de seguridad",
        "operadores de servidor",
        "operadores de impresion",
        "usuarios autenticados",
        "todos",
    }
)


def _preserve_well_known_principals_enabled() -> bool:
    """Return True when well-known AD principals should be preserved verbatim.

    Built-in AD users/groups are always preserved because they are generic and
    useful for debugging. Domain-qualified forms still sanitize the domain part.
    """
    return True


def _is_well_known_principal(value: str) -> bool:
    """Return True if the value is a well-known built-in AD principal name.

    This matcher is intentionally conservative: it only matches plain names
    (no domain prefixes/suffixes) to avoid leaking org identifiers.
    """
    if not value:
        return False
    raw = str(value).strip()
    if not raw:
        return False
    return raw.lower() in _WELL_KNOWN_PRINCIPALS_PASSTHROUGH


def _preserve_well_known_qualified(value: str) -> Optional[str]:
    """Preserve a well-known principal's public NAME while sanitizing its domain.

    Recording paths see qualified forms (``administrators@corp.local``,
    ``CORP\\administrators``, ``NT AUTHORITY\\SYSTEM``). Whole-string
    well-known matching misses these because the bare name is in the set but
    the qualified token is not. This helper splits on ``@`` / ``\\``, checks
    the NAME part via :func:`_is_well_known_principal`, and — when it matches —
    returns the public name with the customer-identifying DOMAIN part still
    pseudonymized.

    The full ``NT AUTHORITY\\SYSTEM`` form is also covered: it matches as a
    whole-string well-known principal first (so ``NT AUTHORITY`` is preserved
    too, because it is a public, non-org-identifying authority — not a customer
    domain).

    Args:
        value: A candidate principal token (may carry quotes/whitespace).

    Returns:
        The name-preserved / domain-sanitized string when the value is a
        well-known principal in qualified form, otherwise ``None`` (caller
        should fall through to normal redaction).
    """
    if not value:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    # Only the QUALIFIED forms preserve here. A bare well-known name reaching the
    # marker path (force=True) is an explicit sensitivity declaration and must
    # still redact -- that is the caller's contract, so we never short-circuit a
    # separator-less token.
    if "@" not in raw and "\\" not in raw:
        return None
    # Fully-public qualified authority (e.g. "NT AUTHORITY\\SYSTEM"): the whole
    # string is a well-known principal whose prefix is a public authority, not a
    # customer domain -- preserve it verbatim.
    if _is_well_known_principal(raw):
        return raw

    def _sanitize_domain_part(domain_part: str) -> str:
        # Route through _record_pseudonym so the result is registered and a
        # domain already pseudonymized by an earlier pass is not re-sanitized
        # (the heuristic paths run this helper after each other on the same
        # content; raw _pseudonymize_value would double-map and diverge).
        if _is_already_sanitized(domain_part):
            return domain_part
        return _record_pseudonym(domain_part, "domain")

    if "@" in raw:
        name_part, domain_part = raw.split("@", 1)
        if _is_well_known_principal(name_part):
            if not domain_part:
                return name_part
            return f"{name_part}@{_sanitize_domain_part(domain_part)}"
    if "\\" in raw:
        domain_part, name_part = raw.rsplit("\\", 1)
        if _is_well_known_principal(name_part):
            if not domain_part:
                return name_part
            return f"{_sanitize_domain_part(domain_part)}\\{name_part}"
    return None


@functools.lru_cache(maxsize=1)
def _get_ip_passthrough_networks() -> tuple[ipaddress._BaseNetwork, ...]:
    """Return networks/IPs that should not be sanitized.

    Some IPs are operationally useful and not sensitive (loopback, local DNS
    resolvers, well-known public DNS). We intentionally keep them as-is in
    session recordings to preserve troubleshooting value.

    Users can extend this allowlist with ``ADSCAN_TELEMETRY_IP_PASSTHROUGH``,
    a comma-separated list of IPs or CIDRs (e.g. ``10.10.10.10,10.0.0.0/24``).
    """
    items = list(_DEFAULT_IP_PASSTHROUGH)
    extra = os.getenv("ADSCAN_TELEMETRY_IP_PASSTHROUGH", "").strip()
    if extra:
        items.extend([part.strip() for part in extra.split(",") if part.strip()])

    networks: list[ipaddress._BaseNetwork] = []
    for item in items:
        try:
            if "/" in item:
                networks.append(ipaddress.ip_network(item, strict=False))
            else:
                networks.append(ipaddress.ip_network(f"{item}/32", strict=False))
        except ValueError:
            # Best-effort: ignore malformed entries.
            continue
    return tuple(networks)


def _is_ip_passthrough(value: str) -> bool:
    """Return True when an IP value should remain unchanged.

    Args:
        value: IPv4 address optionally containing CIDR notation.
    """
    if not value:
        return False

    raw = value.strip()
    if not raw:
        return False

    cidr_sep = raw.find("/")
    ip_part = raw[:cidr_sep] if cidr_sep != -1 else raw

    try:
        ip_value = ipaddress.ip_address(ip_part)
    except ValueError:
        return False

    return any(ip_value in network for network in _get_ip_passthrough_networks())


def _extract_passthrough_segments(content: str) -> tuple[str, dict[str, str]]:
    """Extract passthrough-marked segments and replace them with placeholders.

    Passthrough markers are used to explicitly whitelist non-sensitive text so
    heuristic regex sanitizers do not touch it (for example public URLs like
    GitHub/PyPI). This must run before marker-based sanitization so passthrough
    can override sensitive markers if someone accidentally nests them.

    Args:
        content: Potentially marked content.

    Returns:
        Tuple of (content_with_placeholders, placeholder_to_value_mapping).
    """
    start, end = _PASSTHROUGH_MARKERS
    mapping: dict[str, str] = {}
    counter = 0

    if start in content:
        pattern = re.compile(
            re.escape(start) + r"(?P<value>.*?)" + re.escape(end),
            re.DOTALL,
        )

        def _replace(match: re.Match[str]) -> str:
            nonlocal counter
            value = match.group("value")
            placeholder = f"__ADSCAN_PASSTHROUGH_{counter}__"
            counter += 1
            mapping[placeholder] = value
            return placeholder

        content = pattern.sub(_replace, content)

    # Preserve allowlisted public URLs without requiring explicit passthrough markers.
    # This keeps well-known documentation/reference links visible in session logs.
    for url in _PUBLIC_URL_PASSTHROUGH_ALLOWLIST:
        escaped = re.escape(url.rstrip("/"))
        url_pattern = re.compile(
            rf"(?P<value>{escaped}/?)(?=(?:[\s<>'\"),;:]|$))",
            re.IGNORECASE,
        )

        def _replace_url(match: re.Match[str]) -> str:
            nonlocal counter
            value = match.group("value")
            placeholder = f"__ADSCAN_PASSTHROUGH_{counter}__"
            counter += 1
            mapping[placeholder] = value
            return placeholder

        content = url_pattern.sub(_replace_url, content)

    return content, mapping


def _restore_passthrough_segments(content: str, mapping: dict[str, str]) -> str:
    """Restore previously extracted passthrough segments into sanitized content."""
    if not mapping:
        return content
    for placeholder, value in mapping.items():
        content = content.replace(placeholder, value)
    return content


# --- Custom Sentry Transport for n8n Proxy ---
class _SentryN8nTransport:
    """Custom Sentry transport that proxies events through n8n webhook."""

    def __init__(self, options, proxy_url: str):
        """Initialize n8n proxy transport.

        Args:
            options: Sentry transport options
            proxy_url: n8n webhook URL for Sentry proxy
        """
        self.proxy_url = proxy_url
        self.options = options

    def capture_envelope(self, envelope):
        """Capture Sentry envelope and send via n8n proxy.

        Args:
            envelope: Sentry envelope to send
        """
        try:
            if not _is_telemetry_enabled():
                return
            token = get_cli_shared_token()
            if not token:
                print_error_debug(
                    "Telemetry ingest token not configured; cannot send Sentry event"
                )
                return

            # Serialize envelope
            envelope_payload = _sanitize_serialized_payload_for_telemetry(
                envelope.serialize().decode("utf-8")
            )

            # Configure SSL certificates before making request
            _configure_ssl_certificates_for_requests()

            # Send to n8n proxy
            response = requests.post(
                self.proxy_url,
                json={"envelope": envelope_payload},
                headers={
                    "X-CLI-Token": token,
                    "Content-Type": "application/json",
                },
                timeout=5,
            )
            response.raise_for_status()
        except (requests.RequestException, ValueError, AttributeError) as exc:
            print_warning_debug(f"Failed to send Sentry event via n8n proxy: {exc}")

    def flush(self, timeout: float, callback=None):
        """Flush pending events (no-op for HTTP transport).

        Args:
            timeout: Timeout in seconds (unused for HTTP transport)
            callback: Optional callback to invoke after flush
        """
        _ = timeout  # Unused but required by Sentry SDK interface
        if callback:
            callback()

    def kill(self):
        """Shutdown transport (no-op for HTTP transport)."""


# --- Import debug print functions from rich_output ---
# All print functions in telemetry.py use debug mode to prevent exposing
# internal telemetry information to end users
try:
    from adscan_core.rich_output import (
        print_info_debug,
        print_warning_debug,
        print_error_debug,
    )
    from adscan_core.text_utils import strip_ansi_codes
except ImportError:
    # Fallback if rich_output not available (should not happen in production)
    def print_info_debug(
        message: "Text | str", panel: bool = False, icon: str = "ℹ"
    ) -> Any:
        """Fallback info logger."""
        _ = (message, panel, icon)

    def print_warning_debug(
        message: "Text | str", panel: bool = False, icon: str = "⚠"
    ) -> Any:
        """Fallback warning logger."""
        _ = (message, panel, icon)

    def print_error_debug(
        message: "Text | str", panel: bool = False, icon: str = "✖"
    ) -> Any:
        """Fallback error logger."""
        _ = (message, panel, icon)

    def strip_ansi_codes(value: str) -> str:
        """Fallback ANSI stripper."""
        return value


# --- Forzar uso del bundle de certifi para TLS dentro del binario ---
os.environ["REQUESTS_CA_BUNDLE"] = certifi.where()

def _resolve_installed_version_info() -> dict[str, str]:
    """Compatibility wrapper around centralized version context resolver."""
    return resolve_installed_version_info()


# Detect installation method (binary vs pypi vs source)
def _detect_download_source():
    """Detect how ADscan was downloaded or installed."""
    pkg_dirs = site.getsitepackages() + [site.getusersitepackages()]
    if getattr(sys, "frozen", False):
        # Compiled binary: if launched via pip/pipx wrapper (adscan_bundle),
        # detect installer; else mark as binary
        exe_path = os.path.abspath(sys.argv[0])
        if "adscan_bundle" in exe_path:
            return detect_installer()
        return "binary"
    # Running as a Python script; check if inside site-packages
    file_path = os.path.abspath(__file__)
    for d in pkg_dirs:
        if file_path.startswith(os.path.abspath(d)):
            return detect_installer()
    return "source"


DOWNLOAD_SOURCE = _detect_download_source()


def init_sentry():
    """Initialize Sentry SDK for error tracking via n8n proxy.

    Note: Sentry SDK is initialized with a dummy DSN. Actual error capture
    is proxied through n8n to avoid exposing Sentry credentials in the binary.

    Uses Sentry's environment tag to differentiate dev/ci/prod within a single
    Sentry project, following Sentry's official best practice recommendations.
    """
    # Get single Sentry proxy URL (Sentry recommends single project + environment tags)
    n8n_sentry_proxy = get_sentry_proxy_url()
    if not n8n_sentry_proxy:
        print_error_debug("Sentry proxy URL not configured")
        return

    def _before_send(event, hint):  # type: ignore[no-untyped-def]
        """Sanitize Sentry events and honor runtime telemetry opt-out."""
        _ = hint
        if not _is_telemetry_enabled():
            return None
        return _sanitize_telemetry_value(event)

    try:
        integrations = []
        if ExcepthookIntegration is not None:
            excepthook = ExcepthookIntegration()
            integrations.append(excepthook)

        # Use a dummy DSN for SDK initialization; we'll proxy actual requests
        # through the custom transport. The DSN must have a syntactically
        # valid Sentry format, but the host/project values are ignored by
        # our transport.
        dummy_dsn = "https://00000000000000000000000000000000@dummy.invalid/0"

        # Detect environment for Sentry's environment tag
        current_env = _determine_environment()

        # In frozen (PyInstaller) builds, Sentry default integrations can trigger
        # inspect.getsource() over bundled modules and raise OSError
        # ("could not get source code"). Keep telemetry non-fatal and enable only
        # explicitly requested integrations there.
        is_frozen = bool(getattr(sys, "frozen", False))

        sentry_sdk.init(
            dsn=dummy_dsn,
            integrations=integrations,
            default_integrations=not is_frozen,
            release=get_installed_version(),
            environment=current_env,  # Tag exceptions with environment
            traces_sample_rate=0.0,
            send_default_pii=False,
            attach_stacktrace=False,
            include_local_variables=False,
            include_source_context=False,
            max_breadcrumbs=0,
            before_send=_before_send,
            # Override transport to use n8n proxy
            transport=lambda options: _SentryN8nTransport(options, n8n_sentry_proxy),
        )
        print_info_debug(f"[sentry] Initialized for environment: {current_env}")
    except Exception as exc:  # noqa: BLE001
        print_error_debug(f"Failed to initialize Sentry: {exc}")


# CI/CD environment detection
def _is_ci_environment() -> bool:
    """Detect if running in CI/CD environment to disable telemetry automatically."""
    ci_env_vars = [
        "CI",  # Generic CI indicator
        "GITHUB_ACTIONS",  # GitHub Actions
        "GITLAB_CI",  # GitLab CI
        "CIRCLECI",  # CircleCI
        "TRAVIS",  # Travis CI
        "JENKINS_HOME",  # Jenkins
        "TEAMCITY_VERSION",  # TeamCity
        "BUILDKITE",  # Buildkite
        "DRONE",  # Drone CI
        "CONTINUOUS_INTEGRATION",  # Generic
    ]
    return any(os.getenv(var) for var in ci_env_vars)


# Telemetry configuration (default enabled; disable with ADSCAN_TELEMETRY=0 or in CI/CD)
TELEMETRY_ENABLED = os.getenv("ADSCAN_TELEMETRY", "1") != "0"
_CLI_STATE = SimpleNamespace(telemetry_enabled_override=None)
_TELEMETRY_STATE_FILE = get_adscan_state_dir() / "telemetry_state.json"


def _get_current_telemetry_level() -> tuple[bool, str, str]:
    """Return current effective telemetry state and level.

    Returns:
        Tuple of (enabled, level, source)
        - enabled: effective telemetry enabled state
        - level: one of {"enabled", "session_disabled", "cli_disabled"}
        - source: one of {"offline", "env", "cli", "default"}
    """
    # Offline / no-external kill switch: absolute, highest priority. Reported as
    # source "offline" so the opt-out state-change POST is suppressed (a strict
    # zero-egress engagement must not emit even a metadata packet).
    if offline_mode_enabled():
        return False, "session_disabled", "offline"
    env_val = os.getenv("ADSCAN_TELEMETRY", None)
    if env_val == "0":
        return False, "session_disabled", "env"
    if env_val == "1":
        return True, "enabled", "env"

    override = _CLI_STATE.telemetry_enabled_override
    if override is False:
        return False, "cli_disabled", "cli"
    if override is True:
        return True, "enabled", "cli"

    return True, "enabled", "default"


def _load_last_telemetry_state() -> dict[str, Any]:
    """Load last telemetry state from disk (best-effort)."""
    try:
        if not _TELEMETRY_STATE_FILE.is_file():
            legacy_path = get_adscan_home() / "telemetry_state.json"
            if legacy_path.is_file():
                try:
                    _TELEMETRY_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
                    legacy_path.replace(_TELEMETRY_STATE_FILE)
                except OSError:
                    # Best-effort: if we cannot move the file (permissions, cross-device),
                    # continue reading from the legacy location.
                    pass

        source_path = (
            _TELEMETRY_STATE_FILE
            if _TELEMETRY_STATE_FILE.is_file()
            else (get_adscan_home() / "telemetry_state.json")
        )

        if source_path.is_file():
            data = json.loads(source_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
    except (OSError, json.JSONDecodeError):
        return {}
    return {}


def _save_last_telemetry_state(state: dict[str, Any]) -> None:
    """Persist last telemetry state to disk (best-effort)."""
    try:
        existing = _load_last_telemetry_state()
        sanitization_key = existing.get("sanitization_key")
        if sanitization_key and "sanitization_key" not in state:
            state = {**state, "sanitization_key": sanitization_key}
        _TELEMETRY_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _TELEMETRY_STATE_FILE.write_text(
            json.dumps(state, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except OSError:
        return


def _send_telemetry_state_event(
    *,
    event: str,
    enabled: bool,
    level: str,
    source: str,
    context: Optional[dict[str, Any]] = None,
    previous: Optional[dict[str, Any]] = None,
) -> None:
    """Send a telemetry state-change event even when telemetry becomes disabled."""
    if not _telemetry_client:
        return
    proxy_url = _get_posthog_proxy_url()
    if not proxy_url:
        return
    token = get_cli_shared_token()
    if not token:
        return

    props: dict[str, Any] = {
        "version": get_installed_version(),
        "environment": _determine_environment(),
        "telemetry_level": level,
        "telemetry_source": source,
        "telemetry_enabled_effective": enabled,
    }
    version_fields = get_telemetry_version_fields()
    for key, value in version_fields.items():
        if key == "adscan_version":
            continue
        if value is None or value == "":
            continue
        props[key] = value
    if previous:
        props["telemetry_prev_enabled_effective"] = bool(
            previous.get("enabled_effective")
        )
        prev_level = previous.get("telemetry_level")
        if isinstance(prev_level, str):
            props["telemetry_prev_level"] = prev_level
        prev_source = previous.get("telemetry_source")
        if isinstance(prev_source, str):
            props["telemetry_prev_source"] = prev_source

    if context:
        # Caller is responsible for sanitization. This should already use hashed IDs
        # (e.g., workspace_id_hash) and whitelisted lab names only.
        props.update(context)

    props["$set"] = {
        "telemetry_enabled": enabled,
        "telemetry_level": level,
        "telemetry_source": source,
        "environment": _determine_environment(),
        "version": get_installed_version(),
        "downloaded_source": DOWNLOAD_SOURCE,
    }
    for key, value in version_fields.items():
        if key == "adscan_version":
            continue
        if value is None or value == "":
            continue
        props["$set"][key] = value

    payload = {"event": event, "distinct_id": TELEMETRY_ID, "properties": props}
    try:
        _configure_ssl_certificates_for_requests()
        response = requests.post(
            proxy_url,
            json=payload,
            headers={"X-CLI-Token": token, "Content-Type": "application/json"},
            timeout=5,
        )
        response.raise_for_status()
    except (requests.RequestException, ValueError, TypeError) as exc:
        print_warning_debug(f"Telemetry capture failed for event {event}: {exc}")


def sync_telemetry_state(
    *,
    context: Optional[dict[str, Any]] = None,
    force: bool = False,
) -> dict[str, Any]:
    """Sync telemetry state and emit a state-change event when it changes.

    This is designed to always emit the final event when telemetry gets disabled
    (env/session opt-out or CLI opt-out) so PostHog can observe opt-out behavior.

    Args:
        context: Optional context (workspace_id_hash, lab_provider, etc.).
        force: When True, always writes the current state to disk.

    Returns:
        Dict describing current effective telemetry state.
    """
    enabled, level, source = _get_current_telemetry_level()
    current_state = {
        "enabled_effective": enabled,
        "telemetry_level": level,
        "telemetry_source": source,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }

    prev = _load_last_telemetry_state()
    prev_enabled = prev.get("enabled_effective")
    if force or prev_enabled is None:
        _save_last_telemetry_state(current_state)
        return current_state

    if bool(prev_enabled) == bool(enabled):
        # Same effective state; still update persisted metadata.
        _save_last_telemetry_state(current_state)
        return current_state

    # Emit a state change event — EXCEPT when telemetry was disabled by the
    # env kill switch or offline mode. A strict air-gap / zero-egress engagement
    # must not send even the metadata-only opt-out packet; we persist the state
    # file only. An interactive in-session opt-out (source "cli") still emits,
    # so the product keeps opt-out analytics for normal users.
    suppress_optout_post = (not enabled) and source in {"env", "offline"}
    if not suppress_optout_post:
        event = "telemetry_enabled" if enabled else "telemetry_disabled"
        _send_telemetry_state_event(
            event=event,
            enabled=enabled,
            level=level,
            source=source,
            context=context,
            previous=prev if isinstance(prev, dict) else None,
        )
    _save_last_telemetry_state(current_state)
    return current_state


def set_cli_telemetry(enabled: bool, context: Optional[dict[str, Any]] = None):
    """Set CLI telemetry override and emit telemetry state-change event if needed.

    This does not override ADSCAN_TELEMETRY env var, but will still emit the
    opt-out event if the effective state changes.
    """
    _CLI_STATE.telemetry_enabled_override = enabled
    sync_telemetry_state(context=context)


def _is_telemetry_enabled() -> bool:
    """
    Determine if telemetry should be sent.
    Priority (highest to lowest):
    1. ADSCAN_TELEMETRY=0 → disabled (explicit opt-out)
    2. ADSCAN_TELEMETRY=1 → enabled (explicit opt-in)
    3. CLI setting → use CLI override
    4. Default → enabled (all environments: dev, ci, prod)

    Note: Telemetry is enabled in all environments by default, but events
    are automatically routed to different PostHog projects based on environment
    detection (see _get_posthog_proxy_url).
    """
    # Offline / no-external kill switch: absolute, highest priority. An
    # air-gapped or sovereignty-restricted engagement (ADSCAN_OFFLINE /
    # ADSCAN_NO_EXTERNAL) must never send, persist, or drain telemetry — this
    # one gate also governs the disk-queue writer and the queue drainer, so
    # offline means off on all three axes (send / persist / flush).
    if offline_mode_enabled():
        return False
    # Explicit telemetry setting takes highest priority
    env_val = os.getenv("ADSCAN_TELEMETRY", None)
    if env_val == "0":
        return False
    if env_val == "1":
        return True

    # CLI setting override (for runtime toggling)
    override = _CLI_STATE.telemetry_enabled_override
    if override is not None:
        return override

    # Default: enabled in all environments
    # Events are routed to appropriate PostHog project based on environment
    return True


def _is_session_capture_enabled() -> bool:
    """
    Determine if Rich session recordings should be captured and uploaded.

    Unlike general telemetry, session capture remains enabled in CI by default
    so pipelines can validate HTML uploads. Users can still opt out globally
    via ADSCAN_TELEMETRY=0 or specifically via ADSCAN_SESSION_CAPTURE=0.
    """
    # Offline / no-external kill switch: absolute, highest priority (same as
    # _is_telemetry_enabled). No session HTML may be uploaded when air-gapped.
    if offline_mode_enabled():
        return False
    if os.getenv("ADSCAN_TELEMETRY") == "0":
        return False
    capture_opt = os.getenv("ADSCAN_SESSION_CAPTURE")
    if capture_opt == "0":
        return False
    # If the user explicitly disables telemetry at runtime from the CLI,
    # also disable session capture to avoid unexpected uploads.
    override = _CLI_STATE.telemetry_enabled_override
    if override is False:
        return False
    return True


SESSION_CAPTURE_ALLOWED_COMMANDS = frozenset(
    {"install", "ci", "execute", "doctor", "start", "tui", "check", "update", "upgrade"}
)
HOST_SESSION_CAPTURE_COMMANDS = frozenset({"install", "check", "update", "upgrade"})
CONTAINER_SESSION_CAPTURE_COMMANDS = frozenset({"start", "ci", "execute", "doctor"})
SESSION_WORKSPACE_CONTEXT_COMMANDS = frozenset({"start", "ci"})
_SESSION_TRACE_ID_ENV = "ADSCAN_SESSION_TRACE_ID"
_SESSION_WORKSPACE_CONTEXT_FIELDS = frozenset(
    {
        "workspace_type",
        "compromise_status",
        "user_compromised",
        "domain_compromised",
        "compromised_users_count",
        "lab_provider",
        "lab_name",
        "lab_slug",
        "lab_name_whitelisted",
        "lab_confirmation_state",
        "lab_inference_source",
        "lab_inference_confidence",
    }
)


def is_session_capture_command(
    command_type: Optional[str], *, allowed_commands: Optional[set[str]] = None
) -> bool:
    """Return whether the given command should upload a Rich session recording.

    Args:
        command_type: Command identifier (e.g. ``install``, ``start``).
        allowed_commands: Optional override set; defaults to
            ``SESSION_CAPTURE_ALLOWED_COMMANDS``.

    Returns:
        True when command capture is allowed, False otherwise.
    """
    if not command_type:
        return False
    commands = allowed_commands or set(SESSION_CAPTURE_ALLOWED_COMMANDS)
    return str(command_type) in commands


def is_workspace_context_command(command_type: Optional[str]) -> bool:
    """Return whether workspace/lab metadata should be included for this command."""
    if not command_type:
        return False
    return str(command_type).strip().lower() in SESSION_WORKSPACE_CONTEXT_COMMANDS


def _filter_workspace_context_metadata(
    metadata: dict[str, Any], command_type: Optional[str]
) -> dict[str, Any]:
    """Drop workspace/lab metadata for commands where it is not relevant."""
    if is_workspace_context_command(command_type):
        filtered = dict(metadata)
        workspace_type = normalize_workspace_type(filtered.get("workspace_type"))
        if workspace_type:
            filtered["workspace_type"] = workspace_type
            return filtered

        # If workspace type is missing, infer a best-effort value so session
        # analytics can distinguish "audit/ctf known" from "unknown".
        if filtered.get("lab_provider"):
            filtered["workspace_type"] = "ctf"
        else:
            filtered["workspace_type"] = "unknown"
        return filtered
    filtered = dict(metadata)
    for key in _SESSION_WORKSPACE_CONTEXT_FIELDS:
        filtered.pop(key, None)
    return filtered


def _resolve_session_scope() -> str:
    """Return session scope for telemetry correlation."""
    if os.getenv("ADSCAN_CONTAINER_RUNTIME") == "1":
        return "runtime"
    return "launcher"


def _should_sanitize_session_recording(
    command_type: Optional[str], session_scope: Optional[str]
) -> bool:
    """Return whether uploaded session recordings must be sanitized.

    Session recordings are always sanitized before leaving the host. The
    ``command_type`` / ``session_scope`` parameters are preserved for backward
    compatibility and telemetry metadata, but they no longer control privacy
    policy.
    """
    _ = (command_type, session_scope)
    return True


def _resolve_session_trace_id() -> str | None:
    """Return a sanitized session trace identifier from the environment."""
    raw = str(os.getenv(_SESSION_TRACE_ID_ENV, "")).strip()
    if not raw:
        return None
    sanitized = re.sub(r"[^a-zA-Z0-9._:-]+", "", raw)
    if not sanitized:
        return None
    return sanitized[:128]


def _enrich_session_metadata_context(
    metadata: Optional[dict[str, Any]],
) -> dict[str, Any]:
    """Return metadata enriched with session scope and trace correlation fields."""
    enriched: dict[str, Any] = dict(metadata or {})

    if not enriched.get("session_scope"):
        enriched["session_scope"] = _resolve_session_scope()

    if not enriched.get("session_trace_id"):
        trace_id = _resolve_session_trace_id()
        if trace_id:
            enriched["session_trace_id"] = trace_id

    return enriched


def build_command_session_metadata(
    *,
    command_type: Optional[str],
    base_metadata: Optional[dict[str, Any]] = None,
    extra: Optional[dict[str, Any]] = None,
    success: Optional[bool] = None,
) -> Optional[dict[str, Any]]:
    """Build normalized metadata payload for command-scoped session capture.

    Args:
        command_type: Command identifier to attach.
        base_metadata: Optional pre-computed metadata.
        extra: Optional extra metadata fields.
        success: Optional command success state.

    Returns:
        Metadata dictionary or None when no metadata is available.
    """
    metadata: dict[str, Any] = _enrich_session_metadata_context(base_metadata)
    if command_type:
        metadata["command_type"] = str(command_type)
    if extra:
        for key, value in extra.items():
            if value is not None:
                metadata[key] = value
    if success is not None:
        metadata["command_success"] = bool(success)
    if "environment" not in metadata:
        metadata["environment"] = _determine_session_environment()
    metadata = _filter_workspace_context_metadata(
        metadata, command_type=metadata.get("command_type")
    )
    return metadata or None


def capture_command_session(
    *,
    console: Any = None,
    command_type: Optional[str],
    base_metadata: Optional[dict[str, Any]] = None,
    extra: Optional[dict[str, Any]] = None,
    success: Optional[bool] = None,
    allowed_commands: Optional[set[str]] = None,
) -> bool:
    """Capture and upload a command session recording when allowed.

    Args:
        console: Rich console with recording enabled. When omitted, only metadata
            event capture is attempted by ``capture_session_end``.
        command_type: Command identifier.
        base_metadata: Optional pre-computed metadata.
        extra: Optional metadata fields to merge.
        success: Optional command success state.
        allowed_commands: Optional override set of allowed commands.

    Returns:
        True when capture was attempted, False when command is not eligible.
    """
    if not is_session_capture_command(command_type, allowed_commands=allowed_commands):
        return False
    metadata = build_command_session_metadata(
        command_type=command_type,
        base_metadata=base_metadata,
        extra=extra,
        success=success,
    )
    capture_session_end(console=console, metadata=metadata)
    return True


DEV_MACHINE_IDS = [
    "aa8b2369c8374f788c337132b3a3fa02",
    "c63544afac294af18f329c9b36e6e1df",
    "e7eed2305f90431c82155e2011dcdce5",
]

def _resolve_machine_id_for_env_detection() -> str | None:
    """Resolve machine-id source for environment detection.

    In container runtime mode we should never rely on the container's
    `/etc/machine-id` for dev/prod classification.
    """
    if os.getenv("ADSCAN_CONTAINER_RUNTIME") == "1":
        return None
    try:
        machine_id_path = Path("/etc/machine-id")
        if not machine_id_path.exists():
            return None
        return machine_id_path.read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


@functools.lru_cache(maxsize=1)
def _is_dev_machine_by_id() -> bool:
    """Check if running on a known development machine via host machine-id."""
    machine_id = _resolve_machine_id_for_env_detection()
    if not machine_id:
        return False
    return machine_id in DEV_MACHINE_IDS


def _determine_environment() -> str:
    """
    Determine the environment label (prod/dev/ci) for telemetry.

    Priority (highest to lowest):
    1. CI environment detected → "ci" (always wins; prevents production pollution)
    2. Known development machine-id → "dev"
       (prevents production pollution when running from a dev machine)
    3. ADSCAN_ENV or ADSCAN_SESSION_ENV → manual override
       (ignored if it tries to force "prod" on a dev machine)
    4. Default → "prod"

    Returns:
        Environment label: "dev", "ci", "prod", or custom value from env var
    """
    ci_detected = _is_ci_environment()
    dev_detected = _is_dev_machine_by_id()

    # CI/CD environments should never be labelled as production.
    if ci_detected:
        return "ci"

    # Manual override for special cases (only after CI/dev detection).
    override = os.getenv("ADSCAN_SESSION_ENV") or os.getenv("ADSCAN_ENV")
    cleaned: str | None = None
    if override:
        normalized = override.strip().lower()
        candidate = re.sub(r"[^a-z0-9_-]+", "", normalized)
        if candidate:
            cleaned = candidate

    # Known dev machines should never send production telemetry, even if a
    # production container image is being executed locally.
    if dev_detected:
        if cleaned and cleaned != "prod":
            return cleaned
        return "dev"

    # On production machines, allow override if present.
    if cleaned:
        return cleaned

    return "prod"


def _determine_session_environment() -> str:
    """
    Legacy function for backward compatibility.
    Use _determine_environment() instead.
    """
    return _determine_environment()


def collect_system_context() -> dict[str, Any]:
    """Collect non-sensitive system context for logging and telemetry.

    Returns basic OS and runtime information without hostnames, usernames,
    or environment variable values so it is safe to store in logs and
    remote telemetry.

    Returns:
        Dict with OS, distro, architecture, Python version and environment.
    """
    system = platform.system()
    release = platform.release()
    version_str = platform.version()
    machine = platform.machine()
    python_version = platform.python_version()

    distro_id: Optional[str] = None
    distro_version: Optional[str] = None
    distro_like: Optional[str] = None

    try:
        os_release_path = Path("/etc/os-release")
        if os_release_path.is_file():
            os_release_data: dict[str, str] = {}
            for line in os_release_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                value = value.strip().strip('"').strip("'")
                os_release_data[key] = value
            distro_id = os_release_data.get("ID")
            distro_version = os_release_data.get("VERSION_ID")
            distro_like = os_release_data.get("ID_LIKE")
    except OSError:
        # Best-effort only; missing / unreadable os-release is fine.
        pass

    # In container runtime mode we want distro metadata from the host launcher,
    # not from the container image base (e.g. Debian). If host metadata is not
    # available, omit distro fields rather than reporting container distro.
    if os.getenv("ADSCAN_CONTAINER_RUNTIME") == "1":
        distro_id = None
        distro_version = None
        distro_like = None
        host_distro_id = (os.getenv("ADSCAN_HOST_DISTRO_ID") or "").strip()
        host_distro_version = (os.getenv("ADSCAN_HOST_DISTRO_VERSION") or "").strip()
        host_distro_like = (os.getenv("ADSCAN_HOST_DISTRO_LIKE") or "").strip()
        if host_distro_id:
            distro_id = host_distro_id
        if host_distro_version:
            distro_version = host_distro_version
        if host_distro_like:
            distro_like = host_distro_like

    env = _determine_environment()

    context: dict[str, Any] = {
        "platform_system": system,
        "platform_release": release,
        "platform_version": version_str,
        "platform_machine": machine,
        "python_version": python_version,
        "environment": env,
        # Use a single, consistent key for download source.
        "downloaded_source": DOWNLOAD_SOURCE,
    }

    if distro_id:
        context["distro_id"] = distro_id
    if distro_version:
        context["distro_version"] = distro_version
    if distro_like:
        context["distro_like"] = distro_like

    return context


# Determine distinct id (hashed for anonymity, persisted)
_telemetry_id_override = os.getenv("ADSCAN_TELEMETRY_ID", "").strip()
if _telemetry_id_override:
    # Container-mode wrappers can pass a stable host-derived id to avoid using
    # the container's /etc/machine-id or a non-persistent in-container ADSCAN_HOME.
    TELEMETRY_ID = _telemetry_id_override
else:
    id_dir = get_adscan_home()
    id_file = id_dir / "id"
    if id_file.exists():
        TELEMETRY_ID = id_file.read_text(encoding="utf-8").strip()
    else:
        machine_id_file = Path("/etc/machine-id")
        if machine_id_file.exists():
            raw_id = machine_id_file.read_text(encoding="utf-8").strip()
        else:
            raw_id = uuid.uuid4().hex[:12]
        TELEMETRY_ID = hashlib.sha256(raw_id.encode()).hexdigest()[:12]
        id_dir.mkdir(parents=True, exist_ok=True)
        id_file.write_text(TELEMETRY_ID, encoding="utf-8")

# Partner tag — identifies which partner/beta tester this install belongs to
# (e.g. "glenn-mssp"). Used as a telemetry dimension and as the PRO entitlement
# marker for the shared registry image.
#
# Resolution order (single source of truth — `resolve_partner_tag`):
#   1. env var ADSCAN_PARTNER_TAG (override for CI / power-users / legacy baked
#      images that still carry `ENV ADSCAN_PARTNER_TAG`)
#   2. persisted file in the STATE dir (`get_adscan_state_dir()/partner.json`,
#      field "partner_tag") — written once at runtime by the PRO start gate and
#      surviving across `docker run --rm` because the state dir is bind-mounted
#   3. "" when neither is present
#
# This mirrors the TELEMETRY_ID pattern above (env override → volume file → fall
# back). The file MUST live under the STATE dir (`~/.adscan/state` ↔
# `/opt/adscan/state`), which the launcher bind-mounts — NOT the home root
# (`/opt/adscan`), which is only mounted via specific subdirs. Writing it to the
# unmounted home root meant `docker run --rm` discarded it on every launch and
# re-prompted the operator for the partner tag on every `adscan start`. A
# read-side migration heals already-activated installs whose legacy file still
# sits in the home root on a persistent (non-`--rm`) home.
_PARTNER_TAG_FILENAME = "partner.json"
_PARTNER_TAG_FIELD = "partner_tag"


def _extract_partner_tag(partner_file: Path) -> str:
    """Read and parse a single ``partner.json`` file, or "" on any failure."""
    try:
        if not partner_file.exists():
            return ""
        data = json.loads(partner_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    if not isinstance(data, dict):
        return ""
    return str(data.get(_PARTNER_TAG_FIELD, "") or "").strip()


def _read_persisted_partner_tag() -> str:
    """Return the partner tag persisted in the state dir, or "" when absent.

    Reads ``get_adscan_state_dir()/partner.json`` and extracts the
    ``partner_tag`` field. Any read/parse failure is swallowed and treated as
    "no persisted tag" — resolution then falls through to the empty default.

    Migration: if the state-dir file is absent but a legacy
    ``get_adscan_home()/partner.json`` exists (an install activated before the
    file moved out of the unmounted home root), read the legacy value and
    re-persist it under the state dir so the install self-heals. Best-effort —
    a failed migration write never raises.
    """
    state_tag = _extract_partner_tag(get_adscan_state_dir() / _PARTNER_TAG_FILENAME)
    if state_tag:
        return state_tag
    legacy_tag = _extract_partner_tag(get_adscan_home() / _PARTNER_TAG_FILENAME)
    if legacy_tag:
        try:
            persist_partner_tag(legacy_tag)
        except OSError:
            pass
        return legacy_tag
    return ""


def resolve_partner_tag() -> str:
    """Resolve the partner tag using env override → volume file → "".

    Returns:
        The resolved partner tag, or an empty string when neither the
        ``ADSCAN_PARTNER_TAG`` env var nor a persisted volume file is present.
    """
    env_tag = os.getenv("ADSCAN_PARTNER_TAG", "").strip()
    if env_tag:
        return env_tag
    return _read_persisted_partner_tag()


def persist_partner_tag(partner_tag: str) -> None:
    """Persist the partner tag to the state dir so it survives across containers.

    Writes ``get_adscan_state_dir()/partner.json`` with the ``partner_tag``
    field. The state dir is bind-mounted by the launcher, so the file survives
    ``docker run --rm`` (the home root is not mounted directly). The caller is
    responsible for validating the tag format before calling this.

    Args:
        partner_tag: The partner tag to persist (already validated).
    """
    partner_dir = get_adscan_state_dir()
    partner_dir.mkdir(parents=True, exist_ok=True)
    partner_file = partner_dir / _PARTNER_TAG_FILENAME
    partner_file.write_text(
        json.dumps({_PARTNER_TAG_FIELD: partner_tag.strip()}),
        encoding="utf-8",
    )


# Resolved at import for the telemetry dimension. The PRO start gate may persist
# a tag and then refresh this via `refresh_partner_tag()` within the same
# process so the first session after onboarding is attributed correctly.
PARTNER_TAG: str = resolve_partner_tag()


def refresh_partner_tag() -> str:
    """Re-resolve PARTNER_TAG (e.g. after the start gate persists it).

    Returns:
        The freshly resolved partner tag.
    """
    global PARTNER_TAG  # noqa: PLW0603 — module-level telemetry dimension
    PARTNER_TAG = resolve_partner_tag()
    return PARTNER_TAG

_SANITIZATION_KEY: Optional[bytes] = None
_SANITIZED_VALUES: set[str] = set()

_KNOWN_DOMAINS: list[str] = []
_KNOWN_DOMAINS_LOADED: bool = False
_KNOWN_HOSTNAMES: list[str] = []
_KNOWN_HOSTNAMES_LOADED: bool = False
_KNOWN_USERS: list[str] = []
_KNOWN_USERS_LOADED: bool = False
_KNOWN_PASSWORDS: list[str] = []
_KNOWN_PASSWORDS_LOADED: bool = False
_KNOWN_BASE_DNS: list[str] = []
_KNOWN_BASE_DNS_LOADED: bool = False
_KNOWN_NETBIOS: list[str] = []
_KNOWN_NETBIOS_LOADED: bool = False
_KNOWN_WORKSPACES: list[str] = []
_KNOWN_WORKSPACES_LOADED: bool = False

# Minimum length a workspace-registered known value must have before it is
# eligible for substring redaction in the known-value loops.
#
# SECURITY POLICY -- under-redaction must NEVER happen:
#   A short cracked/weak password (e.g. a 4-char value surfaced by spraying or
#   cracking) and a short sAMAccountName are STILL real secrets and MUST be
#   redacted from the exported telemetry. The floor therefore exists ONLY to
#   stop degenerate 1-char / 2-char matches -- a single-character registered
#   value, even bounded by non-alnum, still hits every standalone "a"/"I" in the
#   buffer. It is NOT a recall trade-off and must never be raised back to a
#   "common word length" floor; doing so would let a real short secret leak.
#
#   Over-greediness (the old "DEBUG -> gibberish" corruption) is now prevented
#   purely by the boundaried, case-sensitive known-value matching in the loops
#   below -- NOT by this floor and NOT by any value-skip-list. A 4-char password
#   such as "Ab1!" is registered, redacted as a bounded standalone token, and
#   does not corrupt surrounding prose (proven by the redaction tests).
#
# Floor = 3 for both: a 3+ char registered value is specific enough that the
# boundaried match only hits the intended token. 1-2 char values are dropped
# because no boundary logic makes a single/double character safe to
# substring-redact across a whole export buffer.
_MIN_KNOWN_PASSWORD_LEN: int = 3
_MIN_KNOWN_USER_LEN: int = 3

# Structural tokens that must NEVER be pseudonymized, regardless of what ends
# up in the known-value sets. Defense-in-depth backstop checked inside
# ``_record_pseudonym`` so that even a future over-greedy known-value loop (or
# a registered secret that happens to equal one of these) cannot corrupt the
# scaffolding of the recording. Kept deliberately small: only log-level tokens
# and a handful of structural words that recur in prompt labels / panel copy.
# Matched case-insensitively (see ``_is_reserved_structural_token``).
_RESERVED_STRUCTURAL_TOKENS: frozenset[str] = frozenset(
    {
        # Log levels only. These are the unambiguously-structural tokens that
        # are NEVER a legitimate sensitive value, so blocking their
        # pseudonymization can only fix corruption, never cause under-redaction.
        #
        # NOTE on scope: prompt-label words ("Enter", "the", "new", ...) are
        # deliberately NOT listed here. They are protected by Layers 1+2 (the
        # registration length floor and the boundaried, case-sensitive
        # known-value matching), which is the correct mechanism. Putting common
        # words like "user"/"domain"/"password"/"target" in this backstop would
        # block their LEGITIMATE redaction when they appear as actual values in
        # structured credential tables / USER@DOMAIN:PASSWORD strings -> an
        # under-redaction regression. Keep this set to structural tokens that
        # cannot be a real secret.
        "debug",
        "info",
        "warning",
        "warn",
        "error",
        "critical",
        "success",
        "verbose",
        "trace",
        "notice",
        "fatal",
    }
)


def _is_reserved_structural_token(value: str) -> bool:
    """Return True if ``value`` is a structural token that must never be pseudonymized.

    Case-insensitive: log levels and prompt-label words appear in mixed case
    across the export buffer (``DEBUG`` vs ``Debug``, ``Enter`` vs ``enter``).
    """
    if not value:
        return False
    return value.strip().casefold() in _RESERVED_STRUCTURAL_TOKENS


def set_workspace_domains(
    domains: Optional[list[str]] | tuple[str, ...] | set[str] | None,
) -> None:
    """Set known workspace domains for targeted sanitization.

    Args:
        domains: Iterable of domain strings, or None to clear.
    """
    global _KNOWN_DOMAINS, _KNOWN_DOMAINS_LOADED
    if not domains:
        _KNOWN_DOMAINS = []
        _KNOWN_DOMAINS_LOADED = True
        return
    normalized: list[str] = []
    for domain in domains:
        if not isinstance(domain, str):
            continue
        cleaned = domain.strip().rstrip(".")
        if not cleaned or "." not in cleaned:
            continue
        normalized.append(cleaned)
    # Preserve order while de-duplicating (case-insensitive)
    seen: set[str] = set()
    deduped: list[str] = []
    for domain in normalized:
        key = domain.casefold()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(domain)
    _KNOWN_DOMAINS = deduped
    _KNOWN_DOMAINS_LOADED = True


def set_workspace_hostnames(
    hostnames: Optional[list[str]] | tuple[str, ...] | set[str] | None,
) -> None:
    """Set known workspace hostnames for targeted sanitization."""
    global _KNOWN_HOSTNAMES, _KNOWN_HOSTNAMES_LOADED
    if not hostnames:
        _KNOWN_HOSTNAMES = []
        _KNOWN_HOSTNAMES_LOADED = True
        return
    normalized: list[str] = []
    for hostname in hostnames:
        if not isinstance(hostname, str):
            continue
        cleaned = hostname.strip().rstrip(".")
        if not cleaned:
            continue
        normalized.append(cleaned)
    seen: set[str] = set()
    deduped: list[str] = []
    for hostname in normalized:
        key = hostname.casefold()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(hostname)
    _KNOWN_HOSTNAMES = deduped
    _KNOWN_HOSTNAMES_LOADED = True


def set_workspace_users(
    users: Optional[list[str]] | tuple[str, ...] | set[str] | None,
) -> None:
    """Set known workspace users for targeted sanitization."""
    global _KNOWN_USERS, _KNOWN_USERS_LOADED
    if not users:
        _KNOWN_USERS = []
        _KNOWN_USERS_LOADED = True
        return
    normalized: list[str] = []
    for user in users:
        if not isinstance(user, str):
            continue
        cleaned = user.strip()
        if not cleaned:
            continue
        # Skip trivially-short / word-like values: substring-redacting a value
        # shorter than the floor corrupts ordinary words and structural tokens
        # across the export buffer. See _MIN_KNOWN_USER_LEN rationale.
        if len(cleaned) < _MIN_KNOWN_USER_LEN:
            continue
        normalized.append(cleaned)
    seen: set[str] = set()
    deduped: list[str] = []
    for user in normalized:
        key = user.casefold()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(user)
    _KNOWN_USERS = deduped
    _KNOWN_USERS_LOADED = True


def set_workspace_passwords(
    passwords: Optional[list[str]] | tuple[str, ...] | set[str] | None,
) -> None:
    """Set known workspace passwords/hashes for targeted sanitization."""
    global _KNOWN_PASSWORDS, _KNOWN_PASSWORDS_LOADED
    if not passwords:
        _KNOWN_PASSWORDS = []
        _KNOWN_PASSWORDS_LOADED = True
        return
    normalized: list[str] = []
    for password in passwords:
        if not isinstance(password, str):
            continue
        cleaned = password.strip()
        if not cleaned:
            continue
        # Skip trivially-short passwords: a 1-5 char registered value gets
        # substring-matched everywhere and corrupts log levels / prose. Real
        # passwords and hashes are well above the floor. See
        # _MIN_KNOWN_PASSWORD_LEN rationale.
        if len(cleaned) < _MIN_KNOWN_PASSWORD_LEN:
            continue
        normalized.append(cleaned)
    seen: set[str] = set()
    deduped: list[str] = []
    for password in normalized:
        key = password
        if key in seen:
            continue
        seen.add(key)
        deduped.append(password)
    _KNOWN_PASSWORDS = deduped
    _KNOWN_PASSWORDS_LOADED = True


def set_workspace_base_dns(
    base_dns: Optional[list[str]] | tuple[str, ...] | set[str] | None,
) -> None:
    """Set known workspace base DNs for targeted sanitization."""
    global _KNOWN_BASE_DNS, _KNOWN_BASE_DNS_LOADED
    if not base_dns:
        _KNOWN_BASE_DNS = []
        _KNOWN_BASE_DNS_LOADED = True
        return
    normalized: list[str] = []
    for base_dn in base_dns:
        if not isinstance(base_dn, str):
            continue
        cleaned = base_dn.strip()
        if not cleaned:
            continue
        normalized.append(cleaned)
    seen: set[str] = set()
    deduped: list[str] = []
    for base_dn in normalized:
        key = base_dn.casefold()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(base_dn)
    _KNOWN_BASE_DNS = deduped
    _KNOWN_BASE_DNS_LOADED = True


def set_workspace_netbios(
    netbios_names: Optional[list[str]] | tuple[str, ...] | set[str] | None,
) -> None:
    """Set known workspace NetBIOS names for targeted sanitization."""
    global _KNOWN_NETBIOS, _KNOWN_NETBIOS_LOADED
    if not netbios_names:
        _KNOWN_NETBIOS = []
        _KNOWN_NETBIOS_LOADED = True
        return
    normalized: list[str] = []
    for netbios in netbios_names:
        if not isinstance(netbios, str):
            continue
        cleaned = netbios.strip()
        if not cleaned:
            continue
        normalized.append(cleaned)
    seen: set[str] = set()
    deduped: list[str] = []
    for netbios in normalized:
        key = netbios.casefold()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(netbios)
    _KNOWN_NETBIOS = deduped
    _KNOWN_NETBIOS_LOADED = True


def set_workspace_names(
    workspace_names: Optional[list[str]] | tuple[str, ...] | set[str] | None,
) -> None:
    """Set known workspace names for targeted sanitization."""
    global _KNOWN_WORKSPACES, _KNOWN_WORKSPACES_LOADED
    if not workspace_names:
        _KNOWN_WORKSPACES = []
        _KNOWN_WORKSPACES_LOADED = True
        return
    normalized: list[str] = []
    for workspace_name in workspace_names:
        if not isinstance(workspace_name, str):
            continue
        cleaned = workspace_name.strip()
        if not cleaned:
            continue
        normalized.append(cleaned)
    seen: set[str] = set()
    deduped: list[str] = []
    for workspace_name in normalized:
        key = workspace_name.casefold()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(workspace_name)
    _KNOWN_WORKSPACES = deduped
    _KNOWN_WORKSPACES_LOADED = True


def _load_workspace_domains_from_dir(workspace_dir: Path) -> list[str]:
    domains: list[str] = []
    variables_path = workspace_dir / "variables.json"
    if variables_path.is_file():
        try:
            variables = json.loads(variables_path.read_text(encoding="utf-8"))
            if isinstance(variables, dict):
                for domain in variables.get("domains", []) or []:
                    if isinstance(domain, str):
                        domains.append(domain)
                domains_data = variables.get("domains_data")
                if isinstance(domains_data, dict):
                    for domain in domains_data.keys():
                        if isinstance(domain, str):
                            domains.append(domain)
        except Exception:
            pass
    domains_dir = workspace_dir / "domains"
    if domains_dir.is_dir():
        for entry in domains_dir.iterdir():
            if entry.is_dir():
                domains.append(entry.name)
    return domains


def _load_workspace_hostnames_from_dir(workspace_dir: Path) -> list[str]:
    hostnames: list[str] = []
    enabled_path = workspace_dir / "enabled_computers.txt"
    if not enabled_path.is_file():
        return hostnames
    try:
        for line in enabled_path.read_text(encoding="utf-8").splitlines():
            value = line.strip()
            if not value:
                continue
            hostnames.append(value)
    except Exception:
        pass
    return hostnames


def _load_workspace_users_from_dir(
    workspace_dir: Path, domains: list[str]
) -> list[str]:
    users: list[str] = []
    domains_dir = workspace_dir / "domains"
    for domain in domains:
        domain_dir = domains_dir / domain
        users_path = domain_dir / "enabled_users.txt"
        if not users_path.is_file():
            continue
        try:
            for line in users_path.read_text(encoding="utf-8").splitlines():
                value = line.strip()
                if value:
                    users.append(value)
        except Exception:
            continue
    return users


def _load_workspace_passwords_from_dir(
    workspace_dir: Path, domains: list[str]
) -> list[str]:
    passwords: list[str] = []
    variables_path = workspace_dir / "variables.json"
    if not variables_path.is_file():
        return passwords
    try:
        variables = json.loads(variables_path.read_text(encoding="utf-8"))
    except Exception:
        return passwords
    if not isinstance(variables, dict):
        return passwords
    domains_data = variables.get("domains_data")
    if isinstance(domains_data, dict):
        for domain in domains:
            domain_data = domains_data.get(domain)
            if not isinstance(domain_data, dict):
                continue
            value = domain_data.get("password")
            if isinstance(value, str) and value:
                passwords.append(value)
            credentials = domain_data.get("credentials")
            if isinstance(credentials, dict):
                for cred_value in credentials.values():
                    if isinstance(cred_value, str) and cred_value:
                        passwords.append(cred_value)
    spraying_history = variables.get("password_spraying_history")
    if isinstance(spraying_history, dict):
        for domain_hist in spraying_history.values():
            if not isinstance(domain_hist, dict):
                continue
            password_section = domain_hist.get("password")
            if not isinstance(password_section, dict):
                continue
            passwords_dict = password_section.get("passwords")
            if isinstance(passwords_dict, dict):
                for pwd in passwords_dict.keys():
                    if isinstance(pwd, str) and pwd:
                        passwords.append(pwd)
    return passwords


def _load_workspace_base_dns_from_dir(workspace_dir: Path) -> list[str]:
    base_dns: list[str] = []
    variables_path = workspace_dir / "variables.json"
    if not variables_path.is_file():
        return base_dns
    try:
        variables = json.loads(variables_path.read_text(encoding="utf-8"))
    except Exception:
        return base_dns
    if not isinstance(variables, dict):
        return base_dns
    value = variables.get("base_dn")
    if isinstance(value, str) and value:
        base_dns.append(value)
    domains_data = variables.get("domains_data")
    if isinstance(domains_data, dict):
        for domain_data in domains_data.values():
            if not isinstance(domain_data, dict):
                continue
            base_dn = domain_data.get("base_dn")
            if isinstance(base_dn, str) and base_dn:
                base_dns.append(base_dn)
    return base_dns


def _load_workspace_netbios_from_dir(workspace_dir: Path) -> list[str]:
    netbios_names: list[str] = []
    variables_path = workspace_dir / "variables.json"
    if not variables_path.is_file():
        return netbios_names
    try:
        variables = json.loads(variables_path.read_text(encoding="utf-8"))
    except Exception:
        return netbios_names
    if not isinstance(variables, dict):
        return netbios_names
    domains_data = variables.get("domains_data")
    if isinstance(domains_data, dict):
        for domain_data in domains_data.values():
            if not isinstance(domain_data, dict):
                continue
            netbios = domain_data.get("netbios")
            if isinstance(netbios, str) and netbios:
                netbios_names.append(netbios)
    return netbios_names


def _looks_like_workspace_root(workspace_dir: Path) -> bool:
    """Return True when a directory looks like an ADscan workspace root."""
    return (workspace_dir / "variables.json").is_file()


def _load_workspace_names_from_dir(workspace_dir: Path) -> list[str]:
    """Load current and sibling workspace names for telemetry sanitization."""
    workspace_names: list[str] = []
    if not _looks_like_workspace_root(workspace_dir):
        return workspace_names

    workspace_names.append(workspace_dir.name)
    parent_dir = workspace_dir.parent
    try:
        for entry in parent_dir.iterdir():
            if not entry.is_dir():
                continue
            if entry.name.startswith("."):
                continue
            if not _looks_like_workspace_root(entry):
                continue
            workspace_names.append(entry.name)
    except Exception:
        pass
    return workspace_names


def _refresh_workspace_cache_if_needed() -> None:
    """Refresh known domains/users/hosts/passwords from workspace files."""
    workspace_dir = Path.cwd()
    workspace_names = _load_workspace_names_from_dir(workspace_dir)
    if workspace_names:
        set_workspace_names(workspace_names)

    domains = _load_workspace_domains_from_dir(workspace_dir)
    if domains:
        set_workspace_domains(domains)

    hostnames = _load_workspace_hostnames_from_dir(workspace_dir)
    if hostnames:
        set_workspace_hostnames(hostnames)

    if domains:
        users = _load_workspace_users_from_dir(workspace_dir, domains)
        if users:
            set_workspace_users(users)

        passwords = _load_workspace_passwords_from_dir(workspace_dir, domains)
        if passwords:
            set_workspace_passwords(passwords)

    base_dns = _load_workspace_base_dns_from_dir(workspace_dir)
    if base_dns:
        set_workspace_base_dns(base_dns)

    netbios_names = _load_workspace_netbios_from_dir(workspace_dir)
    if netbios_names:
        set_workspace_netbios(netbios_names)


def _get_known_domains() -> list[str]:
    global _KNOWN_DOMAINS_LOADED
    _refresh_workspace_cache_if_needed()
    if _KNOWN_DOMAINS:
        return _KNOWN_DOMAINS
    if _KNOWN_DOMAINS_LOADED:
        return []
    _KNOWN_DOMAINS_LOADED = True
    try:
        cwd_domains = _load_workspace_domains_from_dir(Path.cwd())
        if cwd_domains:
            set_workspace_domains(cwd_domains)
    except Exception:
        pass
    return _KNOWN_DOMAINS


def _get_known_hostnames() -> list[str]:
    global _KNOWN_HOSTNAMES_LOADED
    _refresh_workspace_cache_if_needed()
    if _KNOWN_HOSTNAMES:
        return _KNOWN_HOSTNAMES
    if _KNOWN_HOSTNAMES_LOADED:
        return []
    _KNOWN_HOSTNAMES_LOADED = True
    try:
        cwd_hostnames = _load_workspace_hostnames_from_dir(Path.cwd())
        if cwd_hostnames:
            set_workspace_hostnames(cwd_hostnames)
    except Exception:
        pass
    return _KNOWN_HOSTNAMES


def _get_known_users() -> list[str]:
    global _KNOWN_USERS_LOADED
    _refresh_workspace_cache_if_needed()
    if _KNOWN_USERS:
        return _KNOWN_USERS
    if _KNOWN_USERS_LOADED:
        return []
    _KNOWN_USERS_LOADED = True
    try:
        domains = _get_known_domains()
        cwd_users = _load_workspace_users_from_dir(Path.cwd(), domains)
        if cwd_users:
            set_workspace_users(cwd_users)
    except Exception:
        pass
    return _KNOWN_USERS


def _get_known_passwords() -> list[str]:
    global _KNOWN_PASSWORDS_LOADED
    _refresh_workspace_cache_if_needed()
    if _KNOWN_PASSWORDS:
        return _KNOWN_PASSWORDS
    if _KNOWN_PASSWORDS_LOADED:
        return []
    _KNOWN_PASSWORDS_LOADED = True
    try:
        domains = _get_known_domains()
        cwd_passwords = _load_workspace_passwords_from_dir(Path.cwd(), domains)
        if cwd_passwords:
            set_workspace_passwords(cwd_passwords)
    except Exception:
        pass
    return _KNOWN_PASSWORDS


def _get_known_base_dns() -> list[str]:
    global _KNOWN_BASE_DNS_LOADED
    _refresh_workspace_cache_if_needed()
    if _KNOWN_BASE_DNS:
        return _KNOWN_BASE_DNS
    if _KNOWN_BASE_DNS_LOADED:
        return []
    _KNOWN_BASE_DNS_LOADED = True
    try:
        cwd_base_dns = _load_workspace_base_dns_from_dir(Path.cwd())
        if cwd_base_dns:
            set_workspace_base_dns(cwd_base_dns)
    except Exception:
        pass
    return _KNOWN_BASE_DNS


def _get_known_netbios() -> list[str]:
    global _KNOWN_NETBIOS_LOADED
    _refresh_workspace_cache_if_needed()
    if _KNOWN_NETBIOS:
        return _KNOWN_NETBIOS
    if _KNOWN_NETBIOS_LOADED:
        return []
    _KNOWN_NETBIOS_LOADED = True
    try:
        cwd_netbios = _load_workspace_netbios_from_dir(Path.cwd())
        if cwd_netbios:
            set_workspace_netbios(cwd_netbios)
    except Exception:
        pass
    return _KNOWN_NETBIOS


def _get_known_workspaces() -> list[str]:
    global _KNOWN_WORKSPACES_LOADED
    if _KNOWN_WORKSPACES:
        return _KNOWN_WORKSPACES
    _refresh_workspace_cache_if_needed()
    if _KNOWN_WORKSPACES:
        return _KNOWN_WORKSPACES
    if _KNOWN_WORKSPACES_LOADED:
        return []
    _KNOWN_WORKSPACES_LOADED = True
    try:
        cwd_workspaces = _load_workspace_names_from_dir(Path.cwd())
        if cwd_workspaces:
            set_workspace_names(cwd_workspaces)
    except Exception:
        pass
    return _KNOWN_WORKSPACES


def _configure_ssl_certificates_for_requests():
    """Configure SSL certificate environment variables for requests library.

    This is a wrapper around the shared configure_ssl_certificates_for_requests
    function from adscan_internal.ssl_certificates module. It maintains backward
    compatibility with existing code that calls _configure_ssl_certificates_for_requests.
    """
    configure_ssl_certificates_for_requests()


def _get_posthog_proxy_url() -> Optional[str]:
    """
    Get PostHog proxy URL based on detected environment.

    Routes telemetry to different PostHog projects:
    - Development/CI → embedded dev endpoint
    - Production → embedded prod endpoint
    - Fallback → embedded legacy endpoint (if configured)

    Returns:
        PostHog proxy URL for current environment, or None if not configured
    """
    env = _determine_environment()

    # Try environment-specific proxy first
    if env in ("dev", "ci"):
        dev_url = get_posthog_proxy_url_dev()
        if dev_url:
            return dev_url

    if env == "prod":
        prod_url = get_posthog_proxy_url_prod()
        if prod_url:
            return prod_url

    # Fallback to single proxy URL (backward compatibility)
    return get_posthog_proxy_url_legacy()


# Initialize PostHog client (uses n8n proxy instead of direct API)
# Track both wall-clock and monotonic start time so that duration metrics
# remain stable even if the system clock changes (for example, after
# synchronizing with a domain controller).
_session_started_at = datetime.now(timezone.utc)
_session_start_monotonic = time.monotonic()
SEND_TELEMETRY = _is_telemetry_enabled()

# Note: We no longer use PostHog SDK directly; instead we proxy through n8n
# This keeps PostHog API keys on the server instead of bundled in the binary
_telemetry_client = _get_posthog_proxy_url() is not None

if _telemetry_client:
    print_info_debug(
        f"[telemetry] PostHog proxy configured for environment: {_determine_environment()}"
    )
else:
    print_warning_debug("[telemetry] PostHog proxy not configured")


# --- Event-name closed vocabulary (data-protection guard) -------------------
#
# The event NAME is the ONE field capture() forwards without sanitization
# (properties are scrubbed by _sanitize_telemetry_properties). Callers used to
# feed raw operator tokens here (REPL first token: workspace names, loot/ccache
# paths, client hostnames, IPs), which then surfaced verbatim as analytics
# event names. Enforce a closed vocabulary: any name not on this allow-list is
# coerced to a static bucket and the raw string is dropped from every field.
#
# Fail-closed: in doubt, bucket it. Losing one analytics event is acceptable;
# leaking a customer hostname/path into the backend is not.
#
# The set below is the union of: every string-literal first arg to
# telemetry.capture() across the tree, the names forwarded through the wrapper
# helpers (_capture_spraying_ux_event, _capture_workspace_dns_repair_event,
# _capture_user_property_event), and the fully-expanded controlled-enum
# families ({roast_type}_[no_]users_found, {service}_scan_started,
# session_{command}_{phase}). Locked by
# tests/unit/test_telemetry_event_name_allowlist.py.
_TELEMETRY_UNLISTED_EVENT_BUCKET = "telemetry_event_unlisted"

_ALLOWED_EVENT_NAMES: frozenset[str] = frozenset(
    {
        "No template found when generating report",
        "adcs_discovered",
        "adcs_not_discovered",
        "asreproast_no_users_found",
        "asreproast_started",
        "asreproast_users_found",
        "attribution_source",
        "audit_wordlist_cracked",
        "binary_deploy",
        "computers_enumerated",
        "container_runtime_launcher_contract_missing",
        "cracking_started",
        "creds_save_requires_start_auth",
        "ctf_flags.collection",
        "ctf_pre2k_followup_accepted",
        "ctf_pre2k_followup_declined",
        "ctf_pre2k_followup_prompted",
        "ctf_pre2k_selected",
        "ctf_recommended_spraying_started",
        "ctf_spraying_prompt_shown",
        "ctf_spraying_recommendation_shown",
        "ctf_spraying_skipped",
        "dcsync_cracking_summary",
        "delegation_exploitation_failed",
        "delegation_exploitation_started",
        "delegation_exploitation_success",
        "deliver.navigator_bundled",
        "dns_resolv_conf_not_local_first",
        "docker_host_autoremediation_applied",
        "docker_host_autoremediation_declined",
        "docker_host_helper_unavailable",
        "docker_host_resources_context",
        "docker_install_buildx_conflict",
        "docker_install_cancelled",
        "docker_install_check_docker_availability",
        "docker_install_completed",
        "docker_install_failed",
        "docker_install_lock_blocked",
        "docker_install_pull_adscan_image_completed",
        "docker_install_pull_adscan_image_failed",
        "docker_install_pull_adscan_image_started",
        "docker_install_started",
        "docker_pull_dns_preflight",
        "docker_pull_failure_classified",
        "docker_pull_network_preflight",
        "docker_pull_preflight_nonblocking_success",
        "docker_pull_retry",
        "docker_runtime_context",
        "docker_runtime_preflight",
        "docker_workspace_lock_blocked",
        "doctor_start",
        "domain_command_requires_initialization",
        "domain_compromise",
        "domain_discovered",
        "domain_inference",
        "domain_not_discovered",
        "environment_enumerated",
        "execute_start",
        "first_cred_found",
        "first_install",
        "hash_cracked",
        "hash_not_cracked",
        "help_requested",
        "hostname_domain_crosscheck",
        "install_after_fail",
        "install_blocked_low_disk",
        "install_started",
        "installation_mode_selected",
        "kerberoast_no_users_found",
        "kerberoast_started",
        "kerberoast_users_found",
        "kerberos_ccache_principal_mismatch",
        "ldap_computers_enumerated",
        "ldap_scan_started",
        "metric_ttfh",
        "mssql_scan_started",
        "mssql_seimpersonate_checked",
        "myip_auto_configured",
        "myip_auto_updated",
        "native_collection_performance",
        "pdc_preflight_auto_switched",
        "pdc_preflight_confirmed",
        "pdc_preflight_dns_validation",
        "pdc_preflight_domain_fallback",
        "pdc_preflight_mismatch",
        "pdc_preflight_retry_with_fingerprint_domain",
        "pdc_preflight_validated",
        "post_ex_dry_run_executed",
        "post_ex_execute_invoked",
        "post_ex_menu_viewed",
        "post_ex_technique_selected",
        "rdp_scan_started",
        "reinstall",
        "repl_command",
        "repl_command_unknown",
        "roast_etype_prevalence",
        "scan_complete",
        "scan_outcome",
        "session_ci_check_failed",
        "session_ci_check_passed",
        "session_ci_override_accepted",
        "session_ci_override_declined",
        "session_ci_override_prompt_shown",
        "session_end",
        "session_execute_check_failed",
        "session_execute_check_passed",
        "session_execute_override_accepted",
        "session_execute_override_declined",
        "session_execute_override_prompt_shown",
        "session_rating",
        "session_rating_feedback",
        "session_start",
        "session_start_check_failed",
        "session_start_check_passed",
        "session_start_override_accepted",
        "session_start_override_declined",
        "session_start_override_prompt_shown",
        "smb_scan_started",
        "smb_sensitive_auth_normalized",
        "smb_sensitive_data_analysis",
        "spray_replica_gate",
        "spraying_aborted_clock_sync_failed",
        "spraying_pre2k_selected",
        "spraying_recommended_started",
        "star_cta_shown",
        "start_auth",
        "start_network_preflight_interface_switch",
        "start_network_preflight_result",
        "start_unauth",
        "start_wizard_interrupted",
        "telemetry_event_unlisted",
        "telemetry_system_context",
        "timeroast_started",
        "uninstalled",
        "user_discovery_followups",
        "users_enumerated",
        "winrm_scan_started",
        "workspace_dns_repair_attempted",
        "workspace_dns_repair_failed",
        "workspace_dns_repair_skipped",
        "workspace_dns_repair_succeeded",
        "workspace_dns_restore_best_effort",
        "workspace_dns_restore_failed",
    }
)


def _coerce_event_name(event: str) -> str:
    """Return the event name if allow-listed, else the static unlisted bucket.

    Fail-closed guard for the telemetry event-NAME channel. The name is the one
    payload field capture() never sanitizes, so any value outside the closed
    vocabulary is dropped and replaced by a static bucket. This guarantees no
    operator/customer string (hostnames, loot paths, IPs) can reach the
    analytics backend as an event name.

    Args:
        event: The requested event name.

    Returns:
        The event name if it is allow-listed, otherwise the static bucket.
    """
    return event if event in _ALLOWED_EVENT_NAMES else _TELEMETRY_UNLISTED_EVENT_BUCKET


def capture(event: str, properties: Optional[dict[str, Any]] = None):
    """Capture a telemetry event via n8n proxy if enabled.

    Automatically routes events to appropriate PostHog project based on environment:
    - "dev": Development project
    - "ci": Development project
    - "prod": Production project

    Also adds environment property to all events for additional filtering.
    """
    if _telemetry_client and (
        _is_telemetry_enabled()
        or (event.startswith("telemetry_") and not offline_mode_enabled())
    ):
        try:
            # Get appropriate proxy URL for current environment
            proxy_url = _get_posthog_proxy_url()
            if not proxy_url:
                print_error_debug(
                    "PostHog proxy URL not configured for current environment"
                )
                return

            token = get_cli_shared_token()
            if not token:
                print_error_debug(
                    "Telemetry ingest token not configured; cannot send telemetry"
                )
                return

            # Prepare properties and merge user-provided $set with defaults
            props = dict(properties) if properties is not None else {}
            user_set = props.pop("$set", {})

            # Add environment to event properties (for event-level filtering)
            current_environment = _determine_environment()
            version_fields = get_telemetry_version_fields()
            props["version"] = str(
                version_fields.get("adscan_version") or get_installed_version()
            )
            for key, value in version_fields.items():
                if key == "adscan_version":
                    continue
                if value is None or value == "":
                    continue
                props[key] = value
            props["environment"] = current_environment
            if PARTNER_TAG:
                props["partner_tag"] = PARTNER_TAG

            # Add environment to person properties (for user-level filtering).
            # Use a single, consistent key name `downloaded_source` so dashboards
            # and analysis don't need to handle multiple variants.
            default_set: dict[str, Any] = {
                "telemetry_enabled": _is_telemetry_enabled(),
                "version": str(
                    version_fields.get("adscan_version") or get_installed_version()
                ),
                "downloaded_source": DOWNLOAD_SOURCE,
                "environment": current_environment,
            }
            if PARTNER_TAG:
                default_set["partner_tag"] = PARTNER_TAG
            for key, value in version_fields.items():
                if key == "adscan_version":
                    continue
                if value is None or value == "":
                    continue
                default_set[key] = value
            # Enrich person-level properties with non-sensitive system context
            # (OS, distro, Python version, etc.) so they are always linked to
            # the same distinct_id across events.
            try:
                system_ctx = collect_system_context()
                for key, value in system_ctx.items():
                    # Avoid overwriting explicit defaults above; otherwise merge.
                    if key not in default_set:
                        default_set[key] = value
            except Exception:
                # Best-effort only; failures here must not break telemetry.
                pass
            merged_set = _sanitize_telemetry_properties({**default_set, **user_set})
            props = _sanitize_telemetry_properties(props)
            props["$set"] = merged_set

            # Fail-closed event-NAME guard: the name is the only payload field
            # not sanitized above, so coerce any non-allow-listed value to the
            # static bucket. The raw string is dropped, never forwarded in any
            # field (not the event, not the props).
            safe_event = _coerce_event_name(event)

            # Send event to n8n proxy (mimics PostHog API format)
            payload = {
                "event": safe_event,
                "distinct_id": TELEMETRY_ID,
                "properties": props,
            }

            # Configure SSL certificates before making request
            _configure_ssl_certificates_for_requests()

            response = requests.post(
                proxy_url,
                json=payload,
                headers={
                    "X-CLI-Token": token,
                    "Content-Type": "application/json",
                },
                timeout=5,
            )
            response.raise_for_status()
            # print_info(f'Captured event: {event}: {props}, {TELEMETRY_ID}')
        except (requests.exceptions.RequestException, ValueError, TypeError) as exc:
            # Log the coerced (allow-listed / bucketed) name, never the raw one,
            # so an unlisted operator token cannot leak via the debug console.
            print_warning_debug(
                f"Telemetry capture failed for event {_coerce_event_name(event)}: {exc}"
            )
    # else:
    #     print_info("Telemetry disabled")


def _strip_html_tags(html: str) -> str:
    """Remove HTML tags from string, keeping only text content.

    Args:
        html: String potentially containing HTML tags

    Returns:
        String with HTML tags removed
    """
    # Remove HTML tags but keep text content
    # This handles Rich HTML exports like <span class="r1">text</span>
    return re.sub(r"<[^>]+>", "", html)


def _prepare_rich_content_for_processing(content: str) -> str:
    """Normalize Rich exports into plain text suitable for downstream processing.

    This function:
    - Unescapes HTML entities
    - Strips ANSI codes
    - Removes Rich HTML tags (export_html span markup)
    """
    return _strip_html_tags(strip_ansi_codes(unescape(content)))


def _strip_sensitive_markers(content: str) -> str:
    """Remove invisible sensitive markers without redacting the wrapped content."""
    return strip_sensitive_markers(content)


_SAFE_TELEMETRY_STRING_FIELDS: frozenset[str] = frozenset(
    {
        "adscan_detected_installer",
        "adscan_version_source",
        "auth_type",
        "command_type",
        "downloaded_source",
        "environment",
        "event",
        "exception_type",
        "installer",
        "lab_confirmation_state",
        "lab_inference_source",
        "lab_provider",
        "launcher_version_source",
        "result",
        "roast_type",
        "runtime_version_source",
        "scan_mode",
        "service",
        "session_scope",
        "session_trace_id",
        "source",
        "telemetry_level",
        "telemetry_source",
        "target_type",
        "trace_id",
        "version_context_mode",
        "workspace_type",
    }
)

_SAFE_TELEMETRY_STRING_RE = re.compile(r"^[A-Za-z0-9._:/@+-]{1,128}$")
_SENSITIVE_TELEMETRY_FIELD_TYPES: dict[str, str] = {
    "credential": "password",
    "credentials": "password",
    "domain": "domain",
    "exception_message": "workspace",
    "fqdn": "hostname",
    "hash": "hash",
    "host": "hostname",
    "hostname": "hostname",
    "ip": "ip",
    "ip_address": "ip",
    "lab_name": "workspace",
    "message": "workspace",
    "password": "password",
    "path": "path",
    "principal": "user",
    "pwd": "password",
    "server": "hostname",
    "sid": "sid",
    "target_host": "hostname",
    "target_ip": "ip",
    "target_name": "workspace",
    "target_slug": "workspace",
    "user": "user",
    "user_sid": "sid",
    "username": "user",
    "workspace": "workspace",
    "workspace_name": "workspace",
}


def _resolve_telemetry_sensitive_field_type(field_name: str | None) -> str | None:
    """Return the sensitive classification for a telemetry field name."""
    normalized_field = str(field_name or "").strip().lower()
    if not normalized_field:
        return None
    if "sid" in normalized_field:
        return "sid"
    return _SENSITIVE_TELEMETRY_FIELD_TYPES.get(normalized_field)


def _is_safe_telemetry_string(field_name: str | None, value: str) -> bool:
    """Return whether one scalar string can bypass heavy sanitization.

    Only tightly-scoped enum-like fields are preserved verbatim. Everything
    else is sanitized recursively to avoid leaking operator/customer data.
    """
    if not field_name:
        return False
    normalized_field = str(field_name).strip().lower()
    if normalized_field not in _SAFE_TELEMETRY_STRING_FIELDS:
        return False
    normalized_value = str(value).strip()
    if not normalized_value:
        return True
    return bool(_SAFE_TELEMETRY_STRING_RE.fullmatch(normalized_value))


def _sanitize_string_for_telemetry(
    value: str,
    *,
    field_name: str | None = None,
) -> str:
    """Return one telemetry-safe string value."""
    stripped = _strip_sensitive_markers(str(value))
    normalized_field = str(field_name or "").strip().lower()
    sensitive_type = _resolve_telemetry_sensitive_field_type(normalized_field)
    if sensitive_type == "user" and stripped:
        if _is_well_known_principal(stripped):
            return stripped
        if "@" in stripped:
            user_part, domain_part = stripped.split("@", 1)
            if _is_well_known_principal(user_part):
                return (
                    f"{user_part}@{_pseudonymize_value(domain_part, 'domain')}"
                    if domain_part
                    else user_part
                )
        if "\\" in stripped:
            domain_part, user_part = stripped.rsplit("\\", 1)
            if _is_well_known_principal(user_part):
                return (
                    f"{_pseudonymize_value(domain_part, 'domain')}\\{user_part}"
                    if domain_part
                    else user_part
                )
    if sensitive_type and stripped:
        return _pseudonymize_value(stripped, sensitive_type)
    if _is_safe_telemetry_string(field_name, stripped):
        return stripped
    return _sanitize_rich_output(stripped)


def _sanitize_telemetry_value(
    value: Any,
    *,
    field_name: str | None = None,
) -> Any:
    """Recursively sanitize one telemetry payload value."""
    if value is None:
        return None
    if isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _sanitize_string_for_telemetry(value, field_name=field_name)
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, nested_value in value.items():
            sanitized[str(key)] = _sanitize_telemetry_value(
                nested_value, field_name=str(key)
            )
        return sanitized
    if isinstance(value, (list, tuple, set)):
        return [
            _sanitize_telemetry_value(item, field_name=field_name) for item in value
        ]
    return _sanitize_string_for_telemetry(str(value), field_name=field_name)


def _sanitize_telemetry_properties(
    properties: Optional[dict[str, Any]],
) -> dict[str, Any]:
    """Return sanitized telemetry properties for outbound transport."""
    return _sanitize_telemetry_value(properties or {}) or {}


def _sanitize_serialized_payload_for_telemetry(payload: str) -> str:
    """Best-effort sanitization for serialized JSON / line-delimited payloads."""
    text = str(payload)
    sanitized_lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            sanitized_lines.append(line)
            continue
        try:
            parsed = json.loads(stripped)
        except (TypeError, ValueError):
            sanitized_lines.append(_sanitize_string_for_telemetry(line))
            continue

        sanitized_lines.append(
            json.dumps(_sanitize_telemetry_value(parsed), separators=(",", ":"))
        )

    if sanitized_lines:
        return "\n".join(sanitized_lines)
    return _sanitize_string_for_telemetry(text)


def _get_sanitization_key() -> bytes:
    """Return a stable secret key for deterministic sanitization.

    The key is stored in the telemetry state file to keep pseudonyms stable
    across sessions without ever uploading the raw inputs.

    Returns:
        Stable secret key bytes
    """
    global _SANITIZATION_KEY
    if _SANITIZATION_KEY:
        return _SANITIZATION_KEY

    state = _load_last_telemetry_state()
    key_b64 = state.get("sanitization_key")
    key: bytes = b""
    if isinstance(key_b64, str) and key_b64:
        try:
            key = base64.urlsafe_b64decode(key_b64.encode("utf-8"))
        except (binascii.Error, ValueError):
            key = b""

    if not key:
        key = secrets.token_bytes(32)
        state["sanitization_key"] = base64.urlsafe_b64encode(key).decode("ascii")
        _save_last_telemetry_state(state)

    _SANITIZATION_KEY = key
    return key


def _iter_pseudorandom_bytes(data_type: str, value: str) -> Iterator[int]:
    """Yield deterministic pseudorandom bytes for a value and data type.

    Args:
        data_type: Sensitive data type (e.g., "user", "domain")
        value: Raw value to pseudonymize

    Yields:
        Byte values in the range 0-255
    """
    key = _get_sanitization_key()
    seed = f"{data_type}:{value}".encode("utf-8")
    counter = 0
    while True:
        counter_bytes = counter.to_bytes(4, "big")
        digest = hmac.new(key, seed + counter_bytes, hashlib.sha256).digest()
        for byte in digest:
            yield byte
        counter += 1


def _fit_to_length(value: str, length: int) -> str:
    """Trim or pad a value to match the requested length."""
    if length <= 0:
        return ""
    if len(value) >= length:
        return value[:length]
    return value.ljust(length)


def _fit_to_segment(segment: str, replacement: str) -> str:
    """Preserve a table cell's width while swapping its inner content."""
    if not segment:
        return segment
    leading = len(segment) - len(segment.lstrip(" "))
    trailing = len(segment) - len(segment.rstrip(" "))
    inner_width = max(len(segment) - leading - trailing, 0)
    inner = _fit_to_length(replacement, inner_width)
    return (" " * leading) + inner + (" " * trailing)


def _apply_quote_wrapped(raw: str, replacement: str) -> str:
    """Preserve surrounding quotes and original length when replacing values."""
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ("'", '"'):
        inner = _fit_to_length(replacement, len(raw) - 2)
        return f"{raw[0]}{inner}{raw[-1]}"
    return _fit_to_length(replacement, len(raw))


def _scramble_ipv4_provably_fake(value: str) -> Optional[str]:
    """Deterministically scramble an IPv4 address into a provably-fake one.

    The per-digit scramble used for generic "ip"-typed tokens preserved the
    dotted shape but applied no per-octet 0-255 clamp, so most outputs had an
    octet > 255 (obviously fake) -- yet by chance a scramble could land all four
    octets <= 255 and read as a genuine routable address
    (e.g. ``90.33.18.184``). That undermines the no-exfiltration guarantee: a
    reader cannot tell a scrambled IP from real customer infrastructure.

    This replacement guarantees the result is **never** a syntactically-valid
    routable IPv4: exactly one octet (chosen deterministically from the value)
    is forced into the 256-999 range (three digits, structurally invalid), while
    the other three octets carry the full scramble entropy so distinct inputs
    stay distinct. The mapping is:

    - **Deterministic** -- driven by the same HMAC-keyed byte stream as every
      other pseudonym, so the same real IP always maps to the same fake one
      within and across recordings (a reader can still correlate "host X").
    - **Non-reversible** -- the scramble discards the real octet values; the
      keyed HMAC cannot be inverted to recover the input.
    - **Provably non-real** -- one octet is always > 255.

    Args:
        value: A bare IPv4 address (no CIDR suffix).

    Returns:
        The provably-fake scrambled address, or ``None`` if ``value`` is not a
        dotted-quad IPv4 (caller falls back to the generic char scramble).
    """
    octets = value.split(".")
    if len(octets) != 4 or not all(o.isdigit() for o in octets):
        return None

    stream = _iter_pseudorandom_bytes("ip", value)
    # Derive a fresh scrambled value for every octet from independent bytes so
    # distinct inputs stay distinct across the full 0-255 space per octet.
    scrambled = [next(stream) % 256 for _ in range(4)]
    # Pick which octet to force out-of-range deterministically from the stream.
    forced_index = next(stream) % 4
    # Force that octet to 256-999 (structurally invalid -> provably fake) while
    # keeping per-input entropy: 256 + (byte over a 744-wide window).
    scrambled[forced_index] = 256 + (next(stream) % 744)
    return ".".join(str(o) for o in scrambled)


def _scramble_ipv6_provably_fake(value: str) -> Optional[str]:
    """Deterministically scramble an IPv6 address into a provably-fake one.

    Mirrors :func:`_scramble_ipv4_provably_fake` for IPv6. Without this, a v6
    address routed through the generic char scramble keeps its colon shape and
    hex digits, so the output looks like a valid routable v6 address. This maps
    the address into the IETF documentation prefix ``2001:db8::/32`` (RFC 3849)
    -- reserved, non-routable, and large enough (96 host bits) that collisions
    on a realistic recording are negligible while distinct inputs stay distinct.

    The mapping is deterministic (keyed HMAC stream) and non-reversible (the
    real host bits are discarded and replaced with keyed scramble bytes).

    Args:
        value: An IPv6 address (no CIDR suffix, no zone id).

    Returns:
        The provably-fake ``2001:db8:...`` address, or ``None`` if ``value`` is
        not a valid IPv6 literal.
    """
    if ":" not in value:
        return None
    try:
        ipaddress.IPv6Address(value)
    except ValueError:
        return None

    stream = _iter_pseudorandom_bytes("ip", value)
    # Fixed documentation prefix 2001:db8::/32, then 96 keyed bits below it.
    host_bytes = bytes(next(stream) % 256 for _ in range(12))
    addr_int = (0x20010DB8 << 96) | int.from_bytes(host_bytes, "big")
    return str(ipaddress.IPv6Address(addr_int))


def _pseudonymize_value(value: str, data_type: str) -> str:
    """Return a deterministic, length-preserving pseudonym for sensitive values.

    The output:
    - Matches the input length
    - Preserves separators for readable tokens (domains, IPs, paths)
    - Uses vowel/consonant mapping for readability where appropriate
    - Remains stable across sessions for the same input

    Args:
        value: Raw sensitive value
        data_type: Sensitive data type (user/domain/ip/password/etc.)

    Returns:
        Pseudonymized value with the same length as the input
    """
    if not value or not isinstance(value, str):
        return value

    # Never pseudonymize a known public technique / edge name (ADCSESC1,
    # GenericAll, MemberOf, ...). These are vendor-neutral identifiers, not
    # customer data, and mangling them ("ADCSESC1" -> "ISSSOND8") destroys
    # triage readability while protecting nothing. Shape-gated so a host
    # literally named "DCSYNC" still redacts (see is_attack_technique_name).
    if is_attack_technique_name(value):
        return value

    data_type = data_type.lower()
    if data_type == "ip":
        if _is_ip_passthrough(value):
            return value
        cidr_match = re.match(r"^(?P<prefix>[0-9.]+)(?P<sep>/)(?P<suffix>\d+)$", value)
        if cidr_match:
            prefix = cidr_match.group("prefix")
            suffix = cidr_match.group("suffix")
            return f"{_pseudonymize_value(prefix, data_type)}/{suffix}"
        # Whole-address scramble that is PROVABLY non-real. The old per-digit
        # scramble (below, in the char loop) preserved the dotted/colon shape but
        # could land on a syntactically-valid routable address by chance, making a
        # scrambled IP indistinguishable from real customer infrastructure. These
        # helpers guarantee structurally-impossible output (an octet > 255 for v4;
        # the 2001:db8::/32 documentation prefix for v6) while staying
        # deterministic, distinct, and non-reversible. Falls through to the char
        # scramble only for IP-typed tokens that are not bare v4/v6 literals.
        fake_v4 = _scramble_ipv4_provably_fake(value)
        if fake_v4 is not None:
            return fake_v4
        fake_v6 = _scramble_ipv6_provably_fake(value)
        if fake_v6 is not None:
            return fake_v6
    preserve_non_alnum = data_type in {
        "domain",
        "hostname",
        "sid",
        "user",
        "service",
        "path",
        "workspace",
        "share",
        "ip",
        "mac",
        "redacted",
    }
    use_vowel_consonant = data_type in {
        "domain",
        "hostname",
        "user",
        "service",
        "path",
        "workspace",
        "share",
    }
    opaque_types = {"password", "hash"}

    vowels = "aeiou"
    consonants = "bcdfghjklmnpqrstvwxyz"
    letters = vowels + consonants
    digits = "0123456789"
    hex_digits = "0123456789abcdef"
    opaque_pool = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    stream = _iter_pseudorandom_bytes(data_type, value)
    result: list[str] = []

    for char in value:
        if char.isspace():
            result.append(char)
            continue

        if preserve_non_alnum and not char.isalnum():
            result.append(char)
            continue

        byte = next(stream)

        if data_type == "hash":
            result.append(hex_digits[byte % len(hex_digits)])
            continue

        if data_type == "ip":
            if char.isdigit():
                result.append(digits[byte % len(digits)])
            elif char.isalpha():
                replacement = hex_digits[byte % len(hex_digits)]
                result.append(replacement.upper() if char.isupper() else replacement)
            else:
                result.append(
                    char if preserve_non_alnum else digits[byte % len(digits)]
                )
            continue

        if data_type == "mac":
            # Scramble each hex nibble into another valid hex digit, preserving
            # the MAC shape (6 groups of 2 hex separated by : or -) and case.
            # The separators are kept by the preserve_non_alnum branch above, so
            # this only ever sees a hex character here.
            replacement = hex_digits[byte % len(hex_digits)]
            result.append(replacement.upper() if char.isupper() else replacement)
            continue

        if char.isdigit():
            result.append(digits[byte % len(digits)])
            continue

        if char.isalpha():
            if use_vowel_consonant:
                pool = vowels if char.lower() in vowels else consonants
            else:
                pool = letters
            replacement = pool[byte % len(pool)]
            result.append(replacement.upper() if char.isupper() else replacement)
            continue

        if data_type in opaque_types:
            result.append(opaque_pool[byte % len(opaque_pool)])
        else:
            result.append(letters[byte % len(letters)])

    return "".join(result)


# ─────────────────────────────────────────────────────────────────────
# Sanitizer trace (development-only diagnostic)
# ─────────────────────────────────────────────────────────────────────
#
# When active, every call into `_record_pseudonym` writes a structured
# entry to ``~/.adscan/logs/sanitizer-trace.log`` showing:
#   * the input value (repr, so zero-width markers are visible)
#   * the declared data_type
#   * the resulting pseudonym
#   * an abbreviated stack trace identifying which sanitizer pattern
#     fired the call
#
# At session start (each call to `_sanitize_rich_output`) the helper
# also dumps the loaded ``known_*`` lists (workspaces, domains, hosts,
# users, passwords). That surface is the most likely culprit for
# over-sanitization — a workspace literally named "Enter" or "test"
# turns into a regex that rewrites those words anywhere they appear.
#
# Activation policy (no env var knob — keep one source of truth):
#   * Active iff ``_determine_environment() == "dev"``. The launcher's
#     ``--dev`` flag is what flips that environment label by registering
#     the host machine-id as a dev machine, so this trace fires for the
#     ADscan author / contributors and never on a customer install.
#   * Customer (prod) and CI runs never write this file, even if
#     verbose / debug modes are on. The trace contains pre-redaction
#     content and must never reach untrusted disks.
#
# The trace file is capped (entries + size) so it cannot grow unbounded
# during long sessions.

_SANITIZER_TRACE_FH: Optional[Any] = None
_SANITIZER_TRACE_COUNT: int = 0
_SANITIZER_TRACE_LIMIT: int = 5000
_SANITIZER_TRACE_RESOLVED: Optional[bool] = None


def _sanitizer_trace_enabled() -> bool:
    """Return whether the sanitizer trace should write to disk.

    Single rule: trace fires only when the resolved telemetry environment
    is ``"dev"`` (i.e. the launcher detected a registered dev machine,
    typically via ``adscan --dev``). No env-var override — production /
    CI must never write this file because it contains pre-redaction text.
    The decision is cached for the process lifetime; ``--dev`` is set
    once at launcher startup and does not change mid-session.
    """
    global _SANITIZER_TRACE_RESOLVED
    if _SANITIZER_TRACE_RESOLVED is not None:
        return _SANITIZER_TRACE_RESOLVED
    try:
        _SANITIZER_TRACE_RESOLVED = _determine_environment() == "dev"
    except Exception:
        _SANITIZER_TRACE_RESOLVED = False
    return _SANITIZER_TRACE_RESOLVED


def _sanitizer_trace_path() -> Path:
    home = Path(os.getenv("ADSCAN_HOME") or (Path.home() / ".adscan"))
    return home / "logs" / "sanitizer-trace.log"


def _sanitizer_trace_fh() -> Optional[Any]:
    """Lazily open the trace log file. Returns None on any I/O error."""
    global _SANITIZER_TRACE_FH
    if _SANITIZER_TRACE_FH is not None:
        return _SANITIZER_TRACE_FH
    try:
        path = _sanitizer_trace_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        # Rotate if file exceeds 4 MiB so we always have a fresh tail
        # to read after reproducing the bug.
        try:
            if path.exists() and path.stat().st_size > 4 * 1024 * 1024:
                rotated = path.with_suffix(".log.prev")
                try:
                    rotated.unlink()
                except FileNotFoundError:
                    pass
                path.rename(rotated)
        except OSError:
            pass
        _SANITIZER_TRACE_FH = path.open("a", encoding="utf-8")
        _SANITIZER_TRACE_FH.write(
            f"\n\n=== sanitizer-trace session opened "
            f"pid={os.getpid()} at {datetime.now(timezone.utc).isoformat()} ===\n"
        )
        _SANITIZER_TRACE_FH.flush()
    except Exception:
        _SANITIZER_TRACE_FH = None
    return _SANITIZER_TRACE_FH


def _sanitizer_trace_session_open(content: str) -> None:
    """Dump the configuration state at the start of a sanitize pass."""
    global _SANITIZER_TRACE_COUNT
    if not _sanitizer_trace_enabled():
        return
    fh = _sanitizer_trace_fh()
    if fh is None:
        return
    _SANITIZER_TRACE_COUNT = 0
    try:
        known_workspaces = _get_known_workspaces()
    except Exception as exc:
        known_workspaces = [f"<error: {exc}>"]
    try:
        known_domains = _get_known_domains() if "_get_known_domains" in globals() else []
    except Exception:
        known_domains = []
    try:
        known_hosts = _get_known_hostnames() if "_get_known_hostnames" in globals() else []
    except Exception:
        known_hosts = []
    try:
        known_users = _get_known_users() if "_get_known_users" in globals() else []
    except Exception:
        known_users = []
    try:
        known_pw_count = len(_get_known_passwords()) if "_get_known_passwords" in globals() else 0
    except Exception:
        known_pw_count = -1
    try:
        fh.write(
            f"\n--- sanitize pass: content_len={len(content)} chars ---\n"
            f"known_workspaces ({len(known_workspaces)}): {known_workspaces!r}\n"
            f"known_domains    ({len(known_domains)}): {known_domains!r}\n"
            f"known_hosts      ({len(known_hosts)}): {known_hosts!r}\n"
            f"known_users      ({len(known_users)}): {known_users!r}\n"
            f"known_passwords  count={known_pw_count}\n"
        )
        # First and last 800 chars of the pre-sanitize content, so the
        # reader can see WHAT is going in (still pre-redaction — only
        # written to a local file, never uploaded).
        head = content[:800]
        tail = content[-800:] if len(content) > 1600 else ""
        fh.write(f"content_head={head!r}\n")
        if tail:
            fh.write(f"content_tail={tail!r}\n")
        fh.flush()
    except Exception:
        pass


def _sanitizer_trace_event(
    *,
    kind: str,
    value: str,
    data_type: str,
    result: str,
) -> None:
    """Record a single pseudonymization call with its caller context."""
    global _SANITIZER_TRACE_COUNT
    if not _sanitizer_trace_enabled():
        return
    if _SANITIZER_TRACE_COUNT >= _SANITIZER_TRACE_LIMIT:
        return
    fh = _sanitizer_trace_fh()
    if fh is None:
        return
    _SANITIZER_TRACE_COUNT += 1
    # Extract caller frames inside this module so we know which regex /
    # pattern triggered the call. Skip the current frame + the
    # _record_pseudonym frame itself.
    try:
        stack = traceback.extract_stack(limit=12)[:-2]
        # Trim to last ~6 frames for readability.
        recent = stack[-6:]
        frames = [
            f"  {frame.filename.rsplit('/', 1)[-1]}:{frame.lineno} in {frame.name}"
            for frame in recent
        ]
        stack_str = "\n".join(frames)
    except Exception:
        stack_str = "  <stack unavailable>"
    try:
        fh.write(
            f"\n[{_SANITIZER_TRACE_COUNT:04d}] {kind} "
            f"type={data_type!r} value={value!r} -> {result!r}\n"
            f"{stack_str}\n"
        )
        fh.flush()
    except Exception:
        pass


def _record_pseudonym(value: str, data_type: str, *, force: bool = False) -> str:
    """Return a pseudonym and remember it to avoid double-sanitization.

    Args:
        value: The token to pseudonymize.
        data_type: Logical kind ("user", "password", "domain", ...).
        force: When True, bypass the well-known-principal passthrough so an
            explicitly-MARKED sensitive value (a value the call site declared
            sensitive via the marker system) is redacted even if it equals a
            built-in name like "administrator" or "Domain Admins". A marker is
            an explicit sensitivity declaration; honouring it cannot leak. The
            log-level structural backstop is NEVER bypassed -- a log level can
            never be a real secret.
    """
    if value in _SANITIZED_VALUES:
        return value
    # Never pseudonymize a known public technique / edge name, on EVERY path
    # (including force=True from the marker path): a marker means "sensitive",
    # but a technique label like "ADCSESC1" / "GenericAll" is structurally a
    # public identifier, never a secret. Shape-gated (CamelCase / ADCSESC<N>)
    # so a bare all-caps NetBIOS hostname (e.g. "DCSYNC") still redacts.
    if is_attack_technique_name(value):
        return value
    # Defense-in-depth: never pseudonymize a structural log-level token, even if
    # a short/word-like secret slipped into the known set or a future loop
    # over-matches. This keeps the recording's scaffolding readable
    # (DEBUG/WARNING/INFO) regardless of what is registered. Applies on every
    # path, including force=True: a log level is structurally never a secret.
    if (
        data_type.lower() in ("user", "password", "workspace", "domain")
        and _is_reserved_structural_token(value)
    ):
        return value
    # Preserve generic built-in AD principals (useful for telemetry debugging)
    # ONLY on the heuristic/structured shape-detection paths (force=False),
    # where a name like "administrator" was detected by SHAPE in prose/tables
    # and was not declared sensitive. The marker path passes force=True because
    # a marker IS an explicit "this value is sensitive" declaration -- so a
    # marked built-in name is redacted, never passed through (no leak).
    if (
        not force
        and data_type.lower() == "user"
        and _preserve_well_known_principals_enabled()
        and _is_well_known_principal(value)
    ):
        return value
    replacement = _pseudonymize_value(value, data_type)
    _sanitizer_trace_event(
        kind="pseudonym",
        value=value,
        data_type=data_type,
        result=replacement,
    )
    if replacement and replacement != value:
        _SANITIZED_VALUES.add(replacement)
        # Heuristic regex sanitizers often operate on non-whitespace tokens.
        # Store the replacement's token chunks too so we don't accidentally
        # re-sanitize already-pseudonymized content (e.g., paths with spaces).
        for chunk in re.findall(r"\S+", replacement):
            _SANITIZED_VALUES.add(chunk)
            stripped = chunk.strip("'\"")
            if stripped:
                _SANITIZED_VALUES.add(stripped)
            # Heuristic patterns often match from a path separator (e.g. `\\foo\\bar`)
            # rather than the full token. Keep common suffix variants too.
            if "\\" in chunk:
                first = chunk.find("\\")
                if first != -1:
                    _SANITIZED_VALUES.add(chunk[first:])
                    if first + 1 < len(chunk):
                        _SANITIZED_VALUES.add(chunk[first + 1 :])
    return replacement


def _is_already_sanitized(value: str) -> bool:
    """Check if a value has already been pseudonymized in this pass."""
    return value in _SANITIZED_VALUES


def _is_non_identifying_mac(value: str) -> bool:
    """Return whether a MAC-shaped token is a non-customer-identifying MAC.

    The broadcast MAC (ff:ff:ff:ff:ff:ff) and the all-zero MAC
    (00:00:00:00:00:00) are protocol constants, not customer infrastructure
    identifiers, so they survive verbatim for triage readability. The check is
    case-insensitive and accepts both ``:`` and ``-`` separators.

    Args:
        value: A token already matched by the MAC-address structural pattern.

    Returns:
        True if the token is the broadcast or all-zero MAC.
    """
    octets = re.split(r"[:-]", value)
    if len(octets) != 6:
        return False
    lowered = [octet.lower() for octet in octets]
    if all(octet == "ff" for octet in lowered):
        return True
    if all(octet == "00" for octet in lowered):
        return True
    return False


def _replace_table_cell(segment: str, data_type: str) -> str:
    """Replace a table cell's content with a length-preserving pseudonym."""
    raw_value = segment.strip()
    if not raw_value or _is_already_sanitized(raw_value):
        return segment
    if re.fullmatch(r"\[[A-Z_]+\]", raw_value):
        return segment
    replacement = _record_pseudonym(raw_value, data_type)
    return _fit_to_segment(segment, replacement)


def _looks_like_plain_text_table_row(line: str, *, min_columns: int) -> bool:
    """Return whether one line still resembles a plain-text table row.

    This is used by stateful table sanitizers to avoid staying "inside" a table
    after Rich wrapping/export truncates the expected closing border. We only
    accept rows that have at least ``min_columns`` non-empty cells separated by
    runs of two or more spaces, which keeps normal prose/log lines out.
    """
    if "│" in line or "┃" in line:
        return True
    cells = [cell for cell in re.split(r"\s{2,}", line.strip()) if cell]
    return len(cells) >= min_columns


def _sanitize_by_markers(
    content: str,
    data_types: Optional[set[str]] = None,
) -> str:
    """Sanitize content based on invisible markers from rich_output.py.

    This function detects invisible zero-width space markers that were added
    at output creation time and replaces the marked content with a deterministic,
    length-preserving pseudonym. This is the most reliable sanitization method
    as data is marked declaratively.

    Args:
        content: Content with potential invisible markers
        data_types: Optional set of data types to sanitize (default: all)

    Returns:
        Content with marked sensitive data replaced by pseudonyms
    """
    import re

    marker_patterns = SENSITIVE_MARKERS
    marker_chars = MARKER_CHARS

    for data_type, (start_marker, end_marker) in marker_patterns.items():
        if data_types is not None and data_type not in data_types:
            continue

        # Create pattern to match: start_marker + any content + end_marker
        # Use a non-greedy character class that excludes every marker
        # character so we never span across unrelated markers of other types.
        # This prevents cases where overlapping sequences (e.g., hostname/path)
        # would cause a single replacement to wipe an entire multi-line block.
        #
        # CRITICAL: Use re.escape() on the actual Unicode strings (not r""
        # raw strings).
        inner_pattern = f"(?P<value>[^{marker_chars}]*?)"
        pattern = re.escape(start_marker) + inner_pattern + re.escape(end_marker)

        def _replace(match: re.Match[str]) -> str:
            value = match.group("value")
            if _is_already_sanitized(value):
                return value
            if data_type == "ip" and _is_ip_passthrough(value):
                return value
            # A marker is an explicit declaration that this value is sensitive,
            # so it overrides the bare well-known-principal passthrough: a MARKED
            # "administrator" / "Domain Admins" is a registered secret here and
            # must be redacted. force=True keeps only the log-level backstop.
            #
            # EXCEPTION — qualified well-known principals (administrators@domain,
            # CORP\\administrators, NT AUTHORITY\\SYSTEM): preserve the PUBLIC
            # name and sanitize only the customer domain. The bare name still
            # redacts under a marker, but the qualified form would otherwise
            # mangle a public, non-identifying built-in name.
            if data_type == "user":
                preserved = _preserve_well_known_qualified(value)
                if preserved is not None:
                    return preserved
            return _record_pseudonym(value, data_type, force=True)

        content = re.sub(pattern, _replace, content, flags=re.DOTALL)

    return content


def _sanitize_rich_output(content: str) -> str:
    """Sanitize Rich HTML/text output before sending to telemetry.

    Removes sensitive information like domains, IPs, usernames, passwords,
    and file paths while preserving the structure and formatting.

    Uses deterministic, length-preserving pseudonyms to maintain formatting.

    Args:
        content: Rich output (HTML or text) to sanitize

    Returns:
        Sanitized content with sensitive data redacted
    """
    content = _prepare_rich_content_for_processing(content)
    content, passthrough_mapping = _extract_passthrough_segments(content)
    _SANITIZED_VALUES.clear()
    _sanitizer_trace_session_open(content)

    # Placeholder tokens used only for pattern matching of pre-sanitized text.
    placeholder_domain = "[DOMAIN]"

    # PRIORITY: Marker-based sanitization FIRST (invisible markers from rich_output.py)
    # This is the most reliable method as data is marked at creation time.
    content = _sanitize_by_markers(content)

    # Fallback: if any markers survived (for example inside list representations
    # or nested structures), replace them defensively with pseudonyms.
    domain_start = "\u200b\u200d"
    domain_end = "\u200d\u200b"
    marker_chars = "\u200b\u200c\u200d\u2060\u200e\u200f"
    inner_pattern = f"(?P<value>[^{marker_chars}]*?)"
    domain_pattern = re.escape(domain_start) + inner_pattern + re.escape(domain_end)
    content = re.sub(
        domain_pattern,
        lambda m: _record_pseudonym(m.group("value"), "domain"),
        content,
        flags=re.DOTALL,
    )

    hostname_start = "\u2060\u200d"
    hostname_end = "\u200d\u2060"
    hostname_pattern = (
        re.escape(hostname_start) + inner_pattern + re.escape(hostname_end)
    )
    content = re.sub(
        hostname_pattern,
        lambda m: _record_pseudonym(m.group("value"), "hostname"),
        content,
        flags=re.DOTALL,
    )

    # CRITICAL: Redact IP addresses FIRST, before ANY other patterns
    # This must run before domain/user combo patterns that might split IPs like "10.0.0.0/24"
    # into domain (10.0.0.0) and user (24)
    ipv4_pattern = (
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
        r"(?:/[0-9]{1,2})?\b"  # Include optional CIDR notation
    )
    content = re.sub(
        ipv4_pattern,
        lambda m: _record_pseudonym(m.group(0), "ip"),
        content,
    )

    # Structural backstop for Active Directory domain/account SIDs.
    #
    # A domain SID (S-1-5-21-<a>-<b>-<c>) and the per-account SIDs derived from
    # it (one extra RID: ...-<c>-<rid>) are the unique fingerprint of a
    # customer's directory -- customer-identifying data that must never reach
    # the uploaded recording. mark_sensitive(..., "sid") at the source sites is
    # the primary defense; this regex is the fail-closed net for any raw SID
    # that slipped through unmarked (mirroring the IPv4/FQDN structural nets).
    #
    # Anchored on the S-1-5-21- prefix so well-known SIDs are NEVER matched:
    # S-1-5-18/19/20/11/9/7 (local/system principals) and S-1-5-32-<rid>
    # (BUILTIN groups, e.g. S-1-5-32-544 Administrators) are not customer-
    # identifying and must survive verbatim for triage readability.
    domain_account_sid_pattern = re.compile(
        r"\bS-1-5-21-[0-9]+-[0-9]+-[0-9]+(?:-[0-9]+)?\b"
    )
    content = domain_account_sid_pattern.sub(
        lambda m: m.group(0)
        if _is_already_sanitized(m.group(0))
        else _record_pseudonym(m.group(0), "sid"),
        content,
    )

    # Structural backstop for Azure AD Connect / DirSync sync-account names.
    #
    # AAD Connect provisions an on-prem sync account named MSOL_<12 hex> (e.g.
    # MSOL_c95ff8ea0437); the hex suffix is installation-specific, so the name
    # is a customer-identifying account that must not reach the uploaded
    # recording. The generic username heuristics don't catch this shape (the
    # MSOL_ prefix reads as a structural token), so a raw MSOL_<hex> survived
    # while ordinary usernames were scrambled. Anchored to exactly 12 hex
    # digits after MSOL_ so a bare "MSOL" or a word like "MSOLAR" is NOT
    # over-matched. Hex is case-insensitive; the prefix is not (MSOL is fixed).
    msol_sync_account_pattern = re.compile(r"\bMSOL_[0-9a-fA-F]{12}\b")
    content = msol_sync_account_pattern.sub(
        lambda m: m.group(0)
        if _is_already_sanitized(m.group(0))
        else _record_pseudonym(m.group(0), "user"),
        content,
    )

    # Structural backstop for hardware MAC addresses.
    #
    # A host MAC (e.g. from a ligolo agent's network JSON,
    # "HardwareAddr": "00:15:5d:0b:dd:00") is a customer infrastructure
    # identifier, and the OUI (first 3 octets) discloses the hardware/hypervisor
    # vendor -- 00:15:5d is the Microsoft Hyper-V OUI. A raw MAC dumped from
    # agent output has no marker, so this regex is the fail-closed net mirroring
    # the IPv4/SID/MSOL structural nets. The 6-group colon/dash-separated hex
    # shape is specific enough that it does NOT collide with SIDs, IPs, or
    # hashes (none of which are six :/-separated hex pairs). Broadcast and
    # all-zero MACs are protocol constants, not customer data, so they survive
    # verbatim (see _is_non_identifying_mac). The pseudonym preserves the MAC
    # shape and produces valid hex so the OUI is not recoverable.
    mac_address_pattern = re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b")
    content = mac_address_pattern.sub(
        lambda m: m.group(0)
        if (_is_already_sanitized(m.group(0)) or _is_non_identifying_mac(m.group(0)))
        else _record_pseudonym(m.group(0), "mac"),
        content,
    )

    # Redact explicit credential disclosures in log messages early to avoid false positives.
    password_added_pattern = re.compile(
        r"(?i)(password\s+added\s+for\s+user\s+[^\n:]+:\s*)([^\s<>\n]+)"
    )
    content = password_added_pattern.sub(
        lambda m: m.group(1) + _record_pseudonym(m.group(2), "password"),
        content,
    )

    credential_for_pattern = re.compile(
        r"(?i)(credential\s+for\s+[^\n:]+:\s*)([^\s<>\n]+)"
    )
    content = credential_for_pattern.sub(
        lambda m: m.group(1) + _record_pseudonym(m.group(2), "password"),
        content,
    )

    # Redact CN values inside LDAP distinguished names (CN=...).
    content = re.sub(
        r"(?i)(\bCN\s*=\s*)([^,)\n]+)",
        lambda m: m.group(1) + _record_pseudonym(m.group(2).strip(), "user"),
        content,
    )
    # Redact OU values inside LDAP distinguished names (OU=...).
    content = re.sub(
        r"(?i)(\bOU\s*=\s*)([^,)\n]+)",
        lambda m: m.group(1) + _record_pseudonym(m.group(2).strip(), "path"),
        content,
    )

    def _replace_domain_user(match: re.Match[str]) -> str:
        token = match.group(0)
        if _is_already_sanitized(token):
            return token
        domain_raw = match.group("domain") or ""
        user_raw = match.group("user") or ""
        pwd = match.group("pwd")
        domain = domain_raw.strip("'\"")
        user = user_raw.strip("'\"")
        pwd = pwd.strip("'\"") if pwd else None
        domain_repl = _apply_quote_wrapped(
            domain_raw, _record_pseudonym(domain, "domain")
        )
        # Preserve a public well-known principal NAME in the user slot; the
        # domain slot is always sanitized (customer-identifying).
        if _is_well_known_principal(user):
            user_repl = _apply_quote_wrapped(user_raw, user)
        else:
            user_repl = _apply_quote_wrapped(user_raw, _record_pseudonym(user, "user"))
        replacement = f"{domain_repl}/{user_repl}"
        if pwd:
            pwd_repl = _apply_quote_wrapped(
                match.group("pwd") or "", _record_pseudonym(pwd, "password")
            )
            replacement += f":{pwd_repl}"
        return replacement

    # Domain token:
    # - Support both legacy `{DOMAIN}` placeholders and current `[DOMAIN]`
    # - Require at least one alphabetic character to avoid matching phase
    #   counters like ``1/3`` as a fake ``DOMAIN/USER`` combo.
    domain_token = (
        r"(?:\[DOMAIN\]|\{DOMAIN\}|"
        r"[A-Za-z0-9._-]*[A-Za-z][A-Za-z0-9._-]*)"
    )
    # User token:
    # - Support both legacy `{USER}` placeholders and current `[USER]`
    user_token = r"(?:\[USER\]|\{USER\}|[a-z0-9._$-]+)"

    # Replace domain/user combos before general domain redaction
    combo_pattern = re.compile(
        rf"""
        (?<![A-Za-z0-9_./~-])
        (?P<domain>["']?{domain_token}["']?)
        \s*/\s*
        (?P<user>["']?{user_token}["']?)
        (?:
            \s*:\s*
            (?P<pwd>
                (?:"[^"]*"|'[^']*')
                |
                [^\s"'@:]+
            )
        )?
        (?=$|\s|@|:)
        """,
        re.IGNORECASE | re.VERBOSE,
    )
    content = combo_pattern.sub(_replace_domain_user, content)

    # Replace DOMAIN\\USER (e.g., NETBIOS\\username), avoiding Windows drive paths.
    domain_backslash_pattern = re.compile(
        # IMPORTANT: `\.` matches a literal dot. Do NOT use `\\.` here, which would
        # match a backslash followed by any character and could accidentally match
        # Windows paths (e.g. `C:\\Users\\...`), causing double-sanitization.
        r"(?i)(?<![A-Za-z]:)(?<![\\\\/])(?P<domain>[A-Za-z0-9._-]*\.[A-Za-z0-9._-]+)(?P<slashes>\\+)(?P<user>[A-Za-z0-9._$-]+)"
    )
    content = domain_backslash_pattern.sub(
        lambda m: _record_pseudonym(m.group("domain"), "domain")
        + m.group("slashes")
        + _record_pseudonym(m.group("user"), "user"),
        content,
    )

    # Sanitize USER@DOMAIN:PASSWORD pattern (handles placeholders, real values, and quotes)
    def _is_password_context(match: re.Match[str], text: str) -> bool:
        start = match.start()
        window = text[max(0, start - 80) : start].lower()
        if any(
            flag in window
            for flag in (
                "--credential",
                "--credentials",
                "--cred",
                "--password",
                "--pass",
                "--pwd",
                "-pl",
                "-p",
            )
        ):
            return True
        if re.search(r"(credential|password|pwd|pass)\b[^\n]{0,40}[:=]\s*$", window):
            return True
        line_start = text.rfind("\n", 0, start) + 1
        line_end = text.find("\n", start)
        if line_end == -1:
            line_end = len(text)
        line = text[line_start:line_end]
        if "│" in line:
            prev_end = line_start - 1
            for _ in range(4):
                if prev_end <= 0:
                    break
                prev_start = text.rfind("\n", 0, prev_end) + 1
                candidate = text[prev_start:prev_end].strip()
                prev_end = prev_start - 1
                if not candidate:
                    continue
                if any(ch in candidate for ch in "┌┬└┴├┼┤─"):
                    continue
                candidate_lower = candidate.lower()
                if "credential" in candidate_lower or "password" in candidate_lower:
                    return True
                break
        return False

    def _replace_user_at_domain_password(match: re.Match[str]) -> str:
        """Replace USER@DOMAIN:PASSWORD pattern with pseudonyms."""
        if _is_password_context(match, content):
            return match.group(0)
        user_raw = match.group("user") or ""
        domain_raw = match.group("domain") or ""
        pwd = match.group("pwd")
        # Strip quotes from all parts
        user = user_raw.strip("'\"")
        domain = domain_raw.strip("'\"")
        pwd = pwd.strip("'\"") if pwd else None
        # Preserve a public well-known principal NAME in the user slot; the
        # domain slot is always sanitized (customer-identifying).
        if _is_well_known_principal(user):
            user_repl = _apply_quote_wrapped(user_raw, user)
        else:
            user_repl = _apply_quote_wrapped(user_raw, _record_pseudonym(user, "user"))
        domain_repl = _apply_quote_wrapped(
            domain_raw, _record_pseudonym(domain, "domain")
        )
        replacement = f"{user_repl}@{domain_repl}"
        if pwd:
            pwd_repl = _apply_quote_wrapped(
                match.group("pwd") or "", _record_pseudonym(pwd, "password")
            )
            replacement += f":{pwd_repl}"
        return replacement

    # Pattern for USER@DOMAIN:PASSWORD format
    # Handles: [USER]@[DOMAIN]:PASSWORD, user@domain:password, "user"@"domain":"password", etc.
    user_at_domain_pattern = re.compile(
        r"""
        (?<![A-Za-z0-9_./~-])
        (?P<user>
            ["']?\[USER\]["']?
            |
            ["']?\{USER\}["']?
            |
            ["']?[a-z0-9._$-]+["']?
        )
        @
        (?P<domain>
            ["']?\[DOMAIN\]["']?
            |
            ["']?\{DOMAIN\}["']?
            |
            ["']?[A-Za-z0-9._-]*[A-Za-z][A-Za-z0-9._-]*["']?
        )
        (?:
            \s*:\s*
            (?P<pwd>
                (?:"[^"]*"|'[^']*')
                |
                [^\s"'@:]+
            )
        )?
        """,
        re.IGNORECASE | re.VERBOSE,
    )
    content = user_at_domain_pattern.sub(_replace_user_at_domain_password, content)

    # Fallback: handle cases where placeholders were already substituted before matching
    leftover_combo_pattern = re.compile(
        rf"""
        (?P<domain>{re.escape(placeholder_domain)})
        \s*/\s*
        (?P<user>["']?[^\s:/@]+["']?)
        \s*:\s*
        (?P<pwd>["']?[^\s@]+["']?)
        (?P<suffix>@[^\s]+)?
        """,
        re.IGNORECASE | re.VERBOSE,
    )

    def _replace_leftover_combo(match: re.Match[str]) -> str:
        suffix = match.group("suffix") or ""
        user_raw = match.group("user") or ""
        pwd_raw = match.group("pwd") or ""
        user_repl = _apply_quote_wrapped(
            user_raw, _record_pseudonym(user_raw.strip("'\""), "user")
        )
        pwd_repl = _apply_quote_wrapped(
            pwd_raw, _record_pseudonym(pwd_raw.strip("'\""), "password")
        )
        return f"{match.group('domain')}/{user_repl}:{pwd_repl}{suffix}"

    replaced_leftovers = 0

    def _track_leftovers(match: re.Match[str]) -> str:
        nonlocal replaced_leftovers
        replaced_leftovers += 1
        return _replace_leftover_combo(match)

    content = leftover_combo_pattern.sub(_track_leftovers, content)
    if replaced_leftovers:
        print_warning_debug(
            f"[telemetry] Applied fallback sanitization to {replaced_leftovers} domain/user combos"
        )

    # Redact file paths (absolute, relative, and placeholder-backed) before domains.
    path_pattern = re.compile(
        r"""
        (?:
            # Absolute POSIX-style paths. Require at least one alphabetic
            # character after the slash so patterns like ``1/3:`` from
            # phase headers are not mistaken for paths.
            (?<![A-Za-z0-9._-])/(?!\{)(?=[^ \t<>"'`]*[A-Za-z])[^\s<>"'`]+
            |
            \./[^\s<>"'`]+
            |
            ~/[^\s<>"'`]+
            |
            (?<![A-Za-z0-9])[A-Za-z]:\\[^\s<>"']+
            |
            ["'](?<![A-Za-z0-9])[A-Za-z]:\\[^"']+["']
            |
            ["']?(?:\[DOMAIN\]|[A-Za-z0-9._-]+)(?:/[^\s<>"'`:@]+){2,}["']?
        )
        """,
        re.VERBOSE,
    )
    content = path_pattern.sub(
        lambda m: (
            m.group(0)
            if _is_already_sanitized(m.group(0).strip("'\""))
            else _record_pseudonym(m.group(0), "path")
        ),
        content,
    )

    # Redact usernames@domain patterns
    def _replace_user_at_domain(match: re.Match[str]) -> str:
        if _is_password_context(match, content):
            return match.group(0)
        token = match.group(0)
        if "@" not in token:
            return token
        # Qualified well-known principal: keep the public name, sanitize domain.
        preserved = _preserve_well_known_qualified(token)
        if preserved is not None:
            return preserved
        user_part, domain_part = token.split("@", 1)
        user_repl = _record_pseudonym(user_part, "user")
        domain_repl = _record_pseudonym(domain_part, "domain")
        return f"{user_repl}@{domain_repl}"

    content = re.sub(
        r"\b\w+@[a-zA-Z0-9.-]+\b",
        _replace_user_at_domain,
        content,
    )

    # Redact domain names (handles multi-level FQDNs like dc01.example.local)
    # IMPORTANT: Must match at least 2 labels with a TLD of 2+ chars
    # This avoids matching usernames like "john.doe" (only 2 parts, second part is 3 chars)
    # Pattern requires: label1.label2.[...].tld where tld is 2+ chars and there are 2+ dots OR 1 dot + TLD is clearly a TLD
    content = re.sub(
        r"(?<![\\/])\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.){2,}[a-zA-Z]{2,}\b(?![\\/])",
        lambda m: _record_pseudonym(m.group(0), "domain"),
        content,
        flags=re.IGNORECASE,
    )
    # Also match 2-label domains with common TLDs (but not usernames like john.doe)
    content = re.sub(
        r"(?<![\\/])\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.(?:com|net|org|local|edu|gov|mil|int|biz|info|name|pro|aero|coop|museum)\b(?![\\/])",
        lambda m: _record_pseudonym(m.group(0), "domain"),
        content,
        flags=re.IGNORECASE,
    )

    # As a complement to the generic domain patterns above, explicitly sanitize
    # values that appear after the word "domain" even when they do not use a
    # well‑known TLD (e.g., "active.htb", "corp.lab").
    # Pattern: "domain <fqdn>[punctuation]" → "domain [DOMAIN][punctuation]"
    domain_keyword_pattern = re.compile(
        r"(?i)(\bdomain\s+)"
        r"([a-z0-9][a-z0-9.-]*\.[a-z0-9.-]*[a-z0-9])"
        r"(?=[\s)\].,!?:;]|$)"
    )
    content = domain_keyword_pattern.sub(
        lambda m: m.group(1) + _record_pseudonym(m.group(2), "domain"),
        content,
    )

    # Final safety net: redact any remaining ``something.something`` tokens that
    # look like domains but did not match the more specific patterns above.
    # We require at least one alphabetic character on each side of the dot to
    # avoid matching pure numeric patterns (e.g. ``1.23``) and already-sanitized
    # placeholders. This intentionally over-sanitizes ambiguous tokens in favour
    # of safety (e.g. ``corp.htb``, ``lab.internal``).
    fallback_domain_like_pattern = re.compile(
        r"""
        (?<![A-Za-z0-9._-])
        (?<![\\/])\b
        (?=
            [A-Za-z0-9-]*[A-Za-z][A-Za-z0-9-]*      # left side has a letter
            \.
            [A-Za-z0-9.-]*[A-Za-z][A-Za-z0-9.-]*    # right side has a letter
        )
        [A-Za-z0-9.-]+\.[A-Za-z0-9.-]+
        \b(?![\\/])
        """,
        re.IGNORECASE | re.VERBOSE,
    )
    content = fallback_domain_like_pattern.sub(
        lambda m: _record_pseudonym(m.group(0), "domain"),
        content,
    )

    # Redact NetBIOS domain values in table rows to preserve domain semantics.
    content = re.sub(
        r"(│\s+[^│]*\s+│\s+Netbios\s+│\s+)([A-Z][A-Z0-9-]{2,14})(\s+│)",
        lambda m: m.group(1) + _record_pseudonym(m.group(2), "domain") + m.group(3),
        content,
        flags=re.IGNORECASE,
    )

    # Redact short hostnames (NetBIOS-style) in table VALUE cells only (not field names)
    # Pattern: field_name column + pipe + value column (where value is short hostname)
    # This catches hostnames like "DC01", "SERVER01", "WEB-SVR" that don't have dots
    # Only matches in the value column (3rd column), not the field name column (2nd column)
    content = re.sub(
        r"(│\s+[^│]+\s+│\s+)([A-Z][A-Z0-9-]{2,14})(\s+│)",
        lambda m: m.group(1) + _record_pseudonym(m.group(2), "hostname") + m.group(3),
        content,
    )

    # Handle already-sanitized domain placeholders (administrator@[DOMAIN])
    content = re.sub(
        r"\b[^\s@/:]+@\[DOMAIN\](?!\w)",
        lambda m: _record_pseudonym(m.group(0).split("@", 1)[0], "user") + "@[DOMAIN]",
        content,
    )

    # Handle NetBIOS fallback messaging (e.g., using HTB as default)
    netbios_default_pattern = re.compile(
        r'(?i)(netbios[^\n,]*,\s+using\s+)(["\']?)([A-Za-z0-9._-]+)(\2\s+as default\b[^\n]*)'
    )
    content = netbios_default_pattern.sub(
        lambda m: m.group(1)
        + _apply_quote_wrapped(
            m.group(2) + m.group(3) + m.group(2),
            _record_pseudonym(m.group(3), "domain"),
        )
        + m.group(4),
        content,
    )

    # Redact passwords (common patterns)
    password_patterns = [
        r'(password["\']?\s*[:=]\s*["\']?)([^"\'\s<>]+)',
        r'(pass["\']?\s*[:=]\s*["\']?)([^"\'\s<>]+)',
        r'(pwd["\']?\s*[:=]\s*["\']?)([^"\'\s<>]+)',
    ]
    for pattern in password_patterns:
        content = re.sub(
            pattern,
            lambda m: m.group(1) + _record_pseudonym(m.group(2), "password"),
            content,
            flags=re.IGNORECASE,
        )

    content = _sanitize_cli_flag(content, "-p", "password")
    content = _sanitize_cli_flag(content, "-pl", "password")
    content = _sanitize_cli_flag(content, "--password", "password")

    # Redact credentials in URLs
    def _replace_url_credentials(match: re.Match[str]) -> str:
        user = match.group("user")
        pwd = match.group("pwd")
        user_repl = _record_pseudonym(user, "user")
        pwd_repl = _record_pseudonym(pwd, "password")
        return f"://{user_repl}:{pwd_repl}@"

    content = re.sub(
        r"://(?P<user>[^:]+):(?P<pwd>[^@]+)@",
        _replace_url_credentials,
        content,
    )

    # Redact hostname values following explicit labels
    content = re.sub(
        r"(?i)(hostname\s*[:=]\s*)([^\s,;]+)",
        lambda m: m.group(1) + _record_pseudonym(m.group(2), "hostname"),
        content,
    )

    # Redact hostnames embedded in "name:HOST" metadata fields
    content = re.sub(
        r"(?i)(\bname\s*:\s*)([A-Za-z0-9._-]+)",
        lambda m: m.group(1)
        + (
            _record_pseudonym(m.group(2), "hostname")
            if not _is_already_sanitized(m.group(2))
            else m.group(2)
        ),
        content,
    )

    # Redact short DC hostnames (e.g. CICADA-DC, LAB-DC)
    content = re.sub(
        r"(?i)(?<!-)\b([A-Za-z0-9][A-Za-z0-9-]{1,61}-DC)\b(?!-)",
        lambda m: _record_pseudonym(m.group(1), "hostname")
        if not _is_already_sanitized(m.group(1))
        else m.group(1),
        content,
    )

    # Redact hostnames carried by dnspython resolution-failure messages.
    #
    # dnspython's NXDOMAIN/lookup-failure exceptions (bridged into the telemetry
    # buffer via the native-stack log handler) embed the queried host in
    # CLEARTEXT, and single-label / NetBIOS names (no dot) are NOT caught by the
    # IPv4 or multi-label-FQDN structural nets above. We close the leak the same
    # way the labeled hostname-context substitutions do (mirroring the
    # ``hostname:`` / ``name:`` / ``-DC`` passes): match ONLY the specific
    # labeled dnspython phrasings and pseudonymize the captured token as a
    # hostname, so the operator still sees the real name on their own --debug
    # console while the EXPORTED/uploaded buffer is scrubbed. Scoped strictly to
    # these labels -- no blanket single-label scrub (that would over-redact
    # ordinary prose). The captured token may be a single label or a dotted
    # FQDN; ``_record_pseudonym`` deduplicates either form.
    def _replace_dns_host(match: re.Match[str]) -> str:
        host = match.group(2)
        if _is_already_sanitized(host):
            return match.group(0)
        return match.group(1) + _record_pseudonym(host, "hostname")

    # "A lookup failed for SRV01:" / "AAAA lookup failed for SRV01:"
    content = re.sub(
        r"(?i)(\b(?:A|AAAA)\s+lookup\s+failed\s+for\s+)([A-Za-z0-9._-]+)(?=\s*[:.,;)]|\s|$)",
        _replace_dns_host,
        content,
    )

    # "The DNS query name does not exist: PRODFILE01." (optional trailing dot).
    # Also matches the shorter "... does not exist: HOST." phrasing that
    # dnspython appends when the message is concatenated with a lookup-failure
    # prefix.
    content = re.sub(
        r"(?i)((?:The\s+DNS\s+query\s+name\s+)?does\s+not\s+exist:\s+)([A-Za-z0-9._-]+?)\.?(?=[\s)\].,!?:;]|$)",
        _replace_dns_host,
        content,
    )

    # "connecting via aiosmb to FILESERVER:445" (single-label or FQDN host)
    content = re.sub(
        r"(?i)(\bconnecting\s+via\s+aiosmb\s+to\s+)([A-Za-z0-9._-]+)(?=:\d|\s|$)",
        _replace_dns_host,
        content,
    )

    # Protocol-recognizable native-stack scrub runs BEFORE the generic hex/hash
    # nets so its informative markers win (e.g. an NTLMSSP message becomes
    # "<redacted NTLM message: N bytes>", a key line keeps "<principal>:<enctype>:"
    # visible) instead of being collapsed into an opaque hash pseudonym by the
    # length-only nets below. The same scrub also runs as the final pass (LAST
    # LINE OF DEFENCE further down) — it is idempotent, so running it twice is a
    # no-op on already-redacted text.
    content = scrub_native_secrets_buffer(content)

    # Redact hashes (NTLM / LM:NTLM combinations)
    def _replace_hash_argument(match: re.Match[str]) -> str:
        prefix = match.group(1)
        hash_value = match.group(2)
        replacement = _record_pseudonym(hash_value, "hash")
        return prefix + replacement

    content = re.sub(
        r"(?i)(--hashes\s*:?\s*)([0-9a-f]{32})",
        _replace_hash_argument,
        content,
    )
    content = re.sub(
        r"\b[0-9a-f]{32}:[0-9a-f]{32}\b",
        lambda m: _record_pseudonym(m.group(0), "hash"),
        content,
    )
    # Generic long-hex net (defence-in-depth for Kerberos key material). A
    # 64-hex AES256 key has no internal word boundary, so the {32} net below
    # cannot anchor it; this net catches it before upload. The window is bounded
    # 40..128 hex: the floor (40) keeps the 32-hex NT-hash net's dedicated
    # handling below and never matches short hex (flags, etypes, seq numbers);
    # the ceiling (128) covers AES256 (64) and a concatenated key pair while
    # leaving absurdly long runs to the runaway-value guards (a 1024-char blob is
    # not a key and the keyword sanitizer deliberately preserves it).
    content = re.sub(
        r"(?i)\b[0-9a-f]{40,128}\b",
        lambda m: _record_pseudonym(m.group(0), "hash"),
        content,
    )
    content = re.sub(
        r"(?i)\b[0-9a-f]{32}\b",
        lambda m: _record_pseudonym(m.group(0), "hash"),
        content,
    )

    # Redact usernames in CLI flags
    content = _sanitize_cli_flag(content, "--username", "user")
    content = _sanitize_cli_flag(content, "--user", "user")
    content = _sanitize_cli_flag(content, "-u", "user")
    content = _sanitize_cli_flag(content, "-s", "user")
    content = _sanitize_cli_flag(content, "-ul", "user")
    # Redact domains in CLI flags (only when value looks domain-like)
    content = _sanitize_cli_domain_flag(content, "-d", "domain")
    content = _sanitize_cli_domain_flag(content, "--domain", "domain")
    content = _sanitize_cli_domain_flag(content, "--target-domain", "domain")
    content = _sanitize_cli_domain_flag(content, "-target-domain", "domain")
    content = _sanitize_cli_flag(content, "--credential", "password")
    content = _sanitize_cli_flag(content, "--credentials", "password")
    content = _sanitize_cli_flag(content, "--cred", "password")
    content = _sanitize_cli_flag(content, "--log", "path")
    content = _sanitize_cli_flag(content, "--log-file", "path")
    content = _sanitize_cli_flag(content, "--path", "path")
    content = _sanitize_cli_flag(content, "--output", "path")
    content = _sanitize_cli_flag(content, "-o", "path")

    # Redact generic keyword-based disclosures (user/password/Source/Target)
    content = _sanitize_keyword_value(
        content,
        keywords=["user", "username", "target user", "principal"],
        data_type="user",
    )
    content = _sanitize_keyword_value(
        content,
        keywords=["password", "pass", "pwd"],
        data_type="password",
    )
    content = _sanitize_keyword_value(
        content,
        keywords=[
            "cred",
            "creds",
            "credential",
            "credentials",
            "display_credential",
            "current_credential",
            "current_cred",
        ],
        data_type="password",
        separator_pattern=r"(?:\s*[:=]\s+)",
    )
    content = _sanitize_keyword_value(
        content,
        keywords=["source", "target"],
        data_type="user",
        separator_pattern=r"\s*:\s*",
        value_pattern=r"[^\n,<│]+",
    )
    content = _sanitize_keyword_value(
        content,
        keywords=[
            "hostname",
            "hostnames",
            "pdc_hostname",
            "pdc fqdn",
            "pdc ip",
            "target host",
            "target computer",
        ],
        data_type="hostname",
        separator_pattern=r"\s*[│|:=]\s*",  # Only match pipe/colon/equals, not spaces
    )
    content = _sanitize_keyword_value(
        content,
        keywords=[
            "domain",
            "domain context",
            "source domain",
            "target domain",
            "auth domain",
            # Underscore-compound forms used in debug f-strings. The bare
            # "domain" keyword above is matched with a \b word boundary, which
            # does NOT fire inside "current_domain" ('_' is a word char), so
            # current_domain=Rifa would otherwise leak the NetBIOS short name.
            "current_domain",
            "context_domain",
            "source_domain",
            "target_domain",
            "auth_domain",
            "current_credential_domain",
        ],
        data_type="domain",
        separator_pattern=r"\s*[│|:=]\s*",  # Only match pipe/colon/equals, not spaces
    )
    content = _sanitize_keyword_value(
        content,
        keywords=[
            "workspace",
            "workspace name",
            "engagement",
            "engagement name",
            "lab",
            "lab name",
        ],
        data_type="workspace",
        separator_pattern=r"\s*[│|:=]\s*",
    )

    # Redact domains in dig SRV queries/results (e.g., _ldap._tcp.dc._msdcs.example.tld)
    content = re.sub(
        r"(?i)(_msdcs\.)([A-Za-z0-9.-]+\.[A-Za-z]{2,})(\.)?",
        lambda m: m.group(1)
        + (
            _record_pseudonym(m.group(2), "domain")
            if not _is_already_sanitized(m.group(2))
            else m.group(2)
        )
        + (m.group(3) or ""),
        content,
    )
    content = re.sub(
        r"(?i)(\b_[a-z0-9._-]+\.[a-z0-9._-]+\.[a-z0-9._-]+\.)([A-Za-z0-9.-]+\.[A-Za-z]{2,})(\.)?",
        lambda m: m.group(1)
        + (
            _record_pseudonym(m.group(2), "domain")
            if not _is_already_sanitized(m.group(2))
            else m.group(2)
        )
        + (m.group(3) or ""),
        content,
    )

    # Redact known workspace domains (from variables.json / domains dir).
    known_domains = _get_known_domains()
    if known_domains:
        for domain in known_domains:
            escaped = re.escape(domain)
            domain_pattern = re.compile(rf"(?i)(?<![A-Za-z0-9-])({escaped})(\.)?")
            content = domain_pattern.sub(
                lambda m: _record_pseudonym(m.group(1), "domain") + (m.group(2) or ""),
                content,
            )

    # Redact known workspace hostnames (from enabled_computers.txt).
    known_hostnames = _get_known_hostnames()
    if known_hostnames:
        domain_suffixes = [d.casefold() for d in known_domains] if known_domains else []
        for hostname in known_hostnames:
            hostname_clean = hostname.strip().rstrip(".")
            if not hostname_clean:
                continue
            hostname_lower = hostname_clean.casefold()
            matched_domain = None
            for domain in domain_suffixes:
                if hostname_lower.endswith(f".{domain}"):
                    matched_domain = domain
                    break
            if matched_domain:
                short_hostname = hostname_clean[: -(len(matched_domain) + 1)]
                if short_hostname:
                    short_pattern = re.compile(
                        rf"(?i)(?<![A-Za-z0-9-])({re.escape(short_hostname)})(?![A-Za-z0-9-])"
                    )
                    content = short_pattern.sub(
                        lambda m: _record_pseudonym(m.group(1), "hostname"),
                        content,
                    )
            fqdn_pattern = re.compile(
                rf"(?i)(?<![A-Za-z0-9-])({re.escape(hostname_clean)})(\.)?"
            )
            content = fqdn_pattern.sub(
                lambda m: _record_pseudonym(m.group(1), "hostname")
                + (m.group(2) or ""),
                content,
            )

    # Redact known workspace users (from enabled_users.txt per domain).
    known_users = _get_known_users()
    if known_users:
        for user in known_users:
            user_clean = user.strip()
            if not user_clean:
                continue
            # Boundaried, case-insensitive match. A registered username is
            # redacted ONLY as a standalone token; the boundaries stop it from
            # rewriting occurrences inside unrelated words (the over-greediness
            # fix). There is NO value-skip-list: a username that equals a common
            # word (e.g. "admin") is a registered secret and MUST be redacted
            # everywhere it appears as that bounded token -- leaking it is the
            # legal risk; corrupting the prose word is the acceptable lesser evil.
            #
            # force=True: a value registered in the workspace known-user set is an
            # explicit "this is the operation's account" declaration, so it
            # overrides the well-known-principal debugging passthrough. Otherwise
            # an engagement whose actual account is literally "administrator"
            # would leak in cleartext. (The well-known passthrough still applies
            # to UNREGISTERED, shape-detected names elsewhere in this function.)
            user_pattern = re.compile(
                rf"(?i)(?<![A-Za-z0-9._-])({re.escape(user_clean)})(?![A-Za-z0-9._-])"
            )
            content = user_pattern.sub(
                lambda m: _record_pseudonym(m.group(1), "user", force=True),
                content,
            )

    # Redact known workspace base DNs (from variables.json).
    known_base_dns = _get_known_base_dns()
    if known_base_dns:
        for base_dn in known_base_dns:
            base_dn_clean = base_dn.strip()
            if not base_dn_clean:
                continue
            escaped = re.escape(base_dn_clean)
            flexible = escaped.replace(r"\,", r"\s*,\s*")
            base_dn_pattern = re.compile(rf"(?i){flexible}")
            content = base_dn_pattern.sub(
                lambda m: _record_pseudonym(m.group(0), "domain"),
                content,
            )

    # Redact known workspace NetBIOS names (from variables.json).
    known_netbios = _get_known_netbios()
    if known_netbios:
        for netbios in known_netbios:
            netbios_clean = netbios.strip()
            if not netbios_clean:
                continue
            netbios_user_pattern = re.compile(
                rf"(?i)({re.escape(netbios_clean)})(\\+)([A-Za-z0-9._-]+)"
            )
            content = netbios_user_pattern.sub(
                lambda m: (
                    _record_pseudonym(m.group(1), "domain")
                    + m.group(2)
                    + _record_pseudonym(m.group(3), "user")
                ),
                content,
            )
            netbios_pattern = re.compile(
                rf"(?i)(?<![A-Za-z0-9-])({re.escape(netbios_clean)})(?![A-Za-z0-9-])"
            )
            content = netbios_pattern.sub(
                lambda m: _record_pseudonym(m.group(1), "domain"),
                content,
            )

    # Redact known workspace passwords (from variables.json domains_data).
    known_passwords = _get_known_passwords()
    if known_passwords:
        for password in known_passwords:
            password_clean = password.strip()
            if not password_clean:
                continue
            # Boundaried, CASE-SENSITIVE match. Mirrors the known-user loop's
            # alnum/credential-char boundaries so a registered password no
            # longer rewrites occurrences inside unrelated words or log-level
            # tokens (e.g. a password "Inform" must not match inside
            # "Information"). Case is preserved deliberately: password casing is
            # significant, and case-folding here is what let a value match a
            # differently-cased ordinary word.
            password_pattern = re.compile(
                rf"(?<![A-Za-z0-9._@/-])({re.escape(password_clean)})(?![A-Za-z0-9._@/-])"
            )
            content = password_pattern.sub(
                lambda m: _record_pseudonym(m.group(1), "password"),
                content,
            )

    # Redact known workspace names (current workspace and sibling workspaces).
    known_workspaces = _get_known_workspaces()
    if known_workspaces:
        for workspace_name in known_workspaces:
            workspace_clean = workspace_name.strip()
            if not workspace_clean:
                continue
            workspace_pattern = re.compile(
                rf"(?i)(?<![A-Za-z0-9._-])({re.escape(workspace_clean)})(?![A-Za-z0-9._-])"
            )
            content = workspace_pattern.sub(
                lambda m: _record_pseudonym(m.group(1), "workspace"),
                content,
            )

    # Apply structured redaction for credential tables and lists
    content = _mask_credential_sections(content)
    content = _sanitize_domain_property_tables(content)
    content = _sanitize_share_tables(content)
    content = _sanitize_gpp_tables(content)
    # Sanitize User Descriptions table BEFORE other table sanitizations
    # to avoid title being modified by keyword sanitization
    content = _sanitize_user_descriptions_table(content)
    content = _sanitize_detected_credential_tables(content)
    # Sanitize Kerberos Delegations tables
    content = _sanitize_delegation_tables(content)

    # LAST LINE OF DEFENCE — whole-buffer native-stack secret scrub.
    # The marker-based + heuristic redaction above covers ADscan-originated
    # output (values tagged with mark_sensitive() at creation time) and known
    # credential tables. It does NOT cover raw native-stack authentication
    # material that reached the recording WITHOUT a marker — e.g. a vendor
    # ``print()`` mirrored to the --debug console, or a bridged vendor log line
    # carrying an NTLMSSP message / NetNTLM hashcat string / Kerberos blob. We
    # apply the SAME protocol-recognizable + label-gated detectors used by the
    # native-stack logging bridge (single source of truth in
    # ``adscan_core.native_secret_scrub``) over the entire exported buffer, so
    # this material is redacted before upload regardless of how it got here.
    # Runs BEFORE passthrough restore so the (known-safe) passthrough segments
    # are never touched. ``scrub_native_secrets_buffer`` is best-effort and
    # never raises; if a future change makes it raise, the surrounding
    # try/except in ``capture_session_end`` skips the upload (fail-closed).
    content = scrub_native_secrets_buffer(content)

    content = _restore_passthrough_segments(content, passthrough_mapping)
    return content


# C0 control characters that Postgres ``text`` columns cannot store. A NUL
# (``\x00``) — or any other C0 control except tab/newline/carriage-return — in
# the uploaded payload makes the ingest DB reject the whole row with
# ``22P05 / "cannot be converted to text"`` (a deterministic 500 no retry can
# fix). ``\t`` (0x09), ``\n`` (0x0a) and ``\r`` (0x0d) are legal and preserved.
_DB_UNSAFE_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _strip_db_unsafe_chars(content: str) -> str:
    """Remove Postgres-illegal C0 control chars (incl. NUL) from ``content``.

    Deterministic and cheap: a single compiled-regex substitution. Preserves
    ``\\t``, ``\\n`` and ``\\r`` (the only C0 controls a ``text`` column accepts)
    and is a byte-identical no-op when there is nothing illegal to strip.
    """
    if not content:
        return content
    return _DB_UNSAFE_CONTROL_CHARS.sub("", content)


def _maybe_sanitize_rich_output(content: str, *, sanitize: bool) -> str:
    """Prepare Rich export for session storage, optionally applying redaction.

    When sanitization is disabled, we still normalize the Rich export (strip
    ANSI/HTML) but avoid redaction to preserve debugging context. In that mode we
    also strip invisible markers so they don't affect stored text.

    As the LAST step (after any secret/path redaction) we strip DB-unsafe
    control characters so the resulting payload field is storable by the ingest
    DB by construction — this is the single sanitization boundary both the live
    upload and the on-disk retry queue draw from, so neither can be poisoned by
    a NUL byte.
    """
    if sanitize:
        return _strip_db_unsafe_chars(_sanitize_rich_output(content))
    prepared = _prepare_rich_content_for_processing(content)
    return _strip_db_unsafe_chars(_strip_sensitive_markers(prepared))


def _sanitize_cli_flag(content: str, flag: str, data_type: str) -> str:
    """Sanitize CLI flag values with length-preserving pseudonyms."""
    flag_pattern = re.escape(flag)
    # Quoted values
    quoted_pattern = re.compile(
        rf"({flag_pattern}\s+)"
        r"(?:<[^>]+>)*"
        r"([\"'])"
        r"(?:<[^>]+>)*"
        r"([^\"'<]+?)"
        r"(?:<[^>]+>)*"
        r"([\"'])",
        re.IGNORECASE,
    )
    content = quoted_pattern.sub(
        lambda m: m.group(1)
        + (
            f"{m.group(2)}{m.group(3)}{m.group(4)}"
            if _is_already_sanitized(m.group(3))
            else _apply_quote_wrapped(
                f"{m.group(2)}{m.group(3)}{m.group(4)}",
                _record_pseudonym(m.group(3), data_type),
            )
        ),
        content,
    )

    # Unquoted values
    unquoted_pattern = re.compile(
        rf"({flag_pattern}\s+)"
        r"(?:<[^>]+>)*"
        r"([^\s<\"']+)",
        re.IGNORECASE,
    )
    content = unquoted_pattern.sub(
        lambda m: m.group(1)
        + (
            m.group(2)
            if _is_already_sanitized(m.group(2))
            else _fit_to_length(
                _record_pseudonym(m.group(2), data_type), len(m.group(2))
            )
        ),
        content,
    )
    return content


def _sanitize_cli_domain_flag(content: str, flag: str, data_type: str) -> str:
    """Sanitize domain values for a CLI flag, only when value looks domain-like.

    Flags like ``-d`` are used by other tools for unrelated purposes (for example
    ``apt-get -d install``). To avoid over-sanitization (which makes debugging
    harder), we only redact when the value resembles a domain (contains a dot) or
    is already a known domain placeholder.
    """
    flag_pattern = re.escape(flag)
    domain_like = (
        r"(?:\{DOMAIN\}|\[DOMAIN\]|"
        r"[A-Za-z0-9._-]*\.[A-Za-z0-9._-]*[A-Za-z0-9])"
    )

    # Quoted values
    quoted_pattern = re.compile(
        rf"({flag_pattern}\s+)"
        r"(?:<[^>]+>)*"
        r"([\"'])"
        r"(?:<[^>]+>)*"
        rf"({domain_like})"
        r"(?:<[^>]+>)*"
        r"([\"'])",
        re.IGNORECASE,
    )
    content = quoted_pattern.sub(
        lambda m: m.group(1)
        + (
            f"{m.group(2)}{m.group(3)}{m.group(4)}"
            if _is_already_sanitized(m.group(3))
            else _apply_quote_wrapped(
                f"{m.group(2)}{m.group(3)}{m.group(4)}",
                _record_pseudonym(m.group(3), data_type),
            )
        ),
        content,
    )

    # Unquoted values
    unquoted_pattern = re.compile(
        rf"({flag_pattern}\s+)"
        r"(?:<[^>]+>)*"
        rf"({domain_like})",
        re.IGNORECASE,
    )
    content = unquoted_pattern.sub(
        lambda m: m.group(1)
        + (
            m.group(2)
            if _is_already_sanitized(m.group(2))
            else _fit_to_length(
                _record_pseudonym(m.group(2), data_type), len(m.group(2))
            )
        ),
        content,
    )
    return content


# Hard upper bound for any single keyword=value match. Legitimate secrets
# (passwords, tokens, FQDNs, paths, lab names, workspace names) are well
# under this — anything bigger is, in practice, a regex over-capture that
# escaped past the intended single-quoted/unquoted value. Used by the
# sanity guard below to reject runaway matches outright.
_KEYWORD_VALUE_MAX_LEN = 512

# Characters that should never appear inside a real keyword value but
# routinely appear in Rich panels, log lines, and prompt echoes the
# regex might accidentally capture. Box-drawing, vertical bars used as
# table separators, and the warning glyph are all strong signals that
# the regex jumped out of the intended quoted span.
_KEYWORD_VALUE_REJECT_CHARS = frozenset("│─╭╮╰╯┌┐└┘├┤┬┴┼━┃┏┓┗┛⚠")

# Substrings that strongly suggest the captured "value" is a multi-line
# escape into the surrounding log/UI text rather than a real secret.
# Any Rich-emitted log level prefix or panel marker collapses many
# false positives in one check.
_KEYWORD_VALUE_REJECT_SUBSTRINGS = (
    "\nDEBUG",
    "\nINFO",
    "\nWARNING",
    "\nERROR",
    "\nCRITICAL",
    "\n⚠",
    "\nℹ",
    "\n✓",
    "Workspace creation",
    "Workspace Required",
    " » ",
    "Prompt:",
    "Answer for",
)


def _looks_like_keyword_value(value: str) -> bool:
    """Sanity-check a regex-captured keyword value before pseudonymizing.

    The keyword-value regex is intentionally permissive — it has to cope
    with the noisy formats real secrets appear in (CLI flags, table cells,
    log key=value pairs, panel rows). That permissiveness lets it
    occasionally capture a runaway span that escapes its intended quoted
    region (see the historical Workspace Required regression: a stray
    closing quote in ``Answer for 'Enter name for a new workspace: ':``
    let the regex devour the entire follow-up panel before finding the
    next isolated ``'`` further down the buffer).

    This guard rejects captures that cannot plausibly be a real secret:

    * empty / whitespace-only — nothing to sanitize.
    * longer than ``_KEYWORD_VALUE_MAX_LEN`` — secrets are short.
    * contain newlines / carriage returns — keyword values are single
      line; multiline captures are escapes.
    * contain box-drawing characters or panel glyphs — those mark
      captured UI surfaces, not secrets.
    * contain canonical multi-line escape signatures (log level prefixes
      after a newline, recognizable UI substrings).

    Returning ``False`` makes the caller skip the substitution for that
    match without touching the rest of the sanitizer pipeline.
    """
    if not value:
        return False
    if len(value) > _KEYWORD_VALUE_MAX_LEN:
        return False
    if "\n" in value or "\r" in value:
        return False
    if any(ch in _KEYWORD_VALUE_REJECT_CHARS for ch in value):
        return False
    for marker in _KEYWORD_VALUE_REJECT_SUBSTRINGS:
        if marker in value:
            return False
    return True


def _sanitize_keyword_value(
    content: str,
    keywords: list[str],
    data_type: str,
    separator_pattern: str = r"(?:\s*[:=]\s*|\s*[│|]\s*|[ \t]+)",
    value_pattern: str = r"[A-Za-z0-9._@!%^&*+=\\/-]+",
) -> str:
    """Sanitize values that follow specific keywords (user/password/source/etc.).

    Two regexes run in sequence — quoted (``keyword: 'value'``) and
    unquoted (``keyword: value``). Both are defended by the
    ``_looks_like_keyword_value`` guard in the callback so any over-capture
    is silently rejected without polluting the surrounding text.
    """
    if not keywords:
        return content

    keyword_pattern = "|".join(re.escape(keyword) for keyword in keywords)
    base_pattern = rf"(?i)(?<!\{{|\[)(\b(?:{keyword_pattern})\b{separator_pattern})"

    def _build_quoted_regex() -> re.Pattern[str]:
        # The value char-class explicitly excludes newlines / carriage
        # returns. A legitimate quoted keyword value is always single line;
        # allowing the regex to cross line boundaries lets it bridge an
        # unmatched quote in one line with an unrelated quote many lines
        # later (the historical Workspace Required regression).
        # The bounded ``{1,N}?`` quantifier caps backtracking blast radius
        # and keeps a runaway match from spanning the whole buffer even
        # under pathological inputs.
        return re.compile(
            base_pattern
            + r"(?:<[^>]+>)*(?P<quote>['\"])"
            + r"(?:<[^>]+>)*(?P<value>[^\"'<\n\r]{1,"
            + str(_KEYWORD_VALUE_MAX_LEN)
            + r"}?)"
            + r"(?:<[^>]+>)*(?P=quote)",
            re.IGNORECASE,
        )

    def _build_unquoted_regex() -> re.Pattern[str]:
        return re.compile(
            base_pattern + r"(?:<[^>]+>)*(?P<value>" + value_pattern + r")",
            re.IGNORECASE,
        )

    def _line_for_match(match: re.Match[str]) -> str:
        text = match.string
        line_start = text.rfind("\n", 0, match.start()) + 1
        line_end = text.find("\n", match.start())
        if line_end == -1:
            line_end = len(text)
        return text[line_start:line_end]

    def _match_crosses_newline(match: re.Match[str]) -> bool:
        """True if the full match spans a line break.

        The default separator pattern uses ``\\s*`` which matches newlines
        too, so an unquoted regex can pick up a keyword on one line and
        latch onto the first alphanumeric token of the next line as the
        "value" (e.g. ``workspace:\\n  DEBUG     ...`` → value=``DEBUG``).
        Real keyword=value pairs are always single-line, so reject any
        match whose span includes a newline character.
        """
        span = match.string[match.start() : match.end()]
        return "\n" in span or "\r" in span

    def _replace_if_not_placeholder(match: re.Match[str]) -> str:
        """Replace value only if it's not already a placeholder."""
        value = match.group("value")
        if "user descriptions" in _line_for_match(match).lower():
            return match.group(0)
        if _match_crosses_newline(match):
            # Keyword on line N, "value" on line N+1 — pure regex artifact.
            return match.group(0)
        # Strip whitespace and check if it starts with a placeholder
        # This handles cases like "[IP]    │" where trailing spaces/chars are captured
        value_stripped = value.strip()
        if value_stripped.startswith("[") and value_stripped.endswith("]"):
            # Value is already a placeholder, don't replace it
            return match.group(0)
        if _is_already_sanitized(value_stripped):
            return match.group(0)
        if not _looks_like_keyword_value(value_stripped):
            # Regex over-captured into surrounding UI/log text — bail out
            # without pseudonymizing. See `_looks_like_keyword_value`.
            return match.group(0)
        replacement = _record_pseudonym(value_stripped, data_type)
        return match.group(1) + _fit_to_length(replacement, len(value))

    def _replace_quoted(match: re.Match[str]) -> str:
        value = match.group("value")
        if "user descriptions" in _line_for_match(match).lower():
            return match.group(0)
        if _match_crosses_newline(match):
            return match.group(0)
        value_stripped = value.strip()
        if value_stripped.startswith("[") and value_stripped.endswith("]"):
            return match.group(0)
        if _is_already_sanitized(value_stripped):
            return match.group(0)
        if not _looks_like_keyword_value(value_stripped):
            return match.group(0)
        replacement = _record_pseudonym(value_stripped, data_type)
        raw = f"{match.group('quote')}{value}{match.group('quote')}"
        return match.group(1) + _apply_quote_wrapped(raw, replacement)

    quoted_regex = _build_quoted_regex()
    content = quoted_regex.sub(_replace_quoted, content)

    unquoted_regex = _build_unquoted_regex()
    content = unquoted_regex.sub(_replace_if_not_placeholder, content)
    return content


def _mask_credential_sections(content: str) -> str:
    """Redact credential tables and user lists from sanitized Rich output."""
    lines = content.splitlines()
    mask_mode: str | None = None

    for idx, line in enumerate(lines):
        stripped = line.strip().lower()

        if not stripped:
            mask_mode = None
            continue

        if "cracked credentials" in stripped:
            mask_mode = "credentials_table"
            continue

        if "domain credentials" in stripped or "credentials for domain" in stripped:
            mask_mode = "credentials_table"
            continue

        if "asreproastable users" in stripped or (
            "users" in stripped and ("[domain]" in stripped or "rid" in stripped)
        ):
            mask_mode = "user_list"
            continue

        if "users found" in stripped:
            mask_mode = "user_list"
            continue

        if "index" in stripped and "users" in stripped:
            mask_mode = "user_list"
            continue

        if "username" in stripped and "password" in stripped:
            if mask_mode != "credentials_table":
                mask_mode = "credentials_table"
            continue

        if mask_mode == "credentials_table" and any(
            token in line for token in ("┌", "┬", "└", "┴", "├", "┤", "┼")
        ):
            continue

        if mask_mode == "user_list":
            lines[idx] = _record_pseudonym(line, "redacted")
            continue

        if mask_mode == "credentials_table":
            if "│" in line and any(
                keyword in stripped for keyword in ("user", "username", "credential", "password")
            ):
                continue
            if "│" in line:
                segments = line.split("│")
                interior_indices = [
                    idx_seg
                    for idx_seg in range(1, len(segments) - 1)
                    if segments[idx_seg].strip()
                ]
                if len(interior_indices) >= 2:
                    if len(interior_indices) >= 3:
                        segments[interior_indices[0]] = _replace_table_cell(
                            segments[interior_indices[0]], "domain"
                        )
                        segments[interior_indices[1]] = _replace_table_cell(
                            segments[interior_indices[1]], "user"
                        )
                        segments[interior_indices[2]] = _replace_table_cell(
                            segments[interior_indices[2]], "password"
                        )
                    else:
                        segments[interior_indices[0]] = _replace_table_cell(
                            segments[interior_indices[0]], "user"
                        )
                        segments[interior_indices[1]] = _replace_table_cell(
                            segments[interior_indices[1]], "password"
                        )
                    lines[idx] = "│".join(segments)
                    continue
            lines[idx] = _record_pseudonym(line, "redacted")
            continue

    return "\n".join(lines)


def _sanitize_domain_property_tables(content: str) -> str:
    """Redact sensitive key/value data inside domain info tables."""
    replacements: dict[str, str] = {
        "credentials": "redacted",
        "kerberos_tickets": "path",
        "username": "user",
        "password": "password",
        "netbios": "domain",
        "base_dn": "domain",
        "dcs_hostnames": "hostname",
        "pdc_hostname": "hostname",
    }

    lines = content.splitlines()
    for idx, line in enumerate(lines):
        if "│" not in line or not any(name in line.lower() for name in replacements):
            continue
        if any(ch in line for ch in ("┌", "┬", "└", "┴", "├", "┼", "┤")):
            continue

        parts = line.split("│")
        if len(parts) < 4:
            continue

        property_name = parts[2].strip().lower()
        rule = replacements.get(property_name)
        if not rule:
            continue

        parts[3] = _replace_table_cell(parts[3], rule)
        lines[idx] = "│".join(parts)

    return "\n".join(lines)


def _sanitize_share_tables(content: str) -> str:
    """Redact SMB share names from Rich tables."""
    lines = content.splitlines()
    in_share_table = False

    for idx, line in enumerate(lines):
        stripped = line.strip().lower()

        if "smb shares discovered on" in stripped:
            in_share_table = True
            continue

        if not in_share_table:
            continue

        if "└" in line and "┘" in line:
            in_share_table = False
            continue

        if not stripped:
            in_share_table = False
            continue

        if any(token in stripped for token in ("host", "share", "permission")):
            continue

        if any(token in line for token in ("┌", "┬", "└", "┴", "├", "┼", "──")):
            continue

        if "│" not in line:
            in_share_table = False
            continue

        share_replaced = False
        candidate_line = line
        segments = line.split("│")
        interior_indices = [
            idx_seg
            for idx_seg in range(1, len(segments) - 1)
            if segments[idx_seg].strip()
        ]
        if len(interior_indices) >= 2:
            share_idx = interior_indices[1]
            segments[share_idx] = _replace_table_cell(segments[share_idx], "share")
            candidate_line = "│".join(segments)
            share_replaced = True

        raw_tokens = [
            tok for tok in line.replace("│", " ").split() if tok not in ("│", "┃", "──")
        ]
        if len(raw_tokens) >= 2:
            perm_token = raw_tokens[-1]
            share_token = raw_tokens[-2]
            share_regex = re.compile(
                rf"({re.escape(share_token)})(\s+{re.escape(perm_token)})",
                re.IGNORECASE,
            )
            share_replacement = _record_pseudonym(share_token, "share")
            candidate_line, replaced = share_regex.subn(
                lambda m: _fit_to_length(share_replacement, len(share_token))
                + m.group(2),
                candidate_line,
                count=1,
            )
            if replaced:
                share_replaced = True

        if share_replaced:
            lines[idx] = candidate_line

    return "\n".join(lines)


def _sanitize_gpp_tables(content: str) -> str:
    """Redact GPP credential tables."""
    lines = content.splitlines()
    in_gpp_table = False

    for idx, line in enumerate(lines):
        stripped = line.strip().lower()

        if "gpp credentials found" in stripped:
            in_gpp_table = True
            continue

        if not in_gpp_table:
            continue

        if "└" in line and "┘" in line:
            in_gpp_table = False
            continue

        if not stripped:
            in_gpp_table = False
            continue

        if all(keyword in stripped for keyword in ("domain", "user", "credential")):
            continue

        if any(token in line for token in ("┌", "┬", "└", "┴", "├", "┼", "──")):
            continue

        if re.fullmatch(r"[\s-]+", line):
            continue

        if "│" not in line and not _looks_like_plain_text_table_row(
            line, min_columns=3
        ):
            in_gpp_table = False
            continue

        replaced = False
        candidate_line = line

        if "│" in line:
            segments = line.split("│")
            interior_indices = [
                idx_seg
                for idx_seg in range(1, len(segments) - 1)
                if segments[idx_seg].strip()
            ]
            if len(interior_indices) >= 3:
                col_domain, col_user, col_cred = interior_indices[:3]
                segments[col_domain] = _replace_table_cell(
                    segments[col_domain], "domain"
                )
                segments[col_user] = _replace_table_cell(segments[col_user], "user")
                segments[col_cred] = _replace_table_cell(segments[col_cred], "password")
                candidate_line = "│".join(segments)
                replaced = True
            else:
                raw_tokens = [tok for tok in line.replace("│", " ").split() if tok]
                if len(raw_tokens) >= 3:
                    domain_token, user_token, cred_token = raw_tokens[:3]
                    pattern = re.compile(
                        rf"({re.escape(domain_token)})(\s+)({re.escape(user_token)})(\s+){re.escape(cred_token)}",
                        re.IGNORECASE,
                    )
                    domain_repl = _record_pseudonym(domain_token, "domain")
                    user_repl = _record_pseudonym(user_token, "user")
                    cred_repl = _record_pseudonym(cred_token, "password")
                    candidate_line, replaced = pattern.subn(
                        lambda m: _fit_to_length(domain_repl, len(domain_token))
                        + m.group(2)
                        + _fit_to_length(user_repl, len(user_token))
                        + m.group(4)
                        + _fit_to_length(cred_repl, len(cred_token)),
                        line,
                        count=1,
                    )
        else:
            parts = re.split(r"(\s{2,})", line.rstrip("\n"))
            cell_indices = [
                index
                for index in range(0, len(parts), 2)
                if parts[index].strip()
            ]
            if len(cell_indices) >= 3:
                replacements = ("domain", "user", "password")
                for cell_index, data_type in zip(cell_indices[:3], replacements):
                    raw_cell = parts[cell_index]
                    stripped_cell = raw_cell.strip()
                    if not stripped_cell:
                        continue
                    replacement = _fit_to_length(
                        _record_pseudonym(stripped_cell, data_type),
                        len(stripped_cell),
                    )
                    leading = len(raw_cell) - len(raw_cell.lstrip(" "))
                    trailing = len(raw_cell) - len(raw_cell.rstrip(" "))
                    parts[cell_index] = (
                        (" " * leading)
                        + replacement
                        + (" " * trailing)
                    )
                candidate_line = "".join(parts)
                replaced = True

        if replaced:
            lines[idx] = candidate_line
            continue

        if "domain" in stripped and "password" in stripped:
            continue

    return "\n".join(lines)


def _sanitize_detected_credential_tables(content: str) -> str:
    """Redact credential values from CredSweeper/ML detection tables."""
    lines = content.splitlines()
    in_table = False

    for idx, line in enumerate(lines):
        stripped = line.strip().lower()

        if "value" in stripped and "confidence" in stripped:
            in_table = True
            continue

        if not in_table:
            continue

        if "└" in line and "┘" in line:
            in_table = False
            continue

        if not stripped:
            continue

        if any(token in line for token in ("┌", "┬", "├", "┼", "──")):
            continue

        if "│" not in line:
            continue

        segments = line.split("│")
        interior_indices = [
            idx_seg
            for idx_seg in range(1, len(segments) - 1)
            if segments[idx_seg].strip()
        ]
        if len(interior_indices) < 2:
            continue

        value_idx = interior_indices[1]
        segments[value_idx] = _replace_table_cell(segments[value_idx], "password")
        lines[idx] = "│".join(segments)

    return "\n".join(lines)


def _sanitize_delegation_tables(content: str) -> str:
    """Redact account names and delegation targets from Kerberos Delegations tables.

    Sanitizes delegation tables created by print_delegations_summary():
    - Redacts account names (e.g., "WIN-DC$", "Administrator")
    - Redacts delegation targets (e.g., "MSSQL/sql.local", "HTTP/web.corp.local")
    - Preserves table structure and risk indicators

    Args:
        content: Rich output to sanitize

    Returns:
        Sanitized content with account names and delegation targets redacted
    """
    lines = content.splitlines()
    in_table = False

    for idx, line in enumerate(lines):
        stripped = line.strip().lower()

        # Detect table start: contains "delegation" in title with table borders
        # Titles like "🔐 Unconstrained Delegation (2 found)"
        is_delegation_title = "delegation" in stripped and any(
            token in line for token in ("┏", "┃", "│", "┡", "╇", "╭", "╮")
        )

        if is_delegation_title:
            in_table = True
            continue

        if not in_table:
            continue

        # Detect table end
        if ("└" in line and "┘" in line) or ("╰" in line and "╯" in line):
            in_table = False
            continue

        # Skip headers and borders
        if any(
            token in line
            for token in (
                "┌",
                "┬",
                "└",
                "┴",
                "├",
                "┼",
                "┡",
                "╇",
                "┩",
                "┓",
                "┳",
                "┏",
                "┗",
                "╭",
                "╮",
                "╰",
                "╯",
                "━",
                "┃",
            )
        ):
            continue

        # Process data rows (only contains │ separators)
        if "│" in line and "┃" not in line:
            segments = line.split("│")

            # Find non-empty segments
            non_empty_indices = [
                i
                for i, seg in enumerate(segments)
                if seg.strip() and seg.strip() not in ("│", "┃")
            ]

            if len(non_empty_indices) < 3:
                continue

            # Find row number position
            row_number_pos = None
            for idx_pos, seg_idx in enumerate(non_empty_indices):
                seg = segments[seg_idx].strip()
                if seg.isdigit():
                    row_number_pos = idx_pos
                    break

            if row_number_pos is None:
                continue

            # Standard layout: # | Account | Account Type | Delegation To
            # Account is at row_number_pos + 1
            # Delegation To is at row_number_pos + 3
            if row_number_pos + 1 < len(non_empty_indices):
                account_idx = non_empty_indices[row_number_pos + 1]
                account_segment = segments[account_idx].strip()
                if (
                    account_segment
                    and not account_segment.isdigit()
                    and not account_segment.startswith("[")
                ):
                    # Always sanitize account names
                    segments[account_idx] = _replace_table_cell(
                        segments[account_idx], "user"
                    )

            if row_number_pos + 3 < len(non_empty_indices):
                delegation_idx = non_empty_indices[row_number_pos + 3]
                delegation_segment = segments[delegation_idx].strip()
                if (
                    delegation_segment
                    and not delegation_segment.startswith("[")
                    and delegation_segment.lower()
                    not in ("any service", "any", "n/a", "-")
                ):
                    # Sanitize specific service targets
                    segments[delegation_idx] = _replace_table_cell(
                        segments[delegation_idx], "service"
                    )

            lines[idx] = "│".join(segments)

    return "\n".join(lines)


def _sanitize_user_descriptions_table(content: str) -> str:
    """Redact usernames and ALL descriptions from User Descriptions table."""
    lines = content.splitlines()
    in_table = False
    username_col_idx = None
    description_col_idx = None

    for idx, line in enumerate(lines):
        stripped = line.strip().lower()

        # Detect table start: "User Descriptions" (with or without "found")
        # Also detect if title was already sanitized (e.g., "User [USER] (4 found)")
        # Look for pattern: "User" + optional sanitized text + number + "found" + table borders
        is_user_desc_title = "user description" in stripped or (
            "user" in stripped
            and ("found" in stripped or re.search(r"\(\d+\s+found\)", stripped))
            and any(token in line for token in ("┏", "┃", "│", "┡", "╇"))
        )

        # Also detect by header structure: if we see "Username" and "Description" headers
        # this indicates we're in a User Descriptions table (even if title was sanitized)
        has_user_desc_headers = (
            "username" in stripped
            and "description" in stripped
            and ("│" in line or "┃" in line)
        )

        if is_user_desc_title or (has_user_desc_headers and not in_table):
            in_table = True
            username_col_idx = None
            description_col_idx = None
            # Don't continue here - let it process the header line to set column indices

        if not in_table:
            continue

        # Detect table end
        if "└" in line and "┘" in line:
            in_table = False
            continue

        # Skip table borders and headers (but not data rows)
        if any(
            token in line
            for token in (
                "┌",
                "┬",
                "└",
                "┴",
                "├",
                "┼",
                "┡",
                "╇",
                "┩",
                "┓",
                "┳",
                "┏",
                "┗",
            )
        ):
            continue

        # Detect column headers to identify column positions
        if (
            ("│" in line or "┃" in line)
            and "username" in stripped
            and "description" in stripped
        ):
            # Parse header to find column indices
            # Headers may use ┃ but data rows use │
            # When header split by ┃: [0]='│', [1]='#', [2]='Username', [3]='Description', [4]='│'
            # When data split by │: [0]='', [1]='1', [2]='Administrator', [3]='Description', [4]=''
            # The indices match! Username at 2, Description at 3

            # Try splitting by ┃ first (for headers with ┃)
            if "┃" in line:
                segments = line.split("┃")
                # Find column indices in header
                # When header uses ┃: [0]='│', [1]='#', [2]='Username', [3]='Description'
                # When data uses │: [0]='', [1]='', [2]='#', [3]='Username', [4]='Description'
                # So we need to add +1 to map from ┃ indices to │ indices
                for seg_idx, segment in enumerate(segments):
                    seg_lower = segment.strip().lower()
                    if "username" in seg_lower and username_col_idx is None:
                        username_col_idx = seg_idx + 1  # Add 1 to map to │ indices
                    if "description" in seg_lower and description_col_idx is None:
                        description_col_idx = seg_idx + 1  # Add 1 to map to │ indices
            else:
                # Header uses │, parse normally
                segments = line.split("│")
                for seg_idx, segment in enumerate(segments):
                    seg_lower = segment.strip().lower()
                    if "username" in seg_lower and username_col_idx is None:
                        username_col_idx = seg_idx
                    if "description" in seg_lower and description_col_idx is None:
                        description_col_idx = seg_idx

            # Fallback: use standard positions if not found
            # Standard positions when data rows use │: username=3, description=4
            if username_col_idx is None:
                username_col_idx = 3  # Standard position in │-separated rows
            if description_col_idx is None:
                description_col_idx = 4  # Standard position in │-separated rows
            continue

        # Process data rows
        if "│" in line or "┃" in line:
            segments = line.split("│")
            if len(segments) < 3:
                segments = line.split("┃")

            if len(segments) < 3:
                continue

            # If we're in table, detect/recalibrate column indices from first data row
            # This ensures we get correct indices regardless of header format
            # Look for a row that has a digit in early segments (row number) and content in later segments
            if in_table:
                # Check if this looks like a data row (has a digit for row number)
                has_row_number = any(
                    segments[i].strip().isdigit() for i in range(min(4, len(segments)))
                )
                if has_row_number:
                    # Find segments that look like row number, username, and description
                    for i in range(min(4, len(segments))):
                        seg = segments[i].strip()
                        if seg.isdigit():
                            # Found row number at index i, username should be at i+1, description at i+2
                            if i + 1 < len(segments) and i + 2 < len(segments):
                                # Only set if not already set, or recalibrate if indices seem wrong
                                if (
                                    username_col_idx is None
                                    or username_col_idx != i + 1
                                ):
                                    username_col_idx = i + 1
                                if (
                                    description_col_idx is None
                                    or description_col_idx != i + 2
                                ):
                                    description_col_idx = i + 2
                                break

            # Check if this is a continuation line (empty index and username columns)
            index_has_digit = any(
                segments[i].strip().isdigit() for i in range(min(3, len(segments)))
            )
            username_segment = (
                segments[username_col_idx].strip()
                if username_col_idx is not None and username_col_idx < len(segments)
                else ""
            )
            is_continuation = not index_has_digit and username_segment == ""

            # Sanitize username column (only on first line of row, not continuations)
            if (
                not is_continuation
                and username_col_idx is not None
                and username_col_idx < len(segments)
            ):
                username_segment = segments[username_col_idx].strip()
                if (
                    username_segment
                    and not username_segment.isdigit()
                    and not username_segment.startswith("[")
                ):
                    segments[username_col_idx] = _replace_table_cell(
                        segments[username_col_idx], "user"
                    )

            # Sanitize description column (on ALL lines, including continuations)
            # Process description column if we're in a table row
            if description_col_idx is not None:
                # Handle both continuation lines and regular lines
                # For continuation lines, description might be in a different position
                description_segment = None
                desc_seg_idx = description_col_idx

                # First try the expected description column index
                if desc_seg_idx < len(segments):
                    description_segment = segments[desc_seg_idx].strip()

                # If description column is empty (especially in continuation lines),
                # search for content in segments after the username column
                if not description_segment or description_segment == "":
                    # Look for non-empty segments after username column
                    search_start = max(username_col_idx + 1, description_col_idx)
                    for check_idx in range(search_start, len(segments)):
                        candidate = segments[check_idx].strip()
                        # Skip empty segments and border characters
                        if candidate and candidate not in (
                            "",
                            "│",
                            "┃",
                            "┌",
                            "┬",
                            "└",
                            "┴",
                            "├",
                            "┼",
                        ):
                            description_segment = candidate
                            desc_seg_idx = check_idx
                            break

                if description_segment:
                    # ALWAYS sanitize the entire description for privacy
                    # Descriptions may contain sensitive information even if not obviously passwords
                    # Replace the entire description with a length-preserving pseudonym
                    if desc_seg_idx < len(segments):
                        segments[desc_seg_idx] = _replace_table_cell(
                            segments[desc_seg_idx], "redacted"
                        )

            lines[idx] = "│".join(segments)

    return "\n".join(lines)


def _vercel_metadata_fields(metadata: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Return payload updates derived from optional metadata."""
    if not metadata:
        return {}
    command_type = metadata.get("command_type")
    metadata = _filter_workspace_context_metadata(metadata, command_type=command_type)
    updates: dict[str, Any] = {}
    lab_provider = metadata.get("lab_provider")
    lab_name = metadata.get("lab_name")
    lab_slug = metadata.get("lab_slug")
    lab_name_whitelisted = metadata.get("lab_name_whitelisted")
    workspace_type = normalize_workspace_type(metadata.get("workspace_type"))
    environment = metadata.get("environment")
    command_type = metadata.get("command_type")
    command_success = metadata.get("command_success")
    session_scope = metadata.get("session_scope")
    session_trace_id = metadata.get("session_trace_id")
    if environment:
        updates["environment"] = environment.lower()
    if command_type:
        updates["command_type"] = command_type.lower()
    if session_scope:
        updates["session_scope"] = str(session_scope).lower()
    if session_trace_id:
        updates["session_trace_id"] = str(session_trace_id)
        updates["trace_id"] = str(session_trace_id)
    if workspace_type:
        updates["workspace_type"] = workspace_type
    if command_success is not None:
        updates["command_success"] = bool(command_success)
    if lab_provider:
        updates["target_type"] = lab_provider.lower()
    elif workspace_type:
        # Keep legacy target_type populated even when no lab provider exists
        # (e.g., audit workspaces), so downstream filters remain explicit.
        updates["target_type"] = workspace_type
    if lab_name_whitelisted is not None:
        updates["target_whitelisted"] = bool(lab_name_whitelisted)
    preserve_public_lab_identity = bool(lab_name_whitelisted) is True
    if lab_name:
        normalized_lab_name = lab_name.lower()
        updates["target_name"] = (
            normalized_lab_name
            if preserve_public_lab_identity
            else _sanitize_string_for_telemetry(
                normalized_lab_name, field_name="target_name"
            )
        )
    if lab_slug:
        normalized_lab_slug = lab_slug.lower()
        updates["target_slug"] = (
            normalized_lab_slug
            if preserve_public_lab_identity
            else _sanitize_string_for_telemetry(
                normalized_lab_slug, field_name="target_slug"
            )
        )
    confirmation_state = metadata.get("lab_confirmation_state")
    if confirmation_state:
        updates["target_confirmation_state"] = str(confirmation_state)
    inference_source = metadata.get("lab_inference_source")
    inference_confidence = metadata.get("lab_inference_confidence")
    if inference_source:
        updates["target_inference_source"] = str(inference_source)
    if inference_confidence is not None:
        updates["target_inference_confidence"] = float(inference_confidence)
    compromise_status = normalize_session_compromise_status(
        metadata.get("compromise_status")
    )
    if compromise_status:
        updates["compromise_status"] = compromise_status
        updates["user_compromised"] = bool(
            metadata.get("user_compromised")
            if metadata.get("user_compromised") is not None
            else compromise_status in {"user", "domain"}
        )
        updates["domain_compromised"] = bool(
            metadata.get("domain_compromised")
            if metadata.get("domain_compromised") is not None
            else compromise_status == "domain"
        )
    compromised_users_count = metadata.get("compromised_users_count")
    if compromised_users_count is not None:
        try:
            updates["compromised_users_count"] = max(
                0, int(compromised_users_count)
            )
        except (TypeError, ValueError):
            pass
    return updates


def _vercel_timestamp_fields(
    started_at: Optional[datetime],
    finished_at: Optional[datetime],
) -> dict:
    """Return optional timestamp fields used for telemetry payloads."""
    timestamps: dict[str, str] = {}
    if started_at:
        timestamps["started_at"] = started_at.isoformat()
    if finished_at:
        timestamps["finished_at"] = finished_at.isoformat()
    return timestamps


def _vercel_version_field() -> dict:
    """Return normalized version context fields for Vercel session payloads."""
    version_fields = get_telemetry_version_fields()
    payload: dict[str, Any] = {}

    adscan_version = str(version_fields.get("adscan_version") or "").strip()
    if adscan_version:
        payload["adscan_version"] = adscan_version

    forward_keys = (
        "adscan_version_source",
        "launcher_version",
        "launcher_version_source",
        "runtime_version",
        "runtime_version_source",
        "runtime_image",
        "adscan_detected_installer",
        "version_context_mode",
    )
    for key in forward_keys:
        value = version_fields.get(key)
        if value is None or value == "":
            continue
        payload[key] = value
    return payload


def _vercel_session_url(api_url: str, session_id: str) -> str:
    """Build the public session URL from the API endpoint."""
    parsed = urlparse(api_url)
    return f"{parsed.scheme}://{parsed.netloc}/sessions/{session_id}"


def _summarize_vercel_payload_context(payload: dict[str, Any]) -> str:
    """Return a compact debug summary of the Vercel session payload context."""
    field_order = (
        "environment",
        "command_type",
        "session_scope",
        "session_trace_id",
        "trace_id",
        "workspace_type",
        "compromise_status",
        "user_compromised",
        "domain_compromised",
        "compromised_users_count",
        "target_type",
        "target_name",
        "target_slug",
        "target_whitelisted",
        "target_confirmation_state",
        "target_inference_source",
        "target_inference_confidence",
        "adscan_version",
        "adscan_version_source",
        "launcher_version",
        "launcher_version_source",
        "runtime_version",
        "runtime_version_source",
        "runtime_image",
        "adscan_detected_installer",
        "version_context_mode",
        "started_at",
        "finished_at",
    )
    parts: list[str] = []
    for field in field_order:
        value = payload.get(field)
        if value is None or value == "":
            continue
        parts.append(f"{field}={value!r}")
    if not parts:
        return "no-context-fields"
    return ", ".join(parts)


# Defaults for the gzipped upload path. The server-side hard limit
# is the Next.js bodyParser `sizeLimit: '10mb'` on the decompressed
# body — gzip on the wire shrinks transport cost but cannot raise
# that ceiling. We refuse to attempt an upload above
# ``_SESSION_MAX_HTML_BYTES`` and route the payload to the on-disk
# queue instead, where it survives until the next CLI invocation has
# more network luck (or never, if the session is genuinely too large).
# Margin under the 10 MB server cap to leave headroom for the JSON
# envelope keys, version fields, metadata, and timestamps.
_SESSION_MAX_HTML_BYTES: int = 9 * 1024 * 1024  # 9 MiB
# Below this size the network savings from gzip are marginal; above it
# the cost is dominated by the HTML blob, where gzip yields 8-12×.
# We compress unconditionally — the CPU cost is microseconds — but
# this constant is the line where the comment in the code points out
# the saving actually matters.
_SESSION_GZIP_THRESHOLD_BYTES: int = 4 * 1024  # 4 KiB

# Set to True by ``make_session_streamer`` once a SessionStreamer is
# started for the current process. A streamed session delivers its full
# recording incrementally via the chunk endpoint, so the legacy
# single-shot ``_send_session_to_vercel`` upload is only a redundant
# duplicate — and for a large (oversize) recording that single-shot path
# would enqueue a payload the drain discards, silently dropping the
# backstop. When this flag is set we let a streamed session rely on its
# chunks and never enqueue an oversize single-shot payload for discard.
_SESSION_STREAMING_ACTIVE: bool = False


def _session_streaming_active() -> bool:
    """Return True when a SessionStreamer is shipping chunks this run."""
    return _SESSION_STREAMING_ACTIVE


def _resolve_session_ingest_target() -> tuple[str | None, str]:
    """Return ``(url, label)`` for the active session ingest endpoint.

    Preference order (single source of truth so live uploads and queue
    drains pick the same target):

    1. ``get_vercel_sessions_direct_url()`` — direct POST to
       ``sessions.adscanpro.com/api/sessions``. New path. The server
       endpoint accepts ``X-CLI-Token`` natively, gzip is decompressed
       by Next.js bodyParser before its size check, and there is no
       intermediate JSON re-serialisation.
    2. ``get_vercel_sessions_proxy_url()`` — legacy n8n webhook. Kept
       for graceful fallback in case the direct URL is unset in the
       embedded config (kill-switch) or while the rollout cohort
       still includes 9.0.0 deployments.

    Returns ``(None, "no-target")`` when neither URL is configured —
    the caller treats that as "telemetry disabled by config".
    """
    direct = get_vercel_sessions_direct_url()
    if direct:
        return direct, "direct"
    proxy = get_vercel_sessions_proxy_url()
    if proxy:
        return proxy, "n8n-proxy"
    return None, "no-target"


# Bounded same-session retry for the session upload. The upload runs at
# session-END (often right after Ctrl+C), so the total backoff must stay small
# — exit must never feel slow. Three total attempts with 0.5s then 1.0s of
# backoff caps the added wall-clock at ~1.5s. A transient 5xx / connection blip
# succeeds on the first run; anything still failing after the cap falls through
# to the durable on-disk queue (retried next run).
_SESSION_UPLOAD_MAX_ATTEMPTS = 3
# One entry per gap between attempts (len == max_attempts - 1). Simple
# exponential with a hard cap so the summed budget stays ~1.5s.
_SESSION_UPLOAD_BACKOFF_SCHEDULE = (0.5, 1.0)


def _upload_session_payload(payload: dict[str, Any]) -> Optional[str]:
    """POST a fully-built session payload to the active ingest endpoint.

    Single source of truth for the wire format:

    * Body is JSON, then gzipped, then sent with
      ``Content-Encoding: gzip``. Next.js bodyParser decompresses
      transparently before applying its 10 MB size limit. On the
      direct path the request never touches n8n; on the fallback
      proxy path n8n needs the Code-node decompression patch to read
      the body (kept available behind ``get_vercel_sessions_proxy_url``
      until the rollout is complete).
    * Plain JSON fallback (no gzip) is used as defence-in-depth if the
      compression step itself fails — that path keeps behaviour identical
      to the legacy uploader.
    * On success returns the session viewer URL (``sessions.adscanpro.com/sessions/<id>``).
    * On failure returns ``None``; the caller decides whether to enqueue
      for retry.

    Used both by the live ``_send_session_to_vercel`` and by the
    background drain in ``telemetry_queue`` — same wire shape both ways.
    """
    target_url, target_label = _resolve_session_ingest_target()
    token = get_cli_shared_token()
    if not target_url or not token:
        return None

    session_id = str(payload.get("session_id") or "")

    headers: dict[str, str] = {
        "X-CLI-Token": token,
        "Content-Type": "application/json",
    }

    body_json = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request_body: bytes | str
    try:
        request_body = gzip.compress(body_json)
        headers["Content-Encoding"] = "gzip"
        # ``Content-Length`` is set by ``requests`` automatically; we
        # rely on that rather than pre-computing it.
    except (OSError, OverflowError):
        # Compression should never fail for in-memory bytes but guard
        # defensively — fall back to uncompressed JSON.
        request_body = body_json

    _configure_ssl_certificates_for_requests()
    print_info_debug(
        f"[telemetry] sessions ingest target={target_label} url={target_url}"
    )

    # Retry ONLY transient failures (server 5xx, connection errors, timeouts).
    # A 4xx is a client/payload error that will not improve on retry, so it
    # fails fast (no sleeps). Idempotency: the payload carries a
    # ``session_trace_id`` and the server dedups by it, so a retry after a
    # timeout that actually landed is a low-harm double-insert (telemetry is
    # non-transactional) — no client-side dedup needed.
    for attempt in range(1, _SESSION_UPLOAD_MAX_ATTEMPTS + 1):
        try:
            response = requests.post(
                target_url,
                data=request_body,
                headers=headers,
                timeout=10,
            )
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            # Retryable transport failure.
            print_warning_debug(
                f"Failed to send session via {target_label} ingest "
                f"(attempt {attempt}/{_SESSION_UPLOAD_MAX_ATTEMPTS}): {e}"
            )
            print_info_debug(
                f"Session ingest error details: {type(e).__name__} - {str(e)}"
            )
            if attempt < _SESSION_UPLOAD_MAX_ATTEMPTS:
                time.sleep(_SESSION_UPLOAD_BACKOFF_SCHEDULE[attempt - 1])
                continue
            return None
        except requests.exceptions.RequestException as e:
            # Non-retryable transport failure — give up immediately.
            print_warning_debug(
                f"Failed to send session via {target_label} ingest: {e}"
            )
            print_info_debug(
                f"Session ingest error details: {type(e).__name__} - {str(e)}"
            )
            return None

        print_info_debug(
            f"Session ingest ({target_label}) response status: {response.status_code}"
        )

        if response.status_code >= 500:
            # Retryable server error.
            print_warning_debug(
                f"Session ingest ({target_label}) server error "
                f"(attempt {attempt}/{_SESSION_UPLOAD_MAX_ATTEMPTS}): "
                f"status {response.status_code}"
            )
            if attempt < _SESSION_UPLOAD_MAX_ATTEMPTS:
                time.sleep(_SESSION_UPLOAD_BACKOFF_SCHEDULE[attempt - 1])
                continue
            return None

        try:
            # 4xx raises here → non-retryable, caller enqueues to the queue.
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            print_warning_debug(f"Session ingest ({target_label}) HTTP error: {e}")
            return None

        try:
            result = response.json()
            stored_session_id = result.get("session_id") or session_id
            session_url = result.get("session_url") or (
                f"https://sessions.adscanpro.com/sessions/{stored_session_id}"
            )
            return session_url
        except (ValueError, json.JSONDecodeError):
            if response.status_code in (200, 201) and session_id:
                return f"https://sessions.adscanpro.com/sessions/{session_id}"
            return None

    # Loop exhausted without a decisive result (defensive; the branches above
    # always return). Caller enqueues to the durable queue.
    return None


def _send_session_to_vercel(
    session_id: str,
    html_content: str,
    metadata: Optional[dict[str, Any]] = None,
    started_at: Optional[datetime] = None,
    finished_at: Optional[datetime] = None,
) -> Optional[str]:
    """Send terminal session recording to Vercel API via n8n proxy.

    Four-step pipeline (each step degrades gracefully into the next):

    1. Build the canonical session payload.
    2. If the HTML body exceeds the server's decompressed-body limit,
       short-circuit and enqueue for later retry — uploading would only
       waste bandwidth on a guaranteed-413 response.
    3. Attempt the live upload (gzipped via ``_upload_session_payload``).
    4. On any failure mode, enqueue the same payload to the on-disk queue
       so the next CLI invocation can retry without operator action.

    Returns the viewer URL on success, ``None`` if the session was
    enqueued for later or could not be delivered at all.
    """
    target_url, target_label = _resolve_session_ingest_target()
    token = get_cli_shared_token()

    if not target_url or not token:
        print_info_debug(
            "Skipping Vercel session storage: "
            f"no ingest target configured (label={target_label}) or missing token"
        )
        return None

    try:
        payload: dict[str, Any] = {
            "session_id": session_id,
            "user_id_hash": TELEMETRY_ID,
            "html": html_content,
        }
        if PARTNER_TAG:
            payload["partner_tag"] = PARTNER_TAG
        payload.update(_vercel_version_field())
        # _vercel_metadata_fields() already applies the privacy policy for
        # lab/session context. Do not re-sanitize here or we will destroy the
        # distinction between public whitelisted labs and custom/internal labs.
        payload.update(_vercel_metadata_fields(metadata))
        payload.update(_vercel_timestamp_fields(started_at, finished_at))

        html_size = len(html_content)
        print_info_debug(f"Payload size: HTML={html_size} bytes")
        print_info_debug(
            f"Vercel payload context: {_summarize_vercel_payload_context(payload)}",
        )

        # Skip-too-big: refuse to POST when the HTML alone exceeds the
        # server's decompressed-body cap. Enqueue so the session is not
        # silently lost — an operator can inspect the file in
        # ``~/.adscan/telemetry-queue/`` and decide whether to bisect
        # the recording or just accept the loss.
        if html_size > _SESSION_MAX_HTML_BYTES:
            if _session_streaming_active():
                # A streamed session already delivered the full recording
                # incrementally through the chunk endpoint (each chunk is
                # small, well under the ceiling). Enqueuing the oversize
                # single-shot payload here would only get discarded by the
                # drain — dropping a backstop that is not needed. Rely on
                # the chunks; do not enqueue for discard.
                print_info_debug(
                    f"Session HTML exceeds single-shot ceiling "
                    f"({html_size} > {_SESSION_MAX_HTML_BYTES} bytes) but the "
                    "session was streamed; relying on delivered chunks, "
                    "skipping the legacy single-shot backstop."
                )
                return None
            print_warning_debug(
                f"Session HTML exceeds upload ceiling "
                f"({html_size} > {_SESSION_MAX_HTML_BYTES} bytes); "
                "enqueued for offline review."
            )
            _enqueue_oversize_session(payload, html_size=html_size)
            return None

        session_url = _upload_session_payload(payload)
        if session_url is not None:
            return session_url

        # Upload failed for some recoverable reason (network blip, proxy
        # 5xx, n8n hiccup). Enqueue so the next CLI run retries.
        _enqueue_failed_session(payload, reason="upload_failed")
        return None

    except (ValueError, TypeError, AttributeError, OSError) as exc:
        print_warning_debug(f"Unexpected error preparing session payload: {exc}")
        print_info_debug(f"Payload preparation error: {type(exc).__name__} - {exc}")
        return None


def _enqueue_failed_session(payload: dict[str, Any], *, reason: str) -> None:
    """Persist a failed upload to the local queue for next-run retry."""
    try:
        from adscan_core import telemetry_queue
    except ImportError:
        # Queue module unavailable (extremely unlikely) — accept the loss.
        return
    queued_path = telemetry_queue.enqueue_session(payload)
    if queued_path is not None:
        print_info_debug(
            f"(telemetry-queue) enqueued failed session "
            f"reason={reason} path={queued_path}"
        )


def _enqueue_oversize_session(payload: dict[str, Any], *, html_size: int) -> None:
    """Persist an oversize session that cannot be POSTed live.

    Same disk path as a failed upload, but tagged so a future drain can
    decide to skip these unless the server cap is raised.
    """
    try:
        from adscan_core import telemetry_queue
    except ImportError:
        return
    payload = dict(payload)  # shallow copy so we don't mutate caller
    payload["_oversize_html_bytes"] = int(html_size)
    queued_path = telemetry_queue.enqueue_session(payload)
    if queued_path is not None:
        print_info_debug(
            f"(telemetry-queue) enqueued oversize session "
            f"html_bytes={html_size} path={queued_path}"
        )


def _drain_queue_upload_fn(payload: dict[str, Any]) -> bool:
    """Bridge between the disk queue and the wire uploader.

    Routes each queued payload to the endpoint that matches how it was
    captured — the queue mixes two payload shapes and sending one to the
    other's endpoint loses the session:

    * ``_chunk_trace_id``-tagged → a retried streaming chunk. Route it
      back to the per-trace chunk endpoint (``_upload_chunk``). The
      legacy ``/api/sessions`` single-shot endpoint requires an ``html``
      field and 400-rejects a chunk payload, so a chunk sent there is
      lost and the server never assembles the final recording. This is
      the fix for long-audit ``sessions.html`` staying empty when the
      final ``is_final`` chunk was retried.
    * ``_oversize_html_bytes``-tagged → a legacy single-shot payload that
      was too big for the server body cap when captured. A STREAMED
      session never enqueues one of these (its chunks are the delivery
      path), so any oversize payload on disk is from a non-streamed
      session that genuinely cannot be delivered single-shot; the cap has
      not changed since enqueue. Return True so ``drain_queue`` deletes
      it rather than retrying forever.
    * Everything else → a normal legacy single-shot session payload.
    """
    chunk_trace_id = payload.get("_chunk_trace_id")
    if chunk_trace_id:
        # Strip client-only routing markers so the chunk endpoint sees the
        # exact wire shape the live streamer sends.
        chunk_payload = {
            key: value
            for key, value in payload.items()
            if key != "_chunk_trace_id"
        }
        ok = _upload_chunk(str(chunk_trace_id), chunk_payload)
        if ok:
            print_info_debug(
                "(telemetry-queue) re-delivered streaming chunk "
                f"trace={chunk_trace_id} seq={payload.get('seq')}"
            )
        return ok
    if payload.get("_oversize_html_bytes"):
        print_info_debug(
            "(telemetry-queue) discarding oversize queued session "
            f"(html_bytes={payload.get('_oversize_html_bytes')!s}); "
            "server body cap has not changed."
        )
        return True
    return _upload_session_payload(payload) is not None


def start_telemetry_queue_drain() -> None:
    """Kick off a background drain of the on-disk telemetry queue.

    Idempotent — safe to call multiple times per process (subsequent
    calls just spawn a new daemon thread that finds an empty queue and
    exits). Designed to be invoked once during early CLI startup, after
    logging is initialised but before the first user-visible output, so
    a failed delivery from a previous run gets retried without delaying
    the foreground command.
    """
    if not _is_telemetry_enabled():
        return
    try:
        from adscan_core import telemetry_queue
    except ImportError:
        return
    try:
        telemetry_queue.start_background_drain(_drain_queue_upload_fn)
    except Exception as exc:  # noqa: BLE001
        # Background drain is best-effort: any startup error must never
        # bubble into the foreground CLI.
        print_info_debug(
            f"(telemetry-queue) background drain failed to start: "
            f"{type(exc).__name__}: {exc}"
        )


# ─────────────────────────────────────────────────────────────────────
# Tier 2 — chunked streaming uploads
# ─────────────────────────────────────────────────────────────────────


def compute_workspace_id_hash(workspace_name: Optional[str]) -> Optional[str]:
    """Return the stable 12-char workspace identifier for telemetry.

    Mirrors the algorithm used by PostHog event capture in
    ``adscan_internal/cli/common.py``: ``sha256(TELEMETRY_ID + ':' +
    workspace_name)[:12]``. Same workspace under the same user always
    yields the same hash, across sessions, without ever exposing the
    raw workspace name to the dashboard's identity column.

    Returns ``None`` for empty workspace names so callers can include
    the field unconditionally without populating a misleading hash on
    rows that have no workspace context.
    """
    if not workspace_name:
        return None
    raw = f"{TELEMETRY_ID}:{workspace_name}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


def _chunk_endpoint_url(trace_id: str) -> Optional[str]:
    """Return the per-trace chunk endpoint URL, or ``None`` if disabled.

    Built from the direct sessions URL — Tier 2 only runs on the
    direct path; it doesn't go through n8n. If only the proxy URL is
    embedded (kill-switch), the streamer is silently disabled.
    """
    direct = get_vercel_sessions_direct_url()
    if not direct:
        return None
    base = direct.rstrip("/")
    # ``direct`` is ``https://sessions.adscanpro.com/api/sessions``;
    # the chunk endpoint lives at ``/api/sessions/<trace_id>/chunk``.
    safe = "".join(ch for ch in trace_id if ch.isalnum() or ch in "._:-")[:128]
    if not safe:
        return None
    return f"{base}/{safe}/chunk"


def _upload_chunk(trace_id: str, payload: dict[str, Any]) -> bool:
    """POST a single chunk to ``/api/sessions/<trace_id>/chunk``.

    Returns ``True`` on 2xx, ``False`` on any error. Mirrors the
    transport contract of ``_upload_session_payload`` (gzip + JSON +
    X-CLI-Token) so the server's ingest pipeline handles both
    interchangeably.
    """
    endpoint = _chunk_endpoint_url(trace_id)
    token = get_cli_shared_token()
    if not endpoint or not token:
        return False
    headers: dict[str, str] = {
        "X-CLI-Token": token,
        "Content-Type": "application/json",
    }
    body_json = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request_body: bytes | str
    try:
        request_body = gzip.compress(body_json)
        headers["Content-Encoding"] = "gzip"
    except (OSError, OverflowError):
        request_body = body_json

    _configure_ssl_certificates_for_requests()
    try:
        response = requests.post(
            endpoint,
            data=request_body,
            headers=headers,
            timeout=10,
        )
    except requests.exceptions.RequestException as exc:
        print_info_debug(
            f"(telemetry-streamer) chunk upload failed: "
            f"trace={trace_id} seq={payload.get('seq')} error={exc}"
        )
        return False
    if response.status_code in (200, 201, 202):
        return True
    print_info_debug(
        f"(telemetry-streamer) chunk upload non-2xx: "
        f"trace={trace_id} seq={payload.get('seq')} status={response.status_code}"
    )
    return False


def _enqueue_chunk_failure(trace_id: str, payload: dict[str, Any]) -> None:
    """Persist a failed chunk for next-run drain. Reuses Tier 1 queue.

    Tags the payload with ``_chunk_trace_id`` so ``_drain_queue_upload_fn``
    routes it back to the per-trace chunk endpoint (``_upload_chunk``)
    instead of the legacy single-shot ``/api/sessions`` endpoint — which
    requires an ``html`` field and 400-rejects a chunk payload, losing the
    chunk (and, for the final ``is_final`` chunk, the whole assembled
    recording). The chunk wire payload itself carries no ``trace_id`` (the
    live path passes it in the URL, not the body), so it is captured here
    from the streamer closure.
    """
    try:
        from adscan_core import telemetry_queue
    except ImportError:
        return
    tagged = dict(payload)
    tagged["_chunk_trace_id"] = str(trace_id)
    queued = telemetry_queue.enqueue_session(tagged)
    if queued is not None:
        print_info_debug(
            f"(telemetry-streamer) enqueued failed chunk "
            f"trace={trace_id} seq={payload.get('seq')} path={queued}"
        )


def make_session_streamer(
    *,
    trace_id: str,
    user_id_hash: str,
    command_type: str,
    session_scope: str,
    environment: str,
    started_at: datetime,
    export_html_fn: Callable[[], str],
    version_payload_fn: Callable[[], dict[str, Any]],
) -> Optional[Any]:
    """Build and return a started SessionStreamer, or ``None`` when
    streaming is not applicable (telemetry disabled, command not in
    the stream-eligible set, direct sessions URL missing, etc.).

    The caller is responsible for emitting lifecycle events
    (``scan_started`` / ``scan_finished``) at the right hook points
    and calling ``streamer.finalise(...)`` exactly once on session
    exit.
    """
    try:
        from adscan_core.telemetry_streamer import (
            SessionStreamer,
            StreamerConfig,
            should_stream_for_command,
        )
    except ImportError as exc:
        print_info_debug(
            f"(telemetry-streamer) skipped: streamer module import failed ({exc})"
        )
        return None

    # Single-source diagnostic — every eligibility gate emits the same
    # ``(telemetry-streamer) skipped: <reason>`` line so ``--debug``
    # always shows exactly why streaming did not start (instead of
    # the previous silent ``return None`` cascade).
    if not _is_telemetry_enabled():
        print_info_debug(
            "(telemetry-streamer) skipped: telemetry disabled "
            "(ADSCAN_TELEMETRY/_is_telemetry_enabled)"
        )
        return None
    if not _is_session_capture_enabled():
        print_info_debug(
            "(telemetry-streamer) skipped: session capture disabled"
        )
        return None
    if not should_stream_for_command(command_type):
        print_info_debug(
            f"(telemetry-streamer) skipped: command_type={command_type!r} "
            "not in stream-eligible set (start/ci/tui)"
        )
        return None
    if not _chunk_endpoint_url(trace_id):
        print_info_debug(
            "(telemetry-streamer) skipped: no direct chunk endpoint URL "
            "(get_vercel_sessions_direct_url returned empty — embedded "
            "telemetry config missing 'vd' key, or build stripped it)"
        )
        return None
    if not get_cli_shared_token():
        print_info_debug(
            "(telemetry-streamer) skipped: CLI shared token unavailable "
            "(get_cli_shared_token returned empty — embedded config "
            "missing CLI_SHARED_TOKEN)"
        )
        return None

    config = StreamerConfig(
        trace_id=trace_id,
        user_id_hash=user_id_hash,
        command_type=command_type,
        session_scope=session_scope,
        environment=environment,
        started_at=started_at,
        upload_fn=lambda payload: _upload_chunk(trace_id, payload),
        enqueue_fn=lambda payload: _enqueue_chunk_failure(trace_id, payload),
        sanitize_fn=_sanitize_rich_output,
        export_html_fn=export_html_fn,
        version_payload_fn=version_payload_fn,
    )
    streamer = SessionStreamer(config)
    streamer.start()
    global _SESSION_STREAMING_ACTIVE
    _SESSION_STREAMING_ACTIVE = True
    print_info_debug(
        f"(telemetry-streamer) started: trace={trace_id} command={command_type}"
    )
    return streamer


def _build_session_metadata(shell=None) -> Optional[dict]:
    """Build session metadata from shell workspace context.

    Args:
        shell: Optional shell object with workspace context (lab_provider, lab_name, etc.)

    Returns:
        Metadata dictionary with lab information, or None if no metadata available
    """
    if not shell:
        return None

    metadata = build_workspace_telemetry_fields(
        workspace_type=getattr(shell, "type", None),
    )
    metadata.update(
        build_lab_telemetry_fields(
            lab_provider=getattr(shell, "lab_provider", None),
            lab_name=getattr(shell, "lab_name", None),
            lab_name_whitelisted=getattr(shell, "lab_name_whitelisted", None),
            include_slug=False,
        )
    )

    # Build lab_slug using shell helper method (reuses existing logic)
    lab_slug_getter = getattr(shell, "_get_lab_slug", None)
    lab_slug: str | None = None
    if callable(lab_slug_getter):
        # pylint: disable=not-callable
        lab_slug = lab_slug_getter()
    if not lab_slug:
        lab_slug = build_lab_slug(
            getattr(shell, "lab_provider", None),
            getattr(shell, "lab_name", None),
            getattr(shell, "lab_name_whitelisted", None),
        )
    if lab_slug:
        metadata["lab_slug"] = str(lab_slug).lower()

    # Inference metadata: which rule identified the lab and with what confidence.
    inference_source = getattr(shell, "lab_inference_source", None)
    inference_confidence = getattr(shell, "lab_inference_confidence", None)
    if inference_source:
        metadata["lab_inference_source"] = str(inference_source)
    if inference_confidence is not None:
        metadata["lab_inference_confidence"] = float(inference_confidence)
    confirmation_state = getattr(shell, "lab_confirmation_state", None)
    if confirmation_state:
        metadata["lab_confirmation_state"] = str(confirmation_state)
    metadata.update(build_session_compromise_metadata(shell))
    # Anonymous AD-scale fingerprint (counts only, no domain/principal names) so
    # the session viewer can filter/sort by environment scale (multi-domain,
    # host/user counts). Reads the cheap in-memory ``collection_stats``.
    metadata.update(build_session_ad_scale_metadata(shell))

    # Workspace identity — privacy hard rule:
    #
    # The raw workspace name (e.g. "Active", "essos.local",
    # "acme-corp-prod") is **customer-sensitive** and MUST NEVER leave
    # the host. We only transmit ``workspace_id_hash`` — the same
    # anonymised 12-char SHA-256 derivative PostHog uses
    # (``sha256(TELEMETRY_ID + ":" + workspace_name)[:12]``).
    #
    # The hash is stable across sessions for the same operator, so the
    # dashboard can still group "all sessions in workspace X" without
    # ever knowing what X is named. The operator recognises their own
    # hashes from the CLI banner; an outsider sees only opaque ids.
    current_workspace = getattr(shell, "current_workspace", None)
    if current_workspace:
        ws_hash = compute_workspace_id_hash(current_workspace)
        if ws_hash:
            metadata["workspace_id_hash"] = ws_hash

    return metadata or None


def capture_session_end(console=None, metadata: Optional[dict] = None):
    """Capture session end, export Rich recording, and send to telemetry.

    If a Rich Console with recording enabled is provided, exports the session
    recording (HTML/text), sanitizes it, sends to Vercel API (or n8n as fallback)
    for storage, and captures metadata in PostHog.

    Args:
        console: Optional Rich Console instance with recording enabled.
                 If None, only captures session end metadata.
        metadata: Optional metadata dictionary with keys:
            - workspace_type: Workspace type ("ctf" or "audit")
            - lab_name: Lab name (e.g., "Forest") - will be hashed for privacy
            - lab_slug: Lab slug (e.g., "htb/forest")
            - lab_provider: Lab provider (e.g., "hackthebox") - maps to target_type
    """
    telemetry_allowed = _is_telemetry_enabled()
    session_capture_allowed = _is_session_capture_enabled()
    if not telemetry_allowed and not session_capture_allowed:
        return

    try:
        finished_at = datetime.now(timezone.utc)
        # Use a monotonic clock for duration to avoid negative or inflated
        # values when the system clock is adjusted during a session.
        duration_seconds = max(0.0, time.monotonic() - _session_start_monotonic)
        duration = duration_seconds / 60.0
        # Derive a synthetic started_at timestamp from the monotonic duration
        # so that Vercel's duration (finished_at - started_at) matches the
        # monotonic measurement even if the system clock changed.
        effective_started_at = finished_at - timedelta(seconds=duration_seconds)
        session_id = f"{TELEMETRY_ID}_{int(finished_at.timestamp())}"
        metadata_with_env = _enrich_session_metadata_context(metadata)

        # Prefer an explicit environment passed by the caller (e.g., host launcher
        # passing its environment into the container). This prevents dev/ci runs
        # from polluting production telemetry when running inside Docker.
        explicit_env = metadata_with_env.get("environment")
        session_env: str
        ci_detected = _is_ci_environment()
        if ci_detected:
            session_env = "ci"
        elif explicit_env:
            normalized = str(explicit_env).strip().lower()
            candidate = re.sub(r"[^a-z0-9_-]+", "", normalized)
            if not candidate:
                session_env = _determine_session_environment()
            else:
                # Never allow a known dev machine to claim production telemetry.
                dev_detected = _is_dev_machine_by_id()
                session_env = (
                    "dev" if dev_detected and candidate == "prod" else candidate
                )
        else:
            session_env = _determine_session_environment()

        # Always include the selected environment in metadata. Some downstream
        # session backends default to PROD if this field is missing.
        metadata_with_env["environment"] = session_env

        metadata_with_env = _filter_workspace_context_metadata(
            metadata_with_env, command_type=metadata_with_env.get("command_type")
        )

        print_info_debug(
            "[DEBUG] capture_session_end environment selection: "
            f"explicit_env={explicit_env!r}, ci_detected={ci_detected}, "
            f"selected={session_env!r}"
        )

        command_type = None
        if metadata_with_env:
            command_type = metadata_with_env.get("command_type")
        session_scope = metadata_with_env.get("session_scope")
        sanitize_session = _should_sanitize_session_recording(
            command_type, session_scope
        )
        print_info_debug(
            "[DEBUG] capture_session_end metadata summary: "
            f"command_type={metadata_with_env.get('command_type')!r}, "
            f"session_scope={metadata_with_env.get('session_scope')!r}, "
            f"session_trace_id={metadata_with_env.get('session_trace_id')!r}, "
            f"sanitize_session={sanitize_session!r}, "
            f"workspace_type={metadata_with_env.get('workspace_type')!r}, "
            f"lab_provider={metadata_with_env.get('lab_provider')!r}, "
            f"lab_name={metadata_with_env.get('lab_name')!r}, "
            f"lab_slug={metadata_with_env.get('lab_slug')!r}, "
            f"lab_name_whitelisted={metadata_with_env.get('lab_name_whitelisted')!r}, "
            f"lab_confirmation_state={metadata_with_env.get('lab_confirmation_state')!r}"
        )

        # Export and send Rich recording if console is provided
        session_url = None
        if (
            session_capture_allowed
            and console is not None
            and hasattr(console, "export_html")
        ):
            try:
                # Import debug functions (already imported at module level, but keeping for clarity)
                # from adscan_internal.rich_output import print_info_debug, print_warning_debug

                print_info_debug("Exporting Rich console recording...")

                # DIAGNOSTIC: Check console state before exporting
                # COMMENTED: Not directly related to module re-execution tracking
                # console_id = id(console) if console else None
                # buffer_length = None
                # if console and hasattr(console, 'file'):
                #     try:
                #         file_obj = console.file
                #         if hasattr(file_obj, 'getvalue'):
                #             buffer_length = len(file_obj.getvalue())
                #     except Exception:
                #         pass
                #
                # print_info_debug(
                #     f"[TELEMETRY_DIAG] capture_session_end: "
                #     f"console_id={console_id}, "
                #     f"buffer_length={buffer_length}, "
                #     f"console_has_export={hasattr(console, 'export_html') if console else False}"
                # )

                # Export Rich recording
                html_content = console.export_html()
                text_content = console.export_text()

                # DIAGNOSTIC: Check exported content size
                # COMMENTED: Not directly related to module re-execution tracking
                # print_info_debug(
                #     f"[TELEMETRY_DIAG] capture_session_end exported: "
                #     f"html_size={len(html_content)}, "
                #     f"text_size={len(text_content)}"
                # )

                print_info_debug(
                    f"Exported recording: HTML={len(html_content)} bytes, "
                    f"Text={len(text_content)} bytes",
                )

                try:
                    # Session recordings are always sanitized before any outbound upload.
                    sanitized_html = _maybe_sanitize_rich_output(
                        html_content, sanitize=sanitize_session
                    )
                    sanitized_text = _maybe_sanitize_rich_output(
                        text_content, sanitize=sanitize_session
                    )
                except Exception as exc:  # noqa: BLE001
                    print_warning_debug(
                        f"Failed to sanitize session recording before upload: {exc}"
                    )
                    sanitized_html = None
                    sanitized_text = None

                if not isinstance(sanitized_html, str) or not isinstance(
                    sanitized_text, str
                ):
                    print_warning_debug(
                        "Skipping session upload because sanitized recording output "
                        "was invalid."
                    )
                    sanitized_html = None
                    sanitized_text = None

                if sanitized_html is not None and sanitized_text is not None:
                    print_info_debug(
                        f"Sanitized recording: HTML={len(sanitized_html)} bytes, "
                        f"Text={len(sanitized_text)} bytes",
                    )

                    # Try Vercel API first (new, preferred)
                    session_url = _send_session_to_vercel(
                        session_id,
                        sanitized_html,
                        metadata=metadata_with_env,
                        started_at=effective_started_at,
                        finished_at=finished_at,
                    )

            except (ValueError, RuntimeError, AttributeError) as e:
                # Import debug functions (already imported at module level, but keeping for clarity)
                # from adscan_internal.rich_output import print_warning_debug, print_info_debug
                print_warning_debug(f"Failed to export/send Rich recording: {e}")
                print_info_debug(f"Export error details: {type(e).__name__} - {str(e)}")

        # Capture session end metadata in PostHog
        if telemetry_allowed and _telemetry_client:
            properties = {
                "duration_minutes": round(duration, 2),
                "session_id": session_id,
                "environment": session_env,
            }
            command_type = metadata_with_env.get("command_type")
            if command_type:
                properties["command_type"] = str(command_type).lower()
            session_scope = metadata_with_env.get("session_scope")
            if session_scope:
                properties["session_scope"] = str(session_scope).lower()
            session_trace_id = metadata_with_env.get("session_trace_id")
            if session_trace_id:
                properties["session_trace_id"] = str(session_trace_id)
                properties["trace_id"] = str(session_trace_id)
            compromise_status = normalize_session_compromise_status(
                metadata_with_env.get("compromise_status")
            )
            properties["compromise_status"] = compromise_status
            properties["user_compromised"] = bool(
                metadata_with_env.get("user_compromised")
                if metadata_with_env.get("user_compromised") is not None
                else compromise_status in {"user", "domain"}
            )
            properties["domain_compromised"] = bool(
                metadata_with_env.get("domain_compromised")
                if metadata_with_env.get("domain_compromised") is not None
                else compromise_status == "domain"
            )
            compromised_users_count = metadata_with_env.get("compromised_users_count")
            if compromised_users_count is not None:
                try:
                    properties["compromised_users_count"] = max(
                        0, int(compromised_users_count)
                    )
                except (TypeError, ValueError):
                    pass
            if session_url:
                properties["session_url"] = session_url
                # Keep legacy key for backward compatibility
                properties["n8n_session_url"] = session_url

            capture("session_end", properties)
    except (RuntimeError, ValueError, OSError, AttributeError) as exc:
        print_warning_debug(f"Failed to capture session end: {exc}")


def identify_user(properties: dict):
    """Associate a distinct telemetry user with custom properties via n8n proxy.

    Only sends data when telemetry is explicitly enabled.
    """
    # IMPORTANT: Never send data when telemetry is disabled
    if not _is_telemetry_enabled():
        return

    # Include normalized version context for downstream segmentation.
    version_fields = get_telemetry_version_fields()
    properties["version"] = str(
        version_fields.get("adscan_version") or get_installed_version()
    )
    for key, value in version_fields.items():
        if key == "adscan_version":
            continue
        if value is None or value == "":
            continue
        properties.setdefault(key, value)
    properties = _sanitize_telemetry_properties(properties)

    if _telemetry_client:
        try:
            # Get appropriate proxy URL for current environment
            proxy_url = _get_posthog_proxy_url()
            if not proxy_url:
                print_error_debug("PostHog proxy URL not configured")
                return

            token = get_cli_shared_token()
            if not token:
                print_error_debug(
                    "Telemetry ingest token not configured; cannot identify user"
                )
                return

            # Send identify request to n8n proxy (mimics PostHog identify API)
            payload = {
                "distinct_id": TELEMETRY_ID,
                "properties": properties,
            }

            # Configure SSL certificates before making request
            _configure_ssl_certificates_for_requests()

            response = requests.post(
                f"{proxy_url}/identify",
                json=payload,
                headers={
                    "X-CLI-Token": token,
                    "Content-Type": "application/json",
                },
                timeout=5,
            )
            response.raise_for_status()
        except (requests.exceptions.RequestException, ValueError, TypeError) as exc:
            print_warning_debug(f"Failed to identify telemetry user: {exc}")


def sanitize_exc(e: Exception):
    """Return a sanitized representation of an exception stack."""
    exc_type = type(e).__name__
    try:
        msg = _sanitize_rich_output(str(e))[:120]
    except Exception:
        msg = str(e)[:120]
    tb = traceback.extract_tb(e.__traceback__)
    # Original top frame (often library code)
    original_top = f"{Path(tb[-1].filename).name}:{tb[-1].lineno}" if tb else "n/a"
    # Signature based on exception type and original top frame
    stack_sig = hashlib.sha256(f"{exc_type}:{original_top}".encode()).hexdigest()[:12]
    # Identify first frame within project directory
    project_root = os.path.dirname(os.path.abspath(__file__))
    user_frame = next(
        (
            frame
            for frame in reversed(tb)
            if os.path.abspath(frame.filename).startswith(project_root)
        ),
        None,
    )
    user_top = (
        f"{Path(user_frame.filename).name}:{user_frame.lineno}"
        if user_frame
        else original_top
    )
    return {
        "exception_type": exc_type,
        "exception_msg": msg,
        "stack_top": original_top,
        "user_stack_top": user_top,
        "signature": stack_sig,
    }


def capture_installation_failed(e: Exception):
    """Capture an installation failure in telemetry."""
    capture_exception(e, {"$set": {"installation_status": "failed"}})


def capture_exception(e: Exception, properties: Optional[dict[str, Any]] = None):
    """Capture an exception in both Sentry and PostHog via n8n proxies when telemetry is enabled."""
    # Send exception to Sentry (via n8n proxy using custom transport)
    if _is_telemetry_enabled():
        try:
            sentry_sdk.capture_exception(e)
        except (ValueError, TypeError, OSError) as exc:
            # OSError can occur with SSL certificate issues
            print_warning_debug(f"Failed to capture exception in Sentry: {exc}")

    # Send exception to PostHog via n8n proxy
    if _telemetry_client and _is_telemetry_enabled():
        try:
            # Get appropriate proxy URL for current environment
            proxy_url = _get_posthog_proxy_url()
            if not proxy_url:
                print_error_debug("PostHog proxy URL not configured")
                return

            token = get_cli_shared_token()
            if not token:
                print_error_debug(
                    "Telemetry ingest token not configured; cannot capture exception"
                )
                return

            exc_type = type(e).__name__
            exc_summary = sanitize_exc(e)
            raw_message = str(e)
            try:
                exc_message = _sanitize_rich_output(raw_message)
            except Exception:
                exc_message = raw_message

            # PostHog's error tracking expects a `$exception_list` field when
            # using the special `$exception` event name. Populate it with a
            # minimal, non-sensitive description of the exception.
            capture_props = {
                "version": str(
                    get_telemetry_version_fields().get("adscan_version")
                    or get_installed_version()
                ),
                "downloaded_source": DOWNLOAD_SOURCE,
                "exception_type": exc_type,
                "exception_message": exc_message[:200],
                "exception_signature": exc_summary.get("signature"),
                "stack_top": exc_summary.get("stack_top"),
                "user_stack_top": exc_summary.get("user_stack_top"),
                "$exception_list": [
                    {
                        "type": exc_type,
                        "value": exc_message[:500],
                    }
                ],
            }
            for key, value in get_telemetry_version_fields().items():
                if key == "adscan_version":
                    continue
                if value is None or value == "":
                    continue
                capture_props[key] = value
            if properties:
                capture_props.update(properties)
            capture_props = _sanitize_telemetry_properties(capture_props)

            # Send exception as a special event to PostHog via n8n
            payload = {
                "event": "$exception",
                "distinct_id": TELEMETRY_ID,
                "properties": capture_props,
            }

            # Configure SSL certificates before making request
            _configure_ssl_certificates_for_requests()

            response = requests.post(
                proxy_url,
                json=payload,
                headers={
                    "X-CLI-Token": token,
                    "Content-Type": "application/json",
                },
                timeout=5,
            )
            response.raise_for_status()
            # print_info(f"Exception captured: {e}, {TELEMETRY_ID}, {properties}")
        except (
            requests.exceptions.RequestException,
            ValueError,
            TypeError,
            OSError,  # SSL certificate errors (e.g., "Could not find a suitable TLS CA certificate bundle")
        ) as exc:
            # Silently handle telemetry failures - don't let telemetry errors break the main flow
            print_warning_debug(f"Failed to capture exception in PostHog: {exc}")


def _load_local_user_properties_cache() -> dict[str, Any]:
    """Load locally cached user properties used for telemetry deduplication."""
    state = _load_last_telemetry_state()
    cached = state.get("user_properties_cache")
    if isinstance(cached, dict):
        return dict(cached)
    return {}


def _save_local_user_properties_cache(cache: dict[str, Any]) -> None:
    """Persist locally cached user properties used for telemetry deduplication."""
    state = _load_last_telemetry_state()
    state["user_properties_cache"] = dict(cache)
    _save_last_telemetry_state(state)


def _capture_user_property_event(event_name: str, property_key: str, new_value):
    """Capture an event only when the stored property changes.

    Only sends data when telemetry is explicitly enabled.
    """
    # IMPORTANT: Never fetch or send data when telemetry is disabled
    if not _is_telemetry_enabled():
        return

    cached_props = _load_local_user_properties_cache()
    prev_value = cached_props.get(property_key)
    if event_name == "install_started":
        if prev_value is None:
            capture("first_install", {"$set": {property_key: new_value}})
            cached_props[property_key] = new_value
            _save_local_user_properties_cache(cached_props)
            return
        if prev_value == "failed":
            capture("install_after_fail", {"$set": {property_key: new_value}})
            cached_props[property_key] = new_value
            _save_local_user_properties_cache(cached_props)
            return
        if prev_value == "uninstalled":
            capture("reinstall", {"$set": {property_key: new_value}})
            cached_props[property_key] = new_value
            _save_local_user_properties_cache(cached_props)
            return
        capture(event_name, {"$set": {property_key: new_value}})
        cached_props[property_key] = new_value
        _save_local_user_properties_cache(cached_props)
        return
    if prev_value != new_value:
        capture(event_name, {"$set": {property_key: new_value}})
        cached_props[property_key] = new_value
        _save_local_user_properties_cache(cached_props)


# ---------------------------------------------------------------------------
# Post-exploitation telemetry shortcuts (Phase 5 of attack-graph refactor).
#
# These exist so call sites do not have to remember property field names
# and so Phase 7 (data-driven scoring) has a stable, queryable event set.
# ---------------------------------------------------------------------------


def capture_post_ex_menu_viewed(
    *, path_class: str, num_techniques_offered: int
) -> None:
    """Operator inspected a path and saw the post-ex technique menu."""
    capture(
        "post_ex_menu_viewed",
        {
            "path_class": str(path_class or "unknown"),
            "num_techniques_offered": int(num_techniques_offered),
        },
    )


def capture_post_ex_technique_selected(
    *, technique_id: str, path_class: str
) -> None:
    """Operator selected a specific technique from the menu."""
    capture(
        "post_ex_technique_selected",
        {
            "technique_id": str(technique_id),
            "path_class": str(path_class or "unknown"),
        },
    )


def capture_post_ex_dry_run_executed(
    *, technique_id: str, outcome: str
) -> None:
    """A technique dry_run completed (precondition check)."""
    capture(
        "post_ex_dry_run_executed",
        {
            "technique_id": str(technique_id),
            "outcome": str(outcome),
        },
    )


def capture_post_ex_execute_invoked(
    *,
    technique_id: str,
    outcome: str,
    duration_seconds: float,
) -> None:
    """A technique execute() finished. Phase 6 wires the real call site."""
    capture(
        "post_ex_execute_invoked",
        {
            "technique_id": str(technique_id),
            "outcome": str(outcome),
            "duration_seconds": float(duration_seconds),
        },
    )
