"""Telemetry helpers for ADscan."""

import base64
import binascii
import functools
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
from typing import Any, Iterator, Optional, TYPE_CHECKING
from urllib.parse import urlparse
import site
import sys
import traceback
import uuid

import certifi
import requests
import sentry_sdk

from .ssl_certificates import configure_ssl_certificates_for_requests
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

    Controlled by ``ADSCAN_TELEMETRY_PRESERVE_WELL_KNOWN_PRINCIPALS``.
    Defaults to False to keep telemetry maximally privacy-preserving by default.
    """
    raw = str(os.getenv("ADSCAN_TELEMETRY_PRESERVE_WELL_KNOWN_PRINCIPALS", "")).strip()
    if not raw:
        return False
    return raw.lower() in {"1", "true", "yes", "y", "on"}


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
    # Do not preserve domain-qualified representations; those parts must be
    # sanitized independently (domain stays sensitive).
    if "\\" in raw or "@" in raw:
        return False
    return raw.lower() in _WELL_KNOWN_PRINCIPALS_PASSTHROUGH


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
            token = get_cli_shared_token()
            if not token:
                print_error_debug(
                    "Telemetry ingest token not configured; cannot send Sentry event"
                )
                return

            # Serialize envelope
            envelope_payload = envelope.serialize().decode("utf-8")

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
        - source: one of {"env", "cli", "default"}
    """
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

    # Emit a state change event.
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
    {"install", "ci", "start", "check", "update", "upgrade"}
)
HOST_SESSION_CAPTURE_COMMANDS = frozenset({"install", "check", "update", "upgrade"})
CONTAINER_SESSION_CAPTURE_COMMANDS = frozenset({"start", "ci"})
SESSION_WORKSPACE_CONTEXT_COMMANDS = frozenset({"start", "ci"})
_SESSION_WORKSPACE_CONTEXT_FIELDS = frozenset(
    {"workspace_type", "lab_provider", "lab_name", "lab_slug", "lab_name_whitelisted"}
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
    metadata: dict[str, Any] = {}
    if base_metadata:
        metadata.update(base_metadata)
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


def _refresh_workspace_cache_if_needed() -> None:
    """Refresh known domains/users/hosts/passwords from workspace files."""
    workspace_dir = Path.cwd()
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


def capture(event: str, properties: Optional[dict[str, Any]] = None):
    """Capture a telemetry event via n8n proxy if enabled.

    Automatically routes events to appropriate PostHog project based on environment:
    - "dev": Development project
    - "ci": Development project
    - "prod": Production project

    Also adds environment property to all events for additional filtering.
    """
    if _telemetry_client and (
        _is_telemetry_enabled() or event.startswith("telemetry_")
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
            merged_set = {**default_set, **user_set}
            props["$set"] = merged_set

            # Send event to n8n proxy (mimics PostHog API format)
            payload = {
                "event": event,
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
            print_warning_debug(f"Telemetry capture failed for event {event}: {exc}")
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

    data_type = data_type.lower()
    if data_type == "ip":
        if _is_ip_passthrough(value):
            return value
        cidr_match = re.match(r"^(?P<prefix>[0-9.]+)(?P<sep>/)(?P<suffix>\d+)$", value)
        if cidr_match:
            prefix = cidr_match.group("prefix")
            suffix = cidr_match.group("suffix")
            return f"{_pseudonymize_value(prefix, data_type)}/{suffix}"
    preserve_non_alnum = data_type in {
        "domain",
        "hostname",
        "user",
        "service",
        "path",
        "workspace",
        "share",
        "ip",
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


def _record_pseudonym(value: str, data_type: str) -> str:
    """Return a pseudonym and remember it to avoid double-sanitization."""
    if value in _SANITIZED_VALUES:
        return value
    # Opt-in preservation of well-known built-in AD principals (useful for telemetry debugging).
    # We only allow this for "user" tokens because groups are usually treated as users in output.
    if (
        data_type.lower() == "user"
        and _preserve_well_known_principals_enabled()
        and _is_well_known_principal(value)
    ):
        return value
    replacement = _pseudonymize_value(value, data_type)
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


def _replace_table_cell(segment: str, data_type: str) -> str:
    """Replace a table cell's content with a length-preserving pseudonym."""
    raw_value = segment.strip()
    if not raw_value or _is_already_sanitized(raw_value):
        return segment
    if re.fullmatch(r"\[[A-Z_]+\]", raw_value):
        return segment
    replacement = _record_pseudonym(raw_value, data_type)
    return _fit_to_segment(segment, replacement)


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
            return _record_pseudonym(value, data_type)

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
    content = re.sub(
        r"\b[0-9a-f]{32}\b",
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
        ],
        data_type="domain",
        separator_pattern=r"\s*[│|:=]\s*",  # Only match pipe/colon/equals, not spaces
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
            user_pattern = re.compile(
                rf"(?i)(?<![A-Za-z0-9._-])({re.escape(user_clean)})(?![A-Za-z0-9._-])"
            )
            content = user_pattern.sub(
                lambda m: _record_pseudonym(m.group(1), "user"),
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
            password_pattern = re.compile(re.escape(password_clean))
            content = password_pattern.sub(
                lambda m: _record_pseudonym(m.group(0), "password"),
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

    content = _restore_passthrough_segments(content, passthrough_mapping)
    return content


def _maybe_sanitize_rich_output(content: str, *, sanitize: bool) -> str:
    """Prepare Rich export for session storage, optionally applying redaction.

    For non-sensitive commands (e.g. ``install``/``check``), we still normalize the
    Rich export (strip ANSI/HTML) but avoid redaction to preserve debugging context.
    In that mode we also strip invisible markers so they don't affect stored text.
    """
    if sanitize:
        return _sanitize_rich_output(content)
    prepared = _prepare_rich_content_for_processing(content)
    return _strip_sensitive_markers(prepared)


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


def _sanitize_keyword_value(
    content: str,
    keywords: list[str],
    data_type: str,
    separator_pattern: str = r"(?:\s*[:=]\s*|\s*[│|]\s*|[ \t]+)",
    value_pattern: str = r"[A-Za-z0-9._@!%^&*+=\\/-]+",
) -> str:
    """Sanitize values that follow specific keywords (user/password/source/etc.)."""
    if not keywords:
        return content

    keyword_pattern = "|".join(re.escape(keyword) for keyword in keywords)
    base_pattern = rf"(?i)(?<!\{{|\[)(\b(?:{keyword_pattern})\b{separator_pattern})"

    def _build_quoted_regex() -> re.Pattern[str]:
        return re.compile(
            base_pattern
            + r"(?:<[^>]+>)*(?P<quote>['\"])"
            + r"(?:<[^>]+>)*(?P<value>[^\"'<]+?)"
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

    def _replace_if_not_placeholder(match: re.Match[str]) -> str:
        """Replace value only if it's not already a placeholder."""
        value = match.group("value")
        if "user descriptions" in _line_for_match(match).lower():
            return match.group(0)
        # Strip whitespace and check if it starts with a placeholder
        # This handles cases like "[IP]    │" where trailing spaces/chars are captured
        value_stripped = value.strip()
        if value_stripped.startswith("[") and value_stripped.endswith("]"):
            # Value is already a placeholder, don't replace it
            return match.group(0)
        if _is_already_sanitized(value_stripped):
            return match.group(0)
        replacement = _record_pseudonym(value_stripped, data_type)
        return match.group(1) + _fit_to_length(replacement, len(value))

    def _replace_quoted(match: re.Match[str]) -> str:
        value = match.group("value")
        if "user descriptions" in _line_for_match(match).lower():
            return match.group(0)
        value_stripped = value.strip()
        if value_stripped.startswith("[") and value_stripped.endswith("]"):
            return match.group(0)
        if _is_already_sanitized(value_stripped):
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

        share_replaced = False
        candidate_line = line
        if "│" in line:
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
            plain_pattern = re.compile(
                r"(?P<domain>\S+)(\s+)(?P<user>\S+)(\s+)(?P<cred>\S+)",
                re.IGNORECASE,
            )

            def _plain_replace(match: re.Match[str]) -> str:
                domain_value = match.group("domain")
                user_value = match.group("user")
                cred_value = match.group("cred")
                domain_repl = _fit_to_length(
                    _record_pseudonym(domain_value, "domain"), len(domain_value)
                )
                user_repl = _fit_to_length(
                    _record_pseudonym(user_value, "user"), len(user_value)
                )
                cred_repl = _fit_to_length(
                    _record_pseudonym(cred_value, "password"), len(cred_value)
                )
                return (
                    domain_repl
                    + match.group(2)
                    + user_repl
                    + match.group(4)
                    + cred_repl
                )

            candidate_line, replaced = plain_pattern.subn(
                _plain_replace,
                line,
                count=1,
            )

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
    if environment:
        updates["environment"] = environment.lower()
    if command_type:
        updates["command_type"] = command_type.lower()
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
    if lab_name:
        updates["target_name"] = lab_name.lower()
    if lab_slug:
        updates["target_slug"] = lab_slug.lower()
    if lab_name_whitelisted is not None:
        updates["target_whitelisted"] = bool(lab_name_whitelisted)
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
        "workspace_type",
        "target_type",
        "target_name",
        "target_slug",
        "target_whitelisted",
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


def _send_session_to_vercel(
    session_id: str,
    html_content: str,
    metadata: Optional[dict[str, Any]] = None,
    started_at: Optional[datetime] = None,
    finished_at: Optional[datetime] = None,
) -> Optional[str]:
    """Send terminal session recording to Vercel API via n8n proxy."""
    vercel_proxy_url = get_vercel_sessions_proxy_url()
    token = get_cli_shared_token()

    if not vercel_proxy_url or not token:
        print_info_debug("Skipping Vercel session storage: missing proxy URL or token")
        return None

    try:
        payload: dict[str, Any] = {
            "session_id": session_id,
            "user_id_hash": TELEMETRY_ID,
            "html": html_content,
        }
        payload.update(_vercel_version_field())
        payload.update(_vercel_metadata_fields(metadata))
        payload.update(_vercel_timestamp_fields(started_at, finished_at))

        print_info_debug(
            f"Sending session recording to Vercel via n8n proxy (session_id={session_id})",
        )
        print_info_debug(f"Vercel proxy URL: {vercel_proxy_url}")
        print_info_debug(f"Payload size: HTML={len(html_content)} bytes")
        print_info_debug(
            f"Vercel payload context: {_summarize_vercel_payload_context(payload)}",
        )

        # Configure SSL certificates before making request
        _configure_ssl_certificates_for_requests()

        response = requests.post(
            vercel_proxy_url,
            json=payload,
            headers={
                "X-CLI-Token": token,
                "Content-Type": "application/json",
            },
            timeout=10,
        )

        print_info_debug(f"Vercel proxy response status: {response.status_code}")
        response.raise_for_status()

        # Parse response
        try:
            result = response.json()
            print_info_debug(f"Vercel proxy response: {result}")

            # Extract session ID from response
            stored_session_id = result.get("session_id") or session_id
            # Construct public URL (proxy should return this)
            session_url = result.get("session_url")
            if not session_url:
                # Fallback: construct from known pattern
                session_url = (
                    f"https://sessions.adscanpro.com/sessions/{stored_session_id}"
                )

            print_info_debug(f"Session stored successfully via n8n: {session_url}")
            return session_url
        except (ValueError, json.JSONDecodeError) as e:
            print_warning_debug(f"Vercel proxy response is not valid JSON: {e}")
            # Construct URL anyway if status was successful
            if response.status_code in (200, 201):
                session_url = f"https://sessions.adscanpro.com/sessions/{session_id}"
                print_info_debug(
                    "Session stored successfully via n8n "
                    f"(non-JSON response): {session_url}",
                )
                return session_url
            return None

    except requests.exceptions.RequestException as e:
        print_warning_debug(f"Failed to send session via n8n proxy: {e}")
        print_info_debug(f"Vercel proxy error details: {type(e).__name__} - {str(e)}")
        return None
    except (ValueError, TypeError, AttributeError, OSError) as exc:
        print_warning_debug(f"Unexpected error sending session via n8n proxy: {exc}")
        print_info_debug(f"Vercel proxy error details: {type(exc).__name__} - {exc}")
        return None


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
        )
    if lab_slug:
        metadata["lab_slug"] = str(lab_slug).lower()

    # Note: workspace_name is intentionally NOT included to avoid revealing internal information
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
        metadata_with_env = dict(metadata or {})

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
        sanitize_session = command_type not in {"install", "check"}
        print_info_debug(
            "[DEBUG] capture_session_end metadata summary: "
            f"command_type={metadata_with_env.get('command_type')!r}, "
            f"workspace_type={metadata_with_env.get('workspace_type')!r}, "
            f"lab_provider={metadata_with_env.get('lab_provider')!r}, "
            f"lab_name={metadata_with_env.get('lab_name')!r}, "
            f"lab_slug={metadata_with_env.get('lab_slug')!r}, "
            f"lab_name_whitelisted={metadata_with_env.get('lab_name_whitelisted')!r}",
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

                # Sanitize before sending (unless command is known non-sensitive)
                sanitized_html = _maybe_sanitize_rich_output(
                    html_content, sanitize=sanitize_session
                )
                sanitized_text = _maybe_sanitize_rich_output(
                    text_content, sanitize=sanitize_session
                )

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
