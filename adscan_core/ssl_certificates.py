"""SSL certificate configuration for PyInstaller-packaged applications.

This module provides utilities to configure SSL certificate environment variables
for Python/pip operations and requests library. It handles PyInstaller temporary
paths that may be invalid and automatically falls back to system certificates.

This is critical for:
- pip install operations
- requests.post() calls
- Any TLS/HTTPS operations in PyInstaller binaries
"""

import os
from typing import Optional


def _find_system_cert_path() -> Optional[str]:
    """Find system certificate bundle path.

    Returns:
        Path to system certificate bundle, or None if not found
    """
    system_cert_paths = [
        "/etc/ssl/certs/ca-certificates.crt",  # Debian/Ubuntu
        "/etc/pki/tls/certs/ca-bundle.crt",  # RHEL/CentOS
        "/etc/ssl/certs/ca-bundle.crt",  # Alternative location
    ]
    for path in system_cert_paths:
        if os.path.exists(path):
            return path
    return None


def _set_cert_var(
    env: dict,
    var_name: str,
    current_value: Optional[str],
    system_cert_path: Optional[str],
) -> None:
    """Set or remove a certificate environment variable.

    Args:
        env: Environment dictionary to modify
        var_name: Name of the certificate variable (e.g., "SSL_CERT_FILE")
        current_value: Current value of the variable (may be None)
        system_cert_path: Path to system certificate bundle (may be None)
    """
    if current_value and os.path.exists(current_value):
        # Valid existing path - keep it
        env[var_name] = current_value
    elif current_value and not current_value.startswith("/tmp/_MEI"):
        # Non-PyInstaller path (system certificates) - keep it
        env[var_name] = current_value
    elif current_value and current_value.startswith("/tmp/_MEI") and system_cert_path:
        # PyInstaller path is invalid, use system certificates
        env[var_name] = system_cert_path
    elif not current_value and system_cert_path:
        # No variable set, use system certificates
        env[var_name] = system_cert_path
    else:
        # Remove invalid PyInstaller path if no system certs available
        env.pop(var_name, None)


def configure_ssl_certificates(env: dict) -> dict:
    """Configure SSL certificate environment variables for Python/pip operations.

    This function ensures that SSL certificate variables point to valid certificate
    bundles. If PyInstaller temp paths are invalid, it automatically uses system
    certificates. This is critical for pip install and other TLS operations.

    Args:
        env: Environment dictionary to modify in-place

    Returns:
        Modified environment dictionary with SSL certificates configured
    """
    system_cert_path = _find_system_cert_path()

    # Configure all SSL certificate variables
    _set_cert_var(env, "SSL_CERT_FILE", env.get("SSL_CERT_FILE"), system_cert_path)
    _set_cert_var(
        env, "REQUESTS_CA_BUNDLE", env.get("REQUESTS_CA_BUNDLE"), system_cert_path
    )
    _set_cert_var(env, "CURL_CA_BUNDLE", env.get("CURL_CA_BUNDLE"), system_cert_path)

    return env


def configure_ssl_certificates_for_requests() -> None:
    """Configure SSL certificate environment variables for requests library.

    This function modifies os.environ directly so requests library can use the
    certificates. It ensures that SSL certificate variables point to valid certificate
    bundles. If PyInstaller temp paths are invalid, it automatically uses system
    certificates.

    This is critical for requests.post() and other TLS operations in telemetry.
    """
    system_cert_path = _find_system_cert_path()

    # Configure all SSL certificate variables in os.environ
    _set_cert_var(
        os.environ,
        "SSL_CERT_FILE",
        os.environ.get("SSL_CERT_FILE"),
        system_cert_path,
    )
    _set_cert_var(
        os.environ,
        "REQUESTS_CA_BUNDLE",
        os.environ.get("REQUESTS_CA_BUNDLE"),
        system_cert_path,
    )
    _set_cert_var(
        os.environ,
        "CURL_CA_BUNDLE",
        os.environ.get("CURL_CA_BUNDLE"),
        system_cert_path,
    )
