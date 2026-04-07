"""Library-backed CertiHound collection helpers.

This service prefers CertiHound's Python API over shelling out to the CLI so
ADCS collection can be integrated and tested with normal Python error handling.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
import logging

from adscan_internal import print_warning, print_warning_debug, telemetry
from adscan_internal.services.base_service import BaseService
from adscan_internal.services.ldap_transport_service import execute_with_ldap_fallback


logger = logging.getLogger(__name__)


def _load_certihound_library() -> tuple[Any, Any, Any, Any]:
    """Load CertiHound public library objects.

    Returns:
        Tuple containing ``ADCSCollector``, ``BloodHoundCEExporter``,
        ``LDAPConnection``, and ``LDAPConfig``.

    Raises:
        ModuleNotFoundError: If CertiHound is not installed in the interpreter.
    """
    from certihound import ADCSCollector, BloodHoundCEExporter  # type: ignore  # pylint: disable=import-error
    from certihound.ldap.connection import (  # type: ignore  # pylint: disable=import-error
        LDAPConfig,
        LDAPConnection,
    )

    return ADCSCollector, BloodHoundCEExporter, LDAPConnection, LDAPConfig


def is_certihound_library_available() -> bool:
    """Return whether the CertiHound Python package is importable."""
    try:
        _load_certihound_library()
        return True
    except ModuleNotFoundError:
        return False


class CertiHoundLibraryService(BaseService):
    """Execute CertiHound through its Python API and write a BloodHound ZIP."""

    def collect_adcs_zip(
        self,
        *,
        target_domain: str,
        dc_address: str,
        output_dir: str,
        zip_filename: str,
        username: str | None = None,
        password: str | None = None,
        use_kerberos: bool = False,
        use_ldaps: bool = True,
    ) -> str | None:
        """Collect ADCS data and export it as a BloodHound CE ZIP.

        Args:
            target_domain: Target AD domain.
            dc_address: Preferred domain controller address for LDAP.
            output_dir: Directory where the ZIP should be written.
            zip_filename: Final ZIP filename.
            username: Optional username or UPN for password auth.
            password: Optional password for password auth.
            use_kerberos: Whether to authenticate with Kerberos.
            use_ldaps: Whether to connect with LDAPS.

        Returns:
            Absolute ZIP path when collection succeeds, otherwise ``None``.
        """
        try:
            (
                ADCSCollector,
                BloodHoundCEExporter,
                LDAPConnection,
                LDAPConfig,
            ) = _load_certihound_library()
        except ModuleNotFoundError:
            return None

        output_path = Path(output_dir).expanduser().resolve() / zip_filename
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if output_path.exists():
            output_path.unlink()

        try:
            def _collect(connection: Any) -> None:
                collector = ADCSCollector(connection)
                data = collector.collect_all()
                exporter = BloodHoundCEExporter(data.domain, data.domain_sid)
                export_result = exporter.export(data)
                export_result.write_zip(str(output_path))

            execute_with_ldap_fallback(
                operation_name="CertiHound library collection",
                target_domain=target_domain,
                dc_address=dc_address,
                config_cls=LDAPConfig,
                connection_cls=LDAPConnection,
                callback=_collect,
                username=username,
                password=password,
                use_kerberos=use_kerberos,
                prefer_ldaps=use_ldaps,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning("CertiHound library collection failed.")
            print_warning_debug(
                f"CertiHound library collection failure: {type(exc).__name__}: {exc}"
            )
            logger.exception("CertiHound library collection failure")
            return None

        return str(output_path)
