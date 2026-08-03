"""Native ADCS certificate request and authentication services."""

from adscan_internal.services.adcs.cert_auth import (
    CertAuthConfig,
    CertAuthResult,
    authenticate_with_cert_native,
)
from adscan_internal.services.adcs.cert_request import (
    CertRequestConfig,
    CertRequestResult,
    request_certificate_native,
    retrieve_certificate_native,
)
from adscan_internal.services.adcs.ca_backup import (
    CABackupConfig,
    CABackupResult,
    ca_backup_native,
)
from adscan_internal.services.adcs.cert_forge import (
    ForgeConfig,
    ForgeResult,
    build_ca_crl_distribution_uri,
    forge_certificate_native,
)
from adscan_internal.services.adcs.pass_the_cert import (
    PassTheCertificateResult,
    native_ptc_enabled,
    pass_the_certificate_native,
)
from adscan_internal.services.adcs.template_modify import (
    TemplateSnapshot,
    make_template_esc1_vulnerable,
    read_snapshot_from_disk,
    restore_template as restore_template_native,
    snapshot_template,
    write_snapshot_to_disk,
)

__all__ = [
    "CertRequestConfig",
    "CertRequestResult",
    "request_certificate_native",
    "retrieve_certificate_native",
    "CertAuthConfig",
    "CertAuthResult",
    "authenticate_with_cert_native",
    "CABackupConfig",
    "CABackupResult",
    "ca_backup_native",
    "ForgeConfig",
    "ForgeResult",
    "build_ca_crl_distribution_uri",
    "forge_certificate_native",
    "PassTheCertificateResult",
    "native_ptc_enabled",
    "pass_the_certificate_native",
    "TemplateSnapshot",
    "snapshot_template",
    "make_template_esc1_vulnerable",
    "restore_template_native",
    "read_snapshot_from_disk",
    "write_snapshot_to_disk",
]
