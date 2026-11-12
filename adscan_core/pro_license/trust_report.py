"""What an engine build trusts for PRO licences, as the build itself reports it.

``adscan version --json`` (engine) prints this report, so the release cut can
ask a BUILT image which licence-server keys it verifies against, instead of
assuming the image carries what the source tree says
(``scripts/check_pro_license_anchors.py --image``). The PRO binary is a PyArmor
and PyInstaller build, so its constants cannot be read off the file reliably;
the binary answering for itself is the check that survives any packaging.

Everything here is public: key ids and Ed25519 PUBLIC keys. No licence, no
installation identity and no activation key is read or printed.

The field names are a contract between the engine and the release script. They
live here once and the script reads them from this module.
"""

from __future__ import annotations

from typing import Any

#: Top-level key of the PRO licence block in ``adscan version --json``.
REPORT_KEY = "pro_license"
#: ``{kid: base64 raw Ed25519 public key}`` the build verifies licences against.
TRUSTED_KEYS_FIELD = "trusted_keys"
#: True when the image carries the marker that makes a licence REQUIRED
#: (``build_docker_pro_image.sh --licensed``).
REQUIRED_MARKER_FIELD = "licence_required_marker"


def trust_anchor_report() -> dict[str, Any]:
    """The PRO licence trust anchors of THIS build, and whether it requires a licence."""
    from adscan_core.pro_license.evaluation import PRO_LICENSE_MARKER
    from adscan_core.pro_license.model import PRO_LICENSE_SERVER_PUBLIC_KEYS

    try:
        marker = PRO_LICENSE_MARKER.is_file()
    except OSError:
        marker = False
    return {
        TRUSTED_KEYS_FIELD: dict(sorted(PRO_LICENSE_SERVER_PUBLIC_KEYS.items())),
        REQUIRED_MARKER_FIELD: marker,
    }


__all__ = [
    "REPORT_KEY",
    "REQUIRED_MARKER_FIELD",
    "TRUSTED_KEYS_FIELD",
    "trust_anchor_report",
]
