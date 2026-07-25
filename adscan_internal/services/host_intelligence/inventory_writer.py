"""Defensive Posture inventory writer.

Emits ``<workspace>/domains/<domain>/inventory/defensive_posture.json``
from a collection of :class:`HostFingerprint` (or
:class:`LsassHostFingerprint`) objects. The file is the source of
truth consumed by the web app's Defensive Posture KPI surface.

The cache (`host_intel.json`) is keyed by IP and is operational
state; this writer is keyed by ``host_object_id`` (SID / GUID / DNS
fallback) and is the durable inventory artefact.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from adscan_core.rich_output import print_info_debug
from adscan_internal import telemetry
from adscan_internal.services.host_intelligence.models import (
    DetectedProduct,
    HostFingerprint,
)
from adscan_core.rich_output import print_exception

INVENTORY_SCHEMA_VERSION = "inventory-1.0"
RECORD_TYPE = "defensive_posture"
_FILENAME = "defensive_posture.json"


def _serialize_product(product: DetectedProduct) -> dict:
    return {
        "name": product.name,
        "category": product.category,
        "installed": bool(product.installed),
        "running": bool(product.running),
        "svc_start": int(product.svc_start),
        "realtime_protection": bool(product.realtime_protection),
    }


def _serialize_host(
    host_object_id: str,
    fingerprint: HostFingerprint,
    *,
    dns_name: str | None = None,
    observed_at: datetime | None = None,
) -> dict:
    # PPL / lsass extras live on the LSASS extension subclass — read
    # via getattr so the writer accepts both base and extended types
    # without coupling to the LSASS-only module.
    ppl_enabled = getattr(fingerprint, "ppl_enabled", None)
    lsass_pid = getattr(fingerprint, "lsass_pid", None)
    return {
        "host_object_id": host_object_id,
        "dns_name": dns_name,
        "products": [_serialize_product(p) for p in fingerprint.products],
        "ppl_enabled": (None if ppl_enabled is None else bool(ppl_enabled)),
        "lsass_pid_visible": (None if lsass_pid is None else bool(lsass_pid)),
        "observed_at": observed_at.isoformat() if observed_at else None,
    }


def write_defensive_posture_inventory(
    workspace_root: str | Path,
    domain: str,
    fingerprints: Mapping[str, HostFingerprint],
    *,
    domains_dir: str = "domains",
    dns_name_lookup: Mapping[str, str] | None = None,
    observed_at_lookup: Mapping[str, datetime] | None = None,
) -> Path | None:
    """Write the Defensive Posture inventory file.

    Args:
        workspace_root: Workspace root (`current_workspace_dir`).
        domain: Domain name (case-insensitive — normalised to lower).
        fingerprints: ``{host_object_id: HostFingerprint}``. Caller is
            responsible for picking the most stable id available
            (SID > objectGUID > FQDN > IP).
        domains_dir: Override for the workspace ``domains`` subdir.
        dns_name_lookup: Optional ``{host_object_id: dns_name}``.
        observed_at_lookup: Optional ``{host_object_id: datetime}``.

    Returns:
        The path written, or ``None`` on error (errors are captured to
        telemetry and logged to debug — never raised).
    """
    try:
        domain_key = (domain or "").strip().rstrip(".").lower()
        if not domain_key:
            print_info_debug("[defensive_posture_writer] empty domain; skip")
            return None

        target_dir = Path(workspace_root) / domains_dir / domain_key / "inventory"
        target_dir.mkdir(parents=True, exist_ok=True)
        target_path = target_dir / _FILENAME

        dns_lookup = dict(dns_name_lookup or {})
        observed_lookup = dict(observed_at_lookup or {})

        hosts_payload = [
            _serialize_host(
                host_object_id=host_id,
                fingerprint=fp,
                dns_name=dns_lookup.get(host_id),
                observed_at=observed_lookup.get(host_id),
            )
            for host_id, fp in fingerprints.items()
        ]
        # Stable sort by host_object_id for diff-friendly output.
        hosts_payload.sort(key=lambda h: str(h.get("host_object_id") or ""))

        payload = {
            "schema_version": INVENTORY_SCHEMA_VERSION,
            "record_type": RECORD_TYPE,
            "domain": domain_key,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "hosts": hosts_payload,
        }

        # Atomic write: tmp + rename.
        tmp_path = target_path.with_suffix(".json.tmp")
        tmp_path.write_text(
            json.dumps(payload, indent=2, default=str), encoding="utf-8"
        )
        os.replace(tmp_path, target_path)
        return target_path
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"[defensive_posture_writer] write error: {exc}")
        return None


__all__ = [
    "INVENTORY_SCHEMA_VERSION",
    "RECORD_TYPE",
    "write_defensive_posture_inventory",
]
