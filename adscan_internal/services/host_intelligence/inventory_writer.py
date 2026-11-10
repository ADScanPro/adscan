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
from adscan_internal.services.host_intelligence.product_catalog import (
    product_edr_module_indistinguishable,
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
        # False when the RTP state was assumed, not read. Reporting reads it
        # (``endpoint_capability.product_activity_unconfirmed``) so an assumed
        # "on" is never reported as observed protection.
        "realtime_protection_confirmed": bool(
            getattr(product, "realtime_protection_confirmed", True)
        ),
        # Stamped here, where the catalog is importable, so the report and the
        # web (which cannot import it) read a flag instead of re-deriving it:
        # an antivirus suite whose EDR licence runs on the same agent must not
        # read as antivirus-only.
        "edr_module_indistinguishable": product_edr_module_indistinguishable(
            product.name
        ),
    }


def posture_was_assessed(fingerprint: HostFingerprint) -> bool:
    """Whether this host's endpoint posture was actually determined.

    The distinction an empty ``products`` list cannot carry on its own, and
    the reason this field exists: a host whose probe FAILED and a host where
    ADscan genuinely detected nothing both serialize to ``products: []``.
    Collapsing the two would let a failed probe render as "no endpoint
    protection" — false assurance about the one control the client most
    wants to be true, and the same falsehood class as greening a compliance
    control nobody tested.

    Mirrors the collector's ``endpoint_posture_assessed`` semantics:

    * products detected -> assessed, whatever partial error came back (we
      definitively observed something).
    * no products, no error -> assessed; ADscan detected none active. Still
      NOT a claim that the host has none, only that none was observed.
    * no products, with an error -> NOT assessed. UNKNOWN, never clean.
    """
    if list(getattr(fingerprint, "products", None) or []):
        return True
    return not getattr(fingerprint, "error", None)


def _serialize_host(
    host_object_id: str,
    fingerprint: HostFingerprint,
    *,
    dns_name: str | None = None,
    observed_at: datetime | None = None,
    hardening: Mapping[str, str] | None = None,
) -> dict:
    # PPL / lsass extras live on the LSASS extension subclass — read
    # via getattr so the writer accepts both base and extended types
    # without coupling to the LSASS-only module.
    ppl_enabled = getattr(fingerprint, "ppl_enabled", None)
    lsass_pid = getattr(fingerprint, "lsass_pid", None)
    record = {
        "host_object_id": host_object_id,
        "dns_name": dns_name,
        "products": [_serialize_product(p) for p in fingerprint.products],
        # Carries the "could we tell?" axis, which ``products`` cannot. A
        # consumer MUST read this before concluding anything from an empty
        # product list — see ``posture_was_assessed``.
        "posture_assessed": posture_was_assessed(fingerprint),
        "ppl_enabled": (None if ppl_enabled is None else bool(ppl_enabled)),
        "lsass_pid_visible": (None if lsass_pid is None else bool(lsass_pid)),
        "observed_at": observed_at.isoformat() if observed_at else None,
    }
    # Three-state credential-hardening tokens (``lsa_protection``,
    # ``credential_guard``), written only by a caller that read them. A record
    # without them reads "not checked" downstream, never "off".
    for key in ("lsa_protection", "credential_guard"):
        value = str((hardening or {}).get(key) or "").strip()
        if value:
            record[key] = value
    return record


def _host_identity_keys(row: Mapping) -> set[str]:
    """Every identity a posture row can be matched on, lower-cased.

    A host is the same host whether a run recorded it by SID or by DNS name,
    so both are keys. The DNS name also contributes its first label, because
    one run may record ``CASTELBLACK`` and another the FQDN.
    """
    keys: set[str] = set()
    host_id = str(row.get("host_object_id") or "").strip().lower()
    if host_id:
        keys.add(f"id:{host_id}")
    dns = str(row.get("dns_name") or "").strip().rstrip(".").lower()
    if dns:
        keys.add(f"dns:{dns}")
        keys.add(f"short:{dns.split('.', 1)[0]}")
    return keys


def merge_posture_rows(existing: list, fresh: list) -> list:
    """Merge this run's posture rows into the rows already on disk.

    The domain's inventory accumulates across runs. A host this run examined
    replaces its earlier row; a host it did not reach keeps the row an earlier
    run wrote, with that run's ``observed_at``. One exception keeps an
    observation from being erased by a failure: a fresh row whose posture was
    NOT assessed never replaces an earlier row that was ("cache observations,
    never absences").

    Pure, so the rule is unit-testable without a workspace.
    """
    merged = [dict(r) for r in fresh if isinstance(r, Mapping)]
    fresh_keys = [_host_identity_keys(r) for r in merged]
    carried: list[dict] = []
    for old in existing or ():
        if not isinstance(old, Mapping):
            continue
        old_keys = _host_identity_keys(old)
        index = next(
            (i for i, keys in enumerate(fresh_keys) if keys & old_keys), None
        )
        if index is None:
            carried.append(dict(old))
            continue
        fresh_row = merged[index]
        if (
            fresh_row.get("posture_assessed") is not True
            and old.get("posture_assessed") is True
        ):
            merged[index] = dict(old)
    return merged + carried


def _read_existing_rows(target_path: Path) -> list:
    if not target_path.exists():
        return []
    try:
        data = json.loads(target_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    hosts = data.get("hosts") if isinstance(data, dict) else None
    return [h for h in (hosts or ()) if isinstance(h, dict)]


def write_defensive_posture_inventory(
    workspace_root: str | Path,
    domain: str,
    fingerprints: Mapping[str, HostFingerprint],
    *,
    domains_dir: str = "domains",
    dns_name_lookup: Mapping[str, str] | None = None,
    observed_at_lookup: Mapping[str, datetime] | None = None,
    hardening_lookup: Mapping[str, Mapping[str, str]] | None = None,
    merge_existing: bool = False,
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
        hardening_lookup: Optional ``{host_object_id: {lsa_protection,
            credential_guard}}`` three-state tokens from the registry stage.
        merge_existing: Merge into the rows already on disk (see
            :func:`merge_posture_rows`) instead of replacing them. A caller
            whose run may reach only part of the estate MUST pass it, or a
            host examined earlier disappears from the inventory.

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
        hardening = dict(hardening_lookup or {})

        hosts_payload = [
            _serialize_host(
                host_object_id=host_id,
                fingerprint=fp,
                dns_name=dns_lookup.get(host_id),
                observed_at=observed_lookup.get(host_id),
                hardening=hardening.get(host_id),
            )
            for host_id, fp in fingerprints.items()
        ]
        if merge_existing:
            hosts_payload = merge_posture_rows(
                _read_existing_rows(target_path), hosts_payload
            )
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
    "merge_posture_rows",
    "posture_was_assessed",
    "write_defensive_posture_inventory",
]
