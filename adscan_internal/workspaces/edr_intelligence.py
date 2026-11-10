"""EDR/AV catch intelligence — persisted per workspace, consulted before each dump attempt."""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Sequence


@dataclass
class CatchEvent:
    host: str
    method: str  # "comsvcs" | "procdump" | "nanodump" | "silentprocessexit"
    product: str  # e.g. "CrowdStrike Falcon"
    category: str  # "av" | "edr"
    ts: float = field(default_factory=time.time)


class EdrIntelligence:
    """Read/write EDR catch intelligence stored as JSON in the workspace directory.

    File layout:
      <workspace_dir>/edr_intelligence.json  -> {"catches": [...], "host_products": {...}}
    """

    _FILENAME = "edr_intelligence.json"

    def __init__(self, workspace_dir: str | Path) -> None:
        self._path = Path(workspace_dir) / self._FILENAME
        self._data: dict = self._load()

    # ------------------------------------------------------------------ I/O

    def _load(self) -> dict:
        if self._path.exists():
            try:
                return json.loads(self._path.read_text())
            except Exception:  # noqa: BLE001
                pass
        return {"catches": [], "host_products": {}}

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(self._data, indent=2))

    # ------------------------------------------------------------------ writes

    def record_catch(
        self,
        *,
        host: str,
        method: str,
        product: str,
        category: str,
    ) -> None:
        """Record that *method* was caught by *product* on *host*."""
        evt = CatchEvent(host=host, method=method, product=product, category=category)
        self._data["catches"].append(asdict(evt))
        self._save()

    def record_host_products(
        self,
        host: str,
        products: Sequence[tuple[str, str]],  # (name, category)
    ) -> None:
        """Persist the AV/EDR products detected on *host*."""
        self._data["host_products"][host] = [
            {"name": n, "category": c} for n, c in products
        ]
        self._save()

    # ------------------------------------------------------------------ reads

    def was_caught(self, *, method: str, product: str) -> bool:
        """Return True if *method* was ever caught by *product* on any host.

        Product names are compared through the catalog's
        ``product_names_match``, so a catch recorded under a name the catalog
        later split (the merged "Windows Defender") still counts against the
        products it covered. Without it the split silently erased every OPSEC
        lesson a workspace had learned against Defender.
        """
        # Lazy: host_intelligence/__init__ re-exports this module, so a
        # module-level import of the catalog would be circular.
        from adscan_internal.services.host_intelligence.product_catalog import (
            product_names_match,
        )

        return any(
            e.get("method") == method
            and product_names_match(str(e.get("product") or ""), product)
            for e in self._data.get("catches", [])
        )

    def get_host_products(self, host: str) -> list[tuple[str, str]]:
        """Return [(name, category), ...] for *host*, or [] if unknown."""
        raw = self._data.get("host_products", {}).get(host, [])
        return [(r["name"], r["category"]) for r in raw]

    def global_warnings_for_method(self, method: str) -> list[str]:
        """Return human-readable warnings about *method* being caught by any EDR product.

        Returns one warning per unique (method, product) pair where category=="edr".
        EDR catches are global (same EDR = same result on every machine).
        """
        seen: set[str] = set()
        warnings: list[str] = []
        for evt in self._data.get("catches", []):
            if evt["method"] != method:
                continue
            key = f"{evt['product']}"
            if key in seen:
                continue
            seen.add(key)
            label = "EDR" if evt.get("category") == "edr" else "AV"
            warnings.append(
                f"{label} catch: {evt['product']} blocked '{method}' on {evt['host']}"
            )
        return warnings
