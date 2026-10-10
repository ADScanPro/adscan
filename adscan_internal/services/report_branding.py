"""Branding posture SSOT — decides how much ADscan branding a deliverable carries.

LITE-safe: imports nothing from ``adscan_internal.pro`` so both tiers and the web
can consume it. The whole report pipeline reads the resolved posture; it is never
a per-asset toggle.
"""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from typing import Mapping

_ENV_KEY = "ADSCAN_BRANDING"


class BrandingPosture(str, Enum):
    ADSCAN = "adscan"  # LITE / free: full ADscan branding (lead magnet)
    COBRAND = "cobrand"  # PRO default: customer logo + discreet "powered by ADscan"
    WHITELABEL = "whitelabel"  # top unlock: only the customer's brand


VALID_BRANDING_POSTURES: tuple[str, ...] = tuple(p.value for p in BrandingPosture)
_DEFAULT_POSTURE = BrandingPosture.COBRAND


def resolve_branding_posture(
    *,
    requested: str | None,
    env: Mapping[str, str] | None = None,
    is_lite: bool,
    whitelabel_entitled: bool,
) -> BrandingPosture:
    """Resolve the effective branding posture. Never raises.

    Precedence: explicit ``requested`` -> ``ADSCAN_BRANDING`` env -> default.
    LITE is pinned to ADSCAN (cannot be raised). WHITELABEL requires the
    entitlement flag; without it, it degrades to COBRAND.
    """
    if is_lite:
        return BrandingPosture.ADSCAN

    env = env or {}
    raw = (requested or env.get(_ENV_KEY, "") or "").strip().lower()
    try:
        chosen = BrandingPosture(raw) if raw else _DEFAULT_POSTURE
    except ValueError:
        chosen = _DEFAULT_POSTURE

    if chosen is BrandingPosture.WHITELABEL and not whitelabel_entitled:
        return BrandingPosture.COBRAND
    return chosen


CAPABILITIES: tuple[str, ...] = ("whitelabel", "data_export", "composition_seams")


def entitlement_enabled(capability: str, config_path: str | None = None) -> bool:
    """True when the install/licence grants a white-label CAPABILITY. Never raises.

    Reads ``entitlements.<capability>`` from config.json. Back-compat: the legacy
    ``branding_whitelabel_enabled`` bool still grants ``whitelabel``. Default OFF
    for every capability (free-PRO = cobrand; whitelabel is a paid/granted lever).
    """
    try:
        path = Path(config_path) if config_path else _default_config_path()
        data = json.loads(path.read_text(encoding="utf-8"))
        ents = data.get("entitlements")
        if isinstance(ents, dict) and bool(ents.get(capability, False)):
            return True
        if capability == "whitelabel" and bool(
            data.get("branding_whitelabel_enabled", False)
        ):
            return True
        return False
    except Exception:
        return False


def whitelabel_entitled_from_config(config_path: str | None = None) -> bool:
    """True when the install/license enables the full white-label unlock.

    Reads the ``branding_whitelabel_enabled`` boolean from ``config.json``
    (mirrors the read pattern in ``client_logo.load_client_logo_setting``).
    Default OFF. Best-effort: any read error is a hard False (never
    accidentally de-brands). Binding this flag to a paid tier is a licensing
    concern handled outside this function.
    """
    return entitlement_enabled("whitelabel", config_path)


def _default_config_path() -> Path:
    from adscan_core.paths import get_adscan_home_dir

    return get_adscan_home_dir() / "config.json"
