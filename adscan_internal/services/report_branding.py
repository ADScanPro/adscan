"""Branding posture SSOT — decides how much ADscan branding a deliverable carries.

LITE-safe: imports nothing from ``adscan_internal.pro`` so both tiers and the web
can consume it. The whole report pipeline reads the resolved posture; it is never
a per-asset toggle.
"""

from __future__ import annotations

import json
import re
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

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


def whitelabel_degrade_notice(requested: str | None, resolved: BrandingPosture) -> str:
    """The operator notice when a requested white-label render was downgraded.

    Empty unless ``whitelabel`` was asked for and the resolution came back as
    something else, which happens only when the install lacks the entitlement.
    A silent downgrade is how a co-branded kit reached a client that had paid
    for white-label, so the caller prints this before rendering.
    """
    asked = (requested or "").strip().lower()
    if asked != BrandingPosture.WHITELABEL.value or resolved is BrandingPosture.WHITELABEL:
        return ""
    return (
        "White-label was requested, but this install does not carry the "
        "whitelabel entitlement, so the deliverable is rendered co-branded "
        '("powered by ADscan"). Enable entitlements.whitelabel in the ADscan '
        "config.json and render again."
    )


# ---------------------------------------------------------------------------
# White-label prose: the ONE place the product name leaves client-facing text.
# ---------------------------------------------------------------------------

#: The product name as it appears in client-facing prose.
BRAND_NAME = "ADscan"
#: What the product name becomes where it is the actor of a sentence.
WHITELABEL_SUBJECT = "the assessment"

# The name used as a modifier after a determiner ("the ADscan AD Audit
# Wordlist", "a new ADscan scan"). The noun after it carries the meaning, so the
# name is dropped; replacing it would read "the the assessment AD Audit Wordlist".
_ATTRIBUTIVE_BRAND_RE = re.compile(
    r"\b(the|this|that|new|every|each|any|another)\s+ADscan\s+(?=[\w(])",
    re.IGNORECASE,
)
# "an ADscan run" -> "a run"; the article is re-chosen for the word that follows.
_INDEFINITE_BRAND_RE = re.compile(r"\b(an?)\s+ADscan\s+(?=(\w))", re.IGNORECASE)
# Whole word only: "ADscanPro" in a URL or an identifier is not prose.
_BRAND_RE = re.compile(r"\bADscan\b")
_SENTENCE_START_RE = re.compile(r"(^\s*|[.!?]\s+|\n\s*)the assessment\b")


def _reword_indefinite(match: re.Match[str]) -> str:
    article = "an" if match.group(2)[:1].lower() in "aeiou" else "a"
    if match.group(1)[:1].isupper():
        article = article.capitalize()
    return f"{article} "


def debrand_text(text: str) -> str:
    """Remove the product name from one client-facing sentence.

    The name as a modifier is dropped ("a new ADscan scan" -> "a new scan");
    the name as an actor becomes "the assessment", with sentence case restored
    where it opened a sentence. Strings without the name, ``data:`` URIs and
    identifiers that merely contain it ("ADscanPro", a lab account named
    ``adscan``) are returned unchanged.
    """
    if BRAND_NAME not in text or text.startswith("data:"):
        return text
    out = _ATTRIBUTIVE_BRAND_RE.sub(lambda m: f"{m.group(1)} ", text)
    out = _INDEFINITE_BRAND_RE.sub(_reword_indefinite, out)
    out = _BRAND_RE.sub(WHITELABEL_SUBJECT, out)
    return _SENTENCE_START_RE.sub(lambda m: f"{m.group(1)}The assessment", out)


def debrand_prose(obj: Any, branding: str) -> Any:
    """Deep-walk a render context and debrand every string VALUE under white-label.

    The single seam every deliverable (Security Assessment Report, Playbook,
    Coverage Report, Password Hygiene, checklist) runs its assembled context
    through, so catalog, path and remediation copy that names the product as a
    subject cannot reach a white-label document from one surface while another
    is clean. Keys are untouched. No-op for any other posture.
    """
    if branding != BrandingPosture.WHITELABEL.value:
        return obj
    if isinstance(obj, str):
        out = debrand_text(obj)
        if out is obj or type(obj) is str:
            return out
        # A str subclass (Jinja's ``Markup``) keeps its type, so pre-rendered
        # safe HTML is not escaped by the template after the word swap.
        return type(obj)(out)
    if isinstance(obj, dict):
        return {k: debrand_prose(v, branding) for k, v in obj.items()}
    if isinstance(obj, list):
        return [debrand_prose(v, branding) for v in obj]
    if type(obj) is tuple:
        return tuple(debrand_prose(v, branding) for v in obj)
    if isinstance(obj, tuple) and hasattr(obj, "_fields"):
        # A NamedTuple (the diagram ``LegendEntry`` rows carry the state-track
        # legend copy) is walked field by field and rebuilt as its own type.
        return type(obj)(*(debrand_prose(v, branding) for v in obj))
    return obj


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


def whitelabel_downgrade_notice(
    requested: str | None,
    *,
    env: Mapping[str, str] | None = None,
    whitelabel_entitled: bool | None = None,
) -> str | None:
    """The operator warning for a white-label request this install cannot honour.

    :func:`resolve_branding_posture` degrades an un-entitled ``whitelabel`` to
    ``cobrand`` silently, which is right for the render (never fail a delivery)
    but leaves the operator expecting a document without the ADscan mark. Both
    ``deliver`` and ``ci --generate-report`` print this line; ``ci`` prints it
    before the scan so the surprise does not arrive hours later.

    Returns:
        The warning text, or ``None`` when no white-label was requested or the
        install carries the entitlement.
    """
    raw = (requested or (env or {}).get(_ENV_KEY, "") or "").strip().lower()
    if raw != BrandingPosture.WHITELABEL.value:
        return None
    entitled = (
        whitelabel_entitled_from_config() if whitelabel_entitled is None else whitelabel_entitled
    )
    if entitled:
        return None
    return (
        "White-label branding was requested, but this install does not carry the "
        "white-label entitlement: the deliverable will be cobranded (your logo "
        "with a discreet ADscan mark)."
    )


def _default_config_path() -> Path:
    from adscan_core.paths import get_adscan_home_dir

    return get_adscan_home_dir() / "config.json"
