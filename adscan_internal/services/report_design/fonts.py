"""Report fonts: static faces shipped with ADscan, never fetched at render time.

Every ADscan document (the deliverable kit, the LITE exposure report, the
progress report, the bonus documents) is drawn in a small set of open-licence
families. They used to come from the Google Fonts service, which meant a PDF
render made an outbound connection and an air-gapped appliance printed in
fallback faces. They now ship inside the package, in ``_fonts/``, and this
module is the single source of truth for them.

Three things live here.

**Which faces a theme declares** (:data:`THEME_FACES`). Each theme declares
exactly the faces its Google request used to, family by family and weight by
weight, so CSS font matching picks the same face for every element it did
before. A weight the CSS asks for that is not declared (``font-weight: 800`` on
Source Serif 4, say) still resolves to the same neighbour it always did.

**How a document references them.** :func:`font_face_css` emits ``@font-face``
rules whose ``src`` is an ``adscan-font:`` reference. That scheme is inert on
purpose: a browser opening an HTML artifact cannot load it and makes no
network request for it, it simply falls back to the next family in the stack.
Two resolvers turn the reference into bytes:

* the shared Chromium engine (``report_engines.chromium_engine``) maps it onto a
  reserved ``.invalid`` origin and answers those requests from this package
  through request interception, while refusing every other external request;
* :func:`embed_report_fonts` inlines the faces as ``data:`` URIs, for an HTML
  artifact that should carry its typography with it.

**Optical sizes.** Fraunces and Source Serif 4 carry an optical-size axis, and
Chrome sets it from each element's font size when the font is variable. A
static face is one instance, so drawing a 52pt headline and a 12pt caption from
the same file changes their proportions, by up to a fifth of the line width at
the extremes (measured). Headless Chrome cannot embed a variable instance in a
PDF either: it rasterises it into a Type 3 font. So the kit carries one static
per (face, optical size) the documents use, and the engine binds each element to
the instance for its own size before printing (:data:`OPTICAL_BINDER_JS`). A
size the kit has no instance for resolves to the nearest one of the same weight
and style.

The faces are built by ``scripts/build_report_fonts.py`` (which owns the list of
optical sizes) and listed in ``_fonts/manifest.json``. Every family is under the
SIL Open Font License 1.1; each licence ships beside the faces.

LITE-safe: standard library only, nothing from ``adscan_internal.pro``.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from typing import Any
from urllib.parse import quote, unquote, urlsplit, parse_qs

_DESIGN_PACKAGE = "adscan_internal.services.report_design"
_FONTS_DIR = "_fonts"
MANIFEST_NAME = "manifest.json"

#: The inert reference a stylesheet carries. Not a network scheme in any
#: browser, so an HTML artifact opened anywhere never fetches through it.
FONT_REF_SCHEME = "adscan-font:"

#: The origin the Chromium engine maps references onto. ``.invalid`` is
#: reserved (RFC 2606) and never resolves; the engine answers it from this
#: package before any name resolution would happen, and refuses everything else.
ENGINE_FONT_ORIGIN = "https://fonts.adscan.invalid"


@dataclass(frozen=True)
class FontFace:
    """One declared face: what CSS font matching sees."""

    family: str
    style: str
    weight: int


def _faces(family: str, normal: tuple[int, ...], italic: tuple[int, ...] = ()) -> tuple[FontFace, ...]:
    return tuple(FontFace(family, "normal", w) for w in normal) + tuple(
        FontFace(family, "italic", w) for w in italic
    )


#: The faces each theme declares. Mirrors, face for face, the Google request
#: each theme used to make, so font matching is unchanged, plus two deliberate
#: glyph fallbacks, both already in the kit and listed second in their stack, so
#: they only draw a character the first face lacks:
#:
#: * JetBrains Mono behind Spline Sans Mono, which has no arrows or comparison
#:   signs: a mono label such as "Security Assessment Report" plus an arrow fell
#:   through to the system DejaVu for that glyph.
#: * Inter behind Archivo, which has no check mark, ballot box or warning sign:
#:   "(check) No major non-conformities identified" printed its mark in DejaVu.
THEME_FACES: dict[str, tuple[FontFace, ...]] = {
    "editorial": (
        *_faces("Fraunces", (400, 500, 600, 700, 800, 900), (400, 600)),
        *_faces("Spectral", (400, 500, 600, 700, 800), (400,)),
        *_faces("Archivo", (400, 500, 600, 700, 800, 900)),
        *_faces("Inter", (400, 500, 600, 700, 800, 900)),
        *_faces("Spline Sans Mono", (400, 500, 600, 700)),
        *_faces("JetBrains Mono", (400, 500, 600, 700)),
    ),
    "corporate_light": (
        *_faces("Source Serif 4", (400, 500, 600, 700, 900), (400, 600)),
        *_faces("Inter", (400, 500, 600, 700, 800, 900)),
        *_faces("JetBrains Mono", (400, 500, 600, 700)),
    ),
}

#: Families with an optical-size axis, and the axis range. Chrome sets the axis
#: to the element's font size in CSS pixels, clamped to this range.
OPTICAL_SIZE_AXES: dict[str, tuple[float, float]] = {
    "Fraunces": (9.0, 144.0),
    "Source Serif 4": (8.0, 60.0),
}

#: The optical size an optical family is drawn at where nothing binds it per
#: element: an HTML artifact opened in a browser, and the first layout pass in
#: the engine. A heading size, because both families are display faces here.
BASE_OPTICAL_SIZE: dict[str, float] = {
    "Fraunces": 21.333,
    "Source Serif 4": 21.333,
}


@dataclass(frozen=True)
class KitFile:
    """One file of the kit, as listed in the manifest."""

    family: str
    style: str
    weight: int
    opsz: float | None
    file: str


def _fonts_root() -> Any:
    return files(_DESIGN_PACKAGE).joinpath(_FONTS_DIR)


@lru_cache(maxsize=1)
def load_manifest() -> tuple[KitFile, ...]:
    """Return every file the kit ships. Empty when the kit is not installed."""
    try:
        raw = json.loads(_fonts_root().joinpath(MANIFEST_NAME).read_text(encoding="utf-8"))
    except (FileNotFoundError, ModuleNotFoundError, OSError, ValueError):
        return ()
    entries: list[KitFile] = []
    for item in raw.get("faces", []):
        opsz = item.get("opsz")
        entries.append(
            KitFile(
                family=str(item["family"]),
                style=str(item["style"]),
                weight=int(item["weight"]),
                opsz=float(opsz) if opsz is not None else None,
                file=str(item["file"]),
            )
        )
    return tuple(entries)


@lru_cache(maxsize=None)
def _read_font_file(filename: str) -> bytes | None:
    try:
        return _fonts_root().joinpath(filename).read_bytes()
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return None


def clamp_optical_size(family: str, size_px: float) -> float:
    """The optical size Chrome would use for ``family`` at ``size_px``."""
    low, high = OPTICAL_SIZE_AXES[family]
    return round(min(high, max(low, size_px)), 3)


def resolve_face_file(
    family: str, style: str, weight: int, opsz: float | None = None
) -> tuple[KitFile, bool] | None:
    """Pick the kit file for one face, and say whether it is an exact match.

    For an optical family the file nearest to ``opsz`` (or to the family's base
    optical size) is chosen among the files of the SAME style and weight, so a
    missing size never changes the weight or the slant, only the optical size.

    Returns:
        ``(file, exact)`` or ``None`` when the kit has no file for that face.
    """
    candidates = [
        kit
        for kit in load_manifest()
        if kit.family == family and kit.style == style and kit.weight == weight
    ]
    if not candidates:
        return None
    if family not in OPTICAL_SIZE_AXES:
        return candidates[0], True
    target = clamp_optical_size(family, opsz if opsz is not None else BASE_OPTICAL_SIZE[family])
    best = min(candidates, key=lambda kit: (abs((kit.opsz or 0.0) - target), kit.opsz or 0.0))
    return best, opsz is not None and abs((best.opsz or 0.0) - target) < 0.0015


def _face_ref(face: FontFace) -> str:
    return f"{quote(face.family)}/{face.style}/{face.weight}"


def font_face_css(theme: str) -> str:
    """Return the ``@font-face`` rules for ``theme``'s faces.

    The ``src`` of each rule is an inert ``adscan-font:`` reference; see the
    module docstring for who resolves it. Unknown themes get no rules.
    """
    rules = [
        "@font-face{"
        f"font-family:'{face.family}';font-style:{face.style};"
        f"font-weight:{face.weight};font-display:block;"
        f'src:url("{FONT_REF_SCHEME}{_face_ref(face)}") format("woff2")'
        "}"
        for face in THEME_FACES.get(theme, ())
    ]
    if not rules:
        return ""
    header = (
        "/* ADscan report faces, shipped with the product and never fetched.\n"
        "   Their adscan-font references are resolved by the report engine, or inlined\n"
        "   by embed_report_fonts(); a browser on its own ignores them. */"
    )
    return header + "\n" + "\n".join(rules)


_REF_RE = re.compile(re.escape(FONT_REF_SCHEME) + r"([^\"')\s]+)")


def _parse_ref(ref: str) -> tuple[str, str, int, float | None] | None:
    """``Family/style/weight[?opsz=N]`` → its parts, or ``None`` if malformed."""
    path, _, query = ref.partition("?")
    parts = path.strip("/").split("/")
    if len(parts) != 3:
        return None
    family, style, weight = unquote(parts[0]), parts[1], parts[2]
    if style not in ("normal", "italic") or not weight.isdigit():
        return None
    opsz: float | None = None
    values = parse_qs(query).get("opsz")
    if values:
        try:
            opsz = float(values[0])
        except ValueError:
            opsz = None
    return family, style, int(weight), opsz


@lru_cache(maxsize=None)
def _data_uri_for_ref(ref: str) -> str | None:
    parsed = _parse_ref(ref)
    if parsed is None:
        return None
    resolved = resolve_face_file(*parsed)
    if resolved is None:
        return None
    body = _read_font_file(resolved[0].file)
    if body is None:
        return None
    return "data:font/woff2;base64," + base64.b64encode(body).decode("ascii")


def embed_report_fonts(html: str) -> str:
    """Inline every ``adscan-font:`` reference in ``html`` as a ``data:`` URI.

    For an HTML artifact written to disk that should carry its own typography.
    A reference the kit cannot resolve is left as it is, which a browser
    ignores, so the result never depends on the network either way.
    """

    def _swap(match: re.Match[str]) -> str:
        return _data_uri_for_ref(match.group(1)) or match.group(0)

    return _REF_RE.sub(_swap, html)


def route_font_refs_to_engine(html: str) -> str:
    """Point ``adscan-font:`` references at the engine's reserved origin."""
    return html.replace(FONT_REF_SCHEME, ENGINE_FONT_ORIGIN + "/")


@dataclass(frozen=True)
class EngineFontResponse:
    """What the engine answers for one font request."""

    body: bytes
    kit_file: str
    exact: bool


def resolve_engine_font_request(url: str) -> EngineFontResponse | None:
    """Answer a request on :data:`ENGINE_FONT_ORIGIN`, or ``None`` if unknown."""
    if not url.startswith(ENGINE_FONT_ORIGIN + "/"):
        return None
    split = urlsplit(url)
    ref = split.path.lstrip("/") + (f"?{split.query}" if split.query else "")
    parsed = _parse_ref(ref)
    if parsed is None:
        return None
    resolved = resolve_face_file(*parsed)
    if resolved is None:
        return None
    kit, exact = resolved
    body = _read_font_file(kit.file)
    if body is None:
        return None
    # A request without an optical size is a base face: exact by definition.
    return EngineFontResponse(body=body, kit_file=kit.file, exact=exact or parsed[3] is None)


#: Binds every element drawn in an optical family to the instance for its own
#: size, the way Chrome's automatic optical sizing would with a variable font.
#:
#: For each such element (and each styled pseudo-element) it computes the
#: optical size from the computed font size, and prepends a family named for
#: that size to the element's own stack. Each sized family re-declares exactly
#: the faces the document declared for the base family, with the same
#: descriptors, so font matching still picks the same weight and slant; only
#: the file behind the face changes. Everything is measured before anything is
#: changed, so a parent's new family cannot leak into a child's measurement.
#:
#: Returns the font loads to wait for, as CSS ``font`` shorthands.
OPTICAL_BINDER_JS = r"""
({axes, origin}) => {
  const strip = (s) => s.trim().replace(/^["']|["']$/g, '');
  const firstFamily = (stack) => strip(stack.split(',')[0] || '');
  const quoteFamily = (s) => '"' + s.replace(/["\\]/g, '\\$&') + '"';
  const declared = new Map();
  for (const face of document.fonts) {
    const family = strip(face.family);
    if (!(family in axes)) continue;
    if (!declared.has(family)) declared.set(family, []);
    declared.get(family).push(face);
  }
  const sized = (family, px) => {
    const [low, high] = axes[family];
    const opsz = Math.round(Math.min(high, Math.max(low, px)) * 1000) / 1000;
    return {name: `${family} opsz ${opsz}`, family, opsz};
  };
  const PSEUDOS = ['::before', '::after', '::marker', '::first-letter', '::first-line'];
  const plan = [];
  const pseudoPlan = [];
  const elements = document.querySelectorAll('*');
  for (const el of elements) {
    const cs = getComputedStyle(el);
    const family = firstFamily(cs.fontFamily);
    let hostName = null;
    if (declared.has(family)) {
      const target = sized(family, parseFloat(cs.fontSize));
      hostName = target.name;
      plan.push([el, target, cs.fontFamily, cs.fontStyle, cs.fontWeight]);
    }
    for (const pseudo of PSEUDOS) {
      const ps = getComputedStyle(el, pseudo);
      if ((pseudo === '::before' || pseudo === '::after') &&
          (ps.content === 'none' || ps.content === 'normal')) continue;
      if (pseudo === '::marker' && cs.display !== 'list-item') continue;
      const pFamily = firstFamily(ps.fontFamily);
      if (!declared.has(pFamily)) continue;
      const target = sized(pFamily, parseFloat(ps.fontSize));
      // ::first-letter / ::first-line compute to the host's values when no rule
      // styles them; binding those would only repeat the host's binding.
      if ((pseudo === '::first-letter' || pseudo === '::first-line') &&
          target.name === hostName && ps.fontFamily === cs.fontFamily) continue;
      pseudoPlan.push([el, pseudo, target, ps.fontFamily, ps.fontStyle, ps.fontWeight]);
    }
  }
  const needed = new Map();
  const loads = new Set();
  for (const [el, target, stack, style, weight] of plan) {
    el.style.setProperty('font-family', `${quoteFamily(target.name)}, ${stack}`, 'important');
    needed.set(target.name, target);
    loads.add(`${style} ${weight} 16px ${quoteFamily(target.name)}`);
  }
  const pseudoRules = [];
  pseudoPlan.forEach(([el, pseudo, target, stack, style, weight], index) => {
    el.setAttribute('data-adscan-opsz-' + index, '');
    pseudoRules.push(`[data-adscan-opsz-${index}]${pseudo}{font-family:${quoteFamily(target.name)}, ${stack} !important}`);
    needed.set(target.name, target);
    loads.add(`${style} ${weight} 16px ${quoteFamily(target.name)}`);
  });
  const faceRules = [];
  for (const target of needed.values()) {
    for (const face of declared.get(target.family)) {
      const src = `${origin}/${encodeURIComponent(target.family)}/${face.style}/${face.weight}?opsz=${target.opsz}`;
      faceRules.push(
        `@font-face{font-family:${quoteFamily(target.name)};font-style:${face.style};` +
        `font-weight:${face.weight};font-stretch:${face.stretch};unicode-range:${face.unicodeRange};` +
        `font-display:block;src:url("${src}") format("woff2")}`);
    }
  }
  if (faceRules.length || pseudoRules.length) {
    const style = document.createElement('style');
    style.id = 'adscan-optical-sizes';
    style.textContent = faceRules.concat(pseudoRules).join('\n');
    document.head.appendChild(style);
  }
  return {elements: plan.length, pseudos: pseudoPlan.length, families: needed.size, loads: [...loads]};
}
"""

#: Waits until every face a bound element needs has loaded. Font loads start
#: only when text needs them, so this asks for each one explicitly through the
#: same matching the layout uses, then returns the faces that failed.
OPTICAL_LOADS_JS = r"""
async (loads) => {
  document.body && document.body.getBoundingClientRect();
  await Promise.all(loads.map((spec) => document.fonts.load(spec).catch(() => [])));
  await document.fonts.ready;
  return [...document.fonts].filter((f) => f.status === 'error')
    .map((f) => `${f.family} ${f.style} ${f.weight}`);
}
"""


__all__ = [
    "BASE_OPTICAL_SIZE",
    "ENGINE_FONT_ORIGIN",
    "EngineFontResponse",
    "FONT_REF_SCHEME",
    "FontFace",
    "KitFile",
    "MANIFEST_NAME",
    "OPTICAL_BINDER_JS",
    "OPTICAL_LOADS_JS",
    "OPTICAL_SIZE_AXES",
    "THEME_FACES",
    "clamp_optical_size",
    "embed_report_fonts",
    "font_face_css",
    "load_manifest",
    "resolve_engine_font_request",
    "resolve_face_file",
    "route_font_refs_to_engine",
]
