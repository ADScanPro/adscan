"""Locator for the bundled Client Deliverable Kit sample PDFs.

The sample PDFs ship inside the binary (``--add-data`` in
``build_adscan.sh``) and inside the LITE source tree (``adscan_internal``
is copied wholesale by ``Dockerfile.runtime``). They are also declared as
package-data in :file:`pyproject.toml` so installed wheels carry them.

Both LITE and PRO use these files:

* LITE — copies them into ``demo-output/pro-preview/`` so the operator
  sees a real client-grade kit alongside the LITE engine output.
* PRO — used as a graceful fallback when the live generator cannot run
  (e.g. Chromium missing). Not used in the happy path.

There is intentionally no fallback to a workspace-relative path — the
kit lives next to the code so it is reproducible across LITE/PRO and
across host/container.

The LIST is derived from ``adscan deliver``'s own kit definition, not
restated here. A hand-written copy sat at three entries for the whole of the
release that took the kit to four, so the fourth document could be baked into
this directory by the regeneration script and still never be offered to
anyone. Deriving it means the only way to add a kit document is to add it to
the kit.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


@dataclass(frozen=True)
class SamplePDF:
    """One bundled sample PDF.

    Attributes:
        filename: On-disk filename (matches the canonical kit names).
        title: Human-readable title used in panels and READMEs.
    """

    filename: str
    title: str


def _derive_samples() -> tuple[SamplePDF, ...]:
    """Build the sample list from ``deliver``'s canonical kit.

    ``deliver`` is import-safe from LITE: its module-level imports are
    ``adscan_core`` plus two LITE-side ``adscan_internal`` modules, and the PRO
    renderers it drives are imported lazily inside the render functions. A
    failure here still leaves the demo working, because the staging step skips
    any filename it cannot find on disk.
    """
    try:
        from adscan_internal.cli.deliver import _KIT
    except Exception:  # noqa: BLE001 — a locator never breaks the demo
        return ()
    return tuple(SamplePDF(item.filename, item.title) for item in _KIT)


#: Canonical bundled-sample list, in kit order. One entry per document
#: ``adscan deliver`` can ship. The conditional AD Password Hygiene Report is
#: listed here but is present on disk only when the workspace the samples were
#: baked from actually recovered credentials; the staging step skips a filename
#: it cannot find, so an absent conditional document is a quiet no-op rather
#: than a broken demo.
SAMPLES: tuple[SamplePDF, ...] = _derive_samples()


def samples_dir() -> Path:
    """Return the directory that holds the bundled sample PDFs.

    Resolves to ``adscan_internal/assets/report_samples`` regardless of
    whether ADscan is running from source (LITE) or from a PyInstaller
    binary (PRO). PyInstaller's ``--add-data`` preserves the relative
    path under ``_MEIPASS``, so a parent walk works in both cases.
    """
    return Path(__file__).resolve().parents[1] / "assets" / "report_samples"


def all_samples() -> Sequence[SamplePDF]:
    """Return the canonical sample list."""
    return SAMPLES


__all__ = ("SamplePDF", "SAMPLES", "samples_dir", "all_samples")
