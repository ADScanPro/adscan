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


SAMPLES: tuple[SamplePDF, ...] = (
    SamplePDF("Security_Assessment_Report.pdf",    "Security Assessment Report"),
    SamplePDF("AD_Hardening_Playbook.pdf",         "AD Hardening Playbook"),
    SamplePDF("AD_Control_Coverage_Report.pdf",    "AD Control Coverage Report"),
)


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
