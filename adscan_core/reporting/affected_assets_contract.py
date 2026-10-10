"""The ONE spelling of the keys a finding's affected assets ride under.

A finding's ``details`` carries its affected assets under two reserved keys, and
the name of each is a CONTRACT between the engine that stamps them and every
surface that reads them: the PRO deliverable, the LITE report, the web platform's
ingestion, the finding-alias collapse, and the contextual severity overlay.

WHY THE NAME LIVES HERE
-----------------------
The structured key was declared in ``adscan_internal.services.affected_assets``
and then re-typed as a bare literal by every reader that cannot import the
engine: the LITE-safe alias collapse, the web backend's enrichment, and this
package's severity calculator. Three independent spellings of one contract is a
drift waiting to happen, and it already cost a real defect: the contextual
severity extractor read ``_affected_assets`` (the LEGACY flat key) while
production stamped ``_affected_assets_struct``, so the ~43 Tier-0 elevation rules
in ``adscan_core.cvss.contextual_rules`` could never fire and a finding on a
Tier-0 account rated the same as one on any ordinary user.

``adscan_core`` is importable from the container runtime, the host launcher, the
LITE tier and the web backend (which COPYs this package into its image), so it is
the only layer every reader shares. The engine imports the name FROM here; it is
not re-declared anywhere. A structural test asserts that.
"""

from __future__ import annotations

#: The key under which the engine stamps its typed, correlation-ready affected
#: asset entities: a LIST of dicts carrying ``type`` / ``identifier`` /
#: ``display`` / ``role`` plus the STAMPED privilege ``tier`` (see
#: :mod:`adscan_core.reporting.privilege_tier_labels`). This is the live contract
#: and the shape every new reader should target.
AFFECTED_ASSETS_STRUCT_KEY = "_affected_assets_struct"

#: The LEGACY flat affected-asset key, kept only so a reader still tolerates an
#: older persisted finding (an archived workspace, a report re-rendered offline).
#: Its value is a bare list of display strings, or a mapping of ``users`` /
#: ``hosts`` lists. Nothing writes it on the live path. Never target it in new
#: code; read :data:`AFFECTED_ASSETS_STRUCT_KEY` and fall back to this one.
LEGACY_AFFECTED_ASSETS_KEY = "_affected_assets"

__all__ = [
    "AFFECTED_ASSETS_STRUCT_KEY",
    "LEGACY_AFFECTED_ASSETS_KEY",
]
