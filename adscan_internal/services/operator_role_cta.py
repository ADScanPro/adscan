"""Role-aware commercial CTA lane — re-exported from the ``adscan_core`` SSOT.

The mapping from operator role to CTA lane (``/pro`` vs the Enterprise demo)
moved to :mod:`adscan_core.operator_role` so the host launcher, the container
runtime, and any core panel renderer share one implementation. This module is
kept as a stable import path for existing internal call sites (the
session-summary hint and the domain-compromise victory panel) — see the core
module's docstring for the full mapping rules and robustness contract.
"""

from __future__ import annotations

from adscan_core.operator_role import CtaLane, is_enterprise_lane, resolve_cta_lane  # noqa: F401

__all__ = ["CtaLane", "is_enterprise_lane", "resolve_cta_lane"]
