"""Engagement state primitives shared by the CLI engine and the web backend.

Pure, dependency-light (stdlib and ``typing`` only): the web backend and the
appliance bundle import this package, so nothing here may import
``adscan_internal`` or any engine/native-stack module.
"""

from __future__ import annotations

#: Schema tag written into ``coverage.json``.
COVERAGE_SCHEMA = "adscan.coverage/1"

#: Wildcard ``domain_id`` for a check whose coverage applies to every domain of
#: the run (a run-wide check recorded without a domain scope).
ALL_DOMAINS = "*"
