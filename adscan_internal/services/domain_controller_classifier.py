"""Domain controller role helpers.

Centralizes the distinction between writable domain controllers and read-only
domain controllers (RODCs) for both attack-path target classification and
post-exploitation UX decisions.
"""

from __future__ import annotations

from typing import Any


RID_DOMAIN_CONTROLLERS = 516
RID_READ_ONLY_DOMAIN_CONTROLLERS = 521
RODC_TARGET_PRIORITY_RANK = 25


def _coerce_boolish(value: object) -> bool:
    """Return True when *value* clearly represents a boolean true."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    return False


def node_is_rodc_computer(node: dict[str, Any]) -> bool:
    """Return True when an attack-graph node represents an RODC computer."""
    kind = str(node.get("kind") or "")
    if kind != "Computer":
        return False

    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    for key in ("msDS-isRODC", "msds-isrodc", "isRODC", "isrodc"):
        if _coerce_boolish(node.get(key)) or _coerce_boolish(props.get(key)):
            return True
    return False
