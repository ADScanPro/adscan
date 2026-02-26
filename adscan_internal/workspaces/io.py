from __future__ import annotations

import json
from typing import Any


def read_json_file(path: str) -> dict[str, Any]:
    """Read a JSON file and return its parsed dictionary."""
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, dict):
        return data
    return {}


def write_json_file(path: str, data: dict[str, Any]) -> None:
    """Write a JSON dict to disk with stable formatting."""
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=4, sort_keys=True)


__all__ = [
    "read_json_file",
    "write_json_file",
]
