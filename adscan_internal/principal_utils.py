"""Helpers for normalizing and classifying AD principal names."""

from __future__ import annotations


def normalize_machine_account(value: str) -> str:
    """Return a normalized machine account name ending with '$'.

    This strips domain prefixes (DOMAIN\\user), UPN suffixes, and FQDNs before
    ensuring the trailing '$'.
    """
    raw = str(value or "").strip()
    if "\\" in raw:
        raw = raw.split("\\", 1)[1]
    if "@" in raw:
        raw = raw.split("@", 1)[0]
    if "." in raw:
        raw = raw.split(".", 1)[0]
    raw = raw.strip()
    if raw and not raw.endswith("$"):
        raw = f"{raw}$"
    return raw


def is_machine_account(value: str) -> bool:
    """Return True if the value looks like a machine account (ends with '$')."""
    raw = str(value or "").strip()
    if "\\" in raw:
        raw = raw.split("\\", 1)[1]
    if "@" in raw:
        raw = raw.split("@", 1)[0]
    return raw.endswith("$")


__all__ = ["normalize_machine_account", "is_machine_account"]
