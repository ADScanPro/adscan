"""Partner-tag format contract — the single definition, dependency-free.

A partner tag is a URL/telemetry-safe slug such as ``acme-mssp``: it starts
with a lowercase letter or digit, then 1-40 more lowercase letters, digits or
hyphens (2-41 characters in total). No uppercase, no spaces, no underscores,
no leading hyphen.

It lives in its own module so the light consumers (the PRO licence model,
which the licence server also imports) do not have to load
:mod:`adscan_core.telemetry`; telemetry re-exports these names unchanged.
"""

from __future__ import annotations

import re

PARTNER_TAG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{1,40}$")

#: Human-readable description of the format, for prompts and error messages.
PARTNER_TAG_FORMAT_HINT = "lowercase letters, digits and hyphens, 2-41 characters"


def validate_partner_tag(tag: object) -> bool:
    """Return True when ``tag`` matches the partner-tag format contract.

    Accepts e.g. ``acme-mssp``; rejects empty strings, uppercase, whitespace,
    odd characters, and tags longer than 41 characters. Non-strings are
    rejected.
    """
    if not isinstance(tag, str):
        return False
    return bool(PARTNER_TAG_PATTERN.match(tag.strip()))


__all__ = ["PARTNER_TAG_FORMAT_HINT", "PARTNER_TAG_PATTERN", "validate_partner_tag"]
