"""Shared lab-context normalization for telemetry across launcher/runtime."""

from __future__ import annotations

import re
from typing import Any


_PROVIDER_SLUG_MAP: dict[str, str] = {
    "hackthebox": "htb",
    "tryhackme": "thm",
    "dockerlabs": "dockerlabs",
    "vulnhub": "vulnhub",
    "goad": "goad",
    "proving_grounds": "pg",
    "proving-grounds": "pg",
    "proving grounds": "pg",
    "other": "other",
    "local_test": "local_test",
}


def normalize_workspace_type(value: str | None) -> str | None:
    """Normalize workspace type to a telemetry-safe canonical value."""
    if value is None:
        return None
    normalized = str(value).strip().lower()
    if not normalized:
        return None
    return normalized


def normalize_lab_provider(value: str | None) -> str | None:
    """Normalize a lab provider name to a telemetry-safe canonical value."""
    if value is None:
        return None
    normalized = str(value).strip().lower()
    if not normalized:
        return None
    normalized = re.sub(r"\s+", "_", normalized)
    return normalized


def normalize_lab_name(value: str | None) -> str | None:
    """Normalize a lab name to a canonical telemetry value."""
    if value is None:
        return None
    normalized = str(value).strip().lower()
    if not normalized:
        return None
    return normalized


def build_lab_slug(
    lab_provider: str | None,
    lab_name: str | None,
    lab_name_whitelisted: bool | None = None,
) -> str | None:
    """Build canonical lab slug `provider/lab_name` for telemetry.

    When the provider is known but the machine is unknown or intentionally not
    accepted into the public catalog, return `provider/unknown`.
    """
    provider_norm = normalize_lab_provider(lab_provider)
    lab_name_norm = normalize_lab_name(lab_name)
    if not provider_norm:
        return None

    provider_slug = _PROVIDER_SLUG_MAP.get(provider_norm, provider_norm)
    if not lab_name_norm or lab_name_whitelisted is not True:
        return f"{provider_slug}/unknown"
    lab_slug = re.sub(r"\s+", "_", lab_name_norm)
    return f"{provider_slug}/{lab_slug}"


def build_lab_telemetry_fields(
    *,
    lab_provider: str | None,
    lab_name: str | None,
    lab_name_whitelisted: bool | None,
    include_slug: bool,
    lab_slug: str | None = None,
) -> dict[str, Any]:
    """Build centralized telemetry fields for lab/workspace context.

    Privacy policy:
    - `lab_name` is included only when explicitly whitelisted.
    - `lab_name_whitelisted` is included only when a lab name exists.
    - `lab_slug` is emitted only from catalog-safe values. Unknown/custom labs
      are normalized to `provider/unknown`.
    """
    fields: dict[str, Any] = {}

    provider_norm = normalize_lab_provider(lab_provider)
    if provider_norm:
        fields["lab_provider"] = provider_norm

    name_norm = normalize_lab_name(lab_name)
    whitelisted_flag: bool | None
    if lab_name is None:
        whitelisted_flag = None
    else:
        whitelisted_flag = bool(lab_name_whitelisted)

    if name_norm and whitelisted_flag is True:
        fields["lab_name"] = name_norm
    if name_norm is not None and whitelisted_flag is not None:
        fields["lab_name_whitelisted"] = whitelisted_flag

    if include_slug:
        slug_value = None
        if whitelisted_flag is True:
            slug_value = normalize_lab_name(lab_slug) if lab_slug else None
            if not slug_value:
                slug_value = build_lab_slug(provider_norm, name_norm, True)
        elif provider_norm:
            slug_value = build_lab_slug(provider_norm, None, False)
        if slug_value:
            fields["lab_slug"] = slug_value

    return fields


def build_workspace_telemetry_fields(
    *,
    workspace_type: str | None,
) -> dict[str, Any]:
    """Build normalized workspace context fields for telemetry payloads."""
    fields: dict[str, Any] = {}
    workspace_type_norm = normalize_workspace_type(workspace_type)
    if workspace_type_norm:
        fields["workspace_type"] = workspace_type_norm
    return fields
