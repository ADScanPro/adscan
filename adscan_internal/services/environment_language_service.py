"""Helpers to infer and persist coarse environment language hints.

This module intentionally keeps the logic heuristic and side-effect free except
for explicit persistence into ``shell.domains_data``. There is no universally
reliable AD attribute that tells us the local built-in administrator name for
every workstation/server, so we resolve a best-effort domain-wide default and
reuse it consistently.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from adscan_internal.services.membership_snapshot import load_membership_snapshot
from adscan_internal.services.ldap_query_service import query_shell_ldap_attribute_values
from adscan_internal.workspaces import domain_subpath


_LOCAL_ADMIN_VARIANTS_BY_LANGUAGE: dict[str, list[str]] = {
    "en": ["Administrator"],
    "es": ["Administrador", "Administrator"],
    "fr": ["Administrateur", "Administrator"],
    "de": ["Administrator"],
    "it": ["Amministratore", "Administrator"],
    "pt": ["Administrador", "Administrator"],
    "nl": ["Administrator", "Beheerder"],
    "pl": ["Administrator"],
    "ru": ["Администратор", "Administrator"],
    "tr": ["Yönetici", "Administrator"],
    "cs": ["Správce", "Administrator"],
    "hu": ["Rendszergazda", "Administrator"],
    "sv": ["Administratör", "Administrator"],
}

_ADMIN_VARIANT_TO_LANGUAGE: dict[str, str] = {}
for _language_code, _variants in _LOCAL_ADMIN_VARIANTS_BY_LANGUAGE.items():
    for _variant in _variants:
        normalized = str(_variant).strip().casefold()
        if normalized and normalized not in _ADMIN_VARIANT_TO_LANGUAGE:
            _ADMIN_VARIANT_TO_LANGUAGE[normalized] = _language_code


@dataclass(frozen=True)
class EnvironmentLanguageResolution:
    """Resolved language hint and built-in administrator candidates."""

    language_code: str
    built_in_admin_default: str
    candidate_names: list[str]
    source: str


def _normalize_language_code(value: str | None) -> str | None:
    """Normalize a persisted language code to the canonical short form."""
    raw = str(value or "").strip().lower()
    if not raw:
        return None
    primary = raw.split("-", 1)[0].split("_", 1)[0]
    if primary in _LOCAL_ADMIN_VARIANTS_BY_LANGUAGE:
        return primary
    return None


def infer_language_code_from_admin_name(value: str | None) -> str | None:
    """Infer a language code from a localized builtin-admin candidate name."""
    normalized = str(value or "").strip().casefold()
    if not normalized:
        return None
    return _ADMIN_VARIANT_TO_LANGUAGE.get(normalized)


def _build_resolution(
    *,
    language_code: str,
    preferred_name: str | None = None,
    source: str,
) -> EnvironmentLanguageResolution:
    """Build a stable resolution object."""
    variants = list(_LOCAL_ADMIN_VARIANTS_BY_LANGUAGE.get(language_code, ["Administrator"]))
    preferred = str(preferred_name or "").strip()
    if preferred:
        canonical_preferred = next(
            (variant for variant in variants if variant.casefold() == preferred.casefold()),
            preferred,
        )
        deduped = [preferred]
        deduped = [canonical_preferred]
        for variant in variants:
            if variant.casefold() != canonical_preferred.casefold():
                deduped.append(variant)
        variants = deduped
    return EnvironmentLanguageResolution(
        language_code=language_code,
        built_in_admin_default=variants[0],
        candidate_names=variants,
        source=source,
    )


def _iter_known_domain_usernames(domain_data: dict[str, Any]) -> list[str]:
    """Return usernames already observed for one domain."""
    values: list[str] = []
    for key in (
        "builtin_administrator_name",
        "username",
    ):
        raw = str(domain_data.get(key) or "").strip()
        if raw:
            values.append(raw)

    credentials = domain_data.get("credentials", {})
    if isinstance(credentials, dict):
        values.extend(str(username).strip() for username in credentials.keys() if str(username).strip())

    users = domain_data.get("users", [])
    if isinstance(users, list):
        values.extend(str(username).strip() for username in users if str(username).strip())

    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        key = value.casefold()
        if key in seen:
            continue
        seen.add(key)
        ordered.append(value)
    return ordered


def _extract_principal_name(value: str) -> str:
    """Extract the principal name portion from common label formats."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    principal = raw.split("@", 1)[0].split("\\", 1)[-1].strip()
    return principal.rstrip("$").strip()


def _iter_membership_snapshot_usernames(shell: Any, *, domain: str) -> list[str]:
    """Return usernames inferred from local ``memberships.json``."""
    snapshot = load_membership_snapshot(shell, domain)
    if not isinstance(snapshot, dict):
        return []

    values: list[str] = []
    for key in ("user_to_groups", "group_to_parents", "label_to_sid"):
        mapping = snapshot.get(key)
        if not isinstance(mapping, dict):
            continue
        for principal in mapping.keys():
            candidate = _extract_principal_name(str(principal))
            if candidate:
                values.append(candidate)

    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        normalized = value.casefold()
        if normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(value)
    return ordered


def _iter_workspace_list_usernames(
    shell: Any,
    *,
    domain: str,
    filename: str,
) -> list[str]:
    """Return usernames from a simple one-entry-per-line workspace list file."""
    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "").strip()
    domains_dir = str(getattr(shell, "domains_dir", "domains") or "domains").strip()
    if not workspace_dir:
        return []

    path = Path(domain_subpath(workspace_dir, domains_dir, domain, filename))
    if not path.exists() or not path.is_file():
        return []

    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []

    seen: set[str] = set()
    ordered: list[str] = []
    for raw_line in lines:
        candidate = _extract_principal_name(raw_line)
        if not candidate:
            continue
        normalized = candidate.casefold()
        if normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(candidate)
    return ordered


def _iter_bloodhound_usernames(shell: Any, *, domain: str) -> list[str]:
    """Return usernames inferred from the active BloodHound service."""
    service_getter = getattr(shell, "_get_bloodhound_service", None)
    if not callable(service_getter):
        return []

    try:
        service = service_getter()
    except Exception:
        return []
    if service is None or not hasattr(service, "get_users"):
        return []

    try:
        raw_users = service.get_users(domain=domain)  # type: ignore[call-arg]
    except Exception:
        return []
    if not isinstance(raw_users, list):
        return []

    seen: set[str] = set()
    ordered: list[str] = []
    for raw_user in raw_users:
        candidate = _extract_principal_name(str(raw_user))
        if not candidate:
            continue
        normalized = candidate.casefold()
        if normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(candidate)
    return ordered


def _iter_ldap_usernames(shell: Any, *, domain: str) -> list[str]:
    """Return usernames inferred from a lightweight authenticated LDAP query."""
    domain_data = getattr(shell, "domains_data", {}).get(domain, {}) or {}
    pdc = str(domain_data.get("pdc") or "").strip()
    username = str(domain_data.get("username") or "").strip()
    password = str(domain_data.get("password") or "").strip()
    if not pdc or not username or not password:
        return []

    try:
        values = query_shell_ldap_attribute_values(
            shell,
            domain=domain,
            ldap_filter="(&(objectCategory=person)(objectClass=user))",
            attribute="samAccountName",
            auth_username=username,
            auth_password=password,
            pdc=pdc,
            prefer_kerberos=True,
            allow_ntlm_fallback=True,
            operation_name="environment language username sample",
        )
    except Exception:
        return []
    if values is None:
        return []

    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        candidate = _extract_principal_name(str(value))
        if not candidate:
            continue
        normalized = candidate.casefold()
        if normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(candidate)
    return ordered


def persist_environment_language_hint(
    shell: Any,
    *,
    domain: str,
    language_code: str | None = None,
    built_in_admin_name: str | None = None,
) -> None:
    """Persist resolved environment-language hints into ``domains_data``."""
    if domain not in getattr(shell, "domains_data", {}):
        return
    domain_data = shell.domains_data.setdefault(domain, {})
    normalized_language = _normalize_language_code(language_code)
    if normalized_language:
        domain_data["environment_language"] = normalized_language
    if built_in_admin_name and str(built_in_admin_name).strip():
        domain_data["builtin_administrator_name"] = str(built_in_admin_name).strip()


def resolve_environment_language(
    shell: Any,
    *,
    domain: str,
) -> EnvironmentLanguageResolution:
    """Resolve a best-effort environment language hint for one domain.

    Resolution order:
    1. Persisted ``environment_language`` / ``builtin_administrator_name``
    2. Known usernames already observed in ``domains_data``
    3. Fallback to English / ``Administrator``
    """
    domain_data = getattr(shell, "domains_data", {}).get(domain, {}) or {}

    persisted_language = _normalize_language_code(domain_data.get("environment_language"))
    persisted_admin_name = str(domain_data.get("builtin_administrator_name") or "").strip()
    if persisted_language:
        return _build_resolution(
            language_code=persisted_language,
            preferred_name=persisted_admin_name or None,
            source="persisted_language",
        )

    if persisted_admin_name:
        inferred_language = _ADMIN_VARIANT_TO_LANGUAGE.get(persisted_admin_name.casefold(), "en")
        resolution = _build_resolution(
            language_code=inferred_language,
            preferred_name=persisted_admin_name,
            source="persisted_admin_name",
        )
        persist_environment_language_hint(
            shell,
            domain=domain,
            language_code=resolution.language_code,
            built_in_admin_name=resolution.built_in_admin_default,
        )
        return resolution

    for known_username in _iter_known_domain_usernames(domain_data):
        inferred_language = _ADMIN_VARIANT_TO_LANGUAGE.get(known_username.casefold())
        if not inferred_language:
            continue
        resolution = _build_resolution(
            language_code=inferred_language,
            preferred_name=known_username,
            source="observed_domain_username",
        )
        persist_environment_language_hint(
            shell,
            domain=domain,
            language_code=resolution.language_code,
            built_in_admin_name=resolution.built_in_admin_default,
        )
        return resolution

    for known_username in _iter_membership_snapshot_usernames(shell, domain=domain):
        inferred_language = _ADMIN_VARIANT_TO_LANGUAGE.get(known_username.casefold())
        if not inferred_language:
            continue
        resolution = _build_resolution(
            language_code=inferred_language,
            preferred_name=known_username,
            source="memberships_snapshot",
        )
        persist_environment_language_hint(
            shell,
            domain=domain,
            language_code=resolution.language_code,
            built_in_admin_name=resolution.built_in_admin_default,
        )
        return resolution

    for known_username in _iter_workspace_list_usernames(
        shell,
        domain=domain,
        filename="admins.txt",
    ):
        inferred_language = _ADMIN_VARIANT_TO_LANGUAGE.get(known_username.casefold())
        if not inferred_language:
            continue
        resolution = _build_resolution(
            language_code=inferred_language,
            preferred_name=known_username,
            source="admins_txt",
        )
        persist_environment_language_hint(
            shell,
            domain=domain,
            language_code=resolution.language_code,
            built_in_admin_name=resolution.built_in_admin_default,
        )
        return resolution

    for known_username in _iter_workspace_list_usernames(
        shell,
        domain=domain,
        filename="enabled_users.txt",
    ):
        inferred_language = _ADMIN_VARIANT_TO_LANGUAGE.get(known_username.casefold())
        if not inferred_language:
            continue
        resolution = _build_resolution(
            language_code=inferred_language,
            preferred_name=known_username,
            source="enabled_users_txt",
        )
        persist_environment_language_hint(
            shell,
            domain=domain,
            language_code=resolution.language_code,
            built_in_admin_name=resolution.built_in_admin_default,
        )
        return resolution

    for known_username in _iter_bloodhound_usernames(shell, domain=domain):
        inferred_language = _ADMIN_VARIANT_TO_LANGUAGE.get(known_username.casefold())
        if not inferred_language:
            continue
        resolution = _build_resolution(
            language_code=inferred_language,
            preferred_name=known_username,
            source="bloodhound_service",
        )
        persist_environment_language_hint(
            shell,
            domain=domain,
            language_code=resolution.language_code,
            built_in_admin_name=resolution.built_in_admin_default,
        )
        return resolution

    for known_username in _iter_ldap_usernames(shell, domain=domain):
        inferred_language = _ADMIN_VARIANT_TO_LANGUAGE.get(known_username.casefold())
        if not inferred_language:
            continue
        resolution = _build_resolution(
            language_code=inferred_language,
            preferred_name=known_username,
            source="ldap_netexec",
        )
        persist_environment_language_hint(
            shell,
            domain=domain,
            language_code=resolution.language_code,
            built_in_admin_name=resolution.built_in_admin_default,
        )
        return resolution

    return _build_resolution(
        language_code="en",
        preferred_name="Administrator",
        source="fallback_default",
    )
