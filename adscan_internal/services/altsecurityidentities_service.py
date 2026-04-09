"""Helpers for weak explicit certificate mapping enumeration.

This module centralizes LDAP enumeration of users with ``altSecurityIdentities``
and applies ADscan product semantics (enabled-only, low-privileged-only) so
multiple ADCS flows can reuse the same logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from adscan_internal import telemetry
from adscan_internal.rich_output import mark_sensitive, print_info_debug
from adscan_internal.services.high_value import (
    classify_users_tier0_high_value,
    normalize_samaccountname,
)


@dataclass(frozen=True)
class AltSecurityIdentityUser:
    """Normalized LDAP result for a user with weak explicit cert mappings."""

    samaccountname: str
    distinguished_name: str
    alt_security_identities: tuple[str, ...]
    weak_mappings: tuple[str, ...]
    is_enabled: bool
    is_tier0: bool
    is_high_value: bool

    @property
    def is_low_privileged(self) -> bool:
        """Return whether the user is outside Tier-0/high-value sets."""
        return not self.is_tier0 and not self.is_high_value


class AltSecurityIdentitiesService:
    """Enumerate weak explicit certificate mappings from LDAP."""

    LDAP_MATCHING_RULE_BIT_AND = "1.2.840.113556.1.4.803"

    @staticmethod
    def is_weak_altsecurityidentities_mapping(value: str) -> bool:
        """Identify weak explicit mapping strings.

        Weak mappings rely on issuer/subject-style identifiers without strong,
        certificate-bound attributes such as serial number or SKI.
        """
        normalized = value.strip().upper()
        if not normalized.startswith("X509:"):
            return False
        strong_markers = ("<SR>", "<SKI>", "<SHA1-PUKEY>", "<SHA1PUKEY>")
        if any(marker in normalized for marker in strong_markers):
            return False
        weak_markers = ("<I>", "<S>", "<RFC822>", "<SUBJECT>", "<ISSUER>")
        return any(marker in normalized for marker in weak_markers)

    def find_users_with_weak_altsecurityidentities(
        self,
        *,
        connection: Any,
        domain: str,
        shell: Any | None = None,
        enabled_only: bool = True,
        low_privileged_only: bool = True,
    ) -> list[AltSecurityIdentityUser]:
        """Return users with weak ``altSecurityIdentities`` mappings.

        Args:
            connection: LDAP connection wrapper used across ADscan services.
            domain: AD domain name.
            shell: Optional shell context to classify Tier-0/high-value users.
            enabled_only: When True, query only enabled accounts in LDAP.
            low_privileged_only: When True, drop Tier-0/high-value users after
                batch classification.
        """
        domain_dn = str(getattr(connection.config, "domain_dn", "") or "").strip()
        if not domain_dn:
            return []

        search_filter = "(&(objectCategory=person)(objectClass=user)(altSecurityIdentities=*)"
        if enabled_only:
            search_filter += (
                f"(!(userAccountControl:{self.LDAP_MATCHING_RULE_BIT_AND}:=2))"
            )
        search_filter += ")"

        try:
            connection.search(
                search_base=domain_dn,
                search_filter=search_filter,
                attributes=[
                    "distinguishedName",
                    "sAMAccountName",
                    "altSecurityIdentities",
                    "userAccountControl",
                ],
            )
            raw_entries = list(getattr(connection.connection, "entries", []) or [])
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            return []

        weak_candidates: list[AltSecurityIdentityUser] = []
        usernames: list[str] = []
        for entry in raw_entries:
            all_values = self._coerce_entry_values(entry, "altSecurityIdentities")
            weak_values = tuple(
                value
                for value in all_values
                if self.is_weak_altsecurityidentities_mapping(value)
            )
            if not weak_values:
                continue

            samaccountname = normalize_samaccountname(
                self._coerce_single_entry_value(entry, "sAMAccountName")
            )
            if not samaccountname:
                continue

            usernames.append(samaccountname)
            weak_candidates.append(
                AltSecurityIdentityUser(
                    samaccountname=samaccountname,
                    distinguished_name=self._coerce_single_entry_value(
                        entry, "distinguishedName"
                    ),
                    alt_security_identities=tuple(all_values),
                    weak_mappings=weak_values,
                    is_enabled=True,
                    is_tier0=False,
                    is_high_value=False,
                )
            )

        risk_flags = {}
        if shell is not None and usernames:
            try:
                risk_flags = classify_users_tier0_high_value(
                    shell,
                    domain=domain,
                    usernames=usernames,
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                risk_flags = {}

        results: list[AltSecurityIdentityUser] = []
        for candidate in weak_candidates:
            flags = risk_flags.get(candidate.samaccountname)
            hydrated = AltSecurityIdentityUser(
                samaccountname=candidate.samaccountname,
                distinguished_name=candidate.distinguished_name,
                alt_security_identities=candidate.alt_security_identities,
                weak_mappings=candidate.weak_mappings,
                is_enabled=True,
                is_tier0=bool(getattr(flags, "is_tier0", False)),
                is_high_value=bool(getattr(flags, "is_high_value", False)),
            )
            if low_privileged_only and not hydrated.is_low_privileged:
                continue
            results.append(hydrated)

        print_info_debug(
            "[altsecid] weak mapping enumeration: "
            f"domain={mark_sensitive(domain, 'domain')} "
            f"enabled_only={enabled_only!r} "
            f"low_privileged_only={low_privileged_only!r} "
            f"raw_matches={len(raw_entries)} "
            f"weak_candidates={len(weak_candidates)} "
            f"results={len(results)}"
        )
        return results

    @staticmethod
    def _coerce_entry_values(entry: Any, attribute_name: str) -> tuple[str, ...]:
        """Read a multivalue LDAP attribute as normalized strings."""
        try:
            values = list(getattr(entry, attribute_name, []) or [])
        except Exception:  # noqa: BLE001
            values = []
        normalized = tuple(
            str(value).strip() for value in values if str(value).strip()
        )
        return normalized

    @staticmethod
    def _coerce_single_entry_value(entry: Any, attribute_name: str) -> str:
        """Read a single LDAP attribute as a trimmed string."""
        try:
            value = getattr(entry, attribute_name, "")
        except Exception:  # noqa: BLE001
            value = ""
        if isinstance(value, (list, tuple)):
            value = value[0] if value else ""
        return str(value or "").strip()
