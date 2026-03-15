"""Privilege enumeration mixin.

This module provides helpers for enumerating user privileges across a domain.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from adscan_internal import print_error, print_success
from adscan_internal.rich_output import mark_sensitive


@dataclass
class UserPrivileges:
    """Simple container for user privilege information."""

    username: str
    has_admin_privs: bool


class PrivilegeEnumerationMixin:
    """Mixin for privilege enumeration logic.

    The initial implementation is a thin wrapper around existing CLI helpers
    such as :meth:`PentestShell.ask_for_user_privs`.
    """

    def enumerate_all_user_postauth_access(
        self,
        domain: str,
        credentials: Dict[str, str],
        *,
        auto_mode: bool = False,
    ) -> List[UserPrivileges]:
        """Enumerate post-auth access opportunities for all users in a domain.

        Args:
            domain: Domain name.
            credentials: Mapping of username -> password (hashes should be
                filtered by caller).
            auto_mode: Whether to run in automatic enumeration mode.

        Returns:
            List of UserPrivileges entries.
        """
        if not credentials:
            marked_domain = mark_sensitive(domain, "domain")
            print_error(f"No credentials provided for domain {marked_domain}")
            return []

        results: List[UserPrivileges] = []
        marked_domain = mark_sensitive(domain, "domain")
        print_success(
            f"Enumerating post-auth access for all users in domain {marked_domain}"
        )

        for username, credential in credentials.items():
            # The concrete shell/service is expected to provide ask_for_user_privs.
            has_privs: Optional[Dict[str, bool]] = self.ask_for_user_privs(  # type: ignore[attr-defined]  # noqa: E501
                domain,
                username,
                credential,
                auto_mode,
            )
            has_admin = bool(
                has_privs.get("domain_admin") if isinstance(has_privs, dict) else False
            )
            results.append(
                UserPrivileges(
                    username=username,
                    has_admin_privs=has_admin,
                )
            )

        return results

    def enumerate_all_user_privs(
        self,
        domain: str,
        credentials: Dict[str, str],
        *,
        auto_mode: bool = False,
    ) -> List[UserPrivileges]:
        """Backward-compatible alias for all-user post-auth access enumeration."""
        return self.enumerate_all_user_postauth_access(
            domain,
            credentials,
            auto_mode=auto_mode,
        )

