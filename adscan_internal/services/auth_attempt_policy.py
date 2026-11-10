"""Feed the sign-in lockout guard with the session's policy (dependency inversion).

``adscan_core.auth_attempt_guard`` is consulted by the authentication seams
(kerbad ``get_TGT``, SMB session setup, LDAP bind) and cannot import the engine.
This module is the session side: :func:`register_auth_attempt_guard_for_shell`
installs a provider that answers, per realm, how many failed sign-ins ADscan may
cause for one principal, from the two existing SSOTs:

* the scan policy's password-attempt rules
  (:func:`adscan_internal.services.spray_policy_service.resolve_password_attempt_rules`),
  so the reserve margin is the same number spraying keeps;
* the domain lockout policy the collector persisted in
  ``inventory/domain_policy.json`` (threshold and observation window).

It also maps a domain's NetBIOS name to its FQDN, so an NTLM sign-in as
``ESSOS\\user`` and a Kerberos one as ``user@ESSOS.LOCAL`` share one ledger entry,
and installs the live ``badPwdCount`` read (:mod:`adscan_internal.services.lockout_headroom`)
that holds every domain sign-in in a real environment to the counter the domain
controller holds right now.

A host-local account or a SQL login (``auth_attempt_guard.local_realm`` /
``sql_login_realm``) has its own ledger entry and a budget from the same scan
policy with the lockout threshold treated as unknown: the host's own policy is
not read, so a real environment keeps the conservative assumption and a lab
policy that ignores the threshold ignores it there too. A realm the session does
not know (an uncollected trust) gets no answer, and the guard's fail-closed
budget applies.
"""

from __future__ import annotations

import json
import os
from typing import Any, Optional

from adscan_core import telemetry
from adscan_core.auth_attempt_guard import (
    LockoutBudget,
    budget_from_policy,
    is_host_scoped_realm,
    register_policy_provider,
)
from adscan_core.rich_output import print_exception

__all__ = [
    "register_auth_attempt_guard_for_shell",
    "lockout_budget_for_domain",
    "lockout_budget_for_host_scoped_realm",
]


def _domain_for_realm(shell: Any, realm: str) -> Optional[str]:
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return None
    wanted = str(realm or "").strip().rstrip(".").lower()
    for domain in domains_data:
        if str(domain).strip().rstrip(".").lower() == wanted:
            return str(domain)
    return None


def _read_domain_lockout_policy(shell: Any, domain: str) -> tuple[Optional[int], Optional[int]]:
    """``(threshold, window_minutes)`` from ``inventory/domain_policy.json``."""
    from adscan_internal.services.collector.inventory_persistence import (  # noqa: PLC0415
        _inventory_dir,
    )

    path = os.path.join(_inventory_dir(shell, domain), "domain_policy.json")
    if not os.path.isfile(path):
        return None, None
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)
    policy = payload.get("policy") if isinstance(payload, dict) else None
    if not isinstance(policy, dict):
        return None, None

    def _as_int(value: Any) -> Optional[int]:
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    return _as_int(policy.get("lockout_threshold")), _as_int(policy.get("lockout_window_minutes"))


def lockout_budget_for_domain(shell: Any, domain: str) -> LockoutBudget:
    """The guard budget for ``domain`` under the session's scan policy."""
    from adscan_core.scan_policy.policy import ENVIRONMENT_LAB  # noqa: PLC0415
    from adscan_internal.services.spray_policy_service import (  # noqa: PLC0415
        resolve_password_attempt_rules,
    )

    rules = resolve_password_attempt_rules(shell)
    threshold, window_minutes = _read_domain_lockout_policy(shell, domain)
    return budget_from_policy(
        threshold=threshold,
        window_minutes=window_minutes,
        reserve_margin=rules.reserve_margin,
        lab=rules.environment == ENVIRONMENT_LAB,
        ignore_threshold=rules.ignore_threshold,
        attempt_anyway_when_unknown=rules.attempt_anyway_when_unknown,
    )


def lockout_budget_for_host_scoped_realm(shell: Any) -> LockoutBudget:
    """The guard budget for a host-local account or a SQL login.

    The host's own lockout policy is not read (that would take a sign-in), so
    the threshold is unknown and the scan policy decides, exactly as it does
    for a domain whose policy could not be read.
    """
    from adscan_core.scan_policy.policy import ENVIRONMENT_LAB  # noqa: PLC0415
    from adscan_internal.services.spray_policy_service import (  # noqa: PLC0415
        resolve_password_attempt_rules,
    )

    rules = resolve_password_attempt_rules(shell)
    return budget_from_policy(
        threshold=None,
        window_minutes=None,
        reserve_margin=rules.reserve_margin,
        lab=rules.environment == ENVIRONMENT_LAB,
        ignore_threshold=rules.ignore_threshold,
        attempt_anyway_when_unknown=rules.attempt_anyway_when_unknown,
    )


def register_auth_attempt_guard_for_shell(shell: Any) -> None:
    """Install the session's budget provider and realm canonicalizer.

    Called once from ``PentestShell.__init__``. Never raises: without it the
    guard still runs, on its fail-closed budget.
    """

    def _provider(realm: str) -> Optional[LockoutBudget]:
        if is_host_scoped_realm(realm):
            try:
                return lockout_budget_for_host_scoped_realm(shell)
            except Exception as exc:  # noqa: BLE001 - an unreadable policy fails closed
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                return None
        domain = _domain_for_realm(shell, realm)
        if domain is None:
            return None
        try:
            return lockout_budget_for_domain(shell, domain)
        except Exception as exc:  # noqa: BLE001 - an unreadable policy fails closed
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            return None

    def _canonicalizer(name: str) -> str:
        domains_data = getattr(shell, "domains_data", None)
        if not isinstance(domains_data, dict):
            return name
        wanted = str(name or "").strip().rstrip(".").lower()
        for domain, data in domains_data.items():
            if str(domain).strip().lower() == wanted:
                return str(domain)
            netbios = data.get("netbios") if isinstance(data, dict) else None
            if netbios and str(netbios).strip().lower() == wanted:
                return str(domain)
        return name

    register_policy_provider(_provider, _canonicalizer)

    # Rule 5: the domain controller's own counter, read before a domain
    # principal's first sign-in in a real environment.
    try:
        from adscan_internal.services.lockout_headroom import (  # noqa: PLC0415
            register_live_headroom_for_shell,
        )

        register_live_headroom_for_shell(shell)
    except Exception as exc:  # noqa: BLE001 - rule 3 still runs without it
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
