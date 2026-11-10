"""Targets for a LOCAL-account sign-in sweep: never a domain controller.

A domain controller has no local account database. A "local" sign-in sent to a
DC (NTLM domain ``"."`` or the DC's own name) is validated against the DOMAIN
account with the same name, so a wrong local secret raises that domain
account's failed sign-in count, while the lockout guard counts the attempt as a
host-local one and never reads the domain account's live counter. Every sweep
that tries a recovered local credential on other hosts
(``module:local_credential_reuse``) therefore drops the domain controllers
from its target list here, and builds each sign-in with this module's matcher
so the config builder refuses a DC target even if one slips through.

DC identity is the union of every source the workspace holds, alias-aware
(IP, short name, FQDN, ``HOST$``) and bridged IP <-> name through the
workspace's resolved inventory:

* ``resolve_domain_controllers(domain_data)``, the DC topology SSOT;
* ``is_dc_host``, the domain's canonical DC identifiers;
* ``dcs.txt``, the DC list the workspace loader writes per domain.

Erring towards "is a DC" only costs one host not being tested for local reuse;
erring the other way costs a domain account's lockout headroom.
"""

from __future__ import annotations

import os
from typing import Any, Callable, Iterable

from adscan_core.rich_output import print_info, print_info_debug
from adscan_internal import telemetry
from adscan_internal.rich_output import mark_sensitive

#: Operator line shown once per sweep when domain controllers were left out.
DC_SKIP_REASON = (
    "a domain controller has no local accounts, so a local sign-in there is "
    "checked against the domain account of the same name and would count "
    "toward that account's lockout"
)


def _workspace_inventory(shell: Any, domain: str) -> dict[str, Any] | None:
    try:
        from adscan_internal.services.kerberos_hostname_inventory import (  # noqa: PLC0415
            load_workspace_ip_hostname_inventory,
        )

        workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "")
        domains_dir = str(getattr(shell, "domains_dir", "") or "domains")
        if not workspace_dir:
            return None
        return load_workspace_ip_hostname_inventory(
            workspace_dir=workspace_dir, domains_dir=domains_dir, domain=domain
        )
    except Exception as exc:  # noqa: BLE001 - the inventory only widens matching
        telemetry.capture_exception(exc)
        return None


def _dcs_file_entries(shell: Any, domain: str) -> list[str]:
    domains_dir = str(getattr(shell, "domains_dir", "") or "domains")
    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "")
    candidates = [os.path.join(domains_dir, domain, "dcs.txt")]
    if workspace_dir:
        candidates.insert(0, os.path.join(workspace_dir, domains_dir, domain, "dcs.txt"))
    for path in candidates:
        try:
            if os.path.isfile(path):
                with open(path, encoding="utf-8") as handle:
                    return [line.strip() for line in handle if line.strip()]
        except OSError as exc:
            telemetry.capture_exception(exc)
    return []


def domain_controller_matcher(shell: Any, domain: str) -> Callable[[str], bool]:
    """Return ``is_dc(host)`` for ``domain``, alias-aware over every DC source."""
    from adscan_internal.models.domain import (  # noqa: PLC0415
        resolve_domain_controllers,
    )
    from adscan_internal.services.domain_controller_classifier import (  # noqa: PLC0415
        expand_host_aliases,
        is_dc_host,
    )

    domains_data = getattr(shell, "domains_data", None) or {}
    domain_data = domains_data.get(domain) if isinstance(domains_data, dict) else None
    domain_data = domain_data if isinstance(domain_data, dict) else {}
    topology = resolve_domain_controllers(domain_data)
    inventory = _workspace_inventory(shell, domain)

    identifiers: list[str] = []
    for record in topology.dcs:
        identifiers.extend(record.aliases)
    identifiers.extend(_dcs_file_entries(shell, domain))
    dc_keys: set[str] = set()
    for identifier in identifiers:
        dc_keys |= expand_host_aliases(identifier, ip_hostname_inventory=inventory)

    def _is_dc(host: str) -> bool:
        text = str(host or "").strip()
        if not text:
            return False
        if topology.recognizes_host(text):
            return True
        if dc_keys & expand_host_aliases(text, ip_hostname_inventory=inventory):
            return True
        return is_dc_host(
            host=text,
            domains_data=domains_data,
            domain=domain,
            ip_hostname_inventory=inventory,
        )

    return _is_dc


def split_out_domain_controllers(
    hosts: Iterable[str], is_dc: Callable[[str], bool]
) -> tuple[list[str], list[str]]:
    """Return ``(targets, skipped_dcs)`` preserving order."""
    targets: list[str] = []
    skipped: list[str] = []
    for host in hosts:
        (skipped if is_dc(host) else targets).append(host)
    return targets, skipped


def announce_skipped_domain_controllers(skipped: list[str], *, domain: str) -> None:
    """Tell the operator, once, that domain controllers were left out and why."""
    if not skipped:
        return
    count = len(skipped)
    print_info(
        f"Local credential reuse skips {count} domain controller{'s' if count != 1 else ''} "
        f"in {mark_sensitive(domain, 'domain')}: {DC_SKIP_REASON}."
    )
    print_info_debug(
        "[local_reuse] skipped domain controllers: "
        + ", ".join(mark_sensitive(h, "hostname") for h in skipped)
    )


__all__ = (
    "DC_SKIP_REASON",
    "announce_skipped_domain_controllers",
    "domain_controller_matcher",
    "split_out_domain_controllers",
)
