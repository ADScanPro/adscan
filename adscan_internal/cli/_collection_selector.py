"""Phase 2 (Domain Collection) sub-collection selector.

Lets the operator pick which sub-collections run before the host (SMB) phase
of native domain collection. The LDAP graph / ACL / membership / ADCS pass is
the mandatory base (it produces the graph and the computer list the SMB phase
consumes) and is therefore always run -- it is shown as a checked, effectively
mandatory row purely for visibility. The two SMB sub-collections are optional:

- "SMB: sessions & local admins (SAMR)" -> ``collect_samr``
- "SMB: shares & share ACLs (SRVSVC)" -> ``collect_shares``
- "MSSQL: server authorization (logins, roles, sysadmin)" -> ``collect_mssql``

When both SMB options are unchecked, the orchestrator's host phase is skipped
entirely (LDAP-only fast pass).

The MSSQL collector is a peer collector for selection purposes but runs as a
Domain Intelligence sub-step AFTER Host Inventory (reusing the ``mssql/ips.txt``
port-scan result as the single source of truth for reachable MSSQL hosts — no
separate preflight). ``collect_mssql`` only gates whether that step runs; the
checkbox lives here so the operator picks all collectors in one place.

The prompt is rendered through the centralized ``questionary_checkbox_values``
helper, which auto-resolves to ``default_values`` in non-interactive / CI mode.
The default is ALL selected, so CI and the existing flow are unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from adscan_core.rich_output import questionary_checkbox_values
from adscan_internal import telemetry
from adscan_internal.rich_output import mark_sensitive, print_info_debug

# Stable option labels (English-only, user-visible).
_OPT_LDAP = "LDAP graph, ACLs, memberships & ADCS/PKI"
_OPT_SAMR = "SMB: sessions & local admins (SAMR)"
_OPT_SHARES = "SMB: shares & share ACLs (SRVSVC)"
_OPT_MSSQL = "MSSQL: server authorization (logins, roles, sysadmin)"

_OPTIONS = [_OPT_LDAP, _OPT_SAMR, _OPT_SHARES, _OPT_MSSQL]


@dataclass(frozen=True)
class CollectionSelection:
    """Resolved sub-collection choices for one Phase 2 run."""

    collect_samr: bool
    collect_shares: bool
    collect_mssql: bool = True

    @property
    def host_phase_enabled(self) -> bool:
        """True when at least one SMB sub-collection should run."""
        return self.collect_samr or self.collect_shares


def prompt_collection_selection(
    shell: Any, target_domain: str
) -> CollectionSelection:
    """Ask the operator which sub-collections to run for Phase 2.

    Renders an interactive checkbox via the centralized helper. The LDAP base
    is always run regardless of selection. Defaults to ALL selected so that
    non-interactive / CI runs (which auto-resolve to ``default_values``) and the
    existing interactive flow keep identical behavior.

    Returns:
        A :class:`CollectionSelection` with the SMB sub-collection flags.
    """
    try:
        selected = questionary_checkbox_values(
            title=(
                "Domain Collection -- select sub-collections for "
                f"{mark_sensitive(target_domain, 'domain')}"
            ),
            options=_OPTIONS,
            default_values=list(_OPTIONS),
            shell=shell,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        selected = None

    # Helper returned None (cancelled / EOF / error) -> safe default = ALL.
    if selected is None:
        selected = list(_OPTIONS)

    collect_samr = _OPT_SAMR in selected
    collect_shares = _OPT_SHARES in selected
    collect_mssql = _OPT_MSSQL in selected
    print_info_debug(
        "[collection-selector] resolved selection "
        f"samr={collect_samr} shares={collect_shares} mssql={collect_mssql}"
    )
    return CollectionSelection(
        collect_samr=collect_samr,
        collect_shares=collect_shares,
        collect_mssql=collect_mssql,
    )
