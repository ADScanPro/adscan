"""The account population the exposure KPIs measure — one definition.

"X of N accounts have a validated path to full domain compromise" is only as
good as N. This module owns what N is, and what it is not.

**N is the enabled USER population, minus the accounts whose credential is
machine-managed.** A group managed service account is enabled, it is a real
attack-relevant principal, and it belongs in the user inventory — which is why
``graph_queries.inventories.get_enabled_users`` keeps it. But it does not belong
in an account KPI, for the same reason a computer account does not: its password
is a 240-character random value the KDC rotates on its own schedule, so it is
not reachable by anything this metric measures. It is reached by reading
``msDS-ManagedPassword``, which requires membership of the account's
``PrincipalsAllowedToRetrieveManagedPassword`` — a different mechanism, with a
different fix, already reported as its own finding (``gmsa_readable``). Leaving
it in the denominator counts an account that cannot be exposed the way the
figure claims; leaving it in the numerator claims an exposure that is not there.
On the reference Essos workspace it did both at once: ``gmsaDragon$`` sat in the
denominator of "10 of 10" while also being named as the one account without a
route.

**No exposure is lost.** The gMSA's real attack surface — who may retrieve its
password — is enumerated and reported independently. This is a filter over the
KPI population, not over collection, detection or the graph.

**The signal is the account's CLASS, never the trailing ``$``.** Every managed
service account's sAMAccountName ends in ``$``, but so does every inter-domain
trust account, and the two are different problems: the trust account is already
excluded upstream (``_is_machine_or_trust_user``), so a suffix test would add no
recall and only risk excluding whatever else AD chooses to name that way.
:func:`~adscan_internal.services.graph_queries.inventories.is_managed_service_account`
is the SSOT predicate, and it reads the four fields that actually carry the
class (``is_gmsa``, ``account_type``, the ``CN=Managed Service Accounts`` DN,
and the ``msDS-*ManagedServiceAccount`` objectClass), so an artifact written
before any one of them existed still resolves correctly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from adscan_core import telemetry
from adscan_core.rich_output import print_exception, print_info_debug
from adscan_internal.rich_output import mark_sensitive

__all__ = [
    "AccountPopulation",
    "resolve_account_population",
    "resolve_population_tier_breakdown",
]


@dataclass(frozen=True)
class AccountPopulation:
    """The accounts an account-level KPI may count, and the ones it may not.

    Attributes:
        accounts: Normalized sAMAccountNames of the enabled population the KPIs
            measure — the denominator, and the only set a numerator may draw
            from.
        excluded: The machine-managed service accounts removed from it, kept
            (not discarded) so the deliverable can say why the denominator is
            what it is rather than leaving a reader to find the discrepancy.
        available: Whether an enabled population could be resolved at all. False
            means say nothing — a KPI over a population we could not read is a
            figure nobody can stand behind.
    """

    accounts: frozenset[str] = frozenset()
    excluded: frozenset[str] = frozenset()
    available: bool = False

    @property
    def total(self) -> int:
        """The denominator: how many accounts the KPIs measure."""
        return len(self.accounts)

    def sorted_accounts(self) -> list[str]:
        """The population, sorted — the artifact must be deterministic."""
        return sorted(self.accounts)

    def sorted_excluded(self) -> list[str]:
        """The excluded service accounts, sorted."""
        return sorted(self.excluded)


def _normalize(name: Any) -> str:
    """Return the comparison key for an account name.

    Case-folded and realm-stripped, matching the engine's own user key
    (``exposure_score_service._normalize_user``) so a population entry and an
    affected-path principal for the same account are the same string. The
    trailing ``$`` is PRESERVED: it is part of a service account's
    sAMAccountName, and ``enabled_users.txt`` carries it verbatim.
    """
    if not isinstance(name, str):
        return ""
    key = name.strip().lower()
    if "@" in key:
        local = key.split("@", 1)[0]
        if local:
            key = local
    return key


def _managed_service_accounts(shell: Any, domain: str) -> set[str]:
    """Return the domain's managed service accounts, by sAMAccountName.

    Read from the attack graph, because that is where the account class lives —
    ``enabled_users.txt`` is a name list and carries no properties at all.
    Best-effort: a workspace with no readable graph yields an empty set, which
    keeps the population exactly as it was rather than guessing.
    """
    try:
        from adscan_internal.services.attack_graph_service import (  # noqa: PLC0415
            load_attack_graph,
        )
        from adscan_internal.services.graph_queries.filters import (  # noqa: PLC0415
            domain_matches,
        )
        from adscan_internal.services.graph_queries.inventories import (  # noqa: PLC0415
            is_managed_service_account,
        )

        graph = load_attack_graph(shell, domain)
        nodes = graph.get("nodes") if isinstance(graph, dict) else None
        if not isinstance(nodes, dict):
            return set()
        found: set[str] = set()
        for node in nodes.values():
            if not isinstance(node, dict) or node.get("kind") != "User":
                continue
            if not domain_matches(node, domain):
                continue
            props = node.get("properties")
            if not isinstance(props, dict) or not is_managed_service_account(props):
                continue
            key = _normalize(props.get("samaccountname"))
            if key:
                found.add(key)
        return found
    except Exception as exc:  # noqa: BLE001 - a KPI input is never worth a crash
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return set()


def resolve_account_population(shell: Any, domain: str) -> AccountPopulation:
    """Resolve the enabled account population the exposure KPIs measure.

    Args:
        shell: Anything carrying ``current_workspace_dir`` / ``domains_dir`` —
            the report pipeline passes a lightweight namespace.
        domain: The domain whose population is being resolved.

    Returns:
        An :class:`AccountPopulation`. ``available=False`` when no enabled-user
        list could be read, in which case the caller reports no account figure
        at all.
    """
    try:
        from adscan_internal.services.attack_graph_service import (  # noqa: PLC0415
            get_enabled_users_for_domain,
        )

        enabled = get_enabled_users_for_domain(shell, domain)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        enabled = None
    if not enabled:
        return AccountPopulation()

    population = {key for raw in enabled if (key := _normalize(raw))}
    if not population:
        return AccountPopulation()

    excluded = population & _managed_service_accounts(shell, domain)
    if excluded:
        print_info_debug(
            "[kpi-population] excluded machine-managed service accounts for "
            f"{mark_sensitive(domain, 'domain')}: "
            f"{', '.join(mark_sensitive(name, 'user') for name in sorted(excluded))}"
        )
    return AccountPopulation(
        accounts=frozenset(population - excluded),
        excluded=frozenset(excluded),
        available=True,
    )


def resolve_population_tier_breakdown(
    shell: Any,
    domain: str,
    population: AccountPopulation,
) -> dict[str, int] | None:
    """Return the Privilege-Tier split of the account population.

    ``{"tier0", "tier0_direct", "tier1", "tier2"}`` — how many of the accounts
    the KPIs measure ALREADY hold each tier by group membership, and how many of
    the Tier 0 ones hold it directly (Domain Admins and friends) rather than
    through an escalation-capable group.

    This is the input to the privilege-sprawl figure, and sprawl is what makes
    excluding the already-privileged accounts from the path metric defensible:
    without it the exclusion does not clean that figure, it hides the
    population. It has to be the POPULATION's split, not the AFFECTED set's — a
    domain where forty of a hundred accounts are Domain Admins can show modest
    path exposure and be entirely lost, and the affected split cannot see the
    thirty-nine of them that never needed a path.

    Grading goes through the shared account grader, the same one that produces
    the affected set's split, so the two always reconcile.

    Returns ``None`` when there is no population to grade or the grader could
    not run — the caller then reports no sprawl figure rather than a zeroed
    split, which would read as "nobody is privileged".
    """
    if not population.available or not population.accounts:
        return None
    try:
        from adscan_internal.services.attack_graph_service import (  # noqa: PLC0415
            classify_accounts_by_privilege_tier,
        )

        breakdown, tier_map = classify_accounts_by_privilege_tier(
            shell, domain, population.sorted_accounts()
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None
    return {
        "tier0": int(breakdown.get("tier0", 0) or 0),
        "tier0_direct": sum(
            1 for value in tier_map.values() if str(value) == "tier0_direct"
        ),
        "tier1": int(breakdown.get("tier1", 0) or 0),
        "tier2": int(breakdown.get("tier2", 0) or 0),
    }
