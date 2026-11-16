"""The derivation passes of the graph build: the ONE home of every derived edge.

Each pass is a named, idempotent rule set that reads the graph built so far
(and, through :mod:`~adscan_internal.services.graph_build.inputs`, the store's
collected view) and adds, stamps or removes edges. They run in the order of
:func:`registry`, which is the order the 14.0.x persist ran the same rules, so
the build and the persist produce the same graph.

A rule that is added here is added for every reader at once: the collector
persist imports the same functions until package G replaces it with the build.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from adscan_core.graph_store import GraphStore
from adscan_core.graph_store.records import (
    STAGE_ADCS,
    STAGE_LDAP_ACLS,
    STAGE_LDAP_OBJECTS,
    STAGE_LDAP_RELATIONSHIPS,
    STAGE_MSSQL,
    STAGE_SMB_HOSTS,
    STAGE_SMB_SHARES,
    STAGE_TRUSTS,
    STAGE_WELL_KNOWN,
)

if TYPE_CHECKING:
    from adscan_internal.services.graph_build.api import GraphBuildContext

Graph = dict[str, Any]


@dataclass(frozen=True)
class RegisteredPass:
    """One derivation pass (implements ``api.DerivationPass``).

    Attributes:
        name: Stable name (``BuildReport.seconds_by_pass``).
        reads_stages: The stages whose inventory the rule reads. Documentation
            and the key of a future incremental build; the full build runs every
            pass regardless.
        emits: Every relation the pass can write (``_DERIVED_RELATIONS``).
    """

    name: str
    reads_stages: tuple[str, ...]
    emits: tuple[str, ...]
    _run: Callable[[Graph, GraphStore, "GraphBuildContext"], int]

    def run(self, graph: Graph, store: GraphStore, context: "GraphBuildContext") -> int:
        """Apply the pass in place; returns how many edges it added or changed."""
        return self._run(graph, store, context)


def _inputs(graph: Graph, store: GraphStore, context: "GraphBuildContext") -> Any:
    from adscan_internal.services.graph_build.inputs import active_build_inputs  # noqa: PLC0415

    return active_build_inputs(store, context, graph)


def _run_dcsync(graph: Graph, store: GraphStore, context: "GraphBuildContext") -> int:
    from adscan_internal.services.graph_build.passes.dcsync import (  # noqa: PLC0415
        _persist_dcsync_steps,
    )

    inputs = _inputs(graph, store, context)
    return _persist_dcsync_steps(
        graph, result=inputs.result, sid_to_graph_id=inputs.sid_to_graph_id
    )


def _run_adcs(graph: Graph, store: GraphStore, context: "GraphBuildContext") -> int:
    from adscan_internal.services.graph_build.passes.adcs import (  # noqa: PLC0415
        _persist_esc_compromise_steps,
    )

    inputs = _inputs(graph, store, context)
    return _persist_esc_compromise_steps(
        graph,
        domain=context.domain,
        result=inputs.result,
        sid_to_graph_id=inputs.sid_to_graph_id,
    )


def _run_roasting(graph: Graph, store: GraphStore, context: "GraphBuildContext") -> int:
    from adscan_internal.services.graph_build.passes.roasting import (  # noqa: PLC0415
        derive_roasting_edges,
    )

    inputs = _inputs(graph, store, context)
    return derive_roasting_edges(
        graph, result=inputs.result, sid_to_graph_id=inputs.sid_to_graph_id
    )


def _run_delegation(graph: Graph, store: GraphStore, context: "GraphBuildContext") -> int:
    from adscan_internal.services.graph_build.passes.delegation import (  # noqa: PLC0415
        derive_delegation_edges,
    )

    inputs = _inputs(graph, store, context)
    return derive_delegation_edges(
        graph,
        domain=context.domain,
        result=inputs.result,
        sid_to_graph_id=inputs.sid_to_graph_id,
    )


def _run_spnjack(graph: Graph, store: GraphStore, context: "GraphBuildContext") -> int:
    del store, context  # graph-dict rule: re-derives over whatever the graph holds
    from adscan_internal.services.graph_build.passes.delegation import (  # noqa: PLC0415
        derive_spnjack_edges,
    )

    return derive_spnjack_edges(graph)


def _run_privileged_groups(
    graph: Graph, store: GraphStore, context: "GraphBuildContext"
) -> int:
    del store
    from adscan_internal.services.graph_build.passes.privileged_groups import (  # noqa: PLC0415
        derive_privileged_group_edges,
    )

    return derive_privileged_group_edges(graph, domain_data=context.domain_data)


def _run_mssql(graph: Graph, store: GraphStore, context: "GraphBuildContext") -> int:
    del context  # reads only the MSSQL stage's data
    from adscan_internal.services.graph_build.passes.mssql import (  # noqa: PLC0415
        derive_mssql_edges,
    )

    return derive_mssql_edges(graph, store)


def _run_drop_redundant(graph: Graph, store: GraphStore, context: "GraphBuildContext") -> int:
    del store, context
    from adscan_internal.services.graph_build.passes.prunes import (  # noqa: PLC0415
        _drop_redundant_direct_compromise_to_domain_edges,
    )

    return _drop_redundant_direct_compromise_to_domain_edges(graph)


def _run_trusts(graph: Graph, store: GraphStore, context: "GraphBuildContext") -> int:
    del store  # the partner domains' stores and the recorded trusts
    from adscan_internal.services.graph_build.passes.trusts import (  # noqa: PLC0415
        derive_trust_edges,
    )

    return derive_trust_edges(
        graph,
        domains_data=context.domains_data_for_passes(),
        sibling_stores=context.sibling_stores,
    )


#: The relations each AD CS derivation can write: the ESCs re-targeted at the
#: principal they compromise, and ESC13 once its issuance-policy group resolves.
def _adcs_emits() -> tuple[str, ...]:
    from adscan_internal.services.graph_build.passes.adcs import (  # noqa: PLC0415
        _ESC_DERIVED_RELATIONS,
    )

    return tuple(sorted(_ESC_DERIVED_RELATIONS | {"ADCSESC13"}))


def _privileged_group_emits() -> tuple[str, ...]:
    from adscan_internal.services.graph_build.passes.privileged_groups import (  # noqa: PLC0415
        PRIVILEGED_GROUP_ESCALATION_RELATIONS,
    )

    return tuple(sorted(PRIVILEGED_GROUP_ESCALATION_RELATIONS))


def registry() -> tuple[RegisteredPass, ...]:
    """The ordered derivation passes (the order of the 14.0.x persist)."""
    return (
        RegisteredPass(
            name="dcsync",
            reads_stages=(STAGE_LDAP_OBJECTS, STAGE_LDAP_ACLS, STAGE_WELL_KNOWN),
            emits=("DCSync",),
            _run=_run_dcsync,
        ),
        RegisteredPass(
            name="adcs",
            reads_stages=(
                STAGE_ADCS,
                STAGE_LDAP_OBJECTS,
                STAGE_LDAP_ACLS,
                STAGE_LDAP_RELATIONSHIPS,
                STAGE_WELL_KNOWN,
            ),
            emits=_adcs_emits(),
            _run=_run_adcs,
        ),
        RegisteredPass(
            name="roasting",
            reads_stages=(STAGE_LDAP_OBJECTS, STAGE_WELL_KNOWN),
            emits=("ASREPRoasting", "Kerberoasting"),
            _run=_run_roasting,
        ),
        RegisteredPass(
            name="delegation",
            reads_stages=(STAGE_LDAP_OBJECTS,),
            emits=("AllowedToDelegate", "UnconstrainedDelegation"),
            _run=_run_delegation,
        ),
        RegisteredPass(
            name="spnjack",
            reads_stages=(STAGE_LDAP_OBJECTS, STAGE_LDAP_RELATIONSHIPS, STAGE_LDAP_ACLS),
            emits=("SPNJack",),
            _run=_run_spnjack,
        ),
        RegisteredPass(
            name="privileged_groups",
            reads_stages=(STAGE_LDAP_OBJECTS, STAGE_LDAP_RELATIONSHIPS),
            emits=_privileged_group_emits(),
            _run=_run_privileged_groups,
        ),
        RegisteredPass(
            name="mssql",
            reads_stages=(STAGE_MSSQL, STAGE_LDAP_OBJECTS),
            emits=("MssqlLinkedServerLateral", "SQLAccess", "SQLAdmin"),
            _run=_run_mssql,
        ),
        RegisteredPass(
            name="drop_redundant_direct_compromise",
            reads_stages=(
                STAGE_LDAP_OBJECTS,
                STAGE_LDAP_RELATIONSHIPS,
                STAGE_LDAP_ACLS,
                STAGE_SMB_HOSTS,
                STAGE_SMB_SHARES,
            ),
            emits=(),
            _run=_run_drop_redundant,
        ),
        RegisteredPass(
            name="trusts",
            reads_stages=(STAGE_TRUSTS, STAGE_LDAP_OBJECTS),
            emits=("CrossOrgTgtDelegation", "RaiseChild"),
            _run=_run_trusts,
        ),
    )


def derived_relations() -> tuple[str, ...]:
    """Every relation a derivation pass can write, sorted."""
    return tuple(sorted({rel for p in registry() for rel in p.emits}))


__all__ = ("RegisteredPass", "derived_relations", "registry")
