"""Second pass of the CA registry probe, once the collection resolves roles.

The registry probe that feeds ESC6, ESC11 and Certighost reads the CA host's
``CertSvc`` configuration over MS-RRP, which needs a PROVEN administrator of the
CA host. During the LDAP pass the only evidence is the directory membership the
pass has already read (``ca_host_access.collected_directory_roles``). A local
administrator of the CA host that is not a domain-wide admin only becomes
provable later: the SMB sweep records its ``AdminTo`` edge and persistence
writes the graph the credential picker reads.

So the LDAP pass defers such a CA (``CollectionResult.adcs_registry_pending``)
instead of recording it, and the collection orchestrator calls
:func:`rerun_pending_ca_registry_probes` after the first persist. Every deferred
CA gets exactly ONE observation from here: assessed when a credential now
qualifies and the read completed, not assessed with its reason otherwise.

What a late read decides is committed to the graph store as the CA's own
``adcs_ca_registry`` unit (its object id): the registry verdict as data and the
ESC6 / ESC11 / Certighost relationships it raises as facts. The graph build
derives the ESC compromise steps from them like from any other AD CS fact, and
a throttled export follows once all deferred CAs are recorded (the
collection's forced export at its end makes the file current). The in-memory
collection result is not changed (so the directory stages are never committed
again with these relationships in them). A later collection (the privileged
refresh after a domain compromise) runs this again, which is how a credential
gained after the collection is picked up; re-reading a CA replaces its unit.
"""

from __future__ import annotations

from typing import Any

from adscan_core import telemetry
from adscan_core.rich_output import print_exception, print_info_debug
from adscan_internal.rich_output import mark_sensitive


def rerun_pending_ca_registry_probes(
    shell: Any, *, domain: str, result: Any, dc_ip: str | None
) -> bool:
    """Probe the CAs the first pass deferred and record each outcome once.

    Args:
        shell: The scan shell (credential store, workspace, observation recorder).
        domain: The collected domain.
        result: The domain's in-memory ``CollectionResult`` (already persisted).
        dc_ip: The domain controller the collection used (KDC for the CA-host
            credential).

    Returns:
        ``True`` when the late reads raised relationships (committed to the store
        and exported here; nothing for the caller to persist). Never raises.
    """
    pending = list(getattr(result, "adcs_registry_pending", None) or ())
    if not pending:
        return False
    # Consumed here, whatever happens below: a pending CA is recorded once.
    result.adcs_registry_pending = []

    from adscan_internal.services.adcs.esc12_detection import (  # noqa: PLC0415
        REASON_NO_LOCAL_ADMIN,
        REASON_READ_FAILED,
    )
    from adscan_internal.services.collector.adcs_collector import (  # noqa: PLC0415
        observe_ca_registry_checks,
        registry_dependent_edges,
    )

    templates = [n for n in result.nodes.values() if n.kind == "CertTemplate"]
    probes = _probe_pending(
        shell, domain=domain, result=result, dc_ip=dc_ip, pending=pending
    )
    # The detectors see the collected relationships plus what earlier CAs of
    # this re-run raised (ESC6 is raised once per template, by the first CA).
    view = _ResultWithLateEdges(result)
    commits = _CaRegistryCommits(shell, domain)

    changed = False
    for entry in pending:
        ca = result.nodes.get(entry.ca_object_id)
        if ca is None:
            continue
        registry, skip_reason = probes.get(
            entry.ca_object_id, (None, REASON_READ_FAILED)
        )
        new_edges = registry_dependent_edges(
            ca=ca, registry=registry, templates=templates, result=view, domain=domain
        )
        view.late_edges.extend(new_edges)
        changed = changed or bool(new_edges)
        commits.commit(entry, registry, skip_reason, new_edges)
        observe_ca_registry_checks(
            shell,
            domain=domain,
            ca=ca,
            registry=registry,
            skip_reason=skip_reason or REASON_NO_LOCAL_ADMIN,
            ca_edge_relations={e.relation for e in new_edges},
            result=view,
            templates=templates,
        )
        print_info_debug(
            "[adcs-ca-rerun] CA "
            f"{mark_sensitive(entry.ca_name, 'host')} on "
            f"{mark_sensitive(entry.ca_host, 'host')}: "
            + (
                f"registry read, {len(new_edges)} edge(s) added"
                if registry is not None
                else f"still not assessed ({skip_reason})"
            )
        )
    commits.finish()
    return changed


class _ResultWithLateEdges:
    """The collection result as the detectors read it, plus the late edges.

    ``edges`` is a fresh iterator on every access (collected first, then late),
    so a detector may iterate it more than once; it is never a copy.
    """

    def __init__(self, result: Any) -> None:
        self._result = result
        self.late_edges: list[Any] = []

    @property
    def edges(self) -> Any:
        import itertools  # noqa: PLC0415

        return itertools.chain(self._result.edges, self.late_edges)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._result, name)


class _CaRegistryCommits:
    """One ``adcs_ca_registry`` store unit per re-read CA, then one export."""

    def __init__(self, shell: Any, domain: str) -> None:
        self._shell = shell
        self._domain = domain
        self._writer: Any = None
        self._begun = False
        self._failed = False

    def commit(self, entry: Any, registry: Any, skip_reason: str, edges: list[Any]) -> None:
        import dataclasses  # noqa: PLC0415

        from adscan_core.graph_store import DatumRecord  # noqa: PLC0415
        from adscan_core.graph_store.records import STAGE_ADCS_CA_REGISTRY  # noqa: PLC0415
        from adscan_internal.services.collector.store_writer import (  # noqa: PLC0415
            UnitSource,
            store_writer_for_shell,
        )

        try:
            if self._writer is None:
                self._writer = store_writer_for_shell(self._shell, self._domain)
            if not self._begun:
                self._writer.store.begin_stage(STAGE_ADCS_CA_REGISTRY)
                self._begun = True
            unit = str(entry.ca_object_id or "").upper()
            body: dict[str, Any] = {
                "ca_name": str(entry.ca_name or ""),
                "ca_host": str(entry.ca_host or ""),
                "assessed": registry is not None,
                "skip_reason": str(skip_reason or ""),
            }
            if registry is not None and dataclasses.is_dataclass(registry):
                body["registry"] = {
                    k: v for k, v in dataclasses.asdict(registry).items() if k != "error_message"
                }
            datum = DatumRecord(kind="adcs_ca_registry", key=unit, body=body)
            self._writer.commit_unit(
                STAGE_ADCS_CA_REGISTRY, unit, UnitSource(edges=list(edges), data=[datum]), force=True
            )
        except Exception as exc:  # noqa: BLE001 - the observation is still recorded
            self._failed = True
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    def finish(self) -> None:
        if not self._begun or self._writer is None:
            return
        from adscan_core.graph_store.records import STAGE_ADCS_CA_REGISTRY  # noqa: PLC0415
        from adscan_internal.services.graph_runtime import export_graph_if_due  # noqa: PLC0415

        if self._failed:
            self._writer._end_quietly(STAGE_ADCS_CA_REGISTRY, "failed", reason="store_error")  # noqa: SLF001
        else:
            self._writer._end_quietly(STAGE_ADCS_CA_REGISTRY, "complete")  # noqa: SLF001
        # Throttled: the collection's forced export at its end makes it current.
        export_graph_if_due(self._shell, self._domain)


def _probe_pending(
    shell: Any, *, domain: str, result: Any, dc_ip: str | None, pending: list[Any]
) -> dict[str, tuple[Any, str]]:
    """Return ``{ca_object_id: (registry result or None, skip reason)}``."""
    from adscan_internal.services.adcs.esc12_detection import (  # noqa: PLC0415
        REASON_NO_LOCAL_ADMIN,
        REASON_READ_FAILED,
    )

    outcomes: dict[str, tuple[Any, str]] = {
        entry.ca_object_id: (None, REASON_READ_FAILED) for entry in pending
    }
    try:
        from adscan_internal.services.adcs.ca_host_access import (  # noqa: PLC0415
            build_ca_host_smb_config_builder,
            collected_directory_roles,
        )
        from adscan_internal.services.adcs_ca_registry_service import (  # noqa: PLC0415
            ADCSCARegistryProbe,
        )
        from adscan_internal.services.async_bridge import run_async_sync  # noqa: PLC0415

        builder = build_ca_host_smb_config_builder(
            shell,
            domain=domain,
            dc_ip=dc_ip,
            directory_roles=collected_directory_roles(
                shell, domain=domain, result=result
            ),
        )
        if builder is None:
            return {
                entry.ca_object_id: (None, REASON_NO_LOCAL_ADMIN) for entry in pending
            }

        async def _run() -> None:
            probe = ADCSCARegistryProbe()
            for entry in pending:
                # One CA host at a time: each read is its own SMB session.
                try:
                    config = await builder(entry.ca_host) if entry.ca_host else None
                    if config is None:
                        outcomes[entry.ca_object_id] = (None, REASON_NO_LOCAL_ADMIN)
                        continue
                    registry = await probe.probe(config=config, ca_name=entry.ca_name)
                    outcomes[entry.ca_object_id] = (registry, "")
                except Exception as exc:  # noqa: BLE001 - one CA never blocks the next
                    telemetry.capture_exception(exc)
                    print_exception(exception=exc)
                    outcomes[entry.ca_object_id] = (None, REASON_READ_FAILED)

        run_async_sync(_run())
    except Exception as exc:  # noqa: BLE001 - outcomes default to not assessed
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    return outcomes


__all__ = ["rerun_pending_ca_registry_probes"]
