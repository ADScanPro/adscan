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
qualifies and the read completed, not assessed with its reason otherwise. The
edges a late read decides are added to the same in-memory result, so the
orchestrator's second persist carries them through the normal persistence path
(derived ESC compromise steps included). A later collection (the privileged
refresh after a domain compromise) runs this again, which is how a credential
gained after the collection is picked up.
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
        ``True`` when edges were added to ``result`` and it must be persisted
        again. Never raises.
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

    changed = False
    for entry in pending:
        ca = result.nodes.get(entry.ca_object_id)
        if ca is None:
            continue
        registry, skip_reason = probes.get(
            entry.ca_object_id, (None, REASON_READ_FAILED)
        )
        new_edges = registry_dependent_edges(
            ca=ca, registry=registry, templates=templates, result=result, domain=domain
        )
        for edge in new_edges:
            result.add_edge(edge)
        changed = changed or bool(new_edges)
        observe_ca_registry_checks(
            shell,
            domain=domain,
            ca=ca,
            registry=registry,
            skip_reason=skip_reason or REASON_NO_LOCAL_ADMIN,
            ca_edge_relations={e.relation for e in new_edges},
            result=result,
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
    return changed


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
