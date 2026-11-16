"""Record, per run, whether the host sweep read each per-host source on every host.

The host sweep reads two sources per host that a completed sweep can still leave
unread: the local registry (only as a local administrator; a host where the
account is not one is skipped, by design and without an error) and the SMBv1
negotiate (a host that does not answer it conclusively). A finding graded from
one of them that is absent from a later run was not observed absent on a host
whose source was not read, so its absence is not a fix.

Each family here is ``instrumented`` in ``adscan_core.engagement.detectors``:
reconciliation requires its observation before an absent finding can close.
This module writes that observation for every outcome, from the host nodes the
sweep just produced:

* ``finding`` when the family's own grader flags a host it read;
* ``clear`` when it read the source on hosts and flagged none;
* ``not_assessed`` when it read it on no host;
* complete only when the source was read on every host the sweep was to visit,
  so a run that read it on some hosts closes nothing (the finding lists hosts,
  and the hosts not read could still carry it).

The grading is the scan's own (``audit_analyzer``), never a copy: a host counts
as flagged exactly when the scan would emit the finding for it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Optional

from adscan_core import telemetry
from adscan_core.engagement.observations import Outcome
from adscan_core.rich_output import print_exception

#: Registry values each registry family is graded from (``audit_analyzer``).
_REGISTRY_FAMILY_PROPS: Mapping[str, tuple[str, ...]] = {
    "host.registry.lsa_protection": ("reg_lsa_runasppl",),
    "host.registry.wdigest": ("reg_wdigest_uselogoncredential",),
    "host.registry.lm_hash_storage": ("reg_lsa_nolmhash",),
    "host.registry.lm_compatibility": ("reg_lsa_lmcompatibilitylevel",),
    "host.registry.ntlm_min_session_security": (
        "reg_msv1_0_ntlmminclientsec",
        "reg_msv1_0_ntlmminserversec",
    ),
    "host.registry.lsass_custom_ssp": ("reg_lsa_allowcustomsspsaps",),
}
_READ_STATES = frozenset({"present", "absent"})

#: Coverage reasons (recorded on the family's observation).
REASON_NO_LOCAL_ADMIN = "no_local_admin_on_host"
REASON_REGISTRY_NOT_READ = "registry_not_read"
REASON_SMBV1_INCONCLUSIVE = "smbv1_probe_inconclusive"
REASON_HOSTS_NOT_READ = "hosts_not_read"
REASON_SWEEP_SIZE_UNKNOWN = "swept_hosts_unknown"


@dataclass(frozen=True)
class HostRead:
    """What one family established on one host."""

    read: bool
    flagged: bool = False
    reason: str = ""


@dataclass(frozen=True)
class HostSourceFamily:
    """One per-host family: its check id and how a host's read is judged."""

    check_id: str
    judge: Callable[[Any], HostRead]


def _props(node: Any) -> Mapping[str, Any]:
    props = getattr(node, "properties", None)
    return props if isinstance(props, Mapping) else {}


def _registry_judge(check_id: str, finding_key: str) -> Callable[[Any], HostRead]:
    keys = _REGISTRY_FAMILY_PROPS[check_id]

    def judge(node: Any) -> HostRead:
        props = _props(node)
        gate = props.get("reg_admin_gate")
        if gate is not True:
            reason = REASON_NO_LOCAL_ADMIN if gate is False else REASON_REGISTRY_NOT_READ
            return HostRead(read=False, reason=reason)
        states = [str(props.get(f"{key}_state") or "").strip().lower() for key in keys]
        if any(state not in _READ_STATES for state in states):
            return HostRead(read=False, reason=REASON_REGISTRY_NOT_READ)
        from adscan_internal.services.collector.audit_analyzer import (  # noqa: PLC0415
            _registry_hardening_findings,
        )

        flagged = any(
            getattr(f, "category", "") == finding_key
            for f in _registry_hardening_findings(node)
        )
        return HostRead(read=True, flagged=flagged)

    return judge


def _smbv1_judge(node: Any) -> HostRead:
    props = _props(node)
    if "smb_v1" not in props:
        return HostRead(read=False, reason=REASON_SMBV1_INCONCLUSIVE)
    return HostRead(read=True, flagged=bool(props.get("smb_v1")))


def _families() -> tuple[HostSourceFamily, ...]:
    from adscan_core.engagement.detectors import detector_by_id  # noqa: PLC0415

    out: list[HostSourceFamily] = []
    for check_id in _REGISTRY_FAMILY_PROPS:
        detector = detector_by_id(check_id)
        finding_key = detector.finding_keys[0] if detector and detector.finding_keys else ""
        out.append(HostSourceFamily(check_id, _registry_judge(check_id, finding_key)))
    out.append(HostSourceFamily("host.smbv1", _smbv1_judge))
    return tuple(out)


#: Every family this module records. ``test_source_declarations`` checks that
#: each per-host instrumented family in the detector table is listed here.
HOST_SOURCE_CHECK_IDS: tuple[str, ...] = (*_REGISTRY_FAMILY_PROPS, "host.smbv1")


def _object_id(node: Any) -> str:
    return str(getattr(node, "object_id", "") or "").strip().upper()


def _computers(nodes: Iterable[Any]) -> list[Any]:
    return [
        n
        for n in nodes or ()
        if str(getattr(n, "kind", "")) == "Computer" and getattr(n, "enabled", None) is not False
    ]


def build_host_source_observations(
    nodes: Iterable[Any], *, swept_hosts: Optional[int]
) -> list[dict[str, Any]]:
    """One observation per per-host family, as ``note_observation`` keyword sets.

    Args:
        nodes: The collected nodes, carrying the sweep's per-host properties.
        swept_hosts: How many hosts the sweep was to visit (its candidate
            count). ``None`` when unknown: no family can then be complete.

    Returns:
        ``[{"check_id", "outcome", "complete", "examined", "total",
        "examined_ids", "reason"}]``, one entry per family.
    """
    computers = _computers(nodes)
    out: list[dict[str, Any]] = []
    for family in _families():
        read_ids: list[str] = []
        flagged = 0
        unread_reasons: set[str] = set()
        for node in computers:
            verdict = family.judge(node)
            if verdict.read:
                oid = _object_id(node)
                if oid:
                    read_ids.append(oid)
                flagged += 1 if verdict.flagged else 0
            elif _touched_by_sweep(node):
                unread_reasons.add(verdict.reason)
        read = len(read_ids)
        if flagged:
            outcome = Outcome.FINDING
        elif read == 0:
            outcome = Outcome.NOT_ASSESSED
        else:
            outcome = Outcome.CLEAR
        reasons = set(unread_reasons)
        if swept_hosts is None:
            reasons.add(REASON_SWEEP_SIZE_UNKNOWN)
        elif read < swept_hosts and not reasons:
            reasons.add(REASON_HOSTS_NOT_READ)
        complete = read > 0 and not reasons
        out.append(
            {
                "check_id": family.check_id,
                "outcome": outcome,
                "complete": complete,
                "examined": read,
                "total": swept_hosts,
                "examined_ids": read_ids,
                "reason": "" if complete else ",".join(sorted(reasons)),
            }
        )
    return out


def _touched_by_sweep(node: Any) -> bool:
    """Whether the sweep reached this host (it left a per-host property on it)."""
    props = _props(node)
    return any(
        key in props for key in ("reg_admin_gate", "smb_signing_required", "smb_v1", "smb_dialect")
    )


def observe_host_sources(
    shell: Any, domain: str, nodes: Iterable[Any], *, swept_hosts: Optional[int]
) -> None:
    """Record every per-host family's observation for ``domain``. Never raises."""
    try:
        from adscan_internal.services.engagement.coverage_recorder import (  # noqa: PLC0415
            note_observation,
        )

        for entry in build_host_source_observations(nodes, swept_hosts=swept_hosts):
            check_id = entry.pop("check_id")
            outcome = entry.pop("outcome")
            note_observation(shell, check_id, outcome, domain=domain, scope_kind="host", **entry)
    except Exception as exc:  # noqa: BLE001 - coverage never breaks collection
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


#: The share-permission family. Its edges are graded per host from each share's
#: security descriptor; the sweep reports the hosts where every descriptor was
#: read (``HostPhaseTiming.share_acl_examined_host_ids``).
SHARE_ACL_CHECK_ID = "smb.share_access"
REASON_SHARE_DESCRIPTOR_UNREAD = "share_descriptor_not_read"


def build_share_acl_observation(
    read_host_ids: Iterable[str],
    examined_host_ids: Iterable[str],
    *,
    swept_hosts: Optional[int],
) -> dict[str, Any]:
    """The share-permission family's observation, as ``note_observation`` keywords.

    Args:
        read_host_ids: Hosts where every listed share's descriptor was read.
        examined_host_ids: Hosts the sweep fully examined (every stage answered).
        swept_hosts: How many hosts the sweep was to visit (``None``: unknown).
    """
    read = sorted({str(h).strip().upper() for h in read_host_ids if str(h or "").strip()})
    examined = {str(h).strip().upper() for h in examined_host_ids if str(h or "").strip()}
    reasons: set[str] = set()
    if examined - set(read):
        reasons.add(REASON_SHARE_DESCRIPTOR_UNREAD)
    if swept_hosts is None:
        reasons.add(REASON_SWEEP_SIZE_UNKNOWN)
    elif len(read) < swept_hosts:
        reasons.add(REASON_HOSTS_NOT_READ)
    complete = bool(read) and not reasons
    return {
        "outcome": Outcome.OBSERVED if read else Outcome.NOT_ASSESSED,
        "complete": complete,
        "examined": len(read),
        "total": swept_hosts,
        "examined_ids": read,
        "reason": "" if complete else ",".join(sorted(reasons)),
    }


def observe_share_acl_reads(
    shell: Any,
    domain: str,
    read_host_ids: Iterable[str],
    examined_host_ids: Iterable[str],
    *,
    swept_hosts: Optional[int],
) -> None:
    """Record on which hosts the share descriptors were read. Never raises."""
    try:
        from adscan_internal.services.engagement.coverage_recorder import (  # noqa: PLC0415
            note_observation,
        )

        entry = build_share_acl_observation(
            read_host_ids, examined_host_ids, swept_hosts=swept_hosts
        )
        note_observation(
            shell,
            SHARE_ACL_CHECK_ID,
            entry["outcome"],
            domain=domain,
            scope_kind="host",
            complete=entry["complete"],
            examined=entry["examined"],
            total=entry["total"],
            examined_ids=entry["examined_ids"],
            reason=entry["reason"],
        )
    except Exception as exc:  # noqa: BLE001 - coverage never breaks collection
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


__all__ = (
    "HOST_SOURCE_CHECK_IDS",
    "SHARE_ACL_CHECK_ID",
    "build_host_source_observations",
    "build_share_acl_observation",
    "observe_host_sources",
    "observe_share_acl_reads",
)
