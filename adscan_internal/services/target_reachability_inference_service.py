"""Reachability inference layer — derives whether a target is known-unreachable
from the current vantage AND from every pivot probed so far.

ADscan already persists three independent reachability signals per domain:

1. ``network_reachability_report.json`` — direct TCP probe results from the
   current vantage (the host running ADscan, plus any active Ligolo proxy).
2. ``<service>/<host>_pivot_reachability_report.json`` — per-pivot probe
   results, one file per intermediate host ADscan attempted to use as a
   pivot via WinRM/MSSQL. Each report contains either:
     - ``targets`` — list of reachable targets discovered through this pivot
       (positive evidence)
     - ``skip_reason`` + ``hidden_targets`` — negative evidence: this pivot
       has no matching subnet or explicit route to reach any of the listed
       blocked targets
3. The recompute on success via ``post_pivot_followup_service`` updates the
   direct vantage report when a pivot opens new reachability.

What this module adds is the **inference layer**: consume those reports and
answer one question consistently for every consumer (attack path execution
loop, pivot UX, future exporters):

    "Has every reasonable source already been probed against host X, and
    have they all failed?"

When that holds, host X is *globally unreachable from the current vantage's
known frontier* and any caller (e.g. the attack-path loop) can short-circuit
the per-path pivot UX, saving redundant WinRM probes.

Design rules:

- **No new persistence**. Read the reports that already exist; the
  inference is recomputed on every call. Cheap (single-digit file reads)
  and stays consistent with whatever the rest of the codebase wrote last.
- **No side effects**. This module never writes, never prompts, never
  schedules work. Callers decide what to do with the verdict.
- **Conservative**. When uncertain (no probe history, stale data, missing
  fields) the answer defaults to ``False`` so existing behavior is
  preserved — we only short-circuit when we have solid evidence.

Future extensions (Fase 2 in the agreed scope):
- Persist a consolidated ``reachability_inference.json`` derived from these
  primary sources, with vantage signature + TTL, so consumers can read one
  file instead of N.
- Surface as a CLI command (``adscan reachability_matrix <domain>``).
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from typing import Any, Iterable

from adscan_internal.workspaces import domain_subpath


# ---------------------------------------------------------------------------
# Per-pivot verdict — what one ``<host>_pivot_reachability_report.json`` file
# tells us about reaching a specific target IP from that pivot host.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PivotProbeVerdict:
    """One pivot host's verdict about reaching one target IP."""

    pivot_host: str
    service: str  # "winrm" | "mssql" | ...
    target_ip: str
    reachable: bool | None  # None = no information (not probed)
    reason: str  # "confirmed_via_targets" | "no_matching_subnet_or_route" | ...
    report_path: str  # absolute path of the source report, for debug
    generated_at: str | None = None


# ---------------------------------------------------------------------------
# Aggregate inference verdict — combines all pivot reports + the direct
# vantage report for one target.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TargetReachabilityInference:
    """Consolidated reachability verdict for one target IP.

    Attributes:
        target_ip: The IP address probed against (canonicalised).
        direct_reachable: True/False/None — what ``network_reachability_report``
            says about reaching this target directly from the current vantage.
            ``None`` means the report does not mention this target.
        pivot_verdicts: One entry per pivot host ADscan has probed.
        globally_unreachable: True when:
            - direct probe says unreachable (or no entry → treat as
              unreachable for the *current* network frontier), AND
            - every probed pivot says unreachable (no positive evidence
              anywhere), AND
            - at least one pivot was actually probed (so we have evidence).
        rationale: Operator-readable explanation of how the verdict was
            derived; goes to debug logs and (eventually) to the
            ``reachability_matrix`` CLI command.
    """

    target_ip: str
    direct_reachable: bool | None
    pivot_verdicts: tuple[PivotProbeVerdict, ...]
    globally_unreachable: bool
    rationale: str

    @property
    def has_evidence(self) -> bool:
        """Return True when at least one probe (direct or pivot) was recorded."""
        return self.direct_reachable is not None or bool(self.pivot_verdicts)


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def is_target_known_unreachable_from_current_vantage(
    shell: Any,
    *,
    domain: str,
    target_ip: str,
) -> bool:
    """Return True when every probed source has already failed to reach this target.

    This is the load-bearing call for the attack-path execution loop:
    when it returns True, the loop can skip the per-path pivot UX
    (``maybe_offer_pivot_opportunity_for_host_viability``) because every
    known pivot has already been probed and none can reach the target.

    Conservative defaults: returns ``False`` when no probes have been
    recorded, when reports are missing, or when any pivot has positive
    evidence of reaching the target — i.e. existing behavior is preserved
    unless we have explicit evidence of full-network unreachability.
    """
    inference = infer_target_reachability(shell, domain=domain, target_ip=target_ip)
    return inference.globally_unreachable


def infer_target_reachability(
    shell: Any,
    *,
    domain: str,
    target_ip: str,
) -> TargetReachabilityInference:
    """Build the full inference verdict for one target IP.

    Reads the direct vantage report + every per-pivot report under the
    domain's WinRM/MSSQL directories. Returns a structured result so the
    caller can both decide (``globally_unreachable``) and explain
    (``rationale``).
    """
    target_norm = _normalize_ip(target_ip)
    if not target_norm:
        return TargetReachabilityInference(
            target_ip=str(target_ip),
            direct_reachable=None,
            pivot_verdicts=(),
            globally_unreachable=False,
            rationale="empty target token — cannot infer",
        )

    workspace_dir = getattr(shell, "current_workspace_dir", None) or ""
    domains_dir = getattr(shell, "domains_dir", "domains")

    direct_reachable = _resolve_direct_reachability(
        workspace_dir=workspace_dir,
        domains_dir=domains_dir,
        domain=domain,
        target_ip=target_norm,
    )
    pivot_verdicts = _collect_pivot_verdicts(
        workspace_dir=workspace_dir,
        domains_dir=domains_dir,
        domain=domain,
        target_ip=target_norm,
    )

    # Positive evidence anywhere → not globally unreachable.
    if direct_reachable is True or any(v.reachable is True for v in pivot_verdicts):
        return TargetReachabilityInference(
            target_ip=target_norm,
            direct_reachable=direct_reachable,
            pivot_verdicts=pivot_verdicts,
            globally_unreachable=False,
            rationale="positive reachability evidence exists",
        )

    # We need negative evidence from at least one pivot AND a direct-vantage
    # signal of unreachability (or absence, treated as unreachable for the
    # current frontier). No pivots probed → we cannot conclude global
    # unreachability; the operator may still need to probe.
    negative_pivots = [v for v in pivot_verdicts if v.reachable is False]
    if not negative_pivots:
        return TargetReachabilityInference(
            target_ip=target_norm,
            direct_reachable=direct_reachable,
            pivot_verdicts=pivot_verdicts,
            globally_unreachable=False,
            rationale=(
                "no pivot has been probed yet for this target — "
                "cannot infer global unreachability"
            ),
        )

    # All pivots that have an opinion say no, direct says no (or unknown),
    # → globally unreachable from the current vantage's known frontier.
    pivot_summary = ", ".join(
        f"{v.pivot_host}({v.service}):{v.reason}" for v in negative_pivots
    )
    direct_summary = (
        "direct=unreachable"
        if direct_reachable is False
        else "direct=unknown"
    )
    rationale = (
        f"globally unreachable: {direct_summary}, "
        f"{len(negative_pivots)} pivot(s) all failed: {pivot_summary}"
    )
    return TargetReachabilityInference(
        target_ip=target_norm,
        direct_reachable=direct_reachable,
        pivot_verdicts=pivot_verdicts,
        globally_unreachable=True,
        rationale=rationale,
    )


def collect_pivot_reachable_targets(
    shell: Any,
    *,
    domain: str,
    service: str,
    ports: Iterable[int] | None = None,
) -> dict[str, list[int]]:
    """Return ``{target_ip: reachable_ports}`` confirmed reachable via any pivot.

    Positive evidence only: walks every ``<service>/<host>_pivot_reachability_report.json``
    and returns the targets a pivot actually reached (non-empty ``reachable_ports``).
    When ``ports`` is given, a target is included only when its reachable set
    intersects ``ports`` — so an MSSQL caller (``ports=[1433]``) gets the hosts a
    pivot confirmed listening on 1433, NOT every host the pivot could see. This is
    the load-bearing input that lets a service reachable ONLY over a pivot (where
    the direct SYN scan missed the port) still become a connect target.

    Best-effort: ``{}`` when there is no pivot evidence. Never raises.
    """
    workspace_dir = getattr(shell, "current_workspace_dir", None) or ""
    domains_dir = getattr(shell, "domains_dir", "domains")
    service_clean = str(service or "").strip().lower()
    if not workspace_dir or not service_clean:
        return {}
    want_ports: set[int] | None = None
    if ports is not None:
        want_ports = set()
        for port in ports:
            try:
                want_ports.add(int(port))
            except (TypeError, ValueError):
                continue

    service_dir = domain_subpath(workspace_dir, domains_dir, domain, service_clean)
    if not service_dir or not os.path.isdir(service_dir):
        return {}

    out: dict[str, list[int]] = {}
    for entry_name in sorted(os.listdir(service_dir)):
        if not entry_name.endswith("_pivot_reachability_report.json"):
            continue
        payload = _load_json(os.path.join(service_dir, entry_name))
        if not isinstance(payload, dict):
            continue
        targets = payload.get("targets")
        if not isinstance(targets, list):
            continue
        for target in targets:
            if not isinstance(target, dict):
                continue
            ip = _normalize_ip(target.get("ip"))
            if not ip:
                continue
            raw_ports = target.get("reachable_ports")
            if not isinstance(raw_ports, list) or not raw_ports:
                continue
            reachable: list[int] = []
            for port in raw_ports:
                try:
                    reachable.append(int(port))
                except (TypeError, ValueError):
                    continue
            if not reachable:
                continue
            if want_ports is not None and not (want_ports & set(reachable)):
                continue
            merged = set(out.get(ip, [])) | set(reachable)
            out[ip] = sorted(merged)
    return out


# ---------------------------------------------------------------------------
# Direct vantage resolution
# ---------------------------------------------------------------------------


def _resolve_direct_reachability(
    *,
    workspace_dir: str,
    domains_dir: str,
    domain: str,
    target_ip: str,
) -> bool | None:
    """Return True/False/None from ``network_reachability_report.json``."""
    report_path = domain_subpath(
        workspace_dir, domains_dir, domain, "network_reachability_report.json"
    )
    payload = _load_json(report_path)
    if not isinstance(payload, dict):
        return None
    ips = payload.get("ips")
    if not isinstance(ips, list):
        return None
    for entry in ips:
        if not isinstance(entry, dict):
            continue
        if _normalize_ip(entry.get("ip")) != target_ip:
            continue
        status = str(entry.get("status") or "").strip().lower()
        if status == "no_response_from_current_vantage":
            return False
        open_ports = entry.get("open_ports") or entry.get("reachable_ports")
        if isinstance(open_ports, list) and open_ports:
            return True
        # Entry exists but no positive ports → conservative: treat as unknown.
        return None
    return None


# ---------------------------------------------------------------------------
# Per-pivot verdicts
# ---------------------------------------------------------------------------


_PIVOT_REPORT_SERVICES: tuple[str, ...] = ("winrm", "mssql")


def _collect_pivot_verdicts(
    *,
    workspace_dir: str,
    domains_dir: str,
    domain: str,
    target_ip: str,
) -> tuple[PivotProbeVerdict, ...]:
    """Walk every ``<service>/<host>_pivot_reachability_report.json`` and
    extract the verdict for ``target_ip``."""
    verdicts: list[PivotProbeVerdict] = []
    seen_pairs: set[tuple[str, str]] = set()

    for service in _PIVOT_REPORT_SERVICES:
        service_dir = domain_subpath(workspace_dir, domains_dir, domain, service)
        if not service_dir or not os.path.isdir(service_dir):
            continue
        for entry_name in sorted(os.listdir(service_dir)):
            if not entry_name.endswith("_pivot_reachability_report.json"):
                continue
            report_path = os.path.join(service_dir, entry_name)
            payload = _load_json(report_path)
            if not isinstance(payload, dict):
                continue
            verdict = _verdict_from_pivot_report(
                payload=payload,
                service=service,
                target_ip=target_ip,
                report_path=report_path,
            )
            if verdict is None:
                continue
            pair = (verdict.pivot_host, verdict.service)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            verdicts.append(verdict)

    return tuple(verdicts)


def _verdict_from_pivot_report(
    *,
    payload: dict[str, Any],
    service: str,
    target_ip: str,
    report_path: str,
) -> PivotProbeVerdict | None:
    """Map one pivot report to a single-target verdict."""
    pivot_host = str(payload.get("pivot_host") or "").strip()
    if not pivot_host:
        return None
    generated_at = str(payload.get("generated_at") or "").strip() or None

    # Positive evidence: ``targets`` lists IPs the pivot successfully reached.
    targets = payload.get("targets")
    if isinstance(targets, list):
        for entry in targets:
            if not isinstance(entry, dict):
                continue
            if _normalize_ip(entry.get("ip")) != target_ip:
                continue
            reachable_ports = entry.get("reachable_ports")
            if isinstance(reachable_ports, list) and reachable_ports:
                return PivotProbeVerdict(
                    pivot_host=pivot_host,
                    service=service,
                    target_ip=target_ip,
                    reachable=True,
                    reason="confirmed_via_targets",
                    report_path=report_path,
                    generated_at=generated_at,
                )

    # Negative evidence: ``skip_reason`` + ``hidden_targets`` records the
    # pivot was asked but had no route to any candidate.
    skip_reason = str(payload.get("skip_reason") or "").strip().lower()
    if skip_reason:
        hidden_targets = payload.get("hidden_targets") or []
        if isinstance(hidden_targets, list):
            for hidden in hidden_targets:
                if _normalize_ip(hidden) == target_ip:
                    return PivotProbeVerdict(
                        pivot_host=pivot_host,
                        service=service,
                        target_ip=target_ip,
                        reachable=False,
                        reason=skip_reason,
                        report_path=report_path,
                        generated_at=generated_at,
                    )

    # Negative evidence: target appears under ``no_connectivity_confirmed``
    # or equivalent summary list (when present). Falls back to no signal.
    for negative_key in (
        "no_connectivity_confirmed_targets",
        "unreachable_targets",
        "no_response_targets",
    ):
        bucket = payload.get(negative_key)
        if not isinstance(bucket, list):
            continue
        for entry in bucket:
            ip_candidate: str
            if isinstance(entry, dict):
                ip_candidate = _normalize_ip(entry.get("ip"))
            else:
                ip_candidate = _normalize_ip(entry)
            if ip_candidate == target_ip:
                return PivotProbeVerdict(
                    pivot_host=pivot_host,
                    service=service,
                    target_ip=target_ip,
                    reachable=False,
                    reason=negative_key,
                    report_path=report_path,
                    generated_at=generated_at,
                )

    return None  # No signal about this target from this pivot report.


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalize_ip(value: object) -> str:
    """Return a normalised IP/hostname token (strip + lowercase)."""
    return str(value or "").strip().rstrip(".").lower()


def _load_json(path: str) -> Any:
    """Load a JSON file, returning ``None`` on any error (missing, malformed)."""
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None


__all__ = [
    "PivotProbeVerdict",
    "TargetReachabilityInference",
    "collect_pivot_reachable_targets",
    "infer_target_reachability",
    "is_target_known_unreachable_from_current_vantage",
]
