"""Helpers for ADscan end-of-session summary metrics and UX."""

from __future__ import annotations

import os
from dataclasses import dataclass

from adscan_internal import print_info_debug, telemetry
from adscan_internal.workspaces import domain_subpath, read_json_file


@dataclass(frozen=True)
class AttackPathSnapshotMetrics:
    """Canonical user-facing attack-path metrics derived from persisted summaries.

    The persisted ``attack_paths_snapshot.json`` file is the single source of truth
    for operator-facing attack-path counts. These metrics intentionally reflect the
    shell-aware summary pipeline rather than raw graph primitives.
    """

    total: int = 0
    exploited: int = 0
    blocked: int = 0
    unsupported: int = 0

    @property
    def unresolved(self) -> int:
        """Return persisted paths that remain non-exploited."""
        return max(0, self.blocked + self.unsupported)

    def to_dict(self) -> dict[str, int]:
        """Return a stable dict representation for existing call sites."""
        return {
            "total": self.total,
            "exploited": self.exploited,
            "blocked": self.blocked,
            "unsupported": self.unsupported,
            "unresolved": self.unresolved,
        }


def count_workspace_credentials(shell: object) -> int:
    """Return total credentials currently stored across all loaded domains."""
    try:
        domains_data = getattr(shell, "domains_data", {}) or {}
        if not isinstance(domains_data, dict):
            return 0
        total = 0
        for domain_data in domains_data.values():
            if not isinstance(domain_data, dict):
                continue
            creds = domain_data.get("credentials")
            if isinstance(creds, dict):
                total += len(creds)
        return max(0, total)
    except Exception as exc:  # pragma: no cover - defensive
        telemetry.capture_exception(exc)
        return 0


def get_attack_path_snapshot_metrics(
    shell: object, *, domains: list[str] | None = None
) -> AttackPathSnapshotMetrics:
    """Return canonical user-facing attack-path metrics from persisted snapshots."""
    try:
        workspace_cwd = (
            shell._get_workspace_cwd()
            if hasattr(shell, "_get_workspace_cwd")
            else getattr(shell, "current_workspace_dir", os.getcwd())
        )
        domains_dir = getattr(shell, "domains_dir", "domains")
        domains_data = getattr(shell, "domains_data", {}) or {}
        if not isinstance(domains_data, dict):
            return AttackPathSnapshotMetrics()
        requested_domains = {
            str(domain_name or "").strip().lower()
            for domain_name in (domains or [])
            if str(domain_name or "").strip()
        }

        counts = {"total": 0, "exploited": 0, "blocked": 0, "unsupported": 0}
        analyzed_domains = 0
        for domain_name in domains_data.keys():
            domain = str(domain_name or "").strip()
            if not domain:
                continue
            if requested_domains and domain.lower() not in requested_domains:
                continue
            snapshot_path = domain_subpath(
                workspace_cwd,
                domains_dir,
                domain,
                "attack_paths_snapshot.json",
            )
            if not os.path.exists(snapshot_path):
                continue
            payload = read_json_file(snapshot_path)
            paths = payload.get("paths") if isinstance(payload, dict) else None
            if not isinstance(paths, list):
                continue
            analyzed_domains += 1
            for path in paths:
                if not isinstance(path, dict):
                    continue
                counts["total"] += 1
                status = str(path.get("status") or "").strip().lower()
                if status in counts:
                    counts[status] += 1

        if analyzed_domains <= 0:
            return AttackPathSnapshotMetrics()
        return AttackPathSnapshotMetrics(
            total=max(0, counts["total"]),
            exploited=max(0, counts["exploited"]),
            blocked=max(0, counts["blocked"]),
            unsupported=max(0, counts["unsupported"]),
        )
    except Exception as exc:  # pragma: no cover - best effort
        telemetry.capture_exception(exc)
        print_info_debug(f"[summary] attack-path snapshot breakdown unavailable: {exc}")
        return AttackPathSnapshotMetrics()


def get_attack_path_summary_breakdown(shell: object) -> dict[str, int]:
    """Return snapshot metrics as a dict for legacy call sites."""
    return get_attack_path_snapshot_metrics(shell).to_dict()


def resolve_session_attack_paths_for_summary(
    shell: object, *, fallback_count: int
) -> int:
    """Resolve canonical user-facing attack-path counts for summaries and telemetry."""
    fallback = max(0, int(fallback_count or 0))
    snapshot_metrics = get_attack_path_snapshot_metrics(shell)
    if snapshot_metrics.total > 0:
        print_info_debug(
            "[summary] attack-path count resolved from persisted summaries: "
            f"total={snapshot_metrics.total} fallback={fallback}"
        )
        return snapshot_metrics.total
    return fallback
