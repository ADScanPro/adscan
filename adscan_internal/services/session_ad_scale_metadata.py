"""Anonymous AD-scale fingerprint for session telemetry.

Lets the session viewer (Vercel sessions) filter/sort sessions by environment
SCALE — multi-domain, host count, user count, enabled counts — so the next
large-environment behaviour (e.g. the collector on a 2k-host domain) is findable
in the field instead of guessed at in a synthetic lab.

PRIVACY HARD RULE — this fingerprint is ANONYMOUS by construction. It carries
ONLY integer counts. It NEVER includes domain names, principal names, SIDs, or
any org identifier (those are customer-sensitive and must never leave the host —
same rule as the workspace-name → ``workspace_id_hash`` policy in telemetry.py).
The per-domain breakdown is an unlabelled list of count dicts.

Source: ``domains_data[<domain>]["collection_stats"]`` — a compact counts dict
persisted by the attack-graph save (``_compute_ad_scale_stats`` in
attack_graph_service.py). Reading it is cheap (small in-memory dicts), so this is
safe to call on the per-command telemetry path; it never re-reads attack_graph.json.
"""
from __future__ import annotations

from typing import Any

_COUNT_KEYS = (
    "computers",
    "enabled_computers",
    "users",
    "enabled_users",
    "groups",
    "ous",
    "gpos",
)


def build_session_ad_scale_metadata(shell: Any) -> dict[str, Any]:
    """Return an anonymous AD-scale fingerprint for the session.

    Best-effort: never raises; returns ``{}`` when no collection has run.
    """
    try:
        domains_data = getattr(shell, "domains_data", None)
        if not isinstance(domains_data, dict) or not domains_data:
            return {}

        per_domain: list[dict[str, int]] = []
        for data in domains_data.values():
            if not isinstance(data, dict):
                continue
            stats = data.get("collection_stats")
            if not isinstance(stats, dict):
                continue
            # Keep only known integer count keys (anonymity + schema hygiene).
            entry = {k: int(stats.get(k, 0) or 0) for k in _COUNT_KEYS}
            per_domain.append(entry)

        domain_count = len(domains_data)
        meta: dict[str, Any] = {
            "ad_domain_count": domain_count,
            "ad_multi_domain": domain_count > 1,
        }
        if not per_domain:
            # Domains exist but none collected yet — still report the domain count.
            return meta

        totals = {k: sum(d[k] for d in per_domain) for k in _COUNT_KEYS}
        meta.update(
            {
                "ad_collected_domain_count": len(per_domain),
                "ad_total_computers": totals["computers"],
                "ad_enabled_computers": totals["enabled_computers"],
                "ad_total_users": totals["users"],
                "ad_enabled_users": totals["enabled_users"],
                "ad_total_groups": totals["groups"],
                "ad_max_domain_computers": max(d["computers"] for d in per_domain),
                "ad_max_domain_users": max(d["users"] for d in per_domain),
                # Anonymous per-domain breakdown (counts only, no names).
                "ad_scale_domains": per_domain,
            }
        )
        return meta
    except Exception:
        return {}
