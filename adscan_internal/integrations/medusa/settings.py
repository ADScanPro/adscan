"""Shared Medusa execution policy."""

from __future__ import annotations

from .helpers import MedusaSweepSettings


def get_recommended_medusa_settings(
    protocol: str,
    *,
    target_count: int,
) -> MedusaSweepSettings:
    """Return conservative Medusa settings for one protocol."""
    normalized_protocol = str(protocol or "").strip().lower()
    normalized_target_count = max(int(target_count or 1), 1)

    if normalized_protocol == "rdp":
        if normalized_target_count >= 1000:
            return MedusaSweepSettings(
                total_logins=5,
                concurrent_hosts=6,
                connect_timeout_seconds=5,
                retry_count=1,
                retry_sleep_seconds=2,
            )
        if normalized_target_count >= 250:
            return MedusaSweepSettings(
                total_logins=4,
                concurrent_hosts=5,
                connect_timeout_seconds=5,
                retry_count=1,
                retry_sleep_seconds=2,
            )
        return MedusaSweepSettings(
            total_logins=3,
            concurrent_hosts=4,
            connect_timeout_seconds=5,
            retry_count=1,
            retry_sleep_seconds=2,
        )

    return MedusaSweepSettings(
        total_logins=4,
        concurrent_hosts=4,
        connect_timeout_seconds=5,
        retry_count=1,
        retry_sleep_seconds=1,
    )
