"""The review of a database server, kept within memory and declared when cut short.

The MSSQL face of :mod:`adscan_internal.services.host_review_coverage`, which
holds the logic every transport shares: a file listing that reached its bound is
declared as stage ``mssql_file_review``, and the post-authentication workflow
runs under :func:`adscan_core.memory_guard.memory_bounded` as stage
``mssql_post_auth``. Each function here is the shared one with the MSSQL
profile.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from adscan_internal.services import host_review_coverage as _shared
from adscan_internal.services.host_review_coverage import (
    FILE_REVIEW_UNIT,
    LISTING_STATE_FILENAME,
    MSSQL_REVIEW,
    POST_AUTH_STOPS_FILENAME,
    POST_AUTH_UNIT,
)


def file_review_coverage_block(states: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The ``resource_coverage`` block for a domain's incomplete listings."""
    return _shared.file_review_coverage_block(MSSQL_REVIEW, states)


def record_listing_state(
    shell: Any,
    *,
    domain: str,
    host: str,
    manifest_path: str,
    listing: Any,
) -> bool:
    """Record how one server's file listing ended and refresh the domain's gap."""
    return _shared.record_listing_state(
        MSSQL_REVIEW,
        shell,
        domain=domain,
        host=host,
        manifest_path=manifest_path,
        listing=listing,
    )


def listing_gap_statement(listing: Any) -> str:
    """The client sentence for one server's incomplete listing (for a result dict)."""
    return _shared.listing_gap_statement(MSSQL_REVIEW, listing)


def run_post_auth_bounded(
    shell: Any,
    domain: str,
    host: str,
    run: Callable[[], Any],
    *,
    state_dir: str | Path | None = None,
) -> tuple[bool, Any]:
    """Run the post-authentication workflow (one call) under its memory boundary."""
    return _shared.run_post_auth_bounded(
        MSSQL_REVIEW, shell, domain, host, run, state_dir=state_dir
    )


__all__ = (
    "FILE_REVIEW_UNIT",
    "LISTING_STATE_FILENAME",
    "POST_AUTH_STOPS_FILENAME",
    "POST_AUTH_UNIT",
    "file_review_coverage_block",
    "listing_gap_statement",
    "record_listing_state",
    "run_post_auth_bounded",
)
