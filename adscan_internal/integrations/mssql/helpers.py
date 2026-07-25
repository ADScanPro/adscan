"""Shared helpers for the native MSSQL integration."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from adscan_internal.services.credential_routing import looks_like_ntlm_hash


def is_hash_authentication(password: str) -> bool:
    """Return whether ``password`` is a 32-hex-character NTLM hash.

    Used by the native backend to decide whether to call
    ``impacket.tds.MSSQL.login`` with ``hashes=`` instead of a plaintext
    password. Delegates to the central
    :func:`adscan_internal.services.credential_routing.looks_like_ntlm_hash`
    so the format definition stays single-sourced across the codebase.
    """
    return looks_like_ntlm_hash(password)


# Data-source spellings that all denote "this same instance" (a loopback).
_SELF_DATA_SOURCE_TOKENS = frozenset(
    {".", "(local)", "localhost", "127.0.0.1", "::1", "(localdb)"}
)


def _norm(value: object) -> str:
    """Lower-case, trimmed string form used for case-insensitive comparisons."""
    return str(value or "").strip().casefold()


def _extract_linked_server_fields(row: Any) -> tuple[str, str]:
    """Pull ``(name, data_source)`` from a linked-server row of any shape.

    Tolerates the three row shapes the linked-server queries produce: the
    ``sys.servers`` DETAIL rows (``linked_server`` / ``data_source`` keys), the
    ``sp_linkedservers`` BASIC rows (``SRV_NAME`` / ``name`` keys), and parsed
    :class:`~adscan_internal.integrations.mssql.models.LinkedServer` objects
    (``.name`` / ``.data_source`` attributes).
    """
    if isinstance(row, Mapping):
        name = (
            row.get("linked_server")
            or row.get("name")
            or row.get("SRV_NAME")
            or ""
        )
        data_source = row.get("data_source") or ""
        return str(name), str(data_source)
    return str(getattr(row, "name", "") or ""), str(getattr(row, "data_source", "") or "")


def is_self_linked_server(current_instance_name: str | None, row: Any) -> bool:
    """Return whether a linked-server row is the loopback self-reference.

    SQL Server frequently lists the local instance itself among the configured
    linked servers (``sys.servers`` with ``is_linked = 1`` whose ``name`` equals
    ``@@SERVERNAME``). That self-link is not a real pivot target: attempting to
    enable / execute across it wastes a round-trip and yields the confusing
    ``'' is not defined as a remote login`` error, and in the attack graph it
    would emit a useless ``<host> -> <host>`` self-loop edge. This is the single
    canonical test every linked-server consumer applies at the producer so no
    downstream code (post-auth workflow, collector inventory, linked-server
    graph edges, pivot map) ever sees the self-reference.

    Args:
        current_instance_name: The local instance's ``@@SERVERNAME``
            (``sweep.identity.server_name``), e.g. ``DC01\\SQLEXPRESS``. When
            empty/unknown, filtering is skipped (returns ``False``).
        row: One linked-server row — a mapping (DETAIL or BASIC query row) or a
            ``LinkedServer`` object.

    Returns:
        ``True`` when the row denotes the local instance itself.
    """
    self_name = _norm(current_instance_name)
    if not self_name:
        return False
    name, data_source = _extract_linked_server_fields(row)
    name = _norm(name)
    if not name:
        return False
    self_host = self_name.split("\\", 1)[0]
    name_host = name.split("\\", 1)[0]
    # Primary: the link name IS our @@SERVERNAME — exact, or the host part
    # matches across the ``HOST`` vs ``HOST\INSTANCE`` spellings.
    if name == self_name or name == self_host or name_host == self_name:
        return True
    # Secondary guard: a differently-named loopback whose data_source points
    # back at our own instance/host (or is a local sentinel like ``.`` /
    # ``localhost``).
    ds = _norm(data_source)
    if ds and (ds == self_name or ds == self_host or ds in _SELF_DATA_SOURCE_TOKENS):
        return True
    return False


__all__ = ["is_hash_authentication", "is_self_linked_server"]
