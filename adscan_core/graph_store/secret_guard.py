"""The store's last line against a recovered secret reaching disk.

The interface contract says no recovered credential ever reaches the store
(``interface.py``, "No secrets"). The writers are expected to redact first, with
the workspace's fingerprint key, through the same seam ``save_attack_graph``
uses (``graph_secret_store.redact_graph_for_persist``), so a reference keeps its
fingerprint and the value is retained in the credential store's sidecar.

This module is what holds when a writer forgets. Every JSON payload a backend
stores (fact notes, datum bodies, object properties, object patches, overlay
payloads) passes through :func:`guard_secrets` on its way in. A payload with no
inline secret is returned unchanged and the check costs one set intersection
per mapping. A payload with one is redacted WITHOUT a key, which is exactly the
fail-closed path ``redact_graph_for_persist`` takes when its key or its sidecar
fails: the value is replaced by a reference with no fingerprint and never
written. Both backends call it, so a test against the memory backend sees what
the on-disk backend stores.

When the guard fires it says so on the debug channel: one line naming the
field and the object id, never the value, so a writer that forgot to redact is
visible instead of silently repaired. No telemetry event is emitted: event names
are an allow-listed set and the guard sits on the store's hot write path.

Stdlib only (plus ``adscan_core.graph_secret_refs``, itself stdlib only); the
debug printer is imported lazily on the rare firing path.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from adscan_core.graph_secret_refs import (
    SECRET_NOTE_KEYS,
    notes_carry_inline_secret,
    redact_note_secrets,
    redact_secrets_deep,
)


def _may_hold_secret(obj: Any) -> bool:
    """Cheap pre-check: does any mapping in ``obj`` use a secret key name?"""
    if isinstance(obj, Mapping):
        if not SECRET_NOTE_KEYS.isdisjoint(obj.keys()):
            return True
        return any(
            isinstance(v, (Mapping, list, tuple)) and _may_hold_secret(v)
            for v in obj.values()
        )
    if isinstance(obj, (list, tuple)):
        return any(
            isinstance(v, (Mapping, list, tuple)) and _may_hold_secret(v) for v in obj
        )
    return False


def _inline_secret_field_names(obj: Any) -> list[str]:
    """Names (never values) of the secret fields held inline anywhere in ``obj``."""
    names: set[str] = set()
    stack: list[Any] = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, Mapping):
            if notes_carry_inline_secret(cur):
                for field in SECRET_NOTE_KEYS:
                    value = cur.get(field)
                    if (
                        value is not None
                        and not isinstance(value, (bool, dict, list))
                        and str(value).strip()
                    ):
                        names.add(str(field))
            stack.extend(
                v for v in cur.values() if isinstance(v, (Mapping, list, tuple))
            )
        elif isinstance(cur, (list, tuple)):
            stack.extend(v for v in cur if isinstance(v, (Mapping, list, tuple)))
    return sorted(names)


def _report_fired(obj: Any, object_id: str, domain: str) -> None:
    """One debug line per firing: the field names and the object id, no value."""
    try:
        from adscan_core.rich_output import print_info_debug  # noqa: PLC0415

        names = _inline_secret_field_names(obj)
        if not names:
            return
        fields = ",".join(names)
        print_info_debug(
            f"graph store secret guard dropped an inline secret: fields={fields} "
            f"object={object_id or 'unknown'} domain={domain or 'unknown'}"
        )
    except Exception:  # noqa: BLE001 - diagnostics must never break a write
        pass


def guard_secrets(
    obj: Any, *, relation: str = "", domain: str = "", object_id: str = ""
) -> Any:
    """Return ``obj`` with every inline secret replaced by a keyless reference.

    Args:
        obj: A JSON payload about to be stored (notes, a datum body, properties).
        relation: The edge relation the payload belongs to, when it is edge
            notes; it decides which credential store the reference names
            (local or domain), as ``redact_note_secrets`` does for the graph.
        domain: The store's domain, recorded on the reference.
        object_id: The id of the object the payload belongs to, named in the
            debug line when the guard fires.

    Returns:
        ``obj`` itself when it holds no inline secret (the common case, no copy),
        else a redacted copy.
    """
    if not _may_hold_secret(obj):
        return obj
    _report_fired(obj, object_id, domain)
    if isinstance(obj, Mapping) and notes_carry_inline_secret(obj):
        obj, _extracted = redact_note_secrets(obj, domain=domain, relation=relation)
    return redact_secrets_deep(obj)


__all__ = ("guard_secrets",)
