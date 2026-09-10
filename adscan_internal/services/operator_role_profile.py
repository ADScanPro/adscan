"""Persisted operator-role profile — the role the CLI can read back at runtime.

The read side of this profile (:func:`get_operator_role`, :data:`ROLE_PROFILE_KEYS`,
:data:`PROFILE_FILENAME`, :data:`_ROLE_FIELD`) moved to
:mod:`adscan_core.operator_role` so the host launcher, the container runtime, and
any core panel renderer share one implementation — see that module's docstring
for the full robustness contract and rationale (why the profile lives in the
state dir rather than ``config.json``).

The WRITE side (:func:`set_operator_role`) stays here: it is only ever called
from the container runtime during the operator survey
(``operator_survey.py``), never from host/launcher code, so there is no reason
to promote it to ``adscan_core``. It imports the filename/field constants from
the core module so there is exactly one source of truth for where the profile
lives on disk.

Robustness contract
-------------------
* :func:`set_operator_role` is best-effort and never raises; a failed write at
  worst means the role is asked / defaulted again next run.
"""

from __future__ import annotations

import json
import os

from adscan_core.operator_role import (  # noqa: F401
    PROFILE_FILENAME,
    ROLE_PROFILE_KEYS,
    _ROLE_FIELD,
    _profile_path,
    get_operator_role,
)


def set_operator_role(key: str | None) -> bool:
    """Persist the operator-role ``key``. Best-effort; returns success.

    A falsy / non-string key is a no-op (returns ``False``) so a cancelled or
    empty answer never overwrites a previously stored role. Never raises.
    """
    if not key or not isinstance(key, str):
        return False
    resolved = _profile_path()
    document = {_ROLE_FIELD: key.strip()}
    try:
        resolved.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = resolved.with_name(resolved.name + ".tmp")
        tmp_path.write_text(
            json.dumps(document, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        os.replace(tmp_path, resolved)
        return True
    except OSError:
        return False


__all__ = [
    "PROFILE_FILENAME",
    "ROLE_PROFILE_KEYS",
    "get_operator_role",
    "set_operator_role",
]
