"""Persisted operator-role profile — the role the CLI can read back at runtime.

The operator-role question (``adscan start``) records *which kind of work* the
operator does. Historically its answer went only to telemetry, so the running
CLI could never see it: the commercial call-to-action could not branch by role,
and the didactic mode could not adapt what it emphasises. This module fixes that
by persisting the chosen role KEY as a small local profile the CLI reads in
runtime.

Where the value lives (and why it is NOT ``config.json``)
--------------------------------------------------------
The role is written from the container runtime during ``start`` and read back
from the container runtime during a later value moment / didactic render. It has
to survive the ephemeral container, so it lives in the bind-mounted ADscan
**state** directory (``~/.adscan/state/`` on the host ↔ ``/opt/adscan/state/``
in the container) — the same store used by ``first_run_notices`` and the
show-once survey flag, for the same reason. ``config.json`` sits above the mount
and would be discarded when the container exits.

Robustness contract
-------------------
* :func:`get_operator_role` returns ``None`` when the profile is unset, missing,
  corrupt, or unreadable — never raises. A missing role degrades to the safe
  default everywhere it is consumed (the /pro CTA, the offensive didactic
  emphasis), never to a broken flow.
* :func:`set_operator_role` is best-effort and never raises; a failed write at
  worst means the role is asked / defaulted again next run.
* An unknown key (not in :data:`ROLE_PROFILE_KEYS`) is stored verbatim but read
  back as ``None`` by :func:`get_operator_role`, so a future vocabulary drift can
  never inject a role the consumers do not understand.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

# The role keys this profile understands at runtime. This is the SUPERSET of the
# v2 survey keys plus the historic set, so a role captured by the old exit survey
# (if it was ever persisted) still reads back cleanly. Consumers map these to a
# CTA lane / a didactic emphasis; an unknown key reads back as ``None``.
ROLE_PROFILE_KEYS: frozenset[str] = frozenset(
    {
        # v2 set (asked at startup)
        "consultancy_pentester",
        "internal_security",
        "sysadmin_blue_team",
        "security_manager_ciso",
        "student_ctf",
        "other",
        "prefer_not_to_say",
    }
)

#: File under the state dir holding the operator-role profile.
PROFILE_FILENAME = "operator_role"

_ROLE_FIELD = "role"


def _profile_path() -> Path:
    from adscan_core.paths import get_state_dir  # noqa: PLC0415

    return get_state_dir() / PROFILE_FILENAME


def get_operator_role() -> str | None:
    """Return the persisted operator-role key, or ``None`` when unavailable.

    ``None`` is returned when the profile is unset, missing, corrupt, unreadable,
    or holds a key this build does not recognise. Never raises.
    """
    try:
        raw = _profile_path().read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    key = data.get(_ROLE_FIELD)
    if not isinstance(key, str):
        return None
    key = key.strip()
    if key not in ROLE_PROFILE_KEYS:
        return None
    return key


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
