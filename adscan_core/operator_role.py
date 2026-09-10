"""Operator-role profile read + role-aware commercial CTA lane — the SSOT.

This module is the single source of truth for two things that used to live in
``adscan_internal`` but are pure, dependency-light logic with no AD-protocol
surface, so they belong in ``adscan_core`` where the host launcher, the
container runtime, and any core panel renderer can share one implementation:

1. **Reading the persisted operator-role profile** (:func:`get_operator_role`).
   The role the operator picked at ``adscan start`` is persisted so the
   running CLI can read it back later — the commercial call-to-action can
   branch by role, and the didactic mode can adapt what it emphasises.
2. **Resolving the commercial CTA lane** (:func:`resolve_cta_lane`,
   :func:`is_enterprise_lane`) from that role.

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
* An unknown key (not in :data:`ROLE_PROFILE_KEYS`) is stored verbatim but read
  back as ``None`` by :func:`get_operator_role`, so a future vocabulary drift can
  never inject a role the consumers do not understand.
* :func:`resolve_cta_lane` never raises — an unreadable profile resolves to the
  /pro lane.

Role-aware commercial CTA lane
-------------------------------
The operator-role profile lets the peak-value call-to-action branch by who the
operator is:

* a **buyer** running their OWN Active Directory — internal security, sysadmin /
  blue team, or a security manager / CISO — is pointed at the **Enterprise demo**
  (``/get-a-demo``). The pitch is continuous validation + a board/auditor-ready
  report, not a CLI to run themselves.
* a **consultant / pentester** (consultancy, MSSP, freelance) is pointed at
  **/pro** — the paid CLI is their tool.
* everyone else — student / CTF, "something else", "prefer not to say", or an
  UNKNOWN role (not answered yet, corrupt profile) — defaults to **/pro**. Most
  operators are pentesters, /pro is the light safe ask, and the Enterprise demo
  is only offered on a POSITIVE buyer signal, never by default.

**Windows-no-role exception.** When the role is UNKNOWN *and* the host is
Windows, the lane defaults to **Enterprise** instead of /pro: a Windows host
almost certainly means a sysadmin running ADscan on their own domain-joined
machine, not a pentester. An EXPLICIT non-buyer role (e.g. a consultant on
Windows) still wins — it stays on /pro. Linux with no role is unchanged (/pro).

This module owns the mapping so the two CTA call sites (the session-summary hint
and the domain-compromise victory panel) cannot drift apart.
"""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path

from adscan_core.pal.platform import is_windows
from adscan_core.paths import get_state_dir

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

# The roles for which the CTA switches to the Enterprise demo lane. Everything
# else (consultant, student, other, decline, unknown) stays on /pro.
_BUYER_ROLES: frozenset[str] = frozenset(
    {
        "internal_security",
        "sysadmin_blue_team",
        "security_manager_ciso",
    }
)


def _profile_path() -> Path:
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


class CtaLane(str, Enum):
    """Which commercial destination the peak-value CTA points at."""

    PRO = "pro"
    ENTERPRISE = "enterprise"


def resolve_cta_lane() -> CtaLane:
    """Return the CTA lane for the persisted operator role.

    Reads the local role profile; a buyer role (own-estate) resolves to
    :attr:`CtaLane.ENTERPRISE`. An explicit non-buyer role resolves to
    :attr:`CtaLane.PRO`. When no role is set (None / unknown), the host OS is
    the tie-breaker: a Windows host defaults to :attr:`CtaLane.ENTERPRISE`
    (almost certainly a sysadmin on their own domain-joined machine), a
    non-Windows host to :attr:`CtaLane.PRO`. Never raises.
    """
    try:
        role = get_operator_role()
        if role in _BUYER_ROLES:
            return CtaLane.ENTERPRISE
        if role is not None:
            # An explicit non-buyer role wins, even on Windows.
            return CtaLane.PRO
        if is_windows():
            # Role unknown + Windows host → sysadmin default.
            return CtaLane.ENTERPRISE
        return CtaLane.PRO
    except Exception:  # noqa: BLE001
        return CtaLane.PRO


def is_enterprise_lane() -> bool:
    """True when the persisted role is a buyer (own-estate) role."""
    return resolve_cta_lane() is CtaLane.ENTERPRISE


__all__ = [
    "PROFILE_FILENAME",
    "ROLE_PROFILE_KEYS",
    "CtaLane",
    "get_operator_role",
    "is_enterprise_lane",
    "resolve_cta_lane",
]
