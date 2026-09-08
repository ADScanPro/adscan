"""Role-aware commercial CTA lane — one place that maps a role to a destination.

The operator-role profile (:mod:`operator_role_profile`) lets the peak-value
call-to-action branch by who the operator is:

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
and the domain-compromise victory panel) cannot drift apart. It never raises —
an unreadable profile resolves to the /pro lane.
"""

from __future__ import annotations

from enum import Enum

# The roles for which the CTA switches to the Enterprise demo lane. Everything
# else (consultant, student, other, decline, unknown) stays on /pro.
_BUYER_ROLES: frozenset[str] = frozenset(
    {
        "internal_security",
        "sysadmin_blue_team",
        "security_manager_ciso",
    }
)


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
        from adscan_core.pal.platform import is_windows
        from adscan_internal.services.operator_role_profile import get_operator_role

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


__all__ = ["CtaLane", "is_enterprise_lane", "resolve_cta_lane"]
