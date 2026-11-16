"""May the licence channel reach the licence server on this run? (SSOT)

The licence channel is the launch check-in, domain registration and the
sending of queued licence requests (registrations, band and engagement
reports). It is the ONLY thing this predicate governs; every other external
contact (telemetry, session upload, weakpass, downloads) keeps honouring the
offline kill switch (:func:`adscan_core.offline.offline_mode_enabled`).

Founder decision, 2026-11-13: on every licence that needs the server (trial,
partner / OEM, paid PRO) the channel ignores offline mode. Consultancies and
OEMs run with ``--offline`` by default, and a channel that obeyed it never
registered a domain, so every domain hit its grace and was refused while our
server was reachable all along. The channel carries no client data: licence
and installation identifiers, the keyed domain code, a size band (a bracket,
never a count) and the run id, the same as activation. A partner licence also
reports, on its band report, each run's size counts per domain (accounts,
computers, domain controllers, certificate authorities: counts only, see
:mod:`adscan_core.pro_license.run_size`) and how the run ended; the licence
server keeps those from partner grants only. Its attempts stay bounded (about two seconds
at launch, a short timeout at admission) and never block on an unreachable
server. Since 2026-11-13 the trial registers too (``blocking``, 7 days of grace);
a trial document issued before keeps ``deferred`` until it refreshes.

Unchanged, and still closed:

* the offline engagement licence (``registration.policy: offline``, issued
  with ``license-server issue-engagement``): the air-gap path, it never
  contacts the server (``ProLicense.needs_server`` is False);
* the Enterprise appliance: a separate licence (``enterprise_license``) whose
  zero-egress posture is enforced; an Enterprise process never uses this
  channel even if a PRO licence file were present.

Every licence-channel call site asks :func:`licence_channel_allowed`; none
reads ``offline_mode_enabled()`` on its own. :func:`note_offline_contact`
prints one short line, once per process, the first time the channel actually
contacts the server while offline mode is on, so nobody is surprised by the
connection.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Mapping

from adscan_core.pro_license.model import ProLicense

#: What the licence channel sends. Worded once: the offline note, the activation
#: panel and the site read this, so they cannot disagree. A partner licence also
#: reports each run's size counts (:mod:`adscan_core.pro_license.run_size`);
#: every other edition sends the band only.
LICENCE_CHANNEL_FIELDS = (
    "licence identifiers, domain codes and size bands (on a partner licence, also each run's size counts)"
)

#: The one line a run prints when the licence channel contacts the server under offline mode.
OFFLINE_CONTACT_NOTE = (
    "Offline mode is on, but this licence still checks in with the ADscan licence server. "
    f"It sends {LICENCE_CHANNEL_FIELDS}, never scan data."
)

_NOTE_LOCK = threading.Lock()
_NOTE_SHOWN = False


def _offline(env: Mapping[str, str] | None) -> bool:
    from adscan_core.offline import offline_mode_enabled

    return offline_mode_enabled(env=dict(env) if env is not None else None)


def _enterprise(env: Mapping[str, str] | None) -> bool:
    try:
        from adscan_core.tier import is_enterprise_edition

        return is_enterprise_edition(env=dict(env) if env is not None else None)
    except Exception:  # noqa: BLE001 - unknown edition: keep the zero-egress side
        return True


def licence_channel_allowed(
    licence: ProLicense | None, *, env: Mapping[str, str] | None = None
) -> bool:
    """True when the licence channel may contact the licence server now.

    True for every licence that needs the server (trial, partner, paid PRO),
    whatever offline mode says. False without a licence, for the offline
    engagement licence (it never needs the server) and in an Enterprise process.
    """
    if licence is None or not licence.needs_server:
        return False
    return not _enterprise(env)


def licence_channel_offline(
    licence: ProLicense | None, *, env: Mapping[str, str] | None = None
) -> bool:
    """True when offline mode keeps THIS licence's channel closed (status wording).

    An online licence under offline mode still refreshes itself, so it is not
    "offline" for the purpose of telling the operator how to refresh. Only an
    offline-mode process without an open channel is (no licence, an Enterprise
    process; an engagement licence never refreshes at all).
    """
    return _offline(env) and not licence_channel_allowed(licence, env=env)


def bypasses_offline_mode(
    licence: ProLicense | None, *, env: Mapping[str, str] | None = None
) -> bool:
    """True when the channel is open only because this licence's policy overrides offline mode."""
    return _offline(env) and licence_channel_allowed(licence, env=env)


def note_offline_contact(
    licence: ProLicense | None,
    *,
    emit: Callable[[str], None] | None = None,
    env: Mapping[str, str] | None = None,
) -> bool:
    """Print :data:`OFFLINE_CONTACT_NOTE` once per process, when the contact bypasses offline mode.

    Call it on the thread that owns the console, right before the first
    contact. Returns True when it printed. Never raises.
    """
    global _NOTE_SHOWN
    try:
        if not bypasses_offline_mode(licence, env=env):
            return False
        with _NOTE_LOCK:
            if _NOTE_SHOWN:
                return False
            _NOTE_SHOWN = True
        if emit is None:
            from adscan_core.rich_output import print_info

            emit = print_info
        emit(OFFLINE_CONTACT_NOTE)
        return True
    except Exception:  # noqa: BLE001 - an informational line never breaks a launch
        return False


def reset_offline_contact_note() -> None:
    """Forget that the note was shown (tests; a new run in the same process)."""
    global _NOTE_SHOWN
    with _NOTE_LOCK:
        _NOTE_SHOWN = False


__all__ = [
    "LICENCE_CHANNEL_FIELDS",
    "OFFLINE_CONTACT_NOTE",
    "bypasses_offline_mode",
    "licence_channel_allowed",
    "licence_channel_offline",
    "note_offline_contact",
    "reset_offline_contact_note",
]
