"""Show-once notices — the SSOT for "render this onboarding note exactly once".

ADscan shows a few brand / onboarding notices that should greet an operator the
FIRST time they hit a moment (the thank-you after ``adscan install``, the signed
unauth playbook, the long "Choose Scan Type" explainer) and then get out of the
way. That is different from a safety notice (a lockout warning, a "wait 1 hour"
spray guard), which must render EVERY time the operator is at the decision — those
never go through this module.

The rule, decided with the founder: **onboarding is seen once; a safeguard is
seen always.** This module owns only the onboarding half.

Where the state lives (and why it is NOT ``config.json``)
--------------------------------------------------------
A show-once flag has to be written from TWO process contexts and read back from
the other:

* the **host launcher** writes ``welcome_install`` when ``adscan install`` runs
  on the host;
* the **container runtime** writes ``scan_type_explainer`` / ``unauth_playbook``
  during ``start_unauth`` inside Docker;

and each side must SEE what the other wrote, surviving the ephemeral container.
Only a bind-mounted directory does that. The ADscan **state** directory
(``~/.adscan/state/`` on the host ↔ ``/opt/adscan/state/`` in the container) is
bind-mounted for exactly this purpose — it is the documented home for small
cross-run markers (the launcher mounts it at ``docker_runtime.py``; see also
``telemetry_preference.py`` and ``cli/first_run_panel.py`` which already live
there). ``~/.adscan/config.json`` is deliberately NOT used: it sits at the root
of ``~/.adscan``, which is **not** mounted into the container, so a flag written
there from a Docker session would be discarded when the container exits (this is
the same reason ``telemetry_preference`` avoids ``config.json``). The whole point
of show-once is cross-context persistence, so the store has to be the mounted
state dir.

Robustness contract
-------------------
* :func:`should_show_once` returns ``True`` when the flag is unset OR the store is
  missing / corrupt / unreadable. Degrading toward SHOWING the note is the safe
  direction — an operator seeing a welcome note one extra time is harmless; a
  broken store silently swallowing every onboarding note is not.
* :func:`mark_shown` is best-effort and never raises — a failed write at worst
  shows the note again next time.
* Nothing here ever raises into the calling flow.

Placement: this module is in ``adscan_core`` so BOTH the host launcher and the
container runtime import it (the import rule allows ``adscan_core`` anywhere).
"""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from adscan_core.path_utils import get_adscan_state_dir

#: File under the state dir holding the map of already-shown notice keys.
NOTICES_FILENAME = "shown_notices.json"

# --------------------------------------------------------------------------- #
# Canonical notice keys — declare every show-once notice here so call sites and
# tests share ONE spelling and typos can't split a flag into two.
# --------------------------------------------------------------------------- #

#: Thank-you shown after a successful ``adscan install`` (host launcher).
NOTICE_WELCOME_INSTALL = "welcome_install"

#: The signed unauth playbook / note shown before an unauthenticated scan.
NOTICE_UNAUTH_PLAYBOOK = "unauth_playbook"

#: The long "Choose Scan Type" explainer panel at the start of ``start_unauth``.
#: (The yes/no "Do you have domain credentials?" prompt right after it is a
#: cheap per-scan decision and is NOT a show-once notice — it always renders.)
NOTICE_SCAN_TYPE_EXPLAINER = "scan_type_explainer"

#: The one-line social follow CTA shown at the peak-value moment (a scan that
#: proved exploitable attack paths). Shown ONCE per operator, not once per
#: victory: the PRO upsell already owns this moment on a cooldown, so the social
#: ask is deliberately the rarest thing here — seen a single time, then gone.
NOTICE_SOCIAL_CTA_VICTORY = "social_cta_victory"


def notices_path() -> Path:
    """Return the path of the persisted shown-notices store (state dir)."""
    return get_adscan_state_dir() / NOTICES_FILENAME


def _read_document(path: Path) -> dict[str, Any]:
    """Read the notices document, returning ``{}`` when absent/unreadable/corrupt."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def should_show_once(key: str, *, path: Path | None = None) -> bool:
    """Return whether the notice ``key`` has NOT been shown yet.

    ``True`` the first time (flag unset) and whenever the store cannot be read
    (missing / corrupt / unreadable) — degrading toward showing the note. ``False``
    once :func:`mark_shown` has recorded the key with a truthy value.

    Never raises.
    """
    if not key:
        return False
    resolved = path or notices_path()
    document = _read_document(resolved)
    return not bool(document.get(key))


def mark_shown(key: str, *, path: Path | None = None) -> bool:
    """Record that the notice ``key`` has been shown. Best-effort; returns success.

    Merges into the existing store, preserving every other key. A write failure is
    reported via the return value (``False``) rather than raised — at worst the
    note shows again next time.
    """
    if not key:
        return False
    resolved = path or notices_path()
    document = _read_document(resolved)
    document[key] = True
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


@contextmanager
def show_once(key: str, *, path: Path | None = None) -> Iterator[bool]:
    """Context helper: yields ``True`` the first time, then records the key.

    Usage::

        with show_once(NOTICE_WELCOME_INSTALL) as first_time:
            if first_time:
                render_welcome_note()

    The key is marked shown on a clean exit **only when the block was entered as
    the first time** — so a body that raises does NOT burn the flag (the note can
    still appear on the next run). The mark itself is best-effort and never
    propagates a write error.
    """
    first_time = should_show_once(key, path=path)
    yield first_time
    # Reached only on a clean exit of the with-block: a body that raised skips
    # this, so the flag is not consumed and the note can reappear next run.
    if first_time:
        mark_shown(key, path=path)


__all__ = [
    "NOTICES_FILENAME",
    "NOTICE_SCAN_TYPE_EXPLAINER",
    "NOTICE_SOCIAL_CTA_VICTORY",
    "NOTICE_UNAUTH_PLAYBOOK",
    "NOTICE_WELCOME_INSTALL",
    "mark_shown",
    "notices_path",
    "should_show_once",
    "show_once",
]
