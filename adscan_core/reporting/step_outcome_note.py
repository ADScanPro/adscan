"""The one sentence a client reads about how an executed step ended (SSOT).

An attack step's status chip says THAT it ran; this says what happened, in the
words the engine recorded at the time, for example:

* "ADscan ran a command as <user> on <host> through the logged-on session.
  <user> does not administer the domain, so no account was created." (a
  ScheduledTask identity hand-off);
* "Creating the account <acct> as <user> was refused (System error 5 has
  occurred. Access is denied.)" (a command the host refused);
* "The group memberships of <user> could not be read, so ADscan created no
  account ..." (a step that wrote nothing because its rights were unknown).

Opt-in by construction: only a sentence the executor wrote for the client under
:data:`OUTCOME_NOTE_KEY` is shown. The free-form ``reason`` notes many runners
record are operator diagnostics ("Missing PDC IP in domain data") and must not
reach a deliverable. Import-safe (stdlib only), so the PDF report and the web
backend read the same sentence.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

#: ``notes`` key of the client-facing outcome sentence an executor recorded.
OUTCOME_NOTE_KEY = "outcome_note"

#: ``notes["outcome"]`` of a ScheduledTask identity hand-off.
SESSION_IDENTITY_OUTCOME = "session_identity"


def step_outcome_note(notes: Mapping[str, Any] | None) -> str:
    """The recorded client-facing outcome sentence for a step, or ``""``."""
    if not isinstance(notes, Mapping):
        return ""
    return str(notes.get(OUTCOME_NOTE_KEY) or "").strip()
