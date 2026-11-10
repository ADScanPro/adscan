"""How a remote-registry read ended: a value, an observed absence, or no answer.

The one classifier both registry readers use (the collector's credential
hardening stage and the LSASS fingerprint's ``RunAsPPL`` read), so the two can
never disagree about whether a missing value is an observation or a failure.

The distinction carries a verdict: an ABSENT value is something the host told
us (``RunAsPPL`` not set means LSA protection is not enabled), while a FAILED
read (access denied, RemoteRegistry down, a transport error) told us nothing
and must stay unknown. Treating the second as the first is how a host whose
PPL state nobody read was recorded and ranked as PPL off. Same rule as the
posture cache: cache observations, never absences of an answer.
"""

from __future__ import annotations

from typing import Any


def registry_value_absent(err: Any) -> bool:
    """True when a registry read failed because the key or value does not exist.

    The vendor ``RRPRPC`` surfaces a not-found as an ``OSError`` whose ``errno``
    is ERROR_FILE_NOT_FOUND (2) or ERROR_PATH_NOT_FOUND (3). Anything else is a
    real read error (denied / transport), which must NOT be conflated with
    absence: an absent value can be a secure verdict (WDigest) or an insecure
    one (RunAsPPL), whereas an error is simply not assessed.
    """
    errno = getattr(err, "errno", None)
    if errno in (2, 3):  # ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND
        return True
    text = str(err).upper()
    return "NOT_FOUND" in text or "FILE_NOT_FOUND" in text or "ERROR_FILE_NOT" in text


__all__ = ["registry_value_absent"]
