"""Mask the secret-bearing arguments of a command line before it is logged.

SSOT for the host launcher. A command line written to a log must never carry a
credential: the worker log of a client appliance and the outside-workspace log
both outlive the engagement. The appliance runner package is stdlib-only and may
not import ``adscan_core``, so ``appliance/runner/adscan_runner/invocation.py``
mirrors this module; ``tests/unit/test_secret_argv_masking.py`` locks the two
together on one corpus.

An option is a secret carrier when its NAME says so (``--password``, ``--hashes``,
``--aes-key``, ``--cleanup-password`` ...) or when it is the short ``-p``. Matching
the name rather than a list means a future flag of that shape is covered without
anyone remembering to add it. Both ``--flag value`` and ``--flag=value`` are
handled.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

MASK = "***"

_SECRET_FLAG_NAME_RE = re.compile(
    r"(?:pass(?:word|wd|phrase)?|secret|token|hash|aes-?key|api-?key|private-?key|credential)",
    re.IGNORECASE,
)
_SHORT_SECRET_FLAGS = frozenset({"-p"})


def flag_carries_secret(flag: str) -> bool:
    """Return True when a command-line option name marks its value as a secret."""
    name = str(flag or "")
    if name in _SHORT_SECRET_FLAGS:
        return True
    if not name.startswith("--"):
        return False
    return bool(_SECRET_FLAG_NAME_RE.search(name))


def mask_argv(argv: Sequence[str]) -> list[str]:
    """Return a copy of ``argv`` with every secret option's value masked."""
    safe: list[str] = []
    mask_next = False
    for item in argv:
        item = str(item)
        if mask_next:
            safe.append(MASK)
            mask_next = False
            continue
        if item.startswith("--") and "=" in item:
            flag, _, value = item.partition("=")
            if value and flag_carries_secret(flag):
                safe.append(f"{flag}={MASK}")
                continue
        elif flag_carries_secret(item):
            safe.append(item)
            mask_next = True
            continue
        safe.append(item)
    return safe
