"""The scanner-node link: what may leave an assessed network, and in what form.

Shared by the engine (which classifies what it writes), the node service (which
filters egress) and the console (which ingests). Stdlib and ``typing`` only at
module level; ``cryptography`` is imported lazily where a later module needs it.
"""

from __future__ import annotations
