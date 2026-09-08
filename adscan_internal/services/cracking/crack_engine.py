"""Cracker-agnostic executor interface for the cracking-effort engine.

Defines the polymorphic seam the effort engine selects a backend against: the
frozen :class:`CrackResult` value object one attempt produces, and the
:class:`CrackEngine` protocol both concrete executors (hashcat on Linux/GPU,
John the Ripper on CPU/Windows) implement. Keeping the interface here — separate
from either backend — lets the engine pick between them without importing a
concrete cracker, and keeps the two implementations honest against one contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from adscan_internal.services.cracking_wordlist_policy import EffortTier


@dataclass(frozen=True)
class CrackResult:
    """Outcome of running one :class:`~...cracking_wordlist_policy.EffortTier`.

    Attributes:
        recovered: Mapping of hash (or account identifier) to its recovered
            plaintext password. Empty when the attempt found nothing.
        engine: Name of the backend that produced the result (e.g. ``"hashcat"``
            or ``"john"``).
        ruleset: The rule set applied during the attempt, or ``None`` when the
            tier ran without rules.
        tier_name: The name of the effort tier this result came from.
    """

    recovered: dict[str, str]
    engine: str
    ruleset: str | None
    tier_name: str


@runtime_checkable
class CrackEngine(Protocol):
    """Interface a password-cracking backend implements to run an effort tier.

    A conforming backend exposes its ``name`` and executes a single
    :class:`~...cracking_wordlist_policy.EffortTier` against a hash file,
    returning a :class:`CrackResult`. Marked ``@runtime_checkable`` so the
    effort engine can select the appropriate backend polymorphically.
    """

    name: str

    def run(self, tier: EffortTier, hash_file: str, *, hash_kind: str) -> CrackResult:
        """Run ``tier`` against ``hash_file`` and return what it recovered.

        Args:
            tier: The effort tier (base wordlist x rules, budget-checked) to run.
            hash_file: Path to the file of hashes to attack.
            hash_kind: Neutral hash identifier (NOT a hashcat mode number); each
                backend maps it to its own mode/format internally.

        Returns:
            A :class:`CrackResult` describing the recovered plaintexts, if any.
        """
        ...
