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
from typing import TYPE_CHECKING, Callable, Optional, Protocol, runtime_checkable

if TYPE_CHECKING:
    from adscan_internal.services.cracking_wordlist_policy import EffortTier

#: A callback an engine may feed the cracker's own live progress to, in the
#: ``{"progress_pct": float|None, "eta_seconds": int|None}`` shape
#: ``cracking_job.parse_hashcat_status_json`` produces. Optional on every engine:
#: a backend with no machine-readable progress simply never calls it.
StatusSink = Callable[[dict], None]

#: A predicate an engine polls while an attempt is in flight. Returning ``True``
#: asks the backend to STOP the attempt early and return what it has.
#:
#: This is what lets a caller act on the live ETA instead of watching an attempt
#: run on to a truncation it already knows is coming. It is COOPERATIVE: the
#: backend stops its cracker through that cracker's own graceful stop, so every
#: plaintext recovered before the stop is still returned. Measured against
#: hashcat on 2026-10-09 with an emptied potfile: a run stopped mid-pass still
#: had its recovery in the potfile, so the ``--show`` completion pass read it
#: back.
#:
#: ``None`` (the default everywhere) is the untouched path: no polling, no early
#: stop, byte-identical to a backend that never had the parameter.
AbortCheck = Callable[[], bool]

#: ``CrackResult.bounded_by`` vocabulary. One token per REASON a result stopped
#: short of its candidate set, which is what a client-facing declaration of the
#: boundary needs: ``truncated`` says a boundary exists, these say which one.
#:
#: The wall-clock cap fired on its own, with nobody asked.
BOUNDED_BY_BUDGET = "budget"
#: The operator was shown the live projection and chose to let the stage run to
#: the cap it already knew it would reach. A knowing boundary is still a boundary.
BOUNDED_BY_ACCEPTED_BUDGET = "operator_accepted_budget"
#: The operator was shown the live projection and chose NOT to run that stage,
#: keeping the cheaper stage that had already finished. The declined stage's name
#: travels in ``declined_stage``.
BOUNDED_BY_DECLINED_STAGE = "operator_declined_stage"
#: The operator handed the remaining work to the background job, so the blocking
#: lane's own answer is bounded and the real one arrives later.
BOUNDED_BY_HANDED_OFF = "handed_to_background"


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
        truncated: Whether the attempt was STOPPED by a wall-clock cap rather
            than running out of candidates. A bounded computation: the part of
            the keyspace it never reached is unproven, so a caller must declare
            that boundary instead of reading an empty ``recovered`` as "the
            password held".
        bounded_by: WHICH boundary stopped it, from the ``BOUNDED_BY_*``
            vocabulary above, or ``""`` when nothing did. Only meaningful
            alongside ``truncated``, and it never softens it: an operator who
            knowingly accepted a bounded run, or who declined a stage, still has
            a bounded run, and the deliverable still says so. The token exists so
            a boundary the operator CHOSE can be described as the choice it was
            rather than as a silent cut-off.
        declined_stage: The name of the stage the operator chose not to run, set
            only with :data:`BOUNDED_BY_DECLINED_STAGE`. Carried so a surface can
            name what was skipped rather than implying the stage that DID run was
            everything the ladder set out to do.
    """

    recovered: dict[str, str]
    engine: str
    ruleset: str | None
    tier_name: str
    truncated: bool = False
    bounded_by: str = ""
    declined_stage: str = ""


@runtime_checkable
class CrackEngine(Protocol):
    """Interface a password-cracking backend implements to run an effort tier.

    A conforming backend exposes its ``name`` and executes a single
    :class:`~...cracking_wordlist_policy.EffortTier` against a hash file,
    returning a :class:`CrackResult`. Marked ``@runtime_checkable`` so the
    effort engine can select the appropriate backend polymorphically.
    """

    name: str

    def run(
        self,
        tier: EffortTier,
        hash_file: str,
        *,
        hash_kind: str,
        runtime_seconds: Optional[int] = None,
        status_sink: Optional[StatusSink] = None,
        abort_check: Optional[AbortCheck] = None,
    ) -> CrackResult:
        """Run ``tier`` against ``hash_file`` and return what it recovered.

        Args:
            tier: The effort tier (base wordlist x rules, budget-checked) to run.
            hash_file: Path to the file of hashes to attack.
            hash_kind: Neutral hash identifier (NOT a hashcat mode number); each
                backend maps it to its own mode/format internally.
            runtime_seconds: Wall-clock ceiling for this one attempt, in seconds.
                ``None`` / ``0`` runs uncapped, which is what every background
                caller does: a crack off the scan flow must run until it cracks
                or exhausts its keyspace. A BLOCKING caller passes a real budget
                and the engine translates it into its own cracker's graceful time
                limit, so the process stops of its own accord with its recovered
                plaintexts already written rather than being killed mid-pass.
            status_sink: Optional callback fed the cracker's live progress, so a
                blocking caller can show the operator something true while the
                attempt runs.
            abort_check: Optional :data:`AbortCheck` the backend polls while the
                attempt is in flight. A backend that can stop its cracker
                gracefully honours it and returns what was recovered up to that
                point; one that cannot simply ignores it, which costs nothing
                because a backend with no live progress stream gives its caller
                nothing to decide on in the first place.

        Returns:
            A :class:`CrackResult` describing the recovered plaintexts, if any.
        """
        ...
