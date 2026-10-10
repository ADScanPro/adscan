"""Capability-driven engine selection + the shared effort-ladder walker.

This is the keystone that unifies the two cracking executor backends behind ONE
selector. :func:`select_crack_engine` picks the right
:class:`~adscan_internal.services.cracking.crack_engine.CrackEngine` for the host
— :class:`~adscan_internal.services.cracking.hashcat_engine.HashcatEngine` when a
usable GPU device is present, else
:class:`~adscan_internal.services.cracking.john_engine.JohnEngine` on CPU, else
``None`` (honest degrade). :func:`run_effort_ladder` then walks the already-shipped
effort-tier ladder (``cracking_wordlist_policy.resolve_effort``) through whichever
engine was selected, stopping at the first tier that recovers a credential.

It introduces NO new command construction and NO new offensive logic: both engines
delegate to the existing runners, and the tier ladder is the existing SSOT. This
module is pure dispatch/plumbing — the seam that lets John run the SAME ladder
hashcat runs, instead of a single flat wordlist.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable, Optional

from adscan_core.pal import tools as pal_tools
from adscan_internal.services.cracking.crack_engine import (
    BOUNDED_BY_ACCEPTED_BUDGET,
    BOUNDED_BY_BUDGET,
    BOUNDED_BY_DECLINED_STAGE,
    BOUNDED_BY_HANDED_OFF,
    CrackResult,
    StatusSink,
)
from adscan_internal.services.cracking.hashcat_engine import HashcatEngine
from adscan_internal.services.cracking.john_engine import JohnEngine
from adscan_internal.services.john_artifact_cracking_service import (
    JohnArtifactCrackingService,
)

if TYPE_CHECKING:
    from adscan_internal.services.cracking.crack_engine import CrackEngine
    from adscan_internal.services.cracking_wordlist_policy import EffortTier


def _hashcat_device_present(shell: Any) -> bool:
    """Return whether hashcat can see a usable compute device on this host.

    Reuses the SSOT interactive backend selector
    (``cli.cracking._select_hashcat_backend``) so this path and the interactive
    one agree on "hashcat can run here". A device is present when the selector
    reports the backend available (GPU or CPU-OpenCL). Best-effort: any probe
    failure resolves to ``False`` (assume no device) so selection degrades to
    John rather than dispatching hashcat with nothing to run on.

    Args:
        shell: The pentest shell (or a shell-shaped object) the selector probes.

    Returns:
        ``True`` when hashcat exposes a usable device; ``False`` otherwise.
    """
    try:
        from adscan_internal.cli.cracking import (  # noqa: PLC0415
            _select_hashcat_backend,
        )

        return bool(_select_hashcat_backend(shell).is_available)
    except Exception:  # noqa: BLE001 -- probe is best-effort; degrade to no-device
        return False


def select_crack_engine(
    shell: Any, command_executor: Callable[..., object]
) -> CrackEngine | None:
    """Select the cracking backend for this host, or ``None`` when none can run.

    Selection order:

    1. :class:`HashcatEngine` when the ``cracking_gpu`` capability is available
       AND the hashcat device probe is positive (a usable GPU/compute device).
    2. :class:`JohnEngine` when the ``cracking_cpu`` capability is available AND a
       John binary path resolves.
    3. ``None`` — honest degrade; the caller renders today's no-cracker path.

    Args:
        shell: The pentest shell (or shell-shaped object), used for the hashcat
            device probe.
        command_executor: A callable with ``shell.run_command``'s signature,
            injected into whichever engine is selected.

    Returns:
        The selected :class:`CrackEngine`, or ``None`` when no backend can run.
    """
    if pal_tools.capability_available(
        "cracking_gpu"
    ).available and _hashcat_device_present(shell):
        return HashcatEngine(command_executor)

    if pal_tools.capability_available("cracking_cpu").available:
        john_path = JohnArtifactCrackingService.resolve_john_path()
        if john_path:
            return JohnEngine(command_executor=command_executor, john_path=john_path)

    return None


#: Tolerance ceiling, in seconds, for calling a tier "stopped by its cap". A tier
#: whose own elapsed time came within the tolerance of its allotment did not
#: finish of its own accord, so the ladder is a bounded computation.
_CAP_DETECTION_TOLERANCE_SECONDS = 1.0

#: ...and the same tolerance as a FRACTION of the allotment, which is what keeps
#: the verdict honest at both ends of the scale. A flat second is right for a tier
#: allotted minutes and far too loose for one allotted a couple of seconds, where
#: it would call a natural finish a truncation. The tighter of the two wins.
_CAP_DETECTION_TOLERANCE_FRACTION = 0.1


#: How far over the remaining budget a stage's live projection has to land before
#: the operator is interrupted about it, as a FRACTION of what is left.
#:
#: MEASURED on 2026-10-09 (RTX 4060 Laptop, the ~94M-entry audit base, 178 NT
#: hashes, ``--status-timer 5``). At the FIRST status tick the cracker's own
#: projection for a stage carried an error of +21% on the shortest stage
#: (projected 21.4 s, finished in 17.7 s) and -7% on the bare-wordlist stage
#: (projected 8.5 s, finished in 9.1 s), converging from there. A quarter
#: absorbs that whole band, so a stage the cracker merely MIS-estimates by its
#: early-tick error never costs the operator a question, while the case this
#: exists for trips instantly: the full rule stage projected 2,392 s against a
#: 60 s budget, which is forty times over.
_SHORTFALL_MARGIN_FRACTION = 0.25

#: ...and the same question in absolute terms: the overrun has to be worth an
#: interruption. A stage that will exceed its allotment by a handful of seconds
#: is not a decision, it is a rounding error, and the operator is mid-scan. Fifteen
#: seconds is a quarter of the tightest blocking budget in the product.
_MIN_SHORTFALL_SECONDS = 15.0

#: Below this much budget left there is nothing left to decide about: every
#: option but "let it stop" would need time the lane no longer has, so the
#: honest move is to let the cap fire and declare the boundary.
_MIN_REMAINING_BUDGET_SECONDS = 10.0


class ShortfallChoice(Enum):
    """What an operator may do about a stage that will not finish in time.

    Four outcomes, and every one of them except :attr:`EXTEND` leaves the run
    BOUNDED. That is not a technicality: knowing about a boundary is not the same
    as removing it, so three of these four still produce a ``truncated`` result
    and a deliverable that says the test stopped short of the candidate set.
    """

    #: Raise the budget so the stage can finish. The only outcome that can end in
    #: a complete test of this stage.
    EXTEND = "extend"
    #: Do not run this stage. Keeps whatever the cheaper stages already produced,
    #: and declares the skipped stage by name.
    DECLINE_STAGE = "decline_stage"
    #: Hand the remaining work to the background job and stop blocking on it. The
    #: real answer arrives later, through the late-arrival path.
    HAND_OFF = "hand_off"
    #: Let the stage run to the cap it is already heading for. Today's behaviour,
    #: now chosen rather than discovered afterwards.
    ACCEPT_BOUNDED = "accept_bounded"


@dataclass(frozen=True)
class BudgetShortfall:
    """The measured case for interrupting: this stage will not finish in time.

    Every field is a measurement, not an estimate of ours: the projection is the
    cracker's own, read off its live status stream, and the budget figures are
    wall clock this walk has spent and has left.

    Attributes:
        tier_name: The effort tier the stage belongs to.
        stage_label: Operator-facing label for the stage (its wordlist, and its
            rule file when it has one).
        projected_seconds: What the cracker projects the whole stage will take.
        remaining_seconds: What is left of the ladder's budget at the moment of
            the reading.
        elapsed_seconds: How long the stage had already been running.
        progress_pct: How far through its candidate set it had reached, when the
            cracker reported it.
        cheaper_stage_ran: Whether a cheaper stage already ran to completion in
            this walk. When it did not, declining this stage would leave nothing
            tested at all, so that outcome is not worth offering.
        extendable: Whether the projection fits inside what the lane is willing
            to extend to. A projection that does not is what the background
            hand-off exists for, so "let it finish" is not offered for it.
    """

    tier_name: str
    stage_label: str
    projected_seconds: int
    remaining_seconds: int
    elapsed_seconds: int
    progress_pct: Optional[float]
    cheaper_stage_ran: bool
    extendable: bool


@dataclass(frozen=True)
class ShortfallDecision:
    """An operator's answer to a :class:`BudgetShortfall`.

    Attributes:
        choice: Which of the four outcomes they picked.
        extend_seconds: For :attr:`ShortfallChoice.EXTEND`, how much wall clock
            to add to the ladder's budget. The decider owns this number because
            the ceiling on it is a property of the LANE (how long a blocked scan
            may keep reading as progressing), not of the walk.
    """

    choice: ShortfallChoice
    extend_seconds: int = 0


#: The decision seam. Given the measured shortfall, answer what to do about it.
ShortfallDecider = Callable[[BudgetShortfall], ShortfallDecision]


def stage_label_for_tier(tier: "EffortTier") -> str:
    """Operator-facing name for one stage: its wordlist, plus its rule file.

    The SSOT both the waiting surface and the decision panel read, so the stage
    the operator is deciding about is named identically in both places.
    """
    try:
        base = os.path.basename(str(getattr(tier, "base_path", "") or ""))
        rule = os.path.basename(str(getattr(tier, "rule_path", "") or ""))
        label = base or str(getattr(tier, "name", "") or "")
        if rule:
            label = f"{label} + {os.path.splitext(rule)[0] or rule}"
        return label
    except Exception:  # noqa: BLE001 — a label never breaks a crack
        return str(getattr(tier, "name", "") or "")


class _ShortfallWatch:
    """Watches one stage's live status and arms an early stop when it will overrun.

    Sits between the backend and the caller's own status sink: every tick is
    forwarded untouched (the waiting surface keeps showing the cracker's real
    figures), and each one is also tested against what is left of the budget.

    It acts on the FIRST tick that shows a material shortfall, and that choice is
    deliberate. A second sample would cost another status interval of a budget
    measured in tens of seconds, and the measurement says it would not buy
    accuracy where it matters: the stage that provoked this work was forty times
    over its budget at its first tick, while the early-tick error on a stage that
    genuinely fits is a fifth either way. So the uncertainty is absorbed by
    requiring the overrun to be MATERIAL (see :data:`_SHORTFALL_MARGIN_FRACTION`
    and :data:`_MIN_SHORTFALL_SECONDS`) rather than by making the operator wait
    for confirmation of something the first reading already settled.

    Thread note: the backend may feed ticks from whichever thread drains its
    output, so this only ever reads and writes plain attributes. It never prints
    and never prompts.
    """

    def __init__(
        self,
        inner_sink: Optional[StatusSink],
        *,
        tier: "EffortTier",
        remaining_seconds: float,
        cheaper_stage_ran: bool,
        extend_ceiling_seconds: float,
    ) -> None:
        self._inner = inner_sink
        self._tier = tier
        self._remaining = max(0.0, float(remaining_seconds))
        self._cheaper_stage_ran = bool(cheaper_stage_ran)
        self._extend_ceiling = max(0.0, float(extend_ceiling_seconds))
        self._started = time.monotonic()
        self.shortfall: Optional[BudgetShortfall] = None

    # -- the sink the backend is handed ------------------------------------
    def on_status(self, status: dict) -> None:
        """Forward one tick to the caller's sink, then test it for a shortfall."""
        if self._inner is not None:
            try:
                self._inner(status)
            except Exception:  # noqa: BLE001 — a surface never breaks a crack
                pass
        try:
            self._evaluate(status)
        except Exception:  # noqa: BLE001 — a projection never breaks a crack
            pass

    # -- the predicate the backend polls -----------------------------------
    def abort_requested(self) -> bool:
        """Whether this stage should stop now so the operator can be asked."""
        return self.shortfall is not None

    def _evaluate(self, status: dict) -> None:
        if self.shortfall is not None or not isinstance(status, dict):
            return
        elapsed = max(0.0, time.monotonic() - self._started)
        left = self._remaining - elapsed
        if left < _MIN_REMAINING_BUDGET_SECONDS:
            return
        projected = _project_stage_seconds(status, elapsed)
        if projected is None:
            return
        overrun = projected - self._remaining
        if overrun < _MIN_SHORTFALL_SECONDS:
            return
        if projected <= self._remaining * (1.0 + _SHORTFALL_MARGIN_FRACTION):
            return
        pct = status.get("progress_pct")
        self.shortfall = BudgetShortfall(
            tier_name=str(getattr(self._tier, "name", "") or ""),
            stage_label=stage_label_for_tier(self._tier),
            projected_seconds=int(projected),
            remaining_seconds=int(self._remaining),
            elapsed_seconds=int(elapsed),
            progress_pct=float(pct) if isinstance(pct, (int, float)) else None,
            cheaper_stage_ran=self._cheaper_stage_ran,
            extendable=projected <= self._extend_ceiling,
        )


def _project_stage_seconds(status: dict, elapsed: float) -> Optional[float]:
    """Project the whole stage's wall clock from one live tick, or ``None``.

    Prefers the cracker's OWN remaining-time figure, because that is computed
    from the rate it is actually achieving against the real keyspace. Falls back
    to extrapolating the reported progress fraction, which needs enough progress
    to divide by before it means anything.
    """
    eta = status.get("eta_seconds")
    if isinstance(eta, (int, float)) and not isinstance(eta, bool) and eta >= 0:
        return elapsed + float(eta)
    pct = status.get("progress_pct")
    if isinstance(pct, (int, float)) and not isinstance(pct, bool) and pct > 0.5:
        return elapsed * (100.0 / float(pct))
    return None


def _tier_corpus_present(tier: "EffortTier") -> bool:
    """Whether this tier's wordlist actually exists on this runtime.

    Mirrors the background ladder's own check. Best-effort: an unreadable path
    answers ``True`` so a probe quirk can never suppress a crack that would have
    worked.
    """
    try:
        path = str(getattr(tier, "base_path", "") or "")
        return bool(path) and os.path.exists(path)
    except Exception:  # noqa: BLE001
        return True


def _cap_fired(allotted: int, elapsed: float) -> bool:
    """Whether a tier was STOPPED by its allotment rather than finishing."""
    tolerance = min(
        _CAP_DETECTION_TOLERANCE_SECONDS,
        allotted * _CAP_DETECTION_TOLERANCE_FRACTION,
    )
    return elapsed >= allotted - tolerance


def run_effort_ladder(
    engine: CrackEngine,
    tiers: "list[EffortTier]",
    hash_file: str,
    hash_kind: str,
    *,
    budget_seconds: Optional[float] = None,
    status_sink: Optional[StatusSink] = None,
    on_tier_start: Optional[Callable[["EffortTier", Optional[int]], None]] = None,
    skip_absent_corpus: bool = False,
    on_budget_shortfall: Optional[ShortfallDecider] = None,
    extend_ceiling_seconds: float = 0.0,
) -> CrackResult:
    """Walk ``tiers`` in order through ``engine``, stopping at the first recovery.

    Runs each tier sequentially (never in parallel — one crack in flight) and
    returns the first :class:`CrackResult` whose ``recovered`` mapping is
    non-empty. When no tier recovers, returns the LAST result; when ``tiers`` is
    empty, returns an empty :class:`CrackResult`.

    ``budget_seconds`` makes the whole ladder a TIME-BOUNDED walk, for a caller
    that is spending the operator's own wall clock: each tier is allotted
    whatever is left of the budget, and a tier that consumes its whole allotment
    (or a tier reached with nothing left to spend) marks the result
    ``truncated``. That flag is the ladder's honest statement that part of the
    keyspace was never reached, and a caller must declare it rather than reading
    an empty ``recovered`` as a verdict about the password. Measured with
    ``time.monotonic`` throughout, because ADscan steps the host wall clock
    mid-scan for DC sync and a budget measured against that would be corrupted.
    Omitted (the default, and every background caller) the ladder runs uncapped
    and can never report ``truncated``.

    Args:
        engine: The selected cracking backend.
        tiers: The effort-tier ladder (from ``resolve_effort``), tried in order.
        hash_file: Path to the file of hashes to attack.
        hash_kind: Neutral hash identifier (a ``HashKind`` value); each engine
            maps it to its own mode/format internally.
        budget_seconds: Total wall-clock budget for the whole ladder, or ``None``
            to run uncapped.
        status_sink: Optional live-progress callback handed to each tier.
        on_tier_start: Optional callback invoked as ``(tier, allotted_seconds)``
            just before each tier runs, so a waiting surface can name what is
            running and how long it may take. ``allotted_seconds`` is ``None``
            when the ladder is uncapped.
        skip_absent_corpus: Skip a tier whose wordlist is not on this runtime
            instead of handing it to the backend, so ``tier_name`` stays empty
            when nothing was runnable. Opt-in; see the loop comment.
        on_budget_shortfall: Optional decision seam. When given AND the walk is
            capped, each stage is watched against the backend's own live
            remaining-time figure, and a stage that will not finish inside what
            is left of the budget is STOPPED so this is asked what to do about it
            (see :class:`ShortfallChoice`). Omitted (the default, and every
            non-interactive caller) nothing is watched, no early-stop predicate
            is handed to the backend at all, and the walk is byte-identical to
            one that never had the parameter: a stage simply runs to its cap and
            the boundary is declared afterwards.
        extend_ceiling_seconds: The largest TOTAL budget the caller is willing to
            grant. Only used to decide whether to OFFER the "let it finish"
            outcome for a given projection: the ceiling is a property of the
            lane, so the caller owns it.

    Returns:
        The first recovering :class:`CrackResult`, else the last STAGE THAT RAN
        ITS OWN COURSE, else an empty result when ``tiers`` is empty or no tier's
        wordlist was present on this runtime. ``truncated`` is set when the walk
        stopped short of its candidate set, ``bounded_by`` says which boundary
        did it, and ``tier_name`` is empty when nothing ran at all, which is what
        lets a caller tell "tested, nothing found" apart from "never tested".
    """
    capped = budget_seconds is not None and float(budget_seconds) > 0
    budget = float(budget_seconds or 0)
    started = time.monotonic()
    #: The result of the last stage that ran its OWN course. A stage stopped
    #: early so the operator could be asked is NOT one of these: it proves
    #: nothing about its keyspace, so it must never displace the answer a
    #: cheaper stage already earned.
    last: CrackResult | None = None
    truncated = False
    bounded_by = ""
    declined_stage = ""
    stages_run = 0
    watching = capped and on_budget_shortfall is not None
    for tier in tiers:
        if skip_absent_corpus and not _tier_corpus_present(tier):
            # A tier whose wordlist is not on this runtime cannot recover
            # anything, and running it anyway has the backend fail in
            # milliseconds and return nothing, which is indistinguishable from a
            # clean negative. Skipping it keeps ``tier_name`` empty when NO tier
            # was runnable, which is how a caller tells "tested, nothing found"
            # apart from "never tested".
            #
            # Opt-in, because only a caller that turns that distinction into a
            # client-facing claim needs it. The interactive crack path
            # deliberately attempts a wordlist it cannot see (in a container the
            # operator's path may resolve differently) and warns rather than
            # skipping, so the default keeps that behaviour untouched.
            continue
        outcome = _walk_one_stage(
            engine,
            tier,
            hash_file,
            hash_kind,
            capped=capped,
            budget=budget,
            started=started,
            status_sink=status_sink,
            on_tier_start=on_tier_start,
            watching=watching,
            on_budget_shortfall=on_budget_shortfall,
            extend_ceiling_seconds=extend_ceiling_seconds,
            cheaper_stage_ran=stages_run > 0,
        )
        budget = outcome.budget
        if outcome.truncated:
            truncated = True
        if outcome.bounded_by:
            bounded_by = outcome.bounded_by
        if outcome.declined_stage:
            declined_stage = outcome.declined_stage
        if outcome.result is not None:
            last = outcome.result
            stages_run += 1
        if outcome.stop:
            break
    if last is not None:
        return CrackResult(
            recovered=dict(last.recovered),
            engine=last.engine,
            ruleset=last.ruleset,
            tier_name=last.tier_name,
            truncated=bool(last.truncated or truncated),
            bounded_by=bounded_by if (last.truncated or truncated) else "",
            declined_stage=declined_stage,
        )
    return CrackResult(
        recovered={},
        engine=getattr(engine, "name", ""),
        ruleset=None,
        tier_name="",
        truncated=truncated,
        bounded_by=bounded_by if truncated else "",
        declined_stage=declined_stage,
    )


@dataclass(frozen=True)
class _StageOutcome:
    """What walking ONE stage did, for the ladder loop to fold in.

    Attributes:
        result: The stage's result when it ran its own course, else ``None``.
            ``None`` is what keeps a stage that was stopped for a question (or
            declined outright) from displacing the answer a cheaper stage earned.
        budget: The ladder budget after this stage, which an extension raises.
        truncated: Whether this stage left part of the keyspace unproven.
        bounded_by: Which boundary did it, from the ``BOUNDED_BY_*`` vocabulary.
        declined_stage: The stage the operator chose not to run, when they did.
        stop: Whether the walk ends here.
    """

    result: Optional[CrackResult]
    budget: float
    truncated: bool
    bounded_by: str
    declined_stage: str
    stop: bool


def _walk_one_stage(
    engine: CrackEngine,
    tier: "EffortTier",
    hash_file: str,
    hash_kind: str,
    *,
    capped: bool,
    budget: float,
    started: float,
    status_sink: Optional[StatusSink],
    on_tier_start: Optional[Callable[["EffortTier", Optional[int]], None]],
    watching: bool,
    on_budget_shortfall: Optional[ShortfallDecider],
    extend_ceiling_seconds: float,
    cheaper_stage_ran: bool,
) -> _StageOutcome:
    """Run ONE stage, asking the operator about a shortfall when one is measured.

    A stage may be attempted more than once. When the backend's own live
    remaining-time figure says it will not finish inside what is left of the
    budget, it is stopped, the operator is asked, and the answer is applied to a
    fresh attempt: raising the budget so it can finish, or letting it run to the
    cap it is already heading for. Restarting costs whatever the stopped attempt
    had spent, which is seconds because the question is asked at the first status
    tick, and that is the price of not truncating in silence.
    """
    decided = False
    while True:
        allotted: Optional[int] = None
        if capped:
            remaining = budget - (time.monotonic() - started)
            if remaining <= _CAP_DETECTION_TOLERANCE_SECONDS:
                # Nothing left to spend: this stage and the ones below it were
                # never walked at all, the clearest form of the boundary.
                return _StageOutcome(
                    result=None,
                    budget=budget,
                    truncated=True,
                    bounded_by=BOUNDED_BY_BUDGET,
                    declined_stage="",
                    stop=True,
                )
            allotted = max(1, int(remaining))
        if on_tier_start is not None:
            on_tier_start(tier, allotted)
        watch: Optional[_ShortfallWatch] = None
        run_kwargs: dict[str, Any] = {"status_sink": status_sink}
        if watching and not decided and allotted is not None:
            watch = _ShortfallWatch(
                status_sink,
                tier=tier,
                remaining_seconds=float(allotted),
                cheaper_stage_ran=cheaper_stage_ran,
                extend_ceiling_seconds=extend_ceiling_seconds,
            )
            # ``abort_check`` is passed ONLY here, so a caller with no decision
            # seam hands the backend exactly the arguments it always did.
            run_kwargs["status_sink"] = watch.on_status
            run_kwargs["abort_check"] = watch.abort_requested
        stage_started = time.monotonic()
        result = engine.run(
            tier, hash_file, hash_kind=hash_kind, runtime_seconds=allotted, **run_kwargs
        )
        hit_cap = allotted is not None and _cap_fired(
            allotted, time.monotonic() - stage_started
        )
        shortfall = watch.shortfall if watch is not None else None
        if shortfall is not None and not result.recovered:
            decision = _resolve_shortfall(on_budget_shortfall, shortfall)
            decided = True
            if decision.choice is ShortfallChoice.EXTEND:
                budget += max(0, int(decision.extend_seconds))
                continue
            if decision.choice is ShortfallChoice.DECLINE_STAGE:
                return _StageOutcome(
                    result=None,
                    budget=budget,
                    truncated=True,
                    bounded_by=BOUNDED_BY_DECLINED_STAGE,
                    declined_stage=shortfall.stage_label or shortfall.tier_name,
                    stop=True,
                )
            if decision.choice is ShortfallChoice.HAND_OFF:
                return _StageOutcome(
                    result=None,
                    budget=budget,
                    truncated=True,
                    bounded_by=BOUNDED_BY_HANDED_OFF,
                    declined_stage="",
                    stop=True,
                )
            # ACCEPT_BOUNDED: attempt it again under the budget it has and let
            # the cap stop it. The operator owns that boundary now, which is why
            # it is recorded as their choice and not as a silent cut-off.
            continue
        bounded_by = ""
        if shortfall is not None:
            # Stopped for the question, but it had already recovered something,
            # and a recovery ends the walk by contract. Nothing is left to
            # decide; the stage was still cut short, so the boundary stands.
            hit_cap = True
        if hit_cap:
            bounded_by = (
                BOUNDED_BY_ACCEPTED_BUDGET if decided else BOUNDED_BY_BUDGET
            )
        if result.recovered:
            # A recovery stops the walk: the stages above are not worth the
            # operator's remaining wait once something has come out.
            #
            # It does NOT mean the answer is complete. This used to return
            # before the cap was even evaluated, on the reasoning that "a
            # recovery settles the question for this hash set". That holds for a
            # set of one. For a set of many it conflates two different things:
            # the recovery settles the hashes it recovered, and says nothing
            # about the rest, which the cap left untested. Measured on a real
            # engagement: 5 of 178 recovered on a rung cut off at 4.9% of its
            # candidate set, reported as a completed test, so the client
            # deliverable presented a 2.7% crack rate as the measured strength
            # of those passwords. That understates exposure in the direction
            # that reassures, which the Exposure-Validation doctrine forbids.
            return _StageOutcome(
                result=result,
                budget=budget,
                truncated=bool(result.truncated or hit_cap),
                bounded_by=bounded_by,
                declined_stage="",
                stop=True,
            )
        return _StageOutcome(
            result=result,
            budget=budget,
            truncated=bool(result.truncated or hit_cap),
            bounded_by=bounded_by,
            declined_stage="",
            stop=hit_cap,
        )


def _resolve_shortfall(
    decider: Optional[ShortfallDecider], shortfall: BudgetShortfall
) -> ShortfallDecision:
    """Ask ``decider`` what to do, defaulting to the bounded run on any failure.

    Best-effort by design, and the default is load-bearing: accepting the bounded
    run is what the lane did before there was anything to ask, so a decider that
    raises leaves the behaviour exactly where it was instead of silently changing
    the shape of the attack.
    """
    if decider is None:
        return ShortfallDecision(choice=ShortfallChoice.ACCEPT_BOUNDED)
    try:
        decision = decider(shortfall)
    except Exception:  # noqa: BLE001 — a decider never breaks the attack
        return ShortfallDecision(choice=ShortfallChoice.ACCEPT_BOUNDED)
    if not isinstance(decision, ShortfallDecision):
        return ShortfallDecision(choice=ShortfallChoice.ACCEPT_BOUNDED)
    return decision
