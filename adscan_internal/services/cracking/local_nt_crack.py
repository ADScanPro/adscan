"""Local wordlist attack on recovered NT hashes, dispatched at ONE seam.

An NT hash replicated out of the directory used to get exactly one treatment:
a lookup against a public breach-password corpus. That lookup answers "is this
exact password already public?", not "is this password weak?", and the operator
can decline it outright (a regulated engagement, an air-gapped appliance,
``ADSCAN_OFFLINE``). When they did, the hash was never attacked at all, even
though the audit corpus and both cracking backends were sitting on the host.

This module closes that: it hands the hashes a local wordlist attack, which is
the stronger method and the one the deliverable's methodology note advertises.

**The attack runs BLOCKING, in the scan flow, and that is what makes the rest of
the design simple.** It first shipped as a background job, and every awkward
piece of machinery around it existed to paper over the asynchrony: the
client-facing hygiene document could only exist once the job happened to finish,
a fold had to correct the recovery figures after the fact, and ``adscan ci`` has
no drain between scan end and report generation, so a finished attack could still
miss the render entirely. Running it inline collapses all three: the figures are
correct by construction at the moment the block is built, the document exists
whenever recovery ran, and the fold becomes a backstop rather than the mechanism.
Two further reasons, both load-bearing:

* **The sibling method at this same seam is already blocking.** The breach-corpus
  lookup returns synchronously. Two recovery methods feeding one client-facing
  figure have to share a lane, or that figure is assembled from a half-finished
  picture.
* **An NT hash is genuinely cheap, and the reason is the cost SHAPE, not the
  kernel speed.** A cracker tests EVERY loaded hash in one pass over the
  keyspace, so the cost is keyspace x 1, not keyspace x hashes: a replication
  returning two thousand accounts costs very nearly what one costs. The only
  variable is the EFFORT TIER, never the hash count, which is why a time budget
  is a meaningful bound here and a per-hash budget would not be.

Three properties make it safe to call from the credential path:

* **It is time-bounded, and says so.** The lane declares its own wall-clock
  budget (:data:`NT_BLOCKING_BUDGET_SECONDS`), which the effort resolver caps the
  rule rung against so the ladder it picks genuinely fits, and which each cracker
  also receives as its own graceful stop. A run that reaches that budget is a
  bounded computation and is declared as one.
* **It declares its own coverage class.** A local attack is recorded apart from
  the breach-lookup class in :mod:`adscan_core.reporting.cracking_coverage`, so
  the weaker method can never be reported as the stronger one, and an attack that
  stopped at its budget (or could not run at all) is declared as the boundary it
  is rather than rendering as full strength.
* **It is offline-safe.** Nothing here reaches the network. The corpus is
  whatever the runtime already carries: an absent one means the tier is skipped
  and the gap is declared, never downloaded.

The OS split is the PAL's (``cracking_gpu`` = hashcat, ``cracking_cpu`` = John),
and the mode/format pair comes from the neutral registry
(:class:`~adscan_internal.services.cracking.hash_kind.HashKind.NT`), so neither
the hashcat mode nor the John format is written down here. The crack itself goes
through the shared cracker-agnostic ladder walker
(:func:`~adscan_internal.services.cracking.engine_selection.run_effort_ladder`),
so this lane introduces no second way to invoke a cracker.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Optional, Sequence

from adscan_core import telemetry
from adscan_core.reporting.cracking_coverage import (
    LOCAL_ATTACK_COMPLETED,
    LOCAL_ATTACK_TRUNCATED,
    LOCAL_ATTACK_UNAVAILABLE,
)
from adscan_core.rich_output import (
    print_exception,
    print_info,
    print_info_debug,
    print_warning,
)
from adscan_internal.services.cracking.hash_kind import HashKind, hashcat_mode_for

#: Hard opt-out, mirroring ``ADSCAN_NO_POISONING``. The one knob an operator
#: actually needs: local cracking costs no packets and leaves no client-side
#: trace, but it does spend this host's CPU/GPU, which a shared or low-powered
#: assessing box may not have to spare.
OPT_OUT_ENV = "ADSCAN_NO_LOCAL_CRACKING"

#: The hashcat mode / John format for an NT hash both come from the neutral
#: registry, never a literal here, so a Windows CPU fallback can never be left
#: behind by a mode added on the hashcat side alone.
NT_HASHCAT_MODE = hashcat_mode_for(HashKind.NT)

#: Where the ``<username>:<hash>`` crack input is materialised inside the
#: workspace, so the operator can find and re-run it by hand.
_HASHFILE_SUBDIR = "cracking"

#: A 32-hex NT hash, the only thing this path accepts.
_NT_HASH_RE = re.compile(r"\A[0-9a-f]{32}\Z")

#: The NT hash of an empty password. Present on every account whose password is
#: blank and on many disabled ones; no wordlist contains the empty string, so
#: attacking it only burns keyspace. The blank-password condition is detected
#: and reported elsewhere, by its own check.
_EMPTY_PASSWORD_NT_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"

#: Session attribute carrying the operator's one-time answer for this session.
_CONSENT_ATTR = "_local_nt_crack_consent"

#: Hard wall-clock stop, per effort tier, for the BLOCKING NT lane. Enforced by
#: the ladder walker and handed to the cracker as its own graceful time limit.
#:
#: Far tighter than the background tier budgets (5 / 300 / 3600 s), and that gap
#: is the point. An hour is a defensible budget for a job nobody waits on; it is
#: not a budget for a scan that is standing still. The operator here is blocked
#: mid-run, immediately after replication, so the ceiling is how long a blocked
#: scan can keep reading as progressing, which with live progress and an ETA on
#: screen is minutes. The floor is set by the default tier: ``balanced`` is what a
#: non-interactive run resolves to with no prompt, so it has to fit inside what an
#: unattended run can absorb without looking wedged.
#:
#: MEASURED, not guessed, and the measurement is why these are a backstop rather
#: than a constraint that normally bites. On the calibration-class GPU the NT
#: kernel benchmarks at ~42,700 MH/s against ~567 MH/s for Kerberoast, the
#: slowest mode ADscan measures, a factor of ~75. Against the ~94M-entry audit
#: base the REAL cost of the whole rule ladder is therefore: bare wordlist under
#: a hundredth of a second, ``best64`` ~0.2 s, ``OneRule-10k`` ~22 s, and the
#: full ``OneRule`` top rung ~106 s. Every rung the ladder can select finishes
#: inside ``thorough``'s budget on that hardware, with room to spare.
#:
#: That gap used to be absorbed as pessimism, because the NT kernel was not
#: benchmarked and the planner fell back to the slowest mode's rate. It is now
#: measured (mode 1000 is in ``BENCHMARK_MODES``) and this lane is planned
#: against it (``cap_reference_mode``), so the rung and the estimate the operator
#: is shown are both computed at the speed the hardware actually runs.
#:
#: These budgets still deliberately do NOT cap the rule rung. Capping it against
#: them collapsed ``thorough`` onto ``balanced``'s rung, so the operator would
#: wait for a tier that bought nothing. Each tier keeps the rung the shared
#: planner resolves for it; the budget exists for the case the measurement is
#: beaten in the other direction (a far slower host, thermal throttling, a cache
#: whose NT pair was never measured and so falls back to the slow reference),
#: where the run stops and the boundary is DECLARED rather than reported as a
#: complete test. With a real NT rate in hand the budget is now the only brake,
#: which is why the menu keeps naming it.
NT_BLOCKING_BUDGET_SECONDS: dict[str, float] = {
    "fast": 60.0,
    "balanced": 180.0,
    "thorough": 600.0,
}

#: The largest TOTAL wall clock this lane will ever hold the scan for, including
#: an extension the operator asked for explicitly.
#:
#: Read :data:`NT_BLOCKING_BUDGET_SECONDS` first: the budgets above exist because
#: the operator is BLOCKED mid-scan, and the ceiling there is "how long a blocked
#: scan can keep reading as progressing", which with live progress and an ETA on
#: screen is minutes. An extension does not change that fact. What it changes is
#: who decided: the operator is looking at the cracker's own projection for the
#: stage and at what is left of the budget, so the consent is informed in a way
#: the default budget's cannot be, and a stage that needs three more minutes to
#: finish is worth those three minutes to most operators.
#:
#: So the ceiling is deliberately a MULTIPLE of the widest default and not an
#: open door: 15 minutes is 1.5x ``thorough``, which covers every stage the
#: planner can pick on measured hardware with room to spare, and is still inside
#: "minutes". Anything a stage needs BEYOND it is not a budget question, it is
#: the wrong lane: the background hand-off runs uncapped off the scan flow, which
#: is exactly what an hours-long stage wants. A projection over this ceiling
#: therefore does not get offered "let it finish" at all.
NT_BLOCKING_EXTENSION_CEILING_SECONDS: float = 900.0

#: Headroom added to a granted extension, so the stage is not stopped one tick
#: short of finishing by the very estimate used to size the grant. Sized from the
#: measured first-tick error of that estimate (+21% on the shortest stage
#: measured on 2026-10-09), rounded up: an extension that lands just under what
#: the stage needed would spend the operator's time and still truncate, which is
#: the one outcome this whole path exists to avoid.
_EXTENSION_MARGIN_FRACTION = 0.25

#: The tier a blocking run settles on when nothing else resolves one. Mirrors the
#: effort selector's own non-interactive answer, so the prompted and unprompted
#: paths cannot drift.
_DEFAULT_BLOCKING_EFFORT = "balanced"


@dataclass(frozen=True)
class LocalNtCrackDispatch:
    """What the local attack did with a batch of NT hashes.

    Attributes:
        attacked: How many distinct hashes were handed to the attack.
        unavailable: How many hashes could NOT be attacked because this host
            has no cracking engine. A declared data gap, never a verdict about
            the client's passwords.
        recovered: ``hash_lower -> plaintext`` for every password the attack
            resolved. Keyed by HASH, not by account, because the seam that calls
            this resolves hashes to plaintexts and has to merge these with the
            breach lookup's results under one key.
        recovered_accounts: The ``sAMAccountName`` of each resolved account, in
            dispatch order. Names only, never a secret.
        truncated: Whether the attack reached its time budget and stopped short
            of the candidate set. Part of the keyspace is then unproven, so the
            caller declares the boundary rather than reading an empty
            ``recovered`` as a verdict about the passwords.
        bounded_by: WHICH boundary stopped the attack short, from the
            ``crack_engine.BOUNDED_BY_*`` vocabulary, or ``""`` when nothing
            did. Only meaningful alongside ``truncated``, and it never softens
            it: an operator who was shown the live estimate and chose to
            accept a bounded run, to skip a stage, or to move the work to a
            background job still has a bounded result, and the deliverable
            still says so. The token is what lets a boundary the operator
            CHOSE be described as the choice it was rather than as a silent
            cut-off.
        declined_stage: The stage the operator chose not to run, when they
            declined one. Carried so a surface can name what was skipped
            instead of implying the stage that DID run was the whole plan.
        ran: Whether the attack actually executed. ``False`` covers the operator
            opt-out, a declined consent, an absent engine and a write failure:
            all of them mean nothing was tested, and none of them may be
            reported as a completed test.
        hash_file: The materialised crack input, for the operator.
        entries: The ``(username, hash)`` pairs actually dispatched.
    """

    attacked: int = 0
    unavailable: int = 0
    recovered: dict[str, str] = field(default_factory=dict)
    recovered_accounts: tuple[str, ...] = field(default=())
    truncated: bool = False
    bounded_by: str = ""
    declined_stage: str = ""
    ran: bool = False
    hash_file: str = ""
    entries: tuple[tuple[str, str], ...] = field(default=())

    @property
    def completed(self) -> bool:
        """Whether the attack ran to the END of its candidate set.

        The full-strength condition, and the only one that may be reported as a
        completed test of these passwords.
        """
        return self.ran and self.attacked > 0 and not self.truncated


def _env_flag_set(name: str) -> bool:
    """True when environment variable ``name`` is set to a truthy value."""
    return str(os.environ.get(name, "")).strip().lower() in {"1", "true", "yes"}


def local_cracking_available() -> bool:
    """Whether this host can run a local wordlist attack at all.

    The OS split is the PAL's, not this module's: hashcat (``cracking_gpu``) is
    the engine on Linux and the fast path on Windows; John (``cracking_cpu``) is
    the pure-CPU fallback a hardened Windows host degrades to, where hashcat has
    no compute runtime to bind. On Linux, John is deliberately NOT consulted:
    the ``no_device`` degrade there stays honest and hashcat-only, exactly as
    the interactive path does it.

    Best-effort: an unresolvable capability answers ``False``, so a probe
    failure degrades to an honest "could not attack locally" rather than
    launching a job with no engine behind it.
    """
    try:
        from adscan_core.pal import tools as pal_tools  # noqa: PLC0415
        from adscan_core.pal.platform import is_windows  # noqa: PLC0415

        if pal_tools.capability_available("cracking_gpu").available:
            return True
        if is_windows() and pal_tools.capability_available("cracking_cpu").available:
            return True
    except Exception as exc:  # noqa: BLE001 — capability probe is best-effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    return False


def _consent_for_session(shell: Any) -> bool:
    """Resolve the operator's answer for local cracking, ONCE per session.

    Mirrors the poisoning launch seam's shape (hard env opt-out, interactive
    consent, non-interactive auto-launch) with one deliberate difference: the
    answer is memoized on the session instead of being asked per batch. The
    poisoning consent fires once at a scan entry point; this seam is reached
    every time a batch of hashes is resolved, and a prompt there would
    interrupt the credential flow repeatedly to re-ask a question whose answer
    cannot change. Default is yes, because a local attack sends nothing to the
    client's network and leaves no trace on it; the cost is this host's own
    compute.
    """
    cached = getattr(shell, _CONSENT_ATTR, None)
    if isinstance(cached, bool):
        return cached

    consent = True
    try:
        from adscan_core.rich_output import confirm_ask, print_panel  # noqa: PLC0415
        from adscan_internal.interaction import is_non_interactive  # noqa: PLC0415

        if not is_non_interactive(shell):
            print_panel(
                "ADscan can attack the recovered NT hashes against its password "
                "corpus on THIS host, now, before the scan moves on.\n\n"
                "[dim]Nothing is sent to the target network and nothing is "
                "written to it: the attack is entirely local and offline. It "
                "runs under a time budget and reports its progress, so decline "
                "if this machine's GPU/CPU is needed for something else, or if "
                "you would rather the scan keep moving.[/dim]",
                title="Local password recovery",
            )
            consent = bool(
                confirm_ask(
                    "Attack the recovered hashes locally now?",
                    default=True,
                )
            )
    except Exception as exc:  # noqa: BLE001 — a consent failure must not block the flow
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        consent = True

    try:
        setattr(shell, _CONSENT_ATTR, consent)
    except Exception as exc:  # noqa: BLE001 — a read-only shell must not break the gate
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    return consent


def normalize_nt_entries(
    hashes: Iterable[str],
    principals: Optional[Mapping[str, str]] = None,
) -> list[tuple[str, str]]:
    """Normalize raw hashes into de-duplicated ``(username, hash)`` pairs.

    Drops anything that is not a 32-hex NT hash, the empty-password hash, and
    machine accounts: a machine account's password is 120 random characters, so
    putting it in a wordlist attack burns keyspace on every tier for an outcome
    that cannot happen. At enterprise scale that is the difference between
    attacking the accounts that matter and attacking thousands that cannot
    break.

    Args:
        hashes: Candidate NT hashes, in any case, with duplicates allowed.
        principals: Optional ``hash_lower -> sAMAccountName`` attribution. A
            hash with no known principal still gets attacked; its username
            field falls back to the hash itself, which keeps the crack input
            parseable and the recovery traceable.

    Returns:
        ``[(username, hash_lower), ...]``, de-duplicated by hash, order stable.
    """
    by_hash: Mapping[str, str] = {
        str(key or "").strip().lower(): str(value or "").strip()
        for key, value in (principals or {}).items()
    }
    seen: set[str] = set()
    entries: list[tuple[str, str]] = []
    for raw in hashes or ():
        candidate = str(raw or "").strip().lower()
        if not _NT_HASH_RE.match(candidate):
            continue
        if candidate == _EMPTY_PASSWORD_NT_HASH:
            continue
        if candidate in seen:
            continue
        username = by_hash.get(candidate, "")
        if username.endswith("$"):
            continue
        seen.add(candidate)
        entries.append((username or candidate, candidate))
    return entries


def _hash_file_path(shell: Any, domain: str, entries: Sequence[tuple[str, str]]) -> str:
    """Resolve where to materialise the crack input for this batch.

    Keyed by a digest of the hash set, so re-resolving the same batch reuses
    one file instead of littering the workspace, and the ``(kind, scope)``
    idempotency guard upstream sees a stable identity.
    """
    from adscan_core.pal.paths import scratch_dir  # noqa: PLC0415

    digest = hashlib.sha256(
        "\n".join(sorted(hash_value for _, hash_value in entries)).encode("utf-8")
    ).hexdigest()[:12]
    safe_domain = re.sub(r"[^A-Za-z0-9._-]", "_", str(domain or "domain")) or "domain"
    filename = f"nt_hashes_{safe_domain}_{digest}.txt"
    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "")
    base = (
        os.path.join(workspace_dir, _HASHFILE_SUBDIR)
        if workspace_dir
        else str(scratch_dir())
    )
    return os.path.join(base, filename)


def dispatch_local_nt_crack(
    shell: Any,
    *,
    domain: str,
    hashes: Iterable[str],
    principals: Optional[Mapping[str, str]] = None,
    effort: Optional[str] = None,
) -> LocalNtCrackDispatch:
    """Attack recovered NT hashes locally, NOW, before the caller moves on.

    The ONE dispatcher behind both NT-hash seams in
    :mod:`adscan_internal.cli.cracking`, so the single-hash and batch paths can
    never diverge on whether (or how) a local attack runs.

    Blocking by design (see the module docstring): the caller resolves these
    hashes to plaintexts and then derives client-facing password figures from the
    result, so the attack has to have finished by the time it returns or those
    figures describe a test that had not happened yet.

    Args:
        shell: The active session.
        domain: Domain the hashes were replicated from, for attribution and for
            the coverage declaration.
        hashes: Candidate NT hashes the stronger method should attack, normally
            the ones a breach-corpus lookup did NOT resolve.
        principals: Optional ``hash_lower -> sAMAccountName`` attribution, so a
            recovery is credited to the real account in the harvest review and
            the deliverable rather than to an opaque hash.
        effort: Optional effort level (``fast``/``balanced``/``thorough``). When
            omitted the operator is asked, with real per-tier time estimates for
            this hardware; a non-interactive run resolves to ``balanced`` with no
            prompt.

    Returns:
        A :class:`LocalNtCrackDispatch` carrying what the attack recovered and
        whether it reached the end of its candidate set. Never raises: a failure
        degrades to "not attacked locally", which is then declared as a gap, and
        never breaks the credential path that called it.
    """
    try:
        entries = normalize_nt_entries(hashes, principals)
        if not entries:
            return LocalNtCrackDispatch()

        if _env_flag_set(OPT_OUT_ENV):
            print_info_debug(
                f"local-nt-crack: skipped by {OPT_OUT_ENV} "
                f"({len(entries)} hash(es) left untested)"
            )
            # An operator opt-out is not an ADscan capability gap, so it is NOT
            # declared as "no engine available" to the client. The hashes keep
            # whatever class the lookup gave them.
            return LocalNtCrackDispatch(entries=tuple(entries))

        if not local_cracking_available():
            print_info_debug(
                "local-nt-crack: no cracking engine available on this host "
                f"({len(entries)} hash(es) untested)"
            )
            _record_coverage(
                shell,
                domain=domain,
                attacked=len(entries),
                recovered=0,
                status=LOCAL_ATTACK_UNAVAILABLE,
            )
            return LocalNtCrackDispatch(
                unavailable=len(entries), entries=tuple(entries)
            )

        if not _consent_for_session(shell):
            print_info_debug(
                f"local-nt-crack: declined by the operator for this session "
                f"({len(entries)} hash(es) left untested)"
            )
            return LocalNtCrackDispatch(entries=tuple(entries))

        hash_file = _hash_file_path(shell, domain, entries)
        written = _write_hash_file(hash_file, entries)
        if written <= 0:
            return LocalNtCrackDispatch(entries=tuple(entries))

        level = _resolve_blocking_effort(shell, effort, hash_count=written)
        outcome = _run_blocking_ladder(
            shell,
            domain=domain,
            hash_file=hash_file,
            entries=entries,
            effort=level,
        )
        recovered_by_hash, recovered_accounts = _attribute_recoveries(
            outcome.recovered, entries
        )
        if not outcome.tier_name and not recovered_by_hash:
            # No tier was runnable at all: no backend resolved, no tier ladder, or
            # every tier's corpus missing from this runtime. The hashes were never
            # tested, and the one thing that must not happen is reporting that as
            # a test which found nothing, so it is declared as the ADscan-side gap
            # it is rather than promoted to completed.
            print_info_debug(
                "local-nt-crack: no crack tier could run on this host "
                f"({written} hash(es) untested)"
            )
            _record_coverage(
                shell,
                domain=domain,
                attacked=written,
                recovered=0,
                status=LOCAL_ATTACK_UNAVAILABLE,
            )
            return LocalNtCrackDispatch(
                unavailable=written, hash_file=hash_file, entries=tuple(entries)
            )
        status = LOCAL_ATTACK_TRUNCATED if outcome.truncated else LOCAL_ATTACK_COMPLETED
        boundary = str(getattr(outcome, "bounded_by", "") or "")
        declined = str(getattr(outcome, "declined_stage", "") or "")
        print_info_debug(
            f"local-nt-crack: finished mode={NT_HASHCAT_MODE} effort={level} "
            f"hashes={written} recovered={len(recovered_by_hash)} "
            f"status={status} bounded_by={boundary or 'none'} "
            f"declined_stage={declined or 'none'} domain={domain}"
        )
        _record_coverage(
            shell,
            domain=domain,
            attacked=written,
            recovered=len(recovered_by_hash),
            status=status,
        )
        return LocalNtCrackDispatch(
            attacked=written,
            recovered=recovered_by_hash,
            recovered_accounts=tuple(recovered_accounts),
            truncated=outcome.truncated,
            bounded_by=boundary,
            declined_stage=declined,
            ran=True,
            hash_file=hash_file,
            entries=tuple(entries),
        )
    except Exception as exc:  # noqa: BLE001 — dispatch is best-effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return LocalNtCrackDispatch()


def _wordlists_dir() -> str:
    """Resolve the managed wordlists dir, the same way every crack caller does."""
    from adscan_core.paths import get_adscan_home  # noqa: PLC0415

    return str(get_adscan_home() / "wordlists")


def _resolve_blocking_effort(
    shell: Any, effort: Optional[str], *, hash_count: int
) -> str:
    """Resolve the effort tier this blocking run should walk.

    An explicit ``effort`` wins. Otherwise the operator is asked through the ONE
    effort selector, which is what routes this lane onto the same rule-aware,
    benchmark-capped ladder the audit crack path walks instead of the legacy flat
    wordlist list. The selector resolves to ``balanced`` with no prompt in a
    non-interactive run, which matters here because this seam is reached from
    inside the replication flow and from ``adscan ci``.

    The selector is told the lane's own budgets, so the per-tier estimates it
    shows are for the rungs this lane will actually run, and so every tier is
    presented as running NOW rather than as a background hand-off.

    Best-effort: an unusable selector falls back to the default tier rather than
    leaving the hashes untested.
    """
    explicit = str(effort or "").strip().lower()
    if explicit:
        return explicit
    try:
        from adscan_internal.cli.cracking import (  # noqa: PLC0415
            choose_cracking_effort,
        )

        selection = choose_cracking_effort(
            shell,
            hash_type=f"{hash_count:,} recovered NT hash"
            + ("es" if hash_count != 1 else ""),
            mode=NT_HASHCAT_MODE,
            wordlists_dir=_wordlists_dir(),
            domain=str(getattr(shell, "domain", "") or ""),
            inline_budgets=NT_BLOCKING_BUDGET_SECONDS,
            cap_reference_mode=NT_HASHCAT_MODE,
            # NT is the one UNSALTED mode in the set, so the count does not
            # multiply the keyspace here. It is still passed, because the
            # estimate's honesty flag depends on knowing the count rather than
            # assuming one, and because this is the lane whose docstring claims
            # thousands of accounts cost very nearly what one costs: that claim
            # is true of NT precisely because it is unsalted, and the keyspace
            # math is now the thing that encodes it.
            hash_count=hash_count,
        )
        resolved = str(getattr(selection, "effort", "") or "").strip().lower()
        return resolved or _DEFAULT_BLOCKING_EFFORT
    except Exception as exc:  # noqa: BLE001 — a selector failure must not skip the attack
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return _DEFAULT_BLOCKING_EFFORT


def _run_blocking_ladder(
    shell: Any,
    *,
    domain: str,
    hash_file: str,
    entries: Sequence[tuple[str, str]],
    effort: str,
) -> Any:
    """Walk the effort ladder inline, under the lane's budget, with a live surface.

    Every piece of this is the shared machinery: the tier ladder comes from
    ``resolve_effort`` (capped against this lane's budgets so the rungs it picks
    fit), the backend from ``select_crack_engine`` (which is where the
    hashcat-on-Linux / John-on-Windows split lives), and the walk itself from
    ``run_effort_ladder`` (which owns the per-tier budget allocation and the
    truncation verdict). Nothing about invoking a cracker is written down here.

    Returns the walker's ``CrackResult``. Never raises.
    """
    from adscan_internal.services.cracking.crack_engine import CrackResult  # noqa: PLC0415
    from adscan_internal.services.cracking.engine_selection import (  # noqa: PLC0415
        run_effort_ladder,
        select_crack_engine,
    )

    empty = CrackResult(recovered={}, engine="", ruleset=None, tier_name="")
    run_command = getattr(shell, "run_command", None)
    if run_command is None:
        return empty
    engine = select_crack_engine(shell, run_command)
    if engine is None:
        # local_cracking_available() already cleared the PAL capability, so this
        # is the narrower "no device / no binary resolved" case. Honest no-op.
        print_info_debug("local-nt-crack: no cracking backend resolved on this host")
        return empty

    tiers = _resolve_blocking_tiers(
        shell,
        domain=domain,
        effort=effort,
        hash_count=len(entries),
        hash_file=hash_file,
    )
    if not tiers:
        print_info_debug(f"local-nt-crack: no crack tier resolved for effort={effort}")
        return empty

    budget = NT_BLOCKING_BUDGET_SECONDS.get(
        effort, NT_BLOCKING_BUDGET_SECONDS[_DEFAULT_BLOCKING_EFFORT]
    )
    from adscan_internal.services.cracking.hash_kind import HashKind  # noqa: PLC0415
    from adscan_internal.cli.widgets.local_crack_live import (  # noqa: PLC0415
        local_crack_progress,
    )

    with local_crack_progress(
        hash_count=len(entries), effort=effort, budget_seconds=budget
    ) as progress:
        return run_effort_ladder(
            engine,
            tiers,
            hash_file,
            HashKind.NT.value,
            budget_seconds=budget,
            status_sink=progress.on_status,
            on_tier_start=progress.on_tier_start,
            # This lane turns "did a tier run" into a client-facing claim about
            # whether the passwords were tested, so an absent corpus has to read
            # as "never tested" and not as a clean negative.
            skip_absent_corpus=True,
            # The operator is standing still for this, so a stage the cracker
            # itself says will not finish in the time it has is theirs to decide
            # about, not something to discover from the report afterwards. The
            # decider is ``None`` in a non-interactive run, which leaves the walk
            # byte-identical to what it was before this existed.
            on_budget_shortfall=_make_shortfall_decider(
                shell,
                progress=progress,
                domain=domain,
                hash_file=hash_file,
                effort=effort,
                hash_count=len(entries),
            ),
            extend_ceiling_seconds=NT_BLOCKING_EXTENSION_CEILING_SECONDS,
        )


def _format_wait(seconds: float) -> str:
    """Render a wait the operator is being asked to accept, in their units.

    Seconds under a minute, whole minutes above it, hours and minutes above that.
    Rounded UP, because this number is the basis of a decision about how long to
    stand still: understating it by rounding down would make the choice look
    cheaper than it is.
    """
    total = max(0, int(seconds))
    if total < 60:
        return f"{total} seconds"
    minutes = (total + 59) // 60
    if minutes == 1:
        return "about a minute"
    if minutes < 60:
        return f"about {minutes} minutes"
    hours, mins = divmod(minutes, 60)
    hour_word = "hour" if hours == 1 else "hours"
    if not mins:
        return f"about {hours} {hour_word}"
    return f"about {hours} {hour_word} {mins} minutes"


def _shortfall_panel(shortfall: Any) -> str:
    """The body of the panel shown before the question. Every figure is measured.

    States what the cracker itself reports, what is left of the budget, and what
    happens if nothing is changed. It does NOT recommend an option: the right
    answer depends on how much of the operator's remaining engagement time this
    stage is worth, which only they know.
    """
    reached = (
        f"It has covered {shortfall.progress_pct:.1f}% of its candidate set so far.\n"
        if isinstance(shortfall.progress_pct, (int, float))
        else ""
    )
    return (
        f"The [bold]{shortfall.stage_label}[/bold] stage needs "
        f"{_format_wait(shortfall.projected_seconds)} to work through its "
        "candidate set, measured from the rate it is achieving right now on this "
        "hardware.\n"
        f"The time budget for this stage has "
        f"{_format_wait(max(0, shortfall.remaining_seconds - shortfall.elapsed_seconds))} left.\n"
        f"{reached}"
        "\n[dim]Left alone it stops when the budget runs out, and the report says "
        "the test stopped before working through the candidate set. That is "
        "honest, and it is also less than this host can do. Nothing below sends "
        "anything to the target network.[/dim]"
    )


#: The four outcomes, in the order they are offered. Order is a judgement: the
#: two that keep testing come first, the hand-off next, and the one that changes
#: nothing last, where it is also the default so an unattended run lands on
#: today's behaviour.
_EXTEND_LABEL = "Give this stage the time it needs and let it finish"
_DECLINE_LABEL = "Skip this stage and keep what the cheaper stages found"
_HAND_OFF_LABEL = "Hand it to a background job and carry on with the scan"
_ACCEPT_LABEL = "Leave it as it is and accept a result that stops early"


def _make_shortfall_decider(
    shell: Any,
    *,
    progress: Any,
    domain: str,
    hash_file: str,
    effort: str,
    hash_count: int,
) -> Optional[Any]:
    """Build the seam the ladder asks when a stage will not finish in time.

    Returns ``None`` in a non-interactive run, and that is the whole
    non-interactive story: with no decider the ladder watches nothing, hands the
    backend no early-stop predicate, and walks exactly as it did before this
    existed. A stage runs to its cap and the boundary is declared afterwards.
    There is deliberately no "auto-answer" here, because the auto-answer would be
    "accept the bounded run", which is what NOT asking already does, and arriving
    at it through a stopped stage and a restart would cost an unattended run real
    seconds to reach the same place.
    """
    try:
        from adscan_internal.interaction import is_non_interactive  # noqa: PLC0415

        if is_non_interactive(shell):
            return None
    except Exception as exc:  # noqa: BLE001 — unknown means do not interrupt
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None

    def _decide(shortfall: Any) -> Any:
        from adscan_internal.services.cracking.engine_selection import (  # noqa: PLC0415
            ShortfallChoice,
            ShortfallDecision,
        )

        accept = ShortfallDecision(choice=ShortfallChoice.ACCEPT_BOUNDED)
        try:
            from adscan_core.rich_output import (  # noqa: PLC0415
                print_panel,
                questionary_select_index,
            )

            choices: list[tuple[str, Any]] = []
            if shortfall.extendable:
                granted = _extension_seconds_for(shortfall)
                if granted > 0:
                    choices.append(
                        (
                            f"{_EXTEND_LABEL} ({_format_wait(granted)} more)",
                            ShortfallDecision(
                                choice=ShortfallChoice.EXTEND, extend_seconds=granted
                            ),
                        )
                    )
            if shortfall.cheaper_stage_ran:
                choices.append(
                    (
                        _DECLINE_LABEL,
                        ShortfallDecision(choice=ShortfallChoice.DECLINE_STAGE),
                    )
                )
            choices.append((_HAND_OFF_LABEL, ShortfallDecision(choice=ShortfallChoice.HAND_OFF)))
            choices.append((_ACCEPT_LABEL, accept))

            try:
                progress.pause()
            except Exception:  # noqa: BLE001 — a surface never blocks a question
                pass
            print_panel(_shortfall_panel(shortfall), title="Local password recovery")
            idx = questionary_select_index(
                title="This stage will not finish in the time it has. What now?",
                options=[label for label, _ in choices],
                default_idx=len(choices) - 1,
                shell=shell,
            )
            decision = choices[idx][1] if isinstance(idx, int) and 0 <= idx < len(choices) else accept
            if decision.choice is ShortfallChoice.HAND_OFF:
                decision = _hand_off_to_background(
                    shell,
                    domain=domain,
                    hash_file=hash_file,
                    effort=effort,
                    hash_count=hash_count,
                    fallback=accept,
                )
            return decision
        except Exception as exc:  # noqa: BLE001 — a question never breaks the attack
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            return accept
        finally:
            try:
                progress.resume()
            except Exception:  # noqa: BLE001
                pass

    return _decide


def _extension_seconds_for(shortfall: Any) -> int:
    """How much wall clock to add so this stage can finish, or ``0`` if it cannot.

    The grant is sized from the cracker's own projection plus the margin on
    :data:`_EXTENSION_MARGIN_FRACTION`, then clamped so the lane's TOTAL hold on
    the scan never passes :data:`NT_BLOCKING_EXTENSION_CEILING_SECONDS`. A stage
    whose projection does not fit under that ceiling returns ``0`` and is not
    offered this outcome at all, because granting it an extension that still ends
    in a truncation would spend the operator's time for nothing.
    """
    try:
        needed = float(shortfall.projected_seconds) * (1.0 + _EXTENSION_MARGIN_FRACTION)
        already = float(shortfall.remaining_seconds)
        if needed > NT_BLOCKING_EXTENSION_CEILING_SECONDS:
            return 0
        return max(0, int(needed - already))
    except (TypeError, ValueError):
        return 0


def _hand_off_to_background(
    shell: Any,
    *,
    domain: str,
    hash_file: str,
    effort: str,
    hash_count: int,
    fallback: Any,
) -> Any:
    """Move the remaining work to the background cracking job.

    The same hash file, the same effort level, the same shared ladder, run off
    the scan flow where it is uncapped. Its recoveries land through the
    late-arrival path (:func:`record_local_nt_crack_outcome`), which is what that
    function exists for.

    Returns the hand-off decision when a job is actually running, and
    ``fallback`` when one could not be started. Reporting a hand-off that did not
    happen would leave the hashes untested with nobody expecting a result.
    """
    try:
        from adscan_internal.services.background_jobs.cracking_enqueue import (  # noqa: PLC0415
            enqueue_cracking_job,
        )
        from adscan_internal.services.cracking.engine_selection import (  # noqa: PLC0415
            ShortfallChoice,
            ShortfallDecision,
        )

        scope = f"local-nt-{os.path.basename(hash_file) or 'batch'}"
        job_id = enqueue_cracking_job(
            shell,
            domain=domain,
            user=scope,
            hash_file=hash_file,
            mode=NT_HASHCAT_MODE,
            effort=effort,
        )
        if job_id:
            print_info(
                f"Password recovery for {hash_count:,} hash"
                + ("es" if hash_count != 1 else "")
                + " moved to a background job. The scan carries on, and anything "
                "it recovers reaches the report when it finishes."
            )
            return ShortfallDecision(choice=ShortfallChoice.HAND_OFF)
        print_warning(
            "A background job for this could not be started, so the stage keeps "
            "its current time budget and the result will say it stopped early."
        )
    except Exception as exc:  # noqa: BLE001 — a failed hand-off degrades honestly
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_warning(
            "A background job for this could not be started, so the stage keeps "
            "its current time budget and the result will say it stopped early."
        )
    return fallback


def _resolve_blocking_tiers(
    shell: Any,
    *,
    domain: str,
    effort: str,
    hash_count: int | None = None,
    hash_file: str | None = None,
) -> list:
    """The effort-tier ladder for a blocking NT run, or ``[]`` when none resolves.

    The SAME shared ladder the background job walks, planned against the mode
    this lane actually cracks: ``cap_reference_mode`` is the NT mode, so the rung
    is capped against the measured NT rate rather than against the slowest mode
    ADscan benchmarks. On the calibration-class GPU that is the difference
    between planning at ~42,700 MH/s and at ~567 MH/s.

    The lane's budget stays a wall-clock backstop applied by the walker, not a
    planning input here, for the reason recorded on
    :data:`NT_BLOCKING_BUDGET_SECONDS`. Best-effort: any failure returns ``[]``
    and the caller degrades honestly.
    """
    try:
        from adscan_internal.services.cracking_benchmark import (  # noqa: PLC0415
            get_or_run_benchmark,
            load_cached_achieved_rates,
            make_achieved_rate_provider,
        )
        from adscan_internal.services.cracking_wordlist_policy import (  # noqa: PLC0415
            resolve_effort,
        )

        return list(
            resolve_effort(
                effort,
                workspace_type=str(getattr(shell, "type", "") or "audit"),
                domain=domain,
                wordlists_dir=_wordlists_dir(),
                benchmark=get_or_run_benchmark(shell),
                cap_reference_mode=NT_HASHCAT_MODE,
                hash_count=hash_count,
                achieved=load_cached_achieved_rates(),
                # The rung this lane runs is about to cost the operator real
                # wall clock, so it is worth a short real attack to plan it
                # against the rate the crack will actually achieve rather than
                # the benchmark's optimized-kernel number. One probe per pair,
                # cached from then on.
                rate_provider=make_achieved_rate_provider(shell, hash_file=hash_file),
            )
        )
    except Exception as exc:  # noqa: BLE001 — tier resolution is best-effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return []


def _attribute_recoveries(
    recovered: Mapping[str, str], entries: Sequence[tuple[str, str]]
) -> "tuple[dict[str, str], list[str]]":
    """Re-key the ladder's ``{account: plaintext}`` onto ``{hash: plaintext}``.

    The cracker credits a recovery to the principal field of the crack input; the
    seam that called this merges results with the breach lookup's, which are
    keyed by HASH. So both keyings are produced here, once, from the dispatched
    entries: the hash-keyed map the caller merges, and the account names the
    hygiene backstop needs. An account the entries cannot place is skipped rather
    than guessed at, because attributing a recovered password to the wrong
    principal is worse than not reporting it.

    Matching is case-insensitive on the account name: a directory is
    case-insensitive and the cracker echoes back whatever case the input carried.
    """
    hash_by_account = {
        str(username or "").strip().lower(): hash_value
        for username, hash_value in entries
    }
    by_hash: dict[str, str] = {}
    accounts: list[str] = []
    display_by_account = {
        str(username or "").strip().lower(): str(username or "").strip()
        for username, _hash in entries
    }
    for account, plaintext in (recovered or {}).items():
        key = str(account or "").strip().lower()
        secret = str(plaintext or "")
        if not key or not secret:
            continue
        hash_value = hash_by_account.get(key)
        if not hash_value:
            continue
        by_hash[hash_value] = secret
        accounts.append(display_by_account.get(key, key))
    return by_hash, accounts


def _write_hash_file(path: str, entries: Sequence[tuple[str, str]]) -> int:
    """Materialise the crack input through the canonical hashfile writer.

    Routed through ``cracking.write_crack_hashfile`` so the ``--username``-safe
    shape is produced in exactly one place; both backends read the same
    ``<principal>:<hash>`` line, which is what lets a recovery be credited to
    the account that owns it.
    """
    try:
        from adscan_internal.cli.cracking import write_crack_hashfile  # noqa: PLC0415

        return write_crack_hashfile(
            path,
            [(username, hash_value) for username, hash_value in entries],
            mode=NT_HASHCAT_MODE,
        )
    except Exception as exc:  # noqa: BLE001 — a write failure degrades to no attack
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return 0


def _record_coverage(
    shell: Any, *, domain: str, attacked: int, recovered: int, status: str
) -> None:
    """Persist the local-attack coverage class for ``domain``.

    Routed through the ONE merge-preserving coverage writer, so the
    breach-lookup class another seam recorded for this domain is carried
    through rather than overwritten.
    """
    if not domain:
        return
    try:
        from adscan_internal.services.wordlist_service import (  # noqa: PLC0415
            record_cracking_coverage_for_domain,
        )

        record_cracking_coverage_for_domain(
            shell,
            domain,
            local_attack_hashes=attacked,
            local_attack_recovered=recovered,
            local_attack_status=status,
        )
    except Exception as exc:  # noqa: BLE001 — a report is never failed over its own note
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def _existing_coverage(shell: Any, domain: str) -> dict[str, Any]:
    """Read the coverage block already recorded for ``domain`` (``{}`` if none)."""
    try:
        from adscan_core.reporting.technical_report import (  # noqa: PLC0415
            read_cracking_coverage,
        )

        block = read_cracking_coverage(shell, domain)
        return dict(block) if isinstance(block, dict) else {}
    except Exception as exc:  # noqa: BLE001 — an unreadable block reads as absent
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return {}


#: The background cracking-job statuses that mean the ladder reached its END.
#: ``failed`` is deliberately absent: a ladder that crashed did NOT finish, so
#: its declaration stays at ``running`` (a declared boundary) rather than being
#: promoted to the full-strength statement a completed attack earns.
_LADDER_TERMINAL_STATUSES: frozenset[str] = frozenset({"cracked", "uncracked"})


def record_local_nt_crack_outcome(
    shell: Any,
    *,
    domain: str,
    job_status: str,
    recovered: int,
    attacked: Optional[int] = None,
    recovered_accounts: Sequence[str] = (),
) -> None:
    """BACKSTOP: record that a local NT attack finished out-of-band.

    **Not the primary path.** :func:`dispatch_local_nt_crack` runs the attack
    BLOCKING and records its own terminal coverage class before it returns, so on
    the normal path the figures are already correct when the client-facing block
    is built and nothing has to be reconciled afterwards. This function survives
    for recoveries that still land LATE and therefore cannot be correct by
    construction: a background cracking job started from another seam and drained
    after the figures were derived, or a future asynchronous recovery path.

    Flipping the class to ``completed`` is what turns a declared boundary into a
    full-strength statement, and it is what lets ``cracking_attempted`` become
    true for an engagement that declined the external lookup: an attack that ran
    and recovered nothing is a real, reportable positive about the client's
    passwords, and it can only be claimed once the attack has actually finished.

    It ALSO folds the recovered accounts into the domain's persisted
    password-hygiene figures, and that co-location is deliberate. On a late
    arrival those figures were derived before the attack returned, so promoting
    the coverage class without folding them would publish two contradictory
    sentences about one event: a statement that the hashes were tested at full
    strength, beside a recovery rate measured before the test ran. Understating
    recovery is the direction that reads as "these passwords held", so the two
    are updated together or not at all.

    Args:
        shell: The active session.
        domain: The domain the attack was dispatched for.
        job_status: The drained result's status. Only a real ladder terminal
            (see :data:`_LADDER_TERMINAL_STATUSES`) promotes the declaration.
        recovered: How many principals the attack resolved.
        attacked: How many hashes it attacked. ``None`` reads the count the
            dispatch already recorded, so the drain does not have to carry it.
        recovered_accounts: The ``sAMAccountName`` of each resolved account, for
            the hygiene fold. Names only, never a secret.
    """
    if str(job_status or "").strip().lower() not in _LADDER_TERMINAL_STATUSES:
        return
    # The fold runs FIRST and independently of the coverage bookkeeping below: a
    # recovered account is proof on its own, and must not be lost because the
    # dispatch's attacked-count is unreadable.
    if recovered_accounts:
        try:
            from adscan_internal.services.password_hygiene_persistence import (  # noqa: PLC0415
                reconcile_password_hygiene_after_recovery,
            )

            reconcile_password_hygiene_after_recovery(
                shell, domain=domain, recovered_accounts=recovered_accounts
            )
        except Exception as exc:  # noqa: BLE001 — a drain is never failed over this
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
    if attacked is None:
        try:
            attacked = int(
                _existing_coverage(shell, domain).get("local_attack_hashes") or 0
            )
        except (TypeError, ValueError):
            attacked = 0
    if not attacked or attacked <= 0:
        return
    _record_coverage(
        shell,
        domain=domain,
        attacked=int(attacked),
        recovered=max(int(recovered or 0), 0),
        status=LOCAL_ATTACK_COMPLETED,
    )


def local_nt_crack_completed(shell: Any, domain: str) -> bool:
    """Whether a local NT attack has RUN TO COMPLETION for ``domain``.

    The third term of the password-recovery attempt question (see
    ``secretsdump._dcsync_cracking_attempted``). True only for the
    ``completed`` class, which deliberately excludes an attack that stopped at
    its time budget as well as one still in flight: "an attempt ran" is what
    gates a client-facing hygiene document into existence, and a document
    asserting a recovery rate off a test that never reached the end of its
    candidate set would understate exposure in exactly the direction that reads
    as "these passwords held". A truncated run that DID recover something still
    reaches that document, through the recovered-plaintext term, which is proof
    on its own.

    Now satisfiable in time to matter: the attack is blocking, so by the moment
    the figures are derived this answers for a test that has already finished.
    """
    try:
        block = _existing_coverage(shell, domain)
        return str(block.get("local_attack_status") or "") == LOCAL_ATTACK_COMPLETED
    except Exception as exc:  # noqa: BLE001 — unknown means do not claim an attempt
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False


__all__ = [
    "LocalNtCrackDispatch",
    "NT_BLOCKING_BUDGET_SECONDS",
    "NT_HASHCAT_MODE",
    "OPT_OUT_ENV",
    "dispatch_local_nt_crack",
    "local_cracking_available",
    "local_nt_crack_completed",
    "normalize_nt_entries",
    "record_local_nt_crack_outcome",
]
