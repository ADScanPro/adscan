"""Effective credential-harvest view: persisted records plus live in-progress rows.

The durable store (``credential_harvest_store``) only holds a record once a
background crack has produced a TERMINAL result (cracked / uncracked /
uncrackable / rainbow-pending) and that result has been drained on the
foreground thread. While a crack is still running there is no persisted record,
so a scan that ends fast — before the crack finishes — would render an EMPTY
harvest panel even though a hash was captured and cracking is underway.

This module closes that gap: it reads the live background-job registry, finds
the still-running ``cracking`` jobs, and synthesizes a ``"cracking"``
:class:`HarvestedPrincipal` row for each so the operator SEES that a capture is
being worked. It is the single source the scan-end summary, the between-commands
drain review, and the on-demand ``harvest`` command all read, so every surface
shows the same consolidated state (finished captures + in-flight cracks).

Read-only + best-effort: a registry/classification failure degrades to the
persisted records alone, never raises.
"""
from __future__ import annotations

import dataclasses
from typing import Any

from adscan_core import telemetry
from adscan_internal.services.background_jobs.registry import get_or_create_registry
from adscan_internal.services.captured_credential_policy import classify_principal
from adscan_internal.services.credential_harvest_classification import (
    classify_harvested_principal_tier,
    classify_harvested_principals_reach,
)
from adscan_internal.services.credential_harvest_record import HarvestedPrincipal
from adscan_internal.services.credential_harvest_store import load_harvest_records
from adscan_internal.services.high_value import normalize_samaccountname

# Which harvest source a still-running crack most likely came from, inferred
# from the hashcat mode on its job scope (the running job does not carry the
# original source). Cosmetic — it only labels the "cracking…" row's Source cell.
_NETNTLM_MODES: frozenset[str] = frozenset({"5500", "5600"})
_KERBEROAST_MODES: frozenset[str] = frozenset({"13100", "19600", "19700"})
_ASREP_MODES: frozenset[str] = frozenset({"18200", "19800", "19900"})

# NetNTLM version, so the "cracking…" row can still label NTLMv1/v2 (the roast
# modes carry no NTLM version).
_NTLM_VERSION_FOR_MODE: dict[str, str] = {"5500": "v1", "5600": "v2"}

_CRACKING_JOB_KIND = "cracking"
_SCOPE_MODE_MARKER = ".m"


def parse_cracking_job_scope(scope: str) -> tuple[str, str]:
    """Split a cracking job scope ``"<user>.m<mode>"`` into ``(user, mode)``.

    The scope is minted by ``enqueue_cracking_job`` as ``f"{user}.m{mode_str}"``.
    A sAMAccountName may itself contain dots (``robb.stark``), so the mode
    suffix is matched from the RIGHT and validated as digits — the mode is
    always numeric (``5600``/``13100``/…). Returns ``(scope, "")`` when the
    scope carries no recognizable ``.m<digits>`` suffix (a defensive fallback,
    never a crash).
    """
    text = str(scope or "")
    idx = text.rfind(_SCOPE_MODE_MARKER)
    if idx == -1:
        return text, ""
    user = text[:idx]
    mode = text[idx + len(_SCOPE_MODE_MARKER):]
    if not user or not mode.isdigit():
        return text, ""
    return user, mode


def _source_for_mode(mode: str) -> str:
    """Infer the likely harvest source for a running crack from its mode."""
    m = str(mode or "").strip()
    if m in _KERBEROAST_MODES:
        return "kerberoasting"
    if m in _ASREP_MODES:
        return "asreproasting"
    if m in _NETNTLM_MODES:
        return "poisoning"
    return "poisoning"


def build_in_progress_harvest_records(
    shell: Any, domain: str
) -> list[HarvestedPrincipal]:
    """Synthesize an in-progress record per still-running background crack.

    Each record's ``crack_status`` is ``"cracking"`` when the crack currently
    holds the single-instance hashcat slot (hashcat running), or ``"queued"``
    when it is alive but waiting behind another crack for the slot.

    Reads the live job registry, keeps the non-terminal ``cracking`` jobs, and
    classifies each principal's Privilege Tier + Compromise Reach off the
    current graph (the same SSOT the persisted records use) so an in-flight
    capture already shows its value. Returns ``[]`` when nothing is cracking
    (so callers pay no graph-classification cost on the common path). Never
    raises.
    """
    try:
        registry = get_or_create_registry(shell)
        active = [j for j in registry.active() if j.kind == _CRACKING_JOB_KIND]
    except Exception as exc:  # noqa: BLE001 — a registry read is best-effort
        telemetry.capture_exception(exc)
        return []
    if not active:
        return []

    parsed: list[tuple[str, str, Any]] = []
    for job in active:
        # Defense-in-depth: a cracking job's LAST result is marked ``terminal``,
        # so the results-bus sink transitions it to ``done`` and it normally
        # LEAVES ``registry.active()`` the moment the ladder finishes. This
        # exclusion still guards the residual case where a job sits in
        # ``active()`` yet its worker thread has ALREADY ended — a runtime that
        # died without emitting a terminal result (an escaped exception leaves it
        # "running"), or a stale re-enqueue. Synthesizing an in-progress row for
        # such a job would render it FOREVER as "queued" and steal the render from
        # its persisted terminal record. The live runtime is the ground truth: a
        # finished (not-alive) runtime is excluded here so the job falls through
        # to its PERSISTED terminal record (cracked / uncracked) instead of a
        # stale synthesis.
        if _crack_runtime_finished(registry, job):
            continue
        user, mode = parse_cracking_job_scope(job.scope)
        if user:
            parsed.append((user, mode, job))
    if not parsed:
        return []

    domains_data = getattr(shell, "domains_data", None)
    usernames = [user for user, _, _ in parsed]
    try:
        reach_by_user = classify_harvested_principals_reach(
            shell, domain=domain, usernames=usernames
        )
    except Exception as exc:  # noqa: BLE001 — graph read is best-effort
        telemetry.capture_exception(exc)
        reach_by_user = {}

    records: list[HarvestedPrincipal] = []
    seen: set[str] = set()
    for user, mode, job in parsed:
        key = normalize_samaccountname(user)
        if key in seen:
            continue
        seen.add(key)
        account_type = classify_principal(user, domains_data, domain)
        try:
            tier = classify_harvested_principal_tier(
                shell, domain=domain, username=user, account_type=account_type
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            tier = None
        # ``tier`` / ``reach`` may be None (UNDETERMINED — no membership/graph
        # data yet); persist the None so the row renders "Unknown"/"Not
        # assessed" instead of a false Tier 2 / Standard reach.
        reach = reach_by_user.get(key)
        # A crack that HOLDS the hashcat slot renders "cracking" (+ its live
        # method/eta/progress); a crack that is alive but WAITING behind another
        # crack for the single-instance slot renders a plain "queued". Reading the
        # phase off the runtime snapshot is what stops a waiting crack from
        # falsely reading as "cracking".
        phase, method, eta, progress = _live_crack_status(registry, job)
        records.append(
            HarvestedPrincipal(
                domain=domain,
                username=user,
                source=_source_for_mode(mode),
                account_type=account_type,
                ntlm_version=_NTLM_VERSION_FOR_MODE.get(mode, ""),
                crack_status=phase,
                privilege_tier=tier.value if tier is not None else None,
                compromise_reach=reach.value if reach is not None else None,
                hash_file="",
                captured_at="",
                mode=mode,
                method=method,
                eta=eta,
                progress=progress,
            )
        )
    return records


def _crack_runtime_finished(registry: Any, job: Any) -> bool:
    """True when the crack's worker thread has ENDED (its runtime is not alive).

    Distinguishes a crack that is genuinely in-flight from one that
    ``registry.active()`` still lists only because a cracking job's record is
    marked terminal ONLY when its result is drained — so a crack whose thread
    already finished still reads ``"running"``. The in-memory ``JobRuntime`` is
    the ground truth: a dead runtime means the ladder is done (cracked or
    exhausted) and the row must NOT be synthesized as in-progress.

    Only a runtime that is PRESENT and reports ``is_alive() is False`` counts as
    finished. A missing runtime (``None`` — e.g. a job reloaded from disk with no
    live in-memory runtime) is treated as NOT finished, so its display is left to
    the existing default (never guessed here). Best-effort: any read failure
    returns ``False`` (keep the row) so a transient error never hides a genuinely
    running crack.
    """
    try:
        runtime = registry.get_runtime(getattr(job, "id", ""))
        if runtime is None:
            return False
        return not runtime.is_alive()
    except Exception as exc:  # noqa: BLE001 — a runtime liveness read is best-effort
        telemetry.capture_exception(exc)
        return False


def _live_crack_status(registry: Any, job: Any) -> tuple[str, str, str, str]:
    """Read a running crack's live ``(phase, method, eta, progress)`` from its runtime.

    Reads the in-memory ``JobRuntime`` snapshot (never persisted). ``phase`` is
    ``"queued"`` when the crack is alive but WAITING behind another crack for the
    single-instance hashcat slot (another crack is running) — the row then shows
    a plain ``queued`` with no method/eta/progress. ``phase`` is ``"cracking"``
    when this crack HOLDS the slot (hashcat live), carrying the current tier's
    method + benchmark/live-derived ETA/progress.

    Best-effort: a missing runtime / non-dict snapshot / failure degrades to
    ``("cracking", "", "", "")`` — the safe, non-false-``queued`` default (a lone
    crack, or a runtime we cannot read, is treated as running, never as waiting).
    """
    try:
        runtime = registry.get_runtime(getattr(job, "id", ""))
        if runtime is None:
            return "cracking", "", "", ""
        snap = runtime.snapshot()
        if not isinstance(snap, dict):
            return "cracking", "", "", ""
    except Exception as exc:  # noqa: BLE001 — a runtime read is best-effort
        telemetry.capture_exception(exc)
        return "cracking", "", "", ""
    from adscan_internal.services.background_jobs.cracking_job import (  # noqa: PLC0415
        format_eta_seconds,
        format_progress_pct,
    )

    # Only an explicit "queued" phase downgrades the row; any other value
    # (including a missing phase, e.g. a snapshot that predates this field)
    # keeps the "cracking" default so no legacy runtime is mislabeled queued.
    if str(snap.get("phase") or "") == "queued":
        return "queued", "", "", ""
    method = str(snap.get("method") or "")
    eta = format_eta_seconds(snap.get("eta_seconds"))
    progress = format_progress_pct(snap.get("progress_pct"))
    return "cracking", method, eta, progress


def _rederive_tier_and_reach(
    shell: Any, domain: str, records: list[HarvestedPrincipal]
) -> list[HarvestedPrincipal]:
    """Re-classify each record's Privilege Tier + Compromise Reach at render time.

    The stored tier/reach are only a capture-time snapshot: a principal captured
    early (poisoning before any graph existed) is stamped UNDETERMINED, and once
    later authenticated collection populates memberships/attack paths its REAL
    tier/reach become knowable. Re-deriving off the CURRENT graph state at every
    render is what turns "Unknown" into the real Tier 0 for that principal after
    activation, instead of freezing the capture-time value. Uses the same
    classification SSOT the producers use.

    Authoritative: the current classification (including ``None`` = UNDETERMINED)
    replaces the stored value, so a stale/false stored tier is corrected too. On
    an unexpected classifier exception the stored value is kept as a fallback so
    a transient failure never blanks a known verdict. Never raises.
    """
    if not records:
        return records
    usernames = [rec.username for rec in records if rec.username]
    try:
        reach_by_user = classify_harvested_principals_reach(
            shell, domain=domain, usernames=usernames
        )
    except Exception as exc:  # noqa: BLE001 — graph read is best-effort
        telemetry.capture_exception(exc)
        reach_by_user = {}

    out: list[HarvestedPrincipal] = []
    for rec in records:
        key = normalize_samaccountname(rec.username)
        try:
            tier = classify_harvested_principal_tier(
                shell, domain=domain, username=rec.username,
                account_type=rec.account_type,
            )
            tier_value = tier.value if tier is not None else None
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            tier_value = rec.privilege_tier
        if key in reach_by_user:
            reach = reach_by_user[key]
            reach_value = reach.value if reach is not None else None
        else:
            reach_value = rec.compromise_reach
        out.append(
            dataclasses.replace(
                rec, privilege_tier=tier_value, compromise_reach=reach_value
            )
        )
    return out


def load_effective_harvest_records(
    shell: Any, domain: str
) -> list[HarvestedPrincipal]:
    """Return persisted harvest records merged with live in-progress cracks.

    The union the operator should see: every finished capture (from the durable
    store) plus a ``"cracking"`` row for each still-running background crack.
    Dedup is by principal — an in-flight crack overrides a stored NON-cracked
    record for the same user (the freshest state is "still working on it"), but
    a stored ``"cracked"`` record always wins (its recovered secret must not be
    masked by a stale re-enqueued job).

    Every returned record's Privilege Tier + Compromise Reach are RE-DERIVED
    from the current graph state (see :func:`_rederive_tier_and_reach`), so an
    UNDETERMINED early capture resolves to its real tier/reach once later
    collection populates the graph. Never raises.
    """
    try:
        persisted = load_harvest_records(shell)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        persisted = []
    in_progress = build_in_progress_harvest_records(shell, domain)
    if not in_progress:
        return _rederive_tier_and_reach(shell, domain, persisted)

    by_user: dict[str, HarvestedPrincipal] = {
        rec.username.strip().lower(): rec for rec in persisted
    }
    for rec in in_progress:
        key = rec.username.strip().lower()
        existing = by_user.get(key)
        if existing is None or existing.crack_status != "cracked":
            by_user[key] = rec
    return _rederive_tier_and_reach(shell, domain, list(by_user.values()))


__all__ = [
    "build_in_progress_harvest_records",
    "load_effective_harvest_records",
    "parse_cracking_job_scope",
]
