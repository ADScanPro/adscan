"""Scale-aware host-enrichment gate: an informed choice before a long sweep.

On a large directory the LDAP identity graph finishes in minutes, but the SMB
host-enrichment sweep (logged-on sessions, local administrators, shares) over
tens of thousands of reachable hosts can run for hours. Before this gate, that
sweep started silently and unbounded, so an operator on a real 40,000-host
estate could wait most of a day and never reach a single attack path.

This gate fires ONCE, at the SMB-enrichment entry, after the 445/tcp
reachability count is known and BEFORE the per-host sweep dispatches — but only
when the reachable set is large enough to matter (:data:`SCALE_GATE_THRESHOLD`).
Below that it is inert: a small lab or one /24 subnet is byte-for-byte unchanged.

An INTERACTIVE run renders a premium panel and lets the operator choose the exact
scope, with an approximate time for each choice so the decision is informed:

  1. Enrich the recommended :data:`~adscan_internal.services.scan_config.HOST_CAP_DEFAULT`
     most relevant hosts (representative-first, Tier 0 first). Recommended.
  2. Enrich a custom number of hosts the operator types.
  3. Enrich every reachable host (the full sweep).
  4. Skip SMB enrichment and compute attack paths on the identity graph now.

A NON-INTERACTIVE run (``adscan ci`` / the web worker) MUST NOT hang and MUST NOT
override the host cap decided upstream. The web UI is the scale gate for that
flow: the customer picks the cap there (``0`` = all hosts) and it travels into the
CI scan config, so the gate is a NO-OP on the incoming cap — whatever arrived is
honoured verbatim. It never injects a default in non-interactive mode.

The time estimate is a COARSE upper bound derived from the collector's configured
concurrency and per-host timeout, not a measured rate. A measured micro-benchmark
would have to enrich a real sample of hosts before this decision runs, which
contradicts the seam's contract (the choice precedes the sweep, and the gate is
shell-free with no access to the async per-host collector). The estimate is always
labelled approximate so the operator reads it as a rough guide, not a promise.

This module owns the DECISION and its presentation. It is shell-free: the host
collector invokes it through an opaque callback on
:class:`~adscan_internal.services.collector.host_collector.HostCollectorConfig`,
the same clean service/CLI layering the crash-resume and progress callbacks use.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass
from typing import Any

from adscan_core.rich_output import (
    BRAND_COLORS,
    print_info,
    print_info_debug,
    print_panel,
)
from adscan_core.output import prompt_ask, questionary_select_index
from adscan_core.tui.progress_dashboard import format_eta
from adscan_internal.interaction import is_non_interactive
from adscan_internal.services.scan_config import HOST_CAP_DEFAULT

# The reachable-host count above which the scale gate engages. Chosen as a small
# multiple of the ``HOST_CAP_DEFAULT`` (150) PoV scope: below ~1,000 reachable
# hosts a full sweep is a matter of minutes and the choice is not worth an
# interruption; at and beyond it the difference between the capped default and a
# full sweep is hours. Provisional and tunable — override with the env var below.
_SCALE_GATE_THRESHOLD_DEFAULT = 1000
SCALE_GATE_THRESHOLD_ENV = "ADSCAN_SCALE_GATE_THRESHOLD"

# Coarse per-host-time model for the estimate (see the module docstring for why a
# measured benchmark is impractical at this seam). These mirror the collector's
# own env-configurable knobs so a tuned deployment estimates against its OWN
# timing, not a hardcoded one.
_HOST_CONCURRENCY_ENV = "ADSCAN_COLLECTOR_HOST_CONCURRENCY"
_HOST_CONCURRENCY_DEFAULT = 20
_PER_HOST_TIMEOUT_ENV = "ADSCAN_COLLECTOR_PER_HOST_TIMEOUT"
# The per-host timeout (default 20s) is the honest UPPER-BOUND figure for one
# host's wall time: a fast host finishes in a second or two, a filtered/hardened
# host burns close to the full per-host timeout in dead-wait. Modelling every host
# at the timeout keeps the estimate a conservative upper bound, never optimistic.
_PER_HOST_SECONDS_DEFAULT = 20


def _resolve_threshold() -> int:
    """Resolve the scale-gate threshold (env-overridable, floored at 1)."""
    raw = os.environ.get(SCALE_GATE_THRESHOLD_ENV)
    if raw is None:
        return _SCALE_GATE_THRESHOLD_DEFAULT
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return _SCALE_GATE_THRESHOLD_DEFAULT
    return max(1, value)


#: The active threshold, resolved at import for readability. Consumers that need
#: the live env override call :func:`_resolve_threshold` instead.
SCALE_GATE_THRESHOLD = _resolve_threshold()


def _env_int(name: str, default: int, *, floor: int = 1) -> int:
    """Read a positive integer env override, floored, else the default."""
    raw = os.environ.get(name)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        return max(floor, int(str(raw).strip()))
    except (TypeError, ValueError):
        return default


def _resolve_concurrency() -> int:
    """The SMB sweep concurrency the estimate divides by (collector's own knob)."""
    return _env_int(_HOST_CONCURRENCY_ENV, _HOST_CONCURRENCY_DEFAULT, floor=1)


def _resolve_per_host_seconds() -> int:
    """The coarse per-host wall-time model the estimate multiplies by."""
    return _env_int(_PER_HOST_TIMEOUT_ENV, _PER_HOST_SECONDS_DEFAULT, floor=1)


def estimate_sweep_seconds(
    hosts: int,
    *,
    concurrency: int | None = None,
    per_host_seconds: int | None = None,
) -> int:
    """Coarse upper-bound estimate of the SMB host-enrichment wall time, in seconds.

    The sweep runs ``concurrency`` hosts at a time, so ``ceil(hosts / concurrency)``
    waves each cost about ``per_host_seconds`` in the worst case. This is a rough
    UPPER BOUND, not a measured rate: most hosts finish faster than the per-host
    timeout, and a real network's mix varies. It exists to give the operator a
    sense of scale ("seconds vs minutes vs hours"), always presented as approximate.

    Args:
        hosts: The number of hosts that would be swept.
        concurrency: Simultaneous SMB sessions. Defaults to the collector's
            configured concurrency (env-overridable).
        per_host_seconds: Coarse per-host wall time. Defaults to the collector's
            configured per-host timeout (env-overridable).

    Returns:
        Estimated seconds, floored at 0. ``0`` hosts returns ``0``.
    """
    n = max(0, int(hosts))
    if n == 0:
        return 0
    conc = max(1, int(concurrency if concurrency is not None else _resolve_concurrency()))
    per = max(1, int(per_host_seconds if per_host_seconds is not None else _resolve_per_host_seconds()))
    waves = math.ceil(n / conc)
    return waves * per


def _est_label(hosts: int) -> str:
    """The approximate-time suffix rendered beside a host count (``≈ Xm Ys``)."""
    return f"≈ {format_eta(estimate_sweep_seconds(hosts))}"


@dataclass(frozen=True)
class ScaleGateDecision:
    """The outcome of the scale gate for one domain's SMB host-enrichment sweep.

    ``effective_host_cap`` is the cap the collector must apply to the
    representative-first dispatch list: the operator's chosen amount (the
    recommended default, a custom number, or ``0`` for a full sweep), and
    irrelevant when ``skip_enrichment`` is set. ``skip_enrichment`` short-circuits
    the whole per-host sweep. ``reason`` is the coverage-gap reason
    (:mod:`adscan_core.reporting.host_enrichment_coverage`) when the sweep is
    bounded, else empty. ``prompted`` records whether the gate actually engaged
    (True) or was inert / pre-decided / a non-interactive no-op (False) — used only
    for telemetry and tests.
    """

    effective_host_cap: int
    skip_enrichment: bool = False
    reason: str = ""
    prompted: bool = False


def _cap_option(cap: int) -> str:
    return f"Enrich the top {cap:,} most relevant hosts ({_est_label(cap)}, recommended)"


def _custom_option() -> str:
    return "Enrich a specific number of hosts I choose"


def _full_option(reachable: int) -> str:
    return f"Enrich all {reachable:,} reachable hosts ({_est_label(reachable)})"


_SKIP_OPTION = "Skip SMB enrichment and compute attack paths on the identity graph now"


def _render_scale_panel(reachable: int, cap: int) -> None:
    """Render the premium, fact-first scale panel above the choice.

    Concrete numbers, clear hierarchy, no fear-mongering: state what is already
    done, what the sweep is, the approximate time for the recommended cap and the
    full sweep, then let the operator choose. The estimate is labelled approximate
    and its basis is stated in one line, so it reads as a guide, not a promise.
    """
    accent = BRAND_COLORS["info"]
    ok = BRAND_COLORS["success"]
    muted = "dim"
    lines = [
        f"[bold]{reachable:,}[/bold] reachable hosts in this directory.",
        "",
        f"[{ok}]The identity graph is already complete.[/{ok}] Every user, group, "
        "computer, ACL and trust is mapped, so your attack paths, ADCS/ESC "
        "findings and reach are ready to compute now.",
        "",
        "SMB host enrichment is the deeper second pass: logged-on sessions, local "
        "administrators and shares, host by host. Approximate time at the "
        "collector's current concurrency:",
        "",
        f"  [bold]{cap:,}[/bold] hosts (recommended)   [{accent}]{_est_label(cap)}[/{accent}]",
        f"  [bold]{reachable:,}[/bold] hosts (everything)   "
        f"[{accent}]{_est_label(reachable)}[/{accent}]",
        "",
        f"Enriching the top [bold]{cap:,}[/bold] most relevant hosts covers the "
        "highest-value targets first (Tier 0 domain controllers and CAs lead) and "
        "keeps time to a deliverable bounded. The rest can be enriched later.",
        "",
        f"[{muted}]Times are a rough upper bound from the configured concurrency "
        f"and per-host timeout, not a measured rate; real hosts finish faster.[/{muted}]",
    ]
    print_panel(
        "\n".join(lines),
        title="Large directory: choose host-enrichment scope",
        title_align="left",
        border_style=accent,
    )


def _prompt_custom_amount(*, reachable: int, cap: int, shell: Any) -> int:
    """Prompt the operator for a custom host count, clamped to ``[1, reachable]``.

    Echoes the approximate time for the typed number before it is applied, so the
    operator sees the cost of their own figure. Reuses the non-interactive-safe
    ``prompt_ask`` (this path is interactive by construction, but the helper keeps
    the CI-hang guarantee if interaction is disabled mid-run). An empty or invalid
    entry falls back to the recommended ``cap``.
    """
    default = str(cap)
    raw = prompt_ask(
        f"How many hosts should ADscan enrich? (1-{reachable:,}, highest-value first)",
        default=default,
        shell=shell,
        prefill_default=False,
    )
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        print_info(
            f"Not a number; using the recommended {cap:,} hosts ({_est_label(cap)})."
        )
        return cap
    if value <= 0:
        print_info(
            f"Value must be positive; using the recommended {cap:,} hosts "
            f"({_est_label(cap)})."
        )
        return cap
    if value >= reachable:
        # At or above the reachable count is a full sweep — no truncation.
        return reachable
    return value


def resolve_scale_gate_choice(
    *,
    reachable_hosts: int,
    shell: Any = None,
) -> ScaleGateDecision:
    """Decide the SMB host-enrichment scope for a (possibly large) directory.

    Called once per domain by the host collector, after the 445 reachability
    count is known and before the per-host sweep. Below the threshold the gate is
    inert. In non-interactive mode it is a NO-OP on the incoming cap (the web /
    scan config already decided). An explicit ``ADSCAN_COLLECTOR_HOST_CAP`` skips
    the prompt. Only an interactive run renders the panel and asks.

    Args:
        reachable_hosts: Hosts that passed the 445/tcp reachability gate — the
            count that actually drives the time cost.
        shell: Optional shell threaded into the non-interactive prompt predicate
            (so ``adscan ci`` auto-resolves rather than blocking on stdin).

    Returns:
        A :class:`ScaleGateDecision`. Below the threshold, and in non-interactive
        mode, the gate returns ``effective_host_cap=0`` (a no-op — the caller's
        existing cap, if any, is untouched) with ``prompted=False``.
    """
    threshold = _resolve_threshold()
    if reachable_hosts < threshold:
        # Inert below threshold — the caller's existing host_cap (scan config /
        # env) is untouched; a small estate is byte-for-byte unchanged.
        return ScaleGateDecision(effective_host_cap=0, prompted=False)

    cap = HOST_CAP_DEFAULT

    # An operator who set the cap explicitly has already decided — honour it
    # silently, no prompt. A positive value caps to it; 0 means an explicit full
    # sweep. Either way the gate does not override the operator's own choice.
    explicit_cap_raw = os.environ.get("ADSCAN_COLLECTOR_HOST_CAP")
    if explicit_cap_raw is not None and str(explicit_cap_raw).strip() != "":
        try:
            explicit_cap = max(0, int(str(explicit_cap_raw).strip()))
        except (TypeError, ValueError):
            explicit_cap = 0
        print_info_debug(
            "[scale-gate] ADSCAN_COLLECTOR_HOST_CAP set explicitly "
            f"({explicit_cap}); skipping the scale gate prompt."
        )
        if explicit_cap > 0 and explicit_cap < reachable_hosts:
            return ScaleGateDecision(
                effective_host_cap=explicit_cap, reason="cap", prompted=False
            )
        return ScaleGateDecision(effective_host_cap=0, prompted=False)

    # Non-interactive (adscan ci / web worker): the web UI IS the scale gate for
    # this flow — the customer picked the host cap there and it travelled into the
    # scan config, so the gate must NOT inject one of its own. Return a no-op: the
    # incoming cap (0 = all hosts, or whatever positive value the customer set) is
    # honoured verbatim. Never re-cap, never prompt.
    if is_non_interactive(shell):
        print_info_debug(
            "[scale-gate] Non-interactive run: honouring the configured host cap "
            f"({reachable_hosts:,} reachable hosts); the scale gate makes no change. "
            "The host cap is set in the web UI / scan config; 0 sweeps every host."
        )
        return ScaleGateDecision(effective_host_cap=0, prompted=False)

    # Interactive: render the premium panel + the amount-choice select. The select
    # helper auto-resolves to the default index if interaction is disabled mid-run.
    _render_scale_panel(reachable_hosts, cap)
    options = [
        _cap_option(cap),
        _custom_option(),
        _full_option(reachable_hosts),
        _SKIP_OPTION,
    ]
    idx = questionary_select_index(
        title="How should ADscan scope SMB host enrichment?",
        options=options,
        default_idx=0,
        shell=shell,
    )
    if idx is None:
        idx = 0  # cancelled → the recommended, safe default

    if idx == 1:
        chosen = _prompt_custom_amount(reachable=reachable_hosts, cap=cap, shell=shell)
        if chosen >= reachable_hosts:
            print_info(
                f"Enriching all {reachable_hosts:,} reachable hosts "
                f"({_est_label(reachable_hosts)}). You can stop the sweep at any "
                "point and the scan will continue with the hosts collected so far."
            )
            return ScaleGateDecision(effective_host_cap=0, prompted=True)
        print_info(
            f"Enriching the top {chosen:,} most relevant hosts ({_est_label(chosen)}, "
            "highest-value first). The identity graph is complete, so attack paths "
            "and reach cover the full directory."
        )
        return ScaleGateDecision(effective_host_cap=chosen, reason="cap", prompted=True)
    if idx == 2:
        print_info(
            f"Enriching all {reachable_hosts:,} reachable hosts "
            f"({_est_label(reachable_hosts)}). You can stop the sweep at any point "
            "and the scan will continue with the hosts collected so far (the "
            "identity graph is already complete)."
        )
        return ScaleGateDecision(effective_host_cap=0, prompted=True)
    if idx == 3:
        print_info(
            "Skipping SMB host enrichment. Attack paths and reach will be computed "
            "on the complete identity graph. You can run host enrichment later to "
            "add logged-on sessions, local administrators and share exposure."
        )
        return ScaleGateDecision(
            effective_host_cap=0, skip_enrichment=True, reason="skip", prompted=True
        )
    print_info(
        f"Enriching the top {cap:,} most relevant hosts ({_est_label(cap)}, "
        "highest-value first). The identity graph is complete, so attack paths and "
        "reach cover the full directory."
    )
    return ScaleGateDecision(effective_host_cap=cap, reason="cap", prompted=True)


__all__ = [
    "SCALE_GATE_THRESHOLD",
    "SCALE_GATE_THRESHOLD_ENV",
    "ScaleGateDecision",
    "estimate_sweep_seconds",
    "resolve_scale_gate_choice",
]
