"""Unified per-host collector for ADscan.

Single SMB session per host that runs SAMR (sessions, builtin groups) and
SRVSVC (share enumeration with security descriptors) on the same authenticated
``aiosmb`` machine.  Replaces the legacy two-phase flow that opened two
separate SMB sessions per host.

All Computer nodes in the CollectionResult are processed concurrently up to
``concurrency`` simultaneous SMB sessions.  IP resolution must have happened
upstream via ``dns_resolver.resolve_computer_nodes``.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import os
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

from adscan_core import telemetry
from adscan_core.rich_output import print_info_debug, print_info_verbose
from adscan_core.interaction import is_non_interactive
from adscan_core.tui.patience_notice import (
    PatienceNoticeConfig,
    maybe_show_patience_notice,
)
from adscan_core.tui.progress_dashboard import (
    ProgressDashboard,
    ProgressDashboardConfig,
)

if TYPE_CHECKING:
    pass  # DomainPosture, PostureSink used in Tasks 4-5 host-phase logic

from adscan_internal.services.collector.models import (
    CollectionResult,
    CollectorEdge,
    is_collectable_computer_host,
    is_disabled_computer_account,
)

from adscan_internal.services.collector.share_collector import (
    ShareCollectorConfig,
    _ShareInfo,
    mask_to_edge_kinds,
)
from adscan_internal.services.collector.share_ntfs_verification import (
    VERIFICATION_NTFS_COMPUTED,
    VERIFICATION_SELF_MXAC,
    VERIFICATION_SHARE_ACL_ONLY,
    build_sid_group_closure,
    compute_effective_file_mask,
    decide_verification_tier,
    is_broad_auth_sid,
    is_closure_confident,
)
from adscan_internal.services.collector.smb_collector import (
    SMBCollectorConfig,
    sid_to_object_id,
)
from adscan_internal.services.collector.well_known_sids import NON_GRANTEE_SIDS


_HOST_CONCURRENCY_DEFAULT = 20
_HOST_TIMEOUT_DEFAULT = 20

# Hard wall-clock bound on the AUTHENTICATED SMB connect (the per-host
# `smb_machine_with_fallback` enter: Kerberos getST + negotiate + session-setup,
# plus the Kerberos→NTLM fallback). This is the one connect step that otherwise
# rides only the transport's SOFT ``timeout=`` per internal op, so on a host that
# opens TCP/445 but STALLS the SMB session (security appliances, honeypots/EDR,
# printers/IoT, half-open firewalls — common at enterprise scale) the soft
# timeouts sum to ~2-3× per-op (~53s observed) before failing.
#
# Value grounded in the field-proven collectors (studied in reference/): the
# 445 gate above is the TCP pre-check those tools do first (bloodhound.py
# ``tcp_ping(445)``; NetExec ``_is_port_open(1s)``); AFTER that pre-check they
# bound the connect aggressively — bloodhound.py ``set_connect_timeout(1.0)``,
# NetExec ``set_connect_timeout(5)`` (vs impacket's 60s default that an unbounded
# connect would ride). Note both only bound the TCP/RPC SOCKET connect and can
# still hang on a post-TCP SMB-session stall; ADscan bounds the FULL
# authenticated session (negotiate + getST + session-setup), so it is strictly
# more robust. A real authed session (TCP already gated) is <3s typical and <8s
# pathological even with per-host getST under KDC load at scale, so 10s never
# cuts a healthy host while capping a stalled one ~tightly — between NetExec's
# 5s and an audit-tool completeness margin (we prefer not to skip a real-but-slow
# host the way bloodhound's 1s would). Tune via ``ADSCAN_COLLECTOR_CONNECT_TIMEOUT``.
_HOST_CONNECT_TIMEOUT_DEFAULT = 10

# Hard per-host wall-clock SAFETY NET for the full collection of one host
# (negotiate + auth-connect + SAMR + shares). Every per-op step is already a hard
# ``asyncio.wait_for`` bound EXCEPT the authenticated connect, which relies on the
# transport's soft ``timeout=`` param; this generous ceiling guarantees a hung
# host can never hold a worker slot indefinitely, WITHOUT cutting a host that
# respects the intended per-op limits (their worst-case sum, ~140s with the
# fallback, sits below this). It is a safety net, not a perf knob — tune it DOWN
# via the env var only once a measured per-host duration distribution is in hand.
_HOST_BUDGET_DEFAULT = 180

# Emit a running per-host-phase progress line every N completed hosts, so a slow
# run surfaces its duration distribution live instead of only at the end.
_HOST_PROGRESS_TICK = 250

# Phase 2 reachability gate (445/tcp) -- pre-filter unreachable hosts before
# paying the full per-host SMB collection timeout. The connect probe is cheap,
# so concurrency runs far above the ~20 used for full collection.
_GATE_CONCURRENCY_DEFAULT = 256
_GATE_CONCURRENCY_FLOOR = 1
_GATE_TIMEOUT_DEFAULT = 5.0  # seconds; above L2's 3.0 default for VPN RTT budget
_GATE_TIMEOUT_FLOOR = 0.5
_GATE_PORT = 445


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = int(raw)
        return value if value > 0 else default
    except ValueError:
        return default


def _env_float(name: str, default: float, *, floor: float) -> float:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = float(raw)
        return value if value >= floor else default
    except ValueError:
        return default


@dataclass
class HostCollectorConfig:
    """Combined credentials + tuning for the unified host phase."""

    smb: SMBCollectorConfig
    share: ShareCollectorConfig
    concurrency: int = field(
        default_factory=lambda: _env_int(
            "ADSCAN_COLLECTOR_HOST_CONCURRENCY", _HOST_CONCURRENCY_DEFAULT
        )
    )
    per_host_timeout: int = field(
        default_factory=lambda: _env_int(
            "ADSCAN_COLLECTOR_PER_HOST_TIMEOUT", _HOST_TIMEOUT_DEFAULT
        )
    )  # seconds; applied per SMB host operation (negotiate + SAMR + shares combined)
    connect_timeout: int = field(
        default_factory=lambda: _env_int(
            "ADSCAN_COLLECTOR_CONNECT_TIMEOUT", _HOST_CONNECT_TIMEOUT_DEFAULT
        )
    )  # seconds; HARD bound on the authenticated SMB connect (incl. Kerberos→NTLM
    # fallback) — the one step that otherwise rides only the soft transport
    # timeout, so a TCP-open-but-SMB-stalled host fails fast instead of summing
    # ~2-3× per-op. Frees the worker slot at scale; per_host_budget is the net.
    per_host_budget: int = field(
        default_factory=lambda: _env_int(
            "ADSCAN_COLLECTOR_PER_HOST_BUDGET", _HOST_BUDGET_DEFAULT
        )
    )  # seconds; hard wall-clock ceiling for the WHOLE per-host collection (safety net)
    gate_concurrency: int = field(
        default_factory=lambda: max(
            _GATE_CONCURRENCY_FLOOR,
            _env_int("ADSCAN_COLLECTOR_GATE_CONCURRENCY", _GATE_CONCURRENCY_DEFAULT),
        )
    )  # 445/tcp reachability-gate probe fan-out (cheap connect probe)
    gate_timeout: float = field(
        default_factory=lambda: _env_float(
            "ADSCAN_COLLECTOR_GATE_TIMEOUT",
            _GATE_TIMEOUT_DEFAULT,
            floor=_GATE_TIMEOUT_FLOOR,
        )
    )  # seconds; per-host 445 connect-probe budget
    collect_samr: bool = True  # gates _do_samr per host (sessions + builtin groups)
    collect_shares: bool = True  # gates _do_shares per host


@dataclass
class HostCollectionResult:
    """Per-host raw output. Edge construction happens at the domain level."""

    smb_props: dict[str, Any] = field(default_factory=dict)
    session_usernames: list[tuple[str, str]] = field(
        default_factory=list
    )  # (username, ip_address) from SAMR NetSessEnum
    builtin_groups: dict[str, list[str]] = field(default_factory=dict)
    shares: list[_ShareInfo] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)


@dataclass
class HostPhaseTiming:
    """Aggregated timing for the unified host phase across all hosts."""

    negotiate: float = 0.0
    samr: float = 0.0
    shares: float = 0.0
    # Count of Computer nodes excluded from SMB collection specifically because
    # they are disabled accounts (cannot authenticate). Surfaced for telemetry;
    # other exclusion reasons (gMSA, non-SMB) are not counted here.
    disabled_skipped: int = 0
    # 445/tcp reachability-gate metrics (spec section 8). Set by the gate block
    # in _collect_domain_hosts_async; zero when the gate is skipped or fails open.
    gate_probe_ms: float = 0.0
    candidate_count: int = 0
    reachable_445_count: int = 0
    timeouts_avoided_estimate: float = 0.0
    # Per-host MEASUREMENT (observability for the perf investigation — not a knob).
    # Wall-clock duration of each collect_one_host, a single-bucket outcome
    # histogram, and the count of hosts the safety net had to abandon. These let
    # us SEE the real duration distribution (p50/p95/max) instead of guessing
    # where the time goes.
    per_host_durations: list[float] = field(default_factory=list)
    outcome_counts: dict[str, int] = field(default_factory=dict)
    host_budget_timeouts: int = 0
    # Per-STAGE outcome counters, counted ONLY for hosts we reached with a live
    # connection (connect/auth failures live in outcome_counts above). This is
    # what tells us whether a stage's failures are `denied` (permission — normal,
    # nothing to fix) vs `abort` (connection dropped — maybe transient/recoverable)
    # vs `timeout` — the exact split needed to decide a shares reconnect-retry.
    stage_outcomes: dict[str, dict[str, int]] = field(
        default_factory=lambda: {"sessions": {}, "localadmins": {}, "shares": {}}
    )

    @property
    def total(self) -> float:
        return self.negotiate + self.samr + self.shares


def _classify_host_outcome(errors: dict[str, str]) -> str:
    """Map one host's per-op error dict to a single outcome bucket.

    Pure helper for the per-host outcome histogram. Order matters: hard failures
    (budget / connect / auth) are checked first; then the per-STAGE errors
    (sessions / localadmins / shares) are aggregated via the same classifier so
    a swallowed-but-recorded permission denial lands in ``access_denied`` (the
    expected no-local-admin case) rather than ``other_error``, and a connection
    abort/timeout during a stage surfaces as such.
    """
    if not errors:
        return "ok"
    if "host_budget" in errors:
        return "budget_timeout"
    if "connect" in errors:
        return "connect_fail"
    if str(errors.get("auth", "")).startswith("access_denied"):
        return "access_denied"  # cred is not local admin — fast + expected
    if errors.get("auth"):
        return "auth_error"
    buckets = {
        _classify_stage_error(errors.get(k))
        for k in ("sessions", "builtin_groups", "shares")
        if errors.get(k)
    }
    if "abort" in buckets:
        return "rpc_abort"  # 445 open but the connection dropped mid-RPC
    if "timeout" in buckets:
        return "rpc_timeout"  # 445 open but RPC stalled to the per-op timeout
    if "denied" in buckets:
        return "access_denied"  # no local admin on this host — expected, not a failure
    return "other_error"


# Outcomes that are NOT host failures: a clean collect, or the expected
# no-local-admin denial (we still got whatever the share/SID layer allows). The
# dashboard ✓/⚠ split uses this so denied-but-collected hosts read as success.
_NON_FAILURE_OUTCOMES = frozenset({"ok", "access_denied"})


def _classify_stage_error(err: str | None) -> str:
    """Bucket one stage's error string: ok / timeout / denied / abort / other.

    Pure helper. ``err`` is the value stored in ``HostCollectionResult.errors``
    for a stage (``None`` when the stage succeeded). Distinguishes a permission
    denial (normal, unfixable) from a connection drop (maybe transient) so the
    per-stage histogram can answer "would a reconnect-retry recover shares?".
    """
    if not err:
        return "ok"
    e = err.lower()
    if e == "timeout" or "timeout" in e:
        return "timeout"
    if "access_denied" in e or "access denied" in e:
        return "denied"
    if (
        "connection_aborted" in e
        or "connection aborted" in e
        or "connectionterminated" in e
        or "connection closed" in e
        or "connection reset" in e
    ):
        return "abort"
    return "other"


def _percentile(values: list[float], pct: float) -> float:
    """Nearest-rank percentile of ``values`` (pure; 0.0 on empty)."""
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = int(round((pct / 100.0) * (len(ordered) - 1)))
    idx = max(0, min(len(ordered) - 1, idx))
    return ordered[idx]


def _log_host_phase_stats(timing: HostPhaseTiming, total_hosts: int) -> None:
    """Emit the measured per-host duration distribution + outcome histogram.

    This is the data that answers 'where does the SMB-collection time actually
    go' — p50/p95/max wall-clock per host, the single-bucket outcome counts, and
    the slowest durations (no host labels: keeps the line free of sensitive
    hostnames/IPs while still revealing the tail shape).
    """
    durations = timing.per_host_durations
    if not durations:
        return
    hist = ", ".join(f"{k}={v}" for k, v in sorted(timing.outcome_counts.items()))
    print_info_debug(
        f"collector-timing host-phase: {len(durations)}/{total_hosts} hosts · "
        f"per-host wall-clock p50={_percentile(durations, 50):.1f}s "
        f"p95={_percentile(durations, 95):.1f}s max={max(durations):.1f}s · "
        f"budget_timeouts={timing.host_budget_timeouts} · outcomes: {hist or 'none'}"
    )
    slowest = sorted(durations, reverse=True)[:10]
    if slowest:
        print_info_debug(
            "collector-timing slowest per-host durations (s): "
            + ", ".join(f"{d:.0f}" for d in slowest)
        )
    # WHERE the time goes, by stage (sums across hosts; concurrent so they
    # overlap — read the RATIO, not the absolute). `connection-overhead` = total
    # host-work minus the three RPC stages = authenticated connect + teardown +
    # event-loop scheduling. If overhead dominates → the bottleneck is the
    # connection layer (setup/teardown — where the abort/leak lived), NOT the RPC
    # enumeration; if `shares` (or `samr`) dominates → that stage is the cost.
    stage_sum = timing.negotiate + timing.samr + timing.shares
    wall_sum = sum(durations)
    overhead = max(0.0, wall_sum - stage_sum)
    print_info_debug(
        "collector-timing stage time (host-work sums): "
        f"negotiate={timing.negotiate:.0f}s samr={timing.samr:.0f}s "
        f"shares={timing.shares:.0f}s · connection-overhead≈{overhead:.0f}s "
        f"· total host-work={wall_sum:.0f}s"
    )
    # Per-stage outcomes (live-connection hosts only). `denied` = permission
    # (normal, nothing to fix); `abort` = connection dropped (the recoverable
    # case — decides whether a shares reconnect-retry is worth adding).
    for _stage in ("sessions", "localadmins", "shares"):
        _counts = timing.stage_outcomes.get(_stage) or {}
        if _counts:
            _line = ", ".join(f"{k}={v}" for k, v in sorted(_counts.items()))
            print_info_debug(f"collector-timing stage {_stage}: {_line}")


async def _do_negotiate(
    target_ip: str,
    smb_cfg: SMBCollectorConfig,
    out: HostCollectionResult,
    timing: HostPhaseTiming,
) -> None:
    from adscan_internal.services.collector.smb_collector import negotiate_only

    t = time.monotonic()
    try:
        props = await negotiate_only(target_ip, smb_cfg.port, smb_cfg.per_host_timeout)
        if props:
            out.smb_props.update(props)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        out.errors["negotiate"] = f"{type(exc).__name__}: {exc}"
    finally:
        timing.negotiate += time.monotonic() - t


async def _do_samr(
    machine: Any,
    per_host_timeout: int,
    out: HostCollectionResult,
    timing: HostPhaseTiming,
    self_user: str | None = None,
    target_ip: str | None = None,
) -> None:
    from adscan_internal.services.collector.smb_collector import (
        collect_builtin_group_members,
        collect_sessions,
    )

    t = time.monotonic()
    try:
        try:
            sessions, sess_err = await asyncio.wait_for(
                collect_sessions(machine, self_user=self_user, target_ip=target_ip),
                timeout=per_host_timeout,
            )
            out.session_usernames = sessions
            if sess_err:
                # Failure the collector handled gracefully (denial / connection
                # drop). Record it so the per-stage outcome telemetry is accurate
                # — without it, a swallowed abort would miscount as "ok".
                out.errors["sessions"] = sess_err
        except asyncio.TimeoutError:
            out.errors["sessions"] = "timeout"
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            out.errors["sessions"] = f"{type(exc).__name__}: {exc}"

        try:
            builtin_groups, builtin_err = await asyncio.wait_for(
                collect_builtin_group_members(machine), timeout=per_host_timeout
            )
            out.builtin_groups = builtin_groups
            if builtin_err:
                out.errors["builtin_groups"] = builtin_err
        except asyncio.TimeoutError:
            out.errors["builtin_groups"] = "timeout"
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            out.errors["builtin_groups"] = f"{type(exc).__name__}: {exc}"
    finally:
        timing.samr += time.monotonic() - t


async def _do_shares(
    machine: Any,
    target_ip: str,
    share_cfg: ShareCollectorConfig,
    per_host_timeout: int,
    out: HostCollectionResult,
    timing: HostPhaseTiming,
) -> None:
    from adscan_internal.services.collector.share_collector import (
        collect_shares_for_host,
    )

    t = time.monotonic()
    try:
        shares, shares_err = await asyncio.wait_for(
            collect_shares_for_host(machine, share_cfg, target_ip),
            timeout=per_host_timeout * 2,
        )
        out.shares = shares
        if shares_err:
            # Failure the share collector handled gracefully (e.g. a connection
            # abort, or level-1 also denied). Record it so the per-stage outcome
            # telemetry distinguishes denied vs abort — the exact signal that
            # decides whether a shares reconnect-retry is worth adding.
            out.errors["shares"] = shares_err
    except asyncio.TimeoutError:
        out.errors["shares"] = "timeout"
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        out.errors["shares"] = f"{type(exc).__name__}: {exc}"
    finally:
        timing.shares += time.monotonic() - t


async def collect_one_host(
    target_ip: str,
    target_hostname: str | None,
    config: HostCollectorConfig,
    timing: HostPhaseTiming,
) -> HostCollectionResult:
    """Run negotiate + SAMR + SRVSVC against a single host on ONE SMB session."""
    from adscan_internal.services.smb_transport import (
        SMBAccessDeniedError,
        SMBAuthError,
        SMBConfig,
        SMBConnectionError,
        smb_machine_with_fallback,
    )

    out = HostCollectionResult()

    await _do_negotiate(target_ip, config.smb, out, timing)

    smb_config = SMBConfig(
        target_ip=target_ip,
        target_hostname=target_hostname,
        domain=config.smb.domain,
        auth_domain=config.smb.auth_domain,
        username=config.smb.username,
        password=config.smb.password,
        nt_hash=config.smb.nt_hash,
        aes_key=config.smb.aes_key,
        ccache_path=config.smb.ccache_path,
        use_kerberos=config.smb.use_kerberos,
        kdc_ip=config.smb.kdc_ip or config.smb.dc_address,
        port=config.smb.port,
        timeout=config.per_host_timeout,
        posture_sink=config.smb.posture_sink,
        posture_snapshot=config.smb.posture_snapshot,
    )

    import contextlib

    try:
        # Hard-bound the authenticated connect. ``smb_machine_with_fallback``
        # enters via __aenter__ (Kerberos getST + negotiate + session-setup, plus
        # the NTLM fallback) and is the ONLY step not already wrapped in a hard
        # ``wait_for`` — it rides the transport's soft ``timeout=`` per internal
        # op, so a TCP-open-but-SMB-stalled host can burn ~2-3× per_host_timeout
        # (~53s observed) before failing. wait_for caps it at ``connect_timeout``;
        # the resulting TimeoutError is recorded as a connect failure by the
        # handler below, freeing the worker slot fast. The post-connect RPC stages
        # keep their own per-op bounds. (Cancelling a hung connect is safe — the
        # vendor aiosmb fix cancels the keepalive/incoming tasks on teardown, so
        # no task leak; confirmed in-flight 0 at scale.)
        machine_cm = smb_machine_with_fallback(smb_config)
        # smb_machine_with_fallback is an @asynccontextmanager; pylint can't infer
        # __aenter__/__aexit__ through the decorator (false-positive no-member).
        machine = await asyncio.wait_for(
            machine_cm.__aenter__(),  # pylint: disable=no-member
            timeout=config.connect_timeout,
        )
        try:
            if config.collect_samr:
                await _do_samr(
                    machine,
                    config.per_host_timeout,
                    out,
                    timing,
                    self_user=config.smb.username,
                    target_ip=target_ip,
                )
            if config.collect_shares:
                await _do_shares(
                    machine,
                    target_ip,
                    config.share,
                    config.per_host_timeout,
                    out,
                    timing,
                )
        finally:
            with contextlib.suppress(Exception):
                await machine_cm.__aexit__(None, None, None)  # pylint: disable=no-member
    except SMBAuthError as exc:
        out.errors["auth"] = f"{type(exc).__name__}: {exc}"
        if "AP_REP" in str(exc) or "asn1_structs" in str(exc):
            telemetry.capture_exception(exc)
            # NOT a parser bug: a Kerberos AP/KDC rejection — typically a stale-DNS
            # wrong-host SPN (the IP's live host differs from the targeted name).
            # The transport SPN retry + the dedupe gate normally heal this; if it
            # still surfaces here, no live FQDN candidate resolved for the IP.
            print_info_debug(
                f"[host-collector] Kerberos AP/KDC rejection on {target_ip} "
                "(likely stale-DNS wrong-host SPN; no live candidate resolved). "
                "See the duplicate_dns_fqdn hygiene finding."
            )
    except SMBAccessDeniedError as exc:
        out.errors["auth"] = f"access_denied: {exc}"
    except asyncio.TimeoutError:
        # Only the authenticated-connect wait_for can surface a TimeoutError here
        # — the RPC stages catch their own. Distinct, greppable message so a
        # bounded connect-stall is visible in the collector-timing telemetry
        # (separate from a fast RST connect refusal).
        out.errors["connect"] = (
            f"connect_timeout: SMB authenticated session exceeded "
            f"{config.connect_timeout}s (host reachable on 445 but the SMB "
            f"connect stalled — bounded to free the worker slot)"
        )
    except SMBConnectionError as exc:
        out.errors["connect"] = f"{type(exc).__name__}: {exc}"
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        out.errors["unexpected"] = f"{type(exc).__name__}: {exc}"

    return out


def _build_sid_to_node(result: CollectionResult) -> dict[str, Any]:
    sid_to_node: dict[str, Any] = {}
    for node in result.nodes.values():
        oid = str(node.object_id or "").strip().upper()
        if oid:
            sid_to_node[oid] = node
    return sid_to_node


def _build_member_of_closure(
    result: CollectionResult,
) -> dict[str, frozenset[str]]:
    """Build SID → transitive-group-SID closure from MemberOf edges.

    Used by the NTFS effective-access verification to expand each principal's
    group set before evaluating it against the share/NTFS security descriptors.
    The MemberOf edges (including the virtual well-known ones injected by
    ``well_known_sids.py``) are already present in ``result.edges`` by the time
    the host phase runs.
    """
    member_of_pairs = [
        (edge.source_object_id, edge.target_object_id)
        for edge in result.edges
        if edge.relation == "MemberOf"
    ]
    return build_sid_group_closure(member_of_pairs)


def _resolve_share_verification(
    share: _ShareInfo,
    *,
    sid_upper: str,
    principal_kind: str,
    group_closure: dict[str, frozenset[str]],
) -> tuple[str, int | None]:
    """Decide the verification tier + effective mask for one (principal, share).

    Conservative by construction: only upgrades to ``ntfs_computed`` when BOTH
    SDs were read AND the principal's group closure is confident AND the winacl
    intersection actually produced a mask. Any uncertainty keeps the
    ``share_acl_only`` tier with no effective mask (the raw share-ACL edge still
    exists — we never drop it).

    Returns ``(verification_tier, effective_mask_or_None)``.
    """
    eval_possible = bool(share.ntfs_sd_bytes) and is_closure_confident(
        sid_upper, group_closure, principal_kind=principal_kind
    )
    tier = decide_verification_tier(
        share_sd_readable=bool(share.share_sd_bytes),
        ntfs_sd_readable=bool(share.ntfs_sd_bytes),
        per_principal_eval_possible=eval_possible,
    )
    if tier != VERIFICATION_NTFS_COMPUTED:
        # Couldn't intersect NTFS. For the broad authentication groups the
        # scanning identity belongs to, prefer the server-confirmed MxAc
        # self-effective mask (no admin / no NTFS-SD-read needed) over the
        # over-reported raw share grant — this is what stops NETLOGON/SYSVOL
        # showing Full Control / Write when the effective access is Read.
        if share.self_effective_mask is not None and is_broad_auth_sid(sid_upper):
            return VERIFICATION_SELF_MXAC, int(share.self_effective_mask)
        return VERIFICATION_SHARE_ACL_ONLY, None

    group_sids = list(group_closure.get(sid_upper, frozenset()))
    effective = compute_effective_file_mask(
        share.share_sd_bytes,
        share.ntfs_sd_bytes,
        principal_sid=sid_upper,
        group_sids=group_sids,
    )
    if effective is None:
        # Intersection failed (parse error, evaluator unavailable). Stay
        # conservative — the raw share-ACL edge remains, only the tag downgrades.
        return VERIFICATION_SHARE_ACL_ONLY, None
    return VERIFICATION_NTFS_COMPUTED, int(effective)


def _merge_host_into_graph(
    node: Any,
    host_data: HostCollectionResult,
    sid_to_node: dict[str, Any],
    samaccount_to_node: dict[str, Any],
    result: CollectionResult,
    group_closure: dict[str, frozenset[str]] | None = None,
) -> tuple[int, int, int, dict[str, int]]:
    """Merge per-host raw data into the CollectionResult.

    Returns (n_has_session, n_admin_to_like, n_share_edges, sd_source_counts).
    """
    group_closure = group_closure or {}
    for k, v in host_data.smb_props.items():
        node.properties[k] = v

    computer_oid = str(node.object_id or "").strip().upper()
    n_session = 0
    n_admin = 0
    n_share = 0
    sd_source_counts: dict[str, int] = {}

    # HasSession edges — O(1) lookup via pre-built samaccount_to_node index
    for username, _ip in host_data.session_usernames:
        uname_lower = username.lower()
        matched_user = samaccount_to_node.get(uname_lower) or samaccount_to_node.get(
            uname_lower.split("@")[0]
        )
        if matched_user is None:
            continue
        result.add_edge(
            CollectorEdge(
                source_object_id=computer_oid,
                target_object_id=str(matched_user.object_id or "").upper(),
                relation="HasSession",
                source="smb",
                method="srvsvc",
            )
        )
        n_session += 1

    # AdminTo / CanRDP / CanPSRemote edges
    for relation, sids in host_data.builtin_groups.items():
        for sid_str in sids:
            member_oid = sid_to_object_id(sid_str)
            member_node = sid_to_node.get(member_oid)
            if member_node is None or member_node.kind not in (
                "User",
                "Group",
                "Computer",
            ):
                continue
            result.add_edge(
                CollectorEdge(
                    source_object_id=member_oid,
                    target_object_id=computer_oid,
                    relation=relation,
                    source="smb",
                    method="samr",
                )
            )
            n_admin += 1

    # Share edges + names.
    #
    # NTFS-aware verification: a share-ACL grant alone over-reports access. The
    # real access is share-ACL ∩ NTFS-folder-ACL. Each edge is tagged with a
    # verification tier AND, when the effective access is CONFIRMED, that
    # intersection drives the edge KIND (a confirmed read-only share never emits
    # a WriteShare — see the emission below):
    #   * ntfs_computed   — both SDs read + per-principal winacl intersection.
    #                       Effective mask drives the kind + stored in notes.
    #   * self_mxac       — NTFS SD unreadable but the share grants a broad auth
    #                       group the scanning identity belongs to: the server's
    #                       MxAc self-effective mask drives the kind.
    #   * share_acl_only  — NTFS SD unreadable AND not confirmable for this
    #                       principal (e.g. Helpdesk). The RAW share-ACL edge is
    #                       PRESERVED as an unverified write lead (recall).
    if host_data.shares:
        node.properties["smb_shares"] = [s.name for s in host_data.shares]
        for share in host_data.shares:
            sd_source_counts[share.sd_source] = (
                sd_source_counts.get(share.sd_source, 0) + 1
            )
            for sid_str, mask in share.aces:
                sid_upper = sid_str.strip().upper()
                if sid_upper in NON_GRANTEE_SIDS:
                    # Creator Owner / Creator Group / Owner Rights are owner/creator
                    # ABSTRACTIONS, not principals you can authenticate as. Their ACE
                    # is an inheritance/owner template, never a usable folder-access
                    # grant — emitting an edge from them is a false capability (e.g.
                    # Creator Owner:Full on a read-only share → bogus WriteShare).
                    continue
                principal = sid_to_node.get(sid_upper)
                if principal is None or principal.kind not in (
                    "User",
                    "Group",
                    "Computer",
                ):
                    continue
                verification, effective_mask = _resolve_share_verification(
                    share,
                    sid_upper=sid_upper,
                    principal_kind=principal.kind,
                    group_closure=group_closure,
                )
                # The CONFIRMED effective access (share ∩ NTFS) drives the edge
                # KIND when we have it: a share-ACL WRITE that the NTFS folder
                # (ntfs_computed) or the server's MxAc (self_mxac) denies is
                # emitted as ReadShare, never a false WriteShare. When the
                # effective access is NOT confirmable (share_acl_only — NTFS SD
                # unreadable AND not a current-user broad group, e.g. a Helpdesk
                # grant we cannot evaluate), the RAW share-ACL mask drives the
                # kind so the unverified write lead is preserved (recall).
                # effective ⊆ raw (it is an intersection), so this only ever
                # downgrades/drops edges — never invents one.
                kind_mask = effective_mask if effective_mask is not None else mask
                for relation in mask_to_edge_kinds(kind_mask):
                    notes: dict[str, Any] = {
                        "share_name": share.name,
                        "sd_source": share.sd_source,
                        "verification": verification,
                    }
                    if effective_mask is not None:
                        notes["effective_mask"] = effective_mask
                    result.add_edge(
                        CollectorEdge(
                            source_object_id=sid_upper,
                            target_object_id=computer_oid,
                            relation=relation,
                            source="smb",
                            method=f"share_acl:{share.name}",
                            notes=notes,
                        )
                    )
                    n_share += 1

    return n_session, n_admin, n_share, sd_source_counts


def _pick_live_node(ip_nodes: list[Any]) -> Any:
    """Return the LIVE node among several that resolve to one IP.

    Stale DNS / IP reuse can leave two enabled computer accounts pointing at one
    IP (e.g. a decommissioned CZN007 sharing the IP with the live CZN012). The
    live machine is the most-recently-authenticated one (highest
    lastLogonTimestamp). Prefer enabled nodes; fall back to the first when no
    liveness signal exists (the transport SPN retry then backstops correctness).
    """
    def _is_enabled(node: Any) -> bool:
        # enabled may live on the node field (production CollectorNode) or in
        # properties (some builders/tests); only an explicit False disables.
        val = getattr(node, "enabled", None)
        if val is None:
            val = (getattr(node, "properties", None) or {}).get("enabled")
        return val is not False

    enabled = [n for n in ip_nodes if _is_enabled(n)]
    pool = enabled or ip_nodes

    def _last_logon(node: Any) -> int:
        try:
            return int((getattr(node, "properties", None) or {}).get("lastlogon") or 0)
        except (TypeError, ValueError):
            return 0

    return max(pool, key=_last_logon)


async def _gate_reachable_445(
    nodes: list[Any],
    config: HostCollectorConfig,
    timing: HostPhaseTiming,
    resolve_target_ip: Any,
) -> list[Any]:
    """445/tcp reachability gate -- return the subset of ``nodes`` worth probing.

    Builds one connect-probe per unique resolved IP, re-probes the offline set
    once (VPN-loss insurance), and partitions ``nodes`` into reachable vs
    offline. Offline nodes are marked in place (``smb_gate`` property + the
    ``errors``-channel vocabulary) and stay in the graph with no SMB edges.

    FAIL-OPEN (spec section 7): any exception in the gate path returns the FULL
    node list so coverage is never reduced below the no-gate behavior.
    """
    from adscan_internal.services.host_reachability_filter import (
        ReachabilityFilterResult,
        filter_reachable_hosts,
        print_reachability_summary,
    )

    try:
        # A2 -- candidate IP set (dedup, one probe per IP). Nodes massdns could
        # not resolve have no IP to probe or connect to; count them so the
        # summary can surface them instead of silently dropping them.
        ip_to_nodes: dict[str, list[Any]] = {}
        no_ip_count = 0
        for node in nodes:
            target_ip = resolve_target_ip(node)
            if not target_ip:
                no_ip_count += 1
                continue
            ip_to_nodes.setdefault(target_ip, []).append(node)
        candidate_ips = list(ip_to_nodes.keys())
        if not candidate_ips:
            return nodes  # nothing to gate -- keep today's behavior

        # A3 -- probe + VPN-loss insurance re-probe of the offline set only.
        reach = await filter_reachable_hosts(
            candidate_ips,
            _GATE_PORT,
            timeout=config.gate_timeout,
            max_concurrency=config.gate_concurrency,
        )
        gate_probe_ms = reach.elapsed_ms
        if reach.offline:
            reach2 = await filter_reachable_hosts(
                list(reach.offline),
                _GATE_PORT,
                timeout=config.gate_timeout,
                max_concurrency=config.gate_concurrency,
            )
            gate_probe_ms += reach2.elapsed_ms
            reachable_ips = set(reach.reachable) | set(reach2.reachable)
        else:
            reachable_ips = set(reach.reachable)
        # A4 -- partition into reachable vs offline HOST NODES. Reachability is
        # probed once per unique IP (deduped above), but collection runs per host
        # node, so the partition and every operator-facing count below is in
        # host-node units. Offline nodes stay in the graph (marked) with no SMB
        # edges.
        reachable_nodes: list[Any] = []
        offline_nodes: list[Any] = []
        duplicate_dns_skipped = 0
        for ip, ip_nodes in ip_to_nodes.items():
            if ip in reachable_ips:
                if len(ip_nodes) > 1:
                    # Stale DNS / IP reuse: >1 enabled computer maps to one live
                    # IP. Collect the LIVE host once (most-recent lastLogon); skip
                    # the ghost(s) for SMB — the duplicate_dns_fqdn hygiene finding
                    # already reports them. This avoids the wasted Kerberos attempt
                    # against the stale name (cifs/<ghost> → KRB_ERR_GENERIC) and
                    # the misleading "AP_REP parse bug" debug line. The transport
                    # SPN retry remains the backstop when lastLogon is unavailable.
                    live = _pick_live_node(ip_nodes)
                    reachable_nodes.append(live)
                    for node in ip_nodes:
                        if node is not live:
                            node.properties["smb_gate"] = (
                                f"duplicate DNS — superseded by live host at {ip}"
                            )
                            duplicate_dns_skipped += 1
                else:
                    reachable_nodes.extend(ip_nodes)
            else:
                for node in ip_nodes:
                    # Reuse collect_one_host's error vocabulary; persist on the
                    # node so the marker survives into the graph (the node stays,
                    # just gets no SMB edges).
                    node.properties["smb_gate"] = "445 closed/filtered"
                    offline_nodes.append(node)
        offline_count = len(offline_nodes)
        if duplicate_dns_skipped:
            print_info_debug(
                f"[host-collector] skipped {duplicate_dns_skipped} duplicate-DNS "
                "ghost node(s); collected the live host per shared IP"
            )

        # Premium operator line, in host-node units with the FINAL elapsed (incl.
        # the VPN-loss re-probe). Reuses the shared summary vocabulary; the IP
        # dedup detail is kept to the debug line below so the operator sees one
        # consistent unit (hosts). reachable + offline always reconcile.
        print_reachability_summary(
            ReachabilityFilterResult(
                port=_GATE_PORT,
                reachable=tuple(str(id(n)) for n in reachable_nodes),
                offline=tuple(str(id(n)) for n in offline_nodes),
                elapsed_ms=gate_probe_ms,
                raw_results={},
            ),
            service_label="SMB",
        )

        # A5 -- per-collector timing telemetry (structured + debug). All counts
        # are host-node units; the unique-IP count is surfaced as an explicit,
        # labeled detail so the numbers always reconcile (reachable + offline =
        # total hosts), and timeouts-avoided is one skipped SMB attempt per
        # offline host (not per IP).
        timing.gate_probe_ms = gate_probe_ms
        timing.candidate_count = len(candidate_ips)
        timing.reachable_445_count = len(reachable_nodes)
        timing.timeouts_avoided_estimate = offline_count * config.per_host_timeout
        avoided_min = timing.timeouts_avoided_estimate / 60.0
        total_hosts = len(reachable_nodes) + offline_count
        no_ip_note = (
            f"; {no_ip_count} unresolved (no IP), skipped" if no_ip_count else ""
        )
        print_info_debug(
            f"collector-timing gate: {len(reachable_nodes)}/{total_hosts} hosts "
            f"reachable on {_GATE_PORT}/tcp in {gate_probe_ms / 1000:.1f}s "
            f"({offline_count} offline, skipped; "
            f"~{avoided_min:.0f}min of SMB timeouts avoided; "
            f"deduped to {len(candidate_ips)} unique IPs probed{no_ip_note})"
        )
        return reachable_nodes
    except Exception as exc:  # noqa: BLE001 -- FAIL-OPEN: never reduce coverage
        telemetry.capture_exception(exc)
        print_info_debug(
            f"collector-timing gate failed open ({type(exc).__name__}: {exc}); "
            "collecting all hosts (no coverage loss)"
        )
        return nodes


def _build_smb_progress_dashboard(timing: HostPhaseTiming) -> ProgressDashboard:
    """Construct the SMB-collection progress dashboard.

    ``total`` is the gate's reachable-445 count (the X/N denominator). The
    last-item line masks the host via the ``"hostname"`` data_type so the
    telemetry mirror never leaks an unmasked host.
    """
    return ProgressDashboard(
        ProgressDashboardConfig(
            title="SMB Collection",
            total=timing.reachable_445_count,
            unit="hosts",
            last_item_type="hostname",
        )
    )


async def _collect_domain_hosts_async(
    result: CollectionResult,
    config: HostCollectorConfig,
) -> HostPhaseTiming:
    from adscan_internal.services.collector.smb_collector import (
        resolve_target_hostname,
        resolve_target_ip,
    )

    timing = HostPhaseTiming()
    computers = [n for n in result.nodes.values() if is_collectable_computer_host(n)]
    timing.disabled_skipped = sum(
        1 for n in result.nodes.values() if is_disabled_computer_account(n)
    )
    if timing.disabled_skipped:
        print_info_debug(
            f"[host-collector] skipped {timing.disabled_skipped} disabled "
            "computer accounts"
        )
    if not computers:
        return timing

    # 445/tcp reachability gate (Component A). FAIL-OPEN inside the helper:
    # a gate bug returns the full host list so coverage never drops.
    dispatch_nodes = await _gate_reachable_445(
        computers, config, timing, resolve_target_ip
    )

    # Upfront patience notice — threshold-gated on the reachable count. Silent
    # for small estates; a single line under non-interactive (`adscan ci`).
    maybe_show_patience_notice(
        PatienceNoticeConfig(
            operation="SMB collection",
            unit="hosts",
            threshold=200,
            env_var="ADSCAN_PATIENCE_THRESHOLD_SMB_COLLECTION",
        ),
        count=timing.reachable_445_count or len(dispatch_nodes),
        non_interactive=is_non_interactive(),
    )

    sid_to_node = _build_sid_to_node(result)

    # Build the MemberOf group closure once before fan-out — used by the NTFS
    # effective-access verification to expand each principal's group set.
    group_closure = _build_member_of_closure(result)

    # Build SAM-account lookup once before fan-out — O(1) per session in _merge_host_into_graph
    samaccount_to_node: dict[str, Any] = {}
    for n in result.nodes.values():
        if n.kind not in ("User", "Computer"):
            continue
        sam = str(getattr(n, "samaccountname", "") or "").strip().lower()
        if sam:
            samaccount_to_node[sam] = n

    sem = asyncio.Semaphore(config.concurrency)

    totals = {"session": 0, "admin": 0, "share": 0}
    sd_source_counts: dict[str, int] = {}

    # Live progress dashboard (headline UX). ``total`` = reachable-445 count.
    # ``LiveSession`` falls back to inline logging on non-TTY/CI and under
    # ``ADSCAN_NO_LIVE=1`` automatically — no branch here. Presentation-only:
    # the dashboard NEVER gates ``add_edge`` (graph topology is unchanged), and
    # any error inside ``update()`` is swallowed so the fan-out always finishes.
    dashboard = _build_smb_progress_dashboard(timing)
    progress = {"done": 0, "ok": 0, "err": 0, "inflight": 0}

    def _safe_update(**kwargs: Any) -> None:
        # Fail-open: a dashboard render glitch must never abort collection.
        try:
            dashboard.update(**kwargs)
        except Exception as exc:  # noqa: BLE001 — presentation must never break the fan-out
            telemetry.capture_exception(exc)

    async def _run(node: Any) -> None:
        had_error = False
        n_s = n_a = n_sh = 0
        target_ip = resolve_target_ip(node)
        if not target_ip:
            return
        target_hostname = resolve_target_hostname(node)
        progress["inflight"] += 1
        _safe_update(in_flight=progress["inflight"])
        host_data = HostCollectionResult()
        host_t0 = 0.0
        try:
            async with sem:
                # Start the per-host clock AFTER acquiring the slot, so the
                # measured duration is the actual collection WORK, not the time
                # spent queueing for a free worker.
                host_t0 = time.monotonic()
                try:
                    # SAFETY NET: hard wall-clock ceiling for the whole host. Every
                    # per-op step is already wait_for-bounded EXCEPT the authed
                    # connect (soft transport timeout), so this guarantees a hung
                    # host can never hold a worker slot indefinitely. The budget is
                    # generous (well above the intended per-op sum) → it never cuts
                    # a host that behaves; it only kills genuine hangs.
                    host_data = await asyncio.wait_for(
                        collect_one_host(target_ip, target_hostname, config, timing),
                        timeout=config.per_host_budget,
                    )
                except asyncio.TimeoutError:
                    host_data = HostCollectionResult()
                    host_data.errors["host_budget"] = (
                        f"exceeded {config.per_host_budget}s total budget"
                    )
                    timing.host_budget_timeouts += 1
            n_s, n_a, n_sh, src_counts = _merge_host_into_graph(
                node, host_data, sid_to_node, samaccount_to_node, result, group_closure
            )
            # Safe under asyncio: no await between the merge above and these updates,
            # so cooperative scheduling guarantees no preemption inside the read-modify-write.
            totals["session"] += n_s
            totals["admin"] += n_a
            totals["share"] += n_sh
            for k, v in src_counts.items():
                sd_source_counts[k] = sd_source_counts.get(k, 0) + v
        finally:
            progress["inflight"] -= 1
            # Per-host MEASUREMENT (observability). RMW is safe: no await between
            # here and the dashboard update below. host_t0 stays 0.0 if the slot
            # was never acquired (cancelled while queueing) — skip those so the
            # distribution only reflects hosts we actually worked.
            if host_t0:
                timing.per_host_durations.append(time.monotonic() - host_t0)
            _errors = host_data.errors
            _outcome = _classify_host_outcome(_errors)
            timing.outcome_counts[_outcome] = timing.outcome_counts.get(_outcome, 0) + 1
            # Dashboard ✓/⚠: a host is only a FAILURE for hard problems — an
            # expected no-local-admin denial (or a clean collect) is success.
            # This keeps denied-but-collected hosts (shares/admins gathered) as ✓
            # instead of flipping to ⚠ now that denials are recorded.
            had_error = _outcome not in _NON_FAILURE_OUTCOMES
            # Per-stage outcomes, ONLY for hosts we reached with a live connection
            # (connect/auth/budget failures never attempted the stages and are
            # already in outcome_counts). For those hosts, the absence of a stage
            # key means that stage succeeded.
            _conn_failed = bool(
                {"auth", "connect", "host_budget"} & set(_errors)
            )
            if not _conn_failed:
                _stage_keys = []
                if config.collect_samr:
                    _stage_keys += [("sessions", "sessions"), ("localadmins", "builtin_groups")]
                if config.collect_shares:
                    _stage_keys += [("shares", "shares")]
                for _stage, _err_key in _stage_keys:
                    _o = _classify_stage_error(_errors.get(_err_key))
                    _bucket = timing.stage_outcomes[_stage]
                    _bucket[_o] = _bucket.get(_o, 0) + 1
        progress["done"] += 1
        if progress["done"] % _HOST_PROGRESS_TICK == 0:
            # live_tasks is the leak gauge: if it climbs monotonically with hosts
            # processed (rather than staying ~flat at ~concurrency), per-host
            # internal tasks are leaking — the signature of the aiosmb teardown
            # bug fixed in vendor/aiosmb (disconnect cancels before the close).
            try:
                live_tasks = len(asyncio.all_tasks())
            except RuntimeError:
                live_tasks = -1
            print_info_debug(
                f"collector-timing progress: {progress['done']}/{len(dispatch_nodes)} "
                f"hosts · p95={_percentile(timing.per_host_durations, 95):.1f}s · "
                f"budget_timeouts={timing.host_budget_timeouts} · "
                f"live_tasks={live_tasks}"
            )
        if had_error:
            progress["err"] += 1
        else:
            progress["ok"] += 1
        last_label = target_hostname or target_ip
        detail = f"shares {n_sh} · sessions {n_s} · admins {n_a}"
        _safe_update(
            done=progress["done"],
            success=progress["ok"],
            error=progress["err"],
            in_flight=progress["inflight"],
            last=last_label,
            last_detail=detail,
        )

    results: list = []
    async with dashboard.async_live_session():
        tasks = [asyncio.create_task(_run(node)) for node in dispatch_nodes]
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, Exception):
            telemetry.capture_exception(r)
            print_info_debug(f"[host-collector] task raised: {type(r).__name__}: {r}")

    # Measured per-host duration distribution + outcome histogram (the data that
    # tells us where the SMB-collection time actually went).
    _log_host_phase_stats(timing, len(dispatch_nodes))

    relation_counts = Counter(e.relation for e in result.edges)
    signing_required = sum(
        1 for n in computers if n.properties.get("smb_signing_required")
    )
    print_info_verbose(
        f"[host-collector] HasSession={relation_counts['HasSession']} "
        f"AdminTo={relation_counts['AdminTo']} CanRDP={relation_counts['CanRDP']} "
        f"CanPSRemote={relation_counts['CanPSRemote']} "
        f"signing_required={signing_required}/{len(computers)}"
    )
    read_e = relation_counts["ReadShare"]
    write_e = relation_counts["WriteShare"]
    full_e = relation_counts["FullControlShare"]
    src_summary = (
        ", ".join(f"{k}={v}" for k, v in sorted(sd_source_counts.items())) or "none"
    )
    # Verification-tier breakdown across all share-access edges (TAG, not DROP —
    # counts confirm topology is unchanged; only metadata differs).
    verification_counts = Counter(
        str((e.notes or {}).get("verification") or VERIFICATION_SHARE_ACL_ONLY)
        for e in result.edges
        if e.relation in ("ReadShare", "WriteShare", "FullControlShare")
    )
    verif_summary = (
        ", ".join(f"{k}={v}" for k, v in sorted(verification_counts.items())) or "none"
    )
    print_info_verbose(
        f"[host-collector] shares={sum(len(n.properties.get('smb_shares', [])) for n in computers)} "
        f"edges={totals['share']} (Read={read_e} Write={write_e} FullControl={full_e}) "
        f"sd_sources=({src_summary}) verification=({verif_summary})"
    )
    return timing


def collect_domain_hosts(
    result: CollectionResult,
    config: HostCollectorConfig,
) -> HostPhaseTiming:
    """Synchronous entry point.

    Creates a fresh event loop in a worker thread (matches the legacy SMB/Share
    collectors' pattern so the orchestrator can keep being synchronous).
    """
    timing_holder: dict[str, HostPhaseTiming] = {}

    def _run_in_thread() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            timing_holder["t"] = loop.run_until_complete(
                _collect_domain_hosts_async(result, config)
            )
        finally:
            loop.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        fut = pool.submit(_run_in_thread)
        fut.result()

    return timing_holder.get("t", HostPhaseTiming())
