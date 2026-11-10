"""Consumer registry: every component that sends traffic to the client, and its knobs.

Each :class:`ConsumerSpec` names one component (the SMB host collector, the
WinRM access sweep, the Windows connect scan, ...), lists the parameters that
govern how hard it works the network, records the value each parameter has
TODAY (``default``) and, where a deprecated environment variable can change it,
that variable and its exact current parse rule.

Two properties this table must keep, both locked by
``tests/unit/core/test_scan_pacing_normal_identity.py``:

* At the ``normal`` level with no overrides, every parameter resolves to exactly
  the value the component computes today, for every value of its legacy env var
  (unset, valid, zero, negative, garbage, huge).
* A parameter's ``role`` decides which knob moves it at the other levels. The
  role never changes ``normal``.

The ``location`` strings point at the code that owns the value today, so the
WP2 migration can find every call site, and the structural no-direct-env test
can list the modules it guards.

Out of scope on purpose (local CPU, not client traffic): attack-path workers,
cracking, artifact analysis threads, the local-reuse graph topology. Also out of
scope: ``fetch_samr_user_details_via``'s ``max_concurrency=8``, which is
serialised by the DCE-RPC channel's request lock and so is not real parallelism.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Mapping, Optional

from adscan_core.scan_pacing.pacing_levels import PacingLevel

# ---------------------------------------------------------------------------
# Legacy env parse rules. Each returns the parsed value, or None meaning "fall
# back to the default", reproducing the CURRENT reader exactly.
# ---------------------------------------------------------------------------

ParseRule = Callable[[Optional[str]], Any]


def parse_positive_int(raw: Optional[str]) -> Optional[int]:
    """``int(raw)`` when it is > 0, else fallback.

    Matches ``host_collector._env_int``, ``mssql_collector._env_int``,
    ``ntlm_capture._read_int_env`` and ``network_probe_service._env_int`` with
    ``minimum=1``: an empty value, a non-integer, zero and negatives all fall
    back. Python's ``int`` already tolerates surrounding whitespace.
    """
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError:
        return None
    return value if value > 0 else None


def make_clamped_int(low: int, high: int) -> ParseRule:
    """``max(low, min(int(raw), high))``; an empty or non-integer value falls back.

    Matches the access-probe worker readers (1..128) and the native dump
    concurrency reader (1..64).
    """

    def _rule(raw: Optional[str]) -> Optional[int]:
        token = (raw or "").strip()
        if not token:
            return None
        try:
            return max(low, min(int(token), high))
        except ValueError:
            return None

    _rule.__name__ = f"clamped_int_{low}_{high}"
    return _rule


def make_floor_int(low: int) -> ParseRule:
    """``max(int(raw), low)``; an empty or non-integer value falls back.

    Matches ``dns_resolver._resolve_concurrency`` (low=1, no upper bound).
    """

    def _rule(raw: Optional[str]) -> Optional[int]:
        if not raw:
            return None
        try:
            value = int(raw)
        except ValueError:
            return None
        return max(value, low)

    _rule.__name__ = f"floor_int_{low}"
    return _rule


def make_float_at_least(floor: float) -> ParseRule:
    """``float(raw)`` when it is >= ``floor``, else fallback.

    Matches ``host_collector._env_float`` for the 445 gate timeout.
    """

    def _rule(raw: Optional[str]) -> Optional[float]:
        if not raw:
            return None
        try:
            value = float(raw)
        except ValueError:
            return None
        return value if value >= floor else None

    _rule.__name__ = f"float_at_least_{floor}"
    return _rule


def parse_enum_timeout_override(raw: Optional[str]) -> Optional[int]:
    """``max(1, int(raw))`` when set; anything unparsable falls back (adaptive).

    Matches the override branch of ``host_collector._adaptive_enum_timeout``.
    """
    if not raw:
        return None
    try:
        return max(1, int(raw))
    except (TypeError, ValueError):
        return None


_OFF_TOKENS = frozenset({"0", "false", "no", "off"})


def parse_enum_adaptive(raw: Optional[str]) -> Optional[bool]:
    """``False`` when the value is an off token, else fallback (adaptive on).

    Matches ``host_collector._adaptive_enum_timeout``, which reads the var with
    a default of ``"1"`` and disables adaptation only for an off token.
    """
    if raw is None:
        return None
    return False if raw.strip().lower() in _OFF_TOKENS else None


_NMAP_MAX_RETRIES_CEILING = 10


def parse_nmap_max_retries(raw: Optional[str]) -> Optional[int]:
    """Positive int capped at 10, else fallback. Matches ``_nmap_timing_flags``."""
    value = parse_positive_int(raw)
    if value is None:
        return None
    return min(value, _NMAP_MAX_RETRIES_CEILING)


NMAP_HOST_TIMEOUT_RE = re.compile(r"^\d+(?:\.\d+)?[smh]?$")
NMAP_TIMING_TEMPLATE_RE = re.compile(r"^-T[0-5]$")


def parse_nmap_host_timeout(raw: Optional[str]) -> Optional[str]:
    """nmap ``<num>[smh]`` after strip, else fallback. Matches ``_nmap_timing_flags``."""
    token = (raw or "").strip()
    if not token or not NMAP_HOST_TIMEOUT_RE.match(token):
        return None
    return token


def parse_nmap_timing(raw: Optional[str]) -> Optional[str]:
    """``-T0``..``-T5`` after strip, else nothing. Matches ``_nmap_timing_flags``."""
    token = (raw or "").strip()
    if token and NMAP_TIMING_TEMPLATE_RE.match(token):
        return token
    return None


# ---------------------------------------------------------------------------
# Registry model
# ---------------------------------------------------------------------------


class ParamRole(str, Enum):
    """How a parameter responds to levels and knobs (never at ``normal``)."""

    HOST_FANOUT = "host_fanout"  # knob max_parallel_hosts
    PROBE_FANOUT = "probe_fanout"  # knob max_parallel_probes
    PER_HOST_IN_FLIGHT = "per_host_in_flight"  # knob max_in_flight_per_host
    RESOLVER_IN_FLIGHT = "resolver_in_flight"  # DNS: 4 x max_parallel_probes below normal
    TIMEOUT = "timeout"  # x timeout_multiplier
    BUDGET = "budget"  # x timeout_multiplier (wall budgets, never truncate a slow level)
    RATE = "rate"  # knob max_requests_per_second, lower of the two
    BANDWIDTH = "bandwidth"  # knob share_bandwidth_mibps
    DELAY = "delay"  # knob per_host_delay_ms, higher of the two
    PAGE_SIZE = "page_size"  # knob ldap_page_size
    RETRIES = "retries"  # knob max_retries
    PORT_SCAN_HOST_TIMEOUT = "port_scan_host_timeout"  # knob port_scan.host_timeout_minutes
    PORT_RATE = "port_rate"  # knob port_scan.max_rate_pps
    PORT_HOSTGROUP = "port_hostgroup"  # knob port_scan.max_hostgroup
    PORT_SCAN_DELAY = "port_scan_delay"  # knob port_scan.scan_delay_ms
    #: Probe budget of a statistical check (how many tries before "not vulnerable").
    #: No knob moves it; only the parameter's own ``level_values`` do, and a
    #: smaller budget lowers the confidence of a negative result, which the
    #: assessment-pace disclosure states (``detection_per_attempt``).
    ATTEMPTS = "attempts"
    FIXED = "fixed"  # no knob moves it (legacy env only)


class OverrideMode(str, Enum):
    """How an explicit knob override applies to a fan-out parameter."""

    REPLACE = "replace"  # the override is the value
    CAP = "cap"  # the override can only lower the component's own value


@dataclass(frozen=True)
class LegacyEnv:
    """A deprecated env var that still changes one parameter, and its parse rule."""

    name: str
    rule: ParseRule


@dataclass(frozen=True)
class ParamSpec:
    """One pacing parameter of one component.

    ``level_values`` is the component's OWN value at a level other than
    ``normal``, for a component whose safe pace differs from what the scan-wide
    knob gives it (one Zerologon probe loop against one domain controller is not
    the whole network's request budget). The resolver applies the slower of it
    and the knob-derived value, so it can only slow the component down; an
    override can lower it further, never raise it. ``normal`` is never listed:
    the identity lock (``normal`` = today's value) holds by construction.

    ``detection_per_attempt``, ``client_label`` and ``client_target`` describe an
    ``ATTEMPTS`` parameter for the disclosure: the probability that one attempt
    reveals the condition (so a reduced budget can be stated as the chance a
    negative result is wrong), the client name of the check, and what one budget
    is spent on.
    """

    name: str
    default: Any
    role: ParamRole
    unit: str
    legacy_env: LegacyEnv | None = None
    override_mode: OverrideMode = OverrideMode.REPLACE
    level_values: Mapping[PacingLevel, Any] = field(default_factory=dict)
    detection_per_attempt: float | None = None
    client_label: str = ""
    #: What one budget is spent on, in client words ("domain controller").
    client_target: str = "host"

    def __post_init__(self) -> None:
        if PacingLevel.NORMAL in self.level_values:
            raise ValueError(
                f"{self.name}: level_values must not set the normal level "
                "(normal is today's value, locked by the identity test)"
            )
        object.__setattr__(self, "level_values", MappingProxyType(dict(self.level_values)))
        if self.role is ParamRole.ATTEMPTS and not (
            self.detection_per_attempt and 0.0 < self.detection_per_attempt < 1.0
        ):
            raise ValueError(f"{self.name}: an ATTEMPTS parameter needs detection_per_attempt in (0, 1)")

    def miss_probability(self, attempts: Any) -> float | None:
        """Chance that ``attempts`` tries all miss a present condition (``ATTEMPTS`` only)."""
        if self.detection_per_attempt is None:
            return None
        try:
            count = max(0, int(attempts))
        except (TypeError, ValueError):
            return None
        return (1.0 - self.detection_per_attempt) ** count


@dataclass(frozen=True)
class ConsumerSpec:
    """One component that sends traffic to the client."""

    consumer_id: str
    description: str
    location: str
    params: tuple[ParamSpec, ...]

    def param(self, name: str) -> ParamSpec:
        """Return the named parameter; raises ``KeyError`` when absent."""
        for spec in self.params:
            if spec.name == name:
                return spec
        raise KeyError(f"{self.consumer_id} has no pacing parameter {name!r}")


_POSITIVE = parse_positive_int
_CLAMP_1_128 = make_clamped_int(1, 128)
_CLAMP_1_64 = make_clamped_int(1, 64)


def _env(name: str, rule: ParseRule) -> LegacyEnv:
    return LegacyEnv(name=name, rule=rule)


P = ParamSpec
R = ParamRole

CONSUMERS: tuple[ConsumerSpec, ...] = (
    # -- Port scanning -------------------------------------------------------
    ConsumerSpec(
        "portscan.nmap",
        "Linux nmap scans (important ports, DC discovery, single-host reachability).",
        "adscan_internal/cli/nmap.py:95-138 _nmap_timing_flags; :75 whole-scan timeout",
        (
            P("max_retries", 3, R.RETRIES, "retries", _env("ADSCAN_PORTSCAN_NMAP_MAX_RETRIES", parse_nmap_max_retries)),
            P("host_timeout", "15m", R.PORT_SCAN_HOST_TIMEOUT, "nmap time", _env("ADSCAN_PORTSCAN_NMAP_HOST_TIMEOUT", parse_nmap_host_timeout)),
            P("timing_template", None, R.FIXED, "nmap -T", _env("ADSCAN_PORTSCAN_NMAP_TIMING", parse_nmap_timing)),
            P("whole_scan_timeout_s", 7200, R.BUDGET, "s"),
            P("max_rate_pps", None, R.PORT_RATE, "packets/s"),
            P("max_hostgroup", None, R.PORT_HOSTGROUP, "hosts"),
            P("max_parallelism", None, R.PROBE_FANOUT, "probes"),
            P("scan_delay_ms", 0, R.PORT_SCAN_DELAY, "ms"),
        ),
    ),
    ConsumerSpec(
        "portscan.windows_connect",
        "Windows in-process TCP connect scan (replaces nmap on Windows).",
        "adscan_internal/services/network_probe_service.py:267-307 ScanPacing.safe()",
        (
            P("concurrency", 64, R.PROBE_FANOUT, "connections", _env("ADSCAN_PORTSCAN_CONCURRENCY", _POSITIVE)),
            P("per_host", 8, R.PER_HOST_IN_FLIGHT, "connections", _env("ADSCAN_PORTSCAN_PER_HOST", _POSITIVE)),
            P("timeout_s", 2.0, R.TIMEOUT, "s"),
            P("backoff_floor", 8, R.FIXED, "connections"),
            P("backoff_timeout_rate", 0.55, R.FIXED, "fraction"),
            P("backoff_window", 200, R.FIXED, "attempts"),
        ),
    ),
    # -- Light reachability probes -------------------------------------------
    ConsumerSpec(
        "probe.tcp_probe_hosts",
        "Shared one-port reachability probe (tcp_probe_hosts / filter_reachable_hosts).",
        "adscan_internal/services/network_probe_service.py:200-206; host_reachability_filter.py:67-72",
        (
            P("max_concurrency", 50, R.PROBE_FANOUT, "connections"),
            P("timeout_s", 3.0, R.TIMEOUT, "s"),
        ),
    ),
    ConsumerSpec(
        "probe.smb_access_gate",
        "445 liveness gate in front of the SMB access sweep, scaled with the host count.",
        "adscan_internal/services/smb_access_probe_service.py:204",
        (
            P("min_concurrency", 50, R.PROBE_FANOUT, "connections"),
            P("max_concurrency", 256, R.PROBE_FANOUT, "connections"),
        ),
    ),
    ConsumerSpec(
        "probe.cve_preflight",
        "Reachability preflight before CVE checks.",
        "adscan_internal/services/cve_scanner/runner.py:38-39",
        (
            P("concurrency", 64, R.PROBE_FANOUT, "connections"),
            P("timeout_s", 3.0, R.TIMEOUT, "s"),
        ),
    ),
    ConsumerSpec(
        "probe.smb_negotiate",
        "Unauthenticated SMB negotiate sweeps (SMBv1 and signing posture).",
        "adscan_internal/cli/smb.py:2124 _probe_smbv1_hosts; :3558 signing sweep",
        (
            P("concurrency", 64, R.PROBE_FANOUT, "connections"),
            P("timeout_s", 10.0, R.TIMEOUT, "s"),
        ),
    ),
    # -- DNS -------------------------------------------------------------------
    ConsumerSpec(
        "dns.resolve",
        (
            "Resolution of computer names against the domain's resolver. In flight "
            "was 1000 until 2026-11-04; GOAD measurement (3,800 to 4,300 queries, "
            "500 of them names that take about 4 s to fail): 500 in flight resolved "
            "everything in the same wall time as 1000 (4.4 s against 4.7 s) and cut "
            "a second client's p95 latency during the burst from about 36 ms to "
            "about 25 ms; 250 cost 1.9x the wall time and 100 cost 4.4x."
        ),
        "adscan_internal/services/collector/dns_resolver.py:74-110",
        (
            P("in_flight", 500, R.RESOLVER_IN_FLIGHT, "queries", _env("ADSCAN_DNS_RESOLVE_CONCURRENCY", make_floor_int(1))),
            P("attempt_timeout_s", 2.0, R.TIMEOUT, "s"),
            P("lifetime_s", 6.0, R.TIMEOUT, "s"),
        ),
    ),
    # -- Directory --------------------------------------------------------------
    ConsumerSpec(
        "ldap.paged_search",
        "LDAP paged searches against the domain controller.",
        "adscan_internal/services/ldap_transport_service.py:224; collector/ldap_scope.py:47",
        (
            P("page_size", 1000, R.PAGE_SIZE, "objects"),
            P("page_delay_s", 0.0, R.DELAY, "s"),
        ),
    ),
    ConsumerSpec(
        "kdc.spray",
        "Native password spray (AS-REQs to the KDC). Lockout rules are not pacing.",
        "adscan_internal/cli/spraying.py:8235",
        (
            P("in_flight", 5, R.PER_HOST_IN_FLIGHT, "requests"),
            P("rate_per_s", None, R.RATE, "requests/s"),
        ),
    ),
    ConsumerSpec(
        "kdc.blank_spray",
        "Blank-password check (one AS-REQ per eligible user).",
        "adscan_internal/cli/spraying.py:1260",
        (
            P("in_flight", 16, R.PER_HOST_IN_FLIGHT, "requests"),
            P("rate_per_s", None, R.RATE, "requests/s"),
        ),
    ),
    ConsumerSpec(
        "kdc.timeroast",
        "Timeroasting NTP queries to the domain controller.",
        "adscan_internal/cli/timeroast.py:739-744; services/timeroasting/config.py:20-21",
        (
            P("rate_pps", 180, R.RATE, "packets/s"),
            P("timeout_s", 24.0, R.TIMEOUT, "s"),
        ),
    ),
    # -- Host collection ---------------------------------------------------------
    ConsumerSpec(
        "collector.smb_hosts",
        "SMB host collector (sessions, local groups, shares, registry) and its 445 gate.",
        "adscan_internal/services/collector/host_collector.py:90-131, 460-463, 507-551, 1452",
        (
            P("concurrency", 20, R.HOST_FANOUT, "hosts", _env("ADSCAN_COLLECTOR_HOST_CONCURRENCY", _POSITIVE)),
            P("per_host_timeout_s", 20, R.TIMEOUT, "s", _env("ADSCAN_COLLECTOR_PER_HOST_TIMEOUT", _POSITIVE)),
            P("connect_timeout_s", 10, R.TIMEOUT, "s", _env("ADSCAN_COLLECTOR_CONNECT_TIMEOUT", _POSITIVE)),
            P("per_host_budget_s", 180, R.BUDGET, "s", _env("ADSCAN_COLLECTOR_PER_HOST_BUDGET", _POSITIVE)),
            P("teardown_timeout_s", 10, R.TIMEOUT, "s", _env("ADSCAN_COLLECTOR_TEARDOWN_TIMEOUT", _POSITIVE)),
            P("gate_concurrency", 256, R.PROBE_FANOUT, "connections", _env("ADSCAN_COLLECTOR_GATE_CONCURRENCY", _POSITIVE)),
            P("gate_timeout_s", 5.0, R.TIMEOUT, "s", _env("ADSCAN_COLLECTOR_GATE_TIMEOUT", make_float_at_least(0.5))),
            P("enum_timeout_override_s", None, R.FIXED, "s", _env("ADSCAN_COLLECTOR_ENUM_TIMEOUT", parse_enum_timeout_override)),
            P("enum_adaptive", True, R.FIXED, "", _env("ADSCAN_COLLECTOR_ENUM_ADAPTIVE", parse_enum_adaptive)),
        ),
    ),
    ConsumerSpec(
        "collector.mssql",
        "MSSQL collector (instance enumeration).",
        "adscan_internal/services/collector/mssql_collector.py:60-78, 136-153",
        (
            P("concurrency", 8, R.HOST_FANOUT, "instances", _env("ADSCAN_MSSQL_COLLECTOR_CONCURRENCY", _POSITIVE)),
            P("per_instance_timeout_s", 30, R.TIMEOUT, "s", _env("ADSCAN_MSSQL_COLLECTOR_TIMEOUT", _POSITIVE)),
            P("instance_wall_budget_s", 120, R.BUDGET, "s", _env("ADSCAN_MSSQL_COLLECTOR_WALL_BUDGET", _POSITIVE)),
        ),
    ),
    # -- Access sweeps -------------------------------------------------------------
    ConsumerSpec(
        "sweep.smb_access",
        "SMB access sweep (who can reach which host).",
        "adscan_internal/services/smb_access_probe_service.py:42-53, 140",
        (
            P("workers", 30, R.HOST_FANOUT, "hosts", _env("ADSCAN_SMB_PROBE_WORKERS", _CLAMP_1_128)),
            P("timeout_s", 15, R.TIMEOUT, "s"),
        ),
    ),
    ConsumerSpec(
        "sweep.winrm_access",
        "WinRM access sweep.",
        "adscan_internal/services/winrm_access_probe_service.py:38, 546-554",
        (P("workers", 32, R.HOST_FANOUT, "hosts", _env("ADSCAN_WINRM_PROBE_WORKERS", _CLAMP_1_128)),),
    ),
    ConsumerSpec(
        "sweep.mssql_access",
        "MSSQL access sweep.",
        "adscan_internal/services/mssql_access_probe_service.py:35, 54-62, 202",
        (
            P("workers", 30, R.HOST_FANOUT, "hosts", _env("ADSCAN_MSSQL_PROBE_WORKERS", _CLAMP_1_128)),
            P("timeout_s", 30, R.TIMEOUT, "s"),
        ),
    ),
    ConsumerSpec(
        "sweep.rdp_access",
        "RDP access sweep. Workers are min(max_workers, max(min_workers, host count)).",
        "adscan_internal/cli/rdp.py:436; services/rdp_login_service.py:444-445",
        (
            P("max_workers", 10, R.HOST_FANOUT, "hosts"),
            P("min_workers", 3, R.FIXED, "hosts"),
            P("connect_timeout_s", 10.0, R.TIMEOUT, "s"),
        ),
    ),
    ConsumerSpec(
        "sweep.smb_privilege",
        "SMB privilege batches (admin checks before dumps, privilege matrix).",
        "adscan_internal/services/smb_privilege.py:274; smb_privilege_display.py:98",
        (P("max_concurrency", 10, R.HOST_FANOUT, "hosts"),),
    ),
    ConsumerSpec(
        "sweep.gpp",
        "Group Policy Preferences harvest across targets.",
        "adscan_internal/services/gpp_credential_harvester.py:511",
        (P("max_concurrent", 4, R.HOST_FANOUT, "hosts"),),
    ),
    # -- Heavier operations ----------------------------------------------------------
    ConsumerSpec(
        "dump.native",
        "Credential dumps. LSASS stays low by design, so an override can only lower it.",
        "adscan_internal/cli/dumps.py:1034-1052",
        (
            P("sam_lsa_concurrency", 20, R.HOST_FANOUT, "hosts", _env("ADSCAN_NATIVE_DUMP_CONCURRENCY", _CLAMP_1_64)),
            P("lsass_concurrency", 5, R.HOST_FANOUT, "hosts", _env("ADSCAN_LSASS_DUMP_CONCURRENCY", _CLAMP_1_64), OverrideMode.CAP),
            P("other_concurrency", 15, R.HOST_FANOUT, "hosts", _env("ADSCAN_NATIVE_DUMP_CONCURRENCY", _CLAMP_1_64)),
        ),
    ),
    ConsumerSpec(
        "coercion.ntlm_sweep",
        "NTLM authentication-type sweep (coercion triggers to one shared listener).",
        "adscan_internal/cli/ntlm_capture.py:1359-1368, 2384-2387",
        (
            P("concurrency", 8, R.HOST_FANOUT, "hosts", _env("ADSCAN_NTLM_SWEEP_CONCURRENCY", _POSITIVE), OverrideMode.CAP),
            P("budget_s", 1800, R.BUDGET, "s", _env("ADSCAN_NTLM_SWEEP_BUDGET_SECONDS", _POSITIVE)),
            P("capture_timeout_s", 30, R.TIMEOUT, "s"),
            P("trigger_timeout_s", 60, R.TIMEOUT, "s"),
        ),
    ),
    ConsumerSpec(
        "coercion.methods",
        "Pause between coercion methods tried against one host.",
        "adscan_internal/services/coercion/core.py:187, 322; runner.py:44",
        (P("delay_s", 0.05, R.DELAY, "s"),),
    ),
    ConsumerSpec(
        "cve.runner",
        "CVE check scheduler.",
        "adscan_internal/services/cve_scanner/runner.py:134-140; cli/cves_native.py:222",
        (
            P("concurrency", 10, R.HOST_FANOUT, "checks", override_mode=OverrideMode.CAP),
            P("per_host_concurrency", 3, R.PER_HOST_IN_FLIGHT, "checks"),
            P("check_timeout_s", 120.0, R.BUDGET, "s"),
        ),
    ),
    ConsumerSpec(
        "cve.zerologon",
        (
            "Zerologon probe loop against one domain controller. One attempt is a "
            "challenge plus an authentication call. Polite caps the loop at 20 "
            "attempts/s; Fragile also halves the attempt budget, which the "
            "disclosure states as a lower confidence for a negative result. "
            "GOAD measurement 2026-11-04: unpaced, 2000 attempts took 5.3 s at "
            "376 attempts/s over one connection, with no measurable change in a "
            "second client's latency, so normal is unchanged."
        ),
        "adscan_internal/services/cve_scanner/checks/zerologon.py:45-46, 132",
        (
            P(
                "rate_per_s",
                None,
                R.RATE,
                "attempts/s",
                level_values={PacingLevel.POLITE: 20.0},
            ),
            P(
                "max_attempts",
                2000,
                R.ATTEMPTS,
                "attempts",
                level_values={PacingLevel.FRAGILE: 1000},
                # A vulnerable DC accepts the all-zero credential once in 256 tries.
                detection_per_attempt=1 / 256,
                client_label="Zerologon (CVE-2020-1472)",
                client_target="domain controller",
            ),
        ),
    ),
    ConsumerSpec(
        "smb.share_download",
        "Share file downloads (rclone). Unset caps leave rclone's own sizing in place.",
        "adscan_internal/services/rclone_tuning_service.py:50-139; cli/smb.py:5496, 5681",
        (
            P("bandwidth_mibps", None, R.BANDWIDTH, "MiB/s"),
            P("max_target_workers", None, R.HOST_FANOUT, "processes"),
            P("max_streams_per_target", None, R.PER_HOST_IN_FLIGHT, "streams"),
        ),
    ),
)

CONSUMERS_BY_ID: dict[str, ConsumerSpec] = {spec.consumer_id: spec for spec in CONSUMERS}

#: Every deprecated env var the registry honours, in declaration order.
LEGACY_PACING_ENV: tuple[str, ...] = tuple(
    dict.fromkeys(
        param.legacy_env.name
        for consumer in CONSUMERS
        for param in consumer.params
        if param.legacy_env is not None
    )
)


def consumer(consumer_id: str) -> ConsumerSpec:
    """Return the consumer spec; raises ``KeyError`` for an unknown id."""
    return CONSUMERS_BY_ID[consumer_id]


__all__ = [
    "CONSUMERS",
    "CONSUMERS_BY_ID",
    "ConsumerSpec",
    "LEGACY_PACING_ENV",
    "LegacyEnv",
    "NMAP_HOST_TIMEOUT_RE",
    "NMAP_TIMING_TEMPLATE_RE",
    "OverrideMode",
    "ParamRole",
    "ParamSpec",
    "consumer",
    "make_clamped_int",
    "make_float_at_least",
    "make_floor_int",
    "parse_enum_adaptive",
    "parse_enum_timeout_override",
    "parse_nmap_host_timeout",
    "parse_nmap_max_retries",
    "parse_nmap_timing",
    "parse_positive_int",
]
