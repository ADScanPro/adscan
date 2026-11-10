"""The pacing knobs: what an operator may tune, with units, ranges and per-level values.

A knob is the user-facing vocabulary (the web form's Advanced fields, the REPL
``set pacing.<knob>``, the ``adscan ci --pacing-set`` flag). Components never
read knobs directly: :mod:`adscan_core.scan_pacing.pacing_consumers` maps each knob onto
each component's own parameters and the resolver does the arithmetic.

Two sentinels appear in the per-level values:

* :data:`COMPONENT_DEFAULT` means "every component keeps its own tuned value".
  It is what ``normal`` uses for the fan-out knobs, because today the components
  run at different, deliberately chosen concurrencies (the SMB collector at 20,
  the WinRM sweep at 32, LSASS dumps at 5) and one number would change them.
* :data:`COMPONENT_FAST` means "twice the component's own value, up to the
  knob's fast ceiling". Only ``fast`` uses it.

:data:`UNLIMITED` is a legal value for a knob whose ``allow_unlimited`` is set.

Labels and help text are client-facing and pass the ``adscan-writing`` gate.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Union

from adscan_core.scan_pacing.pacing_levels import PacingLevel

COMPONENT_DEFAULT = "component_default"
COMPONENT_FAST = "component_fast"
UNLIMITED = "unlimited"

KnobScalar = Union[int, float, bool, str]


class KnobKind(str, Enum):
    """Value type of a knob."""

    INT = "int"
    FLOAT = "float"
    BOOL = "bool"


class KnobDirection(str, Enum):
    """Which way a knob makes the scan more aggressive.

    The policy ceiling clamps only directional knobs; a ``neutral`` knob changes
    patience or request size, not how hard ADscan works the network, so a
    per-scan value wins even under a policy.
    """

    HIGHER_IS_FASTER = "higher_is_faster"
    HIGHER_IS_SLOWER = "higher_is_slower"
    NEUTRAL = "neutral"


@dataclass(frozen=True)
class KnobSpec:
    """One tunable pacing knob."""

    key: str
    label: str
    help: str
    kind: KnobKind
    unit: str
    minimum: float | None
    maximum: float | None
    direction: KnobDirection
    level_values: dict[PacingLevel, KnobScalar]
    allow_unlimited: bool = False
    group: str = "general"
    #: Upper bound applied to :data:`COMPONENT_FAST` (twice the component value).
    fast_ceiling: int | None = None


def _levels(fragile: KnobScalar, polite: KnobScalar, normal: KnobScalar, fast: KnobScalar) -> dict[PacingLevel, KnobScalar]:
    return {
        PacingLevel.FRAGILE: fragile,
        PacingLevel.POLITE: polite,
        PacingLevel.NORMAL: normal,
        PacingLevel.FAST: fast,
    }


MAX_PARALLEL_HOSTS = "max_parallel_hosts"
MAX_PARALLEL_PROBES = "max_parallel_probes"
MAX_IN_FLIGHT_PER_HOST = "max_in_flight_per_host"
MAX_REQUESTS_PER_SECOND = "max_requests_per_second"
PER_HOST_DELAY_MS = "per_host_delay_ms"
JITTER_PCT = "jitter_pct"
TIMEOUT_MULTIPLIER = "timeout_multiplier"
MAX_RETRIES = "max_retries"
PORT_SCAN_MAX_RATE_PPS = "port_scan.max_rate_pps"
PORT_SCAN_MAX_HOSTGROUP = "port_scan.max_hostgroup"
PORT_SCAN_SCAN_DELAY_MS = "port_scan.scan_delay_ms"
PORT_SCAN_HOST_TIMEOUT_MINUTES = "port_scan.host_timeout_minutes"
LDAP_PAGE_SIZE = "ldap_page_size"
SHARE_BANDWIDTH_MIBPS = "share_bandwidth_mibps"
STRAIN_BACKOFF = "strain_backoff"


PACING_KNOBS: tuple[KnobSpec, ...] = (
    KnobSpec(
        key=MAX_PARALLEL_HOSTS,
        label="Hosts in parallel",
        help=(
            "How many servers ADscan works on at the same time during collection, access "
            "checks, credential extraction and vulnerability checks. Lower it to keep the load "
            "on the network and on the domain controllers low."
        ),
        kind=KnobKind.INT,
        unit="hosts",
        minimum=1,
        maximum=128,
        direction=KnobDirection.HIGHER_IS_FASTER,
        level_values=_levels(4, 8, COMPONENT_DEFAULT, COMPONENT_FAST),
        fast_ceiling=64,
    ),
    KnobSpec(
        key=MAX_PARALLEL_PROBES,
        label="Reachability checks in parallel",
        help=(
            "How many light connection checks run at once, such as testing whether a "
            "server answers on a port. Each check is a single connection attempt with no "
            "login."
        ),
        kind=KnobKind.INT,
        unit="connections",
        minimum=1,
        maximum=1024,
        direction=KnobDirection.HIGHER_IS_FASTER,
        level_values=_levels(16, 64, COMPONENT_DEFAULT, COMPONENT_FAST),
        fast_ceiling=512,
    ),
    KnobSpec(
        key=MAX_IN_FLIGHT_PER_HOST,
        label="Connections per host",
        help=(
            "How many connections ADscan keeps open to one server at the same time. Set it "
            "to 1 so a server only ever handles one ADscan request at a time."
        ),
        kind=KnobKind.INT,
        unit="connections",
        minimum=1,
        maximum=32,
        direction=KnobDirection.HIGHER_IS_FASTER,
        level_values=_levels(1, 2, COMPONENT_DEFAULT, COMPONENT_FAST),
        fast_ceiling=16,
    ),
    KnobSpec(
        key=MAX_REQUESTS_PER_SECOND,
        label="Requests per second",
        help=(
            "The most new connections and requests ADscan starts per second across the "
            "whole network. Unlimited leaves each part of the scan at its own pace."
        ),
        kind=KnobKind.FLOAT,
        unit="requests/s",
        minimum=0.5,
        maximum=5000,
        direction=KnobDirection.HIGHER_IS_FASTER,
        level_values=_levels(10, 50, UNLIMITED, UNLIMITED),
        allow_unlimited=True,
    ),
    KnobSpec(
        key=PER_HOST_DELAY_MS,
        label="Pause between operations on a host",
        help=(
            "How long ADscan waits before starting the next operation on the same server. "
            "A longer pause spreads the work out so the server is never busy with ADscan "
            "for long."
        ),
        kind=KnobKind.INT,
        unit="ms",
        minimum=0,
        maximum=60000,
        direction=KnobDirection.HIGHER_IS_SLOWER,
        level_values=_levels(500, 200, 0, 0),
    ),
    KnobSpec(
        key=JITTER_PCT,
        label="Random variation",
        help=(
            "Adds a random variation of up to this percentage to each pause, so requests "
            "do not arrive at a fixed rhythm."
        ),
        kind=KnobKind.INT,
        unit="%",
        minimum=0,
        maximum=100,
        direction=KnobDirection.NEUTRAL,
        level_values=_levels(30, 20, 0, 0),
    ),
    KnobSpec(
        key=TIMEOUT_MULTIPLIER,
        label="Patience with slow servers",
        help=(
            "Multiplies every connection and response timeout. Raise it on slow links or "
            "busy servers so a server that answers late is waited for instead of being "
            "recorded as unreachable."
        ),
        kind=KnobKind.FLOAT,
        unit="x",
        minimum=0.5,
        maximum=4.0,
        direction=KnobDirection.NEUTRAL,
        level_values=_levels(2.0, 1.5, 1.0, 1.0),
    ),
    KnobSpec(
        key=MAX_RETRIES,
        label="Port scan retries",
        help=(
            "How many times the port scan resends a probe that got no answer. Fewer "
            "retries send less traffic to servers that are switched off."
        ),
        kind=KnobKind.INT,
        unit="retries",
        minimum=0,
        maximum=10,
        direction=KnobDirection.HIGHER_IS_FASTER,
        level_values=_levels(3, 3, 3, 3),
        group="port_scan",
    ),
    KnobSpec(
        key=PORT_SCAN_MAX_RATE_PPS,
        label="Port scan packet rate",
        help=(
            "The most packets per second the port scan sends. Unlimited lets the scanner "
            "adapt its rate to the network on its own."
        ),
        kind=KnobKind.INT,
        unit="packets/s",
        minimum=10,
        maximum=800,
        direction=KnobDirection.HIGHER_IS_FASTER,
        level_values=_levels(50, 300, UNLIMITED, 800),
        allow_unlimited=True,
        group="port_scan",
    ),
    KnobSpec(
        key=PORT_SCAN_MAX_HOSTGROUP,
        label="Port scan hosts per batch",
        help=(
            "The most servers the port scan probes in one batch. Unlimited lets the scanner "
            "choose the batch size."
        ),
        kind=KnobKind.INT,
        unit="hosts",
        minimum=1,
        maximum=1024,
        direction=KnobDirection.HIGHER_IS_FASTER,
        level_values=_levels(8, 32, UNLIMITED, UNLIMITED),
        allow_unlimited=True,
        group="port_scan",
    ),
    KnobSpec(
        key=PORT_SCAN_SCAN_DELAY_MS,
        label="Port scan pause per host",
        help="How long the port scan waits between two probes sent to the same server.",
        kind=KnobKind.INT,
        unit="ms",
        minimum=0,
        maximum=5000,
        direction=KnobDirection.HIGHER_IS_SLOWER,
        level_values=_levels(250, 0, 0, 0),
        group="port_scan",
    ),
    KnobSpec(
        key=PORT_SCAN_HOST_TIMEOUT_MINUTES,
        label="Port scan time per host",
        help=(
            "The longest the port scan spends on one server before moving on. It bounds the "
            "time lost on servers that never answer."
        ),
        kind=KnobKind.INT,
        unit="minutes",
        minimum=5,
        maximum=120,
        direction=KnobDirection.NEUTRAL,
        level_values=_levels(30, 20, 15, 15),
        group="port_scan",
    ),
    KnobSpec(
        key=LDAP_PAGE_SIZE,
        label="Directory objects per page",
        help=(
            "How many directory objects ADscan asks a domain controller for in each page of "
            "results. Smaller pages make each request lighter for the domain controller."
        ),
        kind=KnobKind.INT,
        unit="objects",
        minimum=100,
        maximum=1000,
        direction=KnobDirection.NEUTRAL,
        level_values=_levels(200, 500, 1000, 1000),
        group="directory",
    ),
    KnobSpec(
        key=SHARE_BANDWIDTH_MIBPS,
        label="File download bandwidth",
        help=(
            "The most bandwidth ADscan uses when it downloads files from network shares for "
            "analysis. Set it on links to branch offices or over VPN."
        ),
        kind=KnobKind.FLOAT,
        unit="MiB/s",
        minimum=0.5,
        maximum=1000,
        direction=KnobDirection.HIGHER_IS_FASTER,
        level_values=_levels(2, 10, UNLIMITED, UNLIMITED),
        allow_unlimited=True,
        group="shares",
    ),
    KnobSpec(
        key=STRAIN_BACKOFF,
        label="Slow down when a server struggles",
        help=(
            "ADscan watches for servers that answer more slowly, refuse connections or stop "
            "answering, and slows down on its own. It never speeds up beyond the level you "
            "chose. Every slowdown is listed in the report."
        ),
        kind=KnobKind.BOOL,
        unit="",
        minimum=None,
        maximum=None,
        direction=KnobDirection.HIGHER_IS_SLOWER,
        level_values=_levels(True, True, True, True),
    ),
)

KNOBS_BY_KEY: dict[str, KnobSpec] = {knob.key: knob for knob in PACING_KNOBS}


def knob_level_value(key: str, level: PacingLevel) -> KnobScalar:
    """Return the value a level gives a knob (may be a sentinel)."""
    return KNOBS_BY_KEY[key].level_values[level]


__all__ = [
    "COMPONENT_DEFAULT",
    "COMPONENT_FAST",
    "JITTER_PCT",
    "KNOBS_BY_KEY",
    "KnobDirection",
    "KnobKind",
    "KnobScalar",
    "KnobSpec",
    "LDAP_PAGE_SIZE",
    "MAX_IN_FLIGHT_PER_HOST",
    "MAX_PARALLEL_HOSTS",
    "MAX_PARALLEL_PROBES",
    "MAX_REQUESTS_PER_SECOND",
    "MAX_RETRIES",
    "PACING_KNOBS",
    "PER_HOST_DELAY_MS",
    "PORT_SCAN_HOST_TIMEOUT_MINUTES",
    "PORT_SCAN_MAX_HOSTGROUP",
    "PORT_SCAN_MAX_RATE_PPS",
    "PORT_SCAN_SCAN_DELAY_MS",
    "SHARE_BANDWIDTH_MIBPS",
    "STRAIN_BACKOFF",
    "TIMEOUT_MULTIPLIER",
    "UNLIMITED",
    "knob_level_value",
]
