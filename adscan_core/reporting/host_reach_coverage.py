"""Network-reach coverage: the client-facing statement, derived once.

The identity graph comes from the directory, so it covers every computer object
whatever the network looks like. Everything ADscan learns about a computer
itself (its exposed services, shares, logged-on sessions, local settings,
endpoint defence, host-level attack steps) needs the assessment to reach that
computer over the network. On a segmented estate the scanning host sees only the
segments it is connected or routed to, and the computers elsewhere are silently
absent from every host-level section.

An absent computer reads, to a client, as a computer that was checked and found
clean. Under the Exposure-Validation doctrine that is a **data gap**, in the
same family as ``unsupported`` and the other coverage blocks: the deliverable
states how many enabled computers answered, which network segments produced no
answer at all, and what the client can do to cover them. It never turns the
assessment's own position into a verdict about the client's network (an
unanswered segment is not "well segmented"; ADscan observed its own reach, not
the client's filtering policy).

This module is the SSOT for both halves, mirroring
:mod:`adscan_core.reporting.cracking_coverage` and
:mod:`adscan_core.reporting.host_enrichment_coverage`:

* :func:`build_host_reach_coverage` turns the engine's measurement (the enabled
  computer list plus the per-domain ``network_reachability_report.json``) into
  the block persisted by
  :func:`adscan_core.reporting.technical_report.record_host_reach_coverage`;
* :func:`host_reach_coverage_view` turns that persisted block back into the
  render-ready shape the PRO report, the LITE report and the web platform all
  read; and
* :func:`merge_host_reach_coverage` folds every domain into the one report-wide
  view.

Pure logic: no IO, no console, no network. Safe to import from ``adscan_core``,
the LITE runtime, the PRO report renderer and the web backend alike.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Iterable, Mapping

#: Per-domain key this block is stamped under, in ``technical_report.json``, in
#: the renderer's ``report_data`` and in the web's per-domain stats. One name, so
#: the writer, the PDF, the LITE report and the web cannot drift apart.
HOST_REACH_COVERAGE_KEY = "host_reach_coverage"

#: Reachability-report statuses that mean the address ANSWERED from the
#: assessment's network position. Mirrors the status vocabulary written by the
#: engine's reachability report builder (``cli/nmap.py``).
_RESPONSIVE_STATUSES: frozenset[str] = frozenset(
    {
        "responsive",
        "open_service_observed",
        "host_responded_no_important_ports_open",
        "responded_to_discovery",
    }
)

#: Segment states, worst first.
SEGMENT_UNREACHED = "unreached"
SEGMENT_PARTIAL = "partial"
SEGMENT_REACHED = "reached"

_SEGMENT_STATE_ORDER: dict[str, int] = {
    SEGMENT_UNREACHED: 0,
    SEGMENT_PARTIAL: 1,
    SEGMENT_REACHED: 2,
}

_SEGMENT_STATE_LABELS: dict[str, str] = {
    SEGMENT_UNREACHED: "No computer answered",
    SEGMENT_PARTIAL: "Some computers did not answer",
    SEGMENT_REACHED: "Every computer answered",
}

#: How many segment rows a renderer shows; the rest are counted, never dropped
#: silently.
MAX_SEGMENT_ROWS = 12

#: How many hostnames each persisted segment row keeps as a recognisable sample.
_HOSTNAME_PREVIEW = 5

#: How many silent segments the sentence names before it counts the rest.
_SEGMENTS_NAMED_IN_STATEMENT = 3


def _plural(count: int, singular: str, plural: str) -> str:
    return singular if count == 1 else plural


def _directory_clause(gap: int) -> str:
    """The reminder that directory-derived findings are not undersold."""
    return (
        "Findings drawn from the directory itself, such as accounts, groups, "
        f"permissions and certificate templates, still include {_plural(gap, 'it', 'them')}."
    )


def _normalize_host(value: Any) -> str:
    return str(value or "").strip().rstrip(".").lower()


def segment_for_address(address: Any) -> str:
    """Return the network segment an address belongs to, as a CIDR string.

    IPv4 folds to its ``/24`` and IPv6 to its ``/64``, the granularity the
    engine's reachability report already uses for its prefix hints. An
    unparseable value yields ``""``.
    """
    try:
        parsed = ipaddress.ip_address(str(address or "").strip())
    except ValueError:
        return ""
    prefix = 24 if parsed.version == 4 else 64
    return str(ipaddress.ip_network(f"{parsed}/{prefix}", strict=False))


def ip_entry_is_reached(entry: Any) -> bool:
    """Return whether one address entry of the reachability report answered.

    An address answered when its status is a responsive status, its
    classification starts with ``reachable``, or it exposed at least one open
    port. Anything else (no response, likely offline, unknown) is not reached.
    """
    if not isinstance(entry, Mapping):
        return False
    status = str(entry.get("status") or "").strip().lower()
    if status in _RESPONSIVE_STATUSES:
        return True
    classification = str(entry.get("classification") or "").strip().lower()
    if classification.startswith("reachable"):
        return True
    ports = entry.get("open_ports")
    return isinstance(ports, (list, tuple)) and len(ports) > 0


def _join_names(names: list[str], extra: int) -> str:
    """Join segment names for prose: ``a``, ``a and b``, ``a, b and 2 more``."""
    if extra > 0:
        return f"{', '.join(names)} and {extra:,} more"
    if len(names) <= 1:
        return "".join(names)
    return f"{', '.join(names[:-1])} and {names[-1]}"


def _compose_statement(
    *,
    in_scope: int,
    reached: int,
    not_reached: int,
    not_attempted: int,
    not_measured: int,
    silent_segments: list[str],
    scattered: int,
) -> str:
    """Render the client-facing sentence for one domain or the report-wide fold.

    States what was and was not reached and what the client can do. Never the
    internal reason, never a verdict about the client's network.
    """
    if in_scope <= 0:
        return ""
    computers = _plural(in_scope, "computer", "computers")
    if not_measured >= in_scope:
        whom = (
            "the one enabled computer in the directory was not"
            if in_scope == 1
            else f"none of the {in_scope:,} enabled {computers} in the directory was"
        )
        return (
            f"Network reachability was not measured in this assessment, so {whom} "
            f"assessed over the network. {_directory_clause(in_scope)} Running the "
            "assessment with network discovery enabled will cover "
            f"{_plural(in_scope, 'it', 'them')}."
        )
    gap = not_reached + not_attempted + not_measured
    if gap <= 0:
        subject = (
            "The one enabled computer"
            if in_scope == 1
            else f"All {in_scope:,} enabled computers"
        )
        return (
            f"{subject} in the directory answered over the network from where "
            "the assessment ran."
        )

    single = gap == 1
    remaining = (
        "The remaining computer was not assessed over the network, so its "
        if single
        else f"The remaining {gap:,} were not assessed over the network, so their "
    )
    parts: list[str] = [
        f"{reached:,} of {in_scope:,} enabled {computers} in the directory "
        "answered over the network from where the assessment ran.",
        remaining + "services, shares, sessions and local settings are not "
        "covered by this report.",
    ]
    if silent_segments:
        count = len(silent_segments)
        if count == 1:
            parts.append(
                "No computer answered at all in the network segment "
                f"{silent_segments[0]}."
            )
        else:
            named = silent_segments[:_SEGMENTS_NAMED_IN_STATEMENT]
            parts.append(
                f"No computer answered at all in {count:,} network segments "
                f"({_join_names(named, count - len(named))})."
            )
    if scattered:
        if silent_segments:
            parts.append(
                "One more did not answer in a segment where other computers did."
                if scattered == 1
                else f"A further {scattered:,} did not answer in segments where "
                "other computers did."
            )
        elif scattered == gap:
            parts.append(
                "It did not answer in a segment where other computers did."
                if single
                else "They did not answer in segments where other computers did."
            )
        else:
            parts.append(
                f"Of these, {scattered:,} did not answer in segments where other "
                "computers did."
            )
    if not_attempted:
        whom = "it" if single else f"{not_attempted:,} of them"
        parts.append(
            f"No network address could be found in the directory's DNS for {whom}, "
            "so there was nothing to test."
        )
    if not_measured:
        whom = "it" if single else f"{not_measured:,} of them"
        parts.append(f"Network reachability was not measured for {whom}.")
    if silent_segments:
        target = _plural(len(silent_segments), "that segment", "those segments")
        pronoun = _plural(len(silent_segments), "it", "them")
        parts.append(
            f"Giving the scanning host a network path to {target}, through an "
            "interface on the segment or a route and firewall rule, and re-running "
            f"the assessment will cover {pronoun}."
        )
    elif single:
        parts.append(
            "Re-running the assessment while that computer is online, or from a "
            "network position that reaches it, will cover it."
        )
    else:
        parts.append(
            "Re-running the assessment while those computers are online, or from "
            "a network position that reaches them, will cover them."
        )
    parts.append(_directory_clause(gap))
    return " ".join(parts)


def _clean_interface_rows(rows: Any) -> list[dict[str, Any]]:
    """Keep ``{name, address[, routed_asset_count]}`` rows with a name."""
    out: list[dict[str, Any]] = []
    for row in rows or ():
        if not isinstance(row, Mapping):
            continue
        name = str(row.get("name") or "").strip()
        if not name:
            continue
        clean: dict[str, Any] = {
            "name": name,
            "address": str(row.get("address") or "").strip(),
        }
        if "routed_asset_count" in row:
            try:
                clean["routed_asset_count"] = int(row.get("routed_asset_count") or 0)
            except (TypeError, ValueError):
                clean["routed_asset_count"] = 0
        out.append(clean)
    return out


def _clean_vantage(vantage: Any, report: Any) -> dict[str, Any]:
    """Merge the caller's vantage with the report's own pivot annotation.

    The block records HOW the assessment reached the network (``mode``, the
    client's own ``pivot_host``, how many adapters it was connected through),
    never the scanning host's interface names or addresses: the block reaches
    the client's report, the platform and the JSON exports, and those are the
    assessor's machine details, not the client's.
    """
    out: dict[str, Any] = {
        "mode": "direct",
        "pivot_host": "",
        "interface_count": 0,
        "known": False,
    }
    if isinstance(vantage, Mapping):
        for key in ("mode", "pivot_host"):
            value = str(vantage.get(key) or "").strip()
            if value:
                out[key] = value
        out["interface_count"] = len(_clean_interface_rows(vantage.get("interfaces")))
        out["known"] = bool(
            str(vantage.get("interface") or "").strip()
            or str(vantage.get("address") or "").strip()
            or out["interface_count"]
        )
    report_vantage = report.get("vantage") if isinstance(report, Mapping) else None
    if isinstance(report_vantage, Mapping):
        mode = str(report_vantage.get("mode") or "").strip()
        if mode:
            out["mode"] = mode
        pivot = str(report_vantage.get("pivot_host") or "").strip()
        if pivot:
            out["pivot_host"] = pivot
    return out


def _segment_rows(
    segment_hosts: Mapping[str, set[str]],
    segment_reached: Mapping[str, set[str]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for segment, hosts in segment_hosts.items():
        reached_hosts = segment_reached.get(segment, set())
        total = len(hosts)
        reached = len(reached_hosts)
        if reached == 0:
            state = SEGMENT_UNREACHED
        elif reached < total:
            state = SEGMENT_PARTIAL
        else:
            state = SEGMENT_REACHED
        rows.append(
            {
                "segment": segment,
                "computers": total,
                "reached": reached,
                "not_reached": total - reached,
                "state": state,
                "hostnames_preview": sorted(hosts - reached_hosts)[:_HOSTNAME_PREVIEW],
            }
        )
    return _sort_segment_rows(rows)


def _segment_sort_key(row: Mapping[str, Any]) -> tuple:
    segment = str(row.get("segment") or "")
    try:
        network = ipaddress.ip_network(segment, strict=False)
        address_key: tuple = (network.version, int(network.network_address))
    except ValueError:
        address_key = (9, 0)
    return (
        _SEGMENT_STATE_ORDER.get(str(row.get("state") or ""), 3),
        -int(row.get("not_reached") or 0),
        address_key,
        segment,
    )


def _sort_segment_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(rows, key=_segment_sort_key)


def build_host_reach_coverage(
    *,
    enabled_computers: Iterable[Any],
    reachability_report: Any,
    vantage: Any = None,
    idle_interfaces: Any = None,
) -> dict[str, Any]:
    """Build the ``host_reach_coverage`` block for one domain.

    Args:
        enabled_computers: The enabled computer objects in scope (the engine's
            ``enabled_computers.txt``). Empty falls back to the hosts the
            reachability report lists.
        reachability_report: The parsed ``network_reachability_report.json``
            payload, or ``None`` when no reachability pass ran for the domain
            (every in-scope computer is then ``not_measured``).
        vantage: Where the assessment ran from: ``interface`` / ``address``
            (and optionally ``mode`` / ``pivot_host`` and per-interface
            ``interfaces`` rows). A pivot annotation in the report itself is
            folded in.
        idle_interfaces: ``{name, address}`` rows for the network interfaces a
            target could call back to but that no in-scope AD host was reached
            through: a configured adapter on a segment the assessment did not
            cover. Declared, so an unused adapter never reads as covered.

    Returns:
        The block to hand to ``record_host_reach_coverage``. Always carries
        ``statement``.
    """
    report = reachability_report if isinstance(reachability_report, Mapping) else None
    host_ips: dict[str, list[Mapping[str, Any]]] = {}
    if report is not None:
        for host in report.get("hosts") or ():
            if not isinstance(host, Mapping):
                continue
            name = _normalize_host(host.get("hostname"))
            if not name:
                continue
            ips = [
                ip
                for ip in host.get("ips") or ()
                if isinstance(ip, Mapping) and ip.get("ip")
            ]
            host_ips.setdefault(name, []).extend(ips)

    scope: list[str] = []
    seen: set[str] = set()
    for value in enabled_computers or ():
        name = _normalize_host(value)
        if name and name not in seen:
            seen.add(name)
            scope.append(name)
    if not scope:
        scope = sorted(host_ips)

    reached_hosts: set[str] = set()
    unreached_hosts: set[str] = set()
    not_attempted = 0
    not_measured = 0
    segment_hosts: dict[str, set[str]] = {}
    segment_reached: dict[str, set[str]] = {}

    for name in scope:
        if report is None:
            not_measured += 1
            continue
        ips = host_ips.get(name) or []
        if not ips:
            not_attempted += 1
            continue
        answered = False
        for entry in ips:
            segment = str(
                entry.get("prefix_hint") or ""
            ).strip() or segment_for_address(entry.get("ip"))
            hit = ip_entry_is_reached(entry)
            answered = answered or hit
            if not segment:
                continue
            segment_hosts.setdefault(segment, set()).add(name)
            if hit:
                segment_reached.setdefault(segment, set()).add(name)
        (reached_hosts if answered else unreached_hosts).add(name)

    segments = _segment_rows(segment_hosts, segment_reached)
    silent = [row["segment"] for row in segments if row["state"] == SEGMENT_UNREACHED]
    silent_set = set(silent)
    scattered = sum(
        1
        for name in unreached_hosts
        if not any(name in segment_hosts.get(seg, set()) for seg in silent_set)
    )
    in_scope = len(scope)
    gap = len(unreached_hosts) + not_attempted + not_measured
    return {
        "measured": report is not None,
        "complete": gap == 0,
        "computers_in_scope": in_scope,
        "computers_reached": len(reached_hosts),
        "computers_not_reached": len(unreached_hosts),
        "computers_not_attempted": not_attempted,
        "computers_not_measured": not_measured,
        "unreached_segments": len(silent),
        "scattered_not_reached": scattered,
        "segments": segments,
        "vantage": _clean_vantage(vantage, report),
        "idle_interface_count": len(_clean_interface_rows(idle_interfaces)),
        "statement": _compose_statement(
            in_scope=in_scope,
            reached=len(reached_hosts),
            not_reached=len(unreached_hosts),
            not_attempted=not_attempted,
            not_measured=not_measured,
            silent_segments=silent,
            scattered=scattered,
        ),
    }


def _vantage_label(vantage: Any) -> str:
    """Client-facing sentence on where the assessment ran from, with no host detail.

    Names neither an interface nor an address of the scanning host: those are
    the assessor's machine, not something the client acts on. What the client
    needs (which segments were and were not reached) is in the segment rows and
    the coverage statement. Reads both the current block (``interface_count``,
    ``known``) and one persisted before it (raw ``interface`` / ``address`` /
    ``interfaces`` keys), counting them without ever printing them.
    """
    if not isinstance(vantage, Mapping):
        return ""
    pivot = str(vantage.get("pivot_host") or "").strip()
    pivoted = str(vantage.get("mode") or "").strip() == "pivot_assisted" and pivot
    count = _int(vantage, "interface_count") or len(
        _clean_interface_rows(vantage.get("interfaces"))
    )
    known = bool(
        vantage.get("known")
        or count
        or str(vantage.get("interface") or "").strip()
        or str(vantage.get("address") or "").strip()
    )
    if not known and not pivoted:
        return ""
    where = (
        "a host connected to several network segments"
        if count >= 2
        else "a single network position inside the engagement network"
    )
    tail = f", with additional reach through a pivot on {pivot}" if pivoted else ""
    return f"Assessed from {where}{tail}."


def _idle_interfaces_label(count: int) -> str:
    """Client-facing sentence on connected segments no in-scope computer was reached through.

    ``count`` is the number of such segments; nothing about them is named.
    """
    n = max(0, int(count or 0))
    if n <= 0:
        return ""
    if n == 1:
        return (
            "One network segment the scanning host was connected to had no in-scope "
            "computer reached through it, so no computer on that segment was assessed."
        )
    return (
        f"{n} network segments the scanning host was connected to had no in-scope "
        "computer reached through them, so no computer on those segments was assessed."
    )


def _idle_count(block: Mapping[str, Any]) -> int:
    """Idle adapters a block records: the count, or a legacy block's rows."""
    if "idle_interface_count" in block:
        return _int(block, "idle_interface_count")
    return len(_clean_interface_rows(block.get("idle_interfaces")))


def _int(mapping: Mapping[str, Any], key: str) -> int:
    try:
        return max(0, int(mapping.get(key) or 0))
    except (TypeError, ValueError):
        return 0


def _empty_view() -> dict[str, Any]:
    return {
        "present": False,
        "has_gap": False,
        "statement": "",
        "scope_statement": "",
        "computers_in_scope": 0,
        "computers_reached": 0,
        "computers_not_reached": 0,
        "computers_not_attempted": 0,
        "computers_not_measured": 0,
        "unreached_segments": 0,
        "segments": [],
        "segments_omitted": 0,
        "vantage_label": "",
        "idle_interfaces_label": "",
    }


def host_reach_coverage_view(coverage: Any) -> dict[str, Any]:
    """Return the render-ready view of a persisted ``host_reach_coverage`` block.

    The one shape the PRO report, the LITE report and the web platform read, so
    a reach gap is worded identically wherever a client meets it.

    Returns a mapping with ``present`` (a block was recorded), ``has_gap``
    (surface the declaration), ``statement`` (empty when complete),
    ``scope_statement`` (the recorded sentence whether or not there is a gap,
    for a scope note that also affirms full reach), the per
    computer counts, ``segments`` (the rows with at least one computer that did
    not answer, worst first, capped at :data:`MAX_SEGMENT_ROWS`, each with a
    ``state_label``), ``segments_omitted`` and ``vantage_label``.

    An absent or unreadable block yields ``present=False``/``has_gap=False``: a
    scan predating this record renders exactly as it did before.
    """
    if not isinstance(coverage, Mapping):
        return _empty_view()
    complete = bool(coverage.get("complete", True))
    in_scope = _int(coverage, "computers_in_scope")
    statement = str(coverage.get("statement") or "").strip()
    rows: list[dict[str, Any]] = []
    for row in coverage.get("segments") or ():
        if not isinstance(row, Mapping):
            continue
        if _int(row, "not_reached") <= 0:
            continue
        state = str(row.get("state") or "")
        rows.append(
            {
                "segment": str(row.get("segment") or ""),
                "computers": _int(row, "computers"),
                "reached": _int(row, "reached"),
                "not_reached": _int(row, "not_reached"),
                "state": state,
                "state_label": _SEGMENT_STATE_LABELS.get(state, ""),
                "hostnames_preview": [
                    str(h) for h in row.get("hostnames_preview") or () if str(h).strip()
                ],
            }
        )
    rows = _sort_segment_rows(rows)
    has_gap = bool(not complete and statement and in_scope > 0)
    return {
        "present": True,
        "has_gap": has_gap,
        "statement": statement if has_gap else "",
        "scope_statement": statement if in_scope > 0 else "",
        "computers_in_scope": in_scope,
        "computers_reached": _int(coverage, "computers_reached"),
        "computers_not_reached": _int(coverage, "computers_not_reached"),
        "computers_not_attempted": _int(coverage, "computers_not_attempted"),
        "computers_not_measured": _int(coverage, "computers_not_measured"),
        "unreached_segments": _int(coverage, "unreached_segments"),
        "segments": rows[:MAX_SEGMENT_ROWS],
        "segments_omitted": max(0, len(rows) - MAX_SEGMENT_ROWS),
        "vantage_label": _vantage_label(coverage.get("vantage")),
        "idle_interfaces_label": _idle_interfaces_label(
            _idle_count(coverage)
        ),
    }


def merge_host_reach_coverage(domain_entries: Any) -> dict[str, Any]:
    """Fold every domain's recorded block into one report-wide view.

    Counts are summed, segments shared by several domains are summed into one
    row, and a gap in any domain is a gap for the whole report. A single
    recorded block keeps its RECORDED statement (a later wording change cannot
    rewrite what a delivered report said); several are re-derived from the
    summed counts. Non-mapping entries and entries without a block are skipped;
    nothing recorded anywhere yields the pre-existing render.
    """
    blocks: list[Mapping[str, Any]] = []
    for entry in domain_entries or ():
        if not isinstance(entry, Mapping):
            continue
        block = entry.get(HOST_REACH_COVERAGE_KEY)
        if isinstance(block, Mapping):
            blocks.append(block)
    if not blocks:
        return _empty_view()
    if len(blocks) == 1:
        return host_reach_coverage_view(blocks[0])

    totals = {
        key: sum(_int(block, key) for block in blocks)
        for key in (
            "computers_in_scope",
            "computers_reached",
            "computers_not_reached",
            "computers_not_attempted",
            "computers_not_measured",
            "scattered_not_reached",
        )
    }
    merged_segments: dict[str, dict[str, Any]] = {}
    for block in blocks:
        for row in block.get("segments") or ():
            if not isinstance(row, Mapping):
                continue
            segment = str(row.get("segment") or "")
            if not segment:
                continue
            slot = merged_segments.setdefault(
                segment,
                {
                    "segment": segment,
                    "computers": 0,
                    "reached": 0,
                    "not_reached": 0,
                    "hostnames_preview": [],
                },
            )
            slot["computers"] += _int(row, "computers")
            slot["reached"] += _int(row, "reached")
            slot["not_reached"] += _int(row, "not_reached")
            for host in row.get("hostnames_preview") or ():
                if (
                    host not in slot["hostnames_preview"]
                    and len(slot["hostnames_preview"]) < _HOSTNAME_PREVIEW
                ):
                    slot["hostnames_preview"].append(host)
    rows: list[dict[str, Any]] = []
    for slot in merged_segments.values():
        if slot["reached"] == 0:
            slot["state"] = SEGMENT_UNREACHED
        elif slot["not_reached"] > 0:
            slot["state"] = SEGMENT_PARTIAL
        else:
            slot["state"] = SEGMENT_REACHED
        rows.append(slot)
    rows = _sort_segment_rows(rows)
    silent = [row["segment"] for row in rows if row["state"] == SEGMENT_UNREACHED]

    vantages: list[str] = []
    for block in blocks:
        label = _vantage_label(block.get("vantage"))
        if label and label not in vantages:
            vantages.append(label)
    gap = (
        totals["computers_not_reached"]
        + totals["computers_not_attempted"]
        + totals["computers_not_measured"]
    )
    merged = {
        **totals,
        "measured": all(bool(block.get("measured", True)) for block in blocks),
        "complete": gap == 0,
        "unreached_segments": len(silent),
        "segments": rows,
        "vantage": None,
        # Idle adapters are a property of the scanning host, not of one domain,
        # so every domain block carries the same count: the largest wins.
        "idle_interface_count": max(_idle_count(block) for block in blocks),
        "statement": _compose_statement(
            in_scope=totals["computers_in_scope"],
            reached=totals["computers_reached"],
            not_reached=totals["computers_not_reached"],
            not_attempted=totals["computers_not_attempted"],
            not_measured=totals["computers_not_measured"],
            silent_segments=silent,
            scattered=totals["scattered_not_reached"],
        ),
    }
    view = host_reach_coverage_view(merged)
    view["vantage_label"] = " ".join(vantages)
    return view


__all__ = [
    "HOST_REACH_COVERAGE_KEY",
    "MAX_SEGMENT_ROWS",
    "SEGMENT_PARTIAL",
    "SEGMENT_REACHED",
    "SEGMENT_UNREACHED",
    "build_host_reach_coverage",
    "host_reach_coverage_view",
    "ip_entry_is_reached",
    "merge_host_reach_coverage",
    "segment_for_address",
]
