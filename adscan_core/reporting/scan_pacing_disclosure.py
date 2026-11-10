"""Assessment pace: how hard the run worked the client network, stated once.

The pace an assessment ran at is part of its method, and a client who signed an
authorization that names a maximum speed needs to see that the run respected
it. The strain safeguard makes the second promise: ADscan slows down on a server
that struggles and pauses one that stops answering, and every such action is
listed. A paused server is a boundary of the assessment, so its remaining checks
read as not assessed, never as clean.

This module is the SSOT for both halves (the ``cracking_coverage`` pattern):

* :func:`build_scan_pacing_disclosure` turns the resolved pacing, the strain
  safeguard's report (``PacingRuntime.strain_report()``) and the entry point's
  facts (an unattended run that carried a saved Fast pace down to Normal) into
  the block persisted under ``domains[<domain>]["scan_pacing"]``; and
* :func:`scan_pacing_disclosure_view` turns it into the render shape the PRO
  report, the LITE report and the web CTEM read.

Stdlib only (plus ``adscan_core.scan_pacing``): the web backend imports it.

Design: docs/superpowers/specs/2026-11-04-scan-pacing-ssot-design.md § 6.6.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from adscan_core.scan_pacing.pacing_consumers import CONSUMERS, ParamRole
from adscan_core.scan_pacing.pacing_knobs import (
    COMPONENT_DEFAULT,
    COMPONENT_FAST,
    KNOBS_BY_KEY,
    MAX_IN_FLIGHT_PER_HOST,
    MAX_PARALLEL_HOSTS,
    MAX_REQUESTS_PER_SECOND,
    PER_HOST_DELAY_MS,
    SHARE_BANDWIDTH_MIBPS,
    UNLIMITED,
)
from adscan_core.scan_pacing.pacing_levels import DEFAULT_LEVEL, LEVEL_DESCRIPTIONS, PacingLevel
from adscan_core.scan_pacing.pacing_profiles import (
    lowered_clause,
    lowered_count_phrase,
    lowered_lines,
    pace_digest,
    short_pace_digest,
)
from adscan_core.scan_pacing.pacing_resolver import ResolvedPacing, resolve_pacing

#: Per-domain key in ``technical_report.json`` and the renderer's ``report_data``.
SCAN_PACING_KEY = "scan_pacing"
SCHEMA_VERSION = 1

#: Knob-value sources that mean "someone chose this", as opposed to the level.
_CHOSEN_SOURCES = frozenset({"override", "legacy_env", "policy_cap", "invariant"})

#: Client words for where a knob value came from.
SOURCE_LABELS: dict[str, str] = {
    "level": "from the pace",
    "override": "set for this assessment",
    "profile": "from the saved pace profile",
    "legacy_env": "set by an environment variable on the scanner",
    "policy_cap": "limited by the scan policy",
    "invariant": "fixed by ADscan",
}

#: Hosts listed by name before the rest is counted.
_MAX_HOSTS_NAMED = 10


def _plural(count: int, singular: str, plural: str | None = None) -> str:
    return f"{count} {singular if count == 1 else (plural or singular + 's')}"


def _level_label(level: Any) -> str:
    resolved = PacingLevel.coerce(level)
    if resolved is None:
        return str(level or "")
    return LEVEL_DESCRIPTIONS[resolved].label


def _display_value(value: Any, unit: str) -> str:
    if value == UNLIMITED:
        return "No limit"
    if value in (COMPONENT_DEFAULT, COMPONENT_FAST):
        return "Standard"
    if isinstance(value, bool):
        return "On" if value else "Off"
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    text = str(value)
    if unit == "x":
        return f"{text}×"
    return f"{text} {unit}".strip()


def _numeric(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _knob_rows(resolved: ResolvedPacing) -> list[dict[str, Any]]:
    """Every knob someone chose or a ceiling lowered, with its effective value."""
    ceiling_knobs: Mapping[str, Any] = {}
    if resolved.ceiling is not None:
        try:
            ceiling_knobs = resolve_pacing(resolved.ceiling.as_request()).knobs
        except Exception:  # noqa: BLE001 - disclosure degrades to the request value
            ceiling_knobs = {}
    rows: list[dict[str, Any]] = []
    for key, knob in resolved.knobs.items():
        if knob.source not in _CHOSEN_SOURCES and not knob.capped:
            continue
        spec = KNOBS_BY_KEY.get(key)
        value = knob.value
        requested = None
        if knob.capped and key in ceiling_knobs:
            requested = value
            value = ceiling_knobs[key].value
        rows.append(
            {
                "key": key,
                "label": spec.label if spec is not None else key,
                "value": value,
                "unit": knob.unit,
                "display": _display_value(value, knob.unit),
                "requested": requested,
                "requested_display": (
                    _display_value(requested, knob.unit) if requested is not None else ""
                ),
                "source": (
                    "policy_cap"
                    if knob.capped
                    else ("profile" if knob.source == "override" and knob.detail == "profile" else knob.source)
                ),
                "detail": knob.detail,
                "capped": bool(knob.capped),
            }
        )
    return rows


def format_chance(probability: float) -> str:
    """A chance for a sentence: ``2%``, ``14%``, ``0.04%``; never ``0%`` for a real one."""
    pct = max(0.0, float(probability)) * 100.0
    if pct >= 10:
        return f"{pct:.0f}%"
    if pct >= 1:
        return f"{pct:.1f}".rstrip("0").rstrip(".") + "%"
    return f"{pct:.2g}%"


def _reduced_checks(resolved: ResolvedPacing) -> list[dict[str, Any]]:
    """Statistical checks the pace ran with a smaller attempt budget than standard.

    A smaller budget lowers the confidence of a negative result, so the report
    states the budget and the chance a negative is wrong, next to the standard
    figures. Read from the registry (``ParamRole.ATTEMPTS``), never per check.
    """
    rows: list[dict[str, Any]] = []
    for spec in CONSUMERS:
        try:
            component = resolved.component(spec.consumer_id)
        except KeyError:
            continue
        for param in spec.params:
            if param.role is not ParamRole.ATTEMPTS:
                continue
            value = component.get(param.name)
            if not isinstance(value, int) or value >= param.default:
                continue
            miss = param.miss_probability(value)
            standard_miss = param.miss_probability(param.default)
            rows.append(
                {
                    "consumer": spec.consumer_id,
                    "check": param.client_label or spec.consumer_id,
                    "target": param.client_target,
                    "attempts": value,
                    "standard_attempts": param.default,
                    "miss_probability": round(miss, 6) if miss is not None else None,
                    "standard_miss_probability": (
                        round(standard_miss, 6) if standard_miss is not None else None
                    ),
                }
            )
    return rows


def _reduced_check_sentence(row: Mapping[str, Any]) -> str:
    check = str(row.get("check") or "")
    target = str(row.get("target") or "host")
    attempts = int(row.get("attempts") or 0)
    standard = int(row.get("standard_attempts") or 0)
    sentence = (
        f"At this pace the {check} check makes {attempts:,} attempts on each {target} "
        f"instead of the standard {standard:,}."
    )
    miss = row.get("miss_probability")
    standard_miss = row.get("standard_miss_probability")
    if isinstance(miss, (int, float)) and isinstance(standard_miss, (int, float)):
        article = "An" if target[:1].lower() in "aeiou" else "A"
        sentence += (
            f" {article} {target} it reports as not vulnerable therefore has about a "
            f"{format_chance(miss)} chance of being vulnerable after all, against "
            f"{format_chance(standard_miss)} at the standard budget."
        )
    return sentence


def _strain_block(strain: Mapping[str, Any] | None) -> dict[str, Any]:
    raw = strain if isinstance(strain, Mapping) else {}
    counters = raw.get("counters") if isinstance(raw.get("counters"), Mapping) else {}
    paused = sorted({str(h) for h in (raw.get("paused_hosts") or ()) if str(h).strip()})
    slowed = sorted(
        {str(h) for h in (raw.get("slowed_hosts") or ()) if str(h).strip()} - set(paused)
    )
    return {
        "enabled": bool(raw.get("enabled", True)),
        "acted": bool(raw.get("acted")) or bool(paused),
        "hosts_slowed": int(counters.get("hosts_slowed") or len(slowed) + len(paused)),
        "hosts_paused": int(counters.get("hosts_paused") or len(paused)),
        "operations_skipped": int(counters.get("operations_skipped") or 0),
        "global_backoffs": int(counters.get("global_backoffs") or 0),
        "lowest_fraction": raw.get("lowest_fraction"),
        "slowed_hosts": slowed,
        "paused_hosts": paused,
    }


def strain_for_domain(
    strain: Mapping[str, Any] | None,
    *,
    domain: str,
    hosts_by_domain: Mapping[str, Iterable[str]],
) -> dict[str, Any] | None:
    """Narrow a run-level strain report to the hosts that belong to ``domain``.

    The strain safeguard works per host across the whole run, so its report
    names every slowed server of every domain. A domain's statement must name
    only that domain's servers: a host another domain claims is dropped, a
    host no domain claims (its owner is unknown) is kept so a slowdown is never
    hidden, and the counters are recomputed from what remains.

    Args:
        strain: ``PacingRuntime.strain_report()`` or ``None``.
        domain: The domain the statement is for.
        hosts_by_domain: Known hosts (IPs and names) per domain of the run.

    Returns:
        A strain mapping for ``build_scan_pacing_disclosure``, or ``strain``
        unchanged when it is not a mapping.
    """
    if not isinstance(strain, Mapping):
        return strain  # type: ignore[return-value]
    norm = {
        d.lower(): {str(h).strip().lower() for h in hosts if str(h).strip()}
        for d, hosts in hosts_by_domain.items()
    }
    own = norm.get(domain.lower(), set())
    others = {d: hs for d, hs in norm.items() if d != domain.lower()}

    def _keep(host: Any) -> bool:
        h = str(host).strip().lower()
        if not h:
            return False
        if h in own or h.endswith("." + domain.lower()):
            return True
        for other, hs in others.items():
            if h in hs or h.endswith("." + other):
                return False
        return True  # unattributed: not provably another domain's

    paused = [h for h in (strain.get("paused_hosts") or ()) if _keep(h)]
    slowed = [h for h in (strain.get("slowed_hosts") or ()) if _keep(h)]
    counters = dict(strain.get("counters") or {})
    counters["hosts_slowed"] = len(set(slowed) | set(paused))
    counters["hosts_paused"] = len(paused)
    out = dict(strain)
    out.update(
        paused_hosts=paused,
        slowed_hosts=slowed,
        counters=counters,
        acted=bool(slowed or paused or counters.get("global_backoffs")),
    )
    return out


def build_scan_pacing_disclosure(
    resolved: ResolvedPacing,
    *,
    strain: Mapping[str, Any] | None = None,
    fast_downgraded: bool = False,
) -> dict[str, Any]:
    """Build the persisted ``scan_pacing`` block for one run.

    Args:
        resolved: The run's published pacing (``active_pacing()``).
        strain: ``PacingRuntime.strain_report()`` at scan end, or ``None``.
        fast_downgraded: An unattended run carried a saved Fast pace down to
            Normal (the entry point warned the operator; the report states it).
    """
    ceiling = resolved.ceiling
    ceiling_block: dict[str, Any] | None = None
    if ceiling is not None:
        policy = ceiling.policy.to_dict() if ceiling.policy is not None else {}
        ceiling_block = {
            "level": ceiling.level.value,
            "level_label": _level_label(ceiling.level),
            "policy": policy,
        }
    strain_block = _strain_block(strain)
    overrides = _knob_rows(resolved)
    # Effective values: a knob the ceiling lowered states the ceiling's value,
    # never the faster one that was requested.
    knobs = {key: knob.value for key, knob in resolved.knobs.items()}
    for row in overrides:
        if row["capped"]:
            knobs[row["key"]] = row["value"]
    effective_knobs = {k: v for k, v in knobs.items() if _json_scalar(v)}
    profile = resolved.request.profile
    block: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "level": resolved.level.value,
        "level_label": _level_label(resolved.level),
        "requested_level": resolved.requested_level.value,
        "requested_level_label": _level_label(resolved.requested_level),
        "level_source": resolved.request.level_source,
        "level_capped": bool(resolved.level_capped),
        "is_default": bool(resolved.is_default),
        "knobs": effective_knobs,
        # The fingerprint of the EFFECTIVE pace (after the ceiling): the same
        # pace reached from the CLI or the web, with or without a profile, has
        # the same one, so it can be matched against a written authorization.
        "digest": pace_digest(resolved.level, effective_knobs),
        # The saved pace profile the run started from, when one was chosen.
        "profile": profile.to_dict() if profile is not None else None,
        "overrides": overrides,
        "ceiling": ceiling_block,
        "capped_parameters": len(resolved.capped),
        "legacy_env": list(resolved.legacy_env),
        "legacy_env_ignored": dict(resolved.legacy_env_ignored),
        "fast_downgraded": bool(fast_downgraded),
        "reduced_checks": _reduced_checks(resolved),
        "strain": strain_block,
    }
    block["statement"] = _statement(block)
    return block


def _json_scalar(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool))


# ── statements (client-facing; pass the adscan-writing gate) ─────────────────


def _limits_sentence(knobs: Mapping[str, Any]) -> str:
    clauses: list[str] = []
    hosts = _numeric(knobs.get(MAX_PARALLEL_HOSTS))
    per_host = _numeric(knobs.get(MAX_IN_FLIGHT_PER_HOST))
    if hosts is not None:
        clause = f"worked at most {_plural(int(hosts), 'host')} at a time"
        if per_host is not None:
            clause += f" with {_plural(int(per_host), 'connection')} each"
        clauses.append(clause)
    delay = _numeric(knobs.get(PER_HOST_DELAY_MS))
    if delay:
        clauses.append(f"waited {int(delay)} ms between operations on the same host")
    rate = _numeric(knobs.get(MAX_REQUESTS_PER_SECOND))
    if rate:
        clauses.append(f"sent no more than {int(rate)} requests per second across the network")
    bandwidth = _numeric(knobs.get(SHARE_BANDWIDTH_MIBPS))
    if bandwidth:
        shown = int(bandwidth) if float(bandwidth).is_integer() else bandwidth
        clauses.append(f"held file downloads to {shown} MiB/s")
    if not clauses:
        return ""
    if len(clauses) == 1:
        joined = clauses[0]
    else:
        joined = ", ".join(clauses[:-1]) + " and " + clauses[-1]
    return f"It {joined}."


def _ceiling_sentence(block: Mapping[str, Any]) -> str:
    ceiling = block.get("ceiling")
    if not isinstance(ceiling, Mapping):
        return ""
    policy = ceiling.get("policy") if isinstance(ceiling.get("policy"), Mapping) else {}
    name = str(policy.get("name") or "").strip()
    revision = policy.get("revision")
    who = f"The scan policy '{name}'" if name else "The scan policy"
    if name and revision:
        who += f" (revision {revision})"
    level = str(ceiling.get("level_label") or "")
    sentence = f"{who} set {level} as the fastest pace allowed."
    if block.get("level_capped"):
        sentence += (
            f" The assessment was asked to run at {block.get('requested_level_label')} "
            f"and ran at {block.get('level_label')} instead."
        )
    return sentence


def _profile_sentences(block: Mapping[str, Any]) -> list[str]:
    """Name the saved pace profile, whether it was adjusted, and what the policy lowered."""
    profile = block.get("profile")
    if not isinstance(profile, Mapping) or not str(profile.get("name") or "").strip():
        return []
    name = str(profile.get("name")).strip()
    revision = profile.get("revision")
    who = f"the saved pace profile '{name}'" + (f" (revision {revision})" if revision else "")
    sentence = f"The pace came from {who}"
    sentence += ", adjusted for this assessment." if profile.get("adjusted") else "."
    out = [sentence]
    lowered = list(profile.get("lowered") or ())
    clause = lowered_clause(lowered)
    if clause:
        out.append(f"{lowered_count_phrase(lowered)} lowered to fit the scan policy, {clause}.")
    return out


def _host_list(hosts: list[str]) -> str:
    named = hosts[:_MAX_HOSTS_NAMED]
    text = ", ".join(named)
    if len(hosts) > _MAX_HOSTS_NAMED:
        text += f" and {_plural(len(hosts) - _MAX_HOSTS_NAMED, 'other')}"
    return text


def _strain_sentences(strain: Mapping[str, Any]) -> list[str]:
    if not strain.get("enabled", True):
        return [
            "The automatic slowdown for servers that struggle was turned off for this "
            "assessment."
        ]
    paused = list(strain.get("paused_hosts") or ())
    slowed = list(strain.get("slowed_hosts") or ())
    backoffs = int(strain.get("global_backoffs") or 0)
    if not paused and not slowed and not backoffs and not strain.get("acted"):
        return ["ADscan did not need to slow down for any server."]
    out: list[str] = []
    if slowed:
        out.append(
            f"ADscan slowed down on {_plural(len(slowed), 'server')} that responded more "
            f"slowly during the assessment ({_host_list(slowed)})."
        )
    if paused:
        out.append(
            f"It paused {_plural(len(paused), 'server')} that stopped responding "
            f"({_host_list(paused)}). The checks it had not yet run there are not assessed."
        )
    if backoffs:
        out.append(
            "When several servers struggled at once it also reduced how many it worked "
            "in parallel, then recovered gradually."
        )
    return out


def _statement(block: Mapping[str, Any]) -> str:
    label = str(block.get("level_label") or _level_label(DEFAULT_LEVEL))
    sentences: list[str] = []
    level = PacingLevel.coerce(block.get("level")) or DEFAULT_LEVEL
    if level == DEFAULT_LEVEL and not block.get("overrides"):
        sentences.append(f"This assessment ran at the {label} pace, the standard ADscan pace.")
    else:
        sentences.append(f"This assessment ran at the {label} pace.")
        limits = _limits_sentence(block.get("knobs") or {})
        if limits:
            sentences.append(limits)
    sentences.extend(_profile_sentences(block))
    for row in block.get("reduced_checks") or ():
        if isinstance(row, Mapping):
            sentences.append(_reduced_check_sentence(row))
    ceiling = _ceiling_sentence(block)
    if ceiling:
        sentences.append(ceiling)
    if block.get("fast_downgraded"):
        sentences.append(
            "The workspace was set to the Fast pace, which an unattended run does not "
            "carry over, so this run used Normal."
        )
    sentences.extend(_strain_sentences(block.get("strain") or {}))
    return " ".join(sentences)


def scan_pacing_disclosure_view(block: Any) -> dict[str, Any]:
    """Render shape for the PDF, the LITE report and the web CTEM.

    ``prominent`` is True when the pace differs from the standard one, a ceiling
    applied, an override or a deprecated env var acted, a saved Fast pace was
    carried down, or the safeguard acted. At the default the surfaces print the
    one-line ``headline``.
    """
    if not isinstance(block, Mapping) or not block.get("statement"):
        return {"present": False}
    strain = block.get("strain") if isinstance(block.get("strain"), Mapping) else {}
    paused = [str(h) for h in (strain.get("paused_hosts") or ())]
    slowed = [str(h) for h in (strain.get("slowed_hosts") or ())]
    level = PacingLevel.coerce(block.get("level")) or DEFAULT_LEVEL
    rows = [
        {
            "label": str(r.get("label") or r.get("key") or ""),
            "value": str(r.get("display") or ""),
            "requested": str(r.get("requested_display") or ""),
            "source": SOURCE_LABELS.get(str(r.get("source") or ""), ""),
        }
        for r in (block.get("overrides") or ())
        if isinstance(r, Mapping)
    ]
    legacy = [str(v) for v in (block.get("legacy_env") or ())]
    reduced_lines = [
        _reduced_check_sentence(r) for r in (block.get("reduced_checks") or ()) if isinstance(r, Mapping)
    ]
    acted = bool(strain.get("acted") or paused or slowed or strain.get("global_backoffs"))
    profile = block.get("profile") if isinstance(block.get("profile"), Mapping) else None
    prominent = bool(
        level != DEFAULT_LEVEL
        or profile
        or rows
        or block.get("ceiling")
        or legacy
        or reduced_lines
        or block.get("fast_downgraded")
        or acted
        or not strain.get("enabled", True)
    )
    label = str(block.get("level_label") or "")
    headline = (
        str(block.get("statement") or "")
        if prominent
        else f"{label} pace, the standard ADscan pace. ADscan did not need to slow down for any server."
    )
    not_assessed_line = ""
    if paused:
        not_assessed_line = (
            f"{_plural(len(paused), 'server')} paused by the slowdown safeguard "
            f"({_host_list(paused)}). The checks ADscan had not yet run there are not assessed."
        )
    digest = str(block.get("digest") or "")
    return {
        "present": True,
        "prominent": prominent,
        "headline": headline,
        "profile_name": str((profile or {}).get("name") or ""),
        "profile_adjusted": bool((profile or {}).get("adjusted")),
        "profile_lowered_lines": lowered_lines((profile or {}).get("lowered") or ()),
        "digest": digest,
        "digest_short": short_pace_digest(digest) if digest else "",
        "statement": str(block.get("statement") or ""),
        "level_label": label,
        "rows": rows,
        "legacy_env": legacy,
        "legacy_env_line": (
            f"{_plural(len(legacy), 'deprecated scanner environment variable')} changed "
            "the pace for this run."
            if legacy
            else ""
        ),
        "paused_hosts": paused,
        "slowed_hosts": slowed,
        "not_assessed_line": not_assessed_line,
        #: Checks run with a smaller attempt budget, and what that does to a negative.
        "reduced_check_lines": reduced_lines,
    }


def merge_scan_pacing(entries: Iterable[Any]) -> dict[str, Any]:
    """One view for a multi-domain report: the pace is a property of the run.

    The block carrying the most safeguard actions wins, so a domain stamped
    after the safeguard acted is the one printed.
    """
    best: Mapping[str, Any] | None = None
    best_score = -1
    for entry in entries or ():
        if not isinstance(entry, Mapping):
            continue
        block = entry.get(SCAN_PACING_KEY)
        if not isinstance(block, Mapping) or not block.get("statement"):
            continue
        strain = block.get("strain") if isinstance(block.get("strain"), Mapping) else {}
        score = len(strain.get("paused_hosts") or ()) * 1000 + len(strain.get("slowed_hosts") or ())
        if score > best_score:
            best, best_score = block, score
    return scan_pacing_disclosure_view(best)


def paused_hosts(block: Any) -> list[str]:
    """Hosts the safeguard paused (their remaining checks are not assessed)."""
    if not isinstance(block, Mapping):
        return []
    strain = block.get("strain") if isinstance(block.get("strain"), Mapping) else {}
    return [str(h) for h in (strain.get("paused_hosts") or ()) if str(h).strip()]


__all__ = (
    "SCAN_PACING_KEY",
    "SCHEMA_VERSION",
    "SOURCE_LABELS",
    "build_scan_pacing_disclosure",
    "strain_for_domain",
    "format_chance",
    "merge_scan_pacing",
    "paused_hosts",
    "scan_pacing_disclosure_view",
)
