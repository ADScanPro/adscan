"""Per-asset exposure, counted by FINDING and by ROLE (the one derivation).

A host or an account is described to a client by two figures, never by a raw
attack-graph count:

* **Exposed by N findings**: distinct open findings in which the asset is the
  object at risk. On an attack-step finding that is the edge TARGET (what the
  step exposes); on any other finding (SMBv1 on a host, a stale password on an
  account) it is the affected object itself.
* **Holds N risky rights**: distinct open findings in which the asset is the
  edge SOURCE, the principal that can carry the step out today.

Each figure counts a finding once, however many attack-graph edges, path
occurrences or duplicate entities the finding carries. A group that holds a
right is attributed to the GROUP: the right is configured on the group, so its
members are not expanded here. Per-member reach stays with the "Most Exposed
Accounts" ranking (:mod:`adscan_core.reporting.user_exposure_ranking`), which
does walk memberships.

WHY THIS MODULE EXISTS
----------------------
The web Assets page used to rank hosts by "active attack steps": the number of
attack-graph edges whose JSON happened to mention the host anywhere, folded into
an opaque weighted score. A domain controller read "Score 1550 · 108 active
steps" against nine edges that actually touch it. The figure was not a property
of the host, so it could not be explained to a client or reconciled with the
report. Every surface that shows a per-asset or per-domain exposure figure (the
web Assets cards, the priority queues, the inventory rows and detail panels, the
domain card, the report) reads it from here instead.

Roles come from the engine's stamped entities
(:mod:`adscan_core.reporting.affected_asset_roles`), never from names or finding
keys. The module is stdlib-only so the web backend can import it.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from adscan_core.reporting.affected_asset_roles import (
    PRINCIPAL_TYPES,
    ROLE_SOURCE,
    entity_role,
    is_attack_step,
    is_counted_object,
    stamped_entities,
)

# --------------------------------------------------------------------------- #
# Vocabulary                                                                   #
# --------------------------------------------------------------------------- #

#: The asset is the object at risk in the finding.
SIDE_EXPOSED = "exposed"
#: The asset holds the right the finding is about.
SIDE_HOLDS = "holds"

#: Severity levels, most severe first. Unknown values count as ``info``.
SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
_SEVERITY_RANK: dict[str, int] = {level: rank for rank, level in enumerate(SEVERITY_ORDER)}


def normalize_severity(value: Any) -> str:
    """Return a severity level from :data:`SEVERITY_ORDER` (enum, str or ``None``)."""
    raw = getattr(value, "value", value)
    level = str(raw or "").strip().lower()
    if level == "informational":
        level = "info"
    return level if level in _SEVERITY_RANK else "info"


# --------------------------------------------------------------------------- #
# Identity keys                                                                #
# --------------------------------------------------------------------------- #
# An entity and an inventory row name the same object in different ways (a SID,
# an FQDN, an IP, a ``name:host$`` node id, a sAMAccountName). Both sides are
# reduced to the same typed key set, and an asset matches an entity when the two
# sets intersect. Keys are typed so a user ``meereen`` never matches the computer
# ``meereen$``. Matching is always scoped to ONE domain by the caller.


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _account_stem(value: Any) -> str:
    """Lower-case sAMAccountName with any realm qualifier and node prefix removed."""
    raw = _clean(value)
    if raw.lower().startswith("name:"):
        raw = raw[5:]
    if "\\" in raw:
        raw = raw.rsplit("\\", 1)[-1]
    return raw.split("@", 1)[0].strip().lower()


def _sid_key(value: Any) -> str:
    raw = _clean(value).upper()
    if raw.startswith("NAME:"):
        raw = raw[5:]
    return f"sid:{raw}" if raw.startswith("S-1-") else ""


def _host_keys(fqdn: Any, ip: Any) -> set[str]:
    keys: set[str] = set()
    name = _clean(fqdn).lower().rstrip(".")
    if name:
        keys.add(f"host:{name}")
        short = name.split(".", 1)[0]
        if short:
            keys.add(f"acct:{short}$")
    address = _clean(ip).lower()
    if address:
        keys.add(f"ip:{address}")
    return keys


def entity_identity_keys(entity: Mapping[str, Any]) -> frozenset[str]:
    """Return the typed identity keys of an engine-stamped entity."""
    keys: set[str] = set()
    etype = _clean(entity.get("type")).lower()
    sid = _sid_key(entity.get("sid")) or _sid_key(entity.get("node_id"))
    if sid:
        keys.add(sid)
    if etype == "computer":
        keys |= _host_keys(entity.get("fqdn"), entity.get("ip"))
        for raw in (entity.get("node_id"), entity.get("identifier")):
            stem = _account_stem(raw)
            if not stem or stem.startswith("s-1-"):
                continue
            if "." in stem:
                keys |= _host_keys(stem, None)
            else:
                keys.add(f"acct:{stem if stem.endswith('$') else stem + '$'}")
    else:
        for raw in (entity.get("identifier"), entity.get("node_id")):
            stem = _account_stem(raw)
            if stem and not stem.startswith("s-1-"):
                keys.add(f"acct:{stem}")
    return frozenset(keys)


def host_identity_keys(*, fqdn: Any = None, ip: Any = None, sid: Any = None) -> frozenset[str]:
    """Return the identity keys of a host or computer inventory row."""
    keys = _host_keys(fqdn, ip)
    sid_key = _sid_key(sid)
    if sid_key:
        keys.add(sid_key)
    return frozenset(keys)


def computer_identity_keys(
    *, name: Any = None, fqdn: Any = None, ip: Any = None, sid: Any = None
) -> frozenset[str]:
    """Return the identity keys of a computer account (``name`` with or without ``$``)."""
    keys = set(host_identity_keys(fqdn=fqdn, ip=ip, sid=sid))
    stem = _account_stem(name)
    if stem:
        keys.add(f"acct:{stem if stem.endswith('$') else stem + '$'}")
    return frozenset(keys)


def account_identity_keys(
    *, samaccountname: Any = None, upn: Any = None, sid: Any = None
) -> frozenset[str]:
    """Return the identity keys of a user or group account."""
    keys: set[str] = set()
    for raw in (samaccountname, upn):
        stem = _account_stem(raw)
        if stem:
            keys.add(f"acct:{stem}")
    sid_key = _sid_key(sid)
    if sid_key:
        keys.add(sid_key)
    return frozenset(keys)


_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _label_keys(label: Any) -> set[str]:
    """Identity keys of a path node LABEL (``NAME@REALM``, ``HOST$@REALM``, an IP).

    A bare dotted label without ``@`` is a domain node, not an asset, and gives
    no key: matching it as a hostname is how a whole domain's routes used to be
    pinned on its domain controller.
    """
    raw = _clean(label)
    if not raw:
        return set()
    if _IPV4.match(raw):
        return {f"ip:{raw}"}
    if "@" not in raw:
        return set()
    stem = _account_stem(raw)
    return {f"acct:{stem}"} if stem and not stem.startswith("s-1-") else set()


def _step_endpoint_keys(details: Mapping[str, Any], side: str) -> set[str]:
    """Identity keys of one step endpoint from its stamped identity fields."""
    kind = _clean(details.get(f"{side}_kind")).lower()
    label = details.get("from" if side == "source" else "to")
    if kind and kind not in PRINCIPAL_TYPES:
        return set()
    sam = _clean(details.get(f"{side}_samaccountname"))
    entity = {
        "type": kind or ("computer" if _account_stem(label).endswith("$") else "user"),
        "sid": details.get(f"{side}_sid"),
        "identifier": sam,
        "fqdn": details.get(f"{side}_dnshostname"),
    }
    keys = set(entity_identity_keys(entity)) if (sam or entity["sid"] or entity["fqdn"]) else set()
    return keys | _label_keys(label)


def path_node_identity_keys(nodes: Any, steps: Any) -> frozenset[str]:
    """Identity keys of every asset that is a NODE on an attack path.

    Read from the path's node labels and from each step's stamped endpoint
    identity (SID, sAMAccountName, DNS host name, kind). Nothing else in the
    step is read: its details also carry the domain controller's name and
    address for every step of every path, so a text search over them attached
    a domain's routes to its DC even when the route never touches it.
    """
    keys: set[str] = set()
    if isinstance(nodes, list):
        for node in nodes:
            if isinstance(node, Mapping):
                keys |= _label_keys(node.get("label") or node.get("name") or node.get("id"))
            else:
                keys |= _label_keys(node)
    if isinstance(steps, list):
        for step in steps:
            if not isinstance(step, Mapping):
                continue
            details = step.get("details")
            if not isinstance(details, Mapping):
                continue
            keys |= _step_endpoint_keys(details, "source")
            keys |= _step_endpoint_keys(details, "target")
    return frozenset(keys)


# --------------------------------------------------------------------------- #
# Per-finding sides                                                            #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class FindingExposureInput:
    """One open finding, as the derivation needs it.

    Attributes:
        finding_id: Stable id of the finding (a database id or a catalog key).
        severity: The finding's ADscan severity (enum or string).
        details: The finding ``details`` mapping (carries the stamped entities
            and, for an attack-step finding, ``attack_graph_edges``).
    """

    finding_id: str
    severity: Any
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class FindingAssetSide:
    """One asset of one finding, on one side."""

    side: str
    entity_type: str
    display: str
    keys: frozenset[str]


def finding_asset_sides(details: Any) -> list[FindingAssetSide]:
    """Return the principals and hosts of a finding with the side each one is on.

    Only accounts, groups and computers are returned (a certificate template, a
    CA or the domain object is not an inventory asset). An edge SOURCE holds the
    right; every other role (the edge TARGET, or the affected object of a
    non-attack-step finding) is exposed. One object appears once per side.
    """
    sides: list[FindingAssetSide] = []
    seen: set[tuple[str, frozenset[str]]] = set()
    for entity in stamped_entities(details):
        etype = _clean(entity.get("type")).lower()
        # The role SSOT's counting rule: a display-only landing point and a
        # broad built-in identity on the exploit side (Authenticated Users
        # stands for every account) are shown, never counted.
        if etype not in PRINCIPAL_TYPES or not is_counted_object(entity):
            continue
        keys = entity_identity_keys(entity)
        if not keys:
            continue
        side = SIDE_HOLDS if entity_role(entity) == ROLE_SOURCE else SIDE_EXPOSED
        marker = (side, keys)
        if marker in seen:
            continue
        seen.add(marker)
        display = _clean(entity.get("display") or entity.get("identifier"))
        sides.append(FindingAssetSide(side=side, entity_type=etype, display=display, keys=keys))
    return sides


def finding_is_exploitable_step(details: Any) -> bool:
    """Return whether a finding is an attack step someone can carry out.

    True when the finding carries attack-graph edges (the engine linked it to a
    step in the graph) or when its stamped entities name a source or a target.
    """
    for scope in (details, details.get("details") if isinstance(details, Mapping) else None):
        if isinstance(scope, Mapping):
            edges = scope.get("attack_graph_edges")
            if isinstance(edges, list) and edges:
                return True
    return is_attack_step(stamped_entities(details))


# --------------------------------------------------------------------------- #
# Aggregation                                                                  #
# --------------------------------------------------------------------------- #


def _empty_severity_counts() -> dict[str, int]:
    return {level: 0 for level in SEVERITY_ORDER}


@dataclass
class SideTally:
    """Distinct findings on one side of one asset, with their severity mix."""

    finding_ids: set[str] = field(default_factory=set)
    severities: dict[str, int] = field(default_factory=_empty_severity_counts)

    def add(self, finding_id: str, severity: str) -> None:
        """Count a finding once."""
        if finding_id in self.finding_ids:
            return
        self.finding_ids.add(finding_id)
        self.severities[severity] = self.severities.get(severity, 0) + 1

    @property
    def count(self) -> int:
        """Number of distinct findings."""
        return len(self.finding_ids)


@dataclass
class AssetFindingExposure:
    """The finding-based exposure of one asset."""

    exposed: SideTally = field(default_factory=SideTally)
    holds: SideTally = field(default_factory=SideTally)
    severity_by_finding: dict[str, str] = field(default_factory=dict)

    @property
    def finding_ids(self) -> set[str]:
        """Every distinct finding the asset appears in, on either side."""
        return self.exposed.finding_ids | self.holds.finding_ids

    def side_of(self, finding_id: str) -> str:
        """``exposed``, ``holds``, ``both`` or ``""`` for a finding id."""
        exposed = finding_id in self.exposed.finding_ids
        holds = finding_id in self.holds.finding_ids
        if exposed and holds:
            return "both"
        if exposed:
            return SIDE_EXPOSED
        if holds:
            return SIDE_HOLDS
        return ""

    def union_severities(self) -> dict[str, int]:
        """Severity mix of every distinct finding on either side."""
        counts = _empty_severity_counts()
        for fid in self.finding_ids:
            level = self.severity_by_finding.get(fid, "info")
            counts[level] = counts.get(level, 0) + 1
        return counts

    def rank_key(self) -> tuple[int, ...]:
        """Internal ordering key (most exposed first when sorted descending).

        Not a client figure: it orders the cards, it is never displayed.
        """
        exp, hold = self.exposed.severities, self.holds.severities
        return (
            exp["critical"],
            exp["high"],
            self.exposed.count,
            hold["critical"],
            hold["high"],
            self.holds.count,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize for an API payload, with the client labels."""
        union = self.union_severities()
        return {
            "exposed_by_findings": self.exposed.count,
            "holds_risky_rights": self.holds.count,
            "exposed_by_severity": dict(self.exposed.severities),
            "holds_severity": dict(self.holds.severities),
            "open_findings": len(self.finding_ids),
            "critical_findings": union["critical"],
            "high_findings": union["high"],
            "labels": exposure_labels(self),
        }


class AssetExposureIndex:
    """Finding exposure of every asset of ONE domain, looked up by identity keys."""

    def __init__(self) -> None:
        self._records: list[AssetFindingExposure] = []
        self._by_key: dict[str, int] = {}

    def _record_for(self, keys: frozenset[str]) -> AssetFindingExposure:
        hits = sorted({self._by_key[k] for k in keys if k in self._by_key})
        if hits:
            index = hits[0]
            for other in hits[1:]:
                self._merge_into(index, other)
        else:
            index = len(self._records)
            self._records.append(AssetFindingExposure())
        for key in keys:
            self._by_key[key] = index
        return self._records[index]

    def _merge_into(self, keep: int, drop: int) -> None:
        target, source = self._records[keep], self._records[drop]
        for fid in source.exposed.finding_ids:
            target.exposed.add(fid, source.severity_by_finding.get(fid, "info"))
        for fid in source.holds.finding_ids:
            target.holds.add(fid, source.severity_by_finding.get(fid, "info"))
        target.severity_by_finding.update(source.severity_by_finding)
        for key, idx in list(self._by_key.items()):
            if idx == drop:
                self._by_key[key] = keep

    def add_finding(self, finding: FindingExposureInput) -> None:
        """Attribute one finding to each asset it names, once per side."""
        severity = normalize_severity(finding.severity)
        fid = str(finding.finding_id)
        for side in finding_asset_sides(finding.details):
            record = self._record_for(side.keys)
            record.severity_by_finding[fid] = severity
            tally = record.holds if side.side == SIDE_HOLDS else record.exposed
            tally.add(fid, severity)

    def lookup(self, keys: Iterable[str]) -> AssetFindingExposure:
        """Return the exposure of the asset with these identity keys (empty if none)."""
        hits = sorted({self._by_key[k] for k in keys if k in self._by_key})
        if not hits:
            return AssetFindingExposure()
        if len(hits) == 1:
            return self._records[hits[0]]
        merged = AssetFindingExposure()
        for idx in hits:
            record = self._records[idx]
            merged.severity_by_finding.update(record.severity_by_finding)
            for fid in record.exposed.finding_ids:
                merged.exposed.add(fid, record.severity_by_finding.get(fid, "info"))
            for fid in record.holds.finding_ids:
                merged.holds.add(fid, record.severity_by_finding.get(fid, "info"))
        return merged


def build_asset_exposure_index(findings: Iterable[FindingExposureInput]) -> AssetExposureIndex:
    """Build the per-asset exposure index of ONE domain's open findings."""
    index = AssetExposureIndex()
    for finding in findings:
        index.add_finding(finding)
    return index


def summarize_findings(findings: Iterable[FindingExposureInput]) -> dict[str, Any]:
    """Domain-level figures: open findings, how many are exploitable steps, severity mix."""
    total = 0
    exploitable = 0
    severities = _empty_severity_counts()
    seen: set[str] = set()
    for finding in findings:
        fid = str(finding.finding_id)
        if fid in seen:
            continue
        seen.add(fid)
        total += 1
        severities[normalize_severity(finding.severity)] += 1
        if finding_is_exploitable_step(finding.details):
            exploitable += 1
    return {
        "open_findings": total,
        "exploitable_findings": exploitable,
        "critical_findings": severities["critical"],
        "high_findings": severities["high"],
        "severity_counts": severities,
        "label": findings_summary_label(total, exploitable),
    }


# --------------------------------------------------------------------------- #
# Client copy                                                                  #
# --------------------------------------------------------------------------- #


def _plural(count: int, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


def severity_mix_label(counts: Mapping[str, int], *, include_low: bool = False) -> str:
    """Return ``"2 critical · 3 high"`` for the non-zero severities, most severe first."""
    levels = SEVERITY_ORDER[:4] if include_low else SEVERITY_ORDER[:3]
    parts = [f"{int(counts.get(level, 0))} {level}" for level in levels if int(counts.get(level, 0)) > 0]
    return " · ".join(parts)


def exposure_labels(exposure: AssetFindingExposure) -> dict[str, str]:
    """The client labels of one asset's exposure (empty strings for empty sides)."""
    exposed, holds = exposure.exposed.count, exposure.holds.count
    return {
        "exposed_by": f"Exposed by {_plural(exposed, 'finding', 'findings')}" if exposed else "",
        "exposed_mix": severity_mix_label(exposure.exposed.severities),
        "holds": f"Holds {_plural(holds, 'risky right', 'risky rights')}" if holds else "",
        "holds_mix": severity_mix_label(exposure.holds.severities),
    }


def findings_summary_label(total: int, exploitable: int) -> str:
    """Return ``"30 findings · 15 with an exploitable route"`` (domain card copy)."""
    head = _plural(total, "finding", "findings")
    if exploitable <= 0:
        return head
    return f"{head} · {exploitable} with an exploitable route"


__all__ = [
    "AssetExposureIndex",
    "AssetFindingExposure",
    "FindingAssetSide",
    "FindingExposureInput",
    "SEVERITY_ORDER",
    "SIDE_EXPOSED",
    "SIDE_HOLDS",
    "SideTally",
    "account_identity_keys",
    "build_asset_exposure_index",
    "computer_identity_keys",
    "entity_identity_keys",
    "exposure_labels",
    "finding_asset_sides",
    "finding_is_exploitable_step",
    "findings_summary_label",
    "host_identity_keys",
    "normalize_severity",
    "path_node_identity_keys",
    "severity_mix_label",
    "summarize_findings",
]
