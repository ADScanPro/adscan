"""Positive control evidence for an ENUMERATED attack surface.

Import-safe SSOT (stdlib + typing only) so ONE derivation serves every surface:

* the collector, which counts what it enumerated
  (``adscan_internal/services/collector/persistence.py``),
* the emitter that records it
  (``adscan_internal/services/positive_control_evidence.py``),
* the PRO deliverable (the compliance annex greens a control off the recorded
  entry; the AD Control Coverage Report lists the reading), and
* the paid Enterprise web CTEM
  (``adscan_web/backend/app/services/ingestion_service.py``), which cannot
  import ``adscan_internal`` across the tier boundary.

WHY THIS EXISTS. ``POSITIVE_CONTROL_KEYS`` held 24 keys, of which 2 covered the
TECHNIQUE surface and the other 22 were configuration reads and CVE probes. The
configuration layer is the one every directory-auditing product also reads, so
the positive-evidence surface was inverted against what ADscan alone can say:
it reported verified-OK where it is comparable and stayed silent where it is the
only tool that can speak, because asserting "that technique had no starting
point here" requires having enumerated the surface the technique starts from. A
client certifying at ENS MEDIA received a kit whose scorecard read
``0 verified clear``.

THE RULE THAT KEEPS IT HONEST, and it is the whole design: **the positive is the
ENUMERATION, never the absence of a finding.** "No roastable account in the
findings" is inferred by absence and must never render green. "Read the service
principal names of 412 enabled accounts, none publishes one" is an observation
with a method and a count. So the producer of a census is the service that did
the enumerating and therefore knows the count, and :func:`build_surface_evidence`
cannot reach ``observed`` without a non-zero ``examined``: a census that never
counted anything resolves to ``not_assessed`` whatever else it carries.

THREE STATES, ONE OF THEM GREEN (CLAUDE.md § "Persist the POSITIVE result too"):

* ``observed`` — the surface was enumerated, ``examined`` objects were read and
  none met an abusable condition. Green, persisted, greens its mapped controls.
* ``not_assessed`` — the surface was not enumerated at all, or its precondition
  is absent. Grey. **Never green**: an absent precondition makes its techniques
  not applicable, not healthy.
* no entry at all — the surface WAS enumerated and ``qualifying`` objects do meet
  the condition. That is a finding, and the findings channel already owns it;
  recording "not assessed" over a surface ADscan did assess would be false.

GRANULARITY is one aggregate key per catalogue ``category``, never one per
technique or per object: 111 green rows is noise nobody reads, and 2 gives the
differentiator away. Each definition declares which of its category's techniques
the enumeration COVERS and which it defers, so a green row can never be read as
covering more than the enumeration reached, and
``tests/unit/core/test_enumerated_surface_evidence.py`` fails if a catalogue
technique belongs to neither list.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

#: ``control_evidence`` category stamped on every enumerated-surface entry, so a
#: renderer can group these readings apart from the configuration positives.
ENUMERATED_SURFACE_CATEGORY = "Enumerated Attack Surface"

#: Status values the entry carries. They are the SAME vocabulary the compliance
#: engine keys on (``status == "observed"`` is its one green predicate), so a
#: ``not_assessed`` row is inert by construction rather than by a filter
#: somebody has to remember to write.
STATUS_OBSERVED = "observed"
STATUS_NOT_ASSESSED = "not_assessed"

#: Why a surface resolved to ``not_assessed``. Carried in the entry details so an
#: auditor reads the reason rather than inferring one.
REASON_NOT_ENUMERATED = "surface_not_enumerated"
REASON_PRECONDITION_ABSENT = "precondition_absent"


@dataclass(frozen=True)
class SurfaceDefinition:
    """One catalogue category's enumerated-surface contract.

    Args:
        surface: The catalogue ``category`` value this aggregates.
        key: The positive-control key recorded into ``control_evidence``.
        title: Client-facing row title.
        method: Short client-facing phrase naming HOW the surface was read.
        evidence_template: The client-facing sentence. Formatted with
            ``examined``, ``examined_unit``, ``secondary`` and
            ``secondary_unit``, so the delivered prose always carries the method
            and the measured count.
        boundary: One sentence naming what this reading does NOT cover, appended
            when the definition defers techniques. Without it a green row reads
            as covering the whole category.
        covered_techniques: Catalogue keys the enumeration speaks to.
        deferred_techniques: Catalogue keys of the same category it does not.
    """

    surface: str
    key: str
    title: str
    method: str
    evidence_template: str
    unit_singular: str
    unit_plural: str
    covered_techniques: tuple[str, ...]
    deferred_techniques: tuple[str, ...] = ()
    boundary: str = ""
    secondary_singular: str = ""
    secondary_plural: str = ""


#: ACL / ACE delegation. The LDAP collector parses one security descriptor per
#: directory object it reads, so the count of descriptors parsed IS the surface
#: denominator, and an ACE-derived right held by a principal outside Tier 0 is
#: the abusable condition every technique in the category starts from.
_ACL_ACE = SurfaceDefinition(
    surface="acl_ace",
    key="delegated_object_rights_absent",
    title="Delegated Object Rights Confined to Tier 0",
    method="security descriptor read on every enumerated directory object",
    evidence_template=(
        "ADscan read the security descriptor of {examined} {examined_unit} and "
        "evaluated {secondary} {secondary_unit}. None grants a write, ownership "
        "or extended right over a directory object to a principal outside the "
        "Tier 0 administrative set, so no object-permission escalation was "
        "available from an ordinary account."
    ),
    unit_singular="directory object",
    unit_plural="directory objects",
    secondary_singular="access control entry",
    secondary_plural="access control entries",
    covered_techniques=(
        "addkeycredentiallink",
        "addmember",
        "addself",
        "allextendedrights",
        "forcechangepassword",
        "genericall",
        "genericwrite",
        "managerodcprp",
        "owns",
        "readgmsapassword",
        "readlapspassword",
        "synclapspassword",
        "writeaccountrestrictions",
        "writedacl",
        "writelogonscript",
        "writeowner",
        "writespn",
    ),
    # A writable SMB path is a filesystem right, not a directory ACE, so the
    # directory-wide descriptor read says nothing about it.
    deferred_techniques=("writesmbpath",),
    boundary=(
        "This reading covers rights held in the directory. Writable file shares "
        "are assessed separately."
    ),
)

#: Directory-side credential exposure. The collector evaluates every eligible
#: principal's intrinsic token against the replication right on the domain
#: object, so it knows both how many it evaluated and which hold it. The host
#: side of the category (reading credentials out of an individual machine) is
#: not an enumeration and is deferred explicitly.
_CREDENTIAL_ACCESS = SurfaceDefinition(
    surface="credential_access",
    key="directory_replication_rights_confined",
    title="Directory Replication Rights Confined to Tier 0",
    method="replication rights evaluated on the domain object per principal",
    evidence_template=(
        "ADscan evaluated the directory replication rights of {examined} "
        "{examined_unit} against the domain object, including the rights each "
        "principal carries through its own well-known group membership. Only "
        "Tier 0 administrative principals hold them, so no ordinary account can "
        "replicate the domain's password hashes."
    ),
    unit_singular="directory principal",
    unit_plural="directory principals",
    covered_techniques=(
        "dcsync",
        "getchanges",
        "getchangesall",
        "getchangesinfilteredset",
    ),
    deferred_techniques=(
        "domainpassreuse",
        "dumpdpapi",
        "dumplsa",
        "dumplsass",
        "dumpsam",
        "extractrodckrbtgtsecret",
        "hasshadowcredentials",
        "localcredtodomainreuse",
        "mssql_ntlmv2_theft",
        "poisoncapturentlmv2crack",
        "readshare",
        "timeroasting",
    ),
    boundary=(
        "This reading covers the directory permission. Credential extraction "
        "from individual hosts is assessed separately."
    ),
)

#: Offline Kerberos cracking. The collector walks every enabled, non-managed
#: user account and reads the two attributes that expose one to an offline
#: crack, so the walk is the enumeration and its two conditions are the
#: abusable ones.
_KERBEROS = SurfaceDefinition(
    surface="kerberos",
    key="kerberos_roastable_accounts_absent",
    title="No Accounts Exposed to Offline Kerberos Cracking",
    method=(
        "service principal name and pre-authentication setting read per enabled "
        "user account"
    ),
    evidence_template=(
        "ADscan read the service principal names and the pre-authentication "
        "setting of {examined} enabled {examined_unit}. None publishes a service "
        "principal name and all require Kerberos pre-authentication, so no "
        "account ticket can be requested and cracked offline."
    ),
    unit_singular="user account",
    unit_plural="user accounts",
    covered_techniques=("asreproasting", "kerberoasting"),
    # Both are post-compromise persistence off a read-only domain controller's
    # own secret, not a property of a user account this walk reads.
    deferred_techniques=("forgerodcgoldenticket", "kerberoskeylist"),
    boundary=(
        "This reading covers the accounts an ordinary user can request tickets "
        "for. Secrets held by a read-only domain controller are assessed "
        "separately."
    ),
)


#: The declared surfaces, keyed by catalogue ``category``.
ENUMERATED_SURFACE_DEFINITIONS: dict[str, SurfaceDefinition] = {
    _ACL_ACE.surface: _ACL_ACE,
    _CREDENTIAL_ACCESS.surface: _CREDENTIAL_ACCESS,
    _KERBEROS.surface: _KERBEROS,
}

#: The positive-control keys these surfaces record. ``POSITIVE_CONTROL_KEYS``
#: derives from this tuple rather than re-declaring it, so the key universe and
#: the producer can never disagree about what exists.
ENUMERATED_SURFACE_POSITIVE_KEYS: tuple[str, ...] = tuple(
    definition.key
    for definition in sorted(
        ENUMERATED_SURFACE_DEFINITIONS.values(), key=lambda item: item.key
    )
)


@dataclass
class SurfaceTally:
    """What one enumerating pass counted.

    Deliberately a counter the enumerating loop drives, not a shape a later pass
    reconstructs: ``examined`` only ever moves when real code looked at a real
    object, which is what makes the resulting green an observation.

    Attributes:
        surface: The catalogue ``category`` being counted.
        examined: Objects the enumeration looked at.
        qualifying: Of those, how many met the abusable condition.
        secondary: An optional second denominator the sentence names (ACEs
            evaluated, for the ACL surface).
        enumerated: Whether the pass ran at all.
        precondition_absent: Whether the surface cannot exist here (no such
            object class collected), which is not applicable and never healthy.
        reason: Free-text note persisted alongside a non-green outcome.
    """

    surface: str
    examined: int = 0
    qualifying: int = 0
    secondary: int = 0
    enumerated: bool = False
    precondition_absent: bool = False
    reason: str = ""

    def record(self, *, qualifying: bool = False) -> None:
        """Count one examined object, and whether it met the abusable condition."""
        self.enumerated = True
        self.examined += 1
        if qualifying:
            self.qualifying += 1

    def record_qualifying(self, count: int = 1) -> None:
        """Add ``count`` abusable objects without moving ``examined``.

        For a pass whose denominator and whose abusable set are counted in
        different loops (the ACL surface reads descriptors in the collector and
        judges the derived rights at persistence).
        """
        if count > 0:
            self.qualifying += count

    def note_enumerated(self, *, examined: int, secondary: int = 0) -> None:
        """Adopt a denominator a lower layer already counted."""
        if examined > 0:
            self.enumerated = True
        self.examined = max(self.examined, int(examined))
        self.secondary = max(self.secondary, int(secondary))

    def note_precondition_absent(self, reason: str) -> None:
        """Mark the surface as not applicable here, never as healthy."""
        self.precondition_absent = True
        self.reason = reason

    def as_census(self) -> dict[str, Any]:
        """Return the JSON-safe census the emitter consumes."""
        return {
            "surface": self.surface,
            "examined": int(self.examined),
            "qualifying": int(self.qualifying),
            "secondary": int(self.secondary),
            "enumerated": bool(self.enumerated),
            "precondition_absent": bool(self.precondition_absent),
            "reason": str(self.reason or ""),
        }


@dataclass(frozen=True)
class SurfaceEvidence:
    """One ``control_evidence`` entry, ready for the recorder."""

    key: str
    title: str
    category: str
    status: str
    details: dict[str, Any] = field(default_factory=dict)


def _plural(count: int, singular: str, plural: str) -> str:
    return singular if count == 1 else plural


def _definition_for(census: Mapping[str, Any]) -> SurfaceDefinition | None:
    surface = str(census.get("surface") or "").strip()
    return ENUMERATED_SURFACE_DEFINITIONS.get(surface)


def render_surface_sentence(
    definition: SurfaceDefinition, examined: int, secondary: int = 0
) -> str:
    """Return the client-facing sentence for one cleared surface.

    Always carries the method and the measured count, which is what separates
    the statement from an absence. The boundary sentence is appended when the
    definition defers part of its category, so the row cannot be read as
    covering techniques the enumeration never reached.
    """
    body = definition.evidence_template.format(
        examined=examined,
        examined_unit=_plural(
            examined, definition.unit_singular, definition.unit_plural
        ),
        secondary=secondary,
        secondary_unit=_plural(
            secondary, definition.secondary_singular, definition.secondary_plural
        ),
    )
    if definition.boundary:
        return f"{body} {definition.boundary}"
    return body


def build_surface_evidence(census: Mapping[str, Any]) -> SurfaceEvidence | None:
    """Resolve one census into the entry to record, or ``None``.

    THE HONESTY GATE lives here and nowhere else: ``observed`` requires an
    enumeration that ran AND a non-zero ``examined``. A census that counted
    nothing cannot go green however it is shaped, so a key can never be greened
    off an empty finding list.

    Returns:
        A ``observed`` entry for a surface enumerated and clear; a
        ``not_assessed`` entry for a surface not enumerated or whose
        precondition is absent; ``None`` when the surface was enumerated and
        abusable objects were found, because that is a finding and the findings
        channel owns it.
    """
    definition = _definition_for(census)
    if definition is None:
        return None

    try:
        examined = int(census.get("examined") or 0)
        qualifying = int(census.get("qualifying") or 0)
        secondary = int(census.get("secondary") or 0)
    except (TypeError, ValueError):
        return None

    enumerated = bool(census.get("enumerated")) and examined > 0
    precondition_absent = bool(census.get("precondition_absent"))
    reason = str(census.get("reason") or "").strip()

    details: dict[str, Any] = {
        "surface": definition.surface,
        "method": definition.method,
        "objects_examined": examined,
        "objects_qualifying": qualifying,
        "techniques_covered": list(definition.covered_techniques),
        "techniques_not_assessed": list(definition.deferred_techniques),
    }
    if secondary:
        details["entries_examined"] = secondary

    if not enumerated or precondition_absent:
        details["not_assessed_reason"] = (
            REASON_PRECONDITION_ABSENT if precondition_absent else REASON_NOT_ENUMERATED
        )
        if reason:
            details["observation"] = reason
        return SurfaceEvidence(
            key=definition.key,
            title=definition.title,
            category=ENUMERATED_SURFACE_CATEGORY,
            status=STATUS_NOT_ASSESSED,
            details=details,
        )

    if qualifying > 0:
        return None

    details["evidence"] = render_surface_sentence(definition, examined, secondary)
    return SurfaceEvidence(
        key=definition.key,
        title=definition.title,
        category=ENUMERATED_SURFACE_CATEGORY,
        status=STATUS_OBSERVED,
        details=details,
    )


def read_enumerated_surface_coverage(
    domain_blocks: Iterable[tuple[str, Mapping[str, Any]]],
) -> dict[str, Any]:
    """Read the recorded enumerated-surface rows out of persisted domain blocks.

    The shared reader BOTH the PRO deliverable and the web CTEM consume, so
    neither re-derives a state nor re-authors a sentence. One row per surface
    key, carrying the domains it was recorded in.

    Args:
        domain_blocks: ``(domain, technical_report domain block)`` pairs.

    Returns:
        ``{"present": bool, "surfaces": [...]}``. ``present`` is False when no
        row was recorded, so a surface nothing ever enumerated renders as
        nothing rather than as a reassuring zero.
    """
    by_key: dict[str, dict[str, Any]] = {}
    declared = {
        definition.key: definition
        for definition in ENUMERATED_SURFACE_DEFINITIONS.values()
    }
    for domain, block in domain_blocks or ():
        if not isinstance(block, Mapping):
            continue
        entries = block.get("control_evidence")
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, Mapping):
                continue
            key = str(entry.get("key") or "").strip()
            definition = declared.get(key)
            if definition is None:
                continue
            status = str(entry.get("status") or "").strip().lower()
            if status not in (STATUS_OBSERVED, STATUS_NOT_ASSESSED):
                continue
            details = entry.get("details")
            details = details if isinstance(details, Mapping) else {}
            row = by_key.setdefault(
                key,
                {
                    "key": key,
                    "surface": definition.surface,
                    "title": str(entry.get("title") or definition.title),
                    "status": status,
                    "evidence": str(details.get("evidence") or "").strip(),
                    "method": str(details.get("method") or definition.method),
                    "objects_examined": details.get("objects_examined"),
                    "entries_examined": details.get("entries_examined"),
                    "not_assessed_reason": str(
                        details.get("not_assessed_reason") or ""
                    ),
                    "techniques_covered": list(definition.covered_techniques),
                    "techniques_not_assessed": list(definition.deferred_techniques),
                    "domains": [],
                },
            )
            # An observed reading in ANY domain outranks a not_assessed one: the
            # surface demonstrably was enumerated somewhere.
            if status == STATUS_OBSERVED and row["status"] != STATUS_OBSERVED:
                row["status"] = STATUS_OBSERVED
                row["evidence"] = str(details.get("evidence") or "").strip()
                row["objects_examined"] = details.get("objects_examined")
                row["entries_examined"] = details.get("entries_examined")
                row["not_assessed_reason"] = ""
            domain_name = str(domain or "").strip()
            if domain_name and domain_name not in row["domains"]:
                row["domains"].append(domain_name)

    surfaces = [by_key[key] for key in sorted(by_key)]
    return {"present": bool(surfaces), "surfaces": surfaces}


__all__ = [
    "ENUMERATED_SURFACE_CATEGORY",
    "ENUMERATED_SURFACE_DEFINITIONS",
    "ENUMERATED_SURFACE_POSITIVE_KEYS",
    "REASON_NOT_ENUMERATED",
    "REASON_PRECONDITION_ABSENT",
    "STATUS_NOT_ASSESSED",
    "STATUS_OBSERVED",
    "SurfaceDefinition",
    "SurfaceEvidence",
    "SurfaceTally",
    "build_surface_evidence",
    "read_enumerated_surface_coverage",
    "render_surface_sentence",
]
