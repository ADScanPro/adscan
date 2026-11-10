"""What one positive control-evidence record may claim, decided in one place.

A ``control_evidence`` record (``technical_report.json`` ->
``domains[<d>]["control_evidence"]``) is what turns a compliance control green.
For most keys the recorder already wrote an observed-good verdict, and the
record is the whole story. Two kinds of record are not:

* **Per-host records** carry ``hosts_conformant`` / ``hosts_assessed``. A record
  that says "observed hardened on 1 of 2 hosts" is not evidence that the control
  holds. It is evidence that it holds on one host and was not confirmed on the
  other, and greening a control on that is the false assurance the third-state
  doctrine (``CLAUDE.md`` § "Persist the POSITIVE result too") forbids.
* **Anti-malware** (``endpoint_protection_present``) has a richer per-host truth
  than its own record: the endpoint-defense block the report prints in its own
  section classifies every examined host as active, installed but not active,
  none detected or undetermined, and states how many computers were not
  examined at all. The 14.0.0 release gate found ENS op.exp.6, ISO A.8.7 and
  PCI DSS Req. 5 rendered conformant on "antivirus seen on 1 of 2 hosts" while
  the same report's Endpoint Defense section said the other host's antivirus was
  installed and not running. The compliance verdict now reads that block, so the
  two sections cannot disagree.

So this module answers, for one record, one of four verdicts:

``observed_good``
    Green. Every host the claim covers was observed in the hardened state.
``contradicted``
    A non-conformity: a host was OBSERVED in the opposite state (an antivirus
    installed and not running). It names the hosts, because a non-conformity the
    reader cannot act on is not one.
``incomplete``
    Neither: some hosts were not observed (not examined, nothing detected, the
    check could not complete). Never green and never a gap, because "we could
    not see it" is not a finding. The control carries no verdict from this
    record and the statement says why.
``ignored``
    Not positive evidence at all (another status, an empty key).

Pure logic, stdlib only plus the endpoint-defense vocabulary, so the web
backend can import it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from adscan_core.reporting.endpoint_defense import (
    ENDPOINT_DEFENSE_KEY,
    POSTURE_ACTIVE,
    POSTURE_INSTALLED_INACTIVE,
    POSTURE_NONE_DETECTED,
    POSTURE_UNDETERMINED,
)

VERDICT_OBSERVED_GOOD = "observed_good"
VERDICT_CONTRADICTED = "contradicted"
VERDICT_INCOMPLETE = "incomplete"
VERDICT_IGNORED = "ignored"

#: The ``control_evidence`` statuses a recorder may write for a positive key.
#: ``observed`` is the only one that can turn a control green. ``contradicted``
#: and ``incomplete`` are written by a recorder that already knows the claim
#: does not hold everywhere, so a stale reader that only greens on
#: ``observed`` can never be misled by them.
STATUS_OBSERVED = "observed"
STATUS_CONTRADICTED = "contradicted"
STATUS_INCOMPLETE = "incomplete"

#: The anti-malware key, whose per-host truth is the endpoint-defense block.
ANTI_MALWARE_CONTROL_KEY = "endpoint_protection_present"

#: How many hosts a statement names before it summarises the rest.
_HOSTS_NAMED = 6


@dataclass(frozen=True)
class ControlVerdict:
    """What one control-evidence record may claim."""

    verdict: str
    #: The client sentence that states what was observed. Empty for ``ignored``.
    statement: str = ""
    #: Hosts observed in the opposite state (``contradicted`` only).
    contrary_hosts: tuple[str, ...] = field(default_factory=tuple)
    #: Hosts observed in the hardened state, for a per-host reading.
    observed_hosts: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_observed_good(self) -> bool:
        return self.verdict == VERDICT_OBSERVED_GOOD


def display_host(value: Any) -> str:
    """Return a host the way client prose names it: lower-case, as recorded.

    A computer account (``WINTERFELL$``) and a DNS name
    (``CASTELBLACK.NORTH.EXAMPLE``) are both case-insensitive in AD, and a
    directory that stores them upper-case is no licence to shout them.
    """
    return str(value or "").strip().lower()


def _name_hosts(hosts: list[str]) -> str:
    named = [h for h in hosts if h][:_HOSTS_NAMED]
    rest = max(0, len([h for h in hosts if h]) - len(named))
    text = ", ".join(named)
    if rest:
        text += f" and {rest:,} more"
    return text


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _record_hosts(control: Mapping[str, Any]) -> list[str]:
    hosts: list[str] = []
    for item in control.get("evidence") or ():
        if isinstance(item, Mapping):
            host = display_host(item.get("host"))
            if host and host not in hosts:
                hosts.append(host)
    return hosts


def _plural(count: int, singular: str, plural: str | None = None) -> str:
    return singular if count == 1 else (plural or f"{singular}s")


def anti_malware_verdict_from_block(block: Mapping[str, Any]) -> ControlVerdict | None:
    """Decide the anti-malware verdict from the endpoint-defense block.

    Args:
        block: ``domains[<d>]["endpoint_defense"]`` as
            :func:`adscan_core.reporting.endpoint_defense.build_endpoint_defense`
            persisted it.

    Returns:
        The verdict, or ``None`` when the block carries no examined host (the
        caller then falls back to the record itself).
    """
    hosts = [h for h in (block.get("hosts") or ()) if isinstance(h, Mapping)]
    if not hosts:
        return None
    active: list[str] = []
    inactive: list[tuple[str, list[str]]] = []
    unconfirmed: list[str] = []
    for host in hosts:
        name = display_host(host.get("host"))
        posture = str(host.get("posture") or "").strip().lower()
        if posture == POSTURE_ACTIVE:
            active.append(name)
        elif posture == POSTURE_INSTALLED_INACTIVE:
            products = [
                str(p).strip()
                for p in (host.get("inactive_products") or host.get("products") or ())
                if str(p).strip()
            ]
            inactive.append((name, products))
        elif posture in (POSTURE_NONE_DETECTED, POSTURE_UNDETERMINED):
            unconfirmed.append(name)
        else:
            unconfirmed.append(name)
    not_examined = max(0, _as_int(block.get("hosts_not_examined")) or 0)
    examined = len(hosts)

    if inactive:
        clauses = []
        for name, products in inactive[:_HOSTS_NAMED]:
            product_text = " and ".join(products) if products else "an antivirus product"
            clauses.append(f"{product_text} is installed and not running on {name}")
        rest = len(inactive) - len(clauses)
        sentence = "; ".join(clauses)
        if rest:
            sentence += f"; the same holds on {rest:,} more {_plural(rest, 'host')}"
        statement = (
            f"{sentence[:1].upper()}{sentence[1:]}, and no other active protection "
            f"product was detected on {_plural(len(inactive), 'that host', 'those hosts')}."
        )
        if active:
            statement += f" Protection was observed active on {_name_hosts(active)}."
        if unconfirmed:
            statement += f" It could not be confirmed on {_name_hosts(unconfirmed)}."
        return ControlVerdict(
            verdict=VERDICT_CONTRADICTED,
            statement=statement,
            contrary_hosts=tuple(name for name, _ in inactive),
        )

    if unconfirmed or not_examined:
        parts = []
        if active:
            parts.append(
                f"observed active on {len(active):,} of {examined:,} examined "
                f"{_plural(examined, 'host')} ({_name_hosts(active)})"
            )
        else:
            parts.append("observed active on no examined host")
        if unconfirmed:
            parts.append(
                f"not confirmed on {_name_hosts(unconfirmed)}, where no product "
                "was detected or its protection state could not be read"
            )
        if not_examined:
            parts.append(
                f"{not_examined:,} {_plural(not_examined, 'computer')} in the "
                f"directory {_plural(not_examined, 'was', 'were')} not examined"
            )
        statement = (
            "Anti-malware protection was "
            + ", ".join(parts)
            + ". A control is credited only when every host it covers was observed "
            "protected, so this one carries no verdict from this evidence."
        )
        return ControlVerdict(verdict=VERDICT_INCOMPLETE, statement=statement)

    return ControlVerdict(
        verdict=VERDICT_OBSERVED_GOOD,
        statement=(
            f"Anti-malware protection was observed active on every computer in "
            f"the directory ({examined:,}): {_name_hosts(active)}."
        ),
        observed_hosts=tuple(active),
    )


def _record_verdict(control: Mapping[str, Any]) -> ControlVerdict:
    """Decide a record's verdict from the record alone."""
    status = str(control.get("status") or "").strip().lower()
    details = control.get("details") if isinstance(control.get("details"), Mapping) else {}
    evidence_text = str(details.get("evidence") or "").strip()
    hosts = _record_hosts(control)

    if status == STATUS_CONTRADICTED:
        contrary = [
            display_host(item.get("host") if isinstance(item, Mapping) else item)
            for item in (details.get("hosts_contrary") or ())
        ]
        contrary = [h for h in contrary if h]
        return ControlVerdict(
            verdict=VERDICT_CONTRADICTED,
            statement=evidence_text,
            contrary_hosts=tuple(contrary),
        )
    if status == STATUS_INCOMPLETE:
        return ControlVerdict(verdict=VERDICT_INCOMPLETE, statement=evidence_text)
    if status != STATUS_OBSERVED:
        return ControlVerdict(verdict=VERDICT_IGNORED)

    conformant = _as_int(details.get("hosts_conformant"))
    assessed = _as_int(details.get("hosts_assessed"))
    if conformant is not None and assessed is not None and conformant < assessed:
        named = f" ({_name_hosts(hosts)})" if hosts else ""
        return ControlVerdict(
            verdict=VERDICT_INCOMPLETE,
            statement=(
                f"Observed on {conformant:,} of {assessed:,} assessed "
                f"{_plural(assessed, 'host')}{named}. A control is credited only "
                "when every host it covers was observed in the hardened state, so "
                "this one carries no verdict from this evidence."
            ),
        )
    statement = evidence_text
    if hosts:
        statement = (statement + " " if statement else "") + f"Hosts: {_name_hosts(hosts)}."
    return ControlVerdict(
        verdict=VERDICT_OBSERVED_GOOD, statement=statement, observed_hosts=tuple(hosts)
    )


def positive_evidence_basis(
    observed: list[Mapping[str, Any]],
    *,
    extra: str = "",
    controls_named: int = 3,
) -> str:
    """Return the short sentence a conformant control states as its basis.

    One entry per observed-good reading, by its title, with the hosts it was
    read on when it is a per-host reading: "Observed: WDigest Disabled on
    castelblack$, winterfell$; LDAPS Available." Kept short on purpose, because
    it prints on a control card with a fixed box; the full sentence per reading
    is in the AD Control Coverage Report. ``extra`` is appended verbatim (the
    coverage-check basis).
    """
    parts: list[str] = []
    for item in observed:
        if not isinstance(item, Mapping):
            continue
        title = str(item.get("title") or "").strip()
        if not title:
            continue
        hosts = [display_host(h) for h in (item.get("observed_hosts") or ()) if str(h).strip()]
        entry = f"{title} on {_name_hosts(hosts)}" if hosts else title
        if entry not in parts:
            parts.append(entry)
    text = ""
    if parts:
        shown = parts[:controls_named]
        rest = len(parts) - len(shown)
        text = "Observed: " + "; ".join(shown)
        if rest:
            text += (
                f"; and {rest} more {_plural(rest, 'reading')} listed in the AD "
                "Control Coverage Report"
            )
        text += "."
    if extra:
        text = f"{text} {extra}".strip()
    return text


def resolve_control_verdict(
    control: Mapping[str, Any],
    domain_data: Mapping[str, Any] | None = None,
) -> ControlVerdict:
    """Return what one control-evidence record may claim.

    Args:
        control: One ``control_evidence`` entry.
        domain_data: The domain block the record belongs to. Read for the
            endpoint-defense block when the record is the anti-malware one.

    Returns:
        The :class:`ControlVerdict`. Never raises on a malformed record: it is
        ``ignored``.
    """
    if not isinstance(control, Mapping):
        return ControlVerdict(verdict=VERDICT_IGNORED)
    key = str(control.get("key") or "").strip()
    if not key:
        return ControlVerdict(verdict=VERDICT_IGNORED)
    status = str(control.get("status") or "").strip().lower()
    if status not in (STATUS_OBSERVED, STATUS_CONTRADICTED, STATUS_INCOMPLETE):
        return ControlVerdict(verdict=VERDICT_IGNORED)
    if key == ANTI_MALWARE_CONTROL_KEY and isinstance(domain_data, Mapping):
        block = domain_data.get(ENDPOINT_DEFENSE_KEY)
        if isinstance(block, Mapping):
            verdict = anti_malware_verdict_from_block(block)
            if verdict is not None:
                return verdict
    return _record_verdict(control)


__all__ = [
    "ANTI_MALWARE_CONTROL_KEY",
    "ControlVerdict",
    "STATUS_CONTRADICTED",
    "STATUS_INCOMPLETE",
    "STATUS_OBSERVED",
    "VERDICT_CONTRADICTED",
    "VERDICT_IGNORED",
    "VERDICT_INCOMPLETE",
    "VERDICT_OBSERVED_GOOD",
    "anti_malware_verdict_from_block",
    "display_host",
    "positive_evidence_basis",
    "resolve_control_verdict",
]
