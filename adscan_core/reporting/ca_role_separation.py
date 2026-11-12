"""Segregation of duties on an AD CS certification authority, decided in one place.

A Windows certification authority knows two administrative roles: CA
Administrator (the ``ManageCA`` right) and Certificate Manager (the
``ManageCertificates`` right, the officer who approves and issues requests).
Role separation (``CAINFO.lRoleSeparationEnabled``, [MS-WCCE] 3.2.1.4.3.2.23)
makes the CA refuse every request from an account that holds more than one
role. It is off by default almost everywhere, and a local administrator of the
CA host can turn it off again (``certutil -setreg CA\\RoleSeparationEnabled 0``
and a service restart), so it is not an attack control and it is NOT reported
as a vulnerability. Its value is governance: it is the CA's own enforcement of
segregation of duties, which ISO/IEC 27001:2022 A.5.3, ENS op.acc.3, DORA
Art. 9(4)(c) (as developed by Delegated Regulation (EU) 2024/1774 Art. 21(b))
and NIS2 Art. 21(2)(i) (as developed by Implementing Regulation (EU) 2024/2690
Annex 11.2.2(a)) all ask for.

So this module turns what the scan READ about each CA into ONE
``control_evidence`` record per domain, with four outcomes per CA:

``enforced``
    The CA reported role separation on. Conformant evidence.
``roles_combined``
    The CA reported role separation off AND one principal holds both roles
    directly on the CA's security descriptor. A non-conformity naming the CA and
    the principal, because one account can configure the CA and approve the
    certificates it issues.
``separated_in_practice``
    The CA reported role separation off, the descriptor was read, and no
    principal holds both roles. Segregation holds by assignment, not by the CA:
    a note, never a pass and never a gap.
``not_read``
    The flag was not read, or it read off and the descriptor could not be read,
    so who holds the roles is unknown. Not assessed, never green.

**Built-in domain administration identities are not counted as a conflict.**
Administrators, Domain Admins, Enterprise Admins, the domain's Administrator
account and the system account hold both roles on every CA by default. They
administer the CA host itself, so they can lift role separation whenever they
choose, and the CA cannot segregate their duties whatever its setting. Their
privilege is governed by the privileged-access controls (A.8.2, op.acc.4), not
by segregation of duties. Counting them would make every default installation
non-conformant, which is the noise the founder ruled out. Whether a holder is
one of them is decided by the caller from the Privilege Tier SSOT (Tier 0
direct by its OWN identity) and carried in :attr:`Holder.tier0_by_definition`;
this module never classifies a principal by name. An account or group someone
granted the roles to by hand is always counted, even when it is privileged,
because that grant is a choice the client can revert.

Only the DIRECT trustees of the CA's descriptor are compared. A principal that
holds the two roles through two different groups is not detected here.

Pure logic, stdlib only, so every tier and the web backend can import it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

#: The ``control_evidence`` key this module produces.
CONTROL_KEY = "ca_role_separation_enforced"

#: Title when every CA enforces the separation, and the neutral one otherwise
#: (a contradicted card titled "Enforced" would contradict its own statement).
TITLE_ENFORCED = "AD CS Role Separation Enforced"
TITLE_NEUTRAL = "AD CS Role Separation"
CATEGORY = "Certificate Services"

#: The CA node property the collector stamps (``adcs_collector``).
READING_PROPERTY = "role_separation_reading"
READING_ATTEMPTED = "attempted"
READING_FLAG = "role_separation"
READING_SECURITY_READ = "security_read"
READING_ADMINS = "ca_administrators"
READING_OFFICERS = "certificate_managers"

#: Where the flag came from: the scan account's own read, or the read the
#: cleanup account's reversal-capability probe made in the same run.
FLAG_SOURCE_SCAN = "scan_account"
FLAG_SOURCE_CLEANUP = "cleanup_account"

STATE_ENFORCED = "enforced"
STATE_ROLES_COMBINED = "roles_combined"
STATE_SEPARATED_IN_PRACTICE = "separated_in_practice"
STATE_NOT_READ = "not_read"

#: ``control_evidence`` statuses, mirrored from ``control_evidence_verdict`` so
#: this module stays importable without it. ``not_assessed`` is ignored by the
#: compliance engine (the control stays grey), and it overwrites a stale reading.
STATUS_OBSERVED = "observed"
STATUS_CONTRADICTED = "contradicted"
STATUS_INCOMPLETE = "incomplete"
STATUS_NOT_ASSESSED = "not_assessed"

#: ``details`` flag that marks an incomplete record whose only reason is a CA
#: that does not enforce the separation while the roles are separated anyway.
#: The compliance engine states that case with its own not-assessed reason.
HOLDS_IN_PRACTICE_DETAIL = "holds_in_practice"

_UNRESOLVED_NAME = "an account whose name could not be resolved"


@dataclass(frozen=True)
class Holder:
    """One direct trustee of a CA role."""

    sid: str
    #: Client display name; empty when the SID could not be resolved.
    name: str = ""
    #: A built-in domain administration identity (Tier 0 direct by its own SID).
    tier0_by_definition: bool = False

    @property
    def display(self) -> str:
        return self.name or _UNRESOLVED_NAME


@dataclass(frozen=True)
class CaReading:
    """What the scan read about one CA this domain owns."""

    ca_name: str
    ca_host: str
    #: 1 or 0 when the CA answered definitively, ``None`` otherwise.
    role_separation: int | None = None
    flag_source: str = ""
    #: Whether the CA's security descriptor was read.
    security_read: bool = False
    administrators: tuple[Holder, ...] = ()
    certificate_managers: tuple[Holder, ...] = ()


@dataclass(frozen=True)
class CaRoleState:
    """One CA's outcome."""

    reading: CaReading
    state: str
    #: The counted principals holding both roles (``roles_combined`` only).
    combined: tuple[Holder, ...] = ()
    #: Whether only built-in administration identities hold both roles.
    builtin_only_overlap: bool = False


@dataclass(frozen=True)
class SegregationEvidence:
    """The domain-level record :func:`build_segregation_evidence` produces."""

    status: str
    title: str
    statement: str
    holds_in_practice: bool
    contrary_hosts: tuple[str, ...]
    cas: tuple[CaRoleState, ...] = field(default_factory=tuple)

    def details(self) -> dict[str, Any]:
        """The record's ``details``, with every key this module owns set.

        ``record_control_evidence`` merges ``details`` into the stored entry, so
        a key left unset here would keep a previous run's value.
        """
        return {
            "source": "adcs_ca_role_separation",
            "evidence": self.statement,
            HOLDS_IN_PRACTICE_DETAIL: self.holds_in_practice,
            "hosts_contrary": list(self.contrary_hosts),
            "certification_authorities": [
                {
                    "name": s.reading.ca_name,
                    "host": s.reading.ca_host,
                    "state": s.state,
                    "role_separation": s.reading.role_separation,
                    "flag_source": s.reading.flag_source,
                    "security_read": s.reading.security_read,
                    "principals_holding_both_roles": [h.display for h in s.combined],
                }
                for s in self.cas
            ],
        }


def ca_role_state(reading: CaReading) -> CaRoleState:
    """Decide one CA's outcome from what was read."""
    if reading.role_separation == 1:
        return CaRoleState(reading=reading, state=STATE_ENFORCED)
    if reading.role_separation != 0 or not reading.security_read:
        return CaRoleState(reading=reading, state=STATE_NOT_READ)
    officers = {h.sid.upper() for h in reading.certificate_managers if h.sid}
    both = [h for h in reading.administrators if h.sid and h.sid.upper() in officers]
    counted: list[Holder] = []
    seen: set[str] = set()
    for holder in both:
        key = holder.sid.upper()
        if holder.tier0_by_definition or key in seen:
            continue
        seen.add(key)
        counted.append(holder)
    if counted:
        return CaRoleState(
            reading=reading,
            state=STATE_ROLES_COMBINED,
            combined=tuple(sorted(counted, key=lambda h: h.display.lower())),
        )
    return CaRoleState(
        reading=reading,
        state=STATE_SEPARATED_IN_PRACTICE,
        builtin_only_overlap=bool(both),
    )


def _ca_label(reading: CaReading) -> str:
    name = str(reading.ca_name or "").strip()
    host = str(reading.ca_host or "").strip().lower()
    if name and host:
        return f"{name} ({host})"
    return name or host or "a certification authority"


def _join(items: list[str]) -> str:
    items = [i for i in items if i]
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def _ca_list(states: Iterable[CaRoleState]) -> str:
    return _join([_ca_label(s.reading) for s in states])


def _plural(states: list[CaRoleState], one: str, many: str) -> str:
    return one if len(states) == 1 else many


_BUILTIN_NOTE = (
    "The built-in domain administration groups are not counted, because they "
    "administer the CA host and can lift the separation themselves."
)


def _enforced_sentence(states: list[CaRoleState]) -> str:
    return f"Role separation is enforced on {_ca_list(states)}."


def _separated_sentence(states: list[CaRoleState]) -> str:
    text = (
        f"Role separation is not enforced on {_ca_list(states)}, but no account "
        "or group outside the built-in domain administration groups holds both "
        "the CA Administrator and the Certificate Manager role, so the two duties "
        "are separated by assignment rather than by the CA."
    )
    if any(s.builtin_only_overlap for s in states):
        text += " " + _BUILTIN_NOTE
    return text


def _combined_sentence(state: CaRoleState) -> str:
    names = [h.display for h in state.combined]
    verb = "holds" if len(names) == 1 else "hold"
    return (
        f"Role separation is not enforced on {_ca_label(state.reading)}, and "
        f"{_join(names)} {verb} both the CA Administrator and the Certificate "
        "Manager role there."
    )


def _not_read_sentence(states: list[CaRoleState]) -> str:
    """One sentence per reason a CA was not settled, naming the CAs."""
    flag_unread = [s for s in states if s.reading.role_separation is None]
    holders_unread = [s for s in states if s.reading.role_separation is not None]
    sentences: list[str] = []
    if flag_unread:
        sentences.append(
            f"The role-separation setting of {_ca_list(flag_unread)} could not be "
            f"read, so {_plural(flag_unread, 'that CA carries', 'those CAs carry')} "
            "no verdict."
        )
    if holders_unread:
        sentences.append(
            f"Role separation is not enforced on {_ca_list(holders_unread)}, and who "
            "holds the CA Administrator and Certificate Manager roles there could "
            f"not be read, so {_plural(holders_unread, 'that CA carries', 'those CAs carry')} "
            "no verdict."
        )
    return " ".join(sentences)


def build_segregation_evidence(
    readings: Iterable[CaReading],
) -> SegregationEvidence | None:
    """Return the domain's segregation-of-duties record, or ``None``.

    ``None`` when the domain owns no CA the scan reached: there is nothing to
    say, and no record is written.

    Precedence, first match wins:

    * a CA with the roles combined: ``contradicted`` (a non-conformity on the
      segregation-of-duties requirements), naming every such CA's host;
    * no CA read at all: ``not_assessed`` (grey; written so a previous run's
      reading cannot stand in for this one);
    * some CA not read: ``incomplete`` (never green, never a gap);
    * every CA enforcing: ``observed`` (green);
    * otherwise (at least one CA separated in practice only): ``incomplete``
      with :data:`HOLDS_IN_PRACTICE_DETAIL`, the informative note.
    """
    states = [ca_role_state(r) for r in readings if isinstance(r, CaReading)]
    if not states:
        return None
    by_state: dict[str, list[CaRoleState]] = {}
    for state in states:
        by_state.setdefault(state.state, []).append(state)
    enforced = by_state.get(STATE_ENFORCED, [])
    combined = by_state.get(STATE_ROLES_COMBINED, [])
    separated = by_state.get(STATE_SEPARATED_IN_PRACTICE, [])
    not_read = by_state.get(STATE_NOT_READ, [])

    if combined:
        sentences = [_combined_sentence(s) for s in combined]
        sentences.append(
            "An account holding both roles can change the CA's configuration and "
            "approve the certificates it issues, so the CA does not separate those "
            "duties."
        )
        if enforced:
            sentences.append(_enforced_sentence(enforced))
        if separated:
            sentences.append(_separated_sentence(separated))
        if not_read:
            sentences.append(_not_read_sentence(not_read))
        hosts: list[str] = []
        for state in combined:
            host = (
                str(state.reading.ca_host or state.reading.ca_name or "")
                .strip()
                .lower()
            )
            if host and host not in hosts:
                hosts.append(host)
        return SegregationEvidence(
            status=STATUS_CONTRADICTED,
            title=TITLE_NEUTRAL,
            statement=" ".join(sentences),
            holds_in_practice=False,
            contrary_hosts=tuple(hosts),
            cas=tuple(states),
        )

    if not_read and len(not_read) == len(states):
        return SegregationEvidence(
            status=STATUS_NOT_ASSESSED,
            title=TITLE_NEUTRAL,
            statement=_not_read_sentence(not_read),
            holds_in_practice=False,
            contrary_hosts=(),
            cas=tuple(states),
        )

    if not_read:
        sentences = []
        if enforced:
            sentences.append(_enforced_sentence(enforced))
        if separated:
            sentences.append(_separated_sentence(separated))
        sentences.append(_not_read_sentence(not_read))
        sentences.append(
            "A control is credited only when every CA it covers was read, so this "
            "one carries no verdict from this evidence."
        )
        return SegregationEvidence(
            status=STATUS_INCOMPLETE,
            title=TITLE_NEUTRAL,
            statement=" ".join(sentences),
            holds_in_practice=False,
            contrary_hosts=(),
            cas=tuple(states),
        )

    if not separated:
        scope = _plural(
            enforced,
            "the only certification authority of this domain",
            f"every one of the {len(enforced)} certification authorities of this domain",
        )
        return SegregationEvidence(
            status=STATUS_OBSERVED,
            title=TITLE_ENFORCED,
            statement=(
                f"Role separation is enforced on {_ca_list(enforced)}, {scope}. "
                "The CA refuses every task from an account that holds both the CA "
                "Administrator and the Certificate Manager role, so no single "
                "account can configure the CA and approve the certificates it "
                "issues."
            ),
            holds_in_practice=False,
            contrary_hosts=(),
            cas=tuple(states),
        )

    sentences = []
    if enforced:
        sentences.append(_enforced_sentence(enforced))
    sentences.append(_separated_sentence(separated))
    sentences.append(
        "This is recorded as an observation and carries no verdict, because "
        "nothing on the CA stops a later grant from combining the roles."
    )
    return SegregationEvidence(
        status=STATUS_INCOMPLETE,
        title=TITLE_NEUTRAL,
        statement=" ".join(sentences),
        holds_in_practice=True,
        contrary_hosts=(),
        cas=tuple(states),
    )


def reading_from_properties(
    ca_name: str,
    ca_host: str,
    properties: Mapping[str, Any],
    *,
    resolve_holder: Any,
    fallback_flag: int | None = None,
) -> CaReading | None:
    """Build a :class:`CaReading` from the CA node's stamped reading.

    Args:
        ca_name: The CA's name.
        ca_host: The CA host's DNS name.
        properties: The CA node's properties.
        resolve_holder: ``callable(sid) -> Holder`` (name and tier come from the
            caller, which holds the directory data and the tier SSOT).
        fallback_flag: The flag another account read in this run (the cleanup
            account's reversal-capability probe), used only when the scan
            account's own read gave no answer.

    Returns:
        ``None`` when the CA carries no reading (this domain's collection did
        not reach it, so it is another domain's CA or was never contacted).
    """
    reading = (
        properties.get(READING_PROPERTY) if isinstance(properties, Mapping) else None
    )
    if not isinstance(reading, Mapping) or not reading.get(READING_ATTEMPTED):
        return None
    flag = reading.get(READING_FLAG)
    source = FLAG_SOURCE_SCAN
    if flag not in (0, 1) or isinstance(flag, bool):
        flag = fallback_flag if fallback_flag in (0, 1) else None
        source = FLAG_SOURCE_CLEANUP if flag is not None else ""
    security_read = bool(reading.get(READING_SECURITY_READ))

    def _holders(values: Any) -> tuple[Holder, ...]:
        out: list[Holder] = []
        for sid in values or ():
            text = str(sid or "").strip()
            if text:
                out.append(resolve_holder(text))
        return tuple(out)

    return CaReading(
        ca_name=str(ca_name or "").strip(),
        ca_host=str(ca_host or "").strip(),
        role_separation=flag,
        flag_source=source,
        security_read=security_read,
        administrators=_holders(reading.get(READING_ADMINS)) if security_read else (),
        certificate_managers=(
            _holders(reading.get(READING_OFFICERS)) if security_read else ()
        ),
    )


__all__ = [
    "CATEGORY",
    "CONTROL_KEY",
    "CaReading",
    "CaRoleState",
    "FLAG_SOURCE_CLEANUP",
    "FLAG_SOURCE_SCAN",
    "HOLDS_IN_PRACTICE_DETAIL",
    "Holder",
    "READING_ADMINS",
    "READING_ATTEMPTED",
    "READING_FLAG",
    "READING_OFFICERS",
    "READING_PROPERTY",
    "READING_SECURITY_READ",
    "STATE_ENFORCED",
    "STATE_NOT_READ",
    "STATE_ROLES_COMBINED",
    "STATE_SEPARATED_IN_PRACTICE",
    "STATUS_CONTRADICTED",
    "STATUS_INCOMPLETE",
    "STATUS_NOT_ASSESSED",
    "STATUS_OBSERVED",
    "SegregationEvidence",
    "TITLE_ENFORCED",
    "TITLE_NEUTRAL",
    "build_segregation_evidence",
    "ca_role_state",
    "reading_from_properties",
]
