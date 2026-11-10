"""Domain-controller topology: how many DCs a domain has, alias-aware.

Dependency-light SSOT, moved here from ``adscan_internal.models.domain`` so the
web backend (which bundles ``adscan_core`` but not the engine) can count a
domain's DCs the same way the engine does. ``domains_data[domain]`` records
DCs under a mix of identifiers (``dc_ip``, ``pdc``, ``pdc_hostname_fqdn``,
``dcs[]``...) that are often ALIASES of ONE DC; counting the raw list showed
"2 DCs" for a domain whose single DC was recorded by its IP and its FQDN.

``adscan_internal.models.domain`` re-exports every name, so engine callers are
unchanged. ``host_match_keys`` / ``hosts_match`` are the alias rule the engine's
``credential_store_service`` uses (it delegates here).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Mapping, Optional, Tuple

__all__ = [
    "DomainControllers",
    "host_match_keys",
    "hosts_match",
    "resolve_domain_controllers",
]


def host_match_keys(value: str) -> set[str]:
    """Return the alias-aware comparison keys for one host identifier.

    Service-ticket ``target_host`` (an SPN host, usually an FQDN) and the host a
    follow-up step resolves to (FQDN, short name, IP, ``HOST$``, or the attack
    graph's own ``HOST$@REALM`` node label) must compare equal when they denote
    the same machine.  This produces a normalised set so a match is
    ``keys(a) & keys(b)`` being non-empty:

    - lowercased, trailing dot and trailing ``$`` stripped
    - the full value (FQDN or IP)
    - the short hostname (label before the first dot) for non-IP values

    A graph node label (``BRAAVOS$@ESSOS.LOCAL``) is folded into the FQDN it
    denotes (``braavos.essos.local``), so a host identifier read off an
    attack-path step compares equal to the same host stored by a credential or
    ticket writer.  Keeping the realm rather than reducing the label to its
    short name means the FQDN form matches directly.

    IPs are preserved verbatim (no short-name split).  Empty/blank input yields
    an empty set so it never matches anything.
    """
    raw = str(value or "").strip().strip(".").lower()
    if "@" in raw:
        # Attack-graph node label: ``<samaccountname>@<realm>``.
        name, _, realm = raw.partition("@")
        name = name.rstrip("$").strip()
        realm = realm.strip().strip(".")
        raw = f"{name}.{realm}" if name and realm else name
    raw = raw.rstrip("$")
    if not raw:
        return set()
    keys = {raw}
    # IPv4 literal -> keep as-is, do not derive a "short name".
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", raw):
        return keys
    short = raw.split(".", 1)[0].strip()
    if short:
        keys.add(short)
    return keys


def hosts_match(a: str, b: str) -> bool:
    """Return whether two host identifiers denote the same machine (alias-aware)."""
    keys_a = host_match_keys(a)
    keys_b = host_match_keys(b)
    return bool(keys_a and keys_b and (keys_a & keys_b))


# The PDC field-group: all keys under ``domains_data[domain]`` that describe the
# SAME primary DC. Collected into one record so its IP/short/FQDN aliases are
# linked (defeats the IP<->FQDN dedup trap).
_PRIMARY_DC_FIELDS: Tuple[str, ...] = (
    "dc_ip",
    "pdc",
    "pdc_hostname",
    "pdc_hostname_fqdn",
    "pdc_fqdn",
    "dc_fqdn",
)


def _looks_like_ipv4(value: str) -> bool:
    """Return True when *value* is a dotted-quad IPv4 literal."""
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", str(value or "").strip()))


def _best_fqdn(aliases: Iterable[str]) -> Optional[str]:
    """Return the first alias that looks like an FQDN (dotted, not an IP)."""
    for alias in aliases:
        a = str(alias or "").strip()
        if a and "." in a and not _looks_like_ipv4(a):
            return a
    return None


def _dc_identifiers_provably_distinct(a: str, b: str) -> bool:
    """Return True only when ``a`` and ``b`` are provably DIFFERENT machines.

    Conservative by construction — a false "different machine" is the dangerous
    direction (it fabricates an alternate DC that lets a doomed self-relay
    proceed):

    * ``hosts_match`` True (alias-aware IP/short/FQDN/``HOST$``) -> same machine.
    * One side an IP literal and the other a name -> INDETERMINATE. ``hosts_match``
      cannot bridge IP<->FQDN, so a DC's own FQDN vs its IP is NOT "different" —
      this is exactly the essos single-DC false positive. Treated as
      not-provably-distinct.
    * Same identifier family (both IPs, or both names) and ``hosts_match`` False ->
      provably a different machine.
    """
    a = str(a or "").strip()
    b = str(b or "").strip()
    if not a or not b:
        return False
    if hosts_match(a, b):
        return False
    if _looks_like_ipv4(a) != _looks_like_ipv4(b):
        return False
    return True


@dataclass(frozen=True)
class _DCRecord:
    """One distinct domain controller and every identifier that denotes it."""

    aliases: Tuple[str, ...]
    fqdn: Optional[str] = None

    def matches(self, host: str) -> bool:
        """Return whether ``host`` denotes this DC (alias-aware IP/short/FQDN)."""
        return any(hosts_match(host, alias) for alias in self.aliases)


@dataclass(frozen=True)
class DomainControllers:
    """Deduped domain-controller topology for one domain (SSOT value object).

    Built by :func:`resolve_domain_controllers` (from ``domains_data``) or by
    :meth:`from_dc_records` (from an already-canonical record set, e.g. the
    attack-graph DC nodes). Every "how many DCs / is host X the sole DC / is
    there an alternate DC to relay to" question resolves through this one type so
    the answer is identical wherever it is asked.
    """

    dcs: Tuple[_DCRecord, ...] = ()

    @property
    def count(self) -> int:
        """Number of DISTINCT domain controllers (deduped by alias)."""
        return len(self.dcs)

    def _record_for_host(self, host: str) -> Optional[_DCRecord]:
        h = str(host or "").strip()
        if not h:
            return None
        for rec in self.dcs:
            if rec.matches(h):
                return rec
        return None

    def recognizes_host(self, host: str) -> bool:
        """Return whether ``host`` aliases one of THIS domain's known DCs.

        The plain boolean form of the question "does this domain claim that
        machine", for a caller that needs attribution rather than topology:
        given a captured ``HOST$`` principal, which collected domain does it
        belong to? Alias-aware through :meth:`_DCRecord.matches`, so the short
        name, the FQDN, the IP, the ``HOST$`` machine-account form and the
        attack-graph ``HOST$@REALM`` label all answer alike.

        Deliberately a two-state answer, not the tri-state :meth:`is_sole_dc`
        returns: "this domain does not recognise that host" and "there are no DC
        identifiers recorded" are the same outcome for an attributor (it must
        look elsewhere), and collapsing them here keeps a caller from reading a
        ``None`` as truthy.
        """
        return self._record_for_host(host) is not None

    def is_sole_dc(self, host: str) -> Optional[bool]:
        """Return True iff there is exactly one DC and ``host`` aliases it.

        ``None`` when there are no DC identifiers, ``host`` is empty, or ``host``
        is not a recognized DC (insufficient to decide).
        """
        if not self.dcs or not str(host or "").strip():
            return None
        if self._record_for_host(host) is None:
            return None
        return self.count == 1

    def has_alternate_dc(self, host: str) -> Optional[bool]:
        """Return whether a DC provably distinct from ``host`` exists.

        * ``True`` — a DC that is a provably-different machine than ``host``
          exists (relay has a non-reflecting target).
        * ``False`` — ``host`` IS a recognized DC and it is the only one (the
          single-DC reflection case).
        * ``None`` — indeterminate: no DC identifiers, empty host, or ``host`` is
          not a recognized DC and no DC is provably distinct from it (IP<->name
          indeterminacy). A false "alternate available" is the dangerous
          direction, so indeterminate never returns True.
        """
        if not self.dcs or not str(host or "").strip():
            return None
        matched = self._record_for_host(host)
        if matched is not None:
            return any(rec is not matched for rec in self.dcs)
        if any(
            _dc_identifiers_provably_distinct(alias, host)
            for rec in self.dcs
            for alias in rec.aliases
        ):
            return True
        return None

    def host_is_primary_dc(self, host: str) -> Optional[bool]:
        """Return whether ``host`` denotes this domain's PRIMARY (PDC) record.

        The primary record is the one built from the PDC field-group
        (``pdc``/``dc_ip``/``pdc_hostname``/``pdc_hostname_fqdn``/...), i.e. the
        record form of the SAME ladder :func:`resolve_dc_ip` walks
        (``pdc -> dc_ip -> dcs[0]``) — so a caller that needs the domain's
        RECORDED primary DC resolves it here instead of reading those fields raw,
        and gets the alias-aware IP<->short<->FQDN<->``HOST$`` comparison for
        free. This is the DETERMINISTIC selector; it probes nothing. Use
        ``dns_discovery_service.select_reachable_dc_ip`` when the question is
        "which DC can I reach right now".

        Returns:
            ``True`` when ``host`` aliases the primary record, ``False`` when it
            aliases a DIFFERENT recorded DC, and ``None`` when the answer is
            indeterminate (no DC identifiers, empty ``host``, or ``host`` is not
            a recognized DC) — never guessed.
        """
        if not self.dcs or not str(host or "").strip():
            return None
        matched = self._record_for_host(host)
        if matched is None:
            return None
        return matched is self.dcs[0]

    @property
    def primary_fqdn(self) -> Optional[str]:
        """Return the primary (PDC) record's FQDN, or ``None`` when unknown."""
        return self.dcs[0].fqdn if self.dcs else None

    def alternate_dc_fqdn(self, host: str) -> Optional[str]:
        """Return the FQDN of a DC distinct from ``host`` (relay target), or None.

        Picks the first provably-distinct / other DC record; returns ``None``
        when there is no alternate or the alternate has no usable FQDN.
        """
        if not self.dcs or not str(host or "").strip():
            return None
        matched = self._record_for_host(host)
        if matched is not None:
            for rec in self.dcs:
                if rec is not matched:
                    return rec.fqdn
            return None
        for rec in self.dcs:
            if any(
                _dc_identifiers_provably_distinct(alias, host)
                for alias in rec.aliases
            ):
                return rec.fqdn
        return None

    @classmethod
    def from_dc_records(
        cls, records: Iterable[Tuple[Iterable[str], Optional[str]]]
    ) -> "DomainControllers":
        """Build from an already-canonical ``(aliases, fqdn)`` record set.

        Used where the DC set is already deduped (e.g. attack-graph DC nodes keyed
        by node id), so the caller gets the SAME count/sole/alternate logic as the
        ``domains_data`` path without re-deriving it. ``fqdn`` is kept EXACTLY as
        supplied (an empty/None fqdn stays "no usable relay endpoint") — it is not
        re-derived from the aliases.
        """
        built: List[_DCRecord] = []
        for aliases, fqdn in records:
            alias_tuple = tuple(
                a for a in (str(x or "").strip() for x in aliases) if a
            )
            fq = str(fqdn or "").strip() or None
            if not alias_tuple and not fq:
                continue
            built.append(_DCRecord(aliases=alias_tuple, fqdn=fq))
        return cls(dcs=tuple(built))


def resolve_domain_controllers(domain_data: Mapping) -> DomainControllers:
    """Return the deduped DC topology for one ``domains_data[domain]`` entry.

    Dedup algorithm:

    1. Build the PRIMARY DC record from the PDC field-group (``dc_ip``, ``pdc``,
       ``pdc_hostname``, ``pdc_hostname_fqdn``, ``pdc_fqdn``, ``dc_fqdn``) — all of
       which describe the SAME primary DC, giving the IP<->FQDN link for free.
    2. For each ``dcs[]`` entry: attach it to a record it aliases (``hosts_match``
       against ANY of that record's aliases — short-name/case/IP/FQDN aware), else
       start a NEW record.

    ``count`` is the number of records. A host that is the primary DC's IP still
    matches the primary record via its FQDN alias, so the single-DC case counts as
    one, not two.
    """
    dd = domain_data or {}

    primary_aliases: List[str] = []
    seen: set[str] = set()
    for key in _PRIMARY_DC_FIELDS:
        val = str(dd.get(key) or "").strip()
        if val and val.lower() not in seen:
            primary_aliases.append(val)
            seen.add(val.lower())

    records: List[_DCRecord] = []
    if primary_aliases:
        records.append(
            _DCRecord(aliases=tuple(primary_aliases), fqdn=_best_fqdn(primary_aliases))
        )

    for entry in dd.get("dcs") or []:
        text = str(entry or "").strip()
        if not text:
            continue
        attached = False
        for idx, rec in enumerate(records):
            if any(hosts_match(text, alias) for alias in rec.aliases):
                if text.lower() not in {a.lower() for a in rec.aliases}:
                    new_aliases = rec.aliases + (text,)
                    records[idx] = _DCRecord(
                        aliases=new_aliases,
                        fqdn=rec.fqdn or _best_fqdn(new_aliases),
                    )
                attached = True
                break
        if not attached:
            records.append(_DCRecord(aliases=(text,), fqdn=_best_fqdn([text])))

    return DomainControllers(dcs=tuple(records))
