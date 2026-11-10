"""Secrets a verification rejected for one principal, kept as spray candidates.

A password that is wrong for the account it was found ON is not worthless: it
is exactly the input a password spray exists to test against every OTHER
account. Discarding it at the moment it was about to be tested throws away a
live password-reuse lead, and on a real engagement that is where a shared
service password shows up.

So a definitive rejection RETIRES the secret for that principal and records it
here instead of deleting the string. The pool lives in the credential store
(``domains_data[domain]["rejected_secret_candidates"]``) because "this string
was proven wrong for this principal" is credential-store knowledge, right next
to the provenance that says where the string came from. It is JSON-safe, so it
survives the session in ``variables.json`` the same way the credentials do.

Consumers read it through :func:`iter_rejected_secret_candidates` (or the
flat :func:`rejected_secret_passwords` for the common "give me the strings"
case) and feed the strings into their own candidate list. Nothing in here
sprays anything; it is storage plus a reader.

Each record also carries WHERE the string was read from
(:class:`AttributeDisclosureSource`), which is what makes a later hit
attributable. The case that needs it: the string fails for the account whose
directory attribute leaked it, so the run reports the leak as an unproven
observation, and the spray then finds the same string valid for a DIFFERENT
account. At that moment the leak IS proven exploitable, against a principal the
leaking object never named. Without the source recorded, the hit arrives with a
spray origin and nothing can say which attribute on which object to go and
clear, which is worse than no attribution at all. :func:`find_rejected_secret_candidates`
is the lookup that half of the promotion reads, and
:func:`record_cross_attributed_hit` is where the consumer that PROVED the string
records against which principal it authenticated.

The division of labour is deliberate. This module stores the two facts (the
string leaked HERE, the string authenticated as THAT principal) and nothing
else: it grades no finding and writes no report. Deciding what the pair MEANS
belongs to the finding-reconciliation seam, which runs after every phase
boundary and is called by both report tiers, so one promotion serves the free
report, the paid kit and the web CTEM (see
``docs/superpowers/specs/2026-10-09-leaked-attribute-secret-cross-attribution.md``).
A spray has no business deciding a finding's severity.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, MutableMapping

from adscan_core import telemetry
from adscan_core.rich_output import print_exception
from adscan_core.sensitive import strip_sensitive_markers

#: Workspace key under ``domains_data[domain]``.
REJECTED_SECRET_POOL_KEY = "rejected_secret_candidates"

#: Bounded so a pathological retry loop can never grow ``variables.json``
#: without limit. A real engagement produces a handful of these.
_MAX_POOL_ENTRIES = 64

#: Persisted field holding the principals a later verification PROVED the
#: string against. One record can carry several: the same leaked service
#: password legitimately opens more than one account.
CROSS_ATTRIBUTED_HITS_FIELD = "cross_attributed_hits"

#: Bounded for the same reason as the pool itself. A spray that proves one
#: string against hundreds of accounts is a password-reuse finding in its own
#: right, not an attribution list worth growing without limit.
_MAX_CROSS_ATTRIBUTED_HITS = 32


@dataclass(frozen=True)
class AttributeDisclosureSource:
    """Where a candidate secret was read from, for later attribution.

    Every field answers a question a promoted finding has to answer, and none
    of them is derivable from the secret or from the account it was rejected
    for:

    * ``principal`` — the object that LEAKED the string. It coincides with the
      rejection's own principal for the directory-attribute sweep, which
      verifies a value against the account whose attribute held it, and
      diverges for every other scraped source (a GPP blob, a file on a share),
      so it is recorded explicitly rather than inferred.
    * ``attribute`` — the attribute the value sits in. The sweep covers several
      credential-bearing fields, and "clear THIS attribute on THIS object" is
      the finding's entire value to an administrator. It is also what the
      affected-asset rule for this family reads as its qualifier.
    * ``rule`` — the detector rule that extracted it, so a promoted record can
      be built in the same shape the confirmed finding already writes instead
      of with a blank where the original had a value.
    * ``finding_key`` — the finding the leak was actually recorded under. Its
      two sibling producers write different record containers, so a promotion
      that guesses between them annotates the wrong shape.
    * ``evidence_path`` — the artifact the original finding pointed at, carried
      so a promoted record keeps the same evidence instead of re-deriving a
      path layout.

    Any field may be empty: an unset field is honest, a guessed one is not.
    """

    principal: str = ""
    attribute: str = ""
    rule: str = ""
    finding_key: str = ""
    evidence_path: str = ""

    @property
    def is_empty(self) -> bool:
        """True when nothing about the source was recorded."""
        return not any(
            (
                self.principal,
                self.attribute,
                self.rule,
                self.finding_key,
                self.evidence_path,
            )
        )


@dataclass(frozen=True)
class CrossAttributedHit:
    """A principal a later verification PROVED this secret against.

    The second half of the attribution pair. The first half (where the string
    was read from) is :class:`AttributeDisclosureSource`; this one is "and it
    opened THIS account", recorded by the consumer that authenticated with it.

    Attributes:
        compromised_principal: The principal the secret authenticated as. It is
            never the record's own ``rejected_for``: that account is the one the
            directory REFUSED the string for, so recording it here would claim a
            proof the run does not hold.
        at: ISO-8601 UTC timestamp of the proof.
    """

    compromised_principal: str
    at: str = ""

    def to_dict(self) -> dict[str, str]:
        """Return the JSON-safe persisted shape."""
        payload = {"compromised_principal": self.compromised_principal}
        if self.at:
            payload["at"] = self.at
        return payload


@dataclass(frozen=True)
class RejectedSecretCandidate:
    """One secret a domain controller rejected for a named principal.

    Attributes:
        secret: The rejected secret string.
        rejected_for: The principal the secret was rejected FOR. It may still
            be valid for another account, which is the whole point.
        verdict: Short machine-readable verdict slug from the verification.
        origin: The origin slug the secret arrived with (for example
            ``user_description``), so a consumer can tell a scraped candidate
            from an operator-typed one.
        at: ISO-8601 UTC timestamp of the rejection.
        source: Where the string was read from, as
            :class:`AttributeDisclosureSource`.
        cross_attributed_hits: The principals a later verification proved the
            string against. Empty for the normal case (the string was wrong for
            its owner and wrong for everybody else), and non-empty exactly when
            the leak became provably exploitable against a DIFFERENT principal.
    """

    secret: str
    rejected_for: str
    verdict: str = ""
    origin: str = ""
    at: str = ""
    source: AttributeDisclosureSource = AttributeDisclosureSource()
    cross_attributed_hits: tuple[CrossAttributedHit, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-safe persisted shape.

        The five source fields are persisted FLAT rather than nested, so a
        reader written against the original shape keeps working and an entry
        written by an older build simply has them absent.
        """
        payload: dict[str, Any] = {
            "secret": self.secret,
            "rejected_for": self.rejected_for,
            "verdict": self.verdict,
            "origin": self.origin,
            "at": self.at,
        }
        for key, value in (
            ("source_principal", self.source.principal),
            ("source_attribute", self.source.attribute),
            ("source_rule", self.source.rule),
            ("finding_key", self.source.finding_key),
            ("evidence_path", self.source.evidence_path),
        ):
            if value:
                payload[key] = value
        if self.cross_attributed_hits:
            payload[CROSS_ATTRIBUTED_HITS_FIELD] = [
                hit.to_dict() for hit in self.cross_attributed_hits
            ]
        return payload


def _domain_bucket(
    domains_data: MutableMapping[str, Any] | None, domain: str
) -> MutableMapping[str, Any] | None:
    if not isinstance(domains_data, MutableMapping):
        return None
    bucket = domains_data.get(domain)
    return bucket if isinstance(bucket, MutableMapping) else None


def record_rejected_secret_candidate(
    domains_data: MutableMapping[str, Any],
    *,
    domain: str,
    secret: Any,
    rejected_for: str,
    verdict: str = "",
    origin: str = "",
    source_principal: str = "",
    source_attribute: str = "",
    source_rule: str = "",
    finding_key: str = "",
    evidence_path: str = "",
) -> RejectedSecretCandidate | None:
    """Demote a rejected secret into the domain's spray-candidate pool.

    Idempotent on ``(secret, rejected_for)``: re-verifying the same wrong
    secret for the same principal records once. A repeat whose source fields
    are richer than the stored entry's UPGRADES it in place, so a producer
    that learns where the string came from is not silently ignored because a
    poorer record got there first. Best-effort — a failure here never
    propagates, because losing the demotion must not break the flow that was
    disposing of the credential.

    Args:
        domains_data: Shared workspace domain mapping.
        domain: Domain key in ``domains_data``.
        secret: The rejected secret (sensitive markers are stripped).
        rejected_for: Principal the secret was rejected for.
        verdict: Short verdict slug from the verification result.
        origin: Origin slug the secret arrived with.
        source_principal: Object whose attribute leaked the string.
        source_attribute: Attribute the string was read from.
        source_rule: Detector rule that extracted it.
        finding_key: Finding key the leak was recorded under.
        evidence_path: Artifact the original finding pointed at.

    Returns:
        The recorded candidate, or ``None`` when there was nothing to record.
        All five source arguments are optional: an unset field is honest, and
        every one of them is left unset rather than guessed.
    """
    try:
        text = strip_sensitive_markers(str(secret or "")).strip()
        principal = str(rejected_for or "").strip().lower()
        if not text or not principal:
            return None
        bucket = _domain_bucket(domains_data, domain)
        if bucket is None:
            if not isinstance(domains_data, MutableMapping):
                return None
            domains_data[domain] = {}
            bucket = domains_data[domain]
        pool = bucket.get(REJECTED_SECRET_POOL_KEY)
        if not isinstance(pool, list):
            pool = []
            bucket[REJECTED_SECRET_POOL_KEY] = pool

        candidate = RejectedSecretCandidate(
            secret=text,
            rejected_for=principal,
            verdict=str(verdict or "").strip(),
            origin=str(origin or "").strip(),
            at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            source=AttributeDisclosureSource(
                principal=str(source_principal or "").strip(),
                attribute=str(source_attribute or "").strip(),
                rule=str(source_rule or "").strip(),
                finding_key=str(finding_key or "").strip(),
                evidence_path=str(evidence_path or "").strip(),
            ),
        )
        for index, entry in enumerate(pool):
            if not isinstance(entry, dict):
                continue
            if (
                str(entry.get("secret") or "") == text
                and str(entry.get("rejected_for") or "").strip().lower() == principal
            ):
                merged = _merge_source_into_entry(entry, candidate.source)
                if merged is not None:
                    pool[index] = merged
                return candidate
        if len(pool) >= _MAX_POOL_ENTRIES:
            return candidate
        pool.append(candidate.to_dict())
        return candidate
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


def _merge_source_into_entry(
    entry: dict[str, Any], source: AttributeDisclosureSource
) -> dict[str, Any] | None:
    """Fill a stored entry's EMPTY source fields from ``source``.

    Only absent fields are written, so the first producer to record a value
    keeps it and a later, better-informed one completes the record instead of
    being discarded by the idempotency guard.

    Returns:
        The updated entry when anything changed, otherwise ``None``.
    """
    changed = False
    for key, value in (
        ("source_principal", source.principal),
        ("source_attribute", source.attribute),
        ("source_rule", source.rule),
        ("finding_key", source.finding_key),
        ("evidence_path", source.evidence_path),
    ):
        if value and not str(entry.get(key) or "").strip():
            entry[key] = value
            changed = True
    return entry if changed else None


def _candidate_from_entry(entry: Any) -> RejectedSecretCandidate | None:
    """Rebuild one record from its persisted form, or ``None`` if unusable.

    An entry written before the source fields existed simply has them absent
    and reads back with an empty :class:`AttributeDisclosureSource`.
    """
    if not isinstance(entry, dict):
        return None
    secret = str(entry.get("secret") or "").strip()
    if not secret:
        return None
    return RejectedSecretCandidate(
        secret=secret,
        rejected_for=str(entry.get("rejected_for") or "").strip().lower(),
        verdict=str(entry.get("verdict") or "").strip(),
        origin=str(entry.get("origin") or "").strip(),
        at=str(entry.get("at") or "").strip(),
        source=AttributeDisclosureSource(
            principal=str(entry.get("source_principal") or "").strip(),
            attribute=str(entry.get("source_attribute") or "").strip(),
            rule=str(entry.get("source_rule") or "").strip(),
            finding_key=str(entry.get("finding_key") or "").strip(),
            evidence_path=str(entry.get("evidence_path") or "").strip(),
        ),
        cross_attributed_hits=_hits_from_entry(entry),
    )


def _hits_from_entry(entry: dict[str, Any]) -> tuple[CrossAttributedHit, ...]:
    """Rebuild the cross-attributed hits of one persisted record.

    An entry written before the field existed simply has none, and reads back
    as an empty tuple — which is also the honest answer for every record whose
    string never authenticated anywhere.
    """
    raw = entry.get(CROSS_ATTRIBUTED_HITS_FIELD)
    if not isinstance(raw, list):
        return ()
    hits: list[CrossAttributedHit] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        principal = str(item.get("compromised_principal") or "").strip().lower()
        if not principal:
            continue
        hits.append(
            CrossAttributedHit(
                compromised_principal=principal,
                at=str(item.get("at") or "").strip(),
            )
        )
    return tuple(hits)


def iter_rejected_secret_candidates(
    domains_data: MutableMapping[str, Any] | None, *, domain: str
) -> list[RejectedSecretCandidate]:
    """Return the demoted secrets recorded for ``domain``, in record order."""
    bucket = _domain_bucket(domains_data, domain)
    if bucket is None:
        return []
    pool = bucket.get(REJECTED_SECRET_POOL_KEY)
    if not isinstance(pool, list):
        return []
    out: list[RejectedSecretCandidate] = []
    for entry in pool:
        candidate = _candidate_from_entry(entry)
        if candidate is not None:
            out.append(candidate)
    return out


def find_rejected_secret_candidates(
    domains_data: MutableMapping[str, Any] | None,
    *,
    domain: str,
    secret: Any,
) -> list[RejectedSecretCandidate]:
    """Return every record that leaked ``secret``, in record order.

    The attribution half of the pool's contract: a consumer that has just
    PROVEN a string against some principal asks which leak produced it. One
    string can legitimately leak from several objects (the same service
    password written into two accounts' attributes), so this returns a list and
    the caller is expected to attribute to all of them rather than picking one.

    Matching strips sensitive markers on both sides, exactly as the credential
    store's own comparison does, because a marked copy of a secret is the same
    secret and a consumer may hold either form.

    Args:
        domains_data: Shared workspace domain mapping.
        domain: Domain key in ``domains_data``.
        secret: The secret to look up.

    Returns:
        Every matching record. Empty when the string was never demoted, which
        is the normal case for a password that came from anywhere else.
    """
    wanted = strip_sensitive_markers(str(secret or "")).strip()
    if not wanted:
        return []
    return [
        candidate
        for candidate in iter_rejected_secret_candidates(domains_data, domain=domain)
        if strip_sensitive_markers(candidate.secret).strip() == wanted
    ]


def record_cross_attributed_hit(
    domains_data: MutableMapping[str, Any],
    *,
    domain: str,
    leak: RejectedSecretCandidate,
    compromised_principal: str,
) -> bool:
    """Record that *leak*'s secret authenticated as ``compromised_principal``.

    The ONE call a consumer that just PROVED a string owes the pool, and the
    whole of what it owes: it stores a fact and decides nothing. The promotion
    this unlocks (an unproven "a readable attribute holds secret-shaped text"
    observation becoming the confirmed "a secret in a directory attribute that
    authenticates") is taken at the finding-reconciliation seam, where both
    report tiers see it and where the severity decision belongs.

    Two honesty guards, both of which make this a no-op rather than a record:

    * the principal must DIFFER from the leak's own ``rejected_for``. That
      account is the one the directory refused the string for, so attributing
      the proof back to it would manufacture a contradiction out of two true
      observations.
    * the record must already exist in the pool. This never creates one, so a
      hit can only ever be attached to a leak the run actually observed.

    Idempotent on the principal, so a re-sprayed credential records once.
    Best-effort — a failure here never propagates, because losing an
    attribution must not break the flow that just captured a credential.

    Args:
        domains_data: Shared workspace domain mapping.
        domain: Domain key in ``domains_data``.
        leak: The record returned by :func:`find_rejected_secret_candidates`.
        compromised_principal: The principal the secret authenticated as.

    Returns:
        ``True`` when a hit was appended, ``False`` when there was nothing to
        record (no matching record, the same principal, or the bound reached).
    """
    try:
        principal = str(compromised_principal or "").strip().lower()
        wanted = strip_sensitive_markers(str(leak.secret or "")).strip()
        rejected_for = str(leak.rejected_for or "").strip().lower()
        if not principal or not wanted or principal == rejected_for:
            return False
        bucket = _domain_bucket(domains_data, domain)
        if bucket is None:
            return False
        pool = bucket.get(REJECTED_SECRET_POOL_KEY)
        if not isinstance(pool, list):
            return False
        for entry in pool:
            if not isinstance(entry, dict):
                continue
            if strip_sensitive_markers(str(entry.get("secret") or "")).strip() != wanted:
                continue
            if str(entry.get("rejected_for") or "").strip().lower() != rejected_for:
                continue
            hits = entry.get(CROSS_ATTRIBUTED_HITS_FIELD)
            if not isinstance(hits, list):
                hits = []
                entry[CROSS_ATTRIBUTED_HITS_FIELD] = hits
            for hit in hits:
                if (
                    isinstance(hit, dict)
                    and str(hit.get("compromised_principal") or "").strip().lower()
                    == principal
                ):
                    return False
            if len(hits) >= _MAX_CROSS_ATTRIBUTED_HITS:
                return False
            hits.append(
                CrossAttributedHit(
                    compromised_principal=principal,
                    at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                ).to_dict()
            )
            return True
        return False
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False


def rejected_secret_passwords(
    domains_data: MutableMapping[str, Any] | None, *, domain: str
) -> list[str]:
    """Return the de-duplicated secret strings a spray should still try.

    The ONE call a spray flow needs: every string a verification proved wrong
    for its owning account, which makes each of them a reuse candidate for
    every other account. Order is first-recorded-first.
    """
    seen: set[str] = set()
    out: list[str] = []
    for candidate in iter_rejected_secret_candidates(domains_data, domain=domain):
        if candidate.secret in seen:
            continue
        seen.add(candidate.secret)
        out.append(candidate.secret)
    return out


__all__ = [
    "CROSS_ATTRIBUTED_HITS_FIELD",
    "REJECTED_SECRET_POOL_KEY",
    "AttributeDisclosureSource",
    "CrossAttributedHit",
    "RejectedSecretCandidate",
    "find_rejected_secret_candidates",
    "iter_rejected_secret_candidates",
    "record_cross_attributed_hit",
    "record_rejected_secret_candidate",
    "rejected_secret_passwords",
]
