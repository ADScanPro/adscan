"""Password hygiene: what credential recovery proved about the client's accounts.

Import-safe SSOT (stdlib + typing only) so ONE derivation feeds every surface:
the operator's panel, the telemetry emit, the paid deliverable and the web CTEM.

ADscan already computed all of this inside ``cli/secretsdump.py``: the recovery
rate, the per-tier coverage, and password reuse split between the hashes it
recovered and the hashes it did not. It reached the pentester's terminal and our
analytics, and never the client who paid for it. Lifting it here rather than
rebuilding it is the point: the panel, the telemetry and the deliverable read one
implementation, so they cannot disagree about the client's own numbers.

THE SEGMENTS ARE PRIVILEGE TIERS, AND THERE ARE FOUR OF THEM
------------------------------------------------------------
The breakdown reports the recovery coverage per PRIVILEGE TIER, which is axis 1
of the nomenclature standard and has four canonical values plus the declared
absence of a grade. It used to project a two-boolean model onto three display
buckets (Tier-0 / High-Value / Standard), which was wrong three ways: Tier 1 did
not exist at all, so a server or application admin was reported to the client as
a standard account; "high value" is the graph's own orthogonal flag rather than a
tier, so rendering it as a peer of Tier 0 conflated the two axes the standard
keeps apart; and Tier 0 was not split, so recovering a Domain Admins member read
exactly like recovering a Backup Operators member. Understating a Tier-1 admin as
standard is the direction the Exposure-Validation doctrine rules out.

Each segment therefore carries the TIER TOKEN as its identity and the label the
ONE owner words (``compromise_class.privilege_tier_label``, through the provider
seam in :mod:`adscan_core.reporting.privilege_tier_labels`). The label is
resolved once, where the block is authored, and persisted with it, so every
downstream surface reads the same words verbatim and none of them needs the
classifier. ``high_value`` survives as its own orthogonal pair of counters, never
as a bucket.

AN UNGRADED ACCOUNT IS NOT A STANDARD ONE
-----------------------------------------
An account the assessment could not place (no graph node, or a node carrying no
tier stamp) lands in the ``ungraded`` segment, which words itself "Not graded".
It is counted, so the segments still sum to the extracted total and the table
reconciles, and it is reported, because the default has to be to surface rather
than to assume harmless. What it must never do is read as Tier 2.

THE ABSENCE RULE, and why it is structural
------------------------------------------
When no cracking was attempted, nothing was recovered, so every rate computes as
**0.0** and reads as "your passwords are strong". That is the dangerous false
negative the Exposure-Validation doctrine forbids, and the exact inverse of a
coverage note claiming a stronger method than the one that ran. A guard on the
rendered figure is not enough, because the arithmetic produces 0.0 on its own
whenever the recovered total is 0 against a non-zero extracted total.

So the attempt is an INPUT, not an inference: ``cracking_attempted`` is a
required keyword with no default, every rate is ``None`` without it, and
:attr:`PasswordHygiene.has_figures` is the single gate every surface asks. The
presence of hygiene data IS the statement that cracking ran, which makes the
absence structural rather than a disclaimer somebody has to remember to print.

A real zero is different and is reported: cracking that RAN and recovered
nothing is evidence about the client's passwords, and it is only meaningful
because the attempt is on the record.

WHAT THIS BLOCK NEVER CARRIES
-----------------------------
A recovered password. A reuse group names the ACCOUNTS that share one; the secret
itself belongs on the operator's terminal and in the credential appendix, not in
an aggregate the web platform stores in a database.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Optional

from adscan_core.reporting.privilege_tier_labels import (
    PRIVILEGE_TIER_TOKEN_ORDER,
    TIER0_ROLLUP_LABEL,
    TIER_TOKEN_TIER0_DIRECT,
    TIER_TOKEN_TIER0_ESCALATION_CAPABLE,
    TIER_TOKEN_TIER1,
    TIER_TOKEN_TIER2,
    TIER_TOKEN_UNGRADED,
    normalize_privilege_tier_token,
    privilege_tier_label_for_token,
    token_is_tier0,
)

#: Per-domain key this block is stamped under, in ``technical_report.json`` and
#: in the renderer's ``report_data``. One name, so the writer, the panel, the PDF
#: and the web platform cannot drift apart on where the record lives.
PASSWORD_HYGIENE_KEY = "password_hygiene"

#: The segments, in the order every surface renders them: the tier that decides
#: the engagement first, the declared absence of a grade last. The tokens and
#: their order are the shared privilege-tier SSOT's, never redeclared here.
SEGMENT_ORDER: tuple[str, ...] = PRIVILEGE_TIER_TOKEN_ORDER

#: The identity of the combined Tier-0 roll-up a headline figure reads. Not a
#: segment: it is the two Tier-0 tokens added together, for the one sentence
#: that cares about the containment boundary rather than the directness split.
SEGMENT_TIER0_ROLLUP = "tier0"


def _pct(part: int, whole: int) -> float | None:
    """Return a percentage, or ``None`` when there is no denominator."""
    if whole <= 0:
        return None
    return round(part / whole * 100, 1)


@dataclass(frozen=True)
class HygieneSegment:
    """One privilege tier's recovery coverage.

    ``tier`` is the identity (the tier token, or ``tier0`` for the combined
    roll-up) and ``label`` is the wording the ONE owner produced, resolved where
    the block is authored and carried with it so no downstream surface has to
    re-resolve it.

    ``coverage_pct`` is ``None`` rather than 0.0 when no attempt was made, which
    is what stops a segment row reading as "none of your Tier-0 passwords are
    weak" on a run that never tested one.
    """

    tier: str
    label: str
    extracted: int
    recovered: int
    attempted: bool = True

    @property
    def coverage_pct(self) -> float | None:
        """Share of this segment's extracted hashes that were recovered."""
        if not self.attempted:
            return None
        return _pct(self.recovered, self.extracted)

    @property
    def is_tier0(self) -> bool:
        """Whether this segment sits inside the Tier 0 containment boundary."""
        return self.tier == SEGMENT_TIER0_ROLLUP or token_is_tier0(self.tier)

    def as_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier,
            "label": self.label,
            "extracted": self.extracted,
            "recovered": self.recovered,
            "coverage_pct": self.coverage_pct,
            "is_tier0": self.is_tier0,
        }


@dataclass(frozen=True)
class PasswordReuseGroup:
    """Accounts sharing one password, named without naming the password."""

    accounts: tuple[str, ...]
    #: How many of those accounts fall in each privilege tier, keyed by TIER
    #: TOKEN, so a group covering a Tier-0 account can be surfaced ahead of one
    #: that does not, and so the client learns whether that Tier-0 account holds
    #: direct domain control or is escalation-capable.
    segment_counts: dict[str, int] = field(default_factory=dict)

    @property
    def size(self) -> int:
        return len(self.accounts)

    def as_dict(self) -> dict[str, Any]:
        return {
            "accounts": list(self.accounts),
            "size": self.size,
            "segment_counts": dict(self.segment_counts),
        }


@dataclass(frozen=True)
class PasswordHygiene:
    """What credential recovery proved, or the honest absence of it."""

    cracking_attempted: bool
    extracted_total: int
    recovered_total: int
    segments: tuple[HygieneSegment, ...]
    reuse_groups_recovered: tuple[PasswordReuseGroup, ...] = ()
    reuse_groups_unrecovered: tuple[PasswordReuseGroup, ...] = ()
    krbtgt_recovered: bool = False
    #: The graph's ``highvalue`` flag, counted ORTHOGONALLY to the tiers. It is
    #: an impact marker rather than a tier, so it overlaps every segment and is
    #: never a bucket: a count here plus a count in a segment is the same
    #: account seen on two axes, and the two must never be added together.
    high_value_extracted: int = 0
    high_value_recovered: int = 0
    #: ``tier token -> client-facing label``, resolved once where the block is
    #: authored. Carried with the block so the PDF, the operator panel and the
    #: web platform read identical wording without reaching the tier classifier.
    tier_labels: dict[str, str] = field(default_factory=dict)

    @property
    def has_figures(self) -> bool:
        """The ONE gate every surface asks before rendering anything.

        False when no cracking was attempted, and false when nothing was
        extracted (no denominator). A surface that renders on anything else
        reintroduces the 0% false negative.
        """
        return self.cracking_attempted and self.extracted_total > 0

    @property
    def recovery_rate_pct(self) -> float | None:
        """Overall recovery rate, or ``None`` when there is no figure to give."""
        if not self.has_figures:
            return None
        return _pct(self.recovered_total, self.extracted_total)

    @property
    def tier0_segment(self) -> HygieneSegment | None:
        """The combined Tier-0 roll-up, for the one headline figure.

        Both Tier-0 tokens added together, because the headline asks about the
        containment boundary. The directness split stays visible in
        :attr:`segments`, which is where the client reads which of the two it
        is. ``None`` when the run extracted nothing from either.
        """
        return _tier0_rollup(self.segments)

    def as_dict(self) -> dict[str, Any]:
        """The JSON-safe persisted form. Carries no password, by construction."""
        return {
            "cracking_attempted": self.cracking_attempted,
            "extracted_total": self.extracted_total,
            "recovered_total": self.recovered_total,
            "recovery_rate_pct": self.recovery_rate_pct,
            "krbtgt_recovered": self.krbtgt_recovered,
            "high_value_extracted": self.high_value_extracted,
            "high_value_recovered": self.high_value_recovered,
            "tier_labels": dict(self.tier_labels),
            "segments": [segment.as_dict() for segment in self.segments],
            "reuse_groups_recovered": [
                group.as_dict() for group in self.reuse_groups_recovered
            ],
            "reuse_groups_unrecovered": [
                group.as_dict() for group in self.reuse_groups_unrecovered
            ],
        }


def _fold(values: Iterable[str]) -> set[str]:
    return {
        str(value or "").strip().casefold()
        for value in values
        if str(value or "").strip()
    }


def _tier0_rollup(segments: Iterable[Any]) -> HygieneSegment | None:
    """Add the two Tier-0 segments together, or ``None`` when neither has rows.

    Accepts either :class:`HygieneSegment` instances or the persisted mappings,
    so the headline derivation and the render projection roll the boundary up
    the same way rather than each summing it themselves.
    """
    extracted = 0
    recovered = 0
    attempted = False
    found = False
    for segment in segments or ():
        if isinstance(segment, Mapping):
            tier = str(segment.get("tier") or "")
            seg_extracted = segment.get("extracted")
            seg_recovered = segment.get("recovered")
            # A persisted segment states its attempt through ``coverage_pct``:
            # ``None`` is the absence rule, a number means recovery ran.
            seg_attempted = segment.get("coverage_pct") is not None
        else:
            tier = str(getattr(segment, "tier", "") or "")
            seg_extracted = getattr(segment, "extracted", 0)
            seg_recovered = getattr(segment, "recovered", 0)
            seg_attempted = bool(getattr(segment, "attempted", False))
        if not token_is_tier0(tier):
            continue
        found = True
        try:
            extracted += max(int(seg_extracted or 0), 0)
            recovered += max(int(seg_recovered or 0), 0)
        except (TypeError, ValueError):
            continue
        attempted = attempted or bool(seg_attempted)
    if not found:
        return None
    return HygieneSegment(
        tier=SEGMENT_TIER0_ROLLUP,
        label=TIER0_ROLLUP_LABEL,
        extracted=extracted,
        recovered=recovered,
        attempted=attempted,
    )


def build_password_hygiene(
    *,
    accounts: Iterable[Mapping[str, Any]],
    tier_by_username: Mapping[str, str] | None = None,
    high_value_usernames: Iterable[str] = (),
    cracking_attempted: bool,
    label_for_tier: Callable[[str], str] | None = None,
) -> PasswordHygiene:
    """Derive the hygiene block from the extracted account material.

    Args:
        accounts: One record per account whose credential material was
            extracted, each ``{samaccountname, secret, recovered}``. ``secret``
            is the recovered password when ``recovered`` is true and the hash
            otherwise; it is used only to group reuse and never persisted.
        tier_by_username: ``sAMAccountName -> privilege tier token`` for the
            accounts the assessment could GRADE. An account absent from this
            mapping (or carrying an unrecognised token) is ``ungraded``, which
            is reported as the declared absence of a grade and never as Tier 2:
            "we could not place this account" and "this account is a standard
            user" are different statements, and only one of them is true.
        high_value_usernames: Accounts the graph flags ``highvalue``. Counted on
            its own axis, never as a tier.
        cracking_attempted: Whether password recovery actually RAN. Required and
            without a default on purpose: see the module docstring. Passing
            ``False`` yields a block whose every rate is ``None``, so no surface
            can render a 0% that reads as strength.
        label_for_tier: Resolves a tier token's client-facing label. Defaults to
            the shared provider seam, which the authoring layer wires to the ONE
            label owner. A token that resolves to nothing keeps the token as its
            own label: truthful and greppable, where falling back to a tier name
            would state a grade nothing observed supports.

    Returns:
        A :class:`PasswordHygiene`.
    """
    tier_map = {
        str(user or "").strip().casefold(): normalize_privilege_tier_token(tier)
        for user, tier in (tier_by_username or {}).items()
        if str(user or "").strip()
    }
    high_value = _fold(high_value_usernames)
    resolve_label = label_for_tier or privilege_tier_label_for_token

    def _label_for(tier: str) -> str:
        try:
            label = str(resolve_label(tier) or "").strip()
        except Exception:  # noqa: BLE001 — a label never fails the derivation
            label = ""
        return label or tier

    def _segment_for(username: str) -> str:
        folded = str(username or "").strip().casefold()
        return tier_map.get(folded) or TIER_TOKEN_UNGRADED

    extracted = Counter()
    recovered = Counter()
    extracted_total = 0
    recovered_total = 0
    high_value_extracted = 0
    high_value_recovered = 0
    krbtgt_recovered = False
    # ``secret -> [account]``, kept local and never returned: grouping needs the
    # value, the output does not.
    by_secret_recovered: dict[str, list[str]] = {}
    by_secret_unrecovered: dict[str, list[str]] = {}
    segment_by_account: dict[str, str] = {}

    for record in accounts or ():
        if not isinstance(record, Mapping):
            continue
        username = str(record.get("samaccountname") or "").strip()
        if not username:
            continue
        secret = str(record.get("secret") or "").strip()
        was_recovered = bool(record.get("recovered"))
        segment = _segment_for(username)
        segment_by_account[username] = segment
        extracted[segment] += 1
        extracted_total += 1
        is_high_value = username.casefold() in high_value
        if is_high_value:
            high_value_extracted += 1
        if was_recovered:
            recovered[segment] += 1
            recovered_total += 1
            if is_high_value:
                high_value_recovered += 1
            if username.casefold() == "krbtgt":
                krbtgt_recovered = True
            if secret:
                by_secret_recovered.setdefault(secret, []).append(username)
        elif secret:
            by_secret_unrecovered.setdefault(secret, []).append(username)

    def _groups(buckets: dict[str, list[str]]) -> tuple[PasswordReuseGroup, ...]:
        groups = [
            PasswordReuseGroup(
                accounts=tuple(sorted(users)),
                segment_counts=dict(
                    Counter(
                        segment_by_account.get(user, TIER_TOKEN_UNGRADED)
                        for user in users
                    )
                ),
            )
            for users in buckets.values()
            if len(users) > 1
        ]
        # Largest first, then by name, so the group a client acts on leads.
        groups.sort(key=lambda group: (-group.size, group.accounts))
        return tuple(groups)

    # Every tier is emitted, including the ones with no accounts, so the set is
    # the same on every run and the segments always sum to the extracted total.
    # Dropping the empty rows is a DISPLAY decision and belongs to the render
    # projection, not to the record a client's figures are reconciled against.
    segments = tuple(
        HygieneSegment(
            tier=tier,
            label=_label_for(tier),
            extracted=extracted.get(tier, 0),
            recovered=recovered.get(tier, 0),
            attempted=bool(cracking_attempted),
        )
        for tier in SEGMENT_ORDER
    )
    return PasswordHygiene(
        cracking_attempted=bool(cracking_attempted),
        extracted_total=extracted_total,
        recovered_total=recovered_total,
        segments=segments,
        reuse_groups_recovered=_groups(by_secret_recovered),
        reuse_groups_unrecovered=_groups(by_secret_unrecovered),
        krbtgt_recovered=krbtgt_recovered,
        high_value_extracted=high_value_extracted,
        high_value_recovered=high_value_recovered,
        tier_labels={tier: _label_for(tier) for tier in SEGMENT_ORDER},
    )


def tier0_rollup_segment(segments: Iterable[Any]) -> HygieneSegment | None:
    """The combined Tier-0 roll-up for a segment list, or ``None``.

    The public name for :func:`_tier0_rollup`, so a render surface that needs
    the containment-boundary figure adds the two Tier-0 tokens together exactly
    once, here, rather than summing them itself.
    """
    return _tier0_rollup(segments)


def _group_accounts_folded(group: Mapping[str, Any]) -> set[str]:
    """The casefolded account names a persisted reuse group names."""
    return _fold(str(account) for account in group.get("accounts") or ())


def _stored_tier_label(block: Mapping[str, Any], tier: str) -> str:
    """A tier's label as the stored block worded it, falling back to the token.

    The fold runs where the tier classifier may not be wired, so it reads the
    wording the authoring layer already persisted rather than resolving it
    again. A tier the block never worded keeps its token, which is truthful,
    where picking a tier name would state a grade nothing observed supports.
    """
    labels = block.get("tier_labels")
    if isinstance(labels, Mapping):
        label = str(labels.get(tier) or "").strip()
        if label:
            return label
    return privilege_tier_label_for_token(tier) or tier


def merge_recovered_into_hygiene(
    block: Any,
    *,
    recovered_accounts: Iterable[str],
    tier_for: Optional[Callable[[str], str]] = None,
    high_value_for: Optional[Callable[[str], bool]] = None,
) -> Optional[dict[str, Any]]:
    """Fold a LATER recovery into an already-persisted hygiene block.

    Recovery is not a single moment. The block is derived when the credential
    material is extracted, and a local wordlist attack on the same hashes runs
    in the background and finishes afterwards, so the figures persisted at
    extraction time can be older than the recovery picture by the time a client
    reads them. The error runs in the direction that reads as "these passwords
    held", which is the false negative the Exposure-Validation doctrine forbids,
    so the block is folded forward at the seam where the attack's result is
    drained rather than left to describe a moment that has passed.

    Why a fold and not a re-derivation: the exact inputs cannot be replayed.
    :func:`build_password_hygiene` groups reuse by the SECRET, and the secret is
    deliberately never persisted, so the only honest operation on a stored block
    is to move accounts from the unrecovered side to the recovered one.

    Three properties hold by construction, and each one is load-bearing:

    * **It cannot fabricate.** Only a NAMED recovered account credits anything,
      and ``cracking_attempted`` is raised only when something was actually
      credited. "Nothing was recovered, so assume we tried" stays impossible.
    * **It cannot retract.** ``extracted_total`` and every segment's
      ``extracted`` are carried through untouched, the recovered counters only
      ever rise, and the rise is clamped to the headroom its own denominator
      allows. So a fold can never produce a smaller figure or an impossible rate.
    * **It carries no password.** It takes account NAMES. An NT hash is
      unsalted, so one shared password is one shared hash: recovering it
      resolves the WHOLE reuse group at once, which is why a promoted group
      credits all of its accounts and not only the one the attack named it by.

    Args:
        block: The persisted hygiene block, or the view of it.
        recovered_accounts: ``sAMAccountName`` of each account whose password
            the later recovery resolved.
        tier_for: Resolves one account's privilege tier token, for an account
            the persisted block does not already place in a reuse group.
            Defaults to :data:`TIER_TOKEN_UNGRADED`, matching what
            :func:`build_password_hygiene` does with an account it could not
            grade, so the two derivations agree on the same fallback and neither
            of them reports an ungraded account as a standard one.
        high_value_for: Whether one account carries the graph's ``highvalue``
            flag, so the orthogonal counter rises with the fold instead of
            staying at its extraction-time value. Absent, the counters are
            carried through unchanged.

    Returns:
        The merged block in persisted form, or ``None`` when nothing changed, so
        a caller can skip the write entirely.
    """
    if not isinstance(block, Mapping):
        return None

    names: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw in recovered_accounts or ():
        display = str(raw or "").strip()
        folded = display.casefold()
        if not folded or folded in seen:
            continue
        seen.add(folded)
        names.append((display, folded))
    if not names:
        return None

    try:
        extracted_total = int(block.get("extracted_total") or 0)
        recovered_total = int(block.get("recovered_total") or 0)
    except (TypeError, ValueError):
        return None
    if extracted_total <= 0:
        return None

    # Segments are keyed by their TIER token. A block written before the tiers
    # existed carries only a label, so the label is the fallback key: the fold
    # still moves its totals, which is what that older block can honestly say.
    keys: list[str] = []
    label_by_key: dict[str, str] = {}
    extracted_by_segment: dict[str, int] = {}
    recovered_by_segment: dict[str, int] = {}
    for segment in block.get("segments") or ():
        if not isinstance(segment, Mapping):
            continue
        label = str(segment.get("label") or "").strip()
        key = str(segment.get("tier") or "").strip().lower() or label
        if not key or key in extracted_by_segment:
            continue
        try:
            extracted_by_segment[key] = max(int(segment.get("extracted") or 0), 0)
            recovered_by_segment[key] = max(int(segment.get("recovered") or 0), 0)
        except (TypeError, ValueError):
            return None
        label_by_key[key] = label or key
        keys.append(key)

    unrecovered_groups = [
        dict(group)
        for group in block.get("reuse_groups_unrecovered") or ()
        if isinstance(group, Mapping)
    ]
    recovered_groups = [
        dict(group)
        for group in block.get("reuse_groups_recovered") or ()
        if isinstance(group, Mapping)
    ]
    # The accounts the block already counts as recovered, as far as it can name
    # them. Re-crediting one of these would inflate the numerator.
    already_recovered: set[str] = set()
    for group in recovered_groups:
        already_recovered |= _group_accounts_folded(group)

    krbtgt_recovered = bool(block.get("krbtgt_recovered"))
    credited = 0
    headroom_total = max(extracted_total - recovered_total, 0)

    def _segment_headroom(key: str) -> int:
        return max(extracted_by_segment.get(key, 0) - recovered_by_segment.get(key, 0), 0)

    # Where a credit goes when the segment the account grades into has no room
    # left. That happens when the extraction-time grade and the drain-time grade
    # disagree (the grading improved in between), and the account was therefore
    # counted in a different row. Dropping the credit would LOSE a recovery,
    # which is the understatement the doctrine forbids, so it moves to a row
    # that has room: the ungraded row first, because an account the extraction
    # could not place is where it most likely sits, then the least privileged
    # rows, because overstating Tier-0 recovery is the one direction that must
    # never happen.
    _CREDIT_FALLBACK_ORDER = (
        TIER_TOKEN_UNGRADED,
        TIER_TOKEN_TIER2,
        TIER_TOKEN_TIER1,
        TIER_TOKEN_TIER0_ESCALATION_CAPABLE,
        TIER_TOKEN_TIER0_DIRECT,
    )

    def _credit(key: str, count: int) -> None:
        """Credit ``count`` recoveries, clamped to the block's own headroom."""
        nonlocal credited, headroom_total
        take = min(max(int(count or 0), 0), headroom_total)
        if take <= 0:
            return
        remaining = take
        candidates = [key] + [
            fallback
            for fallback in (*_CREDIT_FALLBACK_ORDER, *keys)
            if fallback != key
        ]
        seen: set[str] = set()
        for candidate in candidates:
            if remaining <= 0:
                break
            if candidate in seen or candidate not in extracted_by_segment:
                continue
            seen.add(candidate)
            room = min(_segment_headroom(candidate), remaining)
            if room <= 0:
                continue
            recovered_by_segment[candidate] += room
            remaining -= room
        take -= remaining
        if take <= 0:
            return
        headroom_total -= take
        credited += take

    def _segment_of(account: str) -> str:
        if tier_for is None:
            return TIER_TOKEN_UNGRADED
        try:
            resolved = str(tier_for(account) or "").strip().lower()
        except Exception:  # noqa: BLE001 — an ungradable account stays ungraded
            return TIER_TOKEN_UNGRADED
        return resolved or TIER_TOKEN_UNGRADED

    try:
        high_value_extracted = max(int(block.get("high_value_extracted") or 0), 0)
        high_value_recovered = max(int(block.get("high_value_recovered") or 0), 0)
    except (TypeError, ValueError):
        high_value_extracted = high_value_recovered = 0

    def _credit_high_value(accounts: Iterable[str]) -> None:
        """Raise the orthogonal high-value counter, clamped to its own total."""
        nonlocal high_value_recovered
        if high_value_for is None:
            return
        for account in accounts:
            if high_value_recovered >= high_value_extracted:
                return
            try:
                if high_value_for(account):
                    high_value_recovered += 1
            except Exception:  # noqa: BLE001 — a flag never fails the fold
                return

    consumed: set[str] = set()
    for display, folded in names:
        if folded in already_recovered or folded in consumed:
            continue
        group = next(
            (
                candidate
                for candidate in unrecovered_groups
                if folded in _group_accounts_folded(candidate)
            ),
            None,
        )
        if group is None:
            _credit(_segment_of(display), 1)
            _credit_high_value((display,))
            consumed.add(folded)
            if folded == "krbtgt":
                krbtgt_recovered = True
            continue
        # One shared password is one shared hash, so the whole group falls with
        # the account the attack happened to name it by.
        unrecovered_groups.remove(group)
        members = _group_accounts_folded(group)
        counts = group.get("segment_counts")
        if isinstance(counts, Mapping) and counts:
            for label, count in counts.items():
                _credit(str(label), count)
        else:
            for member in sorted(members):
                _credit(_segment_of(member), 1)
        recovered_groups.append(group)
        _credit_high_value(sorted(members))
        consumed |= members
        if "krbtgt" in members:
            krbtgt_recovered = True

    if credited <= 0:
        return None

    recovered_groups.sort(
        key=lambda group: (
            -len(group.get("accounts") or ()),
            tuple(str(account) for account in group.get("accounts") or ()),
        )
    )
    ordered_keys = keys or list(SEGMENT_ORDER)
    segments = tuple(
        HygieneSegment(
            tier=key,
            label=label_by_key.get(key) or _stored_tier_label(block, key),
            extracted=extracted_by_segment.get(key, 0),
            recovered=recovered_by_segment.get(key, 0),
            attempted=True,
        )
        for key in ordered_keys
    )
    merged_recovered_total = min(recovered_total + credited, extracted_total)
    return PasswordHygiene(
        # Something was credited, so recovery demonstrably ran. This is the one
        # sound direction of the inference; the inverse never happens here,
        # because a fold with nothing credited returns None above.
        cracking_attempted=True,
        extracted_total=extracted_total,
        recovered_total=merged_recovered_total,
        segments=segments,
        reuse_groups_recovered=tuple(
            PasswordReuseGroup(
                accounts=tuple(str(account) for account in group.get("accounts") or ()),
                segment_counts={
                    str(label): int(count)
                    for label, count in (group.get("segment_counts") or {}).items()
                },
            )
            for group in recovered_groups
        ),
        reuse_groups_unrecovered=tuple(
            PasswordReuseGroup(
                accounts=tuple(str(account) for account in group.get("accounts") or ()),
                segment_counts={
                    str(label): int(count)
                    for label, count in (group.get("segment_counts") or {}).items()
                },
            )
            for group in unrecovered_groups
        ),
        krbtgt_recovered=krbtgt_recovered,
        high_value_extracted=high_value_extracted,
        high_value_recovered=high_value_recovered,
        tier_labels={
            str(tier): str(label)
            for tier, label in (block.get("tier_labels") or {}).items()
        }
        if isinstance(block.get("tier_labels"), Mapping)
        else {},
    ).as_dict()


def _non_negative_int(value: Any) -> int:
    """An integer figure read defensively; never negative, never raising."""
    try:
        return max(int(value or 0), 0)
    except (TypeError, ValueError):
        return 0


def _segment_by_tier(block: Mapping[str, Any], tier: str) -> Mapping[str, Any] | None:
    """One persisted segment by its TIER token, or ``None``.

    By token, never by label: the label is client wording that a localized or
    re-worded deliverable may legitimately change, and matching on it is how a
    renderer silently loses a segment.
    """
    for segment in block.get("segments") or ():
        if isinstance(segment, Mapping) and str(segment.get("tier") or "") == tier:
            return segment
    return None


def _headline(block: Mapping[str, Any]) -> str:
    """One client-safe line stating the measured outcome, never the method."""
    try:
        recovered = int(block.get("recovered_total") or 0)
        extracted = int(block.get("extracted_total") or 0)
    except (TypeError, ValueError):
        return ""
    if extracted <= 0:
        return ""
    accounts_noun = "account" if extracted == 1 else "accounts"
    lead = (
        f"Password recovery resolved the password of {recovered:,} of the "
        f"{extracted:,} {accounts_noun} whose credential material was extracted."
    )
    # The boundary leads the sentence, then the directness split, because a
    # recovered Domain Admins password and a recovered Backup Operators password
    # are not the same headline for the reader deciding what to do tonight.
    tier0 = _tier0_rollup(block.get("segments") or ())
    if tier0 is not None and tier0.extracted > 0 and tier0.recovered > 0:
        total = tier0.recovered
        verb = "is" if total == 1 else "are"
        noun = "an administrative account" if total == 1 else "administrative accounts"
        direct = _segment_by_tier(block, TIER_TOKEN_TIER0_DIRECT)
        direct_recovered = _non_negative_int((direct or {}).get("recovered"))
        if direct_recovered >= total:
            clause = f"{noun} with direct control of the domain"
        elif direct_recovered > 0:
            has = "has" if direct_recovered == 1 else "have"
            clause = (
                f"{noun}, and {direct_recovered:,} of them {has} direct control "
                "of the domain"
            )
        else:
            clause = f"{noun} one step from control of the domain"
        lead = f"{lead} Of those, {total:,} {verb} {clause}, which is where to act first."
    return lead


def password_hygiene_view(block: Any) -> dict[str, Any]:
    """Return the render-ready view of a persisted hygiene block.

    The ONE shape the operator panel, the PDF and the web platform read, so the
    absence rule is enforced in a single place rather than at three renderers.

    ``present`` is the gate: ``False`` means render NOTHING, which is the honest
    answer when no cracking was attempted. An absent, unreadable or
    pre-dating-this-record block is also ``present=False``, so a surface never
    invents a figure for a scan that produced none.
    """
    empty: dict[str, Any] = {
        "present": False,
        "cracking_attempted": False,
        "extracted_total": 0,
        "recovered_total": 0,
        "recovery_rate_pct": None,
        "krbtgt_recovered": False,
        "high_value_extracted": 0,
        "high_value_recovered": 0,
        "tier_labels": {},
        "segments": [],
        "reuse_groups_recovered": [],
        "reuse_groups_unrecovered": [],
        "headline": "",
    }
    if not isinstance(block, Mapping):
        return empty
    attempted = bool(block.get("cracking_attempted"))
    try:
        extracted = int(block.get("extracted_total") or 0)
        recovered = int(block.get("recovered_total") or 0)
    except (TypeError, ValueError):
        return empty
    if not attempted or extracted <= 0:
        return empty
    rate = block.get("recovery_rate_pct")
    if rate is None:
        rate = _pct(recovered, extracted)
    return {
        "present": True,
        "cracking_attempted": True,
        "extracted_total": extracted,
        "recovered_total": recovered,
        "recovery_rate_pct": rate,
        "krbtgt_recovered": bool(block.get("krbtgt_recovered")),
        # Orthogonal to the tiers, carried verbatim: an account counted here is
        # also counted in its tier's segment, so the two are never added up.
        "high_value_extracted": _non_negative_int(block.get("high_value_extracted")),
        "high_value_recovered": _non_negative_int(block.get("high_value_recovered")),
        "tier_labels": {
            str(tier): str(label)
            for tier, label in (block.get("tier_labels") or {}).items()
        }
        if isinstance(block.get("tier_labels"), Mapping)
        else {},
        "segments": [
            dict(segment)
            for segment in block.get("segments") or ()
            if isinstance(segment, Mapping)
        ],
        "reuse_groups_recovered": [
            dict(group)
            for group in block.get("reuse_groups_recovered") or ()
            if isinstance(group, Mapping)
        ],
        "reuse_groups_unrecovered": [
            dict(group)
            for group in block.get("reuse_groups_unrecovered") or ()
            if isinstance(group, Mapping)
        ],
        "headline": _headline(block),
    }


def iter_present_password_hygiene(
    named_blocks: Iterable[tuple[str, Any]],
) -> list[tuple[str, dict[str, Any]]]:
    """Return ``(name, view)`` for each domain whose recovery produced figures.

    The ONE "which domains have a hygiene block to render" walk, so the kit's
    inclusion decision, the companion document and the SAR cross-reference all
    agree on the same set rather than re-implementing the gate three times. Each
    view is the shape :func:`read_password_hygiene` returns, already carrying the
    absence rule: a domain that attempted no recovery is simply absent from the
    list.

    Args:
        named_blocks: ``(domain_name, domain_block)`` pairs, each block a
            ``technical_report.json`` domain entry or the renderer's
            ``report_data`` entry for that domain.

    Returns:
        ``(name, view)`` for the present domains, in input order.
    """
    out: list[tuple[str, dict[str, Any]]] = []
    for name, block in named_blocks or ():
        view = read_password_hygiene(block)
        if view.get("present"):
            out.append((str(name), view))
    return out


def any_password_hygiene_present(domain_blocks: Iterable[Any]) -> bool:
    """True when ANY domain block carries a hygiene block with figures.

    The scalar gate the kit's inclusion decision and the SAR cross-reference
    ask: is there a companion document at all? A run that attempted no recovery
    anywhere answers ``False`` and the fourth kit document is absent, which is
    the structural absence rule, not a disclaimer.
    """
    for block in domain_blocks or ():
        if read_password_hygiene(block).get("present"):
            return True
    return False


def read_password_hygiene(domain_block: Any) -> dict[str, Any]:
    """Return the hygiene view for one domain's report block.

    The engine persists the block as a ``control_evidence`` entry (it is an
    observation about the environment, not a finding), and ``control_evidence``
    is NOT ingested generically by the web: every block the platform renders is
    lifted into ``domain_record.stats`` by an explicit key. So both the PDF and
    the web read it through this ONE extractor, which also applies the absence
    rule, rather than each of them walking the evidence list and deciding for
    itself what an empty result means.

    Args:
        domain_block: One ``technical_report.json`` domain entry, or the
            renderer's ``report_data`` entry for that domain.

    Returns:
        The same shape :func:`password_hygiene_view` returns. ``present`` is
        ``False`` for a domain with no block, which is the honest answer for a
        run that attempted no recovery.
    """
    if not isinstance(domain_block, Mapping):
        return password_hygiene_view(None)
    # The direct form a renderer may already hold.
    direct = domain_block.get(PASSWORD_HYGIENE_KEY)
    if isinstance(direct, Mapping):
        # Either the raw persisted block or an already-built view.
        if "present" in direct:
            return dict(direct)
        return password_hygiene_view(direct)
    entries = domain_block.get("control_evidence")
    if not isinstance(entries, list):
        return password_hygiene_view(None)
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        if str(entry.get("key") or "").strip() != PASSWORD_HYGIENE_KEY:
            continue
        return password_hygiene_view(entry.get("details"))
    return password_hygiene_view(None)


__all__ = [
    "PASSWORD_HYGIENE_KEY",
    "SEGMENT_ORDER",
    "SEGMENT_TIER0_ROLLUP",
    "HygieneSegment",
    "PasswordHygiene",
    "PasswordReuseGroup",
    "any_password_hygiene_present",
    "build_password_hygiene",
    "iter_present_password_hygiene",
    "merge_recovered_into_hygiene",
    "password_hygiene_view",
    "read_password_hygiene",
    "tier0_rollup_segment",
]
