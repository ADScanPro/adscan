"""Separate a Windows Hello rollout from a planted shadow credential.

Import-safe SSOT (stdlib + typing only) so every tier reads one derivation.

``msDS-KeyCredentialLink`` carries a public key that permits certificate-based
(PKINIT) Kerberos logon as the object. Two completely different things populate
it, and at ADscan's vantage a single entry looks identical either way:

* **a sanctioned rollout.** Hybrid Azure AD join writes the attribute on
  COMPUTER objects; Windows Hello for Business enrolment writes it on USER
  objects. Modern, device-bound, good hygiene.
* **an attacker's backdoor.** Whoever holds the matching private key can log on
  as the account and recover its NT hash, and the entry survives a password
  reset.

Aggregating both into one finding produces a number that means nothing. On a
reference engagement it read as one ``high`` over 89 objects: 86 Tier-2
computers and 3 Tier-0 users. The client's AD team dismisses 89 in thirty
seconds with "that is our Hello rollout", and the three accounts that actually
matter leave with the dismissal. Reporting the whole class as INFO instead would
bury the same three.

So the finding is SEGMENTED, and the discriminator is population SHAPE:

1. **Privilege tier.** A Tier-0 object is never absorbed into a baseline, at any
   scale. Scale explains a laptop; it does not explain a Domain Admin, and the
   blast radius there is the whole domain.
2. **Object type, judged as its own population.** A device rollout at scale says
   nothing about why three USERS carry an entry, because a different attribute
   owner writes each one. Counting the two together is what let 86 computers
   vouch for 3 users.
3. **Scale.** At rollout scale the population reads as managed deployment;
   a handful with no rollout behind them is the attack shape and stays in the
   confirm list.
4. **Hybrid corroboration.** An Azure AD Connect synchronization account
   observed in the same workspace is independent evidence that a hybrid rollout
   exists, so a smaller estate still reads as one.

Anything the discriminators cannot place stays in the confirm list. The default
is to surface, never to assume benign.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

#: Population size at which key-credential registrations read as a managed
#: rollout on their own. Chosen well above the one-to-three an attacker plants on
#: the objects worth owning, and well below any real WHfB / hybrid-join estate.
ROLLOUT_MIN = 20

#: The same bar when a hybrid deployment is independently corroborated by an
#: Azure AD Connect synchronization account observed in this workspace. The
#: rollout no longer has to be inferred from scale alone, so a smaller estate
#: qualifies.
HYBRID_ROLLOUT_MIN = 8

#: Object kinds a rollout story can account for. Anything else never inherits it.
_ROLLOUT_KINDS = frozenset({"user", "computer"})


@dataclass(frozen=True)
class ShadowCredentialObject:
    """One AD object carrying at least one ``msDS-KeyCredentialLink`` entry."""

    samaccountname: str
    kind: str  # "User" | "Computer" (anything else is never baseline)
    is_tier0: bool = False
    key_count: int = 1

    @property
    def normalized_kind(self) -> str:
        """Lower-cased object kind, for population bucketing."""
        return str(self.kind or "").strip().lower()


@dataclass(frozen=True)
class ShadowCredentialSegmentation:
    """The two populations one raw shadow-credential observation splits into.

    ``accounts_to_confirm`` is the finding: objects whose entry the rollout does
    not account for, Tier-0 first. ``rollout_baseline`` is the deployment, which
    is reported as an observation of the environment and never as a weakness.
    """

    accounts_to_confirm: tuple[ShadowCredentialObject, ...] = ()
    rollout_baseline: tuple[ShadowCredentialObject, ...] = ()
    hybrid: bool = False
    rollout_threshold: int = ROLLOUT_MIN
    computer_count: int = 0
    user_count: int = 0
    _tier0: int = field(default=0)

    @property
    def has_accounts_to_confirm(self) -> bool:
        """Whether anything survived the discriminators and must be reported."""
        return bool(self.accounts_to_confirm)

    @property
    def has_rollout_baseline(self) -> bool:
        """Whether a managed rollout was observed."""
        return bool(self.rollout_baseline)

    @property
    def tier0_count(self) -> int:
        """How many objects to confirm are Tier 0."""
        return self._tier0


def segment_shadow_credentials(
    objects: Iterable[ShadowCredentialObject],
    *,
    hybrid: bool,
) -> ShadowCredentialSegmentation:
    """Split key-credential holders into the ones to confirm and the rollout.

    Args:
        objects: Every object observed carrying a key credential.
        hybrid: Whether this workspace independently observed an Azure AD
            Connect synchronization account, which corroborates a hybrid
            rollout and lowers the scale bar.

    Returns:
        A :class:`ShadowCredentialSegmentation`. Objects to confirm are ordered
        Tier-0 first, then by name, so the account an attacker most wants is the
        first one the client reads.
    """
    records = [obj for obj in objects if isinstance(obj, ShadowCredentialObject)]
    threshold = HYBRID_ROLLOUT_MIN if hybrid else ROLLOUT_MIN

    # Each object type is its own population with its own attribute owner, so a
    # rollout in one must not vouch for the other.
    per_kind: dict[str, int] = {}
    for obj in records:
        kind = obj.normalized_kind
        if kind in _ROLLOUT_KINDS:
            per_kind[kind] = per_kind.get(kind, 0) + 1

    to_confirm: list[ShadowCredentialObject] = []
    baseline: list[ShadowCredentialObject] = []
    for obj in records:
        kind = obj.normalized_kind
        at_rollout_scale = kind in _ROLLOUT_KINDS and per_kind.get(kind, 0) >= threshold
        # Tier 0 is checked FIRST and overrides scale entirely.
        if obj.is_tier0 or not at_rollout_scale:
            to_confirm.append(obj)
        else:
            baseline.append(obj)

    to_confirm.sort(key=lambda o: (0 if o.is_tier0 else 1, o.samaccountname.lower()))
    baseline.sort(key=lambda o: o.samaccountname.lower())

    return ShadowCredentialSegmentation(
        accounts_to_confirm=tuple(to_confirm),
        rollout_baseline=tuple(baseline),
        hybrid=bool(hybrid),
        rollout_threshold=threshold,
        computer_count=per_kind.get("computer", 0),
        user_count=per_kind.get("user", 0),
        _tier0=sum(1 for o in to_confirm if o.is_tier0),
    )


__all__ = [
    "HYBRID_ROLLOUT_MIN",
    "ROLLOUT_MIN",
    "ShadowCredentialObject",
    "ShadowCredentialSegmentation",
    "segment_shadow_credentials",
]
