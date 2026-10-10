"""Which concrete principal ACTS in an attack step (client-prose SSOT).

An attack-step edge records the SOURCE OBJECT the privilege hangs off: the ACE
holder, the group whose membership grants the right, the well-known identity
every authenticated principal belongs to. That object is the correct subject of
a REMEDIATION sentence ("remove the ACE that Account Operators holds"), but it
is not always the principal that ACTS, because a group cannot act, only a member
can. A narrative that puts the source object in the acting slot can therefore
state that a group controls its own member, which a technical reader reads as a
broken template fill. Two reviewers found exactly that in a paid deliverable.

This module answers one question, "which principal acts in THIS step?", in one
place, for every surface that renders step prose (the PDF report, the writeup
spine, the web CTEM edge panel). Two layers:

1. The step's own recorded executing actor (``details["user"]``), stamped by the
   attack-path executor from the ``resolve_step_execution_actor`` SSOT. This
   layer works even when a SINGLE edge is rendered with no path around it, which
   is how the web CTEM edge panel renders.
2. The nearest preceding individually-named principal in the same displayed
   chain, carried forward across membership hops. Stamped as
   ``acting_principal`` by :func:`resolve_path_step_actors` at the display-record
   decorate seam, the one layer that holds the whole chain.

**A broad source label is sometimes the honest answer.** Everyone,
Authenticated Users and a memberless Domain Users legitimately ARE the source
when any owned principal could act as that source, and the repo's own doctrine
is that the true actor is knowable only after actor selection. So when neither
layer yields a concrete principal, this module returns nothing and the prose
reads with the collective label ("a member of Authenticated Users") instead of
asserting an actor ADscan never identified.

Kept a dependency-light leaf (``__future__`` + ``typing`` + the well-known
principal semantics leaf) so the report, the writeup and the appliance backend
can all resolve an actor without the engine.
"""

from __future__ import annotations

from typing import Any

from adscan_internal.services.well_known_principals import (
    principal_is_dynamic_identity,
)

#: Step-``details`` key carrying the chain-resolved acting principal's label.
ACTING_PRINCIPAL_KEY = "acting_principal"
#: Step-``details`` key carrying that principal's real sAMAccountName.
ACTING_PRINCIPAL_SAM_KEY = "acting_principal_samaccountname"
#: Step-``details`` key carrying that principal's object class.
ACTING_PRINCIPAL_KIND_KEY = "acting_principal_kind"

_ACTING_PRINCIPAL_KEYS: tuple[str, ...] = (
    ACTING_PRINCIPAL_KEY,
    ACTING_PRINCIPAL_SAM_KEY,
    ACTING_PRINCIPAL_KIND_KEY,
)

#: Object classes that name ONE principal, so the source label can act as itself.
_INDIVIDUAL_OBJECT_CLASSES: frozenset[str] = frozenset({"user", "computer"})


def _text(value: Any) -> str:
    return str(value or "").strip()


def _detail(details: Any, key: str) -> str:
    return _text(details.get(key)) if isinstance(details, dict) else ""


def _identity_stem(label: str) -> str:
    """Lowercased comparison stem of a principal label (realm/NetBIOS stripped)."""
    raw = _text(label)
    if "\\" in raw:
        raw = raw.split("\\", 1)[1]
    if "@" in raw:
        raw = raw.split("@", 1)[0]
    return raw.strip().strip("$").lower()


def source_is_collective_principal(details: Any) -> bool:
    """Return whether a step's SOURCE is a collective, not an individual actor.

    True for a group (a real member list, e.g. Backup Operators) and for a
    dynamic well-known identity (Everyone / Authenticated Users / Domain Users).
    Both are legitimate sources of a privilege and neither can be the subject of
    an "acts" sentence on its own.
    """
    if not isinstance(details, dict):
        return False
    if _detail(details, "source_kind").lower() == "group":
        return True
    return principal_is_dynamic_identity(
        sid=_detail(details, "source_sid"),
        label=_detail(details, "from"),
    )


def _source_is_individually_named(details: Any) -> bool:
    """Return whether the step's source names ONE real, individual principal.

    Deliberately three-way with :func:`source_is_collective_principal`: a label
    that is neither (a synthetic unauthenticated vantage, an object class the
    collector could not resolve) is used as-is in prose but never carried
    forward as the actor of a LATER step, because it does not identify an
    account that could act there.
    """
    if not isinstance(details, dict) or source_is_collective_principal(details):
        return False
    if _detail(details, "source_kind").lower() in _INDIVIDUAL_OBJECT_CLASSES:
        return True
    # No stamped object class (an older graph): a real sAMAccountName is still
    # proof the collector resolved an individual directory object.
    return bool(_detail(details, "source_samaccountname"))


def resolve_step_actor(details: Any) -> tuple[str, str, str] | None:
    """Return ``(label, samaccountname, object_class)`` of this step's actor.

    The actor is returned ONLY when it is a concrete principal that differs from
    the step's own source label, so a step whose source already names an
    individual is untouched (its prose is byte-identical to naming the source).
    Returns ``None`` when no concrete actor is known, which is the honest answer
    for a genuinely broad source.
    """
    if not isinstance(details, dict):
        return None

    source_stem = _identity_stem(_detail(details, "from"))
    target_stems = {
        _identity_stem(_detail(details, "to")),
        _identity_stem(_detail(details, "target_samaccountname")),
    } - {""}

    candidates: list[tuple[str, str, str]] = []
    stamped = _detail(details, ACTING_PRINCIPAL_KEY)
    if stamped:
        candidates.append(
            (
                stamped,
                _detail(details, ACTING_PRINCIPAL_SAM_KEY),
                _detail(details, ACTING_PRINCIPAL_KIND_KEY),
            )
        )
    # The executor's own record of who ran the step (``resolve_step_execution_actor``).
    executed_by = _detail(details, "user")
    if executed_by:
        candidates.append((executed_by, executed_by, "user"))

    for label, samaccountname, kind in candidates:
        stem = _identity_stem(label)
        if not stem or stem == source_stem:
            continue
        # Never name the object being acted upon as the one acting on it: that is
        # the same tautology in the other direction.
        if stem in target_stems:
            continue
        return label, samaccountname, kind
    return None


def resolve_path_step_actors(steps: Any) -> None:
    """Stamp each step's acting principal, carried forward along the chain.

    A step whose source is a collective principal was reached THROUGH a concrete
    one: the membership hop before it names the member, and that member is who
    acts. Walks the displayed chain once and stamps
    ``acting_principal``/``..._samaccountname``/``..._kind`` on every collective
    step that has such a predecessor.

    Mutates ``steps`` in place and is idempotent: a re-run recomputes the stamp
    from the step list it is given, so a record whose steps were sliced or
    collapsed after an earlier stamp is corrected rather than left stale. Never
    raises: a missing/odd step shape simply yields no stamp.
    """
    if not isinstance(steps, list):
        return

    carried: tuple[str, str, str] | None = None
    for step in steps:
        details = step.get("details") if isinstance(step, dict) else None
        if not isinstance(details, dict):
            continue
        for key in _ACTING_PRINCIPAL_KEYS:
            details.pop(key, None)

        if _source_is_individually_named(details):
            carried = (
                _detail(details, "from"),
                _detail(details, "source_samaccountname"),
                _detail(details, "source_kind"),
            )
            continue

        if not source_is_collective_principal(details):
            # Neither individual nor collective: prose uses the label as-is and
            # the carried actor is left untouched for later collective steps.
            continue

        actor = carried
        executed_by = _detail(details, "user")
        if executed_by:
            # The step's own executed actor is more specific than anything
            # carried forward, and it is what the executor actually used.
            actor = (executed_by, executed_by, "user")
        if actor is None:
            continue

        label, samaccountname, kind = actor
        stem = _identity_stem(label)
        if not stem or stem == _identity_stem(_detail(details, "from")):
            continue
        if stem in {
            _identity_stem(_detail(details, "to")),
            _identity_stem(_detail(details, "target_samaccountname")),
        }:
            continue
        details[ACTING_PRINCIPAL_KEY] = label
        details[ACTING_PRINCIPAL_SAM_KEY] = samaccountname
        details[ACTING_PRINCIPAL_KIND_KEY] = kind
