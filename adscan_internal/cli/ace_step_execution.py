"""ACL/ACE step execution helpers.

This module centralizes the mapping between BloodHound ACL/ACE relationships
stored in ``attack_graph.json`` and the corresponding ADscan exploitation
wrappers on the shell.

It is intentionally shared by multiple interactive flows:
- executing an attack path (Phase 2, ask_for_user_privs, etc.)
- (future) direct execution from `enumerate_user_aces` without duplicating logic
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rich.prompt import Confirm, Prompt
from rich.text import Text

from adscan_internal import print_info, print_warning, telemetry
from adscan_internal.rich_output import (
    BRAND_COLORS,
    mark_sensitive,
    print_info_debug,
    print_panel,
    print_info_verbose,
    print_system_change_warning,
    strip_sensitive_markers,
)
from adscan_internal.services.attack_graph_service import (
    get_node_by_label,
    infer_directory_object_enabled_state,
    resolve_netexec_target_for_node_label,
)
from adscan_core.rich_output import print_exception


def set_last_execution_outcome(shell: Any, outcome: dict[str, Any] | None) -> None:
    """Persist the last execution outcome on the shell for follow-up UX."""
    setattr(shell, "_last_ace_execution_outcome", outcome)


def _set_last_ace_execution_outcome(shell: Any, outcome: dict[str, Any] | None) -> None:
    """Backwards-compatible wrapper for ACE-specific callers."""
    set_last_execution_outcome(shell, outcome)


def get_last_execution_outcome(shell: Any) -> dict[str, Any] | None:
    """Return and clear the last execution outcome stored on the shell."""
    outcome = getattr(shell, "_last_ace_execution_outcome", None)
    if isinstance(outcome, dict):
        setattr(shell, "_last_ace_execution_outcome", None)
        return dict(outcome)
    setattr(shell, "_last_ace_execution_outcome", None)
    return None


def get_last_ace_execution_outcome(shell: Any) -> dict[str, Any] | None:
    """Backwards-compatible wrapper for ACE-specific callers."""
    return get_last_execution_outcome(shell)


def _consume_group_membership_operation_outcome(shell: Any) -> dict[str, Any]:
    """Return one temporary add-member outcome emitted by the exploit wrapper."""
    outcome = get_last_execution_outcome(shell) or {}
    if str(outcome.get("key") or "").strip().lower() != "group_membership_operation":
        return {}
    return outcome


def _normalize_account(value: str) -> str:
    name = strip_sensitive_markers(str(value or "")).strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name.strip().lower()


def _is_audit_mode(shell: Any) -> bool:
    """Return whether the current shell is running in audit mode."""
    return str(getattr(shell, "type", "") or "").strip().lower() == "audit"


def _is_ctf_mode(shell: Any) -> bool:
    """Return whether the current shell is running in CTF mode."""
    return str(getattr(shell, "type", "") or "").strip().lower() == "ctf"


def _sanitize_prompt_account(value: str) -> str:
    """Normalize an account value captured from interactive prompts."""
    return strip_sensitive_markers(str(value or "")).strip()


def _node_kind(node: dict[str, Any] | None) -> str:
    if not isinstance(node, dict):
        return "Unknown"
    kind = node.get("kind") or node.get("labels") or node.get("type")
    if isinstance(kind, list) and kind:
        return str(kind[0])
    if isinstance(kind, str) and kind:
        return kind
    return "Unknown"


def _node_props(node: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(node, dict):
        return {}
    props = node.get("properties")
    return props if isinstance(props, dict) else {}


def _infer_target_enabled(
    shell: Any,
    *,
    domain: str,
    target_kind: str,
    to_node: dict[str, Any] | None,
    to_label: str,
) -> tuple[bool | None, str]:
    """Infer whether a target is enabled using node metadata plus workspace fallbacks."""
    try:
        return infer_directory_object_enabled_state(
            shell,
            domain=domain,
            principal_name=_node_sam_or_label(to_node, to_label),
            principal_kind=target_kind,
            node=to_node,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        marked_target = mark_sensitive(
            _normalize_account(_node_sam_or_label(to_node, to_label)) or to_label,
            "user",
        )
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            "[ace-context] enabled-state fallback failed: "
            f"domain={marked_domain} target={marked_target} "
            f"reason={mark_sensitive(str(exc), 'detail')}"
        )
        return None, "fallback_error"


def _node_domain(node: dict[str, Any] | None) -> str | None:
    props = _node_props(node)
    value = props.get("domain")
    if isinstance(value, str) and value.strip():
        return value.strip().lower()
    return None


def _node_sam_or_label(node: dict[str, Any] | None, fallback: str) -> str:
    props = _node_props(node)
    sam = props.get("samaccountname")
    if isinstance(sam, str) and sam.strip():
        return sam.strip()
    label = fallback.strip()
    return label


def _node_object_sid(node: dict[str, Any] | None) -> str | None:
    """Return the node's objectSid (normalized to the ``S-1-...`` prefix) or None.

    The SID is the unambiguous identity for resolving a tombstone DN — it is
    preserved across AD Recycle Bin deletion. Mirrors the collector's node keying
    (``object_id`` == SID) and the graph-layer ``objectid``/``objectId`` keys.
    """
    if not isinstance(node, dict):
        return None
    props = _node_props(node)
    for value in (
        props.get("objectid"),
        props.get("objectId"),
        node.get("objectid"),
        node.get("objectId"),
        node.get("object_id"),
    ):
        if isinstance(value, str) and value.strip():
            sid = value.strip()
            idx = sid.upper().find("S-1-")
            if idx != -1:
                sid = sid[idx:]
            if sid.upper().startswith("S-1-"):
                return sid.upper()
    return None


def _resolve_domain_password(shell: object, domain: str, username: str) -> str | None:
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return None
    domain_data = domains_data.get(domain)
    if not isinstance(domain_data, dict):
        return None
    creds = domain_data.get("credentials")
    if not isinstance(creds, dict):
        return None
    normalized_target = _normalize_account(username)
    if not normalized_target:
        return None
    for stored_user, stored_credential in creds.items():
        if _normalize_account(str(stored_user or "")) != normalized_target:
            continue
        if not isinstance(stored_credential, str):
            return None
        candidate = stored_credential.strip()
        return candidate or None
    return None


def _pick_execution_user(
    *,
    summary: dict[str, Any],
    context_username: str | None,
    from_label: str,
    from_node: dict[str, Any] | None,
) -> str | None:
    if context_username:
        normalized = _normalize_account(context_username)
        if normalized:
            return normalized
    applies_to = summary.get("applies_to_users")
    if isinstance(applies_to, list):
        for user in applies_to:
            if isinstance(user, str) and user.strip():
                normalized = _normalize_account(user)
                if normalized:
                    return normalized
    if _node_kind(from_node).lower() == "user":
        normalized = _normalize_account(from_label)
        if normalized:
            return normalized
    return None


# Well-known SIDs that are NOT enumerable member-list groups — every
# authenticated principal is effectively a member. A source step whose principal
# is one of these is controlled by ANY owned principal, so there is no member set
# to intersect. Domain Users / Domain Computers are deliberately NOT here: they
# carry real member lists (the membership SSOT merges the implicit primary-group
# membership) and resolve through the normal group-member intersection.
_WELLKNOWN_ALL_PRINCIPALS_STEMS: frozenset[str] = frozenset(
    {
        "everyone",
        "authenticated users",
        "users",
    }
)


def _source_label_stem(from_label: str | None) -> str:
    """Return the lowercased ``DOMAIN\\``-stripped, ``@realm``-stripped stem."""
    raw = str(from_label or "").strip()
    if "\\" in raw:
        raw = raw.split("\\", 1)[1]
    if "@" in raw:
        raw = raw.split("@", 1)[0]
    return raw.strip().lower()


# Domain-wide broad groups whose membership is EVERY domain principal of the
# relevant type. Unlike the well-known SIDs above these DO carry a real member
# list (the membership SSOT merges the implicit primary-group), so when that list
# is available it is authoritative. They matter only for the INDETERMINATE case:
# when no membership snapshot is available, a missing list must NOT over-block a
# legitimate Domain Users step — every owned domain principal is a member. A
# NON-broad group (Administrators, Domain Admins) with the same indeterminate
# state stays locked, because a false "actionable" on a Tier-0 group is the
# dangerous direction.
_BROAD_DOMAIN_SOURCE_STEMS: frozenset[str] = _WELLKNOWN_ALL_PRINCIPALS_STEMS | frozenset(
    {
        "domain users",
        "domain computers",
    }
)


def is_wellknown_all_principals_source(from_label: str | None) -> bool:
    """Return whether ``from_label`` is a well-known "all principals" SID group.

    These (Everyone / Authenticated Users / BUILTIN Users) are not enumerable
    member-list groups: every authenticated principal is a member, so any owned
    principal legitimately acts as the source.
    """
    return _source_label_stem(from_label) in _WELLKNOWN_ALL_PRINCIPALS_STEMS


def is_broad_domain_source(from_label: str | None) -> bool:
    """Return whether ``from_label`` is a broad domain-wide group.

    The well-known "all principals" SIDs PLUS Domain Users / Domain Computers.
    Used only as an INDETERMINATE-membership fallback: any owned principal is a
    member of one of these, so a missing snapshot must not over-block it.
    """
    return _source_label_stem(from_label) in _BROAD_DOMAIN_SOURCE_STEMS


def source_ownership_bucket(relation: str | None) -> str:
    """Classify how a step's SOURCE principal must be controlled to act.

    Returns:
        ``"carry_forward"`` — a post-exploitation technique chained off a prior
        access edge (``EdgeKind.DERIVED``: DumpLSA/DumpSAM/xp_cmdshell/linked-
        server/token-theft/coercion/…). The acting credential is the session
        carried forward from the completed access step, never ownership of the
        source host.

        ``"own_source"`` — every other executable relation (access/auth edges AND
        control/ACL/delegation/escalation edges). Actionable only when ADscan
        controls the source principal by its ACTUAL type (own the user, own a real
        group member, or own the computer-account credential).

    The discriminator is the RELATION's ``EdgeKind`` — NOT the source object type.
    A COMPUTER source lands in ``own_source`` for ``AllowedToDelegate`` (own
    ``SRV01$``) and in ``carry_forward`` for ``DumpLSA`` (carried session), decided
    purely by the relation.
    """
    from adscan_internal.services.edge_kind import (  # noqa: PLC0415
        EdgeKind,
        classify_edge_kind,
    )

    return "carry_forward" if classify_edge_kind(relation) is EdgeKind.DERIVED else "own_source"


def _group_member_sams(shell: Any, domain: str, from_label: str | None) -> set[str] | None:
    """Return the lowercased sAMAccountNames of a group's direct+nested members.

    Group membership is the SOURCE OF TRUTH for who can act as a group
    ``from_label``. Reuses the membership SSOT (``build_group_member_index`` over
    the cached ``membership_snapshot``) so the actor resolver, the stale-context
    guard, and the readiness predicate all agree.

    Returns a set (possibly empty for a real empty group / a non-group label when
    the snapshot HAS data), or ``None`` when membership is **indeterminate** — no
    snapshot data is available, so callers must NOT treat "not found" as "not a
    member" (that would drop a legitimate explicit-context principal).
    """
    label = str(from_label or "").strip()
    if not label:
        return set()
    try:
        from adscan_internal.services.attack_paths_core import (  # noqa: PLC0415
            build_group_member_index,
        )
        from adscan_internal.services.membership_snapshot import (  # noqa: PLC0415
            load_membership_snapshot,
        )

        snapshot = load_membership_snapshot(shell, domain)
        user_members, computer_members, has_principals = build_group_member_index(
            snapshot,
            domain,
            exclude_tier0=False,
            include_computers=True,
        )
        if not has_principals:
            return None
        from_label_norm = label.upper()
        member_labels: set[str] = set()
        member_labels.update(user_members.get(from_label_norm, set()) or set())
        member_labels.update(computer_members.get(from_label_norm, set()) or set())
        sams: set[str] = set()
        for member in member_labels:
            sam = str(member or "").strip().split("@", 1)[0].strip().lower()
            if sam:
                sams.add(sam)
        return sams
    except Exception as exc:  # noqa: BLE001 — membership lookup is best-effort
        telemetry.capture_exception(exc)
        return None


def resolve_source_node_kind(shell: Any, domain: str, from_label: str | None) -> str:
    """Return the attack-graph node kind of a step's SOURCE label.

    The single implementation of "what kind of thing is this step sourced from"
    (``User`` / ``Group`` / ``Computer`` / ...). Returns ``""`` when the label is
    empty, the node is absent from the graph, or it carries no kind — callers
    must read that as *indeterminate*, never as "not a group".

    It exists as a named helper because the answer decides whether an owned
    principal may act for the step at all, and every consumer must reach the
    same answer: :func:`resolve_execution_candidates` derives it here when a
    caller does not supply one, so the ownership gate and the executor cannot
    disagree about a step the gate already approved.
    """
    label = str(from_label or "").strip()
    if not label:
        return ""
    try:
        node = get_node_by_label(shell, domain, label=label)
    except Exception as exc:  # noqa: BLE001 — graph lookup is best-effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return ""
    kind = _node_kind(node)
    return "" if kind == "Unknown" else kind


def _label_matches_step_source(step: dict[str, Any], from_label: str) -> bool:
    """Return whether ``step``'s source label is the one being resolved."""
    details = step.get("details") if isinstance(step.get("details"), dict) else {}
    step_from = str(details.get("from") or "").strip()
    if not step_from:
        return False
    return step_from.upper() == from_label.strip().upper()


def resolve_step_relation(summary: dict[str, Any] | None, from_label: str | None) -> str:
    """Return the relation of the step in ``summary`` sourced at ``from_label``.

    The companion of :func:`resolve_source_node_kind` for the second argument
    every dispatch call site omits. The relation decides whether a carried
    session legitimately stays the actor (a post-exploitation ``carry_forward``
    edge) or the source principal must be owned by its own type — so deriving
    the node kind WITHOUT the relation would silently drop the carried context
    on every post-ex step, which is a self-loop on the COMPUTER it runs against.

    Resolution is deliberately conservative: an attack path is a simple chain,
    so a source label identifies its step uniquely. When several steps share the
    label and disagree on the relation, this returns ``""`` (indeterminate)
    rather than guessing, which leaves the caller on the pre-existing
    ``own_source`` default.
    """
    label = str(from_label or "").strip()
    if not label or not isinstance(summary, dict):
        return ""
    steps = summary.get("steps")
    if not isinstance(steps, list):
        return ""
    actions = {
        str(step.get("action") or "").strip()
        for step in steps
        if isinstance(step, dict) and _label_matches_step_source(step, label)
    }
    actions.discard("")
    if len(actions) != 1:
        return ""
    return actions.pop()


def _exec_user_memo_key(domain: str, from_label: str | None) -> tuple[str, str]:
    """Key the per-run execution-user selection memo by (domain, source principal).

    Keyed on the SOURCE principal (not the relation/target) so the operator's
    "which owned member of this group do I act as" decision is asked ONCE per run
    and reused for every step and every resolver call that acts from the same
    source — collapsing the repeat "Select a user to execute this step" prompts.
    """
    return (str(domain or "").lower(), _normalize_account(from_label or ""))


def _get_exec_user_memo(shell: Any, key: tuple[str, str]) -> str | None:
    """Return the memoized chosen principal for this step's source, if any."""
    memo = getattr(shell, "_attack_step_exec_user_memo", None)
    if isinstance(memo, dict):
        value = memo.get(key)
        return value if isinstance(value, str) and value else None
    return None


def _set_exec_user_memo(shell: Any, key: tuple[str, str], value: str) -> None:
    """Memoize the operator's chosen principal for this step's source (per run)."""
    memo = getattr(shell, "_attack_step_exec_user_memo", None)
    if not isinstance(memo, dict):
        memo = {}
        try:
            shell._attack_step_exec_user_memo = memo  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 — best-effort; memo is a UX nicety
            return
    memo[key] = value


def reset_execution_user_memo(shell: Any) -> None:
    """Clear the per-run execution-user selection memo.

    Called once at the start of an attack-path execution run so the operator's
    memoized choices do not silently carry across separate runs — each run
    re-asks (at most once per source) rather than reusing a stale prior choice.
    """
    try:
        shell._attack_step_exec_user_memo = {}  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 — best-effort
        pass


# Principals that exist in nearly every domain, hold nothing worth exercising,
# and frequently sort early in credential-capture order. They stay candidates
# (a step with nothing else to try may still want them) but never lead. This is
# a tail-sink, NOT the ranking: the ranking below is what stops the next stale
# service account from leading, which no name list could.
_LOW_VALUE_ACCOUNT_STEMS: frozenset[str] = frozenset(
    {
        "guest",
        "krbtgt",
        "defaultaccount",
        "anonymous",
        "wdagutilityaccount",
    }
)

# Cache of {sAMAccountName: transitive group labels} per membership snapshot.
# Keyed by the snapshot's identity AND holding a reference to it, so an entry
# can never be served to a different snapshot that reused a freed id().
_PRINCIPAL_GROUP_CLOSURE_CACHE: dict[
    tuple[int, str], tuple[dict[str, Any], dict[str, set[str]]]
] = {}
_PRINCIPAL_GROUP_CLOSURE_CACHE_LIMIT = 4


def _principal_group_closures(shell: Any, domain: str) -> dict[str, set[str]]:
    """Return ``{sAMAccountName: transitive group labels}`` for the domain.

    Built by inverting the membership SSOT's group->members index
    (``build_group_member_index``), which already expands nested ancestors and
    merges the implicit primary group, so the values ARE the transitive closure.
    Never hand-roll a MemberOf walk here (``CLAUDE.md`` § Group membership).

    Returns an empty mapping when no membership snapshot is available — the
    caller must degrade to "privilege unknown", never to "no privilege".
    """
    try:
        from adscan_internal.services.attack_paths_core import (  # noqa: PLC0415
            build_group_member_index,
        )
        from adscan_internal.services.membership_snapshot import (  # noqa: PLC0415
            load_membership_snapshot,
        )

        snapshot = load_membership_snapshot(shell, domain)
        if not isinstance(snapshot, dict):
            return {}
        cache_key = (id(snapshot), str(domain or "").strip().lower())
        cached = _PRINCIPAL_GROUP_CLOSURE_CACHE.get(cache_key)
        if cached is not None and cached[0] is snapshot:
            return cached[1]

        user_members, computer_members, has_principals = build_group_member_index(
            snapshot,
            domain,
            exclude_tier0=False,
            include_computers=True,
        )
        if not has_principals:
            return {}
        closures: dict[str, set[str]] = {}
        for index in (user_members, computer_members):
            for group_label, members in index.items():
                for member in members:
                    sam = str(member or "").strip().split("@", 1)[0].strip().lower()
                    if sam:
                        closures.setdefault(sam, set()).add(group_label)
        if len(_PRINCIPAL_GROUP_CLOSURE_CACHE) >= _PRINCIPAL_GROUP_CLOSURE_CACHE_LIMIT:
            _PRINCIPAL_GROUP_CLOSURE_CACHE.clear()
        _PRINCIPAL_GROUP_CLOSURE_CACHE[cache_key] = (snapshot, closures)
        return closures
    except Exception as exc:  # noqa: BLE001 — ranking input is best-effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return {}


def _principal_privilege_rank(group_labels: set[str]) -> int:
    """Rank a principal by its own group memberships (higher = more privileged).

    Reuses the tier SSOT ``classify_principal_by_groups`` — there is no second
    principal-ranking taxonomy (``CLAUDE.md`` § Nomenclature Standard).
    """
    if not group_labels:
        return 0
    try:
        from adscan_internal.services.compromise_class import (  # noqa: PLC0415
            CompromiseClass,
            classify_principal_by_groups,
        )

        compromise_class = classify_principal_by_groups(sorted(group_labels))
        if compromise_class is CompromiseClass.DOMAIN_BREAKER:
            return 2
        if compromise_class is CompromiseClass.PRIVILEGED_ESCALATOR:
            return 1
    except Exception as exc:  # noqa: BLE001 — ranking input is best-effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    return 0


def rank_execution_candidates(
    shell: Any,
    *,
    domain: str,
    candidates: list[str],
    from_label: str | None,
    context_username: str | None,
) -> list[str]:
    """Order owned candidates so the FIRST one is the defensible actor.

    A non-interactive run takes the head of this list (the picker's default
    index), and the ownership gate reads the head to decide whether a usable
    credential exists — so the order is a correctness input, not presentation.
    Before this ranking the head was whichever credential happened to be
    captured first, which on one real engagement was ``guest``.

    Order, best first:

    1. the step's own source principal, when it is itself a candidate;
    2. the principal carried forward from the preceding step in this chain;
    3. the most privileged candidate, by the tier SSOT
       (``classify_principal_by_groups``);
    4. otherwise the incoming order, preserved (a stable sort), so an ordering
       a caller already applied is never scrambled.

    Two sinks override all of the above: a principal with no usable stored
    credential (it cannot authenticate — its only effect at the head of the list
    is to abort the step) and a well-known low-value account. Both are kept at
    the tail rather than dropped, so a step whose only candidates are sunk still
    has something to try.

    Network-logon ordering (``order_logon_capable_first``) is applied by the
    caller AFTER this, since it is host-specific ground truth and must win.
    """
    if len(candidates) < 2:
        return list(candidates)

    from adscan_internal.services.credential_store_service import (  # noqa: PLC0415
        get_stored_domain_credential_for_user,
    )

    domains_data = getattr(shell, "domains_data", {}) or {}
    closures = _principal_group_closures(shell, domain)
    source_key = _normalize_account(from_label or "")
    context_key = _normalize_account(context_username or "")

    def _sort_key(indexed: tuple[int, str]) -> tuple[int, int, int, int, int]:
        index, candidate = indexed
        key = _normalize_account(candidate)
        has_secret = bool(
            get_stored_domain_credential_for_user(
                domains_data, domain=domain, username=candidate
            )
        )
        sunk = (not has_secret) or (key in _LOW_VALUE_ACCOUNT_STEMS)
        return (
            1 if sunk else 0,
            0 if (source_key and key == source_key) else 1,
            0 if (context_key and key == context_key) else 1,
            -_principal_privilege_rank(closures.get(key, set())),
            index,
        )

    ordered = [
        candidate for _, candidate in sorted(enumerate(candidates), key=_sort_key)
    ]
    if ordered != list(candidates):
        print_info_debug(
            "[exec-user] Ranked candidates by source/context/privilege: "
            f"{', '.join(mark_sensitive(user, 'user') for user in ordered[:5])}"
        )
    return ordered


def resolve_execution_candidates(
    shell: Any,
    *,
    domain: str,
    context_username: str | None,
    summary: dict[str, Any],
    from_label: str | None,
    from_node_kind: str | None = None,
    host: str | None = None,
    strict_source: bool = False,
    relation: str | None = None,
) -> tuple[list[str], str]:
    """PURE, read-only resolution of the owned principals that could run a step.

    NO prompt, NO selection, NO side effects. Returns ``(candidates, source_tag)``
    — the ordered list of owned principals source-faithful to this step (empty
    when ADscan controls no valid source principal), plus a debug tag naming how
    they were derived. This is the SSOT every NON-execution consumer uses:

    * the actionability predicate (``is the candidate list non-empty?``),
    * the readiness ``N/M`` column and which steps are shown/selectable,
    * the pre-execution ownership gate.

    None of those fire the interactive picker — the ONE interactive selection
    lives in :func:`select_execution_user`, invoked only at actual step execution.

    When ``host`` is provided (a NETWORK-authenticating step — SMB/WinRM/RDP/
    MSSQL), candidate principals the host has already denied a network logon
    (ground truth in the logon-denied cache) are sunk to the end of the list, so
    the sole-candidate auto-select and the default prompt index prefer a
    logon-capable principal while never emptying the candidate set. ``host=None``
    (TGT/AS-REQ/scoped-ticket callers, or callers without a host in scope) leaves
    ordering unchanged — the denial is network-logon-specific and must not gate
    those flows.

    ``relation`` makes the carried-context decision EDGE-KIND-AWARE (see
    :func:`source_ownership_bucket`). A post-exploitation technique chained off a
    prior access edge (``carry_forward``) keeps the carried session as the actor;
    a control/delegation edge (``own_source``) requires owning the source
    principal by its actual type, so a stale carried context is dropped.

    ``from_node_kind`` and ``relation`` are DERIVED HERE when a caller does not
    supply them — from the graph node behind ``from_label`` and from the step in
    ``summary`` sourced at that label. Both are overrides, not the only source.
    Whether a source principal can hold a credential at all is a property of the
    step, so it must not depend on each of two dozen dispatch branches
    remembering to pass a keyword: when they did not, a group-sourced step fell
    through to "any stored credential" and executed as a principal that was not
    a member of the source group, while the ownership gate — which does pass the
    kind — had already approved the step for the real member. For a verifier that
    authenticates to a host (``AdminTo`` / ``CanRDP`` / ``CanPSRemote`` /
    ``SQLAccess``) that mismatch can even SUCCEED by an unrelated route and stamp
    the edge ``success`` naming the wrong actor, so the deliverable claims ADscan
    validated a grant it never tested.

    The returned list is RANKED (see :func:`rank_execution_candidates`): its head
    is the best actor, which is what the non-interactive picker default and the
    ownership gate both read.
    """

    def _preview_users(users: list[str], *, max_items: int = 5) -> str:
        """Return a compact debug preview of candidate usernames."""
        cleaned = [str(user).strip() for user in users if str(user).strip()]
        if not cleaned:
            return "[]"
        preview = cleaned[:max_items]
        rendered = ", ".join(mark_sensitive(user, "user") for user in preview)
        if len(cleaned) > max_items:
            rendered = f"{rendered}, +{len(cleaned) - max_items} more"
        return f"[{rendered}]"

    creds = getattr(shell, "domains_data", {}).get(domain, {}).get("credentials", {})
    cred_keys = (
        {
            _normalize_account(str(stored_user or "")): str(stored_user)
            for stored_user in creds.keys()
        }
        if isinstance(creds, dict)
        else {}
    )
    from_user = _normalize_account(from_label or "")
    # Derive the step's own properties when the caller did not state them. A
    # supplied value is authoritative (including an explicit "" from a caller
    # that already looked and found nothing); ``None`` means "not stated".
    if from_node_kind is None:
        from_node_kind = resolve_source_node_kind(shell, domain, from_label)
    if relation is None:
        relation = resolve_step_relation(summary, from_label)
    node_kind_lower = str(from_node_kind or "").strip().lower()
    bucket = source_ownership_bucket(relation)
    # Resolve membership for a group source OR any broad domain source (Domain
    # Users / Domain Computers may arrive with an unresolved node kind in
    # degraded/partial graphs — we still need the real None-vs-set distinction so
    # the indeterminate-membership fallback can fire).
    _resolve_membership = node_kind_lower == "group" or is_broad_domain_source(from_label)

    # Membership of the source group (SSOT; merges the implicit primary-group
    # [Domain Users] and well-known nesting). ``None`` = indeterminate (no
    # snapshot data — must NOT be read as "not a member"); a set = authoritative.
    member_sams_raw = _group_member_sams(shell, domain, from_label) if _resolve_membership else set()
    member_sams = member_sams_raw or set()

    # Carried-forward context: trust it by DEFAULT (the pre-execution ownership
    # gate and the target's own ACL check are the backstop), and DROP it only when
    # ADscan can prove it is the WRONG actor. The decision is EDGE-KIND-AWARE — a
    # carried context is dropped only for a control/ACL/delegation edge
    # (``own_source``) whose source we can prove the context does not control:
    #   * source is a USER the context does not match → drop; a user's ACE is
    #     exercised SOLELY by that user.
    #   * source is a COMPUTER → drop; a delegation/RBCD write (AllowedToDelegate)
    #     is minted only by the source COMPUTER ACCOUNT, never a carried user
    #     session (contrast a post-ex DumpLSA, which IS carry_forward and kept).
    #   * source is a GROUP with a CONFIRMED non-membership → drop; the context is
    #     not a real member and would run the write as the wrong principal (the
    #     DCSync-from-a-group-you-don't-control bug).
    # Everything else keeps the context: a post-ex carry_forward session, a
    # well-known all-principals source (every principal is a member), a group with
    # indeterminate/confirmed membership (runtime membership a snapshot can't see),
    # or an unknown node kind (conservative — the gate/ACL is the backstop).
    exec_username = _normalize_account(context_username or "")
    if exec_username:
        if not from_user or exec_username == from_user:
            print_info_debug(
                f"[exec-user] Using context username: {mark_sensitive(exec_username, 'user')}"
            )
            return [exec_username], "context_username"
        keep_context = True
        if bucket != "carry_forward" and not is_broad_domain_source(from_label):
            if node_kind_lower == "user":
                keep_context = False
            elif node_kind_lower == "computer":
                keep_context = False
            elif node_kind_lower == "group":
                keep_context = member_sams_raw is None or exec_username in member_sams
        if keep_context:
            print_info_debug(
                f"[exec-user] Using context username: {mark_sensitive(exec_username, 'user')} "
                f"(bucket={bucket}, source={mark_sensitive(from_label or '?', 'node')})"
            )
            return [exec_username], "context_username"
        print_info_debug(
            "[exec-user] Ignoring stale context username "
            f"{mark_sensitive(exec_username, 'user')}: the step source "
            f"{mark_sensitive(from_label or '?', 'node')} is a control/ACL/delegation "
            "principal the context does not control; resolving the actor from the "
            "source instead."
        )

    if from_user and from_user in cred_keys:
        print_info_debug(
            f"[exec-user] Using from_label credential: {mark_sensitive(from_user, 'user')}"
        )
        return [from_user], "from_label_credential"
    if from_user and str(from_node_kind or "").strip().lower() == "user":
        print_info_debug(
            "[exec-user] Using from_label as execution user candidate without "
            "stored credential match."
        )
        return [from_user], "from_label_user_node"

    candidate_users: list[str] = []
    source_tag = "unresolved"

    # For Group from_label, membership is the SOURCE OF TRUTH for who can
    # execute the step.  The graph collector writes the edge from the
    # group that ACTUALLY holds the right (e.g. DCSync edges originate
    # from ``DOMAIN ADMINS`` / ``DOMAIN CONTROLLERS`` / ``ADMINISTRATORS``
    # — the groups granted ``DS-Replication-Get-Changes-All``). An owned
    # principal may act ONLY if it is a REAL member of that group (the
    # membership SSOT merges the implicit primary-group [Domain Users] and
    # nested membership). This is also what makes the multi-step carry-forward
    # work naturally: when a prior step produces a credential that is a real
    # member of the next step's ``from_label`` group (e.g. ADCSESC1 → a Domain
    # Admin that belongs to ``ADMINISTRATORS``), the next step picks it here.
    # There is intentionally NO ``affected_users`` fallback: the path's
    # entry-point users are never evidence of controlling a mid-path group, and
    # using them ran the write as the wrong principal (the DCSync-from-a-group-
    # you-don't-control bug).
    group_members_resolved = False
    if _resolve_membership and isinstance(creds, dict) and creds:
        matched_via_membership: list[str] = []
        for sam in member_sams:
            stored_key = cred_keys.get(sam)
            if stored_key:
                matched_via_membership.append(stored_key)

        if matched_via_membership:
            candidate_users = list(dict.fromkeys(matched_via_membership))
            group_members_resolved = True
            source_tag = "group_membership"
            print_info_debug(
                "[exec-user] Group-membership resolution: selected "
                f"{len(candidate_users)} candidate(s) for "
                f"from_label={mark_sensitive(str(from_label or ''), 'node')}: "
                f"{_preview_users(candidate_users)}"
            )
        elif member_sams_raw is None:
            # INDETERMINATE, not "nobody". No membership snapshot exists, so we
            # did not check and find nothing — we could not check at all. Both
            # read the same in the candidate list (a non-broad group stays
            # locked either way, per the doctrine below) but they are opposite
            # conclusions, and an operator debugging a locked step is owed the
            # difference.
            print_info_debug(
                "[exec-user] Group-membership resolution: membership of "
                f"group={mark_sensitive(str(from_label or ''), 'node')} is "
                "INDETERMINATE (no membership snapshot for this domain); "
                "treating the source group as not controlled rather than "
                "assuming any stored credential is a member."
            )
        else:
            print_info_debug(
                "[exec-user] Group-membership resolution: no stored "
                "credential matches any actual member of "
                f"group={mark_sensitive(str(from_label or ''), 'node')} "
                f"(members={len(member_sams)}); the source group is not controlled."
            )

    # Broad source where any owned principal legitimately acts:
    #   * a well-known "all principals" SID (Everyone / Authenticated Users /
    #     BUILTIN Users) — always; or
    #   * a domain-wide group (Domain Users / Domain Computers) whose real
    #     membership is INDETERMINATE (no snapshot) — every domain principal is a
    #     member, so a missing snapshot must not over-block it. When membership is
    #     KNOWN, the real member intersection above is authoritative and this
    #     fallback does not fire. A NON-broad group (Administrators, Domain Admins)
    #     stays unresolved -> locked even when membership is indeterminate.
    broad_any_owned = is_wellknown_all_principals_source(from_label) or (
        is_broad_domain_source(from_label) and member_sams_raw is None
    )
    if not candidate_users and broad_any_owned and cred_keys:
        candidate_users = [str(stored_user) for stored_user in creds.keys()]
        source_tag = "broad_source"
        print_info_debug(
            "[exec-user] Broad source "
            f"{mark_sensitive(str(from_label or ''), 'node')}: any owned principal is a "
            f"member ({len(candidate_users)} candidate(s))."
        )

    if (
        not candidate_users
        and not strict_source
        and isinstance(creds, dict)
        and creds
        and node_kind_lower != "group"
    ):
        print_info_debug(
            "[exec-user] No source-faithful actor; falling back to all stored credentials "
            f"(from_node_kind={mark_sensitive(node_kind_lower or 'unknown', 'detail')})."
        )
        candidate_users = [str(stored_user) for stored_user in creds.keys()]
        source_tag = "all_stored_credentials"
    elif (
        not candidate_users
        and strict_source
        and node_kind_lower != "group"
    ):
        # Ownership-gate (strict) path: the SOURCE principal is not owned via any
        # source-faithful route (from_label credential, group membership, or a
        # path-affected principal). Do NOT fall back to "any stored credential" —
        # that is exactly the over-count that offers a step whose real source we
        # do not control. Leave the actor unresolved so the gate locks the step.
        print_info_debug(
            "[exec-user] Strict source resolution: no source-faithful actor for "
            f"from_label={mark_sensitive(str(from_label or '?'), 'node')}; "
            "not falling back to any stored credential."
        )
    elif (
        not candidate_users
        and node_kind_lower == "group"
        and not group_members_resolved
    ):
        # Group from_label AND no owned member.  Without an owned real member we
        # can't safely fall back to "any stored cred" (that would invent a
        # privilege the principal doesn't hold — the DCSync-from-a-group-you-
        # don't-control bug). Leave the actor unresolved so the gate locks it.
        print_info_debug(
            "[exec-user] Group from_label with no owned member: "
            "no stored credential is a real member of the source group. "
            "Skipping fallback to avoid selecting a non-member principal."
        )

    if candidate_users:
        candidate_users = list(dict.fromkeys(candidate_users))
        # Rank BEFORE the host-specific ordering, so logon-denial ground truth
        # (per-host and observed) still wins the head of the list.
        candidate_users = rank_execution_candidates(
            shell,
            domain=domain,
            candidates=candidate_users,
            from_label=from_label,
            context_username=context_username,
        )
        if host:
            # Network-auth step: prefer a logon-capable principal (denied ones
            # sink to the tail, retained as last resort). Single source.
            from adscan_internal.services.credential_store_service import (  # noqa: PLC0415
                order_logon_capable_first,
            )

            candidate_users = order_logon_capable_first(
                getattr(shell, "domains_data", {}) or {},
                domain,
                host=host,
                candidates=candidate_users,
            )
        stored_credential_preview = (
            _preview_users([str(stored_user) for stored_user in creds.keys()])
            if isinstance(creds, dict)
            else "[]"
        )
        print_info_debug(
            "[exec-user] Found "
            f"{len(candidate_users)} candidate user(s) with stored credentials. "
            f"candidates={_preview_users(candidate_users)} "
            f"stored_credentials={stored_credential_preview}"
        )
        return candidate_users, source_tag

    print_info_debug(
        "[exec-user] No execution user resolved: "
        f"from_label={from_label!r}, node_kind={node_kind_lower!r}, "
        f"bucket={bucket!r}, group_member_count={len(member_sams)}"
    )
    return [], "unresolved"


def select_execution_user(
    shell: Any,
    *,
    domain: str,
    candidates: list[str],
    source_tag: str,
    from_label: str | None,
    relation: str | None = None,
    max_options: int = 20,
) -> tuple[str | None, str]:
    """The ONE interactive seam that picks WHICH owned principal runs a step.

    Fires the "Select a user to execute this step" prompt at EXACTLY this call
    site — invoked only when the operator actually executes a step. Read-only
    consumers (annotation, readiness, actionability, the pre-execution gate) call
    :func:`resolve_execution_candidates` directly and NEVER reach here, so merely
    computing the display never prompts.

    Rules:
    * empty candidate list -> unresolved (nothing to run from);
    * a single candidate -> auto-select, no prompt;
    * a choice already memoized for this step's SOURCE in the current run ->
      reuse it silently (so the same step / source is never re-asked);
    * non-interactive runs auto-resolve to the default index (``shell.
      _questionary_select`` delegates to the centralized helper).

    Net effect: the operator is prompted AT MOST ONCE per source principal per run.

    ``default_idx=0`` is deliberate and only defensible because
    :func:`resolve_execution_candidates` hands back a RANKED list (see
    :func:`rank_execution_candidates`): index 0 is the best candidate, not the
    first credential that happened to be captured. Do not add a second ordering
    here — the ranking belongs beside the candidate set, where the ownership
    gate reads it too.
    """
    if not candidates:
        return None, source_tag

    if len(candidates) == 1:
        print_info_debug(
            f"[exec-user] Auto-selected sole candidate: {mark_sensitive(candidates[0], 'user')}"
        )
        return _normalize_account(candidates[0]), source_tag

    memo_key = _exec_user_memo_key(domain, from_label)
    normalized_candidates = {_normalize_account(user) for user in candidates}
    memoized = _get_exec_user_memo(shell, memo_key)
    if memoized and memoized in normalized_candidates:
        print_info_debug(
            "[exec-user] Reusing memoized execution-user selection for source "
            f"{mark_sensitive(from_label or '?', 'node')}: "
            f"{mark_sensitive(memoized, 'user')} (not re-prompting)."
        )
        return memoized, "memoized_selection"

    creds = getattr(shell, "domains_data", {}).get(domain, {}).get("credentials", {})
    cred_keys = (
        {_normalize_account(str(user or "")): str(user) for user in creds.keys()}
        if isinstance(creds, dict)
        else {}
    )

    marked_domain = mark_sensitive(domain, "domain")
    print_panel(
        "\n".join(
            [
                f"Domain: {marked_domain}",
                f"Users with stored credentials: {len(candidates)}",
            ]
        ),
        title=Text("Select Execution User", style=f"bold {BRAND_COLORS['info']}"),
        border_style=BRAND_COLORS["info"],
        expand=False,
    )

    if hasattr(shell, "_questionary_select"):
        options = [mark_sensitive(user, "user") for user in candidates[:max_options]]
        if len(candidates) > max_options:
            options.append(
                f"Enter username (showing {max_options} of {len(candidates)})"
            )
        options.append("Cancel")
        idx = shell._questionary_select(
            "Select a user to execute this step:",
            options,
            default_idx=0,
        )
        if idx is None or idx >= len(options) - 1:
            print_info_debug("[exec-user] User selection cancelled.")
            return None, "cancelled"
        if len(candidates) > max_options and idx == len(options) - 2:
            manual_user = Prompt.ask("Enter username")
            if not manual_user:
                print_info_debug("[exec-user] Manual username entry empty.")
                return None, "manual_empty"
            normalized = _normalize_account(manual_user)
            if not normalized:
                print_info_debug("[exec-user] Manual username entry invalid.")
                print_warning("Invalid username entered.")
                return None, "manual_invalid"
            stored = cred_keys.get(normalized)
            if not stored:
                marked_user = mark_sensitive(normalized, "user")
                print_warning(
                    f"No stored credential found for {marked_user}. "
                    "Please select a user with saved credentials."
                )
                print_info_debug(
                    f"[exec-user] Manual username not in credentials: {marked_user}"
                )
                return None, "manual_missing_credential"
            print_info_debug(
                f"[exec-user] Manual username matched credentials: {mark_sensitive(stored, 'user')}"
            )
            chosen = _normalize_account(stored)
            _set_exec_user_memo(shell, memo_key, chosen)
            return chosen, "manual_selection"
        print_info_debug(
            f"[exec-user] Selected candidate: {mark_sensitive(candidates[idx], 'user')}"
        )
        chosen = _normalize_account(str(candidates[idx]))
        _set_exec_user_memo(shell, memo_key, chosen)
        return chosen, "interactive_selection"

    return _normalize_account(candidates[0]), "fallback_stored_credential"


def _resolve_execution_user_with_source(
    shell: Any,
    *,
    domain: str,
    context_username: str | None,
    summary: dict[str, Any],
    from_label: str | None,
    from_node_kind: str | None = None,
    host: str | None = None,
    max_options: int = 20,
    strict_source: bool = False,
    relation: str | None = None,
) -> tuple[str | None, str]:
    """Resolve AND interactively select the execution user for a step to EXECUTE.

    The execution seam: it computes the source-faithful candidate set via the
    pure :func:`resolve_execution_candidates` and then routes it through the ONE
    interactive picker :func:`select_execution_user` (single candidate auto-
    selects; multiple prompt once, memoized per run; non-interactive auto-
    resolves). Read-only callers (readiness / actionability / the ownership gate)
    must call :func:`resolve_execution_candidates` directly, never this — so
    merely annotating the path list never prompts.
    """
    candidates, source_tag = resolve_execution_candidates(
        shell,
        domain=domain,
        context_username=context_username,
        summary=summary,
        from_label=from_label,
        from_node_kind=from_node_kind,
        host=host,
        strict_source=strict_source,
        relation=relation,
    )
    return select_execution_user(
        shell,
        domain=domain,
        candidates=candidates,
        source_tag=source_tag,
        from_label=from_label,
        relation=relation,
        max_options=max_options,
    )


def resolve_execution_user(
    shell: Any,
    *,
    domain: str,
    context_username: str | None,
    summary: dict[str, Any],
    from_label: str | None,
    from_node_kind: str | None = None,
    host: str | None = None,
    max_options: int = 20,
    strict_source: bool = False,
    relation: str | None = None,
) -> str | None:
    """Resolve an execution user for a step to EXECUTE (interactive selection).

    Pass ``host`` for a NETWORK-authenticating step so principals already denied
    a network logon on that host are deprioritized (see
    :func:`_resolve_execution_user_with_source`). Omit it for TGT/AS-REQ/
    scoped-ticket flows. Pass ``strict_source=True`` from the ownership-gate
    predicate to forbid the "any stored credential" fallback. Pass ``relation`` so
    the carried-context decision is edge-kind-aware (post-ex carry-forward vs
    control/delegation own-source). This is the EXECUTION path and may prompt
    (once, memoized); a read-only caller uses :func:`resolve_execution_candidates`.
    """
    exec_username, _ = _resolve_execution_user_with_source(
        shell,
        domain=domain,
        context_username=context_username,
        summary=summary,
        from_label=from_label,
        from_node_kind=from_node_kind,
        host=host,
        max_options=max_options,
        strict_source=strict_source,
        relation=relation,
    )
    return exec_username


def resolve_exec_password(
    shell: Any,
    *,
    domain: str,
    username: str,
    context_username: str | None,
    context_password: str | None,
) -> str | None:
    """Resolve a password/hash for ``username`` without mismatching context creds."""
    normalized_user = _normalize_account(username)
    if not normalized_user:
        return None
    normalized_context_user = _normalize_account(context_username or "")
    if (
        context_password
        and normalized_context_user
        and normalized_user == normalized_context_user
    ):
        return context_password
    return _resolve_domain_password(shell, domain, normalized_user)


@dataclass(frozen=True, slots=True)
class AceStepContext:
    domain: str
    relation: str
    from_label: str
    to_label: str
    exec_username: str
    exec_password: str
    target_domain: str
    target_kind: str
    target_enabled: bool | None
    target_sam_or_label: str
    # RBCD chain coordination: when an AddMember/write-to-group step feeds a
    # downstream AllowedToAct whose trustee is this group, the member to add must
    # be an owned SPN-bearing account (the one the AllowedToAct will mint as) —
    # resolved once via the shared helper so both steps agree. None = default
    # behaviour (no downstream RBCD coordination).
    member_to_add: str | None = None
    # Tombstoned (AD Recycle Bin) target: the object is deleted and must be
    # reanimated before the ACE technique runs — mirrors target_enabled→enable-first.
    # target_enabled is derived from the tombstone's PRESERVED userAccountControl, so
    # the existing enable-first check then handles a restored-but-disabled account.
    target_tombstoned: bool = False
    target_deleted_dn: str | None = None
    # objectSid of the target — preserved across AD Recycle Bin deletion, so it is
    # the unambiguous key for resolving the real tombstone DN when target_deleted_dn
    # is absent (cached/merged graph node). msDS-LastKnownRDN is the clean RDN.
    target_sid: str | None = None
    target_last_known_rdn: str | None = None


ACL_ACE_RELATIONS: set[str] = {
    "genericall",
    "genericwrite",
    "writeaccountrestrictions",
    "forcechangepassword",
    "addself",
    "addmember",
    "readgmsapassword",
    "readlapspassword",
    "writedacl",
    "writeowner",
    "owns",
    "writespn",
    "dcsync",
    # AddKeyCredentialLink grants exactly the msDS-KeyCredentialLink write →
    # Shadow Credentials (the ONLY valid primitive for this edge). Routed to the
    # existing shadow-creds path with forced_method="shadow".
    "addkeycredentiallink",
    # AllExtendedRights (null-GUID ControlAccess) is the SOLE edge on many paths
    # (SharpHound emits the specific ForceChangePassword/DCSync/ReadLAPSPassword
    # edges from DIFFERENT ACEs). Remapped by target class to the concrete
    # extended-right it confers (see execute_ace_step). NOT a write (no shadow-creds).
    "allextendedrights",
}


def describe_ace_relation_support(
    relation: str,
    target_kind: str,
) -> tuple[bool, str | None]:
    """Return whether an ACE relation is supported for a target object type.

    This is used to prevent "false supported" cases where the relationship
    exists in BloodHound (and the action name is mapped), but ADscan does not
    implement an exploitation path for the specific target object type.

    Args:
        relation: ACE/ACL relation to evaluate.
        target_kind: Target object type.

    Returns:
        Tuple of (supported, reason). If supported is True, reason is None.
    """
    relation = relation.strip().lower()
    target_kind = target_kind.strip()
    target_kind_norm = target_kind.lower()

    if relation == "genericall":
        # GenericAll implies WriteDACL + WriteOwner, so on a Domain head it can
        # be exploited through the DCSync-via-DACL pipeline (add DS-Replication
        # ACEs, then DCSync). On other supported objects it routes to the
        # standard control-object handlers. On a GPO it routes to the Immediate
        # Scheduled Task plant (SYSTEM code-exec on every linked host).
        if target_kind_norm in {"user", "computer", "ou", "group", "domain", "gpo"}:
            return True, None
        return (
            False,
            f"GenericAll exploitation is not implemented for target type {target_kind}.",
        )

    if relation == "genericwrite":
        # GenericWrite allows property writes but NOT DACL modification, so it
        # cannot be turned into DCSync on a Domain head. Keep it scoped to
        # objects where a property-write primitive yields takeover. A GPO is in
        # scope: writing the SYSVOL Machine half plus the versionNumber /
        # gPCMachineExtensionNames attributes is enough to plant an Immediate
        # Scheduled Task (no DACL modification needed).
        if target_kind_norm in {"user", "computer", "ou", "group", "gpo"}:
            return True, None
        if target_kind_norm == "domain":
            return (
                False,
                (
                    "GenericWrite on a Domain object does not grant DACL modification, "
                    "so DCSync is not reachable through this edge."
                ),
            )
        return (
            False,
            f"GenericWrite exploitation is not implemented for target type {target_kind}.",
        )

    if relation == "owns":
        if target_kind_norm in {"user", "computer", "ou", "group", "domain"}:
            return True, None
        return (
            False,
            f"Owns exploitation is not implemented for target type {target_kind}.",
        )

    if relation == "writeaccountrestrictions":
        if target_kind_norm == "computer":
            return True, None
        return (
            False,
            f"WriteAccountRestrictions exploitation is only implemented for Computer targets (got {target_kind}).",
        )

    if relation == "writeowner":
        if target_kind_norm in {"user", "group"}:
            return True, None
        return (
            False,
            f"WriteOwner exploitation is only implemented for User/Group targets (got {target_kind}).",
        )

    if relation == "writespn":
        if target_kind_norm in {"user", "computer"}:
            return True, None
        return (
            False,
            f"WriteSPN exploitation is only implemented for User/Computer targets (got {target_kind}).",
        )

    # Default: assume supported (the executor may still fail at runtime).
    return True, None


def describe_ace_step_support(context: AceStepContext) -> tuple[bool, str | None]:
    """Return whether an ACE step is supported for the given context."""
    return describe_ace_relation_support(
        context.relation,
        context.target_kind,
    )


def build_ace_step_context(
    shell: Any,
    domain: str,
    *,
    relation: str,
    summary: dict[str, Any],
    from_label: str,
    to_label: str,
    context_username: str | None,
    context_password: str | None,
    member_to_add: str | None = None,
    strict_source: bool = False,
) -> AceStepContext | None:
    """Build an ACE execution context for a given step (best-effort).

    ``member_to_add`` (RBCD coordination) overrides the group-membership default
    when a downstream AllowedToAct needs a specific owned SPN-bearing member.
    ``strict_source=True`` (the ownership-gate predicate) forbids resolving the
    actor from the "any stored credential" fallback, so the context is built
    ONLY when the step's real SOURCE principal is controlled.
    """
    from_node = get_node_by_label(shell, domain, label=from_label)
    to_node = get_node_by_label(shell, domain, label=to_label)
    exec_username, exec_user_source = _resolve_execution_user_with_source(
        shell,
        domain=domain,
        context_username=context_username,
        summary=summary,
        from_label=from_label,
        from_node_kind=_node_kind(from_node),
        strict_source=strict_source,
        relation=relation,
    )
    if not exec_username:
        marked_domain = mark_sensitive(domain, "domain")
        marked_from = mark_sensitive(from_label, "node")
        marked_to = mark_sensitive(to_label, "node")
        print_info_debug(
            "[ace-context] Missing exec username: "
            f"relation={mark_sensitive(relation, 'detail')} domain={marked_domain} "
            f"from={marked_from} to={marked_to} "
            f"context_username={'set' if context_username else 'unset'} "
            f"applies_to_users={summary.get('applies_to_users')!r} "
            f"from_node_kind={mark_sensitive(_node_kind(from_node), 'detail')} "
            f"resolution_source={mark_sensitive(exec_user_source, 'detail')}"
        )
        return None

    stored_password = _resolve_domain_password(shell, domain, exec_username)
    password = resolve_exec_password(
        shell,
        domain=domain,
        username=exec_username,
        context_username=context_username,
        context_password=context_password,
    )
    if not password:
        marked_domain = mark_sensitive(domain, "domain")
        marked_from = mark_sensitive(from_label, "node")
        marked_to = mark_sensitive(to_label, "node")
        marked_user = mark_sensitive(exec_username, "user")
        print_info_debug(
            "[ace-context] Missing exec credential: "
            f"relation={mark_sensitive(relation, 'detail')} domain={marked_domain} "
            f"from={marked_from} to={marked_to} exec_user={marked_user} "
            f"context_password={'set' if context_password else 'unset'} "
            f"stored_domain_credential={'present' if stored_password else 'absent'} "
            f"resolution_source={mark_sensitive(exec_user_source, 'detail')}"
        )
        return None

    target_domain = _node_domain(to_node) or domain
    target_kind = _node_kind(to_node)
    target_enabled, target_enabled_source = _infer_target_enabled(
        shell,
        domain=target_domain,
        target_kind=target_kind,
        to_node=to_node,
        to_label=to_label,
    )
    target_sam_or_label = _node_sam_or_label(to_node, to_label)
    _target_props = _node_props(to_node)
    target_tombstoned = bool(_target_props.get("tombstoned"))
    target_deleted_dn = (
        str(_target_props.get("deleted_dn") or "").strip() or None
        if target_tombstoned
        else None
    )
    target_sid = _node_object_sid(to_node)
    target_last_known_rdn = (
        str(_target_props.get("last_known_rdn") or "").strip() or None
    )
    marked_domain = mark_sensitive(domain, "domain")
    marked_from = mark_sensitive(from_label, "node")
    marked_to = mark_sensitive(to_label, "node")
    marked_user = mark_sensitive(exec_username, "user")
    credential_source = (
        "context_password" if context_password else "stored_domain_credential"
    )
    print_info_debug(
        "[ace-context] Built execution context: "
        f"relation={mark_sensitive(relation, 'detail')} domain={marked_domain} "
        f"from={marked_from} to={marked_to} exec_user={marked_user} "
        f"credential_source={mark_sensitive(credential_source, 'detail')} "
        f"user_source={mark_sensitive(exec_user_source, 'detail')} "
        f"target_kind={mark_sensitive(target_kind, 'detail')} "
        f"target_domain={mark_sensitive(target_domain, 'domain')} "
        f"target_enabled={mark_sensitive(str(target_enabled), 'detail')} "
        f"target_enabled_source={mark_sensitive(target_enabled_source, 'detail')}"
    )

    return AceStepContext(
        domain=domain,
        relation=relation,
        from_label=from_label,
        to_label=to_label,
        exec_username=exec_username,
        exec_password=password,
        target_domain=target_domain,
        target_kind=target_kind,
        target_enabled=target_enabled,
        target_sam_or_label=target_sam_or_label,
        member_to_add=member_to_add,
        target_tombstoned=target_tombstoned,
        target_deleted_dn=target_deleted_dn,
        target_sid=target_sid,
        target_last_known_rdn=target_last_known_rdn,
    )


def _acl_cleanup_register(
    shell: Any,
    context: AceStepContext,
    *,
    kind: str,
    detail: dict[str, Any] | None = None,
) -> None:
    """Register an ACL/attribute change with the ledger and acl_cleanup_actions.

    No-op when neither environment_change_ledger nor acl_cleanup_actions is
    present on the shell; backward compatible with test stubs and lite builds.
    """
    ledger = getattr(shell, "environment_change_ledger", None)
    actions = getattr(shell, "acl_cleanup_actions", None)
    if ledger is None and actions is None:
        return

    change_id: str | None = None
    if ledger is not None:
        try:
            ledger_detail = {
                "target_domain": context.target_domain,
                "target_object": context.target_sam_or_label,
                "exec_username": context.exec_username,
                "executor_username": context.exec_username,
                "executor_auth_domain": context.domain,
                "credential_lookup_domain": context.domain,
            }
            if detail:
                ledger_detail.update(detail)
            change_id = ledger.register_change(
                kind=kind,
                domain=context.domain,
                target=context.target_sam_or_label,
                detail=ledger_detail,
                method=(
                    f"BloodHound ACE - {context.relation}"
                    f" ({context.from_label} → {context.to_label})"
                ),
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    if actions is not None:
        action: dict[str, Any] = {
            "kind": kind,
            "domain": context.domain,
            "target_domain": context.target_domain,
            "target": context.target_sam_or_label,
            "exec_username": context.exec_username,
            "exec_password": context.exec_password,
            "_ledger_change_id": change_id,
        }
        if detail:
            action.update(detail)
        try:
            actions.append(action)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)


def _capture_original_owner(shell: Any, context: AceStepContext) -> str | None:
    """Query BloodyAD for the current owner SID of the target object before WriteOwner.

    Returns the SID string (e.g. 'S-1-5-21-...') if parseable, else None.
    None causes cleanup to fall back to operator_required with PS instructions.
    """
    import re

    from adscan_internal.services.exploitation import ExploitationService

    try:
        domains_data = getattr(shell, "domains_data", {}) or {}
        target_domain_data = (
            domains_data.get(context.target_domain) or {}
            if isinstance(domains_data, dict)
            else {}
        )
        pdc_ip = str(target_domain_data.get("pdc") or "").strip() or None
        pdc_hostname = str(target_domain_data.get("pdc_hostname") or "").strip() or None
        pdc_host = pdc_hostname or pdc_ip
        if not pdc_host:
            return None

        service = ExploitationService()
        attr_result = service.acl.get_object_attributes(
            pdc_host=pdc_host,
            domain=context.domain,
            username=context.exec_username,
            password=context.exec_password,
            target_object=context.target_sam_or_label,
            attribute_names=("nTSecurityDescriptor",),
            kerberos=True,
            timeout=30,
        )
        if not attr_result.success:
            return None

        raw = str(attr_result.raw_output or "")
        sid_match = re.search(r"(S-1-\d+-\d+(?:-\d+)+)", raw)
        if sid_match:
            return sid_match.group(1)
        return None
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


def _execute_genericall_domain_dcsync(
    shell: Any,
    context: AceStepContext,
) -> bool:
    """Exploit GenericAll on a Domain head as WriteDACL → DCSync.

    GenericAll implies WriteDACL, so the canonical exploitation against a
    Domain object is to grant DS-Replication-Get-Changes / -All ACEs to the
    executing principal (DACL mutation) and then trigger DCSync. Both stages
    are run from this single handler so the attack-path step that ends at the
    Domain head reaches Domain Compromise without requiring the operator to
    chain a separate WriteDACL edge.

    The handler reuses the existing primitives (`exploit_write_dacl` for the
    DACL grant, `dcsync` for replication) - no new exploitation logic lives
    here, only orchestration and UX.
    """
    marked_target = mark_sensitive(context.target_sam_or_label, "domain")
    marked_user = mark_sensitive(context.exec_username, "user")
    print_system_change_warning(
        title="[bold yellow]Tier-0 Operation: GenericAll on Domain (WriteDACL + DCSync)[/bold yellow]",
        summary=(
            f"Technique: GenericAll on Domain head ({marked_target})\n"
            f"Execution user: {marked_user}"
        ),
        planned_changes=[
            "Grant DS-Replication-Get-Changes and DS-Replication-Get-Changes-All ACEs"
            " on the domain head via native LDAP DACL mutation.",
            "Trigger DCSync to extract domain credential material (krbtgt, DA accounts).",
        ],
        impact_notes=[
            "DACL mutation is logged by domain controllers and by EDR products monitoring"
            " replication ACE grants.",
            "DCSync traffic is visible to SIEM rules monitoring DRSUAPI GetNCChanges calls.",
            "Added replication ACEs will be removed on session teardown via the environment"
            " change ledger.",
        ],
        cleanup_notes=[
            "Added DS-Replication ACEs are tracked and removed automatically.",
            "Verify cleanup completed in the environment change ledger before ending the engagement.",
        ],
        authorization_note=(
            "This reaches Domain Compromise. Only continue if you are authorized"
            " to fully compromise this domain."
        ),
    )
    if not Confirm.ask(
        "Proceed with WriteDACL + DCSync execution?",
        default=False,
    ):
        print_warning("GenericAll on Domain execution cancelled by operator.")
        return False

    grant_ok = shell.exploit_write_dacl(
        context.domain,
        context.exec_username,
        context.exec_password,
        context.target_sam_or_label,
        context.target_domain,
        "domain",
        followup_after=False,
    )
    if not grant_ok:
        print_warning(
            "Failed to grant DCSync rights via DACL mutation; aborting DCSync stage."
        )
        return False

    exec_sid = getattr(shell, "_last_exec_sid", context.exec_username)
    _acl_cleanup_register(
        shell,
        context,
        kind="dacl_ace_added",
        detail={
            "trustee": exec_sid or context.exec_username,
            "rights_type": "dcsync",
        },
    )

    print_info(
        f"[{BRAND_COLORS['success']}]DCSync rights granted.[/{BRAND_COLORS['success']}]"
        " Triggering domain replication..."
    )
    return bool(
        shell.dcsync(
            context.domain,
            context.exec_username,
            context.exec_password,
            context.target_domain,
        )
    )


def _dispatch_gpo_immediate_task(shell: Any, context: AceStepContext) -> bool:
    """Dispatch a GenericAll/GenericWrite→GPO step to the plant helper.

    Resolves the target GPO node's distinguishedName / objectId from the
    workspace attack graph (the unambiguous keys the shell helper matches the
    writable-GPO candidate on), then delegates to the non-interactive,
    single-target shell helper. Falls back to the node label when the
    identifiers are absent (merged/cached nodes).
    """
    to_node = get_node_by_label(shell, context.domain, label=context.to_label)
    props = _node_props(to_node)
    node = to_node if isinstance(to_node, dict) else {}
    target_dn = str(
        node.get("distinguishedname")
        or node.get("distinguished_name")
        or props.get("distinguishedname")
        or props.get("distinguished_name")
        or ""
    ).strip()
    target_object_id = str(
        node.get("objectId")
        or node.get("objectid")
        or props.get("objectid")
        or props.get("objectId")
        or ""
    ).strip()

    helper = getattr(shell, "exploit_gpo_immediate_task_for_step", None)
    if not callable(helper):
        print_warning(
            "GPO Immediate Scheduled Task execution helper is unavailable in "
            "this shell context."
        )
        return False
    return bool(
        helper(
            context,
            target_dn=target_dn or None,
            target_object_id=target_object_id or None,
        )
    )


def execute_ace_step(shell: Any, *, context: AceStepContext) -> bool | None:
    """Execute an ACL/ACE relationship step using the best available primitive.

    Note:
        Most underlying exploit routines are interactive and do not return a
        simple True/False. The higher-level caller should set the active-step
        context and update the edge status to "attempted" before invoking this.
        Any downstream credential additions will typically mark the step as
        success via the active-step mechanism.
    """
    relation = context.relation.strip().lower()
    set_last_execution_outcome(shell, None)
    if relation not in ACL_ACE_RELATIONS:
        return None

    marked_to = mark_sensitive(context.to_label, "node")

    target_kind = context.target_kind.strip().lower()

    if relation == "allextendedrights":
        # AllExtendedRights = an ACE granting ControlAccess with a NULL ObjectType
        # GUID (ALL extended / control-access rights). It is a distinct permission
        # bit from WriteProperty, so it does NOT grant the msDS-KeyCredentialLink
        # write (Shadow Credentials — empirically ACCESS_DENIED / LDAP 50) nor any
        # attribute READ (gMSA password). It confers the object's extended rights,
        # which — mirroring SharpHound's ACLProcessor per-target branching — reduce
        # to ONE concrete abuse per target class. Remap to that supported technique
        # and fall through to its branch (pure dispatch — no duplicated exploit code):
        #   user     -> ForceChangePassword (User-Force-Change-Password)
        #   domain   -> DCSync (Get-Changes + Get-Changes-All)
        #   computer -> ReadLAPSPassword (SharpHound only emits a computer
        #               AllExtendedRights edge when LAPS is present, so never a dead-end)
        _all_ext_remap = {
            "user": "forcechangepassword",
            "domain": "dcsync",
            "computer": "readlapspassword",
        }
        effective_relation = _all_ext_remap.get(target_kind)
        if effective_relation is None:
            print_warning(
                f"AllExtendedRights on a '{target_kind}' target has no supported "
                "extended-right abuse (only user, computer, and domain are actionable)."
            )
            return False
        print_info_debug(
            f"ace allextendedrights -> {effective_relation} "
            f"(target_kind={target_kind})"
        )
        relation = effective_relation

    if relation == "dcsync":
        # GAP 3 — scoped-ticket-first: if a prior step (SPNJack, relay-RBCD)
        # minted an LDAP-service ticket scoped to the DC host (impersonating a
        # privileged user), DRSUAPI replication should run via that ccache rather
        # than the generic, under-privileged execution credential. Mirrors the
        # DumpLSA cifs-scoped-ticket path. Alias-aware host match guarantees a
        # ticket for a different host is never used here.
        dcsync_username = context.exec_username
        dcsync_password = context.exec_password
        try:
            from adscan_internal.models.domain import resolve_dc_fqdn  # noqa: PLC0415
            from adscan_internal.services.credential_store_service import (  # noqa: PLC0415
                resolve_execution_credential,
            )

            _domain_data = getattr(shell, "domains_data", {}).get(context.domain, {})
            # Resolve the DC via the FQDN SSOT (CLAUDE.md "Kerberos SPNs — always
            # FQDN"). The old ``dc_fqdn -> pdc_hostname_fqdn -> resolve_dc_ip``
            # chain skipped the short ``pdc_hostname`` rung and returned a raw IP
            # in best-effort mode, which cannot serve a ``cifs`` service ticket
            # (SEC_E_LOGON_DENIED). ``resolve_dc_fqdn`` promotes a short hostname
            # to ``<host>.<domain>`` and adds the workspace inventory fallback, so
            # the scoped-ticket lookup below keys on a real FQDN, never an IP.
            _dc_host = resolve_dc_fqdn(_domain_data, target_domain=context.domain) or ""
            if _dc_host:
                # relation="dcsync" -> cifs (DRSUAPI replicates over an aiosmb SMB
                # connection, NOT ldap). The central map owns the service class so
                # the right ticket is selected by construction; preferent matching
                # falls back to any ticket for the DC (a TGT-bearing ccache serves
                # cifs regardless of its own SPN class).
                _scoped = resolve_execution_credential(
                    shell, domain=context.domain, host=_dc_host, relation="dcsync"
                )
                if _scoped is not None:
                    dcsync_username, dcsync_password = _scoped
                    print_info_debug(
                        "ace dcsync: reusing host-scoped service ticket for "
                        f"{mark_sensitive(str(_dc_host), 'hostname')} as "
                        f"{mark_sensitive(dcsync_username, 'user')}"
                    )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

        result = shell.dcsync(context.domain, dcsync_username, dcsync_password)
        # Edge semantics: DCSync → Domain means "compromise the domain by
        # replicating its secrets". Success requires either the krbtgt
        # secret (full domain compromise via Golden Ticket material) or at
        # least one Tier-0 account (Administrator RID 500, Domain/Schema/
        # Enterprise Admins). Extracting only standard accounts means the
        # replication ran but did not deliver what this edge promises, so
        # the edge is marked failed. ``None`` signals an aborted run
        # (missing context, transport failure) - also failed.
        if not isinstance(result, dict):
            return False
        if result.get("krbtgt") or int(result.get("tier0_count", 0)) >= 1:
            return True
        return False

    if relation == "readgmsapassword":
        from_domain = (
            context.from_label.rsplit("@", 1)[-1].strip().lower()
            if "@" in context.from_label
            else context.domain
        )

        # Pre-execution structural warning: if the source group is in a different
        # domain than the target gMSA, this edge may be blocked at runtime.
        # Domain Local groups (GROUP_TYPE_RESOURCE_GROUP | SECURITY_ENABLED = -2147483644)
        # are resource-domain scoped; membership via ForeignSecurityPrincipal in DomainB
        # does NOT grant effective read rights on a gMSA object stored in DomainA.
        # The graph edge is present because the group SID appears in msDS-GroupMSAMembership
        # on the gMSA, but that SID resolves to a Domain Local group in a different domain.
        if (
            from_domain
            and context.target_domain
            and from_domain != context.target_domain.lower()
        ):
            print_warning(
                f"[dim]Pre-execution check:[/dim] the ReadGMSAPassword source "
                f"({mark_sensitive(context.from_label, 'node')}) is in [bold]{from_domain}[/bold] "
                f"but the gMSA is in [bold]{context.target_domain}[/bold]. "
                "If the source group is Domain Local, this edge is structurally not effective - "
                "the SID appears in msDS-GroupMSAMembership but Domain Local scope does not "
                "grant cross-domain gMSA read rights. The attempt will proceed, "
                "but expect <no read permissions>."
            )

        return shell.exploit_gmsa_account(
            context.domain,
            context.exec_username,
            context.exec_password,
            context.target_sam_or_label,
            context.target_domain,
            prompt_for_user_privs_after=False,
            group_domain=from_domain,
        )

    if relation == "readlapspassword":
        # LAPS helper expects a host identifier (prefer FQDN).
        target_host = resolve_netexec_target_for_node_label(
            shell, context.domain, node_label=context.to_label
        )
        if not target_host:
            base = context.target_sam_or_label.rstrip("$")
            target_host = f"{base}.{context.target_domain}".lower()
            marked_target = mark_sensitive(target_host, "hostname")
            print_info_verbose(
                f"Resolved LAPS target via fallback (samAccountName -> FQDN): {marked_target}"
            )
        return shell.exploit_laps_password(
            context.domain,
            context.exec_username,
            context.exec_password,
            target_host,
            context.target_domain,
            prompt_for_user_privs_after=False,
        )

    if relation == "forcechangepassword":
        from adscan_internal.services.destructive_action_policy import (  # noqa: PLC0415
            classify_destructive,
            is_machine_account_name,
        )

        # SAFETY HARD-BLOCK (defense-in-depth; the un-bypassable guard lives in
        # ``run_exploit_force_change_password``). A ForceChangePassword against a
        # computer/machine account resets that host's password and disrupts it,
        # so ADscan refuses it in EVERY mode before any warning or prompt. A
        # ``$``-suffixed sAMAccountName OR a computer/machine ``target_kind``
        # triggers the block.
        effective_target_kind = (
            "computer"
            if is_machine_account_name(context.target_sam_or_label)
            or is_machine_account_name(context.to_label)
            else target_kind
        )
        destructive_verdict = classify_destructive(
            "forcechangepassword", effective_target_kind
        )
        if destructive_verdict.hard_blocked:
            print_warning(
                "ForceChangePassword not executed for safety: "
                f"{destructive_verdict.client_safe_reason}"
            )
            set_last_execution_outcome(
                shell,
                {
                    "key": "step_blocked_for_safety",
                    "relation": "forcechangepassword",
                    "blocked_kind": "dangerous_destructive",
                    "reason": destructive_verdict.client_safe_reason,
                },
            )
            return False

        marked_from = mark_sensitive(context.exec_username, "user")
        audit_context = (
            " This is particularly disruptive in audit mode." if _is_audit_mode(shell) else ""
        )
        print_system_change_warning(
            title="[bold yellow]Disruptive Operation: ForceChangePassword[/bold yellow]",
            summary=(
                f"Execution user: {marked_from}\nTarget user: {marked_to}"
                f"{audit_context}"
            ),
            planned_changes=[
                "Reset the target user's domain password immediately.",
                "Store the new credential in ADscan for follow-up path execution.",
            ],
            impact_notes=[
                "This invalidates the target user's current password immediately.",
                "Active sessions and services using this account will lose access.",
                "Password reset is irreversible: the original password cannot be recovered.",
            ],
            cleanup_notes=[
                "Coordinate with the client to reset the password to a known value after the engagement.",
            ],
            authorization_note=(
                "Only continue if you are explicitly authorized to reset this credential during the engagement."
            ),
        )
        # The consent gate lives in the ForceChangePassword choke point
        # (``run_exploit_force_change_password`` in ``exploits.py``), which every
        # entry point funnels through and which owns the mode-dependent default
        # (CTF auto-executes, audit auto-skips) plus the computer hard-block. The
        # panel above is the operator-facing context for that single gate; a
        # second consent prompt here would be a redundant gate with its own drift
        # risk (it once auto-skipped in CTF and cancelled a reset the choke point
        # was about to auto-approve), so the decision is deferred to the SSOT.
        # Ledger-ordering fix: do NOT register a cleanup obligation before the
        # reset runs. A pre-registered "password_changed" entry left a FALSE
        # operator-required obligation when the reset later failed (the operator
        # was told to reset a password that was never changed). Register only
        # AFTER the reset CONFIRMS success: a successful FCP leaves exactly one
        # operator-required entry; a failed FCP leaves the ledger clean.
        fcp_success = shell.exploit_force_change_password(
            context.domain,
            context.exec_username,
            context.exec_password,
            context.target_sam_or_label,
            context.target_domain,
            prompt_for_user_privs_after=False,
            target_kind=effective_target_kind,
        )
        if not fcp_success:
            print_warning(
                "ForceChangePassword did not complete; the target password was not "
                "changed. No cleanup obligation was recorded."
            )
            return False

        _acl_cleanup_register(
            shell,
            context,
            kind="password_changed",
            detail={"target_user": context.target_sam_or_label},
        )
        ledger = getattr(shell, "environment_change_ledger", None)
        if ledger is not None:
            _cid = None
            actions = getattr(shell, "acl_cleanup_actions", None)
            if actions:
                _cid = actions[-1].get("_ledger_change_id")
            if _cid:
                try:
                    ledger.mark_operator_required(
                        _cid,
                        manual_cleanup_instructions=(
                            f"Coordinate with the client to reset the password for "
                            f"'{context.target_sam_or_label}' to a known value.\n"
                            f"  Set-ADAccountPassword -Identity '{context.target_sam_or_label}'"
                            f" -NewPassword (ConvertTo-SecureString 'NewPass' -AsPlainText -Force)"
                        ),
                    )
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
                    print_exception(exception=exc)
        return True

    if relation == "addkeycredentiallink":
        # AddKeyCredentialLink authorizes exactly the msDS-KeyCredentialLink write
        # → Shadow Credentials is the ONLY valid primitive (RBCD / password-reset
        # would fail ACCESS_DENIED — this edge grants neither). Force shadow-creds
        # through the existing computer/user control path (which handles the LDAP
        # write, PKINIT hash recovery, cleanup + env-ledger registration).
        if target_kind == "computer":
            if context.target_enabled is False:
                print_warning(
                    f"Target {marked_to} is disabled — Shadow Credentials needs an "
                    "enabled computer to authenticate via PKINIT."
                )
                return False
            return shell.exploit_control_computer_object(
                context.domain,
                context.exec_username,
                context.exec_password,
                context.target_sam_or_label,
                context.target_domain,
                prompt_for_user_privs_after=False,
                forced_method="shadow",
            )
        if target_kind == "user":
            if context.target_enabled is False:
                print_warning(
                    f"Target {marked_to} is disabled — enable it before Shadow Credentials."
                )
                return False
            # User shadow-creds: add a KeyCredentialLink to the user, PKINIT as
            # them. ForceChangePassword is NOT offered (this edge does not grant it).
            return shell.exploit_generic_all_user(
                context.domain,
                context.exec_username,
                context.exec_password,
                context.target_sam_or_label,
                context.target_domain,
                prompt_for_password_fallback=False,
                prompt_for_user_privs_after=False,
                prompt_for_method_choice=True,
                allow_force_change_password=False,
            )
        print_warning(
            f"AddKeyCredentialLink exploitation requires a user or computer target "
            f"(got '{target_kind}')."
        )
        return False

    if relation in {"genericall", "genericwrite", "writeaccountrestrictions"}:
        if target_kind == "gpo" and relation in {"genericall", "genericwrite"}:
            # GenericAll/GenericWrite over a groupPolicyContainer routes to the
            # native Immediate Scheduled Task plant. The GPO is fixed by the
            # path, so this is a non-interactive, single-target counterpart of
            # the operator wizard: resolve that one GPO into a
            # WritableGPOCandidate and plant + auto-rollback via the shipped
            # exploitation service (recording the change + undo in the session
            # ledger like every other executed step). (container is a distinct,
            # unimplemented technique and is intentionally left unsupported.)
            return _dispatch_gpo_immediate_task(shell, context)
        if target_kind in {"user", "computer"}:
            if context.target_tombstoned and target_kind == "user":
                print_warning(f"Target {marked_to} is a deleted (tombstoned) object.")
                if Confirm.ask(
                    "Restore it from the AD Recycle Bin first?", default=True
                ):
                    # Pass the tombstone DN when known; otherwise the SID +
                    # sAMAccountName so the service resolves the real Deleted-Objects
                    # DN. NEVER fall back to the bare label as a search base — that is
                    # an invalid base the DC always rejects with noSuchObject.
                    if not shell.restore_deleted_object(
                        context.domain,
                        context.exec_username,
                        context.exec_password,
                        context.target_deleted_dn,
                        object_sid=context.target_sid,
                        sam_account_name=context.target_sam_or_label,
                        last_known_rdn=context.target_last_known_rdn,
                    ):
                        print_warning(
                            f"Could not restore {marked_to}. Skipping exploitation."
                        )
                        return False
                    # Reanimated. target_enabled was read from the tombstone's
                    # PRESERVED userAccountControl, so the enable-first check below
                    # still fires for a restored-but-disabled account.
                else:
                    print_warning(
                        f"Skipping exploitation for tombstoned target {marked_to}."
                    )
                    return False
            if context.target_enabled is False and target_kind == "user":
                print_warning(f"Target {marked_to} is disabled.")
                if Confirm.ask("Do you want to try to enable it first?", default=True):
                    if not shell.enable_user(
                        context.domain,
                        context.exec_username,
                        context.exec_password,
                        context.target_sam_or_label,
                    ):
                        print_warning(
                            f"Could not enable {marked_to}. Skipping exploitation."
                        )
                        return False
                else:
                    print_warning(
                        f"Skipping exploitation for disabled target {marked_to}."
                    )
                    return False
            if context.target_enabled is False and target_kind == "computer":
                print_warning(f"Target {marked_to} is disabled.")
                if Confirm.ask("Do you want to try to enable it first?", default=True):
                    if not shell.enable_computer(
                        context.domain,
                        context.exec_username,
                        context.exec_password,
                        context.target_sam_or_label,
                    ):
                        print_warning(
                            f"Could not enable {marked_to}. Skipping exploitation."
                        )
                        return False
                else:
                    print_warning(
                        f"Skipping exploitation for disabled target {marked_to}."
                    )
                    return False
            if target_kind == "computer":
                computer_helper = getattr(
                    shell, "exploit_control_computer_object", None
                )
                if callable(computer_helper):
                    if relation == "writeaccountrestrictions":
                        # WriteAccountRestrictions grants ONLY the
                        # User-Account-Restrictions property-set write, which covers
                        # msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD) but NOT
                        # msDS-KeyCredentialLink (Shadow Credentials). On an
                        # ADCS-present domain the helper auto-selects shadow-creds
                        # first and would hit ACCESS_DENIED, so pin the technique to
                        # RBCD (RBCD needs no PKINIT/enabled-computer guard the way
                        # shadow does).
                        return computer_helper(
                            context.domain,
                            context.exec_username,
                            context.exec_password,
                            context.target_sam_or_label,
                            context.target_domain,
                            prompt_for_user_privs_after=False,
                            forced_method="rbcd",
                        )
                    # GenericAll/GenericWrite grant BOTH primitives → keep the
                    # shadow-vs-RBCD method choice.
                    return computer_helper(
                        context.domain,
                        context.exec_username,
                        context.exec_password,
                        context.target_sam_or_label,
                        context.target_domain,
                        prompt_for_user_privs_after=False,
                        prompt_for_method_choice=True,
                    )
                if relation in {"genericall", "genericwrite"}:
                    # Backwards compatibility for older shell stubs while the
                    # dedicated computer-object helper rolls out.
                    return shell.exploit_generic_all_user(
                        context.domain,
                        context.exec_username,
                        context.exec_password,
                        context.target_sam_or_label,
                        context.target_domain,
                        prompt_for_password_fallback=False,
                        prompt_for_user_privs_after=False,
                        prompt_for_method_choice=True,
                        # ForceChangePassword needs GenericAll/Reset-Password — not GenericWrite.
                        allow_force_change_password=(relation == "genericall"),
                    )
                print_warning(
                    "Computer-object control exploitation helper is unavailable in this shell context."
                )
                return False

            ok = shell.exploit_generic_all_user(
                context.domain,
                context.exec_username,
                context.exec_password,
                context.target_sam_or_label,
                context.target_domain,
                prompt_for_password_fallback=False,
                prompt_for_user_privs_after=False,
                prompt_for_method_choice=True,
                # ForceChangePassword needs GenericAll/Reset-Password — not GenericWrite.
                allow_force_change_password=(relation == "genericall"),
            )
            if ok:
                _acl_cleanup_register(
                    shell,
                    context,
                    kind="shadow_credentials_added",
                    detail={"target_user": context.target_sam_or_label},
                )
            return ok

        if target_kind == "ou":
            return shell.exploit_generic_all_ou(
                context.domain,
                context.exec_username,
                context.exec_password,
                context.target_sam_or_label,
                context.target_domain,
                followup_after=False,
            )

        if target_kind == "domain":
            if relation != "genericall":
                # GenericWrite cannot modify the DACL - gated upstream in
                # describe_ace_relation_support, but kept defensive here.
                print_warning(
                    "GenericWrite on a Domain object does not grant DACL "
                    "modification; DCSync is not reachable through this edge."
                )
                return False
            return _execute_genericall_domain_dcsync(shell, context)

        if target_kind == "group":
            # RBCD coordination: a downstream AllowedToAct on this group needs an
            # owned SPN-bearing member (S4U requires an SPN). When the look-ahead
            # resolved one, default to it instead of the path-source executor — a
            # member without an SPN would fail the RBCD with KDC_ERR_BADOPTION.
            add_default = context.member_to_add or context.exec_username
            if context.member_to_add:
                print_info(
                    f"[dim]Add member:[/dim] the next step is resource-based "
                    f"constrained delegation (AllowedToAct) on {marked_to}, which "
                    f"needs an SPN-bearing member. ADscan selected the owned account "
                    f"{mark_sensitive(context.member_to_add, 'user')} — adding it so "
                    "the delegation ticket can be minted."
                )
            else:
                print_info(
                    f"[dim]Add member:[/dim] select a user to add to group {marked_to}."
                    " This modifies group membership in Active Directory."
                )
            changed_username = Prompt.ask(
                "Enter the user to add",
                default=add_default,
            )
            changed_username = _sanitize_prompt_account(changed_username)
            result = shell.exploit_add_member(
                context.domain,
                context.exec_username,
                context.exec_password,
                context.target_sam_or_label,
                changed_username,
                context.target_domain,
                enumerate_aces_after=False,
            )
            membership_outcome = _consume_group_membership_operation_outcome(shell)
            if result is True:
                _set_last_ace_execution_outcome(
                    shell,
                    {
                        "key": "group_membership_changed",
                        "domain": context.domain,
                        "target_domain": context.target_domain,
                        "target_group": context.target_sam_or_label,
                        "added_user": changed_username,
                        "exec_username": context.exec_username,
                        "exec_password": context.exec_password,
                        "cleanup_required": not bool(
                            membership_outcome.get("already_member")
                        ),
                        "membership_already_present": bool(
                            membership_outcome.get("already_member")
                        ),
                    },
                )
            return result

        print_warning(
            f"GenericAll/GenericWrite exploitation not supported for target type {context.target_kind}."
        )
        return False

    if relation == "addself":
        print_info(
            f"[dim]Add self:[/dim] adding {mark_sensitive(context.exec_username, 'user')}"
            f" to group {marked_to}."
            " This modifies group membership in Active Directory."
        )
        result = shell.exploit_add_member(
            context.domain,
            context.exec_username,
            context.exec_password,
            context.target_sam_or_label,
            context.exec_username,
            context.target_domain,
            enumerate_aces_after=False,
        )
        membership_outcome = _consume_group_membership_operation_outcome(shell)
        if result is True:
            _set_last_ace_execution_outcome(
                shell,
                {
                    "key": "group_membership_changed",
                    "domain": context.domain,
                    "target_domain": context.target_domain,
                    "target_group": context.target_sam_or_label,
                    "added_user": context.exec_username,
                    "exec_username": context.exec_username,
                    "exec_password": context.exec_password,
                    "cleanup_required": not bool(
                        membership_outcome.get("already_member")
                    ),
                    "membership_already_present": bool(
                        membership_outcome.get("already_member")
                    ),
                },
            )
        return result

    if relation == "addmember":
        # RBCD coordination (see the genericall/genericwrite group branch): a
        # downstream AllowedToAct on this group needs an SPN-bearing member.
        add_default = context.member_to_add or context.exec_username
        if context.member_to_add:
            print_info(
                f"[dim]Add member:[/dim] the next step is resource-based "
                f"constrained delegation (AllowedToAct) on {marked_to}, which needs "
                f"an SPN-bearing member. ADscan selected the owned account "
                f"{mark_sensitive(context.member_to_add, 'user')} — adding it so the "
                "delegation ticket can be minted."
            )
        else:
            print_info(
                f"[dim]Add member:[/dim] select a user to add to group {marked_to}."
                " This modifies group membership in Active Directory."
            )
        changed_username = Prompt.ask(
            "Enter the user to add",
            default=add_default,
        )
        changed_username = _sanitize_prompt_account(changed_username)
        result = shell.exploit_add_member(
            context.domain,
            context.exec_username,
            context.exec_password,
            context.target_sam_or_label,
            changed_username,
            context.target_domain,
            enumerate_aces_after=False,
        )
        membership_outcome = _consume_group_membership_operation_outcome(shell)
        if result is True:
            _set_last_ace_execution_outcome(
                shell,
                {
                    "key": "group_membership_changed",
                    "domain": context.domain,
                    "target_domain": context.target_domain,
                    "target_group": context.target_sam_or_label,
                    "added_user": changed_username,
                    "exec_username": context.exec_username,
                    "exec_password": context.exec_password,
                    "cleanup_required": not bool(
                        membership_outcome.get("already_member")
                    ),
                    "membership_already_present": bool(
                        membership_outcome.get("already_member")
                    ),
                },
            )
        return result

    if relation == "owns":
        # Phase 1: leverage ownership to write FullControl DACL entry (no owneredit needed).
        owns_ok = shell.exploit_owns(
            context.domain,
            context.exec_username,
            context.exec_password,
            context.target_sam_or_label,
            context.target_domain,
            target_kind,
        )
        if not owns_ok:
            return False

        # Phase 2: FullControl is now granted; chain to the same target-specific
        # actions as GenericAll.  Print a separator so the operator sees the two
        # phases clearly in the terminal output.
        print_info(
            "[green]Phase 2/2[/green] FullControl granted. "
            "Chaining to target-specific exploitation…"
        )

        if target_kind in {"user", "computer"}:
            if context.target_enabled is False and target_kind == "user":
                print_warning(f"Target {marked_to} is disabled.")
                if Confirm.ask("Do you want to try to enable it first?", default=True):
                    if not shell.enable_user(
                        context.domain,
                        context.exec_username,
                        context.exec_password,
                        context.target_sam_or_label,
                    ):
                        print_warning(f"Could not enable {marked_to}. Skipping.")
                        return False
                else:
                    return False
            if target_kind == "computer":
                computer_helper = getattr(
                    shell, "exploit_control_computer_object", None
                )
                if callable(computer_helper):
                    return computer_helper(
                        context.domain,
                        context.exec_username,
                        context.exec_password,
                        context.target_sam_or_label,
                        context.target_domain,
                        prompt_for_user_privs_after=False,
                        prompt_for_method_choice=True,
                    )
                return shell.exploit_generic_all_user(
                    context.domain,
                    context.exec_username,
                    context.exec_password,
                    context.target_sam_or_label,
                    context.target_domain,
                    prompt_for_password_fallback=False,
                    prompt_for_user_privs_after=False,
                    prompt_for_method_choice=True,
                )
            return shell.exploit_generic_all_user(
                context.domain,
                context.exec_username,
                context.exec_password,
                context.target_sam_or_label,
                context.target_domain,
                prompt_for_password_fallback=False,
                prompt_for_user_privs_after=False,
                prompt_for_method_choice=True,
            )

        if target_kind == "ou":
            return shell.exploit_generic_all_ou(
                context.domain,
                context.exec_username,
                context.exec_password,
                context.target_sam_or_label,
                context.target_domain,
                followup_after=False,
            )

        if target_kind == "group":
            # RBCD coordination: a downstream AllowedToAct on this group needs an
            # owned SPN-bearing member (S4U requires an SPN). When the look-ahead
            # resolved one, default to it instead of the path-source executor — a
            # member without an SPN would fail the RBCD with KDC_ERR_BADOPTION.
            add_default = context.member_to_add or context.exec_username
            if context.member_to_add:
                print_info(
                    f"[dim]Add member:[/dim] the next step is resource-based "
                    f"constrained delegation (AllowedToAct) on {marked_to}, which "
                    f"needs an SPN-bearing member. ADscan selected the owned account "
                    f"{mark_sensitive(context.member_to_add, 'user')} — adding it so "
                    "the delegation ticket can be minted."
                )
            else:
                print_info(
                    f"[dim]Add member:[/dim] select a user to add to group {marked_to}."
                    " This modifies group membership in Active Directory."
                )
            changed_username = Prompt.ask(
                "Enter the user to add",
                default=add_default,
            )
            changed_username = _sanitize_prompt_account(changed_username)
            result = shell.exploit_add_member(
                context.domain,
                context.exec_username,
                context.exec_password,
                context.target_sam_or_label,
                changed_username,
                context.target_domain,
                enumerate_aces_after=False,
            )
            membership_outcome = _consume_group_membership_operation_outcome(shell)
            if result is True:
                _set_last_ace_execution_outcome(
                    shell,
                    {
                        "key": "group_membership_changed",
                        "domain": context.domain,
                        "target_domain": context.target_domain,
                        "target_group": context.target_sam_or_label,
                        "added_user": changed_username,
                        "exec_username": context.exec_username,
                        "exec_password": context.exec_password,
                        "cleanup_required": not bool(
                            membership_outcome.get("already_member")
                        ),
                        "membership_already_present": bool(
                            membership_outcome.get("already_member")
                        ),
                    },
                )
            return result

        if target_kind == "domain":
            # After granting DCSync rights via dacledit, trigger DCSync.
            return shell.dcsync(
                context.domain,
                context.exec_username,
                context.exec_password,
                context.target_domain,
            )

        print_warning(
            f"Owns exploitation not supported for target type {context.target_kind}."
        )
        return False

    if relation == "writedacl":
        target_type = (
            target_kind if target_kind in {"user", "group", "domain"} else target_kind
        )
        ok = shell.exploit_write_dacl(
            context.domain,
            context.exec_username,
            context.exec_password,
            context.target_sam_or_label,
            context.target_domain,
            target_type,
            followup_after=False,
        )
        if ok:
            is_domain = target_type == "domain"
            exec_sid = getattr(shell, "_last_exec_sid", context.exec_username)
            _acl_cleanup_register(
                shell,
                context,
                kind="dacl_ace_added",
                detail={
                    "trustee": exec_sid or context.exec_username,
                    "rights_type": "dcsync" if is_domain else "genericAll",
                },
            )
        return ok

    if relation == "writeowner":
        if target_kind not in {"user", "group"}:
            print_warning(
                f"WriteOwner exploitation is only implemented for User/Group targets (got {context.target_kind})."
            )
            return False
        original_owner_sid = _capture_original_owner(shell, context)
        ok = shell.exploit_write_owner(
            context.domain,
            context.exec_username,
            context.exec_password,
            context.target_sam_or_label,
            context.target_domain,
            target_kind,
            followup_after=False,
        )
        if ok:
            _acl_cleanup_register(
                shell,
                context,
                kind="owner_changed",
                detail={"original_owner_sid": original_owner_sid},
            )
        return ok

    if relation == "writespn":
        if target_kind not in {"user", "computer"}:
            print_warning(
                f"WriteSPN exploitation is only implemented for User/Computer targets (got {context.target_kind})."
            )
            return False
        ok = shell.exploit_write_spn(
            context.domain,
            context.exec_username,
            context.exec_password,
            context.target_sam_or_label,
            context.target_domain,
        )
        if ok:
            from adscan_internal.cli.exploits import _build_targeted_kerberoast_spn  # noqa: PLC0415

            spn = _build_targeted_kerberoast_spn(context.target_sam_or_label)
            _acl_cleanup_register(
                shell,
                context,
                kind="spn_added",
                detail={"spn": spn},
            )
        return ok

    # Defensive: should not happen due to ACL_ACE_RELATIONS guard.
    try:
        telemetry.capture_exception(
            RuntimeError(f"Unhandled ACE relation: {context.relation}")
        )
    except Exception:
        pass
    return None
