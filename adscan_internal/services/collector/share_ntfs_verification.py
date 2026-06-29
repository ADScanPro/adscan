"""NTFS-aware effective-access verification for SMB share-access edges.

The share collector reads SHARE-level ACLs (and, on a fallback, the NTFS
folder-root SD). A share-level grant is necessary but NOT sufficient for real
access: the effective access of a principal is the *intersection* of the
share permissions and the NTFS folder permissions. A share ACL that grants
``Change`` on a folder whose NTFS DACL denies write yields read-only effective
access — emitting a ``WriteShare`` edge from the share ACL alone is a false
positive.

This module isolates the pure-logic decisions so they are unit-testable
without touching the live SMB/winacl path:

* :func:`decide_verification_tier` — given which SDs were readable and whether
  per-principal evaluation was possible, return the verification tier.
* :func:`build_sid_group_closure` — conservative transitive expansion of a
  principal's group SIDs from the collector's ``MemberOf`` edges. Group
  expansion is the bug-prone part: when the closure cannot be computed
  confidently the caller must NOT upgrade the tier to ``ntfs_computed``.
* :func:`effective_mask_has_read` / :func:`effective_mask_has_write` —
  classify an effective file-access mask.
* :func:`hunt_gate_decision` — the share-hunting READ-gate decision: should a
  share be offered for credential hunting, and should it be deprioritized as
  NTFS-unverified.

The actual winacl ``EvaluateSidAgainstDescriptor`` intersection lives in
:func:`compute_effective_file_mask`, which is a thin wrapper over the offline
evaluator already vendored at
``vendor/aiosmb/aiosmb/commons/utils/faccess.py``. It is import-guarded so the
pure-logic helpers above remain importable in environments without winacl.
"""

from __future__ import annotations

from typing import Iterable, Mapping, Optional

# ---------------------------------------------------------------------------
# Verification tiers (metadata tag on the share-access edge — never an edge
# kind, never collapsed into severity).
# ---------------------------------------------------------------------------

#: Effective access computed by intersecting share SD ∩ NTFS folder-root SD
#: per principal. High value but APPROXIMATE (group expansion).
VERIFICATION_NTFS_COMPUTED = "ntfs_computed"

#: Only the share-level ACL was available (NTFS SD unreadable or per-principal
#: evaluation not possible). The edge is still a real lead but NTFS-unverified.
VERIFICATION_SHARE_ACL_ONLY = "share_acl_only"

#: Effective access observed against the operator's OWN live token via
#: MaximalAccess (Phase-1 ``query_effective_root_access``). Not produced by the
#: collector — present only when trivially available from a live merge.
VERIFICATION_SELF_MXAC = "self_mxac"

#: Default tag for back-compat when nothing else applies.
DEFAULT_VERIFICATION = VERIFICATION_SHARE_ACL_ONLY

#: SIDs every authenticated domain principal provably belongs to. For share
#: edges sourced from one of these, the scanning identity's MxAc self-effective
#: access is a valid effective floor — so we (a) trigger the MxAc probe when a
#: share grants one of them, and (b) tag the resulting edge ``self_mxac`` with
#: the server-confirmed mask instead of the over-reported raw share grant. These
#: principals never have a confident group-closure (they are OS-computed, not in
#: the membership snapshot), so their edges otherwise stay share_acl_only forever.
_BROAD_AUTH_SIDS = frozenset({"S-1-5-11", "S-1-1-0", "S-1-5-32-545"})


def is_broad_auth_sid(sid: str) -> bool:
    """True for Authenticated Users / Everyone / Users / Domain Users (RID 513)."""
    s = (sid or "").strip().upper()
    return s in _BROAD_AUTH_SIDS or s.endswith("-513")

# File-access mask bits (winacl FILE_ACCESS_MASK / generic mapping). Mirrors
# the constants in share_collector.py; duplicated here to keep this module
# import-light (no winacl import required for the pure-logic helpers).
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_GENERIC_EXECUTE = 0x20000000
_GENERIC_ALL = 0x10000000
_FILE_READ_DATA = 0x00000001
_FILE_WRITE_DATA = 0x00000002
_FILE_APPEND_DATA = 0x00000004
_FILE_ALL_ACCESS = 0x001F01FF

_READ_BITS = _GENERIC_READ | _FILE_READ_DATA
_WRITE_BITS = _GENERIC_WRITE | _FILE_WRITE_DATA | _FILE_APPEND_DATA


def decide_verification_tier(
    *,
    share_sd_readable: bool,
    ntfs_sd_readable: bool,
    per_principal_eval_possible: bool,
) -> str:
    """Return the verification tier for a share-access edge.

    The tier is purely a function of *what evidence we have*, decided BEFORE
    any winacl evaluation runs:

    * ``ntfs_computed`` — requires BOTH the share SD and the NTFS folder-root
      SD readable, AND that per-principal evaluation was possible (the
      principal's group closure could be expanded confidently).
    * ``share_acl_only`` — every other case where a share-level ACL exists.

    Args:
        share_sd_readable: The share-level security descriptor was parsed.
        ntfs_sd_readable: The NTFS folder-root security descriptor was parsed.
        per_principal_eval_possible: The principal's SID group closure could be
            expanded confidently (see :func:`build_sid_group_closure`).

    Returns:
        One of :data:`VERIFICATION_NTFS_COMPUTED` or
        :data:`VERIFICATION_SHARE_ACL_ONLY`.
    """
    if share_sd_readable and ntfs_sd_readable and per_principal_eval_possible:
        return VERIFICATION_NTFS_COMPUTED
    return VERIFICATION_SHARE_ACL_ONLY


def build_sid_group_closure(
    member_of_edges: Iterable[tuple[str, str]],
    *,
    max_depth: int = 16,
) -> dict[str, frozenset[str]]:
    """Build per-SID transitive group membership closures from MemberOf edges.

    Each edge is ``(member_sid, group_sid)`` meaning *member is a member of
    group*. The closure of a SID is the set of all group SIDs it transitively
    belongs to (NOT including the SID itself).

    Conservative by construction:

    * Cycle-safe — a visited set prevents infinite loops on circular
      memberships (rare but possible across forests).
    * Depth-capped — pathological chains beyond ``max_depth`` stop expanding;
      such a SID is still returned but its closure may be partial. Callers use
      :func:`is_closure_confident` to decide whether to trust it.

    Args:
        member_of_edges: Iterable of ``(member_sid, group_sid)`` upper-cased
            SID pairs. Non-string / empty entries are skipped.
        max_depth: Maximum transitive expansion depth (defense against
            pathological membership graphs at enterprise scale).

    Returns:
        Mapping of ``member_sid -> frozenset(group_sids)``. SIDs that appear
        only as a group (never as a member) are absent.
    """
    direct: dict[str, set[str]] = {}
    for edge in member_of_edges:
        try:
            member, group = edge
        except (TypeError, ValueError):
            continue
        m = str(member or "").strip().upper()
        g = str(group or "").strip().upper()
        if not m or not g or m == g:
            continue
        direct.setdefault(m, set()).add(g)

    closure: dict[str, frozenset[str]] = {}
    for sid in direct:
        seen: set[str] = set()
        stack: list[tuple[str, int]] = [(sid, 0)]
        while stack:
            current, depth = stack.pop()
            if depth >= max_depth:
                continue
            for grp in direct.get(current, ()):  # pylint: disable=consider-using-dict-items
                if grp in seen:
                    continue
                seen.add(grp)
                stack.append((grp, depth + 1))
        # Exclude the seed SID from its own closure even when a membership
        # cycle (A -> B -> A) would otherwise reintroduce it. The principal's
        # own SID is matched separately by the winacl evaluator.
        seen.discard(sid)
        closure[sid] = frozenset(seen)
    return closure


def is_closure_confident(
    sid: str,
    closure: Mapping[str, frozenset[str]],
    *,
    principal_kind: str | None = None,
) -> bool:
    """Return True when the principal's group closure can be trusted for NTFS eval.

    Conservative rule — be cautious and refuse to upgrade the tier when
    uncertain:

    * A principal that appears in ``closure`` (it has at least one resolved
      MemberOf edge) is confident — the membership data covers it.
    * A principal absent from ``closure`` is only confident when it is a kind
      that legitimately has no group memberships in our collected data and we
      can evaluate it against just its own SID plus the well-known
      ``Everyone`` / ``Authenticated Users`` groups injected by the evaluator.
      We treat Users and Computers as evaluable-with-empty-closure (their own
      SID still matches direct ACEs); Groups absent from the closure are
      treated as NOT confident because a group with no resolved parent edges
      may simply be missing membership data.

    Args:
        sid: The principal SID (upper-cased).
        closure: Output of :func:`build_sid_group_closure`.
        principal_kind: ``"User"`` / ``"Group"`` / ``"Computer"`` when known.

    Returns:
        True when per-principal NTFS evaluation may upgrade the tier.
    """
    sid_u = str(sid or "").strip().upper()
    if not sid_u:
        return False
    if sid_u in closure:
        return True
    kind = str(principal_kind or "").strip().lower()
    # Groups with no resolved parent edges: membership data may be missing —
    # refuse to upgrade rather than risk a wrong effective mask.
    if kind == "group":
        return False
    # Users / Computers (or unknown) can be evaluated against their own SID
    # plus the well-known groups the evaluator always injects.
    return True


def effective_mask_has_read(mask: int) -> bool:
    """Return True when an effective file-access mask grants read."""
    m = int(mask or 0)
    if m & _GENERIC_ALL or (m & _FILE_ALL_ACCESS) == _FILE_ALL_ACCESS:
        return True
    return bool(m & _READ_BITS)


def effective_mask_has_write(mask: int) -> bool:
    """Return True when an effective file-access mask grants write."""
    m = int(mask or 0)
    if m & _GENERIC_ALL or (m & _FILE_ALL_ACCESS) == _FILE_ALL_ACCESS:
        return True
    return bool(m & _WRITE_BITS)


def effective_mask_relations(mask: int) -> list[str]:
    """Map an effective file-access mask to ADscan share edge relation names.

    Identical semantics to ``share_collector.mask_to_edge_kinds`` but applied
    to the EFFECTIVE (share ∩ NTFS) mask rather than the raw share-ACL mask.
    """
    m = int(mask or 0)
    if m & _GENERIC_ALL or (m & _FILE_ALL_ACCESS) == _FILE_ALL_ACCESS:
        return ["FullControlShare"]
    kinds: list[str] = []
    if effective_mask_has_read(m):
        kinds.append("ReadShare")
    if effective_mask_has_write(m) or (m & _GENERIC_EXECUTE):
        kinds.append("WriteShare")
    return kinds


def mask_to_access_label(mask: int | None) -> str | None:
    """Map a file-access mask to a single human access label.

    Returns ``"Full Control"`` / ``"Read+Write"`` / ``"Write"`` / ``"Read"``,
    or ``None`` when the mask grants none of these (or is ``None``). Used to
    render the share-level and NTFS-level components of the access breakdown
    (share / NTFS / effective) on the share-exposure surfaces, so the headline
    effective access can be shown next to the two values it was derived from.

    Semantics match :func:`effective_mask_relations` exactly so a label and the
    relation it corresponds to never disagree.
    """
    if mask is None:
        return None
    relations = effective_mask_relations(int(mask))
    if "FullControlShare" in relations:
        return "Full Control"
    has_read = "ReadShare" in relations
    has_write = "WriteShare" in relations
    if has_read and has_write:
        return "Read+Write"
    if has_write:
        return "Write"
    if has_read:
        return "Read"
    return None


def hunt_gate_decision(
    *,
    verification: str,
    has_effective_read: bool,
) -> tuple[bool, bool]:
    """Decide whether a share should be offered for credential hunting.

    Hunting needs effective READ. The gate:

    * No effective read at all → not offered (``allowed=False``).
    * Effective read AND ``ntfs_computed`` → offered, not deprioritized.
    * Effective read but only ``share_acl_only`` (or ``self_mxac`` is fully
      trusted) → offered but deprioritized/flagged as NTFS-unverified so the
      operator knows the read is share-ACL-only, not NTFS-confirmed.

    Args:
        verification: One of the ``VERIFICATION_*`` tiers.
        has_effective_read: Whether the share's effective access includes read.

    Returns:
        ``(allowed, deprioritized)``. ``allowed`` gates whether the share is
        offered at all; ``deprioritized`` flags NTFS-unverified leads.
    """
    if not has_effective_read:
        return (False, False)
    tier = str(verification or DEFAULT_VERIFICATION)
    if tier in (VERIFICATION_NTFS_COMPUTED, VERIFICATION_SELF_MXAC):
        return (True, False)
    return (True, True)


def compute_effective_file_masks(
    share_sd_bytes: Optional[bytes],
    ntfs_sd_bytes: Optional[bytes],
    *,
    principal_sid: str,
    group_sids: Iterable[str],
) -> Optional[tuple[int, int, int]]:
    """Intersect share SD ∩ NTFS folder-root SD for one principal via winacl.

    Like :func:`compute_effective_file_mask` but returns the THREE component
    masks the breakdown is built from: ``(share_mask, ntfs_mask,
    effective_mask)`` where ``effective_mask = share_mask & ntfs_mask``.
    Returns ``None`` when either SD is missing/unparseable (the caller then
    keeps the ``share_acl_only`` tier).

    Surfacing the two operands — not just their AND — lets the share-exposure
    view render "Share: Full Control / NTFS: Read / Effective: Read" so the
    headline effective access is shown next to the values it was derived from,
    making an NTFS-restricted share grant legible rather than a bare number.

    This is the only place that imports winacl; it reuses the offline evaluator
    wrapped at ``vendor/aiosmb/.../utils/faccess.py`` so the intersection
    semantics match the live ``smbclient`` path exactly.
    """
    if not share_sd_bytes or not ntfs_sd_bytes:
        return None
    try:
        from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
        from aiosmb.commons.utils.faccess import faccess_basic_check
    except Exception:
        return None

    try:
        share_sd = SECURITY_DESCRIPTOR.from_bytes(share_sd_bytes)
        ntfs_sd = SECURITY_DESCRIPTOR.from_bytes(ntfs_sd_bytes)
    except Exception:
        return None

    sid_u = str(principal_sid or "").strip().upper()
    if not sid_u:
        return None
    groups = [str(g).strip().upper() for g in group_sids if str(g).strip()]

    try:
        # faccess_basic_check mutates the groups list it receives, so pass a
        # fresh copy for each evaluation.
        share_mask = int(faccess_basic_check(share_sd, sid_u, list(groups)))
        ntfs_mask = int(faccess_basic_check(ntfs_sd, sid_u, list(groups)))
    except Exception:
        return None

    return share_mask, ntfs_mask, share_mask & ntfs_mask


def compute_effective_file_mask(
    share_sd_bytes: Optional[bytes],
    ntfs_sd_bytes: Optional[bytes],
    *,
    principal_sid: str,
    group_sids: Iterable[str],
) -> Optional[int]:
    """Intersect share SD ∩ NTFS folder-root SD for one principal via winacl.

    Returns the effective file-access mask, or ``None`` when either SD is
    missing/unparseable (the caller then keeps the ``share_acl_only`` tier).

    Thin wrapper over :func:`compute_effective_file_masks` keeping the
    single-value contract for callers that only need the AND.
    """
    masks = compute_effective_file_masks(
        share_sd_bytes,
        ntfs_sd_bytes,
        principal_sid=principal_sid,
        group_sids=group_sids,
    )
    if masks is None:
        return None
    return masks[2]


__all__ = [
    "VERIFICATION_NTFS_COMPUTED",
    "VERIFICATION_SHARE_ACL_ONLY",
    "VERIFICATION_SELF_MXAC",
    "DEFAULT_VERIFICATION",
    "decide_verification_tier",
    "build_sid_group_closure",
    "is_closure_confident",
    "effective_mask_has_read",
    "effective_mask_has_write",
    "effective_mask_relations",
    "mask_to_access_label",
    "hunt_gate_decision",
    "compute_effective_file_mask",
    "compute_effective_file_masks",
]
