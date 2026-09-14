"""Helpers to build share-origin credential provenance artifacts.

Centralizes creation of:
- ``source_context`` payloads used by spraying flows.
- ``CredentialSourceStep`` lists used by ``add_credential`` attack-graph recording.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import PurePosixPath
from typing import Any

from adscan_core.reporting.unauthenticated_reach import (
    REACHED_VIA_GUEST_SESSION,
    REACHED_VIA_NULL_SESSION,
)
from adscan_core.rich_output import print_exception
from adscan_internal.services.base_service import BaseService
from adscan_internal.services.smb_guest_auth_service import (
    is_credential_less_reader_identity,
)

# The only two honest bind kinds a pre-credential read can carry. A read-set is
# proven over exactly one of them; anything else normalizes to the conservative
# null-session default (today's long-standing behavior).
_KNOWN_REACHED_VIA: frozenset[str] = frozenset({REACHED_VIA_NULL_SESSION, REACHED_VIA_GUEST_SESSION})


# ---------------------------------------------------------------------------
# Ambient "this share read is credential-less" scope
# ---------------------------------------------------------------------------
#
# The share-spidering/CredSweeper credential producers (``cli/creds.py``'s
# ``process_cpassword_text`` / ``_store_recovered_securestring_credential``,
# ``cli/smb.py``'s ``_handle_prioritized_findings_actions``) sit ~6-9 stack
# frames below the ONE place that knows whether the CURRENT share enumeration
# is running over a genuinely credential-less bind: ``run_null_shares`` /
# ``run_guest_shares`` in ``cli/smb.py``. The intervening frames
# (``_run_post_mapping_sensitive_data_workflow``, the deterministic
# rclone/cifs/manspider backend selector, the staged phase runner, ...) are
# ALSO reused by a genuinely AUTHENTICATED caller
# (``run_smb_share_credential_hunt``, driven from the attack-paths context
# with a real domain credential) — so a positional parameter threaded through
# every one of those frames would still need an explicit "no" default at each
# authenticated call site, for zero behavioural gain over an ambient scope.
#
# This mirrors the established pattern in ``attack_graph_service.py``
# (``suppress_dev_engine_picker`` / ``preselect_dev_engine_for_display``):
# "Scope it ... rather than threading an override through every nested call
# site." Re-entrant and asyncio-safe (``ContextVar``-backed) — safe across the
# ``asyncio.run(...)`` boundary the native share walk uses internally.
_ACTIVE_CREDENTIAL_LESS_SHARE_BIND: ContextVar[str | None] = ContextVar(
    "_active_credential_less_share_bind", default=None
)


@contextmanager
def credential_less_share_read_scope(reached_via: str) -> Iterator[None]:
    """Mark every share-secret producer that runs inside this scope as PROVEN
    over a credential-less (guest/null) SMB bind.

    ``run_null_shares`` / ``run_guest_shares`` (``cli/smb.py``) wrap their
    entire post-enumeration credential-hunt call in this scope with the exact
    bind kind (``REACHED_VIA_NULL_SESSION`` / ``REACHED_VIA_GUEST_SESSION``)
    they used to reach the shares. Any credential producer downstream —
    regardless of stack depth — reads it back via
    :func:`current_credential_less_share_bind` and, when set, MUST source its
    edge from the token-filtered measured read-set (never the scanner's own
    bind username) and stamp ``reached_via`` + ``unauthenticated_reachable``.

    Args:
        reached_via: ``REACHED_VIA_NULL_SESSION`` or ``REACHED_VIA_GUEST_SESSION``.
    """
    token = _ACTIVE_CREDENTIAL_LESS_SHARE_BIND.set(reached_via)
    try:
        yield
    finally:
        _ACTIVE_CREDENTIAL_LESS_SHARE_BIND.reset(token)


def current_credential_less_share_bind() -> str | None:
    """Return the active credential-less bind kind, or ``None`` outside the scope.

    ``None`` means "not currently inside a proven credential-less share read"
    — the authenticated default. Never guess; only
    :func:`credential_less_share_read_scope` sets this.
    """
    return _ACTIVE_CREDENTIAL_LESS_SHARE_BIND.get()


def resolve_ambient_share_read_provenance(
    provenance_origin: str,
    *,
    reader_username: str | None,
    shell: object | None = None,
    domain: str | None = None,
) -> tuple[str, str | None, str | None]:
    """Fold the ambient credential-less scope into one provenance decision.

    Every share-secret credential producer (CredSweeper/rclone share hunt,
    AI-triage findings) calls this immediately before
    :meth:`ShareCredentialProvenanceService.build_credential_source_steps` so
    a proven guest/null-session share read is NEVER attributed to the
    caller's own default ``provenance_origin`` (``"share_spidering"``, which
    ``build_credential_source_steps`` treats as an ordinary AUTHENTICATED
    read and therefore never token-filters or stamps
    ``unauthenticated_reachable``).

    Args:
        provenance_origin: The caller's own default origin
            (e.g. ``"share_spidering"``), returned unchanged when the scope
            does not apply to this read.
        reader_username: The identity that ACTUALLY read the file this
            credential came from for THIS producer call — the scan's own
            ``auth_username`` in scope at the call site. REQUIRED (no
            default) so no caller can silently fall back to the broad
            ambient-only behavior. ``credential_less_share_read_scope`` wraps
            an entire downstream credential-hunt chain — a guest session's
            recovered credential can be validated and the newly-owned
            AUTHENTICATED user can read further shares synchronously inside
            the same ``with`` block. Without this discriminator every
            credential recovered anywhere inside that chain would be
            mis-attributed to the guest/null bind, even one a real
            authenticated identity read. See
            :func:`adscan_internal.services.smb_guest_auth_service.is_credential_less_reader_identity`.
        shell: Session shell, forwarded to the guest-username resolver (for a
            per-domain/shell override of the guest transport username).
        domain: Domain, forwarded to the guest-username resolver.

    Returns ``(effective_origin, reached_via, perspective)``:

    * Outside :func:`credential_less_share_read_scope`, OR inside it but
      ``reader_username`` names a real authenticated identity (not the
      credential-less reader) — the caller's own ``provenance_origin``
      unchanged, ``reached_via=None``, ``perspective=None``. Byte-identical
      to today's authenticated path.
    * Inside the scope AND ``reader_username`` names the credential-less
      reader — ``effective_origin="unauth_enrichment"`` (so
      ``build_credential_source_steps`` applies the read-set token filter and
      stamps ``unauthenticated_reachable``), the exact proven bind as
      ``reached_via``, and the matching ``perspective``
      (``"guest"``/``"anonymous"``) so the no-read-set fallback resolves to
      the honest well-known node (GUESTS / ANONYMOUS LOGON) instead of the
      scanner's OWN transport identity (the guest session's default username,
      ``ADscan`` — see :data:`adscan_internal.services.smb_guest_auth_service.DEFAULT_SMB_GUEST_USERNAME`).
    """
    bind = current_credential_less_share_bind()
    if not bind:
        return provenance_origin, None, None

    if not is_credential_less_reader_identity(reader_username, shell=shell, domain=domain):
        # An authenticated identity read this file INSIDE the ambient scope
        # (e.g. a re-entrant credential-hunt chain reading further shares as
        # a newly-owned user). The scope's guest/null attribution belongs to
        # the credential-less reads it was opened for, never to this one.
        return provenance_origin, None, None

    perspective = "guest" if bind == REACHED_VIA_GUEST_SESSION else "anonymous"
    return _UNAUTHENTICATED_REACHABLE_ORIGIN, bind, perspective


def _normalize_reached_via(reached_via: str | None) -> str:
    """Return a known ``reached_via`` token, defaulting to ``null_session``.

    The bind kind that performed the pre-credential read — ``null_session`` or
    ``guest_session``. An empty/unknown value falls back to ``null_session``, so a
    caller that does not know the bind (or a legacy edge) keeps today's behavior.
    """
    token = str(reached_via or "").strip().lower()
    return token if token in _KNOWN_REACHED_VIA else REACHED_VIA_NULL_SESSION


#: Everyone / World — kept as a case-insensitive literal here (rather than
#: importing ``adscan_core.reporting.well_known_principals``) to keep this
#: module's SID-shape checks self-contained; mirrors that module's own
#: ``_EVERYONE_SID`` constant.
_EVERYONE_SID = "S-1-1-0"


def _filter_primary_readset_for_credential_less_token(
    sources: list[dict[str, str]], reached_via: str
) -> list[dict[str, str]]:
    """Filter the PRIMARY read-set tier down to what a credential-less token can use.

    A ``self_mxac``-verified entry is DIRECT, LIVE proof from ADscan's own
    MaximalAccess probe over its own connection — not an ACL-membership
    INFERENCE (the thing the ordinary token filter guards against) — so it is
    exempt from :func:`~adscan_internal.services.collector.share_ntfs_verification.filter_readset_to_token`,
    EXCEPT for the one case that would otherwise leak a false credential-less
    claim: an entry whose own SID structurally requires a REAL authenticated
    logon (Authenticated Users / BUILTIN\\Users / Domain Users — anything the
    ordinary filter would drop). A credential-less token can never present
    those, self_mxac or not, so they are filtered even from the self_mxac
    tier. Everyone (S-1-1-0) stays exempt at self_mxac tier regardless of
    ``reached_via`` — a live, self-observed effective read is proof enough
    that the credential-less bind reaches this share, independent of the
    "Everyone includes anonymous" DC policy the ordinary (inferred) filter is
    conservative about for a plain null session.

    ``sources`` (the PRIMARY tier from :meth:`ShareCredentialProvenanceService.resolve_share_read_set_tiers`
    / :meth:`resolve_share_read_capable_sources`) is tier-homogeneous by
    construction — when the top tier is ``self_mxac`` every entry in it is —
    so a single check on the first entry decides the whole set.
    """
    if not sources:
        return sources
    from adscan_internal.services.collector.share_ntfs_verification import (
        filter_readset_to_token,
    )

    if sources[0].get("verification") != _SELF_MXAC:
        return filter_readset_to_token(sources, reached_via)

    token_usable_sids = {
        str(entry.get("sid") or "").strip().upper()
        for entry in filter_readset_to_token(sources, reached_via)
    }
    return [
        src
        for src in sources
        if str(src.get("sid") or "").strip().upper() in ({_EVERYONE_SID} | token_usable_sids)
    ]

# The collector stamps share-ACL read edges with ``method = "share_acl:<Share>"``
# and records the read-capability proof in ``notes.verification``. The collector
# emits THREE confidence levels (share_ntfs_verification.py), which the resolver
# ranks by proof specificity into a strict precedence:
#   1. ``self_mxac``      — observed live against the operator's OWN token (a
#                            verified floor for a broad SID; max certainty).
#   2. ``ntfs_computed``  — effective access computed by intersecting the share
#                            SD with the NTFS folder-root SD for the exact
#                            principal (verified-computed, high value).
#   3. ``share_acl_only`` — only the share-level ACL was readable; NTFS
#                            unverified (a real lead, lowest confidence).
# The PRIMARY credential-edge source is the highest tier present for the share;
# the lower-tier read-capable principals are kept (never discarded — a lost lead
# is lost value) and ride along in the edge notes.
_SELF_MXAC = "self_mxac"
_NTFS_COMPUTED = "ntfs_computed"
_SHARE_ACL_ONLY = "share_acl_only"

# Strict precedence, most-certain first. The first bucket that has any entry is
# the PRIMARY read-set; the rest are the "other read-capable principals".
_VERIFICATION_PRECEDENCE: tuple[str, ...] = (_SELF_MXAC, _NTFS_COMPUTED, _SHARE_ACL_ONLY)

# Relation names the share collector uses for share-ACL edges that grant READ.
# FullControl/Change/Write relations also grant read, so they count as read-capable
# sources for provenance purposes.
_READ_CAPABLE_RELATIONS = frozenset(
    {
        "readshare",
        "changeshare",
        "writeshare",
        "fullcontrolshare",
    }
)


class ShareCredentialProvenanceService(BaseService):
    """Build standardized provenance metadata for share-derived credentials."""

    def resolve_share_read_capable_sources(
        self,
        *,
        artifact: str | None = None,
        host: str | None = None,  # noqa: ARG002  (reserved; share name is the join key today)
        share: str | None = None,
        domain: str | None = None,
        shell: object | None = None,
        relationships_path: str | None = None,
        smb_shares_path: str | None = None,
    ) -> list[dict[str, str]]:
        """Resolve the measured read-capable principals for a share, keyed by SID.

        Reads the share collector's ``inventory/relationships.json`` and returns
        one entry per principal the collector measured as able to READ the share
        the leaked ``artifact`` came from — the real credential-edge source, not a
        synthetic ``Domain Users`` placeholder.

        Args:
            artifact: The leaked file's UNC path (``\\\\host\\<share>\\...``); the
                ``<share>`` segment is the join key when ``share`` is not given.
            host: Reserved; the join is on the share name today, not the host.
            share: Explicit share name (wins over parsing it from ``artifact``).
            domain: Domain whose inventory to read (for the production path derive).
            shell: Session shell exposing ``current_workspace_dir`` / ``domains_dir``
                — the production source of the inventory path. May be ``None``.
            relationships_path: Direct path to ``relationships.json`` — injected by
                unit tests so the resolver runs without a shell. Wins over the
                shell-derived path.
            smb_shares_path: Direct path to ``smb/shares.json`` — injected by unit
                tests. Wins over the shell-derived path. See
                :meth:`resolve_share_read_set_tiers`.

        Returns:
            A list of ``{"sid", "label", "verification", "method"}`` dicts, one per
            read-capable principal of the HIGHEST verification tier present for the
            share (3-tier precedence: self_mxac > ntfs_computed > share_acl_only),
            deduped by SID. Empty when no read-set is available (caller uses the
            fallback ladder). Never returns a record without a SID. The lower-tier
            principals are retrievable via :meth:`resolve_share_read_set_tiers`.
        """
        primary, _others = self.resolve_share_read_set_tiers(
            artifact=artifact,
            host=host,
            share=share,
            domain=domain,
            shell=shell,
            relationships_path=relationships_path,
            smb_shares_path=smb_shares_path,
        )
        return primary

    def resolve_share_read_set_tiers(
        self,
        *,
        artifact: str | None = None,
        host: str | None = None,  # noqa: ARG002  (reserved; share name is the join key today)
        share: str | None = None,
        domain: str | None = None,
        shell: object | None = None,
        relationships_path: str | None = None,
        smb_shares_path: str | None = None,
    ) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
        """Resolve the read-capable principals for a share, split PRIMARY vs OTHER.

        Same input contract as :meth:`resolve_share_read_capable_sources`, but
        returns BOTH the highest-tier ("primary") read-set AND the remaining
        lower-tier read-capable principals ("others"), so a caller can source the
        credential edge from the primary while keeping the other leads in notes.

        The collector emits three verification levels; this applies the strict
        3-tier precedence self_mxac > ntfs_computed > share_acl_only. The PRIMARY
        set is every principal in the highest tier that has any entry; OTHER is
        every remaining read-capable principal (in the two lower tiers), each
        tagged with its real ``verification``. A SID present in more than one tier
        is attributed to its highest tier only.

        Two sources feed the SAME tier-precedence buckets:

        * ``inventory/relationships.json`` — the AUTHENTICATED collector's
          share-ACL edges (unchanged, existing behaviour).
        * ``smb/shares.json`` — the light, credential-less live probe
          (``smb_shares_native._resolve_measured_read_set``), consulted for
          any SID this share's relationships.json entry does not already
          cover at as-good-or-better a tier. This is what lets a pure
          unauthenticated guest/null-session sweep (no prior authenticated
          collection, so ``relationships.json`` may not even exist) still
          resolve to the REAL, measured ``ntfs_computed`` reader set instead
          of falling through to the honest-but-unverified fallback ladder.

        Returns:
            ``(primary, others)`` — two lists of
            ``{"sid", "label", "verification", "method"}`` dicts. ``([], [])`` when
            no read-set is available from EITHER source. Never returns a record
            without a SID.
        """
        share_name = str(share or "").strip() or self._share_from_artifact(artifact)
        if not share_name:
            return [], []

        records = self._load_relationship_records(
            domain=domain, shell=shell, relationships_path=relationships_path
        )
        smb_shares_entries = self._load_smb_shares_read_set(
            domain=domain,
            shell=shell,
            smb_shares_path=smb_shares_path,
            share_name=share_name,
        )
        if not records and not smb_shares_entries:
            return [], []

        share_key = share_name.lower()
        # One bucket per verification tier, keyed by canonical order.
        buckets: dict[str, dict[str, dict[str, str]]] = {tier: {} for tier in _VERIFICATION_PRECEDENCE}
        seen_sids: set[str] = set()
        for record in records:
            if not isinstance(record, dict):
                continue
            relation = str(record.get("relation") or "").strip().lower()
            if relation not in _READ_CAPABLE_RELATIONS:
                continue
            notes = record.get("notes") if isinstance(record.get("notes"), dict) else {}
            if str(notes.get("share_name") or "").strip().lower() != share_key:
                continue
            sid = str(record.get("source_object_id") or "").strip()
            if not sid:
                # Exposure-Validation: never fabricate a principal without a SID.
                continue
            verification = str(notes.get("verification") or "").strip().lower()
            if verification not in buckets:
                # An unknown / missing verification is the lowest-confidence lead.
                verification = _SHARE_ACL_ONLY
            entry = {
                "sid": sid,
                "label": str(record.get("source_name") or "").strip(),
                "verification": verification,
                "method": str(record.get("method") or "").strip(),
            }
            buckets[verification].setdefault(sid, entry)

        # Merge the light-probe measured read-set into the SAME buckets, so a
        # relationships.json share_acl_only entry never masks a HIGHER-tier
        # (ntfs_computed) measurement the credential-less probe made for the
        # same SID — the standard highest-tier-wins attribution below handles
        # it uniformly regardless of which source produced it.
        for entry in smb_shares_entries:
            sid = str(entry.get("sid") or "").strip()
            if not sid:
                continue
            verification = str(entry.get("verification") or "").strip().lower()
            if verification not in buckets:
                verification = _SHARE_ACL_ONLY
            buckets[verification].setdefault(sid, entry)

        # Attribute each SID to its HIGHEST tier only, walking most-certain first.
        tiered: list[list[dict[str, str]]] = []
        for tier in _VERIFICATION_PRECEDENCE:
            tier_entries: list[dict[str, str]] = []
            for sid, entry in buckets[tier].items():
                if sid in seen_sids:
                    continue
                seen_sids.add(sid)
                tier_entries.append(entry)
            tiered.append(tier_entries)

        # PRIMARY = the first non-empty tier; OTHER = every remaining tier's entries.
        primary: list[dict[str, str]] = []
        primary_index = -1
        for index, tier_entries in enumerate(tiered):
            if tier_entries:
                primary = tier_entries
                primary_index = index
                break
        if primary_index < 0:
            return [], []
        others: list[dict[str, str]] = [
            entry for tier_entries in tiered[primary_index + 1 :] for entry in tier_entries
        ]
        return primary, others

    @staticmethod
    def _share_from_artifact(artifact: str | None) -> str:
        """Parse the share name from a ``\\\\host\\<share>\\...`` UNC path."""
        text = str(artifact or "").strip().replace("\\", "/")
        if not text:
            return ""
        # Drop the leading ``//`` of the UNC and split: host / share / rest.
        parts = [segment for segment in PurePosixPath(text).parts if segment not in {"/", "//"}]
        # After normalizing backslashes, an absolute UNC ``//host/share/...`` yields
        # parts like ["//", "host", "share", ...] on POSIX PurePosixPath; guard both.
        cleaned = [segment for segment in text.split("/") if segment]
        if len(cleaned) >= 2:
            return cleaned[1].strip()
        if len(parts) >= 2:
            return parts[1].strip()
        return ""

    def _load_relationship_records(
        self,
        *,
        domain: str | None,
        shell: object | None,
        relationships_path: str | None,
    ) -> list[Any]:
        """Load ``records`` from the inventory ``relationships.json`` (best-effort)."""
        path = str(relationships_path or "").strip()
        if not path and shell is not None:
            path = self._derive_relationships_path(shell, domain)
        if not path or not os.path.isfile(path):
            return []
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
        except Exception as exc:  # noqa: BLE001
            print_exception(exception=exc)
            return []
        if not isinstance(data, dict):
            return []
        records = data.get("records")
        return records if isinstance(records, list) else []

    @staticmethod
    def _derive_relationships_path(shell: object, domain: str | None) -> str:
        """Derive ``domains/<domain>/inventory/relationships.json`` from the shell."""
        domain_text = str(domain or "").strip()
        if not domain_text:
            return ""
        try:
            from adscan_internal.workspaces import domain_subpath

            workspace_cwd = (
                shell._get_workspace_cwd()  # noqa: SLF001
                if hasattr(shell, "_get_workspace_cwd")
                else getattr(shell, "current_workspace_dir", "")
            )
            domains_dir = getattr(shell, "domains_dir", "domains")
            inventory_dir = domain_subpath(workspace_cwd, domains_dir, domain_text, "inventory")
            return os.path.join(inventory_dir, "relationships.json")
        except Exception as exc:  # noqa: BLE001
            print_exception(exception=exc)
            return ""

    def _load_smb_shares_read_set(
        self,
        *,
        domain: str | None,
        shell: object | None,
        smb_shares_path: str | None,
        share_name: str,
    ) -> list[dict[str, str]]:
        """Load the light-probe measured NTFS read-set for one share (best-effort).

        ``smb_shares_native._resolve_measured_read_set`` reads a share's real
        folder security descriptor whenever the connecting identity's own
        ``maximal_access`` already includes ``READ_CONTROL`` — even OUTSIDE a
        full authenticated collection run (a null/guest-session-only sweep,
        where ``inventory/relationships.json`` may not exist at all). This
        loader is what lets that measured evidence reach the SAME
        tier-precedence system :meth:`resolve_share_read_set_tiers` builds
        from ``relationships.json``, so a credential-less read still resolves
        to the real access-control entries instead of the honest-but-inferred
        ``share_acl_only`` fallback.

        Only entries carrying an effective READ right are returned (mirrors
        the ``relationships.json`` path, which only ever considers
        read-capable relations) — a write-only ACE contributes no reader.

        Returns:
            A list of ``{"sid", "label", "verification", "method"}`` dicts —
            the same shape :meth:`resolve_share_read_set_tiers` merges every
            other source's entries into. Empty when the share is absent from
            ``smb/shares.json``, the file does not exist, or nothing in its
            read-set grants READ.
        """
        path = str(smb_shares_path or "").strip()
        if not path and shell is not None:
            path = self._derive_smb_shares_path(shell, domain)
        if not path or not os.path.isfile(path):
            return []
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
        except Exception as exc:  # noqa: BLE001
            print_exception(exception=exc)
            return []
        if not isinstance(data, dict):
            return []
        views = data.get("views")
        if not isinstance(views, list):
            return []

        share_key = share_name.strip().lower()
        for view in views:
            if not isinstance(view, dict):
                continue
            if str(view.get("name") or "").strip().lower() != share_key:
                continue
            live = view.get("live") if isinstance(view.get("live"), dict) else {}
            read_set = live.get("read_set")
            if not isinstance(read_set, list) or not read_set:
                return []
            verification = str(live.get("read_set_verification") or "").strip().lower()
            return self._filter_smb_shares_read_set_entries(
                read_set, verification=verification
            )
        return []

    @staticmethod
    def _filter_smb_shares_read_set_entries(
        read_set: list[Any], *, verification: str
    ) -> list[dict[str, str]]:
        """Translate raw ``smb/shares.json`` read-set entries to the tier shape.

        Deferred (function-local) import of ``effective_mask_has_read`` avoids
        a module-level import cycle: ``share_ntfs_verification`` lives inside
        the ``collector`` package, whose ``__init__`` imports
        ``persistence``, which imports THIS module for
        :func:`reconcile_share_credential_edge_sources` — the same cycle
        :meth:`build_credential_source_steps` already defers around below.
        """
        try:
            from adscan_internal.services.collector.share_ntfs_verification import (
                effective_mask_has_read,
            )
        except Exception:  # noqa: BLE001
            return []

        entries: list[dict[str, str]] = []
        for item in read_set:
            if not isinstance(item, dict):
                continue
            sid = str(item.get("sid") or "").strip()
            if not sid:
                # Exposure-Validation: never fabricate a principal without a SID.
                continue
            try:
                mask = int(item.get("mask") or 0)
            except (TypeError, ValueError):
                mask = 0
            if not effective_mask_has_read(mask):
                continue
            entries.append(
                {
                    "sid": sid,
                    "label": str(item.get("label") or "").strip(),
                    "verification": verification or _SHARE_ACL_ONLY,
                    "method": "smb_shares_native",
                }
            )
        return entries

    @staticmethod
    def _derive_smb_shares_path(shell: object, domain: str | None) -> str:
        """Derive ``domains/<domain>/smb/shares.json`` from the shell."""
        domain_text = str(domain or "").strip()
        if not domain_text:
            return ""
        try:
            from adscan_internal.workspaces import domain_subpath

            workspace_cwd = (
                shell._get_workspace_cwd()  # noqa: SLF001
                if hasattr(shell, "_get_workspace_cwd")
                else getattr(shell, "current_workspace_dir", "")
            )
            domains_dir = getattr(shell, "domains_dir", "domains")
            smb_dir = domain_subpath(workspace_cwd, domains_dir, domain_text, "smb")
            return os.path.join(smb_dir, "shares.json")
        except Exception as exc:  # noqa: BLE001
            print_exception(exception=exc)
            return ""

    def build_source_context(
        self,
        *,
        hosts: Sequence[str] | None = None,
        shares: Sequence[str] | None = None,
        artifact: str | None = None,
        auth_username: str | None = None,
        origin: str = "share_spidering",
        access_vector: str | None = None,
        include_origin_without_fields: bool = True,
        reached_via: str | None = None,
    ) -> dict[str, object] | None:
        """Build a normalized source_context dictionary for spraying flows.

        Args:
            reached_via: When the share read that produced this context was
                PROVEN over a credential-less SMB bind (``"null_session"`` /
                ``"guest_session"`` — the value
                :func:`resolve_ambient_share_read_provenance` returns while
                inside :func:`credential_less_share_read_scope`), pass it here
                so it rides in the returned context. A later
                password-validation sweep that attributes this context's
                credential to specific accounts
                (:meth:`build_password_artifact_source_steps`) reads it back
                and sources the resulting edge from the SAME measured
                read-capable set :meth:`build_credential_source_steps` uses —
                never from the scanner's own probe account. Omitted from the
                context when falsy, so every caller that does not pass it gets
                byte-identical behavior to before.
        """
        host_values = self._normalize_values(hosts)
        share_values = self._normalize_values(shares)
        artifact_text = str(artifact or "").strip()
        auth_text = str(auth_username or "").strip()
        context: dict[str, object] = {}

        if host_values:
            context["hosts"] = host_values
        if share_values:
            context["shares"] = share_values
        if artifact_text:
            context["artifact"] = artifact_text
            artifact_kind = self._infer_artifact_kind(artifact_text)
            if artifact_kind != "unknown":
                context["artifact_kind"] = artifact_kind
        if auth_text:
            context["auth_username"] = auth_text
        access_vector_text = str(access_vector or "").strip()
        if access_vector_text:
            context["access_vector"] = access_vector_text
        reached_via_text = str(reached_via or "").strip()
        if reached_via_text:
            context["reached_via"] = _normalize_reached_via(reached_via_text)
        if origin and (include_origin_without_fields or context):
            context["origin"] = origin
        return context or None

    def build_credential_source_steps(
        self,
        *,
        relation: str,
        edge_type: str,
        source: str,
        secret: str | None = None,
        hosts: Sequence[str] | None = None,
        shares: Sequence[str] | None = None,
        artifact: str | None = None,
        auth_username: str | None = None,
        origin: str = "share_spidering",
        share: str | None = None,
        perspective: str | None = None,
        domain: str | None = None,
        shell: object | None = None,
        relationships_path: str | None = None,
        reached_via: str | None = None,
    ) -> list[object]:
        """Build ``CredentialSourceStep``s for a share-derived credential.

        When the share collector measured a read-capable set for the share the
        credential came from, emit ONE step per read-capable principal (keyed by
        its SID in ``notes["source_sid"]`` so the recorder can fuse a well-known
        SID onto its shared node). When no read-set is available, fall back to a
        single step using the honest entry-label ladder (never ``Domain Users``).

        Args:
            reached_via: For a proven-unauthenticated origin, how the read was
                actually obtained — ``"null_session"`` (the default) or
                ``"guest_session"``. The caller passes the bind kind it used
                (ADscan reads GPP/SYSVOL over a null session, but other
                enrichment reads can use a guest session), so the edge records
                the honest mechanism instead of assuming null. ``None``/unknown
                defaults to ``null_session`` — byte-identical to prior behavior.
        """
        relation_text = str(relation or "").strip()
        edge_type_text = str(edge_type or "").strip()
        source_text = str(source or "").strip()
        if not relation_text or not edge_type_text:
            return []

        try:
            from adscan_internal.services.attack_graph_service import (
                CredentialSourceStep,
                resolve_entry_label_for_auth,
            )
        except Exception:  # noqa: BLE001
            return []

        host_values = self._normalize_values(hosts)
        share_values = self._normalize_values(shares)
        artifact_text = str(artifact or "").strip()
        auth_text = str(auth_username or "").strip()
        secret_text = str(secret or "").strip()
        notes: dict[str, Any] = {}
        if source_text:
            notes["source"] = source_text
        if origin:
            notes["origin"] = origin
        # Stamp the proven-no-credential fact at edge BUILD time. An
        # ``unauth_enrichment`` origin means the artifact was actually read over a
        # pre-credential bind (an SMB null session or an SMB guest session), so the
        # file is reachable with NO domain credential. The edge SOURCE will be
        # upgraded to the measured read-set by
        # ``reconcile_share_credential_edge_sources`` (the honest "who can read"),
        # but this separate FACT must survive whether or not reconciliation runs,
        # so it rides as an edge attribute — not encoded in the source node. The
        # bind kind is DERIVED from the caller's ``reached_via`` (the real bind it
        # used), not hardcoded — a guest-session read must not be mislabeled null.
        if _origin_is_unauthenticated_reachable(origin):
            notes["unauthenticated_reachable"] = True
            notes["reached_via"] = _normalize_reached_via(reached_via)
        if artifact_text:
            notes["artifact"] = artifact_text
            artifact_kind = self._infer_artifact_kind(artifact_text)
            if artifact_kind != "unknown":
                notes["artifact_kind"] = artifact_kind
        if host_values:
            notes["hosts"] = ", ".join(host_values)
            notes["hosts_list"] = host_values
        if share_values:
            notes["shares"] = ", ".join(share_values)
            notes["shares_list"] = share_values
        if auth_text:
            notes["auth_username"] = auth_text
        if secret_text:
            notes["secret"] = secret_text

        sources, other_sources = self.resolve_share_read_set_tiers(
            artifact=artifact or (share_values[0] if share_values else None),
            share=share or (share_values[0] if share_values else None),
            domain=domain,
            shell=shell,
            relationships_path=relationships_path,
        )
        # A proven credential-less read (guest/null session) can only ever be
        # ATTRIBUTED to a principal the credential-less TOKEN can actually
        # present — never to a domain-authenticated grantee the measured ACL
        # happens to also list (e.g. "Authenticated Users"). Filter the
        # measured read-set down to what the proven bind can use BEFORE it
        # becomes the edge source, and record the surviving ACL grantees as
        # ``authorized_by_acl`` so the finding cites the real evidence. See
        # :func:`_filter_primary_readset_for_credential_less_token` for the
        # self_mxac exemption (and its own Authenticated-Users carve-out).
        #
        # ``other_sources`` (the lower-tier "other read-capable principals")
        # is NEVER filtered here — it never becomes the edge source (it only
        # rides along in the notes as auxiliary context, see below), so it
        # carries no claim about what the credential-less TOKEN can present.
        if _origin_is_unauthenticated_reachable(origin):
            sources, authorized_by_acl = _filtered_credential_less_readset(sources, reached_via)
            if authorized_by_acl:
                notes["authorized_by_acl"] = authorized_by_acl
        if sources:
            # The lower-tier read-capable principals ride along in the notes so a
            # real lead is never lost — the PRIMARY edge source is the top tier.
            other_read_sources = [
                {
                    "sid": other["sid"],
                    "label": other["label"],
                    "verification": other["verification"],
                    "method": other["method"],
                }
                for other in other_sources
            ]
            step_notes: dict[str, Any] = dict(notes)
            if other_read_sources:
                step_notes["other_read_sources"] = other_read_sources
            return [
                CredentialSourceStep(
                    relation=relation_text,
                    edge_type=edge_type_text,
                    entry_label=src["label"] or src["sid"],
                    entry_kind="group",
                    notes={
                        **step_notes,
                        "source_sid": src["sid"],
                        "verification": src["verification"],
                        "method": src["method"],
                    },
                )
                for src in sources
            ]

        entry_label = resolve_entry_label_for_auth(auth_text, perspective=perspective)
        return [
            CredentialSourceStep(
                relation=relation_text,
                edge_type=edge_type_text,
                entry_label=entry_label,
                notes=notes,
            )
        ]

    def build_share_password_edge_payload(
        self,
        *,
        source_context: dict[str, object] | None,
        spray_type: str | None = None,
        secret: str | None = None,
        verified_via: str = "spraying",
        perspective: str | None = None,
        domain: str | None = None,
        shell: object | None = None,
        relationships_path: str | None = None,
    ) -> tuple[str, dict[str, object]] | None:
        """Build ``(entry_label, notes)`` for ``PasswordInShare`` edge upserts.

        Resolves the edge source from the measured read-capable set when the share
        collector observed one (threading the winning SID into ``notes``), else
        falls back to the honest entry-label ladder. ``Domain Users`` is never a
        fallback.
        """
        if not isinstance(source_context, dict):
            return None
        origin = str(source_context.get("origin") or "").strip().lower()
        if origin != "share_spidering":
            return None

        auth_text = str(source_context.get("auth_username") or "").strip()
        artifact_text = str(source_context.get("artifact") or "").strip()
        share_values = self._normalize_context_values(source_context.get("shares"))
        source_sid = ""
        verification = ""
        method = ""
        sources = self.resolve_share_read_capable_sources(
            artifact=artifact_text or (share_values[0] if share_values else None),
            share=share_values[0] if share_values else None,
            domain=domain,
            shell=shell,
            relationships_path=relationships_path,
        )
        if sources:
            winner = sources[0]
            entry_label = winner["label"] or winner["sid"]
            source_sid = winner["sid"]
            verification = winner["verification"]
            method = winner["method"]
        else:
            try:
                from adscan_internal.services.attack_graph_service import (
                    resolve_entry_label_for_auth,
                )

                entry_label = resolve_entry_label_for_auth(auth_text, perspective=perspective)
            except Exception:  # noqa: BLE001
                # The ladder's own authenticated default, never Domain Users.
                entry_label = "Authenticated Users"

        notes: dict[str, object] = {
            "verified_via": str(verified_via or "spraying"),
            "origin": "share_spidering",
        }
        if source_sid:
            notes["source_sid"] = source_sid
        if verification:
            notes["verification"] = verification
        if method:
            notes["method"] = method
        spray_type_text = str(spray_type or "").strip()
        if spray_type_text:
            notes["spray_type"] = spray_type_text
        artifact_kind = str(source_context.get("artifact_kind") or "").strip().lower()
        if not artifact_kind and artifact_text:
            artifact_kind = self._infer_artifact_kind(artifact_text)
        if artifact_text:
            notes["artifact"] = artifact_text
        if artifact_kind and artifact_kind != "unknown":
            notes["artifact_kind"] = artifact_kind
        secret_text = str(secret or "").strip()
        if secret_text:
            notes["password"] = secret_text

        host_values = self._normalize_context_values(source_context.get("hosts"))
        if host_values:
            notes["hosts"] = ", ".join(host_values)
            notes["hosts_list"] = host_values
        if share_values:
            notes["shares"] = ", ".join(share_values)
            notes["shares_list"] = share_values
        if auth_text:
            notes["auth_username"] = auth_text
        return entry_label, notes

    def build_password_artifact_source_steps(
        self,
        *,
        source_context: dict[str, object] | None,
        spray_type: str | None = None,
        secret: str | None = None,
        verified_via: str = "spraying",
        domain: str | None = None,
        shell: object | None = None,
        relationships_path: str | None = None,
    ) -> list[object]:
        """Build generic artifact/share credential provenance steps from source context.

        This is the LATER-attribution producer: it fires when a credential
        recovered from a share/artifact read is subsequently attributed to
        specific accounts by a password-validation sweep (``cli/spraying.py``),
        as opposed to :meth:`build_credential_source_steps`, which fires when
        the share-file itself names its user directly. When ``source_context``
        carries ``reached_via`` (the proven credential-less SMB bind —
        ``"null_session"`` / ``"guest_session"`` — that :meth:`build_source_context`
        stamps for a read taken inside :func:`credential_less_share_read_scope`),
        this builder now carries the SAME session-origin metadata and measured
        authorized-reader list :meth:`build_credential_source_steps` already
        carries: the edge is sourced from the token-filtered measured
        read-capable set (see :func:`_filtered_credential_less_readset`), never
        from the scanner's own probe account
        (``source_context["auth_username"]`` here is the scanner's OWN
        transport identity, not a real reader).

        Args:
            domain: Domain whose inventory / light-probe read-set to resolve.
                Only consulted when ``source_context["origin"]`` is
                ``"share_spidering"`` AND ``reached_via`` is present.
            shell: Session shell used to derive the inventory paths. May be
                ``None`` (unit tests inject ``relationships_path`` directly).
            relationships_path: Direct path to ``relationships.json`` —
                injected by unit tests so the resolver runs without a shell.
        """
        if not isinstance(source_context, dict):
            return []

        origin = str(source_context.get("origin") or "").strip().lower()
        if origin not in {"share_spidering", "artifact_filesystem"}:
            return []

        relation = "PasswordInShare" if origin == "share_spidering" else "PasswordInFile"
        edge_type = "share_password" if origin == "share_spidering" else "file_password"
        auth_text = str(source_context.get("auth_username") or "").strip()
        host_values = self._normalize_context_values(source_context.get("hosts"))
        share_values = self._normalize_context_values(source_context.get("shares"))
        artifact_text = str(source_context.get("artifact") or "").strip()
        artifact_kind = str(source_context.get("artifact_kind") or "").strip().lower()
        if not artifact_kind and artifact_text:
            artifact_kind = self._infer_artifact_kind(artifact_text)
        secret_text = str(secret or "").strip()
        spray_type_text = str(spray_type or "").strip()
        access_vector_text = str(source_context.get("access_vector") or "").strip()
        reached_via = str(source_context.get("reached_via") or "").strip()

        notes: dict[str, Any] = {
            "origin": origin,
            "verified_via": str(verified_via or "spraying"),
        }
        if access_vector_text:
            notes["access_vector"] = access_vector_text
        if spray_type_text:
            notes["spray_type"] = spray_type_text
        if artifact_text:
            notes["artifact"] = artifact_text
        if artifact_kind and artifact_kind != "unknown":
            notes["artifact_kind"] = artifact_kind
        if secret_text:
            notes["password"] = secret_text
        if auth_text:
            notes["auth_username"] = auth_text
        if host_values:
            notes["hosts"] = ", ".join(host_values)
            notes["hosts_list"] = host_values
        if share_values:
            notes["shares"] = ", ".join(share_values)
            notes["shares_list"] = share_values

        try:
            from adscan_internal.services.attack_graph_service import (
                CredentialSourceStep,
                resolve_entry_label_for_auth,
            )
        except Exception:  # noqa: BLE001
            return []

        # Only a SHARE read carries a measured read-capable set (the
        # collector/light-probe evidence resolved by
        # resolve_share_read_set_tiers); an "artifact_filesystem" read
        # (WinRM/RDP/MSSQL host filesystem) has none and keeps its existing
        # host-node attribution in the fallback block below.
        if origin == "share_spidering" and reached_via:
            sources, other_sources = self.resolve_share_read_set_tiers(
                artifact=artifact_text or (share_values[0] if share_values else None),
                share=share_values[0] if share_values else None,
                domain=domain,
                shell=shell,
                relationships_path=relationships_path,
            )
            sources, authorized_by_acl = _filtered_credential_less_readset(sources, reached_via)
            normalized_reached_via = _normalize_reached_via(reached_via)
            provenance_notes: dict[str, Any] = {
                "unauthenticated_reachable": True,
                "reached_via": normalized_reached_via,
            }
            if authorized_by_acl:
                provenance_notes["authorized_by_acl"] = authorized_by_acl

            if sources:
                other_read_sources = [
                    {
                        "sid": other["sid"],
                        "label": other["label"],
                        "verification": other["verification"],
                        "method": other["method"],
                    }
                    for other in other_sources
                ]
                step_notes: dict[str, Any] = {**notes, **provenance_notes}
                if other_read_sources:
                    step_notes["other_read_sources"] = other_read_sources
                return [
                    CredentialSourceStep(
                        relation=relation,
                        edge_type=edge_type,
                        entry_label=src["label"] or src["sid"],
                        entry_kind="group",
                        notes={
                            **step_notes,
                            "source_sid": src["sid"],
                            "verification": src["verification"],
                            "method": src["method"],
                        },
                    )
                    for src in sources
                ]

            # No measured read-set at all (or nothing the proven token can
            # present) — the honest well-known fallback for the proven bind
            # kind, NEVER the scanner's own probe account (``auth_username``
            # here is ADscan's own guest/null-session transport identity).
            perspective = (
                "guest" if normalized_reached_via == REACHED_VIA_GUEST_SESSION else "anonymous"
            )
            entry_label = resolve_entry_label_for_auth(auth_text, perspective=perspective)
            return [
                CredentialSourceStep(
                    relation=relation,
                    edge_type=edge_type,
                    entry_label=entry_label,
                    notes={**notes, **provenance_notes},
                )
            ]

        entry_label = resolve_entry_label_for_auth(auth_text)
        entry_kind = ""
        if origin == "artifact_filesystem" and host_values:
            entry_label = host_values[0]
            entry_kind = "computer"

        return [
            CredentialSourceStep(
                relation=relation,
                edge_type=edge_type,
                entry_label=entry_label,
                entry_kind=entry_kind,
                notes=notes,
            )
        ]

    @staticmethod
    def _normalize_values(values: Sequence[str] | None) -> list[str]:
        """Return de-duplicated, non-empty string values preserving order."""
        if not values:
            return []
        normalized: list[str] = []
        seen: set[str] = set()
        for value in values:
            text = str(value or "").strip()
            if not text:
                continue
            key = text.lower()
            if key in seen:
                continue
            seen.add(key)
            normalized.append(text)
        return normalized

    @classmethod
    def _normalize_context_values(cls, value: object) -> list[str]:
        """Normalize context values that may be a single str or a sequence."""
        if value is None:
            return []
        if isinstance(value, str):
            return cls._normalize_values([value])
        if isinstance(value, Sequence):
            return cls._normalize_values([str(item) for item in value])
        return cls._normalize_values([str(value)])

    @staticmethod
    def _infer_artifact_kind(artifact: str) -> str:
        """Infer a coarse artifact kind from a path-like artifact string."""
        artifact_text = str(artifact or "").strip().replace("\\", "/")
        if not artifact_text:
            return "unknown"

        path = PurePosixPath(artifact_text)
        filename = path.name.lower()
        suffixes = [suffix.lower() for suffix in path.suffixes]
        suffix_key = "".join(suffixes[-2:]) if len(suffixes) >= 2 else (suffixes[-1] if suffixes else "")

        archive_suffixes = {
            ".zip",
            ".7z",
            ".rar",
            ".tar",
            ".tgz",
            ".gz",
            ".bz2",
            ".xz",
            ".cab",
            ".iso",
            ".tar.gz",
            ".tar.bz2",
            ".tar.xz",
        }
        config_suffixes = {
            ".cfg",
            ".cnf",
            ".conf",
            ".config",
            ".env",
            ".ini",
            ".json",
            ".properties",
            ".toml",
            ".xml",
            ".yaml",
            ".yml",
        }
        document_suffixes = {
            ".csv",
            ".doc",
            ".docx",
            ".odt",
            ".ods",
            ".pdf",
            ".ppt",
            ".pptx",
            ".rtf",
            ".xls",
            ".xlsx",
        }
        text_suffixes = {
            ".log",
            ".md",
            ".ps1",
            ".reg",
            ".sh",
            ".sql",
            ".txt",
        }
        binary_suffixes = {
            ".accdb",
            ".bin",
            ".dat",
            ".db",
            ".dll",
            ".exe",
            ".kdbx",
            ".mdb",
            ".p12",
            ".pfx",
            ".sqlite",
        }

        if suffix_key in archive_suffixes or (filename.endswith(".bak") and "config" not in filename):
            return "archive"
        if suffix_key in config_suffixes:
            return "config"
        if suffix_key in document_suffixes:
            return "document"
        if suffix_key in text_suffixes:
            return "text"
        if suffix_key in binary_suffixes:
            return "binary"
        if any(keyword in filename for keyword in {"config", "settings"}):
            return "config"
        if any(keyword in filename for keyword in {"backup", "archive"}):
            return "archive"
        return "unknown"


# Relations whose source is a share-file credential read-set (the only edges this
# reconciliation pass touches). Lower-cased for case-insensitive comparison.
_SHARE_FILE_EDGE_RELATIONS: frozenset[str] = frozenset(
    {"gpppassword", "gppautologon", "passwordinshare", "passwordinfile"}
)

# Origins stamped by the share-credential provenance builder. An edge must carry
# one of these in ``notes.origin`` to be a reconciliation candidate.
_SHARE_FILE_EDGE_ORIGINS: frozenset[str] = frozenset(
    {"unauth_enrichment", "share_spidering", "artifact_filesystem"}
)

# Node ids the provisional (read-set-absent) fallback ladder produces before
# collection has measured the share read-set. A share-file edge still sourced
# from one of these is what the reconciliation pass rewrites. Guests (S-1-5-32-546)
# and Authenticated Users (S-1-5-11) are Group-kind → keyed by SID; Anonymous
# Logon (S-1-5-7) is User-kind → keyed by name; Domain Users is matched
# structurally below (its id is domain-scoped and localized).
_PROVISIONAL_FALLBACK_NODE_IDS: frozenset[str] = frozenset(
    {
        "name:s-1-5-7",
        "name:anonymous logon",
        "name:s-1-5-32-546",
        "name:guests",
        "name:s-1-5-11",
        "name:authenticated users",
        "name:domain users",
    }
)


# The one origin marker that proves the artifact was read over a pre-credential
# (null-session / anonymous) bind — i.e. unauthenticated-reachable. Authenticated
# share-hunt edges (``share_spidering`` / ``artifact_filesystem``) must NOT carry
# the attribute: they were read WITH a credential, so they were not proven anonymous.
_UNAUTHENTICATED_REACHABLE_ORIGIN: str = "unauth_enrichment"


def _origin_is_unauthenticated_reachable(origin: str | None) -> bool:
    """Return True when an edge origin proves a pre-credential (null-session) read."""
    return str(origin or "").strip().lower() == _UNAUTHENTICATED_REACHABLE_ORIGIN


def _filtered_credential_less_readset(
    sources: list[dict[str, str]], reached_via: str
) -> tuple[list[dict[str, str]], list[str]]:
    """Token-filter a measured read-set for a proven credential-less bind.

    Shared by :meth:`ShareCredentialProvenanceService.build_credential_source_steps`,
    :meth:`ShareCredentialProvenanceService.build_password_artifact_source_steps`,
    and :func:`reconcile_share_credential_edge_sources` so all three producers of
    a share-secret credential edge can NEVER diverge on how a proven guest/null
    -session read is attributed. A credential-less (guest/null) proven read can
    only ever be attributed to a principal the credential-less TOKEN can
    actually present — never to a domain-authenticated grantee the measured ACL
    happens to also list (e.g. ``Authenticated Users``). See
    :func:`_filter_primary_readset_for_credential_less_token` for the exact
    filtering rules (including the ``self_mxac`` exemption).

    Args:
        sources: The PRIMARY read-set tier (see
            :meth:`ShareCredentialProvenanceService.resolve_share_read_set_tiers`).
        reached_via: The proven bind kind (``"null_session"`` /
            ``"guest_session"``); normalized internally.

    Returns:
        ``(filtered_sources, authorized_by_acl)`` — the token-usable subset of
        ``sources`` and the surviving ACL grantee labels (``[]`` when the
        filtered set is empty, never a fabricated entry).
    """
    normalized_reached_via = _normalize_reached_via(reached_via)
    filtered = _filter_primary_readset_for_credential_less_token(sources, normalized_reached_via)
    authorized_by_acl = [
        str(src.get("label") or src.get("sid") or "").strip()
        for src in filtered
        if src.get("label") or src.get("sid")
    ]
    return filtered, authorized_by_acl


def _is_provisional_fallback_source(from_id: str) -> bool:
    """Return True when an edge's ``from`` is a read-set-absent fallback node.

    A reconciliation candidate's source is one of the honest fallbacks the
    provenance builder uses when no read-set was available (Anonymous Logon /
    Guests / Authenticated Users / Everyone placeholder / a Domain Users node).
    A Domain Users node id is domain-scoped and may be localized, so it is matched
    structurally by its RID-513 suffix as well as by the canonical label.
    """
    normalized = str(from_id or "").strip().lower()
    if normalized in _PROVISIONAL_FALLBACK_NODE_IDS:
        return True
    # Domain Users is keyed by RID 513 (e.g. ``name:S-1-5-21-...-513``) or by the
    # canonical ``name:domain users@<domain>`` membership label.
    return normalized.endswith("-513") or normalized.startswith("name:domain users@")


def reconcile_share_credential_edge_sources(
    shell: object,
    domain: str,
    graph: dict[str, Any],
) -> int:
    """Re-point share-file credential edges to the measured read-capable source.

    The unauth GPP / share-spidering credential edge is built in Phase 2.5,
    BEFORE the native share collector writes ``inventory/relationships.json`` in
    Phase 2. At edge-build time the read-set does not exist, so the edge source
    falls to the honest anonymous/authenticated fallback. This pass — run AFTER
    collection persisted both ``relationships.json`` and the attack graph —
    rewrites any share-file edge still on that provisional fallback to the
    measured read-capable SID node(s) for the edge's artifact share.

    Contract (Exposure-Validation discipline):
        - Only edges whose ``relation`` is a share-file credential relation AND
          whose ``notes.origin`` is a share-file origin AND whose current ``from``
          is a provisional-fallback node are candidates.
        - An edge already sourced from a measured read-set principal is NEVER
          rewritten.
        - When the share has no measured read-set, the honest fallback is LEFT in
          place — never fabricated into a read-set principal.
        - Idempotent: re-running makes no further change (the rewritten source is
          no longer a provisional fallback).

    The source node is resolved through the SAME well-known-SID fusion the
    credential-recording path uses (``_resolve_wellknown_source_entry`` →
    ``ensure_entry_node_for_domain``), and the edge ``from`` is rewritten through
    the graph edge-mutation SSOT (``upsert_edge``) — the stale edge is removed and
    a new one upserted so status and notes are preserved.

    Args:
        shell: Session shell exposing the workspace context.
        domain: Domain whose inventory / attack graph to reconcile.
        graph: The loaded attack graph dict (mutated in place).

    Returns:
        The number of edges reconciled (0 when none qualified or no read-set).
    """
    edges = graph.get("edges")
    if not isinstance(edges, list) or not edges:
        return 0

    # Lazy import to avoid a module-level import cycle (attack_graph_service
    # imports this module's classes for CredentialSourceStep building).
    from adscan_internal.services.attack_graph_service import (
        _resolve_wellknown_source_entry,
        ensure_entry_node_for_domain,
        upsert_edge,
    )

    service = ShareCredentialProvenanceService()
    reconciled = 0

    # Snapshot the candidate edges first: upsert_edge appends/rewrites the edges
    # list, so iterate over a stable copy.
    candidates = [edge for edge in edges if isinstance(edge, dict)]
    for edge in candidates:
        relation = str(edge.get("relation") or "").strip().lower()
        if relation not in _SHARE_FILE_EDGE_RELATIONS:
            continue
        notes = edge.get("notes") if isinstance(edge.get("notes"), dict) else {}
        origin = str(notes.get("origin") or "").strip().lower()
        if origin not in _SHARE_FILE_EDGE_ORIGINS:
            continue
        from_id = str(edge.get("from") or "").strip()
        if not _is_provisional_fallback_source(from_id):
            continue  # already on a measured read-set principal — never rewrite

        artifact = str(notes.get("artifact") or "").strip()
        share = str(notes.get("share") or notes.get("shares") or "").strip()
        sources = service.resolve_share_read_capable_sources(
            artifact=artifact or None,
            share=share or None,
            domain=domain,
            shell=shell,
            relationships_path=None,
        )

        # Preserve the proven-no-credential FACT across the source upgrade. The
        # source node is correctly rewritten to the measured read-set ("who can
        # read"), but an ``unauth_enrichment`` edge was read over a pre-credential
        # bind — that separate fact must not be erased, so it rides onto the
        # rewritten edge as an attribute. The bind kind is carried from the
        # build-time notes (``null_session`` or ``guest_session``) so a guest read
        # stays a guest read through reconciliation; a legacy/missing value
        # normalizes to ``null_session``. Idempotent: re-stamping is a no-op.
        preserve_unauth_reachable = _origin_is_unauthenticated_reachable(origin)
        preserved_reached_via = _normalize_reached_via(notes.get("reached_via"))
        authorized_by_acl: list[str] | None = None
        if preserve_unauth_reachable:
            # A credential-less (guest/null) proven read can only be attributed
            # to a principal the proven token can actually present — never to a
            # domain-authenticated grantee the measured ACL also happens to
            # list. Filter down to what the token can use before it becomes the
            # edge source; the surviving labels ride along as the ACL evidence.
            # See :func:`_filtered_credential_less_readset` (the shared
            # filter+attribution helper ``build_credential_source_steps`` and
            # ``build_password_artifact_source_steps`` also call), including
            # its self_mxac exemption and Authenticated-Users carve-out.
            sources, authorized_by_acl_list = _filtered_credential_less_readset(
                sources, preserved_reached_via
            )
            authorized_by_acl = authorized_by_acl_list or None

        if not sources:
            continue  # no read-set → leave the honest fallback, never fabricate

        to_id = str(edge.get("to") or "").strip()
        edge_type = str(edge.get("edge_type") or "").strip()
        status = str(edge.get("status") or "discovered").strip()
        if not to_id or not edge_type:
            continue

        # Resolve the read-set source node(s) through the SAME fusion the
        # credential-recording path uses. When several principals read the share,
        # each becomes its own source edge to the credential owner.
        resolved_any = False
        # A measured winner CAN fuse onto the SAME node id the provisional
        # fallback already points from — the honest case where the read is a
        # null-session read AND the measured NTFS ACEs name Anonymous Logon
        # itself (the fallback label and the measured source coincide). When
        # that happens ``upsert_edge`` below matches the EXISTING edge by
        # (from, to, relation) identity and mutates it IN PLACE, so the
        # measured evidence (``authorized_by_acl``/``source_sid``/
        # ``verification``) lands directly on it — there is no stale
        # duplicate to remove afterward. Skipping the upsert in this case (as
        # earlier code did) silently left the edge on its incomplete
        # provisional notes forever, never attaching the measured evidence.
        edge_updated_in_place = False
        for src in sources:
            src_notes = {k: v for k, v in notes.items()}
            if preserve_unauth_reachable:
                src_notes["unauthenticated_reachable"] = True
                src_notes["reached_via"] = preserved_reached_via
                if authorized_by_acl:
                    src_notes["authorized_by_acl"] = authorized_by_acl
            src_notes["source_sid"] = src.get("sid", "")
            if src.get("verification"):
                src_notes["verification"] = src["verification"]
            if src.get("method"):
                src_notes["method"] = src["method"]
            entry_label = str(src.get("label") or src.get("sid") or "").strip()
            entry_id = _resolve_wellknown_source_entry(graph, entry_label, src_notes)
            if entry_id is None:
                entry_id = ensure_entry_node_for_domain(
                    shell, domain, graph, label=entry_label, entry_kind="group"
                )
            if not entry_id:
                continue
            new_edge = upsert_edge(
                graph,
                from_id=entry_id,
                to_id=to_id,
                relation=edge.get("relation") or relation,
                edge_type=edge_type,
                status=status,
                notes=src_notes,
            )
            if not new_edge:
                continue
            resolved_any = True
            if entry_id == from_id:
                edge_updated_in_place = True

        if not resolved_any:
            continue

        if not edge_updated_in_place:
            # Remove the stale provisional-fallback edge now that the measured
            # source edge(s) are in place under a different node id. Identity
            # by the original dict object.
            graph["edges"] = [e for e in graph.get("edges", []) if e is not edge]
        reconciled += 1

    return reconciled
