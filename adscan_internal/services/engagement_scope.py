"""Engagement scope SSOT: is this domain one the scan may act against?

ONE question, answered here and nowhere else, consulted at the execution seams
every attack step passes through before it runs:

* the attack-path executor's per-step loop
  (``cli/attack_path_execution.py``), and its readiness overlay, so a route
  whose next step leaves the scope is never offered to run;
* the post-compromise cross-domain escalation drain
  (``services/cross_domain_escalation.py``), which fires escalations outside
  any attack path;
* the two cross-domain technique runners themselves (``run_raise_child`` and
  ``run_cross_org_tgt_delegation_step``), so a manual command cannot reach past
  the scope either.

The collection has its own seam, :func:`collection_host_verdict`: the
multi-domain flow collects each domain separately, so a domain's collection
connects only to hosts that domain owns (a CA hosted in the parent domain, a
DC of another domain the forest Configuration NC lists, an SQL host another
domain's SPN names). A host of another domain is collected with that domain,
and only when it is in scope; from elsewhere it stays mapped from directory
data and is reported as not checked.

Scope is contractual. It is settled before collection by the trust-scope
decision (the request's trusted-domain setting, the scan policy, or the
operator) and recorded here, in memory on the shell and in the workspace
``scope.json`` for disclosure. No surface asks per step whether to cross it: the
operator widens the scope before the scan, never mid-route.

Verdict ladder for one domain (first match wins):

1. no domain at all (it could not be determined) -> OUT;
2. the synthetic well-known placeholder -> IN (it is not a domain);
3. an origin (the domain the scan targets, or one the trust decision started
   from) -> IN;
4. a recorded trust decision -> its answer (an explicit exclusion always wins);
5. the domain the route itself was computed for -> IN (computing a route there
   needed that domain enumerated, which was itself a scope decision);
6. a policy that follows trusts on its own (``scope_expansion = automatic``,
   Lab / CTF only) -> IN;
7. otherwise -> OUT: a domain nobody put in scope is not in scope.

An attack step is checked on BOTH axes the step-domain SSOT
(``attack_step_domain_resolution``) defines: the acting object and the target.
Either one outside the scope keeps the step from running, whatever the object
is (the domain itself, a user, group, computer, certificate authority...).

The ASSET scope narrows the domain scope to objects: a deny-list (hosts and
accounts ADscan never touches) and an allow-list (only these), deny winning.
The grammar and the matchers live in :mod:`adscan_core.engagement_scope_model`
(stdlib, shared with the launcher and the web); this module resolves entries to
directory identities, answers the verdicts (:func:`host_scope_verdict`,
:func:`principal_scope_verdict`, :func:`partition_targets_in_scope`,
:func:`require_host_in_scope`, :func:`egress_allowed`) and keeps the record.
Undetermined is never contacted, and directory data about an excluded object is
still collected and drawn: only contact and action are gated.

The record is rehydrated from ``scope.json`` when a workspace is loaded
(:func:`rehydrate_engagement_scope`), so ``execute``, ``recheck`` and a reopened
``start`` session run under the recorded decision, never a fresh default.
"""

from __future__ import annotations

import atexit
import bisect
import ipaddress
import json as json_module
import os
import re
import threading
import time
import uuid
from collections import OrderedDict
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass, field
from dataclasses import fields as dataclass_fields
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Iterable, Iterator, Mapping

from adscan_core import engagement_scope_model as asset_model
from adscan_core import telemetry
from adscan_core.engagement_scope_model import AssetIdentity, AssetMatcher, AssetScope
from adscan_core.reporting.engagement_scope import (
    CAUSE_ADDRESS_NOT_ATTRIBUTED,
    CAUSE_AFFECTED_HOSTS_UNKNOWN,
    CAUSE_ENTRY_NOT_MATCHED,
    CAUSE_NAME_NOT_RESOLVED,
    CAUSE_RECORD_UNREADABLE,
    NOT_EXECUTED_OUTSIDE_SCOPE,
    SCOPE_OUTCOME_EXCLUDED,
    SCOPE_OUTCOME_UNCONFIRMED,
    asset_scope_note,
    domains_named,
    scope_note,
    scope_record_lock,
    set_scope_record_flusher,
)
from adscan_core.rich_output import (
    print_error,
    print_exception,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_warning,
)
from adscan_core.scan_policy import settings as policy_settings
from adscan_internal.rich_output import mark_sensitive

#: Shell attribute holding this session's scope record (never ``domains_data``:
#: it is session state, not workspace data).
_RECORD_ATTR = "_engagement_scope_record"
#: Shell attribute holding the (relation, to) keys already announced.
_ANNOUNCED_ATTR = "_engagement_scope_announced"

SCOPE_FILENAME = "scope.json"

#: Verdict bases.
BASIS_UNDETERMINED = "undetermined"
BASIS_PLACEHOLDER = "not_a_domain"
BASIS_ORIGIN = "origin"
BASIS_SELECTED = "selected"
BASIS_EXCLUDED = "excluded"
BASIS_PATH_DOMAIN = "path_domain"
BASIS_POLICY_AUTOMATIC = "policy_automatic"
BASIS_NOT_CONFIRMED = "not_confirmed"
BASIS_RECORD_UNREADABLE = "record_unreadable"

_PLACEHOLDERS = frozenset({"wellknown"})

#: THE lock of the record: every change to the session record's persisted
#: parts (a refusal counted, a backstop hit, a resolution staged) and every
#: write of ``scope.json`` happens under it, from whichever thread. Re-entrant,
#: and a ``threading`` lock on purpose (never an asyncio primitive).
_RECORD_LOCK = threading.RLock()
_DN_DC = re.compile(r"(?i)\bDC=([^,]+)")


@dataclass(frozen=True)
class ScopeVerdict:
    """Whether one domain is in the engagement scope, and why."""

    domain: str
    in_scope: bool
    basis: str


@dataclass(frozen=True)
class StepScopeVerdict:
    """The scope verdict for one attack step.

    Four axes: the DOMAIN of the acting object and of the target, and, when an
    asset scope exists, the acting object and the target THEMSELVES (an excluded
    account or host inside an in-scope domain). ``allowed`` is the AND of all.
    """

    allowed: bool
    source: ScopeVerdict
    target: ScopeVerdict
    source_asset: "AssetScopeVerdict | None" = None
    target_asset: "AssetScopeVerdict | None" = None

    @property
    def out_of_scope_domain(self) -> str:
        """The first domain that keeps the step from running ("" when allowed).

        Empty as well when only the ASSET scope keeps it out
        (:attr:`asset_refusal`): that object sits in an in-scope domain.
        """
        for verdict in (self.target, self.source):
            if not verdict.in_scope:
                return verdict.domain
        return ""

    @property
    def asset_refusal(self) -> "AssetScopeVerdict | None":
        """The asset verdict that keeps the step out (target first), or ``None``.

        ``None`` whenever a DOMAIN axis already refuses the step: the domain
        reason is the one reported.
        """
        if not (self.source.in_scope and self.target.in_scope):
            return None
        for verdict in (self.target_asset, self.source_asset):
            if verdict is not None and not verdict.allowed:
                return verdict
        return None


# ── The record ─────────────────────────────────────────────────────────────


def _norm(value: Any) -> str:
    return str(value or "").strip().rstrip(".").lower()


def _empty_record() -> dict[str, Any]:
    return {
        "origin_domains": [],
        "entries": {},
        "decided_by": "",
        "withheld": [],
        # Not persisted: what THIS session decided, and the origins read back
        # from an earlier session's file (a later decision may exclude them).
        "session_decided": set(),
        "rehydrated_origins": [],
        "asset_scope": None,
        # Set when scope.json existed but could not be read: never overwritten.
        "unreadable": "",
        "unreadable_path": "",
        # The trust decisions were in a file that could not be read and was set
        # aside: no domain beyond the scan's own target until one is made again.
        "trust_record_lost": False,
        # Set when the last attempt to write the scope failed (fail closed).
        "write_failed": "",
        # Changed in memory since the last write (flush_engagement_scope).
        "dirty": False,
        "refusal_index": None,
        "refusal_index_of": None,
        "backstop_pending": 0,
        # What this session last read from or wrote to the file: the block's
        # (revision, digest), the refusal counts already there, and the file's
        # (mtime, size). A write is a MERGE against the file as it is now.
        "disk_signature": None,
        "refusal_base": {},
        "hits_base": 0,
        "disk_stat": None,
        "adopted_newer": False,
        "resolve_adopted": False,
        # Not persisted: what the operator named for this run before any data
        # about the domain existed (``declare_scan_target``), the name servers
        # that did not answer (``server -> when``), and the engagement name
        # servers this session asked.
        "declared": {},
        "silent_name_servers": {},
        "name_servers_asked": [],
    }


def _record(shell: Any) -> dict[str, Any]:
    record = getattr(shell, _RECORD_ATTR, None)
    if not isinstance(record, dict):
        record = _empty_record()
        try:
            setattr(shell, _RECORD_ATTR, record)
        except Exception:  # noqa: BLE001 - a frozen double still gets an answer
            pass
    for key, value in _empty_record().items():
        record.setdefault(key, value)
    return record


def _workspace_dir(shell: Any) -> str:
    for attr in ("current_workspace_dir", "current_workspace"):
        value = getattr(shell, attr, None)
        if isinstance(value, (str, os.PathLike)) and str(value):
            return os.fspath(value)
    return ""


def record_trust_scope_decision(
    shell: Any,
    *,
    source_domain: str,
    entries: Iterable[Any],
    decided_by: str,
) -> None:
    """Record one trust-scope decision and write the workspace ``scope.json``.

    Successive decisions in the same session MERGE: a domain offered again takes
    the new answer, a domain not offered keeps the earlier one, and a domain the
    session already put in scope stays in scope when a later decision merely
    leaves it unselected because it was already enumerated (the pivot flow).
    That carry-over holds within ONE session: a domain an earlier session put in
    scope (read back by :func:`rehydrate_engagement_scope`) takes the new answer,
    so a narrower rescan of the same workspace is honoured.

    Args:
        shell: The session shell.
        source_domain: The domain the trust enumeration started from (always in
            scope: the scan was pointed at it, or reached it in scope).
        entries: ``collector.scope.ScopeEntry`` rows, one per offered domain.
        decided_by: Who settled it (``adscan_core.reporting.engagement_scope``
            ``DECIDED_BY_*``).
    """
    record = _record(shell)
    origin = _norm(source_domain)
    if origin and origin not in record["origin_domains"]:
        record["origin_domains"].append(origin)
    stored: dict[str, dict[str, Any]] = record["entries"]
    decided: set[str] = record["session_decided"]
    for entry in entries or ():
        row = asdict(entry) if not isinstance(entry, Mapping) else dict(entry)
        name = _norm(row.get("domain"))
        if not name:
            continue
        previous = stored.get(name)
        keep_in = bool(previous and previous.get("in_scope") is True and name in decided)
        row["in_scope"] = bool(row.get("in_scope")) or keep_in or name == origin
        stored[name] = row
        decided.add(name)
    if decided_by:
        record["decided_by"] = str(decided_by)
    record["trust_record_lost"] = False
    _bump_asset_version(shell)
    _save(shell)


def _save(shell: Any, *, strict: bool = False) -> bool:
    """Write the session record to ``<workspace>/scope.json`` (THE writer).

    One atomic write (a temporary file renamed over the target), under the
    record lock, whichever thread asks. Never writes over a file this session
    could not read (:func:`rehydrate_engagement_scope`): that file holds the
    client's recorded decision, and an empty rewrite would erase it
    (:func:`record_asset_scope` sets it aside first).

    Args:
        strict: Raise when the write fails (a scope being recorded must not be
            reported as saved). Otherwise the failure is logged, the record
            stays marked for the next write, and False is returned.

    Returns:
        True when the file was written.
    """
    workspace = _workspace_dir(shell)
    if not workspace:
        return False
    record = _record(shell)
    if record.get("unreadable"):
        print_info_debug("engagement-scope: scope.json left untouched (unreadable on load)")
        return False
    path = os.path.join(workspace, SCOPE_FILENAME)
    current = _asset_state(shell)
    if not strict and current is not None and current.broken:
        # The block on disk is the one this session could not use: a flush
        # never writes over it (recording a scope does, and recovers).
        print_info_debug("engagement-scope: scope.json left untouched (unusable asset scope)")
        return False
    with _RECORD_LOCK:
        try:
            from adscan_internal.services.collector.scope import (  # noqa: PLC0415
                ScopeEntry,
                ScopeResult,
                save_scope,
            )

            with scope_record_lock(workspace):
                # Another session, the web or a promotion may have written the
                # file since this session read it: merge against what is there
                # NOW, never write an older scope back over a newer one.
                if not _merge_with_disk(shell, record, path, recording=strict):
                    return False
                return _write_record(shell, record, path, ScopeEntry, ScopeResult, save_scope)
        except Exception as exc:  # noqa: BLE001 - disclosure never breaks the scan
            if strict:
                raise
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            return False


def _block_signature(block: Any) -> tuple[str, int, str] | None:
    """``(record_id, revision, digest)`` of an ``asset_scope`` block (``None``: no block).

    ``record_id`` is the identity of the record's LINEAGE: it is given when a
    scope is recorded where no usable block exists (a first scope, a file that
    was deleted, a damaged one being recovered) and kept by every later
    revision. Two blocks are comparable by revision only inside one lineage.
    """
    if not isinstance(block, Mapping):
        return None
    try:
        revision = int(block.get("revision") or 0)
    except (TypeError, ValueError):
        revision = 0
    return str(block.get("record_id") or ""), revision, str(block.get("digest") or "")


def _usable_disk_block(payload: Any) -> Mapping[str, Any] | None:
    """The file's ``asset_scope`` block when it is one a session can run under."""
    block = payload.get("asset_scope") if isinstance(payload, Mapping) else None
    if not isinstance(block, Mapping) or _block_problem(block):
        return None
    try:
        if not _digest_holds(block, AssetScope.from_dict(block)):
            return None
    except asset_model.ScopeSyntaxError:
        return None
    return block


def _revision_summary(block: Mapping[str, Any]) -> dict[str, Any]:
    signature = _block_signature(block) or ("", 0, "")
    return {
        "revision": signature[1],
        "digest": signature[2],
        "decided_by": str(block.get("decided_by") or ""),
        "decided_at": str(block.get("decided_at") or ""),
        "allow": len(block.get("allow") or ()) if isinstance(block.get("allow"), list) else 0,
        "deny": len(block.get("deny") or ()) if isinstance(block.get("deny"), list) else 0,
    }


def _refusal_key(row: Mapping[str, Any]) -> tuple[Any, ...]:
    return (row.get("surface"), row.get("target"), row.get("reason"))


def _refusal_counts(block: Any) -> dict[tuple[Any, ...], int]:
    rows = block.get("refusals") if isinstance(block, Mapping) else None
    out: dict[tuple[Any, ...], int] = {}
    for row in rows if isinstance(rows, list) else ():
        if isinstance(row, Mapping):
            try:
                out[_refusal_key(row)] = int(row.get("count") or 0)
            except (TypeError, ValueError):
                out[_refusal_key(row)] = 0
    return out


def _file_stat(path: str) -> tuple[int, int] | None:
    try:
        info = os.stat(path)
    except OSError:
        return None
    return info.st_mtime_ns, info.st_size


def _note_disk_state(record: dict[str, Any], path: str) -> None:
    """Remember what the file holds now (after a load or a write of this session)."""
    block = record.get("asset_scope")
    record["disk_signature"] = _block_signature(block)
    record["refusal_base"] = _refusal_counts(block)
    try:
        record["hits_base"] = int(block.get("backstop_hits") or 0) if isinstance(block, Mapping) else 0
    except (TypeError, ValueError):
        record["hits_base"] = 0
    record["disk_stat"] = _file_stat(path)


def _merge_counters(
    record: dict[str, Any], mine: dict[str, Any], disk: Mapping[str, Any]
) -> None:
    """Add what THIS session counted since its last write to what the file holds.

    Refusal rows are keyed by (surface, target, reason): a row another writer
    added is kept, a row both hold gets this session's increase added. Backstop
    hits are a sum. Nothing another writer counted is ever lost.
    """
    base: Mapping[tuple[Any, ...], int] = record.get("refusal_base") or {}
    merged: list[dict[str, Any]] = []
    index: dict[tuple[Any, ...], dict[str, Any]] = {}
    disk_rows = disk.get("refusals")
    for row in disk_rows if isinstance(disk_rows, list) else ():
        if isinstance(row, Mapping):
            copy = dict(row)
            index[_refusal_key(copy)] = copy
            merged.append(copy)
    for row in mine.get("refusals") or ():
        if not isinstance(row, Mapping):
            continue
        key = _refusal_key(row)
        try:
            delta = int(row.get("count") or 0) - int(base.get(key, 0))
        except (TypeError, ValueError):
            delta = 0
        if key in index:
            if delta > 0:
                index[key]["count"] = int(index[key].get("count") or 0) + delta
        elif delta > 0:
            copy = dict(row)
            copy["count"] = delta
            index[key] = copy
            merged.append(copy)
    mine["refusals"] = merged[:_REFUSALS_MAX]
    try:
        truncated = max(int(disk.get("refusals_truncated") or 0), int(mine.get("refusals_truncated") or 0))
    except (TypeError, ValueError):
        truncated = 0
    if truncated:
        mine["refusals_truncated"] = truncated
    try:
        counted = int(mine.get("backstop_hits") or 0) - int(record.get("hits_base") or 0)
        mine["backstop_hits"] = int(disk.get("backstop_hits") or 0) + max(counted, 0)
    except (TypeError, ValueError):
        mine["backstop_hits"] = int(mine.get("backstop_hits") or 0)
    record["refusal_index"] = None


def _merge_with_disk(shell: Any, record: dict[str, Any], path: str, *, recording: bool) -> bool:
    """Bring the session record in line with ``scope.json`` as it is NOW.

    Called with the record's file lock held, right before the write. The rule
    (the same for every writer of the file, see ``scope_record_lock``):

    * the allow and deny lists on disk are never replaced by OLDER ones. A
      plain flush (refusals, hits, resolution) by a session holding an earlier
      revision ADOPTS the newer scope: the file keeps it, the session runs
      under it from here, and only this session's counters are added;
    * a scope this session is RECORDING is the newest decision: it becomes
      revision ``disk + 1`` and keeps the file's revision history;
    * a session that never loaded the block (it has none) keeps the file's;
    * counters are added, never overwritten;
    * trust decisions this session did not make itself are taken from the file.

    Returns:
        False when the file cannot be read and this is not a recording: it is
        left untouched (an unreadable record is never overwritten by a flush).
    """
    payload, problem = _read_scope_file(path)
    if problem:
        if not recording:
            print_error(
                f"The engagement scope file {mark_sensitive(path, 'path')} can no longer be "
                f"read ({problem}); what this session counted was not written to it."
            )
            return False
        record["unreadable_path"] = path
        _set_aside_unreadable_file(shell, record)
        if isinstance(record.get("asset_scope"), dict):
            # Recorded over a file nobody could read: a new record.
            record["asset_scope"]["record_id"] = uuid.uuid4().hex
        record["disk_signature"] = None
        record["refusal_base"] = {}
        return True
    if not isinstance(payload, Mapping):
        # No file. A flush puts this session's record back; a recording starts
        # a new record, which sessions still holding the old one yield to.
        mine = record.get("asset_scope")
        if recording and isinstance(mine, dict):
            base = record.get("disk_signature")
            mine["record_id"] = uuid.uuid4().hex
            if base is not None and base[0]:
                mine["supersedes"] = {"record_id": base[0], "revision": base[1]}
        return True
    decided: set[str] = record["session_decided"]
    for row in payload.get("entries") or ():
        name = _norm(row.get("domain")) if isinstance(row, Mapping) else ""
        if name and name not in decided:
            record["entries"][name] = dict(row)
    for origin in domains_named(payload.get("origin_domains") or ()):
        if origin not in record["origin_domains"] and origin not in record["rehydrated_origins"]:
            record["rehydrated_origins"].append(origin)
    known_withheld = {repr(sorted(w.items())) for w in record["withheld"] if isinstance(w, Mapping)}
    for row in payload.get("withheld") or ():
        if isinstance(row, Mapping) and repr(sorted(row.items())) not in known_withheld:
            record["withheld"].append(dict(row))
    mine = record.get("asset_scope")
    base = record.get("disk_signature")
    raw = payload.get("asset_scope")
    disk = _usable_disk_block(payload)
    if isinstance(raw, Mapping) and disk is None:
        # The file holds a block nobody can run under (damaged since this
        # session read it). A flush never writes over it, and this session
        # fails closed with it; a recording replaces it as a NEW record.
        if not recording:
            _set_asset_state(shell, _broken_state("the asset_scope block on disk is no longer valid"))
            return False
    if disk is None:
        if recording and isinstance(mine, dict):
            # No usable record on disk (none yet, deleted, damaged): what is
            # recorded now starts a new lineage, which every session still
            # holding the earlier one yields to.
            mine["record_id"] = uuid.uuid4().hex
            if base is not None and base[0]:
                mine["supersedes"] = {"record_id": base[0], "revision": base[1]}
        return True
    on_disk = _block_signature(disk)
    if not isinstance(mine, dict):
        # A session that never loaded the asset scope must not erase it.
        record["asset_scope"] = dict(disk)
        record["adopted_newer"] = True
        return True
    if recording:
        # THE newest decision: numbered after whatever the file holds now, in
        # the file's lineage, whatever this session had seen before.
        mine["record_id"] = on_disk[0] or uuid.uuid4().hex
        mine.pop("supersedes", None)
        if disk.get("supersedes") and on_disk[0]:
            mine["supersedes"] = disk["supersedes"]
        mine["revision"] = on_disk[1] + 1
        history = [r for r in disk.get("revisions") or () if isinstance(r, Mapping)]
        history.append(_revision_summary(disk))
        mine["revisions"] = history[-_REVISIONS_KEPT:]
        _merge_counters(record, mine, disk)
        return True
    if on_disk == base:
        _merge_counters(record, mine, disk)
        return True
    # A block without a record id is a lineage of its own, never a shared
    # "empty" one: two such blocks are not comparable by revision.
    same_lineage = base is not None and bool(base[0]) and on_disk[0] == base[0]
    if same_lineage and on_disk[1] < base[1]:
        # The same record at an EARLIER revision: somebody put an older file
        # back (a restored backup, a promotion rolled back). The engine cannot
        # tell which, and a flush is not a decision, so it never writes this
        # session's lists back over the file. The file stands. When it is at
        # least as strict as what this session runs under, the session runs
        # under it from here; when it would let the session touch MORE, the
        # session fails closed until a scope is recorded (only an explicit
        # recording decides).
        try:
            widens = _scope_widens(AssetScope.from_dict(mine), AssetScope.from_dict(disk))
        except asset_model.ScopeSyntaxError:
            widens = True
        if widens:
            print_warning(
                "Engagement scope: scope.json was put back to an earlier revision "
                f"({on_disk[1]}, this session held {base[1]}) that allows more than this "
                "session's scope. ADscan did not write over it and contacts no host until "
                "the scope is recorded again."
            )
            _set_asset_state(
                shell,
                _broken_state(
                    "scope.json was put back to an earlier revision that allows more than "
                    "the scope this session ran under"
                ),
            )
            return False
        print_warning(
            "Engagement scope: scope.json was put back to an earlier revision "
            f"({on_disk[1]}, this session held {base[1]}). ADscan kept the file and runs "
            "under it from now on."
        )
    # Anything else is newer than what this session holds: a later revision
    # of its record, the same revision with other lists (an edit outside
    # ADscan), or ANOTHER record (the scope was re-created: this session's
    # record is not an ancestor of the file's, so it never wins). The file's
    # scope stands and this session runs under it from here; only what this
    # session counted is added.
    adopted = dict(disk)
    if same_lineage and on_disk[1] == base[1]:
        # Same revision, other lists: an out-of-band change. It is adopted,
        # and the record says so.
        history = [r for r in adopted.get("revisions") or () if isinstance(r, Mapping)]
        history.append(
            {
                "revision": on_disk[1],
                "digest": base[2],
                "decided_by": "out_of_band",
                "decided_at": datetime.now(timezone.utc).isoformat(),
                "out_of_band": True,
                "allow": len(mine.get("allow") or ()) if isinstance(mine.get("allow"), list) else 0,
                "deny": len(mine.get("deny") or ()) if isinstance(mine.get("deny"), list) else 0,
            }
        )
        adopted["revisions"] = history[-_REVISIONS_KEPT:]
    counters = {
        "refusals": mine.get("refusals") or [],
        "refusals_truncated": mine.get("refusals_truncated"),
        "backstop_hits": mine.get("backstop_hits"),
    }
    _merge_counters(record, counters, disk)
    adopted["refusals"] = counters["refusals"]
    adopted["backstop_hits"] = counters["backstop_hits"]
    if counters.get("refusals_truncated"):
        adopted["refusals_truncated"] = counters["refusals_truncated"]
    record["asset_scope"] = adopted
    record["refusal_index"] = None
    record["adopted_newer"] = True
    return True


def _scope_widens(old: AssetScope, new: AssetScope) -> bool:
    """Whether ``new`` lets a session touch anything ``old`` did not.

    Entry by entry, never by what the entries resolve to: an exclusion dropped,
    an allow entry added to an allow list (or the allow list removed), or
    domain controllers opened to host contacts.
    """
    if not {e.key for e in old.deny} <= {e.key for e in new.deny}:
        return True
    if old.allow and (not new.allow or not {e.key for e in new.allow} <= {e.key for e in old.allow}):
        return True
    return (
        old.dc_access != new.dc_access and new.dc_access == asset_model.DC_ACCESS_FULL and bool(new.allow)
    )


def _adopt_newer_scope(shell: Any, record: dict[str, Any]) -> None:
    """Run this session under the scope it just found on disk."""
    previous = _asset_state(shell)
    try:
        state = _state_from_block(record.get("asset_scope"))
    except Exception as exc:  # noqa: BLE001 - a block that cannot be used fails closed
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        state = _broken_state(f"the newer scope could not be loaded ({type(exc).__name__})")
    if state is not None and not state.broken and previous is not None and not previous.broken:
        state.adopt_knowledge(previous)
    _set_asset_state(shell, state)
    revision = (record.get("asset_scope") or {}).get("revision")
    print_warning(
        "Engagement scope: a newer scope was recorded for this workspace "
        f"(revision {revision}). This session runs under it from now on."
    )


def _write_record(
    shell: Any, record: dict[str, Any], path: str, ScopeEntry: Any, ScopeResult: Any, save_scope: Any
) -> bool:
    """Replace ``scope.json`` with the (merged) session record. Lock held."""
    with _RECORD_LOCK:
        try:
            if record.get("adopted_newer"):
                record["adopted_newer"] = False
                record["resolve_adopted"] = True
                _adopt_newer_scope(shell, record)
            _stage_pending_counts(shell)
            fields = {f.name for f in dataclass_fields(ScopeEntry)}
            entries = [
                ScopeEntry(**{k: v for k, v in row.items() if k in fields})
                for row in record["entries"].values()
            ]
            extra: dict[str, Any] = {
                "origin_domains": list(
                    dict.fromkeys([*record["origin_domains"], *record["rehydrated_origins"]])
                ),
                "decided_by": record.get("decided_by") or "",
                "withheld": list(record["withheld"]),
            }
            if isinstance(record.get("asset_scope"), dict):
                extra["asset_scope"] = record["asset_scope"]
            save_scope(ScopeResult(entries=entries), path, extra=extra)
            record["dirty"] = False
            _note_disk_state(record, path)
            return True
        finally:
            # ``resolve_adopted`` stays set for the caller: a checkpoint resolves
            # the pending entries of a scope this write adopted.
            pass


def _session_origins(shell: Any) -> list[str]:
    names = list(_record(shell)["origin_domains"])
    primary = _norm(getattr(shell, "domain", None))
    if primary and primary not in names:
        names.append(primary)
    # The domain the operator named as this run's target, before the session
    # holds anything else about it (``declare_scan_target``).
    for name, row in (_record(shell).get("declared") or {}).items():
        if row.get("target") and name not in names:
            names.append(name)
    return names


def origin_domains(shell: Any) -> list[str]:
    """The domains the scan targets (in scope unless this session excluded them).

    Includes the origins an earlier session recorded in ``scope.json``; those
    yield to an explicit exclusion decided in this session.
    """
    names = _session_origins(shell)
    for name in _record(shell)["rehydrated_origins"]:
        if name not in names:
            names.append(name)
    return names


def _known_domains(shell: Any) -> list[str]:
    """Every AD domain the session knows of, from recorded data only.

    A recorded forest root counts (``forest_topology.FOREST_KEY``): it is a real
    domain even when nothing of it was collected, and without it a host of the
    root (``ca.<root>``) seen from a child's records matched no known suffix and
    was attributed to the child, so the child's checks contacted it.
    """
    from adscan_internal.services.forest_topology import FOREST_KEY  # noqa: PLC0415

    known: list[str] = []
    domains_data = getattr(shell, "domains_data", None)
    if isinstance(domains_data, Mapping):
        known.extend(_norm(k) for k in domains_data.keys())
        for entry in domains_data.values():
            if isinstance(entry, Mapping) and entry.get(FOREST_KEY):
                known.append(_norm(entry.get(FOREST_KEY)))
    known.extend(_record(shell)["entries"].keys())
    known.extend(origin_domains(shell))
    return [d for d in domains_named(known) if d not in _PLACEHOLDERS]


# ── The verdict ────────────────────────────────────────────────────────────


def domain_scope_verdict(
    shell: Any, domain: str | None, *, path_domain: str | None = None
) -> ScopeVerdict:
    """Return whether ``domain`` is in the engagement scope (see module ladder)."""
    name = _norm(domain)
    if not name:
        return ScopeVerdict("", False, BASIS_UNDETERMINED)
    if name in _PLACEHOLDERS:
        return ScopeVerdict(name, True, BASIS_PLACEHOLDER)
    if name in _session_origins(shell):
        return ScopeVerdict(name, True, BASIS_ORIGIN)
    asset_state = getattr(shell, _ASSET_STATE_ATTR, None)
    if isinstance(asset_state, _AssetState) and asset_state.broken:
        # The asset scope of this record cannot be used (a damaged block, a
        # write that failed): the record is one thing, so nothing beyond the
        # scan's own target is in scope until it is recorded again.
        return ScopeVerdict(name, False, BASIS_RECORD_UNREADABLE)
    recorded = _record(shell)["entries"].get(name)
    if isinstance(recorded, Mapping):
        if recorded.get("in_scope") is True:
            return ScopeVerdict(name, True, BASIS_SELECTED)
        return ScopeVerdict(name, False, BASIS_EXCLUDED)
    if _record(shell).get("unreadable") or _record(shell).get("trust_record_lost"):
        # The recorded decision could not be read: nothing beyond the scan's
        # own target is assumed in scope, whatever the policy says.
        return ScopeVerdict(name, False, BASIS_RECORD_UNREADABLE)
    if name in _record(shell)["rehydrated_origins"]:
        return ScopeVerdict(name, True, BASIS_ORIGIN)
    if path_domain and name == _norm(path_domain):
        return ScopeVerdict(name, True, BASIS_PATH_DOMAIN)
    try:
        if policy_settings.expands_scope_automatically(shell):
            return ScopeVerdict(name, True, BASIS_POLICY_AUTOMATIC)
    except Exception as exc:  # noqa: BLE001 - unknown policy: not confirmed
        telemetry.capture_exception(exc)
    return ScopeVerdict(name, False, BASIS_NOT_CONFIRMED)


def domain_in_engagement_scope(
    shell: Any, domain: str | None, *, path_domain: str | None = None
) -> bool:
    """Boolean form of :func:`domain_scope_verdict`."""
    return domain_scope_verdict(shell, domain, path_domain=path_domain).in_scope


def _domain_from_dn(dn: Any) -> str:
    parts = _DN_DC.findall(str(dn or ""))
    return ".".join(p.strip().lower() for p in parts if p.strip())


def _longest_known_suffix(name: str, known: list[str]) -> str:
    best = ""
    for domain in known:
        if (name == domain or name.endswith("." + domain)) and len(domain) > len(best):
            best = domain
    return best


def object_domain(
    shell: Any,
    *,
    label: str | None,
    path_domain: str,
    dn: str | None = None,
    dnshostname: str | None = None,
) -> str | None:
    """The domain an attack-graph object belongs to, or ``None`` if undeterminable.

    Mirrors the step-domain SSOT (``attack_step_domain_resolution``): graph truth
    first (the object's distinguished name), then the label's realm, with a bare
    account name belonging to the route's own domain. On top of it, a dotted
    label or DNS host name (a computer, a domain object) is matched to the
    longest known domain suffix, so a host of the parent domain is never read as
    a host of the child the route was computed for.
    """
    from_dn = _domain_from_dn(dn)
    if from_dn:
        return from_dn
    known = _known_domains(shell)
    path = _norm(path_domain)
    text = str(label or "").strip()
    if "@" in text:
        realm = _norm(text.split("@", 1)[1])
        if not realm or realm in _PLACEHOLDERS:
            return path or None
        return _longest_known_suffix(realm, known) or realm
    if "\\" in text:
        netbios = _norm(text.split("\\", 1)[0])
        return _domain_for_netbios(shell, netbios, known)
    host = _norm(dnshostname)
    if host:
        matched = _longest_known_suffix(host, known)
        if matched:
            return matched
        return host.split(".", 1)[1] if "." in host else (path or None)
    lowered = _norm(text)
    if lowered and "." in lowered:
        matched = _longest_known_suffix(lowered, known)
        if matched:
            return matched
    return path or None


def _domain_for_netbios(shell: Any, netbios: str, known: list[str]) -> str | None:
    if not netbios:
        return None
    domains_data = getattr(shell, "domains_data", None)
    if isinstance(domains_data, Mapping):
        for name, data in domains_data.items():
            if not isinstance(data, Mapping):
                continue
            for key in ("netbios", "netbios_domain"):
                if _norm(data.get(key)) == netbios:
                    return _norm(name)
    for domain in known:
        if domain.split(".", 1)[0] == netbios:
            return domain
    return None


def step_scope_verdict(
    shell: Any,
    *,
    path_domain: str,
    from_label: str | None,
    to_label: str | None,
    details: Mapping[str, Any] | None = None,
) -> StepScopeVerdict:
    """Check one attack step on both axes: the acting object and the target."""
    details = details if isinstance(details, Mapping) else {}
    source_domain = object_domain(
        shell,
        label=from_label,
        path_domain=path_domain,
        dn=details.get("source_dn"),
        dnshostname=details.get("source_dnshostname"),
    )
    target_domain = object_domain(
        shell,
        label=to_label,
        path_domain=path_domain,
        dn=details.get("target_dn"),
        dnshostname=details.get("target_dnshostname"),
    )
    source = domain_scope_verdict(shell, source_domain, path_domain=path_domain)
    target = domain_scope_verdict(shell, target_domain, path_domain=path_domain)
    allowed = source.in_scope and target.in_scope
    if not allowed or _asset_state(shell) is None:
        return StepScopeVerdict(allowed=allowed, source=source, target=target)
    # The step carries what the graph knows about both objects (their kind,
    # SID, DN and DNS host name): the verdict reads those, never looks them up.
    target_asset = principal_scope_verdict(
        shell,
        principal=to_label,
        domain=target.domain,
        dn=details.get("target_dn"),
        sid=_step_sid(details.get("target_sid")),
        dnshostname=details.get("target_dnshostname"),
        kind=_step_kind(details.get("target_kind")),
        path_domain=path_domain,
    )
    source_asset = principal_scope_verdict(
        shell,
        principal=from_label,
        domain=source.domain,
        dn=details.get("source_dn"),
        sid=_step_sid(details.get("source_sid")),
        dnshostname=details.get("source_dnshostname"),
        kind=_step_kind(details.get("source_kind")),
        path_domain=path_domain,
    )
    return StepScopeVerdict(
        allowed=target_asset.allowed and source_asset.allowed,
        source=source,
        target=target,
        source_asset=source_asset,
        target_asset=target_asset,
    )


def _step_kind(value: Any) -> str | None:
    """A step's stamped node kind (``User``, ``GPO``...), ``None`` when unknown."""
    text = str(value or "").strip().lower()
    return None if text in ("", "unknown", "base") else text


def _step_sid(value: Any) -> str | None:
    text = str(value or "").strip()
    return text if text.upper().startswith("S-1-") else None


def step_scope_refusal_line(
    verdict: StepScopeVerdict, action: str, target: str, *, marked: bool = True
) -> str:
    """The operator line for a step the scope keeps out (domain or asset reason)."""
    asset = verdict.asset_refusal
    if asset is not None:
        return asset_refusal_line(action or "This step", target, asset, marked=marked)
    return outside_scope_line(action, target, verdict.out_of_scope_domain, marked=marked)


# ── Collection: which hosts a domain's collection may contact ──────────────

#: Collection host verdict reasons.
HOST_OWNED_BY_COLLECTING_DOMAIN = "owned_by_collecting_domain"
HOST_IN_OTHER_DOMAIN = "host_in_other_domain"
HOST_OUTSIDE_SCOPE = NOT_EXECUTED_OUTSIDE_SCOPE

#: Shell attribute holding the (collecting domain, host) pairs already announced.
_HOST_ANNOUNCED_ATTR = "_engagement_scope_host_announced"


@dataclass(frozen=True)
class CollectionHostVerdict:
    """Whether the collection of one domain may open a connection to a host.

    ``asset`` carries the asset verdict when the ASSET scope kept the host out
    (reason :data:`HOST_OUTSIDE_ASSET_SCOPE`).
    """

    host: str
    host_domain: str
    collecting_domain: str
    allowed: bool
    reason: str
    asset: "AssetScopeVerdict | None" = None


def _is_ip_literal(value: str) -> bool:
    import ipaddress  # noqa: PLC0415

    try:
        ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return False
    return True


def host_owner_domain(
    shell: Any,
    host: str | None,
    *,
    collecting_domain: str,
    host_dn: str | None = None,
) -> str:
    """The AD domain that owns ``host``, as seen from ``collecting_domain``'s data.

    Graph truth first: the host's distinguished name, when the caller has it.
    Otherwise its DNS name is matched to the longest KNOWN domain suffix, so a
    host of the parent domain is never read as a host of the child collecting
    it. A DNS name under no known domain (a disjoint DNS namespace), an IP
    literal or a bare name came from the collecting domain's own records and is
    attributed to it.
    """
    collecting = _norm(collecting_domain)
    from_dn = _domain_from_dn(host_dn)
    if from_dn:
        return from_dn
    name = _norm(host)
    if not name or "." not in name or _is_ip_literal(name):
        return collecting
    known = list(dict.fromkeys([*_known_domains(shell), *([collecting] if collecting else [])]))
    return _longest_known_suffix(name, known) or collecting


def collection_host_verdict(
    shell: Any,
    *,
    host: str | None,
    collecting_domain: str,
    host_dn: str | None = None,
    purpose: Any = None,
    contact: "Contact | None" = None,
) -> CollectionHostVerdict:
    """May the collection of ``collecting_domain`` connect to ``host``?

    ``contact`` describes what the collection opens there
    (:class:`Contact`); ``purpose`` is accepted for one release and ignored.

    The multi-domain flow collects every domain on its own, so a domain's
    collection opens connections ONLY to hosts that domain owns. A host owned by
    another domain is read when that domain is collected, and only if it is in
    the engagement scope; from here it stays mapped from directory data and is
    never contacted. Collecting a domain is itself the scope decision for its
    own hosts. The one exception, trust relationships, is read from the
    collecting domain's own DC and never reaches this check.

    An owned host the ASSET scope excludes is refused too
    (:data:`HOST_OUTSIDE_ASSET_SCOPE`), so every collection consumer of this
    seam inherits the deny- and allow-lists unchanged.
    """
    collecting = _norm(collecting_domain)
    owner = host_owner_domain(
        shell, host, collecting_domain=collecting, host_dn=host_dn
    )
    host_text = str(host or "").strip()
    if not owner or owner == collecting:
        asset = host_scope_verdict(
            shell,
            host=host_text,
            purpose=purpose,
            domain=owner or collecting,
            host_dn=host_dn,
            contact=contact,
        )
        if not asset.allowed:
            return CollectionHostVerdict(
                host_text, owner or collecting, collecting, False, HOST_OUTSIDE_ASSET_SCOPE, asset
            )
        return CollectionHostVerdict(
            host_text, owner or collecting, collecting, True, HOST_OWNED_BY_COLLECTING_DOMAIN
        )
    reason = (
        HOST_IN_OTHER_DOMAIN if domain_in_engagement_scope(shell, owner) else HOST_OUTSIDE_SCOPE
    )
    return CollectionHostVerdict(host_text, owner, collecting, False, reason)


def collection_host_skip_line(verdict: CollectionHostVerdict, what: str, *, marked: bool = True) -> str:
    """The operator line for a host a domain's collection did not contact."""
    from rich.markup import escape  # noqa: PLC0415

    def _m(value: str, kind: str) -> str:
        return mark_sensitive(escape(value), kind) if marked else escape(value)

    host = _m(verdict.host, "hostname")
    owner = _m(verdict.host_domain, "domain")
    collecting = _m(verdict.collecting_domain, "domain")
    if verdict.reason == HOST_OUTSIDE_ASSET_SCOPE and verdict.asset is not None:
        line = asset_refusal_line(what, verdict.host, verdict.asset, marked=marked)
        return line.replace(" not executed: ", " not checked: ", 1).rstrip(".") + (
            "; it stays mapped from directory data."
        )
    if verdict.reason == HOST_UNDETERMINED:
        tail = (
            "the domain of that host could not be determined, so it was not "
            "contacted; it stays mapped from directory data."
        )
    elif verdict.reason == HOST_OUTSIDE_SCOPE:
        tail = (
            f"{owner} is outside the engagement scope, so it was not contacted; "
            "it stays mapped from directory data."
        )
    else:
        tail = (
            f"it belongs to {owner}, so it is checked when that domain is "
            f"collected, not from {collecting}; it stays mapped from directory data."
        )
    return f"{escape(what)} on {host} not checked: {tail}"


def note_collection_host_skipped(
    shell: Any, verdict: CollectionHostVerdict, *, what: str
) -> None:
    """Announce a host the collection did not contact (once per domain and host)."""
    key = (verdict.collecting_domain, _norm(verdict.host), verdict.reason)
    announced = getattr(shell, _HOST_ANNOUNCED_ATTR, None)
    if not isinstance(announced, set):
        announced = set()
        try:
            setattr(shell, _HOST_ANNOUNCED_ATTR, announced)
        except Exception:  # noqa: BLE001
            pass
    first = key not in announced
    announced.add(key)
    if first:
        print_info(collection_host_skip_line(verdict, what))
    print_info_debug(
        "collection-host skip: "
        f"what={mark_sensitive(what, 'detail')} reason={verdict.reason} "
        f"host={mark_sensitive(verdict.host, 'hostname')} "
        f"owner={mark_sensitive(verdict.host_domain or '?', 'domain')} "
        f"collecting={mark_sensitive(verdict.collecting_domain, 'domain')}"
    )


# ── Linked SQL servers: the far side of a link is another host ──────────────

#: The linked server's host has no domain anyone can determine (an empty data
#: source, or a bare name or IP the inventory does not resolve): never
#: contacted, never assumed in scope.
HOST_UNDETERMINED = "host_domain_undetermined"

#: The domain whose collection is running in this context ("" outside one).
#: ``asyncio.to_thread`` and task creation copy it, so a collector's worker
#: threads see the domain they collect for.
_COLLECTING_DOMAIN: ContextVar[str] = ContextVar("adscan_collecting_domain", default="")

#: The session shell the MSSQL transport consults (dependency inversion: the
#: transport never receives a shell), held weakly so it ends with the session.
#: ``None`` outside a session (lab scripts, unit tests): there is no engagement
#: to hold a query to.
_SCOPE_SHELL_REF: Callable[[], Any] | None = None


@contextmanager
def collecting_domain_context(domain: str) -> Iterator[None]:
    """Mark the code inside as the collection of ``domain``."""
    token = _COLLECTING_DOMAIN.set(_norm(domain))
    try:
        yield
    finally:
        _COLLECTING_DOMAIN.reset(token)


def current_collecting_domain() -> str:
    """The domain being collected in this context, ``""`` outside a collection."""
    return _COLLECTING_DOMAIN.get()


def register_scope_shell(shell: Any) -> None:
    """Bind this session's shell to the transport seams that consult the scope."""
    import weakref  # noqa: PLC0415

    global _SCOPE_SHELL_REF, _EXIT_FLUSH_REGISTERED  # noqa: PLW0603 - one session per process
    _install_inbound_source_check(shell)
    if shell is None:
        _SCOPE_SHELL_REF = None
        set_scope_record_flusher(None)
        _sync_egress_guard()
        return
    try:
        _SCOPE_SHELL_REF = weakref.ref(shell)
    except TypeError:
        _SCOPE_SHELL_REF = lambda: shell  # noqa: E731 - unweakrefable double
    if not _EXIT_FLUSH_REGISTERED:
        # What the session counted and did not write yet (refusals, backstop
        # hits) is written when the process ends.
        _EXIT_FLUSH_REGISTERED = True
        atexit.register(_flush_at_exit)
    # A renderer of this process that reads scope.json gets what is pending.
    set_scope_record_flusher(_flush_for_reader)
    _sync_egress_guard()


_EXIT_FLUSH_REGISTERED = False


def _install_inbound_source_check(shell: Any) -> None:
    """Let the listener broker close connections from hosts the scope excludes.

    The broker's hook is installed by the inbound package; without it (a build
    that does not carry that package yet) there is nothing to install.
    """
    try:
        from adscan_internal.services import listener_broker  # noqa: PLC0415
    except Exception:  # noqa: BLE001 - the broker is optional for this module
        return
    install = getattr(listener_broker, "set_inbound_source_check", None)
    if not callable(install):
        return
    if shell is None:
        install(None)  # pylint: disable=not-callable
        return

    def _source_allowed(peer_ip: str) -> bool:
        # No recorded scope: one attribute read, everything is served.
        if _asset_state(shell) is None:
            return True
        return host_scope_verdict(shell, host=peer_ip, connect_address=peer_ip).allowed

    install(_source_allowed)  # pylint: disable=not-callable


def _scope_shell() -> Any:
    ref = _SCOPE_SHELL_REF
    return ref() if ref is not None else None


def _session(shell: Any) -> Any:
    """``shell``, or the registered session shell when the caller has none."""
    return shell if shell is not None else _scope_shell()


def linked_server_gate_active() -> bool:
    """Whether queries through a linked server are held to an engagement."""
    return _scope_shell() is not None


def linked_server_host(data_source: str | None) -> str:
    """The host a linked server's ``data_source`` names, without provider or instance.

    ``tcp:sql02.corp.example,1433`` and ``SQL02\\INST`` become ``sql02.corp.example``
    and ``sql02``. IPv6 literals are kept intact.
    """
    host = str(data_source or "").strip()
    if not host:
        return ""
    if ":" in host and host.count(":") == 1:
        prefix, _, rest = host.partition(":")
        if prefix.isalpha() and rest:
            host = rest
    host = host.split("\\", 1)[0].split(",", 1)[0]
    return host.strip().rstrip(".").lower()


#: Shell attribute caching the inventory index per domain and graph version.
_INVENTORY_ATTR = "_engagement_scope_inventory_index"

#: Verdict reason of a linked host the scope allows.
HOST_IN_SCOPE = "in_engagement_scope"


def _inventory_index(shell: Any, domain: str) -> Any:
    """The domain's computer inventory as the alias-aware asset index (cached).

    Built from the workspace ``attack_graph.json`` of ``domain`` through
    ``affected_assets_struct`` (sAMAccountName, name, DNS name, short name, IP),
    and rebuilt only when that file changes. ``None`` when there is none.
    """
    workspace = _workspace_dir(shell)
    name = _norm(domain)
    if not workspace or not name:
        return None
    path = os.path.join(workspace, "domains", name, "attack_graph.json")
    try:
        stamp = os.stat(path).st_mtime_ns
    except OSError:
        return None
    cache = getattr(shell, _INVENTORY_ATTR, None)
    if not isinstance(cache, dict):
        cache = {}
        try:
            setattr(shell, _INVENTORY_ATTR, cache)
        except Exception:  # noqa: BLE001 - a frozen double rebuilds every time
            pass
    cached = cache.get(name)
    if isinstance(cached, tuple) and cached[0] == stamp:
        return cached[1]
    try:
        from adscan_internal.services.affected_assets_struct import (  # noqa: PLC0415
            load_asset_index,
        )

        index = load_asset_index(workspace, name)
    except Exception as exc:  # noqa: BLE001 - unresolved stays undeterminable
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None
    cache[name] = (stamp, index)
    return index


def resolve_linked_server_host(
    shell: Any, host: str, *, inventory_domain: str | None
) -> tuple[str, str]:
    """Resolve a bare name or IP to ``(dns_name, domain)`` through an inventory.

    Looks the token up in ``inventory_domain``'s computer inventory, alias-aware
    (sAMAccountName, name, short name, IP). Only a directory object counts: a
    node with a distinguished name, whose domain is read from that DN (graph
    truth). A placeholder for a host seen only as a link target, or no match,
    returns ``("", "")``.
    """
    index = _inventory_index(shell, inventory_domain or "")
    if index is None:
        return "", ""
    node = index.lookup(host, f"{host}$")
    if node is None or str(getattr(node, "kind", "")).lower() != "computer":
        return "", ""
    owner = _domain_from_dn(getattr(node, "dn", ""))
    if not owner:
        return "", ""
    fqdn = _norm(getattr(node, "fqdn", "")) or _norm(getattr(node, "name", ""))
    return (fqdn if "." in fqdn else ""), owner


def linked_server_target_verdict(
    shell: Any,
    *,
    data_source: str | None,
    collecting_domain: str | None = None,
    prepare: bool = True,
) -> CollectionHostVerdict:
    """May a query run on the FAR side of a linked server whose data source is this?

    A query sent ``AT [link]`` or through ``OPENQUERY`` executes on the linked
    host and makes it accept a sign-in through the link, so it is a contact with
    that host. Reading the links of an instance (``sys.servers``) is not, and
    stays allowed like reading a trust.

    The engagement SCOPE decides, for a collection's read-only probes and for an
    attack step alike. Ownership does not: a linked server is reachable only
    through the instance that links to it, so no other domain's collection will
    ever probe it (the same reasoning as the trust exception).

    The host's domain comes from its DNS name (:func:`object_domain`). A bare
    name or an IP is resolved through ``collecting_domain``'s computer inventory
    (the domain whose instance holds the link), and a resolved host takes the
    domain of its directory object. Anything still unresolved has no
    determinable domain, and is neither in scope nor contacted.

    A COLLECTION-LEVEL seam, called once per link: this process never resolves
    a linked host's name itself (the SQL server contacts it), so nothing else
    could tell the session where it is. With ``prepare`` (the default) the
    linked host is looked up once (:func:`prepare_scope_targets`) before the
    asset verdict reads it. The per-query transport check passes
    ``prepare=False`` and only reads.
    """
    collecting = _norm(collecting_domain)
    host = linked_server_host(data_source)
    owner = ""
    if host and "." in host and not _is_ip_literal(host):
        owner = _norm(
            object_domain(shell, label=None, path_domain=collecting, dnshostname=host)
        )
    elif host:
        fqdn, owner = resolve_linked_server_host(shell, host, inventory_domain=collecting)
        host = fqdn or host
    if not owner:
        return CollectionHostVerdict(host, "", collecting, False, HOST_UNDETERMINED)
    if not domain_in_engagement_scope(shell, owner):
        return CollectionHostVerdict(host, owner, collecting, False, HOST_OUTSIDE_SCOPE)
    if prepare:
        prepare_scope_targets(shell, [host], domain=owner)
    asset = host_scope_verdict(shell, host=host, domain=owner)
    if not asset.allowed:
        return CollectionHostVerdict(host, owner, collecting, False, HOST_OUTSIDE_ASSET_SCOPE, asset)
    return CollectionHostVerdict(host, owner, collecting, True, HOST_IN_SCOPE)


def linked_server_query_refusal(
    *, data_source: str | None, inventory_domain: str | None = None
) -> CollectionHostVerdict | None:
    """The transport-level check for one query through a link (``None``: allowed).

    Consulted by the MSSQL transport for every query that names a linked server,
    whatever built it, so a new caller cannot reach past a link the scope keeps
    closed. ``inventory_domain`` is the domain whose inventory resolves a bare
    name or IP: the collecting domain inside a collection, else the domain of
    the instance holding the link. Without a session shell there is no
    engagement to hold the query to, and it runs.
    """
    shell = _scope_shell()
    if shell is None:
        return None
    verdict = linked_server_target_verdict(
        shell,
        data_source=data_source,
        collecting_domain=current_collecting_domain() or inventory_domain or None,
        prepare=False,
    )
    return None if verdict.allowed else verdict


def scope_entry(shell: Any, domain: str | None) -> Mapping[str, Any] | None:
    """The recorded trust-scope row for ``domain`` (``None`` when not recorded)."""
    row = _record(shell)["entries"].get(_norm(domain))
    return row if isinstance(row, Mapping) else None


# ── Asset scope: which hosts and accounts the scan may touch ────────────────
#
# How the engine is put together (binding for every later change):
#
# * A VERDICT IS A READ. ``host_scope_verdict``, ``principal_scope_verdict``,
#   ``partition_targets_in_scope``, ``require_host_in_scope`` and the egress
#   check read in-memory state only: the immutable matcher, the knowledge the
#   session was TOLD (name/address observations, directory facts) and
#   ``domains_data``. No directory read, no DNS query, no resolution pass, no
#   file write. Locked by a call-graph test.
# * KNOWLEDGE ARRIVES ON EXPLICIT TRIGGERS, each one a named function:
#   ``record_asset_scope`` / ``reload_asset_scope`` / ``rehydrate_engagement_scope``
#   (a scope recorded or loaded), ``on_directory_committed`` (a directory stage
#   committed), ``note_host_addresses`` (a resolver learned addresses),
#   ``prepare_scope_targets`` / ``prepare_scope_principals`` (a batch about to
#   be judged) and ``scope_checkpoint`` (a phase boundary).
# * A TARGET CAN BE READ SEVERAL WAYS (a bare name in each known domain, a
#   dotted label as an account or as a host, an address under every name it
#   was ever seen with). DENY asks every reading and refuses on any hit
#   (over-matching is safe). ALLOW must cover every reading that could be the
#   true one (under-matching is safe). A differential test against a naive
#   reference model checks exactly this direction.
# * THE RECORD IS WRITTEN IN BATCHES: refusals and backstop hits are counted in
#   memory and written by ``flush_engagement_scope`` (phase boundaries, exit, a
#   recorded decision), through one atomic writer under one lock.


class ScopeOutcome(Enum):
    """The three answers of an asset verdict. Only ALLOWED may be contacted."""

    ALLOWED = "allowed"
    REFUSED = "refused"
    UNDETERMINED = "undetermined"


class ContactPurpose(Enum):
    """Why a host is being contacted (the directory plane vs host assessment).

    A domain controller an allow-list does not name is used for the directory
    plane only (``dc_access = directory_only``): LDAP and the global catalogue,
    Kerberos and password change, DNS, time, and SYSVOL/NETLOGON reads.

    Never named by a caller: a seam describes what it opens with a
    :class:`Contact` and :func:`contact_purpose_for` derives the purpose.
    """

    DIRECTORY = "directory"
    NAME_RESOLUTION = "name_resolution"
    TIME = "time"
    DIRECTORY_SHARE = "directory_share"
    HOST = "host"


_DIRECTORY_PLANE = frozenset(
    {
        ContactPurpose.DIRECTORY,
        ContactPurpose.NAME_RESOLUTION,
        ContactPurpose.TIME,
        ContactPurpose.DIRECTORY_SHARE,
    }
)

#: Ports of the directory plane (kept for callers that list them; the purpose
#: of a contact is never read from 445, see :func:`contact_for_port`).
DIRECTORY_PLANE_PORTS = frozenset({53, 88, 123, 389, 445, 464, 636, 3268, 3269})

#: Protocols that are the directory plane by nature.
_DIRECTORY_PROTOCOLS = frozenset({"ldap", "ldaps", "gc", "gcs", "kerberos", "kpasswd"})

#: Every ``Contact.protocol`` string the derivation reads (lower case). Any
#: other string (``rpc``, ``winrm``, ``rdp``, ``mssql``, ``http``, ``dcom``,
#: a typo) is an ordinary host contact: it is never an error and never grants
#: the directory plane.
CONTACT_PROTOCOLS = frozenset({*_DIRECTORY_PROTOCOLS, "dns", "ntp", "smb"})
#: SMB shares that are part of the directory plane (domain-wide data every
#: member reads: Group Policy, logon scripts, GPP files).
DIRECTORY_SHARES = frozenset({"sysvol", "netlogon"})
#: Named pipes on IPC$ that are part of the directory plane. Kept short on
#: purpose: SAMR serves account and group reads and password change. Every
#: other pipe (lsarpc, efsrpc, spoolss, netdfs, netlogon, svcctl, winreg, atsvc,
#: FssagentRpc...) carries coercion, execution, registry or vulnerability-probe
#: interfaces, so it is a host contact.
DIRECTORY_PIPES = frozenset({"samr"})
#: The port a protocol of the directory plane is recognised by.
_PORT_PROTOCOLS = {
    53: "dns",
    88: "kerberos",
    123: "ntp",
    389: "ldap",
    464: "kpasswd",
    636: "ldaps",
    3268: "gc",
    3269: "gcs",
}

_UNC_SHARE = re.compile(r"^\\\\[^\\]+\\([^\\]+)$")
_PIPE_FORM = re.compile(r"^(?:\\pipe\\)?([^\\]+)$", re.IGNORECASE)


@dataclass(frozen=True)
class Contact:
    """WHAT a seam opens on a host: the facts of the operation, never a purpose.

    The engine derives the purpose from these facts (:func:`contact_purpose_for`),
    so the allowance a directory-only domain controller gets cannot be claimed
    by naming it. ``Contact()`` (nothing stated) is an ordinary host contact.

    Attributes:
        protocol: ``ldap``, ``ldaps``, ``gc``, ``gcs``, ``kerberos``,
            ``kpasswd``, ``dns``, ``ntp``, ``smb``; anything else is a host
            contact (``rpc``, ``winrm``, ``rdp``, ``mssql``, ``http``, ``dcom``).
        share: For SMB, the share being tree-connected: ``SYSVOL``, or its UNC
            form ``\\\\dc01.corp.example\\SYSVOL``. A path below a share is not
            a share.
        pipe: For SMB on ``IPC$``, the named pipe: ``samr`` or ``\\pipe\\samr``.
        write: The operation writes to the share (a file dropped in SYSVOL or
            NETLOGON changes what hosts run, so it is a host contact).
        negotiate_only: For SMB, a pre-authentication NEGOTIATE with no session
            (the clock read).
    """

    protocol: str = ""
    share: str | None = None
    pipe: str | None = None
    write: bool = False
    negotiate_only: bool = False


def contact_purpose_for(
    protocol: str,
    *,
    share: str | None = None,
    pipe: str | None = None,
    negotiate_only: bool = False,
    write: bool = False,
) -> ContactPurpose:
    """THE purpose of a contact, derived from what is actually opened.

    The single derivation. Exact forms only: anything it does not recognise is
    an ordinary host contact, and so is a path with extra components or parent
    references (``C$\\Windows\\SYSVOL``, ``ADMIN$\\..\\NETLOGON``,
    ``lsarpc\\samr``), and so is a WRITE to a directory share.

    Args:
        protocol: See :class:`Contact`.
        share: The share (``SYSVOL``, ``\\\\host\\NETLOGON``, ``IPC$``).
        pipe: The named pipe on ``IPC$`` (``samr``, ``\\pipe\\samr``).
        negotiate_only: An SMB NEGOTIATE with no session: a time contact.
        write: The operation writes to the share.

    Returns:
        DIRECTORY for LDAP, the global catalogue and Kerberos; NAME_RESOLUTION
        for DNS; TIME for NTP and an SMB NEGOTIATE; DIRECTORY_SHARE for an SMB
        READ of SYSVOL or NETLOGON; DIRECTORY for SMB to an IPC$ pipe in
        :data:`DIRECTORY_PIPES`; HOST for everything else.
    """
    proto = protocol.lower() if isinstance(protocol, str) else ""
    if proto in _DIRECTORY_PROTOCOLS:
        return ContactPurpose.DIRECTORY
    if proto == "dns":
        return ContactPurpose.NAME_RESOLUTION
    if proto == "ntp":
        return ContactPurpose.TIME
    if proto != "smb":
        return ContactPurpose.HOST
    if negotiate_only:
        if share or pipe or write:
            return ContactPurpose.HOST
        return ContactPurpose.TIME
    share_name = _share_name(share)
    if not share_name:
        return ContactPurpose.HOST
    if share_name in DIRECTORY_SHARES:
        if pipe or write:
            return ContactPurpose.HOST
        return ContactPurpose.DIRECTORY_SHARE
    if share_name == "ipc$" and isinstance(pipe, str):
        match = _PIPE_FORM.match(pipe)
        if match and match.group(1).lower() in DIRECTORY_PIPES:
            return ContactPurpose.DIRECTORY
    return ContactPurpose.HOST


def _share_name(share: Any) -> str:
    """The share an SMB tree connect names, ``""`` for anything that is not one."""
    if not isinstance(share, str) or not share:
        return ""
    text = share.replace("/", "\\")
    unc = _UNC_SHARE.match(text)
    name = unc.group(1) if unc else text
    if "\\" in name or name in (".", "..") or name != name.strip():
        return ""
    return name.lower()


def contact_for_port(port: Any) -> Contact:
    """The contact a bare TCP or UDP port describes (a probe primitive's case).

    A directory-plane protocol is recognised by its port. Port 445 alone says
    nothing about what will be opened, so it is an ordinary host contact: a
    seam that probes it ahead of a SYSVOL read passes
    ``Contact("smb", share="SYSVOL")`` itself.
    """
    try:
        number = int(port)
    except (TypeError, ValueError):
        return Contact()
    return Contact(_PORT_PROTOCOLS.get(number, ""))


def _over_smb(contact: Any) -> bool:
    """Whether a :class:`Contact` is opened over SMB."""
    return isinstance(contact, Contact) and str(contact.protocol or "").strip().lower() == "smb"


def _purpose_of(contact: Any) -> ContactPurpose:
    """The purpose of a :class:`Contact` (anything else: a host contact)."""
    if not isinstance(contact, Contact):
        return ContactPurpose.HOST
    return contact_purpose_for(
        contact.protocol,
        share=contact.share,
        pipe=contact.pipe,
        negotiate_only=bool(contact.negotiate_only),
        write=bool(contact.write),
    )


#: Legacy ``purpose=`` callers already told once (module names).
_LEGACY_PURPOSE_NOTED: set[str] = set()


def _legacy_purpose(value: Any, contact: Any) -> None:
    """A ``purpose=`` argument is accepted and IGNORED (one release).

    The purpose is derived from ``contact``; a caller that still names one is
    told once, at debug level, what to pass instead.
    """
    if value is None or contact is not None:
        return
    text = value.value if isinstance(value, ContactPurpose) else str(value).strip().lower()
    if text in ("", "host") or text in _LEGACY_PURPOSE_NOTED:
        return
    _LEGACY_PURPOSE_NOTED.add(text)
    print_info_debug(
        f"engagement-scope: a caller passed purpose={text!r}; it is ignored. "
        "Describe what is opened with contact=Contact(protocol, share=..., pipe=...)."
    )


#: Asset verdict reasons.
ASSET_REASON_ALLOWED = "allowed"
ASSET_REASON_DENIED = "denied_entry"
ASSET_REASON_NOT_IN_ALLOW = "not_in_allow_list"
ASSET_REASON_UNDETERMINED = "identity_undetermined"
ASSET_REASON_DOMAIN_OUTSIDE = "domain_outside_scope"
ASSET_REASON_DC_DIRECTORY_ONLY = "dc_directory_only"
#: The recorded asset scope could not be read back: nothing is contacted until
#: the operator records it again (fail closed).
ASSET_REASON_UNREADABLE = "scope_record_unreadable"

#: A change to an object whose effect reaches hosts (a GPO, an OU or container,
#: a certificate template or authority), while a host deny entry or a host
#: allow-list is in force and the hosts it reaches are not known to be all
#: inside the scope: not performed, and declared.
ASSET_REASON_AFFECTED_HOSTS_UNDETERMINED = "affected_hosts_undetermined"

#: Directory object kinds whose change reaches hosts.
HOST_REACHING_KINDS = frozenset(
    {
        "gpo",
        "ou",
        "container",
        "certtemplate",
        "enterpriseca",
        "rootca",
        "aiaca",
        "ntauthstore",
        "issuancepolicy",
    }
)
#: Of those, the kinds whose reach is the hosts BELOW them in the directory,
#: so it can be known from distinguished names.
_SUBTREE_KINDS = frozenset({"ou", "container"})
#: Kinds that are accounts (security principals): never host-reaching.
_ACCOUNT_KINDS = frozenset({"user", "group", "computer"})

#: How long evidence is trusted on the ALLOW side: a resolved allow name's
#: addresses, and an observed address of a named target judged against an
#: allow address entry. An allowed host's address moves with DHCP; after this
#: the evidence grants nothing until a trigger refreshes it.
_ALLOW_ADDRESS_TTL_SECONDS = 900.0

#: Collection host verdict reason of a host the asset scope keeps out.
HOST_OUTSIDE_ASSET_SCOPE = "outside_asset_scope"

#: Resolution statuses of one entry (persisted).
RESOLUTION_RESOLVED = "resolved"
RESOLUTION_PENDING = "pending"
RESOLUTION_AMBIGUOUS = "ambiguous"
RESOLUTION_UNRESOLVABLE = "unresolvable"

_ASSET_STATE_ATTR = "_engagement_scope_asset_state"
#: How many times a verdict is computed again when knowledge arrived from
#: another thread while it was being computed (the last answer is returned
#: uncached if it keeps moving).
_VERDICT_ATTEMPTS = 3
_VERDICT_CACHE_MAX = 200_000
_REFUSALS_MAX = 500
_REVISIONS_KEPT = 20
_NAME_ENTRY_TYPES = frozenset(
    {
        asset_model.TYPE_FQDN,
        asset_model.TYPE_SHORT_HOST,
        asset_model.TYPE_SID,
        asset_model.TYPE_DN,
        asset_model.TYPE_PRINCIPAL,
        asset_model.TYPE_UPN,
    }
)
_COMPUTER = asset_model.KIND_COMPUTER
_NEVER = float("inf")


class ScopeRecordWriteError(asset_model.ScopeSyntaxError):
    """The engagement scope could not be written to the workspace.

    Raised by :func:`record_asset_scope`: the run must not continue as if the
    scope were saved. The session is left refusing every host until a scope is
    recorded successfully.

    A subclass of ``ScopeSyntaxError`` so a handler written for a rejected
    scope still stops the run; it is NOT a mistake in what the operator wrote.
    A handler that words the error tells the two apart with
    ``isinstance(exc, ScopeRecordWriteError)`` (catch it first), or with
    ``getattr(exc, "is_write_failure", False)`` where it cannot import this
    module: the scope was valid, the workspace could not be written.
    """

    is_write_failure = True


@dataclass(frozen=True)
class AssetScopeVerdict:
    """Whether one host or directory object may be touched, and why.

    Attributes:
        outcome: ALLOWED, REFUSED or UNDETERMINED (refused as well).
        reason: One of the ``ASSET_REASON_*`` tokens.
        kind: ``computer``, ``user``, ``group``... or ``address`` for a bare IP.
        identity: What was known about the target when it was decided.
        entry_id: The entry that decided it (``d2``, ``a1``), ``""`` when none.
        cause: For UNDETERMINED, why the target could not be placed (the
            ``CAUSE_*`` tokens of ``adscan_core.reporting.engagement_scope``:
            ``name_not_resolved``, ``address_not_attributed``,
            ``entry_not_matched``, ``affected_hosts_unknown``,
            ``scope_record_unreadable``), ``""`` when none applies.
        domain: The domain the object belongs to, when known.

    REFUSED is an ESTABLISHED exclusion (a deny entry, an allow-list that does
    not list an established object, a domain outside the scope, a directory-only
    domain controller). Everything that could not be established is
    UNDETERMINED, with reason ``identity_undetermined`` (or
    ``scope_record_unreadable``): it is shown to the client as "could not be
    confirmed as in scope", never as an exclusion they asked for.
    """

    outcome: ScopeOutcome
    reason: str
    kind: str = ""
    identity: AssetIdentity | None = None
    entry_id: str = ""
    cause: str = ""
    domain: str = ""

    @property
    def allowed(self) -> bool:
        """Only ALLOWED may be contacted; UNDETERMINED is refused."""
        return self.outcome is ScopeOutcome.ALLOWED

    @property
    def label(self) -> str:
        """A human name for the target (FQDN, account, address)."""
        identity = self.identity
        if identity is None:
            return ""
        if identity.fqdn:
            return identity.fqdn
        if identity.samaccountname:
            return identity.samaccountname
        return identity.addresses[0] if identity.addresses else ""


_ALLOWED_NO_SCOPE = AssetScopeVerdict(ScopeOutcome.ALLOWED, ASSET_REASON_ALLOWED)


@dataclass
class ScopePartition:
    """Targets split by the asset scope (in input order on both sides)."""

    allowed: list[Any]
    refused: list[tuple[Any, AssetScopeVerdict]]

    @property
    def refused_items(self) -> list[Any]:
        """The refused targets without their verdicts."""
        return [item for item, _ in self.refused]


#: How long a name that resolved to nothing is not asked again.
_NEGATIVE_LOOKUP_TTL_SECONDS = 120.0

#: ``_Facts.kind`` of a host name the collected directory does not hold.
_NO_DIRECTORY_RECORD = "none"


@dataclass(frozen=True)
class _Facts:
    """Directory facts the session was told about one target (never looked up
    by a verdict): written by :func:`prepare_scope_targets` and
    :func:`prepare_scope_principals`."""

    kind: str = ""
    dn: str = ""
    sid: str = ""
    upn: str = ""
    fqdn: str = ""
    #: For a label several domains could answer to: the ones that hold it,
    #: once every one of them was read (``None``: not known).
    holders: tuple[str, ...] | None = None


@dataclass(frozen=True)
class _UnreadableScope(AssetScope):
    """What :func:`asset_scope` returns while the record cannot be read.

    Never ``None`` and never ``empty``: an unreadable record is not "no scope".
    """

    unreadable: bool = True
    problem: str = ""

    @property
    def empty(self) -> bool:  # type: ignore[override]
        return False


class _AssetState:
    """The live asset scope of one session: matcher, resolution, knowledge.

    The matcher is immutable and swapped by reference, and so is the resolution
    map (copy-on-write under ``pass_lock``), so a reader on another thread or
    event loop never sees either change under it. The verdict cache and the
    knowledge maps are guarded by a ``threading`` lock (never an asyncio
    primitive). Resolution passes are serialised by ``pass_lock``.

    Knowledge (written by explicit triggers, read by verdicts):

    * ``name_addrs`` / ``addr_names``: every (name, address) pair a resolver
      reported, with when it was last seen. The DENY side uses every pair ever
      seen (an address never un-learns); the ALLOW side only fresh ones.
    * ``facts``: directory facts about targets (DN, SID, kind, UPN).
    """

    def __init__(
        self,
        scope: AssetScope,
        resolution: dict[str, dict[str, Any]] | None = None,
        *,
        broken: bool = False,
        problem: str = "",
    ) -> None:
        self.scope = scope
        self.resolution: dict[str, dict[str, Any]] = dict(resolution or {})
        self.broken = broken
        self.problem = str(problem or "")
        self.version = 0
        self.kb_version = 0
        self.last_resolve = time.monotonic()
        self.last_due_check = time.monotonic()
        self._lock = threading.RLock()
        self.pass_lock = threading.RLock()
        self._cache: OrderedDict[tuple[Any, ...], tuple[Any, ...]] = OrderedDict()
        self.name_addrs: dict[str, dict[str, float]] = {}
        self.name_current: dict[str, frozenset[str]] = {}
        self.addr_names: dict[str, dict[str, float]] = {}
        self.facts: dict[tuple[str, ...], _Facts] = {}
        self.looked_up: dict[str, float] = {}
        #: host names learned whose directory record nobody read yet (drained
        #: by the triggers, never by a verdict)
        self.facts_wanted: set[str] = set()
        #: principal facts established while a domain that could hold the
        #: label had not been read: what they say is provisional, and they are
        #: established again once a directory commits (never left to stand).
        self.principals_unread: set[tuple[str, ...]] = set()
        self._gen: dict[str, int] = {}
        #: ``address -> ((version, address epoch), summary)``: what the names
        #: reported at one address say about it (:func:`_address_summary`).
        self._addr_memo: OrderedDict[str, tuple[tuple[int, int], Any]] = OrderedDict()
        #: host names a batch could not look up within its budget
        #: (``name -> domain``): the next trigger asks them, whoever calls it.
        self.lookup_backlog: dict[str, str] = {}
        #: the refresh the socket guard asked for when allow evidence lapsed
        self.wire_refresh: Any = None
        #: (name, address) pairs learned for DENIED names since the last fold
        #: into the persisted resolution.
        self._unfolded: list[tuple[str, str, str]] = []
        self.view: Any = None
        self.guard_fault = ""
        self.entries = {e.id: e for e in (*scope.allow, *scope.deny)}
        self.matcher = AssetMatcher.build(scope, self.identities())
        self._refresh_flags()

    # identities and flags

    def identities(self) -> dict[str, tuple[AssetIdentity, ...]]:
        """``entry id -> identities`` for the matcher (allow rows freshest first)."""
        out: dict[str, tuple[AssetIdentity, ...]] = {}
        rows = sorted(
            self.resolution.items(),
            key=lambda item: -float(item[1].get("_at") or 0.0),
        )
        for entry_id, row in rows:
            identities = tuple(
                i
                for i in (*(row.get("identities") or ()), *(row.get("provisional") or ()))
                if isinstance(i, AssetIdentity)
            )
            if identities:
                out[entry_id] = identities
        return out

    def rebuild(self) -> None:
        self.matcher = self.matcher.with_resolved(self.identities())
        self._refresh_flags()
        self.bump()

    def _refresh_flags(self) -> None:
        unattributed = False
        open_subtrees = False
        pending_sids = False
        pending_upns = False
        pending_names = False
        suffixes = False
        pending_accounts: set[str] = set()
        pending = 0
        located = True
        recheck_at = _NEVER
        ancestors: dict[str, str] = {}
        neighbourhoods: set[tuple[int, int]] = set()
        for entry in self.scope.deny:
            if entry.type in asset_model.ADDRESS_TYPES:
                located = False
                if entry.type == asset_model.TYPE_IP:
                    _add_neighbourhood(neighbourhoods, entry.value)
                continue
            if entry.type == asset_model.TYPE_DNS_SUFFIX:
                # Its hosts can never be listed: an address nobody attributed,
                # or a computer known only by SID or DN, may be one of them.
                located = False
                unattributed = True
                suffixes = True
                continue
            if entry.type not in _NAME_ENTRY_TYPES:
                continue
            row = self.resolution.get(entry.id) or {}
            status = row.get("status") or RESOLUTION_PENDING
            if status == RESOLUTION_PENDING:
                pending += 1
            identities = [i for i in row.get("identities") or () if isinstance(i, AssetIdentity)]
            for identity in identities:
                for address in identity.addresses:
                    _add_neighbourhood(neighbourhoods, address)
            if entry.type == asset_model.TYPE_UPN and status == RESOLUTION_PENDING:
                pending_upns = True
            if (status == RESOLUTION_PENDING or row.get("uncollected")) and entry.type in (
                asset_model.TYPE_FQDN,
                asset_model.TYPE_SHORT_HOST,
                asset_model.TYPE_PRINCIPAL,
            ):
                pending_names = True
            if status == RESOLUTION_PENDING and entry.type in (
                asset_model.TYPE_PRINCIPAL,
                asset_model.TYPE_UPN,
            ):
                domains = {i.domain for i in row.get("provisional") or () if i.domain}
                pending_accounts.update(domains or {"*"})
            if entry.type == asset_model.TYPE_DN:
                _add_dn_ancestors(ancestors, entry.value, entry.id)
                if not row.get("leaf"):
                    open_subtrees = True
                    continue
            if entry.type == asset_model.TYPE_SID and not identities and status == RESOLUTION_PENDING:
                pending_sids = True
            if not _entry_could_be_host(entry):
                continue
            if status != RESOLUTION_PENDING:
                recheck_at = min(
                    recheck_at, float(row.get("_checked") or 0.0) + _ALLOW_ADDRESS_TTL_SECONDS
                )
            # Where the denied host sits in the directory (for the hosts an OU
            # or container reaches): known once the entry resolved against a
            # collected directory.
            if status == RESOLUTION_PENDING or row.get("uncollected"):
                located = False
            for identity in identities:
                if identity.dn:
                    _add_dn_ancestors(ancestors, identity.dn, entry.id)
                elif identity.object_id:
                    located = False
            # A denied host whose addresses are unknown (pending, or not found in
            # the directory at all) keeps every unattributed address closed.
            if status == RESOLUTION_PENDING:
                # More holders of the name may exist in a domain not read yet.
                unattributed = True
            elif status == RESOLUTION_UNRESOLVABLE and not any(i.addresses for i in identities):
                unattributed = True
            elif any(i.kind in ("", _COMPUTER) and not i.addresses for i in identities):
                unattributed = True
        allow_open_subtrees = False
        allow_pending = False
        allow_always_open = False
        backed_until = _NEVER
        fresh_until: dict[str, float] = {}
        for entry in self.scope.allow:
            if entry.type == asset_model.TYPE_IP:
                _add_neighbourhood(neighbourhoods, entry.value)
            if entry.type == asset_model.TYPE_DNS_SUFFIX:
                allow_always_open = True
            if entry.type not in _NAME_ENTRY_TYPES:
                continue
            row = self.resolution.get(entry.id) or {}
            status = row.get("status") or RESOLUTION_PENDING
            identities = [i for i in row.get("identities") or () if isinstance(i, AssetIdentity)]
            expires = float(row.get("_at") or 0.0) + _ALLOW_ADDRESS_TTL_SECONDS if row.get("_at") else 0.0
            fresh_until[entry.id] = expires
            for identity in identities:
                for address in identity.addresses:
                    _add_neighbourhood(neighbourhoods, address)
            if entry.type == asset_model.TYPE_DN and not row.get("leaf"):
                allow_open_subtrees = True
            if status == RESOLUTION_PENDING:
                allow_pending = True
                pending += 1
            if _entry_could_be_host(entry) and not (
                entry.type == asset_model.TYPE_DN and not row.get("leaf")
            ):
                hosts = [i for i in identities if i.kind in ("", _COMPUTER)]
                if status == RESOLUTION_RESOLVED and hosts and all(i.addresses for i in hosts):
                    backed_until = min(backed_until, expires)
                elif status != RESOLUTION_RESOLVED or hosts:
                    # Named, with no address evidence: an unattributed address
                    # may be this host's.
                    allow_always_open = True
        self.deny_unattributed_hosts = unattributed
        self.deny_open_subtrees = open_subtrees
        self.deny_pending_sids = pending_sids
        self.deny_pending_upns = pending_upns
        #: A denied name (host or account) still waiting for the directory: a
        #: target known only by SID or DN may be it.
        self.deny_pending_names = pending_names
        #: A deny DNS-suffix entry exists (its hosts cannot be enumerated).
        self.deny_suffixes = suffixes
        #: Domains a pending deny ACCOUNT entry could live in (``*``: any). A
        #: ``name@realm`` label may be that account's UPN until it resolves.
        self.deny_pending_account_domains = frozenset(pending_accounts)
        self.deny_hosts_located = located
        #: When the oldest look at a resolved denied host's name is due again.
        self.deny_recheck_at = recheck_at
        self.deny_host_ancestors = ancestors
        self.allow_open_subtrees = allow_open_subtrees
        self.allow_pending = allow_pending
        self.allow_always_open = allow_always_open or allow_open_subtrees or allow_pending
        self.allow_backed_until = backed_until
        self.allow_fresh_until = fresh_until
        self.pending_count = pending
        self.neighbourhoods = neighbourhoods

    @property
    def needs_target_directory(self) -> bool:
        """Whether a verdict needs the target's DN or SID to decide."""
        return (
            self.deny_open_subtrees
            or self.allow_open_subtrees
            or self.deny_pending_sids
            or self.deny_unattributed_hosts
        )

    @property
    def has_pending(self) -> bool:
        """Entries still pending (O(1))."""
        return self.pending_count > 0

    def allow_evidence_stale(self, now: float) -> bool:
        """Whether some resolved allow name's addresses are past their evidence."""
        return any(0.0 < expires <= now for expires in self.allow_fresh_until.values())

    def allow_names_unbacked(self, now: float) -> bool:
        """Whether an unattributed address may be an allowed NAME's host.

        True while a host allow entry is a suffix, an open subtree, pending, or
        resolved without fresh addresses.
        """
        return self.allow_always_open or now >= self.allow_backed_until

    # cache

    def bump(self) -> None:
        with self._lock:
            self.version += 1
            self._cache.clear()
            self._addr_memo.clear()

    def _touch_addresses_of(self, name: str) -> None:
        """Move the epoch of every address ``name`` was reported at (lock held).

        What is known about an address is what is known about the names
        reported there, so a change to one name (a new address, a new latest
        report, its directory record) is a change to each of its addresses. A
        verdict then depends on the epoch of the addresses it read, never on
        each co-located name.
        """
        for address in self.name_addrs.get(name) or ():
            key = "@" + address
            self._gen[key] = self._gen.get(key, 0) + 1

    def gen(self, key: str) -> int:
        return self._gen.get(key, 0)

    def cache_get(self, key: tuple[Any, ...]) -> AssetScopeVerdict | None:
        with self._lock:
            hit = self._cache.get(key)
            if hit is None:
                return None
            version, expires, deps, verdict = hit
            if (
                version != self.version
                or time.monotonic() >= expires
                or any(self._gen.get(name, 0) != seen for name, seen in deps)
            ):
                self._cache.pop(key, None)
                return None
            self._cache.move_to_end(key)
            return verdict

    def cache_put(
        self,
        key: tuple[Any, ...],
        version: int,
        verdict: AssetScopeVerdict,
        *,
        expires: float = _NEVER,
        deps: tuple[tuple[str, int], ...] = (),
    ) -> None:
        with self._lock:
            if version != self.version:
                return
            self._cache[key] = (version, expires, deps, verdict)
            self._cache.move_to_end(key)
            while len(self._cache) > max(1, int(_VERDICT_CACHE_MAX)):
                self._cache.popitem(last=False)

    def cache_put_if_current(
        self,
        key: tuple[Any, ...],
        version: int,
        verdict: AssetScopeVerdict,
        *,
        epoch: int,
        expires: float,
        names: Iterable[str],
    ) -> bool:
        """Cache a verdict ONLY when nothing was learned while it was computed.

        ``epoch`` is ``kb_version`` read BEFORE the computation. Under the
        knowledge lock (the one every report takes), the verdict is stored
        with the counters of the keys it read when the knowledge is still the
        one it was computed on. Returns False when it is not: the caller
        computes again.
        """
        with self._lock:
            if self.kb_version != epoch:
                return False
            deps = tuple((name, self._gen.get(name, 0)) for name in dict.fromkeys(names))
            self.cache_put(key, version, verdict, expires=expires, deps=deps)
            return True

    def cache_size(self) -> int:
        with self._lock:
            return len(self._cache)

    # knowledge

    def learn(self, name: str, addresses: Iterable[str]) -> list[str]:
        """Record that ``name`` was seen at ``addresses``; returns the NEW ones.

        Constant in the number of scope entries. Only the cached verdicts that
        read this name or these addresses are invalidated.
        """
        now = time.monotonic()
        new: list[str] = []
        reported = frozenset(addresses)
        with self._lock:
            seen = self.name_addrs.setdefault(name, {})
            for address in reported:
                if address not in seen:
                    new.append(address)
                seen[address] = now
                self.addr_names.setdefault(address, {})[name] = now
            self.looked_up[name] = now
            self.lookup_backlog.pop(name, None)
            if "." in name and ("h", name) not in self.facts:
                self.facts_wanted.add(name)
            if new or self.name_current.get(name) != reported:
                self.name_current[name] = reported
                self._gen[name] = self._gen.get(name, 0) + 1
                self._touch_addresses_of(name)
                self.kb_version += 1
        return new

    def addresses_of(self, name: str) -> dict[str, float]:
        """Every address ``name`` was EVER reported at (the deny side)."""
        with self._lock:
            return dict(self.name_addrs.get(name) or ())

    def current_of(self, name: str) -> frozenset[str]:
        """The addresses of the LATEST report for ``name`` (the allow side)."""
        with self._lock:
            return self.name_current.get(name) or frozenset()

    def names_of(self, address: str) -> dict[str, float]:
        with self._lock:
            return dict(self.addr_names.get(address) or ())

    def reported_within(self, address: str, names: Iterable[str], since: float) -> list[float]:
        """When each of ``names`` was last reported at ``address``, for the
        ones reported at or after ``since`` (no copy of the address's names)."""
        with self._lock:
            reports = self.addr_names.get(address) or {}
            return [when for when in (reports.get(name) for name in names) if when is not None and when >= since]

    def set_facts(self, key: tuple[str, ...], facts: _Facts) -> None:
        with self._lock:
            if self.facts.get(key) == facts:
                return
            self.facts[key] = facts
            tag = "#" + "|".join(key)
            self._gen[tag] = self._gen.get(tag, 0) + 1
            if key[0] == "h" and len(key) > 1:
                self._touch_addresses_of(key[1])
            self.kb_version += 1

    def adopt_knowledge(self, other: "_AssetState") -> None:
        """Carry what an earlier revision of the scope learned into this one."""
        with other._lock:  # noqa: SLF001
            self.name_addrs = {k: dict(v) for k, v in other.name_addrs.items()}
            self.name_current = dict(other.name_current)
            self.addr_names = {k: dict(v) for k, v in other.addr_names.items()}
            self.facts = dict(other.facts)
            self.looked_up = dict(other.looked_up)
            self.facts_wanted = set(other.facts_wanted)
            self.principals_unread = set(other.principals_unread)
            self.lookup_backlog = dict(other.lookup_backlog)
            self.kb_version = other.kb_version + 1


def _add_neighbourhood(into: set[tuple[int, int]], address: Any) -> None:
    """Note the /24 (IPv4) or /64 (IPv6) around a PUBLIC engagement address."""
    try:
        addr = asset_model.unmap_address(ipaddress.ip_address(str(address).strip().strip("[]")))
    except ValueError:
        return
    if addr.is_global:
        into.add(_neighbourhood(addr))


def _neighbourhood(addr: Any) -> tuple[int, int]:
    return (addr.version, int(addr) >> (8 if addr.version == 4 else 64))


def _add_dn_ancestors(into: dict[str, str], dn: str, entry_id: str) -> None:
    """Index every container ABOVE ``dn`` (it then holds an excluded host)."""
    parts = [p.strip() for p in asset_model._split_dn(str(dn or ""))]  # noqa: SLF001
    for index in range(1, len(parts)):
        into.setdefault(",".join(parts[index:]).casefold(), entry_id)


def _entry_could_be_host(entry: asset_model.ScopeEntry) -> bool:
    """Whether an entry may name a computer (so its addresses matter)."""
    if entry.type in (asset_model.TYPE_FQDN, asset_model.TYPE_SHORT_HOST):
        return True
    if entry.type == asset_model.TYPE_PRINCIPAL:
        return entry.kind == _COMPUTER or entry.value.endswith("$")
    if entry.type == asset_model.TYPE_UPN:
        return entry.kind == _COMPUTER
    return entry.kind in ("", _COMPUTER)


def _asset_state(shell: Any) -> _AssetState | None:
    """The session's asset state, ``None`` when no asset scope is recorded."""
    state = getattr(shell, _ASSET_STATE_ATTR, None) if shell is not None else None
    return state if isinstance(state, _AssetState) else None


def _set_asset_state(shell: Any, state: _AssetState | None) -> None:
    try:
        setattr(shell, _ASSET_STATE_ATTR, state)
    except Exception:  # noqa: BLE001 - a frozen double has no asset scope
        pass
    _sync_egress_guard()


def _bump_asset_version(shell: Any) -> None:
    """Invalidate cached verdicts (the domain scope or the learned data changed)."""
    state = _asset_state(shell)
    if state is not None:
        state.bump()


def asset_scope(shell: Any) -> AssetScope | None:
    """The asset scope this session runs under, ``None`` when there is none.

    While the record cannot be read the answer is neither ``None`` nor an empty
    scope: it is an object whose ``unreadable`` attribute is true and whose
    ``empty`` is false (see :func:`asset_scope_unreadable`).
    """
    state = _asset_state(shell)
    if state is None:
        return None
    if state.broken:
        return _UnreadableScope(problem=state.problem)
    return state.scope


def invalidate_scope_verdicts(shell: Any = None) -> None:
    """Drop every cached verdict of the session (and the socket guard's passes).

    THE call for anything that changes what a verdict depends on without
    going through the engine: the scan policy replaced mid-session, the trust
    scope edited outside :func:`record_trust_scope_decision`, ``domains_data``
    rewritten in place. (The engine's own changes, a recorded scope, a trust
    decision, a learned address, already do it.) ``shell=None`` uses the
    registered session. Cheap: the next verdict of each target is computed
    once.
    """
    shell = _session(shell)
    state = _asset_state(shell)
    if state is None:
        return
    state.view = None
    state.bump()


def asset_scope_recorded(shell: Any = None) -> bool:
    """Whether this session runs under an asset scope (readable or not).

    ``shell=None`` falls back to the registered session. For a seam that
    cannot attribute its peer to a host (a link-local IPv6 client with no name)
    and therefore has to stay silent as soon as ANY asset scope exists.
    """
    return _asset_state(_session(shell)) is not None


def _ip_text(value: Any) -> str:
    try:
        text = str(value or "").strip().strip("[]").partition("%")[0]
        return str(asset_model.unmap_address(ipaddress.ip_address(text)))
    except ValueError:
        return ""


# ── Directory and name lookups (ONLY the explicit triggers read through these) ─
#
# A verdict never calls anything in this block: ``_directory_objects``,
# ``_name_addresses`` and ``_principal_kind`` are the three lookup seams, and
# they are reached from resolution passes and the ``prepare_*`` triggers only
# (locked by ``test_engagement_scope_readonly.py``).


def _identity_from_record(shell: Any, record: Any) -> AssetIdentity:
    kind = str(getattr(record, "kind", "") or "").strip().lower()
    props = getattr(record, "properties", None) or {}
    domain = _norm(getattr(record, "domain", ""))
    fqdn = _norm(props.get("dnshostname")) if isinstance(props, Mapping) else ""
    if not fqdn and kind == _COMPUTER:
        fqdn = _norm(getattr(record, "name", ""))
    upn = _norm(props.get("userprincipalname")) if isinstance(props, Mapping) else ""
    return AssetIdentity(
        kind=kind,
        object_id=str(getattr(record, "object_id", "") or "").upper(),
        domain=domain,
        dn=str(getattr(record, "distinguished_name", "") or ""),
        fqdn=fqdn,
        samaccountname=str(getattr(record, "samaccountname", "") or "").lower(),
        netbios=_netbios_of(shell, domain),
        upn=upn,
    )


def _identity_from_index_node(shell: Any, node: Any, domain: str) -> AssetIdentity:
    kind = str(getattr(node, "kind", "") or "").strip().lower()
    dn = str(getattr(node, "dn", "") or "")
    owner = _domain_from_dn(dn) or _norm(domain)
    ip = _ip_text(getattr(node, "ip", ""))
    return AssetIdentity(
        kind=kind,
        object_id=str(getattr(node, "sid", "") or "").upper(),
        domain=owner,
        dn=dn,
        fqdn=_norm(getattr(node, "fqdn", "")),
        samaccountname=str(getattr(node, "samaccountname", "") or "").lower(),
        netbios=_netbios_of(shell, owner),
        upn=_norm(getattr(node, "upn", "")),
        addresses=(ip,) if ip else (),
    )


def _directory_objects(
    shell: Any,
    domain: str,
    *,
    name: str = "",
    dn: str = "",
    sam: str = "",
    sid: str = "",
) -> list[AssetIdentity] | None:
    """Directory objects of ``domain`` matching ONE indexed query.

    Reads the domain's graph store through its indexed lookups
    (``get_object`` / ``find_objects``), never by iterating the directory. A
    workspace without a store (14.0.x) falls back to the cached asset index of
    its ``attack_graph.json``. ``None`` when the domain has not been collected
    (nothing to read yet), ``[]`` when it has and nothing matches.
    """
    name_key = _norm(domain)
    if not name_key:
        return None
    try:
        from adscan_internal.services.graph_runtime import graph_store_for  # noqa: PLC0415

        store = graph_store_for(shell, name_key, create=False)
    except Exception as exc:  # noqa: BLE001 - an unreadable store is not collected
        print_info_debug(f"engagement-scope directory: store unavailable ({type(exc).__name__})")
        store = None
    if store is not None:
        try:
            if sid:
                found = store.get_object(sid)
                records = [found] if found is not None else []
            else:
                records = store.find_objects(
                    name=name, distinguished_name=dn, samaccountname=sam
                )
            if not records and not _directory_objects_complete(store):
                # The directory objects of this domain are not fully read yet
                # (none, running, stopped): a miss is not an answer.
                return None
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            return None
        return [_identity_from_record(shell, record) for record in records]
    index = _inventory_index(shell, name_key)
    if index is None:
        return None
    token = sid or sam or name
    if not token:
        return []
    node = index.lookup(token)
    if node is None:
        return []
    identity = _identity_from_index_node(shell, node, name_key)
    if dn and _norm(identity.dn) != _norm(dn):
        return []
    return [identity]


def _directory_objects_complete(store: Any) -> bool:
    """Whether the store's ``ldap_objects`` stage committed completely."""
    from adscan_core.graph_store.records import STAGE_LDAP_OBJECTS  # noqa: PLC0415

    return any(
        getattr(run, "stage", "") == STAGE_LDAP_OBJECTS and getattr(run, "status", "") == "complete"
        for run in store.stage_runs() or ()
    )


# ── What the operator named for this run, and the name servers it gives ──────


def declare_scan_target(
    shell: Any,
    *,
    domain: str | None,
    dc_ip: str | None = None,
    dns_server: str | None = None,
    target: bool | None = True,
) -> bool:
    """Tell the session what the operator named for this run, before any data.

    ``ci`` and ``start`` know the target domain, a domain controller of it
    (``--dc-ip``) and, optionally, its name server (``--dns-server``) before
    ``domains_data`` holds any of them. The scope is recorded and checked in
    that window, so without this the session could neither recognise the
    controller the operator named (it judged it as an address nobody
    attributed) nor ask the domain's own name server about the scope's names.

    The declaration grants nothing the recorded fields would not grant a
    moment later: the address is a domain controller of ``domain`` exactly as
    ``domains_data[domain]["dc_ip"]`` makes it one. Deny still wins, over the
    address and over every name later learned for it. Kept in memory only.

    An EXPLICIT trigger: when the declaration is new and entries are still
    pending, they are resolved again here (the declaration may be the first
    name server the session can ask), so a deny name that IS the controller is
    found before anything else is sent.

    Args:
        target: ``domain`` is the domain this run targets (in scope as the
            scan's own origin). ``False`` for a candidate controller of a
            domain whose scope is decided elsewhere; ``None`` decides it: the
            first domain a session with no target yet names a controller for
            is its target.

    Returns:
        True when the declaration added something the session did not hold.
    """
    if target is None:
        target = not _session_origins(shell)
    if not _declare_target(shell, domain=domain, dc_ip=dc_ip, dns_server=dns_server, target=target):
        return False
    state = _asset_state(shell)
    if state is not None and not state.broken and state.has_pending:
        resolve_asset_scope(shell, pending_only=True)
    return True


def _declare_target(
    shell: Any,
    *,
    domain: str | None,
    dc_ip: str | None = None,
    dns_server: str | None = None,
    target: bool = False,
) -> bool:
    """Record the declaration in memory (no lookup, no pass, no write)."""
    name = _norm(domain)
    if not name:
        return False
    record = _record(shell)
    declared = record["declared"]
    row = declared.get(name) or {"target": False, "dc": (), "dns": ""}
    before = (bool(row.get("target")), tuple(row.get("dc") or ()), row.get("dns") or "")
    address = _ip_text(dc_ip)
    controllers = tuple(row.get("dc") or ())
    if address and address not in controllers:
        controllers = (*controllers, address)
    resolver = _ip_text(dns_server) or (row.get("dns") or "")
    row = {"target": bool(row.get("target")) or bool(target), "dc": controllers, "dns": resolver}
    if (row["target"], row["dc"], row["dns"]) == before:
        return False
    with _RECORD_LOCK:
        declared[name] = row
    return True


def _declared_name_servers(shell: Any, domain: str | None) -> list[str]:
    """The name servers the operator's declaration gives for ``domain``.

    ``--dns-server`` first, then the declared domain controller (a domain
    controller serves its domain's zone); the run's target domain stands in
    for a domain nothing was declared for. A server a deny entry names by
    address, or that a denied name already resolved to, is never asked.
    """
    declared = _record(shell).get("declared") or {}
    if not declared:
        return []
    key = _norm(domain)
    rows = [declared[key]] if key in declared else []
    rows.extend(row for name, row in declared.items() if name != key and row.get("target"))
    state = _asset_state(shell)
    matcher = state.matcher if state is not None and not state.broken else None
    out: list[str] = []
    for row in rows:
        for address in (row.get("dns") or "", *(row.get("dc") or ())):
            if not address or address in out:
                continue
            if matcher is not None and matcher.deny_address_entry(address):
                continue
            out.append(address)
    return out


@dataclass(frozen=True)
class NameAnswer:
    """What one name server said about one name.

    ``answered`` is False when nothing came back in time (the server is not a
    name server, or is not reachable): the name is then not known to be
    absent. An answer with no address is "no such name".
    """

    addresses: tuple[str, ...] = ()
    answered: bool = False


#: How long one name lookup may take. A DNS query is one round trip; this
#: leaves room for a slow link without letting a dead resolver hold the run.
_NAME_LOOKUP_SECONDS = 4.0
#: The key of the system resolver in ``silent_name_servers``.
_SYSTEM_RESOLVER = ""


def _ask_name_server(name: str, server: str, timeout: float) -> NameAnswer:
    """Ask ``server`` (an address) for the A records of ``name``: THE resolver seam.

    One DNS question to one server, bounded by ``timeout``. A DNS query to the
    engagement's name server is not host traffic. Never raises.
    """
    try:
        import dns.exception  # noqa: PLC0415
        import dns.resolver  # noqa: PLC0415

        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [server]
        resolver.timeout = timeout
        resolver.lifetime = timeout
        try:
            answers = resolver.resolve(str(name).rstrip("."), "A", search=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return NameAnswer((), True)
        except dns.exception.DNSException:
            return NameAnswer((), False)
        found = tuple(dict.fromkeys(a for a in (_ip_text(str(answer)) for answer in answers) if a))
        return NameAnswer(found, True)
    except Exception as exc:  # noqa: BLE001 - nothing learned is "no answer"
        telemetry.capture_exception(exc)
        print_info_debug(f"engagement-scope name server query failed: {type(exc).__name__}")
        return NameAnswer((), False)


def _within(seconds: float, call: Callable[[], Any]) -> tuple[Any, bool]:
    """``(result, finished)`` of ``call`` run for at most ``seconds``.

    The call runs on a daemon thread; one that has not finished is left behind
    (a resolver library call cannot be cancelled) and its result is dropped.
    The bound holds whatever the call does, so no pass waits on a resolver.
    """
    box: list[Any] = []

    def _run() -> None:
        try:
            box.append(call())
        except Exception as exc:  # noqa: BLE001 - a lookup that failed answered nothing
            telemetry.capture_exception(exc)
            box.append(None)

    worker = threading.Thread(target=_run, name="scope-name-lookup", daemon=True)
    worker.start()
    worker.join(max(0.0, seconds))
    if worker.is_alive() or not box:
        return None, False
    return box[0], True


def _name_server_silent(shell: Any, server: str, now: float) -> bool:
    since = (_record(shell).get("silent_name_servers") or {}).get(server)
    return since is not None and now - since < _NEGATIVE_LOOKUP_TTL_SECONDS


def _note_name_server_silent(shell: Any, server: str, now: float) -> None:
    """A name server that did not answer is not asked again for a while, so a
    list of names costs one wait, not one per name. Said once per window."""
    _record(shell)["silent_name_servers"][server] = now
    subject = f"The name server {mark_sensitive(server, 'ip')}" if server else "The system resolver"
    print_warning(
        f"Engagement scope: {subject} did not answer within "
        f"{_NAME_LOOKUP_SECONDS:.0f} s. The names it was asked stay unresolved; "
        "they are looked up again at the next phase."
    )


def scope_name_servers_asked(shell: Any = None) -> list[str]:
    """The engagement name servers this session sent a DNS question to."""
    shell = _session(shell)
    if shell is None:
        return []
    return list(_record(shell).get("name_servers_asked") or ())


def _name_addresses(shell: Any, host: str, domain: str | None) -> list[str]:
    """Every address the session knows for ``host``, without contacting it.

    The workspace inventory, the reachability report and a DNS query (a DNS
    query is not host traffic). Never a live probe, never an operator prompt.

    Which resolver: the one recorded for the domain (``dns_server``), else the
    ones the operator named for this run (:func:`_declared_name_servers`:
    ``--dns-server``, then the declared domain controller), else the system
    resolver. Each question is bounded (:data:`_NAME_LOOKUP_SECONDS`) and a
    resolver that did not answer is left alone for a while, so a pass never
    waits on a resolver that is not there.
    """
    try:
        from adscan_internal.models.domain import resolve_dns_server  # noqa: PLC0415
        from adscan_internal.services import host_address_resolver as har  # noqa: PLC0415

        name = str(host)
        owner = _norm(domain)
        found: list[str] = []

        def _add(addresses: Iterable[Any]) -> None:
            for address in addresses or ():
                text = _ip_text(address)
                if text and text not in found:
                    found.append(text)

        _add(har._inventory_candidate_ips(shell, domain=owner, host=name))  # noqa: SLF001
        _add(har._reachability_candidate_ips(shell, domain=owner, host=name))  # noqa: SLF001
        domains_data = getattr(shell, "domains_data", None) or {}
        data = domains_data.get(owner) if isinstance(domains_data, Mapping) else None
        recorded = resolve_dns_server(data) if isinstance(data, dict) else None
        now = time.monotonic()
        if not recorded:
            asked = _record(shell)["name_servers_asked"]
            for server in _declared_name_servers(shell, owner):
                if _name_server_silent(shell, server, now):
                    continue
                if server not in asked:
                    asked.append(server)
                answer, finished = _within(
                    _NAME_LOOKUP_SECONDS + 0.5,
                    lambda server=server: _ask_name_server(name, server, _NAME_LOOKUP_SECONDS),
                )
                if not finished or not isinstance(answer, NameAnswer) or not answer.answered:
                    _note_name_server_silent(shell, server, time.monotonic())
                    continue
                _add(answer.addresses)
                if answer.addresses or (owner and _norm(name).endswith("." + owner)):
                    # The domain's own name server answered for a name of that
                    # domain: its answer stands, "no such name" included.
                    return found
        if _name_server_silent(shell, _SYSTEM_RESOLVER, now):
            return found
        answer, finished = _within(
            _NAME_LOOKUP_SECONDS,
            lambda: har._dns_candidate_ips(name, recorded),  # noqa: SLF001
        )
        if not finished:
            _note_name_server_silent(shell, _SYSTEM_RESOLVER, time.monotonic())
            return found
        _add(answer)
        return found
    except Exception as exc:  # noqa: BLE001 - nothing learned is an empty answer
        telemetry.capture_exception(exc)
        print_info_debug(f"engagement-scope name lookup failed: {type(exc).__name__}")
        return []


def _principal_kind(shell: Any, domain: str, label: str) -> str:
    """The kind of a principal from DIRECTORY data, never from its name's shape.

    Indexed evidence only, so a list of thousands of accounts never costs a
    walk of the graph per account: what the label itself proves when it is a
    SID, then the membership snapshot's per-kind sets. The directory record
    (one indexed query) is read by the caller, :func:`prepare_scope_principals`.
    """
    try:
        from adscan_internal.services.membership_snapshot import (  # noqa: PLC0415
            load_membership_snapshot,
        )
        from adscan_internal.services.principal_kind import (  # noqa: PLC0415
            principal_kind_from_sid,
            principal_kind_from_snapshot,
        )

        kind = principal_kind_from_sid(str(label or "").split("@", 1)[0])
        if kind:
            return str(kind).lower()
        return str(
            principal_kind_from_snapshot(load_membership_snapshot(shell, domain), domain, label) or ""
        ).lower()
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return ""


def _netbios_of(shell: Any, domain: str) -> str:
    domains_data = getattr(shell, "domains_data", None)
    if isinstance(domains_data, Mapping):
        data = domains_data.get(_norm(domain))
        if isinstance(data, Mapping):
            for key in ("netbios", "netbios_domain"):
                if data.get(key):
                    return _norm(data.get(key))
    return ""


def _domain_sid_of(shell: Any, domain: str) -> str:
    domains_data = getattr(shell, "domains_data", None)
    if isinstance(domains_data, Mapping):
        data = domains_data.get(_norm(domain))
        if isinstance(data, Mapping):
            for key in ("domain_sid", "sid"):
                value = str(data.get(key) or "").strip()
                if value.upper().startswith("S-1-"):
                    return value.upper()
    return ""


def _in_scope_domains(shell: Any) -> list[str]:
    return [d for d in _known_domains(shell) if domain_in_engagement_scope(shell, d)]


# ── The session's domains and directory servers, as one cached view ──────────

#: Roles of a directory-plane server.
_ROLE_DC = "dc"
_ROLE_DNS = "dns"

_VIEW_FIELDS = (
    "dc_ip",
    "pdc",
    "pdc_hostname",
    "pdc_hostname_fqdn",
    "pdc_fqdn",
    "dc_fqdn",
    "dns_server",
    "netbios",
    "netbios_domain",
    "forest_dns_name",
    "domain_sid",
    "sid",
)


@dataclass(frozen=True)
class _DomainView:
    """What ``domains_data`` and the record say about domains and their servers.

    Built once and reused until one of the fields it reads changes (a cheap
    fingerprint, proportional to the number of DOMAINS, never to hosts or scope
    entries), so a verdict does not rebuild the domain-controller list.
    """

    fingerprint: tuple[Any, ...]
    known: tuple[str, ...]
    netbios: Mapping[str, tuple[str, ...]]
    netbios_of: Mapping[str, str]
    without_netbios: tuple[str, ...]
    by_ip: Mapping[str, tuple[tuple[str, tuple[str, ...], str], ...]]
    by_fqdn: Mapping[str, tuple[tuple[str, tuple[str, ...], str], ...]]
    by_short: Mapping[str, tuple[tuple[str, tuple[str, ...], str], ...]]
    public_server_nets: frozenset[tuple[int, int]]
    #: recorded domain SID -> domain (a SID says which domain its object is in)
    domain_of_sid: Mapping[str, str] = field(default_factory=dict)
    #: the domains with a recorded directory server that are inside the domain
    #: scope (the fingerprint covers every answer this is built from)
    server_domains_in_scope: frozenset[str] = frozenset()

    def sid_domain(self, sid: str) -> str:
        """The domain an object SID belongs to (``""``: not a recorded one)."""
        return self.domain_of_sid.get(str(sid or "").upper().rpartition("-")[0], "")


def _view_fingerprint(shell: Any) -> tuple[Any, ...]:
    record = _record(shell)
    try:
        automatic: Any = bool(policy_settings.expands_scope_automatically(shell))
    except Exception:  # noqa: BLE001 - an unknown policy is "not automatic"
        automatic = None
    parts: list[Any] = [
        getattr(shell, "domain", None),
        # Everything domain_scope_verdict reads: a verdict caches a host's
        # DOMAIN answer, so a trust decision, a policy change or a record that
        # became unreadable must each drop the cache.
        tuple((name, row.get("in_scope")) for name, row in record["entries"].items()),
        tuple(record["origin_domains"]),
        tuple(record["rehydrated_origins"]),
        tuple(sorted(record["session_decided"])),
        bool(record.get("unreadable")),
        bool(record.get("trust_record_lost")),
        automatic,
        getattr(shell, "type", None),
        tuple(
            (name, bool(row.get("target")), tuple(row.get("dc") or ()), row.get("dns") or "")
            for name, row in sorted((record.get("declared") or {}).items())
        ),
    ]
    domains_data = getattr(shell, "domains_data", None)
    if isinstance(domains_data, Mapping):
        for name, data in domains_data.items():
            if isinstance(data, Mapping):
                dcs = data.get("dcs")
                parts.append(
                    (
                        name,
                        *(data.get(field_name) for field_name in _VIEW_FIELDS),
                        tuple(dcs) if isinstance(dcs, (list, tuple)) else None,
                    )
                )
            else:
                parts.append((name,))
    return tuple(parts)


def _domain_view(shell: Any, state: _AssetState | None = None) -> _DomainView:
    fingerprint = _view_fingerprint(shell)
    cached = state.view if state is not None else None
    if isinstance(cached, _DomainView) and cached.fingerprint == fingerprint:
        return cached
    view = _build_domain_view(shell, fingerprint)
    if state is not None:
        state.view = view
        if cached is not None:
            # What the session knows about its domains changed (a domain
            # controller recorded, a NetBIOS name learned): every cached
            # verdict was computed on the old picture.
            state.bump()
    return view


def _build_domain_view(shell: Any, fingerprint: tuple[Any, ...]) -> _DomainView:
    from adscan_core.dc_topology import resolve_domain_controllers  # noqa: PLC0415

    known = tuple(_known_domains(shell))
    netbios: dict[str, list[str]] = {}
    netbios_of: dict[str, str] = {}
    sids: dict[str, str] = {}
    servers: list[tuple[str, tuple[str, ...], str]] = []
    domains_data = getattr(shell, "domains_data", None)
    if isinstance(domains_data, Mapping):
        for raw_name, data in domains_data.items():
            name = _norm(raw_name)
            if not name or not isinstance(data, Mapping):
                continue
            for key in ("netbios", "netbios_domain"):
                value = _norm(data.get(key))
                if value:
                    netbios.setdefault(value, [])
                    if name not in netbios[value]:
                        netbios[value].append(name)
                    netbios_of.setdefault(name, value)
            for key in ("domain_sid", "sid"):
                domain_sid = str(data.get(key) or "").strip().upper()
                if domain_sid.startswith("S-1-5-21-"):
                    sids.setdefault(domain_sid, name)
            aliases_seen: set[str] = set()
            try:
                for dc_record in resolve_domain_controllers(data).dcs:
                    servers.append((name, tuple(dc_record.aliases), _ROLE_DC))
                    aliases_seen.update(_norm(a) for a in dc_record.aliases)
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
            dns = str(data.get("dns_server") or "").strip()
            if dns and _norm(dns) not in aliases_seen:
                servers.append((name, (dns,), _ROLE_DNS))
    # What the operator named for a domain before ``domains_data`` held it
    # (``declare_scan_target``): the same servers the entries above record a
    # moment later, so the answer for them is the same before and after.
    recorded = {(server[0], _ip_text(alias)) for server in servers for alias in server[1]}
    for name, row in (_record(shell).get("declared") or {}).items():
        for address in row.get("dc") or ():
            if (name, address) not in recorded:
                servers.append((name, (address,), _ROLE_DC))
                recorded.add((name, address))
        dns = row.get("dns") or ""
        if dns and (name, dns) not in recorded:
            servers.append((name, (dns,), _ROLE_DNS))
            recorded.add((name, dns))
    by_ip: dict[str, list[Any]] = {}
    by_fqdn: dict[str, list[Any]] = {}
    by_short: dict[str, list[Any]] = {}
    public: set[tuple[int, int]] = set()
    for server in servers:
        for alias in server[1]:
            text = _norm(alias)
            ip = _ip_text(text)
            if ip:
                by_ip.setdefault(ip, []).append(server)
                if server[2] == _ROLE_DC:
                    _add_neighbourhood(public, ip)
            elif "." in text:
                by_fqdn.setdefault(text, []).append(server)
                by_short.setdefault(text.split(".", 1)[0], []).append(server)
            elif text:
                by_short.setdefault(text, []).append(server)
    return _DomainView(
        fingerprint=fingerprint,
        known=known,
        netbios={k: tuple(v) for k, v in netbios.items()},
        netbios_of=netbios_of,
        without_netbios=tuple(d for d in known if d not in netbios_of),
        by_ip={k: tuple(v) for k, v in by_ip.items()},
        by_fqdn={k: tuple(v) for k, v in by_fqdn.items()},
        by_short={k: tuple(v) for k, v in by_short.items()},
        public_server_nets=frozenset(public),
        server_domains_in_scope=frozenset(
            d for d in {server[0] for server in servers} if domain_in_engagement_scope(shell, d)
        ),
        domain_of_sid=sids,
    )


def _pick_server(
    shell: Any, found: Iterable[tuple[str, tuple[str, ...], str]], domain: str = ""
) -> tuple[str, tuple[str, ...], str] | None:
    """One directory server among index hits: in an in-scope domain, DC first."""
    kept: list[tuple[str, tuple[str, ...], str]] = []
    for server in found:
        if domain and server[0] != domain:
            continue
        if not domain_in_engagement_scope(shell, server[0]):
            continue
        kept.append(server)
    if len({server[0] for server in kept}) != 1:
        return None
    for server in kept:
        if server[2] == _ROLE_DC:
            return server
    return kept[0]


def _pick_server_in_view(
    view: _DomainView, found: Iterable[tuple[str, tuple[str, ...], str]]
) -> tuple[str, tuple[str, ...], str] | None:
    """:func:`_pick_server` from the view alone (the domain scope as the view
    was built on it; a change of that scope rebuilds the view)."""
    kept = [server for server in found if server[0] in view.server_domains_in_scope]
    if len({server[0] for server in kept}) != 1:
        return None
    for server in kept:
        if server[2] == _ROLE_DC:
            return server
    return kept[0]


def _directory_server_for(
    shell: Any,
    view: _DomainView,
    *,
    fqdn: str = "",
    short: str = "",
    addresses: Iterable[str] = (),
    domain: str = "",
) -> tuple[str, tuple[str, ...], str] | None:
    """The recorded DC or DNS server a target is, by exact identity.

    An IP matches the same IP; an FQDN matches the same FQDN (never a
    short-label lookalike); a bare short name matches a server's first label
    only when exactly one in-scope domain has such a server (or ``domain``
    says which).
    """
    if fqdn:
        return _pick_server(shell, view.by_fqdn.get(fqdn, ()))
    if short:
        return _pick_server(shell, view.by_short.get(short, ()), domain)
    for address in addresses:
        server = _pick_server(shell, view.by_ip.get(address, ()))
        if server is not None:
            return server
    return None


def _qualifier_domains(view: _DomainView, qualifier: str, *, generous: bool) -> tuple[str, ...]:
    """The DNS domains a ``QUALIFIER\\name`` qualifier can denote.

    STRICT (allow side, and "which domain is this"): a recorded NetBIOS name
    that exactly one domain answers to, or a dotted qualifier taken as the
    domain itself. Nothing else is certain.

    GENEROUS (deny side): every domain recorded under that NetBIOS name, every
    known domain whose first label is the qualifier (a caller, or an operator,
    may write the first label where the NetBIOS name is meant), a dotted
    qualifier itself, and, while no domain is recorded under that NetBIOS
    name, every known domain whose NetBIOS name is not recorded yet (before
    the directory is read, the qualifier may be any of them; once a domain
    answers to it no other can, NetBIOS names being unique among domains that
    trust each other).
    """
    text = _norm(qualifier)
    if not text:
        return ()
    recorded = view.netbios.get(text, ())
    if not generous:
        if recorded:
            return recorded if len(recorded) == 1 else ()
        return (text,) if "." in text else ()
    out = list(recorded)
    if "." in text and text not in out:
        out.append(text)
    out.extend(d for d in view.known if d.split(".", 1)[0] == text and d not in out)
    if not recorded:
        out.extend(d for d in view.without_netbios if d not in out)
    return tuple(out)


def _strict_netbios(view: _DomainView, domain: str) -> str:
    """A domain's recorded NetBIOS name, only when no other domain shares it."""
    name = view.netbios_of.get(domain, "")
    return name if name and len(view.netbios.get(name, ())) == 1 else ""


# ── Resolution: entries to identities (explicit triggers only) ───────────────


def _filter_kind(identities: list[AssetIdentity], kind: str) -> list[AssetIdentity]:
    if not kind:
        return identities
    return [i for i in identities if not i.kind or i.kind == kind]


def _with_addresses(
    shell: Any, state: _AssetState | None, identity: AssetIdentity, *, deny: bool
) -> AssetIdentity:
    """A host identity with the addresses its name has NOW (plus, for a DENIED
    host, every address a resolver ever reported for it).

    An ALLOW identity never takes learned addresses: its evidence is this
    resolution alone, and it lasts :data:`_ALLOW_ADDRESS_TTL_SECONDS`.
    """
    if identity.kind not in ("", _COMPUTER) or not identity.fqdn:
        return identity
    known = set(identity.addresses) if deny else set()
    looked_up = [a for a in (_ip_text(x) for x in _name_addresses(shell, identity.fqdn, identity.domain or None)) if a]
    known.update(looked_up)
    if state is not None:
        # What this lookup learned is knowledge like any other: the name is
        # now known at these addresses (so a name another entry DENIES is
        # refused at them, whatever list asked).
        if looked_up:
            state.learn(_norm(identity.fqdn), looked_up)
        if deny:
            known.update(state.addresses_of(_norm(identity.fqdn)))
    ordered = tuple(sorted(a for a in (_ip_text(x) for x in known) if a))
    if ordered == identity.addresses:
        return identity
    return AssetIdentity(**{**identity.__dict__, "addresses": ordered})


def _merge_previous(
    identities: list[AssetIdentity], previous: Iterable[AssetIdentity]
) -> list[AssetIdentity]:
    """Keep every address an earlier pass learned for a DENIED host.

    An address never un-learns on the deny side (deny wins over a later DHCP
    reuse). Never applied to the allow side: an allowed host's old address must
    not keep granting after it moved. A host an earlier pass knew only by name
    (learned while the entry was pending) is kept as well.
    """
    by_key: dict[tuple[str, str], set[str]] = {}
    for old in previous or ():
        key = (old.domain, old.object_id or old.fqdn or old.samaccountname)
        if key[1]:
            by_key.setdefault(key, set()).update(old.addresses)
    out = []
    seen_fqdns: set[str] = set()
    for identity in identities:
        key = (identity.domain, identity.object_id or identity.fqdn or identity.samaccountname)
        extra = by_key.get(key, set()) - set(identity.addresses)
        if not extra and identity.fqdn:
            for old in previous or ():
                if old.fqdn == identity.fqdn:
                    extra = set(old.addresses) - set(identity.addresses)
        if extra:
            identity = AssetIdentity(
                **{**identity.__dict__, "addresses": tuple(sorted({*identity.addresses, *extra}))}
            )
        if identity.fqdn:
            seen_fqdns.add(identity.fqdn)
        out.append(identity)
    for old in previous or ():
        if old.fqdn and old.addresses and not old.object_id and old.fqdn not in seen_fqdns:
            seen_fqdns.add(old.fqdn)
            out.append(old)
    return out


def _search_domains(
    shell: Any, domains: Iterable[str], **query: str
) -> tuple[list[AssetIdentity], bool]:
    """Query each domain; returns the hits and whether some domain is uncollected.

    No domain to search (none known yet) counts as uncollected: before the
    directory has been read, nothing can be called unresolvable.
    """
    hits: list[AssetIdentity] = []
    names = list(domains)
    uncollected = not names
    for domain in names:
        found = _directory_objects(shell, domain, **query)
        if found is None:
            uncollected = True
            continue
        hits.extend(found)
    return hits, uncollected


def _dns_guesses(
    shell: Any, state: _AssetState | None, short: str, domains: Iterable[str]
) -> list[AssetIdentity]:
    """A host the directory does not know, found by DNS as ``short.<domain>``."""
    out = []
    for domain in domains:
        fqdn = f"{short}.{domain}"
        addresses = tuple(
            sorted(a for a in (_ip_text(x) for x in _name_addresses(shell, fqdn, domain)) if a)
        )
        if addresses:
            if state is not None:
                state.learn(fqdn, addresses)
            out.append(AssetIdentity(kind=_COMPUTER, fqdn=fqdn, domain=domain, addresses=addresses))
    return out


def _resolve_entry(
    shell: Any,
    state: _AssetState | None,
    view: _DomainView,
    entry: asset_model.ScopeEntry,
    *,
    deny: bool,
) -> dict[str, Any]:
    """Resolve one name entry to identities (``status``, ``identities``, ``candidates``)."""
    in_scope = _in_scope_domains(shell)
    etype = entry.type
    identities: list[AssetIdentity] = []
    provisional: list[AssetIdentity] = []
    candidates: list[str] = []
    leaf = False
    status = RESOLUTION_PENDING
    not_collected = False

    def _finish(
        found: list[AssetIdentity], uncollected: bool, *, unique: bool, many: bool = False
    ) -> None:
        nonlocal identities, candidates, status, not_collected
        not_collected = uncollected
        found = _filter_kind(found, entry.kind)
        unique_ids = {(i.domain, i.object_id or i.fqdn or i.samaccountname): i for i in found}
        found = list(unique_ids.values())
        if not found:
            status = RESOLUTION_PENDING if uncollected else RESOLUTION_UNRESOLVABLE
            return
        if unique and len(found) > 1:
            candidates = sorted(i.fqdn or f"{i.domain}\\{i.samaccountname}" for i in found)
            # Deny: every candidate is excluded (and more may come while a
            # domain is still unread). Allow: nothing is granted.
            status = RESOLUTION_PENDING if deny and uncollected else RESOLUTION_AMBIGUOUS
            identities = found if deny else []
            return
        if unique and uncollected and not deny:
            # An allow name is unique only once every domain that could hold
            # it has been read: until then it grants nothing.
            status = RESOLUTION_PENDING
            return
        identities = found
        # A deny name several domains could hold is settled only once every
        # one of them has been read: what was found is excluded now, and the
        # entry keeps failing closed for the holders not seen yet.
        status = RESOLUTION_PENDING if deny and many and uncollected else RESOLUTION_RESOLVED

    if etype == asset_model.TYPE_FQDN:
        owner = _longest_known_suffix(entry.value, list(view.known)) or _norm(
            getattr(shell, "domain", "")
        )
        found, uncollected = _search_domains(shell, [owner] if owner else [], name=entry.value.upper())
        not_collected = uncollected
        found = [i for i in found if i.kind in ("", _COMPUTER)]
        identities = found or [AssetIdentity(kind=_COMPUTER, fqdn=entry.value, domain=owner)]
        identities = [_with_addresses(shell, state, i, deny=deny) for i in identities]
        status = (
            RESOLUTION_RESOLVED
            if found or any(i.addresses for i in identities)
            else RESOLUTION_PENDING
        )
        if not found and not uncollected and not any(i.addresses for i in identities):
            status = RESOLUTION_UNRESOLVABLE
            # The directory was read and the name service asked: the entry
            # matched nothing. The reading of its own text is not an object,
            # so the row carries none (the entry itself still denies the name).
            identities = []
    elif etype == asset_model.TYPE_SHORT_HOST:
        found, uncollected = _search_domains(shell, in_scope, sam=f"{entry.value}$")
        found = [i for i in found if i.kind in ("", _COMPUTER)]
        if not found and deny:
            # Not in the directory (a device that is not domain-joined): try DNS.
            found = _dns_guesses(shell, state, entry.value, in_scope)
        _finish(found, uncollected, unique=True, many=True)
    elif etype == asset_model.TYPE_SID:
        found, uncollected = _search_domains(shell, in_scope, sid=entry.value)
        _finish(found, uncollected, unique=False)
    elif etype == asset_model.TYPE_DN:
        owner = _domain_from_dn(entry.value)
        found, uncollected = _search_domains(shell, [owner] if owner else [], dn=entry.value)
        not_collected = uncollected or not owner
        found = _filter_kind(found, entry.kind)
        # Only an OU or a container holds other objects: an entry that
        # resolved to anything else (an account, a policy, a template) names
        # that one object. A kind the directory did not give stays a subtree.
        leaf = bool(found) and all(i.kind and i.kind not in _SUBTREE_KINDS for i in found)
        identities = found if leaf else []
        status = RESOLUTION_PENDING if uncollected or not owner else RESOLUTION_RESOLVED
    elif etype == asset_model.TYPE_PRINCIPAL:
        qualifier, _, sam = entry.value.rpartition("\\")
        owners: tuple[str, ...] = ()
        if qualifier:
            certain = _qualifier_domains(view, qualifier, generous=False)
            if deny:
                # Every domain the qualifier could denote, the first label of
                # another domain included: a deny entry takes every holder.
                owners = _qualifier_domains(view, qualifier, generous=True)
                found, uncollected = _search_domains(shell, owners, sam=sam)
                if sam.endswith("$") and owners:
                    # Where the directory has nothing (not read yet, or a
                    # device that is not domain-joined), DNS may.
                    held = {i.domain for i in found}
                    found.extend(
                        _dns_guesses(shell, state, sam[:-1], [d for d in owners if d not in held])
                    )
                _finish(found, uncollected or not owners, unique=False, many=len(owners) != 1)
            elif certain:
                found, uncollected = _search_domains(shell, certain, sam=sam)
                _finish(found, uncollected, unique=False)
            else:
                # An allow qualifier no recorded NetBIOS name answers to grants
                # nothing: it waits while a domain's NetBIOS name is still
                # unknown, and is unresolvable once every one is known (the
                # operator writes the NetBIOS name or ``name@domain``).
                not_collected = bool(view.without_netbios) or not view.known
                status = RESOLUTION_PENDING if not_collected else RESOLUTION_UNRESOLVABLE
            if deny and status != RESOLUTION_RESOLVED:
                # Until the directory says which account this is, the entry
                # covers the name in every domain its qualifier could denote
                # (and in any domain when it denotes none that is known).
                provisional = [
                    AssetIdentity(kind=entry.kind, domain=owner, samaccountname=sam)
                    for owner in owners
                ] or [AssetIdentity(kind=entry.kind, samaccountname=sam)]
        else:
            found, uncollected = _search_domains(shell, in_scope, sam=sam)
            _finish(found, uncollected, unique=True, many=True)
    elif etype == asset_model.TYPE_UPN:
        sam, _, realm = entry.value.partition("@")
        owner = _longest_known_suffix(realm, list(view.known)) or realm
        found, uncollected = _search_domains(shell, [owner], name=f"{sam}@{owner}".upper())
        if not found and not uncollected:
            found, uncollected = _search_domains(shell, [owner], sam=sam)
        if not found and not uncollected and owner == realm and realm not in view.known:
            # An alternative UPN suffix: the account may live in any domain.
            uncollected = bool(view.known) and any(
                _directory_objects(shell, d, sam=sam) is None for d in view.known
            )
        _finish(found, uncollected, unique=False, many=realm not in view.known)
    if etype != asset_model.TYPE_FQDN:
        identities = [_with_addresses(shell, state, i, deny=deny) for i in identities]
    row: dict[str, Any] = {"id": entry.id, "status": status, "identities": identities}
    if candidates:
        row["candidates"] = candidates
    if provisional:
        row["provisional"] = provisional
    if etype == asset_model.TYPE_DN:
        row["leaf"] = leaf
    if not_collected:
        row["uncollected"] = True
    if deny:
        row["_checked"] = time.monotonic()
    else:
        row["_at"] = time.monotonic()
    return row


def resolve_asset_scope(
    shell: Any, *, pending_only: bool = False, uncollected: bool = False
) -> None:
    """Resolve the asset scope's name entries against the directory (a pass).

    An EXPLICIT trigger, never run from a verdict. Called when the scope is
    recorded or loaded, by :func:`on_directory_committed` once a domain's
    directory objects are committed, and by :func:`scope_checkpoint` at a
    phase boundary. Every lookup is an indexed query per entry; nothing
    iterates the directory. A denied host's address is never dropped; an
    allowed host's addresses are taken fresh every pass and trusted for
    :data:`_ALLOW_ADDRESS_TTL_SECONDS`.

    ``pending_only`` resolves the entries still pending and the allow names
    whose evidence is stale; everything else keeps its row. ``uncollected``
    (a directory just committed) also resolves the entries that were settled
    by name alone while their domain was unread, so their rows gain the
    directory record. Passes are serialised: a concurrent call waits for the
    running one.

    Nothing is written to disk here: the record is marked for the next
    :func:`flush_engagement_scope`.
    """
    shell = _session(shell)
    state = _asset_state(shell)
    if state is None or state.broken:
        return
    with state.pass_lock:
        _resolution_pass(shell, state, pending_only=pending_only, uncollected=uncollected)


def _resolution_pass(
    shell: Any, state: _AssetState, *, pending_only: bool, uncollected: bool = False
) -> None:
    now = time.monotonic()
    state.last_resolve = now
    view = _domain_view(shell, state)
    resolution = dict(state.resolution)
    if not pending_only and _name_addresses is _SHIPPED_NAME_ADDRESSES:
        # Say what the wait is: a name lookup is the one slow thing a pass does.
        host_names = sum(
            1
            for entry in (*state.scope.allow, *state.scope.deny)
            if entry.type in (asset_model.TYPE_FQDN, asset_model.TYPE_SHORT_HOST)
        )
        if host_names:
            servers = _declared_name_servers(shell, None)
            through = (
                f"the name server {mark_sensitive(servers[0], 'ip')}"
                if servers
                else "the configured resolver"
            )
            print_info(
                f"Engagement scope: looking up {host_names} host "
                f"name{'' if host_names == 1 else 's'} through {through}."
            )
    changed = False
    announced = 0
    unresolvable: list[asset_model.ScopeEntry] = []
    for entry, deny in [*((e, False) for e in state.scope.allow), *((e, True) for e in state.scope.deny)]:
        if entry.type not in _NAME_ENTRY_TYPES:
            continue
        previous = resolution.get(entry.id) or {}
        status = previous.get("status") or RESOLUTION_PENDING
        if pending_only and status != RESOLUTION_PENDING:
            if deny:
                # A denied host may have moved: its name is looked up again
                # once the last look is older than the evidence window (the
                # addresses it had stay denied).
                stale = _entry_could_be_host(entry) and (
                    now - float(previous.get("_checked") or 0.0) >= _ALLOW_ADDRESS_TTL_SECONDS
                )
            else:
                stale = 0.0 < state.allow_fresh_until.get(entry.id, 0.0) <= now
            if (
                not stale
                and not previous.get("provisional")
                and not (uncollected and previous.get("uncollected"))
            ):
                continue
        try:
            row = _resolve_entry(shell, state, view, entry, deny=deny)
        except Exception as exc:  # noqa: BLE001 - an entry that fails stays pending
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            continue
        for identity in row["identities"]:
            # What the directory said about a host while an entry was resolved
            # is knowledge like any other: its record is the record of that
            # NAME, whichever list asked (a host an allow entry names may sit
            # under a denied unit).
            if (
                identity.fqdn
                and identity.kind in ("", _COMPUTER)
                and (identity.dn or identity.object_id)
            ):
                state.set_facts(
                    ("h", _norm(identity.fqdn)),
                    _Facts(
                        kind=_COMPUTER,
                        dn=identity.dn,
                        sid=identity.object_id,
                        fqdn=_norm(identity.fqdn),
                    ),
                )
        if deny:
            row["identities"] = _merge_previous(row["identities"], previous.get("identities") or ())
        if _row_signature(row) != _row_signature(previous):
            changed = True
            if _announce_resolution(entry, row, previous, quiet=announced >= _ANNOUNCE_MAX):
                announced += 1
            if (
                deny
                and row["status"] == RESOLUTION_UNRESOLVABLE
                and _entry_could_be_host(entry)
                and not any(i.addresses for i in row["identities"])
            ):
                unresolvable.append(entry)
        resolution[entry.id] = row
    if _fold_learned(state, resolution):
        # An address a resolver reported while this pass ran: it joins the
        # rows the pass writes, never lost to them.
        changed = True
    state.resolution = resolution
    if announced > _ANNOUNCE_MAX:
        print_info(
            f"Engagement scope: {announced - _ANNOUNCE_MAX} more entries resolved "
            "(the scope record lists what each one resolved to)."
        )
    if unresolvable:
        names = mark_sensitive(", ".join(e.value for e in unresolvable[:10]), "hostname")
        print_warning(
            f"Engagement scope: {names} matches no computer in the directory and no DNS "
            "name. Give its full name or IP address. Until then, ADscan does not contact "
            "any host it cannot identify in the directory."
        )
    state.rebuild()
    if changed:
        _stage_resolution(shell, state)


def _fold_learned(state: _AssetState, resolution: dict[str, dict[str, Any]]) -> bool:
    """Write the addresses learned for DENIED hosts into their resolution rows.

    The verdicts already see them (they read the observations directly); the
    rows are what the matcher's address index and the persisted record carry,
    so the address stays denied in the next session.
    """
    with state._lock:  # noqa: SLF001
        pending, state._unfolded = state._unfolded, []  # noqa: SLF001
    touched = False
    for entry_id, name, address in pending:
        if entry_id not in state.entries:
            continue
        row = dict(resolution.get(entry_id) or {"id": entry_id, "status": RESOLUTION_PENDING})
        identities = list(row.get("identities") or ())
        for index, identity in enumerate(identities):
            if identity.fqdn == name or (
                not identity.fqdn and identity.samaccountname.rstrip("$") == name
            ):
                if address not in identity.addresses:
                    merged = tuple(sorted({*identity.addresses, address}))
                    identities[index] = AssetIdentity(**{**identity.__dict__, "addresses": merged})
                break
        else:
            identities.append(
                AssetIdentity(
                    kind=_COMPUTER,
                    fqdn=name if "." in name else "",
                    samaccountname="" if "." in name else f"{name}$",
                    addresses=(address,),
                )
            )
        row["identities"] = identities
        resolution[entry_id] = row
        touched = True
    return touched


#: How many "resolved to" lines one pass prints before it summarises the rest.
_ANNOUNCE_MAX = 20


def _row_signature(row: Mapping[str, Any]) -> tuple[Any, ...]:
    identities = row.get("identities") or ()
    return (
        row.get("status"),
        tuple(sorted(repr(i) for i in identities)),
        tuple(row.get("candidates") or ()),
        tuple(sorted(repr(i) for i in row.get("provisional") or ())),
    )


def _announce_resolution(
    entry: asset_model.ScopeEntry,
    row: Mapping[str, Any],
    previous: Mapping[str, Any],
    *,
    quiet: bool = False,
) -> bool:
    """Tell the operator what an entry resolved to. Returns whether there was
    something to say; ``quiet`` says it without printing the routine line (a
    large scope is summarised by the pass, never printed entry by entry)."""
    status = row.get("status")
    if status == previous.get("status") and status != RESOLUTION_RESOLVED:
        return False
    value = mark_sensitive(entry.value, "hostname")
    if status == RESOLUTION_RESOLVED and row.get("identities"):
        if _row_signature({**row, "provisional": ()}) == _row_signature({**previous, "provisional": ()}):
            return False
        if quiet:
            return True
        names = []
        for identity in row["identities"][:5]:
            name = identity.fqdn or (
                f"{identity.netbios}\\{identity.samaccountname}" if identity.samaccountname else ""
            )
            addresses = ", ".join(identity.addresses)
            names.append(f"{name} ({addresses})" if addresses else name)
        print_info(
            f"Engagement scope: {value} resolved to "
            f"{mark_sensitive('; '.join(n for n in names if n), 'hostname')}."
        )
    elif status == RESOLUTION_AMBIGUOUS:
        candidates = mark_sensitive(", ".join(row.get("candidates") or ()), "hostname")
        if entry.id.startswith("d"):
            print_info(
                f"Engagement scope: {value} matches several objects ({candidates}); "
                "every one of them is excluded."
            )
        else:
            print_error(
                f"Engagement scope: the allow entry {value} matches several objects "
                f"({candidates}). Use the full name."
            )
    else:
        return False
    return True


def asset_scope_unreadable(shell: Any) -> bool:
    """Whether a recorded asset scope exists but cannot be used.

    One fail-closed state, whatever caused it: a ``scope.json`` that could not
    be parsed, an ``asset_scope`` block that does not validate, or a scope that
    could not be written. The session refuses every host and every object until
    a scope is recorded again (:func:`record_asset_scope` always recovers);
    :func:`asset_scope_errors` says why.
    """
    shell = _session(shell)
    if shell is None:
        return False
    state = _asset_state(shell)
    return bool(_record(shell).get("unreadable")) or bool(state is not None and state.broken)


def asset_scope_errors(shell: Any) -> list[str]:
    """Configuration errors that stop an unattended run (exit 2) before contact.

    The unreadable-record state (with the path and the reason), an egress guard
    that could not be armed, and the errors only the directory can reveal: an
    ambiguous allow entry, and a denied host name that matches nothing (which
    keeps every address ADscan cannot attribute closed). The REPL prints them.
    """
    shell = _session(shell)
    if shell is None:
        return []
    record = _record(shell)
    state = _asset_state(shell)
    if record.get("unreadable"):
        path = record.get("unreadable_path") or SCOPE_FILENAME
        return [
            f"The engagement scope file {path} could not be read: {record['unreadable']}. "
            "Restore it, or record the scope again (ADscan keeps the unreadable file aside)."
        ]
    if state is None:
        return []
    if state.broken:
        path = os.path.join(_workspace_dir(shell), SCOPE_FILENAME) if _workspace_dir(shell) else SCOPE_FILENAME
        return [
            f"The recorded engagement scope ({path}) cannot be used: "
            f"{state.problem or 'it does not validate'}. No host is contacted until the "
            "scope is recorded again."
        ]
    errors: list[str] = []
    if state.guard_fault:
        errors.append(
            "The engagement scope's connection guard could not be armed "
            f"({state.guard_fault}). No engagement host is contacted while it is in this "
            "state; report it, or set ADSCAN_SCOPE_EGRESS_GUARD=off to run on the "
            "per-operation checks alone."
        )
    for entry in state.scope.allow:
        row = state.resolution.get(entry.id) or {}
        if row.get("status") == RESOLUTION_AMBIGUOUS:
            errors.append(
                f"The allow entry '{entry.value}' ({entry.origin or 'scope'}) matches several "
                f"objects: {', '.join(row.get('candidates') or ())}. Use the full name."
            )
    for entry in state.scope.deny:
        row = state.resolution.get(entry.id) or {}
        if (
            row.get("status") == RESOLUTION_UNRESOLVABLE
            and _entry_could_be_host(entry)
            and not any(i.addresses for i in row.get("identities") or ())
        ):
            errors.append(
                f"The deny entry '{entry.value}' ({entry.origin or 'scope'}) matches no computer "
                "in the directory and no DNS name, so ADscan cannot tell which address it is and "
                "contacts no address it cannot attribute to a named host. Give its full name or "
                "its IP address."
            )
    return errors


# ── Explicit triggers: what the session is told, and when it is written ──────


def on_directory_committed(shell: Any = None, *, domain: str | None = None) -> None:
    """HOOK for the collection: a domain's directory objects were committed.

    Call it once per domain right after its ``ldap_objects`` stage commits and
    before the first host-contacting stage. It resolves the entries that were
    waiting for the directory (a SID, a DN, an account, a short host name),
    and, because NetBIOS names are recorded by then, settles which domain a
    ``QUALIFIER\\name`` entry means. ``shell=None`` uses the registered session.
    """
    shell = _session(shell)
    state = _asset_state(shell)
    if state is None or state.broken:
        return
    print_info_debug(
        f"engagement-scope: directory committed for {mark_sensitive(_norm(domain) or '?', 'domain')}"
    )
    resolve_asset_scope(shell, pending_only=True, uncollected=True)
    # Host names the session learned before the directory could say what they
    # are (and names an earlier read did not hold) are read now.
    with state._lock:  # noqa: SLF001
        for key, facts in list(state.facts.items()):
            if key[0] == "h" and facts.kind == _NO_DIRECTORY_RECORD:
                del state.facts[key]
                state.facts_wanted.add(key[1])
                tag = _facts_tag(key[1])
                state._gen[tag] = state._gen.get(tag, 0) + 1  # noqa: SLF001
                state._touch_addresses_of(key[1])  # noqa: SLF001
                state.kb_version += 1
    _drain_wanted_facts(shell, state)
    # Accounts judged before this directory could place them are placed now.
    _reestablish_unread_principals(shell, state)


def scope_checkpoint(shell: Any = None) -> None:
    """HOOK for a phase boundary: refresh what is due, then write the record.

    Re-resolves the entries still pending and the allow names whose address
    evidence is past :data:`_ALLOW_ADDRESS_TTL_SECONDS` (only when there are
    any), and flushes the refusals and backstop hits counted since the last
    write. It also asks the host names earlier batches could not look up
    within their budget. Cheap when nothing is due. ``shell=None`` uses the
    registered session.
    """
    _run_checkpoint(shell, drain_backlog=True)


def _run_checkpoint(shell: Any, *, drain_backlog: bool) -> None:
    shell = _session(shell)
    if shell is None:
        return
    state = _asset_state(shell)
    if state is not None and not state.broken:
        now = time.monotonic()
        if state.has_pending or state.allow_evidence_stale(now) or now >= state.deny_recheck_at:
            resolve_asset_scope(shell, pending_only=True)
        if drain_backlog:
            _drain_lookup_backlog(shell, state)
        _drain_wanted_facts(shell, state)
    record = _record(shell)
    workspace = _workspace_dir(shell)
    if workspace and not record.get("unreadable"):
        # The file changed under this session (another session, the web): the
        # next write merges with it, and a newer scope is adopted here.
        if _file_stat(os.path.join(workspace, SCOPE_FILENAME)) != record.get("disk_stat"):
            record["dirty"] = True
    flush_engagement_scope(shell)
    if record.get("resolve_adopted"):
        record["resolve_adopted"] = False
        adopted = _asset_state(shell)
        if adopted is not None and not adopted.broken:
            resolve_asset_scope(shell, pending_only=True)
            flush_engagement_scope(shell)


#: How often a prepared batch looks at whether a checkpoint is due.
_DUE_CHECK_SECONDS = 60.0


def _checkpoint_if_due(shell: Any, state: _AssetState, *, asks_backlog: bool = False) -> None:
    """Run :func:`scope_checkpoint` from a trigger when its work is overdue.

    The evidence windows (an allow name's addresses, the next look at a denied
    host's name, a pending entry waiting for the directory, a scope somebody
    else recorded) are refreshed at phase boundaries. A flow with no phases
    (``execute``, ``recheck``, a REPL command, a long single phase) would let
    them lapse, so every batch a seam prepares checks, at most once a minute,
    whether that work is due, and does it. A prepared batch is already a
    moment at which lookups are made; a verdict never does this.

    ``asks_backlog``: the caller asks the names earlier batches did not reach
    with its own lookups (a batch of host names), so the checkpoint leaves
    them to it and they share one lookup budget.
    """
    now = time.monotonic()
    if now - state.last_due_check < _DUE_CHECK_SECONDS:
        return
    state.last_due_check = now
    record = _record(shell)
    workspace = _workspace_dir(shell)
    changed = bool(
        workspace
        and not record.get("unreadable")
        and _file_stat(os.path.join(workspace, SCOPE_FILENAME)) != record.get("disk_stat")
    )
    if (
        changed
        or state.has_pending
        or state.allow_evidence_stale(now)
        or now >= state.deny_recheck_at
        or state.facts_wanted
        or (state.lookup_backlog and not asks_backlog)
    ):
        _run_checkpoint(shell, drain_backlog=not asks_backlog)


def _drain_wanted_facts(shell: Any, state: _AssetState) -> None:
    """Read the directory record of the host names learned since the last
    trigger, when the scope holds an entry only a record can settle."""
    if not state.facts_wanted or not state.needs_target_directory:
        return
    with state._lock:  # noqa: SLF001
        names = list(state.facts_wanted)
    _establish_host_facts(shell, state, _domain_view(shell, state), names)


_UNC_HOST = re.compile(r"^[\\/]{2}([^\\/]+)")


def _unc_host(text: str) -> str:
    """The host of a UNC path (``\\\\host\\share\\...``); anything else unchanged.

    A seam that holds a share path names a HOST by it; without this the
    leading backslashes read as an empty ``QUALIFIER\\name`` and the host was
    refused for the wrong reason.
    """
    match = _UNC_HOST.match(text)
    return match.group(1) if match else text


def _embedded_v4(address: str) -> str:
    """The IPv4 address an IPv6 address carries (NAT64, 6to4, IPv4-compatible), ``""`` if none."""
    if ":" not in address:
        return ""
    try:
        carried = asset_model.embedded_ipv4(ipaddress.ip_address(address))
    except ValueError:
        return ""
    return str(carried) if carried is not None else ""


def _host_name_key(host: Any) -> str:
    """The knowledge key of a host name: its FQDN, or its bare label."""
    text = _unc_host(_norm(host))
    if not text or _ip_text(text):
        return ""
    if "\\" in text:
        text = text.rpartition("\\")[2]
    if "@" in text:
        name, _, realm = text.partition("@")
        name = name.rstrip("$")
        return f"{name}.{realm}" if "." in realm else name
    return text.rstrip("$")


def note_host_addresses(shell: Any, *, host: str | None, addresses: Iterable[Any]) -> None:
    """Record addresses a resolver learned for ``host`` (an explicit trigger).

    Called by the DNS layer of the host resolver, the 445 gate, the nmap host
    map, and by the egress guard for every name this process resolves. The
    pair joins the session's knowledge: an address seen under a denied host's
    name is denied for everyone, for the rest of the engagement (deny wins over
    a later DHCP reuse); on the allow side an observation is evidence for
    :data:`_ALLOW_ADDRESS_TTL_SECONDS` and never widens an allow NAME entry.

    Constant in the number of scope entries: no pass over them, no matcher
    rebuild, no file write. Only the cached verdicts that read this name or
    these addresses are invalidated.
    """
    shell = _session(shell)
    state = _asset_state(shell)
    if state is None or state.broken:
        return
    key = _host_name_key(host)
    if not key:
        return
    found = [a for a in (_ip_text(x) for x in addresses or ()) if a]
    if not found:
        return
    new = state.learn(key, found)
    if not new:
        return
    # With every address the name was ever seen at: a host inside a denied
    # range is a denied host, and its other addresses are denied with it.
    entry_id = ""
    for reading in _name_readings(key, state.addresses_of(key), state.view):
        entry_id = state.matcher.match_deny(reading)
        if entry_id:
            break
    if entry_id:
        with state._lock:  # noqa: SLF001
            state._unfolded.extend((entry_id, key, address) for address in new)  # noqa: SLF001
        _mark_dirty(shell)


def note_host_addresses_batch(shell: Any, pairs: Mapping[Any, Iterable[Any]]) -> None:
    """:func:`note_host_addresses` for a whole ``{host: addresses}`` map."""
    for host, addresses in (pairs or {}).items():
        note_host_addresses(shell, host=str(host or ""), addresses=addresses)


def _name_readings(
    name: str,
    addresses: Iterable[str] = (),
    view: _DomainView | None = None,
    facts: _Facts | None = None,
    *,
    strict: bool = False,
) -> list[AssetIdentity]:
    """The host(s) a knowledge key names, as readings (with their addresses).

    An FQDN is one host, in the known domain it sits under, with its directory
    record when the session has it. A bare label is that label in every known
    domain (the deny side; ``strict`` keeps the bare reading only).
    """
    known = tuple(sorted(addresses))
    record = facts if facts is not None and facts.kind != _NO_DIRECTORY_RECORD else None
    if "." in name:
        domain = (_longest_known_suffix(name, list(view.known)) or "") if view is not None else ""
        netbios = ""
        if view is not None and domain:
            netbios = _strict_netbios(view, domain) if strict else view.netbios_of.get(domain, "")
        return [
            AssetIdentity(
                kind=_COMPUTER,
                object_id=record.sid if record else "",
                domain=domain,
                dn=record.dn if record else "",
                fqdn=name,
                samaccountname=f"{name.split('.', 1)[0]}$",
                netbios=netbios,
                addresses=known,
            )
        ]
    out = [AssetIdentity(kind=_COMPUTER, samaccountname=f"{name}$", addresses=known)]
    if view is not None and not strict:
        out.extend(
            AssetIdentity(
                kind=_COMPUTER,
                domain=domain,
                samaccountname=f"{name}$",
                netbios=view.netbios_of.get(domain, ""),
                addresses=known,
            )
            for domain in view.known
        )
    return out


def _establish_host_facts(
    shell: Any, state: _AssetState, view: _DomainView, names: Iterable[str]
) -> int:
    """Read the directory record of host NAMES the session learned (a trigger's work).

    One indexed query per name, never from a verdict. A name the collected
    directory does not hold (a DNS alias, a device that is not domain-joined)
    is recorded as such, so it is not asked again; a name whose domain has not
    been read yet stays wanted.
    """
    done = 0
    for fqdn in list(names):
        if "." not in fqdn:
            state.facts_wanted.discard(fqdn)
            continue
        if state.facts.get(("h", fqdn)) is not None:
            state.facts_wanted.discard(fqdn)
            continue
        owner = _longest_known_suffix(fqdn, list(view.known))
        if not owner:
            continue
        records = _directory_objects(shell, owner, name=fqdn.upper())
        if records is None:
            continue
        hosts = [i for i in list(records) if i.kind in ("", _COMPUTER)]
        if len(hosts) == 1:
            facts = _Facts(kind=_COMPUTER, dn=hosts[0].dn, sid=hosts[0].object_id, fqdn=fqdn)
        else:
            facts = _Facts(kind=_NO_DIRECTORY_RECORD, fqdn=fqdn)
        state.set_facts(("h", fqdn), facts)
        state.facts_wanted.discard(fqdn)
        done += 1
    return done


def prepare_scope_targets(
    shell: Any, hosts: Iterable[Any], *, domain: str | None = None
) -> int:
    """Tell the session what it needs to judge a BATCH of host targets.

    An explicit trigger, called by a seam before it partitions hosts it knows
    only by name. Verdicts never look anything up, so a named target whose
    addresses nobody reported is "not confirmed" whenever an address rule
    could apply to it. This looks each name up ONCE (workspace inventory and
    DNS, never a probe) and, when the scope holds a subtree or a pending SID
    entry, reads the host's directory record (one indexed query), then records
    both. A seam that already holds the address, DN or SID passes them to the
    verdict instead and does not need this.

    Returns:
        How many names were looked up (0 when the scope needs nothing).
    """
    shell = _session(shell)
    state = _asset_state(shell)
    if state is None or state.broken:
        return 0
    _checkpoint_if_due(shell, state, asks_backlog=True)
    state = _asset_state(shell)  # a checkpoint may have adopted a newer scope
    if state is None or state.broken:
        return 0
    matcher = state.matcher
    need_addresses = matcher.has_address_rules
    need_directory = state.needs_target_directory
    if not (need_addresses or need_directory or matcher.allow_applies_to_hosts):
        return 0
    view = _domain_view(shell, state)
    hint = _norm(domain)
    now = time.monotonic()
    # Pass 1 (no lookup): every host each name could be, and which of them
    # need their addresses asked. The whole batch is planned before anything
    # is looked up, so the lookups are made once, together.
    plan: list[tuple[tuple[tuple[str, str], ...], bool]] = []
    to_look: dict[str, str] = {}
    for host in hosts or ():
        text = _norm(host)
        if not text or _ip_text(text):
            continue
        # Every host the name could be: the FQDN, or the bare name in each
        # domain that could hold it (the same reading the verdict makes).
        target = _parse_host(
            shell, view, host=text, connect_address=None, domain=hint, host_dn=None, host_sid=None
        )
        candidates = _host_names(target)
        # A name several domains could hold: each one is looked up and read,
        # so the ones that do not exist stop counting.
        several = len(candidates) > 1
        plan.append((candidates, several))
        for owner, fqdn in candidates:
            # A name that answered is asked again once its evidence is old;
            # one that did not, sooner (the resolver may only now be set up).
            wait = (
                _ALLOW_ADDRESS_TTL_SECONDS
                if state.name_current.get(fqdn)
                else _NEGATIVE_LOOKUP_TTL_SECONDS
            )
            if (need_addresses or several) and now - state.looked_up.get(fqdn, -_NEVER) >= wait:
                to_look.setdefault(fqdn, owner)
    # The names an earlier batch could not look up within its budget are asked
    # with this one (after its own), whoever prepared them: no caller has to
    # prepare the same names again for them to be answered.
    # Pass 2: the addresses of the whole batch (inventory read once, the rest
    # asked concurrently). The batch pays for ITS OWN names in full (the ones
    # an earlier batch of anyone's left unanswered included, when they are in
    # this batch too).
    answered = _name_addresses_batch(shell, list(to_look.items())) if to_look else {}
    _note_batch_answers(shell, state, to_look, answered, now)
    # Names somebody else's batch did not reach get a capped few seconds here
    # (:data:`_BACKLOG_SHARE_SECONDS`): no caller has to prepare them again,
    # and no caller pays another batch's whole budget for them.
    with state._lock:  # noqa: SLF001
        carried_over = {n: d for n, d in state.lookup_backlog.items() if n not in to_look}
    if carried_over:
        late = _name_addresses_batch(
            shell, list(carried_over.items()), budget=_BACKLOG_SHARE_SECONDS
        )
        _note_batch_answers(shell, state, carried_over, late, time.monotonic())
        answered = {**answered, **late}
        for fqdn, owner in carried_over.items():
            if fqdn in late:
                plan.append((((owner, fqdn),), False))
    # Pass 3: the directory record of the names that need one.
    done = 0
    wanted: dict[str, None] = {}
    shared: set[str] = set()
    for candidates, several in plan:
        looked = False
        for _owner, fqdn in candidates:
            looked = looked or fqdn in answered
            if need_directory or several or (need_addresses and not state.addresses_of(fqdn)):
                # (A host with a directory record and no address is a known
                # host; a name with neither may be another name of anything.)
                if ("h", fqdn) not in state.facts:
                    looked = True
                wanted[fqdn] = None
                # Every other name reported at this host's addresses is read
                # with it (the address may be that host's): once per ADDRESS,
                # however many names of the batch share it.
                for address in state.addresses_of(fqdn):
                    if address in shared:
                        continue
                    shared.add(address)
                    for other in state.names_of(address):
                        wanted[other] = None
        done += int(looked)
    if wanted:
        _establish_host_facts(shell, state, view, wanted)
    return done


def _note_batch_answers(
    shell: Any,
    state: _AssetState,
    asked: Mapping[str, str],
    answered: Mapping[str, Iterable[Any]],
    now: float,
) -> None:
    """Record what a batch lookup answered, and keep what it did not reach.

    A name the batch's budget did not reach stays in ``state.lookup_backlog``:
    the next trigger (any prepared batch, a checkpoint, a phase boundary) asks
    it. Until then it reads "not confirmed" wherever its address matters, and
    the record counts it (``names_not_looked_up``): at the end of a run that
    count is a declared coverage gap, never a silent one.
    """
    changed = False
    with state._lock:  # noqa: SLF001
        for fqdn, owner in asked.items():
            if fqdn in answered:
                state.looked_up[fqdn] = now
                changed = state.lookup_backlog.pop(fqdn, None) is not None or changed
            elif fqdn not in state.lookup_backlog:
                state.lookup_backlog[fqdn] = owner
                changed = True
    for fqdn, raw in answered.items():
        found = [a for a in (_ip_text(x) for x in raw) if a]
        if found:
            note_host_addresses(shell, host=fqdn, addresses=found)
    if changed and _asset_block(shell) is not None:
        with _RECORD_LOCK:
            _record(shell)["dirty"] = True


def _drain_lookup_backlog(shell: Any, state: _AssetState) -> int:
    """Ask the names earlier batches did not reach (a trigger's work).

    Returns:
        How many of them were answered.
    """
    with state._lock:  # noqa: SLF001
        asked = dict(state.lookup_backlog)
    if not asked:
        return 0
    answered = _name_addresses_batch(shell, list(asked.items()), budget=_BACKLOG_SHARE_SECONDS)
    _note_batch_answers(shell, state, asked, answered, time.monotonic())
    names = [name for name in asked if name in answered]
    if names:
        _establish_host_facts(shell, state, _domain_view(shell, state), names)
    return len(names)


def names_not_looked_up(shell: Any = None) -> int:
    """How many host names the session could not look up yet (the name service
    did not answer within a batch's budget). They read "not confirmed" until a
    later trigger reaches them; at the end of a run this is a coverage gap the
    record declares (``asset_scope.names_not_looked_up``)."""
    state = _asset_state(_session(shell))
    if state is None:
        return 0
    with state._lock:  # noqa: SLF001
        return len(state.lookup_backlog)


#: The single-name lookup as shipped: a replaced seam (a test double, an
#: injected resolver) is honoured by the batch lookup too.
_SHIPPED_NAME_ADDRESSES = _name_addresses

#: Concurrent DNS queries of one batch, and how long a batch may spend on them.
_PREPARE_DNS_WORKERS = 32
_PREPARE_DNS_BUDGET_SECONDS = 30.0
#: What a trigger spends on names that are NOT its own (the backlog other
#: batches left): a prepared batch after its own names, a checkpoint, a phase
#: boundary. Five seconds at most, each time.
_BACKLOG_SHARE_SECONDS = 5.0


def _inventory_address_index(shell: Any, domain: str) -> dict[str, list[str]]:
    """``host key -> addresses`` from the workspace inventory and the
    reachability report of ``domain``, read and indexed ONCE.

    The same two sources, and the same alias keys, the single-name lookup
    reads (``host_address_resolver._gather_candidate_ips``); what differs is
    that the reports are parsed once per batch instead of once per name.
    """
    index: dict[str, list[str]] = {}
    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "")
    domains_dir = str(getattr(shell, "domains_dir", "domains") or "domains")
    if not workspace_dir or not domain:
        return index
    from adscan_internal.services.host_address_resolver import _host_keys, _is_ip  # noqa: PLC0415

    def _add(hostname: Any, address: Any) -> None:
        if not _is_ip(str(address or "")):
            return
        for key in _host_keys(str(hostname or "")):
            held = index.setdefault(key, [])
            if address not in held:
                held.append(address)

    try:
        from adscan_internal.services.kerberos_hostname_inventory import (  # noqa: PLC0415
            load_workspace_ip_hostname_inventory,
        )

        inventory = load_workspace_ip_hostname_inventory(
            workspace_dir=workspace_dir, domains_dir=domains_dir, domain=domain
        )
        for address, hostnames in (inventory or {}).items():
            for hostname in hostnames or ():
                _add(hostname, address)
    except Exception as exc:  # noqa: BLE001 - a source that fails contributes nothing
        telemetry.capture_exception(exc)
    try:
        from adscan_internal.services.current_vantage_reachability_service import (  # noqa: PLC0415
            _build_hostname_to_ips_map,
            load_current_vantage_reachability_report,
        )

        payload, _path = load_current_vantage_reachability_report(workspace_dir, domains_dir, domain)
        if isinstance(payload, dict):
            for key, addresses in _build_hostname_to_ips_map(payload).items():
                for address in addresses or ():
                    _add(key, address)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
    return index


def _name_addresses_batch(
    shell: Any, pairs: list[tuple[str, str]], *, budget: float | None = None
) -> dict[str, list[str]]:
    """The addresses of a BATCH of ``(name, domain)`` pairs, without contacting any host.

    What :func:`_name_addresses` answers for each name, at a cost that fits a
    whole inventory: the workspace reports are parsed once per domain and
    indexed by host key, and only the names they do not answer are asked over
    DNS, concurrently (:data:`_PREPARE_DNS_WORKERS` at a time) and within
    :data:`_PREPARE_DNS_BUDGET_SECONDS` for the batch. A name the budget did
    not reach is absent from the result: it is not marked as looked up, so the
    next batch asks it.
    """
    if _name_addresses is not _SHIPPED_NAME_ADDRESSES:
        return {name: list(_name_addresses(shell, name, domain or None)) for name, domain in pairs}
    out: dict[str, list[str]] = {}
    try:
        from adscan_internal.models.domain import resolve_dns_server  # noqa: PLC0415
        from adscan_internal.services.host_address_resolver import (  # noqa: PLC0415
            _dns_candidate_ips,
            _host_keys,
        )
    except Exception as exc:  # noqa: BLE001 - nothing learned is an empty answer
        telemetry.capture_exception(exc)
        return out
    by_domain: dict[str, list[str]] = {}
    for name, domain in pairs:
        by_domain.setdefault(_norm(domain), []).append(name)
    domains_data = getattr(shell, "domains_data", None) or {}
    ask: list[tuple[str, Any]] = []
    for domain, names in by_domain.items():
        index = _inventory_address_index(shell, domain)
        data = domains_data.get(domain) if isinstance(domains_data, Mapping) else None
        resolver_ip = resolve_dns_server(data) if isinstance(data, dict) else None
        for name in names:
            found: list[str] = []
            for key in _host_keys(name):
                for address in index.get(key, ()):
                    if address not in found:
                        found.append(address)
            if found:
                out[name] = found
            else:
                ask.append((name, resolver_ip))
    if not ask:
        return out
    from concurrent.futures import ThreadPoolExecutor, wait  # noqa: PLC0415

    allowed = _PREPARE_DNS_BUDGET_SECONDS if budget is None else min(budget, _PREPARE_DNS_BUDGET_SECONDS)
    deadline = time.monotonic() + allowed
    pool = ThreadPoolExecutor(max_workers=min(_PREPARE_DNS_WORKERS, len(ask)), thread_name_prefix="scope-dns")
    try:
        futures = {pool.submit(_dns_candidate_ips, name, resolver): name for name, resolver in ask}
        finished, late = wait(futures, timeout=max(0.0, deadline - time.monotonic()))
        for future in finished:
            try:
                out[futures[future]] = list(future.result())
            except Exception:  # noqa: BLE001 - a lookup that failed answered nothing
                out[futures[future]] = []
        for future in late:
            future.cancel()
        if late:
            print_info_debug(
                f"engagement-scope: {len(late)} of {len(ask)} names were not looked up within "
                f"{_PREPARE_DNS_BUDGET_SECONDS:.0f}s; the next batch asks them"
            )
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return out


def prepare_scope_principals(
    shell: Any, principals: Iterable[Any], *, domain: str | None = None
) -> int:
    """Tell the session the KIND (and DN, SID, UPN) of a batch of principals.

    An explicit trigger for a seam that holds labels only. Under a scope that
    restricts hosts, a verdict needs the object's kind (a GPO or an OU reaches
    hosts; an account does not) and never looks it up. One indexed directory
    query per principal, then the indexed membership snapshot; never a walk of
    the graph. A seam that built its list from a directory query passes
    ``kind=`` to the verdict instead and does not need this.

    Returns:
        How many principals were looked up.
    """
    shell = _session(shell)
    state = _asset_state(shell)
    if state is None or state.broken:
        return 0
    _checkpoint_if_due(shell, state)
    state = _asset_state(shell)  # a checkpoint may have adopted a newer scope
    if state is None or state.broken:
        return 0
    view = _domain_view(shell, state)
    done = 0
    for principal in principals or ():
        target = _parse_principal(view, str(principal or ""), _norm(domain))
        owner = target.owner or (target.generous[0] if target.generous else "") or _norm(
            getattr(shell, "domain", "")
        )
        key = _principal_facts_key(str(principal or ""), _norm(domain))
        if not key[1] or key in state.facts or not owner:
            continue
        if target.fqdn and target.fqdn_certain:
            # A label that is a host name under a known domain: the computer
            # the directory holds under that name (an attack-graph node of a
            # computer is labelled by its FQDN).
            host_owner = _longest_known_suffix(target.fqdn, list(view.known))
            hosts = [
                i
                for i in _directory_objects(shell, host_owner, name=target.fqdn.upper()) or ()
                if i.kind in ("", _COMPUTER)
            ]
            if len(hosts) == 1:
                state.set_facts(
                    key,
                    _Facts(
                        kind=_COMPUTER,
                        dn=hosts[0].dn,
                        sid=hosts[0].object_id,
                        upn=hosts[0].upn,
                        fqdn=target.fqdn,
                    ),
                )
                done += 1
                continue
        query: dict[str, str] = {}
        if target.sid:
            query = {"sid": target.sid}
        elif target.dn:
            query = {"dn": target.dn}
        elif target.sam:
            query = {"sam": target.sam}
        # Every domain the label could name: one when its domain is certain
        # (a SID, a DN, ``name@domain``, the caller's domain), else each domain
        # a bare name or a ``QUALIFIER\\name`` could denote. The record is
        # taken only when it is THE object the label names: one holder, with
        # every one of those domains read. A label two domains could answer to
        # is never pinned to the first that does.
        if target.sid or target.dn or (target.owner and not target.qualifier):
            candidates = [owner]
        else:
            candidates = [d for d in dict.fromkeys((target.owner, *target.generous)) if d] or [owner]
        records: list[AssetIdentity] = []
        unread = not query
        for candidate in candidates if query else ():
            found_here = _directory_objects(shell, candidate, **query)
            if found_here is None:
                unread = True
            else:
                records.extend(found_here)
        facts = _Facts()
        # Which of the candidate domains hold the name, once every one is read.
        holders = None if unread else tuple(sorted({r.domain for r in records if r.domain}))
        if len(records) == 1 and not unread:
            found = records[0]
            facts = _Facts(
                kind=found.kind,
                dn=found.dn,
                sid=found.object_id,
                upn=found.upn,
                fqdn=found.fqdn,
                holders=holders,
            )
        elif records and not unread and len({r.kind for r in records}) == 1:
            facts = _Facts(kind=records[0].kind, holders=holders)
        elif len(candidates) > 1:
            # Not established which object it is: its kind is not either.
            state.set_facts(key, _Facts(holders=holders))
            _note_principal_read(state, key, unread)
            done += 1
            continue
        if not facts.kind:
            facts = _Facts(
                kind=_principal_kind(shell, owner, str(principal or "")),
                dn=facts.dn,
                sid=facts.sid,
                upn=facts.upn,
                fqdn=facts.fqdn,
                holders=facts.holders,
            )
        state.set_facts(key, facts)
        _note_principal_read(state, key, unread)
        done += 1
    return done


def _note_principal_read(state: _AssetState, key: tuple[str, ...], unread: bool) -> None:
    """Mark a principal's facts provisional while a domain that could hold the
    label is unread (``unread``), and settled once every one was read."""
    with state._lock:  # noqa: SLF001
        if unread:
            state.principals_unread.add(key)
        else:
            state.principals_unread.discard(key)


def _reestablish_unread_principals(shell: Any, state: _AssetState) -> int:
    """Establish again the principals judged before their directory was read.

    A seam that names an account before the collection (the scan's own sign-in,
    a credential the operator passed) is told "nothing known yet", and that
    answer used to stand for the whole run: the account stayed "not confirmed"
    after the directory could place it, and was reported as an object left
    alone as a precaution. Called once a domain's directory objects commit.

    Returns:
        How many were established again.
    """
    with state._lock:  # noqa: SLF001
        stale = sorted(state.principals_unread)
        for key in stale:
            state.facts.pop(key, None)
            tag = "#" + "|".join(key)
            state._gen[tag] = state._gen.get(tag, 0) + 1  # noqa: SLF001
        state.principals_unread.difference_update(stale)
        if stale:
            state.kb_version += 1
    by_domain: dict[str, list[str]] = {}
    for key in stale:
        by_domain.setdefault(key[2] if len(key) > 2 else "", []).append(key[1])
    done = 0
    for domain, labels in by_domain.items():
        done += prepare_scope_principals(shell, labels, domain=domain or None)
    return done


def _principal_facts_key(principal: str, domain: str) -> tuple[str, ...]:
    return ("p", _norm(principal), _norm(domain))


# ── The verdicts (reads only) ───────────────────────────────────────────────


def _verdict(
    outcome: ScopeOutcome,
    reason: str,
    identity: AssetIdentity | None,
    entry_id: str = "",
    kind: str = "",
    cause: str = "",
    domain: str = "",
) -> AssetScopeVerdict:
    if not kind and identity is not None:
        kind = identity.kind or (
            "address" if not (identity.fqdn or identity.samaccountname) else _COMPUTER
        )
    return AssetScopeVerdict(
        outcome, reason, kind, identity, entry_id, cause, domain or (identity.domain if identity else "")
    )


def _undetermined(
    identity: AssetIdentity | None, cause: str, kind: str = "", domain: str = ""
) -> AssetScopeVerdict:
    """Not established: left alone as a precaution, never an established exclusion."""
    return _verdict(
        ScopeOutcome.UNDETERMINED, ASSET_REASON_UNDETERMINED, identity, "", kind, cause, domain
    )


@dataclass(frozen=True)
class _HostTarget:
    """A host target as written, read every way it can be read."""

    ips: tuple[str, ...] = ()
    connect: str = ""
    fqdn: str = ""
    short: str = ""
    qualifier: str = ""
    owner: str = ""
    candidates: tuple[str, ...] = ()
    dn: str = ""
    sid: str = ""

    @property
    def named(self) -> bool:
        return bool(self.fqdn or self.short)

    @property
    def keys(self) -> tuple[str, ...]:
        """The knowledge keys this target's addresses were reported under."""
        if self.fqdn:
            return (self.fqdn,)
        if not self.short:
            return ()
        return (self.short, *(f"{self.short}.{d}" for d in self.candidates))


def _parse_host(
    shell: Any,
    view: _DomainView,
    *,
    host: str,
    connect_address: Any,
    domain: Any,
    host_dn: Any,
    host_sid: Any,
) -> _HostTarget:
    """Read a host string in any form the product writes.

    ``192.0.2.10`` and ``::ffff:192.0.2.10`` are an address;
    ``fs01.corp.example`` and ``FS01$@CORP.EXAMPLE`` an FQDN; ``fs01``,
    ``FS01$`` and ``CORP\\FS01$`` a short name, whose owner is certain only
    when the caller says the domain, the DN does, or the qualifier is a
    recorded NetBIOS name. Otherwise every known domain is a candidate.
    """
    text = _unc_host(_norm(host))
    ip = _ip_text(text)
    connect = _ip_text(connect_address)
    ips = tuple(dict.fromkeys(a for a in (ip, connect) if a))
    hint = _norm(domain)
    dn = str(host_dn or "")
    sid = str(host_sid or "").strip().upper()
    dn_domain = _domain_from_dn(dn)
    fqdn = short = qualifier = ""
    if not ip and text:
        if "\\" in text:
            qualifier, _, name = text.rpartition("\\")
            short = name.rstrip("$")
        elif "@" in text:
            name, _, realm = text.partition("@")
            name = name.rstrip("$")
            if "." in name:
                fqdn = name
            elif "." in realm and realm not in _PLACEHOLDERS:
                fqdn = f"{name}.{realm}" if name else ""
            else:
                short = name
                qualifier = "" if realm in _PLACEHOLDERS else realm
        elif "." in text:
            fqdn = text.rstrip("$")
        else:
            short = text.rstrip("$")
    owner = ""
    candidates: tuple[str, ...] = ()
    if fqdn:
        owner = (
            dn_domain
            or _longest_known_suffix(fqdn, list(view.known))
            or hint
            or _norm(getattr(shell, "domain", ""))
        )
    elif short:
        if dn_domain:
            owner = dn_domain
        elif qualifier:
            strict = _qualifier_domains(view, qualifier, generous=False)
            owner = strict[0] if len(strict) == 1 else hint
            candidates = _qualifier_domains(view, qualifier, generous=True)
        else:
            owner = hint
        if owner:
            candidates = tuple(dict.fromkeys((owner, *candidates)))
        elif not candidates:
            candidates = view.known
    return _HostTarget(ips, connect, fqdn, short, qualifier, owner, candidates, dn, sid)


def _host_reading(
    view: _DomainView,
    target: _HostTarget,
    domain: str,
    *,
    strict: bool,
    record: tuple[str, str] | None = None,
) -> AssetIdentity:
    """One reading of a named host in ``domain`` (``""``: the bare name).

    ``record`` is the ``(dn, sid)`` of THAT host when the session knows it.
    """
    fqdn = target.fqdn or (f"{target.short}.{domain}" if domain else "")
    label = target.fqdn.split(".", 1)[0] if target.fqdn else target.short
    netbios = _strict_netbios(view, domain) if strict else view.netbios_of.get(domain, "")
    dn, sid = record if record is not None else (target.dn, target.sid)
    return AssetIdentity(
        kind=_COMPUTER,
        object_id=sid,
        domain=domain,
        dn=dn,
        fqdn=fqdn,
        samaccountname=f"{label}$" if label else "",
        netbios=netbios,
    )


def host_scope_verdict(
    shell: Any,
    *,
    host: str | None,
    connect_address: str | None = None,
    purpose: Any = None,
    domain: str | None = None,
    host_dn: str | None = None,
    host_sid: str | None = None,
    contact: Contact | None = None,
) -> AssetScopeVerdict:
    """May the scan send a packet to this host, for what ``contact`` opens?

    ``contact`` describes WHAT is opened (:class:`Contact`); the purpose is
    derived from it and can not be named: ``purpose`` is accepted for one
    release and ignored. Nothing stated is an ordinary host contact.

    A READ: in-memory state only. The addresses of a name, and its directory
    record, are what the session was told (``connect_address``, ``host_dn``,
    ``host_sid``, :func:`note_host_addresses`, :func:`prepare_scope_targets`);
    a verdict never looks them up. Ladder (first match wins):

    1. no asset scope -> ALLOWED (one attribute read);
    2. the record cannot be read -> UNDETERMINED ``scope_record_unreadable``;
    3. ANY reading of the target matches a deny entry -> REFUSED
       ``denied_entry``: its addresses (given, and every one ever reported for
       its name), its name in every form, the names every one of its addresses
       was ever reported under, its DN and SID;
    4. the host's domain is outside the DOMAIN scope -> REFUSED
       ``domain_outside_scope``;
    5. a domain's configured DNS server that is not a DC: name resolution is
       ALLOWED; anything else is judged as an ordinary host;
    6. a recorded domain controller of an in-scope domain: a directory-plane
       contact is ALLOWED (the directory must stay readable for the entries to
       resolve); a host contact skips the allow-list under ``dc_access =
       full``, is REFUSED ``dc_directory_only`` when a host allow-list does
       not name it, and in every mode still meets rule 8;
    7. a host allow-list exists: ALLOWED only when it covers EVERY reading that
       could be the true one (a bare name must be allowed in each in-scope
       domain, or be an allow short entry that resolved to one computer), or
       every address the contact goes to is inside an allow address entry. An
       address-only target is granted by an allow NAME only while that name's
       resolution is fresh. Otherwise REFUSED ``not_in_allow_list`` when the
       target is established, UNDETERMINED when it is not (an allow entry
       pending, an address not known, a name several domains could hold);
    8. a denied host could still be this target (its addresses or identity are
       not known yet, or this name's addresses are not known while a deny rule
       is matched by address) -> UNDETERMINED;
    9. otherwise ALLOWED.

    ``shell=None`` falls back to the session registered with
    :func:`register_scope_shell`, so a shell-less service cannot fail open by
    forgetting to pass one.
    """
    shell = _session(shell)
    state = _asset_state(shell)
    if state is None:
        return _ALLOWED_NO_SCOPE
    _legacy_purpose(purpose, contact)
    return _host_verdict(
        shell,
        state,
        host=host,
        connect_address=connect_address,
        purpose=_purpose_of(contact),
        smb=_over_smb(contact),
        domain=domain,
        host_dn=host_dn,
        host_sid=host_sid,
    )


def _unreadable_verdict(kind: str) -> AssetScopeVerdict:
    return _verdict(
        ScopeOutcome.UNDETERMINED,
        ASSET_REASON_UNREADABLE,
        None,
        kind=kind,
        cause=CAUSE_RECORD_UNREADABLE,
    )


def _host_verdict(
    shell: Any,
    state: _AssetState,
    *,
    host: Any,
    connect_address: Any,
    purpose: ContactPurpose,
    domain: Any,
    host_dn: Any,
    host_sid: Any,
    smb: bool = False,
) -> AssetScopeVerdict:
    """The cached host verdict for a purpose the ENGINE derived (module-private).

    ``smb``: the contact is opened over SMB (a SYSVOL read, a directory pipe).
    It matters for one case: an address only reported for a domain
    controller's name, where the socket guard lets LDAP and Kerberos through
    and nothing on port 445.
    """
    if state.broken:
        return _unreadable_verdict(_COMPUTER)
    key = (
        "h",
        _norm(host),
        _ip_text(connect_address),
        purpose.value + ("+smb" if smb else ""),
        _norm(domain),
        _norm(host_dn),
        _norm(host_sid),
    )
    view = _domain_view(shell, state)
    version = state.version
    cached = state.cache_get(key)
    if cached is not None:
        return cached
    target = _parse_host(
        shell,
        view,
        host=str(host or ""),
        connect_address=connect_address,
        domain=domain,
        host_dn=host_dn,
        host_sid=host_sid,
    )
    read = (*target.keys, *("@" + ip for ip in target.ips), *(_facts_tag(k) for k in target.keys))
    verdict = _unreadable_verdict(_COMPUTER)
    for _attempt in range(_VERDICT_ATTEMPTS):
        # Knowledge may arrive from another thread WHILE this is computed (the
        # name observer runs on executor threads). An answer computed across
        # such a change is computed again, and never cached.
        epoch = state.kb_version
        verdict, expires, more = _compute_host_verdict(shell, state, view, target, purpose, smb=smb)
        if state.cache_put_if_current(
            key, version, verdict, epoch=epoch, expires=expires, names=(*read, *more)
        ):
            break
    return verdict


def _facts_tag(name: str) -> str:
    return "#h|" + name


def _host_names(target: _HostTarget) -> tuple[tuple[str, str], ...]:
    """``(domain, fqdn)`` for every host this target could be: its FQDN, or
    its bare name in each domain that could hold it."""
    if target.fqdn:
        return ((target.owner, target.fqdn),)
    if not target.short:
        return ()
    return tuple((d, f"{target.short}.{d}") for d in target.candidates)


def _compute_host_verdict(
    shell: Any,
    state: _AssetState,
    view: _DomainView,
    target: _HostTarget,
    purpose: ContactPurpose,
    *,
    smb: bool = False,
) -> tuple[AssetScopeVerdict, float, list[str]]:
    """``(verdict, valid_until, knowledge keys it read)``."""
    # Where the contact goes: the connect address, or the address itself when
    # the target is an address alone (also inside a partitioned list).
    goes_to = target.connect or (target.ips[0] if target.ips and not target.named else "")
    # The addresses of a target given as an address alone, kept apart from the
    # name the verdict may give it below (a recorded domain controller's).
    given_addresses = tuple(target.ips) if not target.named and not target.connect else ()
    matcher = state.matcher
    now = time.monotonic()
    expires = _NEVER
    more: list[str] = []
    # The directory server it is, by exact identity.
    server = _directory_server_for(
        shell, view, fqdn=target.fqdn, short=target.short, addresses=target.ips, domain=target.owner
    )
    if server is None and not target.named:
        # An address in the latest report of a recorded domain controller's
        # name is that domain controller's (another interface of it): the
        # knowledge the socket guard reads for the same address.
        for address in target.ips:
            server = _address_summary(state, view, address).dc
            if server is not None:
                more.append("@" + address)
                break
    dc_domain = dns_domain = ""
    server_ips: list[str] = []
    if server is not None:
        if server[2] == _ROLE_DC:
            dc_domain = server[0]
            dc_fqdn = ""
            for alias in server[1]:
                alias_ip = _ip_text(alias)
                if alias_ip:
                    server_ips.append(alias_ip)
                elif "." in _norm(alias) and not target.named:
                    dc_fqdn = _norm(alias)
            if dc_fqdn:
                # A domain controller known by its address: it is that named host.
                target = _HostTarget(
                    target.ips, target.connect, dc_fqdn, "", "", dc_domain, (), target.dn, target.sid
                )
        else:
            dns_domain = server[0]
    owner = target.owner
    short = target.short
    names = _host_names(target)
    own = {name for _domain, name in names}
    # What the session was told about every host this target could be: its
    # directory record, and every address ever reported for it (the deny side).
    records: dict[str, tuple[str, str]] = {}
    observed: set[str] = set()
    for _domain, name in names:
        facts = state.facts.get(("h", name))
        known = facts if facts is not None and facts.kind != _NO_DIRECTORY_RECORD else None
        records[name] = (target.dn or (known.dn if known else ""), target.sid or (known.sid if known else ""))
        observed.update(state.addresses_of(name))
    if short:
        observed.update(state.addresses_of(short))
    single = names[0][1] if len(names) == 1 else ""
    dn, sid = records[single] if single else (target.dn, target.sid)
    carried = [v4 for v4 in (_embedded_v4(ip) for ip in target.ips) if v4]
    all_addresses = tuple(dict.fromkeys((*target.ips, *carried, *sorted(observed), *server_ips)))
    dc_unconfirmed = False
    if dc_domain and goes_to:
        latest: set[str] = set()
        for _domain, name in names:
            latest.update(state.current_of(name))
        own_addresses = {*server_ips, *latest}
        if own_addresses and goes_to not in own_addresses:
            # Named as a domain controller, but the contact goes to an address
            # that is none of its recorded ones and is not in the latest report
            # of its name (the same knowledge the socket guard reads,
            # ``_AddressSummary.dc``): what a domain controller is allowed (the
            # directory plane, ``dc_access``) is not allowed to whatever
            # answers there. Judged as an ordinary host; the deny side above
            # still reads every address. If the allow-list then does not cover
            # it, that is for lack of knowledge (the address may be another
            # interface of this domain controller): not confirmed, never an
            # established exclusion.
            dc_domain = ""
            dc_unconfirmed = True
        elif goes_to not in server_ips and (purpose not in _DIRECTORY_PLANE or smb):
            # An address only REPORTED for the domain controller's name (never
            # recorded as its address) counts for directory traffic alone. A
            # host contact there is not a contact with a known domain
            # controller, whatever ``dc_access`` says: a name service answer
            # must not open a host to assessment. That holds for every form of
            # the target (a connect address, the address alone, an address in
            # a list), and for anything over SMB, directory reads included:
            # the socket guard lets nothing through to port 445 there, so the
            # check answers "not confirmed" instead of allowing a connection
            # the guard would stop.
            dc_domain = ""
            dc_unconfirmed = True
    more.extend("@" + address for address in all_addresses)
    identity = AssetIdentity(
        kind=_COMPUTER if target.named else "",
        object_id=sid,
        domain=owner or dc_domain or dns_domain,
        dn=dn,
        fqdn=target.fqdn or (f"{short}.{owner}" if short and owner else ""),
        samaccountname=f"{(target.fqdn.split('.', 1)[0] if target.fqdn else short)}$" if target.named else "",
        netbios=view.netbios_of.get(owner, ""),
        addresses=tuple(sorted(all_addresses)),
    )

    # Rule 3: deny wins, over every reading.
    for address in all_addresses:
        hit = matcher.deny_address_entry(address)
        if hit:
            return _verdict(ScopeOutcome.REFUSED, ASSET_REASON_DENIED, identity, hit), _NEVER, more
    readings: list[AssetIdentity] = []
    if target.fqdn:
        readings.append(_host_reading(view, target, owner, strict=False, record=records[target.fqdn]))
    elif short:
        bare = _host_reading(view, target, "", strict=False)
        if not names or not (owner or target.qualifier):
            # Nothing says which domain: the bare label, in any namespace.
            readings.append(bare)
        readings.extend(
            _host_reading(view, target, d, strict=False, record=records[name]) for d, name in names
        )
    elif target.dn or target.sid:
        readings.append(AssetIdentity(object_id=target.sid, dn=target.dn))
    for reading in readings:
        hit = matcher.match_deny(reading)
        if hit:
            return _verdict(ScopeOutcome.REFUSED, ASSET_REASON_DENIED, identity, hit), _NEVER, more
    # Every name one of its addresses was ever reported under: the address may
    # be that host's (an alias, or the address moved). Read once per address
    # (its summary), whatever the number of names sharing it; the verdict
    # depends on the address's epoch (``more`` above), not on each name.
    summaries = [_address_summary(state, view, address) for address in all_addresses]
    for summary in summaries:
        if summary.deny_hit:
            return (
                _verdict(ScopeOutcome.REFUSED, ASSET_REASON_DENIED, identity, summary.deny_hit),
                _NEVER,
                more,
            )
    if short and target.qualifier:
        # The qualifier as written (an entry written the same way), without the
        # match by label alone: the readings above carry each candidate domain.
        as_written = AssetIdentity(
            **{**_host_reading(view, target, "", strict=False).__dict__, "netbios": target.qualifier}
        )
        hit = matcher.match_deny(as_written, by_label=False)
        if hit:
            return _verdict(ScopeOutcome.REFUSED, ASSET_REASON_DENIED, identity, hit), _NEVER, more
    # An address alone is attributed while a host with a directory record was
    # reported at it recently (a bare alias attributes nothing: it may be
    # another name of a host nobody located).
    attributed = bool(target.ips) and not target.named
    if attributed:
        for address in target.ips:
            here = _address_summary(state, view, address)
            seen = state.reported_within(
                address,
                here.current & here.recorded,
                now - _ALLOW_ADDRESS_TTL_SECONDS + _TTL_EPSILON,
            )
            if not seen:
                attributed = False
                break
            expires = min(expires, max(seen) + _ALLOW_ADDRESS_TTL_SECONDS)

    # Rule 4: the domain scope.
    if target.named and owner and not domain_in_engagement_scope(shell, owner):
        return _verdict(ScopeOutcome.REFUSED, ASSET_REASON_DOMAIN_OUTSIDE, identity), _NEVER, more

    # Rules 5 and 6: directory servers.
    if dns_domain and not dc_domain and purpose is ContactPurpose.NAME_RESOLUTION:
        return _verdict(ScopeOutcome.ALLOWED, ASSET_REASON_ALLOWED, identity), _NEVER, more
    skip_allow = False
    if dc_domain:
        if purpose in _DIRECTORY_PLANE:
            return _verdict(ScopeOutcome.ALLOWED, ASSET_REASON_ALLOWED, identity), _NEVER, more
        skip_allow = state.scope.dc_access == asset_model.DC_ACCESS_FULL

    # Rule 7: the allow-list must cover every reading that could be true.
    entry_id = ""
    if matcher.allow_applies_to_hosts and not skip_allow:
        entry_id, granted_until, cause = _host_allowed(
            shell, state, view, target, names, records, now, given_addresses=given_addresses
        )
        if not entry_id:
            if dc_domain:
                return (
                    _verdict(ScopeOutcome.REFUSED, ASSET_REASON_DC_DIRECTORY_ONLY, identity),
                    _NEVER,
                    more,
                )
            if cause:
                return _undetermined(identity, cause), granted_until, more
            if dc_unconfirmed:
                return _undetermined(identity, CAUSE_ADDRESS_NOT_ATTRIBUTED), granted_until, more
            return (
                _verdict(ScopeOutcome.REFUSED, ASSET_REASON_NOT_IN_ALLOW, identity),
                granted_until,
                more,
            )
        expires = min(expires, granted_until)

    # Rule 8: fail closed only while a denied host could still be this target.
    open_tree, pending_sid = state.deny_open_subtrees, state.deny_pending_sids
    if not target.named:
        if not (target.dn or target.sid or attributed) and (
            state.deny_unattributed_hosts or open_tree or pending_sid
        ):
            return _undetermined(identity, CAUSE_ADDRESS_NOT_ATTRIBUTED), _NEVER, more
        if not attributed and ((open_tree and not target.dn) or (pending_sid and not target.sid)):
            return _undetermined(identity, CAUSE_ENTRY_NOT_MATCHED), _NEVER, more
    else:
        # The hosts it could really be: a bare name is one host per domain
        # that could hold it, less the ones the directory says do not exist
        # (no record there, and no address ever reported for the name).
        live = [name for _domain, name in names if not _candidate_absent(state, name)] or [
            name for _domain, name in names
        ]
        known_record = {name: records[name] for name in live}
        if not target.ips and not server_ips:
            # A deny rule matched by ADDRESS: a host with a directory record
            # must have a known address while a deny address ENTRY exists (it
            # may sit inside it); a name with no record, while any denied
            # address is known (it may be another name of that denied host).
            # With a connect address the caller says where the contact goes.
            for name in live:
                if state.addresses_of(name) or (
                    len(live) == 1 and short and state.addresses_of(short)
                ):
                    continue
                has_record = bool(known_record[name][0] or known_record[name][1])
                if matcher.has_deny_address_entries or (
                    not has_record and matcher.has_deny_address_rules
                ):
                    return _undetermined(identity, CAUSE_NAME_NOT_RESOLVED), _NEVER, more
            if not live and matcher.has_deny_address_rules:
                return _undetermined(identity, CAUSE_NAME_NOT_RESOLVED), _NEVER, more
        lacks_record = not live or any(not (d or s) for d, s in known_record.values())
        if state.deny_unattributed_hosts and lacks_record and not dc_domain:
            # A denied host nobody located yet, and a target known only by a
            # name: the name may be another name of that host (a DNS alias).
            return _undetermined(identity, CAUSE_ENTRY_NOT_MATCHED), _NEVER, more
        lacks_dn = not live or any(not d for d, _s in known_record.values())
        lacks_sid = not live or any(not s for _d, s in known_record.values())
        if (open_tree and lacks_dn) or (pending_sid and lacks_sid):
            return _undetermined(identity, CAUSE_ENTRY_NOT_MATCHED), _NEVER, more
    if open_tree or pending_sid:
        mine = {*own, short} if short else own
        for summary in summaries:
            # ANOTHER host reported at one of this target's addresses whose
            # place in the directory is not known: it may be an excluded one.
            if (open_tree and any(name not in mine for name in summary.no_dn)) or (
                pending_sid and any(name not in mine for name in summary.no_sid)
            ):
                return _undetermined(identity, CAUSE_ENTRY_NOT_MATCHED), _NEVER, more
    return _verdict(ScopeOutcome.ALLOWED, ASSET_REASON_ALLOWED, identity, entry_id), expires, more


@dataclass(frozen=True)
class _AddressSummary:
    """What the names reported at ONE address say about it.

    Computed once per change of that address's knowledge (its epoch, which
    moves when a name reported there gains an address, a newer report or a
    directory record) and read by every verdict and every guard check that
    touches the address. So the cost of a verdict does not grow with the
    number of names sharing an address (a name service that redirects unknown
    names, a shared virtual address, years of stale records), and a cached
    verdict depends on the address's epoch instead of on each of those names.
    """

    #: the deny entry some name reported here matches (``""``: none)
    deny_hit: str = ""
    #: every name ever reported here
    names: frozenset[str] = frozenset()
    #: the names whose LATEST report still holds this address
    current: frozenset[str] = frozenset()
    #: the names that belong to the engagement (a bare label, or under a known domain)
    engagement: frozenset[str] = frozenset()
    #: the names an allow entry certainly names
    allowed: frozenset[str] = frozenset()
    #: the names with a directory record (a DN or a SID)
    recorded: frozenset[str] = frozenset()
    #: directory hosts reported here whose DN, or SID, the session does not hold
    no_dn: frozenset[str] = frozenset()
    no_sid: frozenset[str] = frozenset()
    #: the recorded directory server AT this address (a DC or a DNS server)
    server: Any = None
    #: the recorded domain controller this address belongs to: one of its
    #: recorded addresses, or an address in the latest report of its recorded
    #: name. The primary check and the socket guard both read THIS.
    dc: Any = None


_NO_ADDRESS_SUMMARY = _AddressSummary()
#: ``now - when < TTL`` written as ``when >= now - TTL + epsilon`` (the report
#: exactly one window old is no longer fresh).
_TTL_EPSILON = 1e-9
_ADDRESS_MEMO_MAX = 100_000


def _address_summary(state: _AssetState, view: _DomainView, address: str) -> _AddressSummary:
    """The memoised :class:`_AddressSummary` of ``address`` (a read)."""
    with state._lock:  # noqa: SLF001 - the state's own lock
        key = (state.version, state._gen.get("@" + address, 0))  # noqa: SLF001
        held = state._addr_memo.get(address)  # noqa: SLF001
        if held is not None and held[0] == key:
            return held[1]
        matcher = state.matcher
        reports = state.addr_names.get(address)
        names = list(reports) if reports else []
        current = frozenset(n for n in names if address in (state.name_current.get(n) or ()))
        facts = {n: state.facts.get(("h", n)) for n in names}
        others = {n: tuple(state.name_addrs.get(n) or ()) for n in names}
    server = _pick_server_in_view(view, view.by_ip.get(address, ()))
    if not names and server is None:
        return _NO_ADDRESS_SUMMARY
    deny_hit = ""
    for name in names:
        for reading in _name_readings(name, others[name], view, facts[name]):
            deny_hit = matcher.match_deny(reading)
            if deny_hit:
                break
        if deny_hit:
            break
    known = list(view.known)
    engagement = frozenset(n for n in names if "." not in n or _longest_known_suffix(n, known))
    allowed: frozenset[str] = frozenset()
    if matcher.allow_applies_to_hosts:
        allowed = frozenset(
            n
            for n in names
            if any(
                matcher.match_allow(reading, addresses=False)
                for reading in _name_readings(n, (), view, facts[n], strict=True)
            )
        )
    recorded: set[str] = set()
    no_dn: set[str] = set()
    no_sid: set[str] = set()
    for name in names:
        record = facts[name]
        if record is not None and record.kind != _NO_DIRECTORY_RECORD and (record.dn or record.sid):
            recorded.add(name)
        if "." not in name or (record is not None and record.kind == _NO_DIRECTORY_RECORD):
            continue  # not a directory host: it sits under no unit and holds no SID
        if not (record and record.dn):
            no_dn.add(name)
        if not (record and record.sid):
            no_sid.add(name)
    dc = server if server is not None and server[2] == _ROLE_DC else None
    if dc is None:
        for name in names:
            if name in current and "." in name:
                found = _pick_server_in_view(view, view.by_fqdn.get(name, ()))
                if found is not None and found[2] == _ROLE_DC:
                    dc = found
                    break
    summary = _AddressSummary(
        deny_hit=deny_hit,
        names=frozenset(names),
        current=current,
        engagement=engagement,
        allowed=allowed,
        recorded=frozenset(recorded),
        no_dn=frozenset(no_dn),
        no_sid=frozenset(no_sid),
        server=server,
        dc=dc,
    )
    with state._lock:  # noqa: SLF001
        if (state.version, state._gen.get("@" + address, 0)) == key:  # noqa: SLF001
            memo = state._addr_memo  # noqa: SLF001
            memo[address] = (key, summary)
            memo.move_to_end(address)
            while len(memo) > _ADDRESS_MEMO_MAX:
                memo.popitem(last=False)
    return summary


def _allowed_by_name(state: _AssetState, view: _DomainView, name: str) -> str:
    """The allow entry that certainly names the host a knowledge key names."""
    for reading in _name_readings(name, (), view, state.facts.get(("h", name)), strict=True):
        entry = state.matcher.match_allow(reading, addresses=False)
        if entry:
            return entry
    return ""


def _held_by_another_host(
    state: _AssetState, view: _DomainView, address: str, own: Iterable[str]
) -> bool:
    """``address`` is in the LATEST report of a host other than the target's
    own names, one the allow-list does not name: the caller's connect address
    is not (or no longer) the allowed host's."""
    mine = {name for name in own if name}
    # A bare label and its FQDN are the same host.
    labels = {name.split(".", 1)[0] for name in mine}
    here = _address_summary(state, view, address)
    for name in here.current - here.allowed:
        if name in mine or ("." not in name and name in labels):
            continue
        return True
    return False


def _reported_elsewhere_since(
    state: _AssetState, view: _DomainView, address: str, since: float
) -> bool:
    """A resolver reported ``address`` under a host the allow-list does not
    name, at or after ``since`` (when the allow name was resolved to it): the
    address may have moved to that host, so the name's resolution grants it
    no longer."""
    here = _address_summary(state, view, address)
    return bool(state.reported_within(address, here.names - here.allowed, since))


def _no_directory_record(state: _AssetState, name: str) -> bool:
    """The collected directory was asked and holds no computer of this name."""
    facts = state.facts.get(("h", name))
    return facts is not None and facts.kind == _NO_DIRECTORY_RECORD


def _candidate_absent(state: _AssetState, name: str) -> bool:
    """One of the hosts a bare or qualified name could be does not exist: the
    collected directory holds no such computer AND the name was looked up and
    answered nothing. Never assumed from a lookup nobody made."""
    return (
        _no_directory_record(state, name)
        and name in state.looked_up
        and not state.addresses_of(name)
    )


def _has_directory_record(state: _AssetState, name: str) -> bool:
    facts = state.facts.get(("h", name))
    return bool(facts is not None and facts.kind != _NO_DIRECTORY_RECORD and (facts.dn or facts.sid))


def _recorded_controller_addresses(view: _DomainView, name: str) -> frozenset[str]:
    """The recorded addresses of the domain controller called ``name`` (empty: none).

    The addresses the session holds for a controller without any name lookup:
    the ones the directory and the configured controller address recorded
    (``_DomainView.by_fqdn``). Nothing is looked up.
    """
    server = _pick_server_in_view(view, view.by_fqdn.get(name, ()))
    if server is None or server[2] != _ROLE_DC:
        return frozenset()
    return frozenset(address for address in (_ip_text(alias) for alias in server[1]) if address)


def _host_allowed(
    shell: Any,
    state: _AssetState,
    view: _DomainView,
    target: _HostTarget,
    names: tuple[tuple[str, str], ...],
    records: Mapping[str, tuple[str, str]],
    now: float,
    given_addresses: tuple[str, ...] = (),
) -> tuple[str, float, str]:
    """``(entry, granted_until, cause)``: the allow entry that covers the target.

    ``given_addresses`` are the addresses of a target that was given as an
    address alone and that the verdict named after the recorded domain
    controller at it.

    ``entry`` is ``""`` when nothing does; ``cause`` then says why that is not
    an established exclusion (``""``: it is one). ``names`` are the hosts the
    target could be. A named target is inside an allow ADDRESS entry when, for
    EVERY host it could be, every address of that host's latest report is (if
    the host has moved since, the connection itself is refused at the wire).
    An address-only target is granted by an allow NAME only while that name's
    own resolution is fresh: nothing at the wire could tell the two hosts
    apart.
    """
    matcher = state.matcher
    not_established = ""
    could_be: tuple[tuple[str, str], ...] = ()
    if state.allow_pending:
        not_established = CAUSE_ENTRY_NOT_MATCHED
    # By name: every reading that could be the true one.
    if target.named:
        own_name = f"{target.short}.{target.owner}" if target.short and target.owner else ""
        if target.fqdn or (target.owner and not target.qualifier):
            could_be = ((target.owner, target.fqdn or own_name),)
        elif own_name and _has_directory_record(state, own_name):
            # ``NETBIOS\\name`` and the domain called that holds the host: it
            # is that host (the NetBIOS name wins over a first label).
            could_be = ((target.owner, own_name),)
        else:
            # A bare name, or ``QUALIFIER\\name``: a caller may write a
            # domain's first label where its NetBIOS name is meant, so every
            # domain the qualifier could denote must be covered.
            if not target.qualifier:
                unique = matcher.allow_unique_short(target.short)
                if unique and not (
                    target.connect
                    and _held_by_another_host(state, view, target.connect, {target.short})
                ):
                    return unique, _NEVER, ""
            could_be = tuple(
                (d, n)
                for d, n in names
                if domain_in_engagement_scope(shell, d) and not _candidate_absent(state, n)
            )
            if len(could_be) != 1 and not not_established:
                # A bare name several domains (or none) could hold.
                not_established = CAUSE_NAME_NOT_RESOLVED
        hits = [
            matcher.match_allow(
                _host_reading(view, target, d, strict=True, record=records.get(n)), addresses=False
            )
            for d, n in could_be
        ]
        if hits and all(hits):
            if not target.connect or not _held_by_another_host(
                state, view, target.connect, {n for _d, n in could_be} | {target.short}
            ):
                return hits[0], _NEVER, ""
            # The name is allowed, but the address the contact goes to is in
            # the latest report of ANOTHER host the allow-list does not name:
            # only an allow address entry can cover it.
            if not not_established:
                not_established = CAUSE_ADDRESS_NOT_ATTRIBUTED
        if (
            state.allow_open_subtrees
            and not not_established
            and any(not (records.get(n) or ("", ""))[0] for _d, n in could_be)
        ):
            not_established = CAUSE_ENTRY_NOT_MATCHED
    else:
        if target.dn or target.sid:
            hit = matcher.match_allow(
                AssetIdentity(object_id=target.sid, dn=target.dn), addresses=False
            )
            if hit:
                return hit, _NEVER, ""
        if state.allow_open_subtrees and not target.dn and not not_established:
            not_established = CAUSE_ENTRY_NOT_MATCHED
    # By address: every address the contact goes to.
    contact: list[str] = []
    if target.connect:
        contact = [target.connect]
    elif not target.named:
        contact = list(target.ips)
    elif given_addresses:
        # An address alone that the verdict attributed to the recorded domain
        # controller at it (the target then carries the controller's name): the
        # contact goes to that address, so that address is what an allow
        # address entry must cover, whether or not a lookup of the controller's
        # name was reported first. Reading the name's latest report here made
        # the answer depend on call order: refused before the lookup, allowed
        # after it.
        contact = list(given_addresses)
    else:
        for _domain, name in could_be:
            latest = state.current_of(name)
            if not latest and len(could_be) == 1 and target.short:
                latest = state.current_of(target.short)
            if not latest:
                # A recorded domain controller's addresses are known before any
                # lookup of its name (the directory and the configured address
                # recorded them): they stand until a lookup reports others.
                latest = _recorded_controller_addresses(view, name)
            if not latest:
                contact = []
                break
            contact.extend(sorted(latest))
    if not contact:
        if target.named and matcher.has_allow_address_entries and not not_established:
            # Its address is not known, and it may be inside an allowed range.
            not_established = CAUSE_NAME_NOT_RESOLVED
        return "", _NEVER, not_established
    granted_until = _NEVER
    first = ""
    for address in contact:
        hit = matcher.allow_address_entry(address)
        until = _NEVER
        if not hit and not target.named:
            # An allow NAME's own resolution, while it is fresh.
            resolved = matcher.allow_resolved_address_entry(address)
            fresh_until = state.allow_fresh_until.get(resolved, 0.0) if resolved else 0.0
            if (
                resolved
                and now < fresh_until
                and not _reported_elsewhere_since(
                    state, view, address, fresh_until - _ALLOW_ADDRESS_TTL_SECONDS
                )
            ):
                hit, until = resolved, fresh_until
            elif not not_established and (
                resolved or _address_summary(state, view, address).allowed
            ):
                # An allowed name stands behind this address, but not through
                # that name's own fresh resolution: an address a resolver
                # reported never widens an allow NAME. Not an established
                # exclusion either (the seam that knows the name is granted).
                not_established = CAUSE_ENTRY_NOT_MATCHED
        if not hit:
            return "", _NEVER, not_established
        first = first or hit
        granted_until = min(granted_until, until)
    return first, granted_until, ""


# ── Principals ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _PrincipalTarget:
    """A principal label as written, read every way it can be read."""

    sam: str = ""
    sid: str = ""
    dn: str = ""
    upn: str = ""
    qualifier: str = ""
    fqdn: str = ""
    fqdn_certain: bool = False
    owner: str = ""
    generous: tuple[str, ...] = ()


def _parse_principal(view: _DomainView, principal: str, hint: str) -> _PrincipalTarget:
    """Read a principal label in any form the product writes.

    ``S-1-...`` is a SID, ``CN=...`` a DN, ``QUALIFIER\\name`` an account whose
    domain is certain only for a recorded NetBIOS name, ``name@realm`` an
    account of that realm (also its implicit UPN). A bare dotted label is an
    account name (``john.smith``) AND, for the deny side, possibly a
    computer's FQDN; it is certainly an FQDN only when its suffix is a known
    domain.
    """
    text = str(principal or "").strip()
    if text.upper().startswith("S-1-"):
        sid = text.split("@", 1)[0].upper()
        # A SID says which domain its object is in (the recorded domain SID).
        return _PrincipalTarget(sid=sid, owner=view.sid_domain(sid) or hint)
    if re.match(r"(?i)^\s*(CN|OU|DC)\s*=", text):
        owner = _domain_from_dn(text) or hint
        return _PrincipalTarget(dn=text, owner=owner, generous=(owner,) if owner else ())
    lowered = _norm(text)
    if "\\" in lowered:
        qualifier, _, sam = lowered.partition("\\")
        strict = _qualifier_domains(view, qualifier, generous=False)
        owner = strict[0] if len(strict) == 1 else hint
        generous = _qualifier_domains(view, qualifier, generous=True)
        if owner:
            generous = tuple(dict.fromkeys((owner, *generous)))
        return _PrincipalTarget(sam=sam.strip(), qualifier=qualifier, owner=owner, generous=generous)
    if "@" in lowered:
        sam, _, realm = lowered.partition("@")
        sam = sam.strip()
        if not realm or realm in _PLACEHOLDERS:
            return _PrincipalTarget(sam=sam, owner=hint, generous=(hint,) if hint else view.known)
        if realm in view.known:
            owner = realm
        else:
            owner = hint or realm
        generous = tuple(dict.fromkeys((owner, realm)))
        return _PrincipalTarget(sam=sam, upn=f"{sam}@{realm}", owner=owner, generous=generous)
    if not lowered:
        return _PrincipalTarget(owner=hint)
    if "." in lowered and lowered not in view.known:
        suffix = _longest_known_suffix(lowered, list(view.known))
        return _PrincipalTarget(
            sam=lowered,
            fqdn=lowered,
            fqdn_certain=bool(suffix),
            owner=hint,
            generous=(hint,) if hint else view.known,
        )
    return _PrincipalTarget(sam=lowered, owner=hint, generous=(hint,) if hint else view.known)


def principal_scope_verdict(
    shell: Any,
    *,
    principal: str | None,
    domain: str | None = None,
    dn: str | None = None,
    sid: str | None = None,
    dnshostname: str | None = None,
    kind: str | None = None,
    path_domain: str | None = None,
    affected_hosts: Iterable[Any] | None = None,
) -> AssetScopeVerdict:
    """May the scan act ON or AS this directory object (any kind)?

    A READ: in-memory state only. The object's ``kind`` is what the caller
    knows from directory data (a step's ``target_kind``, a list built from a
    user query) or what :func:`prepare_scope_principals` told the session; a
    verdict never looks it up, and never reads it from the shape of the name.

    * DENY asks every reading of the label: the SID, the DN (and every subtree
      entry above it), ``qualifier\\name`` in every domain the qualifier could
      denote, the UPN (also the implicit ``name@domain``), and for a computer
      its FQDN and every address ever reported for it. A denied computer is
      also a denied principal (an RBCD write on ``FS01$`` touches the object
      even if no packet reaches the host).
    * The DOMAIN scope is asked with ``path_domain``, the domain the route
      being walked was computed for (:func:`domain_scope_verdict`).
    * While a host deny entry or a host allow-list is in force, an object whose
      CHANGE REACHES HOSTS (a GPO, an OU or container, a certificate template
      or authority) is UNDETERMINED (cause ``affected_hosts_unknown``) unless
      the hosts it reaches are known and none is excluded: ``affected_hosts``
      when the caller knows them (each is judged as a host), or, for an OU or
      container, when every denied host's place in the directory is known and
      none sits below it (and an allow-list covers it as a subtree). An object
      whose kind is not known is UNDETERMINED too, unless it has a SID (only
      accounts do).
    * ALLOW-lists apply per reach (a host list governs computers, an account
      list governs users and groups, an object of unknown kind must pass
      whichever applies) and must cover the object in the domain it certainly
      belongs to. An object that is not covered is REFUSED
      ``not_in_allow_list`` when it is established, UNDETERMINED when it is
      not (its kind, its domain or a pending entry).

    ``shell=None`` falls back to the registered session.
    """
    shell = _session(shell)
    state = _asset_state(shell)
    if state is None:
        return _ALLOWED_NO_SCOPE
    if state.broken:
        return _unreadable_verdict("principal")
    hosts = None if affected_hosts is None else tuple(str(h or "") for h in affected_hosts)
    known_kind = str(kind or "").strip().lower()
    key = (
        "p",
        _norm(principal),
        _norm(domain),
        _norm(dn),
        _norm(sid),
        _norm(dnshostname),
        known_kind,
        _norm(path_domain),
        hosts,
    )
    view = _domain_view(shell, state)
    version = state.version
    cached = state.cache_get(key)
    if cached is not None:
        return cached
    facts_key = _principal_facts_key(str(principal or ""), _norm(domain))
    host_key = _norm(dnshostname)
    read = ["#" + "|".join(facts_key)]
    if host_key:
        read.append(host_key)
    verdict = _unreadable_verdict("principal")
    for _attempt in range(_VERDICT_ATTEMPTS):
        epoch = state.kb_version
        verdict, expires, more = _compute_principal_verdict(
            shell,
            state,
            view,
            principal=str(principal or ""),
            domain=_norm(domain),
            dn=str(dn or ""),
            sid=str(sid or "").strip().upper(),
            dnshostname=host_key,
            kind=known_kind,
            path_domain=_norm(path_domain),
            affected_hosts=hosts,
        )
        if state.cache_put_if_current(
            key, version, verdict, epoch=epoch, expires=expires, names=(*read, *more)
        ):
            break
    return verdict


def _domain_object_verdict(state: _AssetState, shell: Any, name: str) -> AssetScopeVerdict:
    """The domain object: denied by its ``DC=`` DN or its SID, else allowed."""
    identity = AssetIdentity(
        kind="domain",
        object_id=_domain_sid_of(shell, name),
        domain=name,
        dn=",".join(f"DC={label}" for label in name.split(".") if label),
    )
    hit = state.matcher.match_deny(identity)
    if hit:
        return _verdict(ScopeOutcome.REFUSED, ASSET_REASON_DENIED, identity, hit, "domain")
    if state.deny_pending_sids and not identity.object_id:
        # A denied SID still waiting for the directory may be this domain's.
        return _undetermined(identity, CAUSE_ENTRY_NOT_MATCHED, "domain")
    return _verdict(ScopeOutcome.ALLOWED, ASSET_REASON_ALLOWED, identity, kind="domain")


def _compute_principal_verdict(
    shell: Any,
    state: _AssetState,
    view: _DomainView,
    *,
    principal: str,
    domain: str,
    dn: str,
    sid: str,
    dnshostname: str,
    kind: str,
    path_domain: str,
    affected_hosts: tuple[str, ...] | None,
) -> tuple[AssetScopeVerdict, float, list[str]]:
    matcher = state.matcher
    target = _parse_principal(view, principal, domain)
    dn = dn or target.dn
    sid = sid or target.sid
    label = _norm(principal)
    dn_domain = _domain_from_dn(dn)
    if label in view.known or (
        dn and all(part.strip().upper().startswith("DC=") for part in dn.split(","))
    ):
        name = label if label in view.known else dn_domain
        return _domain_object_verdict(state, shell, name), _NEVER, []
    facts = state.facts.get(_principal_facts_key(principal, domain))
    upn = target.upn
    upn_known = False
    recorded_fqdn = ""
    if facts is not None:
        kind = kind or facts.kind
        dn = dn or facts.dn
        sid = sid or facts.sid
        if facts.upn:
            upn, upn_known = facts.upn, True
        if facts.kind == _COMPUTER:
            recorded_fqdn = _norm(facts.fqdn)
        dn_domain = _domain_from_dn(dn)
    sam = target.sam
    fqdn = (
        dnshostname
        or recorded_fqdn
        or (target.fqdn if (target.fqdn_certain or kind == _COMPUTER) else "")
    )
    if fqdn and (dnshostname or kind == _COMPUTER) and (not sam or sam == fqdn):
        sam = f"{fqdn.split('.', 1)[0]}$"
    if not sam and not sid and not dn:
        return _undetermined(None, "", "principal"), _NEVER, []
    shown_kind = kind or "principal"

    # Which domain it certainly belongs to, and which it could.
    owner = dn_domain or target.owner
    if fqdn and not dn_domain and (
        dnshostname or recorded_fqdn or kind == _COMPUTER or target.fqdn_certain
    ):
        owner = _longest_known_suffix(fqdn, list(view.known)) or owner or fqdn.partition(".")[2]
    generous = tuple(d for d in dict.fromkeys((owner, *target.generous)) if d)
    if owner and (dn_domain or (fqdn and (dnshostname or kind == _COMPUTER or target.fqdn_certain))):
        # Its DN or its host name says which domain it is in.
        generous = (owner,)
    primary = _norm(getattr(shell, "domain", ""))
    if owner:
        scope_domains: tuple[str, ...] = (owner,)
    elif target.qualifier:
        # A qualifier no recorded NetBIOS name answers to: every domain it
        # could denote must be in scope.
        scope_domains = generous
    else:
        scope_domains = (primary,) if primary else ()
    scope_domain = scope_domains[0] if len(scope_domains) == 1 else ""
    is_computer = kind == _COMPUTER or (not kind and sam.endswith("$"))
    host_names: list[str] = []
    if fqdn:
        host_names.append(fqdn)
    elif is_computer and sam.endswith("$"):
        host_names.extend(f"{sam[:-1]}.{d}" for d in (generous or ()))
    elif kind == _COMPUTER and dn_domain:
        # A computer known only by its DN: the name it most likely answers to
        # (its common name under its domain), for the deny side.
        common_name = asset_model._split_dn(dn)[0].partition("=")[2].strip().lower()  # noqa: SLF001
        if common_name and "." not in common_name:
            host_names.append(f"{common_name}.{dn_domain}")
    observed: set[str] = set()
    for name in host_names:
        observed.update(state.addresses_of(name))
    addresses = tuple(sorted(observed))
    identity = AssetIdentity(
        kind=kind,
        object_id=sid,
        domain=scope_domain,
        dn=dn,
        fqdn=fqdn if kind in ("", _COMPUTER) else "",
        samaccountname=sam,
        netbios=target.qualifier or view.netbios_of.get(scope_domain, ""),
        upn=upn,
        addresses=addresses,
    )

    # Deny wins, over every reading.
    readings: list[AssetIdentity] = []
    account_readings: list[AssetIdentity] = []
    for candidate in generous or ("",):
        account_readings.append(
            AssetIdentity(
                kind=kind,
                object_id=sid,
                domain=candidate,
                dn=dn,
                samaccountname=sam,
                netbios=view.netbios_of.get(candidate, ""),
                upn=upn,
            )
        )
    if target.qualifier:
        account_readings.append(AssetIdentity(kind=kind, samaccountname=sam, netbios=target.qualifier))
    # A computer account in a known domain is read as a HOST below, under the
    # name it has there; matching it by its label alone would also catch a
    # host of the same name in another domain.
    by_label = not (host_names and all(generous))
    for reading in account_readings:
        hit = matcher.match_deny(reading, by_label=by_label)
        if hit:
            return (
                _verdict(ScopeOutcome.REFUSED, ASSET_REASON_DENIED, identity, hit, shown_kind),
                _NEVER,
                host_names,
            )
    if kind in ("", _COMPUTER):
        for name in host_names:
            readings.append(
                AssetIdentity(
                    kind=_COMPUTER,
                    fqdn=name,
                    samaccountname=f"{name.split('.', 1)[0]}$",
                    addresses=tuple(sorted(state.addresses_of(name))),
                )
            )
        if target.fqdn and not target.fqdn_certain and not kind:
            # ``john.smith`` could be a host called john in a domain smith:
            # a reading for the deny side only.
            readings.append(
                AssetIdentity(
                    kind=_COMPUTER,
                    fqdn=target.fqdn,
                    samaccountname=f"{target.fqdn.split('.', 1)[0]}$",
                    addresses=tuple(sorted(state.addresses_of(target.fqdn))),
                )
            )
    for reading in readings:
        hit = matcher.match_deny(reading)
        if hit:
            return (
                _verdict(ScopeOutcome.REFUSED, ASSET_REASON_DENIED, identity, hit, shown_kind),
                _NEVER,
                host_names,
            )

    # The domain scope, with the route's own domain.
    outside = [
        d
        for d in scope_domains
        if not domain_in_engagement_scope(shell, d, path_domain=path_domain or None)
    ]
    if not scope_domains or (outside and len(outside) < len(scope_domains)):
        # Its domain could not be established.
        return _undetermined(identity, "", shown_kind), _NEVER, host_names
    if outside:
        return (
            _verdict(
                ScopeOutcome.REFUSED,
                ASSET_REASON_DOMAIN_OUTSIDE,
                identity,
                kind=shown_kind,
                domain=outside[0],
            ),
            _NEVER,
            host_names,
        )

    # Objects whose change reaches hosts, and objects of unknown kind.
    expires = _NEVER
    host_restricted = matcher.deny_applies_to_hosts or matcher.allow_applies_to_hosts
    reaches_hosts = kind in HOST_REACHING_KINDS
    if host_restricted and (reaches_hosts or (not kind and not sid)):
        if not reaches_hosts:
            # Its kind is not known: it may be an object whose change reaches hosts.
            return _undetermined(identity, "", shown_kind), _NEVER, host_names
        refusal, expires = _hosts_reached_verdict(
            shell, state, identity, kind, shown_kind, affected_hosts
        )
        if refusal is not None:
            return refusal, expires, host_names
    could_be_computer = is_computer or (not kind and not sam)
    if (
        host_restricted
        and could_be_computer
        and (
            matcher.has_deny_address_entries
            or (matcher.has_deny_address_rules and not (sid or dn))
        )
        and (not host_names or any(not state.addresses_of(name) for name in host_names))
    ):
        # A computer whose addresses nobody reported (under every name it
        # could have), while a deny rule is matched by address: it may be
        # that host.
        return _undetermined(identity, CAUSE_NAME_NOT_RESOLVED, shown_kind), _NEVER, host_names

    # Allow-lists, per reach.
    if kind == _COMPUTER:
        applies = matcher.allow_applies_to_hosts
    elif kind:
        applies = matcher.allow_applies_to_principals
    else:
        applies = matcher.allow_applies_to_hosts or matcher.allow_applies_to_principals
    entry_id = ""
    if applies:
        entry_id, granted_until, cause = _principal_allowed(
            shell,
            state,
            view,
            identity,
            owner,
            generous,
            kind,
            bool(target.qualifier),
            host_names,
            facts.holders if facts is not None else None,
        )
        if not entry_id:
            if cause or not kind:
                return _undetermined(identity, cause, shown_kind), _NEVER, host_names
            return (
                _verdict(ScopeOutcome.REFUSED, ASSET_REASON_NOT_IN_ALLOW, identity, kind=shown_kind),
                _NEVER,
                host_names,
            )
        expires = min(expires, granted_until)

    # A denied object could still be this one: an entry written in a form the
    # target does not carry, while the directory has not said who it is.
    if (not dn and state.deny_open_subtrees) or (not sid and state.deny_pending_sids):
        return _undetermined(identity, CAUSE_ENTRY_NOT_MATCHED, shown_kind), _NEVER, host_names
    if state.deny_pending_upns and kind in ("", "user", _COMPUTER) and not upn_known:
        return _undetermined(identity, CAUSE_ENTRY_NOT_MATCHED, shown_kind), _NEVER, host_names
    if state.deny_pending_names and not sam and not fqdn:
        return _undetermined(identity, CAUSE_ENTRY_NOT_MATCHED, shown_kind), _NEVER, host_names
    if state.deny_suffixes and kind in ("", _COMPUTER) and not host_names and not (kind == "" and sam):
        # A computer whose DNS name is not known may sit under a denied suffix.
        return _undetermined(identity, CAUSE_ENTRY_NOT_MATCHED, shown_kind), _NEVER, host_names
    pending_accounts = state.deny_pending_account_domains
    if (
        pending_accounts
        and target.upn
        and not upn_known
        and kind in ("", "user", _COMPUTER)
        and ("*" in pending_accounts or any(d in pending_accounts for d in generous))
    ):
        # A label written ``name@realm`` may be a UPN: the account behind a
        # denied entry the directory has not placed yet could carry it.
        return _undetermined(identity, CAUSE_ENTRY_NOT_MATCHED, shown_kind), _NEVER, host_names
    return (
        _verdict(ScopeOutcome.ALLOWED, ASSET_REASON_ALLOWED, identity, entry_id, shown_kind),
        expires,
        host_names,
    )


def _hosts_reached_verdict(
    shell: Any,
    state: _AssetState,
    identity: AssetIdentity,
    kind: str,
    shown_kind: str,
    affected_hosts: tuple[str, ...] | None,
) -> tuple[AssetScopeVerdict | None, float]:
    """``None`` when the hosts the object's change reaches are known and all in
    scope; otherwise the verdict that keeps the change from being made."""
    matcher = state.matcher
    if affected_hosts is not None:
        expires = _NEVER
        for host in affected_hosts:
            verdict = _host_verdict(
                shell,
                state,
                host=host,
                connect_address=None,
                purpose=ContactPurpose.HOST,
                domain=identity.domain,
                host_dn=None,
                host_sid=None,
            )
            if verdict.allowed:
                continue
            if verdict.outcome is ScopeOutcome.REFUSED:
                return (
                    _verdict(
                        ScopeOutcome.REFUSED, verdict.reason, identity, verdict.entry_id, shown_kind
                    ),
                    expires,
                )
            return _undetermined(identity, CAUSE_AFFECTED_HOSTS_UNKNOWN, shown_kind), expires
        return None, expires
    if kind in _SUBTREE_KINDS and identity.dn:
        try:
            dn_key = asset_model.canonical_dn(identity.dn).casefold()
        except ValueError:
            dn_key = ""
        below = state.deny_host_ancestors.get(dn_key, "") if dn_key else ""
        if below:
            # An excluded host sits below it: the change would reach that host.
            return (
                _verdict(ScopeOutcome.REFUSED, ASSET_REASON_DENIED, identity, below, shown_kind),
                _NEVER,
            )
        located = dn_key and (not matcher.deny_applies_to_hosts or state.deny_hosts_located)
        covered = not matcher.allow_applies_to_hosts or matcher.match_allow(
            AssetIdentity(dn=identity.dn), addresses=False
        )
        if located and covered:
            return None, _NEVER
    return _undetermined(identity, CAUSE_AFFECTED_HOSTS_UNKNOWN, shown_kind), _NEVER


def _principal_allowed(
    shell: Any,
    state: _AssetState,
    view: _DomainView,
    identity: AssetIdentity,
    owner: str,
    generous: tuple[str, ...],
    kind: str,
    qualified: bool = False,
    host_names: Iterable[str] = (),
    holders: tuple[str, ...] | None = None,
) -> tuple[str, float, str]:
    """``(entry, granted_until, cause)`` for a principal under an allow-list.

    ``qualified``: the label was written ``QUALIFIER\\name``; every domain the
    qualifier could denote must be covered (a caller may write a domain's first
    label where its NetBIOS name is meant).
    """
    matcher = state.matcher
    not_established = ""
    if state.allow_pending:
        not_established = CAUSE_ENTRY_NOT_MATCHED
    elif state.allow_open_subtrees and not identity.dn:
        not_established = CAUSE_ENTRY_NOT_MATCHED
    if identity.object_id or identity.dn or (owner and not qualified):
        domains: tuple[str, ...] = (owner,)
    elif owner and holders is not None and owner in holders:
        # ``NETBIOS\\name`` and the domain called that holds the account: it
        # is that account (the NetBIOS name wins over a first label).
        domains = (owner,)
    else:
        domains = tuple(
            d
            for d in generous
            if domain_in_engagement_scope(shell, d) and (holders is None or d in holders)
        )
        if len(domains) != 1 and not not_established:
            # A bare account name several domains could hold.
            not_established = CAUSE_ENTRY_NOT_MATCHED
    hits = []
    for candidate in domains:
        reading = AssetIdentity(
            kind=kind,
            object_id=identity.object_id,
            domain=candidate,
            dn=identity.dn,
            fqdn=(
                identity.fqdn
                or (f"{identity.samaccountname[:-1]}.{candidate}" if kind == _COMPUTER and candidate else "")
            ),
            samaccountname=identity.samaccountname,
            netbios=_strict_netbios(view, candidate),
            upn=identity.upn if candidate == owner else "",
        )
        hits.append(matcher.match_allow(reading, addresses=False))
    if hits and all(hits):
        return hits[0], _NEVER, ""
    # A computer inside an allow address entry: for EVERY host it could be,
    # every address of that host's latest report.
    if kind == _COMPUTER or (not kind and identity.samaccountname.endswith("$")):
        if identity.fqdn:
            names = [identity.fqdn]
        elif len(domains) == 1 and len(host_names) == 1:
            names = list(host_names)
        else:
            label = identity.samaccountname.rstrip("$")
            names = [f"{label}.{candidate}" for candidate in domains if candidate and label]
        latest: list[str] = []
        for name in names:
            reported = state.current_of(name)
            if not reported:
                latest = []
                break
            latest.extend(sorted(reported))
        if latest:
            entries = [matcher.allow_address_entry(address) for address in latest]
            if all(entries):
                return entries[0], _NEVER, ""
        elif matcher.has_allow_address_entries and not not_established:
            not_established = CAUSE_NAME_NOT_RESOLVED
    return "", _NEVER, not_established


# ── Seams: refusal lines and the batched refusal record ─────────────────────


def asset_refusal_line(
    what: str, target: str, verdict: AssetScopeVerdict, *, marked: bool = True
) -> str:
    """The operator line for one target the asset scope kept out."""
    from rich.markup import escape  # noqa: PLC0415

    name = verdict.label or str(target or "")
    shown = mark_sensitive(escape(name), "hostname") if marked else name
    subject = f"{escape(what)} on {shown}" if name else escape(what)
    noun = "host" if verdict.kind in (_COMPUTER, "address") else "object"
    if verdict.reason == ASSET_REASON_UNREADABLE:
        tail = "the recorded engagement scope could not be read; record it again before the scan."
    elif verdict.cause == CAUSE_AFFECTED_HOSTS_UNKNOWN:
        tail = (
            "it would change hosts ADscan cannot confirm are all inside the "
            "engagement scope."
        )
    elif verdict.outcome is ScopeOutcome.UNDETERMINED:
        tail = f"ADscan could not confirm the {noun} is inside the engagement scope."
    elif verdict.reason == ASSET_REASON_DC_DIRECTORY_ONLY:
        tail = "this domain controller is used for directory reads only under the engagement scope."
    elif verdict.reason == ASSET_REASON_DOMAIN_OUTSIDE:
        owner = verdict.domain or (verdict.identity.domain if verdict.identity else "")
        where = (mark_sensitive(escape(owner), "domain") if marked else owner) or "its domain"
        tail = f"{where} is outside the engagement scope."
    else:
        tail = f"the {noun} is excluded from the engagement scope."
    return f"{subject} not executed: {tail}"


def asset_verdict_note(
    shell: Any, verdict: AssetScopeVerdict, target: str = ""
) -> dict[str, str]:
    """THE step / edge note for a step the asset scope kept from running.

    One builder for every seam (the executor, the readiness overlay, a list
    seam): :func:`adscan_core.reporting.engagement_scope.asset_scope_note` fed
    from the verdict, so an UNDETERMINED verdict is stamped ``unconfirmed``
    with its cause (rendered "could not be confirmed as within the engagement
    scope") and never with the wording of an exclusion the client asked for.
    ``entry_written_as`` is how the deciding entry was written, when it differs
    from how the target was known.
    """
    known = verdict.label or str(target or "").strip()
    state = _asset_state(_session(shell))
    entry = state.entries.get(verdict.entry_id) if state is not None and verdict.entry_id else None
    written = entry.value if entry is not None else ""
    return asset_scope_note(
        known,
        outcome=(
            SCOPE_OUTCOME_UNCONFIRMED
            if verdict.outcome is ScopeOutcome.UNDETERMINED
            else SCOPE_OUTCOME_EXCLUDED
        ),
        cause=verdict.cause,
        entry_written_as=written if written and written.lower() != known.lower() else "",
    )


def _asset_block(shell: Any) -> dict[str, Any] | None:
    block = _record(shell).get("asset_scope")
    return block if isinstance(block, dict) else None


def asset_scope_block(shell: Any = None) -> dict[str, Any] | None:
    """The LIVE ``asset_scope`` block of the record (``None`` without one).

    What :func:`flush_engagement_scope` writes: a reader inside the process
    (the scan-end coverage stamp) takes it from here instead of re-reading
    ``scope.json``, which only holds what the last flush wrote. A deep copy.
    """
    import copy  # noqa: PLC0415

    shell = _session(shell)
    if shell is None:
        return None
    with _RECORD_LOCK:
        _stage_pending_counts(shell)
        block = _asset_block(shell)
        return copy.deepcopy(block) if block is not None else None


def _refusal_index(record: dict[str, Any], block: dict[str, Any]) -> dict[tuple[Any, ...], dict[str, Any]]:
    index = record.get("refusal_index")
    refusals = block.setdefault("refusals", [])
    if not isinstance(index, dict) or record.get("refusal_index_of") is not refusals:
        index = {
            (row.get("surface"), row.get("target"), row.get("reason")): row
            for row in refusals
            if isinstance(row, dict)
        }
        record["refusal_index"] = index
        record["refusal_index_of"] = refusals
    return index


def _note_refusal(
    shell: Any,
    *,
    surface: str,
    target: str,
    verdict: AssetScopeVerdict,
    domain: str = "",
) -> None:
    """Count one refusal IN MEMORY (first occurrence per surface, target and reason).

    Nothing is written here: :func:`flush_engagement_scope` writes the record.
    Each row says whether the object was excluded or could not be confirmed
    (``outcome``), why (``cause``), how the target was known (``known_as``) and
    the domain it belongs to, so a report never words an unconfirmed object as
    an exclusion and never drops an address-only refusal from its domain.
    """
    block = _asset_block(shell)
    if block is None:
        return
    record = _record(shell)
    known = str(target or "").strip()
    name = known or verdict.label
    with _RECORD_LOCK:
        index = _refusal_index(record, block)
        key = (str(surface or ""), name, verdict.reason)
        row = index.get(key)
        if row is not None:
            row["count"] = int(row.get("count") or 0) + 1
        elif len(index) >= _REFUSALS_MAX:
            block["refusals_truncated"] = int(block.get("refusals_truncated") or 0) + 1
        else:
            row = {
                "surface": str(surface or ""),
                "kind": verdict.kind or _COMPUTER,
                "target": name,
                "reason": verdict.reason,
                "entry": verdict.entry_id,
                "count": 1,
                "outcome": (
                    SCOPE_OUTCOME_UNCONFIRMED
                    if verdict.outcome is ScopeOutcome.UNDETERMINED
                    else SCOPE_OUTCOME_EXCLUDED
                ),
                "cause": verdict.cause,
                "known_as": known or name,
                "label": verdict.label or name,
                "domain": _norm(verdict.domain or domain),
            }
            block["refusals"].append(row)
            index[key] = row
        record["dirty"] = True


def record_scope_refusals(
    shell: Any,
    refused: Iterable[tuple[Any, AssetScopeVerdict]],
    *,
    surface: str,
    domain: str | None = None,
    key: Callable[[Any], Any] = str,
) -> int:
    """Record a BATCH of refusals a list seam made (accounts or hosts).

    For a seam that judges its own list with :func:`principal_scope_verdict`
    (a roast list, a spray list, the user-enumeration word list): the refused
    items join ``asset_scope.refusals`` exactly as a host partition's do, in
    memory, written by the next :func:`flush_engagement_scope`. Returns how
    many were recorded.
    """
    shell = _session(shell)
    if shell is None or _asset_block(shell) is None:
        return 0
    count = 0
    for item, verdict in refused or ():
        if not isinstance(verdict, AssetScopeVerdict) or verdict.allowed:
            continue
        _note_refusal(
            shell, surface=surface, target=str(key(item) or ""), verdict=verdict, domain=_norm(domain)
        )
        count += 1
    return count


def partition_targets_in_scope(
    shell: Any,
    targets: Iterable[Any],
    *,
    key: Callable[[Any], Any] = str,
    purpose: Any = None,
    surface: str,
    what: str,
    domain: str | None = None,
    address: Callable[[Any], Any] | None = None,
    dn: Callable[[Any], Any] | None = None,
    sid: Callable[[Any], Any] | None = None,
    contact: Contact | None = None,
) -> ScopePartition:
    """Split a target list before a fan-out: the fan-out never sees a refused item.

    A READ plus an in-memory count: no lookup and no file write (a seam that
    knows its targets only by name calls :func:`prepare_scope_targets` first).
    Each refusal is counted once per (surface, target, reason) for
    ``scope.json`` (written by the next :func:`flush_engagement_scope`), and
    ONE collapsed operator line is printed per call (names under
    ``--verbose``). Without an asset scope the list is returned untouched.

    Args:
        targets: The items the caller is about to contact.
        key: Maps an item to its host (name or IP).
        purpose: Accepted for one release and IGNORED: pass ``contact``.
        surface: Machine name of the seam (``smb_collection``, ``winrm_sweep``).
        what: Operator wording of the operation ("SMB collection").
        domain: The domain the targets were listed for, when known.
        address: Maps an item to the address actually connected to, when known.
        dn: Maps an item to its distinguished name, when the caller holds the
            directory object: a subtree entry is then decided on the spot.
        sid: Maps an item to its SID, for the same reason.
        contact: What the seam opens on each host (:class:`Contact`).
    """
    items = list(targets or ())
    shell = _session(shell)
    state = _asset_state(shell)
    if state is None:
        return ScopePartition(allowed=items, refused=[])
    _legacy_purpose(purpose, contact)
    derived = _purpose_of(contact)
    allowed: list[Any] = []
    refused: list[tuple[Any, AssetScopeVerdict]] = []
    for item in items:
        host = str(key(item) or "")
        verdict = _host_verdict(
            shell,
            state,
            host=host,
            connect_address=str(address(item) or "") if address else None,
            purpose=derived,
            smb=_over_smb(contact),
            domain=domain,
            host_dn=(str(dn(item) or "") or None) if dn else None,
            host_sid=(str(sid(item) or "") or None) if sid else None,
        )
        if verdict.allowed:
            allowed.append(item)
            continue
        refused.append((item, verdict))
        _note_refusal(shell, surface=surface, target=host, verdict=verdict, domain=_norm(domain))
    if refused:
        _announce_partition(what, refused, key=key)
    return ScopePartition(allowed=allowed, refused=refused)


def partition_principals_in_scope(
    shell: Any,
    principals: Iterable[Any],
    *,
    key: Callable[[Any], Any] = str,
    surface: str,
    what: str,
    domain: str | None = None,
    kind: str | Callable[[Any], Any] | None = None,
    dn: Callable[[Any], Any] | None = None,
    sid: Callable[[Any], Any] | None = None,
    path_domain: str | None = None,
) -> ScopePartition:
    """Split an ACCOUNT list before a roast, a spray or an enumeration.

    The account twin of :func:`partition_targets_in_scope`: a read plus an
    in-memory count, one collapsed operator line per call. ``kind`` is what the
    caller knows from the directory query that built the list (``"user"`` for
    a user query), or a function of the item.
    """
    items = list(principals or ())
    shell = _session(shell)
    state = _asset_state(shell)
    if state is None:
        return ScopePartition(allowed=items, refused=[])
    allowed: list[Any] = []
    refused: list[tuple[Any, AssetScopeVerdict]] = []
    for item in items:
        label = str(key(item) or "")
        verdict = principal_scope_verdict(
            shell,
            principal=label,
            domain=domain,
            dn=(str(dn(item) or "") or None) if dn else None,
            sid=(str(sid(item) or "") or None) if sid else None,
            kind=(str(kind(item) or "") if callable(kind) else kind),
            path_domain=path_domain,
        )
        if verdict.allowed:
            allowed.append(item)
            continue
        refused.append((item, verdict))
        _note_refusal(shell, surface=surface, target=label, verdict=verdict, domain=_norm(domain))
    if refused:
        _announce_partition(what, refused, key=key, noun=("account", "accounts"))
    return ScopePartition(allowed=allowed, refused=refused)


def _announce_partition(
    what: str,
    refused: list[tuple[Any, AssetScopeVerdict]],
    *,
    key: Callable[[Any], Any],
    noun: tuple[str, str] = ("host", "hosts"),
) -> None:
    from rich.markup import escape  # noqa: PLC0415

    excluded = [(i, v) for i, v in refused if v.outcome is ScopeOutcome.REFUSED]
    unsure = [(i, v) for i, v in refused if v.outcome is ScopeOutcome.UNDETERMINED]
    for group, tail in (
        (excluded, "excluded by the engagement scope."),
        (unsure, "it could not confirm inside the engagement scope."),
    ):
        if not group:
            continue
        count = len({str(key(i)) for i, _ in group})
        print_info(f"{escape(what)} skipped {count} {noun[0] if count == 1 else noun[1]} {tail}")
        names = sorted({str(key(i)) for i, _ in group})
        print_info_verbose(
            f"{escape(what)}: {mark_sensitive(escape(', '.join(names[:50])), 'hostname')}"
            + (f" and {len(names) - 50} more" if len(names) > 50 else "")
        )


def require_host_in_scope(
    shell: Any,
    *,
    host: str | None,
    connect_address: str | None = None,
    purpose: Any = None,
    surface: str,
    what: str,
    domain: str | None = None,
    host_dn: str | None = None,
    host_sid: str | None = None,
    contact: Contact | None = None,
) -> bool:
    """Single-target gate: True when ``host`` may be contacted, else refuse and say so.

    A READ plus an in-memory count (no lookup, no file write). ``contact``
    describes what is opened; ``purpose`` is accepted for one release and
    ignored. ``host_dn`` and ``host_sid`` are the directory identity, when the
    caller holds the object. ``shell=None`` falls back to the registered
    session.
    """
    shell = _session(shell)
    verdict = host_scope_verdict(
        shell,
        host=host,
        connect_address=connect_address,
        purpose=purpose,
        domain=domain,
        host_dn=host_dn,
        host_sid=host_sid,
        contact=contact,
    )
    if verdict.allowed:
        return True
    _note_refusal(
        shell, surface=surface, target=str(host or ""), verdict=verdict, domain=_norm(domain)
    )
    print_info(asset_refusal_line(what, str(host or ""), verdict))
    return False


def require_repl_target_in_scope(
    shell: Any,
    *,
    host: str | None = None,
    domain: str | None = None,
    what: str,
) -> bool:
    """Gate for a REPL or ``execute`` verb that takes a host or a domain argument.

    The domain is checked against the domain scope (gap G2) and the host against
    the asset scope. Returns False after one operator line when either refuses.

    The ONE gate that resolves its target first: an operator names one host by
    hand, so this calls :func:`prepare_scope_targets` for it (an explicit
    trigger) before asking the verdict. Never call it from a fan-out or from a
    transport: those partition a prepared list.
    """
    if domain:
        verdict = domain_scope_verdict(shell, domain)
        if not verdict.in_scope:
            print_info(outside_scope_line(what, str(host or ""), verdict.domain or _norm(domain)))
            return False
    if host:
        prepare_scope_targets(shell, [host], domain=_norm(domain) or None)
        return require_host_in_scope(
            shell, host=host, surface="repl", what=what, domain=_norm(domain) or None
        )
    return True


# ── Seams that never receive a shell ───────────────────────────────────────


def session_host_verdict(
    *,
    host: str | None,
    connect_address: str | None = None,
    purpose: Any = None,
    port: int | None = None,
    domain: str | None = None,
    contact: Contact | None = None,
) -> AssetScopeVerdict:
    """:func:`host_scope_verdict` for a seam that never receives a shell.

    Asked against the session registered with :func:`register_scope_shell` (a
    probe primitive, a clock read). Without a session there is no engagement to
    hold the contact to. When ``contact`` is left out it is read from ``port``
    (:func:`contact_for_port`: a directory protocol's own port is that
    protocol; 445 and every other port are a host contact). Quiet: nothing is
    printed or recorded, so a primitive called per port never floods the
    operator. ``purpose`` is accepted for one release and ignored.
    """
    shell = _scope_shell()
    if shell is None or _asset_state(shell) is None:
        return _ALLOWED_NO_SCOPE
    if contact is None and port is not None:
        contact = contact_for_port(port)
    return host_scope_verdict(
        shell,
        host=host,
        connect_address=connect_address,
        purpose=purpose,
        domain=domain,
        contact=contact,
    )


def require_session_host_in_scope(
    *,
    host: str | None,
    connect_address: str | None = None,
    purpose: Any = None,
    surface: str,
    what: str,
    domain: str | None = None,
    contact: Contact | None = None,
) -> bool:
    """:func:`require_host_in_scope` for a seam that never receives a shell."""
    shell = _scope_shell()
    if shell is None:
        return True
    return require_host_in_scope(
        shell,
        host=host,
        connect_address=connect_address,
        purpose=purpose,
        surface=surface,
        what=what,
        domain=domain,
        contact=contact,
    )


# ── Scanners that take address ranges (and child processes) ────────────────

_ADDRESS_FORM = re.compile(r"^[0-9a-fA-F.:\-*/,\[\]]+$")


@dataclass
class AddressSpacePartition:
    """A target expression split by the asset scope, as networks (never expanded).

    Attributes:
        scoped: An asset scope applied. When False the caller scans its original
            expression unchanged (``tokens``).
        tokens: The requested tokens, as given.
        networks: The address space that may be contacted, collapsed.
        names: The host names that may be contacted.
        excluded: Addresses the scope excludes (denied, or outside the allow-list).
        undetermined: Addresses the scan could not confirm inside the scope.
        refused_tokens: Tokens refused whole (an excluded name, an address form
            that cannot be checked against the scope).
        exclusions: Every excluded network and address known to the session, for
            the exclude file of a scanner child process.
    """

    scoped: bool
    tokens: list[str]
    networks: list[Any] = field(default_factory=list)
    names: list[str] = field(default_factory=list)
    excluded: int = 0
    undetermined: int = 0
    refused_tokens: list[str] = field(default_factory=list)
    exclusions: list[str] = field(default_factory=list)

    @property
    def targets(self) -> list[str]:
        """What the scanner is handed: networks and addresses, then names."""
        if not self.scoped:
            return list(self.tokens)
        return [_network_text(net) for net in self.networks] + list(self.names)

    @property
    def empty(self) -> bool:
        """Nothing is left to contact."""
        return not self.targets

    @property
    def address_count(self) -> int:
        """How many addresses the allowed networks hold."""
        return sum(int(net.num_addresses) for net in self.networks)

    def allows(self, target: Any) -> bool:
        """Whether one expanded target (an address or a name) is in the allowed split."""
        text = str(target or "").strip()
        if not self.scoped:
            return True
        try:
            net = ipaddress.ip_network(text.strip("[]"))
        except ValueError:
            return text in self.names
        index = getattr(self, "_index", None)
        if index is None:
            by_version = _collapsed(self.networks)
            index = {
                v: (items, [int(n.network_address) for n in items])
                for v, items in by_version.items()
            }
            self._index = index
        items, starts = index[net.version]
        return bool(_overlapping(items, starts, net))


def _network_text(net: Any) -> str:
    if net.prefixlen == net.max_prefixlen:
        return str(net.network_address)
    return str(net)


def _token_networks(token: str) -> list[Any] | None:
    """The networks a scanner token names (``None`` for a name or an unreadable form)."""
    text = str(token or "").strip().strip("[]")
    try:
        return [ipaddress.ip_network(text, strict=False)]
    except ValueError:
        pass
    if "-" not in text or not _ADDRESS_FORM.match(text):
        return None
    try:
        entry, _warnings = asset_model.parse_entry(f"range:{text}", origin="", source="targets")
        first, _, last = entry.value.partition("-")
        return list(
            ipaddress.summarize_address_range(
                ipaddress.ip_address(first), ipaddress.ip_address(last)
            )
        )
    except (ValueError, TypeError):
        return None


def _collapsed(nets: Iterable[Any]) -> dict[int, list[Any]]:
    """Networks collapsed and sorted, per IP version."""
    by_version: dict[int, list[Any]] = {4: [], 6: []}
    for net in nets:
        by_version[net.version].append(net)
    return {v: list(ipaddress.collapse_addresses(items)) for v, items in by_version.items()}


def _flat(nets: Iterable[Any]) -> list[Any]:
    return [net for items in _collapsed(nets).values() for net in items]


def _overlapping(sorted_nets: list[Any], starts: list[int], net: Any) -> list[Any]:
    """The members of a collapsed, sorted list that overlap ``net`` (bisect)."""
    if not sorted_nets:
        return []
    low = int(net.network_address)
    high = int(net.broadcast_address)
    index = bisect.bisect_left(starts, low)
    out: list[Any] = []
    if index > 0 and int(sorted_nets[index - 1].broadcast_address) >= low:
        out.append(sorted_nets[index - 1])
    while index < len(sorted_nets) and starts[index] <= high:
        out.append(sorted_nets[index])
        index += 1
    return out


def _minus(net: Any, holes: list[Any]) -> list[Any]:
    """``net`` without ``holes`` (all overlapping it), by halving: never an expansion."""
    if not holes:
        return [net]
    if any(hole.prefixlen <= net.prefixlen for hole in holes):
        return []
    low, high = net.subnets(prefixlen_diff=1)
    return _minus(low, [h for h in holes if h.overlaps(low)]) + _minus(
        high, [h for h in holes if h.overlaps(high)]
    )


def _subtract_networks(nets: Iterable[Any], holes: Iterable[Any]) -> list[Any]:
    """``nets`` minus ``holes`` as networks. Cost grows with the holes, not the range."""
    kept: list[Any] = []
    wanted = _collapsed(nets)
    removed = _collapsed(holes)
    for version, items in wanted.items():
        sorted_holes = removed[version]
        starts = [int(h.network_address) for h in sorted_holes]
        for net in items:
            kept.extend(_minus(net, _overlapping(sorted_holes, starts, net)))
    return kept


def _intersect_networks(nets: Iterable[Any], others: Iterable[Any]) -> list[Any]:
    """The address space common to ``nets`` and ``others``, as networks."""
    kept: list[Any] = []
    wanted = _collapsed(nets)
    allowed = _collapsed(others)
    for version, items in wanted.items():
        sorted_allowed = allowed[version]
        starts = [int(a.network_address) for a in sorted_allowed]
        for net in items:
            for other in _overlapping(sorted_allowed, starts, net):
                kept.append(net if other.prefixlen <= net.prefixlen else other)
    return _flat(kept)


def _count_addresses(nets: Iterable[Any]) -> int:
    return sum(int(net.num_addresses) for net in _flat(nets))


def _entry_networks(state: _AssetState, *, deny: bool) -> list[Any]:
    """The address space one list names: its address entries and what its names
    resolved to (an ALLOW name's addresses only while its resolution is fresh)."""
    nets: list[Any] = []
    now = time.monotonic()
    for entry in state.scope.deny if deny else state.scope.allow:
        try:
            if entry.type == asset_model.TYPE_IP:
                nets.append(ipaddress.ip_network(entry.value))
            elif entry.type == asset_model.TYPE_CIDR:
                nets.append(ipaddress.ip_network(entry.value, strict=False))
            elif entry.type == asset_model.TYPE_RANGE:
                first, _, last = entry.value.partition("-")
                nets.extend(
                    ipaddress.summarize_address_range(
                        ipaddress.ip_address(first), ipaddress.ip_address(last)
                    )
                )
        except (ValueError, TypeError):
            continue
    for entry_id, row in state.resolution.items():
        if entry_id.startswith("d") != deny:
            continue
        if not deny and now >= state.allow_fresh_until.get(entry_id, 0.0):
            continue
        for identity in row.get("identities") or ():
            for address in getattr(identity, "addresses", ()):
                text = _ip_text(address)
                if text:
                    nets.append(ipaddress.ip_network(text))
    return nets


def _attributed_addresses(shell: Any, state: _AssetState) -> set[str]:
    """Addresses the session can tie to a name: learned ones and directory servers."""
    with state._lock:  # noqa: SLF001 - the state's own lock
        known = set(state.addr_names)
    known.update(_domain_view(shell, state).by_ip)
    return known


def scanner_exclusions(
    shell: Any,
    *,
    purpose: Any = None,
    domain: str | None = None,
    contact: Contact | None = None,
) -> list[str]:
    """Every network and address a scanner CHILD PROCESS must leave alone.

    No in-process check can see a child process, so its command also carries an
    exclude file built from this list: the deny-list's address entries, the
    addresses its names resolved to, and every address the session tied to a
    host the verdict refuses for what ``contact`` opens. Empty without an asset
    scope. An allow-list cannot be expressed as exclusions: the caller
    restricts the target list itself (:func:`partition_address_space_in_scope`).
    ``purpose`` is accepted for one release and ignored.
    """
    shell = _session(shell)
    state = _asset_state(shell)
    if state is None or state.broken:
        return []
    _legacy_purpose(purpose, contact)
    derived = _purpose_of(contact)
    nets = _entry_networks(state, deny=True)
    for address in _attributed_addresses(shell, state):
        verdict = _host_verdict(
            shell,
            state,
            host=address,
            connect_address=None,
            purpose=derived,
            smb=_over_smb(contact),
            domain=domain,
            host_dn=None,
            host_sid=None,
        )
        if not verdict.allowed:
            nets.append(ipaddress.ip_network(address))
    return [_network_text(net) for net in _flat(nets)]


def partition_address_space_in_scope(
    shell: Any,
    tokens: Iterable[Any],
    *,
    purpose: Any = None,
    surface: str,
    what: str,
    domain: str | None = None,
    contact: Contact | None = None,
) -> AddressSpacePartition:
    """Split a scanner's target expression: (requested and allowed) minus denied.

    For a scanner that takes ranges (a DC discovery over ``--hosts``). The split
    is network arithmetic, so a /16 is never expanded into addresses. It answers
    what :func:`host_scope_verdict` answers for each address:

    * an address tied to a name (learned by a resolver, or a recorded domain
      controller) is judged by its own verdict;
    * any other address is excluded when a deny entry covers it, kept when an
      allow entry covers it, refused when an allow-list exists and none does,
      and not confirmed while a denied host's addresses are still unknown.

    A read plus an in-memory count: one collapsed operator line, no file write.

    Args:
        tokens: The scanner's targets: addresses, CIDRs, ``a-b`` ranges, names.
        purpose: Accepted for one release and IGNORED: pass ``contact``.
        surface: Machine name of the seam (``dc_discovery``).
        what: Operator wording of the operation ("DC discovery").
        domain: The domain the targets were listed for, when known.
        contact: What the scanner opens on each host (:class:`Contact`).
    """
    raw = [str(t).strip() for t in tokens or () if str(t or "").strip()]
    shell = _session(shell)
    state = _asset_state(shell)
    if state is None:
        return AddressSpacePartition(scoped=False, tokens=raw)
    _legacy_purpose(purpose, contact)
    derived = _purpose_of(contact)
    result = AddressSpacePartition(scoped=True, tokens=raw)
    hint = _norm(domain)
    if state.broken:
        verdict = _unreadable_verdict("address")
        result.refused_tokens = list(raw)
        _note_refusal(shell, surface=surface, target=" ".join(raw)[:256], verdict=verdict, domain=hint)
        print_info(asset_refusal_line(what, "", verdict))
        return result

    def _judge(host: str) -> AssetScopeVerdict:
        return _host_verdict(
            shell,
            state,
            host=host,
            connect_address=None,
            purpose=derived,
            smb=_over_smb(contact),
            domain=domain,
            host_dn=None,
            host_sid=None,
        )

    requested: list[Any] = []
    refused_names: list[tuple[str, AssetScopeVerdict]] = []
    for token in raw:
        nets = _token_networks(token)
        if nets is not None:
            requested.extend(nets)
            continue
        if _ADDRESS_FORM.match(token):
            # An address form this module cannot read (an octet range, a
            # wildcard): it cannot be checked, so it is not scanned.
            verdict = _undetermined(None, "", "address")
        else:
            verdict = _judge(token)
            if verdict.allowed:
                result.names.append(token)
                continue
        refused_names.append((token, verdict))
        result.refused_tokens.append(token)
        _note_refusal(shell, surface=surface, target=token, verdict=verdict, domain=hint)

    wanted = _flat(requested)
    deny_nets = _entry_networks(state, deny=True)
    allowed_attr: list[Any] = []
    refused_attr: list[Any] = []
    if wanted:
        by_version = _collapsed(wanted)
        starts = {v: [int(n.network_address) for n in items] for v, items in by_version.items()}
        for address in _attributed_addresses(shell, state):
            net = ipaddress.ip_network(address)
            if not _overlapping(by_version[net.version], starts[net.version], net):
                continue
            (allowed_attr if _judge(address).allowed else refused_attr).append(net)
    # An address nothing ties to a name: the same rules host_scope_verdict
    # applies to an address-only target.
    not_confirmed = False
    matcher = state.matcher
    base = wanted
    if matcher.allow_applies_to_hosts:
        base = _intersect_networks(wanted, _entry_networks(state, deny=False))
        not_confirmed = bool(state.allow_pending or state.allow_open_subtrees)
    if state.deny_unattributed_hosts or state.deny_open_subtrees or state.deny_pending_sids:
        base = []
        not_confirmed = True
    holes = [*deny_nets, *refused_attr]
    result.networks = _flat([*_subtract_networks(base, holes), *allowed_attr])
    total = _count_addresses(wanted)
    lost = max(0, total - result.address_count)
    denied = max(0, total - _count_addresses(_subtract_networks(wanted, holes)))
    if not_confirmed:
        result.excluded = min(lost, denied)
        result.undetermined = lost - result.excluded
    else:
        result.excluded = lost
    result.exclusions = scanner_exclusions(shell, domain=domain, contact=contact)
    expression = " ".join(raw)[:256]
    if result.excluded:
        reason = (
            ASSET_REASON_NOT_IN_ALLOW
            if matcher.allow_applies_to_hosts and result.excluded > denied
            else ASSET_REASON_DENIED
        )
        _note_refusal(
            shell,
            surface=surface,
            target=expression,
            verdict=_verdict(ScopeOutcome.REFUSED, reason, None, kind="address"),
            domain=hint,
        )
    if result.undetermined:
        _note_refusal(
            shell,
            surface=surface,
            target=expression,
            verdict=_undetermined(None, CAUSE_ADDRESS_NOT_ATTRIBUTED, "address"),
            domain=hint,
        )
    _announce_address_space(what, result, refused_names)
    return result


def _announce_address_space(
    what: str,
    result: AddressSpacePartition,
    refused_names: list[tuple[str, AssetScopeVerdict]],
) -> None:
    from rich.markup import escape  # noqa: PLC0415

    for count, tail in (
        (result.excluded, "excluded by the engagement scope."),
        (result.undetermined, "it could not confirm inside the engagement scope."),
    ):
        if count:
            noun = "address" if count == 1 else "addresses"
            print_info(f"{escape(what)} skipped {count} {noun} {tail}")
    if refused_names:
        _announce_partition(what, refused_names, key=lambda item: item)


# ── The egress backstop: the address verdict the socket guard asks ──────────


def egress_address_refused(ip: Any, port: Any = None) -> str | None:
    """The socket-level backstop verdict: is this ADDRESS definitely excluded?

    Returns the deny entry that excludes it (``d2``), a reason token
    (``not_in_allow_list``, ``scope_record_unreadable``), or ``None`` when the
    address may be contacted or its status is not known. Asked by the egress
    guard (``adscan_core.net_egress_guard``) for every outbound connection of
    the registered session.

    A READ: the in-memory matcher and what the session was told. So it refuses
    only DEFINITE refusals:

    * an address a deny entry names (IP, CIDR, range), a resolved address of a
      denied object, or an address EVER reported under a name a deny entry
      covers -> the deny entry;
    * with a host allow-list: an ENGAGEMENT address the allow-list does not
      cover -> ``not_in_allow_list``. Covered means inside an allow address
      entry, in the fresh resolution of an allow name, or currently reported
      under a name the allow-list names. A recorded domain controller of an
      in-scope domain passes on every port (the primary seams decide what
      crosses the directory plane) when the scope assesses domain controllers
      in full, and on the directory plane's ports otherwise (any other port
      is host work, covered by the allow-list or refused), at its recorded
      addresses and at the ones
      in the latest report of its recorded name (the knowledge the primary
      check reads, :class:`_AddressSummary`); a domain's DNS server that is
      not a domain controller passes on port 53 only;
    * with a host allow-list whose names' address evidence has LAPSED (no
      phase boundary and no prepared batch kept the window): the guard asks
      for one refresh of those names, on another thread, waits for it within
      a bound and reads the address again
      (:func:`_refresh_lapsed_evidence`). When that does not restore the
      evidence the address is refused as ``identity_undetermined`` (not
      confirmed): never let through, never reported as excluded.

    An engagement address is one that is not globally routable, one a resolver
    reported under an engagement name, or a public one in the /24 (IPv6: /64)
    of a recorded domain controller or of an address the scope resolved to.
    Any other public address is the product's own service traffic, which the
    offline switch governs, not the engagement scope.

    Not known passes: an address nobody attributed, while an allow NAME could
    still be its host (a suffix, a subtree, a pending entry, a name that never
    resolved to an address). The primary checks know the name and own that
    fail-closed decision. A pass that rests on time-limited evidence is not
    remembered by the guard: it is asked again on the next connection.
    """
    return _egress_decide(ip, port)[0]


def _egress_decide(ip: Any, port: Any = None) -> tuple[str | None, bool]:
    """``(token, cacheable)``: ``cacheable`` is False for a pass the guard must
    not remember (it holds for this port only, or only while time-limited
    evidence is fresh)."""
    shell = _scope_shell()
    state = _asset_state(shell)
    addr = _ip_text(ip) if state is not None else ""
    if state is None or not addr:
        return None, True
    try:
        number = int(port) if port is not None else 0
    except (TypeError, ValueError):
        number = 0
    token, volatile, engagement = _egress_read(shell, state, addr, number)
    if token is None:
        return None, not volatile
    # Only a candidate refusal pays for the address classification below.
    parsed = ipaddress.ip_address(addr)
    if parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_unspecified:
        return None, True  # never a host of the engagement (the guard exempts them too)
    if token in (
        ASSET_REASON_NOT_IN_ALLOW,
        ASSET_REASON_DC_DIRECTORY_ONLY,
        ASSET_REASON_UNREADABLE,
        _EVIDENCE_LAPSED,
    ):
        view = _domain_view(shell, state)
        if not engagement and parsed.is_global:
            place = _neighbourhood(parsed)
            if place not in state.neighbourhoods and place not in view.public_server_nets:
                return None, True  # not known to belong to the engagement
    if token == _EVIDENCE_LAPSED:
        # The allow names' address evidence is past its window, so the session
        # no longer knows which addresses the allowed hosts hold. It is
        # refreshed here, once and within a bound, then read again; when that
        # does not restore it the address is refused as NOT CONFIRMED (never
        # let through, never reported as excluded).
        if _refresh_lapsed_evidence(shell, state):
            state = _asset_state(shell)
            if state is None:
                return None, True
            token, volatile, _engagement = _egress_read(shell, state, addr, number)
            if token is None:
                return None, not volatile
        if token == _EVIDENCE_LAPSED:
            token = ASSET_REASON_UNDETERMINED
    return token, True


#: Internal answer of :func:`_egress_match`: nothing covers the address, and
#: the allow names' address evidence has lapsed (so nothing could).
_EVIDENCE_LAPSED = "allow_evidence_lapsed"


def _egress_read(
    shell: Any, state: _AssetState, addr: str, port: int
) -> tuple[str | None, bool, bool]:
    """``(token, volatile, engagement)`` for one address under ``state``."""
    if state.broken:
        names = state.names_of(addr)
        view = _domain_view(shell, state)
        known = list(view.known)
        return (
            ASSET_REASON_UNREADABLE,
            False,
            any("." not in n or _longest_known_suffix(n, known) for n in names),
        )
    view = _domain_view(shell, state)
    here = _address_summary(state, view, addr)
    token, volatile = _egress_match(shell, state, view, addr, here, port, time.monotonic())
    return token, volatile, bool(here.engagement)


def _egress_match(
    shell: Any,
    state: _AssetState,
    view: _DomainView,
    addr: str,
    here: _AddressSummary,
    port: int,
    now: float,
) -> tuple[str | None, bool]:
    """The deny entry or allow-list refusal for one address (``None``: let it
    through), and whether a pass must not be remembered.

    Everything the names reported at the address say comes from its summary
    (:func:`_address_summary`), the same one the primary check reads.
    """
    matcher = state.matcher
    hit = matcher.deny_address_entry(addr) or here.deny_hit
    if hit:
        return hit, False
    carried = _embedded_v4(addr)
    if carried:
        # A NAT64, 6to4 or IPv4-compatible form of a denied IPv4 address.
        hit = matcher.deny_address_entry(carried) or _address_summary(state, view, carried).deny_hit
        if hit:
            return hit, False
    if not matcher.allow_applies_to_hosts or matcher.allow_address_entry(addr):
        return None, False
    resolved = matcher.allow_resolved_address_entry(addr)
    fresh_until = state.allow_fresh_until.get(resolved, 0.0) if resolved else 0.0
    if (
        resolved
        and now < fresh_until
        and not _reported_elsewhere_since(state, view, addr, fresh_until - _ALLOW_ADDRESS_TTL_SECONDS)
    ):
        return None, True  # while that resolution is fresh
    # Names whose LATEST report still holds this address (a host that moved
    # away no longer vouches for its old address), reported inside the window.
    fresh_since = now - _ALLOW_ADDRESS_TTL_SECONDS + _TTL_EPSILON
    vouching = here.engagement & here.current
    if state.reported_within(addr, vouching & here.allowed, fresh_since):
        return None, True  # while that report is fresh
    directory_only_dc = False
    if here.dc is not None:
        if here.server is not None and here.server[2] == _ROLE_DC:
            directory_only_dc = bool(port)
            # A recorded address of a domain controller. Every port when the
            # client asked for domain controllers to be assessed in full (and
            # for a caller that names no port). Otherwise the ports of the
            # directory plane, each asked again (on 445 the primary seams
            # decide what is opened). Any other port is host work: on a
            # controller the allow-list does not cover it is judged below like
            # any host, so a contact no seam asked the scope about (a NetBIOS
            # node-status query was one) is refused here and counted.
            if state.scope.dc_access == asset_model.DC_ACCESS_FULL or not port:
                return None, False
            if port in DIRECTORY_PLANE_PORTS:
                return None, True
        if _purpose_of(contact_for_port(port)) in _DIRECTORY_PLANE:
            # An address only reported for its name: directory traffic alone.
            return None, True
    if here.server is not None and port == 53:
        return None, True
    if state.allow_pending or state.allow_open_subtrees:
        # An allow entry the directory has not placed yet may be this host.
        return None, False
    if not state.reported_within(addr, vouching, fresh_since):
        # Nobody attributed this address (to a host the allow-list does not name).
        if state.allow_always_open:
            # An allow name with no address evidence at all (a suffix, a host
            # that never resolved) may be its host; the primary checks know
            # the name and own that decision.
            return None, False
        if now >= state.allow_backed_until:
            return _EVIDENCE_LAPSED, False
    if directory_only_dc:
        # A controller the scope keeps to directory reads, asked on a port
        # that is not one of them: named apart from "not in the allow list" so
        # the operator is never told a directory-only controller is excluded.
        return ASSET_REASON_DC_DIRECTORY_ONLY, False
    return ASSET_REASON_NOT_IN_ALLOW, False


#: How long the socket guard waits for the refresh it asked for, and how often
#: it asks for one while the evidence stays lapsed.
_WIRE_REFRESH_WAIT_SECONDS = 5.0
_WIRE_REFRESH_INTERVAL_SECONDS = 60.0


class _WireRefresh:
    """One refresh of lapsed allow evidence the socket guard asked for."""

    __slots__ = ("started", "done", "thread")

    def __init__(self, started: float) -> None:
        self.started = started
        self.done = threading.Event()
        self.thread: threading.Thread | None = None


def _refresh_lapsed_evidence(shell: Any, state: _AssetState) -> bool:
    """Refresh the allow names' address evidence for the socket guard.

    The windows are kept by the triggers (a phase boundary, a prepared batch).
    A flow that ran past them without either reaches the guard with evidence
    that has lapsed; the guard then asks for ONE refresh (the same pass a
    checkpoint runs: name lookups, never a contact with a target), on its own
    thread, and waits for it at most :data:`_WIRE_REFRESH_WAIT_SECONDS` (not at
    all when the connection is opened on a running event loop). While
    the evidence stays lapsed (the name service does not answer) another is
    asked for at most every :data:`_WIRE_REFRESH_INTERVAL_SECONDS`; in between
    the guard refuses at once.

    Returns:
        True when a refresh finished and the address is worth reading again.
    """
    owned = getattr(state.pass_lock, "_is_owned", None)
    if callable(owned) and owned():
        return False  # a resolution pass of this very thread is what is connecting
    now = time.monotonic()
    with state._lock:  # noqa: SLF001 - the state's own lock
        job = state.wire_refresh
        started = False
        if job is None or (
            job.done.is_set() and now - job.started >= _WIRE_REFRESH_INTERVAL_SECONDS
        ):
            job = _WireRefresh(now)
            job.thread = threading.Thread(
                target=_run_wire_refresh, args=(shell, job), name="adscan-scope-refresh", daemon=True
            )
            state.wire_refresh = job
            started = True
    if started and job.thread is not None:
        job.thread.start()
    elif job.done.is_set():
        return False  # asked within the interval, and it did not restore the evidence
    if job.thread is threading.current_thread():
        return False  # the refresh's own connection
    if _on_running_event_loop():
        # Never wait on an event loop: every task of the loop would stall with
        # this connection. It is refused at once as not confirmed; the refresh
        # goes on off the loop, and the connections after it read its result.
        return False
    return job.done.wait(_WIRE_REFRESH_WAIT_SECONDS)


def _on_running_event_loop() -> bool:
    import asyncio  # noqa: PLC0415

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return False
    return True


def _run_wire_refresh(shell: Any, job: _WireRefresh) -> None:
    try:
        state = _asset_state(shell)
        if state is not None and not state.broken:
            resolve_asset_scope(shell, pending_only=True)
    except Exception as exc:  # noqa: BLE001 - the guard then refuses (not confirmed)
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    finally:
        job.done.set()


def egress_allowed(ip: str, port: int) -> bool:
    """Whether the egress guard lets this process contact ``ip`` on ``port``.

    One implementation: :func:`egress_address_refused`. The port matters only
    for a domain's DNS server that is not a domain controller (port 53); a
    directory-only domain controller is admitted at the wire on every port, and
    the primary seams decide what crosses it.
    """
    return egress_address_refused(ip, port) is None


def _egress_guard_verdict(ip: Any, port: Any = None) -> str | None:
    """What the socket guard is handed: a refusal token, ``None`` for a pass it
    may remember, or the guard's own token for a pass that holds for this port
    only."""
    from adscan_core import net_egress_guard  # noqa: PLC0415

    token, cacheable = _egress_decide(ip, port)
    if token is None and not cacheable:
        return net_egress_guard.PASS_THIS_PORT_ONLY
    return token


def _egress_on_resolve(name: Any, addresses: Iterable[Any]) -> None:
    """The guard saw this process resolve a name: remember where it points.

    Every name the process resolves through the system resolver is attributed
    here, so a denied NAME is refused at the wire at whatever address it
    resolves to, with no cooperation from the caller. In-memory, O(addresses).
    """
    shell = _scope_shell()
    if shell is None or _asset_state(shell) is None:
        return
    try:
        note_host_addresses(shell, host=str(name or ""), addresses=addresses)
    except Exception as exc:  # noqa: BLE001 - an observer never breaks a lookup
        telemetry.capture_exception(exc)


def _egress_scope_version() -> Any:
    """What the egress guard keys its cached answers on (``None``: no scope)."""
    state = _asset_state(_scope_shell())
    return (state, state.version, state.kb_version) if state is not None else None


#: Operator kill switch of the socket guard (the primary checks stay on).
EGRESS_GUARD_ENV = "ADSCAN_SCOPE_EGRESS_GUARD"
_GUARD_OFF_VALUES = frozenset({"0", "off", "false", "no", "disabled"})
_GUARD_OFF_ANNOUNCED = False


def egress_guard_disabled_by_operator() -> bool:
    """Whether the operator turned the socket guard off for this process."""
    return str(os.environ.get(EGRESS_GUARD_ENV) or "").strip().lower() in _GUARD_OFF_VALUES


def install_asset_scope_egress_guard(shell: Any = None) -> bool:
    """Arm the socket-level backstop for this process and bring it in line.

    Called once at session start, beside :func:`register_scope_shell`. From then
    on the guard is installed whenever the registered session has an asset
    scope (recorded, reloaded or rehydrated) and removed when it has none; a
    process that never calls this (a unit test, a lab script) is never patched.

    Returns:
        True when the guard is installed now.
    """
    from adscan_core import net_egress_guard  # noqa: PLC0415

    if shell is not None and _scope_shell() is not shell:
        register_scope_shell(shell)
    net_egress_guard.set_address_verdict_provider(
        _egress_guard_verdict,
        version=_egress_scope_version,
        on_hit=record_backstop_hit,
        on_resolve=_egress_on_resolve,
    )
    return _sync_egress_guard()


def _sync_egress_guard() -> bool:
    """Install the egress guard when the registered session has an asset scope.

    Arming runs the guard's self-test: a verdict that cannot answer is found
    here, before any connection, and reported as a configuration error
    (:func:`asset_scope_errors`), never discovered one refused connection at a
    time.
    """
    global _GUARD_OFF_ANNOUNCED  # noqa: PLW0603 - one warning per process
    from adscan_core import net_egress_guard  # noqa: PLC0415

    if not net_egress_guard.has_address_verdict_provider():
        return False
    shell = _scope_shell()
    state = _asset_state(shell)
    if state is None:
        net_egress_guard.uninstall()
        return False
    if egress_guard_disabled_by_operator():
        net_egress_guard.uninstall()
        _record(shell)["backstop_disabled"] = True
        if not _GUARD_OFF_ANNOUNCED:
            _GUARD_OFF_ANNOUNCED = True
            print_warning(
                f"Engagement scope: the connection guard is turned off ({EGRESS_GUARD_ENV}). "
                "Every operation still checks the scope before it contacts a host, but "
                "nothing stops a connection one of them missed. This is recorded with the "
                "scope."
            )
        return False
    _record(shell).pop("backstop_disabled", None)
    net_egress_guard.reset_cache()
    installed = net_egress_guard.install()
    fault = net_egress_guard.self_test()
    if fault != state.guard_fault:
        state.guard_fault = fault
        if fault:
            print_error(
                "Engagement scope: the connection guard failed its own check "
                f"({fault}). No engagement host is contacted while it is in this state."
            )
    return installed


def record_backstop_hit(*, module: str) -> None:
    """Count one connection the egress backstop refused (a missed primary seam).

    Counted IN MEMORY, from whichever thread was refused; the count reaches
    ``scope.json`` -> ``asset_scope.backstop_hits`` with the next
    :func:`flush_engagement_scope`, through the same atomic writer as every
    other change. Never a file write per hit.
    """
    shell = _scope_shell()
    if shell is None or _asset_block(shell) is None:
        return
    record = _record(shell)
    with _RECORD_LOCK:
        record["backstop_pending"] = int(record.get("backstop_pending") or 0) + 1
        record["dirty"] = True
    print_info_debug(f"engagement-scope backstop hit from {module}")


# ── Domain controllers (rules 2 and 3) ─────────────────────────────────────


_DC_FIX = (
    "Name a domain controller inside the scope, or use --dns-server so ADscan can find one."
)


def _controller_refusal_sentence(state: _AssetState, dc_ip: str, verdict: AssetScopeVerdict) -> str:
    """Why the domain controller ``dc_ip`` cannot be used, in the verdict's own terms.

    "Excluded" is said only of an established exclusion (a deny entry, with the
    entry as written). A verdict the scope could not establish says what is not
    confirmed and what settles it; it is never worded as an exclusion.
    """
    if verdict.outcome is ScopeOutcome.UNDETERMINED:
        why = {
            CAUSE_ENTRY_NOT_MATCHED: (
                " (an entry of the scope is not matched to a directory object yet, and "
                "ADscan cannot tell whether it is this host)"
            ),
            CAUSE_ADDRESS_NOT_ATTRIBUTED: (
                " (the address is not attributed to a known domain controller of an "
                "in-scope domain)"
            ),
            CAUSE_NAME_NOT_RESOLVED: " (a name in the scope could not be looked up)",
        }.get(verdict.cause, "")
        return (
            f"ADscan could not confirm that the domain controller {dc_ip} is inside the "
            f"engagement scope{why}. Nothing says it is excluded. Write the entries that "
            "name hosts as IP addresses, or pass --dns-server with the domain's name "
            "server so their names can be looked up."
        )
    if verdict.reason == ASSET_REASON_UNREADABLE:
        return "The recorded engagement scope cannot be read."
    entry = state.entries.get(verdict.entry_id) if verdict.entry_id else None
    if verdict.reason == ASSET_REASON_DENIED and entry is not None:
        if entry.type in asset_model.ADDRESS_TYPES:
            how = f"the deny entry '{entry.value}' covers its address"
        else:
            how = f"the deny entry '{entry.value}' is this host"
        return (
            f"The domain controller {dc_ip} is excluded from the engagement scope: {how}. "
            + _DC_FIX
        )
    if verdict.reason == ASSET_REASON_DOMAIN_OUTSIDE:
        return (
            f"The domain controller {dc_ip} belongs to a domain outside the engagement "
            "scope. " + _DC_FIX
        )
    if verdict.reason in (ASSET_REASON_NOT_IN_ALLOW, ASSET_REASON_DC_DIRECTORY_ONLY):
        return (
            f"The domain controller {dc_ip} is not covered by the engagement scope's "
            "allow-list. " + _DC_FIX
        )
    return f"The domain controller {dc_ip} is excluded from the engagement scope. " + _DC_FIX


def _controller_verdict(shell: Any, state: _AssetState, name: str, host: str) -> AssetScopeVerdict:
    return _host_verdict(
        shell, state, host=host, connect_address=None, purpose=ContactPurpose.DIRECTORY,
        domain=name, host_dn=None, host_sid=None,
    )


def controller_exclusion_error(shell: Any, *, domain: str, dc_ip: str | None) -> str:
    """The sentence for a domain controller a deny entry ESTABLISHES as excluded.

    ``""`` when the controller may be read, and when the scope merely cannot
    place it. A read: for the check made once the directory can say which
    object a SID, a DN or a name entry is (a controller named before the
    directory was read may turn out to be one of them).
    """
    state = _asset_state(_session(shell))
    address = _ip_text(dc_ip)
    if state is None or state.broken or not address:
        return ""
    verdict = _controller_verdict(shell, state, _norm(domain), address)
    if verdict.allowed or verdict.outcome is ScopeOutcome.UNDETERMINED:
        return ""
    return _controller_refusal_sentence(state, address, verdict)


def dc_scope_configuration_error(shell: Any, *, domain: str, dc_ip: str | None = None) -> str:
    """Why a domain cannot be assessed under the asset scope (``""`` when it can).

    ``dc_ip`` is the domain controller the operator (or the preflight) named
    for ``domain``. Naming it is what makes the address a domain controller of
    that domain for this session (:func:`declare_scan_target`), exactly as the
    recorded ``dc_ip`` does a moment later: it is then judged as one, for the
    directory plane, and deny wins as everywhere. So an entry only the
    directory can match (a name that does not resolve yet, a SID, a DN, an
    organisational unit) does not make the controller that holds that directory
    undeterminable: the directory is read, the entry is matched, and a
    controller that turns out to be the excluded object is refused from then on
    (:func:`controller_exclusion_error`). Every other address the scope cannot
    attribute stays closed (rule 8).

    When the named controller is excluded the run stops and asks for an
    in-scope one. When every recorded domain controller of ``domain`` is
    excluded, the domain has no directory to read. An unreadable scope record
    is reported as that, never as an exclusion, and a verdict the scope could
    not establish is never worded as one. Checked before any packet for the
    target domain (name lookups to the domain's name server aside).
    """
    state = _asset_state(shell)
    if state is None:
        return ""
    if state.broken:
        errors = asset_scope_errors(shell)
        return errors[0] if errors else "The recorded engagement scope cannot be read."
    name = _norm(domain)
    address = _ip_text(dc_ip)
    if address:
        # A read: the address is noted as a controller of the domain (in
        # memory), nothing is looked up. A seam that names a controller the
        # session never heard of calls ``declare_scan_target`` first (a
        # trigger), so pending names are asked through it before this check.
        _declare_target(shell, domain=name, dc_ip=address, target=not _session_origins(shell))
        verdict = _controller_verdict(shell, state, name, address)
        if not verdict.allowed:
            return _controller_refusal_sentence(state, address, verdict)
    elif dc_ip:
        # Named by a host name: judged as written (nothing is declared for a name).
        verdict = _controller_verdict(shell, state, name, str(dc_ip))
        if not verdict.allowed:
            return _controller_refusal_sentence(state, str(dc_ip), verdict)
    from adscan_core.dc_topology import resolve_domain_controllers  # noqa: PLC0415

    domains_data = getattr(shell, "domains_data", None) or {}
    data = domains_data.get(name) if isinstance(domains_data, Mapping) else None
    if not isinstance(data, Mapping):
        return ""
    records = resolve_domain_controllers(data).dcs
    if not records:
        return ""
    excluded = 0
    unconfirmed = 0
    for dc_record in records:
        host = dc_record.fqdn or dc_record.aliases[0]
        verdict = _controller_verdict(shell, state, name, host)
        if verdict.outcome is ScopeOutcome.UNDETERMINED:
            unconfirmed += 1
        elif not verdict.allowed:
            excluded += 1
    if excluded == len(records):
        return (
            f"Engagement scope: every domain controller of {name} is excluded; ADscan "
            "needs one for directory reads."
        )
    if excluded + unconfirmed == len(records):
        return (
            f"Engagement scope: ADscan could not confirm that any domain controller of {name} "
            "is inside the scope; it needs one for directory reads."
        )
    return ""


# ── The record ─────────────────────────────────────────────────────────────


def _resolution_payload(state: _AssetState) -> dict[str, Any]:
    entries = []
    for entry in (*state.scope.allow, *state.scope.deny):
        row = state.resolution.get(entry.id)
        if not row:
            continue
        payload: dict[str, Any] = {
            "id": entry.id,
            "status": row.get("status") or RESOLUTION_PENDING,
            "identities": [i.to_dict() for i in row.get("identities") or ()],
            "candidates": list(row.get("candidates") or ()),
        }
        if "leaf" in row:
            payload["leaf"] = bool(row["leaf"])
        if row.get("uncollected"):
            payload["uncollected"] = True
        entries.append(payload)
    return {"resolved_at": datetime.now(timezone.utc).isoformat(), "entries": entries}


def _stage_resolution(shell: Any, state: _AssetState) -> None:
    """Put the current resolution in the record block (written by the next flush)."""
    block = _asset_block(shell)
    if block is None:
        return
    with _RECORD_LOCK:
        block["resolution"] = _resolution_payload(state)
        _record(shell)["dirty"] = True


def _stage_pending_counts(shell: Any) -> None:
    """Fold the counters kept beside the block into it (under the record lock)."""
    record = _record(shell)
    block = _asset_block(shell)
    if block is None:
        return
    pending = int(record.get("backstop_pending") or 0)
    if pending:
        block["backstop_hits"] = int(block.get("backstop_hits") or 0) + pending
        record["backstop_pending"] = 0
    if record.get("backstop_disabled"):
        block["backstop_disabled"] = True
    else:
        block.pop("backstop_disabled", None)
    state = _asset_state(shell)
    waiting = len(state.lookup_backlog) if state is not None else 0
    if waiting:
        block["names_not_looked_up"] = waiting
    else:
        block.pop("names_not_looked_up", None)


def flush_engagement_scope(shell: Any = None) -> bool:
    """Write what the session counted since the last write (ONE atomic write).

    The batch point of the record: refusals, backstop hits, addresses learned
    for denied hosts and resolution changes are kept in memory and written
    here, through the single atomic writer, under the record lock. Called by
    :func:`scope_checkpoint` at a phase boundary, at process exit (registered
    once with ``atexit``), and by a reader that needs ``scope.json`` current
    (the scan-end coverage stamp). A no-op when nothing changed.

    Returns:
        True when the file was written.
    """
    shell = _session(shell)
    if shell is None:
        return False
    record = _record(shell)
    state = _asset_state(shell)
    with _RECORD_LOCK:
        if state is not None and not state.broken and state._unfolded:  # noqa: SLF001
            with state.pass_lock:
                resolution = dict(state.resolution)
                if _fold_learned(state, resolution):
                    state.resolution = resolution
                    state.rebuild()
                    _stage_resolution(shell, state)
        if not record.get("dirty"):
            return False
        return _save(shell)


def _mark_dirty(shell: Any) -> None:
    _record(shell)["dirty"] = True


def _flush_for_reader(workspace_dir: Any = None) -> None:
    """Flush the registered session before its ``scope.json`` is read in-process."""
    shell = _scope_shell()
    if shell is None:
        return
    wanted = os.path.abspath(os.fspath(workspace_dir)) if workspace_dir else ""
    current = _workspace_dir(shell)
    if wanted and (not current or os.path.abspath(current) != wanted):
        return
    flush_engagement_scope(shell)


def _flush_at_exit() -> None:
    try:
        flush_engagement_scope(None)
    except Exception:  # noqa: BLE001 - interpreter teardown
        pass


def _decided_clock_frame(shell: Any, decided_at: str) -> str:
    try:
        from adscan_core.reporting.clock_frame import resolve_stamp_frame  # noqa: PLC0415

        domains_data = getattr(shell, "domains_data", None) or {}
        store = domains_data.get(_norm(getattr(shell, "domain", ""))) if isinstance(domains_data, Mapping) else None
        return resolve_stamp_frame(store, decided_at).frame
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return "unverified"


def _set_aside_unreadable_file(shell: Any, record: dict[str, Any]) -> None:
    """Move a ``scope.json`` that could not be read out of the way (never delete it)."""
    path = str(record.get("unreadable_path") or "")
    if path and os.path.exists(path):
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        aside = f"{path}.unreadable-{stamp}"
        os.replace(path, aside)
        print_warning(
            "Engagement scope: the scope file that could not be read was kept as "
            f"{mark_sensitive(aside, 'path')}. The trust decisions it held are gone: no "
            "domain beyond the scan's own target is in scope until they are made again."
        )
    record["unreadable"] = ""
    record["unreadable_path"] = ""
    # The trust decisions were in the lost file: the domain axis stays closed
    # for this session until a decision is recorded again.
    record["trust_record_lost"] = True


def record_asset_scope(
    shell: Any,
    scope: AssetScope,
    *,
    decided_by: str,
    decided_by_label: str = "",
    source: Mapping[str, Any] | None = None,
    resolve: bool = True,
) -> dict[str, Any]:
    """Record the asset scope this engagement runs under (a new revision).

    Replace semantics: ``scope`` becomes the whole asset scope. An unchanged
    scope (same digest) keeps its revision; a change adds one and keeps the last
    :data:`_REVISIONS_KEPT` in ``revisions``. Who decided, when (with its clock
    frame) and from which source are recorded, the entries are resolved against
    the directory (an explicit trigger), and ``scope.json`` is written.

    ALWAYS recovers the unreadable state: recording a scope while the record
    cannot be read replaces it (an unparseable ``scope.json`` is first moved
    aside, never deleted; the trust decisions it held must be made again).

    Returns:
        The persisted ``asset_scope`` block (``{}`` when an empty scope is
        recorded on a session that never had one).

    Raises:
        ScopeRecordWriteError: ``scope.json`` could not be written. The run
            must not continue as if the scope were saved: the session is left
            refusing every host until a scope is recorded successfully.
    """
    record = _record(shell)
    old_state = _asset_state(shell)
    recovering = bool(record.get("unreadable")) or bool(old_state is not None and old_state.broken)
    if record.get("unreadable"):
        _set_aside_unreadable_file(shell, record)
    previous = _asset_block(shell)
    if scope.empty and previous is None and not recovering:
        return {}
    digest = scope.digest()
    if previous is not None and previous.get("digest") == digest and not recovering:
        # Unchanged for THIS session. It is a no-op only when the file still
        # holds what this session last read or wrote: another writer may have
        # changed the scope since, and recording it again is then a decision.
        workspace = _workspace_dir(shell)
        on_disk = None
        if workspace:
            payload, _problem = _read_scope_file(os.path.join(workspace, SCOPE_FILENAME))
            on_disk = _block_signature(_usable_disk_block(payload))
        if not workspace or on_disk == record.get("disk_signature"):
            return previous
    history = previous if isinstance(previous, dict) else {}
    try:
        previous_revision = int(history.get("revision") or 0)
    except (TypeError, ValueError):
        previous_revision = 0
    revisions = [r for r in history.get("revisions") or () if isinstance(r, Mapping)]
    if previous is not None:
        revisions.append(
            {
                "revision": previous_revision,
                "digest": str(history.get("digest") or ""),
                "decided_by": str(history.get("decided_by") or ""),
                "decided_at": str(history.get("decided_at") or ""),
                "allow": len(history.get("allow") or ()) if isinstance(history.get("allow"), list) else 0,
                "deny": len(history.get("deny") or ()) if isinstance(history.get("deny"), list) else 0,
            }
        )
    refusals = history.get("refusals")
    try:
        backstop_hits = int(history.get("backstop_hits") or 0)
    except (TypeError, ValueError):
        backstop_hits = 0
    decided_at = datetime.now(timezone.utc).isoformat()
    block: dict[str, Any] = {
        **scope.to_dict(),
        # Kept from the record this revises; a new one is given under the file
        # lock when there is no usable record on disk (``_merge_with_disk``).
        "record_id": str(history.get("record_id") or "") or uuid.uuid4().hex,
        **({"supersedes": history["supersedes"]} if isinstance(history.get("supersedes"), Mapping) else {}),
        "revision": previous_revision + 1,
        "decided_by": str(decided_by or ""),
        "decided_by_label": str(decided_by_label or ""),
        "decided_at": decided_at,
        "clock_frame": _decided_clock_frame(shell, decided_at),
        "source": dict(source or {}),
        "resolution": {"resolved_at": "", "entries": []},
        "refusals": [r for r in refusals if isinstance(r, dict)] if isinstance(refusals, list) else [],
        "backstop_hits": backstop_hits,
        "revisions": revisions[-_REVISIONS_KEPT:],
    }
    new_state = None if scope.empty else _AssetState(scope)
    if new_state is not None and old_state is not None and not old_state.broken:
        new_state.adopt_knowledge(old_state)
    with _RECORD_LOCK:
        record["asset_scope"] = block
        record["refusal_index"] = None
        record["write_failed"] = ""
        record["adopted_newer"] = False
        record["resolve_adopted"] = False
    _set_asset_state(shell, new_state)
    if resolve and new_state is not None:
        resolve_asset_scope(shell)
        _stage_resolution(shell, new_state)
    try:
        _save(shell, strict=True)
    except Exception as exc:  # noqa: BLE001 - any failure to write fails closed
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        reason = f"it could not be written to the workspace ({type(exc).__name__}: {exc})"
        record["write_failed"] = reason
        _set_asset_state(shell, _broken_state(reason))
        raise ScopeRecordWriteError(SCOPE_FILENAME, 0, reason) from exc
    return block


def reload_asset_scope(shell: Any) -> None:
    """Rebuild the session's asset state from the record (and re-resolve it).

    Never turns an unusable record into "no scope": an unreadable file, a block
    that does not validate, or a failure while rebuilding all leave the session
    in the fail-closed state.
    """
    record = _record(shell)
    if record.get("unreadable"):
        _set_asset_state(shell, _broken_state(str(record["unreadable"])))
        return
    if record.get("write_failed"):
        _set_asset_state(shell, _broken_state(str(record["write_failed"])))
        return
    old_state = _asset_state(shell)
    try:
        state = _state_from_block(_asset_block(shell))
    except Exception as exc:  # noqa: BLE001 - any failure here fails closed
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        state = _broken_state(f"it could not be loaded ({type(exc).__name__})")
    if state is not None and not state.broken and old_state is not None and not old_state.broken:
        state.adopt_knowledge(old_state)
    _set_asset_state(shell, state)
    if state is not None and not state.broken:
        resolve_asset_scope(shell, pending_only=True)


def _broken_state(problem: str = "") -> _AssetState:
    return _AssetState(AssetScope(), broken=True, problem=problem)


def _state_from_block(block: Mapping[str, Any] | None) -> _AssetState | None:
    """The asset state a persisted block describes (``None``: no asset scope).

    Fails closed: an entry that no longer parses gives a broken state (nothing
    is contacted). A resolution whose ids do not match the entries is dropped
    and resolved again. Addresses of ALLOW identities are never trusted from
    the file: those rows are resolved again, so an address DHCP has since given
    to another host never carries the allowance.

    Raises:
        TypeError, ValueError: a malformed resolution row; the caller turns any
            exception into a broken state.
    """
    if block is None:
        return None
    if not isinstance(block, Mapping):
        raise TypeError("asset_scope is not an object")
    problem = _block_problem(block)
    scope = None
    if not problem:
        try:
            scope = AssetScope.from_dict(block)
        except asset_model.ScopeSyntaxError as exc:
            problem = str(exc)
    if scope is not None and not _digest_holds(block, scope):
        # The lists are not the ones the digest was taken over: an entry was
        # lost, added or edited outside ADscan.
        problem = "its asset_scope digest does not match its allow and deny lists"
    if problem or scope is None:
        print_error(
            "The recorded engagement scope (scope.json) could not be read: "
            f"{problem}. No host will be contacted until the scope is recorded again."
        )
        return _broken_state(problem)
    if scope.empty:
        # A VALID block with both lists empty: the scope was cleared on purpose
        # (a revision of its own), which is "no asset scope".
        return None
    resolution: dict[str, dict[str, Any]] = {}
    rows = (block.get("resolution") or {}).get("entries") or ()
    if AssetScope.ids_consistent(block):
        for row in rows:
            if not isinstance(row, Mapping) or not row.get("id"):
                raise TypeError("a resolution row is not an object with an id")
            entry_id = str(row["id"])
            # An entry not matched to a directory object yet (pending, or
            # one that matched nothing) is saved with an EMPTY list: that is a
            # valid row, and the common one. Only a value that is not a list
            # is malformed.
            raw_identities = row.get("identities")
            if raw_identities is None:
                raw_identities = []
            if not isinstance(raw_identities, list) or not all(
                isinstance(i, Mapping) for i in raw_identities
            ):
                raise TypeError("a resolution identity is malformed")
            identities = [AssetIdentity.from_dict(i) for i in raw_identities]
            status = str(row.get("status") or RESOLUTION_PENDING)
            if entry_id.startswith("a"):
                identities = [
                    AssetIdentity(**{**i.__dict__, "addresses": ()}) for i in identities
                ]
                status = RESOLUTION_PENDING
            resolution[entry_id] = {
                "status": status,
                "identities": identities,
                "candidates": [str(c) for c in row.get("candidates") or ()],
                **({"leaf": bool(row["leaf"])} if "leaf" in row else {}),
                **({"uncollected": True} if row.get("uncollected") else {}),
            }
    return _AssetState(scope, resolution)


def _digest_holds(block: Mapping[str, Any], scope: AssetScope) -> bool:
    """Whether the block's lists are the ones its digest was taken over.

    The digest is a tamper and truncation check, taken by the WRITER over the
    entries as it wrote them. A reader of another version may normalise an
    entry differently (a DN's spacing, an IPv6 form), and its own digest of the
    lists then differs although nothing was lost or edited. So the check has
    two legs: the reader's digest matches, or the digest of the rows exactly as
    written does. Only a block that fails both was changed outside ADscan.
    """
    stored = block.get("digest")
    if scope.digest() == stored:
        return True
    try:
        import hashlib  # noqa: PLC0415

        def _keys(rows: Any) -> list[list[str]]:
            return sorted(
                [str(r.get("type") or ""), str(r.get("value") or ""), str(r.get("kind") or "")]
                for r in rows
            )

        canonical = {
            "format": asset_model.ASSET_SCOPE_FORMAT,
            "dc_access": str(block.get("dc_access") or ""),
            "allow": _keys(block.get("allow") or ()),
            "deny": _keys(block.get("deny") or ()),
        }
        blob = json_module.dumps(canonical, sort_keys=True, separators=(",", ":"))
        as_written = "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()
    except Exception:  # noqa: BLE001 - rows that cannot be read do not hold
        return False
    if as_written == stored:
        print_info_debug(
            "engagement-scope: the record's digest matches its entries as written; this "
            "version normalises an entry differently (not a change of the lists)"
        )
        return True
    return False


def _block_problem(block: Mapping[str, Any]) -> str:
    """Why a persisted ``asset_scope`` block cannot be used (``""``: it can).

    A block that is PRESENT must be the block the published schema describes
    (``engagement_scope.v1.json``, ``$defs/asset_scope``): ``allow``, ``deny``,
    ``digest`` and ``revision`` are required and typed. A block that lost a
    list, or holds ``null`` where a list belongs, is damaged; reading it as
    "no entries" would turn the client's exclusions off.
    """
    try:
        from adscan_core.engagement import contract  # noqa: PLC0415

        root = contract.load_schema("engagement_scope")
        contract.validate_against(
            {"$ref": "#/$defs/asset_scope", "$defs": root["$defs"]}, dict(block)
        )
    except Exception as exc:  # noqa: BLE001 - whatever stops the check fails closed
        code = getattr(exc, "code", type(exc).__name__)
        where = getattr(exc, "path", "") or "/"
        return f"its asset_scope block is not valid ({code} at {where})"
    return ""


def _read_scope_file(path: str) -> tuple[Mapping[str, Any] | None, str]:
    """``(payload, problem)``: ``(None, "")`` when there is no file."""
    if not os.path.exists(path):
        return None, ""
    try:
        with open(path, encoding="utf-8") as handle:
            payload = json_module.load(handle)
    except (OSError, ValueError) as exc:
        return None, f"the file could not be parsed ({type(exc).__name__})"
    if not isinstance(payload, Mapping):
        return None, "the file does not hold a JSON object"
    if "asset_scope" in payload and not isinstance(payload.get("asset_scope"), Mapping):
        return None, "its asset_scope block is not an object"
    for key in ("entries", "withheld", "origin_domains"):
        if key in payload and not isinstance(payload.get(key), list):
            return None, f"its {key} is not a list"
    return payload, ""


def _set_unreadable(shell: Any, path: str, problem: str) -> None:
    record = _empty_record()
    record["unreadable"] = problem
    record["unreadable_path"] = path
    try:
        setattr(shell, _RECORD_ATTR, record)
    except Exception:  # noqa: BLE001
        pass
    _set_asset_state(shell, _broken_state(problem))
    print_error(
        f"The engagement scope file {mark_sensitive(path, 'path')} could not be read: "
        f"{problem}. No host will be contacted and no other domain acted on until a "
        "scope is in place again. Restore the file, or record the scope again (ADscan "
        "keeps the unreadable file aside and never overwrites it)."
    )


def rehydrate_engagement_scope(shell: Any, workspace_dir: str | None = None) -> None:
    """Load the workspace's recorded scope into the session (gap G1).

    Called when a workspace is loaded, so ``adscan execute``, ``adscan recheck``
    and a reopened ``start`` session run under the trust decision and the asset
    scope recorded for the engagement, never a fresh default: an explicitly
    excluded domain stays out even under a policy that follows trusts. The
    session record is REPLACED (switching workspaces never carries a scope
    over); a workspace without ``scope.json`` starts empty. An earlier session's
    choices yield to a decision this session makes.

    Loading a scope is an explicit trigger: the entries that are pending (and
    every allow name, whose persisted addresses are never trusted) are resolved
    here, once.

    Fails closed and never raises: a file that exists but cannot be read (a
    truncated write, a non-object payload, a malformed block) leaves the session
    refusing every host and every domain other than the scan's own target, and
    marks the file so nothing this session does overwrites it.
    """
    workspace = str(workspace_dir or _workspace_dir(shell) or "")
    path = os.path.join(workspace, SCOPE_FILENAME) if workspace else ""
    try:
        payload, problem = _read_scope_file(path) if path else (None, "")
        if problem:
            _set_unreadable(shell, path, problem)
            return
        record = _empty_record()
        if isinstance(payload, Mapping):
            for row in payload.get("entries") or ():
                if isinstance(row, Mapping) and _norm(row.get("domain")):
                    record["entries"][_norm(row.get("domain"))] = dict(row)
            record["rehydrated_origins"] = domains_named(payload.get("origin_domains") or ())
            record["decided_by"] = str(payload.get("decided_by") or "")
            record["withheld"] = [
                dict(w) for w in payload.get("withheld") or () if isinstance(w, Mapping)
            ]
            block = payload.get("asset_scope")
            if isinstance(block, Mapping):
                record["asset_scope"] = dict(block)
        state = _state_from_block(record.get("asset_scope"))
    except Exception as exc:  # noqa: BLE001 - any failure here fails closed
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        _set_unreadable(shell, path or SCOPE_FILENAME, f"it could not be loaded ({type(exc).__name__})")
        return
    try:
        setattr(shell, _RECORD_ATTR, record)
    except Exception:  # noqa: BLE001
        return
    if path:
        _note_disk_state(record, path)
    _set_asset_state(shell, state)
    if state is not None and not state.broken:
        print_info_debug(
            f"engagement-scope rehydrated: allow={len(state.scope.allow)} "
            f"deny={len(state.scope.deny)} revision={record['asset_scope'].get('revision')}"
        )
        try:
            resolve_asset_scope(shell, pending_only=True)
        except Exception as exc:  # noqa: BLE001 - pending entries keep failing closed
            telemetry.capture_exception(exc)
            print_exception(exception=exc)


# ── Refusal ────────────────────────────────────────────────────────────────


def outside_scope_line(action: str, target: str, domain: str, *, marked: bool = True) -> str:
    """The operator line for a step the scope kept from running.

    ``marked`` wraps the domain and target for the telemetry sanitizer (the
    terminal line); the persisted execution event takes the plain form.
    """
    from rich.markup import escape  # noqa: PLC0415

    def _m(value: str, kind: str) -> str:
        return mark_sensitive(escape(value), kind) if marked else value

    where = _m(domain, "domain") if domain else "a domain that could not be determined"
    subject = f"{escape(action)} on {_m(target, 'node')}" if target else escape(action)
    return (
        f"{subject} not executed: {where} is outside the engagement scope. "
        "Widen the scope before the scan (trusted-domain setting) to assess it."
    )


def refuse_outside_scope(
    shell: Any,
    *,
    relation: str,
    out_domain: str,
    surface: str,
    path_domain: str = "",
    from_label: str = "",
    to_label: str = "",
    source_domain: str = "",
    step_status: str | None = None,
    event_recorder: Callable[[str, dict[str, Any]], None] | None = None,
    asset_verdict: AssetScopeVerdict | None = None,
) -> None:
    """Keep one step from running because it leaves the engagement scope.

    One operator line per (relation, target), the edge note every surface reads
    (``not_executed_reason = outside_engagement_scope``, status unchanged so the
    route stays mapped), and a ``withheld`` row in ``scope.json`` for the report.
    Never raises.

    With ``asset_verdict`` (an excluded host or account inside an in-scope
    domain) the note names the OBJECT and never a domain
    (:func:`adscan_core.reporting.engagement_scope.asset_scope_note`), and the
    refusal is recorded in the asset block instead of ``withheld``.
    """
    action = str(relation or "").strip() or "This step"
    target = str(to_label or "").strip()
    if asset_verdict is not None and not asset_verdict.allowed:
        _refuse_asset_step(
            shell,
            action=action,
            relation=relation,
            target=target,
            surface=surface,
            path_domain=path_domain,
            from_label=from_label,
            step_status=step_status,
            event_recorder=event_recorder,
            verdict=asset_verdict,
        )
        return
    key = (action.lower(), target.lower(), _norm(out_domain))
    announced = getattr(shell, _ANNOUNCED_ATTR, None)
    if not isinstance(announced, set):
        announced = set()
        try:
            setattr(shell, _ANNOUNCED_ATTR, announced)
        except Exception:  # noqa: BLE001
            pass
    first = key not in announced
    announced.add(key)
    # An attack path the operator launched never stops in silence, so that
    # surface prints on every refusal; elsewhere a repeat is collapsed.
    if first or surface == "attack_path":
        print_info(outside_scope_line(action, target, _norm(out_domain)))
    if first:
        withheld = _record(shell)["withheld"]
        withheld.append(
            {
                "source_domain": _norm(source_domain or path_domain),
                "target_domain": _norm(out_domain),
                "technique": action.lower(),
                "from": str(from_label or "").strip(),
                "to": target,
                "surface": surface,
            }
        )
        _mark_dirty(shell)
    print_info_debug(
        "engagement-scope refuse: "
        f"relation={mark_sensitive(action, 'detail')} surface={surface} "
        f"domain={mark_sensitive(_norm(out_domain) or '?', 'domain')} first={first}"
    )
    if path_domain and from_label and target and relation:
        try:
            from adscan_internal.services.attack_graph_service import (  # noqa: PLC0415
                update_edge_status_by_labels,
            )

            update_edge_status_by_labels(
                shell,
                path_domain,
                from_label=str(from_label),
                relation=relation,
                to_label=target,
                status=str(step_status or "theoretical").strip().lower() or "theoretical",
                notes=scope_note(_norm(out_domain)),
            )
        except Exception as exc:  # noqa: BLE001 - the note never breaks the scan
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
    if event_recorder is not None:
        try:
            event_recorder(
                outside_scope_line(action, target, _norm(out_domain), marked=False),
                {"reason": NOT_EXECUTED_OUTSIDE_SCOPE, **scope_note(_norm(out_domain))},
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)


def _refuse_asset_step(
    shell: Any,
    *,
    action: str,
    relation: str,
    target: str,
    surface: str,
    path_domain: str,
    from_label: str,
    step_status: str | None,
    event_recorder: Callable[[str, dict[str, Any]], None] | None,
    verdict: AssetScopeVerdict,
) -> None:
    key = (action.lower(), target.lower(), "asset:" + verdict.reason)
    announced = getattr(shell, _ANNOUNCED_ATTR, None)
    if not isinstance(announced, set):
        announced = set()
        try:
            setattr(shell, _ANNOUNCED_ATTR, announced)
        except Exception:  # noqa: BLE001
            pass
    first = key not in announced
    announced.add(key)
    if first or surface == "attack_path":
        print_info(asset_refusal_line(action, target, verdict))
    if first:
        _note_refusal(
            shell,
            surface=surface,
            target=verdict.label or target,
            verdict=verdict,
            domain=_norm(path_domain),
        )
    # The note carries the verdict's OUTCOME: a step left alone because its
    # object could not be placed is never worded as an exclusion.
    note = asset_verdict_note(shell, verdict, target)
    if path_domain and from_label and target and relation:
        try:
            from adscan_internal.services.attack_graph_service import (  # noqa: PLC0415
                update_edge_status_by_labels,
            )

            update_edge_status_by_labels(
                shell,
                path_domain,
                from_label=str(from_label),
                relation=relation,
                to_label=target,
                status=str(step_status or "theoretical").strip().lower() or "theoretical",
                notes=note,
            )
        except Exception as exc:  # noqa: BLE001 - the note never breaks the scan
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
    if event_recorder is not None:
        try:
            event_recorder(asset_refusal_line(action, target, verdict, marked=False), dict(note))
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)


def gate_cross_domain_technique(
    shell: Any,
    *,
    technique: str,
    source_domain: str,
    target_domain: str,
    surface: str,
) -> bool:
    """Seam for a technique runner acting from one domain INTO another.

    Returns True when both domains are in the engagement scope; otherwise
    refuses (one line, a ``withheld`` record) and returns False so the runner
    returns its own "nothing done" result.
    """
    for domain in (target_domain, source_domain):
        verdict = domain_scope_verdict(shell, domain)
        if not verdict.in_scope:
            # The escalation edge joins the two domain objects; noting it lets the
            # shared status derivation split every route that crosses it.
            refuse_outside_scope(
                shell,
                relation=technique,
                out_domain=verdict.domain or _norm(domain),
                surface=surface,
                path_domain=_norm(source_domain),
                from_label=str(source_domain or "").strip().upper(),
                source_domain=source_domain,
                to_label=str(target_domain or "").strip().upper(),
            )
            return False
    target_dc = _target_domain_dc(shell, target_domain)
    if target_dc:
        asset = host_scope_verdict(shell, host=target_dc, domain=_norm(target_domain))
        if not asset.allowed:
            refuse_outside_scope(
                shell,
                relation=technique,
                out_domain="",
                surface=surface,
                path_domain=_norm(source_domain),
                from_label=str(source_domain or "").strip().upper(),
                source_domain=source_domain,
                to_label=str(target_domain or "").strip().upper(),
                asset_verdict=asset,
            )
            return False
    return True


def _target_domain_dc(shell: Any, domain: str) -> str:
    """The recorded DC a cross-domain runner will contact in ``domain``."""
    if _asset_state(shell) is None:
        return ""
    domains_data = getattr(shell, "domains_data", None)
    data = domains_data.get(_norm(domain)) if isinstance(domains_data, Mapping) else None
    if not isinstance(data, dict):
        return ""
    try:
        from adscan_internal.models.domain import resolve_dc_ip  # noqa: PLC0415

        return str(resolve_dc_ip(data) or "")
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return ""


__all__ = (
    "ASSET_REASON_AFFECTED_HOSTS_UNDETERMINED",
    "ASSET_REASON_ALLOWED",
    "HOST_REACHING_KINDS",
    "ASSET_REASON_DC_DIRECTORY_ONLY",
    "ASSET_REASON_DENIED",
    "ASSET_REASON_DOMAIN_OUTSIDE",
    "ASSET_REASON_NOT_IN_ALLOW",
    "ASSET_REASON_UNDETERMINED",
    "ASSET_REASON_UNREADABLE",
    "AddressSpacePartition",
    "AssetScopeVerdict",
    "Contact",
    "ContactPurpose",
    "DIRECTORY_PIPES",
    "DIRECTORY_SHARES",
    "EGRESS_GUARD_ENV",
    "contact_for_port",
    "contact_purpose_for",
    "DIRECTORY_PLANE_PORTS",
    "HOST_OUTSIDE_ASSET_SCOPE",
    "ScopeOutcome",
    "ScopePartition",
    "ScopeRecordWriteError",
    "asset_refusal_line",
    "asset_scope",
    "asset_scope_block",
    "asset_scope_errors",
    "asset_scope_recorded",
    "asset_scope_unreadable",
    "asset_verdict_note",
    "controller_exclusion_error",
    "dc_scope_configuration_error",
    "declare_scan_target",
    "NameAnswer",
    "scope_name_servers_asked",
    "egress_address_refused",
    "egress_allowed",
    "egress_guard_disabled_by_operator",
    "flush_engagement_scope",
    "host_scope_verdict",
    "install_asset_scope_egress_guard",
    "note_host_addresses",
    "note_host_addresses_batch",
    "on_directory_committed",
    "partition_address_space_in_scope",
    "partition_principals_in_scope",
    "partition_targets_in_scope",
    "prepare_scope_principals",
    "prepare_scope_targets",
    "principal_scope_verdict",
    "record_asset_scope",
    "record_backstop_hit",
    "record_scope_refusals",
    "rehydrate_engagement_scope",
    "reload_asset_scope",
    "require_host_in_scope",
    "require_repl_target_in_scope",
    "require_session_host_in_scope",
    "resolve_asset_scope",
    "scanner_exclusions",
    "scope_checkpoint",
    "session_host_verdict",
    "step_scope_refusal_line",
    "BASIS_EXCLUDED",
    "BASIS_NOT_CONFIRMED",
    "BASIS_RECORD_UNREADABLE",
    "BASIS_ORIGIN",
    "BASIS_PATH_DOMAIN",
    "BASIS_POLICY_AUTOMATIC",
    "BASIS_SELECTED",
    "BASIS_UNDETERMINED",
    "HOST_IN_OTHER_DOMAIN",
    "HOST_IN_SCOPE",
    "HOST_UNDETERMINED",
    "HOST_OUTSIDE_SCOPE",
    "HOST_OWNED_BY_COLLECTING_DOMAIN",
    "CollectionHostVerdict",
    "ScopeVerdict",
    "StepScopeVerdict",
    "domain_in_engagement_scope",
    "domain_scope_verdict",
    "collecting_domain_context",
    "collection_host_skip_line",
    "collection_host_verdict",
    "gate_cross_domain_technique",
    "current_collecting_domain",
    "host_owner_domain",
    "linked_server_gate_active",
    "linked_server_host",
    "linked_server_query_refusal",
    "linked_server_target_verdict",
    "note_collection_host_skipped",
    "object_domain",
    "origin_domains",
    "outside_scope_line",
    "record_trust_scope_decision",
    "refuse_outside_scope",
    "resolve_linked_server_host",
    "register_scope_shell",
    "scope_entry",
    "step_scope_verdict",
)
