"""Centralized audit ledger for all environment changes made during a scan."""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from typing import Any

from adscan_internal import print_info, print_success, print_warning, telemetry
from adscan_internal.cli.ci_events import emit_event
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services import cleanup_taxonomy as _tax
from adscan_internal.workspaces.io import read_json_file, write_json_file

_LEDGER_FILENAME = "environment_changes.json"
# Schema 1.0 → 1.1 adds the verified-revert taxonomy fields (verified_at,
# verification_method, manual_reason, remediation_command, remediation_object_dn,
# revert_attempts, min_credential_principal) and the reverted_confirmed /
# manual_required terminal states. Old 1.0 workspaces are backfilled on _load.
_SCHEMA_VERSION = "1.1"
_LEGACY_SCHEMA_VERSION = "1.0"

# Re-exported taxonomy constants (the ledger module is the historical import
# point; cleanup_taxonomy is the SSOT). New code may import either.
STATUS_PENDING = _tax.STATUS_PENDING
STATUS_REVERT_IN_PROGRESS = _tax.STATUS_REVERT_IN_PROGRESS
STATUS_REVERT_FAILED_RETRYING = _tax.STATUS_REVERT_FAILED_RETRYING
STATUS_REVERTED_CONFIRMED = _tax.STATUS_REVERTED_CONFIRMED
STATUS_KEPT = _tax.STATUS_KEPT
STATUS_MANUAL_REQUIRED = _tax.STATUS_MANUAL_REQUIRED
CLEANUP_BUCKET_REVERTED = _tax.CLEANUP_BUCKET_REVERTED
CLEANUP_BUCKET_MANUAL = _tax.CLEANUP_BUCKET_MANUAL
CLEANUP_BUCKET_KEPT = _tax.CLEANUP_BUCKET_KEPT
CLEANUP_BUCKET_IN_PROGRESS = _tax.CLEANUP_BUCKET_IN_PROGRESS
cleanup_bucket = _tax.cleanup_bucket

# Maximum bounded retries before a transient revert failure becomes manual.
MAX_REVERT_ATTEMPTS = 3

# Change lifecycle classes. They govern WHEN/WHETHER a reversible change is
# reverted at workspace exit:
#   * AUTO_REVERT        — transient artifacts (uploaded files, Ligolo agents, an
#                          enabled xp_cmdshell). Reverted automatically by the
#                          owning service at exit. This is the historical
#                          default, so every existing caller keeps its behavior
#                          unchanged.
#   * OPERATOR_CONFIRMED — durable AD objects/grants ADscan minted (machine
#                          accounts, RBCD delegation, KeyCredentialLink). NOT
#                          auto-reverted: a successful run keeps them so the
#                          operator retains the access and can reuse the asset;
#                          at exit the operator is prompted whether to revert.
CHANGE_CLASS_AUTO_REVERT = "auto_revert"
CHANGE_CLASS_OPERATOR_CONFIRMED = "operator_confirmed"
_VALID_CHANGE_CLASSES = (CHANGE_CLASS_AUTO_REVERT, CHANGE_CLASS_OPERATOR_CONFIRMED)


def _utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


class EnvironmentChangeLedger:
    """Append-only audit ledger for environment changes during a scan.

    Persists every change to {workspace_dir}/environment_changes.json after
    each mutation. Emits structured events via ci_events for web UI consumption.
    Safe to instantiate even when the workspace directory does not exist yet —
    flush() will simply fail silently and capture via telemetry.
    """

    def __init__(self, workspace_dir: str) -> None:
        self._path = os.path.join(workspace_dir, _LEDGER_FILENAME)
        self._state: dict[str, Any] = self._load()

    # ── Public API ────────────────────────────────────────────────────────────

    def register_change(
        self,
        *,
        kind: str,
        domain: str,
        target: str,
        detail: dict[str, Any],
        method: str,
        change_class: str = CHANGE_CLASS_AUTO_REVERT,
    ) -> str:
        """Register a new environment change. Returns change_id. Flushes to disk.

        Args:
            kind: Change category (e.g. "group_membership_added", "file_uploaded").
            domain: Domain where the change occurred (e.g. "corp.local").
            target: Human-readable description of the affected object.
            detail: Arbitrary key-value metadata for the change.
            method: Attack method or technique that caused the change.
            change_class: Lifecycle class governing exit cleanup. Defaults to
                ``CHANGE_CLASS_AUTO_REVERT`` (the historical behavior — every
                existing caller is unaffected). Durable AD objects/grants pass
                ``CHANGE_CLASS_OPERATOR_CONFIRMED`` so they are kept on success
                and only reverted on operator confirmation at exit.

        Returns:
            Unique change_id string (UUID4).
        """
        normalized_class = (
            change_class if change_class in _VALID_CHANGE_CLASSES else CHANGE_CLASS_AUTO_REVERT
        )
        change_id = str(uuid.uuid4())
        entry: dict[str, Any] = {
            "change_id": change_id,
            "kind": str(kind),
            "change_class": normalized_class,
            "domain": str(domain),
            "target": str(target),
            "detail": dict(detail),
            "method": str(method),
            "registered_at": _utc_now_iso(),
            "revert_status": STATUS_PENDING,
            "reverted_at": None,
            "revert_error": None,
            "manual_cleanup_instructions": None,
            # Schema 1.1 verified-revert taxonomy fields.
            "verified_at": None,
            "verification_method": None,
            "manual_reason": None,
            "remediation_command": None,
            "remediation_object_dn": None,
            "revert_attempts": 0,
            "min_credential_principal": None,
        }
        self._state["changes"].append(entry)
        self._recompute_summary()
        self.flush()
        emit_event(
            "environment_change_registered",
            change_id=change_id,
            kind=kind,
            domain=domain,
            target=target,
            revert_status="pending",
            change_class=normalized_class,
        )
        print_info(
            f"Environment change registered · {kind} · {mark_sensitive(target, 'text')}"
        )
        return change_id

    def mark_reverted(self, change_id: str, *, reverted_at: str | None = None) -> None:
        """DEPRECATED — prefer :meth:`mark_reverted_confirmed` after a verify re-read.

        Retained as a back-compat shim: a bare revert with no verification still
        reaches the good terminal state for callers that have not yet adopted the
        verify-the-undo flow. New code MUST call ``mark_reverted_confirmed`` only
        after the post-revert re-read confirms the change is gone.

        Args:
            change_id: ID returned by register_change.
            reverted_at: Optional ISO timestamp; defaults to now.
        """
        entry = self._find(change_id)
        if entry is None:
            return
        entry["revert_status"] = STATUS_REVERTED_CONFIRMED
        entry["reverted_at"] = reverted_at or _utc_now_iso()
        self._recompute_summary()
        self.flush()
        emit_event(
            "environment_change_reverted",
            change_id=change_id,
            revert_status=STATUS_REVERTED_CONFIRMED,
        )
        print_success(
            f"Reverted · {entry['kind']} · {mark_sensitive(entry['target'], 'text')}"
        )

    def mark_revert_in_progress(self, change_id: str) -> None:
        """Transition ``pending``/``revert_failed_retrying`` → ``revert_in_progress``.

        Marks that a revert attempt is running NOW. If the session dies while a
        record is in this state, ``finalize()`` force-transitions it to
        ``manual_required(session_died)`` so a half-state is never reported as
        done. Emits a registered-style event for the live web view.
        """
        entry = self._find(change_id)
        if entry is None:
            return
        if entry.get("revert_status") not in (
            STATUS_PENDING,
            STATUS_REVERT_FAILED_RETRYING,
        ):
            # Already terminal or already in progress — no-op.
            return
        entry["revert_status"] = STATUS_REVERT_IN_PROGRESS
        self._recompute_summary()
        self.flush()
        emit_event(
            "environment_change_reverting",
            change_id=change_id,
            revert_status=STATUS_REVERT_IN_PROGRESS,
        )

    def mark_reverted_confirmed(
        self,
        change_id: str,
        *,
        verification_method: str,
        verified_at: str | None = None,
        min_credential_principal: str | None = None,
    ) -> None:
        """The ONLY path to the good terminal state after a confirming re-read.

        Args:
            change_id: ID returned by register_change.
            verification_method: How the revert was confirmed (e.g.
                ``"group_membership_reread"``).
            verified_at: Optional ISO timestamp of the confirming re-read.
            min_credential_principal: Which principal performed the revert.
        """
        entry = self._find(change_id)
        if entry is None:
            return
        now = _utc_now_iso()
        entry["revert_status"] = STATUS_REVERTED_CONFIRMED
        entry["reverted_at"] = entry.get("reverted_at") or now
        entry["verified_at"] = verified_at or now
        entry["verification_method"] = str(verification_method)
        if min_credential_principal:
            entry["min_credential_principal"] = str(min_credential_principal)
        # Clearing any prior failure context on a confirmed revert.
        entry["revert_error"] = None
        entry["manual_reason"] = None
        self._recompute_summary()
        self.flush()
        emit_event(
            "environment_change_reverted",
            change_id=change_id,
            revert_status=STATUS_REVERTED_CONFIRMED,
        )
        print_success(
            f"Reverted (confirmed) · {entry['kind']} · "
            f"{mark_sensitive(entry['target'], 'text')}"
        )

    def mark_revert_retry(self, change_id: str, *, error: str) -> int:
        """Account one transient revert failure under the bounded-retry budget.

        Increments ``revert_attempts``. While attempts remain (< MAX_REVERT_ATTEMPTS)
        sets ``revert_failed_retrying`` and returns the attempts used so far. When
        the budget is exhausted, routes to ``mark_manual_required`` with
        ``manual_reason="revert_failed"`` and returns the attempts used.

        A ``TimeoutError`` / transient stall MUST pass through here, never become
        a terminal state on the first hit.

        Returns:
            The number of attempts used so far (1-based).
        """
        entry = self._find(change_id)
        if entry is None:
            return 0
        attempts = int(entry.get("revert_attempts") or 0) + 1
        entry["revert_attempts"] = attempts
        entry["revert_error"] = str(error)
        if attempts < MAX_REVERT_ATTEMPTS:
            entry["revert_status"] = STATUS_REVERT_FAILED_RETRYING
            self._recompute_summary()
            self.flush()
            emit_event(
                "environment_change_reverting",
                change_id=change_id,
                revert_status=STATUS_REVERT_FAILED_RETRYING,
                error=error,
            )
            return attempts
        # Budget exhausted — definitive manual.
        self.mark_manual_required(
            change_id,
            reason=_tax.MANUAL_REASON_REVERT_FAILED,
            remediation_command=str(entry.get("remediation_command") or ""),
            remediation_object_dn=str(entry.get("remediation_object_dn") or ""),
            error=error,
        )
        return attempts

    def mark_manual_required(
        self,
        change_id: str,
        *,
        reason: str,
        remediation_command: str,
        remediation_object_dn: str,
        error: str | None = None,
        manual_cleanup_instructions: str | None = None,
    ) -> None:
        """The ONE legal-critical terminal state: client must clean up by hand.

        Supersedes :meth:`mark_failed` / :meth:`mark_operator_required` (both kept
        as thin shims). Records WHY (``manual_reason``), the client-safe native
        ``remediation_command``, and the exact ``remediation_object_dn`` the client
        acts on, so the report never shows a half-state.

        Args:
            change_id: ID returned by register_change.
            reason: A ``cleanup_taxonomy.MANUAL_REASON_*`` discriminator.
            remediation_command: Client-safe native command (native only).
            remediation_object_dn: The exact DN the client acts on.
            error: Optional underlying error string.
            manual_cleanup_instructions: Optional free-text fallback (kept for
                back-compat rendering).
        """
        entry = self._find(change_id)
        if entry is None:
            return
        entry["revert_status"] = STATUS_MANUAL_REQUIRED
        entry["manual_reason"] = str(reason)
        if remediation_command:
            entry["remediation_command"] = str(remediation_command)
        if remediation_object_dn:
            entry["remediation_object_dn"] = str(remediation_object_dn)
        if error is not None:
            entry["revert_error"] = str(error)
        instructions = manual_cleanup_instructions or remediation_command
        if instructions:
            entry["manual_cleanup_instructions"] = str(instructions)
        self._recompute_summary()
        self.flush()
        emit_event(
            "environment_change_failed",
            change_id=change_id,
            revert_status=STATUS_MANUAL_REQUIRED,
            error=error or _tax.manual_reason_label(reason),
        )
        print_warning(
            f"Manual cleanup required · {entry['kind']} · "
            f"{mark_sensitive(entry['target'], 'text')}"
        )

    def set_revert_metadata(
        self,
        change_id: str,
        *,
        remediation_command: str | None = None,
        remediation_object_dn: str | None = None,
        min_credential_principal: str | None = None,
    ) -> None:
        """Stamp remediation metadata on a record before/while reverting.

        Lets a cleanup service record the client-safe command + object DN up front
        so that a later ``mark_revert_retry`` exhaustion (which routes to
        ``mark_manual_required``) carries the right remediation even when the
        retry site has no metadata in scope.
        """
        entry = self._find(change_id)
        if entry is None:
            return
        if remediation_command is not None:
            entry["remediation_command"] = str(remediation_command)
        if remediation_object_dn is not None:
            entry["remediation_object_dn"] = str(remediation_object_dn)
        if min_credential_principal is not None:
            entry["min_credential_principal"] = str(min_credential_principal)
        self.flush()

    def mark_kept(self, change_id: str) -> None:
        """Mark an operator_confirmed change as intentionally kept by the operator.

        Used when the operator chooses to retain a durable AD object/grant at
        exit (or when a successful run keeps it). Distinct from a failed revert:
        the change is durable on purpose, not because cleanup failed. Flushes to
        disk.

        Args:
            change_id: ID returned by register_change.
        """
        entry = self._find(change_id)
        if entry is None:
            return
        entry["revert_status"] = "kept"
        entry["reverted_at"] = None
        entry["revert_error"] = None
        self._recompute_summary()
        self.flush()
        emit_event("environment_change_kept", change_id=change_id, revert_status="kept")
        print_info(
            f"Kept by operator · {entry['kind']} · {mark_sensitive(entry['target'], 'text')}"
        )

    def mark_failed(
        self,
        change_id: str,
        *,
        error: str,
        manual_cleanup_instructions: str | None = None,
    ) -> None:
        """DEPRECATED shim — delegates to :meth:`mark_manual_required`.

        Existing call sites keep compiling, but new code MUST call
        ``mark_manual_required`` directly (a structural test asserts no new call
        site uses this). Maps to ``manual_reason="revert_failed"``.

        Args:
            change_id: ID returned by register_change.
            error: Error message describing why the revert failed.
            manual_cleanup_instructions: Optional instructions for manual remediation.
        """
        self.mark_manual_required(
            change_id,
            reason=_tax.MANUAL_REASON_REVERT_FAILED,
            remediation_command=manual_cleanup_instructions or "",
            remediation_object_dn="",
            error=error,
            manual_cleanup_instructions=manual_cleanup_instructions,
        )

    def mark_operator_required(
        self,
        change_id: str,
        *,
        manual_cleanup_instructions: str,
    ) -> None:
        """DEPRECATED shim — delegates to :meth:`mark_manual_required`.

        Existing call sites keep compiling, but new code MUST call
        ``mark_manual_required`` directly. Maps to ``manual_reason="not_attempted"``.

        Args:
            change_id: ID returned by register_change.
            manual_cleanup_instructions: Instructions the operator must follow to clean up.
        """
        self.mark_manual_required(
            change_id,
            reason=_tax.MANUAL_REASON_NOT_ATTEMPTED,
            remediation_command=str(manual_cleanup_instructions),
            remediation_object_dn="",
            manual_cleanup_instructions=str(manual_cleanup_instructions),
        )

    def find_and_reset_failed(self, kind: str, target: str) -> str | None:
        """Find the most recent failed entry matching kind+target and reset it to pending.

        Returns the change_id if found and reset, None if no matching failed entry exists.
        Idempotent: a second call for the same entry returns None (it is no longer failed).
        Used by retry-on-reentry: cleanup services call this before register_change so that
        failed entries are reused and updated rather than duplicated in the ledger.

        Args:
            kind: Change category to match (e.g. "file_uploaded").
            target: Target string to match exactly.

        Returns:
            The change_id string of the reset entry, or None if no failed match exists.
        """
        matched: dict[str, Any] | None = None
        for entry in self._state["changes"]:
            status = str(entry.get("revert_status") or "").strip().lower()
            # A retryable "failed" today is either the legacy ``failed`` status or
            # the collapsed ``manual_required(revert_failed)`` terminal state.
            is_retryable_fail = status == _tax.STATUS_LEGACY_FAILED or (
                status == STATUS_MANUAL_REQUIRED
                and str(entry.get("manual_reason") or "")
                == _tax.MANUAL_REASON_REVERT_FAILED
            )
            if (
                entry.get("kind") == kind
                and entry.get("target") == target
                and is_retryable_fail
            ):
                matched = entry  # keep iterating to get the last (most recent) match
        if matched is None:
            return None
        matched["revert_status"] = STATUS_PENDING
        matched["revert_error"] = None
        matched["manual_reason"] = None
        matched["revert_attempts"] = 0
        self._recompute_summary()
        self.flush()
        return str(matched["change_id"])

    def get_operator_confirmed_pending(self) -> list[dict[str, Any]]:
        """Return durable operator_confirmed changes still standing (deep copies).

        "Still standing" means the change has not been reverted, kept, or marked
        for manual action yet — i.e. ``revert_status`` is ``pending`` or
        ``failed``. These are the changes the exit hook offers to revert. Each
        entry is a shallow copy of the record with a deep-copied ``detail`` so
        callers can read the prior-state metadata needed to revert.

        Returns:
            List of operator_confirmed change entry dicts.
        """
        still_standing = {
            STATUS_PENDING,
            STATUS_REVERT_IN_PROGRESS,
            STATUS_REVERT_FAILED_RETRYING,
            _tax.STATUS_LEGACY_FAILED,
        }
        out: list[dict[str, Any]] = []
        for entry in self._state["changes"]:
            if entry.get("change_class") != CHANGE_CLASS_OPERATOR_CONFIRMED:
                continue
            status = str(entry.get("revert_status") or "").strip().lower()
            is_standing = status in still_standing or (
                status == STATUS_MANUAL_REQUIRED
                and str(entry.get("manual_reason") or "")
                == _tax.MANUAL_REASON_REVERT_FAILED
            )
            if not is_standing:
                continue
            copy = dict(entry)
            copy["detail"] = dict(entry.get("detail") or {})
            out.append(copy)
        return out

    def finalize(self) -> None:
        """Mark scan complete, force-transition non-terminal records, and flush.

        Legal-critical session-died guarantee: any record still left
        ``pending`` / ``revert_in_progress`` / ``revert_failed_retrying`` at
        finalize (e.g. the session died mid-revert via Ctrl+C/crash) is
        force-transitioned to ``manual_required(session_died)`` with a native
        remediation command + the object DN, so the report NEVER shows a
        half-state and the client always gets a complete manual checklist. A
        change ADscan could not PROVE it reverted is always reported as manual.
        """
        non_terminal = {
            STATUS_PENDING,
            STATUS_REVERT_IN_PROGRESS,
            STATUS_REVERT_FAILED_RETRYING,
        }
        for entry in self._state["changes"]:
            status = str(entry.get("revert_status") or "").strip().lower()
            if status not in non_terminal:
                continue
            command = self._remediation_command_for(entry)
            object_dn = self._remediation_dn_for(entry)
            self.mark_manual_required(
                str(entry.get("change_id") or ""),
                reason=_tax.MANUAL_REASON_SESSION_DIED,
                remediation_command=command,
                remediation_object_dn=object_dn,
                error="Session ended before rollback completed.",
            )
        self._state["scan_completed_at"] = _utc_now_iso()
        self.flush()

    def _remediation_command_for(self, entry: dict[str, Any]) -> str:
        """Resolve a client-safe native remediation command for a record."""
        existing = str(entry.get("remediation_command") or "").strip()
        if existing:
            return existing
        existing_instr = str(entry.get("manual_cleanup_instructions") or "").strip()
        if existing_instr:
            return existing_instr
        kind = str(entry.get("kind") or "")
        target = str(entry.get("target") or "TARGET")
        detail = entry.get("detail") if isinstance(entry.get("detail"), dict) else {}
        spn = str((detail or {}).get("spn") or "SPN")
        return (
            _tax.remediation_template_for_kind(kind)
            .replace("TARGET", target)
            .replace("SPN", spn)
        )

    def _remediation_dn_for(self, entry: dict[str, Any]) -> str:
        """Resolve the best-known object DN for the client to act on."""
        existing = str(entry.get("remediation_object_dn") or "").strip()
        if existing:
            return existing
        detail = entry.get("detail") if isinstance(entry.get("detail"), dict) else {}
        detail = detail or {}
        for key in ("target_dn", "object_dn", "dn", "target_object"):
            value = str(detail.get(key) or "").strip()
            if value:
                return value
        return str(entry.get("target") or "").strip()

    def get_summary(self) -> dict[str, int]:
        """Return current summary counts (copy).

        Returns:
            Dictionary with keys: total, reverted, reverted_confirmed,
            manual_required, kept, pending, pending_manual, failed, in_progress.
        """
        return dict(self._state["summary"])

    def get_cleanup_report(self) -> dict[str, Any]:
        """Return the normalized, render-ready cleanup report (the ONE shape).

        Both the PDF context builder and the web ingester consume this — neither
        re-derives buckets, labels, or remediation. See
        :func:`build_cleanup_report_from_dict` for the pure equivalent used by the
        report process (which does not hold a live ledger).

        Returns:
            ``{summary, reverted, manual, kept, in_progress}`` where each list
            item is a normalized change dict.
        """
        return _build_cleanup_report(
            self._state.get("changes") or [], self.get_summary()
        )

    def get_changes(self) -> list[dict[str, Any]]:
        """Return all change entries (shallow copy of the list, deep copy of each entry).

        Returns:
            List of change entry dicts.
        """
        return [dict(entry) for entry in self._state["changes"]]

    def flush(self) -> None:
        """Write current state to disk. Called automatically by mutating methods."""
        try:
            write_json_file(self._path, self._state)
        except Exception as exc:  # pylint: disable=broad-except
            telemetry.capture_exception(exc)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _load(self) -> dict[str, Any]:
        if os.path.exists(self._path):
            try:
                data = read_json_file(self._path)
                if isinstance(data, dict) and data.get("schema_version") in (
                    _SCHEMA_VERSION,
                    _LEGACY_SCHEMA_VERSION,
                ):
                    _backfill_schema_1_1(data)
                    self._state = data
                    self._recompute_summary()
                    return data
            except Exception as exc:  # pylint: disable=broad-except
                telemetry.capture_exception(exc)
        return {
            "schema_version": _SCHEMA_VERSION,
            "session_id": str(uuid.uuid4()),
            "scan_started_at": _utc_now_iso(),
            "scan_completed_at": None,
            "changes": [],
            "summary": _empty_summary(),
        }

    def _find(self, change_id: str) -> dict[str, Any] | None:
        for entry in self._state["changes"]:
            if entry.get("change_id") == change_id:
                return entry
        return None

    def _recompute_summary(self) -> None:
        self._state["summary"] = _compute_summary(self._state.get("changes") or [])


# ── Module-level helpers (pure — shared by the live ledger + the report path) ──


def _empty_summary() -> dict[str, int]:
    return {
        "total": 0,
        "reverted": 0,
        "reverted_confirmed": 0,
        "manual_required": 0,
        "kept": 0,
        "pending": 0,
        "pending_manual": 0,
        "failed": 0,
        "in_progress": 0,
    }


def _compute_summary(changes: list[dict[str, Any]]) -> dict[str, int]:
    """Compute summary counts by surface bucket. Keeps legacy keys populated."""
    buckets = {
        _tax.CLEANUP_BUCKET_REVERTED: 0,
        _tax.CLEANUP_BUCKET_MANUAL: 0,
        _tax.CLEANUP_BUCKET_KEPT: 0,
        _tax.CLEANUP_BUCKET_IN_PROGRESS: 0,
    }
    for c in changes:
        buckets[_tax.cleanup_bucket(c.get("revert_status"))] += 1
    return {
        "total": len(changes),
        # Legacy keys (kept so nothing downstream breaks); equal to the bucket.
        "reverted": buckets[_tax.CLEANUP_BUCKET_REVERTED],
        "reverted_confirmed": buckets[_tax.CLEANUP_BUCKET_REVERTED],
        "manual_required": buckets[_tax.CLEANUP_BUCKET_MANUAL],
        "kept": buckets[_tax.CLEANUP_BUCKET_KEPT],
        "pending": buckets[_tax.CLEANUP_BUCKET_IN_PROGRESS],
        "pending_manual": buckets[_tax.CLEANUP_BUCKET_MANUAL],
        "failed": buckets[_tax.CLEANUP_BUCKET_MANUAL],
        "in_progress": buckets[_tax.CLEANUP_BUCKET_IN_PROGRESS],
    }


def _backfill_schema_1_1(data: dict[str, Any]) -> None:
    """Backfill schema-1.1 fields onto any 1.0 record (in place).

    A missing change_class is the historical auto_revert. The schema-1.1 verified
    fields default to None/0. Legacy ``failed`` → manual_reason ``revert_failed``;
    legacy ``operator_required`` → ``not_attempted`` (statuses themselves are left
    as-is for back-compat reads — ``cleanup_bucket`` collapses them).
    """
    for entry in data.get("changes", []) or []:
        if not isinstance(entry, dict):
            continue
        if not entry.get("change_class"):
            entry["change_class"] = CHANGE_CLASS_AUTO_REVERT
        for field_name, default in (
            ("verified_at", None),
            ("verification_method", None),
            ("manual_reason", None),
            ("remediation_command", None),
            ("remediation_object_dn", None),
            ("revert_attempts", 0),
            ("min_credential_principal", None),
        ):
            entry.setdefault(field_name, default)
        status = str(entry.get("revert_status") or "").strip().lower()
        if not entry.get("manual_reason"):
            if status == _tax.STATUS_LEGACY_FAILED:
                entry["manual_reason"] = _tax.MANUAL_REASON_REVERT_FAILED
            elif status == _tax.STATUS_LEGACY_OPERATOR_REQUIRED:
                entry["manual_reason"] = _tax.MANUAL_REASON_NOT_ATTEMPTED
    data["schema_version"] = _SCHEMA_VERSION


def _normalize_change(entry: dict[str, Any]) -> dict[str, Any]:
    """Project one ledger record into the normalized render-ready shape."""
    status = str(entry.get("revert_status") or _tax.STATUS_PENDING)
    bucket = _tax.cleanup_bucket(status)
    detail = entry.get("detail") if isinstance(entry.get("detail"), dict) else {}
    detail = detail or {}
    object_dn = str(entry.get("remediation_object_dn") or "").strip()
    if not object_dn:
        for key in ("target_dn", "object_dn", "dn", "target_object"):
            candidate = str(detail.get(key) or "").strip()
            if candidate:
                object_dn = candidate
                break
    return {
        "change_id": str(entry.get("change_id") or ""),
        "kind": str(entry.get("kind") or ""),
        "kind_display": _tax.kind_display(entry.get("kind")),
        "domain": str(entry.get("domain") or ""),
        "target": str(entry.get("target") or ""),
        "object_dn": object_dn,
        "method": str(entry.get("method") or ""),
        "registered_at": entry.get("registered_at"),
        "reverted_at": entry.get("reverted_at"),
        "verified_at": entry.get("verified_at"),
        "verification_method": entry.get("verification_method"),
        "bucket": bucket,
        "status": status,
        "status_label": _tax.status_label(status),
        "manual_reason": entry.get("manual_reason"),
        "manual_reason_label": _tax.manual_reason_label(entry.get("manual_reason"))
        if entry.get("manual_reason")
        else None,
        "remediation_command": str(
            entry.get("remediation_command")
            or entry.get("manual_cleanup_instructions")
            or ""
        ),
        "performed_as": entry.get("min_credential_principal"),
    }


def _build_cleanup_report(
    changes: list[dict[str, Any]], summary: dict[str, int]
) -> dict[str, Any]:
    """Build the normalized {summary, reverted, manual, kept, in_progress} shape."""
    out: dict[str, Any] = {
        "summary": dict(summary),
        _tax.CLEANUP_BUCKET_REVERTED: [],
        _tax.CLEANUP_BUCKET_MANUAL: [],
        _tax.CLEANUP_BUCKET_KEPT: [],
        _tax.CLEANUP_BUCKET_IN_PROGRESS: [],
    }
    for entry in changes:
        if not isinstance(entry, dict):
            continue
        normalized = _normalize_change(entry)
        out[normalized["bucket"]].append(normalized)
    return out


def build_cleanup_report_from_dict(env_changes: dict[str, Any] | None) -> dict[str, Any] | None:
    """Build the cleanup report from the persisted ``environment_changes`` dict.

    Same shape as :meth:`EnvironmentChangeLedger.get_cleanup_report`, built from
    the ``{summary, changes}`` dict attached to ``technical_report.json``. The
    report process does not hold a live ledger, so the PDF context builder and the
    web ingester call this pure function instead. Returns ``None`` when there are
    no changes (caller omits the whole section).

    Args:
        env_changes: The ``report_data["environment_changes"]`` dict, or None.

    Returns:
        The normalized report dict, or None when there is nothing to report.
    """
    if not isinstance(env_changes, dict):
        return None
    changes = env_changes.get("changes")
    if not isinstance(changes, list) or not changes:
        return None
    summary = env_changes.get("summary")
    if not isinstance(summary, dict):
        summary = _compute_summary(changes)
    else:
        # Ensure the bucket keys exist even on a persisted legacy summary.
        recomputed = _compute_summary(changes)
        merged = dict(recomputed)
        merged.update({k: v for k, v in summary.items() if isinstance(v, int)})
        summary = merged
    return _build_cleanup_report(changes, summary)
