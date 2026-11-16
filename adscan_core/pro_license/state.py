"""Local PRO licence state: the licence, queued requests and the domain register.

Files, all in the licence directory (``enterprise_license.license_dir()``,
``<state>/license``, which the launcher bind-mounts into the engine
container so the host command and the engine read the same state):

* ``pro-license.json`` — the installed licence document (as signed).
* ``pro-installation.json`` — the installation key pair (0600).
* ``pro-pending.json`` — requests signed but not yet answered (0600: an
  activation request carries the activation key).
* ``pro-register.json`` — one entry per domain code: pending, registered
  (with our signed receipt, and only while that receipt verifies:
  :meth:`ProLicenseStore.verified_receipt`) or refused; plus the usage lines, one per
  assessment of a code (run kind, run id, parent run, band, date), from which
  :mod:`adscan_core.pro_license.billable_engagements` counts engagements.
* ``pro-notice.json`` — the last terminal notice (revoked, deactivated).
* ``pro-checkin.json`` — when this machine last checked in and what came back.
* ``clock-state.json`` — shared with the Enterprise licence: the clock
  high-water mark, the sealed ``first_seen`` of each pending code, and the
  latest domain-controller time seen during a scan (``pro_dc_time_witness``,
  an expiry witness the operator does not control).

Every change goes through :meth:`ProLicenseStore.apply_answer`, which accepts
an answer only when it is signed by the server, names this installation and
settles a request this installation emitted and still holds (spec § 5.3).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from adscan_core.enterprise_license import (
    CLOCK_STATE_FILENAME,
    LicenseError,
)
from adscan_core.environment_ledger import state_file_lock
from adscan_core.pro_license import documents as docs
from adscan_core.pro_license._io import read_json, write_json
from adscan_core.pro_license.billable_engagements import AssessmentRecord
from adscan_core.pro_license.installation import Installation
from adscan_core.pro_license.model import ProLicense, parse_pro_license

LICENCE_FILENAME = "pro-license.json"
PENDING_FILENAME = "pro-pending.json"
REGISTER_FILENAME = "pro-register.json"
NOTICE_FILENAME = "pro-notice.json"
CREDENTIAL_FILENAME = "pro-registry-credential.json"
CHECK_IN_FILENAME = "pro-checkin.json"
FIRST_SEEN_SEAL_KEY = "pro_first_seen"
DC_TIME_WITNESS_KEY = "pro_dc_time_witness"

#: Check-in outcome recorded when the server did not answer (same value as
#: ``client.CHECK_IN_UNREACHABLE``; the client imports this module, not the reverse).
CHECK_IN_UNREACHABLE_RESULT = "unreachable"

STATUS_PENDING = "pending"
STATUS_REGISTERED = "registered"
STATUS_REFUSED = "refused"


@dataclass(frozen=True)
class ApplyResult:
    """What happened to one server answer."""

    applied: bool
    kind: str = ""
    reason: str = ""
    message: str = ""
    notice_code: str = ""


def _min_instant(*values: str | None) -> str | None:
    parsed = []
    for value in values:
        if not value:
            continue
        try:
            parsed.append(docs.parse_instant(value))
        except (TypeError, ValueError):
            continue
    return docs.format_instant(min(parsed)) if parsed else None


class ProLicenseStore:
    """Read and change the PRO licence state in one directory."""

    def __init__(self, directory: Path | str | None = None) -> None:
        if directory is None:
            from adscan_core.enterprise_license import license_dir

            directory = license_dir()
        self.directory = Path(directory)

    # ── Paths ────────────────────────────────────────────────────────────────

    @property
    def licence_path(self) -> Path:
        return self.directory / LICENCE_FILENAME

    def _path(self, name: str) -> Path:
        return self.directory / name

    # ── Installation ─────────────────────────────────────────────────────────

    def installation(self) -> Installation:
        """The installation of this machine (created on first use)."""
        return Installation.load_or_create(self.directory)

    def existing_installation(self) -> Installation | None:
        """The installation, or None when this machine never created one."""
        return Installation.load(self.directory)

    # ── Licence ──────────────────────────────────────────────────────────────

    def has_licence_file(self) -> bool:
        return self.licence_path.exists()

    def load_licence(
        self, *, trusted_keys: Mapping[str, str] | None = None
    ) -> tuple[ProLicense | None, LicenseError | None]:
        """Return ``(licence, None)``, ``(None, error)`` or ``(None, None)`` (absent)."""
        try:
            raw = self.licence_path.read_bytes()
        except FileNotFoundError:
            return None, None
        except OSError:
            return None, LicenseError("unreadable", "The licence file cannot be read.")
        try:
            licence = parse_pro_license(raw, trusted_keys=trusted_keys)
        except LicenseError as exc:
            return None, exc
        installation = self.existing_installation()
        if licence.bound and (
            installation is None
            or not licence.bound_to(installation.installation_id, installation.public_key_b64)
        ):
            return None, LicenseError(
                "wrong_installation",
                "This licence belongs to another installation. Activate this machine with "
                "`adscan license activate`.",
            )
        return licence, None

    def install_licence_document(
        self, raw: bytes | str | Mapping[str, Any], *, trusted_keys: Mapping[str, str] | None = None
    ) -> ProLicense:
        """Verify a licence and, only if it verifies for this installation, install it.

        Raises:
            LicenseError: it does not verify or belongs to another installation.
        """
        if isinstance(raw, Mapping):
            raw = json.dumps(raw)
        licence = parse_pro_license(raw, trusted_keys=trusted_keys)
        installation = self.installation() if licence.bound else self.existing_installation()
        if licence.bound and (
            installation is None
            or not licence.bound_to(installation.installation_id, installation.public_key_b64)
        ):
            raise LicenseError("wrong_installation", "This licence belongs to another installation.")
        data = raw.encode("utf-8") if isinstance(raw, str) else raw
        with state_file_lock(self.directory):
            from adscan_core.pro_license._io import atomic_write

            atomic_write(self.licence_path, data, mode=0o644)
            notice = self._path(NOTICE_FILENAME)
            if notice.exists():
                notice.unlink()
            # A document the server just signed supersedes what a domain
            # controller's clock said about the previous one.
            state = self._clock_state()
            if DC_TIME_WITNESS_KEY in state:
                state.pop(DC_TIME_WITNESS_KEY)
                write_json(self._path(CLOCK_STATE_FILENAME), state)
        self.record_server_time(licence.issued_at)
        return licence

    def remove_licence(self) -> None:
        """Remove the local licence (after a deactivation)."""
        with state_file_lock(self.directory):
            for name in (LICENCE_FILENAME, CREDENTIAL_FILENAME):
                try:
                    self._path(name).unlink()
                except FileNotFoundError:
                    pass

    # ── Pending requests ─────────────────────────────────────────────────────

    def pending(self) -> list[dict[str, Any]]:
        """Requests signed but not yet answered, oldest first."""
        data = read_json(self._path(PENDING_FILENAME))
        items = data.get("requests") if isinstance(data, Mapping) else None
        return [item for item in (items or []) if isinstance(item, dict)]

    def withdrawn_sequences(self) -> list[int]:
        """Sequence numbers dropped unsent and not yet declared to the server (spec § 5.6)."""
        data = read_json(self._path(PENDING_FILENAME))
        values = data.get("withdrawn") if isinstance(data, Mapping) else None
        return [n for n in (values or []) if isinstance(n, int) and not isinstance(n, bool) and n > 0]

    def _write_pending(self, items: list[dict[str, Any]], *, withdrawn: list[int] | None = None) -> None:
        if withdrawn is None:
            withdrawn = self.withdrawn_sequences()
        # Bounded: a machine that never reaches the server keeps only the newest numbers.
        kept = sorted(set(withdrawn))[-4096:]
        write_json(self._path(PENDING_FILENAME), {"requests": items, "withdrawn": kept}, mode=0o600)

    def build_request(self, kind: str, *, engine_version: str, **fields: Any) -> dict[str, Any]:
        """Sign a request that also states which earlier sequence numbers are held or withdrawn.

        The server uses the two lists to tell a request that was lost from one
        that is still queued here or was replaced (spec § 5.6). Every request
        this machine queues is built here.
        """
        held = []
        for item in self.pending():
            sequence = item.get("document", {}).get("payload", {}).get("sequence")
            if isinstance(sequence, int):
                held.append(sequence)
        context = {
            docs.PENDING_SEQUENCES_FIELD: docs.sequence_ranges(held),
            docs.WITHDRAWN_SEQUENCES_FIELD: docs.sequence_ranges(self.withdrawn_sequences()),
            # Which held numbers are registrations or engagement reports: the
            # server then closes each only when that same request arrives.
            docs.PENDING_USAGE_FIELD: docs.pending_usage(self.pending()),
        }
        return docs.build_request(self.installation(), kind, engine_version=engine_version, **context, **fields)

    def withdraw_pending(self, request_id: str) -> None:
        """Drop a queued request WITHOUT sending it (it was replaced) and remember its number.

        The next requests declare the number as withdrawn, so the server does
        not read it as a request that was lost.
        """
        with state_file_lock(self.directory):
            items = self.pending()
            dropped = next((i for i in items if i.get("request_id") == request_id), None)
            withdrawn = self.withdrawn_sequences()
            sequence = (dropped or {}).get("document", {}).get("payload", {}).get("sequence")
            if isinstance(sequence, int) and not isinstance(sequence, bool):
                withdrawn.append(sequence)
            self._write_pending([i for i in items if i.get("request_id") != request_id], withdrawn=withdrawn)

    def _acknowledge_withdrawn(self, payload: Mapping[str, Any]) -> None:
        """Forget withdrawn numbers a request the server answered already declared."""
        declared = docs.parse_sequence_ranges(payload.get(docs.WITHDRAWN_SEQUENCES_FIELD))
        if not declared:
            return
        with state_file_lock(self.directory):
            remaining = [n for n in self.withdrawn_sequences() if not docs.in_sequence_ranges(n, declared)]
            self._write_pending(self.pending(), withdrawn=remaining)

    def add_pending(self, document: Mapping[str, Any], **extra: Any) -> dict[str, Any]:
        """Queue a signed request."""
        payload = document["payload"]
        entry = {
            "request_id": payload["request_id"],
            "kind": payload["kind"],
            "digest": docs.request_digest(document),
            "created_at": payload["created_at"],
            "document": dict(document),
            **extra,
        }
        with state_file_lock(self.directory):
            items = [i for i in self.pending() if i.get("request_id") != entry["request_id"]]
            items.append(entry)
            self._write_pending(items)
        return entry

    def find_pending(self, request_id: str) -> dict[str, Any] | None:
        return next((i for i in self.pending() if i.get("request_id") == request_id), None)

    def pending_of_kind(self, kind: str, **match: Any) -> dict[str, Any] | None:
        """The queued request of ``kind`` whose payload matches ``match``."""
        for item in self.pending():
            payload = item.get("document", {}).get("payload", {})
            if item.get("kind") == kind and all(payload.get(k) == v for k, v in match.items()):
                return item
        return None

    def drop_pending(self, request_id: str) -> None:
        with state_file_lock(self.directory):
            self._write_pending([i for i in self.pending() if i.get("request_id") != request_id])

    # ── Register ─────────────────────────────────────────────────────────────
    #
    # ``pro-register.json`` = {"entries": {code: entry}, "assessments": [line],
    # "last_contact": instant}. ``assessments`` (the usage lines, one per
    # assessment of a code) was added after the first files were written: a
    # file without it reads as no lines, and every writer below rewrites the
    # whole document so no key is ever dropped.

    def _register_doc(self) -> dict[str, Any]:
        data = read_json(self._path(REGISTER_FILENAME))
        return dict(data) if isinstance(data, Mapping) else {}

    def _write_register_doc(self, **changes: Any) -> None:
        doc = self._register_doc()
        doc.update(changes)
        entries = doc.get("entries")
        lines = doc.get("assessments")
        last_contact = doc.get("last_contact")
        write_json(
            self._path(REGISTER_FILENAME),
            {
                "entries": dict(entries) if isinstance(entries, Mapping) else {},
                "assessments": list(lines) if isinstance(lines, list) else [],
                "last_contact": last_contact if isinstance(last_contact, str) else None,
            },
        )

    def register_entries(self) -> dict[str, dict[str, Any]]:
        entries = self._register_doc().get("entries")
        entries = entries if isinstance(entries, Mapping) else {}
        return {k: v for k, v in entries.items() if isinstance(v, dict)}

    def _write_register(self, entries: Mapping[str, Any]) -> None:
        self._write_register_doc(entries=dict(entries))

    def upsert_entry(self, code: str, **fields: Any) -> dict[str, Any]:
        with state_file_lock(self.directory):
            entries = self.register_entries()
            entry = dict(entries.get(code) or {"domain_code": code})
            entry.update(fields)
            entries[code] = entry
            self._write_register(entries)
            return entry

    def verified_receipt(
        self, code: str, *, trusted_keys: Mapping[str, str] | None = None
    ) -> dict[str, Any] | None:
        """The payload of ``code``'s registration receipt, or None when it does not prove a registration.

        The ONE test of "this domain is registered": the entry says so, it
        carries the receipt, the receipt is signed by a trusted licence-server
        key, and it names this domain code and this installation. A status
        written into ``pro-register.json`` by hand passes none of that.
        Never raises.
        """
        entry = self.register_entries().get(code) or {}
        receipt = entry.get("receipt")
        if entry.get("status") != STATUS_REGISTERED or not isinstance(receipt, Mapping):
            return None
        try:
            payload = docs.verify_server_document(
                receipt, trusted_keys=trusted_keys, kinds={docs.KIND_REGISTRATION_RECEIPT}
            )
        except (LicenseError, ValueError, TypeError, KeyError):
            return None
        installation = self.existing_installation()
        if installation is None or payload.get("installation_id") != installation.installation_id:
            return None
        if payload.get("domain_code") != code:
            return None
        return payload

    def is_registered(self, code: str, *, trusted_keys: Mapping[str, str] | None = None) -> bool:
        """True when ``code`` holds a receipt that verifies (:meth:`verified_receipt`)."""
        return self.verified_receipt(code, trusted_keys=trusted_keys) is not None

    def last_contact(self) -> str | None:
        value = self._register_doc().get("last_contact")
        return value if isinstance(value, str) else None

    def _set_last_contact(self, instant: str) -> None:
        self._write_register_doc(last_contact=instant)

    # ── Usage lines (one per assessment of a domain code) ───────────────────

    def assessment_lines(self) -> list[dict[str, Any]]:
        """The stored usage lines as written (oldest first)."""
        lines = self._register_doc().get("assessments")
        return [dict(line) for line in (lines if isinstance(lines, list) else []) if isinstance(line, Mapping)]

    def assessment_records(self) -> list[AssessmentRecord]:
        """The usage lines as records; a line that cannot be read is skipped."""
        records = (AssessmentRecord.from_dict(line) for line in self.assessment_lines())
        return [record for record in records if record is not None]

    def record_assessment_line(self, record: AssessmentRecord, *, supersedes: str | None = None) -> None:
        """Add or replace the line of ``record`` (one line per run, code and kind).

        ``supersedes``: the provisional code this run recorded before the
        forest root answered; its line for this run is replaced.
        """
        with state_file_lock(self.directory):
            lines = self.assessment_lines()
            keep = []
            for line in lines:
                same_run = record.run_id and line.get("run_id") == record.run_id
                if same_run and line.get("run_kind") == record.run_kind and line.get("domain_code") in (
                    record.domain_code,
                    supersedes,
                ):
                    continue
                keep.append(line)
            keep.append(record.to_dict())
            self._write_register_doc(assessments=keep)

    def _update_line(self, run_id: str, code: str, **fields: Any) -> bool:
        with state_file_lock(self.directory):
            lines = self.assessment_lines()
            changed = False
            for line in lines:
                if line.get("run_id") == run_id and line.get("domain_code") == code:
                    line.update(fields)
                    changed = True
            if changed:
                self._write_register_doc(assessments=lines)
            return changed

    def set_assessment_band(self, run_id: str, code: str, band: str) -> bool:
        """Record the identity band counted at scan end on that run's line."""
        return self._update_line(run_id, code, band=band)

    def set_assessment_size(
        self,
        run_id: str,
        code: str,
        *,
        domain_sizes: Any,
        run_status: str | None,
    ) -> bool:
        """Record the scan-end counts and run status on that run's line.

        Both are normalised (:mod:`adscan_core.pro_license.run_size`) before
        they are stored. Returns True only when the line changed, so a second
        scan-end pass of the same run (``adscan ci`` records at its end and
        again at exit) queues nothing new.
        """
        from adscan_core.pro_license.run_size import normalize_domain_sizes, normalize_run_status

        fields = {
            "domain_sizes": normalize_domain_sizes(domain_sizes),
            "run_status": normalize_run_status(run_status),
        }
        with state_file_lock(self.directory):
            lines = self.assessment_lines()
            changed = False
            for line in lines:
                if line.get("run_id") != run_id or line.get("domain_code") != code:
                    continue
                if any(line.get(key) != value for key, value in fields.items()):
                    line.update(fields)
                    changed = True
            if changed:
                self._write_register_doc(assessments=lines)
            return changed

    # ── Grace seal and clock floor (clock-state.json) ────────────────────────

    def _clock_state(self) -> dict[str, Any]:
        data = read_json(self._path(CLOCK_STATE_FILENAME))
        return data if isinstance(data, dict) else {}

    def seal_first_seen(self, code: str, instant: datetime) -> str:
        """Record ``first_seen`` for ``code`` in the register AND the seal.

        Returns the effective first_seen: the EARLIEST of the register, the seal
        and ``instant``, so editing either file forward never extends a grace.
        """
        with state_file_lock(self.directory):
            state = self._clock_state()
            seal = state.get(FIRST_SEEN_SEAL_KEY)
            seal = dict(seal) if isinstance(seal, Mapping) else {}
            entries = self.register_entries()
            current = (entries.get(code) or {}).get("first_seen")
            effective = _min_instant(seal.get(code), current, docs.format_instant(instant))
            seal[code] = effective
            state[FIRST_SEEN_SEAL_KEY] = seal
            write_json(self._path(CLOCK_STATE_FILENAME), state)
            entry = dict(entries.get(code) or {"domain_code": code})
            entry["first_seen"] = effective
            entries[code] = entry
            self._write_register(entries)
            return str(effective)

    def first_seen(self, code: str) -> str | None:
        seal = self._clock_state().get(FIRST_SEEN_SEAL_KEY)
        sealed = seal.get(code) if isinstance(seal, Mapping) else None
        current = (self.register_entries().get(code) or {}).get("first_seen")
        return _min_instant(sealed, current)

    def record_server_time(self, instant: datetime) -> None:
        """Raise the shared clock high-water mark to a time the SERVER signed.

        Unlike the engine's own launch mark this is real time even while the
        host clock is stepped to a domain controller, so it is always recorded.
        """
        with state_file_lock(self.directory):
            state = self._clock_state()
            current = state.get("last_seen")
            try:
                if isinstance(current, str) and docs.parse_instant(current) >= instant:
                    return
            except ValueError:
                pass
            state["last_seen"] = docs.format_instant(instant)
            write_json(self._path(CLOCK_STATE_FILENAME), state)

    def record_dc_time_witness(self, instant: datetime) -> None:
        """Remember the latest domain-controller time a scan measured.

        Only ever moves forward. It is an EXPIRY witness: a document whose end
        (plus grace and a drift tolerance) is behind the client's DC clock is
        expired for new assessments, whatever this machine's clock says. It
        never extends validity. Cleared when a new document is installed.
        """
        with state_file_lock(self.directory):
            state = self._clock_state()
            current = state.get(DC_TIME_WITNESS_KEY)
            try:
                if isinstance(current, str) and docs.parse_instant(current) >= instant:
                    return
            except ValueError:
                pass
            state[DC_TIME_WITNESS_KEY] = docs.format_instant(instant)
            write_json(self._path(CLOCK_STATE_FILENAME), state)

    def dc_time_witness(self) -> datetime | None:
        value = self._clock_state().get(DC_TIME_WITNESS_KEY)
        try:
            return docs.parse_instant(value) if isinstance(value, str) else None
        except ValueError:
            return None

    # ── Check-ins ────────────────────────────────────────────────────────────

    def record_check_in(self, outcome: str, *, error: str = "") -> None:
        """Remember the last check-in attempt and its outcome.

        ``unreachable_since`` is the first failed attempt of the current run of
        failures (cleared by any answer), so a notice can say since when.
        """
        now = docs.format_instant(docs.utc_now())
        with state_file_lock(self.directory):
            data = read_json(self._path(CHECK_IN_FILENAME))
            data = dict(data) if isinstance(data, Mapping) else {}
            data["last_attempt_at"] = now
            data["last_result"] = outcome
            if outcome == CHECK_IN_UNREACHABLE_RESULT:
                data.setdefault("unreachable_since", now)
                data["last_error"] = str(error or "")[:200]
            else:
                data.pop("unreachable_since", None)
                data.pop("last_error", None)
            write_json(self._path(CHECK_IN_FILENAME), data)

    def last_check_in(self) -> dict[str, Any]:
        """``{"last_attempt_at", "last_result", "unreachable_since"?, "last_error"?}``, or {}."""
        data = read_json(self._path(CHECK_IN_FILENAME))
        return dict(data) if isinstance(data, Mapping) else {}

    # ── Notices ──────────────────────────────────────────────────────────────

    def terminal_notice(self) -> dict[str, Any] | None:
        data = read_json(self._path(NOTICE_FILENAME))
        return data if isinstance(data, dict) else None

    # ── Registry credential ──────────────────────────────────────────────────

    def registry_credential(self) -> dict[str, Any] | None:
        data = read_json(self._path(CREDENTIAL_FILENAME))
        return data if isinstance(data, dict) else None

    def save_registry_credential(self, credential: Mapping[str, Any]) -> None:
        write_json(self._path(CREDENTIAL_FILENAME), dict(credential), mode=0o600)

    # ── Applying answers ─────────────────────────────────────────────────────

    def apply_answer(
        self, answer: Mapping[str, Any], *, trusted_keys: Mapping[str, str] | None = None
    ) -> ApplyResult:
        """Verify one server answer and apply it (spec § 5.3). Never raises."""
        try:
            payload = docs.verify_server_document(answer, trusted_keys=trusted_keys)
        except LicenseError as exc:
            return ApplyResult(False, reason=exc.code, message=str(exc))
        kind = str(payload.get("kind") or "")
        installation = self.existing_installation()
        if installation is None or payload.get("installation_id") != installation.installation_id:
            return ApplyResult(False, kind, "wrong_installation", "The answer is for another installation.")
        request_id = str(payload.get("request_id") or "")
        pending = self.find_pending(request_id)
        if pending is None:
            return self._already_applied(kind, payload)
        if payload.get("request_digest") != pending.get("digest"):
            return ApplyResult(False, kind, "digest_mismatch", "The answer does not match the request sent.")
        if kind not in docs.EXPECTED_ANSWERS.get(str(pending.get("kind")), frozenset()):
            return ApplyResult(False, kind, "unexpected_kind", "The answer does not fit the request sent.")

        server_time = payload.get("server_time") or payload.get("issued_at")
        if kind == docs.KIND_LICENCE:
            result = self._apply_licence(answer, pending, trusted_keys)
        elif kind == docs.KIND_REGISTRATION_RECEIPT:
            result = self._apply_registration(answer, payload, pending)
        elif kind == docs.KIND_BAND_RECEIPT:
            result = self._apply_band(payload, pending)
        elif kind == docs.KIND_ENGAGEMENT_RECEIPT:
            result = self._apply_engagement(payload, pending)
        else:
            result = self._apply_notice(answer, payload, pending)
        if result.applied:
            with state_file_lock(self.directory):
                self._set_last_contact(docs.format_instant(docs.utc_now()))
            self._acknowledge_withdrawn(pending.get("document", {}).get("payload", {}))
            if isinstance(server_time, str):
                try:
                    self.record_server_time(docs.parse_instant(server_time))
                except ValueError:
                    pass
        return result

    def _already_applied(self, kind: str, payload: Mapping[str, Any]) -> ApplyResult:
        if kind == docs.KIND_REGISTRATION_RECEIPT:
            entry = self.register_entries().get(str(payload.get("domain_code") or ""))
            if entry and entry.get("receipt_id") == payload.get("receipt_id"):
                return ApplyResult(False, kind, "already_applied", "This receipt is already recorded.")
        if kind == docs.KIND_LICENCE:
            current = read_json(self.licence_path)
            if isinstance(current, Mapping) and current.get("payload", {}).get("request_id") == payload.get(
                "request_id"
            ):
                return ApplyResult(False, kind, "already_applied", "This licence is already installed.")
        return ApplyResult(False, kind, "unknown_request", "The answer is for a request this installation is not waiting for.")

    def _apply_licence(
        self, answer: Mapping[str, Any], pending: Mapping[str, Any], trusted_keys: Mapping[str, str] | None
    ) -> ApplyResult:
        try:
            licence = self.install_licence_document(answer, trusted_keys=trusted_keys)
        except LicenseError as exc:
            return ApplyResult(False, docs.KIND_LICENCE, exc.code, str(exc))
        self.drop_pending(str(pending["request_id"]))
        return ApplyResult(True, docs.KIND_LICENCE, message=f"{licence.label} licence installed.")

    def _apply_registration(
        self, answer: Mapping[str, Any], payload: Mapping[str, Any], pending: Mapping[str, Any]
    ) -> ApplyResult:
        requested = pending["document"]["payload"]
        code = str(payload.get("domain_code") or "")
        if code != requested.get("domain_code"):
            return ApplyResult(False, docs.KIND_REGISTRATION_RECEIPT, "code_mismatch", "The receipt names another domain.")
        self.upsert_entry(
            code,
            status=STATUS_REGISTERED,
            code_basis=payload.get("code_basis"),
            band=payload.get("band"),
            license_id=payload.get("license_id"),
            receipt_id=payload.get("receipt_id"),
            registered_at=payload.get("registered_at"),
            receipt=dict(answer),
            refusal=None,
        )
        self.drop_pending(str(pending["request_id"]))
        return ApplyResult(True, docs.KIND_REGISTRATION_RECEIPT, message="Domain registered.")

    def _apply_band(self, payload: Mapping[str, Any], pending: Mapping[str, Any]) -> ApplyResult:
        code = str(pending["document"]["payload"].get("domain_code") or "")
        if code and payload.get("domain_code") == code:
            self.upsert_entry(code, band=payload.get("band"), band_confirmed_at=payload.get("server_time"))
        self.drop_pending(str(pending["request_id"]))
        return ApplyResult(True, docs.KIND_BAND_RECEIPT)

    def _apply_engagement(self, payload: Mapping[str, Any], pending: Mapping[str, Any]) -> ApplyResult:
        requested = pending["document"]["payload"]
        code = str(requested.get("domain_code") or "")
        if payload.get("domain_code") != code:
            return ApplyResult(False, docs.KIND_ENGAGEMENT_RECEIPT, "code_mismatch", "The receipt names another domain.")
        self._update_line(
            str(requested.get("run_id") or ""),
            code,
            engagement_receipt_id=payload.get("receipt_id"),
            engagement_reported_at=payload.get("server_time"),
        )
        self.drop_pending(str(pending["request_id"]))
        return ApplyResult(True, docs.KIND_ENGAGEMENT_RECEIPT)

    def _apply_notice(
        self, answer: Mapping[str, Any], payload: Mapping[str, Any], pending: Mapping[str, Any]
    ) -> ApplyResult:
        code = str(payload.get("code") or "")
        message = str(payload.get("message") or "")
        if code in docs.TERMINAL_NOTICES:
            write_json(self._path(NOTICE_FILENAME), dict(answer))
        requested = pending["document"]["payload"]
        if pending.get("kind") == docs.KIND_REGISTRATION and code not in docs.TERMINAL_NOTICES:
            self.upsert_entry(str(requested.get("domain_code")), status=STATUS_REFUSED, refusal=code)
        self.drop_pending(str(pending["request_id"]))
        return ApplyResult(True, docs.KIND_NOTICE, reason=code, message=message, notice_code=code)


__all__ = [
    "ApplyResult",
    "CHECK_IN_FILENAME",
    "CREDENTIAL_FILENAME",
    "DC_TIME_WITNESS_KEY",
    "LICENCE_FILENAME",
    "NOTICE_FILENAME",
    "PENDING_FILENAME",
    "ProLicenseStore",
    "REGISTER_FILENAME",
    "STATUS_PENDING",
    "STATUS_REFUSED",
    "STATUS_REGISTERED",
]
