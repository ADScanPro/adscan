"""PRO licence status and domain admission (spec § 6, § 9).

Two questions, answered locally without any network:

* :func:`check_pro_license` — may a NEW assessment start? Same states and
  clock-rollback rule as the Enterprise licence, plus ``revoked``.
* :func:`admit_domain` — may assessment of THIS forest start? Decided by the
  licence's registration policy: a registered code always passes; a trial
  queues the code and passes; a partner or paid licence passes during the
  grace window of a new code and stops after it; an offline engagement
  licence hands the decision to the environment ledger. A RECHECK never
  registers a code and never starts a grace: it may only re-assess a code a
  full scan already brought in.
* :func:`record_assessment` — the usage line of one assessment, and, when a
  full scan opens a NEW billable engagement of an already-known code (outside
  the licence's retest window), the engagement report that tells the server.

The only network this module ever touches is the optional ``send`` callable
:func:`admit_domain` receives, used once to try a direct registration.

Enforcement is DORMANT until required (:func:`enforcement_required`): PRO
behaves exactly as before on an image without the marker and a machine with no
licence, which is what lets this ship before the licence server is deployed.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from adscan_core.enterprise_license import (
    DEFAULT_CLOCK_TOLERANCE_HOURS,
    LicenseError,
    read_last_seen,
    record_last_seen,
)
from adscan_core.environment_ledger import ForestIdentity
from adscan_core.pro_license import documents as docs
from adscan_core.pro_license.billable_engagements import (
    RUN_KIND_FULL_SCAN,
    RUN_KIND_RECHECK,
    AssessmentRecord,
    opens_new_engagement,
)
from adscan_core.pro_license.domain_code import code_for_identity
from adscan_core.pro_license.model import (
    EDITION_TRIAL,
    POLICY_DEFERRED,
    POLICY_OFFLINE,
    ProLicense,
)
from adscan_core.pro_license.state import (
    STATUS_REFUSED,
    STATUS_REGISTERED,
    ProLicenseStore,
)

#: Marker baked by ``build_docker_pro_image.sh --licensed``. A file, not an
#: ENV, so ``docker run -e`` cannot remove the requirement.
PRO_LICENSE_MARKER = Path("/usr/local/share/adscan/pro-license")

STATE_NOT_REQUIRED = "not_required"
STATE_MISSING = "missing"
STATE_INVALID = "invalid"
STATE_REVOKED = "revoked"
STATE_CLOCK_ROLLBACK = "clock_rollback"
STATE_NOT_YET_VALID = "not_yet_valid"
STATE_VALID = "valid"
STATE_EXPIRING = "expiring"
STATE_GRACE = "grace"
STATE_EXPIRED = "expired"
_ALLOWED_STATES = frozenset({STATE_NOT_REQUIRED, STATE_VALID, STATE_EXPIRING, STATE_GRACE})
_WARNING_STATES = frozenset({STATE_EXPIRING, STATE_GRACE})

TRIAL_WARN_DAYS = 7
WARN_DAYS = 30

OUTCOME_REGISTERED = "registered"
OUTCOME_DEFERRED = "deferred"
OUTCOME_GRACE = "grace"
OUTCOME_REFUSED = "refused"
OUTCOME_OFFLINE = "offline"

#: Reason written beside exit 78 when a new domain's grace ran out.
REASON_REGISTRATION_REQUIRED = "pro_registration_required"
#: Reason when the licence server refused the registration (no credits…).
REASON_REGISTRATION_REFUSED = "pro_registration_refused"
#: Reason when a recheck reaches a domain no full scan brought in: a recheck
#: never registers a domain nor starts its grace.
REASON_RECHECK_UNKNOWN_DOMAIN = "pro_recheck_unknown_domain"

_KEEPS_DATA = "Existing reports and workspaces remain available."
_HOW_TO_ACTIVATE = "Activate this machine once with `adscan license activate`."


def _human_date(value: datetime) -> str:
    return f"{value.day} {value.strftime('%B %Y')}"


def _days_until(target: datetime, now: datetime) -> int:
    return max(0, math.ceil((target - now).total_seconds() / 86400))


@dataclass(frozen=True)
class ProLicenseStatus:
    """May a new assessment start, and what do we tell the operator?"""

    state: str
    message: str
    licence: ProLicense | None = None
    error_code: str = ""
    days_remaining: int | None = None

    @property
    def scans_allowed(self) -> bool:
        return self.state in _ALLOWED_STATES

    @property
    def required(self) -> bool:
        return self.state != STATE_NOT_REQUIRED

    @property
    def warning(self) -> bool:
        return self.state in _WARNING_STATES

    def to_dict(self) -> dict[str, Any]:
        lic = self.licence
        return {
            "state": self.state,
            "required": self.required,
            "scans_allowed": self.scans_allowed,
            "warning": self.warning,
            "message": self.message,
            "error_code": self.error_code or None,
            "days_remaining": self.days_remaining,
            "license": None
            if lic is None
            else {
                "license_id": lic.license_id,
                "grant_id": lic.grant_id or None,
                "key_id": lic.key_id or None,
                "issued_at": lic.issued_at.isoformat() if lic.issued_at else None,
                "holder": lic.customer,
                "edition": lic.edition,
                "edition_label": lic.label,
                "partner_tag": lic.partner_tag or None,
                "valid_from": lic.valid_from.isoformat(),
                "valid_until": lic.valid_until.isoformat(),
                "registration_policy": lic.registration_policy,
                "registration_grace_days": lic.registration_grace_days,
                "installation_id": lic.installation_id or None,
                "renew_after": lic.renew_after.isoformat() if lic.renew_after else None,
            },
        }


def not_required_status() -> ProLicenseStatus:
    return ProLicenseStatus(STATE_NOT_REQUIRED, "This build does not require a PRO licence yet.")


def enforcement_required(store: ProLicenseStore, *, marker: Path | None = None) -> bool:
    """True when the PRO licence governs new assessments on this machine.

    Required when the image carries the licensed-build marker, or once a PRO
    licence is installed (whoever activated is governed by their licence).
    """
    from adscan_core.pal.platform import is_posix

    marker_path = marker or PRO_LICENSE_MARKER
    if is_posix() or marker is not None:
        try:
            if marker_path.is_file():
                return True
        except OSError:
            pass
    return store.has_licence_file()


def evaluate_pro_license(
    licence: ProLicense | None,
    *,
    now: datetime,
    error: LicenseError | None = None,
    notice: Mapping[str, Any] | None = None,
    last_seen: datetime | None = None,
) -> ProLicenseStatus:
    """Decide the licence state at ``now``. Pure: no I/O, no clock reads."""
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    if licence is None:
        if error is None:
            return ProLicenseStatus(
                STATE_MISSING,
                f"No ADscan PRO licence is active on this machine, so new assessments cannot start. "
                f"{_HOW_TO_ACTIVATE} {_KEEPS_DATA}",
                error_code="missing",
            )
        return ProLicenseStatus(
            STATE_INVALID,
            f"The PRO licence on this machine cannot be accepted: {error} New assessments cannot "
            f"start. {_KEEPS_DATA}",
            error_code=error.code,
        )
    notice_payload = (notice or {}).get("payload") if isinstance(notice, Mapping) else None
    if isinstance(notice_payload, Mapping) and notice_payload.get("code") in docs.TERMINAL_NOTICES:
        released = notice_payload.get("code") == docs.NOTICE_DEACTIVATED
        return ProLicenseStatus(
            STATE_REVOKED,
            (
                "This machine's PRO licence was released, so new assessments cannot start. "
                f"{_HOW_TO_ACTIVATE} {_KEEPS_DATA}"
                if released
                else "ADscan revoked this PRO licence, so new assessments cannot start. "
                f"Contact ADscan if you think this is a mistake. {_KEEPS_DATA}"
            ),
            licence=licence,
            error_code=str(notice_payload.get("code")),
        )
    tolerance = timedelta(hours=DEFAULT_CLOCK_TOLERANCE_HOURS)
    reference = max([licence.issued_at] + ([last_seen] if last_seen else []))
    if now < reference - tolerance:
        return ProLicenseStatus(
            STATE_CLOCK_ROLLBACK,
            "The system clock is earlier than the last time ADscan confirmed the date "
            f"({docs.format_instant(reference)}), so new assessments cannot start until it is "
            f"corrected. {_KEEPS_DATA}",
            licence=licence,
            error_code="clock_rollback",
        )
    if now < licence.starts_at:
        return ProLicenseStatus(
            STATE_NOT_YET_VALID,
            f"Your {licence.label} licence starts on {_human_date(licence.starts_at)}.",
            licence=licence,
            error_code="not_yet_valid",
        )
    if now < licence.ends_at:
        days = _days_until(licence.ends_at, now)
        warn = TRIAL_WARN_DAYS if licence.edition == EDITION_TRIAL else WARN_DAYS
        last_day = _human_date(licence.ends_at - timedelta(days=1))
        if licence.ends_at - now <= timedelta(days=warn):
            return ProLicenseStatus(
                STATE_EXPIRING,
                f"Your {licence.label} licence ends on {last_day} ({days} day"
                f"{'s' if days != 1 else ''} left).",
                licence=licence,
                days_remaining=days,
            )
        return ProLicenseStatus(
            STATE_VALID,
            f"{licence.label} licence for {licence.customer}, valid until {last_day}.",
            licence=licence,
            days_remaining=days,
        )
    if now < licence.grace_ends_at:
        days = _days_until(licence.grace_ends_at, now)
        return ProLicenseStatus(
            STATE_GRACE,
            f"Your {licence.label} licence ended on {_human_date(licence.ends_at - timedelta(days=1))}. "
            f"New assessments remain possible for {days} more day{'s' if days != 1 else ''}.",
            licence=licence,
            days_remaining=days,
        )
    return ProLicenseStatus(
        STATE_EXPIRED,
        f"Your {licence.label} licence ended on {_human_date(licence.ends_at - timedelta(days=1))}, "
        f"so new assessments cannot start. {_KEEPS_DATA}",
        licence=licence,
        error_code="expired",
        days_remaining=0,
    )


def check_pro_license(
    store: ProLicenseStore,
    *,
    now: datetime | None = None,
    trusted_keys: Mapping[str, str] | None = None,
    record: bool = False,
) -> ProLicenseStatus:
    """Read, verify and evaluate the installed PRO licence.

    ``record`` advances the shared clock high-water mark when the launch is
    allowed (scan-launch seams only), exactly like the Enterprise check.
    """
    current = now or docs.utc_now()
    licence, error = store.load_licence(trusted_keys=trusted_keys)
    status = evaluate_pro_license(
        licence,
        now=current,
        error=error,
        notice=store.terminal_notice(),
        last_seen=read_last_seen(store.directory),
    )
    if record and status.scans_allowed:
        record_last_seen(current, store.directory)
    return status


# ── Domain admission ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class DomainAdmission:
    """The decision for one forest under a PRO licence."""

    allowed: bool
    outcome: str
    domain_code: str
    code_basis: str
    message: str = ""
    reason_code: str = ""
    grace_until: datetime | None = None


def _queue_registration(
    store: ProLicenseStore,
    licence: ProLicense,
    code: str,
    basis: str,
    *,
    engine_version: str,
    supersedes: str | None,
    run_id: str,
    now: datetime,
) -> dict[str, Any]:
    existing = store.pending_of_kind(docs.KIND_REGISTRATION, domain_code=code)
    if existing is not None:
        return existing
    # The registration is also the report of the code's FIRST engagement: it
    # carries the opening run, so the server needs no second message for it.
    document = docs.build_request(
        store.installation(),
        docs.KIND_REGISTRATION,
        engine_version=engine_version,
        license_id=licence.license_id,
        domain_code=code,
        code_basis=basis,
        band="pending",
        supersedes=supersedes,
        run_kind=RUN_KIND_FULL_SCAN,
        run_id=run_id or None,
        assessed_at=docs.format_instant(now),
        retest_window_days=licence.retest_window_days,
    )
    if run_id:
        # Remembered on the entry, not read off the pending request: a direct
        # registration is settled (and its request dropped) before the usage
        # line is recorded.
        store.upsert_entry(code, registration_run_id=run_id)
    return store.add_pending(document)


def admit_domain(
    store: ProLicenseStore,
    licence: ProLicense,
    identity: ForestIdentity,
    *,
    now: datetime | None = None,
    engine_version: str = "",
    send: Callable[[Mapping[str, Any]], Mapping[str, Any] | None] | None = None,
    trusted_keys: Mapping[str, str] | None = None,
    supersedes: str | None = None,
    run_kind: str = RUN_KIND_FULL_SCAN,
    run_id: str = "",
) -> DomainAdmission:
    """Decide whether assessment of ``identity``'s forest may start (spec § 6.2).

    ``run_kind`` :data:`RUN_KIND_RECHECK` never registers the code and never
    seals a ``first_seen`` (it would start a grace): see :func:`_admit_recheck`.
    """
    current = now or docs.utc_now()
    code, basis = code_for_identity(licence.domain_code_key, identity)
    if licence.registration_policy == POLICY_OFFLINE:
        if run_kind == RUN_KIND_RECHECK and not any(r.domain_code == code for r in store.assessment_records()):
            # An offline licence counts forests in the environment ledger at a
            # full scan; a recheck must not reach (or count) a forest no full
            # scan brought in.
            return _recheck_unknown(code, basis)
        return DomainAdmission(True, OUTCOME_OFFLINE, code, basis)

    entry = store.register_entries().get(code) or {}
    if entry.get("status") == STATUS_REGISTERED:
        return DomainAdmission(True, OUTCOME_REGISTERED, code, basis)
    if run_kind == RUN_KIND_RECHECK:
        return _admit_recheck(store, licence, code, basis, entry, current)

    if entry.get("status") == STATUS_REFUSED:
        store.upsert_entry(code, status="pending", refusal=None)
    store.upsert_entry(code, status="pending", code_basis=basis, license_id=licence.license_id)
    first_seen_text = store.seal_first_seen(code, current)
    pending = _queue_registration(
        store,
        licence,
        code,
        basis,
        engine_version=engine_version,
        supersedes=supersedes,
        run_id=run_id,
        now=current,
    )

    if send is not None:
        try:
            answer = send(pending["document"])
        except Exception:  # noqa: BLE001 - a transport failure leaves the work queued
            answer = None
        if isinstance(answer, Mapping):
            result = store.apply_answer(answer, trusted_keys=trusted_keys)
            settled = store.register_entries().get(code) or {}
            if settled.get("status") == STATUS_REGISTERED:
                return DomainAdmission(True, OUTCOME_REGISTERED, code, basis)
            if result.applied and result.notice_code:
                if licence.registration_policy == POLICY_DEFERRED:
                    return DomainAdmission(True, OUTCOME_DEFERRED, code, basis)
                return DomainAdmission(
                    False,
                    OUTCOME_REFUSED,
                    code,
                    basis,
                    message=(
                        f"ADscan did not register this forest (domain code {code}): "
                        f"{result.message or result.notice_code} Domains already registered are not affected."
                    ),
                    reason_code=REASON_REGISTRATION_REFUSED,
                )

    if licence.registration_policy == POLICY_DEFERRED:
        return DomainAdmission(
            True,
            OUTCOME_DEFERRED,
            code,
            basis,
            message="It will be registered with ADscan the next time this machine is online.",
        )

    first_seen = docs.parse_instant(first_seen_text)
    grace_until = first_seen + timedelta(days=licence.registration_grace_days)
    if current < grace_until:
        return DomainAdmission(
            True,
            OUTCOME_GRACE,
            code,
            basis,
            message=(
                f"This forest is not registered with ADscan yet (domain code {code}). Its assessment "
                f"may continue until {_human_date(grace_until)}. Register it before then with "
                "`adscan license sync`, or through your platform with `adscan license relay export`."
            ),
            grace_until=grace_until,
        )
    return _grace_refusal(code, basis, first_seen, grace_until)


def _grace_refusal(code: str, basis: str, first_seen: datetime, grace_until: datetime) -> DomainAdmission:
    return DomainAdmission(
        False,
        OUTCOME_REFUSED,
        code,
        basis,
        message=(
            f"This forest (domain code {code}) was first assessed on {_human_date(first_seen)} and is "
            "still not registered with ADscan, so its assessment cannot start. Register it with "
            "`adscan license sync` when this machine can reach ADscan, or through your platform with "
            "`adscan license relay export` and `adscan license relay import`. Domains already "
            "registered are not affected."
        ),
        reason_code=REASON_REGISTRATION_REQUIRED,
        grace_until=grace_until,
    )


def _recheck_unknown(code: str, basis: str) -> DomainAdmission:
    return DomainAdmission(
        False,
        OUTCOME_REFUSED,
        code,
        basis,
        message=(
            f"This forest (domain code {code}) was never brought in by a full assessment under this "
            "licence, and a re-check cannot register a domain. Run a full assessment of it first."
        ),
        reason_code=REASON_RECHECK_UNKNOWN_DOMAIN,
    )


def _admit_recheck(
    store: ProLicenseStore,
    licence: ProLicense,
    code: str,
    basis: str,
    entry: Mapping[str, Any],
    now: datetime,
) -> DomainAdmission:
    """A recheck of a code that is not registered (yet): read-only on the register.

    Nothing is queued and nothing is sealed, so a recheck can neither register
    a domain nor start (or extend) its grace. A code a full scan brought in
    keeps the grace that scan started; a code no full scan brought in is
    refused, except under a trial, which never blocks.
    """
    if licence.registration_policy == POLICY_DEFERRED:
        return DomainAdmission(True, OUTCOME_DEFERRED, code, basis)
    first_seen_text = store.first_seen(code) if entry else None
    if first_seen_text is None:
        return _recheck_unknown(code, basis)
    first_seen = docs.parse_instant(first_seen_text)
    grace_until = first_seen + timedelta(days=licence.registration_grace_days)
    if now < grace_until:
        return DomainAdmission(
            True,
            OUTCOME_GRACE,
            code,
            basis,
            message=(
                f"This forest is not registered with ADscan yet (domain code {code}). Its assessment "
                f"may continue until {_human_date(grace_until)}."
            ),
            grace_until=grace_until,
        )
    return _grace_refusal(code, basis, first_seen, grace_until)


@dataclass(frozen=True)
class AssessmentOutcome:
    """The usage line recorded for one assessment of one code."""

    record: AssessmentRecord
    opens_engagement: bool
    reported: bool = False


def record_assessment(
    store: ProLicenseStore,
    licence: ProLicense,
    *,
    domain_code: str,
    run_kind: str,
    run_id: str,
    now: datetime | None = None,
    parent_run_id: str = "",
    engine_version: str = "",
    supersedes: str | None = None,
) -> AssessmentOutcome:
    """Record the usage line of one assessment and report a new engagement.

    The line carries the run kind (full scan or recheck), the run, the parent
    run of a recheck, the date, the band known so far and, for a full scan, the
    licence's retest window. A full scan that opens a NEW billable engagement
    of a code queues an ``engagement_report``, unless the registration queued
    by this same run already carries it (the code's first engagement). A
    recheck, and a full scan inside the window, send nothing. An offline
    licence keeps the line locally only.
    """
    current = now or docs.utc_now()
    entry = store.register_entries().get(domain_code) or {}
    band = entry.get("band") if isinstance(entry.get("band"), str) else ""
    is_recheck = run_kind == RUN_KIND_RECHECK
    record = AssessmentRecord(
        domain_code=domain_code,
        run_kind=run_kind,
        assessed_at=current,
        run_id=run_id,
        parent_run_id=parent_run_id if is_recheck else "",
        band=band or "pending",
        window_days=None if is_recheck else licence.retest_window_days,
    )
    prior = [
        r
        for r in store.assessment_records()
        if not (run_id and r.run_id == run_id and r.domain_code in (domain_code, supersedes))
    ]
    opens = opens_new_engagement(record, prior, window_days=licence.retest_window_days)
    store.record_assessment_line(record, supersedes=supersedes)
    if not opens or not licence.needs_server:
        return AssessmentOutcome(record, opens)
    if run_id and entry.get("registration_run_id") == run_id:
        # This run's registration request already carries the first engagement.
        return AssessmentOutcome(record, opens)
    if store.pending_of_kind(docs.KIND_ENGAGEMENT_REPORT, domain_code=domain_code, run_id=run_id) is None:
        store.add_pending(
            docs.build_request(
                store.installation(),
                docs.KIND_ENGAGEMENT_REPORT,
                engine_version=engine_version or "unknown",
                license_id=licence.license_id,
                domain_code=domain_code,
                run_kind=RUN_KIND_FULL_SCAN,
                run_id=run_id or None,
                assessed_at=docs.format_instant(current),
                band=record.band,
                retest_window_days=licence.retest_window_days,
            )
        )
    return AssessmentOutcome(record, opens, reported=True)


__all__ = [
    "AssessmentOutcome",
    "DomainAdmission",
    "OUTCOME_DEFERRED",
    "OUTCOME_GRACE",
    "OUTCOME_OFFLINE",
    "OUTCOME_REFUSED",
    "OUTCOME_REGISTERED",
    "PRO_LICENSE_MARKER",
    "ProLicenseStatus",
    "REASON_RECHECK_UNKNOWN_DOMAIN",
    "REASON_REGISTRATION_REFUSED",
    "REASON_REGISTRATION_REQUIRED",
    "STATE_CLOCK_ROLLBACK",
    "STATE_EXPIRED",
    "STATE_EXPIRING",
    "STATE_GRACE",
    "STATE_INVALID",
    "STATE_MISSING",
    "STATE_NOT_REQUIRED",
    "STATE_NOT_YET_VALID",
    "STATE_REVOKED",
    "STATE_VALID",
    "admit_domain",
    "check_pro_license",
    "enforcement_required",
    "evaluate_pro_license",
    "not_required_status",
    "record_assessment",
]
