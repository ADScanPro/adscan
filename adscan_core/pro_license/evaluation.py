"""PRO licence status and domain admission (spec § 6, § 9).

Two questions, answered locally without any network:

* :func:`check_pro_license` — may a NEW assessment start? Same states and
  clock-rollback rule as the Enterprise licence, plus ``revoked``. The
  status keeps two dates apart: the CONTRACT end (ADscan's to extend, possibly
  none) is what the operator is told about; the DOCUMENT validity (how long
  this machine may work without checking in) is internal and refreshed by the
  launch check-in (:func:`adscan_core.pro_license.client.check_in`). Only a
  machine that cannot refresh (offline mode, no route) hears about the
  document, and only when its renewal date has passed.
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
import time as _time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from adscan_core.enterprise_license import (
    DEFAULT_CLOCK_TOLERANCE_HOURS,
    LicenseError,
    read_last_seen,
    record_last_seen,
)
from adscan_core.engagement.model import RUN_INTERRUPTED
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
    CONTRACT_OPEN_ENDED,
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
#: Contract days remaining at or below which the launch notice is a warning on
#: every start (above it, up to WARN_DAYS, a quiet note at most once a day).
WARNING_DAYS = 7
#: At or below this, the notice is urgent (and on the last day).
URGENT_DAYS = 3

#: Presentation tiers of the launch notice (:attr:`ProLicenseStatus.notice_level`).
NOTICE_NONE = "none"
NOTICE_NOTE = "note"
NOTICE_WARNING = "warning"
NOTICE_URGENT = "urgent"
NOTICE_CRITICAL = "critical"

#: Version of ``adscan license status --json`` (the ``license_status`` output format).
STATUS_SCHEMA_NAME = "license_status"

#: How far a domain controller's clock may run past a document's grace before
#: that DC time counts as proof the document expired. Generous on purpose: lab
#: and client DCs drift by hours, and this witness only ever SHORTENS validity.
DC_WITNESS_TOLERANCE = timedelta(hours=DEFAULT_CLOCK_TOLERANCE_HOURS)

# ── Session clock ─────────────────────────────────────────────────────────────
#
# The launch decision reads the wall clock BEFORE ADscan steps it to a domain
# controller (PKINIT, Kerberos skew). Every later licence decision in the same
# process (a domain admitted mid-scan) reads the SESSION clock instead: the
# launch instant plus monotonic elapsed time. So neither ADscan's own clock
# steps nor an operator moving the wall clock back mid-run can make a long
# session outlive its document, and a step does not read as a clock rollback.
# CLOCK_MONOTONIC restarts at boot, so this never carries across processes.

_SESSION_ANCHOR: tuple[datetime, float] | None = None


def anchor_session_clock(now: datetime) -> None:
    """Pin the session clock to the launch instant (the licence gate calls it once)."""
    global _SESSION_ANCHOR
    _SESSION_ANCHOR = (now, _time.monotonic())


def reset_session_clock() -> None:
    """Forget the session anchor (tests; a new launch in the same process)."""
    global _SESSION_ANCHOR
    _SESSION_ANCHOR = None


#: Floor of a new code's registration grace. A licence issued with no grace
#: still lets the FIRST assessment of a new forest run (both its phases) when
#: the server does not answer; the next day it needs the registration.
MIN_REGISTRATION_GRACE = timedelta(days=1)


def registration_grace_until(licence: ProLicense, first_seen: datetime) -> datetime:
    """End of a pending code's grace: its OWN ``first_seen`` plus the licence's grace (floored)."""
    return first_seen + max(timedelta(days=licence.registration_grace_days), MIN_REGISTRATION_GRACE)


def session_now() -> datetime:
    """The session clock, or the wall clock when no launch anchored it."""
    if _SESSION_ANCHOR is None:
        return docs.utc_now()
    wall, mono = _SESSION_ANCHOR
    return wall + timedelta(seconds=max(0.0, _time.monotonic() - mono))

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

#: What ``adscan license status`` says on a machine with no licence and no PRO
#: build. True for both editions: the free one needs no licence, PRO needs one
#: (since 15.0.0). It once read "this build does not require one yet", which
#: was the wording of the release before the licence became mandatory for PRO.
DORMANT_MESSAGE = (
    "No ADscan PRO licence is installed on this machine. The free edition needs none and "
    "runs as it is. ADscan PRO needs one. Run `adscan license activate` with the activation "
    "key from your onboarding email."
)
#: Every refusal says where the user's own evidence still is: the launch is
#: refused (``start`` included), ``adscan deliver`` never passes the licence seam.
_KEEPS_DATA = "Your workspaces and reports are untouched, and `adscan deliver` still renders a report from any of them."
_HOW_TO_ACTIVATE = "Run `adscan license activate` once, with the activation key from your ADscan onboarding email."


def licence_contact_email() -> str:
    """Where a licence holder writes to ADscan (one place for every licence message)."""
    from adscan_core.outbound_links import ADSCAN_SITE_HOST

    return f"hello@{ADSCAN_SITE_HOST}"


def _no_key_line() -> str:
    return f"No key? Write to {licence_contact_email()}."


def _contact_line() -> str:
    return f"To extend it, contact ADscan at {licence_contact_email()}."


def offline_until(licence: ProLicense) -> datetime:
    """First instant (UTC) new assessments can no longer start without refreshing this document.

    The document's end plus its grace: the same instant the ``grace`` state
    names as "new assessments stop after". Every surface that tells a person how
    long this machine works without the licence server reads it here.
    """
    return licence.grace_ends_at


def _refresh_how(offline: bool) -> str:
    if offline:
        return (
            "Offline mode is on, so this machine cannot refresh it by itself. Run "
            "`adscan license relay export`, send the file through your platform, then run "
            "`adscan license relay import`."
        )
    return (
        "Let this machine reach the ADscan licence server once (any launch refreshes it, "
        "offline mode included). `adscan license check` finds what blocks the connection and "
        "refreshes it once the route works. With no route to ADscan, run "
        "`adscan license relay export`, send the file through your platform, then run "
        "`adscan license relay import`."
    )


def _human_date(value: datetime) -> str:
    return f"{value.day} {value.strftime('%B %Y')}"


def _days_until(target: datetime, now: datetime) -> int:
    return max(0, math.ceil((target - now).total_seconds() / 86400))


def _plural(days: int) -> str:
    return f"{days} day{'s' if days != 1 else ''}"


def _contract_level(days: int) -> str:
    if days <= URGENT_DAYS:
        return NOTICE_URGENT
    if days <= WARNING_DAYS:
        return NOTICE_WARNING
    return NOTICE_NOTE


@dataclass(frozen=True)
class ProLicenseStatus:
    """May a new assessment start, and what do we tell the operator?"""

    state: str
    message: str
    licence: ProLicense | None = None
    error_code: str = ""
    #: Days the DOCUMENT (or its grace) still allows new assessments.
    days_remaining: int | None = None
    #: Days to the end of the CONTRACT (None: no end date or not stated).
    contract_days_remaining: int | None = None
    #: How loudly a launch tells the operator (NOTICE_*).
    notice_level: str = NOTICE_NONE
    #: True when the notice is about refreshing the document (offline host),
    #: not about the contract.
    refresh_notice: bool = False
    #: Offline mode was on when the status was computed.
    offline: bool = False
    #: Last answer this machine got from the licence server (ISO instant).
    last_check_in: str | None = None

    @property
    def scans_allowed(self) -> bool:
        return self.state in _ALLOWED_STATES

    @property
    def required(self) -> bool:
        return self.state != STATE_NOT_REQUIRED

    @property
    def warning(self) -> bool:
        return self.state in _WARNING_STATES

    @property
    def renews_automatically(self) -> bool:
        """True when this machine refreshes its licence document on its own (online launches)."""
        lic = self.licence
        return bool(lic is not None and lic.needs_server and not self.offline and self.state not in (
            STATE_REVOKED,
        ))

    def to_dict(self, *, enforced: bool = True) -> dict[str, Any]:
        """Machine-readable status.

        ``enforced`` is :func:`enforcement_required`. While enforcement is dormant
        (no licensed-build marker, no licence installed) a missing licence is not a
        block: ``required`` is false, ``scans_allowed`` is true and the message is
        the dormant one, so a pipeline never reads "scans blocked" when they run.
        """
        from adscan_core.engagement.output_formats import SCHEMA_VERSION_KEY, output_marker

        lic = self.licence
        dormant = (not enforced) and self.state == STATE_MISSING
        return {
            SCHEMA_VERSION_KEY: output_marker(STATUS_SCHEMA_NAME),
            "state": self.state,
            "required": False if dormant else self.required,
            "scans_allowed": True if dormant else self.scans_allowed,
            "warning": self.warning,
            "message": DORMANT_MESSAGE if dormant else self.message,
            "error_code": self.error_code or None,
            "days_remaining": self.days_remaining,
            "contract_term": lic.contract_term if lic is not None else None,
            "contract_ends_on": lic.contract_ends_on.isoformat() if lic and lic.contract_ends_on else None,
            "contract_days_remaining": self.contract_days_remaining,
            "document_valid_until": lic.valid_until.isoformat() if lic is not None else None,
            "renews_automatically": self.renews_automatically,
            "last_refreshed_at": docs.format_instant(lic.issued_at) if lic is not None else None,
            "last_check_in_at": self.last_check_in,
            "notice_level": NOTICE_NONE if dormant else self.notice_level,
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
    offline: bool = False,
    last_check_in: str | None = None,
    dc_time_witness: datetime | None = None,
) -> ProLicenseStatus:
    """Decide the licence state at ``now``. Pure: no I/O, no clock reads.

    ``dc_time_witness`` is the latest domain-controller time a scan measured.
    When it is past the document's grace by more than
    :data:`DC_WITNESS_TOLERANCE`, the document is expired for new assessments
    whatever this machine's clock says (an operator controls their own clock,
    rarely their client's DC). It never extends validity.

    Enforcement reads the DOCUMENT (its end and grace). The wording reads the
    CONTRACT: a document about to end while the contract continues is a
    refresh this machine does on its own, so it is mentioned only once the
    renewal date passed without one (and from the renewal date under offline
    mode, where the operator has to carry it).
    """
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    extra = {"offline": offline, "last_check_in": last_check_in}
    if licence is None:
        if error is None:
            return ProLicenseStatus(
                STATE_MISSING,
                f"No ADscan PRO licence is active on this machine, so new assessments cannot start. "
                f"{_HOW_TO_ACTIVATE} {_no_key_line()} {_KEEPS_DATA}",
                error_code="missing",
                notice_level=NOTICE_CRITICAL,
                **extra,
            )
        return ProLicenseStatus(
            STATE_INVALID,
            f"The PRO licence on this machine cannot be accepted: {error} New assessments cannot "
            f"start. {_KEEPS_DATA}",
            error_code=error.code,
            notice_level=NOTICE_CRITICAL,
            **extra,
        )
    contract_end = licence.contract_ends_at
    contract_days = _days_until(contract_end, now) if contract_end is not None else None
    extra["contract_days_remaining"] = contract_days
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
            notice_level=NOTICE_CRITICAL,
            **extra,
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
            notice_level=NOTICE_CRITICAL,
            **extra,
        )
    if now < licence.starts_at:
        return ProLicenseStatus(
            STATE_NOT_YET_VALID,
            f"Your {licence.label} licence starts on {_human_date(licence.starts_at)}.",
            licence=licence,
            error_code="not_yet_valid",
            notice_level=NOTICE_CRITICAL,
            **extra,
        )
    outlasts = licence.contract_outlasts_document
    last_doc_day = _human_date(licence.ends_at - timedelta(days=1))
    if dc_time_witness is not None and dc_time_witness - DC_WITNESS_TOLERANCE >= licence.grace_ends_at:
        return ProLicenseStatus(
            STATE_EXPIRED,
            f"A domain controller this machine assessed reports a date after this {licence.label} "
            f"licence ended ({last_doc_day}), so new assessments cannot start. "
            f"{_refresh_how(offline) if outlasts else _contact_line()} {_KEEPS_DATA}",
            licence=licence,
            error_code="expired_by_dc_time",
            days_remaining=0,
            notice_level=NOTICE_CRITICAL,
            refresh_notice=outlasts,
            **extra,
        )
    if now < licence.ends_at:
        days = _days_until(licence.ends_at, now)
        warn = TRIAL_WARN_DAYS if licence.edition == EDITION_TRIAL else WARN_DAYS
        if contract_days is not None and contract_days <= warn:
            last_day = _human_date(contract_end - timedelta(days=1))
            when = "today" if contract_days <= 1 else f"on {last_day} ({_plural(contract_days)} left)"
            return ProLicenseStatus(
                STATE_EXPIRING,
                f"Your {licence.label} licence ends {when}. {_contact_line()}",
                licence=licence,
                days_remaining=days,
                notice_level=_contract_level(contract_days),
                **extra,
            )
        renew_after = licence.renew_after
        if outlasts and renew_after is not None:
            overdue_from = renew_after if offline else renew_after + timedelta(days=1)
            if now.date() >= overdue_from:
                # The date new assessments stop (document end plus its grace),
                # the one the launch notice and `adscan license status` show.
                stop = offline_until(licence)
                stop_days = _days_until(stop, now)
                level = _contract_level(stop_days)
                if not offline:
                    level = NOTICE_URGENT if stop_days <= URGENT_DAYS else NOTICE_WARNING
                return ProLicenseStatus(
                    STATE_EXPIRING,
                    f"This machine has not refreshed its {licence.label} licence, so new assessments can "
                    f"start without the licence server until {_human_date(stop - timedelta(days=1))} "
                    f"({_plural(stop_days)} left). {_refresh_how(offline)}",
                    licence=licence,
                    days_remaining=days,
                    notice_level=level,
                    refresh_notice=True,
                    **extra,
                )
        if licence.contract_term == CONTRACT_OPEN_ENDED:
            summary = f"{licence.label} licence for {licence.customer}, no end date."
        elif contract_end is not None:
            summary = (
                f"{licence.label} licence for {licence.customer}, valid until "
                f"{_human_date(contract_end - timedelta(days=1))}."
            )
        else:
            summary = f"{licence.label} licence for {licence.customer}, active."
        return ProLicenseStatus(
            STATE_VALID,
            summary,
            licence=licence,
            days_remaining=days,
            **extra,
        )
    if now < licence.grace_ends_at:
        days = _days_until(licence.grace_ends_at, now)
        stop_day = _human_date(licence.grace_ends_at - timedelta(days=1))
        if outlasts:
            message = (
                f"This machine has not refreshed its {licence.label} licence since "
                f"{_human_date(licence.issued_at)}. New assessments stop after {stop_day} "
                f"({_plural(days)} left). {_refresh_how(offline)}"
            )
        else:
            message = (
                f"Your {licence.label} licence ended on {last_doc_day}. New assessments stop after "
                f"{stop_day} ({_plural(days)} left). {_contact_line()}"
            )
        return ProLicenseStatus(
            STATE_GRACE,
            message,
            licence=licence,
            days_remaining=days,
            notice_level=NOTICE_CRITICAL,
            refresh_notice=outlasts,
            **extra,
        )
    if outlasts:
        message = (
            f"This machine's {licence.label} licence could not be refreshed since "
            f"{_human_date(licence.issued_at)}, so new assessments cannot start. "
            f"{_refresh_how(offline)} {_KEEPS_DATA}"
        )
    else:
        message = (
            f"Your {licence.label} licence ended on {last_doc_day}, so new assessments cannot start. "
            f"{_contact_line()} {_KEEPS_DATA}"
        )
    return ProLicenseStatus(
        STATE_EXPIRED,
        message,
        licence=licence,
        error_code="expired",
        days_remaining=0,
        notice_level=NOTICE_CRITICAL,
        refresh_notice=outlasts,
        **extra,
    )


def check_pro_license(
    store: ProLicenseStore,
    *,
    now: datetime | None = None,
    trusted_keys: Mapping[str, str] | None = None,
    record: bool = False,
    session_clock: bool = False,
) -> ProLicenseStatus:
    """Read, verify and evaluate the installed PRO licence.

    ``record`` advances the shared clock high-water mark when the launch is
    allowed (scan-launch seams only), exactly like the Enterprise check.
    ``session_clock`` reads :func:`session_now` instead of the wall clock
    (mid-session decisions, after ADscan may have stepped the host clock).
    Offline mode changes only the wording, and only when it keeps the licence
    channel closed (:func:`adscan_core.pro_license.channel.licence_channel_offline`;
    an online licence still refreshes itself under offline mode): the
    document's validity, grace, clock floor and DC-time witness are enforced
    exactly the same.
    """
    from adscan_core.pro_license.channel import licence_channel_offline

    current = now or (session_now() if session_clock else docs.utc_now())
    licence, error = store.load_licence(trusted_keys=trusted_keys)
    status = evaluate_pro_license(
        licence,
        now=current,
        error=error,
        notice=store.terminal_notice(),
        last_seen=read_last_seen(store.directory),
        offline=licence_channel_offline(licence),
        last_check_in=store.last_contact(),
        dc_time_witness=store.dc_time_witness(),
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
    #: Set when the local register said "registered" without a receipt that
    #: verifies: one line for the operator. The code was then handled as a
    #: domain that is not registered yet (registered now, or its normal grace).
    receipt_problem: str = ""


def _receipt_problem_line(code: str) -> str:
    return (
        f"The local licence record marked this forest (domain code {code}) as registered, but it holds "
        "no valid receipt from the ADscan licence server, so ADscan treats it as not registered yet "
        "and registers it again."
    )


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
    document = store.build_request(
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

    Grace is PER DOMAIN: it counts from that code's own ``first_seen`` (the
    earliest sealed sighting), never from the licence or another domain. A new
    code is never refused at its first assessment, server down or not (the
    grace is at least :data:`MIN_REGISTRATION_GRACE`), and a registered code
    never needs the server. Registered means the entry holds the server's
    receipt and it verifies (:meth:`ProLicenseStore.verified_receipt`); an
    entry that only says so is handled as a code not registered yet and the
    admission carries ``receipt_problem`` for the operator.

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
    if entry.get("status") != STATUS_REGISTERED:
        return _admit_unregistered(
            store, licence, code, basis, entry, current, engine_version, send, trusted_keys, supersedes,
            run_kind, run_id,
        )
    if store.is_registered(code, trusted_keys=trusted_keys):
        return DomainAdmission(True, OUTCOME_REGISTERED, code, basis)
    # "registered" with no receipt that verifies (signed by us, for this code
    # and this installation) is a status somebody wrote, not a registration.
    # It goes back to the normal path: registered now when the server answers,
    # else the grace that counts from the code's sealed first sighting.
    entry = store.upsert_entry(code, status="pending", receipt=None, receipt_id=None, registered_at=None)
    admission = _admit_unregistered(
        store, licence, code, basis, entry, current, engine_version, send, trusted_keys, supersedes,
        run_kind, run_id,
    )
    return replace(admission, receipt_problem=_receipt_problem_line(code))


def _admit_unregistered(
    store: ProLicenseStore,
    licence: ProLicense,
    code: str,
    basis: str,
    entry: Mapping[str, Any],
    current: datetime,
    engine_version: str,
    send: Callable[[Mapping[str, Any]], Mapping[str, Any] | None] | None,
    trusted_keys: Mapping[str, str] | None,
    supersedes: str | None,
    run_kind: str,
    run_id: str,
) -> DomainAdmission:
    """Admission of a code that holds no verified registration (see :func:`admit_domain`)."""
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
            if store.is_registered(code, trusted_keys=trusted_keys):
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
    grace_until = registration_grace_until(licence, first_seen)
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
    grace_until = registration_grace_until(licence, first_seen)
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
        # A full scan reads "interrupted" until its scan end records how it
        # ended (the coverage.json convention: an unfinished run closes nothing).
        run_status="" if is_recheck else RUN_INTERRUPTED,
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
            store.build_request(
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
    "NOTICE_CRITICAL",
    "NOTICE_NONE",
    "NOTICE_NOTE",
    "NOTICE_URGENT",
    "NOTICE_WARNING",
    "STATUS_SCHEMA_NAME",
    "anchor_session_clock",
    "reset_session_clock",
    "session_now",
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
