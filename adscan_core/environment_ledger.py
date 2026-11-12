"""Licence usage for the Enterprise edition: what may be assessed, and what was.

A signed licence in format 2 (``license_format: 2`` inside the signed payload)
declares ONE of two entitlement modes in ``entitlements``, and this module is
the single source of truth for both (decision 2026-11-04). A format 1 licence
keeps the behaviour it was issued under: its entitlements are recorded and
shown, never enforced. The
engine admits each domain at the seam where assessment activity in it begins
(``adscan_internal/cli/enterprise_license_gate.py``); the web platform reads the
usage for display, records an administrator's declarations, and exports the
usage report used at renewal.

Mode ``scoped`` (an Enterprise end customer, priced by enabled identities over
an agreed scope)::

    "entitlements": {
      "mode": "scoped",
      "identities": 5000,
      "scope": [
        {"forest": "corp.example", "root_sid": "<forest root domain SID>",
         "root_guid": "<forest root domain GUID>",
         "domains": ["corp.example", "emea.corp.example"]},
        {"forest": "partner.example"}
      ]
    }

* A domain is in scope when its forest matches a scope entry and, when the
  entry lists ``domains``, the domain is one of them (an entry without
  ``domains`` covers its whole forest). The forest is matched by its root
  domain name, and by the forest root SID and GUID whenever both the licence
  and the scan know them: a different SID or GUID never matches, whatever the
  name. A match by name alone (the scan could not read either) is allowed and
  recorded as unconfirmed.
* A domain outside the scope is REFUSED. A trusted domain discovered but not in
  scope stays mapped as context and is never assessed.
* Enabled identities are counted per assessed domain at each scan, from the
  workspace. The current figure is the sum of the latest count of every
  in-scope domain; a high-water mark is kept per domain and for the whole
  scope. Over the priced figure every surface WARNS and the usage report
  records it for the true-up at renewal; nothing is ever blocked for growth
  mid-term.
* Workspaces are free-form: billing is the scope.

Mode ``organizations`` (an assessor or MSSP, priced per organization assessed
per term)::

    "entitlements": {
      "mode": "organizations",
      "organizations_per_year": 20,
      "max_declared_forests": 3      # optional, default 3, or "unlimited"
    }

* One organization = one workspace. The first forest assessed in a workspace
  ANCHORS it to an organization and uses one of N for the term.
* A further forest in that workspace is FREE when the trust records ADscan
  collected (``domains_data[<domain>]["trusts"]``, read from an assessed domain
  controller's ``trustedDomain`` objects, :func:`confirmed_trust_edges`) show a
  trust path, direct or transitive, to a forest of that organization. Unknown,
  disabled or unobserved trusts are no link.
* An UNRELATED forest in an anchored workspace is REFUSED: it belongs in its own
  workspace, which also keeps each client's data apart. One organization that
  really owns disconnected forests is handled by an explicit administrator
  DECLARATION ("same organization") for the refused forest, recorded with who
  and when in the sealed ledger, shown on the licence panel and in the usage
  report, and capped at ``max_declared_forests`` declarations per
  organization. It uses no extra count.
* A forest already counted this term stays counted, is never counted twice, and
  is assessed again freely in a workspace that is new (a deleted and recreated
  one) or that belongs to its organization. When a later assessment observes a
  trust path between two organizations counted apart in the same workspace,
  they are joined: they were one organization.

Forest identity. Each forest is identified by its forest root domain GUID
(``DomainGuid`` in the CLDAP netlogon reply, read before authentication). When
the root does not answer the forest is recorded provisionally (DNS name plus
the GUID of the domain that answered), and with nothing at all by name only;
either still counts, so an unreachable forest never reads as free. A forest
sharing a DNS name with a counted one but not its identity is a different
forest: the name proves nothing.

Counting. Usage counts for a licence when it happened inside that licence's
term (``valid_from`` to the end of the grace period); a renewal starts afresh.

What this is and is not. Every fact here is recorded on the appliance and read
back by ADscan; the appliance holds no signing key of its own, so the usage
report is a declaration the client sends at renewal, backed by the contract,
not a cryptographic proof. The licence itself is the only signed artefact.

Tamper stance, the same as the clock high-water mark beside it. The ledger
(``environments.json``) is chained (each forest entry carries a SHA-256 over its
immutable fields and the previous digest), and the facts that lower a count or
allow an admission (the counted forests, organization joins, declarations, the
identity high-water marks) are sealed into ``clock-state.json``. Editing or deleting one file
is detected and repaired from the other and the count never goes down; deleting
both resets it, which needs a shell the delivered appliance does not give. It is
a deterrent; the contract governs the term.

Pure stdlib, importable by the engine, the web backend and the launcher.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import secrets
import tempfile
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any

from adscan_core.license_storage import (
    REASON_LICENSE_STORAGE_UNAVAILABLE,
    LicenseStorageError,
    adopt_directory_owner,
)
from adscan_core.pal.platform import is_windows

#: Entitlement keys in the signed licence payload.
ENVIRONMENT_ENTITLEMENT = "organizations_per_year"
MODE_KEY = "mode"
MODE_ORGANIZATIONS = "organizations"
MODE_SCOPED = "scoped"
MAX_DECLARED_KEY = "max_declared_forests"
DEFAULT_MAX_DECLARED_FORESTS = 3
#: ``max_declared_forests`` value for a licence with no cap on declarations.
#: A text token on purpose: an appliance that predates it reads the cap through
#: the whole-number rule alone and refuses the licence file as malformed,
#: never as a cap of 0 nor as a licence without a mode.
UNLIMITED = "unlimited"
#: How a "same organization" declaration was made. Both are the same record,
#: written by :func:`declare_same_organization`.
DECLARED_VIA_SETTINGS = "license_settings"
DECLARED_VIA_ASSESSMENT = "assessment_prompt"
_DECLARATION_CHANNELS = frozenset({DECLARED_VIA_SETTINGS, DECLARED_VIA_ASSESSMENT})
#: Option indices of :func:`declaration_question`.
DECLARE_SAME_ORGANIZATION = 0
DECLARE_DIFFERENT_ORGANIZATION = 1
#: Licence format from which entitlements are enforced (``license_format``
#: inside the signed payload, see ``adscan_core.enterprise_license``).
ENFORCED_FORMAT_VERSION = 2
SCOPE_KEY = "scope"
IDENTITIES_KEY = "identities"

LEDGER_FILENAME = "environments.json"
LEDGER_LOCK_FILENAME = ".environments.lock"
#: Key under which the seal lives in the licence clock-state file.
SEAL_KEY = "environments"
LEDGER_VERSION = 2
#: Share of the quota from which every surface warns.
WARN_FRACTION = 0.8

#: Stable reason codes the engine writes beside exit 78 so the appliance worker
#: can tell the refusals apart from a licence-state refusal.
REASON_ENVIRONMENT_QUOTA = "environment_quota_reached"
REASON_WORKSPACE_ORGANIZATION = "workspace_belongs_to_another_organization"
REASON_OUTSIDE_SCOPE = "outside_license_scope"

SOURCE_CLDAP_ROOT = "cldap_root"
SOURCE_CLDAP_CHILD = "cldap_child"
SOURCE_NAME_ONLY = "name_only"

INTEGRITY_OK = "ok"
INTEGRITY_RESTORED = "restored"

OUTCOME_NOT_ENFORCED = "not_enforced"
OUTCOME_KNOWN = "known"
OUTCOME_ADMITTED = "admitted"
#: A new forest joined an organization already counted (trust or declaration).
OUTCOME_JOINED = "joined"
#: A domain inside the licence scope (``scoped`` mode).
OUTCOME_IN_SCOPE = "in_scope"
OUTCOME_REFUSED = "refused"

_KEEPS_DATA = "Existing reports, history and exports remain available."


class EntitlementError(ValueError):
    """The ``entitlements`` of a licence do not form a valid policy, or a declaration is refused."""


# ── Value objects ────────────────────────────────────────────────────────────


def normalize_guid(value: str | None) -> str | None:
    """Return a GUID as lowercase canonical text, or None when it is not one."""
    text = str(value or "").strip().strip("{}").lower()
    if len(text) != 36 or text.count("-") != 4:
        return None
    if not all(ch in "0123456789abcdef-" for ch in text):
        return None
    if text == "00000000-0000-0000-0000-000000000000":
        return None
    return text


def _normalize_dns(value: str | None) -> str:
    return str(value or "").strip().rstrip(".").lower()


@dataclass(frozen=True)
class ForestIdentity:
    """Who a domain belongs to, as far as ADscan could establish it.

    Attributes:
        forest_dns_name: DNS name of the forest root domain (the assessed
            domain's own name when the forest name is unknown).
        domain_dns_name: The domain ADscan is about to assess.
        root_domain_guid: Forest root domain GUID, when the root answered.
        domain_guid: GUID of the domain that answered (the assessed domain).
        root_sid: Forest root domain SID, when an authenticated phase read it.
        source: How it was established (``SOURCE_*``).
    """

    forest_dns_name: str
    domain_dns_name: str
    root_domain_guid: str | None = None
    domain_guid: str | None = None
    root_sid: str | None = None
    source: str = SOURCE_NAME_ONLY

    def __post_init__(self) -> None:
        object.__setattr__(self, "forest_dns_name", _normalize_dns(self.forest_dns_name))
        object.__setattr__(self, "domain_dns_name", _normalize_dns(self.domain_dns_name))
        object.__setattr__(self, "root_domain_guid", normalize_guid(self.root_domain_guid))
        object.__setattr__(self, "domain_guid", normalize_guid(self.domain_guid))
        if not self.forest_dns_name:
            object.__setattr__(self, "forest_dns_name", self.domain_dns_name)

    @property
    def provisional(self) -> bool:
        """True when the forest root GUID is not known."""
        return self.root_domain_guid is None

    @property
    def label(self) -> str:
        """Operator-facing name of the forest."""
        return self.forest_dns_name or self.domain_dns_name


@dataclass(frozen=True)
class ScopeEntry:
    """One in-scope forest of a ``scoped`` licence."""

    forest: str
    root_guid: str | None = None
    root_sid: str | None = None
    domains: tuple[str, ...] = ()

    @property
    def names(self) -> tuple[str, ...]:
        """The domain names this entry covers (its forest when none are listed)."""
        return self.domains or (self.forest,)


@dataclass(frozen=True)
class EntitlementPolicy:
    """The usage rule a licence declares."""

    mode: str
    organizations: int | None = None
    #: None means no cap (:data:`UNLIMITED` in the licence).
    max_declared_forests: int | None = DEFAULT_MAX_DECLARED_FORESTS
    scope: tuple[ScopeEntry, ...] = ()
    identities: int | None = None


def _whole_number(value: Any, name: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise EntitlementError(
            f"The license entitlement '{name}' must be a whole number of at least {minimum}."
        )
    return value


def _declaration_cap(value: Any) -> int | None:
    """The ``max_declared_forests`` entitlement: a whole number, or None for unlimited."""
    if value == UNLIMITED:
        return None
    return _whole_number(value, MAX_DECLARED_KEY)


def _under_cap(count: int, cap: int | None) -> bool:
    return cap is None or count < cap


def cap_label(cap: int | None) -> str | int:
    """How a declaration cap is written in the usage report: a number or ``"unlimited"``."""
    return UNLIMITED if cap is None else cap


_SID_PREFIX = "S-1-5-21-"


def _normalize_sid(value: Any) -> str | None:
    text = str(value or "").strip().upper()
    if not text.startswith(_SID_PREFIX):
        return None
    parts = text[len(_SID_PREFIX) :].split("-")
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        return None
    return text


def parse_entitlement_policy(
    entitlements: Mapping[str, Any] | None, *, format_version: int = ENFORCED_FORMAT_VERSION
) -> EntitlementPolicy | None:
    """Read the policy from ``entitlements``; None when the licence sets none.

    A licence older than :data:`ENFORCED_FORMAT_VERSION` sets none, whatever its
    entitlements say: they were issued as informational and stay so.

    Raises:
        EntitlementError: the entitlements name a mode but do not form it.
    """
    if format_version < ENFORCED_FORMAT_VERSION:
        return None
    data = dict(entitlements or {})
    mode = data.get(MODE_KEY)
    if mode is None:
        return None
    if mode == MODE_ORGANIZATIONS:
        return EntitlementPolicy(
            mode=MODE_ORGANIZATIONS,
            organizations=_whole_number(data.get(ENVIRONMENT_ENTITLEMENT), ENVIRONMENT_ENTITLEMENT),
            max_declared_forests=_declaration_cap(data.get(MAX_DECLARED_KEY, DEFAULT_MAX_DECLARED_FORESTS)),
        )
    if mode == MODE_SCOPED:
        raw_scope = data.get(SCOPE_KEY)
        if not isinstance(raw_scope, list) or not raw_scope:
            raise EntitlementError("A scoped license must list at least one in-scope forest under 'scope'.")
        entries = []
        for item in raw_scope:
            if not isinstance(item, Mapping):
                raise EntitlementError("Each scope entry must be an object with a 'forest'.")
            forest = _normalize_dns(item.get("forest"))
            if not forest:
                raise EntitlementError("Each scope entry must name its 'forest'.")
            raw_guid = item.get("root_guid")
            guid = normalize_guid(raw_guid) if raw_guid else None
            if raw_guid and guid is None:
                raise EntitlementError(f"The scope entry for {forest} has an invalid 'root_guid'.")
            raw_sid = item.get("root_sid")
            sid = _normalize_sid(raw_sid) if raw_sid else None
            if raw_sid and sid is None:
                raise EntitlementError(f"The scope entry for {forest} has an invalid 'root_sid'.")
            domains = item.get("domains") or []
            if not isinstance(domains, list) or not all(isinstance(d, str) and d.strip() for d in domains):
                raise EntitlementError(f"The scope entry for {forest} has an invalid 'domains' list.")
            entries.append(
                ScopeEntry(
                    forest=forest,
                    root_guid=guid,
                    root_sid=sid,
                    domains=tuple(_normalize_dns(d) for d in domains),
                )
            )
        return EntitlementPolicy(
            mode=MODE_SCOPED,
            scope=tuple(entries),
            identities=_whole_number(data.get(IDENTITIES_KEY), IDENTITIES_KEY),
        )
    raise EntitlementError(f"Unknown license entitlement mode '{mode}'.")


def entitlement_policy(license_payload: Any) -> EntitlementPolicy | None:
    """Policy of a verified licence, or None (no policy, or none readable)."""
    if license_payload is None:
        return None
    entitlements = getattr(license_payload, "entitlements", None) or {}
    if not isinstance(entitlements, Mapping):
        return None
    try:
        return parse_entitlement_policy(
            entitlements, format_version=int(getattr(license_payload, "format_version", 1) or 1)
        )
    except EntitlementError:
        return None


def environment_quota(license_payload: Any) -> int | None:
    """Organizations a licence covers per term, or None outside that mode."""
    policy = entitlement_policy(license_payload)
    if policy is None or policy.mode != MODE_ORGANIZATIONS:
        return None
    return policy.organizations


@dataclass(frozen=True)
class EnvironmentUsage:
    """Usage of the licence entitlement for its term.

    ``organizations`` mode: ``entries`` holds one item per counted organization
    (its label, workspaces, first assessment and forests, each marked counted,
    included through a trust, or declared), and ``pending`` lists the refused
    forests an administrator may declare part of an organization.

    ``scoped`` mode: ``scope`` lists the in-scope domains with their latest
    identity counts; ``quota`` / ``used`` are the priced and current identity
    figures.
    """

    mode: str
    quota: int
    used: int
    term_start: date
    term_end: date
    entries: tuple[dict[str, Any], ...] = ()
    pending: tuple[dict[str, Any], ...] = ()
    declarations: tuple[dict[str, Any], ...] = ()
    scope: tuple[dict[str, Any], ...] = ()
    identity_peak: int = 0
    #: None means no cap (shown as ``"unlimited"``).
    max_declared_forests: int | None = DEFAULT_MAX_DECLARED_FORESTS
    integrity: str = INTEGRITY_OK

    @property
    def remaining(self) -> int:
        return max(0, self.quota - self.used)

    @property
    def exhausted(self) -> bool:
        return self.mode == MODE_ORGANIZATIONS and self.used >= self.quota

    @property
    def over(self) -> bool:
        """``scoped``: the current identity count is above the priced figure."""
        return self.mode == MODE_SCOPED and self.used > self.quota

    @property
    def near_limit(self) -> bool:
        return self.quota > 0 and self.used >= self.quota * WARN_FRACTION

    @property
    def summary(self) -> str:
        """``"7 of 20 organizations used this term"`` or ``"scope: 3 domains, ..."``."""
        if self.mode == MODE_SCOPED:
            count = len(self.scope)
            return (
                f"scope: {count} domain{'s' if count != 1 else ''}, "
                f"{self.used:,} of {self.quota:,} identities"
            )
        noun = "organization" if self.quota == 1 else "organizations"
        return f"{self.used} of {self.quota} {noun} used this term"

    @property
    def warning_message(self) -> str:
        """Empty, or the notice every surface shows near or at the limit."""
        if self.mode == MODE_SCOPED:
            if self.over:
                return (
                    f"The assessed scope holds {self.used:,} enabled identities, above "
                    f"the {self.quota:,} this license covers. Assessments continue; "
                    "the difference is recorded for the review at renewal."
                )
            return ""
        if self.exhausted:
            return (
                f"All {self.quota} organizations this license covers for its term "
                "are in use. Organizations already assessed this term can still be "
                "assessed again; a new organization cannot start until ADscan "
                "extends the license."
            )
        if self.near_limit:
            return (
                f"{self.summary[0].upper()}{self.summary[1:]} ({self.remaining} left). "
                "Contact ADscan before the last ones are needed."
            )
        return ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "quota": self.quota,
            "used": self.used,
            "remaining": self.remaining,
            "term_start": self.term_start.isoformat(),
            "term_end": self.term_end.isoformat(),
            "summary": self.summary,
            "warning": bool(self.warning_message),
            "exhausted": self.exhausted,
            "over": self.over,
            "integrity": self.integrity,
            "max_declared_forests": cap_label(self.max_declared_forests),
            "identity_peak": self.identity_peak,
            "entries": [dict(entry) for entry in self.entries],
            "pending": [dict(item) for item in self.pending],
            "declarations": [dict(item) for item in self.declarations],
            "scope": [dict(item) for item in self.scope],
        }


@dataclass(frozen=True)
class EnvironmentAdmission:
    """The answer to "may ADscan start assessing this domain?"."""

    allowed: bool
    outcome: str
    message: str
    reason_code: str = ""
    usage: EnvironmentUsage | None = None
    entry: Mapping[str, Any] | None = field(default=None)
    #: Ledger key of the forest entry (pass it back as ``supersedes``).
    admitted_as: str = ""
    #: A refused forest the administrator may declare (``organizations`` mode).
    declarable: bool = False
    #: Refusal record to pass to :func:`declare_same_organization` (a refusal
    #: in an anchored workspace), so the operator can declare it on the spot.
    refusal_id: str = ""
    #: The refused forest and the forest that anchors the workspace, unmarked.
    forest_label: str = ""
    anchor_label: str = ""


# ── Licence term helpers (duck-typed on LicensePayload) ─────────────────────


def _term_window(license_payload: Any) -> tuple[datetime, datetime]:
    """[start, end) of the counting window: the term plus its grace period."""
    starts = datetime.combine(license_payload.valid_from, time.min, tzinfo=timezone.utc)
    ends = datetime.combine(
        license_payload.valid_until + timedelta(days=1 + int(license_payload.grace_days)),
        time.min,
        tzinfo=timezone.utc,
    )
    return starts, ends


def _parse_instant(text: Any) -> datetime | None:
    if not isinstance(text, str) or not text.strip():
        return None
    try:
        value = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _format_instant(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now(now: datetime | None) -> datetime:
    current = now or datetime.now(timezone.utc)
    return current if current.tzinfo else current.replace(tzinfo=timezone.utc)


# ── Files, lock, chain ───────────────────────────────────────────────────────


def _atomic_write_json(path: Path, data: Mapping[str, Any]) -> None:
    """Replace ``path`` atomically; the file takes the directory's owner.

    Raises:
        LicenseStorageError: the directory or the file could not be written.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    except OSError as exc:
        raise LicenseStorageError.from_os_error(exc, path) from exc
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, sort_keys=True, indent=2)
        os.chmod(tmp, 0o644)
        adopt_directory_owner(Path(tmp), directory=path.parent)
        os.replace(tmp, path)
    except BaseException as exc:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        if isinstance(exc, OSError) and not isinstance(exc, LicenseStorageError):
            raise LicenseStorageError.from_os_error(exc, path) from exc
        raise


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _open_lock_file(lock_path: Path):
    """Open (creating) the lock file without needing write access to it.

    POSIX opens it READ-ONLY: ``flock`` takes an exclusive lock on any open
    descriptor of a local file, so the lock works whichever user created the
    file and whatever its mode. On the appliance a web backend that ran as root
    (before 14.0.1) created it first and the engine, running as the host user,
    must still lock it; an
    ``"a+b"`` open needed write access and failed with EACCES there, which
    refused every assessment with exit 78 on a valid license. A file this call
    creates (or finds) as root takes the directory's owner.

    Windows keeps the original ``"a+b"`` handle: ``msvcrt.locking`` works on
    it and there is no cross-user bind mount on that path.
    """
    if is_windows():
        return open(lock_path, "a+b")  # noqa: SIM115 - closed by the caller
    fd = os.open(lock_path, os.O_RDONLY | os.O_CREAT, 0o664)
    # Also repairs a lock an older build left root-owned (a no-op unless root).
    adopt_directory_owner(lock_path)
    return os.fdopen(fd, "rb")


@contextlib.contextmanager
def state_file_lock(directory: Path) -> Iterator[None]:
    """Serialise read-modify-write of the ledger across processes.

    The engine containers and the web backend share the directory through bind
    mounts on one kernel, so an advisory lock on a file in it is enough.
    Best-effort: when no lock primitive is available the write still happens.

    Raises:
        LicenseStorageError: the directory or the lock file could not be
            created or opened (permissions, a read-only filesystem). That is a
            storage fault, and callers report it as one, never as a license
            decision.
    """
    lock_path = directory / LEDGER_LOCK_FILENAME
    try:
        directory.mkdir(parents=True, exist_ok=True)
        handle = _open_lock_file(lock_path)
    except OSError as exc:
        raise LicenseStorageError.from_os_error(exc, lock_path) from exc
    locked = False
    try:
        try:
            import fcntl  # POSIX

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            locked = True
        except ImportError:
            try:
                import msvcrt  # Windows

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
                locked = True
            except (ImportError, OSError):
                locked = False
        except OSError:
            locked = False
        yield
    finally:
        if locked:
            with contextlib.suppress(Exception):
                try:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                except ImportError:
                    import msvcrt

                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        handle.close()


_IMMUTABLE_FIELDS = ("index", "admitted_as", "first_assessed", "license_id")


def _entry_digest(entry: Mapping[str, Any], previous: str) -> str:
    material = {name: entry.get(name) for name in _IMMUTABLE_FIELDS}
    # The organization a forest was admitted into is a counted fact. Entries
    # written before organizations existed carry no key and keep their digest.
    if "environment" in entry:
        material["environment"] = entry.get("environment")
    material["previous"] = previous
    blob = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode("ascii")).hexdigest()


def _chain_is_valid(entries: list[dict[str, Any]]) -> bool:
    previous = ""
    for position, entry in enumerate(entries):
        if entry.get("index") != position:
            return False
        digest = _entry_digest(entry, previous)
        if entry.get("digest") != digest:
            return False
        previous = digest
    return True


def _rechain(entries: list[dict[str, Any]]) -> None:
    previous = ""
    for position, entry in enumerate(entries):
        entry["index"] = position
        entry["digest"] = _entry_digest(entry, previous)
        previous = entry["digest"]


def _seal_records(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records = []
    for entry in entries:
        record = {
            "admitted_as": entry.get("admitted_as"),
            "first_assessed": entry.get("first_assessed"),
            "license_id": entry.get("license_id"),
        }
        if "environment" in entry:
            record["environment"] = entry.get("environment")
        records.append(record)
    return records


def _normalize_links(raw: Any) -> list[list[str]]:
    links: list[list[str]] = []
    for item in raw or []:
        if isinstance(item, (list, tuple)) and len(item) == 2:
            a, b = str(item[0] or ""), str(item[1] or "")
            if a and b and a != b and [a, b] not in links:
                links.append([a, b])
    return links


def _normalize_declarations(raw: Any) -> list[dict[str, Any]]:
    return [dict(item) for item in raw or [] if isinstance(item, Mapping) and item.get("id")]


def _identity_key(identity: ForestIdentity) -> str:
    if identity.root_domain_guid:
        return f"guid:{identity.root_domain_guid}"
    if identity.domain_guid:
        return f"provisional:{identity.forest_dns_name}:{identity.domain_guid}"
    return f"name:{identity.forest_dns_name}"


def _entry_from_sealed_key(admitted_as: str) -> dict[str, Any]:
    """Rebuild the identifying fields of an entry from its sealed key."""
    kind, _, rest = admitted_as.partition(":")
    entry: dict[str, Any] = {"admitted_as": admitted_as}
    if kind == "guid":
        entry["root_domain_guid"] = normalize_guid(rest)
        entry["provisional"] = False
        entry["label"] = rest
    elif kind == "provisional":
        forest, _, child = rest.rpartition(":")
        entry["forest_dns_name"] = forest
        entry["domain_guids"] = [g for g in [normalize_guid(child)] if g]
        entry["provisional"] = True
        entry["label"] = forest
    else:
        entry["forest_dns_name"] = rest
        entry["provisional"] = True
        entry["label"] = rest
    return entry


def _int_or_zero(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _normalize_peaks(raw: Any) -> dict[str, int]:
    if not isinstance(raw, Mapping):
        return {}
    return {_normalize_dns(k): _int_or_zero(v) for k, v in raw.items() if _normalize_dns(k)}


@dataclass
class _Ledger:
    entries: list[dict[str, Any]]
    links: list[list[str]]
    declarations: list[dict[str, Any]]
    refusals: list[dict[str, Any]]
    identity_counts: dict[str, dict[str, Any]]
    identity_peak: int
    integrity: str
    identity_peaks: dict[str, int] = field(default_factory=dict)


def _load(directory: Path, clock_state_name: str) -> _Ledger:
    """Return the reconciled ledger and its integrity verdict.

    The ledger file and the seal in the clock-state file must agree. A record
    the seal holds that the ledger lost is rebuilt from the seal, an edited
    entry is put back to the sealed facts, and the verdict says so; the count
    never goes down. Facts that lower a count or allow an admission (joins,
    declarations, the identity peak) are taken from the seal only.
    """
    ledger = _read_json(directory / LEDGER_FILENAME) or {}
    raw_entries = ledger.get("entries")
    entries = [dict(e) for e in raw_entries if isinstance(e, dict)] if isinstance(raw_entries, list) else []
    refusals = [dict(r) for r in ledger.get("refusals") or [] if isinstance(r, Mapping)]
    counts_raw = ledger.get("identity_counts")
    identity_counts = (
        {str(k): dict(v) for k, v in counts_raw.items() if isinstance(v, Mapping)}
        if isinstance(counts_raw, Mapping)
        else {}
    )
    clock_state = _read_json(directory / clock_state_name) or {}
    seal = clock_state.get(SEAL_KEY)
    sealed = (
        [dict(r) for r in seal.get("records", []) if isinstance(r, dict)]
        if isinstance(seal, dict) and isinstance(seal.get("records"), list)
        else None
    )
    integrity = INTEGRITY_OK
    if entries and not _chain_is_valid(entries):
        integrity = INTEGRITY_RESTORED
    if sealed is None:
        # No seal yet (first admission, or a licence directory older than this
        # module). The ledger alone is the record.
        return _Ledger(
            entries=entries,
            links=_normalize_links(ledger.get("links")),
            declarations=_normalize_declarations(ledger.get("declarations")),
            refusals=refusals,
            identity_counts=identity_counts,
            identity_peak=_int_or_zero(ledger.get("identity_peak")),
            integrity=integrity,
            identity_peaks=_normalize_peaks(ledger.get("identity_peaks")),
        )
    links = _normalize_links(seal.get("links"))
    declarations = _normalize_declarations(seal.get("declarations"))
    if ledger.get("links") and _normalize_links(ledger.get("links")) != links:
        integrity = INTEGRITY_RESTORED
    if ledger.get("declarations") and _normalize_declarations(ledger.get("declarations")) != declarations:
        integrity = INTEGRITY_RESTORED

    def _fact(record: Mapping[str, Any]) -> tuple[Any, Any]:
        return (record.get("admitted_as"), record.get("first_assessed"))

    by_fact = {_fact(entry): entry for entry in entries}
    rebuilt: list[dict[str, Any]] = []
    for record in sealed:
        match = by_fact.pop(_fact(record), None)
        if match is None:
            integrity = INTEGRITY_RESTORED
            match = _entry_from_sealed_key(str(record.get("admitted_as") or ""))
            match.update(
                {
                    "first_assessed": record.get("first_assessed"),
                    "license_id": record.get("license_id"),
                    "restored_from_seal": True,
                }
            )
            if "environment" in record:
                match["environment"] = record.get("environment")
        else:
            if match.get("license_id") != record.get("license_id"):
                integrity = INTEGRITY_RESTORED
                match["license_id"] = record.get("license_id")
            if "environment" in record and match.get("environment") != record.get("environment"):
                integrity = INTEGRITY_RESTORED
                match["environment"] = record.get("environment")
        rebuilt.append(match)
    # Entries written after the seal (a crash between the two writes) are kept.
    rebuilt.extend(entry for entry in entries if _fact(entry) in by_fact)
    return _Ledger(
        entries=rebuilt,
        links=links,
        declarations=declarations,
        refusals=refusals,
        identity_counts=identity_counts,
        identity_peak=_int_or_zero(seal.get("identity_peak")),
        integrity=integrity,
        identity_peaks=_normalize_peaks(seal.get("identity_peaks")),
    )


def _store(directory: Path, clock_state_name: str, state: _Ledger) -> None:
    _rechain(state.entries)
    state.links = _normalize_links(state.links)
    _atomic_write_json(
        directory / LEDGER_FILENAME,
        {
            "version": LEDGER_VERSION,
            "entries": state.entries,
            "links": state.links,
            "declarations": state.declarations,
            "refusals": state.refusals,
            "identity_counts": state.identity_counts,
            "identity_peak": state.identity_peak,
            "identity_peaks": state.identity_peaks,
        },
    )
    clock_path = directory / clock_state_name
    clock_state = _read_json(clock_path) or {}
    clock_state[SEAL_KEY] = {
        "records": _seal_records(state.entries),
        "links": state.links,
        "declarations": state.declarations,
        "identity_peak": state.identity_peak,
        "identity_peaks": state.identity_peaks,
        "head": state.entries[-1]["digest"] if state.entries else "",
    }
    _atomic_write_json(clock_path, clock_state)


# ── Matching and grouping ────────────────────────────────────────────────────


def _counts(entry: Mapping[str, Any]) -> bool:
    return not entry.get("merged_into")


def _in_window(record: Mapping[str, Any], start: datetime, end: datetime, key: str = "first_assessed") -> bool:
    first = _parse_instant(record.get(key))
    return first is not None and start <= first < end


def _entry_matches(entry: Mapping[str, Any], identity: ForestIdentity) -> bool:
    """True when ``entry`` is the forest ``identity`` describes.

    Only a GUID proves identity. A domain GUID ties a provisional answer to the
    forest it was later confirmed as; a bare DNS name ties name-only records
    together and nothing else, because ``corp.local`` exists in every other
    organization. The cost of that rule is an over-count (one forest recorded
    twice when its first visit was name-only), never a free assessment.
    """
    root = normalize_guid(entry.get("root_domain_guid"))
    domain_guids = {normalize_guid(g) for g in entry.get("domain_guids") or []}
    domain_guids.discard(None)
    if identity.root_domain_guid and root:
        return root == identity.root_domain_guid
    if identity.domain_guid and identity.domain_guid in domain_guids:
        return True
    if identity.root_domain_guid or identity.domain_guid:
        return False
    return not root and not domain_guids and entry.get("forest_dns_name") == identity.forest_dns_name


def _annotate(entry: dict[str, Any], identity: ForestIdentity, workspace: str, now: datetime) -> None:
    """Add what this assessment learned to an entry (never the counted facts)."""
    if identity.root_domain_guid and not normalize_guid(entry.get("root_domain_guid")):
        entry["root_domain_guid"] = identity.root_domain_guid
        entry["provisional"] = False
        entry["confirmed_at"] = _format_instant(now)
    entry["forest_dns_name"] = entry.get("forest_dns_name") or identity.forest_dns_name
    entry["label"] = entry.get("forest_dns_name") or identity.label
    if identity.root_sid and not entry.get("root_sid"):
        entry["root_sid"] = identity.root_sid
    for key, value in (
        ("domains", identity.domain_dns_name),
        ("domain_guids", identity.domain_guid),
        ("workspaces", workspace),
    ):
        if not value:
            continue
        values = [v for v in entry.get(key) or [] if v]
        if value not in values:
            values.append(value)
        entry[key] = values
    entry["last_assessed"] = _format_instant(now)


def _public_entry(entry: Mapping[str, Any]) -> dict[str, Any]:
    via = entry.get("joined_by") or ("trust" if entry.get("free_by_trust") else "")
    return {
        "forest": entry.get("forest_dns_name") or entry.get("label") or "",
        "first_assessed": entry.get("first_assessed"),
        "last_assessed": entry.get("last_assessed") or entry.get("first_assessed"),
        "provisional": not bool(normalize_guid(entry.get("root_domain_guid"))),
        "workspaces": list(entry.get("workspaces") or []),
        "domains": list(entry.get("domains") or []),
        "joined_by": via or None,
        "free_by_trust": via == "trust",
        "linked_to": entry.get("linked_to") or None,
        "declared_by": entry.get("declared_by") or None,
        "declared_at": entry.get("declared_at") or None,
        "restored": bool(entry.get("restored_from_seal")),
    }


def _env_key(entry: Mapping[str, Any]) -> str:
    """The organization an entry belongs to (its own key when it anchors one)."""
    return str(entry.get("environment") or entry.get("admitted_as") or "")


class _EnvironmentGroups:
    """Union-find over organization keys, joined by the sealed links."""

    def __init__(self, links: list[list[str]]) -> None:
        self._parent: dict[str, str] = {}
        for a, b in links:
            self.union(a, b)

    def find(self, key: str) -> str:
        parent = self._parent.setdefault(key, key)
        if parent != key:
            parent = self._parent[key] = self.find(parent)
        return parent

    def union(self, a: str, b: str) -> None:
        root_a, root_b = self.find(a), self.find(b)
        if root_a != root_b:
            low, high = sorted((root_a, root_b))
            self._parent[high] = low


def _add_link(links: list[list[str]], groups: _EnvironmentGroups, a: str, b: str) -> None:
    """Record that two counted organizations are one."""
    if not a or not b or groups.find(a) == groups.find(b):
        return
    pair = sorted((a, b))
    if pair not in links:
        links.append(pair)
    groups.union(a, b)


def _in_term_entries(state: _Ledger, start: datetime, end: datetime) -> list[dict[str, Any]]:
    return [e for e in state.entries if _counts(e) and _in_window(e, start, end)]


def _organizations(
    state: _Ledger, start: datetime, end: datetime, groups: _EnvironmentGroups | None = None
) -> dict[str, list[dict[str, Any]]]:
    groups = groups or _EnvironmentGroups(state.links)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for entry in _in_term_entries(state, start, end):
        grouped.setdefault(groups.find(_env_key(entry)), []).append(entry)
    for members in grouped.values():
        members.sort(key=lambda e: (str(e.get("first_assessed") or ""), int(e.get("index") or 0)))
    return grouped


def _declarations_for(state: _Ledger, groups: _EnvironmentGroups, organization: str, start, end) -> int:
    """Declarations made this term for an organization (assessed or still waiting)."""
    return sum(
        1
        for declaration in state.declarations
        if groups.find(str(declaration.get("organization") or "")) == organization
        and _in_window(declaration, start, end, key="declared_at")
    )


def _usage_from(state: _Ledger, license_payload: Any, policy: EntitlementPolicy) -> EnvironmentUsage:
    start, end = _term_window(license_payload)
    if policy.mode == MODE_SCOPED:
        return _scoped_usage(state, license_payload, policy, start, end)
    organizations = []
    for members in _organizations(state, start, end).values():
        anchor = members[0]
        workspaces: list[str] = []
        for member in members:
            for name in member.get("workspaces") or []:
                if name and name not in workspaces:
                    workspaces.append(name)
        organizations.append(
            {
                "label": anchor.get("forest_dns_name") or anchor.get("label") or "",
                "first_assessed": anchor.get("first_assessed"),
                "workspaces": workspaces,
                "forests": [_public_entry(member) for member in members],
                "declared_forests": sum(1 for m in members if m.get("joined_by") == "declaration"),
            }
        )
    organizations.sort(key=lambda item: str(item.get("first_assessed") or ""))
    declared_refusals = {d.get("refusal_id") for d in state.declarations}
    pending = [
        {
            "id": r.get("id"),
            "forest": r.get("forest_label"),
            "workspace": r.get("workspace"),
            "anchored_at": r.get("anchor_label"),
            "refused_at": r.get("at"),
        }
        for r in state.refusals
        if r.get("id") not in declared_refusals and _in_window(r, start, end, key="at")
    ]
    declarations = [
        {
            "forest": d.get("forest_label"),
            "workspace": d.get("workspace"),
            "organization": d.get("organization_label"),
            "declared_by": d.get("declared_by"),
            "declared_at": d.get("declared_at"),
            # A declaration recorded before the channel was kept came from Settings.
            "declared_via": d.get("declared_via") or DECLARED_VIA_SETTINGS,
        }
        for d in state.declarations
        if _in_window(d, start, end, key="declared_at")
    ]
    return EnvironmentUsage(
        mode=MODE_ORGANIZATIONS,
        quota=int(policy.organizations or 0),
        used=len(organizations),
        term_start=license_payload.valid_from,
        term_end=license_payload.valid_until,
        entries=tuple(organizations),
        pending=tuple(pending),
        declarations=tuple(declarations),
        max_declared_forests=policy.max_declared_forests,
        integrity=state.integrity,
    )


def _scoped_usage(
    state: _Ledger, license_payload: Any, policy: EntitlementPolicy, start: datetime, end: datetime
) -> EnvironmentUsage:
    scope = []
    total = 0
    for entry in policy.scope:
        for name in entry.names:
            latest = state.identity_counts.get(name) or {}
            in_term = _in_window(latest, start, end, key="at")
            count = int(latest.get("count") or 0) if in_term else 0
            total += count
            scope.append(
                {
                    "domain": name,
                    "forest": entry.forest,
                    "identities": count if in_term else None,
                    "identities_peak": _int_or_zero(state.identity_peaks.get(name)) if in_term else None,
                    "counted_at": latest.get("at") if in_term else None,
                    "identity_confirmed": bool(latest.get("identity_confirmed")) if in_term else None,
                }
            )
    return EnvironmentUsage(
        mode=MODE_SCOPED,
        quota=int(policy.identities or 0),
        used=total,
        term_start=license_payload.valid_from,
        term_end=license_payload.valid_until,
        scope=tuple(scope),
        identity_peak=max(state.identity_peak, total),
        integrity=state.integrity,
    )


# ── Trust links ──────────────────────────────────────────────────────────────


def confirmed_trust_edges(domains_data: Mapping[str, Any] | None) -> list[tuple[str, str]]:
    """Trust edges ADscan observed, as ``(source domain, partner domain)`` pairs.

    Read from ``domains_data[<domain>]["trusts"]``, the records the trust
    enumeration persists from an assessed domain controller's ``trustedDomain``
    objects (``adscan_internal/cli/domains.py``). Only a record with an observed,
    enabled direction is an edge: a disabled trust links nothing, and an
    unreadable direction is not evidence of a link.
    """
    from adscan_core.ad_trust import DIRECTION_DISABLED, DIRECTION_UNKNOWN, normalize_trust_direction

    edges: list[tuple[str, str]] = []
    for owner, entry in (domains_data or {}).items():
        if not isinstance(entry, Mapping):
            continue
        for record in entry.get("trusts") or []:
            if not isinstance(record, Mapping):
                continue
            source = _normalize_dns(record.get("source_domain") or owner)
            partner = _normalize_dns(
                record.get("target_domain") or record.get("name") or record.get("partner")
            )
            if not source or not partner or source == partner:
                continue
            direction, _raw = normalize_trust_direction(
                record.get("trust_direction", record.get("direction"))
            )
            if direction in (DIRECTION_DISABLED, DIRECTION_UNKNOWN):
                continue
            edges.append((source, partner))
    return edges


def _entry_names(entry: Mapping[str, Any]) -> set[str]:
    names = {_normalize_dns(entry.get("forest_dns_name"))}
    names.update(_normalize_dns(d) for d in entry.get("domains") or [])
    names.discard("")
    return names


def _identity_names(identity: ForestIdentity) -> set[str]:
    return {n for n in (identity.forest_dns_name, identity.domain_dns_name) if n}


def _trust_path(edges: list[tuple[str, str]], start: set[str], goal: set[str]) -> list[str] | None:
    """Shortest undirected path from ``start`` to ``goal`` over ``edges``.

    A trust either way relates the two organizations, so direction does not
    matter here (it was already required to be observed and enabled).
    """
    graph: dict[str, set[str]] = {}
    for a, b in edges:
        graph.setdefault(a, set()).add(b)
        graph.setdefault(b, set()).add(a)
    frontier = [[name] for name in sorted(start)]
    seen = set(start)
    while frontier:
        next_frontier = []
        for path in frontier:
            for neighbour in sorted(graph.get(path[-1], ())):
                if neighbour in seen:
                    continue
                candidate = path + [neighbour]
                if neighbour in goal:
                    return candidate
                seen.add(neighbour)
                next_frontier.append(candidate)
        frontier = next_frontier
    return None


# ── Entry points ─────────────────────────────────────────────────────────────


def _default_clock_state_name() -> str:
    from adscan_core.enterprise_license import CLOCK_STATE_FILENAME

    return CLOCK_STATE_FILENAME


def _default_directory() -> Path:
    from adscan_core.enterprise_license import license_dir

    return license_dir()


def environment_usage(license_payload: Any, *, directory: Path | None = None) -> EnvironmentUsage | None:
    """Usage for display, or None when the licence sets no policy."""
    policy = entitlement_policy(license_payload)
    if policy is None:
        return None
    target = directory or _default_directory()
    state = _load(target, _default_clock_state_name())
    _rechain(state.entries)
    return _usage_from(state, license_payload, policy)


def _scope_match(policy: EntitlementPolicy, identity: ForestIdentity) -> tuple[ScopeEntry | None, bool]:
    """The scope entry ``identity`` falls under, and whether a GUID confirmed it.

    A scope entry with a GUID never matches a forest whose GUID ADscan read and
    found different, whatever its name. A match by name alone is allowed only
    when the forest's own GUID could not be read, and is reported as
    unconfirmed.
    """
    for entry in policy.scope:
        names = set(entry.names)
        in_names = identity.domain_dns_name in names or (
            not entry.domains and identity.forest_dns_name == entry.forest
        )
        if not in_names:
            continue
        root_sid = _normalize_sid(identity.root_sid)
        if entry.root_sid and root_sid and entry.root_sid != root_sid:
            continue  # same name, another forest
        if entry.root_guid and identity.root_domain_guid and entry.root_guid != identity.root_domain_guid:
            continue
        if identity.root_domain_guid and identity.forest_dns_name != entry.forest:
            continue
        confirmed = bool(
            (entry.root_sid and root_sid) or (entry.root_guid and identity.root_domain_guid)
        )
        return entry, confirmed
    return None, False


def admit_environment(
    identity: ForestIdentity,
    *,
    license_payload: Any,
    now: datetime | None = None,
    workspace: str = "",
    trusted: bool = False,
    supersedes: str | None = None,
    trust_edges: Iterable[tuple[str, str]] = (),
    directory: Path | None = None,
    format_label: Callable[[str], str] = str,
    format_person: Callable[[str], str] = str,
) -> EnvironmentAdmission:
    """Decide whether ADscan may start assessing the domain ``identity`` names.

    Args:
        identity: The forest the domain about to be assessed belongs to.
        license_payload: The verified licence (``LicensePayload``).
        now: Override the clock (tests).
        workspace: Logical workspace name (the organization, in that mode).
        trusted: The forest was reached across a trust from another assessed
            forest this session (recorded; the decision is the same).
        supersedes: ``admitted_as`` key of a provisional entry admitted earlier
            in this session for the same domain, reused once the identity is
            better known.
        trust_edges: Observed trust edges (:func:`confirmed_trust_edges`).
        directory: Override the licence directory (tests).
        format_label: How a forest or domain name is rendered in a message (the
            engine passes its sensitive-value marker).
        format_person: How the name of who declared a forest is rendered.

    Never raises on a storage error after a decision: an already counted forest
    stays allowed even when the annotation cannot be written. A NEW forest
    whose admission cannot be persisted is refused, because an unrecorded
    admission would read as free.
    """
    policy = entitlement_policy(license_payload)
    if policy is None:
        return EnvironmentAdmission(
            allowed=True,
            outcome=OUTCOME_NOT_ENFORCED,
            message="This license does not limit what can be assessed.",
        )
    current = _now(now)
    target = directory or _default_directory()
    clock_state_name = _default_clock_state_name()
    if policy.mode == MODE_SCOPED:
        return _admit_scoped(identity, policy, license_payload, target, clock_state_name, format_label)
    return _admit_organization(
        identity,
        policy,
        license_payload,
        current,
        workspace=workspace,
        trusted=trusted,
        supersedes=supersedes,
        edges=[(_normalize_dns(a), _normalize_dns(b)) for a, b in trust_edges],
        target=target,
        clock_state_name=clock_state_name,
        format_label=format_label,
        format_person=format_person,
    )


def _unconfirmed_scope_note(entry: ScopeEntry, identity: ForestIdentity) -> str:
    """Why a scoped admission is matched by name alone, stated truthfully.

    There are two different causes and the client acts differently on each: the
    licence entry carries no forest identifier (ask ADscan for a re-issue), or
    the directory's own identifier could not be read (a reachability matter).
    """
    if not (entry.root_sid or entry.root_guid):
        return " This license entry carries no forest identifier, so it is matched by name."
    if not (identity.root_sid or identity.root_domain_guid):
        return (
            " The forest identifier could not be read from the directory, "
            "so it is matched by name."
        )
    return (
        " The forest identifier read from the directory is not of the kind this license "
        "entry carries, so it is matched by name."
    )


def _admit_scoped(
    identity: ForestIdentity,
    policy: EntitlementPolicy,
    license_payload: Any,
    target: Path,
    clock_state_name: str,
    format_label: Callable[[str], str],
) -> EnvironmentAdmission:
    entry, confirmed = _scope_match(policy, identity)
    shown = format_label(identity.domain_dns_name or identity.label)
    usage = _usage_from(_load(target, clock_state_name), license_payload, policy)
    if entry is None:
        return EnvironmentAdmission(
            allowed=False,
            outcome=OUTCOME_REFUSED,
            reason_code=REASON_OUTSIDE_SCOPE,
            message=(
                f"{shown} is not in this license's scope; contact ADscan to extend it. "
                f"{_KEEPS_DATA}"
            ),
            usage=usage,
        )
    note = "" if confirmed else _unconfirmed_scope_note(entry, identity)
    return EnvironmentAdmission(
        allowed=True,
        outcome=OUTCOME_IN_SCOPE,
        message=f"{shown} is in this license's scope ({usage.summary}).{note}",
        usage=usage,
        entry={"forest": entry.forest, "identity_confirmed": confirmed},
    )


def _remaining_tail(remaining: int) -> str:
    if remaining > 0:
        return f"uses 1 of the remaining {remaining}"
    return "no organizations remain on this license this term"


def _cap_reached_sentence(cap: int | None) -> str:
    noun = "forest" if cap == 1 else "forests"
    return (
        f" This organization already has the {cap} declared {noun} this license allows, "
        "so it cannot be declared the same organization. Contact ADscan if it needs more."
    )


def declaration_question(*, forest: str, anchor: str, remaining: int) -> tuple[str, list[str]]:
    """The question an attended assessment asks when it meets an unrelated forest.

    Returns the title and the two options, indexed by
    :data:`DECLARE_SAME_ORGANIZATION` and :data:`DECLARE_DIFFERENT_ORGANIZATION`.
    One wording for the command line and the web console.
    """
    title = f"{forest} has no trust with {anchor}. Is it the same organization?"
    options = [
        "Same organization, included here and recorded with your name (uses no new organization)",
        f"Different organization, assessed in a new workspace ({_remaining_tail(remaining)})",
    ]
    return title, options


def _organization_refusal_message(
    *,
    anchor: str,
    shown: str,
    remaining: int,
    declarable: bool,
    known: bool,
    cap: int | None = None,
    cap_reached: bool = False,
) -> str:
    if known:
        tail = "it is already counted this term, so this uses no new organization"
    else:
        tail = _remaining_tail(remaining)
    message = (
        f"This workspace belongs to the organization anchored at {anchor}. "
        f"Assess {shown} in a new workspace ({tail})."
    )
    if declarable:
        message += (
            " If it is the same organization, an administrator can declare it under "
            "Settings > License, and the next assessment includes it."
        )
    elif cap_reached and not known:
        message += _cap_reached_sentence(cap)
    return message


def _admit_organization(
    identity: ForestIdentity,
    policy: EntitlementPolicy,
    license_payload: Any,
    current: datetime,
    *,
    workspace: str,
    trusted: bool,
    supersedes: str | None,
    edges: list[tuple[str, str]],
    target: Path,
    clock_state_name: str,
    format_label: Callable[[str], str],
    format_person: Callable[[str], str] = str,
) -> EnvironmentAdmission:
    start, end = _term_window(license_payload)
    quota = int(policy.organizations or 0)
    shown = format_label(identity.label)
    with state_file_lock(target):
        state = _load(target, clock_state_name)
        _rechain(state.entries)
        in_term = _in_term_entries(state, start, end)
        known = next((e for e in in_term if _entry_matches(e, identity)), None)
        previous = next(
            (e for e in in_term if supersedes and e.get("admitted_as") == supersedes),
            None,
        )
        if previous is not None and previous is not known:
            if known is not None:
                previous["merged_into"] = known.get("admitted_as")
            else:
                known = previous
            in_term = _in_term_entries(state, start, end)

        groups = _EnvironmentGroups(state.links)
        organizations = _organizations(state, start, end, groups)
        own_names = _identity_names(identity)
        workspace_orgs = sorted(
            {groups.find(_env_key(e)) for e in in_term if workspace and workspace in (e.get("workspaces") or [])}
        )
        known_org = groups.find(_env_key(known)) if known is not None else None

        def _anchor_label() -> str:
            for root in workspace_orgs:
                members = organizations.get(root) or []
                if members:
                    return str(members[0].get("forest_dns_name") or members[0].get("label") or "")
            return ""

        # Organizations of this workspace this forest has an observed trust
        # path to. A counted forest sharing a DNS name with this one but not its
        # identity is a different forest: never linked by name.
        linked: list[tuple[dict[str, Any], list[str]]] = []
        for other in in_term:
            other_org = groups.find(_env_key(other))
            if other is known or other_org not in workspace_orgs or other_org == known_org:
                continue
            other_names = _entry_names(other)
            if not other_names or other_names & own_names:
                continue
            path = _trust_path(edges, own_names, other_names)
            if path is not None:
                linked.append((other, path))

        declaration = next(
            (
                d
                for d in state.declarations
                if d.get("workspace") == workspace
                and _entry_matches(d.get("identity") or {}, identity)
                and _in_window(d, start, end, key="declared_at")
            ),
            None,
        )

        if known is not None:
            if not workspace_orgs or known_org in workspace_orgs or linked:
                _annotate(known, identity, workspace, current)
                for other, _path in linked:
                    _add_link(state.links, groups, _env_key(known), _env_key(other))
                with contextlib.suppress(OSError):
                    _store(target, clock_state_name, state)
                usage = _usage_from(state, license_payload, policy)
                return EnvironmentAdmission(
                    allowed=True,
                    outcome=OUTCOME_KNOWN,
                    message=f"Forest {shown} was already counted this term ({usage.summary}).",
                    usage=usage,
                    entry=_public_entry(known),
                    admitted_as=str(known.get("admitted_as") or ""),
                )
            usage = _usage_from(state, license_payload, policy)
            return EnvironmentAdmission(
                allowed=False,
                outcome=OUTCOME_REFUSED,
                reason_code=REASON_WORKSPACE_ORGANIZATION,
                message=_organization_refusal_message(
                    anchor=format_label(_anchor_label()),
                    shown=shown,
                    remaining=usage.remaining,
                    declarable=False,
                    known=True,
                ),
                usage=usage,
            )

        entry: dict[str, Any] = {
            "admitted_as": _identity_key(identity),
            "first_assessed": _format_instant(current),
            "license_id": getattr(license_payload, "license_id", ""),
            "forest_dns_name": identity.forest_dns_name,
            "label": identity.label,
            "root_domain_guid": identity.root_domain_guid,
            "provisional": identity.provisional,
            "source": identity.source,
            "trusted": bool(trusted),
        }
        outcome = OUTCOME_ADMITTED
        if linked:
            anchor, path = linked[0]
            entry["environment"] = groups.find(_env_key(anchor))
            entry["free_by_trust"] = True
            entry["joined_by"] = "trust"
            entry["linked_to"] = anchor.get("forest_dns_name") or anchor.get("label")
            entry["trust_path"] = path
            for other, _path in linked[1:]:
                _add_link(state.links, groups, _env_key(anchor), _env_key(other))
            outcome = OUTCOME_JOINED
        elif declaration is not None and groups.find(str(declaration.get("organization") or "")) in workspace_orgs:
            entry["environment"] = groups.find(str(declaration.get("organization") or ""))
            entry["joined_by"] = "declaration"
            entry["linked_to"] = declaration.get("organization_label")
            entry["declared_by"] = declaration.get("declared_by")
            entry["declared_at"] = declaration.get("declared_at")
            outcome = OUTCOME_JOINED
        else:
            usage = _usage_from(state, license_payload, policy)
            if workspace_orgs:
                declarable = _under_cap(
                    _declarations_for(state, groups, workspace_orgs[0], start, end),
                    policy.max_declared_forests,
                )
                anchor_label = _anchor_label()
                refusal_id = _record_refusal(state, identity, workspace, anchor_label, workspace_orgs[0], current)
                with contextlib.suppress(OSError):
                    _store(target, clock_state_name, state)
                return EnvironmentAdmission(
                    allowed=False,
                    outcome=OUTCOME_REFUSED,
                    reason_code=REASON_WORKSPACE_ORGANIZATION,
                    message=_organization_refusal_message(
                        anchor=format_label(anchor_label),
                        shown=shown,
                        remaining=usage.remaining,
                        declarable=declarable,
                        known=False,
                        cap=policy.max_declared_forests,
                        cap_reached=not declarable,
                    ),
                    usage=usage,
                    declarable=declarable,
                    refusal_id=refusal_id,
                    forest_label=identity.label,
                    anchor_label=anchor_label,
                )
            if usage.exhausted:
                return EnvironmentAdmission(
                    allowed=False,
                    outcome=OUTCOME_REFUSED,
                    reason_code=REASON_ENVIRONMENT_QUOTA,
                    message=(
                        f"This license covers {quota} organization"
                        f"{'s' if quota != 1 else ''} for this term and all {quota} "
                        f"are in use, so the assessment of {shown} cannot "
                        f"start. {_KEEPS_DATA} Organizations already assessed this term "
                        "can be assessed again. Contact ADscan to extend the license."
                    ),
                    usage=usage,
                )
            entry["environment"] = entry["admitted_as"]
        _annotate(entry, identity, workspace, current)
        state.entries.append(entry)
        try:
            _store(target, clock_state_name, state)
        except OSError:
            # A storage fault, never a quota verdict: the worker maps the reason
            # code to the client's message, and "all organizations are in use"
            # would send them to the wrong cause.
            state.entries.pop()
            return EnvironmentAdmission(
                allowed=False,
                outcome=OUTCOME_REFUSED,
                reason_code=REASON_LICENSE_STORAGE_UNAVAILABLE,
                message=(
                    f"The assessment of {shown} cannot start because ADscan "
                    "could not write its license records on this appliance. "
                    f"The license itself was not checked. {_KEEPS_DATA} "
                    "Contact ADscan support."
                ),
                usage=_usage_from(state, license_payload, policy),
            )
        usage = _usage_from(state, license_payload, policy)
        provisional_note = (
            " It is recorded provisionally until its forest root answers."
            if identity.provisional
            else ""
        )
        if outcome == OUTCOME_JOINED and entry.get("joined_by") == "trust":
            message = (
                f"Forest {shown} has an Active Directory trust to "
                f"{format_label(str(entry['linked_to']))}, already assessed in this "
                "workspace, so it is part of the same organization and uses no new "
                f"one ({usage.summary}).{provisional_note}"
            )
        elif outcome == OUTCOME_JOINED:
            message = (
                f"Forest {shown} was declared part of the organization anchored at "
                f"{format_label(str(entry['linked_to']))} by {format_person(str(entry.get('declared_by') or ''))}, "
                f"so it uses no new organization ({usage.summary}).{provisional_note}"
            )
        else:
            message = (
                f"New organization anchored at {shown} counted for this term "
                f"({usage.summary}).{provisional_note}"
            )
        return EnvironmentAdmission(
            allowed=True,
            outcome=outcome,
            message=message,
            usage=usage,
            entry=_public_entry(entry),
            admitted_as=str(entry["admitted_as"]),
        )


def _identity_record(identity: ForestIdentity) -> dict[str, Any]:
    return {
        "forest_dns_name": identity.forest_dns_name,
        "root_domain_guid": identity.root_domain_guid,
        "domain_guids": [identity.domain_guid] if identity.domain_guid else [],
        "domains": [identity.domain_dns_name] if identity.domain_dns_name else [],
    }


def _record_refusal(
    state: _Ledger,
    identity: ForestIdentity,
    workspace: str,
    anchor_label: str,
    organization: str,
    now: datetime,
) -> str:
    """Keep a refused forest as a candidate for an administrator's declaration.

    Returns the refusal's id (an existing record is refreshed, not duplicated).
    """
    for refusal in state.refusals:
        if refusal.get("workspace") == workspace and _entry_matches(refusal.get("identity") or {}, identity):
            refusal["at"] = _format_instant(now)
            return str(refusal.get("id") or "")
    refusal_id = secrets.token_hex(8)
    state.refusals.append(
        {
            "id": refusal_id,
            "at": _format_instant(now),
            "workspace": workspace,
            "forest_label": identity.label,
            "anchor_label": anchor_label,
            "organization": organization,
            "identity": _identity_record(identity),
        }
    )
    return refusal_id


def declare_same_organization(
    refusal_id: str,
    *,
    declared_by: str,
    license_payload: Any,
    declared_via: str = DECLARED_VIA_SETTINGS,
    now: datetime | None = None,
    directory: Path | None = None,
) -> dict[str, Any]:
    """Record an administrator's declaration that a refused forest is the same organization.

    Returns the declaration. Raises :class:`EntitlementError` with an
    administrator-facing reason when it cannot be made: the licence does not
    count organizations, the refusal is unknown or already declared, or the
    organization already holds ``max_declared_forests`` declarations this term.

    The declaration is recorded on the appliance with who made it, when, and
    through which channel (:data:`DECLARED_VIA_SETTINGS` for Settings > License,
    :data:`DECLARED_VIA_ASSESSMENT` for the question an attended assessment
    asks when it meets the forest). Both channels write this same record under
    the same cap. It is not signed by anything: it is the client's statement,
    backed by the contract, and it travels in the usage report.
    """
    policy = entitlement_policy(license_payload)
    if policy is None or policy.mode != MODE_ORGANIZATIONS:
        raise EntitlementError("This license does not count organizations, so there is nothing to declare.")
    who = str(declared_by or "").strip()
    if not who:
        raise EntitlementError("A declaration must name the administrator who makes it.")
    if declared_via not in _DECLARATION_CHANNELS:
        raise EntitlementError(f"Unknown declaration channel '{declared_via}'.")
    current = _now(now)
    target = directory or _default_directory()
    clock_state_name = _default_clock_state_name()
    start, end = _term_window(license_payload)
    with state_file_lock(target):
        state = _load(target, clock_state_name)
        _rechain(state.entries)
        refusal = next((r for r in state.refusals if r.get("id") == refusal_id), None)
        if refusal is None or not _in_window(refusal, start, end, key="at"):
            raise EntitlementError("That refused forest is not on record for this term.")
        if any(d.get("refusal_id") == refusal_id for d in state.declarations):
            raise EntitlementError("That forest is already declared part of an organization.")
        groups = _EnvironmentGroups(state.links)
        organization = groups.find(str(refusal.get("organization") or ""))
        members = _organizations(state, start, end, groups).get(organization) or []
        if not members:
            raise EntitlementError(
                "The organization that workspace belonged to is no longer counted this term."
            )
        if not _under_cap(_declarations_for(state, groups, organization, start, end), policy.max_declared_forests):
            raise EntitlementError(
                f"This license allows {policy.max_declared_forests} declared forests per "
                "organization, and this one already has them. Contact ADscan if the "
                "organization needs more."
            )
        declaration = {
            "id": secrets.token_hex(8),
            "refusal_id": refusal_id,
            "workspace": refusal.get("workspace"),
            "forest_label": refusal.get("forest_label"),
            "identity": refusal.get("identity") or {},
            "organization": organization,
            "organization_label": members[0].get("forest_dns_name") or members[0].get("label"),
            "declared_by": who,
            "declared_at": _format_instant(current),
            "declared_via": declared_via,
            "license_id": getattr(license_payload, "license_id", ""),
        }
        state.declarations.append(declaration)
        _store(target, clock_state_name, state)
        return dict(declaration)


def record_identity_count(
    domain: str,
    count: int,
    *,
    license_payload: Any,
    workspace: str = "",
    identity_confirmed: bool = False,
    now: datetime | None = None,
    directory: Path | None = None,
) -> EnvironmentUsage | None:
    """Record the enabled identities of one assessed domain (``scoped`` mode).

    Returns the updated usage (its ``warning_message`` says when the scope is
    over the priced figure), or None outside that mode. Never blocks anything.
    """
    policy = entitlement_policy(license_payload)
    if policy is None or policy.mode != MODE_SCOPED or count < 0:
        return None
    target = directory or _default_directory()
    clock_state_name = _default_clock_state_name()
    with state_file_lock(target):
        state = _load(target, clock_state_name)
        key = _normalize_dns(domain)
        state.identity_counts[key] = {
            "count": int(count),
            "at": _format_instant(_now(now)),
            "workspace": workspace,
            "identity_confirmed": bool(identity_confirmed),
        }
        state.identity_peaks[key] = max(state.identity_peaks.get(key, 0), int(count))
        state.identity_peak = max(state.identity_peak, _usage_from(state, license_payload, policy).used)
        _store(target, clock_state_name, state)
        return _usage_from(state, license_payload, policy)


def usage_report(license_payload: Any, *, directory: Path | None = None) -> dict[str, Any] | None:
    """The exportable usage report for renewal reviews (JSON-safe), or None."""
    usage = environment_usage(license_payload, directory=directory)
    if usage is None:
        return None
    report = usage.to_dict()
    report["license_id"] = getattr(license_payload, "license_id", "")
    report["customer"] = getattr(license_payload, "customer", "")
    report["generated_at"] = _format_instant(datetime.now(timezone.utc))
    return report


def admission_key(identity: ForestIdentity) -> str:
    """The ``admitted_as`` key an admission of ``identity`` records."""
    return _identity_key(identity)


__all__ = [
    "DECLARED_VIA_ASSESSMENT",
    "DECLARED_VIA_SETTINGS",
    "DECLARE_DIFFERENT_ORGANIZATION",
    "DECLARE_SAME_ORGANIZATION",
    "DEFAULT_MAX_DECLARED_FORESTS",
    "ENFORCED_FORMAT_VERSION",
    "ENVIRONMENT_ENTITLEMENT",
    "EntitlementError",
    "EntitlementPolicy",
    "EnvironmentAdmission",
    "EnvironmentUsage",
    "ForestIdentity",
    "INTEGRITY_OK",
    "INTEGRITY_RESTORED",
    "LEDGER_FILENAME",
    "MODE_ORGANIZATIONS",
    "MODE_SCOPED",
    "OUTCOME_ADMITTED",
    "OUTCOME_IN_SCOPE",
    "OUTCOME_JOINED",
    "OUTCOME_KNOWN",
    "OUTCOME_NOT_ENFORCED",
    "OUTCOME_REFUSED",
    "REASON_ENVIRONMENT_QUOTA",
    "REASON_LICENSE_STORAGE_UNAVAILABLE",
    "REASON_OUTSIDE_SCOPE",
    "REASON_WORKSPACE_ORGANIZATION",
    "SOURCE_CLDAP_CHILD",
    "SOURCE_CLDAP_ROOT",
    "SOURCE_NAME_ONLY",
    "ScopeEntry",
    "UNLIMITED",
    "admission_key",
    "admit_environment",
    "cap_label",
    "confirmed_trust_edges",
    "declaration_question",
    "declare_same_organization",
    "entitlement_policy",
    "environment_quota",
    "environment_usage",
    "normalize_guid",
    "parse_entitlement_policy",
    "record_identity_count",
    "state_file_lock",
    "usage_report",
]
