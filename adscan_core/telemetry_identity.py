"""Telemetry installation identity: one random id per installation.

**Why this exists.** Until 14.0.x the telemetry ``distinct_id`` was
``sha256(/etc/machine-id)[:12]``, and the launcher forwarded the HOST's value
into the container. A cloned or prebuilt VM image (a Kali VM download, a company
template) ships one machine-id to everybody who boots it, so different people
collapsed into one analytics "user": measured in PostHog over 90 days, one id
reported from 33 countries, 49 cities and 454 addresses. The hash was also an
unkeyed digest of a system identifier, where systemd asks applications to use an
app-specific keyed hash.

**The model now.**

1. A random ``installation_id`` (uuid4) is minted ONCE per installation and
   persisted in ``<state>/installation.json`` (host ``~/.adscan/state`` <->
   container ``/opt/adscan/state``; ``%LOCALAPPDATA%\\ADscan\\state`` for the
   Windows bundle). It is the telemetry ``distinct_id``. It survives ADscan
   updates, reboots and container restarts because nothing re-derives it.
2. Beside it the file keeps a FINGERPRINT of the machine: keyed hashes of the
   machine id, of each permanent physical MAC, and of the host name. When the
   fingerprint says this is a different machine (the state directory was cloned
   or copied), a NEW installation id is minted and the previous one is announced
   once, in an ``installation_identity_rotated`` event carrying
   ``previous_installation_id``. Clones diverge and people are never merged.
3. ``machine_hash`` (a keyed, app-specific hash of the machine id, truncated)
   is sent as an event property so analytics can count how many installations
   share one machine image. Never the raw machine id, never an unkeyed digest,
   and never the MAC or host name in any form: those stay in the local file.
4. The first run after the upgrade records the id 14.0.x would have used
   (``legacy_telemetry_id``) and announces it once on the rotation event and
   as a ``$set_once`` person property. The client NEVER emits ``$create_alias``:
   aliasing a legacy id that a shared image produced would merge every person
   behind it. ``scripts/telemetry_identity_backfill.py`` merges only the legacy
   ids exactly one installation claims, run deliberately by the founder.

**Which machine is fingerprinted.** Only a process running directly on the
machine: the host launcher, the Windows bundle, a source checkout. A container
(ADscan's runtime image, the web backend, any other) never fingerprints (it would see its own machine id and a veth MAC that changes
every run, and would rotate on every start); it receives the host's identity
through ``ADSCAN_TELEMETRY_ID`` / ``ADSCAN_TELEMETRY_MACHINE_HASH`` /
``ADSCAN_TELEMETRY_LEGACY_ID`` / ``ADSCAN_TELEMETRY_VIRTUALIZATION`` from the
launcher and never writes the file.

**The clone decision** (:func:`detect_rotation`) compares only components BOTH
sides have, so a component that is unreadable today is never evidence of a
clone: a different machine id rotates; otherwise disjoint permanent-MAC sets
rotate (a hypervisor gives a clone new MACs, while adding or removing one NIC
keeps an overlap); the host name is consulted only when no MAC can be compared
(macOS host names follow the network, so they never outrank hardware).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import socket
import threading
import time
import uuid
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

from adscan_core.path_utils import get_adscan_home, get_adscan_state_dir

__all__ = [
    "INSTALLATION_FILENAME",
    "LEGACY_ID_ENV",
    "MACHINE_HASH_ENV",
    "ROTATION_EVENT",
    "ROTATION_REASONS",
    "TELEMETRY_ID_ENV",
    "VIRTUALIZATION_ENV",
    "Fingerprint",
    "InstallationIdentity",
    "PendingAnnouncement",
    "collect_fingerprint",
    "current_installation_identity",
    "detect_rotation",
    "is_valid_installation_id",
    "is_valid_legacy_id",
    "keyed_machine_hash",
    "legacy_telemetry_id",
    "mark_rotation_announced",
    "reset_identity_cache",
    "resolve_installation_identity",
]

TELEMETRY_ID_ENV = "ADSCAN_TELEMETRY_ID"
MACHINE_HASH_ENV = "ADSCAN_TELEMETRY_MACHINE_HASH"
LEGACY_ID_ENV = "ADSCAN_TELEMETRY_LEGACY_ID"
VIRTUALIZATION_ENV = "ADSCAN_TELEMETRY_VIRTUALIZATION"

INSTALLATION_FILENAME = "installation.json"
_LOCK_FILENAME = "installation.lock"
_LEGACY_ID_FILENAME = "id"
_SCHEMA = 1

ROTATION_EVENT = "installation_identity_rotated"
#: Why an installation id was replaced. ``legacy_migration`` is the one-off
#: first run after the upgrade from the machine-id-derived id.
ROTATION_REASONS = frozenset(
    {"legacy_migration", "machine_id_changed", "hardware_changed", "hostname_changed"}
)

#: The fixed application key for every keyed hash. It is public (the source is
#: available) on purpose: what it buys is an APP-SPECIFIC value, as systemd
#: recommends for machine-id consumers, so our hash cannot be joined with any
#: other product's digest of the same id. The machine id itself is 128 random
#: bits, so the published key does not make it guessable.
_APP_KEY = b"adscan.telemetry.installation-identity.v1"

#: Length of the ``machine_hash`` sent as a property: 64 bits, enough to count
#: collisions, and below the 32-hex length the telemetry sanitizer pseudonymizes.
MACHINE_HASH_HEX_LEN = 16

_MACHINE_HASH_RE = re.compile(r"^[0-9a-f]{16}$")
_LEGACY_ID_RE = re.compile(r"^[0-9a-f]{12}$")
_INSTALLATION_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


def is_valid_installation_id(value: Any) -> bool:
    """Return whether ``value`` has the shape of an id this module mints."""

    return isinstance(value, str) and bool(_INSTALLATION_ID_RE.match(value))


def is_valid_legacy_id(value: Any) -> bool:
    """Return whether ``value`` has the 14.0.x id shape (12 lower-case hex)."""

    return isinstance(value, str) and bool(_LEGACY_ID_RE.match(value))


def _is_valid_previous_id(value: Any) -> bool:
    return is_valid_installation_id(value) or is_valid_legacy_id(value)


def _keyed(purpose: str, value: str) -> str:
    message = f"{purpose}\x00{value}".encode("utf-8", errors="replace")
    return hmac.new(_APP_KEY, message, hashlib.sha256).hexdigest()


def keyed_machine_hash(machine_id: str | None) -> str | None:
    """Return the telemetry ``machine_hash`` for a raw machine id."""

    if not machine_id:
        return None
    return _keyed("machine", machine_id.strip())[:MACHINE_HASH_HEX_LEN]


@dataclass(frozen=True)
class Fingerprint:
    """Keyed hashes describing one machine. Local only, never sent."""

    machine: Optional[str] = None
    macs: tuple[str, ...] = ()
    host: Optional[str] = None
    machine_hash: Optional[str] = None

    @property
    def empty(self) -> bool:
        return not (self.machine or self.macs or self.host)

    def to_json(self) -> dict[str, Any]:
        return {"machine": self.machine, "macs": list(self.macs), "host": self.host}

    @classmethod
    def from_json(cls, data: Any) -> "Fingerprint":
        if not isinstance(data, Mapping):
            return cls()
        machine = data.get("machine")
        host = data.get("host")
        macs = data.get("macs") or []
        return cls(
            machine=machine if isinstance(machine, str) and machine else None,
            macs=tuple(sorted(m for m in macs if isinstance(m, str) and m)),
            host=host if isinstance(host, str) and host else None,
        )


def collect_fingerprint() -> Fingerprint:
    """Fingerprint THIS machine through the PAL. Never raises."""

    from adscan_core.pal.machine import machine_identifier  # noqa: PLC0415
    from adscan_core.pal.net import hardware_mac_addresses  # noqa: PLC0415

    try:
        machine_id = machine_identifier()
    except Exception:  # noqa: BLE001
        machine_id = None
    try:
        macs = hardware_mac_addresses()
    except Exception:  # noqa: BLE001
        macs = []
    try:
        hostname = socket.gethostname().strip().lower().rstrip(".")
    except Exception:  # noqa: BLE001
        hostname = ""
    if hostname in {"", "localhost", "localhost.localdomain"}:
        hostname = ""
    return Fingerprint(
        machine=_keyed("machine", machine_id.strip()) if machine_id else None,
        macs=tuple(sorted({_keyed("mac", mac) for mac in macs})),
        host=_keyed("host", hostname) if hostname else None,
        machine_hash=keyed_machine_hash(machine_id),
    )


def detect_rotation(stored: Fingerprint, current: Fingerprint) -> Optional[str]:
    """Return the rotation reason when ``current`` is another machine, else ``None``.

    Only components present on BOTH sides are compared (see the module
    docstring for the order and why).
    """

    if stored.machine and current.machine and stored.machine != current.machine:
        return "machine_id_changed"
    if stored.macs and current.macs:
        if not set(stored.macs) & set(current.macs):
            return "hardware_changed"
        return None
    if stored.host and current.host and stored.host != current.host:
        return "hostname_changed"
    return None


def _merge_fingerprint(stored: Fingerprint, current: Fingerprint) -> Fingerprint:
    """Track legitimate drift: keep the current reading where one exists."""

    return Fingerprint(
        machine=current.machine or stored.machine,
        macs=current.macs or stored.macs,
        host=current.host or stored.host,
    )


@dataclass(frozen=True)
class PendingAnnouncement:
    """A rotation not yet announced to telemetry."""

    previous_installation_id: str
    reason: str
    legacy_telemetry_id: Optional[str] = None

    def to_json(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "previous_installation_id": self.previous_installation_id,
            "reason": self.reason,
        }
        if self.legacy_telemetry_id:
            data["legacy_telemetry_id"] = self.legacy_telemetry_id
        return data

    @classmethod
    def from_json(cls, data: Any) -> Optional["PendingAnnouncement"]:
        if not isinstance(data, Mapping):
            return None
        previous = data.get("previous_installation_id")
        reason = data.get("reason")
        legacy = data.get("legacy_telemetry_id")
        if not _is_valid_previous_id(previous) or reason not in ROTATION_REASONS:
            return None
        return cls(
            previous_installation_id=previous,
            reason=reason,
            legacy_telemetry_id=legacy if is_valid_legacy_id(legacy) else None,
        )


@dataclass(frozen=True)
class InstallationIdentity:
    """The resolved identity for this process."""

    installation_id: str
    machine_hash: Optional[str] = None
    legacy_telemetry_id: Optional[str] = None
    virtualization: Optional[str] = None
    #: False when the state directory could not be written: the id lives only
    #: for this process, and telemetry says so.
    persisted: bool = True
    #: True when the identity came from the launcher (container) or an operator
    #: override, so this process neither fingerprints nor writes the file.
    forwarded: bool = False
    pending: Optional[PendingAnnouncement] = None
    state_dir: Optional[Path] = field(default=None, compare=False)


def _new_installation_id() -> str:
    return str(uuid.uuid4())


def legacy_telemetry_id(home: Path | None = None) -> Optional[str]:
    """Return the id 14.0.x used on this machine, computed the way it did.

    14.0.x read ``<ADSCAN_HOME>/id`` when present, else
    ``sha256(/etc/machine-id)[:12]`` (and wrote that into the file). This
    mirrors it byte for byte, including reading ``/etc/machine-id`` directly
    rather than through the PAL, because the point is to reproduce the old
    value, not a better one. Windows had no ``/etc/machine-id``, so there the
    old id only ever lived in the file.
    """

    base = home if home is not None else get_adscan_home()
    try:
        stored = (base / _LEGACY_ID_FILENAME).read_text(encoding="utf-8").strip()
    except OSError:
        stored = ""
    if is_valid_legacy_id(stored):
        return stored
    try:
        raw = Path("/etc/machine-id").read_text(encoding="utf-8").strip()
    except OSError:
        raw = ""
    if raw:
        return hashlib.sha256(raw.encode()).hexdigest()[:12]
    return None


def _read_state(path: Path) -> Optional[dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not is_valid_installation_id(data.get("installation_id")):
        return None
    return data


def _write_state(path: Path, data: dict[str, Any]) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        try:
            # World-readable on purpose: nothing in it is secret (a random id
            # and keyed hashes), and a file a ``sudo`` run wrote must stay
            # readable to the next unprivileged run, or that run would mint a
            # second identity.
            os.chmod(tmp, 0o644)
        except OSError:
            pass
        os.replace(tmp, path)
        return True
    except OSError:
        return False


class _StateLock:
    """Best-effort cross-process lock around the read-modify-write."""

    def __init__(self, state_dir: Path) -> None:
        self._path = state_dir / _LOCK_FILENAME
        self._handle = None

    def __enter__(self) -> "_StateLock":
        try:
            from adscan_core.pal.filelock import acquire_file_lock  # noqa: PLC0415

            self._handle = acquire_file_lock(self._path, blocking=True, timeout=5.0)
        except Exception:  # noqa: BLE001 - no lock is better than no identity
            self._handle = None
        return self

    def __exit__(self, *_exc: object) -> None:
        if self._handle is not None:
            try:
                from adscan_core.pal.filelock import release_file_lock  # noqa: PLC0415

                release_file_lock(self._handle)
            except Exception:  # noqa: BLE001
                pass


def _state_document(
    installation_id: str,
    fingerprint: Fingerprint,
    *,
    created_at: Optional[str],
    legacy: Optional[str],
    pending: Optional[PendingAnnouncement],
    previous: Optional[str],
) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "schema": _SCHEMA,
        "installation_id": installation_id,
        "created_at": created_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "fingerprint": fingerprint.to_json(),
    }
    if legacy:
        doc["legacy_telemetry_id"] = legacy
    if previous:
        doc["previous_installation_id"] = previous
    if pending:
        doc["pending_announcement"] = pending.to_json()
    return doc


def _forwarded_identity(environ: Mapping[str, str]) -> Optional[InstallationIdentity]:
    override = str(environ.get(TELEMETRY_ID_ENV, "") or "").strip()
    if not override:
        return None
    machine_hash = str(environ.get(MACHINE_HASH_ENV, "") or "").strip().lower()
    legacy = str(environ.get(LEGACY_ID_ENV, "") or "").strip().lower()
    virt = str(environ.get(VIRTUALIZATION_ENV, "") or "").strip().lower()
    from adscan_core.pal.machine import VIRTUALIZATION_VALUES  # noqa: PLC0415

    return InstallationIdentity(
        installation_id=override,
        machine_hash=machine_hash if _MACHINE_HASH_RE.match(machine_hash) else None,
        legacy_telemetry_id=legacy if is_valid_legacy_id(legacy) else None,
        virtualization=virt if virt in VIRTUALIZATION_VALUES else None,
        forwarded=True,
    )


def resolve_installation_identity(
    *,
    state_dir: Path | None = None,
    home: Path | None = None,
    environ: Mapping[str, str] | None = None,
    fingerprint_provider: Callable[[], Fingerprint] = collect_fingerprint,
    legacy_provider: Callable[[Path | None], Optional[str]] = legacy_telemetry_id,
    virtualization_provider: Callable[[], str] | None = None,
    new_id: Callable[[], str] = _new_installation_id,
) -> InstallationIdentity:
    """Resolve (and persist) this installation's identity. Never raises.

    See the module docstring for the model. The keyword arguments are seams for
    tests; production calls it with none.
    """

    env = os.environ if environ is None else environ
    forwarded = _forwarded_identity(env)
    if forwarded is not None:
        return forwarded

    if virtualization_provider is None:
        from adscan_core.pal.machine import virtualization  # noqa: PLC0415

        virtualization_provider = virtualization
    try:
        virt = virtualization_provider()
    except Exception:  # noqa: BLE001
        virt = "unknown"

    # Any container, not only ADscan's runtime image: the web backend and its
    # workers import telemetry too. A container's machine id, veth MAC and
    # hostname say nothing about the machine and change on every recreation,
    # so fingerprinting one would rotate the id on every restart.
    in_container = env.get("ADSCAN_CONTAINER_RUNTIME") == "1" or virt == "container"
    directory = state_dir if state_dir is not None else get_adscan_state_dir()
    path = directory / INSTALLATION_FILENAME
    try:
        current = Fingerprint() if in_container else fingerprint_provider()
    except Exception:  # noqa: BLE001
        current = Fingerprint()

    with _StateLock(directory):
        stored_doc = _read_state(path)
        if stored_doc is not None:
            stored_id = stored_doc["installation_id"]
            stored_fp = Fingerprint.from_json(stored_doc.get("fingerprint"))
            legacy = stored_doc.get("legacy_telemetry_id")
            legacy = legacy if is_valid_legacy_id(legacy) else None
            pending = PendingAnnouncement.from_json(stored_doc.get("pending_announcement"))
            reason = None if current.empty else detect_rotation(stored_fp, current)
            if reason is not None:
                minted = new_id()
                announcement = PendingAnnouncement(
                    previous_installation_id=stored_id, reason=reason
                )
                doc = _state_document(
                    minted,
                    current,
                    created_at=None,
                    legacy=None,
                    pending=announcement,
                    previous=stored_id,
                )
                persisted = _write_state(path, doc)
                return InstallationIdentity(
                    installation_id=minted,
                    machine_hash=current.machine_hash,
                    virtualization=virt,
                    persisted=persisted,
                    pending=announcement if persisted else None,
                    state_dir=directory,
                )
            merged = _merge_fingerprint(stored_fp, current)
            if merged != stored_fp:
                stored_doc["fingerprint"] = merged.to_json()
                _write_state(path, stored_doc)
            return InstallationIdentity(
                installation_id=stored_id,
                machine_hash=current.machine_hash,
                legacy_telemetry_id=legacy,
                virtualization=virt,
                pending=pending,
                state_dir=directory,
            )

        # First run of this release on this installation.
        minted = new_id()
        legacy = None
        if not in_container:
            try:
                legacy = legacy_provider(home)
            except Exception:  # noqa: BLE001
                legacy = None
            legacy = legacy if is_valid_legacy_id(legacy) else None
        announcement = (
            PendingAnnouncement(
                previous_installation_id=legacy,
                reason="legacy_migration",
                legacy_telemetry_id=legacy,
            )
            if legacy
            else None
        )
        doc = _state_document(
            minted, current, created_at=None, legacy=legacy, pending=announcement, previous=None
        )
        persisted = _write_state(path, doc)
        if persisted and not in_container:
            _retire_legacy_id_file(home)
        return InstallationIdentity(
            installation_id=minted,
            machine_hash=current.machine_hash,
            legacy_telemetry_id=legacy,
            virtualization=virt,
            persisted=persisted,
            pending=announcement if persisted else None,
            state_dir=directory,
        )


def _retire_legacy_id_file(home: Path | None) -> None:
    """Delete ``<ADSCAN_HOME>/id`` once its value is recorded in the new file.

    Nothing reads it any more, and leaving a second identity file beside the
    real one invites a future reader to pick the wrong one. Its value is kept
    as ``legacy_telemetry_id`` in ``installation.json``, so nothing is lost.
    """

    base = home if home is not None else get_adscan_home()
    try:
        (base / _LEGACY_ID_FILENAME).unlink()
    except OSError:
        pass


def mark_rotation_announced(identity: InstallationIdentity) -> InstallationIdentity:
    """Clear the persisted pending announcement once the event was queued."""

    if identity.pending is None or identity.state_dir is None or identity.forwarded:
        return replace(identity, pending=None)
    path = identity.state_dir / INSTALLATION_FILENAME
    with _StateLock(identity.state_dir):
        doc = _read_state(path)
        if doc is not None and doc.get("installation_id") == identity.installation_id:
            doc.pop("pending_announcement", None)
            _write_state(path, doc)
    return replace(identity, pending=None)


_CACHE_LOCK = threading.Lock()
_CACHED: Optional[InstallationIdentity] = None


def current_installation_identity() -> InstallationIdentity:
    """Process-wide memo of :func:`resolve_installation_identity`."""

    global _CACHED
    with _CACHE_LOCK:
        if _CACHED is None:
            try:
                _CACHED = resolve_installation_identity()
            except Exception:  # noqa: BLE001 - telemetry identity must never break a run
                _CACHED = InstallationIdentity(
                    installation_id=_new_installation_id(), persisted=False
                )
        return _CACHED


def _set_cached_identity(identity: InstallationIdentity) -> None:
    global _CACHED
    with _CACHE_LOCK:
        _CACHED = identity


def reset_identity_cache() -> None:
    """Forget the memo (tests)."""

    _set_cached_identity(None)  # type: ignore[arg-type]
