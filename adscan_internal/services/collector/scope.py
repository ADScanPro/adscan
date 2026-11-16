"""Scope persistence for native collector runs."""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Literal, Mapping

if TYPE_CHECKING:
    from adscan_internal.services.collector.orchestrator import DomainScope

DomainStatus = Literal[
    "reachable_ldap",
    "reachable_kerberos",
    "dns_only",
    "unreachable",
    "degraded",
]


@dataclass(frozen=True)
class ScopeEntry:
    """One domain candidate discovered during trust scope selection."""

    domain: str
    dc_address: str
    auth_domain: str
    auth_kdc: str
    reachability: DomainStatus
    in_scope: bool
    kerberos_target_hostname: str | None = None
    degraded_reason: str | None = None
    trust_type: str | None = None
    trust_direction: str | None = None

    def to_domain_scope(self) -> "DomainScope":
        """Convert this entry into a collector DomainScope."""
        from adscan_internal.services.collector.orchestrator import DomainScope

        return DomainScope(
            domain=self.domain,
            dc_address=self.dc_address,
            auth_domain=self.auth_domain,
            auth_kdc=self.auth_kdc,
            kerberos_target_hostname=self.kerberos_target_hostname,
        )


@dataclass
class ScopeResult:
    """Persisted scope selection for a workspace run."""

    entries: list[ScopeEntry] = field(default_factory=list)
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def in_scope_domains(self) -> list[str]:
        """Return selected domains in the original selection order."""
        return [entry.domain for entry in self.entries if entry.in_scope]

    def to_domain_scopes(self) -> list["DomainScope"]:
        """Return collector scopes for selected entries."""
        return [entry.to_domain_scope() for entry in self.entries if entry.in_scope]


def save_scope(
    result: ScopeResult, path: str, *, extra: Mapping[str, Any] | None = None
) -> None:
    """Write a ScopeResult JSON artifact to disk.

    ``extra`` carries the engagement-scope record
    (``services.engagement_scope``): the origin domains, who decided the scope,
    the cross-domain steps it kept from running and the asset scope
    (``asset_scope``). ``scope.json`` is an output-contract file
    (``adscan_core/engagement/output_formats.py``, ``engagement_scope``): the
    marker comes from the registry, and readers of an older minor ignore the
    keys they do not know.
    """
    from adscan_core.engagement.output_formats import output_marker  # noqa: PLC0415

    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    payload: dict[str, Any] = {
        "schema_version": output_marker("engagement_scope"),
        "generated_at": result.generated_at,
        "entries": [asdict(entry) for entry in result.entries],
    }
    for key, value in (extra or {}).items():
        if key not in payload:
            payload[key] = value
    # Write to a temporary file in the same directory and rename it over the
    # target: a crash mid-write leaves the previous file intact, never a
    # truncated one (an unreadable scope.json makes the engine fail closed).
    directory = os.path.dirname(os.path.abspath(path))
    # Created like a plain open() would (0666 less the process umask), under a
    # name nothing else uses: the operator's umask decides who reads the file,
    # and a file that already exists keeps the mode it has.
    temp_path = os.path.join(directory, f".scope.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    handle = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as file:
            json.dump(payload, file, indent=2)
            file.flush()
            os.fsync(file.fileno())
        try:
            os.chmod(temp_path, os.stat(path).st_mode & 0o777)
        except OSError:
            pass  # no earlier file: the mode the umask gave stands
        os.replace(temp_path, path)
    except BaseException:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise


def load_scope_payload(path: str) -> dict[str, Any] | None:
    """The raw ``scope.json`` mapping (with the engagement-scope keys), or None."""
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as file:
            payload = json.load(file)
    except Exception:  # noqa: BLE001 - an unreadable file discloses nothing
        return None
    return payload if isinstance(payload, dict) else None


def load_scope(path: str) -> ScopeResult | None:
    """Load a ScopeResult from disk, returning None for missing or invalid files."""
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as file:
            payload = json.load(file)
        entries = [ScopeEntry(**entry) for entry in payload.get("entries", [])]
        return ScopeResult(
            entries=entries,
            generated_at=str(payload.get("generated_at") or ""),
        )
    except Exception:
        return None
