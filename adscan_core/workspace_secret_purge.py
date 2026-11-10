"""Remove every recovered secret from one workspace and keep its history.

An assessor runs the same client again months later and compares: which
findings closed, which attack paths still exist. That comparison needs the
findings, the attack graph, the engagement ledger and the reports. It does not
need the passwords, hashes, keys, tickets and certificates the assessment
recovered, and a laptop that keeps a year of them from many organizations is a
liability. This module removes them and leaves the history in place.

What one purge does, in order:

1. **Collects the recorded secrets** before touching anything: every value in the
   credential store of every domain (passwords, NT hashes, Kerberos keys, local
   credentials), the graph's retention sidecar, and the secret-class files that
   hold recovered values (dumps, cracked lists, harvested credentials).
2. **Clears the credential store** in ``variables.json`` (and the per-domain
   snapshot beside each domain): the credential, metadata, Kerberos key, ticket,
   service-ticket, local-credential and capability-ticket stores, and the
   domain-level and top-level password fields. The domain context (DCs, base DN,
   compromise state, the domain list) stays. With ``keep_starting_credential``
   the scan's own starting credential is kept, and nothing else.
3. **Deletes the secret-class files** named by the egress classification
   (:mod:`adscan_core.node_link.artifact_classes`, the one list of what a secret
   file is): tickets, keys, certificates, dumps, cracking files, loot, caches,
   the graph's retention sidecar and its fingerprint key, the operator history.
   Three exceptions are rewritten instead, because the history needs their
   other content: the two ``variables.json`` files (step 2) and the per-user
   password-age table, whose name matches a secret rule but whose content holds
   no secret. Logs are emptied IN PLACE, so a session that still has the file
   open keeps writing to it.
4. **Scrubs everything that remains.** Every other file is searched for every
   recorded value. A JSON file has the value replaced inside its strings (the
   structure the report and the console read is unchanged); the attack graph
   also has any inline note secret turned into a reference; plain text has the
   value replaced; a binary file that holds one is deleted when no rule says the
   history needs it, and is reported otherwise.
5. **Marks what was removed.** Every graph note that records a recovered secret
   gets ``secret_removed: true``, so a report rendered later says the value was
   removed instead of "held in the credential store".
6. **Records the purge** in ``purge_record.json`` and, when the workspace has an
   engagement ledger, in its metadata: when, by whom, from which surface, and
   the counts.

What it does NOT do, stated so nobody has to infer it:

* A rendered deliverable (PDF, DOCX, HTML) is never edited. It is listed in the
  result, and deleted only when the caller asks (``delete_deliverables``).
* A secret equal to an identifier the history needs (an account whose password
  is its own name) cannot be told apart from that name; it stays wherever the
  name appears, and the result counts how many such values there were.
* A secret shorter than :data:`MIN_SUBSTRING_SECRET_LENGTH` characters is
  replaced only where it is a whole value, never inside longer text, so a short
  password cannot destroy unrelated words. The result counts these too.
* Only values the workspace RECORDED can be searched for. A secret that never
  reached the store (a candidate typed at a prompt and rejected) is found only
  if it sits in a file the purge deletes or empties anyway.
* Copies outside the workspace (a report e-mailed, a file copied elsewhere) are
  out of reach.

Refused while a scan of the workspace is running: an execution workspace
(``.run_<name>_<scanid>``) that is still being written, or a lock held by
another run. Finished execution workspaces are full copies of the engagement,
so they are purged the same way, never deleted (a failed promotion leaves the
only intact copy there).

Stdlib only: the engine and the web backend call the same function.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

from adscan_core.credential_origins import NON_COMPROMISE_ORIGINS
from adscan_core.graph_secret_refs import (
    SECRET_NOTE_KEYS,
    SECRET_RECOVERED_KEY,
    SECRET_REFS_KEY,
    SECRET_REMOVED_KEY,
    GRAPH_SECRET_SIDECAR_FILENAME,
    redact_graph_secrets,
    redact_secrets_deep,
)
from adscan_core.node_link.artifact_classes import ArtifactClass, classify

#: What replaces a removed value inside a string. No brackets: a report string
#: can reach a Rich-rendered sink, where ``[...]`` is markup.
REMOVED_MARKER = "(removed)"
PURGE_RECORD_FILENAME = "purge_record.json"
PURGE_RECORD_SCHEMA = "adscan.secret_purge/1"
ENGAGEMENT_META_KEY = "secret_purges"
#: Below this length a value is replaced only where it is a whole string.
MIN_SUBSTRING_SECRET_LENGTH = 6
#: A file larger than this is not searched; the result names it.
MAX_SCAN_BYTES = 512 * 1024 * 1024

#: What the web platform stores in place of a credential's dedup hash once the
#: secret is removed. The hash was an unsalted SHA-256 of the value, which a
#: dictionary reverses for a password, so it cannot stay. A later scan that
#: sees the same account again adopts its new hash without calling it rotated.
PURGED_CREDENTIAL_HASH_PREFIX = "purged:"

SURFACE_CLI = "cli"
SURFACE_WEB = "web"

#: Secret-classed by name, rewritten instead of deleted (see module docstring).
_SCRUB_NOT_DELETE = (
    "variables.json",
    "domains/*/variables.json",
    "domains/*/inventory/password_compliance.json",
)
_VARIABLES_FILES = ("variables.json", "domains/*/variables.json")
_LOG_PREFIX = "logs/"
_NEVER_TOUCH = (PURGE_RECORD_FILENAME, "engagement/engagement.sqlite*")
_DELIVERABLE_DIRS = ("deliverables/", "reports/")
_DELIVERABLE_SUFFIXES = (".pdf", ".docx", ".pptx", ".xlsx")
_RENDERED_SUFFIXES = (".pdf", ".docx", ".pptx", ".xlsx", ".html", ".htm")

#: Per-domain stores the purge empties.
_DOMAIN_STORES = (
    "credentials",
    "credentials_meta",
    "kerberos_keys",
    "kerberos_tickets",
    "service_tickets",
    "local_credentials",
    "capability_bearing_ccache",
    "rejected_secret_candidates",
    "compromised_credentials",
    "post_ex_credentials",
)
#: Per-domain scalar fields that hold a secret (or point at a ticket file).
_DOMAIN_SECRET_FIELDS = (
    "password",
    "hash",
    "nt_hash",
    "aes_key",
    "ccache",
    "ccache_path",
    "unauth_description_creds_preview",
)
#: Workspace-level fields that hold the active session secret.
_TOP_SECRET_FIELDS = ("password", "hash", "nt_hash", "aes_key", "ccache_path")

#: Keys whose value is a secret inside a secret-class JSON file.
_HARVEST_KEYS = frozenset(SECRET_NOTE_KEYS) | {
    "hash",
    "lm_hash",
    "aes128",
    "aes256",
    "aes_key",
    "des",
    "rc4",
    "value",
    "raw_value",
    "plaintext_password",
}
_KEY_MATERIAL_FIELDS = frozenset(
    {"nt_hash", "lm_hash", "aes128", "aes256", "aes128_key", "aes256_key", "aes_key", "des", "rc4",
     "password", "secret"}
)
#: Well-known constants, not secrets: the empty LM and NT hashes.
_NOT_SECRETS = frozenset({"aad3b435b51404eeaad3b435b51404ee", "31d6cfe0d16ae931b73c59d7e0c089c0"})
_HEX_RE = re.compile(r"^[0-9a-fA-F:]+$")
_PREVIEW_RE = re.compile(r"(?:→|->)\s*(.+?)\s*(?:\([^()]*\))?\s*$")


class PurgeRefused(RuntimeError):
    """The purge did not start; ``reason`` says why (nothing was touched)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class PurgeOptions:
    """Caller choices. The defaults remove the most."""

    #: Keep the credential the scan was started with (origin ``authenticated_scan``
    #: or ``user_provided``). Everything the assessment recovered still goes.
    keep_starting_credential: bool = False
    #: Delete the rendered deliverables too (they cannot be edited, only listed).
    delete_deliverables: bool = False
    #: The caller is the session that holds this workspace's lock (the REPL).
    allow_own_lock: bool = False


@dataclass
class RecordedSecrets:
    """The values the workspace recorded, and the ones the purge must keep."""

    values: set[str] = field(default_factory=set)
    kept: set[str] = field(default_factory=set)
    identifiers: set[str] = field(default_factory=set)


@dataclass
class PurgeResult:
    """What one purge did. Every path is workspace-relative."""

    workspace: str = ""
    files_deleted: list[str] = field(default_factory=list)
    files_rewritten: list[str] = field(default_factory=list)
    logs_cleared: list[str] = field(default_factory=list)
    store_entries_removed: int = 0
    kept_starting_credentials: int = 0
    secrets_removed: int = 0
    secrets_not_substituted: dict[str, int] = field(default_factory=dict)
    remaining: list[dict[str, str]] = field(default_factory=list)
    deliverables: list[str] = field(default_factory=list)
    deliverables_deleted: list[str] = field(default_factory=list)
    execution_workspaces_purged: list[str] = field(default_factory=list)
    #: ``{domain: [principal, ...]}`` whose stored credential was removed.
    removed_principals: dict[str, list[str]] = field(default_factory=dict)
    record: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ── matching ────────────────────────────────────────────────────────────────
@dataclass
class SecretMatcher:
    """Finds recorded secret values in text, longest value first."""

    long_pattern: Optional[re.Pattern[str]]
    short_values: frozenset[str]
    short_hex_values: frozenset[str]
    count: int
    skipped: dict[str, int]

    @classmethod
    def build(cls, values: Iterable[str], *, identifiers: Iterable[str]) -> "SecretMatcher":
        """Compile the matcher, leaving out values that would destroy history."""
        idents = {str(i).strip().casefold() for i in identifiers if str(i).strip()}
        skipped: dict[str, int] = {}
        long_values: list[str] = []
        short: set[str] = set()
        short_hex: set[str] = set()
        for raw in sorted({str(v) for v in values if v}):
            value = raw.strip()
            if not value or value.lower() in _NOT_SECRETS:
                continue
            if value.casefold() in idents:
                skipped["equals_an_identifier"] = skipped.get("equals_an_identifier", 0) + 1
                continue
            if len(value) >= MIN_SUBSTRING_SECRET_LENGTH:
                long_values.append(value)
            elif _HEX_RE.match(value):
                short_hex.add(value.lower())
            else:
                short.add(value)
        if short or short_hex:
            skipped["shorter_than_minimum_replaced_whole_only"] = len(short) + len(short_hex)
        pattern = None
        if long_values:
            parts = []
            for value in sorted(long_values, key=len, reverse=True):
                escaped = re.escape(value)
                parts.append(f"(?i:{escaped})" if _HEX_RE.match(value) else escaped)
            pattern = re.compile("|".join(parts))
        return cls(
            long_pattern=pattern,
            short_values=frozenset(short),
            short_hex_values=frozenset(short_hex),
            count=len(long_values) + len(short) + len(short_hex),
            skipped=skipped,
        )

    def sub(self, text: str) -> tuple[str, int]:
        """Return ``text`` with every recorded value replaced, and the count."""
        stripped = text.strip()
        if stripped and (stripped in self.short_values or stripped.lower() in self.short_hex_values):
            return REMOVED_MARKER, 1
        if self.long_pattern is None:
            return text, 0
        return self.long_pattern.subn(REMOVED_MARKER, text)

    def search_bytes(self, data: bytes) -> bool:
        """Whether ``data`` holds a long recorded value (UTF-8 or UTF-16LE)."""
        if self.long_pattern is None:
            return False
        text = data.decode("utf-8", errors="ignore")
        if self.long_pattern.search(text):
            return True
        if b"\x00" in data:
            return bool(self.long_pattern.search(data.decode("utf-16-le", errors="ignore")))
        return False


def scrub_document(obj: Any, matcher: SecretMatcher) -> tuple[Any, int]:
    """Return ``obj`` with every recorded value removed from its strings and keys."""
    if isinstance(obj, str):
        return matcher.sub(obj)
    if isinstance(obj, Mapping):
        out: dict[Any, Any] = {}
        hits = 0
        for key, value in obj.items():
            new_key, key_hits = matcher.sub(key) if isinstance(key, str) else (key, 0)
            new_value, value_hits = scrub_document(value, matcher)
            out[new_key] = new_value
            hits += key_hits + value_hits
        return out, hits
    if isinstance(obj, list):
        items = [scrub_document(item, matcher) for item in obj]
        return [item for item, _ in items], sum(h for _, h in items)
    return obj, 0


def mark_removed_deep(obj: Any) -> int:
    """Set ``secret_removed`` on every mapping that records a recovered secret."""
    count = 0
    if isinstance(obj, dict):
        if SECRET_REFS_KEY in obj or obj.get(SECRET_RECOVERED_KEY) is True:
            if obj.get(SECRET_REMOVED_KEY) is not True:
                obj[SECRET_REMOVED_KEY] = True
                count += 1
        for value in obj.values():
            count += mark_removed_deep(value)
    elif isinstance(obj, list):
        for item in obj:
            count += mark_removed_deep(item)
    return count


# ── collection ──────────────────────────────────────────────────────────────
def _read_json(path: Path) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


def _matches(relpath: str, patterns: Iterable[str]) -> bool:
    segments = relpath.split("/")
    for pattern in patterns:
        parts = pattern.split("/")
        if len(parts) == len(segments) and all(fnmatchcase(s, p) for s, p in zip(segments, parts)):
            return True
    return False


def _add(values: set[str], value: Any) -> None:
    if isinstance(value, str):
        text = value.strip()
        if text and not text.lower().endswith((".ccache", ".kirbi")):
            values.add(text)


def _harvest_leaves(obj: Any, values: set[str]) -> None:
    if isinstance(obj, Mapping):
        for value in obj.values():
            _harvest_leaves(value, values)
    elif isinstance(obj, list):
        for item in obj:
            _harvest_leaves(item, values)
    else:
        _add(values, obj)


def _harvest_keyed(obj: Any, values: set[str], keys: frozenset[str]) -> None:
    if isinstance(obj, Mapping):
        for key, value in obj.items():
            if str(key).lower() in keys and isinstance(value, (str, int)) and not isinstance(value, bool):
                _add(values, str(value))
            elif str(key).lower() == "kerberos_keys" and isinstance(value, list):
                for pair in value:
                    if isinstance(pair, (list, tuple)) and len(pair) == 2:
                        _add(values, pair[1])
            else:
                _harvest_keyed(value, values, keys)
    elif isinstance(obj, list):
        for item in obj:
            _harvest_keyed(item, values, keys)


def _domain_entries(variables: Mapping[str, Any]) -> list[dict[str, Any]]:
    data = variables.get("domains_data")
    if not isinstance(data, Mapping):
        return []
    return [entry for entry in data.values() if isinstance(entry, dict)]


def _starting_users(entry: Mapping[str, Any]) -> set[str]:
    meta = entry.get("credentials_meta")
    if not isinstance(meta, Mapping):
        return set()
    return {
        str(user)
        for user, record in meta.items()
        if isinstance(record, Mapping)
        and str(record.get("credential_origin") or "").strip().lower() in NON_COMPROMISE_ORIGINS
    }


def _store_values(variables: Mapping[str, Any]) -> tuple[set[str], set[str]]:
    """Return ``(all secret values, the starting credentials' values)``."""
    values: set[str] = set()
    starting: set[str] = set()
    for key in _TOP_SECRET_FIELDS:
        _add(values, variables.get(key))
    for entry in _domain_entries(variables):
        starters = {u.casefold() for u in _starting_users(entry)}
        creds = entry.get("credentials")
        if isinstance(creds, Mapping):
            for user, secret in creds.items():
                _add(values, secret)
                if str(user).casefold() in starters:
                    _add(starting, secret)
        meta = entry.get("credentials_meta")
        if isinstance(meta, Mapping):
            for user, record in meta.items():
                bucket: set[str] = set()
                _harvest_keyed(record, bucket, _KEY_MATERIAL_FIELDS | {"aes128_key", "aes256_key"})
                values |= bucket
                if str(user).casefold() in starters:
                    starting |= bucket
        keys = entry.get("kerberos_keys")
        if isinstance(keys, Mapping):
            for user, record in keys.items():
                bucket = set()
                _harvest_keyed(record, bucket, _KEY_MATERIAL_FIELDS)
                values |= bucket
                if str(user).casefold() in starters:
                    starting |= bucket
        for store in ("local_credentials", "rejected_secret_candidates", "compromised_credentials",
                      "post_ex_credentials"):
            _harvest_leaves(entry.get(store), values)
        for key in ("password", "hash", "nt_hash", "aes_key"):
            _add(values, entry.get(key))
        if str(entry.get("username") or "").casefold() in starters:
            for key in ("password", "hash", "nt_hash", "aes_key"):
                _add(starting, entry.get(key))
        preview = entry.get("unauth_description_creds_preview")
        if isinstance(preview, str):
            for line in preview.splitlines():
                match = _PREVIEW_RE.search(line)
                if match:
                    _add(values, match.group(1))
    if isinstance(variables.get("username"), str):
        for entry in _domain_entries(variables):
            if variables["username"].casefold() in {u.casefold() for u in _starting_users(entry)}:
                for key in _TOP_SECRET_FIELDS:
                    _add(starting, variables.get(key))
    return values, starting


def _identifiers(root: Path, variables: Mapping[str, Any]) -> set[str]:
    idents: set[str] = set()
    for name in variables.get("domains") or []:
        _add(idents, name)
    for domain, entry in (variables.get("domains_data") or {}).items():
        _add(idents, domain)
        if not isinstance(entry, Mapping):
            continue
        for key in ("username", "netbios", "pdc_hostname", "dc_fqdn", "pdc_fqdn"):
            _add(idents, entry.get(key))
        for store in ("credentials", "credentials_meta", "kerberos_keys", "kerberos_tickets"):
            bucket = entry.get(store)
            if isinstance(bucket, Mapping):
                for user in bucket:
                    _add(idents, str(user))
                    _add(idents, str(user).rstrip("$"))
    _add(idents, variables.get("username"))
    for listing in ("enabled_users.txt", "users.txt", "enabled_computers.txt"):
        for path in [root / listing, *root.glob(f"domains/*/{listing}")]:
            try:
                for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()[:200000]:
                    _add(idents, line)
                    _add(idents, line.split(".", 1)[0])
            except OSError:
                continue
    return idents


def _secret_file_values(root: Path) -> set[str]:
    values: set[str] = set()
    for path in _walk(root):
        relpath = path.relative_to(root).as_posix()
        if classify(relpath) is not ArtifactClass.SECRET or _matches(relpath, _VARIABLES_FILES):
            continue
        if relpath.startswith(_LOG_PREFIX):
            continue
        name = path.name.lower()
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > 64 * 1024 * 1024:
            continue
        if name == GRAPH_SECRET_SIDECAR_FILENAME:
            payload = _read_json(path)
            for record in (payload or {}).get("secrets", {}).values() if isinstance(payload, dict) else []:
                if isinstance(record, Mapping):
                    _add(values, record.get("value"))
        elif name.endswith(".json"):
            _harvest_keyed(_read_json(path), values, _HARVEST_KEYS)
        elif name.startswith("hashes."):
            # One captured hash (roasted ticket, AS-REP, NetNTLM) per line.
            try:
                for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                    _add(values, line)
            except OSError:
                continue
        elif name.startswith(("cracked_", "nt_hashes_")) or name.endswith((".pot", ".potfile")):
            try:
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            for line in lines:
                if ":" in line:
                    _add(values, line.rsplit(":", 1)[1])
    return values


def collect_recorded_secrets(
    workspace_dir: str | os.PathLike[str], *, keep_starting_credential: bool = False
) -> RecordedSecrets:
    """Every secret value one workspace recorded, read before anything changes."""
    root = Path(workspace_dir)
    recorded = RecordedSecrets()
    for relpath in ("variables.json", *[p.relative_to(root).as_posix() for p in root.glob("domains/*/variables.json")]):
        variables = _read_json(root / relpath)
        if not isinstance(variables, dict):
            continue
        values, starting = _store_values(variables)
        recorded.values |= values
        if keep_starting_credential:
            recorded.kept |= starting
        if relpath == "variables.json":
            recorded.identifiers |= _identifiers(root, variables)
    recorded.values |= _secret_file_values(root)
    return recorded


# ── the credential store ────────────────────────────────────────────────────
@dataclass
class StoreClearing:
    """What :func:`clear_credential_store` removed from one document."""

    entries_removed: int = 0
    starting_kept: int = 0
    #: ``{domain: [principal, ...]}`` whose credential (or key, ticket) was
    #: removed. Names only: a later re-test says a route it could not walk
    #: started from one of these.
    principals: dict[str, list[str]] = field(default_factory=dict)


def clear_credential_store(variables: dict[str, Any], *, keep_starting_credential: bool = False) -> StoreClearing:
    """Empty the credential stores of a ``variables.json`` document IN PLACE.

    The domain context (controllers, base DN, compromise state, the domain list)
    is left alone.
    """
    removed = 0
    kept = 0
    principals: dict[str, list[str]] = {}
    top_user = str(variables.get("username") or "")
    keep_top = False
    data = variables.get("domains_data")
    domain_items = [(str(d), e) for d, e in data.items() if isinstance(e, dict)] if isinstance(data, Mapping) else []
    for domain, entry in domain_items:
        names: set[str] = set()
        for store in ("credentials", "credentials_meta", "kerberos_keys", "kerberos_tickets",
                      "capability_bearing_ccache"):
            bucket = entry.get(store)
            if isinstance(bucket, Mapping):
                names.update(str(k) for k in bucket)
        starters = _starting_users(entry) if keep_starting_credential else set()
        folded = {u.casefold() for u in starters}
        if top_user and top_user.casefold() in folded:
            keep_top = True
        for store in _DOMAIN_STORES:
            bucket = entry.get(store)
            if isinstance(bucket, dict):
                keep = {k: v for k, v in bucket.items() if str(k).casefold() in folded
                        and store in ("credentials", "credentials_meta")}
                removed += len(bucket) - len(keep)
                kept += len(keep) if store == "credentials" else 0
                if keep:
                    entry[store] = keep
                else:
                    entry.pop(store, None)
            elif isinstance(bucket, list):
                removed += len(bucket)
                entry.pop(store, None)
            elif store in entry:
                entry.pop(store, None)
        keep_domain_login = str(entry.get("username") or "").casefold() in folded
        for key in _DOMAIN_SECRET_FIELDS:
            if key in entry and not (keep_domain_login and key in ("password", "hash", "nt_hash", "aes_key")):
                entry.pop(key, None)
                removed += 1
        removed_names = sorted(n for n in names if n.casefold() not in folded)
        if removed_names:
            principals[domain] = removed_names
    if not keep_top:
        for key in _TOP_SECRET_FIELDS:
            if variables.pop(key, None) is not None:
                removed += 1
    return StoreClearing(entries_removed=removed, starting_kept=kept, principals=principals)


# ── files ───────────────────────────────────────────────────────────────────
def _walk(root: Path) -> list[Path]:
    found: list[Path] = []
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        base = Path(current)
        for name in sorted(filenames):
            path = base / name
            if not path.is_symlink() and path.is_file():
                found.append(path)
    return found


def _is_deliverable(relpath: str) -> bool:
    lowered = relpath.lower()
    if lowered.startswith(_DELIVERABLE_DIRS):
        return lowered.endswith(_RENDERED_SUFFIXES)
    return lowered.endswith(_DELIVERABLE_SUFFIXES)


def find_rendered_deliverables(workspace_dir: str | os.PathLike[str]) -> list[str]:
    """Rendered documents in a workspace (they cannot be edited, only removed)."""
    root = Path(workspace_dir)
    return [p.relative_to(root).as_posix() for p in _walk(root) if _is_deliverable(p.relative_to(root).as_posix())]


def _json_indent(text: str) -> Optional[int]:
    lines = text.split("\n", 2)
    if len(lines) < 2:
        return None
    second = lines[1]
    return (len(second) - len(second.lstrip(" "))) or None


def _atomic_write(path: Path, text: str) -> None:
    mode = None
    try:
        mode = path.stat().st_mode & 0o777
    except OSError:
        pass
    tmp = path.with_name(f".{path.name}.purge.{os.getpid()}")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode or 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.replace(tmp, path)


def _dump(obj: Any, original: str) -> str:
    return json.dumps(obj, indent=_json_indent(original), ensure_ascii=False)


def _rewrite_json(
    path: Path, relpath: str, matcher: SecretMatcher, *, keep_starting: bool
) -> tuple[bool, StoreClearing]:
    """Returns ``(changed, what the store clearing removed)``; raises ValueError."""
    original = path.read_text(encoding="utf-8")
    doc = json.loads(original)
    before = json.loads(original)
    clearing = StoreClearing()
    if _matches(relpath, _VARIABLES_FILES) and isinstance(doc, dict):
        clearing = clear_credential_store(doc, keep_starting_credential=keep_starting)
        if relpath != "variables.json":
            for key in ("password", "hash", "nt_hash", "aes_key"):
                doc.pop(key, None)
    if path.name.startswith("attack_graph.json") and isinstance(doc, dict):
        redact_graph_secrets(doc)
    elif path.name.startswith("attack_paths_snapshot"):
        doc = redact_secrets_deep(doc)
    mark_removed_deep(doc)
    doc, _hits = scrub_document(doc, matcher)
    if doc == before:
        return False, clearing
    _atomic_write(path, _dump(doc, original))
    return True, clearing


def _rewrite_text(path: Path, matcher: SecretMatcher) -> bool:
    original = path.read_text(encoding="utf-8")
    if path.suffix == ".jsonl":
        lines = []
        for line in original.splitlines(keepends=True):
            body = line.rstrip("\n")
            try:
                obj = json.loads(body)
            except ValueError:
                new, _ = matcher.sub(body)
            else:
                mark_removed_deep(obj)
                scrubbed, _ = scrub_document(obj, matcher)
                new = json.dumps(scrubbed, ensure_ascii=False)
            lines.append(new + ("\n" if line.endswith("\n") else ""))
        text = "".join(lines)
    else:
        text, _ = matcher.sub(original)
    if text == original:
        return False
    _atomic_write(path, text)
    return True


def _purge_tree(
    root: Path,
    matcher: SecretMatcher,
    options: PurgeOptions,
    result: PurgeResult,
    *,
    prefix: str = "",
) -> None:
    for path in _walk(root):
        relpath = path.relative_to(root).as_posix()
        shown = f"{prefix}{relpath}"
        if _matches(relpath, _NEVER_TOUCH) or relpath.startswith("engagement/engagement.sqlite"):
            continue
        artifact_class = classify(relpath)
        try:
            if _is_deliverable(relpath):
                result.deliverables.append(shown)
                if options.delete_deliverables:
                    path.unlink()
                    result.deliverables_deleted.append(shown)
                continue
            if relpath.startswith(_LOG_PREFIX):
                if path.stat().st_size:
                    os.truncate(path, 0)
                    result.logs_cleared.append(shown)
                continue
            if artifact_class is ArtifactClass.SECRET and not _matches(relpath, _SCRUB_NOT_DELETE):
                path.unlink()
                result.files_deleted.append(shown)
                continue
            size = path.stat().st_size
            if size > MAX_SCAN_BYTES:
                result.remaining.append({"path": shown, "reason": "too_large_to_search"})
                continue
            if path.suffix == ".json" or path.name.startswith("attack_graph.json"):
                try:
                    changed, clearing = _rewrite_json(
                        path, relpath, matcher, keep_starting=options.keep_starting_credential
                    )
                except (ValueError, UnicodeDecodeError):
                    changed, clearing = None, StoreClearing()
                if changed is not None:
                    result.store_entries_removed += clearing.entries_removed
                    if relpath == "variables.json":
                        result.kept_starting_credentials += clearing.starting_kept
                        for domain, names in clearing.principals.items():
                            merged = set(result.removed_principals.get(domain, [])) | set(names)
                            result.removed_principals[domain] = sorted(merged)
                    if changed:
                        result.files_rewritten.append(shown)
                    continue
            data = path.read_bytes()
            if not matcher.search_bytes(data):
                continue
            try:
                data.decode("utf-8")
                is_text = b"\x00" not in data
            except UnicodeDecodeError:
                is_text = False
            if is_text:
                if _rewrite_text(path, matcher):
                    result.files_rewritten.append(shown)
                continue
            if artifact_class in (ArtifactClass.FINDING, ArtifactClass.EVIDENCE, ArtifactClass.SUMMARY):
                result.remaining.append({"path": shown, "reason": "binary_file_kept_for_history"})
            else:
                path.unlink()
                result.files_deleted.append(shown)
        except OSError as exc:
            result.remaining.append({"path": shown, "reason": f"unreadable: {exc.__class__.__name__}"})


# ── refusal ─────────────────────────────────────────────────────────────────
def _running_scan_reason(
    workspace_name: str, workspaces_dir: Optional[Path], *, allow_own_lock: bool
) -> tuple[Optional[str], list[Any]]:
    from adscan_core.execution_workspace import (  # noqa: PLC0415
        execution_workspace_is_quiescent,
        execution_workspaces_for,
    )
    from adscan_core.workspace_locks import workspace_lock_is_held  # noqa: PLC0415

    if not allow_own_lock:
        try:
            if workspace_lock_is_held(workspace_name):
                return "a scan or session is using this workspace", []
        except Exception:  # noqa: BLE001 - an unreadable lock is not a licence to proceed
            return "the workspace lock could not be read", []
    entries = execution_workspaces_for(workspaces_dir, workspace_name) if workspaces_dir else []
    for entry in entries:
        if not execution_workspace_is_quiescent(entry):
            return "a scan of this workspace is still running", []
    return None, entries


# ── record ──────────────────────────────────────────────────────────────────
def read_purge_records(workspace_dir: str | os.PathLike[str]) -> list[dict[str, Any]]:
    """The purges recorded for a workspace, oldest first (empty when none)."""
    payload = _read_json(Path(workspace_dir) / PURGE_RECORD_FILENAME)
    if isinstance(payload, dict) and isinstance(payload.get("purges"), list):
        return [p for p in payload["purges"] if isinstance(p, dict)]
    return []


def _write_record(root: Path, record: dict[str, Any]) -> None:
    records = read_purge_records(root) + [record]
    _atomic_write(
        root / PURGE_RECORD_FILENAME,
        json.dumps({"schema": PURGE_RECORD_SCHEMA, "purges": records}, indent=2, ensure_ascii=False),
    )


def _write_engagement_meta(root: Path, record: dict[str, Any]) -> bool:
    from adscan_core.engagement.store import open_store, store_path  # noqa: PLC0415

    path = store_path(root)
    if not Path(path).exists():
        return False
    store = open_store(path)
    try:
        current = store.get_meta(ENGAGEMENT_META_KEY)
        try:
            history = json.loads(current) if current else []
        except ValueError:
            history = []
        if not isinstance(history, list):
            history = []
        history.append(record)
        store.set_meta(ENGAGEMENT_META_KEY, json.dumps(history, sort_keys=True))
    finally:
        store.close()
    return True


def removed_credential_principals(workspace_dir: str | os.PathLike[str]) -> dict[str, set[str]]:
    """``{domain (lower-case): {principal (case-folded), ...}}`` every purge removed.

    A re-test reads this to say why it could not walk a route: the credential
    the route started from was removed on purpose, not refused by the client.
    """
    out: dict[str, set[str]] = {}
    for record in read_purge_records(workspace_dir):
        principals = record.get("removed_principals")
        if not isinstance(principals, Mapping):
            continue
        for domain, names in principals.items():
            if isinstance(names, list):
                out.setdefault(str(domain).lower(), set()).update(str(n).casefold() for n in names)
    return out


# ── entry point ─────────────────────────────────────────────────────────────
def purge_workspace_secrets(
    workspace_dir: str | os.PathLike[str],
    *,
    operator: str,
    surface: str,
    options: Optional[PurgeOptions] = None,
    workspaces_dir: Optional[str | os.PathLike[str]] = None,
    extra_secrets: Iterable[str] = (),
) -> PurgeResult:
    """Remove every recorded secret from one workspace; see the module docstring.

    Args:
        workspace_dir: The logical workspace directory.
        operator: Who asked, as it will be recorded (never empty).
        surface: :data:`SURFACE_CLI` or :data:`SURFACE_WEB`.
        options: What to keep and what else to remove.
        workspaces_dir: Where the workspace's execution workspaces live
            (defaults to the workspace's parent directory).
        extra_secrets: Values the caller holds that the workspace may not
            (the web passes none today; kept for a caller that does).

    Raises:
        PurgeRefused: a scan is running, or no operator was given.
    """
    options = options or PurgeOptions()
    root = Path(workspace_dir)
    if not str(operator or "").strip():
        raise PurgeRefused("no operator name was given")
    if not root.is_dir():
        raise PurgeRefused("the workspace does not exist")
    parent = Path(workspaces_dir) if workspaces_dir else root.parent
    reason, executions = _running_scan_reason(root.name, parent, allow_own_lock=options.allow_own_lock)
    if reason:
        raise PurgeRefused(reason)

    recorded = collect_recorded_secrets(root, keep_starting_credential=options.keep_starting_credential)
    for entry in executions:
        extra = collect_recorded_secrets(entry.path, keep_starting_credential=options.keep_starting_credential)
        recorded.values |= extra.values
        recorded.kept |= extra.kept
    recorded.values |= {str(v) for v in extra_secrets if v}
    matcher = SecretMatcher.build(recorded.values - recorded.kept, identifiers=recorded.identifiers)

    result = PurgeResult(workspace=root.name)
    result.secrets_removed = matcher.count
    result.secrets_not_substituted = dict(matcher.skipped)
    _purge_tree(root, matcher, options, result)
    for entry in executions:
        _purge_tree(entry.path, matcher, options, result, prefix=f"{entry.name}/")
        result.execution_workspaces_purged.append(entry.name)

    record = {
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        # The host's wall clock; ADscan may have stepped it to a DC during an
        # earlier scan, so it is not claimed to be any verified frame.
        "at_frame": "unverified",
        "by": str(operator).strip(),
        "surface": surface,
        "kept_starting_credential": bool(options.keep_starting_credential),
        "files_deleted": len(result.files_deleted),
        "files_rewritten": len(result.files_rewritten),
        "logs_cleared": len(result.logs_cleared),
        "store_entries_removed": result.store_entries_removed,
        "secrets_removed": result.secrets_removed,
        "secrets_not_substituted": dict(result.secrets_not_substituted),
        "deliverables_listed": len(result.deliverables),
        "deliverables_deleted": len(result.deliverables_deleted),
        "execution_workspaces_purged": len(result.execution_workspaces_purged),
        "remaining": len(result.remaining),
        "removed_principals": {d: list(n) for d, n in result.removed_principals.items()},
    }
    _write_record(root, record)
    try:
        record["engagement_ledger"] = _write_engagement_meta(root, record)
    except Exception:  # noqa: BLE001 - the workspace record above is the primary one
        record["engagement_ledger"] = False
    result.record = record
    return result


__all__ = [
    "ENGAGEMENT_META_KEY",
    "MIN_SUBSTRING_SECRET_LENGTH",
    "PURGED_CREDENTIAL_HASH_PREFIX",
    "PURGE_RECORD_FILENAME",
    "REMOVED_MARKER",
    "SURFACE_CLI",
    "SURFACE_WEB",
    "PurgeOptions",
    "PurgeRefused",
    "PurgeResult",
    "RecordedSecrets",
    "SecretMatcher",
    "StoreClearing",
    "clear_credential_store",
    "mark_removed_deep",
    "removed_credential_principals",
    "collect_recorded_secrets",
    "find_rendered_deliverables",
    "purge_workspace_secrets",
    "read_purge_records",
    "scrub_document",
]
