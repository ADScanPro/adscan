"""Secret values never live in attack-graph notes: a reference does.

``attack_graph.json`` is a ``finding`` artifact. The web ingests its edge notes
into ``attack_graph_edges.properties``, the report projects them into attack-path
steps, and the node-link egress classes it as redaction-required. Several writers
used to put the recovered secret itself into those notes: the password a spray
accepted, the password read from a share or a GPP file, the hash a credential
dump returned, the credential shared by a reuse cluster. This module is the one
place that decides what a secret-bearing note field is and what replaces it.

What replaces the value, per field, under ``notes["secret_refs"][<field>]``:

* ``kind``: ``password``, ``nt_hash``, ``lm_hash`` or ``aes_key``.
* ``store`` / ``domain`` / ``username`` / ``host``: the identity the credential
  store keys the secret by (``add_credential``: domain + username, plus host for
  a local credential), so a consumer that needs the value resolves it there.
* ``fingerprint``: HMAC-SHA256 under a per-workspace key that never leaves the
  node (:data:`GRAPH_SECRET_KEY_FILENAME`, an egress ``secret`` file). Equal
  fingerprints mean the same secret, which is what reuse metrics and the
  "one foothold per secret" grouping need. It is never a bare hash, so it cannot
  be looked up in a precomputed table. Empty when no key is available.

plus ``notes["secret_recovered"] = True`` and a human ``notes["secret_marker"]``
("Password recovered by password spraying") that a UI or a report can show.

The value is RETAINED, never discarded (owner decision 2026-11-03, see
``docs/superpowers/specs/2026-11-03-engagement-state-and-reverification-design.md``):
the engine writes it to the per-domain sidecar :data:`GRAPH_SECRET_SIDECAR_FILENAME`
keyed by fingerprint (also an egress ``secret`` file) before the graph is
written. The operator terminal still prints the cleartext at capture time.

Reading:

* :func:`resolve_note_secret` returns the value for a note: a legacy inline value
  first (old workspaces keep working), then the resolver the engine injects with
  :func:`set_note_secret_resolver` (sidecar, then credential store). Empty when
  nothing resolves, which is the web's case by construction.
* :func:`note_has_recovered_secret` answers "was a secret recovered here"
  without the value, for a "[redacted]" marker.
* :func:`note_secret_identity` gives a value-free equality key.

Stdlib only: imported by the engine, the web backend and the node service.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets as _secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

#: Note fields whose value IS a secret. Matched case-sensitively on the exact key
#: the writers use. ``credential`` is the reuse-cluster field (its sibling
#: ``credential_type`` says password or hash and is kept).
SECRET_NOTE_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "secret",
        "plaintext",
        "cleartext",
        "cleartext_password",
        "cpassword",
        "nt_hash",
        "nthash",
        "ntlm_hash",
        "ntlm",
        "lm_hash",
        "aes_key",
        "aes128_key",
        "aes256_key",
        "credential",
        "gmsa_password",
        "laps_password",
    }
)

SECRET_REFS_KEY = "secret_refs"
SECRET_RECOVERED_KEY = "secret_recovered"
SECRET_MARKER_KEY = "secret_marker"

#: Per-workspace HMAC key, at the workspace root. Egress class ``secret``
#: (``**/*.key`` and ``**/*secret*``): it never leaves the node.
GRAPH_SECRET_KEY_FILENAME = ".graph_secret_fingerprint.key"
#: Per-domain retention of the values the graph references, beside
#: ``attack_graph.json``. Egress class ``secret`` (``**/*secret*``).
GRAPH_SECRET_SIDECAR_FILENAME = "attack_graph_secrets.json"

_FINGERPRINT_HEX_LEN = 32
_KEY_BYTES = 32
_HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_HEX_PAIR = re.compile(r"^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$")

_KIND_LABELS = {
    "password": "Password",
    "nt_hash": "NT hash",
    "lm_hash": "LM hash",
    "aes_key": "Kerberos AES key",
}

#: How the secret was obtained, by relation (lowercase), for the marker.
_RELATION_ORIGIN = {
    "passwordspray": "by password spraying",
    "useraspass": "by password spraying (username as password)",
    "computerpre2k": "from a pre-Windows 2000 computer default",
    "passwordinshare": "from a file share",
    "passwordinfile": "from a file on a host",
    "gpppassword": "from Group Policy Preferences",
    "gppautologin": "from Group Policy Preferences",
    "userdescription": "from a directory description attribute",
    "dumplsa": "from a credential dump",
    "dumpsam": "from a credential dump",
    "dumplsass": "from a credential dump",
    "dumpdpapi": "from a credential dump",
    "domainpassreuse": "and shared by several accounts",
    "domainpassreusesource": "and shared by several accounts",
    "localadminpassreuse": "and shared by several local administrators",
    "localcredreusesource": "and shared by several local administrators",
    "localcredtodomainreuse": "and reused by a domain account",
}

_LOCAL_RELATIONS = frozenset(
    {"localadminpassreuse", "localcredreusesource", "localcredtodomainreuse"}
)


@dataclass(frozen=True)
class ExtractedSecret:
    """One secret value removed from a note, with the reference that replaced it."""

    field: str
    value: str
    kind: str
    fingerprint: str
    ref: dict[str, str]
    relation: str = ""


# ── fingerprint ──────────────────────────────────────────────────────────────
def fingerprint_secret(value: Any, key: bytes | None) -> str:
    """Return the keyed fingerprint of *value*, or ``""`` without a key.

    HMAC-SHA256 over the exact value, truncated to 128 bits. Never falls back to
    an unkeyed hash: a bare SHA-256 of a sprayed password is a dictionary lookup.
    """
    text = str(value or "")
    if not text or not key:
        return ""
    digest = hmac.new(key, text.encode("utf-8", "replace"), hashlib.sha256)
    return digest.hexdigest()[:_FINGERPRINT_HEX_LEN]


def workspace_root_for_graph_path(graph_path: str | os.PathLike[str]) -> Path:
    """Return the workspace root of ``<root>/domains/<domain>/attack_graph.json``."""
    path = Path(graph_path)
    domain_dir = path.parent
    if domain_dir.parent.name == "domains":
        return domain_dir.parent.parent
    return domain_dir


def read_fingerprint_key(workspace_root: str | os.PathLike[str]) -> bytes | None:
    """Return the workspace's fingerprint key when it exists. Never creates it."""
    key_path = Path(workspace_root) / GRAPH_SECRET_KEY_FILENAME
    try:
        data = key_path.read_bytes()
    except OSError:
        return None
    return data if len(data) >= 16 else None


def ensure_fingerprint_key(workspace_root: str | os.PathLike[str]) -> bytes | None:
    """Return the workspace's fingerprint key, creating it (mode 0600) if absent.

    Returns ``None`` when the workspace is not writable; the caller then redacts
    without a fingerprint rather than keeping the value inline.
    """
    existing = read_fingerprint_key(workspace_root)
    if existing:
        return existing
    root = Path(workspace_root)
    key_path = root / GRAPH_SECRET_KEY_FILENAME
    try:
        root.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return read_fingerprint_key(workspace_root)
    except OSError:
        return None
    key = _secrets.token_bytes(_KEY_BYTES)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(key)
    except OSError:
        return None
    return key


# ── classification ───────────────────────────────────────────────────────────
def secret_kind_for_field(field: str, value: str, notes: Mapping[str, Any] | None = None) -> str:
    """Return the kind of secret a note field holds."""
    field_key = str(field or "").strip().lower()
    if field_key in {"nt_hash", "nthash", "ntlm_hash", "ntlm"}:
        return "nt_hash"
    if field_key == "lm_hash":
        return "lm_hash"
    if field_key.startswith("aes"):
        return "aes_key"
    if field_key in {"secret", "credential"}:
        declared = ""
        if isinstance(notes, Mapping):
            declared = str(
                notes.get("credential_type") or notes.get("secret_kind") or ""
            ).strip().lower()
        if declared in {"hash", "nt_hash", "nthash", "ntlm"}:
            return "nt_hash"
        if declared in {"aes", "aes_key", "aes256", "aes128"}:
            return "aes_key"
        text = str(value or "").strip()
        if _HEX32.match(text) or _HEX_PAIR.match(text):
            return "nt_hash"
        if _HEX64.match(text):
            return "aes_key"
    return "password"


def secret_marker(kind: str, relation: str = "") -> str:
    """Return the client-safe sentence that stands in for a recovered secret."""
    label = _KIND_LABELS.get(str(kind or "").strip().lower(), "Credential")
    origin = _RELATION_ORIGIN.get(str(relation or "").strip().lower(), "")
    return f"{label} recovered {origin}".strip() if origin else f"{label} recovered"


def _inline_secret_fields(notes: Mapping[str, Any]) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for field in sorted(SECRET_NOTE_KEYS):
        value = notes.get(field)
        if isinstance(value, str) and value.strip():
            found.append((field, value))
        elif value is not None and not isinstance(value, (str, bool, dict, list)):
            text = str(value).strip()
            if text:
                found.append((field, text))
    return found


def notes_carry_inline_secret(notes: Any) -> bool:
    """True when *notes* still holds a secret value inline."""
    return isinstance(notes, Mapping) and bool(_inline_secret_fields(notes))


# ── redaction ────────────────────────────────────────────────────────────────
def redact_note_secrets(
    notes: Mapping[str, Any] | None,
    *,
    key: bytes | None = None,
    domain: str = "",
    username: str = "",
    host: str = "",
    relation: str = "",
) -> tuple[dict[str, Any], list[ExtractedSecret]]:
    """Return a copy of *notes* with every secret value replaced by a reference.

    Existing references are kept; a field present inline AND as a reference is
    re-referenced from the inline value (it is the newer capture).
    """
    if not isinstance(notes, Mapping):
        return {}, []
    out: dict[str, Any] = dict(notes)
    inline = _inline_secret_fields(out)
    if not inline:
        return out, []
    existing_refs = out.get(SECRET_REFS_KEY)
    refs: dict[str, Any] = dict(existing_refs) if isinstance(existing_refs, Mapping) else {}
    relation_key = str(relation or "").strip().lower()
    store = "local_credentials" if relation_key in _LOCAL_RELATIONS else "domain_credentials"
    principal = str(
        username
        or out.get("username")
        or out.get("credential_username")
        or out.get("local_admin_username")
        or out.get("source_username")
        or ""
    ).strip()
    extracted: list[ExtractedSecret] = []
    kinds: list[str] = []
    for field, value in inline:
        kind = secret_kind_for_field(field, value, out)
        fingerprint = fingerprint_secret(value, key)
        ref = {
            "kind": kind,
            "store": store,
            "domain": str(domain or "").strip().lower(),
            "username": principal,
            "host": str(host or "").strip(),
            "fingerprint": fingerprint,
        }
        refs[field] = ref
        out.pop(field, None)
        kinds.append(kind)
        extracted.append(
            ExtractedSecret(
                field=field,
                value=value,
                kind=kind,
                fingerprint=fingerprint,
                ref=dict(ref),
                relation=relation_key,
            )
        )
    out[SECRET_REFS_KEY] = refs
    out[SECRET_RECOVERED_KEY] = True
    out[SECRET_MARKER_KEY] = secret_marker(kinds[0], relation_key)
    return out, extracted


def _node_username(node: Any) -> str:
    if not isinstance(node, Mapping):
        return ""
    props = node.get("properties") if isinstance(node.get("properties"), Mapping) else {}
    for candidate in (
        props.get("samaccountname"),
        node.get("samaccountname"),
        node.get("label"),
        props.get("name"),
        node.get("name"),
    ):
        text = str(candidate or "").strip()
        if text:
            return text.split("@", 1)[0]
    return ""


def redact_graph_secrets(
    graph: Any, *, key: bytes | None = None, domain: str = ""
) -> list[ExtractedSecret]:
    """Redact every edge's notes in *graph* IN PLACE; return what was removed."""
    if not isinstance(graph, dict):
        return []
    edges = graph.get("edges")
    if not isinstance(edges, list):
        return []
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), Mapping) else {}
    graph_domain = str(domain or graph.get("domain") or "").strip().lower()
    extracted: list[ExtractedSecret] = []
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        notes = edge.get("notes")
        if not notes_carry_inline_secret(notes):
            continue
        target_user = _node_username(nodes.get(str(edge.get("to") or "")))
        redacted, found = redact_note_secrets(
            notes,
            key=key,
            domain=graph_domain,
            username=str(
                notes.get("username")
                or notes.get("credential_username")
                or notes.get("local_admin_username")
                or target_user
            ),
            relation=str(edge.get("relation") or ""),
        )
        edge["notes"] = redacted
        extracted.extend(found)
    return extracted


def redact_secrets_deep(obj: Any) -> Any:
    """Return *obj* with every mapping that holds an inline secret redacted.

    For projections whose structure is not fixed (an attack-path snapshot, step
    details stored by an older build). No key: references carry no fingerprint.
    """
    if isinstance(obj, Mapping):
        walked = {k: redact_secrets_deep(v) for k, v in obj.items()}
        if notes_carry_inline_secret(walked):
            walked, _ = redact_note_secrets(walked)
        return walked
    if isinstance(obj, list):
        return [redact_secrets_deep(item) for item in obj]
    if isinstance(obj, tuple):
        return tuple(redact_secrets_deep(item) for item in obj)
    return obj


# ── retention sidecar ────────────────────────────────────────────────────────
def sidecar_path_for_graph(graph_path: str | os.PathLike[str]) -> Path:
    """Return the retention sidecar beside an ``attack_graph.json``."""
    return Path(graph_path).with_name(GRAPH_SECRET_SIDECAR_FILENAME)


def read_secret_sidecar(path: str | os.PathLike[str]) -> dict[str, dict[str, Any]]:
    """Return ``{fingerprint: record}`` from a sidecar, ``{}`` when absent."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError):
        return {}
    secrets_map = payload.get("secrets") if isinstance(payload, dict) else None
    if not isinstance(secrets_map, dict):
        return {}
    return {str(k): v for k, v in secrets_map.items() if isinstance(v, dict)}


def retain_extracted_secrets(
    path: str | os.PathLike[str], extracted: Iterable[ExtractedSecret]
) -> bool:
    """Persist extracted values in the sidecar keyed by fingerprint (mode 0600).

    Returns True when every extracted value is retained. A value without a
    fingerprint cannot be keyed and makes this return False.
    """
    items = list(extracted)
    if not items:
        return True
    current = read_secret_sidecar(path)
    complete = True
    changed = False
    for item in items:
        if not item.fingerprint:
            complete = False
            continue
        record = {
            "value": item.value,
            "kind": item.kind,
            "field": item.field,
            "relation": item.relation,
            "domain": item.ref.get("domain", ""),
            "username": item.ref.get("username", ""),
        }
        if current.get(item.fingerprint) != record:
            current[item.fingerprint] = record
            changed = True
    if not changed:
        return complete
    target = Path(path)
    tmp = target.with_name(f".{target.name}.tmp")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump({"schema_version": 1, "secrets": current}, handle, indent=2, sort_keys=True)
        os.replace(tmp, target)
    except OSError:
        return False
    return complete


# ── reading ──────────────────────────────────────────────────────────────────
NoteSecretResolver = Callable[[Mapping[str, Any], str], "str | None"]
_RESOLVER: NoteSecretResolver | None = None


def set_note_secret_resolver(resolver: NoteSecretResolver | None) -> None:
    """Install (or clear) the engine's resolver for referenced secrets."""
    global _RESOLVER  # noqa: PLW0603
    _RESOLVER = resolver


def note_secret_ref(notes: Any, field: str) -> dict[str, Any] | None:
    """Return the reference recorded for *field*, if any."""
    if not isinstance(notes, Mapping):
        return None
    refs = notes.get(SECRET_REFS_KEY)
    if not isinstance(refs, Mapping):
        return None
    ref = refs.get(field)
    return dict(ref) if isinstance(ref, Mapping) else None


def note_has_recovered_secret(notes: Any, *fields: str) -> bool:
    """True when *notes* records a recovered secret (inline or referenced)."""
    if not isinstance(notes, Mapping):
        return False
    wanted = fields or tuple(SECRET_NOTE_KEYS)
    for field in wanted:
        value = notes.get(field)
        if isinstance(value, str) and value.strip():
            return True
        if note_secret_ref(notes, field):
            return True
    return False


def note_secret_identity(notes: Any, *fields: str) -> str:
    """Return a value-free equality key for the secret in *notes*.

    The fingerprint when referenced; for a legacy inline value only its own
    in-memory identity, never written anywhere.
    """
    if not isinstance(notes, Mapping):
        return ""
    for field in fields or tuple(sorted(SECRET_NOTE_KEYS)):
        ref = note_secret_ref(notes, field)
        if ref and ref.get("fingerprint"):
            return f"fp:{ref['fingerprint']}"
        value = notes.get(field)
        if isinstance(value, str) and value.strip():
            return f"inline:{value.strip()}"
    return ""


def resolve_note_secret(notes: Any, *fields: str) -> str:
    """Return the secret for the first of *fields* that resolves, else ``""``."""
    if not isinstance(notes, Mapping):
        return ""
    for field in fields or tuple(sorted(SECRET_NOTE_KEYS)):
        value = notes.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if note_secret_ref(notes, field) and _RESOLVER is not None:
            try:
                resolved = _RESOLVER(notes, field)
            except Exception:  # noqa: BLE001 — a display/read path never raises here
                resolved = None
            if resolved:
                return str(resolved)
    return ""


#: What a renderer shows when a secret was recovered but is not resolvable in
#: this process (the web, a report run without a credential store).
REFERENCED_SECRET_DISPLAY = "recovered (held in the credential store)"

#: Set on a note by the workspace secret purge
#: (``adscan_core.workspace_secret_purge``): the value was recovered, and was
#: later removed from the workspace on purpose, so "held in the credential
#: store" is no longer true and a renderer must say so.
SECRET_REMOVED_KEY = "secret_removed"
REMOVED_SECRET_DISPLAY = "recovered (removed from this workspace after the assessment)"


def referenced_secret_display(notes: Any) -> str:
    """What a renderer shows for a recovered secret it cannot resolve.

    The store phrase while the workspace still holds the value; the removal
    phrase once the secret purge has run, so a report rendered after the purge
    never claims a credential is still held.
    """
    if isinstance(notes, Mapping) and notes.get(SECRET_REMOVED_KEY) is True:
        return REMOVED_SECRET_DISPLAY
    return REFERENCED_SECRET_DISPLAY


def secret_for_display(notes: Any, *fields: str) -> tuple[str, bool]:
    """Return ``(value, recovered)`` for a renderer.

    ``value`` is the cleartext when it resolves (legacy inline, or the engine's
    resolver); ``recovered`` is True whenever *notes* records a secret for one of
    *fields*, so a renderer can say so without the value.
    """
    value = resolve_note_secret(notes, *fields)
    return value, bool(value) or note_has_recovered_secret(notes, *fields)


__all__ = [
    "REFERENCED_SECRET_DISPLAY",
    "REMOVED_SECRET_DISPLAY",
    "SECRET_REMOVED_KEY",
    "referenced_secret_display",
    "secret_for_display",
    "GRAPH_SECRET_KEY_FILENAME",
    "GRAPH_SECRET_SIDECAR_FILENAME",
    "SECRET_MARKER_KEY",
    "SECRET_NOTE_KEYS",
    "SECRET_RECOVERED_KEY",
    "SECRET_REFS_KEY",
    "ExtractedSecret",
    "ensure_fingerprint_key",
    "fingerprint_secret",
    "note_has_recovered_secret",
    "note_secret_identity",
    "note_secret_ref",
    "notes_carry_inline_secret",
    "read_fingerprint_key",
    "read_secret_sidecar",
    "redact_graph_secrets",
    "redact_note_secrets",
    "redact_secrets_deep",
    "resolve_note_secret",
    "retain_extracted_secrets",
    "secret_kind_for_field",
    "secret_marker",
    "set_note_secret_resolver",
    "sidecar_path_for_graph",
    "workspace_root_for_graph_path",
]
