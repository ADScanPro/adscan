"""Egress classification of every artifact an engine run writes.

Each workspace-relative path is classified ONCE, here, as one of:

* ``summary``: identifier-free counts, ratios and lifecycle only
  (``run_summary.json``, nothing else). Leaves under every data policy.
* ``finding``: findings, attack paths, the asset inventory, rendered reports,
  and the run documents that name objects (``scan_summary.json``,
  ``coverage.json``, the manifest). Leaves under ``findings`` and ``full``.
* ``evidence``: saved command output and collected configuration (scan output,
  share listings). Leaves under ``full`` only.
* ``secret``: credentials, hashes, tickets, keys, captured material, logs and
  the operator's history. Never leaves, under any policy.

A path no rule covers is UNLISTED (:func:`classify` returns ``None``) and never
leaves either, so the registry is fail-closed: a new artifact stays on the node
until someone decides its class. ``tests/unit/core/node_link/
test_artifact_classes_cover_ingestion.py`` extracts every artifact name the web
ingestion reads and fails if one is unclassified, so the other direction (a
file the console needs that silently stops arriving) is closed too.

Rules are ordered and the FIRST match wins; every ``secret`` rule comes before
any other, so a secret-shaped name under a findings directory still reads as
secret. Patterns are matched per path segment (``*`` never crosses a ``/``;
``**`` matches any number of segments).

Whether a file may leave is decided in ONE place, :func:`may_leave`
(``refuse`` | ``as_is`` | ``after_redaction``), from its class, the data
policy and the content audit (:data:`REDACTION_REQUIRED`). There is no second
predicate for a caller to disagree with.

The manifest's SHA-256 is over the file AS WRITTEN, before any redaction, and is
recorded only for summary, finding and evidence files (never for a secret or
unlisted file, whose digest could be a crackable hash). An egress filter that
redacts a file sends different bytes, so it must re-hash exactly what it sends
and report that digest, never the manifest's.

TODO(Phase D, egress filter): ``deliverables/**`` (rendered PDFs and HTML)
cannot be field-redacted. The intended clearance is the known-secret scanner
over the text layer extracted from each document (plain, hex, base64 and
UTF-16LE forms of every secret the node holds); a hit refuses that document and
reports ``egress_blocked``. Not implemented here.

Stdlib only: the node service and the console import this module.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timezone
from enum import Enum
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Iterator, Optional

ARTIFACT_MANIFEST_FILENAME = "artifact_manifest.json"

#: Largest file the manifest hashes (bytes) and the total hashing time budget
#: (seconds, monotonic) at the end of a run.
MAX_HASH_BYTES = 256 * 1024 * 1024
HASH_BUDGET_SECONDS = 60.0
UNLISTED = "unlisted"


class ArtifactClass(str, Enum):
    """The egress class of one artifact."""

    SUMMARY = "summary"
    FINDING = "finding"
    EVIDENCE = "evidence"
    SECRET = "secret"


_S = ArtifactClass.SECRET
_M = ArtifactClass.SUMMARY
_F = ArtifactClass.FINDING
_E = ArtifactClass.EVIDENCE

#: Ordered ``(pattern, class)`` rules. Secrets first, always.
_RULES: tuple[tuple[str, ArtifactClass], ...] = (
    # ── secret: credential stores and anything derived from one ───────────
    ("variables.json", _S),  # raw: credential store; the console gets a redacted derivative
    ("domains/*/variables.json", _S),
    ("**/secrets/**", _S),  # run-directory secret files (RunPlan file: references)
    ("**/*vault*", _S),
    ("**/vault/**", _S),
    ("**/dcsync_dump.json", _S),
    ("**/*secretsdump*", _S),
    ("**/*ntds*", _S),
    ("**/*.ccache", _S),
    ("**/*.kirbi", _S),
    ("**/*.keytab", _S),
    ("**/*.pfx", _S),
    ("**/*.p12", _S),
    ("**/*.pem", _S),
    ("**/*.key", _S),
    ("**/*.dmp", _S),
    ("**/lsass*", _S),
    ("**/*credential*", _S),
    ("**/*password*", _S),
    ("**/*secret*", _S),
    ("**/cracked_*", _S),
    ("**/hashes.*", _S),
    ("**/*.hashcat", _S),
    ("**/*.pot", _S),
    ("**/*.potfile", _S),
    ("**/gpp_*.json", _S),  # recovered Group Policy Preference passwords
    ("domains/*/cracking/**", _S),
    ("domains/_unattributed/**", _S),  # captured hashes not yet tied to a domain
    ("domains/captured/**", _S),  # legacy name of the same bucket
    ("domains/*/smb/**/*.zip", _S),  # files retrieved from hosts
    # Found by the workspace secret purge on a lab scan (2026-11-09): each of
    # these held a recovered secret under a name no rule above caught.
    ("cracking/**", _S),  # workspace-level cracking input (NT hash lists)
    ("**/loot/**", _S),  # files retrieved from hosts by share hunting
    ("smb/spidering/**", _S),  # credentials found inside retrieved files
    ("**/gpp_*.log", _S),  # Group Policy Preference extraction output
    ("domains/*/ldap/descriptions.*", _S),  # description attributes, where passwords are left
    ("**/.attack_paths_cache/**", _S),  # derived cache; carries node attributes verbatim
    # Share-artifact processing: the report recorded each NTLM hash it found and
    # the cache replays the full records. The writer now strips the values; the
    # class stays SECRET as the second defence (content, not name, decided it).
    ("**/artifact_processing_report.json", _S),
    ("**/analysis_history.json", _S),
    ("logs/**", _S),  # the operator terminal shows recovered secrets in cleartext
    ("flags/**", _S),
    (".adscan_history", _S),
    # ── summary: identifier-free counts and lifecycle ONLY ─────────────────
    # Leaves under metadata_only, so nothing that names a domain, host, object
    # or workspace may sit here (scan_summary.json, coverage.json and the
    # manifest all do, and are findings).
    ("run_summary.json", _M),
    # ── finding: what the console renders ─────────────────────────────────
    ("scan_summary.json", _F),
    ("purge_record.json", _F),  # when recovered secrets were removed, by whom, counts
    ("coverage.json", _F),
    (ARTIFACT_MANIFEST_FILENAME, _F),
    ("technical_report.json", _F),
    ("report_model.json", _F),
    ("environment_changes.json", _F),
    ("trusts.json", _F),
    ("network_reachability_report.json", _F),
    ("enabled_users.txt", _F),
    ("enabled_computers.txt", _F),
    ("attack_graph.json", _F),
    ("attack_paths_snapshot.json", _F),
    ("host_intel.json", _F),
    ("inventory/widgets/*.json", _F),
    ("domains/*/trusts.json", _F),
    ("domains/*/network_reachability_report.json", _F),
    ("domains/*/enabled_users.txt", _F),
    ("domains/*/enabled_computers.txt", _F),
    ("domains/*/attack_graph.json", _F),
    ("domains/*/attack_paths_snapshot.json", _F),
    ("domains/*/memberships.json", _F),
    ("domains/*/users.json", _F),
    ("domains/*/computers.json", _F),
    ("domains/*/admins.txt", _F),
    ("domains/*/privileged.txt", _F),
    ("domains/*/identity_risk_snapshot.json", _F),
    ("domains/*/identity_choke_points.json", _F),
    ("domains/*/inventory/**/*.json", _F),
    ("deliverables/**", _F),
    # ── evidence: saved command output and collected configuration ────────
    ("domains/*/nmap/**", _E),
    ("domains/*/smb/**/shares.json", _E),
)


#: Content audit of every non-secret rule (2026-11-03). Classification is by
#: NAME, but a secret can sit inside a harmlessly named file, so each rule is in
#: exactly one of these sets, locked by test:
#:
#: * ``REDACTION_REQUIRED``: the content CAN embed a secret, so the file may leave
#:   a node only after a field-level redactor (``node_link/redact.py``, Phase D)
#:   and the known-secret scanner have passed it. The egress filter must refuse a
#:   file in this set that has no registered redactor. Measured carriers:
#:   attack-graph edge notes held the cleartext password of a sprayed account
#:   (``attack_graph_service`` entry-vector notes) and the snapshot and report
#:   project those steps. The engine writer now stores a reference instead
#:   (``adscan_core/graph_secret_refs.py``), but a graph written by an older
#:   engine still carries values, so the class stays redaction-required; user and computer objects carry the ``description``
#:   attribute, where passwords are routinely left; the inventory may hold
#:   attributes such as a readable LAPS value; a widget can be a credential table;
#:   a writeup can be rendered with full credentials; the report and its data
#:   model quote credential findings; the ledger and host intelligence quote
#:   values the engine set or read.
#: * ``CONTENT_AUDITED_CLEAN``: names, counts, addresses, trust attributes, scan
#:   output and share listings. They can identify objects (a policy decides
#:   that), but hold no secret value.
REDACTION_REQUIRED: frozenset[str] = frozenset(
    {
        "technical_report.json",
        "report_model.json",
        "environment_changes.json",
        "attack_graph.json",
        "attack_paths_snapshot.json",
        "host_intel.json",
        "inventory/widgets/*.json",
        "domains/*/attack_graph.json",
        "domains/*/attack_paths_snapshot.json",
        "domains/*/users.json",
        "domains/*/computers.json",
        "domains/*/identity_risk_snapshot.json",
        "domains/*/identity_choke_points.json",
        "domains/*/inventory/**/*.json",
        "deliverables/**",
    }
)

CONTENT_AUDITED_CLEAN: frozenset[str] = frozenset(
    {
        "run_summary.json",
        "scan_summary.json",
        "purge_record.json",
        "coverage.json",
        ARTIFACT_MANIFEST_FILENAME,
        "trusts.json",
        "network_reachability_report.json",
        "enabled_users.txt",
        "enabled_computers.txt",
        "domains/*/trusts.json",
        "domains/*/network_reachability_report.json",
        "domains/*/enabled_users.txt",
        "domains/*/enabled_computers.txt",
        "domains/*/memberships.json",
        "domains/*/admins.txt",
        "domains/*/privileged.txt",
        "domains/*/nmap/**",
        "domains/*/smb/**/shares.json",
    }
)


#: Data policies (spec section 9.1) and the classes each lets leave. Phase D's
#: ``node_link/policy.py`` consumes these; it does not redefine them.
POLICY_METADATA_ONLY = "metadata_only"
POLICY_FINDINGS = "findings"
POLICY_FULL = "full"
POLICY_ALLOWED_CLASSES: dict[str, frozenset[ArtifactClass]] = {
    POLICY_METADATA_ONLY: frozenset({ArtifactClass.SUMMARY}),
    POLICY_FINDINGS: frozenset({ArtifactClass.SUMMARY, ArtifactClass.FINDING}),
    POLICY_FULL: frozenset({ArtifactClass.SUMMARY, ArtifactClass.FINDING, ArtifactClass.EVIDENCE}),
}


class EgressDecision(str, Enum):
    """What may happen to one file at a node's egress filter."""

    REFUSE = "refuse"
    AS_IS = "as_is"
    AFTER_REDACTION = "after_redaction"


def _matching_rule(relpath: str) -> Optional[tuple[str, ArtifactClass]]:
    segments = _normalise(relpath)
    if segments is None:
        return None
    for pattern, artifact_class in _RULES:
        if _match(tuple(pattern.split("/")), segments):
            return pattern, artifact_class
    return None


def _redaction_required(rule: Optional[tuple[str, ArtifactClass]]) -> bool:
    return rule is not None and rule[1] is not ArtifactClass.SECRET and rule[0] in REDACTION_REQUIRED


def may_leave(relpath: str, policy: str) -> EgressDecision:
    """The one egress decision for a workspace-relative path under a data policy.

    ``refuse`` for a secret, an unlisted or out-of-workspace path, a class the
    policy does not allow, or an unknown policy name (fail closed);
    ``after_redaction`` when the content audit says the file can embed a secret
    (:data:`REDACTION_REQUIRED`); ``as_is`` otherwise.
    """
    rule = _matching_rule(relpath)
    allowed = POLICY_ALLOWED_CLASSES.get(str(policy or ""))
    if rule is None or allowed is None or rule[1] is ArtifactClass.SECRET or rule[1] not in allowed:
        return EgressDecision.REFUSE
    return EgressDecision.AFTER_REDACTION if _redaction_required(rule) else EgressDecision.AS_IS


def iter_rules() -> Iterator[tuple[str, ArtifactClass]]:
    """Yield the ordered classification rules (for audits and tests)."""
    yield from _RULES


def _normalise(relpath: str) -> Optional[tuple[str, ...]]:
    """Return the path's segments, or ``None`` when it is not inside a workspace."""
    text = str(relpath or "").replace("\\", "/")
    if not text or text.startswith("/") or (len(text) > 1 and text[1] == ":"):
        return None
    segments = tuple(part for part in text.split("/") if part not in ("", "."))
    if not segments or any(part == ".." for part in segments):
        return None
    return segments


def _match(pattern: tuple[str, ...], segments: tuple[str, ...]) -> bool:
    if not pattern:
        return not segments
    head, rest = pattern[0], pattern[1:]
    if head == "**":
        return any(_match(rest, segments[index:]) for index in range(len(segments) + 1))
    if not segments:
        return False
    return fnmatchcase(segments[0], head) and _match(rest, segments[1:])


def classify(relpath: str) -> Optional[ArtifactClass]:
    """Return the egress class of a workspace-relative path, ``None`` when unlisted.

    An absolute path, a ``..`` segment or a drive-qualified path is outside the
    workspace by definition and is never classified (so it can never leave).
    """
    segments = _normalise(relpath)
    if segments is None:
        return None
    rule = _matching_rule("/".join(segments))
    return rule[1] if rule is not None else None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_artifact_manifest(
    workspace_dir: Path,
    run_id: str,
    *,
    generated_at: Optional[str] = None,
    generated_at_frame: Optional[dict] = None,
    max_hash_bytes: int = MAX_HASH_BYTES,
    hash_budget_seconds: float = HASH_BUDGET_SECONDS,
) -> dict:
    """Return the ``adscan.artifact_manifest/1`` document for a workspace.

    Every regular file under the workspace is listed with its class (``unlisted``
    when no rule covers it) and size. Symbolic links are not followed and not
    listed: what a link points at is not an artifact of this workspace. The
    manifest does not list itself.

    A SHA-256 is recorded for a file only when hashing it is safe and bounded:
    only for a summary, finding or evidence file (never for a SECRET or an
    UNLISTED one: a digest of a one-line secret or loot file is a crackable
    hash), computed over the content AS WRITTEN (before any redaction; an egress
    filter re-hashes what it actually sends), never for a file larger than ``max_hash_bytes``, and never once the
    run has spent ``hash_budget_seconds`` hashing (monotonic clock), so a
    multi-gigabyte workspace cannot stall the end of a run. A skipped digest is
    stated (``hashed: false`` with ``hash_skipped``), never faked.
    """
    root = Path(workspace_dir)
    artifacts = []
    started = time.monotonic()
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        base = Path(current)
        for name in sorted(filenames):
            path = base / name
            if path.is_symlink() or not path.is_file():
                continue
            relpath = path.relative_to(root).as_posix()
            if relpath == ARTIFACT_MANIFEST_FILENAME:
                continue
            if len(relpath) > 1024 or any(ord(ch) < 32 for ch in relpath):
                continue  # not a name the contract can carry; it stays on the node, unlisted
            rule = _matching_rule(relpath)
            artifact_class = rule[1] if rule is not None else None
            try:
                size = path.stat().st_size
            except OSError:
                continue  # vanished mid-walk: not an artifact we can vouch for
            entry: dict = {
                "path": relpath,
                "class": artifact_class.value if artifact_class is not None else UNLISTED,
                "size": size,
                "redaction_required": _redaction_required(rule),
            }
            skipped = None
            if artifact_class is None:
                skipped = "unlisted"
            elif artifact_class is ArtifactClass.SECRET:
                skipped = "secret"
            elif size > max_hash_bytes:
                skipped = "size_cap"
            elif time.monotonic() - started >= hash_budget_seconds:
                skipped = "time_budget"
            if skipped is None:
                try:
                    entry["sha256"] = _sha256(path)
                except OSError:
                    skipped = "unreadable"
            entry["hashed"] = skipped is None
            if skipped is not None:
                entry["hash_skipped"] = skipped
            artifacts.append(entry)
    return {
        "schema": "adscan.artifact_manifest/1",
        "run_id": run_id,
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(),
        # Which clock generated_at came from (adscan_core/reporting/clock_frame.py);
        # the caller resolves it, this module holds no domain state.
        "generated_at_frame": dict(generated_at_frame or {"frame": "unverified", "stepped": False}),
        "artifacts": artifacts,
    }


def write_artifact_manifest(
    workspace_dir: Path,
    run_id: str,
    *,
    generated_at: Optional[str] = None,
    generated_at_frame: Optional[dict] = None,
) -> Path:
    """Write ``artifact_manifest.json`` into the workspace and return its path.

    Validated against the contract schema before it is written, so a manifest on
    disk is always a valid one.
    """
    from adscan_core.engagement.contract import validate

    manifest = build_artifact_manifest(
        workspace_dir, run_id, generated_at=generated_at, generated_at_frame=generated_at_frame
    )
    validate("artifact_manifest", manifest)
    target = Path(workspace_dir) / ARTIFACT_MANIFEST_FILENAME
    tmp = target.with_name(target.name + ".tmp")
    tmp.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, target)
    return target


__all__ = (
    "ARTIFACT_MANIFEST_FILENAME",
    "UNLISTED",
    "ArtifactClass",
    "CONTENT_AUDITED_CLEAN",
    "REDACTION_REQUIRED",
    "build_artifact_manifest",
    "classify",
    "iter_rules",
    "EgressDecision",
    "POLICY_ALLOWED_CLASSES",
    "POLICY_FINDINGS",
    "POLICY_FULL",
    "POLICY_METADATA_ONLY",
    "may_leave",
    "write_artifact_manifest",
)
