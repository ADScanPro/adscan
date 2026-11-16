"""What a workspace accumulates ACROSS scans, decided once.

A workspace holds two kinds of things. The SNAPSHOT is what one scan produced
(the domains, the attack graph, the technical report, the inventories) and the
next scan replaces it. The HISTORY is what the engagement accumulates over all
of its scans, and no scan may remove it:

* ``engagement/``: the engagement ledger, the audit trail of every run and
  recheck (new, fixed, reopened, not re-checked, with dates and parentage).
* ``runs/``: one evidence folder per run, named by the ledger.
* ``deliverables/``: every document rendered for the client (kits, progress
  reports); the platform keeps one database row per document holding its path.
* ``scope.json`` and its sidecars: the client's decision about what the
  assessment may touch, the write lock, the block a platform run started from,
  and any copy set aside as unreadable.
* ``purge_record.json``: when recovered secrets were removed, by whom, and the
  counts; the proof a data-removal request was honoured.
* ``.graph_secret_fingerprint.key``: the key that makes secret fingerprints
  comparable across the runs of one engagement (a new key per scan reads every
  recovered secret as a different one).
* ``.adscan_history``: the operator's command history.

Two writers remove a snapshot and both obey this module, so they cannot drift
again. They did on 2026-11-15 (release gate R50 and R51): the engine's clear
kept the scope record but not the ledger, promotion kept the ledger but not the
purge record, so a second scan of a workspace lost its history and the record
of a secret purge.

* The engine's workspace clear (``PentestShell.do_clear_all``), which ``ci``
  runs on every non-resume start and an operator runs as ``clear_all``.
* The platform runner's promotion of an execution workspace into the logical
  one (``appliance/runner/adscan_runner/workspace.py``). The runner imports the
  standard library only, so it keeps a mirror of these names, each with the
  rule it applies at promotion; ``tests/unit/core/test_workspace_retention.py``
  fails when the two disagree.

An entry here is never removed by a scan: deleting the workspace is then the
only way it goes, which is the end-of-engagement procedure. Stdlib only,
constants only.
"""

from __future__ import annotations

#: The engagement ledger directory (``adscan_core.engagement.store.STORE_DIRNAME``).
ENGAGEMENT_LEDGER_DIRNAME = "engagement"
#: The per-run evidence folders
#: (``adscan_internal.services.engagement.run_folder.RUNS_DIRNAME``).
RUN_FOLDERS_DIRNAME = "runs"
#: Every document rendered for the client from this workspace.
DELIVERABLES_DIRNAME = "deliverables"
#: The engagement scope record and its sidecars
#: (``adscan_core.reporting.engagement_scope.SCOPE_FILENAME`` / ``SCOPE_LOCK_FILENAME``).
SCOPE_RECORD_FILENAME = "scope.json"
SCOPE_RECORD_LOCK_FILENAME = "scope.json.lock"
SCOPE_CARRIED_FILENAME = "scope.json.carried"
SCOPE_UNREADABLE_PREFIX = "scope.json.unreadable-"
#: The secret-purge record (``adscan_core.workspace_secret_purge.PURGE_RECORD_FILENAME``).
PURGE_RECORD_FILENAME = "purge_record.json"
#: The secret-fingerprint key (``adscan_core.graph_secret_refs.GRAPH_SECRET_KEY_FILENAME``).
SECRET_FINGERPRINT_KEY_FILENAME = ".graph_secret_fingerprint.key"
#: The operator's command history.
COMMAND_HISTORY_FILENAME = ".adscan_history"

#: Top-level workspace entries no scan removes, with the reason each is kept.
ACCUMULATED_ACROSS_SCANS: dict[str, str] = {
    ENGAGEMENT_LEDGER_DIRNAME: "the engagement ledger: the audit trail of every run and recheck",
    RUN_FOLDERS_DIRNAME: "one evidence folder per run, named by the ledger",
    DELIVERABLES_DIRNAME: "every document handed to the client, referenced by path",
    SCOPE_RECORD_FILENAME: "the client's decision about what the assessment may touch",
    SCOPE_RECORD_LOCK_FILENAME: "the scope record's write lock",
    SCOPE_CARRIED_FILENAME: "the scope block a platform run started from",
    PURGE_RECORD_FILENAME: "when recovered secrets were removed, by whom, and the counts",
    SECRET_FINGERPRINT_KEY_FILENAME: "keeps secret fingerprints comparable across runs",
    COMMAND_HISTORY_FILENAME: "the operator's command history",
}

#: Name prefixes of top-level entries no scan removes, with the reason.
ACCUMULATED_PREFIXES: dict[str, str] = {
    SCOPE_UNREADABLE_PREFIX: "a scope record set aside as unreadable: evidence of the client's decision",
}


def accumulates_across_scans(name: str) -> bool:
    """Whether the top-level workspace entry ``name`` survives every scan."""
    if name in ACCUMULATED_ACROSS_SCANS:
        return True
    return any(name.startswith(prefix) for prefix in ACCUMULATED_PREFIXES)


__all__ = [
    "ACCUMULATED_ACROSS_SCANS",
    "ACCUMULATED_PREFIXES",
    "COMMAND_HISTORY_FILENAME",
    "DELIVERABLES_DIRNAME",
    "ENGAGEMENT_LEDGER_DIRNAME",
    "PURGE_RECORD_FILENAME",
    "RUN_FOLDERS_DIRNAME",
    "SCOPE_CARRIED_FILENAME",
    "SCOPE_RECORD_FILENAME",
    "SCOPE_RECORD_LOCK_FILENAME",
    "SCOPE_UNREADABLE_PREFIX",
    "SECRET_FINGERPRINT_KEY_FILENAME",
    "accumulates_across_scans",
]
