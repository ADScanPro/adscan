"""Engine side of the attack-graph secret references (shell-bound).

:mod:`adscan_core.graph_secret_refs` decides WHAT a secret-bearing note field is
and what replaces it. This module binds that to a workspace:

* :func:`redact_graph_for_persist` runs at the graph write seam
  (``save_attack_graph``) and at the engine load seam: it creates the
  per-workspace fingerprint key if needed, redacts the graph in place, and
  retains every removed value in the per-domain sidecar BEFORE the caller
  writes, so a value is never discarded.
* :func:`resolve_note_secret_for_shell` returns the value a reference points at:
  a legacy inline value, then the sidecar (exact by fingerprint), then the
  credential store under the recorded identity (accepted only when its keyed
  fingerprint matches, so a rotated password is never presented as the one
  this edge recorded).
* :func:`register_graph_secret_resolver_for_shell` installs that resolver in
  ``adscan_core`` so dependency-light renderers (the operator's attack-path
  view) can show the cleartext the operator is entitled to.
"""

from __future__ import annotations

from typing import Any, Mapping

from adscan_core import graph_secret_refs as refs
from adscan_core.rich_output import print_info_debug
from adscan_internal.workspaces import domain_subpath, resolve_workspace_cwd


def _workspace_root(shell: object) -> str:
    return resolve_workspace_cwd(shell)


def graph_path_for(shell: object, domain: str) -> str:
    """Return ``domains/<domain>/attack_graph.json`` for *shell*'s workspace."""
    return domain_subpath(
        _workspace_root(shell),
        getattr(shell, "domains_dir", "domains"),
        domain,
        "attack_graph.json",
    )


def sidecar_path_for(shell: object, domain: str) -> str:
    """Return the per-domain retention sidecar path."""
    return str(refs.sidecar_path_for_graph(graph_path_for(shell, domain)))


def fingerprint_key_for(shell: object, *, create: bool = True) -> bytes | None:
    """Return the workspace fingerprint key (created on first use when *create*)."""
    root = _workspace_root(shell)
    if not root:
        return None
    if create:
        return refs.ensure_fingerprint_key(root)
    return refs.read_fingerprint_key(root)


def redact_graph_for_persist(shell: object, domain: str, graph: dict[str, Any]) -> int:
    """Redact *graph* in place and retain the removed values. Returns the count.

    Never raises: a failure to retain is logged and the graph is still redacted,
    because a secret in a ``finding`` artifact is the worse outcome.
    """
    try:
        key = fingerprint_key_for(shell, create=True)
        extracted = refs.redact_graph_secrets(graph, key=key, domain=domain)
        if not extracted:
            return 0
        retained = refs.retain_extracted_secrets(sidecar_path_for(shell, domain), extracted)
        if not retained:
            print_info_debug(
                "graph secret refs: one or more recovered values could not be "
                "retained in the sidecar; the credential store remains the source"
            )
        return len(extracted)
    except Exception as exc:  # noqa: BLE001 — never break the graph write
        print_info_debug(f"graph secret refs: redaction failed: {type(exc).__name__}")
        # Fail closed: strip values even if retention or the key failed.
        refs.redact_graph_secrets(graph, key=None, domain=domain)
        return 0


def _store_candidates(shell: object, domain: str, ref: Mapping[str, Any]) -> list[str]:
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return []
    username = str(ref.get("username") or "").strip()
    if not username:
        return []
    wanted = username.lower()
    ref_domain = str(ref.get("domain") or domain or "").strip()
    candidates: list[str] = []
    domain_keys = [d for d in domains_data if str(d).lower() == ref_domain.lower()] or [domain]
    for domain_key in domain_keys:
        entry = domains_data.get(domain_key)
        if not isinstance(entry, dict):
            continue
        if ref.get("store") == "local_credentials":
            from adscan_internal.services.credential_store_service import (  # noqa: PLC0415
                iter_local_credential_records,
            )

            for record in iter_local_credential_records(domains_data, domain=domain_key):
                if record.username.lower() == wanted:
                    candidates.append(record.secret)
            continue
        creds = entry.get("credentials")
        if isinstance(creds, dict):
            for user, secret in creds.items():
                if str(user).lower() == wanted and isinstance(secret, str) and secret:
                    candidates.append(secret)
    return candidates


def resolve_note_secret_for_shell(
    shell: object, domain: str, notes: Any, *fields: str
) -> str:
    """Return the secret recorded by *notes* for the first resolvable field."""
    if not isinstance(notes, Mapping):
        return ""
    for field in fields or tuple(sorted(refs.SECRET_NOTE_KEYS)):
        inline = notes.get(field)
        if isinstance(inline, str) and inline.strip():
            return inline.strip()
        ref = refs.note_secret_ref(notes, field)
        if not ref:
            continue
        value = _resolve_ref(shell, domain or str(ref.get("domain") or ""), ref)
        if value:
            return value
    return ""


def _resolve_ref(shell: object, domain: str, ref: Mapping[str, Any]) -> str:
    fingerprint = str(ref.get("fingerprint") or "")
    if fingerprint and domain:
        record = refs.read_secret_sidecar(sidecar_path_for(shell, domain)).get(fingerprint)
        if isinstance(record, dict) and isinstance(record.get("value"), str):
            return record["value"]
    key = fingerprint_key_for(shell, create=False) if fingerprint else None
    for candidate in _store_candidates(shell, domain, ref):
        if not fingerprint:
            return candidate
        if key and refs.fingerprint_secret(candidate, key) == fingerprint:
            return candidate
    return ""


def register_graph_secret_resolver_for_shell(shell: object) -> None:
    """Install the shell-bound resolver into :mod:`adscan_core.graph_secret_refs`."""

    def _resolver(notes: Mapping[str, Any], field: str) -> str | None:
        ref = refs.note_secret_ref(notes, field) or {}
        domain = str(ref.get("domain") or getattr(shell, "domain", "") or "")
        return resolve_note_secret_for_shell(shell, domain, notes, field) or None

    refs.set_note_secret_resolver(_resolver)


__all__ = [
    "fingerprint_key_for",
    "graph_path_for",
    "redact_graph_for_persist",
    "register_graph_secret_resolver_for_shell",
    "resolve_note_secret_for_shell",
    "sidecar_path_for",
]
