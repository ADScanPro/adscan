"""Persist credentials recovered from a VM disk artifact, DCSync-style.

This is the storage + premium-UX layer on top of
:class:`adscan_internal.services.vm_artifact_service.VMArtifactService`. It mirrors
the native DCSync experience (``cli/secretsdump.py`` + ``cli/kerberos.py``) and
branches on what the snapshot actually is:

* **Domain Controller snapshot (ntds.dit present)** → the DCSync flow: an
  ``All / Domain Admin / specific user`` selector (``_resolve_dcsync_target_user``),
  then ``add_credentials_batch`` for *All* (batch cracking + reuse analysis) or a
  single ``add_credential`` for one targeted account.
* **Member server / workstation snapshot (no ntds.dit)** → the Backup-Operators
  flow: every local SAM hash is stored via ``add_credential`` (host-scoped).

The presentation follows ADscan's premium Rich style (semantic colour, a framed
header panel, a dense credentials table, ``mark_sensitive`` on every secret).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from adscan_internal import get_console, print_info, print_success, print_warning, telemetry
from adscan_internal.rich_output import mark_sensitive, print_panel

# NT hash of the empty string — disabled / blank-password accounts. Skipped on
# persistence exactly like the Backup-Operators escalation does.
_EMPTY_NTLM_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"


@dataclass(frozen=True)
class VMArtifactPersistResult:
    """Outcome of persisting credentials recovered from one VM disk artifact."""

    handled: bool
    is_domain_controller: bool
    stored: int
    error_message: str | None = None
    cancelled: bool = False


def _non_empty_domain_creds(extraction: Any) -> list[Any]:
    """Domain (ntds.dit) credentials that carry a usable NT hash."""
    return [
        cred
        for cred in extraction.credentials
        if cred.kind == "domain"
        and cred.nt_hash
        and cred.nt_hash.lower() != _EMPTY_NTLM_HASH
    ]


def _non_empty_local_creds(extraction: Any) -> list[Any]:
    """Local SAM credentials that carry a usable NT hash."""
    return [
        cred
        for cred in extraction.credentials
        if cred.kind == "local"
        and cred.nt_hash
        and cred.nt_hash.lower() != _EMPTY_NTLM_HASH
    ]


def _render_header_panel(*, source_label: str, extraction: Any, domain: str) -> None:
    """Render the premium framed header for one VM disk credential extraction."""
    domain_count = len(_non_empty_domain_creds(extraction))
    local_count = len(_non_empty_local_creds(extraction))
    if extraction.has_ntds:
        kind_line = (
            "[bold #9ece6a]Domain Controller snapshot[/]  "
            "[dim](ntds.dit present → DCSync extraction)[/]"
        )
        count_line = (
            f"[#7dcfff]{domain_count}[/] domain account(s)  ·  "
            f"[dim]{local_count} local[/]"
        )
    else:
        kind_line = (
            "[bold #e0af68]Member server / workstation snapshot[/]  "
            "[dim](no ntds.dit → local SAM extraction)[/]"
        )
        count_line = f"[#7dcfff]{local_count}[/] local account(s)"
    bootkey_line = (
        f"[dim]Boot key[/] [#bb9af7]{extraction.bootkey}[/]"
        if extraction.bootkey
        else "[dim]Boot key unavailable[/]"
    )
    body = (
        f"[dim]Artifact[/] {mark_sensitive(source_label, 'path')}\n"
        f"[dim]Domain[/]   {mark_sensitive(domain, 'domain')}\n"
        f"{kind_line}\n"
        f"{count_line}   {bootkey_line}"
    )
    print_panel(
        body,
        title="🗄️  VM Disk Artifact · Offline Credential Extraction",
        border_style="#7aa2f7",
    )


def _render_credentials_table(*, title: str, creds: list[Any]) -> None:
    """Render a dense, right-aligned credentials table (premium style)."""
    try:
        from rich.table import Table
    except ImportError:  # pragma: no cover - rich always present in the runtime
        for cred in creds:
            print_info(f"  {cred.principal}: {mark_sensitive(cred.nt_hash or '-', 'hash')}")
        return

    table = Table(title=title, title_style="bold #c0caf5", header_style="bold #7aa2f7",
                  border_style="#414868", expand=False, show_lines=False)
    table.add_column("Account", style="#c0caf5", no_wrap=True)
    table.add_column("RID", justify="right", style="#565f89")
    table.add_column("NT hash", style="#9ece6a", no_wrap=True)
    table.add_column("Source", style="#565f89")
    for cred in creds:
        table.add_row(
            mark_sensitive(cred.principal or "-", "user"),
            str(cred.rid) if cred.rid is not None else "-",
            mark_sensitive(cred.nt_hash or "-", "hash"),
            cred.source or "-",
        )
    get_console().print(table)


def persist_vm_disk_credentials(
    shell: Any,
    *,
    domain: str,
    host: str,
    source_label: str,
    extraction: Any,
) -> VMArtifactPersistResult:
    """Persist credentials from an already-extracted VM disk artifact, DCSync-style.

    ``extraction`` is a ``VMArtifactExtractionResult`` produced by
    :class:`VMArtifactService`. Routes DC snapshots through the DCSync selector +
    batch persistence and member-server snapshots through host-scoped local
    persistence. Returns a summary of what was stored.
    """
    if not getattr(extraction, "handled", False):
        msg = getattr(extraction, "error_message", None) or "extraction failed"
        print_warning(f"VM disk artifact not processed: {msg}")
        return VMArtifactPersistResult(
            handled=False, is_domain_controller=False, stored=0, error_message=msg
        )

    _render_header_panel(source_label=source_label, extraction=extraction, domain=domain)

    if extraction.has_ntds:
        return _persist_domain_controller(
            shell, domain=domain, source_label=source_label, extraction=extraction
        )
    return _persist_member_server(
        shell, domain=domain, host=host, source_label=source_label, extraction=extraction
    )


def _persist_domain_controller(
    shell: Any,
    *,
    domain: str,
    source_label: str,
    extraction: Any,
) -> VMArtifactPersistResult:
    """DCSync-style persistence for a DC snapshot (selector + All/specific)."""
    domain_creds = _non_empty_domain_creds(extraction)
    if not domain_creds:
        print_warning("No domain NT hashes recovered from the ntds.dit.")
        return VMArtifactPersistResult(
            handled=True, is_domain_controller=True, stored=0,
            error_message="ntds.dit yielded no usable domain hashes",
        )

    # Reuse the exact DCSync target selector: All / Domain Admin / manual / Cancel.
    from adscan_internal.cli.kerberos import _resolve_dcsync_target_user

    target_user = _resolve_dcsync_target_user(shell, domain=domain)
    if target_user is None:
        print_info("VM disk credential persistence cancelled by operator.")
        return VMArtifactPersistResult(
            handled=True, is_domain_controller=True, stored=0, cancelled=True
        )

    if target_user.strip().casefold() == "all":
        return _persist_dc_all(shell, domain=domain, domain_creds=domain_creds)
    return _persist_dc_single(
        shell, domain=domain, target_user=target_user, domain_creds=domain_creds
    )


def _persist_dc_all(
    shell: Any,
    *,
    domain: str,
    domain_creds: list[Any],
) -> VMArtifactPersistResult:
    """Persist ALL recovered domain hashes via the DCSync batch path."""
    from adscan_internal.cli.creds import add_credentials_batch

    credentials = [(cred.principal, cred.nt_hash) for cred in domain_creds]
    _render_credentials_table(
        title=f"Domain accounts recovered from ntds.dit ({len(credentials)})",
        creds=domain_creds,
    )
    try:
        persisted = add_credentials_batch(
            shell,
            domain=domain,
            credentials=credentials,
            verify_credential=True,
            credential_origin="ntds",
        )
    except Exception as exc:  # noqa: BLE001 - persistence failure is non-fatal
        telemetry.capture_exception(exc)
        print_warning(f"Batch credential persistence failed: {exc}")
        return VMArtifactPersistResult(
            handled=True, is_domain_controller=True, stored=0, error_message=str(exc)
        )
    count = len(persisted) if isinstance(persisted, list) else len(credentials)
    print_success(
        f"Stored {count} domain credential(s) from the offline ntds.dit "
        f"(DCSync-equivalent, no live DC contacted)."
    )
    return VMArtifactPersistResult(
        handled=True, is_domain_controller=True, stored=count
    )


def _persist_dc_single(
    shell: Any,
    *,
    domain: str,
    target_user: str,
    domain_creds: list[Any],
) -> VMArtifactPersistResult:
    """Persist a single targeted account recovered from the ntds.dit."""
    wanted = target_user.strip().casefold()
    match = next(
        (c for c in domain_creds if c.principal.strip().casefold() == wanted), None
    )
    if match is None:
        print_warning(
            f"Account {mark_sensitive(target_user, 'user')} was not present in the "
            "recovered ntds.dit hashes."
        )
        return VMArtifactPersistResult(
            handled=True, is_domain_controller=True, stored=0,
            error_message="targeted user not found in ntds.dit",
        )
    _render_credentials_table(title="Targeted account", creds=[match])
    try:
        shell.add_credential(
            domain, match.principal, match.nt_hash, credential_origin="ntds"
        )
    except Exception as exc:  # noqa: BLE001 - persistence failure is non-fatal
        telemetry.capture_exception(exc)
        print_warning(f"Could not store credential for {target_user}: {exc}")
        return VMArtifactPersistResult(
            handled=True, is_domain_controller=True, stored=0, error_message=str(exc)
        )
    print_success(
        f"Stored credential for {mark_sensitive(match.principal, 'user')} "
        "from the offline ntds.dit."
    )
    return VMArtifactPersistResult(handled=True, is_domain_controller=True, stored=1)


def _persist_member_server(
    shell: Any,
    *,
    domain: str,
    host: str,
    source_label: str,
    extraction: Any,
) -> VMArtifactPersistResult:
    """Backup-Operators-style persistence for a non-DC snapshot (local SAM hashes)."""
    local_creds = _non_empty_local_creds(extraction)
    if not local_creds:
        print_warning("No usable local SAM hashes recovered from the snapshot hives.")
        return VMArtifactPersistResult(
            handled=True, is_domain_controller=False, stored=0,
            error_message="no usable local SAM hashes",
        )

    _render_credentials_table(
        title=f"Local SAM accounts recovered from snapshot ({len(local_creds)})",
        creds=local_creds,
    )
    stored = 0
    for cred in local_creds:
        try:
            # Host-scoped local credential: the principal is local to the snapshot's
            # origin. We key it by the host where the disk was found (best available
            # anchor), service "smb" — mirroring the Backup-Operators escalation.
            shell.add_credential(
                domain,
                cred.principal,
                cred.nt_hash,
                host=host,
                service="smb",
                credential_origin="sam_dump",
            )
            stored += 1
        except Exception as exc:  # noqa: BLE001 - one failure must not abort the rest
            telemetry.capture_exception(exc)
            print_warning(
                f"Could not store local credential {mark_sensitive(cred.principal, 'user')}: {exc}"
            )
    print_success(
        f"Stored {stored} local credential(s) from the member-server snapshot hives."
    )
    return VMArtifactPersistResult(
        handled=True, is_domain_controller=False, stored=stored
    )
