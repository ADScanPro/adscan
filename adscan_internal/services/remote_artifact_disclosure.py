"""Disclosure of the files ADscan writes on an assessed host, at the WRITE seam.

Why this module exists
----------------------
Several techniques cannot run without putting a file on the target: a process
dump has to be written somewhere before it can be read back, a registry hive has
to be saved to disk before it can be downloaded, and a helper executable has to
be uploaded before it can be run. The file is transient (ADscan deletes it the
moment it has the bytes) but it exists, it holds credential material while it
does, and when the delete fails it stays on the client's machine. The client is
owed a written record of both outcomes: a verified removal is a statement that
earns trust, and a failed removal is legal-critical, because a saved SECURITY
hive or an LSASS dump left on a domain controller is exactly the kind of thing
an assessment must never leave behind silently.

Why the seam, and not the dump entry point
------------------------------------------
Registering at each ``dump_*`` entry point means every future backend author has
to remember to do it, and a path that writes nothing (the inline registry read,
which never touches disk) has to remember NOT to. Both are things people forget.
So the disclosure lives where the file is actually created and removed:

* :func:`adscan_internal.services.smb_transport.download_admin_file_bytes`, which
  every dump file and every saved hive funnels through, and which is the only
  place that knows whether the delete succeeded;
* the single upload seam in
  :mod:`adscan_internal.services.exploitation.native_dump_service`, for the
  helper binaries that are pushed rather than retrieved.

A path that creates no remote file therefore discloses nothing by construction,
and a new backend inherits the disclosure for free.

Layering
--------
``smb_transport`` is the transport layer: it holds no session shell, no domain
and no technique name, and it must not reach for them. So this module takes the
dependency-inversion shape already used for the Kerberos clock seam
(``dc_time.register_clock_resync_for_shell``): the session registers itself once
at shell setup, the dump layer declares the ambient context for the technique it
is running, and the transport seam calls a shell-less function that is a no-op
when nothing is registered. Every function here is best-effort and never raises,
because a bookkeeping failure must not break a dump that is working.
"""

from __future__ import annotations

import contextlib
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Iterator

from adscan_core.rich_output import print_exception
from adscan_internal import telemetry
from adscan_internal.services import cleanup_taxonomy as _tax

KIND_FILE_WRITTEN = _tax.KIND_REMOTE_FILE_WRITTEN
KIND_FILE_UPLOADED = _tax.KIND_REMOTE_FILE_UPLOADED
KIND_SCHEDULED_TASK = "scheduled_task_created"

#: Verification method recorded on a confirmed remote delete, so the client
#: document says HOW the removal was established rather than asserting it.
VERIFICATION_REMOTE_DELETE = "remote_file_delete_confirmed"


@dataclass(frozen=True)
class RemoteArtifactContext:
    """Who is writing, where, and with which technique.

    Attributes:
        domain: Domain the target belongs to, for the ledger record.
        host: Host the file is written on.
        method: Technique that needed the file (e.g. ``lsass-wsass``).
    """

    domain: str = ""
    host: str = ""
    method: str = ""


_EMPTY_CONTEXT = RemoteArtifactContext()

#: Ambient per-technique context. A ContextVar (not a module global) so the
#: value is correct under concurrent per-host tasks on one event loop.
_CONTEXT: ContextVar[RemoteArtifactContext] = ContextVar(
    "adscan_remote_artifact_context", default=_EMPTY_CONTEXT
)

#: The session whose ledger receives the disclosure. Set once by
#: :func:`register_artifact_disclosure_for_shell` at shell setup, mirroring
#: ``dc_time._ACTIVE_CLOCK_SHELL``, so the transport seam reaches the ledger
#: without the shell being threaded through every dump backend.
_ACTIVE_DISCLOSURE_SHELL: Any = None


def register_artifact_disclosure_for_shell(shell: Any) -> None:
    """Register the session whose ledger remote-artefact disclosure writes to.

    One call site (shell setup). Until it runs, every disclosure call is a
    no-op, which is what unit tests and standalone use want.

    Args:
        shell: The session shell carrying ``environment_change_ledger``.
    """
    global _ACTIVE_DISCLOSURE_SHELL  # noqa: PLW0603
    _ACTIVE_DISCLOSURE_SHELL = shell


def _ledger() -> Any:
    """The live environment-change ledger, or None when there is no session."""
    return getattr(_ACTIVE_DISCLOSURE_SHELL, "environment_change_ledger", None)


@contextlib.contextmanager
def remote_artifact_context(
    *, domain: str = "", host: str = "", method: str = ""
) -> Iterator[None]:
    """Declare the ambient context for files written inside this block.

    The transport seam records the path and the delete outcome; the dump layer
    is the only layer that knows which domain, host and technique those belong
    to. Wrapping a backend in this context is what turns a bare path into a
    client-readable record. Omitting it still discloses the file: the record
    simply carries less context, never nothing.

    Args:
        domain: Domain the target belongs to.
        host: Host the file is written on.
        method: Technique that needed the file.
    """
    token = _CONTEXT.set(
        RemoteArtifactContext(
            domain=str(domain or ""), host=str(host or ""), method=str(method or "")
        )
    )
    try:
        yield
    finally:
        _CONTEXT.reset(token)


def active_remote_artifact_context() -> RemoteArtifactContext:
    """The ambient context, or an empty one when no block declared it."""
    try:
        return _CONTEXT.get()
    except LookupError:  # pragma: no cover - ContextVar has a default
        return _EMPTY_CONTEXT


def local_windows_path(remote_path: str) -> str:
    """Normalize any remote path shape to the path the host's admin would type.

    The dump backends pass three shapes around: an absolute local path
    (``C:\\Windows\\Temp\\x.dmp``), the ADMIN$-relative form the download
    helper takes (``\\Windows\\Temp\\x.sav``), and the UNC aiosmb reports
    (``\\\\HOST\\C$\\Windows\\Temp\\x.dmp``). A remediation command must carry
    the first: ``Remove-Item "\\Windows\\Temp\\x.sav"`` resolves against
    whatever drive the client's shell happens to be on, which is not a command
    anyone should paste onto a domain controller.

    Args:
        remote_path: A path in any of the three shapes.

    Returns:
        An absolute local Windows path, or the input when it cannot be read as
        one of the three.
    """
    path = str(remote_path or "").strip()
    if not path:
        return path
    if path.startswith("\\\\"):
        parts = path[2:].split("\\", 2)
        if len(parts) < 3:
            return path
        share, tail = parts[1], parts[2]
        if len(share) == 2 and share[1] == "$":
            return f"{share[0]}:\\{tail}"
        if share.upper() == "ADMIN$":
            return f"C:\\Windows\\{tail}"
        return path
    if len(path) > 1 and path[1] == ":":
        return path
    # The ADMIN$-relative form, which is always on the system drive.
    return "C:\\" + path.lstrip("\\")


def _unc_target(remote_path: str, host: str) -> str:
    """Name the file the way a client can act on it.

    A bare ``C:\\Windows\\Temp\\x.dmp`` does not say which machine it is on, and
    the change table has no host column, so the target string carries the host
    as a UNC admin path when the host is known. That is both unambiguous and
    directly usable from an administrative workstation.

    Args:
        remote_path: Local Windows path on the target.
        host: Host the file sits on, when known.

    Returns:
        ``\\\\host\\C$\\Windows\\Temp\\x.dmp``, or the plain path with no host.
    """
    if str(remote_path or "").strip().startswith("\\\\"):
        return str(remote_path).strip()  # already a UNC path
    path = local_windows_path(remote_path)
    host = str(host or "").strip()
    if not host or not path:
        return path
    if len(path) > 1 and path[1] == ":":
        # C:\Windows\Temp\x  ->  \\HOST\C$\Windows\Temp\x
        return f"\\\\{host}\\{path[0]}$" + path[2:]
    return f"\\\\{host}\\{path.lstrip(chr(92))}"


def host_from_machine(machine: Any) -> str:
    """Best-effort host name for the open SMB connection behind ``machine``.

    The ambient context usually carries the host already; this is the fallback
    for a seam that has only the connection, so a disclosure never ends up
    unable to say WHICH machine the file is on.

    Args:
        machine: An aiosmb machine wrapper with an open connection.

    Returns:
        The connection's hostname or IP, or an empty string when unavailable.
    """
    try:
        return str(machine.connection.target.get_hostname_or_ip() or "")
    except Exception:  # noqa: BLE001 - diagnostics only, never break a dump
        return ""


def disclose_remote_artifact(
    remote_path: str,
    *,
    kind: str = KIND_FILE_WRITTEN,
    host: str = "",
    domain: str = "",
    method: str = "",
    detail: dict[str, Any] | None = None,
) -> str | None:
    """Record that a file now exists on the target. Returns the change id.

    Call this at the moment the file is known to exist, BEFORE attempting to
    remove it, so a record exists even if the session dies between the two (the
    ledger's ``finalize()`` then reports it as needing manual cleanup rather
    than losing it). The remediation command and object are stamped up front
    for the same reason.

    Args:
        remote_path: Local Windows path on the target.
        kind: ``file_written`` (ADscan created it) or ``file_uploaded``.
        host: Host override; defaults to the ambient context.
        domain: Domain override; defaults to the ambient context.
        method: Technique override; defaults to the ambient context.
        detail: Extra metadata merged into the ledger record.

    Returns:
        The change id, or None when there is no session ledger to write to.
    """
    ledger = _ledger()
    if ledger is None:
        return None
    ctx = active_remote_artifact_context()
    resolved_host = str(host or ctx.host or "")
    resolved_domain = str(domain or ctx.domain or "")
    resolved_method = str(method or ctx.method or "remote_file_write")
    target = _unc_target(remote_path, resolved_host)
    try:
        change_id = ledger.register_change(
            kind=kind,
            domain=resolved_domain,
            target=target,
            detail={
                "host": resolved_host,
                "remote_path": str(remote_path or ""),
                **(detail or {}),
            },
            method=resolved_method,
        )
        ledger.set_revert_metadata(
            change_id,
            remediation_command=_tax.remote_artifact_remediation(
                remote_path=local_windows_path(remote_path), host=resolved_host
            ),
            remediation_object_dn=target,
        )
        return change_id
    except Exception as exc:  # pylint: disable=broad-except
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


def settle_remote_artifact_removed(
    change_id: str | None,
    *,
    verification_method: str = VERIFICATION_REMOTE_DELETE,
) -> None:
    """Record a CONFIRMED removal of a disclosed file.

    Only call this when the delete actually reported success (including "the
    file is already gone"). Anything less goes to
    :func:`settle_remote_artifact_manual`: a removal ADscan cannot prove is
    never reported as done.

    Args:
        change_id: The id returned by :func:`disclose_remote_artifact`.
        verification_method: How the removal was established.
    """
    ledger = _ledger()
    if ledger is None or not change_id:
        return
    try:
        ledger.mark_reverted_confirmed(
            change_id, verification_method=verification_method
        )
    except Exception as exc:  # pylint: disable=broad-except
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def settle_remote_artifact_manual(
    change_id: str | None,
    *,
    remote_path: str,
    host: str = "",
    error: str = "",
    attempted: bool = True,
) -> None:
    """Record that a disclosed file is still on the target.

    This is the legal-critical half: the client gets the exact path and a
    native command to remove it, in the deliverable, instead of a console
    warning nobody keeps.

    Args:
        change_id: The id returned by :func:`disclose_remote_artifact`.
        remote_path: Local Windows path on the target.
        host: Host the file sits on.
        error: Why the removal failed, for the record.
        attempted: False when no removal was tried at all, which is a different
            reason the client should see.
    """
    ledger = _ledger()
    if ledger is None or not change_id:
        return
    ctx = active_remote_artifact_context()
    resolved_host = str(host or ctx.host or "")
    try:
        ledger.mark_manual_required(
            change_id,
            reason=(
                _tax.MANUAL_REASON_REVERT_FAILED
                if attempted
                else _tax.MANUAL_REASON_NOT_ATTEMPTED
            ),
            remediation_command=_tax.remote_artifact_remediation(
                remote_path=local_windows_path(remote_path), host=resolved_host
            ),
            remediation_object_dn=_unc_target(remote_path, resolved_host),
            error=str(error or "Remote file could not be deleted."),
        )
    except Exception as exc:  # pylint: disable=broad-except
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def flag_leftover_scheduled_task(
    task_name: str,
    *,
    host: str = "",
    domain: str = "",
    method: str = "",
    error: str = "",
) -> None:
    """Record that a scheduled task could NOT be removed from an assessed host.

    HasSession and similar techniques register a scheduled task to run a command
    and then delete it within the same sub-second operation. The common case
    leaves nothing, so no ledger record is created for it. This is the exception
    path: the delete failed, the task is genuinely left on the host, and the
    client is owed the exact task name and a native removal command in the
    cleanup appendix. The record is created already in the manual_required
    terminal, so it lands in the legal-critical bucket, never the noisy
    reverted one. Best-effort: never raises into the technique flow.

    Args:
        task_name: The scheduled-task name left on the host.
        host: Host the task sits on.
        domain: Domain the host belongs to.
        method: Technique that created the task.
        error: Why the removal failed, for the record.
    """
    ledger = _ledger()
    if ledger is None or not str(task_name or "").strip():
        return
    resolved_host = str(host or "")
    resolved_domain = str(domain or "")
    remediation = (
        _tax.MANUAL_SCHEDULED_TASK.replace("TASK_NAME", str(task_name))
        .replace("ARTIFACT_HOST", resolved_host or "the assessed host")
    )
    try:
        change_id = ledger.register_change(
            kind=KIND_SCHEDULED_TASK,
            domain=resolved_domain,
            target=f"{task_name} on {resolved_host}" if resolved_host else str(task_name),
            detail={"host": resolved_host, "task_name": str(task_name)},
            method=str(method or "scheduled_task"),
        )
        ledger.mark_manual_required(
            change_id,
            reason=_tax.MANUAL_REASON_REVERT_FAILED,
            remediation_command=remediation,
            remediation_object_dn=str(task_name),
            error=str(error or "Scheduled task could not be removed."),
        )
    except Exception as exc:  # pylint: disable=broad-except
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def count_host_artifacts(changes: Any) -> tuple[int, int]:
    """Split a ledger change list into (directory changes, host artefacts).

    The client disclosure has to keep the two apart: writing a file on a server
    is not a modification of Active Directory, and a sentence that merges them
    overstates one and hides the other.

    Args:
        changes: The ledger's ``changes`` list (anything else counts as empty).

    Returns:
        ``(directory_changes, host_artifacts)``.
    """
    if not isinstance(changes, list):
        return (0, 0)
    host = 0
    directory = 0
    for entry in changes:
        if not isinstance(entry, dict):
            continue
        if _tax.kind_is_host_artifact(entry.get("kind")):
            host += 1
        else:
            directory += 1
    return (directory, host)
