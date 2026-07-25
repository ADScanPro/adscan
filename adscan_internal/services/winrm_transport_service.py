"""Async WinRM transport facade for the post-exploitation executor.

Phase 5 of the attack-graph refactor needs a way to drive the existing
post-exploitation techniques (see
:mod:`adscan_internal.services.post_exploitation`) over a real WinRM
session. The technique executors expose a pluggable
``RemoteRunner = Callable[[FootholdContext, str], Awaitable[str]]``
contract so the transport choice is decoupled from the technique logic.

Architecture decision (documented inline so future readers do not have
to dig through PR history):

* CLAUDE.md "subprocess paths are legacy" forbids spawning
  ``evil-winrm`` subprocesses for new code. ``reference/awinrm`` is
  a different (incompatible) library and is not currently wired into the
  ADscan stack. There is no async-native WinRM transport in the kerbad /
  badldap / aiosmb / asysocks family at the time of this phase.
* ADscan already ships ``WinRMPSRPService`` (see
  ``services/winrm_psrp_service.py``), which wraps the in-tree
  ``pypsrp[kerberos]`` dependency, supports NTLM, password, hash, and
  Kerberos ccache auth, and exposes
  :py:meth:`WinRMPSRPService.async_execute_powershell` which already
  delegates the blocking ``pypsrp`` call to a thread executor.
* Therefore the right move for Phase 5 is to layer a small async
  transport facade on top of ``WinRMPSRPService`` and inject it as the
  default ``RemoteRunner``. When a fully native async WinRM transport
  appears in ``reference/`` (post Phase 5b), only the body of
  :func:`winrm_run_powershell` needs to change — the public facade and
  the post-ex contract stay stable.

Public API:

* :class:`WinRMResult` — structured return value (stdout/stderr/exit-ish).
* :func:`winrm_run_powershell` — async entry point for one-shot PowerShell.
* :func:`make_post_ex_remote_runner` — factory returning a
  ``RemoteRunner`` callable suitable for the post-ex executors.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Awaitable, Callable, Optional

from adscan_core import telemetry
from adscan_core.rich_output import print_error, print_info_verbose
from adscan_core.sensitive import mark_sensitive

from adscan_internal.services.post_exploitation import FootholdContext
from adscan_internal.services.posture_sink import PostureSink
from adscan_core.rich_output import print_exception

if TYPE_CHECKING:  # pragma: no cover
    from adscan_internal.services.domain_posture import DomainPosture


# Public type alias mirrors the one declared in the technique scaffolds.
RemoteRunner = Callable[[FootholdContext, str], Awaitable[str]]


@dataclass(frozen=True)
class WinRMResult:
    """Structured WinRM PowerShell execution outcome.

    ``had_errors`` is the closest analogue to a non-zero exit code that
    PSRP exposes — pypsrp surfaces error/warning streams instead of a
    classic UNIX exit status.
    """

    stdout: str
    stderr: str
    had_errors: bool


async def winrm_run_powershell(
    *,
    domain: str,
    host: str,
    username: str,
    secret: str,
    script: str,
    timeout: int
    | None = None,  # honored by underlying client config; kept for API symmetry
    auth_mode: str = "auto",
    operation_name: str = "post_ex_remote_runner",
    posture_sink: Optional[PostureSink] = None,
    posture_snapshot: Optional["DomainPosture"] = None,
    domain_for_posture: Optional[str] = None,
) -> WinRMResult:
    """Execute a PowerShell script over WinRM and return structured output.

    The implementation delegates to
    :class:`adscan_internal.services.winrm_psrp_service.WinRMPSRPService`,
    which encapsulates NTLM/Kerberos negotiation, hash-as-password
    handling, and the GSSAPI ccache plumbing. ``timeout`` is reserved for
    a future native transport — pypsrp currently uses its built-in
    request timeout.
    """
    # Local import to keep this module importable from contexts that do
    # not have pypsrp installed (e.g. unit tests that exercise the
    # post-ex catalog without touching the network).
    from adscan_internal.services.winrm_psrp_service import (  # noqa: PLC0415
        WinRMPSRPError,
        WinRMPSRPService,
    )

    _ = timeout  # see docstring — reserved.
    masked_host = mark_sensitive(host, "host")
    print_info_verbose(
        f"[winrm_transport] PSRP exec on {masked_host} ({operation_name})"
    )
    service = WinRMPSRPService(
        domain=domain,
        host=host,
        username=username,
        password=secret,
        auth_mode=auth_mode,
        posture_sink=posture_sink,
        posture_snapshot=posture_snapshot,
        domain_for_posture=domain_for_posture or domain,
    )
    try:
        result = await service.async_execute_powershell(
            script,
            operation_name=operation_name,
        )
    except WinRMPSRPError as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(f"[winrm_transport] PSRP failure on {masked_host}: {exc}")
        raise
    except Exception as exc:  # noqa: BLE001 — telemetry sink
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(f"[winrm_transport] unexpected error on {masked_host}: {exc}")
        raise

    return WinRMResult(
        stdout=result.stdout or "",
        stderr=result.stderr or "",
        had_errors=bool(result.had_errors),
    )


def make_post_ex_remote_runner(
    *,
    secret_resolver: Callable[[FootholdContext], str],
    auth_mode: str = "auto",
    posture_sink: Optional[PostureSink] = None,
    posture_snapshot: Optional["DomainPosture"] = None,
    domain_for_posture: Optional[str] = None,
) -> RemoteRunner:
    """Build a ``RemoteRunner`` suitable for the post-ex executor contract.

    ``secret_resolver`` receives the :class:`FootholdContext` and must
    return the raw password, NT hash, or absolute path to a Kerberos
    ccache associated with ``context.auth_credential_ref``. This keeps
    the credential store opaque to the transport layer.
    """

    async def _runner(context: FootholdContext, command: str) -> str:
        secret = secret_resolver(context)
        result = await winrm_run_powershell(
            domain=context.domain,
            host=context.target_host,
            username=context.auth_username,
            secret=secret,
            script=command,
            auth_mode=auth_mode,
            operation_name=f"post_ex:{context.protocol.value}",
            posture_sink=posture_sink,
            posture_snapshot=posture_snapshot,
            domain_for_posture=domain_for_posture or context.domain,
        )
        if result.had_errors and not result.stdout:
            # Surface stderr to the caller so the technique can decide
            # whether it counts as FAILED_EXECUTION vs FAILED_NO_DATA.
            return result.stderr
        return result.stdout

    return _runner


__all__ = [
    "RemoteRunner",
    "WinRMResult",
    "make_post_ex_remote_runner",
    "winrm_run_powershell",
]
