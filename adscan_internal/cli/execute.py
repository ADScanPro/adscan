"""Non-interactive single-verb runner — ``adscan execute <verb> [-- passthrough]``.

``adscan execute`` exposes the interactive REPL's ``do_<verb>`` commands so a
single action can run from the host shell without entering the persistent
workbench. It is the scripting / smoke-test / demo companion to the interactive
``adscan start``: one verb, sensible defaults, fully non-interactive, then exit.

Design (all four properties hold by construction):

1. **Registry-derived, not hand-listed.** The set of verbs ``execute`` can run is
   derived from :class:`adscan.PentestShell` ``do_<verb>`` reflection plus the
   REPL alias normaliser. Adding a ``do_<verb>`` surfaces in ``execute`` the
   moment it is allowlisted — no second list to maintain. ``--list`` prints the
   available verbs with help auto-generated from the same source.

2. **Allowlist + prerequisites.** Not every ``do_*`` is safe standalone — many
   are session-only (``help``, ``exit``, ``set``) or need prior collection
   (``attack_paths``, ``dcsync``). :data:`EXECUTE_SAFE_VERBS` is the conservative
   allowlist; each entry declares what context the verb needs so a verb run
   without its prerequisite fails *gracefully* ("needs collection first; run
   ``adscan ci``") instead of crashing.

3. **Bootstrap via reuse.** Context is established by REUSING the ``adscan ci``
   bootstrap: the shared session preflight, the same auto/non-interactive mode,
   the same ephemeral-vs-named workspace machinery, the same DNS + credential +
   posture preflight the interactive shell runs. ``execute`` never reimplements
   any of it.

4. **Non-interactive by construction.** ``enable_auto_mode`` + the ``ci`` env
   markers are set exactly as ``adscan ci`` does, so every prompt auto-resolves
   to a safe default through the existing centralized helpers. Any required
   choice must come from a session flag or the verb passthrough.
"""

from __future__ import annotations

import os
import shutil
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from adscan_internal import (
    print_error,
    print_info,
    print_success,
    print_warning,
    telemetry,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.cli.session_preflight import (
    SessionPreflightConfig,
    SessionPreflightDeps,
    run_session_preflight,
)


# --------------------------------------------------------------------------- #
# Allowlist + prerequisite model
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ExecuteVerbSpec:
    """Declares how a REPL verb participates in ``adscan execute``.

    Attributes:
        needs_domain: The verb reads the target domain from session context;
            ``execute`` requires ``--domain`` (and resolves the DC) before
            invoking it.
        needs_auth: The verb authenticates against the DC; ``execute`` requires
            credentials (``--username`` + ``--password``) and seeds them into
            the workspace credential store before invoking it.
        needs_collection: The verb consumes a prior scan's collected data
            (attack graph, enumerated users). ``execute`` cannot synthesise this
            in a one-shot run; the verb is offered but fails gracefully with a
            pointer to ``adscan ci`` / the prerequisite when the data is absent.
        summary: One-line operator-facing description for ``--list``. Falls back
            to the ``do_<verb>`` docstring first line when empty.
    """

    needs_domain: bool = False
    needs_auth: bool = False
    needs_collection: bool = False
    summary: str = ""


# Conservative, easy-to-extend allowlist. Start with clearly-safe verbs that
# either need no prior state or only need a domain + credentials (which
# ``execute`` establishes from the session flags). Adding a verb here is the
# single edit required to expose a new ``do_<verb>`` through ``execute``.
EXECUTE_SAFE_VERBS: dict[str, ExecuteVerbSpec] = {
    "check_dns": ExecuteVerbSpec(
        needs_domain=True,
        summary="Resolve a domain's DNS / locate its domain controllers.",
    ),
    "posture": ExecuteVerbSpec(
        needs_domain=True,
        summary="Inspect, probe, or clear the hardening posture for a domain.",
    ),
    "enum_trusts": ExecuteVerbSpec(
        needs_domain=True,
        needs_auth=True,
        summary="Enumerate domain trusts (parent/child, external, forest).",
    ),
    "kerberoast": ExecuteVerbSpec(
        needs_domain=True,
        needs_auth=True,
        summary="Request SPN service tickets and auto-crack the hashes.",
    ),
    "asreproast": ExecuteVerbSpec(
        needs_domain=True,
        needs_auth=True,
        summary="Roast accounts with Kerberos pre-auth disabled.",
    ),
    "smb_shares": ExecuteVerbSpec(
        needs_domain=True,
        needs_auth=True,
        summary="Enumerate SMB shares and effective access across the domain.",
    ),
    "search_adcs": ExecuteVerbSpec(
        needs_domain=True,
        needs_auth=True,
        summary="Enumerate ADCS templates and ESC findings.",
    ),
}


# --------------------------------------------------------------------------- #
# Config + dependency injection (mirrors adscan_internal/cli/ci.py)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ExecuteConfig:
    """Parsed inputs for one ``adscan execute`` invocation.

    Attributes:
        verb: Canonical verb name (after alias normalisation).
        passthrough: Remaining tokens forwarded verbatim to ``do_<verb>``.
        domain: Target domain (``-d/--domain``).
        dc_ip: DC / PDC IP (``--dc-ip``).
        username: Auth username (``-u/--username``).
        password: Auth password / hash (``-p/--password``).
        workspace: Named workspace to persist into; ``None`` → ephemeral temp.
        interface: Network interface for myip auto-config.
        keep_workspace: Retain an auto-created ephemeral workspace on exit.
        requested_pro: PRO licence requested for this run.
    """

    verb: str
    passthrough: tuple[str, ...] = ()
    domain: Optional[str] = None
    dc_ip: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    workspace: Optional[str] = None
    interface: Optional[str] = None
    keep_workspace: bool = False
    requested_pro: bool = False


@dataclass(frozen=True)
class ExecuteDeps:
    """Injected dependencies — keeps this module decoupled from ``adscan.py``."""

    enable_auto_mode: Callable[[], None]
    build_preflight_args: Callable[[], object]
    handle_check: Callable[[object], bool]
    get_last_check_extra: Callable[[], dict[str, object]]
    track_docs_link_shown: Callable[[str, str], None]
    resolve_license_mode: Callable[[bool], object]
    create_shell: Callable[[object, object], object]
    console: object
    exit: Callable[[int], None]
    # Lazily resolved so importing this module never imports the monolith.
    repl_verbs: Callable[[], set[str]] = field(
        default_factory=lambda: _default_repl_verbs
    )


def _default_repl_verbs() -> set[str]:
    """Reflect every ``do_<verb>`` exposed by ``PentestShell`` (lazy import)."""
    from adscan import PentestShell  # noqa: PLC0415 — avoid importing monolith at module load

    return {
        name[len("do_"):]
        for name in dir(PentestShell)
        if name.startswith("do_") and callable(getattr(PentestShell, name, None))
    }


# --------------------------------------------------------------------------- #
# Verb resolution
# --------------------------------------------------------------------------- #


def normalize_execute_verb(raw: str, known_verbs: set[str]) -> str:
    """Resolve a user-typed verb to its canonical ``do_<verb>`` name.

    Reuses the REPL alias normaliser so ``execute`` and the interactive shell
    agree on aliases (``report`` → ``deliver``, ``start auth`` → ``start_auth``).

    Args:
        raw: The verb token the user typed.
        known_verbs: The set of canonical REPL verbs (for alias gating).

    Returns:
        The canonical verb name, or the lowered input when no alias applies.
    """
    from adscan_internal.cli.common import normalize_command_alias  # noqa: PLC0415

    cmd = (raw or "").strip().lower()
    mapped, _args, used = normalize_command_alias(cmd, [], known_commands=known_verbs)
    return mapped if used else cmd


@dataclass(frozen=True)
class VerbResolution:
    """Outcome of resolving a requested verb against the registry + allowlist."""

    ok: bool
    verb: str
    spec: Optional[ExecuteVerbSpec]
    reason: str = ""


def resolve_execute_verb(
    raw_verb: str,
    *,
    known_verbs: set[str],
) -> VerbResolution:
    """Resolve and validate a requested verb.

    Three failure modes, each surfaced with a clear, non-crashing reason:

    * the verb does not exist as a ``do_<verb>`` at all → typo / wrong name;
    * the verb exists but is not on the standalone-safe allowlist → it is a
      session-only or not-yet-vetted verb;
    * (success) the verb is allowlisted → returns its :class:`ExecuteVerbSpec`.
    """
    verb = normalize_execute_verb(raw_verb, known_verbs)
    if not verb:
        return VerbResolution(False, verb, None, "No verb provided.")

    spec = EXECUTE_SAFE_VERBS.get(verb)
    if spec is not None:
        # Defensive: an allowlisted verb whose do_<verb> was renamed/removed.
        if verb not in known_verbs:
            return VerbResolution(
                False,
                verb,
                None,
                f"'{verb}' is allowlisted but PentestShell.do_{verb} no longer exists.",
            )
        return VerbResolution(True, verb, spec)

    if verb in known_verbs:
        return VerbResolution(
            False,
            verb,
            None,
            (
                f"'{verb}' is a REPL command but is not enabled for standalone "
                f"execution. Run it inside `adscan start`, or open a request to "
                f"add it to the execute allowlist."
            ),
        )

    return VerbResolution(
        False,
        verb,
        None,
        f"Unknown verb '{verb}'. Run `adscan execute --list` to see available verbs.",
    )


def _verb_summary(verb: str, spec: ExecuteVerbSpec) -> str:
    """Best summary for a verb: curated text, else the do_<verb> docstring."""
    if spec.summary:
        return spec.summary
    try:
        from adscan import PentestShell  # noqa: PLC0415

        method = getattr(PentestShell, f"do_{verb}", None)
        doc = (getattr(method, "__doc__", "") or "").strip()
        if doc:
            return doc.splitlines()[0].strip()
    except Exception:  # noqa: BLE001 — help text is best-effort
        pass
    return ""


def list_execute_verbs() -> int:
    """Render the available verbs + auto-generated help. Returns an exit code."""
    from rich.table import Table  # noqa: PLC0415
    from rich import box as _box  # noqa: PLC0415
    from adscan_core.rich_output import get_console, print_panel  # noqa: PLC0415

    table = Table(box=_box.SIMPLE_HEAD, expand=True, show_edge=False)
    table.add_column("Verb", style="bold", no_wrap=True)
    table.add_column("Needs", no_wrap=True)
    table.add_column("What it does")

    for verb in sorted(EXECUTE_SAFE_VERBS):
        spec = EXECUTE_SAFE_VERBS[verb]
        needs: list[str] = []
        if spec.needs_domain:
            needs.append("domain")
        if spec.needs_auth:
            needs.append("creds")
        if spec.needs_collection:
            needs.append("prior scan")
        table.add_row(verb, ", ".join(needs) or "-", _verb_summary(verb, spec))

    print_panel(
        table,
        title="adscan execute · available verbs",
        subtitle="Usage: adscan execute <verb> -d <domain> [--dc-ip IP] [-u USER -p PASS] [-- ARGS]",
        border_style="cyan",
    )
    get_console()  # ensure the shared TeeConsole is initialised for recording
    return 0


# --------------------------------------------------------------------------- #
# Context bootstrap
# --------------------------------------------------------------------------- #


def _setup_workspace(shell: Any, config: ExecuteConfig) -> bool:
    """Establish the workspace, reusing the ``adscan ci`` ephemeral machinery.

    ``--workspace NAME`` → persist into that named workspace (loot survives,
    platform-ingestible). Omitted → an ephemeral ``exec-<id>`` temp workspace,
    auto-cleaned on exit unless ``--keep-workspace``.

    Returns ``True`` when the workspace was auto-created (ephemeral or freshly
    created named) so the caller knows whether to honour the cleanup contract.
    """
    from adscan_internal.workspaces import (  # noqa: PLC0415
        create_workspace_dir,
        write_initial_workspace_variables,
    )

    shell.ensure_workspaces_dir()
    created = False
    if config.workspace:
        ws_dir = os.path.join(shell.workspaces_dir, config.workspace)
        if not os.path.isdir(ws_dir):
            create_workspace_dir(shell.workspaces_dir, config.workspace)
            write_initial_workspace_variables(
                workspace_name=config.workspace,
                workspace_path=ws_dir,
                workspace_type=getattr(shell, "type", None) or "audit",
            )
            created = True
        shell.current_workspace = config.workspace
        shell.current_workspace_dir = ws_dir
        shell.load_workspace_data(ws_dir)
    else:
        ws = f"exec-{uuid.uuid4().hex[:6]}"
        ws_dir = os.path.join(shell.workspaces_dir, ws)
        os.makedirs(ws_dir, exist_ok=True)
        shell.current_workspace = ws
        shell.current_workspace_dir = ws_dir
        shell.load_workspace_data(ws_dir)
        created = True
    return created


def _cleanup_workspace(shell: Any, *, created: bool, keep: bool) -> None:
    """Honour the ephemeral-workspace retention contract (mirror of ci.py)."""
    if not created:
        return
    marked = mark_sensitive(str(shell.current_workspace or ""), "workspace")
    if keep:
        print_info(f"Workspace '{marked}' kept (--keep-workspace specified)")
        return
    try:
        if shell.current_workspace_dir:
            shutil.rmtree(shell.current_workspace_dir)
        print_success(f"Ephemeral workspace '{marked}' deleted")
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning(f"Could not remove ephemeral workspace '{marked}'.")


def _establish_domain_context(shell: Any, config: ExecuteConfig) -> bool:
    """Resolve the domain → DC context the verb needs (DNS + posture).

    Reuses ``shell.do_check_dns`` (which seeds ``domains_data[domain]`` with the
    discovered DCs / PDC) and the centralized ``ensure_posture_fresh`` guard.
    Returns ``False`` with a clear message when the domain cannot be resolved.
    """
    domain = (config.domain or "").strip()
    if not domain:
        print_error("This verb needs a target domain. Pass -d/--domain.")
        return False

    # DNS resolution + DC discovery. do_check_dns seeds domains_data[domain].
    if not shell.do_check_dns(domain, config.dc_ip):
        print_error(
            "Could not resolve the domain or locate its domain controllers. "
            "Check DNS reachability (-d/--domain, --dc-ip) and try again."
        )
        return False

    # Resolve the DC IP for posture; prefer the explicit flag, fall back to
    # whatever do_check_dns discovered (never read raw dc_ip — use the SSOT).
    from adscan_internal.models.domain import resolve_dc_ip  # noqa: PLC0415

    domain_data = (shell.domains_data or {}).get(domain, {}) or {}
    dc_ip = (config.dc_ip or "").strip() or resolve_dc_ip(domain_data) or ""

    # Posture preflight — idempotent, best-effort, adapts auth automatically.
    try:
        import asyncio  # noqa: PLC0415

        from adscan_internal.services.posture_orchestration import (  # noqa: PLC0415
            ensure_posture_fresh,
        )
        from adscan_internal.services.posture_probe import (  # noqa: PLC0415
            ProbeCredentials,
            ProbePhase,
        )

        creds = None
        phase = ProbePhase.UNAUTH
        if config.username and config.password:
            creds = ProbeCredentials(
                username=str(config.username), password=str(config.password)
            )
            phase = ProbePhase.AUTH
        if dc_ip:
            asyncio.run(
                ensure_posture_fresh(
                    shell,
                    domain=domain,
                    dc_ip=dc_ip,
                    creds=creds,
                    phase=phase,
                )
            )
    except Exception as exc:  # noqa: BLE001 — posture is best-effort, never blocks
        telemetry.capture_exception(exc)

    shell.current_domain = domain
    return True


def _establish_credentials(shell: Any, config: ExecuteConfig) -> bool:
    """Seed the auth credential into the workspace credential store (SSOT path).

    Routes through ``adscan_internal.cli.creds.add_credential`` — the canonical
    credential bootstrap that verifies the credential, mints a posture-aware TGT,
    and flips the domain auth state — exactly what the auth verbs expect to find.
    Returns ``False`` (gracefully) when no usable credential was provided or it
    failed verification.
    """
    domain = (config.domain or "").strip()
    user = (config.username or "").strip()
    password = config.password or ""
    if not user or not password:
        print_error(
            "This verb authenticates against the DC. Pass -u/--username and "
            "-p/--password."
        )
        return False

    from adscan_internal.cli.creds import add_credential  # noqa: PLC0415

    try:
        add_credential(
            shell,
            domain,
            user,
            password,
            prompt_for_user_privs_after=False,
            prompt_local_reuse_after=False,
            ui_silent=True,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error(
            f"Credential bootstrap failed for {mark_sensitive(user, 'user')}: {exc}"
        )
        return False

    domain_data = (shell.domains_data or {}).get(domain, {}) or {}
    if user.lower() not in {
        str(k).lower() for k in (domain_data.get("credentials", {}) or {})
    }:
        print_error(
            "The provided credential did not authenticate. Check the username, "
            "password/hash, and domain, then retry."
        )
        return False
    return True


def _check_collection_prerequisite(shell: Any, config: ExecuteConfig) -> bool:
    """Fail gracefully when a verb needs a prior scan's collected data.

    ``execute`` runs ONE verb; it does not run a full collection. A verb that
    consumes the attack graph / enumerated objects cannot be satisfied from a
    cold one-shot run, so we point the operator at the prerequisite instead of
    crashing deep inside the verb.
    """
    domain = (config.domain or "").strip()
    domain_data = (shell.domains_data or {}).get(domain, {}) or {}
    auth_state = str(domain_data.get("auth", "") or "")
    if auth_state in ("auth", "pwned", "with_users"):
        return True
    print_warning(
        "This verb needs data from a prior scan (enumerated objects / attack "
        "graph), which a one-shot `execute` run does not collect."
    )
    print_info(
        "Run a full scan first: `adscan ci auth -d <domain> --dc-ip <ip> "
        "-u <user> -p <pass> -w <workspace>`, then re-run `execute` against "
        "that same `--workspace`."
    )
    return False


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def _add_execute_session_flags(parser: Any) -> None:
    """Register the session flags shared by the subparser and the re-splitter.

    Single source of truth for the ``execute`` session-flag surface so the
    top-level parser and the passthrough re-splitter never drift.
    """
    import argparse  # noqa: PLC0415

    parser.add_argument(
        "--list",
        action="store_true",
        dest="list_verbs",
        help="List the verbs available to `execute` and exit.",
    )
    parser.add_argument("-d", "--domain", help="Target domain.")
    parser.add_argument("--dc-ip", dest="dc_ip", help="PDC/DC IP for the target domain.")
    parser.add_argument("-u", "--username", help="Auth username (for verbs that authenticate).")
    parser.add_argument("-p", "--password", help="Auth password or hash.")
    parser.add_argument(
        "-w", "--workspace",
        help="Named workspace to persist into (default: ephemeral temp, auto-cleaned).",
    )
    parser.add_argument("-i", "--interface", help="Network interface (myip auto-config).")
    parser.add_argument(
        "--keep-workspace",
        action="store_true",
        help="Keep an auto-created ephemeral workspace on exit.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output.")
    parser.add_argument("--debug", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--dev", action="store_true", help=argparse.SUPPRESS)


def add_execute_subparser(subparsers: Any) -> Any:
    """Register the ``execute`` subparser. Shared by container + launcher.

    Session flags reuse the ``ci`` arg surface (``-d``/``--dc-ip``/``-u``/
    ``-p``/``--workspace``/``-i``). The verb is the first positional; everything
    after it is captured as REMAINDER and re-split in :func:`config_from_args`
    so a session flag works whether it appears before or after the verb, and
    the rest forwards verbatim to ``do_<verb>``.
    """
    import argparse  # noqa: PLC0415

    parser = subparsers.add_parser(
        "execute",
        help="Run a single REPL command non-interactively (scripting / smoke-test).",
        description=(
            "Run ONE ADscan REPL command from the shell without entering the "
            "interactive workbench. Establishes the minimum session context "
            "(workspace, domain, credentials, posture) and invokes the verb.\n\n"
            "Examples:\n"
            "  adscan execute --list\n"
            "  adscan execute check_dns -d corp.local --dc-ip 10.0.0.1\n"
            "  adscan execute kerberoast -d corp.local --dc-ip 10.0.0.1 -u alice -p Pass\n"
            "  adscan execute posture -d corp.local --dc-ip 10.0.0.1 -- show"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_execute_session_flags(parser)
    parser.add_argument(
        "verb",
        nargs="?",
        help="REPL verb to run (see `adscan execute --list`).",
    )
    parser.add_argument(
        "rest",
        nargs=argparse.REMAINDER,
        help="Arguments forwarded verbatim to the verb (session flags may also appear here).",
    )
    return parser


def config_from_args(args: Any) -> ExecuteConfig:
    """Build an :class:`ExecuteConfig` from a parsed argparse namespace.

    ``argparse.REMAINDER`` after the ``verb`` positional captures EVERYTHING the
    operator typed after the verb — including session flags like ``-d corp.local``.
    We re-split that tail through a session-flag-only parser so flags work after
    the verb too; whatever the session parser does not recognise (the verb's own
    arguments, or anything after a ``--``) becomes the verb passthrough.
    """
    import argparse  # noqa: PLC0415

    tail = list(getattr(args, "rest", []) or [])
    # A leading "--" right after the verb is a pure passthrough separator.
    forced_passthrough: list[str] = []
    if "--" in tail:
        sep = tail.index("--")
        forced_passthrough = tail[sep + 1:]
        tail = tail[:sep]

    splitter = argparse.ArgumentParser(add_help=False)
    _add_execute_session_flags(splitter)
    tail_ns, leftover = splitter.parse_known_args(tail)

    # Top-level flags win when present; otherwise take the re-split tail value.
    def _pick(name: str, default=None):
        return getattr(args, name, None) or getattr(tail_ns, name, None) or default

    passthrough = list(leftover) + forced_passthrough
    return ExecuteConfig(
        verb=str(getattr(args, "verb", "") or ""),
        passthrough=tuple(passthrough),
        domain=_pick("domain"),
        dc_ip=_pick("dc_ip"),
        username=_pick("username"),
        password=_pick("password"),
        workspace=_pick("workspace"),
        interface=_pick("interface"),
        keep_workspace=bool(
            getattr(args, "keep_workspace", False)
            or getattr(tail_ns, "keep_workspace", False)
        ),
    )


def run_execute(*, config: ExecuteConfig, deps: ExecuteDeps) -> int:
    """Run a single REPL verb non-interactively. Returns a process exit code."""
    known_verbs = deps.repl_verbs()

    resolution = resolve_execute_verb(config.verb, known_verbs=known_verbs)
    if not resolution.ok:
        print_error(resolution.reason)
        print_info("Run `adscan execute --list` to see available verbs.")
        return 2
    spec = resolution.spec
    verb = resolution.verb
    assert spec is not None  # ok=True guarantees a spec

    # Non-interactive by construction — identical to `adscan ci`.
    os.environ.setdefault("ADSCAN_SESSION_ENV", "ci")
    os.environ["ADSCAN_NONINTERACTIVE"] = "1"
    deps.enable_auto_mode()

    # Shared session preflight (DNS validation, connectivity, tool sanity).
    run_session_preflight(
        config=SessionPreflightConfig(
            command_name="execute",
            docs_utm_medium="execute_preflight_failed",
            allow_unsafe_override=False,
        ),
        deps=SessionPreflightDeps(
            build_preflight_args=deps.build_preflight_args,
            handle_check=deps.handle_check,
            get_last_check_extra=deps.get_last_check_extra,
            track_docs_link_shown=deps.track_docs_link_shown,
            confirm_ask=lambda _prompt, _default: False,
            exit=deps.exit,
        ),
    )

    license_mode = deps.resolve_license_mode(config.requested_pro)
    shell = deps.create_shell(deps.console, license_mode)
    shell.session_command_type = "execute"
    shell.auto = True
    shell.type = getattr(shell, "type", None) or "audit"
    if config.interface:
        shell.interface = config.interface

    telemetry.capture(
        "execute_start",
        properties={"verb": verb, "ephemeral": not bool(config.workspace)},
    )

    created = _setup_workspace(shell, config)

    # Best-effort myip auto-config from the interface (mirrors ci.py).
    if config.interface:
        try:
            from adscan_internal.services.myip_staleness import (  # noqa: PLC0415
                check_and_refresh_myip,
            )

            check_and_refresh_myip(shell, context="execute_start")
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)

    exit_code = 1
    try:
        # 1) Domain → DC context (DNS + posture) when the verb needs it.
        if spec.needs_domain and not _establish_domain_context(shell, config):
            return 2
        # 2) Credentials when the verb authenticates.
        if spec.needs_auth and not _establish_credentials(shell, config):
            return 2
        # 3) Prior-collection guard (graceful, points at the prerequisite).
        if spec.needs_collection and not _check_collection_prerequisite(shell, config):
            return 3

        cmd_method = getattr(shell, f"do_{verb}", None)
        if not callable(cmd_method):  # pragma: no cover — resolution guards this
            print_error(f"Internal error: do_{verb} is not callable.")
            return 2

        # The REPL dispatches do_<verb>(arg_string); a verb that reads the
        # domain from context still expects it as the bare positional, so when
        # the operator gave no explicit passthrough we pass the domain (the
        # exact shape `do_kerberoast <domain>` / `do_posture show <domain>`
        # expect). An explicit passthrough always wins.
        import shlex as _shlex  # noqa: PLC0415

        if config.passthrough:
            arg_string = " ".join(
                _shlex.quote(a) if (" " in a or not a) else a
                for a in config.passthrough
            )
        elif spec.needs_domain:
            arg_string = str(config.domain or "")
        else:
            arg_string = ""

        print_info(
            f"Executing `{verb}` "
            f"(workspace: {mark_sensitive(str(shell.current_workspace or ''), 'workspace')})"
        )
        cmd_method(arg_string)
        exit_code = 0
    except KeyboardInterrupt:
        print_warning("Execution interrupted.")
        exit_code = 130
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error(f"Error executing '{verb}'.")
        exit_code = 1
    finally:
        _cleanup_workspace(
            shell, created=created, keep=bool(config.keep_workspace)
        )
        try:
            shell.do_exit(exit=False)
        except Exception:  # noqa: BLE001 — teardown is best-effort
            pass

    return exit_code
