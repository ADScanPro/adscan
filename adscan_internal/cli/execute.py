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

import difflib
import os
import shutil
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from adscan_internal import (
    print_error,
    print_exception,
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
        auth_from_workspace_owned: When ``needs_auth`` is set, allow the run to
            proceed WITHOUT explicit ``-u/-p`` if the positional start principal
            is already OWNED in the kept workspace with a resolvable stored
            credential (password / NT hash / ccache). Used by ``attack_paths``
            so the L3.5 loop can re-run a path from an owned principal without
            re-typing its password. ``-u/-p`` are still required when the start
            principal is not owned or has no stored secret.
        summary: One-line operator-facing description for ``--list``. Falls back
            to the ``do_<verb>`` docstring first line when empty.
    """

    needs_domain: bool = False
    needs_auth: bool = False
    needs_collection: bool = False
    auth_from_workspace_owned: bool = False
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
    "attack_paths": ExecuteVerbSpec(
        needs_domain=True,
        needs_auth=True,
        auth_from_workspace_owned=True,
        summary="Compute + execute attack paths from a collected workspace "
        "(execution offered only from OWNED start principals: the `owned` "
        "scope, or an explicit user that is owned). The L3.5 rung — run one "
        "attack (e.g. ESC7) from a kept workspace without a full `ci`.",
    ),
    "users": ExecuteVerbSpec(
        needs_domain=True,
        needs_collection=True,
        summary="Write the user inventories (enabled users, control exposure, "
        "domain-compromise enablers) for a collected domain.",
    ),
    "reset_attack_path_statuses": ExecuteVerbSpec(
        needs_domain=True,
        # Local workspace op (no DC auth): clears persisted attack-path outcomes
        # back to the fresh-run `theoretical` baseline. Needed before re-running
        # `execute attack_paths` for L3.5 — the non-interactive executor is
        # theoretical-only, so an already-attempted/exploited path is skipped
        # until it is reset.
        summary="Reset a domain's persisted attack-path statuses to the "
        "`theoretical` baseline (L3.5: re-arm a path for re-execution).",
    ),
}


# REPL scan-entry verbs that are intentionally NOT allowlisted: a full scan is
# not a "clearly-safe quick verb". When rejected they get bespoke recovery text
# routing to ``adscan ci`` (the non-interactive one-shot a user who typed
# ``adscan execute`` actually wants) rather than the generic allowlist advice.
_SCAN_ENTRY_VERBS: frozenset[str] = frozenset({"start_unauth", "start_auth"})


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
        if verb in _SCAN_ENTRY_VERBS:
            # Scan-entry verbs are deliberately not on the allowlist — a full
            # scan is not a "clearly-safe quick verb". A user who typed
            # ``adscan execute start_unauth`` wants a non-interactive one-shot
            # scan, whose true equivalent is ``adscan ci <mode>``. Name the
            # exact mode (auth/unauth) the verb maps to and point at the
            # runtime help for the required --type/--interface, then at the
            # interactive session.
            ci_mode = "unauth" if verb == "start_unauth" else "auth"
            return VerbResolution(
                False,
                verb,
                None,
                (
                    f"'{verb}' launches a full scan, which is not a standalone "
                    f"`execute` verb. For a non-interactive one-shot scan run "
                    f"`adscan ci {ci_mode}` (run `adscan ci --help` for the "
                    f"required --type/--interface and auth flags); for an "
                    f"interactive session run `adscan start`."
                ),
            )
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

    # Nothing matched. A near-miss on a real verb is the common case (the verb
    # the operator wanted exists under a different name), so name the closest
    # candidates instead of leaving them to guess from `--list`.
    suggestions = _suggest_verbs(verb, known_verbs=known_verbs)
    hint = f" Did you mean: {', '.join(suggestions)}?" if suggestions else ""
    return VerbResolution(
        False,
        verb,
        None,
        f"Unknown verb '{verb}'.{hint} Run `adscan execute --list` to see available verbs.",
    )


def _suggest_verbs(verb: str, *, known_verbs: set[str], limit: int = 3) -> list[str]:
    """Closest allowlisted verbs to a mistyped one (``enum_users`` → ``users``).

    Allowlisted verbs are proposed first because they are the ones ``execute``
    can actually run; only when none is close enough do we fall back to the
    wider REPL registry, so the operator at least learns the real name.
    """
    normalized = (verb or "").strip().lower()
    allowlisted = sorted(EXECUTE_SAFE_VERBS)
    # Containment ("enum_users" → "users") beats difflib's ratio, which ranks a
    # shared prefix ("enum_trusts") above the verb the operator actually meant.
    contained = [v for v in allowlisted if v in normalized or normalized in v]
    close = difflib.get_close_matches(normalized, allowlisted, n=limit, cutoff=0.6)
    ranked = contained + [v for v in close if v not in contained]
    if ranked:
        return ranked[:limit]
    return difflib.get_close_matches(normalized, sorted(known_verbs), n=limit, cutoff=0.7)


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
    from rich.text import Text  # noqa: PLC0415
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

    # The usage line lives in the panel BODY, not the subtitle: Rich truncates a
    # subtitle to the border width, which cut this one off mid-syntax — exactly
    # where the operator needed to read it. In the body it wraps instead.
    # Built with plain ``Text`` (never markup) so the bracketed optional
    # arguments are not parsed as Rich style tags.
    usage = Text("Usage: ", style="bold")
    usage.append(
        "adscan execute <verb> -d <domain> [--dc-ip IP] [-u USER -p PASS] "
        "[-w WORKSPACE] [-- VERB ARGS]"
    )
    example = Text("Example: ", style="bold")
    example.append("adscan execute kerberoast -d corp.local --dc-ip 10.0.0.1 -u alice -p 'S3cr3t!'")

    print_panel(
        [table, Text(""), usage, example],
        title="adscan execute · available verbs",
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


def _resolve_execute_dc_ip(shell: Any, config: ExecuteConfig) -> str:
    """The DC/KDC IP for this run: the explicit flag, else the domain record.

    Single source of truth for both the posture preflight and the credential
    bootstrap, so the address the operator passed on the command line cannot be
    known to one and missing from the other. Never reads ``dc_ip``/``pdc``
    directly — ``resolve_dc_ip`` owns that fallback chain.
    """
    from adscan_internal.models.domain import resolve_dc_ip  # noqa: PLC0415

    explicit = (config.dc_ip or "").strip()
    if explicit:
        return explicit
    domain = (config.domain or "").strip()
    domain_data = (getattr(shell, "domains_data", {}) or {}).get(domain, {}) or {}
    return (resolve_dc_ip(domain_data) or "").strip()


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
    # whatever do_check_dns seeded (never read raw dc_ip — use the SSOT).
    dc_ip = _resolve_execute_dc_ip(shell, config)

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
    The DC IP resolved for this run is handed over so verification has a KDC to
    talk to; without it ``add_credential`` can only skip verification.
    Returns ``False`` (gracefully) when no usable credential was provided or the
    DC rejected it.
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
    from adscan_internal.services.credentials.credential_origin import (  # noqa: PLC0415
        ORIGIN_AUTHENTICATED_SCAN,
    )

    dc_ip = _resolve_execute_dc_ip(shell, config)
    try:
        add_credential(
            shell,
            domain,
            user,
            password,
            pdc_ip=dc_ip or None,
            prompt_for_user_privs_after=False,
            prompt_local_reuse_after=False,
            ui_silent=True,
            # The operator's own login for this run — the INPUT to the
            # execution, not something it compromised. Stamping it keeps it out
            # of the compromised-credential counters and the report's
            # provenance table (see NON_COMPROMISE_ORIGINS).
            credential_origin=ORIGIN_AUTHENTICATED_SCAN,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(
            f"Credential bootstrap failed for {mark_sensitive(user, 'user')}: {exc}"
        )
        return False

    domain_data = (shell.domains_data or {}).get(domain, {}) or {}
    stored = user.lower() in {
        str(k).lower() for k in (domain_data.get("credentials", {}) or {})
    }
    verification_skipped = bool(
        getattr(shell, "_last_domain_credential_verification_skipped", False)
    )
    if stored:
        if verification_skipped:
            # The credential is usable; we simply had no KDC to check it against.
            # Say that, rather than letting the verb fail later with no context.
            print_warning(
                "Credential stored without verification: no domain controller IP "
                f"could be resolved for {mark_sensitive(domain, 'domain')}. Pass "
                "--dc-ip <DC_IP> to have it verified before the verb runs."
            )
        return True

    if verification_skipped:
        # Never claim the credential is wrong when nothing ever checked it.
        print_error(
            "Credential verification was skipped — no domain controller IP could "
            f"be resolved for {mark_sensitive(domain, 'domain')}. Pass --dc-ip "
            "<DC_IP> (or check DNS for the domain) and retry."
        )
        return False

    print_error(
        "The domain controller rejected the credential. Check the username, "
        "password/hash, and domain, then retry."
    )
    return False


# Value-taking flags in ``do_attack_paths`` (mirror of adscan.py); every other
# ``--flag`` is boolean. Used only to skip flags when locating the positional
# start principal for the workspace-owned credential gate.
_ATTACK_PATHS_VALUE_FLAGS: frozenset[str] = frozenset(
    {"--max", "--depth", "--path-steps"}
)


def _attack_paths_start_principals(
    passthrough: tuple[str, ...], *, domain: str
) -> tuple[list[str], bool]:
    """Extract the start principal(s) from an ``attack_paths`` passthrough.

    Mirrors the positional parsing in ``PentestShell.do_attack_paths``: the
    first positional is the domain, a trailing integer is a path index, and the
    remaining non-flag tokens are start principals. Flags (and the values of
    value-taking flags) are skipped so a start principal that follows a flag is
    still found.

    Args:
        passthrough: The verb passthrough tokens (what ``do_attack_paths`` parses).
        domain: The resolved target domain — dropped when it is the first
            positional (``attack_paths <domain> <user>``).

    Returns:
        ``(explicit_users, owned_scope)`` where ``owned_scope`` is True when the
        special ``owned`` token was requested.
    """
    positionals: list[str] = []
    tokens = list(passthrough)
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in _ATTACK_PATHS_VALUE_FLAGS:
            i += 2  # skip the flag and its value
            continue
        if tok.startswith("--"):
            i += 1  # boolean flag (or --flag=value)
            continue
        positionals.append(tok)
        i += 1

    start = positionals[1:] if positionals and positionals[0] == domain else positionals
    if start and start[-1].isdigit():
        start = start[:-1]  # trailing path index
    users = [t for t in start if not t.isdigit() and t.lower() != "owned"]
    owned_scope = any(t.lower() == "owned" for t in start)
    return users, owned_scope


def _resolve_workspace_owned_auth(shell: Any, config: ExecuteConfig) -> bool:
    """Whether the run may proceed WITHOUT ``-u/-p`` from the workspace store.

    Returns True only when the positional start principal is already OWNED in
    the loaded workspace AND has a resolvable stored credential — i.e. the
    attack-path execution can authenticate as it without any secret typed on the
    command line. Reuses the owned SSOT
    (``get_owned_domain_usernames_for_attack_paths``), the same owned-execution
    gate ``run_show_attack_paths`` applies (``_execution_allowed_for_start``),
    and the stored-credential resolver (``_get_stored_domain_credential_for_user``).
    A non-owned start principal, or one with no stored secret, returns False so
    the caller keeps requiring ``-u/-p``.
    """
    passthrough = tuple(config.passthrough)
    domain = (config.domain or "").strip() or (passthrough[0] if passthrough else "")
    if not domain:
        return False

    from adscan_internal.services.attack_graph_service import (  # noqa: PLC0415
        get_owned_domain_usernames_for_attack_paths,
    )
    from adscan_internal.cli.attack_graph_reports import (  # noqa: PLC0415
        _execution_allowed_for_start,
    )
    from adscan_internal.cli.attack_path_execution import (  # noqa: PLC0415
        _get_stored_domain_credential_for_user,
    )

    owned = get_owned_domain_usernames_for_attack_paths(shell, domain)
    owned_norm = {u.split("@", 1)[0].strip().lower() for u in owned}
    users, owned_scope = _attack_paths_start_principals(passthrough, domain=domain)

    domain_data = (getattr(shell, "domains_data", {}) or {}).get(domain, {}) or {}
    domain_auth = str(domain_data.get("auth", "") or "").strip().lower()

    if owned_scope:
        start_user_norm, start_users = "owned", None
    elif len(users) > 1:
        start_user_norm, start_users = "", users
    elif len(users) == 1:
        start_user_norm, start_users = users[0].split("@", 1)[0].strip().lower(), None
    else:
        start_user_norm, start_users = "", None  # domain scope

    # Gate: execution is only offered from principals we already control. This is
    # the exact predicate run_show_attack_paths uses — do not re-derive it.
    if not _execution_allowed_for_start(
        allow_execution=True,
        start_user_norm=start_user_norm,
        start_users=start_users,
        domain_auth=domain_auth,
        owned_norm=owned_norm,
    ):
        return False

    def _resolvable(user: str) -> bool:
        return bool(
            _get_stored_domain_credential_for_user(shell, domain=domain, username=user)
        )

    # owned scope / domain-pwned scope run from ANY owned user → one must be
    # resolvable; an explicit selection needs every named principal resolvable.
    if owned_scope or not users:
        return any(_resolvable(user) for user in owned)
    return all(_resolvable(user) for user in users)


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
            docs_placement="execute_preflight_failed",
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
        # 2) Credentials when the verb authenticates. When -u/-p are absent and
        #    the verb allows it, an OWNED start principal already in the kept
        #    workspace (with a resolvable stored secret) authenticates from the
        #    store — no need to re-type its password. Falls through to the
        #    require-`-u/-p` error otherwise.
        if spec.needs_auth:
            explicit_absent = not (config.username or config.password)
            if (
                explicit_absent
                and spec.auth_from_workspace_owned
                and _resolve_workspace_owned_auth(shell, config)
            ):
                print_info(
                    "Authenticating as the owned start principal using its "
                    "stored workspace credential (no -u/-p needed)."
                )
            elif not _establish_credentials(shell, config):
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
        # Always write the full traceback to adscan.debug.log (DEBUG-on-disk,
        # unconditional) so an `execute` failure is diagnosable from the log;
        # the console stays generic unless --debug/SECRET_MODE is on. Without
        # this the traceback reached ONLY PostHog and every `execute` error was
        # an opaque one-liner in the debug log.
        print_exception(exception=exc)
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
