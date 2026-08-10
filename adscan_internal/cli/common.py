"""Common CLI helpers for telemetry context, workspace selection, onboarding, and shared constants.

This module provides shared functionality used across CLI commands to avoid
circular dependencies and duplicate code.
"""

from __future__ import annotations

import hashlib
import inspect
from typing import Any, Callable, Literal

from adscan_core.outbound_links import cta_markup, cta_url
from adscan_core.lab_context import (
    build_lab_telemetry_fields,
    build_workspace_telemetry_fields,
)
from adscan_internal.path_utils import get_adscan_state_dir
from adscan_internal.telemetry import TELEMETRY_ID
from adscan_internal.rich_output import (
    mark_sensitive,
    print_info_debug,
    print_panel,
)
from rich.text import Text


# SECRET_MODE is a global flag that controls whether internal implementation
# details are shown. It is set in adscan.py during initialization.
# CLI modules should import this from here instead of adscan.py.
# This will be initialized by adscan.py on startup.
import os
from adscan_core.rich_output import print_exception

SECRET_MODE: bool = os.getenv("ADSCAN_SECRET_MODE") == "1"  # pylint: disable=invalid-name

_WORKSPACE_ONBOARDING_KEY = "workspace_onboarding"
_WORKSPACE_SCAN_STARTED_KEY = "start_scan_completed"
_WORKSPACE_FIRST_START_COMMAND_KEY = "first_start_command"
_WORKSPACE_SCAN_EVIDENCE_KEYS = {
    "auth",
    "pdc",
    "pdc_hostname",
    "dcs",
    "dcs_hostnames",
    "username",
    "password",
    "hash",
    "base_dn",
    "phase1_complete",
}

DomainContextPolicy = Literal[
    "auto_by_signature",
    "exempt",
    "requires_initialized_domain",
]

_DOMAIN_CONTEXT_PARAM_NAMES = {"domain", "target_domain", "domain_name"}
_COMMAND_DOMAIN_CONTEXT_POLICIES: dict[str, DomainContextPolicy] = {
    "ask": "exempt",
    "add_auths": "exempt",
    "attack_paths": "requires_initialized_domain",
    "reset_attack_path_statuses": "requires_initialized_domain",
    "attack_steps": "requires_initialized_domain",
    "bloodhound_attack_paths": "requires_initialized_domain",
    "cat": "exempt",
    "cd": "exempt",
    "check_dc_ntlm_auth_type": "requires_initialized_domain",
    "check_dns": "exempt",
    "clear": "exempt",
    "clear_all": "exempt",
    "clear_auths": "exempt",
    "clear_creds_and_auths": "exempt",
    "clear_poisoning": "exempt",
    "cp": "exempt",
    "cracking": "requires_initialized_domain",
    "cracking_history": "exempt",
    "creds": "exempt",
    "dcsync": "requires_initialized_domain",
    "download": "exempt",
    "dump_dpapi": "requires_initialized_domain",
    "dump_host": "requires_initialized_domain",
    "dump_lsa": "requires_initialized_domain",
    "dump_registries": "requires_initialized_domain",
    "dump_sam": "requires_initialized_domain",
    "enum_adcs_privs": "requires_initialized_domain",
    "enum_all_user_postauth_access": "requires_initialized_domain",
    "enum_all_user_privs": "requires_initialized_domain",
    "enumerate_user_aces": "requires_initialized_domain",
    "exit": "exempt",
    "export": "exempt",
    "generate_report": "exempt",
    "get_flags": "requires_initialized_domain",
    "help": "exempt",
    "info": "exempt",
    "initialize_report": "exempt",
    "is_computer_dc": "requires_initialized_domain",
    "is_user_dc": "requires_initialized_domain",
    "kerberoast_preauth": "requires_initialized_domain",
    "ls": "exempt",
    "massdns_report": "exempt",
    "mkdir": "exempt",
    "mssql_check_impersonate": "requires_initialized_domain",
    "mssql_impersonate": "requires_initialized_domain",
    "mssql_steal_ntlmv2": "requires_initialized_domain",
    "mv": "exempt",
    "netexec_cve_all": "requires_initialized_domain",
    "netexec_cve_dcs": "requires_initialized_domain",
    "quit": "exempt",
    "raise_child": "requires_initialized_domain",
    "poisoning": "exempt",
    "rm": "exempt",
    "session": "exempt",
    "set": "exempt",
    "smb_auth_shares": "requires_initialized_domain",
    "start_auth": "exempt",
    "start_unauth": "exempt",
    "stop_poisoning": "exempt",
    "system": "exempt",
    "unauth_scan": "requires_initialized_domain",
    "update": "exempt",
    "update_domain_data": "exempt",
    "update_resolv_conf": "exempt",
    "upload": "exempt",
    "user_postauth_access": "requires_initialized_domain",
    "validate_attack_graph": "requires_initialized_domain",
    "workspace": "exempt",
    # Reads a finished workspace off disk; it never touches the domain, so it
    # stays usable months later when the lab is long gone.
    "writeup": "exempt",
}
_AUTH_INIT_RECOMMENDED_COMMANDS = {
    "bloodhound_collector",
    "check_autologon",
    "check_firefox_credentials",
    "check_powershell_transcripts",
    "dcsync",
    "dump_dpapi",
    "dump_lsa",
    "dump_registries",
    "dump_sam",
    "enum_authenticated",
    "enum_configs",
    "enum_domain_auth",
    "enum_domain_auth_phase1",
    "generate_relay_list",
    "mssql_check_impersonate",
    "mssql_impersonate",
    "mssql_steal_ntlmv2",
    "gpp_autologin",
    "gpp_passwords",
    "smb_user_descriptions",
    "search_adcs",
    "show_adcs_cache",
    "secretsdump_registries",
    "show_powershell_history",
    "smb_auth_shares",
}
_UNAUTH_INIT_RECOMMENDED_COMMANDS = {
    "asreproast",
    "enum_with_users",
    "kerberoast",
    "kerberoast_preauth",
    "kerberos_enum_users",
    "ldap_anonymous",
    "smb_guest_shares",
    "rid_cycling",
    "smb_scan",
    "spraying",
    "unauth_scan",
}
_COMMAND_INITIALIZER_RECOMMENDATIONS: dict[str, str] = {
    **{command_name: "start_auth" for command_name in _AUTH_INIT_RECOMMENDED_COMMANDS},
    **{
        command_name: "start_unauth"
        for command_name in _UNAUTH_INIT_RECOMMENDED_COMMANDS
    },
}


def build_telemetry_context(
    *,
    shell: Any,
    trigger: str,
) -> dict[str, Any]:
    """Build telemetry context dictionary from shell state.

    This helper extracts workspace and lab information from a shell instance
    and builds a standardized telemetry context dictionary.

    Args:
        shell: Shell instance with workspace attributes (current_workspace, type,
               lab_provider, lab_name, lab_name_whitelisted).
        trigger: Telemetry change trigger (e.g., "session_start", "ci_start").

    Returns:
        Dictionary with telemetry context including workspace_id_hash,
        workspace_type, lab_provider, lab_name, lab_name_whitelisted, and
        telemetry_change_trigger.
    """
    telemetry_context: dict[str, Any] = {}

    if getattr(shell, "current_workspace", None):
        workspace_unique_id = f"{TELEMETRY_ID}:{shell.current_workspace}"
        telemetry_context["workspace_id_hash"] = hashlib.sha256(
            workspace_unique_id.encode()
        ).hexdigest()[:12]

    telemetry_context.update(
        build_workspace_telemetry_fields(workspace_type=getattr(shell, "type", None))
    )

    telemetry_context.update(build_lab_event_fields(shell=shell, include_slug=False))

    telemetry_context["telemetry_change_trigger"] = trigger

    return telemetry_context


def build_lab_event_fields(*, shell: Any, include_slug: bool = True) -> dict[str, Any]:
    """Build normalized lab telemetry fields for event payloads.

    Args:
        shell: Shell instance that may expose ``lab_provider``, ``lab_name``,
            ``lab_name_whitelisted`` and optional ``_get_lab_slug``.
        include_slug: Whether to include ``lab_slug``.

    Returns:
        Dictionary with normalized lab context fields according to privacy rules.
    """
    lab_slug: str | None = None
    if include_slug:
        slug_getter = getattr(shell, "_get_lab_slug", None)
        if callable(slug_getter):
            try:
                lab_slug = slug_getter()
            except Exception:
                lab_slug = None

    return build_lab_telemetry_fields(
        lab_provider=getattr(shell, "lab_provider", None),
        lab_name=getattr(shell, "lab_name", None),
        lab_name_whitelisted=getattr(shell, "lab_name_whitelisted", None),
        include_slug=include_slug,
        lab_slug=lab_slug,
    ) | (
        {"lab_confirmation_state": str(getattr(shell, "lab_confirmation_state", None))}
        if getattr(shell, "lab_confirmation_state", None)
        else {}
    )


def is_first_run() -> bool:
    """Check if this is the first time running ADscan.

    Returns:
        True if first run, False otherwise.
    """
    # Use persisted state (mounted from host in Docker-mode) so the panel is only shown once.
    flag_file = get_adscan_state_dir() / ".first_run_complete"
    return not flag_file.exists()


def mark_first_run_complete() -> None:
    """Mark first run as complete by creating flag file."""
    flag_file = get_adscan_state_dir() / ".first_run_complete"
    try:
        flag_file.parent.mkdir(parents=True, exist_ok=True)
        flag_file.touch()
    except Exception:
        # Silently fail if can't create flag (non-critical)
        pass


def _get_workspace_onboarding_state(shell: Any) -> dict[str, Any]:
    """Return the mutable onboarding state stored in workspace variables."""
    variables = getattr(shell, "variables", None)
    if not isinstance(variables, dict):
        variables = {}
        setattr(shell, "variables", variables)

    onboarding_state = variables.get(_WORKSPACE_ONBOARDING_KEY)
    if not isinstance(onboarding_state, dict):
        onboarding_state = {}
        variables[_WORKSPACE_ONBOARDING_KEY] = onboarding_state

    return onboarding_state


def _workspace_has_scan_evidence(shell: Any) -> bool:
    """Return ``True`` when the workspace already contains scan-derived state.

    This protects existing workspaces created before the onboarding state key
    existed. Mature workspaces should not start showing the getting-started
    panel again just because the new flag is missing.
    """
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return False

    for domain_data in domains_data.values():
        if not isinstance(domain_data, dict):
            continue
        for key in _WORKSPACE_SCAN_EVIDENCE_KEYS:
            value = domain_data.get(key)
            if value in (None, "", [], {}, False):
                continue
            return True
    return False


def should_show_workspace_getting_started(shell: Any) -> bool:
    """Return whether the getting-started helper should still be shown.

    The helper remains visible until the operator has successfully started an
    authenticated or unauthenticated scan in the workspace. For legacy
    workspaces, existing scan evidence suppresses the helper automatically.
    """
    if not getattr(shell, "current_workspace", None):
        return False

    onboarding_state = _get_workspace_onboarding_state(shell)
    if onboarding_state.get(_WORKSPACE_SCAN_STARTED_KEY):
        return False

    return not _workspace_has_scan_evidence(shell)


def mark_workspace_start_scan_completed(shell: Any, command_name: str) -> None:
    """Persist that the workspace has already launched its first scan flow."""
    onboarding_state = _get_workspace_onboarding_state(shell)
    onboarding_state[_WORKSPACE_SCAN_STARTED_KEY] = True
    onboarding_state.setdefault(_WORKSPACE_FIRST_START_COMMAND_KEY, command_name)


def show_first_run_helper(
    track_docs_link_shown: Any | None = None,
) -> None:
    """Show the getting-started helper until the workspace launches a scan.

    Args:
        track_docs_link_shown: Optional function to track when docs link is shown.
                              If provided, should accept (context: str, url: str).
    """
    helper_text = Text.from_markup(
        "💡 [bold]This workspace has not started a scan yet.[/bold]\n\n"
        "Commands to type:\n"
        "  • Start unauth scan: [cyan]start_unauth[/cyan]\n"
        "  • Start auth scan:   [cyan]start_auth[/cyan]\n"
        "  • Save more creds:   [cyan]creds save <domain> <username> <password_or_hash>[/cyan]\n"
        f"📚 Full documentation: {cta_markup('first_run')}\n"
        "   (Installation, guides, troubleshooting, and more)\n\n"
        "[dim]Tip: This panel disappears automatically after the first successful "
        "`start_unauth` or `start_auth` in this workspace.[/dim]"
    )

    print_panel(
        helper_text,
        title="[bold cyan]Getting Started[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    )

    # Track docs link shown if tracking function provided
    if track_docs_link_shown is not None:
        try:
            track_docs_link_shown("first_run", cta_url("first_run"))
        except Exception:
            # Silently fail if tracking fails (non-critical)
            pass


def resolve_command_context_domain(
    shell: Any,
    command_name: str,
    args_list: list[str],
) -> tuple[str | None, str]:
    """Resolve the most relevant domain for command-context logging."""
    try:
        if args_list:
            arg0 = (args_list[0] or "").strip()
            if arg0:
                if arg0 in getattr(shell, "domains_data", {}):
                    return arg0, "arg0_domains_data"
                if arg0 in getattr(shell, "domains", []):
                    return arg0, "arg0_domains"
        current_domain = getattr(shell, "domain", None)
        if current_domain and current_domain in getattr(shell, "domains_data", {}):
            return current_domain, "current_domain"
        if args_list:
            arg0 = (args_list[0] or "").strip()
            if (
                arg0
                and "." in arg0
                and not arg0.startswith("-")
                and command_name not in {"set", "workspace", "session", "help"}
            ):
                return arg0, "arg0_fallback"
        # Secondary safety net: when the shell carries exactly one domain in
        # ``domains_data`` and nothing else resolved (e.g. a workspace saved by
        # an older ADscan that never persisted ``shell.domain``), that single
        # domain is unambiguous — adopt it so bare commands are not blocked.
        # The primary fix populates ``shell.domain`` at the start_unauth/
        # start_auth source; this only heals the reload edge case.
        domains_data = getattr(shell, "domains_data", None)
        if isinstance(domains_data, dict) and len(domains_data) == 1:
            only_domain = next(iter(domains_data))
            if only_domain:
                return only_domain, "single_loaded_domain"
    except Exception:
        pass
    return None, "none"


def resolve_repl_domain_or_default(shell: Any, provided: str | None) -> str | None:
    """Resolve the domain a bare REPL command should act on (single source of truth).

    Every domain-taking ``do_*`` REPL command routes its first positional through
    this helper so the "no explicit domain" fallback behaves identically across
    the whole shell. Before this SSOT, only ``spraying`` / ``pre2k`` fell back to
    the active domain; the rest (``kerberoast``, ``asreproast``, ``timeroast``,
    the GPP scanners, the identity/computer inventories, ...) passed the empty
    positional straight to their ``run_*`` delegate, which then failed with
    ``Domain '' is not configured`` even when a domain was already selected.

    Resolution order (first match wins):

    1. ``provided`` — an explicit ``<domain>`` argument always wins (stripped).
    2. ``shell.domain`` — the active domain written by ``set_active_domain`` (the
       canonical bare-command default set by ``start_unauth`` / ``start_auth`` /
       ``creds`` on every entry point).
    3. ``shell.current_domain`` — the logical domain set by interactive domain
       selection / native collection (``activate_domain``). Checked as a second
       net so a workspace whose active context was established only through the
       selection UI still resolves.
    4. The single configured domain — when the workspace has EXACTLY ONE domain
       (in ``shell.domains``, else the loaded ``domains_data``), that domain is
       unambiguous and is adopted. This is the key generalization beyond the old
       ``spraying`` / ``pre2k`` behavior.
    5. ``None`` — genuinely ambiguous (multiple domains and none selected) or no
       domain configured at all. The caller keeps its existing "please
       select / configure a domain" path unchanged; this helper never silently
       picks one of several domains.

    Args:
        shell: The interactive shell instance.
        provided: The raw ``<domain>`` positional the operator passed (may be
            empty / ``None`` when the command was typed bare).

    Returns:
        The resolved domain string, or ``None`` when the choice is ambiguous.
    """
    explicit = str(provided or "").strip()
    if explicit:
        return explicit

    # The active domain context — prefer the SSOT ``shell.domain`` (the writer is
    # ``set_active_domain``), then the selection-UI ``shell.current_domain``.
    for attr in ("domain", "current_domain"):
        candidate = str(getattr(shell, attr, None) or "").strip()
        if candidate:
            return candidate

    # Exactly one configured domain -> unambiguous, adopt it. Prefer the
    # ``shell.domains`` list (what the ``run_*`` delegates validate against), and
    # fall back to ``domains_data`` to heal a workspace reloaded before the list
    # was repopulated.
    domains = getattr(shell, "domains", None)
    if isinstance(domains, (list, tuple)) and len(domains) == 1:
        only = str(domains[0] or "").strip()
        if only:
            return only

    domains_data = getattr(shell, "domains_data", None)
    if isinstance(domains_data, dict) and len(domains_data) == 1:
        only = str(next(iter(domains_data)) or "").strip()
        if only:
            return only

    return None


def resolve_effective_username_for_domain(
    shell: Any, domain: str, *, default: str = "N/A"
) -> str:
    """Return the username actually used to authenticate against ``domain`` (SSOT).

    A trusted domain reached across a forest trust has NO credential of its own —
    it is enumerated with the AUTH domain's credential over a cross-realm referral
    (``auth_domain`` != ``target_domain``). Every operation panel that shows a
    per-domain "Username" must therefore fall back to the auth domain's credential
    for such a domain, or it misrepresents an authenticated cross-realm scan as
    anonymous (``Username: N/A``) — the recurring UX defect across the collection,
    quick-credential-wins, LDAP-description, and other per-domain phase panels.

    Resolution (first match wins):
      1. ``domains_data[domain]["username"]`` when the TARGET domain has its own
         credential (a normally-authenticated domain).
      2. ``domains_data[shell.domain]["username"]`` — the ACTIVE auth domain's
         credential, used for a trusted domain enumerated via a cross-realm
         referral.
      3. ``default`` (``"N/A"``) when neither is known (a genuinely anonymous /
         unauthenticated context).

    Args:
        shell: The active shell (source of ``domains_data`` + the active
            ``shell.domain`` auth domain).
        domain: The TARGET domain the panel is about.
        default: The value returned when no credential is resolvable (kept as
            ``"N/A"`` so existing anonymous-context panels are unchanged).
    """
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return default

    def _clean(value: Any) -> str | None:
        text = str(value or "").strip()
        return text if text and text != "N/A" else None

    own = _clean((domains_data.get(domain) or {}).get("username"))
    if own:
        return own

    auth_domain = str(getattr(shell, "domain", None) or "").strip()
    if auth_domain and auth_domain != domain:
        auth_user = _clean((domains_data.get(auth_domain) or {}).get("username"))
        if auth_user:
            return auth_user

    return default


def set_active_domain(shell: Any, domain: str | None) -> None:
    """Set the shell's active domain context (single source of truth).

    ``shell.domain`` is the domain that bare REPL commands default to when the
    operator does not pass an explicit ``<domain>`` argument. It MUST be
    populated as soon as a domain has been resolved and locked — by either the
    unauthenticated (``start_unauth``) or the authenticated (``start_auth`` /
    ``add_credential``) entry point — otherwise subsequent commands fail with
    "Domain not configured; run start_unauth first" even though the domain is
    fully resolved in ``domains_data``.

    This helper is the ONLY place that should assign ``shell.domain`` so both
    paths stay in lockstep. It is idempotent and safe to call repeatedly.

    Args:
        shell: The interactive shell instance.
        domain: The resolved domain FQDN to make active. No-op when empty.
    """
    normalized = str(domain or "").strip().rstrip(".")
    if not normalized:
        return
    if not hasattr(shell, "domain"):
        return
    if getattr(shell, "domain", None) == normalized:
        return
    shell.domain = normalized
    try:
        print_info_debug(
            f"[domain-context] active domain set to {mark_sensitive(normalized, 'domain')}"
        )
    except Exception:
        pass


def ensure_shell_domain_context(shell: Any, target_domain: str) -> None:
    """Point the shell's logical domain context at ``target_domain`` (in-memory).

    ``shell.current_domain`` / ``shell.current_domain_dir`` are a SEPARATE pair of
    attributes from ``shell.domain`` (set by ``set_active_domain`` above) — they are
    what ``save_domain_data()`` (``workspaces/saver.py``) reads to resolve the
    on-disk domain directory for ``variables.json``. They are otherwise populated
    ONLY by the interactive domain-selection / workspace-UI commands and by
    ``run_native_collection`` (the authenticated collection path), via the
    canonical ``activate_domain`` SSOT (``workspaces/domains.py``).

    Any scan flow that reaches a ``save_domain_data()`` call (collector findings,
    machine-pwd rotation, ADCS detection state, …) without ever going through one
    of those entry points — most notably the UNAUTHENTICATED scan path
    (``do_unauth_scan`` / ``ask_for_unauth_scan``, ``cli/scan.py``), which only
    calls ``finalize_domain_context(make_active=False)`` and never touches
    ``current_domain``/``current_domain_dir`` — trips the "No active domain
    selected ... Cannot save domain data" guard and silently drops
    ``variables.json`` for the whole flow. Call this helper right after the
    domain/PDC IP is resolved (e.g. right after ``finalize_domain_context``) so
    every path that can reach ``save_domain_data()`` has the context set first.

    This helper is in-memory only (no I/O, safe on an unauthenticated context —
    ``activate_domain`` only resolves a filesystem path from the workspace dir +
    domain name, it does not assume any authenticated state). It is a no-op when
    the context is already on ``target_domain`` or no workspace dir is known.
    """
    ws_dir = getattr(shell, "current_workspace_dir", None)
    if not ws_dir:
        return
    if (
        getattr(shell, "current_domain_dir", None) is not None
        and getattr(shell, "current_domain", None) == target_domain
    ):
        return
    from adscan_internal.workspaces import activate_domain  # noqa: PLC0415

    activate_domain(
        shell,
        workspace_dir=ws_dir,
        domains_dir_name=getattr(shell, "domains_dir", "domains"),
        domain=target_domain,
    )


# Per-command secret POSITIONAL indices for the command-dispatch echo.
#
# The interactive shell echoes every dispatched command under ``--debug``. The
# operator/pentester MUST see the FULL cleartext command they ran (domain, IP,
# user, scan_mode, flags …) on screen and in their own session recording — so
# the echo is NOT redacted. Only the secret positional(s) are wrapped with
# ``mark_sensitive(arg, "password")``: the markers are invisible (zero-width),
# so the secret stays cleartext on the terminal while the telemetry EXPORT
# sanitizer scrubs exactly that value before upload.
#
# Index is into ``args_list`` (the tokens AFTER the command verb), counting
# POSITIONALS only (flags like ``-k`` / ``--debug`` are skipped when counting —
# see ``_FLAG_FREE_SECRET_COMMANDS`` below for the commands where that
# skipping is deliberately disabled). A command absent from this map has no
# secret positional → every arg cleartext.
#
# Built from a full survey of every ``do_*``/CLI-helper grammar that accepts a
# password, NT hash, or other credential as a raw positional (grep ``args =
# args.split()`` + the ``Usage:`` docstrings across ``adscan.py`` and
# ``adscan_internal/cli/*.py``):
#   - ``start_auth <domain> <ip> <user> <password>``            → index 3
#   - ``get_flags <domain> <username> <password>``               → index 2
#   - ``mssql_check_impersonate <domain> <host> <user> <pass>``  → index 3
#   - ``dump_sam <domain> <user> <password> <host> <islocal>``   → index 2
#   - ``dump_dpapi <domain> <user> <password> <host> <islocal>`` → index 2
#   - ``dump_lsa <domain> <user> <password> <host> <islocal>``   → index 2
#   - ``dump_lsass <domain> <user> <password> <host> <islocal>`` → index 2
#   - ``dcsync <domain> <username> <password>``                  → index 2
#   - ``cracking <type> <domain> <hash>``                         → index 2
#   - ``smb_auth_shares <domain> <username> <password>``         → index 2
#   - ``user_postauth_access <domain> <user> <pass>``            → index 2
#   - ``enumerate_user_aces <domain> <user> <password>``         → index 2
#   - ``enum_adcs_privs <domain> <user> <password>``             → index 2
_SECRET_POSITIONAL_INDICES: dict[str, tuple[int, ...]] = {
    "start_auth": (3,),
    "get_flags": (2,),
    "mssql_check_impersonate": (3,),
    "dump_sam": (2,),
    "dump_dpapi": (2,),
    "dump_lsa": (2,),
    "dump_lsass": (2,),
    "dcsync": (2,),
    "cracking": (2,),
    "smb_auth_shares": (2,),
    "user_postauth_access": (2,),
    "enumerate_user_aces": (2,),
    "enum_adcs_privs": (2,),
}

# Commands whose FIRST positional is a subcommand that shifts the secret index.
# Maps ``command -> {subcommand: (secret positional indices counted from arg0)}``.
#   - ``creds save|add <domain> <username> <credential> [host] [service]``
#     → after the ``save``/``add`` subcommand, the credential is positional 3
#     (the subcommand token itself counts as positional 0).
#   - ``session launch <smb|winrm> <host> <domain> <user> <password> [os]``
#     → after the ``launch`` subcommand, the password is positional 5.
#   - ``set password <value>`` / ``set hash <value>``
#     → the value is positional 1 (the ``password``/``hash`` token is 0).
_SECRET_POSITIONAL_BY_SUBCOMMAND: dict[str, dict[str, tuple[int, ...]]] = {
    "creds": {
        "save": (3,),
        "add": (3,),
    },
    "session": {
        "launch": (5,),
    },
    "set": {
        "password": (1,),
        "hash": (1,),
        # `set` is a generic <variable> <value> config setter (adscan.py
        # do_set) — NOT migrated to the flag grammar (see
        # docs/superpowers/plans/2026-07-21-repl-flag-argument-grammar.md
        # Investigation § 1: converting a 15-branch generic setter for 2
        # secret branches is not a real UX win). The variable name (the
        # first token) already acts as the "flag name" here, so this
        # dict is the equivalent robust-by-construction mechanism for
        # `set`. RULE: any NEW `set <variable>` branch added to
        # `adscan.py do_set` that stores a password/hash/secret MUST add
        # its variable name here in the SAME change — this is the one
        # place a future secret `set` variable can still silently drift,
        # exactly like the original bug this map fixed.
    },
}

# Commands whose entire grammar is raw ``args.split()`` positionals with a
# strict arg-count check — they have NO flag syntax at all. For these, a
# leading ``-`` in a positional VALUE (a strong password like
# ``-Str0ngP@ss!``, or a hash/credential that happens to start with a
# hyphen-shaped token) must NOT be misread as a CLI flag: the
# ``token.startswith("-")`` heuristic below exists only to skip REAL flags
# (``-k``, ``--debug``) on commands that mix flags and positionals, and
# misapplying it here shifts the positional count and lets the secret slip
# through unmarked. Every command key in the two maps above is flag-free
# today, so this is simply their union.
_FLAG_FREE_SECRET_COMMANDS: frozenset[str] = frozenset(_SECRET_POSITIONAL_INDICES) | frozenset(
    _SECRET_POSITIONAL_BY_SUBCOMMAND
)

# Global secret-bearing FLAG NAMES, recognized regardless of command. This is
# a defensive backstop — mirroring the inline ``pass=``/``password=`` form
# below — for any command whose grammar accepts the secret via a flag
# (``-p <value>`` / ``--password <value>``) instead of a bare positional.
# None of today's REPL commands mix flags with a credential positional (they
# are all covered by ``_FLAG_FREE_SECRET_COMMANDS`` above), but the launcher
# CLI already uses this exact spelling for ``adscan doctor``/``adscan
# execute`` (``-p``/``--password``) and a future REPL command could adopt the
# same grammar. When the CURRENT token exactly matches one of these names, the
# token immediately following it is treated as the secret VALUE and marked —
# independent of, and in addition to, the positional-index maps above.
_SECRET_FLAG_NAMES: frozenset[str] = frozenset(
    {
        "-p",
        "--password",
        "--pass",
        "-h",
        "--hash",
        "--hashes",
        "--ntlm-hash",
        "--ntlm",
        "--nthash",
        "--aes-key",
        "--aeskey",
    }
)


def redact_command_for_log(command_name: str, args_list: list[str]) -> str:
    """Build a debug echo of a CLI command line, marking ONLY secret positionals.

    The interactive shell echoes every dispatched command under ``--debug``. The
    operator must see the FULL cleartext command they ran — domain, IP, user,
    scan_mode, flags, everything — both on screen and in their own session
    recording. So this returns the command verbatim; the only transformation is
    wrapping the secret positional(s)/flag-value(s) with ``mark_sensitive(_,
    "password")``. Those markers are invisible zero-width characters, so the
    secret stays cleartext on the terminal while the telemetry export sanitizer
    scrubs exactly that value before upload.

    Three independent marking mechanisms run, any of which can mark a token:

    1. **Positional index** (:data:`_SECRET_POSITIONAL_INDICES` /
       :data:`_SECRET_POSITIONAL_BY_SUBCOMMAND`) — the primary mechanism for
       today's flag-free REPL grammar (``dcsync <domain> <user> <password>``,
       ...). For commands in :data:`_FLAG_FREE_SECRET_COMMANDS`, EVERY token
       counts as a positional (a value that happens to start with ``-`` is
       never misread as a flag).
    2. **Flag name** (:data:`_SECRET_FLAG_NAMES`) — a global backstop: when a
       token exactly matches a known secret flag spelling, the following
       token is marked, regardless of the command.
    3. **Inline ``pass=``/``password=``** — an existing defensive backstop for
       the inline credential form.

    A command with no entry in the maps and no recognized flag has no secret
    positional, so every argument is echoed in cleartext unchanged.

    Args:
        command_name: The resolved command verb (already alias-normalized).
        args_list: The tokenized arguments following the command.

    Returns:
        A single-line echo string safe to pass to ``print_info_debug``: full
        cleartext, with only the secret positional(s) ``mark_sensitive``-wrapped.
    """
    cmd = (command_name or "").lower()

    # Resolve which POSITIONAL indices (counted over non-flag tokens) are secret.
    secret_positional_indices: tuple[int, ...] = _SECRET_POSITIONAL_INDICES.get(cmd, ())
    sub_map = _SECRET_POSITIONAL_BY_SUBCOMMAND.get(cmd)
    if sub_map and args_list:
        first = (args_list[0] or "").strip().lower()
        secret_positional_indices = sub_map.get(first, secret_positional_indices)

    # Flag-free commands: every token is positional. A secret value starting
    # with "-" must never be misclassified as a CLI flag (see
    # ``_FLAG_FREE_SECRET_COMMANDS`` docstring above).
    treat_all_as_positional = cmd in _FLAG_FREE_SECRET_COMMANDS

    echoed: list[str] = []
    positional_idx = -1
    mark_next_as_flag_value = False
    for token in args_list:
        if mark_next_as_flag_value:
            echoed.append(mark_sensitive(token, "password"))
            mark_next_as_flag_value = False
            continue

        is_flag = (not treat_all_as_positional) and token.startswith("-")

        if is_flag and token.lower() in _SECRET_FLAG_NAMES:
            echoed.append(token)
            mark_next_as_flag_value = True
            continue

        if not is_flag:
            positional_idx += 1
        mark_this = (not is_flag) and positional_idx in secret_positional_indices
        # Defensive backstop: an inline credential form (``pass=…`` /
        # ``password=…``) is marked even if the index map missed it. The index
        # map is the primary mechanism; this only covers the obvious inline case.
        lowered = token.lower()
        if not is_flag and (
            lowered.startswith("pass=") or lowered.startswith("password=")
        ):
            prefix, _, value = token.partition("=")
            if value:
                echoed.append(f"{prefix}={mark_sensitive(value, 'password')}")
                continue
        if mark_this:
            echoed.append(mark_sensitive(token, "password"))
        else:
            echoed.append(token)
    if echoed:
        return f"{command_name} {' '.join(echoed)}"
    return command_name


def normalize_help_alias(
    command_name: str,
    args_list: list[str],
    *,
    known_commands: set[str] | None = None,
) -> tuple[str, list[str], bool]:
    """Normalize `command help`/`command -h` patterns into `help command`.

    Examples:
        - ``workspace help`` -> (``help``, [``workspace``], True)
        - ``workspace -h`` -> (``help``, [``workspace``], True)
        - ``workspace --help`` -> (``help``, [``workspace``], True)
    """
    cmd = (command_name or "").strip().lower()
    if cmd in {"", "help"}:
        return command_name, args_list, False
    if not args_list:
        return command_name, args_list, False

    first_arg = str(args_list[0] or "").strip().lower()
    if first_arg not in {"help", "-h", "--help"}:
        return command_name, args_list, False

    if known_commands is not None and cmd not in known_commands:
        return command_name, args_list, False

    # Keep backwards-compatible shape expected by do_help(arg_string)
    # while allowing extra context if user wrote e.g. `foo help bar`.
    normalized_args = [cmd]
    if len(args_list) > 1:
        normalized_args.extend(args_list[1:])
    return "help", normalized_args, True


def normalize_command_alias(
    command_name: str,
    args_list: list[str],
    *,
    known_commands: set[str] | None = None,
) -> tuple[str, list[str], bool]:
    """Normalize common CLI command aliases into canonical command names.

    Examples:
        - ``start auth`` -> (``start_auth``, [], True)
        - ``start unauth`` -> (``start_unauth``, [], True)
        - ``start-auth`` -> (``start_auth``, [...], True)
        - ``report`` / ``reporting`` / ``generate_report`` -> (``deliver``, [...], True)

    The reporting verbs (``report``, ``reporting``, ``generate_report``) are
    aliased onto ``deliver`` so the REPL exposes ONE report engine: the full
    Client Deliverable Kit (the user deselects in the deliver checkbox to get
    a report-only PDF). ``deliver`` is the canonical verb; these are the
    discoverable on-ramps an operator naturally types.

    ``?`` (bare or with a category argument) is aliased onto ``help`` — the
    universal help convention that ``cmd.Cmd`` maps by default but which this
    shell's custom dispatch would otherwise reject as an unknown command. So a
    new user's reflexive first keystroke ``?`` opens the help tree, and
    ``? <category>`` opens that category's help exactly like ``help <category>``.
    """
    cmd = (command_name or "").strip().lower()
    if not cmd:
        return command_name, args_list, False

    direct_aliases = {
        "report": "deliver",
        "reporting": "deliver",
        "generate_report": "deliver",
        "start-auth": "start_auth",
        "startauth": "start_auth",
        "start-unauth": "start_unauth",
        "startunauth": "start_unauth",
        "?": "help",
    }

    mapped_direct = direct_aliases.get(cmd)
    if mapped_direct:
        if known_commands is not None and mapped_direct not in known_commands:
            return command_name, args_list, False
        return mapped_direct, args_list, True

    if cmd != "start" or not args_list:
        return command_name, args_list, False

    first_arg = str(args_list[0] or "").strip().lower().replace("-", "_")
    split_aliases = {
        "auth": "start_auth",
        "unauth": "start_unauth",
    }
    mapped_split = split_aliases.get(first_arg)
    if not mapped_split:
        return command_name, args_list, False
    if known_commands is not None and mapped_split not in known_commands:
        return command_name, args_list, False

    return mapped_split, args_list[1:], True


def classify_command_domain_context_policy(
    command_name: str,
    command_method: Callable[..., Any] | None,
) -> tuple[DomainContextPolicy, str]:
    """Classify how a command should participate in domain-context gating.

    Args:
        command_name: Canonical CLI command name.
        command_method: Resolved ``do_*`` method for that command.

    Returns:
        Tuple ``(policy, source)`` where ``policy`` is one of:
        ``exempt``, ``requires_initialized_domain``, or ``auto_by_signature``.
        ``source`` explains whether the result came from explicit policy or
        method-signature inference.
    """
    normalized = str(command_name or "").strip().lower()
    explicit_policy = _COMMAND_DOMAIN_CONTEXT_POLICIES.get(normalized)
    if explicit_policy is not None:
        return explicit_policy, "explicit"
    if command_method is None:
        return "exempt", "fallback"

    try:
        signature = inspect.signature(command_method)
    except (TypeError, ValueError):
        return "exempt", "fallback"

    positional_params = [
        param
        for param in signature.parameters.values()
        if param.name != "self"
        and param.kind
        in {
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        }
    ]
    if not positional_params:
        return "exempt", "fallback"

    if positional_params[0].name in _DOMAIN_CONTEXT_PARAM_NAMES:
        return "auto_by_signature", "signature"

    return "exempt", "fallback"


def command_requires_initialized_domain_context(
    command_name: str,
    command_method: Callable[..., Any] | None,
) -> bool:
    """Return whether a CLI command depends on a pre-initialized domain context.

    Args:
        command_name: Canonical CLI command name.
        command_method: Resolved ``do_*`` method for that command.

    Returns:
        ``True`` when the command should only run after ``start_unauth`` or
        ``start_auth`` initialized the domain in ``domains_data``.
    """
    policy, _source = classify_command_domain_context_policy(
        command_name, command_method
    )
    return policy in {"auto_by_signature", "requires_initialized_domain"}


def resolve_domain_dir_on_disk(shell: Any, domain: str | None) -> str | None:
    """Return the domain sub-workspace directory when it exists on disk.

    The ``dir`` key in ``domains_data`` is a cache of a derivable fact: the
    per-domain directory under the active workspace. This derives it instead,
    so a workspace written before the entry was reconciled correctly is not
    permanently unusable. Pure read — it never writes back.

    Args:
        shell: Active shell instance.
        domain: Domain name to resolve.

    Returns:
        The absolute directory path when it exists, otherwise ``None``.
    """
    if not domain:
        return None

    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "").strip()
    if not workspace_dir:
        return None

    try:
        from adscan_internal.workspaces.domains import resolve_domain_paths

        domain_dir = resolve_domain_paths(
            workspace_dir,
            str(getattr(shell, "domains_dir", "domains") or "domains"),
            str(domain),
        ).domain_dir
    except Exception as exc:  # noqa: BLE001 - a guard must never raise
        print_exception(exception=exc)
        return None

    return domain_dir if os.path.isdir(domain_dir) else None


def is_domain_context_initialized(shell: Any, domain: str | None) -> bool:
    """Return whether the given domain already has the minimum initialized state.

    A domain counts as initialized when a DC is known for it (``pdc``) and its
    sub-workspace exists. The sub-workspace is normally recorded as the ``dir``
    key, but the on-disk directory is accepted as equivalent evidence so an
    older workspace whose ``dir`` key was never written still works.

    Args:
        shell: Active shell instance with ``domains_data``.
        domain: Domain name to validate.

    Returns:
        ``True`` when the domain exists in ``domains_data`` and includes the
        critical state created by ``start_unauth``/``start_auth``.
    """
    if not domain:
        return False

    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return False

    domain_state = domains_data.get(domain)
    if not isinstance(domain_state, dict):
        return False

    if not domain_state.get("pdc"):
        return False

    if domain_state.get("dir"):
        return True

    return bool(resolve_domain_dir_on_disk(shell, domain))


def _recommended_domain_initializer(command_name: str) -> str | None:
    """Return the best start command to suggest for a blocked domain command."""
    normalized = str(command_name or "").strip().lower()
    return _COMMAND_INITIALIZER_RECOMMENDATIONS.get(normalized)


def ensure_initialized_domain_context_for_command(
    shell: Any,
    *,
    command_name: str,
    args_list: list[str],
    command_method: Callable[..., Any] | None,
) -> bool:
    """Block domain commands until a domain was initialized by ``start_*``.

    Args:
        shell: Active shell instance.
        command_name: Canonical CLI command name.
        args_list: Parsed CLI arguments.
        command_method: Resolved ``do_*`` method for the command.

    Returns:
        ``True`` when the command may continue, ``False`` when execution should
        stop because the domain context has not been initialized yet.
    """
    if not command_requires_initialized_domain_context(command_name, command_method):
        return True

    domain, domain_source = resolve_command_context_domain(
        shell=shell,
        command_name=command_name,
        args_list=args_list,
    )
    if is_domain_context_initialized(shell, domain):
        return True

    marked_domain = mark_sensitive(str(domain or "Not resolved"), "domain")
    recommended_start_command = _recommended_domain_initializer(command_name)
    if recommended_start_command == "start_auth":
        starter_guidance = (
            "Run `start_auth` first to initialize the domain, validate DNS/DC, "
            "and verify credentials for this workflow."
        )
    elif recommended_start_command == "start_unauth":
        starter_guidance = (
            "Run `start_unauth` first to initialize the domain, discover the PDC, "
            "and create the per-domain workspace context."
        )
    else:
        starter_guidance = (
            "Run `start_unauth` first for unauthenticated initialization, or "
            "`start_auth` if you already have valid domain credentials."
        )

    print_panel(
        "\n".join(
            [
                "⚠️ Domain context not initialized in this workspace.",
                f"Command: {command_name}",
                f"Domain: {marked_domain}",
                f"Resolution source: {domain_source}",
                "",
                "This command depends on the domain entry, PDC, and subworkspace "
                "created by `start_unauth` / `start_auth`.",
                "",
                "Recommended workflow:",
                f"1) {starter_guidance}",
                f"2) Re-run `{command_name}` once the domain appears in `info` / `domains_data`.",
            ]
        ),
        title="[bold yellow]Initialize Domain First[/bold yellow]",
        border_style="yellow",
        expand=False,
    )

    from adscan_internal import print_instruction, telemetry
    from adscan_internal.interaction import is_non_interactive

    print_instruction(
        "Initialize the target first with `start_unauth` or `start_auth`, then rerun this command."
    )
    if recommended_start_command:
        print_instruction(f"Recommended next step: `{recommended_start_command}`")

    try:
        properties: dict[str, Any] = {
            "command": command_name,
            "domain": domain,
            "domain_source": domain_source,
            "recommended_start_command": recommended_start_command,
            "workspace_type": getattr(shell, "type", None),
            "auto_mode": getattr(shell, "auto", False),
            "scan_mode": getattr(shell, "scan_mode", None),
        }
        properties.update(build_lab_event_fields(shell=shell, include_slug=True))
        telemetry.capture("domain_command_requires_initialization", properties)
    except Exception as exc:  # pragma: no cover - telemetry best effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)

    if is_non_interactive(shell=shell):
        return False

    if not recommended_start_command:
        return False

    from rich.prompt import Confirm

    if not Confirm.ask(
        f"Do you want to run `{recommended_start_command}` now?",
        default=True,
    ):
        return False

    try:
        start_method = getattr(shell, f"do_{recommended_start_command}", None)
        if callable(start_method):
            print_info_debug(
                f"[cli] Launching recommended initializer {recommended_start_command} "
                f"for blocked command {command_name}"
            )
            start_method("")
    except Exception as exc:  # pragma: no cover - best effort handoff
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        raise

    return False


def build_cli_runtime_snapshot(
    *,
    shell: Any,
    command_name: str | None = None,
    args_list: list[str] | None = None,
) -> dict[str, Any]:
    """Build a normalized runtime snapshot shared by `info` and CLI command logging."""
    args = list(args_list or [])
    resolved_command = (command_name or "").strip()
    context_domain: str | None = None
    domain_source = "none"
    if resolved_command:
        context_domain, domain_source = resolve_command_context_domain(
            shell=shell,
            command_name=resolved_command,
            args_list=args,
        )
    elif getattr(shell, "domain", None):
        context_domain = str(getattr(shell, "domain", None))
        domain_source = "current_domain"

    domains_data = getattr(shell, "domains_data", {}) or {}
    current_domain = getattr(shell, "domain", None)
    current_domain_auth = "unknown"
    if current_domain and isinstance(domains_data, dict):
        current_domain_data = domains_data.get(current_domain, {})
        if isinstance(current_domain_data, dict):
            current_domain_auth = str(current_domain_data.get("auth", "unknown"))

    domain_state: dict[str, Any] | None = None
    if context_domain and context_domain in domains_data:
        domain_data = domains_data.get(context_domain, {})
        if isinstance(domain_data, dict):
            creds = domain_data.get("credentials", {})
            creds_count = len(creds) if isinstance(creds, dict) else 0
            # Surface the Kerberos-relevant FQDN/hostname keys on every
            # command. Captures the workspace state at the exact moment
            # the user runs a command — the next bug report triggered by
            # stale FQDN data (e.g. v8 → v9 workspace migration) will
            # carry the field provenance inline instead of requiring a
            # second round trip to the user. See BACKLOG entry "v8→v9
            # workspace migration — stale Kerberos target hostname"
            # for the diagnostic story that motivated these fields.
            domain_state = {
                "domain": context_domain,
                "auth": str(domain_data.get("auth", "unknown")),
                "pdc": str(domain_data.get("pdc", "N/A")),
                "pdc_hostname": str(domain_data.get("pdc_hostname", "N/A")),
                "pdc_hostname_fqdn": str(
                    domain_data.get("pdc_hostname_fqdn", "N/A")
                ),
                "pdc_fqdn": str(domain_data.get("pdc_fqdn", "N/A")),
                "dc_fqdn": str(domain_data.get("dc_fqdn", "N/A")),
                "username": str(domain_data.get("username", "N/A")),
                "credentials_count": creds_count,
            }

    telemetry_enabled = False
    telemetry_source = "persisted"
    telemetry_scope = "default"
    telemetry_reenable_hint = ""
    try:
        from adscan_internal import telemetry

        env_val = os.getenv("ADSCAN_TELEMETRY", None)
        telemetry_enabled = bool(telemetry._is_telemetry_enabled())
        telemetry_source = "session override" if env_val is not None else "persisted"

        # When telemetry is OFF, name the SCOPE that turned it off and the exact
        # command to re-enable it — the recovery hint that kills the silent-loss
        # class (a per-engagement opt-out is easy to forget you set).
        if not telemetry_enabled:
            from adscan_core.telemetry_preference import (
                WORKSPACE_PREFERENCE_ATTR,
                load_global_preference,
            )

            workspace_pref = getattr(shell, WORKSPACE_PREFERENCE_ATTR, None)
            if env_val is not None:
                telemetry_scope = "session (ADSCAN_TELEMETRY)"
            elif workspace_pref is False:
                telemetry_scope = "this workspace"
                telemetry_reenable_hint = "set telemetry on"
            elif load_global_preference() is False:
                telemetry_scope = "global"
                telemetry_reenable_hint = "set telemetry on global"
    except Exception:
        pass

    return {
        "hosts": getattr(shell, "hosts", None),
        "interface": getattr(shell, "interface", None),
        "myip": getattr(shell, "myip", None),
        "starting_domain": current_domain,
        "starting_domain_auth": current_domain_auth,
        "configured_domains": getattr(shell, "domains", None),
        "automatic_mode": getattr(shell, "auto", None),
        "pentest_type": getattr(shell, "type", None),
        "current_workspace": getattr(shell, "current_workspace_dir", None),
        "telemetry_enabled": telemetry_enabled,
        "telemetry_source": telemetry_source,
        "telemetry_scope": telemetry_scope,
        "telemetry_reenable_hint": telemetry_reenable_hint,
        "context_domain": context_domain,
        "domain_source": domain_source,
        "domains_loaded": len(domains_data) if isinstance(domains_data, dict) else 0,
        "domain_state": domain_state,
    }


def _flatten_runtime_snapshot_for_exception(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Reduce a ``build_cli_runtime_snapshot`` dict to file-log-safe scalars.

    Strips nested dicts (notably ``domain_state``) up to one level, marking
    sensitive fields so the resulting dict can be passed directly to the
    exception logger's ``context`` parameter. Returns a flat ``{str: str}``
    dictionary that ``_format_exception_context`` knows how to render as
    ``key=value`` pairs alongside the traceback.
    """
    flat: dict[str, Any] = {}
    flat["workspace"] = mark_sensitive(
        str(snapshot.get("current_workspace") or "None"), "path"
    )
    flat["interface"] = snapshot.get("interface")
    flat["pentest_type"] = snapshot.get("pentest_type")
    flat["auto"] = snapshot.get("automatic_mode")
    flat["current_domain"] = mark_sensitive(
        str(snapshot.get("starting_domain") or "None"), "domain"
    )
    flat["context_domain"] = mark_sensitive(
        str(snapshot.get("context_domain") or "None"), "domain"
    )
    flat["domains_loaded"] = snapshot.get("domains_loaded")

    domain_state = snapshot.get("domain_state")
    if isinstance(domain_state, dict):
        flat["domain"] = mark_sensitive(
            str(domain_state.get("domain", "N/A")), "domain"
        )
        flat["auth"] = str(domain_state.get("auth", "unknown"))
        flat["pdc"] = mark_sensitive(str(domain_state.get("pdc", "N/A")), "ip")
        flat["pdc_hostname"] = mark_sensitive(
            str(domain_state.get("pdc_hostname", "N/A")), "hostname"
        )
        flat["pdc_hostname_fqdn"] = mark_sensitive(
            str(domain_state.get("pdc_hostname_fqdn", "N/A")), "hostname"
        )
        flat["pdc_fqdn"] = mark_sensitive(
            str(domain_state.get("pdc_fqdn", "N/A")), "hostname"
        )
        flat["dc_fqdn"] = mark_sensitive(
            str(domain_state.get("dc_fqdn", "N/A")), "hostname"
        )
        flat["username"] = mark_sensitive(
            str(domain_state.get("username", "N/A")), "user"
        )
        flat["credentials_count"] = domain_state.get("credentials_count", 0)
    return flat


def install_exception_context_provider(shell: Any) -> None:
    """Wire the shell into the exception logger's diagnostic-context hook.

    After this call, any ``print_exception`` invoked anywhere in ADscan that
    does not pass an explicit ``context`` will automatically attach the
    current workspace + active domain snapshot (including the FQDN/hostname
    keys that drive Kerberos targeting) to the file log.

    The provider is intentionally lazy — it runs at exception time, so the
    snapshot reflects the workspace state at the moment of failure, not at
    the moment of registration. Idempotent: re-installing on the same shell
    replaces the provider with a fresh closure.
    """
    try:
        from adscan_core.output._log import register_exception_context_provider

        def _provider() -> dict[str, Any] | None:
            try:
                snapshot = build_cli_runtime_snapshot(shell=shell)
                return _flatten_runtime_snapshot_for_exception(snapshot)
            except Exception:
                return None

        register_exception_context_provider(_provider)
    except Exception:
        # Diagnostic plumbing must never crash the host process.
        pass


def log_cli_command_context(
    shell: Any,
    command_name: str,
    args_list: list[str],
    *,
    source: str = "cli",
) -> None:
    """Emit a compact workspace/domain snapshot for CLI command execution."""
    try:
        # Make sure the exception logger has a current snapshot provider
        # bound to this shell — registering here covers shells that were
        # constructed before install_exception_context_provider was wired
        # in adscan.py, and is cheap (function call + global assign).
        install_exception_context_provider(shell)

        snapshot = build_cli_runtime_snapshot(
            shell=shell,
            command_name=command_name,
            args_list=args_list,
        )
        marked_workspace = mark_sensitive(
            str(snapshot.get("current_workspace") or "None"), "path"
        )
        marked_current_domain = mark_sensitive(
            str(snapshot.get("starting_domain") or "None"), "domain"
        )
        context_domain = snapshot.get("context_domain")
        marked_context_domain = mark_sensitive(str(context_domain or "None"), "domain")
        print_info_debug(
            f"[{source}] Context: "
            f"command={command_name} "
            f"interface={snapshot.get('interface')} "
            f"type={snapshot.get('pentest_type')} "
            f"auto={snapshot.get('automatic_mode')} "
            f"scan_mode={getattr(shell, 'scan_mode', None)} "
            f"workspace={marked_workspace} "
            f"current_domain={marked_current_domain} "
            f"current_domain_auth={snapshot.get('starting_domain_auth')} "
            f"context_domain={marked_context_domain} "
            f"domain_source={snapshot.get('domain_source')} "
            f"domains_loaded={snapshot.get('domains_loaded')}"
        )

        domain_state = snapshot.get("domain_state")
        if not isinstance(domain_state, dict):
            return

        auth = str(domain_state.get("auth", "unknown"))
        marked_pdc = mark_sensitive(str(domain_state.get("pdc", "N/A")), "ip")
        marked_pdc_host = mark_sensitive(
            str(domain_state.get("pdc_hostname", "N/A")), "hostname"
        )
        marked_pdc_host_fqdn = mark_sensitive(
            str(domain_state.get("pdc_hostname_fqdn", "N/A")), "hostname"
        )
        marked_pdc_fqdn = mark_sensitive(
            str(domain_state.get("pdc_fqdn", "N/A")), "hostname"
        )
        marked_dc_fqdn = mark_sensitive(
            str(domain_state.get("dc_fqdn", "N/A")), "hostname"
        )
        marked_username = mark_sensitive(
            str(domain_state.get("username", "N/A")), "user"
        )
        creds_count = int(domain_state.get("credentials_count", 0) or 0)
        print_info_debug(
            f"[{source}] Domain state: "
            f"domain={mark_sensitive(str(domain_state.get('domain', context_domain)), 'domain')} "
            f"auth={auth} "
            f"pdc={marked_pdc} "
            f"pdc_hostname={marked_pdc_host} "
            f"pdc_hostname_fqdn={marked_pdc_host_fqdn} "
            f"pdc_fqdn={marked_pdc_fqdn} "
            f"dc_fqdn={marked_dc_fqdn} "
            f"username={marked_username} "
            f"credentials_count={creds_count}"
        )
    except Exception:
        pass
