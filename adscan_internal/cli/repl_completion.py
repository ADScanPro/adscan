"""Context-aware, bidirectional flag-value completion for flag-grammar REPL
commands (adscan_internal.cli.repl_args is PARSING; this module is
COMPLETION — the two are independent but this one is only meaningful once a
command speaks the flag grammar the other module adds).

See docs/superpowers/plans/2026-07-21-repl-flag-argument-grammar.md
"Phase 2: Context-Aware Bidirectional Flag Completion" for the full design
and the credential-store / telemetry investigation behind the rules below.

Two invariants, both load-bearing:

1. prompt_toolkit's NestedCompleter (adscan.py's PromptSession completer)
   strips the command STEM before delegating to a per-command completer —
   so ``document.text`` here NEVER includes the command name, only the
   argument tokens typed so far.
2. A field's ``provider`` receives a ``FlagCompletionContext`` whose
   ``known`` mapping already contains every OTHER flag's value typed on the
   line so far, regardless of order — this is what makes completion
   bidirectional "for free": the same provider design works whether ``-d``
   or ``-u`` was typed first, because it only ever asks "is X already in
   ``known``", never "was X typed before me".
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping

from prompt_toolkit.completion import Completer, Completion


@dataclass(frozen=True)
class FlagCompletionContext:
    """Everything a field's completion provider needs to decide what to offer."""

    shell: Any
    known: Mapping[str, str]
    word: str


@dataclass(frozen=True)
class FlagCompletionSpec:
    """One completable flag on one command."""

    canonical_name: str
    flag_names: tuple[str, ...]
    depends_on: tuple[str, ...]
    provider: Callable[[FlagCompletionContext], Iterable[Completion]]


@dataclass(frozen=True)
class CommandCompletionSpec:
    """The full completable-flag table for one migrated REPL command."""

    command: str
    fields: tuple[FlagCompletionSpec, ...]

    def field_by_flag(self, token: str) -> "FlagCompletionSpec | None":
        for field_spec in self.fields:
            if token in field_spec.flag_names:
                return field_spec
        return None


class FlagAwareCompleter(Completer):
    """Order-independent, bidirectional completion for one flag-grammar command.

    Sketch-level tokenizer (see Phase 2 plan for the full rationale): it does
    NOT use argparse (argparse errors on incomplete trailing input, which is
    the normal state while the operator is still typing). It walks tokens
    pairwise, treats the LAST flag+value pair as "in progress" when the
    cursor sits inside/right after it, and hands everything else to the
    matching field's ``provider`` as ``ctx.known``.
    """

    def __init__(self, shell_instance: Any, spec: CommandCompletionSpec) -> None:
        self.shell = shell_instance
        self.spec = spec

    def get_completions(self, document, complete_event) -> Iterable[Completion]:
        text = document.text_before_cursor
        try:
            tokens = shlex.split(text)
        except ValueError:
            # Unterminated quote mid-typing — degrade to whitespace split
            # rather than raise; a live completer must never crash the REPL.
            tokens = text.split()

        ends_with_space = text == "" or text[-1] in (" ", "\t")
        word = "" if ends_with_space else (tokens[-1] if tokens else "")
        # Tokens NOT part of the in-progress flag/value pair.
        settled = tokens if ends_with_space else tokens[:-1]

        in_progress_flag: FlagCompletionSpec | None = None
        if ends_with_space and settled:
            in_progress_flag = self.spec.field_by_flag(settled[-1])
        elif not ends_with_space and settled:
            in_progress_flag = self.spec.field_by_flag(settled[-1])

        known: dict[str, str] = {}
        i = 0
        pairs_source = settled[:-1] if in_progress_flag is not None else settled
        while i < len(pairs_source) - 1:
            field_spec = self.spec.field_by_flag(pairs_source[i])
            if field_spec is not None:
                known[field_spec.canonical_name] = pairs_source[i + 1]
                i += 2
            else:
                i += 1

        if in_progress_flag is not None:
            ctx = FlagCompletionContext(shell=self.shell, known=known, word=word)
            yield from in_progress_flag.provider(ctx)
            return

        already_used = set(known)
        for field_spec in self.spec.fields:
            if field_spec.canonical_name in already_used:
                continue
            for flag_name in field_spec.flag_names:
                if flag_name.startswith(word):
                    yield Completion(
                        flag_name,
                        start_position=-len(word),
                        display_meta=field_spec.canonical_name,
                    )


FLAG_COMPLETION_SPECS: dict[str, CommandCompletionSpec] = {}


def _username_domain_index(shell: Any) -> dict[str, list[str]]:
    """``username.lower() -> [domain, ...]`` across the generic + local stores.

    Rebuilt on every completion call rather than cached — ``domains_data`` is
    small even at multi-domain-engagement scale, so this can never go stale.
    Carries no per-credential timestamp (``domains_data`` doesn't serialize
    one — see Phase 2 Investigation §4), so ambiguity between multiple
    matching domains is resolved by the caller using ``shell.domain``, not by
    ranking here.
    """
    index: dict[str, list[str]] = {}
    domains_data = getattr(shell, "domains_data", {}) or {}
    for domain, data in domains_data.items():
        if not isinstance(data, dict):
            continue
        for username in data.get("credentials") or {}:
            index.setdefault(username.lower(), []).append(domain)
        for host_services in (data.get("local_credentials") or {}).values():
            for creds in (host_services or {}).values():
                for username in creds or {}:
                    index.setdefault(username.lower(), []).append(domain)
    return index


def _complete_domain_generic(ctx: FlagCompletionContext) -> Iterable[Completion]:
    """Domain provider shared by every generic-credential (domain/username/password)
    command — ``get_flags``, ``dcsync``. Both read the SAME generic ``credentials``
    store (no ``--host`` scoping), so their domain-completion behavior is identical.
    """
    known_username = ctx.known.get("username")
    candidates: list[tuple[str, str]] = []

    if known_username:
        # Reverse inference: -u was typed first. Offer EVERY domain where
        # this username has a known credential — never silently pick one.
        matches = _username_domain_index(ctx.shell).get(known_username.lower(), [])
        active_domain = getattr(ctx.shell, "domain", None)
        matches.sort(
            key=lambda d: d != active_domain
        )  # active domain first if present, stable otherwise
        candidates.extend(
            (d, f"known credential for {known_username}") for d in matches
        )

    seen = {d for d, _ in candidates}
    for domain in getattr(ctx.shell, "domains", None) or []:
        if domain not in seen:
            candidates.append((domain, "scanned domain"))
            seen.add(domain)

    for domain, meta in candidates:
        if domain.startswith(ctx.word):
            yield Completion(
                domain, start_position=-len(ctx.word), display=domain, display_meta=meta
            )


def _complete_username_generic(ctx: FlagCompletionContext) -> Iterable[Completion]:
    """Username provider shared by ``get_flags``/``dcsync`` — both are generic
    domain-auth commands (no ``--host``), so their ``-u`` reads ONLY
    ``domains_data[domain]["credentials"]``, never ``local_credentials`` or a
    scoped ``ServiceTicket`` (see CLAUDE.md § Credential storage).
    """
    from adscan_internal.cli.creds import is_hash

    domains_data = getattr(ctx.shell, "domains_data", {}) or {}
    known_domain = ctx.known.get("domain")

    if known_domain:
        # Forward narrowing: -d already known. Strictly the generic
        # "credentials" store, never local_credentials/service_tickets.
        creds = (domains_data.get(known_domain, {}) or {}).get("credentials") or {}
        for username, value in creds.items():
            if username.lower().startswith(ctx.word.lower()):
                kind = "hash" if is_hash(value) else "password"
                yield Completion(
                    username,
                    start_position=-len(ctx.word),
                    display=username,
                    display_meta=f"known {kind}",
                )
        return
    # -d not typed yet: nothing to narrow by — offering an unfiltered,
    # cross-domain union here would make ambiguity worse, not better, so
    # -u stays empty until -d is known (unlike -d, which always has a safe
    # unfiltered fallback: "every scanned domain").


def _complete_password_generic(ctx: FlagCompletionContext) -> Iterable[Completion]:
    """Password provider shared by ``get_flags``/``dcsync`` — both have a single
    ``-p``/``--password`` flag accepting EITHER a password or a hash (mirrors
    ``credentials[user] = password-or-hash``), so both are offered here.
    """
    from adscan_internal.cli.creds import is_hash

    domain, username = ctx.known.get("domain"), ctx.known.get("username")
    if not domain or not username:
        return
    domains_data = getattr(ctx.shell, "domains_data", {}) or {}
    value = ((domains_data.get(domain, {}) or {}).get("credentials") or {}).get(
        username
    )
    if not value:
        return
    if is_hash(value):
        preview = f"{value[:8]}...{value[-4:]}"
        meta = f"Hash | {preview}"
    else:
        preview = f"{value[:3]}{'*' * min(len(value) - 3, 8)}"
        meta = f"Password | {preview}"
    yield Completion(
        value,
        start_position=-len(ctx.word),
        display=f"<{username}'s credential>",
        display_meta=meta,
    )


GET_FLAGS_COMPLETION_SPEC = CommandCompletionSpec(
    command="get_flags",
    fields=(
        FlagCompletionSpec(
            "domain",
            ("-d", "--domain"),
            depends_on=(),
            provider=_complete_domain_generic,
        ),
        FlagCompletionSpec(
            "username",
            ("-u", "--username"),
            depends_on=("domain",),
            provider=_complete_username_generic,
        ),
        FlagCompletionSpec(
            "password",
            ("-p", "--password"),
            depends_on=("domain", "username"),
            provider=_complete_password_generic,
        ),
    ),
)
FLAG_COMPLETION_SPECS["get_flags"] = GET_FLAGS_COMPLETION_SPEC


# dcsync (Phase 1 Task 3) has the identical 3-field generic-credential shape
# as get_flags (-d/--domain, -u/--username, -p/--password, no --host), so its
# completion spec reuses the SAME providers verbatim — see "Recommended
# Rollout Order" in the plan: dcsync is called out explicitly as the natural
# first completion pilot for this exact reason.
DCSYNC_COMPLETION_SPEC = CommandCompletionSpec(
    command="dcsync",
    fields=(
        FlagCompletionSpec(
            "domain",
            ("-d", "--domain"),
            depends_on=(),
            provider=_complete_domain_generic,
        ),
        FlagCompletionSpec(
            "username",
            ("-u", "--username"),
            depends_on=("domain",),
            provider=_complete_username_generic,
        ),
        FlagCompletionSpec(
            "password",
            ("-p", "--password"),
            depends_on=("domain", "username"),
            provider=_complete_password_generic,
        ),
    ),
)
FLAG_COMPLETION_SPECS["dcsync"] = DCSYNC_COMPLETION_SPEC


# enumerate_user_aces (Phase 1 Task 10) has the identical 3-field
# generic-credential shape as get_flags/dcsync (-d/--domain, -u/--username,
# -p/--password, no --host) -- Task 22's own delta note for this command is
# "None", so its completion spec reuses the SAME providers verbatim.
ENUMERATE_USER_ACES_COMPLETION_SPEC = CommandCompletionSpec(
    command="enumerate_user_aces",
    fields=(
        FlagCompletionSpec(
            "domain",
            ("-d", "--domain"),
            depends_on=(),
            provider=_complete_domain_generic,
        ),
        FlagCompletionSpec(
            "username",
            ("-u", "--username"),
            depends_on=("domain",),
            provider=_complete_username_generic,
        ),
        FlagCompletionSpec(
            "password",
            ("-p", "--password"),
            depends_on=("domain", "username"),
            provider=_complete_password_generic,
        ),
    ),
)
FLAG_COMPLETION_SPECS["enumerate_user_aces"] = ENUMERATE_USER_ACES_COMPLETION_SPEC


# enum_adcs_privs (Phase 1 Task 11) has the identical 3-field
# generic-credential shape as get_flags/dcsync (-d/--domain, -u/--username,
# -p/--password, no --host) -- Task 22's own delta note for this command is
# "None", so its completion spec reuses the SAME providers verbatim.
ENUM_ADCS_PRIVS_COMPLETION_SPEC = CommandCompletionSpec(
    command="enum_adcs_privs",
    fields=(
        FlagCompletionSpec(
            "domain",
            ("-d", "--domain"),
            depends_on=(),
            provider=_complete_domain_generic,
        ),
        FlagCompletionSpec(
            "username",
            ("-u", "--username"),
            depends_on=("domain",),
            provider=_complete_username_generic,
        ),
        FlagCompletionSpec(
            "password",
            ("-p", "--password"),
            depends_on=("domain", "username"),
            provider=_complete_password_generic,
        ),
    ),
)
FLAG_COMPLETION_SPECS["enum_adcs_privs"] = ENUM_ADCS_PRIVS_COMPLETION_SPEC


def _build_generic_credential_completion_spec(command: str) -> CommandCompletionSpec:
    """Shared completion-flag table for generic domain-auth commands.

    Mirrors GET_FLAGS_COMPLETION_SPEC/DCSYNC_COMPLETION_SPEC's 3-field
    generic-credential shape (-d/--domain, -u/--username, -p/--password, no
    --host) — extracted into a factory once ``smb_auth_shares`` and
    ``user_postauth_access`` (Task 22) joined the same family, the same way
    ``_build_dump_completion_spec`` (below) was extracted for the host-scoped
    shape shared by the four dump_* commands.
    """
    return CommandCompletionSpec(
        command=command,
        fields=(
            FlagCompletionSpec(
                "domain",
                ("-d", "--domain"),
                depends_on=(),
                provider=_complete_domain_generic,
            ),
            FlagCompletionSpec(
                "username",
                ("-u", "--username"),
                depends_on=("domain",),
                provider=_complete_username_generic,
            ),
            FlagCompletionSpec(
                "password",
                ("-p", "--password"),
                depends_on=("domain", "username"),
                provider=_complete_password_generic,
            ),
        ),
    )


# smb_auth_shares (Task 7) is a standalone -d/-u/-p command
# (smb.py:run_smb_auth_shares_from_args); user_postauth_access (Task 9)
# dispatches through adscan.py's ``_dispatch_user_postauth_access`` parser.
# Both have the identical generic-credential shape, so both completion specs
# come from the same factory call.
_SMB_AUTH_GENERIC_COMMANDS = (
    "smb_auth_shares",
    "user_postauth_access",
)
for _smb_auth_command_name in _SMB_AUTH_GENERIC_COMMANDS:
    FLAG_COMPLETION_SPECS[_smb_auth_command_name] = (
        _build_generic_credential_completion_spec(_smb_auth_command_name)
    )


# --- dump_lsa / dump_lsass / dump_sam / dump_dpapi (Phase 1 Task 5) -------
#
# All four SMB-dump commands share the identical 5-field shape (domain,
# username, password, host, islocal) -- see dumps.py's `_build_dump_parser`
# factory, which this section mirrors for completion the same way it does
# for parsing. Design delta from get_flags/dcsync (Task 21 of the plan):
# once --domain/--host/--islocal are known, -u/-p ALSO offer the host-scoped
# `local_credentials[domain][host][<service>]` entries when islocal=="true",
# tagged `display_meta="local: <host>/<service> ..."` so they are never
# confused with a domain-wide `credentials` entry (CLAUDE.md § Credential
# storage -- three stores, pick the right one). islocal=="false" (or not yet
# known) delegates straight to the SAME generic providers get_flags/dcsync
# use, by direct call, not reimplementation.


def _known_hosts_for_domain(shell: Any, domain: str) -> list[str]:
    """Discovered-computer + local-credential hosts for one domain, deduped.

    Union of ``domains_data[domain]["computers"]`` (the native collector's
    discovered-host list) and the keys of
    ``domains_data[domain]["local_credentials"]`` (a host can carry a
    captured local credential without ever having been enumerated as a
    "computer" object, e.g. a workstation reached only via a spray). Order-
    preserving, first-seen-wins.
    """
    domains_data = getattr(shell, "domains_data", {}) or {}
    data = domains_data.get(domain) or {}
    hosts: list[str] = []
    seen: set[str] = set()
    for host in data.get("computers") or []:
        if host not in seen:
            hosts.append(host)
            seen.add(host)
    for host in (data.get("local_credentials") or {}).keys():
        if host not in seen:
            hosts.append(host)
            seen.add(host)
    return hosts


def _complete_host_for_dump(ctx: FlagCompletionContext) -> Iterable[Completion]:
    """``--host`` provider shared by the four dump_* commands.

    Mirrors -d's "always has a safe fallback" design (Task 19's domain
    provider, ``depends_on=()``): when --domain is already known, host
    candidates are scoped to that domain's discovered hosts; otherwise it
    falls back to the union of every known domain's hosts rather than
    offering nothing just because --domain hasn't been typed yet. The
    literal ``All`` sentinel (every host in the domain -- see the four
    commands' own docstrings / ``_build_dump_parser``'s ``--host`` help
    text) is always offered too.
    """
    known_domain = ctx.known.get("domain")
    domains_data = getattr(ctx.shell, "domains_data", {}) or {}

    candidates: list[tuple[str, str]] = []
    seen: set[str] = set()
    if known_domain:
        for host in _known_hosts_for_domain(ctx.shell, known_domain):
            if host not in seen:
                candidates.append((host, "discovered host"))
                seen.add(host)
    else:
        for domain in domains_data:
            for host in _known_hosts_for_domain(ctx.shell, domain):
                if host not in seen:
                    candidates.append((host, f"discovered host ({domain})"))
                    seen.add(host)

    candidates.append(("All", "every host in the domain"))

    for host, meta in candidates:
        if host.lower().startswith(ctx.word.lower()):
            yield Completion(
                host, start_position=-len(ctx.word), display=host, display_meta=meta
            )


def _complete_islocal_choice(ctx: FlagCompletionContext) -> Iterable[Completion]:
    """``--islocal`` provider shared by the four dump_* commands.

    A static true/false choice, mirroring the ``choices=["true", "false"]``
    constraint already enforced by ``_build_dump_parser`` at parse time.
    """
    choices = {
        "true": "local dump (host-scoped local_credentials)",
        "false": "remote dump (domain-wide credentials)",
    }
    for value, meta in choices.items():
        if value.startswith(ctx.word.lower()):
            yield Completion(
                value, start_position=-len(ctx.word), display=value, display_meta=meta
            )


def _complete_username_for_dump(ctx: FlagCompletionContext) -> Iterable[Completion]:
    """``-u``/``--username`` provider shared by the four dump_* commands.

    Delegates to the SAME generic provider get_flags/dcsync use (domain-wide
    ``credentials`` store), then, only when ``--islocal`` is known to be
    ``"true"`` and ``--host`` is known, ALSO offers every username found in
    ``domains_data[domain]["local_credentials"][host]`` across every service
    key present for that host -- each tagged ``display_meta="local:
    <host>/<service> (...)"`` so it can never be mistaken for a domain-wide
    credential.
    """
    from adscan_internal.cli.creds import is_hash

    yield from _complete_username_generic(ctx)

    known_domain = ctx.known.get("domain")
    known_host = ctx.known.get("host")
    if ctx.known.get("islocal") != "true" or not (known_domain and known_host):
        return

    domains_data = getattr(ctx.shell, "domains_data", {}) or {}
    host_services = (
        (domains_data.get(known_domain, {}) or {}).get("local_credentials") or {}
    ).get(known_host) or {}
    for service, creds in host_services.items():
        for username, value in (creds or {}).items():
            if not username.lower().startswith(ctx.word.lower()):
                continue
            kind = "hash" if is_hash(value) else "password"
            yield Completion(
                username,
                start_position=-len(ctx.word),
                display=username,
                display_meta=f"local: {known_host}/{service} ({kind})",
            )


def _complete_password_for_dump(ctx: FlagCompletionContext) -> Iterable[Completion]:
    """``-p``/``--password`` provider shared by the four dump_* commands.

    Delegates to the SAME generic provider get_flags/dcsync use (domain-wide
    ``credentials[domain][username]``), then, only when ``--islocal`` is
    known to be ``"true"`` and ``--host`` is known, ALSO offers the host-
    scoped ``local_credentials[domain][host][<service>][username]`` value
    for every service key present for that host -- each tagged
    ``display_meta="local: <host>/<service> | ..."`` so it can never be
    mistaken for a domain-wide credential.
    """
    from adscan_internal.cli.creds import is_hash

    yield from _complete_password_generic(ctx)

    domain = ctx.known.get("domain")
    username = ctx.known.get("username")
    host = ctx.known.get("host")
    if ctx.known.get("islocal") != "true" or not (domain and username and host):
        return

    domains_data = getattr(ctx.shell, "domains_data", {}) or {}
    host_services = (
        (domains_data.get(domain, {}) or {}).get("local_credentials") or {}
    ).get(host) or {}
    for service, creds in host_services.items():
        value = (creds or {}).get(username)
        if not value:
            continue
        if is_hash(value):
            preview = f"{value[:8]}...{value[-4:]}"
            meta = f"local: {host}/{service} | Hash | {preview}"
        else:
            preview = f"{value[:3]}{'*' * min(len(value) - 3, 8)}"
            meta = f"local: {host}/{service} | Password | {preview}"
        yield Completion(
            value,
            start_position=-len(ctx.word),
            display=f"<{username}'s local credential>",
            display_meta=meta,
        )


def _build_dump_completion_spec(command: str) -> CommandCompletionSpec:
    """Shared completion-flag table for the four SMB-dump commands.

    Mirrors ``dumps.py``'s ``_build_dump_parser`` factory (Phase 1 Task 5):
    all four commands (``dump_lsa``, ``dump_lsass``, ``dump_sam``,
    ``dump_dpapi``) take the identical 5-field shape, so the completion
    table is extracted once instead of quadruplicated across the four
    call sites.
    """
    return CommandCompletionSpec(
        command=command,
        fields=(
            FlagCompletionSpec(
                "domain",
                ("-d", "--domain"),
                depends_on=(),
                provider=_complete_domain_generic,
            ),
            FlagCompletionSpec(
                "username",
                ("-u", "--username"),
                depends_on=("domain",),
                provider=_complete_username_for_dump,
            ),
            FlagCompletionSpec(
                "password",
                ("-p", "--password"),
                depends_on=("domain", "username"),
                provider=_complete_password_for_dump,
            ),
            FlagCompletionSpec(
                "host",
                ("--host",),
                depends_on=(),
                provider=_complete_host_for_dump,
            ),
            FlagCompletionSpec(
                "islocal",
                ("--islocal",),
                depends_on=(),
                provider=_complete_islocal_choice,
            ),
        ),
    )


_DUMP_COMMANDS = ("dump_lsa", "dump_lsass", "dump_sam", "dump_dpapi")
for _dump_command_name in _DUMP_COMMANDS:
    FLAG_COMPLETION_SPECS[_dump_command_name] = _build_dump_completion_spec(
        _dump_command_name
    )


# --- mssql_check_impersonate (Phase 1 Task 6) -----------------------------
#
# Host-scoped like dump_* (Task 21) for --host completion (reuses
# _known_hosts_for_domain), but the REAL do_mssql_check_impersonate /
# run_mssql_check_impersonate has NO --islocal flag and never touches
# local_credentials -- it authenticates to MSSQL on the target host with a
# plain DOMAIN credential. So -u/-p reuse the generic providers verbatim
# (get_flags/dcsync's _complete_username_generic/_complete_password_generic),
# and --host offers NO "All" sentinel (mssql_check_impersonate always
# targets exactly one host, unlike the dump commands' "every host in the
# domain" option).


def _complete_host_for_mssql_check_impersonate(
    ctx: FlagCompletionContext,
) -> Iterable[Completion]:
    """``--host`` provider for ``mssql_check_impersonate``.

    Mirrors ``_complete_host_for_dump``'s domain-scoped-with-fallback shape
    (Task 21) but WITHOUT the "All" sentinel: mssql_check_impersonate always
    checks exactly one host -- it has no "every host in the domain" mode.
    """
    known_domain = ctx.known.get("domain")
    domains_data = getattr(ctx.shell, "domains_data", {}) or {}

    candidates: list[tuple[str, str]] = []
    seen: set[str] = set()
    if known_domain:
        for host in _known_hosts_for_domain(ctx.shell, known_domain):
            if host not in seen:
                candidates.append((host, "discovered host"))
                seen.add(host)
    else:
        for domain in domains_data:
            for host in _known_hosts_for_domain(ctx.shell, domain):
                if host not in seen:
                    candidates.append((host, f"discovered host ({domain})"))
                    seen.add(host)

    for host, meta in candidates:
        if host.lower().startswith(ctx.word.lower()):
            yield Completion(
                host, start_position=-len(ctx.word), display=host, display_meta=meta
            )


MSSQL_CHECK_IMPERSONATE_COMPLETION_SPEC = CommandCompletionSpec(
    command="mssql_check_impersonate",
    fields=(
        FlagCompletionSpec(
            "domain",
            ("-d", "--domain"),
            depends_on=(),
            provider=_complete_domain_generic,
        ),
        FlagCompletionSpec(
            "host",
            ("--host",),
            depends_on=(),
            provider=_complete_host_for_mssql_check_impersonate,
        ),
        FlagCompletionSpec(
            "username",
            ("-u", "--username"),
            depends_on=("domain",),
            provider=_complete_username_generic,
        ),
        FlagCompletionSpec(
            "password",
            ("-p", "--password"),
            depends_on=("domain", "username"),
            provider=_complete_password_generic,
        ),
    ),
)
FLAG_COMPLETION_SPECS["mssql_check_impersonate"] = (
    MSSQL_CHECK_IMPERSONATE_COMPLETION_SPEC
)


# --- cracking (Phase 1 Task 8) ---------------------------------------------
#
# New pattern vs get_flags/dcsync/dump_*: cracking's secret field is
# --hash-ONLY -- there is no -u/-p pair at all (do_cracking's fields are
# --type/-d/--hash, see cracking.py). Its provider filters candidates with
# is_hash(value) and offers NOTHING for a user whose stored credential is a
# plaintext password -- cracking(...) operates on hashes, never passwords.
# --type is a small closed-choice provider over the hash types the real
# cracking.py implementation branches on (asreproast/kerberoast/timeroast/
# NTLMv1/NTLMv2 -- see _resolve_hashcat_mode_and_description).

_CRACKING_HASH_TYPE_CHOICES: dict[str, str] = {
    "asreproast": "AS-REP roast (Kerberos 5 AS-REP)",
    "kerberoast": "Kerberoast (Kerberos 5 TGS-REP)",
    "timeroast": "MS-SNTP Timeroast",
    "NTLMv1": "NetNTLMv1",
    "NTLMv2": "NetNTLMv2",
}


def _complete_type_for_cracking(ctx: FlagCompletionContext) -> Iterable[Completion]:
    """``--type`` provider for ``cracking`` -- a closed choice set, no
    dependency on any other known field."""
    for value, meta in _CRACKING_HASH_TYPE_CHOICES.items():
        if value.lower().startswith(ctx.word.lower()):
            yield Completion(
                value, start_position=-len(ctx.word), display=value, display_meta=meta
            )


def _complete_hash_for_cracking(ctx: FlagCompletionContext) -> Iterable[Completion]:
    """``--hash`` provider for ``cracking`` -- the ``accepts="hash"``
    type-matching example (see Phase 2 plan Task 22's cracking row).

    cracking has no -u/-p pair, so there is no single "known username" to
    key off; instead this scans every stored credential in the known domain
    and offers ONLY the ones that are already a hash (``is_hash(value)``).
    A user whose stored credential is a plaintext password offers NOTHING
    here -- cracking(...) operates on captured hashes, never passwords.
    """
    from adscan_internal.cli.creds import is_hash

    known_domain = ctx.known.get("domain")
    if not known_domain:
        return
    domains_data = getattr(ctx.shell, "domains_data", {}) or {}
    creds = (domains_data.get(known_domain, {}) or {}).get("credentials") or {}
    for username, value in creds.items():
        if not value or not is_hash(value):
            continue
        if not value.lower().startswith(ctx.word.lower()):
            continue
        preview = f"{value[:8]}...{value[-4:]}"
        yield Completion(
            value,
            start_position=-len(ctx.word),
            display=f"<{username}'s hash>",
            display_meta=f"Hash | {preview}",
        )


CRACKING_COMPLETION_SPEC = CommandCompletionSpec(
    command="cracking",
    fields=(
        FlagCompletionSpec(
            "hash_type",
            ("--type",),
            depends_on=(),
            provider=_complete_type_for_cracking,
        ),
        FlagCompletionSpec(
            "domain",
            ("-d", "--domain"),
            depends_on=(),
            provider=_complete_domain_generic,
        ),
        FlagCompletionSpec(
            "hash_file",
            ("--hash",),
            depends_on=("domain",),
            provider=_complete_hash_for_cracking,
        ),
    ),
)
FLAG_COMPLETION_SPECS["cracking"] = CRACKING_COMPLETION_SPEC




# --- creds save / creds add (Phase 1 Task 13) -----------------------------
#
# `creds` is a NESTED command (`creds show|clear|delete|select|save|add`,
# do_creds in adscan.py) -- unlike the flat dump_* / dcsync / get_flags
# commands, NestedCompleter only ever strips the OUTER command stem
# ("creds "), never the subcommand ("save"/"add"/...), so the completable
# text handed to this spec's FlagAwareCompleter still starts with that
# subcommand token (e.g. "save -d corp.local -u alice ..."). This is safe
# by construction: FlagAwareCompleter's pairwise tokenizer treats any token
# that isn't a registered flag name as unmatched and skips exactly one
# position (see the `else: i += 1` branch in `get_completions`), so the
# leading "save"/"add" token is silently absorbed without shifting the
# flag/value pairing. The registration key is therefore the OUTER stem
# "creds", not a synthetic "creds_save" -- every other `creds` subcommand
# (show/clear/delete/select) simply gets zero flag-name matches and falls
# through to the "offer any --flag prefix" branch, which matches today's
# baseline (no completer was registered for "creds" before this task, so
# every subcommand had zero completions -- this is a strict improvement,
# not a behavior change for the other subcommands).
#
# Per the plan (Task 22): domain/username/credential reuse the get_flags
# generic providers VERBATIM (both-or-neither host/service pairing is a
# PARSING concern, enforced in `do_creds`/`parse_command_args` -- nothing
# here enforces it). --host and --service are independent, always-offered
# optional fields.


def _complete_discovered_host(ctx: FlagCompletionContext) -> Iterable[Completion]:
    """``--host`` provider shared by commands that accept ONLY a literal,
    real host -- unlike the four dump_* commands, whose ``--host`` also
    accepts the "All" sentinel (see ``_complete_host_for_dump``). Neither
    ``creds save``/``creds add`` nor ``session launch`` support "All", so
    this variant omits it. Mirrors the same "domain known -> scope to it,
    else union across every known domain" fallback design.
    """
    known_domain = ctx.known.get("domain")
    domains_data = getattr(ctx.shell, "domains_data", {}) or {}

    candidates: list[tuple[str, str]] = []
    seen: set[str] = set()
    if known_domain:
        for host in _known_hosts_for_domain(ctx.shell, known_domain):
            if host not in seen:
                candidates.append((host, "discovered host"))
                seen.add(host)
    else:
        for domain in domains_data:
            for host in _known_hosts_for_domain(ctx.shell, domain):
                if host not in seen:
                    candidates.append((host, f"discovered host ({domain})"))
                    seen.add(host)

    for host, meta in candidates:
        if host.lower().startswith(ctx.word.lower()):
            yield Completion(
                host, start_position=-len(ctx.word), display=host, display_meta=meta
            )


def _complete_service_for_creds_save(
    ctx: FlagCompletionContext,
) -> Iterable[Completion]:
    """``--service`` provider for ``creds save``/``creds add``.

    Unlike ``session launch``'s ``--service`` (a closed 2-item choice), the
    service label here is FREEFORM -- it is whatever string the operator
    already used (or will use) to key ``local_credentials[domain][host][svc]``
    (CLAUDE.md Section "Credential storage": ``smb``, ``mssql``, ``rdp``,
    ``winrm``, ``cifs`` are all seen in the wild, never a fixed enum). So this
    provider offers, in priority order: services already stored for the known
    (domain, host) pair, then services seen anywhere else in the domain, then
    a short list of common conventional labels not already offered -- the same
    "always has a safe fallback" shape as the other providers in this module.
    """
    known_domain = ctx.known.get("domain")
    known_host = ctx.known.get("host")
    domains_data = getattr(ctx.shell, "domains_data", {}) or {}

    candidates: list[tuple[str, str]] = []
    seen: set[str] = set()

    if known_domain and known_host:
        host_services = (
            (domains_data.get(known_domain, {}) or {}).get("local_credentials") or {}
        ).get(known_host) or {}
        for service in host_services:
            if service not in seen:
                candidates.append(
                    (service, f"existing local credential on {known_host}")
                )
                seen.add(service)
    elif known_domain:
        all_local = (domains_data.get(known_domain, {}) or {}).get(
            "local_credentials"
        ) or {}
        for host_services in all_local.values():
            for service in host_services or {}:
                if service not in seen:
                    candidates.append((service, "used elsewhere in this domain"))
                    seen.add(service)

    for service in ("smb", "mssql", "winrm", "rdp", "cifs"):
        if service not in seen:
            candidates.append((service, "common service label"))
            seen.add(service)

    for service, meta in candidates:
        if service.lower().startswith(ctx.word.lower()):
            yield Completion(
                service,
                start_position=-len(ctx.word),
                display=service,
                display_meta=meta,
            )


CREDS_SAVE_COMPLETION_SPEC = CommandCompletionSpec(
    command="creds",
    fields=(
        FlagCompletionSpec(
            "domain",
            ("-d", "--domain"),
            depends_on=(),
            provider=_complete_domain_generic,
        ),
        FlagCompletionSpec(
            "username",
            ("-u", "--username"),
            depends_on=("domain",),
            provider=_complete_username_generic,
        ),
        FlagCompletionSpec(
            "credential",
            ("-p", "--credential"),
            depends_on=("domain", "username"),
            provider=_complete_password_generic,
        ),
        FlagCompletionSpec(
            "host",
            ("--host",),
            depends_on=(),
            provider=_complete_discovered_host,
        ),
        FlagCompletionSpec(
            "service",
            ("--service",),
            depends_on=("host",),
            provider=_complete_service_for_creds_save,
        ),
    ),
)
FLAG_COMPLETION_SPECS["creds"] = CREDS_SAVE_COMPLETION_SPEC


# --- session launch (Phase 1 Task 14) --------------------------------------
#
# `session` is ALSO a nested command (do_session in adscan.py: listener,
# list, use, kill, current, interact, rename, info, interfaces, launch,
# connect, download, upload, system, shell, agent, ...), so the same
# "outer stem, leading subcommand token silently skipped" reasoning as
# `creds` above applies verbatim -- the registration key is "session", not
# "session_launch". Before this task, "session" had no completer registered
# at all (do_session's source has no `if ... in [...]` literal-list pattern
# for `_extract_options_from_method` to find), so every OTHER `session`
# subcommand (listener/list/use/kill/...) goes from "no completions" to
# "no completions" -- a strict improvement for `launch`, no regression
# elsewhere.
#
# domain/username/password reuse the get_flags generic providers verbatim
# (session launch resolves credentials from the SAME domain-wide
# `credentials` store, never `local_credentials` -- see the `launch` branch
# in `do_session`). --host reuses the literal-host-only provider defined
# above (no "All" sentinel -- `session launch` targets exactly one host).
# --service is a genuinely closed 2-item choice (mirrors the
# `choices=["smb", "winrm"]` constraint enforced by the flag parser), and
# --os is a genuinely closed 2-item choice (mirrors `choices=["windows",
# "linux"]`) -- both static, no store lookup, same shape as `--islocal`.


def _complete_service_choice_session_launch(
    ctx: FlagCompletionContext,
) -> Iterable[Completion]:
    """``--service`` provider for ``session launch`` -- a closed choice."""
    choices = {
        "smb": "reverse shell via SMB",
        "winrm": "reverse shell via WinRM",
    }
    for value, meta in choices.items():
        if value.startswith(ctx.word.lower()):
            yield Completion(
                value, start_position=-len(ctx.word), display=value, display_meta=meta
            )


def _complete_os_choice_session_launch(
    ctx: FlagCompletionContext,
) -> Iterable[Completion]:
    """``--os`` provider for ``session launch`` -- a closed choice."""
    choices = {
        "windows": "Windows target",
        "linux": "Linux target",
    }
    for value, meta in choices.items():
        if value.startswith(ctx.word.lower()):
            yield Completion(
                value, start_position=-len(ctx.word), display=value, display_meta=meta
            )


SESSION_LAUNCH_COMPLETION_SPEC = CommandCompletionSpec(
    command="session",
    fields=(
        FlagCompletionSpec(
            "service",
            ("--service",),
            depends_on=(),
            provider=_complete_service_choice_session_launch,
        ),
        FlagCompletionSpec(
            "host",
            ("--host",),
            depends_on=(),
            provider=_complete_discovered_host,
        ),
        FlagCompletionSpec(
            "domain",
            ("-d", "--domain"),
            depends_on=(),
            provider=_complete_domain_generic,
        ),
        FlagCompletionSpec(
            "username",
            ("-u", "--username"),
            depends_on=("domain",),
            provider=_complete_username_generic,
        ),
        FlagCompletionSpec(
            "password",
            ("-p", "--password"),
            depends_on=("domain", "username"),
            provider=_complete_password_generic,
        ),
        FlagCompletionSpec(
            "os",
            ("--os",),
            depends_on=(),
            provider=_complete_os_choice_session_launch,
        ),
    ),
)
FLAG_COMPLETION_SPECS["session"] = SESSION_LAUNCH_COMPLETION_SPEC


# --- start_auth (Phase 1 Task 12) ------------------------------------------
#
# start_auth is Shape C (the interactive-wizard fallback, see the plan) --
# it is a FLAT command (no subcommand token to skip), and its zero-args form
# is load-bearing UX: an empty line must keep triggering the guided wizard.
# That trigger is decided entirely inside `_run_start_auth_impl` by
# inspecting the raw `args` string BEFORE any flag parsing runs (`if not
# (args or "").strip() and not is_non_interactive(shell): ...wizard...`) --
# completion never touches that string, it only decides what the completion
# POPUP offers while the operator is still typing. On a genuinely empty
# document, `FlagAwareCompleter.get_completions` degrades to "offer every
# flag name" (word="" matches every prefix), which is a completion-menu
# suggestion only -- it does not pre-fill the line, does not intercept
# Enter, and does not change what `args` is when the operator submits an
# empty line. So no guard is needed in this spec: the claim from the plan is
# confirmed correct (see `test_start_auth_empty_line_does_not_break_wizard_trigger`).


def _complete_dc_ip_for_start_auth(ctx: FlagCompletionContext) -> Iterable[Completion]:
    """``--dc-ip`` provider for ``start_auth``.

    Resolves via the SSOT ``resolve_dc_ip()`` (CLAUDE.md "DC/KDC IP from
    domains_data -- always resolve_dc_ip()") rather than reading
    ``dc_ip``/``pdc`` ad hoc. Falls back to every known domain's resolved DC
    IP, tagged with its domain, when ``--domain`` hasn't been typed yet --
    the same "always has a safe fallback" shape as ``_complete_domain_generic``.
    """
    from adscan_internal.models.domain import resolve_dc_ip

    known_domain = ctx.known.get("domain")
    domains_data = getattr(ctx.shell, "domains_data", {}) or {}

    candidates: list[tuple[str, str]] = []
    seen: set[str] = set()
    if known_domain:
        dc_ip = resolve_dc_ip(domains_data.get(known_domain) or {})
        if dc_ip and dc_ip not in seen:
            candidates.append((dc_ip, f"resolved DC/KDC for {known_domain}"))
            seen.add(dc_ip)
    else:
        for domain, data in domains_data.items():
            if not isinstance(data, dict):
                continue
            dc_ip = resolve_dc_ip(data)
            if dc_ip and dc_ip not in seen:
                candidates.append((dc_ip, f"resolved DC/KDC for {domain}"))
                seen.add(dc_ip)

    for dc_ip, meta in candidates:
        if dc_ip.startswith(ctx.word):
            yield Completion(
                dc_ip, start_position=-len(ctx.word), display=dc_ip, display_meta=meta
            )


START_AUTH_COMPLETION_SPEC = CommandCompletionSpec(
    command="start_auth",
    fields=(
        FlagCompletionSpec(
            "domain",
            ("-d", "--domain"),
            depends_on=(),
            provider=_complete_domain_generic,
        ),
        FlagCompletionSpec(
            "dc_ip",
            ("--dc-ip",),
            depends_on=("domain",),
            provider=_complete_dc_ip_for_start_auth,
        ),
        FlagCompletionSpec(
            "username",
            ("-u", "--username"),
            depends_on=("domain",),
            provider=_complete_username_generic,
        ),
        FlagCompletionSpec(
            "password",
            ("-p", "--password"),
            depends_on=("domain", "username"),
            provider=_complete_password_generic,
        ),
    ),
)
FLAG_COMPLETION_SPECS["start_auth"] = START_AUTH_COMPLETION_SPEC
