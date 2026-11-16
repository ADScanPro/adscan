"""How an operator states the asset-level engagement scope (allow and deny lists).

Three inputs, one recording path:

* the ``--scope-*`` flags of ``adscan ci`` and ``adscan start``
  (:mod:`adscan_core.engagement_scope_cli`);
* the ``asset_scope`` section of ``--scan-config`` (an unattended run and the
  web platform pass the scope as data);
* the REPL ``scope`` command inside ``adscan start``.

Each produces an :class:`~adscan_core.engagement_scope_model.AssetScope` and
records it through the engine SSOT
:func:`adscan_internal.services.engagement_scope.record_asset_scope`, which owns
the revision history, the resolution and ``scope.json``. Nothing here decides a
verdict; it only collects, confirms and records what the operator asked for.

Rerun rule: the recorded scope stays unless a new scope is given; a new one
REPLACES it (a new revision, with who and when). A change that WIDENS the scope
(drops a deny entry, adds to or drops an allow-list, opens domain controllers to
host assessment) is confirmed with default No; an unattended run never widens
through the REPL, and a run's flags or scan configuration are its decision.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from adscan_core import telemetry
from adscan_core.engagement_scope_cli import (
    ORIGIN_CLI,
    SCOPE_DC_ACCESS_CHOICES,
    ScopeFlagValues,
    ScopeInput,
    dc_access_sentence,
    parse_scope_flags,
    scope_error_line,
    scope_flag_values,
)
from adscan_core.engagement_scope_model import (
    AssetScope,
    ParsedScope,
    ScopeEntry,
    ScopeSyntaxError,
    normalise_dc_access,
    parse_scope_values,
    read_scope_file,
    widening_changes,
)
from adscan_core.interaction import is_non_interactive
from adscan_core.output._responsive_table import ResponsiveColumn, ResponsiveTable
from adscan_core.reporting.engagement_scope import (
    DECIDED_BY_CONFIGURATION,
    DECIDED_BY_OPERATOR,
    identity_observed,
    scope_cause_label,
    scope_cause_remedy,
)
from adscan_core.rich_output import (
    confirm_ask,
    mark_sensitive,
    print_error,
    print_exception,
    print_info,
    print_panel,
    print_success,
    print_table,
    print_warning,
)

#: ``decided_by`` for a scope the web user saved (the web writes it in the
#: scan-config section; its label carries the user's display name).
DECIDED_BY_WEB_USER = "web_user"
#: Values the scan-config section may carry in ``decided_by``.
SCAN_CONFIG_DECIDED_BY = frozenset({DECIDED_BY_CONFIGURATION, DECIDED_BY_WEB_USER})

#: ``source.kind`` values recorded with a revision.
SOURCE_CLI_FLAGS = "cli_flags"
SOURCE_SCAN_CONFIG = "scan_config"
SOURCE_REPL = "repl"

_ROWS_SHOWN = 50


# ── Requests ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AssetScopeRequest:
    """A scope the run was given, parsed and validated, not yet recorded."""

    scope_input: ScopeInput
    decided_by: str
    decided_by_label: str = ""
    source_kind: str = SOURCE_CLI_FLAGS

    def source(self) -> dict[str, Any]:
        """The ``source`` block recorded with the revision."""
        out: dict[str, Any] = {"kind": self.source_kind}
        if self.scope_input.files:
            out["files"] = [dict(f) for f in self.scope_input.files]
        return out


def scope_input_from_section(section: Any) -> ScopeInput:
    """Parse the scan-config ``asset_scope`` section (already shape-checked).

    Raises:
        ScopeSyntaxError: An invalid entry, naming the list and the position.
    """
    def _parse(values: Sequence[str]) -> ParsedScope:
        # An empty list clears that side (the section replaces the scope), so
        # only present entries go through the grammar.
        return parse_scope_values(list(values), origin="scan_config") if values else ParsedScope()

    allow = _parse(getattr(section, "allow", ()) or ())
    deny = _parse(getattr(section, "deny", ()) or ())
    dc_access = getattr(section, "dc_access", None)
    return ScopeInput(
        allow=allow.entries,
        deny=deny.entries,
        dc_access=normalise_dc_access(dc_access) if dc_access else None,
        # A present section is authoritative: an empty one clears the scope.
        lists_given=True,
        warnings=tuple(dict.fromkeys((*allow.warnings, *deny.warnings))),
    )


def resolve_scope_request(args: Any, scan_config: Any = None) -> AssetScopeRequest | None:
    """The scope this run was given, or ``None`` to keep the recorded one.

    Flags win over a scan-config section (one warning line says so).

    Raises:
        ScopeSyntaxError: A flag value, a file line or a section entry is invalid.
    """
    values: ScopeFlagValues = scope_flag_values(args)
    section = getattr(scan_config, "asset_scope", None) if scan_config is not None else None
    if values.any_given:
        if section is not None:
            print_warning(
                "Engagement scope: the --scope flags replace the asset_scope section of "
                "the scan configuration for this run."
            )
        return AssetScopeRequest(
            scope_input=parse_scope_flags(values),
            decided_by=DECIDED_BY_OPERATOR,
            source_kind=SOURCE_CLI_FLAGS,
        )
    if section is not None:
        return AssetScopeRequest(
            scope_input=scope_input_from_section(section),
            decided_by=str(getattr(section, "decided_by", "") or DECIDED_BY_CONFIGURATION),
            decided_by_label=str(getattr(section, "decided_by_label", "") or ""),
            source_kind=SOURCE_SCAN_CONFIG,
        )
    return None


def validate_scope_flags_or_exit(args: Any, *, exit_fn: Callable[[int], Any]) -> bool:
    """Parse the scope flags of ``ci``/``start`` before anything is sent.

    The native Windows runtime has no launcher, so this is where a syntax error
    stops the run there. Prints the error and calls ``exit_fn(2)`` on failure.
    """
    values = scope_flag_values(args)
    if not values.any_given:
        return True
    try:
        parse_scope_flags(values)
    except ScopeSyntaxError as exc:
        print_error(_escape(scope_error_line(exc)))
        exit_fn(2)
        return False
    return True


# ── Recording ──────────────────────────────────────────────────────────────


def _escape(text: str) -> str:
    from rich.markup import escape  # noqa: PLC0415

    return escape(str(text))


def _engine() -> Any:
    from adscan_internal.services import engagement_scope  # noqa: PLC0415

    return engagement_scope


def scope_record_unreadable(shell: Any) -> bool:
    """True when the workspace holds a scope record the engine cannot use.

    The engine then fails closed (no host is contacted). ``asset_scope`` returns
    a non-empty placeholder in that state, so the engine's own predicate is the
    only way to tell it from a recorded scope.
    """
    return bool(_engine().asset_scope_unreadable(shell))


def _scope_file_path(shell: Any) -> str:
    workspace = getattr(shell, "current_workspace_dir", None)
    return os.path.join(os.fspath(workspace), "scope.json") if workspace else "scope.json"


def unreadable_scope_lines(shell: Any) -> list[str]:
    """The error and the fix for an unreadable scope record."""
    path = mark_sensitive(_escape(_scope_file_path(shell)), "path")
    return [
        f"The recorded engagement scope in {path} could not be read. "
        "ADscan contacts no host until a scope is recorded again.",
        "Fix the file, or record the scope again: rerun with the --scope flags (or the "
        "scan configuration's asset_scope section), or use 'scope allow' / 'scope deny'.",
    ]


def _print_unreadable(shell: Any) -> None:
    for line in unreadable_scope_lines(shell):
        print_error(line)


def _scope_payload(shell: Any) -> Mapping[str, Any]:
    """The persisted ``asset_scope`` block of the open workspace (``{}`` if none)."""
    workspace = ""
    for attr in ("current_workspace_dir",):
        value = getattr(shell, attr, None)
        if isinstance(value, (str, os.PathLike)) and str(value):
            workspace = os.fspath(value)
    if not workspace:
        return {}
    from adscan_internal.services.collector.scope import load_scope_payload  # noqa: PLC0415

    payload = load_scope_payload(os.path.join(workspace, "scope.json")) or {}
    block = payload.get("asset_scope") if isinstance(payload, Mapping) else None
    return block if isinstance(block, Mapping) else {}


def _entries(count: int) -> str:
    return f"{count} entr{'y' if count == 1 else 'ies'}"


def _type_counts(entries: Sequence[ScopeEntry]) -> str:
    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry.type] = counts.get(entry.type, 0) + 1
    return ", ".join(f"{n} {t.replace('_', ' ')}" for t, n in sorted(counts.items()))


def _preview_lines(scope: AssetScope, *, widening: Sequence[str]) -> list[str]:
    lines: list[str] = []
    if scope.empty:
        lines.append("No allow-list and no deny-list: every in-scope host may be assessed.")
        return lines
    if scope.allow:
        lines.append(f"Allow: {_entries(len(scope.allow))} ({_type_counts(scope.allow)}).")
    else:
        lines.append("Allow: no allow-list (every host not denied may be assessed).")
    if scope.deny:
        lines.append(f"Deny: {_entries(len(scope.deny))} ({_type_counts(scope.deny)}). Deny always wins.")
    both = scope.in_both_lists()
    if both:
        shown = mark_sensitive(_escape(", ".join(both[:5])), "hostname")
        lines.append(f"In both lists, so denied: {shown}{' ...' if len(both) > 5 else ''}.")
    if scope.allow:
        # One wording for what the engine does with domain controllers (the
        # setting only matters under an allow-list).
        lines.append(dc_access_sentence(scope.dc_access))
    lines.append("Excluded hosts receive no traffic from ADscan; excluded accounts are never acted on.")
    for change in widening:
        lines.append(f"Widens the recorded scope: {change}.")
    return lines


def confirm_scope_change(
    shell: Any,
    new: AssetScope,
    *,
    title: str,
    ask: Callable[[str, bool], bool] = confirm_ask,
) -> bool:
    """Show the change and ask; widening defaults to No, narrowing to Yes.

    Unattended, nothing is asked: a narrowing change is accepted and a widening
    one is refused (an unattended session must not open its own authorisation).
    """
    old = _engine().asset_scope(shell)
    widening = widening_changes(old, new)
    lines = _preview_lines(new, widening=widening)
    if is_non_interactive(shell):
        for line in lines:
            print_info(f"Engagement scope: {line}")
        if widening:
            print_error(
                "Engagement scope: a change that widens the recorded scope needs an "
                "operator's confirmation; it was not applied."
            )
            return False
        return True
    print_panel("\n".join(lines), title=f"[bold]{_escape(title)}[/bold]", border_style="cyan")
    if widening:
        return bool(ask("This widens what ADscan may touch. Apply it?", False))
    return bool(ask("Apply this engagement scope?", True))


def record_scope(shell: Any, scope: AssetScope, request: AssetScopeRequest) -> dict[str, Any]:
    """Record ``scope`` (a new revision when it changed) and report the result."""
    engine = _engine()
    before = engine.asset_scope(shell)
    if before is not None and before.digest() == scope.digest():
        print_info("Engagement scope unchanged: the recorded scope applies.")
        return dict(_scope_payload(shell))
    block = engine.record_asset_scope(
        shell,
        scope,
        decided_by=request.decided_by,
        decided_by_label=request.decided_by_label,
        source=request.source(),
    )
    for warning in request.scope_input.warnings:
        print_warning(f"Engagement scope: {_escape(warning)}")
    if scope.empty:
        print_success("Engagement scope cleared: no host or account is excluded.")
    else:
        print_success(
            f"Engagement scope recorded (revision {block.get('revision', '?')}): "
            f"{len(scope.allow)} allow, {len(scope.deny)} deny."
        )
    return block


def apply_scope_request(
    shell: Any,
    request: AssetScopeRequest | None,
    *,
    confirm: bool,
    ask: Callable[[str, bool], bool] = confirm_ask,
) -> bool:
    """Apply the run's scope request (or announce the recorded scope).

    Args:
        confirm: Interactive ``start``: show the summary and ask before
            recording. ``ci`` passes ``False``: its flags are its decision.

    Returns:
        False when the operator declined (the recorded scope stays).
    """
    engine = _engine()
    unreadable = scope_record_unreadable(shell)
    if request is None:
        if unreadable:
            _print_unreadable(shell)
        elif engine.asset_scope(shell) is not None:
            print_info("Engagement scope: the scope recorded for this workspace applies.")
            print_scope_summary(shell)
            print_scope_check(shell)
        return True
    if unreadable and (not request.scope_input.lists_given or request.scope_input.to_scope().empty):
        # Only a new, non-empty scope replaces a record ADscan could not read;
        # an empty one (or a domain-controller setting alone) would mean
        # continuing without the scope the client asked for.
        _print_unreadable(shell)
        return False
    scope = request.scope_input.to_scope(None if unreadable else engine.asset_scope(shell))
    if confirm:
        if not confirm_scope_change(shell, scope, title="Engagement scope", ask=ask):
            print_warning("Engagement scope not changed: the recorded scope (if any) applies.")
            return False
    else:
        for line in _preview_lines(scope, widening=widening_changes(engine.asset_scope(shell), scope)):
            print_info(f"Engagement scope: {line}")
    before = engine.asset_scope(shell)
    unchanged = before is not None and before.digest() == scope.digest()
    record_scope(shell, scope, request)
    print_scope_summary(shell)
    # Recording a scope resolves its entries: the check reads that resolution
    # instead of looking every name up a second time.
    print_scope_check(shell, entries_fresh=not unchanged)
    return True


def scope_configuration_errors(
    shell: Any, *, domain: str = "", dc_ip: str | None = None, username: str = ""
) -> list[str]:
    """Errors that stop a run under the recorded scope.

    A record that cannot be used, the DC rules, an ambiguous allow entry, and
    the scan credential (``username``) when the scope excludes that account.
    """
    engine = _engine()
    if scope_record_unreadable(shell):
        # The engine says why (the path and the reason); the fix line follows.
        reasons = list(engine.asset_scope_errors(shell))
        return reasons or [" ".join(unreadable_scope_lines(shell))]
    if engine.asset_scope(shell) is None:
        return []
    errors: list[str] = []
    try:
        dc_error = engine.dc_scope_configuration_error(shell, domain=domain or "", dc_ip=dc_ip or None)
    except Exception as exc:  # noqa: BLE001 - a check that fails must not pass silently
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        dc_error = "The engagement scope could not be checked against the domain controllers."
    if dc_error:
        errors.append(dc_error)
    errors.extend(engine.asset_scope_errors(shell))
    if username and domain:
        try:
            from adscan_internal.services.engagement_scope_principals import (  # noqa: PLC0415
                scan_credential_scope_error,
            )

            credential_error = scan_credential_scope_error(shell, domain=domain, username=username)
        except Exception as exc:  # noqa: BLE001 - a check that fails must not pass silently
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            credential_error = "The scan credential could not be checked against the engagement scope."
        if credential_error:
            errors.append(credential_error)
    return errors


def scope_stops_unattended_run(
    shell: Any, *, domain: str = "", dc_ip: str | None = None, username: str = ""
) -> bool:
    """Print the scope errors that stop an unattended run; True when there are any.

    One check for every unattended entry (``ci``, ``execute``, ``recheck``, and
    the web worker, which runs ``ci``): a scope record that cannot be used, a
    scan credential the scope excludes, or a scope the directory contradicts
    ends the run with exit 2 BEFORE its first network contact. The caller exits.
    """
    errors = scope_configuration_errors(shell, domain=domain, dc_ip=dc_ip, username=username)
    if not errors:
        return False
    for error in errors:
        print_error(_escape(error))
    print_error(nothing_sent_line(shell))
    return True


def nothing_sent_line(shell: Any) -> str:
    """The closing line of a run the scope stopped before its first contact.

    True to what left the machine: when the scope's names were looked up
    through the engagement's name server, those DNS questions are named.
    """
    try:
        asked = list(_engine().scope_name_servers_asked(shell))
    except Exception as exc:  # noqa: BLE001 - an unknown answer claims nothing
        telemetry.capture_exception(exc)
        asked = []
    if not asked:
        return "Nothing was sent: fix the engagement scope and run it again."
    servers = ", ".join(asked)
    return (
        "No host was contacted: only DNS questions about the scope's names were sent, to "
        f"{servers}. Fix the engagement scope and run it again."
    )


# ── Summary ────────────────────────────────────────────────────────────────


def _resolution_counts(block: Mapping[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in (block.get("resolution") or {}).get("entries") or ():
        if isinstance(row, Mapping):
            status = str(row.get("status") or "pending")
            counts[status] = counts.get(status, 0) + 1
    return counts


def summary_lines(shell: Any) -> list[str]:
    """The scope summary as plain lines (counts, resolution, who and when, DC rule)."""
    scope = _engine().asset_scope(shell)
    if scope is None:
        return ["No allow-list or deny-list is recorded for this workspace."]
    if scope_record_unreadable(shell):
        return unreadable_scope_lines(shell)
    block = _scope_payload(shell)
    counts = _resolution_counts(block)
    resolved_hosts = 0
    for row in (block.get("resolution") or {}).get("entries") or ():
        if isinstance(row, Mapping):
            # Observed computers only: a reading of the entry's own text
            # (a name that matched nothing yet) is not one.
            resolved_hosts += sum(
                1
                for i in row.get("identities") or ()
                if isinstance(i, Mapping)
                and i.get("kind") in ("", "computer", None)
                and identity_observed(i)
            )
    lines = [
        f"Revision {block.get('revision', '?')}: allow {_entries(len(scope.allow))}, "
        f"deny {_entries(len(scope.deny))}.",
    ]
    if counts:
        parts = [f"{n} {status}" for status, n in sorted(counts.items())]
        lines.append(f"Name entries: {', '.join(parts)}; {resolved_hosts} resolved to computers.")
    who = str(block.get("decided_by") or "")
    label = str(block.get("decided_by_label") or "")
    when = str(block.get("decided_at") or "")
    if who:
        who_text = f"{who} ({mark_sensitive(_escape(label), 'user')})" if label else who
        lines.append(f"Decided by {who_text} at {when} ({block.get('clock_frame', '')}).")
    if scope.allow:
        lines.append(dc_access_sentence(scope.dc_access))
    return lines


def print_scope_summary(shell: Any) -> None:
    """Print the scope summary lines (also safe unattended: lines, never a prompt)."""
    if scope_record_unreadable(shell):
        _print_unreadable(shell)
        return
    for line in summary_lines(shell):
        print_info(f"Engagement scope: {line}")


#: The scope's two tables degrade by design in a narrow terminal: the entry as
#: the operator wrote it never moves and is never cut; the columns that only
#: help (the id, where the entry came from) are stacked under it first.
_ENTRY_COLUMNS: tuple[ResponsiveColumn, ...] = (
    ResponsiveColumn("Id", priority=3, stack_label="Id"),
    ResponsiveColumn("List", priority=1, stack_label="List"),
    ResponsiveColumn("Type", priority=2, stack_label="Type"),
    ResponsiveColumn("Value", priority=0),
    ResponsiveColumn("Resolution", priority=1, stack_label="Resolution"),
    ResponsiveColumn("Origin", priority=4, stack_label="Origin", max_width=28),
)
_VERIFY_COLUMNS: tuple[ResponsiveColumn, ...] = (
    ResponsiveColumn("Id", priority=3, stack_label="Id"),
    ResponsiveColumn("List", priority=1, stack_label="List"),
    ResponsiveColumn("Entry", priority=0, max_width=34),
    ResponsiveColumn("Resolves to", priority=2, stack_label="Resolves to", max_width=34),
    # The outcome is what the operator reads: it keeps a readable measure, and
    # the list and the id are stacked under it before it is squeezed.
    ResponsiveColumn("Result", priority=0, min_width=30),
)


def _scope_table(columns: tuple[ResponsiveColumn, ...], *, primary: int, title: str) -> ResponsiveTable:
    return ResponsiveTable(
        columns=columns,
        primary=primary,
        table_kwargs={"title": title, "show_lines": False},
    )


def _entries_table(shell: Any, scope: AssetScope) -> None:
    status_by_id = {
        str(row.get("id")): str(row.get("status") or "")
        for row in (_scope_payload(shell).get("resolution") or {}).get("entries") or ()
        if isinstance(row, Mapping)
    }
    table = _scope_table(_ENTRY_COLUMNS, primary=3, title="Engagement scope entries")
    rows = [("allow", e) for e in scope.allow] + [("deny", e) for e in scope.deny]
    for name, entry in rows[:_ROWS_SHOWN]:
        table.add_row(
            entry.id,
            name,
            entry.type.replace("_", " "),
            mark_sensitive(_escape(entry.value), "hostname"),
            status_by_id.get(entry.id, "address" if entry.type in ("ip", "cidr", "range", "dns_suffix") else "pending"),
            mark_sensitive(_escape(entry.origin), "path"),
        )
    print_table(table)
    if len(rows) > _ROWS_SHOWN:
        print_info(f"{len(rows) - _ROWS_SHOWN} more entries are recorded in the workspace scope.json.")


# ── Target gate for REPL and execute verbs (gap G2) ─────────────────────────


def command_targets(arg_string: str, *, domain_is_first_positional: bool) -> tuple[str, str]:
    """The host and domain a verb's argument string names (``""`` when none).

    Reads ``--host``/``--target`` and ``-d``/``--domain`` (both ``--flag VALUE``
    and ``--flag=VALUE``), and the first positional as the domain when the verb
    declares it so. The flags-and-first-positional reading of
    :func:`adscan_internal.cli.repl_verb_targets.bind_command_targets`.
    """
    from adscan_internal.cli import repl_verb_targets as verbs  # noqa: PLC0415

    bound = verbs.bind_command_targets(
        arg_string, verbs.DOMAIN_FIRST if domain_is_first_positional else verbs.FLAGS_ONLY
    )
    return bound.host, bound.domain


def verb_targets(shell: Any, verb: str) -> Any:
    """How ``verb`` names its targets: the ONE declaration the gate reads.

    In order: the verb's declared grammar, the list of verbs that name no
    target, the handler's own signature (``do_<verb>(self, domain)``), the
    ``execute`` registry's ``domain_is_first_positional``, and for a verb
    nothing declares, the ``--host`` and ``-d`` flags.
    """
    import inspect  # noqa: PLC0415

    from adscan_internal.cli import repl_verb_targets as verbs  # noqa: PLC0415

    name = str(verb or "").strip().lower()
    declared = verbs.REPL_VERB_TARGETS.get(name)
    if declared is not None:
        return declared
    if name in verbs.REPL_VERBS_WITHOUT_TARGET:
        return verbs.NO_TARGETS
    method = (getattr(shell, "commands", None) or {}).get(name)
    if callable(method):
        try:
            params = [
                p
                for p in inspect.signature(method).parameters.values()
                if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
            ]
        except (TypeError, ValueError):
            params = []
        if params and params[0].name in verbs.DOMAIN_SIGNATURE_PARAMS:
            return verbs.DOMAIN_FIRST
    from adscan_internal.cli.execute import EXECUTE_SAFE_VERBS  # noqa: PLC0415

    spec = EXECUTE_SAFE_VERBS.get(name)
    if spec is not None and spec.domain_is_first_positional:
        return verbs.DOMAIN_FIRST
    return verbs.FLAGS_ONLY


def _domain_axis_refuses(shell: Any, domain: str, origin_domain: str | None) -> bool:
    """Whether the named domain is ruled out by the engagement scope.

    Refused: a domain the scope explicitly excludes, and, once the engagement has
    a target domain, any domain not confirmed in scope. Not refused: the run's
    own target (``origin_domain``, the ``--domain`` of ``execute``) and, in a
    session with no target yet, the first domain the operator names (the verb
    that names it is what makes it the target).
    """
    engine = _engine()
    verdict = engine.domain_scope_verdict(shell, domain)
    if verdict.in_scope:
        return False
    if verdict.basis == engine.BASIS_EXCLUDED:
        return True
    def _name(value: str) -> str:
        return str(value or "").strip().rstrip(".").lower()

    if origin_domain and _name(domain) == _name(origin_domain):
        return False
    return bool(engine.origin_domains(shell))


def _account_axis_refuses(shell: Any, account: str, domain: str, what: str) -> bool:
    """Whether the scope excludes the account a verb was told to act as.

    The rule of the scan's own credential (``scan_credential_scope_error``): an
    account the scope excludes is refused here, with one operator line and a
    refusal on the record. One the session cannot place yet is not refused at
    dispatch: the sign-in guard judges it again at the first sign-in, where the
    directory can be read. An account of another domain is the domain scope's
    question, asked above.
    """
    from adscan_internal.services.engagement_scope_principals import (  # noqa: PLC0415
        account_scope_refusal,
        prepare_accounts_for_scope,
        scope_cannot_place,
    )

    engine = _engine()
    prepare_accounts_for_scope(shell, [account], domain=domain or None)
    verdict = account_scope_refusal(shell, principal=account, domain=domain or None)
    if verdict is None or scope_cannot_place(verdict):
        return False
    if verdict.reason == engine.ASSET_REASON_DOMAIN_OUTSIDE:
        return False
    try:
        engine.record_scope_refusals(
            shell, [(account, verdict)], surface="repl", domain=domain or None
        )
    except Exception as exc:  # noqa: BLE001 - the record never changes the refusal
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    print_info(engine.asset_refusal_line(what, account, verdict))
    return True


def gate_command_targets(
    shell: Any, verb: str, arg_string: str, *, origin_domain: str | None = None
) -> bool:
    """The one dispatch-point gate for a verb that names a domain, a host or an account.

    Called by the REPL dispatch and by ``adscan execute`` before the verb runs.
    What the verb names is read from its declaration (:func:`verb_targets`):
    the flags, and the bare positionals of its own grammar. Returns False (after
    one operator line) when the engagement scope refuses the named domain, host
    or account; the verb is then not run.
    """
    try:
        from adscan_internal.cli import repl_verb_targets as verbs  # noqa: PLC0415
        from adscan_internal.cli.common import resolve_repl_domain_or_default  # noqa: PLC0415

        targets = verb_targets(shell, verb)
        if targets is verbs.NO_TARGETS:
            return True
        bound = verbs.bind_command_targets(arg_string, targets)
        what = str(verb or "").replace("_", " ")
        engine = _engine()
        # A verb typed without its domain acts on the session's current one.
        domain = bound.domain or (
            str(resolve_repl_domain_or_default(shell, None) or "") if bound.takes_domain else ""
        )
        if domain and _domain_axis_refuses(shell, domain, origin_domain):
            return bool(
                engine.require_repl_target_in_scope(shell, host=None, domain=domain, what=what)
            )
        # The domain qualifies a short host or account name only once the scope
        # holds it; the first domain a session names is not yet one it knows.
        known = domain if domain and engine.domain_scope_verdict(shell, domain).in_scope else ""
        if bound.host and not engine.require_repl_target_in_scope(
            shell, host=bound.host, domain=known or None, what=what
        ):
            return False
        if bound.account and _account_axis_refuses(shell, bound.account, known, what):
            return False
        return True
    except Exception as exc:  # noqa: BLE001 - a gate that cannot decide refuses
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error("The engagement scope could not be checked; the command was not run.")
        return False


# ── The REPL command ───────────────────────────────────────────────────────


SCOPE_USAGE = (
    "Usage: scope [show]\n"
    "       scope allow <entry>[,<entry>...]     add allow entries\n"
    "       scope deny <entry>[,<entry>...]      add deny entries\n"
    "       scope allow-file <path> | deny-file <path>\n"
    "       scope remove <id|value>[,...]        remove entries (a1, d2 or the value)\n"
    "       scope clear [allow|deny|all]\n"
    "       scope dc-access directory|full\n"
    "       scope check <host or account>        the verdict and the entry that decided it\n"
    "       scope verify                         what every entry resolves to, before anything is contacted"
)


def _current(shell: Any) -> AssetScope:
    return _engine().asset_scope(shell) or AssetScope()


def _apply_repl_change(shell: Any, new: AssetScope, *, ask: Callable[[str, bool], bool]) -> None:
    if not getattr(shell, "current_workspace_dir", None):
        print_error("Engagement scope: open a workspace first (workspace select).")
        return
    if scope_record_unreadable(shell):
        # Replacing an unreadable record lets ADscan contact hosts again, so it
        # is treated as widening: shown, then asked with default No.
        if new.empty:
            _print_unreadable(shell)
            return
        _print_unreadable(shell)
        print_panel(
            "\n".join(_preview_lines(new, widening=["replaces the unreadable record"])),
            title="[bold]Record a new engagement scope[/bold]",
            border_style="yellow",
        )
        if is_non_interactive(shell) or not ask(
            "Record this scope in place of the unreadable one?", False
        ):
            print_warning("Engagement scope not changed: no host is contacted until it is recorded.")
            return
    elif _current(shell).digest() == new.digest():
        print_info("Engagement scope unchanged.")
        return
    elif not confirm_scope_change(shell, new, title="Change the engagement scope", ask=ask):
        print_warning("Engagement scope not changed.")
        return
    record_scope(
        shell,
        new,
        AssetScopeRequest(scope_input=ScopeInput(), decided_by=DECIDED_BY_OPERATOR, source_kind=SOURCE_REPL),
    )
    print_info("The new scope applies from the next action.")
    for error in scope_configuration_errors(shell, domain=str(getattr(shell, "domain", "") or "")):
        print_error(_escape(error))


def _remove(scope: AssetScope, tokens: Sequence[str]) -> tuple[AssetScope, list[str]]:
    wanted = {t.strip() for t in tokens if t.strip()}
    keys: set[tuple[str, str, str]] = set()
    unknown: list[str] = []
    for token in wanted:
        entry = scope.entry(token)
        if entry is not None:
            keys.add(entry.key)
            continue
        try:
            parsed = parse_scope_values([token], origin=ORIGIN_CLI).entries
        except ScopeSyntaxError:
            parsed = ()
        matched = [e for e in (*scope.allow, *scope.deny) if parsed and e.key == parsed[0].key]
        if matched:
            keys.update(e.key for e in matched)
        else:
            unknown.append(token)
    new = AssetScope.create(
        allow=[e for e in scope.allow if e.key not in keys],
        deny=[e for e in scope.deny if e.key not in keys],
        dc_access=scope.dc_access,
    )
    return new, unknown


def _check(shell: Any, target: str) -> None:
    engine = _engine()
    text = target.strip()
    principal = "\\" in text or "@" in text or text.upper().startswith("S-1-") or "=" in text
    domain = str(getattr(shell, "domain", "") or "") or None
    # One target the operator typed: the session is told about it (a name is
    # looked up, the directory record is read), then the verdict is a read.
    if principal:
        engine.prepare_scope_principals(shell, [text], domain=domain)
        verdict = engine.principal_scope_verdict(shell, principal=text, domain=domain)
    else:
        engine.prepare_scope_targets(shell, [text], domain=domain)
        verdict = engine.host_scope_verdict(shell, host=text, domain=domain)
    shown = mark_sensitive(_escape(verdict.label or text), "hostname")
    entry = _current(shell).entry(verdict.entry_id) if verdict.entry_id else None
    decided = (
        f" (entry {verdict.entry_id}: {mark_sensitive(_escape(entry.value), 'hostname')})" if entry else ""
    )
    if verdict.allowed:
        print_success(f"{shown}: inside the engagement scope{decided}.")
    elif verdict.outcome is engine.ScopeOutcome.UNDETERMINED:
        # Never worded as an exclusion: nothing excluded it, it could not be placed.
        cause = scope_cause_label(verdict.cause)
        print_warning(
            f"{shown}: not confirmed as within the engagement scope ({cause}){decided}. "
            f"{scope_cause_remedy(verdict.cause)}"
        )
    else:
        print_warning(f"{shown}: {verdict.reason.replace('_', ' ')}{decided}.")


# ── Whole-scope verification ("scope verify", and the line a run prints) ───

_HINTS = {
    "covers_this_address_only": (
        "covers that address only; a host with other addresses needs its name or "
        "its computer object"
    ),
    "name_without_address": "does not resolve; it stays not confirmed until it does",
    "resolves_without_directory_object": "resolves, with no computer of the directory behind it",
}


def _verification(
    shell: Any, *, refresh: bool = True, entries_fresh: bool = False
) -> Mapping[str, Any] | None:
    from adscan_internal.services.engagement_scope_verify import verify_asset_scope  # noqa: PLC0415

    return verify_asset_scope(shell, refresh=refresh, entries_fresh=entries_fresh)


def _marked(values: Sequence[str]) -> str:
    return ", ".join(mark_sensitive(_escape(str(v)), "hostname") for v in values)


def _print_issue(issue: Mapping[str, Any]) -> None:
    severity = str(issue.get("severity") or "")
    emit = print_error if severity == "error" else print_warning if severity == "warning" else print_info
    labels = [str(x) for x in issue.get("labels") or ()]
    entries = [str(x) for x in issue.get("entries") or ()]
    where = f" (entry {', '.join(entries)})" if entries else ""
    subject = f"{_marked(labels)}{where}: " if labels else ""
    emit(f"Engagement scope: {subject}{_escape(str(issue.get('statement') or ''))}")


def print_scope_check(shell: Any, *, entries_fresh: bool = False) -> Mapping[str, Any] | None:
    """Print the one-line scope check of a run's start (lines, never a prompt).

    ``entries_fresh``: the entries were resolved a moment ago (the scope was
    just recorded), so the check does not look their names up again.

    An exclusion that matched nothing is stated first: a typo there leaves the
    host the client wanted excluded inside the scope under its real name. The
    result stays with the session; the scan-end stamp records it with the run.
    Never raises.
    """
    try:
        result = _verification(shell, entries_fresh=entries_fresh)
        if not result or not result.get("usable", True):
            return result
        for issue in result.get("issues") or ():
            if issue.get("kind") == "deny_matched_nothing":
                _print_issue(issue)
        print_info(f"Engagement scope: {_escape(str(result.get('summary') or ''))}")
        if result.get("level") != "directory":
            print_info(f"Engagement scope: {_escape(str(result.get('level_statement') or ''))}")
        return result
    except Exception as exc:  # noqa: BLE001 - a check that fails never stops a run
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


def _verify(shell: Any, *, ask: Callable[[str, bool], bool]) -> None:
    """The REPL ``scope verify``: every entry, what the entries say together,
    the counts, and the offer to pin entries to their computer object."""

    if scope_record_unreadable(shell):
        _print_unreadable(shell)
        return
    result = _verification(shell)
    if result is None:
        print_info("No allow-list or deny-list is recorded for this workspace.")
        return
    issues = list(result.get("issues") or ())
    for issue in issues:
        if issue.get("kind") == "deny_matched_nothing":
            _print_issue(issue)
    counts = result.get("counts") or {}
    lines = [_escape(str(result.get("summary") or "")), "", _escape(str(result.get("level_statement") or ""))]
    for row in result.get("domains") or ():
        lines.append(
            f"  {mark_sensitive(_escape(str(row.get('domain'))), 'domain')}: "
            + (
                f"{row.get('computers')} computers read from the directory"
                if row.get("level") == "directory"
                else "directory not read yet"
            )
        )
    if counts.get("known_computers"):
        lines += [
            "",
            f"Inside the scope: {counts.get('inside', 0)}",
            f"Excluded: {counts.get('excluded', 0)}",
            f"Not confirmed: {counts.get('not_confirmed', 0)}",
        ]
        if counts.get("directory_only"):
            lines.append(f"Domain controllers used for directory reads only: {counts['directory_only']}")
    if result.get("names_not_looked_up"):
        lines.append(f"Names still waiting for the name service: {result['names_not_looked_up']}")
    print_panel("\n".join(lines), title="[bold]Engagement scope check[/bold]", border_style="cyan")
    for issue in issues:
        if issue.get("kind") != "deny_matched_nothing":
            _print_issue(issue)
    rows = list(result.get("entries") or ())
    attention = {"matched_nothing": 0, "matched_not_confirmed": 1}
    rows.sort(key=lambda r: (attention.get(str(r.get("outcome")), 2), r.get("side") != "deny"))
    table = _scope_table(_VERIFY_COLUMNS, primary=4, title="What each entry resolves to")
    for row in rows[:_ROWS_SHOWN]:
        shown = [str(x) for x in row.get("labels") or ()] or [str(x) for x in row.get("names") or ()]
        resolves = _marked(shown)
        addresses = [str(x) for x in row.get("addresses") or ()]
        if addresses and row.get("type") not in ("ip", "cidr", "range"):
            resolves = f"{resolves} ({_marked(addresses)})" if resolves else _marked(addresses)
        more = int(row.get("labels_omitted") or 0)
        if more:
            resolves += f" and {more} more"
        hints = [_HINTS[n] for n in row.get("notes") or () if n in _HINTS]
        result_text = _escape(str(row.get("statement") or ""))
        if hints and row.get("outcome") != "matched_nothing":
            result_text += " Note: " + "; ".join(hints) + "."
        table.add_row(
            str(row.get("id")),
            str(row.get("side")),
            mark_sensitive(_escape(str(row.get("value"))), "hostname"),
            resolves or "-",
            result_text,
        )
    print_table(table)
    if len(rows) > _ROWS_SHOWN:
        print_info(f"{len(rows) - _ROWS_SHOWN} more entries are not shown; the ones needing attention come first.")
    _offer_pins(shell, rows, ask=ask)


def _offer_pins(shell: Any, rows: Sequence[Mapping[str, Any]], *, ask: Callable[[str, bool], bool]) -> None:
    """Offer to pin address and name entries to the computer object behind them."""
    pins = {str(r["id"]): r["pin"] for r in rows if isinstance(r.get("pin"), Mapping)}
    if not pins or is_non_interactive(shell):
        return
    named = _marked([str(p.get("label")) for p in list(pins.values())[:5]])
    extra = f" and {len(pins) - 5} more" if len(pins) > 5 else ""
    question = (
        f"{len(pins)} {'entry names' if len(pins) == 1 else 'entries name'} one computer of the "
        f"directory by address or by name ({named}{extra}). Pin "
        f"{'it' if len(pins) == 1 else 'them'} to the computer object, so the entry follows a "
        "rename or a new address?"
    )
    if not ask(question, False):
        return
    current = _current(shell)

    def _pinned(entries: Sequence[ScopeEntry]) -> list[ScopeEntry]:
        out: list[ScopeEntry] = []
        for entry in entries:
            pin = pins.get(entry.id)
            if pin is None:
                out.append(entry)
                continue
            out.extend(parse_scope_values([str(pin["value"])], origin=f"pinned:{entry.value}").entries)
        return out

    _apply_repl_change(
        shell,
        AssetScope.create(
            allow=_pinned(current.allow), deny=_pinned(current.deny), dc_access=current.dc_access
        ),
        ask=ask,
    )


def _print_input_hints(entries: Sequence[ScopeEntry]) -> None:
    """Hints at input, without blocking: what a bare address entry covers."""
    singles = [e for e in entries if e.type == "ip"]
    if singles:
        print_info(
            f"Engagement scope: {_marked([e.value for e in singles[:3]])}"
            + (f" and {len(singles) - 3} more" if len(singles) > 3 else "")
            + f" {'covers' if len(singles) == 1 else 'each cover'} that address only. A host with "
            "other addresses needs its name or its computer object (its SID or DN)."
        )


def _print_unresolved_hints(shell: Any, entries: Sequence[ScopeEntry]) -> None:
    """After recording: the names just added that do not resolve yet."""
    wanted = {(e.type, e.value) for e in entries if e.type in ("fqdn", "short_host")}
    if not wanted:
        return
    result = _verification(shell, refresh=False)
    waiting = [
        str(r.get("value"))
        for r in (result or {}).get("entries") or ()
        if (r.get("type"), r.get("value")) in wanted and "name_without_address" in (r.get("notes") or ())
    ]
    if waiting:
        print_info(
            f"Engagement scope: {_marked(waiting[:3])}"
            + (f" and {len(waiting) - 3} more" if len(waiting) > 3 else "")
            + f" {'does' if len(waiting) == 1 else 'do'} not resolve to an address yet. It stays "
            "not confirmed until it does; 'scope verify' shows where every entry points."
        )


def handle_scope_command(
    shell: Any, args: str, *, ask: Callable[[str, bool], bool] = confirm_ask
) -> None:
    """The REPL ``scope`` command (see :data:`SCOPE_USAGE`)."""
    text = str(args or "").strip()
    action, _, rest = text.partition(" ")
    action = action.lower()
    rest = rest.strip()
    try:
        if action in ("", "show"):
            print_scope_summary(shell)
            scope = _engine().asset_scope(shell)
            if scope is not None and not scope_record_unreadable(shell):
                _entries_table(shell, scope)
            return
        if action in ("help", "-h", "--help"):
            print_info(_escape(SCOPE_USAGE))
            return
        unreadable = scope_record_unreadable(shell)
        if unreadable and action in ("remove", "clear", "dc-access"):
            # These edit a scope ADscan cannot read; only a new scope replaces it.
            _print_unreadable(shell)
            return
        current = AssetScope() if unreadable else _current(shell)
        if action in ("allow", "deny"):
            if not rest:
                print_error(f"Usage: scope {action} <entry>[,<entry>...]")
                return
            parsed = parse_scope_values([rest], origin="repl")
            for warning in parsed.warnings:
                print_warning(f"Engagement scope: {_escape(warning)}")
            if action == "allow":
                _print_input_hints(parsed.entries)
            allow = (*current.allow, *parsed.entries) if action == "allow" else current.allow
            deny = (*current.deny, *parsed.entries) if action == "deny" else current.deny
            _apply_repl_change(
                shell, AssetScope.create(allow=allow, deny=deny, dc_access=current.dc_access), ask=ask
            )
            _print_unresolved_hints(shell, parsed.entries)
            return
        if action in ("allow-file", "deny-file"):
            if not rest:
                print_error(f"Usage: scope {action} <path>")
                return
            parsed = read_scope_file(os.path.expanduser(rest.strip("'\"")))
            allow = (*current.allow, *parsed.entries) if action == "allow-file" else current.allow
            deny = (*current.deny, *parsed.entries) if action == "deny-file" else current.deny
            _apply_repl_change(
                shell, AssetScope.create(allow=allow, deny=deny, dc_access=current.dc_access), ask=ask
            )
            return
        if action == "remove":
            new, unknown = _remove(current, rest.replace(",", " ").split())
            for token in unknown:
                print_warning(f"Engagement scope: no entry {mark_sensitive(_escape(token), 'hostname')}.")
            _apply_repl_change(shell, new, ask=ask)
            return
        if action == "clear":
            which = (rest or "all").lower()
            if which not in ("allow", "deny", "all"):
                print_error("Usage: scope clear [allow|deny|all]")
                return
            new = AssetScope.create(
                allow=() if which in ("allow", "all") else current.allow,
                deny=() if which in ("deny", "all") else current.deny,
                dc_access=current.dc_access,
            )
            _apply_repl_change(shell, new, ask=ask)
            return
        if action == "dc-access":
            if rest not in SCOPE_DC_ACCESS_CHOICES:
                print_error("Usage: scope dc-access directory|full")
                return
            _apply_repl_change(
                shell,
                AssetScope.create(allow=current.allow, deny=current.deny, dc_access=rest),
                ask=ask,
            )
            return
        if action == "verify":
            _verify(shell, ask=ask)
            return
        if action == "check":
            if not rest:
                print_error("Usage: scope check <host or account>")
                return
            _check(shell, rest)
            return
        print_error(f"Unknown scope action: {_escape(action)}")
        print_info(_escape(SCOPE_USAGE))
    except ScopeSyntaxError as exc:
        print_error(_escape(scope_error_line(exc).replace(", nothing was sent", "")))


__all__ = [
    "DECIDED_BY_WEB_USER",
    "SCAN_CONFIG_DECIDED_BY",
    "SCOPE_USAGE",
    "AssetScopeRequest",
    "apply_scope_request",
    "confirm_scope_change",
    "handle_scope_command",
    "print_scope_check",
    "print_scope_summary",
    "record_scope",
    "resolve_scope_request",
    "scope_configuration_errors",
    "scope_input_from_section",
    "scope_stops_unattended_run",
    "summary_lines",
    "validate_scope_flags_or_exit",
    "widening_changes",
]
