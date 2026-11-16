"""The asset-scope command-line surface, shared by the launcher and the engine.

``adscan ci`` and ``adscan start`` take the same five scope flags. The launcher
runs on the host and must reject a syntax error before Docker starts; the engine
(and the native Windows runtime, which has no launcher) parses the same flags
again before its first network contact. Both read the flag names, the argument
definitions and the parsing from here, so they cannot drift. Stdlib only: the
model layer (:mod:`adscan_core.engagement_scope_model`) does the grammar.

Flag grammar (each repeatable)::

    --scope-allow VALUE[,VALUE...]    only these may be touched
    --scope-deny VALUE[,VALUE...]     never touch these (deny always wins)
    --scope-allow-file PATH           one entry per line, '#' comments
    --scope-deny-file PATH
    --scope-dc-access {directory,full}

A host file reaches the engine by a read-only bind mount of that one file (the
launcher rewrites the flag value to the container path, under
:data:`adscan_core.container_io.SCOPE_IO_CONTAINER_DIR`); the engine re-reads it
with the same parser, so the scope it records is the one the launcher validated.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Sequence

from adscan_core.engagement_scope_model import (
    DC_ACCESS_DIRECTORY_ONLY,
    DC_ACCESS_FULL,
    MAX_ENTRIES,
    SCOPE_FILE_LIMITS_PHRASE,
    AssetScope,
    ParsedScope,
    ScopeEntry,
    ScopeSyntaxError,
    normalise_dc_access,
    parse_scope_values,
    read_scope_file,
)

SCOPE_ALLOW_FLAG = "--scope-allow"
SCOPE_DENY_FLAG = "--scope-deny"
SCOPE_ALLOW_FILE_FLAG = "--scope-allow-file"
SCOPE_DENY_FILE_FLAG = "--scope-deny-file"
SCOPE_DC_ACCESS_FLAG = "--scope-dc-access"

#: Every scope flag, in the order the help lists them.
SCOPE_FLAGS: tuple[str, ...] = (
    SCOPE_ALLOW_FLAG,
    SCOPE_DENY_FLAG,
    SCOPE_ALLOW_FILE_FLAG,
    SCOPE_DENY_FILE_FLAG,
    SCOPE_DC_ACCESS_FLAG,
)
#: ``--scope-dc-access`` choices as typed (``directory`` is stored as
#: ``directory_only``).
SCOPE_DC_ACCESS_CHOICES: tuple[str, ...] = ("directory", "full")

#: Origin recorded on an entry given inline on the command line.
ORIGIN_CLI = "cli"

#: How the recorded scope relates to new flags; shown in ``--help``.
SCOPE_RERUN_RULE = (
    "The scope is recorded in the workspace. A later run on the same workspace "
    "keeps it unless scope flags are given; flags REPLACE it (a new revision, "
    "recorded with who and when). A host the current scope excludes is never "
    "contacted again, even if an earlier run collected it."
)

#: One-line help per flag (English, client-safe: the launcher and the engine
#: both print it).
SCOPE_FLAG_HELP: dict[str, str] = {
    SCOPE_ALLOW_FLAG: (
        "Engagement scope: only these hosts or accounts may be touched. IP, CIDR, "
        "range, FQDN, *.suffix, short host name, SID, DN, DOMAIN\\name or UPN; "
        "comma-separated, repeatable."
    ),
    SCOPE_DENY_FLAG: (
        "Engagement scope: never touch these hosts or accounts (deny always wins "
        "over allow). Same grammar as --scope-allow; comma-separated, repeatable."
    ),
    SCOPE_ALLOW_FILE_FLAG: (
        "Read allow entries from a file: one per line, '#' comments, blank lines, "
        f"CRLF and a BOM accepted ({SCOPE_FILE_LIMITS_PHRASE}). Repeatable."
    ),
    SCOPE_DENY_FILE_FLAG: "Read deny entries from a file (same format). Repeatable.",
    SCOPE_DC_ACCESS_FLAG: (
        "Domain controllers not named in an allow-list: 'directory' (default) uses "
        "them for directory reads only (LDAP, Kerberos, DNS, time, SYSVOL); 'full' "
        "assesses every domain controller of an in-scope domain as a host, named or "
        "not. A denied domain controller is never contacted either way."
    ),
}

#: What each ``dc_access`` value means, as ONE sentence per value: the wording
#: every surface shows (the confirmation summary, ``scope show``, the web's
#: option text and its summary line). It states what the engine does, and a test
#: holds the two together: under ``full`` a domain controller the allow-list
#: does not name IS assessed as a host; under ``directory_only`` it is not.
DC_ACCESS_SENTENCES: dict[str, str] = {
    DC_ACCESS_DIRECTORY_ONLY: (
        "Domain controllers the allow-list does not name are used for directory reads "
        "only (LDAP, Kerberos, DNS, time, SYSVOL); they are not assessed as hosts."
    ),
    DC_ACCESS_FULL: (
        "Every domain controller of an in-scope domain is assessed as a host, whether "
        "or not the allow-list names it."
    ),
}


def dc_access_sentence(dc_access: object) -> str:
    """The one sentence that says how domain controllers are treated under ``dc_access``."""
    key = DC_ACCESS_FULL if str(dc_access or "").strip().lower() == DC_ACCESS_FULL else DC_ACCESS_DIRECTORY_ONLY
    return DC_ACCESS_SENTENCES[key]

_DESTS: dict[str, str] = {
    SCOPE_ALLOW_FLAG: "scope_allow",
    SCOPE_DENY_FLAG: "scope_deny",
    SCOPE_ALLOW_FILE_FLAG: "scope_allow_file",
    SCOPE_DENY_FILE_FLAG: "scope_deny_file",
    SCOPE_DC_ACCESS_FLAG: "scope_dc_access",
}
_METAVARS: dict[str, str] = {
    SCOPE_ALLOW_FLAG: "VALUE[,VALUE...]",
    SCOPE_DENY_FLAG: "VALUE[,VALUE...]",
    SCOPE_ALLOW_FILE_FLAG: "PATH",
    SCOPE_DENY_FILE_FLAG: "PATH",
}


def add_scope_arguments(parser: argparse.ArgumentParser) -> argparse._ArgumentGroup:
    """Register the five scope flags on ``parser`` (one argument group).

    Used by the container ``ci`` and ``start`` parsers and the launcher's own
    ``start`` parser, so the three declare exactly the same surface.
    """
    group = parser.add_argument_group(
        "engagement scope (hosts and accounts)", SCOPE_RERUN_RULE
    )
    for flag in (SCOPE_ALLOW_FLAG, SCOPE_DENY_FLAG, SCOPE_ALLOW_FILE_FLAG, SCOPE_DENY_FILE_FLAG):
        group.add_argument(
            flag,
            dest=_DESTS[flag],
            action="append",
            default=None,
            metavar=_METAVARS[flag],
            help=SCOPE_FLAG_HELP[flag],
        )
    group.add_argument(
        SCOPE_DC_ACCESS_FLAG,
        dest=_DESTS[SCOPE_DC_ACCESS_FLAG],
        choices=SCOPE_DC_ACCESS_CHOICES,
        default=None,
        help=SCOPE_FLAG_HELP[SCOPE_DC_ACCESS_FLAG],
    )
    return group


@dataclass(frozen=True)
class ScopeFlagValues:
    """The raw values of the scope flags (before parsing)."""

    allow: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()
    allow_files: tuple[str, ...] = ()
    deny_files: tuple[str, ...] = ()
    dc_access: str | None = None

    @property
    def lists_given(self) -> bool:
        """True when an allow or deny list was given (inline or as a file)."""
        return bool(self.allow or self.deny or self.allow_files or self.deny_files)

    @property
    def any_given(self) -> bool:
        """True when any scope flag was given."""
        return self.lists_given or bool(self.dc_access)


def scope_flag_values(ns: Any) -> ScopeFlagValues:
    """Read the scope flags from a parsed argparse namespace."""

    def _list(dest: str) -> tuple[str, ...]:
        value = getattr(ns, dest, None) or ()
        if isinstance(value, str):
            value = (value,)
        return tuple(str(v) for v in value if str(v or "").strip())

    dc = getattr(ns, _DESTS[SCOPE_DC_ACCESS_FLAG], None)
    return ScopeFlagValues(
        allow=_list("scope_allow"),
        deny=_list("scope_deny"),
        allow_files=_list("scope_allow_file"),
        deny_files=_list("scope_deny_file"),
        dc_access=str(dc) if dc else None,
    )


def split_scope_tokens(tokens: Sequence[str]) -> tuple[ScopeFlagValues, list[str]]:
    """Pull the scope flags out of raw pass-through tokens.

    The launcher forwards ``ci`` arguments through ``argparse.REMAINDER``, so
    the scope flags arrive as raw tokens, in ``--flag VALUE`` or
    ``--flag=VALUE`` form, anywhere in the list.

    Returns:
        The flag values and the remaining tokens, in order.

    Raises:
        ScopeSyntaxError: A scope flag without a value, or a
            ``--scope-dc-access`` value other than ``directory``/``full``.
    """
    found: dict[str, list[str]] = {flag: [] for flag in SCOPE_FLAGS}
    rest: list[str] = []
    index = 0
    items = list(tokens)
    while index < len(items):
        token = items[index]
        flag, _, inline = token.partition("=")
        if flag in found:
            if "=" in token:
                value = inline
                index += 1
            elif index + 1 < len(items):
                value = items[index + 1]
                index += 2
            else:
                raise ScopeSyntaxError(flag, 0, "needs a value")
            if not str(value or "").strip():
                raise ScopeSyntaxError(flag, 0, "needs a value")
            found[flag].append(value)
            continue
        rest.append(token)
        index += 1
    dc_values = found[SCOPE_DC_ACCESS_FLAG]
    dc_access = dc_values[-1] if dc_values else None
    if dc_access is not None and dc_access not in SCOPE_DC_ACCESS_CHOICES:
        raise ScopeSyntaxError(
            SCOPE_DC_ACCESS_FLAG, 0, f"'{dc_access}' is not one of directory, full"
        )
    return (
        ScopeFlagValues(
            allow=tuple(found[SCOPE_ALLOW_FLAG]),
            deny=tuple(found[SCOPE_DENY_FLAG]),
            allow_files=tuple(found[SCOPE_ALLOW_FILE_FLAG]),
            deny_files=tuple(found[SCOPE_DENY_FILE_FLAG]),
            dc_access=dc_access,
        ),
        rest,
    )


def scope_flag_tokens(values: ScopeFlagValues) -> list[str]:
    """Render scope flag values back into argv tokens (``--flag VALUE`` pairs)."""
    tokens: list[str] = []
    for flag, items in (
        (SCOPE_ALLOW_FLAG, values.allow),
        (SCOPE_DENY_FLAG, values.deny),
        (SCOPE_ALLOW_FILE_FLAG, values.allow_files),
        (SCOPE_DENY_FILE_FLAG, values.deny_files),
    ):
        for item in items:
            tokens.extend([flag, item])
    if values.dc_access:
        tokens.extend([SCOPE_DC_ACCESS_FLAG, values.dc_access])
    return tokens


@dataclass(frozen=True)
class ScopeInput:
    """Parsed scope flags: the entries per list, and what the operator asked for.

    ``lists_given`` False with a ``dc_access`` means "change only how domain
    controllers are treated, keep the recorded lists".
    """

    allow: tuple[ScopeEntry, ...] = ()
    deny: tuple[ScopeEntry, ...] = ()
    dc_access: str | None = None
    lists_given: bool = False
    warnings: tuple[str, ...] = ()
    files: tuple[dict[str, str], ...] = ()

    def to_scope(self, base: AssetScope | None = None) -> AssetScope:
        """The scope to record. Replace semantics, except a dc-access-only change."""
        if not self.lists_given and base is not None:
            return AssetScope.create(
                allow=base.allow,
                deny=base.deny,
                dc_access=self.dc_access or base.dc_access,
            )
        return AssetScope.create(
            allow=self.allow,
            deny=self.deny,
            dc_access=self.dc_access or DC_ACCESS_DIRECTORY_ONLY,
        )


def _file_digest(path: str) -> str:
    try:
        with open(path, "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()
    except OSError:
        return ""


def parse_scope_flags(
    values: ScopeFlagValues,
    *,
    read_file: Callable[[str], ParsedScope] = read_scope_file,
) -> ScopeInput:
    """Parse the inline values and read the files of the scope flags.

    Raises:
        ScopeSyntaxError: An invalid entry (named with its file and line), an
            unreadable file, or more than the entry bound across one list.
    """
    warnings: list[str] = []
    files: list[dict[str, str]] = []

    def _side(inline: Iterable[str], paths: Iterable[str], flag: str, name: str) -> list[ScopeEntry]:
        entries: list[ScopeEntry] = []
        inline = list(inline)
        if inline:
            parsed = parse_scope_values(inline, origin=ORIGIN_CLI)
            entries.extend(parsed.entries)
            warnings.extend(parsed.warnings)
        for path in paths:
            path = os.path.expanduser(str(path))
            parsed = read_file(path)
            entries.extend(parsed.entries)
            warnings.extend(parsed.warnings)
            files.append(
                {"list": name, "name": os.path.basename(str(path)), "sha256": _file_digest(str(path))}
            )
        if len({e.key for e in entries}) > MAX_ENTRIES:
            raise ScopeSyntaxError(flag, 0, f"more than {MAX_ENTRIES} entries in the {name} list")
        return entries

    allow = _side(values.allow, values.allow_files, SCOPE_ALLOW_FLAG, "allow")
    deny = _side(values.deny, values.deny_files, SCOPE_DENY_FLAG, "deny")
    dc_access = None
    if values.dc_access:
        dc_access = normalise_dc_access(values.dc_access)
    return ScopeInput(
        allow=tuple(allow),
        deny=tuple(deny),
        dc_access=dc_access,
        lists_given=values.lists_given,
        warnings=tuple(dict.fromkeys(warnings)),
        files=tuple(files),
    )


def scope_error_line(exc: ScopeSyntaxError) -> str:
    """The one operator line for a scope error (file, line, reason).

    A record that could not be WRITTEN is not a syntax error although the engine
    raises it as a subclass (so existing handlers stop the run): it is worded as
    what it is. Recognised by the marker the engine sets on that error
    (``is_write_failure``), because this module cannot import the engine.
    """
    if getattr(exc, "is_write_failure", False):
        reason = getattr(exc, "reason", "") or str(exc)
        return f"Engagement scope not saved, nothing was sent: {reason}"
    return f"Engagement scope not accepted, nothing was sent: {exc}"


#: What a domain-controller discovery says when the engagement scope left it
#: nothing to contact. Not "no controller was found": nothing was sent, so the
#: range says nothing about the network and widening it is not the remedy.
SCOPE_EMPTIED_DISCOVERY_HEADLINE = (
    "The engagement scope left no domain controller to contact in this range."
)


def scope_emptied_discovery_guidance(*, unattended: bool) -> list[str]:
    """How to check and correct a discovery the engagement scope emptied.

    One wording for the scanner's warning, the unattended stop and the
    interactive recovery panel. ``unattended`` names the scan's flags; a
    session names the ``scope`` command.
    """
    lines = [
        "Nothing was sent: every address in the range is excluded, or is not on the allow list.",
    ]
    if unattended:
        lines.append(
            f"Check the scope the run was given ({SCOPE_ALLOW_FLAG}, {SCOPE_DENY_FLAG} "
            "and their file forms, or the scan configuration)."
        )
        lines.append(
            "Re-run with a domain controller that is inside the scope, by range or "
            "by passing the domain and its address."
        )
    else:
        lines.append(
            "See what the scope holds with `scope show`, or ask about one address "
            "with `scope check <address>`."
        )
        lines.append(
            "Name a domain controller that is inside the scope, or correct the scope "
            "with `scope allow` / `scope remove` if it is wrong."
        )
    return lines


@dataclass
class ScopeMount:
    """Host scope files rewritten to read-only container paths."""

    tokens: list[str] = field(default_factory=list)
    mounts: list[tuple[str, str]] = field(default_factory=list)


def mount_scope_files(values: ScopeFlagValues, *, container_root: str) -> ScopeMount:
    """Map each host scope file to its own read-only mount and rewrite the flags.

    Every file gets its own folder (``<root>/<n>/<name>``), so two files with the
    same name never collide and the engine names the file the operator gave.
    """
    mounts: list[tuple[str, str]] = []

    def _remap(paths: Iterable[str], offset: int) -> tuple[str, ...]:
        out: list[str] = []
        for number, path in enumerate(paths, start=offset):
            host = os.path.abspath(os.path.expanduser(str(path)))
            container = f"{container_root}/{number}/{os.path.basename(host)}"
            mounts.append((host, container))
            out.append(container)
        return tuple(out)

    allow_files = _remap(values.allow_files, 1)
    deny_files = _remap(values.deny_files, 1 + len(values.allow_files))
    rewritten = ScopeFlagValues(
        allow=values.allow,
        deny=values.deny,
        allow_files=allow_files,
        deny_files=deny_files,
        dc_access=values.dc_access,
    )
    return ScopeMount(tokens=scope_flag_tokens(rewritten), mounts=mounts)


__all__ = [
    "DC_ACCESS_SENTENCES",
    "ORIGIN_CLI",
    "SCOPE_ALLOW_FILE_FLAG",
    "SCOPE_ALLOW_FLAG",
    "SCOPE_DC_ACCESS_CHOICES",
    "SCOPE_DC_ACCESS_FLAG",
    "SCOPE_DENY_FILE_FLAG",
    "SCOPE_DENY_FLAG",
    "SCOPE_EMPTIED_DISCOVERY_HEADLINE",
    "SCOPE_FLAGS",
    "SCOPE_FLAG_HELP",
    "SCOPE_RERUN_RULE",
    "ScopeFlagValues",
    "ScopeInput",
    "ScopeMount",
    "add_scope_arguments",
    "dc_access_sentence",
    "mount_scope_files",
    "parse_scope_flags",
    "scope_emptied_discovery_guidance",
    "scope_error_line",
    "scope_flag_tokens",
    "scope_flag_values",
    "split_scope_tokens",
]
