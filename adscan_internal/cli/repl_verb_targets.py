"""Which host, domain and account a REPL verb's argument string names.

The engagement scope's dispatch gate (``asset_scope_cmd.gate_command_targets``)
has to know, BEFORE a verb runs, what the operator pointed it at. A verb that
reads its target from a flag (``--host``, ``-d``) says so in the flag; a verb
that reads it from a bare positional says so only in its own parser, and that
is what this module declares, once per verb:

* :data:`REPL_VERB_TARGETS`: the positional grammar of each verb that names a
  host, a domain or an account (the same field order its parser binds).
* :data:`REPL_VERBS_WITHOUT_TARGET`: every verb that names none, with the
  reason. A verb listed here is never asked about a target.
* A ``do_<verb>(self, domain)`` handler needs no entry: its signature is the
  declaration (the first positional is the domain), the rule the domain-context
  gate in ``cli/common.py`` already reads.

A structural test (``tests/unit/services/test_engagement_scope_integration.py``)
walks every ``do_*`` handler of ``PentestShell`` and fails when one is declared
nowhere, so a new verb cannot reach a host the scope was never asked about.

Pure data and string handling: no engine import, no I/O.
"""

from __future__ import annotations

import ipaddress
import shlex
from dataclasses import dataclass, field

# ── Grammar vocabulary ─────────────────────────────────────────────────────
#
# A grammar is the verb's positionals in order. These names are scope axes; any
# other name (written with a leading underscore) is a positional the scope does
# not judge. ``=word`` is a literal the token must equal (a subcommand).

AXIS_DOMAIN = "domain"
AXIS_HOST = "host"
AXIS_ACCOUNT = "account"
#: A domain, or the word ``all`` (every domain of the workspace: nothing to judge).
AXIS_DOMAIN_OR_ALL = "domain_or_all"
#: The verb takes an address and a domain in either order: an address is the
#: host, anything else the domain (``check_ntlm_auth``).
AXIS_HOST_OR_DOMAIN = "host_or_domain"

_AXES = frozenset(
    {AXIS_DOMAIN, AXIS_HOST, AXIS_ACCOUNT, AXIS_DOMAIN_OR_ALL, AXIS_HOST_OR_DOMAIN}
)

HOST_FLAGS = ("--host", "--target")
DOMAIN_FLAGS = ("-d", "--domain")
ACCOUNT_FLAGS = ("-u", "--user", "--username")
_TARGET_FLAGS = frozenset((*HOST_FLAGS, *DOMAIN_FLAGS, *ACCOUNT_FLAGS))

#: Flags whose NEXT token is their value, so it is never read as a positional.
#: The secret flags are here on purpose: a password is never bound to an axis.
_VALUE_FLAGS = frozenset(
    {
        "-p",
        "--password",
        "--pass",
        "-h",
        "-H",
        "--hash",
        "--credential",
        "--islocal",
        "--service",
        "--type",
        "--timeout",
        "--trigger-timeout",
        "--method",
        "--socks5",
        "--listener-ip",
        "--listener",
        "--actor-sid",
        "--impersonate",
        "--spn",
        "--file-type",
        "--filename",
        "--wait",
        "--dir",
        "--mode",
        "--max",
        "--depth",
        "--path-steps",
        "--relation",
        "--since",
        "--vs",
        "--output",
        "--cve",
        "--targets",
        "--concurrency",
        "--dc-ip",
        "--os",
        "--hosts",
        "-w",
        "--workspace",
    }
)


@dataclass(frozen=True)
class VerbTargets:
    """How one verb names its targets.

    Attributes:
        grammars: The positional forms the verb accepts, each a tuple of field
            names in order. Several forms are told apart by their literals and
            their length.
        flags: Axes the verb also reads from a flag although no grammar names
            them (``smb_shares <domain> --host <host>``). The axes a grammar
            names are always readable by flag.
    """

    grammars: tuple[tuple[str, ...], ...] = ()
    flags: frozenset[str] = field(default_factory=frozenset)

    def flag_axes(self) -> frozenset[str]:
        """The axes this verb reads from ``--host`` / ``-d`` / ``-u``."""
        named: set[str] = set(self.flags)
        for grammar in self.grammars:
            for name in grammar:
                if name == AXIS_DOMAIN_OR_ALL:
                    named.add(AXIS_DOMAIN)
                elif name == AXIS_HOST_OR_DOMAIN:
                    named.update((AXIS_HOST, AXIS_DOMAIN))
                elif name in _AXES:
                    named.add(name)
        return frozenset(named)


@dataclass(frozen=True)
class BoundTargets:
    """The host, domain and account one argument string names (``""`` when none)."""

    host: str = ""
    domain: str = ""
    account: str = ""
    #: The verb's grammar has a domain position (so a bare verb acts on the
    #: session's current domain).
    takes_domain: bool = False


#: A verb whose first positional is the domain (the signature rule and the
#: ``execute`` registry's ``domain_is_first_positional``). ``--host`` is read
#: too: the flag has one meaning on every verb that has no grammar of its own.
DOMAIN_FIRST = VerbTargets(grammars=((AXIS_DOMAIN,),), flags=frozenset({AXIS_HOST}))
#: A verb nothing declares (not a ``do_*`` handler of the shell): the flags only.
FLAGS_ONLY = VerbTargets(flags=frozenset({AXIS_HOST, AXIS_DOMAIN}))
#: A verb that names no target.
NO_TARGETS = VerbTargets()

_CRED = (AXIS_DOMAIN, AXIS_ACCOUNT, "_password")
_HOST_CRED = (AXIS_DOMAIN, AXIS_HOST, AXIS_ACCOUNT, "_password")
_DUMP = (AXIS_DOMAIN, AXIS_ACCOUNT, "_password", AXIS_HOST, "_islocal")
_SAVE = (AXIS_DOMAIN, AXIS_ACCOUNT, "_credential", AXIS_HOST, "_service")


def _one(*grammar: str, flags: tuple[str, ...] = ()) -> VerbTargets:
    return VerbTargets(grammars=(tuple(grammar),), flags=frozenset(flags))


REPL_VERB_TARGETS: dict[str, VerbTargets] = {
    # A host named by a bare positional.
    "dump_host": _one(AXIS_DOMAIN, AXIS_HOST, AXIS_ACCOUNT, "_password", "_islocal"),
    "deploy_binary": _one("_binary", AXIS_HOST, AXIS_DOMAIN, AXIS_ACCOUNT, "_secret"),
    "check_ntlm_auth": _one(AXIS_HOST_OR_DOMAIN, AXIS_HOST_OR_DOMAIN),
    "capture_ntlm_share_drop": _one(AXIS_DOMAIN, AXIS_HOST, "_share"),
    "relay_ldap": _one(AXIS_HOST, flags=(AXIS_DOMAIN,)),
    "relay_rbcd": _one(AXIS_HOST, flags=(AXIS_DOMAIN,)),
    "check_autologon": _one(*_HOST_CRED),
    "show_powershell_history": _one(*_HOST_CRED),
    "check_firefox_credentials": _one(*_HOST_CRED),
    "check_powershell_transcripts": _one(*_HOST_CRED),
    "check_winrm_sensitive_data": _one(*_HOST_CRED),
    "mssql_check_impersonate": _one(*_HOST_CRED),
    "mssql_impersonate": _one(*_HOST_CRED),
    "mssql_steal_ntlmv2": _one(*_HOST_CRED, "_islocal"),
    "dump_lsa": _one(*_DUMP),
    "dump_lsass": _one(*_DUMP),
    "dump_sam": _one(*_DUMP),
    "dump_dpapi": _one(*_DUMP),
    "is_user_dc": _one(AXIS_DOMAIN, AXIS_HOST),
    "is_computer_dc": _one(AXIS_DOMAIN, AXIS_HOST),
    "check_dns": _one(AXIS_DOMAIN, AXIS_HOST),
    "smb_shares": _one(AXIS_DOMAIN, flags=(AXIS_HOST,)),
    # An account named by a bare positional (the credential the verb signs in with).
    "dump_registries": _one(*_CRED),
    "get_flags": _one(*_CRED),
    "dcsync": _one(*_CRED),
    "smb_auth_shares": _one(*_CRED),
    "user_postauth_access": _one(*_CRED),
    "enumerate_user_aces": _one(*_CRED),
    "enum_adcs_privs": _one(*_CRED),
    "raise_child": _one(*_CRED),
    "kerberoast_preauth": _one(AXIS_DOMAIN, AXIS_ACCOUNT),
    "creds": VerbTargets(
        grammars=(
            ("=save", *_SAVE),
            ("=add", *_SAVE),
            ("=select", AXIS_DOMAIN),
        )
    ),
    # A domain named by a positional the handler's signature does not show.
    "binary_ops": _one(AXIS_DOMAIN),
    "check_dc_ntlm_auth_type": _one(AXIS_DOMAIN),
    "enum_all_user_privs": _one(AXIS_DOMAIN),
    "enum_all_user_postauth_access": _one(AXIS_DOMAIN),
    "refresh_inventory": _one(AXIS_DOMAIN_OR_ALL),
    "attack_path_discovery": _one(AXIS_DOMAIN, "_max_depth"),
    "attack_paths": _one(AXIS_DOMAIN),
    "reset_attack_path_statuses": _one(AXIS_DOMAIN),
    "paths_execute": VerbTargets(
        grammars=((AXIS_DOMAIN, "_path", "_technique"), ("_path", "_technique"))
    ),
    "posture": VerbTargets(grammars=(("=probe", AXIS_DOMAIN),)),
    "cleanup_credential": VerbTargets(grammars=(("=set", AXIS_DOMAIN),)),
}

_LOCAL = "works on the workspace's own files; nothing is contacted"
_SESSION = "session and shell housekeeping; nothing is contacted"
_READ = "reads what an earlier scan recorded; nothing is contacted"
_REPORT = "builds a document from the workspace; nothing is contacted"

REPL_VERBS_WITHOUT_TARGET: dict[str, str] = {
    # Session, shell and workspace housekeeping.
    "clear": _SESSION,
    "update": _SESSION,
    "info": _SESSION,
    "benchmark": _SESSION,
    "workspace": _SESSION,
    "ask": _SESSION,
    "exit": _SESSION,
    "help": _SESSION,
    "explain": _SESSION,
    "export": _LOCAL,
    "cd": _LOCAL,
    "ls": _LOCAL,
    "rm": _LOCAL,
    "cp": _LOCAL,
    "mv": _LOCAL,
    "mkdir": _LOCAL,
    "cat": _LOCAL,
    "clear_all": _LOCAL,
    "clear_auths": _LOCAL,
    "add_auths": _LOCAL,
    "clear_creds_and_auths": _LOCAL,
    "system": "the operator's own shell command, not a contact ADscan makes",
    "set": "records a setting; a host range it names is judged when a scan contacts it",
    "scope": "the engagement scope's own command",
    # Reads of recorded data.
    "cracking_history": _READ,
    "massdns_report": _READ,
    "inventory_diff": _READ,
    "paths_inspect": _READ,
    "attack_steps": _READ,
    "graph_stats": _READ,
    "validate_attack_graph": _READ,
    "show_timeline": _READ,
    "show_adcs_cache": _READ,
    "extract_base_dn": "derives the base DN from the domain's name; nothing is contacted",
    "cracking": "cracks a hash offline; nothing in the directory is contacted",
    "harvest": _READ,
    "jobs": _SESSION,
    # Documents.
    "initialize_report": _REPORT,
    "compliance_scope": _REPORT,
    "deliver": _REPORT,
    "cheatsheet": _REPORT,
    "cheat": _REPORT,
    "generate_report": _REPORT,
    # Records the operator states; the contacts they lead to pass the scope there.
    "update_domain_data": "records what the operator states about a domain; nothing is contacted",
    "update_resolv_conf": "rewrites the scanning host's resolver file; nothing is contacted",
    # Verbs whose target is not in the argument string; the seam they reach asks.
    "start_unauth": "starts a scan: the scan records its own target and applies the scope itself",
    "start_auth": "starts a scan: the scan records its own target and applies the scope itself",
    "cves": "targets come from a file or the workspace; the scanner partitions them by scope",
    "exploit_gpo_abuse": "a wizard: each step it runs passes the scope at the executor",
    "exploit_gpo_rollback": "undoes a recorded change by its ledger id",
    "poisoning": "listens on the scanning host; inbound callers pass the listener broker's source check",
    "clear_poisoning": _SESSION,
    "stop_poisoning": _SESSION,
    "stop_writeshare": _SESSION,
    "session": "manages reverse-shell sessions already open",
    "download": "acts on the session already open",
    "upload": "acts on the session already open",
    "ligolo": "manages the local proxy; a contact through it passes the scope at its own seam",
}

#: First-parameter names that make a handler's signature its declaration.
DOMAIN_SIGNATURE_PARAMS = frozenset({"domain", "target_domain", "domain_name"})


def looks_like_address(token: str) -> bool:
    """Whether ``token`` is an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(str(token or "").strip())
    except ValueError:
        return False
    return True


def _tokens(arg_string: str) -> list[str]:
    try:
        return shlex.split(str(arg_string or ""))
    except ValueError:
        return str(arg_string or "").split()


def _literals_match(grammar: tuple[str, ...], positionals: list[str]) -> bool:
    for index, name in enumerate(grammar):
        if not name.startswith("="):
            continue
        if index >= len(positionals) or positionals[index].lower() != name[1:]:
            return False
    return True


def _pick_grammar(
    grammars: tuple[tuple[str, ...], ...], positionals: list[str]
) -> tuple[str, ...] | None:
    """The form the positionals are in: exact length, else the longest that fits."""
    candidates = [g for g in grammars if _literals_match(g, positionals)]
    if not candidates:
        return None
    count = len(positionals)
    exact = [g for g in candidates if len(g) == count]
    if exact:
        return exact[0]
    shorter = [g for g in candidates if len(g) <= count]
    if shorter:
        return max(shorter, key=len)
    return min(candidates, key=len)


def _bind(grammar: tuple[str, ...], values: list[str], bound: dict[str, str]) -> None:
    """Fill the axes ``grammar`` names from ``values``; a flag's value is kept."""
    for name, value in zip(grammar, values):
        text = str(value or "").strip()
        if not text or name not in _AXES:
            continue
        axis = name
        if name == AXIS_DOMAIN_OR_ALL:
            if text.lower() == "all":
                continue
            axis = AXIS_DOMAIN
        elif name == AXIS_HOST_OR_DOMAIN:
            axis = AXIS_HOST if looks_like_address(text) else AXIS_DOMAIN
        bound.setdefault(axis, text)


def bind_command_targets(arg_string: str, targets: VerbTargets) -> BoundTargets:
    """The host, domain and account ``arg_string`` names for a verb.

    Mirrors ``repl_args.parse_command_args``: an argument string with exactly a
    grammar's token count is the legacy positional form and binds one to one
    (so a password that starts with ``-`` is never read as a flag); otherwise
    the flags are read and what is left binds the grammar by position. A value
    a flag gave is never replaced by a positional. A secret's flag value and a
    grammar's own secret position are never bound to an axis.
    """
    takes_domain = AXIS_DOMAIN in targets.flag_axes() and any(
        name in (AXIS_DOMAIN, AXIS_DOMAIN_OR_ALL, AXIS_HOST_OR_DOMAIN)
        for grammar in targets.grammars
        for name in grammar
    )
    tokens = _tokens(arg_string)
    bound: dict[str, str] = {}

    for grammar in targets.grammars:
        if len(tokens) != len(grammar) or not _literals_match(grammar, tokens):
            continue
        if any(
            token.startswith("-")
            for name, token in zip(grammar, tokens)
            if name in _AXES or name.startswith("=")
        ):
            continue
        _bind(grammar, tokens, bound)
        return BoundTargets(
            host=bound.get(AXIS_HOST, ""),
            domain=bound.get(AXIS_DOMAIN, ""),
            account=bound.get(AXIS_ACCOUNT, ""),
            takes_domain=takes_domain,
        )

    axes = targets.flag_axes()
    flag_axis = {
        **{flag: AXIS_HOST for flag in HOST_FLAGS if AXIS_HOST in axes},
        **{flag: AXIS_DOMAIN for flag in DOMAIN_FLAGS if AXIS_DOMAIN in axes},
        **{flag: AXIS_ACCOUNT for flag in ACCOUNT_FLAGS if AXIS_ACCOUNT in axes},
    }
    positionals: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        name, sep, inline = token.partition("=")
        if name in flag_axis:
            value = inline if sep else (tokens[index + 1] if index + 1 < len(tokens) else "")
            index += 1 if sep else 2
            bound.setdefault(flag_axis[name], value.strip())
            continue
        if token.startswith("-"):
            # A value flag takes the next token with it; any other flag is a switch.
            # A target flag this verb does not read (``attack_paths --target
            # <label>``) still takes its value, which is not a positional.
            takes_value = name in _VALUE_FLAGS or name in _TARGET_FLAGS
            index += 2 if (not sep and takes_value) else 1
            continue
        positionals.append(token)
        index += 1

    grammar = _pick_grammar(targets.grammars, positionals)
    if grammar is not None:
        _bind(grammar, positionals, bound)
    return BoundTargets(
        host=bound.get(AXIS_HOST, ""),
        domain=bound.get(AXIS_DOMAIN, ""),
        account=bound.get(AXIS_ACCOUNT, ""),
        takes_domain=takes_domain,
    )
