"""Argument parser for the ``attack_paths`` command (SSOT).

``PentestShell.do_attack_paths`` and the ``execute`` credential gate both need
to read the same token list, so the parsing lives here once. Before this module
the two were hand-mirrored and drifted: the shell parser folded any flag it did
not recognise into the start-principal list, so ``--terminal-relations
forcechangepassword`` became two extra "principals" (``--terminal-relations``
and ``forcechangepassword``), the filter never applied, and an unattended
``adscan execute attack_paths`` ran every path of the start user instead of the
one the operator asked for.

The parser is pure (no shell, no I/O) so it is covered by L1 tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field

#: Flags that take a value (``--flag VALUE`` or ``--flag=VALUE``).
VALUE_FLAGS: frozenset[str] = frozenset(
    {"--max", "--depth", "--path-steps", "--target", "--terminal-relations"}
)

#: Boolean flags, with their aliases.
_ALL_FLAGS = frozenset({"--all"})
_LOWPRIV_FLAGS = frozenset({"--lowpriv", "--low-priv", "--non-highvalue"})
_TIER0_FLAGS = frozenset({"--tier0-only", "--tierzero-only", "--tier0"})
_NOOP_FLAGS = frozenset({"--impact", "--highvalue", "--keep-longest", "--keep_longest"})
_KEEP_SHORTEST_FLAGS = frozenset({"--keep-shortest", "--keep_shortest"})
_NO_CACHE_FLAGS = frozenset({"--no-cache"})

BOOLEAN_FLAGS: frozenset[str] = (
    _ALL_FLAGS
    | _LOWPRIV_FLAGS
    | _TIER0_FLAGS
    | _NOOP_FLAGS
    | _KEEP_SHORTEST_FLAGS
    | _NO_CACHE_FLAGS
)

USAGE = (
    "Usage: attack_paths <domain> [user|owned|user1 user2 ...] [index] [--max N] [--depth N] "
    "[--path-steps N] [--tier0-only] [--all] [--lowpriv] [--no-cache] [--keep-shortest] "
    "[--target LABEL] [--terminal-relations REL1,REL2]"
)


@dataclass(slots=True)
class AttackPathsArgs:
    """The parsed ``attack_paths`` invocation.

    ``errors`` is non-empty when the invocation must be refused (an unknown
    flag, a value flag with no value). The caller prints them and stops; it
    never runs on a partially understood command line.
    """

    domain: str = ""
    start_users: list[str] = field(default_factory=list)
    index: int | None = None
    max_display: int | None = None
    max_depth: int | None = None
    max_path_steps: int | None = None
    include_all: bool = False
    lowpriv: bool = False
    target_mode: str = "object"
    no_cache: bool = False
    keep_longest: bool = True
    target: str | None = None
    terminal_relations: tuple[str, ...] = ()
    errors: list[str] = field(default_factory=list)

    @property
    def owned_scope(self) -> bool:
        """Whether the special ``owned`` scope was requested."""
        return any(user.strip().lower() == "owned" for user in self.start_users)

    @property
    def explicit_users(self) -> list[str]:
        """The named start principals, without the ``owned`` keyword."""
        return [user for user in self.start_users if user.strip().lower() != "owned"]

    @property
    def attack_target(self) -> str:
        """The target class to compute over.

        A named ``--target`` or a ``--terminal-relations`` filter is a narrowing
        over the full target universe, so either implies ``all`` unless the
        operator asked for ``--lowpriv``: a ForceChangePassword onto an ordinary
        user is not a high-value terminal, and computing over high-value targets
        first would leave the filter nothing to keep.
        """
        if self.lowpriv:
            return "lowpriv"
        if self.include_all or self.target or self.terminal_relations:
            return "all"
        return "highvalue"


def _parse_int(raw: str) -> int | None:
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _split_relations(raw: str) -> tuple[str, ...]:
    seen: list[str] = []
    for chunk in str(raw or "").split(","):
        relation = chunk.strip().lower()
        if relation and relation not in seen:
            seen.append(relation)
    return tuple(seen)


def parse_attack_paths_args(parts: list[str]) -> AttackPathsArgs:
    """Parse the ``attack_paths`` token list.

    The first token is the domain. After it: ``owned``, one or more start
    principals, and an optional trailing integer path index. Any token that
    starts with ``--`` must be a known flag; an unknown one is an error and is
    never read as a principal.

    Args:
        parts: The shell-split argument tokens, domain first.

    Returns:
        The parsed arguments. ``errors`` lists why the invocation is refused.
    """
    parsed = AttackPathsArgs()
    if not parts:
        return parsed
    parsed.domain = parts[0]

    positionals: list[str] = []
    tokens = list(parts[1:])
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if not token.startswith("--"):
            positionals.append(token)
            i += 1
            continue

        name, has_inline, inline_value = token.partition("=")
        if name in VALUE_FLAGS:
            if has_inline:
                value = inline_value
                i += 1
            elif i + 1 < len(tokens):
                value = tokens[i + 1]
                i += 2
            else:
                parsed.errors.append(f"{name} needs a value.")
                i += 1
                continue
            # A non-numeric --max / --depth keeps the default (historical behaviour).
            if name == "--max":
                number = _parse_int(value)
                if number is not None:
                    parsed.max_display = number
            elif name == "--depth":
                number = _parse_int(value)
                if number is not None:
                    parsed.max_depth = number
            elif name == "--path-steps":
                parsed.max_path_steps = _parse_int(value)
            elif name == "--target":
                parsed.target = value
            elif name == "--terminal-relations":
                relations = _split_relations(value)
                if not relations:
                    parsed.errors.append("--terminal-relations needs at least one relation.")
                parsed.terminal_relations = tuple(
                    dict.fromkeys((*parsed.terminal_relations, *relations))
                )
            continue

        if has_inline or name not in BOOLEAN_FLAGS:
            parsed.errors.append(f"Unknown option: {token}")
            i += 1
            continue
        if name in _ALL_FLAGS:
            parsed.include_all = True
        elif name in _LOWPRIV_FLAGS:
            parsed.include_all = False
            parsed.lowpriv = True
        elif name in _TIER0_FLAGS:
            parsed.target_mode = "tier0"
        elif name in _NO_CACHE_FLAGS:
            parsed.no_cache = True
        elif name in _KEEP_SHORTEST_FLAGS:
            parsed.keep_longest = False
        # _NOOP_FLAGS: accepted for backwards compatibility, change nothing.
        i += 1

    remaining = positionals
    if remaining and remaining[-1].isdigit():
        parsed.index = int(remaining[-1])
        remaining = remaining[:-1]
    for token in remaining:
        if token.isdigit():
            parsed.index = int(token)  # legacy: a second numeric token is the index
        else:
            parsed.start_users.append(token)
    return parsed
