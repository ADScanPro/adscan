"""Shared REPL argument-parsing primitive: legacy positional OR flag form.

Every credential-bearing REPL command (``dcsync``, ``get_flags``, ``dump_lsa``,
``creds save``, ``start_auth``, ...) historically parsed its argument string
with a naive ``args.split()`` and an exact positional-count check. Marking the
secret positional for telemetry sanitization required a hand-maintained
positional-index map (``adscan_internal.cli.common._SECRET_POSITIONAL_INDICES``)
that silently drifted out of sync every time a new command was added — the
root cause of a real credential-leak fix (see ``common.py`` module docstring
around ``redact_command_for_log``).

This module lets a command accept the SAME positional shape it always has
(so every existing script/runbook keeps working, byte-for-byte, forever) while
ALSO accepting an order-independent flag form (``-d <domain> -u <user> -p
<password>``). Once a command speaks flags, its secret is marked by FLAG NAME
(``-p/--password``, ``--hash`` — both already recognized command-agnostically
by ``adscan_internal.cli.common._SECRET_FLAG_NAMES``), which cannot silently
drift the way a positional-index map can: the flag name IS the sanitization
key, defined once, at the call site that introduces the secret.

Design constraints (see ``docs/superpowers/plans/2026-07-21-repl-flag-argument-grammar.md``
for the full investigation):

- ``PentestShell.run()``'s dispatch loop only catches ``Exception``, not
  ``BaseException``/``SystemExit`` — a parser that calls ``sys.exit`` on a bad
  flag kills the entire interactive session. ``ReplArgumentParser`` overrides
  ``error()`` to raise :class:`ReplArgumentError` instead.
- Every parser built for this system MUST be constructed with
  ``add_help=False``. The REPL's ``normalize_help_alias`` (this package,
  ``common.py``) already intercepts ``<cmd> help``/``<cmd> -h``/``<cmd>
  --help`` as the first token and redirects to ``do_help(<cmd>)`` (which
  prints the ``do_<cmd>`` docstring). A parallel argparse ``--help`` would
  collide with ``-h`` already reserved for ``--hash`` on some commands and
  would bypass the mandatory ``_TeeConsole`` telemetry mirror.
- The legacy-first dispatch rule (below) means a value that happens to start
  with ``-`` (a strong password) is NEVER misread as a flag as long as the
  operator keeps the current, exact positional argument count.
"""

from __future__ import annotations

import argparse
import shlex
from typing import Sequence

from adscan_internal.rich_output import print_error


class ReplArgumentError(Exception):
    """Raised by :class:`ReplArgumentParser` instead of ``SystemExit``.

    A REPL command's argument parser must never end the process — this is
    the exception :func:`parse_command_args` catches to turn a parse failure
    into a normal "print an error, return None" outcome.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class ReplArgumentParser(argparse.ArgumentParser):
    """``argparse.ArgumentParser`` that raises instead of calling ``sys.exit``.

    Always construct with ``add_help=False`` (see module docstring). Every
    argparse failure path (missing required argument, invalid choice,
    unrecognized argument, bad type conversion) funnels through
    ``ArgumentParser.error()`` — overriding it here is sufficient to make
    the whole parser REPL-safe with no other changes.
    """

    def error(self, message: str) -> None:  # noqa: D401 - argparse override signature
        raise ReplArgumentError(message)


def parse_command_args(
    *,
    tokens_source: str,
    legacy_field_order: Sequence[str],
    parser: argparse.ArgumentParser,
    usage: str,
) -> argparse.Namespace | None:
    """Parse a REPL command's argument string, legacy-positional-first.

    Args:
        tokens_source: The raw argument string as received by ``do_<verb>``
            (everything after the command name).
        legacy_field_order: Field names, in the exact order the command's
            CURRENT (pre-migration) positional grammar expects them. When
            ``tokens_source`` tokenizes to exactly this many tokens, they are
            bound 1:1 to these names UNCONDITIONALLY — this is the backward-
            compat branch and never touches ``parser`` at all, so a value
            starting with ``-`` (a strong password) is never misread as a
            flag as long as the caller keeps the legacy argument count.
        parser: A :class:`ReplArgumentParser` (``add_help=False``) declaring
            the flag grammar. Only reached when the token count does not
            match ``legacy_field_order``.
        usage: One-line usage string shown on a tokenize/parse failure.

    Returns:
        The parsed ``argparse.Namespace`` (for both the legacy and flag
        branches — the legacy branch synthesizes one so callers have a single
        code path regardless of which form the operator used), or ``None``
        after printing an error when parsing failed for any reason. Never
        raises.
    """
    try:
        tokens = shlex.split(tokens_source or "")
    except ValueError:
        print_error(f"Mismatched quotes. Usage: {usage}")
        return None

    if len(tokens) == len(legacy_field_order):
        namespace = argparse.Namespace()
        for field_name, value in zip(legacy_field_order, tokens):
            setattr(namespace, field_name, value)
        return namespace

    try:
        return parser.parse_args(tokens)
    except ReplArgumentError as exc:
        print_error(f"{exc.message}\nUsage: {usage}")
        return None
