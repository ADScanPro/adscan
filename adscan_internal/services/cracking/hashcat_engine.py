"""hashcat backend for the cracker-agnostic effort engine.

:class:`HashcatEngine` is a thin adapter that puts the already-shipped hashcat
tier runner (:func:`adscan_internal.services.background_jobs.cracking_job._run_hashcat_tier_impl`)
behind the :class:`~adscan_internal.services.cracking.crack_engine.CrackEngine`
protocol so the effort engine can pick between hashcat (GPU/Linux) and John
(CPU/Windows) polymorphically.

It introduces NO new command construction: ``run`` delegates to the existing
runner, which owns the exact ``hashcat -m <mode> --username --show ...`` argv,
so the command hashcat receives for a given tier stays byte-identical to today.
The engine only translates the neutral :class:`~adscan_internal.services.cracking.hash_kind.HashKind`
into a hashcat mode, forwards the tier's wordlist and rule file, and adapts the
runner's ``{username: password}`` output into a :class:`CrackResult`.
"""

from __future__ import annotations

import os
from types import SimpleNamespace
from typing import TYPE_CHECKING, Callable

from adscan_internal.services.cracking.crack_engine import CrackResult
from adscan_internal.services.cracking.hash_kind import HashKind, hashcat_mode_for

if TYPE_CHECKING:
    from adscan_internal.services.cracking_wordlist_policy import EffortTier


class HashcatEngine:
    """Run an effort tier through the existing hashcat tier runner.

    Implements the :class:`~adscan_internal.services.cracking.crack_engine.CrackEngine`
    protocol. The runner it delegates to reads its executor from a shell-shaped
    object's ``run_command`` attribute, so the injected ``command_executor`` is
    wrapped into exactly that shape — letting tests inject a fake without a real
    shell.
    """

    name = "hashcat"

    def __init__(self, command_executor: Callable[..., object]) -> None:
        """Store the command executor the delegated runner will use.

        Args:
            command_executor: A callable with the same signature as
                ``shell.run_command`` — invoked to launch hashcat and its
                ``--show`` potfile read. Injectable for tests.
        """
        self._command_executor = command_executor

    def run(self, tier: EffortTier, hash_file: str, *, hash_kind: str) -> CrackResult:
        """Run ``tier`` against ``hash_file`` via the existing hashcat runner.

        Args:
            tier: The effort tier (base wordlist x optional rules) to run.
            hash_file: Path to the file of hashes to attack.
            hash_kind: Neutral hash identifier (a :class:`HashKind` value, e.g.
                ``"asrep"``); mapped to a hashcat ``-m`` mode internally.

        Returns:
            A :class:`CrackResult` carrying every recovered ``username ->
            password`` pair, the ``"hashcat"`` engine name, the rule set applied
            (the rule file's basename, or ``None`` when the tier ran ruleless),
            and the tier name.
        """
        # Import lazily to avoid a services -> background_jobs import at module
        # load and to keep the delegated command construction the single SSOT.
        from adscan_internal.services.background_jobs.cracking_job import (  # noqa: PLC0415
            _run_hashcat_tier_impl,
        )

        mode = hashcat_mode_for(HashKind(hash_kind))
        shell = SimpleNamespace(run_command=self._command_executor)
        recovered = _run_hashcat_tier_impl(
            shell,
            hash_file,
            tier.base_path,
            mode,
            rules_path=tier.rule_path,
        )
        ruleset = os.path.basename(tier.rule_path) if tier.rule_path else None
        return CrackResult(
            recovered=dict(recovered or {}),
            engine=self.name,
            ruleset=ruleset,
            tier_name=tier.name,
        )
