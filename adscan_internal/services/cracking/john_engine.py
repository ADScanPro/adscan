"""John the Ripper backend for the cracker-agnostic effort engine.

:class:`JohnEngine` is a thin adapter that puts the already-shipped CPU cracking
service (:class:`~adscan_internal.services.john_artifact_cracking_service.JohnArtifactCrackingService`)
behind the :class:`~adscan_internal.services.cracking.crack_engine.CrackEngine`
protocol so the effort engine can pick between John (CPU/Windows) and hashcat
(GPU/Linux) polymorphically.

It introduces NO new command construction: ``run`` delegates to the existing
service's :meth:`crack_hashes_file`, which owns the exact John argv (converter,
``--wordlist``, ``--show`` and pinned potfile), so the command John receives for
a given tier stays byte-identical to today. The engine only translates the
neutral :class:`~adscan_internal.services.cracking.hash_kind.HashKind` into a John
``--format``, forwards the tier's wordlist, and adapts the service's
``{username: password}`` output into a :class:`CrackResult`.

Symmetric with :class:`~adscan_internal.services.cracking.hashcat_engine.HashcatEngine`.
The tier's effort rung selects a John rule section: the engine maps
``tier.rule_rung`` through :func:`john_ruleset_for_rung` and passes the resolved
ruleset name plus the bundled ``john.conf`` path down to the service, which adds
``--config``/``--rules`` to the crack command. Rung 0 (or an absent rung) stays
ruleless and reports :attr:`CrackResult.ruleset` as ``None``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable

from adscan_internal.services.cracking.crack_engine import CrackResult
from adscan_internal.services.cracking.hash_kind import HashKind, john_format_for
from adscan_internal.services.cracking.john_rules import (
    john_conf_path,
    john_ruleset_for_rung,
)
from adscan_internal.services.john_artifact_cracking_service import (
    JohnArtifactCrackingService,
)

if TYPE_CHECKING:
    from adscan_internal.services.cracking_wordlist_policy import EffortTier


class JohnEngine:
    """Run an effort tier through the existing John CPU cracking service.

    Implements the :class:`~adscan_internal.services.cracking.crack_engine.CrackEngine`
    protocol. The service it delegates to takes a ``command_executor`` and a
    ``john_path``, both injected here so tests can drive the engine without a real
    John binary or shell.
    """

    name = "john"

    def __init__(self, command_executor: Callable[..., object], john_path: str) -> None:
        """Store the executor and John path the delegated service will use.

        Args:
            command_executor: A callable with the same signature as
                ``shell.run_command`` — invoked to launch John and its ``--show``
                potfile read. Injectable for tests.
            john_path: Path to the John the Ripper binary.
        """
        self._executor = command_executor
        self._john_path = john_path

    def run(self, tier: EffortTier, hash_file: str, *, hash_kind: str) -> CrackResult:
        """Run ``tier`` against ``hash_file`` via the existing John service.

        Args:
            tier: The effort tier (base wordlist plus the rules of its
                ``rule_rung``, mapped to a John rule section) to run.
            hash_file: Path to the file of hashes to attack.
            hash_kind: Neutral hash identifier (a :class:`HashKind` value, e.g.
                ``"asrep"``); mapped to a John ``--format`` internally.

        Returns:
            A :class:`CrackResult` carrying every recovered ``username ->
            password`` pair, the ``"john"`` engine name, the ruleset name that ran
            (the rung's John rule section, e.g. ``"adscan_r1"``, or ``None`` for
            rung 0), and the tier name. When John cannot process the kind
            (:func:`john_format_for` returns ``None``, e.g. ``TIMEROAST``) the
            result is empty and John is never invoked — an honest no-op.
        """
        ruleset = (
            john_ruleset_for_rung(tier.rule_rung)
            if tier.rule_rung is not None
            else None
        )

        fmt = john_format_for(HashKind(hash_kind))
        if fmt is None:
            # John cannot process this kind (e.g. TIMEROAST). Honest no-op: return
            # an empty result without touching the binary, never crash.
            return CrackResult(
                recovered={},
                engine=self.name,
                ruleset=None,
                tier_name=tier.name,
            )

        service = JohnArtifactCrackingService(
            command_executor=self._executor,
            john_path=self._john_path,
        )
        recovered = service.crack_hashes_file(
            hash_file=hash_file,
            wordlist_path=tier.base_path,
            john_format=fmt,
            rules=ruleset,
            john_config=john_conf_path() if ruleset else None,
        )
        return CrackResult(
            recovered=dict(recovered or {}),
            engine=self.name,
            ruleset=ruleset,
            tier_name=tier.name,
        )
