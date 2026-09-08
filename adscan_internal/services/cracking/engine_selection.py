"""Capability-driven engine selection + the shared effort-ladder walker.

This is the keystone that unifies the two cracking executor backends behind ONE
selector. :func:`select_crack_engine` picks the right
:class:`~adscan_internal.services.cracking.crack_engine.CrackEngine` for the host
— :class:`~adscan_internal.services.cracking.hashcat_engine.HashcatEngine` when a
usable GPU device is present, else
:class:`~adscan_internal.services.cracking.john_engine.JohnEngine` on CPU, else
``None`` (honest degrade). :func:`run_effort_ladder` then walks the already-shipped
effort-tier ladder (``cracking_wordlist_policy.resolve_effort``) through whichever
engine was selected, stopping at the first tier that recovers a credential.

It introduces NO new command construction and NO new offensive logic: both engines
delegate to the existing runners, and the tier ladder is the existing SSOT. This
module is pure dispatch/plumbing — the seam that lets John run the SAME ladder
hashcat runs, instead of a single flat wordlist.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable

from adscan_core.pal import tools as pal_tools
from adscan_internal.services.cracking.crack_engine import CrackResult
from adscan_internal.services.cracking.hashcat_engine import HashcatEngine
from adscan_internal.services.cracking.john_engine import JohnEngine
from adscan_internal.services.john_artifact_cracking_service import (
    JohnArtifactCrackingService,
)

if TYPE_CHECKING:
    from adscan_internal.services.cracking.crack_engine import CrackEngine
    from adscan_internal.services.cracking_wordlist_policy import EffortTier


def _hashcat_device_present(shell: Any) -> bool:
    """Return whether hashcat can see a usable compute device on this host.

    Reuses the SSOT interactive backend selector
    (``cli.cracking._select_hashcat_backend``) so this path and the interactive
    one agree on "hashcat can run here". A device is present when the selector
    reports the backend available (GPU or CPU-OpenCL). Best-effort: any probe
    failure resolves to ``False`` (assume no device) so selection degrades to
    John rather than dispatching hashcat with nothing to run on.

    Args:
        shell: The pentest shell (or a shell-shaped object) the selector probes.

    Returns:
        ``True`` when hashcat exposes a usable device; ``False`` otherwise.
    """
    try:
        from adscan_internal.cli.cracking import (  # noqa: PLC0415
            _select_hashcat_backend,
        )

        return bool(_select_hashcat_backend(shell).is_available)
    except Exception:  # noqa: BLE001 -- probe is best-effort; degrade to no-device
        return False


def select_crack_engine(
    shell: Any, command_executor: Callable[..., object]
) -> CrackEngine | None:
    """Select the cracking backend for this host, or ``None`` when none can run.

    Selection order:

    1. :class:`HashcatEngine` when the ``cracking_gpu`` capability is available
       AND the hashcat device probe is positive (a usable GPU/compute device).
    2. :class:`JohnEngine` when the ``cracking_cpu`` capability is available AND a
       John binary path resolves.
    3. ``None`` — honest degrade; the caller renders today's no-cracker path.

    Args:
        shell: The pentest shell (or shell-shaped object), used for the hashcat
            device probe.
        command_executor: A callable with ``shell.run_command``'s signature,
            injected into whichever engine is selected.

    Returns:
        The selected :class:`CrackEngine`, or ``None`` when no backend can run.
    """
    if pal_tools.capability_available(
        "cracking_gpu"
    ).available and _hashcat_device_present(shell):
        return HashcatEngine(command_executor)

    if pal_tools.capability_available("cracking_cpu").available:
        john_path = JohnArtifactCrackingService.resolve_john_path()
        if john_path:
            return JohnEngine(command_executor=command_executor, john_path=john_path)

    return None


def run_effort_ladder(
    engine: CrackEngine,
    tiers: "list[EffortTier]",
    hash_file: str,
    hash_kind: str,
) -> CrackResult:
    """Walk ``tiers`` in order through ``engine``, stopping at the first recovery.

    Runs each tier sequentially (never in parallel — one crack in flight) and
    returns the first :class:`CrackResult` whose ``recovered`` mapping is
    non-empty. When no tier recovers, returns the LAST result; when ``tiers`` is
    empty, returns an empty :class:`CrackResult`.

    Args:
        engine: The selected cracking backend.
        tiers: The effort-tier ladder (from ``resolve_effort``), tried in order.
        hash_file: Path to the file of hashes to attack.
        hash_kind: Neutral hash identifier (a ``HashKind`` value); each engine
            maps it to its own mode/format internally.

    Returns:
        The first recovering :class:`CrackResult`, else the last one run, else an
        empty result when ``tiers`` is empty.
    """
    last: CrackResult | None = None
    for tier in tiers:
        last = engine.run(tier, hash_file, hash_kind=hash_kind)
        if last.recovered:
            return last
    if last is not None:
        return last
    return CrackResult(
        recovered={}, engine=getattr(engine, "name", ""), ruleset=None, tier_name=""
    )
