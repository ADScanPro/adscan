"""John the Ripper rule-ladder mapping and bundled-conf resolution.

The GPU backend (hashcat) walks a 4-rung password-mutation effort ladder built
from hashcat ``.rule`` files (see ``_RULE_LADDER`` in
``cracking_wordlist_policy.py``: rung 0 = bare wordlist, 1 = best64,
2 = OneRule-10k, 3 = OneRule-full). John the Ripper cannot read hashcat
``.rule`` files; it applies named rule sections from its own config file,
selected via ``--rules=<name>``. This module maps each rung index to the
John-native rule section (defined in the bundled ``john.conf``) that
approximates the same escalating effort, and resolves the bundled conf path.

The two ladders are functionally equivalent, not byte-identical -- hashcat and
John rule dialects differ, so the John sections reproduce the rough keyspace
escalation rather than translating individual rules one-for-one.
"""

from __future__ import annotations

# Rung index -> John rule-section name, mirroring the hashcat ``_RULE_LADDER``
# rungs in cracking_wordlist_policy.py:
#   rung 0 -> None       bare wordlist, no --rules flag
#   rung 1 -> adscan_r1  compact/fast  (best64-equivalent)
#   rung 2 -> adscan_r2  medium        (stronger than r1)
#   rung 3 -> adscan_r3  strongest bundled ruleset
_JOHN_RULE_LADDER: dict[int, str] = {
    1: "adscan_r1",
    2: "adscan_r2",
    3: "adscan_r3",
}


def john_ruleset_for_rung(rung_index: int) -> str | None:
    """Map an effort-ladder rung index to its John rule-section name.

    Args:
        rung_index: The effort rung (0..3) from the shared rule ladder.

    Returns:
        The ``[List.Rules:<name>]`` section name to pass to John's
        ``--rules=<name>`` flag, or ``None`` for rung 0 (no rules) and for any
        out-of-range index (a safe default -- an unknown rung never fabricates
        a ruleset).
    """
    return _JOHN_RULE_LADDER.get(rung_index)


def john_conf_path() -> str:
    """Resolve the bundled ``john.conf`` path.

    Mirrors the resolution order of ``_resolve_rule_asset_path`` in
    ``cracking_wordlist_policy.py``: the in-repo bundled assets dir first, then
    the managed ``~/.adscan`` home dir. Both resolve the same on-disk file.

    Returns:
        The absolute path to ``john.conf``. When the bundled asset is present
        (the shipped case) that path is returned; otherwise the managed-home
        path is returned even if it does not yet exist, so a caller can report a
        concrete missing-file location.
    """
    from pathlib import Path  # noqa: PLC0415

    from adscan_core.paths import get_adscan_home  # noqa: PLC0415

    bundled = Path(__file__).resolve().parents[2] / "assets" / "cracking" / "john.conf"
    if bundled.is_file():
        return str(bundled)
    try:
        managed = get_adscan_home() / "tools" / "cracking" / "john.conf"
    except Exception:  # noqa: BLE001
        return str(bundled)
    return str(managed)
