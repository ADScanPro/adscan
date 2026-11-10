"""Where the per-domain targeted cracking wordlist lives (path only).

The wordlist itself is built by the engine
(``adscan_internal.services.custom_wordlist_service``) from the domain's user and
computer names, so it is client data and must go when the last workspace
holding that domain is deleted. The PATH is needed on both sides: the engine
writes it, and the workspace delete removes it from the CLI, from the platform
and from its worker, which cannot import the engine. So the layout lives here,
stdlib only, and the engine re-exports it.
"""

from __future__ import annotations

import re
from pathlib import Path


def custom_wordlist_dir(domain: str, *, base_dir: Path | None = None) -> Path:
    """Resolve the per-domain custom wordlist asset directory.

    Host ``~/.adscan/wordlists/custom/<domain>/`` <-> container
    ``/opt/adscan/wordlists/custom/<domain>/`` (both resolve via the paths
    helper, so no path is hardcoded).

    Args:
        domain: Target domain.
        base_dir: The ADscan home to resolve under. Defaults to the home of this
            process (``get_adscan_home_dir``); a caller whose home is laid out
            differently (the platform worker reads the workspaces root from its
            own configuration) passes the parent of that root.

    Returns:
        The resolved directory Path (not yet created).
    """
    if base_dir is None:
        from adscan_core.paths import get_adscan_home_dir  # noqa: PLC0415

        base_dir = get_adscan_home_dir()
    safe_domain = re.sub(r"[^A-Za-z0-9._-]", "_", str(domain or "unknown"))
    # Collapse any ``..`` run so the domain can never form a path-traversal
    # component, and trim leading/trailing dots.
    safe_domain = re.sub(r"\.{2,}", "_", safe_domain).strip(".") or "unknown"
    return Path(base_dir) / "wordlists" / "custom" / safe_domain


__all__ = ("custom_wordlist_dir",)
