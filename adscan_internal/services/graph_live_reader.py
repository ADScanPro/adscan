"""Engine side of ``adscan_core.graph_file_reader``: bring a domain's export up to date.

A reader that holds a workspace path asks :func:`ensure_export_fresh_for_domain_dir`
whether an engine session in this process owns that domain's store; if one does,
its ``attack_graph.json`` is exported now (a no-op when current). The reader then
parses the file, so what a deliverable reads inside the scan is the same document
it reads in a later process: the live graph is deliberately NOT handed out, since it
carries session enrichments the export does not.
"""

from __future__ import annotations

import os

from adscan_core import telemetry
from adscan_core.rich_output import print_exception, print_info_debug


def _key(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def ensure_export_fresh_for_domain_dir(domain_dir: str) -> bool:
    """Export the domain at ``domain_dir`` from the session that owns it.

    Returns whether a live session owned that directory. A session that raises is
    reported, not skipped silently. When no session owns the directory but one
    holds the same domain under a DIFFERENT directory (the execution ``.run_*``
    workspace against the logical one), the reader falls back to the file as it
    stands; that is logged at debug and counted in telemetry.
    """
    from adscan_internal.services import graph_runtime  # noqa: PLC0415

    wanted = _key(domain_dir)
    domain = os.path.basename(os.path.normpath(domain_dir))
    if not domain:
        return False
    elsewhere: list[str] = []
    for shell in graph_runtime.live_sessions():
        try:
            held = _key(graph_runtime.domain_dir_for(shell, domain))
            if graph_runtime.graph_store_for(shell, domain, create=False) is None:
                continue
            if held != wanted:
                elsewhere.append(held)
                continue
            graph_runtime.ensure_export_fresh(shell, domain)
            return True
        except Exception as exc:  # noqa: BLE001 - reported below, the next session may own it
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
    if elsewhere:
        print_info_debug(
            "graph reader read the export of a domain a live session holds under another "
            "directory (execution workspace against the logical one); it may be behind"
        )
        telemetry.capture(
            "graph_reader_workspace_mismatch", {"live_sessions_elsewhere": len(elsewhere)}
        )
    return False


__all__ = ("ensure_export_fresh_for_domain_dir",)
