"""Workspace migration helpers — BH/ → graph/, attack_graph.json backup."""

from __future__ import annotations

import os
import shutil
from typing import Any

from adscan_core.rich_output import print_info_debug, print_info_verbose
from adscan_internal import telemetry
from adscan_internal.rich_output import mark_sensitive
from adscan_core.rich_output import print_exception


def migrate_bh_directory_to_graph(
    workspace_cwd: str,
    *,
    domain: str,
    domains_dir: str = "domains",
) -> dict[str, Any]:
    """Rename ``BH/`` to ``graph/`` for one domain. Idempotent.

    - ``BH/`` exists, ``graph/`` doesn't → rename BH → graph; ZIPs end up under
      ``graph/legacy/``.
    - ``BH/`` and ``graph/`` both exist → move BH/* into ``graph/legacy/``, then
      rmdir BH.
    - ``BH/`` missing → no-op.

    Returns:
        dict with ``renamed`` bool and one of:
        ``already_migrated``, ``nothing_to_do``, ``error``.
    """
    domain_dir = os.path.join(workspace_cwd, domains_dir, domain)
    bh_dir = os.path.join(domain_dir, "BH")
    graph_dir = os.path.join(domain_dir, "graph")

    bh_exists = os.path.isdir(bh_dir)
    graph_exists = os.path.isdir(graph_dir)
    marked_domain = mark_sensitive(domain, "domain")

    if not bh_exists and graph_exists:
        return {"renamed": False, "already_migrated": True}

    if not bh_exists and not graph_exists:
        return {"renamed": False, "nothing_to_do": True}

    try:
        if bh_exists and not graph_exists:
            # Simple rename — create legacy/ so ZIPs land there
            legacy_dir = os.path.join(graph_dir, "legacy")
            os.rename(bh_dir, graph_dir)
            # Move any ZIPs / blobs into legacy/
            os.makedirs(legacy_dir, exist_ok=True)
            for entry in list(os.listdir(graph_dir)):
                if entry == "legacy":
                    continue
                src = os.path.join(graph_dir, entry)
                dst = os.path.join(legacy_dir, entry)
                if not os.path.exists(dst):
                    shutil.move(src, dst)
            print_info_verbose(f"[migration] renamed BH/ to graph/ for {marked_domain}")
            return {"renamed": True, "rename_only": True}

        # Both exist: move BH artifacts under graph/legacy/
        legacy_dir = os.path.join(graph_dir, "legacy")
        os.makedirs(legacy_dir, exist_ok=True)
        for entry in os.listdir(bh_dir):
            src = os.path.join(bh_dir, entry)
            dst = os.path.join(legacy_dir, entry)
            if os.path.exists(dst):
                continue  # don't overwrite existing legacy artifacts
            shutil.move(src, dst)
        # rmdir BH only if now empty
        try:
            os.rmdir(bh_dir)
        except OSError:
            pass  # something left, leave it for manual inspection
        print_info_verbose(
            f"[migration] moved BH/ artifacts to graph/legacy/ for {marked_domain}"
        )
        return {"renamed": True, "moved_to_legacy": True}
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"[migration] failed for {marked_domain}: {exc}")
        return {"renamed": False, "error": f"{type(exc).__name__}: {exc}"}


def backup_pre_migration_attack_graph(
    workspace_cwd: str,
    *,
    domain: str,
    domains_dir: str = "domains",
) -> dict[str, Any]:
    """Back up ``attack_graph.json`` as ``attack_graph.json.pre_migration`` once.

    Idempotent — does not overwrite an existing backup. Skips when the source
    file does not exist.
    """
    domain_dir = os.path.join(workspace_cwd, domains_dir, domain)
    src = os.path.join(domain_dir, "attack_graph.json")
    dst = os.path.join(domain_dir, "attack_graph.json.pre_migration")

    if not os.path.exists(src):
        return {"backed_up": False, "nothing_to_back_up": True}
    if os.path.exists(dst):
        return {"backed_up": False, "already_backed_up": True}

    try:
        shutil.copy2(src, dst)
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            f"[migration] backed up pre-migration attack_graph for {marked_domain}"
        )
        return {"backed_up": True}
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return {"backed_up": False, "error": f"{type(exc).__name__}: {exc}"}


def run_workspace_migrations(
    workspace_cwd: str,
    *,
    domain: str,
    domains_dir: str = "domains",
) -> dict[str, Any]:
    """Run all workspace migrations for one domain. Idempotent."""
    bh_result = migrate_bh_directory_to_graph(
        workspace_cwd, domain=domain, domains_dir=domains_dir
    )
    backup_result = backup_pre_migration_attack_graph(
        workspace_cwd, domain=domain, domains_dir=domains_dir
    )
    return {
        "bh_to_graph": bh_result,
        "pre_migration_backup": backup_result,
    }
