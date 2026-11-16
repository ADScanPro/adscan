"""After a successful activation: offer the ADscan PRO download right away.

Founder decision, 2026-11-12. ``adscan license activate`` (and ``adscan install
--license``) end with the image the licence just unlocked, instead of leaving
the user to find an ``update`` command. Interactive: one panel, a free-disk
check first, default Yes, Docker's own progress during the pull.
Non-interactive: ``--pull`` pulls without asking; otherwise it prints the one
command to run.
"""

from __future__ import annotations

import shutil

from adscan_core.rich_output import print_info, print_instruction, print_success, print_warning

#: Measured on the 14.0.0 PRO image (spec § 1): 5.17 GB compressed, 12.1 GB unpacked.
DOWNLOAD_GB = 5.2
DISK_GB = 12.0
#: Docker keeps the compressed layers while it unpacks them.
REQUIRED_FREE_GB = 18.0


def _free_gb() -> float | None:
    try:
        from adscan_launcher.docker_commands import _get_docker_storage_path

        return shutil.disk_usage(_get_docker_storage_path()).free / 1e9
    except Exception:  # noqa: BLE001 - an unreadable mount just skips the check
        return None


def _pro_image_present() -> bool:
    from adscan_launcher.docker_runtime import docker_available, image_exists
    from adscan_launcher.edition import pro_image_candidates

    if not docker_available():
        return False
    return any(image_exists(image) for image in pro_image_candidates())


def pull_pro_image(*, pull_timeout_seconds: int | None = 3600, command_name: str = "update") -> bool:
    """Pull the PRO image the licence selects (with the failure panel on error)."""
    from adscan_launcher import docker_commands as dc

    pull_timeout = dc._normalize_pull_timeout_seconds(pull_timeout_seconds)
    resolved = dc._ensure_image_pulled_with_legacy_fallback(pull_timeout=pull_timeout, stream_output=True)
    if resolved:
        print_success("ADscan PRO is ready. Start it with `adscan start`.")
        return True
    dc._print_docker_image_pull_failure_guidance(
        image=dc._get_docker_image(), pull_timeout=pull_timeout, command_name=command_name
    )
    return False


def offer_pro_download(*, pull: bool | None, pull_timeout_seconds: int | None = 3600) -> bool:
    """Offer (or do) the PRO download after activation. Returns False only on a failed pull.

    Args:
        pull: True pulls without asking (``--pull``/``--yes``), False never pulls
            (``--no-pull``), None asks when interactive and prints the command otherwise.
        pull_timeout_seconds: Docker pull ceiling.
    """
    from adscan_core.interaction import is_non_interactive
    from adscan_launcher.edition import clear_cache, resolve_edition

    clear_cache()
    decision = resolve_edition()
    if not decision.is_pro:
        if decision.source in ("lite_flag", "config"):
            print_info(
                "This machine is set to run ADscan LITE. Run `adscan config edition auto` to let the "
                "licence choose PRO."
            )
        return True
    if _pro_image_present():
        print_info("ADscan PRO is already on this machine. Start it with `adscan start`.")
        return True
    if pull is False:
        print_instruction("Download ADscan PRO when you are ready with `adscan update`.")
        return True
    free = _free_gb()
    if pull is None:
        if is_non_interactive():
            print_instruction("Download ADscan PRO with `adscan update` (or pass --pull).")
            return True
        from adscan_core.rich_output import confirm_ask, print_panel

        lines = [
            "[bold]Your PRO licence is active.[/bold]",
            "",
            f"ADscan PRO is about a {DOWNLOAD_GB:.1f} GB download and takes about {DISK_GB:.0f} GB on disk.",
        ]
        enough = free is None or free >= REQUIRED_FREE_GB
        if free is not None:
            lines.append(
                f"Free space for Docker images on this machine is {free:.0f} GB."
                + ("" if enough else f" Make at least {REQUIRED_FREE_GB:.0f} GB free first.")
            )
        print_panel("\n".join(lines), title="ADscan PRO", border_style="cyan" if enough else "yellow")
        if not confirm_ask("Download ADscan PRO now?", default=enough):
            print_instruction("Download it later with `adscan update`.")
            return True
    elif free is not None and free < REQUIRED_FREE_GB:
        print_warning(
            f"Only {free:.0f} GB is free for Docker images and ADscan PRO needs about {REQUIRED_FREE_GB:.0f} GB "
            "while it unpacks. The download may fail."
        )
    return pull_pro_image(pull_timeout_seconds=pull_timeout_seconds, command_name="update")


__all__ = ["DISK_GB", "DOWNLOAD_GB", "REQUIRED_FREE_GB", "offer_pro_download", "pull_pro_image"]
