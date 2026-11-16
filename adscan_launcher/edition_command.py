"""``adscan config edition`` and the licence half of ``adscan install --license``.

Host-side launcher commands. The edition decision itself lives in
:mod:`adscan_launcher.edition`; this module only exposes it to the operator.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

from adscan_core.rich_output import print_error, print_info, print_success, print_warning


def add_config_subparser(sub: Any) -> None:
    """Register ``adscan config edition [lite|auto]``."""
    cfg = sub.add_parser(
        "config",
        help="Launcher preferences (which edition runs).",
        description=(
            "Launcher preferences. `adscan config edition` shows which edition runs and why; "
            "`adscan config edition lite` always runs ADscan LITE on this machine; "
            "`adscan config edition auto` lets the PRO licence decide again."
        ),
    )
    csub = cfg.add_subparsers(dest="config_command", metavar="setting", required=True)
    ed = csub.add_parser("edition", help="Show or set which edition runs (lite, or auto from the licence).")
    ed.add_argument("value", nargs="?", choices=["lite", "auto"], help="lite or auto. Omit to show.")


_SOURCE_LINES = {
    "image_override": "image chosen with --image or ADSCAN_DOCKER_IMAGE",
    "lite_flag": "--lite was given",
    "config": "set with `adscan config edition lite`",
    "licence": "active PRO licence",
    "licence_inactive": "the PRO licence does not allow new assessments",
    "no_licence": "no PRO licence on this machine",
}


def describe_edition() -> str:
    """One line: the edition this machine runs and why (also used by ``--version``)."""
    from adscan_launcher.edition import resolve_edition

    decision = resolve_edition()
    label = "ADscan PRO" if decision.is_pro else "ADscan LITE"
    return f"This machine runs {label} ({_SOURCE_LINES.get(decision.source, decision.source)})."


def run_config_command(ns: argparse.Namespace) -> int:
    """Dispatch ``adscan config``; return the exit code."""
    from adscan_launcher.edition import announce_fallback_once, resolve_edition, set_persisted_edition

    if str(getattr(ns, "config_command", "")) != "edition":
        print_error("Unknown setting. Use: adscan config edition [lite|auto].")
        return 2
    value = getattr(ns, "value", None)
    if value:
        set_persisted_edition(value)
        print_success(
            "This machine now always runs ADscan LITE."
            if value == "lite"
            else "The PRO licence decides the edition again."
        )
    decision = resolve_edition()
    announce_fallback_once(decision)
    print_info(describe_edition())
    return 0


def _read_install_key(ns: argparse.Namespace) -> tuple[str | None, bool]:
    """``(key, given)``: given is False when no licence source was named at all."""
    from adscan_launcher.license_command import ACTIVATION_KEY_ENV, _KEY_ON_ARGV_WARNING

    if getattr(ns, "license_file", None):
        try:
            return Path(ns.license_file).read_text(encoding="utf-8").strip(), True
        except OSError as exc:
            print_error(f"The licence file cannot be read: {exc.strerror or exc}.")
            return None, True
    if getattr(ns, "license_stdin", False):
        return sys.stdin.readline().strip(), True
    if getattr(ns, "license", None):
        print_warning(_KEY_ON_ARGV_WARNING)
        return str(ns.license).strip(), True
    env = os.getenv(ACTIVATION_KEY_ENV, "").strip()
    if env:
        return env, True
    return None, False


def activate_for_install(ns: argparse.Namespace) -> int:
    """Activate before ``install`` when a licence source was given; 0 when there is nothing to do."""
    key, given = _read_install_key(ns)
    if not given:
        return 0
    if not key:
        print_error("No activation key was read. Check the file or the value you passed.")
        return 1
    from adscan_launcher.license_command import activate_with_key

    rc = activate_with_key(key, seat_label=getattr(ns, "seat_label", None))
    if rc != 0:
        return rc
    from adscan_launcher.edition import clear_cache, resolve_edition

    clear_cache()
    decision = resolve_edition()
    if decision.is_pro:
        print_info("Installing ADscan PRO.")
    else:
        print_info(describe_edition())
    return 0


def load_image_archive(ns: argparse.Namespace) -> bool | None:
    """``install --image-archive``: verify the signed sidecar and checksum, then ``docker load``.

    Returns None when no archive was given, True when the PRO image is loaded
    and tagged as the registry image (so the edition finds it locally), False
    on any refusal (nothing is loaded).
    """
    archive = getattr(ns, "image_archive", None)
    if not archive:
        return None
    import subprocess

    from adscan_core.enterprise_license import LicenseError
    from adscan_core.pro_license.image_export import read_sidecar_for, verify_archive, verify_export_sidecar
    from adscan_launcher.docker_runtime import docker_needs_sudo, run_docker
    from adscan_launcher.edition import PRO_IMAGE, PRO_REGISTRY_HOST, PRO_REPOSITORY

    path = Path(archive)
    try:
        sidecar = getattr(ns, "image_sidecar", None)
        payload = verify_export_sidecar(read_sidecar_for(path, Path(sidecar) if sidecar else None))
        verify_archive(path, payload)
    except (OSError, LicenseError) as exc:
        print_error(f"The image archive was not loaded: {exc}")
        return False
    print_info(f"Loading ADscan PRO {payload['version']} from the verified archive.")
    import zstandard

    cmd = ["docker", "load"]
    if docker_needs_sudo() and os.geteuid() != 0:
        cmd = ["sudo", "--preserve-env=HOME"] + cmd
    with path.open("rb") as raw, subprocess.Popen(cmd, stdin=subprocess.PIPE) as proc:  # noqa: S603 - fixed argv
        assert proc.stdin is not None
        zstandard.ZstdDecompressor().copy_stream(raw, proc.stdin)
        proc.stdin.close()
        rc = proc.wait()
    if rc != 0:
        print_error("docker load failed; nothing was installed.")
        return False
    for target in (PRO_IMAGE, f"{PRO_REGISTRY_HOST}/{PRO_REPOSITORY}:{payload['version']}"):
        run_docker(["docker", "tag", str(payload["source_ref"]), target], check=True, capture_output=True)
    print_success(f"ADscan PRO {payload['version']} is loaded and verified.")
    return True


__all__ = [
    "activate_for_install",
    "add_config_subparser",
    "describe_edition",
    "load_image_archive",
    "run_config_command",
]
