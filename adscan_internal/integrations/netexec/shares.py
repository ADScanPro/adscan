"""NetExec helpers for SMB share listing and file retrieval."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import os

from adscan_internal import print_info_debug, print_warning
from adscan_internal.integrations.netexec.parsers import (
    NetexecShareEntry,
    parse_netexec_share_dir_listing,
)
from adscan_internal.rich_output import mark_sensitive


@dataclass(frozen=True)
class NetexecShareListing:
    """Result of listing a SMB share."""

    entries: list[NetexecShareEntry]
    output: str


def list_share_directory(
    shell: Any,
    *,
    domain: str,
    host: str,
    auth: str,
    share: str,
    directory: str | None = None,
    timeout: int = 300,
) -> NetexecShareListing:
    """List a SMB share directory using NetExec."""
    if not getattr(shell, "netexec_path", None):
        return NetexecShareListing(entries=[], output="")

    share_arg = str(share).strip()
    cmd = f"{shell.netexec_path} smb {host} {auth} --share {share_arg}"
    if directory is None:
        cmd = f"{cmd} --dir \"\""
    elif directory:
        cmd = f"{cmd} --dir \"{directory}\""

    print_info_debug(
        f"[netexec] Share list command: {cmd}"
    )
    proc = shell._run_netexec(
        cmd,
        domain=domain,
        timeout=timeout,
        operation_kind="share_list",
        service="smb",
        target_count=1,
    )
    output = ""
    if proc:
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    entries = parse_netexec_share_dir_listing(output)
    return NetexecShareListing(entries=entries, output=output)


def download_share_files(
    shell: Any,
    *,
    domain: str,
    host: str,
    auth: str,
    share: str,
    files: list[str],
    output_dir: str,
    timeout: int = 300,
) -> list[str]:
    """Download multiple files from a SMB share using NetExec."""
    if not getattr(shell, "netexec_path", None):
        return []
    if not files:
        return []
    os.makedirs(output_dir, exist_ok=True)

    downloaded: list[str] = []
    for remote in files:
        remote_clean = str(remote).strip()
        if not remote_clean:
            continue
        local_name = os.path.basename(remote_clean)
        local_path = os.path.join(output_dir, local_name)
        cmd = (
            f"{shell.netexec_path} smb {host} {auth} --share {share} "
            f"--get-file \"{remote_clean}\" \"{local_path}\""
        )
        print_info_debug(f"[netexec] Share download command: {cmd}")
        proc = shell._run_netexec(
            cmd,
            domain=domain,
            timeout=timeout,
            operation_kind="share_download",
            service="smb",
            target_count=1,
        )
        if not proc or proc.returncode != 0:
            marked_file = mark_sensitive(remote_clean, "path")
            print_warning(f"Failed to download {marked_file} from share {share}.")
            continue
        if os.path.exists(local_path):
            downloaded.append(local_path)
    return downloaded
