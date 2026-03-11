"""Shared exclusion policy for SMB share discovery, mapping, and spidering."""

from __future__ import annotations

from pathlib import PurePosixPath
import shlex


GLOBAL_SMB_EXCLUDED_SHARE_NAMES: tuple[str, ...] = (
    "print$",
    "ipc$",
    "admin$",
)
GLOBAL_SMB_EXCLUDED_DRIVE_SHARES: tuple[str, ...] = tuple(
    f"{letter}$" for letter in "abcdefghijklmnopqrstuvwxyz"
)
GLOBAL_SMB_EXCLUDE_FILTER_TOKENS: tuple[str, ...] = (
    GLOBAL_SMB_EXCLUDED_SHARE_NAMES + GLOBAL_SMB_EXCLUDED_DRIVE_SHARES
)
GLOBAL_SMB_MAPPING_EXCLUDED_EXTENSIONS: tuple[str, ...] = ("ico", "lnk")
GLOBAL_SMB_EXCLUDED_DIRECTORIES: tuple[str, ...] = ()
GLOBAL_SMB_HEAVY_ARTIFACT_MAX_FILESIZE_MB: int = 50

_GLOBAL_SMB_EXCLUDED_SHARES_CASEFOLD: set[str] = {
    name.casefold() for name in GLOBAL_SMB_EXCLUDE_FILTER_TOKENS
}
_GLOBAL_SMB_EXCLUDED_DIRECTORIES_CASEFOLD: set[str] = {
    name.casefold() for name in GLOBAL_SMB_EXCLUDED_DIRECTORIES
}


def is_globally_excluded_smb_share(share_name: str) -> bool:
    """Return ``True`` when one SMB share is excluded by shared policy."""
    return (
        str(share_name or "").strip().casefold()
        in _GLOBAL_SMB_EXCLUDED_SHARES_CASEFOLD
    )


def filter_shares_by_global_smb_exclusions(shares: list[str]) -> list[str]:
    """Filter share names according to the shared SMB exclusion policy."""
    filtered: list[str] = []
    seen: set[str] = set()
    for share in shares:
        share_name = str(share or "").strip()
        if not share_name:
            continue
        key = share_name.casefold()
        if key in seen:
            continue
        seen.add(key)
        if is_globally_excluded_smb_share(share_name):
            continue
        filtered.append(share_name)
    return filtered


def filter_share_map_by_global_smb_exclusions(
    share_map: dict[str, dict[str, str]] | None,
) -> dict[str, dict[str, str]] | None:
    """Filter host/share permissions according to the shared SMB exclusion policy."""
    if not isinstance(share_map, dict):
        return share_map
    filtered: dict[str, dict[str, str]] = {}
    for host, host_shares in share_map.items():
        if not isinstance(host_shares, dict):
            continue
        filtered_host_shares: dict[str, str] = {}
        for share_name, perms in host_shares.items():
            normalized_share = str(share_name or "").strip()
            if not normalized_share or is_globally_excluded_smb_share(
                normalized_share
            ):
                continue
            filtered_host_shares[normalized_share] = str(perms or "")
        if filtered_host_shares:
            filtered[str(host or "").strip()] = filtered_host_shares
    return filtered


def build_manspider_exclusion_args() -> str:
    """Return shared ``manspider`` exclusion arguments."""
    args = [
        "--exclude-sharenames "
        + " ".join(shlex.quote(share) for share in GLOBAL_SMB_EXCLUDE_FILTER_TOKENS)
    ]
    if GLOBAL_SMB_EXCLUDED_DIRECTORIES:
        args.append(
            "--exclude-dirnames "
            + " ".join(
                shlex.quote(directory)
                for directory in GLOBAL_SMB_EXCLUDED_DIRECTORIES
            )
        )
    return " ".join(args)


def is_globally_excluded_smb_relative_path(relative_path: str) -> bool:
    """Return ``True`` when one SMB relative path matches excluded directories."""
    normalized = str(relative_path or "").strip().replace("\\", "/")
    if not normalized or not _GLOBAL_SMB_EXCLUDED_DIRECTORIES_CASEFOLD:
        return False
    return any(
        part.casefold() in _GLOBAL_SMB_EXCLUDED_DIRECTORIES_CASEFOLD
        for part in PurePosixPath(normalized).parts
        if str(part).strip() not in {"", ".", ".."}
    )


def prune_excluded_walk_dirs(dirnames: list[str]) -> None:
    """Prune excluded SMB directories in-place for ``os.walk`` traversal."""
    if not _GLOBAL_SMB_EXCLUDED_DIRECTORIES_CASEFOLD:
        return
    dirnames[:] = [
        dirname
        for dirname in dirnames
        if str(dirname).strip().casefold()
        not in _GLOBAL_SMB_EXCLUDED_DIRECTORIES_CASEFOLD
    ]


__all__ = [
    "GLOBAL_SMB_HEAVY_ARTIFACT_MAX_FILESIZE_MB",
    "GLOBAL_SMB_EXCLUDED_DIRECTORIES",
    "GLOBAL_SMB_EXCLUDED_DRIVE_SHARES",
    "GLOBAL_SMB_EXCLUDED_SHARE_NAMES",
    "GLOBAL_SMB_EXCLUDE_FILTER_TOKENS",
    "GLOBAL_SMB_MAPPING_EXCLUDED_EXTENSIONS",
    "build_manspider_exclusion_args",
    "filter_share_map_by_global_smb_exclusions",
    "filter_shares_by_global_smb_exclusions",
    "is_globally_excluded_smb_relative_path",
    "is_globally_excluded_smb_share",
    "prune_excluded_walk_dirs",
]
