"""Ownership and failure handling for the license storage directory.

The license directory (``adscan_core.enterprise_license.license_dir``) is
shared by two containers through a bind mount. On the Enterprise appliance the
web backend writes the clock high-water mark, the environment ledger and the
lock that serialises them on every scan launch, and the scan engine container,
which starts as root and drops to the host user, reads and writes the same
files. Since 14.0.1 the backend runs as that host user as well; until then it
ran as root, and directories in the field may still hold files it left
root-owned, which is what the rules below keep usable.

Two rules keep that sharing safe, and both live here so every writer applies
them the same way:

1. **A file root creates in the directory takes the directory's owner**
   (:func:`adopt_directory_owner`). Without it the directory fills with
   root-owned files the engine cannot open in place, which is how the first
   assessment launched from the web failed with exit 78 on a valid license.
2. **A storage failure is reported as one, never as a license verdict**
   (:class:`LicenseStorageError`, :data:`REASON_LICENSE_STORAGE_UNAVAILABLE`).
   A permission error on the lock tells the client nothing about the license
   and must not read as "missing, expired, not yet active".

Dependency-light on purpose: the web backend imports this module, so it uses
only the standard library and the PAL.
"""

from __future__ import annotations

import os
from pathlib import Path

from adscan_core.pal.process import effective_user_is_root

#: Reason code the engine writes beside exit 78 when it could not read or write
#: the license directory. Mirrored by the appliance worker (which never imports
#: ``adscan_core``); locked by
#: ``tests/unit/appliance/test_appliance_license_contract.py``.
REASON_LICENSE_STORAGE_UNAVAILABLE = "license_storage_unavailable"

#: What the engine prints, and records for the worker, for that fault.
LICENSE_STORAGE_UNAVAILABLE_MESSAGE = (
    "ADscan could not read or write its license records on this appliance, so "
    "this assessment cannot start. The license itself was not checked. Existing "
    "reports, history and exports remain available. Contact ADscan support."
)


class LicenseStorageError(OSError):
    """The license directory or one of its files could not be read or written.

    Subclasses :class:`OSError` so every existing ``except OSError`` around a
    license write keeps behaving as before; callers that need to tell a storage
    fault apart from a network or verification failure test for this class.
    """

    @classmethod
    def from_os_error(cls, exc: OSError, path: Path) -> "LicenseStorageError":
        """Wrap ``exc`` (raised while touching ``path``) keeping its errno."""
        return cls(exc.errno, exc.strerror or str(exc), str(path))


def _debug(message: str) -> None:
    try:
        from adscan_core.rich_output import print_info_debug  # noqa: PLC0415

        print_info_debug(message)
    except Exception:  # noqa: BLE001 - diagnostics must never break a write
        return


def adopt_directory_owner(path: Path, *, directory: Path | None = None) -> None:
    """Give ``path`` the owner of its directory when root created it.

    A no-op unless the current process is root (never on Windows, through the
    PAL) and the file's owner differs from the directory's. Never raises: a
    failed chown is logged at debug level and the write it follows stands,
    because the read-only lock open already keeps a root-owned lock usable and
    the runtime entrypoint repairs ownership at the next scan start.

    Args:
        path: The file just created or replaced. Not followed if a symlink.
        directory: The directory whose owner it takes. Defaults to
            ``path.parent``; a temporary file about to be renamed into place
            passes the final directory, which is the same one.
    """
    if not effective_user_is_root():
        return
    owner_dir = directory or path.parent
    try:
        dir_stat = os.stat(owner_dir)
        file_stat = os.lstat(path)
        wanted = (dir_stat.st_uid, dir_stat.st_gid)
        if (file_stat.st_uid, file_stat.st_gid) == wanted:
            return
        os.chown(path, wanted[0], wanted[1], follow_symlinks=False)
    except (OSError, AttributeError, NotImplementedError) as exc:
        _debug(f"license storage ownership not adopted for {path.name}: {exc}")


__all__ = [
    "LICENSE_STORAGE_UNAVAILABLE_MESSAGE",
    "LicenseStorageError",
    "REASON_LICENSE_STORAGE_UNAVAILABLE",
    "adopt_directory_owner",
]
