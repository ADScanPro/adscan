"""ADscan launcher (host-side) utilities.

This package contains the host-side launcher logic that orchestrates Docker.
It is intended to be publishable to PyPI/GitHub as open source.

The actual ADscan runtime CLI runs inside the Docker image.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from adscan_core.version_context import VERSION, get_source_tree_version

__all__ = ["__version__"]

try:
    __version__ = version("adscan")
except PackageNotFoundError:
    __version__ = get_source_tree_version() or VERSION
