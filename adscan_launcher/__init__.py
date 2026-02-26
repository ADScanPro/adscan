"""ADscan launcher (host-side) utilities.

This package contains the host-side launcher logic that orchestrates Docker.
It is intended to be publishable to PyPI/GitHub as open source.

The actual ADscan runtime CLI runs inside the Docker image.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

__all__ = ["__version__"]

try:
    __version__ = version("adscan")
except PackageNotFoundError:
    # Source checkout fallback.
    __version__ = "0.0.0"
