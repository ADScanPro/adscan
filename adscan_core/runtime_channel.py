"""Which release channel the running image was built for.

The image bakes ``ADSCAN_IMAGE_CHANNEL`` at build time (``dev`` for images built
with ``--dev``, ``stable`` for ``--prod`` builds). A capability that is withdrawn
from the shipped product but kept for development (the interactive reverse shell)
asks :func:`is_dev_image` instead of inventing its own switch.

Anything that is not explicitly ``dev`` counts as shipped, including a bare
Windows bundle, a unit-test process and an image built before this marker
existed, so the safe default is always the shipped behaviour.
"""

from __future__ import annotations

import os

IMAGE_CHANNEL_ENV = "ADSCAN_IMAGE_CHANNEL"
DEV_CHANNEL = "dev"


def is_dev_image() -> bool:
    """Return True only when the running image was built on the dev channel."""
    return (os.environ.get(IMAGE_CHANNEL_ENV) or "").strip().lower() == DEV_CHANNEL
