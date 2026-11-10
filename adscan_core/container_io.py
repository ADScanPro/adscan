"""Container paths the launcher bind-mounts single host files under.

Shared by the host launcher (which builds the ``docker run`` mounts) and the
container runtime (which recognises a mounted path), so the two agree on one
location. These directories sit outside the ADscan home, so nothing a command
reads or writes through them is left on the persistent volume. They exist only
in the Docker deployment; the native Windows runtime never sees them.
"""

from __future__ import annotations

CONTAINER_IO_ROOT = "/opt/adscan-io"
POLICY_IO_CONTAINER_DIR = f"{CONTAINER_IO_ROOT}/policy"
# Where a deliverable command writes when the operator passes --output: the
# launcher bind-mounts the host folder here, so the files land on the host
# instead of in the throwaway container layer.
OUTPUT_IO_CONTAINER_DIR = f"{CONTAINER_IO_ROOT}/output"
# The operator's deliverables folder (``ADSCAN_DELIVERABLES_DIR``, default
# ``~/ADscan-deliverables``), mounted read-write for the session so the REPL
# can save a copy of a report outside ADscan's own tree. See
# ``adscan_core.deliverable_destination``.
DELIVERABLES_CONTAINER_DIR = f"{CONTAINER_IO_ROOT}/deliverables"


def is_container_io_path(path: str) -> bool:
    """Return True when ``path`` lives under the launcher's bind-mount root."""
    return str(path).startswith(f"{CONTAINER_IO_ROOT}/")


__all__ = [
    "CONTAINER_IO_ROOT",
    "DELIVERABLES_CONTAINER_DIR",
    "OUTPUT_IO_CONTAINER_DIR",
    "POLICY_IO_CONTAINER_DIR",
    "is_container_io_path",
]
