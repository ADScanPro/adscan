"""Where a deliverable is saved outside the workspace: the single source of truth.

Every surface that lets the operator keep a report somewhere of their choosing
goes through this module: ``adscan ci --output``, host ``adscan deliver
--output``, the guided REPL ``deliver`` (PRO kit) and the LITE exposure report.
It answers three questions, the same way for all of them:

1. Which folder is the operator's deliverables folder, and how does THIS
   process reach it? (:func:`deliverables_root`)
2. Is a folder the operator typed reachable, and where do we write it?
   (:func:`resolve_destination`)
3. How are the files copied, and what path does the operator see?
   (:func:`copy_to_destination`, :func:`display_path_for`)

Two deployment shapes, one API:

* **Docker runtime (Linux / macOS).** The engine runs in a container that can
  only write to mounted folders and cannot mount a new host path mid-session.
  The launcher therefore mounts the deliverables folder at
  :data:`~adscan_core.container_io.DELIVERABLES_CONTAINER_DIR` and forwards its
  host path (:data:`DELIVERABLES_HOST_DIR_ENV`) for display, plus the host home
  (:data:`HOST_HOME_ENV`) so a typed ``~/...`` means the operator's home, not
  the container's. Only paths at or under that folder are reachable.
* **Native (the Windows bundle, or a dev ``uv run``).** No container, no
  mapping: any path is accepted and the folder resolves through the PAL.

The workspace copy always stays where it is; this module only ever copies.
It is dependency-light (stdlib + ``adscan_core``) so the launcher, the
container engine and LITE import it alike.
"""

from __future__ import annotations

import os
import posixpath
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from adscan_core.container_io import DELIVERABLES_CONTAINER_DIR, OUTPUT_IO_CONTAINER_DIR
from adscan_core.pal import paths as pal_paths

__all__ = [
    "DELIVERABLES_DIR_ENV",
    "DELIVERABLES_HOST_DIR_ENV",
    "HOST_HOME_ENV",
    "DeliverablesRoot",
    "DestinationResolution",
    "HostOutputPlan",
    "copy_to_destination",
    "default_destination_display",
    "deliverables_root",
    "display_path_for",
    "host_deliverables_dir",
    "in_container_runtime",
    "move_staged_into",
    "plan_host_output",
    "resolve_destination",
    "unreachable_destination_message",
    "workspace_folder_name",
]

#: Operator setting (a HOST path). Launcher-only in the Docker deployment.
DELIVERABLES_DIR_ENV = pal_paths.DELIVERABLES_DIR_ENV
#: Launcher -> container: the host path of the mounted deliverables folder.
DELIVERABLES_HOST_DIR_ENV = "ADSCAN_DELIVERABLES_HOST_DIR"
#: Launcher -> container: the operator's host home, to expand a typed ``~``.
HOST_HOME_ENV = "ADSCAN_HOST_HOME"

_CONTAINER_RUNTIME_ENV = "ADSCAN_CONTAINER_RUNTIME"
_UNSAFE_FOLDER_CHARS = re.compile(r"[^A-Za-z0-9._ -]+")


def in_container_runtime() -> bool:
    """True when this process is the engine inside ADscan's Docker runtime."""
    return os.environ.get(_CONTAINER_RUNTIME_ENV) == "1"


def host_deliverables_dir() -> Path:
    """The deliverables folder on THIS host (launcher or native engine)."""
    return pal_paths.deliverables_dir()


@dataclass(frozen=True)
class DeliverablesRoot:
    """How this process reaches the operator's deliverables folder.

    Attributes:
        io_path: Where this process reads and writes.
        display_path: The same folder as the operator sees it (a host path).
        mapped: True when the two differ (the Docker runtime).
    """

    io_path: Path
    display_path: str
    mapped: bool


def deliverables_root() -> Optional[DeliverablesRoot]:
    """Resolve the deliverables folder for this process, or None.

    None means "no reachable deliverables folder": a container started without
    the mount (an older launcher, the web worker). Callers skip the copy step.
    """
    if not in_container_runtime():
        folder = host_deliverables_dir()
        return DeliverablesRoot(io_path=folder, display_path=str(folder), mapped=False)
    host_dir = os.environ.get(DELIVERABLES_HOST_DIR_ENV, "").strip()
    mount = Path(DELIVERABLES_CONTAINER_DIR)
    if not host_dir or not mount.is_dir():
        return None
    return DeliverablesRoot(
        io_path=mount, display_path=posixpath.normpath(host_dir), mapped=True
    )


def workspace_folder_name(workspace: str) -> str:
    """A folder name for a workspace: its basename, with path-hostile chars dropped.

    A per-workspace subfolder keeps each client's kits apart, which is how a
    consultant avoids attaching one client's report to another's email.
    """
    base = os.path.basename(str(workspace or "").rstrip("/\\")) or "workspace"
    cleaned = _UNSAFE_FOLDER_CHARS.sub("-", base).strip(" .-")
    return cleaned or "workspace"


def default_destination_display(root: DeliverablesRoot, workspace: str) -> str:
    """The suggested destination (display form): ``<deliverables>/<workspace>``."""
    name = workspace_folder_name(workspace)
    if root.mapped:
        return posixpath.join(root.display_path, name)
    return str(Path(root.display_path) / name)


@dataclass(frozen=True)
class DestinationResolution:
    """Outcome of :func:`resolve_destination`.

    Exactly one of ``io_path`` / ``error`` is set. ``display_path`` is what the
    operator sees (the host path) when the destination is reachable.
    """

    io_path: Optional[Path] = None
    display_path: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        """True when the destination is reachable."""
        return self.io_path is not None


def unreachable_destination_message(raw: str, root: DeliverablesRoot) -> str:
    """Plain explanation for a host path the container cannot reach."""
    return (
        f"ADscan runs in a container and can only write to your deliverables "
        f"folder ({root.display_path}), so it cannot reach {raw}. Save under that "
        f"folder, or run 'adscan deliver --output {raw}' from your host shell. "
        f"The deliverables folder is set with ADSCAN_DELIVERABLES_DIR."
    )


def _expand_container_typed_path(raw: str) -> Optional[str]:
    """Expand a host path typed inside the container (``~`` = HOST home)."""
    if raw == "~" or raw.startswith("~/"):
        host_home = os.environ.get(HOST_HOME_ENV, "").strip()
        if not host_home:
            return None
        return posixpath.join(host_home, raw[2:]) if raw != "~" else host_home
    return raw


def resolve_destination(raw: str, root: DeliverablesRoot) -> DestinationResolution:
    """Map a folder the operator typed to a path this process can write.

    * A relative name lands inside the deliverables folder (``acme`` ->
      ``<deliverables>/acme``), on every OS.
    * Native: any absolute path is accepted (``~`` expands, sudo-safe).
    * Container: the path must be the deliverables folder or below it; ``..``
      cannot escape. The container mount path itself is accepted too.
    """
    value = os.path.expandvars(str(raw or "").strip())
    if not value:
        return DestinationResolution(error="No folder given.")

    if not root.mapped:
        from adscan_core.path_utils import expand_effective_user_path  # noqa: PLC0415

        candidate = Path(expand_effective_user_path(value))
        if not candidate.is_absolute():
            candidate = root.io_path / candidate
        return DestinationResolution(io_path=candidate, display_path=str(candidate))

    expanded = _expand_container_typed_path(value)
    if expanded is None:
        return DestinationResolution(error=unreachable_destination_message(value, root))
    if not posixpath.isabs(expanded):
        expanded = posixpath.join(root.display_path, expanded)
    normalized = posixpath.normpath(expanded)
    for base_display, base_io in (
        (root.display_path, str(root.io_path)),
        (str(root.io_path), str(root.io_path)),
    ):
        if normalized == base_display or normalized.startswith(base_display.rstrip("/") + "/"):
            relative = posixpath.relpath(normalized, base_display)
            io_path = Path(base_io) if relative == "." else Path(base_io) / relative
            display = (
                root.display_path
                if relative == "."
                else posixpath.join(root.display_path, relative)
            )
            return DestinationResolution(io_path=io_path, display_path=display)
    return DestinationResolution(error=unreachable_destination_message(value, root))


def display_path_for(path: Path | str) -> str:
    """Render an io path as the host path the operator knows.

    Under the deliverables mount the container path is replaced by the host
    folder; anything else is returned unchanged (the workspace tree is mapped
    by ``host_open.display_host_path``).
    """
    raw = str(path)
    if not in_container_runtime():
        return raw
    host_dir = os.environ.get(DELIVERABLES_HOST_DIR_ENV, "").strip()
    if not host_dir:
        return raw
    if raw == DELIVERABLES_CONTAINER_DIR:
        return posixpath.normpath(host_dir)
    prefix = DELIVERABLES_CONTAINER_DIR + "/"
    if raw.startswith(prefix):
        return posixpath.join(posixpath.normpath(host_dir), raw[len(prefix):])
    return raw


def copy_to_destination(files: Iterable[Path | str], destination: Path | str) -> list[Path]:
    """Copy ``files`` into ``destination`` (created), overwriting same-named files.

    Missing sources are skipped. The originals are never moved.

    Returns:
        The copied paths, in the order given.

    Raises:
        OSError: When the folder cannot be created or a copy fails.
    """
    dest = Path(destination)
    dest.mkdir(parents=True, exist_ok=True)
    copied: list[Path] = []
    for source in files:
        src = Path(source)
        if not src.is_file():
            continue
        target = dest / src.name
        shutil.copy2(src, target)
        copied.append(target)
    return copied


@dataclass(frozen=True)
class HostOutputPlan:
    """A host ``--output`` prepared for a containerised command.

    Attributes:
        final: The absolute host path the operator asked for.
        dest_dir: The host folder the results land in.
        container_arg: The path the container is told to write to.
    """

    final: str
    dest_dir: str
    container_arg: str


def plan_host_output(value: str, *, is_file: bool) -> HostOutputPlan:
    """Validate a host ``--output`` and compute the container-side argument.

    The launcher stages the output in a fresh folder mounted at
    :data:`~adscan_core.container_io.OUTPUT_IO_CONTAINER_DIR` and moves the
    results with :func:`move_staged_into` once the container exits.

    Raises:
        ValueError: When the folder contains ``:``, which a Docker ``-v`` spec
            cannot express.
    """
    final = os.path.abspath(os.path.expanduser(value))
    dest_dir = os.path.dirname(final) if is_file else final
    if ":" in dest_dir:
        raise ValueError(f"Output path cannot contain ':' (Docker cannot mount it): {dest_dir}")
    container_arg = (
        f"{OUTPUT_IO_CONTAINER_DIR}/{os.path.basename(final)}" if is_file else OUTPUT_IO_CONTAINER_DIR
    )
    return HostOutputPlan(final=final, dest_dir=dest_dir, container_arg=container_arg)


def move_staged_into(staging: str, dest_dir: str) -> None:
    """Move what a container wrote into ``staging`` to ``dest_dir``; drop staging."""
    try:
        for entry in sorted(os.listdir(staging)):
            source = os.path.join(staging, entry)
            target = os.path.join(dest_dir, entry)
            if os.path.isdir(target) and not os.path.islink(target):
                shutil.rmtree(target)
            elif os.path.lexists(target):
                os.remove(target)
            shutil.move(source, target)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
