"""Pull credentials for the licence-authorised PRO registry, with no stored password.

Before each pull from ``registry.adscanpro.com`` the launcher signs a fresh
registry assertion with this machine's installation key
(:mod:`adscan_core.pro_license.registry_assertion`), writes it into an
ADscan-owned Docker config directory (dir 0700, file 0600), runs
``docker --config <dir> pull`` and deletes the file afterwards. The operator's
own ``~/.docker/config.json`` is never read or written, and ``--config``
survives ``sudo``. The token service checks the assertion against the public
key it stored at activation and applies the licence's standing refusal, so a
revoked licence stops pulling within minutes with no step on this machine.

Spec: ``docs/superpowers/specs/2026-11-12-licence-authorised-pro-registry.md`` § 3, § 6.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path

from adscan_launcher.edition import PRO_REGISTRY_HOST, is_pro_registry_image

#: Prefix of the per-pull directory. It lives in the per-user runtime directory
#: (``$XDG_RUNTIME_DIR``) or the system temp dir, never under ``~/.adscan``,
#: which is bind-mounted into every ADscan container.
PRIVATE_CONFIG_PREFIX = "adscan-registry-"


def _private_parent() -> str | None:
    runtime = os.getenv("XDG_RUNTIME_DIR", "").strip()
    return runtime if runtime and os.path.isdir(runtime) and os.access(runtime, os.W_OK) else None


def _user_context(user_dir: Path) -> str | None:
    """``currentContext`` of the operator's own Docker config, if any."""
    try:
        data = json.loads((user_dir / "config.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    value = data.get("currentContext") if isinstance(data, dict) else None
    return str(value) if isinstance(value, str) and value.strip() else None


class RegistryCredentialUnavailable(RuntimeError):
    """No activated installation on this machine, so no registry credential can be signed."""


@contextlib.contextmanager
def registry_pull_config(image: str) -> Iterator[Path | None]:
    """Yield a Docker config dir carrying a fresh assertion for ``image``'s registry, or None.

    None for any image that is not on the licence-authorised registry, so the
    caller pulls exactly as before. The directory is created per pull (0700,
    outside the state tree containers mount) and removed on exit, success or not.

    The operator's Docker CONTEXT is kept: ``docker --config DIR`` would otherwise
    start from an empty config and talk to the default socket, so a rootless
    daemon, Docker Desktop for Linux or Colima would pull into the wrong daemon
    (or fail) and ``image_exists`` would never see the image. ``currentContext``
    is copied and the operator's ``contexts/`` directory is linked (read, never
    written). ``DOCKER_HOST`` / ``DOCKER_CONTEXT`` in the environment keep
    working as they always do. Nothing else of the operator's config is used:
    no credential helper, no other registry's login.

    Raises:
        RegistryCredentialUnavailable: a registry image but no installation key
            on this machine (the licence was never activated here).
    """
    if not is_pro_registry_image(image):
        yield None
        return
    from adscan_core.pro_license.registry_assertion import build_registry_credentials, docker_config_auth
    from adscan_core.pro_license.state import ProLicenseStore
    from adscan_launcher.edition import user_docker_config_dir

    store = ProLicenseStore()
    installation = store.existing_installation()
    if installation is None:
        raise RegistryCredentialUnavailable(
            "This machine has no activated PRO licence. Run `adscan license activate` first."
        )
    credentials = build_registry_credentials(
        installation, service=PRO_REGISTRY_HOST, now=_signing_time(store)
    )
    body = dict(docker_config_auth(credentials, PRO_REGISTRY_HOST))
    user_dir = user_docker_config_dir()
    context = _user_context(user_dir)
    if context:
        body["currentContext"] = context
    directory = Path(tempfile.mkdtemp(prefix=PRIVATE_CONFIG_PREFIX, dir=_private_parent()))
    try:
        os.chmod(directory, 0o700)
        if (user_dir / "contexts").is_dir():
            (directory / "contexts").symlink_to((user_dir / "contexts").resolve(), target_is_directory=True)
        fd = os.open(directory / "config.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(body, handle)
        yield directory
    finally:
        # rmtree removes the contexts LINK, never what it points to.
        shutil.rmtree(directory, ignore_errors=True)


def _signing_time(store: object):  # noqa: ANN202 - datetime | None
    """The instant to date the assertion: the licence server's clock when known.

    See :func:`adscan_core.pro_license.route_check.server_corrected_now`.
    """
    from adscan_core.pro_license.route_check import server_corrected_now

    return server_corrected_now(store)


def docker_pull_argv(image: str, config_dir: Path | None) -> list[str]:
    """``docker [--config DIR] pull IMAGE``."""
    return ["docker"] + (["--config", str(config_dir)] if config_dir is not None else []) + ["pull", image]


__all__ = [
    "PRIVATE_CONFIG_PREFIX",
    "RegistryCredentialUnavailable",
    "docker_pull_argv",
    "registry_pull_config",
]
