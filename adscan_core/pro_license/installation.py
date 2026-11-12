"""The engine installation's own key pair.

Every request an installation sends to the licence server is signed with this
key, so the server knows which installation sent it and nobody in between (a
partner platform relaying the request included) can forge or alter one. The
installation id is derived from the public key, so an id cannot be claimed
without the key.

The private key lives in ``pro-installation.json`` (mode 0600) in the licence
directory. Copying the directory copies the installation; the server detects
two copies diverging through the request ``sequence`` (spec § 5.6).
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from adscan_core.enterprise_license import LicenseError, sign_payload
from adscan_core.pro_license._io import read_json, write_json

INSTALLATION_FILENAME = "pro-installation.json"
_ID_PREFIX = "in-"
_ID_LENGTH = 24


def installation_id_for(public_key_b64: str) -> str:
    """Derive the installation id from its base64 raw Ed25519 public key."""
    raw = base64.b64decode(public_key_b64, validate=True)
    digest = hashlib.sha256(raw).digest()
    return _ID_PREFIX + base64.b32encode(digest).decode("ascii").lower()[:_ID_LENGTH]


def _generate() -> tuple[bytes, str]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    private_raw = key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    public_raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return private_raw, base64.b64encode(public_raw).decode("ascii")


@dataclass
class Installation:
    """One engine installation: its id, its key pair and its request counter."""

    installation_id: str
    public_key_b64: str
    private_key_raw: bytes
    directory: Path

    @property
    def path(self) -> Path:
        """File holding the key pair and the counter."""
        return self.directory / INSTALLATION_FILENAME

    @classmethod
    def load(cls, directory: Path) -> Installation | None:
        """Return the installation stored in ``directory``, or None."""
        data = read_json(Path(directory) / INSTALLATION_FILENAME)
        if not isinstance(data, Mapping):
            return None
        try:
            public_b64 = str(data["public_key"])
            private_raw = base64.b64decode(str(data["private_key"]), validate=True)
            installation_id = installation_id_for(public_b64)
        except (KeyError, ValueError, TypeError):
            return None
        if installation_id != data.get("installation_id"):
            return None
        return cls(installation_id, public_b64, private_raw, Path(directory))

    @classmethod
    def load_or_create(cls, directory: Path) -> Installation:
        """Return the installation in ``directory``, creating it on first use."""
        from adscan_core.environment_ledger import state_file_lock

        directory = Path(directory)
        existing = cls.load(directory)
        if existing is not None:
            return existing
        directory.mkdir(parents=True, exist_ok=True)
        with state_file_lock(directory):
            existing = cls.load(directory)
            if existing is not None:
                return existing
            private_raw, public_b64 = _generate()
            installation = cls(installation_id_for(public_b64), public_b64, private_raw, directory)
            write_json(
                installation.path,
                {
                    "installation_id": installation.installation_id,
                    "public_key": public_b64,
                    "private_key": base64.b64encode(private_raw).decode("ascii"),
                    "sequence": 0,
                },
                mode=0o600,
            )
            return installation

    def next_sequence(self) -> int:
        """Increment and persist the request counter; return the new value."""
        from adscan_core.environment_ledger import state_file_lock

        with state_file_lock(self.directory):
            data = read_json(self.path)
            if not isinstance(data, dict):
                raise LicenseError("unreadable", "The installation record cannot be read.")
            current = data.get("sequence")
            previous = current if isinstance(current, int) and not isinstance(current, bool) else 0
            data["sequence"] = previous + 1
            write_json(self.path, data, mode=0o600)
            return previous + 1

    def sign(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        """Sign ``payload`` with this installation's key (kid = installation id)."""
        return sign_payload(payload, private_key_raw=self.private_key_raw, key_id=self.installation_id)


__all__ = ["INSTALLATION_FILENAME", "Installation", "installation_id_for"]
