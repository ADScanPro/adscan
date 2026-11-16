"""Offline PRO image exports: the signed sidecar and its verification.

An air-gapped or engagement installation receives ``adscan-pro-<version>.tar.zst``
(``docker save`` compressed with zstd) through a short-lived presigned link,
plus ``adscan-pro-<version>.json``: a sidecar naming the version, the image
digest, the archive's sha256 and size, signed with the LICENCE SERVER key (the
key every PRO engine already trusts, :data:`PRO_LICENSE_SERVER_PUBLIC_KEYS`).
The sidecar is signed on the licence server (``registry_admin sign-export``),
so the release machine never holds that key.

``adscan install --image-archive FILE`` verifies the sidecar signature and the
archive checksum before ``docker load``; a mismatch loads nothing.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from adscan_core.enterprise_license import FORMAT_VERSION, PAYLOAD_FORMAT_KEY, LicenseError

EXPORT_KIND = "image_export"
_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z.]{1,32})?$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REF_RE = re.compile(r"^[a-z0-9./:_-]{1,200}$")


def export_payload(unsigned: Mapping[str, Any]) -> dict[str, Any]:
    """Validate an unsigned sidecar and return the payload the licence server signs.

    Raises:
        ValueError: a missing or malformed field.
    """
    version = str(unsigned.get("version") or "")
    digest = str(unsigned.get("image_digest") or "")
    sha = str(unsigned.get("sha256") or "")
    size = unsigned.get("size")
    source_ref = str(unsigned.get("source_ref") or "")
    image = str(unsigned.get("image") or "")
    if not _VERSION_RE.fullmatch(version):
        raise ValueError("version is not a release version")
    if not _DIGEST_RE.fullmatch(digest):
        raise ValueError("image_digest is not a sha256 digest")
    if not _SHA256_RE.fullmatch(sha):
        raise ValueError("sha256 is not a hex digest")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise ValueError("size is not a positive integer")
    if not _REF_RE.fullmatch(source_ref) or not _REF_RE.fullmatch(image) or ".." in source_ref + image:
        raise ValueError("source_ref or image is not an image reference")
    return {
        PAYLOAD_FORMAT_KEY: FORMAT_VERSION,
        "kind": EXPORT_KIND,
        "edition": "pro",
        "version": version,
        "image_digest": digest,
        "sha256": sha,
        "size": size,
        "image": image,
        "source_ref": source_ref,
    }


def verify_export_sidecar(raw: bytes | str, *, trusted_keys: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Verify a signed sidecar against the licence-server keys; return its payload.

    Raises:
        LicenseError: not signed by ADscan, or not an image-export sidecar.
    """
    from adscan_core.pro_license import documents as docs

    payload = docs.verify_server_document(raw, trusted_keys=trusted_keys, kinds={EXPORT_KIND})
    try:
        export_payload(payload)
    except ValueError as exc:
        raise LicenseError("malformed", f"The image sidecar is malformed: {exc}.") from exc
    return payload


def verify_archive(path: Path, payload: Mapping[str, Any]) -> None:
    """Check the archive's size and sha256 against a verified sidecar payload.

    Raises:
        LicenseError: the archive is not the one the sidecar names.
    """
    path = Path(path)
    if path.stat().st_size != int(payload["size"]):
        raise LicenseError("checksum_mismatch", "The image archive does not have the signed size.")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != payload["sha256"]:
        raise LicenseError("checksum_mismatch", "The image archive does not match its signed checksum.")


def read_sidecar_for(archive: Path, sidecar: Path | None = None) -> bytes:
    """The sidecar bytes: ``sidecar`` or ``<archive without .tar.zst>.json`` beside it."""
    if sidecar is None:
        name = archive.name
        stem = name[: -len(".tar.zst")] if name.endswith(".tar.zst") else archive.stem
        sidecar = archive.with_name(stem + ".json")
    return Path(sidecar).read_bytes()


__all__ = ["EXPORT_KIND", "export_payload", "read_sidecar_for", "verify_archive", "verify_export_sidecar"]
