"""Embedded telemetry endpoints/tokens with lightweight obfuscation.

This module intentionally avoids reading telemetry endpoint/token values from
`.env` files so public distributions do not carry an obvious plaintext config
file. Values are still recoverable by reverse engineering and must be treated
as public ingest credentials on the backend.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import json
from typing import Any


_EMBEDDED_BLOB = (
    "sJzkv3DTL0tO-Tl9RLcqxWn_q9y1oVuTdoWa5s9yihWv2vX_epciG0yuPioWvSaXaK3xibCi"
    "XsEkhMjiynLfRqqG8qsrwzUFWOw3LwK_MMkvv-LMvehFy3_T17CdYN1Fpc7i8mSSeERV6zop"
    "SOp9ynS7_czzrwXCatmcp9s_nFSjzrKnaJljXQrvZWQP6yrPdar2zOSmBNU10teyln6RU67c"
    "-PIlmjhZFe8rI0_iP9EppPadq-UazWWH2_PVMc0G8Zz46T6BZBNVszFzTqtzxSio89H3tQWLJ"
    "NKU_o523Eyk0fuyOZR5XQjlfWcC8zCbeaPmy_e0UIpo08G_13LaV6jf_u04njlKFfFwPEXnes"
    "40oL3J4rUJwCuQirSKYNdLpc2ysWidNRNY9Cs_UPYojnSlqtGppg7WJNyXoYt8kEek07_qL5N"
    "_RhX3cCpE9nHANZT-3uW0SNg="
)
_BLOB_KEY = hashlib.sha256(b"ADscan::telemetry::embedded::v1").digest()


@functools.lru_cache(maxsize=1)
def _payload() -> dict[str, Any]:
    """Return decoded telemetry payload (best-effort)."""
    try:
        raw = base64.urlsafe_b64decode(_EMBEDDED_BLOB.encode("ascii"))
        plain = bytes([byte ^ _BLOB_KEY[idx % len(_BLOB_KEY)] for idx, byte in enumerate(raw)])
        data = json.loads(plain.decode("utf-8"))
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def _get(name: str) -> str | None:
    value = _payload().get(name)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def get_cli_shared_token() -> str | None:
    return _get("t")


def get_posthog_proxy_url_dev() -> str | None:
    return _get("phd")


def get_posthog_proxy_url_prod() -> str | None:
    return _get("php")


def get_posthog_proxy_url_legacy() -> str | None:
    return _get("ph")


def get_sentry_proxy_url() -> str | None:
    return _get("s")


def get_vercel_sessions_proxy_url() -> str | None:
    return _get("v")


def get_labs_webhook_url() -> str | None:
    return _get("l")

