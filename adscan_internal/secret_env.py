"""Compatibility helpers for legacy `--secret-env-file` arguments.

Secret-based unlock flows were removed from the public launcher/LITE runtime.
This module intentionally keeps a small compatibility surface so older call
sites can import the same function names without enabling secret loading.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence


def extract_secret_env_file_argv(argv: Sequence[str]) -> str | None:
    """Extract `--secret-env-file` value from argv if present.

    Supported forms:
    - `--secret-env-file /abs/path/.secret.env`
    - `--secret-env-file=/abs/path/.secret.env`
    """
    for idx, arg in enumerate(argv):
        if arg == "--secret-env-file" and idx + 1 < len(argv):
            return argv[idx + 1]
        if arg.startswith("--secret-env-file="):
            _, value = arg.split("=", 1)
            return value
    return None


def load_secret_env(*, allow_cwd_fallback: bool = True) -> Path | None:
    """Legacy no-op retained for backward compatibility.

    Args:
        allow_cwd_fallback: Ignored. Kept only for call-site compatibility.

    Returns:
        Always ``None`` because secret loading is disabled in LITE.
    """
    _ = allow_cwd_fallback
    return None
