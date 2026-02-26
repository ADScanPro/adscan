"""PyInstaller runtime hook: disable Pydantic plugins in frozen binaries.

Some third-party Pydantic plugins (loaded via entry points) may call
``inspect.getsource()`` during model initialization, which can fail in
PyInstaller onefile/onedir environments with:
``OSError: could not get source code``.

Setting ``PYDANTIC_DISABLE_PLUGINS=__all__`` at runtime-hook phase ensures the
variable is present before regular imports run.
"""

from __future__ import annotations

import os


os.environ.setdefault("PYDANTIC_DISABLE_PLUGINS", "__all__")
