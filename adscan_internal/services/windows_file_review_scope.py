"""Which files a bounded listing of a Windows host asks the server for.

A bounded listing (``WindowsFileMappingService.generate_bounded_file_map``)
cuts volume by what a file IS, never by where it is: every directory is still
walked, and the server keeps only the files whose extension the review reads.
This module is the one place that says which extensions those are, for every
transport (a database server through ``xp_cmdshell``, a host over Windows
Remote Management), so the listing of one transport can never leave out a file
type another transport's review would have read.
"""

from __future__ import annotations

from adscan_internal.services.smb_sensitive_file_policy import (
    get_production_sensitive_scan_phase_sequence,
    get_sensitive_phase_extensions,
)

#: The review mode that triages every file name, so its listing is unfiltered.
REVIEW_MODE_AI = "ai"


def review_listing_extensions(mode: str) -> tuple[str, ...]:
    """The extensions the file listing keeps on the server, for one review mode.

    The deterministic review reads only the extensions of its phases and the
    virtual-machine disk and memory images, so the listing asks the server for
    those alone. The server matches a file on ANY of its dot-separated
    suffixes, so ``Groups.xml.bak`` is kept for ``.xml``: the set is a superset
    of what the phases select by a file's effective extension. The AI review
    triages every file name: no filter.

    Args:
        mode: ``"ai"`` or the deterministic mode.

    Returns:
        Lower-case single-suffix extensions (``.txt``); empty keeps every file.
    """
    if mode == REVIEW_MODE_AI:
        return ()
    from adscan_internal.services.vm_artifact_service import (  # noqa: PLC0415
        DISK_IMAGE_EXTENSIONS,
        MEMORY_IMAGE_EXTENSIONS,
    )

    extensions: list[str] = []
    for phase in get_production_sensitive_scan_phase_sequence():
        extensions.extend(get_sensitive_phase_extensions(phase))
    extensions.extend(DISK_IMAGE_EXTENSIONS)
    extensions.extend(MEMORY_IMAGE_EXTENSIONS)
    # The server matches one dot-separated suffix at a time.
    return tuple(
        dict.fromkeys(
            "." + str(ext).strip().lower().rsplit(".", 1)[-1]
            for ext in extensions
            if str(ext).strip().strip(".")
        )
    )


__all__ = ("REVIEW_MODE_AI", "review_listing_extensions")
