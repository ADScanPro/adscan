"""Hashcat cracking service.

This module encapsulates small, reusable helpers for processing hashcat
output, so that the monolithic CLI in ``adscan.py`` does not need to
own all of the cracking logic directly.

The goal is to progressively migrate hash-cracking responsibilities into
service-layer components that can be tested in isolation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional
import logging

from adscan_internal import telemetry
from adscan_internal.rich_output import print_error, print_exception
from adscan_internal.services.base_service import BaseService


logger = logging.getLogger(__name__)


@dataclass
class HashcatCrackingResult:
    """Result of processing a hashcat cracked output file.

    Attributes:
        credentials: Mapping of username to cracked password.
        file_path: Path to the processed file.
    """

    credentials: Dict[str, str]
    file_path: str

    def has_credentials(self) -> bool:
        """Return True when at least one credential was recovered."""

        return bool(self.credentials)


class HashcatCrackingService(BaseService):
    """Service for post-processing hashcat cracking results.

    This service does **not** execute hashcat itself. Instead, it focuses on
    reading hashcat output files and extracting usable credentials in a
    structured way. Execution and orchestration remain the responsibility of
    the CLI layer for now.
    """

    def extract_creds_from_hash(
        self,
        file_path: str,
    ) -> Optional[HashcatCrackingResult]:
        """Extract credentials from a hashcat output file.

        The expected format is one credential per line using a ``:`` separator:

        - ``username:password``
        - ``username:password:extra:fields`` (only the first two fields matter)

        Empty lines and lines without a ``:`` separator are ignored.

        Args:
            file_path: Path to the file produced by hashcat (e.g. ``--show``
                output redirected to disk).

        Returns:
            HashcatCrackingResult with a mapping of ``username -> password``,
            or ``None`` if an unrecoverable error occurred while reading the
            file.
        """

        creds: Dict[str, str] = {}
        try:
            with open(file_path, "r", encoding="utf-8") as handle:
                for raw_line in handle:
                    line = raw_line.strip()
                    if not line:
                        continue
                    parts = line.split(":")
                    if len(parts) < 2:
                        continue
                    username = parts[0]
                    password = parts[1]
                    creds[username] = password

            logger.debug(
                "Extracted %d credential(s) from hashcat file %s",
                len(creds),
                file_path,
            )
            return HashcatCrackingResult(credentials=creds, file_path=file_path)

        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error("Error extracting credentials from the hashcat output file.")
            print_exception(show_locals=False, exception=exc)
            logger.exception(
                "Failed to extract credentials from hashcat output file: %s",
                file_path,
            )
            return None


__all__ = [
    "HashcatCrackingService",
    "HashcatCrackingResult",
]


