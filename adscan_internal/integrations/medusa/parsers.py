"""Parsers for Medusa output."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Literal


_ACCOUNT_FOUND_RE = re.compile(
    r"ACCOUNT FOUND:\s+(?:\[(?P<protocol>[^\]]+)\]\s+)?"
    r"Host:\s+(?P<host>\S+)\s+"
    r"User:\s+(?P<username>\S+)\s+"
    r"Password:\s+(?P<password>.*?)\s+"
    r"\[(?P<status>[^\]]+)\]",
    re.IGNORECASE,
)

_MEDUSA_NEGATIVE_SUCCESS_MARKERS = (
    "ERRCONNECT_",
    "ACCESS DENIED",
    "LOGON_FAILURE",
    "AUTHENTICATION FAILED",
    "STATE_RUN_FAILED",
    "UNKNOWN_ERROR_CODE",
)

_MEDUSA_DENIED_MARKERS = (
    "ACCESS DENIED",
    "LOGON_FAILURE",
    "ERRCONNECT_LOGON_FAILURE",
    "ACCOUNT RESTRICTION",
    "ACCOUNT_DISABLED",
    "ACCOUNT LOCKED",
    "NOT AUTHORIZED",
    "AUTHORIZATION FAILED",
)

_MEDUSA_TRANSPORT_MARKERS = (
    "ERRCONNECT_CONNECT_",
    "TRANSPORT_FAILED",
    "CONNECTION_STATE",
    "STATE_RUN_FAILED",
    "TIMEOUT",
    "TLS",
    "CERTIFICATE",
    "NETWORK",
    "HOST UNREACHABLE",
    "CONNECTION RESET",
    "BROKEN PIPE",
)


@dataclass(frozen=True)
class MedusaAccountMatch:
    """One Medusa account result emitted through ACCOUNT FOUND."""

    protocol: str
    host: str
    username: str
    password: str
    status: str

    @property
    def is_success(self) -> bool:
        """Return True when Medusa reported a confirmed successful authentication."""
        normalized = self.status.strip().upper()
        if not normalized.startswith("SUCCESS"):
            return False
        return not any(marker in normalized for marker in _MEDUSA_NEGATIVE_SUCCESS_MARKERS)

    @property
    def result_category(self) -> Literal["confirmed", "denied", "transport", "ambiguous"]:
        """Classify the Medusa RDP result into a UX-friendly bucket."""
        if self.is_success:
            return "confirmed"

        normalized = self.status.strip().upper()
        if any(marker in normalized for marker in _MEDUSA_DENIED_MARKERS):
            return "denied"
        if any(marker in normalized for marker in _MEDUSA_TRANSPORT_MARKERS):
            return "transport"
        return "ambiguous"

    @property
    def result_reason(
        self,
    ) -> Literal[
        "confirmed",
        "rdp_denied",
        "logon_failure",
        "transport_failure",
        "backend_error",
    ]:
        """Return a more specific reason for UX and operator guidance."""
        if self.is_success:
            return "confirmed"

        normalized = self.status.strip().upper()
        if "ACCESS DENIED" in normalized:
            return "rdp_denied"
        if "LOGON_FAILURE" in normalized or "AUTHENTICATION FAILED" in normalized:
            return "logon_failure"
        if self.result_category == "transport":
            return "transport_failure"
        return "backend_error"


def parse_medusa_account_matches(
    output: str,
    *,
    protocol: str | None = None,
) -> list[MedusaAccountMatch]:
    """Parse Medusa account results from command output.

    The caller can decide whether to keep only successful entries or also inspect
    ambiguous/non-success statuses such as ``ERROR (...)``.
    """
    if not output:
        return []

    expected_protocol = str(protocol or "").strip().lower() or None
    matches: list[MedusaAccountMatch] = []
    seen: set[tuple[str, str, str]] = set()
    for match in _ACCOUNT_FOUND_RE.finditer(output):
        parsed_protocol = str(match.group("protocol") or "").strip().lower()
        if not parsed_protocol and expected_protocol:
            parsed_protocol = expected_protocol
        if expected_protocol and parsed_protocol != expected_protocol:
            continue
        host = str(match.group("host") or "").strip()
        username = str(match.group("username") or "").strip()
        password = str(match.group("password") or "").strip()
        key = (parsed_protocol, host.lower(), username.lower())
        if not host or not username or key in seen:
            continue
        seen.add(key)
        parsed_match = MedusaAccountMatch(
            protocol=parsed_protocol,
            host=host,
            username=username,
            password=password,
            status=str(match.group("status") or "").strip(),
        )
        matches.append(parsed_match)
    return matches
