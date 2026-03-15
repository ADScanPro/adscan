"""Shared exclusion policy for WinRM file discovery and sensitive-data analysis."""

from __future__ import annotations

from adscan_internal.services.smb_sensitive_file_policy import (
    SMB_SENSITIVE_SCAN_PHASE_DOCUMENT_CREDENTIALS,
    SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS,
)


WINRM_ROOT_STRATEGY_AUTO = "auto"

WINRM_GLOBAL_EXCLUDED_PATH_PREFIXES: tuple[str, ...] = (
    r"C:\Windows\WinSxS",
    r"C:\Windows\Installer",
    r"C:\Windows\SoftwareDistribution",
    r"C:\ProgramData\Package Cache",
)

WINRM_GLOBAL_EXCLUDED_DIRECTORY_NAMES: tuple[str, ...] = (
    "$Recycle.Bin",
    "System Volume Information",
)

WINRM_TEXT_PHASE_EXCLUDED_PATH_PREFIXES: tuple[str, ...] = (
    r"C:\Windows\Logs\DISM",
    r"C:\ProgramData\VMware\logs",
    r"C:\ProgramData\Microsoft\EdgeUpdate\Log",
    r"C:\Windows\System32\DiagTrack",
    r"C:\Windows\System32\wbem\Logs",
    r"C:\Windows\Performance\WinSAT",
    r"C:\Windows\SysWOW64\winrm",
    r"C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\cache",
    r"C:\Windows\System32\WindowsPowerShell\v1.0\Modules",
    r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\Modules",
    r"C:\Program Files\WindowsPowerShell\Modules",
    r"C:\Program Files (x86)\WindowsPowerShell\Modules",
)

WINRM_TEXT_PHASE_EXCLUDED_PATH_FRAGMENTS: tuple[str, ...] = (
    "\\test\\modules\\",
    "\\diagnostics\\simple\\",
)

WINRM_TEXT_PHASE_EXCLUDED_FILE_NAMES: tuple[str, ...] = (
    "dumpstack.log.tmp",
    "winrm.ini",
)

WINRM_DOCUMENT_PHASE_EXCLUDED_PATH_PREFIXES: tuple[str, ...] = (
    r"C:\Windows\Help",
    r"C:\Windows\System32\Licenses",
    r"C:\Windows\System32\oobe",
    r"C:\Windows\System32\MSDRM",
    r"C:\Windows\SysWOW64\Licenses",
)


def _normalize_winrm_path_prefixes(prefixes: tuple[str, ...]) -> tuple[str, ...]:
    """Normalize one tuple of absolute WinRM path prefixes for prefix matching."""
    normalized: list[str] = []
    for prefix in prefixes:
        value = str(prefix or "").strip().replace("/", "\\")
        if not value:
            continue
        normalized.append(value.rstrip("\\").lower() + "\\")
    return tuple(dict.fromkeys(normalized))


def _normalize_winrm_path_fragments(fragments: tuple[str, ...]) -> tuple[str, ...]:
    """Normalize one tuple of path fragments for substring matching."""
    normalized = [
        str(fragment or "").strip().replace("/", "\\").lower()
        for fragment in fragments
        if str(fragment or "").strip()
    ]
    return tuple(dict.fromkeys(normalized))


def _normalize_winrm_file_names(file_names: tuple[str, ...]) -> tuple[str, ...]:
    """Normalize one tuple of basenames for exact filename matching."""
    normalized = [
        str(file_name or "").strip().replace("/", "\\").lower()
        for file_name in file_names
        if str(file_name or "").strip()
    ]
    return tuple(dict.fromkeys(normalized))


def get_winrm_excluded_path_prefixes() -> tuple[str, ...]:
    """Return normalized absolute path prefixes excluded from WinRM discovery."""
    normalized: list[str] = []
    for prefix in WINRM_GLOBAL_EXCLUDED_PATH_PREFIXES:
        value = str(prefix or "").strip().replace("/", "\\")
        if not value:
            continue
        normalized.append(value.rstrip("\\").lower() + "\\")
    return tuple(dict.fromkeys(normalized))


def get_winrm_excluded_directory_names() -> tuple[str, ...]:
    """Return normalized directory names excluded from WinRM discovery."""
    normalized = [
        str(name or "").strip().lower()
        for name in WINRM_GLOBAL_EXCLUDED_DIRECTORY_NAMES
        if str(name or "").strip()
    ]
    return tuple(dict.fromkeys(normalized))


def get_winrm_phase_excluded_path_prefixes(phase: str) -> tuple[str, ...]:
    """Return normalized phase-specific path prefixes excluded from WinRM candidate sets."""
    normalized_phase = str(phase or "").strip().lower()
    if normalized_phase == SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS:
        return _normalize_winrm_path_prefixes(WINRM_TEXT_PHASE_EXCLUDED_PATH_PREFIXES)
    if normalized_phase == SMB_SENSITIVE_SCAN_PHASE_DOCUMENT_CREDENTIALS:
        return _normalize_winrm_path_prefixes(WINRM_DOCUMENT_PHASE_EXCLUDED_PATH_PREFIXES)
    return ()


def get_winrm_phase_excluded_path_fragments(phase: str) -> tuple[str, ...]:
    """Return normalized phase-specific path fragments excluded from WinRM candidate sets."""
    normalized_phase = str(phase or "").strip().lower()
    if normalized_phase == SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS:
        return _normalize_winrm_path_fragments(WINRM_TEXT_PHASE_EXCLUDED_PATH_FRAGMENTS)
    return ()


def get_winrm_phase_excluded_file_names(phase: str) -> tuple[str, ...]:
    """Return normalized phase-specific basenames excluded from WinRM candidate sets."""
    normalized_phase = str(phase or "").strip().lower()
    if normalized_phase == SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS:
        return _normalize_winrm_file_names(WINRM_TEXT_PHASE_EXCLUDED_FILE_NAMES)
    return ()


def classify_winrm_phase_exclusion_reason(path: str, phase: str) -> str | None:
    """Return the phase-specific exclusion reason for one WinRM path, if any."""
    normalized_path = str(path or "").strip().replace("/", "\\").lower()
    if not normalized_path:
        return None
    if not normalized_path.endswith("\\"):
        normalized_path_with_sep = normalized_path + "\\"
    else:
        normalized_path_with_sep = normalized_path
    for prefix in get_winrm_phase_excluded_path_prefixes(phase):
        trimmed_prefix = prefix.rstrip("\\")
        if normalized_path_with_sep.startswith(prefix) or normalized_path.startswith(trimmed_prefix):
            return f"path_prefix:{trimmed_prefix}"
    for fragment in get_winrm_phase_excluded_path_fragments(phase):
        if fragment in normalized_path:
            return f"path_fragment:{fragment}"
    file_name = normalized_path.rsplit("\\", 1)[-1]
    for excluded_name in get_winrm_phase_excluded_file_names(phase):
        if file_name == excluded_name:
            return f"file_name:{excluded_name}"
    return None


__all__ = [
    "classify_winrm_phase_exclusion_reason",
    "WINRM_GLOBAL_EXCLUDED_DIRECTORY_NAMES",
    "WINRM_GLOBAL_EXCLUDED_PATH_PREFIXES",
    "WINRM_DOCUMENT_PHASE_EXCLUDED_PATH_PREFIXES",
    "WINRM_ROOT_STRATEGY_AUTO",
    "WINRM_TEXT_PHASE_EXCLUDED_FILE_NAMES",
    "WINRM_TEXT_PHASE_EXCLUDED_PATH_FRAGMENTS",
    "WINRM_TEXT_PHASE_EXCLUDED_PATH_PREFIXES",
    "get_winrm_excluded_directory_names",
    "get_winrm_excluded_path_prefixes",
    "get_winrm_phase_excluded_file_names",
    "get_winrm_phase_excluded_path_fragments",
    "get_winrm_phase_excluded_path_prefixes",
]
