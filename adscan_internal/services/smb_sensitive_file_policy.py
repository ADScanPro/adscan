"""Shared file-selection policy for SMB sensitive-data hunting flows."""

from __future__ import annotations

from pathlib import Path
from typing import Final


TEXT_LIKE_CREDENTIAL_EXTENSIONS: tuple[str, ...] = (
    ".bat",
    ".cfg",
    ".cmd",
    ".conf",
    ".config",
    ".csv",
    ".env",
    ".ini",
    ".json",
    ".log",
    ".ps1",
    ".psd1",
    ".psm1",
    ".properties",
    ".reg",
    ".sh",
    ".sql",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
)

DOCUMENT_LIKE_CREDENTIAL_EXTENSIONS: tuple[str, ...] = (
    ".doc",
    ".docx",
    ".odt",
    ".pdf",
    ".ppt",
    ".pptx",
    ".rtf",
    ".xls",
    ".xlsm",
    ".xlsx",
)

DIRECT_SECRET_ARTIFACT_EXTENSIONS: tuple[str, ...] = (
    ".pfx",
    ".pem",
    ".key",
    ".rsa",
    ".pub",
    ".kdb",
    ".kdbx",
)

HEAVY_ARTIFACT_EXTENSIONS: tuple[str, ...] = (
    ".zip",
    ".dmp",
    ".pcap",
    ".vdi",
)

DOCUMENT_CREDENTIAL_MAX_FILESIZE_BYTES: Final[int] = 10 * 1024 * 1024

SENSITIVE_FILE_WRAPPER_EXTENSIONS: tuple[str, ...] = (
    ".bak",
    ".backup",
    ".old",
    ".orig",
    ".tmp",
    ".save",
)

SMB_SENSITIVE_FILE_PROFILE_TEXT_ONLY: Final[str] = "text_only"
SMB_SENSITIVE_FILE_PROFILE_DOCUMENTS_ONLY: Final[str] = "documents_only"
SMB_SENSITIVE_FILE_PROFILE_TEXT_AND_DOCUMENTS: Final[str] = "text_and_documents"
DEFAULT_SMB_SENSITIVE_FILE_PROFILE: Final[str] = SMB_SENSITIVE_FILE_PROFILE_TEXT_ONLY
SMB_SENSITIVE_BENCHMARK_SCOPE_TEXT_ONLY: Final[str] = "text_only"
SMB_SENSITIVE_BENCHMARK_SCOPE_BINARY_ONLY: Final[str] = "binary_only"
SMB_SENSITIVE_BENCHMARK_SCOPE_ALL_SUPPORTED: Final[str] = "all_supported"
SMB_SENSITIVE_BENCHMARK_SCOPE_DOCUMENTS_DEPTH_EXPERIMENTAL: Final[str] = (
    "documents_depth_experimental"
)

SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS: Final[str] = "text_credentials"
SMB_SENSITIVE_SCAN_PHASE_DIRECT_SECRET_ARTIFACTS: Final[str] = "direct_secret_artifacts"
SMB_SENSITIVE_SCAN_PHASE_DOCUMENT_CREDENTIALS: Final[str] = "document_credentials"
SMB_SENSITIVE_SCAN_PHASE_HEAVY_ARTIFACTS: Final[str] = "heavy_artifacts"

SMB_SENSITIVE_FILE_PROFILES: Final[
    dict[str, dict[str, tuple[str, ...]]]
] = {
    SMB_SENSITIVE_FILE_PROFILE_TEXT_ONLY: {
        "text_like": TEXT_LIKE_CREDENTIAL_EXTENSIONS,
        "document_like": (),
    },
    SMB_SENSITIVE_FILE_PROFILE_DOCUMENTS_ONLY: {
        "text_like": (),
        "document_like": DOCUMENT_LIKE_CREDENTIAL_EXTENSIONS,
    },
    SMB_SENSITIVE_FILE_PROFILE_TEXT_AND_DOCUMENTS: {
        "text_like": TEXT_LIKE_CREDENTIAL_EXTENSIONS,
        "document_like": DOCUMENT_LIKE_CREDENTIAL_EXTENSIONS,
    },
}

SMB_SENSITIVE_SCAN_PHASES: Final[
    dict[str, dict[str, object]]
] = {
    SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS: {
        "label": "Text credential scan",
        "description": "Fast pass over text-like files using CredSweeper.",
        "kind": "credentials",
        "profile": SMB_SENSITIVE_FILE_PROFILE_TEXT_ONLY,
    },
    SMB_SENSITIVE_SCAN_PHASE_DIRECT_SECRET_ARTIFACTS: {
        "label": "High-value artifact scan",
        "description": "Search for direct secret-bearing artifacts like PFX/KDBX.",
        "kind": "artifacts",
        "extensions": DIRECT_SECRET_ARTIFACT_EXTENSIONS,
    },
    SMB_SENSITIVE_SCAN_PHASE_DOCUMENT_CREDENTIALS: {
        "label": "Document credential scan",
        "description": "Search office/PDF-style files for embedded credentials.",
        "kind": "credentials",
        "profile": SMB_SENSITIVE_FILE_PROFILE_DOCUMENTS_ONLY,
    },
    SMB_SENSITIVE_SCAN_PHASE_HEAVY_ARTIFACTS: {
        "label": "Heavy artifact scan",
        "description": "Search ZIP/DMP/PCAP/VDI artifacts with deeper analysis.",
        "kind": "artifacts",
        "extensions": HEAVY_ARTIFACT_EXTENSIONS,
    },
}


def get_sensitive_file_profile(
    profile: str = DEFAULT_SMB_SENSITIVE_FILE_PROFILE,
) -> dict[str, tuple[str, ...]]:
    """Return extension groups for one supported sensitive-data profile."""
    normalized = str(profile or "").strip().lower() or DEFAULT_SMB_SENSITIVE_FILE_PROFILE
    selected = SMB_SENSITIVE_FILE_PROFILES.get(normalized)
    if selected is None:
        selected = SMB_SENSITIVE_FILE_PROFILES[DEFAULT_SMB_SENSITIVE_FILE_PROFILE]
    return {
        "text_like": tuple(selected.get("text_like", ())),
        "document_like": tuple(selected.get("document_like", ())),
    }


def get_sensitive_file_extensions(
    profile: str = DEFAULT_SMB_SENSITIVE_FILE_PROFILE,
) -> tuple[str, ...]:
    """Return merged unique suffixes for one sensitive-data profile."""
    profile_groups = get_sensitive_file_profile(profile)
    return tuple(
        dict.fromkeys(
            profile_groups["text_like"] + profile_groups["document_like"]
        )
    )


def get_manspider_sensitive_extensions(
    profile: str = DEFAULT_SMB_SENSITIVE_FILE_PROFILE,
) -> tuple[str, ...]:
    """Return merged unique extensions formatted for ``manspider -e``."""
    return tuple(
        extension.lstrip(".") for extension in get_sensitive_file_extensions(profile)
    )


def get_sensitive_phase_definition(phase: str) -> dict[str, object]:
    """Return metadata for one supported production SMB sensitive-data phase."""
    normalized = str(phase or "").strip().lower()
    selected = SMB_SENSITIVE_SCAN_PHASES.get(normalized)
    if selected is None:
        selected = SMB_SENSITIVE_SCAN_PHASES[SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS]
    return dict(selected)


def get_sensitive_phase_extensions(phase: str) -> tuple[str, ...]:
    """Return suffix list for one artifact or credential phase."""
    definition = get_sensitive_phase_definition(phase)
    profile = str(definition.get("profile", "") or "").strip().lower()
    if profile:
        return get_sensitive_file_extensions(profile)
    extensions = definition.get("extensions", ())
    if not isinstance(extensions, tuple):
        return ()
    return tuple(str(ext) for ext in extensions)


def get_sensitive_phase_max_file_size_bytes(phase: str) -> int | None:
    """Return an optional max file size budget for one sensitive-data phase."""
    normalized = str(phase or "").strip().lower()
    if normalized == SMB_SENSITIVE_SCAN_PHASE_DOCUMENT_CREDENTIALS:
        return DOCUMENT_CREDENTIAL_MAX_FILESIZE_BYTES
    return None


def get_manspider_phase_extensions(phase: str) -> tuple[str, ...]:
    """Return extension list formatted for ``manspider -e`` for one phase."""
    return tuple(ext.lstrip(".") for ext in get_sensitive_phase_extensions(phase))


def get_production_sensitive_scan_phase_sequence() -> tuple[str, ...]:
    """Return default ordered production phase sequence for SMB share analysis."""
    return (
        SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS,
        SMB_SENSITIVE_SCAN_PHASE_DIRECT_SECRET_ARTIFACTS,
        SMB_SENSITIVE_SCAN_PHASE_DOCUMENT_CREDENTIALS,
        SMB_SENSITIVE_SCAN_PHASE_HEAVY_ARTIFACTS,
    )


def resolve_effective_sensitive_extension(
    path: str,
    *,
    allowed_extensions: tuple[str, ...] | set[str] | None = None,
) -> str:
    """Resolve the meaningful extension for backup-like filenames.

    Examples:
        ``Groups.xml`` -> ``.xml``
        ``Groups.xml.bak`` -> ``.xml``
        ``vault.kdbx.old`` -> ``.kdbx``
        ``report.txt`` -> ``.txt``
    """
    suffixes = [suffix.casefold() for suffix in Path(str(path or "")).suffixes]
    if not suffixes:
        return ""
    normalized_allowed = {
        str(extension).strip().casefold()
        for extension in (allowed_extensions or ())
        if str(extension).strip()
    }
    for suffix in reversed(suffixes):
        if normalized_allowed and suffix in normalized_allowed:
            return suffix
        if suffix not in SENSITIVE_FILE_WRAPPER_EXTENSIONS:
            return suffix
    return suffixes[-1]


def get_sensitive_benchmark_profile(scope: str) -> str:
    """Map a benchmark scope into one shared CredSweeper profile."""
    normalized = str(scope or "").strip().lower()
    if normalized == SMB_SENSITIVE_BENCHMARK_SCOPE_BINARY_ONLY:
        return SMB_SENSITIVE_FILE_PROFILE_DOCUMENTS_ONLY
    if normalized == SMB_SENSITIVE_BENCHMARK_SCOPE_DOCUMENTS_DEPTH_EXPERIMENTAL:
        return SMB_SENSITIVE_FILE_PROFILE_DOCUMENTS_ONLY
    if normalized == SMB_SENSITIVE_BENCHMARK_SCOPE_ALL_SUPPORTED:
        return SMB_SENSITIVE_FILE_PROFILE_TEXT_AND_DOCUMENTS
    return SMB_SENSITIVE_FILE_PROFILE_TEXT_ONLY


__all__ = [
    "DEFAULT_SMB_SENSITIVE_FILE_PROFILE",
    "DIRECT_SECRET_ARTIFACT_EXTENSIONS",
    "DOCUMENT_CREDENTIAL_MAX_FILESIZE_BYTES",
    "DOCUMENT_LIKE_CREDENTIAL_EXTENSIONS",
    "HEAVY_ARTIFACT_EXTENSIONS",
    "SENSITIVE_FILE_WRAPPER_EXTENSIONS",
    "SMB_SENSITIVE_FILE_PROFILES",
    "SMB_SENSITIVE_FILE_PROFILE_DOCUMENTS_ONLY",
    "SMB_SENSITIVE_FILE_PROFILE_TEXT_AND_DOCUMENTS",
    "SMB_SENSITIVE_FILE_PROFILE_TEXT_ONLY",
    "SMB_SENSITIVE_BENCHMARK_SCOPE_ALL_SUPPORTED",
    "SMB_SENSITIVE_BENCHMARK_SCOPE_BINARY_ONLY",
    "SMB_SENSITIVE_BENCHMARK_SCOPE_DOCUMENTS_DEPTH_EXPERIMENTAL",
    "SMB_SENSITIVE_BENCHMARK_SCOPE_TEXT_ONLY",
    "SMB_SENSITIVE_SCAN_PHASE_DIRECT_SECRET_ARTIFACTS",
    "SMB_SENSITIVE_SCAN_PHASE_DOCUMENT_CREDENTIALS",
    "SMB_SENSITIVE_SCAN_PHASE_HEAVY_ARTIFACTS",
    "SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS",
    "SMB_SENSITIVE_SCAN_PHASES",
    "TEXT_LIKE_CREDENTIAL_EXTENSIONS",
    "get_manspider_phase_extensions",
    "get_manspider_sensitive_extensions",
    "get_sensitive_benchmark_profile",
    "get_production_sensitive_scan_phase_sequence",
    "resolve_effective_sensitive_extension",
    "get_sensitive_phase_definition",
    "get_sensitive_phase_extensions",
    "get_sensitive_phase_max_file_size_bytes",
    "get_sensitive_file_extensions",
    "get_sensitive_file_profile",
]
