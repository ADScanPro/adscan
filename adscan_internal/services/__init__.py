"""Service layer for ADScan business logic.

This package is shared by the CLI and the web backend. Keep import-time side
effects to a minimum so lightweight consumers can reuse pure helpers such as
``attack_graph_core`` without pulling optional runtime stacks (DNS/WinRM/etc.).
"""
# ruff: noqa: F401

from __future__ import annotations

import importlib
import sys
from typing import TYPE_CHECKING, Any

_STATIC_ANALYSIS = TYPE_CHECKING or "pylint" in sys.modules

if _STATIC_ANALYSIS:
    from .artifact_processing_tuning_service import (
        ArtifactProcessingTuning,
        choose_artifact_processing_tuning,
    )
    from .base_service import BaseService
    from .bloodhound_service import BloodHoundService, BloodHoundServiceError
    from .certipy_service import CertipyService, PassTheCertificateResult
    from .cifs_credsweeper_scan_service import (
        CIFSCredSweeperScanResult,
        CIFSCredSweeperScanService,
    )
    from .cifs_share_mapping_service import CIFSShareMappingService
    from .credential_service import (
        CredentialService,
        CredentialStatus,
        CredentialVerificationResult,
        PasswordChangeResult,
        RoastingResult,
    )
    from .credential_store_service import (
        CredentialStoreService,
        DomainCredentialUpdateResult,
        LocalCredentialUpdateResult,
    )
    from .credsweeper_library_service import (
        CredSweeperLibraryService,
        InMemoryCredSweeperTarget,
    )
    from .credsweeper_service import (
        CredSweeperFinding,
        CredSweeperService,
        get_credsweeper_rules_paths,
    )
    from .dns_discovery_service import DNSDiscoveryRuntime, DNSDiscoveryService
    from .dns_resolver_service import DNSResolverRuntime, DNSResolverService
    from .domain_service import DomainService, TrustRelationship
    from .enumeration import (
        EnumerationService,
        KerberosTicketArtifact,
        LDAPGroup,
        LDAPUser,
        NetworkServiceFinding,
        SMBSession,
    )
    from .enumeration.rid_cycling import RIDCyclingResult, RIDCyclingService
    from .exploitation import ExploitationService
    from .file_byte_reader_service import (
        FileByteReadResult,
        LocalFileByteReaderService,
        SMBFileByteReaderService,
    )
    from .impacket_smb_byte_reader_service import (
        ImpacketSMBByteReaderService,
        SMBByteReadResult,
    )
    from .john_artifact_cracking_service import (
        JohnArtifactCrackingResult,
        JohnArtifactCrackingService,
    )
    from .keepass_artifact_service import (
        KeePassArtifactProcessResult,
        KeePassArtifactService,
        KeePassEntryRecord,
    )
    from .kerberos_ticket_service import KerberosTGTResult, KerberosTicketService
    from .ligolo_service import LigoloProxyService
    from .pivot_service import (
        PivotReachableSubnetSummary,
        build_ligolo_agent_keepalive_script,
        build_ligolo_agent_start_script,
        orchestrate_ligolo_pivot_tunnel,
        probe_ligolo_routed_targets,
        summarize_confirmed_pivot_subnets,
    )
    from .rclone_share_mapping_service import RcloneShareMappingService
    from .rclone_tuning_service import (
        RcloneCatTuning,
        RcloneTuning,
        choose_rclone_cat_tuning,
        choose_rclone_tuning,
    )
    from .scan_orchestration import ScanOrchestrationService
    from .share_credential_provenance_service import ShareCredentialProvenanceService
    from .share_file_analysis_pipeline_service import (
        ShareFileAnalysisPipelineService,
        ShareFilePipelineAnalysisResult,
    )
    from .share_file_analyzer_service import (
        ShareFileAnalyzerFinding,
        ShareFileAnalyzerResult,
        ShareFileAnalyzerService,
    )
    from .share_file_content_extraction_service import (
        ShareFileContentExtractionResult,
        ShareFileContentExtractionService,
    )
    from .share_file_finding_action_service import (
        ShareFileFindingActionService,
        ShareFileFindingActionStats,
    )
    from .share_map_ai_triage_service import ShareMapAITriageService
    from .share_mapping_service import ShareMappingService
    from .smb_guest_auth_service import (
        DEFAULT_SMB_GUEST_USERNAME,
        is_guest_alias,
        resolve_smb_guest_username,
    )
    from .smb_sensitive_file_policy import (
        DEFAULT_SMB_SENSITIVE_FILE_PROFILE,
        DOCUMENT_LIKE_CREDENTIAL_EXTENSIONS,
        SMB_SENSITIVE_FILE_PROFILES,
        SMB_SENSITIVE_FILE_PROFILE_DOCUMENTS_ONLY,
        SMB_SENSITIVE_FILE_PROFILE_TEXT_AND_DOCUMENTS,
        SMB_SENSITIVE_FILE_PROFILE_TEXT_ONLY,
        TEXT_LIKE_CREDENTIAL_EXTENSIONS,
        get_manspider_sensitive_extensions,
        get_sensitive_file_extensions,
        get_sensitive_file_profile,
    )
    from .spidering_service import SpideringService
    from .winrm_backend_service import WinRMExecutionBackend, build_winrm_backend
    from .winrm_exclusion_policy import (
        WINRM_GLOBAL_EXCLUDED_DIRECTORY_NAMES,
        WINRM_GLOBAL_EXCLUDED_PATH_PREFIXES,
        WINRM_ROOT_STRATEGY_AUTO,
        get_winrm_excluded_directory_names,
        get_winrm_excluded_path_prefixes,
    )
    from .winrm_file_mapping_service import WinRMFileMapEntry, WinRMFileMappingService
    from .winrm_logon_bypass_service import WinRMLogonBypassService
    from .winrm_psrp_service import (
        WinRMPSRPError,
        WinRMPSRPExecutionResult,
        WinRMPSRPService,
    )
    from .zip_processing_service import (
        ZipAIExtractionResult,
        ZipInspectionResult,
        ZipProcessingService,
    )


_EXPORT_MODULES: dict[str, str] = {
    "BaseService": ".base_service",
    "DomainService": ".domain_service",
    "TrustRelationship": ".domain_service",
    "CredentialService": ".credential_service",
    "CredentialStatus": ".credential_service",
    "CredentialVerificationResult": ".credential_service",
    "PasswordChangeResult": ".credential_service",
    "RoastingResult": ".credential_service",
    "EnumerationService": ".enumeration",
    "SMBSession": ".enumeration",
    "LDAPUser": ".enumeration",
    "LDAPGroup": ".enumeration",
    "KerberosTicketArtifact": ".enumeration",
    "NetworkServiceFinding": ".enumeration",
    "RIDCyclingService": ".enumeration.rid_cycling",
    "RIDCyclingResult": ".enumeration.rid_cycling",
    "BloodHoundService": ".bloodhound_service",
    "BloodHoundServiceError": ".bloodhound_service",
    "DNSDiscoveryRuntime": ".dns_discovery_service",
    "DNSDiscoveryService": ".dns_discovery_service",
    "DNSResolverService": ".dns_resolver_service",
    "DNSResolverRuntime": ".dns_resolver_service",
    "ExploitationService": ".exploitation",
    "ScanOrchestrationService": ".scan_orchestration",
    "KerberosTicketService": ".kerberos_ticket_service",
    "KerberosTGTResult": ".kerberos_ticket_service",
    "CertipyService": ".certipy_service",
    "PassTheCertificateResult": ".certipy_service",
    "CredSweeperService": ".credsweeper_service",
    "CredSweeperFinding": ".credsweeper_service",
    "get_credsweeper_rules_paths": ".credsweeper_service",
    "CredSweeperLibraryService": ".credsweeper_library_service",
    "InMemoryCredSweeperTarget": ".credsweeper_library_service",
    "SpideringService": ".spidering_service",
    "CredentialStoreService": ".credential_store_service",
    "DomainCredentialUpdateResult": ".credential_store_service",
    "LocalCredentialUpdateResult": ".credential_store_service",
    "ShareMappingService": ".share_mapping_service",
    "CIFSShareMappingService": ".cifs_share_mapping_service",
    "CIFSCredSweeperScanResult": ".cifs_credsweeper_scan_service",
    "CIFSCredSweeperScanService": ".cifs_credsweeper_scan_service",
    "RcloneShareMappingService": ".rclone_share_mapping_service",
    "RcloneCatTuning": ".rclone_tuning_service",
    "RcloneTuning": ".rclone_tuning_service",
    "choose_rclone_cat_tuning": ".rclone_tuning_service",
    "choose_rclone_tuning": ".rclone_tuning_service",
    "ArtifactProcessingTuning": ".artifact_processing_tuning_service",
    "choose_artifact_processing_tuning": ".artifact_processing_tuning_service",
    "JohnArtifactCrackingResult": ".john_artifact_cracking_service",
    "JohnArtifactCrackingService": ".john_artifact_cracking_service",
    "KeePassArtifactProcessResult": ".keepass_artifact_service",
    "KeePassArtifactService": ".keepass_artifact_service",
    "KeePassEntryRecord": ".keepass_artifact_service",
    "WINRM_GLOBAL_EXCLUDED_DIRECTORY_NAMES": ".winrm_exclusion_policy",
    "WINRM_GLOBAL_EXCLUDED_PATH_PREFIXES": ".winrm_exclusion_policy",
    "WINRM_ROOT_STRATEGY_AUTO": ".winrm_exclusion_policy",
    "get_winrm_excluded_directory_names": ".winrm_exclusion_policy",
    "get_winrm_excluded_path_prefixes": ".winrm_exclusion_policy",
    "WinRMFileMapEntry": ".winrm_file_mapping_service",
    "WinRMFileMappingService": ".winrm_file_mapping_service",
    "WinRMExecutionBackend": ".winrm_backend_service",
    "build_winrm_backend": ".winrm_backend_service",
    "WinRMLogonBypassService": ".winrm_logon_bypass_service",
    "WinRMPSRPError": ".winrm_psrp_service",
    "WinRMPSRPExecutionResult": ".winrm_psrp_service",
    "WinRMPSRPService": ".winrm_psrp_service",
    "LigoloProxyService": ".ligolo_service",
    "PivotReachableSubnetSummary": ".pivot_service",
    "build_ligolo_agent_keepalive_script": ".pivot_service",
    "build_ligolo_agent_start_script": ".pivot_service",
    "orchestrate_ligolo_pivot_tunnel": ".pivot_service",
    "probe_ligolo_routed_targets": ".pivot_service",
    "summarize_confirmed_pivot_subnets": ".pivot_service",
    "ShareMapAITriageService": ".share_map_ai_triage_service",
    "ImpacketSMBByteReaderService": ".impacket_smb_byte_reader_service",
    "SMBByteReadResult": ".impacket_smb_byte_reader_service",
    "FileByteReadResult": ".file_byte_reader_service",
    "LocalFileByteReaderService": ".file_byte_reader_service",
    "SMBFileByteReaderService": ".file_byte_reader_service",
    "ShareFileContentExtractionService": ".share_file_content_extraction_service",
    "ShareFileContentExtractionResult": ".share_file_content_extraction_service",
    "ZipProcessingService": ".zip_processing_service",
    "ZipInspectionResult": ".zip_processing_service",
    "ZipAIExtractionResult": ".zip_processing_service",
    "ShareFileAnalyzerService": ".share_file_analyzer_service",
    "ShareFileAnalyzerResult": ".share_file_analyzer_service",
    "ShareFileAnalyzerFinding": ".share_file_analyzer_service",
    "ShareFileFindingActionService": ".share_file_finding_action_service",
    "ShareFileFindingActionStats": ".share_file_finding_action_service",
    "ShareFileAnalysisPipelineService": ".share_file_analysis_pipeline_service",
    "ShareFilePipelineAnalysisResult": ".share_file_analysis_pipeline_service",
    "ShareCredentialProvenanceService": ".share_credential_provenance_service",
    "DEFAULT_SMB_GUEST_USERNAME": ".smb_guest_auth_service",
    "is_guest_alias": ".smb_guest_auth_service",
    "resolve_smb_guest_username": ".smb_guest_auth_service",
    "DEFAULT_SMB_SENSITIVE_FILE_PROFILE": ".smb_sensitive_file_policy",
    "DOCUMENT_LIKE_CREDENTIAL_EXTENSIONS": ".smb_sensitive_file_policy",
    "SMB_SENSITIVE_FILE_PROFILES": ".smb_sensitive_file_policy",
    "SMB_SENSITIVE_FILE_PROFILE_DOCUMENTS_ONLY": ".smb_sensitive_file_policy",
    "SMB_SENSITIVE_FILE_PROFILE_TEXT_AND_DOCUMENTS": ".smb_sensitive_file_policy",
    "SMB_SENSITIVE_FILE_PROFILE_TEXT_ONLY": ".smb_sensitive_file_policy",
    "TEXT_LIKE_CREDENTIAL_EXTENSIONS": ".smb_sensitive_file_policy",
    "get_manspider_sensitive_extensions": ".smb_sensitive_file_policy",
    "get_sensitive_file_extensions": ".smb_sensitive_file_policy",
    "get_sensitive_file_profile": ".smb_sensitive_file_policy",
}

__all__ = list(_EXPORT_MODULES)


def __getattr__(name: str) -> Any:
    """Resolve service exports lazily to keep import boundaries modular."""
    module_name = _EXPORT_MODULES.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = importlib.import_module(module_name, __name__)
    value = getattr(module, name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Return a stable module dir for interactive discovery."""
    return sorted(set(globals()) | set(__all__))
