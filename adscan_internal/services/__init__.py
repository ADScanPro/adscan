"""Service layer for ADScan business logic.

This package contains services that encapsulate domain operations,
credential verification, enumeration, exploitation, and orchestration.

Services can be used:
- In CLI mode (via PentestShell delegation)
- In Web mode (via FastAPI backend)

All services emit events for progress tracking and real-time updates.
"""

from .base_service import BaseService
from .domain_service import DomainService, TrustRelationship
from .credential_service import (
    CredentialService,
    CredentialStatus,
    CredentialVerificationResult,
    PasswordChangeResult,
    RoastingResult,
)
from .enumeration import (
    EnumerationService,
    SMBSession,
    LDAPUser,
    LDAPGroup,
    KerberosTicketArtifact,
    NetworkServiceFinding,
)
from .enumeration.rid_cycling import RIDCyclingService, RIDCyclingResult
from .bloodhound_service import BloodHoundService, BloodHoundServiceError
from .dns_discovery_service import DNSDiscoveryRuntime, DNSDiscoveryService
from .dns_resolver_service import DNSResolverService, DNSResolverRuntime
from .exploitation import ExploitationService
from .scan_orchestration import ScanOrchestrationService
from .kerberos_ticket_service import KerberosTicketService, KerberosTGTResult
from .certipy_service import CertipyService, PassTheCertificateResult
from .credsweeper_service import (
    CredSweeperService,
    CredSweeperFinding,
    get_credsweeper_rules_paths,
)
from .credsweeper_library_service import (
    CredSweeperLibraryService,
    InMemoryCredSweeperTarget,
)
from .spidering_service import SpideringService
from .credential_store_service import (
    CredentialStoreService,
    DomainCredentialUpdateResult,
    LocalCredentialUpdateResult,
)
from .share_mapping_service import ShareMappingService
from .cifs_share_mapping_service import CIFSShareMappingService
from .cifs_credsweeper_scan_service import (
    CIFSCredSweeperScanResult,
    CIFSCredSweeperScanService,
)
from .rclone_share_mapping_service import RcloneShareMappingService
from .rclone_tuning_service import (
    RcloneCatTuning,
    RcloneTuning,
    choose_rclone_cat_tuning,
    choose_rclone_tuning,
)
from .artifact_processing_tuning_service import (
    ArtifactProcessingTuning,
    choose_artifact_processing_tuning,
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
from .winrm_exclusion_policy import (
    WINRM_GLOBAL_EXCLUDED_DIRECTORY_NAMES,
    WINRM_GLOBAL_EXCLUDED_PATH_PREFIXES,
    WINRM_ROOT_STRATEGY_AUTO,
    get_winrm_excluded_directory_names,
    get_winrm_excluded_path_prefixes,
)
from .winrm_file_mapping_service import (
    WinRMFileMapEntry,
    WinRMFileMappingService,
)
from .winrm_backend_service import WinRMExecutionBackend, build_winrm_backend
from .winrm_psrp_service import WinRMPSRPError, WinRMPSRPExecutionResult, WinRMPSRPService
from .share_map_ai_triage_service import ShareMapAITriageService
from .impacket_smb_byte_reader_service import (
    ImpacketSMBByteReaderService,
    SMBByteReadResult,
)
from .file_byte_reader_service import (
    FileByteReadResult,
    LocalFileByteReaderService,
    SMBFileByteReaderService,
)
from .share_file_content_extraction_service import (
    ShareFileContentExtractionService,
    ShareFileContentExtractionResult,
)
from .zip_processing_service import ZipProcessingService, ZipInspectionResult, ZipAIExtractionResult
from .share_file_analyzer_service import (
    ShareFileAnalyzerService,
    ShareFileAnalyzerResult,
    ShareFileAnalyzerFinding,
)
from .share_file_finding_action_service import (
    ShareFileFindingActionService,
    ShareFileFindingActionStats,
)
from .share_file_analysis_pipeline_service import (
    ShareFileAnalysisPipelineService,
    ShareFilePipelineAnalysisResult,
)
from .share_credential_provenance_service import ShareCredentialProvenanceService
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

__all__ = [
    "BaseService",
    "DomainService",
    "TrustRelationship",
    "CredentialService",
    "CredentialStatus",
    "CredentialVerificationResult",
    "PasswordChangeResult",
    "RoastingResult",
    "EnumerationService",
    "SMBSession",
    "LDAPUser",
    "LDAPGroup",
    "KerberosTicketArtifact",
    "NetworkServiceFinding",
    "RIDCyclingService",
    "RIDCyclingResult",
    "BloodHoundService",
    "BloodHoundServiceError",
    "DNSDiscoveryRuntime",
    "DNSDiscoveryService",
    "DNSResolverService",
    "DNSResolverRuntime",
    "ExploitationService",
    "ScanOrchestrationService",
    "KerberosTicketService",
    "KerberosTGTResult",
    "CertipyService",
    "PassTheCertificateResult",
    "CredSweeperService",
    "CredSweeperFinding",
    "CredSweeperLibraryService",
    "InMemoryCredSweeperTarget",
    "get_credsweeper_rules_paths",
    "SpideringService",
    "CredentialStoreService",
    "DomainCredentialUpdateResult",
    "LocalCredentialUpdateResult",
    "ShareMappingService",
    "CIFSShareMappingService",
    "CIFSCredSweeperScanResult",
    "CIFSCredSweeperScanService",
    "RcloneShareMappingService",
    "RcloneCatTuning",
    "RcloneTuning",
    "choose_rclone_cat_tuning",
    "choose_rclone_tuning",
    "ArtifactProcessingTuning",
    "choose_artifact_processing_tuning",
    "JohnArtifactCrackingResult",
    "JohnArtifactCrackingService",
    "KeePassArtifactProcessResult",
    "KeePassArtifactService",
    "KeePassEntryRecord",
    "WINRM_GLOBAL_EXCLUDED_DIRECTORY_NAMES",
    "WINRM_GLOBAL_EXCLUDED_PATH_PREFIXES",
    "WINRM_ROOT_STRATEGY_AUTO",
    "WinRMFileMapEntry",
    "WinRMFileMappingService",
    "WinRMExecutionBackend",
    "build_winrm_backend",
    "get_winrm_excluded_directory_names",
    "get_winrm_excluded_path_prefixes",
    "WinRMPSRPError",
    "WinRMPSRPExecutionResult",
    "WinRMPSRPService",
    "ShareMapAITriageService",
    "ImpacketSMBByteReaderService",
    "SMBByteReadResult",
    "FileByteReadResult",
    "LocalFileByteReaderService",
    "SMBFileByteReaderService",
    "ShareFileContentExtractionService",
    "ShareFileContentExtractionResult",
    "ZipProcessingService",
    "ZipInspectionResult",
    "ZipAIExtractionResult",
    "ShareFileAnalyzerService",
    "ShareFileAnalyzerResult",
    "ShareFileAnalyzerFinding",
    "ShareFileFindingActionService",
    "ShareFileFindingActionStats",
    "ShareFileAnalysisPipelineService",
    "ShareFilePipelineAnalysisResult",
    "ShareCredentialProvenanceService",
    "DEFAULT_SMB_GUEST_USERNAME",
    "is_guest_alias",
    "resolve_smb_guest_username",
    "DEFAULT_SMB_SENSITIVE_FILE_PROFILE",
    "DOCUMENT_LIKE_CREDENTIAL_EXTENSIONS",
    "SMB_SENSITIVE_FILE_PROFILES",
    "SMB_SENSITIVE_FILE_PROFILE_DOCUMENTS_ONLY",
    "SMB_SENSITIVE_FILE_PROFILE_TEXT_AND_DOCUMENTS",
    "SMB_SENSITIVE_FILE_PROFILE_TEXT_ONLY",
    "TEXT_LIKE_CREDENTIAL_EXTENSIONS",
    "get_manspider_sensitive_extensions",
    "get_sensitive_file_extensions",
    "get_sensitive_file_profile",
]
