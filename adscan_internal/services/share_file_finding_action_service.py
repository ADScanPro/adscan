"""Action handlers for deterministic credential findings."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable
import os

from adscan_internal import print_info, print_info_debug, print_warning
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.base_service import BaseService
from adscan_internal.services.share_file_analyzer_service import ShareFileAnalyzerFinding


AddCredentialCallback = Callable[[str, str, str], None]
File2JohnCallback = Callable[[str, object, str, str], None]
CPasswordCallback = Callable[
    [str, str, str, list[str] | None, list[str] | None, str | None], bool
]
CertipyCallback = Callable[[str, str], bool]
KeePassArtifactCallback = Callable[
    [str, str, list[str] | None, list[str] | None, str | None], int
]


@dataclass(frozen=True)
class ShareFileFindingActionStats:
    """Summary of actions applied from one finding batch."""

    total_findings: int
    applied_findings: int
    by_type: dict[str, int]


class ShareFileFindingActionService(BaseService):
    """Apply deterministic finding actions using injected CLI callbacks."""

    def __init__(
        self,
        *,
        add_credential_callback: AddCredentialCallback | None = None,
        file2john_callback: File2JohnCallback | None = None,
        cpassword_callback: CPasswordCallback | None = None,
        certipy_callback: CertipyCallback | None = None,
        keepass_artifact_callback: KeePassArtifactCallback | None = None,
    ) -> None:
        """Initialize callbacks used to apply deterministic findings."""
        super().__init__()
        self._add_credential_callback = add_credential_callback
        self._file2john_callback = file2john_callback
        self._cpassword_callback = cpassword_callback
        self._certipy_callback = certipy_callback
        self._keepass_artifact_callback = keepass_artifact_callback

    def apply_pfx_artifact(
        self,
        *,
        domain: str,
        source_path: str,
    ) -> bool:
        """Process a PFX artifact through Certipy/file2john callbacks."""
        if not self._certipy_callback:
            print_warning("No Certipy callback configured; skipping PFX processing.")
            return False
        success = self._certipy_callback(domain, source_path)
        if success:
            return True
        print_warning("PFX is password protected")
        if self._file2john_callback:
            filename = Path(source_path).name
            hash_file = f"domains/{domain}/smb/manspider/{filename}.hash"
            self._file2john_callback(domain, source_path, hash_file, "pfx")
        return False

    def apply_keepass_artifact(
        self,
        *,
        domain: str,
        source_path: str,
        source_hosts: list[str] | None = None,
        source_shares: list[str] | None = None,
        auth_username: str | None = None,
    ) -> int:
        """Process one KeePass artifact through the configured callback."""
        if not self._keepass_artifact_callback:
            print_warning("No KeePass callback configured; skipping KeePass artifact processing.")
            return 0
        return int(
            self._keepass_artifact_callback(
                domain,
                source_path,
                source_hosts,
                source_shares,
                auth_username,
            )
            or 0
        )

    def apply_findings(
        self,
        *,
        domain: str,
        source_path: str,
        findings: list[ShareFileAnalyzerFinding],
        xml_content: str | None = None,
        source_hosts: list[str] | None = None,
        source_shares: list[str] | None = None,
        auth_username: str | None = None,
    ) -> ShareFileFindingActionStats:
        """Apply deterministic findings grouped by credential type."""
        grouped = self._group_findings_by_type(findings)
        applied = 0

        ntlm_hashes = grouped.get("ntlm_hash", [])
        if ntlm_hashes:
            applied += self._apply_ntlm_hash_findings(
                domain=domain,
                source_path=source_path,
                findings=ntlm_hashes,
            )

        macro_passwords = grouped.get("macro_password", [])
        if macro_passwords:
            applied += self._apply_macro_password_findings(
                domain=domain,
                source_path=source_path,
                findings=macro_passwords,
            )

        ansible_vaults = grouped.get("ansible_vault", [])
        if ansible_vaults:
            applied += self._apply_ansible_vault_findings(
                domain=domain,
                source_path=source_path,
                findings=ansible_vaults,
            )

        cpasswords = grouped.get("cpassword", [])
        if cpasswords:
            applied += self._apply_cpassword_findings(
                domain=domain,
                source_path=source_path,
                findings=cpasswords,
                xml_content=xml_content,
                source_hosts=source_hosts,
                source_shares=source_shares,
                auth_username=auth_username,
            )

        return ShareFileFindingActionStats(
            total_findings=len(findings),
            applied_findings=applied,
            by_type={key: len(value) for key, value in grouped.items()},
        )

    @staticmethod
    def _group_findings_by_type(
        findings: list[ShareFileAnalyzerFinding],
    ) -> dict[str, list[ShareFileAnalyzerFinding]]:
        """Group findings by their credential_type field."""
        grouped: dict[str, list[ShareFileAnalyzerFinding]] = {}
        for finding in findings:
            ftype = str(getattr(finding, "credential_type", "") or "").strip().lower()
            if not ftype:
                continue
            grouped.setdefault(ftype, []).append(finding)
        return grouped

    def _apply_ntlm_hash_findings(
        self,
        *,
        domain: str,
        source_path: str,
        findings: list[ShareFileAnalyzerFinding],
    ) -> int:
        """Apply NTLM hash findings by storing credentials for later UX flows."""
        applied = 0
        for finding in findings:
            username = str(getattr(finding, "username", "") or "").strip()
            nt_hash = str(getattr(finding, "secret", "") or "").strip()
            if not username or not nt_hash:
                continue
            if self._add_credential_callback:
                self._add_credential_callback(domain, username, nt_hash)
            applied += 1
        if applied:
            print_info_debug(
                "Deterministic NTLM hash findings persisted: "
                f"path={mark_sensitive(source_path, 'path')} count={applied}"
            )
        return applied

    def _apply_macro_password_findings(
        self,
        *,
        domain: str,
        source_path: str,
        findings: list[ShareFileAnalyzerFinding],
    ) -> int:
        """Apply macro password findings from XLSM analysis."""
        marked_source_path = mark_sensitive(source_path, "path")
        print_warning(f"Possible credentials found in {marked_source_path}:")
        applied = 0
        for finding in findings:
            evidence = str(getattr(finding, "evidence", "") or "").strip()
            if evidence:
                print_info(f" - {evidence}")
            username = str(getattr(finding, "username", "") or "").strip()
            password = str(getattr(finding, "secret", "") or "").strip()
            if password:
                marked_password = mark_sensitive(password, "password")
                print_warning(f"Extracted password: {marked_password}")
            if username and username != "-":
                marked_username = mark_sensitive(username, "user")
                print_warning(f"Extracted username: {marked_username}")
            if (
                username
                and username != "-"
                and password
                and self._add_credential_callback is not None
            ):
                self._add_credential_callback(domain, username, password)
            if password:
                applied += 1
        return applied

    def _apply_ansible_vault_findings(
        self,
        *,
        domain: str,
        source_path: str,
        findings: list[ShareFileAnalyzerFinding],
    ) -> int:
        """Apply Ansible Vault findings by persisting blocks and calling file2john."""
        filename = Path(source_path).name
        print_warning(f"Found {len(findings)} Ansible Vault hashes in {filename}")
        vault_files: list[str] = []
        for idx, finding in enumerate(findings, start=1):
            vault_text = str(getattr(finding, "secret", "") or "").strip()
            if not vault_text:
                continue
            vault_file = f"domains/{domain}/smb/manspider/{filename}_vault_{idx}.txt"
            os.makedirs(os.path.dirname(vault_file), exist_ok=True)
            with open(vault_file, "w", encoding="utf-8") as vault_handle:
                vault_handle.write(vault_text)
            vault_files.append(vault_file)
        if vault_files and self._file2john_callback:
            hash_file = f"domains/{domain}/smb/manspider/{filename}.ansible.hash"
            self._file2john_callback(domain, vault_files, hash_file, "ansible")
        return len(vault_files)

    def _apply_cpassword_findings(
        self,
        *,
        domain: str,
        source_path: str,
        findings: list[ShareFileAnalyzerFinding],
        xml_content: str | None,
        source_hosts: list[str] | None,
        source_shares: list[str] | None,
        auth_username: str | None,
    ) -> int:
        """Apply cpassword findings by delegating to configured callback."""
        if not findings:
            print_warning("No cpasswords found")
            return 0
        if not self._cpassword_callback:
            print_warning("No cpassword callback configured; skipping GPP XML processing.")
            return 0
        if not xml_content:
            print_warning(
                "cpassword findings detected but XML content is unavailable for callback processing."
            )
            return 0
        filename = Path(source_path).name
        processed = self._cpassword_callback(
            xml_content,
            domain,
            filename,
            source_hosts,
            source_shares,
            auth_username,
        )
        if not processed:
            print_warning("No cpasswords found")
            return 0
        return len(findings)
