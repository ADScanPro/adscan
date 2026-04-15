"""Shared UX/policy helpers for Windows sensitive filesystem scans."""

from __future__ import annotations

from typing import Any

from rich.prompt import Confirm

from adscan_internal import print_info_debug
from adscan_internal.rich_output import mark_sensitive


class WindowsSensitiveScanPolicyService:
    """Resolve shared scan mode and continuation prompts across transports."""

    def select_analysis_mode(
        self,
        *,
        shell: Any,
        ai_configured: bool,
        workflow_label: str,
    ) -> str:
        """Select one sensitive-data analysis mode for a Windows workflow."""
        selector = getattr(shell, "_questionary_select", None)
        if not ai_configured:
            options = [
                "Deterministic file analysis",
                "Skip sensitive-data analysis",
            ]
            if callable(selector):
                idx = selector(
                    f"Select {workflow_label} sensitive-data analysis mode:",
                    options,
                    default_idx=0,
                )
                return "skip" if int(idx or 0) == 1 else "deterministic"
            return "deterministic"

        options = [
            "Deterministic file analysis",
            "AI-assisted file analysis",
            "Skip sensitive-data analysis",
        ]
        if callable(selector):
            idx = int(
                selector(
                    f"Select {workflow_label} sensitive-data analysis mode:",
                    options,
                    default_idx=0,
                )
                or 0
            )
            if idx == 1:
                return "ai"
            if idx == 2:
                return "skip"
        return "deterministic"

    def should_continue_with_deeper_scan(
        self,
        *,
        shell: Any,
        domain: str,
        phase_result: dict[str, Any],
        workflow_label: str,
        skip_for_pwned_ctf: bool,
    ) -> bool:
        """Ask whether deeper deterministic analysis should continue."""
        if skip_for_pwned_ctf:
            print_info_debug(
                f"Skipping deeper deterministic {workflow_label} prompt because the CTF "
                f"domain is already pwned: domain={mark_sensitive(domain, 'domain')}"
            )
            return False
        credential_findings = int(phase_result.get("credential_findings", 0) or 0)
        files_with_findings = int(phase_result.get("files_with_findings", 0) or 0)
        if credential_findings > 0 or files_with_findings > 0:
            prompt = (
                f"{workflow_label} text-file credential findings were identified. "
                "Continue with deeper analysis for additional artifacts and "
                "document-based secrets?"
            )
        else:
            prompt = (
                f"No credential-like findings were identified in {workflow_label} text files. "
                "Continue with deeper analysis on high-value artifacts and document "
                "formats? This will take longer."
            )
        confirmer = getattr(shell, "_questionary_confirm", None)
        if callable(confirmer):
            return bool(confirmer(prompt, default=True))
        return Confirm.ask(prompt, default=True)

    def should_continue_with_heavy_artifacts(
        self,
        *,
        shell: Any,
        domain: str,
        workflow_label: str,
        skip_for_pwned_ctf: bool,
    ) -> bool:
        """Ask whether the heaviest artifact phase should run."""
        if skip_for_pwned_ctf:
            print_info_debug(
                f"Skipping heavy-artifact deterministic {workflow_label} prompt because "
                f"the CTF domain is already pwned: domain={mark_sensitive(domain, 'domain')}"
            )
            return False
        prompt = (
            f"Do you want to continue with heavy {workflow_label} artifact analysis "
            "(ZIP/DMP/PCAP/VDI)? This is slower and more resource-intensive."
        )
        confirmer = getattr(shell, "_questionary_confirm", None)
        if callable(confirmer):
            return bool(confirmer(prompt, default=True))
        return Confirm.ask(prompt, default=True)

    def select_ai_triage_scope(self, *, shell: Any) -> str | None:
        """Select one AI triage scope after filesystem mapping."""
        pentest_type = str(getattr(shell, "type", "") or "").strip().lower()
        if pentest_type == "ctf":
            return "credentials"

        options = [
            "Credentials only (default)",
            "Sensitive data only",
            "Credentials + sensitive data",
            "Skip AI triage",
        ]
        selector = getattr(shell, "_questionary_select", None)
        if not callable(selector):
            return "credentials"
        selected_idx = selector("AI triage scope:", options, default_idx=0)
        if selected_idx is None:
            return "credentials"
        if selected_idx == 1:
            return "sensitive_data"
        if selected_idx == 2:
            return "both"
        if selected_idx == 3:
            return None
        return "credentials"

    def should_inspect_ai_prioritized_files(
        self,
        *,
        shell: Any,
        workflow_label: str,
    ) -> bool:
        """Ask whether AI should inspect the prioritized files it selected."""
        prompt = f"Do you want AI to inspect these prioritized {workflow_label} files?"
        confirmer = getattr(shell, "_questionary_confirm", None)
        if callable(confirmer):
            return bool(confirmer(prompt, default=True))
        return Confirm.ask(prompt, default=True)

    def should_continue_after_ai_findings(
        self,
        *,
        shell: Any,
        domain: str,
        workflow_label: str,
        skip_for_pwned_ctf: bool,
    ) -> bool:
        """Ask whether prioritized AI analysis should continue after findings."""
        if skip_for_pwned_ctf:
            print_info_debug(
                f"Skipping {workflow_label} AI continue-after-findings prompt because the CTF "
                f"domain is already pwned: domain={mark_sensitive(domain, 'domain')}"
            )
            return False
        run_type = str(getattr(shell, "type", "") or "").strip().lower()
        default_continue = run_type != "ctf"
        prompt = (
            "Credential-like findings detected. Continue analyzing remaining prioritized files?"
        )
        confirmer = getattr(shell, "_questionary_confirm", None)
        if callable(confirmer):
            return bool(confirmer(prompt, default=default_continue))
        return Confirm.ask(prompt, default=default_continue)


__all__ = ["WindowsSensitiveScanPolicyService"]
