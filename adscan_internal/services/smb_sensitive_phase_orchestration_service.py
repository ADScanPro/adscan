"""Shared SMB deterministic phase orchestration helpers.

This service keeps prompt/phase sequencing logic out of ``adscan_internal.cli.smb``
while leaving acquisition and backend execution inside the CLI module.
"""

from __future__ import annotations

from typing import Any, Callable

from rich.prompt import Confirm

from adscan_internal import print_info_debug, print_warning_debug, telemetry
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.smb_sensitive_file_policy import (
    SMB_SENSITIVE_SCAN_PHASE_DIRECT_SECRET_ARTIFACTS,
    SMB_SENSITIVE_SCAN_PHASE_DOCUMENT_CREDENTIALS,
    SMB_SENSITIVE_SCAN_PHASE_HEAVY_ARTIFACTS,
    SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS,
)


def should_skip_sensitive_scan_prompt_for_ctf_pwned(*, shell: Any, domain: str) -> bool:
    """Return ``True`` when SMB follow-up prompts should be skipped for pwned CTF domains."""
    checker = getattr(shell, "_is_ctf_domain_pwned", None)
    if callable(checker):
        try:
            if bool(checker(domain)):
                return True
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning_debug(
                "CTF pwned-domain check failed during SMB prompt gating; "
                f"falling back to domain auth state. error={type(exc).__name__}: {exc}"
            )
    workspace_type = str(getattr(shell, "type", "") or "").strip().lower()
    domain_auth = str(
        getattr(shell, "domains_data", {}).get(domain, {}).get("auth", "") or ""
    ).strip().lower()
    return workspace_type == "ctf" and domain_auth == "pwned"


def should_continue_with_deeper_sensitive_scan(
    *,
    shell: Any,
    domain: str,
    phase_result: dict[str, Any],
) -> bool:
    """Ask whether deeper deterministic SMB analysis should continue."""
    if should_skip_sensitive_scan_prompt_for_ctf_pwned(shell=shell, domain=domain):
        print_info_debug(
            "Skipping deeper deterministic SMB prompt because the CTF domain is "
            f"already pwned: domain={mark_sensitive(domain, 'domain')}"
        )
        return False
    credential_findings = int(phase_result.get("credential_findings", 0) or 0)
    files_with_findings = int(phase_result.get("files_with_findings", 0) or 0)
    if credential_findings > 0 or files_with_findings > 0:
        prompt = (
            "Text-file credential findings were identified. Continue with deeper "
            "analysis for additional artifacts and document-based secrets?"
        )
    else:
        prompt = (
            "No credential-like findings were identified in text files. Continue "
            "with deeper analysis on high-value artifacts and document formats? "
            "This will take longer."
        )
    confirmer = getattr(shell, "_questionary_confirm", None)
    if callable(confirmer):
        response = confirmer(prompt, default=True)
        return bool(response)
    return Confirm.ask(prompt, default=True)


def should_run_credential_phase(
    *,
    shell: Any,
    domain: str,
    phase: str,
    prior_phase_result: dict[str, Any] | None,
) -> bool:
    """Ask whether one credential-oriented SMB phase should run."""
    if should_skip_sensitive_scan_prompt_for_ctf_pwned(shell=shell, domain=domain):
        print_info_debug(
            "Skipping SMB credential phase prompt because the CTF domain is "
            f"already pwned: domain={mark_sensitive(domain, 'domain')} "
            f"phase={mark_sensitive(phase, 'text')}"
        )
        return False
    if getattr(shell, "auto", False):
        return True
    if phase == SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS:
        prompt = (
            "Do you want to search for credentials in text-like share files first? "
            "You can skip this phase and continue directly to document-based secrets."
        )
    else:
        credential_findings = int((prior_phase_result or {}).get("credential_findings", 0) or 0)
        files_with_findings = int((prior_phase_result or {}).get("files_with_findings", 0) or 0)
        if credential_findings > 0 or files_with_findings > 0:
            prompt = (
                "Text-file credential findings were identified. Do you want to continue "
                "with document-based credential analysis and high-value artifact review?"
            )
        else:
            prompt = (
                "Do you want to continue with document-based credential analysis "
                "and high-value artifact review? This phase is slower."
            )
    confirmer = getattr(shell, "_questionary_confirm", None)
    if callable(confirmer):
        return bool(confirmer(prompt, default=True))
    return Confirm.ask(prompt, default=True)


def should_continue_with_heavy_artifact_analysis(
    *,
    shell: Any,
    domain: str,
) -> bool:
    """Ask whether to run the slowest SMB artifact analysis phase."""
    if should_skip_sensitive_scan_prompt_for_ctf_pwned(shell=shell, domain=domain):
        print_info_debug(
            "Skipping heavy-artifact deterministic SMB prompt because the CTF "
            f"domain is already pwned: domain={mark_sensitive(domain, 'domain')}"
        )
        return False
    prompt = (
        "Do you want to continue with heavy artifact analysis "
        "(ZIP/DMP/PCAP/VDI)? This is slower and more resource-intensive."
    )
    confirmer = getattr(shell, "_questionary_confirm", None)
    if callable(confirmer):
        response = confirmer(prompt, default=True)
        return bool(response)
    return Confirm.ask(prompt, default=True)


def run_staged_smb_sensitive_scan(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    hosts: list[str],
    share_map: dict[str, dict[str, str]] | None,
    username: str,
    password: str,
    backend: str,
    cifs_mount_root: str | None,
    ai_configured: bool,
    prepare_backend_context: Callable[..., dict[str, Any]],
    run_phase: Callable[..., dict[str, Any]],
    print_completion_summary: Callable[..., None],
    should_run_phase: Callable[..., bool] = should_run_credential_phase,
    should_run_heavy_phase: Callable[..., bool] = should_continue_with_heavy_artifact_analysis,
) -> dict[str, Any]:
    """Run the staged SMB sensitive-data flow using injected backend callbacks."""
    analysis_context: dict[str, Any] = {
        "ai_configured": bool(ai_configured),
    }
    backend_context: dict[str, Any] | None = None
    if backend in {"rclone_direct", "rclone_mapped"}:
        backend_context = prepare_backend_context(
            shell=shell,
            domain=domain,
            shares=shares,
            hosts=hosts,
            share_map=share_map,
            username=username,
            password=password,
            backend=backend,
        )
        if not bool(backend_context.get("completed")):
            return {
                "completed": False,
                "credential_findings": 0,
                "artifact_hits": 0,
                "phases_run": [],
                "backend_context": backend_context,
                "ai_attempted": bool(analysis_context.get("ai_attempted")),
                "ai_success": analysis_context.get("ai_success"),
            }

    results: list[dict[str, Any]] = []
    text_phase_result: dict[str, Any] | None = None

    if should_run_phase(
        shell=shell,
        domain=domain,
        phase=SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS,
        prior_phase_result=None,
    ):
        text_phase_result = run_phase(
            shell=shell,
            domain=domain,
            shares=shares,
            hosts=hosts,
            share_map=share_map,
            username=username,
            password=password,
            backend=backend,
            phase=SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS,
            cifs_mount_root=cifs_mount_root,
            backend_context=backend_context,
            analysis_context=analysis_context,
        )
        results.append(text_phase_result)
        if not bool(text_phase_result.get("completed")):
            print_completion_summary(backend_context=backend_context)
            return {
                "completed": False,
                "credential_findings": int(text_phase_result.get("credential_findings", 0) or 0),
                "phases_run": results,
                "ai_attempted": bool(analysis_context.get("ai_attempted")),
                "ai_success": analysis_context.get("ai_success"),
            }

    if should_run_phase(
        shell=shell,
        domain=domain,
        phase=SMB_SENSITIVE_SCAN_PHASE_DOCUMENT_CREDENTIALS,
        prior_phase_result=text_phase_result,
    ):
        for phase in (
            SMB_SENSITIVE_SCAN_PHASE_DOCUMENT_CREDENTIALS,
            SMB_SENSITIVE_SCAN_PHASE_DIRECT_SECRET_ARTIFACTS,
        ):
            phase_result = run_phase(
                shell=shell,
                domain=domain,
                shares=shares,
                hosts=hosts,
                share_map=share_map,
                username=username,
                password=password,
                backend=backend,
                phase=phase,
                cifs_mount_root=cifs_mount_root,
                backend_context=backend_context,
                analysis_context=analysis_context,
            )
            results.append(phase_result)
            if not bool(phase_result.get("completed")):
                break

    if should_run_heavy_phase(shell=shell, domain=domain):
        heavy_result = run_phase(
            shell=shell,
            domain=domain,
            shares=shares,
            hosts=hosts,
            share_map=share_map,
            username=username,
            password=password,
            backend=backend,
            phase=SMB_SENSITIVE_SCAN_PHASE_HEAVY_ARTIFACTS,
            cifs_mount_root=cifs_mount_root,
            backend_context=backend_context,
            analysis_context=analysis_context,
        )
        results.append(heavy_result)

    print_completion_summary(backend_context=backend_context)
    return {
        "completed": all(bool(item.get("completed")) for item in results if item),
        "credential_findings": sum(
            int(item.get("credential_findings", 0) or 0) for item in results
        ),
        "artifact_hits": sum(int(item.get("artifact_hits", 0) or 0) for item in results),
        "phases_run": results,
        "backend_context": backend_context,
        "ai_attempted": bool(analysis_context.get("ai_attempted")),
        "ai_success": analysis_context.get("ai_success"),
    }


__all__ = [
    "run_staged_smb_sensitive_scan",
    "should_continue_with_deeper_sensitive_scan",
    "should_continue_with_heavy_artifact_analysis",
    "should_run_credential_phase",
    "should_skip_sensitive_scan_prompt_for_ctf_pwned",
]
