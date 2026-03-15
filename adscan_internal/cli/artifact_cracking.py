"""Reusable CLI orchestration for John-backed artifact cracking flows."""

from __future__ import annotations

import os
import shlex
from typing import Any, Sequence

from adscan_internal import (
    print_error,
    print_exception,
    print_info,
    print_info_verbose,
    print_success,
    print_success_verbose,
    print_warning,
    telemetry,
)
from adscan_internal.cli.cracking import resolve_cracking_wordlist
from adscan_internal.rich_output import mark_sensitive, print_info_debug
from adscan_internal.services.john_artifact_cracking_service import (
    JohnArtifactCrackingService,
)
from adscan_internal.services.cracking_history_service import (
    build_cracking_attempt,
    find_matching_attempt,
    register_cracking_attempt,
)
import time
import subprocess
from rich.prompt import Confirm


def run_file2john_artifact_flow(
    shell: Any,
    *,
    domain: str,
    input_files: object,
    hash_file: str,
    file_type: str,
    wordlists_dir: str,
    original_file: object | None = None,
) -> str | None:
    """Convert one artifact to John format, crack it, and return the recovered secret."""
    try:
        converter_name = f"{file_type}2john"
        converter_path = JohnArtifactCrackingService.resolve_converter_path(
            converter_name
        )
        if not converter_path:
            print_error(f"Required converter not found: {converter_name}")
            return None

        if file_type == "ansible":
            files_str = " ".join(shlex.quote(str(path)) for path in input_files)
        else:
            files_str = shlex.quote(str(input_files))
        command = JohnArtifactCrackingService._build_converter_command(
            converter_path=converter_path,
            files_str=files_str,
            hash_file=str(hash_file),
        )
        print_info_verbose(f"Generating hash with {file_type}2john: {command}")
        shell.run_command(command, timeout=300)
        JohnArtifactCrackingService.normalize_hash_file(str(hash_file))

        if not os.path.exists(hash_file):
            print_error(f"Error generating hash with {file_type}2john")
            return None

        print_success_verbose(f"Hash saved in {hash_file}")
        print_warning(
            f"Cracking {file_type} file. Please be patient, this can take a while."
        )
        wordlist = resolve_cracking_wordlist(
            shell=shell,
            domain=domain,
            hash_type=f"{file_type} artifact",
            wordlists_dir=wordlists_dir,
        )
        if not wordlist:
            print_warning("No wordlist selected. Skipping John cracking.")
            return None

        marked_wordlist = mark_sensitive(wordlist, "path")
        print_info(f"Using wordlist for John cracking: {marked_wordlist}")
        password = run_john_cracking(
            shell,
            hash_file=hash_file,
            wordlist=wordlist,
            domain=domain,
            original_file=original_file or input_files,
        )
        if password:
            apply_artifact_post_action(
                shell,
                domain=domain,
                input_files=input_files,
                file_type=file_type,
                password=password,
            )
        return password
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error(f"Error executing {file_type}2john flow.")
        print_exception(show_locals=False, exception=exc)
        return None


def run_john_cracking(
    shell: Any,
    *,
    hash_file: str,
    wordlist: str,
    domain: str,
    original_file: object | None = None,
) -> str | None:
    """Run John against one hash file and return the cracked secret when available."""
    try:
        wordlist_name = os.path.basename(str(wordlist)) if wordlist else None
        original_paths = [str(original_file)] if original_file is not None else []
        attempt_template = build_cracking_attempt(
            tool="john",
            crack_type="john_artifact",
            wordlist_name=wordlist_name,
            wordlist_path=wordlist,
            hash_file=hash_file,
            original_files=original_paths,
            result="started",
            cracked_count=0,
        )
        previous_attempt = find_matching_attempt(shell, domain=domain, attempt=attempt_template)
        if previous_attempt:
            marked_wordlist = mark_sensitive(wordlist_name or wordlist or "N/A", "path")
            print_warning(
                f"This John cracking attempt appears to have already been run using {marked_wordlist}."
            )
            print_info_debug(
                "[cracking] repeated John attempt detected: "
                f"wordlist={marked_wordlist} previous_result={previous_attempt.get('result')} previous_timestamp={previous_attempt.get('timestamp')}"
            )
            if not getattr(shell, "auto", False):
                if not Confirm.ask(
                    "Do you want to continue with this John cracking attempt?",
                    default=False,
                ):
                    print_info(
                        "John cracking cancelled because the same inputs were already attempted."
                    )
                    return None

        john_path = JohnArtifactCrackingService.resolve_john_path() or "john"
        command = (
            f"{shlex.quote(john_path)} --wordlist={shlex.quote(str(wordlist))} "
            f"{shlex.quote(str(hash_file))}"
        )
        print_info_verbose("Starting john the ripper")
        proc = shell.run_command(command, timeout=300)

        if proc and proc.returncode == 0:
            print_success_verbose("Cracking with john completed")
            password = check_john_result(shell, hash_file=hash_file)
            register_cracking_attempt(
                shell,
                domain=domain,
                attempt=build_cracking_attempt(
                    tool="john",
                    crack_type="john_artifact",
                    wordlist_name=wordlist_name,
                    wordlist_path=wordlist,
                    hash_file=hash_file,
                    original_files=original_paths,
                    result="success" if password else "no_match",
                    cracked_count=1 if password else 0,
                ),
            )
            return password
        error_text = str(getattr(proc, "stderr", "") or "").strip()
        if error_text:
            print_error(f"Error executing john: {error_text}")
        register_cracking_attempt(
            shell,
            domain=domain,
            attempt=build_cracking_attempt(
                tool="john",
                crack_type="john_artifact",
                wordlist_name=wordlist_name,
                wordlist_path=wordlist,
                hash_file=hash_file,
                original_files=original_paths,
                result="error",
                cracked_count=0,
            ),
        )
        return None
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("Error in john.")
        print_exception(show_locals=False, exception=exc)
        return None


def check_john_result(shell: Any, *, hash_file: str) -> str | None:
    """Parse ``john --show`` output using the shared John helper semantics."""
    try:
        john_path = JohnArtifactCrackingService.resolve_john_path() or "john"
        command = f"{shlex.quote(john_path)} --show {shlex.quote(str(hash_file))}"
        proc = shell.run_command(command, timeout=300)
        if proc and getattr(proc, "returncode", 1) == 0 and getattr(proc, "stdout", ""):
            password = JohnArtifactCrackingService.parse_john_show_output(proc.stdout)
            if password:
                marked_password = mark_sensitive(password, "password")
                print_warning(f"Password found: {marked_password}")
                return password
            print_warning("Password not found")
        return None
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("Error checking result.")
        print_exception(show_locals=False, exception=exc)
        return None


def apply_artifact_post_action(
    shell: Any,
    *,
    domain: str,
    input_files: object,
    file_type: str,
    password: str,
) -> None:
    """Run artifact-specific follow-up logic after cracking a secret."""
    if file_type == "pfx":
        shell.ptc_certipy(domain, input_files, pfx_password=password)
        return
    if file_type == "zip":
        extract_protected_zip(
            shell,
            zip_file=input_files,
            password=password,
            domain=domain,
        )
        return
    if file_type == "ansible":
        _decrypt_ansible_vaults(
            shell,
            domain=domain,
            input_files=input_files,
            password=password,
        )


def _decrypt_ansible_vaults(
    shell: Any,
    *,
    domain: str,
    input_files: object,
    password: str,
) -> None:
    """Decrypt Ansible vault files with a cracked password."""
    marked_password = mark_sensitive(password, "password")
    print_info(f"Attempting to decrypt vaults with password: {marked_password}")
    pass_file = f"domains/{domain}/smb/manspider/cracked_vault_pass.txt"
    os.makedirs(os.path.dirname(pass_file), exist_ok=True)
    with open(pass_file, "w", encoding="utf-8") as handle:
        handle.write(password)

    for vault_file in _coerce_input_files(input_files):
        command = (
            f"cat {shlex.quote(str(vault_file))} "
            "| ansible-vault decrypt "
            f"--vault-password-file {shlex.quote(pass_file)}; echo"
        )
        try:
            proc = shell.run_command(command, timeout=300)
            print_info(f"Attempting to decrypt {vault_file}: {command}")
            if "successful" in proc.stdout:
                decrypted = proc.stdout.split("Decryption successful\n", 1)[1].strip()
                print_success(f"Decrypted content of {vault_file}:")
                shell.console.print(decrypted)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error(f"Error decrypting {vault_file}: {str(exc)}")
            print_exception(show_locals=False, exception=exc)


def _coerce_input_files(input_files: object) -> Sequence[str]:
    """Normalize one or many input files to a sequence."""
    if isinstance(input_files, (list, tuple, set)):
        return [str(path) for path in input_files]
    return [str(input_files)]


def extract_protected_zip(
    shell: Any,
    *,
    zip_file: object,
    password: str,
    domain: str,
) -> None:
    """Extract a password-protected ZIP archive and reprocess extracted files."""
    try:
        print_info(
            f"Attempting to extract protected ZIP with found password: {zip_file}"
        )
        output_dir = f"domains/{domain}/smb/manspider/extracted"
        os.makedirs(output_dir, exist_ok=True)

        escaped_password = shlex.quote(password)
        command = (
            f"unzip -P {escaped_password} -d {shlex.quote(output_dir)} "
            f"{shlex.quote(str(zip_file))}"
        )
        proc = shell.run_command(command, timeout=300)
        time.sleep(5)
        if proc.returncode != 0:
            stderr = str(getattr(proc, "stderr", "") or "").strip()
            print_error(f"Error extracting ZIP: {stderr}")
            return

        print_success(f"ZIP extracted successfully in {output_dir}")
        for root, _dirs, files in os.walk(output_dir):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                print_info(f"Processing extracted file: {file_name}")
                shell.process_found_file(file_path, domain, "ext")
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("Error extracting protected ZIP.")
        print_exception(show_locals=False, exception=exc)


def list_zip(shell: Any, *, zip_file: object) -> None:
    """List ZIP contents using the structured ZIP service with legacy fallback."""
    try:
        from adscan_internal.services.zip_processing_service import ZipProcessingService

        print_info(f"Listing contents of {zip_file}")
        service = ZipProcessingService()
        inspection = service.inspect_zip_file(zip_path=str(zip_file))
        if inspection.success:
            shell.console.print(
                f"Entries: {len(inspection.entries)} "
                f"(encrypted={inspection.encrypted_entries})"
            )
            preview_limit = 200
            for entry in inspection.entries[:preview_limit]:
                if entry.is_dir:
                    continue
                marker = "[enc]" if entry.is_encrypted else "[clr]"
                shell.console.print(f"{marker} {entry.file_size:>10} {entry.name}")
            if len(inspection.entries) > preview_limit:
                print_warning(
                    f"ZIP listing preview truncated to first {preview_limit} entries."
                )
            return

        command = f"unzip -l {shlex.quote(str(zip_file))}"
        proc = shell.run_command(command, timeout=300)
        if proc.returncode == 0:
            shell.console.print(proc.stdout)
        else:
            stderr = str(getattr(proc, "stderr", "") or "").strip()
            print_error(f"Error listing contents: {stderr}")
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("Error.")
        print_exception(show_locals=False, exception=exc)


def extract_zip(shell: Any, *, zip_file: object, domain: str) -> None:
    """Inspect a ZIP archive, crack if protected, or extract and reprocess it."""
    try:
        from adscan_internal.services.zip_processing_service import ZipProcessingService

        print_info(f"Attempting to extract ZIP file: {zip_file}")
        service = ZipProcessingService()
        inspection = service.inspect_zip_file(zip_path=str(zip_file))

        is_encrypted = False
        if inspection.success:
            is_encrypted = inspection.is_password_protected
            print_info_debug(
                f"ZIP inspection result: entries={len(inspection.entries)} "
                f"encrypted={inspection.encrypted_entries}"
            )
        else:
            try:
                test_cmd = f'unzip -P "" -t {shlex.quote(str(zip_file))}'
                completed_process = shell.run_command(test_cmd, timeout=5)
                if completed_process is None or (
                    hasattr(completed_process, "returncode")
                    and completed_process.returncode != 0
                ):
                    is_encrypted = True
            except subprocess.TimeoutExpired as exc:
                telemetry.capture_exception(exc)
                is_encrypted = True
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_error(f"Error testing zip file {zip_file}.")
                print_exception(show_locals=False, exception=exc)
                return

        if is_encrypted:
            print_warning("ZIP file is password protected")
            hash_file = f"{zip_file}.hash"
            shell.file2john(domain, zip_file, hash_file, "zip")
            return

        print_success("ZIP file is not protected, extracting...")
        output_dir = f"domains/{domain}/smb/manspider/extracted"
        os.makedirs(output_dir, exist_ok=True)
        command = (
            f"unzip -q -n {shlex.quote(str(zip_file))} "
            f"-d {shlex.quote(output_dir)}"
        )
        proc = shell.run_command(command, timeout=300)

        if proc.returncode != 0:
            print_error(f"Error extracting ZIP: {proc.stderr}")
            return

        print_success(f"ZIP extracted successfully in {output_dir}")
        for root, _dirs, files in os.walk(output_dir):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                print_info(f"Processing extracted file: {file_name}")
                shell.process_found_file(file_path, domain, "ext")
    except subprocess.TimeoutExpired as exc:
        telemetry.capture_exception(exc)
        print_error("Timeout reached while processing the ZIP")
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("Error processing ZIP.")
        print_exception(show_locals=False, exception=exc)


__all__ = [
    "apply_artifact_post_action",
    "check_john_result",
    "extract_zip",
    "extract_protected_zip",
    "list_zip",
    "run_file2john_artifact_flow",
    "run_john_cracking",
]
