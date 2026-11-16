"""Rclone-backed SMB share mapping helpers.

This service builds per-host share metadata JSON files by invoking ``rclone``
against SMB shares and transforming the output into the same shape expected by
``ShareMappingService.merge_spider_plus_run``.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable
import json
import shlex
import subprocess

from adscan_core.subprocess_env import get_clean_env_for_compilation
from adscan_core.scan_control import scan_control
from adscan_core.scan_control.isolation import terminal_isolated_subprocess_kwargs
from adscan_core.reporting.resource_coverage import (
    REASON_LISTING_INCOMPLETE,
    REASON_MEMORY,
)
from adscan_internal.services.base_service import BaseService
from adscan_internal.services.share_mapping_bounds import (
    MEMORY_CHECK_EVERY_ENTRIES,
    REASON_ACCESS_DENIED,
    ReviewNameBudget,
    ShareListingCollector,
    iter_listing_lines,
    stderr_is_access_denied_only,
)
from adscan_internal.services.smb_guest_auth_service import is_guest_alias
from adscan_internal.workspaces import write_json_file

# rclone reads backend config from ``RCLONE_<BACKEND>_<KEY>`` environment
# variables when the corresponding param is OMITTED from the connection string.
# Passing the (reversible) obscured SMB password this way keeps it OUT of the
# connection string rclone echoes verbatim into its STDERR error lines — the
# exact text the recorded command preview captures. Verified against rclone:
# with ``pass=`` absent from the ``:smb,...`` connection string and this env var
# set, rclone resolves ``smb_pass`` from the environment and the echoed remote no
# longer contains the credential.
_RCLONE_SMB_PASS_ENV = "RCLONE_SMB_PASS"


def _quote_redirect_target(path: str) -> str:
    """Quote a file path as the target of a shell output redirect, per OS."""
    from adscan_core.pal.platform import is_windows  # noqa: PLC0415

    if is_windows():
        return subprocess.list2cmdline([path])
    return shlex.quote(path)


class RcloneShareMappingService(BaseService):
    """Generate spider_plus-compatible host JSON metadata using rclone."""

    @staticmethod
    def resolve_smb_remote_auth(
        *,
        username: str,
        password: str,
        domain: str,
    ) -> dict[str, str]:
        """Normalize one SMB auth context for inline rclone remotes.

        ``rclone`` null sessions must omit ``user=``, ``pass=``, and ``domain=``
        entirely. Guest transport keeps the username but can still legitimately
        use an empty password.
        """
        normalized_username = str(username or "").strip()
        normalized_password = str(password or "")
        normalized_domain = str(domain or "").strip()
        lowered_username = normalized_username.lower()

        if lowered_username == "null":
            return {
                "auth_mode": "null",
                "username": "",
                "password": "",
                "domain": "",
            }

        if is_guest_alias(lowered_username) and normalized_password == "":
            return {
                "auth_mode": "guest",
                "username": normalized_username,
                "password": "",
                "domain": normalized_domain,
            }

        return {
            "auth_mode": "authenticated",
            "username": normalized_username,
            "password": normalized_password,
            "domain": normalized_domain,
        }

    def obscure_password(
        self,
        *,
        command_executor: Callable[..., Any],
        rclone_path: str,
        password: str,
    ) -> str:
        """Return rclone-obscured password text for SMB inline remote config."""
        if password == "":
            return ""
        return self._obscure_password(
            command_executor=command_executor,
            rclone_path=rclone_path,
            password=password,
        )

    @staticmethod
    def build_smb_remote(
        *,
        host: str,
        share: str,
        username: str,
        obscured_password: str,
        domain: str,
    ) -> str:
        """Build one inline rclone SMB remote for a host/share target.

        SECURITY: the (reversible) obscured SMB password is deliberately NOT
        embedded in the connection string. rclone echoes the whole connection
        string verbatim into its STDERR error lines, which the recorded command
        preview captures — and ``rclone obscure`` is reversible with a static
        public key, so an inline ``pass=<obscured>`` is a recoverable cleartext
        credential in the session recording. The password is supplied OUT-OF-BAND
        via the ``RCLONE_SMB_PASS`` environment variable instead (see
        :meth:`build_rclone_env`). ``obscured_password`` is accepted only to
        decide whether credentials are present at all.
        """
        auth = RcloneShareMappingService.resolve_smb_remote_auth(
            username=username,
            password=obscured_password,
            domain=domain,
        )
        remote_parts = [":smb", f"host={host}"]
        if auth["username"]:
            remote_parts.append(f"user={auth['username']}")
        if auth["domain"]:
            remote_parts.append(f"domain={auth['domain']}")
        return f"{','.join(remote_parts)}:{share}"

    @staticmethod
    def build_rclone_env(obscured_password: str) -> dict[str, str] | None:
        """Build the subprocess env that supplies the SMB password out-of-band.

        Returns ``None`` when there is no password to inject (null/guest/empty),
        so the caller leaves the executor's default environment untouched. When a
        password IS present, returns a PyInstaller-safe clean environment (no
        ``LD_LIBRARY_PATH`` leakage into the external rclone binary) with
        ``RCLONE_SMB_PASS`` set to the obscured value. rclone reads it because the
        connection string omits ``pass=``.
        """
        if not obscured_password:
            return None
        env = get_clean_env_for_compilation()
        env[_RCLONE_SMB_PASS_ENV] = obscured_password
        return env

    def generate_host_metadata_json(
        self,
        *,
        run_output_dir: str,
        host_share_targets: list[tuple[str, str]],
        username: str,
        password: str,
        domain: str,
        command_executor: Callable[..., Any],
        rclone_path: str = "rclone",
        timeout_seconds: int = 1200,
        shell: Any | None = None,
        stage: Any | None = None,
        keep_all_file_names: bool = False,
    ) -> dict[str, Any]:
        """Generate host JSON metadata files using ``rclone lsjson``.

        Engagement scope: rclone runs as a child process, which no in-process
        check can see, so the targets are partitioned here, where its commands
        are built. A target on a host the scope excludes produces no command
        (``shell`` is the session whose scope applies). One child is started per
        (host, share) pair and a listing can take many minutes, so each host is
        asked about again immediately before its command is built: a host
        excluded while the mapping runs gets no child, and is counted in
        ``outside_scope_targets`` (never in ``failed_targets``).

        Args:
            run_output_dir: Directory where per-host JSON files will be written.
            host_share_targets: List of (host, share) tuples to enumerate.
            username: SMB username.
            password: SMB password.
            domain: SMB domain/workgroup.
            command_executor: Callable used to run shell commands.
            rclone_path: Path to ``rclone`` executable.
            timeout_seconds: Per-target listing timeout.
            keep_all_file_names: The AI review: keep every file name, not only
                the candidate types, up to one total for the run
                (``MAX_AI_REVIEW_FILE_NAMES_PER_RUN``); past it candidate files
                are still kept and the share is a declared gap.
            stage: The enclosing memory-bounded stage, when there is one. It is
                asked (``over_line``) between shares and while a long listing
                is read; past the line no further share is listed and the
                summary says ``memory_stopped``.

        Memory: each share's listing is written by rclone to a spool file and
        read back one entry at a time; only candidate files are kept
        (:mod:`adscan_internal.services.share_mapping_bounds`), within a bound
        per share, and each host's result is written as soon as that host is
        done. The whole tree of every share is still listed.

        Returns:
            Mapping summary with counters, and ``share_outcomes``
            (``{host: {share: outcome}}``): how each share's listing ended.
        """
        run_output_path = Path(run_output_dir).expanduser().resolve(strict=False)
        run_output_path.mkdir(parents=True, exist_ok=True)
        normalized_targets = self._unique_targets(host_share_targets)
        from adscan_internal.services.engagement_scope import (  # noqa: PLC0415
            partition_targets_in_scope,
        )
        from adscan_internal.services.engagement_scope_targets import (  # noqa: PLC0415
            host_contact_gate,
            prepare_targets_for_scope,
        )

        target_hosts = list(dict.fromkeys(host for host, _share in normalized_targets))
        prepare_targets_for_scope(shell, target_hosts)
        allowed_hosts = {
            host.lower()
            for host in partition_targets_in_scope(
                shell,
                target_hosts,
                surface="smb_share_hunt",
                what="SMB share mapping",
            ).allowed
        }
        normalized_targets = [
            (host, share) for host, share in normalized_targets if host.lower() in allowed_hosts
        ]
        # The partition above is from the start of the mapping. The gate below
        # is asked per pair, right before that pair's child process is started.
        child_gate = host_contact_gate(
            shell,
            [host for host in target_hosts if host.lower() in allowed_hosts],
            surface="smb_share_hunt",
            what="SMB share mapping",
        )
        transport_auth = self.resolve_smb_remote_auth(
            username=username,
            password=password,
            domain=domain,
        )
        obscured_password = self.obscure_password(
            command_executor=command_executor,
            rclone_path=rclone_path,
            password=transport_auth["password"],
        )
        if transport_auth["password"] and not obscured_password:
            return {
                "run_output_dir": str(run_output_path),
                "host_json_files": 0,
                "mapped_shares": 0,
                "mapped_file_entries": 0,
                "partial_targets": 0,
                "capped_targets": 0,
                "failed_targets": len(normalized_targets),
                "outside_scope_targets": 0,
                "targets_total": len(normalized_targets),
                "shares_done": 0,
                "memory_stopped": False,
                "share_outcomes": {},
            }

        # Supply the obscured SMB password out-of-band via RCLONE_SMB_PASS so it
        # never appears in the connection string rclone echoes into its STDERR
        # (and thence the recorded command preview).
        rclone_env = self.build_rclone_env(obscured_password)

        # Targets are taken host by host, so one host's result is written and
        # released before the next host starts: nothing is held for the estate.
        normalized_targets = self._group_targets_by_host(normalized_targets)
        failed_targets = 0
        partial_targets = 0
        capped_targets = 0
        mapped_shares = 0
        mapped_file_entries = 0
        outside_scope_targets = 0
        host_json_files = 0
        shares_done = 0
        memory_stopped = False
        share_outcomes: dict[str, dict[str, dict[str, Any]]] = {}
        name_budget = ReviewNameBudget() if keep_all_file_names else None
        current_host: str | None = None
        host_payload: dict[str, dict[str, dict[str, str]]] = {}

        def _flush_host() -> None:
            nonlocal host_json_files, host_payload
            if current_host is not None and host_payload:
                write_json_file(str(run_output_path / f"{current_host}.json"), host_payload)
                host_json_files += 1
            host_payload = {}

        def _memory_crossed() -> bool:
            return stage is not None and bool(stage.over_line())

        try:
            for index, (host, share) in enumerate(normalized_targets):
                # Scan control checkpoint: stop listing new shares once the operator
                # stopped the step; what was listed so far is kept.
                if scan_control().should_stop():
                    break
                # Memory checkpoint: past the stage line no further share is
                # listed; the caller's stage boundary declares the rest.
                if _memory_crossed():
                    memory_stopped = True
                    break
                if host != current_host:
                    _flush_host()
                    current_host = host
                # Engagement scope, immediately before the child is handed this host.
                if not child_gate.admits(host):
                    outside_scope_targets += 1
                    continue
                spool_path = run_output_path / f".listing-{index}.spool"
                command = self._build_lsjson_command(
                    rclone_path=rclone_path,
                    host=host,
                    share=share,
                    username=transport_auth["username"],
                    obscured_password=obscured_password,
                    domain=transport_auth["domain"],
                    spool_path=str(spool_path),
                )
                executor_kwargs: dict[str, Any] = {
                    "timeout": timeout_seconds,
                    "ignore_errors": True,
                    # rclone never reads the terminal: out of Ctrl+C's reach.
                    **terminal_isolated_subprocess_kwargs(),
                }
                if rclone_env is not None:
                    executor_kwargs["env"] = rclone_env
                try:
                    result = command_executor(command, **executor_kwargs)
                    # ``None`` is the executor's timeout or failure. Whatever the
                    # listing wrote before that is still in the spool file.
                    return_code = 1 if result is None else int(getattr(result, "returncode", 1))
                    stderr_text = str(getattr(result, "stderr", "") or "").strip()
                    collector = ShareListingCollector(name_budget=name_budget)
                    stream_stopped = self._consume_listing(
                        collector,
                        iter_listing_lines(
                            spool_path, str(getattr(result, "stdout", "") or "")
                        ),
                        memory_crossed=_memory_crossed,
                    )
                finally:
                    try:
                        spool_path.unlink(missing_ok=True)
                    except OSError:
                        pass
                shares_done += 1
                if stage is not None:
                    stage.progress(shares_done)
                if stream_stopped:
                    memory_stopped = True
                if collector.entries_listed == 0 and return_code != 0:
                    failed_targets += 1
                    if memory_stopped:
                        break
                    continue

                interrupted: str | None = None
                if stream_stopped:
                    interrupted = REASON_MEMORY
                elif return_code != 0:
                    interrupted = (
                        REASON_ACCESS_DENIED
                        if result is not None and stderr_is_access_denied_only(stderr_text)
                        else REASON_LISTING_INCOMPLETE
                    )
                    partial_targets += 1
                    self.logger.warning(
                        "rclone lsjson did not finish cleanly; keeping the part it "
                        "listed for host=%s share=%s rc=%s timed_out=%s stderr=%s",
                        host,
                        share,
                        return_code,
                        result is None,
                        stderr_text,
                    )
                outcome = collector.outcome(interrupted_reason=interrupted)
                if collector.capped:
                    capped_targets += 1
                share_outcomes.setdefault(host, {})[share] = outcome
                if collector.files:
                    host_payload[share] = collector.files
                    mapped_shares += 1
                    mapped_file_entries += len(collector.files)
                if memory_stopped:
                    break
        finally:
            _flush_host()

        return {
            "run_output_dir": str(run_output_path),
            "host_json_files": host_json_files,
            "mapped_shares": mapped_shares,
            "mapped_file_entries": mapped_file_entries,
            "partial_targets": partial_targets,
            "capped_targets": capped_targets,
            "failed_targets": failed_targets,
            "outside_scope_targets": outside_scope_targets,
            "targets_total": len(normalized_targets),
            "shares_done": shares_done,
            "memory_stopped": memory_stopped,
            "share_outcomes": share_outcomes,
        }

    @staticmethod
    def _group_targets_by_host(
        targets: list[tuple[str, str]],
    ) -> list[tuple[str, str]]:
        """Order targets so each host's shares are contiguous (first-seen order)."""
        by_host: dict[str, list[tuple[str, str]]] = {}
        for host, share in targets:
            by_host.setdefault(host, []).append((host, share))
        return [pair for pairs in by_host.values() for pair in pairs]

    def _consume_listing(
        self,
        collector: ShareListingCollector,
        lines: Iterable[str],
        *,
        memory_crossed: Callable[[], bool],
    ) -> bool:
        """Feed one share's listing to its collector, one entry per line.

        ``rclone lsjson`` writes one JSON object per line, so the listing is
        never parsed as one document. Returns True when reading stopped because
        memory crossed the stage line.
        """
        for line in lines:
            candidate = line.strip()
            if candidate.endswith(","):
                candidate = candidate[:-1].rstrip()
            if candidate.startswith("[") and candidate.endswith("]") and len(candidate) > 2:
                # A whole listing on one line (an executor that returned the
                # text): its entries are parsed together.
                try:
                    entries = json.loads(candidate)
                except ValueError:
                    entries = []
                for entry in entries if isinstance(entries, list) else []:
                    self._admit_entry(collector, entry)
                continue
            if not candidate.startswith("{"):
                continue
            try:
                entry = json.loads(candidate)
            except ValueError:
                continue
            self._admit_entry(collector, entry)
            if (
                collector.entries_listed % MEMORY_CHECK_EVERY_ENTRIES == 0
                and memory_crossed()
            ):
                return True
        return False

    def _admit_entry(self, collector: ShareListingCollector, entry: Any) -> None:
        """Offer one ``lsjson`` entry to the collector; keep it when admitted."""
        if not isinstance(entry, dict) or bool(entry.get("IsDir", False)):
            return
        path = str(entry.get("Path") or entry.get("Name") or "").strip()
        if not path or not collector.admit(path):
            return
        collector.files[path] = {
            "size": self._format_size_human(self._parse_size(entry.get("Size"))),
            "ctime_epoch": "",
            "mtime_epoch": self._parse_modtime_epoch(entry.get("ModTime")),
            "atime_epoch": "",
        }

    @staticmethod
    def _unique_targets(
        targets: list[tuple[str, str]],
    ) -> list[tuple[str, str]]:
        """Return stable unique non-empty host/share targets."""
        unique: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for host, share in targets:
            host_name = str(host or "").strip()
            share_name = str(share or "").strip()
            if not host_name or not share_name:
                continue
            key = (host_name.lower(), share_name.lower())
            if key in seen:
                continue
            seen.add(key)
            unique.append((host_name, share_name))
        return unique

    def _obscure_password(
        self,
        *,
        command_executor: Callable[..., Any],
        rclone_path: str,
        password: str,
    ) -> str:
        """Obscure SMB password via ``rclone obscure`` for backend inline config."""
        command = f"{shlex.quote(rclone_path)} obscure {shlex.quote(password)}"
        result = command_executor(command, timeout=30, ignore_errors=True)
        if result is None or int(getattr(result, "returncode", 1)) != 0:
            return ""
        return str(getattr(result, "stdout", "") or "").strip()

    @staticmethod
    def _build_lsjson_command(
        *,
        rclone_path: str,
        host: str,
        share: str,
        username: str,
        obscured_password: str,
        domain: str,
        spool_path: str | None = None,
    ) -> str:
        """Build one ``rclone lsjson`` command for one SMB host/share target.

        The whole tree is listed: no depth limit and no path filter. With
        ``spool_path`` the listing is written to that file instead of being
        returned, so its size never reaches this process's memory.
        """
        remote = RcloneShareMappingService.build_smb_remote(
            host=host,
            share=share,
            username=username,
            obscured_password=obscured_password,
            domain=domain,
        )
        command = (
            f"{shlex.quote(rclone_path)} lsjson {shlex.quote(remote)} "
            "--recursive --files-only --no-mimetype "
            # At most one sign-in that can fail per invocation: rclone's
            # verdict never reaches the lockout guard, so it must not retry one.
            "--retries 1 --low-level-retries 1"
        )
        if spool_path:
            command += f" > {_quote_redirect_target(spool_path)}"
        return command

    @staticmethod
    def _parse_size(value: Any) -> int:
        """Parse size to non-negative integer bytes."""
        try:
            parsed = int(value)
        except Exception:
            return 0
        return max(0, parsed)

    @staticmethod
    def _parse_modtime_epoch(value: Any) -> str:
        """Parse RFC3339 timestamp into epoch seconds as string."""
        text = str(value or "").strip()
        if not text:
            return ""
        normalized = text.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(normalized)
        except Exception:
            return ""
        return str(int(parsed.timestamp()))

    @staticmethod
    def _format_size_human(num_bytes: int) -> str:
        """Format byte count into spider_plus-compatible human readable string."""
        value = float(max(0, num_bytes))
        units = ["B", "KB", "MB", "GB", "TB"]
        unit_idx = 0
        while value >= 1024 and unit_idx < len(units) - 1:
            value /= 1024
            unit_idx += 1
        if unit_idx == 0:
            return f"{int(value)} B"
        return f"{value:.2f} {units[unit_idx]}"
