"""Writable-attribute attack-step discovery backed by BloodyAD.

This service wraps ``bloodyAD get writable --detail`` so ADscan can ingest
effective per-attribute write permissions that BloodHound CE collectors do not
currently model. The output is normalized into an ADscan-native report that the
Phase 2 attack-graph pipeline can consume.

Current scope:
- user objects only
- ``scriptPath`` -> ``WriteLogonScript`` relation

The collector primitive is BloodyAD because it already computes effective
writable attributes for the authenticated principal. ADscan then persists a
stable JSON report and converts it into attack steps internally.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
import shlex
import subprocess
from typing import Any, Callable

from adscan_core.text_utils import normalize_cli_output
from adscan_internal import telemetry
from adscan_internal.integrations.bloody import build_auth_bloody
from adscan_internal.services.base_service import BaseService


_SAFE_TOKEN_RE = re.compile(r"[^a-zA-Z0-9_.-]+")

_USER_ATTRIBUTE_RELATION_MAP: dict[str, dict[str, str]] = {
    "scriptpath": {
        "relation": "WriteLogonScript",
        "attribute": "scriptPath",
    },
}


@dataclass(frozen=True, slots=True)
class WritableObjectBlock:
    """One ``bloodyAD get writable --detail`` object block."""

    distinguished_name: str
    writable_attributes: tuple[str, ...]


def sanitize_report_username(value: str) -> str:
    """Return a stable filename-safe token for one username."""
    cleaned = _SAFE_TOKEN_RE.sub("_", str(value or "").strip())
    cleaned = cleaned.strip("._")
    return cleaned or "user"


def parse_bloodyad_writable_detail_output(output: str) -> list[WritableObjectBlock]:
    """Parse ``bloodyAD get writable --detail`` output into object blocks."""
    normalized = normalize_cli_output(output or "")
    if not normalized.strip():
        return []

    blocks: list[WritableObjectBlock] = []
    current_dn = ""
    current_attrs: list[str] = []

    def flush_current() -> None:
        nonlocal current_dn, current_attrs
        if current_dn:
            blocks.append(
                WritableObjectBlock(
                    distinguished_name=current_dn,
                    writable_attributes=tuple(current_attrs),
                )
            )
        current_dn = ""
        current_attrs = []

    for raw_line in normalized.splitlines():
        line = str(raw_line or "").strip()
        if not line:
            flush_current()
            continue
        if line.startswith("distinguishedName:"):
            flush_current()
            current_dn = line.split(":", 1)[1].strip()
            continue
        if not current_dn or ":" not in line:
            continue
        key, value = line.split(":", 1)
        if value.strip().upper() != "WRITE":
            continue
        attribute_name = key.strip()
        if attribute_name:
            current_attrs.append(attribute_name)

    flush_current()
    return blocks


def parse_bloodyad_object_output(output: str) -> dict[str, str]:
    """Parse ``bloodyAD get object`` key/value output."""
    normalized = normalize_cli_output(output or "")
    if not normalized.strip():
        return {}

    values: dict[str, str] = {}
    for raw_line in normalized.splitlines():
        line = str(raw_line or "").strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key_clean = key.strip()
        value_clean = value.strip()
        if key_clean and value_clean and key_clean not in values:
            values[key_clean] = value_clean
    return values


class WritableAttributeDiscoveryService(BaseService):
    """Discover custom writable-attribute attack steps with BloodyAD."""

    def _run_command(
        self,
        runner: Callable[[str, int | None], subprocess.CompletedProcess[str]],
        *,
        command: str,
        timeout: int,
    ) -> subprocess.CompletedProcess[str]:
        """Execute one command and normalize subprocess errors."""
        return runner(command, timeout)

    def build_user_attribute_write_report(
        self,
        *,
        bloodyad_path: str,
        dc_address: str,
        target_domain: str,
        auth_domain: str,
        auth_username: str,
        auth_password: str,
        kerberos: bool,
        run_command: Callable[[str, int | None], subprocess.CompletedProcess[str]],
        timeout: int = 600,
    ) -> dict[str, Any] | None:
        """Collect writable user attributes and return a normalized report."""
        auth = build_auth_bloody(
            username=auth_username,
            password=auth_password,
            domain=auth_domain,
            kerberos=kerberos,
        )
        command = (
            f"{bloodyad_path} --host {dc_address} {auth} "
            "get writable --otype useronly --right WRITE --detail "
            "--partition DOMAIN --exclude-del"
        )
        self.logger.debug(
            "Collecting writable user attributes with BloodyAD",
            extra={
                "domain": target_domain,
                "auth_domain": auth_domain,
                "auth_username": auth_username,
                "kerberos": kerberos,
            },
        )
        try:
            result = self._run_command(
                run_command,
                command=command,
                timeout=timeout,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            self.logger.exception("Writable-attribute discovery command failed")
            return None

        if int(getattr(result, "returncode", 1)) != 0:
            self.logger.warning(
                "bloodyAD writable discovery failed",
                extra={
                    "domain": target_domain,
                    "returncode": getattr(result, "returncode", None),
                    "stdout": getattr(result, "stdout", ""),
                    "stderr": getattr(result, "stderr", ""),
                },
            )
            return None

        writable_blocks = parse_bloodyad_writable_detail_output(result.stdout or "")
        if not writable_blocks:
            return {
                "schema_version": "writable-attributes-1.0",
                "detector": "bloodyad",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "actor_username": auth_username,
                "actor_domain": auth_domain,
                "findings": [],
            }

        findings: list[dict[str, Any]] = []
        for block in writable_blocks:
            supported_attributes: list[dict[str, str]] = []
            for attribute_name in block.writable_attributes:
                mapped = _USER_ATTRIBUTE_RELATION_MAP.get(attribute_name.strip().lower())
                if mapped:
                    supported_attributes.append(mapped)
            if not supported_attributes:
                continue

            target_details = self._resolve_target_object(
                bloodyad_path=bloodyad_path,
                dc_address=dc_address,
                auth_string=auth,
                target_dn=block.distinguished_name,
                run_command=run_command,
                timeout=max(60, min(timeout, 180)),
            )
            if not target_details:
                continue

            target_username = str(target_details.get("sAMAccountName") or "").strip()
            target_object_id = str(target_details.get("objectSid") or "").strip()
            if not target_username:
                continue

            for mapped in supported_attributes:
                findings.append(
                    {
                        "relation": mapped["relation"],
                        "attribute": mapped["attribute"],
                        "target_dn": block.distinguished_name,
                        "target_username": target_username,
                        "target_object_id": target_object_id,
                        "raw_writable_attributes": list(block.writable_attributes),
                    }
                )

        return {
            "schema_version": "writable-attributes-1.0",
            "detector": "bloodyad",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "actor_username": auth_username,
            "actor_domain": auth_domain,
            "findings": findings,
        }

    def _resolve_target_object(
        self,
        *,
        bloodyad_path: str,
        dc_address: str,
        auth_string: str,
        target_dn: str,
        run_command: Callable[[str, int | None], subprocess.CompletedProcess[str]],
        timeout: int,
    ) -> dict[str, str]:
        """Resolve one writable DN into identity metadata via BloodyAD."""
        command = (
            f"{bloodyad_path} --host {dc_address} {auth_string} "
            f"get object {shlex.quote(target_dn)} "
            "--attr distinguishedName,sAMAccountName,objectSid"
        )
        try:
            result = self._run_command(
                run_command,
                command=command,
                timeout=timeout,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            self.logger.exception("bloodyAD target resolution failed")
            return {}

        if int(getattr(result, "returncode", 1)) != 0:
            self.logger.warning(
                "bloodyAD target resolution failed",
                extra={
                    "target_dn": target_dn,
                    "returncode": getattr(result, "returncode", None),
                    "stdout": getattr(result, "stdout", ""),
                    "stderr": getattr(result, "stderr", ""),
                },
            )
            return {}
        return parse_bloodyad_object_output(result.stdout or "")


__all__ = [
    "WritableAttributeDiscoveryService",
    "WritableObjectBlock",
    "parse_bloodyad_object_output",
    "parse_bloodyad_writable_detail_output",
    "sanitize_report_username",
]
