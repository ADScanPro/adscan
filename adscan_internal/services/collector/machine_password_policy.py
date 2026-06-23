"""Recover the machine-account password rotation policy from GPO SYSVOL templates.

The two settings that govern whether (and how often) domain members rotate their
computer-account passwords are GPO **Security Options**, NOT domain LDAP
attributes:

- "Domain member: Maximum machine account password age" → Netlogon registry value
  ``MaximumPasswordAge`` (default 30 days).
- "Domain member: Disable machine account password changes" → ``DisablePasswordChange``
  (and the member-side ``RefusePasswordChange``). When set, members never rotate,
  so every machine password is static and a durable Timeroast/cracking target.

Both live in each GPO's SYSVOL template at
``…\\Policies\\{GUID}\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf`` under
the ``[Registry Values]`` section. SYSVOL is readable by any authenticated domain
user (that is how every member applies policy at boot), so the collector can
recover these with the same credentials it already holds — no admin required.

This module is best-effort: a blocked 445, a missing GptTmpl.inf, or an
unparseable template returns ``None`` and never breaks collection.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import re
from dataclasses import dataclass
from typing import Iterable

from adscan_core import telemetry
from adscan_core.rich_output import print_info_debug

# Registry value paths as they appear (case-insensitively) in [Registry Values].
_NETLOGON = r"machine\system\currentcontrolset\services\netlogon\parameters"
_KEY_MAX_AGE = _NETLOGON + r"\maximumpasswordage"
_KEY_DISABLE = _NETLOGON + r"\disablepasswordchange"
_KEY_REFUSE = _NETLOGON + r"\refusepasswordchange"

_GUID_RE = re.compile(r"\{[0-9A-Fa-f-]{36}\}")
_MAX_GPOS = 200
_PER_FILE_MAX_BYTES = 512 * 1024


@dataclass(frozen=True)
class MachinePasswordPolicy:
    """Effective machine-account password rotation policy recovered from GPOs."""

    max_age_days: int | None  # from a GPO; None = no GPO sets it → host default (30)
    disable_password_change: bool  # any inspected GPO disables/refuses rotation
    source_gpos: tuple[str, ...]  # GPO labels that set a machine-password value
    inspected_gpos: int  # how many GptTmpl.inf templates were read successfully


def _decode_inf(data: bytes) -> str:
    """Decode a GptTmpl.inf (usually UTF-16-LE with BOM) to text, best-effort."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")
    for encoding in ("utf-16", "utf-8-sig", "latin-1"):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, UnicodeError):
            continue
    return data.decode("latin-1", errors="replace")


def parse_gpttmpl_registry_values(text: str) -> dict[str, str]:
    """Return the ``[Registry Values]`` section as ``{lowercased_key: raw_value}``.

    Values keep their raw ``TYPE,DATA`` form (e.g. ``4,30`` = REG_DWORD 30).
    """
    values: dict[str, str] = {}
    in_section = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            in_section = line[1:-1].strip().casefold() == "registry values"
            continue
        if not in_section or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip().casefold()] = value.strip()
    return values


def _dword(raw: str | None) -> int | None:
    """Parse the DATA of a ``TYPE,DATA`` registry value (e.g. ``4,30`` → 30)."""
    if raw is None:
        return None
    part = raw.split(",")[-1].strip()
    try:
        return int(part, 0)
    except ValueError:
        return None


def extract_machine_password_settings(
    text: str,
) -> tuple[int | None, bool | None, bool | None]:
    """Return ``(max_age_days, disable_password_change, refuse_password_change)``.

    Each element is ``None`` when the GPO does not set that value.
    """
    values = parse_gpttmpl_registry_values(text)
    max_age = _dword(values.get(_KEY_MAX_AGE))
    disable = values.get(_KEY_DISABLE)
    refuse = values.get(_KEY_REFUSE)
    disable_b = (_dword(disable) == 1) if disable is not None else None
    refuse_b = (_dword(refuse) == 1) if refuse is not None else None
    return max_age, disable_b, refuse_b


def normalize_gpo_guid(value: str) -> str | None:
    """Extract the ``{GUID}`` from a GPO name or gpcFileSysPath; ``None`` if absent."""
    match = _GUID_RE.search(str(value or ""))
    return match.group(0).upper() if match else None


async def read_machine_password_policy(
    *,
    smb_config,
    dc_unc_host: str,
    domain_fqdn: str,
    gpo_specs: Iterable[tuple[str, str]],
    max_gpos: int = _MAX_GPOS,
) -> MachinePasswordPolicy | None:
    """Read each GPO's SYSVOL GptTmpl.inf over SMB and aggregate the machine policy.

    Args:
        smb_config: an ``SMBConfig`` already targeting the DC that hosts SYSVOL.
        dc_unc_host: host portion for the SYSVOL UNC (matches ``smb_config``'s target).
        domain_fqdn: dotted domain used in the SYSVOL path.
        gpo_specs: iterable of ``(label, guid_or_path)`` for every collected GPO.

    Returns:
        The aggregated :class:`MachinePasswordPolicy`, or ``None`` when SYSVOL could
        not be read at all (best-effort: never raises).
    """
    from adscan_internal.services.smb_transport import (
        read_unc_file_bytes,
        smb_machine_with_fallback,
    )

    specs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for label, raw in gpo_specs:
        guid = normalize_gpo_guid(raw) or normalize_gpo_guid(label)
        if guid and guid not in seen:
            seen.add(guid)
            specs.append((label or guid, guid))
    if not specs:
        return None

    max_age_found: int | None = None
    disabled = False
    source_gpos: list[str] = []
    inspected = 0

    try:
        async with smb_machine_with_fallback(smb_config) as machine:
            for label, guid in specs[:max_gpos]:
                unc = (
                    f"\\\\{dc_unc_host}\\SYSVOL\\{domain_fqdn}\\Policies\\{guid}"
                    "\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf"
                )
                try:
                    data = await read_unc_file_bytes(
                        machine, unc, max_bytes=_PER_FILE_MAX_BYTES
                    )
                except Exception:  # noqa: BLE001 — a missing GptTmpl.inf is normal
                    continue
                inspected += 1
                max_age, disable, refuse = extract_machine_password_settings(
                    _decode_inf(data)
                )
                if disable or refuse or max_age is not None:
                    source_gpos.append(label)
                if disable or refuse:
                    disabled = True
                if max_age is not None:
                    max_age_found = (
                        max_age if max_age_found is None else max(max_age_found, max_age)
                    )
    except Exception as exc:  # noqa: BLE001 — best-effort, never break collection
        telemetry.capture_exception(exc)
        print_info_debug(f"machine-pwd-policy: SYSVOL read failed: {exc}")
        return None

    if inspected == 0:
        return None
    return MachinePasswordPolicy(
        max_age_days=max_age_found,
        disable_password_change=disabled,
        source_gpos=tuple(source_gpos),
        inspected_gpos=inspected,
    )


def collect_machine_password_policy_sync(
    *,
    smb_config,
    dc_unc_host: str,
    domain_fqdn: str,
    gpo_specs: Iterable[tuple[str, str]],
) -> MachinePasswordPolicy | None:
    """Synchronous wrapper: run the async SYSVOL read in a fresh event loop.

    Mirrors ``collect_domain_hosts`` so the synchronous collector orchestrator can
    call it without owning an event loop. Best-effort: returns ``None`` on failure.
    """
    specs = list(gpo_specs)
    holder: dict[str, MachinePasswordPolicy | None] = {}

    def _run() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            holder["r"] = loop.run_until_complete(
                read_machine_password_policy(
                    smb_config=smb_config,
                    dc_unc_host=dc_unc_host,
                    domain_fqdn=domain_fqdn,
                    gpo_specs=specs,
                )
            )
        finally:
            loop.close()

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(_run).result()
    except Exception as exc:  # noqa: BLE001 — best-effort, never break collection
        telemetry.capture_exception(exc)
        print_info_debug(f"machine-pwd-policy: sync wrapper failed: {exc}")
        return None
    return holder.get("r")
