"""Defender configuration probe via MSSQL xp_cmdshell.

Queries ``Get-MpComputerStatus`` on a remote Windows host through an
existing MSSQL sysadmin connection and returns the active Defender
protection configuration.

Why via MSSQL rather than SMB/WMI:
    We already have MSSQL sysadmin access (xp_cmdshell enabled) in the
    SeImpersonate flow.  Querying Defender config via PowerShell through
    xp_cmdshell requires no additional credentials or protocol.  SMB-based
    registry reads (aiosmb) are an alternative for non-MSSQL paths — not
    implemented here yet.

Orthogonal to :class:`HostFingerprintService`:
    - HostFingerprintService (aiosmb) → WHAT is installed (product detection)
    - DefenderConfigProbe (xp_cmdshell) → HOW it is configured (state)

Usage::

    from adscan_internal.services.host_intelligence.defender_config_probe import (
        DefenderConfigProbe, DefenderConfig,
    )
    probe = DefenderConfigProbe(backend, domain, username, password, host)
    cfg = probe.query()
    # cfg.rtp_enabled, cfg.cloud_enabled, cfg.behavior_enabled, ...
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from adscan_core import telemetry
from adscan_core.rich_output import print_info_debug
from adscan_core.rich_output import print_exception


@dataclass(frozen=True, slots=True)
class DefenderConfig:
    """Defender protection configuration state on a remote host.

    ``None`` fields mean the probe could not determine the value
    (Defender not installed, WMI query failed, etc.).
    """

    rtp_enabled: bool | None = None
    """Real-time protection (on-access file scanning)."""

    cloud_enabled: bool | None = None
    """Cloud-delivered protection (MAPS / Microsoft Active Protection Service).
    True when MAPSReporting >= 1 (Basic or Advanced)."""

    behavior_enabled: bool | None = None
    """Behavior monitoring (suspicious activity heuristics)."""

    block_at_first_sight: bool | None = None
    """Block-at-first-sight (aggressive cloud lookup for unknown files)."""

    cloud_block_level: str | None = None
    """Cloud block aggressiveness: Default / Moderate / High / HighPlus / ZeroTolerance."""

    am_service_enabled: bool | None = None
    """Antimalware engine running."""

    probe_error: str | None = None
    """Set if the probe query failed; other fields may be None."""

    @property
    def is_fully_active(self) -> bool:
        """True when RTP + cloud + behavior are all enabled."""
        return bool(self.rtp_enabled and self.cloud_enabled and self.behavior_enabled)

    @property
    def coverage_label(self) -> str:
        """Human-readable coverage summary for CLI cards."""
        if self.probe_error:
            return "unknown (probe failed)"
        parts = []
        if self.rtp_enabled:
            parts.append("RTP")
        if self.cloud_enabled:
            parts.append("Cloud")
        if self.behavior_enabled:
            parts.append("Behavior")
        if self.block_at_first_sight:
            parts.append("BaFS")
        if not parts:
            return "disabled"
        return " + ".join(parts)


class DefenderConfigProbe:
    """Runs ``Get-MpComputerStatus`` via MSSQL xp_cmdshell and parses the result."""

    # Get-MpComputerStatus: runtime state (RTP, Behavior, AMService)
    # Get-MpPreference:     policy settings (MAPSReporting, BaFS, CloudBlockLevel)
    # We merge both into one CSV row via Select-Object -Property *
    _PS_QUERY = (
        "powershell -NoP -C \""
        "$s=Get-MpComputerStatus; $p=Get-MpPreference; "
        "[PSCustomObject]@{"
        "RealTimeProtectionEnabled=$s.RealTimeProtectionEnabled;"
        "BehaviorMonitorEnabled=$s.BehaviorMonitorEnabled;"
        "AMServiceEnabled=$s.AMServiceEnabled;"
        "MAPSReporting=$p.MAPSReporting;"
        "DisableBlockAtFirstSeen=$p.DisableBlockAtFirstSeen;"
        "CloudBlockLevel=$p.CloudBlockLevel"
        "} | ConvertTo-Csv -NoTypeInformation\""
    )

    def __init__(
        self,
        backend: Any,
        domain: str,
        username: str,
        password: str,
        host: str,
        timeout: int = 20,
    ) -> None:
        self._backend = backend
        self._domain = domain
        self._username = username
        self._password = password
        self._host = host
        self._timeout = timeout

    def query(self) -> DefenderConfig:
        """Run the probe and return a :class:`DefenderConfig`.

        Always returns a value — never raises.  Sets ``probe_error`` on failure.
        """
        try:
            r = self._backend.execute_command(
                domain=self._domain,
                username=self._username,
                secret=self._password,
                command=self._PS_QUERY,
                host=self._host,
                timeout=self._timeout,
            )
            raw = (r.stdout or "").strip()
            return self._parse(raw)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(f"[defender_config_probe] query failed: {exc}")
            return DefenderConfig(probe_error=str(exc)[:120])

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse(raw: str) -> DefenderConfig:
        """Parse ConvertTo-Csv output into a DefenderConfig."""
        lines = [line for line in raw.splitlines() if line.strip() and line.strip() != "NULL"]
        if len(lines) < 2:
            return DefenderConfig(probe_error="no output from Get-MpComputerStatus")

        # First line = headers, second = values (CSV)
        headers = [h.strip('"') for h in lines[0].split(",")]
        values  = [v.strip('"') for v in lines[1].split(",")]
        row: dict[str, str] = dict(zip(headers, values))

        def _bool(key: str, true_if_false: bool = False) -> bool | None:
            """Parse True/False string; true_if_false inverts (e.g. DisableBaFS=False → BaFS=True)."""
            v = row.get(key, "").strip().lower()
            if v == "true":
                return not true_if_false if true_if_false else True
            if v == "false":
                return true_if_false if true_if_false else False
            return None

        def _maps() -> bool | None:
            """MAPSReporting: 0=disabled, 1=basic, 2=advanced."""
            v = row.get("MAPSReporting", "").strip()
            if v.isdigit():
                return int(v) > 0
            return None

        return DefenderConfig(
            rtp_enabled           = _bool("RealTimeProtectionEnabled"),
            cloud_enabled         = _maps(),
            behavior_enabled      = _bool("BehaviorMonitorEnabled"),
            block_at_first_sight  = _bool("DisableBlockAtFirstSeen", true_if_false=True),
            cloud_block_level     = row.get("CloudBlockLevel", "").strip() or None,
            am_service_enabled    = _bool("AMServiceEnabled"),
        )


__all__ = ["DefenderConfig", "DefenderConfigProbe"]
