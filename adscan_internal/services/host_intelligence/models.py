"""Generic host fingerprint dataclasses (AV/EDR detection only).

These types are shared by every consumer of host intelligence — the
remote-exec cascade, dump orchestrators, future post-ex techniques, etc.
LSASS-specific fields (PPL state, lsass PID) live in the
:mod:`adscan_internal.services.exploitation.host_fingerprint_service`
extension, never here.

No dependency on aiosmb or any I/O — keep this importable from tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from adscan_internal.services.host_intelligence.defender_config_probe import DefenderConfig

# Windows service Start values — re-exported for callers that classify
# detected products without re-deriving the constants.
SVC_START_BOOT = 0
SVC_START_SYSTEM = 1
SVC_START_AUTOMATIC = 2
SVC_START_MANUAL = 3
SVC_START_DISABLED = 4


@dataclass(frozen=True)
class DetectedProduct:
    """One AV/EDR product detected on a host.

    Attributes:
        name: Catalog display name (e.g. ``"Windows Defender"``).
        category: ``"av"`` or ``"edr"``.
        installed: True if the product's service key was found.
        running: True if a known IPC$ pipe for the product was seen.
        svc_start: Windows service ``Start`` DWORD (0-4); ``-1`` if
            unreadable.
        realtime_protection: False only for products whose RTP toggle is
            explicitly disabled (currently Defender ``DisableRealtimeMonitoring``).
        realtime_protection_confirmed: False when the product has an RTP
            toggle and its state could NOT be read, so ``realtime_protection``
            is an assumption ("on", the conservative choice for picking a
            technique) rather than an observation. Reporting reads
            :attr:`observed_active`, which never credits an assumption.
    """

    name: str
    category: str
    installed: bool
    running: bool
    svc_start: int
    realtime_protection: bool = True
    realtime_protection_confirmed: bool = True

    @property
    def active(self) -> bool:
        """True if the product is process-running AND its RTP is on.

        Conservative for OPSEC decisions: an RTP state that could not be read
        counts as on, so a technique is never chosen on the assumption that
        protection is off. NOT an observation; reporting reads
        :attr:`observed_active`.
        """
        process_running = self.running or (
            self.installed
            and self.svc_start
            in (SVC_START_BOOT, SVC_START_SYSTEM, SVC_START_AUTOMATIC)
        )
        return process_running and self.realtime_protection

    @property
    def activity_unconfirmed(self) -> bool:
        """True when ``active`` rests on an RTP state that was assumed, not read."""
        return self.active and not self.realtime_protection_confirmed

    @property
    def observed_active(self) -> bool:
        """True only when the product was OBSERVED protecting the host.

        The three-state doctrine: an assumed real-time-protection state is not
        an observation, so a product whose RTP toggle could not be read is
        never observed active, and never observed inactive either.
        """
        return self.active and self.realtime_protection_confirmed

    @property
    def status_label(self) -> str:
        """Human-readable status for display."""
        if not self.realtime_protection and self.running:
            return "EN EJECUCIÓN — RTP desactivado"
        if not self.realtime_protection and self.installed:
            return "INSTALADO — RTP desactivado"
        if self.running:
            return "ACTIVO (en ejecución)"
        if self.installed and self.svc_start == SVC_START_AUTOMATIC:
            return "ACTIVO (auto-start)"
        if self.installed and self.svc_start == SVC_START_MANUAL:
            return "INSTALADO (manual)"
        if self.installed and self.svc_start == SVC_START_DISABLED:
            return "INSTALADO (deshabilitado)"
        if self.installed:
            return "INSTALADO"
        return "DETECTADO (pipe)"


@dataclass
class HostFingerprint:
    """Generic AV/EDR fingerprint of a remote host.

    LSASS-specific extensions (``ppl_enabled``, ``ppl_level``,
    ``lsass_pid``) live in
    :class:`adscan_internal.services.exploitation.host_fingerprint_service.LsassHostFingerprint`.
    """

    target_ip: str
    products: list[DetectedProduct] = field(default_factory=list)
    defender_rtp: bool = True
    defender_rtp_state: Literal["on", "off", "unknown"] = "unknown"
    """What the Defender RTP read actually returned. ``defender_rtp`` stays the
    conservative boolean (unknown counts as on) for technique selection; this
    is the observation, and only ``on`` / ``off`` were read."""
    defender_cloud: bool | None = None
    """Cloud-delivered protection (MAPS). None = not yet probed."""
    defender_behavior: bool | None = None
    """Behavior monitoring. None = not yet probed."""
    defender_block_at_first_sight: bool | None = None
    """Block-at-first-sight. None = not yet probed."""
    elapsed_s: float = 0.0
    error: str | None = None
    winrm_available: Literal["available", "auth_failed", "port_closed", "unknown"] = "unknown"
    winrm_probed_at: datetime | None = None

    def enrich_from_defender_config(self, cfg: "DefenderConfig") -> None:
        """Merge a :class:`DefenderConfig` probe result into this fingerprint.

        Call this after running :class:`DefenderConfigProbe` via any transport
        (MSSQL xp_cmdshell, WinRM, etc.) to populate the cloud/behavior/BaFS
        fields that the SMB-based :class:`HostFingerprintService` cannot read.
        """
        if cfg.probe_error:
            return
        if cfg.rtp_enabled is not None:
            self.defender_rtp = cfg.rtp_enabled
            self.defender_rtp_state = "on" if cfg.rtp_enabled else "off"
        self.defender_cloud                = cfg.cloud_enabled
        self.defender_behavior             = cfg.behavior_enabled
        self.defender_block_at_first_sight = cfg.block_at_first_sight

    @property
    def has_edr(self) -> bool:
        """True if any EDR is *active* (not just installed)."""
        return any(p.category == "edr" and p.active for p in self.products)

    @property
    def has_edr_installed(self) -> bool:
        """True if any EDR is installed, even if disabled."""
        return any(p.category == "edr" and p.installed for p in self.products)

    @property
    def has_av(self) -> bool:
        """True if any AV is active."""
        return any(p.category == "av" and p.active for p in self.products)

    @property
    def detected_products(self) -> list[DetectedProduct]:
        return [p for p in self.products if p.installed or p.running]

    @property
    def active_products(self) -> list[DetectedProduct]:
        return [p for p in self.products if p.active]

    @property
    def observed_active_products(self) -> list[DetectedProduct]:
        """Products OBSERVED active (never on an assumed RTP state)."""
        return [p for p in self.products if p.observed_active]


__all__ = [
    "DetectedProduct",
    "HostFingerprint",
    "SVC_START_BOOT",
    "SVC_START_SYSTEM",
    "SVC_START_AUTOMATIC",
    "SVC_START_MANUAL",
    "SVC_START_DISABLED",
]
