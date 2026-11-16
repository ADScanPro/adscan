"""Machine identity and virtualisation facts for the PAL.

Two OS facts the telemetry installation identity needs, behind one API with a
POSIX and a Windows side:

* :func:`machine_identifier` returns the OS's own per-installation machine id
  (``/etc/machine-id`` on Linux, ``MachineGuid`` on Windows). It is RAW: callers
  must never send it anywhere. The only consumer, ``adscan_core.
  telemetry_identity``, feeds it straight into a keyed, app-specific hash.
* :func:`virtualization` returns a closed vocabulary describing what the OS
  runs on (bare metal, a hypervisor, WSL, a container). It is a property only:
  nothing here tries to infer the physical host behind a guest, because that
  cannot be done reliably from inside one.

Neither function raises. An unreadable source is ``None`` / ``"unknown"``, never
a guess, and neither one spawns a process on the hot path: Linux reads
``/sys`` and ``/proc`` first and only falls back to ``systemd-detect-virt``
when DMI is unreadable.
"""

from __future__ import annotations

import os
from pathlib import Path

from adscan_core.pal.platform import is_windows

__all__ = [
    "VIRTUALIZATION_VALUES",
    "classify_dmi_virtualization",
    "machine_identifier",
    "virtualization",
]

#: The closed vocabulary :func:`virtualization` returns. ``none`` means bare
#: metal was positively observed; ``unknown`` means the OS did not say.
VIRTUALIZATION_VALUES: frozenset[str] = frozenset(
    {"none", "kvm", "vmware", "virtualbox", "hyperv", "wsl", "container", "unknown"}
)

_LINUX_MACHINE_ID_PATHS = ("/etc/machine-id", "/var/lib/dbus/machine-id")
_DMI_ROOT = "/sys/class/dmi/id"

# systemd-detect-virt prints one token; map it into the closed vocabulary.
_SYSTEMD_DETECT_VIRT_MAP = {
    "none": "none",
    "kvm": "kvm",
    "qemu": "kvm",
    "amazon": "kvm",
    "google": "kvm",
    "vmware": "vmware",
    "oracle": "virtualbox",
    "microsoft": "hyperv",
    "wsl": "wsl",
    "docker": "container",
    "podman": "container",
    "lxc": "container",
    "lxc-libvirt": "container",
    "systemd-nspawn": "container",
    "rkt": "container",
    "openvz": "container",
    "container-other": "container",
}


def _read_text(path: str | Path) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read().strip()
    except OSError:
        return ""


def _windows_registry_value(subkey: str, name: str) -> str:
    """Read one ``HKLM`` string value on Windows, ``""`` on any failure."""

    try:
        import importlib  # noqa: PLC0415

        # Windows-only stdlib module, resolved at call time so this file
        # imports (and lints) cleanly on POSIX.
        winreg = importlib.import_module("winreg")

        access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0, access) as key:
            value, _kind = winreg.QueryValueEx(key, name)
        return str(value or "").strip()
    except Exception:  # noqa: BLE001 - absent key, no winreg, no access
        return ""


def machine_identifier() -> str | None:
    """Return the OS's raw machine id, or ``None`` when there is none.

    Linux: ``/etc/machine-id`` (then the D-Bus copy). Windows: the
    ``MachineGuid`` value under ``HKLM\\SOFTWARE\\Microsoft\\Cryptography``.
    Other POSIX systems (macOS) return ``None``: there is no file-backed id and
    a subprocess is not worth it for a telemetry property.

    The value is raw and must never leave the process unhashed.
    """

    if is_windows():
        value = _windows_registry_value(r"SOFTWARE\Microsoft\Cryptography", "MachineGuid")
        return value or None
    for candidate in _LINUX_MACHINE_ID_PATHS:
        value = _read_text(candidate)
        if value:
            return value
    return None


def classify_dmi_virtualization(vendor: str, product: str) -> str | None:
    """Map a firmware vendor / product pair onto the vocabulary.

    Returns ``None`` when the pair names no known hypervisor, so the caller
    decides between ``none`` and ``unknown`` from other evidence.
    """

    text = f"{vendor} {product}".lower()
    if not text.strip():
        return None
    if "virtualbox" in text or "innotek" in text:
        return "virtualbox"
    if "vmware" in text:
        return "vmware"
    if "microsoft corporation" in text and "virtual" in text:
        return "hyperv"
    if (
        "qemu" in text
        or "kvm" in text
        or "amazon ec2" in text
        or "google compute engine" in text
        or "openstack" in text
    ):
        return "kvm"
    return None


def _cpu_reports_hypervisor() -> bool:
    for line in _read_text("/proc/cpuinfo").splitlines():
        if line.startswith("flags") and " hypervisor" in f" {line.partition(':')[2]} ":
            return True
    return False


def _linux_in_container() -> bool:
    if os.environ.get("ADSCAN_CONTAINER_RUNTIME") == "1":
        return True
    for marker in ("/.dockerenv", "/run/.containerenv"):
        if os.path.exists(marker):
            return True
    return False


def _linux_is_wsl() -> bool:
    release = _read_text("/proc/sys/kernel/osrelease").lower()
    return "microsoft" in release or "wsl" in release


def _systemd_detect_virt() -> str | None:
    import shutil  # noqa: PLC0415
    import subprocess  # noqa: PLC0415

    binary = shutil.which("systemd-detect-virt")
    if not binary:
        return None
    try:
        completed = subprocess.run(  # noqa: S603 - fixed binary, no shell
            [binary],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except Exception:  # noqa: BLE001
        return None
    token = (completed.stdout or "").strip().lower()
    return _SYSTEMD_DETECT_VIRT_MAP.get(token, "unknown" if token else None)


def _linux_virtualization(dmi_root: str) -> str:
    if _linux_in_container():
        return "container"
    if _linux_is_wsl():
        return "wsl"
    vendor = _read_text(os.path.join(dmi_root, "sys_vendor"))
    product = _read_text(os.path.join(dmi_root, "product_name"))
    if vendor or product:
        known = classify_dmi_virtualization(vendor, product)
        if known:
            return known
        # DMI names no hypervisor we map. A CPU still flagging a hypervisor is a
        # guest of something else (Xen, Parallels): say so honestly.
        return "unknown" if _cpu_reports_hypervisor() else "none"
    detected = _systemd_detect_virt()
    if detected:
        return detected
    return "unknown"


def _windows_virtualization() -> str:
    bios = r"HARDWARE\DESCRIPTION\System\BIOS"
    vendor = _windows_registry_value(bios, "SystemManufacturer")
    product = _windows_registry_value(bios, "SystemProductName")
    if not (vendor or product):
        return "unknown"
    return classify_dmi_virtualization(vendor, product) or "none"


def virtualization(*, dmi_root: str | None = None) -> str:
    """Return what this OS runs on, as one of :data:`VIRTUALIZATION_VALUES`.

    Args:
        dmi_root: Override the Linux DMI directory (tests).

    Returns:
        ``none`` / ``kvm`` / ``vmware`` / ``virtualbox`` / ``hyperv`` / ``wsl``
        / ``container`` / ``unknown``. Never raises.
    """

    try:
        if is_windows():
            return _windows_virtualization()
        if not os.path.isdir(dmi_root or _DMI_ROOT) and not os.path.isdir("/proc"):
            # macOS and other POSIX without /sys or /proc: no cheap signal.
            return "unknown"
        return _linux_virtualization(dmi_root or _DMI_ROOT)
    except Exception:  # noqa: BLE001 - a property, never a failure
        return "unknown"
