"""
SysWhispers4 - Utility Functions
"""
from __future__ import annotations
import json
import os
import struct
from pathlib import Path
from typing import Any


DATA_DIR = Path(__file__).parent.parent / "data"


def load_json(path: Path | str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_prototypes() -> dict:
    return load_json(DATA_DIR / "prototypes.json")


def load_presets() -> dict:
    return load_json(DATA_DIR / "presets.json")


def load_ssn_table_x64() -> dict:
    return load_json(DATA_DIR / "syscalls_nt_x64.json")


def load_ssn_table_x86() -> dict:
    path = DATA_DIR / "syscalls_nt_x86.json"
    if path.exists():
        return load_json(path)
    return {}


def djb2_hash(name: str) -> int:
    """DJB2 hash of a function name (32-bit)."""
    h = 0x1505
    for ch in name.encode("ascii"):
        h = (((h << 5) + h) ^ ch) & 0xFFFFFFFF
    return h


def ror13_hash(name: str) -> int:
    """ROR-13 hash (used by Metasploit/PEB walker convention)."""
    h = 0
    for ch in name.encode("ascii"):
        h = (((h >> 13) | (h << 19)) & 0xFFFFFFFF) + ch
    return h & 0xFFFFFFFF


def crc32_hash(name: str) -> int:
    """CRC32 hash of a function name (unsigned 32-bit)."""
    crc = 0xFFFFFFFF
    for ch in name.encode("ascii"):
        crc ^= ch
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xEDB88320
            else:
                crc >>= 1
    return crc ^ 0xFFFFFFFF


def fnv1a_hash(name: str) -> int:
    """FNV-1a hash of a function name (32-bit)."""
    h = 0x811C9DC5
    for ch in name.encode("ascii"):
        h = ((h ^ ch) * 0x01000193) & 0xFFFFFFFF
    return h


def get_current_build_from_table(ssn_table: dict, func_name: str) -> int | None:
    """
    Return the SSN for the most recent Windows build in the table.
    Used when the exact build number is not specified.
    """
    entry = ssn_table.get(func_name)
    if not entry:
        return None
    # Find the highest build number key (skip comment keys starting with _)
    numeric_keys = [k for k in entry.keys() if k.isdigit()]
    if not numeric_keys:
        return None
    latest_build = max(numeric_keys, key=int)
    return entry[latest_build]


def get_ssn_for_build(ssn_table: dict, func_name: str, build: int) -> int | None:
    """Return SSN for a specific Windows build number."""
    entry = ssn_table.get(func_name)
    if not entry:
        return None
    # Exact match first
    if str(build) in entry:
        return entry[str(build)]
    # Find nearest build <= requested
    numeric_keys = sorted([int(k) for k in entry.keys() if k.isdigit()])
    candidates = [b for b in numeric_keys if b <= build]
    if candidates:
        return entry[str(candidates[-1])]
    return None


def xor_key_bytes(data: list[int], key: int) -> list[int]:
    """XOR each DWORD in data with key (for SSN encryption)."""
    return [v ^ key for v in data]


def banner() -> str:
    return r"""
  ____         __        ___     _                        _  _
 / ___|  _   _ \ \      / / |__ (_)___  _ __   ___ _ __ | || |
 \___ \ | | | | \ \ /\ / /| '_ \| / __|| '_ \ / _ \ '__|| || |_
  ___) || |_| |  \ V  V / | | | | \__ \| |_) |  __/ |   |__   _|
 |____/  \__, |   \_/\_/  |_| |_|_|___/| .__/ \___|_|      |_|
          |___/                         |_|
 Direct/Indirect/Randomized/Egg Syscalls - Windows 7 through 11 24H2
 Techniques: FreshyCalls | Hell's/Halo's/Tartarus' Gate | RecycledGate
             SyscallsFromDisk | HW Breakpoint
 Methods:    Embedded | Indirect | Randomized | Egg Hunt
 Evasion:    ETW Bypass | AMSI Bypass | ntdll Unhooking | Anti-Debug
             Sleep Encryption | Stack Spoofing | SSN Encryption
 Arches:     x64 | x86 | WoW64 | ARM64
"""
