"""
SysWhispers4 - Data Models
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Optional


class Architecture(str, Enum):
    x64   = "x64"
    x86   = "x86"
    WoW64 = "wow64"
    ARM64 = "arm64"

    def __str__(self) -> str:
        return self.value


class Compiler(str, Enum):
    MSVC  = "msvc"    # ml64.exe / MASM
    MinGW = "mingw"   # x86_64-w64-mingw32-gcc (GAS inline asm)
    Clang = "clang"   # clang-cl / GAS inline asm

    def __str__(self) -> str:
        return self.value


class InvocationMethod(str, Enum):
    """How the syscall instruction is executed."""
    Embedded    = "embedded"    # syscall in our stub (direct syscall)
    Indirect    = "indirect"    # jmp to syscall;ret gadget in ntdll
    Randomized  = "randomized"  # jmp to RANDOM syscall;ret gadget in ntdll
    Egg         = "egg"         # egg marker replaced at runtime with syscall

    def __str__(self) -> str:
        return self.value


class ResolutionMethod(str, Enum):
    """How the Syscall Service Number (SSN) is obtained."""
    Static        = "static"         # Embedded from j00ru table at generation time
    FreshyCalls   = "freshycalls"    # Sort ntdll Nt* exports by VA -> index = SSN
    HellsGate     = "hells_gate"     # Read SSN from ntdll stub opcode bytes
    HalosGate     = "halos_gate"     # HellsGate + neighbor scan when hooked
    TartarusGate  = "tartarus"       # HalosGate + handles near/far JMP hooks
    SyscallsFromDisk = "from_disk"   # Load clean ntdll from KnownDlls/disk, read SSNs
    RecycledGate  = "recycled"       # Combine: sort by VA + validate with opcode check
    HWBreakpoint  = "hw_breakpoint"  # Hardware breakpoints + VEH to extract SSN

    def __str__(self) -> str:
        return self.value


@dataclass
class SyscallParam:
    name:       str
    type:       str
    annotation: str = ""

    def c_declaration(self) -> str:
        """Return 'TYPE NAME' string for C function parameter."""
        return f"{self.type} {self.name}"


@dataclass
class SyscallPrototype:
    name:        str
    return_type: str
    params:      List[SyscallParam] = field(default_factory=list)

    @property
    def param_count(self) -> int:
        return len(self.params)

    def c_signature(self, prefix: str = "") -> str:
        """Return C function signature (without semicolon)."""
        func_name = f"{prefix}{self.name}" if prefix else self.name
        param_str = ", ".join(p.c_declaration() for p in self.params)
        return f"{self.return_type} NTAPI {func_name}({param_str})"

    def c_prototype(self, prefix: str = "") -> str:
        return self.c_signature(prefix) + ";"


@dataclass
class GeneratorConfig:
    # Syscall selection
    functions:   List[str] = field(default_factory=list)

    # Target options
    arch:        Architecture     = Architecture.x64
    compiler:    Compiler         = Compiler.MSVC
    method:      InvocationMethod = InvocationMethod.Embedded
    resolve:     ResolutionMethod = ResolutionMethod.FreshyCalls

    # Output options
    out_file:    str = "SW4Syscalls"
    out_dir:     str = "."
    prefix:      str = "SW4"

    # Obfuscation / evasion options
    obfuscate:    bool = False    # Randomize stub/function name prefix
    encrypt_ssn:  bool = False    # XOR-encrypt SSN table at rest
    stack_spoof:  bool = False    # Include synthetic call stack frame
    etw_bypass:   bool = False    # Include ETW user-mode patch
    amsi_bypass:  bool = False    # Include AMSI patch (AmsiScanBuffer)
    unhook_ntdll: bool = False    # Remap clean ntdll .text over hooked one
    anti_debug:   bool = False    # Anti-debugging checks (PEB, timing, instrumentation)
    sleep_encrypt: bool = False   # Sleep obfuscation with memory encryption (Ekko-style)
    string_encrypt: bool = False  # Compile-time string encryption

    # Static resolution: path to syscall table JSON
    syscall_table: Optional[str] = None

    # Internal: resolved data (populated by generator)
    _prototypes:  List[SyscallPrototype] = field(default_factory=list, repr=False)
    _ssn_table:   dict = field(default_factory=dict, repr=False)  # name -> {build: ssn}

    def files(self) -> dict[str, str]:
        """Return map of {filename: extension} for generated files."""
        base = self.out_file
        files = {
            f"{base}_Types.h":    "h",
            f"{base}.h":          "h",
            f"{base}.c":          "c",
        }
        if self.compiler == Compiler.MSVC:
            files[f"{base}.asm"] = "asm"
        else:
            # MinGW/Clang use inline assembly embedded in C
            pass
        return files
