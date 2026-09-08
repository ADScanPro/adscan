#!/usr/bin/env python3
"""
SysWhispers4 -- Direct/Indirect/Randomized/Egg Syscall Generator
Windows 7 through Windows 11 24H2 -- x64 -- x86 -- WoW64 -- ARM64

Techniques implemented:
  SSN Resolution : Static | FreshyCalls | Hell's Gate | Halo's Gate |
                   Tartarus' Gate | SyscallsFromDisk | RecycledGate | HW Breakpoint
  Invocation     : Embedded (direct) | Indirect | Randomized Indirect | Egg Hunt
  Evasion        : XOR SSN encryption | Call stack spoofing | ETW bypass |
                   AMSI bypass | ntdll unhooking | Anti-debug | Sleep encryption
  Compilers      : MSVC (MASM) | MinGW | Clang

Usage examples:
  python syswhispers.py --preset common
  python syswhispers.py --preset injection --method indirect --resolve freshycalls
  python syswhispers.py --preset stealth --method randomized --resolve recycled \\
                         --obfuscate --encrypt-ssn --etw-bypass --amsi-bypass
  python syswhispers.py --preset all --method egg --resolve from_disk \\
                         --unhook-ntdll --anti-debug --stack-spoof
  python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx \\
                         --method randomized --resolve tartarus --obfuscate

References:
  SysWhispers  : https://github.com/jthuraisamy/SysWhispers
  SysWhispers2 : https://github.com/jthuraisamy/SysWhispers2
  SysWhispers3 : https://github.com/klezVirus/SysWhispers3
  Syscall table: https://github.com/j00ru/windows-syscalls
  Hell's Gate  : https://github.com/am0nsec/HellsGate
  Halo's Gate  : https://sektor7.net
  Tartarus'Gate: https://github.com/trickster0/TartarusGate
  FreshyCalls  : https://github.com/crummie5/FreshyCalls
  RecycledGate : https://github.com/thefLink/RecycledGate
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Allow running from the project root without installing the package
sys.path.insert(0, str(Path(__file__).parent))

from core.models import (
    Architecture, Compiler, GeneratorConfig,
    InvocationMethod, ResolutionMethod,
)
from core.generator import SysWhispers4
from core.utils import banner, load_presets, load_prototypes


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

def _resolve_functions(args) -> list[str]:
    """Expand preset names and/or comma-separated function lists."""
    functions: list[str] = []

    if args.preset:
        presets = load_presets()
        for p in args.preset.split(","):
            p = p.strip()
            if p not in presets:
                print(f"[!] Unknown preset '{p}'. Available: {', '.join(presets)}")
                sys.exit(1)
            functions.extend(presets[p]["functions"])

    if args.functions:
        for f in args.functions.split(","):
            f = f.strip()
            if f and f not in functions:
                functions.append(f)

    # Deduplicate while preserving order
    seen = set()
    result = []
    for f in functions:
        if f not in seen:
            seen.add(f)
            result.append(f)

    return result


def _validate_functions(functions: list[str]) -> None:
    known = set(load_prototypes().keys())
    unknown = [f for f in functions if f not in known]
    if unknown:
        print(f"[!] Unknown function(s): {', '.join(unknown)}")
        print(f"    Available: {', '.join(sorted(known))}")
        sys.exit(1)


def _print_banner() -> None:
    print(banner())
    print("  Version : 4.1.0")
    print("  Author  : CyberSecurityUP / community")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="syswhispers.py",
        description="SysWhispers4 -- NT syscall stub generator with advanced EDR evasion",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Resolution methods:
  static        Embed SSNs from bundled j00ru table (run update_syscall_table.py first)
  freshycalls   Sort ntdll Nt* exports by VA -> index = SSN  [DEFAULT, hook-resistant]
  hells_gate    Read SSN from ntdll stub (fails if hooked)
  halos_gate    Hell's Gate + neighbor scan to handle hooked functions
  tartarus      Tartarus' Gate: handles near JMP (E9) and far JMP (FF 25) hooks
  from_disk     Load clean ntdll from \\KnownDlls and read SSNs (bypasses ALL hooks)
  recycled      RecycledGate: FreshyCalls + opcode cross-validation (most resilient)
  hw_breakpoint Hardware breakpoints + VEH to extract SSN (advanced)

Invocation methods:
  embedded      syscall instruction in our stub -- direct syscall  [DEFAULT]
  indirect      jmp to syscall;ret gadget inside ntdll (RIP appears in ntdll)
  randomized    jmp to a RANDOM syscall;ret gadget in ntdll per call (anti-RIP)
  egg           8-byte egg marker replaced at runtime -- no static syscall bytes

Presets:
  common        General process/thread/memory operations (25 functions)
  injection     Process/shellcode injection via APC, threads, sections (20 functions)
  evasion       AV/EDR evasion queries and operations (15 functions)
  token         Token manipulation (6 functions)
  stealth       Maximum evasion: injection + evasion + unhooking (31 functions)
  file_ops      File I/O via NT syscalls (7 functions)
  transaction   Process doppelganging / transaction rollback (7 functions)
  all           All supported functions (62 functions)

Examples:
  python syswhispers.py --preset common
  python syswhispers.py --preset stealth --method randomized --resolve recycled \\
                         --obfuscate --encrypt-ssn --stack-spoof --etw-bypass
  python syswhispers.py --preset injection --method indirect --resolve from_disk \\
                         --unhook-ntdll --amsi-bypass
  python syswhispers.py --preset all --method egg --resolve tartarus \\
                         --anti-debug --sleep-encrypt
""",
    )

    # ---- Function selection -----------------------------------------------
    sel = p.add_argument_group("Function selection (at least one required)")
    sel.add_argument(
        "-p", "--preset",
        metavar="PRESET[,PRESET...]",
        help="Preset: common, injection, evasion, token, stealth, file_ops, transaction, all",
    )
    sel.add_argument(
        "-f", "--functions",
        metavar="FUNC[,FUNC...]",
        help="Comma-separated list of NT function names",
    )

    # ---- Architecture / compiler ------------------------------------------
    tgt = p.add_argument_group("Target")
    tgt.add_argument(
        "-a", "--arch",
        choices=[a.value for a in Architecture],
        default=Architecture.x64.value,
        metavar="ARCH",
        help="Target architecture: x64 (default), x86, wow64, arm64",
    )
    tgt.add_argument(
        "-c", "--compiler",
        choices=[c.value for c in Compiler],
        default=Compiler.MSVC.value,
        metavar="COMPILER",
        help="Compiler: msvc (default, MASM), mingw (GAS inline), clang (GAS inline)",
    )

    # ---- Techniques -------------------------------------------------------
    tech = p.add_argument_group("Techniques")
    tech.add_argument(
        "-m", "--method",
        choices=[m.value for m in InvocationMethod],
        default=InvocationMethod.Embedded.value,
        metavar="METHOD",
        help="Invocation: embedded (default), indirect, randomized, egg",
    )
    tech.add_argument(
        "-r", "--resolve",
        choices=[r.value for r in ResolutionMethod],
        default=ResolutionMethod.FreshyCalls.value,
        metavar="RESOLVE",
        help="SSN resolution: freshycalls (default), static, hells_gate, halos_gate, "
             "tartarus, from_disk, recycled, hw_breakpoint",
    )

    # ---- Evasion options --------------------------------------------------
    eva = p.add_argument_group("Evasion / obfuscation")
    eva.add_argument(
        "--obfuscate",
        action="store_true",
        help="Randomize stub ordering and inject junk instructions",
    )
    eva.add_argument(
        "--encrypt-ssn",
        action="store_true",
        help="XOR-encrypt SSN values at rest (decrypted at runtime)",
    )
    eva.add_argument(
        "--stack-spoof",
        action="store_true",
        help="Include synthetic call stack frame helper (reduces stack anomaly)",
    )
    eva.add_argument(
        "--etw-bypass",
        action="store_true",
        help="Include optional user-mode ETW writer patch (see SW4PatchEtw)",
    )
    eva.add_argument(
        "--amsi-bypass",
        action="store_true",
        help="Include AMSI bypass (patches AmsiScanBuffer)",
    )
    eva.add_argument(
        "--unhook-ntdll",
        action="store_true",
        help="Include ntdll unhooking (remaps clean .text from KnownDlls)",
    )
    eva.add_argument(
        "--anti-debug",
        action="store_true",
        help="Include anti-debugging checks (PEB, timing, heap flags, debug port)",
    )
    eva.add_argument(
        "--sleep-encrypt",
        action="store_true",
        help="Include sleep encryption (Ekko-style XOR .text during sleep)",
    )

    # ---- Static table override -------------------------------------------
    p.add_argument(
        "--syscall-table",
        metavar="PATH",
        help="Path to custom syscall table JSON (for --resolve static)",
    )

    # ---- Output -----------------------------------------------------------
    out = p.add_argument_group("Output")
    out.add_argument(
        "--prefix",
        default="SW4",
        metavar="PREFIX",
        help="Prefix for all generated identifiers (default: SW4)",
    )
    out.add_argument(
        "-o", "--out-file",
        default=None,
        metavar="OUTFILE",
        help="Output filename base (default: <PREFIX>Syscalls)",
    )
    out.add_argument(
        "--out-dir",
        default=".",
        metavar="OUTDIR",
        help="Output directory (default: current directory)",
    )

    # ---- Misc -------------------------------------------------------------
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    p.add_argument(
        "--list-functions",
        action="store_true",
        help="Print all available function names and exit",
    )
    p.add_argument(
        "--list-presets",
        action="store_true",
        help="Print all available presets and exit",
    )

    return p


def main() -> None:
    _print_banner()
    parser = build_parser()
    args = parser.parse_args()

    # ---- Info commands ---------------------------------------------------
    if args.list_functions:
        proto = load_prototypes()
        print(f"  Available functions ({len(proto)}):")
        for name in sorted(proto):
            entry = proto[name]
            n_params = len(entry.get("params", []))
            print(f"    {name} ({n_params} params)")
        return

    if args.list_presets:
        presets = load_presets()
        print("  Available presets:")
        for name, data in presets.items():
            funcs = data["functions"]
            print(f"    {name:14s} -- {data['description']}")
            print(f"                ({len(funcs)} functions: {', '.join(funcs[:4])}{'...' if len(funcs) > 4 else ''})")
        return

    # ---- Validate inputs -------------------------------------------------
    if not args.preset and not args.functions:
        parser.error("Specify at least --preset or --functions.")

    functions = _resolve_functions(args)
    if not functions:
        parser.error("No functions selected.")

    _validate_functions(functions)

    # ---- Warn about static resolution ------------------------------------
    if args.resolve == ResolutionMethod.Static.value:
        table_path = args.syscall_table or str(Path(__file__).parent / "data" / "syscalls_nt_x64.json")
        print(f"  [i] Static resolution: using table from {table_path}")
        print( "  [i] Run scripts/update_syscall_table.py to fetch the latest j00ru table.\n")

    if args.etw_bypass:
        print("  [!] ETW bypass enabled -- for authorized use only.\n")
    if args.amsi_bypass:
        print("  [!] AMSI bypass enabled -- for authorized use only.\n")
    if args.unhook_ntdll:
        print("  [!] ntdll unhooking enabled -- for authorized use only.\n")

    # ---- Build config ----------------------------------------------------
    prefix_clean = args.prefix.rstrip("_")
    out_file = args.out_file if args.out_file is not None else f"{prefix_clean}Syscalls"
    cfg = GeneratorConfig(
        functions       = functions,
        arch            = Architecture(args.arch),
        compiler        = Compiler(args.compiler),
        method          = InvocationMethod(args.method),
        resolve         = ResolutionMethod(args.resolve),
        prefix          = prefix_clean + "_",
        out_file        = out_file,
        out_dir         = args.out_dir,
        obfuscate       = args.obfuscate,
        encrypt_ssn     = args.encrypt_ssn,
        stack_spoof     = args.stack_spoof,
        etw_bypass      = args.etw_bypass,
        amsi_bypass     = args.amsi_bypass,
        unhook_ntdll    = args.unhook_ntdll,
        anti_debug      = args.anti_debug,
        sleep_encrypt   = args.sleep_encrypt,
        syscall_table   = args.syscall_table,
    )

    # ---- Summary ---------------------------------------------------------
    print(f"  Functions  : {len(functions)}")
    print(f"  Arch       : {cfg.arch}")
    print(f"  Compiler   : {cfg.compiler}")
    print(f"  Resolution : {cfg.resolve}")
    print(f"  Method     : {cfg.method}")
    print(f"  Prefix     : {cfg.prefix}")
    if cfg.obfuscate:     print( "  Obfuscate  : yes (stub reordering + junk instructions)")
    if cfg.encrypt_ssn:   print( "  Encrypt SSN: yes (XOR key embedded at compile time)")
    if cfg.stack_spoof:   print( "  Stack spoof: yes (synthetic call stack helper)")
    if cfg.etw_bypass:    print( "  ETW bypass : yes (user-mode EtwEventWrite patch)")
    if cfg.amsi_bypass:   print( "  AMSI bypass: yes (AmsiScanBuffer patch)")
    if cfg.unhook_ntdll:  print( "  Unhook     : yes (remap clean ntdll from KnownDlls)")
    if cfg.anti_debug:    print( "  Anti-debug : yes (PEB, timing, heap, debug port, instrumentation)")
    if cfg.sleep_encrypt: print( "  Sleep crypt: yes (Ekko-style XOR .text during sleep)")
    print()

    # ---- Generate --------------------------------------------------------
    gen = SysWhispers4(cfg)

    try:
        outputs = gen.generate()
    except Exception as exc:
        print(f"[!] Generation failed: {exc}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    gen.write_outputs(outputs)

    # ---- Usage hint ------------------------------------------------------
    print()
    print("  [*] Integration guide:")
    out_base = cfg.out_file
    if cfg.compiler == Compiler.MSVC:
        print(f"      Add to MSVC project:")
        print(f"        {out_base}_Types.h  {out_base}.h  {out_base}.c  {out_base}.asm")
        print(f"      Enable MASM: Project -> Build Customizations -> masm (.targets)")
        if cfg.method == InvocationMethod.Egg:
            print(f"      Call {cfg.prefix}HatchEggs() before any syscall functions.")
        elif cfg.resolve != ResolutionMethod.Static or cfg.method != InvocationMethod.Embedded:
            print(f"      Call {cfg.prefix}Initialize() at startup.")
    else:
        print(f"      Add to MinGW/Clang project:")
        print(f"        {out_base}_Types.h  {out_base}.h  {out_base}.c  {out_base}_stubs.c")
        print(f"      Compile with: -masm=intel")
        print(f"      Call {cfg.prefix}Initialize() at startup.")

    if cfg.unhook_ntdll:
        print(f"      Call {cfg.prefix}UnhookNtdll() BEFORE {cfg.prefix}Initialize() for best results.")
    if cfg.etw_bypass:
        print(f"      Optionally call {cfg.prefix}PatchEtw() to suppress user-mode ETW.")
    if cfg.amsi_bypass:
        print(f"      Optionally call {cfg.prefix}PatchAmsi() to bypass AMSI scanning.")
    if cfg.anti_debug:
        print(f"      Call {cfg.prefix}AntiDebugCheck() to verify clean environment.")
    if cfg.sleep_encrypt:
        print(f"      Use {cfg.prefix}SleepEncrypt(ms) instead of Sleep() to encrypt memory during sleep.")

    print()
    print("  [+] Done.")


if __name__ == "__main__":
    main()
