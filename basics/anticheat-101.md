---
icon: shield-keyhole
---

# AntiCheat 101

## Fuck fest anticheat (sorry im frustrated cheating is much easier)

Anticheat systems aim to maintain a fair and enjoyable gaming environment by detecting and preventing unauthorized advantages without disrupting legitimate players. At their core, these systems balance proactive and reactive measures, such as code integrity checks, memory scanning, and behavior analysis, against the risk of false positives that could frustrate honest users. Because a game’s longterm revenue depends on player satisfaction, anticheat strategies prioritize minimal performance impact and seamless updates, ensuring security features do not degrade the user experience.&#x20;

Furthermore, developers must navigate legal boundaries (for example, respecting terms of service and avoiding overreach into protected system areas) and privacy concerns (collecting only necessary data, anonymizing logs, and complying with regulations like GDPR). By combining technical safeguards with clear policies and transparent communication, anticheat efforts protect both the integrity of gameplay and the trust of the player community.

#### Preventing vs Punishing

Preventing cheating is the primary objective of any anticheat system: robust measures are put in place to stop unauthorized tools or behavior before they can affect gameplay. If a player circumvents these defenses, the focus shifts to detecting malicious activity, such as memory tampering or network manipulation and applying appropriate penalties.

#### Effective punishments

Effective punishments are designed to deter repeat offenses and uphold a positive user experience. Sanctions range from temporary account suspensions to permanent bans, and can include hardware or network‐level restrictions. In particular, "hardware bans" (also known as trace bans) tie the restriction to device identifiers, making it significantly more difficult for banned users to return under a different account.

<figure><img src="../.gitbook/assets/head-anti-cheat-analyst-at-riot-games-shares-ban-numbers-v0-1e9vewrfouce1.webp" alt=""><figcaption><p><a href="https://x.com/deteccphilippe/status/1878950002632053203">https://x.com/deteccphilippe/status/1878950002632053203</a></p></figcaption></figure>

#### Technical possibilites and limitations

User‐mode anticheat tools operate entirely in the same privilege context as the game process, enabling techniques like inmemory scanning, API hooking, and behavioral analysis without requiring elevated rights. They can verify game file integrity, monitor suspicious function calls, and detect known cheat signatures by inspecting process memory or hooking graphics and input APIs. However, because they lack kernel level privileges, usermode solutions can be bypassed by more sophisticated attacks: for example, a cheat running in kernel mode can disable or tamper with usermode hooks, hide malicious modules from process listings, or use DMA to read and write memory without triggering usermode checks. In addition, performance considerations often limit how aggressively usermode tools can scan memory or run heuristics, risking both missed detections and false positives if patterns are too broad or too narrow.

Simple usermode hook:

```cpp
#include <windows.h>
#include "MinHook.h"

// Protected range in game’s address space
static const uintptr_t PROT_BASE = 0x00ABC000;
static const size_t    PROT_SIZE = 0x1000;  // [0x00ABC000 … 0x00ABD000)

typedef BOOL (WINAPI* tRPM)(
    HANDLE  hProcess,
    LPCVOID lpBaseAddress,
    LPVOID  lpBuffer,
    SIZE_T  nSize,
    SIZE_T* lpNumberOfBytesRead
);
static tRPM oReadProcessMemory = nullptr;

BOOL WINAPI hkReadProcessMemory(
    HANDLE  hProcess,
    LPCVOID lpBaseAddress,
    LPVOID  lpBuffer,
    SIZE_T  nSize,
    SIZE_T* lpNumberOfBytesRead
) {
    uintptr_t addr = (uintptr_t)lpBaseAddress;
    if (addr >= PROT_BASE && addr < PROT_BASE + PROT_SIZE) {
        OutputDebugStringA("AntiCheat: Protected range read detected!\n");
        // → Flag or counter‐measure here
    }
    return oReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, 
                              lpNumberOfBytesRead);
}

void InstallRPMHook() {
    MH_Initialize();
    MH_CreateHook(&ReadProcessMemory, &hkReadProcessMemory,
                  reinterpret_cast<LPVOID*>(&oReadProcessMemory));
    MH_EnableHook(&ReadProcessMemory);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        InstallRPMHook();
    }
    return TRUE;
}
```

Kernelmode anticheat drivers gain higher privileges, allowing them to intercept system calls, monitor all processes, and enforce memory protections at a lower level. This expanded access can prevent many usermode workarounds by validating code pages, blocking unauthorized code injections, or even disabling untrusted drivers before they load. Yet running in kernel space carries significant privacy and security implications. To detect cheats effectively, kernelmode components may need to read large portions of RAM, inspect network buffers, or log user input events, actions that can inadvertently capture sensitive information like passwords, personal files, or other applications’ memory contents. Because kernel drivers run with elevated rights, any flaw or backdoor can be exploited by malware to compromise the entire system. Consequently, anticheat designers must balance detection efficacy against strict data‐minimization practices, ensure transparent handling of collected data, and adhere to privacy regulations (e.g., GDPR), lest they expose users to undue risk.

Simple kmd hook example:

```cpp
#include <ntddk.h>

typedef NTSTATUS (NTAPI* tNtReadVM)(
    HANDLE    ProcessHandle,
    PVOID     BaseAddress,
    PVOID     Buffer,
    ULONG     NumberOfBytesToRead,
    PULONG    NumberOfBytesRead
);

extern PVOID* KeServiceDescriptorTableShadow; // Pointer to SSDT
static tNtReadVM  origNtReadVM = NULL;
static PEPROCESS  gGameProcess = NULL;
static const uintptr_t PROT_BASE = 0x00ABC000;
static const size_t    PROT_SIZE = 0x1000;  // [0x00ABC000 … 0x00ABD000)

// Hooked version of NtReadVirtualMemory
NTSTATUS HK_NtReadVM(
    HANDLE    ProcessHandle,
    PVOID     BaseAddress,
    PVOID     Buffer,
    ULONG     NumberOfBytesToRead,
    PULONG    NumberOfBytesRead
) {
    PEPROCESS targetProc;
    // 1. Get EPROCESS for the target handle
    if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessHandle, &targetProc))) {
        // 2. Compare with our game’s EPROCESS pointer
        if (targetProc == gGameProcess) {
            uintptr_t addr = (uintptr_t)BaseAddress;
            // 3. If read falls within protected range, flag it
            if (addr >= PROT_BASE && addr < PROT_BASE + PROT_SIZE) {
                DbgPrint("AntiCheat: Protected range read detected in kernel‐mode!\n");
                // → Could terminate or quarantine the calling process here
            }
        }
        ObDereferenceObject(targetProc);
    }
    // 4. Call the original NtReadVirtualMemory
    return origNtReadVM(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
}

// Installs the SSDT hook for NtReadVirtualMemory
VOID InstallKernelHook(PEPROCESS GameProcess) {
    // 1. Store the game’s EPROCESS pointer for later comparison
    gGameProcess = GameProcess;

    // 2. Locate the SSDT entry for NtReadVirtualMemory (index depends on Windows version)
    //    For illustration, assume index 0x3C; real code must discover it dynamically.
    const ULONG NtReadVM_Index = 0x3C; 
    PVOID* ssdt  = KeServiceDescriptorTableShadow[0]; 
    origNtReadVM = (tNtReadVM)ssdt[NtReadVM_Index];

    // 3. Replace the SSDT pointer with our hook
    KIRQL oldIrql = KeRaiseIrqlToDpcLevel();
    ssdt[NtReadVM_Index] = HK_NtReadVM;
    KeLowerIrql(oldIrql);
}

// Driver unload cleans up the hook
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    // Restore original SSDT entry
    const ULONG NtReadVM_Index = 0x3C;
    PVOID* ssdt = KeServiceDescriptorTableShadow[0];
    ssdt[NtReadVM_Index] = origNtReadVM;
    DbgPrint("AntiCheat: Kernel-mode detection driver unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;

    // 1. Find the EPROCESS for our game by PID (say, 1234)
    HANDLE gamePid = (HANDLE)1234;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(gamePid, &gGameProcess))) {
        DbgPrint("AntiCheat: Failed to find Game EPROCESS\n");
        return STATUS_UNSUCCESSFUL;
    }

    // 2. Install the SSDT hook
    InstallKernelHook(gGameProcess);
    DbgPrint("AntiCheat: Kernel-mode detection driver loaded\n");
    return STATUS_SUCCESS;
}
```
