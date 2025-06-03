#include <windows.h>
#include <winternl.h>
#include <ntstatus.h> 
#include <iostream>
#include <vector>
#include <set>
#include <algorithm>

// Definitions for NtQuerySystemInformation(SystemHandleInformation)
typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength
    );
#define SystemHandleInformation 16

// Structure for a single handle entry
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID  Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO;

// Top-level structure returned by NtQuerySystemInformation
typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG                            NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO   Handles[1];
} SYSTEM_HANDLE_INFORMATION;

// Change these to whatever PIDs you consider “trusted” (e.g., launcher, updater, etc.)
static const std::set<USHORT> WHITELISTED_PIDS = {
    // Example:  4321,  8765
    4321, 8765
};

// Color‐helper:  red = 12, green = 10, default = 7
void SetColor(int color) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(h, (WORD)color);
}

int main() {
    SetConsoleTitleA("AntiCheat - process_handle monitor");
    DWORD myPid = GetCurrentProcessId();
    std::set<USHORT> knownPids;  // which PIDs already had a handle (within whitelist or not)
    NtQuerySystemInformation_t NtQuerySystemInformation =
        (NtQuerySystemInformation_t)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"),
            "NtQuerySystemInformation"
        );
    if (!NtQuerySystemInformation) {
        std::cerr << "ERROR: NtQuerySystemInformation not found.\n";
        return 1;
    }

    std::cout << "[*] GameProcessMonitor (whitelist) started (PID=" << myPid << ")\n";
    std::cout << "[*] Trusted PIDs: ";
    for (auto pid : WHITELISTED_PIDS) {
        std::cout << pid << " ";
    }
    std::cout << "\n";

    // Initial pass: record any existing handles (trusted or not)
    {
        ULONG bufSize = 0x10000;
        std::vector<BYTE> buffer;
        while (true) {
            buffer.resize(bufSize);
            ULONG retLen = 0;
            NTSTATUS status = NtQuerySystemInformation(
                SystemHandleInformation,
                buffer.data(),
                bufSize,
                &retLen
            );
            if (status == STATUS_INFO_LENGTH_MISMATCH) {
                bufSize = retLen + 0x1000;
                continue;
            }
            if (!NT_SUCCESS(status)) {
                std::cerr << "ERROR: Initial query failed (0x"
                    << std::hex << status << ")\n";
                return 1;
            }
            auto* info = (SYSTEM_HANDLE_INFORMATION*)buffer.data();
            for (ULONG i = 0; i < info->NumberOfHandles; i++) {
                auto& e = info->Handles[i];
                if (e.UniqueProcessId == myPid) continue;

                // Duplicate into our process to confirm it really points at us
                HANDLE hSourceProc = OpenProcess(
                    PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
                    FALSE,
                    (DWORD)e.UniqueProcessId
                );
                if (!hSourceProc) continue;

                HANDLE dupHandle = NULL;
                if (DuplicateHandle(
                    hSourceProc,
                    (HANDLE)(ULONG_PTR)e.HandleValue,
                    GetCurrentProcess(),
                    &dupHandle,
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    FALSE,
                    0
                )) {
                    if (GetProcessId(dupHandle) == myPid) {
                        knownPids.insert(e.UniqueProcessId);
                    }
                    CloseHandle(dupHandle);
                }
                CloseHandle(hSourceProc);
            }
            break;
        }
    }

    // Poll loop: every 3 seconds, look for new or unauthorized handles
    while (true) {
        ULONG bufSize = 0x10000;
        std::vector<BYTE> buffer;

        while (true) {
            buffer.resize(bufSize);
            ULONG retLen = 0;
            NTSTATUS status = NtQuerySystemInformation(
                SystemHandleInformation,
                buffer.data(),
                bufSize,
                &retLen
            );
            if (status == STATUS_INFO_LENGTH_MISMATCH) {
                bufSize = retLen + 0x1000;
                continue;
            }
            if (!NT_SUCCESS(status)) {
                std::cerr << "ERROR: Query failed (0x"
                    << std::hex << status << ")\n";
                return 1;
            }
            auto* info = (SYSTEM_HANDLE_INFORMATION*)buffer.data();
            for (ULONG i = 0; i < info->NumberOfHandles; i++) {
                auto& e = info->Handles[i];
                USHORT pid = e.UniqueProcessId;
                if (pid == myPid) continue;  // ignore self‐handles

                // If we've already processed this PID (whitelisted or not), skip
                if (knownPids.find(pid) != knownPids.end()) continue;

                // Duplicate handle into our process to see what it points at
                HANDLE hSourceProc = OpenProcess(
                    PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
                    FALSE,
                    (DWORD)pid
                );
                if (!hSourceProc) continue;

                HANDLE dupHandle = NULL;
                if (DuplicateHandle(
                    hSourceProc,
                    (HANDLE)(ULONG_PTR)e.HandleValue,
                    GetCurrentProcess(),
                    &dupHandle,
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    FALSE,
                    0
                )) {
                    // If it really refers to us...
                    if (GetProcessId(dupHandle) == myPid) {
                        knownPids.insert(pid);

                        // Check if this PID is whitelisted
                        if (WHITELISTED_PIDS.count(pid)) {
                            // Log in green
                            SetColor(10);  // LIGHT_GREEN
                            std::cout << "[+] Whitelisted handle detected: PID=" << pid << "\n";
                        }
                        else {
                            // Not whitelisted: forcibly close the source handle
                            BOOL closed = DuplicateHandle(
                                hSourceProc,
                                (HANDLE)(ULONG_PTR)e.HandleValue,
                                NULL,
                                NULL,
                                0,
                                0,
                                DUPLICATE_CLOSE_SOURCE
                            );
                            // Log in red
                            SetColor(12);  // LIGHT_RED
                            if (closed) {
                                std::cout << "[!!!] Closed unauthorized handle from PID=" << pid << "\n";
                            }
                            else {
                                std::cout << "[!!!] Failed to close handle from PID=" << pid
                                    << " (Error=" << GetLastError() << ")\n";
                            }
                        }
                        SetColor(7);  // DEFAULT
                    }
                    CloseHandle(dupHandle);
                }
                CloseHandle(hSourceProc);
            }
            break;
        }
        Sleep(3000);
    }
    return 0;
}
