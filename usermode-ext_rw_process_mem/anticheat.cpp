#include <windows.h>
#include <winternl.h>   // NtQuerySystemInformation
#include <ntstatus.h>   // STATUS_INFO_LENGTH_MISMATCH, NT_SUCCESS
#include <iostream>
#include <vector>
#include <set>
#include <thread>
#include <chrono>
#include <sstream>
#include <iomanip>

// 1) NtQuerySystemInformation definitions
typedef NTSTATUS (NTAPI *NtQuerySI_t)(ULONG, PVOID, ULONG, PULONG);
#define SystemHandleInformation 16
#pragma comment(lib, "ntdll.lib")

// 2) Track which PIDs have already opened a handle to gamePID
static std::set<USHORT> knownOwners;

// Helper: parse hex string (no “0x”) to uintptr_t
static bool parseHex(const std::string &s, uintptr_t &out) {
    std::istringstream iss(s);
    iss >> std::hex >> out;
    return !iss.fail();
}

// 3) Scan system handles for any new handle to gamePID
void scanHandles(DWORD gamePid) {
    static NtQuerySI_t NtQuerySI =
        (NtQuerySI_t)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                    "NtQuerySystemInformation");
    if (!NtQuerySI) return;

    ULONG bufSize = 0x10000;
    std::vector<BYTE> buffer;
    NTSTATUS status;
    do {
        buffer.resize(bufSize);
        ULONG retLen = 0;
        status = NtQuerySI(SystemHandleInformation,
                           buffer.data(),
                           bufSize,
                           &retLen);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            bufSize = retLen + 0x1000;
        } else break;
    } while (true);

    if (!NT_SUCCESS(status)) return;

    struct SYS_HANDLE_ENTRY {
        USHORT UniqueProcessId;
        USHORT CreatorBackTraceIndex;
        UCHAR  ObjectTypeIndex;
        UCHAR  HandleAttributes;
        USHORT HandleValue;
        PVOID  Object;
        ACCESS_MASK GrantedAccess;
    };
    struct SYS_HANDLE_INFO {
        ULONG NumberOfHandles;
        SYS_HANDLE_ENTRY Handles[1];
    };

    auto* info = reinterpret_cast<SYS_HANDLE_INFO*>(buffer.data());
    for (ULONG i = 0; i < info->NumberOfHandles; i++) {
        auto& e = info->Handles[i];
        if (e.UniqueProcessId == gamePid) {
            USHORT owner = e.UniqueProcessId; // Process owning this handle
            // Duplicate to verify it really points to gamePid
            HANDLE hSrc = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
                                      FALSE, owner);
            if (!hSrc) continue;
            HANDLE dup = NULL;
            if (DuplicateHandle(
                    hSrc,
                    (HANDLE)(ULONG_PTR)e.HandleValue,
                    GetCurrentProcess(),
                    &dup,
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    FALSE,
                    0
                )) {
                if (GetProcessId(dup) == gamePid) {
                    if (!knownOwners.count(owner)) {
                        knownOwners.insert(owner);
                        std::cout << "[HANDLE] New handle to game from PID "
                                  << owner << "\n";
                    }
                }
                CloseHandle(dup);
            }
            CloseHandle(hSrc);
        }
    }
}

// 4) Read protectedValue and check for anomalies
bool checkValue(DWORD gamePid, uintptr_t addr, int &last) {
    HANDLE hGame = OpenProcess(PROCESS_VM_READ, FALSE, gamePid);
    if (!hGame) {
        std::cerr << "[anticheat] OpenProcess failed (Error " << GetLastError() << ")\n";
        return false;
    }
    int current = 0; SIZE_T bytesRead = 0;
    BOOL ok = ReadProcessMemory(hGame,
                                reinterpret_cast<LPCVOID>(addr),
                                &current,
                                sizeof(current),
                                &bytesRead);
    CloseHandle(hGame);
    if (!ok || bytesRead != sizeof(current)) {
        std::cerr << "[anticheat] ReadProcessMemory failed (Error " << GetLastError() << ")\n";
        return false;
    }

    int delta = current - last;
    if (delta > 1 || delta < 0) {
        std::cout << "[VALUE] CRITICAL: expected +1 but jumped from "
                  << last << " to " << current << "\n";
    } else {
        std::cout << "[VALUE] OK: " << current << " (delta=" << delta << ")\n";
    }
    last = current;
    return true;
}

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cout << "Usage: anticheat <GamePID> <ValueAddressHex>\n";
        return 1;
    }
    DWORD gamePid = std::stoul(argv[1]);
    uintptr_t addr = 0;
    if (!parseHex(argv[2], addr)) {
        std::cerr << "[anticheat] Invalid address.\n";
        return 1;
    }

    std::cout << "[anticheat] Monitoring Game PID=" << gamePid
              << "  at 0x" << std::hex << addr << std::dec << "\n";

    // Initialize last by reading once
    int lastValue = 0;
    {
        HANDLE hGame = OpenProcess(PROCESS_VM_READ, FALSE, gamePid);
        if (hGame) {
            ReadProcessMemory(hGame,
                              reinterpret_cast<LPCVOID>(addr),
                              &lastValue,
                              sizeof(lastValue),
                              nullptr);
            CloseHandle(hGame);
        }
    }

    // Loop every second
    while (true) {
        checkValue(gamePid, addr, lastValue);
        scanHandles(gamePid);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    return 0;
}
