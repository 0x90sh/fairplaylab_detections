#include <windows.h>
#include <iostream>
#include <string>

// In a real scenario, you discover these at runtime by enumerating system handles
static const DWORD WHITELISTED_PID       = 4321;   // must match entry in WHITELISTED_PIDS
static const HANDLE KNOWN_HANDLE_VALUE   = (HANDLE)0x00000030;  // example handle value in that PID
static const DWORD TARGET_GAME_PID       = 1234;   // PID of the game you wish to hijack

int main() {
    std::cout << "[*] Attempting to hijack handle from whitelisted PID="
              << WHITELISTED_PID << "\n";

    // Step 1: Open the whitelisted “source” process with DUP_HANDLE rights
    HANDLE hSourceProc = OpenProcess(
        PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        WHITELISTED_PID
    );
    if (!hSourceProc) {
        std::cerr << "ERROR: Cannot open source PID=" << WHITELISTED_PID
                  << " (GetLastError=" << GetLastError() << ")\n";
        return 1;
    }

    // Step 2: Duplicate that known handle into our own process
    HANDLE hGameDup = NULL;
    BOOL ok = DuplicateHandle(
        hSourceProc,            // source process (whitelisted)
        KNOWN_HANDLE_VALUE,     // handle value in that process that already points to the game
        GetCurrentProcess(),    // our process
        &hGameDup,              // out: our new handle to game
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        DUPLICATE_SAME_ACCESS
    );
    CloseHandle(hSourceProc);

    if (!ok) {
        std::cerr << "DuplicateHandle failed (GetLastError=" << GetLastError() << ")\n";
        return 1;
    }

    // Step 3: Verify it truly points to our target game PID
    DWORD pidCheck = GetProcessId(hGameDup);
    if (pidCheck != TARGET_GAME_PID) {
        std::cerr << "Hijacked handle invalid — points to PID=" << pidCheck
                  << ", expected " << TARGET_GAME_PID << "\n";
        CloseHandle(hGameDup);
        return 1;
    }

    std::cout << "[+] Successfully hijacked a whitelisted handle to game (PID=" 
              << TARGET_GAME_PID << ").\n";
    std::cout << "Holding it for 30 seconds...\n";
    Sleep(30000);

    CloseHandle(hGameDup);
    return 0;
}
