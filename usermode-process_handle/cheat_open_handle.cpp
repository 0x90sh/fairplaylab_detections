#include <windows.h>
#include <iostream>
#include <string>

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <GamePID>\n";
        return 1;
    }
    DWORD gamePid = std::stoul(argv[1]);

    HANDLE hGame = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        gamePid
    );

    if (!hGame) {
        std::cerr << "Failed to open handle to PID " << gamePid
                  << " (error " << GetLastError() << ")\n";
        return 1;
    }

    std::cout << "Opened handle to game (PID=" << gamePid << ").\n"
              << "Holding it for 30 seconds...\n";
    Sleep(30000);

    CloseHandle(hGame);
    return 0;
}
