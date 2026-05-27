#include <windows.h>

#include <iostream>
#include <string>

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: " << argv[0] << " <game_pid>\n";
        return 1;
    }

    const DWORD game_pid = std::stoul(argv[1]);

    HANDLE game = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        game_pid
    );

    if (!game) {
        std::cerr << "[cheat] openprocess failed, pid=" << game_pid
                  << ", error=" << GetLastError() << "\n";
        return 1;
    }

    std::cout << "[cheat] opened handle to pid=" << game_pid << "\n";
    std::cout << "[cheat] holding handle for 30 seconds\n";

    Sleep(30000);
    CloseHandle(game);
    return 0;
}
