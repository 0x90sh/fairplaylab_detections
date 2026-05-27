#include <windows.h>

#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>

static bool parse_hex(const std::string& text, std::uintptr_t& value) {
    std::istringstream stream(text);
    stream >> std::hex >> value;
    return !stream.fail();
}

int main(int argc, char** argv) {
    if (argc != 4) {
        std::cerr << "usage: " << argv[0]
                  << " <source_pid> <source_handle_hex> <game_pid>\n";
        return 1;
    }

    const DWORD source_pid = std::stoul(argv[1]);
    const DWORD game_pid = std::stoul(argv[3]);
    std::uintptr_t source_handle = 0;

    if (!parse_hex(argv[2], source_handle)) {
        std::cerr << "[cheat] invalid source handle\n";
        return 1;
    }

    HANDLE source = OpenProcess(
        PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        source_pid
    );

    if (!source) {
        std::cerr << "[cheat] openprocess failed, pid=" << source_pid
                  << ", error=" << GetLastError() << "\n";
        return 1;
    }

    HANDLE game = nullptr;
    const BOOL ok = DuplicateHandle(
        source,
        reinterpret_cast<HANDLE>(source_handle),
        GetCurrentProcess(),
        &game,
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        DUPLICATE_SAME_ACCESS
    );

    CloseHandle(source);

    if (!ok) {
        std::cerr << "[cheat] duplicatehandle failed, error=" << GetLastError() << "\n";
        return 1;
    }

    const DWORD duplicated_pid = GetProcessId(game);
    if (duplicated_pid != game_pid) {
        std::cerr << "[cheat] duplicated handle points to pid=" << duplicated_pid
                  << ", expected pid=" << game_pid << "\n";
        CloseHandle(game);
        return 1;
    }

    std::cout << "[cheat] hijacked handle to pid=" << game_pid << "\n";
    std::cout << "[cheat] holding handle for 30 seconds\n";

    Sleep(30000);
    CloseHandle(game);
    return 0;
}
