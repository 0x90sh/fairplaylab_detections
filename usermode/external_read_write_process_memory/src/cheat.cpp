#include <windows.h>

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

static bool parse_hex(const std::string& text, std::uintptr_t& value) {
    std::istringstream stream(text);
    stream >> std::hex >> value;
    return !stream.fail();
}

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: " << argv[0] << " <game_pid> <address_hex>\n";
        return 1;
    }

    const DWORD game_pid = std::stoul(argv[1]);
    std::uintptr_t address = 0;

    if (!parse_hex(argv[2], address)) {
        std::cerr << "[cheat] invalid address\n";
        return 1;
    }

    HANDLE game = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
        FALSE,
        game_pid
    );

    if (!game) {
        std::cerr << "[cheat] openprocess failed, error=" << GetLastError() << "\n";
        return 1;
    }

    int value = 0;
    SIZE_T bytes_read = 0;
    const BOOL read_ok = ReadProcessMemory(
        game,
        reinterpret_cast<LPCVOID>(address),
        &value,
        sizeof(value),
        &bytes_read
    );

    if (read_ok && bytes_read == sizeof(value)) {
        std::cout << "[cheat] read value=" << value << " from 0x"
                  << std::hex << address << std::dec << "\n";
    } else {
        std::cerr << "[cheat] readprocessmemory failed, error=" << GetLastError() << "\n";
    }

    const int new_value = 9999;
    SIZE_T bytes_written = 0;
    const BOOL write_ok = WriteProcessMemory(
        game,
        reinterpret_cast<LPVOID>(address),
        &new_value,
        sizeof(new_value),
        &bytes_written
    );

    if (write_ok && bytes_written == sizeof(new_value)) {
        std::cout << "[cheat] wrote value=" << new_value << " to 0x"
                  << std::hex << address << std::dec << "\n";
    } else {
        std::cerr << "[cheat] writeprocessmemory failed, error=" << GetLastError() << "\n";
    }

    CloseHandle(game);
    return 0;
}
