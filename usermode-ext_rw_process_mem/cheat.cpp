#include <windows.h>
#include <iostream>
#include <sstream>
#include <iomanip>

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <GamePID> <AddressHex>\n";
        return 1;
    }

    DWORD gamePid = std::stoul(argv[1]);
    uintptr_t addr = 0;
    {
        std::istringstream iss(argv[2]);
        iss >> std::hex >> addr;
        if (!iss) {
            std::cerr << "[cheat] Invalid address.\n";
            return 1;
        }
    }

    HANDLE hGame = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
        FALSE,
        gamePid
    );
    if (!hGame) {
        std::cerr << "[cheat] OpenProcess failed (Error " << GetLastError() << ")\n";
        return 1;
    }
    std::cout << "[cheat] Opened handle to PID=" << gamePid << "\n";

    // 1) Read the current int
    int value = 0;
    SIZE_T bytesRead = 0;
    BOOL okR = ReadProcessMemory(
        hGame,
        reinterpret_cast<LPCVOID>(addr),
        &value,
        sizeof(value),
        &bytesRead
    );
    if (okR && bytesRead == sizeof(value)) {
        std::cout << "[cheat] Read value = " << value << " from 0x"
                  << std::hex << addr << std::dec << "\n";
    } else {
        std::cerr << "[cheat] ReadProcessMemory failed (Error " << GetLastError() << ")\n";
    }

    // 2) Overwrite with 9999
    int newValue = 9999;
    SIZE_T bytesWritten = 0;
    BOOL okW = WriteProcessMemory(
        hGame,
        reinterpret_cast<LPVOID>(addr),
        &newValue,
        sizeof(newValue),
        &bytesWritten
    );
    if (okW && bytesWritten == sizeof(newValue)) {
        std::cout << "[cheat] Wrote 9999 to 0x" 
                  << std::hex << addr << std::dec << "\n";
    } else {
        std::cerr << "[cheat] WriteProcessMemory failed (Error " << GetLastError() << ")\n";
    }

    CloseHandle(hGame);
    return 0;
}
