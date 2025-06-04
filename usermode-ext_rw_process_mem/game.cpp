#include <windows.h>
#include <iostream>

static int protectedValue = 1234;

int main() {
    DWORD pid = GetCurrentProcessId();
    std::cout << "[game] PID=" << pid
              << "  &protectedValue=0x"
              << std::hex << reinterpret_cast<uintptr_t>(&protectedValue)
              << std::dec << "\n";

    while (true) {
        Sleep(1000);
        protectedValue += 1;
        std::cout << "[game] protectedValue = " << protectedValue << "\n";
    }
    return 0;
}