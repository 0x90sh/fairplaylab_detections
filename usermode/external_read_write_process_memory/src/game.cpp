#include <windows.h>

#include <cstdint>
#include <iostream>

static int protected_value = 1234;

int main() {
    const DWORD pid = GetCurrentProcessId();
    const auto address = reinterpret_cast<std::uintptr_t>(&protected_value);

    std::cout << "[game] pid=" << pid << "\n";
    std::cout << "[game] protected_value=0x" << std::hex << address << std::dec << "\n";

    while (true) {
        Sleep(1000);
        ++protected_value;
        std::cout << "[game] protected_value=" << protected_value << "\n";
    }
}
