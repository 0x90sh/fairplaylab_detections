#include <windows.h>

#include <iostream>
#include <string>

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: " << argv[0] << " <pid>\n";
        return 1;
    }

    const DWORD pid = std::stoul(argv[1]);

    HANDLE process = OpenProcess(
        PROCESS_CREATE_THREAD |
        PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE |
        PROCESS_VM_READ,
        FALSE,
        pid
    );

    if (!process) {
        std::cerr << "[loader] openprocess failed, error=" << GetLastError() << "\n";
        return 1;
    }

    BYTE code[] = {
        0x48,
        0x31,
        0xc0,
        0xc3
    };

    void* remote_code = VirtualAllocEx(
        process,
        nullptr,
        0x1000,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!remote_code) {
        std::cerr << "[loader] virtualallocex failed, error=" << GetLastError() << "\n";
        CloseHandle(process);
        return 1;
    }

    if (!WriteProcessMemory(process, remote_code, code, sizeof(code), nullptr)) {
        std::cerr << "[loader] writeprocessmemory failed, error=" << GetLastError() << "\n";
        VirtualFreeEx(process, remote_code, 0, MEM_RELEASE);
        CloseHandle(process);
        return 1;
    }

    HANDLE thread = CreateRemoteThread(
        process,
        nullptr,
        0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_code),
        nullptr,
        CREATE_SUSPENDED,
        nullptr
    );

    if (!thread) {
        std::cerr << "[loader] createremotethread failed, error=" << GetLastError() << "\n";
        VirtualFreeEx(process, remote_code, 0, MEM_RELEASE);
        CloseHandle(process);
        return 1;
    }

    std::cout << "[loader] private executable thread created at 0x"
              << std::hex << reinterpret_cast<std::uintptr_t>(remote_code)
              << std::dec << "\n";

    CloseHandle(thread);
    CloseHandle(process);
    return 0;
}
