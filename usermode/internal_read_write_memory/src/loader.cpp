#include <windows.h>

#include <iostream>
#include <string>

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: " << argv[0] << " <game_pid> <cheat_dll_path>\n";
        return 1;
    }

    const DWORD pid = std::stoul(argv[1]);
    const std::string dll_path = argv[2];

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

    const SIZE_T bytes = dll_path.size() + 1;
    void* remote_path = VirtualAllocEx(
        process,
        nullptr,
        bytes,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!remote_path) {
        std::cerr << "[loader] virtualallocex failed, error=" << GetLastError() << "\n";
        CloseHandle(process);
        return 1;
    }

    if (!WriteProcessMemory(process, remote_path, dll_path.c_str(), bytes, nullptr)) {
        std::cerr << "[loader] writeprocessmemory failed, error=" << GetLastError() << "\n";
        VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
        CloseHandle(process);
        return 1;
    }

    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    auto load_library = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        GetProcAddress(kernel32, "LoadLibraryA")
    );

    HANDLE thread = CreateRemoteThread(
        process,
        nullptr,
        0,
        load_library,
        remote_path,
        0,
        nullptr
    );

    if (!thread) {
        std::cerr << "[loader] createremotethread failed, error=" << GetLastError() << "\n";
        VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
        CloseHandle(process);
        return 1;
    }

    WaitForSingleObject(thread, INFINITE);

    DWORD exit_code = 0;
    GetExitCodeThread(thread, &exit_code);

    std::cout << "[loader] loadlibrary result=0x" << std::hex << exit_code << std::dec << "\n";

    CloseHandle(thread);
    VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
    CloseHandle(process);
    return exit_code ? 0 : 1;
}
