#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <set>
#include <string>
#include <thread>
#include <vector>

struct module_info {
    std::uintptr_t base;
    std::uintptr_t end;
    std::string path;
};

static volatile LONG worker_counter = 0;
static DWORD worker_tid = 0;
static std::set<DWORD> reported_threads;
static std::set<void*> reported_memory;

static std::vector<module_info> snapshot_modules() {
    std::vector<module_info> modules;
    const DWORD pid = GetCurrentProcessId();

    HANDLE snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        pid
    );

    if (snapshot == INVALID_HANDLE_VALUE) {
        return modules;
    }

    MODULEENTRY32 entry = {};
    entry.dwSize = sizeof(entry);

    if (Module32First(snapshot, &entry)) {
        do {
            const auto base = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
            modules.push_back({
                base,
                base + entry.modBaseSize,
                entry.szExePath
            });
        } while (Module32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return modules;
}

static bool address_in_modules(std::uintptr_t address, const std::vector<module_info>& modules) {
    for (const auto& module : modules) {
        if (address >= module.base && address < module.end) {
            return true;
        }
    }

    return false;
}

static bool has_execute(DWORD protect) {
    const DWORD clean = protect & 0xff;
    return clean == PAGE_EXECUTE ||
           clean == PAGE_EXECUTE_READ ||
           clean == PAGE_EXECUTE_READWRITE ||
           clean == PAGE_EXECUTE_WRITECOPY;
}

static void scan_private_executable_memory() {
    SYSTEM_INFO system_info = {};
    GetSystemInfo(&system_info);

    auto address = reinterpret_cast<std::uintptr_t>(system_info.lpMinimumApplicationAddress);
    const auto max_address = reinterpret_cast<std::uintptr_t>(system_info.lpMaximumApplicationAddress);

    while (address < max_address) {
        MEMORY_BASIC_INFORMATION info = {};
        if (!VirtualQuery(reinterpret_cast<void*>(address), &info, sizeof(info))) {
            address += system_info.dwPageSize;
            continue;
        }

        const bool suspicious =
            info.State == MEM_COMMIT &&
            info.Type == MEM_PRIVATE &&
            has_execute(info.Protect);

        if (suspicious && !reported_memory.count(info.BaseAddress)) {
            reported_memory.insert(info.BaseAddress);

            std::cout << "[anticheat] executable private memory base=0x"
                      << std::hex << reinterpret_cast<std::uintptr_t>(info.BaseAddress)
                      << " size=0x" << info.RegionSize << std::dec << "\n";
        }

        address = reinterpret_cast<std::uintptr_t>(info.BaseAddress) + info.RegionSize;
    }
}

static bool read_thread_ip(DWORD tid, std::uintptr_t& ip) {
    HANDLE thread = OpenThread(
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
        FALSE,
        tid
    );

    if (!thread) {
        return false;
    }

    const DWORD suspend_count = SuspendThread(thread);
    if (suspend_count == static_cast<DWORD>(-1)) {
        CloseHandle(thread);
        return false;
    }

    CONTEXT context = {};
    context.ContextFlags = CONTEXT_CONTROL;

    const BOOL ok = GetThreadContext(thread, &context);
    ResumeThread(thread);
    CloseHandle(thread);

    if (!ok) {
        return false;
    }

#if defined(_M_X64)
    ip = static_cast<std::uintptr_t>(context.Rip);
#else
    ip = static_cast<std::uintptr_t>(context.Eip);
#endif

    return true;
}

static void scan_worker_context(const std::vector<module_info>& modules) {
    if (!worker_tid || reported_threads.count(worker_tid)) {
        return;
    }

    std::uintptr_t ip = 0;
    if (!read_thread_ip(worker_tid, ip)) {
        return;
    }

    if (!address_in_modules(ip, modules)) {
        reported_threads.insert(worker_tid);

        std::cout << "[anticheat] worker context outside module tid="
                  << worker_tid << " ip=0x" << std::hex << ip << std::dec << "\n";
    }
}

static DWORD WINAPI worker_thread(void*) {
    while (true) {
        InterlockedIncrement(&worker_counter);
        Sleep(500);
    }
}

int main() {
    std::cout.setf(std::ios::unitbuf);

    HANDLE worker = CreateThread(nullptr, 0, worker_thread, nullptr, 0, &worker_tid);
    if (!worker) {
        std::cerr << "[game] worker thread failed, error=" << GetLastError() << "\n";
        return 1;
    }

    CloseHandle(worker);

    std::cout << "[game] pid=" << GetCurrentProcessId() << "\n";
    std::cout << "[game] worker_tid=" << worker_tid << "\n";

    while (true) {
        const auto modules = snapshot_modules();

        scan_private_executable_memory();
        scan_worker_context(modules);

        std::cout << "[game] counter=" << worker_counter
                  << " modules=" << modules.size() << "\n";

        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}
