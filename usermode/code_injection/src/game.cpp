#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <iostream>
#include <set>
#include <string>
#include <thread>
#include <vector>

using nt_query_information_thread_t = NTSTATUS(NTAPI*)(
    HANDLE,
    THREADINFOCLASS,
    PVOID,
    ULONG,
    PULONG
);

constexpr THREADINFOCLASS thread_query_set_win32_start_address =
    static_cast<THREADINFOCLASS>(9);

struct module_info {
    std::uintptr_t base;
    std::uintptr_t end;
    std::string path;
};

static std::vector<module_info> baseline_modules;
static std::set<std::uintptr_t> reported_modules;
static std::set<void*> reported_memory;
static std::set<DWORD> reported_threads;

static std::string lower_copy(std::string value) {
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        }
    );

    return value;
}

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

static bool has_execute(DWORD protect) {
    const DWORD clean = protect & 0xff;
    return clean == PAGE_EXECUTE ||
           clean == PAGE_EXECUTE_READ ||
           clean == PAGE_EXECUTE_READWRITE ||
           clean == PAGE_EXECUTE_WRITECOPY;
}

static bool address_in_modules(std::uintptr_t address, const std::vector<module_info>& modules) {
    for (const auto& module : modules) {
        if (address >= module.base && address < module.end) {
            return true;
        }
    }

    return false;
}

static bool known_module(std::uintptr_t base) {
    for (const auto& module : baseline_modules) {
        if (module.base == base) {
            return true;
        }
    }

    return false;
}

static nt_query_information_thread_t load_nt_query_information_thread() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        return nullptr;
    }

    return reinterpret_cast<nt_query_information_thread_t>(
        GetProcAddress(ntdll, "NtQueryInformationThread")
    );
}

static void scan_new_modules(const std::vector<module_info>& modules) {
    for (const auto& module : modules) {
        if (known_module(module.base) || reported_modules.count(module.base)) {
            continue;
        }

        reported_modules.insert(module.base);

        std::cout << "[anticheat] new module base=0x" << std::hex << module.base
                  << " size=0x" << (module.end - module.base)
                  << std::dec << " path=" << module.path << "\n";

        const std::string lower_path = lower_copy(module.path);
        if (lower_path.find("payload.dll") != std::string::npos) {
            std::cout << "[anticheat] demo payload module loaded\n";
        }
    }
}

static void scan_executable_memory() {
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

static void scan_thread_starts(const std::vector<module_info>& modules) {
    static const auto query_thread = load_nt_query_information_thread();
    if (!query_thread) {
        return;
    }

    const DWORD pid = GetCurrentProcessId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    THREADENTRY32 entry = {};
    entry.dwSize = sizeof(entry);

    if (Thread32First(snapshot, &entry)) {
        do {
            if (entry.th32OwnerProcessID != pid || reported_threads.count(entry.th32ThreadID)) {
                continue;
            }

            HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, entry.th32ThreadID);
            if (!thread) {
                continue;
            }

            PVOID start_address = nullptr;
            const NTSTATUS status = query_thread(
                thread,
                thread_query_set_win32_start_address,
                &start_address,
                sizeof(start_address),
                nullptr
            );

            CloseHandle(thread);

            if (status < 0 || !start_address) {
                continue;
            }

            const auto start = reinterpret_cast<std::uintptr_t>(start_address);
            if (!address_in_modules(start, modules)) {
                reported_threads.insert(entry.th32ThreadID);

                std::cout << "[anticheat] thread start outside module tid="
                          << entry.th32ThreadID << " start=0x"
                          << std::hex << start << std::dec << "\n";
            }
        } while (Thread32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
}

int main() {
    std::cout.setf(std::ios::unitbuf);

    baseline_modules = snapshot_modules();

    std::cout << "[game] pid=" << GetCurrentProcessId() << "\n";
    std::cout << "[game] baseline modules=" << baseline_modules.size() << "\n";

    while (true) {
        const auto modules = snapshot_modules();

        scan_new_modules(modules);
        scan_executable_memory();
        scan_thread_starts(modules);

        std::cout << "[game] monitor tick modules=" << modules.size() << "\n";
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}
