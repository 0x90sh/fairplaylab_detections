#include <windows.h>
#include <winternl.h>

#include <algorithm>
#include <chrono>
#include <iostream>
#include <set>
#include <thread>
#include <utility>
#include <vector>

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH static_cast<NTSTATUS>(0xC0000004L)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(status) (static_cast<NTSTATUS>(status) >= 0)
#endif

constexpr ULONG system_extended_handle_information = 64;

using nt_query_system_information_t = NTSTATUS(NTAPI*)(
    ULONG,
    PVOID,
    ULONG,
    PULONG
);

struct system_handle_entry {
    PVOID object;
    ULONG_PTR process_id;
    ULONG_PTR handle_value;
    ULONG granted_access;
    USHORT creator_backtrace_index;
    USHORT object_type_index;
    ULONG handle_attributes;
    ULONG reserved;
};

struct system_handle_information {
    ULONG_PTR number_of_handles;
    ULONG_PTR reserved;
    system_handle_entry handles[1];
};

static const std::set<DWORD> whitelisted_pids = {
    4321,
    8765
};

static std::set<std::pair<DWORD, ULONG_PTR>> known_handles;

static nt_query_system_information_t load_nt_query_system_information() {
    auto ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        return nullptr;
    }

    return reinterpret_cast<nt_query_system_information_t>(
        GetProcAddress(ntdll, "NtQuerySystemInformation")
    );
}

static bool query_handles(
    nt_query_system_information_t query,
    std::vector<BYTE>& buffer
) {
    ULONG size = 0x10000;

    while (true) {
        buffer.resize(size);

        ULONG needed = 0;
        const NTSTATUS status = query(
            system_extended_handle_information,
            buffer.data(),
            size,
            &needed
        );

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            size = needed + 0x1000;
            continue;
        }

        return NT_SUCCESS(status);
    }
}

static bool duplicate_points_to_self(
    DWORD owner_pid,
    ULONG_PTR handle_value,
    DWORD self_pid,
    HANDLE& owner_process,
    HANDLE& duplicated
) {
    owner_process = OpenProcess(
        PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        owner_pid
    );

    if (!owner_process) {
        return false;
    }

    const BOOL ok = DuplicateHandle(
        owner_process,
        reinterpret_cast<HANDLE>(handle_value),
        GetCurrentProcess(),
        &duplicated,
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        0
    );

    if (!ok) {
        CloseHandle(owner_process);
        owner_process = nullptr;
        return false;
    }

    return GetProcessId(duplicated) == self_pid;
}

static bool close_remote_handle(HANDLE owner_process, ULONG_PTR handle_value) {
    return DuplicateHandle(
        owner_process,
        reinterpret_cast<HANDLE>(handle_value),
        nullptr,
        nullptr,
        0,
        0,
        DUPLICATE_CLOSE_SOURCE
    );
}

static void scan_handles(
    nt_query_system_information_t query,
    DWORD self_pid,
    bool baseline_only
) {
    std::vector<BYTE> buffer;
    if (!query_handles(query, buffer)) {
        std::cerr << "[anticheat] handle query failed\n";
        return;
    }

    const auto& handles = *reinterpret_cast<const system_handle_information*>(buffer.data());

    for (ULONG_PTR i = 0; i < handles.number_of_handles; ++i) {
        const auto& entry = handles.handles[i];
        const DWORD owner_pid = static_cast<DWORD>(entry.process_id);

        if (owner_pid == self_pid) {
            continue;
        }

        const auto key = std::make_pair(owner_pid, entry.handle_value);
        if (known_handles.count(key)) {
            continue;
        }

        HANDLE owner_process = nullptr;
        HANDLE duplicated = nullptr;
        const bool points_to_self = duplicate_points_to_self(
            owner_pid,
            entry.handle_value,
            self_pid,
            owner_process,
            duplicated
        );

        if (!points_to_self) {
            if (duplicated) {
                CloseHandle(duplicated);
            }

            if (owner_process) {
                CloseHandle(owner_process);
            }

            continue;
        }

        known_handles.insert(key);

        if (!baseline_only) {
            if (whitelisted_pids.count(owner_pid)) {
                std::cout << "[anticheat] allowed pid=" << owner_pid
                          << " handle=0x" << std::hex << entry.handle_value << std::dec << "\n";
            } else if (close_remote_handle(owner_process, entry.handle_value)) {
                std::cout << "[anticheat] closed handle from pid=" << owner_pid
                          << " handle=0x" << std::hex << entry.handle_value << std::dec << "\n";
            } else {
                std::cout << "[anticheat] failed to close handle from pid=" << owner_pid
                          << ", error=" << GetLastError() << "\n";
            }
        }

        CloseHandle(duplicated);
        CloseHandle(owner_process);
    }
}

int main() {
    const auto query = load_nt_query_system_information();
    if (!query) {
        std::cerr << "[anticheat] ntquerysysteminformation missing\n";
        return 1;
    }

    const DWORD self_pid = GetCurrentProcessId();

    std::cout << "[anticheat] process handle monitor pid=" << self_pid << "\n";
    std::cout << "[anticheat] trusted pids:";
    for (const DWORD pid : whitelisted_pids) {
        std::cout << " " << pid;
    }
    std::cout << "\n";

    scan_handles(query, self_pid, true);

    while (true) {
        scan_handles(query, self_pid, false);
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }
}
