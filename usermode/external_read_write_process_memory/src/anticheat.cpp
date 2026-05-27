#include <windows.h>
#include <winternl.h>

#include <cstdint>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
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

static std::set<std::pair<DWORD, ULONG_PTR>> known_handles;

static bool parse_hex(const std::string& text, std::uintptr_t& value) {
    std::istringstream stream(text);
    stream >> std::hex >> value;
    return !stream.fail();
}

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

static void scan_handles(DWORD game_pid) {
    static const auto query = load_nt_query_system_information();
    if (!query) {
        return;
    }

    std::vector<BYTE> buffer;
    if (!query_handles(query, buffer)) {
        return;
    }

    const auto& handles = *reinterpret_cast<const system_handle_information*>(buffer.data());

    for (ULONG_PTR i = 0; i < handles.number_of_handles; ++i) {
        const auto& entry = handles.handles[i];
        const DWORD owner_pid = static_cast<DWORD>(entry.process_id);

        if (owner_pid == game_pid || owner_pid == GetCurrentProcessId()) {
            continue;
        }

        const auto key = std::make_pair(owner_pid, entry.handle_value);
        if (known_handles.count(key)) {
            continue;
        }

        HANDLE owner = OpenProcess(
            PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            owner_pid
        );

        if (!owner) {
            continue;
        }

        HANDLE duplicated = nullptr;
        const BOOL duplicated_ok = DuplicateHandle(
            owner,
            reinterpret_cast<HANDLE>(entry.handle_value),
            GetCurrentProcess(),
            &duplicated,
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            0
        );

        if (duplicated_ok) {
            if (GetProcessId(duplicated) == game_pid) {
                known_handles.insert(key);
                std::cout << "[handle] pid=" << owner_pid
                          << " opened handle=0x" << std::hex << entry.handle_value
                          << " access=0x" << entry.granted_access << std::dec << "\n";
            }

            CloseHandle(duplicated);
        }

        CloseHandle(owner);
    }
}

static bool read_game_value(DWORD game_pid, std::uintptr_t address, int& value) {
    HANDLE game = OpenProcess(PROCESS_VM_READ, FALSE, game_pid);

    if (!game) {
        std::cerr << "[anticheat] openprocess failed, error=" << GetLastError() << "\n";
        return false;
    }

    SIZE_T bytes_read = 0;
    const BOOL ok = ReadProcessMemory(
        game,
        reinterpret_cast<LPCVOID>(address),
        &value,
        sizeof(value),
        &bytes_read
    );

    CloseHandle(game);

    if (!ok || bytes_read != sizeof(value)) {
        std::cerr << "[anticheat] readprocessmemory failed, error=" << GetLastError() << "\n";
        return false;
    }

    return true;
}

static void check_value(DWORD game_pid, std::uintptr_t address, int& last_value) {
    int current = 0;
    if (!read_game_value(game_pid, address, current)) {
        return;
    }

    const int delta = current - last_value;
    if (delta > 1 || delta < 0) {
        std::cout << "[value] changed from " << last_value
                  << " to " << current << ", expected +1\n";
    } else {
        std::cout << "[value] ok, current=" << current
                  << ", delta=" << delta << "\n";
    }

    last_value = current;
}

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: " << argv[0] << " <game_pid> <address_hex>\n";
        return 1;
    }

    const DWORD game_pid = std::stoul(argv[1]);
    std::uintptr_t address = 0;

    if (!parse_hex(argv[2], address)) {
        std::cerr << "[anticheat] invalid address\n";
        return 1;
    }

    int last_value = 0;
    if (!read_game_value(game_pid, address, last_value)) {
        return 1;
    }

    std::cout << "[anticheat] watching pid=" << game_pid
              << " address=0x" << std::hex << address << std::dec << "\n";

    while (true) {
        check_value(game_pid, address, last_value);
        scan_handles(game_pid);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}
