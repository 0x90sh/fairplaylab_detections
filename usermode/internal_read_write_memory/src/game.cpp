#include <windows.h>
#include <memoryapi.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <set>
#include <string>
#include <thread>

struct game_state {
    volatile LONG health;
    volatile LONG health_mirror;
    volatile LONG ammo;
};

using action_fn = int(__cdecl*)();

constexpr LONG mirror_key = 0x5a5a1234;
constexpr SIZE_T code_hash_size = 32;

static game_state state = {
    100,
    100 ^ mirror_key,
    30
};

static BYTE* guard_page = nullptr;
static int* guard_value = nullptr;
static int* write_watch_value = nullptr;
static DWORD page_size = 0;
static std::atomic<LONG> guard_hits = 0;
static std::set<void*> reported_private_exec;
static std::array<BYTE, code_hash_size> original_damage_bytes = {};

extern "C" __declspec(dllexport) __declspec(noinline) int __cdecl fpl_damage_value() {
    return 7;
}

static int __cdecl legit_action() {
    return fpl_damage_value();
}

static action_fn action_slot = legit_action;

extern "C" __declspec(dllexport) game_state* fpl_get_state() {
    return &state;
}

extern "C" __declspec(dllexport) int* fpl_get_guard_value() {
    return guard_value;
}

extern "C" __declspec(dllexport) int* fpl_get_write_watch_value() {
    return write_watch_value;
}

extern "C" __declspec(dllexport) action_fn* fpl_get_action_slot() {
    return &action_slot;
}

static bool has_execute(DWORD protect) {
    const DWORD clean = protect & 0xff;
    return clean == PAGE_EXECUTE ||
           clean == PAGE_EXECUTE_READ ||
           clean == PAGE_EXECUTE_READWRITE ||
           clean == PAGE_EXECUTE_WRITECOPY;
}

static LONG CALLBACK vectored_handler(EXCEPTION_POINTERS* info) {
    if (!info) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    const auto& exception = *info;
    if (!exception.ExceptionRecord) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    const auto& record = *exception.ExceptionRecord;

    if (record.ExceptionCode != STATUS_GUARD_PAGE_VIOLATION) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    const auto address = static_cast<std::uintptr_t>(
        record.ExceptionInformation[1]
    );
    const auto base = reinterpret_cast<std::uintptr_t>(guard_page);

    if (address < base || address >= base + page_size) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    ++guard_hits;
    return EXCEPTION_CONTINUE_EXECUTION;
}

static bool setup_guard_page() {
    guard_page = static_cast<BYTE*>(VirtualAlloc(
        nullptr,
        page_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    ));

    if (!guard_page) {
        std::cerr << "[game] guard page allocation failed, error=" << GetLastError() << "\n";
        return false;
    }

    guard_value = reinterpret_cast<int*>(guard_page);
    *guard_value = 1000;

    DWORD old_protect = 0;
    if (!VirtualProtect(guard_page, page_size, PAGE_READWRITE | PAGE_GUARD, &old_protect)) {
        std::cerr << "[game] guard page protect failed, error=" << GetLastError() << "\n";
        return false;
    }

    if (!AddVectoredExceptionHandler(1, vectored_handler)) {
        std::cerr << "[game] vectored handler failed\n";
        return false;
    }

    return true;
}

static bool setup_write_watch() {
    write_watch_value = static_cast<int*>(VirtualAlloc(
        nullptr,
        page_size,
        MEM_COMMIT | MEM_RESERVE | MEM_WRITE_WATCH,
        PAGE_READWRITE
    ));

    if (!write_watch_value) {
        std::cerr << "[game] write watch allocation failed, error=" << GetLastError() << "\n";
        return false;
    }

    *write_watch_value = 500;

    PVOID touched[8] = {};
    ULONG_PTR count = 8;
    DWORD granularity = 0;
    GetWriteWatch(
        WRITE_WATCH_FLAG_RESET,
        write_watch_value,
        page_size,
        touched,
        &count,
        &granularity
    );

    return true;
}

static void rearm_guard_page() {
    DWORD old_protect = 0;
    VirtualProtect(guard_page, page_size, PAGE_READWRITE | PAGE_GUARD, &old_protect);
}

static void check_state() {
    const LONG health = state.health;
    const LONG mirror = state.health_mirror;

    if ((health ^ mirror_key) != mirror) {
        std::cout << "[anticheat] health mirror mismatch, health=" << health
                  << " mirror=" << mirror << "\n";
    }

    if (health < 0 || health > 100) {
        std::cout << "[anticheat] impossible health value=" << health << "\n";
    }
}

static void check_guard_page() {
    static LONG last_hits = 0;
    const LONG current_hits = guard_hits.load();

    if (current_hits != last_hits) {
        std::cout << "[anticheat] guard page touched, hits=" << current_hits << "\n";
        last_hits = current_hits;
    }

    rearm_guard_page();
}

static void check_write_watch() {
    PVOID touched[16] = {};
    ULONG_PTR count = 16;
    DWORD granularity = 0;

    const UINT result = GetWriteWatch(
        WRITE_WATCH_FLAG_RESET,
        write_watch_value,
        page_size,
        touched,
        &count,
        &granularity
    );

    if (result != 0 || count == 0) {
        return;
    }

    std::cout << "[anticheat] write watch page changed, count=" << count
              << " value=" << *write_watch_value << "\n";
}

static void check_code_patch() {
    std::array<BYTE, code_hash_size> current = {};
    std::memcpy(current.data(), reinterpret_cast<void*>(&fpl_damage_value), current.size());

    if (current != original_damage_bytes) {
        std::cout << "[anticheat] code bytes changed at fpl_damage_value\n";
    }
}

static bool pointer_inside_main_image(void* pointer) {
    MEMORY_BASIC_INFORMATION info = {};
    if (!VirtualQuery(pointer, &info, sizeof(info))) {
        return false;
    }

    return info.Type == MEM_IMAGE && info.AllocationBase == GetModuleHandleA(nullptr);
}

static void check_action_pointer() {
    auto pointer = reinterpret_cast<void*>(action_slot);

    if (!pointer_inside_main_image(pointer)) {
        std::cout << "[anticheat] action pointer outside main image, address=0x"
                  << std::hex << reinterpret_cast<std::uintptr_t>(pointer)
                  << std::dec << "\n";
    }
}

static void scan_private_executable_memory() {
    SYSTEM_INFO system_info = {};
    GetSystemInfo(&system_info);

    auto address = reinterpret_cast<std::uintptr_t>(system_info.lpMinimumApplicationAddress);
    const auto max_address = reinterpret_cast<std::uintptr_t>(system_info.lpMaximumApplicationAddress);

    while (address < max_address) {
        MEMORY_BASIC_INFORMATION info = {};
        if (!VirtualQuery(reinterpret_cast<void*>(address), &info, sizeof(info))) {
            address += page_size;
            continue;
        }

        if (info.State == MEM_COMMIT &&
            info.Type == MEM_PRIVATE &&
            has_execute(info.Protect) &&
            !reported_private_exec.count(info.BaseAddress)) {
            reported_private_exec.insert(info.BaseAddress);

            std::cout << "[anticheat] private executable memory at 0x"
                      << std::hex << reinterpret_cast<std::uintptr_t>(info.BaseAddress)
                      << " size=0x" << info.RegionSize << std::dec << "\n";
        }

        address = reinterpret_cast<std::uintptr_t>(info.BaseAddress) + info.RegionSize;
    }
}

static void monitor_loop() {
    while (true) {
        const int damage = action_slot();

        check_state();
        check_guard_page();
        check_write_watch();
        check_code_patch();
        check_action_pointer();
        scan_private_executable_memory();

        std::cout << "[game] health=" << state.health
                  << " ammo=" << state.ammo
                  << " damage=" << damage
                  << " guard_hits=" << guard_hits.load()
                  << " watch=" << *write_watch_value << "\n";

        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

int main() {
    std::cout.setf(std::ios::unitbuf);

    SYSTEM_INFO system_info = {};
    GetSystemInfo(&system_info);
    page_size = system_info.dwPageSize;

    std::memcpy(
        original_damage_bytes.data(),
        reinterpret_cast<void*>(&fpl_damage_value),
        original_damage_bytes.size()
    );

    if (!setup_guard_page() || !setup_write_watch()) {
        return 1;
    }

    std::cout << "[game] pid=" << GetCurrentProcessId() << "\n";
    std::cout << "[game] state=0x" << std::hex
              << reinterpret_cast<std::uintptr_t>(&state) << "\n";
    std::cout << "[game] guard=0x"
              << reinterpret_cast<std::uintptr_t>(guard_value) << "\n";
    std::cout << "[game] write_watch=0x"
              << reinterpret_cast<std::uintptr_t>(write_watch_value)
              << std::dec << "\n";

    monitor_loop();
}
