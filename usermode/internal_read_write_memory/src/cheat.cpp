#include <windows.h>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <thread>

struct game_state {
    volatile LONG health;
    volatile LONG health_mirror;
    volatile LONG ammo;
};

using action_fn = int(__cdecl*)();
using get_state_t = game_state*(*)();
using get_int_t = int*(*)();
using get_action_slot_t = action_fn*(*)();

static int __cdecl fake_action() {
    return 1337;
}

static FARPROC load_export(HMODULE module, const char* name) {
    FARPROC proc = GetProcAddress(module, name);
    if (!proc) {
        std::cout << "[cheat] missing export " << name << "\n";
    }

    return proc;
}

static void patch_damage_function(HMODULE game_module) {
    auto damage = reinterpret_cast<BYTE*>(GetProcAddress(game_module, "fpl_damage_value"));
    if (!damage) {
        return;
    }

    BYTE patch[] = {
        0xb8,
        0x39,
        0x05,
        0x00,
        0x00,
        0xc3
    };

    DWORD old_protect = 0;
    if (!VirtualProtect(damage, sizeof(patch), PAGE_EXECUTE_READWRITE, &old_protect)) {
        std::cout << "[cheat] virtualprotect failed, error=" << GetLastError() << "\n";
        return;
    }

    std::memcpy(damage, patch, sizeof(patch));
    FlushInstructionCache(GetCurrentProcess(), damage, sizeof(patch));

    DWORD unused = 0;
    VirtualProtect(damage, sizeof(patch), old_protect, &unused);
}

static void allocate_private_exec() {
    auto code = static_cast<BYTE*>(VirtualAlloc(
        nullptr,
        0x1000,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    ));

    if (!code) {
        std::cout << "[cheat] private exec allocation failed, error=" << GetLastError() << "\n";
        return;
    }

    code[0] = 0xc3;
}

static void run_demo() {
    Sleep(2500);

    HMODULE game_module = GetModuleHandleA(nullptr);

    auto get_state = reinterpret_cast<get_state_t>(
        load_export(game_module, "fpl_get_state")
    );
    auto get_guard_value = reinterpret_cast<get_int_t>(
        load_export(game_module, "fpl_get_guard_value")
    );
    auto get_write_watch_value = reinterpret_cast<get_int_t>(
        load_export(game_module, "fpl_get_write_watch_value")
    );
    auto get_action_slot = reinterpret_cast<get_action_slot_t>(
        load_export(game_module, "fpl_get_action_slot")
    );

    if (!get_state || !get_guard_value || !get_write_watch_value || !get_action_slot) {
        return;
    }

    game_state* state = get_state();
    int* guard_value = get_guard_value();
    int* write_watch_value = get_write_watch_value();
    action_fn* action_slot = get_action_slot();

    std::cout << "[cheat] direct read health=" << (*state).health << "\n";

    (*state).health = 999;
    (*state).ammo = 999;
    std::cout << "[cheat] direct write complete\n";

    *write_watch_value = 31337;
    std::cout << "[cheat] write watch value changed\n";

    *guard_value = 2026;
    std::cout << "[cheat] guard value changed\n";

    *action_slot = fake_action;
    std::cout << "[cheat] action pointer swapped\n";

    patch_damage_function(game_module);
    std::cout << "[cheat] code patch attempted\n";

    allocate_private_exec();
    std::cout << "[cheat] private executable memory allocated\n";
}

static DWORD WINAPI worker_thread(void*) {
    run_demo();
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(instance);
        HANDLE thread = CreateThread(nullptr, 0, worker_thread, nullptr, 0, nullptr);
        if (thread) {
            CloseHandle(thread);
        }
    }

    return TRUE;
}
