---
description: Internal read and write memory detection from usermode.
---

# usermode:internal\_read\_write\_memory

**Cheat**

**Type**: Internal usermode

**Goal**: Read and change game memory from inside the game process.

**AntiCheat**

**Type**: Usermode

**Goal**: Detect memory changes, code patches, pointer swaps, guarded page access, and private executable memory.

Notes:

Internal memory access is a different game than external memory access. Once cheat code is running inside the process, it can read game data with normal pointers. That read does not need `ReadProcessMemory`, a suspicious external handle, or a clear syscall. From plain usermode, direct reads are mostly invisible.

Writes are where you get signal. A write changes something the process can check later. That can be a value, a mirrored value, a function pointer, code bytes, page protections, or a memory region that should not exist.

This demo runs the check logic inside `game.exe`, then loads `cheat.dll` into that same process. The dll performs several common internal tamper actions in one run, so the output shows the difference between silent reads and detectable side effects.

<figure><img src="../.gitbook/assets/internal_read_write_memory.png" alt=""><figcaption><p><a href="https://github.com/0x90sh/fairplaylab_detections/tree/main/usermode/internal_read_write_memory">https://github.com/0x90sh/fairplaylab_detections/tree/main/usermode/internal_read_write_memory</a></p></figcaption></figure>

#### Cheater

The internal payload first reads the protected state directly. This is the boring but important part. The read itself is not a useful detection event.

```cpp
game_state* state = get_state();
std::cout << "[cheat] direct read health=" << (*state).health << "\n";
```

Then it writes values without updating the mirror.

```cpp
(*state).health = 999;
(*state).ammo = 999;
```

It also touches a guarded value and a write watch allocation.

```cpp
*write_watch_value = 31337;
*guard_value = 2026;
```

After that it swaps a function pointer to code inside the dll, patches an exported function, and allocates private executable memory.

```cpp
*action_slot = fake_action;

VirtualProtect(damage, sizeof(patch), PAGE_EXECUTE_READWRITE, &old_protect);
std::memcpy(damage, patch, sizeof(patch));
FlushInstructionCache(GetCurrentProcess(), damage, sizeof(patch));

VirtualAlloc(
    nullptr,
    0x1000,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
);
```

#### AntiCheat

The simplest check is mirrored value integrity. The game stores a value and a keyed mirror. If a cheat only changes the obvious value, the mismatch is visible.

```cpp
if ((health ^ mirror_key) != mirror) {
    std::cout << "[anticheat] health mirror mismatch\n";
}
```

For selected high value data, `PAGE_GUARD` can act as a noisy access alarm. A vectored exception handler records the hit, then the monitor rearms the guard page.

```cpp
const auto& record = *info.ExceptionRecord;
if (record.ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
    ++guard_hits;
    return EXCEPTION_CONTINUE_EXECUTION;
}
```

`MEM_WRITE_WATCH` works for memory that was allocated with write tracking. It is useful for protected allocations, not arbitrary existing game memory.

```cpp
GetWriteWatch(
    WRITE_WATCH_FLAG_RESET,
    write_watch_value,
    page_size,
    touched,
    &count,
    &granularity
);
```

Code patching can be caught by comparing important bytes against a clean baseline.

```cpp
std::memcpy(current.data(), reinterpret_cast<void*>(&fpl_damage_value), current.size());
if (current != original_damage_bytes) {
    std::cout << "[anticheat] code bytes changed\n";
}
```

Function pointers can be checked with `VirtualQuery`. In this demo the action pointer is expected to point into the main image. A pointer into the injected dll is suspicious.

```cpp
VirtualQuery(pointer, &info, sizeof(info));
return info.Type == MEM_IMAGE && info.AllocationBase == GetModuleHandleA(nullptr);
```

Private executable memory is another strong signal. Normal modules are `MEM_IMAGE`. Shellcode, unpacked code, and some manual maps often leave executable `MEM_PRIVATE` regions.

```cpp
if (info.State == MEM_COMMIT &&
    info.Type == MEM_PRIVATE &&
    has_execute(info.Protect)) {
    std::cout << "[anticheat] private executable memory\n";
}
```

#### Limits

This does not magically solve internal cheats. If hostile code runs inside the same process, it shares the same usermode trust boundary. It can patch hooks, call syscalls directly, remove handlers, or copy clean bytes back before scans.

The point is to raise cost and collect useful signals:

- direct reads are weak
- writes can be checked
- code patches can be hashed
- pointer swaps can be validated
- private executable memory can be scanned
- guard pages and write watch can protect selected regions

For stronger protection you eventually need kernel help, hypervisor backed checks, server authority, or a design where the client never owns the important truth.

#### Build

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
```

#### Run

```bat
build\Release\game.exe
build\Release\loader.exe <game_pid> build\Release\cheat.dll
```

Full source is here:

[https://github.com/0x90sh/fairplaylab\_detections/tree/main/usermode/internal\_read\_write\_memory](https://github.com/0x90sh/fairplaylab_detections/tree/main/usermode/internal_read_write_memory)
