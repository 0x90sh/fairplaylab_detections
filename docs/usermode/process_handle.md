---
description: Process handle detection and bypass.
---

# process\_handle

**Cheat**

**Type**: External usermode

**Goal**: Open or reuse a process handle for memory access.

**AntiCheat**

**Type**: Usermode

**Goal**: Monitor active handles and close suspicious ones.

Notes:

Many normal processes open handles to game processes. Launchers, overlays, crash reporters, debuggers, capture tools, and security products can all show up. Banning only because a handle exists is a bad idea.

Still, handle monitoring is useful. You can reduce easy external access, log suspicious processes, and force cheats into weaker bypasses. The problem is whitelisting. If a trusted process has a useful handle, a cheat may try to duplicate that handle instead of opening a fresh one.

<figure><img src="../.gitbook/assets/open_handle.png" alt=""><figcaption><p><a href="https://github.com/0x90sh/fairplaylab_detections/tree/main/usermode/process_handle">https://github.com/0x90sh/fairplaylab_detections/tree/main/usermode/process_handle</a></p></figcaption></figure>

#### Cheater

The basic external path is just `OpenProcess` with enough rights.

```cpp
HANDLE game = OpenProcess(
    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
    FALSE,
    game_pid
);
```

#### AntiCheat

The AntiCheat queries system handles, duplicates a remote handle into itself, then checks whether the duplicated handle points at the protected process.

```cpp
HANDLE owner_process = OpenProcess(
    PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
    FALSE,
    owner_pid
);

DuplicateHandle(
    owner_process,
    reinterpret_cast<HANDLE>(handle_value),
    GetCurrentProcess(),
    &duplicated,
    PROCESS_QUERY_LIMITED_INFORMATION,
    FALSE,
    0
);

if (GetProcessId(duplicated) == self_pid) {
    known_handles.insert(key);
}
```

If the owner pid is not trusted, the demo closes the source handle.

```cpp
DuplicateHandle(
    owner_process,
    reinterpret_cast<HANDLE>(handle_value),
    nullptr,
    nullptr,
    0,
    0,
    DUPLICATE_CLOSE_SOURCE
);
```

#### Cheater Bypass

The bypass demo duplicates a known handle from another process. This is the reason a plain pid whitelist is weak.

```cpp
DuplicateHandle(
    source,
    reinterpret_cast<HANDLE>(source_handle),
    GetCurrentProcess(),
    &game,
    PROCESS_QUERY_LIMITED_INFORMATION,
    FALSE,
    DUPLICATE_SAME_ACCESS
);

if (GetProcessId(game) != game_pid) {
    CloseHandle(game);
}
```

Real handling needs more than a pid list. Think signatures, process lineage, expected modules, handle rights, timing, and whether the process has any reason to touch the game.

#### Build

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
```

#### Run

```bat
build\Release\anticheat.exe
build\Release\cheat_open_handle.exe <anticheat_pid>
build\Release\cheat_hijack_handle.exe <source_pid> <source_handle_hex> <anticheat_pid>
```

Full source is here:

[https://github.com/0x90sh/fairplaylab\_detections/tree/main/usermode/process\_handle](https://github.com/0x90sh/fairplaylab_detections/tree/main/usermode/process_handle)
