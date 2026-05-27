---
description: Detecting external read and write process memory attempts.
---

# External Memory Access

**Cheat**

**Type**: External usermode

**Goal**: Read or write game process memory from another process.

**AntiCheat**

**Type**: Usermode

**Goal**: Catch suspicious handles and detect bad value changes.

Notes:

External process memory reads are one of the annoying limits of usermode AntiCheat work. The read happens in the attacker process, so the game does not get a clean callback saying that a value was read. You can watch handles, harden access, encrypt values, and add friction, but you should not pretend that every read is visible from usermode.

Writes are different. If a cheat changes memory, the game state changes. That means the AntiCheat can check important values, hashes, counters, or state transitions and catch impossible changes. This can get CPU heavy if you check too much, so keep it focused.

Kernelmode helps here because it can see access at a better layer. Usermode can still give useful signals, but it is mostly hardening and integrity checks.

<figure><img src="../.gitbook/assets/extrwprocmem.png" alt=""><figcaption><p><a href="https://github.com/0x90sh/fairplaylab_detections/tree/main/usermode/external_read_write_process_memory">https://github.com/0x90sh/fairplaylab_detections/tree/main/usermode/external_read_write_process_memory</a></p></figcaption></figure>

#### Cheater

The external tool opens the game process with read and write rights, reads the demo value, then writes `9999`.

```cpp
HANDLE game = OpenProcess(
    PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
    FALSE,
    game_pid
);

ReadProcessMemory(
    game,
    reinterpret_cast<LPCVOID>(address),
    &value,
    sizeof(value),
    &bytes_read
);

WriteProcessMemory(
    game,
    reinterpret_cast<LPVOID>(address),
    &new_value,
    sizeof(new_value),
    &bytes_written
);
```

#### AntiCheat

The demo game increments `protected_value` by one every second. The AntiCheat reads that value and flags changes that do not match the expected pattern.

```cpp
const int delta = current - last_value;
if (delta > 1 || delta < 0) {
    std::cout << "[value] changed from " << last_value
              << " to " << current << ", expected +1\n";
}
```

It also scans system handles and logs new external handles that really point to the game process.

```cpp
HANDLE owner = OpenProcess(
    PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
    FALSE,
    owner_pid
);

DuplicateHandle(
    owner,
    reinterpret_cast<HANDLE>(entry.handle_value),
    GetCurrentProcess(),
    &duplicated,
    PROCESS_QUERY_LIMITED_INFORMATION,
    FALSE,
    0
);

if (GetProcessId(duplicated) == game_pid) {
    std::cout << "[handle] pid=" << owner_pid << " opened handle\n";
}
```

#### Build

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
```

#### Run

```bat
build\Release\game.exe
build\Release\anticheat.exe <game_pid> <address_hex>
build\Release\cheat.exe <game_pid> <address_hex>
```

Full source is here:

[https://github.com/0x90sh/fairplaylab\_detections/tree/main/usermode/external\_read\_write\_process\_memory](https://github.com/0x90sh/fairplaylab_detections/tree/main/usermode/external_read_write_process_memory)
