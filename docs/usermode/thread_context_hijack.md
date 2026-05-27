---
description: Thread context hijack detection from usermode.
---

# usermode:thread\_context\_hijack

**Cheat**

**Type**: External usermode

**Goal**: Reuse an existing game thread instead of creating a new obvious thread.

**AntiCheat**

**Type**: Usermode

**Goal**: Detect thread instruction pointers outside known modules and private executable memory.

Notes:

Remote thread injection is noisy. A new thread appears, and its start address can point at `LoadLibraryA` or private executable memory. Thread context hijacking tries to avoid that by reusing a thread that already exists.

The usual flow is simple:

- open a target thread
- suspend it
- read its context
- change the instruction pointer
- resume it

No new payload thread is needed. That makes thread creation monitoring weaker, but it does not remove the final memory artifact. The thread still has to execute somewhere.

This demo creates a worker thread in `game.exe`, then `hijacker.exe` redirects that worker into a tiny private executable loop. The AntiCheat side samples the worker context and checks whether the instruction pointer still belongs to a loaded module.

<figure><img src="../.gitbook/assets/thread_context_hijack.png" alt=""><figcaption><p><a href="https://github.com/0x90sh/fairplaylab_detections/tree/main/usermode/thread_context_hijack">https://github.com/0x90sh/fairplaylab_detections/tree/main/usermode/thread_context_hijack</a></p></figcaption></figure>

#### Cheater

The hijacker writes a tiny loop into private executable memory.

```cpp
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
```

Then it suspends the worker thread, changes the instruction pointer, and resumes it.

```cpp
SuspendThread(thread);
GetThreadContext(thread, &context);
context.Rip = reinterpret_cast<DWORD64>(remote_code);
SetThreadContext(thread, &context);
ResumeThread(thread);
```

#### AntiCheat

The monitor samples the worker thread context. If the instruction pointer is outside every loaded module, something is wrong.

```cpp
if (!address_in_modules(ip, modules)) {
    std::cout << "[anticheat] worker context outside module\n";
}
```

It also scans memory for executable private regions.

```cpp
if (info.State == MEM_COMMIT &&
    info.Type == MEM_PRIVATE &&
    has_execute(info.Protect)) {
    std::cout << "[anticheat] executable private memory\n";
}
```

The demo worker increments a counter. After the hijack, the counter stops. That is not a universal detection, but it is useful for showing that the original thread is no longer running normal worker code.

#### Stealth Notes

Short lived hijacks are harder to catch. A cheat can suspend a thread, run a small stub, restore the original context, and resume normal execution before a slow monitor notices.

APC based injection and fiber tricks have the same problem. They try to avoid a fresh obvious thread, but execution still lands in code that must be backed by some memory region.

Better detection comes from combining views:

- thread context sampling
- executable private memory scanning
- code section hashing
- callback and function pointer validation
- timing anomalies in important worker threads

Usermode cannot make this perfect. It can still make the cheap versions very visible.

#### Build

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
```

#### Run

```bat
build\Release\game.exe
build\Release\hijacker.exe <pid> <worker_tid>
```

Full source is here:

[https://github.com/0x90sh/fairplaylab\_detections/tree/main/usermode/thread\_context\_hijack](https://github.com/0x90sh/fairplaylab_detections/tree/main/usermode/thread_context_hijack)
