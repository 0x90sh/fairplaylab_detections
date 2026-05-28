---
description: Real ObRegisterCallbacks driver PoC for process and thread handle protection.
---

# Process Handle Callbacks

**Cheat**

**Type**: Usermode external helper

**Goal**: Open or duplicate process and thread handles with rights useful for memory access, injection, or thread hijacking.

**AntiCheat**

**Type**: Kernel driver

**Goal**: Strip dangerous handle rights before the caller receives the handle and record the attempt.

Notes:

This is the first kernel PoC because it directly upgrades the existing usermode handle examples. Usermode can see a bad handle after it exists. Kernel mode can reduce the requested access inside an object pre callback before the handle is returned.

The driver uses `ObRegisterCallbacks` for process and thread objects. The client sets a target PID. When another process asks for dangerous access to that target, the driver removes rights and writes an event into a ring buffer.

#### What It Blocks

For process handles:

- memory read
- memory write
- memory operation
- remote thread creation
- duplicate handle
- terminate
- suspend and resume

For thread handles:

- set context
- suspend and resume
- terminate

This does not stop a kernel cheat. A hostile driver can write memory without asking for a usermode process handle. This PoC is about closing the usermode path cleanly and collecting useful signal.

#### Detection Value

A stripped handle event is strong because it shows intent. The caller asked for rights that are useful for cheating. Pair it with parent process, signer, launch time, and later memory or injection signals.

The driver does not ban. It records:

- requestor PID
- target PID
- object kind
- original requested access
- stripped access

#### Build

Build the client from the repo root:

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
```

Build the driver from an x64 Native Tools Command Prompt with WDK installed:

```bat
msbuild kernel\process_handle_callbacks\driver\fpl_handle_guard.vcxproj /p:Configuration=Release /p:Platform=x64
```

#### Run

Enable test signing on a lab VM first:

```bat
bcdedit /set testsigning on
shutdown /r /t 0
```

Load:

```bat
sc create fpl_handle_guard type= kernel binPath= "%CD%\kernel\process_handle_callbacks\bin\windows-x64\fpl_handle_guard.sys"
sc start fpl_handle_guard
```

Protect a game PID:

```bat
kernel\process_handle_callbacks\bin\windows-x64\process_handle_callbacks_client.exe set <pid>
```

Probe handle access from another process:

```bat
kernel\process_handle_callbacks\bin\windows-x64\process_handle_callbacks_client.exe probe <pid>
```

Read events:

```bat
kernel\process_handle_callbacks\bin\windows-x64\process_handle_callbacks_client.exe events
```

Unload:

```bat
sc stop fpl_handle_guard
sc delete fpl_handle_guard
```

Full source:

[https://github.com/0x90sh/fairplaylab_detections/tree/main/kernel/process_handle_callbacks](https://github.com/0x90sh/fairplaylab_detections/tree/main/kernel/process_handle_callbacks)

References:

- [ObRegisterCallbacks](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks)
- [OB_CALLBACK_REGISTRATION](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_callback_registration)
- [Windows security model for driver developers](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/windows-security-model)
