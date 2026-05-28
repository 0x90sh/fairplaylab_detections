---
description: Real callback driver PoC for process, image, and thread telemetry.
---

# Process Image Thread Monitor

**Cheat**

**Type**: Usermode loader, injected module, or process helper

**Goal**: Start helpers, create threads, or load code near the game process.

**AntiCheat**

**Type**: Kernel driver

**Goal**: Collect early process, thread, and image events from documented callbacks.

Notes:

This driver is the clean telemetry base. It uses process creation, thread creation, and image load callbacks. The client reads a ring buffer of events from the driver.

The point is not to catch every stealth trick by itself. Callbacks are not perfect. The point is to build a timeline that can be joined with handle callbacks, memory checks, module checks, and communication channel checks.

#### What It Observes

Process callback:

- process ID
- parent process ID
- image path when available

Thread callback:

- process ID
- thread ID
- creation only

Image callback:

- target process ID
- image base low bits
- image size
- image path when available

Image callbacks see normal image mappings. They do not prove that no manual map exists. That is exactly why later checks still need memory ownership and code integrity.

#### Detection Value

Useful joins:

- suspicious parent process starts before the game
- helper opens handles after launch
- late unsigned image load appears in the game
- new thread appears after a denied handle request
- vulnerable driver load appears before hidden kernel behavior

The driver records events only. The policy layer should live above it.

#### Build

Build the client:

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
```

Build the driver:

```bat
msbuild kernel\process_image_thread_monitor\driver\fpl_process_monitor.vcxproj /p:Configuration=Release /p:Platform=x64
```

#### Run

Load:

```bat
sc create fpl_process_monitor type= kernel binPath= "%CD%\kernel\process_image_thread_monitor\bin\windows-x64\fpl_process_monitor.sys"
sc start fpl_process_monitor
```

Read events:

```bat
kernel\process_image_thread_monitor\bin\windows-x64\process_image_thread_monitor_client.exe
```

Clear events:

```bat
kernel\process_image_thread_monitor\bin\windows-x64\process_image_thread_monitor_client.exe clear
```

Unload:

```bat
sc stop fpl_process_monitor
sc delete fpl_process_monitor
```

Full source:

[https://github.com/0x90sh/fairplaylab_detections/tree/main/kernel/process_image_thread_monitor](https://github.com/0x90sh/fairplaylab_detections/tree/main/kernel/process_image_thread_monitor)

References:

- [PsSetCreateProcessNotifyRoutineEx](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)
- [PsSetLoadImageNotifyRoutine](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetloadimagenotifyroutine)
- [Notification routine timing research](https://pmc.ncbi.nlm.nih.gov/articles/PMC7338165/)
