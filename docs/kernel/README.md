---
description: Kernel mode driver PoCs for anti cheat detection.
---

# Kernel

Kernel mode examples are real driver PoCs, not console simulations.

Each topic has a WDM driver and a tiny usermode client:

```text
kernel/topic_name/
  driver/
    *.c
    *.inf
    *.vcxproj
  client/
    src/
    CMakeLists.txt
  bin/windows-x64/
```

The clients build from the repo root with CMake. The drivers require Visual Studio with the Windows Driver Kit installed. Build and run the drivers inside a VM first. A bad kernel driver can crash the machine.

#### Topics

- [Process Handle Callbacks](process_handle_callbacks.md)
- [Process Image Thread Monitor](process_image_thread_monitor.md)
- [Driver Inventory](driver_inventory.md)
- [Communication Surface](communication_surface.md)

#### Driver Build Requirements

- Visual Studio 2022 with C++ desktop tools
- Windows Driver Kit for Windows 10 or Windows 11
- admin shell for loading and unloading drivers
- test signing enabled on a lab VM

Enable test signing:

```bat
bcdedit /set testsigning on
shutdown /r /t 0
```

Build clients:

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
```

Build a driver from an x64 Native Tools Command Prompt:

```bat
msbuild kernel\process_handle_callbacks\driver\fpl_handle_guard.vcxproj /p:Configuration=Release /p:Platform=x64
```

Load a driver:

```bat
sc create fpl_handle_guard type= kernel binPath= "%CD%\kernel\process_handle_callbacks\bin\windows-x64\fpl_handle_guard.sys"
sc start fpl_handle_guard
```

Unload it:

```bat
sc stop fpl_handle_guard
sc delete fpl_handle_guard
```

#### Safety Line

These PoCs use documented driver APIs. They do not include vulnerable driver abuse, manual mapping, PatchGuard bypasses, driver hiding, callback removal, or dispatch hijacking code.
