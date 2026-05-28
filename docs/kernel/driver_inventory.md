---
description: Real driver PoC for loaded kernel module inventory.
---

# Driver Inventory

**Cheat**

**Type**: Kernel driver, vulnerable driver, or hidden payload setup

**Goal**: Place privileged code on the system and avoid simple loaded driver checks.

**AntiCheat**

**Type**: Kernel driver

**Goal**: Build a trusted baseline of loaded kernel modules and compare it with other signals.

Notes:

Driver inventory is not enough to catch manual mapped drivers by itself. That is exactly the lesson. A normally loaded driver appears in supported module enumeration. A manual mapped payload may not.

This PoC uses `AuxKlibQueryModuleInformation` to return loaded kernel modules to a usermode client. It gives you the normal loader view. The next step in a real product is to compare this view against executable kernel memory, thread starts, dispatch pointers, callback ownership, and Code Integrity events.

#### What It Reports

- image base
- image size
- module flags
- module path
- truncated state if the fixed output buffer filled up

#### Detection Value

Good use:

- build a module baseline before the game starts
- flag vulnerable drivers that should not be present
- record driver load state for support and forensics
- compare known module ranges against callback and dispatch targets

Bad use:

- assuming a clean module list means the kernel is clean
- banning on an unknown driver name without signer and hardware context
- ignoring vulnerable drivers that loaded and unloaded before the scan

#### Build

Build the client:

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
```

Build the driver:

```bat
msbuild kernel\driver_inventory\driver\fpl_driver_inventory.vcxproj /p:Configuration=Release /p:Platform=x64
```

#### Run

Load:

```bat
sc create fpl_driver_inventory type= kernel binPath= "%CD%\kernel\driver_inventory\bin\windows-x64\fpl_driver_inventory.sys"
sc start fpl_driver_inventory
```

Query:

```bat
kernel\driver_inventory\bin\windows-x64\driver_inventory_client.exe
```

Unload:

```bat
sc stop fpl_driver_inventory
sc delete fpl_driver_inventory
```

Full source:

[https://github.com/0x90sh/fairplaylab_detections/tree/main/kernel/driver_inventory](https://github.com/0x90sh/fairplaylab_detections/tree/main/kernel/driver_inventory)

References:

- [AuxKlibQueryModuleInformation](https://learn.microsoft.com/en-us/windows/desktop/devnotes/auxklibquerymoduleinformation-func)
- [Microsoft recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules)
- [Kernel mode code signing requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-requirements--windows-vista-and-later-)
- [Detecting manually mapped drivers](https://tulach.cc/detecting-manually-mapped-drivers/)
