---
description: Real driver PoC for safe usermode and kernel communication plus channel detection.
---

# Communication Surface

**Cheat**

**Type**: Usermode client with kernel helper

**Goal**: Send commands, addresses, and results between usermode and kernel mode.

**AntiCheat**

**Type**: Kernel driver

**Goal**: Design a safe communication surface and detect suspicious command channels.

Notes:

Every kernel cheat needs control. IOCTLs are the obvious channel, but not the only one. Cheats can use shared sections, event pairs, service relays, registry mailboxes, hijacked dispatch paths, or callbacks that fire during normal system activity.

This PoC shows the defensive side. It creates a named device with an admin only security descriptor, accepts a tiny ping IOCTL, records audit events, and exposes a self check that validates its own dispatch table targets.

It does not implement stealth communication tricks. It implements the checks that explain why those tricks leak.

#### What The Driver Does

- creates `\Device\FplCommSurface`
- exposes `\\.\FplCommSurface`
- restricts access to system and administrators
- logs every IOCTL caller PID and buffer size
- replies to a ping request
- validates that its major function pointers still point inside the driver image

#### Detecting Cheat Channels

IOCTL broker:

- broad device ACL
- unknown client process
- high command rate
- command sizes that look like memory requests
- command timing tied to game frames

Shared section ring:

- shared section handle
- paired events
- tight wakeup rhythm
- memory changes after event pulses

Service relay:

- trusted looking process with strange parentage
- service created near game launch
- broker talks to an unexpected client
- broker owns the driver device handle

Hijacked dispatch:

- usermode opens a legitimate looking device
- driver object dispatch pointer points outside the owner image
- dispatch target points into executable pool
- owner driver code changed after load

Callback mailbox:

- callback target outside expected image
- callback side effects do not match the owner driver
- hidden executable memory referenced from callback state

#### Build

Build the client:

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
```

Build the driver:

```bat
msbuild kernel\communication_surface\driver\fpl_comm_surface.vcxproj /p:Configuration=Release /p:Platform=x64
```

#### Run

Load:

```bat
sc create fpl_comm_surface type= kernel binPath= "%CD%\kernel\communication_surface\bin\windows-x64\fpl_comm_surface.sys"
sc start fpl_comm_surface
```

Send a ping:

```bat
kernel\communication_surface\bin\windows-x64\communication_surface_client.exe
```

Read audit events:

```bat
kernel\communication_surface\bin\windows-x64\communication_surface_client.exe audit
```

Validate dispatch ownership:

```bat
kernel\communication_surface\bin\windows-x64\communication_surface_client.exe self
```

Unload:

```bat
sc stop fpl_comm_surface
sc delete fpl_comm_surface
```

Full source:

[https://github.com/0x90sh/fairplaylab_detections/tree/main/kernel/communication_surface](https://github.com/0x90sh/fairplaylab_detections/tree/main/kernel/communication_surface)

References:

- [Device Input and Output Control](https://learn.microsoft.com/windows/desktop/DevIO/device-input-and-output-control-ioctl-)
- [Controlling device access](https://learn.microsoft.com/en-au/windows-hardware/drivers/kernel/controlling-device-access)
- [SDDL for device objects](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/sddl-for-device-objects)
- [Security issues for section objects and views](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/security-issues-for-section-objects-and-views)
- [DRIVER_OBJECT](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_driver_object)
- [Rekall driver IRP hook detection notes](https://rekall.readthedocs.io/en/gh-pages/Manual/Plugins/Windows/DriverIrp.html)
