# code injection

This demo shows two common usermode code injection shapes and the signals they leave behind.

![code injection demo](assets/code_injection.png)

The first path is classic `LoadLibraryA` through a remote thread. It creates a normal module entry, so the target can see a new dll in the module list.

The second path is a small no-op private executable thread. It does not implement a real manual mapper, but it leaves the same kind of usermode signals that manual mapped code often leaves behind. Executable `MEM_PRIVATE` memory and a thread start address outside normal modules.

## files

- `src/game.cpp` runs the monitor inside the target process
- `src/payload.cpp` builds `payload.dll`
- `src/load_library_loader.cpp` loads `payload.dll` with a remote `LoadLibraryA` thread
- `src/private_thread_loader.cpp` starts a no-op thread from private executable memory
- `bin/windows-x64/` contains prebuilt demo binaries

## what it checks

- new modules after startup
- demo payload dll loaded by the windows loader
- executable `MEM_PRIVATE` regions
- thread start addresses outside known modules

## extra notes in gitbook

The GitBook page also covers the bigger injection family:

- classic dll injection
- manual mapping
- reflective loading
- section mapping
- APC injection
- thread hijacking
- `SetWindowsHookEx`
- module stomping
- export and IAT hooks

Those do not all need their own example folder. The useful detection lesson is the same: compare module list, memory map, thread execution, and code integrity. If those views disagree, injected code usually leaked somewhere.

## build

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
```

## run

Start the target:

```bat
build\Release\game.exe
```

Copy the pid, then run classic dll injection:

```bat
build\Release\load_library_loader.exe <pid> build\Release\payload.dll
```

Run the private executable thread demo:

```bat
build\Release\private_thread_loader.exe <pid>
```

Expected result:

- loading the dll creates a new module signal
- the payload thread is visible as a normal image backed thread
- the private thread creates executable private memory
- the suspended private thread start address is outside the module list

This is not a stealth injection toolkit. It is a detection demo for the artifacts those techniques usually leave.
