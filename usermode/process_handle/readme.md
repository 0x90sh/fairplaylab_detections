# process handle detection

This demo watches for other processes opening handles to the AntiCheat process.

The AntiCheat queries the system handle table, duplicates suspicious handles into its own process, verifies that they point back to itself, then closes handles from non trusted pids.

This is a decent prevention trick for a toy process, but it has limits. Legit software can open handles too. A cheat can also duplicate a handle from a trusted process if it can find a useful one.

## files

- `src/anticheat.cpp` monitors handles to itself
- `src/cheat_open_handle.cpp` opens a direct handle to the target pid
- `src/cheat_hijack_handle.cpp` duplicates a known handle from another process
- `bin/windows-x64/` contains prebuilt demo binaries

## build

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
```

## run

Start the monitor:

```bat
build\Release\anticheat.exe
```

Copy the printed pid, then open a handle from another console:

```bat
build\Release\cheat_open_handle.exe <anticheat_pid>
```

To test handle hijacking, pass the process that owns the source handle, the source handle value in hex, and the target pid:

```bat
build\Release\cheat_hijack_handle.exe <source_pid> <source_handle_hex> <anticheat_pid>
```

Expected result:

- direct handles from non trusted pids are detected and closed
- trusted pids are logged as allowed
- hijacking a trusted handle shows why a plain pid whitelist is weak
