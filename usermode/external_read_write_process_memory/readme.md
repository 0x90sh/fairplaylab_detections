# external read write process memory

This demo shows what a usermode AntiCheat can and cannot see when another process reads or writes game memory.

The important part is simple. External reads happen in the attacker process, so the game process does not get a clean event for every read. Writes are easier to catch when the game checks important values or regions for impossible changes.

## files

- `src/game.cpp` starts a fake game value and prints its pid and address
- `src/cheat.cpp` opens the game process, reads the value, then writes `9999`
- `src/anticheat.cpp` checks the value and logs new external handles to the game
- `bin/windows-x64/` contains prebuilt demo binaries

## build

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
```

## run

Start the fake game:

```bat
build\Release\game.exe
```

Copy the printed pid and address, then start the AntiCheat:

```bat
build\Release\anticheat.exe <game_pid> <address_hex>
```

Run the external memory tool from another console:

```bat
build\Release\cheat.exe <game_pid> <address_hex>
```

Expected result:

- the AntiCheat logs normal `+1` value changes
- after the write, it logs that the value jumped
- it also logs the external process handle when it can duplicate and verify it

This is a demo signal, not a magic fix. Reads are still weak from usermode. Writes are more visible because the protected value changes in the game process.
