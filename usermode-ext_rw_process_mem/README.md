# External Memory Access Detection Demo

This project demonstrates a simple anti‐cheat detection vector based on external read/write of another process’s memory. It includes three components:

1. **game**
   Simulates a running process with a single global `int protectedValue` that increments by 1 every second and prints its value.

2. **cheat**
   An external program that opens a handle to `game.exe`, reads `protectedValue` once, prints it, then overwrites it with 9999.

3. **anticheat**
   Every second, reads `protectedValue` from `game.exe` and flags any jump greater than +1 as **CRITICAL**. Simultaneously enumerates all system handles via `NtQuerySystemInformation` and logs any new owner PID that opened a handle to `game.exe`.

---

## Setup Instructions

1. **Prerequisites**

   * Windows 10 (x64)
   * Visual Studio (any edition with “Desktop development with C++” workload)
   * Developer Command Prompt for VS (run as x64)

2. **Compile each component**
   In the VS Developer Command Prompt, run:

   ```batch
   cl /EHsc game.cpp
   cl /EHsc cheat.cpp
   cl /EHsc anticheat.cpp /link ntdll.lib
   ```

   * `game.cpp` and `cheat.cpp` use only Win32 APIs—no extra libraries required.
   * `anticheat.cpp` requires linking against `ntdll.lib` for `NtQuerySystemInformation`.

3. **Run the demo**

   1. Launch **game.exe**. It will print its PID and the address of `protectedValue`, then show that `protectedValue` increments by 1 each second.
   2. In another console, run:

      ```batch
      anticheat.exe <GamePID> <ValueAddressHex>
      ```

      Replace `<GamePID>` and `<ValueAddressHex>` with the values printed by `game.exe`.
      You’ll see output like:

      ```
      [anticheat] Monitoring Game PID=4321 at 0x00ABCDEF
      [VALUE] OK: 1235 (Δ=1)
      [HANDLE] New handle to game from PID 4321
      ```
   3. In a third console, run:

      ```batch
      cheat.exe <GamePID> <ValueAddressHex>
      ```

      It will read the current value, print it, then write 9999 to that address.
   4. Observe **game.exe** show:

      ```
      [game] protectedValue = 9999
      ```

      And **anticheat.exe** log:

      ```
      [VALUE] CRITICAL: expected +1 but jumped from 1242 to 9999
      [HANDLE] New handle to game from PID 5678
      ```

---

## References

* Usermode external Read/write process memory:
  [https://bible.fairplaylab.org/detection-vectors/usermode-ext_rw_process_mem](https://bible.fairplaylab.org/detection-vectors/usermode-ext_rw_process_mem)

---

**Filenames**

* `game.cpp`        – simulates a process with a protected integer
* `cheat.cpp`       – external tool that reads and writes `game.exe`’s memory
* `anticheat.cpp`   – detects unexpected value jumps and new handles opened to `game.exe`
