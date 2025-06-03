# Handle Detection Demo

This project demonstrates a simple anti-cheat detection vector based on process handles. It includes three components:

1. **anticheat**  
   Monitors system handles and enforces a whitelist of trusted PIDs. Any non-whitelisted handle opened to the “game” process is closed immediately.

2. **cheat_open_handle**  
   Attempts to open a new handle to the game via `OpenProcess`. The monitor will detect and close this handle, since the PID is not whitelisted.

3. **cheat_hijack_handle**  
   Bypasses the monitor by duplicating an existing handle from a whitelisted process. Because the source PID is trusted, the monitor does not close it.

---

## Setup Instructions

1. **Prerequisites**  
   - Windows 10 (x64)  
   - Visual Studio (any edition with “Desktop development with C++” workload)  
   - Developer Command Prompt for VS (run as x64)

2. **Compile each component**  
   Open the VS Developer Command Prompt and run:

   ```batch
   cl /EHsc anticheat.cpp /link ntdll.lib
   cl /EHsc cheat_open_handle.cpp /link /SUBSYSTEM:CONSOLE
   cl /EHsc cheat_hijack_handle.cpp /link /SUBSYSTEM:CONSOLE
    ```

* `anticheat.cpp` requires `ntdll.lib`.
* The other two programs use standard Win32 APIs and need no extra libraries.

3. **Run the demo**

   * First, launch **anticheat.exe**. It will print its PID and the list of whitelisted PIDs.
   * In a separate console, run `cheat_open_handle.exe <GamePID>`. The monitor will close that handle and log a red warning.
   * Finally, run `cheat_hijack_handle.exe`. It will duplicate a handle from a whitelisted PID, and the monitor will log it in green (trusted), allowing it to remain open.
   * Whitelist is not implemented... obviously a handle with configured PID must exist.

---

## References

* User‐mode process‐handle detection vector documentation:
  [https://bible.fairplaylab.org/detection-vectors/usermode-process\_handle](https://bible.fairplaylab.org/detection-vectors/usermode-process_handle)
