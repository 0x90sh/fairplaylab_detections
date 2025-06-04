# Overlay Window Detection Demo

This project illustrates a simple anti‐cheat detection vector based on window enumeration. It includes two components:

1. **anticheat**
   Scans all top‐level windows for suspicious titles, class names (e.g., containing “cheat”, “aimbot”, “esp”), or extended styles (`WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TRANSPARENT`) and logs them in color.

2. **OverlayDemo**
   A proof-of-concept “cheat” that either creates its own transparent topmost overlay window or hijacks an existing overlay (e.g., NVIDIA GeForce or AMD Radeon) based on user input.

---

## Setup Instructions

1. **Prerequisites**

   * Windows 10 (x64)
   * Visual Studio (any edition with “Desktop development with C++” workload)
   * Developer Command Prompt for VS (run as x64)

2. **Compile each component**
   In the VS Developer Command Prompt, run:

   ```batch
   cl /EHsc anticheat.cpp user32.lib
   cl /EHsc OverlayDemo.cpp user32.lib gdi32.lib
   ```

   * `anticheat.cpp` uses only Win32 APIs—no extra libraries required.
   * `OverlayDemo.cpp` requires linking `user32.lib` and `gdi32.lib` for window management.

3. **Run the demo**

   * First, launch **anticheat.exe**. It will enumerate all visible windows and print any that match suspicious titles, class names, or overlay style flags.
   * In a separate console, run `OverlayDemo.exe`. When prompted, press **Y** to hijack an existing overlay window (if present) or **N** to create a new transparent overlay.
   * Observe that if **OverlayDemo** opens a window with class/title containing “cheat” or uses the topmost+layered+transparent combination, **anticheat** will highlight it in red as suspicious.

---

## References

* User‐mode overlay/windows detection vector:
  [https://bible.fairplaylab.org/detection-vectors/usermode-overlay](https://bible.fairplaylab.org/detection-vectors/usermode-overlay)

---

**Filenames**

* `anticheat.cpp` – window‐scan detector
* `OverlayDemo.cpp` – overlay “cheat” PoC
