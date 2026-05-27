# overlay window detection

This demo shows a common usermode overlay signal.

The AntiCheat enumerates visible top level windows and checks for suspicious title or class names, plus the usual overlay style combo:

```text
WS_EX_TOPMOST
WS_EX_LAYERED
WS_EX_TRANSPARENT
```

That combo is useful, but noisy. Legit overlays and desktop windows can look similar, so this should be treated as a signal for follow up process analysis.

## files

- `src/anticheat.cpp` scans windows and prints suspicious ones
- `src/cheat.cpp` creates a transparent overlay or hijacks an existing overlay window
- `bin/windows-x64/` contains prebuilt demo binaries

## build

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
```

## run

Start the scanner:

```bat
build\Release\anticheat.exe
```

Start the overlay demo:

```bat
build\Release\cheat.exe
```

Choose `n` to create a fresh overlay. Choose `y` to try hijacking a known overlay like NVIDIA GeForce Overlay or AMD Radeon Overlay.

Expected result:

- a new overlay gets flagged by class or title text and style flags
- a hijacked overlay is harder to judge because the owning process may look legit
- the detection is useful as a lead, not as a ban reason by itself
