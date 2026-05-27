# FairplayLab Detections

Runnable windows examples for the FairplayLab Bible.

Full docs:

https://bible.fairplaylab.org/

## layout

- `docs/` contains the GitBook source
- `docs/usermode/` contains usermode detection writeups
- `usermode/` contains runnable usermode demos
- `usermode/code_injection/` shows dll injection and private executable thread signals
- `usermode/external_read_write_process_memory/` shows external process memory reads and writes
- `usermode/internal_read_write_memory/` shows internal memory reads, writes, patches, and usermode checks
- `usermode/overlay_window/` shows overlay window detection
- `usermode/process_handle/` shows process handle detection and handle hijacking
- `usermode/thread_context_hijack/` shows hijacking an existing thread context

Later categories should live next to `usermode/` with the same style, for example `kernel/`, `hypervisor/`, and `dma/`.

Each example uses the same folder shape:

```text
usermode/detection_name/
  CMakeLists.txt
  readme.md
  assets/
  bin/windows-x64/
  src/
```

## build

Build everything from the repo root:

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
```

Or build only one example from its folder:

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
```

The checked in binaries live in `bin/windows-x64`. Fresh local builds live in `build`.
