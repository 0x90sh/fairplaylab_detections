---
description: Cheat overlay detection and bypass.
---

# overlay\_window

**Cheat**

**Type**: External usermode

**Goal**: Get a window that can be used for drawing overlays.

**AntiCheat**

**Type**: Usermode

**Goal**: Enumerate windows and flag suspicious overlay behavior.

Notes:

Overlay detection is useful, but it is noisy. A lot of legit software creates topmost, layered, transparent windows. Discord, GPU overlays, capture tools, accessibility tools, and random desktop helpers can all look suspicious if you only check flags.

Names and class names are weak too. If a window says `cheat`, `aimbot`, or `esp`, sure, flag it. A real cheat can just pick a boring name. The better use is to collect signals, connect them to the owning process, and decide what needs deeper analysis.

<figure><img src="../.gitbook/assets/overlay.png" alt=""><figcaption><p><a href="https://github.com/0x90sh/fairplaylab_detections/tree/main/usermode/overlay_window">https://github.com/0x90sh/fairplaylab_detections/tree/main/usermode/overlay_window</a></p></figcaption></figure>

#### Cheater

The demo can create its own overlay window. It uses the classic overlay style combo.

```cpp
HWND hwnd = CreateWindowExA(
    WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW,
    class_name,
    "fpl cheat overlay",
    WS_POPUP,
    0,
    0,
    GetSystemMetrics(SM_CXSCREEN),
    GetSystemMetrics(SM_CYSCREEN),
    nullptr,
    nullptr,
    window_class.hInstance,
    nullptr
);

SetLayeredWindowAttributes(hwnd, 0, 1, LWA_ALPHA);
```

#### AntiCheat

The scanner walks visible top level windows, checks the title and class name, then checks the extended window styles.

```cpp
for (const auto& keyword : { "cheat", "aimbot", "esp" }) {
    if (contains_ci(title, keyword)) {
        reasons.push_back("title contains " + std::string(keyword));
    }

    if (contains_ci(class_name, keyword)) {
        reasons.push_back("class contains " + std::string(keyword));
    }
}

const LONG ex_style = GetWindowLongA(hwnd, GWL_EXSTYLE);
const bool overlay_flags =
    (ex_style & WS_EX_TOPMOST) &&
    (ex_style & WS_EX_LAYERED) &&
    (ex_style & WS_EX_TRANSPARENT);
```

#### Cheater Bypass

Creating a new suspicious window is the easy path. A better bypass is to reuse an overlay that already exists, like a GPU vendor overlay, then draw through that surface or modify its flags.

```cpp
HWND hwnd = FindWindowA("CEF-OSC-WIDGET", "NVIDIA GeForce Overlay");
if (!hwnd) {
    hwnd = FindWindowA(nullptr, "AMD Radeon Overlay");
}

if (hwnd) {
    set_overlay_style(hwnd);
}
```

This is why overlay windows should not be a ban reason by themselves. Treat them as one signal, then look at the owning process, modules, timing, and behavior.

#### Build

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
```

#### Run

```bat
build\Release\anticheat.exe
build\Release\cheat.exe
```

Full source is here:

[https://github.com/0x90sh/fairplaylab\_detections/tree/main/usermode/overlay\_window](https://github.com/0x90sh/fairplaylab_detections/tree/main/usermode/overlay_window)
