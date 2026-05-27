#include <windows.h>

#include <cstdint>
#include <iostream>

static LRESULT CALLBACK overlay_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
    if (message == WM_DESTROY) {
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcA(hwnd, message, wparam, lparam);
}

static void set_overlay_style(HWND hwnd) {
    LONG style = GetWindowLongA(hwnd, GWL_EXSTYLE);
    style |= WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TRANSPARENT;

    SetWindowLongA(hwnd, GWL_EXSTYLE, style);
    SetLayeredWindowAttributes(hwnd, 0, 1, LWA_ALPHA);
}

static HWND find_existing_overlay() {
    HWND hwnd = FindWindowA("CEF-OSC-WIDGET", "NVIDIA GeForce Overlay");
    if (hwnd) {
        return hwnd;
    }

    return FindWindowA(nullptr, "AMD Radeon Overlay");
}

static HWND create_overlay_window() {
    const char* class_name = "fpl_cheat_overlay";

    WNDCLASSEXA window_class = {};
    window_class.cbSize = sizeof(window_class);
    window_class.style = CS_HREDRAW | CS_VREDRAW;
    window_class.lpfnWndProc = overlay_proc;
    window_class.hInstance = GetModuleHandleA(nullptr);
    window_class.hCursor = LoadCursorA(nullptr, IDC_ARROW);
    window_class.lpszClassName = class_name;

    if (!RegisterClassExA(&window_class)) {
        std::cerr << "[cheat] registerclassex failed, error=" << GetLastError() << "\n";
        return nullptr;
    }

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

    if (!hwnd) {
        std::cerr << "[cheat] createwindowexa failed, error=" << GetLastError() << "\n";
        return nullptr;
    }

    set_overlay_style(hwnd);
    ShowWindow(hwnd, SW_SHOWNOACTIVATE);
    return hwnd;
}

int main() {
    std::cout << "hijack existing overlay? y/n: ";

    char choice = 0;
    std::cin >> choice;

    HWND overlay = nullptr;
    if (choice == 'y' || choice == 'Y') {
        overlay = find_existing_overlay();
        if (!overlay) {
            std::cout << "[cheat] no existing overlay found\n";
            return 0;
        }

        set_overlay_style(overlay);
        std::cout << "[cheat] hijacked hwnd=0x" << std::hex
                  << reinterpret_cast<std::uintptr_t>(overlay) << std::dec << "\n";
        Sleep(30000);
        return 0;
    }

    overlay = create_overlay_window();
    if (!overlay) {
        return 1;
    }

    std::cout << "[cheat] created hwnd=0x" << std::hex
              << reinterpret_cast<std::uintptr_t>(overlay) << std::dec << "\n";

    MSG message = {};
    while (GetMessageA(&message, nullptr, 0, 0)) {
        TranslateMessage(&message);
        DispatchMessageA(&message);
    }

    return 0;
}
