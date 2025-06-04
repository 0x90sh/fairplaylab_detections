#include <windows.h>
#include <iostream>

LRESULT CALLBACK OverlayProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_DESTROY) PostQuitMessage(0);
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

int main() {
    std::cout << "Hijack existing overlay? (y/n): ";
    char choice; std::cin >> choice;

    HWND hOverlay = NULL;
    if (choice == 'y' || choice == 'Y') {
        // Try NVIDIA GeForce Overlay
        hOverlay = FindWindowA("CEF-OSC-WIDGET", "NVIDIA GeForce Overlay");
        if (!hOverlay) {
            // Fallback: AMD Radeon Overlay
            hOverlay = FindWindowA(NULL, "AMD Radeon Overlay");
        }
        if (hOverlay) {
            // Make the found window topmost, layered, and click‐through
            LONG ex = GetWindowLongA(hOverlay, GWL_EXSTYLE);
            ex |= WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TRANSPARENT;
            SetWindowLongA(hOverlay, GWL_EXSTYLE, ex);
            // Fully transparent (alpha = 1)
            SetLayeredWindowAttributes(hOverlay, 0, 1, LWA_ALPHA);
            std::cout << "Hijacked overlay HWND=" << hOverlay << "\n";
        } else {
            std::cout << "No existing overlay found. Exiting.\n";
            return 0;
        }
    } else {
        // Register our own overlay window class
        const char* clsName = "MyCheatOverlayClass";
        WNDCLASSEXA wc = { sizeof(WNDCLASSEXA), CS_HREDRAW | CS_VREDRAW,
                          OverlayProc, 0, 0, GetModuleHandleA(NULL),
                          NULL, LoadCursorA(NULL, IDC_ARROW),
                          NULL, NULL, clsName, NULL };
        RegisterClassExA(&wc);

        // Create a topmost, layered, transparent, click‐through window
        hOverlay = CreateWindowExA(
            WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW,
            clsName, "myCheatOverlay",
            WS_POPUP,
            0, 0,
            GetSystemMetrics(SM_CXSCREEN),
            GetSystemMetrics(SM_CYSCREEN),
            NULL, NULL,
            wc.hInstance,
            NULL
        );
        // Fully transparent (alpha = 1)
        SetLayeredWindowAttributes(hOverlay, 0, 1, LWA_ALPHA);

        ShowWindow(hOverlay, SW_SHOWNOACTIVATE);
        std::cout << "Created new overlay HWND=" << hOverlay << "\n";

        // Simple message loop to keep the window alive
        MSG msg;
        while (GetMessageA(&msg, NULL, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }

    return 0;
}
