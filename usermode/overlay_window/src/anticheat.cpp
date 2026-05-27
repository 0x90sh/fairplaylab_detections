#include <windows.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <iostream>
#include <set>
#include <string>
#include <thread>
#include <vector>

static std::set<HWND> flagged_windows;

static std::string to_lower(std::string text) {
    std::transform(
        text.begin(),
        text.end(),
        text.begin(),
        [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        }
    );

    return text;
}

static bool contains_ci(const std::string& haystack, const std::string& needle) {
    return to_lower(haystack).find(to_lower(needle)) != std::string::npos;
}

static void print_window(HWND hwnd, const std::string& title, const std::string& class_name, const std::vector<std::string>& reasons) {
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);

    std::cout << "[anticheat] suspicious window\n";
    std::cout << "  hwnd=0x" << std::hex << reinterpret_cast<std::uintptr_t>(hwnd) << std::dec << "\n";
    std::cout << "  pid=" << pid << "\n";
    std::cout << "  class=" << class_name << "\n";
    std::cout << "  title=" << title << "\n";

    for (const auto& reason : reasons) {
        std::cout << "  reason=" << reason << "\n";
    }

    std::cout << "\n";
}

static BOOL CALLBACK enum_windows_proc(HWND hwnd, LPARAM) {
    if (!IsWindowVisible(hwnd)) {
        return TRUE;
    }

    char title_buffer[256] = {};
    char class_buffer[256] = {};

    GetWindowTextA(hwnd, title_buffer, sizeof(title_buffer));
    GetClassNameA(hwnd, class_buffer, sizeof(class_buffer));

    const std::string title = title_buffer;
    const std::string class_name = class_buffer;
    std::vector<std::string> reasons;

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

    if (overlay_flags) {
        reasons.push_back("topmost layered transparent");
    }

    if (!reasons.empty() && !flagged_windows.count(hwnd)) {
        flagged_windows.insert(hwnd);
        print_window(hwnd, title, class_name, reasons);
    }

    return TRUE;
}

int main() {
    std::cout << "[anticheat] window scan started\n";

    while (true) {
        EnumWindows(enum_windows_proc, 0);
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}
