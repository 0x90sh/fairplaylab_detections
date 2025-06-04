#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <thread>
#include <set>

// Helper: convert a string to lowercase
static std::string to_lower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return out;
}

// Helper: case‐insensitive substring check
static bool contains_ci(const std::string& haystack, const std::string& needle) {
    return to_lower(haystack).find(to_lower(needle)) != std::string::npos;
}

// Colors for console output
enum ConsoleColor {
    COLOR_DEFAULT = 7,
    COLOR_WARNING = 12  // light red
};

// Print a message in a given color
static void print_colored(const std::string& msg, ConsoleColor color) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(h, (WORD)color);
    std::cout << msg << "\n";
    SetConsoleTextAttribute(h, COLOR_DEFAULT);
}

// Keep track of HWNDs already flagged
static std::set<HWND> flaggedWindows;

// Callback for EnumWindows
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM) {
    // Skip invisible or zero‐length windows
    if (!IsWindowVisible(hwnd))
        return TRUE;

    // Retrieve window title
    char title[256] = {};
    GetWindowTextA(hwnd, title, sizeof(title));

    // Retrieve window class name
    char cls[256] = {};
    GetClassNameA(hwnd, cls, sizeof(cls));

    std::vector<std::string> reasons;
    std::string strTitle = title;
    std::string strClass = cls;

    // Check for suspicious substrings in title/class
    for (const auto& keyword : { "cheat", "aimbot", "esp" }) {
        if (contains_ci(strTitle, keyword)) {
            reasons.push_back(std::string("Title contains \"") + keyword + "\"");
        }
        if (contains_ci(strClass, keyword)) {
            reasons.push_back(std::string("Class name contains \"") + keyword + "\"");
        }
    }

    // Check for extended style combination: topmost + layered + transparent
    LONG exStyle = GetWindowLongA(hwnd, GWL_EXSTYLE);
    if ((exStyle & WS_EX_TOPMOST) &&
        (exStyle & WS_EX_LAYERED) &&
        (exStyle & WS_EX_TRANSPARENT)) {
        reasons.push_back("Has WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TRANSPARENT");
    }

    if (!reasons.empty()) {
        // Only log if not flagged before
        if (flaggedWindows.find(hwnd) == flaggedWindows.end()) {
            // Mark as flagged
            flaggedWindows.insert(hwnd);

            char buf[64];
            sprintf_s(buf, "HWND=0x%p", (void*)hwnd);

            print_colored("Suspicious Window Found:", COLOR_WARNING);
            std::cout << "  " << buf << "\n";
            std::cout << "  Class: \"" << strClass << "\"\n";
            std::cout << "  Title: \"" << strTitle << "\"\n";
            for (const auto& r : reasons) {
                std::cout << "  -> " << r << "\n";
            }
            std::cout << std::endl;
        }
    }
    return TRUE;  // continue enumeration
}

int main() {
    std::cout << "[*] Starting windowscan loop. Press CTRL+C to exit.\n\n";
    while (true) {
        EnumWindows(EnumWindowsProc, 0);
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
    return 0;
}
