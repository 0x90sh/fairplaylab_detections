#include <windows.h>

#include <iostream>
#include <thread>

static DWORD WINAPI worker_thread(void*) {
    std::cout << "[payload] dll loaded inside pid=" << GetCurrentProcessId() << "\n";

    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(instance);
        HANDLE thread = CreateThread(nullptr, 0, worker_thread, nullptr, 0, nullptr);
        if (thread) {
            CloseHandle(thread);
        }
    }

    return TRUE;
}
