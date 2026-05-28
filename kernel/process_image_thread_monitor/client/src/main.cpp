#include "client_common.h"
#include "../../protocol.h"

#include <iomanip>

constexpr auto device_path = L"\\\\.\\FplMonitor";

const char* type_name(ULONG type)
{
    switch (type) {
    case FPL_MONITOR_EVENT_PROCESS:
        return "process";
    case FPL_MONITOR_EVENT_THREAD:
        return "thread";
    case FPL_MONITOR_EVENT_IMAGE:
        return "image";
    default:
        return "unknown";
    }
}

int wmain(int argc, wchar_t** argv)
{
    const auto device = open_device(device_path);
    if (device == INVALID_HANDLE_VALUE) {
        print_last_error("open device");
        return 1;
    }

    if (argc > 1 && std::wstring(argv[1]) == L"clear") {
        if (!ioctl_buffer(device, IOCTL_FPL_MONITOR_CLEAR_EVENTS, nullptr, 0, nullptr, 0, nullptr)) {
            print_last_error("clear events");
            CloseHandle(device);
            return 1;
        }

        std::cout << "events cleared\n";
        CloseHandle(device);
        return 0;
    }

    FPL_MONITOR_EVENT_BATCH batch{};
    DWORD bytes = 0;

    if (!ioctl_buffer(device, IOCTL_FPL_MONITOR_GET_EVENTS, nullptr, 0, &batch, sizeof(batch), &bytes)) {
        print_last_error("get events");
        CloseHandle(device);
        return 1;
    }

    std::cout << "events: " << batch.Count << "\n";

    for (ULONG i = 0; i < batch.Count; ++i) {
        const auto& item = batch.Events[i];
        std::wcout << L"[" << i << L"] "
                   << type_name(item.Type)
                   << L" pid=" << item.ProcessId
                   << L" parent=" << item.ParentProcessId
                   << L" tid=" << item.ThreadId
                   << L" image_size=" << item.ImageSize
                   << L" path=" << item.Path
                   << L"\n";
    }

    CloseHandle(device);
    return 0;
}
