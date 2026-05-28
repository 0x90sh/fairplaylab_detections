#include "client_common.h"
#include "../../protocol.h"

#include <iomanip>

constexpr auto device_path = L"\\\\.\\FplDriverInventory";

int wmain()
{
    const auto device = open_device(device_path);
    if (device == INVALID_HANDLE_VALUE) {
        print_last_error("open device");
        return 1;
    }

    FPL_INVENTORY_BATCH batch{};
    DWORD bytes = 0;

    if (!ioctl_buffer(device, IOCTL_FPL_INVENTORY_QUERY, nullptr, 0, &batch, sizeof(batch), &bytes)) {
        print_last_error("query inventory");
        CloseHandle(device);
        return 1;
    }

    std::cout << "modules: " << batch.Count << "\n";
    std::cout << "truncated: " << batch.Truncated << "\n";

    for (ULONG i = 0; i < batch.Count; ++i) {
        const auto& item = batch.Modules[i];
        std::wcout << L"[" << i << L"] base=0x"
                   << std::hex << item.ImageBase
                   << L" size=0x" << item.ImageSize
                   << std::dec
                   << L" flags=" << item.Flags
                   << L" path=" << item.Path
                   << L"\n";
    }

    CloseHandle(device);
    return 0;
}
