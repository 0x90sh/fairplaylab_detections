#include "client_common.h"
#include "../../protocol.h"

#include <iomanip>

constexpr auto device_path = L"\\\\.\\FplHandleGuard";

void usage()
{
    std::cout << "usage:\n";
    std::cout << "  process_handle_callbacks_client set <pid>\n";
    std::cout << "  process_handle_callbacks_client events\n";
    std::cout << "  process_handle_callbacks_client probe <pid>\n";
}

int wmain(int argc, wchar_t** argv)
{
    if (argc < 2) {
        usage();
        return 1;
    }

    const auto device = open_device(device_path);
    if (device == INVALID_HANDLE_VALUE) {
        print_last_error("open device");
        return 1;
    }

    const std::wstring command = argv[1];

    if (command == L"set") {
        if (argc < 3) {
            usage();
            CloseHandle(device);
            return 1;
        }

        FPL_HANDLE_TARGET_REQUEST request{};
        request.ProcessId = parse_u32(argv[2]);

        if (!ioctl_buffer(device, IOCTL_FPL_HANDLE_SET_TARGET, &request, sizeof(request), nullptr, 0, nullptr)) {
            print_last_error("set target");
            CloseHandle(device);
            return 1;
        }

        std::cout << "protected pid set to " << request.ProcessId << "\n";
        CloseHandle(device);
        return 0;
    }

    if (command == L"events") {
        FPL_HANDLE_EVENT_BATCH batch{};
        DWORD bytes = 0;

        if (!ioctl_buffer(device, IOCTL_FPL_HANDLE_GET_EVENTS, nullptr, 0, &batch, sizeof(batch), &bytes)) {
            print_last_error("get events");
            CloseHandle(device);
            return 1;
        }

        std::cout << "target pid: " << batch.TargetPid << "\n";
        std::cout << "events: " << batch.Count << "\n";

        for (ULONG i = 0; i < batch.Count; ++i) {
            const auto& item = batch.Events[i];
            std::cout << "[" << i << "] requestor=" << item.RequestorPid
                      << " target=" << item.TargetPid
                      << " kind=" << item.ObjectKind
                      << " original=0x" << std::hex << item.OriginalAccess
                      << " stripped=0x" << item.StrippedAccess
                      << std::dec << "\n";
        }

        CloseHandle(device);
        return 0;
    }

    if (command == L"probe") {
        if (argc < 3) {
            usage();
            CloseHandle(device);
            return 1;
        }

        const auto pid = parse_u32(argv[2]);
        const auto process = OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            pid
        );

        if (!process) {
            print_last_error("open process probe");
        } else {
            std::cout << "open process returned a handle. try events to see stripped access\n";
            CloseHandle(process);
        }

        CloseHandle(device);
        return 0;
    }

    usage();
    CloseHandle(device);
    return 1;
}
