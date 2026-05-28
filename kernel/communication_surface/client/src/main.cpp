#include "client_common.h"
#include "../../protocol.h"

#include <iomanip>

constexpr auto device_path = L"\\\\.\\FplCommSurface";

void print_audit(HANDLE device)
{
    FPL_COMM_AUDIT_BATCH batch{};
    DWORD bytes = 0;

    if (!ioctl_buffer(device, IOCTL_FPL_COMM_GET_AUDIT, nullptr, 0, &batch, sizeof(batch), &bytes)) {
        print_last_error("get audit");
        return;
    }

    std::cout << "audit events: " << batch.Count << "\n";

    for (ULONG i = 0; i < batch.Count; ++i) {
        const auto& item = batch.Events[i];
        std::cout << "[" << i << "] pid=" << item.ClientPid
                  << " ioctl=0x" << std::hex << item.IoControlCode
                  << std::dec
                  << " in=" << item.InputSize
                  << " out=" << item.OutputSize
                  << "\n";
    }
}

void print_self_check(HANDLE device)
{
    FPL_COMM_SELF_CHECK check{};
    DWORD bytes = 0;

    if (!ioctl_buffer(device, IOCTL_FPL_COMM_VALIDATE_SELF, nullptr, 0, &check, sizeof(check), &bytes)) {
        print_last_error("validate self");
        return;
    }

    std::cout << "major functions checked: " << check.MajorFunctionCount << "\n";
    std::cout << "outside image targets: " << check.OutsideImageCount << "\n";
}

int wmain(int argc, wchar_t** argv)
{
    const auto device = open_device(device_path);
    if (device == INVALID_HANDLE_VALUE) {
        print_last_error("open device");
        return 1;
    }

    if (argc > 1 && std::wstring(argv[1]) == L"audit") {
        print_audit(device);
        CloseHandle(device);
        return 0;
    }

    if (argc > 1 && std::wstring(argv[1]) == L"self") {
        print_self_check(device);
        CloseHandle(device);
        return 0;
    }

    FPL_COMM_PING ping{};
    ping.ClientPid = GetCurrentProcessId();
    ping.Nonce = 0x20260528;
    wcscpy_s(ping.Text, L"fairplaylab ping");

    DWORD bytes = 0;

    if (!ioctl_buffer(device, IOCTL_FPL_COMM_PING, &ping, sizeof(ping), &ping, sizeof(ping), &bytes)) {
        print_last_error("ping");
        CloseHandle(device);
        return 1;
    }

    std::wcout << L"driver replied: pid=" << ping.ClientPid
               << L" nonce=0x" << std::hex << ping.Nonce
               << std::dec
               << L" text=" << ping.Text
               << L"\n";

    CloseHandle(device);
    return 0;
}
