#pragma once

#include <windows.h>

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

inline HANDLE open_device(const wchar_t* path)
{
    return CreateFileW(
        path,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
}

inline bool ioctl_buffer(
    HANDLE device,
    DWORD code,
    void* input,
    DWORD input_size,
    void* output,
    DWORD output_size,
    DWORD* bytes
)
{
    DWORD local_bytes = 0;
    const auto ok = DeviceIoControl(
        device,
        code,
        input,
        input_size,
        output,
        output_size,
        &local_bytes,
        nullptr
    );

    if (bytes) {
        *bytes = local_bytes;
    }

    return ok != FALSE;
}

inline std::uint32_t parse_u32(const wchar_t* value)
{
    return static_cast<std::uint32_t>(wcstoul(value, nullptr, 10));
}

inline void print_last_error(const char* action)
{
    std::cout << action << " failed with win32=" << GetLastError() << "\n";
}
