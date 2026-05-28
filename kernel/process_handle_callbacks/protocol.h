#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

#define FPL_HANDLE_DEVICE_TYPE 0x8001

#define IOCTL_FPL_HANDLE_SET_TARGET CTL_CODE(FPL_HANDLE_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_FPL_HANDLE_GET_EVENTS CTL_CODE(FPL_HANDLE_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_DATA)

#define FPL_HANDLE_EVENT_CAPACITY 64

typedef struct _FPL_HANDLE_TARGET_REQUEST {
    ULONG ProcessId;
} FPL_HANDLE_TARGET_REQUEST;

typedef struct _FPL_HANDLE_EVENT {
    ULONG RequestorPid;
    ULONG TargetPid;
    ULONG ObjectKind;
    ULONG OriginalAccess;
    ULONG StrippedAccess;
} FPL_HANDLE_EVENT;

typedef struct _FPL_HANDLE_EVENT_BATCH {
    ULONG TargetPid;
    ULONG Count;
    FPL_HANDLE_EVENT Events[FPL_HANDLE_EVENT_CAPACITY];
} FPL_HANDLE_EVENT_BATCH;
