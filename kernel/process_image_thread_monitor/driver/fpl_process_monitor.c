#include <ntddk.h>
#include <wdmsec.h>
#include <initguid.h>

#include "../protocol.h"

#define FPL_DEVICE_NAME L"\\Device\\FplMonitor"
#define FPL_SYMBOLIC_NAME L"\\DosDevices\\FplMonitor"

DEFINE_GUID(GUID_DEVCLASS_FPL_MONITOR, 0x5f8a63bb, 0x56ed, 0x4f8a, 0xa8, 0xef, 0x3f, 0x11, 0x3d, 0x7a, 0xa0, 0x22);

static PDEVICE_OBJECT g_device;
static UNICODE_STRING g_symbolic_link;
static KSPIN_LOCK g_event_lock;
static ULONG g_event_count;
static FPL_MONITOR_EVENT g_events[FPL_MONITOR_EVENT_CAPACITY];
static BOOLEAN g_process_callback;
static BOOLEAN g_thread_callback;
static BOOLEAN g_image_callback;

static void fpl_copy_path(WCHAR* target, ULONG target_chars, PCUNICODE_STRING source)
{
    if (!target || target_chars == 0) {
        return;
    }

    target[0] = L'\0';

    if (!source || !source->Buffer || source->Length == 0) {
        return;
    }

    ULONG chars = source->Length / sizeof(WCHAR);
    if (chars >= target_chars) {
        chars = target_chars - 1;
    }

    RtlCopyMemory(target, source->Buffer, chars * sizeof(WCHAR));
    target[chars] = L'\0';
}

static void fpl_log_event(const FPL_MONITOR_EVENT* event)
{
    KIRQL old_irql;
    KeAcquireSpinLock(&g_event_lock, &old_irql);

    const ULONG index = g_event_count % FPL_MONITOR_EVENT_CAPACITY;
    g_events[index] = *event;
    ++g_event_count;

    KeReleaseSpinLock(&g_event_lock, old_irql);
}

static void fpl_process_notify(PEPROCESS process, HANDLE process_id, PPS_CREATE_NOTIFY_INFO create_info)
{
    UNREFERENCED_PARAMETER(process);

    if (!create_info) {
        return;
    }

    FPL_MONITOR_EVENT event;
    RtlZeroMemory(&event, sizeof(event));
    event.Type = FPL_MONITOR_EVENT_PROCESS;
    event.ProcessId = HandleToULong(process_id);
    event.ParentProcessId = HandleToULong(create_info->ParentProcessId);
    fpl_copy_path(event.Path, FPL_MONITOR_PATH_CHARS, create_info->ImageFileName);
    fpl_log_event(&event);
}

static void fpl_thread_notify(HANDLE process_id, HANDLE thread_id, BOOLEAN create)
{
    if (!create) {
        return;
    }

    FPL_MONITOR_EVENT event;
    RtlZeroMemory(&event, sizeof(event));
    event.Type = FPL_MONITOR_EVENT_THREAD;
    event.ProcessId = HandleToULong(process_id);
    event.ThreadId = HandleToULong(thread_id);
    fpl_log_event(&event);
}

static void fpl_image_notify(PUNICODE_STRING full_image_name, HANDLE process_id, PIMAGE_INFO image_info)
{
    if (HandleToULong(process_id) == 0) {
        return;
    }

    FPL_MONITOR_EVENT event;
    RtlZeroMemory(&event, sizeof(event));
    event.Type = FPL_MONITOR_EVENT_IMAGE;
    event.ProcessId = HandleToULong(process_id);
    event.ImageBaseLow = PtrToUlong(image_info->ImageBase);
    event.ImageSize = (ULONG)image_info->ImageSize;
    fpl_copy_path(event.Path, FPL_MONITOR_PATH_CHARS, full_image_name);
    fpl_log_event(&event);
}

static NTSTATUS fpl_complete(PIRP irp, NTSTATUS status, ULONG_PTR information)
{
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS fpl_create_close(PDEVICE_OBJECT device, PIRP irp)
{
    UNREFERENCED_PARAMETER(device);
    return fpl_complete(irp, STATUS_SUCCESS, 0);
}

static NTSTATUS fpl_device_control(PDEVICE_OBJECT device, PIRP irp)
{
    UNREFERENCED_PARAMETER(device);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    const ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    void* buffer = irp->AssociatedIrp.SystemBuffer;
    const ULONG output_size = stack->Parameters.DeviceIoControl.OutputBufferLength;

    if (code == IOCTL_FPL_MONITOR_GET_EVENTS) {
        if (output_size < sizeof(FPL_MONITOR_EVENT_BATCH) || !buffer) {
            return fpl_complete(irp, STATUS_BUFFER_TOO_SMALL, 0);
        }

        FPL_MONITOR_EVENT_BATCH* batch = (FPL_MONITOR_EVENT_BATCH*)buffer;
        RtlZeroMemory(batch, sizeof(*batch));

        KIRQL old_irql;
        KeAcquireSpinLock(&g_event_lock, &old_irql);

        const ULONG available = g_event_count < FPL_MONITOR_EVENT_CAPACITY ? g_event_count : FPL_MONITOR_EVENT_CAPACITY;
        batch->Count = available;

        for (ULONG i = 0; i < available; ++i) {
            batch->Events[i] = g_events[i];
        }

        KeReleaseSpinLock(&g_event_lock, old_irql);

        return fpl_complete(irp, STATUS_SUCCESS, sizeof(*batch));
    }

    if (code == IOCTL_FPL_MONITOR_CLEAR_EVENTS) {
        KIRQL old_irql;
        KeAcquireSpinLock(&g_event_lock, &old_irql);
        RtlZeroMemory(g_events, sizeof(g_events));
        g_event_count = 0;
        KeReleaseSpinLock(&g_event_lock, old_irql);
        return fpl_complete(irp, STATUS_SUCCESS, 0);
    }

    return fpl_complete(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
}

static void fpl_unload(PDRIVER_OBJECT driver)
{
    UNREFERENCED_PARAMETER(driver);

    if (g_image_callback) {
        PsRemoveLoadImageNotifyRoutine(fpl_image_notify);
        g_image_callback = FALSE;
    }

    if (g_thread_callback) {
        PsRemoveCreateThreadNotifyRoutine(fpl_thread_notify);
        g_thread_callback = FALSE;
    }

    if (g_process_callback) {
        PsSetCreateProcessNotifyRoutineEx(fpl_process_notify, TRUE);
        g_process_callback = FALSE;
    }

    if (g_symbolic_link.Buffer) {
        IoDeleteSymbolicLink(&g_symbolic_link);
    }

    if (g_device) {
        IoDeleteDevice(g_device);
        g_device = NULL;
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry_path)
{
    UNREFERENCED_PARAMETER(registry_path);

    KeInitializeSpinLock(&g_event_lock);

    UNICODE_STRING device_name;
    RtlInitUnicodeString(&device_name, FPL_DEVICE_NAME);
    RtlInitUnicodeString(&g_symbolic_link, FPL_SYMBOLIC_NAME);

    UNICODE_STRING sddl;
    RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

    NTSTATUS status = IoCreateDeviceSecure(
        driver,
        0,
        &device_name,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &sddl,
        &GUID_DEVCLASS_FPL_MONITOR,
        &g_device
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IoCreateSymbolicLink(&g_symbolic_link, &device_name);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_device);
        g_device = NULL;
        return status;
    }

    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i) {
        driver->MajorFunction[i] = fpl_create_close;
    }

    driver->MajorFunction[IRP_MJ_CREATE] = fpl_create_close;
    driver->MajorFunction[IRP_MJ_CLOSE] = fpl_create_close;
    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = fpl_device_control;
    driver->DriverUnload = fpl_unload;

    status = PsSetCreateProcessNotifyRoutineEx(fpl_process_notify, FALSE);
    if (!NT_SUCCESS(status)) {
        fpl_unload(driver);
        return status;
    }
    g_process_callback = TRUE;

    status = PsSetCreateThreadNotifyRoutine(fpl_thread_notify);
    if (!NT_SUCCESS(status)) {
        fpl_unload(driver);
        return status;
    }
    g_thread_callback = TRUE;

    status = PsSetLoadImageNotifyRoutine(fpl_image_notify);
    if (!NT_SUCCESS(status)) {
        fpl_unload(driver);
        return status;
    }
    g_image_callback = TRUE;

    return STATUS_SUCCESS;
}
