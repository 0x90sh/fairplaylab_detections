#include <ntddk.h>
#include <ntstrsafe.h>
#include <wdmsec.h>
#include <initguid.h>

#include "../protocol.h"

#pragma warning(disable: 4152)

#define FPL_DEVICE_NAME L"\\Device\\FplCommSurface"
#define FPL_SYMBOLIC_NAME L"\\DosDevices\\FplCommSurface"

DEFINE_GUID(GUID_DEVCLASS_FPL_COMM_SURFACE, 0x9bb2ab45, 0x9799, 0x430e, 0x8e, 0x2d, 0xc7, 0x84, 0xc3, 0x08, 0xde, 0x44);

static PDEVICE_OBJECT g_device;
static PDRIVER_OBJECT g_driver;
static UNICODE_STRING g_symbolic_link;
static KSPIN_LOCK g_audit_lock;
static ULONG g_audit_count;
static FPL_COMM_AUDIT_EVENT g_audit[FPL_COMM_AUDIT_CAPACITY];

static void fpl_audit(ULONG ioctl_code, ULONG input_size, ULONG output_size)
{
    KIRQL old_irql;
    KeAcquireSpinLock(&g_audit_lock, &old_irql);

    const ULONG index = g_audit_count % FPL_COMM_AUDIT_CAPACITY;
    g_audit[index].ClientPid = HandleToULong(PsGetCurrentProcessId());
    g_audit[index].IoControlCode = ioctl_code;
    g_audit[index].InputSize = input_size;
    g_audit[index].OutputSize = output_size;
    ++g_audit_count;

    KeReleaseSpinLock(&g_audit_lock, old_irql);
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

static BOOLEAN fpl_pointer_inside_driver(PVOID pointer)
{
    if (!g_driver || !g_driver->DriverStart || g_driver->DriverSize == 0) {
        return FALSE;
    }

    const ULONG_PTR start = (ULONG_PTR)g_driver->DriverStart;
    const ULONG_PTR end = start + g_driver->DriverSize;
    const ULONG_PTR value = (ULONG_PTR)pointer;
    return value >= start && value < end;
}

static void fpl_validate_self(FPL_COMM_SELF_CHECK* check)
{
    RtlZeroMemory(check, sizeof(*check));

    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i) {
        PVOID target = g_driver->MajorFunction[i];
        if (!target) {
            continue;
        }

        ++check->MajorFunctionCount;

        if (!fpl_pointer_inside_driver(target)) {
            ++check->OutsideImageCount;
        }
    }
}

static NTSTATUS fpl_device_control(PDEVICE_OBJECT device, PIRP irp)
{
    UNREFERENCED_PARAMETER(device);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    const ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    const ULONG input_size = stack->Parameters.DeviceIoControl.InputBufferLength;
    const ULONG output_size = stack->Parameters.DeviceIoControl.OutputBufferLength;
    void* buffer = irp->AssociatedIrp.SystemBuffer;

    fpl_audit(code, input_size, output_size);

    if (code == IOCTL_FPL_COMM_PING) {
        if (input_size < sizeof(FPL_COMM_PING) || output_size < sizeof(FPL_COMM_PING) || !buffer) {
            return fpl_complete(irp, STATUS_BUFFER_TOO_SMALL, 0);
        }

        FPL_COMM_PING* ping = (FPL_COMM_PING*)buffer;
        ping->ClientPid = HandleToULong(PsGetCurrentProcessId());
        ping->Nonce ^= 0xf1a9b00d;
        RtlStringCbCopyW((NTSTRSAFE_PWSTR)ping->Text, sizeof(ping->Text), L"fairplaylab ack");
        return fpl_complete(irp, STATUS_SUCCESS, sizeof(*ping));
    }

    if (code == IOCTL_FPL_COMM_GET_AUDIT) {
        if (output_size < sizeof(FPL_COMM_AUDIT_BATCH) || !buffer) {
            return fpl_complete(irp, STATUS_BUFFER_TOO_SMALL, 0);
        }

        FPL_COMM_AUDIT_BATCH* batch = (FPL_COMM_AUDIT_BATCH*)buffer;
        RtlZeroMemory(batch, sizeof(*batch));

        KIRQL old_irql;
        KeAcquireSpinLock(&g_audit_lock, &old_irql);

        const ULONG available = g_audit_count < FPL_COMM_AUDIT_CAPACITY ? g_audit_count : FPL_COMM_AUDIT_CAPACITY;
        batch->Count = available;

        for (ULONG i = 0; i < available; ++i) {
            batch->Events[i] = g_audit[i];
        }

        KeReleaseSpinLock(&g_audit_lock, old_irql);
        return fpl_complete(irp, STATUS_SUCCESS, sizeof(*batch));
    }

    if (code == IOCTL_FPL_COMM_VALIDATE_SELF) {
        if (output_size < sizeof(FPL_COMM_SELF_CHECK) || !buffer) {
            return fpl_complete(irp, STATUS_BUFFER_TOO_SMALL, 0);
        }

        fpl_validate_self((FPL_COMM_SELF_CHECK*)buffer);
        return fpl_complete(irp, STATUS_SUCCESS, sizeof(FPL_COMM_SELF_CHECK));
    }

    return fpl_complete(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
}

static void fpl_unload(PDRIVER_OBJECT driver)
{
    UNREFERENCED_PARAMETER(driver);

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

    g_driver = driver;
    KeInitializeSpinLock(&g_audit_lock);

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
        &GUID_DEVCLASS_FPL_COMM_SURFACE,
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

    return STATUS_SUCCESS;
}
