#include <ntddk.h>
#include <wdmsec.h>
#include <aux_klib.h>
#include <initguid.h>

#include "../protocol.h"

#define FPL_DEVICE_NAME L"\\Device\\FplDriverInventory"
#define FPL_SYMBOLIC_NAME L"\\DosDevices\\FplDriverInventory"
#define FPL_POOL_TAG 'IvPF'

DEFINE_GUID(GUID_DEVCLASS_FPL_DRIVER_INVENTORY, 0x70631efd, 0x9547, 0x475d, 0x9f, 0x4d, 0x50, 0x45, 0x9f, 0x1d, 0x33, 0x10);

static PDEVICE_OBJECT g_device;
static UNICODE_STRING g_symbolic_link;

static void fpl_copy_ansi_path(WCHAR* target, ULONG target_chars, const UCHAR* source)
{
    if (!target || target_chars == 0) {
        return;
    }

    target[0] = L'\0';

    if (!source) {
        return;
    }

    ULONG i = 0;
    for (; i + 1 < target_chars && source[i] != '\0'; ++i) {
        target[i] = (WCHAR)source[i];
    }

    target[i] = L'\0';
}

static NTSTATUS fpl_query_modules(FPL_INVENTORY_BATCH* batch)
{
    RtlZeroMemory(batch, sizeof(*batch));

    ULONG bytes = 0;
    NTSTATUS status = AuxKlibQueryModuleInformation(&bytes, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
    if (!NT_SUCCESS(status) || bytes == 0) {
        return status;
    }

    AUX_MODULE_EXTENDED_INFO* modules = (AUX_MODULE_EXTENDED_INFO*)ExAllocatePool2(POOL_FLAG_NON_PAGED, bytes, FPL_POOL_TAG);
    if (!modules) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = AuxKlibQueryModuleInformation(&bytes, sizeof(AUX_MODULE_EXTENDED_INFO), modules);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(modules, FPL_POOL_TAG);
        return status;
    }

    const ULONG module_count = bytes / sizeof(AUX_MODULE_EXTENDED_INFO);
    const ULONG copy_count = module_count < FPL_INVENTORY_MODULE_CAPACITY ? module_count : FPL_INVENTORY_MODULE_CAPACITY;
    batch->Count = copy_count;
    batch->Truncated = module_count > FPL_INVENTORY_MODULE_CAPACITY ? 1 : 0;

    for (ULONG i = 0; i < copy_count; ++i) {
        batch->Modules[i].ImageBase = (ULONGLONG)(ULONG_PTR)modules[i].BasicInfo.ImageBase;
        batch->Modules[i].ImageSize = modules[i].ImageSize;
        batch->Modules[i].Flags = 0;
        fpl_copy_ansi_path(batch->Modules[i].Path, FPL_INVENTORY_PATH_CHARS, modules[i].FullPathName);
    }

    ExFreePoolWithTag(modules, FPL_POOL_TAG);
    return STATUS_SUCCESS;
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

    if (code == IOCTL_FPL_INVENTORY_QUERY) {
        if (output_size < sizeof(FPL_INVENTORY_BATCH) || !buffer) {
            return fpl_complete(irp, STATUS_BUFFER_TOO_SMALL, 0);
        }

        NTSTATUS status = fpl_query_modules((FPL_INVENTORY_BATCH*)buffer);
        return fpl_complete(irp, status, NT_SUCCESS(status) ? sizeof(FPL_INVENTORY_BATCH) : 0);
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

    NTSTATUS status = AuxKlibInitialize();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    UNICODE_STRING device_name;
    RtlInitUnicodeString(&device_name, FPL_DEVICE_NAME);
    RtlInitUnicodeString(&g_symbolic_link, FPL_SYMBOLIC_NAME);

    UNICODE_STRING sddl;
    RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

    status = IoCreateDeviceSecure(
        driver,
        0,
        &device_name,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &sddl,
        &GUID_DEVCLASS_FPL_DRIVER_INVENTORY,
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
