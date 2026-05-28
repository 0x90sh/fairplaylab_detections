#include <ntddk.h>
#include <wdmsec.h>
#include <initguid.h>

#include "../protocol.h"

#define FPL_DEVICE_NAME L"\\Device\\FplHandleGuard"
#define FPL_SYMBOLIC_NAME L"\\DosDevices\\FplHandleGuard"
#define FPL_ALTITUDE L"370030"

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD 0x0002
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION 0x0008
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ 0x0010
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE 0x0020
#endif
#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE 0x0040
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME 0x0800
#endif

#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE 0x0001
#endif
#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME 0x0002
#endif
#ifndef THREAD_SET_CONTEXT
#define THREAD_SET_CONTEXT 0x0010
#endif

DEFINE_GUID(GUID_DEVCLASS_FPL_HANDLE_GUARD, 0x7ef34680, 0x1ad2, 0x41f2, 0xa8, 0x6b, 0x19, 0x3d, 0x7e, 0xb2, 0x70, 0x11);

static PDEVICE_OBJECT g_device;
static UNICODE_STRING g_symbolic_link;
static PVOID g_callback_registration;
static KSPIN_LOCK g_event_lock;
static ULONG g_target_pid;
static ULONG g_event_count;
static FPL_HANDLE_EVENT g_events[FPL_HANDLE_EVENT_CAPACITY];

static void fpl_log_event(ULONG requestor_pid, ULONG target_pid, ULONG kind, ACCESS_MASK original, ACCESS_MASK stripped)
{
    KIRQL old_irql;
    KeAcquireSpinLock(&g_event_lock, &old_irql);

    const ULONG index = g_event_count % FPL_HANDLE_EVENT_CAPACITY;
    g_events[index].RequestorPid = requestor_pid;
    g_events[index].TargetPid = target_pid;
    g_events[index].ObjectKind = kind;
    g_events[index].OriginalAccess = original;
    g_events[index].StrippedAccess = stripped;
    ++g_event_count;

    KeReleaseSpinLock(&g_event_lock, old_irql);
}

static ACCESS_MASK* fpl_desired_access(POB_PRE_OPERATION_INFORMATION info)
{
    if (info->Operation == OB_OPERATION_HANDLE_CREATE) {
        return &info->Parameters->CreateHandleInformation.DesiredAccess;
    }

    if (info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        return &info->Parameters->DuplicateHandleInformation.DesiredAccess;
    }

    return NULL;
}

static OB_PREOP_CALLBACK_STATUS fpl_pre_operation(PVOID registration_context, POB_PRE_OPERATION_INFORMATION info)
{
    UNREFERENCED_PARAMETER(registration_context);

    if (info->KernelHandle || g_target_pid == 0) {
        return OB_PREOP_SUCCESS;
    }

    ACCESS_MASK* desired_access = fpl_desired_access(info);
    if (!desired_access) {
        return OB_PREOP_SUCCESS;
    }

    ULONG object_kind = 0;
    ULONG target_pid = 0;
    ACCESS_MASK deny_mask = 0;

    if (info->ObjectType == *PsProcessType) {
        target_pid = HandleToULong(PsGetProcessId((PEPROCESS)info->Object));
        object_kind = 1;
        deny_mask = PROCESS_VM_READ |
                    PROCESS_VM_WRITE |
                    PROCESS_VM_OPERATION |
                    PROCESS_CREATE_THREAD |
                    PROCESS_DUP_HANDLE |
                    PROCESS_TERMINATE |
                    PROCESS_SUSPEND_RESUME;
    } else if (info->ObjectType == *PsThreadType) {
        target_pid = HandleToULong(PsGetThreadProcessId((PETHREAD)info->Object));
        object_kind = 2;
        deny_mask = THREAD_SET_CONTEXT |
                    THREAD_SUSPEND_RESUME |
                    THREAD_TERMINATE;
    } else {
        return OB_PREOP_SUCCESS;
    }

    if (target_pid != g_target_pid) {
        return OB_PREOP_SUCCESS;
    }

    if (HandleToULong(PsGetCurrentProcessId()) == g_target_pid) {
        return OB_PREOP_SUCCESS;
    }

    const ACCESS_MASK original = *desired_access;
    *desired_access &= ~deny_mask;

    const ACCESS_MASK stripped = original & ~(*desired_access);
    if (stripped != 0) {
        fpl_log_event(HandleToULong(PsGetCurrentProcessId()), target_pid, object_kind, original, stripped);
    }

    return OB_PREOP_SUCCESS;
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
    const ULONG input_size = stack->Parameters.DeviceIoControl.InputBufferLength;
    const ULONG output_size = stack->Parameters.DeviceIoControl.OutputBufferLength;

    if (code == IOCTL_FPL_HANDLE_SET_TARGET) {
        if (input_size < sizeof(FPL_HANDLE_TARGET_REQUEST) || !buffer) {
            return fpl_complete(irp, STATUS_BUFFER_TOO_SMALL, 0);
        }

        const FPL_HANDLE_TARGET_REQUEST* request = (const FPL_HANDLE_TARGET_REQUEST*)buffer;
        g_target_pid = request->ProcessId;
        return fpl_complete(irp, STATUS_SUCCESS, 0);
    }

    if (code == IOCTL_FPL_HANDLE_GET_EVENTS) {
        if (output_size < sizeof(FPL_HANDLE_EVENT_BATCH) || !buffer) {
            return fpl_complete(irp, STATUS_BUFFER_TOO_SMALL, 0);
        }

        FPL_HANDLE_EVENT_BATCH* batch = (FPL_HANDLE_EVENT_BATCH*)buffer;
        RtlZeroMemory(batch, sizeof(*batch));
        batch->TargetPid = g_target_pid;

        KIRQL old_irql;
        KeAcquireSpinLock(&g_event_lock, &old_irql);

        const ULONG available = g_event_count < FPL_HANDLE_EVENT_CAPACITY ? g_event_count : FPL_HANDLE_EVENT_CAPACITY;
        batch->Count = available;

        for (ULONG i = 0; i < available; ++i) {
            batch->Events[i] = g_events[i];
        }

        KeReleaseSpinLock(&g_event_lock, old_irql);

        return fpl_complete(irp, STATUS_SUCCESS, sizeof(*batch));
    }

    return fpl_complete(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
}

static NTSTATUS fpl_register_callbacks(void)
{
    OB_OPERATION_REGISTRATION operations[2];
    RtlZeroMemory(operations, sizeof(operations));

    operations[0].ObjectType = PsProcessType;
    operations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[0].PreOperation = fpl_pre_operation;

    operations[1].ObjectType = PsThreadType;
    operations[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[1].PreOperation = fpl_pre_operation;

    UNICODE_STRING altitude;
    RtlInitUnicodeString(&altitude, FPL_ALTITUDE);

    OB_CALLBACK_REGISTRATION registration;
    RtlZeroMemory(&registration, sizeof(registration));
    registration.Version = OB_FLT_REGISTRATION_VERSION;
    registration.OperationRegistrationCount = RTL_NUMBER_OF(operations);
    registration.Altitude = altitude;
    registration.OperationRegistration = operations;

    return ObRegisterCallbacks(&registration, &g_callback_registration);
}

static void fpl_unload(PDRIVER_OBJECT driver)
{
    UNREFERENCED_PARAMETER(driver);

    if (g_callback_registration) {
        ObUnRegisterCallbacks(g_callback_registration);
        g_callback_registration = NULL;
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
        &GUID_DEVCLASS_FPL_HANDLE_GUARD,
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

    status = fpl_register_callbacks();
    if (!NT_SUCCESS(status)) {
        fpl_unload(driver);
        return status;
    }

    return STATUS_SUCCESS;
}
