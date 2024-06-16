#include "FilterCallbacks.h"
#include "helpers.h"
#pragma warning(disable : 6305)


NTSTATUS IoctlCallbacks::CreateCloseCallback(PDEVICE_OBJECT DeviceObject,
    PIRP Irp){
    UNREFERENCED_PARAMETER(DeviceObject);
    PAGED_CODE();
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}


NTSTATUS IoctlCallbacks::DeviceControlCallback(PDEVICE_OBJECT DeviceObject,
    PIRP Irp) {
    /*
    Assumes input/output buffers are the same
    input: PID value of calling process to inject info into (8 bytes) + dummy address (8 bytes)
    output: database UM buffer (8 bytes) + database size (8 bytes)
    */
    PIO_STACK_LOCATION ParamStackLocation = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG InputBufferSize = 0;
    ULONG OutputBufferSize = 0;
    PUCHAR InputBuffer = NULL;
    PUCHAR OutputBuffer = NULL;
    PVOID Database = NULL;
    ULONG64 DatabaseSize = 0;
    ULONG64 CallerPID = 0;
    PEPROCESS CallerProcess = NULL;
    KAPC_STATE CallerContext = { 0 };
    PVOID AllocatedUserBuffer = NULL;
    UNREFERENCED_PARAMETER(DeviceObject);
    PAGED_CODE();
    ParamStackLocation = IoGetCurrentIrpStackLocation(Irp);
    InputBufferSize = ParamStackLocation->Parameters.DeviceIoControl.InputBufferLength;
    OutputBufferSize = ParamStackLocation->Parameters.DeviceIoControl.OutputBufferLength;


    // Determine which I/O control code was specified:
    switch (ParamStackLocation->Parameters.DeviceIoControl.IoControlCode) {
    case INFOPASS_IOCTL:

        // Verify correct parameters:
        InputBufferSize = ParamStackLocation->Parameters.DeviceIoControl.InputBufferLength;
        OutputBufferSize = ParamStackLocation->Parameters.DeviceIoControl.OutputBufferLength;
        InputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
        OutputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
        if (InputBufferSize != 16 || OutputBufferSize != 16 || InputBuffer == NULL) {
            Status = STATUS_INVALID_PARAMETER;
            break;
        }
        RtlCopyMemory(&CallerPID, InputBuffer, sizeof(ULONG64));
        RtlCopyMemory(&AllocatedUserBuffer, &InputBuffer[sizeof(ULONG64)], sizeof(PVOID));
        if (CallerPID == 0 || CallerPID >= 0xFFFF || AllocatedUserBuffer == NULL) {
            Status = STATUS_INVALID_PARAMETER;
            break;
        }
        DatabaseCallbacks::GetDatabase(&Database, &DatabaseSize);


        // Get EPROCESS of calling process and attach to it for allocating memory and sending database:
        if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)CallerPID, &CallerProcess))) {
            Status = STATUS_INVALID_PARAMETER;
            break;
        }
        DbgPrintEx(0, 0, "Shminifilter IOCTL - Called by process %llu, dummy address to allocate: %p\n",
            CallerPID, AllocatedUserBuffer);
        KeStackAttachProcess(CallerProcess, &CallerContext);
        AllocatedUserBuffer = HelperFunctions::AllocateMemory(AllocatedUserBuffer,
            DatabaseSize, &CallerContext, 0);
        if (AllocatedUserBuffer == NULL) {
            Status = STATUS_MEMORY_NOT_ALLOCATED;
            DbgPrintEx(0, 0, "Shminifilter IOCTL - Failed to allocate memory for database update\n");
            break;
        }
        RtlCopyMemory(OutputBuffer, &AllocatedUserBuffer, sizeof(PVOID));
        RtlCopyMemory(&OutputBuffer[sizeof(PVOID)], &DatabaseSize, sizeof(ULONG64));


        // Lock adding operations and copy buffer into UM:
        DatabaseCallbacks::LockExtracting();
        Status = HelperFunctions::KernelToUser(CallerProcess, Database, AllocatedUserBuffer,
            DatabaseSize, FALSE);
        if (!NT_SUCCESS(Status)) {
            DatabaseCallbacks::UnlockExtracting();
            DbgPrintEx(0, 0, "Shminifilter IOCTL - Failed to pass database from KM to UM\n");
            break;
        }

        // Destroy current database and unlock extracting:
        DatabaseCallbacks::DeleteDatabase();
        DatabaseCallbacks::InitiateDatabase();  // Re-initialize the database with the initial entry
        DatabaseCallbacks::UnlockExtracting();
        Irp->IoStatus.Information = 16;
        DbgPrintEx(0, 0, "Shminifilter IOCTL - Passed the database and re-initiated basic information\n");
        break;

    default:
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}