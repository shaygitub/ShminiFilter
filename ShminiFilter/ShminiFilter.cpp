#include "FilterCallbacks.h"


// Global variables:
UNICODE_STRING SymbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\ShminiFilter");
UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\ShminiFilter");
PDEVICE_OBJECT FilterDeviceObject = NULL;
PFLT_FILTER MinifilterHandle = NULL;
const FLT_OPERATION_REGISTRATION CallbacksArray[] = {
	{
		IRP_MJ_CREATE,
		0,
		PreOperationCallbacks::CreateFilterCallback,
		PostOperationCallbacks::CreateFilterCallback
	},  // Create filtering event

	{
		IRP_MJ_READ,
		FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
		PreOperationCallbacks::GeneralFilterCallback,
		PostOperationCallbacks::ReadFilterCallback
	},  // Create read event to detect readings and data read from file

	{
	    IRP_MJ_DIRECTORY_CONTROL,
	    NULL,
	    PreOperationCallbacks::GeneralFilterCallback,
	    PostOperationCallbacks::DirectoryControlFilterCallback
	},  // Control access to files/directories for file disclosing and similar functions
	
    {
		IRP_MJ_SET_INFORMATION,
		FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
		PreOperationCallbacks::SetInformationFilterCallback,
		PostOperationCallbacks::GeneralFilterCallback
	},  //  Delete restrictions and backup of deleted files

	{
		IRP_MJ_CLEANUP,
		0,
		PreOperationCallbacks::GeneralFilterCallback,
		PostOperationCallbacks::GeneralFilterCallback
	},  // Trace closed handles

	{
	  IRP_MJ_FILE_SYSTEM_CONTROL,
	  0,
	  PreOperationCallbacks::FileSystemControlFilterCallback,
	  PostOperationCallbacks::GeneralFilterCallback,
	},  // Trace FSCTLs, mostly used to trace DeviceIoControl calls

	{
	  IRP_MJ_WRITE,
	  0,
	  PreOperationCallbacks::WriteFilterCallback,
	  PostOperationCallbacks::GeneralFilterCallback,
	},  // Restrict possible write operations and backup last data of file before write

	{ IRP_MJ_OPERATION_END }
};
const FLT_REGISTRATION RegistrationInfo = {
	sizeof(FLT_REGISTRATION),      //  Size
	FLT_REGISTRATION_VERSION,      //  Version
	0,                             //  Flags
	NULL,                          //  Context registration
	CallbacksArray,                   //  Operation callbacks
	GeneralCallbacks::UnloadFilterCallback,  //  FilterUnload
	GeneralCallbacks::InstanceSetupFilterCallback,         //  InstanceSetup
	GeneralCallbacks::InstanceQueryTeardownFilterCallback, //  InstanceQueryTeardown
	NULL,                          //  InstanceTeardownStart
	NULL,                          //  InstanceTeardownComplete
	NULL,                          //  GenerateFileName
	NULL,                          //  GenerateDestinationFileName
	NULL                           //  NormalizeNameComponent
};


NTSTATUS FLTAPI GeneralCallbacks::UnloadFilterCallback(_In_ FLT_FILTER_UNLOAD_FLAGS Flags) {
	if (MinifilterHandle != NULL) {
		FltUnregisterFilter(MinifilterHandle);
		MinifilterHandle = NULL;
	}
	IoDeleteSymbolicLink(&SymbolicLink);
	if (FilterDeviceObject != NULL) {
		IoDeleteDevice(FilterDeviceObject);
		FilterDeviceObject = NULL;
	}
	DatabaseCallbacks::DeleteDatabase();
	DbgPrintEx(0, 0, "Shminifilter general - UnloadFilterCallback() called with %lu\n", Flags);
	return STATUS_SUCCESS;
}


VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
	if (MinifilterHandle != NULL) {
		FltUnregisterFilter(MinifilterHandle);
		MinifilterHandle = NULL;
	}
	IoDeleteSymbolicLink(&SymbolicLink);
	if (FilterDeviceObject != NULL) {
		IoDeleteDevice(FilterDeviceObject);
		FilterDeviceObject = NULL;
	}
	DatabaseCallbacks::DeleteDatabase();
	DbgPrintEx(0, 0, "Shminifilter general - DriverUnload() called\n");
}


NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	NTSTATUS Status = STATUS_SUCCESS;
	const char* HelloMessage =
		"\n----------\n"
		" _____ _               _       _  ______ _ _ _            \n"
		"/  ___| |             (_)     (_) |  ___(_) | |           \n"
		"\\ `--.| |__  _ __ ___  _ _ __  _  | |_   _| | |_ ___ _ __ \n"
		" `--. \\ '_ \\| '_ ` _ \\| | '_ \\| | |  _| | | | __/ _ \\ '__|\n"
		"/\\__/ / | | | | | | | | | | | | | | |   | | | ||  __/ |   \n"
		"\\____/|_| |_|_| |_| |_|_|_| |_|_| \\_|   |_|_|\\__\\___|_|   \n\n"
		"Discord: bldysis#0868  GitHub: shaygitub\n"
		"\n----------\n";
	UNREFERENCED_PARAMETER(RegistryPath);
	DbgPrintEx(0, 0, "%s", HelloMessage);


	// Initiate database and register IOCTL callbacks:
	if (!DatabaseCallbacks::InitiateDatabase()) {
		DbgPrintEx(0, 0, "Shminifilter - InitiateDatabase() failed\n");
		return Status;
	}
	Status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN, FALSE, &FilterDeviceObject);
	if (!NT_SUCCESS(Status)) {
		DbgPrintEx(0, 0, "Shminifilter - IoCreateDevice() failed with status 0x%x\n", Status);
		return Status;
	}
	Status = IoCreateSymbolicLink(&SymbolicLink, &DeviceName);
	if (!NT_SUCCESS(Status)) {
		DbgPrintEx(0, 0, "Shminifilter - IoCreateSymbolicLink() failed with status 0x%x\n", Status);
		IoDeleteDevice(FilterDeviceObject);
		return Status;
	}
	DriverObject->MajorFunction[IRP_MJ_CREATE] = IoctlCallbacks::CreateCloseCallback;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = IoctlCallbacks::CreateCloseCallback;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoctlCallbacks::DeviceControlCallback;
	DriverObject->DriverUnload = DriverUnload;


	// Register the filter driver:
	Status = FltRegisterFilter(DriverObject, &RegistrationInfo, &MinifilterHandle);
	if (!NT_SUCCESS(Status)) {
		DbgPrintEx(0, 0, "Shminifilter - FltRegisterFilter() failed with status 0x%x\n", Status);
		IoDeleteSymbolicLink(&SymbolicLink);
		IoDeleteDevice(FilterDeviceObject);
		return Status;
	}


	// Start filtering:
	Status = FltStartFiltering(MinifilterHandle);
	if (!NT_SUCCESS(Status)) {
		DbgPrintEx(0, 0, "Shminifilter - FltStartFiltering() failed with status 0x%x\n", Status);
		FltUnregisterFilter(MinifilterHandle);
		IoDeleteSymbolicLink(&SymbolicLink);
		IoDeleteDevice(FilterDeviceObject);
		return Status;
	}
	DbgPrintEx(0, 0, "Shminifilter - registered and started filtering\n");
	return Status;
}