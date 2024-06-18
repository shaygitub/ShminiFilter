#pragma once
#include <fltkernel.h>
#include <ntddk.h>
#include <wdm.h>
#include "definitions.h"
#define TRUE 1
#define FALSE 0
typedef int BOOL;


namespace PreOperationCallbacks {
    FLT_PREOP_CALLBACK_STATUS FLTAPI CreateFilterCallback(_Inout_ PFLT_CALLBACK_DATA Data,
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);
    FLT_PREOP_CALLBACK_STATUS SetInformationFilterCallback(_Inout_ PFLT_CALLBACK_DATA Data,
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);
    FLT_PREOP_CALLBACK_STATUS FileSystemControlFilterCallback(_Inout_ PFLT_CALLBACK_DATA Data,
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);
    FLT_PREOP_CALLBACK_STATUS WriteFilterCallback(_Inout_ PFLT_CALLBACK_DATA Data,
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);
    FLT_PREOP_CALLBACK_STATUS GeneralFilterCallback(_Inout_ PFLT_CALLBACK_DATA Data,
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);
}


namespace PostOperationCallbacks {
    FLT_POSTOP_CALLBACK_STATUS CreateFilterCallback(_Inout_ PFLT_CALLBACK_DATA Data,
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _In_ PVOID CompletionContext,
        _In_ FLT_POST_OPERATION_FLAGS Flags);
    FLT_POSTOP_CALLBACK_STATUS ReadFilterCallback(_Inout_ PFLT_CALLBACK_DATA Data,
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _In_opt_ PVOID CompletionContext,
        _In_ FLT_POST_OPERATION_FLAGS Flags);
    FLT_POSTOP_CALLBACK_STATUS DirectoryControlFilterCallback(_Inout_ PFLT_CALLBACK_DATA Data,
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _In_opt_ PVOID CompletionContext,
        _In_ FLT_POST_OPERATION_FLAGS Flags);
    FLT_POSTOP_CALLBACK_STATUS GeneralFilterCallback(_Inout_ PFLT_CALLBACK_DATA Data,
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _In_opt_ PVOID CompletionContext,
        _In_ FLT_POST_OPERATION_FLAGS Flags);
}


namespace GeneralCallbacks {
    NTSTATUS FLTAPI UnloadFilterCallback(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
    NTSTATUS FLTAPI InstanceSetupFilterCallback(_In_ PCFLT_RELATED_OBJECTS  FltObjects,
        _In_ FLT_INSTANCE_SETUP_FLAGS  Flags,
        _In_ DEVICE_TYPE  VolumeDeviceType,
        _In_ FLT_FILESYSTEM_TYPE  VolumeFilesystemType);
    NTSTATUS FLTAPI InstanceQueryTeardownFilterCallback(_In_ PCFLT_RELATED_OBJECTS FltObjects,
        _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);
}


namespace IoctlCallbacks {
    NTSTATUS CreateCloseCallback(PDEVICE_OBJECT DeviceObject, PIRP Irp);
    NTSTATUS DeviceControlCallback(PDEVICE_OBJECT DeviceObject, PIRP Irp);
}


namespace DatabaseCallbacks {
    BOOL InitiateDatabase();
    BOOL IncrementDetected();
    BOOL IncrementByInformation(PFLT_CALLBACK_DATA Data,
        PFLT_FILE_NAME_INFORMATION NameInfo, STARTINFO_OPERATION InitialCall);
    PVOID CreateDatabaseEntry(PFLT_CALLBACK_DATA Data, PFLT_FILE_NAME_INFORMATION NameInfo,
        LPSTR SpecialString, LPSTR OperationDescriptor);
    BOOL AddEntryToDatabase(PVOID Entry, ULONG EntrySize);
    void GetDatabase(PVOID* DatabasePool, ULONG64* DatabaseSize);
    void DeleteDatabase();
    void LockExtracting();
    void UnlockExtracting();
}