#include "FilterCallbacks.h"
#include "helpers.h"
#pragma warning (disable : 4996)


FLT_PREOP_CALLBACK_STATUS FLTAPI PreOperationCallbacks::CreateFilterCallback(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
    PFLT_PARAMETERS FilterParameters = NULL;
    PVOID DatabaseEntry = NULL;
    UNICODE_STRING TriggerAccessDeniedParentDir = RTL_CONSTANT_STRING(L"\\VeryImportantStuffDeleteProtection\\");
    UNICODE_STRING BackupDirectory = RTL_CONSTANT_STRING(L"\\DeleteBackupShminiFilter\\C");
    WCHAR BackupFilePath[1024] = { 0 };
    WCHAR FullDeletedPath[1024] = { 0 };
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING FileExtension = { 0 };
    UNICODE_STRING FileName = { 0 };
    FLT_PREOP_CALLBACK_STATUS FilterStatus = FLT_PREOP_SYNCHRONIZE;
    HANDLE DeletedFile = NULL;
    HANDLE BackupFile = NULL;
    OBJECT_ATTRIBUTES DeletedAttrs = { 0 };
    OBJECT_ATTRIBUTES BackupAttrs = { 0 };
    IO_STATUS_BLOCK StatusBlock = { 0 };
    UNICODE_STRING DeletedUnicode = { 0 };
    UNICODE_STRING BackupUnicode = { 0 };
    FILE_STANDARD_INFORMATION DeletedInformation = { 0 };
    ULONG64 DeletedFileSize = 0;
    PVOID DeletedFileData = NULL;
    BOOLEAN IsDirectoryDelete = FALSE;


    // Get the file information:
    if (!NT_SUCCESS(FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED
        | FLT_FILE_NAME_QUERY_DEFAULT,
        &NameInfo))) {
        goto FinishLabel;
    }


    // Parse the file name from information:
    if (!NT_SUCCESS(FltParseFileNameInformation(NameInfo))) {
        goto FinishLabel;
    }


    // Increment counters for generic create-pre request:
    if (!DatabaseCallbacks::IncrementByInformation(Data, NameInfo, CreatePreCount)) {
        DbgPrintEx(0, 0, "Shminifilter preoperation - create-pre operation incrementing failed\n");
    }


    // Prevent deletion of protected files and backup deleted files:
    if (FilterParameters != NULL && FilterParameters->Create.Options & FILE_DELETE_ON_CLOSE) {
        Status = FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &IsDirectoryDelete);
        if (NT_SUCCESS(Status)) {
            if (IsDirectoryDelete) {
                goto FinishLabel;  // Ignore directory deletion
            }
        }
        if (HelperFunctions::IsInParentDirectory(&NameInfo->ParentDir, &TriggerAccessDeniedParentDir)) {
            DatabaseCallbacks::IncrementDetected();
            DbgPrintEx(0, 0, "-- Delete with create is on a file inside a disclosed directory (parent directory = %wZ, disclosed directory = %wZ), blocking access ...\n",
                &NameInfo->ParentDir, &TriggerAccessDeniedParentDir);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            DatabaseEntry = DatabaseCallbacks::CreateDatabaseEntry(Data, NameInfo, "Deleted file is protected, preventing deletion ..",
                "CREATE PREOPERATION");
            FilterStatus = FLT_PREOP_COMPLETE;
        }
        else {

            // Create paths for the deleted file and the backup file:
            wcscat_s(BackupFilePath, BackupDirectory.Buffer);
            wcscat_s(BackupFilePath, NameInfo->ParentDir.Buffer);
            wcscat_s(BackupFilePath, NameInfo->Name.Buffer);
            wcscat_s(FullDeletedPath, NameInfo->ParentDir.Buffer);
            wcscat_s(FullDeletedPath, NameInfo->Name.Buffer);
            RtlInitUnicodeString(&DeletedUnicode, FullDeletedPath);
            InitializeObjectAttributes(&DeletedAttrs, &DeletedUnicode, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                NULL, NULL);
            RtlInitUnicodeString(&BackupUnicode, BackupFilePath);
            InitializeObjectAttributes(&BackupAttrs, &BackupUnicode, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                NULL, NULL);


            // Read deleted file data to copy it into backup file:
            Status = ZwCreateFile(&DeletedFile, SYNCHRONIZE | GENERIC_READ, &DeletedAttrs, &StatusBlock,
                NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
                FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
            if (!NT_SUCCESS(Status) || DeletedFile == NULL) {
                DbgPrintEx(0, 0, "Shminifilter preoperation - create-pre operation backup of deleted failed (del_create)\n");
                goto FinishLabel;
            }
            Status = NtQueryInformationFile(DeletedFile, &StatusBlock,
                &DeletedInformation, sizeof(DeletedInformation), FileStandardInformation);
            if (!NT_SUCCESS(Status) || DeletedFile == NULL) {
                DbgPrintEx(0, 0, "Shminifilter preoperation - create-pre operation backup of deleted failed (del_size)\n");
                ZwClose(DeletedFile);
                goto FinishLabel;
            }
            DeletedFileSize = DeletedInformation.EndOfFile.QuadPart;
            DeletedFileData = ExAllocatePoolWithTag(NonPagedPool, DeletedFileSize, 'DfBd');
            if (DeletedFileData == NULL) {
                DbgPrintEx(0, 0, "Shminifilter preoperation - create-pre operation backup of deleted failed (del_alloc)\n");
                ZwClose(DeletedFile);
                goto FinishLabel;
            }
            Status = ZwReadFile(DeletedFile, NULL, NULL, NULL, &StatusBlock, DeletedFileData, (ULONG)DeletedFileSize,
                NULL, NULL);
            if (!NT_SUCCESS(Status)) {
                DbgPrintEx(0, 0, "Shminifilter preoperation - create-pre operation backup of deleted failed (del_read)\n");
                ExFreePool(DeletedFileData);
                ZwClose(DeletedFile);
                goto FinishLabel;
            }
            ZwClose(DeletedFile);


            // Write deleted file data into backup file (make sure to overwrite existing backup):
            Status = ZwCreateFile(&BackupFile, SYNCHRONIZE | GENERIC_READ, &BackupAttrs, &StatusBlock,
                NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SUPERSEDE,
                FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
            if (!NT_SUCCESS(Status) || BackupFile == NULL) {
                DbgPrintEx(0, 0, "Shminifilter preoperation - create-pre operation backup of deleted failed (bck_create)\n");
                ExFreePool(DeletedFileData);
                goto FinishLabel;
            }
            Status = ZwWriteFile(BackupFile, NULL, NULL, NULL, &StatusBlock, DeletedFileData, (ULONG)DeletedFileSize,
                NULL, NULL);
            if (!NT_SUCCESS(Status)) {
                DbgPrintEx(0, 0, "Shminifilter preoperation - create-pre operation backup of deleted failed (bck_create)\n");
            }
            ExFreePool(DeletedFileData);
            ZwClose(BackupFile);
        }
    }


    // Add entry to database:
    if (DatabaseEntry != NULL) {
        if (!DatabaseCallbacks::AddEntryToDatabase(DatabaseEntry, ((PDETECTED_ENTRY)DatabaseEntry)->EntrySize)) {
            DatabaseCallbacks::DeleteDatabase();
        }
    }


    FinishLabel:
    return FilterStatus;
}


FLT_PREOP_CALLBACK_STATUS PreOperationCallbacks::ReadFilterCallback(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext) {
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);


    //  Skip IRP_PAGING_IO, IRP_SYNCHRONOUS_PAGING_IO and TopLevelIrp:
    if ((Data->Iopb->IrpFlags & IRP_PAGING_IO) ||
        (Data->Iopb->IrpFlags & IRP_SYNCHRONOUS_PAGING_IO) ||
        IoGetTopLevelIrp()) {
        DbgPrintEx(0, 0, "Shminifilter preoperation - read operation stopped, edge case occured (%lu)\n",
            Data->Iopb->IrpFlags);
        return FLT_PREOP_SYNCHRONIZE;
    }


    // Get the file information:
    Status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED
        | FLT_FILE_NAME_QUERY_DEFAULT,
        &NameInfo);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_FLT_INVALID_NAME_REQUEST) {
            DbgPrintEx(0, 0, "Shminifilter preoperation - read operation stopped, FltGetFileNameInformation() returned 0x%x\n",
                Status);
        }
        return FLT_PREOP_SYNCHRONIZE;
    }


    // Parse the file name from information:
    Status = FltParseFileNameInformation(NameInfo);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_FLT_INVALID_NAME_REQUEST) {
            DbgPrintEx(0, 0, "Shminifilter preoperation - read operation stopped, FltParseFileNameInformation() returned 0x%x (Name = %wZ)\n",
                Status, &NameInfo->Name);
        }
        return FLT_PREOP_SYNCHRONIZE;
    }


    // Increment counters for generic read-pre request:
    if (!DatabaseCallbacks::IncrementByInformation(Data, NameInfo, ReadPreCount)) {
        DbgPrintEx(0, 0, "Shminifilter preoperation - read-pre operation incrementing failed\n");
    }
    return FLT_PREOP_SYNCHRONIZE;
}


FLT_PREOP_CALLBACK_STATUS PreOperationCallbacks::DirectoryControlFilterCallback(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext) {
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);


    // Get the file information:
    Status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED
        | FLT_FILE_NAME_QUERY_DEFAULT,
        &NameInfo);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_FLT_INVALID_NAME_REQUEST) {
            DbgPrintEx(0, 0, "Shminifilter preoperation - directory control operation stopped, FltGetFileNameInformation() returned 0x%x\n",
                Status);
        }
        return FLT_PREOP_SYNCHRONIZE;
    }


    // Parse the file name from information:
    Status = FltParseFileNameInformation(NameInfo);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_FLT_INVALID_NAME_REQUEST) {
            DbgPrintEx(0, 0, "Shminifilter preoperation - directory control operation stopped, FltParseFileNameInformation() returned 0x%x (Name = %wZ)\n",
                Status, &NameInfo->Name);
        }
        return FLT_PREOP_SYNCHRONIZE;
    }


    // Increment counters for generic dircontrol-pre request:
    if (!DatabaseCallbacks::IncrementByInformation(Data, NameInfo, DirControlPreCount)) {
        DbgPrintEx(0, 0, "Shminifilter preoperation - dircontrol-pre operation incrementing failed\n");
    }
    return FLT_PREOP_SYNCHRONIZE;
}


FLT_PREOP_CALLBACK_STATUS FLTAPI PreOperationCallbacks::SetInformationFilterCallback(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
    PVOID DatabaseEntry = NULL;
    UNICODE_STRING TriggerAccessDeniedParentDir = RTL_CONSTANT_STRING(L"\\VeryImportantStuffDeleteProtection\\");
    UNICODE_STRING BackupDirectory = RTL_CONSTANT_STRING(L"\\DeleteBackupShminiFilter\\C");
    WCHAR BackupFilePath[1024] = { 0 };
    WCHAR FullDeletedPath[1024] = { 0 };
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING FileExtension = { 0 };
    UNICODE_STRING FileName = { 0 };
    FLT_PREOP_CALLBACK_STATUS FilterStatus = FLT_PREOP_SYNCHRONIZE;
    HANDLE DeletedFile = NULL;
    HANDLE BackupFile = NULL;
    OBJECT_ATTRIBUTES DeletedAttrs = { 0 };
    OBJECT_ATTRIBUTES BackupAttrs = { 0 };
    IO_STATUS_BLOCK StatusBlock = { 0 };
    UNICODE_STRING DeletedUnicode = { 0 };
    UNICODE_STRING BackupUnicode = { 0 };
    FILE_STANDARD_INFORMATION DeletedInformation = { 0 };
    ULONG64 DeletedFileSize = 0;
    PVOID DeletedFileData = NULL;
    BOOLEAN IsDirectoryDelete = FALSE;


    // Get the file information:
    if (!NT_SUCCESS(FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED
        | FLT_FILE_NAME_QUERY_DEFAULT,
        &NameInfo))) {
        goto FinishLabel;
    }


    // Parse the file name from information:
    if (!NT_SUCCESS(FltParseFileNameInformation(NameInfo))) {
        goto FinishLabel;
    }


    // Increment counters for generic setinfo-pre request:
    if (!DatabaseCallbacks::IncrementByInformation(Data, NameInfo, SetInfoPreCount)) {
        DbgPrintEx(0, 0, "Shminifilter preoperation - setinfo-pre operation incrementing failed\n");
    }


    // Process only file dispositions / renames to files for delete backup (set-info is not important otherwise):
    switch (Data->Iopb->Parameters.SetFileInformation.FileInformationClass) {
    case FileRenameInformation:
    case FileRenameInformationEx:
    case FileDispositionInformation:
    case FileDispositionInformationEx:
    case FileRenameInformationBypassAccessCheck:
    case FileRenameInformationExBypassAccessCheck:
        break;

    default:
        goto FinishLabel;
    }


    // Prevent deletion of protected files and backup deleted files:
    Status = FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &IsDirectoryDelete);
    if (NT_SUCCESS(Status)) {
        if (IsDirectoryDelete) {
            goto FinishLabel;  // Ignore directory deletion
        }
    }
    if (HelperFunctions::IsInParentDirectory(&NameInfo->ParentDir, &TriggerAccessDeniedParentDir)) {
        DatabaseCallbacks::IncrementDetected();
        DbgPrintEx(0, 0, "-- Delete with set information is on a file inside a disclosed directory (parent directory = %wZ, disclosed directory = %wZ), blocking access ...\n",
            &NameInfo->ParentDir, &TriggerAccessDeniedParentDir);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        DatabaseEntry = DatabaseCallbacks::CreateDatabaseEntry(Data, NameInfo, "Deleted file is protected, preventing deletion ..",
            "SETINFO PREOPERATION");
        FilterStatus = FLT_PREOP_COMPLETE;
    }
    else {

        // Create paths for the deleted file and the backup file:
        wcscat_s(BackupFilePath, BackupDirectory.Buffer);
        wcscat_s(BackupFilePath, NameInfo->ParentDir.Buffer);
        wcscat_s(BackupFilePath, NameInfo->Name.Buffer);
        wcscat_s(FullDeletedPath, NameInfo->ParentDir.Buffer);
        wcscat_s(FullDeletedPath, NameInfo->Name.Buffer);
        RtlInitUnicodeString(&DeletedUnicode, FullDeletedPath);
        InitializeObjectAttributes(&DeletedAttrs, &DeletedUnicode, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL, NULL);
        RtlInitUnicodeString(&BackupUnicode, BackupFilePath);
        InitializeObjectAttributes(&BackupAttrs, &BackupUnicode, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL, NULL);


        // Read deleted file data to copy it into backup file:
        Status = ZwCreateFile(&DeletedFile, SYNCHRONIZE | GENERIC_READ, &DeletedAttrs, &StatusBlock,
            NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        if (!NT_SUCCESS(Status) || DeletedFile == NULL) {
            DbgPrintEx(0, 0, "Shminifilter preoperation - setinfo-pre operation backup of deleted failed (del_create)\n");
            goto FinishLabel;
        }
        Status = NtQueryInformationFile(DeletedFile, &StatusBlock,
            &DeletedInformation, sizeof(DeletedInformation), FileStandardInformation);
        if (!NT_SUCCESS(Status) || DeletedFile == NULL) {
            DbgPrintEx(0, 0, "Shminifilter preoperation - setinfo-pre operation backup of deleted failed (del_size)\n");
            ZwClose(DeletedFile);
            goto FinishLabel;
        }
        DeletedFileSize = DeletedInformation.EndOfFile.QuadPart;
        DeletedFileData = ExAllocatePoolWithTag(NonPagedPool, DeletedFileSize, 'DfBd');
        if (DeletedFileData == NULL) {
            DbgPrintEx(0, 0, "Shminifilter preoperation - setinfo-pre operation backup of deleted failed (del_alloc)\n");
            ZwClose(DeletedFile);
            goto FinishLabel;
        }
        Status = ZwReadFile(DeletedFile, NULL, NULL, NULL, &StatusBlock, DeletedFileData, (ULONG)DeletedFileSize,
            NULL, NULL);
        if (!NT_SUCCESS(Status)) {
            DbgPrintEx(0, 0, "Shminifilter preoperation - setinfo-pre operation backup of deleted failed (del_read)\n");
            ExFreePool(DeletedFileData);
            ZwClose(DeletedFile);
            goto FinishLabel;
        }
        ZwClose(DeletedFile);


        // Write deleted file data into backup file (make sure to overwrite existing backup):
        Status = ZwCreateFile(&BackupFile, SYNCHRONIZE | GENERIC_READ, &BackupAttrs, &StatusBlock,
            NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SUPERSEDE,
            FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        if (!NT_SUCCESS(Status) || BackupFile == NULL) {
            DbgPrintEx(0, 0, "Shminifilter preoperation - setinfo-pre operation backup of deleted failed (bck_create)\n");
            ExFreePool(DeletedFileData);
            goto FinishLabel;
        }
        Status = ZwWriteFile(BackupFile, NULL, NULL, NULL, &StatusBlock, DeletedFileData, (ULONG)DeletedFileSize,
            NULL, NULL);
        if (!NT_SUCCESS(Status)) {
            DbgPrintEx(0, 0, "Shminifilter preoperation - setinfo-pre operation backup of deleted failed (bck_create)\n");
        }
        ExFreePool(DeletedFileData);
        ZwClose(BackupFile);
    }

    
    // Add entry to database:
    if (DatabaseEntry != NULL) {
        if (!DatabaseCallbacks::AddEntryToDatabase(DatabaseEntry, ((PDETECTED_ENTRY)DatabaseEntry)->EntrySize)) {
            DatabaseCallbacks::DeleteDatabase();
        }
    }


FinishLabel:
    return FilterStatus;
}


FLT_POSTOP_CALLBACK_STATUS PostOperationCallbacks::CreateFilterCallback(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNICODE_STRING TriggerAccessDeniedParentDir = RTL_CONSTANT_STRING(L"\\VeryImportantStuffPostCreate\\");
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PVOID* CreateInfo = NULL;  // Will probably return the handle
    PULONG CreateInfoSize = NULL;
    PMDL* CreateMdl = NULL;
    UNICODE_STRING FileExtension = { 0 };
    UNICODE_STRING FileName = { 0 };
    PVOID DatabaseEntry = NULL;


    //  If our instance is in the process of being torn down - exit without doing anything:
    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }


    // Get the file information:
    Status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED
        | FLT_FILE_NAME_QUERY_DEFAULT,
        &NameInfo);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_FLT_INVALID_NAME_REQUEST) {
            DbgPrintEx(0, 0, "Shminifilter postoperation - create operation stopped, FltGetFileNameInformation() returned 0x%x\n",
                Status);
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }


    // Parse the file name from information:
    Status = FltParseFileNameInformation(NameInfo);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_FLT_INVALID_NAME_REQUEST) {
            DbgPrintEx(0, 0, "Shminifilter postoperation - create operation stopped, FltParseFileNameInformation() returned 0x%x (Name = %wZ)\n",
                Status, &NameInfo->Name);
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }


    // Output information about the create operation and other attributes:
    FltDecodeParameters(Data, &CreateMdl, &CreateInfo, &CreateInfoSize, NULL);
    FltParseFileName(&Data->Iopb->TargetFileObject->FileName, &FileExtension, NULL, &FileName);


    // Limit access to files inside a disclosed directory:
    if (HelperFunctions::IsInParentDirectory(&NameInfo->ParentDir, &TriggerAccessDeniedParentDir)) {
        DatabaseCallbacks::IncrementDetected();
        DbgPrintEx(0, 0, "-- Create is on a file inside a disclosed directory (parent directory = %wZ, disclosed directory = %wZ), blocking access ...\n",
            &NameInfo->ParentDir, &TriggerAccessDeniedParentDir);
        Data->IoStatus.Status = STATUS_NOT_FOUND;
        Data->IoStatus.Information = 0;
        DatabaseEntry = DatabaseCallbacks::CreateDatabaseEntry(Data, NameInfo, "Parent directory is disclosed, access denied",
            "CREATE POSTOPERATION");
    }


    // Increment counters for generic create-post request:
    if (!DatabaseCallbacks::IncrementByInformation(Data, NameInfo, CreatePostCount)) {
        DbgPrintEx(0, 0, "Shminifilter postoperation - create-post operation incrementing failed\n");
    }


    // Add database entry to the current database:
    if (DatabaseEntry != NULL) {
        if (!DatabaseCallbacks::AddEntryToDatabase(DatabaseEntry, ((PDETECTED_ENTRY)DatabaseEntry)->EntrySize)) {
            DatabaseCallbacks::DeleteDatabase();
        }
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_POSTOP_CALLBACK_STATUS PostOperationCallbacks::ReadFilterCallback(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);
    LPSTR TriggerHidingSequence = "The password is:";
    LPSTR AccessDeniedMessage = "ACCESS_DENIED XXX";
    int HidingIndex = -1;
    PVOID* ReadBuffer = NULL;
    PULONG ReadLength = NULL;
    UNICODE_STRING TextExtension = RTL_CONSTANT_STRING(L"txt");
    UNICODE_STRING TriggerObfuscateEnding = RTL_CONSTANT_STRING(L"dirty.txt");
    UNICODE_STRING TriggerAccessDeniedParentDir = RTL_CONSTANT_STRING(L"\\VeryImportantStuffPostRead\\");
    UNICODE_STRING FileExtension = { 0 };
    UNICODE_STRING FileName = { 0 };
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    BOOL AlreadyPrinted = FALSE;
    LPCSTR DisclosedInformation = "Content holds disclosed information ";
    LPCSTR EncryptedFile = "File matches needed suffix for irreversible encryption ";
    LPCSTR ParentDirectory = "Parent directory is disclosed, erasing read information ";
    char MultipleSpecial[1024] = { 0 };
    PVOID DatabaseEntry = NULL;


    // Get the file information:
    Status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED
        | FLT_FILE_NAME_QUERY_DEFAULT,
        &NameInfo);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_FLT_INVALID_NAME_REQUEST) {
            DbgPrintEx(0, 0, "Shminifilter postoperation - read operation stopped, FltGetFileNameInformation() returned 0x%x\n",
                Status);
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }


    // Parse the file name from information:
    Status = FltParseFileNameInformation(NameInfo);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_FLT_INVALID_NAME_REQUEST) {
            DbgPrintEx(0, 0, "Shminifilter postoperation - read operation stopped, FltParseFileNameInformation() returned 0x%x (Name = %wZ)\n",
                Status, &NameInfo->Name);
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }


    // Output information about the read data from the file and other attributes:
    FltDecodeParameters(Data, NULL, &ReadBuffer, &ReadLength, NULL);
    FltParseFileName(&Data->Iopb->TargetFileObject->FileName, &FileExtension, NULL, &FileName);


    // Change data from \..txt read to something else:
    if (RtlCompareUnicodeString(&FileExtension, &TextExtension, TRUE) == 0) {
        
        // Hide content after certain sequences of words:
        HidingIndex = HelperFunctions::DoesContain((LPSTR)Data->Iopb->Parameters.Read.ReadBuffer, TriggerHidingSequence, TRUE);
        if (HidingIndex != -1) {
            DatabaseCallbacks::IncrementDetected();
            HelperFunctions::PrintFileInfo(Data, NameInfo, &FileName, &FileExtension, *ReadLength);
            DbgPrintEx(0, 0, "-- File content contains hiding trigger (%s, index %d), hiding read content ...\n",
                TriggerHidingSequence, HidingIndex);
            AlreadyPrinted = TRUE;
            FltLockUserBuffer(Data);
            HelperFunctions::HideFileContent((LPSTR)Data->Iopb->Parameters.Read.ReadBuffer, HidingIndex, TriggerHidingSequence);
            FltSetCallbackDataDirty(Data);
            strcat_s(MultipleSpecial, DisclosedInformation);
        }

        // Irrevesingly obfuscate files with certain name suffixes:
        if (HelperFunctions::EndsWith(FileName.Buffer, TriggerObfuscateEnding.Buffer)) {
            DatabaseCallbacks::IncrementDetected();
            if (!AlreadyPrinted) {
                HelperFunctions::PrintFileInfo(Data, NameInfo, &FileName, &FileExtension, *ReadLength);
                AlreadyPrinted = TRUE;
            }
            DbgPrintEx(0, 0, "-- File name ends with obfuscate trigger (%wZ), obfuscating read content ...\n", &TriggerObfuscateEnding);
            FltLockUserBuffer(Data);
            HelperFunctions::ObfuscateFileContent((LPSTR)Data->Iopb->Parameters.Read.ReadBuffer);
            FltSetCallbackDataDirty(Data);
            strcat_s(MultipleSpecial, EncryptedFile);
        }
    }

    
    // Make sure that access to file/folder is permitted:
    if (HelperFunctions::IsInParentDirectory(&NameInfo->ParentDir, &TriggerAccessDeniedParentDir)) {
        DatabaseCallbacks::IncrementDetected();
        if (!AlreadyPrinted) {
            HelperFunctions::PrintFileInfo(Data, NameInfo, &FileName, &FileExtension, *ReadLength);
            AlreadyPrinted = TRUE;
        }
        DbgPrintEx(0, 0, "-- Read was on a file inside a disclosed directory (parent directory = %wZ, disclosed directory = %wZ), deleting read content ...\n",
            &NameInfo->ParentDir, &TriggerAccessDeniedParentDir);
        FltLockUserBuffer(Data);
        for (ULONG FileIndex = 0; FileIndex < *ReadLength; FileIndex++) {
            RtlCopyMemory((PVOID)((ULONG64)Data->Iopb->Parameters.Read.ReadBuffer + FileIndex),
                (PVOID)((ULONG64)AccessDeniedMessage + (FileIndex % strlen(AccessDeniedMessage))), 1);
        }
        FltSetCallbackDataDirty(Data);
        strcat_s(MultipleSpecial, ParentDirectory);
    }


    // Increment counters for generic read-post request:
    if (!DatabaseCallbacks::IncrementByInformation(Data, NameInfo, ReadPostCount)) {
        DbgPrintEx(0, 0, "Shminifilter postoperation - read-post operation incrementing failed\n");
    }


    // Create database entry and add it to the current database:
    if (strlen(MultipleSpecial) != 0) {
        DatabaseEntry = DatabaseCallbacks::CreateDatabaseEntry(Data, NameInfo, MultipleSpecial,
            "READ POSTOPERATION");
        if (DatabaseEntry != NULL) {
            if (!DatabaseCallbacks::AddEntryToDatabase(DatabaseEntry, ((PDETECTED_ENTRY)DatabaseEntry)->EntrySize)) {
                DatabaseCallbacks::DeleteDatabase();
            }
        }
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_POSTOP_CALLBACK_STATUS PostOperationCallbacks::DirectoryControlFilterCallback(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNICODE_STRING TriggerAccessDeniedParentDir = RTL_CONSTANT_STRING(L"\\VeryImportantStuffPostDirControl\\");
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PVOID* CreateInfo = NULL;  // Will probably return the handle
    PULONG CreateInfoSize = NULL;
    PMDL* CreateMdl = NULL;
    UNICODE_STRING FileExtension = { 0 };
    UNICODE_STRING FileName = { 0 };
    LPCSTR ParentBlocked = "Parent directory is disclosed, access denied";
    PVOID DatabaseEntry = NULL;
    PFLT_PARAMETERS FilterParameters = &Data->Iopb->Parameters;


    // Increment counters for generic dircontrol-post request:
    DatabaseCallbacks::IncrementByInformation(Data, NameInfo, DirControlPostCount);


    //  If our instance is in the process of being torn down - exit without doing anything:
    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }


    // If the operation failed just exit, no results to filter:
    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }


    // Get the file information:
    Status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED
        | FLT_FILE_NAME_QUERY_DEFAULT,
        &NameInfo);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_FLT_INVALID_NAME_REQUEST) {
            DbgPrintEx(0, 0, "Shminifilter postoperation - dircontrol operation stopped, FltGetFileNameInformation() returned 0x%x\n",
                Status);
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }


    // Parse the file name from information:
    Status = FltParseFileNameInformation(NameInfo);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_FLT_INVALID_NAME_REQUEST) {
            DbgPrintEx(0, 0, "Shminifilter postoperation - dircontrol operation stopped, FltParseFileNameInformation() returned 0x%x (Name = %wZ)\n",
                Status, &NameInfo->Name);
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }


    // Output information about the create operation and other attributes:
    FltDecodeParameters(Data, &CreateMdl, &CreateInfo, &CreateInfoSize, NULL);
    FltParseFileName(&Data->Iopb->TargetFileObject->FileName, &FileExtension, NULL, &FileName);


    // Make sure that access to file/folder is permitted and create database entries:
    if (HelperFunctions::IsInParentDirectory(&NameInfo->ParentDir, &TriggerAccessDeniedParentDir)) {
        DatabaseCallbacks::IncrementDetected();
        DbgPrintEx(0, 0, "-- Directory control is on a file inside a disclosed directory (parent directory = %wZ, disclosed directory = %wZ), blocking access ...\n",
            &NameInfo->ParentDir, &TriggerAccessDeniedParentDir);
        FilterParameters->DirectoryControl.QueryDirectory.DirectoryBuffer = NULL;
        Data->IoStatus.Status = STATUS_NO_MORE_ENTRIES;
        DatabaseEntry = DatabaseCallbacks::CreateDatabaseEntry(Data, NameInfo, (LPSTR)ParentBlocked,
            "DIRCONTROL POSTOPERATION");
    }


    // Add database entry to the current database:
    if (DatabaseEntry != NULL) {
        if (!DatabaseCallbacks::AddEntryToDatabase(DatabaseEntry, ((PDETECTED_ENTRY)DatabaseEntry)->EntrySize)) {
            DatabaseCallbacks::DeleteDatabase();
        }
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_POSTOP_CALLBACK_STATUS PostOperationCallbacks::SetInformationFilterCallback(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PVOID* CreateInfo = NULL;  // Will probably return the handle
    PULONG CreateInfoSize = NULL;
    PMDL* CreateMdl = NULL;
    UNICODE_STRING FileExtension = { 0 };
    UNICODE_STRING FileName = { 0 };


    // Increment counters for generic setinfo-post request:
    DatabaseCallbacks::IncrementByInformation(Data, NameInfo, SetInfoPostCount);


    //  If our instance is in the process of being torn down - exit without doing anything:
    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }


    // If the operation failed just exit, no results to filter:
    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }


    // Get the file information:
    Status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED
        | FLT_FILE_NAME_QUERY_DEFAULT,
        &NameInfo);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_FLT_INVALID_NAME_REQUEST) {
            DbgPrintEx(0, 0, "Shminifilter postoperation - set-info operation stopped, FltGetFileNameInformation() returned 0x%x\n",
                Status);
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }


    // Parse the file name from information:
    Status = FltParseFileNameInformation(NameInfo);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_FLT_INVALID_NAME_REQUEST) {
            DbgPrintEx(0, 0, "Shminifilter postoperation - set-info operation stopped, FltParseFileNameInformation() returned 0x%x (Name = %wZ)\n",
                Status, &NameInfo->Name);
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }


    // Output information about the set-info operation and other attributes:
    FltDecodeParameters(Data, &CreateMdl, &CreateInfo, &CreateInfoSize, NULL);
    FltParseFileName(&Data->Iopb->TargetFileObject->FileName, &FileExtension, NULL, &FileName);
    return FLT_POSTOP_FINISHED_PROCESSING;
}


/*
-------------
General callbacks, used for infrastructure of a mini-filter driver
-------------
*/


NTSTATUS FLTAPI GeneralCallbacks::InstanceSetupFilterCallback(_In_ PCFLT_RELATED_OBJECTS  FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS  Flags,
    _In_ DEVICE_TYPE  VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE  VolumeFilesystemType) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    // DbgPrintEx(0, 0, "Shminifilter general - InstanceSetupFilterCallback called, does nothing for now\n");
    return STATUS_SUCCESS;
}


NTSTATUS FLTAPI GeneralCallbacks::InstanceQueryTeardownFilterCallback(_In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    DbgPrintEx(0, 0, "Shminifilter general - InstanceQueryTeardownFilterCallback called, does nothing for now\n");
    return STATUS_SUCCESS;
}