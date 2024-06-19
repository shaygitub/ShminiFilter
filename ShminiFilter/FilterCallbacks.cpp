#include "FilterCallbacks.h"
#include "helpers.h"
#pragma warning (disable : 4996)
#pragma warning (disable : 4267)
#pragma warning (disable : 4244)


FLT_PREOP_CALLBACK_STATUS FLTAPI PreOperationCallbacks::CreateFilterCallback(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
    PFLT_PARAMETERS FilterParameters = NULL;
    PVOID DatabaseEntry = NULL;
    UNICODE_STRING TriggerAccessDeniedParentDir = RTL_CONSTANT_STRING(L"\\VeryImportantStuffDeleteProtection\\");
    UNICODE_STRING TriggerDeleteBackup = RTL_CONSTANT_STRING(L"\\VeryImportantStuffBackup\\");
    UNICODE_STRING BackupDirectory = RTL_CONSTANT_STRING(L"\\DeleteBackupShminiFilter\\C");
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING FileExtension = { 0 };
    UNICODE_STRING FileName = { 0 };
    FLT_PREOP_CALLBACK_STATUS FilterStatus = FLT_PREOP_SYNCHRONIZE;
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
            if (HelperFunctions::IsInParentDirectory(&NameInfo->ParentDir, &TriggerDeleteBackup)) {
                DbgPrintEx(0, 0, "Shminifilter preoperation - Backup parameters: %ws, %ws, %ws, %ws, %ws\n", BackupDirectory.Buffer,
                    NameInfo->ParentDir.Buffer, NameInfo->Name.Buffer, NameInfo->ParentDir.Buffer, NameInfo->Name.Buffer);
                HelperFunctions::CreateBackupOfFile(&BackupDirectory, NameInfo->ParentDir.Buffer, NameInfo->Name.Buffer);
            }
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


FLT_PREOP_CALLBACK_STATUS FLTAPI PreOperationCallbacks::SetInformationFilterCallback(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
    PVOID DatabaseEntry = NULL;
    UNICODE_STRING TriggerAccessDeniedParentDir = RTL_CONSTANT_STRING(L"\\VeryImportantStuffDeleteProtection\\");
    UNICODE_STRING TriggerDeniedRenameParentDir = RTL_CONSTANT_STRING(L"\\VeryImportantStuffRenameProtection\\");
    UNICODE_STRING TriggerDeleteBackup = RTL_CONSTANT_STRING(L"\\VeryImportantStuffBackup\\");
    UNICODE_STRING TriggerDeniedRenameName = RTL_CONSTANT_STRING(L"CannotRenameToThisName");
    UNICODE_STRING BackupDirectory = RTL_CONSTANT_STRING(L"\\BackupShminiFilterDelete\\C");
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING FileExtension = { 0 };
    UNICODE_STRING FileName = { 0 };
    FLT_PREOP_CALLBACK_STATUS FilterStatus = FLT_PREOP_SYNCHRONIZE;
    BOOLEAN IsDirectoryDelete = FALSE;
    PFILE_RENAME_INFORMATION RenameParameters = NULL;
    PFILE_END_OF_FILE_INFORMATION EndOfFileParameters = NULL;
    PFILE_NAME_INFORMATION ShortNameParameters = NULL;
    PFILE_POSITION_INFORMATION PositionParameters = NULL;
    PFILE_LINK_INFORMATION LinkParameters = NULL;
    PFILE_BASIC_INFORMATION BasicParameters = NULL;

    BOOL IsRename = FALSE;
    BOOL IsRenameShort = TRUE;
    IO_STATUS_BLOCK StatusBlock = { 0 };
    FILE_NAME_INFORMATION FileNameInfo = { 0 };
    UNICODE_STRING RootDirUnicode = { 0 };
    UNICODE_STRING RenameUnicode = { 0 };


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
    case FileDispositionInformation:
    case FileDispositionInformationEx:
        break;

    case FileRenameInformation:
    case FileRenameInformationEx:
    case FileRenameInformationBypassAccessCheck:
    case FileRenameInformationExBypassAccessCheck:
        IsRename = TRUE;
        RenameParameters = (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        break;

    case FileShortNameInformation:
        IsRename = TRUE;
        IsRenameShort = TRUE;
        ShortNameParameters = (PFILE_NAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        break;

    case FileEndOfFileInformation:
        EndOfFileParameters = (PFILE_END_OF_FILE_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        //DbgPrintEx(0, 0, "Shminifilter preoperation - setinfo-pre operation, changing file size to %llu\n",
        //    EndOfFileParameters->EndOfFile.QuadPart);
        break;

    case FilePositionInformation:
        PositionParameters = (PFILE_POSITION_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        DbgPrintEx(0, 0, "Shminifilter preoperation - setinfo-pre operation, changing file position to %llu\n",
            PositionParameters->CurrentByteOffset.QuadPart);
        break;

    case FileLinkInformation:
        LinkParameters = (PFILE_LINK_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        DbgPrintEx(0, 0, "Shminifilter preoperation - setinfo-pre operation, new link: %wZ, %wZ <--> %ws, %lu, %lu\n",
            &NameInfo->Name, &NameInfo->ParentDir, LinkParameters->FileName, LinkParameters->Flags,
            (ULONG)LinkParameters->ReplaceIfExists);
        break;

    case FileBasicInformation:
        BasicParameters = (PFILE_BASIC_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        //DbgPrintEx(0, 0, "Shminifilter preoperation - setinfo-pre operation, new basic information: %llu, %llu, %llu, %llu, %lu\n",
        //    BasicParameters->ChangeTime.QuadPart, BasicParameters->CreationTime.QuadPart,
        //    BasicParameters->LastAccessTime.QuadPart, BasicParameters->LastWriteTime.QuadPart, 
        //    BasicParameters->FileAttributes);
        break;

    default:
        goto FinishLabel;
    }


    // Prevent deletion of protected files and backup deleted files:
    Status = FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &IsDirectoryDelete);
    if (NT_SUCCESS(Status)) {
        if (IsDirectoryDelete) {
            goto FinishLabel;  // Ignore directory deletion/rename
        }
    }
    if (!IsRename) {
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
            if (HelperFunctions::IsInParentDirectory(&NameInfo->ParentDir, &TriggerDeleteBackup)) {
                DbgPrintEx(0, 0, "Shminifilter preoperation - Backup parameters: %ws, %ws, %ws, %ws, %ws\n", BackupDirectory.Buffer,
                    NameInfo->ParentDir.Buffer, NameInfo->Name.Buffer, NameInfo->ParentDir.Buffer, NameInfo->Name.Buffer);
                HelperFunctions::CreateBackupOfFile(&BackupDirectory, NameInfo->ParentDir.Buffer, NameInfo->Name.Buffer);
            }
        }
    }
    else {
        if (IsRenameShort) {
            goto InvalidNameCheck;  // ShortInformation only changes the shortened file name
        }
        Status = ZwQueryInformationFile(RenameParameters->RootDirectory,
            &StatusBlock,
            &FileNameInfo,
            (ULONG)sizeof(FILE_NAME_INFORMATION) + (MAX_PATH - 1),
            FileNameInformation);
        if (Status != STATUS_SUCCESS){
            goto InvalidNameCheck;  // Cannot get information to determine validation of root directory
        }
        RootDirUnicode.Buffer = FileNameInfo.FileName;
        RootDirUnicode.Length = FileNameInfo.FileNameLength;
        RootDirUnicode.MaximumLength = FileNameInfo.FileNameLength + sizeof(WCHAR);  // Null terminator not included
        if (HelperFunctions::IsInParentDirectory(&RootDirUnicode, &TriggerDeniedRenameParentDir)) {
            DatabaseCallbacks::IncrementDetected();
            DbgPrintEx(0, 0, "-- Rename is to a file inside a disclosed directory (parent directory = %wZ, disclosed directory = %wZ), blocking access ...\n",
                &NameInfo->ParentDir, &TriggerDeniedRenameParentDir);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            DatabaseEntry = DatabaseCallbacks::CreateDatabaseEntry(Data, NameInfo, "Rename root directory is protected, preventing rename ..",
                "SETINFO PREOPERATION");
            FilterStatus = FLT_PREOP_COMPLETE;
            goto DatabaseManipulation;
        }

    InvalidNameCheck:
        if (IsRenameShort) {
            if (ShortNameParameters != NULL) {
                RenameUnicode.Buffer = ShortNameParameters->FileName;
                RenameUnicode.Length = ShortNameParameters->FileNameLength;
                RenameUnicode.MaximumLength = ShortNameParameters->FileNameLength + sizeof(WCHAR);
            }
        }
        else {
            RenameUnicode.Buffer = RenameParameters->FileName;
            RenameUnicode.Length = wcslen(RenameParameters->FileName) * sizeof(WCHAR);
            RenameUnicode.MaximumLength = (wcslen(RenameParameters->FileName) + 1) * sizeof(WCHAR);
        }
        if (RenameUnicode.Buffer != NULL && RtlCompareUnicodeString(&TriggerDeniedRenameName, &RenameUnicode, TRUE) == 0) {
            DatabaseCallbacks::IncrementDetected();
            DbgPrintEx(0, 0, "-- Rename is to a blocked file name (file name = %wZ), blocking rename ...\n",
                &RenameUnicode);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            DatabaseEntry = DatabaseCallbacks::CreateDatabaseEntry(Data, NameInfo, "Rename file name is protected, preventing rename ..",
                "SETINFO PREOPERATION");
            FilterStatus = FLT_PREOP_COMPLETE;
            goto DatabaseManipulation;
        }
        if (!IsRenameShort) {
            if (FileNameInfo.FileName == NULL) {
                DbgPrintEx(0, 0, "Shminifilter preoperation - setinfo-pre operation with rename flag: NULL, %wZ, %lu, %lu\n",
                    &RenameUnicode, RenameParameters->Flags, (ULONG)RenameParameters->ReplaceIfExists);
            }
            else {
                DbgPrintEx(0, 0, "Shminifilter preoperation - setinfo-pre operation with rename flag: %wZ, %wZ, %lu, %lu\n",
                    &RootDirUnicode, &RenameUnicode, RenameParameters->Flags, (ULONG)RenameParameters->ReplaceIfExists);
            }
        }
    }


    // Add entry to database:
    DatabaseManipulation:
    if (DatabaseEntry != NULL) {
        if (!DatabaseCallbacks::AddEntryToDatabase(DatabaseEntry, ((PDETECTED_ENTRY)DatabaseEntry)->EntrySize)) {
            DatabaseCallbacks::DeleteDatabase();
        }
    }


FinishLabel:
    return FilterStatus;
}


FLT_PREOP_CALLBACK_STATUS PreOperationCallbacks::FileSystemControlFilterCallback(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext) {
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    BOOL FromKernel = FALSE;
    PVOID InputBuffer = NULL;
    PVOID OutputBuffer = NULL;
    ULONG InputBufferSize = 0;
    ULONG OutputBufferSize = 0;
    PMDL RelatedMdl = NULL;
    ULONG RelatedFsctl = 0;
    ULONG PassingMethod = 0;


    // Get the file information:
    Status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED
        | FLT_FILE_NAME_QUERY_DEFAULT,
        &NameInfo);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_FLT_INVALID_NAME_REQUEST) {
            DbgPrintEx(0, 0, "Shminifilter preoperation - filesys-pre operation stopped, FltGetFileNameInformation() returned 0x%x\n",
                Status);
        }
        return FLT_PREOP_SYNCHRONIZE;
    }


    // Parse the file name from information:
    Status = FltParseFileNameInformation(NameInfo);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_FLT_INVALID_NAME_REQUEST) {
            DbgPrintEx(0, 0, "Shminifilter preoperation - filesys-pre operation stopped, FltParseFileNameInformation() returned 0x%x (Name = %wZ)\n",
                Status, &NameInfo->Name);
        }
        return FLT_PREOP_SYNCHRONIZE;
    }


    // Increment counters for generic filesys-pre request:
    if (!DatabaseCallbacks::IncrementByInformation(Data, NameInfo, FileSysCntlPreCount)) {
        DbgPrintEx(0, 0, "Shminifilter preoperation - filesys-pre operation incrementing failed\n");
    }


    // Trace specific FSTCL codes:
    switch (Data->Iopb->MinorFunction) {
    case IRP_MN_KERNEL_CALL:
        FromKernel = TRUE;
        break;
    case IRP_MN_USER_FS_REQUEST:
        break;
    default:
        goto FinishLabel;  // IRP_MN_LOAD_FILE_SYSTEM / IRP_MN_MOUNT_VOLUME / IRP_MN_VERIFY_VOLUME:
    }


    // Get the I/O buffers and lengths for logging:
    if (Data->Iopb->Parameters.FileSystemControl.Buffered.SystemBuffer != NULL) {
        InputBuffer = Data->Iopb->Parameters.FileSystemControl.Buffered.SystemBuffer;
        OutputBuffer = InputBuffer;  // In METHOD_BUFFERED both input and output buffers are in SystemBuffer
        InputBufferSize = Data->Iopb->Parameters.FileSystemControl.Buffered.InputBufferLength;
        OutputBufferSize = Data->Iopb->Parameters.FileSystemControl.Buffered.OutputBufferLength;
        RelatedFsctl = Data->Iopb->Parameters.FileSystemControl.Buffered.FsControlCode;
        PassingMethod = METHOD_BUFFERED;
    }
    else if (Data->Iopb->Parameters.FileSystemControl.Direct.OutputMdlAddress != NULL) {
        InputBuffer = Data->Iopb->Parameters.FileSystemControl.Direct.InputSystemBuffer;
        OutputBuffer = Data->Iopb->Parameters.FileSystemControl.Direct.OutputBuffer;
        InputBufferSize = Data->Iopb->Parameters.FileSystemControl.Direct.InputBufferLength;
        OutputBufferSize = Data->Iopb->Parameters.FileSystemControl.Direct.OutputBufferLength;
        RelatedMdl = Data->Iopb->Parameters.FileSystemControl.Direct.OutputMdlAddress;  // Describes OutputBuffer
        RelatedFsctl = Data->Iopb->Parameters.FileSystemControl.Direct.FsControlCode;
        PassingMethod = METHOD_IN_DIRECT | METHOD_OUT_DIRECT;
    }
    else if (Data->Iopb->Parameters.FileSystemControl.Neither.InputBuffer != NULL ||
        Data->Iopb->Parameters.FileSystemControl.Neither.OutputBuffer != NULL) {
        InputBuffer = Data->Iopb->Parameters.FileSystemControl.Neither.InputBuffer;
        OutputBuffer = Data->Iopb->Parameters.FileSystemControl.Neither.OutputBuffer;
        InputBufferSize = Data->Iopb->Parameters.FileSystemControl.Neither.InputBufferLength;
        OutputBufferSize = Data->Iopb->Parameters.FileSystemControl.Neither.OutputBufferLength;
        RelatedMdl = Data->Iopb->Parameters.FileSystemControl.Neither.OutputMdlAddress;  // Describes OutputBuffer
        RelatedFsctl = Data->Iopb->Parameters.FileSystemControl.Neither.FsControlCode;
        PassingMethod = METHOD_NEITHER;
    }
    if (FromKernel) {
        //DbgPrintEx(0, 0, "ShminiFilter pre-operation - FSCTL %lu passed from KM component, parameters: %p, %p, %lu, %lu, %p method: %lu\n",
        //    RelatedFsctl, InputBuffer, OutputBuffer, InputBufferSize, OutputBufferSize, RelatedMdl, PassingMethod);
    }
    else {
        //DbgPrintEx(0, 0, "ShminiFilter pre-operation - FSCTL %lu passed from UM component, parameters: %p, %p, %lu, %lu, %p method: %lu\n",
        //    RelatedFsctl, InputBuffer, OutputBuffer, InputBufferSize, OutputBufferSize, RelatedMdl, PassingMethod);
    }
    
    FinishLabel:
    return FLT_PREOP_SYNCHRONIZE;
}


FLT_PREOP_CALLBACK_STATUS PreOperationCallbacks::WriteFilterCallback(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext) {
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    PVOID DatabaseEntry = NULL;
    UNICODE_STRING TriggerDeniedWriteParentDir = RTL_CONSTANT_STRING(L"\\VeryImportantStuffWriteProtection\\");
    UNICODE_STRING TriggerWriteBackup = RTL_CONSTANT_STRING(L"\\VeryImportantStuffBackup\\");
    UNICODE_STRING TriggerDeniedWriteName = RTL_CONSTANT_STRING(L"CannotWriteIntoThisName");
    UNICODE_STRING BackupDirectory = RTL_CONSTANT_STRING(L"\\BackupShminiFilterWrite\\C");
    UNICODE_STRING TriggerEncryptName = RTL_CONSTANT_STRING(L"encrypt_my_write.txt");
    UNICODE_STRING TextExtension = RTL_CONSTANT_STRING(L"txt");
    LPSTR VulnurableInfo = "Here is some vulnurable information to write:";
    LPCSTR VulnurableInformation = "Writing content holds vulnurable information ";
    LPCSTR EncryptedFile = "File matches needed suffix for irreversible encryption of any write data ";
    FLT_PREOP_CALLBACK_STATUS FilterStatus = FLT_PREOP_SYNCHRONIZE;
    ULONG VulnDataIndex = 0;
    char MultipleSpecial[1024] = { 0 };


    // Get the file information:
    Status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED
        | FLT_FILE_NAME_QUERY_DEFAULT,
        &NameInfo);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_FLT_INVALID_NAME_REQUEST) {
            DbgPrintEx(0, 0, "Shminifilter preoperation - write-pre operation stopped, FltGetFileNameInformation() returned 0x%x\n",
                Status);
        }
        return FLT_PREOP_SYNCHRONIZE;
    }


    // Parse the file name from information:
    Status = FltParseFileNameInformation(NameInfo);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_FLT_INVALID_NAME_REQUEST) {
            DbgPrintEx(0, 0, "Shminifilter preoperation - write-pre operation stopped, FltParseFileNameInformation() returned 0x%x (Name = %wZ)\n",
                Status, &NameInfo->Name);
        }
        return FLT_PREOP_SYNCHRONIZE;
    }


    // Increment counters for generic write-pre request:
    if (!DatabaseCallbacks::IncrementByInformation(Data, NameInfo, WritePreCount)) {
        DbgPrintEx(0, 0, "Shminifilter preoperation - write-pre operation incrementing failed\n");
    }


    // Verify that write operation is on an unrestricted file:
    if (HelperFunctions::IsInParentDirectory(&NameInfo->ParentDir, &TriggerDeniedWriteParentDir)) {
        DatabaseCallbacks::IncrementDetected();
        DbgPrintEx(0, 0, "-- Write is into a file inside a disclosed directory (parent directory = %wZ, disclosed directory = %wZ), blocking access ...\n",
            &NameInfo->ParentDir, &TriggerDeniedWriteParentDir);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        DatabaseEntry = DatabaseCallbacks::CreateDatabaseEntry(Data, NameInfo, "Write root directory is protected, preventing writing ..",
            "WRITE PREOPERATION");
        FilterStatus = FLT_PREOP_COMPLETE;
        goto FinishLabel;
    }
    if (RtlCompareUnicodeString(&TriggerDeniedWriteName, &NameInfo->Name, TRUE) == 0) {
        DatabaseCallbacks::IncrementDetected();
        DbgPrintEx(0, 0, "-- Write is into a blocked file name (file name = %wZ), blocking write ...\n", &NameInfo->Name);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        DatabaseEntry = DatabaseCallbacks::CreateDatabaseEntry(Data, NameInfo, "Write file name is protected, preventing write ..",
            "WRITE PREOPERATION");
        FilterStatus = FLT_PREOP_COMPLETE;
        goto FinishLabel;
    }


    // From now on make sure write content/size manipulation is only made on valid buffer writing method:
    if (Data->Iopb->MinorFunction != IRP_MN_NORMAL) {
        goto FinishLabel;  // MDL manipulation is done by the user
    }
    

    // Manipulate write size and write content to prevent writing plaintext vulnurable information into a file / encrypt content:
    if (RtlCompareUnicodeString(&NameInfo->Extension, &TextExtension, TRUE) == 0) {
        VulnDataIndex = HelperFunctions::DoesContain((LPSTR)Data->Iopb->Parameters.Write.WriteBuffer, VulnurableInfo, TRUE);
        if (VulnDataIndex != -1) {
            DatabaseCallbacks::IncrementDetected();
            DbgPrintEx(0, 0, "-- File content contains vulnurable information (%s, index %d), writing less content ...\n",
                VulnurableInfo, VulnDataIndex);
           Data->Iopb->Parameters.Write.Length = VulnDataIndex + strlen(VulnurableInfo);  // Dont write the information after
           strcat_s(MultipleSpecial, VulnurableInformation);
        }

        // Irrevesingly obfuscate files with certain name suffixes:
        if (HelperFunctions::EndsWith(NameInfo->Name.Buffer, TriggerEncryptName.Buffer)) {
            DatabaseCallbacks::IncrementDetected();
            DbgPrintEx(0, 0, "-- File name ends with obfuscate trigger (%wZ), obfuscating write content ...\n", &TriggerEncryptName);
            FltLockUserBuffer(Data);
            HelperFunctions::ObfuscateFileContent((LPSTR)Data->Iopb->Parameters.Write.WriteBuffer);
            FltSetCallbackDataDirty(Data);
            strcat_s(MultipleSpecial, EncryptedFile);
        }
    }


    // Create entry in case of a couple needed events:
    if (strlen(MultipleSpecial) != 0) {
        DatabaseEntry = DatabaseCallbacks::CreateDatabaseEntry(Data, NameInfo, MultipleSpecial,
            "WRITE PREOPERATION");
    }
    else {

        // If nothing is wrong with the write parameters - backup last version of file:
        if (HelperFunctions::IsInParentDirectory(&NameInfo->ParentDir, &TriggerWriteBackup)) {
            DbgPrintEx(0, 0, "Shminifilter preoperation - Backup parameters: %ws, %ws, %ws, %ws, %ws\n", BackupDirectory.Buffer,
                NameInfo->ParentDir.Buffer, NameInfo->Name.Buffer, NameInfo->ParentDir.Buffer, NameInfo->Name.Buffer);
            HelperFunctions::CreateBackupOfFile(&BackupDirectory, NameInfo->ParentDir.Buffer, NameInfo->Name.Buffer);
        }
    }

    FinishLabel:
    if (DatabaseEntry != NULL) {
        if (!DatabaseCallbacks::AddEntryToDatabase(DatabaseEntry, ((PDETECTED_ENTRY)DatabaseEntry)->EntrySize)) {
            DatabaseCallbacks::DeleteDatabase();
        }
    }
    return FilterStatus;
}


FLT_PREOP_CALLBACK_STATUS PreOperationCallbacks::GeneralFilterCallback(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING FileExtension = { 0 };
    UNICODE_STRING FileName = { 0 };
    PVOID* Information = NULL;
    PULONG InformationSize = NULL;
    PMDL* Module = NULL;


    // Increment counters for generic request:
    switch (Data->Iopb->MajorFunction) {
    case IRP_MJ_CLEANUP:
        DatabaseCallbacks::IncrementByInformation(Data, NameInfo, CleanupPreCount); break;
    case IRP_MJ_CREATE:
        DatabaseCallbacks::IncrementByInformation(Data, NameInfo, CreatePreCount); break;
    case IRP_MJ_DIRECTORY_CONTROL:
        DatabaseCallbacks::IncrementByInformation(Data, NameInfo, DirControlPreCount); break;
    case IRP_MJ_FILE_SYSTEM_CONTROL:
        DatabaseCallbacks::IncrementByInformation(Data, NameInfo, FileSysCntlPreCount); break;
    case IRP_MJ_READ:
        DatabaseCallbacks::IncrementByInformation(Data, NameInfo, ReadPreCount); break;
    case IRP_MJ_SET_INFORMATION:
        DatabaseCallbacks::IncrementByInformation(Data, NameInfo, SetInfoPreCount); break;
    case IRP_MJ_WRITE:
        DatabaseCallbacks::IncrementByInformation(Data, NameInfo, WritePreCount); break;
    }


    // If the operation failed just exit, no results to filter:
    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_PREOP_SYNCHRONIZE;
    }


    // Get the file information:
    Status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED
        | FLT_FILE_NAME_QUERY_DEFAULT,
        &NameInfo);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_FLT_INVALID_NAME_REQUEST) {
            DbgPrintEx(0, 0, "Shminifilter preoperation - operation stopped, FltGetFileNameInformation() returned 0x%x\n",
                Status);
        }
        return FLT_PREOP_SYNCHRONIZE;
    }


    // Parse the file name from information:
    Status = FltParseFileNameInformation(NameInfo);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_FLT_INVALID_NAME_REQUEST) {
            DbgPrintEx(0, 0, "Shminifilter preoperation - operation stopped, FltParseFileNameInformation() returned 0x%x (Name = %wZ)\n",
                Status, &NameInfo->Name);
        }
        return FLT_PREOP_SYNCHRONIZE;
    }


    // Get information about the operation and other attributes:
    FltDecodeParameters(Data, &Module, &Information, &InformationSize, NULL);
    FltParseFileName(&Data->Iopb->TargetFileObject->FileName, &FileExtension, NULL, &FileName);
    return FLT_PREOP_SYNCHRONIZE;
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


FLT_POSTOP_CALLBACK_STATUS PostOperationCallbacks::GeneralFilterCallback(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING FileExtension = { 0 };
    UNICODE_STRING FileName = { 0 };
    PVOID* Information = NULL;
    PULONG InformationSize = NULL;
    PMDL* Module = NULL;


    // Increment counters for generic request:
    switch (Data->Iopb->MajorFunction) {
    case IRP_MJ_CLEANUP:
        DatabaseCallbacks::IncrementByInformation(Data, NameInfo, CleanupPostCount); break;
    case IRP_MJ_CREATE:
        DatabaseCallbacks::IncrementByInformation(Data, NameInfo, CreatePostCount); break;
    case IRP_MJ_DIRECTORY_CONTROL:
        DatabaseCallbacks::IncrementByInformation(Data, NameInfo, DirControlPostCount); break;
    case IRP_MJ_FILE_SYSTEM_CONTROL:
        DatabaseCallbacks::IncrementByInformation(Data, NameInfo, FileSysCntlPostCount); break;
    case IRP_MJ_READ:
        DatabaseCallbacks::IncrementByInformation(Data, NameInfo, ReadPostCount); break;
    case IRP_MJ_SET_INFORMATION:
        DatabaseCallbacks::IncrementByInformation(Data, NameInfo, SetInfoPostCount); break;
    case IRP_MJ_WRITE:
        DatabaseCallbacks::IncrementByInformation(Data, NameInfo, WritePostCount); break;
    }


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
            DbgPrintEx(0, 0, "Shminifilter postoperation - operation stopped, FltGetFileNameInformation() returned 0x%x\n",
                Status);
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }


    // Parse the file name from information:
    Status = FltParseFileNameInformation(NameInfo);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_FLT_INVALID_NAME_REQUEST) {
            DbgPrintEx(0, 0, "Shminifilter postoperation - operation stopped, FltParseFileNameInformation() returned 0x%x (Name = %wZ)\n",
                Status, &NameInfo->Name);
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }


    // Get information about the operation and other attributes:
    FltDecodeParameters(Data, &Module, &Information, &InformationSize, NULL);
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