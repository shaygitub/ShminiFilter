#include "FilterCallbacks.h"
#include "helpers.h"
#pragma warning(disable : 4996)
#pragma warning(disable : 6305)
#pragma warning(disable : 4267)
#pragma warning(disable : 6387)


// Global variables:
PVOID Database = NULL;
ULONG64 DatabaseBufferSize = 0;
BOOL IsExtracting = FALSE;
ULONG64 UpdateIdentifier = 0;


BOOL DatabaseCallbacks::InitiateDatabase() {
	DatabaseBufferSize = sizeof(MINIFILTER_STARTINFO);
	Database = ExAllocatePoolWithTag(NonPagedPool, sizeof(MINIFILTER_STARTINFO), 'DbSi');
	if (Database == NULL) {
		DatabaseBufferSize = 0;
		return FALSE;
	}
	RtlZeroMemory(Database, sizeof(MINIFILTER_STARTINFO));
	UpdateIdentifier++;
	return TRUE;
}


BOOL DatabaseCallbacks::IncrementDetected() {
	/*
	Note: only to be called after DB is initiated
	*/
	if (Database == NULL) {
		return FALSE;
	}
	((PMINIFILTER_STARTINFO)Database)->DetectedCount++;
	return TRUE;
}


BOOL DatabaseCallbacks::IncrementByInformation(PFLT_CALLBACK_DATA Data, 
	PFLT_FILE_NAME_INFORMATION NameInfo, STARTINFO_OPERATION InitialCall) {
	UNICODE_STRING TextExtension = RTL_CONSTANT_STRING(L"txt");
	UNICODE_STRING CRoot = RTL_CONSTANT_STRING(L"\\");
	UNICODE_STRING WindowsRoot = RTL_CONSTANT_STRING(L"\\Windows");
	UNICODE_STRING System32Root = RTL_CONSTANT_STRING(L"\\Windows\\System32");
	UNICODE_STRING DriversRoot = RTL_CONSTANT_STRING(L"\\Windows\\System32\\drivers");
	UNICODE_STRING Ntoskrnl = RTL_CONSTANT_STRING(L"ntoskrnl.exe");
	UNICODE_STRING NtDll = RTL_CONSTANT_STRING(L"ntdll.dll");
	UNICODE_STRING User32Dll = RTL_CONSTANT_STRING(L"user32.dll");

	PVOID* Information = NULL;
	PULONG InformationSize = NULL;
	UNICODE_STRING FileExtension = { 0 };
	UNICODE_STRING FileName = { 0 };


	// Increment initial calls by registered filtering:
	__try {
		switch (InitialCall) {
		case EntryIdentifier: HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->EntryIdentifier,
			TRUE, &UpdateIdentifier); break;
		case CreatePreCount: HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->CreatePreCount,
			FALSE, NULL); break;
		case ReadPreCount: HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->ReadPreCount,
			FALSE, NULL); break;
		case WritePreCount: HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->WritePreCount,
			FALSE, NULL); break;
		case SetInfoPreCount: HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->SetInfoPreCount,
			FALSE, NULL); break;
		case CleanupPreCount: HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->CleanupPreCount,
			FALSE, NULL); break;
		case FileSysCntlPreCount: HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->FileSysCntlPreCount,
			FALSE, NULL); break;
		case DirControlPreCount: HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->DirControlPreCount,
			FALSE, NULL); break;
		case CreatePostCount: HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->CreatePostCount,
			FALSE, NULL); break;
		case ReadPostCount: HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->ReadPostCount,
			FALSE, NULL); break;
		case WritePostCount: HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->WritePostCount,
			FALSE, NULL); break;
		case SetInfoPostCount: HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->SetInfoPostCount,
			FALSE, NULL); break;
		case CleanupPostCount: HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->CleanupPostCount,
			FALSE, NULL); break;
		case FileSysCntlPostCount: HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->FileSysCntlPostCount,
			FALSE, NULL); break;
		case DirControlPostCount: HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->DirControlPostCount,
			FALSE, NULL); break;
		default:
			break;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrintEx(0, 0, "-- Access violation occured while incrementing basic operation counters\n");
	}


	// Create string for access information:
	if (Data != NULL && NameInfo != NULL) {
		FltDecodeParameters(Data, NULL, &Information, &InformationSize, NULL);
		FltParseFileName(&Data->Iopb->TargetFileObject->FileName, &FileExtension, NULL, &FileName);
		__try {
			if (FlagOn(Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess, FILE_GENERIC_READ)) {
				HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->GenericReadCount,
					FALSE, NULL);
			}
			if (FlagOn(Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess, FILE_GENERIC_WRITE)) {
				HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->GenericWriteCount,
					FALSE, NULL);	
			}
			if (FlagOn(Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess, FILE_GENERIC_EXECUTE)) {
				HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->GenericExecuteCount,
					FALSE, NULL);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->AccessViolationCount,
				FALSE, NULL);
		}


		// Create string for sharing information:
		__try {
			if (FlagOn(Data->Iopb->Parameters.Create.ShareAccess, FILE_SHARE_READ)) {
				HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->FileShareReadCount,
					FALSE, NULL);
			}
			if (FlagOn(Data->Iopb->Parameters.Create.ShareAccess, FILE_SHARE_WRITE)) {
				HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->FileShareWriteCount,
					FALSE, NULL);
			}
			if (FlagOn(Data->Iopb->Parameters.Create.ShareAccess, FILE_SHARE_DELETE)) {
				HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->FileShareDeleteCount,
					FALSE, NULL);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->AccessViolationCount,
				FALSE, NULL);
		}


		// Add specific information:
		if (Data->RequestorMode == UserMode) {
			HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->UserModeCount,
				FALSE, NULL);
		}
		else {
			HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->KernelModeCount,
				FALSE, NULL);
		}
		if (RtlCompareUnicodeString(&FileExtension, &TextExtension, TRUE)) {
			HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->TextCount,
				FALSE, NULL);
		}
		else {
			HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->ByteCount,
				FALSE, NULL);
		}


		// Check for specific folders/files:
		if (RtlCompareUnicodeString(&NameInfo->ParentDir, &CRoot, TRUE)) {
			HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->CRootCount,
				FALSE, NULL);
		}
		if (RtlCompareUnicodeString(&NameInfo->ParentDir, &WindowsRoot, TRUE)) {
			HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->WindowsRootCount,
				FALSE, NULL);
		}
		if (RtlCompareUnicodeString(&NameInfo->ParentDir, &System32Root, TRUE)) {
			HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->System32RootCount,
				FALSE, NULL);
		}
		if (RtlCompareUnicodeString(&NameInfo->ParentDir, &DriversRoot, TRUE)) {
			HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->DriversRootCount,
				FALSE, NULL);
		}
		if (RtlCompareUnicodeString(&FileName, &Ntoskrnl, TRUE)) {
			HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->NtoskrnlCount,
				FALSE, NULL);
		}
		if (RtlCompareUnicodeString(&FileName, &NtDll, TRUE)) {
			HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->NtdllCount,
				FALSE, NULL);
		}
		if (RtlCompareUnicodeString(&FileName, &User32Dll, TRUE)) {
			HelperFunctions::IncrementBuffer(&((PMINIFILTER_STARTINFO)Database)->User32dllCount,
				FALSE, NULL);
		}
		((PMINIFILTER_STARTINFO)Database)->CopiedBytesCount += *InformationSize;
	}
	return TRUE;
}


void DatabaseCallbacks::GetDatabase(PVOID* DatabasePool, ULONG64* DatabaseSize) {
	if (DatabasePool != NULL) {
		*DatabasePool = Database;
	}
	if (DatabaseSize != NULL) {
		*DatabaseSize = DatabaseBufferSize;
	}
}


void DatabaseCallbacks::DeleteDatabase() {
	if (Database != NULL) {
		ExFreePool(Database);
	}
	Database = NULL;
	DatabaseBufferSize = 0;
}


void DatabaseCallbacks::LockExtracting() {
	InterlockedExchange((volatile LONG*)&IsExtracting, TRUE);
}


void DatabaseCallbacks::UnlockExtracting() {
	InterlockedExchange((volatile LONG*)&IsExtracting, FALSE);
}


PVOID DatabaseCallbacks::CreateDatabaseEntry(PFLT_CALLBACK_DATA Data, PFLT_FILE_NAME_INFORMATION NameInfo,
	LPSTR SpecialString, LPSTR OperationDescriptor) {
	UNICODE_STRING TextExtension = RTL_CONSTANT_STRING(L"txt");
	PVOID* Information = NULL;
	PULONG InformationSize = NULL;
	PMDL* CallerMdl = NULL;
	UNICODE_STRING FileExtension = { 0 };
	UNICODE_STRING FileName = { 0 };
	UNICODE_STRING StatusString = { 0 };
	LARGE_INTEGER CurrentTimePassed = { 0 };
	LARGE_INTEGER AllignedTime = { 0 };
	PUCHAR EntryBuffer = NULL;
	ULONG BufferOffset = 0;

	ANSI_STRING FileExtensionAnsi = { 0 };
	ANSI_STRING FileNameAnsi = { 0 };
	ANSI_STRING ParentDirectory = { 0 };
	ANSI_STRING Share = { 0 };
	ANSI_STRING Stream = { 0 };
	ANSI_STRING Volume = { 0 };
	ANSI_STRING StatusStringAnsi = { 0 };
	DETECTED_ENTRY CurrentEntry = { 0 };
	char SecurityInfo[1024] = { 0 };
	char SharedInfo[1024] = { 0 };
	// NTSTATUS Status = STATUS_SUCCESS;


	// Check for invalid parameters:
	if (Data == NULL || NameInfo == NULL || SpecialString == NULL ||
		OperationDescriptor == NULL) {
		return NULL;
	}


	// Create string for access information:
	FltDecodeParameters(Data, &CallerMdl, &Information, &InformationSize, NULL);
	FltParseFileName(&Data->Iopb->TargetFileObject->FileName, &FileExtension, NULL, &FileName);
	__try {
		if (FlagOn(Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess, FILE_GENERIC_READ)) {
			strcat_s(SecurityInfo, "FILE_GENERIC_READ");
		}
		if (FlagOn(Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess, FILE_GENERIC_WRITE)) {
			if (strlen(SecurityInfo) != 0) {
				strcat_s(SecurityInfo, " | FILE_GENERIC_WRITE");
			}
			else {
				strcat_s(SecurityInfo, "FILE_GENERIC_WRITE");
			}
		}
		if (FlagOn(Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess, FILE_GENERIC_EXECUTE)) {
			if (strlen(SecurityInfo) != 0) {
				strcat_s(SecurityInfo, " | FILE_GENERIC_EXECUTE");
			}
			else {
				strcat_s(SecurityInfo, "FILE_GENERIC_EXECUTE");
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		// Status = GetExceptionCode();
		strcat_s(SecurityInfo, "ACCESS_INFO_EXCEPTION");
	}


	// Create string for sharing information:
	__try {
		if (FlagOn(Data->Iopb->Parameters.Create.ShareAccess, FILE_SHARE_READ)) {
			strcat_s(SharedInfo, "FILE_SHARE_READ");
		}
		if (FlagOn(Data->Iopb->Parameters.Create.ShareAccess, FILE_SHARE_WRITE)) {
			if (strlen(SharedInfo) != 0) {
				strcat_s(SharedInfo, " | FILE_SHARE_WRITE");
			}
			else {
				strcat_s(SharedInfo, "FILE_SHARE_WRITE");
			}
		}
		if (FlagOn(Data->Iopb->Parameters.Create.ShareAccess, FILE_SHARE_DELETE)) {
			if (strlen(SharedInfo) != 0) {
				strcat_s(SharedInfo, " | FILE_SHARE_DELETE");
			}
			else {
				strcat_s(SharedInfo, "FILE_SHARE_DELETE");
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		// Status = GetExceptionCode();
		strcat_s(SecurityInfo, "SHARE_INFO_EXCEPTION");
	}


	// Create timestamp for operation:
	KeQuerySystemTimePrecise(&CurrentTimePassed);
	ExSystemTimeToLocalTime(&CurrentTimePassed, &AllignedTime);


	// Convert wide character strings to ansi strings:
	RtlUnicodeStringToAnsiString(&FileExtensionAnsi, &FileExtension, TRUE);
	RtlUnicodeStringToAnsiString(&FileNameAnsi, &FileName, TRUE);
	RtlUnicodeStringToAnsiString(&ParentDirectory, &NameInfo->ParentDir, TRUE);
	RtlUnicodeStringToAnsiString(&Share, &NameInfo->Share, TRUE);
	RtlUnicodeStringToAnsiString(&Stream, &NameInfo->Stream, TRUE);
	RtlUnicodeStringToAnsiString(&Volume, &NameInfo->Volume, TRUE);


	// Define entry size:
	CurrentEntry.EntrySize = sizeof(DETECTED_ENTRY) +
		(strlen(OperationDescriptor) + 1) +  // Special description for operation
		(FileNameAnsi.Length + FileExtensionAnsi.Length + 2) +  // File name + extension
		(ParentDirectory.Length + 1) +  // Parent directory
		(Share.Length + 1) +  // Share string
		(Stream.Length + 1) +  // Stream string
		(Volume.Length + 1) +  // Volume string
		(strlen(SpecialString) + 1) +  // Special description for operation
		(strlen(SecurityInfo) + 1) +  // Security file information
		(strlen(SharedInfo) + 1);  // Sharing file information


	// Allocate entry and fill it with the needed information:
	EntryBuffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, CurrentEntry.EntrySize, 'EbDe');
	if (EntryBuffer != NULL) {

		// Fill basic entry with information:
		CurrentEntry.CallingProcess = PsGetCurrentProcess();
		if (Data->RequestorMode == UserMode) {
			RtlCopyMemory(CurrentEntry.CallerContext, "UM", 3);
		}
		else {
			RtlCopyMemory(CurrentEntry.CallerContext, "KM", 3);
		}
		if (CallerMdl == NULL) {
			CurrentEntry.CallerMdl = NULL;
		}
		else {
			CurrentEntry.CallerMdl = *CallerMdl;
		}
		if (InformationSize == NULL) {
			CurrentEntry.InformationSize = 0;
		}
		else {
			CurrentEntry.InformationSize = *InformationSize;
		}
		if (FileExtension.Buffer != NULL && FileExtension.Length == 3 * sizeof(WCHAR) &&
			FileExtension.Buffer[0] == TextExtension.Buffer[0] &&
			FileExtension.Buffer[1] == TextExtension.Buffer[1] &&
			FileExtension.Buffer[2] == TextExtension.Buffer[2]) {
			RtlCopyMemory(CurrentEntry.InformationType, "TEXT", 5);
		}
		else {
			RtlCopyMemory(CurrentEntry.InformationType, "BYTE", 5);
		}
		CurrentEntry.Timestamp.QuadPart = AllignedTime.QuadPart;


		// Copy basic entry into entry buffer and copy the other strings:
		RtlCopyMemory(EntryBuffer, &CurrentEntry, sizeof(CurrentEntry));
		BufferOffset += sizeof(CurrentEntry);
		RtlCopyMemory(&EntryBuffer[BufferOffset], OperationDescriptor,
			strlen(OperationDescriptor) + 1);
		BufferOffset += strlen(OperationDescriptor) + 1;
		RtlCopyMemory(&EntryBuffer[BufferOffset], FileNameAnsi.Buffer, FileNameAnsi.Length + 1);
		BufferOffset += FileNameAnsi.Length + 1;
		RtlCopyMemory(&EntryBuffer[BufferOffset], FileExtensionAnsi.Buffer,
			FileExtensionAnsi.Length + 1);
		BufferOffset += FileExtensionAnsi.Length + 1;
		RtlCopyMemory(&EntryBuffer[BufferOffset], ParentDirectory.Buffer,
			ParentDirectory.Length + 1);
		BufferOffset += ParentDirectory.Length + 1;
		RtlCopyMemory(&EntryBuffer[BufferOffset], Share.Buffer,
			Share.Length + 1);
		BufferOffset += Share.Length + 1;
		RtlCopyMemory(&EntryBuffer[BufferOffset], Stream.Buffer,
			Stream.Length + 1);
		BufferOffset += Stream.Length + 1;
		RtlCopyMemory(&EntryBuffer[BufferOffset], Volume.Buffer,
			Volume.Length + 1);
		BufferOffset += Volume.Length + 1;
		RtlCopyMemory(&EntryBuffer[BufferOffset], SpecialString,
			strlen(SpecialString) + 1);
		BufferOffset += strlen(SpecialString) + 1;
		RtlCopyMemory(&EntryBuffer[BufferOffset], SecurityInfo,
			strlen(SecurityInfo) + 1);
		BufferOffset += strlen(SecurityInfo) + 1;
		RtlCopyMemory(&EntryBuffer[BufferOffset], SharedInfo,
			strlen(SharedInfo) + 1);
		BufferOffset += strlen(SharedInfo) + 1;
	}
	return EntryBuffer;
}


BOOL DatabaseCallbacks::AddEntryToDatabase(PVOID Entry, ULONG EntrySize) {
	/*
	Note: should only be called to add special entries for detected evemts
	*/
	PUCHAR TemporaryDatabase = NULL;
	if (Entry == NULL || EntrySize == 0 || Database == NULL ||
		DatabaseBufferSize < sizeof(MINIFILTER_STARTINFO)) {
		if (Entry != NULL) {
			ExFreePool(Entry);
		}
		return FALSE;
	}


	// Wait until driver is able to add new entries to database:
	while (IsExtracting) {
	}


	// Allocate memory for new database and copy the original data in:
	TemporaryDatabase = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, DatabaseBufferSize + EntrySize,
		'TdTb');
	if (TemporaryDatabase == NULL) {
		ExFreePool(Entry);
		return FALSE;
	}
	if (Database != NULL) {
		RtlCopyMemory(TemporaryDatabase, Database, DatabaseBufferSize);
		ExFreePool(Database);
	}
	RtlCopyMemory(&TemporaryDatabase[DatabaseBufferSize], Entry, EntrySize);
	DatabaseBufferSize += EntrySize;
	Database = TemporaryDatabase;
	ExFreePool(Entry);
	return TRUE;
}