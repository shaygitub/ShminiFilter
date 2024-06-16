#include "helpers.h"
#pragma warning (disable : 4996)


PVOID HelperFunctions::AllocateMemory(PVOID InitialAddress, SIZE_T AllocSize,
	KAPC_STATE* CurrState, ULONG_PTR ZeroBits) {
	MEMORY_BASIC_INFORMATION MemoryBasic = { 0 };
	PVOID AllocationAddress = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;


	// Check for invalid paramters:
	if (InitialAddress == NULL || AllocSize == 0) {
		return NULL;
	}


	// Initial query of memory (to confirm state and other parameters):
	__try {
		ProbeForRead(InitialAddress, AllocSize, sizeof(UCHAR));
		Status = ZwQueryVirtualMemory(ZwCurrentProcess(), InitialAddress, MemoryBasicInformation, &MemoryBasic, sizeof(MemoryBasic), NULL);

		if (!NT_SUCCESS(Status)) {
			KeUnstackDetachProcess(CurrState);
			return NULL;
		}
	}

	__except (STATUS_ACCESS_VIOLATION) {
		KeUnstackDetachProcess(CurrState);
		return NULL;
	}


	// Act upon initial memory status:
	if (MemoryBasic.Protect & PAGE_NOACCESS) {
		HelperFunctions::ChangeProtectionSettings(ZwCurrentProcess(), InitialAddress,
			(ULONG)AllocSize, PAGE_READWRITE, MemoryBasic.Protect);
	}


	// Set the initial allocation base for each memory state:
	if (MemoryBasic.State & MEM_FREE) {
		AllocationAddress = InitialAddress;
	}

	else if (MemoryBasic.State & MEM_RESERVE) {
		AllocationAddress = MemoryBasic.AllocationBase;

		// Verify region size:
		if (AllocSize > MemoryBasic.RegionSize) {
			Status = ZwFreeVirtualMemory(ZwCurrentProcess(), &MemoryBasic.AllocationBase,
				&MemoryBasic.RegionSize, MEM_RELEASE);
			if (!NT_SUCCESS(Status)) {
				KeUnstackDetachProcess(CurrState);
				return NULL;
			}

			Status = ZwQueryVirtualMemory(ZwCurrentProcess(), InitialAddress,
				MemoryBasicInformation, &MemoryBasic, sizeof(MemoryBasic), NULL);
			if (!NT_SUCCESS(Status)) {
				KeUnstackDetachProcess(CurrState);
				return NULL;
			}

			AllocationAddress = InitialAddress;
		}
	}

	else {
		Status = ZwFreeVirtualMemory(ZwCurrentProcess(), &MemoryBasic.AllocationBase,
			&MemoryBasic.RegionSize, MEM_RELEASE);
		if (!NT_SUCCESS(Status)) {
			KeUnstackDetachProcess(CurrState);
			return NULL;
		}

		Status = ZwQueryVirtualMemory(ZwCurrentProcess(), InitialAddress, 
			MemoryBasicInformation, &MemoryBasic, sizeof(MemoryBasic), NULL);
		if (!NT_SUCCESS(Status)) {
			KeUnstackDetachProcess(CurrState);
			return NULL;
		}

		AllocationAddress = InitialAddress;
	}


	// Verify updated region size:
	if (AllocSize > MemoryBasic.RegionSize) {
		KeUnstackDetachProcess(CurrState);
		return NULL;
	}


	// Allocate the actual memory:
	AllocationAddress = HelperFunctions::CommitMemoryRegions(ZwCurrentProcess(), AllocationAddress,
		AllocSize, PAGE_READWRITE, NULL, ZeroBits);
	KeUnstackDetachProcess(CurrState);
	return AllocationAddress;
}


BOOL HelperFunctions::ChangeProtectionSettings(HANDLE ProcessHandle, PVOID Address, ULONG Size,
	ULONG ProtSettings, ULONG OldProtect) {
	MEMORY_BASIC_INFORMATION MemoryInfo = { 0 };
	NTSTATUS Status = STATUS_UNSUCCESSFUL;


	// Check for invalid parameters:
	if (ProcessHandle == NULL || Address == NULL || Size == 0) {
		return FALSE;
	}


	// Change the protection settings of the whole memory range:
	__try {
		ProbeForRead(Address, Size, sizeof(UCHAR));
		Status = ZwProtectVirtualMemory(ProcessHandle, &Address, &Size, ProtSettings, &OldProtect);
		if (!NT_SUCCESS(Status)) {
			return FALSE;
		}
	}
	__except (STATUS_ACCESS_VIOLATION) {
		return FALSE;
	}


	// Query to verify that changes were done:
	__try {
		ProbeForRead(Address, Size, sizeof(UCHAR));
		Status = ZwQueryVirtualMemory(ProcessHandle, Address, MemoryBasicInformation, &MemoryInfo, sizeof(MemoryInfo), NULL);
		if (!NT_SUCCESS(Status)) {
			return TRUE;
		}
	}
	__except (STATUS_ACCESS_VIOLATION) {
		return TRUE;
	}

	if ((MemoryInfo.Protect & ProtSettings) && !(MemoryInfo.Protect & PAGE_GUARD || MemoryInfo.Protect & PAGE_NOACCESS)) {
		return FALSE;
	}
	return TRUE;
}


PVOID HelperFunctions::CommitMemoryRegions(HANDLE ProcessHandle, PVOID Address,
	SIZE_T Size, ULONG AllocProt, PVOID ExistingAllocAddr, ULONG_PTR ZeroBit) {
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	MEMORY_BASIC_INFORMATION MemoryInfo = { 0 };


	// Check for invalid parameters:
	if (ProcessHandle == NULL || Address == NULL || Size == 0) {
		return NULL;
	}


	// Allocate the actual needed pages and save them for committing later:
	if (ExistingAllocAddr != NULL) {
		Address = ExistingAllocAddr;
	}
	if (Address != ExistingAllocAddr) {
		__try {
			ProbeForRead(Address, Size, sizeof(UCHAR));
			Status = ZwAllocateVirtualMemory(ProcessHandle, &Address, ZeroBit, &Size, MEM_RESERVE, PAGE_NOACCESS);
		}
		__except (STATUS_ACCESS_VIOLATION) {
			DbgPrintEx(0, 0, "KMDFdriver Memory - Commit memory regions in process failed (access violation system exception)\n");
			return NULL;
		}

		if (!NT_SUCCESS(Status)) {
			Address = NULL;  // Required to tell the system to choose where to allocate the memory
			ZeroBit = 0;
			Status = ZwAllocateVirtualMemory(ProcessHandle, &Address, ZeroBit, &Size, MEM_RESERVE, PAGE_NOACCESS);  // Size and Address are alligned here after the first call
			if (!NT_SUCCESS(Status)) {
				return NULL;
			}
		}
	}


	// Allocate the range of pages in processes virtual memory with the required allocation type and protection settings:
	Status = ZwAllocateVirtualMemory(ProcessHandle, &Address, ZeroBit, &Size, MEM_COMMIT, AllocProt);
	if (!NT_SUCCESS(Status)) {
		if (Address != ExistingAllocAddr) {
			ZwFreeVirtualMemory(ProcessHandle, &Address, &Size, MEM_RELEASE);  // Release the unused memory
		}
		else {
			ZwFreeVirtualMemory(ProcessHandle, &Address, &Size, MEM_DECOMMIT);  // De-commit the unused memory
		}
		return NULL;
	}


	// Query to verify the change of memory state:
	Status = ZwQueryVirtualMemory(ProcessHandle, Address, MemoryBasicInformation, &MemoryInfo, sizeof(MemoryInfo), NULL);
	if (!NT_SUCCESS(Status)) {
		return Address;
	}

	if (!(MemoryInfo.State & MEM_COMMIT)) {
		return NULL;
	}
	return Address;
}


BOOL HelperFunctions::FreeAllocatedMemory(PEPROCESS EpDst, ULONG OldState,
	PVOID BufferAddress, SIZE_T BufferSize) {
	KAPC_STATE DstState = { 0 };
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	MEMORY_BASIC_INFORMATION MemoryBasic = { 0 };


	// Check for invalid paramters:
	if (EpDst == NULL || BufferAddress == NULL || BufferSize == 0) {
		return NULL;
	}


	// Query the memory area to get newer status update:
	KeStackAttachProcess(EpDst, &DstState);
	Status = ZwQueryVirtualMemory(ZwCurrentProcess(), BufferAddress, MemoryBasicInformation, &MemoryBasic, sizeof(MemoryBasic), NULL);
	if (!NT_SUCCESS(Status)) {
		KeUnstackDetachProcess(&DstState);
		return FALSE;
	}


	// Free memory if needed:
	if (MemoryBasic.AllocationBase == BufferAddress) {
		switch (MemoryBasic.State) {
		case MEM_COMMIT:
			if (!(OldState & MEM_RESERVE)) {
				Status = ZwFreeVirtualMemory(ZwCurrentProcess(), &BufferAddress, &BufferSize, MEM_RELEASE);  // Release the unused memory
			}
			else {
				Status = ZwFreeVirtualMemory(ZwCurrentProcess(), &BufferAddress, &BufferSize, MEM_DECOMMIT);  // De-commit the unused memory
			}
			KeUnstackDetachProcess(&DstState);
			if (!NT_SUCCESS(Status)) {
				return FALSE;
			}
			return TRUE;

		case MEM_RESERVE:
			if (!(OldState & MEM_RESERVE)) {
				Status = ZwFreeVirtualMemory(ZwCurrentProcess(), &BufferAddress, &BufferSize, MEM_RELEASE);  // Release the unused memory
			}
			KeUnstackDetachProcess(&DstState);
			if (!NT_SUCCESS(Status)) {
				return FALSE;
			}
			return TRUE;

		default:
			KeUnstackDetachProcess(&DstState);  // detach from the destination process
			return TRUE;
		}
	}
	else {
		KeUnstackDetachProcess(&DstState);
		return TRUE;
	}
}


NTSTATUS HelperFunctions::UserToKernel(PEPROCESS SrcProcess, PVOID UserAddress,
	PVOID KernelAddress, SIZE_T Size, BOOL IsAttached) {
	KAPC_STATE SrcState = { 0 };


	// Check for invalid parameters:
	if (SrcProcess == NULL || UserAddress == NULL || KernelAddress == NULL || Size == 0) {
		return STATUS_INVALID_PARAMETER;
	}


	// Attach to the usermode process if needed:
	if (!IsAttached) {
		KeStackAttachProcess(SrcProcess, &SrcState);
	}


	// Perform the transfer:
	__try {
		ProbeForRead(UserAddress, Size, sizeof(UCHAR));
		RtlCopyMemory(KernelAddress, UserAddress, Size);
		if (!IsAttached) {
			KeUnstackDetachProcess(&SrcState);
		}
		return STATUS_SUCCESS;
	}

	__except (STATUS_ACCESS_VIOLATION) {
		if (!IsAttached) {
			KeUnstackDetachProcess(&SrcState);
		}
		return STATUS_ACCESS_VIOLATION;
	}
}


NTSTATUS HelperFunctions::KernelToUser(PEPROCESS DstProcess, PVOID KernelAddress, PVOID UserAddress,
	SIZE_T Size, BOOL IsAttached) {
	KAPC_STATE DstState = { 0 };



	// Check for invalid parameters:
	if (DstProcess == NULL || KernelAddress == NULL || UserAddress == NULL || Size == 0) {
		return STATUS_INVALID_PARAMETER;
	}


	// Attach to the usermode process if needed:
	if (!IsAttached) {
		KeStackAttachProcess(DstProcess, &DstState);
	}


	// Perform the transfer:
	__try {
		ProbeForRead(UserAddress, Size, sizeof(UCHAR));
		RtlCopyMemory(UserAddress, KernelAddress, Size);
		if (!IsAttached) {
			KeUnstackDetachProcess(&DstState);
		}
		return STATUS_SUCCESS;
	}

	__except (STATUS_ACCESS_VIOLATION) {
		if (!IsAttached) {
			KeUnstackDetachProcess(&DstState);
		}
		return STATUS_ACCESS_VIOLATION;
	}
}


BOOL HelperFunctions::EndsWith(LPWSTR String, LPWSTR Ending) {
	if (Ending == NULL || String == NULL || wcslen(Ending) > wcslen(String)) {
		return FALSE;
	}
	for (ULONG StringIndex = 0; StringIndex < wcslen(String) - wcslen(Ending); StringIndex++) {
		if (wcscmp((LPWSTR)((ULONG64)String + (StringIndex * sizeof(WCHAR))), Ending) == 0) {
			return TRUE;
		}
	}
	return wcscmp((LPWSTR)((ULONG64)String + ((wcslen(String) - wcslen(Ending)) * sizeof(WCHAR))), Ending) == 0;
}


int HelperFunctions::DoesContain(LPSTR String, LPSTR Substring, BOOL CannotFinish) {
	LPSTR TemporaryPart = NULL;
	if (Substring == NULL || String == NULL || strlen(Substring) >= strlen(String)) {
		return -1;  // Also do not manipulate content if length is similar, best case is the same but then no password is read
	}
	TemporaryPart = (LPSTR)ExAllocatePoolWithTag(NonPagedPool, strlen(Substring) + 1, 'TpSs');
	if (TemporaryPart == NULL) {
		return -1;
	}
	for (ULONG StringIndex = 0; StringIndex < strlen(String) - strlen(Substring); StringIndex++) {
		RtlCopyMemory(TemporaryPart, (PVOID)((ULONG64)String + StringIndex), strlen(Substring));
		TemporaryPart[strlen(Substring)] = '\0';
		if (strcmp(TemporaryPart, Substring) == 0) {
			if (CannotFinish && StringIndex + strlen(Substring) == strlen(String)) {
				continue;  // Substring is at end
			}
			return StringIndex;
		}
	}
	ExFreePool(TemporaryPart);
	return -1;  // Not found
}


BOOL HelperFunctions::IsInParentDirectory(PUNICODE_STRING ParentDirectory, PUNICODE_STRING OperationDirectory) {
	ULONG ParentIndex = 0;
	if (ParentDirectory == NULL || OperationDirectory == NULL ||
		ParentDirectory->Buffer == NULL || OperationDirectory->Buffer == NULL ||
		wcslen(ParentDirectory->Buffer) < wcslen(OperationDirectory->Buffer)) {
		return FALSE;
	}
	if (wcslen(ParentDirectory->Buffer) == wcslen(OperationDirectory->Buffer)){
		if (wcscmp(ParentDirectory->Buffer, OperationDirectory->Buffer) == 0) {
			return TRUE;  // Exactly the same path
		}
		return FALSE;
	}
	for (; ParentIndex < wcslen(OperationDirectory->Buffer); ParentIndex++) {
		if (ParentDirectory->Buffer[ParentIndex] != OperationDirectory->Buffer[ParentIndex]) {
			return FALSE;
		}
	}
	return TRUE;
}


void HelperFunctions::CeasarEncode(LPSTR EncodingContent, ULONG BufferSize) {
	char CeasarShift = BufferSize % 26;
	if (EncodingContent != NULL && BufferSize != 0) {
		for (DWORD FileIndex = 0; FileIndex < strlen(EncodingContent); FileIndex++) {
			if (EncodingContent[FileIndex] >= 'A' && EncodingContent[FileIndex] <= 'Z') {
				EncodingContent[FileIndex] += CeasarShift;
				if (EncodingContent[FileIndex] > 'Z') {
					EncodingContent[FileIndex] -= 26;
				}
			}
			else if (EncodingContent[FileIndex] >= 'a' && EncodingContent[FileIndex] <= 'z') {
				EncodingContent[FileIndex] += CeasarShift;
				if (EncodingContent[FileIndex] > 'z') {
					EncodingContent[FileIndex] -= 26;
				}
			}
		}
	}
}


NTSTATUS HelperFunctions::CreateDataHash(PVOID DataToHash, ULONG SizeOfDataToHash, LPCWSTR HashName,
	PVOID* HashedDataOutput, ULONG* HashedDataLength) {
	/*
	Note: hash name is the documented macro for the type of encryption
	documented in https://learn.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers
	*/
	NTSTATUS Status = STATUS_SUCCESS;
	BCRYPT_ALG_HANDLE HashAlgorithm = { 0 };
	BCRYPT_HASH_HANDLE HashHandle = { 0 };
	ULONG HashObjectLength = 0;
	ULONG HashObjLengthWritten = 0;
	ULONG HashDataLength = 0;
	ULONG HashDataLengthWritten = 0;
	PVOID HashObject = NULL;
	PVOID HashedData = NULL;
	BOOL HashHandleCreated = FALSE;
	BOOL HashProviderCreated = FALSE;


	// Make sure no invalid parameters are provided (no need to enforce outputed hashed data length):
	if (HashName == NULL || DataToHash == NULL || HashedDataOutput == NULL) {
		return STATUS_INVALID_PARAMETER;
	}


	// Create the hashing algorithm provider handle to hash the data:
	Status = BCryptOpenAlgorithmProvider(&HashAlgorithm, HashName, NULL, 0);
	if (!NT_SUCCESS(Status)) {
		goto CleanUp;
	}
	HashProviderCreated = TRUE;


	// Get the needed length for the hashing object and allocate a non-paged pool for the object:
	Status = BCryptGetProperty(HashAlgorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&HashObjectLength,
		sizeof(HashObjectLength), &HashObjLengthWritten, 0);
	if (!NT_SUCCESS(Status) || HashObjLengthWritten != sizeof(HashObjectLength)) {
		if (NT_SUCCESS(Status)) {
			Status = STATUS_INFO_LENGTH_MISMATCH;  // In this case not all the data size was written
		}
		goto CleanUp;
	}
	HashObject = ExAllocatePoolWithTag(NonPagedPool, HashObjectLength, 'ThOp');
	if (HashObject == NULL) {
		Status = STATUS_MEMORY_NOT_ALLOCATED;
		goto CleanUp;
	}


	// Create the hashing object used to hash the actual data:
	Status = BCryptCreateHash(HashAlgorithm, &HashHandle, (PUCHAR)HashObject, HashObjectLength, NULL, 0, 0);
	if (!NT_SUCCESS(Status)) {
		goto CleanUp;
	}
	HashHandleCreated = TRUE;


	// Get the hashed data size and allocate a non-paged pool for the hashed data:
	Status = BCryptGetProperty(HashAlgorithm, BCRYPT_HASH_LENGTH, (PUCHAR)&HashDataLength,
		sizeof(HashDataLength), &HashDataLengthWritten, 0);
	if (!NT_SUCCESS(Status) || HashDataLengthWritten != sizeof(HashDataLength)) {
		if (NT_SUCCESS(Status)) {
			Status = STATUS_INFO_LENGTH_MISMATCH;  // In this case not all the data size was written
		}
		goto CleanUp;
	}
	HashedData = ExAllocatePoolWithTag(NonPagedPool, HashDataLength, 'ThDp');
	if (HashedData == NULL) {
		Status = STATUS_MEMORY_NOT_ALLOCATED;
		goto CleanUp;
	}


	// Hash the actual data:
	Status = BCryptHashData(HashHandle, (PUCHAR)DataToHash, SizeOfDataToHash, 0);
	if (!NT_SUCCESS(Status)) {
		goto CleanUp;
	}


	// Get the hash value (hash handle cannot be reused after this operation) and return it to caller:
	Status = BCryptFinishHash(HashHandle, (PUCHAR)HashedData, HashDataLength, 0);
	if (!NT_SUCCESS(Status)) {
		goto CleanUp;
	}


	// Clean up and return successfully:
CleanUp:
	if (HashHandleCreated) {
		BCryptDestroyHash(HashHandle);
	}
	if (HashProviderCreated) {
		BCryptCloseAlgorithmProvider(HashAlgorithm, 0);
	}
	if (HashObject != NULL) {
		ExFreePool(HashObject);
	}
	if (HashedData != NULL && !NT_SUCCESS(Status)) {
		ExFreePool(HashedData);  // Note: dont free HashedData if succeeded, will hold the hashed data
		HashedData = NULL;
		HashedDataLength = 0;
	}
	*HashedDataOutput = HashedData;
	if (HashedDataLength != NULL) {
		*HashedDataLength = HashDataLength;
	}
	return Status;
}


void HelperFunctions::PrintFileInfo(PFLT_CALLBACK_DATA Data, PFLT_FILE_NAME_INFORMATION NameInfo,
	PUNICODE_STRING FileName, PUNICODE_STRING FileExtension, ULONG BufferLength) {
	UNICODE_STRING TextExtension = RTL_CONSTANT_STRING(L"txt");


	// Output information about the running context of the operating process and its PEPROCESS:
	DbgPrintEx(0, 0, "\nCalling process is at %p\n", PsGetCurrentProcess());
	if (Data->RequestorMode == UserMode) {
		DbgPrintEx(0, 0, "-- Calling process is running at usermode\n");
	}
	else {
		DbgPrintEx(0, 0, "-- Calling process is running at kernelmode\n");
	}
	DbgPrintEx(0, 0, "-- Operation file name: %wZ, extension: %wZ\n", FileName, FileExtension);
	DbgPrintEx(0, 0, "-- Parent directory of file: %wZ\n", &NameInfo->ParentDir);
	DbgPrintEx(0, 0, "-- File share: %wZ\n", &NameInfo->Share);
	DbgPrintEx(0, 0, "-- File stream: %wZ\n", &NameInfo->Stream);
	DbgPrintEx(0, 0, "-- File volume: %wZ\n", &NameInfo->Volume);


	// Log if text file was received or not:
	if (RtlCompareUnicodeString(FileExtension, &TextExtension, TRUE) == 0) {
		DbgPrintEx(0, 0, "-- File content (size = %lu bytes): %s\n", BufferLength, (LPSTR)Data->Iopb->Parameters.Read.ReadBuffer);
	}
	else {
		DbgPrintEx(0, 0, "-- File content is not text and its size is %lu bytes\n", BufferLength);
	}
	// DbgPrintEx(0, 0, "-- Thread verification returned %d\n", (DWORD)ProtectionFunctions::FixHiddenOperations(Data->Thread));
}


void HelperFunctions::PrintSecurityInfo(ULONG Value, NTSTATUS Type) {
	switch (Type) {
	case STATUS_ACCESS_AUDIT_BY_POLICY:
		if (FlagOn(Value, FILE_GENERIC_READ)) {
			DbgPrintEx(0, 0, "-- Read access detected\n");
		}
		if (FlagOn(Value, FILE_GENERIC_WRITE)) {
			DbgPrintEx(0, 0, "-- Write access detected\n");
		}
		if (FlagOn(Value, FILE_GENERIC_EXECUTE)) {
			DbgPrintEx(0, 0, "-- Execute access detected\n");
		}
		break;
	case STATUS_SHARED_POLICY:
		if (FlagOn(Value, FILE_SHARE_READ)) {
			DbgPrintEx(0, 0, "-- Read share detected\n");
		}
		if (FlagOn(Value, FILE_SHARE_WRITE)) {
			DbgPrintEx(0, 0, "-- Write share detected\n");
		}
		if (FlagOn(Value, FILE_SHARE_DELETE)) {
			DbgPrintEx(0, 0, "-- Delete share detected\n");
		}
		break;
	}
}


BOOL HelperFunctions::ObfuscateFileContent(LPSTR FileContent) {
	PVOID ObfuscatedFile = NULL;
	DWORD ObFuscatedSize = 0;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	DbgPrintEx(0, 0, "Shminifilter helpers - obfuscating file content ..\n");
	if (FileContent == NULL) {
		return FALSE;
	}

	// Ceasar encode the file content:
	HelperFunctions::CeasarEncode(FileContent, (ULONG)strlen(FileContent) + 1);
	DbgPrintEx(0, 0, "-- Ceasar encoded file\n");


	// Create SHA256 hash of encoded file content:
	Status = HelperFunctions::CreateDataHash(FileContent, (ULONG)strlen(FileContent) + 1,
		BCRYPT_SHA256_ALGORITHM, &ObfuscatedFile, &ObFuscatedSize);
	if (!NT_SUCCESS(Status) || ObfuscatedFile == NULL || ObFuscatedSize == 0) {
		DbgPrintEx(0, 0, "-- Encryption failed: 0x%x\n", Status);
		if (ObfuscatedFile != NULL) {
			ExFreePool(ObfuscatedFile);
		}
		return FALSE;
	}


	// Copy the SHA256 into the buffer time after time:
	for (ULONG FileIndex = 0; FileIndex < strlen(FileContent); FileIndex++) {
		RtlCopyMemory((PVOID)((ULONG64)FileContent + FileIndex), 
			(PVOID)((ULONG64)ObfuscatedFile + (FileIndex % ObFuscatedSize)), 1);
	}
	DbgPrintEx(0, 0, "-- Created SHA256 of file data and filled buffer with hash\n");
	return TRUE;
}


void HelperFunctions::HideFileContent(LPSTR FileContent, int HidingIndex, LPSTR TriggerHidingSequence) {
	char HidingCharacter = '*';
	if (FileContent != NULL && HidingIndex != -1 && TriggerHidingSequence != NULL) {
		for (SIZE_T FileIndex = HidingIndex + strlen(TriggerHidingSequence); FileIndex < strlen(FileContent); FileIndex++) {
			FileContent[FileIndex] = HidingCharacter;
		}
	}
}


BOOL ProtectionFunctions::UnhideParentProcess(PACTEPROCESS ThreadParentProcess) {
	PACTEPROCESS CurrentProcess = NULL;
	PACTEPROCESS PreviousProcess = NULL;
	LIST_ENTRY* CurrentList = NULL;
	LIST_ENTRY* PreviousList = NULL;
	LIST_ENTRY* NextList = NULL;
	LIST_ENTRY* InitialProcessFlink = &((PACTEPROCESS)PsInitialSystemProcess)->ActiveProcessLinks;
	CurrentProcess = (PACTEPROCESS)PsInitialSystemProcess;
	PreviousList = &CurrentProcess->ActiveProcessLinks;
	CurrentList = PreviousList->Flink;
	CurrentProcess = (PACTEPROCESS)((ULONG64)CurrentList - offsetof(struct _ACTEPROCESS, ActiveProcessLinks));
	NextList = CurrentList->Flink;
	if (ThreadParentProcess == NULL) {
		return FALSE;
	}


	// Iterate list to check if any fixing is needed, if so - link process to end of list:
	while (CurrentList != InitialProcessFlink) {
		if ((ULONG64)CurrentProcess->UniqueProcessId == (ULONG64)ThreadParentProcess->UniqueProcessId) {
			return TRUE;  // Process was not hidden (unlinked from list)
		}
		PreviousList = CurrentList;
		CurrentList = NextList;
		NextList = CurrentList->Flink;
		CurrentProcess = (PACTEPROCESS)((ULONG64)CurrentList - offsetof(struct _ACTEPROCESS, ActiveProcessLinks));
	}
	PreviousProcess = (PACTEPROCESS)((ULONG64)PreviousList - offsetof(struct _ACTEPROCESS, ActiveProcessLinks));
	(&ThreadParentProcess->ActiveProcessLinks)->Flink = CurrentList;
	PreviousList->Flink = &ThreadParentProcess->ActiveProcessLinks;
	(&ThreadParentProcess->ActiveProcessLinks)->Blink = PreviousList;
	CurrentList->Blink = &ThreadParentProcess->ActiveProcessLinks;
	DbgPrintEx(0, 0, "UnhideParentProcess() - Parent EPROCESS %p was not found in the list, reattached\n", ThreadParentProcess);
	return TRUE;
}


BOOL ProtectionFunctions::UnhideThreadInProcessThreadList(PETHREAD CheckedThread, PEPROCESS ThreadParentProcess) {
	PLIST_ENTRY InitialThreadEntry = (PLIST_ENTRY)((ULONG64)ThreadParentProcess + offsetof(_ACTKPROCESS, ThreadListHead));
	PLIST_ENTRY CurrentThreadEntry = InitialThreadEntry->Flink;
	PLIST_ENTRY PreviousThreadEntry = NULL;
	PLIST_ENTRY CheckedThreadEntry = NULL;
	PETHREAD CurrentThread = NULL;


	// Pass the first thread so the while() stop condition (pointer = list head) will not stop function:
	CurrentThread = (PETHREAD)((ULONG64)CurrentThreadEntry - LISTENTRY_ETHREAD_OFFSET);
	if ((ULONG64)CurrentThread == (ULONG64)CheckedThread) {
		return TRUE;  // Thread exists in process thread list FIRST
	}
	CurrentThreadEntry = CurrentThreadEntry->Flink;


	// Pass through the whole thread list of the host process to find checked thread:
	while (CurrentThreadEntry != NULL && (ULONG64)CurrentThreadEntry != (ULONG64)InitialThreadEntry) {
		CurrentThread = (PETHREAD)((ULONG64)CurrentThreadEntry - LISTENTRY_ETHREAD_OFFSET);
		if ((ULONG64)CurrentThread == (ULONG64)CheckedThread) {
			return TRUE;  // Thread exists in process thread list
		}
		CurrentThreadEntry = CurrentThreadEntry->Flink;
	}


	// Thread was unlinked from its EPROCESS's thread list - Attach it back:
	if (CurrentThreadEntry != NULL) {
		PreviousThreadEntry = CurrentThreadEntry->Blink;
		CheckedThreadEntry = (PLIST_ENTRY)((ULONG64)CheckedThread + LISTENTRY_ETHREAD_OFFSET);
		CheckedThreadEntry->Blink = PreviousThreadEntry;
		PreviousThreadEntry->Flink = CheckedThreadEntry;
		CurrentThreadEntry->Blink = CheckedThreadEntry;
		CheckedThreadEntry->Flink = CurrentThreadEntry;
		DbgPrintEx(0, 0, "UnhideThreadInProcessThreadList() - EHTREAD %p of parent EPROCESS %p was not found in the list, reattached\n",
			CheckedThread, ThreadParentProcess);
		return TRUE;
	}
	return FALSE;  // Error in list structure
}


BOOL ProtectionFunctions::FixHiddenOperations(PETHREAD CurrentThread) {
	PETHREAD LookupThread = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PEPROCESS ThreadParentProcess = *(PEPROCESS*)((ULONG64)CurrentThread + PARENT_PROCESS_OFFSET);
	BOOL ValidThread = FALSE;
	BOOL ValidProcess = FALSE;
	if (CurrentThread == NULL) {
		return FALSE;  // Nothing needs to be fixed, error in thread pointer
	}
	ValidThread = ProtectionFunctions::UnhideThreadInProcessThreadList(CurrentThread, ThreadParentProcess);
	ValidProcess = ProtectionFunctions::UnhideParentProcess((PACTEPROCESS)ThreadParentProcess);
	Status = PsLookupThreadByThreadId((HANDLE)PsGetThreadId(CurrentThread), &LookupThread);
	if (NT_SUCCESS(Status)) {
		if ((ULONG64)LookupThread == (ULONG64)CurrentThread) {
			return ValidThread && ValidProcess;  // Looked up thread matches the provided thread, cannot be hidden
		}
	}
	return FALSE;  // Lookup failed or looked up process is not the same
}