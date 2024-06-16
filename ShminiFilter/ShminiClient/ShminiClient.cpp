#include <iostream>
#include <Windows.h>
#define INFOPASS_IOCTL 0x40002000
#define INTERVALS_PER_SECOND 10000000
#define UNIX_EPOCH_IN_INTERVALS 11644473600ULL * INTERVALS_PER_SECOND


typedef struct _DETECTED_ENTRY {
	ULONG EntrySize;
	PVOID CallingProcess;
	char CallerContext[3];  // "KM" / "UM"
	PVOID CallerMdl;  // Descriptor module
	ULONG InformationSize;  // Size of information operated on
	char InformationType[5];  // "TEXT" / "BYTE" for now
	LARGE_INTEGER Timestamp;  // Timestamp
	/*
	PANSI_STRING OperationDescriptor;  // Special description for operation
	PANSI_STRING FileName;  // File name
	PANSI_STRING FileExtension;  // File extension
	PANSI_STRING ParentDirectory;  // Parent directory
	PANSI_STRING Share;  // Share string
	PANSI_STRING Stream;  // Stream string
	PANSI_STRING Volume;  // Volume string
	PANSI_STRING SpecialString;  // Special description for operation
	PANSI_STRING SecurityInfo;  // Security file information
	PANSI_STRING SharedInfo;  // Sharing file information
	*/
} DETECTED_ENTRY, * PDETECTED_ENTRY;


typedef struct _MINIFILTER_STARTINFO {
	ULONG64 EntryIdentifier;
	ULONG64 CopiedBytesCount;
	ULONG64 AccessViolationCount;
	ULONG64 CreatePreCount;
	ULONG64	ReadPreCount;
	ULONG64	WritePreCount;
	ULONG64	SetInfoPreCount;
	ULONG64	CleanupPreCount;
	ULONG64	FileSysCntlPreCount;
	ULONG64	DirControlPreCount;
	ULONG64	CreatePostCount;
	ULONG64	ReadPostCount;
	ULONG64	WritePostCount;
	ULONG64	SetInfoPostCount;
	ULONG64	CleanupPostCount;
	ULONG64	FileSysCntlPostCount;
	ULONG64	DirControlPostCount;
	ULONG64 GenericReadCount;
	ULONG64 GenericWriteCount;
	ULONG64 GenericExecuteCount;
	ULONG64 FileShareReadCount;
	ULONG64 FileShareWriteCount;
	ULONG64 FileShareDeleteCount;
	ULONG64 CRootCount;
	ULONG64 WindowsRootCount;
	ULONG64 System32RootCount;
	ULONG64 DriversRootCount;
	ULONG64 NtoskrnlCount;
	ULONG64	NtdllCount;
	ULONG64	User32dllCount;
	ULONG64 KernelModeCount;
	ULONG64 UserModeCount;
	ULONG64 TextCount;
	ULONG64 ByteCount;
	ULONG64 DetectedCount;
} MINIFILTER_STARTINFO, * PMINIFILTER_STARTINFO;


typedef struct _DRIVER_PARAMS {
	ULONG64 FirstParameter;  // Input = CurrentProcessId, output = allocation address
	ULONG64 SecondParameter;  // Input = dummy address for allocation, output = allocation size
} DRIVER_PARAMS, * PDRIVER_PARAMS;


// Global variables:
const char* MinifilterSymlink = "\\\\.\\ShminiFilter";
const char* TempDatabaseName = "database_update.txt";
HANDLE MinifilterHandle = INVALID_HANDLE_VALUE;


void FormatULONG64TimeToString(ULONG64 IntervalsSince1601, char* Buffer, SIZE_T BufferSize) {
	uint64_t SecondsSince1601 = IntervalsSince1601 / INTERVALS_PER_SECOND;
	uint64_t UnixTimeSeconds = SecondsSince1601 - (UNIX_EPOCH_IN_INTERVALS / INTERVALS_PER_SECOND);
	time_t TimeValue = (time_t)UnixTimeSeconds;
	struct tm TimeInfo = { 0 };
	gmtime_s(&TimeInfo, &TimeValue);
	strftime(Buffer, BufferSize, "%Y-%m-%d %H:%M:%S", &TimeInfo);
}


ULONG64 AnalyzeEntry(PUCHAR Buffer, ULONG64 EntryNumber) {
	char DatetimeString[20] = { 0 };
	DETECTED_ENTRY EntryStart = { 0 };
	ULONG64 BufferOffset = 0;
	if (Buffer == NULL) {
		return 0;  // Invalid parameter
	}
	printf("Entry number %llu:\n", EntryNumber);
	RtlCopyMemory(&EntryStart, Buffer, sizeof(EntryStart));
	printf("  Total entry size: %lu\n", EntryStart.EntrySize);
	printf("  Calling process: %p\n", EntryStart.CallingProcess);
	printf("  Calling process provided MDL: %p\n", EntryStart.CallerMdl);
	printf("  Information size: %lu\n", EntryStart.InformationSize);
	FormatULONG64TimeToString(EntryStart.Timestamp.QuadPart, DatetimeString, sizeof(DatetimeString));
	printf("  Timestamp: %llu (%s)\n", EntryStart.Timestamp.QuadPart, DatetimeString);
	printf("  Calling context: %s\n", EntryStart.CallerContext);
	printf("  Information type: %s\n", EntryStart.InformationType);
	BufferOffset += sizeof(EntryStart);
	printf("  Operation descriptor: %s\n", &Buffer[BufferOffset]);
	BufferOffset += (strlen((const char*)&Buffer[BufferOffset]) + 1);
	printf("  File name: %s\n", &Buffer[BufferOffset]);
	BufferOffset += (strlen((const char*)&Buffer[BufferOffset]) + 1);
	printf("  File extension: %s\n", &Buffer[BufferOffset]);
	BufferOffset += (strlen((const char*)&Buffer[BufferOffset]) + 1);
	printf("  Parent directory: %s\n", &Buffer[BufferOffset]);
	BufferOffset += (strlen((const char*)&Buffer[BufferOffset]) + 1);
	printf("  Share: %s\n", &Buffer[BufferOffset]);
	BufferOffset += (strlen((const char*)&Buffer[BufferOffset]) + 1);
	printf("  Stream: %s\n", &Buffer[BufferOffset]);
	BufferOffset += (strlen((const char*)&Buffer[BufferOffset]) + 1);
	printf("  Volume: %s\n", &Buffer[BufferOffset]);
	BufferOffset += (strlen((const char*)&Buffer[BufferOffset]) + 1);
	printf("  Special operation: %s\n", &Buffer[BufferOffset]);
	BufferOffset += (strlen((const char*)&Buffer[BufferOffset]) + 1);
	printf("  Security information: %s\n", &Buffer[BufferOffset]);
	BufferOffset += (strlen((const char*)&Buffer[BufferOffset]) + 1);
	printf("  Sharing information: %s\n", &Buffer[BufferOffset]);
	BufferOffset += (strlen((const char*)&Buffer[BufferOffset]) + 1);
	return BufferOffset;
}


void PrintInitialInformation(PMINIFILTER_STARTINFO StartInfo) {
	if (StartInfo != NULL) {
		printf("  EntryIdentifier: %llu\n", StartInfo->EntryIdentifier);
		printf("  CopiedBytesCount: %llu\n", StartInfo->CopiedBytesCount);
		printf("  AccessViolationCount: %llu\n", StartInfo->AccessViolationCount);
		printf("  CreatePreCount: %llu\n", StartInfo->CreatePreCount);
		printf("  ReadPreCount: %llu\n", StartInfo->ReadPreCount);
		printf("  WritePreCount: %llu\n", StartInfo->WritePreCount);
		printf("  SetInfoPreCount: %llu\n", StartInfo->SetInfoPreCount);
		printf("  CleanupPreCount: %llu\n", StartInfo->CleanupPreCount);
		printf("  FileSysCntlPreCount: %llu\n", StartInfo->FileSysCntlPreCount);
		printf("  DirControlPreCount: %llu\n", StartInfo->DirControlPreCount);
		printf("  CreatePostCount: %llu\n", StartInfo->CreatePostCount);
		printf("  ReadPostCount: %llu\n", StartInfo->ReadPostCount);
		printf("  WritePostCount: %llu\n", StartInfo->WritePostCount);
		printf("  SetInfoPostCount: %llu\n", StartInfo->SetInfoPostCount);
		printf("  CleanupPostCount: %llu\n", StartInfo->CleanupPostCount);
		printf("  FileSysCntlPostCount: %llu\n", StartInfo->FileSysCntlPostCount);
		printf("  DirControlPostCount: %llu\n", StartInfo->DirControlPostCount);
		printf("  GenericReadCount: %llu\n", StartInfo->GenericReadCount);
		printf("  GenericWriteCount: %llu\n", StartInfo->GenericWriteCount);
		printf("  GenericExecuteCount: %llu\n", StartInfo->GenericExecuteCount);
		printf("  FileShareReadCount: %llu\n", StartInfo->FileShareReadCount);
		printf("  FileShareWriteCount: %llu\n", StartInfo->FileShareWriteCount);
		printf("  FileShareDeleteCount: %llu\n", StartInfo->FileShareDeleteCount);
		printf("  CRootCount: %llu\n", StartInfo->CRootCount);
		printf("  WindowsRootCount: %llu\n", StartInfo->WindowsRootCount);
		printf("  System32RootCount: %llu\n", StartInfo->System32RootCount);
		printf("  DriversRootCount: %llu\n", StartInfo->DriversRootCount);
		printf("  NtoskrnlCount: %llu\n", StartInfo->NtoskrnlCount);
		printf("  NtdllCount: %llu\n", StartInfo->NtdllCount);
		printf("  User32dllCount: %llu\n", StartInfo->User32dllCount);
		printf("  KernelModeCount: %llu\n", StartInfo->KernelModeCount);
		printf("  UserModeCount: %llu\n", StartInfo->UserModeCount);
		printf("  TextCount: %llu\n", StartInfo->TextCount);
		printf("  ByteCount: %llu\n", StartInfo->ByteCount);
		printf("  DetectedCount: %llu\n", StartInfo->DetectedCount);
	}
}


void PrintUpdateInformation(PVOID Database, ULONG64 DatabaseSize) {
	MINIFILTER_STARTINFO InitialInfo = { 0 };
	ULONG64 EntryNumber = 0;
	ULONG64 DatabaseOffset = sizeof(InitialInfo);
	if (Database != NULL && DatabaseSize != 0) {
		printf("-----\nDATABASE UPDATE\n-----\n");
		RtlCopyMemory(&InitialInfo, Database, sizeof(InitialInfo));
		PrintInitialInformation(&InitialInfo);
		if (DatabaseSize == sizeof(InitialInfo)) {
			printf("  No special events detected while minifilter was up!\n");
		}
		else {
			while (DatabaseOffset < DatabaseSize) {
				DatabaseOffset += AnalyzeEntry((PUCHAR)Database + DatabaseOffset, EntryNumber);
				EntryNumber++;
			}
		}
	}
}


int main() {
	HANDLE DatabaseFile = INVALID_HANDLE_VALUE;
	DWORD BytesWritten = 0;
	DWORD OperatedBytes = 0;
	PVOID DummyAddress = NULL;
	DWORD LastError = 0;
	DWORD BytesReturned = 0;
	DRIVER_PARAMS DriverParams = { 0 };
	char UpdateCommand[MAX_PATH] = "python.exe DatabaseManipulator\\DbMan.py ";


	// Make sure that service is running:
	system("sc start ShminiFilter");


	// Open communication to driver:
	MinifilterHandle = CreateFileA(MinifilterSymlink, GENERIC_ALL, FILE_SHARE_DELETE | FILE_SHARE_WRITE |
		FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (MinifilterHandle == INVALID_HANDLE_VALUE || MinifilterHandle == NULL) {
		LastError = GetLastError();
		printf("[-] Failed to get handle to driver %s: %d\n", MinifilterSymlink, LastError);
		return FALSE;
	}
	printf("[+] Got handle to driver %s - %d\n", MinifilterSymlink, (DWORD)MinifilterHandle);


	// Send IOCTLs repeatedaly and add it to general database using python program:
	while (TRUE) {
		DriverParams.FirstParameter = GetCurrentProcessId();
		DriverParams.SecondParameter = (ULONG64)&DummyAddress;
		if (!DeviceIoControl(MinifilterHandle, INFOPASS_IOCTL, &DriverParams,
			sizeof(DriverParams), &DriverParams, sizeof(DriverParams), &BytesReturned, NULL) ||
			DriverParams.FirstParameter == NULL || DriverParams.SecondParameter == 0) {
			printf("[-] Failed to call driver %s for database update - %d\n", MinifilterSymlink,
				GetLastError());
			CloseHandle(MinifilterHandle);
			return FALSE;
		}
		printf("[+] Got updated database info from driver, calling program to parse update information\n");
		PrintUpdateInformation((PVOID)DriverParams.FirstParameter, DriverParams.SecondParameter);
		/*
		DatabaseFile = CreateFileA(TempDatabaseName, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (MinifilterHandle == INVALID_HANDLE_VALUE) {
			LastError = GetLastError();
			printf("[-] Failed to get handle to temporary database: %d\n", LastError);
			CloseHandle(MinifilterHandle);
			return FALSE;
		}
		if (!WriteFile(DatabaseFile, (PVOID)DriverParams.FirstParameter, DriverParams.SecondParameter,
			&BytesWritten, NULL) || BytesWritten != DriverParams.SecondParameter) {
			LastError = GetLastError();
			printf("[-] Failed to write into temporary database: %d\n", LastError);
			CloseHandle(DatabaseFile);
			CloseHandle(MinifilterHandle);
			return FALSE;
		}
		CloseHandle(DatabaseFile);
		strcat_s(UpdateCommand, TempDatabaseName);
		system(UpdateCommand);
		*/
		VirtualFree((PVOID)DriverParams.FirstParameter, 0, MEM_RELEASE);  // Free temporary database
		Sleep(30000);  // Sleep for 30 seconds
	}
	CloseHandle(MinifilterHandle);
	return 0;
}