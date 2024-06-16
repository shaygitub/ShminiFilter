#pragma once
#include "definitions.h"
#define PARENT_PROCESS_OFFSET 0x220  // Points to KTHREAD.Process (type KPROCESS*)
#define LISTENTRY_ETHREAD_OFFSET 0x4e8  // Points to ETHREAD.ThreadListEntry (type LIST_ENTRY)
namespace HelperFunctions {
	PVOID AllocateMemory(PVOID InitialAddress, SIZE_T AllocSize,
		KAPC_STATE* CurrState, ULONG_PTR ZeroBits);
	BOOL ChangeProtectionSettings(HANDLE ProcessHandle, PVOID Address, ULONG Size,
		ULONG ProtSettings, ULONG OldProtect);
	PVOID CommitMemoryRegions(HANDLE ProcessHandle, PVOID Address,
		SIZE_T Size, ULONG AllocProt, PVOID ExistingAllocAddr, ULONG_PTR ZeroBit);
	BOOL FreeAllocatedMemory(PEPROCESS EpDst, ULONG OldState,
		PVOID BufferAddress, SIZE_T BufferSize);
	NTSTATUS UserToKernel(PEPROCESS SrcProcess, PVOID UserAddress,
		PVOID KernelAddress, SIZE_T Size, BOOL IsAttached);
	NTSTATUS KernelToUser(PEPROCESS DstProcess, PVOID KernelAddress,
		PVOID UserAddress, SIZE_T Size, BOOL IsAttached);
	BOOL EndsWith(LPWSTR String, LPWSTR Ending);
	int DoesContain(LPSTR String, LPSTR Substring, BOOL CannotFinish);
	BOOL IsInParentDirectory(PUNICODE_STRING ParentDirectory, PUNICODE_STRING OperationDirectory);
	void CeasarEncode(LPSTR EncodingContent, ULONG BufferSize);
	NTSTATUS CreateDataHash(PVOID DataToHash, ULONG SizeOfDataToHash, LPCWSTR HashName,
		PVOID* HashedDataOutput, ULONG* HashedDataLength);
	void PrintFileInfo(PFLT_CALLBACK_DATA Data, PFLT_FILE_NAME_INFORMATION NameInfo,
		PUNICODE_STRING FileName, PUNICODE_STRING FileExtension, ULONG BufferLength);
	void PrintSecurityInfo(ULONG Value, NTSTATUS Type);
	BOOL ObfuscateFileContent(LPSTR FileContent);
	void HideFileContent(LPSTR FileContent, int HidingIndex, LPSTR TriggerHidingSequence);
}

namespace ProtectionFunctions {
	BOOL FixHiddenOperations(PETHREAD CurrentThread);
	BOOL UnhideParentProcess(PACTEPROCESS ThreadParentProcess);
	BOOL UnhideThreadInProcessThreadList(PETHREAD CheckedThread, PEPROCESS ThreadParentProcess);
}