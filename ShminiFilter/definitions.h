#pragma once
#include <fltkernel.h>
#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <windef.h>
#include <bcrypt.h>
#define INFOPASS_IOCTL 0x40002000
#define offsetof(s,m)   (size_t)( (ptrdiff_t)&(((s *)0)->m) )
#define AV_FLAG_PREFETCH  0x00000001


typedef struct _DETECTED_ENTRY {
	ULONG EntrySize;
	PEPROCESS CallingProcess;
	char CallerContext[3];  // "KM" / "UM"
	PMDL CallerMdl;  // Descriptor module
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


enum STARTINFO_OPERATION {
	EntryIdentifier,
	CopiedBytesCount,
	AccessViolationCount,
	CreatePreCount,
	ReadPreCount,
	WritePreCount,
	SetInfoPreCount,
	CleanupPreCount,
	FileSysCntlPreCount,
	DirControlPreCount,
	CreatePostCount,
	ReadPostCount,
	WritePostCount,
	SetInfoPostCount,
	CleanupPostCount,
	FileSysCntlPostCount,
	DirControlPostCount,
	GenericReadCount,
	GenericWriteCount,
	GenericExecuteCount,
	FileShareReadCount,
	FileShareWriteCount,
	FileShareDeleteCount,
	CRootCount,
	WindowsRootCount,
	System32RootCount,
	DriversRootCount,
	NtoskrnlCount,
	NtdllCount,
	User32dllCount,
	KernelModeCount,
	UserModeCount,
	TextCount,
	ByteCount,
	DetectedCount,
};


extern "C" __declspec(dllimport) NTSTATUS NTAPI ZwProtectVirtualMemory
(
	HANDLE ProcessHandle,
	PVOID * BaseAddress,
	PULONG ProtectSize,
	ULONG NewProtect,
	PULONG OldProtect
);


// FltMgr.sys IRP major codes for different operations:
#define IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION  ((UCHAR)-1)
#define IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION  ((UCHAR)-2)
#define IRP_MJ_ACQUIRE_FOR_MOD_WRITE                ((UCHAR)-3)
#define IRP_MJ_RELEASE_FOR_MOD_WRITE                ((UCHAR)-4)
#define IRP_MJ_ACQUIRE_FOR_CC_FLUSH                 ((UCHAR)-5)
#define IRP_MJ_RELEASE_FOR_CC_FLUSH                 ((UCHAR)-6)
#define IRP_MJ_NOTIFY_STREAM_FO_CREATION            ((UCHAR)-7)

#define IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE            ((UCHAR)-13)
#define IRP_MJ_NETWORK_QUERY_OPEN                   ((UCHAR)-14)
#define IRP_MJ_MDL_READ                             ((UCHAR)-15)
#define IRP_MJ_MDL_READ_COMPLETE                    ((UCHAR)-16)
#define IRP_MJ_PREPARE_MDL_WRITE                    ((UCHAR)-17)
#define IRP_MJ_MDL_WRITE_COMPLETE                   ((UCHAR)-18)
#define IRP_MJ_VOLUME_MOUNT                         ((UCHAR)-19)
#define IRP_MJ_VOLUME_DISMOUNT                      ((UCHAR)-20)


typedef struct _EX_FAST_REF {
	PVOID Object;
} EX_FAST_REF, * PEX_FAST_REF;

typedef struct _RTL_AVL_TREE {
	RTL_BALANCED_NODE* Root;
} RTL_AVL_TREE, * PRTL_AVL_TREE;

typedef struct _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES {
	RTL_AVL_TREE Tree;
	EX_PUSH_LOCK Lock;
} PS_DYNAMIC_ENFORCED_ADDRESS_RANGES, * PPS_DYNAMIC_ENFORCED_ADDRESS_RANGES;


typedef struct _KAFFINITY_EX {
	char Affinity[0xA8];
} KAFFINITY_EX, * PKAFFINITY_EX;


typedef struct _KSTACK_COUNT {
	ULONG State;
	ULONG StackCount;
} KSTACK_COUNT, * PKSTACK_COUNT;


typedef struct _MMSUPPORT_FLAGS {
	/*
	0x000 WorkingSetType   : Pos 0, 3 Bits
		+ 0x000 Reserved0 : Pos 3, 3 Bits
		+ 0x000 MaximumWorkingSetHard : Pos 6, 1 Bit
		+ 0x000 MinimumWorkingSetHard : Pos 7, 1 Bit
		+ 0x001 SessionMaster : Pos 0, 1 Bit
		+ 0x001 TrimmerState : Pos 1, 2 Bits
		+ 0x001 Reserved : Pos 3, 1 Bit
		+ 0x001 PageStealers : Pos 4, 4 Bits
		*/
	USHORT u1;
	UCHAR MemoryPriority;
	/*
	+ 0x003 WsleDeleted : Pos 0, 1 Bit
	+ 0x003 SvmEnabled : Pos 1, 1 Bit
	+ 0x003 ForceAge : Pos 2, 1 Bit
	+ 0x003 ForceTrim : Pos 3, 1 Bit
	+ 0x003 NewMaximum : Pos 4, 1 Bit
	+ 0x003 CommitReleaseState : Pos 5, 2 Bits
	*/
	UCHAR u2;
}MMSUPPORT_FLAGS, * PMMSUPPORT_FLAGS;

typedef struct _MMSUPPORT_INSTANCE {
	UINT NextPageColor;
	UINT PageFaultCount;
	UINT64 TrimmedPageCount;
	PVOID VmWorkingSetList;
	LIST_ENTRY WorkingSetExpansionLinks;
	UINT64 AgeDistribution[8];
	PVOID ExitOutswapGate;
	UINT64 MinimumWorkingSetSize;
	UINT64 WorkingSetLeafSize;
	UINT64 WorkingSetLeafPrivateSize;
	UINT64 WorkingSetSize;
	UINT64 WorkingSetPrivateSize;
	UINT64 MaximumWorkingSetSize;
	UINT64 PeakWorkingSetSize;
	UINT HardFaultCount;
	USHORT LastTrimStamp;
	USHORT PartitionId;
	UINT64 SelfmapLock;
	MMSUPPORT_FLAGS Flags;
} MMSUPPORT_INSTANCE, * PMMSUPPORT_INSTANCE;

typedef struct _MMSUPPORT_SHARED {
	long WorkingSetLock;
	long GoodCitizenWaiting;
	UINT64 ReleasedCommitDebt;
	UINT64 ResetPagesRepurposedCount;
	PVOID WsSwapSupport;
	PVOID CommitReleaseContext;
	PVOID AccessLog;
	UINT64 ChargedWslePages;
	UINT64 ActualWslePages;
	UINT64 WorkingSetCoreLock;
	PVOID ShadowMapping;
} MMSUPPORT_SHARED, * PMMSUPPORT_SHARED;

typedef struct _MMSUPPORT_FULL {
	MMSUPPORT_INSTANCE Instance;
	MMSUPPORT_SHARED Shared;
	UCHAR Padding[48];
} MMSUPPORT_FULL, * PMMSUPPORT_FULL;

typedef struct _ALPC_PROCESS_CONTEXT {
	char AlpcContext[0x20];
} ALPC_PROCESS_CONTEXT, * PALPC_PROCESS_CONTEXT;

typedef struct _JOBOBJECT_WAKE_FILTER {
	UINT HighEdgeFilter;
	UINT LowEdgeFilter;
} JOBOBJECT_WAKE_FILTER, * PJOBOBJECT_WAKE_FILTER;

typedef struct _PS_PROCESS_WAKE_INFORMATION {
	UINT64 NotificationChannel;
	UINT WakeCounters[7];
	JOBOBJECT_WAKE_FILTER WakeFilter;
	UINT NoWakeCounter;
} PS_PROCESS_WAKE_INFORMATION, * PPS_PROCESS_WAKE_INFORMATION;

typedef struct _PS_PROTECTION
{
	union
	{
		UCHAR Level;                                                        //0x0
		struct
		{
			UCHAR Type : 3;                                                   //0x0
			UCHAR Audit : 1;                                                  //0x0
			UCHAR Signer : 4;                                                 //0x0
		} ns1;
	};
} PS_PROTECTION, * PPS_PROTECTION;


#define true (__LINE__ % 10 != 0)

// Internal EPROCESS/KPROCESS of 1909:
typedef struct _ACTKPROCESS {
	DISPATCHER_HEADER Header;
	LIST_ENTRY ProfileListHead;
	UINT64 DirectoryTableBase;
	LIST_ENTRY ThreadListHead;
	UINT ProcessLock;
	UINT ProcessTimerDelay;
	UINT64 DeepFreezeStartTime;
	KAFFINITY_EX Affinity;
	UINT64 AffinityPadding[12];
	LIST_ENTRY ReadyListHead;
	SINGLE_LIST_ENTRY SwapListEntry;
	KAFFINITY_EX ActiveProcessors;
	UINT64 ActiveProcessorsPadding[12];
	/*
   AutoAlignment    : Pos 0; 1 Bit
   DisableBoost     : Pos 1; 1 Bit
   DisableQuantum   : Pos 2; 1 Bit
   DeepFreeze       : Pos 3; 1 Bit
   TimerVirtualization : Pos 4; 1 Bit
   CheckStackExtents : Pos 5; 1 Bit
   CacheIsolationEnabled : Pos 6; 1 Bit
   PpmPolicy        : Pos 7; 3 Bits
   ActiveGroupsMask : Pos 10; 20 Bits
   VaSpaceDeleted   : Pos 30; 1 Bit
   ReservedFlags    : Pos 31; 1 Bit
	*/
	int ProcessFlags;
	int ActiveGroupsMask;
	char BasePriority;
	char QuantumReset;
	char Visited;
	char Flags;
	USHORT ThreadSeed[20];
	USHORT ThreadSeedPadding[12];
	USHORT IdealProcessor[20];
	USHORT IdealProcessorPadding[12];
	USHORT IdealNode[20];
	USHORT IdealNodePadding[12];
	USHORT IdealGlobalNode;
	USHORT Spare1;
	KSTACK_COUNT StackCount;
	LIST_ENTRY ProcessListEntry;
	UINT64 CycleTime;
	UINT64 ContextSwitches;
	PVOID SchedulingGroup;
	UINT FreezeCount;
	UINT KernelTime;
	UINT UserTime;
	UINT ReadyTime;
	UINT64 UserDirectoryTableBase;
	UCHAR AddressPolicy;
	UCHAR Spare2[71];
	PVOID InstrumentationCallback;
	PVOID SecureState;
	PVOID KernelWaitTime;
	PVOID UserWaitTime;
	UINT64 EndPadding[8];
} ACTKPROCESS, * PACTKPROCESS;

typedef struct _ACTEPROCESS {
	ACTKPROCESS Pcb;
	EX_PUSH_LOCK ProcessLock;
	PVOID UniqueProcessId;
	LIST_ENTRY ActiveProcessLinks;
	EX_RUNDOWN_REF RundownProtect;
	UINT Flags2;
	/*
		+ 0x300 JobNotReallyActive : Pos 0, 1 Bit
		+ 0x300 AccountingFolded : Pos 1, 1 Bit
		+ 0x300 NewProcessReported : Pos 2, 1 Bit
		+ 0x300 ExitProcessReported : Pos 3, 1 Bit
		+ 0x300 ReportCommitChanges : Pos 4, 1 Bit
		+ 0x300 LastReportMemory : Pos 5, 1 Bit
		+ 0x300 ForceWakeCharge : Pos 6, 1 Bit
		+ 0x300 CrossSessionCreate : Pos 7, 1 Bit
		+ 0x300 NeedsHandleRundown : Pos 8, 1 Bit
		+ 0x300 RefTraceEnabled : Pos 9, 1 Bit
		+ 0x300 PicoCreated : Pos 10, 1 Bit
		+ 0x300 EmptyJobEvaluated : Pos 11, 1 Bit
		+ 0x300 DefaultPagePriority : Pos 12, 3 Bits
		+ 0x300 PrimaryTokenFrozen : Pos 15, 1 Bit
		+ 0x300 ProcessVerifierTarget : Pos 16, 1 Bit
		+ 0x300 RestrictSetThreadContext : Pos 17, 1 Bit
		+ 0x300 AffinityPermanent : Pos 18, 1 Bit
		+ 0x300 AffinityUpdateEnable : Pos 19, 1 Bit
		+ 0x300 PropagateNode : Pos 20, 1 Bit
		+ 0x300 ExplicitAffinity : Pos 21, 1 Bit
		+ 0x300 ProcessExecutionState : Pos 22, 2 Bits
		+ 0x300 EnableReadVmLogging : Pos 24, 1 Bit
		+ 0x300 EnableWriteVmLogging : Pos 25, 1 Bit
		+ 0x300 FatalAccessTerminationRequested : Pos 26, 1 Bit
		+ 0x300 DisableSystemAllowedCpuSet : Pos 27, 1 Bit
		+ 0x300 ProcessStateChangeRequest : Pos 28, 2 Bits
		+ 0x300 ProcessStateChangeInProgress : Pos 30, 1 Bit
		+ 0x300 InPrivate : Pos 31, 1 Bit
		*/
	UINT Flags;
	/*
+ 0x304 CreateReported : Pos 0, 1 Bit
+ 0x304 NoDebugInherit : Pos 1, 1 Bit
+ 0x304 ProcessExiting : Pos 2, 1 Bit
+ 0x304 ProcessDelete : Pos 3, 1 Bit
+ 0x304 ManageExecutableMemoryWrites : Pos 4, 1 Bit
+ 0x304 VmDeleted : Pos 5, 1 Bit
+ 0x304 OutswapEnabled : Pos 6, 1 Bit
+ 0x304 Outswapped : Pos 7, 1 Bit
+ 0x304 FailFastOnCommitFail : Pos 8, 1 Bit
+ 0x304 Wow64VaSpace4Gb : Pos 9, 1 Bit
+ 0x304 AddressSpaceInitialized : Pos 10, 2 Bits
+ 0x304 SetTimerResolution : Pos 12, 1 Bit
+ 0x304 BreakOnTermination : Pos 13, 1 Bit
+ 0x304 DeprioritizeViews : Pos 14, 1 Bit
+ 0x304 WriteWatch : Pos 15, 1 Bit
+ 0x304 ProcessInSession : Pos 16, 1 Bit
+ 0x304 OverrideAddressSpace : Pos 17, 1 Bit
+ 0x304 HasAddressSpace : Pos 18, 1 Bit
+ 0x304 LaunchPrefetched : Pos 19, 1 Bit
+ 0x304 Background : Pos 20, 1 Bit
+ 0x304 VmTopDown : Pos 21, 1 Bit
+ 0x304 ImageNotifyDone : Pos 22, 1 Bit
+ 0x304 PdeUpdateNeeded : Pos 23, 1 Bit
+ 0x304 VdmAllowed : Pos 24, 1 Bit
+ 0x304 ProcessRundown : Pos 25, 1 Bit
+ 0x304 ProcessInserted : Pos 26, 1 Bit
+ 0x304 DefaultIoPriority : Pos 27, 3 Bits
+ 0x304 ProcessSelfDelete : Pos 30, 1 Bit
+ 0x304 SetTimerResolutionLink : Pos 31, 1 Bit
*/
	LARGE_INTEGER CreateTime;
	UINT64 ProcessQuotaUsage[2];
	UINT64 ProcessQuotaPeak[2];
	UINT64 PeakVirtualSize;
	UINT64 VirtualSize;
	LIST_ENTRY SessionProcessLinks;
	PVOID ExceptionPortData;  // also defined as UINT64 ExceptionPortValue;
	/*
+ 0x350 ExceptionPortState : Pos 0, 3 Bits
*/
	EX_FAST_REF Token;
	UINT64 MmReserved;
	ULONG_PTR AddressCreationLock;
	ULONG_PTR PageTableCommitmentLock;
	PVOID RotateInProgress;
	PVOID ForkInProgress;
	PVOID CommitChargeJob;
	ULONG64 CloneRoot;
	UINT64 NumberOfPrivatePages;
	UINT64 NumberOfLockedPages;
	PVOID Win32Process;
	PVOID Job;
	PVOID SectionObject;
	PVOID SectionBaseAddress;
	UINT64 Cookie;
	PVOID WorkingSetWatch;
	PVOID Win32WindowStation;
	PVOID InheritedFromUniqueProcessId;
	UINT64 OwnerProcessId;
	PVOID Peb;
	PVOID Session;
	PVOID Spare1;
	PVOID QuotaBlock;
	PVOID ObjectTable;
	PVOID DebugPort;
	PVOID WoW64Process;
	PVOID DeviceMap;
	PVOID EtwDataSource;
	UINT64 PageDirectoryPte;
	PVOID ImageFilePointer;
	UCHAR ImageFileName[15];
	UCHAR PriorityClass;
	PVOID SecurityPort;
	ULONG64 SeAuditProcessCreationInfo;
	LIST_ENTRY JobLinks;
	PVOID HighestUserAddress;
	LIST_ENTRY ThreadListHead;
	UINT ActiveThreads;
	UINT ImagePathHash;
	UINT DefaultHardErrorProcessing;
	int LastThreadExitStatus;
	EX_FAST_REF PrefetchTrace;
	PVOID LockedPagesList;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	UINT64 CommitChargeLimit;
	UINT64 CommitCharge;
	UINT64 CommitChargePeak[6];
	MMSUPPORT_FULL Vm;

	LIST_ENTRY MmProcessLinks;
	UINT ModifiedPageCount;
	int ExitStatus;
	RTL_AVL_TREE VadRoot;
	PVOID VadHint;
	UINT64 VadCount;
	UINT64 VadPhysicalPages;
	UINT64 VadPhysicalPagesLimit;
	ALPC_PROCESS_CONTEXT AlpcContext;
	LIST_ENTRY TimerResolutionLink;
	PVOID TimerResolutionStackRecord;
	UINT RequestedTimerResolution;
	UINT SmallestTimerResolution;
	LARGE_INTEGER ExitTime;
	PVOID InvertedFunctionTable;
	EX_PUSH_LOCK InvertedFunctionTableLock;
	UINT ActiveThreadsHighWatermark;
	UINT LargePrivateVadCount;
	EX_PUSH_LOCK ThreadListLock;
	PVOID WnfContext;
	PVOID ServerSilo;
	UCHAR SignatureLevel;
	UCHAR SectionSignatureLevel;
	PS_PROTECTION Protection;
	union {
		UCHAR HangCount;
		UCHAR GhostCount;
		UCHAR PrefilterException;
	};
	union {
		UINT Flags3;
		UINT Minimal;
		UINT ReplacingPageRoot;
		UINT Crashed;
		UINT JobVadsAreTracked;
		UINT VadTrackingDisabled;
		UINT AuxiliaryProcess;
		UINT SubsystemProcess;
		UINT IndirectCpuSets;
		UINT RelinquishedCommit;
		UINT HighGraphicsPriority;
		UINT CommitFailLogged;
		UINT ReserveFailLogged;
		UINT SystemProcess;
		UINT HideImageBaseAddresses;
		UINT AddressPolicyFrozen;
		UINT ProcessFirstResume;
		UINT ForegroundExternal;
		UINT ForegroundSystem;
		UINT HighMemoryPriority;
		UINT EnableProcessSuspendResumeLogging;
		UINT EnableThreadSuspendResumeLogging;
		UINT SecurityDomainChanged;
		UINT SecurityFreezeComplete;
		UINT VmProcessorHost;
		UINT VmProcessorHostTransition;
		UINT AltSyscall;
		UINT TimerResolutionIgnore;
		UINT DisallowUserTerminate;
	};
	INT64 DeviceAsid;
	PVOID SvmData;
	EX_PUSH_LOCK SvmProcessLock;
	UINT64 SvmLock;
	LIST_ENTRY SvmProcessDeviceListHead;
	UINT64 LastFreezeInterruptTime;
	PVOID DiskCounters;
	PVOID PicoContext;
	PVOID EnclaveTable;
	UINT64 EnclaveNumber;
	EX_PUSH_LOCK EnclaveLock;
	UINT64 HighPriorityFaultsAllowed;
	PVOID EnergyContext;
	PVOID VmContext;
	UINT64 SequenceNumber;
	UINT64 CreateInterruptTime;
	UINT64 CreateUnbiasedInterruptTime;
	UINT64 TotalUnbiasedFrozenTime;
	UINT64 LastAppStateUpdateTime;
	union {
		ULONG64 LastAppStateUptime;
		ULONG64 LastAppState;
	};
	UINT64 SharedCommitCharge;
	EX_PUSH_LOCK SharedCommitLock;
	LIST_ENTRY SharedCommitLinks;
	union {
		UINT64 AllowedCpuSets;
		UINT64 AllowedCpuSetsIndirect;
	};
	union {
		UINT64 DefaultCpuSets;
		UINT64 DefaultCpuSetsIndirect;
	};
	PVOID DiskIoAttribution;
	PVOID DxgProcess;
	UINT64 Win32KFilterSet;
	ULONG64 ProcessTimerDelay;
	UINT KTimerSets;
	UINT KTimer2Sets;
	UINT64 ThreadTimerSets;
	UINT64 VirtualTimerListLock;
	LIST_ENTRY VirtualTimerListHead;
	union {
		WNF_STATE_NAME WakeChannel;
		PS_PROCESS_WAKE_INFORMATION WakeInfo;
	};
	union {
		UINT MitigationFlags;
		UINT MitigationFlagsValues;
	};
	union {
		UINT MitigationFlags2;
		UINT MitigationFlags2Values;
	};
	PVOID PartitionObject;
	UINT64 SecurityDomain;
	UINT64 ParentSecurityDomain;
	PVOID CoverageSamplerContext;
	PVOID MmHotPatchContext;
	RTL_AVL_TREE DynamicEHContinuationTargetsTree;
	EX_PUSH_LOCK DynamicEHContinuationTargetsLock;
	PS_DYNAMIC_ENFORCED_ADDRESS_RANGES DynamicEnforcedCetCompatibleRanges;
	UINT64 DisabledComponentFlags;
	UINT64 PathRedirectionHashes;
	union {
		ULONG MitigationFlags3[4];
		ULONG MitigationFlags3Values[4];
	};
} ACTEPROCESS, * PACTEPROCESS;