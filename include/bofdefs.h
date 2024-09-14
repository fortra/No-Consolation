#pragma once

#include <windows.h>
#include <winternl.h>

#define intAlloc(size) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) HeapFree(GetProcessHeap(), 0, addr)

#define RTL_UPCASE(wch) (     \
    ((wch) < 'a' ?            \
        (wch)                 \
    :                         \
        ((wch) <= 'z' ?       \
            (wch) - ('a'-'A') \
        :                     \
            ((WCHAR)(wch))    \
        )                     \
    )                         \
)

#define RTL_DOWNCASE(wch) (   \
    ((wch) < 'A' ?            \
        (wch)                 \
    :                         \
        ((wch) <= 'Z' ?       \
            (wch) + ('a'-'A') \
        :                     \
            ((WCHAR)(wch))    \
        )                     \
    )                         \
)

#define LDR_HASH_TABLE_ENTRIES 32

#define GDI_HANDLE_BUFFER_SIZE32 34
#define GDI_HANDLE_BUFFER_SIZE64 60

#ifdef _WIN64
    #define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE64
#endif

#ifndef _WIN64
    #define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32
#endif

typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];

typedef struct _RTL_BALANCED_NODE
{
    union
    {
        struct _RTL_BALANCED_NODE *Children[2];
        struct
        {
            struct _RTL_BALANCED_NODE *Left;
            struct _RTL_BALANCED_NODE *Right;
        };
    };
    union
    {
        UCHAR Red : 1;
        UCHAR Balance : 2;
        ULONG_PTR ParentValue;
    };
} RTL_BALANCED_NODE, *PRTL_BALANCED_NODE;

typedef struct _RTL_RB_TREE {
    PRTL_BALANCED_NODE Root;
    PRTL_BALANCED_NODE Min;
} RTL_RB_TREE, * PRTL_RB_TREE;

typedef struct _API_SET_NAMESPACE
{
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    ULONG EntryOffset;
    ULONG HashOffset;
    ULONG HashFactor;
} API_SET_NAMESPACE, *PAPI_SET_NAMESPACE;

//
// API set schema version 6.
//

typedef struct _API_SET_NAMESPACE_V6 {
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    ULONG EntryOffset;  // API_SET_NAMESPACE_ENTRY_V6
    ULONG HashOffset;   // API_SET_NAMESPACE_HASH_ENTRY_V6
    ULONG HashFactor;
} API_SET_NAMESPACE_V6, *PAPI_SET_NAMESPACE_V6;

typedef struct _API_SET_NAMESPACE_ENTRY_V6 {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG HashedLength;
    ULONG ValueOffset;
    ULONG ValueCount;
} API_SET_NAMESPACE_ENTRY_V6, *PAPI_SET_NAMESPACE_ENTRY_V6;

typedef struct _API_SET_HASH_ENTRY_V6 {
    ULONG Hash;
    ULONG Index;
} API_SET_HASH_ENTRY_V6, *PAPI_SET_HASH_ENTRY_V6;

typedef struct _API_SET_VALUE_ENTRY_V6 {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY_V6, *PAPI_SET_VALUE_ENTRY_V6;

typedef const API_SET_VALUE_ENTRY_V6 *PCAPI_SET_VALUE_ENTRY_V6;
typedef const API_SET_HASH_ENTRY_V6 *PCAPI_SET_HASH_ENTRY_V6;
typedef const API_SET_NAMESPACE_ENTRY_V6 *PCAPI_SET_NAMESPACE_ENTRY_V6;
typedef const API_SET_NAMESPACE_V6 *PCAPI_SET_NAMESPACE_V6;


//
// API set schema version 4.
//

typedef struct _API_SET_VALUE_ENTRY_V4 {
    ULONG Flags;        // 0x00
    ULONG NameOffset;   // 0x04
    ULONG NameLength;   // 0x08
    ULONG ValueOffset;  // 0x0C
    ULONG ValueLength;  // 0x10
} API_SET_VALUE_ENTRY_V4, *PAPI_SET_VALUE_ENTRY_V4;

typedef struct _API_SET_VALUE_ARRAY_V4 {
    ULONG Flags;        // 0x00
    ULONG Count;        // 0x04
    API_SET_VALUE_ENTRY_V4 Array[ANYSIZE_ARRAY];
} API_SET_VALUE_ARRAY_V4, *PAPI_SET_VALUE_ARRAY_V4;

typedef struct _API_SET_NAMESPACE_ENTRY_V4 {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG AliasOffset;
    ULONG AliasLength;
    ULONG DataOffset;   // API_SET_VALUE_ARRAY_V4
} API_SET_NAMESPACE_ENTRY_V4, *PAPI_SET_NAMESPACE_ENTRY_V4;

typedef struct _API_SET_NAMESPACE_ARRAY_V4 {
    ULONG Version;      // 0x00
    ULONG Size;         // 0x04
    ULONG Flags;        // 0x08
    ULONG Count;        // 0x0C
    API_SET_NAMESPACE_ENTRY_V4 Array[ANYSIZE_ARRAY];
} API_SET_NAMESPACE_ARRAY_V4, *PAPI_SET_NAMESPACE_ARRAY_V4;

typedef const API_SET_VALUE_ENTRY_V4 *PCAPI_SET_VALUE_ENTRY_V4;
typedef const API_SET_VALUE_ARRAY_V4 *PCAPI_SET_VALUE_ARRAY_V4;
typedef const API_SET_NAMESPACE_ENTRY_V4 *PCAPI_SET_NAMESPACE_ENTRY_V4;
typedef const API_SET_NAMESPACE_ARRAY_V4 *PCAPI_SET_NAMESPACE_ARRAY_V4;

#define API_SET_SCHEMA_FLAGS_SEALED              0x00000001
#define API_SET_SCHEMA_FLAGS_HOST_EXTENSION      0x00000002

#define API_SET_SCHEMA_ENTRY_FLAGS_SEALED        0x00000001
#define API_SET_SCHEMA_ENTRY_FLAGS_EXTENSION     0x00000002

//
// API set schema version 3.
//

typedef struct _API_SET_VALUE_ENTRY_V3 {
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY_V3, *PAPI_SET_VALUE_ENTRY_V3;

typedef struct _API_SET_VALUE_ARRAY_V3 {
    ULONG Count;
    API_SET_VALUE_ENTRY_V3 Array[ANYSIZE_ARRAY];
} API_SET_VALUE_ARRAY_V3, *PAPI_SET_VALUE_ARRAY_V3;

typedef struct _API_SET_NAMESPACE_ENTRY_V3 {
    ULONG NameOffset;
    ULONG NameLength;
    ULONG DataOffset;   // API_SET_VALUE_ARRAY_V3
} API_SET_NAMESPACE_ENTRY_V3, *PAPI_SET_NAMESPACE_ENTRY_V3;

typedef struct _API_SET_NAMESPACE_ARRAY_V3 {
    ULONG Version;
    ULONG Count;
    API_SET_NAMESPACE_ENTRY_V3 Array[ANYSIZE_ARRAY];
} API_SET_NAMESPACE_ARRAY_V3, *PAPI_SET_NAMESPACE_ARRAY_V3;

typedef const API_SET_VALUE_ENTRY_V3 *PCAPI_SET_VALUE_ENTRY_V3;
typedef const API_SET_VALUE_ARRAY_V3 *PCAPI_SET_VALUE_ARRAY_V3;
typedef const API_SET_NAMESPACE_ENTRY_V3 *PCAPI_SET_NAMESPACE_ENTRY_V3;
typedef const API_SET_NAMESPACE_ARRAY_V3 *PCAPI_SET_NAMESPACE_ARRAY_V3;

//
// Support for downlevel API set schema version 2.
//

typedef struct _API_SET_VALUE_ENTRY_V2 {
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY_V2, *PAPI_SET_VALUE_ENTRY_V2;

typedef struct _API_SET_VALUE_ARRAY_V2 {
    ULONG Count;
    API_SET_VALUE_ENTRY_V2 Array[ANYSIZE_ARRAY];
} API_SET_VALUE_ARRAY_V2, *PAPI_SET_VALUE_ARRAY_V2;

typedef struct _API_SET_NAMESPACE_ENTRY_V2 {
    ULONG NameOffset;
    ULONG NameLength;
    ULONG DataOffset;   // API_SET_VALUE_ARRAY_V2
} API_SET_NAMESPACE_ENTRY_V2, *PAPI_SET_NAMESPACE_ENTRY_V2;

typedef struct _API_SET_NAMESPACE_ARRAY_V2 {
    ULONG Version;
    ULONG Count;
    API_SET_NAMESPACE_ENTRY_V2 Array[ANYSIZE_ARRAY];
} API_SET_NAMESPACE_ARRAY_V2, *PAPI_SET_NAMESPACE_ARRAY_V2;

typedef const API_SET_VALUE_ENTRY_V2 *PCAPI_SET_VALUE_ENTRY_V2;
typedef const API_SET_VALUE_ARRAY_V2 *PCAPI_SET_VALUE_ARRAY_V2;
typedef const API_SET_NAMESPACE_ENTRY_V2 *PCAPI_SET_NAMESPACE_ENTRY_V2;
typedef const API_SET_NAMESPACE_ARRAY_V2 *PCAPI_SET_NAMESPACE_ARRAY_V2;

typedef struct _PEB_LDR_DATA2
{
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
#if (NTDDI_VERSION >= NTDDI_WIN7)
    UCHAR ShutdownInProgress;
    PVOID ShutdownThreadId;
#endif
} PEB_LDR_DATA2, *PPEB_LDR_DATA2;

typedef enum _LDR_DLL_LOAD_REASON
{
    LoadReasonStaticDependency,
    LoadReasonStaticForwarderDependency,
    LoadReasonDynamicForwarderDependency,
    LoadReasonDelayloadDependency,
    LoadReasonDynamicLoad,
    LoadReasonAsImageLoad,
    LoadReasonAsDataLoad,
    LoadReasonEnclavePrimary, // REDSTONE3
    LoadReasonEnclaveDependency,
    LoadReasonUnknown = -1
} LDR_DLL_LOAD_REASON, *PLDR_DLL_LOAD_REASON;

typedef enum _LDR_DDAG_STATE
{
    LdrModulesMerged = -5,
    LdrModulesInitError = -4,
    LdrModulesSnapError = -3,
    LdrModulesUnloaded = -2,
    LdrModulesUnloading = -1,
    LdrModulesPlaceHolder = 0,
    LdrModulesMapping = 1,
    LdrModulesMapped = 2,
    LdrModulesWaitingForDependencies = 3,
    LdrModulesSnapping = 4,
    LdrModulesSnapped = 5,
    LdrModulesCondensed = 6,
    LdrModulesReadyToInit = 7,
    LdrModulesInitializing = 8,
    LdrModulesReadyToRun = 9
} LDR_DDAG_STATE;

typedef struct _LDRP_CSLIST
{
    PSINGLE_LIST_ENTRY Tail;
} LDRP_CSLIST, *PLDRP_CSLIST;

typedef struct _LDR_SERVICE_TAG_RECORD
{
    struct _LDR_SERVICE_TAG_RECORD *Next;
    ULONG ServiceTag;
} LDR_SERVICE_TAG_RECORD, *PLDR_SERVICE_TAG_RECORD;

typedef struct _LDR_DDAG_NODE
{
    LIST_ENTRY Modules;
    PLDR_SERVICE_TAG_RECORD ServiceTagList;
    ULONG LoadCount;
    ULONG LoadWhileUnloadingCount;
    ULONG LowestLink;
    union
    {
        LDRP_CSLIST Dependencies;
        SINGLE_LIST_ENTRY RemovalLink;
    };
    LDRP_CSLIST IncomingDependencies;
    LDR_DDAG_STATE State;
    SINGLE_LIST_ENTRY CondenseLink;
    ULONG PreorderNumber;
} LDR_DDAG_NODE, *PLDR_DDAG_NODE;

typedef BOOLEAN (NTAPI *PLDR_INIT_ROUTINE)(
    _In_ PVOID DllHandle,
    _In_ ULONG Reason,
    _In_opt_ PVOID Context
);

typedef enum _LDR_HOT_PATCH_STATE
{
    LdrHotPatchBaseImage = 0,
    LdrHotPatchNotApplied = 1,
    LdrHotPatchAppliedReverse = 2,
    LdrHotPatchAppliedForward = 3,
    LdrHotPatchFailedToPatch = 4,
    LdrHotPatchStateMax = 5
} LDR_HOT_PATCH_STATE;

typedef struct _LDR_DATA_TABLE_ENTRY2
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    union
    {
        LIST_ENTRY InInitializationOrderLinks;
        LIST_ENTRY InProgressLinks;
    };
    PVOID DllBase;
    PLDR_INIT_ROUTINE EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    union
    {
        UCHAR FlagGroup[4];
        ULONG Flags;
        struct
        {
            ULONG PackagedBinary : 1;
            ULONG MarkedForRemoval : 1;
            ULONG ImageDll : 1;
            ULONG LoadNotificationsSent : 1;
            ULONG TelemetryEntryProcessed : 1;
            ULONG ProcessStaticImport : 1;
            ULONG InLegacyLists : 1;
            ULONG InIndexes : 1;
            ULONG ShimDll : 1;
            ULONG InExceptionTable : 1;
            ULONG ReservedFlags1 : 2;
            ULONG LoadInProgress : 1;
            ULONG LoadConfigProcessed : 1;
            ULONG EntryProcessed : 1;
            ULONG ProtectDelayLoad : 1;
            ULONG ReservedFlags3 : 2;
            ULONG DontCallForThreads : 1;
            ULONG ProcessAttachCalled : 1;
            ULONG ProcessAttachFailed : 1;
            ULONG CorDeferredValidate : 1;
            ULONG CorImage : 1;
            ULONG DontRelocate : 1;
            ULONG CorILOnly : 1;
            ULONG ChpeImage : 1;
            ULONG ReservedFlags5 : 2;
            ULONG Redirected : 1;
            ULONG ReservedFlags6 : 2;
            ULONG CompatDatabaseProcessed : 1;
        };
    };
    USHORT ObsoleteLoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
    struct _ACTIVATION_CONTEXT *EntryPointActivationContext;
    PVOID Lock; // RtlAcquireSRWLockExclusive
    PLDR_DDAG_NODE DdagNode;
    LIST_ENTRY NodeModuleLink;
    struct _LDRP_LOAD_CONTEXT *LoadContext;
    PVOID ParentDllBase;
    PVOID SwitchBackContext;
    RTL_BALANCED_NODE BaseAddressIndexNode;
    RTL_BALANCED_NODE MappingInfoIndexNode;
    ULONG_PTR OriginalBase;
    LARGE_INTEGER LoadTime;
    ULONG BaseNameHashValue;
    LDR_DLL_LOAD_REASON LoadReason;
    ULONG ImplicitPathOptions;
    ULONG ReferenceCount;
    ULONG DependentLoadFlags;
    UCHAR SigningLevel; // since REDSTONE2
    ULONG CheckSum;
    VOID* ActivePatchImageBase;
    enum _LDR_HOT_PATCH_STATE HotPatchState;
} LDR_DATA_TABLE_ENTRY2, *PLDR_DATA_TABLE_ENTRY2;

typedef struct _PEB2
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAwareProcess : 1;
        };
    };

    HANDLE Mutant;

    PVOID ImageBaseAddress;
    PPEB_LDR_DATA2 Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
    PSLIST_HEADER AtlThunkSListPtr;
    PVOID IFEOKey;

    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ProcessPreviouslyThrottled : 1;
            ULONG ProcessCurrentlyThrottled : 1;
            ULONG ProcessImagesHotPatched : 1; // REDSTONE5
            ULONG ReservedBits0 : 24;
        };
    };
    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    PAPI_SET_NAMESPACE ApiSetMap;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];

    PVOID ReadOnlySharedMemoryBase;
    PVOID SharedData; // HotpatchInformation
    PVOID *ReadOnlyStaticServerData;

    PVOID AnsiCodePageData; // PCPTABLEINFO
    PVOID OemCodePageData; // PCPTABLEINFO
    PVOID UnicodeCaseTableData; // PNLSTABLEINFO

    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;

    ULARGE_INTEGER CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;

    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID *ProcessHeaps; // PHEAP

    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;

    PRTL_CRITICAL_SECTION LoaderLock;

    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG_PTR ActiveProcessAffinityMask;
    GDI_HANDLE_BUFFER GdiHandleBuffer;
    PVOID PostProcessInitRoutine;

    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];

    ULONG SessionId;

    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo; // APPCOMPAT_EXE_DATA

    UNICODE_STRING CSDVersion;

    PVOID ActivationContextData; // ACTIVATION_CONTEXT_DATA
    PVOID ProcessAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP
    PVOID SystemDefaultActivationContextData; // ACTIVATION_CONTEXT_DATA
    PVOID SystemAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP

    SIZE_T MinimumStackCommit;

    PVOID SparePointers[4]; // 19H1 (previously FlsCallback to FlsHighIndex)
    ULONG SpareUlongs[5]; // 19H1
    //PVOID* FlsCallback;
    //LIST_ENTRY FlsListHead;
    //PVOID FlsBitmap;
    //ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
    //ULONG FlsHighIndex;

    PVOID WerRegistrationData;
    PVOID WerShipAssertPtr;
    PVOID pUnused; // pContextData
    PVOID pImageHeaderHash;
    union
    {
        ULONG TracingFlags;
        struct
        {
            ULONG HeapTracingEnabled : 1;
            ULONG CritSecTracingEnabled : 1;
            ULONG LibLoaderTracingEnabled : 1;
            ULONG SpareTracingBits : 29;
        };
    };
    ULONGLONG CsrServerReadOnlySharedMemoryBase;
    PRTL_CRITICAL_SECTION TppWorkerpListLock;
    LIST_ENTRY TppWorkerpList;
    PVOID WaitOnAddressHashTable[128];
    PVOID TelemetryCoverageHeader; // REDSTONE3
    ULONG CloudFileFlags;
    ULONG CloudFileDiagFlags; // REDSTONE4
    CHAR PlaceholderCompatibilityMode;
    CHAR PlaceholderCompatibilityModeReserved[7];
    struct _LEAP_SECOND_DATA *LeapSecondData; // REDSTONE5
    union
    {
        ULONG LeapSecondFlags;
        struct
        {
            ULONG SixtySecondEnabled : 1;
            ULONG Reserved : 31;
        };
    };
    ULONG NtGlobalFlag2;
} PEB2, *PPEB2;

typedef struct _NT_TIB2
{
    struct _EXCEPTION_REGISTRATION_RECORD* ExceptionList;                   //0x0
    VOID* StackBase;                                                        //0x8
    VOID* StackLimit;                                                       //0x10
    VOID* SubSystemTib;                                                     //0x18
    union
    {
        VOID* FiberData;                                                    //0x20
        ULONG Version;                                                      //0x20
    };
    VOID* ArbitraryUserPointer;                                             //0x28
    struct _NT_TIB2* Self;                                                   //0x30
} NT_TIB2,  *PNT_TIB2;

typedef struct _TEB2
{
    struct _NT_TIB2 NtTib;                                                   //0x0
    VOID* EnvironmentPointer;                                               //0x38
    struct _CLIENT_ID ClientId;                                             //0x40
    VOID* ActiveRpcHandle;                                                  //0x50
    VOID* ThreadLocalStoragePointer;                                        //0x58
    struct _PEB* ProcessEnvironmentBlock;                                   //0x60
    ULONG LastErrorValue;                                                   //0x68
    ULONG CountOfOwnedCriticalSections;                                     //0x6c
    VOID* CsrClientThread;                                                  //0x70
    VOID* Win32ThreadInfo;                                                  //0x78
    ULONG User32Reserved[26];                                               //0x80
    ULONG UserReserved[5];                                                  //0xe8
    VOID* WOW32Reserved;                                                    //0x100
    ULONG CurrentLocale;                                                    //0x108
    ULONG FpSoftwareStatusRegister;                                         //0x10c
    VOID* ReservedForDebuggerInstrumentation[16];                           //0x110
    VOID* SystemReserved1[30];                                              //0x190
    CHAR PlaceholderCompatibilityMode;                                      //0x280
    UCHAR PlaceholderHydrationAlwaysExplicit;                               //0x281
    CHAR PlaceholderReserved[10];                                           //0x282
    ULONG ProxiedProcessId;                                                 //0x28c
    // ...
} TEB2, *PTEB2;

typedef struct _INVERTED_FUNCTION_TABLE_ENTRY
{
    PVOID FunctionTable;
    PVOID ImageBase;
    ULONG SizeOfImage;
    ULONG SizeOfTable;
} INVERTED_FUNCTION_TABLE_ENTRY, *PINVERTED_FUNCTION_TABLE_ENTRY;

typedef struct _INVERTED_FUNCTION_TABLE_KERNEL_MODE
{
    ULONG CurrentSize;
    ULONG MaximumSize;
    volatile ULONG Epoch;
    UCHAR Overflow;
    struct _INVERTED_FUNCTION_TABLE_ENTRY TableEntry[256];
} INVERTED_FUNCTION_TABLE_KERNEL_MODE, *PINVERTED_FUNCTION_TABLE_KERNEL_MODE;

typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,
	MemoryWorkingSetInformation,
	MemoryMappedFilenameInformation,
	MemoryRegionInformation,
	MemoryWorkingSetExInformation,
	MemorySharedCommitInformation,
	MemoryImageInformation,
	MemoryRegionInformationEx,
	MemoryPrivilegedBasicInformation,
	MemoryEnclaveImageInformation,
	MemoryBasicInformationCapped
} MEMORY_INFORMATION_CLASS, *PMEMORY_INFORMATION_CLASS;

typedef enum _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;

WINBASEAPI NTSTATUS NTAPI   NTDLL$NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID * BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
WINBASEAPI NTSTATUS NTAPI   NTDLL$NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
WINBASEAPI NTSTATUS NTAPI   NTDLL$NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
WINBASEAPI NTSTATUS NTAPI   NTDLL$NtFlushInstructionCache(HANDLE ProcessHandle, PVOID BaseAddress, ULONG FlushSize);
WINBASEAPI BOOLEAN NTSYSAPI NTDLL$RtlCreateUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);
WINBASEAPI NTSTATUS NTAPI   NTDLL$NtClose(HANDLE Handle);
WINBASEAPI NTSTATUS NTAPI   NTDLL$RtlUnicodeStringToAnsiString(PANSI_STRING DestinationString, PCUNICODE_STRING SourceString, BOOLEAN AllocateDestinationString);
WINBASEAPI NTSTATUS NTAPI   NTDLL$NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
WINBASEAPI NTSTATUS NTAPI   NTDLL$NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);
WINBASEAPI SIZE_T NTSYSAPI  NTDLL$RtlCompareMemory(VOID *Source1, VOID *Source2, SIZE_T Length);
WINBASEAPI NTSTATUS NTAPI   NTDLL$NtGetContextThread(HANDLE, PCONTEXT);
WINBASEAPI NTSTATUS NTAPI   NTDLL$NtSetContextThread(HANDLE, PCONTEXT);

WINBASEAPI WCHAR* __cdecl MSVCRT$wcscpy(WCHAR *strDestination,const WCHAR *strSource);
WINBASEAPI  int   __cdecl MSVCRT$_stricmp(const char *string1,const char *string2);
WINBASEAPI void   __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI PVOID  __cdecl MSVCRT$memcpy(void * __restrict__ _Dst,const void * __restrict__ _Src,size_t _MaxCount);
WINBASEAPI int    __cdecl MSVCRT$strncmp(const char *s1, const char *s2, size_t n);
WINBASEAPI int    __cdecl MSVCRT$wcscmp(const wchar_t *string1, const wchar_t *string2);

WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);
WINBASEAPI void * WINAPI KERNEL32$HeapAlloc (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI BOOL   WINAPI KERNEL32$HeapFree (HANDLE, DWORD, PVOID);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
WINBASEAPI DWORD  WINAPI KERNEL32$GetLastError (VOID);
WINBASEAPI BOOL   WINAPI KERNEL32$GetFileSizeEx(HANDLE hFile, PLARGE_INTEGER lpFileSize);
WINBASEAPI BOOL   WINAPI KERNEL32$ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
WINBASEAPI LPWSTR WINAPI KERNEL32$GetCommandLineW(VOID);
WINBASEAPI LPWSTR WINAPI KERNEL32$GetCommandLineA(VOID);
WINBASEAPI BOOL   WINAPI KERNEL32$CreatePipe( PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize);
WINBASEAPI BOOL   WINAPI KERNEL32$QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount);
WINBASEAPI BOOL   WINAPI KERNEL32$QueryPerformanceFrequency(LARGE_INTEGER *lpFrequency);
WINBASEAPI BOOL   WINAPI KERNEL32$TerminateThread(HANDLE hthread, DWORD dwExitCode);
WINBASEAPI DWORD  WINAPI KERNEL32$WaitForSingleObject (HANDLE hHandle, DWORD dwMilliseconds);
WINBASEAPI BOOL   WINAPI KERNEL32$PeekNamedPipe(HANDLE hNamedPipe, LPVOID lpBuffer, DWORD nBufferSize, LPDWORD lpBytesRead, LPDWORD lpTotalBytesAvail, LPDWORD lpBytesLeftThisMessage);
WINBASEAPI BOOL   WINAPI KERNEL32$FreeLibrary(HANDLE hLibModule);

#define NtAllocateVirtualMemory      NTDLL$NtAllocateVirtualMemory
#define NtProtectVirtualMemory       NTDLL$NtProtectVirtualMemory
#define NtFreeVirtualMemory          NTDLL$NtFreeVirtualMemory
#define NtFlushInstructionCache      NTDLL$NtFlushInstructionCache
#define RtlCreateUnicodeString       NTDLL$RtlCreateUnicodeString
#define NtClose                      NTDLL$NtClose
#define RtlUnicodeStringToAnsiString NTDLL$RtlUnicodeStringToAnsiString
#define NtQueryVirtualMemory         NTDLL$NtQueryVirtualMemory
#define NtCreateThreadEx             NTDLL$NtCreateThreadEx
#define RtlCompareMemory             NTDLL$RtlCompareMemory
#define NtGetContextThread           NTDLL$NtGetContextThread
#define NtSetContextThread           NTDLL$NtSetContextThread

#define wcscpy                       MSVCRT$wcscpy
#define _stricmp                     MSVCRT$_stricmp
#define memset                       MSVCRT$memset
#define memcpy                       MSVCRT$memcpy
#define strncmp                      MSVCRT$strncmp
#define wcscmp                       MSVCRT$wcscmp

#define GetProcessHeap               KERNEL32$GetProcessHeap
#define HeapAlloc                    KERNEL32$HeapAlloc
#define HeapFree                     KERNEL32$HeapFree
#define CreateFileA                  KERNEL32$CreateFileA
#define GetLastError                 KERNEL32$GetLastError
#define GetFileSizeEx                KERNEL32$GetFileSizeEx
#define ReadFile                     KERNEL32$ReadFile
#define GetCommandLineW              KERNEL32$GetCommandLineW
#define GetCommandLineA              KERNEL32$GetCommandLineA
#define CreatePipe                   KERNEL32$CreatePipe
#define QueryPerformanceCounter      KERNEL32$QueryPerformanceCounter
#define QueryPerformanceFrequency    KERNEL32$QueryPerformanceFrequency
#define TerminateThread              KERNEL32$TerminateThread
#define WaitForSingleObject          KERNEL32$WaitForSingleObject
#define PeekNamedPipe                KERNEL32$PeekNamedPipe
#define FreeLibrary                  KERNEL32$FreeLibrary
