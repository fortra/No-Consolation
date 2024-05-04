#pragma once

#include <windows.h>
#include <winternl.h>

#define intAlloc(size) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) HeapFree(GetProcessHeap(), 0, addr)

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

WINBASEAPI NTSTATUS NTAPI NTDLL$NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID * BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtFlushInstructionCache(HANDLE ProcessHandle, PVOID BaseAddress, ULONG FlushSize);
WINBASEAPI BOOLEAN NTSYSAPI NTDLL$RtlCreateUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtClose(HANDLE Handle);
WINBASEAPI NTSTATUS NTAPI NTDLL$RtlUnicodeStringToAnsiString(PANSI_STRING DestinationString, PCUNICODE_STRING SourceString, BOOLEAN AllocateDestinationString);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);
WINBASEAPI SIZE_T NTSYSAPI NTDLL$RtlCompareMemory(VOID *Source1, VOID *Source2, SIZE_T Length);

WINBASEAPI  int   __cdecl MSVCRT$_stricmp(const char *string1,const char *string2);
WINBASEAPI void   __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI PVOID  __cdecl MSVCRT$memcpy(void * __restrict__ _Dst,const void * __restrict__ _Src,size_t _MaxCount);
WINBASEAPI int    __cdecl MSVCRT$strncmp(const char *s1, const char *s2, size_t n);
WINBASEAPI int    __cdecl MSVCRT$strcmp(const char *s1, const char *s2);

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

#define _stricmp                     MSVCRT$_stricmp
#define memset                       MSVCRT$memset
#define memcpy                       MSVCRT$memcpy
#define strncmp                      MSVCRT$strncmp
#define strcmp                       MSVCRT$strcmp

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
