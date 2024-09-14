#pragma once

#include <windows.h>
#include <stdio.h>
#include <winternl.h>

#include "entry.h"
#include "utils.h"
#include "bofdefs.h"
#include "console.h"
#include "apisetlookup.h"

#ifdef _WIN64
#define MACHINE 0x8664
#else
#define MACHINE 0x14C
#endif

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define NtCurrentThread() ( (HANDLE)(LONG_PTR) -2 )

typedef NTSTATUS(__stdcall* STDCALL)(PLDR_DATA_TABLE_ENTRY);
typedef NTSTATUS(__thiscall* THISCALL)(PLDR_DATA_TABLE_ENTRY);

typedef struct _FP {
    union {
        STDCALL  stdcall;
        THISCALL thiscall;
        PVOID    ptr;
    };
} FP, *PFP;

typedef struct _IMAGE_RELOC {
    WORD offset :12;
    WORD type   :4;
} IMAGE_RELOC, *PIMAGE_RELOC;

typedef BOOL  (WINAPI *DllMain_t)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
typedef BOOL  (WINAPI *Entry_t)(PVOID Param1, PVOID Param2, PVOID Param3);

// for setting the command line...
typedef CHAR**  (WINAPI *p_acmdln_t)(VOID);
typedef WCHAR** (WINAPI *p_wcmdln_t)(VOID);

BOOL SetCommandLineW(
    IN PCWSTR NewCommandLine);
BOOL IsExitAPI(
    IN PCHAR name);

// Relative Virtual Address to Virtual Address
#define RVA2VA(type, base, rva) (type)((ULONG_PTR) base + rva)

BOOL IsHeapPtr(
    IN LPVOID ptr);

BOOL IsReadable(
    IN LPVOID ptr);

VOID unload_dependency(
    IN PLOADED_PE_INFO peinfo);

PVOID handle_dependency(
    IN PLOADED_PE_INFO peinfo,
    IN LPSTR dll_name);

PVOID handle_import(
    IN PLOADED_PE_INFO peinfo,
    IN PVOID dll_base,
    IN LPSTR dll_name,
    IN LPSTR api_name);

BOOL load_pe(
    IN PVOID pedata,
    IN UINT32 pelen,
    IN OUT PLOADED_PE_INFO peinfo);
