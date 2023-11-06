#pragma once

#include <windows.h>
#include <stdio.h>
#include <winternl.h>

#include "entry.h"
#include "utils.h"
#include "bofdefs.h"
#include "console.h"

#ifdef _WIN64
#define MACHINE 0x8664
#else
#define MACHINE 0x14C
#endif

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )

typedef struct _IMAGE_RELOC {
    WORD offset :12;
    WORD type   :4;
} IMAGE_RELOC, *PIMAGE_RELOC;

typedef BOOL  (WINAPI *DllMain_t)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

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

BOOL load_pe(
    IN PVOID pedata,
    IN UINT32 pelen,
    OUT PLOADED_PE_INFO peinfo);
