#pragma once

#include "bofdefs.h"
#include "loader.h"

#ifdef _WIN64
 #define PEB_OFFSET 0x60
 #define READ_MEMLOC __readgsqword
#else
 #define PEB_OFFSET 0x30
 #define READ_MEMLOC __readfsdword
#endif

#define LDRP_IMAGE_DLL 0x00000004
#define LDRP_ENTRY_INSERTED 0x00008000
#define LDRP_ENTRY_PROCESSED 0x00004000
#define LDRP_DONT_CALL_FOR_THREADS 0x00040000
#define LDRP_PROCESS_ATTACH_CALLED 0x00080000

LPVOID xGetProcAddress(
    IN LPVOID base,
    IN PCHAR api_name,
    IN DWORD ordinal);

LPVOID xGetLibAddress(
    IN PCHAR search,
    IN BOOL load,
    OUT PBOOL loaded);

BOOL link_module(
    IN PLOADED_PE_INFO peinfo,
    IN PVOID base_address);

BOOL unlink_module(
    IN PLDR_DATA_TABLE_ENTRY2 ldr_entry);
