
#include "peb.h"
#include "loader.h"

// find a DLL with a certain export, used by xGetProcAddress and FindExport
LPVOID find_reference(
    IN LPVOID original_dll,
    IN PCHAR dll_name,
    IN PCHAR api_name)
{
    PPEB2                  peb  = NULL;
    PPEB_LDR_DATA2         ldr  = NULL;
    PLDR_DATA_TABLE_ENTRY2 dte  = NULL;
    LPVOID                 addr = NULL;
    LPVOID                 base = NULL;

    peb = (PPEB2)READ_MEMLOC(PEB_OFFSET);
    ldr = (PPEB_LDR_DATA2)peb->Ldr;

    // for each DLL loaded
    for (dte=(PLDR_DATA_TABLE_ENTRY2)ldr->InLoadOrderModuleList.Flink;
         dte->DllBase != NULL && addr == NULL;
         dte=(PLDR_DATA_TABLE_ENTRY2)dte->InLoadOrderLinks.Flink)
    {
        base = dte->DllBase;
        // if this is the dll with the reference, continue
        if (base == original_dll) continue;

        addr = xGetProcAddress(base, api_name, 0);
    }
    if (addr == NULL)
    {
        // we did not find the reference, use LoadLibrary
        DPRINT("Could not find %s, using LoadLibraryA", dll_name);
        HMODULE hModule = LoadLibraryA(dll_name);
        if (hModule != NULL)
        {
            DPRINT("Calling GetProcAddress(%s, %s)", dll_name, api_name);
            addr = GetProcAddress(hModule, api_name);
        }
    }

    return addr;
}

// search for an export in a DLL
LPVOID xGetProcAddress(
    IN LPVOID base,
    IN PCHAR api_name,
    IN DWORD ordinal)
{
    PIMAGE_DOS_HEADER       dos           = NULL;
    PIMAGE_NT_HEADERS       nt            = NULL;
    PIMAGE_DATA_DIRECTORY   dir           = NULL;
    PIMAGE_EXPORT_DIRECTORY exp           = NULL;
    LPVOID                  addr          = NULL;
    DWORD                   rva           = 0;
    DWORD                   cnt           = 0;
    PDWORD                  adr           = NULL;
    PDWORD                  sym           = NULL;
    PWORD                   ord           = NULL;
    PCHAR                   api           = NULL;
    CHAR                    dll_name[256] = { 0 };
    CHAR                    new_api[256]  = { 0 };
    DWORD                   i             = 0;
    PCHAR                   p             = NULL;
    DWORD                   len           = 0;
    PVOID                   newbase       = NULL;

    if (base == NULL) return NULL;

    dos = (PIMAGE_DOS_HEADER)base;
    nt  = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
    dir = (PIMAGE_DATA_DIRECTORY)nt->OptionalHeader.DataDirectory;
    rva = dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    // if no export table, return NULL
    if (rva == 0) return NULL;

    exp = RVA2VA(PIMAGE_EXPORT_DIRECTORY, base, rva);
    adr = RVA2VA(PDWORD,base, exp->AddressOfFunctions);
    sym = RVA2VA(PDWORD,base, exp->AddressOfNames);
    ord = RVA2VA(PWORD, base, exp->AddressOfNameOrdinals);

    if (api_name != NULL)
    {
        // exported by name
        cnt = exp->NumberOfNames;
        // if no api names, return NULL
        if (cnt == 0) return NULL;

        do {
            api = RVA2VA(PCHAR, base, sym[cnt-1]);
            // check if the export name matches the API we are looking for
            if (!_stricmp(api, api_name))
            {
                // get the address of the API
                addr = RVA2VA(LPVOID, base, adr[ord[cnt-1]]);
            }
        } while (--cnt && addr == NULL);
    }
    else
    {
        // exported by ordinal
        addr = RVA2VA(PVOID, base, adr[ordinal - exp->Base]);
    }

      // is this a forward reference?
    if ((PBYTE)addr >= (PBYTE)exp &&
      (PBYTE)addr <  (PBYTE)exp +
      dir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
    {
        //DPRINT("%s is forwarded to %s", api_name, (char*)addr);

        // copy DLL name to buffer
        p=(char*)addr;
        len=StringLengthA(p);

        for (i=0; p[i] != 0 && i < sizeof(dll_name) - 4; i++)
        {
            dll_name[i] = p[i];
        }

        for (i=len-1; i > 0; i--)
        {
            if(p[i] == '.') break;
        }

        dll_name[i+1] = 'd';
        dll_name[i+2] = 'l';
        dll_name[i+3] = 'l';
        dll_name[i+4] = 0;

        p += i + 1;

        // copy API name to buffer
        for(i = 0; p[i] != 0 && i < sizeof(new_api) - 1; i++)
        {
            new_api[i] = p[i];
        }
        new_api[i] = 0;

        newbase = handle_dependency(NULL, dll_name);
        if (base == newbase)
        {
            /*
             * the api set seems to resolve to itself...
             * lets just iterate over all loaded modules and
             * find a module with the export we are looking for
             */

            addr = find_reference(base, dll_name, new_api);
        }
        else
        {
            /*
             * we got a different DLL, call xGetProcAddress recursively
             */

            addr = xGetProcAddress(newbase, new_api, 0);
        }
    }

    return addr;
}

// find a DLL by name, load it if not found
LPVOID xGetLibAddress(
    IN PCHAR search,
    IN BOOL load,
    OUT PBOOL loaded)
{
    PPEB2                   peb          = NULL;
    PPEB_LDR_DATA2          ldr          = NULL;
    PIMAGE_DOS_HEADER       dos          = NULL;
    PIMAGE_NT_HEADERS       nt           = NULL;
    PLDR_DATA_TABLE_ENTRY2  dte          = NULL;
    PIMAGE_EXPORT_DIRECTORY exp          = NULL;
    LPVOID                  addr         = NULL;
    LPVOID                  base         = NULL;
    DWORD                   rva          = 0;
    PCHAR                   name         = NULL;
    CHAR                    dll_name[64] = { 0 };
    DWORD                   i            = 0;
    int                     correct      = -1;

    if (loaded)
        *loaded = FALSE;

    for(i = 0; search[i] != 0 && i < 64; i++)
    {
        dll_name[i] = search[i];
    }
    dll_name[i] = 0;
    // make sure the name ends with '.dll'
    if (dll_name[i-4] != '.')
    {
        dll_name[i++] = '.';
        dll_name[i++] = 'd';
        dll_name[i++] = 'l';
        dll_name[i++] = 'l';
        dll_name[i++] = 0;
    }

    peb = (PPEB2)READ_MEMLOC(PEB_OFFSET);
    ldr = (PPEB_LDR_DATA2)peb->Ldr;

    // for each DLL loaded
    for (dte=(PLDR_DATA_TABLE_ENTRY2)ldr->InLoadOrderModuleList.Flink;
         correct != 0 && dte->DllBase != NULL && addr == NULL;
         dte=(PLDR_DATA_TABLE_ENTRY2)dte->InLoadOrderLinks.Flink)
    {
        base = dte->DllBase;
        dos  = (PIMAGE_DOS_HEADER)base;
        nt   = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
        rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (rva == 0) continue;

        exp  = RVA2VA(PIMAGE_EXPORT_DIRECTORY, base, rva);
        name = RVA2VA(PCHAR, base, exp->Name);

        correct = _stricmp(dll_name, name);

        if (correct == 0) {
            addr = base;
        }
    }

    //DPRINT("Address of %s: %p", dll_name, addr);

    // if the DLL was not found, load it
    if (!addr && load)
    {
        addr = LoadLibraryA(dll_name);
        DPRINT("Dll not found. Loaded %s via LoadLibrary at 0x%p", dll_name, addr);
        if (addr && loaded)
            *loaded = TRUE;
    }

    return addr;
}

ULONG ldr_hash_entry(
    IN UNICODE_STRING UniName,
    IN BOOL XorHash)
{
    ULONG ulRes = 0;

    NTSTATUS ( WINAPI *RtlHashUnicodeString ) ( PCUNICODE_STRING, BOOLEAN, ULONG, PULONG ) = xGetProcAddress(xGetLibAddress("ntdll", TRUE, NULL), "RtlHashUnicodeString", 0);
    if (!RtlHashUnicodeString)
    {
        api_not_found("RtlHashUnicodeString");
        return 0;
    }

    RtlHashUnicodeString(&UniName, TRUE, 0, &ulRes);

    if (XorHash)
    {
        ulRes &= (LDR_HASH_TABLE_ENTRIES - 1);
    }

    return ulRes;
}

#ifdef _WIN64

PLDR_DATA_TABLE_ENTRY2 find_ldr_table_entry(
    IN PCWSTR BaseName)
{
    PPEB2                  peb        = NULL;
    PLDR_DATA_TABLE_ENTRY2 pCurEntry  = NULL;
    PLIST_ENTRY            pListHead  = NULL;
    PLIST_ENTRY            pListEntry = NULL;

    peb = (PPEB2)READ_MEMLOC(PEB_OFFSET);

    pListHead  = &peb->Ldr->InLoadOrderModuleList;
    pListEntry = pListHead->Flink;

    do
    {
        pCurEntry  = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY2, InLoadOrderLinks);
        pListEntry = pListEntry->Flink;

        if (wcscmp(BaseName, pCurEntry->BaseDllName.Buffer) == 0)
            return pCurEntry;
    } while (pListEntry != pListHead);

    DPRINT_ERR("Failed to find FindLdr table entry for %ls", BaseName);

    return NULL;
}

/*
 * Try to find the address of ntdll!LdrpModuleBaseAddressIndex
 */
PRTL_RB_TREE find_module_base_address_index(VOID)
{
    SIZE_T                 stEnd             = 0;
    PRTL_BALANCED_NODE     pNode             = NULL;
    PRTL_RB_TREE           pModBaseAddrIndex = NULL;
    PLDR_DATA_TABLE_ENTRY2 ldr_entry         = NULL;
    PIMAGE_NT_HEADERS      nt                = NULL;
    PIMAGE_SECTION_HEADER  sh                = NULL;
    SIZE_T                 stRet             = 0;
    DWORD                  dwLen             = 0;
    SIZE_T                 stBegin           = 0;
    PMEMORY_STRUCTS        mem_structs       = NULL;

    // check if we have saved the address of the module_base_address_index
    mem_structs = BeaconGetValue(NC_MEM_STRUCTS_KEY);
    if (mem_structs && mem_structs->module_base_address_index)
        return mem_structs->module_base_address_index;

    ldr_entry = find_ldr_table_entry(L"ntdll.dll");
    if (!ldr_entry)
        return NULL;

    pNode = &ldr_entry->BaseAddressIndexNode;

    do
    {
        pNode = (PRTL_BALANCED_NODE)(pNode->ParentValue & (~7));
    } while (pNode->ParentValue & (~7));

    if (!pNode->Red)
    {
        dwLen   = 0;
        stBegin = 0;

        nt = RVA2VA(
            PIMAGE_NT_HEADERS,
            ldr_entry->DllBase,
            ((PIMAGE_DOS_HEADER)ldr_entry->DllBase)->e_lfanew);

        sh = IMAGE_FIRST_SECTION(nt);

        for (INT i = 0; i < nt->FileHeader.NumberOfSections; i++)
        {
            if (!strncmp(".data", (LPCSTR)sh->Name, 6))
            {
                stBegin = RVA2VA(SIZE_T, ldr_entry->DllBase, sh->VirtualAddress);
                dwLen   = sh->Misc.VirtualSize;
                break;
            }

            ++sh;
        }

        if (!stBegin || !dwLen)
        {
            DPRINT("Failed to find section");
            return NULL;
        }

        for (DWORD i = 0; i < dwLen - sizeof(SIZE_T); ++stBegin, ++i)
        {
            stRet = RtlCompareMemory((PVOID)stBegin, &pNode, sizeof(SIZE_T));

            if (stRet == sizeof(SIZE_T))
            {
                stEnd = stBegin;
                break;
            }
        }

        if (stEnd)
        {
            PRTL_RB_TREE pTree = (PRTL_RB_TREE)stEnd;

            if (pTree && pTree->Root && pTree->Min)
                pModBaseAddrIndex = pTree;
        }
    }

    if (!pModBaseAddrIndex)
    {
        DPRINT_ERR("Failed to find module base address index");
    }
    else
    {
        // save the address of the module_base_address_index;
        if (mem_structs)
            mem_structs->module_base_address_index = pModBaseAddrIndex;
    }

    return pModBaseAddrIndex;
}

/*
 * This function is equivalent to ntdll!LdrpInsertModuleToIndexLockHeld
 */
BOOL update_base_address_entry(
    IN PLDR_DATA_TABLE_ENTRY2 ldr_entry,
    IN BOOL add_entry)
{
    PRTL_RB_TREE           pModBaseAddrIndex = NULL;
    PLDR_DATA_TABLE_ENTRY2 pNodeLdrEntry     = NULL;
    PRTL_BALANCED_NODE     pLdrNode          = NULL;
    PRTL_BALANCED_NODE     CurrNode          = NULL;
    BOOL                   bRight            = FALSE;
    PVOID                  lpBaseAddr        = ldr_entry->DllBase;

    pModBaseAddrIndex = find_module_base_address_index();
    if (!pModBaseAddrIndex)
        return FALSE;

    if (!add_entry)
    {
        VOID ( WINAPI *RtlRbRemoveNode ) ( PRTL_RB_TREE, PRTL_BALANCED_NODE ) = xGetProcAddress(xGetLibAddress("ntdll", TRUE, NULL), "RtlRbRemoveNode", 0);
        if (!RtlRbRemoveNode)
        {
            api_not_found("RtlRbRemoveNode");
            return FALSE;
        }

        RtlRbRemoveNode(pModBaseAddrIndex, &ldr_entry->BaseAddressIndexNode);
        return TRUE;
    }

    pLdrNode = pModBaseAddrIndex->Root;
    CurrNode = pLdrNode;

    while (pLdrNode != NULL)
    {
        CurrNode = pLdrNode;

        pNodeLdrEntry = CONTAINING_RECORD(pLdrNode, LDR_DATA_TABLE_ENTRY2, BaseAddressIndexNode);

        if (pNodeLdrEntry->DllBase <= lpBaseAddr)
        {
            pLdrNode = CurrNode->Right;

            if (!pLdrNode)
            {
                bRight = TRUE;
                break;
            }
        }
        else
        {
            pLdrNode = CurrNode->Left;
        }
    }

    VOID ( WINAPI *RtlRbInsertNodeEx ) ( PRTL_RB_TREE, PRTL_BALANCED_NODE, BOOLEAN, PRTL_BALANCED_NODE ) = xGetProcAddress(xGetLibAddress("ntdll", TRUE, NULL), "RtlRbInsertNodeEx", 0);
    if (!RtlRbInsertNodeEx)
    {
        api_not_found("RtlRbInsertNodeEx");
        return FALSE;
    }

    RtlRbInsertNodeEx(pModBaseAddrIndex, CurrNode, bRight, &ldr_entry->BaseAddressIndexNode);
    ldr_entry->Flags |= 0x80;

    return TRUE;
}

/*
 * Find the address of ntdll!LdrpHashTable in memory
 */
PLIST_ENTRY find_hash_table(VOID)
{
    PPEB2                  peb           = NULL;
    PLIST_ENTRY            pList         = NULL;
    PLIST_ENTRY            pHead         = NULL;
    PLIST_ENTRY            pEntry        = NULL;
    PLDR_DATA_TABLE_ENTRY2 pCurrentEntry = NULL;
    ULONG                  ulHash        = 0;
    PMEMORY_STRUCTS        mem_structs   = NULL;

    // check if we have saved the address of the hash_table
    mem_structs = BeaconGetValue(NC_MEM_STRUCTS_KEY);
    if (mem_structs && mem_structs->hash_table)
        return mem_structs->hash_table;

    peb = (PPEB2)READ_MEMLOC(PEB_OFFSET);

    pHead  = &peb->Ldr->InInitializationOrderModuleList;
    pEntry = pHead->Flink;

    do
    {
        pCurrentEntry = CONTAINING_RECORD(
            pEntry,
            LDR_DATA_TABLE_ENTRY2,
            InInitializationOrderLinks);

        pEntry = pEntry->Flink;

        if (pCurrentEntry->HashLinks.Flink == &pCurrentEntry->HashLinks)
            continue;

        pList = pCurrentEntry->HashLinks.Flink;

        if (pList->Flink == &pCurrentEntry->HashLinks)
        {
            ulHash = ldr_hash_entry(pCurrentEntry->BaseDllName, TRUE);

            pList = (PLIST_ENTRY)(
                (size_t)pCurrentEntry->HashLinks.Flink -
                ulHash * sizeof(LIST_ENTRY));

            break;
        }

        pList = NULL;
    } while (pHead != pEntry);

    if (!pList)
    {
        DPRINT_ERR("Failed to find hash table");
    }
    else
    {
        // save the address of the hash_table
        if (mem_structs)
            mem_structs->hash_table = pList;
    }

    return pList;
}

#endif

BOOL unlink_module(
    IN PLDR_DATA_TABLE_ENTRY2 ldr_entry)
{
#ifdef _WIN64
    // remove from the base address entry
    if (!update_base_address_entry(ldr_entry, FALSE))
        return FALSE;

    // remove from the ldr hash table
    unlink_from_list(&ldr_entry->HashLinks);
#endif

    // remove from standard lists
    unlink_from_list(&ldr_entry->InLoadOrderLinks);
    unlink_from_list(&ldr_entry->InMemoryOrderLinks);
    unlink_from_list(&ldr_entry->InInitializationOrderLinks);

    return TRUE;
}

/*
 * Link the Ldr entry into all the PEB lists
 */
BOOL link_ldr_entry(
    IN PLDR_DATA_TABLE_ENTRY2 ldr_entry)
{
    PPEB2          peb           = NULL;
    PPEB_LDR_DATA2 ldr           = NULL;
#ifdef _WIN64
    PLIST_ENTRY    LdrpHashTable = NULL;
    ULONG          ulHash        = 0;

    LdrpHashTable = find_hash_table();
    if (!LdrpHashTable)
        return FALSE;

    // add to the ldr hash table
    if (!update_base_address_entry(ldr_entry, TRUE))
        return FALSE;

    // insert into the ldr hash table
    ulHash = ldr_hash_entry(ldr_entry->BaseDllName, TRUE);
    insert_tail_list(&LdrpHashTable[ulHash], &ldr_entry->HashLinks);
#endif

    peb = (PPEB2)READ_MEMLOC(PEB_OFFSET);
    ldr = (PPEB_LDR_DATA2)peb->Ldr;

    // insert into standard lists
    insert_tail_list(&ldr->InLoadOrderModuleList, &ldr_entry->InLoadOrderLinks);
    insert_tail_list(&ldr->InMemoryOrderModuleList, &ldr_entry->InMemoryOrderLinks);
    insert_tail_list(&ldr->InInitializationOrderModuleList, &ldr_entry->InInitializationOrderLinks);

    return TRUE;
}

PLDR_DATA_TABLE_ENTRY2 create_ldr_entry(
    IN PLOADED_PE_INFO peinfo,
    IN PVOID base_address)
{
    PIMAGE_NT_HEADERS      nt        = NULL;
    PLDR_DATA_TABLE_ENTRY2 ldr_entry = NULL;
    LPWSTR                 pe_wname  = NULL;
    LPWSTR                 pe_wpath  = NULL;

    nt = RVA2VA(PIMAGE_NT_HEADERS, base_address, ((PIMAGE_DOS_HEADER)base_address)->e_lfanew);

    NTSTATUS ( WINAPI *NtQuerySystemTime ) ( PLARGE_INTEGER ) = xGetProcAddress(xGetLibAddress("ntdll", TRUE, NULL), "NtQuerySystemTime", 0);
    if (!NtQuerySystemTime)
    {
        api_not_found("NtQuerySystemTime");
        return NULL;
    }

    ldr_entry = intAlloc(sizeof(LDR_DATA_TABLE_ENTRY2));
    if (!ldr_entry)
    {
        malloc_failed();
        return NULL;
    }

    pe_wname = intAlloc(sizeof(WCHAR) * MAX_PATH);
    wcscpy(pe_wname, peinfo->pe_wname);
    pe_wpath = intAlloc(sizeof(WCHAR) * MAX_PATH);
    wcscpy(pe_wpath, peinfo->pe_wpath);

    // start setting the values in the entry
    NtQuerySystemTime(&ldr_entry->LoadTime);

    ldr_entry->ReferenceCount        = 1;
    ldr_entry->LoadReason            = LoadReasonDynamicLoad;
    ldr_entry->OriginalBase          = nt->OptionalHeader.ImageBase;
    ldr_entry->ImageDll              = TRUE;
    ldr_entry->LoadNotificationsSent = TRUE;
    ldr_entry->EntryProcessed        = TRUE;
    ldr_entry->InLegacyLists         = TRUE;
    ldr_entry->InIndexes             = TRUE;
    ldr_entry->ProcessAttachCalled   = TRUE;
    ldr_entry->InExceptionTable      = FALSE;
    ldr_entry->DllBase               = base_address;
    ldr_entry->SizeOfImage           = nt->OptionalHeader.SizeOfImage;
    ldr_entry->TimeDateStamp         = nt->FileHeader.TimeDateStamp;
    myRtlInitUnicodeString(&ldr_entry->BaseDllName, pe_wname);
    myRtlInitUnicodeString(&ldr_entry->FullDllName, pe_wpath);
    ldr_entry->ObsoleteLoadCount     = 1;
    ldr_entry->Flags                 = LDRP_IMAGE_DLL | LDRP_ENTRY_INSERTED | LDRP_ENTRY_PROCESSED | LDRP_PROCESS_ATTACH_CALLED | LDRP_DONT_CALL_FOR_THREADS;
    ldr_entry->BaseNameHashValue     = ldr_hash_entry(ldr_entry->BaseDllName, FALSE);
    ldr_entry->EntryPoint            = RVA2VA(PVOID, base_address, nt->OptionalHeader.AddressOfEntryPoint);

    // set the correct values in the Ddag node struct
    ldr_entry->DdagNode = intAlloc(sizeof(LDR_DDAG_NODE));
    if (!ldr_entry->DdagNode)
    {
        malloc_failed();
        intFree(ldr_entry);
        return NULL;
    }

    ldr_entry->NodeModuleLink.Flink    = &ldr_entry->DdagNode->Modules;
    ldr_entry->NodeModuleLink.Blink    = &ldr_entry->DdagNode->Modules;
    ldr_entry->DdagNode->Modules.Flink = &ldr_entry->NodeModuleLink;
    ldr_entry->DdagNode->Modules.Blink = &ldr_entry->NodeModuleLink;
    ldr_entry->DdagNode->State         = LdrModulesReadyToRun;
    ldr_entry->DdagNode->LoadCount     = 1;

    return ldr_entry;
}

BOOL link_module(
    IN PLOADED_PE_INFO peinfo,
    IN PVOID base_address)
{
    PLDR_DATA_TABLE_ENTRY2 ldr_entry = NULL;
    BOOL                   Success   = FALSE;

    ldr_entry = create_ldr_entry(peinfo, base_address);
    if (!ldr_entry)
        goto Cleanup;

    if (!link_ldr_entry(ldr_entry))
        goto Cleanup;

    Success = TRUE;

Cleanup:
    if (!Success && ldr_entry)
        intFree(ldr_entry);

    if (Success)
        peinfo->ldr_entry = ldr_entry;

    return Success;
}
